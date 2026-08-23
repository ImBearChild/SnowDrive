#!/usr/bin/env python3
"""SCSI over USB BOT pcapng analyzer.

Parses USBPcap-format pcapng captures, pairs CBW→Data→CSW into complete
SCSI transactions, and decodes CDB fields + data-phase payloads.

Architecture:
  §1  pcapng parsing
  §2  USBPcap pseudo-header
  §3  BOT CBW/CSW correlation
  §4  SCSI opcode table + CDB decoders
  §5  Payload decoders
  §6  Output formatters
  §7  CLI + main

Usage:
  python3 usbms-pcap.py [--format table|json|csv] [--lun N] [--opcode 0x43] file.pcapng
"""

import argparse
import csv
import io
import json
import os
import struct
import sys
from dataclasses import dataclass, field
from typing import Optional

# ═══════════════════════════════════════════════════════════════════
# §1  pcapng parsing
# ═══════════════════════════════════════════════════════════════════

PCAPNG_MAGIC = 0x0A0D0D0A
EPB_TYPE = 0x00000006
IDB_TYPE = 0x00000001
# USBPcap uses link type 220 (standard) or 249 (Windows USBPcap)
USBPCAP_LINKTYPES = {220, 249}


def read_blocks(path):
    """Yield (block_type, raw_data) for each pcapng block."""
    with open(path, "rb") as f:
        while True:
            hdr = f.read(8)
            if len(hdr) < 8:
                break
            block_type, block_len = struct.unpack("<II", hdr)
            if block_len < 12:
                break
            body = f.read(block_len - 12)
            trailer = f.read(4)
            if len(body) != block_len - 12:
                break
            yield block_type, body


def parse_pcapng(path):
    """Parse pcapng and yield (timestamp_sec, usb_data_bytes) for bulk packets."""
    link_type = None
    for btype, body in read_blocks(path):
        if btype == PCAPNG_MAGIC:
            pass  # Section Header — skip
        elif btype == IDB_TYPE:
            if len(body) >= 2:
                link_type = struct.unpack("<H", body[0:2])[0]
                if link_type not in USBPCAP_LINKTYPES:
                    print(
                        f"warning: link type {link_type} (expected one of {USBPCAP_LINKTYPES})",
                        file=sys.stderr,
                    )
        elif btype == EPB_TYPE:
            if len(body) < 20:
                continue
            _if_id, ts_high, ts_low, cap_len, orig_len = struct.unpack("<IIIII", body[:20])
            ts_sec = ((ts_high << 32) | ts_low) / 1_000_000.0
            pkt = body[20 : 20 + cap_len]
            if len(pkt) < 27:
                continue
            yield ts_sec, pkt
        # skip unknown block types


# ═══════════════════════════════════════════════════════════════════
# §2  USBPcap pseudo-header (27 bytes)
# ═══════════════════════════════════════════════════════════════════

def parse_usbpcap_header(pkt):
    """Return (direction, bus, device, endpoint, transfer, data_length, data_offset) or None."""
    if len(pkt) < 27:
        return None
    header_len = struct.unpack("<H", pkt[0:2])[0]
    if header_len < 27 or len(pkt) < header_len:
        return None
    # status = struct.unpack("<I", pkt[10:14])[0]
    function = struct.unpack("<H", pkt[14:16])[0]
    info = pkt[16]
    bus = struct.unpack("<H", pkt[17:19])[0]
    device = struct.unpack("<H", pkt[19:21])[0]
    endpoint = pkt[21]
    transfer = pkt[22]
    data_length = struct.unpack("<I", pkt[23:27])[0]

    direction = "IN" if (info & 1) else "OUT"

    return {
        "direction": direction,
        "bus": bus,
        "device": device,
        "endpoint": endpoint,
        "transfer": transfer,
        "data_length": data_length,
        "data_offset": header_len,
    }


# ═══════════════════════════════════════════════════════════════════
# §3  BOT CBW/CSW correlation
# ═══════════════════════════════════════════════════════════════════

CBW_SIGNATURE = 0x43425355  # "USBC" LE
CSW_SIGNATURE = 0x53425355  # "USBS" LE
CBW_LEN = 31
CSW_LEN = 13
CSW_STATUS = {0: "GOOD", 1: "FAILED", 2: "PHASE_ERROR"}


@dataclass
class Cbw:
    frame: int
    time: float
    tag: int
    data_len: int
    direction: str  # "IN" (Data-In) or "OUT" (Data-Out)
    lun: int
    cdb_len: int
    cdb: bytes
    raw: bytes = b""


@dataclass
class Transaction:
    cbw: Cbw = None
    data_in: bytes = field(default_factory=bytes)
    data_out: bytes = field(default_factory=bytes)
    csw_tag: int = -1
    csw_residue: int = 0
    csw_status: str = ""


def try_parse_cbw(pkt, hdr):
    """Attempt to parse a CBW from an OUT bulk packet. Returns Cbw or None."""
    if hdr["direction"] != "OUT":
        return None
    data_off = hdr["data_offset"]
    if len(pkt) - data_off < CBW_LEN:
        return None
    sig = struct.unpack("<I", pkt[data_off : data_off + 4])[0]
    if sig != CBW_SIGNATURE:
        return None
    tag = struct.unpack("<I", pkt[data_off + 4 : data_off + 8])[0]
    data_len = struct.unpack("<I", pkt[data_off + 8 : data_off + 12])[0]
    flags = pkt[data_off + 12]
    if flags & 0x7F != 0:
        return None
    lun = pkt[data_off + 13]
    cdb_len = pkt[data_off + 14]
    if cdb_len == 0 or cdb_len > 16:
        return None
    cdb = bytes(pkt[data_off + 15 : data_off + 15 + cdb_len])
    direction = "IN" if (flags & 0x80) else "OUT"
    return Cbw(
        frame=0,
        time=0.0,
        tag=tag,
        data_len=data_len,
        direction=direction,
        lun=lun,
        cdb_len=cdb_len,
        cdb=cdb,
        raw=bytes(pkt[data_off : data_off + CBW_LEN]),
    )


def try_parse_csw(pkt, hdr):
    """Attempt to parse a CSW from an IN bulk packet. Returns (tag, residue, status_str) or None."""
    if hdr["direction"] != "IN":
        return None
    data_off = hdr["data_offset"]
    if len(pkt) - data_off < CSW_LEN:
        return None
    sig = struct.unpack("<I", pkt[data_off : data_off + 4])[0]
    if sig != CSW_SIGNATURE:
        return None
    tag = struct.unpack("<I", pkt[data_off + 4 : data_off + 8])[0]
    residue = struct.unpack("<I", pkt[data_off + 8 : data_off + 12])[0]
    status = pkt[data_off + 12]
    return tag, residue, CSW_STATUS.get(status, f"UNKNOWN(0x{status:02X})")


# ═══════════════════════════════════════════════════════════════════
# §4  SCSI opcode table + CDB decoders
# ═══════════════════════════════════════════════════════════════════

PDT_NAMES = {
    0x00: "Direct-Access Block",
    0x01: "Sequential-Access",
    0x02: "Printer",
    0x03: "Processor",
    0x04: "Write-Once",
    0x05: "CD-ROM",
    0x06: "Scanner",
    0x07: "Optical Memory",
    0x08: "Media Changer",
    0x0E: "Enclosure",
    0x1F: "Unknown",
}


def cdb_lba10(cdb):
    if len(cdb) < 6:
        return 0
    return (cdb[2] << 24) | (cdb[3] << 16) | (cdb[4] << 8) | cdb[5]


def cdb_transfer_len10(cdb):
    if len(cdb) < 9:
        return 0
    return (cdb[7] << 8) | cdb[8]


def cdb_lba16(cdb):
    if len(cdb) < 10:
        return 0
    return (
        (cdb[2] << 56) | (cdb[3] << 48) | (cdb[4] << 40) | (cdb[5] << 32)
        | (cdb[6] << 24) | (cdb[7] << 16) | (cdb[8] << 8) | cdb[9]
    )


def cdb_transfer_len16(cdb):
    if len(cdb) < 14:
        return 0
    return (cdb[10] << 24) | (cdb[11] << 16) | (cdb[12] << 8) | cdb[13]


def cdb_lba12(cdb):
    return cdb_lba10(cdb)


def cdb_transfer_len12(cdb):
    if len(cdb) < 10:
        return 0
    return (cdb[6] << 24) | (cdb[7] << 16) | (cdb[8] << 8) | cdb[9]


def cdb_lba6(cdb):
    if len(cdb) < 4:
        return 0
    return ((cdb[1] & 0x1F) << 16) | (cdb[2] << 8) | cdb[3]


def cdb_transfer_len6(cdb):
    if len(cdb) < 5:
        return 0
    raw = cdb[4]
    return 256 if raw == 0 else raw


# ── CDB field decoder functions ──────────────────────────────────


def _noop(_cdb, _data):
    return None


def _decode_request_sense(cdb, data):
    if not data or len(data) < 2:
        return None
    resp_code = data[0] & 0x7F
    if resp_code != 0x70 and resp_code != 0x71:
        return None
    if len(data) < 14:
        return None
    key = data[2] & 0x0F
    asc = data[12]
    ascq = data[13]
    key_names = {
        0: "No Sense", 1: "Recovered Error", 2: "Not Ready",
        3: "Medium Error", 4: "Hardware Error", 5: "Illegal Request",
        6: "Unit Attention", 7: "Data Protect", 8: "Blank Check",
        0x0B: "Copy Aborted", 0x0D: "Volume Overflow",
    }
    key_str = key_names.get(key, f"0x{key:X}")
    asc_name = _ASC_ASCQ.get((asc, ascq)) or _ASC_ASCQ.get((asc, None)) or f"0x{asc:02X}/0x{ascq:02X}"
    return f"key={key_str}, {asc_name}"


# ASC/ASCQ name table (SPC-4 §4.5.6, common codes)
_ASC_ASCQ = {
    (0x00, 0x00): "ASC=00h ASCQ=00h NO ADDITIONAL SENSE INFORMATION",
    (0x00, 0x01): "ASC=00h ASCQ=01h FILEMARK DETECTED",
    (0x00, 0x02): "ASC=00h ASCQ=02h END-OF-PARTITION/MEDIUM DETECTED",
    (0x00, 0x03): "ASC=00h ASCQ=03h SETMARK DETECTED",
    (0x00, 0x04): "ASC=00h ASCQ=04h BEGINNING-OF-PARTITION/MEDIUM DETECTED",
    (0x00, 0x05): "ASC=00h ASCQ=05h END-OF-DATA DETECTED",
    (0x00, 0x06): "ASC=00h ASCQ=06h I/O PROCESS TERMINATED",
    (0x00, 0x11): "ASC=00h ASCQ=11h READ PRIORITY OVERRIDE",
    (0x00, 0x12): "ASC=00h ASCQ=12h INCOMPLETE READ REMAINING",
    (0x01, 0x00): "ASC=01h ASCQ=00h NO INDEX/SECTOR SIGNAL",
    (0x02, 0x00): "ASC=02h ASCQ=00h NO SEEK COMPLETE",
    (0x03, 0x00): "ASC=03h ASCQ=00h PERIPHERAL DEVICE WRITE FAULT",
    (0x03, 0x01): "ASC=03h ASCQ=01h NO WRITE CURRENT",
    (0x03, 0x02): "ASC=03h ASCQ=02h WRITE ERROR",
    (0x04, 0x00): "ASC=04h ASCQ=00h LOGICAL UNIT NOT READY, CAUSE NOT REPORTABLE",
    (0x04, 0x01): "ASC=04h ASCQ=01h LOGICAL UNIT NOT READY, IN PROGRESS OF BECOMING READY",
    (0x04, 0x02): "ASC=04h ASCQ=02h LOGICAL UNIT NOT READY, INITIALIZATION REQUIRED",
    (0x04, 0x04): "ASC=04h ASCQ=04h LOGICAL UNIT NOT READY, FORMAT IN PROGRESS",
    (0x05, 0x00): "ASC=05h ASCQ=00h NO RESPONSE / NON-EXISTENT LUN",
    (0x06, 0x00): "ASC=06h ASCQ=00h NO REFERENCE POSITION FOUND",
    (0x07, 0x00): "ASC=07h ASCQ=00h MULTIPLE PERIPHERAL DEVICES SELECTED",
    (0x08, 0x00): "ASC=08h ASCQ=00h LUN COMMUNICATION FAILED",
    (0x08, 0x01): "ASC=08h ASCQ=01h LUN COMMUNICATION TIMEOUT",
    (0x09, 0x00): "ASC=09h ASCQ=00h TRACK FOLLOWING ERROR",
    (0x0B, 0x00): "ASC=0Bh ASCQ=00h OVERLAPPED COMMANDS ATTEMPTED",
    (0x0C, 0x00): "ASC=0Ch ASCQ=00h WRITE FORMAT ERROR",
    (0x10, 0x00): "ASC=10h ASCQ=00h ID CRC OR ECC ERROR",
    (0x11, 0x00): "ASC=11h ASCQ=00h UNRECOVERED READ ERROR",
    (0x11, 0x01): "ASC=11h ASCQ=01h READ RETRIES EXHAUSTED",
    (0x11, 0x02): "ASC=11h ASCQ=02h ERROR TOO LONG TO CORRECT",
    (0x11, 0x04): "ASC=11h ASCQ=04h UNRECOVERED READ ERROR - AUTO REALLOCATE FAILED",
    (0x12, 0x00): "ASC=12h ASCQ=00h ADDRESS MARK NOT FOUND FOR ID FIELD",
    (0x13, 0x00): "ASC=13h ASCQ=00h ADDRESS MARK NOT FOUND FOR DATA FIELD",
    (0x14, 0x00): "ASC=14h ASCQ=00h RECORDED ENTITY NOT FOUND",
    (0x14, 0x01): "ASC=14h ASCQ=01h RECORD NOT FOUND",
    (0x15, 0x00): "ASC=15h ASCQ=00h RANDOM POSITIONING ERROR",
    (0x15, 0x01): "ASC=15h ASCQ=01h MECHANICAL POSITIONING ERROR",
    (0x16, 0x00): "ASC=16h ASCQ=00h DATA SYNCHRONIZATION MARK ERROR",
    (0x17, 0x00): "ASC=17h ASCQ=00h RECOVERED DATA WITH NO ERROR CORRECTION APPLIED",
    (0x17, 0x01): "ASC=17h ASCQ=01h RECOVERED DATA WITH RETRIES",
    (0x18, 0x00): "ASC=18h ASCQ=00h RECOVERED DATA WITH ERROR CORRECTION APPLIED",
    (0x19, 0x00): "ASC=19h ASCQ=00h DEFECT LIST ERROR",
    (0x1A, 0x00): "ASC=1Ah ASCQ=00h NUMBER OF SYNCHRONIZATION MARKS FAULT",
    (0x1B, 0x00): "ASC=1Bh ASCQ=00h END-OF-DATA UNSUPPORTED",
    (0x1C, 0x00): "ASC=1Ch ASCQ=00h DEFECT LIST NOT AVAILABLE",
    (0x1D, 0x00): "ASC=1Dh ASCQ=00h MISCOMPARE DURING VERIFY OPERATION",
    (0x1E, 0x00): "ASC=1Eh ASCQ=00h RECOVERED ID WITH ECC CORRECTION",
    (0x20, 0x00): "ASC=20h ASCQ=00h INVALID COMMAND OPERATION CODE",
    (0x21, 0x00): "ASC=21h ASCQ=00h LBA OUT OF RANGE",
    (0x21, 0x01): "ASC=21h ASCQ=01h INVALID ELEMENT ADDRESS",
    (0x22, 0x00): "ASC=22h ASCQ=00h ILLEGAL FUNCTION",
    (0x24, 0x00): "ASC=24h ASCQ=00h INVALID FIELD IN CDB",
    (0x24, 0x01): "ASC=24h ASCQ=01h INVALID FIELD IN PARAMETER LIST",
    (0x25, 0x00): "ASC=25h ASCQ=00h LOGICAL UNIT NOT SUPPORTED",
    (0x26, 0x00): "ASC=26h ASCQ=00h INVALID FIELD IN PARAMETER LIST",
    (0x27, 0x00): "ASC=27h ASCQ=00h WRITE PROTECTED",
    (0x28, 0x00): "ASC=28h ASCQ=00h NOT READY TO READY TRANSITION, MEDIUM MAY HAVE CHANGED",
    (0x29, 0x00): "ASC=29h ASCQ=00h POWER ON, RESET, OR BUS DEVICE RESET OCCURRED",
    (0x29, 0x01): "ASC=29h ASCQ=01h POWER ON OCCURRED",
    (0x29, 0x02): "ASC=29h ASCQ=02h SCSI BUS RESET OCCURRED",
    (0x29, 0x03): "ASC=29h ASCQ=03h BUS DEVICE RESET MESSAGE OCCURRED",
    (0x29, 0x04): "ASC=29h ASCQ=04h DEVICE RESET MESSAGE OCCURRED",
    (0x2A, 0x00): "ASC=2Ah ASCQ=00h MODE PARAMETERS CHANGED",
    (0x2A, 0x01): "ASC=2Ah ASCQ=01h MODE PARAMETERS CHANGED BY OTHER INITIATOR",
    (0x2B, 0x00): "ASC=2Bh ASCQ=00h COPY CANNOT EXECUTE AS INITIATOR",
    (0x2C, 0x00): "ASC=2Ch ASCQ=00h COMMAND SEQUENCE ERROR",
    (0x2D, 0x00): "ASC=2Dh ASCQ=00h OVERWRITE ERROR ON UPDATE IN PLACE",
    (0x2E, 0x00): "ASC=2Eh ASCQ=00h INSUFFICIENT TIME FOR OPERATION",
    (0x2F, 0x00): "ASC=2Fh ASCQ=00h COMMANDS CLEARED BY OTHER INITIATOR",
    (0x30, 0x00): "ASC=30h ASCQ=00h INCOMPATIBLE MEDIUM INSTALLED",
    (0x30, 0x01): "ASC=30h ASCQ=01h CANNOT READ MEDIUM - UNKNOWN FORMAT",
    (0x30, 0x02): "ASC=30h ASCQ=02h CANNOT READ MEDIUM - INCOMPATIBLE FORMAT",
    (0x31, 0x00): "ASC=31h ASCQ=00h MEDIUM FORMAT CORRUPTED",
    (0x32, 0x00): "ASC=32h ASCQ=00h NO DEFECT SPARE LOCATION AVAILABLE",
    (0x33, 0x00): "ASC=33h ASCQ=00h TAPE LENGTH EXCEEDED",
    (0x34, 0x00): "ASC=34h ASCQ=00h ENCLOSURE FAILURE",
    (0x35, 0x00): "ASC=35h ASCQ=00h ENCLOSURE SERVICES FAILURE",
    (0x36, 0x00): "ASC=36h ASCQ=00h RIBBON, INK, OR TONER FAILURE",
    (0x37, 0x00): "ASC=37h ASCQ=00h ROUNDED PARAMETER",
    (0x38, 0x00): "ASC=38h ASCQ=00h EVENT STATUS NOTIFICATION",
    (0x39, 0x00): "ASC=39h ASCQ=00h SAVING PARAMETERS NOT SUPPORTED",
    (0x3A, 0x00): "ASC=3Ah ASCQ=00h MEDIUM NOT PRESENT",
    (0x3A, 0x01): "ASC=3Ah ASCQ=01h MEDIUM NOT PRESENT - TRAY CLOSED",
    (0x3A, 0x02): "ASC=3Ah ASCQ=02h MEDIUM NOT PRESENT - TRAY OPEN",
    (0x3B, 0x00): "ASC=3Bh ASCQ=00h SEQUENTIAL POSITIONING ERROR",
    (0x3C, 0x00): "ASC=3Ch ASCQ=00h SEE REQUIRED",
    (0x3D, 0x00): "ASC=3Dh ASCQ=00h INVALID ELEMENT ADDRESS",
    (0x3E, 0x00): "ASC=3Eh ASCQ=00h LOGICAL UNIT HAS FAILED SELF-TEST",
    (0x3F, 0x00): "ASC=3Fh ASCQ=00h TARGET CONDITION MET",
    (0x3F, 0x01): "ASC=3Fh ASCQ=01h INITIATOR CONDITION MET",
    (0x3F, 0x02): "ASC=3Fh ASCQ=02h COPYING PARAMETER FAILED",
    (0x40, 0x00): "ASC=40h ASCQ=00h DIAGNOSTIC FAILURE ON COMPONENT NN",
    (0x41, 0x00): "ASC=41h ASCQ=00h DATA PATH FAILING",
    (0x42, 0x00): "ASC=42h ASCQ=00h POWER-ON OR SELF-TEST FAILURE",
    (0x43, 0x00): "ASC=43h ASCQ=00h MESSAGE ERROR",
    (0x44, 0x00): "ASC=44h ASCQ=00h INTERNAL TARGET FAILURE",
    (0x45, 0x00): "ASC=45h ASCQ=00h SELECT OR RESELECT FAILURE",
    (0x46, 0x00): "ASC=46h ASCQ=00h UNSUCCESSFUL SOFT RESET",
    (0x47, 0x00): "ASC=47h ASCQ=00h SCSI PARITY ERROR",
    (0x48, 0x00): "ASC=48h ASCQ=00h INITIATOR DETECTED ERROR MESSAGE RECEIVED",
    (0x49, 0x00): "ASC=49h ASCQ=00h INVALID MESSAGE ERROR",
    (0x4A, 0x00): "ASC=4Ah ASCQ=00h COMMAND PHASE ERROR",
    (0x4B, 0x00): "ASC=4Bh ASCQ=00h DATA PHASE ERROR",
    (0x4C, 0x00): "ASC=4Ch ASCQ=00h LOGICAL UNIT FAILED SELF-TEST",
    (0x4D, 0x00): "ASC=4Dh ASCQ=00h OVERLAPPED COMMANDS ATTEMPTED",
    (0x4E, 0x00): "ASC=4Eh ASCQ=00h OVERLAPPED TAG",
    (0x50, 0x00): "ASC=50h ASCQ=00h READ OFFSET ERROR",
    (0x51, 0x00): "ASC=51h ASCQ=00h ERASE FAILURE",
    (0x52, 0x00): "ASC=52h ASCQ=00h CARTRIDGE FAULT",
    (0x53, 0x00): "ASC=53h ASCQ=00h MEDIA LOAD OR EJECT FAILED",
    (0x53, 0x01): "ASC=53h ASCQ=01h MEDIUM REMOVAL PREVENTED",
    (0x53, 0x02): "ASC=53h ASCQ=02h MEDIUM REMOVAL PREVENTED",
    (0x54, 0x00): "ASC=54h ASCQ=00h SCSI TO HOST SYSTEM FAILURE",
    (0x55, 0x00): "ASC=55h ASCQ=00h SYSTEM RESOURCE FAILURE",
    (0x57, 0x00): "ASC=57h ASCQ=00h UNABLE TO RECOVER TABLE OF CONTENTS",
    (0x58, 0x00): "ASC=58h ASCQ=00h GENERATION DOES NOT EXIST",
    (0x59, 0x00): "ASC=59h ASCQ=00h UPDATED BLOCK READ ERROR",
    (0x5A, 0x00): "ASC=5Ah ASCQ=00h INDEX OR DATA FIELD CHANGE ERROR",
    (0x5B, 0x00): "ASC=5Bh ASCQ=00h SHARING VIOLATION",
    (0x5C, 0x00): "ASC=5Ch ASCQ=00h RESOURCE RELEASE FAILURE",
    (0x5D, 0x00): "ASC=5Dh ASCQ=00h NO SPARE BLOCK AVAILABLE",
    (0x5E, 0x00): "ASC=5Eh ASCQ=00h LOGICAL UNIT NOT CONFIGURED",
    (0x5F, 0x00): "ASC=5Fh ASCQ=00h ORDER EXPRESSION MISMATCH",
    (0x60, 0x00): "ASC=60h ASCQ=00h LAMP FAILURE",
    (0x61, 0x00): "ASC=61h ASCQ=00h VIDEO ACQUISITION ERROR",
    (0x62, 0x00): "ASC=62h ASCQ=00h SCAN OUTPUT POSITION ERROR",
    (0x63, 0x00): "ASC=63h ASCQ=00h END OF USER AREA ENCOUNTERED",
    (0x64, 0x00): "ASC=64h ASCQ=00h ILLEGAL MODE FOR THIS TRACK",
    (0x65, 0x00): "ASC=65h ASCQ=00h INVALID PACKET SIZE",
    (0x6F, 0x00): "ASC=6Fh ASCQ=00h OVERLAPPING DATA/COMPARISON CONFLICT",
    (0x70, 0x00): "ASC=70h ASCQ=00h DECOMPRESSION EXCEPTION SHORT BLOCK",
    (0x71, 0x00): "ASC=71h ASCQ=00h DECOMPRESSION EXCEPTION LONG BLOCK",
    (0x72, 0x00): "ASC=72h ASCQ=00h ONE OR MORE UNCORRECTABLE ERRORS",
    (0x73, 0x00): "ASC=73h ASCQ=00h FAILED RANDOMIZATION",
    (0x74, 0x00): "ASC=74h ASCQ=00h BLOCK SEQUENCING ERROR",
    (0x75, 0x00): "ASC=75h ASCQ=00h HARDWARE OVERRUN",
    (0x76, 0x00): "ASC=76h ASCQ=00h RATE MISMATCH",
    (0x77, 0x00): "ASC=77h ASCQ=00h DATA LENGTH ERROR",
    (0x78, 0x00): "ASC=78h ASCQ=00h IDENTIFY MESSAGE NOT FOUND",
    (0x79, 0x00): "ASC=79h ASCQ=00h UNSUPPORTED COMMAND RECEIVED",
    (0x7A, 0x00): "ASC=7Ah ASCQ=00h ILLEGAL WRITE TO DATA BLOCK PARTITION",
    (0x7B, 0x00): "ASC=7Bh ASCQ=00h LOGICAL BLOCK DECRC FAULT",
    (0x7C, 0x00): "ASC=7Ch ASCQ=00h LOGICAL BLOCK MISCOMPARISON",
    (0x7D, 0x00): "ASC=7Dh ASCQ=00h DEFECT LIST UPDATE FAILED",
    (0x7E, 0x00): "ASC=7Eh ASCQ=00h SPARE AREA ALLOCATION FAILURE",
    (0x7F, 0x00): "ASC=7Fh ASCQ=00h DEFECT LIST SHORT ERROR",
}


def _decode_format_unit(cdb, _data):
    flags2 = cdb[1]
    imm = (flags2 >> 1) & 1
    fmtdata = (flags2 >> 4) & 1
    return f"IMMED={imm}, FMTDATA={fmtdata}"


def _decode_inquiry(cdb, data):
    evpd = cdb[1] & 1
    page = cdb[2]
    if not data or len(data) < 5:
        return None
    if evpd:
        return f"VPD page 0x{page:02X}, {len(data)} bytes"
    if page != 0:
        return f"page={page} (non-standard)"
    pdt = data[0] & 0x1F
    removable = (data[1] & 0x80) != 0
    spc_ver = data[2]
    vendor = data[8:16].decode("ascii", errors="replace").strip()
    product = data[16:32].decode("ascii", errors="replace").strip()
    revision = data[32:36].decode("ascii", errors="replace").strip()
    return (
        f"PDT={PDT_NAMES.get(pdt, f'0x{pdt:02X}')}"
        f"{', Removable' if removable else ''}"
        f", SPC-{spc_ver - 2 if spc_ver >= 3 else spc_ver}"
        f", \"{vendor}\" \"{product}\" \"{revision}\""
    )


def _decode_read_capacity10(cdb, data):
    if not data or len(data) < 8:
        return None
    last_lba = struct.unpack(">I", data[0:4])[0]
    block_size = struct.unpack(">I", data[4:8])[0]
    return f"last_lba=0x{last_lba:08X} ({last_lba}), block_size={block_size}"


def _decode_read_capacity16(cdb, data):
    if not data or len(data) < 16:
        return None
    last_lba = struct.unpack(">Q", data[0:8])[0]
    block_size = struct.unpack(">I", data[8:12])[0]
    return f"last_lba=0x{last_lba:016X} ({last_lba}), block_size={block_size}"


def _decode_read_toc(cdb, data):
    msf = (cdb[1] & 0x02) != 0
    fmt = cdb[2] & 0x0F
    track = cdb[6]
    if not data or len(data) < 4:
        return None
    toc_len = (data[0] << 8) | data[1]
    first_track = data[2]
    last_track = data[3]
    parts = [f"fmt={fmt}", f"{'MSF' if msf else 'LBA'}"]
    if fmt == 0:
        parts.append(f"tracks {first_track}-{last_track}")
        descs = toc_len // 8
        for i in range(min(descs, 8)):
            off = 4 + i * 8
            if off + 8 > len(data):
                break
            ctrl = data[off + 1]
            trk = data[off + 2]
            if msf:
                m, s, f_ = data[off + 4], data[off + 5], data[off + 6]
                addr = f"{m:02d}:{s:02d}:{f_:02d}"
            else:
                addr = f"0x{(data[off+4]<<24|data[off+5]<<16|data[off+6]<<8|data[off+7]):08X}"
            is_lead_out = trk == 0xAA
            label = "lead-out" if is_lead_out else f"track {trk}"
            ctl_str = "data" if (ctrl & 0x04) else "audio"
            parts.append(f"{label}({ctl_str}) @ {addr}")
    elif fmt == 1:
        parts.append(f"first_session={first_track}, last_session={last_track}")
    return ", ".join(parts)


def _decode_get_configuration(cdb, data):
    rt = cdb[1] & 0x03
    start = (cdb[2] << 8) | cdb[3]
    rt_names = {0: "all", 1: "current", 2: f">=0x{start:04X}"}
    if not data or len(data) < 8:
        return f"RT={rt_names.get(rt, rt)}"
    data_len = struct.unpack(">I", data[0:4])[0]
    profile = (data[6] << 8) | data[7]
    profile_names = {
        0x0008: "CD-ROM", 0x0009: "CD-R", 0x000A: "CD-RW",
        0x0010: "DVD-ROM", 0x0011: "DVD-R sequential",
        0x0012: "DVD-RAM", 0x0013: "DVD-RW sequential",
        0x0014: "DVD-RW restricted overwrite", 0x0015: "DVD-R DL sequential",
        0x0016: "DVD-R DL layer jump", 0x001A: "DVD+RW", 0x001B: "DVD+R",
        0x0020: "DDCD-ROM", 0x0021: "DDCD-R", 0x0022: "DDCD-RW",
        0x0040: "BD-ROM", 0x0041: "BD-R SRM", 0x0042: "BD-R RRM",
        0x0043: "BD-RE", 0x0050: "HD DVD-ROM", 0x0051: "HD DVD-R",
        0x0052: "HD DVD-RAM",
        0x0102: "HD DVD-ROM", 0x0202: "MO read/write",
    }
    prof_str = profile_names.get(profile, f"0x{profile:04X}")
    # Decode feature descriptors
    features = []
    off = 8
    while off + 4 <= len(data) and off + 4 <= 8 + data_len:
        feat_code = (data[off] << 8) | data[off + 1]
        ver_cur = data[off + 2]
        add_len = data[off + 3]
        version = (ver_cur >> 2) & 0x03
        current = ver_cur & 1
        feat_names = {
            0x0001: "Core", 0x0002: "Morphing", 0x0003: "Removable",
            0x0010: "RandomReadable", 0x001D: "MultiRead",
            0x001E: "CDRead", 0x001F: "DVDRead",
            0x0020: "RandomWritable", 0x0021: "Incremental",
            0x0022: "SectorErasable", 0x0023: "Formattable",
            0x0024: "DefectManage", 0x0025: "WOPC",
            0x0026: "C2SV", 0x002D: "Packet",
            0x002E: "DVD+RPC", 0x002F: "DVD+RWSpeed",
            0x0030: "RigidRestricted", 0x0031: "CDTAO",
            0x0032: "CDMastering", 0x0033: "DVDRecordable",
        }
        name = feat_names.get(feat_code, f"Unknown")
        extra = ""
        if feat_code == 0x0010 and add_len >= 8 and off + 12 <= len(data):
            block_size = struct.unpack(">I", data[off + 4 : off + 8])[0]
            extra = f" blk_size={block_size}"
        elif feat_code == 0x0001 and add_len >= 8 and off + 12 <= len(data):
            phys = struct.unpack(">I", data[off + 4 : off + 8])[0]
            flags = data[off + 8] if off + 9 <= len(data) else 0
            extra = f" phys=0x{phys:08X} flags=0x{flags:02X}"
        cur = "*" if current else ""
        features.append(f"0x{feat_code:04X}{cur} {name} v{version}{extra}")
        off += 4 + add_len
        if add_len & 3:
            off += 4 - (add_len & 3)  # pad to 4-byte boundary
    parts = [f"profile={prof_str} (0x{profile:04X})", f"data_len={data_len}"]
    if features:
        parts.append(", ".join(features[:6]))
        if len(features) > 6:
            parts.append(f"... +{len(features) - 6} more")
    return ", ".join(parts)


def _decode_gesn(cdb, data):
    pol = cdb[1] & 0x0F
    class_req = (cdb[4] >> 4) & 0x0F
    if not data or len(data) < 4:
        return f"pol={pol}, class={class_req}"
    data_len = struct.unpack(">I", data[0:4])[0]
    if len(data) < 8:
        return f"data_len={data_len}"
    supported = (data[5] >> 4) & 0x0F
    classes = []
    class_names = {0: "None", 1: "OpChange", 2: "PowerChange", 3: "ExtChange", 4: "MediaChange", 5: "Busy"}
    for i in range(4):
        if supported & (1 << i):
            classes.append(class_names.get(i, f"class {i}"))
    return f"supported=[{', '.join(classes)}]" if classes else "supported=[none]"


def _decode_read_disc_info(cdb, data):
    dtype = cdb[1] & 0x07
    if not data or len(data) < 4:
        return None
    info_len = (data[0] << 8) | data[1]
    state = data[2]
    state_str = ["empty", "appendable", "complete", "other"][state & 0x03] if state & 0x03 <= 3 else f"0x{state & 3:X}"
    erasable = "erasable" if (state & 0x08) else "non-erasable"
    return f"info_len={info_len}, state={state_str}, {erasable}"


def _decode_read_track_info(cdb, data):
    addr_type = (cdb[1] >> 3) & 0x01
    track_num = (cdb[2] << 8) | cdb[3]
    if not data or len(data) < 36:
        return f"track={track_num}"
    info_len = (data[0] << 8) | data[1]
    start_lba = struct.unpack(">I", data[8:12])[0]
    next_writable = struct.unpack(">I", data[12:16])[0]
    track_size = struct.unpack(">I", data[20:24])[0]
    return f"track={track_num}, start_lba=0x{start_lba:08X}, size={track_size}, next_writable=0x{next_writable:08X}"


def _decode_read_format_cap(cdb, data):
    if not data or len(data) < 4:
        return None
    # MMC-6 / SFF-8070i format:
    # Header: 3 reserved bytes + 1-byte capacity list length
    # Descriptor (8 bytes each): blocks(4B BE) + code(1B) + reserved(1B) + blocksize(2B BE)
    cap_len = data[3]
    descs = []
    off = 4
    while off + 8 <= len(data) and off - 4 < cap_len:
        num_blocks = struct.unpack(">I", data[off:off+4])[0]
        code = data[off+4]
        block_size = struct.unpack(">H", data[off+6:off+8])[0]
        code_names = {0x01: "current", 0x02: "formattable", 0x03: "no_media"}
        # Handle DVD+RW format type (bits 7..2, code << 2)
        if code & 0xFC == (0x26 << 2):
            desc = f"current: {num_blocks} × {block_size}B, DVD+RW format (0x{code:02X})"
        else:
            desc = f"{code_names.get(code, f'code=0x{code:02X}')}: {num_blocks} × {block_size}B"
        descs.append(desc)
        off += 8
    return ", ".join(descs) if descs else f"cap_len={cap_len}"


def _decode_send_opc(cdb, data):
    return None  # no meaningful decode


def _decode_read_buf_cap(cdb, data):
    if not data or len(data) < 18:
        return None
    data_len = (data[0] << 8) | data[1]
    block_size = struct.unpack(">I", data[4:8])[0]
    blocks_available = struct.unpack(">I", data[8:12])[0]
    return f"block_size={block_size}, blocks_available={blocks_available}"


def _decode_mode_sense(cdb, data, is_10):
    if not data or len(data) < 1:
        return None
    if is_10:
        mode_len = (data[0] << 8) | data[1]
        medium = data[3]
    else:
        mode_len = data[0]
        medium = data[1] if len(data) > 1 else 0
    parts = [f"mode_len={mode_len}"]
    if medium:
        parts.append(f"medium=0x{medium:02X}")
    # decode pages present
    pages = []
    off = 4 if not is_10 else 8
    while off + 2 <= len(data) and off <= mode_len + (4 if not is_10 else 8):
        page = data[off] & 0x3F
        ps = (data[off] & 0x80) != 0
        page_len = data[off + 1] if off + 1 < len(data) else 0
        page_names = {0x00: "Vendor", 0x01: "RW Error", 0x05: "NOfReadRetry", 0x08: "Caching", 0x0A: "Control"}
        name = page_names.get(page, f"page 0x{page:02X}")
        extra = ""
        if page == 0x08 and page_len >= 16 and off + 18 <= len(data):
            cached = (data[off + 2] & 0x04) == 0
            dra = (data[off + 2] & 0x20) != 0
            wce = (data[off + 2] & 0x08) != 0
            extra = f" [WCE={int(wce)}, RCD={int(cached)}, DRA={int(dra)}]"
        pages.append(f"{name}({page_len}B){extra}" if extra else f"{name}({page_len}B)")
        off += 2 + page_len
    if pages:
        parts.append("pages: " + ", ".join(pages[:5]))
    return ", ".join(parts)


def _decode_report_luns(cdb, data):
    if not data or len(data) < 8:
        return None
    list_len = struct.unpack(">I", data[0:4])[0]
    num_luns = list_len // 8
    return f"LUN count={num_luns}"


def _decode_get_performance(cdb, data):
    perf_type = cdb[1] & 0xFF
    if not data or len(data) < 4:
        return f"type={perf_type}"
    data_len = struct.unpack(">I", data[0:4])[0]
    descs = data_len // 16
    return f"type={perf_type}, descriptors={descs}"


def _decode_read_dvd_struct(cdb, data):
    fmt = cdb[7]
    if not data or len(data) < 4:
        return f"format=0x{fmt:02X}"
    data_len = struct.unpack(">I", data[0:4])[0]
    fmt_names = {
        0x00: "DVD-ROM", 0x01: "DVD-RAM", 0x02: "DVD-R/RO",
        0x03: "DVD-R/RW", 0x04: "DVD+RW", 0x05: "DVD+R",
    }
    return f"format={fmt_names.get(fmt, f'0x{fmt:02X}')}, data_len={data_len}"


def _decode_sync_cache(cdb, data):
    lba = cdb_lba10(cdb)
    count = cdb_transfer_len10(cdb)
    return f"LBA=0x{lba:08X}, count={count}"


def _decode_set_cd_speed(cdb, _data):
    speed_rd = (cdb[2] << 8) | cdb[3]
    speed_wr = (cdb[4] << 8) | cdb[5]
    return f"read_speed={speed_rd * 150}KB/s, write_speed={speed_wr * 150}KB/s"


def _decode_read_write_common(cdb, size):
    lba = cdb_lba10(cdb)
    count = cdb_transfer_len10(cdb)
    total = count * size if count and size else 0
    return f"LBA=0x{lba:08X}, count={count}, {total}B"


def _decode_read6(cdb, _data):
    lba = cdb_lba6(cdb)
    count = cdb_transfer_len6(cdb)
    return f"LBA=0x{lba:08X}, count={count}, {count * 2048}B"


def _decode_read10(cdb, _data):
    return _decode_read_write_common(cdb, 2048)


def _decode_write10(cdb, _data):
    return _decode_read_write_common(cdb, 2048)


def _decode_read12(cdb, _data):
    lba = cdb_lba12(cdb)
    count = cdb_transfer_len12(cdb)
    return f"LBA=0x{lba:08X}, count={count}, {count * 2048}B"


def _decode_write12(cdb, _data):
    return _decode_read12(cdb, _data)


def _decode_read16(cdb, _data):
    lba = cdb_lba16(cdb)
    count = cdb_transfer_len16(cdb)
    return f"LBA=0x{lba:016X}, count={count}, {count * 2048}B"


def _decode_write16(cdb, _data):
    return _decode_read16(cdb, _data)


def _decode_start_stop(cdb, _data):
    loej = (cdb[4] >> 1) & 1
    load = cdb[4] & 1
    return f"LoEj={loej}, Start={load}"


def _decode_prevent_allow(cdb, _data):
    prevent = cdb[4] & 0x03
    return f"prevent={prevent}"


def _decode_service_action_in(cdb, data):
    sa = cdb[1] & 0x1F
    if sa == 0x10:
        return _decode_read_capacity16(cdb, data)
    return f"SA=0x{sa:02X}"


# ── Opcode table ────────────────────────────────────────────────

OPCODE_TABLE = {
    0x00: ("TEST_UNIT_READY",            6,  _noop),
    0x03: ("REQUEST_SENSE",              6,  _decode_request_sense),
    0x04: ("FORMAT_UNIT",                6,  _decode_format_unit),
    0x08: ("READ_6",                     6,  _decode_read6),
    0x0A: ("WRITE_6",                    6,  _decode_read6),  # same format
    0x12: ("INQUIRY",                    6,  _decode_inquiry),
    0x15: ("MODE_SELECT_6",             6,  _noop),
    0x16: ("RESERVE_6",                 6,  _noop),
    0x17: ("RELEASE_6",                 6,  _noop),
    0x1A: ("MODE_SENSE_6",             6,  lambda c, d: _decode_mode_sense(c, d, False)),
    0x1B: ("START_STOP_UNIT",           6,  _decode_start_stop),
    0x1C: ("RECEIVE_DIAGNOSTIC",        6,  _noop),
    0x1D: ("SEND_DIAGNOSTIC",           6,  _noop),
    0x1E: ("PREVENT_ALLOW",             6,  _decode_prevent_allow),
    0x23: ("READ_FORMAT_CAPACITIES",    10, _decode_read_format_cap),
    0x25: ("READ_CAPACITY_10",          10, _decode_read_capacity10),
    0x28: ("READ_10",                   10, _decode_read10),
    0x2A: ("WRITE_10",                  10, _decode_write10),
    0x35: ("SYNCHRONIZE_CACHE_10",      10, _decode_sync_cache),
    0x43: ("READ_TOC",                  10, _decode_read_toc),
    0x46: ("GET_CONFIGURATION",         10, _decode_get_configuration),
    0x4A: ("GET_EVENT_STATUS_NOTIF",    10, _decode_gesn),
    0x51: ("READ_DISC_INFORMATION",     10, _decode_read_disc_info),
    0x52: ("READ_TRACK_INFORMATION",    10, _decode_read_track_info),
    0x54: ("SEND_OPC_INFORMATION",      10, _decode_send_opc),
    0x55: ("MODE_SELECT_10",            10, _noop),
    0x5A: ("MODE_SENSE_10",             10, lambda c, d: _decode_mode_sense(c, d, True)),
    0x5B: ("CLOSE_TRACK",               10, _noop),
    0x5C: ("READ_BUFFER_CAPACITY",      10, _decode_read_buf_cap),
    0x88: ("READ_16",                   16, _decode_read16),
    0x8A: ("WRITE_16",                  16, _decode_write16),
    0x9E: ("SERVICE_ACTION_IN",         16, _decode_service_action_in),
    0xA0: ("REPORT_LUNS",               12, _decode_report_luns),
    0xA8: ("READ_12",                   12, _decode_read12),
    0xAA: ("WRITE_12",                  12, _decode_write12),
    0xAC: ("GET_PERFORMANCE",           12, _decode_get_performance),
    0xAD: ("READ_DVD_STRUCTURE",        12, _decode_read_dvd_struct),
    0xB6: ("SET_STREAMING",             12, _noop),
    0xBB: ("SET_CD_SPEED",              12, _decode_set_cd_speed),
}


def cdb_len_from_opcode(opcode):
    """SPC-4 §7.3: group -> fixed CDB length."""
    group = (opcode >> 5) & 0x07
    if group == 0:
        return 6
    elif group in (1, 2):
        return 10
    elif group == 4:
        return 16
    elif group == 5:
        return 12
    return 6


def decode_cdb(opcode, cdb, data):
    """Return (name, details_str) for a CDB."""
    entry = OPCODE_TABLE.get(opcode)
    if entry:
        name, _expected_len, decoder = entry
        details = decoder(cdb, data)
        return name, details
    group = (opcode >> 5) & 0x07
    clen = cdb_len_from_opcode(opcode)
    return f"UNKNOWN(0x{opcode:02X})", f"group={group}, cdb_len={clen}"


# ═══════════════════════════════════════════════════════════════════
# §5  Payload decoders (post-CSW decoding of data_in)
# ═══════════════════════════════════════════════════════════════════

# §5 is folded into §4: each decoder receives both cdb and data.


# ═══════════════════════════════════════════════════════════════════
# §6  Output formatters
# ═══════════════════════════════════════════════════════════════════

ANSI_RESET = "\033[0m"
ANSI_BOLD = "\033[1m"
ANSI_DIM = "\033[2m"
ANSI_RED = "\033[31m"
ANSI_GREEN = "\033[32m"
ANSI_YELLOW = "\033[33m"
ANSI_CYAN = "\033[36m"
ANSI_MAGENTA = "\033[35m"


def fmt_status(status, color=True):
    if not color:
        return status
    if status == "GOOD":
        return f"{ANSI_GREEN}{status}{ANSI_RESET}"
    elif status == "FAILED":
        return f"{ANSI_RED}{ANSI_BOLD}{status}{ANSI_RESET}"
    elif status == "PHASE_ERROR":
        return f"{ANSI_YELLOW}{status}{ANSI_RESET}"
    return status


def fmt_direction(d, color=True):
    if not color:
        return d
    return f"{ANSI_CYAN}{d}{ANSI_RESET}"


def fmt_name(name, color=True):
    if not color:
        return name
    return f"{ANSI_BOLD}{name}{ANSI_RESET}"


def fmt_details(details, color=True):
    if not details:
        return "—"
    if color:
        return f"{ANSI_DIM}{details}{ANSI_RESET}"
    return details


def fmt_frame(n, color=True):
    s = f"#{n:<5d}"
    if color:
        return f"{ANSI_BOLD}{s}{ANSI_RESET}"
    return s


def format_table(transactions, color=True):
    lines = []
    hdr = f"{'#':<6s} {'Time':>10s}  {'Command':<28s} {'LUN':>3s}  {'Dir':>4s}  {'Status':<14s}  {'Details'}"
    if color:
        hdr = f"{ANSI_BOLD}{hdr}{ANSI_RESET}"
    lines.append(hdr)
    lines.append("─" * 120)
    for t in transactions:
        cbw = t.cbw
        opcode = cbw.cdb[0]
        name, _ = decode_cdb(opcode, cbw.cdb, t.data_in)
        data_desc = ""
        if cbw.data_len > 0:
            if cbw.direction == "IN":
                data_desc = f"[{cbw.data_len}→] "
            else:
                data_desc = f"[←{cbw.data_len}] "

        details = data_desc + (t._decoded_details or "")
        line = (
            f"{fmt_frame(cbw.frame, color):<17s}"
            f"{cbw.time:>10.6f}  "
            f"{fmt_name(f'{name} (0x{opcode:02X})', color):<40s}"
            f"{cbw.lun:>3d}  "
            f"{fmt_direction(cbw.direction, color):>4s}  "
            f"{fmt_status(t.csw_status, color):<23s}  "
            f"{fmt_details(details.strip(), color)}"
        )
        lines.append(line)
    return "\n".join(lines)


def format_json(transactions):
    out = []
    for t in transactions:
        cbw = t.cbw
        opcode = cbw.cdb[0]
        name, _ = decode_cdb(opcode, cbw.cdb, t.data_in)
        obj = {
            "frame": cbw.frame,
            "time": round(cbw.time, 6),
            "opcode": name,
            "opcode_hex": f"0x{opcode:02X}",
            "lun": cbw.lun,
            "direction": cbw.direction,
            "data_len": cbw.data_len,
            "csw_status": t.csw_status,
            "csw_residue": t.csw_residue,
            "cdb_hex": cbw.cdb.hex(),
        }
        if t._decoded_details:
            obj["details"] = t._decoded_details
        out.append(obj)
    return json.dumps(out, indent=2)


def format_csv(transactions):
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["frame", "time", "opcode", "opcode_hex", "lun", "direction", "data_len", "csw_status", "csw_residue", "details"])
    for t in transactions:
        cbw = t.cbw
        opcode = cbw.cdb[0]
        name, _ = decode_cdb(opcode, cbw.cdb, t.data_in)
        writer.writerow([
            cbw.frame, f"{cbw.time:.6f}", name, f"0x{opcode:02X}",
            cbw.lun, cbw.direction, cbw.data_len, t.csw_status,
            t.csw_residue, t._decoded_details or "",
        ])
    return buf.getvalue()


# ═══════════════════════════════════════════════════════════════════
# §7  CLI + main
# ═══════════════════════════════════════════════════════════════════


def process_capture(path, args):
    """Parse pcapng, correlate BOT transactions, decode SCSI commands."""
    pending = {}  # tag -> Transaction (with accumulated data)
    completed = []
    frame_num = 0
    first_ts = None
    last_failed = None  # last FAILED transaction for REQUEST SENSE correlation

    for ts_sec, pkt in parse_pcapng(path):
        if first_ts is None:
            first_ts = ts_sec
        frame_num += 1
        hdr = parse_usbpcap_header(pkt)
        if hdr is None or hdr["transfer"] != 3:
            continue

        data_off = hdr["data_offset"]
        payload = pkt[data_off:]
        payload_len = hdr["data_length"]

        # Only process full bulk transfers (not partial URB fragments)
        actual_payload = payload[:min(len(payload), payload_len)] if payload_len > 0 else payload

        # Try CBW
        cbw = try_parse_cbw(pkt, hdr)
        if cbw:
            cbw.frame = frame_num
            cbw.time = ts_sec - first_ts
            txn = Transaction(cbw=cbw)
            pending[cbw.tag] = txn
            continue

        # Try CSW
        csw = try_parse_csw(pkt, hdr)
        if csw:
            tag, residue, status = csw
            txn = pending.pop(tag, None)
            if txn is None:
                # CSW without matching CBW — skip
                continue
            txn.csw_tag = tag
            txn.csw_residue = residue
            txn.csw_status = status
            # Decode details from payload
            opcode = txn.cbw.cdb[0]
            name, details = decode_cdb(opcode, txn.cbw.cdb, b"")
            # Only decode actual payload for commands where data is meaningful
            _DATA_OPCODES = {0x08, 0x0A, 0x28, 0x2A, 0x88, 0x8A, 0xA8, 0xAA, 0x00, 0x1B, 0x1E, 0x35}
            if opcode not in _DATA_OPCODES:
                payload = txn.data_in if txn.cbw.direction == "IN" else txn.data_out
                _, details = decode_cdb(opcode, txn.cbw.cdb, payload)
            # Mark CHECK CONDITION on FAILED CSW
            if status == "FAILED":
                txn._decoded_details = (details or "") + " ⚠ CHECK CONDITION"
                last_failed = txn
            else:
                txn._decoded_details = details or ""
            # Correlate REQUEST SENSE with preceding FAILED command
            if opcode == 0x03 and last_failed is not None:  # REQUEST_SENSE
                lf = last_failed
                lf_name, _ = decode_cdb(lf.cbw.cdb[0], lf.cbw.cdb, b"")
                sense_detail = f" ← sense for #{lf.cbw.frame} {lf_name}"
                if txn._decoded_details:
                    txn._decoded_details += sense_detail
                else:
                    txn._decoded_details = sense_detail
                last_failed = None  # consumed
            # Apply filters
            if args.lun is not None and txn.cbw.lun != args.lun:
                continue
            if args.opcode is not None and opcode != args.opcode:
                continue
            if args.direction is not None and txn.cbw.direction.lower() != args.direction.lower():
                continue
            if args.no_payload:
                txn._decoded_details = ""
            completed.append(txn)
            last_tag = tag
            continue

        # Data phase — accumulate into pending transaction
        if hdr["direction"] == "IN":
            # Data-In: accumulate into the most recent pending IN transaction
            for tag_val in list(pending.keys()):
                txn = pending[tag_val]
                if txn.cbw.direction == "IN":
                    # check if this data is for this transaction (by endpoint, etc.)
                    txn.data_in += bytes(actual_payload)
                    break
        elif hdr["direction"] == "OUT":
            for tag_val in list(pending.keys()):
                txn = pending[tag_val]
                if txn.cbw.direction == "OUT":
                    txn.data_out += bytes(actual_payload)
                    break

    return completed


def main():
    parser = argparse.ArgumentParser(
        description="SCSI over USB BOT pcapng analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("pcap", nargs="?", default=None, help="pcapng file to analyze")
    parser.add_argument(
        "--selftest", action="store_true",
        help="Run built-in tests and exit",
    )
    parser.add_argument(
        "--format", choices=["table", "json", "csv"],
        default="table", help="Output format (default: table)",
    )
    parser.add_argument("--lun", type=int, default=None, help="Filter to LUN N")
    parser.add_argument(
        "--direction", choices=["in", "out"], default=None,
        help="Filter by CBW direction (Data-In or Data-Out)",
    )
    parser.add_argument(
        "--opcode", type=lambda x: int(x, 0), default=None,
        help="Filter by hex opcode (e.g. 0x43)",
    )
    parser.add_argument(
        "--no-payload", action="store_true",
        help="Don't decode data-phase payload (just show sizes)",
    )
    parser.add_argument("--show-cbw", action="store_true", help="Dump raw CBW bytes")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI colors")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")

    args = parser.parse_args()

    if args.selftest:
        print("tests moved to tools/tests/usbms_pcap_test.py", file=sys.stderr)
        sys.exit(1)

    if not args.pcap:
        parser.error("the following arguments are required: pcap")

    if not os.path.isfile(args.pcap):
        print(f"error: file not found: {args.pcap}", file=sys.stderr)
        sys.exit(1)

    use_color = not args.no_color and sys.stdout.isatty()

    transactions = process_capture(args.pcap, args)

    if args.format == "json":
        print(format_json(transactions))
    elif args.format == "csv":
        print(format_csv(transactions), end="")
    else:
        print(format_table(transactions, color=use_color))
        total = len(transactions)
        good = sum(1 for t in transactions if t.csw_status == "GOOD")
        failed = sum(1 for t in transactions if t.csw_status == "FAILED")
        pe = sum(1 for t in transactions if t.csw_status == "PHASE_ERROR")
        if use_color:
            print(
                f"\n{total} transactions: "
                f"{ANSI_GREEN}{good} GOOD{ANSI_RESET}, "
                f"{ANSI_RED}{failed} FAILED{ANSI_RESET}"
                f"{f', {ANSI_YELLOW}{pe} PHASE_ERROR{ANSI_RESET}' if pe else ''}"
            )
        else:
            print(f"\n{total} transactions: {good} GOOD, {failed} FAILED" + (f", {pe} PHASE_ERROR" if pe else ""))


if __name__ == "__main__":
    main()
