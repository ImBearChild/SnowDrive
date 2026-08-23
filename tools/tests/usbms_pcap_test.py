#!/usr/bin/env python3
"""Integration tests for usbms-pcap.py.

Generates synthetic USBPcap pcapng captures in-memory and verifies
the full parsing pipeline: pcapng → USBPcap → BOT → SCSI → decode.

Usage:
    python3 tests/usbms_pcap_test.py          # run all tests
    python3 usbms-pcap.py --selftest          # same via main script
"""

import argparse
import io
import json
import os
import struct
import sys
import tempfile

# Import the module under test
sys.path.insert(0, os.path.dirname(__file__))
import importlib.util
_spec = importlib.util.spec_from_file_location(
    "usbms_pcap", os.path.join(os.path.dirname(__file__), "..", "usbms-pcap.py")
)
_m = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_m)

# Re-export the public API we test
parse_pcapng = _m.parse_pcapng
parse_usbpcap_header = _m.parse_usbpcap_header
try_parse_cbw = _m.try_parse_cbw
try_parse_csw = _m.try_parse_csw
process_capture = _m.process_capture
format_table = _m.format_table
format_json = _m.format_json
format_csv = _m.format_csv
PCAPNG_MAGIC = _m.PCAPNG_MAGIC
EPB_TYPE = _m.EPB_TYPE
IDB_TYPE = _m.IDB_TYPE


# ═══════════════════════════════════════════════════════════════════
# Test infrastructure
# ═══════════════════════════════════════════════════════════════════

class _TestFailure(Exception):
    pass


def _check(condition, msg=""):
    if not condition:
        raise _TestFailure(msg)


# ── Synthetic pcapng builder ─────────────────────────────────────

def _build_pcapng(frames):
    """Build a minimal USBPcap pcapng in memory.

    `frames` is a list of (direction, data_bytes) tuples.
    direction: "OUT" or "IN".
    Each frame becomes one Enhanced Packet Block with a 27-byte USBPcap header.
    Returns the raw pcapng bytes.
    """
    buf = io.BytesIO()

    def _write_block(block_type, body):
        total = 12 + len(body)
        buf.write(struct.pack("<II", block_type, total))
        buf.write(body)
        buf.write(struct.pack("<I", total))

    # Section Header Block
    _write_block(PCAPNG_MAGIC, struct.pack("<IHBB", 0x00000001, 1, 0, 0))
    # Interface Description Block (link type 220)
    _write_block(IDB_TYPE, struct.pack("<HHI", 220, 0, 65535))

    ts = 1_000_000_000  # base timestamp (seconds * 1e6 for microsecond)
    for direction, data in frames:
        data_len = len(data)
        hdr = struct.pack("<H", 27)  # headerLen
        hdr += b"\x00" * 8           # irpId
        hdr += struct.pack("<I", 0)  # status
        hdr += struct.pack("<H", 0x0009)  # function = bulk
        hdr += struct.pack("B", 1 if direction == "IN" else 0)  # info
        hdr += struct.pack("<HH", 1, 2)  # bus, device
        hdr += struct.pack("B", 0x82 if direction == "IN" else 0x02)  # endpoint
        hdr += struct.pack("B", 3)  # transfer = bulk
        hdr += struct.pack("<I", data_len)
        pkt = hdr + data

        cap_len = len(pkt)
        epb_body = struct.pack("<IIII", 0, ts >> 32, ts & 0xFFFFFFFF, cap_len)
        epb_body += struct.pack("<I", cap_len)
        epb_body += pkt
        _write_block(EPB_TYPE, epb_body)
        ts += 1  # increment by 1 microsecond

    return buf.getvalue()


def _cbw(tag, data_len, direction, lun, cdb):
    """Build a raw 31-byte CBW."""
    flags = 0x80 if direction == "IN" else 0x00
    raw = struct.pack("<II", 0x43425355, tag)
    raw += struct.pack("<I", data_len)
    raw += struct.pack("B", flags)
    raw += struct.pack("B", lun)
    raw += struct.pack("B", len(cdb))
    raw += cdb.ljust(16, b"\x00")
    return raw


def _csw(tag, residue, status):
    """Build a raw 13-byte CSW."""
    status_byte = {"GOOD": 0, "FAILED": 1, "PHASE_ERROR": 2}[status]
    raw = struct.pack("<II", 0x53425355, tag)
    raw += struct.pack("<I", residue)
    raw += struct.pack("B", status_byte)
    return raw


def _run(pcap_bytes, **kwargs):
    """Write pcap to temp file and run process_capture."""
    with tempfile.NamedTemporaryFile(suffix=".pcapng", delete=False) as f:
        f.write(pcap_bytes)
        path = f.name
    try:
        ns = argparse.Namespace(
            lun=kwargs.get("lun"),
            direction=kwargs.get("direction"),
            opcode=kwargs.get("opcode"),
            no_payload=kwargs.get("no_payload", False),
        )
        return process_capture(path, ns)
    finally:
        os.unlink(path)


# Helper: parse pcapng from raw bytes
def _read_blocks_from_bytes(data):
    f = io.BytesIO(data)
    while True:
        hdr = f.read(8)
        if len(hdr) < 8:
            break
        block_type, block_len = struct.unpack("<II", hdr)
        if block_len < 12:
            break
        body = f.read(block_len - 12)
        _trailer = f.read(4)
        if len(body) != block_len - 12:
            break
        yield block_type, body


def _parse_pcapng_bytes(data):
    for btype, body in _read_blocks_from_bytes(data):
        if btype == EPB_TYPE:
            if len(body) < 20:
                continue
            _if_id, ts_high, ts_low, cap_len, _orig_len = struct.unpack("<IIIII", body[:20])
            ts_sec = ((ts_high << 32) | ts_low) / 1_000_000.0
            pkt = body[20 : 20 + cap_len]
            if len(pkt) >= 27:
                yield ts_sec, pkt


# ═══════════════════════════════════════════════════════════════════
# Test cases
# ═══════════════════════════════════════════════════════════════════

def _test_pcapng_parse():
    """pcapng block parsing yields correct packet count."""
    frames = [
        ("OUT", _cbw(1, 0, "OUT", 0, bytes(6))),
        ("IN", _csw(1, 0, "GOOD")),
    ]
    pcap = _build_pcapng(frames)
    blocks = list(_read_blocks_from_bytes(pcap))
    _check(len(blocks) == 4, f"expected 4 blocks (SHB+IDB+2 EPB), got {len(blocks)}")


def _test_usbpcap_header():
    """USBPcap header decode returns correct direction and data_length."""
    pkt = _build_pcapng([("IN", b"\x00" * 10)])
    for _ts, raw_pkt in _parse_pcapng_bytes(pkt):
        hdr = parse_usbpcap_header(raw_pkt)
        _check(hdr is not None, "header is None")
        _check(hdr["direction"] == "IN", f"direction={hdr['direction']}")
        _check(hdr["data_length"] == 10, f"data_length={hdr['data_length']}")
        _check(hdr["transfer"] == 3, f"transfer={hdr['transfer']}")


def _test_cbw_parse():
    """CBW signature, tag, direction, lun, opcode parsed correctly."""
    cdb = bytes([0x28, 0, 0, 0, 0, 0, 0, 0, 1, 0])  # READ(10)
    raw = _cbw(0xDEADBEEF, 512, "IN", 3, cdb)
    pkt = _build_pcapng([("OUT", raw)])
    for _ts, raw_pkt in _parse_pcapng_bytes(pkt):
        hdr = parse_usbpcap_header(raw_pkt)
        cbw = try_parse_cbw(raw_pkt, hdr)
        _check(cbw is not None, "CBW parse failed")
        _check(cbw.tag == 0xDEADBEEF, f"tag={cbw.tag:#x}")
        _check(cbw.direction == "IN", f"dir={cbw.direction}")
        _check(cbw.lun == 3, f"lun={cbw.lun}")
        _check(cbw.cdb[0] == 0x28, f"opcode={cbw.cdb[0]:#x}")
        _check(cbw.data_len == 512, f"data_len={cbw.data_len}")


def _test_csw_parse():
    """CSW signature, tag, residue, status parsed correctly."""
    raw = _csw(0xCAFEBABE, 128, "FAILED")
    pkt = _build_pcapng([("IN", raw)])
    for _ts, raw_pkt in _parse_pcapng_bytes(pkt):
        hdr = parse_usbpcap_header(raw_pkt)
        csw = try_parse_csw(raw_pkt, hdr)
        _check(csw is not None, "CSW parse failed")
        tag, residue, status = csw
        _check(tag == 0xCAFEBABE, f"tag={tag:#x}")
        _check(residue == 128, f"residue={residue}")
        _check(status == "FAILED", f"status={status}")


def _test_cbw_rejects_bad_signature():
    """CBW with wrong signature is rejected."""
    raw = bytearray(_cbw(1, 0, "OUT", 0, bytes(6)))
    raw[0] = 0xFF  # corrupt signature
    pkt = _build_pcapng([("OUT", bytes(raw))])
    for _ts, raw_pkt in _parse_pcapng_bytes(pkt):
        hdr = parse_usbpcap_header(raw_pkt)
        cbw = try_parse_cbw(raw_pkt, hdr)
        _check(cbw is None, "bad signature should return None")


def _test_csw_rejects_bad_signature():
    """CSW with wrong signature is rejected."""
    raw = bytearray(_csw(1, 0, "GOOD"))
    raw[0] = 0xFF
    pkt = _build_pcapng([("IN", bytes(raw))])
    for _ts, raw_pkt in _parse_pcapng_bytes(pkt):
        hdr = parse_usbpcap_header(raw_pkt)
        csw = try_parse_csw(raw_pkt, hdr)
        _check(csw is None, "bad signature should return None")


def _test_full_good_transaction():
    """Full CBW→Data→CSW round-trip with GOOD status."""
    cdb = bytes([0x12, 0, 0, 0, 96, 0])  # INQUIRY, alloc=96
    inquiry_resp = bytes(range(95))  # 95-byte INQUIRY response
    frames = [
        ("OUT", _cbw(1, 96, "IN", 0, cdb)),
        ("IN", inquiry_resp),
        ("IN", _csw(1, 1, "GOOD")),  # residue=1 because 95 < 96
    ]
    txns = _run(_build_pcapng(frames))
    _check(len(txns) == 1, f"expected 1 txn, got {len(txns)}")
    t = txns[0]
    _check(t.cbw.cdb[0] == 0x12, f"opcode={t.cbw.cdb[0]:#x}")
    _check(t.csw_status == "GOOD", f"status={t.csw_status}")
    _check(t.csw_residue == 1, f"residue={t.csw_residue}")
    _check(len(t.data_in) == 95, f"data_in len={len(t.data_in)}")


def _test_failed_csw_check_condition():
    """FAILED CSW triggers CHECK CONDITION marker."""
    frames = [
        ("OUT", _cbw(1, 0, "OUT", 0, bytes([0x00] * 6))),  # TEST UNIT READY
        ("IN", _csw(1, 0, "FAILED")),
    ]
    txns = _run(_build_pcapng(frames))
    _check(len(txns) == 1)
    _check(txns[0].csw_status == "FAILED")
    _check("CHECK CONDITION" in txns[0]._decoded_details, txns[0]._decoded_details)


def _test_unit_attention_correlation():
    """REQUEST SENSE after FAILED CSW correlates with preceding command."""
    frames = [
        ("OUT", _cbw(1, 0, "OUT", 0, bytes([0x00] * 6))),  # TUR → FAILED
        ("IN", _csw(1, 0, "FAILED")),
        ("OUT", _cbw(2, 18, "IN", 0, bytes([0x03, 0, 0, 0, 18, 0]))),  # REQUEST SENSE
        ("IN", bytes([0x70, 0, 0x06, 0, 0, 0, 0, 0x0A, 0, 0, 0, 0, 0x29, 0, 0, 0, 0, 0])),
        ("IN", _csw(2, 0, "GOOD")),
        ("OUT", _cbw(3, 0, "OUT", 0, bytes([0x00] * 6))),  # TUR → GOOD (UA cleared)
        ("IN", _csw(3, 0, "GOOD")),
    ]
    txns = _run(_build_pcapng(frames))
    _check(len(txns) == 3, f"expected 3, got {len(txns)}")
    # txn[0]: TUR FAILED
    _check(txns[0].csw_status == "FAILED")
    _check("CHECK CONDITION" in txns[0]._decoded_details)
    # txn[1]: REQUEST SENSE with correlation
    _check(txns[1].cbw.cdb[0] == 0x03)
    _check("Unit Attention" in txns[1]._decoded_details, txns[1]._decoded_details)
    _check("29h" in txns[1]._decoded_details, txns[1]._decoded_details)
    _check("← sense for #1" in txns[1]._decoded_details, txns[1]._decoded_details)
    # txn[2]: TUR GOOD
    _check(txns[2].csw_status == "GOOD")


def _test_inquiry_decoder():
    """INQUIRY standard data decoded correctly."""
    cdb = bytes([0x12, 0, 0, 0, 96, 0])
    data = bytearray(95)
    data[0] = 0x05  # PDT = CD-ROM
    data[1] = 0x80  # removable
    data[2] = 0x06  # SPC-4
    data[4] = 91    # additional length
    data[8:16] = b"TESTVEND"
    data[16:32] = b"Test Product     "
    data[32:36] = b"1.00"
    frames = [
        ("OUT", _cbw(1, 96, "IN", 0, cdb)),
        ("IN", bytes(data)),
        ("IN", _csw(1, 0, "GOOD")),
    ]
    txns = _run(_build_pcapng(frames))
    d = txns[0]._decoded_details
    _check("CD-ROM" in d, d)
    _check("Removable" in d, d)
    _check("TESTVEND" in d, d)
    _check("Test Product" in d, d)
    _check("1.00" in d, d)


def _test_read_capacity10_decoder():
    """READ CAPACITY(10) response decoded correctly."""
    cdb = bytes([0x25, 0, 0, 0, 0, 0, 0, 0, 0, 0])
    data = struct.pack(">II", 0x00018FFF, 2048)  # last_lba, block_size
    frames = [
        ("OUT", _cbw(1, 8, "IN", 0, cdb)),
        ("IN", data),
        ("IN", _csw(1, 0, "GOOD")),
    ]
    txns = _run(_build_pcapng(frames))
    d = txns[0]._decoded_details
    _check("0x00018FFF" in d, d)
    _check("2048" in d, d)


def _test_read_toc_decoder():
    """READ TOC format 0 decoded correctly."""
    cdb = bytes([0x43, 0, 0, 0, 0, 0, 0, 0xFF, 0, 0])  # fmt=0, alloc=255
    data = bytearray(20)
    data[1] = 0x12   # data length = 18
    data[2] = 1      # first track
    data[3] = 1      # last track
    # Track 1 descriptor at offset 4
    data[5] = 0x14   # ADR=1, CONTROL=4 (data)
    data[6] = 1      # track number
    # Lead-out descriptor at offset 12
    data[13] = 0x14
    data[14] = 0xAA
    data[17] = 0      # lead-out LBA MSB
    data[18] = 0
    data[19] = 0x64   # lead-out LBA = 100
    frames = [
        ("OUT", _cbw(1, 256, "IN", 0, cdb)),
        ("IN", bytes(data)),
        ("IN", _csw(1, 0, "GOOD")),
    ]
    txns = _run(_build_pcapng(frames))
    d = txns[0]._decoded_details
    _check("fmt=0" in d, d)
    _check("tracks 1-1" in d, d)
    _check("lead-out" in d, d)


def _test_format_unit_decoder():
    """FORMAT UNIT CDB fields decoded correctly."""
    cdb = bytes([0x04, 0x11, 0, 0, 0, 0])  # FMTDATA=1, IMMED=0, format type 1
    frames = [
        ("OUT", _cbw(1, 12, "OUT", 0, cdb)),
        ("OUT", b"\x00" * 12),
        ("IN", _csw(1, 0, "GOOD")),
    ]
    txns = _run(_build_pcapng(frames))
    d = txns[0]._decoded_details
    _check("IMMED=0" in d, d)
    _check("FMTDATA=1" in d, d)


def _test_get_configuration_decoder():
    """GET CONFIGURATION response decoded correctly."""
    cdb = bytes([0x46, 0, 0, 0, 0, 0, 0, 0x01, 0, 0])  # alloc=256
    data = bytearray(20)
    data[0:4] = struct.pack(">I", 12)  # data length = 12
    data[6] = 0x00
    data[7] = 0x08  # profile = CD-ROM
    data[8] = 0x00
    data[9] = 0x01  # feature code = Core
    data[10] = 0x03  # version 2 + persistent + current
    data[11] = 0x08  # additional length = 8
    frames = [
        ("OUT", _cbw(1, 256, "IN", 0, cdb)),
        ("IN", bytes(data)),
        ("IN", _csw(1, 0, "GOOD")),
    ]
    txns = _run(_build_pcapng(frames))
    d = txns[0]._decoded_details
    _check("CD-ROM" in d, d)
    _check("Core" in d, d)


def _test_read_format_capacities_decoder():
    """READ FORMAT CAPACITIES MMC-6 format decoded correctly."""
    cdb = bytes([0x23, 0, 0, 0, 0, 0, 0, 0x10, 0, 0])  # alloc=16
    data = bytearray(12)
    data[3] = 8       # capacity list length
    data[4:8] = struct.pack(">I", 101860)  # blocks
    data[8] = 0x02    # code = formattable
    data[10] = 0x08   # block size MSB
    data[11] = 0x00   # block size LSB = 2048
    frames = [
        ("OUT", _cbw(1, 16, "IN", 0, cdb)),
        ("IN", bytes(data)),
        ("IN", _csw(1, 0, "GOOD")),
    ]
    txns = _run(_build_pcapng(frames))
    d = txns[0]._decoded_details
    _check("101860" in d, d)
    _check("2048" in d, d)
    _check("formattable" in d, d)


def _test_request_sense_decoder():
    """REQUEST SENSE response decoded with semantic names."""
    cdb = bytes([0x03, 0, 0, 0, 18, 0])
    sense = bytes([
        0x70, 0x00, 0x05, 0, 0, 0, 0, 0x0A, 0, 0, 0, 0,
        0x24, 0x00, 0, 0, 0, 0,
    ])
    frames = [
        ("OUT", _cbw(1, 18, "IN", 0, cdb)),
        ("IN", sense),
        ("IN", _csw(1, 0, "GOOD")),
    ]
    txns = _run(_build_pcapng(frames))
    d = txns[0]._decoded_details
    _check("Illegal Request" in d, d)
    _check("24h" in d, d)
    _check("INVALID FIELD IN CDB" in d, d)


def _test_format_table():
    """Table output format renders without error."""
    frames = [
        ("OUT", _cbw(1, 0, "OUT", 0, bytes([0x00] * 6))),
        ("IN", _csw(1, 0, "GOOD")),
    ]
    txns = _run(_build_pcapng(frames))
    out = format_table(txns, color=False)
    _check("TEST_UNIT_READY" in out, out)
    _check("GOOD" in out, out)


def _test_format_json():
    """JSON output is valid and contains expected fields."""
    frames = [
        ("OUT", _cbw(1, 0, "OUT", 0, bytes([0x00] * 6))),
        ("IN", _csw(1, 0, "GOOD")),
    ]
    txns = _run(_build_pcapng(frames))
    out = format_json(txns)
    parsed = json.loads(out)
    _check(len(parsed) == 1)
    _check(parsed[0]["opcode"] == "TEST_UNIT_READY")
    _check(parsed[0]["csw_status"] == "GOOD")
    _check("frame" in parsed[0])
    _check("time" in parsed[0])


def _test_format_csv():
    """CSV output has header + data row."""
    frames = [
        ("OUT", _cbw(1, 0, "OUT", 0, bytes([0x00] * 6))),
        ("IN", _csw(1, 0, "GOOD")),
    ]
    txns = _run(_build_pcapng(frames))
    out = format_csv(txns)
    lines = out.strip().split("\n")
    _check(len(lines) == 2, f"expected 2 lines, got {len(lines)}")
    _check("opcode" in lines[0])  # header
    _check("TEST_UNIT_READY" in lines[1])


def _test_filter_by_lun():
    """--lun filter works."""
    frames = [
        ("OUT", _cbw(1, 0, "OUT", 0, bytes([0x00] * 6))),
        ("IN", _csw(1, 0, "GOOD")),
        ("OUT", _cbw(2, 0, "OUT", 1, bytes([0x00] * 6))),
        ("IN", _csw(2, 0, "GOOD")),
    ]
    txns = _run(_build_pcapng(frames), lun=0)
    _check(len(txns) == 1, f"expected 1, got {len(txns)}")
    _check(txns[0].cbw.lun == 0)


def _test_filter_by_opcode():
    """--opcode filter works."""
    frames = [
        ("OUT", _cbw(1, 0, "OUT", 0, bytes([0x00] * 6))),  # TUR
        ("IN", _csw(1, 0, "GOOD")),
        ("OUT", _cbw(2, 8, "IN", 0, bytes([0x25] + [0]*9))),  # READ CAPACITY
        ("IN", struct.pack(">II", 100, 512)),
        ("IN", _csw(2, 0, "GOOD")),
    ]
    txns = _run(_build_pcapng(frames), opcode=0x00)
    _check(len(txns) == 1, f"expected 1, got {len(txns)}")
    _check(txns[0].cbw.cdb[0] == 0x00)


def _test_filter_by_direction():
    """--direction filter works."""
    frames = [
        ("OUT", _cbw(1, 8, "IN", 0, bytes([0x25] + [0]*9))),  # READ CAPACITY (Data-In)
        ("IN", struct.pack(">II", 100, 512)),
        ("IN", _csw(1, 0, "GOOD")),
        ("OUT", _cbw(2, 0, "OUT", 0, bytes([0x00] * 6))),  # TUR (no data)
        ("IN", _csw(2, 0, "GOOD")),
    ]
    txns = _run(_build_pcapng(frames), direction="in")
    _check(len(txns) == 1, f"expected 1, got {len(txns)}")
    _check(txns[0].cbw.direction == "IN")


def _test_no_payload():
    """--no-payload clears details."""
    cdb = bytes([0x12, 0, 0, 0, 96, 0])
    data = bytearray(95)
    data[8:16] = b"TESTVEND"
    frames = [
        ("OUT", _cbw(1, 96, "IN", 0, cdb)),
        ("IN", bytes(data)),
        ("IN", _csw(1, 0, "GOOD")),
    ]
    txns = _run(_build_pcapng(frames), no_payload=True)
    _check(txns[0]._decoded_details == "", txns[0]._decoded_details)


def _test_read10_decoder():
    """READ(10) CDB fields decoded correctly."""
    cdb = bytes([0x28, 0, 0, 0, 0, 16, 0, 0, 2, 0])  # LBA=16, count=2
    frames = [
        ("OUT", _cbw(1, 4096, "IN", 0, cdb)),
        ("IN", b"\x00" * 4096),
        ("IN", _csw(1, 0, "GOOD")),
    ]
    txns = _run(_build_pcapng(frames))
    d = txns[0]._decoded_details
    _check("LBA=0x00000010" in d, d)
    _check("count=2" in d, d)


def _test_write10_decoder():
    """WRITE(10) CDB fields decoded correctly."""
    cdb = bytes([0x2A, 0, 0, 0, 1, 0, 0, 0, 1, 0])  # LBA=256, count=1
    frames = [
        ("OUT", _cbw(1, 2048, "OUT", 0, cdb)),
        ("OUT", b"\x00" * 2048),
        ("IN", _csw(1, 0, "GOOD")),
    ]
    txns = _run(_build_pcapng(frames))
    d = txns[0]._decoded_details
    _check("LBA=0x00000100" in d, d)
    _check("count=1" in d, d)


def _test_sync_cache_decoder():
    """SYNCHRONIZE CACHE(10) decoded correctly."""
    cdb = bytes([0x35, 0, 0, 0, 0, 80, 0, 0, 16, 0])  # LBA=80, count=16
    frames = [
        ("OUT", _cbw(1, 0, "OUT", 0, cdb)),
        ("IN", _csw(1, 0, "GOOD")),
    ]
    txns = _run(_build_pcapng(frames))
    d = txns[0]._decoded_details
    _check("LBA=0x00000050" in d, d)
    _check("count=16" in d, d)


def _test_start_stop_decoder():
    """START STOP UNIT decoded correctly."""
    cdb = bytes([0x1B, 0, 0, 0, 0x03, 0])  # LoEj=1, Start=1
    frames = [
        ("OUT", _cbw(1, 0, "OUT", 0, cdb)),
        ("IN", _csw(1, 0, "GOOD")),
    ]
    txns = _run(_build_pcapng(frames))
    d = txns[0]._decoded_details
    _check("LoEj=1" in d, d)
    _check("Start=1" in d, d)


def _test_mode_sense6_decoder():
    """MODE SENSE(6) decoded correctly."""
    cdb = bytes([0x1A, 0, 0x08, 0, 32, 0])  # page=0x08 (Caching), alloc=32
    data = bytearray(24)
    data[0] = 23      # mode data length
    data[4] = 0x88    # caching page header
    data[5] = 18      # page length
    frames = [
        ("OUT", _cbw(1, 32, "IN", 0, cdb)),
        ("IN", bytes(data)),
        ("IN", _csw(1, 0, "GOOD")),
    ]
    txns = _run(_build_pcapng(frames))
    d = txns[0]._decoded_details
    _check("Caching" in d, d)


def _test_pcie_phase_error():
    """PHASE_ERROR status decoded correctly."""
    frames = [
        ("OUT", _cbw(1, 512, "OUT", 0, bytes([0x2A] + [0]*9))),  # WRITE(10)
        ("IN", _csw(1, 512, "PHASE_ERROR")),
    ]
    txns = _run(_build_pcapng(frames))
    _check(txns[0].csw_status == "PHASE_ERROR")
    _check(txns[0].csw_residue == 512)


def _test_report_luns_decoder():
    """REPORT LUNS decoded correctly."""
    cdb = bytes([0xA0, 0, 0, 0, 0, 0, 0, 0, 0x10, 0])  # alloc=16
    data = struct.pack(">II", 8, 0) + struct.pack(">Q", 0)  # 1 LUN
    frames = [
        ("OUT", _cbw(1, 16, "IN", 0, cdb)),
        ("IN", data),
        ("IN", _csw(1, 0, "GOOD")),
    ]
    txns = _run(_build_pcapng(frames))
    d = txns[0]._decoded_details
    _check("LUN count=1" in d, d)


# ═══════════════════════════════════════════════════════════════════
# Test runner
# ═══════════════════════════════════════════════════════════════════

ALL_TESTS = [
    _test_pcapng_parse,
    _test_usbpcap_header,
    _test_cbw_parse,
    _test_csw_parse,
    _test_cbw_rejects_bad_signature,
    _test_csw_rejects_bad_signature,
    _test_full_good_transaction,
    _test_failed_csw_check_condition,
    _test_unit_attention_correlation,
    _test_inquiry_decoder,
    _test_read_capacity10_decoder,
    _test_read_toc_decoder,
    _test_format_unit_decoder,
    _test_get_configuration_decoder,
    _test_read_format_capacities_decoder,
    _test_request_sense_decoder,
    _test_format_table,
    _test_format_json,
    _test_format_csv,
    _test_filter_by_lun,
    _test_filter_by_opcode,
    _test_filter_by_direction,
    _test_no_payload,
    _test_read10_decoder,
    _test_write10_decoder,
    _test_sync_cache_decoder,
    _test_start_stop_decoder,
    _test_mode_sense6_decoder,
    _test_pcie_phase_error,
    _test_report_luns_decoder,
]


def run_all():
    passed = 0
    failed = 0
    for fn in ALL_TESTS:
        name = fn.__name__.lstrip("_").replace("_test_", "")
        try:
            fn()
            passed += 1
            print(f"  PASS  {name}")
        except _TestFailure as e:
            failed += 1
            print(f"  FAIL  {name}: {e}")
        except Exception as e:
            failed += 1
            print(f"  ERROR {name}: {type(e).__name__}: {e}")
    print(f"\n{passed + failed} tests: {passed} passed, {failed} failed")
    return failed == 0


if __name__ == "__main__":
    sys.exit(0 if run_all() else 1)
