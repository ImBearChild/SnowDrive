#include <snowscsi/iscsi.h>

#include <string.h>

/* ── BHS byte offsets ────────────────────────────────────────────
 *
 * Common across all PDUs (RFC 3720 §3.1):
 *   byte 0  — Opcode (bits 5-0) + Immediate/Rsvd (bit 6-7)
 *   byte 1  — Flags (PDU-specific)
 *   byte 4  — TotalAHSLength
 *   bytes 5-7 — DataSegmentLength (3 bytes, big-endian)
 *   bytes 16-19 — Initiator Task Tag (4 bytes, big-endian)
 *
 * Login Request / SCSI Command / Logout Request:
 *   bytes 24-27 — CmdSN
 *   bytes 28-31 — ExpStatSN (Login/SCSI Cmd) / reserved (Logout)
 *
 * "Response-style" PDUs (SCSI Response, Logout Response,
 * Data-In with S=1):
 *   bytes 20-23 — ExpCmdSN
 *   bytes 24-27 — MaxCmdSN
 *   bytes 36-39 — StatSN
 *
 * "Notification-style" PDUs (Login Response, NOP-In, R2T, Reject):
 *   bytes 24-27 — StatSN
 *   bytes 28-31 — ExpCmdSN
 *   bytes 32-35 — MaxCmdSN
 *
 * T bit (Login PDU, RFC 3720 §10.12):
 *   byte 1  — bit 7                                                  */

/* ── Internal helper: encode uint32 big-endian ──────────────────── */

static void put_be32(uint8_t *p, uint32_t v) {
  p[0] = (v >> 24) & 0xFF;
  p[1] = (v >> 16) & 0xFF;
  p[2] = (v >> 8) & 0xFF;
  p[3] = v & 0xFF;
}

/* ── Internal helper: decode uint32 big-endian ──────────────────── */

static uint32_t get_be32(const uint8_t *p) {
  return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
         ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

/* ── Opcode ─────────────────────────────────────────────────────── */

uint8_t snowscsi_iscsi_bhs_get_opcode(const uint8_t bhs[48]) {
  return bhs[0] & 0x3F;
}

void snowscsi_iscsi_bhs_set_opcode(uint8_t bhs[48], uint8_t opcode) {
  bhs[0] = (bhs[0] & 0xC0) | (opcode & 0x3F);
}

/* ── Flags ──────────────────────────────────────────────────────── */

uint8_t snowscsi_iscsi_bhs_get_flags(const uint8_t bhs[48]) { return bhs[1]; }

void snowscsi_iscsi_bhs_set_flags(uint8_t bhs[48], uint8_t flags) {
  bhs[1] = flags;
}

/* ── DataSegmentLength ────────────────────────────────────────────
 * RFC 3720 §3.1: 24-bit big-endian field at bytes 5-7. Byte 4 is
 * TotalAHSLength and must not be overwritten.                      */

uint32_t snowscsi_iscsi_bhs_get_data_seg_len(const uint8_t bhs[48]) {
  return ((uint32_t)bhs[5] << 16) | ((uint32_t)bhs[6] << 8) | (uint32_t)bhs[7];
}

void snowscsi_iscsi_bhs_set_data_seg_len(uint8_t bhs[48], uint32_t len) {
  bhs[5] = (len >> 16) & 0xFF;
  bhs[6] = (len >> 8) & 0xFF;
  bhs[7] = len & 0xFF;
}

/* ── Initiator Task Tag ─────────────────────────────────────────── */

uint32_t snowscsi_iscsi_bhs_get_itt(const uint8_t bhs[48]) {
  return get_be32(&bhs[16]);
}

void snowscsi_iscsi_bhs_set_itt(uint8_t bhs[48], uint32_t itt) {
  put_be32(&bhs[16], itt);
}

/* ── CmdSN ──────────────────────────────────────────────────────── */

uint32_t snowscsi_iscsi_bhs_get_cmd_sn(const uint8_t bhs[48]) {
  return get_be32(&bhs[24]);
}

/* ── ExpStatSN ──────────────────────────────────────────────────── */

uint32_t snowscsi_iscsi_bhs_get_exp_stat_sn(const uint8_t bhs[48]) {
  return get_be32(&bhs[28]);
}

/* ── Response-style StatSN ──────────────────────────────────────── */

void snowscsi_iscsi_bhs_resp_set_stat_sn(uint8_t bhs[48], uint32_t sn) {
  put_be32(&bhs[36], sn);
}

uint32_t snowscsi_iscsi_bhs_resp_get_stat_sn(const uint8_t bhs[48]) {
  return get_be32(&bhs[36]);
}

/* ── Response-style ExpCmdSN ────────────────────────────────────── */

void snowscsi_iscsi_bhs_resp_set_exp_cmd_sn(uint8_t bhs[48], uint32_t sn) {
  put_be32(&bhs[20], sn);
}

uint32_t snowscsi_iscsi_bhs_resp_get_exp_cmd_sn(const uint8_t bhs[48]) {
  return get_be32(&bhs[20]);
}

/* ── Response-style MaxCmdSN ────────────────────────────────────── */

void snowscsi_iscsi_bhs_resp_set_max_cmd_sn(uint8_t bhs[48], uint32_t sn) {
  put_be32(&bhs[24], sn);
}

uint32_t snowscsi_iscsi_bhs_resp_get_max_cmd_sn(const uint8_t bhs[48]) {
  return get_be32(&bhs[24]);
}

/* ── Notification-style StatSN ──────────────────────────────────── */

void snowscsi_iscsi_bhs_notify_set_stat_sn(uint8_t bhs[48], uint32_t sn) {
  put_be32(&bhs[24], sn);
}

uint32_t snowscsi_iscsi_bhs_notify_get_stat_sn(const uint8_t bhs[48]) {
  return get_be32(&bhs[24]);
}

/* ── Notification-style ExpCmdSN ────────────────────────────────── */

void snowscsi_iscsi_bhs_notify_set_exp_cmd_sn(uint8_t bhs[48], uint32_t sn) {
  put_be32(&bhs[28], sn);
}

/* ── Notification-style MaxCmdSN ────────────────────────────────── */

void snowscsi_iscsi_bhs_notify_set_max_cmd_sn(uint8_t bhs[48], uint32_t sn) {
  put_be32(&bhs[32], sn);
}

/* ── CSG / NSG ──────────────────────────────────────────────────── */

uint8_t snowscsi_iscsi_bhs_get_csg(const uint8_t bhs[48]) {
  return (bhs[1] >> SNOWSCSI_ISCSI_FLAG_CSG_SHIFT) & 0x03;
}

uint8_t snowscsi_iscsi_bhs_get_nsg(const uint8_t bhs[48]) {
  return (bhs[1] >> SNOWSCSI_ISCSI_FLAG_NSG_SHIFT) & 0x0F;
}

void snowscsi_iscsi_bhs_set_nsg(uint8_t bhs[48], uint8_t nsg) {
  bhs[1] = (bhs[1] & ~0x0F) | (nsg & 0x0F);
}

/* ── T bit ────────────────────────────────────────────────────────
 * RFC 3720 §10.12: T (Transit) bit is byte 1, bit 7 of Login PDUs. */

bool snowscsi_iscsi_bhs_get_t_bit(const uint8_t bhs[48]) {
  return (bhs[1] & SNOWSCSI_ISCSI_FLAG_T_BIT) != 0;
}

void snowscsi_iscsi_bhs_set_t_bit(uint8_t bhs[48], bool t) {
  if (t)
    bhs[1] |= SNOWSCSI_ISCSI_FLAG_T_BIT;
  else
    bhs[1] &= ~SNOWSCSI_ISCSI_FLAG_T_BIT;
}

/* ── LUN ────────────────────────────────────────────────────────── */

uint8_t snowscsi_iscsi_bhs_get_lun(const uint8_t bhs[48]) {
  /* Single-level LUN addressing: byte 8=0, byte 9=LUN id */
  return bhs[9];
}

void snowscsi_iscsi_bhs_set_lun(uint8_t bhs[48], uint8_t lun) {
  memset(&bhs[8], 0, 8);
  bhs[9] = lun;
}

/* ── CDB extraction ─────────────────────────────────────────────── */

void snowscsi_iscsi_bhs_get_cdb(const uint8_t bhs[48], uint8_t *cdb,
                                uint8_t *cdb_len) {
  *cdb_len =
      snowscsi_iscsi_cdb_len_from_opcode(snowscsi_iscsi_bhs_get_opcode(bhs));
  uint8_t len = *cdb_len;
  if (len > 16)
    len = 16;
  memcpy(cdb, &bhs[32], len);
}

/* ── SCSI Response status ───────────────────────────────────────── */

void snowscsi_iscsi_bhs_set_status(uint8_t bhs[48], uint8_t status) {
  bhs[3] = status;
}

/* ── SCSI Response sense length ─────────────────────────────────── */

void snowscsi_iscsi_bhs_set_sense_len(uint8_t bhs[48], uint8_t len) {
  bhs[2] = len;
}

/* ── DataSN — bytes 28-31 in Data-In PDU (RFC 7143 §10.7) ──────── */

void snowscsi_iscsi_bhs_set_data_sn(uint8_t bhs[48], uint32_t sn) {
  put_be32(&bhs[28], sn);
}

uint32_t snowscsi_iscsi_bhs_get_data_sn(const uint8_t bhs[48]) {
  return get_be32(&bhs[28]);
}

/* ── Data-In status fields (S=1) — StatSN at bytes 36-39,
 *    ExpCmdSN at bytes 40-43, MaxCmdSN at bytes 44-47. ──────────── */

void snowscsi_iscsi_bhs_data_in_set_stat_sn(uint8_t bhs[48], uint32_t sn) {
  put_be32(&bhs[36], sn);
}

uint32_t snowscsi_iscsi_bhs_data_in_get_stat_sn(const uint8_t bhs[48]) {
  return get_be32(&bhs[36]);
}

void snowscsi_iscsi_bhs_data_in_set_exp_cmd_sn(uint8_t bhs[48], uint32_t sn) {
  put_be32(&bhs[40], sn);
}

void snowscsi_iscsi_bhs_data_in_set_max_cmd_sn(uint8_t bhs[48], uint32_t sn) {
  put_be32(&bhs[44], sn);
}

/* ── Buffer Offset (Data-Out) ───────────────────────────────────── */

uint32_t snowscsi_iscsi_bhs_get_buffer_offset(const uint8_t bhs[48]) {
  return get_be32(&bhs[40]);
}

/* ── R2T specific ───────────────────────────────────────────────── */

void snowscsi_iscsi_bhs_set_r2t_buffer_offset(uint8_t bhs[48],
                                              uint32_t offset) {
  put_be32(&bhs[40], offset);
}

void snowscsi_iscsi_bhs_set_desired_data_len(uint8_t bhs[48], uint32_t len) {
  put_be32(&bhs[20], len);
}

/* ── Target Transfer Tag ────────────────────────────────────────── */

uint32_t snowscsi_iscsi_bhs_get_ttt(const uint8_t bhs[48]) {
  return get_be32(&bhs[20]);
}

void snowscsi_iscsi_bhs_set_ttt(uint8_t bhs[48], uint32_t ttt) {
  put_be32(&bhs[20], ttt);
}

/* ── Reject reason ──────────────────────────────────────────────── */

void snowscsi_iscsi_bhs_set_reject_reason(uint8_t bhs[48], uint8_t reason) {
  bhs[2] = reason;
}

uint8_t snowscsi_iscsi_bhs_get_reject_reason(const uint8_t bhs[48]) {
  return bhs[2];
}

/* ── Opcode name ────────────────────────────────────────────────── */

const char *snowscsi_iscsi_opcode_name(uint8_t opcode) {
  static const char *names[] = {
      [0x00] = "NOP_OUT",       [0x01] = "SCSI_CMD",
      [0x02] = "SCSI_TASK_REQ", [0x03] = "LOGIN_REQ",
      [0x04] = "TEXT_REQ",      [0x05] = "SCSI_DATA_OUT",
      [0x06] = "LOGOUT_REQ",    [0x20] = "NOP_IN",
      [0x21] = "SCSI_RESP",     [0x22] = "SCSI_TASK_RESP",
      [0x23] = "LOGIN_RESP",    [0x24] = "TEXT_RESP",
      [0x25] = "SCSI_DATA_IN",  [0x26] = "LOGOUT_RESP",
      [0x31] = "R2T",           [0x3F] = "REJECT",
  };
  if (opcode <= 0x3F && names[opcode])
    return names[opcode];
  return "UNKNOWN";
}

/* ── CDB length from opcode group code ──────────────────────────── */

uint8_t snowscsi_iscsi_cdb_len_from_opcode(uint8_t opcode) {
  switch ((opcode >> 5) & 0x07) {
  case 0:
    return 6;
  case 1:
  case 2:
    return 10;
  case 4:
    return 16;
  case 5:
    return 12;
  default:
    return 6;
  }
}
