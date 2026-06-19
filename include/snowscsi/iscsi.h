#ifndef SNOWSCSI_ISCSI_H
#define SNOWSCSI_ISCSI_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* ── iSCSI PDU Opcodes ─────────────────────────────────────────── */

#define SNOWSCSI_ISCSI_OP_NOP_OUT 0x00
#define SNOWSCSI_ISCSI_OP_SCSI_CMD 0x01
#define SNOWSCSI_ISCSI_OP_SCSI_TASK_REQ 0x02
#define SNOWSCSI_ISCSI_OP_LOGIN_REQ 0x03
#define SNOWSCSI_ISCSI_OP_TEXT_REQ 0x04
#define SNOWSCSI_ISCSI_OP_SCSI_DATA_OUT 0x05
#define SNOWSCSI_ISCSI_OP_LOGOUT_REQ 0x06
#define SNOWSCSI_ISCSI_OP_NOP_IN 0x20
#define SNOWSCSI_ISCSI_OP_SCSI_RESP 0x21
#define SNOWSCSI_ISCSI_OP_SCSI_TASK_RESP 0x22
#define SNOWSCSI_ISCSI_OP_LOGIN_RESP 0x23
#define SNOWSCSI_ISCSI_OP_TEXT_RESP 0x24
#define SNOWSCSI_ISCSI_OP_SCSI_DATA_IN 0x25
#define SNOWSCSI_ISCSI_OP_LOGOUT_RESP 0x26
#define SNOWSCSI_ISCSI_OP_R2T 0x31
#define SNOWSCSI_ISCSI_OP_REJECT 0x3F

/* ── iSCSI Constants ───────────────────────────────────────────── */

#define SNOWSCSI_ISCSI_BHS_SIZE 48
#define SNOWSCSI_ISCSI_MAX_DATA_SEGMENT 8192

/* Login stage negotiation */
#define SNOWSCSI_ISCSI_STAGE_SECURITY 0
#define SNOWSCSI_ISCSI_STAGE_OP_PARAM 1
#define SNOWSCSI_ISCSI_STAGE_FULL_FEATURE 3

/* Reject reasons */
#define SNOWSCSI_ISCSI_REJECT_FORMAT_ERROR 0x02
#define SNOWSCSI_ISCSI_REJECT_CMD_SN 0x0A

/* Data-In flags */
#define SNOWSCSI_ISCSI_FLAG_DATA_FINAL 0x80
#define SNOWSCSI_ISCSI_FLAG_DATA_STATUS 0x01

/* SCSI status codes */
#define SNOWSCSI_ISCSI_SCSI_STATUS_GOOD 0x00
#define SNOWSCSI_ISCSI_SCSI_STATUS_CHECK_CONDITION 0x02

/* ── PDU-specific flag masks ───────────────────────────────────── */

/* Login/Logout PDU flags */
#define SNOWSCSI_ISCSI_FLAG_T_BIT 0x80
#define SNOWSCSI_ISCSI_FLAG_F_BIT 0x80 /* Final bit in Data PDUs */

/* CSG/NSG fields (RFC 3720 §10.12–10.13):
 *   byte 1 bits 3-2 = CSG (2 bits), bits 1-0 = NSG (2 bits)
 *   (MSB0 diagram: bits 4-5=CSG, bits 6-7=NSG) */
#define SNOWSCSI_ISCSI_FLAG_CSG_SHIFT 2
#define SNOWSCSI_ISCSI_FLAG_NSG_SHIFT 0

/* ── Generic BHS field accessors ─────────────────────────────────
 *  Use these to read/write protocol-defined fields at their RFC
 *  3720 byte offsets within the 48-byte BHS.                          */

uint8_t snowscsi_iscsi_bhs_get_opcode(const uint8_t bhs[48]);
void snowscsi_iscsi_bhs_set_opcode(uint8_t bhs[48], uint8_t opcode);
uint8_t snowscsi_iscsi_bhs_get_flags(const uint8_t bhs[48]);
void snowscsi_iscsi_bhs_set_flags(uint8_t bhs[48], uint8_t flags);
uint32_t snowscsi_iscsi_bhs_get_data_seg_len(const uint8_t bhs[48]);
void snowscsi_iscsi_bhs_set_data_seg_len(uint8_t bhs[48], uint32_t len);
uint32_t snowscsi_iscsi_bhs_get_itt(const uint8_t bhs[48]);
void snowscsi_iscsi_bhs_set_itt(uint8_t bhs[48], uint32_t itt);

/* ── CmdSN / ExpStatSN — at bytes 24-27, 28-31 in Login Req, SCSI
 * Cmd, Logout Req ───────────────────────────────────────────────── */

uint32_t snowscsi_iscsi_bhs_get_cmd_sn(const uint8_t bhs[48]);
uint32_t snowscsi_iscsi_bhs_get_exp_stat_sn(const uint8_t bhs[48]);

/* ── Response-style fields — at bytes 24-27 (StatSN), 28-31
 * (ExpCmdSN), 32-35 (MaxCmdSN).
 * Applies to: SCSI Response (§11.4), Logout Response (§11.15) ───── */

void snowscsi_iscsi_bhs_resp_set_stat_sn(uint8_t bhs[48], uint32_t sn);
void snowscsi_iscsi_bhs_resp_set_exp_cmd_sn(uint8_t bhs[48], uint32_t sn);
void snowscsi_iscsi_bhs_resp_set_max_cmd_sn(uint8_t bhs[48], uint32_t sn);
uint32_t snowscsi_iscsi_bhs_resp_get_stat_sn(const uint8_t bhs[48]);
uint32_t snowscsi_iscsi_bhs_resp_get_exp_cmd_sn(const uint8_t bhs[48]);
uint32_t snowscsi_iscsi_bhs_resp_get_max_cmd_sn(const uint8_t bhs[48]);

/* ── Notification-style fields — at bytes 24-27 (StatSN), 28-31
 * (ExpCmdSN), 32-35 (MaxCmdSN).
 * Applies to: Login Response, NOP-In, R2T, Reject ───────────────── */

void snowscsi_iscsi_bhs_notify_set_stat_sn(uint8_t bhs[48], uint32_t sn);
void snowscsi_iscsi_bhs_notify_set_exp_cmd_sn(uint8_t bhs[48], uint32_t sn);
void snowscsi_iscsi_bhs_notify_set_max_cmd_sn(uint8_t bhs[48], uint32_t sn);
uint32_t snowscsi_iscsi_bhs_notify_get_stat_sn(const uint8_t bhs[48]);

/* ── Login-specific — byte 1 bits 3-0 carry CSG/NSG ─────────────── */

uint8_t snowscsi_iscsi_bhs_get_csg(const uint8_t bhs[48]);
uint8_t snowscsi_iscsi_bhs_get_nsg(const uint8_t bhs[48]);
void snowscsi_iscsi_bhs_set_nsg(uint8_t bhs[48], uint8_t nsg);
bool snowscsi_iscsi_bhs_get_t_bit(const uint8_t bhs[48]);
void snowscsi_iscsi_bhs_set_t_bit(uint8_t bhs[48], bool t);

/* ── LUN / CDB — byte 8 (first level) is 0, byte 9 = LUN id ────── */

uint8_t snowscsi_iscsi_bhs_get_lun(const uint8_t bhs[48]);
void snowscsi_iscsi_bhs_set_lun(uint8_t bhs[48], uint8_t lun);
void snowscsi_iscsi_bhs_get_cdb(const uint8_t bhs[48], uint8_t *cdb,
                                uint8_t *cdb_len);

/* ── SCSI Response specific fields ──────────────────────────────── */

void snowscsi_iscsi_bhs_set_status(uint8_t bhs[48], uint8_t status);
void snowscsi_iscsi_bhs_set_sense_len(uint8_t bhs[48], uint8_t len);

/* ── Data-In specific — DataSN at bytes 36-39 (RFC 7143 §11.7) ─── */

void snowscsi_iscsi_bhs_set_data_sn(uint8_t bhs[48], uint32_t sn);
uint32_t snowscsi_iscsi_bhs_get_data_sn(const uint8_t bhs[48]);

/* ── Data-In status fields (S=1) — StatSN at bytes 24-27,
 *    ExpCmdSN at bytes 28-31, MaxCmdSN at bytes 32-35. ──────────── */

void snowscsi_iscsi_bhs_data_in_set_stat_sn(uint8_t bhs[48], uint32_t sn);
uint32_t snowscsi_iscsi_bhs_data_in_get_stat_sn(const uint8_t bhs[48]);
void snowscsi_iscsi_bhs_data_in_set_exp_cmd_sn(uint8_t bhs[48], uint32_t sn);
void snowscsi_iscsi_bhs_data_in_set_max_cmd_sn(uint8_t bhs[48], uint32_t sn);

/* ── Data-Out specific — Buffer Offset at bytes 40-43 ───────────── */

uint32_t snowscsi_iscsi_bhs_get_buffer_offset(const uint8_t bhs[48]);

/* ── R2T specific — Buffer Offset bytes 40-43, Desired Data
 * Transfer Length bytes 44-47, R2TSN bytes 36-39 ────────────────── */

void snowscsi_iscsi_bhs_set_r2t_buffer_offset(uint8_t bhs[48], uint32_t offset);
void snowscsi_iscsi_bhs_set_desired_data_len(uint8_t bhs[48], uint32_t len);
void snowscsi_iscsi_bhs_r2t_set_r2tsn(uint8_t bhs[48], uint32_t sn);

/* ── NOP specific — Target Transfer Tag at bytes 20-23 ──────────── */

uint32_t snowscsi_iscsi_bhs_get_ttt(const uint8_t bhs[48]);
void snowscsi_iscsi_bhs_set_ttt(uint8_t bhs[48], uint32_t ttt);

/* ── Reject specific — Reason at byte 2 (when opcode == 0x3F) ───── */

void snowscsi_iscsi_bhs_set_reject_reason(uint8_t bhs[48], uint8_t reason);
uint8_t snowscsi_iscsi_bhs_get_reject_reason(const uint8_t bhs[48]);

/* ── Utility ───────────────────────────────────────────────────── */

const char *snowscsi_iscsi_opcode_name(uint8_t opcode);
uint8_t snowscsi_iscsi_cdb_len_from_opcode(uint8_t opcode);

/* ── Transport abstraction ─────────────────────────────────────── */

typedef struct snowscsi_transport_ops {
  intptr_t (*listen)(void *ctx, const char *addr, uint16_t port);
  intptr_t (*accept)(void *ctx, intptr_t listener);
  int (*recv)(void *ctx, intptr_t conn, void *buf, size_t len);
  int (*send)(void *ctx, intptr_t conn, const void *buf, size_t len);
  void (*disconnect)(void *ctx, intptr_t conn);
  void (*stop)(void *ctx, intptr_t listener);
} snowscsi_transport_ops_t;

extern const snowscsi_transport_ops_t SNOWSCSI_TRANSPORT_BSD;

/* ── iSCSI Target ──────────────────────────────────────────────── */

typedef struct snowscsi_device snowscsi_device_t;

int snowscsi_iscsi_serve(snowscsi_device_t **devs, int num_devs,
                         const char *addr,
                         const snowscsi_transport_ops_t *transport_ops,
                         void *transport_ctx);

#endif /* SNOWSCSI_ISCSI_H */
