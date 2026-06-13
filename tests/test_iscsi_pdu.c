#include "unity.h"

#include <snowscsi/iscsi.h>

#include <string.h>

void setUp(void) {}
void tearDown(void) {}

/* ── test_iscsi_pdu_opcode ─────────────────────────────────────── */

void test_iscsi_pdu_opcode(void) {
  uint8_t bhs[48];
  memset(bhs, 0, 48);

  snowscsi_iscsi_bhs_set_opcode(bhs, SNOWSCSI_ISCSI_OP_SCSI_CMD);
  TEST_ASSERT_EQUAL_HEX8(SNOWSCSI_ISCSI_OP_SCSI_CMD,
                         snowscsi_iscsi_bhs_get_opcode(bhs));

  /* Opcode should only affect lower 6 bits, preserve upper 2 */
  bhs[0] = 0xC0;
  snowscsi_iscsi_bhs_set_opcode(bhs, SNOWSCSI_ISCSI_OP_LOGIN_REQ);
  TEST_ASSERT_EQUAL_HEX8(SNOWSCSI_ISCSI_OP_LOGIN_REQ,
                         snowscsi_iscsi_bhs_get_opcode(bhs));
  TEST_ASSERT_EQUAL_HEX8(0xC3, bhs[0]);
}

/* ── test_iscsi_pdu_flags ──────────────────────────────────────── */

void test_iscsi_pdu_flags(void) {
  uint8_t bhs[48];
  memset(bhs, 0, 48);

  snowscsi_iscsi_bhs_set_flags(bhs, 0xAB);
  TEST_ASSERT_EQUAL_HEX8(0xAB, snowscsi_iscsi_bhs_get_flags(bhs));
  TEST_ASSERT_EQUAL_HEX8(0xAB, bhs[1]);
}

/* ── test_iscsi_pdu_data_seg_len ───────────────────────────────── */

void test_iscsi_pdu_data_seg_len(void) {
  uint8_t bhs[48];
  memset(bhs, 0, 48);

  snowscsi_iscsi_bhs_set_data_seg_len(bhs, 0x123456);
  TEST_ASSERT_EQUAL_UINT32(0x123456, snowscsi_iscsi_bhs_get_data_seg_len(bhs));
  /* RFC 3720 §3.1: DataSegmentLength at bytes 5-7; byte 4 is TotalAHSLength */
  TEST_ASSERT_EQUAL_HEX8(0x00, bhs[4]);
  TEST_ASSERT_EQUAL_HEX8(0x12, bhs[5]);
  TEST_ASSERT_EQUAL_HEX8(0x34, bhs[6]);
  TEST_ASSERT_EQUAL_HEX8(0x56, bhs[7]);

  /* Zero */
  snowscsi_iscsi_bhs_set_data_seg_len(bhs, 0);
  TEST_ASSERT_EQUAL_UINT32(0, snowscsi_iscsi_bhs_get_data_seg_len(bhs));
}

/* ── test_iscsi_pdu_itt ────────────────────────────────────────── */

void test_iscsi_pdu_itt(void) {
  uint8_t bhs[48];
  memset(bhs, 0, 48);

  snowscsi_iscsi_bhs_set_itt(bhs, 0xDEADBEEF);
  TEST_ASSERT_EQUAL_UINT32(0xDEADBEEF, snowscsi_iscsi_bhs_get_itt(bhs));
}

/* ── test_iscsi_pdu_cmd_sn ─────────────────────────────────────── */

void test_iscsi_pdu_cmd_sn(void) {
  uint8_t bhs[48];
  memset(bhs, 0, 48);

  /* CmdSN is at bytes 24-27 */
  bhs[24] = 0x00;
  bhs[25] = 0x00;
  bhs[26] = 0x00;
  bhs[27] = 0x05;

  TEST_ASSERT_EQUAL_UINT32(5, snowscsi_iscsi_bhs_get_cmd_sn(bhs));
}

/* ── test_iscsi_pdu_exp_stat_sn ────────────────────────────────── */

void test_iscsi_pdu_exp_stat_sn(void) {
  uint8_t bhs[48];
  memset(bhs, 0, 48);

  /* ExpStatSN is at bytes 28-31 */
  bhs[28] = 0x00;
  bhs[29] = 0x00;
  bhs[30] = 0x00;
  bhs[31] = 0x03;

  TEST_ASSERT_EQUAL_UINT32(3, snowscsi_iscsi_bhs_get_exp_stat_sn(bhs));
}

/* ── test_iscsi_pdu_resp_stat_sn ───────────────────────────────── */

void test_iscsi_pdu_resp_stat_sn(void) {
  uint8_t bhs[48];
  memset(bhs, 0, 48);

  snowscsi_iscsi_bhs_resp_set_stat_sn(bhs, 42);
  TEST_ASSERT_EQUAL_UINT32(42, snowscsi_iscsi_bhs_resp_get_stat_sn(bhs));

  /* Verify byte offset: StatSN for SCSI/Logout resp is at bytes 24-27 */
  TEST_ASSERT_EQUAL_HEX8(0x00, bhs[24]);
  TEST_ASSERT_EQUAL_HEX8(0x00, bhs[25]);
  TEST_ASSERT_EQUAL_HEX8(0x00, bhs[26]);
  TEST_ASSERT_EQUAL_HEX8(0x2A, bhs[27]);
}

/* ── test_iscsi_pdu_resp_exp_cmd_sn ────────────────────────────── */

void test_iscsi_pdu_resp_exp_cmd_sn(void) {
  uint8_t bhs[48];
  memset(bhs, 0, 48);

  snowscsi_iscsi_bhs_resp_set_exp_cmd_sn(bhs, 99);
  TEST_ASSERT_EQUAL_UINT32(99, snowscsi_iscsi_bhs_resp_get_exp_cmd_sn(bhs));

  /* ExpCmdSN for SCSI/Logout resp is at bytes 28-31 */
  TEST_ASSERT_EQUAL_HEX8(0x00, bhs[28]);
  TEST_ASSERT_EQUAL_HEX8(0x00, bhs[29]);
  TEST_ASSERT_EQUAL_HEX8(0x00, bhs[30]);
  TEST_ASSERT_EQUAL_HEX8(0x63, bhs[31]);
}

/* ── test_iscsi_pdu_resp_max_cmd_sn ────────────────────────────── */

void test_iscsi_pdu_resp_max_cmd_sn(void) {
  uint8_t bhs[48];
  memset(bhs, 0, 48);

  snowscsi_iscsi_bhs_resp_set_max_cmd_sn(bhs, 100);
  TEST_ASSERT_EQUAL_UINT32(100, snowscsi_iscsi_bhs_resp_get_max_cmd_sn(bhs));

  /* MaxCmdSN for SCSI/Logout resp is at bytes 32-35 */
  TEST_ASSERT_EQUAL_HEX8(0x00, bhs[32]);
  TEST_ASSERT_EQUAL_HEX8(0x00, bhs[33]);
  TEST_ASSERT_EQUAL_HEX8(0x00, bhs[34]);
  TEST_ASSERT_EQUAL_HEX8(0x64, bhs[35]);
}

/* ── test_iscsi_pdu_notify_stat_sn ─────────────────────────────── */

void test_iscsi_pdu_notify_stat_sn(void) {
  uint8_t bhs[48];
  memset(bhs, 0, 48);

  snowscsi_iscsi_bhs_notify_set_stat_sn(bhs, 7);
  TEST_ASSERT_EQUAL_UINT32(7, snowscsi_iscsi_bhs_notify_get_stat_sn(bhs));

  /* StatSN for notify PDUs is at bytes 24-27 */
  TEST_ASSERT_EQUAL_HEX8(0x00, bhs[24]);
  TEST_ASSERT_EQUAL_HEX8(0x00, bhs[25]);
  TEST_ASSERT_EQUAL_HEX8(0x00, bhs[26]);
  TEST_ASSERT_EQUAL_HEX8(0x07, bhs[27]);
}

/* ── test_iscsi_pdu_notify_exp_cmd_sn ──────────────────────────── */

void test_iscsi_pdu_notify_exp_cmd_sn(void) {
  uint8_t bhs[48];
  memset(bhs, 0, 48);

  snowscsi_iscsi_bhs_notify_set_exp_cmd_sn(bhs, 55);
  TEST_ASSERT_EQUAL_HEX8(0x00, bhs[28]);
  TEST_ASSERT_EQUAL_HEX8(0x00, bhs[29]);
  TEST_ASSERT_EQUAL_HEX8(0x00, bhs[30]);
  TEST_ASSERT_EQUAL_HEX8(0x37, bhs[31]);
}

/* ── test_iscsi_pdu_notify_max_cmd_sn ──────────────────────────── */

void test_iscsi_pdu_notify_max_cmd_sn(void) {
  uint8_t bhs[48];
  memset(bhs, 0, 48);

  snowscsi_iscsi_bhs_notify_set_max_cmd_sn(bhs, 66);
  TEST_ASSERT_EQUAL_HEX8(0x00, bhs[32]);
  TEST_ASSERT_EQUAL_HEX8(0x00, bhs[33]);
  TEST_ASSERT_EQUAL_HEX8(0x00, bhs[34]);
  TEST_ASSERT_EQUAL_HEX8(0x42, bhs[35]);
}

/* ── test_iscsi_pdu_login_csg_nsg ──────────────────────────────── */

void test_iscsi_pdu_login_csg_nsg(void) {
  uint8_t bhs[48];
  memset(bhs, 0, 48);

  /* Set CSG=1 (bits 6-5), NSG=3 (bits 3-0) */
  bhs[1] = (1 << 5) | 3;

  TEST_ASSERT_EQUAL_UINT8(1, snowscsi_iscsi_bhs_get_csg(bhs));
  TEST_ASSERT_EQUAL_UINT8(3, snowscsi_iscsi_bhs_get_nsg(bhs));

  /* Change NSG */
  snowscsi_iscsi_bhs_set_nsg(bhs, 1);
  TEST_ASSERT_EQUAL_UINT8(1, snowscsi_iscsi_bhs_get_nsg(bhs));
  /* CSG should be unchanged */
  TEST_ASSERT_EQUAL_UINT8(1, snowscsi_iscsi_bhs_get_csg(bhs));
}

/* ── test_iscsi_pdu_t_bit ──────────────────────────────────────── */

void test_iscsi_pdu_t_bit(void) {
  uint8_t bhs[48];
  memset(bhs, 0, 48);

  TEST_ASSERT_FALSE(snowscsi_iscsi_bhs_get_t_bit(bhs));

  snowscsi_iscsi_bhs_set_t_bit(bhs, true);
  TEST_ASSERT_TRUE(snowscsi_iscsi_bhs_get_t_bit(bhs));
  /* RFC 3720 §10.12: T bit is byte 1, bit 7 */
  TEST_ASSERT_EQUAL_HEX8(0x80, bhs[1] & 0x80);
  TEST_ASSERT_EQUAL_HEX8(0x00, bhs[0]);

  snowscsi_iscsi_bhs_set_t_bit(bhs, false);
  TEST_ASSERT_FALSE(snowscsi_iscsi_bhs_get_t_bit(bhs));
  TEST_ASSERT_EQUAL_HEX8(0x00, bhs[1]);
}

/* ── test_iscsi_pdu_lun ────────────────────────────────────────── */

void test_iscsi_pdu_lun(void) {
  uint8_t bhs[48];
  memset(bhs, 0, 48);

  snowscsi_iscsi_bhs_set_lun(bhs, 3);
  TEST_ASSERT_EQUAL_UINT8(3, snowscsi_iscsi_bhs_get_lun(bhs));
  /* Byte 8 should be 0 (first-level LUN addressing) */
  TEST_ASSERT_EQUAL_HEX8(0x00, bhs[8]);
  TEST_ASSERT_EQUAL_HEX8(0x03, bhs[9]);
}

/* ── test_iscsi_pdu_cdb ────────────────────────────────────────── */

void test_iscsi_pdu_cdb(void) {
  uint8_t bhs[48];
  memset(bhs, 0, 48);

  /* Set a READ(10) opcode + CDB (LBA=1, transfer_len=1) */
  snowscsi_iscsi_bhs_set_opcode(bhs, 0x28); /* READ(10) */
  /* cdb[0]=0x28 opcode, cdb[1]=0 reserved,
   * cdb[2-5]=LBA (big-endian, LBA=1), cdb[6]=0 reserved,
   * cdb[7-8]=transfer_len (big-endian, len=1), cdb[9]=0 */
  bhs[32] = 0x28;
  bhs[33] = 0x00;
  bhs[34] = 0x00;
  bhs[35] = 0x00;
  bhs[36] = 0x00;
  bhs[37] = 0x01; /* LBA byte 3 = 1 */
  bhs[38] = 0x00;
  bhs[39] = 0x00; /* transfer_len MSB = 0 */
  bhs[40] = 0x01; /* transfer_len LSB = 1 */
  bhs[41] = 0x00;

  uint8_t cdb[16];
  uint8_t cdb_len;
  snowscsi_iscsi_bhs_get_cdb(bhs, cdb, &cdb_len);
  TEST_ASSERT_EQUAL_UINT8(10, cdb_len);
  TEST_ASSERT_EQUAL_HEX8(0x28, cdb[0]);
  TEST_ASSERT_EQUAL_HEX8(0x01, cdb[8]);
}

/* ── test_iscsi_pdu_scsi_status ────────────────────────────────── */

void test_iscsi_pdu_scsi_status(void) {
  uint8_t bhs[48];
  memset(bhs, 0, 48);

  snowscsi_iscsi_bhs_set_status(bhs,
                                SNOWSCSI_ISCSI_SCSI_STATUS_CHECK_CONDITION);
  TEST_ASSERT_EQUAL_HEX8(SNOWSCSI_ISCSI_SCSI_STATUS_CHECK_CONDITION, bhs[3]);
}

/* ── test_iscsi_pdu_scsi_sense_len ─────────────────────────────── */

void test_iscsi_pdu_scsi_sense_len(void) {
  uint8_t bhs[48];
  memset(bhs, 0, 48);

  snowscsi_iscsi_bhs_set_sense_len(bhs, 18);
  TEST_ASSERT_EQUAL_HEX8(18, bhs[2]);
}

/* ── test_iscsi_pdu_data_sn ────────────────────────────────────── */

void test_iscsi_pdu_data_sn(void) {
  uint8_t bhs[48];
  memset(bhs, 0, 48);

  snowscsi_iscsi_bhs_set_data_sn(bhs, 0x12345678);
  TEST_ASSERT_EQUAL_UINT32(0x12345678, snowscsi_iscsi_bhs_get_data_sn(bhs));

  /* DataSN at bytes 36-39 (RFC 7143 §11.7) */
  TEST_ASSERT_EQUAL_HEX8(0x12, bhs[36]);
  TEST_ASSERT_EQUAL_HEX8(0x34, bhs[37]);
  TEST_ASSERT_EQUAL_HEX8(0x56, bhs[38]);
  TEST_ASSERT_EQUAL_HEX8(0x78, bhs[39]);
}

/* ── test_iscsi_pdu_buffer_offset ──────────────────────────────── */

void test_iscsi_pdu_buffer_offset(void) {
  uint8_t bhs[48];
  memset(bhs, 0, 48);

  /* Buffer Offset at bytes 40-43 */
  bhs[40] = 0x00;
  bhs[41] = 0x00;
  bhs[42] = 0x04;
  bhs[43] = 0x00;

  TEST_ASSERT_EQUAL_UINT32(1024, snowscsi_iscsi_bhs_get_buffer_offset(bhs));
}

/* ── test_iscsi_pdu_r2t ────────────────────────────────────────── */

void test_iscsi_pdu_r2t(void) {
  uint8_t bhs[48];
  memset(bhs, 0, 48);

  snowscsi_iscsi_bhs_set_r2t_buffer_offset(bhs, 0x00002000);
  TEST_ASSERT_EQUAL_HEX8(0x00, bhs[40]);
  TEST_ASSERT_EQUAL_HEX8(0x00, bhs[41]);
  TEST_ASSERT_EQUAL_HEX8(0x20, bhs[42]);
  TEST_ASSERT_EQUAL_HEX8(0x00, bhs[43]);

  snowscsi_iscsi_bhs_set_desired_data_len(bhs, 65536);
  /* Desired Data Transfer Length at bytes 44-47 (RFC 7143 §11.8) */
  TEST_ASSERT_EQUAL_HEX8(0x00, bhs[44]);
  TEST_ASSERT_EQUAL_HEX8(0x01, bhs[45]);
  TEST_ASSERT_EQUAL_HEX8(0x00, bhs[46]);
  TEST_ASSERT_EQUAL_HEX8(0x00, bhs[47]);
}

/* ── test_iscsi_pdu_ttt ────────────────────────────────────────── */

void test_iscsi_pdu_ttt(void) {
  uint8_t bhs[48];
  memset(bhs, 0, 48);

  snowscsi_iscsi_bhs_set_ttt(bhs, 0xFFFFFFFF);
  TEST_ASSERT_EQUAL_UINT32(0xFFFFFFFF, snowscsi_iscsi_bhs_get_ttt(bhs));

  snowscsi_iscsi_bhs_set_ttt(bhs, 0x12345678);
  TEST_ASSERT_EQUAL_UINT32(0x12345678, snowscsi_iscsi_bhs_get_ttt(bhs));
}

/* ── test_iscsi_pdu_reject ─────────────────────────────────────── */

void test_iscsi_pdu_reject(void) {
  uint8_t bhs[48];
  memset(bhs, 0, 48);

  snowscsi_iscsi_bhs_set_reject_reason(bhs, SNOWSCSI_ISCSI_REJECT_CMD_SN);
  TEST_ASSERT_EQUAL_HEX8(SNOWSCSI_ISCSI_REJECT_CMD_SN,
                         snowscsi_iscsi_bhs_get_reject_reason(bhs));

  /* Reason at byte 2 */
  TEST_ASSERT_EQUAL_HEX8(SNOWSCSI_ISCSI_REJECT_CMD_SN, bhs[2]);
}

/* ── test_iscsi_pdu_cdb_len_from_opcode ────────────────────────── */

void test_iscsi_pdu_cdb_len_from_opcode(void) {
  /* Group 0 (000b) → 6 bytes */
  TEST_ASSERT_EQUAL_UINT8(6, snowscsi_iscsi_cdb_len_from_opcode(0x00));
  TEST_ASSERT_EQUAL_UINT8(6, snowscsi_iscsi_cdb_len_from_opcode(0x12));

  /* Group 1 (001b) → 10 bytes */
  TEST_ASSERT_EQUAL_UINT8(10, snowscsi_iscsi_cdb_len_from_opcode(0x28));

  /* Group 2 (010b) → 10 bytes */
  TEST_ASSERT_EQUAL_UINT8(10, snowscsi_iscsi_cdb_len_from_opcode(0x4C));

  /* Group 4 (100b) → 16 bytes */
  TEST_ASSERT_EQUAL_UINT8(16, snowscsi_iscsi_cdb_len_from_opcode(0x8F));

  /* Group 5 (101b) → 12 bytes */
  TEST_ASSERT_EQUAL_UINT8(12, snowscsi_iscsi_cdb_len_from_opcode(0xA0));
}

/* ── test_iscsi_pdu_data_seg_len_rfc_read ─────────────────────────
 *  Place known bytes at RFC 3720 §3.1 offsets (5-7) and verify the
 *  getter reads from the correct position — without using the setter. */

void test_iscsi_pdu_data_seg_len_rfc_read(void) {
  uint8_t bhs[48];
  memset(bhs, 0, 48);

  /* RFC 3720 §3.1: DataSegmentLength at bytes 5-7 */
  bhs[5] = 0xAB;
  bhs[6] = 0xCD;
  bhs[7] = 0xEF;

  TEST_ASSERT_EQUAL_UINT32(0xABCDEF, snowscsi_iscsi_bhs_get_data_seg_len(bhs));
}

/* ── test_iscsi_pdu_data_seg_len_rfc_write ────────────────────────
 *  Call the setter, then verify each byte directly (not via getter)
 *  against RFC 3720 positions. Byte 4 (TotalAHSLength) must remain 0. */

void test_iscsi_pdu_data_seg_len_rfc_write(void) {
  uint8_t bhs[48];
  memset(bhs, 0, 48);

  snowscsi_iscsi_bhs_set_data_seg_len(bhs, 0xABCDEF);

  /* Byte 4 is TotalAHSLength — must not be overwritten */
  TEST_ASSERT_EQUAL_HEX8(0x00, bhs[4]);
  /* DataSegmentLength MSB at byte 5 */
  TEST_ASSERT_EQUAL_HEX8(0xAB, bhs[5]);
  /* DataSegmentLength middle at byte 6 */
  TEST_ASSERT_EQUAL_HEX8(0xCD, bhs[6]);
  /* DataSegmentLength LSB at byte 7 */
  TEST_ASSERT_EQUAL_HEX8(0xEF, bhs[7]);
}

/* ── test_iscsi_pdu_t_bit_rfc_read ────────────────────────────────
 *  Place T bit at RFC 3720 §10.12 position (byte 1, bit 7) and
 *  verify the getter reads from the correct byte.                   */

void test_iscsi_pdu_t_bit_rfc_read(void) {
  uint8_t bhs[48];
  memset(bhs, 0, 48);

  /* T bit set on byte 1 */
  bhs[1] = 0x80;
  TEST_ASSERT_TRUE(snowscsi_iscsi_bhs_get_t_bit(bhs));

  /* T bit clear, but set on byte 0 — should not be read as T bit */
  bhs[0] = 0x80;
  bhs[1] = 0x00;
  TEST_ASSERT_FALSE(snowscsi_iscsi_bhs_get_t_bit(bhs));
}

/* ── test_iscsi_pdu_t_bit_rfc_write ───────────────────────────────
 *  Call the setter, then verify byte positions directly.             */

void test_iscsi_pdu_t_bit_rfc_write(void) {
  uint8_t bhs[48];
  memset(bhs, 0, 48);

  snowscsi_iscsi_bhs_set_t_bit(bhs, true);

  /* T bit at byte 1, bit 7 */
  TEST_ASSERT_EQUAL_HEX8(0x80, bhs[1]);
  /* Byte 0 must not be affected */
  TEST_ASSERT_EQUAL_HEX8(0x00, bhs[0]);

  snowscsi_iscsi_bhs_set_t_bit(bhs, false);
  TEST_ASSERT_EQUAL_HEX8(0x00, bhs[1]);
}

/* ── Main ──────────────────────────────────────────────────────── */

int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_iscsi_pdu_opcode);
  RUN_TEST(test_iscsi_pdu_flags);
  RUN_TEST(test_iscsi_pdu_data_seg_len);
  RUN_TEST(test_iscsi_pdu_itt);
  RUN_TEST(test_iscsi_pdu_cmd_sn);
  RUN_TEST(test_iscsi_pdu_exp_stat_sn);
  RUN_TEST(test_iscsi_pdu_resp_stat_sn);
  RUN_TEST(test_iscsi_pdu_resp_exp_cmd_sn);
  RUN_TEST(test_iscsi_pdu_resp_max_cmd_sn);
  RUN_TEST(test_iscsi_pdu_notify_stat_sn);
  RUN_TEST(test_iscsi_pdu_notify_exp_cmd_sn);
  RUN_TEST(test_iscsi_pdu_notify_max_cmd_sn);
  RUN_TEST(test_iscsi_pdu_login_csg_nsg);
  RUN_TEST(test_iscsi_pdu_t_bit);
  RUN_TEST(test_iscsi_pdu_lun);
  RUN_TEST(test_iscsi_pdu_cdb);
  RUN_TEST(test_iscsi_pdu_scsi_status);
  RUN_TEST(test_iscsi_pdu_scsi_sense_len);
  RUN_TEST(test_iscsi_pdu_data_sn);
  RUN_TEST(test_iscsi_pdu_buffer_offset);
  RUN_TEST(test_iscsi_pdu_r2t);
  RUN_TEST(test_iscsi_pdu_ttt);
  RUN_TEST(test_iscsi_pdu_reject);
  RUN_TEST(test_iscsi_pdu_cdb_len_from_opcode);
  RUN_TEST(test_iscsi_pdu_data_seg_len_rfc_read);
  RUN_TEST(test_iscsi_pdu_data_seg_len_rfc_write);
  RUN_TEST(test_iscsi_pdu_t_bit_rfc_read);
  RUN_TEST(test_iscsi_pdu_t_bit_rfc_write);
  return UNITY_END();
}
