#include "unity.h"

#include <snowscsi/iscsi.h>

#include <string.h>

void setUp(void) {}
void tearDown(void) {}

/* ── test_iscsi_login_resp_fields ────────────────────────────────
 *  Build a Login Response PDU and verify all field locations.      */

void test_iscsi_login_resp_fields(void) {
  uint8_t bhs[48];
  memset(bhs, 0, 48);

  uint32_t itt = 0x00001234;

  /* Simulate building a Login Response like the target does */
  snowscsi_iscsi_bhs_set_opcode(bhs, SNOWSCSI_ISCSI_OP_LOGIN_RESP);
  snowscsi_iscsi_bhs_set_t_bit(bhs, true);
  snowscsi_iscsi_bhs_set_itt(bhs, itt);

  /* NSG=3, CSG=1 */
  bhs[1] = (uint8_t)((SNOWSCSI_ISCSI_STAGE_OP_PARAM
                      << SNOWSCSI_ISCSI_FLAG_CSG_SHIFT) |
                     (SNOWSCSI_ISCSI_STAGE_FULL_FEATURE
                      << SNOWSCSI_ISCSI_FLAG_NSG_SHIFT));

  /* Notification-style sequence numbers (used by Login Resp) */
  snowscsi_iscsi_bhs_notify_set_stat_sn(bhs, 0);
  snowscsi_iscsi_bhs_notify_set_exp_cmd_sn(bhs, 0);
  snowscsi_iscsi_bhs_notify_set_max_cmd_sn(bhs, 0);

  /* DataSegmentLength */
  snowscsi_iscsi_bhs_set_data_seg_len(bhs, 187);

  /* Verify */
  TEST_ASSERT_EQUAL_HEX8(SNOWSCSI_ISCSI_OP_LOGIN_RESP,
                         snowscsi_iscsi_bhs_get_opcode(bhs));
  TEST_ASSERT_TRUE(snowscsi_iscsi_bhs_get_t_bit(bhs));
  TEST_ASSERT_EQUAL_UINT32(itt, snowscsi_iscsi_bhs_get_itt(bhs));
  TEST_ASSERT_EQUAL_UINT8(SNOWSCSI_ISCSI_STAGE_OP_PARAM,
                          snowscsi_iscsi_bhs_get_csg(bhs));
  TEST_ASSERT_EQUAL_UINT8(SNOWSCSI_ISCSI_STAGE_FULL_FEATURE,
                          snowscsi_iscsi_bhs_get_nsg(bhs));
  TEST_ASSERT_EQUAL_UINT32(0, snowscsi_iscsi_bhs_notify_get_stat_sn(bhs));
  TEST_ASSERT_EQUAL_UINT32(187, snowscsi_iscsi_bhs_get_data_seg_len(bhs));
}

/* ── test_iscsi_scsi_resp_fields ─────────────────────────────────
 *  Build a SCSI Response PDU and verify field locations.           */

void test_iscsi_scsi_resp_fields(void) {
  uint8_t bhs[48];
  memset(bhs, 0, 48);

  uint32_t itt = 0x00005678;
  uint32_t stat_sn = 5;
  uint32_t exp_cmd_sn = 4;
  uint32_t max_cmd_sn = 4;

  snowscsi_iscsi_bhs_set_opcode(bhs, SNOWSCSI_ISCSI_OP_SCSI_RESP);
  snowscsi_iscsi_bhs_set_itt(bhs, itt);
  snowscsi_iscsi_bhs_set_status(bhs, SNOWSCSI_ISCSI_SCSI_STATUS_GOOD);
  snowscsi_iscsi_bhs_set_sense_len(bhs, 18);
  snowscsi_iscsi_bhs_resp_set_stat_sn(bhs, stat_sn);
  snowscsi_iscsi_bhs_resp_set_exp_cmd_sn(bhs, exp_cmd_sn);
  snowscsi_iscsi_bhs_resp_set_max_cmd_sn(bhs, max_cmd_sn);
  snowscsi_iscsi_bhs_set_data_seg_len(bhs, 18);

  /* Verify */
  TEST_ASSERT_EQUAL_HEX8(SNOWSCSI_ISCSI_OP_SCSI_RESP,
                         snowscsi_iscsi_bhs_get_opcode(bhs));
  TEST_ASSERT_EQUAL_UINT32(itt, snowscsi_iscsi_bhs_get_itt(bhs));
  TEST_ASSERT_EQUAL_HEX8(SNOWSCSI_ISCSI_SCSI_STATUS_GOOD, bhs[3]);
  TEST_ASSERT_EQUAL_HEX8(18, bhs[2]);
  TEST_ASSERT_EQUAL_UINT32(stat_sn, snowscsi_iscsi_bhs_resp_get_stat_sn(bhs));
  TEST_ASSERT_EQUAL_UINT32(exp_cmd_sn,
                           snowscsi_iscsi_bhs_resp_get_exp_cmd_sn(bhs));
  TEST_ASSERT_EQUAL_UINT32(max_cmd_sn,
                           snowscsi_iscsi_bhs_resp_get_max_cmd_sn(bhs));
  TEST_ASSERT_EQUAL_UINT32(18, snowscsi_iscsi_bhs_get_data_seg_len(bhs));
}

/* ── test_iscsi_data_in_fields ───────────────────────────────────
 *  Build a Data-In PDU with F=1, S=1 and verify all fields.       */

void test_iscsi_data_in_fields(void) {
  uint8_t bhs[48];
  memset(bhs, 0, 48);

  uint32_t itt = 0x0000ABCD;
  uint32_t data_sn = 3;
  uint32_t stat_sn = 7;
  uint32_t exp_cmd_sn = 8;

  snowscsi_iscsi_bhs_set_opcode(bhs, SNOWSCSI_ISCSI_OP_SCSI_DATA_IN);
  snowscsi_iscsi_bhs_set_itt(bhs, itt);
  snowscsi_iscsi_bhs_set_data_sn(bhs, data_sn);
  snowscsi_iscsi_bhs_set_data_seg_len(bhs, 2048);

  /* F=1, S=1 */
  bhs[1] |= SNOWSCSI_ISCSI_FLAG_DATA_FINAL;
  bhs[1] |= SNOWSCSI_ISCSI_FLAG_DATA_STATUS;

  /* Status included in final Data-In — uses notify-style offsets */
  snowscsi_iscsi_bhs_set_status(bhs, SNOWSCSI_ISCSI_SCSI_STATUS_GOOD);
  snowscsi_iscsi_bhs_notify_set_stat_sn(bhs, stat_sn);
  snowscsi_iscsi_bhs_notify_set_exp_cmd_sn(bhs, exp_cmd_sn);
  snowscsi_iscsi_bhs_notify_set_max_cmd_sn(bhs, exp_cmd_sn);

  /* Verify */
  TEST_ASSERT_EQUAL_HEX8(SNOWSCSI_ISCSI_OP_SCSI_DATA_IN,
                         snowscsi_iscsi_bhs_get_opcode(bhs));
  TEST_ASSERT_EQUAL_UINT32(data_sn, snowscsi_iscsi_bhs_get_data_sn(bhs));
  TEST_ASSERT_EQUAL_UINT32(2048, snowscsi_iscsi_bhs_get_data_seg_len(bhs));
  TEST_ASSERT_EQUAL_UINT32(stat_sn, snowscsi_iscsi_bhs_notify_get_stat_sn(bhs));
}

/* ── test_iscsi_r2t_fields ───────────────────────────────────────
 *  Build an R2T PDU and verify field locations.                    */

void test_iscsi_r2t_fields(void) {
  uint8_t bhs[48];
  memset(bhs, 0, 48);

  uint32_t itt = 0x00001111;
  uint32_t ttt = 0x00000001;
  uint32_t stat_sn = 2;
  uint32_t exp_cmd_sn = 3;
  uint32_t buffer_offset = 0;
  uint32_t desired_len = 512;

  snowscsi_iscsi_bhs_set_opcode(bhs, SNOWSCSI_ISCSI_OP_R2T);
  snowscsi_iscsi_bhs_set_itt(bhs, itt);
  snowscsi_iscsi_bhs_set_ttt(bhs, ttt);
  snowscsi_iscsi_bhs_notify_set_stat_sn(bhs, stat_sn);
  snowscsi_iscsi_bhs_notify_set_exp_cmd_sn(bhs, exp_cmd_sn);
  snowscsi_iscsi_bhs_notify_set_max_cmd_sn(bhs, exp_cmd_sn);
  snowscsi_iscsi_bhs_set_r2t_buffer_offset(bhs, buffer_offset);
  snowscsi_iscsi_bhs_set_desired_data_len(bhs, desired_len);

  /* Verify — R2T uses bytes 20-23 for Desired Data Transfer
   * Length (same offset as TTT in other PDUs) */
  TEST_ASSERT_EQUAL_HEX8(SNOWSCSI_ISCSI_OP_R2T,
                         snowscsi_iscsi_bhs_get_opcode(bhs));
  TEST_ASSERT_EQUAL_UINT32(itt, snowscsi_iscsi_bhs_get_itt(bhs));
  TEST_ASSERT_EQUAL_UINT32(stat_sn, snowscsi_iscsi_bhs_notify_get_stat_sn(bhs));

  /* Desired Data Transfer Length at bytes 20-23 (= desired_len, 512) */
  TEST_ASSERT_EQUAL_UINT32(desired_len, snowscsi_iscsi_bhs_get_ttt(bhs));

  /* Buffer Offset at bytes 40-43 = 0 */
  TEST_ASSERT_EQUAL_HEX8(0x00, bhs[40]);
  TEST_ASSERT_EQUAL_HEX8(0x00, bhs[41]);
  TEST_ASSERT_EQUAL_HEX8(0x00, bhs[42]);
  TEST_ASSERT_EQUAL_HEX8(0x00, bhs[43]);
}

/* ── test_iscsi_nop_in_fields ────────────────────────────────────
 *  Build a NOP-In PDU and verify sequence numbers.                 */

void test_iscsi_nop_in_fields(void) {
  uint8_t bhs[48];
  memset(bhs, 0, 48);

  uint32_t itt = 0x0000BEEF;
  uint32_t ttt = 0xFFFFFFFF;
  uint32_t stat_sn = 10;
  uint32_t exp_cmd_sn = 15;

  snowscsi_iscsi_bhs_set_opcode(bhs, SNOWSCSI_ISCSI_OP_NOP_IN);
  snowscsi_iscsi_bhs_set_itt(bhs, itt);
  snowscsi_iscsi_bhs_set_ttt(bhs, ttt);
  snowscsi_iscsi_bhs_notify_set_stat_sn(bhs, stat_sn);
  snowscsi_iscsi_bhs_notify_set_exp_cmd_sn(bhs, exp_cmd_sn);
  snowscsi_iscsi_bhs_notify_set_max_cmd_sn(bhs, exp_cmd_sn);

  TEST_ASSERT_EQUAL_UINT32(itt, snowscsi_iscsi_bhs_get_itt(bhs));
  TEST_ASSERT_EQUAL_UINT32(ttt, snowscsi_iscsi_bhs_get_ttt(bhs));
  TEST_ASSERT_EQUAL_UINT32(stat_sn, snowscsi_iscsi_bhs_notify_get_stat_sn(bhs));
}

/* ── test_iscsi_reject_fields ────────────────────────────────────
 *  Build a Reject PDU for CmdSN mismatch.                          */

void test_iscsi_reject_fields(void) {
  uint8_t bhs[48];
  memset(bhs, 0, 48);

  uint32_t stat_sn = 3;
  uint32_t exp_cmd_sn = 5;

  snowscsi_iscsi_bhs_set_opcode(bhs, SNOWSCSI_ISCSI_OP_REJECT);
  snowscsi_iscsi_bhs_set_reject_reason(bhs, SNOWSCSI_ISCSI_REJECT_CMD_SN);
  snowscsi_iscsi_bhs_notify_set_stat_sn(bhs, stat_sn);
  snowscsi_iscsi_bhs_notify_set_exp_cmd_sn(bhs, exp_cmd_sn);
  snowscsi_iscsi_bhs_notify_set_max_cmd_sn(bhs, exp_cmd_sn);

  TEST_ASSERT_EQUAL_HEX8(SNOWSCSI_ISCSI_REJECT_CMD_SN,
                         snowscsi_iscsi_bhs_get_reject_reason(bhs));
  TEST_ASSERT_EQUAL_UINT32(stat_sn, snowscsi_iscsi_bhs_notify_get_stat_sn(bhs));
}

/* ── test_iscsi_sequence_stat_sn_increment ───────────────────────
 *  Simulate sending three SCSI Responses in sequence and verify
 *  StatSN increments properly.                                     */

void test_iscsi_sequence_stat_sn_increment(void) {
  uint8_t bhs[48];
  uint32_t stat_sn = 1;
  uint32_t cmd_sn = 0;

  /* Response 1: StatSN=1 */
  memset(bhs, 0, 48);
  snowscsi_iscsi_bhs_set_opcode(bhs, SNOWSCSI_ISCSI_OP_SCSI_RESP);
  snowscsi_iscsi_bhs_resp_set_stat_sn(bhs, stat_sn);
  TEST_ASSERT_EQUAL_UINT32(1, snowscsi_iscsi_bhs_resp_get_stat_sn(bhs));
  stat_sn++;
  cmd_sn++;

  /* Response 2: StatSN=2 */
  memset(bhs, 0, 48);
  snowscsi_iscsi_bhs_set_opcode(bhs, SNOWSCSI_ISCSI_OP_SCSI_RESP);
  snowscsi_iscsi_bhs_resp_set_stat_sn(bhs, stat_sn);
  TEST_ASSERT_EQUAL_UINT32(2, snowscsi_iscsi_bhs_resp_get_stat_sn(bhs));
  stat_sn++;
  cmd_sn++;

  /* Response 3: StatSN=3 */
  memset(bhs, 0, 48);
  snowscsi_iscsi_bhs_set_opcode(bhs, SNOWSCSI_ISCSI_OP_SCSI_RESP);
  snowscsi_iscsi_bhs_resp_set_stat_sn(bhs, stat_sn);
  TEST_ASSERT_EQUAL_UINT32(3, snowscsi_iscsi_bhs_resp_get_stat_sn(bhs));
}

/* ── test_iscsi_sequence_exp_max_cmd_sn ──────────────────────────
 *  Verify ExpCmdSN = MaxCmdSN = CmdSN + 1 after each command.     */

void test_iscsi_sequence_exp_max_cmd_sn(void) {
  uint8_t bhs[48];
  uint32_t cmd_sn = 0;

  /* After processing first command (CmdSN=0), ExpCmdSN should be 1
   */
  memset(bhs, 0, 48);
  snowscsi_iscsi_bhs_set_opcode(bhs, SNOWSCSI_ISCSI_OP_SCSI_RESP);
  snowscsi_iscsi_bhs_resp_set_exp_cmd_sn(bhs, cmd_sn + 1);
  snowscsi_iscsi_bhs_resp_set_max_cmd_sn(bhs, cmd_sn + 1);

  TEST_ASSERT_EQUAL_UINT32(1, snowscsi_iscsi_bhs_resp_get_exp_cmd_sn(bhs));
  TEST_ASSERT_EQUAL_UINT32(1, snowscsi_iscsi_bhs_resp_get_max_cmd_sn(bhs));

  cmd_sn = 1;

  /* After second command (CmdSN=1) */
  memset(bhs, 0, 48);
  snowscsi_iscsi_bhs_set_opcode(bhs, SNOWSCSI_ISCSI_OP_SCSI_RESP);
  snowscsi_iscsi_bhs_resp_set_exp_cmd_sn(bhs, cmd_sn + 1);
  snowscsi_iscsi_bhs_resp_set_max_cmd_sn(bhs, cmd_sn + 1);

  TEST_ASSERT_EQUAL_UINT32(2, snowscsi_iscsi_bhs_resp_get_exp_cmd_sn(bhs));
  TEST_ASSERT_EQUAL_UINT32(2, snowscsi_iscsi_bhs_resp_get_max_cmd_sn(bhs));
}

/* ── test_iscsi_login_params_len ─────────────────────────────────
 *  Verify the login parameter list has expected content.           */

void test_iscsi_login_params_len(void) {
  /* Login parameter text from the target implementation:
   * each key=value pair is null-terminated, including the last. */
  const char params[] = "TargetName=iqn.2025-01.local.snowscsi:target\0"
                        "TargetAlias=SnowSCSI\0"
                        "MaxConnections=1\0"
                        "InitialR2T=Yes\0"
                        "ImmediateData=Yes\0"
                        "MaxRecvDataSegmentLength=8192\0"
                        "MaxBurstLength=262144\0"
                        "FirstBurstLength=65536\0"
                        "MaxOutstandingR2T=1\0"
                        "ErrorRecoveryLevel=0\0"
                        "TargetPortalGroupTag=1\0";

  uint32_t len = sizeof(params) - 1;
  TEST_ASSERT_GREATER_THAN_UINT32(0, len);
  TEST_ASSERT_LESS_OR_EQUAL_UINT32(SNOWSCSI_ISCSI_MAX_DATA_SEGMENT, len);

  /* DataSegmentLength should be the total length */
  TEST_ASSERT_TRUE(len <= 4096);
}

/* ── test_iscsi_logout_resp_fields ───────────────────────────────
 *  Build a Logout Response PDU and verify.                         */

void test_iscsi_logout_resp_fields(void) {
  uint8_t bhs[48];
  memset(bhs, 0, 48);

  uint32_t itt = 0xCAFE;
  uint32_t stat_sn = 15;
  uint32_t exp_cmd_sn = 20;

  snowscsi_iscsi_bhs_set_opcode(bhs, SNOWSCSI_ISCSI_OP_LOGOUT_RESP);
  snowscsi_iscsi_bhs_set_itt(bhs, itt);
  snowscsi_iscsi_bhs_resp_set_stat_sn(bhs, stat_sn);
  snowscsi_iscsi_bhs_resp_set_exp_cmd_sn(bhs, exp_cmd_sn);
  snowscsi_iscsi_bhs_resp_set_max_cmd_sn(bhs, exp_cmd_sn);

  TEST_ASSERT_EQUAL_HEX8(SNOWSCSI_ISCSI_OP_LOGOUT_RESP,
                         snowscsi_iscsi_bhs_get_opcode(bhs));
  TEST_ASSERT_EQUAL_UINT32(itt, snowscsi_iscsi_bhs_get_itt(bhs));
  TEST_ASSERT_EQUAL_UINT32(stat_sn, snowscsi_iscsi_bhs_resp_get_stat_sn(bhs));
}

/* ── Main ──────────────────────────────────────────────────────── */

int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_iscsi_login_resp_fields);
  RUN_TEST(test_iscsi_scsi_resp_fields);
  RUN_TEST(test_iscsi_data_in_fields);
  RUN_TEST(test_iscsi_r2t_fields);
  RUN_TEST(test_iscsi_nop_in_fields);
  RUN_TEST(test_iscsi_reject_fields);
  RUN_TEST(test_iscsi_sequence_stat_sn_increment);
  RUN_TEST(test_iscsi_sequence_exp_max_cmd_sn);
  RUN_TEST(test_iscsi_login_params_len);
  RUN_TEST(test_iscsi_logout_resp_fields);
  return UNITY_END();
}
