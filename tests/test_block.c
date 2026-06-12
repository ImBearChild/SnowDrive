#include "unity.h"
#include <snowscsi/block.h>
#include <snowscsi/device.h>
#include <snowscsi/scsi.h>
#include <string.h>

static snowscsi_device_t *dev;

void setUp(void) {
  dev = snowscsi_block_open_ram(1024 * 1024); /* 1 MB */
  TEST_ASSERT_NOT_NULL(dev);
}

void tearDown(void) {
  snowscsi_device_destroy(dev);
  dev = NULL;
}

/* ── Helper: build a 10-byte CDB ───────────────────────────────── */

static void make_cdb10(uint8_t *cdb, uint8_t opcode, uint32_t lba,
                       uint16_t transfer_len) {
  memset(cdb, 0, 10);
  cdb[0] = opcode;
  cdb[2] = (lba >> 24) & 0xFF;
  cdb[3] = (lba >> 16) & 0xFF;
  cdb[4] = (lba >> 8) & 0xFF;
  cdb[5] = (lba) & 0xFF;
  cdb[7] = (transfer_len >> 8) & 0xFF;
  cdb[8] = (transfer_len) & 0xFF;
}

/* ── Tests ─────────────────────────────────────────────────────── */

void test_block_create_ram(void) {
  /* setUp already created it — just verify type */
  TEST_ASSERT_EQUAL(SNOWSCSI_TYPE_BLOCK, snowscsi_device_get_type(dev));
}

void test_block_read_zero(void) {
  uint8_t cdb[10];
  make_cdb10(cdb, SNOWSCSI_OP_READ_10, 0, 1);

  uint32_t xfer;
  snowscsi_result_t r = snowscsi_do_cmd(dev, cdb, 10, &xfer);
  TEST_ASSERT_EQUAL(SNOWSCSI_DATA_IN, r);
  TEST_ASSERT_EQUAL(512, (int)xfer);

  uint8_t buf[512];
  int n = snowscsi_read_data(dev, buf, sizeof(buf));
  TEST_ASSERT_EQUAL(512, n);

  /* All zeros */
  uint8_t zeros[512];
  memset(zeros, 0, 512);
  TEST_ASSERT_EQUAL_MEMORY(zeros, buf, 512);

  /* Second read should return 0 */
  n = snowscsi_read_data(dev, buf, sizeof(buf));
  TEST_ASSERT_EQUAL(0, n);
}

void test_block_write_read_roundtrip(void) {
  uint8_t cdb[10];
  uint32_t xfer;

  /* Prepare write data */
  uint8_t pattern[512];
  for (int i = 0; i < 512; i++)
    pattern[i] = (uint8_t)(i & 0xFF);

  /* WRITE(10) LBA=10, 1 sector */
  make_cdb10(cdb, SNOWSCSI_OP_WRITE_10, 10, 1);
  snowscsi_result_t r = snowscsi_do_cmd(dev, cdb, 10, &xfer);
  TEST_ASSERT_EQUAL(SNOWSCSI_DATA_OUT, r);
  TEST_ASSERT_EQUAL(512, (int)xfer);

  int done = snowscsi_write_data(dev, pattern, 512);
  TEST_ASSERT_EQUAL(1, done);

  /* READ(10) LBA=10, 1 sector */
  make_cdb10(cdb, SNOWSCSI_OP_READ_10, 10, 1);
  r = snowscsi_do_cmd(dev, cdb, 10, &xfer);
  TEST_ASSERT_EQUAL(SNOWSCSI_DATA_IN, r);

  uint8_t buf[512];
  int n = snowscsi_read_data(dev, buf, 512);
  TEST_ASSERT_EQUAL(512, n);
  TEST_ASSERT_EQUAL_MEMORY(pattern, buf, 512);
}

void test_block_lba_out_of_range(void) {
  /* 1MB / 512 = 2048 sectors, max_lba = 2047 */
  uint8_t cdb[10];
  make_cdb10(cdb, SNOWSCSI_OP_READ_10, 2048, 1);

  uint32_t xfer;
  snowscsi_result_t r = snowscsi_do_cmd(dev, cdb, 10, &xfer);
  TEST_ASSERT_EQUAL(SNOWSCSI_CHECK_CONDITION, r);

  snowscsi_sense_t s;
  snowscsi_device_get_sense(dev, &s);
  TEST_ASSERT_EQUAL(SNOWSCSI_SENSE_ILLEGAL_REQUEST, s.key);
  TEST_ASSERT_EQUAL_HEX8(SNOWSCSI_ASC_LBA_OUT_OF_RANGE, s.asc);
}

void test_block_unknown_opcode(void) {
  uint8_t cdb[10];
  memset(cdb, 0, 10);
  cdb[0] = 0xFF;

  uint32_t xfer;
  snowscsi_result_t r = snowscsi_do_cmd(dev, cdb, 10, &xfer);
  TEST_ASSERT_EQUAL(SNOWSCSI_CHECK_CONDITION, r);

  snowscsi_sense_t s;
  snowscsi_device_get_sense(dev, &s);
  TEST_ASSERT_EQUAL(SNOWSCSI_SENSE_ILLEGAL_REQUEST, s.key);
  TEST_ASSERT_EQUAL_HEX8(SNOWSCSI_ASC_INVALID_COMMAND, s.asc);
}

void test_block_test_unit_ready(void) {
  uint8_t cdb[6];
  memset(cdb, 0, 6);

  uint32_t xfer;
  snowscsi_result_t r = snowscsi_do_cmd(dev, cdb, 6, &xfer);
  TEST_ASSERT_EQUAL(SNOWSCSI_STATUS, r);
}

void test_block_request_sense(void) {
  /* Trigger an error first */
  uint8_t cdb[10];
  memset(cdb, 0, 10);
  cdb[0] = 0xFF;
  uint32_t xfer;
  snowscsi_do_cmd(dev, cdb, 10, &xfer);

  /* Now REQUEST SENSE */
  memset(cdb, 0, 6);
  cdb[0] = SNOWSCSI_OP_REQUEST_SENSE;
  cdb[4] = 18;

  snowscsi_result_t r = snowscsi_do_cmd(dev, cdb, 6, &xfer);
  TEST_ASSERT_EQUAL(SNOWSCSI_DATA_IN, r);
  TEST_ASSERT_EQUAL(18, (int)xfer);

  uint8_t buf[18];
  int n = snowscsi_read_data(dev, buf, 18);
  TEST_ASSERT_EQUAL(18, n);

  /* Verify sense data */
  TEST_ASSERT_EQUAL_HEX8(0x70, buf[0]); /* response code */
  TEST_ASSERT_EQUAL_HEX8(0x05, buf[2]); /* ILLEGAL REQUEST */
  TEST_ASSERT_EQUAL_HEX8(SNOWSCSI_ASC_INVALID_COMMAND, buf[12]);
}

void test_block_read_capacity(void) {
  uint8_t cdb[10];
  memset(cdb, 0, 10);
  cdb[0] = SNOWSCSI_OP_READ_CAPACITY_10;

  uint32_t xfer;
  snowscsi_result_t r = snowscsi_do_cmd(dev, cdb, 10, &xfer);
  TEST_ASSERT_EQUAL(SNOWSCSI_DATA_IN, r);
  TEST_ASSERT_EQUAL(8, (int)xfer);

  uint8_t buf[8];
  int n = snowscsi_read_data(dev, buf, 8);
  TEST_ASSERT_EQUAL(8, n);

  uint32_t max_lba = ((uint32_t)buf[0] << 24) | ((uint32_t)buf[1] << 16) |
                     ((uint32_t)buf[2] << 8) | ((uint32_t)buf[3]);
  uint32_t block_size = ((uint32_t)buf[4] << 24) | ((uint32_t)buf[5] << 16) |
                        ((uint32_t)buf[6] << 8) | ((uint32_t)buf[7]);

  /* 1MB / 512 = 2048 sectors, max_lba = 2047 */
  TEST_ASSERT_EQUAL_UINT32(2047, max_lba);
  TEST_ASSERT_EQUAL_UINT32(512, block_size);
}

/* ── Main ──────────────────────────────────────────────────────── */

int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_block_create_ram);
  RUN_TEST(test_block_read_zero);
  RUN_TEST(test_block_write_read_roundtrip);
  RUN_TEST(test_block_lba_out_of_range);
  RUN_TEST(test_block_unknown_opcode);
  RUN_TEST(test_block_test_unit_ready);
  RUN_TEST(test_block_request_sense);
  RUN_TEST(test_block_read_capacity);
  return UNITY_END();
}
