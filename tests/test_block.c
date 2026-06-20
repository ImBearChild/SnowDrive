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

/* ── Helper: build a 6-byte CDB ─────────────────────────────────── */

static void make_cdb6(uint8_t *cdb, uint8_t opcode, uint32_t lba,
                      uint8_t transfer_len) {
  memset(cdb, 0, 6);
  cdb[0] = opcode;
  cdb[1] = (uint8_t)((lba >> 16) & 0x1F);
  cdb[2] = (uint8_t)((lba >> 8) & 0xFF);
  cdb[3] = (uint8_t)(lba & 0xFF);
  cdb[4] = transfer_len;
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

/* ── Helper: build a 12-byte CDB ────────────────────────────────── */

static void make_cdb12(uint8_t *cdb, uint8_t opcode, uint32_t lba,
                       uint32_t transfer_len) {
  memset(cdb, 0, 12);
  cdb[0] = opcode;
  cdb[2] = (lba >> 24) & 0xFF;
  cdb[3] = (lba >> 16) & 0xFF;
  cdb[4] = (lba >> 8) & 0xFF;
  cdb[5] = (lba) & 0xFF;
  cdb[6] = (transfer_len >> 24) & 0xFF;
  cdb[7] = (transfer_len >> 16) & 0xFF;
  cdb[8] = (transfer_len >> 8) & 0xFF;
  cdb[9] = (transfer_len) & 0xFF;
}

/* ── Helper: build a 16-byte CDB ────────────────────────────────── */

static void make_cdb16(uint8_t *cdb, uint8_t opcode, uint64_t lba,
                       uint32_t transfer_len) {
  memset(cdb, 0, 16);
  cdb[0] = opcode;
  cdb[2] = (uint8_t)(lba >> 56);
  cdb[3] = (uint8_t)(lba >> 48);
  cdb[4] = (uint8_t)(lba >> 40);
  cdb[5] = (uint8_t)(lba >> 32);
  cdb[6] = (uint8_t)(lba >> 24);
  cdb[7] = (uint8_t)(lba >> 16);
  cdb[8] = (uint8_t)(lba >> 8);
  cdb[9] = (uint8_t)(lba);
  cdb[10] = (uint8_t)(transfer_len >> 24);
  cdb[11] = (uint8_t)(transfer_len >> 16);
  cdb[12] = (uint8_t)(transfer_len >> 8);
  cdb[13] = (uint8_t)(transfer_len);
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

void test_block_read_capacity_16(void) {
  uint8_t cdb[16];
  memset(cdb, 0, 16);
  cdb[0] = SNOWSCSI_OP_SERVICE_ACTION_IN;
  cdb[1] = 0x10;
  cdb[10] = 0x00;
  cdb[11] = 0x00;
  cdb[12] = 0x00;
  cdb[13] = 0x20;

  uint32_t xfer;
  snowscsi_result_t r = snowscsi_do_cmd(dev, cdb, 16, &xfer);
  TEST_ASSERT_EQUAL(SNOWSCSI_DATA_IN, r);
  TEST_ASSERT_EQUAL(32, (int)xfer);

  uint8_t buf[32];
  int n = snowscsi_read_data(dev, buf, 32);
  TEST_ASSERT_EQUAL(32, n);

  /* 1MB / 512 = 2048 sectors, max_lba = 2047 = 0x00000000000007FF */
  uint8_t expected_lba[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0xFF};
  TEST_ASSERT_EQUAL_MEMORY(expected_lba, buf, 8);

  /* Block length = 512 = 0x00000200 */
  uint8_t expected_blk[4] = {0x00, 0x00, 0x02, 0x00};
  TEST_ASSERT_EQUAL_MEMORY(expected_blk, buf + 8, 4);

  /* Bytes 12-31: protection / reserved — all zero */
  uint8_t zeros[20];
  memset(zeros, 0, 20);
  TEST_ASSERT_EQUAL_MEMORY(zeros, buf + 12, 20);
}

void test_block_read_capacity_16_unknown_sa(void) {
  uint8_t cdb[16];
  memset(cdb, 0, 16);
  cdb[0] = SNOWSCSI_OP_SERVICE_ACTION_IN;
  cdb[1] = 0xFF;

  uint32_t xfer;
  snowscsi_result_t r = snowscsi_do_cmd(dev, cdb, 16, &xfer);
  TEST_ASSERT_EQUAL(SNOWSCSI_CHECK_CONDITION, r);

  snowscsi_sense_t s;
  snowscsi_device_get_sense(dev, &s);
  TEST_ASSERT_EQUAL(SNOWSCSI_SENSE_ILLEGAL_REQUEST, s.key);
  TEST_ASSERT_EQUAL_HEX8(SNOWSCSI_ASC_INVALID_FIELD, s.asc);
}

void test_block_read_6_zero_blocks(void) {
  uint8_t cdb[6];
  make_cdb6(cdb, SNOWSCSI_OP_READ_6, 0, 0); /* 0 = 256 blocks */

  uint32_t xfer;
  snowscsi_result_t r = snowscsi_do_cmd(dev, cdb, 6, &xfer);
  TEST_ASSERT_EQUAL(SNOWSCSI_DATA_IN, r);
  TEST_ASSERT_EQUAL(256 * 512, (int)xfer);

  uint8_t buf[256 * 512];
  int n = snowscsi_read_data(dev, buf, sizeof(buf));
  TEST_ASSERT_EQUAL(sizeof(buf), (size_t)n);
}

void test_block_write_read_roundtrip_6(void) {
  uint8_t cdb[6];
  uint32_t xfer;

  uint8_t pattern[512];
  for (int i = 0; i < 512; i++)
    pattern[i] = (uint8_t)(i & 0xFF);

  make_cdb6(cdb, SNOWSCSI_OP_WRITE_6, 5, 1);
  snowscsi_result_t r = snowscsi_do_cmd(dev, cdb, 6, &xfer);
  TEST_ASSERT_EQUAL(SNOWSCSI_DATA_OUT, r);
  TEST_ASSERT_EQUAL(512, (int)xfer);
  TEST_ASSERT_EQUAL(1, snowscsi_write_data(dev, pattern, 512));

  make_cdb6(cdb, SNOWSCSI_OP_READ_6, 5, 1);
  r = snowscsi_do_cmd(dev, cdb, 6, &xfer);
  TEST_ASSERT_EQUAL(SNOWSCSI_DATA_IN, r);

  uint8_t buf[512];
  int n = snowscsi_read_data(dev, buf, 512);
  TEST_ASSERT_EQUAL(512, n);
  TEST_ASSERT_EQUAL_MEMORY(pattern, buf, 512);
}

void test_block_write_read_roundtrip_12(void) {
  uint8_t cdb[12];
  uint32_t xfer;

  uint8_t pattern[1024];
  for (int i = 0; i < 1024; i++)
    pattern[i] = (uint8_t)(i & 0xFF);

  make_cdb12(cdb, SNOWSCSI_OP_WRITE_12, 20, 2);
  snowscsi_result_t r = snowscsi_do_cmd(dev, cdb, 12, &xfer);
  TEST_ASSERT_EQUAL(SNOWSCSI_DATA_OUT, r);
  TEST_ASSERT_EQUAL(1024, (int)xfer);
  TEST_ASSERT_EQUAL(1, snowscsi_write_data(dev, pattern, 1024));

  make_cdb12(cdb, SNOWSCSI_OP_READ_12, 20, 2);
  r = snowscsi_do_cmd(dev, cdb, 12, &xfer);
  TEST_ASSERT_EQUAL(SNOWSCSI_DATA_IN, r);

  uint8_t buf[1024];
  int n = snowscsi_read_data(dev, buf, 1024);
  TEST_ASSERT_EQUAL(1024, n);
  TEST_ASSERT_EQUAL_MEMORY(pattern, buf, 1024);
}

void test_block_write_read_roundtrip_16(void) {
  uint8_t cdb[16];
  uint32_t xfer;

  uint8_t pattern[1024];
  for (int i = 0; i < 1024; i++)
    pattern[i] = (uint8_t)(i & 0xFF);

  make_cdb16(cdb, SNOWSCSI_OP_WRITE_16, 30, 2);
  snowscsi_result_t r = snowscsi_do_cmd(dev, cdb, 16, &xfer);
  TEST_ASSERT_EQUAL(SNOWSCSI_DATA_OUT, r);
  TEST_ASSERT_EQUAL(1024, (int)xfer);
  TEST_ASSERT_EQUAL(1, snowscsi_write_data(dev, pattern, 1024));

  make_cdb16(cdb, SNOWSCSI_OP_READ_16, 30, 2);
  r = snowscsi_do_cmd(dev, cdb, 16, &xfer);
  TEST_ASSERT_EQUAL(SNOWSCSI_DATA_IN, r);

  uint8_t buf[1024];
  int n = snowscsi_read_data(dev, buf, 1024);
  TEST_ASSERT_EQUAL(1024, n);
  TEST_ASSERT_EQUAL_MEMORY(pattern, buf, 1024);
}

void test_block_read_zero_6(void) {
  uint8_t cdb[6];
  make_cdb6(cdb, SNOWSCSI_OP_READ_6, 0, 0);

  uint32_t xfer;
  snowscsi_result_t r = snowscsi_do_cmd(dev, cdb, 6, &xfer);
  TEST_ASSERT_EQUAL(SNOWSCSI_DATA_IN, r);
  TEST_ASSERT_EQUAL(256 * 512, (int)xfer);

  uint8_t buf[256 * 512];
  int n = snowscsi_read_data(dev, buf, sizeof(buf));
  TEST_ASSERT_EQUAL(sizeof(buf), (size_t)n);

  uint8_t zeros[256 * 512];
  memset(zeros, 0, sizeof(zeros));
  TEST_ASSERT_EQUAL_MEMORY(zeros, buf, sizeof(buf));
}

void test_block_lba_out_of_range_6(void) {
  /* 1MB / 512 = 2048 sectors, max_lba = 2047 */
  uint8_t cdb[6];
  make_cdb6(cdb, SNOWSCSI_OP_READ_6, 2048, 1);

  uint32_t xfer;
  snowscsi_result_t r = snowscsi_do_cmd(dev, cdb, 6, &xfer);
  TEST_ASSERT_EQUAL(SNOWSCSI_CHECK_CONDITION, r);

  snowscsi_sense_t s;
  snowscsi_device_get_sense(dev, &s);
  TEST_ASSERT_EQUAL(SNOWSCSI_SENSE_ILLEGAL_REQUEST, s.key);
  TEST_ASSERT_EQUAL_HEX8(SNOWSCSI_ASC_LBA_OUT_OF_RANGE, s.asc);
}

void test_block_lba_out_of_range_12(void) {
  uint8_t cdb[12];
  make_cdb12(cdb, SNOWSCSI_OP_READ_12, 2048, 1);

  uint32_t xfer;
  snowscsi_result_t r = snowscsi_do_cmd(dev, cdb, 12, &xfer);
  TEST_ASSERT_EQUAL(SNOWSCSI_CHECK_CONDITION, r);

  snowscsi_sense_t s;
  snowscsi_device_get_sense(dev, &s);
  TEST_ASSERT_EQUAL(SNOWSCSI_SENSE_ILLEGAL_REQUEST, s.key);
  TEST_ASSERT_EQUAL_HEX8(SNOWSCSI_ASC_LBA_OUT_OF_RANGE, s.asc);
}

void test_block_lba_out_of_range_16(void) {
  uint8_t cdb[16];
  make_cdb16(cdb, SNOWSCSI_OP_READ_16, 2048, 1);

  uint32_t xfer;
  snowscsi_result_t r = snowscsi_do_cmd(dev, cdb, 16, &xfer);
  TEST_ASSERT_EQUAL(SNOWSCSI_CHECK_CONDITION, r);

  snowscsi_sense_t s;
  snowscsi_device_get_sense(dev, &s);
  TEST_ASSERT_EQUAL(SNOWSCSI_SENSE_ILLEGAL_REQUEST, s.key);
  TEST_ASSERT_EQUAL_HEX8(SNOWSCSI_ASC_LBA_OUT_OF_RANGE, s.asc);
}

/* ── New command tests ─────────────────────────────────────────── */

void test_block_inquiry_version_spc3(void) {
  uint8_t cdb[6];
  memset(cdb, 0, 6);
  cdb[0] = SNOWSCSI_OP_INQUIRY;
  cdb[4] = 96;

  uint32_t xfer;
  snowscsi_result_t r = snowscsi_do_cmd(dev, cdb, 6, &xfer);
  TEST_ASSERT_EQUAL(SNOWSCSI_DATA_IN, r);

  uint8_t buf[96];
  int n = snowscsi_read_data(dev, buf, 96);
  TEST_ASSERT_EQUAL(95, n);

  TEST_ASSERT_EQUAL_HEX8(0x00, buf[0]);          /* PDT = disk */
  TEST_ASSERT_EQUAL_HEX8(0x05, buf[2]);          /* Version = SPC-3 */
  TEST_ASSERT_EQUAL_HEX8(0x02, buf[7]);          /* CmdQue = 1 */
  TEST_ASSERT_EQUAL_HEX8(90, buf[4]);            /* Additional Length = total - 5 */
  TEST_ASSERT_EQUAL_MEMORY("SnowSCSI", buf + 8, 8);
  TEST_ASSERT_EQUAL_MEMORY("Virtual Disk    ", buf + 16, 16);
  TEST_ASSERT_EQUAL_MEMORY("0100", buf + 32, 4);
  /* Version descriptors */
  TEST_ASSERT_EQUAL_HEX8(0x00, buf[58]);
  TEST_ASSERT_EQUAL_HEX8(0xA0, buf[59]); /* SAM-5 */
  TEST_ASSERT_EQUAL_HEX8(0x09, buf[60]);
  TEST_ASSERT_EQUAL_HEX8(0x60, buf[61]); /* iSCSI */
}

void test_block_inquiry_evpd_page_code_nonzero(void) {
  uint8_t cdb[6];
  memset(cdb, 0, 6);
  cdb[0] = SNOWSCSI_OP_INQUIRY;
  cdb[2] = 0x01; /* EVPD=0, Page Code=1 */
  cdb[4] = 96;

  uint32_t xfer;
  snowscsi_result_t r = snowscsi_do_cmd(dev, cdb, 6, &xfer);
  TEST_ASSERT_EQUAL(SNOWSCSI_CHECK_CONDITION, r);

  snowscsi_sense_t s;
  snowscsi_device_get_sense(dev, &s);
  TEST_ASSERT_EQUAL(SNOWSCSI_SENSE_ILLEGAL_REQUEST, s.key);
  TEST_ASSERT_EQUAL_HEX8(SNOWSCSI_ASC_INVALID_FIELD, s.asc);
}

void test_block_inquiry_vpd_00(void) {
  uint8_t cdb[6];
  memset(cdb, 0, 6);
  cdb[0] = SNOWSCSI_OP_INQUIRY;
  cdb[1] = 0x01; /* EVPD=1 */
  cdb[2] = 0x00; /* Page Code = 0x00 */
  cdb[4] = 8;

  uint32_t xfer;
  snowscsi_result_t r = snowscsi_do_cmd(dev, cdb, 6, &xfer);
  TEST_ASSERT_EQUAL(SNOWSCSI_DATA_IN, r);

  uint8_t buf[8];
  int n = snowscsi_read_data(dev, buf, 8);
  TEST_ASSERT_EQUAL(7, n); /* VPD_PAGE_LIST_LEN = 7 */

  TEST_ASSERT_EQUAL_HEX8(0x00, buf[0]); /* PDT */
  TEST_ASSERT_EQUAL_HEX8(0x00, buf[1]); /* Page Code */
  TEST_ASSERT_EQUAL_HEX8(0x03, buf[3]); /* Page Length = 3 */
  TEST_ASSERT_EQUAL_HEX8(0x00, buf[4]); /* Page 0x00 supported */
  TEST_ASSERT_EQUAL_HEX8(0x80, buf[5]); /* Page 0x80 supported */
  TEST_ASSERT_EQUAL_HEX8(0x83, buf[6]); /* Page 0x83 supported */
}

void test_block_inquiry_vpd_80(void) {
  uint8_t cdb[6];
  memset(cdb, 0, 6);
  cdb[0] = SNOWSCSI_OP_INQUIRY;
  cdb[1] = 0x01; /* EVPD=1 */
  cdb[2] = 0x80;
  cdb[4] = 20; /* alloc len */

  uint32_t xfer;
  snowscsi_result_t r = snowscsi_do_cmd(dev, cdb, 6, &xfer);
  TEST_ASSERT_EQUAL(SNOWSCSI_DATA_IN, r);

  uint8_t buf[20];
  int n = snowscsi_read_data(dev, buf, sizeof(buf));
  TEST_ASSERT_EQUAL(20, n);

  TEST_ASSERT_EQUAL_HEX8(0x80, buf[1]); /* Page Code */
  TEST_ASSERT_EQUAL_HEX8(16, buf[3]);   /* Page Length */
  /* Serial should start with SNOW */
  TEST_ASSERT_EQUAL_MEMORY("SNOW", buf + 4, 4);
}

void test_block_inquiry_vpd_83(void) {
  uint8_t cdb[6];
  memset(cdb, 0, 6);
  cdb[0] = SNOWSCSI_OP_INQUIRY;
  cdb[1] = 0x01; /* EVPD=1 */
  cdb[2] = 0x83;
  cdb[4] = 16; /* alloc len */

  uint32_t xfer;
  snowscsi_result_t r = snowscsi_do_cmd(dev, cdb, 6, &xfer);
  TEST_ASSERT_EQUAL(SNOWSCSI_DATA_IN, r);

  uint8_t buf[16];
  int n = snowscsi_read_data(dev, buf, sizeof(buf));
  TEST_ASSERT_EQUAL(16, n);

  TEST_ASSERT_EQUAL_HEX8(0x83, buf[1]); /* Page Code */
  /* Designation descriptor #1: NAA */
  TEST_ASSERT_EQUAL_HEX8(0x04, buf[4]);  /* Code Set = Binary */
  TEST_ASSERT_EQUAL_HEX8(0x03, buf[5]);  /* Designator Type = NAA */
  TEST_ASSERT_EQUAL_HEX8(0x60, buf[8]);  /* NAA-6 prefix */
}

void test_block_inquiry_vpd_unsupported(void) {
  uint8_t cdb[6];
  memset(cdb, 0, 6);
  cdb[0] = SNOWSCSI_OP_INQUIRY;
  cdb[1] = 0x01; /* EVPD=1 */
  cdb[2] = 0xFF; /* Unsupported page code */
  cdb[4] = 96;

  uint32_t xfer;
  snowscsi_result_t r = snowscsi_do_cmd(dev, cdb, 6, &xfer);
  TEST_ASSERT_EQUAL(SNOWSCSI_CHECK_CONDITION, r);

  snowscsi_sense_t s;
  snowscsi_device_get_sense(dev, &s);
  TEST_ASSERT_EQUAL(SNOWSCSI_SENSE_ILLEGAL_REQUEST, s.key);
  TEST_ASSERT_EQUAL_HEX8(SNOWSCSI_ASC_INVALID_FIELD, s.asc);
}

void test_block_mode_sense_6_caching_page(void) {
  uint8_t cdb[6];
  memset(cdb, 0, 6);
  cdb[0] = SNOWSCSI_OP_MODE_SENSE_6;
  cdb[2] = 0x08; /* Page = 0x08 Caching */
  cdb[4] = 32;

  uint32_t xfer;
  snowscsi_result_t r = snowscsi_do_cmd(dev, cdb, 6, &xfer);
  TEST_ASSERT_EQUAL(SNOWSCSI_DATA_IN, r);

  uint8_t buf[32];
  int n = snowscsi_read_data(dev, buf, 32);
  TEST_ASSERT(n >= 24); /* 4 header + 20 page */

  /* Mode parameter header */
  uint8_t mode_len = buf[0];
  TEST_ASSERT(mode_len >= 23); /* 3 bytes header + 20 page */

  /* Caching mode page */
  uint8_t page_offset = 4;
  TEST_ASSERT_EQUAL_HEX8(0x88, buf[page_offset]);     /* PS=1, SPF=0, page=08 */
  TEST_ASSERT_EQUAL_HEX8(18, buf[page_offset + 1]);   /* Page Length */
  TEST_ASSERT_EQUAL_HEX8(0x00, buf[page_offset + 2]);  /* WCE=0, RCD=0 */
  TEST_ASSERT_EQUAL_HEX8(0x20, buf[page_offset + 12]); /* DRA=1 */
}

void test_block_mode_sense_6_page_00(void) {
  uint8_t cdb[6];
  memset(cdb, 0, 6);
  cdb[0] = SNOWSCSI_OP_MODE_SENSE_6;
  cdb[2] = 0x00; /* Page = 0x00 */
  cdb[4] = 16;

  uint32_t xfer;
  snowscsi_result_t r = snowscsi_do_cmd(dev, cdb, 6, &xfer);
  TEST_ASSERT_EQUAL(SNOWSCSI_DATA_IN, r);

  uint8_t buf[16];
  int n = snowscsi_read_data(dev, buf, 16);
  TEST_ASSERT(n >= 8);

  /* Page 0x00: supported pages list */
  uint8_t page_offset = 4;
  TEST_ASSERT_EQUAL_HEX8(0x00, buf[page_offset]);     /* Page Code */
  TEST_ASSERT_EQUAL_HEX8(2, buf[page_offset + 1]);    /* Page Length */
  TEST_ASSERT_EQUAL_HEX8(0x00, buf[page_offset + 2]); /* Page 0x00 */
  TEST_ASSERT_EQUAL_HEX8(0x08, buf[page_offset + 3]); /* Page 0x08 */
}

void test_block_mode_sense_6_page_3f(void) {
  uint8_t cdb[6];
  memset(cdb, 0, 6);
  cdb[0] = SNOWSCSI_OP_MODE_SENSE_6;
  cdb[2] = 0x3F; /* Return all pages */
  cdb[4] = 32;

  uint32_t xfer;
  snowscsi_result_t r = snowscsi_do_cmd(dev, cdb, 6, &xfer);
  TEST_ASSERT_EQUAL(SNOWSCSI_DATA_IN, r);

  uint8_t buf[32];
  int n = snowscsi_read_data(dev, buf, 32);
  /* Should have header + page 0x08 (20B) + page 0x00 (4B) = 28B */
  TEST_ASSERT(n >= 28);
}

void test_block_mode_sense_6_unsupported_page(void) {
  uint8_t cdb[6];
  memset(cdb, 0, 6);
  cdb[0] = SNOWSCSI_OP_MODE_SENSE_6;
  cdb[2] = 0x01; /* Page = 0x01 (R/W Error Recovery, not supported) */
  cdb[4] = 32;

  uint32_t xfer;
  snowscsi_result_t r = snowscsi_do_cmd(dev, cdb, 6, &xfer);
  TEST_ASSERT_EQUAL(SNOWSCSI_CHECK_CONDITION, r);
}

void test_block_mode_sense_10(void) {
  uint8_t cdb[10];
  memset(cdb, 0, 10);
  cdb[0] = SNOWSCSI_OP_MODE_SENSE_10;
  cdb[2] = 0x08;
  cdb[8] = 32;

  uint32_t xfer;
  snowscsi_result_t r = snowscsi_do_cmd(dev, cdb, 10, &xfer);
  TEST_ASSERT_EQUAL(SNOWSCSI_DATA_IN, r);

  uint8_t buf[32];
  int n = snowscsi_read_data(dev, buf, 32);
  TEST_ASSERT(n >= 28);

  /* Mode parameter header is 8 bytes for MODE SENSE(10) */
  uint8_t mode_len_hi = buf[0];
  uint8_t mode_len_lo = buf[1];
  uint16_t mode_len = ((uint16_t)mode_len_hi << 8) | mode_len_lo;
  TEST_ASSERT(mode_len >= 26); /* 6 bytes header + 20 page */

  /* Caching page at offset 8 */
  TEST_ASSERT_EQUAL_HEX8(0x88, buf[8]);
  TEST_ASSERT_EQUAL_HEX8(18, buf[9]);
}

void test_block_mode_select_10(void) {
  uint8_t cdb[10];
  memset(cdb, 0, 10);
  cdb[0] = SNOWSCSI_OP_MODE_SELECT_10;
  cdb[1] = 0x10; /* PF=1 */

  uint32_t xfer;
  snowscsi_result_t r = snowscsi_do_cmd(dev, cdb, 10, &xfer);
  TEST_ASSERT_EQUAL(SNOWSCSI_STATUS, r);
}

void test_block_report_luns(void) {
  uint8_t cdb[12];
  memset(cdb, 0, 12);
  cdb[0] = SNOWSCSI_OP_REPORT_LUNS;
  cdb[9] = 16;

  uint32_t xfer;
  snowscsi_result_t r = snowscsi_do_cmd(dev, cdb, 12, &xfer);
  TEST_ASSERT_EQUAL(SNOWSCSI_DATA_IN, r);

  uint8_t buf[16];
  int n = snowscsi_read_data(dev, buf, 16);
  TEST_ASSERT_EQUAL(8, n);

  /* LUN list length = 8 (one LUN = 8 bytes) */
  TEST_ASSERT_EQUAL_HEX8(0x00, buf[0]);
  TEST_ASSERT_EQUAL_HEX8(0x00, buf[1]);
  TEST_ASSERT_EQUAL_HEX8(0x00, buf[2]);
  TEST_ASSERT_EQUAL_HEX8(0x08, buf[3]);
  /* Response is only 8 bytes, so buf[4..7] are the start of LUN 0 */
  TEST_ASSERT_EQUAL_HEX8(0x00, buf[4]);
}

void test_block_send_diagnostic(void) {
  uint8_t cdb[6];
  memset(cdb, 0, 6);
  cdb[0] = SNOWSCSI_OP_SEND_DIAGNOSTIC;
  cdb[1] = 0x10; /* PF=1, SelfTest=0 */

  uint32_t xfer;
  snowscsi_result_t r = snowscsi_do_cmd(dev, cdb, 6, &xfer);
  TEST_ASSERT_EQUAL(SNOWSCSI_STATUS, r);
}

void test_block_synchronize_cache(void) {
  uint8_t cdb[10];
  memset(cdb, 0, 10);
  cdb[0] = SNOWSCSI_OP_SYNCHRONIZE_CACHE_10;

  uint32_t xfer;
  snowscsi_result_t r = snowscsi_do_cmd(dev, cdb, 10, &xfer);
  TEST_ASSERT_EQUAL(SNOWSCSI_STATUS, r);
}

void test_block_prevent_allow_start_stop_eject(void) {
  uint32_t xfer;

  /* PREVENT ALLOW: set prevent=1 */
  uint8_t cdb[6];
  memset(cdb, 0, 6);
  cdb[0] = SNOWSCSI_OP_PREVENT_ALLOW;
  cdb[4] = 0x01; /* prevent = 1 */
  snowscsi_result_t r = snowscsi_do_cmd(dev, cdb, 6, &xfer);
  TEST_ASSERT_EQUAL(SNOWSCSI_STATUS, r);

  /* START STOP UNIT: LoEj=1, Load=0 (eject) → should fail */
  memset(cdb, 0, 6);
  cdb[0] = SNOWSCSI_OP_START_STOP_UNIT;
  cdb[4] = 0x02; /* LoEj=1, Load=0 (eject) */
  r = snowscsi_do_cmd(dev, cdb, 6, &xfer);
  TEST_ASSERT_EQUAL(SNOWSCSI_CHECK_CONDITION, r);

  snowscsi_sense_t s;
  snowscsi_device_get_sense(dev, &s);
  TEST_ASSERT_EQUAL(SNOWSCSI_SENSE_ILLEGAL_REQUEST, s.key);
  TEST_ASSERT_EQUAL_HEX8(SNOWSCSI_ASC_MEDIUM_REMOVAL_PREVENTED, s.asc);

  /* START STOP UNIT: LoEj=0, Load=0 (stop) → should succeed */
  memset(cdb, 0, 6);
  cdb[0] = SNOWSCSI_OP_START_STOP_UNIT;
  cdb[4] = 0x00; /* LoEj=0, Start=0 (stop) */
  r = snowscsi_do_cmd(dev, cdb, 6, &xfer);
  TEST_ASSERT_EQUAL(SNOWSCSI_STATUS, r);
}

void test_block_read_capacity_pmi_zero_lba_nonzero(void) {
  uint8_t cdb[10];
  memset(cdb, 0, 10);
  cdb[0] = SNOWSCSI_OP_READ_CAPACITY_10;
  cdb[2] = 0x00; /* LBA = some non-zero value */
  cdb[3] = 0x00;
  cdb[4] = 0x00;
  cdb[5] = 0x01; /* PMI=0, LBA=1 → CHECK CONDITION */

  uint32_t xfer;
  snowscsi_result_t r = snowscsi_do_cmd(dev, cdb, 10, &xfer);
  TEST_ASSERT_EQUAL(SNOWSCSI_CHECK_CONDITION, r);

  snowscsi_sense_t s;
  snowscsi_device_get_sense(dev, &s);
  TEST_ASSERT_EQUAL(SNOWSCSI_SENSE_ILLEGAL_REQUEST, s.key);
  TEST_ASSERT_EQUAL_HEX8(SNOWSCSI_ASC_INVALID_FIELD, s.asc);
}

void test_block_read_capacity_pmi_zero_lba_zero(void) {
  uint8_t cdb[10];
  memset(cdb, 0, 10);
  cdb[0] = SNOWSCSI_OP_READ_CAPACITY_10;
  /* LBA=0, PMI=0 → should succeed */

  uint32_t xfer;
  snowscsi_result_t r = snowscsi_do_cmd(dev, cdb, 10, &xfer);
  TEST_ASSERT_EQUAL(SNOWSCSI_DATA_IN, r);
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
  RUN_TEST(test_block_read_capacity_16);
  RUN_TEST(test_block_read_capacity_16_unknown_sa);
  RUN_TEST(test_block_read_6_zero_blocks);
  RUN_TEST(test_block_write_read_roundtrip_6);
  RUN_TEST(test_block_write_read_roundtrip_12);
  RUN_TEST(test_block_write_read_roundtrip_16);
  RUN_TEST(test_block_read_zero_6);
  RUN_TEST(test_block_lba_out_of_range_6);
  RUN_TEST(test_block_lba_out_of_range_12);
  RUN_TEST(test_block_lba_out_of_range_16);
  /* New command tests */
  RUN_TEST(test_block_inquiry_version_spc3);
  RUN_TEST(test_block_inquiry_evpd_page_code_nonzero);
  RUN_TEST(test_block_inquiry_vpd_00);
  RUN_TEST(test_block_inquiry_vpd_80);
  RUN_TEST(test_block_inquiry_vpd_83);
  RUN_TEST(test_block_inquiry_vpd_unsupported);
  RUN_TEST(test_block_mode_sense_6_caching_page);
  RUN_TEST(test_block_mode_sense_6_page_00);
  RUN_TEST(test_block_mode_sense_6_page_3f);
  RUN_TEST(test_block_mode_sense_6_unsupported_page);
  RUN_TEST(test_block_mode_sense_10);
  RUN_TEST(test_block_mode_select_10);
  RUN_TEST(test_block_report_luns);
  RUN_TEST(test_block_send_diagnostic);
  RUN_TEST(test_block_synchronize_cache);
  RUN_TEST(test_block_prevent_allow_start_stop_eject);
  RUN_TEST(test_block_read_capacity_pmi_zero_lba_nonzero);
  RUN_TEST(test_block_read_capacity_pmi_zero_lba_zero);
  return UNITY_END();
}
