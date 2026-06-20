#include "device_internal.h"

#define SNOWLOG_TAG "block"
#include "snowhex.h"
#include "snowlog.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── INQUIRY standard data (95 bytes with version descriptors) ─── */

#define INQUIRY_STD_LEN 95

static void build_inquiry_std(uint8_t *buf) {
  memset(buf, 0, INQUIRY_STD_LEN);
  buf[0] = 0x00;            /* PDT = 0x00 (disk) */
  buf[1] = 0x00;            /* RMB = 0 (non-removable) */
  buf[2] = 0x05;            /* Version = SPC-3 */
  buf[3] = 0x02;            /* Response Data Format = 2 */
  buf[4] = INQUIRY_STD_LEN - 5; /* Additional Length = 91 */
  buf[7] = 0x02;            /* CmdQue = 1 */
  memcpy(buf + 8, "SnowSCSI", 8);
  memcpy(buf + 16, "Virtual Disk    ", 16);
  memcpy(buf + 32, "0100", 4);
  /* Version descriptors (SPC-4 §7.6.2, Table 160) */
  buf[58] = 0x00; buf[59] = 0xA0; /* SAM-5 */
  buf[60] = 0x09; buf[61] = 0x60; /* iSCSI */
  buf[62] = 0x04; buf[63] = 0x60; /* SPC-4 */
  buf[64] = 0x04; buf[65] = 0xC0; /* SBC-3 */
}

/* ── INQUIRY VPD 0x00: Supported VPD Pages ─────────────────────── */

#define VPD_PAGE_LIST_LEN 7

static void build_vpd_00(uint8_t *buf) {
  memset(buf, 0, VPD_PAGE_LIST_LEN);
  buf[0] = 0x00;            /* Peripheral Qualifier + PDT = 0 */
  buf[1] = 0x00;            /* Page Code = 0x00 */
  buf[2] = 0x00;            /* Reserved */
  buf[3] = VPD_PAGE_LIST_LEN - 4; /* Page Length = 3 */
  buf[4] = 0x00;            /* Supported page list: 0x00 */
  buf[5] = 0x80;            /* 0x80 */
  buf[6] = 0x83;            /* 0x83 */
}

/* ── INQUIRY VPD 0x80: Unit Serial Number ──────────────────────── */

#define VPD_SERIAL_LEN (4 + 16)

static void build_vpd_80(uint8_t *buf, uint64_t size) {
  memset(buf, 0, VPD_SERIAL_LEN);
  buf[0] = 0x00;            /* Peripheral Qualifier + PDT = 0 */
  buf[1] = 0x80;            /* Page Code = 0x80 */
  buf[2] = 0x00;            /* Reserved */
  buf[3] = VPD_SERIAL_LEN - 4; /* Page Length = 16 */
  /* Serial number derived from backend size (purely for demonstration) */
  snprintf((char *)buf + 4, 16, "SNOW%016llX",
           (unsigned long long)size);
}

/* ── INQUIRY VPD 0x83: Device Identification ───────────────────── */

#define VPD_ID_LEN (4 + 4 + 16)

static void build_vpd_83(uint8_t *buf, uint64_t size) {
  memset(buf, 0, VPD_ID_LEN);
  buf[0] = 0x00;            /* Peripheral Qualifier + PDT = 0 */
  buf[1] = 0x83;            /* Page Code = 0x83 */
  buf[2] = 0x00;            /* Reserved */
  buf[3] = VPD_ID_LEN - 4;  /* Page Length = 20 */
  /* Designation descriptor #1: NAA Locally Assigned (Type 3h) */
  buf[4] = 0x04;            /* Code Set = Binary */
  buf[5] = 0x03;            /* Designator Type = NAA */
  buf[6] = 0x00;            /* Reserved */
  buf[7] = VPD_ID_LEN - 8;  /* Designator Length = 12 */
  /* NAA-6 Locally Assigned (format NAA IEEE Registered) */
  buf[8] = 0x60;            /* NAA=6, first nibble, plus 4 MSB of NAA value */
  /* Remaining 11 bytes encode the device identifier based on size */
  uint64_t id = size;
  for (int i = 0; i < 8; i++)
    buf[12 + i] = (uint8_t)(id >> (56 - 8 * i));
}

/* ── REQUEST SENSE response (18 bytes) ─────────────────────────── */

#define SENSE_LEN 18

static void build_sense(uint8_t *buf, const snowscsi_sense_t *s) {
  memset(buf, 0, SENSE_LEN);
  buf[0] = 0x70; /* Response Code: current errors, fixed format */
  buf[2] = (uint8_t)(s->key & 0x0F);
  buf[7] = SENSE_LEN - 8; /* Additional Sense Length */
  buf[12] = s->asc;
  buf[13] = s->ascq;
}

/* ── READ CAPACITY(10) response (8 bytes) ──────────────────────── */

static void build_read_capacity(uint8_t *buf, uint32_t max_lba,
                                uint32_t block_size) {
  buf[0] = (max_lba >> 24) & 0xFF;
  buf[1] = (max_lba >> 16) & 0xFF;
  buf[2] = (max_lba >> 8) & 0xFF;
  buf[3] = (max_lba) & 0xFF;
  buf[4] = (block_size >> 24) & 0xFF;
  buf[5] = (block_size >> 16) & 0xFF;
  buf[6] = (block_size >> 8) & 0xFF;
  buf[7] = (block_size) & 0xFF;
}

/* ── Shared read/write helpers ───────────────────────────────────── */

static snowscsi_result_t do_read(snowscsi_device_t *dev, uint32_t max_lba,
                                 uint64_t lba, uint32_t count,
                                 uint32_t *transfer_len, const char *tag) {
  if (count == 0) {
    *transfer_len = 0;
    return SNOWSCSI_STATUS;
  }
  if (lba > max_lba || lba + count > (uint64_t)max_lba + 1) {
    SNOW_LOGW("%s: LBA out of range lba=%lu max_lba=%u count=%u", tag,
              (unsigned long)lba, max_lba, count);
    snowscsi_sense_set(&dev->sense, SNOWSCSI_SENSE_ILLEGAL_REQUEST,
                       SNOWSCSI_ASC_LBA_OUT_OF_RANGE, 0x00);
    goto check_condition;
  }
  uint64_t bytes64 = (uint64_t)count * dev->sector_size;
  if (bytes64 > UINT32_MAX) {
    snowscsi_sense_set(&dev->sense, SNOWSCSI_SENSE_ILLEGAL_REQUEST,
                       SNOWSCSI_ASC_INVALID_FIELD, 0x00);
    goto check_condition;
  }
  uint32_t bytes = (uint32_t)bytes64;
  dev->data_buf = malloc(bytes);
  if (!dev->data_buf)
    goto alloc_fail;
  uint64_t offset = lba * dev->sector_size;
  if (dev->backend->ops->read(dev->backend->ctx, offset, dev->data_buf,
                              bytes) != 0) {
    SNOW_LOGE("%s: backend read failed offset=%lu bytes=%u", tag,
              (unsigned long)offset, bytes);
    free(dev->data_buf);
    dev->data_buf = NULL;
    snowscsi_sense_set(&dev->sense, SNOWSCSI_SENSE_MEDIUM_ERROR, 0x11, 0x00);
    goto check_condition;
  }
  SNOW_LOGD("%s: lba=%lu blocks=%u bytes=%u", tag, (unsigned long)lba, count,
            bytes);
  dev->data_total = bytes;
  dev->data_offset = 0;
  *transfer_len = bytes;
  return SNOWSCSI_DATA_IN;

alloc_fail:
  SNOW_LOGE("malloc failed for %s", tag);
  snowscsi_sense_set(&dev->sense, SNOWSCSI_SENSE_MEDIUM_ERROR, 0x00, 0x00);
check_condition:
  *transfer_len = 0;
  return SNOWSCSI_CHECK_CONDITION;
}

static snowscsi_result_t do_write(snowscsi_device_t *dev, uint32_t max_lba,
                                  uint64_t lba, uint32_t count,
                                  uint32_t *transfer_len, const char *tag) {
  if (count == 0) {
    *transfer_len = 0;
    return SNOWSCSI_STATUS;
  }
  if (lba > max_lba || lba + count > (uint64_t)max_lba + 1) {
    SNOW_LOGW("%s: LBA out of range lba=%lu max_lba=%u count=%u", tag,
              (unsigned long)lba, max_lba, count);
    snowscsi_sense_set(&dev->sense, SNOWSCSI_SENSE_ILLEGAL_REQUEST,
                       SNOWSCSI_ASC_LBA_OUT_OF_RANGE, 0x00);
    goto check_condition;
  }
  uint64_t bytes64 = (uint64_t)count * dev->sector_size;
  if (bytes64 > UINT32_MAX) {
    snowscsi_sense_set(&dev->sense, SNOWSCSI_SENSE_ILLEGAL_REQUEST,
                       SNOWSCSI_ASC_INVALID_FIELD, 0x00);
    goto check_condition;
  }
  uint32_t bytes = (uint32_t)bytes64;
  dev->data_buf = malloc(bytes);
  if (!dev->data_buf)
    goto alloc_fail;
  SNOW_LOGD("%s: lba=%lu blocks=%u bytes=%u", tag, (unsigned long)lba, count,
            bytes);
  dev->data_total = bytes;
  dev->data_offset = 0;
  dev->write_backend_offset = lba * dev->sector_size;
  *transfer_len = bytes;
  return SNOWSCSI_DATA_OUT;

alloc_fail:
  SNOW_LOGE("malloc failed for %s", tag);
  snowscsi_sense_set(&dev->sense, SNOWSCSI_SENSE_MEDIUM_ERROR, 0x00, 0x00);
check_condition:
  *transfer_len = 0;
  return SNOWSCSI_CHECK_CONDITION;
}

/* ── SBC command handler ───────────────────────────────────────── */

static snowscsi_result_t block_handle_cmd(snowscsi_device_t *dev,
                                          const uint8_t *cdb, uint8_t cdb_len,
                                          uint32_t *transfer_len) {
  (void)cdb_len;
  uint8_t opcode = snowscsi_cdb_get_opcode(cdb);
  uint64_t backend_size = dev->backend->ops->get_size(dev->backend->ctx);
  uint32_t max_lba = (dev->sector_size > 0)
                         ? (uint32_t)(backend_size / dev->sector_size) - 1
                         : 0;

  SNOW_LOGD("cmd=%s opcode=0x%02x", snowscsi_cdb_opcode_name(opcode), opcode);

  switch (opcode) {

  /* ── INQUIRY ──────────────────────────────────────────────────── */

  case SNOWSCSI_OP_INQUIRY: {
    uint8_t evpd = cdb[1] & 0x01;
    uint8_t page_code = cdb[2];

    if (evpd) {
      uint32_t alloc_len = ((uint16_t)cdb[3] << 8) | cdb[4];
      switch (page_code) {
      case 0x00: {
        /* Always allocate full internal size, truncate data_total */
        uint32_t resp_len = alloc_len < VPD_PAGE_LIST_LEN
                                ? alloc_len
                                : VPD_PAGE_LIST_LEN;
        dev->data_buf = malloc(VPD_PAGE_LIST_LEN);
        if (!dev->data_buf) goto alloc_fail;
        build_vpd_00(dev->data_buf);
        dev->data_total = resp_len;
        dev->data_offset = 0;
        *transfer_len = resp_len;
        SNOW_LOGV("INQUIRY VPD 0x00: alloc_len=%u resp_len=%u", alloc_len,
                  resp_len);
        return SNOWSCSI_DATA_IN;
      }
      case 0x80: {
        uint32_t resp_len =
            alloc_len < VPD_SERIAL_LEN ? alloc_len : VPD_SERIAL_LEN;
        dev->data_buf = malloc(VPD_SERIAL_LEN);
        if (!dev->data_buf) goto alloc_fail;
        build_vpd_80(dev->data_buf, backend_size);
        dev->data_total = resp_len;
        dev->data_offset = 0;
        *transfer_len = resp_len;
        return SNOWSCSI_DATA_IN;
      }
      case 0x83: {
        uint32_t resp_len =
            alloc_len < VPD_ID_LEN ? alloc_len : VPD_ID_LEN;
        dev->data_buf = malloc(VPD_ID_LEN);
        if (!dev->data_buf) goto alloc_fail;
        build_vpd_83(dev->data_buf, backend_size);
        dev->data_total = resp_len;
        dev->data_offset = 0;
        *transfer_len = resp_len;
        return SNOWSCSI_DATA_IN;
      }
      default:
        SNOW_LOGW("INQUIRY: unsupported VPD page 0x%02x", page_code);
        snowscsi_sense_set(&dev->sense, SNOWSCSI_SENSE_ILLEGAL_REQUEST,
                           SNOWSCSI_ASC_INVALID_FIELD, 0x00);
        goto check_condition;
      }
    }

    if (page_code != 0) {
      SNOW_LOGW("INQUIRY: EVPD=0 but page_code=0x%02x", page_code);
      snowscsi_sense_set(&dev->sense, SNOWSCSI_SENSE_ILLEGAL_REQUEST,
                         SNOWSCSI_ASC_INVALID_FIELD, 0x00);
      goto check_condition;
    }

    uint16_t alloc = ((uint16_t)cdb[3] << 8) | cdb[4];
    uint32_t resp_len = alloc < INQUIRY_STD_LEN ? alloc : INQUIRY_STD_LEN;
    SNOW_LOGV("INQUIRY: alloc_len=%u resp_len=%u", alloc, resp_len);
    dev->data_buf = malloc(INQUIRY_STD_LEN);
    if (!dev->data_buf) goto alloc_fail;
    build_inquiry_std(dev->data_buf);
    dev->data_total = resp_len;
    dev->data_offset = 0;
    *transfer_len = resp_len;
    return SNOWSCSI_DATA_IN;
  }

  /* ── TEST UNIT READY ──────────────────────────────────────────── */

  case SNOWSCSI_OP_TEST_UNIT_READY:
    *transfer_len = 0;
    return SNOWSCSI_STATUS;

  /* ── REQUEST SENSE ────────────────────────────────────────────── */

  case SNOWSCSI_OP_REQUEST_SENSE: {
    dev->data_buf = malloc(SENSE_LEN);
    if (!dev->data_buf)
      goto alloc_fail;
    build_sense(dev->data_buf, &dev->sense);
    dev->data_total = SENSE_LEN;
    dev->data_offset = 0;
    *transfer_len = SENSE_LEN;
    SNOW_LOGV("REQUEST_SENSE: key=0x%02x asc=0x%02x ascq=0x%02x",
              dev->sense.key, dev->sense.asc, dev->sense.ascq);
    snowscsi_sense_clear(&dev->sense);
    return SNOWSCSI_DATA_IN;
  }

  /* ── READ CAPACITY(10) ────────────────────────────────────────── */

  case SNOWSCSI_OP_READ_CAPACITY_10: {
    uint8_t pmi = cdb[1] & 0x01;
    uint32_t req_lba = ((uint32_t)cdb[2] << 24) | ((uint32_t)cdb[3] << 16) |
                       ((uint32_t)cdb[4] << 8) | cdb[5];
    if (pmi == 0 && req_lba != 0) {
      SNOW_LOGW("READ_CAPACITY_10: PMI=0 but LBA=%u", req_lba);
      snowscsi_sense_set(&dev->sense, SNOWSCSI_SENSE_ILLEGAL_REQUEST,
                         SNOWSCSI_ASC_INVALID_FIELD, 0x00);
      goto check_condition;
    }
    SNOW_LOGV("READ_CAPACITY_10: max_lba=%u block_size=%u pmi=%u", max_lba,
              dev->sector_size, pmi);
    dev->data_buf = malloc(8);
    if (!dev->data_buf)
      goto alloc_fail;
    build_read_capacity(dev->data_buf, max_lba, dev->sector_size);
    dev->data_total = 8;
    dev->data_offset = 0;
    *transfer_len = 8;
    return SNOWSCSI_DATA_IN;
  }

  /* ── READ(6) / WRITE(6) ──────────────────────────────────────── */

  case SNOWSCSI_OP_READ_6: {
    uint32_t lba = snowscsi_cdb_get_lba6(cdb);
    uint8_t raw = snowscsi_cdb_get_transfer_len6(cdb);
    uint32_t count = (raw == 0) ? 256 : raw;
    return do_read(dev, max_lba, lba, count, transfer_len, "READ_6");
  }

  case SNOWSCSI_OP_WRITE_6: {
    uint32_t lba = snowscsi_cdb_get_lba6(cdb);
    uint8_t raw = snowscsi_cdb_get_transfer_len6(cdb);
    uint32_t count = (raw == 0) ? 256 : raw;
    return do_write(dev, max_lba, lba, count, transfer_len, "WRITE_6");
  }

  /* ── READ(10) / WRITE(10) ─────────────────────────────────────── */

  case SNOWSCSI_OP_READ_10: {
    uint32_t lba = snowscsi_cdb_get_lba10(cdb);
    uint16_t count = snowscsi_cdb_get_transfer_len10(cdb);
    return do_read(dev, max_lba, lba, count, transfer_len, "READ_10");
  }

  case SNOWSCSI_OP_WRITE_10: {
    uint32_t lba = snowscsi_cdb_get_lba10(cdb);
    uint16_t count = snowscsi_cdb_get_transfer_len10(cdb);
    return do_write(dev, max_lba, lba, count, transfer_len, "WRITE_10");
  }

  /* ── READ(12) / WRITE(12) ─────────────────────────────────────── */

  case SNOWSCSI_OP_READ_12: {
    uint32_t lba = snowscsi_cdb_get_lba12(cdb);
    uint32_t count = snowscsi_cdb_get_transfer_len12(cdb);
    return do_read(dev, max_lba, lba, count, transfer_len, "READ_12");
  }

  case SNOWSCSI_OP_WRITE_12: {
    uint32_t lba = snowscsi_cdb_get_lba12(cdb);
    uint32_t count = snowscsi_cdb_get_transfer_len12(cdb);
    return do_write(dev, max_lba, lba, count, transfer_len, "WRITE_12");
  }

  /* ── READ(16) / WRITE(16) ─────────────────────────────────────── */

  case SNOWSCSI_OP_READ_16: {
    uint64_t lba = snowscsi_cdb_get_lba16(cdb);
    uint32_t count = snowscsi_cdb_get_transfer_len16(cdb);
    return do_read(dev, max_lba, lba, count, transfer_len, "READ_16");
  }

  case SNOWSCSI_OP_WRITE_16: {
    uint64_t lba = snowscsi_cdb_get_lba16(cdb);
    uint32_t count = snowscsi_cdb_get_transfer_len16(cdb);
    return do_write(dev, max_lba, lba, count, transfer_len, "WRITE_16");
  }

  /* ── SERVICE ACTION IN (READ CAPACITY 16) ─────────────────────── */

  case SNOWSCSI_OP_SERVICE_ACTION_IN: {
    if (cdb_len < 16 || cdb[1] != 0x10) {
      snowscsi_sense_set(&dev->sense, SNOWSCSI_SENSE_ILLEGAL_REQUEST,
                         SNOWSCSI_ASC_INVALID_FIELD, 0x00);
      goto check_condition;
    }
    uint32_t alloc_len = ((uint32_t)cdb[10] << 24) | ((uint32_t)cdb[11] << 16) |
                         ((uint32_t)cdb[12] << 8) | cdb[13];
    uint32_t resp_len = 32;
    if (alloc_len < resp_len)
      resp_len = alloc_len;
    SNOW_LOGV("SERVICE_ACTION_IN(READ_CAPACITY_16): alloc_len=%u resp_len=%u",
              alloc_len, resp_len);
    dev->data_buf = malloc(resp_len);
    if (!dev->data_buf)
      goto alloc_fail;
    memset(dev->data_buf, 0, resp_len);
    uint64_t max_lba_64 = (backend_size / dev->sector_size) - 1;
    dev->data_buf[0] = (uint8_t)(max_lba_64 >> 56);
    dev->data_buf[1] = (uint8_t)(max_lba_64 >> 48);
    dev->data_buf[2] = (uint8_t)(max_lba_64 >> 40);
    dev->data_buf[3] = (uint8_t)(max_lba_64 >> 32);
    dev->data_buf[4] = (uint8_t)(max_lba_64 >> 24);
    dev->data_buf[5] = (uint8_t)(max_lba_64 >> 16);
    dev->data_buf[6] = (uint8_t)(max_lba_64 >> 8);
    dev->data_buf[7] = (uint8_t)(max_lba_64);
    dev->data_buf[8] = (uint8_t)(dev->sector_size >> 24);
    dev->data_buf[9] = (uint8_t)(dev->sector_size >> 16);
    dev->data_buf[10] = (uint8_t)(dev->sector_size >> 8);
    dev->data_buf[11] = (uint8_t)(dev->sector_size);
    dev->data_total = resp_len;
    dev->data_offset = 0;
    *transfer_len = resp_len;
    return SNOWSCSI_DATA_IN;
  }

  /* ── SYNCHRONIZE CACHE(10) ────────────────────────────────────── */

  case SNOWSCSI_OP_SYNCHRONIZE_CACHE_10: {
    if (dev->backend && dev->backend->ops->sync)
      dev->backend->ops->sync(dev->backend->ctx);
    SNOW_LOGV("SYNCHRONIZE_CACHE(10): no-op for RAM backend");
    *transfer_len = 0;
    return SNOWSCSI_STATUS;
  }

  /* ── MODE SENSE(6) ────────────────────────────────────────────── */

  case SNOWSCSI_OP_MODE_SENSE_6: {
    uint8_t pc = (cdb[2] & 0xC0) >> 6;
    uint8_t page = cdb[2] & 0x3F;
    uint8_t alloc = cdb[4];
    (void)pc; /* Current values (PC=0) always */

    /* Build mode parameter header (4 bytes) + page data */
    uint8_t header[4] = {0, 0, 0, 0}; /* mode data len, MT, DSP, BDL */
    uint8_t page_buf[32];
    uint16_t page_offset = 0;

    if (page == 0x3F || page == 0x08) {
      /* Caching mode page (20 bytes) */
      uint8_t caching[20] = {0};
      caching[0] = 0x88; /* PS=1, SPF=0, Page Code=0x08 */
      caching[1] = 18;   /* Page Length */
      caching[2] = 0x00; /* WCE=0, RCD=0 */
      caching[3] = 0x00;
      caching[12] = 0x20; /* DRA=1 */
      memcpy(page_buf + page_offset, caching, 20);
      page_offset += 20;
    }

    if (page == 0x3F || page == 0x00) {
      /* Supported page list: page codes we support */
      uint8_t pages[4] = {0};
      pages[0] = 0x00; /* Page code = 0x00 */
      pages[1] = 2;    /* Page length */
      pages[2] = 0x00; /* Supported page codes */
      pages[3] = 0x08;
      memcpy(page_buf + page_offset, pages, 4);
      page_offset += 4;
    }

    if (page != 0x3F && page != 0x00 && page != 0x08) {
      SNOW_LOGW("MODE_SENSE(6): unsupported page 0x%02x", page);
      snowscsi_sense_set(&dev->sense, SNOWSCSI_SENSE_ILLEGAL_REQUEST,
                         SNOWSCSI_ASC_INVALID_FIELD, 0x00);
      goto check_condition;
    }

    header[0] = (uint8_t)(page_offset + 3); /* mode data length */
    uint8_t total_len = 4 + page_offset;
    /* Always allocate at least total_len to avoid overflow on small alloc */
    uint32_t resp_len = alloc < total_len ? alloc : total_len;
    uint32_t alloc_size = total_len;
    dev->data_buf = malloc(alloc_size);
    if (!dev->data_buf) goto alloc_fail;
    memset(dev->data_buf, 0, alloc_size);
    memcpy(dev->data_buf, header, 4);
    memcpy(dev->data_buf + 4, page_buf, page_offset);
    dev->data_total = resp_len;
    dev->data_offset = 0;
    *transfer_len = resp_len;
    return SNOWSCSI_DATA_IN;
  }

  /* ── MODE SENSE(10) ───────────────────────────────────────────── */

  case SNOWSCSI_OP_MODE_SENSE_10: {
    uint8_t pc = (cdb[2] & 0xC0) >> 6;
    uint8_t page = cdb[2] & 0x3F;
    uint16_t alloc = ((uint16_t)cdb[7] << 8) | cdb[8];
    (void)pc;

    uint8_t header[8] = {0, 0, 0, 0, 0, 0, 0, 0}; /* LLB, MT, DSP, BDL */
    uint8_t page_buf[32];
    uint16_t page_offset = 0;

    if (page == 0x3F || page == 0x08) {
      uint8_t caching[20] = {0};
      caching[0] = 0x88;
      caching[1] = 18;
      caching[2] = 0x00;
      caching[3] = 0x00;
      caching[12] = 0x20;
      memcpy(page_buf + page_offset, caching, 20);
      page_offset += 20;
    }

    if (page == 0x3F || page == 0x00) {
      uint8_t pages[4] = {0};
      pages[0] = 0x00;
      pages[1] = 2;
      pages[2] = 0x00;
      pages[3] = 0x08;
      memcpy(page_buf + page_offset, pages, 4);
      page_offset += 4;
    }

    if (page != 0x3F && page != 0x00 && page != 0x08) {
      SNOW_LOGW("MODE_SENSE(10): unsupported page 0x%02x", page);
      snowscsi_sense_set(&dev->sense, SNOWSCSI_SENSE_ILLEGAL_REQUEST,
                         SNOWSCSI_ASC_INVALID_FIELD, 0x00);
      goto check_condition;
    }

    header[0] = (uint8_t)((page_offset + 6) >> 8); /* mode data length (big-endian) */
    header[1] = (uint8_t)(page_offset + 6);
    uint8_t total_len = 8 + page_offset;
    uint32_t resp_len = alloc < total_len ? alloc : total_len;
    uint32_t alloc_size = total_len;
    dev->data_buf = malloc(alloc_size);
    if (!dev->data_buf) goto alloc_fail;
    memset(dev->data_buf, 0, alloc_size);
    memcpy(dev->data_buf, header, 8);
    memcpy(dev->data_buf + 8, page_buf, page_offset);
    dev->data_total = resp_len;
    dev->data_offset = 0;
    *transfer_len = resp_len;
    return SNOWSCSI_DATA_IN;
  }

  /* ── MODE SELECT(6) / (10) ────────────────────────────────────── */

  case SNOWSCSI_OP_MODE_SELECT_6:
  case SNOWSCSI_OP_MODE_SELECT_10: {
    uint8_t pf = (cdb[1] & 0x10) >> 4;
    (void)pf;
    /* Accept any valid MODE SELECT — just return GOOD */
    SNOW_LOGV("MODE_SELECT: accepted (PF=%u)", pf);
    *transfer_len = 0;
    return SNOWSCSI_STATUS;
  }

  /* ── SEND DIAGNOSTIC ──────────────────────────────────────────── */

  case SNOWSCSI_OP_SEND_DIAGNOSTIC: {
    uint8_t pf = (cdb[1] & 0x10) >> 4;
    uint8_t self_test = cdb[1] & 0x04;
    if (!pf && !self_test) {
      /* Unit attention: return GOOD */
      *transfer_len = 0;
      return SNOWSCSI_STATUS;
    }
    if (pf && !self_test) {
      /* No diagnostic page data to process */
      *transfer_len = 0;
      return SNOWSCSI_STATUS;
    }
    /* Self-test or other: not supported */
    SNOW_LOGW("SEND_DIAGNOSTIC: unsupported PF=%u SelfTest=%u", pf, self_test);
    snowscsi_sense_set(&dev->sense, SNOWSCSI_SENSE_ILLEGAL_REQUEST,
                       SNOWSCSI_ASC_INVALID_FIELD, 0x00);
    goto check_condition;
  }

  /* ── RECEIVE DIAGNOSTIC RESULTS ───────────────────────────────── */

  case SNOWSCSI_OP_RECEIVE_DIAGNOSTIC: {
    uint16_t alloc = ((uint16_t)cdb[3] << 8) | cdb[4];
    uint32_t resp_len = alloc < 4 ? alloc : 4;
    dev->data_buf = malloc(4);
    if (!dev->data_buf) goto alloc_fail;
    memset(dev->data_buf, 0, 4);
    dev->data_buf[0] = 0x00; /* Page code */
    dev->data_buf[1] = 0x00; /* Reserved */
    dev->data_buf[2] = 0x00; /* Page length MSB */
    dev->data_buf[3] = 0x00; /* Page length LSB = 0 (no supported pages) */
    dev->data_total = resp_len;
    dev->data_offset = 0;
    *transfer_len = resp_len;
    return SNOWSCSI_DATA_IN;
  }

  /* ── REPORT LUNS ──────────────────────────────────────────────── */

  case SNOWSCSI_OP_REPORT_LUNS: {
    uint32_t alloc = ((uint32_t)cdb[6] << 24) | ((uint32_t)cdb[7] << 16) |
                     ((uint32_t)cdb[8] << 8) | cdb[9];
    uint32_t resp_len = alloc < 8 ? alloc : 8;
    dev->data_buf = malloc(8);
    if (!dev->data_buf) goto alloc_fail;
    memset(dev->data_buf, 0, 8);
    dev->data_buf[0] = 0x00; /* LUN list length MSB */
    dev->data_buf[1] = 0x00; /* LUN list length */
    dev->data_buf[2] = 0x00;
    dev->data_buf[3] = 0x08; /* 8 bytes (LUN 0 only) */
    /* LUN 0 (16-byte LUN format, but we report 8-byte so just all zeros) */
    dev->data_total = resp_len;
    dev->data_offset = 0;
    *transfer_len = resp_len;
    SNOW_LOGV("REPORT_LUNS: alloc=%u resp_len=%u", alloc, resp_len);
    return SNOWSCSI_DATA_IN;
  }

  /* ── PREVENT ALLOW MEDIUM REMOVAL ─────────────────────────────── */

  case SNOWSCSI_OP_PREVENT_ALLOW: {
    uint8_t prevent = cdb[4] & 0x03;
    dev->prevent_removal = (prevent != 0);
    SNOW_LOGV("PREVENT_ALLOW: prevent=%u lock=%s", prevent,
              dev->prevent_removal ? "yes" : "no");
    *transfer_len = 0;
    return SNOWSCSI_STATUS;
  }

  /* ── START STOP UNIT ──────────────────────────────────────────── */

  case SNOWSCSI_OP_START_STOP_UNIT: {
    uint8_t immed = (cdb[1] >> 1) & 0x01;
    uint8_t loej = (cdb[4] >> 1) & 0x01;
    uint8_t load = cdb[4] & 0x01;
    (void)immed;
    (void)load;

    if (loej && load == 0) {
      /* Eject requested */
      if (dev->prevent_removal) {
        SNOW_LOGW("START_STOP_UNIT: eject prevented");
        snowscsi_sense_set(&dev->sense, SNOWSCSI_SENSE_ILLEGAL_REQUEST,
                           SNOWSCSI_ASC_MEDIUM_REMOVAL_PREVENTED, 0x00);
        goto check_condition;
      }
    }

    *transfer_len = 0;
    return SNOWSCSI_STATUS;
  }

  default:
    SNOW_LOGI("unknown opcode 0x%02x", opcode);
    {
      char _hex[16 * 3 + 1];
      snowhex_format(cdb, cdb_len, _hex, sizeof(_hex));
      SNOW_LOGV("cdb=%s", _hex);
    }
    snowscsi_sense_set(&dev->sense, SNOWSCSI_SENSE_ILLEGAL_REQUEST,
                       SNOWSCSI_ASC_INVALID_COMMAND, 0x00);
    goto check_condition;
  }

alloc_fail:
  SNOW_LOGE("malloc failed for opcode=0x%02x", opcode);
  snowscsi_sense_set(&dev->sense, SNOWSCSI_SENSE_MEDIUM_ERROR, 0x00, 0x00);
check_condition:
  SNOW_LOGV("CHECK_CONDITION: key=0x%02x asc=0x%02x ascq=0x%02x",
            dev->sense.key, dev->sense.asc, dev->sense.ascq);
  *transfer_len = 0;
  return SNOWSCSI_CHECK_CONDITION;
}

/* ── Public API ────────────────────────────────────────────────── */

snowscsi_device_t *snowscsi_block_create(snowscsi_backend_t *backend,
                                         uint32_t sector_size) {
  if (!backend || sector_size == 0)
    return NULL;

  snowscsi_device_t *dev = calloc(1, sizeof(*dev));
  if (!dev)
    return NULL;

  dev->type = SNOWSCSI_TYPE_BLOCK;
  dev->backend = backend;
  dev->sector_size = sector_size;
  dev->handle_cmd = block_handle_cmd;
  snowscsi_sense_clear(&dev->sense);
  return dev;
}

snowscsi_device_t *snowscsi_block_open_ram(uint64_t size) {
  snowscsi_backend_t *b = snowscsi_backend_ram_create(size);
  if (!b)
    return NULL;

  snowscsi_device_t *dev = snowscsi_block_create(b, 512);
  if (!dev) {
    snowscsi_backend_destroy(b);
    return NULL;
  }
  return dev;
}
