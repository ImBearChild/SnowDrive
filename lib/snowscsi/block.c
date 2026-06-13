#include "device_internal.h"

#define SNOWLOG_TAG "block"
#include "snowlog.h"

#include <stdlib.h>
#include <string.h>

/* ── INQUIRY response layout (36 bytes) ────────────────────────── */

#define INQUIRY_LEN 36

static void build_inquiry(uint8_t *buf) {
  memset(buf, 0, INQUIRY_LEN);
  buf[0] = 0x00;            /* PDT = 0x00 (disk) */
  buf[1] = 0x00;            /* RMB = 0 (non-removable) */
  buf[2] = 0x02;            /* SCSI-2 (skip REPORT LUNS) */
  buf[3] = 0x02;            /* Response Data Format = 2 */
  buf[4] = INQUIRY_LEN - 5; /* Additional Length */
  memcpy(buf + 8, "SnowSCSI", 8);
  memcpy(buf + 16, "Virtual Disk    ", 16);
  memcpy(buf + 32, "0100", 4);
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

  case SNOWSCSI_OP_INQUIRY: {
    uint16_t alloc = ((uint16_t)cdb[3] << 8) | cdb[4];
    if (alloc > INQUIRY_LEN)
      alloc = INQUIRY_LEN;
    SNOW_LOGV("INQUIRY: alloc_len=%u", alloc);
    dev->data_buf = malloc(INQUIRY_LEN);
    if (!dev->data_buf)
      goto alloc_fail;
    build_inquiry(dev->data_buf);
    dev->data_total = alloc;
    dev->data_offset = 0;
    *transfer_len = alloc;
    return SNOWSCSI_DATA_IN;
  }

  case SNOWSCSI_OP_TEST_UNIT_READY:
    *transfer_len = 0;
    return SNOWSCSI_STATUS;

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

  case SNOWSCSI_OP_READ_CAPACITY_10: {
    SNOW_LOGV("READ_CAPACITY_10: max_lba=%u block_size=%u", max_lba,
              dev->sector_size);
    dev->data_buf = malloc(8);
    if (!dev->data_buf)
      goto alloc_fail;
    build_read_capacity(dev->data_buf, max_lba, dev->sector_size);
    dev->data_total = 8;
    dev->data_offset = 0;
    *transfer_len = 8;
    return SNOWSCSI_DATA_IN;
  }

  case SNOWSCSI_OP_READ_10: {
    uint32_t lba = snowscsi_cdb_get_lba10(cdb);
    uint16_t count = snowscsi_cdb_get_transfer_len10(cdb);
    SNOW_LOGD("READ_10: lba=%u blocks=%u bytes=%u", lba, count,
              (uint32_t)count * dev->sector_size);
    if (count == 0) {
      *transfer_len = 0;
      return SNOWSCSI_STATUS;
    }
    if (lba > max_lba || (uint64_t)lba + count > (uint64_t)max_lba + 1) {
      SNOW_LOGW("READ_10: LBA out of range lba=%u max_lba=%u count=%u", lba,
                max_lba, count);
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
    uint64_t offset = (uint64_t)lba * dev->sector_size;
    if (dev->backend->ops->read(dev->backend->ctx, offset, dev->data_buf,
                                bytes) != 0) {
      SNOW_LOGE("READ_10: backend read failed offset=%lu bytes=%u",
                (unsigned long)offset, bytes);
      free(dev->data_buf);
      dev->data_buf = NULL;
      snowscsi_sense_set(&dev->sense, SNOWSCSI_SENSE_MEDIUM_ERROR, 0x11, 0x00);
      goto check_condition;
    }
    dev->data_total = bytes;
    dev->data_offset = 0;
    *transfer_len = bytes;
    return SNOWSCSI_DATA_IN;
  }

  case SNOWSCSI_OP_WRITE_10: {
    uint32_t lba = snowscsi_cdb_get_lba10(cdb);
    uint16_t count = snowscsi_cdb_get_transfer_len10(cdb);
    SNOW_LOGD("WRITE_10: lba=%u blocks=%u bytes=%u", lba, count,
              (uint32_t)count * dev->sector_size);
    if (count == 0) {
      *transfer_len = 0;
      return SNOWSCSI_STATUS;
    }
    if (lba > max_lba || (uint64_t)lba + count > (uint64_t)max_lba + 1) {
      SNOW_LOGW("WRITE_10: LBA out of range lba=%u max_lba=%u count=%u", lba,
                max_lba, count);
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
    dev->data_total = bytes;
    dev->data_offset = 0;
    dev->write_backend_offset = (uint64_t)lba * dev->sector_size;
    *transfer_len = bytes;
    return SNOWSCSI_DATA_OUT;
  }

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

  default:
    SNOW_LOGW("unknown opcode 0x%02x", opcode);
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
