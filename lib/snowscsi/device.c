#include "device_internal.h"

#define SNOWLOG_TAG "device"
#include "snowlog.h"

#include <stdlib.h>
#include <string.h>

snowscsi_result_t snowscsi_do_cmd(snowscsi_device_t *dev, const uint8_t *cdb,
                                  uint8_t cdb_len, uint32_t *transfer_len) {
  free(dev->data_buf);
  dev->data_buf = NULL;
  dev->data_total = 0;
  dev->data_offset = 0;
  dev->write_backend_offset = 0;

  snowscsi_result_t r = dev->handle_cmd(dev, cdb, cdb_len, transfer_len);
  SNOW_LOGV("do_cmd: opcode=0x%02x result=%d transfer_len=%u", cdb ? cdb[0] : 0,
            (int)r, transfer_len ? *transfer_len : 0);
  if (r != SNOWSCSI_CHECK_CONDITION)
    snowscsi_sense_clear(&dev->sense);
  return r;
}

int snowscsi_read_data(snowscsi_device_t *dev, void *buf, uint32_t len) {
  if (dev->data_offset >= dev->data_total)
    return 0;

  uint32_t remaining = dev->data_total - dev->data_offset;
  uint32_t n = (len < remaining) ? len : remaining;

  memcpy(buf, dev->data_buf + dev->data_offset, n);
  dev->data_offset += n;
  SNOW_LOGV("read_data: offset=%u/%u n=%u", dev->data_offset - n,
            dev->data_total, n);
  return (int)n;
}

int snowscsi_write_data(snowscsi_device_t *dev, const void *data,
                        uint32_t len) {
  if (dev->data_offset >= dev->data_total)
    return 1;

  uint32_t remaining = dev->data_total - dev->data_offset;
  uint32_t n = (len < remaining) ? len : remaining;

  memcpy(dev->data_buf + dev->data_offset, data, n);
  dev->data_offset += n;
  SNOW_LOGV("write_data: offset=%u/%u n=%u", dev->data_offset - n,
            dev->data_total, n);

  if (dev->data_offset >= dev->data_total) {
    /* All data received — flush to backend */
    if (dev->backend && dev->backend->ops->write) {
      if (dev->backend->ops->write(dev->backend->ctx, dev->write_backend_offset,
                                   dev->data_buf, dev->data_total) != 0) {
        SNOW_LOGE("write_data: backend write failed offset=%lu bytes=%u",
                  (unsigned long)dev->write_backend_offset, dev->data_total);
        snowscsi_sense_set(&dev->sense, SNOWSCSI_SENSE_MEDIUM_ERROR,
                           SNOWSCSI_ASC_WRITE_FAULT, 0x00);
        return -1;
      }
    }
    SNOW_LOGD("write_data: complete offset=%lu bytes=%u",
              (unsigned long)dev->write_backend_offset, dev->data_total);
    return 1;
  }
  return 0;
}

snowscsi_device_type_t snowscsi_device_get_type(const snowscsi_device_t *dev) {
  return dev->type;
}

void snowscsi_device_get_sense(const snowscsi_device_t *dev,
                               snowscsi_sense_t *sense) {
  *sense = dev->sense;
}

void snowscsi_device_destroy(snowscsi_device_t *dev) {
  if (!dev)
    return;
  free(dev->data_buf);
  if (dev->backend)
    snowscsi_backend_destroy(dev->backend);
  free(dev);
}
