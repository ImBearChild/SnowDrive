#ifndef SNOWSCSI_DEVICE_INTERNAL_H
#define SNOWSCSI_DEVICE_INTERNAL_H

#include <snowscsi/backend.h>
#include <snowscsi/device.h>

struct snowscsi_device {
  snowscsi_device_type_t type;
  snowscsi_backend_t *backend;
  snowscsi_sense_t sense;
  uint32_t sector_size;

  /* Chunked data transfer state */
  uint8_t *data_buf;
  uint32_t data_total;
  uint32_t data_offset;

  /* Backend write target offset (set by handle_cmd for DATA_OUT) */
  uint64_t write_backend_offset;

  /* Command handler (set by block.c or cdrom.c) */
  snowscsi_result_t (*handle_cmd)(snowscsi_device_t *dev, const uint8_t *cdb,
                                  uint8_t cdb_len, uint32_t *transfer_len);
};

#endif
