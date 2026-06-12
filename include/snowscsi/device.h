#ifndef SNOWSCSI_DEVICE_H
#define SNOWSCSI_DEVICE_H

#include <stdbool.h>
#include <stdint.h>

#include <snowscsi/scsi.h>

/* ── Result Types ──────────────────────────────────────────────── */

typedef enum {
  SNOWSCSI_STATUS,   /* No data phase, command succeeded (GOOD) */
  SNOWSCSI_DATA_IN,  /* Device → Host: caller loops snowscsi_read_data */
  SNOWSCSI_DATA_OUT, /* Host → Device: caller loops snowscsi_write_data */
  SNOWSCSI_CHECK_CONDITION, /* Command failed, get sense via
                               snowscsi_device_get_sense */
} snowscsi_result_t;

/* ── Device Types ──────────────────────────────────────────────── */

typedef enum {
  SNOWSCSI_TYPE_BLOCK,
  SNOWSCSI_TYPE_CDROM,
} snowscsi_device_type_t;

/* ── Device Handle (opaque) ────────────────────────────────────── */

typedef struct snowscsi_device snowscsi_device_t;

/* ── Core Command Processing ───────────────────────────────────── */

snowscsi_result_t snowscsi_do_cmd(snowscsi_device_t *dev, const uint8_t *cdb,
                                  uint8_t cdb_len, uint32_t *transfer_len);

int snowscsi_read_data(snowscsi_device_t *dev, void *buf, uint32_t len);
int snowscsi_write_data(snowscsi_device_t *dev, const void *data,
                        uint32_t len); /* -1=error (check sense), 0=more data,
                                          1=done */

/* ── Device Queries ────────────────────────────────────────────── */

snowscsi_device_type_t snowscsi_device_get_type(const snowscsi_device_t *dev);
void snowscsi_device_get_sense(const snowscsi_device_t *dev,
                               snowscsi_sense_t *sense);

/* ── Device Lifecycle ──────────────────────────────────────────── */

void snowscsi_device_destroy(snowscsi_device_t *dev);

#endif
