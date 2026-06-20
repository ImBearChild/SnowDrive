#ifndef SNOWSCSI_BLOCK_H
#define SNOWSCSI_BLOCK_H

#include <stdint.h>

#include <snowscsi/backend.h>
#include <snowscsi/device.h>

/* ── Block Device API ──────────────────────────────────────────── */

snowscsi_device_t *snowscsi_block_create(snowscsi_backend_t *backend,
                                         uint32_t sector_size);

snowscsi_device_t *snowscsi_block_open_ram(uint64_t size);

snowscsi_device_t *snowscsi_block_open_file(const char *path);

#endif
