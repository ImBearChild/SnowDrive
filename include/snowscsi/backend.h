#ifndef SNOWSCSI_BACKEND_H
#define SNOWSCSI_BACKEND_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* ── Backend Operations ────────────────────────────────────────── */

typedef struct snowscsi_backend_ops {
  int (*read)(void *ctx, uint64_t offset, void *buf, size_t len);
  int (*write)(void *ctx, uint64_t offset, const void *buf, size_t len);
  int (*sync)(void *ctx);
  uint64_t (*get_size)(void *ctx);
  void (*destroy)(void *ctx);
} snowscsi_backend_ops_t;

/* ── Backend Handle ────────────────────────────────────────────── */

typedef struct {
  const snowscsi_backend_ops_t *ops;
  void *ctx;
} snowscsi_backend_t;

/* ── Predefined Backends ───────────────────────────────────────── */

snowscsi_backend_t *snowscsi_backend_ram_create(uint64_t size);
snowscsi_backend_t *snowscsi_backend_file_open(const char *path, bool writable);
void snowscsi_backend_destroy(snowscsi_backend_t *backend);

#endif
