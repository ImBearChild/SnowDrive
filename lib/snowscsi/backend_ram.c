#include <snowscsi/backend.h>

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
  uint8_t *data;
  uint64_t size;
} ram_ctx_t;

static int ram_read(void *ctx, uint64_t offset, void *buf, size_t len) {
  ram_ctx_t *r = ctx;
  if (offset + len > r->size)
    return -1;
  memcpy(buf, r->data + offset, len);
  return 0;
}

static int ram_write(void *ctx, uint64_t offset, const void *buf, size_t len) {
  ram_ctx_t *r = ctx;
  if (offset + len > r->size)
    return -1;
  memcpy(r->data + offset, buf, len);
  return 0;
}

static int ram_sync(void *ctx) {
  (void)ctx;
  return 0;
}

static uint64_t ram_get_size(void *ctx) {
  ram_ctx_t *r = ctx;
  return r->size;
}

static void ram_destroy(void *ctx) {
  ram_ctx_t *r = ctx;
  free(r->data);
  free(r);
}

static const snowscsi_backend_ops_t ram_ops = {
    .read = ram_read,
    .write = ram_write,
    .sync = ram_sync,
    .get_size = ram_get_size,
    .destroy = ram_destroy,
};

snowscsi_backend_t *snowscsi_backend_ram_create(uint64_t size) {
  if (size > SIZE_MAX)
    return NULL;

  ram_ctx_t *rc = calloc(1, sizeof(*rc));
  if (!rc)
    return NULL;

  rc->data = calloc(1, (size_t)size);
  if (!rc->data) {
    free(rc);
    return NULL;
  }
  rc->size = size;

  snowscsi_backend_t *b = calloc(1, sizeof(*b));
  if (!b) {
    free(rc->data);
    free(rc);
    return NULL;
  }

  b->ops = &ram_ops;
  b->ctx = rc;
  return b;
}

void snowscsi_backend_destroy(snowscsi_backend_t *backend) {
  if (!backend)
    return;
  if (backend->ops && backend->ops->destroy)
    backend->ops->destroy(backend->ctx);
  free(backend);
}
