#include <snowscsi/backend.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

typedef struct {
  FILE *fp;
  uint64_t size;
  bool writable;
} file_ctx_t;

static int file_read(void *ctx, uint64_t offset, void *buf, size_t len) {
  file_ctx_t *f = ctx;
  if (fseeko(f->fp, (off_t)offset, SEEK_SET) != 0)
    return -1;
  if (fread(buf, 1, len, f->fp) != len)
    return -1;
  return 0;
}

static int file_write(void *ctx, uint64_t offset, const void *buf, size_t len) {
  file_ctx_t *f = ctx;
  if (!f->writable)
    return -1;
  if (fseeko(f->fp, (off_t)offset, SEEK_SET) != 0)
    return -1;
  if (fwrite(buf, 1, len, f->fp) != len)
    return -1;
  return 0;
}

static int file_sync(void *ctx) {
  file_ctx_t *f = ctx;
  if (fflush(f->fp) != 0)
    return -1;
  if (fsync(fileno(f->fp)) != 0)
    return -1;
  return 0;
}

static uint64_t file_get_size(void *ctx) {
  file_ctx_t *f = ctx;
  return f->size;
}

static void file_destroy(void *ctx) {
  file_ctx_t *f = ctx;
  fclose(f->fp);
  free(f);
}

static const snowscsi_backend_ops_t file_ops = {
    .read = file_read,
    .write = file_write,
    .sync = file_sync,
    .get_size = file_get_size,
    .destroy = file_destroy,
};

snowscsi_backend_t *snowscsi_backend_file_open(const char *path, bool writable) {
  if (!path)
    return NULL;

  const char *mode = writable ? "r+b" : "rb";
  FILE *fp = fopen(path, mode);
  if (!fp) {
    /* Try creating the file if writable and it doesn't exist */
    if (writable) {
      fp = fopen(path, "w+b");
      if (!fp)
        return NULL;
    } else {
      return NULL;
    }
  }

  if (fseeko(fp, 0, SEEK_END) != 0) {
    fclose(fp);
    return NULL;
  }
  uint64_t file_size = (uint64_t)ftello(fp);

  file_ctx_t *fc = calloc(1, sizeof(*fc));
  if (!fc) {
    fclose(fp);
    return NULL;
  }
  fc->fp = fp;
  fc->size = file_size;
  fc->writable = writable;

  snowscsi_backend_t *b = calloc(1, sizeof(*b));
  if (!b) {
    fclose(fp);
    free(fc);
    return NULL;
  }

  b->ops = &file_ops;
  b->ctx = fc;
  return b;
}
