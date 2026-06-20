#define SNOWLOG_TAG "snowscsi"
#include "snowlog.h"

#include <snowscsi/block.h>
#include <snowscsi/device.h>
#include <snowscsi/iscsi.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void print_usage(void) {
  printf("usage: snowscsi serve --block <spec> --iscsi <addr> "
         "[--verbose] [--help]\n");
  printf("\n");
  printf("  --block <path>        File-backed block device (R/W)\n");
  printf("  --block ram=<size>    RAM-backed block device "
         "(e.g. 256M, 1G)\n");
  printf("  --iscsi <addr:port>   iSCSI listen address (required)\n");
  printf("  --verbose             Verbose logging\n");
  printf("  --help                Show this help\n");
}

static uint64_t parse_size(const char *s) {
  char *end;
  uint64_t val = strtoull(s, &end, 10);
  if (end == s)
    return 0;
  char c = *end;
  if (c == 'K' || c == 'k')
    val *= 1024ULL;
  else if (c == 'M' || c == 'm')
    val *= 1024ULL * 1024ULL;
  else if (c == 'G' || c == 'g')
    val *= 1024ULL * 1024ULL * 1024ULL;
  else if (c != '\0')
    return 0;
  return val;
}

int main(int argc, char *argv[]) {
  const char *iscsi_addr = NULL;
  const char *block_spec = NULL;
  int block_count = 0;

  /* Require "serve" subcommand */
  int idx = 1;
  if (idx >= argc || strcmp(argv[idx], "serve") != 0) {
    if (idx < argc && (strcmp(argv[idx], "--help") == 0 ||
                       strcmp(argv[idx], "-h") == 0)) {
      print_usage();
      return 0;
    }
    fprintf(stderr, "snowscsi: expected 'serve' subcommand\n");
    print_usage();
    return 1;
  }
  idx++;

  for (; idx < argc; idx++) {
    if (strcmp(argv[idx], "--help") == 0 || strcmp(argv[idx], "-h") == 0) {
      print_usage();
      return 0;
    }
    if (strcmp(argv[idx], "--verbose") == 0 ||
        strcmp(argv[idx], "-v") == 0) {
      snowlog_set_level(SNOWLOG_DEBUG);
      continue;
    }
    if (strcmp(argv[idx], "--iscsi") == 0) {
      if (idx + 1 >= argc) {
        fprintf(stderr, "snowscsi: --iscsi requires an address argument\n");
        return 1;
      }
      iscsi_addr = argv[++idx];
      continue;
    }
    if (strcmp(argv[idx], "--block") == 0) {
      if (idx + 1 >= argc) {
        fprintf(stderr, "snowscsi: --block requires a spec argument\n");
        return 1;
      }
      block_count++;
      if (block_count == 1) {
        block_spec = argv[++idx];
      } else {
        SNOW_LOGW("multi-LUN not yet supported, using first --block only");
        idx++;
      }
      continue;
    }
    if (strcmp(argv[idx], "--cdrom") == 0) {
      fprintf(stderr, "snowscsi: --cdrom not yet supported\n");
      return 1;
    }
    if (strncmp(argv[idx], "--", 2) == 0) {
      fprintf(stderr, "snowscsi: unknown option: %s\n", argv[idx]);
      return 1;
    }
    fprintf(stderr, "snowscsi: unexpected argument: %s\n", argv[idx]);
    return 1;
  }

  /* Validate required arguments */
  if (!iscsi_addr) {
    fprintf(stderr, "snowscsi: --iscsi is required\n");
    return 1;
  }
  if (!block_spec) {
    fprintf(stderr, "snowscsi: --block is required\n");
    return 1;
  }

  /* Parse block spec and create device */
  snowscsi_device_t *dev = NULL;

  if (strncmp(block_spec, "ram=", 4) == 0) {
    uint64_t size = parse_size(block_spec + 4);
    if (size == 0) {
      fprintf(stderr, "snowscsi: invalid RAM size: %s\n", block_spec + 4);
      return 1;
    }
    dev = snowscsi_block_open_ram(size);
    if (!dev) {
      SNOW_LOGE("failed to create RAM disk (%llu bytes)",
                (unsigned long long)size);
      return 1;
    }
  } else {
    /* File backend — extract path before first comma */
    const char *comma = strchr(block_spec, ',');
    char path[4096];

    if (comma) {
      size_t plen = (size_t)(comma - block_spec);
      if (plen >= sizeof(path)) {
        fprintf(stderr, "snowscsi: path too long\n");
        return 1;
      }
      memcpy(path, block_spec, plen);
      path[plen] = '\0';

      const char *opt = comma + 1;
      if (strcmp(opt, "ro") == 0) {
        SNOW_LOGW("read-only file backend not yet supported, "
                   "opening as R/W");
      } else {
        SNOW_LOGW("unknown block option '%s', ignoring", opt);
      }
    } else {
      if (strlen(block_spec) >= sizeof(path)) {
        fprintf(stderr, "snowscsi: path too long\n");
        return 1;
      }
      strcpy(path, block_spec);
    }

    /* Verify file exists */
    FILE *ftest = fopen(path, "rb");
    if (!ftest) {
      fprintf(stderr, "snowscsi: file not found: %s\n", path);
      return 1;
    }
    fclose(ftest);

    dev = snowscsi_block_open_file(path);
    if (!dev) {
      SNOW_LOGE("failed to open file block device: %s", path);
      return 1;
    }
  }

  snowscsi_device_t *devs[] = {dev};
  int ret = snowscsi_iscsi_serve(devs, 1, iscsi_addr, NULL, NULL);

  snowscsi_device_destroy(dev);
  return ret;
}
