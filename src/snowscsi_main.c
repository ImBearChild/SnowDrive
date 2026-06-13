#define SNOWLOG_TAG "snowscsi"
#include "snowlog.h"

#include <snowscsi/block.h>
#include <snowscsi/device.h>
#include <snowscsi/iscsi.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[]) {
  const char *addr = "0.0.0.0:3260";
  if (argc > 1)
    addr = argv[1];
  if (argc > 1 && strcmp(argv[1], "--help") == 0) {
    printf("usage: snowscsi [addr:port]\n");
    return 0;
  }

  snowscsi_device_t *dev = snowscsi_block_open_ram(16 * 1024 * 1024);
  if (!dev) {
    SNOW_LOGE("failed to create 16MB RAM disk");
    return 1;
  }

  printf("snowscsi: serving 16MB RAM disk on %s\n", addr);

  snowscsi_device_t *devs[] = {dev};
  int ret = snowscsi_iscsi_serve(devs, 1, addr, NULL, NULL);

  snowscsi_device_destroy(dev);
  return ret;
}
