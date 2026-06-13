#include <snowscsi/block.h>
#include <snowscsi/device.h>
#include <snowscsi/iscsi.h>

#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
  (void)argc;
  (void)argv;

  snowscsi_device_t *dev = snowscsi_block_open_ram(16 * 1024 * 1024);
  if (!dev) {
    fprintf(stderr, "snowscsi: failed to create 16MB RAM disk\n");
    return 1;
  }

  printf("snowscsi: serving 16MB RAM disk on 0.0.0.0:3260\n");

  snowscsi_device_t *devs[] = {dev};
  int ret = snowscsi_iscsi_serve(devs, 1, "0.0.0.0:3260", NULL, NULL);

  snowscsi_device_destroy(dev);
  return ret;
}
