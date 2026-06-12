#include <stdio.h>

int main(int argc, char *argv[]) {
  (void)argc;
  (void)argv;
  printf("snowscsi: SCSI device emulation toolkit\n");
  printf("Usage: snowscsi serve [--block <spec>]... [--cdrom <spec>]... "
         "--iscsi <addr>\n");
  return 0;
}
