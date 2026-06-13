#include "unity.h"
#include <iscsi/iscsi.h>
#include <iscsi/scsi-lowlevel.h>
#include <pthread.h>
#include <snowscsi/block.h>
#include <snowscsi/device.h>
#include <snowscsi/iscsi.h>
#include <stdio.h>
#include <unistd.h>

#define PORTAL "127.0.0.2:13260"
#define TARGET "iqn.1970-01.local.snowscsi:target"
#define INITIATOR "iqn.1970-01.local.test:initiator"

static pthread_t g_server_thread;
static snowscsi_device_t *g_dev;

/* ── server thread ───────────────────────────────────────────────── */

static void *server_thread_func(void *arg) {
  (void)arg;
  snowscsi_device_t *devs[] = {g_dev};
  snowscsi_iscsi_serve(devs, 1, PORTAL, NULL, NULL);
  return NULL;
}

/* ── setUp/tearDown ──────────────────────────────────────────────── */

void setUp(void) {
  if (g_dev == NULL) {
    g_dev = snowscsi_block_open_ram(16 * 1024 * 1024); /* 16 MB */
    pthread_create(&g_server_thread, NULL, server_thread_func, NULL);
  }
}

void tearDown(void) {}

/* ── libiscsi_connect ────────────────────────────────────────────── */

static struct iscsi_context *libiscsi_connect(const char *portal,
                                              const char *target) {
  struct iscsi_context *iscsi = iscsi_create_context(INITIATOR);
  if (!iscsi)
    return NULL;

  if (iscsi_set_targetname(iscsi, target) < 0)
    goto fail;
  if (iscsi_set_session_type(iscsi, ISCSI_SESSION_NORMAL) < 0)
    goto fail;
  if (iscsi_set_header_digest(iscsi, ISCSI_HEADER_DIGEST_NONE) < 0)
    goto fail;

  if (iscsi_connect_sync(iscsi, portal) < 0) {
    fprintf(stderr, "libiscsi_connect: connect failed: %s\n",
            iscsi_get_error(iscsi));
    goto fail;
  }
  if (iscsi_login_sync(iscsi) < 0) {
    fprintf(stderr, "libiscsi_connect: login failed: %s\n",
            iscsi_get_error(iscsi));
    goto fail;
  }

  return iscsi;

fail:
  iscsi_destroy_context(iscsi);
  return NULL;
}

/* ── test_whitebox_inquiry ──────────────────────────────────────── */

void test_whitebox_inquiry(void) {
  struct iscsi_context *iscsi = NULL;
  for (int i = 0; i < 20; i++) {
    iscsi = libiscsi_connect(PORTAL, TARGET);
    if (iscsi)
      break;
    usleep(100000);
  }
  if (!iscsi)
    TEST_FAIL_MESSAGE("failed to connect to snowscsi");

  struct scsi_task *task = iscsi_inquiry_sync(iscsi, 0, 0, 0, 36);
  TEST_ASSERT_NOT_NULL(task);
  TEST_ASSERT_EQUAL(SCSI_STATUS_GOOD, task->status);

  const unsigned char *inq = scsi_datain_unmarshall(task);
  TEST_ASSERT_NOT_NULL(inq);

  uint8_t peripheral = inq[0] & 0x1f;
  TEST_ASSERT_EQUAL_UINT8(SCSI_INQUIRY_PERIPHERAL_DEVICE_TYPE_DIRECT_ACCESS,
                          peripheral);

  scsi_free_scsi_task(task);
  iscsi_destroy_context(iscsi);
}

/* ── test_whitebox_read_capacity ────────────────────────────────── */

void test_whitebox_read_capacity(void) {
  struct iscsi_context *iscsi = NULL;
  for (int i = 0; i < 20; i++) {
    iscsi = libiscsi_connect(PORTAL, TARGET);
    if (iscsi)
      break;
    usleep(100000);
  }
  if (!iscsi)
    TEST_FAIL_MESSAGE("failed to connect to snowscsi");

  struct scsi_task *task = iscsi_readcapacity10_sync(iscsi, 0, 0, 0);
  TEST_ASSERT_NOT_NULL(task);
  TEST_ASSERT_EQUAL(SCSI_STATUS_GOOD, task->status);

  struct scsi_readcapacity10 *cap =
      (struct scsi_readcapacity10 *)scsi_datain_unmarshall(task);
  TEST_ASSERT_NOT_NULL(cap);

  TEST_ASSERT_EQUAL_UINT32(32767, cap->lba);
  TEST_ASSERT_EQUAL_UINT32(512, cap->block_size);

  scsi_free_scsi_task(task);
  iscsi_destroy_context(iscsi);
}

/* ── test_whitebox_read ──────────────────────────────────────────── */

void test_whitebox_read(void) {
  /* TOOD: implement after write-through via iSCSI is available */
  TEST_IGNORE_MESSAGE("write-through test not yet implemented");
}

/* ── main ────────────────────────────────────────────────────────── */

int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_whitebox_inquiry);
  RUN_TEST(test_whitebox_read_capacity);
  RUN_TEST(test_whitebox_read);
  int result = UNITY_END();

  if (g_server_thread) {
    pthread_cancel(g_server_thread);
    pthread_join(g_server_thread, NULL);
  }
  if (g_dev)
    snowscsi_device_destroy(g_dev);

  return result;
}
