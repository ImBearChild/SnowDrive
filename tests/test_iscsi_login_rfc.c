#include "unity.h"

#include <snowscsi/block.h>
#include <snowscsi/device.h>
#include <snowscsi/iscsi.h>

#include <pthread.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

/* ── Build initiator text keys ──────────────────────────────────────
 *  Use sizeof(literal) to capture the full text including embedded
 *  null separators.  Each literal's first byte is the key=value text
 *  with trailing \0; adjacent literals are concatenated by the
 *  compiler, preserving each embedded null.
 *
 *  We wrap them in a helper macro so the preprocessor concatenates
 *  them into a single string literal, and sizeof gives the total
 *  bytes including the final \0 from the last fragment.
 */
#define REQ_TEXT                                                               \
  "InitiatorName=iqn.1994-05.com.redhat:702f27e1da14\0"                       \
  "InitiatorAlias=develop\0"                                                  \
  "TargetName=iqn.1970-01.local.snowscsi:target\0"                            \
  "SessionType=Normal\0"                                                      \
  "HeaderDigest=None\0"                                                       \
  "DataDigest=None\0"                                                         \
  "DefaultTime2Wait=2\0"                                                      \
  "DefaultTime2Retain=0\0"                                                    \
  "IFMarker=No\0"                                                             \
  "OFMarker=No\0"                                                             \
  "ErrorRecoveryLevel=0\0"                                                    \
  "InitialR2T=No\0"                                                           \
  "ImmediateData=Yes\0"                                                       \
  "MaxBurstLength=16776192\0"                                                 \
  "FirstBurstLength=262144\0"                                                 \
  "MaxOutstandingR2T=1\0"                                                     \
  "MaxConnections=1\0"                                                        \
  "DataPDUInOrder=Yes\0"                                                      \
  "DataSequenceInOrder=Yes\0"                                                 \
  "MaxRecvDataSegmentLength=262144\0"

/* ── Mock transport context ──────────────────────────────────────── */

typedef struct {
  uint8_t req_bhs[48];                /* Login Request BHS */
  const char *req_text;               /* null-separated key=value pairs */
  uint32_t req_dsl;                   /* DataSegmentLength of text */

  uint8_t resp[48 + 8192 + 3];        /* captured Login Response */
  size_t  resp_len;

  int     recv_call_nr;               /* which recv call we are on */
  int     accept_called;              /* ensure only one connection */
  bool    stop;                       /* signal mock_accept to stop */
} mock_ctx_t;

static mock_ctx_t g_mock;

/* ── Mock transport callbacks ────────────────────────────────────── */

static intptr_t mock_listen(void *ctx, const char *addr, uint16_t port) {
  (void)ctx; (void)addr; (void)port;
  return 42;                          /* dummy listener fd */
}

static intptr_t mock_accept(void *ctx, intptr_t listener) {
  (void)listener;
  mock_ctx_t *m = (mock_ctx_t *)ctx;
  if (m->accept_called++ == 0)
    return 1;                         /* one fake connection */

  /* Block until the test finishes */
  while (!m->stop)
    usleep(10000);
  return -1;
}

static int mock_recv(void *ctx, intptr_t conn, void *buf, size_t len) {
  (void)conn; (void)len;
  mock_ctx_t *m = (mock_ctx_t *)ctx;
  int n = m->recv_call_nr++;

  if (n == 0) {
    memcpy(buf, m->req_bhs, 48);
    return 48;
  }

  if (n == 1) {
    memcpy(buf, m->req_text, m->req_dsl);
    return (int)m->req_dsl;
  }

  if (n == 2) {
    uint32_t pad = (4 - ((48 + m->req_dsl) & 3)) & 3;
    if (pad > 0) {
      memset(buf, 0, pad);
      return (int)pad;
    }
  }

  return -1;
}

static int mock_send(void *ctx, intptr_t conn, const void *buf, size_t len) {
  (void)conn;
  mock_ctx_t *m = (mock_ctx_t *)ctx;
  memcpy(m->resp + m->resp_len, buf, len);
  m->resp_len += len;
  return (int)len;
}

static void mock_disconnect(void *ctx, intptr_t conn) {
  (void)ctx; (void)conn;
}

static void mock_stop(void *ctx, intptr_t listener) {
  (void)ctx; (void)listener;
}

static const snowscsi_transport_ops_t MOCK_TRANSPORT = {
    .listen     = mock_listen,
    .accept     = mock_accept,
    .recv       = mock_recv,
    .send       = mock_send,
    .disconnect = mock_disconnect,
    .stop       = mock_stop,
};

/* ── Server thread ───────────────────────────────────────────────── */

static pthread_t       g_server;
static snowscsi_device_t *g_dev;

static void *server_thread(void *arg) {
  (void)arg;
  snowscsi_device_t *devs[] = {g_dev};
  snowscsi_iscsi_serve(devs, 1, "0.0.0.1:13260", &MOCK_TRANSPORT, &g_mock);
  return NULL;
}

/* ── Helpers ─────────────────────────────────────────────────────── */

/* Build a Login Request BHS that matches what the Linux initiator sends */
static void build_login_req_bhs(uint8_t bhs[48], uint32_t dsl) {
  memset(bhs, 0, 48);
  bhs[0] = SNOWSCSI_ISCSI_OP_LOGIN_REQ | 0x40;          /* I bit set */
  bhs[1] = 0x80 | (SNOWSCSI_ISCSI_STAGE_OP_PARAM << 2) |
           SNOWSCSI_ISCSI_STAGE_FULL_FEATURE;
  bhs[2] = 0;                     /* Version-max */
  bhs[3] = 0;                     /* Version-min */
  bhs[5] = (uint8_t)((dsl >> 16) & 0xFF);
  bhs[6] = (uint8_t)((dsl >> 8) & 0xFF);
  bhs[7] = (uint8_t)(dsl & 0xFF);
}

/* Check whether a key=value pair exists in the response text */
static int resp_has_key(const uint8_t *data, uint32_t dlen, const char *key) {
  const char *p = (const char *)data;
  const char *end = p + dlen;
  while (p < end) {
    size_t kl = strlen(key);
    if ((size_t)(end - p) > kl && memcmp(p, key, kl) == 0 && p[kl] == '=')
      return 1;
    /* advance past this null-terminated string */
    p += strlen(p) + 1;
  }
  return 0;
}

/* Extract the value for a given key from the response text */
static const char *resp_value(const uint8_t *data, uint32_t dlen,
                              const char *key) {
  const char *p = (const char *)data;
  const char *end = p + dlen;
  while (p < end) {
    size_t kl = strlen(key);
    if ((size_t)(end - p) > kl && memcmp(p, key, kl) == 0 && p[kl] == '=')
      return p + kl + 1;
    p += strlen(p) + 1;
  }
  return NULL;
}

/* ── setUp / tearDown ────────────────────────────────────────────── */

void setUp(void) {
  memset(&g_mock, 0, sizeof(g_mock));
  g_mock.stop = false;

  g_dev = snowscsi_block_open_ram(16 * 1024 * 1024);

  /* Build initiator text keys (same as Linux open-iscsi would send) */
  g_mock.req_dsl = (uint32_t)sizeof(REQ_TEXT);
  g_mock.req_text = REQ_TEXT;

  build_login_req_bhs(g_mock.req_bhs, g_mock.req_dsl);

  pthread_create(&g_server, NULL, server_thread, NULL);
  usleep(200000);   /* give the server time to process the login */
}

void tearDown(void) {
  g_mock.stop = true;
  pthread_cancel(g_server);
  pthread_join(g_server, NULL);
  if (g_dev)
    snowscsi_device_destroy(g_dev);
}

/* ── Tests ───────────────────────────────────────────────────────── */

/* Verify the Login Response BHS layout matches RFC 3720 §10.12.2 */
void test_login_resp_bhs_rfc(void) {
  TEST_ASSERT_GREATER_THAN_UINT32(48, g_mock.resp_len);
  uint8_t *bhs = g_mock.resp;

  /* Byte 0: opcode */
  TEST_ASSERT_EQUAL_HEX8(SNOWSCSI_ISCSI_OP_LOGIN_RESP, bhs[0] & 0x3F);

  /* Byte 1: T=1 (bit 7), C=0 (bit 6), CSG=1 (bits 3-2), NSG=3 (bits 1-0) */
  TEST_ASSERT_BIT_HIGH(7, bhs[1]);
  TEST_ASSERT_BIT_LOW(6, bhs[1]);
  uint8_t csg = (bhs[1] >> 2) & 3;
  uint8_t nsg = bhs[1] & 3;
  TEST_ASSERT_EQUAL_UINT8(SNOWSCSI_ISCSI_STAGE_OP_PARAM, csg);
  TEST_ASSERT_EQUAL_UINT8(SNOWSCSI_ISCSI_STAGE_FULL_FEATURE, nsg);

  /* Byte 2: Version-max = 0 (RFC 3720 §10.12.4) */
  TEST_ASSERT_EQUAL_HEX8(0x00, bhs[2]);

  /* Byte 3: Version-active = 0 */
  TEST_ASSERT_EQUAL_HEX8(0x00, bhs[3]);

  /* Byte 4: TotalAHSLength = 0 */
  TEST_ASSERT_EQUAL_HEX8(0x00, bhs[4]);

  /* Bytes 5-7: DataSegmentLength > 0 */
  uint32_t dsl = ((uint32_t)bhs[5] << 16) | ((uint32_t)bhs[6] << 8) | bhs[7];
  TEST_ASSERT_GREATER_THAN_UINT32(0, dsl);

  /* ISID echoed (bytes 8-13) */
  TEST_ASSERT_EQUAL_UINT8_ARRAY(g_mock.req_bhs + 8, bhs + 8, 6);

  /* TSIH (bytes 14-15): non-zero for new session Login Final-Response
   * (§10.13.3) */
  uint16_t tsih = (uint16_t)bhs[14] << 8 | bhs[15];
  TEST_ASSERT_NOT_EQUAL_UINT16(0, tsih);

  /* Initiator Task Tag (bytes 16-19): echoed from request */
  TEST_ASSERT_EQUAL_UINT8_ARRAY(g_mock.req_bhs + 16, bhs + 16, 4);

  /* Bytes 20-23: reserved, MUST be 0 */
  TEST_ASSERT_EQUAL_HEX8(0x00, bhs[20]);
  TEST_ASSERT_EQUAL_HEX8(0x00, bhs[21]);
  TEST_ASSERT_EQUAL_HEX8(0x00, bhs[22]);
  TEST_ASSERT_EQUAL_HEX8(0x00, bhs[23]);

  /* StatSN = 0 (first response) */
  uint32_t stat_sn = (uint32_t)bhs[24] << 24 | (uint32_t)bhs[25] << 16 |
                     (uint32_t)bhs[26] << 8 | bhs[27];
  TEST_ASSERT_EQUAL_UINT32(0, stat_sn);

  /* ExpCmdSN (bytes 28-31): equals CmdSN from Login Request */
  uint32_t req_cmd_sn = (uint32_t)g_mock.req_bhs[28] << 24 |
                        (uint32_t)g_mock.req_bhs[29] << 16 |
                        (uint32_t)g_mock.req_bhs[30] << 8 |
                        g_mock.req_bhs[31];
  uint32_t exp_cmd_sn = (uint32_t)bhs[28] << 24 | (uint32_t)bhs[29] << 16 |
                        (uint32_t)bhs[30] << 8 | bhs[31];
  TEST_ASSERT_EQUAL_UINT32(req_cmd_sn, exp_cmd_sn);

  /* MaxCmdSN (bytes 32-35): equals CmdSN from Login Request */
  uint32_t max_cmd_sn = (uint32_t)bhs[32] << 24 | (uint32_t)bhs[33] << 16 |
                        (uint32_t)bhs[34] << 8 | bhs[35];
  TEST_ASSERT_EQUAL_UINT32(req_cmd_sn, max_cmd_sn);

  /* Status-Class (byte 36) = 0 (Success); Status-Detail (byte 37) = 0 */
  TEST_ASSERT_EQUAL_HEX8(0x00, bhs[36]);
  TEST_ASSERT_EQUAL_HEX8(0x00, bhs[37]);

  /* Bytes 38-47: reserved, MUST be 0 */
  for (int i = 38; i < 48; i++)
    TEST_ASSERT_EQUAL_HEX8_MESSAGE(0x00, bhs[i], "reserved byte not zero");
}

/* Verify no disallowed keys appear in the Login Response text */
void test_login_resp_no_skipped_keys(void) {
  uint32_t dsl = ((uint32_t)g_mock.resp[5] << 16) |
                 ((uint32_t)g_mock.resp[6] << 8) | g_mock.resp[7];
  const uint8_t *text = g_mock.resp + 48;

  /* TargetName must not be redeclared (RFC 3720 §12.4) */
  TEST_ASSERT_FALSE_MESSAGE(resp_has_key(text, dsl, "TargetName"),
                            "TargetName must not appear in Login Response");

  /* Initiator-only keys must not appear */
  TEST_ASSERT_FALSE_MESSAGE(resp_has_key(text, dsl, "InitiatorName"),
                            "InitiatorName must not appear");
  TEST_ASSERT_FALSE_MESSAGE(resp_has_key(text, dsl, "InitiatorAlias"),
                            "InitiatorAlias must not appear");
  TEST_ASSERT_FALSE_MESSAGE(resp_has_key(text, dsl, "SessionType"),
                            "SessionType must not appear");

  /* AuthMethod — initiator didn't send it and always=false */
  TEST_ASSERT_FALSE_MESSAGE(resp_has_key(text, dsl, "AuthMethod"),
                            "AuthMethod must not appear (stage mismatch)");

  /* TargetAddress — only appears on redirect, never in normal accept */
  TEST_ASSERT_FALSE_MESSAGE(resp_has_key(text, dsl, "TargetAddress"),
                            "TargetAddress must not appear (no redirect)");
}

/* Verify required keys are present in the Login Response text */
void test_login_resp_has_required_keys(void) {
  uint32_t dsl = ((uint32_t)g_mock.resp[5] << 16) |
                 ((uint32_t)g_mock.resp[6] << 8) | g_mock.resp[7];
  const uint8_t *text = g_mock.resp + 48;

  /* TargetAlias must be present (always=true) */
  const char *alias = resp_value(text, dsl, "TargetAlias");
  TEST_ASSERT_NOT_NULL(alias);
  TEST_ASSERT_EQUAL_STRING("SnowSCSI", alias);

  /* TargetPortalGroupTag must be present (RFC 3720 §12.9, always=true) */
  const char *tpgt = resp_value(text, dsl, "TargetPortalGroupTag");
  TEST_ASSERT_NOT_NULL(tpgt);
  TEST_ASSERT_EQUAL_STRING("1", tpgt);
}

/* Verify ALL keys proposed by the initiator are echoed back */
void test_login_resp_echoes_all_keys(void) {
  uint32_t dsl = ((uint32_t)g_mock.resp[5] << 16) |
                 ((uint32_t)g_mock.resp[6] << 8) | g_mock.resp[7];
  const uint8_t *text = g_mock.resp + 48;

  /* Keys echoed because LOGIN_TABLE entry has value=NULL */
  const char *  v = resp_value(text, dsl, "InitialR2T");
  TEST_ASSERT_NOT_NULL(v);
  TEST_ASSERT_EQUAL_STRING("Yes", v);
  v = resp_value(text, dsl, "MaxBurstLength");
  TEST_ASSERT_NOT_NULL(v);
  TEST_ASSERT_EQUAL_STRING("16776192", v);
  v = resp_value(text, dsl, "FirstBurstLength");
  TEST_ASSERT_NOT_NULL(v);
  TEST_ASSERT_EQUAL_STRING("262144", v);
  v = resp_value(text, dsl, "MaxRecvDataSegmentLength");
  TEST_ASSERT_NOT_NULL(v);
  TEST_ASSERT_EQUAL_STRING("8192", v);
  v = resp_value(text, dsl, "DataPDUInOrder");
  TEST_ASSERT_NOT_NULL(v);
  TEST_ASSERT_EQUAL_STRING("Yes", v);
  v = resp_value(text, dsl, "DataSequenceInOrder");
  TEST_ASSERT_NOT_NULL(v);
  TEST_ASSERT_EQUAL_STRING("Yes", v);
  v = resp_value(text, dsl, "DefaultTime2Wait");
  TEST_ASSERT_NOT_NULL(v);
  TEST_ASSERT_EQUAL_STRING("2", v);
  v = resp_value(text, dsl, "DefaultTime2Retain");
  TEST_ASSERT_NOT_NULL(v);
  TEST_ASSERT_EQUAL_STRING("0", v);
  v = resp_value(text, dsl, "IFMarker");
  TEST_ASSERT_NOT_NULL(v);
  TEST_ASSERT_EQUAL_STRING("No", v);
  v = resp_value(text, dsl, "OFMarker");
  TEST_ASSERT_NOT_NULL(v);
  TEST_ASSERT_EQUAL_STRING("No", v);

  /* Keys echoed because LOGIN_TABLE entry has hardcoded value */
  v = resp_value(text, dsl, "HeaderDigest");
  TEST_ASSERT_NOT_NULL(v);
  TEST_ASSERT_EQUAL_STRING("None", v);
  v = resp_value(text, dsl, "DataDigest");
  TEST_ASSERT_NOT_NULL(v);
  TEST_ASSERT_EQUAL_STRING("None", v);
  v = resp_value(text, dsl, "ImmediateData");
  TEST_ASSERT_NOT_NULL(v);
  TEST_ASSERT_EQUAL_STRING("Yes", v);
  v = resp_value(text, dsl, "MaxOutstandingR2T");
  TEST_ASSERT_NOT_NULL(v);
  TEST_ASSERT_EQUAL_STRING("1", v);
  v = resp_value(text, dsl, "MaxConnections");
  TEST_ASSERT_NOT_NULL(v);
  TEST_ASSERT_EQUAL_STRING("1", v);
  v = resp_value(text, dsl, "ErrorRecoveryLevel");
  TEST_ASSERT_NOT_NULL(v);
  TEST_ASSERT_EQUAL_STRING("0", v);
}

/* Verify the response data fits within bounds */
void test_login_resp_data_length(void) {
  uint32_t dsl = ((uint32_t)g_mock.resp[5] << 16) |
                 ((uint32_t)g_mock.resp[6] << 8) | g_mock.resp[7];
  TEST_ASSERT_LESS_OR_EQUAL_UINT32(4096, dsl);
  /* Must not exceed transport buffer in send_pdu */
  TEST_ASSERT_LESS_OR_EQUAL_UINT32(SNOWSCSI_ISCSI_MAX_DATA_SEGMENT, dsl);
}

/* ── Main ─────────────────────────────────────────────────────────── */

int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_login_resp_bhs_rfc);
  RUN_TEST(test_login_resp_no_skipped_keys);
  RUN_TEST(test_login_resp_has_required_keys);
  RUN_TEST(test_login_resp_echoes_all_keys);
  RUN_TEST(test_login_resp_data_length);
  return UNITY_END();
}
