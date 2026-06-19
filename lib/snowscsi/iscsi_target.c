#include "device_internal.h"

#include <snowscsi/device.h>
#include <snowscsi/iscsi.h>
#include <snowscsi/scsi.h>

#define SNOWLOG_TAG "iscsi"
#include "snowlog.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LOGIN_RESP_MAX 4096

/* ── Login parameter negotiation ─────────────────────────────────── */

typedef struct {
  const char *key;
  const char *value; /* NULL = accept initiator value */
  bool always;       /* output this key even if initiator didn't send it */
} login_param_t;

static const login_param_t LOGIN_TABLE[] = {
    {"TargetAlias", "SnowSCSI", true},
    {"AuthMethod", "None", false},
    {"HeaderDigest", "None", false},
    {"DataDigest", "None", false},
    {"InitialR2T", NULL, false},
    {"ImmediateData", "Yes", false},
    {"MaxBurstLength", NULL, false},
    {"FirstBurstLength", NULL, false},
    {"MaxRecvDataSegmentLength", NULL, false},
    {"MaxOutstandingR2T", "1", false},
    {"ErrorRecoveryLevel", "0", false},
    {"MaxConnections", "1", false},
    {"TargetPortalGroupTag", "1", true},
    {"DataPDUInOrder", NULL, false},
    {"DataSequenceInOrder", NULL, false},
    {"DefaultTime2Wait", NULL, false},
    {"DefaultTime2Retain", NULL, false},
    {"IFMarker", NULL, false},
    {"OFMarker", NULL, false},
};

enum { LOGIN_TABLE_SIZE = sizeof(LOGIN_TABLE) / sizeof(LOGIN_TABLE[0]) };

static bool is_skip_key(const char *key) {
  static const char *list[] = {"InitiatorName", "InitiatorAlias", "SessionType",
                               "TargetName", NULL};
  for (int i = 0; list[i]; i++)
    if (strcmp(key, list[i]) == 0)
      return true;
  return false;
}

static int login_find_key(const char *key) {
  for (int i = 0; i < (int)LOGIN_TABLE_SIZE; i++)
    if (strcmp(key, LOGIN_TABLE[i].key) == 0)
      return i;
  return -1;
}

static char *login_build_resp(const uint8_t *idata, uint32_t ilen,
                              uint32_t *out_len) {
  char *buf = malloc(LOGIN_RESP_MAX);
  if (!buf)
    return NULL;

  uint32_t w = 0;

#define APPEND_KV(k, v)                                                        \
  do {                                                                         \
    size_t kl = strlen(k), vl = strlen(v);                                     \
    if (w + kl + 1 + vl + 1 <= LOGIN_RESP_MAX) {                               \
      memcpy(buf + w, k, kl);                                                  \
      w += (uint32_t)kl;                                                       \
      buf[w++] = '=';                                                          \
      memcpy(buf + w, v, vl);                                                  \
      w += (uint32_t)vl;                                                       \
      buf[w++] = '\0';                                                         \
    }                                                                          \
  } while (0)

  bool sent[LOGIN_TABLE_SIZE];
  memset(sent, 0, sizeof(sent));

  const uint8_t *p = idata;
  const uint8_t *end = idata + ilen;
  while (p < end) {
    const uint8_t *eq = (const uint8_t *)memchr(p, '=', (size_t)(end - p));
    if (!eq)
      break;
    const uint8_t *nul =
        (const uint8_t *)memchr(eq + 1, '\0', (size_t)(end - eq - 1));
    if (!nul) {
      nul = end;
    }

    size_t klen = (size_t)(eq - p);
    size_t vlen = (size_t)(nul - eq - 1);

    char *k = (char *)malloc(klen + 1);
    char *v = (char *)malloc(vlen + 1);
    if (!k || !v) {
      free(k);
      free(v);
      break;
    }
    memcpy(k, p, klen);
    k[klen] = '\0';
    memcpy(v, eq + 1, vlen);
    v[vlen] = '\0';

    int idx = login_find_key(k);
    if (idx >= 0) {
      sent[idx] = true;
      const char *usev = LOGIN_TABLE[idx].value;
      if (usev == NULL) {
        APPEND_KV(k, v);
      } else {
        APPEND_KV(k, usev);
      }
    } else if (!is_skip_key(k)) {
      APPEND_KV(k, "Reject");
    }

    free(k);
    free(v);

    p = nul + 1;
    if (nul == end)
      break;
  }

  for (int i = 0; i < (int)LOGIN_TABLE_SIZE; i++) {
    if (LOGIN_TABLE[i].always && !sent[i])
      APPEND_KV(LOGIN_TABLE[i].key, LOGIN_TABLE[i].value);
  }

  *out_len = w;
  return buf;
}

/* ── I/O helpers ────────────────────────────────────────────────── */

static int t_recv(const snowscsi_transport_ops_t *t, void *ctx, intptr_t conn,
                  void *buf, size_t len) {
  return t->recv(ctx, conn, buf, len);
}

static int t_send(const snowscsi_transport_ops_t *t, void *ctx, intptr_t conn,
                  const void *buf, size_t len) {
  return t->send(ctx, conn, buf, len);
}

/* ── log BHS at verbose level ───────────────────────────────────── */

static void log_bhs(const char *dir, const uint8_t bhs[48]) {
  uint8_t op = snowscsi_iscsi_bhs_get_opcode(bhs);
  uint8_t flags = bhs[1];
  uint8_t ahs = bhs[4];
  uint32_t dsl = snowscsi_iscsi_bhs_get_data_seg_len(bhs);
  uint8_t lun = snowscsi_iscsi_bhs_get_lun(bhs);
  uint32_t itt = snowscsi_iscsi_bhs_get_itt(bhs);

  /* Format opcode-specific 28 bytes (bhs[20..47]) as hex */
  char spec[28 * 3 + 1];
  for (int i = 0; i < 28; i++) {
    uint8_t b = bhs[20 + i];
    spec[i * 3] = "0123456789abcdef"[b >> 4];
    spec[i * 3 + 1] = "0123456789abcdef"[b & 0xF];
    spec[i * 3 + 2] = ' ';
  }
  spec[28 * 3 - 1] = '\0';

  SNOW_LOGV(
      "%s op=%s(0x%02x) flags=0x%02x ahs=%u dsl=%u lun=%u itt=0x%04x spec=%s",
      dir, snowscsi_iscsi_opcode_name(op), op, flags, ahs, dsl, lun, itt, spec);
}

/* ── receive BHS + discard any DataSegment ──────────────────────── */

static int recv_bhs(const snowscsi_transport_ops_t *t, void *ctx, intptr_t conn,
                    uint8_t bhs[48]) {
  int r = t_recv(t, ctx, conn, bhs, 48);
  if (r < 0)
    return -1;
  log_bhs("RX", bhs);

  /* Discard DataSegment (we never expect or parse initiator data
   * besides the CDB in the SCSI Command BHS) */
  uint32_t dsl = snowscsi_iscsi_bhs_get_data_seg_len(bhs);
  if (dsl > 0) {
    uint8_t discard[8192];
    uint32_t remain = dsl;
    while (remain > 0) {
      uint32_t chunk =
          remain > sizeof(discard) ? (uint32_t)sizeof(discard) : remain;
      if (t_recv(t, ctx, conn, discard, chunk) < 0)
        return -1;
      remain -= chunk;
    }
  }

  /* Consume PDU padding to 4-byte boundary (RFC 3720 §3.1) */
  uint32_t pdu_len = 48 + dsl;
  uint32_t pad = (4 - (pdu_len & 3)) & 3;
  if (pad > 0) {
    uint8_t junk[4];
    if (t_recv(t, ctx, conn, junk, pad) < 0)
      return -1;
  }

  return 0;
}

/* ── send BHS + optional DataSegment ────────────────────────────── */

static int send_pdu(const snowscsi_transport_ops_t *t, void *ctx, intptr_t conn,
                    const uint8_t bhs[48], const void *data,
                    uint32_t data_len) {
  /* Assemble complete PDU in a single buffer (BHS + data + padding)
   * to avoid TCP framing issues from multiple send calls. */
  uint32_t total = 48 + data_len;
  uint32_t pad = (4 - (total & 3)) & 3;
  uint32_t buf_len = total + pad;
  uint8_t buf[48 + SNOWSCSI_ISCSI_MAX_DATA_SEGMENT + 3];
  if (buf_len > sizeof(buf))
    return -1;

  log_bhs("TX", bhs);
  memcpy(buf, bhs, 48);
  if (data_len > 0)
    memcpy(buf + 48, data, data_len);
  if (pad > 0)
    memset(buf + total, 0, pad);

  return t_send(t, ctx, conn, buf, buf_len);
}

/* ── Build sense data (18 bytes, fixed format) ──────────────────── */

static void build_sense_data(uint8_t *buf, const snowscsi_sense_t *s) {
  memset(buf, 0, 18);
  buf[0] = 0x70;
  buf[2] = (uint8_t)(s->key & 0x0F);
  buf[7] = 10;
  buf[12] = s->asc;
  buf[13] = s->ascq;
}

/* ── Send SCSI Response PDU ─────────────────────────────────────── */

static int send_scsi_response(const snowscsi_transport_ops_t *t, void *ctx,
                              intptr_t conn, uint32_t itt, uint32_t *stat_sn,
                              uint32_t *cmd_sn, uint8_t scsi_status,
                              const snowscsi_sense_t *sense) {
  uint8_t bhs[48];
  memset(bhs, 0, 48);

  snowscsi_iscsi_bhs_set_opcode(bhs, SNOWSCSI_ISCSI_OP_SCSI_RESP);
  snowscsi_iscsi_bhs_set_itt(bhs, itt);
  bhs[1] |= 0x80; /* libiscsi requires F bit set on SCSI Response */

  uint32_t exp_cmd_sn = *cmd_sn + 1;
  snowscsi_iscsi_bhs_resp_set_exp_cmd_sn(bhs, exp_cmd_sn);
  snowscsi_iscsi_bhs_resp_set_max_cmd_sn(bhs, exp_cmd_sn);
  snowscsi_iscsi_bhs_resp_set_stat_sn(bhs, *stat_sn);
  snowscsi_iscsi_bhs_set_status(bhs, scsi_status);

  uint8_t sense_buf[18];
  uint32_t data_len = 0;
  if (scsi_status == SNOWSCSI_ISCSI_SCSI_STATUS_CHECK_CONDITION && sense) {
    build_sense_data(sense_buf, sense);
    data_len = 18;
  }

  snowscsi_iscsi_bhs_set_data_seg_len(bhs, data_len);

  if (send_pdu(t, ctx, conn, bhs, sense_buf, data_len) < 0)
    return -1;

  *cmd_sn = exp_cmd_sn;
  (*stat_sn)++;
  return 0;
}

/* ── Send Data-In PDU ───────────────────────────────────────────── */

static int send_data_in(const snowscsi_transport_ops_t *t, void *ctx,
                        intptr_t conn, uint32_t itt, const uint8_t *data,
                        uint32_t data_len, uint32_t data_sn, bool final,
                        bool with_status, uint32_t stat_sn,
                        uint32_t exp_cmd_sn) {
  uint8_t bhs[48];
  memset(bhs, 0, 48);

  snowscsi_iscsi_bhs_set_opcode(bhs, SNOWSCSI_ISCSI_OP_SCSI_DATA_IN);
  snowscsi_iscsi_bhs_set_itt(bhs, itt);
  snowscsi_iscsi_bhs_set_data_sn(bhs, data_sn);
  snowscsi_iscsi_bhs_set_data_seg_len(bhs, data_len);

  if (final)
    bhs[1] |= SNOWSCSI_ISCSI_FLAG_DATA_FINAL;
  if (with_status) {
    bhs[1] |= SNOWSCSI_ISCSI_FLAG_DATA_STATUS;
    snowscsi_iscsi_bhs_set_status(bhs, SNOWSCSI_ISCSI_SCSI_STATUS_GOOD);
    /* Data-In with S=1: StatSN=36-39, ExpCmdSN=40-43, MaxCmdSN=44-47 */
    snowscsi_iscsi_bhs_data_in_set_stat_sn(bhs, stat_sn);
    snowscsi_iscsi_bhs_data_in_set_exp_cmd_sn(bhs, exp_cmd_sn);
    snowscsi_iscsi_bhs_data_in_set_max_cmd_sn(bhs, exp_cmd_sn);
  }

  return send_pdu(t, ctx, conn, bhs, data, data_len);
}

/* ── Send R2T PDU ───────────────────────────────────────────────── */

static int send_r2t(const snowscsi_transport_ops_t *t, void *ctx, intptr_t conn,
                    uint32_t itt, uint32_t ttt, uint32_t stat_sn,
                    uint32_t exp_cmd_sn, uint32_t buffer_offset,
                    uint32_t desired_len) {
  uint8_t bhs[48];
  memset(bhs, 0, 48);

  snowscsi_iscsi_bhs_set_opcode(bhs, SNOWSCSI_ISCSI_OP_R2T);
  snowscsi_iscsi_bhs_set_itt(bhs, itt);
  snowscsi_iscsi_bhs_set_ttt(bhs, ttt);
  snowscsi_iscsi_bhs_notify_set_stat_sn(bhs, stat_sn);
  snowscsi_iscsi_bhs_notify_set_exp_cmd_sn(bhs, exp_cmd_sn);
  snowscsi_iscsi_bhs_notify_set_max_cmd_sn(bhs, exp_cmd_sn);
  snowscsi_iscsi_bhs_r2t_set_r2tsn(bhs, ttt); /* R2TSN = TTT for simplicity */
  snowscsi_iscsi_bhs_set_r2t_buffer_offset(bhs, buffer_offset);
  snowscsi_iscsi_bhs_set_desired_data_len(bhs, desired_len);

  return send_pdu(t, ctx, conn, bhs, NULL, 0);
}

/* ── Send Reject PDU ────────────────────────────────────────────── */

static int send_reject(const snowscsi_transport_ops_t *t, void *ctx,
                       intptr_t conn, uint8_t reason, uint32_t stat_sn,
                       uint32_t exp_cmd_sn) {
  uint8_t bhs[48];
  memset(bhs, 0, 48);

  snowscsi_iscsi_bhs_set_opcode(bhs, SNOWSCSI_ISCSI_OP_REJECT);
  snowscsi_iscsi_bhs_set_reject_reason(bhs, reason);
  snowscsi_iscsi_bhs_notify_set_stat_sn(bhs, stat_sn);
  snowscsi_iscsi_bhs_notify_set_exp_cmd_sn(bhs, exp_cmd_sn);
  snowscsi_iscsi_bhs_notify_set_max_cmd_sn(bhs, exp_cmd_sn);

  return send_pdu(t, ctx, conn, bhs, NULL, 0);
}

/* ── Send NOP-In PDU ────────────────────────────────────────────── */

static int send_nop_in(const snowscsi_transport_ops_t *t, void *ctx,
                       intptr_t conn, uint32_t itt, uint32_t ttt,
                       uint32_t stat_sn, uint32_t exp_cmd_sn) {
  uint8_t bhs[48];
  memset(bhs, 0, 48);

  snowscsi_iscsi_bhs_set_opcode(bhs, SNOWSCSI_ISCSI_OP_NOP_IN);
  snowscsi_iscsi_bhs_set_itt(bhs, itt);
  snowscsi_iscsi_bhs_set_ttt(bhs, ttt);
  snowscsi_iscsi_bhs_notify_set_stat_sn(bhs, stat_sn);
  snowscsi_iscsi_bhs_notify_set_exp_cmd_sn(bhs, exp_cmd_sn);
  snowscsi_iscsi_bhs_notify_set_max_cmd_sn(bhs, exp_cmd_sn);

  return send_pdu(t, ctx, conn, bhs, NULL, 0);
}

/* ── Login handshake ────────────────────────────────────────────── */

static int do_login(const snowscsi_transport_ops_t *t, void *ctx, intptr_t conn,
                    uint32_t *out_cmd_sn, uint32_t *out_stat_sn) {
  uint8_t bhs[48];

  /* Receive Login Request */
  if (t_recv(t, ctx, conn, bhs, 48) < 0)
    return -1;

  uint8_t op = snowscsi_iscsi_bhs_get_opcode(bhs);
  uint32_t dsl = snowscsi_iscsi_bhs_get_data_seg_len(bhs);
  SNOW_LOGD("do_login: op=0x%02x dsl=%u", op, dsl);
  SNOW_LOGD("  ver-max=%u ver-min=%u", bhs[2], bhs[3]);
  SNOW_LOGD("  ISID=%02x%02x%02x%02x%02x%02x", bhs[8], bhs[9], bhs[10], bhs[11],
            bhs[12], bhs[13]);
  SNOW_LOGD("  TSIH=%u ITT=0x%08x CID=0x%08x CmdSN=%u ExpStatSN=%u",
            ((uint32_t)bhs[16] << 24) | ((uint32_t)bhs[17] << 16) |
                ((uint32_t)bhs[18] << 8) | (uint32_t)bhs[19],
            ((uint32_t)bhs[20] << 24) | ((uint32_t)bhs[21] << 16) |
                ((uint32_t)bhs[22] << 8) | (uint32_t)bhs[23],
            ((uint32_t)bhs[24] << 24) | ((uint32_t)bhs[25] << 16) |
                ((uint32_t)bhs[26] << 8) | (uint32_t)bhs[27],
            ((uint32_t)bhs[28] << 24) | ((uint32_t)bhs[29] << 16) |
                ((uint32_t)bhs[30] << 8) | (uint32_t)bhs[31],
            ((uint32_t)bhs[32] << 24) | ((uint32_t)bhs[33] << 16) |
                ((uint32_t)bhs[34] << 8) | (uint32_t)bhs[35]);
  SNOW_LOGD("  T=%d CSG=%u NSG=%u", snowscsi_iscsi_bhs_get_t_bit(bhs),
            snowscsi_iscsi_bhs_get_csg(bhs), snowscsi_iscsi_bhs_get_nsg(bhs));
  if (op != SNOWSCSI_ISCSI_OP_LOGIN_REQ)
    return -1;

  /* Read initiator DataSegment for parameter negotiation */
  uint8_t *idata = NULL;
  if (dsl > 0 && dsl <= LOGIN_RESP_MAX) {
    idata = malloc(dsl);
    if (idata) {
      if (t_recv(t, ctx, conn, idata, dsl) < 0) {
        free(idata);
        return -1;
      }
      if (snowlog_get_level() >= SNOWLOG_DEBUG)
        for (uint32_t i = 0; i < dsl; i++)
          if (idata[i] == '\0')
            fputc('\n', stderr);
          else
            fputc(idata[i], stderr);
    }
  }
  SNOW_LOGD("--- end params ---");

  /* Discard PDU padding (RFC 3720 §3.1: pad to 4-byte boundary) */
  uint32_t pdu_len = 48 + dsl;
  uint32_t pad = (4 - (pdu_len & 3)) & 3;
  if (pad > 0) {
    uint8_t junk[4];
    t_recv(t, ctx, conn, junk, pad);
  }

  uint32_t resp_len = 0;
  char *resp =
      login_build_resp(idata ? idata : (const uint8_t *)"", dsl, &resp_len);
  free(idata);
  if (!resp)
    return -1;

  /* Pad response data to 4-byte boundary so no PDU padding remains.
   * This avoids a common iSCSI interop issue where the client reads
   * DataSegmentLength bytes but leaves padding in the socket buffer,
   * corrupting all subsequent PDU reads. */
  uint32_t pdu_total = 48 + resp_len;
  uint32_t resp_pad = (4 - (pdu_total & 3)) & 3;
  if (resp_pad > 0) {
    memset(resp + resp_len, 0, resp_pad);
    resp_len += resp_pad;
  }

  if (snowlog_get_level() >= SNOWLOG_DEBUG) {
    fprintf(stderr, "[D][iscsi] do_login: resp params (len=%u):\n", resp_len);
    for (uint32_t i = 0; i < resp_len; i++)
      if (resp[i] == '\0')
        fputc('\n', stderr);
      else
        fputc(resp[i], stderr);
    fprintf(stderr, "[D][iscsi] --- end resp ---\n");
  }

  uint8_t req_csg = snowscsi_iscsi_bhs_get_csg(bhs);
  uint8_t req_nsg = snowscsi_iscsi_bhs_get_nsg(bhs);
  SNOW_LOGD("do_login: req_csg=%u req_nsg=%u", req_csg, req_nsg);

  uint32_t itt = snowscsi_iscsi_bhs_get_itt(bhs);

  /* Save CmdSN before memset overwrites bhs (Bug 1 fix) */
  uint32_t login_cmd_sn = snowscsi_iscsi_bhs_get_cmd_sn(bhs);

  uint8_t isid[6];
  memcpy(isid, &bhs[8], 6);
  uint8_t tsih[2];
  memcpy(tsih, &bhs[14], 2);
  uint16_t cid = ((uint16_t)bhs[22] << 8) | bhs[23];

  memset(bhs, 0, 48);
  memcpy(&bhs[8], isid, 6);
  memcpy(&bhs[14], tsih, 2);
  bhs[2] = 0; /* Version-max (RFC 3720 §10.12.4) */
  bhs[3] = 0; /* Version-active */

  snowscsi_iscsi_bhs_set_opcode(bhs, SNOWSCSI_ISCSI_OP_LOGIN_RESP);
  snowscsi_iscsi_bhs_set_t_bit(bhs, true);

  bhs[1] |= (uint8_t)(((req_csg & 0x03) << SNOWSCSI_ISCSI_FLAG_CSG_SHIFT) |
                      (SNOWSCSI_ISCSI_STAGE_FULL_FEATURE
                       << SNOWSCSI_ISCSI_FLAG_NSG_SHIFT));

  snowscsi_iscsi_bhs_set_itt(bhs, itt);
  bhs[22] = (uint8_t)(cid >> 8);
  bhs[23] = (uint8_t)(cid & 0xFF);
  snowscsi_iscsi_bhs_set_data_seg_len(bhs, resp_len);
  /* ExpCmdSN = initial CmdSN from Login Request (first command uses same CmdSN)
   */
  snowscsi_iscsi_bhs_notify_set_stat_sn(bhs, 0);
  snowscsi_iscsi_bhs_notify_set_exp_cmd_sn(bhs, login_cmd_sn);
  snowscsi_iscsi_bhs_notify_set_max_cmd_sn(bhs, login_cmd_sn);

  if (send_pdu(t, ctx, conn, bhs, resp, resp_len) < 0) {
    free(resp);
    return -1;
  }

  free(resp);

  SNOW_LOGI("do_login: sent Login Response, entering command loop");

  *out_cmd_sn = login_cmd_sn;
  *out_stat_sn = 1;
  return 0;
}

/* ── Handle DATA_IN (read from device to initiator) ─────────────── */

static int handle_data_in(const snowscsi_transport_ops_t *t, void *ctx,
                          intptr_t conn, snowscsi_device_t *dev, uint32_t itt,
                          uint32_t *stat_sn, uint32_t *cmd_sn) {
  /* Double-buffer to know when we're on the last chunk */
  uint8_t buf_a[SNOWSCSI_ISCSI_MAX_DATA_SEGMENT];
  uint8_t buf_b[SNOWSCSI_ISCSI_MAX_DATA_SEGMENT];
  uint8_t *cur = buf_a;
  uint8_t *next = buf_b;
  uint32_t cur_len, next_len;
  uint32_t data_sn = 0;
  int n;

  n = snowscsi_read_data(dev, cur, sizeof(buf_a));
  if (n <= 0) {
    /* No data at all — send final/status Data-In with zero payload */
    uint32_t exp = *cmd_sn + 1;
    if (send_data_in(t, ctx, conn, itt, NULL, 0, data_sn, true, true, *stat_sn,
                     exp) < 0)
      return -1;
    *cmd_sn = exp;
    (*stat_sn)++;
    return 0;
  }
  cur_len = (uint32_t)n;

  while (1) {
    n = snowscsi_read_data(dev, next, sizeof(buf_b));
    if (n <= 0) {
      /* cur is the last chunk — send with F=1, S=1 */
      uint32_t exp = *cmd_sn + 1;
      if (send_data_in(t, ctx, conn, itt, cur, cur_len, data_sn, true, true,
                       *stat_sn, exp) < 0)
        return -1;
      data_sn++;
      *cmd_sn = exp;
      (*stat_sn)++;
      break;
    }
    next_len = (uint32_t)n;

    /* cur is not final — send with F=0, S=0 */
    uint32_t exp = *cmd_sn + 1;
    if (send_data_in(t, ctx, conn, itt, cur, cur_len, data_sn, false, false,
                     *stat_sn, exp) < 0)
      return -1;
    data_sn++;

    /* Swap buffers */
    uint8_t *tmp = cur;
    cur = next;
    next = tmp;
    cur_len = next_len;
  }

  return 0;
}

/* ── Handle DATA_OUT (write from initiator to device) ───────────── */

static int handle_data_out(const snowscsi_transport_ops_t *t, void *ctx,
                           intptr_t conn, snowscsi_device_t *dev, uint32_t itt,
                           uint32_t *stat_sn, uint32_t *cmd_sn,
                           uint32_t transfer_len) {
  uint8_t bhs[48];
  uint8_t data_buf[SNOWSCSI_ISCSI_MAX_DATA_SEGMENT];

  /* Send R2T for the full transfer */
  if (send_r2t(t, ctx, conn, itt, 1, *stat_sn, *cmd_sn + 1, 0, transfer_len) <
      0)
    return -1;

  /* Receive Data-Out PDUs until complete */
  while (1) {
    if (t_recv(t, ctx, conn, bhs, 48) < 0)
      return -1;

    uint8_t op = snowscsi_iscsi_bhs_get_opcode(bhs);
    if (op != SNOWSCSI_ISCSI_OP_SCSI_DATA_OUT) {
      SNOW_LOGW("handle_data_out: expected SCSI_DATA_OUT, got %s(0x%02x)",
                snowscsi_iscsi_opcode_name(op), op);
      send_reject(t, ctx, conn, SNOWSCSI_ISCSI_REJECT_FORMAT_ERROR, *stat_sn,
                  *cmd_sn + 1);
      return -1;
    }

    uint32_t dsl = snowscsi_iscsi_bhs_get_data_seg_len(bhs);
    if (dsl > 0) {
      if (dsl > sizeof(data_buf))
        return -1;
      if (t_recv(t, ctx, conn, data_buf, dsl) < 0)
        return -1;
    }

    int done = snowscsi_write_data(dev, dsl > 0 ? data_buf : NULL, dsl);
    if (done < 0) {
      /* Write error — sense already set in dev */
      snowscsi_sense_t sense;
      snowscsi_device_get_sense(dev, &sense);
      return send_scsi_response(t, ctx, conn, itt, stat_sn, cmd_sn,
                                SNOWSCSI_ISCSI_SCSI_STATUS_CHECK_CONDITION,
                                &sense);
    }
    if (done == 1) {
      /* All data received — send GOOD response */
      return send_scsi_response(t, ctx, conn, itt, stat_sn, cmd_sn,
                                SNOWSCSI_ISCSI_SCSI_STATUS_GOOD, NULL);
    }
  }
}

/* ── Handle SCSI Command ────────────────────────────────────────── */

static int handle_scsi_cmd(const snowscsi_transport_ops_t *t, void *ctx,
                           intptr_t conn, const uint8_t bhs[48],
                           snowscsi_device_t **devs, int num_devs,
                           uint32_t *stat_sn, uint32_t *cmd_sn) {
  uint8_t lun = snowscsi_iscsi_bhs_get_lun(bhs);
  uint32_t itt = snowscsi_iscsi_bhs_get_itt(bhs);
  uint8_t cdb[16];
  uint8_t cdb_len;
  snowscsi_iscsi_bhs_get_cdb(bhs, cdb, &cdb_len);
  uint8_t opcode = cdb_len > 0 ? cdb[0] : 0;

  if (lun >= (uint8_t)num_devs) {
    SNOW_LOGW("invalid LUN %u for opcode=0x%02x itt=0x%x", lun, opcode, itt);
    return send_reject(t, ctx, conn, SNOWSCSI_ISCSI_REJECT_FORMAT_ERROR,
                       *stat_sn, *cmd_sn + 1);
  }

  snowscsi_device_t *dev = devs[lun];

  uint32_t transfer_len = 0;
  snowscsi_result_t r = snowscsi_do_cmd(dev, cdb, cdb_len, &transfer_len);

  SNOW_LOGD("scsi_cmd: %s(0x%02x) lun=%u itt=0x%x result=%s%s",
            snowscsi_cdb_opcode_name(opcode), opcode, lun, itt,
            r == SNOWSCSI_STATUS            ? "STATUS"
            : r == SNOWSCSI_DATA_IN         ? "DATA_IN"
            : r == SNOWSCSI_DATA_OUT        ? "DATA_OUT"
            : r == SNOWSCSI_CHECK_CONDITION ? "CHECK_CONDITION"
                                            : "UNKNOWN",
            r == SNOWSCSI_CHECK_CONDITION ? " (see block log for sense)" : "");

  switch (r) {
  case SNOWSCSI_STATUS:
    return send_scsi_response(t, ctx, conn, itt, stat_sn, cmd_sn,
                              SNOWSCSI_ISCSI_SCSI_STATUS_GOOD, NULL);

  case SNOWSCSI_CHECK_CONDITION: {
    snowscsi_sense_t sense;
    snowscsi_device_get_sense(dev, &sense);
    return send_scsi_response(t, ctx, conn, itt, stat_sn, cmd_sn,
                              SNOWSCSI_ISCSI_SCSI_STATUS_CHECK_CONDITION,
                              &sense);
  }

  case SNOWSCSI_DATA_IN:
    SNOW_LOGV("scsi_cmd: DATA_IN transfer_len=%u", transfer_len);
    return handle_data_in(t, ctx, conn, dev, itt, stat_sn, cmd_sn);

  case SNOWSCSI_DATA_OUT:
    SNOW_LOGV("scsi_cmd: DATA_OUT transfer_len=%u", transfer_len);
    return handle_data_out(t, ctx, conn, dev, itt, stat_sn, cmd_sn,
                           transfer_len);
  }

  return -1;
}

/* ── iSCSI Target main serve loop ───────────────────────────────── */

int snowscsi_iscsi_serve(snowscsi_device_t **devs, int num_devs,
                         const char *addr,
                         const snowscsi_transport_ops_t *transport_ops,
                         void *transport_ctx) {
  if (!devs || num_devs <= 0 || !addr)
    return -1;

  const snowscsi_transport_ops_t *t = transport_ops;
  if (!t)
    t = &SNOWSCSI_TRANSPORT_BSD;

  /* Parse host:port */
  const char *colon = strrchr(addr, ':');
  if (!colon)
    return -1;

  char host[256];
  size_t hlen = (size_t)(colon - addr);
  if (hlen >= sizeof(host))
    return -1;
  memcpy(host, addr, hlen);
  host[hlen] = '\0';

  char *endp = NULL;
  long p = strtol(colon + 1, &endp, 10);
  if (p <= 0 || p > 65535 || *endp != '\0')
    return -1;
  uint16_t port = (uint16_t)p;

  /* Listen */
  intptr_t listener = t->listen(transport_ctx, addr, port);
  if (listener < 0) {
    SNOW_LOGE("iSCSI: failed to listen on %s:%u", host, port);
    return -1;
  }

  SNOW_LOGI("iSCSI target listening on %s:%u", host, port);

  while (1) {
    intptr_t conn = t->accept(transport_ctx, listener);
    if (conn < 0) {
      SNOW_LOGW("iSCSI: accept failed, retrying");
      continue;
    }

    /* Login */
    uint32_t cmd_sn = 0, stat_sn = 0;
    if (do_login(t, transport_ctx, conn, &cmd_sn, &stat_sn) < 0) {
      SNOW_LOGW("iSCSI: login failed, disconnecting");
      t->disconnect(transport_ctx, conn);
      continue;
    }

    /* Command loop */
    int running = 1;
    SNOW_LOGI("cmd_loop: waiting for first PDU");
    while (running) {
      uint8_t bhs[48];

      if (recv_bhs(t, transport_ctx, conn, bhs) < 0) {
        SNOW_LOGW("cmd_loop: recv_bhs failed, disconnecting");
        running = 0;
        break;
      }

      uint8_t op = snowscsi_iscsi_bhs_get_opcode(bhs);

      switch (op) {

      case SNOWSCSI_ISCSI_OP_SCSI_CMD: {
        /* Validate CmdSN — accept any command >= expected (RFC 7143 §3.2.2.1)
         */
        uint32_t recv_cmd_sn = snowscsi_iscsi_bhs_get_cmd_sn(bhs);
        if ((int32_t)(recv_cmd_sn - cmd_sn) < 0) {
          send_reject(t, transport_ctx, conn, SNOWSCSI_ISCSI_REJECT_CMD_SN,
                      stat_sn, cmd_sn + 1);
          break;
        }

        /* Advance cmd_sn so responses use the correct ExpCmdSN */
        cmd_sn = recv_cmd_sn;

        if (handle_scsi_cmd(t, transport_ctx, conn, bhs, devs, num_devs,
                            &stat_sn, &cmd_sn) < 0) {
          running = 0;
        }
        break;
      }

      case SNOWSCSI_ISCSI_OP_NOP_OUT: {
        uint32_t itt = snowscsi_iscsi_bhs_get_itt(bhs);
        uint32_t ttt = snowscsi_iscsi_bhs_get_ttt(bhs);
        if (send_nop_in(t, transport_ctx, conn, itt, ttt, stat_sn, cmd_sn + 1) <
            0)
          running = 0;
        break;
      }

      case SNOWSCSI_ISCSI_OP_LOGOUT_REQ: {
        uint32_t itt = snowscsi_iscsi_bhs_get_itt(bhs);
        uint8_t lbhs[48];
        memset(lbhs, 0, 48);
        snowscsi_iscsi_bhs_set_opcode(lbhs, SNOWSCSI_ISCSI_OP_LOGOUT_RESP);
        snowscsi_iscsi_bhs_set_itt(lbhs, itt);
        lbhs[1] = 0x80; /* response PDU flag */
        snowscsi_iscsi_bhs_resp_set_stat_sn(lbhs, stat_sn);
        snowscsi_iscsi_bhs_resp_set_exp_cmd_sn(lbhs, cmd_sn + 1);
        snowscsi_iscsi_bhs_resp_set_max_cmd_sn(lbhs, cmd_sn + 1);
        send_pdu(t, transport_ctx, conn, lbhs, NULL, 0);
        stat_sn++;
        running = 0;
        break;
      }

      case SNOWSCSI_ISCSI_OP_LOGIN_REQ: {
        /* recv_bhs() already consumed BHS + DataSegment + padding,
         * only a minimal Login Response needs to be sent. */
        uint32_t itt = snowscsi_iscsi_bhs_get_itt(bhs);
        uint8_t req_csg = snowscsi_iscsi_bhs_get_csg(bhs);
        uint8_t lbhs[48];
        memset(lbhs, 0, 48);
        lbhs[2] = 0; /* Version-max (RFC 3720 §10.12.4) */
        lbhs[3] = 0; /* Version-active */
        snowscsi_iscsi_bhs_set_opcode(lbhs, SNOWSCSI_ISCSI_OP_LOGIN_RESP);
        snowscsi_iscsi_bhs_set_t_bit(lbhs, true);
        lbhs[1] |=
            (uint8_t)(((req_csg & 0x03) << SNOWSCSI_ISCSI_FLAG_CSG_SHIFT) |
                      (SNOWSCSI_ISCSI_STAGE_FULL_FEATURE
                       << SNOWSCSI_ISCSI_FLAG_NSG_SHIFT));
        snowscsi_iscsi_bhs_set_itt(lbhs, itt);
        snowscsi_iscsi_bhs_notify_set_stat_sn(lbhs, stat_sn);
        snowscsi_iscsi_bhs_notify_set_exp_cmd_sn(lbhs, cmd_sn);
        snowscsi_iscsi_bhs_notify_set_max_cmd_sn(lbhs, cmd_sn);
        send_pdu(t, transport_ctx, conn, lbhs, NULL, 0);
        stat_sn++;
        break;
      }

      default:
        SNOW_LOGW("unexpected iSCSI PDU opcode=%s(0x%02x)",
                  snowscsi_iscsi_opcode_name(op), op);
        send_reject(t, transport_ctx, conn, SNOWSCSI_ISCSI_REJECT_FORMAT_ERROR,
                    stat_sn, cmd_sn + 1);
        break;
      }
    }

    t->disconnect(transport_ctx, conn);
  }

  t->stop(transport_ctx, listener);
  return 0;
}
