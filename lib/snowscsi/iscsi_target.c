#include "device_internal.h"

#include <snowscsi/device.h>
#include <snowscsi/iscsi.h>
#include <snowscsi/scsi.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── Fixed login negotiation parameters ───────────────────────────
 *  We do not parse initiator keys; we always respond with this fixed
 *  set. The initiator MUST accept them.
 *  Each key=value pair is null-terminated.                               */

static const char LOGIN_PARAMS[] =
    "TargetName=iqn.2025-01.local.snowscsi:target\0"
    "TargetAlias=SnowSCSI\0"
    "MaxConnections=1\0"
    "InitialR2T=Yes\0"
    "ImmediateData=Yes\0"
    "MaxRecvDataSegmentLength=8192\0"
    "MaxBurstLength=262144\0"
    "FirstBurstLength=65536\0"
    "MaxOutstandingR2T=1\0"
    "ErrorRecoveryLevel=0\0"
    "TargetPortalGroupTag=1\0";

static const uint32_t LOGIN_PARAMS_LEN = sizeof(LOGIN_PARAMS) - 1;

/* ── I/O helpers ────────────────────────────────────────────────── */

static int t_recv(const snowscsi_transport_ops_t *t, void *ctx, intptr_t conn,
                  void *buf, size_t len) {
  return t->recv(ctx, conn, buf, len);
}

static int t_send(const snowscsi_transport_ops_t *t, void *ctx, intptr_t conn,
                  const void *buf, size_t len) {
  return t->send(ctx, conn, buf, len);
}

/* ── receive BHS + discard any DataSegment ──────────────────────── */

static int recv_bhs(const snowscsi_transport_ops_t *t, void *ctx, intptr_t conn,
                    uint8_t bhs[48]) {
  int r = t_recv(t, ctx, conn, bhs, 48);
  if (r < 0)
    return -1;

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
  return 0;
}

/* ── send BHS + optional DataSegment ────────────────────────────── */

static int send_pdu(const snowscsi_transport_ops_t *t, void *ctx, intptr_t conn,
                    const uint8_t bhs[48], const void *data,
                    uint32_t data_len) {
  if (t_send(t, ctx, conn, bhs, 48) < 0)
    return -1;
  if (data_len > 0 && t_send(t, ctx, conn, data, data_len) < 0)
    return -1;
  return 0;
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

  uint32_t exp_cmd_sn = *cmd_sn + 1;
  snowscsi_iscsi_bhs_resp_set_exp_cmd_sn(bhs, exp_cmd_sn);
  snowscsi_iscsi_bhs_resp_set_max_cmd_sn(bhs, exp_cmd_sn);
  snowscsi_iscsi_bhs_resp_set_stat_sn(bhs, *stat_sn);
  snowscsi_iscsi_bhs_set_status(bhs, scsi_status);

  uint8_t sense_buf[18];
  uint32_t data_len = 0;
  if (scsi_status == SNOWSCSI_ISCSI_SCSI_STATUS_CHECK_CONDITION && sense) {
    build_sense_data(sense_buf, sense);
    snowscsi_iscsi_bhs_set_sense_len(bhs, 18);
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
    /* Data-In uses notify-style offsets: StatSN=24-27, ExpCmdSN=28-31,
     * MaxCmdSN=32-35 */
    snowscsi_iscsi_bhs_notify_set_stat_sn(bhs, stat_sn);
    snowscsi_iscsi_bhs_notify_set_exp_cmd_sn(bhs, exp_cmd_sn);
    snowscsi_iscsi_bhs_notify_set_max_cmd_sn(bhs, exp_cmd_sn);
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
  snowscsi_iscsi_bhs_set_desired_data_len(bhs, desired_len);
  snowscsi_iscsi_bhs_set_r2t_buffer_offset(bhs, buffer_offset);

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
  if (op != SNOWSCSI_ISCSI_OP_LOGIN_REQ)
    return -1;

  /* Discard DataSegment (we don't parse initiator keys) */
  uint32_t dsl = snowscsi_iscsi_bhs_get_data_seg_len(bhs);
  if (dsl > 0) {
    uint8_t *discard = malloc(dsl);
    if (discard) {
      t_recv(t, ctx, conn, discard, dsl);
      free(discard);
    }
  }

  uint8_t req_nsg = snowscsi_iscsi_bhs_get_nsg(bhs);
  uint32_t itt = snowscsi_iscsi_bhs_get_itt(bhs);

  /* Build Login Response — skip to Full Feature Phase (NSG=3) */
  memset(bhs, 0, 48);
  snowscsi_iscsi_bhs_set_opcode(bhs, SNOWSCSI_ISCSI_OP_LOGIN_RESP);
  snowscsi_iscsi_bhs_set_t_bit(bhs, true);

  /* CSG = nsg from request (accept their transition),
   * NSG = 3  (Full Feature Phase) */
  bhs[1] = (uint8_t)(((req_nsg & 0x03) << SNOWSCSI_ISCSI_FLAG_CSG_SHIFT) |
                     (SNOWSCSI_ISCSI_STAGE_FULL_FEATURE
                      << SNOWSCSI_ISCSI_FLAG_NSG_SHIFT));

  snowscsi_iscsi_bhs_set_itt(bhs, itt);
  snowscsi_iscsi_bhs_set_data_seg_len(bhs, LOGIN_PARAMS_LEN);
  snowscsi_iscsi_bhs_notify_set_stat_sn(bhs, 0);
  snowscsi_iscsi_bhs_notify_set_exp_cmd_sn(bhs, 0);
  snowscsi_iscsi_bhs_notify_set_max_cmd_sn(bhs, 0);

  if (send_pdu(t, ctx, conn, bhs, LOGIN_PARAMS, LOGIN_PARAMS_LEN) < 0)
    return -1;

  *out_cmd_sn = 0;
  *out_stat_sn = 1; /* next response uses StatSN=1 */
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
      /* Unexpected PDU during data phase */
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
  if (lun >= (uint8_t)num_devs) {
    /* Invalid LUN — just reject with format error */
    return send_reject(t, ctx, conn, SNOWSCSI_ISCSI_REJECT_FORMAT_ERROR,
                       *stat_sn, *cmd_sn + 1);
  }

  snowscsi_device_t *dev = devs[lun];
  uint32_t itt = snowscsi_iscsi_bhs_get_itt(bhs);
  uint8_t cdb[16];
  uint8_t cdb_len;
  snowscsi_iscsi_bhs_get_cdb(bhs, cdb, &cdb_len);

  uint32_t transfer_len = 0;
  snowscsi_result_t r = snowscsi_do_cmd(dev, cdb, cdb_len, &transfer_len);

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
    return handle_data_in(t, ctx, conn, dev, itt, stat_sn, cmd_sn);

  case SNOWSCSI_DATA_OUT:
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
    fprintf(stderr, "iSCSI: failed to listen on %s:%u\n", host, port);
    return -1;
  }

  fprintf(stderr, "iSCSI target listening on %s:%u\n", host, port);

  while (1) {
    intptr_t conn = t->accept(transport_ctx, listener);
    if (conn < 0) {
      fprintf(stderr, "iSCSI: accept failed\n");
      t->stop(transport_ctx, listener);
      return -1;
    }

    /* Login */
    uint32_t cmd_sn = 0, stat_sn = 0;
    if (do_login(t, transport_ctx, conn, &cmd_sn, &stat_sn) < 0) {
      t->disconnect(transport_ctx, conn);
      t->stop(transport_ctx, listener);
      return -1;
    }

    /* Command loop */
    int running = 1;
    while (running) {
      uint8_t bhs[48];

      if (recv_bhs(t, transport_ctx, conn, bhs) < 0) {
        running = 0;
        break;
      }

      uint8_t op = snowscsi_iscsi_bhs_get_opcode(bhs);

      switch (op) {

      case SNOWSCSI_ISCSI_OP_SCSI_CMD: {
        /* Validate CmdSN */
        uint32_t recv_cmd_sn = snowscsi_iscsi_bhs_get_cmd_sn(bhs);
        if (recv_cmd_sn != cmd_sn) {
          send_reject(t, transport_ctx, conn, SNOWSCSI_ISCSI_REJECT_CMD_SN,
                      stat_sn, cmd_sn + 1);
          break;
        }

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
        snowscsi_iscsi_bhs_resp_set_stat_sn(lbhs, stat_sn);
        snowscsi_iscsi_bhs_resp_set_exp_cmd_sn(lbhs, cmd_sn + 1);
        snowscsi_iscsi_bhs_resp_set_max_cmd_sn(lbhs, cmd_sn + 1);
        send_pdu(t, transport_ctx, conn, lbhs, NULL, 0);
        stat_sn++;
        running = 0;
        break;
      }

      case SNOWSCSI_ISCSI_OP_LOGIN_REQ:
        /* Initiator wants to re-login — just reply again */
        do_login(t, transport_ctx, conn, &cmd_sn, &stat_sn);
        break;

      default:
        /* Unknown/unsupported PDU */
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
