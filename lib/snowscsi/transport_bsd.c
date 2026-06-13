#include <snowscsi/iscsi.h>

#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/* ── Parse "host:port" string ──────────────────────────────────── */

static int parse_addr(const char *addr, char *host, size_t host_len,
                      uint16_t *port) {
  const char *colon = strrchr(addr, ':');
  if (!colon)
    return -1;

  size_t hlen = (size_t)(colon - addr);
  if (hlen >= host_len)
    return -1;
  memcpy(host, addr, hlen);
  host[hlen] = '\0';

  char *endp = NULL;
  long p = strtol(colon + 1, &endp, 10);
  if (p <= 0 || p > 65535 || *endp != '\0')
    return -1;
  *port = (uint16_t)p;
  return 0;
}

/* ── listen ─────────────────────────────────────────────────────── */

static intptr_t bsd_listen(void *ctx, const char *addr, uint16_t port) {
  (void)ctx;

  char host[256];
  int fd = -1;

  if (parse_addr(addr, host, sizeof(host), &port) != 0)
    return -1;

  struct addrinfo hints;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE;

  char port_str[8];
  snprintf(port_str, sizeof(port_str), "%u", port);

  struct addrinfo *res = NULL;
  if (getaddrinfo(host[0] ? host : NULL, port_str, &hints, &res) != 0)
    return -1;

  for (struct addrinfo *rp = res; rp; rp = rp->ai_next) {
    fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
    if (fd < 0)
      continue;

    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    if (bind(fd, rp->ai_addr, rp->ai_addrlen) == 0)
      break;

    close(fd);
    fd = -1;
  }

  freeaddrinfo(res);

  if (fd < 0)
    return -1;

  if (listen(fd, 1) < 0) {
    close(fd);
    return -1;
  }

  return fd;
}

/* ── accept ─────────────────────────────────────────────────────── */

static intptr_t bsd_accept(void *ctx, intptr_t listener) {
  (void)ctx;
  return accept((int)listener, NULL, NULL);
}

/* ── recv ───────────────────────────────────────────────────────── */

static int bsd_recv(void *ctx, intptr_t conn, void *buf, size_t len) {
  (void)ctx;

  size_t total = 0;
  uint8_t *p = (uint8_t *)buf;

  while (total < len) {
    ssize_t n = recv((int)conn, p + total, len - total, 0);
    if (n <= 0)
      return -1;
    total += (size_t)n;
  }

  return (int)total;
}

/* ── send ───────────────────────────────────────────────────────── */

static int bsd_send(void *ctx, intptr_t conn, const void *buf, size_t len) {
  (void)ctx;

  size_t total = 0;
  const uint8_t *p = (const uint8_t *)buf;

  while (total < len) {
    ssize_t n = send((int)conn, p + total, len - total, MSG_NOSIGNAL);
    if (n <= 0)
      return -1;
    total += (size_t)n;
  }

  return (int)total;
}

/* ── disconnect ─────────────────────────────────────────────────── */

static void bsd_disconnect(void *ctx, intptr_t conn) {
  (void)ctx;
  shutdown((int)conn, SHUT_RDWR);
  close((int)conn);
}

/* ── stop ───────────────────────────────────────────────────────── */

static void bsd_stop(void *ctx, intptr_t listener) {
  (void)ctx;
  close((int)listener);
}

/* ── Transport ops instance ─────────────────────────────────────── */

const snowscsi_transport_ops_t SNOWSCSI_TRANSPORT_BSD = {
    .listen = bsd_listen,
    .accept = bsd_accept,
    .recv = bsd_recv,
    .send = bsd_send,
    .disconnect = bsd_disconnect,
    .stop = bsd_stop,
};
