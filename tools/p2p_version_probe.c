/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * p2p_version_probe — one bounded P2P version handshake against a named
 * peer, reporting the start_height it advertises.
 *
 * Used by tools/scripts/cold_start_to_tip_stopwatch.sh as the PRE-FLIGHT peer
 * gate. A TCP connect proves only that something listens; this probe proves
 * the peer answers the P2P version exchange for the configured network magic.
 *
 * Wire exchange (client side only, read-only against the peer): send one
 * `version` message, then read framed messages until the peer's `version`
 * arrives (a peer may send other messages first, bounded at 8). No verack and
 * no further traffic; the socket is closed on exit.
 *
 * Usage: p2p_version_probe HOST PORT [BUDGET_SECS]      (default budget 12)
 *   env ZCL_CS_PEER_MAGIC  4-byte network magic as 8 lowercase hex characters
 *                          (default 24e92764, ZClassic mainnet;
 *                          core/chainparams/src/chainparams.c)
 * stdout (one line) and exit code:
 *   ok START_HEIGHT        rc 0  peer completed the version exchange
 *   peer_unreachable       rc 3  name resolution failed or connect was refused
 *   peer_no_handshake      rc 4  no valid version within the budget
 *                                (closed at once, silent, wrong magic, junk)
 *   usage                  rc 2
 */

#include "base/hex.h"
#include "base/serialize_le.h"
#include "crypto/sha256.h"
#include "platform/clock.h"
#include "platform/rng.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

enum {
    RC_OK = 0,
    RC_USAGE = 2,
    RC_UNREACHABLE = 3,
    RC_NO_HANDSHAKE = 4,
};

#define PROTOCOL_VERSION 170011u
#define DEFAULT_BUDGET_SECS 12u
#define DEFAULT_MAGIC_HEX "24e92764"
#define HEADER_LEN 24u
#define MAX_BODY_LEN 65536u
#define MAX_MESSAGES 8
#define VERSION_MIN_BODY 85u
#define VERSION_UA_LIMIT 253u
#define ADDR_LEN 26u
#define USER_AGENT "/z23-peerprecheck/"
#define USER_AGENT_LEN (sizeof USER_AGENT - 1)
#define VERSION_PAYLOAD_LEN (4u + 8u + 8u + ADDR_LEN + ADDR_LEN + 8u + 1u + USER_AGENT_LEN + 4u + 1u)
#define COMMAND_LEN 12u

static const uint8_t cmd_version[COMMAND_LEN] = {'v', 'e', 'r', 's', 'i', 'o', 'n'};

struct probe_args {
    const char *host;
    const char *port_text;
    uint32_t port;
    uint32_t budget_secs;
    uint8_t magic[4];
};

static uint8_t body_buf[MAX_BODY_LEN];

static uint64_t now_ms(void)
{
    return (uint64_t)(clock_now_monotonic_ns() / 1000000);
}

/* Strict decimal: digits only, no overflow, value at most max. */
static bool parse_decimal(const char *s, uint32_t max, uint32_t *out)
{
    uint64_t v = 0;
    if (*s == '\0') {
        return false;
    }
    for (; *s != '\0'; s++) {
        if (*s < '0' || *s > '9') {
            return false;
        }
        v = v * 10u + (uint64_t)(*s - '0');
        if (v > max) {
            return false;
        }
    }
    *out = (uint32_t)v;
    return true;
}

static bool magic_from_env(uint8_t out[4])
{
    const char *m = getenv("ZCL_CS_PEER_MAGIC");
    if (m == NULL || *m == '\0') {
        m = DEFAULT_MAGIC_HEX;
    }
    return zcl_hex_decode_lower(m, out, 4);
}

static bool parse_args(int argc, char **argv, struct probe_args *a)
{
    if (argc < 3 || argv[1][0] == '\0' || argv[2][0] == '\0') {
        return false;
    }
    a->host = argv[1];
    a->port_text = argv[2];
    a->budget_secs = DEFAULT_BUDGET_SECS;
    if (argc >= 4 && argv[3][0] != '\0') {
        if (!parse_decimal(argv[3], UINT32_MAX, &a->budget_secs) || a->budget_secs == 0) {
            return false;
        }
    }
    if (!parse_decimal(a->port_text, UINT32_MAX, &a->port)) {
        return false;
    }
    return magic_from_env(a->magic);
}

/* One poll bounded by the absolute deadline. Returns 1 when fd is ready. */
static int wait_ready(int fd, short events, uint64_t deadline)
{
    uint64_t now = now_ms();
    if (now >= deadline) {
        return 0;
    }
    uint64_t left = deadline - now;
    if (left > INT_MAX) {
        left = INT_MAX;
    }
    struct pollfd p = {.fd = fd, .events = events};
    return poll(&p, 1, (int)left) > 0;
}

static int try_connect(const struct addrinfo *ai, uint64_t deadline, int *fd_out)
{
    int fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if (fd < 0) {
        return RC_UNREACHABLE;
    }
    if (fcntl(fd, F_SETFL, O_NONBLOCK) != 0) {
        close(fd);
        return RC_UNREACHABLE;
    }
    if (connect(fd, ai->ai_addr, ai->ai_addrlen) != 0 && errno != EINPROGRESS) {
        close(fd);
        return RC_UNREACHABLE;
    }
    if (!wait_ready(fd, POLLOUT, deadline)) {
        close(fd);
        return RC_NO_HANDSHAKE;
    }
    int err = 0;
    socklen_t len = sizeof err;
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len) != 0 || err != 0) {
        close(fd);
        return RC_UNREACHABLE;
    }
    *fd_out = fd;
    return RC_OK;
}

static int connect_peer(const char *host, const char *port, uint64_t deadline, int *fd_out)
{
    struct addrinfo hints;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo *res = NULL;
    if (getaddrinfo(host, port, &hints, &res) != 0) {
        return RC_UNREACHABLE;
    }
    int rc = RC_UNREACHABLE;
    for (struct addrinfo *ai = res; ai != NULL && rc == RC_UNREACHABLE; ai = ai->ai_next) {
        rc = try_connect(ai, deadline, fd_out);
    }
    freeaddrinfo(res);
    return rc;
}

static bool send_all(int fd, const uint8_t *buf, size_t n, uint64_t deadline)
{
    size_t off = 0;
    while (off < n) {
        if (!wait_ready(fd, POLLOUT, deadline)) {
            return false;
        }
        ssize_t w = write(fd, buf + off, n - off);
        if (w < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
                continue;
            }
            return false;
        }
        off += (size_t)w;
    }
    return true;
}

/* Reads up to n bytes; returns the count received before EOF, error or deadline. */
static size_t recv_exact(int fd, uint8_t *buf, size_t n, uint64_t deadline)
{
    size_t got = 0;
    while (got < n) {
        if (!wait_ready(fd, POLLIN, deadline)) {
            break;
        }
        ssize_t r = read(fd, buf + got, n - got);
        if (r > 0) {
            got += (size_t)r;
        } else if (r == 0 || (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)) {
            break;
        }
    }
    return got;
}

/* Net address without time: services(8), IPv4-mapped 127.0.0.1 in a 16-byte
 * field, port(2, big-endian) = 0. */
static void put_addr_localhost(uint8_t *p)
{
    memset(p, 0, ADDR_LEN);
    p[18] = 0xff;
    p[19] = 0xff;
    p[20] = 127;
    p[23] = 1;
}

/* version(4) services(8) time(8) addr_recv(26) addr_from(26) nonce(8)
 * user_agent(varstr) start_height(4) relay(1). */
static void build_payload(uint8_t *p, uint64_t now, const uint8_t nonce[8])
{
    size_t o = 0;
    zcl_write_u32_le(p + o, PROTOCOL_VERSION);
    o += 4;
    zcl_write_u64_le(p + o, 0);
    o += 8;
    zcl_write_u64_le(p + o, now);
    o += 8;
    put_addr_localhost(p + o);
    o += ADDR_LEN;
    put_addr_localhost(p + o);
    o += ADDR_LEN;
    memcpy(p + o, nonce, 8);
    o += 8;
    p[o++] = (uint8_t)USER_AGENT_LEN;
    memcpy(p + o, USER_AGENT, USER_AGENT_LEN);
    o += USER_AGENT_LEN;
    zcl_write_u32_le(p + o, 0);
    o += 4;
    p[o] = 0;
}

static void double_sha256(const uint8_t *in, size_t n, uint8_t out[SHA256_OUTPUT_SIZE])
{
    uint8_t first[SHA256_OUTPUT_SIZE];
    struct sha256_ctx ctx;
    sha256_init(&ctx);
    sha256_write(&ctx, in, n);
    sha256_finalize(&ctx, first);
    sha256_init(&ctx);
    sha256_write(&ctx, first, sizeof first);
    sha256_finalize(&ctx, out);
}

/* Frame: magic(4) command(12) length(4, LE) checksum(4) payload. */
static size_t build_message(uint8_t *msg, const uint8_t magic[4])
{
    uint8_t payload[VERSION_PAYLOAD_LEN];
    uint8_t nonce[8];
    uint8_t digest[SHA256_OUTPUT_SIZE];
    if (!rng_fill(nonce, sizeof nonce)) {
        memset(nonce, 0, sizeof nonce);
    }
    build_payload(payload, (uint64_t)(clock_now_wall_ms() / 1000), nonce);
    double_sha256(payload, sizeof payload, digest);

    memcpy(msg, magic, 4);
    memcpy(msg + 4, cmd_version, COMMAND_LEN);
    zcl_write_u32_le(msg + 16, (uint32_t)sizeof payload);
    memcpy(msg + 20, digest, 4);
    memcpy(msg + HEADER_LEN, payload, sizeof payload);
    return HEADER_LEN + sizeof payload;
}

static int parse_version_body(const uint8_t *body, size_t len, uint32_t *height)
{
    if (len < VERSION_MIN_BODY) {
        return RC_NO_HANDSHAKE;
    }
    size_t ualen = body[80];
    if (ualen >= VERSION_UA_LIMIT || len < VERSION_MIN_BODY + ualen) {
        return RC_NO_HANDSHAKE;
    }
    *height = zcl_read_u32_le(body + 81 + ualen);
    return RC_OK;
}

static int read_peer_version(int fd, const uint8_t magic[4], uint64_t deadline, uint32_t *height)
{
    for (int i = 0; i < MAX_MESSAGES; i++) {
        uint8_t hdr[HEADER_LEN];
        if (recv_exact(fd, hdr, HEADER_LEN, deadline) != HEADER_LEN) {
            break;
        }
        if (memcmp(hdr, magic, 4) != 0) {
            break;
        }
        uint64_t len = zcl_read_u32_le(hdr + 16);
        if (len > MAX_BODY_LEN || recv_exact(fd, body_buf, (size_t)len, deadline) != len) {
            break;
        }
        if (memcmp(hdr + 4, cmd_version, COMMAND_LEN) != 0) {
            continue;
        }
        return parse_version_body(body_buf, (size_t)len, height);
    }
    return RC_NO_HANDSHAKE;
}

static int handshake(int fd, const uint8_t magic[4], uint64_t deadline, uint32_t *height)
{
    uint8_t msg[HEADER_LEN + VERSION_PAYLOAD_LEN];
    size_t n = build_message(msg, magic);
    if (!send_all(fd, msg, n, deadline)) {
        return RC_NO_HANDSHAKE;
    }
    return read_peer_version(fd, magic, deadline, height);
}

int main(int argc, char **argv)
{
    struct probe_args a;
    if (!parse_args(argc, argv, &a)) {
        puts("usage");
        return RC_USAGE;
    }
    if (a.port > 65535u) {
        puts("peer_unreachable");
        return RC_UNREACHABLE;
    }
    signal(SIGPIPE, SIG_IGN);

    uint64_t deadline = now_ms() + (uint64_t)a.budget_secs * 1000u;
    uint32_t height = 0;
    int fd = -1;
    int rc = connect_peer(a.host, a.port_text, deadline, &fd);
    if (rc == RC_OK) {
        rc = handshake(fd, a.magic, deadline, &height);
        close(fd);
    }
    if (rc == RC_OK) {
        printf("ok %u\n", height);
    } else {
        puts(rc == RC_UNREACHABLE ? "peer_unreachable" : "peer_no_handshake");
    }
    return rc;
}
