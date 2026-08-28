/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * network_crawler_probe — the DEFAULT real dialer behind the network_crawler
 * probe_fn seam. It opens a SHORT-LIVED clearnet socket to one address OUTSIDE
 * the node's connman, performs a minimal version/verack handshake (Bitnodes
 * pattern), records {version, subver, services, best_height, latency}, then
 * disconnects immediately. It NEVER relays, syncs, or requests blocks; it
 * advertises no services and relay=false.
 *
 * ONION targets are dialed too, through the embedded Tor
 * (tor_integration_fetch_onion_blocking — dynhost, no SOCKS; the same call
 * connman uses for onion seed fetches). Because dynhost speaks HTTP and not a
 * raw stream, the onion measurement is "did the service answer /directory.json"
 * rather than a version/verack handshake; a completed fetch also yields the
 * peer's advertised height and version from its own directory row. Stated
 * consequence: an onion peer that serves P2P but no HTTP surface measures as
 * unreachable. When Tor is NOT built in or not bootstrapped, the onion row is
 * recorded NOT_PROBED with a reason — never unreachable, because a false
 * negative there feeds peer reputation and is worse than no data at all.
 *
 * Kept in its own TU (no sockets in the census fold, no fold logic here) so the
 * fold is unit-testable hermetically and this untested, public-network-dialing
 * code stays isolated. Every read/write is bounded (connect/recv/send timeouts,
 * payload cap, handshake-message cap).
 */

// one-result-type-ok:network-crawler-probe-dialer — this TU is the default
// probe_fn seam; every export/helper returns bool per the ncrawl_probe_fn
// typedef (a recordable-result predicate), not a fallible zcl_result service
// surface. The crawler's fallible lifecycle (network_crawler_start) lives in
// network_crawler.c and returns struct zcl_result.

#include "services/network_crawler.h"

#include "chain/chainparams.h"
#include "core/hash.h"
#include "core/serialize.h"
#include "core/uint256.h"
#include "crypto/sha3.h"
#include "encoding/utilstrencodings.h"
#include "net/netaddr.h"
#include "net/netbase.h"
#include "net/onion_peer_merge.h"
#include "net/p2p_message.h"
#include "net/protocol.h"
#include "net/tor_integration.h"
#include "net/version.h"
#include "platform/socket_compat.h"
#include "platform/time_compat.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NCRAWL_MAX_MSG_PAYLOAD  (1u << 20) /* 1 MiB cap on any handshake frame */
#define NCRAWL_MAX_HANDSHAKE_MSGS 4        /* frames read while awaiting version */
#define NCRAWL_USER_AGENT "/zclassic23-observatory:1/"

/* Tor v3 hostname: 56 base32 chars + ".onion". */
#define NCRAWL_ONION_HOST_LEN 62
/* One /directory.json node object, copied out for bounded parsing. */
#define NCRAWL_DIR_OBJ_MAX 768
/* Never scan more than this much of a peer-supplied directory body. */
#define NCRAWL_DIR_SCAN_MAX (256u * 1024u)

/* Record `out` as NOT PROBED — no dial ran, so `reachable` carries no meaning
 * and MUST NOT be read as a negative. Always a recordable result. */
static bool ncrawl_not_probed(struct ncrawl_probe_result *out, const char *why)
{
    out->outcome = (uint8_t)NCRAWL_OUTCOME_NOT_PROBED;
    out->reachable = false;
    snprintf(out->reason, sizeof(out->reason), "%s", why ? why : "not probed");
    return true;
}

static bool ncrawl_send_all(platform_socket_t sock, const uint8_t *buf,
                            size_t len)
{
    return platform_socket_send_all(sock, buf, len);
}

static bool ncrawl_recv_all(platform_socket_t sock, uint8_t *buf, size_t len)
{
    size_t got = 0;
    while (got < len) {
        int n = platform_socket_receive(sock, buf + got, len - got);
        if (n <= 0)
            return false; /* 0 = peer closed, <0 = error/timeout */
        got += (size_t)n;
    }
    return true;
}

/* Frame `payload` as a P2P message with the given command and send it. Mirrors
 * p2p_node_end_message: 24-byte header (magic, command, LE length, checksum)
 * then payload; checksum = first 4 bytes of hash256(payload). */
static bool ncrawl_send_framed(platform_socket_t sock,
                               const struct chain_params *params,
                               const char *command,
                               const struct byte_stream *payload)
{
    struct byte_stream msg;
    stream_init(&msg, MSG_HEADER_SIZE + (payload ? payload->size : 0) + 8);

    struct msg_header hdr;
    msg_header_init_full(&hdr, params->pchMessageStart, command,
                         payload ? (unsigned int)payload->size : 0);
    stream_write(&msg, (const uint8_t *)&hdr, MSG_HEADER_SIZE);
    if (payload && payload->size)
        stream_write(&msg, payload->data, payload->size);
    if (msg.error || msg.size < MSG_HEADER_SIZE) {
        stream_free(&msg);
        return false;
    }

    uint8_t *buf = msg.data;
    unsigned int plen = (unsigned int)(msg.size - MSG_HEADER_SIZE);
    buf[MESSAGE_START_SIZE + COMMAND_SIZE + 0] = (uint8_t)(plen & 0xff);
    buf[MESSAGE_START_SIZE + COMMAND_SIZE + 1] = (uint8_t)((plen >> 8) & 0xff);
    buf[MESSAGE_START_SIZE + COMMAND_SIZE + 2] = (uint8_t)((plen >> 16) & 0xff);
    buf[MESSAGE_START_SIZE + COMMAND_SIZE + 3] = (uint8_t)((plen >> 24) & 0xff);
    struct uint256 h;
    hash256(buf + MSG_HEADER_SIZE, msg.size - MSG_HEADER_SIZE, h.data);
    memcpy(buf + MESSAGE_START_SIZE + COMMAND_SIZE + 4, h.data, 4);

    bool ok = ncrawl_send_all(sock, buf, msg.size);
    stream_free(&msg);
    return ok;
}

static bool ncrawl_send_version(platform_socket_t sock,
                                const struct chain_params *params,
                                const struct net_address *peer)
{
    struct version_message ver;
    version_message_init(&ver);
    ver.protocol_version = PROTOCOL_VERSION;
    ver.services = 0;                   /* pure observer: advertise nothing */
    ver.timestamp = platform_time_wall_unix();
    ver.addr_recv = *peer;
    ver.addr_recv.nServices = 0;
    ver.nonce = (uint64_t)platform_time_monotonic_us() ^
                ((uint64_t)peer->svc.port << 48);
    snprintf(ver.sub_version, sizeof(ver.sub_version), "%s", NCRAWL_USER_AGENT);
    ver.start_height = 0;
    ver.relay = false;                  /* do not want relayed txs */

    struct byte_stream s;
    stream_init(&s, 256);
    if (!version_message_serialize(&ver, &s)) {
        stream_free(&s);
        return false;
    }
    bool ok = ncrawl_send_framed(sock, params, "version", &s);
    stream_free(&s);
    return ok;
}

/* Read framed messages (bounded) until the peer's `version`, parsed into out. */
static bool ncrawl_read_version(platform_socket_t sock,
                                const struct chain_params *params,
                                struct ncrawl_probe_result *out)
{
    for (int attempt = 0; attempt < NCRAWL_MAX_HANDSHAKE_MSGS; attempt++) {
        uint8_t hdr[MSG_HEADER_SIZE];
        if (!ncrawl_recv_all(sock, hdr, MSG_HEADER_SIZE))
            return false; // raw-return-ok:crawler probe handshake IO failure is expected per-address, not logged
        if (memcmp(hdr, params->pchMessageStart, MESSAGE_START_SIZE) != 0)
            return false;

        char cmd[COMMAND_SIZE + 1];
        memcpy(cmd, hdr + MESSAGE_START_SIZE, COMMAND_SIZE);
        cmd[COMMAND_SIZE] = '\0';

        unsigned int plen =
            (unsigned int)hdr[MESSAGE_START_SIZE + COMMAND_SIZE] |
            ((unsigned int)hdr[MESSAGE_START_SIZE + COMMAND_SIZE + 1] << 8) |
            ((unsigned int)hdr[MESSAGE_START_SIZE + COMMAND_SIZE + 2] << 16) |
            ((unsigned int)hdr[MESSAGE_START_SIZE + COMMAND_SIZE + 3] << 24);
        if (plen > NCRAWL_MAX_MSG_PAYLOAD)
            return false;

        uint8_t *payload = NULL;
        if (plen) {
            payload = zcl_malloc(plen, "ncrawl_payload");
            if (!payload)
                return false;
            if (!ncrawl_recv_all(sock, payload, plen)) {
                free(payload);
                return false;
            }
        }

        if (strcmp(cmd, "version") == 0) {
            struct byte_stream s;
            stream_init_from_data(&s, payload ? payload : (const uint8_t *)"",
                                  plen);
            struct version_message ver;
            version_message_init(&ver);
            bool ok = version_message_deserialize(&ver, &s);
            free(payload);
            if (!ok)
                return false;
            out->version = ver.protocol_version;
            out->services = ver.services;
            out->best_height = ver.start_height >= 0 ? ver.start_height : -1;
            snprintf(out->subver, sizeof(out->subver), "%.*s",
                     (int)sizeof(out->subver) - 1, ver.sub_version);
            return true;
        }
        free(payload);
        /* not the version frame yet — skip and keep reading (bounded) */
    }
    return false;
}

/* ── onion branch ────────────────────────────────────────────────────── */

/* Derive the Tor v3 hostname from the 32-byte ed25519 key held in net_addr:
 *   host = base32(pubkey || checksum || version) + ".onion"
 *   checksum = SHA3-256(".onion checksum" || pubkey || version)[0..1]
 *   version  = 0x03
 * 35 bytes encode to exactly 56 base32 chars, so no padding is produced. */
static bool ncrawl_onion_hostname(const struct net_addr *a, char *out,
                                  size_t out_size)
{
    /* Every `false` here is a CLASSIFICATION — "not a renderable v3 onion
     * address" — which the caller turns into a NOT_PROBED row carrying a
     * reason. Logging per address would emit one line per crawled peer per
     * round; the reason travels in the census row instead. */
    if (!a || !out || out_size < NCRAWL_ONION_HOST_LEN + 1)
        return false; // raw-return-ok:onion-address-shape-classified-by-caller
    out[0] = '\0';
    if (!a->has_torv3)
        return false; // raw-return-ok:onion-address-shape-classified-by-caller

    unsigned char pre[15 + TORV3_ADDR_SIZE + 1];
    memcpy(pre, ".onion checksum", 15);
    memcpy(pre + 15, a->torv3, TORV3_ADDR_SIZE);
    pre[15 + TORV3_ADDR_SIZE] = 0x03;

    unsigned char digest[SHA3_256_OUTPUT_SIZE];
    sha3_256(pre, sizeof(pre), digest);

    unsigned char blob[TORV3_ADDR_SIZE + 3];
    memcpy(blob, a->torv3, TORV3_ADDR_SIZE);
    blob[TORV3_ADDR_SIZE + 0] = digest[0];
    blob[TORV3_ADDR_SIZE + 1] = digest[1];
    blob[TORV3_ADDR_SIZE + 2] = 0x03;

    char b32[NCRAWL_ONION_HOST_LEN + 8];
    if (EncodeBase32(blob, sizeof(blob), b32, sizeof(b32)) != 56)
        return false; // raw-return-ok:onion-address-shape-classified-by-caller
    if (snprintf(out, out_size, "%s.onion", b32) != NCRAWL_ONION_HOST_LEN)
        return false; // raw-return-ok:onion-address-shape-classified-by-caller
    return onion_hostname_valid(out);
}

bool network_crawler_render_addr(const struct net_address *addr,
                                 char *out, size_t out_size)
{
    if (!out || out_size == 0)
        return false;
    out[0] = '\0';
    if (!addr)
        return false;
    if (net_addr_is_tor(&addr->svc.addr)) {
        char host[NCRAWL_ONION_HOST_LEN + 1];
        if (!ncrawl_onion_hostname(&addr->svc.addr, host, sizeof(host)))
            return false; // raw-return-ok:unrenderable-onion-becomes-NOT_PROBED
        return snprintf(out, out_size, "%s:%u", host, addr->svc.port) > 0 &&
               out[0] != '\0';
    }
    net_service_to_string(&addr->svc, out, out_size);
    return out[0] != '\0';
}

bool network_crawler_onion_probe_available(void)
{
    /* Bootstrapped embedded Tor is the ONLY thing that can carry an onion
     * dial. The stub build (vendor/tor_stub.c) never reaches ready, so this
     * stays false and every onion row is recorded NOT PROBED. */
    return tor_integration_is_ready();
}

/* Copy the /directory.json node object that describes the onion we dialed —
 * its own row, marked "self":true — into `obj` (NUL-terminated). Falls back to
 * the FIRST node object when no self row is present. Bounded: the scan stops
 * at NCRAWL_DIR_SCAN_MAX bytes and each object copy at NCRAWL_DIR_OBJ_MAX. */
static bool ncrawl_dir_self_object(const char *body, size_t body_len,
                                   char *obj, size_t obj_size)
{
    if (!body || !obj || obj_size == 0)
        return false;
    obj[0] = '\0';
    if (body_len > NCRAWL_DIR_SCAN_MAX)
        body_len = NCRAWL_DIR_SCAN_MAX;

    const char *first = NULL, *first_end = NULL;
    const char *p = body;
    const char *limit = body + body_len;
    while (p < limit) {
        const char *start = strstr(p, "{\"onion\":\"");
        if (!start || start >= limit)
            break;
        const char *end = strstr(start + 1, "{\"onion\":\"");
        if (!end || end > limit)
            end = limit;
        size_t span = (size_t)(end - start);
        if (span >= obj_size)
            span = obj_size - 1;
        if (!first) {
            first = start;
            first_end = start + span;
        }
        memcpy(obj, start, span);
        obj[span] = '\0';
        if (strstr(obj, "\"self\":true"))
            return true;
        p = start + 1;
    }
    if (!first)
        return false;
    size_t span = (size_t)(first_end - first);
    if (span >= obj_size)
        span = obj_size - 1;
    memcpy(obj, first, span);
    obj[span] = '\0';
    return true;
}

/* "key":<int> inside a NUL-terminated object slice. */
static bool ncrawl_dir_int(const char *obj, const char *key, int64_t *out)
{
    char pat[32];
    if (snprintf(pat, sizeof(pat), "\"%s\":", key) <= 0)
        return false;
    const char *at = strstr(obj, pat);
    if (!at)
        return false;
    at += strlen(pat);
    if (*at != '-' && (*at < '0' || *at > '9'))
        return false;
    *out = strtoll(at, NULL, 10);
    return true;
}

/* "key":"<string>" inside a NUL-terminated object slice; copied verbatim and
 * truncated to cap (peer-supplied text is never trusted to be short). */
static bool ncrawl_dir_str(const char *obj, const char *key, char *out,
                           size_t cap)
{
    if (!out || cap == 0)
        return false;
    out[0] = '\0';
    char pat[32];
    if (snprintf(pat, sizeof(pat), "\"%s\":\"", key) <= 0)
        return false;
    const char *at = strstr(obj, pat);
    if (!at)
        return false;
    at += strlen(pat);
    const char *end = strchr(at, '"');
    if (!end || end == at)
        return false;
    size_t n = (size_t)(end - at);
    if (n >= cap)
        n = cap - 1;
    memcpy(out, at, n);
    out[n] = '\0';
    return true;
}

/* One bounded onion measurement. timeout_ms bounds the WHOLE dial: a dead or
 * slow onion costs at most that, never an unbounded wait. */
static bool ncrawl_probe_onion(const struct net_address *addr, int timeout_ms,
                               struct ncrawl_probe_result *out)
{
    char host[NCRAWL_ONION_HOST_LEN + 1];
    if (!ncrawl_onion_hostname(&addr->svc.addr, host, sizeof(host)))
        return ncrawl_not_probed(out, "onion hostname unrenderable");

    if (!network_crawler_onion_probe_available())
        return ncrawl_not_probed(out, "tor unavailable (no circuit to dial)");

    int timeout_secs = (timeout_ms + 999) / 1000;
    if (timeout_secs < 1) timeout_secs = 1;
    if (timeout_secs > 120) timeout_secs = 120;

    struct onion_fetch_result res;
    memset(&res, 0, sizeof(res));
    int64_t t0 = platform_time_monotonic_us();
    int rc = tor_integration_fetch_onion_blocking(host, "/directory.json", &res,
                                                  timeout_secs);
    int64_t elapsed = platform_time_monotonic_us() - t0;

    if (rc < 0) {
        /* The dial RAN and did not complete — a real measurement, not a gap. */
        snprintf(out->reason, sizeof(out->reason), "onion dial failed");
        if (res.body)
            free(res.body);
        return true;
    }

    /* The service answered over a live circuit: that IS reachability. */
    out->reachable = true;
    out->latency_us = elapsed;
    snprintf(out->reason, sizeof(out->reason), "onion http %d", res.status);

    if (res.body && res.body_len > 0) {
        char obj[NCRAWL_DIR_OBJ_MAX];
        if (ncrawl_dir_self_object((const char *)res.body, res.body_len, obj,
                                   sizeof(obj))) {
            int64_t h = -1, svc = 0;
            if (ncrawl_dir_int(obj, "height", &h) && h >= 0)
                out->best_height = h;
            if (ncrawl_dir_int(obj, "services", &svc) && svc >= 0)
                out->services = (uint64_t)svc;
            (void)ncrawl_dir_str(obj, "version", out->subver,
                                 sizeof(out->subver));
        }
    }
    if (res.body)
        free(res.body);
    return true;
}

bool network_crawler_default_probe(const struct net_address *addr,
                                   int connect_timeout_ms,
                                   int handshake_timeout_ms,
                                   struct ncrawl_probe_result *out)
{
    if (!addr || !out)
        return false;

    memset(out, 0, sizeof(*out));
    out->is_onion = net_addr_is_tor(&addr->svc.addr);
    out->reachable = false;
    out->outcome = (uint8_t)NCRAWL_OUTCOME_MEASURED;
    out->best_height = -1;
    out->last_probe_us = platform_time_wall_unix();
    if (!network_crawler_render_addr(addr, out->addr, sizeof(out->addr)) ||
        !out->addr[0])
        return false; /* could not render address → not recordable */

    /* Onion: dial through the embedded Tor. The crawler hands us the onion
     * timeout in both slots; take the larger so a caller that only set one
     * still gets the ceiling it meant. */
    if (out->is_onion) {
        int t = connect_timeout_ms > handshake_timeout_ms ? connect_timeout_ms
                                                          : handshake_timeout_ms;
        return ncrawl_probe_onion(addr, t, out);
    }

    const struct chain_params *params = chain_params_get();
    if (!params) {
        /* No chain params → we structurally cannot frame a handshake. That is
         * "we did not look", not "this node is down". */
        return ncrawl_not_probed(out, "chain params not loaded");
    }

    platform_socket_t sock = PLATFORM_SOCKET_INVALID;
    int64_t t0 = platform_time_monotonic_us();
    if (!connect_socket_directly(&addr->svc, &sock, connect_timeout_ms) ||
        sock == PLATFORM_SOCKET_INVALID) {
        snprintf(out->reason, sizeof(out->reason), "tcp connect failed");
        return true; /* MEASURED unreachable */
    }

    (void)platform_socket_set_receive_timeout(sock, handshake_timeout_ms);
    (void)platform_socket_set_send_timeout(sock, handshake_timeout_ms);

    if (ncrawl_send_version(sock, params, addr) &&
        ncrawl_read_version(sock, params, out)) {
        (void)ncrawl_send_framed(sock, params, "verack", NULL); /* best-effort */
        out->reachable = true;
        out->latency_us = platform_time_monotonic_us() - t0;
    } else {
        snprintf(out->reason, sizeof(out->reason), "version handshake failed");
    }

    (void)platform_socket_close(sock);
    return true;
}
