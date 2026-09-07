/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * One gamelink session: its subkeys, its socket, its sequence numbers, its
 * replay window and its byte cap.
 *
 * The three properties this file is responsible for:
 *
 *   NONCE UNIQUENESS. The AEAD nonce is the 64-bit sequence number and each
 *   direction has its own key, so a nonce is used once. At the top of the
 *   space the session REFUSES to send rather than wrapping — a reused
 *   ChaCha20-Poly1305 nonce loses confidentiality and the Poly1305 key, so
 *   "stop working" is the only honest behaviour there is.
 *
 *   REPLAY. A bounded window (GAMELINK_REPLAY_WINDOW sequences below the
 *   highest accepted) drops old and duplicate datagrams. The check runs
 *   BEFORE decryption, so a replay costs no cipher work; the window only
 *   ADVANCES after a datagram authenticates, so a forged header carrying a
 *   huge sequence number cannot push the window past live traffic.
 *
 *   BYTE CAPS. A token bucket enforces the design note's pacing cap
 *   numerically. The blockchain never contends with this transport because
 *   they share no socket and no code, but a game loop that runs away should
 *   still hit a number rather than a neighbour's uplink.
 *
 * The socket seam follows core/modules/net/src/nat.c: platform/socket_compat.h
 * for the type, the lifecycle and the address helpers, with the two datagram
 * calls wrapped locally because the seam does not name them.
 */

#if !defined(_WIN32)
#define _POSIX_C_SOURCE 200809L
#endif

#include "gamelink_internal.h"

#include "crypto/hkdf_sha3.h"
#include "platform/socket_compat.h"

#include <stdio.h>
#include <string.h>

/* The label is the domain separation. Every other consumer of the same
 * session material derives under a different one, so no key derived here can
 * be used anywhere else and no key derived elsewhere opens a datagram. */
#define GAMELINK_KDF_LABEL "z23/gamelink/v1/datagram"
#define GAMELINK_KDF_INFO "keys+session-id"
#define GAMELINK_OKM_BYTES 72u

/* One drain of the socket reads at most this many datagrams. A caller's game
 * loop must come back for the rest rather than be held inside one poll by a
 * peer that sends faster than the loop runs. */
#define GAMELINK_POLL_BUDGET 256u

const char *gamelink_status_label(enum gamelink_status status)
{
    switch (status) {
    case GAMELINK_OK: return "ok";
    case GAMELINK_ARGUMENT: return "argument";
    case GAMELINK_ADDRESS: return "address";
    case GAMELINK_SOCKET: return "socket";
    case GAMELINK_CLOSED: return "closed";
    case GAMELINK_TOO_LARGE: return "payload_too_large";
    case GAMELINK_RATE: return "byte_cap";
    case GAMELINK_NONCE_EXHAUSTED: return "nonce_exhausted";
    case GAMELINK_SEND_FAILED: return "send_failed";
    }
    return "unknown";
}

/* ── key derivation ──────────────────────────────────────────────────── */

bool gamelink_derive_keys(const uint8_t *material, size_t material_len,
                          bool initiator, uint8_t tx_key[32],
                          uint8_t rx_key[32], uint64_t *session_id)
{
    if (!material || material_len < 32 || !tx_key || !rx_key || !session_id)
        return false;
    uint8_t okm[GAMELINK_OKM_BYTES];
    if (!hkdf_sha3_256((const uint8_t *)GAMELINK_KDF_LABEL,
                       sizeof GAMELINK_KDF_LABEL - 1, material, material_len,
                       (const uint8_t *)GAMELINK_KDF_INFO,
                       sizeof GAMELINK_KDF_INFO - 1, okm, sizeof okm))
        return false;
    /* okm[0..32) seals initiator->responder, okm[32..64) the other way, and
     * okm[64..72) names the session. Both ends compute both keys and pick by
     * role, so neither end has to be told which key is which. */
    memcpy(tx_key, initiator ? okm : okm + 32, 32);
    memcpy(rx_key, initiator ? okm + 32 : okm, 32);
    uint64_t id = 0;
    for (size_t i = 0; i < 8; i++)
        id = (id << 8) | okm[64 + i];
    *session_id = id;
    memset(okm, 0, sizeof okm);
    return true;
}

/* ── clock ───────────────────────────────────────────────────────────── */

int64_t gamelink_now_ns(const struct gamelink *link)
{
    if (link && link->clock && link->clock->now_monotonic_ns)
        return link->clock->now_monotonic_ns(link->clock->self);
    return clock_now_monotonic_ns();
}

/* ── the socket seam ─────────────────────────────────────────────────── */

static int gamelink_sendto(intptr_t sock, const void *data, size_t size,
                           const struct sockaddr *address, size_t address_size)
{
#if defined(_WIN32)
    if (size > INT32_MAX || address_size > INT32_MAX)
        return -1;
    return sendto((platform_socket_t)sock, (const char *)data, (int)size, 0,
                  address, (int)address_size);
#else
    return (int)sendto((platform_socket_t)sock, data, size, 0, address,
                       (socklen_t)address_size);
#endif
}

static int gamelink_recvfrom(intptr_t sock, void *data, size_t size,
                             struct sockaddr_in *from)
{
    int amount = size > INT32_MAX ? INT32_MAX : (int)size;
#if defined(_WIN32)
    int from_size = (int)sizeof *from;
    return recvfrom((platform_socket_t)sock, (char *)data, amount, 0,
                    (struct sockaddr *)from, &from_size);
#else
    socklen_t from_size = (socklen_t)sizeof *from;
    return (int)recvfrom((platform_socket_t)sock, data, (size_t)amount, 0,
                         (struct sockaddr *)from, &from_size);
#endif
}

/* "ip:port", IPv4 only. Loopback and the fleet's own clearnet endpoints are
 * what this carries; an unparseable string is refused by name rather than
 * silently becoming a wildcard bind. */
static bool gamelink_parse_endpoint(const char *text, uint8_t out_addr[4],
                                    uint16_t *out_port)
{
    if (!text || !out_addr || !out_port)
        return false;
    const char *colon = strrchr(text, ':');
    if (!colon || colon == text || (size_t)(colon - text) >= 46u)
        return false;
    char host[46];
    memcpy(host, text, (size_t)(colon - text));
    host[colon - text] = 0;
    struct in_addr parsed;
    if (platform_socket_parse_address(AF_INET, host, &parsed) != 1)
        return false;
    unsigned long port = 0;
    const char *p = colon + 1;
    if (!*p)
        return false;
    for (; *p; p++) {
        if (*p < '0' || *p > '9' || port > 65535u)
            return false;
        port = port * 10u + (unsigned long)(*p - '0');
    }
    if (port > 65535u)
        return false;
    memcpy(out_addr, &parsed.s_addr, 4);
    *out_port = (uint16_t)port;
    return true;
}

static void gamelink_fill_sockaddr(const uint8_t addr[4], uint16_t port,
                                   struct sockaddr_in *out)
{
    memset(out, 0, sizeof *out);
    out->sin_family = AF_INET;
    out->sin_port = htons(port);
    memcpy(&out->sin_addr.s_addr, addr, 4);
}

static bool gamelink_bind_socket(struct gamelink *link, const char *local_bind)
{
    uint8_t bind_addr[4];
    uint16_t bind_port = 0;
    if (!gamelink_parse_endpoint(local_bind, bind_addr, &bind_port))
        return false;
    platform_socket_t sock =
        platform_socket_open(AF_INET, SOCK_DGRAM, 0, true, true);
    if (sock == PLATFORM_SOCKET_INVALID)
        return false;
    struct sockaddr_in local;
    gamelink_fill_sockaddr(bind_addr, bind_port, &local);
    if (platform_socket_bind(sock, (const struct sockaddr *)&local,
                             sizeof local) != 0) {
        (void)platform_socket_close(sock);
        return false;
    }
    /* Read the port back: a caller that bound port 0 has to be able to tell
     * the peer where to answer, and a test cannot use a fixed port. */
    struct sockaddr_in bound;
    size_t bound_size = sizeof bound;
    memset(&bound, 0, sizeof bound);
    if (platform_socket_local_address(sock, (struct sockaddr *)&bound,
                                      &bound_size) == 0)
        link->local_port = ntohs(bound.sin_port);
    link->socket = (intptr_t)sock;
    return true;
}

/* ── open / close ────────────────────────────────────────────────────── */

enum gamelink_status gamelink_open(struct gamelink *link,
                                   const uint8_t *material,
                                   size_t material_len, bool initiator,
                                   const char *local_bind,
                                   const char *peer_addr,
                                   const clock_iface_t *clock)
{
    if (!link || !material || !local_bind)
        return GAMELINK_ARGUMENT;
    memset(link, 0, sizeof *link);
    link->socket = -1;
    if (!gamelink_derive_keys(material, material_len, initiator, link->tx_key,
                              link->rx_key, &link->session_id))
        return GAMELINK_ARGUMENT;
    if (peer_addr &&
        !gamelink_parse_endpoint(peer_addr, link->peer_addr, &link->peer_port))
        return GAMELINK_ADDRESS;
    if (!gamelink_bind_socket(link, local_bind)) {
        memset(link->tx_key, 0, sizeof link->tx_key);
        memset(link->rx_key, 0, sizeof link->rx_key);
        return GAMELINK_SOCKET;
    }
    link->initiator = initiator;
    link->clock = clock;
    link->rate_bytes_per_s = GAMELINK_DEFAULT_RATE_BYTES_PER_S;
    link->burst_bytes = GAMELINK_DEFAULT_BURST_BYTES;
    link->bucket_bytes = (int64_t)link->burst_bytes;
    link->bucket_last_ns = gamelink_now_ns(link);
    link->open = true;
    return GAMELINK_OK;
}

void gamelink_close(struct gamelink *link)
{
    if (!link)
        return;
    if (link->socket >= 0)
        (void)platform_socket_close((platform_socket_t)link->socket);
    link->socket = -1;
    link->open = false;
    memset(link->tx_key, 0, sizeof link->tx_key);
    memset(link->rx_key, 0, sizeof link->rx_key);
}

/* ── the byte cap ────────────────────────────────────────────────────── */

static bool gamelink_bucket_take(struct gamelink *link, size_t wire_bytes)
{
    int64_t now = gamelink_now_ns(link);
    int64_t elapsed = now - link->bucket_last_ns;
    if (elapsed > 0 && link->rate_bytes_per_s > 0) {
        /* Nanoseconds to bytes without overflowing: seconds first, then the
         * remainder, both against a rate that fits in 32 bits. */
        int64_t refill = (elapsed / 1000000000) * (int64_t)link->rate_bytes_per_s +
                         ((elapsed % 1000000000) * (int64_t)link->rate_bytes_per_s) /
                             1000000000;
        link->bucket_bytes += refill;
        if (link->bucket_bytes > (int64_t)link->burst_bytes)
            link->bucket_bytes = (int64_t)link->burst_bytes;
    }
    if (elapsed > 0)
        link->bucket_last_ns = now;
    if (link->bucket_bytes < (int64_t)wire_bytes)
        return false;
    link->bucket_bytes -= (int64_t)wire_bytes;
    return true;
}

/* ── send ────────────────────────────────────────────────────────────── */

static enum gamelink_status gamelink_send_flagged(struct gamelink *link,
                                                  uint8_t flags,
                                                  const uint8_t *payload,
                                                  size_t len,
                                                  uint64_t *out_seq)
{
    if (!link)
        return GAMELINK_ARGUMENT;
    if (!link->open || link->socket < 0)
        return GAMELINK_CLOSED;
    if (len > GAMELINK_MAX_PAYLOAD)
        return GAMELINK_TOO_LARGE;
    if (link->peer_port == 0)
        return GAMELINK_ADDRESS;
    /* The last sequence number is never spent: reaching it means the next
     * send would reuse a nonce, and refusing is the only safe answer. */
    if (link->send_seq == UINT64_MAX)
        return GAMELINK_NONCE_EXHAUSTED;
    size_t wire_bytes = (size_t)GAMELINK_HEADER_BYTES + len + GAMELINK_TAG_BYTES;
    if (!gamelink_bucket_take(link, wire_bytes))
        return GAMELINK_RATE;
    struct gamelink_header header = {
        .session_id = link->session_id,
        .seq = link->send_seq,
        .ack = link->recv_highest,
        .ack_bits = (uint32_t)(link->recv_window >> 1),
        .flags = flags,
    };
    uint8_t datagram[GAMELINK_MAX_DATAGRAM];
    size_t datagram_len = 0;
    if (!gamelink_wire_seal(link->tx_key, &header, payload, len, datagram,
                            &datagram_len))
        return GAMELINK_SEND_FAILED;
    struct sockaddr_in peer;
    gamelink_fill_sockaddr(link->peer_addr, link->peer_port, &peer);
    int written = gamelink_sendto(link->socket, datagram, datagram_len,
                                  (const struct sockaddr *)&peer, sizeof peer);
    if (written < 0 || (size_t)written != datagram_len)
        return GAMELINK_SEND_FAILED;
    if (out_seq)
        *out_seq = link->send_seq;
    link->send_seq++;
    link->stats.sent++;
    link->stats.sent_bytes += datagram_len;
    return GAMELINK_OK;
}

enum gamelink_status gamelink_send(struct gamelink *link,
                                   const uint8_t *payload, size_t len,
                                   uint64_t *out_seq)
{
    return gamelink_send_flagged(link, 0, payload, len, out_seq);
}

enum gamelink_status gamelink_ping(struct gamelink *link)
{
    if (!link)
        return GAMELINK_ARGUMENT;
    int64_t now = gamelink_now_ns(link);
    uint8_t stamp[8];
    for (size_t i = 0; i < 8; i++)
        stamp[i] = (uint8_t)((uint64_t)now >> (56 - 8 * i));
    enum gamelink_status status =
        gamelink_send_flagged(link, GAMELINK_FLAG_PING, stamp, sizeof stamp,
                              NULL);
    if (status == GAMELINK_OK)
        link->stats.pings_sent++;
    return status;
}

/* ── the replay window ───────────────────────────────────────────────── */

/* Bit 0 of `recv_window` is `recv_highest` itself; bit N is N sequences
 * below it. Returns false when the sequence is a duplicate or is further
 * behind than the window reaches. */
static bool gamelink_window_admits(const struct gamelink *link, uint64_t seq)
{
    if (!link->recv_any)
        return true;
    if (seq > link->recv_highest)
        return true;
    uint64_t behind = link->recv_highest - seq;
    if (behind >= GAMELINK_REPLAY_WINDOW)
        return false;
    return (link->recv_window & ((uint64_t)1 << behind)) == 0;
}

static void gamelink_window_accept(struct gamelink *link, uint64_t seq)
{
    if (!link->recv_any) {
        link->recv_any = true;
        link->recv_first = seq;
        link->recv_highest = seq;
        link->recv_window = 1;
        return;
    }
    if (seq > link->recv_highest) {
        uint64_t advance = seq - link->recv_highest;
        link->recv_window = advance >= 64 ? 0 : (link->recv_window << advance);
        link->recv_window |= 1;
        link->recv_highest = seq;
        return;
    }
    link->recv_window |= (uint64_t)1 << (link->recv_highest - seq);
}

/* ── receive ─────────────────────────────────────────────────────────── */

static void gamelink_note_pong(struct gamelink *link, const uint8_t *payload,
                               size_t len)
{
    if (len != 8)
        return;
    uint64_t stamp = 0;
    for (size_t i = 0; i < 8; i++)
        stamp = (stamp << 8) | payload[i];
    int64_t now = gamelink_now_ns(link);
    if ((uint64_t)now < stamp)
        return;
    uint64_t rtt_us = ((uint64_t)now - stamp) / 1000u;
    /* RFC 3550's interarrival-jitter shape: J += (|D| - J) / 16. One
     * exponentially weighted number, so a single late packet moves it a
     * sixteenth rather than replacing it. */
    if (link->have_rtt) {
        uint64_t delta = rtt_us > link->rtt_us ? rtt_us - link->rtt_us
                                               : link->rtt_us - rtt_us;
        link->jitter_us += (delta - link->jitter_us) / 16u;
    }
    link->rtt_us = rtt_us;
    link->have_rtt = true;
    link->stats.pongs_recv++;
}

/* One datagram, already read off the socket. Returns 1 when it reached the
 * callback, 0 otherwise; every 0 has raised exactly one counter. */
static size_t gamelink_accept_one(struct gamelink *link, const uint8_t *buffer,
                                  size_t len, const struct sockaddr_in *from,
                                  gamelink_recv_fn cb, void *user)
{
    struct gamelink_header header;
    if (!gamelink_wire_parse_header(buffer, len, &header) ||
        header.session_id != link->session_id) {
        link->stats.dropped_malformed++;
        return 0;
    }
    if (!gamelink_window_admits(link, header.seq)) {
        link->stats.dropped_old++;
        return 0;
    }
    uint8_t payload[GAMELINK_MAX_PAYLOAD];
    size_t payload_len = 0;
    enum gamelink_open_result opened = gamelink_wire_open(
        link->rx_key, buffer, len, &header, payload, &payload_len);
    if (opened == GAMELINK_WIRE_AUTH) {
        link->stats.dropped_auth++;
        return 0;
    }
    if (opened != GAMELINK_WIRE_OK) {
        link->stats.dropped_malformed++;
        return 0;
    }
    gamelink_window_accept(link, header.seq);
    link->stats.recv++;
    link->stats.recv_bytes += len;
    /* An endpoint that opened without a peer learns it from the first
     * datagram that AUTHENTICATES — never from one that merely arrived. */
    if (link->peer_port == 0) {
        memcpy(link->peer_addr, &from->sin_addr.s_addr, 4);
        link->peer_port = ntohs(from->sin_port);
    }
    if (header.flags & GAMELINK_FLAG_PING) {
        (void)gamelink_send_flagged(link, GAMELINK_FLAG_PONG, payload,
                                    payload_len, NULL);
        return 0;
    }
    if (header.flags & GAMELINK_FLAG_PONG) {
        gamelink_note_pong(link, payload, payload_len);
        return 0;
    }
    if (cb)
        cb(user, header.seq, payload, payload_len);
    return 1;
}

size_t gamelink_poll(struct gamelink *link, gamelink_recv_fn cb, void *user)
{
    if (!link || !link->open || link->socket < 0)
        return 0;
    size_t delivered = 0;
    for (size_t i = 0; i < GAMELINK_POLL_BUDGET; i++) {
        uint8_t buffer[GAMELINK_MAX_DATAGRAM];
        struct sockaddr_in from;
        memset(&from, 0, sizeof from);
        int amount =
            gamelink_recvfrom(link->socket, buffer, sizeof buffer, &from);
        if (amount <= 0)
            break;
        delivered +=
            gamelink_accept_one(link, buffer, (size_t)amount, &from, cb, user);
    }
    return delivered;
}

/* ── statistics ──────────────────────────────────────────────────────── */

void gamelink_stats(const struct gamelink *link, struct gamelink_stats *out)
{
    if (!out)
        return;
    memset(out, 0, sizeof *out);
    if (!link)
        return;
    *out = link->stats;
    out->rtt_us = link->rtt_us;
    out->jitter_us = link->jitter_us;
    /* Loss is measured where it can be measured: the receive side knows how
     * many sequence numbers the peer spent and how many of them arrived. */
    if (link->recv_any && link->recv_highest >= link->recv_first) {
        uint64_t expected = link->recv_highest - link->recv_first + 1;
        uint64_t got = link->stats.recv;
        if (expected > 0 && expected >= got)
            out->loss_ppm = ((expected - got) * 1000000u) / expected;
    }
}
