/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * gamelink: two real UDP sessions on loopback, an injected clock, and every
 * way a datagram does not become a delivery.
 *
 * Nothing here is simulated except time. Both endpoints bind real sockets on
 * 127.0.0.1 with ephemeral ports read back from the kernel, and the bytes go
 * through the kernel's UDP path, because a transport proven against a fake
 * socket is a transport nobody has proven.
 *
 * Time IS injected, deliberately: the round-trip assertion is an exact
 * microsecond count, not a tolerance. A test that asserts "under 50 ms"
 * passes on a machine where the code is ten times too slow and fails on a
 * loaded machine where it is correct.
 *
 * The reorder, replay, tamper and loss cases run through a plain UDP relay
 * the test owns: it receives what the sender emitted and chooses what to hand
 * on, in what order, and with which byte flipped. That is the only way to
 * prove the receive path against traffic the sender would never produce.
 */

#include "test/test_core.h"

#include "gamelink/gamelink.h"
#include "platform/socket_compat.h"

#include <string.h>

/* ── an injected clock ───────────────────────────────────────────────── */

struct gl_clock {
    int64_t ns;
};

static struct gl_clock g_ticks = {.ns = 0};

static int64_t gl_clock_monotonic(void *self)
{
    return ((struct gl_clock *)self)->ns;
}

static int64_t gl_clock_wall(void *self)
{
    (void)self;
    return 0;
}

static const clock_iface_t g_clock = {.now_monotonic_ns = gl_clock_monotonic,
                                      .now_wall_ms = gl_clock_wall,
                                      .self = &g_ticks};

/* ── delivery capture ────────────────────────────────────────────────── */

#define GL_CAPTURE_MAX 2048u

struct gl_sink {
    size_t count;
    uint64_t seq[GL_CAPTURE_MAX];
    size_t len[GL_CAPTURE_MAX];
    uint8_t first_byte[GL_CAPTURE_MAX];
};

static struct gl_sink g_sink;

static void gl_sink_reset(void)
{
    memset(&g_sink, 0, sizeof g_sink);
}

static void gl_on_datagram(void *user, uint64_t seq, const uint8_t *payload,
                           size_t len)
{
    struct gl_sink *sink = (struct gl_sink *)user;
    if (sink->count >= GL_CAPTURE_MAX)
        return;
    sink->seq[sink->count] = seq;
    sink->len[sink->count] = len;
    sink->first_byte[sink->count] = len > 0 ? payload[0] : 0;
    sink->count++;
}

/* ── a relay the test controls ───────────────────────────────────────── */

#define GL_RELAY_HOLD 16u

struct gl_relay {
    intptr_t socket;
    uint16_t port;
    size_t held;
    size_t held_len[GL_RELAY_HOLD];
    uint8_t held_bytes[GL_RELAY_HOLD][GAMELINK_MAX_DATAGRAM];
};

static struct gl_relay g_relay;

static int gl_relay_recv(intptr_t sock, void *data, size_t size)
{
    int amount = size > INT32_MAX ? INT32_MAX : (int)size;
#if defined(_WIN32)
    return recvfrom((platform_socket_t)sock, (char *)data, amount, 0, NULL,
                    NULL);
#else
    return (int)recvfrom((platform_socket_t)sock, data, (size_t)amount, 0,
                         NULL, NULL);
#endif
}

static int gl_relay_send(intptr_t sock, const void *data, size_t size,
                         const struct sockaddr *to, size_t to_size)
{
#if defined(_WIN32)
    if (size > INT32_MAX || to_size > INT32_MAX)
        return -1;
    return sendto((platform_socket_t)sock, (const char *)data, (int)size, 0,
                  to, (int)to_size);
#else
    return (int)sendto((platform_socket_t)sock, data, size, 0, to,
                       (socklen_t)to_size);
#endif
}

static bool gl_loopback_sockaddr(struct sockaddr_in *out, uint16_t port)
{
    memset(out, 0, sizeof *out);
    out->sin_family = AF_INET;
    out->sin_port = htons(port);
    return platform_socket_parse_address(AF_INET, "127.0.0.1",
                                         &out->sin_addr) == 1;
}

static bool gl_relay_open(void)
{
    memset(&g_relay, 0, sizeof g_relay);
    platform_socket_t sock =
        platform_socket_open(AF_INET, SOCK_DGRAM, 0, true, true);
    if (sock == PLATFORM_SOCKET_INVALID)
        return false;
    g_relay.socket = (intptr_t)sock;
    struct sockaddr_in local;
    if (!gl_loopback_sockaddr(&local, 0))
        return false;
    if (platform_socket_bind(sock, (const struct sockaddr *)&local,
                             sizeof local) != 0)
        return false;
    struct sockaddr_in bound;
    size_t bound_size = sizeof bound;
    memset(&bound, 0, sizeof bound);
    if (platform_socket_local_address(sock, (struct sockaddr *)&bound,
                                      &bound_size) != 0)
        return false;
    g_relay.port = ntohs(bound.sin_port);
    return true;
}

static void gl_relay_close(void)
{
    if (g_relay.socket >= 0)
        (void)platform_socket_close((platform_socket_t)g_relay.socket);
    g_relay.socket = -1;
}

/* Drain everything waiting, keeping each datagram in arrival order. */
static size_t gl_relay_capture(size_t expected)
{
    size_t taken = 0;
    while (taken < expected && g_relay.held < GL_RELAY_HOLD) {
        if (platform_socket_wait_readable(
                (platform_socket_t)g_relay.socket, 1000) <= 0)
            break;
        int amount = gl_relay_recv(g_relay.socket,
                                   g_relay.held_bytes[g_relay.held],
                                   GAMELINK_MAX_DATAGRAM);
        if (amount <= 0)
            break;
        g_relay.held_len[g_relay.held] = (size_t)amount;
        g_relay.held++;
        taken++;
    }
    return taken;
}

/* Hand held datagram `index` to `port`, flipping one byte when `flip_offset`
 * lands inside it. SIZE_MAX means "verbatim". */
static bool gl_relay_forward(size_t index, uint16_t port, size_t flip_offset)
{
    if (index >= g_relay.held)
        return false;
    uint8_t copy[GAMELINK_MAX_DATAGRAM];
    size_t len = g_relay.held_len[index];
    memcpy(copy, g_relay.held_bytes[index], len);
    if (flip_offset < len)
        copy[flip_offset] = (uint8_t)(copy[flip_offset] ^ 0x40u);
    struct sockaddr_in to;
    if (!gl_loopback_sockaddr(&to, port))
        return false;
    int written = gl_relay_send(g_relay.socket, copy, len,
                                (const struct sockaddr *)&to, sizeof to);
    return written == (int)len;
}

/* ── session setup ───────────────────────────────────────────────────── */

static uint8_t g_material[GAMELINK_MATERIAL_BYTES];
static uint8_t g_other_material[GAMELINK_MATERIAL_BYTES];

static void gl_fill_material(uint8_t *out, uint8_t salt)
{
    for (size_t i = 0; i < GAMELINK_MATERIAL_BYTES; i++)
        out[i] = (uint8_t)(i * 7u + salt);
}

/* Open a responder bound to an ephemeral port with no peer yet, then an
 * initiator aimed at `peer_port`. Returns false if either refused. */
static bool gl_open_pair(struct gamelink *initiator, struct gamelink *responder,
                         uint16_t peer_port_override)
{
    if (gamelink_open(responder, g_material, sizeof g_material, false,
                      "127.0.0.1:0", NULL, &g_clock) != GAMELINK_OK)
        return false;
    char endpoint[64];
    uint16_t port = peer_port_override ? peer_port_override
                                       : responder->local_port;
    if ((size_t)snprintf(endpoint, sizeof endpoint, "127.0.0.1:%u",
                         (unsigned)port) >= sizeof endpoint)
        return false;
    return gamelink_open(initiator, g_material, sizeof g_material, true,
                         "127.0.0.1:0", endpoint, &g_clock) == GAMELINK_OK;
}

static int gl_send_fill(struct gamelink *link, uint8_t value, size_t len)
{
    uint8_t body[64];
    memset(body, value, sizeof body);
    return (int)gamelink_send(link, body, len > sizeof body ? sizeof body : len,
                              NULL);
}

/* ── the cases ───────────────────────────────────────────────────────── */

/* Send completion is not receive readiness. Wait on the real descriptor;
 * protocol time remains injected, and every expected packet must be counted. */
static uint64_t gl_seen(const struct gamelink *link)
{
    struct gamelink_stats stats;
    gamelink_stats(link, &stats);
    return stats.recv + stats.dropped_old + stats.dropped_auth +
           stats.dropped_malformed;
}

static bool gl_drain_until(struct gamelink *link, uint64_t expected)
{
    while (gl_seen(link) < expected) {
        uint64_t before = gl_seen(link);
        if (platform_socket_wait_readable((platform_socket_t)link->socket,
                                          1000) <= 0)
            return false;
        (void)gamelink_poll(link, gl_on_datagram, &g_sink);
        if (gl_seen(link) == before)
            return false;
    }
    return gl_seen(link) == expected;
}

static bool gl_receive(struct gamelink *link, uint64_t count)
{
    return gl_drain_until(link, gl_seen(link) + count);
}

static int gl_case_derivation(void)
{
    int failures = 0;
    TEST_CASE("gamelink: both ends derive the same directional subkeys") {
        uint8_t a_tx[32], a_rx[32], b_tx[32], b_rx[32];
        uint64_t a_id = 0, b_id = 0;
        ASSERT(gamelink_derive_keys(g_material, sizeof g_material, true, a_tx,
                                    a_rx, &a_id));
        ASSERT(gamelink_derive_keys(g_material, sizeof g_material, false, b_tx,
                                    b_rx, &b_id));
        /* The initiator seals with the key the responder opens with, and the
         * two directions are different keys. */
        ASSERT(memcmp(a_tx, b_rx, 32) == 0);
        ASSERT(memcmp(a_rx, b_tx, 32) == 0);
        ASSERT(memcmp(a_tx, a_rx, 32) != 0);
        ASSERT_EQ(a_id, b_id);
        /* Different session material derives a different everything. */
        uint8_t c_tx[32], c_rx[32];
        uint64_t c_id = 0;
        ASSERT(gamelink_derive_keys(g_other_material, sizeof g_other_material,
                                    true, c_tx, c_rx, &c_id));
        ASSERT(memcmp(a_tx, c_tx, 32) != 0);
        ASSERT(a_id != c_id);
        /* Short material is refused rather than stretched. */
        ASSERT(!gamelink_derive_keys(g_material, 31u, true, c_tx, c_rx, &c_id));
    } TEST_END;
    return failures;
}

static int gl_case_thousand_in_order(void)
{
    int failures = 0;
    struct gamelink a = {.socket = -1}, b = {.socket = -1};
    TEST_CASE("gamelink: a thousand datagrams in order all arrive, in order") {
        ASSERT(gl_open_pair(&a, &b, 0));
        gl_sink_reset();
        for (size_t round = 0; round < 10; round++) {
            for (size_t i = 0; i < 100; i++)
                ASSERT_EQ(gl_send_fill(&a, (uint8_t)i, 64u), (int)GAMELINK_OK);
            ASSERT(gl_receive(&b, 100));
        }
        ASSERT_EQ(g_sink.count, (size_t)1000);
        for (size_t i = 0; i < g_sink.count; i++) {
            ASSERT_EQ(g_sink.seq[i], (uint64_t)i);
            ASSERT_EQ(g_sink.len[i], (size_t)64);
        }
        struct gamelink_stats stats;
        gamelink_stats(&b, &stats);
        ASSERT_EQ(stats.recv, (uint64_t)1000);
        ASSERT_EQ(stats.dropped_old, (uint64_t)0);
        ASSERT_EQ(stats.dropped_auth, (uint64_t)0);
        ASSERT_EQ(stats.dropped_malformed, (uint64_t)0);
        ASSERT_EQ(stats.loss_ppm, (uint64_t)0);
        gamelink_stats(&a, &stats);
        ASSERT_EQ(stats.sent, (uint64_t)1000);
    } TEST_END;
    gamelink_close(&a);
    gamelink_close(&b);
    return failures;
}

static int gl_case_reorder_and_replay(void)
{
    int failures = 0;
    struct gamelink a = {.socket = -1}, b = {.socket = -1};
    TEST_CASE("gamelink: reordered arrives, duplicate and stale are dropped") {
        ASSERT(gl_relay_open());
        ASSERT(gl_open_pair(&a, &b, g_relay.port));
        for (uint8_t i = 0; i < 5; i++)
            ASSERT_EQ(gl_send_fill(&a, i, 8u), (int)GAMELINK_OK);
        ASSERT_EQ(gl_relay_capture(5), (size_t)5);
        gl_sink_reset();
        /* 0, 1, 2 in order, then 4 — which leaves 3 late but inside the
         * reorder window, and a late datagram the window still has room for
         * is DELIVERED, not dropped. */
        size_t order[] = {0, 1, 2, 4, 3};
        for (size_t i = 0; i < 5; i++) {
            ASSERT(gl_relay_forward(order[i], b.local_port, SIZE_MAX));
            ASSERT(gl_receive(&b, 1));
        }
        ASSERT_EQ(g_sink.count, (size_t)5);
        ASSERT_EQ(g_sink.seq[3], (uint64_t)4);
        ASSERT_EQ(g_sink.seq[4], (uint64_t)3);
        struct gamelink_stats stats;
        gamelink_stats(&b, &stats);
        ASSERT_EQ(stats.dropped_old, (uint64_t)0);
        /* The same bytes again: every one is a duplicate the window already
         * holds, and none of them is delivered a second time. */
        for (size_t i = 0; i < 5; i++) {
            ASSERT(gl_relay_forward(i, b.local_port, SIZE_MAX));
            ASSERT(gl_receive(&b, 1));
        }
        ASSERT_EQ(g_sink.count, (size_t)5);
        gamelink_stats(&b, &stats);
        ASSERT_EQ(stats.dropped_old, (uint64_t)5);
        ASSERT_EQ(stats.recv, (uint64_t)5);
        /* Push the window far ahead, then replay a datagram from before it.
         * That one is not a duplicate the window remembers — it is older
         * than the window reaches, the same refusal for a different reason,
         * and it must never become a delivery either. */
        a.send_seq = 5000;
        ASSERT_EQ(gl_send_fill(&a, 0x5A, 8u), (int)GAMELINK_OK);
        ASSERT_EQ(gl_relay_capture(1), (size_t)1);
        ASSERT(gl_relay_forward(5, b.local_port, SIZE_MAX));
        ASSERT(gl_receive(&b, 1));
        ASSERT_EQ(g_sink.count, (size_t)6);
        ASSERT(gl_relay_forward(0, b.local_port, SIZE_MAX));
        ASSERT(gl_receive(&b, 1));
        ASSERT_EQ(g_sink.count, (size_t)6);
        gamelink_stats(&b, &stats);
        ASSERT_EQ(stats.dropped_old, (uint64_t)6);
    } TEST_END;
    gamelink_close(&a);
    gamelink_close(&b);
    gl_relay_close();
    return failures;
}

static int gl_case_tamper(void)
{
    int failures = 0;
    struct gamelink a = {.socket = -1}, b = {.socket = -1};
    TEST_CASE("gamelink: one flipped byte is dropped and the session lives") {
        ASSERT(gl_relay_open());
        ASSERT(gl_open_pair(&a, &b, g_relay.port));
        ASSERT_EQ(gl_send_fill(&a, 0x3C, 16u), (int)GAMELINK_OK);
        ASSERT_EQ(gl_relay_capture(1), (size_t)1);
        gl_sink_reset();
        struct gamelink_stats stats;
        /* A byte of ciphertext. */
        ASSERT(gl_relay_forward(0, b.local_port, GAMELINK_HEADER_BYTES + 2u));
        ASSERT(gl_receive(&b, 1));
        gamelink_stats(&b, &stats);
        ASSERT_EQ(g_sink.count, (size_t)0);
        ASSERT_EQ(stats.dropped_auth, (uint64_t)1);
        /* A byte of the header, which the AEAD covers as additional data. */
        ASSERT(gl_relay_forward(0, b.local_port, 20u));
        ASSERT(gl_receive(&b, 1));
        gamelink_stats(&b, &stats);
        ASSERT_EQ(g_sink.count, (size_t)0);
        ASSERT_EQ(stats.dropped_auth, (uint64_t)2);
        /* The magic, which never even reaches the cipher. */
        ASSERT(gl_relay_forward(0, b.local_port, 0u));
        ASSERT(gl_receive(&b, 1));
        gamelink_stats(&b, &stats);
        ASSERT_EQ(stats.dropped_malformed, (uint64_t)1);
        /* The untouched original still arrives: the session took three bad
         * datagrams and stayed up, because on an open UDP port a bad
         * datagram is weather, not an incident. */
        ASSERT(gl_relay_forward(0, b.local_port, SIZE_MAX));
        ASSERT(gl_receive(&b, 1));
        ASSERT_EQ(g_sink.count, (size_t)1);
        ASSERT_EQ(g_sink.len[0], (size_t)16);
        ASSERT_EQ(g_sink.first_byte[0], (uint8_t)0x3C);
    } TEST_END;
    gamelink_close(&a);
    gamelink_close(&b);
    gl_relay_close();
    return failures;
}

static int gl_case_nonce_wrap(void)
{
    int failures = 0;
    struct gamelink a = {.socket = -1}, b = {.socket = -1};
    TEST_CASE("gamelink: the last nonce is refused, never wrapped") {
        ASSERT(gl_open_pair(&a, &b, 0));
        a.send_seq = UINT64_MAX - 1u;
        ASSERT_EQ(gl_send_fill(&a, 0, 8u), (int)GAMELINK_OK);
        ASSERT_EQ(a.send_seq, UINT64_MAX);
        ASSERT_EQ(gl_send_fill(&a, 0, 8u), (int)GAMELINK_NONCE_EXHAUSTED);
        /* It stays refused. A session at the end of its nonce space does not
         * recover; it is replaced. */
        ASSERT_EQ(gl_send_fill(&a, 0, 8u), (int)GAMELINK_NONCE_EXHAUSTED);
        ASSERT_EQ(a.send_seq, UINT64_MAX);
        ASSERT_STR_EQ(gamelink_status_label(GAMELINK_NONCE_EXHAUSTED),
                      "nonce_exhausted");
    } TEST_END;
    gamelink_close(&a);
    gamelink_close(&b);
    return failures;
}

static int gl_case_round_trip(void)
{
    int failures = 0;
    struct gamelink a = {.socket = -1}, b = {.socket = -1};
    TEST_CASE("gamelink: round trip is the injected delta, jitter is EWMA") {
        g_ticks.ns = 0;
        ASSERT(gl_open_pair(&a, &b, 0));
        /* Ping at t=0, answered and read at t=5 ms. */
        ASSERT_EQ(gamelink_ping(&a), GAMELINK_OK);
        g_ticks.ns = 5000000;
        ASSERT_EQ(platform_socket_wait_readable((platform_socket_t)b.socket, 1000), 1);
        ASSERT_EQ(gamelink_probe_serve(&b), (size_t)0);
        gl_sink_reset();
        ASSERT(gl_receive(&a, 1));
        struct gamelink_stats stats;
        gamelink_stats(&a, &stats);
        ASSERT_EQ(stats.rtt_us, (uint64_t)5000);
        ASSERT_EQ(stats.jitter_us, (uint64_t)0);
        ASSERT_EQ(stats.pongs_recv, (uint64_t)1);
        /* A control frame is never handed to the application. */
        ASSERT_EQ(g_sink.count, (size_t)0);
        /* Second round trip, 7 ms. RFC 3550's shape moves jitter by a
         * sixteenth of the change: |7000 - 5000| / 16 = 125. */
        ASSERT_EQ(gamelink_ping(&a), GAMELINK_OK);
        g_ticks.ns = 12000000;
        ASSERT_EQ(platform_socket_wait_readable((platform_socket_t)b.socket, 1000), 1);
        ASSERT_EQ(gamelink_probe_serve(&b), (size_t)0);
        ASSERT(gl_receive(&a, 1));
        gamelink_stats(&a, &stats);
        ASSERT_EQ(stats.rtt_us, (uint64_t)7000);
        ASSERT_EQ(stats.jitter_us, (uint64_t)125);
        /* And the probe loop reports what it actually saw, not what it sent. */
        uint64_t a_seen = gl_seen(&a), b_seen = gl_seen(&b);
        uint64_t pongs_before = stats.pongs_recv;
        size_t observed = gamelink_probe_run(&a, &b, 4, 0);
        gamelink_stats(&a, &stats);
        ASSERT_EQ((uint64_t)observed, stats.pongs_recv - pongs_before);
        ASSERT(gl_drain_until(&b, b_seen + 4));
        ASSERT(gl_drain_until(&a, a_seen + 4));
        gamelink_stats(&a, &stats);
        ASSERT_EQ(stats.pongs_recv - pongs_before, (uint64_t)4);
        gamelink_stats(&a, &stats);
        ASSERT_EQ(stats.pongs_recv, (uint64_t)6);
    } TEST_END;
    gamelink_close(&a);
    gamelink_close(&b);
    return failures;
}

static int gl_case_loss(void)
{
    int failures = 0;
    struct gamelink a = {.socket = -1}, b = {.socket = -1};
    TEST_CASE("gamelink: a gap in the sequence becomes a loss estimate") {
        ASSERT(gl_relay_open());
        ASSERT(gl_open_pair(&a, &b, g_relay.port));
        for (uint8_t i = 0; i < 4; i++)
            ASSERT_EQ(gl_send_fill(&a, i, 8u), (int)GAMELINK_OK);
        ASSERT_EQ(gl_relay_capture(4), (size_t)4);
        gl_sink_reset();
        /* Everything but sequence 2 reaches the far end. */
        size_t keep[] = {0, 1, 3};
        for (size_t i = 0; i < 3; i++) {
            ASSERT(gl_relay_forward(keep[i], b.local_port, SIZE_MAX));
            ASSERT(gl_receive(&b, 1));
        }
        ASSERT_EQ(g_sink.count, (size_t)3);
        struct gamelink_stats stats;
        gamelink_stats(&b, &stats);
        /* Four sequence numbers were spent and three arrived: one in four. */
        ASSERT_EQ(stats.loss_ppm, (uint64_t)250000);
        ASSERT_EQ(stats.recv, (uint64_t)3);
    } TEST_END;
    gamelink_close(&a);
    gamelink_close(&b);
    gl_relay_close();
    return failures;
}

static int gl_case_wrong_key(void)
{
    int failures = 0;
    struct gamelink b = {.socket = -1}, wrong = {.socket = -1};
    TEST_CASE("gamelink: a peer with the wrong key delivers nothing") {
        ASSERT_EQ(gamelink_open(&b, g_material, sizeof g_material, false,
                                "127.0.0.1:0", NULL, &g_clock), GAMELINK_OK);
        char endpoint[64];
        ASSERT((size_t)snprintf(endpoint, sizeof endpoint, "127.0.0.1:%u",
                                (unsigned)b.local_port) < sizeof endpoint);
        ASSERT_EQ(gamelink_open(&wrong, g_other_material,
                                sizeof g_other_material, true, "127.0.0.1:0",
                                endpoint, &g_clock), GAMELINK_OK);
        gl_sink_reset();
        for (size_t i = 0; i < 8; i++)
            ASSERT_EQ(gl_send_fill(&wrong, 0x77, 32u), (int)GAMELINK_OK);
        ASSERT(gl_receive(&b, 8));
        struct gamelink_stats stats;
        gamelink_stats(&b, &stats);
        ASSERT_EQ(g_sink.count, (size_t)0);
        ASSERT_EQ(stats.recv, (uint64_t)0);
        /* Different material derives a different session id, so these never
         * reach the cipher — and the peer this endpoint would answer was
         * never learned from a datagram that did not authenticate. */
        ASSERT_EQ(stats.dropped_malformed, (uint64_t)8);
        ASSERT_EQ((int)b.peer_port, 0);
    } TEST_END;
    gamelink_close(&b);
    gamelink_close(&wrong);
    return failures;
}

static int gl_case_caps(void)
{
    int failures = 0;
    struct gamelink a = {.socket = -1}, b = {.socket = -1};
    static uint8_t payload[GAMELINK_MAX_PAYLOAD + 1];
    TEST_CASE("gamelink: an oversize payload is refused at the sender") {
        memset(payload, 0xA5, sizeof payload);
        ASSERT(gl_open_pair(&a, &b, 0));
        ASSERT_EQ(gamelink_send(&a, payload, GAMELINK_MAX_PAYLOAD + 1u, NULL),
                  GAMELINK_TOO_LARGE);
        /* The sequence number was not spent by the refusal: a refused send
         * is not a send, and a gap here would read as loss at the far end. */
        ASSERT_EQ(a.send_seq, (uint64_t)0);
        ASSERT_EQ(gamelink_send(&a, payload, GAMELINK_MAX_PAYLOAD, NULL),
                  GAMELINK_OK);
        ASSERT_EQ(a.send_seq, (uint64_t)1);
        gl_sink_reset();
        ASSERT(gl_receive(&b, 1));
        ASSERT_EQ(g_sink.count, (size_t)1);
        ASSERT_EQ(g_sink.len[0], (size_t)GAMELINK_MAX_PAYLOAD);
        /* And the byte cap is a number, not a convention. */
        a.bucket_bytes = 4;
        ASSERT_EQ(gamelink_send(&a, payload, 64u, NULL), GAMELINK_RATE);
        ASSERT_EQ(a.send_seq, (uint64_t)1);
    } TEST_END;
    gamelink_close(&a);
    gamelink_close(&b);
    return failures;
}

int test_gamelink(void)
{
    gl_fill_material(g_material, 0x11);
    gl_fill_material(g_other_material, 0x99);
    g_relay.socket = -1;
    int failures = 0;
    failures += gl_case_derivation();
    failures += gl_case_thousand_in_order();
    failures += gl_case_reorder_and_replay();
    failures += gl_case_tamper();
    failures += gl_case_nonce_wrap();
    failures += gl_case_round_trip();
    failures += gl_case_loss();
    failures += gl_case_wrong_key();
    failures += gl_case_caps();
    return failures;
}
