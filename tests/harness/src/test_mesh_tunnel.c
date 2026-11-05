/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Proves the TCP tunnel service over a two-peer loopback: two real p2p
 * nodes at each end of the shared fixture's in-process Noise pair, the
 * production stream encoder and decoder carrying every frame, and real
 * loopback sockets at both ends. Covers the two admission gates (an unpaired
 * peer never reaches the service; a port no allow row names is refused by
 * that name), bytes both ways, the credit window stopping a sender whose
 * reader stopped, the listing, and close in both directions. Every refusal is
 * checked by the token on the wire.
 */

#include "test/test_core.h"

#include "config/boot_internal.h"
#include "../../../engine/composition/src/boot_mesh_status_internal.h"
#include "config/mesh_stream.h"
#include "config/mesh_tunnel.h"
#include "config/runtime.h"
#include "test/mesh_stream_fixture.h"
#include "test/mesh_term_fixture.h"

#include "base/safe_alloc.h"
#include "chain/chainparams.h"
#include "models/mesh_pairing.h"
#include "net/msgprocessor.h"
#include "net/net.h"
#include "net/noise_transport.h"
#include "net/protocol.h"
#include "platform/private_directory.h"
#include "platform/socket_compat.h"
#include "platform/time_compat.h"
#include "rpc/server.h"
#include "json/json.h"

#include <stdlib.h>
#include <string.h>

#define TUNNEL_TEST_WIRE_MAX 32768u
/* A pairing window that brackets any clock this test could read. */
#define TUNNEL_TEST_PAIRED_AT INT64_C(1)
#define TUNNEL_TEST_EXPIRES INT64_C(4102444800)
/* The offset of a CLOSE frame's service payload: prefix, kind, id, reason,
 * length. The stream layer composes it; this test reads it back. */
#define TUNNEL_TEST_CLOSE_PAYLOAD (MESH_STREAM_FRAME_PREFIX_LEN + 1u + 8u + 3u)
/* Enough ticks for one loopback round trip to settle, and short enough
 * that a wedged copy fails the assertion instead of the group. */
#define TUNNEL_TEST_SETTLE_ROUNDS 40
#define TUNNEL_TEST_IO_WAIT_MS 2000
/* Far more than the beats that follow it may carry, so a sender that
 * ignored its credit would be caught pushing the rest. */
#define TUNNEL_TEST_FLOOD_BYTES (size_t)(256u * 1024u)
#define TUNNEL_TEST_CLIENT_SNDBUF (1024 * 1024)
#define TUNNEL_TEST_CREDIT_ROUNDS 3

/* ── The loopback wire (the stream fixture's, one service further on) ─── */

static struct send_segment *tunnel_sentinel(struct p2p_node *node)
{
    struct send_segment *sentinel =
        zcl_calloc(1, sizeof(*sentinel), "tunnel_test_sentinel");
    node->send_head = sentinel;
    node->send_tail = sentinel;
    node->send_offset = 0;
    return sentinel;
}

static size_t tunnel_take(struct p2p_node *from, struct send_segment *sentinel,
                          struct noise_transport *to_transport, uint8_t *out,
                          size_t out_cap, bool *more)
{
    *more = false;
    struct send_segment *seg = sentinel->next;
    if (!seg)
        return 0;
    *more = true;
    sentinel->next = seg->next;
    if (from->send_tail == seg)
        from->send_tail = sentinel;
    if (from->send_size >= seg->size)
        from->send_size -= seg->size;
    else
        from->send_size = 0;
    from->send_offset = 0;

    uint8_t *wire = NULL, *plain = NULL;
    size_t wire_len = 0, plain_len = 0, moved = 0;
    if (noise_transport_feed(to_transport, seg->data, seg->size, &wire,
                             &wire_len, &plain, &plain_len) &&
        wire_len == 0 && plain_len > MSG_HEADER_SIZE &&
        memcmp(plain + MESSAGE_START_SIZE, "zpkgswm", 7) == 0) {
        size_t payload_len = plain_len - MSG_HEADER_SIZE;
        if (payload_len <= out_cap) {
            memcpy(out, plain + MSG_HEADER_SIZE, payload_len);
            moved = payload_len;
        }
    }
    free(wire);
    free(plain);
    send_segment_free(seg);
    return moved;
}

static size_t tunnel_pump(struct p2p_node *from, struct send_segment *sentinel,
                          struct noise_transport *to_transport,
                          struct msg_processor *mp, struct p2p_node *to)
{
    size_t frames = 0;
    for (;;) {
        uint8_t frame[TUNNEL_TEST_WIRE_MAX];
        bool more = false;
        size_t n = tunnel_take(from, sentinel, to_transport, frame,
                               sizeof(frame), &more);
        if (!more)
            break;
        if (n && mesh_stream_frame(mp, to, frame, n, NULL))
            frames++;
    }
    return frames;
}

/* ── Real loopback sockets ───────────────────────────────────────────── */

static platform_socket_t tunnel_listen_local(uint16_t *port, int rcvbuf)
{
    platform_socket_t sock =
        platform_socket_open(AF_INET, SOCK_STREAM, 0, true, false);
    if (sock == PLATFORM_SOCKET_INVALID)
        return PLATFORM_SOCKET_INVALID;
    if (rcvbuf)
        (void)platform_socket_set_receive_buffer(sock, rcvbuf);
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (platform_socket_bind(sock, (struct sockaddr *)&addr, sizeof(addr)) !=
            0 ||
        platform_socket_listen(sock, 4) != 0) {
        (void)platform_socket_close(sock);
        return PLATFORM_SOCKET_INVALID;
    }
    struct sockaddr_in got;
    size_t got_len = sizeof(got);
    memset(&got, 0, sizeof(got));
    if (platform_socket_local_address(sock, (struct sockaddr *)&got,
                                      &got_len) != 0) {
        (void)platform_socket_close(sock);
        return PLATFORM_SOCKET_INVALID;
    }
    *port = ntohs(got.sin_port);
    return sock;
}

static platform_socket_t tunnel_dial_local(uint16_t port)
{
    platform_socket_t sock =
        platform_socket_open(AF_INET, SOCK_STREAM, 0, true, false);
    if (sock == PLATFORM_SOCKET_INVALID)
        return PLATFORM_SOCKET_INVALID;
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (platform_socket_connect(sock, (struct sockaddr *)&addr,
                                sizeof(addr)) != 0) {
        (void)platform_socket_close(sock);
        return PLATFORM_SOCKET_INVALID;
    }
    (void)platform_socket_set_nonblocking(sock, true);
    return sock;
}

static platform_socket_t tunnel_accept_local(platform_socket_t listener)
{
    if (platform_socket_wait_readable(listener, TUNNEL_TEST_IO_WAIT_MS) <= 0)
        return PLATFORM_SOCKET_INVALID;
    struct sockaddr_in from;
    size_t from_len = sizeof(from);
    memset(&from, 0, sizeof(from));
    platform_socket_t got =
        platform_socket_accept(listener, (struct sockaddr *)&from, &from_len);
    if (got != PLATFORM_SOCKET_INVALID)
        (void)platform_socket_set_nonblocking(got, true);
    return got;
}

static void tunnel_drop(platform_socket_t *sock)
{
    if (*sock == PLATFORM_SOCKET_INVALID)
        return;
    (void)platform_socket_close(*sock);
    *sock = PLATFORM_SOCKET_INVALID;
}

/* Read exactly `want` bytes, waiting between attempts. False when the
 * bytes never arrive, which is the failure this test is looking for. */
static bool tunnel_read_exact(platform_socket_t sock, char *out, size_t want)
{
    size_t got = 0;
    while (got < want) {
        if (platform_socket_wait_readable(sock, TUNNEL_TEST_IO_WAIT_MS) <= 0)
            return false;
        int n = platform_socket_receive_nonblocking(sock, out + got,
                                                    want - got);
        if (n <= 0)
            return false;
        got += (size_t)n;
    }
    return true;
}

/* Everything the socket has right now, thrown away; returns the count. */
static size_t tunnel_drain(platform_socket_t sock)
{
    size_t total = 0;
    for (;;) {
        char buf[8192];
        if (platform_socket_wait_readable(sock, 50) <= 0)
            return total;
        int n = platform_socket_receive_nonblocking(sock, buf, sizeof(buf));
        if (n <= 0)
            return total;
        total += (size_t)n;
    }
}

/* ── The fixture's two sides, and the beats that move them ───────────── */

struct tunnel_test_wire {
    struct msg_processor *mp;
    struct p2p_node *a;
    struct p2p_node *b;
    struct send_segment *a_queue;
    struct send_segment *b_queue;
    struct mesh_term_fixture *f;
};

/* One production beat on both sides plus one frame exchange each way: the
 * listener accepts, each live stream copies, and the frames land. */
static void tunnel_beat(struct tunnel_test_wire *w, int rounds)
{
    for (int i = 0; i < rounds; i++) {
        mesh_tunnel_test_tick(TUNNEL_TEST_PAIRED_AT + i);
        (void)tunnel_pump(w->a, w->a_queue, w->f->res_term, w->mp, w->b);
        (void)tunnel_pump(w->b, w->b_queue, w->f->term_peer.ini, w->mp, w->a);
    }
}

/* The pairing row that lets side A name side B — the fixture files rows
 * for its peers, and the responder identity needs one too. */
static bool tunnel_pair_responder(struct mesh_term_fixture *f, char out[65])
{
    struct db_mesh_pairing row;
    memset(&row, 0, sizeof(row));
    memcpy(row.network_genesis, f->genesis, 32);
    memcpy(row.peer_master_pubkey, f->resp_master_pub, 32);
    memcpy(row.peer_noise_pubkey, f->resp_noise_pub, 32);
    row.capability_mask = MESH_PAIRING_CAP_STATUS_READ;
    row.delegation_sequence = 1;
    row.paired_at = TUNNEL_TEST_PAIRED_AT;
    row.expires_at = TUNNEL_TEST_EXPIRES;
    if (!mesh_pairing_id_derive(row.network_genesis, row.peer_master_pubkey,
                                row.peer_noise_pubkey, row.pairing_id) ||
        !db_mesh_pairing_insert(&f->ndb, &row))
        return false;
    snprintf(out, 65, "%s", row.pairing_id);
    return true;
}

/* The OPEN payload a legitimate initiator composes: "ZTUN", version,
 * reserved, port. Built by hand so the refusal cases drive the production
 * decoder with bytes this test chose. */
static size_t tunnel_open_payload(uint16_t port, uint8_t out[8])
{
    memcpy(out, "ZTUN", 4);
    out[4] = 1;
    out[5] = 0;
    out[6] = (uint8_t)(port >> 8);
    out[7] = (uint8_t)(port & 0xffu);
    return 8u;
}

static bool tunnel_file_equals(const char *path, const char *expected,
                               size_t expected_len)
{
    FILE *file = fopen(path, "rb");
    if (!file)
        return false;
    char actual[1024];
    size_t got = fread(actual, 1, sizeof(actual), file);
    bool read_ok = !ferror(file);
    bool close_ok = fclose(file) == 0;
    bool ok = read_ok && close_ok && got == expected_len &&
              memcmp(actual, expected, expected_len) == 0;
    return ok;
}

static bool tunnel_failed_open_refused(struct tunnel_test_wire *wire,
                                       uint16_t port, uint64_t stream_id,
                                       platform_socket_t target)
{
    uint8_t payload[8], frame[TUNNEL_TEST_WIRE_MAX];
    size_t payload_len = tunnel_open_payload(port, payload);
    size_t frame_len = mesh_stream_test_open_frame(
        stream_id, MESH_TUNNEL_CHUNK, MESH_TUNNEL_SERVICE_NAME, payload,
        payload_len, frame, sizeof(frame));
    if (!frame_len || !mesh_stream_frame(wire->mp, wire->b, frame, frame_len,
                                         NULL))
        return false;
    uint8_t answer[TUNNEL_TEST_WIRE_MAX];
    bool more = false;
    size_t answer_len = tunnel_take(wire->b, wire->b_queue,
                                    wire->f->term_peer.ini, answer,
                                    sizeof(answer), &more);
    uint8_t kind = 0;
    const char *token = "tunnel_target_not_allowed";
    if (!more || answer_len < TUNNEL_TEST_CLOSE_PAYLOAD + strlen(token) ||
        !mesh_stream_test_read_header(answer, answer_len, &kind, NULL))
        return false;
    return kind == MESH_STREAM_KIND_CLOSE &&
           answer[MESH_STREAM_FRAME_PREFIX_LEN + 1u + 8u] ==
               MESH_STREAM_CLOSED_BY_SERVICE &&
           memcmp(answer + TUNNEL_TEST_CLOSE_PAYLOAD, token,
                  strlen(token)) == 0 &&
           mesh_stream_test_live_count(MESH_TUNNEL_SERVICE_NAME) == 0 &&
           platform_socket_wait_readable(target, 0) <= 0;
}

struct tunnel_allow_case {
    char path[512];
    char staging[544];
    char bytes[256];
    size_t bytes_len;
    uint16_t committed_port;
};

static bool tunnel_allow_case_start(struct tunnel_allow_case *c,
                                    const char *dir, const char *peer,
                                    uint16_t target_port)
{
    int path_len = snprintf(c->path, sizeof(c->path), "%s/%s", dir,
                            MESH_TUNNEL_ALLOW_FILE);
    int staging_len = snprintf(c->staging, sizeof(c->staging), "%s.tmp",
                               c->path);
    if (path_len <= 0 || path_len >= (int)sizeof(c->path) ||
        staging_len <= 0 || staging_len >= (int)sizeof(c->staging))
        return false;
    c->committed_port = target_port == UINT16_MAX ? target_port - 1u
                                                 : target_port + 1u;
    if (mesh_tunnel_allow(peer, c->committed_port, "committed reason") !=
        MESH_TUNNEL_OK)
        return false;
    int bytes_len = snprintf(
        c->bytes, sizeof(c->bytes),
        "# <pairing id> <port> <why> — nothing is allowed without a row here\n"
        "%s %u committed reason\n", peer, (unsigned)c->committed_port);
    if (bytes_len <= 0 || bytes_len >= (int)sizeof(c->bytes))
        return false;
    c->bytes_len = (size_t)bytes_len;
    return tunnel_file_equals(c->path, c->bytes, c->bytes_len) &&
           platform_private_directory_create(c->staging);
}

static bool tunnel_allow_snapshot_matches(const struct tunnel_allow_case *c,
                                          const char *peer)
{
    struct mesh_tunnel_allow_row rows[MESH_TUNNEL_ALLOW_MAX];
    size_t total = SIZE_MAX;
    return mesh_tunnel_allow_list(rows, MESH_TUNNEL_ALLOW_MAX, &total) == 1 &&
           total == 1 && rows[0].port == c->committed_port &&
           strcmp(rows[0].peer, peer) == 0 &&
           strcmp(rows[0].why, "committed reason") == 0 &&
           tunnel_file_equals(c->path, c->bytes, c->bytes_len);
}

static bool tunnel_allow_recovery_matches(const struct tunnel_allow_case *c,
                                          const char *peer, uint16_t port)
{
    if (mesh_tunnel_allow(peer, port, "ordinary addition") != MESH_TUNNEL_OK ||
        mesh_tunnel_allow(peer, c->committed_port, "ordinary update") !=
            MESH_TUNNEL_OK)
        return false;
    struct mesh_tunnel_allow_row rows[MESH_TUNNEL_ALLOW_MAX];
    size_t total = SIZE_MAX;
    return mesh_tunnel_allow_list(rows, MESH_TUNNEL_ALLOW_MAX, &total) == 2 &&
           total == 2 && strcmp(rows[0].why, "ordinary update") == 0;
}

static int tunnel_allow_transaction_case(struct tunnel_test_wire *wire,
                                         uint16_t port,
                                         platform_socket_t target,
                                         const char *dir)
{
    int failures = 0;
    struct tunnel_allow_case c = {0};
    bool collision = false;
    const char *peer = wire->f->term_peer.pairing.pairing_id;
    TEST("mesh tunnel: failed persistence never admits an owned target") {
        ASSERT(tunnel_allow_case_start(&c, dir, peer, port));
        collision = true;
        ASSERT_EQ(mesh_tunnel_allow(peer, port, "must not persist"),
                  MESH_TUNNEL_REFUSED_UNAVAILABLE);
        /* Production OPEN precedes every rollback list assertion. */
        ASSERT(tunnel_failed_open_refused(wire, port, 4, target));
        ASSERT(tunnel_allow_snapshot_matches(&c, peer));
        ASSERT_EQ(mesh_tunnel_allow(peer, c.committed_port, "changed reason"),
                  MESH_TUNNEL_REFUSED_UNAVAILABLE);
        ASSERT(tunnel_allow_snapshot_matches(&c, peer));
        ASSERT(platform_private_directory_remove_empty(c.staging));
        collision = false;
        ASSERT(tunnel_allow_recovery_matches(&c, peer, port));
        PASS();
    }
_test_next:
    if (collision && !platform_private_directory_remove_empty(c.staging)) {
        fprintf(stderr, "mesh tunnel: staging collision cleanup failed: %s\n",
                c.staging);
        failures++;
    }
    return failures;
}

#define TUNNEL_TEXT_PEER \
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
#define TUNNEL_TEXT_BEFORE TUNNEL_TEXT_PEER " 80 before\n"
#define TUNNEL_TEXT_AFTER TUNNEL_TEXT_PEER " 81 after\n"

static int tunnel_allow_text_cases(void)
{
    int failures = 0;
    char dir[256], path[512];
    test_make_tmpdir(dir, sizeof(dir), "mesh_tunnel", "allow_text");
    snprintf(path, sizeof(path), "%s/%s", dir, MESH_TUNNEL_ALLOW_FILE);
    struct boot_svc_ctx svc = {0};
    svc.datadir = dir;
    TEST("mesh tunnel: missing allow file grants nothing") {
        mesh_tunnel_test_bind(&svc);
        size_t total = SIZE_MAX;
        ASSERT_EQ(mesh_tunnel_allow_list(NULL, 0, &total), (size_t)0);
        ASSERT_EQ(total, (size_t)0);
        PASS();
    }
    static const char hidden[] = TUNNEL_TEXT_BEFORE
        TUNNEL_TEXT_PEER " 22\0junk\n" TUNNEL_TEXT_AFTER;
    static const char partial[] = TUNNEL_TEXT_BEFORE TUNNEL_TEXT_PEER " 2";
    static const char partial_lf[] = TUNNEL_TEXT_BEFORE
        TUNNEL_TEXT_PEER " 2\n" TUNNEL_TEXT_AFTER;
    static const char leading[] = TUNNEL_TEXT_BEFORE
        "\0" TUNNEL_TEXT_PEER " 22\n" TUNNEL_TEXT_AFTER;
    static const char between[] = TUNNEL_TEXT_BEFORE "\0\n" TUNNEL_TEXT_AFTER;
    static const char space[] = TUNNEL_TEXT_BEFORE TUNNEL_TEXT_PEER " ";
    static const char valid[] = TUNNEL_TEXT_PEER " 80 \xc2\xa2\r\n"
        TUNNEL_TEXT_PEER " 81 \n";
    static const char final[] = TUNNEL_TEXT_PEER " 80 before";
    static const char final_empty[] = TUNNEL_TEXT_BEFORE
        TUNNEL_TEXT_PEER " 81 ";
    const struct {
        const char *bytes;
        size_t len, count;
    } cases[] = {
        {hidden, sizeof(hidden) - 1, 2},
        {partial, sizeof(partial) - 1, 1},
        {partial_lf, sizeof(partial_lf) - 1, 2},
        {leading, sizeof(leading) - 1, 2},
        {between, sizeof(between) - 1, 2},
        {space, sizeof(space) - 1, 1},
        {valid, sizeof(valid) - 1, 2},
        {final, sizeof(final) - 1, 1},
        {final_empty, sizeof(final_empty) - 1, 2},
        {"", 0, 0},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        TEST("mesh tunnel: counted complete allow records") {
            FILE *fp = fopen(path, "wb");
            ASSERT(fp != NULL);
            size_t wrote = fwrite(cases[i].bytes, 1, cases[i].len, fp);
            int closed = fclose(fp);
            ASSERT_EQ(wrote, cases[i].len);
            ASSERT_EQ(closed, 0);
            mesh_tunnel_test_bind(&svc);
            struct mesh_tunnel_allow_row rows[3];
            size_t total = SIZE_MAX;
            ASSERT_EQ(mesh_tunnel_allow_list(rows, 3, &total), cases[i].count);
            ASSERT_EQ(total, cases[i].count);
            for (size_t j = 0; j < total; j++) {
                ASSERT_EQ(rows[j].port, 80u + j);
                ASSERT_STR_EQ(rows[j].peer, TUNNEL_TEXT_PEER);
            }
            PASS();
        }
    }
_test_next:
    mesh_tunnel_test_reset();
    mesh_tunnel_test_bind(NULL);
    test_cleanup_tmpdir(dir);
    return failures;
}

static void tunnel_test_node_drop(struct p2p_node *node,
                                  struct send_segment *queue)
{
    if (!node)
        return;
    while (queue && queue->next) {
        struct send_segment *seg = queue->next;
        queue->next = seg->next;
        send_segment_free(seg);
    }
    node->send_head = NULL;
    node->send_tail = NULL;
    node->transport = NULL; /* owned by the fixture */
    p2p_node_free(node);
}

/* One byte each way through the tunnel: the proof a connection still
 * carries traffic. Beats run until the byte lands or the rounds run out. */
static bool tunnel_roundtrip(struct tunnel_test_wire *wire,
                             platform_socket_t client,
                             platform_socket_t served)
{
    char got[2] = {0};
    if (platform_socket_send_nonblocking(client, "x", 1) != 1)
        return false;
    for (int i = 0; i < TUNNEL_TEST_SETTLE_ROUNDS; i++) {
        tunnel_beat(wire, 1);
        if (platform_socket_wait_readable(served, 0) > 0)
            break;
    }
    if (!tunnel_read_exact(served, got, 1) || got[0] != 'x')
        return false;
    if (platform_socket_send_nonblocking(served, "y", 1) != 1)
        return false;
    for (int i = 0; i < TUNNEL_TEST_SETTLE_ROUNDS; i++) {
        tunnel_beat(wire, 1);
        if (platform_socket_wait_readable(client, 0) > 0)
            break;
    }
    return tunnel_read_exact(client, got, 1) && got[0] == 'y';
}

/* Take the acceptor's next frame and report whether it is a CLOSE from
 * the service carrying exactly `token`. The frame stays in `answer` so the
 * caller can deliver it onward. */
static bool tunnel_take_close(struct tunnel_test_wire *wire,
                              const char *token, uint8_t *answer,
                              size_t answer_cap, size_t *answer_len)
{
    bool more = false;
    *answer_len = tunnel_take(wire->b, wire->b_queue,
                              wire->f->term_peer.ini, answer, answer_cap,
                              &more);
    uint8_t kind = 0;
    size_t want = strlen(token);
    return more && *answer_len >= TUNNEL_TEST_CLOSE_PAYLOAD + want &&
           mesh_stream_test_read_header(answer, *answer_len, &kind, NULL) &&
           kind == MESH_STREAM_KIND_CLOSE &&
           answer[MESH_STREAM_FRAME_PREFIX_LEN + 1u + 8u] ==
               MESH_STREAM_CLOSED_BY_SERVICE &&
           memcmp(answer + TUNNEL_TEST_CLOSE_PAYLOAD, token, want) == 0;
}

/* One tunnelled connection's four ends: the target stand-in, the entrance's
 * client, the target's accepted socket, and the entrance itself. */
struct tunnel_live_conn {
    platform_socket_t target;
    platform_socket_t client;
    platform_socket_t served;
    uint64_t id;
    uint16_t port;
    uint16_t entrance;
};

static void tunnel_live_init(struct tunnel_live_conn *c)
{
    memset(c, 0, sizeof(*c));
    c->target = PLATFORM_SOCKET_INVALID;
    c->client = PLATFORM_SOCKET_INVALID;
    c->served = PLATFORM_SOCKET_INVALID;
}

static void tunnel_live_drop(struct tunnel_live_conn *c)
{
    tunnel_drop(&c->client);
    tunnel_drop(&c->served);
    tunnel_drop(&c->target);
}

/* Allow one fresh loopback target for this peer, open an entrance onto it
 * and dial the entrance. The accept half waits for the beats in between. */
static bool tunnel_live_open(const char *paired, const char *peer_b,
                             const char *why, struct tunnel_live_conn *c)
{
    c->target = tunnel_listen_local(&c->port, 0);
    if (c->target == PLATFORM_SOCKET_INVALID ||
        mesh_tunnel_allow(paired, c->port, why) != MESH_TUNNEL_OK ||
        mesh_tunnel_listen(peer_b, c->port, 0, &c->id, &c->entrance) !=
            MESH_TUNNEL_OK)
        return false;
    c->client = tunnel_dial_local(c->entrance);
    return c->client != PLATFORM_SOCKET_INVALID;
}

static bool tunnel_live_accept(struct tunnel_live_conn *c)
{
    c->served = tunnel_accept_local(c->target);
    return c->served != PLATFORM_SOCKET_INVALID;
}

/* Deny removes the rows of one peer and port; the streams that row
 * admitted end before it returns, and nothing else does. */
static int tunnel_deny_live_case(struct tunnel_test_wire *wire,
                                 const char *peer_b)
{
    int failures = 0;
    struct tunnel_live_conn c1, c2;
    platform_socket_t c1b = PLATFORM_SOCKET_INVALID;
    tunnel_live_init(&c1);
    tunnel_live_init(&c2);
    const char *paired = wire->f->term_peer.pairing.pairing_id;
    TEST("mesh tunnel: deny closes the live streams of exactly that peer "
         "and port before it returns") {
        /* The stream layer admits a bounded number of OPENs per peer per
         * second and the cases above spent it; a fresh table starts a fresh
         * window. */
        mesh_stream_test_reset();
        ASSERT(tunnel_live_open(paired, peer_b, "deny-live one", &c1));
        ASSERT(tunnel_live_open(paired, peer_b, "deny-live two", &c2));
        ASSERT_EQ(mesh_tunnel_allow(TUNNEL_TEXT_PEER, c2.port, "other peer"),
                  MESH_TUNNEL_OK);
        tunnel_beat(wire, 2);
        ASSERT(tunnel_live_accept(&c1));
        ASSERT(tunnel_live_accept(&c2));
        tunnel_beat(wire, 2);
        ASSERT(tunnel_roundtrip(wire, c1.client, c1.served));
        ASSERT(tunnel_roundtrip(wire, c2.client, c2.served));

        bool live_before =
            mesh_stream_test_live_count(MESH_TUNNEL_SERVICE_NAME) == 4;
        ASSERT(live_before);
        tunnel_beat(wire, 2);

        /* Another peer's row on the same port goes: nothing of ours moves. */
        bool other_peer_row_survives_deny =
            mesh_tunnel_deny(TUNNEL_TEXT_PEER, c2.port) &&
            tunnel_roundtrip(wire, c2.client, c2.served) &&
            mesh_stream_test_live_count(MESH_TUNNEL_SERVICE_NAME) == 4;
        ASSERT(other_peer_row_survives_deny);
        tunnel_beat(wire, 2);

        bool deny_returns_true = mesh_tunnel_deny(paired, c1.port);
        ASSERT(deny_returns_true);
        /* No beat ran: the acceptor stream of connection one is already
         * gone; its initiator twin waits for the CLOSE frame. */
        bool closed_before_return =
            mesh_stream_test_live_count(MESH_TUNNEL_SERVICE_NAME) == 3;
        ASSERT(closed_before_return);
        char tail[2];
        bool target_connection_shut = !tunnel_read_exact(c1.served, tail, 1);
        ASSERT(target_connection_shut);

        uint8_t answer[TUNNEL_TEST_WIRE_MAX];
        size_t answer_len = 0;
        bool close_frame_token = tunnel_take_close(
            wire, "tunnel_target_denied", answer, sizeof(answer),
            &answer_len);
        ASSERT(close_frame_token);
        ASSERT(mesh_stream_frame(wire->mp, wire->a, answer, answer_len, NULL));
        tunnel_beat(wire, 4);
        bool initiator_client_sees_end = !tunnel_read_exact(c1.client, tail, 1);
        ASSERT(initiator_client_sees_end);
        bool other_port_still_carries =
            tunnel_roundtrip(wire, c2.client, c2.served) &&
            mesh_stream_test_live_count(MESH_TUNNEL_SERVICE_NAME) == 2;
        ASSERT(other_port_still_carries);

        /* A new connection on the denied entrance is refused by name: the
         * OPEN gate and deny agree. Only the initiator half of the beat
         * runs, so the acceptor's refusal is still queued to be read. */
        c1b = tunnel_dial_local(c1.entrance);
        ASSERT(c1b != PLATFORM_SOCKET_INVALID);
        mesh_tunnel_test_tick(TUNNEL_TEST_PAIRED_AT);
        mesh_tunnel_test_tick(TUNNEL_TEST_PAIRED_AT + 1);
        (void)tunnel_pump(wire->a, wire->a_queue, wire->f->res_term, wire->mp,
                          wire->b);
        bool new_connection_refused_by_name = tunnel_take_close(
            wire, "tunnel_target_not_allowed", answer, sizeof(answer),
            &answer_len);
        ASSERT(new_connection_refused_by_name);
        ASSERT(mesh_stream_frame(wire->mp, wire->a, answer, answer_len, NULL));
        tunnel_beat(wire, 4);

        size_t live_now =
            mesh_stream_test_live_count(MESH_TUNNEL_SERVICE_NAME);
        bool deny_missing_row_is_false =
            !mesh_tunnel_deny(paired, c1.port) &&
            mesh_stream_test_live_count(MESH_TUNNEL_SERVICE_NAME) == live_now;
        ASSERT(deny_missing_row_is_false);

        tunnel_live_drop(&c1);
        tunnel_live_drop(&c2);
        tunnel_drop(&c1b);
        ASSERT(mesh_tunnel_close(c1.id));
        ASSERT(mesh_tunnel_close(c2.id));
        tunnel_beat(wire, 4);
        ASSERT(mesh_tunnel_deny(paired, c2.port));
        PASS();
    }
_test_next:
    tunnel_live_drop(&c1);
    tunnel_live_drop(&c2);
    tunnel_drop(&c1b);
    return failures;
}

/* Missing authority during a periodic check must end the admitted acceptor,
 * while local listener lifetime and the initiator remain separately owned. */
static int tunnel_missing_db_live_case(struct tunnel_test_wire *wire,
                                       const char *peer_b,
                                       struct db_service *dbsvc)
{
    int failures = 0;
    struct tunnel_live_conn c;
    tunnel_live_init(&c);
    uint64_t idle_id = 0;
    uint16_t idle_port = 0;
    struct node_db *saved = dbsvc->node_db;
    const char *paired = wire->f->term_peer.pairing.pairing_id;
    TEST("mesh tunnel: missing pairing database ends an admitted acceptor "
         "by name without closing local listeners") {
        mesh_stream_test_reset();
        ASSERT(tunnel_live_open(paired, peer_b, "missing-db-live", &c));
        tunnel_beat(wire, 2);
        ASSERT(tunnel_live_accept(&c));
        tunnel_beat(wire, 2);
        ASSERT(tunnel_roundtrip(wire, c.client, c.served));
        ASSERT_EQ(mesh_stream_test_live_count(MESH_TUNNEL_SERVICE_NAME),
                  (size_t)2);
        ASSERT_EQ(mesh_tunnel_listen(peer_b, c.port, 0, &idle_id, &idle_port),
                  MESH_TUNNEL_OK);
        dbsvc->node_db = NULL;
        mesh_tunnel_test_tick(TUNNEL_TEST_PAIRED_AT + 1000);
        dbsvc->node_db = saved;
        ASSERT_EQ(mesh_stream_test_live_count(MESH_TUNNEL_SERVICE_NAME),
                  (size_t)1);
        char tail[2];
        ASSERT(platform_socket_wait_readable(c.served,
                                             TUNNEL_TEST_IO_WAIT_MS) > 0);
        ASSERT_EQ(platform_socket_receive_nonblocking(c.served, tail, 1), 0);
        uint8_t answer[TUNNEL_TEST_WIRE_MAX];
        size_t answer_len = 0;
        ASSERT(tunnel_take_close(wire, "tunnel_peer_unpaired", answer,
                                 sizeof(answer), &answer_len));
        struct mesh_tunnel_row rows[MESH_TUNNEL_LISTENERS_MAX];
        size_t total = 0;
        ASSERT_EQ(mesh_tunnel_list(rows, MESH_TUNNEL_LISTENERS_MAX, &total),
                  (size_t)2);
        ASSERT_EQ(total, (size_t)2);
        ASSERT(mesh_stream_frame(wire->mp, wire->a, answer, answer_len, NULL));
        tunnel_beat(wire, 4);
        ASSERT_EQ(mesh_stream_test_live_count(MESH_TUNNEL_SERVICE_NAME),
                  (size_t)0);
        PASS();
    }
_test_next:
    dbsvc->node_db = saved;
    tunnel_live_drop(&c);
    (void)mesh_tunnel_close(c.id);
    (void)mesh_tunnel_close(idle_id);
    (void)mesh_tunnel_deny(paired, c.port);
    tunnel_beat(wire, 4);
    return failures;
}

/* A pairing revoked while a stream is live: the acceptor's next check
 * reads the row, finds it gone, and ends the stream by name. */
static int tunnel_revoke_live_case(struct tunnel_test_wire *wire,
                                   const char *peer_b)
{
    int failures = 0;
    struct tunnel_live_conn c;
    tunnel_live_init(&c);
    const char *paired = wire->f->term_peer.pairing.pairing_id;
    TEST("mesh tunnel: a pairing revoked mid-stream ends the stream within "
         "one check interval") {
        /* A fresh table and open window, as above. */
        mesh_stream_test_reset();
        ASSERT(tunnel_live_open(paired, peer_b, "revoke-live", &c));
        tunnel_beat(wire, 2);
        ASSERT(tunnel_live_accept(&c));
        tunnel_beat(wire, 2);
        ASSERT(tunnel_roundtrip(wire, c.client, c.served));
        ASSERT_EQ(mesh_stream_test_live_count(MESH_TUNNEL_SERVICE_NAME),
                  (size_t)2);

        ASSERT(db_mesh_pairing_revoke(&wire->f->ndb, paired, 2400));
        /* One tick far past the last check: the acceptor re-reads the row. */
        mesh_tunnel_test_tick(TUNNEL_TEST_PAIRED_AT + 1000);
        char tail[2];
        bool revoked_stream_ended =
            mesh_stream_test_live_count(MESH_TUNNEL_SERVICE_NAME) == 1 &&
            !tunnel_read_exact(c.served, tail, 1);
        ASSERT(revoked_stream_ended);
        uint8_t answer[TUNNEL_TEST_WIRE_MAX];
        size_t answer_len = 0;
        bool revoked_token_on_wire = tunnel_take_close(
            wire, "tunnel_peer_unpaired", answer, sizeof(answer),
            &answer_len);
        ASSERT(revoked_token_on_wire);
        ASSERT(mesh_stream_frame(wire->mp, wire->a, answer, answer_len, NULL));
        tunnel_beat(wire, 4);
        ASSERT_EQ(mesh_stream_test_live_count(MESH_TUNNEL_SERVICE_NAME),
                  (size_t)0);

        tunnel_live_drop(&c);
        ASSERT(mesh_tunnel_close(c.id));
        ASSERT(mesh_tunnel_deny(paired, c.port));
        PASS();
    }
_test_next:
    tunnel_live_drop(&c);
    return failures;
}

/* ── The list reports health ─────────────────────────────────────────── */

/* Fixed stamps the health cases pin the tunnel clock to, so every
 * timestamp is asserted exactly. Distinct values, so a swap fails. */
#define TUNNEL_TEST_STAMP_ACTIVITY INT64_C(1000)
#define TUNNEL_TEST_STAMP_END INT64_C(2000)

/* The list row of one entrance, as the operator verb would render it. */
static bool tunnel_row_of(uint64_t id, struct mesh_tunnel_row *out)
{
    struct mesh_tunnel_row rows[MESH_TUNNEL_LISTENERS_MAX];
    size_t total = 0;
    size_t n = mesh_tunnel_list(rows, MESH_TUNNEL_LISTENERS_MAX, &total);
    for (size_t i = 0; i < n; i++)
        if (rows[i].tunnel_id == id) {
            *out = rows[i];
            return true;
        }
    return false;
}

/* Beat until the socket has bytes to read, or the rounds run out. */
static void tunnel_beat_until_readable(struct tunnel_test_wire *wire,
                                       platform_socket_t sock)
{
    for (int i = 0; i < TUNNEL_TEST_SETTLE_ROUNDS; i++) {
        tunnel_beat(wire, 1);
        if (platform_socket_wait_readable(sock, 0) > 0)
            return;
    }
}

/* Beat until the entrance's newest stream has ended, or the rounds run out.
 * A hang-up reaches the tunnel's socket when the kernel delivers it, which
 * is not inside a fixed number of beats on every host; the outcome waited
 * on is the row naming the end, and between beats the served socket (shut
 * when the far side ends) gets a short readable wait so a slow delivery
 * has real time to land. */
static void tunnel_beat_until_ended(struct tunnel_test_wire *wire,
                                    uint64_t id, platform_socket_t served)
{
    struct mesh_tunnel_row row;
    for (int i = 0; i < TUNNEL_TEST_SETTLE_ROUNDS; i++) {
        tunnel_beat(wire, 1);
        if (tunnel_row_of(id, &row) && row.streams_open == 0 &&
            row.last_stream_end_unix != 0)
            return;
        (void)platform_socket_wait_readable(served, 10);
    }
}

/* Close one finished entrance and take its allow row away. */
static bool tunnel_live_finish(struct tunnel_test_wire *wire,
                               struct tunnel_live_conn *c, const char *paired)
{
    tunnel_live_drop(c);
    bool closed = mesh_tunnel_close(c->id);
    tunnel_beat(wire, 4);
    return mesh_tunnel_deny(paired, c->port) && closed;
}

/* A fresh entrance reads zero and live; bytes toward the peer stamp the
 * activity; a clean end keeps the activity and names itself clean. */
static int tunnel_health_flow_case(struct tunnel_test_wire *wire,
                                   const char *peer_b)
{
    int failures = 0;
    struct tunnel_live_conn c;
    struct mesh_tunnel_row row;
    tunnel_live_init(&c);
    const char *paired = wire->f->term_peer.pairing.pairing_id;
    TEST("mesh tunnel: the list reports a fresh entrance as idle and live, "
         "stamps activity, and names a clean end") {
        mesh_stream_test_reset();
        ASSERT(tunnel_live_open(paired, peer_b, "health-flow", &c));
        /* C-fresh-1 */
        bool c_fresh_1 =
            tunnel_row_of(c.id, &row) && row.last_activity_unix == 0 &&
            row.last_stream_end_reason[0] == '\0' &&
            row.last_stream_end_unix == 0 && row.streams_failed_total == 0;
        ASSERT(c_fresh_1);
        /* C-fresh-2 */
        bool c_fresh_2 = row.peer_session == MESH_TUNNEL_PEER_SESSION_LIVE;
        ASSERT(c_fresh_2);
        tunnel_beat(wire, 2);
        ASSERT(tunnel_live_accept(&c));
        tunnel_beat(wire, 2);

        /* C-act-out: only the client side wrote. */
        mesh_tunnel_test_set_now(TUNNEL_TEST_STAMP_ACTIVITY);
        ASSERT(platform_socket_send_nonblocking(c.client, "to-peer", 7) == 7);
        tunnel_beat_until_readable(wire, c.served);
        char got[8];
        ASSERT(tunnel_read_exact(c.served, got, 7));
        bool c_act_out = tunnel_row_of(c.id, &row) &&
                         row.last_activity_unix == TUNNEL_TEST_STAMP_ACTIVITY;
        ASSERT(c_act_out);

        /* C-clean: the client hangs up, later. */
        mesh_tunnel_test_set_now(TUNNEL_TEST_STAMP_END);
        tunnel_drop(&c.client);
        tunnel_beat(wire, 4);
        tunnel_beat_until_ended(wire, c.id, c.served);
        bool c_clean =
            tunnel_row_of(c.id, &row) && row.streams_open == 0 &&
            row.streams_failed_total == 0 &&
            strcmp(row.last_stream_end_reason,
                   mesh_tunnel_refusal_string(MESH_TUNNEL_ENDED_LOCAL_CLOSE)) ==
                0 &&
            row.last_stream_end_unix == TUNNEL_TEST_STAMP_END;
        ASSERT(c_clean);
        /* The retired stream's activity outlives it, unchanged by the end. */
        bool c_clean_activity =
            row.last_activity_unix == TUNNEL_TEST_STAMP_ACTIVITY;
        ASSERT(c_clean_activity);
        ASSERT(tunnel_live_finish(wire, &c, paired));
        PASS();
    }
_test_next:
    mesh_tunnel_test_set_now(0);
    tunnel_live_drop(&c);
    (void)mesh_tunnel_close(c.id);
    return failures;
}

/* Bytes arriving from the peer stamp the activity on their own. */
static int tunnel_health_inbound_case(struct tunnel_test_wire *wire,
                                      const char *peer_b)
{
    int failures = 0;
    struct tunnel_live_conn c;
    struct mesh_tunnel_row row;
    tunnel_live_init(&c);
    const char *paired = wire->f->term_peer.pairing.pairing_id;
    TEST("mesh tunnel: bytes from the peer alone stamp the entrance's "
         "activity") {
        mesh_stream_test_reset();
        ASSERT(tunnel_live_open(paired, peer_b, "health-inbound", &c));
        tunnel_beat(wire, 2);
        ASSERT(tunnel_live_accept(&c));
        tunnel_beat(wire, 2);
        mesh_tunnel_test_set_now(TUNNEL_TEST_STAMP_ACTIVITY);
        ASSERT(platform_socket_send_nonblocking(c.served, "to-here", 7) == 7);
        tunnel_beat_until_readable(wire, c.client);
        char got[8];
        ASSERT(tunnel_read_exact(c.client, got, 7));
        /* C-act-in */
        bool c_act_in = tunnel_row_of(c.id, &row) &&
                        row.last_activity_unix == TUNNEL_TEST_STAMP_ACTIVITY;
        ASSERT(c_act_in);
        ASSERT(tunnel_live_finish(wire, &c, paired));
        PASS();
    }
_test_next:
    mesh_tunnel_test_set_now(0);
    (void)mesh_tunnel_close(c.id);
    tunnel_live_drop(&c);
    return failures;
}

/* An entrance whose far side has no allow row: the refusal token names the
 * end and the end counts as failed. */
static int tunnel_health_refused_case(struct tunnel_test_wire *wire,
                                      const char *peer_b)
{
    int failures = 0;
    platform_socket_t target = PLATFORM_SOCKET_INVALID;
    platform_socket_t client = PLATFORM_SOCKET_INVALID;
    uint64_t id = 0;
    bool open = false;
    struct mesh_tunnel_row row;
    TEST("mesh tunnel: a remote refusal is the named last end and counts "
         "as failed") {
        mesh_stream_test_reset();
        uint16_t port = 0, entrance = 0;
        target = tunnel_listen_local(&port, 0);
        ASSERT(target != PLATFORM_SOCKET_INVALID);
        ASSERT_EQ(mesh_tunnel_listen(peer_b, port, 0, &id, &entrance),
                  MESH_TUNNEL_OK);
        open = true;
        client = tunnel_dial_local(entrance);
        ASSERT(client != PLATFORM_SOCKET_INVALID);
        mesh_tunnel_test_set_now(TUNNEL_TEST_STAMP_END);
        tunnel_beat(wire, 6);
        /* C-fail-remote */
        bool c_fail_remote =
            tunnel_row_of(id, &row) && row.streams_failed_total == 1 &&
            strcmp(row.last_stream_end_reason,
                   mesh_tunnel_refusal_string(
                       MESH_TUNNEL_REFUSED_TARGET_NOT_ALLOWED)) == 0 &&
            row.last_stream_end_unix == TUNNEL_TEST_STAMP_END;
        ASSERT(c_fail_remote);
        tunnel_drop(&client);
        tunnel_drop(&target);
        ASSERT(mesh_tunnel_close(id));
        open = false;
        tunnel_beat(wire, 4);
        PASS();
    }
_test_next:
    mesh_tunnel_test_set_now(0);
    tunnel_drop(&client);
    tunnel_drop(&target);
    if (open)
        (void)mesh_tunnel_close(id);
    return failures;
}

/* The peer's session is gone, or this node cannot say: the row says so. */
static int tunnel_health_peer_case(struct tunnel_test_wire *wire,
                                   const char *peer_b)
{
    int failures = 0;
    struct tunnel_live_conn c;
    struct mesh_tunnel_row row;
    struct net_manager *nm = wire->mp->net_mgr;
    size_t nodes_saved = nm->num_nodes;
    tunnel_live_init(&c);
    const char *paired = wire->f->term_peer.pairing.pairing_id;
    TEST("mesh tunnel: a missing session reads absent with the open "
         "refusal named, and missing context reads unknown") {
        mesh_stream_test_reset();
        ASSERT(tunnel_live_open(paired, peer_b, "health-peer", &c));
        mesh_tunnel_test_set_now(TUNNEL_TEST_STAMP_END);
        nm->num_nodes = 0;
        tunnel_beat(wire, 2);
        /* C-fail-open */
        bool c_fail_open =
            tunnel_row_of(c.id, &row) &&
            row.peer_session == MESH_TUNNEL_PEER_SESSION_ABSENT &&
            row.streams_failed_total == 1 &&
            strcmp(row.last_stream_end_reason,
                   mesh_stream_refusal_string(
                       MESH_STREAM_REFUSED_PEER_NOT_CONNECTED)) == 0 &&
            row.last_stream_end_unix == TUNNEL_TEST_STAMP_END;
        ASSERT(c_fail_open);
        nm->num_nodes = nodes_saved;

        /* C-unknown */
        ASSERT_EQ((int)MESH_TUNNEL_PEER_SESSION_UNKNOWN, 0);
        wire->mp->net_mgr = NULL;
        bool c_unknown = tunnel_row_of(c.id, &row) &&
                         row.peer_session == MESH_TUNNEL_PEER_SESSION_UNKNOWN;
        wire->mp->net_mgr = nm;
        ASSERT(c_unknown);
        ASSERT(tunnel_live_finish(wire, &c, paired));
        PASS();
    }
_test_next:
    mesh_tunnel_test_set_now(0);
    wire->mp->net_mgr = nm;
    (void)mesh_tunnel_close(c.id);
    nm->num_nodes = nodes_saved;
    tunnel_live_drop(&c);
    return failures;
}

/* Ready nodes that share the fixture's responder transport, whose peer is
 * not the paired one: readable non-matches. One more than a single capture
 * holds, so the scan cases can cross both the 64-node mark and the bound. */
#define TUNNEL_TEST_FILLERS (BOOT_MESH_OBSERVE_MAX_READY + 1u)
#define TUNNEL_TEST_PAST_64 70u

static void tunnel_fillers_free(struct p2p_node **fill, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        if (!fill[i])
            continue;
        fill[i]->transport = NULL; /* shared with the fixture */
        p2p_node_free(fill[i]);
        fill[i] = NULL;
    }
}

static struct p2p_node *tunnel_ready_node(struct net_manager *nm,
                                          struct noise_transport *transport)
{
    struct net_address addr;
    memset(&addr, 0, sizeof(addr));
    addr.svc.port = 18035;
    struct p2p_node *node =
        p2p_node_create(nm, ZCL_INVALID_SOCKET, &addr, "tunnel-fill", false);
    if (!node)
        return NULL;
    node->transport = transport;
    node->state = PEER_HANDSHAKE_COMPLETE;
    return node;
}

/* The list's session reading comes from one snapshot of every ready node: a
 * match anywhere in it is live, a node holding no session is a non-match,
 * and absent is claimed only when every ready node was captured and read. */
static int tunnel_health_scan_case(struct tunnel_test_wire *wire,
                                   const char *peer_b)
{
    int failures = 0;
    struct tunnel_live_conn c;
    struct mesh_tunnel_row row;
    struct net_manager *nm = wire->mp->net_mgr;
    struct p2p_node **nodes_saved = nm->nodes;
    size_t num_saved = nm->num_nodes;
    struct p2p_node *fill[TUNNEL_TEST_FILLERS] = {0};
    struct p2p_node *table[TUNNEL_TEST_FILLERS + 1] = {0};
    struct p2p_node *unread = NULL;
    struct noise_transport *unread_transport = NULL;
    uint8_t key[32];
    const unsigned char magic[4] = {0x5a, 0x32, 0x33, 0x01};
    memset(key, 0x42, sizeof(key));
    tunnel_live_init(&c);
    const char *paired = wire->f->term_peer.pairing.pairing_id;
    TEST("mesh tunnel: the session reading scans every ready node, and "
         "claims absent only when all were read") {
        mesh_stream_test_reset();
        ASSERT(tunnel_live_open(paired, peer_b, "health-scan", &c));
        for (size_t i = 0; i < TUNNEL_TEST_FILLERS; i++) {
            fill[i] = tunnel_ready_node(nm, wire->b->transport);
            ASSERT(fill[i] != NULL);
            table[i] = fill[i];
        }
        table[TUNNEL_TEST_PAST_64] = wire->a;
        nm->nodes = table;

        /* C-beyond-64-live: the paired peer sits past the first batch. */
        nm->num_nodes = TUNNEL_TEST_PAST_64 + 1;
        bool c_beyond_64_live =
            tunnel_row_of(c.id, &row) &&
            row.peer_session == MESH_TUNNEL_PEER_SESSION_LIVE;
        ASSERT(c_beyond_64_live);

        /* C-unestablished-is-absent: a ready node whose transport holds no
         * established session (a fresh responder, still detecting) is a
         * definite non-match, and nothing else matches. */
        unread_transport = noise_transport_begin(false, key, magic, NULL, NULL);
        ASSERT(unread_transport != NULL);
        unread = tunnel_ready_node(nm, unread_transport);
        ASSERT(unread != NULL);
        table[0] = fill[0];
        table[1] = unread;
        nm->num_nodes = 2;
        bool c_unestablished_is_absent =
            tunnel_row_of(c.id, &row) &&
            row.peer_session == MESH_TUNNEL_PEER_SESSION_ABSENT;
        ASSERT(c_unestablished_is_absent);
        table[1] = fill[1];

        /* C-complete-absent: a few readable non-matches. */
        nm->num_nodes = 3;
        bool c_complete_absent =
            tunnel_row_of(c.id, &row) &&
            row.peer_session == MESH_TUNNEL_PEER_SESSION_ABSENT;
        ASSERT(c_complete_absent);

        /* C-beyond-64-absent: more than one batch, none matches. */
        nm->num_nodes = TUNNEL_TEST_PAST_64;
        bool c_beyond_64_absent =
            tunnel_row_of(c.id, &row) &&
            row.peer_session == MESH_TUNNEL_PEER_SESSION_ABSENT;
        ASSERT(c_beyond_64_absent);

        /* C-over-bound-unknown: more ready non-matches than one capture
         * holds. The surplus was never read, so absent cannot be claimed. */
        for (size_t i = 0; i < TUNNEL_TEST_FILLERS; i++)
            table[i] = fill[i];
        nm->num_nodes = TUNNEL_TEST_FILLERS;
        bool c_over_bound_unknown =
            tunnel_row_of(c.id, &row) &&
            row.peer_session == MESH_TUNNEL_PEER_SESSION_UNKNOWN;
        ASSERT(c_over_bound_unknown);

        /* C-over-bound-live: the same crowd with the match captured first. */
        table[0] = wire->a;
        for (size_t i = 0; i < TUNNEL_TEST_FILLERS; i++)
            table[i + 1] = fill[i];
        nm->num_nodes = TUNNEL_TEST_FILLERS + 1;
        bool c_over_bound_live =
            tunnel_row_of(c.id, &row) &&
            row.peer_session == MESH_TUNNEL_PEER_SESSION_LIVE;
        ASSERT(c_over_bound_live);

        nm->nodes = nodes_saved;
        nm->num_nodes = num_saved;
        ASSERT(tunnel_live_finish(wire, &c, paired));
        PASS();
    }
_test_next:
    nm->nodes = nodes_saved;
    nm->num_nodes = num_saved;
    (void)mesh_tunnel_close(c.id);
    if (c.port)
        (void)mesh_tunnel_deny(paired, c.port);
    tunnel_live_drop(&c);
    if (unread) {
        unread->transport = NULL;
        p2p_node_free(unread);
    }
    noise_transport_free(unread_transport);
    tunnel_fillers_free(fill, TUNNEL_TEST_FILLERS);
    return failures;
}

static bool tunnel_json_str_is(const struct json_value *row, const char *key,
                               const char *want)
{
    const struct json_value *v = json_get(row, key);
    return v && v->type == JSON_STR && strcmp(json_get_str(v), want) == 0;
}

static bool tunnel_json_int_is(const struct json_value *row, const char *key,
                               int64_t want)
{
    const struct json_value *v = json_get(row, key);
    return v && v->type == JSON_INT && json_get_int(v) == want;
}

/* The operator verb renders the same five keys the list holds. */
static int tunnel_health_rpc_case(struct tunnel_test_wire *wire,
                                  const char *peer_b)
{
    int failures = 0;
    struct tunnel_live_conn c;
    struct mesh_tunnel_row row;
    struct json_value params = {0}, result = {0};
    struct rpc_table *table = NULL;
    tunnel_live_init(&c);
    const char *paired = wire->f->term_peer.pairing.pairing_id;
    TEST("mesh tunnel: the list verb renders the health keys of the row") {
        mesh_stream_test_reset();
        ASSERT(tunnel_live_open(paired, peer_b, "health-rpc", &c));
        tunnel_beat(wire, 2);
        ASSERT(tunnel_live_accept(&c));
        tunnel_beat(wire, 2);
        mesh_tunnel_test_set_now(TUNNEL_TEST_STAMP_ACTIVITY);
        ASSERT(platform_socket_send_nonblocking(c.client, "to-peer", 7) == 7);
        tunnel_beat_until_readable(wire, c.served);
        ASSERT(tunnel_row_of(c.id, &row));
        ASSERT(row.last_activity_unix == TUNNEL_TEST_STAMP_ACTIVITY);

        table = zcl_calloc(1, sizeof(*table), "tunnel_test_rpc_table");
        ASSERT(table != NULL);
        rpc_table_init(table);
        mesh_tunnel_register_rpc(table);
        const struct rpc_command *cmd =
            rpc_table_find(table, "mesh_tunnel_list");
        ASSERT(cmd != NULL);
        json_set_array(&params);
        ASSERT(cmd->actor(&params, false, &result));
        const struct json_value *list = json_get(&result, "tunnels");
        const struct json_value *r0 = list ? json_at(list, 0) : NULL;
        /* C-rpc */
        bool c_rpc =
            r0 &&
            tunnel_json_int_is(r0, "last_activity_unix",
                               TUNNEL_TEST_STAMP_ACTIVITY) &&
            tunnel_json_str_is(r0, "last_stream_end_reason", "") &&
            tunnel_json_int_is(r0, "last_stream_end_unix", 0) &&
            tunnel_json_int_is(r0, "streams_failed_total", 0) &&
            tunnel_json_str_is(r0, "peer_session", "live");
        ASSERT(c_rpc);
        ASSERT(tunnel_live_finish(wire, &c, paired));
        PASS();
    }
_test_next:
    mesh_tunnel_test_set_now(0);
    json_free(&params);
    (void)mesh_tunnel_close(c.id);
    json_free(&result);
    free(table);
    tunnel_live_drop(&c);
    return failures;
}

int test_mesh_tunnel(void)
{
    int failures = tunnel_allow_text_cases();
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "mesh_tunnel", "loopback");
    struct mesh_term_fixture f;
    bool fixture_open = false;

    struct net_manager nm;
    struct msg_processor mp;
    struct p2p_node *a = NULL; /* dialled out: mints even stream ids */
    struct p2p_node *b = NULL; /* accepted: mints odd stream ids */
    struct p2p_node *nodes[2];
    struct send_segment *a_queue = NULL, *b_queue = NULL;
    struct boot_svc_ctx svc;
    struct db_service dbsvc;
    struct app_runtime_context runtime;
    struct tunnel_test_wire wire;
    platform_socket_t target = PLATFORM_SOCKET_INVALID;
    platform_socket_t served = PLATFORM_SOCKET_INVALID;
    platform_socket_t client = PLATFORM_SOCKET_INVALID;
    uint16_t target_port = 0;
    char peer_b[65] = {0};
    memset(&nm, 0, sizeof(nm));
    memset(&mp, 0, sizeof(mp));
    memset(&svc, 0, sizeof(svc));
    memset(&dbsvc, 0, sizeof(dbsvc));
    memset(&runtime, 0, sizeof(runtime));
    memset(&wire, 0, sizeof(wire));

    TEST("mesh tunnel: an unpaired peer never reaches the service, and a "
         "port no allow row names is refused by that name") {
        ASSERT(mesh_term_fixture_open(&f, dir));
        fixture_open = true;

        zcl_mutex_init(&nm.cs_nodes);
        zcl_mutex_init(&nm.cs_last_node_id);
        struct net_address addr;
        memset(&addr, 0, sizeof(addr));
        addr.svc.port = 18034;
        a = p2p_node_create(&nm, ZCL_INVALID_SOCKET, &addr, "tunnel-a", false);
        b = p2p_node_create(&nm, ZCL_INVALID_SOCKET, &addr, "tunnel-b", true);
        ASSERT(a && b);
        a->transport = f.term_peer.ini;
        b->transport = f.res_term;
        a->state = PEER_HANDSHAKE_COMPLETE;
        b->state = PEER_HANDSHAKE_COMPLETE;
        nodes[0] = a;
        nodes[1] = b;
        nm.nodes = nodes;
        nm.num_nodes = 2;
        a_queue = tunnel_sentinel(a);
        b_queue = tunnel_sentinel(b);
        ASSERT(a_queue && b_queue);

        mp.net_mgr = &nm;
        mp.params = chain_params_get();
        ASSERT(mp.params != NULL);
        svc.msg_processor = &mp;
        svc.datadir = dir;
        dbsvc.node_db = &f.ndb;
        dbsvc.started = true;
        runtime.db_service = &dbsvc;
        app_runtime_set_current(&runtime);
        wire.mp = &mp;
        wire.a = a;
        wire.b = b;
        wire.a_queue = a_queue;
        wire.b_queue = b_queue;
        wire.f = &f;

        mesh_stream_test_bind(&svc);
        mesh_stream_test_reset();
        mesh_tunnel_test_bind(&svc);
        mesh_tunnel_test_reset();

        /* The stand-in for the service being reached: a real listener on
         * loopback, exactly what an allow row would name. */
        target = tunnel_listen_local(&target_port, 0);
        ASSERT(target != PLATFORM_SOCKET_INVALID);

        /* a) No pairing row names this peer at all. The stream primitive
         * refuses before the tunnel service is ever asked. */
        uint8_t payload[8];
        size_t payload_len = tunnel_open_payload(target_port, payload);
        uint8_t frame[TUNNEL_TEST_WIRE_MAX];
        size_t frame_len = mesh_stream_test_open_frame(
            0, MESH_TUNNEL_CHUNK, MESH_TUNNEL_SERVICE_NAME, payload,
            payload_len, frame, sizeof(frame));
        ASSERT(frame_len != 0);
        ASSERT(mesh_stream_frame(&mp, b, frame, frame_len, NULL));
        uint8_t answer[TUNNEL_TEST_WIRE_MAX];
        bool more = false;
        size_t answer_len =
            tunnel_take(b, b_queue, f.term_peer.ini, answer, sizeof(answer),
                        &more);
        ASSERT(more);
        uint8_t kind = 0;
        ASSERT(mesh_stream_test_read_header(answer, answer_len, &kind, NULL));
        ASSERT_EQ(kind, MESH_STREAM_KIND_CLOSE);
        ASSERT_EQ(answer[MESH_STREAM_FRAME_PREFIX_LEN + 1u + 8u],
                  MESH_STREAM_REFUSED_PEER_UNPAIRED);
        ASSERT_EQ(mesh_stream_test_live_count(MESH_TUNNEL_SERVICE_NAME),
                  (size_t)0);

        /* b) Paired but unauthorized OPEN is refused by name and never dials. */
        ASSERT(mesh_term_pair_row(&f, &f.term_peer,
                                  MESH_PAIRING_CAP_STATUS_READ,
                                  TUNNEL_TEST_PAIRED_AT,
                                  TUNNEL_TEST_EXPIRES));
        frame_len = mesh_stream_test_open_frame(
            2, MESH_TUNNEL_CHUNK, MESH_TUNNEL_SERVICE_NAME, payload,
            payload_len, frame, sizeof(frame));
        ASSERT(frame_len != 0);
        ASSERT(mesh_stream_frame(&mp, b, frame, frame_len, NULL));
        answer_len = tunnel_take(b, b_queue, f.term_peer.ini, answer,
                                 sizeof(answer), &more);
        ASSERT(more);
        ASSERT(mesh_stream_test_read_header(answer, answer_len, &kind, NULL));
        ASSERT_EQ(kind, MESH_STREAM_KIND_CLOSE);
        ASSERT_EQ(answer[MESH_STREAM_FRAME_PREFIX_LEN + 1u + 8u],
                  MESH_STREAM_CLOSED_BY_SERVICE);
        const char *token = "tunnel_target_not_allowed";
        ASSERT(answer_len >= TUNNEL_TEST_CLOSE_PAYLOAD + strlen(token));
        ASSERT(memcmp(answer + TUNNEL_TEST_CLOSE_PAYLOAD, token,
                      strlen(token)) == 0);
        ASSERT_EQ(mesh_stream_test_live_count(MESH_TUNNEL_SERVICE_NAME),
                  (size_t)0);
        /* Nothing was dialled: the stand-in server saw no connection. */
        ASSERT(platform_socket_wait_readable(target, 0) <= 0);

        failures += tunnel_allow_transaction_case(&wire, target_port, target,
                                                  dir);
        if (failures)
            goto _test_next;
        PASS();
    }

    TEST("mesh tunnel: an allowed port carries bytes both ways over real "
         "loopback sockets, is listed while it lives, and closes both ends") {
        ASSERT(tunnel_pair_responder(&f, peer_b));
        /* This node's whole authority: one peer, one port, one reason. */
        ASSERT_EQ(mesh_tunnel_allow(f.term_peer.pairing.pairing_id,
                                    target_port, "loopback stand-in"),
                  MESH_TUNNEL_OK);

        uint64_t tunnel_id = 0;
        uint16_t local_port = 0;
        ASSERT_EQ(mesh_tunnel_listen(peer_b, target_port, 0, &tunnel_id,
                                     &local_port),
                  MESH_TUNNEL_OK);
        ASSERT(local_port != 0);

        client = tunnel_dial_local(local_port);
        ASSERT(client != PLATFORM_SOCKET_INVALID);
        tunnel_beat(&wire, 2);
        served = tunnel_accept_local(target);
        ASSERT(served != PLATFORM_SOCKET_INVALID);
        tunnel_beat(&wire, 2);

        /* Client → peer: the bytes arrive on the allowed loopback port. */
        ASSERT_EQ(platform_socket_send_nonblocking(client, "to-peer", 7),
                  7);
        char got[8];
        memset(got, 0, sizeof(got));
        for (int i = 0; i < TUNNEL_TEST_SETTLE_ROUNDS; i++) {
            tunnel_beat(&wire, 1);
            if (platform_socket_wait_readable(served, 0) > 0)
                break;
        }
        ASSERT(tunnel_read_exact(served, got, 7));
        ASSERT(memcmp(got, "to-peer", 7) == 0);

        /* Peer → client: and back the other way. */
        ASSERT_EQ(platform_socket_send_nonblocking(served, "to-here", 7), 7);
        memset(got, 0, sizeof(got));
        for (int i = 0; i < TUNNEL_TEST_SETTLE_ROUNDS; i++) {
            tunnel_beat(&wire, 1);
            if (platform_socket_wait_readable(client, 0) > 0)
                break;
        }
        ASSERT(tunnel_read_exact(client, got, 7));
        ASSERT(memcmp(got, "to-here", 7) == 0);

        /* The listing shows one tunnel with one live connection, its ports
         * and the bytes it has carried each way. */
        struct mesh_tunnel_row rows[MESH_TUNNEL_LISTENERS_MAX];
        size_t total = 0;
        ASSERT_EQ(mesh_tunnel_list(rows, MESH_TUNNEL_LISTENERS_MAX, &total),
                  (size_t)1);
        ASSERT_EQ(total, (size_t)1);
        ASSERT_EQ(rows[0].tunnel_id, tunnel_id);
        ASSERT_EQ(rows[0].local_port, local_port);
        ASSERT_EQ(rows[0].remote_port, target_port);
        ASSERT_EQ(rows[0].streams_open, UINT64_C(1));
        ASSERT_EQ(rows[0].streams_total, UINT64_C(1));
        ASSERT_EQ(rows[0].bytes_to_peer, UINT64_C(7));
        ASSERT_EQ(rows[0].bytes_from_peer, UINT64_C(7));
        ASSERT(strcmp(rows[0].peer, peer_b) == 0);

        /* The local program hangs up: the stream closes, and the far
         * socket sees the same end. */
        tunnel_drop(&client);
        tunnel_beat(&wire, TUNNEL_TEST_SETTLE_ROUNDS);
        ASSERT_EQ(mesh_stream_test_live_count(MESH_TUNNEL_SERVICE_NAME),
                  (size_t)0);
        char tail[4];
        ASSERT(!tunnel_read_exact(served, tail, 1));
        tunnel_drop(&served);

        /* Closing the entrance takes the row out of the listing. */
        ASSERT(mesh_tunnel_close(tunnel_id));
        total = 0;
        ASSERT_EQ(mesh_tunnel_list(rows, MESH_TUNNEL_LISTENERS_MAX, &total),
                  (size_t)0);
        ASSERT_EQ(total, (size_t)0);
        ASSERT(!mesh_tunnel_close(tunnel_id));
        PASS();
    }

    TEST("mesh tunnel: the sender never reads more from its socket than the "
         "credit it holds, and moves again once the reader catches up") {
        tunnel_drop(&target);
        target = tunnel_listen_local(&target_port, 0);
        ASSERT(target != PLATFORM_SOCKET_INVALID);
        ASSERT_EQ(mesh_tunnel_allow(f.term_peer.pairing.pairing_id,
                                    target_port, "slow reader"),
                  MESH_TUNNEL_OK);

        uint64_t tunnel_id = 0;
        uint16_t local_port = 0;
        ASSERT_EQ(mesh_tunnel_listen(peer_b, target_port, 0, &tunnel_id,
                                     &local_port),
                  MESH_TUNNEL_OK);
        client = tunnel_dial_local(local_port);
        ASSERT(client != PLATFORM_SOCKET_INVALID);
        (void)platform_socket_set_send_buffer(client,
                                              TUNNEL_TEST_CLIENT_SNDBUF);
        tunnel_beat(&wire, 2);
        served = tunnel_accept_local(target);
        ASSERT(served != PLATFORM_SOCKET_INVALID);
        tunnel_beat(&wire, 2);

        /* Write everything the local socket takes at once, so credit alone
         * decides what the tunnel moves. */
        uint8_t *flood = zcl_calloc(1, TUNNEL_TEST_FLOOD_BYTES, "tunnel_flood");
        ASSERT(flood != NULL);
        memset(flood, 'z', TUNNEL_TEST_FLOOD_BYTES);
        size_t wrote = 0;
        while (wrote < TUNNEL_TEST_FLOOD_BYTES) {
            int n = platform_socket_send_nonblocking(
                client, flood + wrote, TUNNEL_TEST_FLOOD_BYTES - wrote);
            if (n <= 0)
                break;
            wrote += (size_t)n;
        }
        free(flood);
        ASSERT(wrote > (size_t)TUNNEL_TEST_CREDIT_ROUNDS * MESH_TUNNEL_CHUNK);

        /* One beat is one credit window: the sender spends the credit it
         * holds and no more, so after a fixed number of beats the bytes moved
         * are bounded by that many windows — back-pressure independent of
         * kernel buffer size. */
        tunnel_beat(&wire, TUNNEL_TEST_CREDIT_ROUNDS);
        struct mesh_tunnel_row rows[MESH_TUNNEL_LISTENERS_MAX];
        size_t total = 0;
        ASSERT_EQ(mesh_tunnel_list(rows, MESH_TUNNEL_LISTENERS_MAX, &total),
                  (size_t)1);
        uint64_t paced = rows[0].bytes_to_peer;
        ASSERT(paced > 0);
        ASSERT(paced <= (uint64_t)TUNNEL_TEST_CREDIT_ROUNDS *
                            MESH_TUNNEL_CHUNK);
        ASSERT(paced < (uint64_t)wrote);

        /* The reader catches up, and every byte written arrives — the
         * window paces the copy, it never drops any of it. */
        size_t drained = 0;
        for (int i = 0; i < TUNNEL_TEST_SETTLE_ROUNDS && drained < wrote; i++) {
            tunnel_beat(&wire, TUNNEL_TEST_SETTLE_ROUNDS);
            drained += tunnel_drain(served);
        }
        ASSERT_EQ(drained, wrote);
        ASSERT_EQ(mesh_tunnel_list(rows, MESH_TUNNEL_LISTENERS_MAX, &total),
                  (size_t)1);
        ASSERT_EQ(rows[0].bytes_to_peer, (uint64_t)wrote);

        tunnel_drop(&client);
        tunnel_drop(&served);
        tunnel_beat(&wire, 4);
        ASSERT(mesh_tunnel_close(tunnel_id));
        PASS();
    }

    failures += tunnel_deny_live_case(&wire, peer_b);
    /* The revoke case ends with the shared pairing revoked, so it runs last. */
    failures += tunnel_health_flow_case(&wire, peer_b);
    failures += tunnel_health_inbound_case(&wire, peer_b);
    failures += tunnel_health_refused_case(&wire, peer_b);
    failures += tunnel_health_peer_case(&wire, peer_b);
    failures += tunnel_health_scan_case(&wire, peer_b);
    failures += tunnel_health_rpc_case(&wire, peer_b);
    failures += tunnel_missing_db_live_case(&wire, peer_b, &dbsvc);
    failures += tunnel_revoke_live_case(&wire, peer_b);

_test_next:
    tunnel_drop(&client);
    tunnel_drop(&served);
    tunnel_drop(&target);
    mesh_tunnel_test_reset();
    mesh_tunnel_test_bind(NULL);
    mesh_stream_test_reset();
    mesh_stream_test_bind(NULL);
    app_runtime_set_current(NULL);
    tunnel_test_node_drop(a, a_queue);
    tunnel_test_node_drop(b, b_queue);
    free(a_queue);
    free(b_queue);
    if (nm.nodes) {
        zcl_mutex_destroy(&nm.cs_nodes);
        zcl_mutex_destroy(&nm.cs_last_node_id);
    }
    if (fixture_open)
        mesh_term_fixture_close(&f);
    test_rm_rf_recursive(dir);
    return failures;
}
