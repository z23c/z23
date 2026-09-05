/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Proves the TCP tunnel service over a two-peer loopback: two real p2p
 * nodes at each end of the shared fixture's in-process Noise pair, the
 * production stream encoder and decoder carrying every frame, and REAL
 * loopback sockets at both ends — a client dialing the local entrance and
 * a stand-in server on the port the acceptor is allowed to reach. Covers
 * the two admission gates (an unpaired peer never reaches the service, and
 * a port no allow row names is refused by that name), bytes crossing both
 * ways, the credit window stopping a sender a reader stopped reading from,
 * the listing showing the tunnel and then showing it gone, and close in
 * both directions. Every refusal is checked by the token on the wire,
 * because a tunnel that failed open would hand a peer a local port.
 */

#include "test/test_core.h"

#include "config/boot_internal.h"
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
#include "platform/socket_compat.h"

#include <stdlib.h>
#include <string.h>

#define TUNNEL_TEST_WIRE_MAX 32768u
/* A pairing window that brackets any clock this test could read: the lane
 * under test grades the row, not the hour the box thinks it is. */
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

int test_mesh_tunnel(void)
{
    int failures = 0;
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

        /* b) The peer is paired, and still nothing is allowed: the tunnel
         * service refuses the exact port by name, and never dials. */
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

        /* Everything the local socket will take, in one go and with no
         * beat in between, so what the tunnel then moves is decided by
         * credit alone and not by how the writer paced itself. */
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

        /* One beat is one credit window: the sender may spend the credit
         * it holds and not a byte more, and only the WINDOW that comes
         * back in that beat lets it spend again. So after a fixed number
         * of beats the bytes moved are bounded by that many windows —
         * which is the whole back-pressure claim, in a form no kernel
         * buffer size can flatter. */
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

_test_next:
    tunnel_drop(&client);
    tunnel_drop(&served);
    tunnel_drop(&target);
    mesh_tunnel_test_reset();
    mesh_tunnel_test_bind(NULL);
    mesh_stream_test_reset();
    mesh_stream_test_bind(NULL);
    app_runtime_set_current(NULL);
    if (a) {
        while (a_queue && a_queue->next) {
            struct send_segment *seg = a_queue->next;
            a_queue->next = seg->next;
            send_segment_free(seg);
        }
        a->send_head = NULL;
        a->send_tail = NULL;
        a->transport = NULL; /* owned by the fixture */
        p2p_node_free(a);
    }
    if (b) {
        while (b_queue && b_queue->next) {
            struct send_segment *seg = b_queue->next;
            b_queue->next = seg->next;
            send_segment_free(seg);
        }
        b->send_head = NULL;
        b->send_tail = NULL;
        b->transport = NULL;
        p2p_node_free(b);
    }
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
