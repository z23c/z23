/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Proves the multiplexed stream primitive over a two-peer loopback: two
 * real p2p nodes, one at each end of the shared fixture's in-process Noise
 * pair, with the production encoder sealing every frame and the production
 * decoder opening it — only the socket is elided. Covers the open/data/
 * window/close round trip, the credit window stopping a sender until a
 * WINDOW arrives, close freeing the slot, the per-peer cap and the OPEN
 * cadence, and the named refusals for an unknown service, an unpaired peer
 * and a link that is not Noise. Every refusal is checked by name on the
 * wire, because a stream that fails open would hand a stranger a service.
 */

#include "test/test_core.h"

#include "config/boot_internal.h"
#include "config/mesh_stream.h"
#include "config/runtime.h"
#include "test/mesh_stream_fixture.h"
#include "test/mesh_stream_loopback.h"
#include "test/mesh_term_fixture.h"

#include "base/safe_alloc.h"
#include "chain/chainparams.h"
#include "models/mesh_pairing.h"
#include "net/msgprocessor.h"
#include "net/net.h"
#include "net/noise_transport.h"
#include "net/protocol.h"

#include <stdlib.h>
#include <string.h>

#define STREAM_TEST_ECHO "echo"
#define STREAM_TEST_GUARD "guarded"
#define STREAM_TEST_WINDOW 4096u
/* A pairing window that brackets any clock this test could read: the
 * lane under test grades the row, not the hour the box thinks it is. */
#define STREAM_TEST_PAIRED_AT INT64_C(1)
#define STREAM_TEST_PAIRING_EXPIRES INT64_C(4102444800)

/* ── A test service: the whole contract a service implements ─────────── */

struct stream_test_session {
    uint64_t id;
    size_t received;
};

static size_t g_opens;
static size_t g_closes;
static size_t g_releases;
static size_t g_data_frames;
static size_t g_data_bytes;
static enum mesh_stream_refusal g_last_close;
static uint8_t g_big[STREAM_TEST_WINDOW];
static uint8_t g_last_data[512];
static size_t g_last_data_len;

static void stream_test_counters_reset(void)
{
    g_opens = 0;
    g_closes = 0;
    g_releases = 0;
    g_data_frames = 0;
    g_data_bytes = 0;
    g_last_close = MESH_STREAM_OK;
    g_last_data_len = 0;
}

static enum mesh_stream_refusal stream_test_open(struct mesh_stream *st,
                                                 const uint8_t *payload,
                                                 size_t len, uint8_t *reply,
                                                 size_t reply_cap,
                                                 size_t *reply_len, void *ctx)
{
    (void)ctx;
    struct stream_test_session *s =
        zcl_calloc(1, sizeof(*s), "stream_test_session");
    if (!s)
        return MESH_STREAM_REFUSED_UNAVAILABLE;
    s->id = st->id;
    st->service_state = s;
    g_opens++;
    /* The service answers the open with its own first bytes, which ride
     * back as the stream's first DATA. */
    if (len && reply_cap >= len + 3u) {
        memcpy(reply, "re:", 3);
        memcpy(reply + 3, payload, len);
        *reply_len = len + 3u;
    }
    return MESH_STREAM_OK;
}

static void stream_test_data(struct mesh_stream *st, const uint8_t *payload,
                             size_t len, void *ctx)
{
    (void)ctx;
    struct stream_test_session *s = st->service_state;
    if (s)
        s->received += len;
    g_data_frames++;
    g_data_bytes += len;
    g_last_data_len = len < sizeof(g_last_data) ? len : sizeof(g_last_data);
    memcpy(g_last_data, payload, g_last_data_len);
}

static void stream_test_close(struct mesh_stream *st,
                              enum mesh_stream_refusal reason,
                              const uint8_t *payload, size_t len, void *ctx)
{
    (void)st;
    (void)payload;
    (void)len;
    (void)ctx;
    g_closes++;
    g_last_close = reason;
}

static void stream_test_release(struct mesh_stream *st, void *ctx)
{
    (void)ctx;
    free(st->service_state);
    st->service_state = NULL;
    g_releases++;
}

static bool stream_test_register(const char *name, uint64_t capability)
{
    struct mesh_stream_service svc;
    memset(&svc, 0, sizeof(svc));
    svc.name = name;
    svc.required_pairing_capability = capability;
    svc.on_open = stream_test_open;
    svc.on_data = stream_test_data;
    svc.on_close = stream_test_close;
    svc.on_release = stream_test_release;
    return mesh_stream_service_register(&svc);
}

/* Visitor helpers: the stream verbs are lock-held-only, so every one of
 * them runs inside a visit. */
struct stream_test_visit {
    uint64_t id;
    bool found;
    bool ok;
    uint32_t credit;
    const uint8_t *bytes;
    size_t len;
    bool local_initiator;
    bool ended;
    enum mesh_stream_refusal end_reason;
    uint32_t send_credit;
    size_t live;
};

static struct mesh_stream *stream_test_match(struct mesh_stream *st,
                                             struct stream_test_visit *v)
{
    if (st->id != v->id || st->local_initiator != v->local_initiator)
        return NULL;
    return st;
}

static bool stream_test_send_visit(struct mesh_stream *st, void *ctx)
{
    struct stream_test_visit *v = ctx;
    if (!stream_test_match(st, v))
        return true;
    v->found = true;
    v->ok = mesh_stream_send(st, v->bytes, v->len);
    return false;
}

static bool stream_test_grant_visit(struct mesh_stream *st, void *ctx)
{
    struct stream_test_visit *v = ctx;
    if (!stream_test_match(st, v))
        return true;
    v->found = true;
    v->ok = mesh_stream_grant(st, v->credit);
    return false;
}

static bool stream_test_close_visit(struct mesh_stream *st, void *ctx)
{
    struct stream_test_visit *v = ctx;
    if (!stream_test_match(st, v))
        return true;
    v->found = true;
    mesh_stream_close(st, MESH_STREAM_CLOSED_BY_SERVICE, NULL, 0);
    return false;
}

static bool stream_test_release_visit(struct mesh_stream *st, void *ctx)
{
    struct stream_test_visit *v = ctx;
    if (!stream_test_match(st, v))
        return true;
    v->found = true;
    mesh_stream_release(st);
    return false;
}

static bool stream_test_read_visit(struct mesh_stream *st, void *ctx)
{
    struct stream_test_visit *v = ctx;
    v->live++;
    if (!stream_test_match(st, v))
        return true;
    v->found = true;
    v->ended = st->ended;
    v->end_reason = st->end_reason;
    v->send_credit = st->send_credit;
    return true;
}

static bool stream_test_send(uint64_t id, bool initiator, const void *bytes,
                             size_t len)
{
    struct stream_test_visit v;
    memset(&v, 0, sizeof(v));
    v.id = id;
    v.local_initiator = initiator;
    v.bytes = bytes;
    v.len = len;
    mesh_stream_visit(STREAM_TEST_ECHO, stream_test_send_visit, &v);
    return v.found && v.ok;
}

static bool stream_test_grant(uint64_t id, bool initiator, uint32_t credit)
{
    struct stream_test_visit v;
    memset(&v, 0, sizeof(v));
    v.id = id;
    v.local_initiator = initiator;
    v.credit = credit;
    mesh_stream_visit(STREAM_TEST_ECHO, stream_test_grant_visit, &v);
    return v.found && v.ok;
}

int test_mesh_stream(void)
{
    int failures = 0;
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "mesh_stream", "loopback");
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
    memset(&nm, 0, sizeof(nm));
    memset(&mp, 0, sizeof(mp));
    memset(&svc, 0, sizeof(svc));
    memset(&dbsvc, 0, sizeof(dbsvc));
    memset(&runtime, 0, sizeof(runtime));

    TEST("mesh stream: an open is answered by the service, data and window "
         "cross both ways, and close frees the slot") {
        ASSERT(mesh_term_fixture_open(&f, dir));
        fixture_open = true;

        /* Two real nodes over the fixture's established Noise pair, both
         * reachable through one net manager so either side can find the
         * peer its stream is bound to. */
        zcl_mutex_init(&nm.cs_nodes);
        zcl_mutex_init(&nm.cs_last_node_id);
        struct net_address addr;
        memset(&addr, 0, sizeof(addr));
        addr.svc.port = 18033;
        a = p2p_node_create(&nm, ZCL_INVALID_SOCKET, &addr, "stream-a", false);
        b = p2p_node_create(&nm, ZCL_INVALID_SOCKET, &addr, "stream-b", true);
        ASSERT(a && b);
        a->transport = f.term_peer.ini;
        b->transport = f.res_term;
        a->state = PEER_HANDSHAKE_COMPLETE;
        b->state = PEER_HANDSHAKE_COMPLETE;
        nodes[0] = a;
        nodes[1] = b;
        nm.nodes = nodes;
        nm.num_nodes = 2;
        a_queue = mesh_loop_sentinel(a);
        b_queue = mesh_loop_sentinel(b);
        ASSERT(a_queue && b_queue);

        mp.net_mgr = &nm;
        mp.params = chain_params_get();
        ASSERT(mp.params != NULL);
        svc.msg_processor = &mp;

        /* The pairing authority the guarded service reads later. */
        dbsvc.node_db = &f.ndb;
        dbsvc.started = true;
        runtime.db_service = &dbsvc;
        app_runtime_set_current(&runtime);

        mesh_stream_test_bind(&svc);
        mesh_stream_test_reset();
        stream_test_counters_reset();
        ASSERT(stream_test_register(STREAM_TEST_ECHO, 0));

        /* OPEN travels A → B, the service answers, and the reply comes
         * back as the stream's first DATA. */
        uint64_t id = UINT64_MAX;
        ASSERT_EQ(mesh_stream_open(STREAM_TEST_ECHO, f.resp_noise_pub,
                                   STREAM_TEST_WINDOW,
                                   (const uint8_t *)"hi", 2, NULL, &id),
                  MESH_STREAM_OK);
        ASSERT_EQ(id & 1u, UINT64_C(0)); /* the dialling side mints even */
        ASSERT_EQ(mesh_loop_pump(a, a_queue, f.res_term, &mp, b),
                  (size_t)1);
        ASSERT_EQ(g_opens, (size_t)1);
        ASSERT_EQ(mesh_stream_test_live_count(STREAM_TEST_ECHO), (size_t)2);
        ASSERT_EQ(mesh_loop_pump(b, b_queue, f.term_peer.ini, &mp, a),
                  (size_t)1);
        ASSERT_EQ(g_data_frames, (size_t)1);
        ASSERT_EQ(g_last_data_len, (size_t)5);
        ASSERT(memcmp(g_last_data, "re:hi", 5) == 0);

        /* DATA travels A → B inside the window B advertised. */
        uint8_t chunk[64];
        memset(chunk, 'x', sizeof(chunk));
        ASSERT(stream_test_send(id, true, chunk, sizeof(chunk)));
        ASSERT_EQ(mesh_loop_pump(a, a_queue, f.res_term, &mp, b),
                  (size_t)1);
        ASSERT_EQ(g_data_frames, (size_t)2);
        ASSERT_EQ(g_data_bytes, (size_t)5 + sizeof(chunk));

        /* A WINDOW from B replenishes A's credit. */
        struct stream_test_visit v;
        memset(&v, 0, sizeof(v));
        v.id = id;
        v.local_initiator = true;
        mesh_stream_visit(STREAM_TEST_ECHO, stream_test_read_visit, &v);
        ASSERT(v.found);
        ASSERT_EQ(v.send_credit, STREAM_TEST_WINDOW - (uint32_t)sizeof(chunk));
        ASSERT(stream_test_grant(id, false, (uint32_t)sizeof(chunk)));
        ASSERT_EQ(mesh_loop_pump(b, b_queue, f.term_peer.ini, &mp, a),
                  (size_t)1);
        memset(&v, 0, sizeof(v));
        v.id = id;
        v.local_initiator = true;
        mesh_stream_visit(STREAM_TEST_ECHO, stream_test_read_visit, &v);
        ASSERT(v.found);
        ASSERT_EQ(v.send_credit, STREAM_TEST_WINDOW);

        /* CLOSE from A ends both sides by name; the closed slot stops
         * counting as live at once, and release frees it. */
        memset(&v, 0, sizeof(v));
        v.id = id;
        v.local_initiator = true;
        mesh_stream_visit(STREAM_TEST_ECHO, stream_test_close_visit, &v);
        ASSERT(v.found);
        ASSERT_EQ(mesh_loop_pump(a, a_queue, f.res_term, &mp, b),
                  (size_t)1);
        ASSERT_EQ(g_closes, (size_t)2);
        ASSERT_EQ(g_last_close, MESH_STREAM_CLOSED_BY_SERVICE);
        ASSERT_EQ(mesh_stream_test_live_count(STREAM_TEST_ECHO), (size_t)0);
        memset(&v, 0, sizeof(v));
        v.id = id;
        v.local_initiator = true;
        mesh_stream_visit(STREAM_TEST_ECHO, stream_test_release_visit, &v);
        ASSERT(v.found);
        memset(&v, 0, sizeof(v));
        v.id = id;
        v.local_initiator = false;
        mesh_stream_visit(STREAM_TEST_ECHO, stream_test_release_visit, &v);
        ASSERT(v.found);
        ASSERT_EQ(g_releases, (size_t)2);
        memset(&v, 0, sizeof(v));
        v.id = UINT64_MAX;
        mesh_stream_visit(STREAM_TEST_ECHO, stream_test_read_visit, &v);
        ASSERT_EQ(v.live, (size_t)0);
        PASS();
    }

    TEST("mesh stream: a spent credit window stops the sender until a "
         "window arrives") {
        mesh_loop_discard(a, a_queue, f.res_term);
        mesh_loop_discard(b, b_queue, f.term_peer.ini);
        mesh_stream_test_reset();
        stream_test_counters_reset();
        uint64_t id = UINT64_MAX;
        ASSERT_EQ(mesh_stream_open(STREAM_TEST_ECHO, f.resp_noise_pub,
                                   STREAM_TEST_WINDOW, NULL, 0, NULL, &id),
                  MESH_STREAM_OK);
        ASSERT_EQ(mesh_loop_pump(a, a_queue, f.res_term, &mp, b),
                  (size_t)1);

        /* The whole window in one frame, then nothing: the sender is
         * stopped by its own credit, not by the peer. */
        memset(g_big, 'y', sizeof(g_big));
        ASSERT(stream_test_send(id, true, g_big, sizeof(g_big)));
        ASSERT(!stream_test_send(id, true, "z", 1));
        ASSERT_EQ(mesh_loop_pump(a, a_queue, f.res_term, &mp, b),
                  (size_t)1);
        ASSERT_EQ(g_data_bytes, (size_t)STREAM_TEST_WINDOW);

        /* The receiver makes room and says so; the sender moves again. */
        ASSERT(stream_test_grant(id, false, 16u));
        ASSERT_EQ(mesh_loop_pump(b, b_queue, f.term_peer.ini, &mp, a),
                  (size_t)1);
        ASSERT(stream_test_send(id, true, "z", 1));
        ASSERT_EQ(mesh_loop_pump(a, a_queue, f.res_term, &mp, b),
                  (size_t)1);
        ASSERT_EQ(g_data_bytes, (size_t)STREAM_TEST_WINDOW + 1u);

        /* A peer that spends credit it was never granted is ended by
         * name, not absorbed: the raw frame is composed by hand. */
        uint8_t frame[MESH_LOOP_WIRE_MAX];
        uint8_t spend[64];
        memset(spend, 'q', sizeof(spend));
        size_t frame_len = mesh_stream_test_data_frame(id, spend,
                                                       sizeof(spend), frame,
                                                       sizeof(frame));
        ASSERT(frame_len != 0);
        ASSERT(mesh_stream_frame(&mp, b, frame, frame_len, NULL));
        ASSERT_EQ(g_last_close, MESH_STREAM_REFUSED_CREDIT_EXCEEDED);
        struct stream_test_visit v;
        memset(&v, 0, sizeof(v));
        v.id = id;
        v.local_initiator = false;
        mesh_stream_visit(STREAM_TEST_ECHO, stream_test_read_visit, &v);
        ASSERT(v.found);
        ASSERT(v.ended);
        ASSERT_EQ(v.end_reason, MESH_STREAM_REFUSED_CREDIT_EXCEEDED);
        PASS();
    }

    TEST("mesh stream: the per-peer cap and the open cadence bound one "
         "peer's share of the table") {
        mesh_loop_discard(a, a_queue, f.res_term);
        mesh_loop_discard(b, b_queue, f.term_peer.ini);
        mesh_stream_test_reset();
        stream_test_counters_reset();
        uint64_t ids[MESH_STREAM_PER_PEER_MAX];
        for (size_t i = 0; i < MESH_STREAM_PER_PEER_MAX; i++)
            ASSERT_EQ(mesh_stream_open(STREAM_TEST_ECHO, f.resp_noise_pub,
                                       STREAM_TEST_WINDOW, NULL, 0, NULL,
                                       &ids[i]),
                      MESH_STREAM_OK);
        uint64_t extra = UINT64_MAX;
        ASSERT_EQ(mesh_stream_open(STREAM_TEST_ECHO, f.resp_noise_pub,
                                   STREAM_TEST_WINDOW, NULL, 0, NULL, &extra),
                  MESH_STREAM_REFUSED_CAP);
        ASSERT_EQ(extra, UINT64_MAX);
        ASSERT_EQ(mesh_loop_pump(a, a_queue, f.res_term, &mp, b),
                  (size_t)MESH_STREAM_PER_PEER_MAX);
        ASSERT_EQ(mesh_stream_test_live_count(STREAM_TEST_ECHO),
                  (size_t)2 * MESH_STREAM_PER_PEER_MAX);

        /* One more OPEN in the same second is over the cadence the
         * responder allows a single peer, and is refused by name — the
         * cadence gate stands in front of the table cap, so a burst never
         * reaches the slots at all. */
        uint8_t frame[MESH_LOOP_WIRE_MAX];
        size_t frame_len = mesh_stream_test_open_frame(
            2u * MESH_STREAM_PER_PEER_MAX, STREAM_TEST_WINDOW,
            STREAM_TEST_ECHO, NULL, 0, frame, sizeof(frame));
        ASSERT(frame_len != 0);
        ASSERT(mesh_stream_frame(&mp, b, frame, frame_len, NULL));
        ASSERT_EQ(mesh_stream_test_live_count(STREAM_TEST_ECHO),
                  (size_t)2 * MESH_STREAM_PER_PEER_MAX);
        uint8_t answer[MESH_LOOP_WIRE_MAX];
        bool more = false;
        size_t answer_len = mesh_loop_take(b, b_queue, f.term_peer.ini,
                                             answer, sizeof(answer), &more);
        ASSERT(more);
        uint8_t kind = 0;
        uint64_t answer_id = 0;
        ASSERT(mesh_stream_test_read_header(answer, answer_len, &kind,
                                            &answer_id));
        ASSERT_EQ(kind, MESH_STREAM_KIND_CLOSE);
        ASSERT_EQ(answer_id, (uint64_t)(2u * MESH_STREAM_PER_PEER_MAX));
        ASSERT_EQ(answer[MESH_STREAM_FRAME_PREFIX_LEN + 1u + 8u],
                  MESH_STREAM_REFUSED_RATE);
        PASS();
    }

    TEST("mesh stream: an unknown service, an unpaired peer and a link "
         "that is not Noise are refused by name") {
        mesh_loop_discard(a, a_queue, f.res_term);
        mesh_loop_discard(b, b_queue, f.term_peer.ini);
        mesh_stream_test_reset();
        stream_test_counters_reset();
        ASSERT(stream_test_register(STREAM_TEST_GUARD,
                                    MESH_PAIRING_CAP_TERMINAL_EXEC));

        /* a) A service nobody registered. */
        uint8_t frame[MESH_LOOP_WIRE_MAX];
        size_t frame_len = mesh_stream_test_open_frame(0, STREAM_TEST_WINDOW,
                                                       "nosuch", NULL, 0,
                                                       frame, sizeof(frame));
        ASSERT(frame_len != 0);
        ASSERT(mesh_stream_frame(&mp, b, frame, frame_len, NULL));
        uint8_t answer[MESH_LOOP_WIRE_MAX];
        bool more = false;
        size_t answer_len = mesh_loop_take(b, b_queue, f.term_peer.ini,
                                             answer, sizeof(answer), &more);
        ASSERT(more);
        uint8_t kind = 0;
        ASSERT(mesh_stream_test_read_header(answer, answer_len, &kind, NULL));
        ASSERT_EQ(kind, MESH_STREAM_KIND_CLOSE);
        ASSERT_EQ(answer[MESH_STREAM_FRAME_PREFIX_LEN + 1u + 8u],
                  MESH_STREAM_REFUSED_SERVICE_UNKNOWN);

        /* b) A registered service the peer holds no pairing for. */
        frame_len = mesh_stream_test_open_frame(2, STREAM_TEST_WINDOW,
                                                STREAM_TEST_GUARD, NULL, 0,
                                                frame, sizeof(frame));
        ASSERT(frame_len != 0);
        ASSERT(mesh_stream_frame(&mp, b, frame, frame_len, NULL));
        answer_len = mesh_loop_take(b, b_queue, f.term_peer.ini, answer,
                                      sizeof(answer), &more);
        ASSERT(more);
        ASSERT(mesh_stream_test_read_header(answer, answer_len, &kind, NULL));
        ASSERT_EQ(kind, MESH_STREAM_KIND_CLOSE);
        ASSERT_EQ(answer[MESH_STREAM_FRAME_PREFIX_LEN + 1u + 8u],
                  MESH_STREAM_REFUSED_PEER_UNPAIRED);
        ASSERT_EQ(mesh_stream_test_live_count(STREAM_TEST_GUARD), (size_t)0);

        /* The same open, once the peer holds the capability the service
         * asked for, is admitted. The row's window is a fixed one that no
         * clock this test could read falls outside, so the assertion
         * grades the stream lane's decision and never the box. */
        ASSERT(mesh_term_pair_row(&f, &f.term_peer,
                                  MESH_PAIRING_CAP_STATUS_READ |
                                      MESH_PAIRING_CAP_TERMINAL_EXEC,
                                  STREAM_TEST_PAIRED_AT,
                                  STREAM_TEST_PAIRING_EXPIRES));
        frame_len = mesh_stream_test_open_frame(4, STREAM_TEST_WINDOW,
                                                STREAM_TEST_GUARD, NULL, 0,
                                                frame, sizeof(frame));
        ASSERT(frame_len != 0);
        ASSERT(mesh_stream_frame(&mp, b, frame, frame_len, NULL));
        ASSERT_EQ(mesh_stream_test_live_count(STREAM_TEST_GUARD), (size_t)1);

        /* c) A link that is not an established Noise session carries no
         * stream at all: the frame is claimed and dropped, and nothing is
         * answered over a link we cannot name a peer on. */
        struct p2p_node plain;
        memset(&plain, 0, sizeof(plain));
        frame_len = mesh_stream_test_open_frame(6, STREAM_TEST_WINDOW,
                                                STREAM_TEST_GUARD, NULL, 0,
                                                frame, sizeof(frame));
        ASSERT(frame_len != 0);
        ASSERT(mesh_stream_frame(&mp, &plain, frame, frame_len, NULL));
        ASSERT_EQ(mesh_stream_test_live_count(STREAM_TEST_GUARD), (size_t)1);
        (void)mesh_loop_take(b, b_queue, f.term_peer.ini, answer,
                               sizeof(answer), &more);
        ASSERT(!more);
        mesh_stream_service_unregister(STREAM_TEST_GUARD);
        PASS();
    }

    TEST("mesh stream: an OPEN with the wrong id parity is refused by name") {
        stream_test_discard(a, a_queue, f.res_term);
        stream_test_discard(b, b_queue, f.term_peer.ini);
        mesh_stream_test_reset();
        stream_test_counters_reset();
        /* b accepted the link so it mints odd ids; inbound OPEN is even. */
        size_t live = mesh_stream_test_live_count(STREAM_TEST_ECHO);
        uint8_t frame[STREAM_TEST_WIRE_MAX];
        uint8_t answer[STREAM_TEST_WIRE_MAX];
        uint8_t kind = 0;
        uint64_t answer_id = 0;
        bool more = false;
        size_t frame_len = mesh_stream_test_open_frame(
            1, STREAM_TEST_WINDOW, STREAM_TEST_ECHO, NULL, 0, frame,
            sizeof(frame));
        ASSERT(frame_len != 0);
        ASSERT(mesh_stream_frame(&mp, b, frame, frame_len, NULL));
        ASSERT_EQ(mesh_stream_test_live_count(STREAM_TEST_ECHO), live);
        ASSERT_EQ(g_opens, (size_t)0);
        size_t answer_len = stream_test_take(b, b_queue, f.term_peer.ini,
                                             answer, sizeof(answer), &more);
        ASSERT(more);
        ASSERT(mesh_stream_test_read_header(answer, answer_len, &kind,
                                            &answer_id));
        ASSERT_EQ(kind, MESH_STREAM_KIND_CLOSE);
        ASSERT_EQ(answer_id, UINT64_C(1));
        ASSERT_EQ(answer[MESH_STREAM_FRAME_PREFIX_LEN + 1u + 8u],
                  MESH_STREAM_REFUSED_ID_PARITY);
        frame_len = mesh_stream_test_open_frame(0, STREAM_TEST_WINDOW,
                                                STREAM_TEST_ECHO, NULL, 0,
                                                frame, sizeof(frame));
        ASSERT(frame_len != 0);
        ASSERT(mesh_stream_frame(&mp, b, frame, frame_len, NULL));
        ASSERT_EQ(g_opens, (size_t)1);
        ASSERT_EQ(mesh_stream_test_live_count(STREAM_TEST_ECHO), live + 1u);
        PASS();
    }

    TEST("mesh stream: a duplicate OPEN of a live id is refused and the "
         "live stream keeps its state") {
        stream_test_discard(a, a_queue, f.res_term);
        stream_test_discard(b, b_queue, f.term_peer.ini);
        mesh_stream_test_reset();
        stream_test_counters_reset();
        uint64_t id = UINT64_MAX;
        ASSERT_EQ(mesh_stream_open(STREAM_TEST_ECHO, f.resp_noise_pub,
                                   STREAM_TEST_WINDOW, NULL, 0, NULL, &id),
                  MESH_STREAM_OK);
        ASSERT_EQ(stream_test_pump(a, a_queue, f.res_term, &mp, b),
                  (size_t)1);
        ASSERT_EQ(g_opens, (size_t)1);
        ASSERT_EQ(mesh_stream_test_live_count(STREAM_TEST_ECHO), (size_t)2);
        uint8_t frame[STREAM_TEST_WIRE_MAX];
        uint8_t answer[STREAM_TEST_WIRE_MAX];
        uint8_t kind = 0;
        uint64_t answer_id = 0;
        bool more = false;
        size_t frame_len = mesh_stream_test_open_frame(
            id, STREAM_TEST_WINDOW, STREAM_TEST_ECHO, NULL, 0, frame,
            sizeof(frame));
        ASSERT(frame_len != 0);
        ASSERT(mesh_stream_frame(&mp, b, frame, frame_len, NULL));
        size_t answer_len = stream_test_take(b, b_queue, f.term_peer.ini,
                                             answer, sizeof(answer), &more);
        ASSERT(more);
        ASSERT(mesh_stream_test_read_header(answer, answer_len, &kind,
                                            &answer_id));
        ASSERT_EQ(kind, MESH_STREAM_KIND_CLOSE);
        ASSERT_EQ(answer_id, id);
        ASSERT_EQ(answer[MESH_STREAM_FRAME_PREFIX_LEN + 1u + 8u],
                  MESH_STREAM_REFUSED_ID_IN_USE);
        ASSERT_EQ(mesh_stream_test_live_count(STREAM_TEST_ECHO), (size_t)2);
        uint8_t chunk[32];
        memset(chunk, 'd', sizeof(chunk));
        ASSERT(stream_test_send(id, true, chunk, sizeof(chunk)));
        ASSERT_EQ(stream_test_pump(a, a_queue, f.res_term, &mp, b),
                  (size_t)1);
        ASSERT_EQ(g_data_bytes, sizeof(chunk));
        struct stream_test_visit v;
        memset(&v, 0, sizeof(v));
        v.id = id;
        v.local_initiator = false;
        mesh_stream_visit(STREAM_TEST_ECHO, stream_test_read_visit, &v);
        ASSERT(v.found);
        ASSERT(!v.ended);
        PASS();
    }

_test_next:
    mesh_stream_test_reset();
    mesh_stream_service_unregister(STREAM_TEST_ECHO);
    mesh_stream_service_unregister(STREAM_TEST_GUARD);
    mesh_stream_test_bind(NULL);
    app_runtime_set_current(NULL);
    if (a) {
        mesh_loop_free_queue(a, a_queue);
        p2p_node_free(a);
    }
    if (b) {
        mesh_loop_free_queue(b, b_queue);
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
