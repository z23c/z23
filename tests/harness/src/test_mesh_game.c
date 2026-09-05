/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Proves the `game` service's wire contract over the same two-peer
 * loopback the stream primitive is proven on: real p2p nodes at each end
 * of the shared fixture's in-process Noise pair, the production decoder
 * opening every frame, only the socket elided.
 *
 * What is asserted is the thing a game will rely on and the thing an
 * attacker will try. The round trip — HELLO in the OPEN, then ROSTER,
 * MATCH_OPEN, MATCH_STATE, MATCH_CLOSE — has to walk end to end. And each
 * refusal has to arrive BY ITS OWN NAME on the wire, because a game
 * service that failed open would let a paired peer claim another
 * operator's machines or describe a match larger than it declared. Every
 * check reads the token out of the CLOSE payload rather than trusting
 * that the stream merely ended.
 */

#include "test/test_core.h"

#include "config/boot_internal.h"
#include "config/boot_mesh_game.h"
#include "config/mesh_stream.h"
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

#include <stdlib.h>
#include <string.h>

#define GAME_TEST_WIRE_MAX 8192u
#define GAME_TEST_WINDOW 8192u
/* A pairing window that brackets any clock this test could read: the lane
 * under test grades the row, not the hour the box thinks it is. */
#define GAME_TEST_PAIRED_AT INT64_C(1)
#define GAME_TEST_EXPIRES INT64_C(4102444800)
/* prefix + kind + stream id + reason + payload length. */
#define GAME_TEST_CLOSE_PAYLOAD_AT (MESH_STREAM_FRAME_PREFIX_LEN + 1u + 8u + 3u)

static struct msg_processor *g_mp;
static struct p2p_node *g_b;
static struct send_segment *g_b_queue;
static struct noise_transport *g_to_peer;

/* A queue head that is never sent, so p2p_node_end_message never asks the
 * (invalid) socket to write. */
static struct send_segment *game_sentinel(struct p2p_node *node)
{
    struct send_segment *sentinel =
        zcl_calloc(1, sizeof(*sentinel), "game_test_sentinel");
    node->send_head = sentinel;
    node->send_tail = sentinel;
    node->send_offset = 0;
    return sentinel;
}

/* Take the next sealed segment queued on the node under test and copy out
 * the one zpkgswm payload it carries. */
static size_t game_take(uint8_t *out, size_t out_cap, bool *more)
{
    struct send_segment *seg = g_b_queue->next;
    uint8_t *wire = NULL, *plain = NULL;
    size_t wire_len = 0, plain_len = 0, moved = 0;

    *more = false;
    if (!seg)
        return 0;
    *more = true;
    g_b_queue->next = seg->next;
    if (g_b->send_tail == seg)
        g_b->send_tail = g_b_queue;
    g_b->send_size = 0;
    g_b->send_offset = 0;
    if (noise_transport_feed(g_to_peer, seg->data, seg->size, &wire, &wire_len,
                             &plain, &plain_len) &&
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

static void game_drain(void)
{
    for (;;) {
        uint8_t frame[GAME_TEST_WIRE_MAX];
        bool more = false;

        (void)game_take(frame, sizeof(frame), &more);
        if (!more)
            break;
    }
}

/* The service's own token out of the CLOSE payload, or "" when the node
 * answered nothing or answered something that is not a CLOSE. */
static const char *game_close_token(void)
{
    static char token[MESH_STREAM_SERVICE_REPLY_MAX];
    uint8_t frame[GAME_TEST_WIRE_MAX];
    uint8_t kind = 0;
    bool more = false;
    size_t len;

    token[0] = '\0';
    len = game_take(frame, sizeof(frame), &more);
    if (!more || !mesh_stream_test_read_header(frame, len, &kind, NULL) ||
        kind != MESH_STREAM_KIND_CLOSE || len <= GAME_TEST_CLOSE_PAYLOAD_AT)
        return token;
    len -= GAME_TEST_CLOSE_PAYLOAD_AT;
    if (len >= sizeof(token))
        len = sizeof(token) - 1u;
    memcpy(token, frame + GAME_TEST_CLOSE_PAYLOAD_AT, len);
    token[len] = '\0';
    return token;
}

/* One composed game frame into one ZSTRM frame, through the production
 * decoder on the node under test. */
static bool game_send(uint64_t id, bool as_open,
                      const struct mesh_game_frame *frame)
{
    uint8_t body[MESH_GAME_FRAME_MAX];
    uint8_t wire[GAME_TEST_WIRE_MAX];
    size_t body_len = mesh_game_compose(frame, body, sizeof(body));
    size_t wire_len;

    if (!body_len)
        return false;
    wire_len = as_open
                   ? mesh_stream_test_open_frame(id, GAME_TEST_WINDOW,
                                                 MESH_GAME_SERVICE_NAME, body,
                                                 body_len, wire, sizeof(wire))
                   : mesh_stream_test_data_frame(id, body, body_len, wire,
                                                 sizeof(wire));
    if (!wire_len)
        return false;
    return mesh_stream_frame(g_mp, g_b, wire, wire_len, NULL);
}

/* Raw bytes as a DATA frame, for the shapes no composer will build. */
static bool game_send_raw(uint64_t id, const uint8_t *body, size_t body_len)
{
    uint8_t wire[GAME_TEST_WIRE_MAX];
    size_t wire_len = mesh_stream_test_data_frame(id, body, body_len, wire,
                                                  sizeof(wire));

    return wire_len && mesh_stream_frame(g_mp, g_b, wire, wire_len, NULL);
}

static void game_hello(struct mesh_game_frame *out, const uint8_t zid[32])
{
    memset(out, 0, sizeof(*out));
    out->kind = MESH_GAME_KIND_HELLO;
    memcpy(out->body.hello.zid, zid, 32);
    memset(out->body.hello.roster_digest, 0xa5, 32);
}

static void game_roster(struct mesh_game_frame *out, const uint8_t zid[32],
                        uint8_t rows)
{
    memset(out, 0, sizeof(*out));
    out->kind = MESH_GAME_KIND_ROSTER;
    memcpy(out->body.roster.zid, zid, 32);
    out->body.roster.asset_count = 2u; /* airship, escort */
    out->body.roster.row_count = rows;
    for (uint8_t i = 0; i < rows; i++) {
        memset(out->body.roster.rows[i].noise_fingerprint, (int)(i + 1u), 32);
        out->body.roster.rows[i].reachable = (i == 0);
        out->body.roster.rows[i].assets[0] = (i == 0) ? 1u : 0u;
    }
}

static void game_match_open(struct mesh_game_frame *out, uint8_t airships)
{
    memset(out, 0, sizeof(*out));
    out->kind = MESH_GAME_KIND_MATCH_OPEN;
    out->body.match_open.seed = UINT64_C(0x5eed);
    out->body.match_open.airships = airships;
}

static void game_match_state(struct mesh_game_frame *out, uint32_t tick,
                             uint8_t airships)
{
    memset(out, 0, sizeof(*out));
    out->kind = MESH_GAME_KIND_MATCH_STATE;
    out->body.match_state.tick = tick;
    out->body.match_state.airships = airships;
    for (uint8_t i = 0; i < airships; i++)
        memset(out->body.match_state.poses[i], (int)i, MESH_GAME_POSE_BYTES);
}

int test_mesh_game(void)
{
    int failures = 0;
    char dir[256];
    struct mesh_term_fixture f;
    bool fixture_open = false;
    struct net_manager nm;
    struct msg_processor mp;
    struct p2p_node *b = NULL;
    struct p2p_node *nodes[1];
    struct boot_svc_ctx svc;
    struct db_service dbsvc;
    struct app_runtime_context runtime;
    const uint8_t *peer_zid = NULL;
    uint8_t stranger[32];

    test_make_tmpdir(dir, sizeof(dir), "mesh_game", "loopback");
    memset(&nm, 0, sizeof(nm));
    memset(&mp, 0, sizeof(mp));
    memset(&svc, 0, sizeof(svc));
    memset(&dbsvc, 0, sizeof(dbsvc));
    memset(&runtime, 0, sizeof(runtime));
    memset(stranger, 0x77, sizeof(stranger));

    TEST("mesh game: a session walks hello, roster, match open, match "
         "state and match close end to end") {
        ASSERT(mesh_term_fixture_open(&f, dir));
        fixture_open = true;

        zcl_mutex_init(&nm.cs_nodes);
        zcl_mutex_init(&nm.cs_last_node_id);
        struct net_address addr;
        memset(&addr, 0, sizeof(addr));
        addr.svc.port = 18034;
        b = p2p_node_create(&nm, ZCL_INVALID_SOCKET, &addr, "game-b", true);
        ASSERT(b != NULL);
        b->transport = f.res_term;
        b->state = PEER_HANDSHAKE_COMPLETE;
        nodes[0] = b;
        nm.nodes = nodes;
        nm.num_nodes = 1;
        g_b = b;
        g_b_queue = game_sentinel(b);
        ASSERT(g_b_queue != NULL);
        g_to_peer = f.term_peer.ini;

        mp.net_mgr = &nm;
        mp.params = chain_params_get();
        ASSERT(mp.params != NULL);
        svc.msg_processor = &mp;
        g_mp = &mp;

        dbsvc.node_db = &f.ndb;
        dbsvc.started = true;
        runtime.db_service = &dbsvc;
        app_runtime_set_current(&runtime);

        mesh_stream_test_bind(&svc);
        mesh_stream_test_reset();
        ASSERT(boot_mesh_game_register_service());
        /* The row the game service reads the peer's chain identity from.
         * STATUS_READ is what a pairing grants by default and what the
         * service asks for. */
        ASSERT(mesh_term_pair_row(&f, &f.term_peer,
                                  MESH_PAIRING_CAP_STATUS_READ,
                                  GAME_TEST_PAIRED_AT, GAME_TEST_EXPIRES));
        peer_zid = f.term_peer.pairing.peer_master_pubkey;

        struct mesh_game_frame frame;
        game_hello(&frame, peer_zid);
        ASSERT(game_send(1, true, &frame));
        ASSERT_EQ(mesh_stream_test_live_count(MESH_GAME_SERVICE_NAME),
                  (size_t)1);
        game_drain();

        game_roster(&frame, peer_zid, 2u);
        ASSERT(game_send(1, false, &frame));
        ASSERT_EQ(mesh_stream_test_live_count(MESH_GAME_SERVICE_NAME),
                  (size_t)1);

        game_match_open(&frame, 3u);
        ASSERT(game_send(1, false, &frame));
        ASSERT_EQ(mesh_stream_test_live_count(MESH_GAME_SERVICE_NAME),
                  (size_t)1);

        game_match_state(&frame, 7u, 3u);
        ASSERT(game_send(1, false, &frame));
        ASSERT_EQ(mesh_stream_test_live_count(MESH_GAME_SERVICE_NAME),
                  (size_t)1);
        game_drain();

        memset(&frame, 0, sizeof(frame));
        frame.kind = MESH_GAME_KIND_MATCH_CLOSE;
        frame.body.match_close.reason_len = 4u;
        memcpy(frame.body.match_close.reason, "over", 4);
        ASSERT(game_send(1, false, &frame));
        ASSERT_EQ(mesh_stream_test_live_count(MESH_GAME_SERVICE_NAME),
                  (size_t)0);
        ASSERT(strcmp(game_close_token(), "game_ok") == 0);
        PASS();
    }

    TEST("mesh game: a roster claiming another operator's identity ends "
         "the stream by name") {
        game_drain();
        mesh_stream_test_reset();
        struct mesh_game_frame frame;

        game_hello(&frame, peer_zid);
        ASSERT(game_send(3, true, &frame));
        game_drain();
        game_roster(&frame, stranger, 1u);
        ASSERT(game_send(3, false, &frame));
        ASSERT_EQ(mesh_stream_test_live_count(MESH_GAME_SERVICE_NAME),
                  (size_t)0);
        ASSERT(strcmp(game_close_token(),
                      "game_roster_identity_mismatch") == 0);
        PASS();
    }

    TEST("mesh game: a hello claiming another operator's identity never "
         "opens a stream at all") {
        game_drain();
        mesh_stream_test_reset();
        struct mesh_game_frame frame;

        game_hello(&frame, stranger);
        ASSERT(game_send(5, true, &frame));
        ASSERT_EQ(mesh_stream_test_live_count(MESH_GAME_SERVICE_NAME),
                  (size_t)0);
        PASS();
    }

    TEST("mesh game: a match state carrying more airships than the match "
         "declared is refused by name") {
        game_drain();
        mesh_stream_test_reset();
        struct mesh_game_frame frame;

        game_hello(&frame, peer_zid);
        ASSERT(game_send(7, true, &frame));
        game_drain();
        game_roster(&frame, peer_zid, 1u);
        ASSERT(game_send(7, false, &frame));
        game_match_open(&frame, 2u);
        ASSERT(game_send(7, false, &frame));
        game_match_state(&frame, 1u, 4u);
        ASSERT(game_send(7, false, &frame));
        ASSERT_EQ(mesh_stream_test_live_count(MESH_GAME_SERVICE_NAME),
                  (size_t)0);
        ASSERT(strcmp(game_close_token(), "game_state_overflow") == 0);
        PASS();
    }

    TEST("mesh game: an unknown kind and a frame out of order each end "
         "the stream by their own name") {
        game_drain();
        mesh_stream_test_reset();
        struct mesh_game_frame frame;
        uint8_t bogus[8];

        game_hello(&frame, peer_zid);
        ASSERT(game_send(9, true, &frame));
        game_drain();
        memset(bogus, 0, sizeof(bogus));
        bogus[0] = 0x77; /* no kind claims this byte */
        ASSERT(game_send_raw(9, bogus, sizeof(bogus)));
        ASSERT_EQ(mesh_stream_test_live_count(MESH_GAME_SERVICE_NAME),
                  (size_t)0);
        ASSERT(strcmp(game_close_token(), "game_unknown_kind") == 0);

        /* A match state before any match opened is the order rule, not the
         * overflow rule, and says so. */
        game_drain();
        mesh_stream_test_reset();
        game_hello(&frame, peer_zid);
        ASSERT(game_send(11, true, &frame));
        game_drain();
        game_match_state(&frame, 1u, 1u);
        ASSERT(game_send(11, false, &frame));
        ASSERT_EQ(mesh_stream_test_live_count(MESH_GAME_SERVICE_NAME),
                  (size_t)0);
        ASSERT(strcmp(game_close_token(), "game_sequence") == 0);
        PASS();
    }

    TEST("mesh game: every frame kind survives compose and parse, and a "
         "truncated body is refused rather than half-read") {
        struct mesh_game_frame in, out;
        uint8_t wire[MESH_GAME_FRAME_MAX];
        size_t len;

        game_hello(&in, peer_zid ? peer_zid : stranger);
        len = mesh_game_compose(&in, wire, sizeof(wire));
        ASSERT_EQ(len, (size_t)65);
        ASSERT_EQ(mesh_game_parse(wire, len, &out), MESH_GAME_OK);
        ASSERT(memcmp(out.body.hello.zid, in.body.hello.zid, 32) == 0);
        ASSERT(memcmp(out.body.hello.roster_digest,
                      in.body.hello.roster_digest, 32) == 0);
        ASSERT_EQ(mesh_game_parse(wire, len - 1u, &out), MESH_GAME_MALFORMED);

        game_roster(&in, peer_zid ? peer_zid : stranger, 3u);
        len = mesh_game_compose(&in, wire, sizeof(wire));
        ASSERT(len != 0);
        ASSERT_EQ(mesh_game_parse(wire, len, &out), MESH_GAME_OK);
        ASSERT_EQ(out.body.roster.row_count, (uint8_t)3);
        ASSERT(out.body.roster.rows[0].reachable);
        ASSERT(!out.body.roster.rows[1].reachable);
        ASSERT_EQ(out.body.roster.rows[0].assets[0], (uint8_t)1);
        ASSERT_EQ(mesh_game_parse(wire, len - 1u, &out), MESH_GAME_MALFORMED);
        /* An asset vocabulary that is not this build's is named, never
         * read as a shorter row. */
        wire[33] = (uint8_t)(MESH_GAME_ASSET_MAX + 1u);
        ASSERT_EQ(mesh_game_parse(wire, len, &out),
                  MESH_GAME_ASSET_VOCABULARY);

        game_match_open(&in, 5u);
        len = mesh_game_compose(&in, wire, sizeof(wire));
        ASSERT_EQ(len, (size_t)10);
        ASSERT_EQ(mesh_game_parse(wire, len, &out), MESH_GAME_OK);
        ASSERT_EQ(out.body.match_open.seed, UINT64_C(0x5eed));
        ASSERT_EQ(out.body.match_open.airships, (uint8_t)5);

        game_match_state(&in, 42u, 4u);
        len = mesh_game_compose(&in, wire, sizeof(wire));
        ASSERT_EQ(len, (size_t)6 + 4u * MESH_GAME_POSE_BYTES);
        ASSERT_EQ(mesh_game_parse(wire, len, &out), MESH_GAME_OK);
        ASSERT_EQ(out.body.match_state.tick, (uint32_t)42);
        ASSERT_EQ(out.body.match_state.airships, (uint8_t)4);
        ASSERT(memcmp(out.body.match_state.poses[3], in.body.match_state.poses[3],
                      MESH_GAME_POSE_BYTES) == 0);
        /* A state frame claiming more airships than the wire can carry is
         * named before a single pose is copied. */
        wire[5] = (uint8_t)(MESH_GAME_AIRSHIPS_MAX + 1u);
        ASSERT_EQ(mesh_game_parse(wire, len, &out), MESH_GAME_STATE_OVERFLOW);

        memset(&in, 0, sizeof(in));
        in.kind = MESH_GAME_KIND_MATCH_CLOSE;
        in.body.match_close.reason_len = 5u;
        memcpy(in.body.match_close.reason, "spent", 5);
        len = mesh_game_compose(&in, wire, sizeof(wire));
        ASSERT_EQ(len, (size_t)7);
        ASSERT_EQ(mesh_game_parse(wire, len, &out), MESH_GAME_OK);
        ASSERT(strcmp(out.body.match_close.reason, "spent") == 0);

        wire[0] = 0x00;
        ASSERT_EQ(mesh_game_parse(wire, len, &out), MESH_GAME_UNKNOWN_KIND);
        ASSERT(strcmp(mesh_game_refusal_string(MESH_GAME_STATE_OVERFLOW),
                      "game_state_overflow") == 0);
        PASS();
    }

_test_next:
    mesh_stream_test_reset();
    mesh_stream_service_unregister(MESH_GAME_SERVICE_NAME);
    mesh_stream_test_bind(NULL);
    app_runtime_set_current(NULL);
    if (b) {
        while (g_b_queue && g_b_queue->next) {
            struct send_segment *seg = g_b_queue->next;
            g_b_queue->next = seg->next;
            send_segment_free(seg);
        }
        b->send_head = NULL;
        b->send_tail = NULL;
        b->transport = NULL; /* owned by the fixture */
        p2p_node_free(b);
    }
    free(g_b_queue);
    g_b_queue = NULL;
    g_b = NULL;
    g_mp = NULL;
    if (nm.nodes) {
        zcl_mutex_destroy(&nm.cs_nodes);
        zcl_mutex_destroy(&nm.cs_last_node_id);
    }
    if (fixture_open)
        mesh_term_fixture_close(&f);
    test_rm_rf_recursive(dir);
    return failures;
}
