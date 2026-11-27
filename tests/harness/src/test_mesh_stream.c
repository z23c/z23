/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Proves the multiplexed stream primitive over a two-peer loopback: two
 * real p2p nodes, one at each end of the shared fixture's in-process Noise
 * pair, with the production encoder sealing every frame and the production
 * decoder opening it — only the socket is elided. Covers the open/data/
 * window/close round trip, the credit window stopping a sender until a
 * WINDOW arrives, close freeing the slot, the per-peer cap and the OPEN
 * cadence, supervised session-loss handling, the session a stream is bound to
 * when a peer holds several, and the named refusals for an
 * unknown service, an unpaired peer and a link that is not Noise. Every
 * refusal is checked by name on the wire, because a stream that fails open
 * would hand a stranger a service.
 */

#include "test/test_core.h"

#include "config/boot_internal.h"
#include "config/mesh_stream.h"
#include "config/runtime.h"
#include "test/mesh_stream_fixture.h"
#include "test/mesh_stream_loopback.h"
#include "test/mesh_term_fixture.h"

#include "base/cleanse.h"
#include "base/safe_alloc.h"
#include "chain/chainparams.h"
#include "models/mesh_pairing.h"
#include "net/msgprocessor.h"
#include "net/net.h"
#include "net/noise_transport.h"
#include "net/protocol.h"
#include "net/v2_identity.h"
#include "platform/clock.h"
#include "platform/private_directory.h"
#include "services/p2p_node_noise.h"

#include <stdio.h>
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

/* ── Many peers on one loopback link ─────────────────────────────────── */

/* A hand-set wall clock, so the OPEN cadence window a test lands in is a
 * choice and never the second the box happens to be in. */
static int64_t g_stream_test_wall_s;

static int64_t stream_test_now_wall_ms(void *self)
{
    (void)self;
    return g_stream_test_wall_s * 1000;
}

static int64_t stream_test_now_monotonic_ns(void *self)
{
    (void)self;
    return clock_default()->now_monotonic_ns(clock_default()->self);
}

static const clock_iface_t g_stream_test_clock = {
    .now_monotonic_ns = stream_test_now_monotonic_ns,
    .now_wall_ms = stream_test_now_wall_ms,
    .self = NULL,
};

static void stream_test_peer_key(uint8_t out[32], uint8_t n)
{
    memset(out, (int)(0x40u + n), 32);
}

/* The responder end of the loopback link, for answers a test reads back. */
struct stream_test_link {
    struct msg_processor *mp;
    struct p2p_node *node;
    struct send_segment *queue;
    struct noise_transport *peer_transport;
};

/* One OPEN of `service` from the stand-in peer `peer`, delivered to the
 * responder. Returns the reason byte of the CLOSE the responder answered
 * with, or -1 when it answered nothing (the stream was admitted). */
static int stream_test_open_as(const struct stream_test_link *lk,
                               const uint8_t peer[32], uint64_t id,
                               const char *service)
{
    uint8_t frame[MESH_LOOP_WIRE_MAX];
    size_t frame_len = mesh_stream_test_open_frame(
        id, STREAM_TEST_WINDOW, service, NULL, 0, frame, sizeof(frame));
    if (frame_len == 0)
        return -2;
    if (!mesh_stream_test_frame_as(lk->mp, lk->node, peer, frame, frame_len))
        return -2;
    uint8_t answer[MESH_LOOP_WIRE_MAX];
    bool more = false;
    size_t answer_len = mesh_loop_take(lk->node, lk->queue,
                                       lk->peer_transport, answer,
                                       sizeof(answer), &more);
    if (!more)
        return -1;
    uint8_t kind = 0;
    if (!mesh_stream_test_read_header(answer, answer_len, &kind, NULL) ||
        kind != MESH_STREAM_KIND_CLOSE)
        return -2;
    return answer[MESH_STREAM_FRAME_PREFIX_LEN + 1u + 8u];
}

/* A live pairing row for a stand-in peer, valid over any clock the test
 * installs. */
static bool stream_test_pair_stand_in(struct mesh_term_fixture *f,
                                      const uint8_t peer[32], uint8_t n)
{
    struct db_mesh_pairing row;
    memset(&row, 0, sizeof(row));
    memcpy(row.network_genesis, f->genesis, 32);
    memset(row.peer_master_pubkey, (int)(0x80u + n), 32);
    memcpy(row.peer_noise_pubkey, peer, 32);
    row.capability_mask = MESH_PAIRING_CAP_TERMINAL_EXEC;
    row.delegation_sequence = 1;
    row.paired_at = STREAM_TEST_PAIRED_AT;
    row.expires_at = STREAM_TEST_PAIRING_EXPIRES;
    if (!mesh_pairing_id_derive(row.network_genesis, row.peer_master_pubkey,
                                row.peer_noise_pubkey, row.pairing_id))
        return false;
    return db_mesh_pairing_insert(&f->ndb, &row);
}

static bool stream_test_end_all_visit(struct mesh_stream *st, void *ctx)
{
    (void)ctx;
    mesh_stream_close(st, MESH_STREAM_CLOSED_BY_SERVICE, NULL, 0);
    return true;
}

static bool stream_test_count_ended_visit(struct mesh_stream *st, void *ctx)
{
    if (st->ended)
        (*(size_t *)ctx)++;
    return true;
}

/* Case runners called from the group below; each owns its failure count
 * and its own teardown, so the group's own branching stays small. */

static int stream_test_case_ninth_paired(struct mesh_term_fixture *f,
                                         struct p2p_node *a,
                                         struct send_segment *a_queue,
                                         struct msg_processor *mp,
                                         struct p2p_node *b,
                                         struct send_segment *b_queue)
{
    int failures = 0;
    TEST("mesh stream: a ninth paired peer opens when both cadence tables "
         "are full in the same second") {
        mesh_loop_discard(a, a_queue, f->res_term);
        mesh_loop_discard(b, b_queue, f->term_peer.ini);
        mesh_stream_test_reset();
        stream_test_counters_reset();
        ASSERT(stream_test_register(STREAM_TEST_GUARD,
                                    MESH_PAIRING_CAP_TERMINAL_EXEC));
        struct stream_test_link lk = {mp, b, b_queue, f->term_peer.ini};
        g_stream_test_wall_s = INT64_C(3000000);
        clock_set_default(&g_stream_test_clock);
        for (uint8_t n = 0; n <= MESH_STREAM_PER_PEER_MAX; n++) {
            uint8_t peer[32];
            stream_test_peer_key(peer, (uint8_t)(60u + n));
            ASSERT(stream_test_pair_stand_in(f, peer, (uint8_t)(60u + n)));
        }

        /* Eight paired peers take every paired slot of this second. */
        for (uint8_t n = 0; n < MESH_STREAM_PER_PEER_MAX; n++) {
            uint8_t peer[32];
            stream_test_peer_key(peer, (uint8_t)(60u + n));
            ASSERT_EQ(stream_test_open_as(&lk, peer, 0, STREAM_TEST_GUARD),
                      -1);
        }
        /* Eight strangers take every unpaired slot of the same second. */
        for (uint8_t n = 21; n < 21u + MESH_STREAM_PER_PEER_MAX; n++) {
            uint8_t stranger[32];
            stream_test_peer_key(stranger, n);
            ASSERT_EQ(stream_test_open_as(&lk, stranger, 0,
                                          STREAM_TEST_GUARD),
                      MESH_STREAM_REFUSED_PEER_UNPAIRED);
        }
        /* The ninth paired peer has no slot in either table and is
         * still served. */
        uint8_t ninth[32];
        stream_test_peer_key(ninth, (uint8_t)(60u + MESH_STREAM_PER_PEER_MAX));
        ASSERT_EQ(stream_test_open_as(&lk, ninth, 0, STREAM_TEST_GUARD), -1);
        ASSERT_EQ(mesh_stream_test_live_count(STREAM_TEST_GUARD),
                  (size_t)(MESH_STREAM_PER_PEER_MAX + 1u));
        PASS();
    }
_test_next:
    clock_reset_default();
    mesh_stream_service_unregister(STREAM_TEST_GUARD);
    return failures;
}

/* `held` local opens toward the responder on the session `a` holds, ids
 * 0, 2, 4, ..., all ended: verdicts inside their linger, each still
 * holding its id on that session. The frames their ending wrote are
 * dropped, so the queue keeps nothing of theirs. */
static bool stream_test_hold_verdicts(struct mesh_term_fixture *f,
                                      struct p2p_node *a,
                                      struct send_segment *a_queue,
                                      size_t held)
{
    struct noise_transport_snapshot session;
    if (!p2p_node_noise_snapshot(a, &session))
        return false;
    for (size_t n = 0; n < held; n++) {
        if (!mesh_stream_test_inject(STREAM_TEST_ECHO, f->resp_noise_pub,
                                     session.transcript_hash,
                                     session.connection_generation, true,
                                     2u * (uint64_t)n, 4096u, NULL))
            return false;
    }
    mesh_stream_visit(STREAM_TEST_ECHO, stream_test_end_all_visit, NULL);
    mesh_loop_discard(a, a_queue, f->res_term);
    return true;
}

static int stream_test_case_failed_open_keeps_ended(
    struct mesh_term_fixture *f, struct p2p_node *a,
    struct send_segment *a_queue, struct p2p_node *b,
    struct send_segment *b_queue)
{
    int failures = 0;
    TEST("mesh stream: a local open that fails after picking an ended slot "
         "leaves that slot and its verdict in place") {
        mesh_loop_discard(a, a_queue, f->res_term);
        mesh_loop_discard(b, b_queue, f->term_peer.ini);
        mesh_stream_test_reset();
        /* Every id the local open can name is held toward the responder on
         * the session it will use, so the table is all verdicts and the
         * open has nothing left to pick. */
        ASSERT(stream_test_hold_verdicts(f, a, a_queue,
                                         MESH_STREAM_TABLE_MAX));
        stream_test_counters_reset();

        uint64_t local_id = UINT64_MAX;
        ASSERT_EQ(mesh_stream_open(STREAM_TEST_ECHO, f->resp_noise_pub,
                                   STREAM_TEST_WINDOW, NULL, 0, NULL,
                                   &local_id),
                  MESH_STREAM_REFUSED_ID_IN_USE);
        ASSERT_EQ(g_releases, (size_t)0);
        size_t ended = 0;
        mesh_stream_visit(STREAM_TEST_ECHO, stream_test_count_ended_visit,
                          &ended);
        ASSERT_EQ(ended, (size_t)MESH_STREAM_TABLE_MAX);
        PASS();
    }
_test_next:
    return failures;
}

/* An id is named per session: a frame arrives on one session, and a verdict
 * keeps its id through the linger so a late frame can never reach a new
 * stream under an old name. That hold is the session's own. */
static int stream_test_case_ended_id_kept(struct mesh_term_fixture *f,
                                          struct p2p_node *a,
                                          struct send_segment *a_queue,
                                          struct msg_processor *mp,
                                          struct p2p_node *b,
                                          struct send_segment *b_queue)
{
    int failures = 0;
    TEST("mesh stream: an id an ended verdict still holds on the session an "
         "open uses is not reused while it lingers") {
        mesh_loop_discard(a, a_queue, f->res_term);
        mesh_loop_discard(b, b_queue, f->term_peer.ini);
        mesh_stream_test_reset();
        ASSERT(stream_test_hold_verdicts(f, a, a_queue, 1));
        stream_test_counters_reset();

        /* The open takes a free slot and the next id, and leaves the
         * verdict in place. */
        uint64_t id = UINT64_MAX;
        ASSERT_EQ(mesh_stream_open(STREAM_TEST_ECHO, f->resp_noise_pub,
                                   STREAM_TEST_WINDOW,
                                   (const uint8_t *)"hi", 2, NULL, &id),
                  MESH_STREAM_OK);
        ASSERT_EQ(id, (uint64_t)2);
        ASSERT_EQ(g_releases, (size_t)0);
        size_t ended = 0;
        mesh_stream_visit(STREAM_TEST_ECHO, stream_test_count_ended_visit,
                          &ended);
        ASSERT_EQ(ended, (size_t)1);
        ASSERT_EQ(mesh_loop_pump(a, a_queue, f->res_term, mp, b), (size_t)1);
        ASSERT_EQ(mesh_loop_pump(b, b_queue, f->term_peer.ini, mp, a),
                  (size_t)1);
        ASSERT_EQ(g_opens, (size_t)1);
        ASSERT(memcmp(g_last_data, "re:hi", 5) == 0);
        PASS();
    }
_test_next:
    return failures;
}

/* The board lane asks a peer for a page every five seconds, and each
 * answer keeps its id through a linger of sixty: about thirteen ids held
 * at once on one session, by a lane doing exactly what it was told. */
static int stream_test_case_verdicts_leave_room(struct mesh_term_fixture *f,
                                                struct p2p_node *a,
                                                struct send_segment *a_queue,
                                                struct msg_processor *mp,
                                                struct p2p_node *b,
                                                struct send_segment *b_queue)
{
    int failures = 0;
    TEST("mesh stream: ended verdicts of a session leave an open an id "
         "until they fill the table") {
        mesh_loop_discard(a, a_queue, f->res_term);
        mesh_loop_discard(b, b_queue, f->term_peer.ini);
        mesh_stream_test_reset();
        ASSERT(stream_test_hold_verdicts(f, a, a_queue, 13));
        stream_test_counters_reset();

        /* Thirteen ids taken, so the open takes the fourteenth and the
         * verdicts keep theirs. */
        uint64_t id = UINT64_MAX;
        ASSERT_EQ(mesh_stream_open(STREAM_TEST_ECHO, f->resp_noise_pub,
                                   STREAM_TEST_WINDOW,
                                   (const uint8_t *)"hi", 2, NULL, &id),
                  MESH_STREAM_OK);
        ASSERT_EQ(id, (uint64_t)26);
        ASSERT_EQ(mesh_loop_pump(a, a_queue, f->res_term, mp, b), (size_t)1);
        ASSERT_EQ(mesh_loop_pump(b, b_queue, f->term_peer.ini, mp, a),
                  (size_t)1);
        ASSERT_EQ(g_opens, (size_t)1);
        ASSERT(memcmp(g_last_data, "re:hi", 5) == 0);
        size_t ended = 0;
        mesh_stream_visit(STREAM_TEST_ECHO, stream_test_count_ended_visit,
                          &ended);
        ASSERT_EQ(ended, (size_t)13);
        ASSERT_EQ(g_releases, (size_t)0);

        /* One candidate per slot the table holds: while a slot is free
         * the last candidate is there to take. */
        mesh_loop_discard(a, a_queue, f->res_term);
        mesh_loop_discard(b, b_queue, f->term_peer.ini);
        mesh_stream_test_reset();
        ASSERT(stream_test_hold_verdicts(f, a, a_queue,
                                         MESH_STREAM_TABLE_MAX - 1u));
        id = UINT64_MAX;
        ASSERT_EQ(mesh_stream_open(STREAM_TEST_ECHO, f->resp_noise_pub,
                                   STREAM_TEST_WINDOW, NULL, 0, NULL, &id),
                  MESH_STREAM_OK);
        ASSERT_EQ(id, (uint64_t)(2u * (MESH_STREAM_TABLE_MAX - 1u)));
        PASS();
    }
_test_next:
    return failures;
}

/* ── Several sessions to one peer static ─────────────────────────────── */

/* Three independent Noise sessions between ONE initiator static and ONE
 * responder static (the public in/out, onion and loopback links a real node
 * holds to one peer), each with a node at both ends. The stream is bound to
 * session 1; sessions 0 and 2 are decoys that match the peer's static but
 * carry other transcripts. */
#define STREAM_MULTI_SESSIONS 3u
#define STREAM_MULTI_BOUND 1u

struct stream_multi {
    uint8_t ini_pub[32];
    uint8_t res_pub[32];
    struct noise_transport *ini[STREAM_MULTI_SESSIONS];
    struct noise_transport *res[STREAM_MULTI_SESSIONS];
    struct p2p_node *ia[STREAM_MULTI_SESSIONS]; /* dialled: even ids */
    struct p2p_node *rb[STREAM_MULTI_SESSIONS]; /* accepted: odd ids */
    struct send_segment *iq[STREAM_MULTI_SESSIONS];
    struct send_segment *rq[STREAM_MULTI_SESSIONS];
    struct p2p_node *order[2u * STREAM_MULTI_SESSIONS];
};

static bool stream_multi_sessions(struct stream_multi *m, const char *dir)
{
    char idir[320], rdir[320], error[160];
    uint8_t ini_priv[32], res_priv[32];
    snprintf(idir, sizeof(idir), "%s/multi_ini", dir);
    snprintf(rdir, sizeof(rdir), "%s/multi_res", dir);
    bool ok = platform_private_directory_create(idir) &&
              platform_private_directory_create(rdir) &&
              v2_identity_load_or_create(idir, ini_priv, m->ini_pub, error,
                                         sizeof(error)) &&
              v2_identity_load_or_create(rdir, res_priv, m->res_pub, error,
                                         sizeof(error));
    for (size_t k = 0; ok && k < STREAM_MULTI_SESSIONS; k++)
        ok = mesh_term_handshake(ini_priv, res_priv, &m->ini[k], &m->res[k]);
    memory_cleanse(ini_priv, sizeof(ini_priv));
    memory_cleanse(res_priv, sizeof(res_priv));
    return ok;
}

static struct p2p_node *stream_multi_node(struct net_manager *nm,
                                          struct noise_transport *t,
                                          bool inbound,
                                          struct send_segment **queue)
{
    struct net_address addr;
    memset(&addr, 0, sizeof(addr));
    addr.svc.port = 18033;
    struct p2p_node *n =
        p2p_node_create(nm, ZCL_INVALID_SOCKET, &addr, "stream-multi",
                        inbound);
    if (!n)
        return NULL;
    n->transport = t;
    n->state = PEER_HANDSHAKE_COMPLETE;
    *queue = mesh_loop_sentinel(n);
    return *queue ? n : NULL;
}

static bool stream_multi_open(struct stream_multi *m, struct net_manager *nm,
                              const char *dir)
{
    memset(m, 0, sizeof(*m));
    if (!stream_multi_sessions(m, dir))
        return false;
    for (size_t k = 0; k < STREAM_MULTI_SESSIONS; k++) {
        m->ia[k] = stream_multi_node(nm, m->ini[k], false, &m->iq[k]);
        m->rb[k] = stream_multi_node(nm, m->res[k], true, &m->rq[k]);
        if (!m->ia[k] || !m->rb[k])
            return false;
    }
    return true;
}

static void stream_multi_close(struct stream_multi *m)
{
    for (size_t k = 0; k < STREAM_MULTI_SESSIONS; k++) {
        if (m->ia[k]) {
            mesh_loop_free_queue(m->ia[k], m->iq[k]);
            p2p_node_free(m->ia[k]);
        }
        if (m->rb[k]) {
            mesh_loop_free_queue(m->rb[k], m->rq[k]);
            p2p_node_free(m->rb[k]);
        }
        free(m->iq[k]);
        free(m->rq[k]);
        noise_transport_free(m->ini[k]);
        noise_transport_free(m->res[k]);
    }
}

/* The node table, as production reorders it. */
static void stream_multi_order(struct net_manager *nm, struct stream_multi *m,
                               struct p2p_node *const *list, size_t count)
{
    for (size_t i = 0; i < count; i++)
        m->order[i] = list[i];
    nm->nodes = m->order;
    nm->num_nodes = count;
}

/* connman's disconnect: the last node takes the freed slot. */
static void stream_multi_swap_remove(struct net_manager *nm, size_t index)
{
    nm->nodes[index] = nm->nodes[nm->num_nodes - 1u];
    nm->num_nodes--;
}

/* Frames queued on the sessions the stream is NOT bound to. */
static size_t stream_multi_decoy_frames(struct stream_multi *m,
                                        struct msg_processor *mp)
{
    size_t frames = 0;
    for (size_t k = 0; k < STREAM_MULTI_SESSIONS; k++) {
        if (k == STREAM_MULTI_BOUND)
            continue;
        frames += mesh_loop_pump(m->ia[k], m->iq[k], m->res[k], mp, m->rb[k]);
        frames += mesh_loop_pump(m->rb[k], m->rq[k], m->ini[k], mp, m->ia[k]);
    }
    return frames;
}

/* Opens the echo stream while only the bound session's two nodes are in the
 * table, so the open binds it, and delivers OPEN and the service's reply. */
static bool stream_multi_open_stream(struct stream_multi *m,
                                     struct net_manager *nm,
                                     struct msg_processor *mp, uint64_t *id)
{
    const size_t k = STREAM_MULTI_BOUND;
    struct p2p_node *only[2] = {m->ia[k], m->rb[k]};
    stream_multi_order(nm, m, only, 2);
    mesh_stream_test_reset();
    stream_test_counters_reset();
    return mesh_stream_open(STREAM_TEST_ECHO, m->res_pub, STREAM_TEST_WINDOW,
                            (const uint8_t *)"hi", 2, NULL,
                            id) == MESH_STREAM_OK &&
           mesh_loop_pump(m->ia[k], m->iq[k], m->res[k], mp, m->rb[k]) ==
               1u &&
           mesh_loop_pump(m->rb[k], m->rq[k], m->ini[k], mp, m->ia[k]) ==
               1u &&
           mesh_stream_test_live_count(STREAM_TEST_ECHO) == 2u;
}

static int stream_test_case_bound_session_found(
    struct stream_multi *m, struct net_manager *nm, struct msg_processor *mp)
{
    int failures = 0;
    const size_t k = STREAM_MULTI_BOUND;
    TEST("mesh stream: with three sessions to one static, sends, ticks and "
         "CLOSE use the session the stream is bound to") {
        uint64_t id = UINT64_MAX;
        ASSERT(stream_multi_open_stream(m, nm, mp, &id));
        /* Decoys first, the bound session last, for both ends. */
        struct p2p_node *table[6] = {m->ia[0], m->rb[0], m->ia[2],
                                     m->rb[2], m->ia[k], m->rb[k]};
        stream_multi_order(nm, m, table, 6);

        mesh_stream_test_pump_tick();
        ASSERT_EQ(mesh_stream_test_live_count(STREAM_TEST_ECHO), (size_t)2);
        uint8_t chunk[64];
        memset(chunk, 'x', sizeof(chunk));
        ASSERT(stream_test_send(id, true, chunk, sizeof(chunk)));
        ASSERT_EQ(mesh_loop_pump(m->ia[k], m->iq[k], m->res[k], mp, m->rb[k]),
                  (size_t)1);
        /* The answering side's answer rides the same bound session. */
        ASSERT(stream_test_send(id, false, "answer", 6));
        ASSERT_EQ(mesh_loop_pump(m->rb[k], m->rq[k], m->ini[k], mp, m->ia[k]),
                  (size_t)1);
        ASSERT(memcmp(g_last_data, "answer", 6) == 0);

        /* A disconnect swap-removes the first node: the table reorders and
         * the bound session still is not the first match for either end. */
        stream_multi_swap_remove(nm, 0);
        mesh_stream_test_pump_tick();
        ASSERT_EQ(mesh_stream_test_live_count(STREAM_TEST_ECHO), (size_t)2);
        ASSERT(stream_test_send(id, true, chunk, sizeof(chunk)));
        ASSERT_EQ(mesh_loop_pump(m->ia[k], m->iq[k], m->res[k], mp, m->rb[k]),
                  (size_t)1);

        /* CLOSE is delivered on the bound session, to both ends. */
        struct stream_test_visit v;
        memset(&v, 0, sizeof(v));
        v.id = id;
        v.local_initiator = true;
        mesh_stream_visit(STREAM_TEST_ECHO, stream_test_close_visit, &v);
        ASSERT(v.found);
        ASSERT_EQ(mesh_loop_pump(m->ia[k], m->iq[k], m->res[k], mp, m->rb[k]),
                  (size_t)1);
        ASSERT_EQ(g_closes, (size_t)2);
        ASSERT_EQ(g_last_close, MESH_STREAM_CLOSED_BY_SERVICE);
        ASSERT_EQ(mesh_stream_test_live_count(STREAM_TEST_ECHO), (size_t)0);
        ASSERT_EQ(stream_multi_decoy_frames(m, mp), (size_t)0);
        PASS();
    }
_test_next:
    return failures;
}

static int stream_test_case_bound_session_lost(
    struct stream_multi *m, struct net_manager *nm, struct msg_processor *mp)
{
    int failures = 0;
    TEST("mesh stream: when the bound session is gone and two others to the "
         "same static remain, the stream ends SESSION_LOST and never "
         "migrates") {
        uint64_t id = UINT64_MAX;
        ASSERT(stream_multi_open_stream(m, nm, mp, &id));
        struct p2p_node *decoys[4] = {m->ia[0], m->rb[0], m->ia[2], m->rb[2]};
        stream_multi_order(nm, m, decoys, 4);

        mesh_stream_test_pump_tick();
        ASSERT_EQ(g_closes, (size_t)2);
        ASSERT_EQ(mesh_stream_test_live_count(STREAM_TEST_ECHO), (size_t)0);
        for (uint8_t initiator = 0; initiator < 2; initiator++) {
            struct stream_test_visit v;
            memset(&v, 0, sizeof(v));
            v.id = id;
            v.local_initiator = initiator != 0;
            mesh_stream_visit(STREAM_TEST_ECHO, stream_test_read_visit, &v);
            ASSERT(v.found);
            ASSERT(v.ended);
            ASSERT_EQ(v.end_reason, MESH_STREAM_ENDED_SESSION_LOST);
        }
        /* Nothing was sent on any other session to that peer. */
        ASSERT(!stream_test_send(id, true, "late", 4));
        ASSERT_EQ(stream_multi_decoy_frames(m, mp), (size_t)0);
        PASS();
    }
_test_next:
    return failures;
}

/* The open finds the bound session first; the two other sessions to the
 * same static stay in the table behind it. */
static void stream_multi_bound_first(struct stream_multi *m,
                                     struct net_manager *nm)
{
    const size_t k = STREAM_MULTI_BOUND;
    struct p2p_node *table[6] = {m->ia[k], m->rb[k], m->ia[0],
                                 m->rb[0], m->ia[2], m->rb[2]};
    stream_multi_order(nm, m, table, 6);
}

/* Holds every even id up to the sixteenth toward the peer on the two
 * sessions an open on the bound session does not use: the first `live` by
 * live streams, the rest by verdicts still inside their linger. Nothing
 * frees one before the case has read the id its open took: a live stream
 * ends only when its case closes it, and a verdict stays for its linger. */
static bool stream_multi_hold_elsewhere(struct stream_multi *m, size_t live)
{
    struct noise_transport_snapshot decoy[2];
    if (!p2p_node_noise_snapshot(m->ia[0], &decoy[0]) ||
        !p2p_node_noise_snapshot(m->ia[2], &decoy[1]))
        return false;
    for (size_t n = 0; n <= MESH_STREAM_PER_PEER_MAX; n++) {
        if (!mesh_stream_test_inject(
                STREAM_TEST_ECHO, m->res_pub,
                decoy[n % 2u].transcript_hash,
                decoy[n % 2u].connection_generation, true, 2u * n, 4096u,
                NULL))
            return false;
    }
    for (size_t n = live; n <= MESH_STREAM_PER_PEER_MAX; n++) {
        struct stream_test_visit v;
        memset(&v, 0, sizeof(v));
        v.id = 2u * n;
        v.local_initiator = true;
        mesh_stream_visit(STREAM_TEST_ECHO, stream_test_close_visit, &v);
        if (!v.found)
            return false;
    }
    mesh_loop_discard(m->ia[0], m->iq[0], m->res[0]);
    mesh_loop_discard(m->ia[2], m->iq[2], m->res[2]);
    return true;
}

/* The open and the service's answer both ride the bound session, and no
 * other session to the peer carries a frame for them. */
static bool stream_multi_answered(struct stream_multi *m,
                                  struct msg_processor *mp)
{
    const size_t k = STREAM_MULTI_BOUND;
    return mesh_loop_pump(m->ia[k], m->iq[k], m->res[k], mp, m->rb[k]) ==
               1u &&
           mesh_loop_pump(m->rb[k], m->rq[k], m->ini[k], mp, m->ia[k]) ==
               1u &&
           g_opens == 1u && g_last_data_len == 5u &&
           memcmp(g_last_data, "re:hi", 5) == 0 &&
           stream_multi_decoy_frames(m, mp) == 0u;
}

/* A verdict holds its id on its own session only: toward the same peer on
 * another session it is not the name of anything a frame can reach. */
static int stream_test_case_verdicts_other_session(
    struct stream_multi *m, struct net_manager *nm, struct msg_processor *mp)
{
    int failures = 0;
    TEST("mesh stream: ids held toward the same static by verdicts on OTHER "
         "sessions do not spend the ids of the session an open uses") {
        stream_multi_bound_first(m, nm);
        mesh_stream_test_reset();
        stream_test_counters_reset();
        ASSERT(stream_multi_hold_elsewhere(m, 0));

        uint64_t id = UINT64_MAX;
        ASSERT_EQ(mesh_stream_open(STREAM_TEST_ECHO, m->res_pub,
                                   STREAM_TEST_WINDOW,
                                   (const uint8_t *)"hi", 2, NULL, &id),
                  MESH_STREAM_OK);
        ASSERT_EQ(id, (uint64_t)0);
        ASSERT(stream_multi_answered(m, mp));
        ASSERT_EQ(mesh_stream_test_live_count(STREAM_TEST_ECHO), (size_t)2);
        PASS();
    }
_test_next:
    return failures;
}

/* A live stream keeps its id toward its peer on every session: a peer that
 * puts a stream's frames on another of its sessions here must find no
 * other stream under that id to hand them to. */
static int stream_test_case_live_other_session(
    struct stream_multi *m, struct net_manager *nm, struct msg_processor *mp)
{
    int failures = 0;
    TEST("mesh stream: an id live toward the same static on ANOTHER session "
         "is not reused, and the open takes the next one that is free") {
        stream_multi_bound_first(m, nm);
        mesh_stream_test_reset();
        stream_test_counters_reset();
        /* Seven live stay under the per-peer cap, leaving room for exactly
         * one more stream toward the peer. */
        ASSERT(stream_multi_hold_elsewhere(m, MESH_STREAM_PER_PEER_MAX - 1u));

        uint64_t id = UINT64_MAX;
        ASSERT_EQ(mesh_stream_open(STREAM_TEST_ECHO, m->res_pub,
                                   STREAM_TEST_WINDOW,
                                   (const uint8_t *)"hi", 2, NULL, &id),
                  MESH_STREAM_OK);
        /* Ids 0 to 12 are live toward the peer on the other sessions. The
         * two past them are verdicts there, so the first of those is the
         * first id nothing live holds. */
        ASSERT_EQ(id, (uint64_t)2u * (MESH_STREAM_PER_PEER_MAX - 1u));
        ASSERT(stream_multi_answered(m, mp));
        ASSERT_EQ(mesh_stream_test_live_count(STREAM_TEST_ECHO),
                  (size_t)MESH_STREAM_PER_PEER_MAX + 1u);
        PASS();
    }
_test_next:
    return failures;
}

static int stream_test_case_multi_session(const char *dir,
                                          struct net_manager *nm,
                                          struct msg_processor *mp)
{
    int failures = 0;
    struct p2p_node **saved_nodes = nm->nodes;
    size_t saved_count = nm->num_nodes;
    struct stream_multi m;
    TEST("mesh stream: the multi-session fixture opens") {
        ASSERT(stream_multi_open(&m, nm, dir));
        PASS();
    }
    if (failures == 0) {
        failures += stream_test_case_bound_session_found(&m, nm, mp);
        failures += stream_test_case_bound_session_lost(&m, nm, mp);
        failures += stream_test_case_verdicts_other_session(&m, nm, mp);
        failures += stream_test_case_live_other_session(&m, nm, mp);
    }
_test_next:
    nm->nodes = saved_nodes;
    nm->num_nodes = saved_count;
    mesh_stream_test_reset();
    stream_multi_close(&m);
    return failures;
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
        mesh_loop_discard(a, a_queue, f.res_term);
        mesh_loop_discard(b, b_queue, f.term_peer.ini);
        mesh_stream_test_reset();
        stream_test_counters_reset();
        /* b accepted the link so it mints odd ids; inbound OPEN is even. */
        size_t live = mesh_stream_test_live_count(STREAM_TEST_ECHO);
        uint8_t frame[MESH_LOOP_WIRE_MAX];
        uint8_t answer[MESH_LOOP_WIRE_MAX];
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
        size_t answer_len = mesh_loop_take(b, b_queue, f.term_peer.ini,
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
        ASSERT_EQ(g_opens, (size_t)1);
        ASSERT_EQ(mesh_stream_test_live_count(STREAM_TEST_ECHO), (size_t)2);
        uint8_t frame[MESH_LOOP_WIRE_MAX];
        uint8_t answer[MESH_LOOP_WIRE_MAX];
        uint8_t kind = 0;
        uint64_t answer_id = 0;
        bool more = false;
        size_t frame_len = mesh_stream_test_open_frame(
            id, STREAM_TEST_WINDOW, STREAM_TEST_ECHO, NULL, 0, frame,
            sizeof(frame));
        ASSERT(frame_len != 0);
        ASSERT(mesh_stream_frame(&mp, b, frame, frame_len, NULL));
        size_t answer_len = mesh_loop_take(b, b_queue, f.term_peer.ini,
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
        ASSERT_EQ(mesh_loop_pump(a, a_queue, f.res_term, &mp, b),
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

    TEST("mesh stream: the side that accepted a link opens a stream to the "
         "peer that dialled it, so a box behind NAT can still be asked") {
        /* b accepted the link; a dialled it. A box behind NAT is always
         * the dialler, so every pull toward it opens on this side. */
        mesh_loop_discard(a, a_queue, f.res_term);
        mesh_loop_discard(b, b_queue, f.term_peer.ini);
        mesh_stream_test_reset();
        stream_test_counters_reset();
        uint64_t id = 0;
        ASSERT_EQ(mesh_stream_open(STREAM_TEST_ECHO, f.term_peer.noise_pub,
                                   STREAM_TEST_WINDOW,
                                   (const uint8_t *)"up", 2, NULL, &id),
                  MESH_STREAM_OK);
        ASSERT_EQ(id & 1u, UINT64_C(1)); /* the accepting side mints odd */
        ASSERT_EQ(mesh_loop_pump(b, b_queue, f.term_peer.ini, &mp, a),
                  (size_t)1);
        ASSERT_EQ(g_opens, (size_t)1);
        ASSERT_EQ(mesh_loop_pump(a, a_queue, f.res_term, &mp, b),
                  (size_t)1);
        ASSERT_EQ(g_data_frames, (size_t)1);
        ASSERT_EQ(g_last_data_len, (size_t)5);
        ASSERT(memcmp(g_last_data, "re:up", 5) == 0);
        PASS();
    }

    TEST("mesh stream: supervised pump ends both streams on session loss "
         "without sending CLOSE frames") {
        mesh_loop_discard(a, a_queue, f.res_term);
        mesh_loop_discard(b, b_queue, f.term_peer.ini);
        mesh_stream_test_reset();
        stream_test_counters_reset();
        uint64_t id = 0;
        ASSERT_EQ(mesh_stream_open(STREAM_TEST_ECHO, f.resp_noise_pub,
                                   STREAM_TEST_WINDOW,
                                   (const uint8_t *)"up", 2, NULL, &id),
                  MESH_STREAM_OK);
        ASSERT_EQ(mesh_loop_pump(a, a_queue, f.res_term, &mp, b),
                  (size_t)1);
        ASSERT_EQ(mesh_loop_pump(b, b_queue, f.term_peer.ini, &mp, a),
                  (size_t)1);
        ASSERT_EQ(mesh_stream_test_live_count(STREAM_TEST_ECHO), (size_t)2);
        a->disconnect = true;
        b->disconnect = true;
        mesh_stream_test_pump_tick();
        a->disconnect = false;
        b->disconnect = false;
        ASSERT_EQ(g_closes, (size_t)2);
        ASSERT_EQ(mesh_stream_test_live_count(STREAM_TEST_ECHO), (size_t)0);
        for (uint8_t initiator = 0; initiator < 2; initiator++) {
            struct stream_test_visit v;
            memset(&v, 0, sizeof(v));
            v.id = id;
            v.local_initiator = initiator != 0;
            mesh_stream_visit(STREAM_TEST_ECHO, stream_test_read_visit, &v);
            ASSERT(v.found);
            ASSERT(v.ended);
            ASSERT_EQ(v.end_reason, MESH_STREAM_ENDED_SESSION_LOST);
        }
        ASSERT_EQ(mesh_loop_pump(a, a_queue, f.res_term, &mp, b),
                  (size_t)0);
        ASSERT_EQ(mesh_loop_pump(b, b_queue, f.term_peer.ini, &mp, a),
                  (size_t)0);
        PASS();
    }

    TEST("mesh stream: ended slots in a full table are reused, live slots "
         "never are") {
        mesh_loop_discard(a, a_queue, f.res_term);
        mesh_loop_discard(b, b_queue, f.term_peer.ini);
        mesh_stream_test_reset();
        stream_test_counters_reset();
        struct stream_test_link lk = {&mp, b, b_queue, f.term_peer.ini};
        uint8_t transcript[32];
        memset(transcript, 7, sizeof(transcript));
        for (uint8_t n = 0; n < MESH_STREAM_TABLE_MAX; n++) {
            uint8_t other[32];
            stream_test_peer_key(other, (uint8_t)(100u + n));
            ASSERT(mesh_stream_test_inject(STREAM_TEST_ECHO, other,
                                           transcript, 1, false,
                                           (uint64_t)(2u * n), 4096u, NULL));
        }

        /* Every slot live: the responder and a local open both refuse. */
        uint8_t fixture_peer[32];
        memcpy(fixture_peer, f.term_peer.noise_pub, 32);
        uint64_t local_id = UINT64_MAX;
        ASSERT_EQ(mesh_stream_open(STREAM_TEST_ECHO, f.resp_noise_pub,
                                   STREAM_TEST_WINDOW, NULL, 0, NULL,
                                   &local_id),
                  MESH_STREAM_REFUSED_CAP);
        ASSERT_EQ(stream_test_open_as(&lk, fixture_peer, 0,
                                      STREAM_TEST_ECHO),
                  MESH_STREAM_REFUSED_CAP);
        ASSERT_EQ(g_releases, (size_t)0);

        /* Every slot ended and lingering: a verdict is not a channel, so
         * one authorized peer's ended slots cannot keep the others out. */
        mesh_stream_visit(STREAM_TEST_ECHO, stream_test_end_all_visit, NULL);
        ASSERT_EQ(mesh_stream_test_live_count(STREAM_TEST_ECHO), (size_t)0);
        ASSERT_EQ(stream_test_open_as(&lk, fixture_peer, 2,
                                      STREAM_TEST_ECHO),
                  -1);
        ASSERT_EQ(mesh_stream_test_live_count(STREAM_TEST_ECHO), (size_t)1);
        ASSERT_EQ(g_releases, (size_t)1);
        ASSERT_EQ(mesh_stream_open(STREAM_TEST_ECHO, f.resp_noise_pub,
                                   STREAM_TEST_WINDOW, NULL, 0, NULL,
                                   &local_id),
                  MESH_STREAM_OK);
        ASSERT_EQ(g_releases, (size_t)2);
        PASS();
    }

    TEST("mesh stream: unpaired peers that fill the OPEN cadence table "
         "cannot cost a paired peer its next OPEN") {
        mesh_loop_discard(a, a_queue, f.res_term);
        mesh_loop_discard(b, b_queue, f.term_peer.ini);
        mesh_stream_test_reset();
        stream_test_counters_reset();
        ASSERT(stream_test_register(STREAM_TEST_GUARD,
                                    MESH_PAIRING_CAP_TERMINAL_EXEC));
        struct stream_test_link lk = {&mp, b, b_queue, f.term_peer.ini};
        uint8_t paired[32];
        stream_test_peer_key(paired, 0);
        ASSERT(stream_test_pair_stand_in(&f, paired, 0));
        g_stream_test_wall_s = INT64_C(1000000);
        clock_set_default(&g_stream_test_clock);

        /* The paired peer opens once and is admitted. */
        ASSERT_EQ(stream_test_open_as(&lk, paired, 0, STREAM_TEST_GUARD),
                  -1);
        ASSERT_EQ(mesh_stream_test_live_count(STREAM_TEST_GUARD), (size_t)1);

        /* The next second, as many unpaired peers as the cadence table has
         * slots each send one OPEN of the same service; every one is
         * refused as unpaired. */
        g_stream_test_wall_s++;
        for (uint8_t n = 1; n <= MESH_STREAM_PER_PEER_MAX; n++) {
            uint8_t stranger[32];
            stream_test_peer_key(stranger, n);
            ASSERT_EQ(stream_test_open_as(&lk, stranger, 0,
                                          STREAM_TEST_GUARD),
                      MESH_STREAM_REFUSED_PEER_UNPAIRED);
        }

        /* The paired peer's next OPEN in that second is still admitted. */
        ASSERT_EQ(stream_test_open_as(&lk, paired, 2, STREAM_TEST_GUARD),
                  -1);
        ASSERT_EQ(mesh_stream_test_live_count(STREAM_TEST_GUARD), (size_t)2);

        /* The unpaired flood is still bounded: one more stranger finds no
         * cadence slot left. A service with no pairing gate has nothing
         * for it to prove, so it is refused by name before any read. */
        uint8_t late[32];
        stream_test_peer_key(late, 20);
        ASSERT_EQ(stream_test_open_as(&lk, late, 0, STREAM_TEST_ECHO),
                  MESH_STREAM_REFUSED_RATE);
        clock_reset_default();
        mesh_stream_service_unregister(STREAM_TEST_GUARD);
        PASS();
    }

    TEST("mesh stream: a paired peer with no cadence slot opens while "
         "strangers fill the table in the same second") {
        mesh_loop_discard(a, a_queue, f.res_term);
        mesh_loop_discard(b, b_queue, f.term_peer.ini);
        mesh_stream_test_reset();
        stream_test_counters_reset();
        ASSERT(stream_test_register(STREAM_TEST_GUARD,
                                    MESH_PAIRING_CAP_TERMINAL_EXEC));
        struct stream_test_link lk = {&mp, b, b_queue, f.term_peer.ini};
        uint8_t paired[32];
        stream_test_peer_key(paired, 50);
        ASSERT(stream_test_pair_stand_in(&f, paired, 50));
        g_stream_test_wall_s = INT64_C(2000000);
        clock_set_default(&g_stream_test_clock);

        /* The paired peer has opened nothing yet; strangers take every
         * unpaired slot of this second first. */
        for (uint8_t n = 1; n <= MESH_STREAM_PER_PEER_MAX; n++) {
            uint8_t stranger[32];
            stream_test_peer_key(stranger, n);
            ASSERT_EQ(stream_test_open_as(&lk, stranger, 0,
                                          STREAM_TEST_GUARD),
                      MESH_STREAM_REFUSED_PEER_UNPAIRED);
        }
        ASSERT_EQ(stream_test_open_as(&lk, paired, 0, STREAM_TEST_GUARD),
                  -1);
        ASSERT_EQ(mesh_stream_test_live_count(STREAM_TEST_GUARD), (size_t)1);
        /* It now holds a paired slot, so its next OPEN spends no shared
         * read. */
        ASSERT_EQ(stream_test_open_as(&lk, paired, 2, STREAM_TEST_GUARD),
                  -1);

        /* The shared reads are bounded: one went to the paired peer, so
         * the remaining ones go to strangers, then none are left. */
        for (uint8_t n = 21; n < 21u + MESH_STREAM_OPEN_OVERFLOW_PER_SECOND - 1u;
             n++) {
            uint8_t stranger[32];
            stream_test_peer_key(stranger, n);
            ASSERT_EQ(stream_test_open_as(&lk, stranger, 0,
                                          STREAM_TEST_GUARD),
                      MESH_STREAM_REFUSED_PEER_UNPAIRED);
        }
        uint8_t spent[32];
        stream_test_peer_key(spent, 40);
        ASSERT_EQ(stream_test_open_as(&lk, spent, 0, STREAM_TEST_GUARD),
                  MESH_STREAM_REFUSED_RATE);
        clock_reset_default();
        mesh_stream_service_unregister(STREAM_TEST_GUARD);
        PASS();
    }

    failures += stream_test_case_ninth_paired(&f, a, a_queue, &mp, b,
                                              b_queue);
    failures += stream_test_case_failed_open_keeps_ended(&f, a, a_queue, b,
                                                         b_queue);
    failures += stream_test_case_ended_id_kept(&f, a, a_queue, &mp, b,
                                               b_queue);
    failures += stream_test_case_verdicts_leave_room(&f, a, a_queue, &mp, b,
                                                     b_queue);
    failures += stream_test_case_multi_session(dir, &nm, &mp);

_test_next:
    clock_reset_default();
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
