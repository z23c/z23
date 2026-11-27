/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Push one fleet post to a roster peer that has no working pairing
 * row, on "board.rpush". The OPEN is the paired push head, then a 96-byte
 * roster proof (side PUSH, cursor FLEET_BOARD_ROSTER_PUSH_AFTER), then the
 * records. The paired push inbox and push_opened counter are not used. The
 * pull remains the repair. See config/boot_fleet_board.h.
 */

#include "boot_fleet_board_roster_internal.h"

#include "boot_fleet_board_authority_internal.h"
#include "boot_fleet_board_frame_internal.h"
#include "boot_fleet_board_push_internal.h"
#include "boot_mesh_status_internal.h"
#include "config/boot_fleet_board.h"
#include "config/boot_fleet_roster.h"
#include "config/boot_internal.h"
#include "config/mesh_stream.h"
#include "config/runtime.h"

#include "base/safe_alloc.h"
#include "models/fleet_board_post.h"
#include "net/net.h"
#include "net/noise_transport.h"
#include "platform/time_compat.h"
#include "services/p2p_node_noise.h"
#include "session/fleet_board_proto.h"
#include "util/sync.h"

#include <stdatomic.h>
#include <string.h>

#define RP_INBOX 4u
#define RP_SESSIONS 32u

struct rp_slot {
    uint8_t state; /* 0 free, 1 filled */
    uint32_t seq;
    uint8_t peer[32];
    uint8_t author[32];
    uint8_t *bytes;
    size_t len;
};

struct rp_in_state {
    uint32_t slot;
    uint32_t seq;
};

struct rp_out_state {
    uint8_t n;
    /* The delivery note indexes this up to FLEET_BOARD_PUSH_POSTS_MAX.
     * A one-row array makes that read a zero-size region under LTO. */
    uint8_t ids[FLEET_BOARD_PUSH_POSTS_MAX][32];
    bool closed;
};

struct rp_session {
    bool used;
    uint8_t peer[32];
    uint8_t transcript[32];
    uint64_t generation;
};

static struct rp_slot g_inbox[RP_INBOX];
static uint32_t g_seq;
static struct rp_session g_unsup[RP_SESSIONS];
static size_t g_unsup_next;
static zcl_mutex_t g_lock;
static zcl_once_t g_once = ZCL_ONCE_INIT;
static bool g_enabled = true;
static _Atomic uint64_t g_stored;
static _Atomic uint64_t g_unsupported;

#ifdef ZCL_TESTING
static bool g_test_unknown;
#endif

static void rp_lock_init(void)
{
    zcl_mutex_init(&g_lock);
}

static void rp_lock(void)
{
    (void)zcl_once_call(&g_once, rp_lock_init);
    zcl_mutex_lock(&g_lock);
}

static void rp_unlock(void)
{
    zcl_mutex_unlock(&g_lock);
}

static int64_t rp_now_ms(void)
{
    return platform_time_realtime_us() / 1000;
}

static enum mesh_stream_refusal rp_refuse(uint8_t code,
                                          enum mesh_stream_refusal why,
                                          uint8_t *reply, size_t reply_cap,
                                          size_t *reply_len)
{
    struct board_push_receipt rc;
    memset(&rc, 0, sizeof rc);
    rc.code = code;
    rc.commit_ms = rp_now_ms();
    if (reply && reply_len && reply_cap >= FLEET_BOARD_PUSH_RECEIPT_MAX)
        *reply_len = board_push_receipt_encode(&rc, reply);
    return why;
}

/* Head, then the proof, then the records of a normal push. */
static bool rp_normalize(const uint8_t *payload, size_t len, uint8_t proof[96],
                         uint8_t **norm, size_t *norm_len)
{
    const size_t proof_at = FLEET_BOARD_PUSH_HEAD;
    size_t nlen;
    *norm = NULL;
    *norm_len = 0;
    if (!payload || len < proof_at + FLEET_BOARD_ROSTER_PROOF_BYTES ||
        len > FLEET_BOARD_PUSH_MAX + FLEET_BOARD_ROSTER_PROOF_BYTES)
        return false;
    nlen = len - FLEET_BOARD_ROSTER_PROOF_BYTES;
    if (nlen < FLEET_BOARD_PUSH_HEAD || nlen > FLEET_BOARD_PUSH_MAX)
        return false;
    *norm = zcl_malloc(nlen, "fleet_board_roster_push");
    if (!*norm)
        return false;
    memcpy(*norm, payload, FLEET_BOARD_PUSH_HEAD);
    memcpy(proof, payload + proof_at, FLEET_BOARD_ROSTER_PROOF_BYTES);
    memcpy(*norm + FLEET_BOARD_PUSH_HEAD,
           payload + proof_at + FLEET_BOARD_ROSTER_PROOF_BYTES,
           nlen - FLEET_BOARD_PUSH_HEAD);
    *norm_len = nlen;
    if (board_push_valid(*norm, nlen, NULL))
        return true;
    free(*norm);
    *norm = NULL;
    *norm_len = 0;
    return false;
}

static enum mesh_stream_refusal rp_gate(struct mesh_stream *st,
                                        const uint8_t proof[96])
{
    struct fleet_board_roster_bind bind;
    struct node_db *pairings = app_runtime_node_db();
    struct node_db *store = board_db();
    memset(&bind, 0, sizeof bind);
    if (!g_enabled || !pairings || !app_runtime_node_db_handle_open(pairings) ||
        !store || !board_network_genesis(bind.network_genesis))
        return MESH_STREAM_REFUSED_UNAVAILABLE;
    memcpy(bind.transcript_hash, st->transcript_hash, 32);
    bind.connection_generation = st->connection_generation;
    bind.after = FLEET_BOARD_ROSTER_PUSH_AFTER;
    if (!fleet_board_roster_standing(pairings, store, st->peer_static, proof,
                                     board_now()))
        return MESH_STREAM_REFUSED_PEER_UNPAIRED;
    if (!fleet_board_roster_proof_check(FLEET_BOARD_ROSTER_SIDE_PUSH, &bind,
                                        proof))
        return MESH_STREAM_REFUSED_MALFORMED;
    if (!board_push_may_read(proof))
        return MESH_STREAM_REFUSED_PEER_UNPAIRED;
    return MESH_STREAM_OK;
}

static uint8_t rp_inbox_put(struct mesh_stream *st, const uint8_t author[32],
                            uint8_t *bytes, size_t len, struct rp_in_state *out)
{
    struct rp_slot *free_slot = NULL;
    uint8_t code = FLEET_BOARD_PUSH_CODE_INBOX_FULL;
    rp_lock();
    for (size_t i = 0; i < RP_INBOX; i++) {
        if (g_inbox[i].state != 0 &&
            memcmp(g_inbox[i].peer, st->peer_static, 32) == 0) {
            code = FLEET_BOARD_PUSH_CODE_BUSY;
            free_slot = NULL;
            break;
        }
        if (g_inbox[i].state == 0 && !free_slot)
            free_slot = &g_inbox[i];
    }
    if (free_slot) {
        if (++g_seq == 0)
            g_seq = 1;
        free_slot->state = 1;
        free_slot->seq = g_seq;
        memcpy(free_slot->peer, st->peer_static, 32);
        memcpy(free_slot->author, author, 32);
        free_slot->bytes = bytes;
        free_slot->len = len;
        out->slot = (uint32_t)(free_slot - g_inbox);
        out->seq = free_slot->seq;
        code = FLEET_BOARD_PUSH_CODE_COMMITTED;
    }
    rp_unlock();
    return code;
}

static void rp_drop_in(void *state)
{
    struct rp_in_state *s = state;
    if (!s)
        return;
    rp_lock();
    if (s->slot < RP_INBOX && g_inbox[s->slot].state == 1 &&
        g_inbox[s->slot].seq == s->seq) {
        free(g_inbox[s->slot].bytes);
        g_inbox[s->slot].bytes = NULL;
        g_inbox[s->slot].state = 0;
        g_inbox[s->slot].len = 0;
    }
    rp_unlock();
}

static enum mesh_stream_refusal rp_on_open(struct mesh_stream *st,
                                           const uint8_t *payload, size_t len,
                                           uint8_t *reply, size_t reply_cap,
                                           size_t *reply_len, void *ctx)
{
    uint8_t proof[FLEET_BOARD_ROSTER_PROOF_BYTES];
    uint8_t *norm = NULL;
    size_t nlen = 0;
    enum mesh_stream_refusal gate;
    struct rp_in_state *in;
    uint8_t code;
    (void)ctx;
    if (reply_len)
        *reply_len = 0;
#ifdef ZCL_TESTING
    if (g_test_unknown)
        return MESH_STREAM_REFUSED_SERVICE_UNKNOWN;
#endif
    if (!rp_normalize(payload, len, proof, &norm, &nlen))
        return rp_refuse(FLEET_BOARD_PUSH_CODE_MALFORMED,
                         MESH_STREAM_REFUSED_MALFORMED, reply, reply_cap,
                         reply_len);
    gate = rp_gate(st, proof);
    if (gate != MESH_STREAM_OK) {
        uint8_t code = FLEET_BOARD_PUSH_CODE_REVOKED;
        free(norm);
        if (gate == MESH_STREAM_REFUSED_MALFORMED)
            code = FLEET_BOARD_PUSH_CODE_MALFORMED;
        else if (gate == MESH_STREAM_REFUSED_UNAVAILABLE)
            code = FLEET_BOARD_PUSH_CODE_UNAVAILABLE;
        return rp_refuse(code, gate, reply, reply_cap, reply_len);
    }
    in = zcl_calloc(1, sizeof *in, "fleet_board_roster_push_in");
    if (!in) {
        free(norm);
        return rp_refuse(FLEET_BOARD_PUSH_CODE_UNAVAILABLE,
                         MESH_STREAM_REFUSED_UNAVAILABLE, reply, reply_cap,
                         reply_len);
    }
    code = rp_inbox_put(st, proof, norm, nlen, in);
    if (code != FLEET_BOARD_PUSH_CODE_COMMITTED) {
        free(norm);
        free(in);
        return rp_refuse(code, MESH_STREAM_CLOSED_BY_SERVICE, reply, reply_cap,
                         reply_len);
    }
    st->service_state = in;
    return MESH_STREAM_OK;
}

static uint8_t rp_screen(const struct board_push_record *rec,
                         const uint8_t author[32], struct node_db *store,
                         struct fleet_board_post *post, uint8_t *verdict,
                         uint8_t *result, bool *decoded)
{
    enum fleet_board_result r;
    *decoded = false;
    *result = FLEET_BOARD_OK;
    r = fleet_board_post_decode(rec->wire, rec->wire_len, post);
    if (r != FLEET_BOARD_OK) {
        *verdict = FLEET_BOARD_PUSH_RECORD_REFUSED;
        *result = (uint8_t)r;
        return FLEET_BOARD_PUSH_CODE_COMMITTED;
    }
    if (memcmp(post->id, rec->id, 32) != 0 ||
        post->scope != FLEET_BOARD_SCOPE_FLEET)
        return FLEET_BOARD_PUSH_CODE_MALFORMED;
    if (memcmp(post->host_pubkey, author, 32) != 0)
        return FLEET_BOARD_PUSH_CODE_AUTHOR;
    if (db_fleet_board_have(store, rec->id)) {
        *verdict = FLEET_BOARD_PUSH_RECORD_HELD;
        return FLEET_BOARD_PUSH_CODE_COMMITTED;
    }
    *decoded = true;
    return FLEET_BOARD_PUSH_CODE_COMMITTED;
}

static uint8_t rp_ingest(struct node_db *store, const struct fleet_board_post *post,
                         int64_t now, uint8_t *result)
{
    bool stored = false;
    enum fleet_board_result r = boot_fleet_roster_screen_post(store, post, now);
    if (r == FLEET_BOARD_OK) {
        db_fleet_board_post_prepare_nowait();
        r = db_fleet_board_post_ingest_nowait(store, post, now, &stored);
    }
    if (r == FLEET_BOARD_OK && stored && boot_fleet_roster_is_row(post))
        boot_fleet_roster_invalidate();
    *result = (r == FLEET_BOARD_ERR_BUSY || r == FLEET_BOARD_ERR_CAPACITY ||
               r == FLEET_BOARD_ERR_STORAGE || r == FLEET_BOARD_ERR_WIKI_QUOTA)
                  ? (uint8_t)FLEET_BOARD_OK
                  : (uint8_t)r;
    if (r == FLEET_BOARD_OK) {
        if (stored)
            atomic_fetch_add_explicit(&g_stored, 1, memory_order_relaxed);
        return stored ? FLEET_BOARD_PUSH_RECORD_STORED
                      : FLEET_BOARD_PUSH_RECORD_HELD;
    }
    return board_refusal_retryable(r) ? FLEET_BOARD_PUSH_RECORD_DEFERRED
                                      : FLEET_BOARD_PUSH_RECORD_REFUSED;
}

static void rp_fill_receipt(struct node_db *store, const struct rp_slot *slot,
                            struct board_push_receipt *rc)
{
    struct fleet_board_post *posts;
    struct node_db *pairings = app_runtime_node_db();
    size_t off = FLEET_BOARD_PUSH_HEAD;
    unsigned n = 0;
    uint8_t code = FLEET_BOARD_PUSH_CODE_COMMITTED;
    bool decoded[FLEET_BOARD_PUSH_POSTS_MAX] = { false };
    memset(rc, 0, sizeof *rc);
    if (!store || !pairings || !app_runtime_node_db_handle_open(pairings)) {
        rc->code = FLEET_BOARD_PUSH_CODE_UNAVAILABLE;
        return;
    }
    if (!fleet_board_roster_standing(pairings, store, slot->peer, slot->author,
                                     board_now())) {
        rc->code = FLEET_BOARD_PUSH_CODE_REVOKED;
        return;
    }
    posts = zcl_calloc(FLEET_BOARD_PUSH_POSTS_MAX, sizeof *posts,
                       "fleet_board_roster_push_commit");
    if (!posts) {
        rc->code = FLEET_BOARD_PUSH_CODE_UNAVAILABLE;
        return;
    }
    while (code == FLEET_BOARD_PUSH_CODE_COMMITTED &&
           n < FLEET_BOARD_PUSH_POSTS_MAX) {
        struct board_push_record rec;
        if (!board_push_record_next(slot->bytes, slot->len, &off, &rec))
            break;
        memcpy(rc->rec[n].id, rec.id, 32);
        code = rp_screen(&rec, slot->author, store, &posts[n],
                         &rc->rec[n].verdict, &rc->rec[n].result, &decoded[n]);
        n++;
    }
    rc->code = code;
    rc->n = code == FLEET_BOARD_PUSH_CODE_COMMITTED ? (uint8_t)n : 0;
    for (unsigned i = 0; i < rc->n; i++) {
        if (decoded[i])
            rc->rec[i].verdict =
                rp_ingest(store, &posts[i], board_now(), &rc->rec[i].result);
    }
    free(posts);
}

struct rp_answer {
    uint32_t slot;
    uint32_t seq;
    const uint8_t *receipt;
    size_t len;
};

static bool rp_answer_visit(struct mesh_stream *st, void *ctx)
{
    const struct rp_answer *a = ctx;
    const struct rp_in_state *s = st->service_state;
    if (st->ended || st->local_initiator || !s || s->slot != a->slot ||
        s->seq != a->seq)
        return true;
    mesh_stream_close(st, MESH_STREAM_CLOSED_BY_SERVICE, a->receipt, a->len);
    return false;
}

static bool rp_take(struct rp_slot *out, uint32_t *slot, uint32_t *seq)
{
    bool found = false;
    rp_lock();
    for (size_t i = 0; i < RP_INBOX && !found; i++) {
        if (g_inbox[i].state != 1)
            continue;
        *out = g_inbox[i];
        *slot = (uint32_t)i;
        *seq = g_inbox[i].seq;
        g_inbox[i].state = 0;
        g_inbox[i].bytes = NULL;
        g_inbox[i].len = 0;
        found = true;
    }
    rp_unlock();
    return found;
}

void boot_fleet_board_roster_push_tick(struct node_db *store)
{
    struct rp_slot slot;
    uint32_t index = 0, seq = 0;
    struct board_push_receipt rc;
    uint8_t receipt[FLEET_BOARD_PUSH_RECEIPT_MAX];
    struct rp_answer answer;
    if (!rp_take(&slot, &index, &seq))
        return;
    rp_fill_receipt(store, &slot, &rc);
    rc.commit_ms = rp_now_ms();
    answer.slot = index;
    answer.seq = seq;
    answer.receipt = receipt;
    answer.len = board_push_receipt_encode(&rc, receipt);
    mesh_stream_visit(FLEET_BOARD_ROSTER_PUSH_SERVICE_NAME, rp_answer_visit,
                      &answer);
    free(slot.bytes);
}

static bool rp_unsupported(const uint8_t peer[32], const uint8_t transcript[32],
                           uint64_t generation)
{
    bool found = false;
    rp_lock();
    for (size_t i = 0; i < RP_SESSIONS && !found; i++)
        found = g_unsup[i].used && memcmp(g_unsup[i].peer, peer, 32) == 0 &&
                memcmp(g_unsup[i].transcript, transcript, 32) == 0 &&
                g_unsup[i].generation == generation;
    rp_unlock();
    return found;
}

static void rp_mark_unsupported(const uint8_t peer[32],
                                const uint8_t transcript[32],
                                uint64_t generation)
{
    rp_lock();
    for (size_t i = 0; i < RP_SESSIONS; i++) {
        if (!g_unsup[i].used || memcmp(g_unsup[i].peer, peer, 32) != 0 ||
            memcmp(g_unsup[i].transcript, transcript, 32) != 0 ||
            g_unsup[i].generation != generation)
            continue;
        rp_unlock();
        return;
    }
    g_unsup[g_unsup_next].used = true;
    memcpy(g_unsup[g_unsup_next].peer, peer, 32);
    memcpy(g_unsup[g_unsup_next].transcript, transcript, 32);
    g_unsup[g_unsup_next].generation = generation;
    g_unsup_next = (g_unsup_next + 1) % RP_SESSIONS;
    rp_unlock();
    atomic_fetch_add_explicit(&g_unsupported, 1, memory_order_relaxed);
}

struct rp_live {
    const uint8_t *peer;
    bool found;
};

static bool rp_live_visit(struct mesh_stream *st, void *ctx)
{
    struct rp_live *live = ctx;
    if (st->local_initiator && !st->ended &&
        memcmp(st->peer_static, live->peer, 32) == 0) {
        live->found = true;
        return false;
    }
    return true;
}

static bool rp_build(const struct fleet_board_post *post,
                     const uint8_t proof[FLEET_BOARD_ROSTER_PROOF_BYTES],
                     uint8_t **wire, size_t *wlen)
{
    uint8_t *body = zcl_malloc(FLEET_BOARD_PUSH_MAX, "fleet_board_roster_push");
    size_t blen = FLEET_BOARD_PUSH_HEAD;
    *wire = NULL;
    *wlen = 0;
    if (!body)
        return false;
    board_push_begin(body);
    if (!board_push_append_post(body, &blen, post)) {
        free(body);
        return false;
    }
    *wlen = blen + FLEET_BOARD_ROSTER_PROOF_BYTES;
    *wire = zcl_malloc(*wlen, "fleet_board_roster_push_wire");
    if (!*wire) {
        free(body);
        return false;
    }
    memcpy(*wire, body, FLEET_BOARD_PUSH_HEAD);
    memcpy(*wire + FLEET_BOARD_PUSH_HEAD, proof, FLEET_BOARD_ROSTER_PROOF_BYTES);
    memcpy(*wire + FLEET_BOARD_PUSH_HEAD + FLEET_BOARD_ROSTER_PROOF_BYTES,
           body + FLEET_BOARD_PUSH_HEAD, blen - FLEET_BOARD_PUSH_HEAD);
    free(body);
    return true;
}

static void rp_out_closed(struct mesh_stream *st, enum mesh_stream_refusal reason,
                          const uint8_t *payload, size_t len)
{
    struct rp_out_state *s = st->service_state;
    struct board_push_receipt rc;
    if (!s || s->closed)
        return;
    s->closed = true;
    if (board_push_receipt_decode(payload, len, &rc)) {
        board_delivery_note_receipt(st->peer_static, s->ids, s->n, &rc,
                                    board_now());
        return;
    }
    if (reason == MESH_STREAM_REFUSED_SERVICE_UNKNOWN ||
        (reason == MESH_STREAM_REFUSED_MALFORMED && len == 0))
        rp_mark_unsupported(st->peer_static, st->transcript_hash,
                            st->connection_generation);
    board_delivery_note_unanswered(st->peer_static, s->ids, s->n,
                                   reason == MESH_STREAM_REFUSED_SERVICE_UNKNOWN
                                       ? "peer_unsupported"
                                       : "no_receipt",
                                   board_now());
}

static void rp_on_close(struct mesh_stream *st, enum mesh_stream_refusal reason,
                        const uint8_t *payload, size_t len, void *ctx)
{
    (void)ctx;
    if (st->local_initiator)
        rp_out_closed(st, reason, payload, len);
    mesh_stream_release(st);
}

static void rp_on_release(struct mesh_stream *st, void *ctx)
{
    (void)ctx;
    if (st && !st->local_initiator)
        rp_drop_in(st->service_state);
    free(st->service_state);
    st->service_state = NULL;
}

static void rp_on_data(struct mesh_stream *st, const uint8_t *payload,
                       size_t len, void *ctx)
{
    (void)payload;
    (void)len;
    (void)ctx;
    /* The post rode the OPEN. A later DATA frame is not a record, so drop
     * a push this half has not committed yet and refuse the stream. */
    if (!st->local_initiator)
        rp_drop_in(st->service_state);
    mesh_stream_close(st, MESH_STREAM_REFUSED_MALFORMED, NULL, 0);
}

bool boot_fleet_board_roster_push_register(void)
{
    struct mesh_stream_service service;
    memset(&service, 0, sizeof service);
    mesh_stream_service_unregister(FLEET_BOARD_ROSTER_PUSH_SERVICE_NAME);
    service.name = FLEET_BOARD_ROSTER_PUSH_SERVICE_NAME;
    service.required_pairing_capability = 0;
    service.on_open = rp_on_open;
    service.on_data = rp_on_data;
    service.on_close = rp_on_close;
    service.on_release = rp_on_release;
    return mesh_stream_service_register(&service);
}

void boot_fleet_board_roster_push_forget(void)
{
    rp_lock();
    for (size_t i = 0; i < RP_INBOX; i++) {
        free(g_inbox[i].bytes);
        g_inbox[i].bytes = NULL;
        g_inbox[i].state = 0;
        g_inbox[i].len = 0;
    }
    memset(g_unsup, 0, sizeof g_unsup);
    g_unsup_next = 0;
    rp_unlock();
}

/* False when this peer has no live session, or the send budget is spent.
 * The node is released before return; `snap` is the session this OPEN binds. */
static bool rp_peer_ready(struct boot_svc_ctx *svc, const uint8_t peer[32],
                          const struct noise_transport_snapshot *expected,
                          struct noise_transport_snapshot *snap)
{
    struct p2p_node *node;
    if (!svc || !svc->msg_processor || !svc->msg_processor->net_mgr)
        return false;
    node = expected
        ? boot_mesh_find_session_bound(svc->msg_processor->net_mgr, peer,
                                       expected->transcript_hash, expected->connection_generation, snap)
        : boot_mesh_find_session_peer(svc->msg_processor->net_mgr, peer, snap);
    if (!node)
        return false;
    if (net_send_over_budget(node)) {
        p2p_node_release(node);
        return false;
    }
    p2p_node_release(node);
    return true;
}

static bool rp_target_allowed(const uint8_t peer[32],
                              const struct noise_transport_snapshot *snap,
                              const uint8_t target[32])
{
    uint8_t proved[32];
    return fleet_board_roster_session_standing(app_runtime_node_db(), board_db(), peer,
               snap->transcript_hash, snap->connection_generation, board_now(), proved) &&
           (!target || memcmp(proved, target, 32) == 0) && board_push_may_read(proved);
}

static int rp_offer(struct boot_svc_ctx *svc, const uint8_t peer[32],
                    const struct fleet_board_post *post,
                    const struct noise_transport_snapshot *expected,
                    const uint8_t target[32])
{
    struct noise_transport_snapshot snap;
    struct fleet_board_roster_bind bind;
    struct rp_live live = { peer, false };
    struct rp_out_state *out;
    uint8_t proof[FLEET_BOARD_ROSTER_PROOF_BYTES];
    uint8_t *wire = NULL;
    size_t wlen = 0;
    uint64_t id = 0;
    enum mesh_stream_refusal opened;
    memset(&snap, 0, sizeof snap);
    memset(&bind, 0, sizeof bind);
    if (!g_enabled || !post || !rp_peer_ready(svc, peer, expected, &snap))
        return 0;
    if (rp_unsupported(peer, snap.transcript_hash, snap.connection_generation))
        return -1;
    mesh_stream_visit(FLEET_BOARD_ROSTER_PUSH_SERVICE_NAME, rp_live_visit, &live);
    if (live.found)
        return target ? 2 : 0;
    if (!rp_target_allowed(peer, &snap, target)) return 0;
    memcpy(bind.transcript_hash, snap.transcript_hash, 32);
    bind.connection_generation = snap.connection_generation;
    bind.after = FLEET_BOARD_ROSTER_PUSH_AFTER;
    if (!board_network_genesis(bind.network_genesis) ||
        !fleet_board_roster_proof_make(FLEET_BOARD_ROSTER_SIDE_PUSH, &bind,
                                       proof) ||
        !rp_build(post, proof, &wire, &wlen))
        return 0;
    out = zcl_calloc(1, sizeof *out, "fleet_board_roster_push_out");
    if (!out) {
        free(wire);
        return 0;
    }
    out->n = 1;
    memcpy(out->ids[0], post->id, 32);
    if (!rp_target_allowed(peer, &snap, target)) { free(wire); free(out); return 0; }
    opened = mesh_stream_open_bound(FLEET_BOARD_ROSTER_PUSH_SERVICE_NAME, peer, &snap,
                                    FLEET_BOARD_PUSH_WINDOW, wire, wlen, out, &id);
    free(wire);
    if (opened == MESH_STREAM_OK)
        return 1;
    free(out);
    if (opened == MESH_STREAM_REFUSED_SERVICE_UNKNOWN) {
        rp_mark_unsupported(peer, snap.transcript_hash,
                            snap.connection_generation);
        return -1;
    }
    return 0;
}

int boot_fleet_board_roster_push_offer(struct boot_svc_ctx *svc,
                                       const uint8_t peer[32],
                                       const struct fleet_board_post *post)
{
    return rp_offer(svc, peer, post, NULL, NULL);
}

int boot_fleet_board_roster_push_offer_bound(
    struct boot_svc_ctx *svc, const uint8_t peer[32],
    const struct fleet_board_post *post, const struct noise_transport_snapshot *session,
    const uint8_t target[32])
{
    if (!session || !target) return 0;
    return rp_offer(svc, peer, post, session, target);
}

#ifdef ZCL_TESTING
void boot_fleet_board_roster_push_test_enable(bool on)
{
    g_enabled = on;
}

void boot_fleet_board_roster_push_test_unknown(bool on)
{
    g_test_unknown = on;
}

uint64_t boot_fleet_board_roster_push_test_unsupported(void)
{
    return atomic_load_explicit(&g_unsupported, memory_order_relaxed);
}

size_t boot_fleet_board_roster_push_test_commit(struct node_db *store)
{
    uint64_t before = atomic_load_explicit(&g_stored, memory_order_relaxed);
    boot_fleet_board_roster_push_tick(store);
    return (size_t)(atomic_load_explicit(&g_stored, memory_order_relaxed) -
                    before);
}
#endif
