/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: PUSH on the paired "board" stream service
 * (config/boot_fleet_board.h). The sending half: a bounded queue of post ids
 * this box signed and stored, filled in O(1) from the publish path and
 * drained on the board lane's tick into one-shot streams whose whole payload
 * rides the OPEN, to the one paired peer the local caller's delivery hint
 * names or else the post answers and, for a post from the local post path,
 * to every other connected peer (boot_fleet_board_push_fanout.c), each only
 * when a pull from that peer would be served the post. The receiving half:
 * the OPEN is framed-checked and copied into a preallocated push inbox on
 * the frame path, nothing else; the lane tick re-proves the pusher, stores
 * every record through the checks a pulled post meets, and closes the
 * stream with a receipt. Nothing here is ever retried: the pull is.
 */

// one-result-type-ok:closed-security-verdict — board_push_accept returns the
// stream primitive's bounded refusal enum; the service's own name for each
// refusal rides the receipt, and failure logging happens here, named.

#include "boot_fleet_board_push_internal.h"
#include "boot_fleet_board_push_round_internal.h"

#include "boot_fleet_board_authority_internal.h"
#include "boot_fleet_board_frame_internal.h"
#include "boot_mesh_status_internal.h"
#include "config/boot_fleet_roster.h"
#include "config/boot_internal.h"
#include "config/runtime.h"

#include "base/hex.h"
#include "base/safe_alloc.h"
#include "models/fleet_board_post.h"
#include "models/mesh_pairing.h"
#include "net/msgprocessor.h"
#include "net/net.h"
#include "net/noise_transport.h"
#include "platform/time_compat.h"
#include "util/log_macros.h"
#include "util/sync.h"
#include "vcs/zcode_dht_identity.h"

#include <assert.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

static_assert(MESH_STREAM_CLOSED_BY_SERVICE < 16,
              "push_closed holds one count per primitive reason");
static_assert(FLEET_BOARD_PUSH_MAX <= MESH_STREAM_PAYLOAD_MAX,
              "a push rides one OPEN");
static_assert(FLEET_BOARD_PUSH_RECEIPT_MAX <= MESH_STREAM_SERVICE_REPLY_MAX,
              "a refusal receipt fits the reply an OPEN may carry");

/* The sending half's per-stream state: which posts rode the OPEN. */
struct board_push_out_state {
    enum board_state_tag tag; /* BOARD_STATE_PUSH_OUT; first, always */
    bool self_closed;         /* this box ended it: there is no receipt */
    uint8_t n;
    uint8_t ids[FLEET_BOARD_PUSH_POSTS_MAX][32];
};

/* The receiving half's per-stream state: which inbox slot holds the push. */
struct board_push_in_state {
    enum board_state_tag tag; /* BOARD_STATE_PUSH_IN; first, always */
    uint32_t slot;
    uint32_t seq;
};

enum push_slot_state {
    PUSH_SLOT_FREE = 0,
    PUSH_SLOT_FILLED,     /* copied on the frame path, waiting for the tick */
    PUSH_SLOT_COMMITTING, /* the tick owns it until it answers */
};

struct push_slot {
    enum push_slot_state state;
    uint32_t seq; /* names this fill, so a stale stream state frees nothing */
    uint8_t peer_static[32];
    size_t len;
    uint8_t bytes[FLEET_BOARD_PUSH_MAX];
};

/* A session that answered the push type stream_malformed: an older node. */
struct push_session {
    bool used;
    uint8_t peer_static[32];
    uint8_t transcript[32];
    uint64_t generation;
};

#define PUSH_SESSIONS_MAX 8u
#define PUSH_LOG_WINDOW_S 60

/* The most board keys one pusher's live pairing rows can prove at once. */
#define PUSH_PUSHER_KEYS_MAX 4u

enum push_log_kind {
    PUSH_LOG_SKIP = 0,
    PUSH_LOG_IN,
    PUSH_LOG_RECEIPT,
    PUSH_LOG_JUDGE_OUT, /* an addressee judged ineligible */
    PUSH_LOG_JUDGE_IN,  /* a pusher whose standing failed at the commit */
    PUSH_LOG_HINT,      /* a delivery hint refused */
    PUSH_LOG_KINDS
};

/* A leaf lock: taken under the stream lane lock from the callbacks and with
 * no lock from the tick and the publish path, and never held across a store,
 * stream or board-lock call. */
static zcl_mutex_t g_push_lock;
static zcl_once_t g_push_once = ZCL_ONCE_INIT;
static struct push_queued g_queue[FLEET_BOARD_PUSH_QUEUE_MAX];
static size_t g_queue_head;
static size_t g_queue_len;
static _Atomic size_t g_queue_count; /* g_queue_len, for the idle tick */
static struct push_slot g_inbox[FLEET_BOARD_PUSH_INBOX_MAX];
static uint32_t g_slot_seq;
static _Atomic size_t g_inbox_filled; /* FILLED slots, for the idle tick */
static struct push_session g_unsupported[PUSH_SESSIONS_MAX];
static size_t g_unsupported_next;
/* Bumped when a post is queued and when a push this box sent ends: what can
 * make a sending round do something the last one could not. */
static _Atomic uint64_t g_send_gen;
static uint64_t g_round_gen;    /* g_send_gen when the last round ran */
static int64_t g_round_second; /* the lane second it ran in */
static struct {
    int64_t last;
    uint64_t skipped;
} g_log[PUSH_LOG_KINDS];

static _Atomic uint64_t g_queued;
static _Atomic uint64_t g_opened;
static _Atomic uint64_t g_skipped[FLEET_BOARD_PUSH_SKIPS];
static _Atomic uint64_t g_closed[16];
static _Atomic uint64_t g_receipt[FLEET_BOARD_PUSH_CODES];
static _Atomic uint64_t g_receipt_records[FLEET_BOARD_PUSH_VERDICTS];
static _Atomic uint64_t g_in[FLEET_BOARD_PUSH_CODES];
static _Atomic uint64_t g_in_records[FLEET_BOARD_PUSH_VERDICTS];
static _Atomic uint64_t g_in_dropped;
static _Atomic uint64_t g_data_refused;
static _Atomic uint64_t g_refused_out[FLEET_BOARD_PUSH_REFUSALS];
static _Atomic uint64_t g_refused_in[FLEET_BOARD_PUSH_REFUSALS];
static _Atomic uint64_t g_hint[FLEET_BOARD_PUSH_HINTS];

#ifdef ZCL_TESTING
static bool g_test_pre_push;
static _Atomic uint64_t g_test_peer_walks;
#endif

static const char *const k_skip_names[FLEET_BOARD_PUSH_SKIPS] = {
    "not_own",     "no_addressee", "queue_full",    "gone",
    "unresolved",  "ambiguous",    "ineligible",    "not_connected",
    "over_budget", "unsupported",  "busy",          "too_large",
    "open_failed", "no_receipt",   "expired",
};

static const char *const k_hint_names[FLEET_BOARD_PUSH_HINTS] = {
    "none",      "queued",     "malformed", "not_fleet",
    "not_own",   "not_stored", "self",
};

static const char *const k_code_names[FLEET_BOARD_PUSH_CODES] = {
    "committed",   "push_malformed", "push_author_mismatch", "push_inbox_full",
    "push_busy",   "push_revoked",   "push_unavailable",
};

static const char *const k_refusal_names[FLEET_BOARD_PUSH_REFUSALS] = {
    "no pairing row grants the status capability",
    "delegation unresolved or not current",
    "no read role",
    "not on the fleet roster",
};

static void push_lock_init(void)
{
    zcl_mutex_init(&g_push_lock);
}

static void push_lock(void)
{
    (void)zcl_once_call(&g_push_once, push_lock_init);
    zcl_mutex_lock(&g_push_lock);
}

static void push_unlock(void)
{
    zcl_mutex_unlock(&g_push_lock);
}

static void push_bump(_Atomic uint64_t *counter, uint64_t by)
{
    atomic_fetch_add_explicit(counter, by, memory_order_relaxed);
}

/* One line per kind per PUSH_LOG_WINDOW_S; `*skipped` receives how many were
 * left out since the last one. */
static bool push_log_due(enum push_log_kind kind, uint64_t *skipped)
{
    int64_t now = (int64_t)platform_time_wall_time_t();
    push_lock();
    bool due = now < g_log[kind].last ||
               now - g_log[kind].last >= PUSH_LOG_WINDOW_S;
    if (due) {
        *skipped = g_log[kind].skipped;
        g_log[kind].skipped = 0;
        g_log[kind].last = now;
    } else {
        g_log[kind].skipped++;
    }
    push_unlock();
    return due;
}

/* Count `n` posts not pushed for `why`; the reasons a push could have gone
 * and did not are logged, rate limited. */
void board_push_skip(enum fleet_board_push_skip why, uint64_t n)
{
    push_bump(&g_skipped[why], n);
    uint64_t skipped = 0;
    /* An ineligible addressee is logged, with the check it failed, by
     * push_peer_judge. */
    if (why > FLEET_BOARD_PUSH_SKIP_QUEUE_FULL &&
        why != FLEET_BOARD_PUSH_SKIP_INELIGIBLE &&
        push_log_due(PUSH_LOG_SKIP, &skipped))
        LOG_INFO("fleet.board", "fleet push skipped: %s, %llu post(s); the "
                 "pull carries them (%llu more lines since the last)",
                 k_skip_names[why], (unsigned long long)n,
                 (unsigned long long)skipped);
}

/* A push judgment that refused a peer: counted by the check that failed, in
 * the push's own counters, and logged at most once a window. */
static void push_refused(bool sending, enum fleet_board_push_refusal why)
{
    push_bump(sending ? &g_refused_out[why] : &g_refused_in[why], 1);
    uint64_t skipped = 0;
    if (!push_log_due(sending ? PUSH_LOG_JUDGE_OUT : PUSH_LOG_JUDGE_IN,
                      &skipped))
        return;
    if (sending)
        LOG_INFO("fleet.board", "fleet push skipped: the addressee failed a "
                 "push check (%s); the pull carries the post (%llu more "
                 "lines since the last)", k_refusal_names[why],
                 (unsigned long long)skipped);
    else
        LOG_WARN("fleet.board", "fleet push refused at commit: the pusher "
                 "failed a push check (%s) (%llu more lines since the last)",
                 k_refusal_names[why], (unsigned long long)skipped);
}

static int64_t push_now_ms(void)
{
    return platform_time_realtime_us() / 1000;
}

/* ── the queue (any thread, O(1)) ─────────────────────────────────────── */

static bool push_id_zero(const uint8_t id[32])
{
    static const uint8_t zero[32];
    return memcmp(id, zero, 32) == 0;
}

const char *boot_fleet_board_push_hint_name(enum fleet_board_push_hint h)
{
    return (unsigned)h < FLEET_BOARD_PUSH_HINTS ? k_hint_names[h] : "unknown";
}

/* Count what was done with a hint; a refused one is logged, rate limited. */
static enum fleet_board_push_hint push_hint_count(enum fleet_board_push_hint h)
{
    if (h == FLEET_BOARD_PUSH_HINT_NONE)
        return h;
    push_bump(&g_hint[h], 1);
    uint64_t skipped = 0;
    if (h != FLEET_BOARD_PUSH_HINT_QUEUED &&
        push_log_due(PUSH_LOG_HINT, &skipped))
        LOG_INFO("fleet.board", "fleet push hint refused: %s; the post is "
                 "handled as if it carried none (%llu more lines since the "
                 "last)", k_hint_names[h], (unsigned long long)skipped);
    return h;
}

/* NONE for no hint, MALFORMED unless it is exactly 64 lowercase hex, else
 * QUEUED with the key in `to` (not yet judged against the post). */
static enum fleet_board_push_hint push_hint_parse(const char *push_to,
                                                  uint8_t to[32])
{
    if (!push_to)
        return FLEET_BOARD_PUSH_HINT_NONE;
    return strlen(push_to) == 64 && zcl_hex_decode_lower(push_to, to, 32)
               ? FLEET_BOARD_PUSH_HINT_QUEUED
               : FLEET_BOARD_PUSH_HINT_MALFORMED;
}

enum fleet_board_push_hint boot_fleet_board_fleet_push_hint_unused(
    const char *push_to)
{
    uint8_t to[32];
    enum fleet_board_push_hint h = push_hint_parse(push_to, to);
    return push_hint_count(h == FLEET_BOARD_PUSH_HINT_QUEUED
                               ? FLEET_BOARD_PUSH_HINT_NOT_STORED
                               : h);
}

void boot_fleet_board_fleet_push_enqueue(const struct fleet_board_post *post,
                                         const uint8_t own_key[32])
{
    (void)boot_fleet_board_fleet_push_enqueue_to(post, own_key, NULL);
}

/* Append one entry under the push lock; a full queue gives up its oldest. */
static void push_queue_put(const struct push_queued *q)
{
    bool dropped = false;
    push_lock();
    if (g_queue_len == FLEET_BOARD_PUSH_QUEUE_MAX) {
        g_queue_head = (g_queue_head + 1) % FLEET_BOARD_PUSH_QUEUE_MAX;
        g_queue_len--;
        dropped = true;
    }
    g_queue[(g_queue_head + g_queue_len) % FLEET_BOARD_PUSH_QUEUE_MAX] = *q;
    g_queue_len++;
    atomic_store_explicit(&g_queue_count, g_queue_len, memory_order_relaxed);
    push_unlock();
    push_bump(&g_send_gen, 1);
    push_bump(&g_queued, 1);
    if (dropped)
        board_push_skip(FLEET_BOARD_PUSH_SKIP_QUEUE_FULL, 1);
}

/* A hinted post kept out of the queue is counted once, by its hint. */
static void push_skip_unhinted(enum fleet_board_push_hint hint,
                               enum fleet_board_push_skip why)
{
    if (hint == FLEET_BOARD_PUSH_HINT_NONE)
        board_push_skip(why, 1);
}

/* A post that is not this box's own FLEET post, and a usable hint on it
 * refused by which of the two it is not. */
static enum fleet_board_push_hint push_not_own(
    const struct fleet_board_post *post, enum fleet_board_push_hint hint)
{
    push_skip_unhinted(hint, FLEET_BOARD_PUSH_SKIP_NOT_OWN);
    if (hint == FLEET_BOARD_PUSH_HINT_QUEUED)
        hint = post && post->scope != FLEET_BOARD_SCOPE_FLEET
                   ? FLEET_BOARD_PUSH_HINT_NOT_FLEET
                   : FLEET_BOARD_PUSH_HINT_NOT_OWN;
    return push_hint_count(hint);
}

/* The queue entry for this box's own new FLEET post; with `fanout` it is
 * queued even with no addressee, and also offered to every connected peer. */
static enum fleet_board_push_hint push_enqueue(
    const struct fleet_board_post *post, const uint8_t own_key[32],
    const char *push_to, bool fanout)
{
    uint8_t to[32];
    enum fleet_board_push_hint hint = push_hint_parse(push_to, to);
    if (!post || !own_key || post->scope != FLEET_BOARD_SCOPE_FLEET ||
        memcmp(post->host_pubkey, own_key, 32) != 0)
        return push_not_own(post, hint);
    if (hint == FLEET_BOARD_PUSH_HINT_QUEUED && memcmp(to, own_key, 32) == 0)
        hint = FLEET_BOARD_PUSH_HINT_SELF;
    /* A refused hint is as if there were none: the ref decides, or nothing;
     * with nothing, the post is counted once, under its hint verdict. */
    bool use_to = hint == FLEET_BOARD_PUSH_HINT_QUEUED;
    if (!use_to && !fanout &&
        (push_id_zero(post->ref) || memcmp(post->ref, post->id, 32) == 0)) {
        push_skip_unhinted(hint, FLEET_BOARD_PUSH_SKIP_NO_ADDRESSEE);
        return push_hint_count(hint);
    }
    struct push_queued q;
    memset(&q, 0, sizeof q);
    memcpy(q.id, post->id, 32);
    memcpy(q.ref, post->ref, 32);
    memcpy(q.host, post->host_pubkey, 32);
    q.has_to = use_to;
    if (use_to)
        memcpy(q.to, to, 32);
    q.fanout = fanout;
    q.queued = board_now();
    push_queue_put(&q);
    return push_hint_count(hint);
}

enum fleet_board_push_hint boot_fleet_board_fleet_push_enqueue_to(
    const struct fleet_board_post *post, const uint8_t own_key[32],
    const char *push_to)
{
    return push_enqueue(post, own_key, push_to, false);
}

enum fleet_board_push_hint boot_fleet_board_fleet_push_enqueue_all(
    const struct fleet_board_post *post, const uint8_t own_key[32],
    const char *push_to)
{
    return push_enqueue(post, own_key, push_to, true);
}

/* Put held posts back behind whatever arrived since; a full queue keeps the
 * newer ones. */
static void push_requeue(const struct push_queued *held, size_t n)
{
    size_t lost = 0;
    push_lock();
    for (size_t i = 0; i < n; i++) {
        if (g_queue_len == FLEET_BOARD_PUSH_QUEUE_MAX) {
            lost++;
            continue;
        }
        g_queue[(g_queue_head + g_queue_len) % FLEET_BOARD_PUSH_QUEUE_MAX] =
            held[i];
        g_queue_len++;
    }
    atomic_store_explicit(&g_queue_count, g_queue_len, memory_order_relaxed);
    push_unlock();
    if (lost)
        board_push_skip(FLEET_BOARD_PUSH_SKIP_QUEUE_FULL, lost);
}

static size_t push_take_queue(struct push_queued out[FLEET_BOARD_PUSH_QUEUE_MAX])
{
    push_lock();
    size_t n = g_queue_len;
    for (size_t i = 0; i < n; i++)
        out[i] = g_queue[(g_queue_head + i) % FLEET_BOARD_PUSH_QUEUE_MAX];
    g_queue_head = 0;
    g_queue_len = 0;
    atomic_store_explicit(&g_queue_count, 0, memory_order_relaxed);
    push_unlock();
    return n;
}

/* ── per-session memory: an older node ────────────────────────────────── */

static void push_session_mark_unsupported(const struct mesh_stream *st)
{
    push_lock();
    struct push_session *s = &g_unsupported[g_unsupported_next];
    g_unsupported_next = (g_unsupported_next + 1) % PUSH_SESSIONS_MAX;
    s->used = true;
    memcpy(s->peer_static, st->peer_static, 32);
    memcpy(s->transcript, st->transcript_hash, 32);
    s->generation = st->connection_generation;
    push_unlock();
}

bool board_push_session_unsupported(const uint8_t peer_static[32],
                                    const struct noise_transport_snapshot *snap)
{
    bool found = false;
    push_lock();
    for (size_t i = 0; i < PUSH_SESSIONS_MAX && !found; i++) {
        const struct push_session *s = &g_unsupported[i];
        found = s->used && memcmp(s->peer_static, peer_static, 32) == 0 &&
                memcmp(s->transcript, snap->transcript_hash, 32) == 0 &&
                s->generation == snap->connection_generation;
    }
    push_unlock();
    return found;
}

/* ── the sending half, on the lane tick ───────────────────────────────── */

static struct push_peer *push_peer_lead(struct push_round *r,
                                        const uint8_t noise[32])
{
    for (size_t i = 0; i < r->n_peers; i++)
        if (memcmp(r->peers[i].row.peer_noise_pubkey, noise, 32) == 0)
            return r->peers[i].lead;
    return NULL;
}

/* Every pairing row that grants the status capability now and whose
 * delegation resolves, newest first (the list runs oldest first, so it is
 * walked from the end). The table only finds which Noise key a board key
 * belongs to (push_match); it decides nothing: whether that peer is pushed
 * to is the pull's own decision, asked in push_peer_judge. */
static void push_round_peers(struct push_round *r)
{
    struct node_db *pairings = app_runtime_node_db();
    if (!pairings || !app_runtime_node_db_handle_open(pairings))
        return;
    struct db_mesh_pairing *rows = zcl_calloc(
        FLEET_BOARD_FLEET_PEERS_MAX, sizeof *rows, "fleet_board_push_pairings");
    if (!rows)
        return;
#ifdef ZCL_TESTING
    push_bump(&g_test_peer_walks, 1);
#endif
    int count = db_mesh_pairing_list(pairings, rows,
                                     FLEET_BOARD_FLEET_PEERS_MAX);
    for (int i = count - 1; i >= 0 && r->n_peers < FLEET_BOARD_FLEET_PEERS_MAX;
         i--) {
        struct vcs_zcode_dht_delegation peer;
        if (!mesh_pairing_allows(&rows[i], MESH_PAIRING_CAP_STATUS_READ,
                                 r->now) ||
            !board_peer_delegation(&rows[i], &peer))
            continue;
        struct push_peer *lead = push_peer_lead(r, rows[i].peer_noise_pubkey);
        struct push_peer *p = &r->peers[r->n_peers++];
        p->row = rows[i];
        memcpy(p->online, peer.online_pubkey, 32);
        p->lead = lead ? lead : p;
        p->ready = PUSH_UNASKED;
        p->fan_ready = PUSH_UNASKED;
    }
    free(rows);
}

/* Build what resolving an entry needs, once a round. False when memory ran
 * out. */
static bool push_round_ready(struct push_round *r)
{
    if (r->ready)
        return true;
    if (!r->peers)
        r->peers = zcl_calloc(FLEET_BOARD_FLEET_PEERS_MAX, sizeof *r->peers,
                              "fleet_board_push_peers");
    if (!r->row)
        r->row = zcl_calloc(1, sizeof *r->row, "fleet_board_push_row");
    if (!r->ref_row)
        r->ref_row = zcl_calloc(1, sizeof *r->ref_row, "fleet_board_push_ref");
    if (!r->peers || !r->row || !r->ref_row)
        return false;
    push_round_peers(r);
    r->ready = true;
    return true;
}

struct push_live_probe {
    const uint8_t *peer_static;
    bool found;
};

static bool push_live_visitor(struct mesh_stream *st, void *ctx)
{
    struct push_live_probe *probe = ctx;
    const enum board_state_tag *tag = st->service_state;
    if (tag && *tag == BOARD_STATE_PUSH_OUT && st->local_initiator &&
        !st->ended && memcmp(st->peer_static, probe->peer_static, 32) == 0) {
        probe->found = true;
        return false;
    }
    return true;
}

/* A push to this peer is still waiting for its receipt. */
bool board_push_out_live(const uint8_t peer_static[32])
{
    struct push_live_probe probe = { peer_static, false };
    mesh_stream_visit(FLEET_BOARD_FLEET_SERVICE_NAME, push_live_visitor,
                      &probe);
    return probe.found;
}

/* The post, still one a pull would serve, and the board key it goes to: the
 * hinted box when the entry carries one, else the author of the answered
 * post when that is another box. */
static int push_resolve(struct push_round *r, const struct push_queued *q,
                        uint8_t to[32])
{
    if (db_fleet_board_post_lookup_checked(r->store, q->id, r->row) !=
            FLEET_BOARD_LOOKUP_FOUND ||
        r->row->post.scope != FLEET_BOARD_SCOPE_FLEET ||
        memcmp(r->row->post.host_pubkey, q->host, 32) != 0)
        return FLEET_BOARD_PUSH_SKIP_GONE;
    /* The pull serves an unexpired post or a wiki page, nothing else. */
    if (r->row->post.kind != FLEET_BOARD_KIND_WIKI &&
        r->row->expires_at <= r->now)
        return FLEET_BOARD_PUSH_SKIP_EXPIRED;
    if (q->has_to) {
        memcpy(to, q->to, 32);
        return PUSH_OK;
    }
    /* No addressee at all: only a fan-out entry is queued so. */
    if (push_id_zero(q->ref) || memcmp(q->ref, q->id, 32) == 0)
        return PUSH_UNASKED;
    if (db_fleet_board_post_lookup_checked(r->store, q->ref, r->ref_row) !=
            FLEET_BOARD_LOOKUP_FOUND ||
        memcmp(r->ref_row->post.host_pubkey, q->host, 32) == 0)
        return FLEET_BOARD_PUSH_SKIP_NO_ADDRESSEE;
    memcpy(to, r->ref_row->post.host_pubkey, 32);
    return PUSH_OK;
}

/* The paired peer whose board key is `to`: its rows may be many, but they
 * must all belong to one Noise key, whose lead is returned. */
static int push_match(struct push_round *r, const uint8_t to[32],
                      struct push_peer **out)
{
    struct push_peer *lead = NULL;
    for (size_t i = 0; i < r->n_peers; i++) {
        if (memcmp(r->peers[i].online, to, 32) != 0)
            continue;
        if (lead && r->peers[i].lead != lead)
            return FLEET_BOARD_PUSH_SKIP_AMBIGUOUS;
        lead = r->peers[i].lead;
    }
    if (!lead)
        return FLEET_BOARD_PUSH_SKIP_UNRESOLVED;
    *out = lead;
    return PUSH_OK;
}

/* The pull's own disclosure decision for `lead`'s Noise key
 * (board_push_disclosure), counted as a push judgment when it refuses; its
 * row must prove `to`. Then the link: connected, under its send budget, not
 * an older node this session, and no push to it already open. */
static int push_peer_judge(const struct push_round *r,
                           const struct push_peer *lead, const uint8_t to[32])
{
    const uint8_t *noise = lead->row.peer_noise_pubkey;
    uint8_t served[32];
    enum fleet_board_push_refusal refusal = board_push_disclosure(noise, served);
    if (refusal != FLEET_BOARD_PUSH_REFUSALS) {
        push_refused(true, refusal);
        return FLEET_BOARD_PUSH_SKIP_INELIGIBLE;
    }
    if (memcmp(served, to, 32) != 0)
        return FLEET_BOARD_PUSH_SKIP_UNRESOLVED;
    struct noise_transport_snapshot snap;
    memset(&snap, 0, sizeof snap);
    struct p2p_node *node =
        r->svc && r->svc->msg_processor && r->svc->msg_processor->net_mgr
            ? boot_mesh_find_session_peer(r->svc->msg_processor->net_mgr,
                                          noise, &snap)
            : NULL;
    if (!node)
        return FLEET_BOARD_PUSH_SKIP_NOT_CONNECTED;
    bool over = net_send_over_budget(node);
    p2p_node_release(node);
    if (over)
        return FLEET_BOARD_PUSH_SKIP_OVER_BUDGET;
    if (board_push_session_unsupported(noise, &snap))
        return FLEET_BOARD_PUSH_SKIP_UNSUPPORTED;
    return board_push_out_live(noise) ? PUSH_HOLD : PUSH_OK;
}

/* Add the resolved post to the peer's push. A push that is full waits for
 * the next tick; a post that cannot ride an OPEN alone is never pushed. */
int board_push_batch_add(struct push_round *r, struct push_peer *p,
                         const struct push_queued *q)
{
    if (!p->frame) {
        p->frame = zcl_malloc(FLEET_BOARD_PUSH_MAX, "fleet_board_push_frame");
        if (!p->frame)
            return FLEET_BOARD_PUSH_SKIP_OPEN_FAILED;
        board_push_begin(p->frame);
        p->len = FLEET_BOARD_PUSH_HEAD;
    }
    if (board_push_append_post(p->frame, &p->len, &r->row->post)) {
        memcpy(p->ids[p->n++], q->id, 32);
        return PUSH_OK;
    }
    return p->n == 0 ? FLEET_BOARD_PUSH_SKIP_TOO_LARGE : PUSH_HOLD;
}

/* A post waits for the next tick while its peer's push is open, for at most
 * FLEET_BOARD_PUSH_WAIT_S; then it is left to the pull. */
void board_push_hold(struct push_round *r, const struct push_queued *q,
                     const struct push_peer *p)
{
    if (r->now < q->queued || r->now - q->queued >= FLEET_BOARD_PUSH_WAIT_S ||
        r->n_held >= FLEET_BOARD_PUSH_QUEUE_MAX) {
        board_push_skip(FLEET_BOARD_PUSH_SKIP_BUSY, 1);
        return;
    }
    struct push_queued *h = &r->held[r->n_held++];
    *h = *q;
    h->fanout = false; /* held for one peer: never fanned out again */
    if (p) {
        h->waiting = true;
        memcpy(h->waiting_peer, p->row.peer_noise_pubkey, 32);
    }
}

static void push_offer(struct push_round *r, const struct push_queued *q)
{
    /* A post held for a peer whose push is still open waits again without
     * a store read. */
    if (q->waiting && board_push_out_live(q->waiting_peer)) {
        board_push_hold(r, q, NULL);
        return;
    }
    if (!push_round_ready(r)) {
        board_push_skip(FLEET_BOARD_PUSH_SKIP_OPEN_FAILED, 1);
        return;
    }
    struct push_peer *p = NULL;
    uint8_t to[32];
    int step = push_resolve(r, q, to);
    if (step == PUSH_OK)
        step = push_match(r, to, &p);
    if (step == PUSH_OK) {
        /* Judged once a round per peer and board key. */
        if (p->ready == PUSH_UNASKED || memcmp(p->ready_to, to, 32) != 0) {
            p->ready = push_peer_judge(r, p, to);
            memcpy(p->ready_to, to, 32);
        }
        step = p->ready;
    }
    if (step == PUSH_OK)
        step = board_push_batch_add(r, p, q);
    if (step == PUSH_HOLD)
        board_push_hold(r, q, p);
    else if (step != PUSH_OK && step != PUSH_UNASKED)
        board_push_skip((enum fleet_board_push_skip)step, 1);
    /* The fan-out needs the post a pull would still serve, in r->row. */
    if (q->fanout && step != FLEET_BOARD_PUSH_SKIP_GONE &&
        step != FLEET_BOARD_PUSH_SKIP_EXPIRED)
        board_push_fanout(r, q, p);
}

/* Open one push. The stream owns the state once it opens. */
static void push_open(const struct push_peer *p)
{
    struct board_push_out_state *s =
        zcl_calloc(1, sizeof *s, "fleet_board_push_out");
    if (!s) {
        board_push_skip(FLEET_BOARD_PUSH_SKIP_OPEN_FAILED, p->n);
        return;
    }
    s->tag = BOARD_STATE_PUSH_OUT;
    s->n = p->n;
    memcpy(s->ids, p->ids, sizeof s->ids);
    uint64_t stream_id = 0;
    enum mesh_stream_refusal refusal = mesh_stream_open(
        FLEET_BOARD_FLEET_SERVICE_NAME, p->row.peer_noise_pubkey,
        FLEET_BOARD_PUSH_WINDOW, p->frame, p->len, s, &stream_id);
    if (refusal == MESH_STREAM_OK) {
        push_bump(&g_opened, 1);
        return;
    }
    free(s);
    uint64_t skipped = 0;
    if (push_log_due(PUSH_LOG_SKIP, &skipped))
        LOG_INFO("fleet.board", "fleet push not opened: %s (%llu more lines "
                 "since the last)", mesh_stream_refusal_string(refusal),
                 (unsigned long long)skipped);
    push_bump(&g_skipped[FLEET_BOARD_PUSH_SKIP_OPEN_FAILED], p->n);
}

static void push_round_free(struct push_round *r)
{
    if (r->peers)
        for (size_t i = 0; i < r->n_peers; i++)
            free(r->peers[i].frame);
    free(r->peers);
    free(r->row);
    free(r->ref_row);
    free(r);
}

/* Whether a sending round may do anything the last one could not: a post
 * was queued or a push this box sent ended since it ran, or the lane second
 * moved on (a held post's wait, a pairing or a session can change with
 * time). At most once a second otherwise, and O(1) when not due. */
static bool push_round_due(int64_t now)
{
    uint64_t gen = atomic_load_explicit(&g_send_gen, memory_order_relaxed);
    push_lock();
    bool due = gen != g_round_gen || now != g_round_second;
    if (due) {
        g_round_gen = gen;
        g_round_second = now;
    }
    push_unlock();
    return due;
}

/* Drain the queue once: resolve, judge, batch, open. Returns the pushes
 * opened. */
static size_t push_send_round(struct boot_svc_ctx *svc, struct node_db *store,
                              int64_t now)
{
    if (!push_round_due(now))
        return 0;
    struct push_queued taken[FLEET_BOARD_PUSH_QUEUE_MAX];
    size_t n = push_take_queue(taken);
    if (n == 0)
        return 0;
    struct push_round *r = zcl_calloc(1, sizeof *r, "fleet_board_push_round");
    if (!r || !store) {
        free(r);
        board_push_skip(FLEET_BOARD_PUSH_SKIP_OPEN_FAILED, n);
        return 0;
    }
    r->svc = svc;
    r->store = store;
    r->now = now;
    for (size_t i = 0; i < n; i++)
        push_offer(r, &taken[i]);
    uint64_t before = atomic_load_explicit(&g_opened, memory_order_relaxed);
    for (size_t i = 0; i < r->n_peers; i++)
        if (r->peers[i].n > 0)
            push_open(&r->peers[i]);
    push_requeue(r->held, r->n_held);
    push_round_free(r);
    return (size_t)(atomic_load_explicit(&g_opened, memory_order_relaxed) -
                    before);
}

/* ── the receiving half: the frame path ───────────────────────────────── */

bool board_push_dispatch_enabled(void)
{
#ifdef ZCL_TESTING
    return !g_test_pre_push;
#else
    return true;
#endif
}

/* Take a slot for this push: one per pushing peer, none when all are taken.
 * Push lock held by the caller. */
static uint8_t push_inbox_fill_locked(const uint8_t peer_static[32],
                                      const uint8_t *payload, size_t len,
                                      struct board_push_in_state *s)
{
    struct push_slot *free_slot = NULL;
    for (size_t i = 0; i < FLEET_BOARD_PUSH_INBOX_MAX; i++) {
        struct push_slot *slot = &g_inbox[i];
        if (slot->state != PUSH_SLOT_FREE &&
            memcmp(slot->peer_static, peer_static, 32) == 0)
            return FLEET_BOARD_PUSH_CODE_BUSY;
        if (slot->state == PUSH_SLOT_FREE && !free_slot)
            free_slot = slot;
    }
    if (!free_slot)
        return FLEET_BOARD_PUSH_CODE_INBOX_FULL;
    if (++g_slot_seq == 0)
        g_slot_seq = 1;
    free_slot->state = PUSH_SLOT_FILLED;
    free_slot->seq = g_slot_seq;
    memcpy(free_slot->peer_static, peer_static, 32);
    free_slot->len = len;
    memcpy(free_slot->bytes, payload, len);
    s->slot = (uint32_t)(free_slot - g_inbox);
    s->seq = free_slot->seq;
    atomic_fetch_add_explicit(&g_inbox_filled, 1, memory_order_relaxed);
    return FLEET_BOARD_PUSH_CODE_COMMITTED;
}

/* A push refused at its OPEN: counted, named in a receipt that rides the
 * CLOSE, and logged at most once a window. */
static enum mesh_stream_refusal push_refuse_open(uint8_t code,
                                                 enum mesh_stream_refusal why,
                                                 uint8_t *reply,
                                                 size_t reply_cap,
                                                 size_t *reply_len)
{
    struct board_push_receipt rc;
    memset(&rc, 0, sizeof rc);
    rc.code = code;
    rc.commit_ms = push_now_ms();
    if (reply && reply_len && reply_cap >= FLEET_BOARD_PUSH_RECEIPT_MAX)
        *reply_len = board_push_receipt_encode(&rc, reply);
    push_bump(&g_in[code], 1);
    uint64_t skipped = 0;
    if (push_log_due(PUSH_LOG_IN, &skipped))
        LOG_WARN("fleet.board", "fleet push refused: %s (%llu more lines "
                 "since the last)", k_code_names[code],
                 (unsigned long long)skipped);
    return why;
}

enum mesh_stream_refusal board_push_accept(struct mesh_stream *st,
                                           const uint8_t *payload, size_t len,
                                           uint8_t *reply, size_t reply_cap,
                                           size_t *reply_len)
{
    if (reply_len)
        *reply_len = 0;
    if (!board_push_valid(payload, len, NULL))
        return push_refuse_open(FLEET_BOARD_PUSH_CODE_MALFORMED,
                                MESH_STREAM_REFUSED_MALFORMED, reply,
                                reply_cap, reply_len);
    struct board_push_in_state *s =
        zcl_calloc(1, sizeof *s, "fleet_board_push_in");
    if (!s)
        return push_refuse_open(FLEET_BOARD_PUSH_CODE_UNAVAILABLE,
                                MESH_STREAM_REFUSED_UNAVAILABLE, reply,
                                reply_cap, reply_len);
    push_lock();
    uint8_t code = push_inbox_fill_locked(st->peer_static, payload, len, s);
    push_unlock();
    if (code != FLEET_BOARD_PUSH_CODE_COMMITTED) {
        free(s);
        return push_refuse_open(code, MESH_STREAM_CLOSED_BY_SERVICE, reply,
                                reply_cap, reply_len);
    }
    s->tag = BOARD_STATE_PUSH_IN;
    st->service_state = s;
    return MESH_STREAM_OK;
}

/* ── the receiving half: the inbox ────────────────────────────────────── */

enum push_slot_drop {
    PUSH_DROP_GONE = 0, /* not this fill any more */
    PUSH_DROP_DONE,     /* dropped before its commit */
    PUSH_DROP_COMMITTING,
};

/* Give back a slot whose stream ended before the tick took it. */
static enum push_slot_drop push_slot_drop(uint32_t slot, uint32_t seq)
{
    enum push_slot_drop out = PUSH_DROP_GONE;
    if (slot >= FLEET_BOARD_PUSH_INBOX_MAX)
        return out;
    push_lock();
    struct push_slot *s = &g_inbox[slot];
    if (s->seq == seq && s->state == PUSH_SLOT_COMMITTING)
        out = PUSH_DROP_COMMITTING;
    else if (s->seq == seq && s->state == PUSH_SLOT_FILLED) {
        s->state = PUSH_SLOT_FREE;
        s->len = 0;
        atomic_fetch_sub_explicit(&g_inbox_filled, 1, memory_order_relaxed);
        out = PUSH_DROP_DONE;
    }
    push_unlock();
    return out;
}

/* The slot the commit took, read in place: no other path writes a slot that
 * is COMMITTING. */
struct push_commit {
    uint32_t slot;
    uint32_t seq;
    uint8_t peer_static[32];
    const uint8_t *bytes;
    size_t len;
};

/* Take the push that arrived first. Fills are numbered in arrival order, so
 * a peer that refills its slot the moment it is answered waits behind every
 * push that arrived before the refill: no pushing peer is served twice while
 * another waits, and a waiting push is committed within
 * FLEET_BOARD_PUSH_INBOX_MAX ticks. The numbers wrap; at most
 * FLEET_BOARD_PUSH_INBOX_MAX are live, so a signed difference orders them. */
static bool push_take_filled(struct push_commit *c)
{
    struct push_slot *oldest = NULL;
    push_lock();
    for (uint32_t i = 0; i < FLEET_BOARD_PUSH_INBOX_MAX; i++) {
        struct push_slot *s = &g_inbox[i];
        if (s->state == PUSH_SLOT_FILLED &&
            (!oldest || (int32_t)(s->seq - oldest->seq) < 0))
            oldest = s;
    }
    if (oldest) {
        oldest->state = PUSH_SLOT_COMMITTING;
        atomic_fetch_sub_explicit(&g_inbox_filled, 1, memory_order_relaxed);
        c->slot = (uint32_t)(oldest - g_inbox);
        c->seq = oldest->seq;
        memcpy(c->peer_static, oldest->peer_static, 32);
        c->bytes = oldest->bytes;
        c->len = oldest->len;
    }
    push_unlock();
    return oldest != NULL;
}

static void push_release_slot(uint32_t slot, uint32_t seq)
{
    push_lock();
    if (g_inbox[slot].seq == seq && g_inbox[slot].state == PUSH_SLOT_COMMITTING) {
        g_inbox[slot].state = PUSH_SLOT_FREE;
        g_inbox[slot].len = 0;
    }
    push_unlock();
}

/* The board keys a pusher may author as, at most PUSH_PUSHER_KEYS_MAX. */
struct push_authors {
    uint8_t key[PUSH_PUSHER_KEYS_MAX][32];
    size_t n;
};

/* The pusher's standing now and the board keys it proves: the checks this
 * box's asking half makes on any row before it pulls from that peer
 * (board_push_pusher_keys; config/boot_fleet_board.h, PUSH). A failure is
 * counted as a push judgment, never as a pull. */
static bool push_pusher_standing(const uint8_t peer_static[32],
                                 struct push_authors *authors)
{
    struct node_db *pairings = app_runtime_node_db();
    enum fleet_board_push_refusal refusal = FLEET_BOARD_PUSH_REFUSAL_PAIRING;
    authors->n = 0;
    if (pairings && app_runtime_node_db_handle_open(pairings))
        authors->n = board_push_pusher_keys(pairings, peer_static, board_now(),
                                            authors->key, PUSH_PUSHER_KEYS_MAX,
                                            &refusal);
    if (authors->n > 0)
        return true;
    push_refused(false, refusal);
    return false;
}

static bool push_author_proven(const struct push_authors *authors,
                               const uint8_t host[32])
{
    for (size_t i = 0; i < authors->n; i++)
        if (memcmp(authors->key[i], host, 32) == 0)
            return true;
    return false;
}

/* One record before anything is stored. It is decoded (its id re-derived
 * from the bytes and its signature checked), and it must be the record the
 * pusher named, FLEET scope, and signed by a board key the pusher proved,
 * before the store is asked anything about it: a record that fails is
 * answered the same whether or not this box holds that id, so a push cannot
 * learn what this box holds that another box wrote. Only the pusher's own
 * post may be answered held. A failed decode is the record's own refusal; a
 * wrong id, scope or author voids the whole push. */
static uint8_t push_screen(struct node_db *store,
                           const struct board_push_record *rec,
                           const struct push_authors *authors,
                           struct fleet_board_post *post, uint8_t *verdict,
                           uint8_t *result, bool *decoded)
{
    *decoded = false;
    *result = FLEET_BOARD_OK;
    enum fleet_board_result r =
        fleet_board_post_decode(rec->wire, rec->wire_len, post);
    if (r != FLEET_BOARD_OK) {
        *verdict = FLEET_BOARD_PUSH_RECORD_REFUSED;
        *result = (uint8_t)r;
        return FLEET_BOARD_PUSH_CODE_COMMITTED;
    }
    if (memcmp(post->id, rec->id, 32) != 0 ||
        post->scope != FLEET_BOARD_SCOPE_FLEET)
        return FLEET_BOARD_PUSH_CODE_MALFORMED;
    if (!push_author_proven(authors, post->host_pubkey))
        return FLEET_BOARD_PUSH_CODE_AUTHOR;
    if (db_fleet_board_have(store, rec->id)) {
        *verdict = FLEET_BOARD_PUSH_RECORD_HELD;
        return FLEET_BOARD_PUSH_CODE_COMMITTED;
    }
    *decoded = true;
    return FLEET_BOARD_PUSH_CODE_COMMITTED;
}

/* The ingest a pulled post goes through, without the cursor's pinned-arrival
 * rule: the roster screen, then the one store write every post takes
 * (signature, TTL, author role, quotas). It never waits for another board
 * writer: on the shared tick-runner thread a held board write lock is
 * FLEET_BOARD_ERR_BUSY, which the receipt answers deferred and the pull
 * retries. A refusal that describes this box rather than the pusher's post
 * (another board writer holding the lock, a full store, a failed append, a
 * wiki quota that may be the node-wide replacement cap) goes back with its
 * verdict and no result code. */
static uint8_t push_ingest(struct node_db *store,
                           const struct fleet_board_post *post, int64_t now,
                           uint8_t *result)
{
    bool stored = false;
    enum fleet_board_result r = boot_fleet_roster_screen_post(store, post, now);
    if (r == FLEET_BOARD_OK) {
        db_fleet_board_post_prepare_nowait();
        r = db_fleet_board_post_ingest_nowait(store, post, now, &stored);
    }
    if (r == FLEET_BOARD_OK && stored && boot_fleet_roster_is_row(post))
        boot_fleet_roster_invalidate();
    bool node_wide = r == FLEET_BOARD_ERR_BUSY ||
                     r == FLEET_BOARD_ERR_CAPACITY ||
                     r == FLEET_BOARD_ERR_STORAGE ||
                     r == FLEET_BOARD_ERR_WIKI_QUOTA;
    *result = node_wide ? (uint8_t)FLEET_BOARD_OK : (uint8_t)r;
    if (r == FLEET_BOARD_OK)
        return stored ? FLEET_BOARD_PUSH_RECORD_STORED
                      : FLEET_BOARD_PUSH_RECORD_HELD;
    return board_refusal_retryable(r) ? FLEET_BOARD_PUSH_RECORD_DEFERRED
                                      : FLEET_BOARD_PUSH_RECORD_REFUSED;
}

/* Screen every record, then store: a push one record of which is not the
 * pusher's own stores nothing. Returns the records newly stored. */
static size_t push_judge(struct node_db *store, const struct push_commit *c,
                         const struct push_authors *authors, int64_t now,
                         struct board_push_receipt *rc)
{
    struct fleet_board_post *posts = zcl_calloc(
        FLEET_BOARD_PUSH_POSTS_MAX, sizeof *posts, "fleet_board_push_commit");
    if (!posts) {
        rc->code = FLEET_BOARD_PUSH_CODE_UNAVAILABLE;
        return 0;
    }
    bool decoded[FLEET_BOARD_PUSH_POSTS_MAX] = { false };
    size_t off = FLEET_BOARD_PUSH_HEAD;
    struct board_push_record rec;
    uint8_t code = FLEET_BOARD_PUSH_CODE_COMMITTED;
    unsigned n = 0;
    while (code == FLEET_BOARD_PUSH_CODE_COMMITTED &&
           n < FLEET_BOARD_PUSH_POSTS_MAX &&
           board_push_record_next(c->bytes, c->len, &off, &rec)) {
        memcpy(rc->rec[n].id, rec.id, 32);
        code = push_screen(store, &rec, authors, &posts[n], &rc->rec[n].verdict,
                           &rc->rec[n].result, &decoded[n]);
        n++;
    }
    size_t stored = 0;
    rc->code = code;
    rc->n = code == FLEET_BOARD_PUSH_CODE_COMMITTED ? (uint8_t)n : 0;
    for (unsigned i = 0; i < rc->n; i++) {
        if (decoded[i])
            rc->rec[i].verdict =
                push_ingest(store, &posts[i], now, &rc->rec[i].result);
        if (rc->rec[i].verdict == FLEET_BOARD_PUSH_RECORD_STORED)
            stored++;
        push_bump(&g_in_records[rc->rec[i].verdict], 1);
    }
    free(posts);
    return stored;
}

struct push_answer {
    uint32_t slot;
    uint32_t seq;
    const uint8_t *receipt;
    size_t len;
};

static bool push_answer_visitor(struct mesh_stream *st, void *ctx)
{
    const struct push_answer *a = ctx;
    const struct board_push_in_state *s = st->service_state;
    if (st->ended || st->local_initiator || !s ||
        s->tag != BOARD_STATE_PUSH_IN || s->slot != a->slot ||
        s->seq != a->seq)
        return true;
    mesh_stream_close(st, MESH_STREAM_CLOSED_BY_SERVICE, a->receipt, a->len);
    return false;
}

/* Commit at most one received push into `store` and answer it. Returns the
 * records newly stored. */
static size_t push_commit_one(struct node_db *store)
{
    struct push_commit c;
    if (!push_take_filled(&c))
        return 0;
    struct board_push_receipt rc;
    memset(&rc, 0, sizeof rc);
    struct push_authors authors;
    size_t stored = 0;
    if (!store)
        rc.code = FLEET_BOARD_PUSH_CODE_UNAVAILABLE;
    else if (!push_pusher_standing(c.peer_static, &authors))
        rc.code = FLEET_BOARD_PUSH_CODE_REVOKED;
    else
        stored = push_judge(store, &c, &authors, board_now(), &rc);
    rc.commit_ms = push_now_ms();
    uint8_t receipt[FLEET_BOARD_PUSH_RECEIPT_MAX];
    struct push_answer a = { c.slot, c.seq, receipt,
                             board_push_receipt_encode(&rc, receipt) };
    mesh_stream_visit(FLEET_BOARD_FLEET_SERVICE_NAME, push_answer_visitor, &a);
    push_release_slot(c.slot, c.seq);
    push_bump(&g_in[rc.code], 1);
    uint64_t skipped = 0;
    /* push_revoked was logged, with the check that failed, by
     * push_pusher_standing. */
    if (rc.code != FLEET_BOARD_PUSH_CODE_COMMITTED &&
        rc.code != FLEET_BOARD_PUSH_CODE_REVOKED &&
        push_log_due(PUSH_LOG_IN, &skipped))
        LOG_WARN("fleet.board", "fleet push refused: %s (%llu more lines "
                 "since the last)", k_code_names[rc.code],
                 (unsigned long long)skipped);
    return stored;
}

void board_push_lane_tick(struct boot_svc_ctx *svc, struct node_db *store,
                          int64_t now)
{
    if (atomic_load_explicit(&g_inbox_filled, memory_order_relaxed) > 0)
        (void)push_commit_one(store);
    if (atomic_load_explicit(&g_queue_count, memory_order_relaxed) > 0)
        (void)push_send_round(svc, store, now);
}

/* ── the stream callbacks for push states (lane lock held) ────────────── */

void board_push_data_refused(struct mesh_stream *st, enum board_state_tag tag)
{
    if (tag == BOARD_STATE_PUSH_OUT)
        ((struct board_push_out_state *)st->service_state)->self_closed = true;
    push_bump(&g_data_refused, 1);
    uint64_t skipped = 0;
    if (push_log_due(PUSH_LOG_IN, &skipped))
        LOG_WARN("fleet.board", "fleet push stream refused: DATA on a push "
                 "stream %s opened (%llu more lines since the last)",
                 tag == BOARD_STATE_PUSH_OUT ? "this node" : "the peer",
                 (unsigned long long)skipped);
    mesh_stream_close(st, MESH_STREAM_REFUSED_MALFORMED, NULL, 0);
}

/* The receiving half's deadline: an uncommitted push is answered
 * unavailable. A push the tick is committing is left to the tick. */
static void push_in_expire(struct mesh_stream *st)
{
    const struct board_push_in_state *s = st->service_state;
    if (push_slot_drop(s->slot, s->seq) == PUSH_DROP_COMMITTING)
        return;
    struct board_push_receipt rc;
    memset(&rc, 0, sizeof rc);
    rc.code = FLEET_BOARD_PUSH_CODE_UNAVAILABLE;
    rc.commit_ms = push_now_ms();
    uint8_t receipt[FLEET_BOARD_PUSH_RECEIPT_MAX];
    size_t len = board_push_receipt_encode(&rc, receipt);
    push_bump(&g_in[FLEET_BOARD_PUSH_CODE_UNAVAILABLE], 1);
    mesh_stream_close(st, MESH_STREAM_CLOSED_BY_SERVICE, receipt, len);
}

/* Both halves wait, through every pump tick, for the commit or the receipt
 * until FLEET_BOARD_PUSH_WAIT_S after the OPEN; then each ends its own side. */
void board_push_stream_tick(struct mesh_stream *st, enum board_state_tag tag,
                            int64_t now)
{
    if (now < st->opened_unix ||
        now - st->opened_unix < FLEET_BOARD_PUSH_WAIT_S)
        return;
    if (tag == BOARD_STATE_PUSH_IN) {
        push_in_expire(st);
        return;
    }
    struct board_push_out_state *s = st->service_state;
    s->self_closed = true;
    board_push_skip(FLEET_BOARD_PUSH_SKIP_NO_RECEIPT, s->n);
    mesh_stream_close(st, MESH_STREAM_CLOSED_BY_SERVICE, NULL, 0);
}

/* A receipt the peer sent for this push: counted by code and, when it names
 * exactly the posts sent, by record. */
void board_push_receipt_seen(const uint8_t ids[][32], uint8_t n,
                             const struct board_push_receipt *rc)
{
    bool matches = rc->n == 0 || rc->n == n;
    for (unsigned i = 0; matches && i < rc->n; i++)
        matches = memcmp(rc->rec[i].id, ids[i], 32) == 0;
    uint64_t skipped = 0;
    if (!matches) {
        push_bump(&g_closed[MESH_STREAM_REFUSED_MALFORMED], 1);
        if (push_log_due(PUSH_LOG_RECEIPT, &skipped))
            LOG_WARN("fleet.board", "fleet push receipt names other posts "
                     "than were pushed; not counted (%llu more lines since "
                     "the last)", (unsigned long long)skipped);
        return;
    }
    push_bump(&g_receipt[rc->code], 1);
    bool clean = rc->code == FLEET_BOARD_PUSH_CODE_COMMITTED;
    for (unsigned i = 0; i < rc->n; i++) {
        if (rc->code == FLEET_BOARD_PUSH_CODE_COMMITTED)
            push_bump(&g_receipt_records[rc->rec[i].verdict], 1);
        clean = clean && rc->rec[i].verdict <= FLEET_BOARD_PUSH_RECORD_HELD;
    }
    if (!clean && push_log_due(PUSH_LOG_RECEIPT, &skipped))
        LOG_INFO("fleet.board", "fleet push answered %s at %lld ms; the pull "
                 "carries what it did not store (%llu more lines since the "
                 "last)", k_code_names[rc->code], (long long)rc->commit_ms,
                 (unsigned long long)skipped);
}

static void push_out_closed(struct mesh_stream *st,
                            enum mesh_stream_refusal reason,
                            const uint8_t *payload, size_t len)
{
    struct board_push_out_state *s = st->service_state;
    if (s->self_closed)
        return;
    s->self_closed = true;
    struct board_push_receipt rc;
    if (board_push_receipt_decode(payload, len, &rc)) {
        board_push_receipt_seen(s->ids, s->n, &rc);
        return;
    }
    if (reason == MESH_STREAM_REFUSED_MALFORMED && len == 0) {
        /* What a node from before the push answers the type: remember the
         * session, so it is not asked again while it lasts. */
        push_session_mark_unsupported(st);
        board_push_skip(FLEET_BOARD_PUSH_SKIP_UNSUPPORTED, s->n);
        return;
    }
    push_bump(&g_closed[(unsigned)reason & 15u], 1);
    uint64_t skipped = 0;
    if (push_log_due(PUSH_LOG_RECEIPT, &skipped))
        LOG_INFO("fleet.board", "fleet push ended with no receipt: %s (%llu "
                 "more lines since the last)",
                 mesh_stream_refusal_string(reason),
                 (unsigned long long)skipped);
}

void board_push_stream_close(struct mesh_stream *st, enum board_state_tag tag,
                             enum mesh_stream_refusal reason,
                             const uint8_t *payload, size_t len)
{
    if (tag == BOARD_STATE_PUSH_OUT) {
        push_out_closed(st, reason, payload, len);
        push_bump(&g_send_gen, 1); /* a post held for this peer may go now */
        return;
    }
    const struct board_push_in_state *s = st->service_state;
    if (push_slot_drop(s->slot, s->seq) == PUSH_DROP_DONE)
        push_bump(&g_in_dropped, 1);
}

void board_push_state_free(void *state)
{
    const enum board_state_tag *tag = state;
    if (tag && *tag == BOARD_STATE_PUSH_IN) {
        const struct board_push_in_state *s = state;
        if (push_slot_drop(s->slot, s->seq) == PUSH_DROP_DONE)
            push_bump(&g_in_dropped, 1);
    } else if (tag && *tag == BOARD_STATE_PUSH_OUT) {
        push_bump(&g_send_gen, 1); /* however the push ended */
    }
    free(state);
}

/* ── counters and lifecycle ───────────────────────────────────────────── */

static void push_copy(uint64_t *out, _Atomic uint64_t *in, size_t n)
{
    for (size_t i = 0; i < n; i++)
        out[i] = atomic_load_explicit(&in[i], memory_order_relaxed);
}

void board_push_counts(struct boot_fleet_board_fleet_counts *out)
{
    out->push_queued = atomic_load_explicit(&g_queued, memory_order_relaxed);
    out->push_opened = atomic_load_explicit(&g_opened, memory_order_relaxed);
    push_copy(out->push_skipped, g_skipped, FLEET_BOARD_PUSH_SKIPS);
    push_copy(out->push_closed, g_closed, 16);
    push_copy(out->push_receipt, g_receipt, FLEET_BOARD_PUSH_CODES);
    push_copy(out->push_receipt_records, g_receipt_records,
              FLEET_BOARD_PUSH_VERDICTS);
    push_copy(out->push_in, g_in, FLEET_BOARD_PUSH_CODES);
    push_copy(out->push_in_records, g_in_records, FLEET_BOARD_PUSH_VERDICTS);
    out->push_in_dropped =
        atomic_load_explicit(&g_in_dropped, memory_order_relaxed);
    out->push_data_refused =
        atomic_load_explicit(&g_data_refused, memory_order_relaxed);
    push_copy(out->push_refused_out, g_refused_out, FLEET_BOARD_PUSH_REFUSALS);
    push_copy(out->push_refused_in, g_refused_in, FLEET_BOARD_PUSH_REFUSALS);
    push_copy(out->push_hint, g_hint, FLEET_BOARD_PUSH_HINTS);
    board_push_fanout_counts(out);
}

const char *board_push_skip_name(unsigned why)
{
    return why < FLEET_BOARD_PUSH_SKIPS ? k_skip_names[why] : "unknown";
}

const char *board_push_code_name(unsigned code)
{
    return code < FLEET_BOARD_PUSH_CODES ? k_code_names[code] : "unknown";
}

void board_push_forget(void)
{
    push_lock();
    g_queue_head = 0;
    g_queue_len = 0;
    for (size_t i = 0; i < FLEET_BOARD_PUSH_INBOX_MAX; i++) {
        g_inbox[i].state = PUSH_SLOT_FREE;
        g_inbox[i].len = 0;
    }
    memset(g_unsupported, 0, sizeof g_unsupported);
    g_unsupported_next = 0;
    g_round_gen = atomic_load_explicit(&g_send_gen, memory_order_relaxed);
    g_round_second = 0;
    atomic_store_explicit(&g_queue_count, 0, memory_order_relaxed);
    atomic_store_explicit(&g_inbox_filled, 0, memory_order_relaxed);
    push_unlock();
}

#ifdef ZCL_TESTING
size_t boot_fleet_board_fleet_test_push_send(struct boot_svc_ctx *svc,
                                             struct node_db *store)
{
    return push_send_round(svc, store, board_now());
}

size_t boot_fleet_board_fleet_test_push_send_at(struct boot_svc_ctx *svc,
                                                struct node_db *store,
                                                int64_t now)
{
    return push_send_round(svc, store, now);
}

uint64_t boot_fleet_board_fleet_test_push_peer_walks(void)
{
    return atomic_load_explicit(&g_test_peer_walks, memory_order_relaxed);
}

size_t boot_fleet_board_fleet_test_push_commit(struct node_db *store)
{
    return push_commit_one(store);
}

void boot_fleet_board_fleet_test_pre_push_dispatch(bool on)
{
    g_test_pre_push = on;
}

void boot_fleet_board_fleet_test_push_forget_inbox(void)
{
    push_lock();
    for (size_t i = 0; i < FLEET_BOARD_PUSH_INBOX_MAX; i++) {
        g_inbox[i].state = PUSH_SLOT_FREE;
        g_inbox[i].len = 0;
    }
    atomic_store_explicit(&g_inbox_filled, 0, memory_order_relaxed);
    push_unlock();
}

size_t boot_fleet_board_fleet_test_push_queued(void)
{
    push_lock();
    size_t n = g_queue_len;
    push_unlock();
    return n;
}

size_t boot_fleet_board_fleet_test_push_inbox_used(void)
{
    size_t n = 0;
    push_lock();
    for (size_t i = 0; i < FLEET_BOARD_PUSH_INBOX_MAX; i++)
        n += g_inbox[i].state != PUSH_SLOT_FREE;
    push_unlock();
    return n;
}

struct push_tag_count {
    bool local_initiator;
    int tag;
    size_t n;
};

static bool push_tag_visitor(struct mesh_stream *st, void *ctx)
{
    struct push_tag_count *c = ctx;
    const enum board_state_tag *tag = st->service_state;
    if (!st->ended && st->local_initiator == c->local_initiator && tag &&
        (int)*tag == c->tag)
        c->n++;
    return true;
}

size_t boot_fleet_board_fleet_test_live_tagged(bool local_initiator, int tag)
{
    struct push_tag_count c = { local_initiator, tag, 0 };
    mesh_stream_visit(FLEET_BOARD_FLEET_SERVICE_NAME, push_tag_visitor, &c);
    return c.n;
}

static bool push_age_visitor(struct mesh_stream *st, void *ctx)
{
    const int64_t *seconds = ctx;
    const enum board_state_tag *tag = st->service_state;
    if (tag && (*tag == BOARD_STATE_PUSH_OUT || *tag == BOARD_STATE_PUSH_IN)) {
        st->opened_unix -= *seconds;
        st->last_activity_unix -= *seconds;
    }
    return true;
}

void boot_fleet_board_fleet_test_age_push(int64_t seconds)
{
    mesh_stream_visit(FLEET_BOARD_FLEET_SERVICE_NAME, push_age_visitor,
                      &seconds);
}
#endif
