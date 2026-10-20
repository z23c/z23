/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: The fleet roster and its relay gate. See config/boot_fleet_roster.h
 *          for the contract (ZRC 0012 step 2).
 *
 * The roster is derived, never stored on its own: it is the set of signing
 * keys named by the root-sealed lines held in FLEET-scope roster notes of
 * this node's board store, which db_fleet_board_post_ingest already saves
 * through the ActiveRecord lifecycle. Only a row whose seal verified is ever
 * stored (boot_fleet_roster_screen_post), so the store holds the roster and
 * nothing that merely looks like one. A cached copy lives in memory for a few
 * seconds and is dropped the moment a roster row arrives.
 *
 * COST. A fleet post from an already-listed peer costs a memcmp over at most
 * BOOT_FLEET_ROSTER_MAX keys: zero signature verifies on the cached path. A
 * roster row costs one Ed25519 verify at ingest. A rebuild reads at most
 * BOOT_FLEET_ROSTER_SCAN_ROWS notes and verifies each DISTINCT line once
 * (republished copies share a digest), one rebuild at a time. */

#include "config/boot_fleet_roster.h"

#include "config/boot_endpoint_records.h"
#include "config/boot_fleet_board.h"

#include "base/hex.h"
#include "base/safe_alloc.h"
#include "platform/time_compat.h"
#include "crypto/sha256.h"
#include "models/fleet_board_post.h"
#include "util/fleet_roster_check.h"
#include "util/log_macros.h"
#include "util/sync.h"
#include "vcs/zendp_swarm.h"

#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

#define ROSTER_LOG "fleet.roster"

enum snap_state {
    SNAP_UNARMED = 0,
    SNAP_READY,
    SNAP_UNVERIFIABLE,
};

struct roster_snap {
    struct node_db *ndb;
    uint64_t generation;
    int64_t built_at;
    bool valid;
    bool disabled;          /* -fleetrostergate=0: not enforced on this box */
    enum snap_state state;
    size_t count;
    struct zcl_fleet_head head; /* the trusted head this snapshot was built
                                 * under: revocation outlives the roster
                                 * notes, so UNARMED still applies it */
    uint8_t keys[BOOT_FLEET_ROSTER_MAX][32];
};

/* The trusted root as seen through the seam and the chain projection. */
struct root_view {
    uint8_t root[32];
    enum zcl_fleet_root_state state;
    bool require;
    bool manager;
};

static zcl_mutex_t g_lock;        /* guards g_snap and g_logged */
static zcl_mutex_t g_build_lock;  /* one rebuild at a time */
static zcl_once_t g_lock_once = ZCL_ONCE_INIT;
static struct roster_snap g_snap;
static enum snap_state g_logged;  /* last state announced (under g_lock) */
static bool g_disabled_logged;    /* under g_lock */
static _Atomic uint64_t g_generation;
static _Atomic int g_gate;
static _Atomic uint64_t g_non_member;
static _Atomic uint64_t g_unverifiable;
static _Atomic uint64_t g_bad_rows;
static _Atomic uint64_t g_verifies;
static _Atomic uint64_t g_rebuilds;
static _Atomic uint64_t g_armed_events;
static _Atomic uint64_t g_lapse_events;
#ifdef ZCL_TESTING
static _Atomic int g_test_build_delay_ms;
#endif
static _Atomic int64_t g_log_last[BOOT_FLEET_ROSTER_LOG_KINDS];
static _Atomic uint64_t g_log_skipped[BOOT_FLEET_ROSTER_LOG_KINDS];

static void roster_lock_init(void)
{
    zcl_mutex_init(&g_lock);
    zcl_mutex_init(&g_build_lock);
}

static void roster_lock(void)
{
    (void)zcl_once_call(&g_lock_once, roster_lock_init);
    zcl_mutex_lock(&g_lock);
}

static void roster_unlock(void)
{
    zcl_mutex_unlock(&g_lock);
}

static bool build_trylock(void)
{
    (void)zcl_once_call(&g_lock_once, roster_lock_init);
    return zcl_mutex_trylock(&g_build_lock);
}

static void build_lock(void)
{
    (void)zcl_once_call(&g_lock_once, roster_lock_init);
    zcl_mutex_lock(&g_build_lock);
}

static void build_unlock(void)
{
    zcl_mutex_unlock(&g_build_lock);
}

void boot_fleet_roster_set_gate(enum boot_fleet_roster_gate gate)
{
    atomic_store_explicit(&g_gate, (int)gate, memory_order_relaxed);
    boot_fleet_roster_invalidate();
}

enum boot_fleet_roster_gate boot_fleet_roster_gate(void)
{
    int g = atomic_load_explicit(&g_gate, memory_order_relaxed);
    if (g == (int)BOOT_FLEET_ROSTER_GATE_ON)
        return BOOT_FLEET_ROSTER_GATE_ON;
    if (g == (int)BOOT_FLEET_ROSTER_GATE_OFF)
        return BOOT_FLEET_ROSTER_GATE_OFF;
    return BOOT_FLEET_ROSTER_GATE_DEFAULT;
}

bool boot_fleet_roster_is_row(const struct fleet_board_post *post)
{
    return post && post->scope == FLEET_BOARD_SCOPE_FLEET &&
           post->kind == FLEET_BOARD_KIND_NOTE &&
           strcmp(post->agent, BOOT_FLEET_ROSTER_AGENT) == 0;
}

void boot_fleet_roster_invalidate(void)
{
    atomic_fetch_add_explicit(&g_generation, 1, memory_order_relaxed);
}

bool boot_fleet_roster_log_due(enum boot_fleet_roster_log_kind kind,
                               int64_t now, uint64_t *skipped)
{
    if ((unsigned)kind >= (unsigned)BOOT_FLEET_ROSTER_LOG_KINDS)
        return false;
    int64_t last = atomic_load_explicit(&g_log_last[kind],
                                        memory_order_relaxed);
    bool inside = last != 0 && now >= last &&
                  now - last < BOOT_FLEET_ROSTER_LOG_WINDOW_S;
    if (inside || !atomic_compare_exchange_strong_explicit(
                      &g_log_last[kind], &last, now, memory_order_relaxed,
                      memory_order_relaxed)) {
        atomic_fetch_add_explicit(&g_log_skipped[kind], 1,
                                  memory_order_relaxed);
        return false;
    }
    uint64_t left = atomic_exchange_explicit(&g_log_skipped[kind], 0,
                                             memory_order_relaxed);
    if (skipped)
        *skipped = left;
    return true;
}

/* Every Ed25519 verify the roster runs goes through here, so the count the
 * tests read is the count the node paid. */
static bool roster_verify(const char *line, const struct root_view *rv,
                          uint8_t signer[32], uint8_t box[32],
                          bool *sealed)
{
    const char *why = NULL;
    atomic_fetch_add_explicit(&g_verifies, 1, memory_order_relaxed);
    return zcl_fleet_roster_verify(line, rv->root, rv->state, rv->require,
                                   signer, box, sealed, &why);
}

/* ── the root, through the seam and the chain ────────────────────────── */

static enum zcl_fleet_root_state roster_anchor_state(struct node_db *ndb,
                                                     const uint8_t root[32])
{
    struct zendp_anchor a;
    if (!boot_endpoint_anchor_from_db(ndb, root, &a))
        return ZCL_FLEET_ROOT_UNREADABLE;
    switch (a.state) {
    case ZENDP_ANCHOR_ABSENT: return ZCL_FLEET_ROOT_NOT_ANCHORED;
    case ZENDP_ANCHOR_ACTIVE: return ZCL_FLEET_ROOT_ACTIVE;
    case ZENDP_ANCHOR_ROTATED: return ZCL_FLEET_ROOT_ROTATED;
    case ZENDP_ANCHOR_REVOKED: return ZCL_FLEET_ROOT_REVOKED;
    case ZENDP_ANCHOR_UNKNOWN: break;
    }
    return ZCL_FLEET_ROOT_UNREADABLE;
}

/* Fill `rv`. UNARMED: this box trusts no root. READY: `rv` is usable.
 * UNVERIFIABLE: a root is recorded and cannot be read. */
static enum snap_state roster_root_read(struct node_db *ndb,
                                        struct root_view *rv)
{
    bool present = false;
    memset(rv, 0, sizeof *rv);
    if (!zcl_fleet_roster_root(rv->root, &present, &rv->manager)) {
        LOG_WARN(ROSTER_LOG, "the recorded fleet root cannot be read: no "
                 "fleet-scope relay until it can");
        return SNAP_UNVERIFIABLE;
    }
    if (!present)
        return SNAP_UNARMED;
    rv->state = roster_anchor_state(ndb, rv->root);
    rv->require = rv->state != ZCL_FLEET_ROOT_NOT_ANCHORED;
    return SNAP_READY;
}

/* The root as the gate sees it: -fleetrostergate=0 hides it, so nothing is
 * enforced on this box. */
static enum snap_state roster_root_view(struct node_db *ndb,
                                        struct root_view *rv, bool *disabled)
{
    *disabled = boot_fleet_roster_gate() == BOOT_FLEET_ROSTER_GATE_OFF;
    if (*disabled) {
        memset(rv, 0, sizeof *rv);
        return SNAP_UNARMED;
    }
    return roster_root_read(ndb, rv);
}

/* ── the scan ────────────────────────────────────────────────────────── */

/* Lines already proven under a given root and chain state, so a rebuild that
 * finds the same line again (the cache is rebuilt every few seconds and
 * whenever a roster row arrives) does not verify it again. Only a line that
 * verified is remembered, and only for the exact root, chain state and
 * require flag it verified under: a rotation or a revocation changes the
 * state and the memo is not consulted. Guarded by the build lock. */
struct memo_entry {
    uint8_t digest[SHA256_OUTPUT_SIZE];
    uint8_t signer[32];
    uint8_t box[32];        /* the key a roster head revokes, checked on
                             * every use: the head can change under a memo */
};

struct line_memo {
    bool valid;
    uint8_t root[32];
    enum zcl_fleet_root_state state;
    bool require;
    size_t n;
    struct memo_entry e[BOOT_FLEET_ROSTER_SCAN_ROWS];
};

static struct line_memo g_memo;

static bool memo_matches(const struct line_memo *m, const struct root_view *rv)
{
    return m->valid && m->state == rv->state && m->require == rv->require &&
           memcmp(m->root, rv->root, 32) == 0;
}

static const struct memo_entry *memo_find(
    const struct line_memo *m, const uint8_t digest[SHA256_OUTPUT_SIZE])
{
    for (size_t i = 0; i < m->n; i++)
        if (memcmp(m->e[i].digest, digest, SHA256_OUTPUT_SIZE) == 0)
            return &m->e[i];
    return NULL;
}

static void memo_add(struct line_memo *m,
                     const uint8_t digest[SHA256_OUTPUT_SIZE],
                     const uint8_t signer[32], const uint8_t box[32])
{
    if (m->n >= BOOT_FLEET_ROSTER_SCAN_ROWS)
        return;
    memcpy(m->e[m->n].digest, digest, SHA256_OUTPUT_SIZE);
    memcpy(m->e[m->n].signer, signer, 32);
    memcpy(m->e[m->n].box, box, 32);
    m->n++;
}

struct scan_acc {
    struct roster_snap *snap;
    const struct root_view *rv;
    unsigned sealed;        /* rows whose seal verified */
    unsigned refused;       /* sealed, but the root's chain state refuses */
    unsigned bad;           /* roster-shaped rows that are not sealed */
    unsigned dropped;       /* member keys past the roster bound */
    unsigned copies;        /* republished copies skipped by digest */
    bool memo_ok;           /* g_memo was made under this root and state */
    size_t n_seen;
    uint8_t seen[BOOT_FLEET_ROSTER_SCAN_ROWS][SHA256_OUTPUT_SIZE];
    unsigned revoked;       /* verified, but the head revokes the box */
    struct zcl_fleet_head head; /* loaded once for this rebuild */
    struct line_memo next;  /* what this scan proved, kept for the next */
};

static void snap_add_key(struct scan_acc *acc, const uint8_t key[32])
{
    static const uint8_t none[32];
    struct roster_snap *s = acc->snap;
    if (memcmp(key, none, 32) == 0)
        return;
    for (size_t i = 0; i < s->count; i++)
        if (memcmp(s->keys[i], key, 32) == 0)
            return;
    if (s->count >= BOOT_FLEET_ROSTER_MAX) {
        acc->dropped++;
        return;
    }
    memcpy(s->keys[s->count++], key, 32);
}

/* Has a row with this exact text already been judged in this scan? A line
 * is republished every 10 days and the old copy lives 30, so a roster holds
 * up to three copies of each; the digest makes each distinct line cost one
 * verify, not one per copy. */
static bool scan_seen(struct scan_acc *acc,
                      const uint8_t digest[SHA256_OUTPUT_SIZE])
{
    for (size_t i = 0; i < acc->n_seen; i++)
        if (memcmp(acc->seen[i], digest, SHA256_OUTPUT_SIZE) == 0)
            return true;
    if (acc->n_seen < BOOT_FLEET_ROSTER_SCAN_ROWS)
        memcpy(acc->seen[acc->n_seen++], digest, SHA256_OUTPUT_SIZE);
    return false;
}

static void scan_digest(const char *text, size_t len,
                        uint8_t digest[SHA256_OUTPUT_SIZE])
{
    struct sha256_ctx h;
    sha256_init(&h);
    sha256_write(&h, (const unsigned char *)text, len);
    sha256_finalize(&h, digest);
}

/* Is this box key in the head's revoked set? O(revoked), and the head was
 * loaded once for this rebuild. */
static bool head_revokes(const struct zcl_fleet_head *h, const uint8_t box[32])
{
    for (uint32_t i = 0; i < h->count; i++)
        if (memcmp(h->revoked[i], box, 32) == 0)
            return true;
    return false;
}

/* One verified line becomes a member unless the head revokes its box. The
 * memo keeps the line either way: the head can change under it. */
static void scan_member(struct scan_acc *acc, const uint8_t digest[],
                        const uint8_t signer[32], const uint8_t box[32])
{
    memo_add(&acc->next, digest, signer, box);
    if (head_revokes(&acc->head, box) || head_revokes(&acc->head, signer)) {
        acc->revoked++;
        return;
    }
    snap_add_key(acc, signer);
}

/* Judge one distinct line: from the memo when the same line already
 * verified under this root and state, else by verifying it. */
static void scan_judge(const struct fleet_board_post *p,
                       const uint8_t digest[SHA256_OUTPUT_SIZE],
                       struct scan_acc *acc)
{
    uint8_t signer[32], box[32];
    bool sealed = false;
    const struct memo_entry *known =
        acc->memo_ok ? memo_find(&g_memo, digest) : NULL;
    if (known) {
        acc->sealed++;
        scan_member(acc, digest, known->signer, known->box);
        return;
    }
    bool ok = roster_verify(p->text, acc->rv, signer, box, &sealed);
    if (sealed)
        acc->sealed++;
    if (ok)
        scan_member(acc, digest, signer, box);
    else if (sealed)
        acc->refused++;
    else
        acc->bad++;
    memset(signer, 0, sizeof signer);
}

static void scan_row(const struct fleet_board_post *p, struct scan_acc *acc)
{
    uint8_t digest[SHA256_OUTPUT_SIZE];
    if (!boot_fleet_roster_is_row(p))
        return;
    if (p->text_len == 0 || p->text_len >= ZCL_FLEET_ROSTER_LINE_MAX) {
        acc->bad++;
        return;
    }
    scan_digest(p->text, p->text_len, digest);
    if (scan_seen(acc, digest)) {
        acc->copies++;
        return;
    }
    scan_judge(p, digest, acc);
}

static void scan_report(const struct scan_acc *acc, bool page_full)
{
    if (acc->bad) {
        atomic_fetch_add_explicit(&g_bad_rows, acc->bad,
                                  memory_order_relaxed);
        LOG_WARN(ROSTER_LOG,
                 "fleetboard.roster_signature_invalid: %u roster row(s) "
                 "were not sealed by the fleet root and add nobody",
                 acc->bad);
    }
    if (acc->dropped)
        LOG_WARN(ROSTER_LOG, "the roster holds more than %d members; %u "
                 "were left out", (int)BOOT_FLEET_ROSTER_MAX, acc->dropped);
    if (acc->revoked)
        LOG_WARN(ROSTER_LOG, "fleet_box_revoked: %u sealed roster row(s) "
                 "name a box the roster head revokes and add nobody",
                 acc->revoked);
    if (acc->refused)
        LOG_WARN(ROSTER_LOG, "the roster has %u sealed row(s) but the fleet "
                 "root's chain state refuses them: no fleet-scope relay",
                 acc->refused);
    if (page_full)
        LOG_WARN(ROSTER_LOG, "the roster scan filled its page; members past "
                 "it are not seen");
}

/* Fold every stored roster row into the snapshot. The memo of proven lines
 * is replaced by what this scan proved, so it never outlives its rows. */
static enum snap_state scan_fold(const struct db_fleet_board_post *rows, int n,
                                 const struct root_view *rv,
                                 struct roster_snap *snap,
                                 struct scan_acc *acc)
{
    acc->snap = snap;
    acc->rv = rv;
    acc->memo_ok = memo_matches(&g_memo, rv);
    snap->head = acc->head;
    for (int i = 0; i < n; i++)
        scan_row(&rows[i].post, acc);
    bool full = n >= BOOT_FLEET_ROSTER_SCAN_ROWS;
    scan_report(acc, full);
    acc->next.valid = true;
    memcpy(acc->next.root, rv->root, 32);
    acc->next.state = rv->state;
    acc->next.require = rv->require;
    g_memo = acc->next;
    if (rv->state == ZCL_FLEET_ROOT_REVOKED ||
        rv->state == ZCL_FLEET_ROOT_ROTATED ||
        rv->state == ZCL_FLEET_ROOT_UNREADABLE) {
        LOG_WARN(ROSTER_LOG, "the fleet root is %s on chain: no fleet-scope "
                 "relay, whatever roster notes are held",
                 rv->state == ZCL_FLEET_ROOT_REVOKED ? "revoked"
                 : rv->state == ZCL_FLEET_ROOT_ROTATED ? "rotated"
                                                       : "unreadable");
        return SNAP_UNVERIFIABLE;
    }
    if (acc->refused)
        return SNAP_UNVERIFIABLE;
    if (acc->sealed == 0)
        return full ? SNAP_UNVERIFIABLE : SNAP_UNARMED;
    return SNAP_READY;
}

/* Read every stored roster note and fold the roster rows. A read that fails
 * is UNVERIFIABLE, never "no roster": the store may hold the very rows that
 * name the members. */
static enum snap_state roster_scan(struct node_db *ndb, int64_t now,
                                   const struct root_view *rv,
                                   struct roster_snap *snap)
{
    struct fleet_board_filter filter;
    memset(&filter, 0, sizeof filter);
    filter.kind = FLEET_BOARD_KIND_NOTE;
    (void)snprintf(filter.agent, sizeof filter.agent, "%s",
                   BOOT_FLEET_ROSTER_AGENT);
    filter.scope_set = true;
    filter.scope = FLEET_BOARD_SCOPE_FLEET;
    struct db_fleet_board_post *rows = zcl_calloc(
        BOOT_FLEET_ROSTER_SCAN_ROWS, sizeof *rows, "fleet_roster_scan");
    struct scan_acc *acc = zcl_calloc(1, sizeof *acc, "fleet_roster_acc");
    if (!rows || !acc) {
        free(rows);
        free(acc);
        return SNAP_UNVERIFIABLE;
    }
    /* The head is loaded ONCE here, not per peer. A head that exists and
     * cannot be trusted is not "nothing revoked": it admits nobody, by name,
     * until the owner repairs it. */
    zcl_fleet_roster_head(rv->root, &acc->head);
    if (acc->head.state == ZCL_FLEET_HEAD_FAILED) {
        LOG_WARN(ROSTER_LOG, "fleet_head_unreadable: the roster head cannot "
                 "be trusted (unreadable, corrupt, or not sealed by the "
                 "fleet root): no fleet-scope relay until it is repaired");
        free(rows);
        free(acc);
        return SNAP_UNVERIFIABLE;
    }
    bool complete = false;
    int n = db_fleet_board_list_checked(ndb, &filter, now, rows,
                                        BOOT_FLEET_ROSTER_SCAN_ROWS,
                                        &complete);
    enum snap_state out = SNAP_UNVERIFIABLE;
    if (!complete) {
        LOG_WARN(ROSTER_LOG, "the roster notes could not be read from the "
                 "board store: no fleet-scope relay until they can");
    } else {
        out = scan_fold(rows, n, rv, snap, acc);
    }
    free(rows);
    free(acc);
    return out;
}

static void roster_build(struct node_db *ndb, int64_t now,
                         struct roster_snap *snap)
{
    struct root_view rv;
    memset(snap, 0, sizeof *snap);
    snap->ndb = ndb;
    snap->generation = atomic_load_explicit(&g_generation,
                                            memory_order_relaxed);
    snap->built_at = now;
    snap->valid = true;
    snap->state = roster_root_view(ndb, &rv, &snap->disabled);
    if (snap->state == SNAP_READY)
        snap->state = roster_scan(ndb, now, &rv, snap);
#ifdef ZCL_TESTING
    /* A test seam: a slow store read, so askers certainly arrive mid-build. */
    int slow = atomic_load_explicit(&g_test_build_delay_ms,
                                    memory_order_relaxed);
    if (slow > 0)
        platform_sleep_ms(slow);
#endif
    atomic_fetch_add_explicit(&g_rebuilds, 1, memory_order_relaxed);
    memset(rv.root, 0, sizeof rv.root);
}

/* Announce a change of state, once per change (called under g_lock). The
 * UNARMED to armed step is INFO with the member count; every way back down
 * is WARN, including the quiet one where the notes simply outlived their
 * TTL. */
static void snap_log_transition(const struct roster_snap *s)
{
    if (s->disabled && !g_disabled_logged) {
        g_disabled_logged = true;
        LOG_WARN(ROSTER_LOG, "the fleet roster gate is switched off on this "
                 "box (-fleetrostergate=0): fleet-scope carriage follows "
                 "pairing and role only");
    }
    if (s->state == g_logged)
        return;
    enum snap_state was = g_logged;
    g_logged = s->state;
    if (s->state == SNAP_READY) {
        atomic_fetch_add_explicit(&g_armed_events, 1, memory_order_relaxed);
        LOG_INFO(ROSTER_LOG, "fleet roster armed: %zu member(s); fleet-scope "
                 "posts now move between roster members only", s->count);
    } else if (s->state == SNAP_UNARMED) {
        if (was == SNAP_READY)
            atomic_fetch_add_explicit(&g_lapse_events, 1,
                                      memory_order_relaxed);
        LOG_WARN(ROSTER_LOG, "fleet roster lapsed to unarmed (%s): "
                 "fleet-scope carriage is pairing plus role again",
                 s->disabled ? "switched off locally"
                             : "no sealed roster row is held; the notes "
                               "expired or were never republished");
    } else {
        LOG_WARN(ROSTER_LOG, "fleet roster is unverifiable: no fleet-scope "
                 "relay until the root and the roster notes can be read");
    }
}

static bool snap_fresh(const struct roster_snap *s, struct node_db *ndb,
                       int64_t now)
{
    return s->valid && s->ndb == ndb && now >= s->built_at &&
           now - s->built_at < BOOT_FLEET_ROSTER_TTL_S &&
           s->generation == atomic_load_explicit(&g_generation,
                                                 memory_order_relaxed);
}

static enum boot_fleet_roster_verdict snap_verdict(const struct roster_snap *s,
                                                   const uint8_t key[32])
{
    static const uint8_t none[32];
    if (s->state == SNAP_UNARMED)
        return head_revokes(&s->head, key) ? BOOT_FLEET_ROSTER_NOT_MEMBER
                                           : BOOT_FLEET_ROSTER_UNARMED;
    if (s->state != SNAP_READY)
        return BOOT_FLEET_ROSTER_UNVERIFIABLE;
    if (memcmp(key, none, 32) == 0)
        return BOOT_FLEET_ROSTER_NOT_MEMBER;
    for (size_t i = 0; i < s->count; i++)
        if (memcmp(s->keys[i], key, 32) == 0)
            return BOOT_FLEET_ROSTER_MEMBER;
    return BOOT_FLEET_ROSTER_NOT_MEMBER;
}

/* Look at the cached snapshot. True when it is fresh and *v is its verdict.
 * Otherwise *stale says an older snapshot of this store exists, and *v then
 * holds the verdict it gives. */
static bool snap_peek(struct node_db *ndb, const uint8_t key[32], int64_t now,
                      enum boot_fleet_roster_verdict *v, bool *stale)
{
    roster_lock();
    bool fresh = snap_fresh(&g_snap, ndb, now);
    *stale = !fresh && g_snap.valid && g_snap.ndb == ndb;
    if (fresh || *stale)
        *v = snap_verdict(&g_snap, key);
    roster_unlock();
    return fresh;
}

/* Rebuild and publish the snapshot. The caller holds the build lock. */
static enum boot_fleet_roster_verdict roster_rebuild(
    struct node_db *ndb, const uint8_t key[32], int64_t now)
{
    struct roster_snap *fresh = zcl_calloc(1, sizeof *fresh,
                                           "fleet_roster_snap");
    if (!fresh)
        return BOOT_FLEET_ROSTER_UNVERIFIABLE;
    roster_build(ndb, now, fresh);
    roster_lock();
    g_snap = *fresh;
    snap_log_transition(&g_snap);
    enum boot_fleet_roster_verdict v = snap_verdict(&g_snap, key);
    roster_unlock();
    memset(fresh, 0, sizeof *fresh);
    free(fresh);
    return v;
}

/* Single flight: one thread rebuilds; a thread that finds the rebuild under
 * way answers from the last snapshot of this store (a rebuild is a store read
 * plus a handful of verifies, and the snapshot it replaces is at most one
 * rebuild old); only a thread with no snapshot at all waits for the builder. */
enum boot_fleet_roster_verdict boot_fleet_roster_check(
    struct node_db *ndb, const uint8_t key[32], int64_t now)
{
    enum boot_fleet_roster_verdict v = BOOT_FLEET_ROSTER_UNVERIFIABLE;
    bool stale = false;
    if (!ndb || !key || !ndb->open)
        return BOOT_FLEET_ROSTER_UNVERIFIABLE; /* cannot ask: closed */
    if (snap_peek(ndb, key, now, &v, &stale))
        return v;
    if (!build_trylock()) {
        if (stale)
            return v;
        build_lock();
        build_unlock();
        if (snap_peek(ndb, key, now, &v, &stale) || stale)
            return v;
        return BOOT_FLEET_ROSTER_UNVERIFIABLE; /* the builder failed */
    }
    if (!snap_peek(ndb, key, now, &v, &stale))
        v = roster_rebuild(ndb, key, now);
    build_unlock();
    return v;
}

static bool roster_admits(enum boot_fleet_roster_verdict v)
{
    switch (v) {
    case BOOT_FLEET_ROSTER_UNARMED:
    case BOOT_FLEET_ROSTER_MEMBER:
        return true;
    case BOOT_FLEET_ROSTER_NOT_MEMBER:
        atomic_fetch_add_explicit(&g_non_member, 1, memory_order_relaxed);
        return false;
    case BOOT_FLEET_ROSTER_UNVERIFIABLE:
        break;
    }
    atomic_fetch_add_explicit(&g_unverifiable, 1, memory_order_relaxed);
    return false;
}

bool boot_fleet_roster_admits_peer(struct node_db *ndb, const uint8_t key[32],
                                   int64_t now)
{
    return roster_admits(boot_fleet_roster_check(ndb, key, now));
}

/* A roster row may be stored only if its seal verifies under the root this
 * box trusts. This is the one place a roster row is judged on its way in:
 * the same screen runs for the mesh stream, a P2P POST and a local publish. */
static enum fleet_board_result roster_row_screen(
    struct node_db *ndb, const struct fleet_board_post *post, int64_t now)
{
    struct root_view rv;
    uint8_t signer[32], box[32];
    bool sealed = false;
    if (!ndb || !ndb->open)
        return FLEET_BOARD_ERR_ARGS;
    if (db_fleet_board_have(ndb, post->id))
        return FLEET_BOARD_OK; /* judged when it was stored */
    if (post->text_len == 0 || post->text_len >= ZCL_FLEET_ROSTER_LINE_MAX) {
        atomic_fetch_add_explicit(&g_bad_rows, 1, memory_order_relaxed);
        return FLEET_BOARD_ERR_SIGNATURE;
    }
    enum snap_state have_root = roster_root_read(ndb, &rv);
    if (have_root == SNAP_UNARMED)
        return FLEET_BOARD_OK; /* no root: this box gates nothing, so the row
                                * is an ordinary note, as before this step;
                                * the scan verifies it if a root appears */
    if (have_root != SNAP_READY) {
        /* A root is recorded and cannot be read: not stored now, offered
         * again when this box can tell. */
        atomic_fetch_add_explicit(&g_unverifiable, 1, memory_order_relaxed);
        return FLEET_BOARD_ERR_ROLE;
    }
    bool ok = roster_verify(post->text, &rv, signer, box, &sealed);
    memset(signer, 0, sizeof signer);
    memset(box, 0, sizeof box);
    memset(rv.root, 0, sizeof rv.root);
    (void)now;
    if (ok)
        return FLEET_BOARD_OK;
    if (sealed) {
        atomic_fetch_add_explicit(&g_unverifiable, 1, memory_order_relaxed);
        return FLEET_BOARD_ERR_ROLE;
    }
    atomic_fetch_add_explicit(&g_bad_rows, 1, memory_order_relaxed);
    return FLEET_BOARD_ERR_SIGNATURE;
}

enum fleet_board_result boot_fleet_roster_screen_post(
    struct node_db *ndb, const struct fleet_board_post *post, int64_t now)
{
    if (!post)
        return FLEET_BOARD_ERR_ARGS;
    if (post->scope != FLEET_BOARD_SCOPE_FLEET)
        return FLEET_BOARD_OK;
    if (boot_fleet_roster_is_row(post))
        return roster_row_screen(ndb, post, now);
    return boot_fleet_roster_admits_peer(ndb, post->host_pubkey, now)
               ? FLEET_BOARD_OK : FLEET_BOARD_ERR_ROLE;
}

bool boot_fleet_roster_admits_post(struct node_db *ndb,
                                   const struct fleet_board_post *post,
                                   int64_t now)
{
    return boot_fleet_roster_screen_post(ndb, post, now) == FLEET_BOARD_OK;
}

void boot_fleet_roster_counts(struct boot_fleet_roster_counts *out)
{
    if (!out)
        return;
    out->non_member = atomic_load_explicit(&g_non_member,
                                           memory_order_relaxed);
    out->unverifiable = atomic_load_explicit(&g_unverifiable,
                                             memory_order_relaxed);
    out->bad_rows = atomic_load_explicit(&g_bad_rows, memory_order_relaxed);
    out->verifies = atomic_load_explicit(&g_verifies, memory_order_relaxed);
    out->rebuilds = atomic_load_explicit(&g_rebuilds, memory_order_relaxed);
    out->armed_events = atomic_load_explicit(&g_armed_events,
                                             memory_order_relaxed);
    out->lapse_events = atomic_load_explicit(&g_lapse_events,
                                             memory_order_relaxed);
}

/* ── the manager's half: publish the local roster onto the board ─────── */

struct pub_lines {
    char (*lines)[ZCL_FLEET_ROSTER_LINE_MAX];
    size_t n;
};

static void pub_collect(const char *line, void *user)
{
    struct pub_lines *p = user;
    size_t len = strlen(line);
    if (p->n >= BOOT_FLEET_ROSTER_MAX || len == 0 ||
        len >= ZCL_FLEET_ROSTER_LINE_MAX)
        return;
    memcpy(p->lines[p->n], line, len + 1u);
    p->n++;
}

/* Is `line` already carried by a live roster note written less than one
 * republish period ago? A note lives FLEET_BOARD_TTL_MAX and is written again
 * once its newest copy is older than BOOT_FLEET_ROSTER_REPUBLISH_S, so one
 * copy is always live while the manager's node runs. */
static bool pub_already_carried(const struct db_fleet_board_post *notes, int n,
                                const char *line, size_t len, int64_t now)
{
    for (int i = 0; i < n; i++) {
        const struct fleet_board_post *p = &notes[i].post;
        if (p->text_len == len && memcmp(p->text, line, len) == 0 &&
            (int64_t)p->created_at + BOOT_FLEET_ROSTER_REPUBLISH_S > now)
            return true;
    }
    return false;
}

/* Write one roster note unless a young live copy of this exact line is
 * already on the board. True when a row was written. */
static bool pub_one(const struct db_fleet_board_post *notes,
                    int n_notes, const char *line, int64_t now)
{
    size_t len = strlen(line);
    if (len == 0 || len >= FLEET_BOARD_TEXT_MAX) {
        LOG_WARN(ROSTER_LOG, "a roster line of %zu characters cannot be "
                 "carried (the board text bound is %d)", len,
                 (int)FLEET_BOARD_TEXT_MAX);
        return false;
    }
    if (pub_already_carried(notes, n_notes, line, len, now))
        return false;
    struct fleet_board_post *post = zcl_calloc(1, sizeof *post,
                                               "fleet_roster_post");
    if (!post)
        return false;
    post->kind = FLEET_BOARD_KIND_NOTE;
    post->scope = FLEET_BOARD_SCOPE_FLEET;
    post->created_at = (uint64_t)now;
    post->ttl = FLEET_BOARD_TTL_MAX;
    (void)snprintf(post->agent, sizeof post->agent, "%s",
                   BOOT_FLEET_ROSTER_AGENT);
    post->text_len = (uint32_t)len;
    memcpy(post->text, line, len + 1u);
    enum fleet_board_result r = boot_fleet_board_publish(post, now);
    if (r != FLEET_BOARD_OK)
        LOG_WARN(ROSTER_LOG, "roster row not published: %s",
                 fleet_board_result_string(r));
    memset(post, 0, sizeof *post);
    free(post);
    return r == FLEET_BOARD_OK;
}

/* The roster notes this store already holds, newest first. */
static int pub_held(struct node_db *ndb, int64_t now,
                    struct db_fleet_board_post *rows)
{
    struct fleet_board_filter filter;
    memset(&filter, 0, sizeof filter);
    filter.kind = FLEET_BOARD_KIND_NOTE;
    filter.scope_set = true;
    filter.scope = FLEET_BOARD_SCOPE_FLEET;
    (void)snprintf(filter.agent, sizeof filter.agent, "%s",
                   BOOT_FLEET_ROSTER_AGENT);
    return db_fleet_board_list(ndb, &filter, now, rows,
                               BOOT_FLEET_ROSTER_SCAN_ROWS);
}


/* A line the manager may publish: sealed by the root it trusts, accepted by
 * the root's chain state, and naming a board signing key. */
static bool pub_line_ok(const char *line, const struct root_view *rv)
{
    static const uint8_t none[32];
    uint8_t signer[32], box[32];
    bool sealed = false;
    bool ok = roster_verify(line, rv, signer, box, &sealed) &&
              memcmp(signer, none, 32) != 0;
    memset(signer, 0, sizeof signer);
    return ok;
}

static size_t pub_pass(struct node_db *ndb, const struct root_view *rv,
                       const struct pub_lines *p, int64_t now)
{
    struct db_fleet_board_post *held = zcl_calloc(
        BOOT_FLEET_ROSTER_SCAN_ROWS, sizeof *held, "fleet_roster_held");
    size_t wrote = 0;
    if (!held)
        return 0;
    int n = pub_held(ndb, now, held);
    for (size_t i = 0; i < p->n && wrote < BOOT_FLEET_ROSTER_PUBLISH_PER_PASS;
         i++) {
        if (pub_line_ok(p->lines[i], rv) &&
            pub_one(held, n, p->lines[i], now))
            wrote++;
    }
    free(held);
    return wrote;
}

size_t boot_fleet_roster_publish(struct node_db *ndb, int64_t now)
{
    struct root_view rv;
    struct pub_lines p = { NULL, 0 };
    size_t wrote = 0;
    /* Opt-in: without -fleetrostergate nothing is ever published. */
    if (boot_fleet_roster_gate() != BOOT_FLEET_ROSTER_GATE_ON)
        return 0;
    if (!ndb || !ndb->open || now <= 0 ||
        !zcl_fleet_roster_provider_installed())
        return 0;
    if (roster_root_read(ndb, &rv) != SNAP_READY || !rv.manager)
        return 0;
    p.lines = zcl_calloc(BOOT_FLEET_ROSTER_MAX, ZCL_FLEET_ROSTER_LINE_MAX,
                         "fleet_roster_lines");
    if (!p.lines)
        return 0;
    if (zcl_fleet_roster_each_line(pub_collect, &p))
        wrote = pub_pass(ndb, &rv, &p, now);
    free(p.lines);
    memset(rv.root, 0, sizeof rv.root);
    if (wrote)
        boot_fleet_roster_invalidate();
    return wrote;
}

#ifdef ZCL_TESTING
void boot_fleet_roster_test_reset(void)
{
    build_lock(); /* build lock first, as the rebuild takes them */
    roster_lock();
    memset(&g_snap, 0, sizeof g_snap);
    memset(&g_memo, 0, sizeof g_memo);
    g_logged = SNAP_UNARMED;
    g_disabled_logged = false;
    roster_unlock();
    build_unlock();
    atomic_store_explicit(&g_gate, (int)BOOT_FLEET_ROSTER_GATE_DEFAULT,
                          memory_order_relaxed);
    atomic_store_explicit(&g_non_member, 0, memory_order_relaxed);
    atomic_store_explicit(&g_unverifiable, 0, memory_order_relaxed);
    atomic_store_explicit(&g_bad_rows, 0, memory_order_relaxed);
    atomic_store_explicit(&g_verifies, 0, memory_order_relaxed);
    atomic_store_explicit(&g_rebuilds, 0, memory_order_relaxed);
    atomic_store_explicit(&g_armed_events, 0, memory_order_relaxed);
    atomic_store_explicit(&g_test_build_delay_ms, 0, memory_order_relaxed);
    atomic_store_explicit(&g_lapse_events, 0, memory_order_relaxed);
    for (int i = 0; i < (int)BOOT_FLEET_ROSTER_LOG_KINDS; i++) {
        atomic_store_explicit(&g_log_last[i], 0, memory_order_relaxed);
        atomic_store_explicit(&g_log_skipped[i], 0, memory_order_relaxed);
    }
    boot_fleet_roster_invalidate();
}
#endif

#ifdef ZCL_TESTING
void boot_fleet_roster_test_build_delay_ms(int ms)
{
    atomic_store_explicit(&g_test_build_delay_ms, ms, memory_order_relaxed);
}
#endif
