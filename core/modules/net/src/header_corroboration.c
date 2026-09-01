/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * header_corroboration — see net/header_corroboration.h.
 *
 * Two pieces of state, both bounded and self-contained:
 *
 *   1. A direct-mapped corroboration cache: header hash -> set of distinct
 *      address-group keys that announced/served it. Direct-mapped (slot =
 *      cheap_hash % N) is deliberate — the SAME hash from two peers always
 *      lands in the SAME slot and accumulates their groups, which is exactly
 *      the corroboration signal we need; distinct hashes that collide simply
 *      evict, which only ever makes us MORE conservative (treats an evicted
 *      branch as un-corroborated -> held), never less safe.
 *
 *   2. A single "held switch" record describing the current un-corroborated
 *      reorg candidate we are refusing to adopt, surfaced by the
 *      chain_reorg_uncorroborated condition as the transient blocker.
 */

#include "net/header_corroboration.h"

#include <pthread.h>
#include <stdatomic.h>
#include <string.h>

#include "platform/time_compat.h"
#include "platform/os_proc.h"
#include "core/uint256.h"
#include "core/arith_uint256.h"
#include "chain/chain.h"
#include "util/log_macros.h"

/* ── Corroboration cache ─────────────────────────────────────────────── */

#define CORROB_SLOTS        8192   /* power of two; direct-mapped */
#define CORROB_MAX_GROUPS   6      /* distinct group keys tracked per hash */
#define CORROB_GROUP_BYTES  16     /* a net_addr_get_group key is <= 6 bytes */

struct corrob_slot {
    struct uint256 hash;
    bool           used;
    uint8_t        group_count;
    uint8_t        group_len[CORROB_MAX_GROUPS];
    unsigned char  group[CORROB_MAX_GROUPS][CORROB_GROUP_BYTES];
};

/* Internal hold record (superset of the public snapshot). */
struct corrob_hold {
    bool                 active;
    int                  fork_height;
    int                  candidate_height;
    int                  current_height;
    int                  switch_depth;
    struct arith_uint256 candidate_work;   /* for staleness / moot detection */
    struct uint256       candidate_tip;
    char                 work_delta_hex[65];
    char                 candidate_tip_hex[65];
    char                 peer_name[64];
    int64_t              raised_unix;
};

static pthread_mutex_t   g_lock = PTHREAD_MUTEX_INITIALIZER;
static struct corrob_slot g_slots[CORROB_SLOTS];
static struct corrob_hold g_hold;
static atomic_bool        g_enabled = true;
static atomic_bool        g_init_done = false;

/* ── Enable flag ─────────────────────────────────────────────────────── */

/* The -nocorroborate escape hatch is parsed here, lazily, from the process
 * command line rather than plumbed through the argv loop — the policy owns its
 * own config and no consensus/boot/argv path grows. Runs at most once;
 * header_corroboration_set_enabled() (tests, or a future explicit setter) marks
 * init done so it wins over the command line. */
static void header_corroboration_init_once(void)
{
    bool expected = false;
    if (!atomic_compare_exchange_strong(&g_init_done, &expected, true))
        return;
    if (os_proc_cmdline_has_token("-nocorroborate"))
        atomic_store(&g_enabled, false);
}

void header_corroboration_set_enabled(bool enabled)
{
    atomic_store(&g_init_done, true);
    atomic_store(&g_enabled, enabled);
}

bool header_corroboration_enabled(void)
{
    header_corroboration_init_once();
    return atomic_load(&g_enabled);
}

/* ── Cache primitives ────────────────────────────────────────────────── */

static inline size_t corrob_slot_index(const struct uint256 *hash)
{
    return (size_t)(uint256_get_cheap_hash(hash) & (CORROB_SLOTS - 1));
}

void header_corroboration_note(const struct uint256 *hash,
                               const unsigned char *group, size_t group_len)
{
    if (!hash || !group || group_len == 0)
        return;
    if (group_len > CORROB_GROUP_BYTES)
        group_len = CORROB_GROUP_BYTES;

    size_t idx = corrob_slot_index(hash);
    pthread_mutex_lock(&g_lock);
    struct corrob_slot *s = &g_slots[idx];
    if (!s->used || !uint256_eq(&s->hash, hash)) {
        /* Fresh slot or eviction of a colliding hash. */
        memset(s, 0, sizeof(*s));
        s->hash = *hash;
        s->used = true;
    }
    /* Dedup: only append a group we have not already recorded. */
    for (uint8_t i = 0; i < s->group_count; i++) {
        if (s->group_len[i] == group_len &&
            memcmp(s->group[i], group, group_len) == 0) {
            pthread_mutex_unlock(&g_lock);
            return;
        }
    }
    if (s->group_count < CORROB_MAX_GROUPS) {
        s->group_len[s->group_count] = (uint8_t)group_len;
        memcpy(s->group[s->group_count], group, group_len);
        s->group_count++;
    }
    pthread_mutex_unlock(&g_lock);
}

int header_corroboration_groups(const struct uint256 *hash)
{
    if (!hash)
        return 0;
    size_t idx = corrob_slot_index(hash);
    pthread_mutex_lock(&g_lock);
    struct corrob_slot *s = &g_slots[idx];
    int n = (s->used && uint256_eq(&s->hash, hash)) ? (int)s->group_count : 0;
    pthread_mutex_unlock(&g_lock);
    return n;
}

/* ── Header-tree classification helpers (no store lock held) ─────────── */

static bool candidate_strictly_better_work(const struct arith_uint256 *cand_w,
                                            int cand_h,
                                            const struct arith_uint256 *cur_w,
                                            int cur_h)
{
    bool have_work = !arith_uint256_is_zero(cand_w) &&
                     !arith_uint256_is_zero(cur_w);
    if (have_work)
        return arith_uint256_compare(cand_w, cur_w) > 0;
    return cand_h > cur_h;
}

static bool candidate_strictly_better(const struct block_index *cand,
                                      const struct block_index *cur)
{
    if (!cand || cand == cur)
        return false;
    if (!cur)
        return true;
    return candidate_strictly_better_work(&cand->nChainWork, cand->nHeight,
                                          &cur->nChainWork, cur->nHeight);
}

/* Last common ancestor of two chain tips, or NULL if they do not share one
 * (disconnected sub-trees — treated as "cannot classify"). */
static const struct block_index *last_common_ancestor(
    const struct block_index *a, const struct block_index *b)
{
    if (!a || !b)
        return NULL;
    if (a->nHeight > b->nHeight)
        a = block_index_get_ancestor((struct block_index *)a, b->nHeight);
    else if (b->nHeight > a->nHeight)
        b = block_index_get_ancestor((struct block_index *)b, a->nHeight);
    while (a && b && a != b) {
        a = a->pprev;
        b = b->pprev;
    }
    return (a == b) ? a : NULL;
}

/* True iff any header on `candidate`'s branch, from the tip down to (but not
 * including) `fork`, has been vouched for by >= 2 distinct address groups. */
static bool branch_corroborated(const struct block_index *candidate,
                                const struct block_index *fork)
{
    const struct block_index *bi = candidate;
    int steps = 0;
    const int CAP = 512;
    while (bi && bi != fork && steps < CAP) {
        if (bi->phashBlock &&
            header_corroboration_groups(bi->phashBlock) >= 2)
            return true;
        bi = bi->pprev;
        steps++;
    }
    return false;
}

/* ── Hold record ─────────────────────────────────────────────────────── */

static void hold_clear_locked(void)
{
    memset(&g_hold, 0, sizeof(g_hold));
}

bool header_corroboration_hold_active(void)
{
    pthread_mutex_lock(&g_lock);
    bool a = g_hold.active;
    pthread_mutex_unlock(&g_lock);
    return a;
}

bool header_corroboration_hold_get(struct header_corroboration_hold *out)
{
    if (!out)
        return false;
    memset(out, 0, sizeof(*out));
    pthread_mutex_lock(&g_lock);
    bool a = g_hold.active;
    if (a) {
        out->active           = true;
        out->fork_height      = g_hold.fork_height;
        out->candidate_height = g_hold.candidate_height;
        out->current_height   = g_hold.current_height;
        out->switch_depth     = g_hold.switch_depth;
        out->raised_unix      = g_hold.raised_unix;
        memcpy(out->work_delta_hex, g_hold.work_delta_hex,
               sizeof(out->work_delta_hex));
        memcpy(out->candidate_tip_hex, g_hold.candidate_tip_hex,
               sizeof(out->candidate_tip_hex));
        memcpy(out->peer_name, g_hold.peer_name, sizeof(out->peer_name));
    }
    pthread_mutex_unlock(&g_lock);
    return a;
}

/* Clear a stale hold: the held candidate is no longer strictly better than the
 * (advanced) current best header — the switch has been abandoned or absorbed. */
static void hold_maybe_clear_stale(const struct block_index *current)
{
    pthread_mutex_lock(&g_lock);
    if (g_hold.active && current) {
        bool still_better = candidate_strictly_better_work(
            &g_hold.candidate_work, g_hold.candidate_height,
            &current->nChainWork, current->nHeight);
        if (!still_better)
            hold_clear_locked();
    }
    pthread_mutex_unlock(&g_lock);
}

/* Clear the hold iff it names exactly `candidate` (a resolved switch). */
static void hold_clear_if_matches(const struct block_index *candidate)
{
    if (!candidate || !candidate->phashBlock)
        return;
    pthread_mutex_lock(&g_lock);
    if (g_hold.active && uint256_eq(&g_hold.candidate_tip, candidate->phashBlock))
        hold_clear_locked();
    pthread_mutex_unlock(&g_lock);
}

static void hold_set(const struct block_index *current,
                     const struct block_index *candidate,
                     const struct block_index *fork,
                     int switch_depth,
                     const char *peer_name)
{
    struct arith_uint256 delta;
    if (arith_uint256_compare(&candidate->nChainWork, &current->nChainWork) > 0)
        arith_uint256_sub(&delta, &candidate->nChainWork, &current->nChainWork);
    else
        memset(&delta, 0, sizeof(delta));

    pthread_mutex_lock(&g_lock);
    /* Preserve the original raise time when refreshing the same held tip. */
    bool same = g_hold.active && candidate->phashBlock &&
                uint256_eq(&g_hold.candidate_tip, candidate->phashBlock);
    int64_t raised = same ? g_hold.raised_unix : platform_time_wall_unix();

    memset(&g_hold, 0, sizeof(g_hold));
    g_hold.active           = true;
    g_hold.fork_height      = fork->nHeight;
    g_hold.candidate_height = candidate->nHeight;
    g_hold.current_height   = current->nHeight;
    g_hold.switch_depth     = switch_depth;
    g_hold.candidate_work   = candidate->nChainWork;
    g_hold.raised_unix      = raised;
    arith_uint256_get_hex(&delta, g_hold.work_delta_hex);
    if (candidate->phashBlock) {
        g_hold.candidate_tip = *candidate->phashBlock;
        uint256_get_hex(candidate->phashBlock, g_hold.candidate_tip_hex);
    }
    if (peer_name) {
        strncpy(g_hold.peer_name, peer_name, sizeof(g_hold.peer_name) - 1);
        g_hold.peer_name[sizeof(g_hold.peer_name) - 1] = '\0';
    }
    pthread_mutex_unlock(&g_lock);
}

/* ── The gate ────────────────────────────────────────────────────────── */

enum header_corroboration_gate header_corroboration_gate_switch(
    const struct block_index *current,
    const struct block_index *candidate,
    int checkpoint_last_height,
    const unsigned char *peer_group, size_t peer_group_len,
    const char *peer_name)
{
    (void)peer_group;
    (void)peer_group_len;

    if (!header_corroboration_enabled())
        return HEADER_CORROBORATION_ALLOW;
    if (!candidate)
        return HEADER_CORROBORATION_ALLOW;

    /* A prior hold may have gone stale as the honest chain advanced. */
    hold_maybe_clear_stale(current);

    if (!current || candidate == current)
        return HEADER_CORROBORATION_ALLOW;

    /* Only a candidate we would actually adopt can be a dangerous switch. */
    if (!candidate_strictly_better(candidate, current))
        return HEADER_CORROBORATION_ALLOW;

    const struct block_index *fork = last_common_ancestor(current, candidate);
    if (!fork || fork == current)
        return HEADER_CORROBORATION_ALLOW;   /* extension or unclassifiable */

    int switch_depth = current->nHeight - fork->nHeight;
    if (switch_depth <= HEADER_CORROBORATION_MIN_SWITCH_DEPTH)
        return HEADER_CORROBORATION_ALLOW;   /* normal shallow competing tip */

    if (fork->nHeight <= checkpoint_last_height)
        return HEADER_CORROBORATION_ALLOW;   /* checkpoint already stronger */

    if (branch_corroborated(candidate, fork)) {
        hold_clear_if_matches(candidate);
        return HEADER_CORROBORATION_ALLOW;
    }

    hold_set(current, candidate, fork, switch_depth, peer_name);
    LOG_WARN("net",
             "header_corroboration: HOLD un-corroborated switch fork_h=%d "
             "depth=%d cand_h=%d peer=%s",
             fork->nHeight, switch_depth, candidate->nHeight,
             peer_name ? peer_name : "?");
    return HEADER_CORROBORATION_HOLD;
}

#ifdef ZCL_TESTING
void header_corroboration_test_reset(void)
{
    pthread_mutex_lock(&g_lock);
    memset(g_slots, 0, sizeof(g_slots));
    hold_clear_locked();
    pthread_mutex_unlock(&g_lock);
    /* Deterministic in tests: skip the /proc cmdline scan, force enabled. */
    atomic_store(&g_init_done, true);
    atomic_store(&g_enabled, true);
}
#endif
