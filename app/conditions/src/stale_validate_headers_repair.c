/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "framework/condition.h"

#include "config/runtime.h"
#include "jobs/reducer_frontier.h"
#include "jobs/block_header_emit.h"
#include "jobs/stage_repair.h"
#include "services/header_probe.h"
#include "services/sync_monitor.h"
#include "net/connman.h"
#include "net/header_serve_repair.h"
#include "platform/time_compat.h"
#include "storage/progress_store.h"
#include "util/blocker.h"
#include "util/log_macros.h"
#include "support/log_throttle.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"

#include <sqlite3.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <limits.h>
#include <stdio.h>

static _Atomic int g_target_at_detect = -1;
static _Atomic int g_hstar_at_detect = -1;
static _Atomic int g_remedy_calls = 0;
static _Atomic int g_mode_at_detect = STAGE_REPAIR_POISON_NONE;

/* Detective A2 — which source (oracle vs P2P) the in-flight repair attempt last
 * fired, so the completion tick can attribute the served repair. The oracle
 * pull is synchronous (attributed inline), the P2P getdata is async (its
 * solution appears on a later tick and is attributed there). Reset when the
 * episode target changes (detect) or on test reset. */
static _Atomic int g_repair_pending_source = HEADER_PROBE_SRC_NONE;

/* De-storm the remedy's recurring "deferring" WARN: the condition re-arms on
 * cooldown forever (cooldown_max_rearms=0) while a missing-input episode
 * persists, so an unthrottled WARN here is a co-mechanism of the log storm.
 * Keyed on (target,peers-available) — a genuinely-new episode re-emits, a
 * stuck repeat collapses to first-fire + 60 s keepalive. */
static struct log_throttle g_stale_repair_defer_log = LOG_THROTTLE_INIT;

/* Typed blocker id: names the missing input when NEITHER the oracle NOR any
 * peer can serve the header-solution repair. TRANSIENT class — the Condition's
 * unbounded cooldown re-arm (cooldown_secs>0, cooldown_max_rearms=0) governs
 * retry, so this never latches into a human dead-end on a recoverable cause. */
#define STALE_HEADER_NO_SOURCE_BLOCKER_ID "header_repair_no_source"

/* ── Lane B3: bounded runtime poisoned-`blocks`-row escalation ────────────────
 * The refetch-only ladder above can NEVER win when the DURABLE `blocks` row at
 * the frontier is itself poisoned: each attempt re-fetches a body, overwrites
 * the header_solution side-table, but leaves the poisoned durable row in place,
 * so the same poison re-hits forever. At ladder EXHAUSTION (the attempt that
 * reaches max_attempts) we escalate ONCE to stage_repair_quarantine_blocks_row,
 * which purges the durable row IFF it fails the frozen block_row_verify. The
 * escalation fires AT MOST ONCE per target height per process: a fixed
 * remembered-height set gates re-fire, so a second exhaustion at the same height
 * falls through to the existing operator page (never a delete loop). The
 * remembered set is process-scoped (survives condition cooldown re-arms; cleared
 * only by test_reset). */
#define RUNTIME_QUARANTINE_FIRED_MAX 64
static _Atomic int g_runtime_quarantine_fired[RUNTIME_QUARANTINE_FIRED_MAX];
static _Atomic int g_runtime_quarantine_fired_count = 0;
/* Test observability: count of quarantine ESCALATIONS actually invoked (the
 * helper was called), independent of node_db availability. */
static _Atomic int g_runtime_quarantine_escalations = 0;

#ifdef ZCL_TESTING
/* Test-only node_db override so a hermetic fixture can inject a seeded handle
 * (production wiring is app_runtime_node_db()). NULL => use the runtime handle. */
static struct node_db *g_test_node_db;
void stale_validate_headers_repair_test_set_node_db(struct node_db *ndb);
void stale_validate_headers_repair_test_set_node_db(struct node_db *ndb)
{
    g_test_node_db = ndb;
}
int stale_validate_headers_repair_test_quarantine_escalations(void);
int stale_validate_headers_repair_test_quarantine_escalations(void)
{
    return atomic_load(&g_runtime_quarantine_escalations);
}
#endif

static struct node_db *runtime_row_quarantine_node_db(void)
{
#ifdef ZCL_TESTING
    if (g_test_node_db)
        return g_test_node_db;
#endif
    return app_runtime_node_db();
}

static bool runtime_quarantine_already_fired(int height)
{
    int n = atomic_load(&g_runtime_quarantine_fired_count);
    if (n > RUNTIME_QUARANTINE_FIRED_MAX)
        n = RUNTIME_QUARANTINE_FIRED_MAX;
    for (int i = 0; i < n; i++)
        if (atomic_load(&g_runtime_quarantine_fired[i]) == height)
            return true;
    return false;
}

static void runtime_quarantine_mark_fired(int height)
{
    /* Single-threaded (condition-engine tick), but atomic to match the file. */
    int idx = atomic_fetch_add(&g_runtime_quarantine_fired_count, 1);
    if (idx < RUNTIME_QUARANTINE_FIRED_MAX)
        atomic_store(&g_runtime_quarantine_fired[idx], height);
    /* else: set full (>64 distinct runtime quarantines this process) — the
     * per-episode operator page remains the terminal backstop. */
}

/* True on the remedy attempt that will REACH max_attempts. condition.c
 * increments attempts AFTER the remedy returns, so the current attempt number is
 * snap.attempts + 1; exhaustion is when that reaches max_attempts. Read via the
 * public snapshot API (no recursive registry lock — remedy runs outside it). */
static bool runtime_quarantine_escalation_due(void)
{
    struct condition_runtime_snapshot snap;
    if (!condition_engine_get_registered_snapshot(
            "stale_validate_headers_repair", &snap))
        return false;
    int max = snap.max_attempts > 0 ? snap.max_attempts : 1;
    return snap.attempts + 1 >= max;
}

#ifdef ZCL_TESTING
/* Test-only override of the connected-peer count seen by the P2P fallback, so
 * a hermetic fixture can exercise both the peers-available and the
 * missing-input (0 peers) branches without wiring the net stack. -1 = use the
 * real connman via sync_monitor_connman(). */
static _Atomic int g_test_peer_count_override = -1;
void stale_validate_headers_repair_test_set_peer_count(int n);
void stale_validate_headers_repair_test_set_peer_count(int n)
{
    atomic_store(&g_test_peer_count_override, n);
}
#endif

/* LANE D / #3b + Detective A2 — file-scope forward declaration; defined after
 * the remedy. Oracle-independent P2P re-fetch of the exact best-header
 * ancestor at `height`: arms the existing bounded header-only getheaders
 * repair first, then clears BLOCK_HAVE_DATA on that hash-bound block_index
 * entry and actively enqueues a full-block getdata as the durable fallback.
 * Returns the count of connected peers available to serve the re-fetch (0 =>
 * missing input), or -1 if the best-header authority is absent or no longer
 * agrees with `expected_hash`. */
static int cure_request_peer_refetch(int height,
                                     const struct uint256 *expected_hash);

/* Resolve the same authoritative chain identity used by the normal
 * best-header body queue. A target above the visible active tip is eligible
 * only when its best-header parent is that visible tip; a target within the
 * active window must be the exact active block. This keeps repair fail-closed
 * across concurrent reorg/header publication boundaries. */
static bool best_header_target_hash(struct main_state *ms, int height,
                                    struct uint256 *out_hash);

/* Connected-peer count, the single reader both the re-fetch and the refusal
 * text use so the two can never disagree about how many peers were there. */
static int connected_peer_count(void);

/* Lane B3 — bounded, once-per-height escalation (defined after the remedy). */
static void maybe_escalate_runtime_row_quarantine(
    int target, const struct uint256 *canon, struct main_state *ms);

/* Name the refusal for the cause that actually held, not for the one that is
 * easiest to print. cure_request_peer_refetch() returns -1 when it did not even
 * ASK the network — the height has no best-header ancestor agreeing with the
 * visible active-chain identity, so there is no authoritative block_index
 * entry to clear HAVE_DATA on and no hash to getdata.
 * That -1 used to reach the caller's `peers <= 0` test and be reported as
 * "no connected peer can serve a P2P getdata re-fetch". Measured on a real
 * wiped-datadir C3 run (2026-08-20, H* pinned at 3,193,024): the node had a
 * connected peer that was serving headers the whole time and this blocker still
 * said there was none, so the recovery ladder and the operator were both sent
 * looking for peers instead of for the successor the active chain was missing.
 * A refusal that names the wrong cause is worse than an unnamed one. */
static void raise_stale_header_no_source_blocker(int height,
                                                 bool refetch_attempted,
                                                 int peers)
{
    struct blocker_record r;
    char reason[BLOCKER_REASON_MAX];
    if (!refetch_attempted)
        snprintf(reason, sizeof(reason),
                 "header-solution repair h=%d: zclassicd oracle unreachable and "
                 "h=%d has no best-header ancestor agreeing with the visible "
                 "active chain, so no P2P getdata re-fetch "
                 "was requested (%d peer(s) connected)", height, height, peers);
    else
        snprintf(reason, sizeof(reason),
                 "header-solution repair h=%d: zclassicd oracle unreachable and "
                 "no connected peer can serve a P2P getdata re-fetch", height);
    if (!blocker_init(&r, STALE_HEADER_NO_SOURCE_BLOCKER_ID, "header_probe",
                      BLOCKER_TRANSIENT, reason))
        return; // raw-return-ok:blocker-init-failed-already-logged
    (void)blocker_set(&r);
}

static void clear_stale_header_no_source_blocker(void)
{
    blocker_clear(STALE_HEADER_NO_SOURCE_BLOCKER_ID);
}

#ifdef ZCL_TESTING
static _Atomic int g_test_hstar_override = -1;

void stale_validate_headers_repair_test_set_hstar_override(int height);
void stale_validate_headers_repair_test_set_hstar_override(int height)
{
    atomic_store(&g_test_hstar_override, height);
}
#endif

static bool validate_repairable_mode(
    enum stage_repair_header_solution_poison mode)
{
    return mode == STAGE_REPAIR_POISON_VALIDATE_SOLUTIONLESS ||
           mode == STAGE_REPAIR_POISON_VALIDATE_HASH_MISMATCH;
}

static int reducer_frontier_height(sqlite3 *db)
{
    if (!db)
        return -1; // raw-return-ok:progress-db-not-open

#ifdef ZCL_TESTING
    int ov = atomic_load(&g_test_hstar_override);
    if (ov >= 0)
        return ov;
#endif

    progress_store_tx_lock();
    int32_t hstar = -1;
    int32_t served_floor = -1;
    bool ok = reducer_frontier_compute_hstar(db, &hstar, &served_floor);
    progress_store_tx_unlock();
    if (!ok)
        return -1; // raw-return-ok:hstar-read-failed
    return (int)hstar;
}

static int repair_target_height(sqlite3 *db)
{
    int scan = -1;
    bool have_scan =
        stage_repair_header_solution_repairable_validate_frontier(db, &scan) &&
        scan >= reducer_frontier_floor();

    int hstar = reducer_frontier_height(db);
    if (hstar < 0)
        return have_scan ? scan : -1; // raw-return-ok:no-repairable-frontier

    if (hstar >= INT_MAX)
        return have_scan ? scan : -1; // raw-return-ok:frontier-overflow

    int hstar_target = hstar + 1;
    if (have_scan && scan <= hstar_target)
        return scan;

    enum stage_repair_header_solution_poison hstar_mode =
        stage_repair_header_solution_poison_mode(db, hstar_target);
    if (hstar_mode != STAGE_REPAIR_POISON_NONE)
        return hstar_target;

    /* validate_headers may run far ahead of the body/fold frontier and record
     * repairable rows there. They are real future work, but they are not an
     * actionable H* repair yet: best_header_target_locked deliberately admits
     * only an active-window height or the direct child H*+1. Selecting a scan
     * above H*+1 therefore manufactures a contradiction — the remedy refuses
     * its own target as "no best-header authority", names a false no-source
     * blocker despite connected peers, and can page while H* is still climbing.
     * Rows at/below H*+1 were handled above. Leave later rows inert until the
     * frontier reaches them; the condition's next poll will re-evaluate them. */
    return -1; // raw-return-ok:no-actionable-frontier-poison
}

#ifdef ZCL_TESTING
int stale_validate_headers_repair_test_repair_target(sqlite3 *db);
int stale_validate_headers_repair_test_repair_target(sqlite3 *db)
{
    return repair_target_height(db);
}
#endif

static bool detect_stale_validate_headers_repair(void)
{
    sqlite3 *db = progress_store_db();
    if (!db)
        return false;
    int target = repair_target_height(db);
    if (target < 0)
        return false;

    enum stage_repair_header_solution_poison mode =
        stage_repair_header_solution_poison_mode(db, target);
    if (mode == STAGE_REPAIR_POISON_NONE)
        return false;

    /* A repairable validate poison stays detected until H* advances. If the
     * correct repair header is already present, the remedy below returns SKIP
     * and lets validate_headers' non-destructive recheck flip the row forward;
     * keeping detect=true makes a stuck recheck page instead of going quiet. */

    /* New episode (target moved) → forget any stale source attribution so the
     * next served solution is credited to the source THIS episode fires. */
    if (atomic_exchange(&g_target_at_detect, target) != target)
        atomic_store(&g_repair_pending_source, HEADER_PROBE_SRC_NONE);
    atomic_store(&g_hstar_at_detect, reducer_frontier_height(db));
    atomic_store(&g_mode_at_detect, (int)mode);
    return true;
}

static enum condition_remedy_result remedy_stale_validate_headers_repair(void)
{
    sqlite3 *db = progress_store_db();
    int target = atomic_load(&g_target_at_detect);
    if (!db || target < 0)
        return COND_REMEDY_SKIP;

    atomic_fetch_add(&g_remedy_calls, 1);

    enum stage_repair_header_solution_poison mode =
        stage_repair_header_solution_poison_mode(db, target);

    if (validate_repairable_mode(mode)) {
        struct main_state *ms0 = condition_engine_main_state();
        struct uint256 canon_hash;
        bool have_canon =
            best_header_target_hash(ms0, target, &canon_hash);
        const struct uint256 *canon = have_canon ? &canon_hash : NULL;
        bool solution_present = have_canon &&
            stage_repair_header_solution_available(db, target, canon);

        /* Already repaired (e.g. an async P2P getdata re-fetch fired on an
         * earlier tick has now delivered + saved the canonical solution).
         * Attribute the served repair to whichever source we last fired, then
         * DEFER to the non-destructive validate_headers recheck (see the long
         * rationale at the bottom of this block — no poison_rewind here). */
        if (solution_present) {
            int pending = atomic_exchange(&g_repair_pending_source,
                                          HEADER_PROBE_SRC_NONE);
            if (pending != HEADER_PROBE_SRC_NONE)
                header_probe_note_repair_served(
                    (enum header_probe_repair_source)pending, target);
            clear_stale_header_no_source_blocker();
            LOG_WARN("condition",
                     "[condition:stale_validate_headers_repair] "
                     "solution present h=%d source=%s — deferring to "
                     "non-destructive validate_headers recheck (no "
                     "poison_rewind)",
                     target, header_probe_repair_source_name(
                         (enum header_probe_repair_source)pending));
            return COND_REMEDY_SKIP;
        }

        /* Step 1 — ORACLE FIRST (cheap, local). header_probe_pull_range
         * re-validates the fetched header and writes it hash-bound into
         * header_solution_repair (INSERT OR REPLACE by height — it OVERWRITES
         * any stale wrong-block row, which the hash-aware availability check
         * above does not accept). */
        struct zcl_result r = have_canon
            ? header_probe_pull_range(target, 128, NULL)
            : ZCL_ERR(-1, "best-header authority unavailable h=%d", target);
        if (r.ok) {
            solution_present = stage_repair_header_solution_available(
                db, target, canon);
            if (solution_present) {
                /* Oracle served it synchronously — attribute inline. */
                atomic_store(&g_repair_pending_source, HEADER_PROBE_SRC_NONE);
                header_probe_note_repair_served(HEADER_PROBE_SRC_ORACLE, target);
                clear_stale_header_no_source_blocker();
                LOG_WARN("condition",
                         "[condition:stale_validate_headers_repair] "
                         "solution present h=%d source=oracle — deferring to "
                         "non-destructive validate_headers recheck", target);
                return COND_REMEDY_SKIP;
            }
            /* Oracle reachable but did not supply the canonical solution
             * (remote behind / missing the row) — fall through to P2P. */
        } else {
            LOG_WARN("condition",
                     "[condition:stale_validate_headers_repair] "
                     "header probe (oracle) failed h=%d code=%d msg=%s — "
                     "falling back to P2P", target, r.code, r.message);
        }

        /* Step 2 — P2P FALLBACK (oracle-independent, the zclassicd oracle is
         * being retired). Ask for the canonical HEADER first through the
         * existing bounded getheaders repair, then keep canonical full-block
         * getdata as the durable fallback. A headers message already carries
         * nSolution; downloading the whole body just to recover those bytes
         * made a snapshot node validate far ahead, log every missing solution
         * as ok=0, then crawl through the backlog in body-sized recheck bursts.
         * The header-only path hash-binds and independently verifies
         * PoW/Equihash before restoring the index bytes. The full-block path
         * still re-validates with check_block and saves hash-bound into
         * header_solution_repair. In both cases validate_headers independently
         * re-verifies before H* advances. Both arrive asynchronously, so this
         * tick fires the requests and defers. */
        int refetch = cure_request_peer_refetch(target, canon);
        /* -1 is "not asked" (best-header authority absent/disagrees), NOT
         * "zero peers".
         * Keep the two apart from here down: the peer count is read from the
         * one connman reader either way, so the refusal below can name which
         * of the two actually held. */
        bool refetch_attempted = refetch >= 0;
        int peers = refetch_attempted ? refetch : connected_peer_count();
        atomic_store(&g_repair_pending_source, HEADER_PROBE_SRC_P2P);
        header_probe_note_p2p_request(target, peers);
        /* De-storm: while the oracle is down / no peer can serve, this remedy
         * re-fires on the condition cooldown re-arm indefinitely (by design —
         * cooldown_max_rearms=0). Throttle the deferral WARN so a persistent
         * missing-input episode collapses to first-fire + 60 s keepalive keyed
         * on the (target,peers-available) fingerprint, rather than one WARN per
         * re-arm. The typed blocker (below) remains the authoritative signal. */
        /* Two bits, because the two causes are different episodes: a target
         * that goes from "not asked" to "asked but no peer" must re-emit
         * rather than be swallowed as a repeat of the previous reason. */
        uint64_t defer_key =
            ((uint64_t)(uint32_t)target << 2) |
            (uint64_t)(peers > 0 ? 2u : 0u) |
            (uint64_t)(refetch_attempted ? 1u : 0u);
        uint64_t defer_reps = 0;
        bool emit_defer = log_throttle_should_emit(
            &g_stale_repair_defer_log, defer_key, platform_time_wall_unix(),
            60, &defer_reps);
        if (!refetch_attempted || peers <= 0) {
            /* Missing input: no oracle, no peer can serve the repair right now.
             * Name it with a typed blocker and SKIP. condition.c increments
             * attempts unconditionally, but cooldown_secs>0 +
             * cooldown_max_rearms==0 re-arm the remedy forever, so this is an
             * always-terminating remedy on a recoverable cause — never a latch
             * to EV_OPERATOR_NEEDED. */
            raise_stale_header_no_source_blocker(target, refetch_attempted,
                                                 peers);
            if (emit_defer)
                LOG_WARN("condition",
                         "[condition:stale_validate_headers_repair] "
                         "no durable repair header h=%d via oracle AND %s "
                         "(peers=%d) — named blocker %s, deferring (cooldown "
                         "re-arms, no operator page) (repeats=%llu)", target,
                         refetch_attempted
                             ? "no peer can serve the re-fetch"
                             : "best-header authority is absent/disagrees so "
                               "no re-fetch was requested",
                         peers, STALE_HEADER_NO_SOURCE_BLOCKER_ID,
                         (unsigned long long)defer_reps);
        } else {
            clear_stale_header_no_source_blocker();
            if (emit_defer)
                LOG_WARN("condition",
                         "[condition:stale_validate_headers_repair] "
                         "no durable repair header h=%d via oracle — requested "
                         "P2P getdata re-fetch (peers=%d), deferring (no "
                         "operator page) (repeats=%llu)", target, peers,
                         (unsigned long long)defer_reps);
        }

        /* Lane B3 — at ladder EXHAUSTION, if the refetch-only loop has been
         * non-advancing the whole ladder, the DURABLE `blocks` row may itself
         * be poisoned; escalate ONCE per target height to purge it (evidence-
         * gated). The H*-advance witness still governs the clear; a second
         * exhaustion at the same height falls through to the operator page. */
        maybe_escalate_runtime_row_quarantine(target, canon, ms0);
        return COND_REMEDY_SKIP;
    }

    /* DOWNSTREAM_STALE: validate_headers is ok=1 but a body was skipped-invalid
     * at the frontier. There is no non-destructive heal for this, so the
     * sanctioned frontier poison_rewind is the correct tool. Its guards in
     * stage_repair_rewind.c are unchanged (frontier-only == H*+1;
     * refuses if any ok=1 success_checked row sits at/above the frontier; never
     * deletes tip_finalize_log), so the Tier-2 public-tip floor is preserved. */
    struct stage_repair_header_solution_result rr;
    int hstar = reducer_frontier_height(db);
    if (!stage_repair_header_solution_poison_rewind(db, target, hstar, &rr))
        return COND_REMEDY_FAILED;

    LOG_WARN("condition",
             "[condition:stale_validate_headers_repair] h=%d mode=%d "
             "deleted=%d rewound=%d",
             target, rr.mode, rr.deleted_rows, rr.rewound_cursors);
    return rr.repaired ? COND_REMEDY_OK : COND_REMEDY_SKIP;
}

/* LANE D / #3b + Detective A2 — oracle-independent P2P re-fetch of the
 * canonical best-header block at `height`. Three coordinated steps, all
 * through EXISTING machinery (Law: one way in — no second fetch stack):
 *   1. Arm header_serve_repair for the exact canonical entry. Its normal peer
 *      send loop requests a bounded getheaders span and its normal headers
 *      handler full-verifies each candidate before restoring nSolution.
 *   2. Drop BLOCK_HAVE_DATA on the canonical block_index entry and re-emit the
 *      header event, so the cleared re-fetch state persists across restarts
 *      (same discipline as body_persist_stage.c:requeue_body_for_refetch).
 *   3. ACTIVELY enqueue a getdata for that exact block via
 *      sync_monitor_queue_best_header_body → dl_queue_priority →
 *      the download-manager getdata loop, rather than passively waiting for a
 *      background scan to notice the cleared bit.
 * Returns the count of connected peers available to serve the re-fetch (0 =>
 * missing input; the caller names a typed blocker), or -1 if the exact
 * best-header authority is absent or changed (nothing to re-fetch — the
 * witness still governs and the next tick retries). */
static struct block_index *best_header_target_locked(struct main_state *ms,
                                                     int height)
{
    if (!ms || height < 0 || !ms->pindex_best_header ||
        height > ms->pindex_best_header->nHeight)
        return NULL;

    struct block_index *bi =
        block_index_get_ancestor(ms->pindex_best_header, height);
    if (!bi || bi->nHeight != height || !bi->phashBlock ||
        (bi->nStatus & BLOCK_FAILED_ANY_MASK))
        return NULL;

    struct block_index *visible =
        active_chain_at(&ms->chain_active, height);
    if (visible && visible != bi)
        return NULL;
    if (!visible && height > 0) {
        struct block_index *visible_parent =
            active_chain_at(&ms->chain_active, height - 1);
        if (!visible_parent || bi->pprev != visible_parent)
            return NULL;
    }
    return bi;
}

static bool best_header_target_hash(struct main_state *ms, int height,
                                    struct uint256 *out_hash)
{
    if (!ms || !out_hash || height < 0)
        return false;

    bool found = false;
    zcl_mutex_lock(&ms->cs_main);
    struct block_index *bi = best_header_target_locked(ms, height);
    if (bi) {
        *out_hash = *bi->phashBlock;
        found = true;
    }
    zcl_mutex_unlock(&ms->cs_main);
    return found;
}

static int cure_request_peer_refetch(int height,
                                     const struct uint256 *expected_hash)
{
    if (height < 0 || !expected_hash)
        return -1; // raw-return-ok:nothing-authoritative-to-refetch
    struct main_state *ms = condition_engine_main_state();
    if (!ms)
        return -1; // raw-return-ok:no-main-state

    struct block_index *bi = NULL;
    bool cleared_have_data = false;
    zcl_mutex_lock(&ms->cs_main);
    bi = best_header_target_locked(ms, height);
    if (!bi || !uint256_eq(bi->phashBlock, expected_hash)) {
        zcl_mutex_unlock(&ms->cs_main);
        return -1; // raw-return-ok:best-header-authority-changed
    }

    if (bi->nStatus & BLOCK_HAVE_DATA) {
        bi->nStatus &= ~(unsigned)BLOCK_HAVE_DATA;
        cleared_have_data = true;
    }
    zcl_mutex_unlock(&ms->cs_main);

    /* Cheap path first: the standard headers wire already carries the exact
     * Equihash solution validate_headers is missing. Arm only after the
     * best-header hash was rechecked under cs_main. block_index entries live
     * for the process lifetime, so `bi` remains stable after unlock;
     * header_serve_repair takes cs_main itself to repeat the authority check. */
    header_serve_repair_arm(ms, bi);

    if (cleared_have_data) {
        block_index_emit_header_event(bi, "stale_validate_headers_repair",
                                      NULL, NULL);
        LOG_WARN("condition",
                 "[condition:stale_validate_headers_repair] cleared HAVE_DATA "
                 "h=%d — P2P getdata will re-download canonical body", height);
    }

    /* Active getdata via the existing sync machinery. A non-ok result just
     * means the sync context is not wired yet (e.g. an isolated fixture, or
     * pre-context boot) — not an error; the next tick retries. */
    struct zcl_result qr = sync_monitor_queue_best_header_body(
        height, expected_hash, "header_repair_p2p");
    if (!qr.ok)
        LOG_WARN("condition",
                 "[condition:stale_validate_headers_repair] P2P body queue "
                 "h=%d not accepted (code=%d msg=%s) — sync context may be "
                 "unset; retrying next tick", height, qr.code, qr.message);

    /* A concurrent best-header change invalidates the exact plan. Refuse this
     * attempt; the next condition tick resolves and reviews the new authority
     * instead of reporting that a different hash was requested. */
    if (qr.code == -3 || qr.code == -6)
        return -1; // raw-return-ok:best-header-authority-changed-during-queue

    /* Connected-peer count = whether P2P can serve the re-fetch at all. */
    return connected_peer_count();
}

static int connected_peer_count(void)
{
    int peers = 0;
    struct connman *cm = sync_monitor_connman();
    if (cm)
        peers = (int)connman_get_node_count(cm);
#ifdef ZCL_TESTING
    int ov = atomic_load(&g_test_peer_count_override);
    if (ov >= 0)
        peers = ov;
#endif
    return peers;
}

/* Lane B3 — bounded runtime poisoned-`blocks`-row escalation. Fires ONLY at
 * ladder exhaustion (runtime_quarantine_escalation_due) and AT MOST ONCE per
 * target height per process (runtime_quarantine_*_fired set). Requires the
 * canonical hash (a frontier row to address) and a node_db handle. The purge
 * itself is evidence-gated inside stage_repair_quarantine_blocks_row — a row
 * that verifies OK is refused there, so this is safe to call whenever exhausted;
 * the once-per-height gate only bounds the delete/refuse ATTEMPTS. */
static void maybe_escalate_runtime_row_quarantine(
    int target, const struct uint256 *canon, struct main_state *ms)
{
    if (!canon || target < 0)
        return;
    if (!runtime_quarantine_escalation_due())
        return;
    if (runtime_quarantine_already_fired(target))
        return;

    /* Mark BEFORE the attempt so a second exhaustion at this height can never
     * re-enter — one attempt per height, whatever its outcome. */
    runtime_quarantine_mark_fired(target);
    atomic_fetch_add(&g_runtime_quarantine_escalations, 1);

    struct node_db *ndb = runtime_row_quarantine_node_db();
    if (!ndb) {
        LOG_WARN("condition",
                 "[condition:stale_validate_headers_repair] runtime row "
                 "quarantine escalation h=%d: no node_db handle — skipped "
                 "(refetch ladder + operator page remain)", target);
        return;
    }

    struct stage_repair_row_quarantine_result qr;
    bool purged = stage_repair_quarantine_blocks_row(
        ndb, ms, (int64_t)target, canon, &qr);
    if (purged)
        LOG_WARN("condition",
                 "[condition:stale_validate_headers_repair] EXHAUSTION h=%d: "
                 "purged poisoned durable `blocks` row (verdict=%d) — header "
                 "sync + body_fetch will re-request a clean body", target,
                 qr.verdict);
    else
        LOG_WARN("condition",
                 "[condition:stale_validate_headers_repair] EXHAUSTION h=%d: "
                 "runtime row quarantine did NOT purge (attempted=%d "
                 "refused_clean=%d row_absent=%d no_params=%d verdict=%d) — "
                 "operator page remains the backstop", target, qr.attempted,
                 qr.refused_clean, qr.row_absent, qr.no_params, qr.verdict);
}

static bool witness_stale_validate_headers_repair(int64_t target_at_detect)
{
    /* The engine passes a wall-clock TIMESTAMP here (condition.c stores
     * `now` into target_at_detect), NOT a height — ignore it and read our
     * own captured frontier height. */
    (void)target_at_detect;

    /* A validate-header poison has a narrower honest success predicate than a
     * downstream poison: its exact failed row must have been replaced by the
     * unchanged validate_headers verifier. This condition's validate-mode
     * remedy never deletes or rewinds that row; merely receiving/caching a
     * repair header also leaves its poison mode unchanged. Therefore a
     * transition from the captured validate poison to NONE is durable evidence
     * that the independent recheck accepted it, and this condition must clear
     * even when a DIFFERENT downstream stage still holds H*. Otherwise the
     * already-repaired header condition keeps spending attempts and falsely
     * pages itself for the downstream stall.
     *
     * DOWNSTREAM_STALE remains governed solely by reducer-frontier movement.
     * Its remedy is destructive and can delete poison rows without moving the
     * tip, so row disappearance cannot self-certify success there. The H*
     * witness below preserves the Law-7 guard: a non-advancing downstream
     * remedy accrues attempts and pages. */
    int target = atomic_load(&g_target_at_detect);
    if (target < 0)
        return false;

    sqlite3 *db = progress_store_db();
    if (!db)
        return false;

    enum stage_repair_header_solution_poison mode_at_detect =
        (enum stage_repair_header_solution_poison)
            atomic_load(&g_mode_at_detect);
    if (validate_repairable_mode(mode_at_detect) &&
        stage_repair_header_solution_poison_mode(db, target) ==
            STAGE_REPAIR_POISON_NONE)
        return true;

    int hstar_at_detect = atomic_load(&g_hstar_at_detect);
    if (hstar_at_detect >= 0 && target <= hstar_at_detect) {
        return stage_repair_header_solution_poison_mode(db, target) ==
               STAGE_REPAIR_POISON_NONE;
    }

#ifdef ZCL_TESTING
    int ov = atomic_load(&g_test_hstar_override);
    if (ov >= 0)
        return ov >= target;
#endif

    progress_store_tx_lock();
    int32_t hstar_now = -1;
    int32_t served_floor = -1;
    bool ok = reducer_frontier_compute_hstar(db, &hstar_now, &served_floor);
    progress_store_tx_unlock();
    return ok && hstar_now >= target;
}

static struct condition c_stale_validate_headers_repair = {
    .name = "stale_validate_headers_repair",
    .severity = COND_CRITICAL,
    .poll_secs = 5,
    .backoff_secs = 30,
    /* Finite fast ladder: 5 un-witnessed remedies page a human once per
     * episode (the honest-witness escalation the W2 tests pin). */
    .max_attempts = 5,
    /* Continue-with-cooldown (sticky-node plan #7), routed for LANE D / #3b.
     * The repair frontier can be solutionless purely because an EXTERNAL
     * dependency is absent (the zclassicd oracle is unreachable / a peer is
     * forging the header page). In that case the remedy's oracle-independent
     * fallback (cure_request_peer_refetch + COND_REMEDY_SKIP) still accrues an
     * attempt — condition.c:321 increments attempts UNCONDITIONALLY regardless
     * of result, so SKIP does NOT avoid the ladder — and would otherwise trip
     * max_attempts and LATCH FOREVER at EV_OPERATOR_NEEDED (condition.c:259 +
     * :353). That is a human dead-end on a RECOVERABLE class. With
     * cooldown_secs > 0 the engine re-arms the remedy every 10 minutes after the
     * page, UNBOUNDED (cooldown_max_rearms = 0), so an oracle-absent /
     * forged-page stall keeps retrying the P2P re-fetch forever and can NEVER
     * permanently give up healing on a recoverable cause. The episode resets
     * (fresh ladder) the instant the fault identity (target_at_detect) moves or
     * detect() goes false; the single per-episode page still fires once at
     * max_attempts so a human is informed. */
    .cooldown_secs = 600,
    .cooldown_max_rearms = 0,
    .detect = detect_stale_validate_headers_repair,
    .remedy = remedy_stale_validate_headers_repair,
    .witness = witness_stale_validate_headers_repair,
    .witness_window_secs = 60,
};

void register_stale_validate_headers_repair(void)
{
    (void)condition_register(&c_stale_validate_headers_repair);
}

#ifdef ZCL_TESTING
void stale_validate_headers_repair_test_reset(void)
{
    struct condition_state *s = &c_stale_validate_headers_repair.state;
    atomic_store(&g_target_at_detect, -1);
    atomic_store(&g_hstar_at_detect, -1);
    atomic_store(&g_remedy_calls, 0);
    atomic_store(&g_mode_at_detect, STAGE_REPAIR_POISON_NONE);
    atomic_store(&g_repair_pending_source, HEADER_PROBE_SRC_NONE);
    /* Lane B3: drop the per-process quarantine bookkeeping so a fresh fixture
     * starts with an empty remembered-height set. (In production this set is
     * deliberately process-scoped — it survives condition cooldown re-arms.) */
    atomic_store(&g_runtime_quarantine_fired_count, 0);
    atomic_store(&g_runtime_quarantine_escalations, 0);
#ifdef ZCL_TESTING
    atomic_store(&g_test_hstar_override, -1);
    atomic_store(&g_test_peer_count_override, -1);
    g_test_node_db = NULL;
#endif
    clear_stale_header_no_source_blocker();
    log_throttle_reset(&g_stale_repair_defer_log);
    condition_reset_state(&c_stale_validate_headers_repair);
    /* Zero last_remedy_unix so condition_due_for_remedy treats the next tick
     * as due (last==0 bypasses the wall-clock backoff). There is no
     * injectable clock; the escalation test re-zeros this between ticks to
     * drive successive remedy attempts within the same wall-second. */
    atomic_store(&s->last_remedy_unix, (int64_t)0);
    atomic_store(&s->last_operator_needed_unix, (int64_t)0);
}

/* Test-only: clear last_remedy_unix between ticks so the next remedy is due
 * despite backoff_secs (no injectable clock — see test_reset). */
void stale_validate_headers_repair_test_clear_backoff(void);
void stale_validate_headers_repair_test_clear_backoff(void)
{
    struct condition_state *s = &c_stale_validate_headers_repair.state;
    atomic_store(&s->last_remedy_unix, (int64_t)0);
}

int stale_validate_headers_repair_test_remedy_calls(void)
{
    return atomic_load(&g_remedy_calls);
}
#endif
