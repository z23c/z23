/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * validate_headers_stage — implementation. See validate_headers_stage.h.
 *
 * Single-process singleton. Validates header_admit_log output via a
 * pthread pool (VH_POOL_SIZE workers on a normal live node; wider only
 * under a catch-up/fold gate — see validate_headers_tuning.c) and a
 * per-step bounded batch. The pool stays warm for the lifetime of the
 * stage, re-sized between steps by vh_pool_sync_width() on a gate
 * transition; each step submits up to VH_BATCH_SIZE jobs, awaits them
 * all, and writes the batch + cursor bump atomically. */

#include "platform/time_compat.h"
#include "jobs/validate_headers_stage.h"
#include "jobs/stage_helpers.h"
#include "jobs/stage_db_fault.h"
#include "jobs/stage_repair.h"
#include "jobs/stage_repair_internal.h"  /* STAGE_REPAIR_SOLUTIONLESS_REASON */
#include "validate_headers_internal.h"
#include "validate_headers_pool.h"
#include "jobs/header_admit_stage.h"
#include "validate_headers_log_store.h"

#include "chain/chain.h"
#include "core/uint256.h"
#include "json/json.h"
#include "primitives/block.h"
#include "storage/progress_store.h"
#include "storage/txdb.h"
#include "util/blocker.h"
#include "util/log_macros.h"
#include "support/log_throttle.h"
#include "util/stage.h"
#include "util/util.h"
#include "validation/chainstate.h"
#include "validation/check_block.h"
#include "validation/main_state.h"

#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define STAGE_NAME       "validate_headers"
#define VH_WINDOW_MISS_BLOCKER_ID "validate_headers.window_resolve_miss"
/* Raised when the UNCHANGED PoW+Equihash validator PASSES a header but the
 * block_index entry is BLOCK_FAILED-masked and the stale mask cannot be
 * cleared here (no repairable evidence). Root cause: the getheaders serve
 * path (core/modules/net/src/msg_headers.c) sets BLOCK_FAILED_VALID when its local index
 * copy of a header has a missing/corrupt Equihash solution ("invalid-solution",
 * classified permanent); that mask persists across boots via block_index_cache
 * and mark_valid_header refuses any FAILED-masked entry forever. A
 * throttled blocker + JOB_IDLE backoff keeps that from becoming a
 * WARN/JOB_FATAL hot loop. */
#define VH_MARK_FAIL_BLOCKER_ID "validate_headers.mark_failed"

/* The default header validator (PoW target + Equihash-from-nSolution)
 * lives in validate_headers_validator.c — see validate_headers_internal.h. */

/* struct vh_job — the per-height work item — lives in validate_headers_pool.h
 * with the pool that stores and dispatches it. */

/* ── Globals ──────────────────────────────────────────────────────── */

static pthread_mutex_t  g_lock = PTHREAD_MUTEX_INITIALIZER;
static struct main_state *g_ms = NULL;
static stage_t          *g_stage = NULL;
static struct vh_pool    g_pool;   /* also owns the per-step vh_job scratch */

static _Atomic uint64_t g_passed_total = 0;
static _Atomic uint64_t g_failed_total = 0;
static _Atomic int64_t  g_last_step_unix = 0;
static _Atomic int64_t  g_last_blocked_unix = 0;
static _Atomic int64_t  g_failure_recheck_cursor = 0;
static _Atomic int64_t  g_last_recheck_frontier = -1;
static _Atomic int64_t  g_last_recheck_start = -1;
static _Atomic int64_t  g_last_recheck_selected = 0;

/* Mark-failure throttle (deliverable a), standardized on the shared
 * log_throttle primitive (support/log_throttle.h) rather than a bespoke streak
 * counter: only the FIRST refusal of a streak (keyed on height+nStatus) emits
 * a WARN + raises the typed blocker; same-key repeats collapse to a 60 s
 * keep-alive so the condition stays visible without storming (this is the
 * exact site that stormed 18,440 WARN lines at h=3,179,245). The next clean
 * mark logs one recovery line, gated on the typed blocker still being set
 * (vh_mark_fail_recover). Both mark sites hold progress_store_tx_lock (the
 * serial reducer drive); log_throttle's own atomics make it safe regardless.
 * g_mark_fail_warn_total is the atomic rising-edge WARN counter (test hook,
 * incremented only on an actual emit). */
static struct log_throttle g_mark_fail_throttle = LOG_THROTTLE_INIT;
static _Atomic int64_t  g_mark_fail_warn_total = 0;

/* Infra-db fault ladder (R5). A momentary sqlite glitch (busy/locked/transient
 * IO) must NOT be a dead JOB_FATAL: a transient fault holds the cursor and
 * retries (JOB_IDLE), a persistent/permanent one routes to the bounded
 * auto-reindex. Reset on every advancing step. NEVER used for a validity
 * verdict — those advance the cursor with an ok=0/ok=1 row. */
static struct stage_db_fault g_vh_db_fault;

/* Shared by both call sites: neither authority resolves a block_index entry
 * — a concurrent reorg is conceivable. JOB_IDLE, never JOB_BLOCKED. */
static void vh_window_miss_note(int height, const char *context)
{
    char reason[BLOCKER_REASON_MAX];
    snprintf(reason, sizeof(reason),
             "height=%d (%s): neither the finalized window nor the "
             "best-header frontier resolves a block_index entry; holding "
             "until the active chain settles", height, context);
    struct blocker_record rec;
    if (blocker_init(&rec, VH_WINDOW_MISS_BLOCKER_ID, STAGE_NAME,
                     BLOCKER_TRANSIENT, reason))
        blocker_set(&rec);
}

/* Injectable validator. Default = full PoW + Equihash from disk.
 * Tests set this via validate_headers_stage_set_validator(). Reset to
 * default on shutdown. */
static vh_validator_fn g_validator      = NULL;
static void           *g_validator_user = NULL;
/* Datadir cached at init for the workers (g_validator may need it). */
static char            g_datadir[2048] = {0};

/* Map a sqlite failure inside the step body to the result the step must return.
 * `rc` is the sqlite (extended) code captured AT the failing call. Returns
 * JOB_IDLE (transient, within budget — cursor held, supervisor re-ticks) or
 * JOB_FATAL (persistent/permanent — a bounded auto-reindex was requested). */
static job_result_t vh_db_fault(int rc, int height, const char *ctx)
{
    return stage_db_fault_result(&g_vh_db_fault, rc, g_datadir,
                                 (int32_t)height, ctx);
}

/* A validate_headers failure is REPAIRABLE — worth keeping in the recheck
 * window until it can be re-validated — ONLY when it failed for lack of a
 * backfillable Equihash solution (STAGE_REPAIR_SOLUTIONLESS_REASON, the exact
 * reason the live tip-wedge produced: the header is canonical but its solution
 * had not yet been backfilled when the forward drain first reached it).
 * recheck_failed_rows retries these until backfill_header_solutions supplies
 * the solution and the unchanged PoW+Equihash validator flips the row to ok=1.
 *
 * A TERMINAL failure (high-hash / invalid-solution / version-too-low / a test
 * stub) will never pass, so the recheck floor must ADVANCE past it — never pin
 * — or recheck would re-run the validator on a permanently-bad header every
 * tick. Restricting the pin to repairable rows is what keeps the floor's
 * forward-progress behavior identical to before for genuine rejections. */
static inline bool vh_failure_is_repairable(const char *reason)
{
    return reason &&
           strcmp(reason, STAGE_REPAIR_SOLUTIONLESS_REASON) == 0;
}

static inline bool vh_failure_is_recheck_candidate(const char *reason)
{
    return reason &&
           (strcmp(reason, STAGE_REPAIR_SOLUTIONLESS_REASON) == 0 ||
            strcmp(reason, "header-source-hash-mismatch") == 0);
}

/* ── Worker pool ──────────────────────────────────────────────────── */

static void vh_run_job(void *jobp, void *user)
{
    (void)user;
    struct vh_job *job = jobp;
    /* Snapshot validator under no lock — it can only change via
     * shutdown which joins workers first. */
    job->reason[0] = 0;
    job->ok = g_validator(job->bi, g_datadir,
                          job->reason, sizeof(job->reason),
                          g_validator_user);
}

/* Reconcile the live pool width with vh_runtime_pool_size() /
 * vh_runtime_batch_size(). Called once per step from step_once. A no-op
 * compare while the gate state is unchanged (the hot path); on a
 * catch-up/fold transition edge it stops and restarts the pool at the new
 * width.
 *
 * Race/deadlock safety: this runs on the stage drive thread — the ONLY
 * thread that ever calls vh_pool_run_batch — and only BETWEEN batches, so
 * the workers being joined are idle-blocked on cv_take holding no locks.
 * In the batched drain, STAGE_DRAIN_IMPL already holds
 * progress_store_tx_lock across the whole step loop, so the join happens
 * under that lock — safe because workers never acquire it (when busy they
 * run under the drive's tx lock today) and pool->mu is never held while
 * taking it (no lock-order cycle). shutdown() joins the same pool after
 * the supervisor stops ticking, exactly as it did when the width was
 * fixed. The resize is all-or-nothing: if the new width fails to start,
 * fall back to the compile-time defaults so the pool is never left dead
 * (a dead pool would make vh_pool_run_batch a silent no-op and steps
 * would mis-write ok=0 rows); if even the fallback cannot start, return
 * false and the stage idles with its cursor held. */
static bool vh_pool_sync_width(void)
{
    if (!g_pool.inited)
        return false;
    int want_pool  = vh_runtime_pool_size();
    int want_batch = vh_runtime_batch_size();
    if (want_pool == g_pool.n_threads && want_batch == g_pool.batch_cap)
        return true;

    int prev_pool  = g_pool.n_threads;
    int prev_batch = g_pool.batch_cap;
    vh_pool_stop(&g_pool);
    if (!vh_pool_start(&g_pool, vh_run_job, NULL, want_pool, want_batch) &&
        !vh_pool_start(&g_pool, vh_run_job, NULL, VH_POOL_SIZE,
                       VH_BATCH_SIZE))
        LOG_FAIL("validate_headers",
                 "pool resize %d/%d -> %d/%d failed and the %d/%d fallback "
                 "would not start; stage idles with cursor held",
                 prev_pool, prev_batch, want_pool, want_batch,
                 VH_POOL_SIZE, VH_BATCH_SIZE);
    LOG_INFO("validate_headers",
             "[validate_headers] pool resized %d/%d -> %d/%d "
             "(catch-up/fold gate transition; per-header validation "
             "unchanged)", prev_pool, prev_batch, g_pool.n_threads,
             g_pool.batch_cap);
    return true;
}

/* ── Schema + log writes ──────────────────────────────────────────────
 * validate_headers_log schema + insert live in validate_headers_log_store.c
 * (pure sqlite kernel helpers below the AR layer). This stage owns only the
 * vh_job → primitive binding at the call sites. */

static bool mark_valid_header(struct block_index *bi);
/* Mark a passing header valid, healing a stale serve-path FAILED mask when the
 * failure is the repairable serve-refusal class (`clearable`). Defined below
 * mark_valid_header; forward-declared here for recheck_failed_rows. */
static bool vh_authoritative_mark(struct vh_job *job, bool clearable);
static void vh_mark_fail_note(int height, const struct block_index *bi);

/* Resolve the block_index at height `h`, including the live frontier ONE
 * (or more) above the finalized active-chain window.
 *
 * active_chain_at is a finalized-window accessor: it returns NULL for any
 * height above c->height (chainstate.c). That is by design and MUST stay
 * that way — every other reader depends on its finalized-window contract,
 * so we never "fix" it to peek the map. Instead, when the window does not
 * cover `h`, reach the canonical header via the block_map (pprev/pskip)
 * up to the best-header frontier. This only changes HOW bi is found; the
 * resolved bi still flows through the SAME validator (PoW + Equihash) and
 * is never marked valid without that verdict. No window extend (the
 * window-extend machinery is the tip_finalize oscillator we must not
 * poke) and no array-bound dependence. */
static struct block_index *vh_resolve_bi(struct main_state *ms, int h)
{
    if (!ms)
        return NULL;
    struct block_index *bi = active_chain_at(&ms->chain_active, h);
    if (bi)
        return bi;
    if (ms->pindex_best_header && h <= ms->pindex_best_header->nHeight)
        return block_index_get_ancestor(ms->pindex_best_header, h);
    return NULL;
}

static void vh_job_bind_block(sqlite3 *db, struct vh_job *job,
                              struct block_index *bi, int height)
{
    job->bi = bi;
    job->mark_bi = bi;
    job->height = height;

    if (!db || !bi || !bi->phashBlock)
        return;

    struct block_header repaired;
    if (!stage_repair_header_solution_load(db, height, bi->phashBlock,
                                           &repaired))
        return;

    /* A hash-bound repair row exists: the header went through the solutionless
     * header-solution backfill path (header_probe / stale-validate Condition),
     * the exact fingerprint of the serve-refusal FAILED-mask class. Recorded so
     * the forward mark path may clear a stale mask only with this proof. */
    job->had_repair_row = true;
    job->snapshot = *bi;
    job->snapshot.nVersion = repaired.nVersion;
    job->snapshot.hashMerkleRoot = repaired.hashMerkleRoot;
    job->snapshot.hashFinalSaplingRoot = repaired.hashFinalSaplingRoot;
    job->snapshot.nTime = repaired.nTime;
    job->snapshot.nBits = repaired.nBits;
    job->snapshot.nNonce = repaired.nNonce;
    memcpy(job->solution, repaired.nSolution, repaired.nSolutionSize);
    job->snapshot.nSolution = job->solution;
    job->snapshot.nSolutionSize = repaired.nSolutionSize;
    job->bi = &job->snapshot;
}

/* Undo the recheck's write transaction. Batched (an outer stage_batch txn is
 * open): ROLLBACK TO then RELEASE the savepoint — undo only this recheck's
 * writes while leaving the outer batch (and any earlier advanced blocks in it)
 * open and the savepoint name free. Standalone: plain ROLLBACK of our own txn.
 * Mirrors stage_step_rollback in platform/modules/util/src/stage.c. Best-effort. */
static void vh_recheck_rollback(sqlite3 *db, bool batched)
{
    if (batched) {
        sqlite3_exec(db, "ROLLBACK TO SAVEPOINT vh_recheck", NULL, NULL, NULL);
        sqlite3_exec(db, "RELEASE SAVEPOINT vh_recheck", NULL, NULL, NULL);
    } else {
        sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
    }
}

static job_result_t recheck_failed_rows(struct main_state *ms,
                                          sqlite3 *db,
                                          uint64_t validated_cursor)
{
    if (!ms || !db || validated_cursor == 0)
        return JOB_IDLE;

    int64_t start = atomic_load(&g_failure_recheck_cursor);
    if (start < 0)
        start = 0;

    /* Anchor the scan at the live pipeline frontier so stale reindex-artifact
     * ok=0 rows (cold-imported solutionless headers far below the tip) can
     * never pin the bounded (LIMIT VH_BATCH_SIZE) batch before it reaches the
     * real frontier — the live tip-wedge. The frontier is the LOWER of two
     * durable cursors: tip_finalize (= finalized_tip+1) and body_fetch (which
     * JOB_BLOCKs on a live solutionless ok=0 row, so its cursor is the height
     * that must not be skipped even if a torn WAL restart leaves the finalized
     * seed above it).
     *
     * The durable executable frontier is authoritative in BOTH directions.
     * Raising a low in-process floor excludes ancient rows; lowering a stale
     * high in-process floor re-arms a frontier row that was stranded after the
     * floor advanced past it before the repair header landed. Verdict-
     * preserving: this only controls WHICH heights reach the unchanged
     * PoW+Equihash validator. */
    {
        uint64_t fin_cursor = 0;
        uint64_t bf_cursor = 0;
        if (!stage_cursor_read_or_zero(db, "tip_finalize", STAGE_NAME,
                                       &fin_cursor) ||
            !stage_cursor_read_or_zero(db, "body_fetch", STAGE_NAME,
                                       &bf_cursor))
            return vh_db_fault(sqlite3_extended_errcode(db), (int)start,
                               "recheck frontier cursor read");
        int64_t fin_cur = (int64_t)fin_cursor;
        int64_t bf_cur  = (int64_t)bf_cursor;
        int64_t frontier = fin_cur;
        if (bf_cur > 0 && (frontier <= 0 || bf_cur < frontier))
            frontier = bf_cur;
        atomic_store(&g_last_recheck_frontier, frontier);
        if (frontier > 0)
            start = frontier;
    }
    atomic_store(&g_last_recheck_start, start);
    atomic_store(&g_last_recheck_selected, 0);

    if ((uint64_t)start >= validated_cursor)
        return JOB_IDLE;

    progress_store_tx_lock();
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db,
        "SELECT height, COALESCE(fail_reason,'') FROM validate_headers_log"
        " WHERE ok=0 AND height>=? AND height<?"
        " AND fail_reason IN (?, ?)"
        " ORDER BY height ASC LIMIT ?",
        -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        progress_store_tx_unlock();
        /* De-storm: a stuck db connection re-hits this same prepare failure
         * every recheck poll. Key on rc so a genuinely different sqlite fault
         * re-emits but a stuck one collapses to first-fire + 60 s keepalive. */
        static struct log_throttle recheck_prepare_throttle = LOG_THROTTLE_INIT;
        uint64_t reps = 0;
        if (log_throttle_should_emit(&recheck_prepare_throttle, (uint64_t)rc,
                                     platform_time_wall_unix(), 60, &reps))
            LOG_ERR("validate_headers",
                    "failed-row recheck query prepare failed rc=%d repeats=%llu",
                    rc, (unsigned long long)reps);
        return vh_db_fault(rc, (int)start, "recheck query prepare");
    }
    sqlite3_bind_int64(stmt, 1, (sqlite3_int64)start);
    sqlite3_bind_int64(stmt, 2, (sqlite3_int64)validated_cursor);
    sqlite3_bind_text(stmt, 3, STAGE_REPAIR_SOLUTIONLESS_REASON, -1,
                      SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, "header-source-hash-mismatch", -1,
                      SQLITE_STATIC);
    sqlite3_bind_int(stmt, 5, VH_BATCH_SIZE * 64);

    struct vh_job jobs[VH_BATCH_SIZE];
    memset(jobs, 0, sizeof(jobs));
    int n = 0;
    int64_t last_seen = start - 1;
    int64_t first_unresolved = -1;
    while (n < VH_BATCH_SIZE &&
           (rc = sqlite3_step(stmt)) == SQLITE_ROW) {  // raw-sql-ok:progress-kv-kernel-store
        int64_t h64 = sqlite3_column_int64(stmt, 0);
        const unsigned char *reason_txt = sqlite3_column_text(stmt, 1);
        const char *reason = reason_txt ? (const char *)reason_txt : "";
        last_seen = h64;
        if (h64 < 0 || h64 > INT32_MAX) {
            sqlite3_finalize(stmt);
            progress_store_tx_unlock();
            /* De-storm: key on the offending height so a genuinely different
             * corrupt row re-emits but the same one collapses to first-fire +
             * 60 s keepalive. */
            static struct log_throttle recheck_range_throttle = LOG_THROTTLE_INIT;
            uint64_t reps = 0;
            if (log_throttle_should_emit(&recheck_range_throttle,
                                         (uint64_t)h64,
                                         platform_time_wall_unix(), 60, &reps))
                LOG_ERR("validate_headers",
                        "failed-row recheck height out of range h=%lld "
                        "repeats=%llu", (long long)h64,
                        (unsigned long long)reps);
            return JOB_FATAL;
        }
        struct block_index *bi = vh_resolve_bi(ms, (int)h64);
        if (!bi || !bi->phashBlock) {
            /* Transient resolve miss. SKIP this height rather than abort the
             * whole pass; remember the lowest such height so the floor never
             * advances past it (retried next pass). */
            vh_window_miss_note((int)h64, "recheck");
            atomic_store(&g_last_blocked_unix, platform_time_wall_unix());
            if (first_unresolved < 0)
                first_unresolved = h64;
            continue;
        }
        blocker_clear(VH_WINDOW_MISS_BLOCKER_ID);
        if (!vh_failure_is_recheck_candidate(reason))
            continue;
        if (!validate_headers_recheck_ready(db, (int)h64, bi, reason)) {
            /* No exact solution bytes yet: the condition engine owns their
             * backfill/refetch. Pin the lowest unresolved height and back off
             * rather than claiming progress from an unchanged verdict. */
            atomic_store(&g_last_blocked_unix, platform_time_wall_unix());
            if (first_unresolved < 0)
                first_unresolved = h64;
            continue;
        }
        vh_job_bind_block(db, &jobs[n], bi, (int)h64);
        n++;
    }
    if (rc != SQLITE_DONE && rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        progress_store_tx_unlock();
        /* De-storm: keyed on rc, mirrors recheck_prepare_throttle above. */
        static struct log_throttle recheck_step_throttle = LOG_THROTTLE_INIT;
        uint64_t reps = 0;
        if (log_throttle_should_emit(&recheck_step_throttle, (uint64_t)rc,
                                     platform_time_wall_unix(), 60, &reps))
            LOG_ERR("validate_headers",
                    "failed-row recheck query failed rc=%d repeats=%llu",
                    rc, (unsigned long long)reps);
        return vh_db_fault(rc, (int)last_seen, "recheck query step");
    }
    atomic_store(&g_last_recheck_selected, n);
    sqlite3_finalize(stmt);
    progress_store_tx_unlock();

    if (n == 0) {
        /* If every selected row was skipped (unresolvable), pin at the lowest
         * skipped height so the next pass retries it; only a genuinely empty
         * scan may jump the floor to validated_cursor. */
        int64_t idle_floor = (first_unresolved >= 0)
                             ? first_unresolved : (int64_t)validated_cursor;
        atomic_store(&g_failure_recheck_cursor, idle_floor);
        return JOB_IDLE;
    }

    vh_pool_run_batch(&g_pool, jobs, sizeof(jobs[0]), n);
    char *err = NULL;
    progress_store_tx_lock();
    /* This path runs both standalone (validate_headers_stage_step_once with no
     * outer txn) and inside the bounded drain (STAGE_DRAIN_IMPL → stage_run_once
     * → here), where stage_batch_begin has already opened a BEGIN IMMEDIATE on
     * this same connection. A bare BEGIN here would nest a transaction inside
     * that batch ("cannot start a transaction within a transaction") and the
     * recheck/repair would never run — the failed-row self-heal silently
     * disabled. Mirror stage_run_once's contract: open a SAVEPOINT when a batch
     * is active (its writes stay enrolled in the batch, committed once by
     * stage_batch_end), a fresh BEGIN IMMEDIATE only when standalone. */
    const bool vh_batched = stage_batch_active();
    const char *vh_open   = vh_batched ? "SAVEPOINT vh_recheck" : "BEGIN IMMEDIATE";
    const char *vh_commit = vh_batched ? "RELEASE SAVEPOINT vh_recheck" : "COMMIT";
    if (sqlite3_exec(db, vh_open, NULL, NULL, &err) != SQLITE_OK) {
        int frc = sqlite3_extended_errcode(db);
        /* De-storm: keyed on frc, mirrors recheck_prepare_throttle above. */
        static struct log_throttle recheck_begin_throttle = LOG_THROTTLE_INIT;
        uint64_t reps = 0;
        if (log_throttle_should_emit(&recheck_begin_throttle, (uint64_t)frc,
                                     platform_time_wall_unix(), 60, &reps))
            LOG_WARN("validate_headers",
                     "[validate_headers] failed-row recheck BEGIN failed: %s "
                     "repeats=%llu", err ? err : "(no message)",
                     (unsigned long long)reps);
        if (err) sqlite3_free(err);
        progress_store_tx_unlock();
        return vh_db_fault(frc, (int)start, "recheck begin/savepoint");
    }
    for (int i = 0; i < n; i++) {
        /* Recheck rows are pre-filtered to the repairable reasons (solutionless /
         * source-hash-mismatch), so a stale BLOCK_FAILED mask on a now-passing
         * header IS the serve-refusal class: pass clearable=true. This is the
         * reachable repair (deliverable b) — clear the mask and flip the row to
         * ok=1 once the backfilled solution makes the unchanged validator pass. */
        if (jobs[i].ok &&
            !vh_authoritative_mark(&jobs[i], true)) {
            /* Still un-markable after the scoped clear (e.g. a NULL entry). Name
             * ONE typed blocker (throttled) and back off JOB_IDLE — never
             * the JOB_FATAL hot loop. */
            vh_mark_fail_note(jobs[i].height, jobs[i].mark_bi);
            vh_recheck_rollback(db, vh_batched);
            progress_store_tx_unlock();
            atomic_store(&g_last_blocked_unix, platform_time_wall_unix());
            return JOB_IDLE;
        }
        if (!validate_headers_log_insert(db, jobs[i].height,
                                         jobs[i].bi->phashBlock, jobs[i].ok,
                                         jobs[i].reason)) {
            int frc = sqlite3_extended_errcode(db);
            vh_recheck_rollback(db, vh_batched);
            progress_store_tx_unlock();
            return vh_db_fault(frc, jobs[i].height, "recheck log insert");
        }
        if (jobs[i].ok)
            atomic_fetch_add(&g_passed_total, 1);
        else
            atomic_fetch_add(&g_failed_total, 1);
    }
    if (sqlite3_exec(db, vh_commit, NULL, NULL, &err) != SQLITE_OK) {
        int frc = sqlite3_extended_errcode(db);
        /* De-storm: keyed on frc, mirrors recheck_begin_throttle above. */
        static struct log_throttle recheck_commit_throttle = LOG_THROTTLE_INIT;
        uint64_t reps = 0;
        if (log_throttle_should_emit(&recheck_commit_throttle, (uint64_t)frc,
                                     platform_time_wall_unix(), 60, &reps))
            LOG_WARN("validate_headers",
                     "[validate_headers] failed-row recheck COMMIT failed: %s "
                     "repeats=%llu", err ? err : "(no message)",
                     (unsigned long long)reps);
        if (err) sqlite3_free(err);
        vh_recheck_rollback(db, vh_batched);
        progress_store_tx_unlock();
        return vh_db_fault(frc, (int)last_seen, "recheck commit");
    }
    progress_store_tx_unlock();
    /* Advance the floor only past rows that RESOLVED to ok=1; pin it at the
     * lowest row still ok=0 so the next pass retries it once its solution is
     * backfilled. jobs[] is height-ascending, so the first !ok is the lowest
     * still-failing height. Advancing unconditionally to last_seen+1 (the old
     * behavior) re-stranded a repairable row the moment recheck touched it
     * before its solution landed — the same monotonic-strand defect as the
     * forward drain. Verdict-preserving: a row only leaves ok=0 via a genuine
     * PoW + Equihash pass in vh_pool_run_batch above. */
    int64_t lowest_still_failing = -1;
    for (int i = 0; i < n; i++)
        if (!jobs[i].ok && vh_failure_is_repairable(jobs[i].reason)) {
            lowest_still_failing = jobs[i].height; break;
        }
    int64_t new_floor = (lowest_still_failing >= 0)
                        ? lowest_still_failing : (last_seen + 1);
    /* Never advance the floor past a height skipped as unresolvable this pass —
     * it must be retried on the next pass, not stepped over. */
    if (first_unresolved >= 0 && new_floor > first_unresolved)
        new_floor = first_unresolved;
    atomic_store(&g_failure_recheck_cursor, new_floor);
    /* Only claim progress when the floor actually advanced. A pinned floor
     * (the lowest repairable row still has no backfilled solution) returns
     * JOB_IDLE so the stage backs off rather than busy-looping on a row it
     * cannot yet flip; the next poll retries it once the solution lands. */
    return (new_floor > start) ? JOB_ADVANCED : JOB_IDLE;
}

static bool mark_valid_header(struct block_index *bi)
{
    if (!bi || (bi->nStatus & BLOCK_FAILED_MASK))
        return false;
    if ((bi->nStatus & BLOCK_VALID_MASK) < BLOCK_VALID_HEADER)
        bi->nStatus = (bi->nStatus & ~BLOCK_VALID_MASK) |
                      BLOCK_VALID_HEADER;
    return true;
}

/* Rising-edge recovery for the mark-failure throttle: the stale FAILED mask
 * cleared and the header marked valid, so emit ONE recovery line and clear the
 * blocker — only if the typed blocker was actually raised (i.e. a suppressed
 * streak was open). */
static void vh_mark_fail_recover(void)
{
    if (blocker_exists(VH_MARK_FAIL_BLOCKER_ID)) {
        LOG_INFO("validate_headers",
                 "[validate_headers] header mark recovered after %llu "
                 "suppressed refusal(s); stale BLOCK_FAILED mask cleared by a "
                 "clean PoW+Equihash re-validation",
                 (unsigned long long)log_throttle_reps(&g_mark_fail_throttle));
        log_throttle_reset(&g_mark_fail_throttle);
        blocker_clear(VH_MARK_FAIL_BLOCKER_ID);
    }
}

/* Throttled typed blocker for a header that re-validates clean but whose
 * block_index entry is FAILED-masked and could not be cleared here (no
 * repairable evidence). Keyed on (height, nStatus) via the shared
 * log_throttle primitive: log the FIRST refusal of a streak (loud + named:
 * height+hash+nStatus), then collapse same-key repeats to a 60 s keep-alive so
 * the condition stays visible without storming; the typed blocker is
 * (re)raised every call — cheap and idempotent — so it always reflects the
 * live condition regardless of log cadence. Runs on the serial reducer drive
 * under progress_store_tx_lock; log_throttle's atomics make it race-free
 * regardless. */
static void vh_mark_fail_note(int height, const struct block_index *bi)
{
    char hex[65] = {0};
    if (bi && bi->phashBlock)
        uint256_get_hex(bi->phashBlock, hex);
    unsigned long nstatus = bi ? (unsigned long)bi->nStatus : 0UL;

    uint64_t key = ((uint64_t)(uint32_t)height << 32) | (uint32_t)nstatus;
    uint64_t reps = 0;
    if (log_throttle_should_emit(&g_mark_fail_throttle, key,
                                 platform_time_wall_unix(), 60, &reps)) {
        atomic_fetch_add(&g_mark_fail_warn_total, 1);
        LOG_WARN("validate_headers",
                 "[validate_headers] header mark refused height=%d hash=%s "
                 "nStatus=0x%lx: header re-validates clean (PoW+Equihash) but "
                 "the block_index entry carries a stale BLOCK_FAILED mask with "
                 "no clearable repair row; holding (JOB_IDLE, no hot loop), "
                 "repeats=%llu", height, hex[0] ? hex : "(unknown)", nstatus,
                 (unsigned long long)reps);
    }
    char reason[BLOCKER_REASON_MAX];
    snprintf(reason, sizeof(reason),
             "height=%d hash=%.64s status=0x%lx: clean header retains a stale "
             "BLOCK_FAILED mask; holding until repair, revalidation, or fresh "
             "solution receipt",
             height, hex[0] ? hex : "(unknown)", nstatus);
    struct blocker_record rec;
    if (blocker_init(&rec, VH_MARK_FAIL_BLOCKER_ID, STAGE_NAME,
                     BLOCKER_TRANSIENT, reason))
        blocker_set(&rec);
}

/* Mark a passing header valid, healing a stale serve-path FAILED mask.
 *
 * The caller guarantees the UNCHANGED PoW+Equihash validator PASSED (job->ok).
 * mark_valid_header refuses any BLOCK_FAILED-masked entry, so a stale mask —
 * set by the getheaders serve path (msg_headers.c) when the local Equihash
 * solution was missing/corrupt and then persisted across boots by
 * block_index_cache — otherwise pins the header forever and re-fires JOB_FATAL
 * hot (the live 18,440-WARN storm at h=3,179,245).
 *
 * When `clearable`, clear ONLY the header-scope bits (BLOCK_FAILED_MASK) and
 * re-mark. `clearable` is the proof the mask is the repairable serve-refusal
 * class: true on the recheck path (rows are pre-filtered to repairable reasons)
 * and, on the forward path, only when a hash-bound header_solution_repair row
 * exists at this height (job->had_repair_row) — the solutionless-backfill
 * fingerprint. An operator invalidateblock / genuine consensus reject has no
 * such row and is never cleared here (find_most_work_chain still skips it).
 * Verdict-preserving (E13): a header leaves FAILED ONLY because the unchanged
 * validator passed. Returns true when the entry is (now) markable; false when
 * the caller must name a blocker and back off. */
static bool vh_authoritative_mark(struct vh_job *job, bool clearable)
{
    struct block_index *bi = job ? job->mark_bi : NULL;
    if (mark_valid_header(bi))
        return true;                        /* not FAILED-masked: fast path */
    if (bi && clearable && (bi->nStatus & BLOCK_FAILED_MASK)) {
        bi->nStatus &= ~(unsigned)BLOCK_FAILED_MASK;
        if (mark_valid_header(bi)) {
            vh_mark_fail_recover();
            return true;
        }
    }
    return false;
}

/* ── Step body ────────────────────────────────────────────────────── */

static job_result_t step_validate(struct stage_step_ctx *c)
{
    atomic_store(&g_last_step_unix, platform_time_wall_unix());

    struct main_state *ms = g_ms;
    if (!ms) return JOB_IDLE;
    reducer_extend_window_to_candidate(ms, true);
    sqlite3 *db = progress_store_db();
    if (!db) return JOB_IDLE;

    int next_h = (int)c->cursor_in;
    if (next_h < 0) return JOB_FATAL;

    /* Floor: never get ahead of header_admit. The header_admit cursor
     * is "next height to admit" — so heights [0, ha_cursor-1] are
     * admitted. We can validate up to ha_cursor-1. */
    uint64_t ha_cursor = 0;
    if (!stage_cursor_read_or_zero(db, "header_admit", STAGE_NAME,
                                   &ha_cursor))
        return vh_db_fault(sqlite3_extended_errcode(db), next_h,
                           "header_admit cursor read");
    if ((uint64_t)next_h >= ha_cursor) {
        atomic_store(&g_last_blocked_unix, platform_time_wall_unix());
        return JOB_IDLE;  /* not BLOCKED — header_admit will catch up */
    }

    int available = (int)(ha_cursor - (uint64_t)next_h);
    int batch_n = (available < g_pool.batch_cap) ? available : g_pool.batch_cap;
    if (batch_n <= 0 || !g_pool.batch) return JOB_IDLE;

    /* Build the batch. Each job points to the block_index entry at
     * its target height. */
    struct vh_job *jobs = g_pool.batch;
    memset(jobs, 0, sizeof(*jobs) * (size_t)batch_n);
    for (int i = 0; i < batch_n; i++) {
        int h = next_h + i;
        struct block_index *bi = vh_resolve_bi(ms, h);
        if (!bi || !bi->phashBlock) {
            /* Shouldn't happen (header_admit just admitted it), but a
             * concurrent reorg is conceivable — name a typed blocker rather
             * than rely solely on the 60-min stage-freeze backstop. */
            vh_window_miss_note(h, "validation");
            atomic_store(&g_last_blocked_unix, platform_time_wall_unix());
            return JOB_IDLE;
        }
        blocker_clear(VH_WINDOW_MISS_BLOCKER_ID);
        vh_job_bind_block(db, &jobs[i], bi, h);
    }

    /* Dispatch + await. Pool stays inside this step. */
    vh_pool_run_batch(&g_pool, jobs, sizeof(jobs[0]), batch_n);

    /* Write rows + bump cursor, all under the F-2 BEGIN IMMEDIATE txn. */
    for (int i = 0; i < batch_n; i++) {
        if (jobs[i].ok &&
            !vh_authoritative_mark(&jobs[i], jobs[i].had_repair_row)) {
            /* Validator PASSED but the block_index entry is FAILED-masked and no
             * clearable repair row proves it is the serve-refusal class. Name
             * ONE typed blocker (throttled) and BACK OFF (JOB_IDLE) —
             * never the hot JOB_FATAL loop that stormed 18,440 WARN lines at
             * h=3,179,245. Backing off also un-starves the condition runner so
             * block_failed_mask_at_tip / process_block_revalidate can clear the
             * mask consensus-safely; the cursor holds until it does. The step's
             * partial writes roll back (stage_run_once), so a mid-batch hold is
             * clean and the whole batch re-marks idempotently next tick. */
            vh_mark_fail_note(jobs[i].height, jobs[i].mark_bi);
            atomic_store(&g_last_blocked_unix, platform_time_wall_unix());
            return JOB_IDLE;
        }
        if (!validate_headers_log_insert(db, jobs[i].height,
                                         jobs[i].bi->phashBlock, jobs[i].ok,
                                         jobs[i].reason))
            return vh_db_fault(sqlite3_extended_errcode(db), jobs[i].height,
                               "validate_headers_log insert");
        if (jobs[i].ok) atomic_fetch_add(&g_passed_total, 1);
        else            atomic_fetch_add(&g_failed_total, 1);
    }

    c->cursor_out = c->cursor_in + (uint64_t)batch_n;
    /* Failure-recheck floor: the lowest height recheck_failed_rows will
     * revisit. It must NEVER advance past a still-failing (ok=0) row. recheck
     * only scans [floor, validated_cursor); slaving the floor to the forward
     * cursor (the old `floor = max(floor, cursor_out)`) made recheck a no-op
     * for every row this drain logged ok=0 — they were stranded the instant
     * they were written. That is the live tip-wedge: validate_headers logged
     * height H ok=0 "no-header-solution-backfill-required" (its Equihash
     * solution not yet backfilled), the floor jumped past H, backfill_header_
     * solutions later supplied H's solution, but recheck never looked back —
     * so body_fetch stalled at H and the public tip froze one block below.
     * Pin the floor at the lowest failure in this batch; only advance to
     * cursor_out when the whole batch passed. This changes only WHICH rows are
     * re-validated, never the verdict — a row still flips to ok=1 solely
     * through the unchanged PoW + Equihash validator, so it can never admit an
     * invalid header (zero fork risk). Only REPAIRABLE (solutionless) failures
     * pin the floor; a terminal rejection advances it exactly as before, so
     * recheck never re-runs the validator on a permanently-bad header. */
    int64_t lowest_fail = -1;
    for (int i = 0; i < batch_n; i++)
        if (!jobs[i].ok && vh_failure_is_repairable(jobs[i].reason)) {
            lowest_fail = jobs[i].height; break;
        }
    int64_t recheck_floor = atomic_load(&g_failure_recheck_cursor);
    if (lowest_fail >= 0) {
        if (recheck_floor > lowest_fail)
            atomic_store(&g_failure_recheck_cursor, lowest_fail);
    } else if (recheck_floor < (int64_t)c->cursor_out) {
        atomic_store(&g_failure_recheck_cursor, (int64_t)c->cursor_out);
    }
    /* Clean advancing step — the infra-db fault retry budget resets. */
    stage_db_fault_clear(&g_vh_db_fault);
    return JOB_ADVANCED;
}

/* ── Public API ───────────────────────────────────────────────────── */

bool validate_headers_stage_init(struct main_state *ms)
{
    if (!ms) LOG_FAIL("validate_headers", "init: NULL main_state");

    sqlite3 *db = progress_store_db();
    if (!db) LOG_FAIL("validate_headers",
        "init: progress_store not open");

    pthread_mutex_lock(&g_lock);

    if (g_stage != NULL) {
        bool same = (g_ms == ms);
        pthread_mutex_unlock(&g_lock);
        if (!same)
            LOG_FAIL("validate_headers",
                "init: already bound to a different main_state");
        return true;
    }

    if (!validate_headers_log_ensure_schema(db)) {
        pthread_mutex_unlock(&g_lock);
        return false;
    }

    /* Cache the datadir for workers. GetDataDir is the canonical
     * accessor; it's stable for the process lifetime. */
    GetDataDir(true, g_datadir, sizeof(g_datadir));

    /* Default validator runs full PoW + Equihash from disk. */
    if (!g_validator) {
        g_validator      = validate_headers_default_validator;
        g_validator_user = NULL;
    }

    uint64_t persisted_cursor = 0;
    if (!stage_cursor_read_or_zero(db, STAGE_NAME, STAGE_NAME,
                                   &persisted_cursor)) {
        pthread_mutex_unlock(&g_lock);
        return false;
    }

    /* Starting widths for this run: the compile-time defaults on a live node,
     * wider only under an offline mint/refold fold (validate_headers_tuning.c).
     * A live catch-up normally arms AFTER init (peers connect later), so its
     * widening engages via vh_pool_sync_width() on the step path. */
    if (!vh_pool_start(&g_pool, vh_run_job, NULL, vh_runtime_pool_size(),
                       vh_runtime_batch_size())) {
        pthread_mutex_unlock(&g_lock);
        return false;
    }

    stage_t *s = stage_create(STAGE_NAME, step_validate, NULL);
    if (!s) {
        vh_pool_stop(&g_pool);
        pthread_mutex_unlock(&g_lock);
        LOG_FAIL("validate_headers", "init: stage_create failed");
    }
    if (!stage_set_cursor(s, db, persisted_cursor)) {
        stage_destroy(s);
        vh_pool_stop(&g_pool);
        pthread_mutex_unlock(&g_lock);
        return false;
    }

    g_ms    = ms;
    g_stage = s;
    pthread_mutex_unlock(&g_lock);

    LOG_INFO("validate_headers",
             "[validate_headers] stage initialised (authoritative, pool=%d batch=%d)",
             g_pool.n_threads, g_pool.batch_cap);
    return true;
}

void validate_headers_stage_set_validator(vh_validator_fn fn, void *user)
{
    pthread_mutex_lock(&g_lock);
    g_validator      = fn ? fn : validate_headers_default_validator;
    g_validator_user = fn ? user : NULL;
    pthread_mutex_unlock(&g_lock);
}

job_result_t validate_headers_stage_step_once(void)
{
    if (!g_stage) return JOB_IDLE;
    sqlite3 *db = progress_store_db();
    if (!db) return JOB_IDLE;

    /* Resize the pool on a catch-up/fold gate edge, before the tx lock is
     * taken. No-op compare on the hot path; a false return leaves the cursor
     * held (retry next tick). */
    if (!vh_pool_sync_width()) return JOB_IDLE;

    progress_store_tx_lock();

    job_result_t r = stage_run_once(g_stage, db);
    if (r != JOB_IDLE) {
        progress_store_tx_unlock();
        return r;
    }

    uint64_t validated_cursor = 0;
    if (!stage_cursor_read_or_zero(db, STAGE_NAME, STAGE_NAME,
                                   &validated_cursor)) {
        int frc = sqlite3_extended_errcode(db);
        progress_store_tx_unlock();
        return vh_db_fault(frc, 0, "step_once validated cursor read");
    }
    job_result_t recheck = recheck_failed_rows(g_ms, db, validated_cursor);
    if (recheck == JOB_ADVANCED)
        stage_db_fault_clear(&g_vh_db_fault);
    progress_store_tx_unlock();
    return recheck;
}

STAGE_DRAIN_IMPL(validate_headers)

void validate_headers_stage_shutdown(void)
{
    /* Registry hygiene: re-derived on next fire, so clearing loses nothing. */
    blocker_clear(VH_WINDOW_MISS_BLOCKER_ID);
    blocker_clear(VH_MARK_FAIL_BLOCKER_ID);
    pthread_mutex_lock(&g_lock);
    /* Pool must stop before stage_destroy so the workers' read of
     * g_validator stays valid. */
    vh_pool_stop(&g_pool);
    if (g_stage) {
        stage_destroy(g_stage);
        g_stage = NULL;
    }
    g_ms = NULL;
    g_validator      = NULL;   /* re-default on next init */
    g_validator_user = NULL;
    atomic_store(&g_passed_total, (uint64_t)0);
    atomic_store(&g_failed_total, (uint64_t)0);
    atomic_store(&g_last_step_unix, (int64_t)0);
    atomic_store(&g_last_blocked_unix, (int64_t)0);
    atomic_store(&g_failure_recheck_cursor, (int64_t)0);
    atomic_store(&g_last_recheck_frontier, (int64_t)-1);
    atomic_store(&g_last_recheck_start, (int64_t)-1);
    atomic_store(&g_last_recheck_selected, (int64_t)0);
    log_throttle_reset(&g_mark_fail_throttle);
    atomic_store(&g_mark_fail_warn_total, (int64_t)0);
    stage_db_fault_clear(&g_vh_db_fault);
    pthread_mutex_unlock(&g_lock);
}

int64_t validate_headers_stage_mark_fail_warn_count(void)
{
    return atomic_load(&g_mark_fail_warn_total);
}

/* Test-only: the current failure-recheck floor (g_failure_recheck_cursor) —
 * the lowest height recheck_failed_rows will revisit. Exposed so the Task A #12
 * floor-pin regression (a hash-mismatch row with no repair entry must NOT let
 * the floor skip past it) can be asserted directly. */
int64_t validate_headers_stage_recheck_floor_for_test(void)
{
    return atomic_load(&g_failure_recheck_cursor);
}

uint64_t validate_headers_stage_cursor(void)
{
    if (!g_stage)
        return 0;
    return stage_cursor(g_stage);
}

int64_t validate_headers_stage_step_us_ewma(void)
{
    return g_stage ? stage_step_us_ewma(g_stage) : 0;
}

uint64_t validate_headers_stage_passed_total(void)
{
    return atomic_load(&g_passed_total);
}

uint64_t validate_headers_stage_failed_total(void)
{
    return atomic_load(&g_failed_total);
}

bool validate_headers_stage_has_pass_record(int32_t height,
                                            const struct uint256 *hash)
{
    sqlite3 *db = progress_store_db();
    if (!db || !hash || height < 0) return false;

    progress_store_tx_lock();
    sqlite3_stmt *st = NULL;
    int rc = sqlite3_prepare_v2(db,
        "SELECT ok FROM validate_headers_log WHERE height=? AND hash=?",
        -1, &st, NULL);
    if (rc != SQLITE_OK) {
        progress_store_tx_unlock();
        return false;
    }
    sqlite3_bind_int64(st, 1, (sqlite3_int64)height);
    sqlite3_bind_blob(st, 2, hash->data, 32, SQLITE_STATIC);

    bool found = false;
    if (sqlite3_step(st) == SQLITE_ROW)  // raw-sql-ok:progress-kv-kernel-store
        found = sqlite3_column_int(st, 0) == 1;
    sqlite3_finalize(st);
    progress_store_tx_unlock();
    return found;
}

/* validate_headers_stage_window_report() and the failure-summary loader
 * live in validate_headers_report.c — see validate_headers_internal.h. */

bool validate_headers_stage_dump_state_json(struct json_value *out,
                                             const char *key)
{
    (void)key;
    if (!out) return false;
    json_set_object(out);
    json_push_kv_bool(out, "initialised", g_stage != NULL);
    json_push_kv_str (out, "stage_name", STAGE_NAME);
    json_push_kv_str(out, "authority", "authoritative");
    json_push_kv_int (out, "cursor",
                      (int64_t)(g_stage ? stage_cursor(g_stage) : 0));
    /* The widths in force this run, not the compile-time defaults. */
    json_push_kv_int (out, "pool_size", (int64_t)g_pool.n_threads);
    json_push_kv_int (out, "batch_size", (int64_t)g_pool.batch_cap);
    json_push_kv_int(out, "passed_total", (int64_t)atomic_load(&g_passed_total));
    json_push_kv_int(out, "failed_total", (int64_t)atomic_load(&g_failed_total));
    json_push_kv_int(out, "last_step_unix", atomic_load(&g_last_step_unix));
    json_push_kv_int(out, "last_blocked_unix", atomic_load(&g_last_blocked_unix));
    json_push_kv_int (out, "failure_recheck_cursor",
                      atomic_load(&g_failure_recheck_cursor));
    json_push_kv_int (out, "last_recheck_frontier",
                      atomic_load(&g_last_recheck_frontier));
    json_push_kv_int (out, "last_recheck_start",
                      atomic_load(&g_last_recheck_start));
    json_push_kv_int (out, "last_recheck_selected",
                      atomic_load(&g_last_recheck_selected));
    json_push_kv_int (out, "mark_fail_warn_total",
                      atomic_load(&g_mark_fail_warn_total));
    struct validate_headers_failure_summary failures;
    validate_headers_failure_summary_load(&failures);
    /* Labeled staleness: progress_store_busy => the counts below are the
     * struct's init'd defaults (0 / -1), not a real read (fold owned the lock). */
    json_push_kv_str(out, "failure_summary_status",
        failures.progress_store_busy ? "progress_store_busy" : "available");
    json_push_kv_int(out, "failure_log_count", failures.count);
    json_push_kv_int(out, "first_failed_height", failures.first_height);
    json_push_kv_str(out, "first_fail_reason", failures.first_reason);
    json_push_kv_int(out, "last_failed_height", failures.last_height);
    json_push_kv_str(out, "last_fail_reason", failures.last_reason);
    stage_dump_counters(out, g_stage);
    stage_dump_health(out, STAGE_NAME, g_stage);
    return true;
}
