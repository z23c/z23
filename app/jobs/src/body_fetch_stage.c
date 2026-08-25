/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * body_fetch_stage — implementation. See jobs/body_fetch_stage.h.
 *
 * Single-process singleton, single-step (no worker pool). The work per
 * step is one in-memory flag check + one SQL insert, so batching adds
 * complexity without throughput. The F-2 stage primitive does the
 * cursor + replay heavy lifting; this module is the step body and the
 * schema-bootstrap glue for the `body_fetch_log` table that lives in
 * progress.kv alongside the cursor table. */

#include "platform/time_compat.h"
#include "jobs/body_fetch_stage.h"
#include "jobs/reducer_frontier.h"
#include "jobs/stage_helpers.h"
#include "jobs/tip_finalize_stage.h"
#include "body_fetch_log_store.h"

#include "chain/chain.h"
#include "core/uint256.h"
#include "json/json.h"
#include "storage/progress_store.h"
#include "util/blocker.h"
#include "util/log_macros.h"
#include "util/stage.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define STAGE_NAME "body_fetch"

static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static struct main_state *g_ms = NULL;
static stage_t *g_stage = NULL;
static _Atomic uint64_t g_observed_total = 0;
static _Atomic uint64_t g_skipped_total  = 0;
static _Atomic int64_t  g_last_advance_height = -1;
static _Atomic int64_t  g_last_step_unix = 0;
static _Atomic int64_t  g_last_blocked_unix = 0;

enum body_fetch_idle_reason {
    BF_IDLE_NONE = 0,
    BF_IDLE_BEST_HEADER_ABSENT,
    BF_IDLE_BEST_HASH_MISMATCH,
    BF_IDLE_ACTIVE_HASH_MISMATCH,
    BF_IDLE_VISIBLE_PARENT_ABSENT,
    BF_IDLE_VISIBLE_PARENT_MISMATCH,
    BF_IDLE_AUTHORITY_FAILED,
    BF_IDLE_BODY_MISSING,
    BF_IDLE_REASON_COUNT,
};

static _Atomic int g_last_idle_reason = BF_IDLE_NONE;
static _Atomic uint64_t g_idle_reason_total[BF_IDLE_REASON_COUNT];

static const char *body_fetch_idle_reason_name(enum body_fetch_idle_reason r)
{
    static const char *const names[BF_IDLE_REASON_COUNT] = {
        "none",
        "authority.best_header_absent",
        "authority.best_hash_mismatch",
        "authority.active_hash_mismatch",
        "authority.visible_parent_absent",
        "authority.visible_parent_mismatch",
        "authority.failed",
        "body.missing",
    };
    return r >= 0 && r < BF_IDLE_REASON_COUNT ? names[r] : "unknown";
}

static job_result_t body_fetch_idle(enum body_fetch_idle_reason reason)
{
    atomic_store(&g_last_blocked_unix, platform_time_wall_unix());
    atomic_store(&g_last_idle_reason, reason);
    if (reason > BF_IDLE_NONE && reason < BF_IDLE_REASON_COUNT)
        atomic_fetch_add(&g_idle_reason_total[reason], 1u);
    return JOB_IDLE;
}

static enum body_fetch_idle_reason body_fetch_idle_reason_from_exact(
    enum body_fetch_exact_authority_state state)
{
    switch (state) {
    case BODY_FETCH_EXACT_READY:
    case BODY_FETCH_EXACT_HAVE_DATA:
        return BF_IDLE_NONE;
    case BODY_FETCH_EXACT_BEST_ABSENT:
        return BF_IDLE_BEST_HEADER_ABSENT;
    case BODY_FETCH_EXACT_BEST_HASH_MISMATCH:
        return BF_IDLE_BEST_HASH_MISMATCH;
    case BODY_FETCH_EXACT_ACTIVE_HASH_MISMATCH:
        return BF_IDLE_ACTIVE_HASH_MISMATCH;
    case BODY_FETCH_EXACT_PARENT_ABSENT:
        return BF_IDLE_VISIBLE_PARENT_ABSENT;
    case BODY_FETCH_EXACT_PARENT_MISMATCH:
        return BF_IDLE_VISIBLE_PARENT_MISMATCH;
    case BODY_FETCH_EXACT_AUTHORITY_FAILED:
        return BF_IDLE_AUTHORITY_FAILED;
    }
    return BF_IDLE_AUTHORITY_FAILED;
}

const char *body_fetch_exact_authority_state_name(
    enum body_fetch_exact_authority_state state)
{
    static const char *const names[] = {
        "ready",
        "exact_have_data",
        "best_absent",
        "best_hash_mismatch",
        "active_hash_mismatch",
        "visible_parent_absent",
        "visible_parent_mismatch",
        "authority_failed",
    };
    return state >= BODY_FETCH_EXACT_READY &&
                   state <= BODY_FETCH_EXACT_AUTHORITY_FAILED
        ? names[state] : "unknown";
}

/* Join the durable validate_headers verdict to live chain identity.  Caller
 * owns cs_main.  `durable_parent_hash` was captured before taking cs_main and
 * is consulted only when the raw active parent slot is absent. */
static struct block_index *body_fetch_exact_authority_locked(
    struct main_state *ms, int height, const struct uint256 *expected_hash,
    const struct uint256 *durable_parent_hash,
    enum body_fetch_exact_authority_state *out_state)
{
    *out_state = BODY_FETCH_EXACT_BEST_ABSENT;
    if (!ms || height < 0 || !expected_hash || !ms->pindex_best_header ||
        height > ms->pindex_best_header->nHeight)
        return NULL;

    struct block_index *best = block_index_get_ancestor(
        ms->pindex_best_header, height);
    if (!best || !best->phashBlock)
        return NULL;
    if (!uint256_eq(best->phashBlock, expected_hash)) {
        *out_state = BODY_FETCH_EXACT_BEST_HASH_MISMATCH;
        return NULL;
    }
    if (block_has_any_failure(best)) {
        *out_state = BODY_FETCH_EXACT_AUTHORITY_FAILED;
        return NULL;
    }

    if (height > 0) {
        struct block_index *parent = active_chain_at(
            &ms->chain_active, height - 1);
        const struct uint256 *parent_hash =
            parent && parent->phashBlock ? parent->phashBlock
                                         : durable_parent_hash;
        if (!parent_hash) {
            *out_state = BODY_FETCH_EXACT_PARENT_ABSENT;
            return NULL;
        }
        if ((parent && block_has_any_failure(parent)) ||
            (best->pprev && block_has_any_failure(best->pprev))) {
            *out_state = BODY_FETCH_EXACT_AUTHORITY_FAILED;
            return NULL;
        }
        if (!best->pprev || !best->pprev->phashBlock ||
            !uint256_eq(best->pprev->phashBlock, parent_hash)) {
            *out_state = BODY_FETCH_EXACT_PARENT_MISMATCH;
            return NULL;
        }
    }

    struct block_index *active = active_chain_at(&ms->chain_active, height);
    if (active && (!active->phashBlock ||
                   !uint256_eq(active->phashBlock, expected_hash))) {
        *out_state = BODY_FETCH_EXACT_ACTIVE_HASH_MISMATCH;
        return NULL;
    }
    if (active && block_has_any_failure(active)) {
        *out_state = BODY_FETCH_EXACT_AUTHORITY_FAILED;
        return NULL;
    }
    if (height > 0 && active &&
        (!active->pprev || !active->pprev->phashBlock ||
         !uint256_eq(active->pprev->phashBlock, best->pprev->phashBlock))) {
        *out_state = BODY_FETCH_EXACT_PARENT_MISMATCH;
        return NULL;
    }

    *out_state = BODY_FETCH_EXACT_READY;
    if (active && (block_index_status_load(active) & BLOCK_HAVE_DATA)) {
        *out_state = BODY_FETCH_EXACT_HAVE_DATA;
        return active;
    }
    if (block_index_status_load(best) & BLOCK_HAVE_DATA) {
        *out_state = BODY_FETCH_EXACT_HAVE_DATA;
        return best;
    }
    return active ? active : best;
}

static bool body_fetch_durable_parent_hash_at(sqlite3 *db, int height,
                                               struct uint256 *out)
{
    if (!db || height < 0 || !out)
        return false;
    if (tip_finalize_stage_block_hash_at(db, height, out->data))
        return true;

    /* The first checkpoint transition may replace the seed anchor row before
     * a height-1 finalized row exists.  Header-admit and utxo-apply use this
     * same exact trusted-base pair for that one convention gap. */
    int32_t base_height = -1;
    bool found = false;
    uint8_t base_hash[32];
    if (!reducer_frontier_trusted_base_read(db, &base_height, base_hash,
                                            &found))
        return false;
    if (!found || base_height != height)
        return false;
    memcpy(out->data, base_hash, sizeof(base_hash));
    return true;
}

struct block_index *body_fetch_exact_authority_resolve(
    sqlite3 *db, struct main_state *ms, int height,
    const struct uint256 *expected_hash,
    enum body_fetch_exact_authority_state *out_state)
{
    if (!out_state)
        return NULL;
    *out_state = BODY_FETCH_EXACT_BEST_ABSENT;
    if (!db || !ms || height < 0 || !expected_hash)
        return NULL;

    zcl_mutex_lock(&ms->cs_main);
    struct block_index *bi = body_fetch_exact_authority_locked(
        ms, height, expected_hash, NULL, out_state);
    zcl_mutex_unlock(&ms->cs_main);
    if (bi || *out_state != BODY_FETCH_EXACT_PARENT_ABSENT || height == 0)
        return bi;

    /* Durable read outside cs_main. NOT a lock-order requirement: the tree's
     * order is cs_main OUTER, progress_store_tx_lock INNER — active_chain_height
     * and active_chain_tip take the progress lock internally, so every cs_main
     * holder that calls them already nests that way, and
     * reconcile_block_index_flags (stage_repair_reducer_frontier.c), the only
     * site that needs both, matches. This split exists for correctness and
     * latency instead: no pointer or verdict from the first pass may cross the
     * lock gap, and the sqlite read stays off cs_main. */
    struct uint256 durable_parent_hash;
    if (!body_fetch_durable_parent_hash_at(db, height - 1,
                                           &durable_parent_hash))
        return NULL;

    /* Re-resolve every identity after re-locking.  No pointer or verdict from
     * the first pass crosses the lock gap. */
    zcl_mutex_lock(&ms->cs_main);
    bi = body_fetch_exact_authority_locked(
        ms, height, expected_hash, &durable_parent_hash, out_state);
    zcl_mutex_unlock(&ms->cs_main);
    return bi;
}

/* ── Schema + log I/O ─────────────────────────────────────────────────
 * The body_fetch_log schema, its insert, and the upstream
 * validate_headers_log ok-flag reader live in body_fetch_log_store.c
 * (pure sqlite kernel helpers below the AR layer). The upstream cursor is
 * read via stage_cursor_read_or_zero() (jobs/stage_helpers.h) so
 * body_fetch's floor check reflects what is DURABLY committed, not the
 * in-memory value which is 0 on a fresh init until the first
 * stage_run_once. */

/* ── Step body ─────────────────────────────────────────────────────── */

static job_result_t step_body_fetch(struct stage_step_ctx *c)
{
    atomic_store(&g_last_step_unix, platform_time_wall_unix());

    struct main_state *ms = g_ms;
    if (!ms) return JOB_IDLE;
    sqlite3 *db = progress_store_db();
    if (!db) return JOB_IDLE;

    int next_h = (int)c->cursor_in;
    if (next_h < 0) return JOB_FATAL;

    /* Floor: never overrun validate_headers' DURABLY persisted cursor.
     * validate cursor = "next height to validate" → heights
     * [0, vh_cursor-1] are validated. We can fetch up to vh_cursor-1.
     * Reading from disk (vs the in-memory accessor) means body_fetch
     * never advances past what is actually committed upstream, and
     * keeps body_fetch testable in isolation. */
    uint64_t vh_cursor = 0;
    if (!stage_upstream_frontier_or_zero(db, "validate_headers", STAGE_NAME,
                                   &vh_cursor))
        return JOB_FATAL;
    if ((uint64_t)next_h >= vh_cursor) {
        atomic_store(&g_last_blocked_unix, platform_time_wall_unix());
        return JOB_IDLE;  /* not BLOCKED — validate will catch up */
    }

    /* Read the validate_headers_log row to learn pass/fail. Floor
     * guarantees the row exists; defend against torn writes anyway. */
    int vh_ok = -1;
    struct uint256 vh_hash;
    char vh_reason[96];
    int found = body_fetch_vh_log_at(db, next_h, &vh_ok, &vh_hash,
                                     vh_reason, sizeof(vh_reason));
    if (found < 0) return JOB_FATAL;
    if (found == 0) {
        /* Row missing despite floor — a durable upstream-log hole, not
         * "not yet" (see stage_upstream_log_hole_note). JOB_IDLE, never
         * JOB_BLOCKED: reducer_frontier_reconcile_light is the healer. */
        stage_upstream_log_hole_note(STAGE_NAME, "validate_headers_log",
                                     next_h, vh_cursor, &g_last_blocked_unix);
        return JOB_IDLE;
    }
    stage_upstream_log_hole_clear(STAGE_NAME);

    /* A durable validate FAIL is already bound to vh_hash. It does not need a
     * live nonfailed chain candidate: recording any independently selected
     * block_index here would let a same-height sibling borrow that verdict. */
    if (vh_ok == 0) {
        if (strcmp(vh_reason,
                   "no-header-solution-backfill-required") == 0) {
            blocker_init(&c->blocker,
                         "body_fetch.header_solution_missing",
                         STAGE_NAME,
                         BLOCKER_TRANSIENT,
                         "validate_headers is waiting for a real "
                         "Equihash solution, not rejecting consensus");
            atomic_store(&g_last_blocked_unix, platform_time_wall_unix());
            return JOB_BLOCKED;
        }
        if (!body_fetch_log_insert(db, next_h, &vh_hash,
                                   "skipped_invalid", 0, false,
                                   "header_validation_failed"))
            return JOB_FATAL;
        atomic_fetch_add(&g_skipped_total, 1);
        atomic_store(&g_last_advance_height, (int64_t)next_h);
        atomic_store(&g_last_idle_reason, BF_IDLE_NONE);
        c->cursor_out = c->cursor_in + 1;
        return JOB_ADVANCED;
    }

    enum body_fetch_exact_authority_state authority_state =
        BODY_FETCH_EXACT_BEST_ABSENT;
    struct block_index *bi = body_fetch_exact_authority_resolve(
        db, ms, next_h, &vh_hash, &authority_state);
    if (!bi)
        return body_fetch_idle(
            body_fetch_idle_reason_from_exact(authority_state));

    /* Header passed validation; check body availability. */
    if (!(block_index_status_load(bi) & BLOCK_HAVE_DATA)) {
        /* Body not yet on disk — JOB_IDLE, don't advance. The natural
         * backpressure: cursor stays put until msg_blocks brings it in. */
        return body_fetch_idle(BF_IDLE_BODY_MISSING);
    }

    /* Body observed on disk. Record presence; bytes=0 because size probing
     * would add per-height pread cost. */
    if (!body_fetch_log_insert(db, next_h, &vh_hash, "disk", 0, true, NULL))
        return JOB_FATAL;

    atomic_fetch_add(&g_observed_total, 1);
    atomic_store(&g_last_advance_height, (int64_t)next_h);
    atomic_store(&g_last_idle_reason, BF_IDLE_NONE);
    c->cursor_out = c->cursor_in + 1;
    return JOB_ADVANCED;
}

/* ── Public API ────────────────────────────────────────────────────── */

bool body_fetch_stage_init(struct main_state *ms)
{
    if (!ms) LOG_FAIL("body_fetch", "init: NULL main_state");

    sqlite3 *db = progress_store_db();
    if (!db) LOG_FAIL("body_fetch",
        "init: progress_store not open");

    pthread_mutex_lock(&g_lock);

    /* Idempotent: same ms, already initialised → success. */
    if (g_stage != NULL) {
        bool same = (g_ms == ms);
        pthread_mutex_unlock(&g_lock);
        if (!same)
            LOG_FAIL("body_fetch",
                "init: already bound to a different main_state");
        return true;
    }

    if (!body_fetch_log_ensure_schema(db)) {
        pthread_mutex_unlock(&g_lock);
        return false;
    }

    stage_t *s = stage_create(STAGE_NAME, step_body_fetch, NULL);
    if (!s) {
        pthread_mutex_unlock(&g_lock);
        LOG_FAIL("body_fetch", "init: stage_create failed");
    }

    g_ms = ms;
    g_stage = s;
    pthread_mutex_unlock(&g_lock);

    LOG_INFO("body_fetch", "[body_fetch] stage initialised");
    return true;
}

STAGE_STEP_ONCE_SIMPLE(body_fetch)

STAGE_DRAIN_IMPL(body_fetch)

void body_fetch_stage_shutdown(void)
{
    /* Registry hygiene (tests re-init in-process): re-derived from live
     * state the next time the condition fires, so clearing here loses
     * nothing. */
    stage_upstream_log_hole_clear(STAGE_NAME);
    pthread_mutex_lock(&g_lock);
    if (g_stage) {
        stage_destroy(g_stage);
        g_stage = NULL;
    }
    g_ms = NULL;
    /* Reset per-init observability state. Persisted cursor + log rows
     * are preserved — that is the saga contract. */
    atomic_store(&g_observed_total, (uint64_t)0);
    atomic_store(&g_skipped_total, (uint64_t)0);
    atomic_store(&g_last_advance_height, (int64_t)-1);
    atomic_store(&g_last_step_unix, (int64_t)0);
    atomic_store(&g_last_blocked_unix, (int64_t)0);
    atomic_store(&g_last_idle_reason, BF_IDLE_NONE);
    for (int i = 0; i < BF_IDLE_REASON_COUNT; i++)
        atomic_store(&g_idle_reason_total[i], 0u);
    pthread_mutex_unlock(&g_lock);
}

uint64_t body_fetch_stage_cursor(void)
{
    return g_stage ? stage_cursor(g_stage) : 0;
}

int64_t body_fetch_stage_step_us_ewma(void)
{
    return g_stage ? stage_step_us_ewma(g_stage) : 0;
}

uint64_t body_fetch_stage_observed_total(void)
{
    return atomic_load(&g_observed_total);
}

uint64_t body_fetch_stage_skipped_total(void)
{
    return atomic_load(&g_skipped_total);
}

bool body_fetch_stage_dump_state_json(struct json_value *out,
                                       const char *key)
{
    (void)key;
    if (!out) return false;
    json_set_object(out);

    stage_dump_header(out, STAGE_NAME, g_stage);
    json_push_kv_int (out, "observed_total",
                      (int64_t)atomic_load(&g_observed_total));
    json_push_kv_int (out, "skipped_total",
                      (int64_t)atomic_load(&g_skipped_total));
    json_push_kv_int (out, "last_advance_height",
                      atomic_load(&g_last_advance_height));
    json_push_kv_int (out, "last_step_unix",
                      atomic_load(&g_last_step_unix));
    json_push_kv_int (out, "last_blocked_unix",
                      atomic_load(&g_last_blocked_unix));
    enum body_fetch_idle_reason idle_reason =
        (enum body_fetch_idle_reason)atomic_load(&g_last_idle_reason);
    json_push_kv_str(out, "last_idle_reason",
                     body_fetch_idle_reason_name(idle_reason));
    json_push_kv_int(out, "authority_best_header_absent_total",
                     (int64_t)atomic_load(
                         &g_idle_reason_total[BF_IDLE_BEST_HEADER_ABSENT]));
    json_push_kv_int(out, "authority_best_hash_mismatch_total",
                     (int64_t)atomic_load(
                         &g_idle_reason_total[BF_IDLE_BEST_HASH_MISMATCH]));
    json_push_kv_int(out, "authority_active_hash_mismatch_total",
                     (int64_t)atomic_load(
                         &g_idle_reason_total[BF_IDLE_ACTIVE_HASH_MISMATCH]));
    json_push_kv_int(out, "authority_visible_parent_absent_total",
                     (int64_t)atomic_load(
                         &g_idle_reason_total[BF_IDLE_VISIBLE_PARENT_ABSENT]));
    json_push_kv_int(out, "authority_visible_parent_mismatch_total",
                     (int64_t)atomic_load(
                         &g_idle_reason_total[BF_IDLE_VISIBLE_PARENT_MISMATCH]));
    json_push_kv_int(out, "authority_failed_total",
                     (int64_t)atomic_load(
                         &g_idle_reason_total[BF_IDLE_AUTHORITY_FAILED]));
    json_push_kv_int(out, "body_missing_total",
                     (int64_t)atomic_load(
                         &g_idle_reason_total[BF_IDLE_BODY_MISSING]));
    stage_dump_counters(out, g_stage);
    stage_dump_health(out, STAGE_NAME, g_stage);
    return true;
}
