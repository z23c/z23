/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * script_validate_stage — implementation. See jobs/script_validate_stage.h.
 *
 * Consumes body_persist_log and replays script verification over block
 * bodies already proven readable by body_persist. It writes
 * script_validate_log plus its stage cursor in progress.kv. */

#include "platform/time_compat.h"
#include "jobs/script_validate_stage.h"
#include "jobs/stage_helpers.h"
#include "jobs/stage_body_index.h"
#include "jobs/stage_db_fault.h"
#include "script_validate_log_store.h"
#include "script_validate_stage_internal.h"
#include "jobs/script_validate_verify.h"

#include "chain/chain.h"
#include "chain/chainparams.h"
#include "consensus/upgrades.h"
#include "coins/coins.h"
#include "core/uint256.h"
#include "event/event.h"
#include "primitives/block.h"
#include "script/interpreter.h"
#include "script/script_error.h"
#include "script/script_flags.h"
#include "storage/disk_block_io.h"
#include "storage/event_log.h"
#include "storage/event_log_payloads.h"
#include "storage/event_log_singleton.h"
#include "jobs/block_header_emit.h"
#include "jobs/created_outputs_index.h"
#include "jobs/mint_skip_crypto.h"
#include "jobs/reducer_frontier.h"
#include "jobs/script_validate_contextual.h"
#include "stage_repair_coin_backfill_util.h"
#include "script/script.h"
#include "storage/progress_store.h"
#include "storage/coins_kv.h"
#include "util/blocker.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"
#include "util/reducer_stage_profile.h"
#include "util/stage.h"
#include "util/util.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"
#include "validation/sighash.h"
#include "validation/tx_verifier.h"

#include <pthread.h>
#include <sqlite3.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define STAGE_NAME "script_validate"

/* struct body_persist_row + the script_validate_log schema/migrations/read/
 * write helpers live in script_validate_log_store.c (pure sqlite kernel
 * helpers below the AR layer).
 *
 * The block-level verify itself (serial reference + pool-parallel sweep, and
 * the shared struct script_verify_summary) lives in script_validate_verify.c —
 * this file owns the stage state machine, the cursor/log persistence, and the
 * telemetry atomics; it folds the summary the verify returns. */

static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static struct main_state *g_ms = NULL;
static stage_t *g_stage = NULL;
static char g_datadir[2048] = {0};
static script_validate_reader_fn g_reader = NULL;
static void *g_reader_user = NULL;
static script_validate_prevout_fn g_prevout = NULL;
static void *g_prevout_user = NULL;

/* Infra-db fault ladder (R5). A momentary sqlite glitch (busy/locked/transient
 * IO) holds the cursor and retries (JOB_IDLE); a persistent/permanent one
 * routes to the bounded auto-reindex. Reset on every advancing step. NEVER used
 * for a validity verdict (script_invalid etc.) — those advance with an ok=0
 * row. */
static struct stage_db_fault g_sv_db_fault;

/* Map a sqlite failure inside the step body to the result the step must return:
 * JOB_IDLE (transient, within budget — cursor held, supervisor re-ticks) or
 * JOB_FATAL (persistent/permanent — a bounded auto-reindex was requested). `rc`
 * is the sqlite (extended) code captured AT the failing call. */
static job_result_t sv_db_fault(int rc, int height, const char *ctx)
{
    return stage_db_fault_result(&g_sv_db_fault, rc, g_datadir,
                                 (int32_t)height, ctx);
}

static _Atomic uint64_t g_verified_total = 0;
static _Atomic uint64_t g_script_invalid_total = 0;
static _Atomic uint64_t g_internal_error_total = 0;
static _Atomic uint64_t g_upstream_failed_total = 0;
static _Atomic uint64_t g_inputs_verified_total = 0;
static _Atomic uint64_t g_inputs_failed_total = 0;
static _Atomic int64_t  g_last_step_unix = 0;
static _Atomic int64_t  g_last_blocked_unix = 0;
static _Atomic int64_t  g_last_advance_height = -1;
static _Atomic uint64_t g_header_event_emit_total = 0;
static _Atomic uint64_t g_header_event_emit_fail_total = 0;

static void sv_profile_acquire(const struct block_parse_handle *h)
{
    reducer_stage_profile_add(REDUCER_PROFILE_SCRIPT_VALIDATE,
                              h->cache_hit ? RPF_CACHE_HITS : RPF_CACHE_MISSES,
                              1);
    reducer_stage_profile_add(REDUCER_PROFILE_SCRIPT_VALIDATE,
                              RPF_CACHE_PROBES, h->lookup_probes);
    reducer_stage_profile_observe_us(REDUCER_PROFILE_SCRIPT_VALIDATE,
                                     RPF_CACHE_LOCK_WAIT_US, h->lock_wait_us);
    reducer_stage_profile_observe_us(REDUCER_PROFILE_SCRIPT_VALIDATE,
                                     RPF_DISK_READ_US, h->disk_read_us);
    reducer_stage_profile_observe_us(REDUCER_PROFILE_SCRIPT_VALIDATE,
                                     RPF_PARSE_US, h->parse_us);
}

static void sv_release_stage_block(struct block_parse_handle *handle,
                                   struct block *owned, bool borrowed)
{
    if (borrowed)
        block_parse_cache_release(handle);
    else
        block_free(owned);
}

/* STEP 2A — HOLD-and-re-derive budget for the transient "couldn't determine
 * yet" class (prevout_unresolved / block_decode_failed). The stage HOLDS the
 * cursor (no terminal ok=0 row, no advance, no EV_BLOCK_REJECTED) and re-derives
 * the same height next tick — once utxo_apply has folded the creating coin the
 * same shared resolver resolves it and the height advances ok=1. A bounded
 * blocked-since budget converts a genuinely irreducible hole into EXACTLY ONE
 * named PERMANENT blocker + EV_OPERATOR_NEEDED (naming the outpoint), never a
 * silent loop. g_sv_unresolved_height is the height currently held (-1 = none);
 * g_sv_unresolved_since_unix is when the hold began; g_sv_unresolved_paged_height
 * is the height we already paged the operator for (so we page once per episode). */
#define SV_UNRESOLVED_BUDGET_SECONDS 600  /* 10 min held before naming a blocker */
static _Atomic int64_t g_sv_unresolved_height = -1;
static _Atomic int64_t g_sv_unresolved_since_unix = 0;
static _Atomic int64_t g_sv_unresolved_paged_height = -1;

#ifdef ZCL_TESTING
/* Test-only override of the held-budget so a test can reach the named-blocker
 * path without waiting 10 minutes (lane E3, part 3). <0 restores the default. */
static _Atomic int g_sv_unresolved_budget_override = -1;
void script_validate_stage_unresolved_budget_set_for_test(int seconds)
{
    atomic_store(&g_sv_unresolved_budget_override, seconds);
}
static int sv_unresolved_budget(void)
{
    int o = atomic_load(&g_sv_unresolved_budget_override);
    return o >= 0 ? o : SV_UNRESOLVED_BUDGET_SECONDS;
}
#else
static int sv_unresolved_budget(void) { return SV_UNRESOLVED_BUDGET_SECONDS; }
#endif

/* Clear the HOLD tracking once a height advances cleanly (verified /
 * script_invalid / upstream_failed / contextual reject): the next hole, if any,
 * restarts the budget clock from scratch and the named blocker is released. */
static void sv_unresolved_clear(sqlite3 *db)
{
    if (atomic_exchange(&g_sv_unresolved_height, (int64_t)-1) != (int64_t)-1) {
        atomic_store(&g_sv_unresolved_paged_height, (int64_t)-1);
        blocker_clear("script_validate.prevout_unresolved");
        /* Retire the non-terminal pending-prevout HOLD signal: the held height
         * advanced (verified / script_invalid / upstream_failed / contextual
         * reject), so coin_backfill and the boot torn gate must no longer treat
         * it as an armed torn-coin hole. */
        if (db)
            (void)coin_backfill_pending_prevout_clear(db);
    }
}

/* Root-cause chaining exemplar (see util/blocker.h "Root-cause chaining").
 * A missing prevout means some earlier height's creating coin never entered
 * coins_kv; if an upstream stage is currently HELD on its own body-read
 * failure (stage_body_read_hold, "*.body_read_failed"), that stall is very
 * likely why the coin never applied — not an independent script_validate
 * fault. utxo_apply is checked first (it is the stage that must itself read
 * the block bytes to fold the coin into coins_kv, so its own read failure is
 * the most direct match); body_persist is the fallback (a body_persist
 * read-hold blocks its own cursor, so script_validate would never even reach
 * a later height while it holds — but check it anyway for completeness). */
static const char *const SV_BODY_AVAIL_BLOCKER_CANDIDATES[] = {
    "utxo_apply.body_read_failed",
    "body_persist.body_read_failed",
};

/* Read-only: the first candidate body-availability blocker id currently
 * active, or NULL if none. `snap_out` receives the matched snapshot; the
 * returned pointer aliases `snap_out->id` — callers should copy it out
 * before this function is called again, since `snap_out` is caller-owned
 * stack storage, not registry-owned.
 * Deliberately non-static (no public header entry) so
 * test_script_validate_stage.c can drive it directly without waiting on the
 * real-wall-clock SV_UNRESOLVED_BUDGET_SECONDS hold — same pattern as
 * find_lowest_prevout_unresolved_hole_unlocked in
 * stage_repair_coin_backfill_util.c. */
const char *sv_find_body_availability_cause(
    struct blocker_snapshot *snap_out)
{
    for (size_t k = 0; k < sizeof(SV_BODY_AVAIL_BLOCKER_CANDIDATES) /
                            sizeof(SV_BODY_AVAIL_BLOCKER_CANDIDATES[0]); k++) {
        if (blocker_find_by_id_prefix(SV_BODY_AVAIL_BLOCKER_CANDIDATES[k],
                                      snap_out))
            return snap_out->id;
    }
    return NULL;
}

/* HOLD the cursor on a transient prevout_unresolved / block_decode_failed at
 * `height`: within the blocked-since budget return JOB_IDLE (re-derive next
 * tick, no ok=0 row written); past the budget name ONE PERMANENT blocker +
 * page the operator ONCE and return JOB_BLOCKED. Never advances, never inserts
 * a terminal row. `s` carries the unresolved outpoint (txid+vin) for the name. */
static job_result_t sv_hold_unresolved(struct stage_step_ctx *c, int height,
                                       const struct script_verify_summary *s,
                                       sqlite3 *db,
                                       const struct uint256 *block_hash)
{
    int64_t now = platform_time_wall_unix();
    if (atomic_load(&g_sv_unresolved_height) != (int64_t)height) {
        atomic_store(&g_sv_unresolved_height, (int64_t)height);
        atomic_store(&g_sv_unresolved_since_unix, now);
        atomic_store(&g_sv_unresolved_paged_height, (int64_t)-1);
        atomic_fetch_add(&g_internal_error_total, 1); /* once per held height */
        /* Publish the NON-TERMINAL pending-prevout HOLD signal exactly once per
         * held episode (also refreshed after a reboot, when g_sv_unresolved_
         * height resets to -1). This is the TRIGGER — in place of the removed
         * terminal ok=0 row — that arms coin_backfill (its G2 hole finder) and
         * the boot torn-import gate for a genuinely torn pre-anchor coin. For
         * such a coin re-derivation alone can never resolve (the creating coin
         * is missing); coin_backfill must re-insert it, which it does within the
         * HOLD budget, after which the next HOLD re-derivation resolves ok=1.
         * Carries (height, block_hash, first_failure_txid, first_failure_vin)
         * so the repair can hash-bind the hole without a log row. It is an
         * IN-MEMORY signal (a JOB_IDLE step's progress.kv writes get rolled back
         * by the stage per-step SAVEPOINT, so it cannot be durably persisted from
         * the HOLD); after a restart it is RE-DERIVED — this same path re-runs the
         * frozen-cursor block and re-publishes it within a tick. ONLY for the
         * prevout_unresolved class: a block_decode_failed HOLD still budgets to a
         * named blocker, but coin_backfill / the torn gate both exclude that
         * class (it is not a torn coin), so arming them would be a dead branch. */
        if (db && block_hash &&
            strncmp(s->reason, "prevout_unresolved", 18) == 0)
            (void)coin_backfill_pending_prevout_set(
                db, height, block_hash, &s->first_failure_txid,
                s->first_failure_vin);
    }
    int64_t since = atomic_load(&g_sv_unresolved_since_unix);
    int64_t elapsed = (since > 0 && now >= since) ? now - since : 0;
    atomic_store(&g_last_blocked_unix, now);

    if (elapsed < sv_unresolved_budget())
        return JOB_IDLE; /* hold the cursor; the body re-derives next tick */

    char txhex[65];
    uint256_get_hex(&s->first_failure_txid, txhex);
    /* Name the ROOT CAUSE when a stage_repair body torn-read note is active for
     * an ancestor height (lane E3): the descendant's prevout is unresolvable
     * precisely because that torn body has not yet been refetched + revalidated,
     * so the operator-visible blocker points at the block to fix rather than the
     * downstream symptom. `torn_h` also feeds the typed caused_by/cause_detail
     * fields below (lane E4) once the blocker record exists — kept as a plain
     * string here too so the reason text stays self-contained for anyone
     * reading it without decoding the typed fields. */
    char cause[96];
    cause[0] = '\0';
    int64_t torn_h = -1;
    if (reducer_frontier_body_read_note_active()) {
        int64_t h = reducer_frontier_body_read_note_height();
        if (h >= 0 && h < (int64_t)height) {
            torn_h = h;
            snprintf(cause, sizeof(cause),
                     " cause: torn body height=%lld awaiting refetch",
                     (long long)torn_h);
        }
    }
    char reason[BLOCKER_REASON_MAX];
    snprintf(reason, sizeof(reason),
             "script_validate height=%d reason=%.80s held=%llds; prevout "
             "not derivable from body%.60s",
             height, s->reason[0] ? s->reason : "prevout_unresolved",
             (long long)elapsed, cause);
    if (!blocker_init(&c->blocker, "script_validate.prevout_unresolved",
                      STAGE_NAME, BLOCKER_PERMANENT, reason)) {
        /* The prevout anomaly is ALREADY detected (the budget lapsed and the
         * body still cannot re-derive the prevout) — this is not a legitimate
         * wait. Failing OPEN to JOB_IDLE here would name nothing and leave only
         * the generic watchdog; latch JOB_FATAL (the fatal path emits
         * EV_OPERATOR_NEEDED) so the halt is at least surfaced (Task A #9). */
        LOG_WARN("script_validate",
                 "[script_validate] could not name prevout_unresolved blocker "
                 "height=%d — latching JOB_FATAL rather than failing open", height);
        return JOB_FATAL;
    }
    c->blocker.retry_budget = -1;
    /* Root-cause chaining (lane E4's typed caused_by/cause_detail, see
     * util/blocker.h "Root-cause chaining"): prefer the torn-ancestor-body
     * note above (lane E3, the most direct and precise match — it names the
     * exact height a coin_backfill/have_data_unreadable refetch is waiting
     * on). Fall back to a live body-availability blocker (utxo_apply /
     * body_persist read failure) only when no torn-body note is active, so
     * the two mechanisms never fight over which cause wins. */
    if (torn_h >= 0) {
        snprintf(c->blocker.caused_by, sizeof(c->blocker.caused_by),
                 "%s", "reducer_frontier.body_read_torn");
        snprintf(c->blocker.cause_detail, sizeof(c->blocker.cause_detail),
                 "torn body height=%lld", (long long)torn_h);
    } else {
        struct blocker_snapshot root_snap;
        const char *root_id = sv_find_body_availability_cause(&root_snap);
        if (root_id) {
            char cause_detail[BLOCKER_CAUSE_DETAIL_MAX];
            snprintf(cause_detail, sizeof(cause_detail),
                     "prevout height=%d", height);
            snprintf(c->blocker.caused_by, sizeof(c->blocker.caused_by),
                     "%s", root_id);
            snprintf(c->blocker.cause_detail, sizeof(c->blocker.cause_detail),
                     "%s", cause_detail);
        }
    }
    /* Page the operator exactly once per held height (EXACTLY ONE escalation). */
    if (atomic_exchange(&g_sv_unresolved_paged_height, (int64_t)height) !=
        (int64_t)height)
        event_emitf(EV_OPERATOR_NEEDED, 0,
                    "script_validate prevout_unresolved height=%d tx=%s vin=%d "
                    "held %llds — H* cannot advance; the creating coin is "
                    "missing or unfolded",
                    height, txhex, s->first_failure_vin, (long long)elapsed);
    return JOB_BLOCKED;
}

static bool dry_run_block_impl(
    const struct block *blk,
    int height,
    script_validate_prevout_fn prevout,
    void *prevout_user,
    struct script_validate_dry_run_report *out)
{
    if (!blk || !out)
        LOG_FAIL("script_validate", "dry_run_block: bad input");

    /* Dry run — never fold the reached-input tallies into the live atomics.
     * The production (parallel) sweep is used so a dry run exercises the same
     * verdict path the stage does. */
    struct script_verify_summary summary;
    script_verify_block(blk, height, g_prevout, g_prevout_user, prevout,
                        prevout_user, true, &summary);

    memset(out, 0, sizeof(*out));
    out->ok = summary.ok != 0;
    out->internal_error = summary.internal_error != 0;
    out->tx_count = summary.tx_count;
    out->input_count = summary.input_count;
    out->first_failure_txid = summary.first_failure_txid;
    out->first_failure_vin = summary.first_failure_vin;
    out->first_failure_serror = summary.first_failure_serror;

    const char *status = "verified";
    if (!summary.ok && summary.internal_error) {
        status = (summary.reason[0] != '\0' &&
                  strncmp(summary.reason, "block_decode_failed", 19) == 0)
                     ? "block_decode_failed"
                     : "prevout_unresolved";
    } else if (!summary.ok) {
        status = "script_invalid";
    }
    snprintf(out->status, sizeof(out->status), "%s", status);
    return true;
}

bool script_validate_stage_dry_run_block(
    const struct block *blk,
    int height,
    struct script_validate_dry_run_report *out)
{
    return dry_run_block_impl(blk, height, NULL, NULL, out);
}

static job_result_t step_validate(struct stage_step_ctx *c)
{
    int64_t total_started = platform_time_monotonic_us();
    atomic_store(&g_last_step_unix, platform_time_wall_unix());

    struct main_state *ms = g_ms;
    if (!ms) return JOB_IDLE;
    sqlite3 *db = progress_store_db();
    if (!db) return JOB_IDLE;

    int next_h = (int)c->cursor_in;
    if (next_h < 0) return JOB_FATAL;

    uint64_t bp_cursor = 0;
    if (!stage_upstream_frontier_or_zero(db, "body_persist", STAGE_NAME,
                                   &bp_cursor))
        return sv_db_fault(sqlite3_extended_errcode(db), next_h,
                           "body_persist cursor read");
    if ((uint64_t)next_h >= bp_cursor) {
        atomic_store(&g_last_blocked_unix, platform_time_wall_unix());
        return JOB_IDLE;
    }

    struct body_persist_row upstream;
    int found = script_validate_body_persist_log_at(db, next_h, &upstream);
    if (found < 0)
        return sv_db_fault(sqlite3_extended_errcode(db), next_h,
                           "body_persist_log read");
    if (found == 0) {
        /* Row missing despite floor — a durable upstream-log hole, not
         * "not yet" (see stage_upstream_log_hole_note). JOB_IDLE, never
         * JOB_BLOCKED: reducer_frontier_reconcile_light is the healer. */
        stage_upstream_log_hole_note(STAGE_NAME, "body_persist_log", next_h,
                                     bp_cursor, &g_last_blocked_unix);
        return JOB_IDLE;
    }
    stage_upstream_log_hole_clear(STAGE_NAME);

    if (upstream.ok == 0) {
        if (!script_validate_log_insert(db, next_h, "upstream_failed", false,
                        0, 0, NULL, -1, SCRIPT_ERR_OK, NULL))
            return sv_db_fault(sqlite3_extended_errcode(db), next_h,
                               "script_validate_log insert (upstream_failed)");
        atomic_fetch_add(&g_upstream_failed_total, 1);
        sv_unresolved_clear(db); /* advancing past any held height */
        atomic_store(&g_last_advance_height, (int64_t)next_h);
        c->cursor_out = c->cursor_in + 1;
        stage_db_fault_clear(&g_sv_db_fault);
        return JOB_ADVANCED;
    }

    struct block_index *bi = stage_body_index_at(ms, next_h);
    if (!bi || !(block_index_status_load(bi) & BLOCK_HAVE_DATA)) {
        atomic_store(&g_last_blocked_unix, platform_time_wall_unix());
        return JOB_IDLE;
    }

    struct block owned;
    block_init(&owned);
    struct block_parse_handle handle;
    memset(&handle, 0, sizeof(handle));
    bool borrowed = g_reader == NULL;
    int64_t acquire_started = platform_time_monotonic_us();
    bool read_ok = borrowed
        ? block_parse_cache_acquire(next_h, bi->phashBlock->data, bi,
                                    g_datadir, &handle)
        : stage_read_block(&owned, bi, next_h, g_datadir, g_reader,
                           g_reader_user);
    if (!read_ok) {
        block_free(&owned);
        /* body_persist already hash+merkle verified this body — a later
         * read failure is not a normal wait (see stage_body_read_hold). */
        return stage_body_read_hold(STAGE_NAME, next_h, bi->phashBlock,
                                    &g_last_blocked_unix);
    }
    if (borrowed) sv_profile_acquire(&handle);
    const struct block *blk = borrowed ? block_parse_handle_block(&handle)
                                       : &owned;
    reducer_stage_profile_observe_us(
        REDUCER_PROFILE_SCRIPT_VALIDATE, RPF_UPSTREAM_US,
        (uint64_t)(acquire_started - total_started));
    stage_body_read_hold_clear(STAGE_NAME);

    /* #26 — at-tip contextual gate (script_validate_contextual.c): per-tx
     * contextual rules / finality / BIP34 before script verification. */
    bool ctx_internal = false;
    int64_t phase_started = platform_time_monotonic_us();
    switch (script_validate_contextual_gate(ms, db, next_h, bi, blk,
                                            &ctx_internal)) {
    case SV_CTX_PASS:
        reducer_stage_profile_observe_us(REDUCER_PROFILE_SCRIPT_VALIDATE,
                                         RPF_CONTEXTUAL_US,
                                  (uint64_t)(platform_time_monotonic_us() -
                                             phase_started));
        break;
    case SV_CTX_WAIT_PARAMS:
        sv_release_stage_block(&handle, &owned, borrowed);
        atomic_store(&g_last_blocked_unix, platform_time_wall_unix());
        return JOB_IDLE;
    case SV_CTX_REJECTED:
        sv_release_stage_block(&handle, &owned, borrowed);
        if (ctx_internal)
            atomic_fetch_add(&g_internal_error_total, 1);
        sv_unresolved_clear(db); /* advancing past any held height */
        atomic_store(&g_last_advance_height, (int64_t)next_h);
        c->cursor_out = c->cursor_in + 1;
        stage_db_fault_clear(&g_sv_db_fault);
        return JOB_ADVANCED;
    case SV_CTX_FATAL:
        /* The contextual gate's only FATAL is a log-insert store failure (an
         * infra fault, never a validity verdict — a contextual REJECT is
         * SV_CTX_REJECTED above): route it through the bounded retry/reindex
         * ladder instead of a dead JOB_FATAL. */
        sv_release_stage_block(&handle, &owned, borrowed);
        return sv_db_fault(sqlite3_extended_errcode(db), next_h,
                           "contextual gate log insert");
    }

    struct script_verify_summary summary;
    bool skip_crypto = mint_skip_crypto_get();
    if (skip_crypto) {
        /* OFFLINE FAST-MINT pass-through (jobs/mint_skip_crypto.h): SKIP the
         * per-input ECDSA verify_script loop.  The summary advances the state
         * fold, but the durable status remains explicitly "checkpoint_fold" so
         * no exporter can mistake this row for cryptographic verification (the
         * contextual gate above still ran;
         * the coin SET is unchanged — utxo_apply is the state transition). The
         * terminal SHA3==checkpoint assertion certifies only the transparent
         * fold; it does not certify skipped signatures. Default OFF → a normal
         * boot never reaches this branch. */
        script_verify_summary_init(&summary);   /* ok=1, internal_error=0 */
        for (size_t ti = 0; ti < blk->num_vtx; ti++) {
            const struct transaction *tx = &blk->vtx[ti];
            summary.tx_count++;
            if (!transaction_is_coinbase(tx))
                summary.input_count += tx->num_vin;
        }
    } else {
        /* Production path: fan the per-input ECDSA verify across the worker
         * pool, then fold the reached-input tallies the reduce computed into
         * the live atomics (verdict-identical to the serial sweep). */
        script_verify_block(blk, next_h, g_prevout, g_prevout_user, NULL, NULL,
                            true, &summary);
        atomic_fetch_add(&g_inputs_verified_total, summary.inputs_verified);
        atomic_fetch_add(&g_inputs_failed_total, summary.inputs_failed);
    }
    sv_release_stage_block(&handle, &owned, borrowed);

    /* STEP 2A: the internal_error class (prevout_unresolved / block_decode_failed)
     * is a TRANSIENT "cannot determine validity yet" — utxo_apply / the creating
     * body is still behind — NOT a permanent reject. HOLD the cursor and
     * re-derive next tick: do NOT insert a terminal ok=0 row, do NOT advance the
     * cursor, do NOT emit EV_BLOCK_REJECTED. A bounded blocked-since budget turns
     * a genuinely irreducible hole into one named PERMANENT blocker (above),
     * never a silent loop and never a frozen false reject. */
    if (!summary.ok && summary.internal_error)
        return sv_hold_unresolved(c, next_h, &summary, db, bi->phashBlock);

    const char *status = skip_crypto ? "checkpoint_fold" : "verified";
    bool ok = true;
    const struct uint256 *fail_txid = NULL;
    int fail_vin = -1;
    ScriptError fail_serror = SCRIPT_ERR_OK;
    if (!summary.ok) {
        status = "script_invalid";
        ok = false;
        fail_txid = &summary.first_failure_txid;
        fail_vin = summary.first_failure_vin;
        fail_serror = summary.first_failure_serror;
        atomic_fetch_add(&g_script_invalid_total, 1);
        /* Carry ScriptError code + mapped string + txid + vin into the reject
         * event so a bad-signature block is distinguishable downstream. */
        char ev_txhex[65];
        uint256_get_hex(fail_txid, ev_txhex);
        event_emitf(EV_BLOCK_REJECTED, 0,
                    "script_validate script_invalid height=%d tx=%s vin=%d "
                    "err=%d (%s) reason=%s",
                    next_h, ev_txhex, fail_vin, (int)fail_serror,
                    ScriptErrorString(fail_serror),
                    summary.reason[0] ? summary.reason : "script_invalid");
    } else if (!skip_crypto) {
        atomic_fetch_add(&g_verified_total, 1);
        /* Raise the in-memory validity level to BLOCK_VALID_SCRIPTS, which
         * tip_finalize.preconditions_ok requires before publication. This is
         * a validity LEVEL stored in the low BLOCK_VALID_MASK bits, not an
         * OR-able flag, so clear the mask before setting it. Re-emit a
         * lightweight status event (jobs/block_header_emit.h) so the
         * projection persists the new nStatus across restart WITHOUT
         * re-serializing the immutable header fields + Equihash solution —
         * those were already durably recorded by the first-admit
         * EV_BLOCK_HEADER (header_admit_stage) this hash's projection row
         * carries; only the mutable status/nTx bits change here. bi is the
         * live in-memory entry from active_chain_at; blk was freed above but
         * bi is independent. */
        block_index_status_set_valid_level(bi, BLOCK_VALID_SCRIPTS);
        phase_started = platform_time_monotonic_us();
        block_index_emit_status_event(bi, "script_validate", &g_header_event_emit_total, &g_header_event_emit_fail_total);
        reducer_stage_profile_observe_us(REDUCER_PROFILE_SCRIPT_VALIDATE,
                                         RPF_HEADER_EVENT_US,
                                  (uint64_t)(platform_time_monotonic_us() -
                                             phase_started));
    }

    phase_started = platform_time_monotonic_us();
    if (!script_validate_log_insert(db, next_h, status, ok, summary.tx_count,
                    summary.input_count, fail_txid, fail_vin, fail_serror,
                    bi->phashBlock))
        return sv_db_fault(sqlite3_extended_errcode(db), next_h,
                           "script_validate_log insert");
    reducer_stage_profile_observe_us(REDUCER_PROFILE_SCRIPT_VALIDATE,
                                     RPF_STAGE_LOG_CURSOR_US,
                              (uint64_t)(platform_time_monotonic_us() -
                                         phase_started));

    /* A height advanced cleanly: release any HOLD budget/named blocker so a
     * later hole restarts from scratch. */
    sv_unresolved_clear(db);
    atomic_store(&g_last_advance_height, (int64_t)next_h);
    c->cursor_out = c->cursor_in + 1;
    /* Clean advancing step — the infra-db fault retry budget resets. */
    stage_db_fault_clear(&g_sv_db_fault);
    return JOB_ADVANCED;
}

bool script_validate_stage_init(struct main_state *ms)
{
    if (!ms) LOG_FAIL("script_validate", "init: NULL main_state");

    sqlite3 *db = progress_store_db();
    if (!db) LOG_FAIL("script_validate",
        "init: progress_store not open");

    pthread_mutex_lock(&g_lock);
    if (g_stage != NULL) {
        bool same = (g_ms == ms);
        pthread_mutex_unlock(&g_lock);
        if (!same)
            LOG_FAIL("script_validate",
                "init: already bound to a different main_state");
        return true;
    }

    if (!script_validate_log_ensure_schema(db)) {
        pthread_mutex_unlock(&g_lock);
        return false;
    }

    GetDataDir(true, g_datadir, sizeof(g_datadir));

    stage_t *s = stage_create(STAGE_NAME, step_validate, NULL);
    if (!s) {
        pthread_mutex_unlock(&g_lock);
        LOG_FAIL("script_validate", "init: stage_create failed");
    }

    g_ms = ms;
    g_stage = s;
    /* Wire the production prevout resolver (P0 §2.1) unless a caller (e.g. a
     * test) already installed one. */
    if (!g_prevout)
        g_prevout = script_validate_created_index_prevout;
    pthread_mutex_unlock(&g_lock);

    LOG_INFO("script_validate", "[script_validate] stage initialised");
    return true;
}

STAGE_STEP_ONCE_SIMPLE(script_validate)

/* script_validate_stage_drain lives in script_validate_stage_drain.c: it is
 * hand-written (not STAGE_DRAIN_IMPL) so the per-batch prepared-statement caches
 * on the drain thread are finalized once the outer batch closes. */

void script_validate_stage_shutdown(void)
{
    /* Stop the shared verify worker pool before tearing down stage state so no
     * worker outlives the stage. Safe to call even if the pool never started. */
    script_verify_pool_shutdown();
    /* Finalize any residual per-batch statement caches (drain-end normally
     * clears them; this is the belt-and-suspenders teardown). */
    created_outputs_index_batch_reset();
    script_validate_prevout_batch_reset();
    script_validate_log_store_batch_reset();
    /* Registry hygiene (tests re-init in-process): both are re-derived from
     * live state the next time the condition fires, so clearing here loses
     * nothing. */
    stage_upstream_log_hole_clear(STAGE_NAME);
    stage_body_read_hold_clear(STAGE_NAME);
    pthread_mutex_lock(&g_lock);
    if (g_stage) {
        stage_destroy(g_stage);
        g_stage = NULL;
    }
    g_ms = NULL;
    g_datadir[0] = '\0';
    g_reader = NULL;
    g_reader_user = NULL;
    g_prevout = NULL;
    g_prevout_user = NULL;
    atomic_store(&g_verified_total, (uint64_t)0);
    atomic_store(&g_script_invalid_total, (uint64_t)0);
    atomic_store(&g_internal_error_total, (uint64_t)0);
    atomic_store(&g_upstream_failed_total, (uint64_t)0);
    script_validate_contextual_counters_reset();
    atomic_store(&g_inputs_verified_total, (uint64_t)0);
    atomic_store(&g_inputs_failed_total, (uint64_t)0);
    atomic_store(&g_last_step_unix, (int64_t)0);
    atomic_store(&g_last_blocked_unix, (int64_t)0);
    atomic_store(&g_last_advance_height, (int64_t)-1);
    atomic_store(&g_header_event_emit_total, (uint64_t)0);
    atomic_store(&g_header_event_emit_fail_total, (uint64_t)0);
    atomic_store(&g_sv_unresolved_height, (int64_t)-1);
    atomic_store(&g_sv_unresolved_since_unix, (int64_t)0);
    atomic_store(&g_sv_unresolved_paged_height, (int64_t)-1);
    stage_db_fault_clear(&g_sv_db_fault);
    pthread_mutex_unlock(&g_lock);
}

void script_validate_stage_set_reader(script_validate_reader_fn fn,
                                      void *user)
{
    pthread_mutex_lock(&g_lock);
    g_reader = fn;
    g_reader_user = user;
    pthread_mutex_unlock(&g_lock);
}

void script_validate_stage_set_prevout_resolver(script_validate_prevout_fn fn,
                                                void *user)
{
    pthread_mutex_lock(&g_lock);
    g_prevout = fn;
    g_prevout_user = user;
    pthread_mutex_unlock(&g_lock);
}

uint64_t script_validate_stage_cursor(void)
{
    return g_stage ? stage_cursor(g_stage) : 0;
}

int64_t script_validate_stage_step_us_ewma(void)
{
    return g_stage ? stage_step_us_ewma(g_stage) : 0;
}

uint64_t script_validate_stage_verified_total(void)
{
    return atomic_load(&g_verified_total);
}

uint64_t script_validate_stage_script_invalid_total(void)
{
    return atomic_load(&g_script_invalid_total);
}

uint64_t script_validate_stage_internal_error_total(void)
{
    return atomic_load(&g_internal_error_total);
}

uint64_t script_validate_stage_upstream_failed_total(void)
{
    return atomic_load(&g_upstream_failed_total);
}

uint64_t script_validate_stage_inputs_verified_total(void)
{
    return atomic_load(&g_inputs_verified_total);
}

stage_t *script_validate_stage_handle(void)
{
    return g_stage;
}

uint64_t script_validate_stage_inputs_failed_total(void)
{
    return atomic_load(&g_inputs_failed_total);
}

uint64_t script_validate_stage_header_event_emit_total(void)
{
    return atomic_load(&g_header_event_emit_total);
}

uint64_t script_validate_stage_header_event_emit_fail_total(void)
{
    return atomic_load(&g_header_event_emit_fail_total);
}

int64_t script_validate_stage_last_step_unix(void)
{
    return atomic_load(&g_last_step_unix);
}

int64_t script_validate_stage_last_blocked_unix(void)
{
    return atomic_load(&g_last_blocked_unix);
}

int64_t script_validate_stage_last_advance_height(void)
{
    return atomic_load(&g_last_advance_height);
}
