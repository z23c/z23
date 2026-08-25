/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * proof_validate_stage — implementation. See jobs/proof_validate_stage.h.
 *
 * Consumes script_validate_log and replays shielded proof verification
 * over block bodies that have already passed script_validate. It writes
 * proof_validate_log plus its stage cursor in progress.kv. */

#include "platform/time_compat.h"
#include "jobs/proof_validate_stage.h"
#include "jobs/stage_helpers.h"
#include "jobs/stage_body_index.h"
#include "proof_validate_log_store.h"
#include "proof_validate_stage_internal.h"
#include "proof_validate_trace.h"
#include "jobs/proof_validate_verify.h"
#include "script_validate_log_store.h"
#include "chain/chain.h"
#include "chain/chainparams.h"
#include "consensus/upgrades.h"
#include "crypto/ed25519.h"
#include "core/uint256.h"
#include "event/event.h"
#include "jobs/mint_skip_crypto.h"
#include "jobs/pv_lookahead.h"
#include "primitives/block.h"
#include "sapling/bn254.h"
#include "sapling/bls12_381.h"
#include "sapling/params_init.h"
#include "sapling/sapling.h"
#include "sapling/sapling_prover.h"
#include "sapling/sprout.h"
#include "util/safe_alloc.h"
#include "script/script.h"
#include "script/sighashtype.h"
#include "storage/disk_block_io.h"
#include "storage/progress_store.h"
#include "util/log_macros.h"
#include "util/reducer_stage_profile.h"
#include "util/stage.h"
#include "util/util.h"
#include "validation/main_state.h"
#include "validation/sighash.h"

#include <pthread.h>
#include <sqlite3.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define STAGE_NAME "proof_validate"
/* Log helpers live in proof_validate_log_store.c; the dump-state JSON view
 * lives in proof_validate_stage_dump.c. The block-level proof verification
 * (built-in verifier + serial reference + pool-parallel sweep, and the shared
 * struct proof_verify_summary) lives in proof_validate_verify.c — this file
 * owns the stage state machine, the cursor/log persistence, and the telemetry
 * atomics it applies through the reduce callbacks. */

static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static struct main_state *g_ms = NULL;
static stage_t *g_stage = NULL;
static char g_datadir[2048] = {0};
static proof_validate_reader_fn g_reader = NULL;
static void *g_reader_user = NULL;
static proof_validate_tx_verify_fn g_tx_verifier = NULL;
static void *g_tx_verifier_user = NULL;

static _Atomic uint64_t g_verified_total = 0;
static _Atomic uint64_t g_proof_invalid_total = 0;
static _Atomic uint64_t g_internal_error_total = 0;
static _Atomic uint64_t g_upstream_failed_total = 0;
static _Atomic uint64_t g_sapling_spends_verified_total = 0;
static _Atomic uint64_t g_sapling_spends_failed_total = 0;
static _Atomic uint64_t g_sapling_outputs_verified_total = 0;
static _Atomic uint64_t g_sapling_outputs_failed_total = 0;
static _Atomic uint64_t g_sprout_groth16_verified_total = 0;
static _Atomic uint64_t g_sprout_groth16_failed_total = 0;
static _Atomic uint64_t g_sprout_phgr13_verified_total = 0;
static _Atomic uint64_t g_sprout_phgr13_failed_total = 0;
static _Atomic uint64_t g_binding_sig_verified_total = 0;
static _Atomic uint64_t g_binding_sig_failed_total = 0;
static _Atomic int64_t  g_last_step_unix = 0;
static _Atomic int64_t  g_last_blocked_unix = 0;
static _Atomic int64_t  g_last_advance_height = -1;

/* TL-2 — HOLD-and-re-derive budget for the TRANSIENT internal_error class on
 * the proof path (e.g. a sapling_ctx allocation failure under memory pressure
 * on <8GB targets, or a transient verifier/decode glitch). Like the script
 * path's STEP-2A, the stage HOLDS the cursor (no terminal ok=0 row, no advance,
 * no EV_BLOCK_REJECTED) and re-derives the same height next tick — once the
 * transient clears (memory freed, params loaded) the SAME verification path
 * resolves it and the height advances ok=1. A bounded blocked-since budget
 * converts a genuinely irreducible internal_error into EXACTLY ONE named
 * PERMANENT blocker + EV_OPERATOR_NEEDED (naming height+txid+proof_type), never
 * a silent loop AND never a transient flipped into a permanent ok=0 reject.
 * g_pv_unresolved_height is the height currently held (-1 = none);
 * g_pv_unresolved_since_unix is when the hold began; g_pv_unresolved_paged_height
 * is the height we already paged the operator for (page once per episode).
 * The GENUINE proof-invalid verdict (a real bad proof) is unaffected — it still
 * writes ok=0 + advances below. */
#define PV_UNRESOLVED_BUDGET_SECONDS 600  /* 10 min held before naming a blocker */
static _Atomic int64_t g_pv_unresolved_height = -1;
static _Atomic int64_t g_pv_unresolved_since_unix = 0;
static _Atomic int64_t g_pv_unresolved_paged_height = -1;

/* Clear HOLD tracking after a clean advance so the next internal error gets a
 * fresh budget and releases the named blocker. */
static void pv_unresolved_clear(void)
{
    if (atomic_exchange(&g_pv_unresolved_height, (int64_t)-1) != (int64_t)-1) {
        atomic_store(&g_pv_unresolved_paged_height, (int64_t)-1);
        blocker_clear("proof_validate.internal_error");
    }
}

/* HOLD transient internal_error at `height`; after the budget, name one
 * permanent blocker and page once. Never advance or write a terminal row. */
static job_result_t pv_hold_unresolved(struct stage_step_ctx *c, int height,
                                       const struct uint256 *fail_txid,
                                       const char *fail_type)
{
    int64_t now = platform_time_wall_unix();
    if (atomic_load(&g_pv_unresolved_height) != (int64_t)height) {
        atomic_store(&g_pv_unresolved_height, (int64_t)height);
        atomic_store(&g_pv_unresolved_since_unix, now);
        atomic_store(&g_pv_unresolved_paged_height, (int64_t)-1);
        atomic_fetch_add(&g_internal_error_total, 1); /* once per held height */
    }
    int64_t since = atomic_load(&g_pv_unresolved_since_unix);
    int64_t elapsed = (since > 0 && now >= since) ? now - since : 0;
    atomic_store(&g_last_blocked_unix, now);

    if (elapsed < PV_UNRESOLVED_BUDGET_SECONDS)
        return JOB_IDLE; /* hold the cursor; the body re-derives next tick */

    char txhex[65] = {0};
    if (fail_txid)
        uint256_get_hex(fail_txid, txhex);
    char reason[BLOCKER_REASON_MAX];
    snprintf(reason, sizeof(reason),
             "proof_validate height=%d type=%s txid=%s held %llds: proof "
             "verification hit a transient internal_error that did not clear "
             "(sapling_ctx alloc / verifier fault)",
             height, fail_type ? fail_type : "internal", txhex,
             (long long)elapsed);
    if (!blocker_init(&c->blocker, "proof_validate.internal_error",
                      STAGE_NAME, BLOCKER_PERMANENT, reason)) {
        /* The internal_error anomaly is ALREADY detected (the budget lapsed and
         * the transient proof-verify fault did not clear) — not a legitimate
         * wait. Failing OPEN to JOB_IDLE would name nothing; latch JOB_FATAL so
         * the halt is surfaced via the fatal/operator-needed path (Task A #9). */
        LOG_WARN("proof_validate",
                 "[proof_validate] could not name internal_error blocker "
                 "height=%d — latching JOB_FATAL rather than failing open", height);
        return JOB_FATAL;
    }
    c->blocker.retry_budget = -1;
    /* Page the operator exactly once per held height (EXACTLY ONE escalation). */
    if (atomic_exchange(&g_pv_unresolved_paged_height, (int64_t)height) !=
        (int64_t)height)
        event_emitf(EV_OPERATOR_NEEDED, 0,
                    "proof_validate internal_error height=%d type=%s txid=%s "
                    "held %llds — H* cannot advance; transient proof-verify "
                    "fault did not clear",
                    height, fail_type ? fail_type : "internal", txhex,
                    (long long)elapsed);
    return JOB_BLOCKED;
}

/* ── Sub-phase profiling (util/reducer_stage_profile.h) ──────────────────
 * proof_validate is routinely quoted at "13-18 ms/block" with nothing behind
 * the figure: the stage had no sub-phase instrumentation at all, so the number
 * could not be attributed to body acquisition, the proof sweep, or the log
 * insert, and no per-proof cost was derivable. These helpers feed the
 * REDUCER_PROFILE_PROOF_VALIDATE domain. Timing calls are two GetTimeMicros()
 * reads around work that is already milliseconds long.
 *
 * SCOPE BOUNDARY: the Groth16-spend vs Groth16-output vs Sprout vs binding-sig
 * TIME split lives inside the per-tx sweep (app/jobs/src/proof_validate_verify.c)
 * and is not reachable from this file; what is emitted here is the sweep's
 * total plus the exact primitive COUNTS that sweep ran, which is the
 * denominator that split would divide. */
static inline void pv_profile_add(enum reducer_profile_field f, uint64_t v)
{
    reducer_stage_profile_add(REDUCER_PROFILE_PROOF_VALIDATE, f, v);
}

static inline void pv_profile_us(enum reducer_profile_field f, int64_t started)
{
    int64_t d = platform_time_monotonic_us() - started;
    reducer_stage_profile_observe_us(REDUCER_PROFILE_PROOF_VALIDATE, f,
                                     d > 0 ? (uint64_t)d : 0);
}

/* Reduce-order counter callbacks (proof_verify_success_cb /
 * proof_verify_failure_cb): proof_verify_block invokes these in ORIGINAL tx
 * order during its serial reduce, so the telemetry atomics see exactly the
 * serial-sweep ordering regardless of parallel verification. */
static void add_success_counters(const struct transaction *tx,
                                 const struct proof_validate_tx_report *r,
                                 void *user)
{
    (void)user;
    atomic_fetch_add(&g_sapling_spends_verified_total,
                     (uint64_t)r->sapling_spends_total);
    atomic_fetch_add(&g_sapling_outputs_verified_total,
                     (uint64_t)r->sapling_outputs_total);
    pv_profile_add(RPF_PV_SPENDS, (uint64_t)r->sapling_spends_total);
    pv_profile_add(RPF_PV_OUTPUTS, (uint64_t)r->sapling_outputs_total);
    for (size_t i = 0; tx && i < tx->num_joinsplit; i++) {
        if (tx->v_joinsplit[i].use_groth) {
            atomic_fetch_add(&g_sprout_groth16_verified_total, 1);
            pv_profile_add(RPF_PV_SPROUT_GROTH16, 1);
        } else {
            atomic_fetch_add(&g_sprout_phgr13_verified_total, 1);
            pv_profile_add(RPF_PV_SPROUT_PHGR13, 1);
        }
    }
    if (tx && (tx->num_shielded_spend > 0 ||
               tx->num_shielded_output > 0)) {
        atomic_fetch_add(&g_binding_sig_verified_total, 1);
        pv_profile_add(RPF_PV_BINDING_SIGS, 1);
    }
}

static void add_failure_counter(const char *type, void *user)
{
    (void)user;
    if (!type) return;
    if (strcmp(type, "sapling_spend") == 0)
        atomic_fetch_add(&g_sapling_spends_failed_total, 1);
    else if (strcmp(type, "sapling_output") == 0)
        atomic_fetch_add(&g_sapling_outputs_failed_total, 1);
    else if (strcmp(type, "sprout_groth16") == 0)
        atomic_fetch_add(&g_sprout_groth16_failed_total, 1);
    else if (strcmp(type, "sprout_phgr13") == 0)
        atomic_fetch_add(&g_sprout_phgr13_failed_total, 1);
    else if (strcmp(type, "binding_sig") == 0)
        atomic_fetch_add(&g_binding_sig_failed_total, 1);
}

static job_result_t step_validate(struct stage_step_ctx *c)
{
    atomic_store(&g_last_step_unix, platform_time_wall_unix());
    /* ZCL_PV_TRACE=1 narrates every reason this stage declines to advance.
     * proof_validate has several early returns that are deliberately silent
     * (they are normal "not yet" waits in a live sync), but on an OFFLINE
     * mint the same silence is indistinguishable from a wedge — and because
     * every downstream stage is pinned behind this cursor, the mint's stall
     * report blames whichever stage sits lowest instead of this one. */
    const bool pv_trace = pv_trace_enabled();
    if (pv_trace) {
        static _Atomic uint64_t entries;
        uint64_t n = atomic_fetch_add(&entries, 1u);
        if (n < 3u || n % 5000u == 0u)
            LOG_WARN(STAGE_NAME, "[pv-trace] step entered (call #%llu)",
                     (unsigned long long)n);
    }
    struct main_state *ms = g_ms;
    if (!ms) {
        if (pv_trace)
            LOG_WARN(STAGE_NAME, "[pv-trace] declined: main_state is NULL");
        return JOB_IDLE;
    }
    sqlite3 *db = progress_store_db();
    if (!db) {
        if (pv_trace)
            LOG_WARN(STAGE_NAME, "[pv-trace] declined: progress_store_db NULL");
        return JOB_IDLE;
    }
    int next_h = (int)c->cursor_in;
    if (next_h < 0) return JOB_FATAL;
    bool skip_crypto = mint_skip_crypto_get();
    enum mint_validation_evidence expected_evidence =
        mint_validation_evidence_expected(skip_crypto);
    uint64_t sv_cursor = 0;
    int64_t t_upstream = platform_time_monotonic_us();
    if (!stage_upstream_frontier_or_zero(db, "script_validate", STAGE_NAME,
                                   &sv_cursor))
        return JOB_FATAL;
    pv_profile_us(RPF_UPSTREAM_US, t_upstream);
    if ((uint64_t)next_h >= sv_cursor) {
        if (pv_trace)
            LOG_WARN(STAGE_NAME,
                     "[pv-trace] height=%d declined: upstream script_validate "
                     "derived frontier=%llu (raw stage_cursor=%llu, "
                     "script_validate_log rows=%lld) is not above it",
                     next_h, (unsigned long long)sv_cursor,
                     (unsigned long long)stage_cursor_persisted(
                         db, "script_validate", STAGE_NAME),
                     (long long)pv_trace_log_rows(db));
        atomic_store(&g_last_blocked_unix, platform_time_wall_unix());
        return JOB_IDLE;
    }
    struct script_validate_row upstream;
    int found = proof_validate_script_validate_log_at(db, next_h, &upstream);
    if (found < 0) return JOB_FATAL;
    if (found == 0 && pv_trace)
        LOG_WARN(STAGE_NAME,
                 "[pv-trace] height=%d declined: no script_validate_log row "
                 "despite frontier=%llu", next_h,
                 (unsigned long long)sv_cursor);
    if (found == 0) {
        /* Row missing despite floor — a durable upstream-log hole, not
         * "not yet" (see stage_upstream_log_hole_note). JOB_IDLE, never
         * JOB_BLOCKED: reducer_frontier_reconcile_light is the healer. */
        stage_upstream_log_hole_note(STAGE_NAME, "script_validate_log",
                                     next_h, sv_cursor, &g_last_blocked_unix);
        return JOB_IDLE;
    }
    stage_upstream_log_hole_clear(STAGE_NAME);
    struct block_index *bi = stage_body_index_at(ms, next_h);
    if (!bi || !(bi->nStatus & BLOCK_HAVE_DATA)) {
        /* SAY SO. This was a silent JOB_IDLE, and a silent idle here wedges
         * the whole pipeline without leaving a trace: proof_validate holds its
         * cursor, utxo_apply can never pass it, and the offline mint's stall
         * detector reports the LOWEST cursor — utxo_apply — as "the walled
         * stage", so the log accuses the one stage that is working correctly.
         * Deduplicated on height so a long wait costs one line, not a flood. */
        static _Atomic int64_t last_noted_h = -1;
        int64_t prev = atomic_exchange(&last_noted_h, (int64_t)next_h);
        if (prev != (int64_t)next_h)
            LOG_WARN(STAGE_NAME,
                     "[proof_validate] holding at height=%d: %s. Upstream "
                     "script_validate is at cursor=%llu, so this is not a "
                     "'not yet' — the selected block carries no readable body "
                     "in the in-memory index. proof_validate cannot advance, "
                     "and every downstream stage is pinned behind it.",
                     next_h,
                     !bi ? "no block_index entry for the selected height"
                         : "block_index entry has no BLOCK_HAVE_DATA",
                     (unsigned long long)sv_cursor);
        atomic_store(&g_last_blocked_unix, platform_time_wall_unix());
        return JOB_IDLE;
    }
    bool verdict_canonical = upstream.ok == 0 || upstream.ok == 1;
    if (verdict_canonical)
        proof_validate_upstream_verdict_clear();
    if (!proof_validate_upstream_hash_ready(
            next_h, bi->phashBlock, upstream.has_block_hash,
            &upstream.block_hash)) {
        atomic_store(&g_last_blocked_unix, platform_time_wall_unix());
        return JOB_IDLE;
    }
    if (!verdict_canonical)
        return proof_validate_upstream_verdict_refuse(c, next_h, upstream.ok);
    if (upstream.ok == 1 && upstream.evidence != expected_evidence) {
        if (pv_trace)
            LOG_WARN(STAGE_NAME,
                     "[pv-trace] height=%d declined: evidence mismatch "
                     "got=%s expected=%s (skip_crypto=%d)",
                     next_h, mint_validation_evidence_status(upstream.evidence),
                     mint_validation_evidence_status(expected_evidence),
                     (int)skip_crypto);
        return proof_validate_upstream_evidence_refuse(
            c, next_h, expected_evidence, upstream.evidence);
    }
    proof_validate_upstream_evidence_clear();
    if (upstream.ok == 0) {
        if (!proof_validate_log_insert(db, next_h, "upstream_failed", false,
                        0, 0, 0, bi->phashBlock, NULL, NULL))
            return JOB_FATAL;
        atomic_fetch_add(&g_upstream_failed_total, 1);
        pv_unresolved_clear();
        atomic_store(&g_last_advance_height, (int64_t)next_h);
        c->cursor_out = c->cursor_in + 1;
        return JOB_ADVANCED;
    }
    struct proof_verify_summary summary;
    struct pv_lookahead_verdict cached;
    if (!skip_crypto &&
        pv_lookahead_take(next_h, bi->phashBlock, g_tx_verifier,
                          g_tx_verifier_user, &cached)) {
        /* LOOKAHEAD HIT (jobs/pv_lookahead.h; the pool is started by the
         * -mint-anchor drive and, under -pv-lookahead, by the live/replay
         * boot path): a worker already verified this exact
         * (height, block_hash) with the same effective verifier, so the verdict
         * IS what the serial sweep below would compute (proof verification is a
         * pure function of block bytes + verifying keys). internal_error is
         * never cached, so the TL-2 HOLD path below stays inline-only. The
         * block read and its params wait gate are not needed on a hit: the
         * worker proved the body readable, and a shielded block can only be
         * cached after the keys loaded (the worker mirrors the gate). */
        proof_verify_summary_init(&summary);
        summary.ok = cached.ok;
        summary.sapling_spends_total = cached.sapling_spends_total;
        summary.sapling_outputs_total = cached.sapling_outputs_total;
        summary.sprout_joinsplits_total = cached.sprout_joinsplits_total;
        summary.first_failure_txid = cached.first_failure_txid;
        summary.first_failure_proof_type = cached.first_failure_proof_type;
        /* Apply the worker-accumulated serial-reduce counter deltas; the drive
         * consumes heights in strict serial order, so every counter equals the
         * serial sweep's value at each block boundary. */
        atomic_fetch_add(&g_sapling_spends_verified_total,
                         cached.spends_verified);
        atomic_fetch_add(&g_sapling_outputs_verified_total,
                         cached.outputs_verified);
        atomic_fetch_add(&g_sprout_groth16_verified_total,
                         cached.sprout_groth16_verified);
        atomic_fetch_add(&g_sprout_phgr13_verified_total,
                         cached.sprout_phgr13_verified);
        atomic_fetch_add(&g_binding_sig_verified_total,
                         cached.binding_sig_verified);
        if (!cached.ok)
            add_failure_counter(cached.first_failure_proof_type, NULL);
        pv_profile_add(RPF_PV_LOOKAHEAD_HITS, 1);
        pv_profile_add(RPF_PV_SPENDS, cached.spends_verified);
        pv_profile_add(RPF_PV_OUTPUTS, cached.outputs_verified);
        pv_profile_add(RPF_PV_SPROUT_GROTH16, cached.sprout_groth16_verified);
        pv_profile_add(RPF_PV_SPROUT_PHGR13, cached.sprout_phgr13_verified);
        pv_profile_add(RPF_PV_BINDING_SIGS, cached.binding_sig_verified);
        stage_body_read_hold_clear(STAGE_NAME);
    } else {
    /* Lookahead consulted and missed. skip_crypto never consults it, so that
     * pass-through is neither a hit nor a miss. */
    if (!skip_crypto)
        pv_profile_add(RPF_PV_LOOKAHEAD_MISSES, 1);
    struct block owned;
    struct block_parse_handle handle;
    const struct block *blk = NULL;
    bool borrowed = false;
    /* Body acquisition. In production this is a block_parse_cache acquire, so
     * it is normally a shared-cache hit populated by body_persist rather than
     * a disk read + deserialize — whether that is true on a live fold is
     * exactly what this measurement answers. */
    int64_t t_acquire = platform_time_monotonic_us();
    if (!stage_acquire_block_view(&owned, &handle, &blk, &borrowed,
                                  bi, next_h, g_datadir,
                                  g_reader, g_reader_user)) {
        pv_profile_us(RPF_PV_BODY_ACQUIRE_US, t_acquire);
        block_free(&owned);
        /* body_persist already hash+merkle verified this body — a later
         * read failure is not a normal wait (see stage_body_read_hold). */
        return stage_body_read_hold(STAGE_NAME, next_h, bi->phashBlock,
                                    &g_last_blocked_unix);
    }
    pv_profile_us(RPF_PV_BODY_ACQUIRE_US, t_acquire);
    stage_body_read_hold_clear(STAGE_NAME);
    /* The sapling-params wait gate is a VERIFICATION precondition; in the
     * OFFLINE FAST-MINT pass-through we never call the proof verifier, so the
     * params need not be loaded. Keep the gate ONLY when actually verifying. */
    if (!skip_crypto && !g_tx_verifier &&
        proof_verify_block_has_shielded_proofs(blk) &&
        !sapling_params_loaded()) {
        stage_release_block_view(&owned, &handle, borrowed);
        atomic_store(&g_last_blocked_unix, platform_time_wall_unix());
        /* The zk verification keys are not loaded yet and this block carries
         * shielded proofs that REQUIRE them. The LOADER (load_params_thread,
         * boot.c) is the AUTHORITY for this blocker: it names PERMANENT
         * "params_missing" ONLY on a genuine corrupt/parse failure. During the
         * NORMAL in-flight background load g_params_loaded is still false with
         * nothing wrong, so naming a PERMANENT blocker here would convert a
         * transient param-load window into a wedge. Only RE-SURFACE the loader's
         * blocker (it already declared it permanent) as JOB_BLOCKED; otherwise
         * HOLD the cursor (JOB_IDLE) and re-derive next tick — once the keys
         * finish loading the same height advances. proof_validate never SETS the
         * blocker, so no blocker_clear is needed. */
        if (!blocker_exists("params_missing"))
            return JOB_IDLE; /* transient load window; re-derive next tick */
        /* The loader ALREADY declared params_missing PERMANENT (a genuine
         * corrupt/parse failure — an anomaly, still registry-visible here).
         * Re-surfacing it as this stage's blocker cannot fail on the literal
         * id/owner, but if it ever did, failing OPEN to JOB_IDLE would silently
         * spin on an unvalidatable shielded block; latch JOB_FATAL instead so
         * the permanent params_missing halt is surfaced (Task A #9). */
        if (!blocker_init(&c->blocker, "params_missing", "crypto.params",
                          BLOCKER_PERMANENT,
                          "zk verification keys not loaded; shielded-proof block "
                          "cannot be validated"))
            return JOB_FATAL; /* blocker_init logged the reason; latch fatal */
        return JOB_BLOCKED;
    }

    if (skip_crypto) {
        /* OFFLINE FAST-MINT pass-through (jobs/mint_skip_crypto.h): the
         * -mint-anchor-fast driver set the toggle. SKIP validate_block_proofs
         * (Groth16 / Ed25519 / PHGR13 / binding-sig) and synthesize an advancing
         * summary with durable status "checkpoint_fold", never "verified". The
         * coin SET is unaffected (utxo_apply is the state
         * transition; proofs only authorize shielded value, they do not change
         * which outpoints a block consumes). The terminal SHA3==checkpoint
         * assertion certifies only the transparent fold, not skipped proofs. A
         * divergence still aborts without publishing the minted DB. Default OFF
         * → a normal boot never reaches this branch. */
        proof_verify_summary_init(&summary);   /* ok=1, internal_error=0 */
    } else {
        /* Production path: fan per-tx shielded-proof verification across the
         * worker pool, then reduce in original tx order — the add_success /
         * add_failure counter callbacks fire in serial-sweep order. */
        int64_t t_verify = platform_time_monotonic_us();
        proof_verify_block(blk, next_h, g_tx_verifier, g_tx_verifier_user,
                           true, add_success_counters, add_failure_counter,
                           NULL, &summary);
        pv_profile_us(RPF_PV_VERIFY_US, t_verify);
    }
    stage_release_block_view(&owned, &handle, borrowed);
    }

    /* TL-2: the internal_error class is a TRANSIENT "could not complete proof
     * verification yet" (a sapling_ctx allocation failure under memory pressure
     * on <8GB targets, or a transient verifier/decode fault) — NOT a permanent
     * bad-proof reject. Mirror the script path STEP-2A: HOLD the cursor and
     * re-derive next tick — do NOT insert a terminal ok=0 row, do NOT advance the
     * cursor, do NOT emit EV_BLOCK_REJECTED. A bounded blocked-since budget turns
     * a genuinely irreducible internal_error into one named PERMANENT blocker
     * (pv_hold_unresolved), never a silent loop and never a transient frozen as a
     * false ok=0 reject (the very wedge the script path already cured). */
    if (!summary.ok && summary.internal_error)
        return pv_hold_unresolved(c, next_h, &summary.first_failure_txid,
                                  summary.first_failure_proof_type);

    const char *status = skip_crypto ? "checkpoint_fold" : "verified";
    bool ok = true;
    const struct uint256 *fail_txid = NULL;
    const char *fail_type = NULL;
    char fail_txid_hex[65] = {0};
    if (!summary.ok) {
        /* TL-2 holds the internal_error class above, so a !ok summary here is a
         * GENUINE proof-invalid verdict (a real bad proof): write the terminal
         * ok=0 row and advance the cursor — this path is unchanged. */
        uint256_get_hex(&summary.first_failure_txid, fail_txid_hex);
        fail_txid = &summary.first_failure_txid;
        fail_type = summary.first_failure_proof_type;
        status = "proof_invalid";
        ok = false;
        atomic_fetch_add(&g_proof_invalid_total, 1);
        event_emitf(EV_BLOCK_REJECTED, 0,
                    "proof_validate proof_invalid height=%d type=%s txid=%s",
                    next_h, fail_type ? fail_type : "unknown", fail_txid_hex);
    } else if (!skip_crypto) {
        atomic_fetch_add(&g_verified_total, 1);
    }

    int64_t t_insert = platform_time_monotonic_us();
    if (!proof_validate_log_insert(db, next_h, status, ok,
                    summary.sapling_spends_total,
                    summary.sapling_outputs_total,
                    summary.sprout_joinsplits_total, bi->phashBlock,
                    fail_txid, fail_type))
        return JOB_FATAL;
    pv_profile_us(RPF_PV_LOG_INSERT_US, t_insert);

    /* A height advanced cleanly: release any HOLD budget/named blocker so a
     * later internal_error restarts the budget clock from scratch. */
    pv_unresolved_clear();
    atomic_store(&g_last_advance_height, (int64_t)next_h);
    c->cursor_out = c->cursor_in + 1;
    return JOB_ADVANCED;
}
bool proof_validate_stage_init(struct main_state *ms)
{
    if (!ms) LOG_FAIL("proof_validate", "init: NULL main_state");
    sqlite3 *db = progress_store_db();
    if (!db) LOG_FAIL("proof_validate", "init: progress_store not open");
    pthread_mutex_lock(&g_lock);
    if (g_stage != NULL) {
        bool same = (g_ms == ms);
        pthread_mutex_unlock(&g_lock);
        if (!same)
            LOG_FAIL("proof_validate",
                "init: already bound to a different main_state");
        return true;
    }
    if (!proof_validate_log_ensure_schema(db) ||
        !script_validate_log_ensure_schema(db)) {
        pthread_mutex_unlock(&g_lock);
        return false;
    }

    GetDataDir(true, g_datadir, sizeof(g_datadir));

    stage_t *s = stage_create(STAGE_NAME, step_validate, NULL);
    if (!s) {
        pthread_mutex_unlock(&g_lock);
        LOG_FAIL("proof_validate", "init: stage_create failed");
    }

    g_ms = ms;
    g_stage = s;
    pthread_mutex_unlock(&g_lock);

    LOG_INFO("proof_validate", "[proof_validate] stage initialised");
    return true;
}

STAGE_STEP_ONCE_SIMPLE(proof_validate)

STAGE_DRAIN_IMPL(proof_validate)

bool proof_validate_lookahead_start(void)
{
    /* Snapshot the stage's binding under g_lock so the pool starts with the
     * EXACT (main_state, datadir, reader, verifier) tuple step_validate uses —
     * pv_lookahead_take re-checks the verifier pair on every consume, so a
     * later set_tx_verifier turns the cache into a permanent miss instead of a
     * mixed-verifier verdict. */
    pthread_mutex_lock(&g_lock);
    struct main_state *ms = g_ms;
    char datadir[sizeof(g_datadir)];
    snprintf(datadir, sizeof(datadir), "%s", g_datadir);
    proof_validate_reader_fn reader = g_reader;
    void *reader_user = g_reader_user;
    proof_validate_tx_verify_fn verifier = g_tx_verifier;
    void *verifier_user = g_tx_verifier_user;
    pthread_mutex_unlock(&g_lock);
    if (!ms)
        LOG_FAIL("proof_validate",
                 "[proof_validate] lookahead start: stage not initialised");
    return pv_lookahead_start(ms, datadir, reader, reader_user,
                              verifier, verifier_user);
}

void proof_validate_lookahead_stop(void)
{
    pv_lookahead_stop();
}

void proof_validate_stage_shutdown(void)
{
    /* Stop the mint lookahead pool first (idempotent; a no-op unless a mint
     * drive started it), then the shared verify worker pool, before tearing
     * down stage state so no worker outlives the stage. */
    pv_lookahead_stop();
    proof_verify_pool_shutdown();
    proof_validate_upstream_hash_clear();
    proof_validate_upstream_verdict_clear();
    proof_validate_upstream_evidence_clear();
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
    g_tx_verifier = NULL;
    g_tx_verifier_user = NULL;
    atomic_store(&g_verified_total, (uint64_t)0);
    atomic_store(&g_proof_invalid_total, (uint64_t)0);
    atomic_store(&g_internal_error_total, (uint64_t)0);
    atomic_store(&g_upstream_failed_total, (uint64_t)0);
    atomic_store(&g_sapling_spends_verified_total, (uint64_t)0);
    atomic_store(&g_sapling_spends_failed_total, (uint64_t)0);
    atomic_store(&g_sapling_outputs_verified_total, (uint64_t)0);
    atomic_store(&g_sapling_outputs_failed_total, (uint64_t)0);
    atomic_store(&g_sprout_groth16_verified_total, (uint64_t)0);
    atomic_store(&g_sprout_groth16_failed_total, (uint64_t)0);
    atomic_store(&g_sprout_phgr13_verified_total, (uint64_t)0);
    atomic_store(&g_sprout_phgr13_failed_total, (uint64_t)0);
    atomic_store(&g_binding_sig_verified_total, (uint64_t)0);
    atomic_store(&g_binding_sig_failed_total, (uint64_t)0);
    atomic_store(&g_last_step_unix, (int64_t)0);
    atomic_store(&g_last_blocked_unix, (int64_t)0);
    atomic_store(&g_last_advance_height, (int64_t)-1);
    /* TL-2 HOLD tracking reset (clears the named blocker if one is live). */
    pv_unresolved_clear();
    atomic_store(&g_pv_unresolved_height, (int64_t)-1);
    atomic_store(&g_pv_unresolved_since_unix, (int64_t)0);
    atomic_store(&g_pv_unresolved_paged_height, (int64_t)-1);
    pthread_mutex_unlock(&g_lock);
}

void proof_validate_stage_set_reader(proof_validate_reader_fn fn, void *user)
{
    pthread_mutex_lock(&g_lock);
    g_reader = fn;
    g_reader_user = user;
    pthread_mutex_unlock(&g_lock);
}

void proof_validate_stage_set_tx_verifier(proof_validate_tx_verify_fn fn,
                                          void *user)
{
    pthread_mutex_lock(&g_lock);
    g_tx_verifier = fn;
    g_tx_verifier_user = user;
    pthread_mutex_unlock(&g_lock);
}

uint64_t proof_validate_stage_cursor(void) { return g_stage ? stage_cursor(g_stage) : 0; }
int64_t  proof_validate_stage_step_us_ewma(void)
{ return g_stage ? stage_step_us_ewma(g_stage) : 0; }

stage_t *proof_validate_stage_handle(void)
{
    return g_stage;
}

int64_t proof_validate_stage_last_step_unix(void)
{
    return atomic_load(&g_last_step_unix);
}

int64_t proof_validate_stage_last_blocked_unix(void)
{
    return atomic_load(&g_last_blocked_unix);
}

int64_t proof_validate_stage_last_advance_height(void)
{
    return atomic_load(&g_last_advance_height);
}

uint64_t proof_validate_stage_verified_total(void)
{
    return atomic_load(&g_verified_total);
}

uint64_t proof_validate_stage_proof_invalid_total(void)
{
    return atomic_load(&g_proof_invalid_total);
}

uint64_t proof_validate_stage_internal_error_total(void)
{
    return atomic_load(&g_internal_error_total);
}

uint64_t proof_validate_stage_upstream_failed_total(void)
{
    return atomic_load(&g_upstream_failed_total);
}

uint64_t proof_validate_stage_sapling_spends_verified_total(void)
{
    return atomic_load(&g_sapling_spends_verified_total);
}

uint64_t proof_validate_stage_sapling_spends_failed_total(void)
{
    return atomic_load(&g_sapling_spends_failed_total);
}

uint64_t proof_validate_stage_sapling_outputs_verified_total(void)
{
    return atomic_load(&g_sapling_outputs_verified_total);
}

uint64_t proof_validate_stage_sapling_outputs_failed_total(void)
{
    return atomic_load(&g_sapling_outputs_failed_total);
}

uint64_t proof_validate_stage_sprout_groth16_verified_total(void)
{
    return atomic_load(&g_sprout_groth16_verified_total);
}

uint64_t proof_validate_stage_sprout_groth16_failed_total(void)
{
    return atomic_load(&g_sprout_groth16_failed_total);
}

uint64_t proof_validate_stage_sprout_phgr13_verified_total(void)
{
    return atomic_load(&g_sprout_phgr13_verified_total);
}

uint64_t proof_validate_stage_sprout_phgr13_failed_total(void)
{
    return atomic_load(&g_sprout_phgr13_failed_total);
}

uint64_t proof_validate_stage_binding_sig_verified_total(void)
{
    return atomic_load(&g_binding_sig_verified_total);
}

uint64_t proof_validate_stage_binding_sig_failed_total(void)
{
    return atomic_load(&g_binding_sig_failed_total);
}
