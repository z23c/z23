/* Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright (c) 2014-2017 The Zcash developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */

#define _GNU_SOURCE  /* pthread_timedjoin_np */

/*
 *
 * Background Full Validation Service
 * -----------------------------------
 * After fast sync via FlyClient + SHA3, walks every locally-derived block
 * and verifies all cryptographic proofs:
 *   - Equihash PoW solutions
 *   - ECDSA script signatures (every input of every transaction)
 *   - Ed25519 JoinSplit signatures
 *   - Sapling Groth16 spend/output proofs + binding signatures
 *   - Sprout Groth16 JoinSplit proofs
 *   - Merkle root integrity
 *
 * Walk extent: a fresh walk starts at the external-seed floor + 1
 * (REDUCER_SEED_FLOOR_HEIGHT_KEY) when one is declared — the floor is
 * written ONCE, only by a genuine external-seed path (cold-import wedge
 * heal, consensus-state bundle install); the extent at/below it is
 * certified by the sealed compiled checkpoint + the SHA3-verified snapshot
 * seed and has no undo data to script-verify against — and at genesis
 * otherwise (a from-genesis or reindexed datadir declares no floor; that
 * full-history walk is the replay-canary --from=genesis exact tier).
 * The advancing trusted base (REDUCER_TRUSTED_BASE_HEIGHT_KEY) is NOT the
 * floor: tip_finalize keeps raising it toward tip as anchors finalize, so
 * by bg-validation start it can sit at ~tip and zero the walk out (the
 * 306-second anchor-canary FAIL that proved this).
 *
 * Uses a thread pool for parallel script verification within each block.
 * Saves progress to SQLite every 1000 blocks for crash-resume.
 * Resets g_deferred_proof_validation_below_height = -1 when complete.
 */

// one-result-type-ok:validation-progress-result
//
// The service result of this file is the validation PROGRESS — a single
// coherent type carried by struct bg_validation_progress (returned by
// bg_validation_get_progress) and the enum bg_validation_state within it
// (IDLE/RUNNING/PAUSED/COMPLETE/FAILED). A validation failure surfaces as
// progress.state = BG_VALIDATION_FAILED, not a reason-less bool.
// The bool/int helpers do NOT strip a failure reason:
//   - read_block_undo(), validate_block_proofs(), bg_validation_start() each
//     LOG_FAIL / LOG_WARN (with state.reject_reason) on every failure branch.
//   - load_progress() returns a height-or-sentinel and LOG_ERRs when absent.
//   - bg_validation_state_name() is the enum->name table.
// init/stop/reset are void lifecycle. Behavior bit-for-bit.

#include "platform/time_compat.h"
#include "services/bg_validation_service.h"
#include "services/bg_validation_authority.h"
#include "bg_validation_internal.h"
#include "supervisors/domains.h"
#include "validation/main_state.h"
#include "validation/chainstate.h"
#include "validation/check_block.h"
#include "validation/contextual_check_tx.h"
#include "validation/sighash.h"
#include "validation/tx_verifier.h"
#include "validation/main_constants.h"
#include "consensus/upgrades.h"
#include "consensus/validation.h"
#include "storage/disk_block_io.h"
#include "coins/undo.h"
#include "script/interpreter.h"
#include "script/script_flags.h"
#include "crypto/ed25519.h"
#include "sapling/sprout.h"
#include "sapling/bn254.h"
#include "sapling/sapling_prover.h"
#include "models/database.h"
#include "ports/bg_validation_store_port.h"
#include "jobs/reducer_frontier.h"           /* reducer_seed_floor_height_read */
#include "jobs/utxo_apply_delta_undo.h"      /* bg_validation_applied_next */
#include "storage/progress_store.h"          /* progress_store_db */
#include "event/event.h"
#include "platform/rng.h"
#include "util/blocker.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sched.h>
#include "platform/allocator_compat.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"
#include "util/supervisor.h"
#include "util/thread_qos.h"
#include "util/thread_registry.h"

/* Global instance for RPC access */
struct bg_validation_service *g_bg_validation = NULL;

/* The crash-resume cursor (state key "bg_validation_height") now lives
 * behind bg_validation_store_port; the sqlite adapter owns the key. */

/* ── How often to save progress and log ─────────────────────── */
#define SAVE_INTERVAL  1000
#define LOG_INTERVAL   10000
#define BG_VALIDATION_SUPERVISOR_DEADLINE_SEC 600
/* Idle gap between sampled re-verifies (post-COMPLETE). Deliberately long so
 * the always-on re-verify stays a low-rate background witness and NEVER
 * competes with the fold hot path — ~2 samples/min plus each sample's own
 * verify time. Respects the same stop_requested wake as the main walk. */
#define BG_REVERIFY_IDLE_SECS  30

static bool bg_validation_coverage_version_current(int64_t version)
{
    return version == BG_VALIDATION_COVERAGE_VERSION;
}

static _Atomic supervisor_child_id g_bg_validation_supervisor_id =
    SUPERVISOR_INVALID_ID;
static struct liveness_contract g_bg_validation_contract;

static int64_t bg_validation_progress_marker(
    const struct bg_validation_service *svc)
{
    if (!svc)
        LOG_RETURN((int64_t)-1, "bg_validation",
                   "bg_validation_progress_marker: null svc");
    return atomic_load(&svc->progress.verified_height);
}

void bg_validation_supervisor_heartbeat(
    const struct bg_validation_service *svc)
{
    supervisor_child_id id = atomic_load(&g_bg_validation_supervisor_id);
    if (id == SUPERVISOR_INVALID_ID)
        return;
    supervisor_tick(id);
    supervisor_progress(id, bg_validation_progress_marker(svc));
}

static void bg_validation_supervisor_done(void)
{
    supervisor_child_id id = atomic_load(&g_bg_validation_supervisor_id);
    if (id != SUPERVISOR_INVALID_ID)
        supervisor_set_deadline(id, 0);
}

static void bg_validation_on_stall(struct liveness_contract *c)
{
    const struct bg_validation_service *svc =
        c ? (const struct bg_validation_service *)c->ctx : NULL;
    const char *reason = c
        ? supervisor_stall_reason_name(
              (enum supervisor_stall_reason)atomic_load(&c->stall_reason))
        : "unknown";
    int verified = svc ? atomic_load(&svc->progress.verified_height) : -1;
    int chain_height = svc ? atomic_load(&svc->progress.chain_height) : -1;
    int state = svc ? atomic_load(&svc->progress.state) : BG_VALIDATION_IDLE;
    int64_t sigs = svc ? atomic_load(&svc->progress.sigs_verified) : 0;
    int64_t proofs = svc ? atomic_load(&svc->progress.proofs_verified) : 0;
    LOG_WARN("bg_validation",
             "[bg-valid] supervisor stall reason=%s verified=%d chain_height=%d state=%s sigs=%lld proofs=%lld",
             reason, verified, chain_height,
             bg_validation_state_name((enum bg_validation_state)state),
             (long long)sigs, (long long)proofs);
    event_emitf(EV_CHAIN_ADVANCE_DECISION, 0,
                "source=chain.bg_validation decision=worker_stall "
                "reason=%s verified=%d chain_height=%d state=%s sigs=%lld proofs=%lld",
                reason, verified, chain_height,
                bg_validation_state_name((enum bg_validation_state)state),
                (long long)sigs, (long long)proofs);
}

static bool bg_validation_register_supervisor(
    struct bg_validation_service *svc)
{
    if (!supervisor_start()) {
        LOG_FAIL("bg_validation", "bg_validation_start: supervisor_start failed");
        return false;
    }

    supervisor_child_id id = atomic_load(&g_bg_validation_supervisor_id);
    if (id != SUPERVISOR_INVALID_ID) {
        supervisor_set_deadline(id, BG_VALIDATION_SUPERVISOR_DEADLINE_SEC);
        supervisor_progress(id, bg_validation_progress_marker(svc));
        supervisor_tick(id);
        return true;
    }

    liveness_contract_init(&g_bg_validation_contract, "chain.bg_validation");
    atomic_store(&g_bg_validation_contract.period_secs, 0);
    atomic_store(&g_bg_validation_contract.deadline_secs,
                 BG_VALIDATION_SUPERVISOR_DEADLINE_SEC);
    atomic_store(&g_bg_validation_contract.progress_max_quiet_us, 0);
    g_bg_validation_contract.ctx = svc;
    g_bg_validation_contract.on_stall = bg_validation_on_stall;

    supervisor_domains_init();
    id = supervisor_register_in_domain(g_chain_sup, &g_bg_validation_contract);
    if (id == SUPERVISOR_INVALID_ID) {
        LOG_FAIL("bg_validation", "bg_validation_start: supervisor_register failed");
        return false;
    }
    atomic_store(&g_bg_validation_supervisor_id, id);
    supervisor_progress(id, bg_validation_progress_marker(svc));
    supervisor_tick(id);
    return true;
}

/* Proof and script workers live in the sibling bg_validation_*.c units. */

/* ── Load/save progress from SQLite ──────────────────────────── */

static int load_progress(const struct bg_validation_store_port *store)
{
    int val = -1;
    if (store && store->load_progress &&
        store->load_progress(store->self, &val))
        return val;
    LOG_ERR("bgv", "no saved progress found");
}

static void save_progress(const struct bg_validation_store_port *store,
                          int height)
{
    if (store && store->save_progress)
        store->save_progress(store->self, height);
}

/* Cumulative non-coinbase txs not script-verified (undo missing). Persisted
 * under a separate key so the tally survives restarts. -1 = never written. */
static int64_t load_skips(const struct bg_validation_store_port *store)
{
    int64_t val = -1;
    if (store && store->load_skips &&
        store->load_skips(store->self, &val))
        return val;
    return -1; // raw-return-ok:no-key-on-fresh-datadir-means-zero-skips-not-an-error
}

static void save_skips(const struct bg_validation_store_port *store,
                       int64_t skips)
{
    if (store && store->save_skips)
        store->save_skips(store->self, skips);
}

static int64_t load_coverage_version(
    const struct bg_validation_store_port *store)
{
    int64_t version = 0;
    if (store && store->load_coverage_version)
        store->load_coverage_version(store->self, &version);
    return version;
}

static bool save_coverage_version(
    const struct bg_validation_store_port *store, int64_t version)
{
    return store && store->save_coverage_version &&
           store->save_coverage_version(store->self, version);
}

/* ── Stay behind the fold ─────────────────────────────────────
 * For a height this node connected, the spent outputs live in the delta row
 * the utxo_apply stage co-commits with its cursor. The active chain can run
 * ahead of that cursor by the pipeline depth, so verifying such a height
 * would turn a transient absence into a permanent skip in the walk census.
 *
 * bg_validation_applied_next() reads the stage's durable next-to-apply
 * height. It returns UINT64_MAX (nothing to wait for) when the store is not
 * open or the stage has never committed on it, and 0 on a read error so the
 * caller re-probes instead of trusting a stale value. */
static uint64_t bg_validation_applied_next(void)
{
    sqlite3 *db = progress_store_db();
    if (!db)
        return UINT64_MAX;
    uint64_t next = 0;
    bool found = false;
    if (!utxo_apply_delta_undo_next_unapplied(db, &next, &found))
        return 0; // raw-return-ok:read-error-logged-by-probe-caller-reprobes
    return found ? next : UINT64_MAX;
}

/* One stop-responsive, heartbeating second of waiting on the fold. The
 * reason is logged on the first wait at a height and then once a minute, so
 * a wedged reducer is named without flooding the log. */
static void bg_validation_fold_backoff(struct bg_validation_service *svc,
                                       int h, const char *reason,
                                       unsigned *waits)
{
    if (*waits % 60 == 0)
        LOG_INFO("bg_validation",
                 "[bg-valid] h=%d waits for the reducer: %s (waited %us)",
                 h, reason, *waits);
    (*waits)++;
    bg_validation_supervisor_heartbeat(svc);
    if (!atomic_load(&svc->stop_requested))
        platform_sleep_ms(1000);
}

/* Wait until the reducer has applied `h`. `*applied_next` caches the last
 * observed cursor so the store is read only when the walk reaches it. An
 * unreadable cursor is waited out like an unapplied height: verifying
 * without knowing the frontier could book a transient absence as a
 * permanent skip. Returns false only when stop is requested. */
static bool bg_validation_wait_until_applied(
    struct bg_validation_service *svc, int h, uint64_t *applied_next)
{
    unsigned waits = 0;
    while (!atomic_load(&svc->stop_requested)) {
        if ((uint64_t)h < *applied_next)
            return true;
        uint64_t next = bg_validation_applied_next();
        if (next != 0)
            *applied_next = next;
        if ((uint64_t)h < *applied_next)
            return true;
        bg_validation_fold_backoff(
            svc, h, next == 0 ? "utxo_apply cursor unreadable"
                              : "height not applied yet", &waits);
    }
    return false;
}

/* Why this height's delta row cannot be trusted yet, or NULL when it is
 * either resolved (FOUND/ABSENT) or the store has no fold at all. Restores
 * the exact cursor comparison the walk needs: a rewind can pull the fold's
 * cursor back under a cached value, and "height no longer applied" is a
 * real reason to wait, not a bug. After the active chain switches branches
 * the fold still holds the abandoned block's delta row at `h` until it
 * rewinds: neither is a missing undo, both resolve once the reducer
 * catches up. A store error is also retried: the answer is unknown, not
 * negative. The cursor read is purely internal — nothing outside this
 * function needs its value, only the reason string.
 *
 * Deliberately CHEAP — one SQLite point read, no block body, no crypto —
 * so it can run every attempt of the backoff below (or after a full
 * validation, on the pindex that validation actually used) without ever
 * itself paying for a full block re-validation while the fold races. */
static const char *bg_validation_row_unresolved_reason(
    int h, const struct block_index *pindex)
{
    uint64_t applied_next = bg_validation_applied_next();
    if (applied_next == 0)
        return "utxo_apply cursor unreadable";
    if (applied_next == UINT64_MAX)
        return NULL;  /* this store has no fold: nothing will ever appear */
    if ((uint64_t)h >= applied_next)
        return "height no longer applied";
    if (!pindex || !pindex->phashBlock)
        return NULL;
    progress_store_tx_lock();
    sqlite3 *db = progress_store_db();
    enum utxo_apply_delta_undo_status row = db
        ? utxo_apply_delta_undo_row_branch(db, h, pindex->phashBlock)
        : UTXO_DELTA_UNDO_ABSENT;
    progress_store_tx_unlock();
    if (row == UTXO_DELTA_UNDO_OTHER_BRANCH)
        return "fold still holds another branch's block";
    if (row == UTXO_DELTA_UNDO_ERROR)
        return "delta row unreadable";
    return NULL;
}

/* Past this many attempts the row is a LOUD, not a silent, wait: still
 * never gives up (the probe is one cheap point read — there is no CPU
 * reason to ever fall back to booking a skip it could not confirm), just
 * escalates the log so a wedged reducer past this long is visible. */
#define BG_VALIDATION_ROW_LOUD_AFTER 20u
/* Growing backoff cap: doubling per attempt, capped at 5 minutes, so a
 * genuinely slow fold gets patience without the walk polling a stuck row
 * once a second forever. */
#define BG_VALIDATION_ROW_BACKOFF_MAX_MS (5u * 60u * 1000u)

#ifdef ZCL_TESTING
static bg_validation_test_row_probe_fn g_row_probe_fn =
    bg_validation_row_unresolved_reason;
static bg_validation_test_sleep_fn g_row_backoff_sleep_fn = platform_sleep_ms;

void bg_validation_test_set_row_backoff_stubs(
    bg_validation_test_row_probe_fn probe_fn,
    bg_validation_test_sleep_fn sleep_fn)
{
    g_row_probe_fn = probe_fn ? probe_fn : bg_validation_row_unresolved_reason;
    g_row_backoff_sleep_fn = sleep_fn ? sleep_fn : platform_sleep_ms;
}
#endif

static void bg_validation_row_backoff(struct bg_validation_service *svc,
                                      int h, const char *reason,
                                      unsigned attempt)
{
    uint64_t wait_ms = 1000;
    for (unsigned i = 0; i < attempt && wait_ms < BG_VALIDATION_ROW_BACKOFF_MAX_MS;
         i++)
        wait_ms *= 2;
    if (wait_ms > BG_VALIDATION_ROW_BACKOFF_MAX_MS)
        wait_ms = BG_VALIDATION_ROW_BACKOFF_MAX_MS;
    /* Throttled like bg_validation_fold_backoff's own wait log: every
     * attempt already means a real, growing wait in production (seconds
     * apart at first, minutes apart once capped), but a driven-hard test
     * fixture with a no-delay sleep stub can run thousands of attempts a
     * second, so log only the first few and then every 10th. */
    if (attempt < 3 || attempt % 10 == 0) {
        if (attempt >= BG_VALIDATION_ROW_LOUD_AFTER)
            LOG_WARN("bg_validation",
                     "[bg-valid] h=%d delta row unresolved (attempt %u): %s — "
                     "never booking while unresolved; backing off %llus before "
                     "re-checking",
                     h, attempt + 1, reason,
                     (unsigned long long)(wait_ms / 1000));
        else
            LOG_INFO("bg_validation",
                     "[bg-valid] h=%d delta row unresolved (attempt %u): %s — "
                     "never booking while unresolved; backing off %llus before "
                     "re-checking",
                     h, attempt + 1, reason,
                     (unsigned long long)(wait_ms / 1000));
    }
    /* Sleep in 1s slices, checking stop_requested and heartbeating between
     * each — the same shape as bg_validation_fold_backoff and the re-verify
     * loop's idle wait. wait_ms can run up to BG_VALIDATION_ROW_BACKOFF_MAX_MS
     * (5 minutes); one uninterruptible platform_sleep_ms(wait_ms) here made
     * bg_validation_stop's undeadlined pthread_join block that long, long
     * enough for systemd's shutdown timeout to SIGKILL the node. */
    for (uint64_t slept = 0; slept < wait_ms && !atomic_load(&svc->stop_requested);
         slept += 1000) {
        bg_validation_supervisor_heartbeat(svc);
#ifdef ZCL_TESTING
        g_row_backoff_sleep_fn(1000);
#else
        platform_sleep_ms(1000);
#endif
    }
}

/* Cheap pre/post row check + growing backoff shared by BOTH call sites in
 * the walk: before the (expensive) full validation, to skip paying for
 * crypto while the row is already known-stuck, and after it, on the
 * pindex validation actually used (bg_validation_read_body_resilient can
 * swap pindex under cs_main on a reorg between the pre-check and the
 * read, so only the post-validation pindex is trustworthy for booking).
 * Returns true when the walk must retry `h` (a backoff sleep already
 * ran, *row_retries advanced) — NEVER returns true forever without
 * sleeping, and never signals "give up and book". Returns false once the
 * row is resolved (*row_retries reset to 0). */
static bool bg_validation_row_wait_if_unresolved(
    struct bg_validation_service *svc, int h,
    const struct block_index *pindex, unsigned *row_retries)
{
    const char *row_reason =
#ifdef ZCL_TESTING
        g_row_probe_fn(h, pindex);
#else
        bg_validation_row_unresolved_reason(h, pindex);
#endif
    if (!row_reason) {
        *row_retries = 0;
        return false;
    }
    bg_validation_row_backoff(svc, h, row_reason, *row_retries);
    (*row_retries)++;
    return true;
}

/* ── Where a walk campaign starts ─────────────────────────────
 * A current-coverage cursor resumes at its next height with the census it
 * saved. A fresh store, or a cursor stamped with another coverage version,
 * starts at the floor (the external-seed floor + 1, else genesis) with a
 * zero census: the skips belong to the campaign that counted them, and a
 * refused cursor's tally must not block the authority of the re-walk. */
struct bg_walk_start {
    int height;
    bool coverage_complete;
    int64_t skips;
};

static struct bg_walk_start bg_validation_walk_start(
    struct bg_validation_service *svc, bool external_seeded,
    int32_t seed_floor)
{
    struct bg_walk_start ws = { .height = external_seeded ? seed_floor + 1
                                                          : 0 };
    const struct bg_validation_store_port *store = &svc->progress_store;
    int cursor = load_progress(store);
    if (cursor >= 0 &&
        bg_validation_coverage_version_current(load_coverage_version(store))) {
        int64_t ls = load_skips(store);
        ws.height = cursor + 1; /* Resume from next unverified block. */
        ws.coverage_complete = true;
        ws.skips = ls < 0 ? 0 : ls;
        return ws;
    }
    if (cursor < 0) {
        ws.coverage_complete = save_coverage_version(
            store, BG_VALIDATION_COVERAGE_VERSION);
        if (external_seeded) {
            printf("[bg-valid] seed floor at height %d — starting above "
                   "the checkpoint-certified seeded extent\n", seed_floor);
            event_emitf(EV_SYNC_STATE_CHANGE, 0,
                        "bg_validation seed_floor from=%d", seed_floor);
        }
    } else {
        bool cursor_cleared = store->save_progress &&
            store->save_progress(store->self, -1);
        ws.coverage_complete = cursor_cleared && save_coverage_version(
            store, BG_VALIDATION_COVERAGE_VERSION);
        LOG_WARN("bg_validation",
                 "[bg-valid] legacy coverage cursor refused; restarting "
                 "walk from h=%d",
                 ws.height);
    }
    save_skips(store, 0);
    return ws;
}

/* ── Sampled re-verify loop (after the genesis→tip walk completes) ──── */

static struct zcl_result bg_validation_publish_with_catchup(
    struct bg_validation_service *svc, bool external_seeded,
    const char *datadir, const struct chain_params *params, int num_workers);

/* A walk whose authority publish was refused (the live tip moved past the
 * verified height in the window, or the evidence was not ready yet) heals
 * here without a restart: every BG_PUBLISH_RETRY_CYCLES cycles, while the
 * authority is still unpublished, catch up and publish again. The throttle
 * keeps the publisher's coins scan off the per-cycle path. Returns true
 * when the walk has FAILED and the loop must stop. */
#define BG_PUBLISH_RETRY_CYCLES 10u
static bool bg_validation_reverify_heal_authority(
    struct bg_validation_service *svc, bool external_seeded, bool *published,
    unsigned cycle, const char *datadir, const struct chain_params *params,
    int num_workers)
{
    if (*published || cycle % BG_PUBLISH_RETRY_CYCLES != 0)
        return false;
    /* Skipped script checks never heal in this loop (only a refold clears
     * them), so a retry would only repeat the refusal and its operator event
     * (r1 and r5 carry skips today). */
    if (atomic_load(&svc->progress.script_verif_skipped_no_undo) != 0)
        return false;
    struct zcl_result r = bg_validation_publish_with_catchup(
        svc, external_seeded, datadir, params, num_workers);
    *published = r.ok;
    if (r.ok)
        LOG_INFO("bg_validation",
                 "[bg-valid] full-history authority published by the "
                 "re-verify loop");
    return atomic_load(&svc->progress.state) == BG_VALIDATION_FAILED;
}

/* Highest height the sampler may draw: the active tip (or the walk's end when
 * the chain is empty), clipped below the reducer's apply cursor. Never sample
 * a height the reducer has not applied yet: its undo does not exist, and the
 * process tally would record a false gap. */
static int bg_validation_reverify_ceiling(struct main_state *ms,
                                          int chain_height)
{
    int ceiling = active_chain_height(&ms->chain_active);
    if (ceiling < 1)
        ceiling = chain_height;
    uint64_t applied_next = bg_validation_applied_next();
    if (applied_next != UINT64_MAX && (uint64_t)ceiling >= applied_next)
        ceiling = applied_next > 1 ? (int)(applied_next - 1) : 0;
    return ceiling;
}

/* Low-rate, always-on re-verification of RANDOM already-verified heights.
 * Re-runs the SAME read-only proof/script verification under the SAME
 * sched_yield/idle throttle the forward walk uses — it changes NO validity
 * predicate, it just catches a previously-passed height that no longer passes
 * (bit-rot / miscompile / memory corruption). A single re-verify FAIL raises a
 * PERMANENT blocker and stops the loop; otherwise it advances reverify_passes
 * forever. Wakes promptly on stop_requested. */
static void bg_validation_sampled_reverify_loop(
    struct bg_validation_service *svc, int chain_height,
    const char *datadir, const struct chain_params *params, int num_workers,
    bool external_seeded, bool published)
{
    struct main_state *ms = svc->ms;
    if (chain_height < 1)
        return;

    unsigned cycle = 1; /* the caller just tried; first retry is later */
    atomic_store(&svc->progress.reverify_active, true);
    printf("[bg-valid] entering always-on sampled re-verify loop (1..%d)\n",
           chain_height);
    event_emitf(EV_SYNC_STATE_CHANGE, 0,
                "bg_validation reverify start ceiling=%d", chain_height);

    while (!atomic_load(&svc->stop_requested)) {
        bg_validation_supervisor_heartbeat(svc);
        if (bg_validation_reverify_heal_authority(svc, external_seeded, &published,
                                                  cycle++, datadir, params,
                                                  num_workers))
            break;

        int ceiling = bg_validation_reverify_ceiling(ms, chain_height);
        if (ceiling < 1) {
            for (int i = 0; i < BG_REVERIFY_IDLE_SECS &&
                            !atomic_load(&svc->stop_requested); i++)
                platform_sleep_ms(1000);
            continue;
        }
        int h = 1 + (int)(rng_u64() % (uint64_t)ceiling);

        struct block_index *pindex = NULL;
        struct block blk;
        block_init(&blk);
        if (bg_validation_read_body_resilient(
                svc, h, datadir, BG_VALIDATION_COMPLETE, &blk, &pindex)) {
                    /* `k` (undo-missing script skips) is DELIBERATELY not
                     * folded into progress.script_verif_skipped_no_undo.
                     * That counter is the forward walk's per-height census:
                     * it is persisted, restored on restart, and is a term in
                     * bg_validation_authority_claim_is_complete. This loop
                     * draws a RANDOM height forever, so adding k here would
                     * re-count heights the walk already counted and grow the
                     * persisted total without bound on an idle chain —
                     * turning a census into a rate. The skips are not lost:
                     * bg_validation_note_undo_skips() inside
                     * validate_block_proofs already tallies every draw in
                     * the process-global undo_missing_* counters, which is
                     * where a sampled gap is meant to be read. */
                    int64_t s = 0, p = 0, k = 0;
                    enum bg_validation_block_outcome outcome =
                        bg_validation_validate_canonical_block(
                            ms, h, &blk, pindex, datadir, params, num_workers,
                            svc->max_script_batch, &s, &p, &k);
                    block_free(&blk);
                    if (outcome == BG_VALIDATION_BLOCK_ORPHAN)
                        continue;
                    if (!bg_validation_record_reverify(
                            svc, h, outcome == BG_VALIDATION_BLOCK_VALID)) {
                        /* Re-verify FAILED — blocker raised, state FAILED. */
                        atomic_store(&svc->progress.reverify_active, false);
                        return;
                    }
        }

        /* Idle between samples; wake promptly on stop. */
        for (int i = 0; i < BG_REVERIFY_IDLE_SECS &&
                        !atomic_load(&svc->stop_requested); i++)
            platform_sleep_ms(1000);
        sched_yield();
    }
    atomic_store(&svc->progress.reverify_active, false);
}

enum bg_validation_height_result {
    BG_VALIDATION_HEIGHT_BOOKED,   /* block_sigs/proofs/skips are final */
    BG_VALIDATION_HEIGHT_RETRY,    /* `blk` already freed; walk retries `h` */
    BG_VALIDATION_HEIGHT_FAILED,   /* state set FAILED; thread must return */
};

/* Runs the one full validation for `h` (already body-read into `blk`,
 * against the pindex that read actually returned) and decides what the
 * walk does with the result, pulled out of bg_validation_thread to keep
 * that loop under the complexity cap. On BOOKED/FAILED the caller still
 * owns freeing `blk` on the OUTCOME_VALID path; on RETRY this already freed
 * it. Feeds a post-check failure into the same backoff counter as the
 * pre-check, and never books a skip while the row is still unresolved —
 * bg_validation_read_body_resilient can have swapped `pindex` under
 * cs_main after the pre-check (a one-block reorg at the tip), so only the
 * pindex actually validated is trustworthy for booking. */
static enum bg_validation_height_result bg_validation_height_validate(
    struct bg_validation_service *svc, int h, struct block *blk,
    struct block_index *pindex, const char *datadir,
    const struct chain_params *params, int num_workers,
    size_t max_script_batch, unsigned *row_retries, int64_t *block_sigs,
    int64_t *block_proofs, int64_t *block_skips)
{
    enum bg_validation_block_outcome outcome =
        bg_validation_validate_canonical_block(
            svc->ms, h, blk, pindex, datadir, params, num_workers,
            max_script_batch, block_sigs, block_proofs, block_skips);
    if (outcome == BG_VALIDATION_BLOCK_ORPHAN) {
        block_free(blk);
        return BG_VALIDATION_HEIGHT_RETRY;
    }
    if (outcome == BG_VALIDATION_BLOCK_INVALID) {
        fprintf(stderr, "[bg-valid] VALIDATION FAILURE at height %d\n", h);
        atomic_store(&svc->progress.state, BG_VALIDATION_FAILED);
        block_free(blk);
        return BG_VALIDATION_HEIGHT_FAILED;
    }
    if (*block_skips > 0 &&
        bg_validation_row_wait_if_unresolved(svc, h, pindex, row_retries)) {
        block_free(blk);
        return BG_VALIDATION_HEIGHT_RETRY;
    }
    return BG_VALIDATION_HEIGHT_BOOKED;
}

enum bg_validation_step {
    BG_VALIDATION_STEP_BOOKED,  /* sigs/proofs/skips are final, blk freed */
    BG_VALIDATION_STEP_RETRY,   /* the caller retries the same height */
    BG_VALIDATION_STEP_STOP,    /* stop requested while waiting on the fold */
    BG_VALIDATION_STEP_GAP,     /* body unreadable: a coverage gap */
    BG_VALIDATION_STEP_FAILED,  /* state set FAILED; thread must return */
};

/* The ONE per-block step both the forward walk and the publish catch-up run
 * for an active height `h` (genesis excluded): wait for the fold, pre-check
 * the delta row, read the body, then the full validation. Neither caller
 * has a weaker path. */
static enum bg_validation_step bg_validation_walk_step(
    struct bg_validation_service *svc, int h, struct block_index *pindex,
    const char *datadir, const struct chain_params *params, int num_workers,
    enum bg_validation_state ready_state, uint64_t *applied_next,
    unsigned *row_retries, int64_t *block_sigs,
    int64_t *block_proofs, int64_t *block_skips)
{
    if (!bg_validation_wait_until_applied(svc, h, applied_next))
        return BG_VALIDATION_STEP_STOP;
    if (bg_validation_row_wait_if_unresolved(svc, h, pindex, row_retries))
        return BG_VALIDATION_STEP_RETRY;

    struct block blk;
    block_init(&blk);
    if (!bg_validation_read_body_resilient(
            svc, h, datadir, ready_state, &blk, &pindex))
        return BG_VALIDATION_STEP_GAP;

    enum bg_validation_height_result result = bg_validation_height_validate(
        svc, h, &blk, pindex, datadir, params, num_workers,
        svc->max_script_batch, row_retries, block_sigs, block_proofs,
        block_skips);
    if (result == BG_VALIDATION_HEIGHT_RETRY)
        return BG_VALIDATION_STEP_RETRY;
    if (result == BG_VALIDATION_HEIGHT_FAILED)
        return BG_VALIDATION_STEP_FAILED;
    block_free(&blk);
    return BG_VALIDATION_STEP_BOOKED;
}

/* ── Publish catch-up ─────────────────────────────────────────
 * The walk verifies up to the tip it saw; the live tip can move before the
 * authority is published, and the publisher (rightly) demands verified ==
 * tip. Verify the missing blocks with the walk's own step, bounded per
 * attempt, then let the unchanged publisher decide. It runs only after the
 * walk set COMPLETE, so bodies it reads restore COMPLETE (not RUNNING), and
 * chain_height follows verified so the status readers see a complete walk. */
#define BG_CATCHUP_ROUNDS 8
#define BG_CATCHUP_MAX_RETRIES 8u

/* Verifies verified+1..tip once. True when verified reached `tip`. */
static bool bg_validation_catch_up_round(
    struct bg_validation_service *svc, int tip, const char *datadir,
    const struct chain_params *params, int num_workers)
{
    uint64_t applied_next = 0;
    unsigned row_retries = 0, retries = 0;
    int h = atomic_load(&svc->progress.verified_height) + 1;
    while (h <= tip && !atomic_load(&svc->stop_requested)) {
        struct block_index *pindex =
            active_chain_at(&svc->ms->chain_active, h);
        if (!pindex)
            break;
        int64_t sigs = 0, proofs = 0, skips = 0;
        enum bg_validation_step step = bg_validation_walk_step(
            svc, h, pindex, datadir, params, num_workers,
            BG_VALIDATION_COMPLETE, &applied_next, &row_retries, &sigs, &proofs, &skips);
        if (step == BG_VALIDATION_STEP_RETRY &&
            ++retries <= BG_CATCHUP_MAX_RETRIES)
            continue;
        if (step != BG_VALIDATION_STEP_BOOKED)
            break;
        atomic_fetch_add(&svc->progress.sigs_verified, sigs);
        atomic_fetch_add(&svc->progress.proofs_verified, proofs);
        atomic_fetch_add(&svc->progress.script_verif_skipped_no_undo, skips);
        atomic_store(&svc->progress.verified_height, h);
        atomic_store(&svc->progress.chain_height, h);
        h++;
    }
    int verified = atomic_load(&svc->progress.verified_height);
    save_skips(&svc->progress_store,
               atomic_load(&svc->progress.script_verif_skipped_no_undo));
    save_progress(&svc->progress_store, verified);
    return verified >= tip;
}

#ifdef ZCL_TESTING
bool bg_validation_test_catch_up_round(
    struct bg_validation_service *svc, int tip, const char *datadir,
    const struct chain_params *params, int num_workers)
{
    return bg_validation_catch_up_round(svc, tip, datadir, params,
                                        num_workers);
}
#endif

/* Publish the authority for a completed, coverage-complete walk, first
 * catching up blocks that arrived after the walk's last height. Every
 * refusal in the publisher is unchanged; the catch-up only runs while its
 * pure predicate says the live tip is the sole obstacle. */
static struct zcl_result bg_validation_publish_with_catchup(
    struct bg_validation_service *svc, bool external_seeded,
    const char *datadir, const struct chain_params *params, int num_workers)
{
    for (int round = 0; round < BG_CATCHUP_ROUNDS; round++) {
        int verified = atomic_load(&svc->progress.verified_height);
        int tip = active_chain_height(&svc->ms->chain_active);
        int64_t skips =
            atomic_load(&svc->progress.script_verif_skipped_no_undo);
        if (atomic_load(&svc->stop_requested) ||
            !bg_validation_authority_catchup_wanted(verified, tip, skips,
                                                    true))
            break;
        LOG_INFO("bg_validation",
                 "[bg-valid] catching up verified=%d to tip=%d before "
                 "publishing authority", verified, tip);
        if (!bg_validation_catch_up_round(svc, tip, datadir, params,
                                          num_workers))
            break;
    }
    return bg_validation_authority_publish(svc, external_seeded, true);
}

/* ── Main validation thread ──────────────────────────────────── */

static void *bg_validation_thread(void *arg)
{
    struct bg_validation_service *svc = arg;
    struct main_state *ms = svc->ms;
    const struct chain_params *params = svc->params;
    const char *datadir = svc->datadir;
    int num_workers = svc->num_workers;
    bool external_seeded = false;
    bool coverage_complete;

    /* Genuinely-background bulk walker (full proof/script re-verification
     * of the locally-derived extent) — never the reducer/net/RPC/tip-follow
     * path. Apply OS QoS armor before any work so the kernel schedules it
     * behind the node's liveness threads. */
    zcl_thread_qos_background();

    bg_validation_supervisor_heartbeat(svc);

    int32_t seed_floor = 0;
    bool seed_floor_found = false;
    external_seeded = reducer_seed_floor_height_read(
        progress_store_db(), &seed_floor, &seed_floor_found) &&
        seed_floor_found && seed_floor > 0;

    struct bg_walk_start ws =
        bg_validation_walk_start(svc, external_seeded, seed_floor);
    int start_height = ws.height;
    coverage_complete = ws.coverage_complete;

    int chain_height = active_chain_height(&ms->chain_active);
    atomic_store(&svc->progress.chain_height, chain_height);
    atomic_store(&svc->progress.verified_height, start_height - 1);
    atomic_store(&svc->progress.state, BG_VALIDATION_RUNNING);

    printf("[bg-valid] Starting full validation from height %d to %d "
           "(%d workers)\n", start_height, chain_height, num_workers);
    event_emitf(EV_SYNC_STATE_CHANGE, 0,
                "bg_validation start from=%d to=%d workers=%d",
                start_height, chain_height, num_workers);

    int64_t t_start = (int64_t)platform_time_wall_time_t();
    int64_t t_last_log = t_start;
    int h_last_log = start_height;
    int64_t total_sigs = 0;
    int64_t total_proofs = 0;
    int64_t total_skips = ws.skips;
    uint64_t applied_next = 0;
    unsigned row_retries = 0;
    atomic_store(&svc->progress.script_verif_skipped_no_undo, total_skips);

    for (int h = start_height; h <= chain_height; h++) {
        if (atomic_load(&svc->stop_requested))
            break;
        bg_validation_supervisor_heartbeat(svc);

        /* Refresh chain height periodically (chain may advance) */
        if (h % 100 == 0) {
            chain_height = active_chain_height(&ms->chain_active);
            atomic_store(&svc->progress.chain_height, chain_height);
        }

        struct block_index *pindex = active_chain_at(&ms->chain_active, h);
        if (!pindex) {
            coverage_complete = false;
            LOG_WARN("bg_validation", "[bg-valid] coverage gap: no active block h=%d", h);
            break;
        }

        /* Genesis is hardcoded; every later body must be readable. */
        if (h == 0) {
            atomic_store(&svc->progress.verified_height, 0);
            continue;
        }
        /* One shared block step (fold wait, row pre-check with backoff,
         * resilient body read, full validation); see bg_validation_walk_step. */
        int64_t block_sigs = 0, block_proofs = 0, block_skips = 0;
        enum bg_validation_step step = bg_validation_walk_step(
            svc, h, pindex, datadir, params, num_workers,
            BG_VALIDATION_RUNNING, &applied_next,
            &row_retries, &block_sigs, &block_proofs, &block_skips);
        if (step == BG_VALIDATION_STEP_RETRY) {
            h--;
            continue;
        }
        if (step == BG_VALIDATION_STEP_FAILED) {
            bg_validation_supervisor_done();
            return NULL;
        }
        if (step == BG_VALIDATION_STEP_GAP)
            coverage_complete = false;
        if (step != BG_VALIDATION_STEP_BOOKED)
            break;
        total_sigs += block_sigs;
        total_proofs += block_proofs;
        total_skips += block_skips;
        atomic_store(&svc->progress.verified_height, h);
        atomic_store(&svc->progress.sigs_verified, total_sigs);
        atomic_store(&svc->progress.proofs_verified, total_proofs);
        atomic_store(&svc->progress.script_verif_skipped_no_undo, total_skips);
        bg_validation_supervisor_heartbeat(svc);

        /* Save progress periodically */
        if (h % SAVE_INTERVAL == 0) {
            save_skips(&svc->progress_store, total_skips);
            save_progress(&svc->progress_store, h);

            /* Bound peak RSS. Every block here churns large transient
             * heap — a per-block undo buffer (up to MAX_UNDO_READ = 4 MB),
             * the script_check_item array, and a fully-deserialized block
             * (hundreds of small tx/vin/vout/joinsplit allocations) — all
             * freed before the next iteration. The PER-BLOCK footprint is
             * already bounded, but glibc keeps freed chunks in its arenas
             * instead of returning them to the OS, so RESIDENT memory
             * stair-steps upward as the walk deepens (~1.5 GB -> 2.4 GB+
             * over millions of blocks) and never falls back. malloc_trim
             * hands the retained pages back to the kernel, flattening peak
             * RSS. This is purely memory discipline — it does not change
             * what gets verified. Same idiom fast_sync.c uses after its
             * bulk UTXO serialization. Called once per SAVE_INTERVAL
             * (1000 blocks) so the cost is negligible vs. the per-block
             * crypto. */
            platform_allocator_release_free_pages();
        }

        /* Log progress */
        if (h % LOG_INTERVAL == 0 && h > start_height) {
            int64_t now = (int64_t)platform_time_wall_time_t();
            int64_t elapsed = now - t_last_log;
            double bps = elapsed > 0 ?
                (double)(h - h_last_log) / (double)elapsed : 0;
            int remaining = chain_height - h;
            int eta = bps > 0 ? (int)((double)remaining / bps) : 0;

            printf("[bg-valid] height %d/%d  %.0f blk/s  "
                   "%lld sigs  %lld proofs  ETA %dm%ds\n",
                   h, chain_height, bps,
                   (long long)total_sigs, (long long)total_proofs,
                   eta / 60, eta % 60);

            atomic_store(&svc->progress.blocks_per_sec, (int64_t)bps);
            t_last_log = now;
            h_last_log = h;
        }

        /* Yield CPU periodically to avoid starving the node */
        if (h % 100 == 0)
            sched_yield();
    }

    if (!atomic_load(&svc->stop_requested) && !coverage_complete) {
        int verified = atomic_load(&svc->progress.verified_height);
        save_skips(&svc->progress_store, total_skips);
        save_progress(&svc->progress_store, verified);
        atomic_store(&svc->progress.state, BG_VALIDATION_PAUSED);
        struct zcl_result authority =
            bg_validation_authority_publish(svc, external_seeded, false);
        if (!authority.ok)
            printf("[bg-valid] PAUSED: %s\n", authority.message);
        bg_validation_supervisor_done();
        return NULL;
    }

    if (!atomic_load(&svc->stop_requested)) {
        /* Validation complete — save final progress */
        save_skips(&svc->progress_store, total_skips);
        save_progress(&svc->progress_store, chain_height);
        atomic_store(&svc->progress.verified_height, chain_height);
        atomic_store(&svc->progress.state, BG_VALIDATION_COMPLETE);

        /* Only reset if we crossed the deferred-validation floor.
         * Otherwise an empty-chain run (chain_height==0) trivially
         * "completes" and clears the boot-time deferred=3,100,000
         * setting, which then makes incoming peer blocks at low heights
         * (h=737 etc.) fail phgr13 verify before the PHGR13 verifying
         * key is ready. */
        if (chain_height >= g_deferred_proof_validation_below_height)
            g_deferred_proof_validation_below_height = -1;

        int64_t total_time = (int64_t)platform_time_wall_time_t() - t_start;
        printf("[bg-valid] COMPLETE: %d blocks, %lld sigs, %lld proofs "
               "in %lldm%llds\n",
               chain_height - start_height + 1,
               (long long)total_sigs, (long long)total_proofs,
               (long long)(total_time / 60), (long long)(total_time % 60));
        event_emitf(EV_SYNC_STATE_CHANGE, 0,
                    "bg_validation complete height=%d sigs=%lld proofs=%lld "
                    "time=%llds",
                    chain_height, (long long)total_sigs,
                    (long long)total_proofs, (long long)total_time);

        struct zcl_result authority = bg_validation_publish_with_catchup(
            svc, external_seeded, datadir, params, num_workers);
        if (!authority.ok)
            printf("[bg-valid] COMPLETE without full-history authority: %s\n",
                   authority.message);

        /* Keep the thread alive as the sampled re-verify witness. */
        bg_validation_supervisor_done();
        bg_validation_sampled_reverify_loop(svc, chain_height, datadir,
                                            params, num_workers,
                                            external_seeded, authority.ok);
    } else {
        /* Stopped early — save where we got to */
        int verified = atomic_load(&svc->progress.verified_height);
        save_skips(&svc->progress_store, total_skips);
        save_progress(&svc->progress_store, verified);
        printf("[bg-valid] Stopped at height %d (will resume next start)\n",
               verified);
    }

    bg_validation_supervisor_done();
    return NULL;
}

/* ── Public API ──────────────────────────────────────────────── */

bool bg_validation_start(struct bg_validation_service *svc)
{
    if (!svc || !svc->ms || !svc->datadir || svc->thread_started)
        LOG_FAIL("bg_validation",
                 "bg_validation_start: invalid svc/ms/datadir or thread already started");

    int chain_h = active_chain_height(&svc->ms->chain_active);
    /* Safety check: verify active_chain has valid entries at h=0 and h=1.
     * After block_map_grow, phashBlock pointers may be stale (fixed by
     * re-linking at boot). Never publish completion when entries remain
     * unusable: defer the worker and leave authority fail-closed. */
    if (chain_h > 1000) {
        struct block_index *h0 = active_chain_at(&svc->ms->chain_active, 0);
        struct block_index *h1 = active_chain_at(&svc->ms->chain_active, 1);
        if (!h0 || !h1 || !(block_index_status_load(h0) & BLOCK_HAVE_DATA)) {
            printf("[bg-valid] Deferred — chain[0] or chain[1] not valid "
                   "(tip=%d)\n", chain_h);
            atomic_store(&svc->progress.state, BG_VALIDATION_PAUSED);
            atomic_store(&svc->progress.verified_height, -1);
            atomic_store(&svc->progress.chain_height, chain_h);
            return false;
        }
    }

    atomic_store(&svc->stop_requested, false);
    if (!bg_validation_register_supervisor(svc))
        return false;  // raw-return-ok:callee-already-LOG_FAILs-the-root-cause
    if (thread_registry_spawn("zcl_bg_valid", bg_validation_thread, svc,
                                  &svc->thread) != 0) {
        bg_validation_supervisor_done();
        LOG_FAIL("bg-valid", "failed to create thread");
    }
    svc->thread_started = true;
    return true;
}

void bg_validation_stop(struct bg_validation_service *svc)
{
    if (!svc || !svc->thread_started)
        return;
    bg_validation_supervisor_done();
    atomic_store(&svc->stop_requested, true);
    /* Linux supplies a five-second diagnostic deadline. Every platform
     * retains ownership until the worker exits, so dependencies cannot be
     * freed live. */
    struct timespec ts;
#if defined(__linux__)
    if (platform_time_realtime_timespec(&ts) == 0) {
        ts.tv_sec += 5;
        int rc = pthread_timedjoin_np(svc->thread, NULL, &ts);
        if (rc != 0) {
            LOG_WARN("bg_validation_stop", "bg_validation_stop: thread join exceeded deadline (rc=%d); retaining ownership", rc);
            pthread_join(svc->thread, NULL);
        }
    } else {
        pthread_join(svc->thread, NULL);
    }
#else
    (void)ts;
    pthread_join(svc->thread, NULL);
#endif
    svc->thread_started = false;
#ifdef ZCL_TESTING
    supervisor_child_id id = atomic_exchange(&g_bg_validation_supervisor_id,
                                             SUPERVISOR_INVALID_ID);
    if (id != SUPERVISOR_INVALID_ID)
        supervisor_unregister(id);
#endif
}

struct bg_validation_progress bg_validation_get_progress(
    const struct bg_validation_service *svc)
{
    struct bg_validation_progress p;
    p.verified_height = atomic_load(&svc->progress.verified_height);
    p.chain_height = atomic_load(&svc->progress.chain_height);
    p.sigs_verified = atomic_load(&svc->progress.sigs_verified);
    p.proofs_verified = atomic_load(&svc->progress.proofs_verified);
    p.blocks_per_sec = atomic_load(&svc->progress.blocks_per_sec);
    p.script_verif_skipped_no_undo =
        atomic_load(&svc->progress.script_verif_skipped_no_undo);
    p.state = atomic_load(&svc->progress.state);
    p.reverify_active = atomic_load(&svc->progress.reverify_active);
    p.reverify_passes = atomic_load(&svc->progress.reverify_passes);
    p.reverify_fails = atomic_load(&svc->progress.reverify_fails);
    p.reverify_height = atomic_load(&svc->progress.reverify_height);
    return p;
}

bool bg_validation_record_reverify(struct bg_validation_service *svc,
                                   int height, bool verify_ok)
{
    if (!svc)
        LOG_FAIL("bg_validation",
                 "bg_validation_record_reverify: null svc (h=%d)", height);

    atomic_store(&svc->progress.reverify_height, height);
    if (verify_ok) {
        atomic_fetch_add(&svc->progress.reverify_passes, 1);
        return true;
    }

    /* A previously-passed height no longer verifies: bit-rot / miscompile /
     * memory corruption of proven work. Name it — PERMANENT; consensus history
     * that already verified must never silently regress. */
    atomic_fetch_add(&svc->progress.reverify_fails, 1);
    atomic_store(&svc->progress.state, BG_VALIDATION_FAILED);

    char reason[BLOCKER_REASON_MAX];
    snprintf(reason, sizeof(reason),
             "bg re-verify FAILED at already-verified height %d "
             "(passes=%lld fails=%lld) — proof/script re-check regressed; "
             "possible bit-rot / miscompile / memory corruption",
             height,
             (long long)atomic_load(&svc->progress.reverify_passes),
             (long long)atomic_load(&svc->progress.reverify_fails));

    struct blocker_record rec;
    if (blocker_init(&rec, "bg_validation.reverify_failed", "bg_validation",
                     BLOCKER_PERMANENT, reason)) {
        if (blocker_set(&rec) == 0)
            event_emitf(EV_OPERATOR_NEEDED, 0,
                        "check=bg_validation.reverify_failed %s", reason);
    }
    LOG_WARN("bg_validation", "[bg-valid] %s", reason);
    return false;
}

#ifdef ZCL_TESTING
bool bg_validation_test_coverage_version_current(int64_t version)
{
    return bg_validation_coverage_version_current(version);
}
#endif

void bg_validation_reset(struct bg_validation_service *svc)
{
    if (!svc) return;
    bg_validation_stop(svc);
    save_progress(&svc->progress_store, -1);
    save_skips(&svc->progress_store, 0);
    atomic_store(&svc->progress.verified_height, -1);
    atomic_store(&svc->progress.sigs_verified, 0);
    atomic_store(&svc->progress.proofs_verified, 0);
    atomic_store(&svc->progress.script_verif_skipped_no_undo, 0);
    /* Process-wide undo-skip tallies + suppression streak travel with the
     * persisted skip counter, so a reset walk re-announces its first gap. */
    bg_validation_reset_undo_skip_stats();
    atomic_store(&svc->progress.blocks_per_sec, 0);
    atomic_store(&svc->progress.reverify_active, false);
    atomic_store(&svc->progress.reverify_passes, 0);
    atomic_store(&svc->progress.reverify_fails, 0);
    atomic_store(&svc->progress.reverify_height, 0);
    atomic_store(&svc->progress.state, BG_VALIDATION_IDLE);
    printf("[bg-valid] Progress reset — will re-verify from block 0\n");
    bg_validation_start(svc);
}

const char *bg_validation_state_name(enum bg_validation_state state)
{
    switch (state) {
    case BG_VALIDATION_IDLE:     return "idle";
    case BG_VALIDATION_RUNNING:  return "running";
    case BG_VALIDATION_PAUSED:   return "paused";
    case BG_VALIDATION_COMPLETE: return "complete";
    case BG_VALIDATION_FAILED:   return "failed";
    }
    return "unknown";
}
