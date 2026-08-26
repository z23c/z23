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
#include "adapters/outbound/persistence/bg_validation_store_sqlite.h"
#include "ports/bg_validation_store_port.h"
#include "jobs/reducer_frontier.h"           /* reducer_seed_floor_height_read */
#include "storage/progress_store.h"          /* progress_store_db */
#include "event/event.h"
#include "platform/rng.h"
#include "util/blocker.h"
#include "util/hw_bench.h"
#include "util/hw_profile.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sched.h>
#ifdef __GLIBC__
#include <malloc.h>  /* malloc_trim — return retained transient heap to the OS */
#endif
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
#define BG_VALIDATION_COVERAGE_VERSION 1
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

/* ── Sampled re-verify loop (after the genesis→tip walk completes) ──── */

/* Low-rate, always-on re-verification of RANDOM already-verified heights.
 * Re-runs the SAME read-only proof/script verification under the SAME
 * sched_yield/idle throttle the forward walk uses — it changes NO validity
 * predicate, it just catches a previously-passed height that no longer passes
 * (bit-rot / miscompile / memory corruption). A single re-verify FAIL raises a
 * PERMANENT blocker and stops the loop; otherwise it advances reverify_passes
 * forever. Wakes promptly on stop_requested. */
static void bg_validation_sampled_reverify_loop(
    struct bg_validation_service *svc, int chain_height,
    const char *datadir, const struct chain_params *params, int num_workers)
{
    struct main_state *ms = svc->ms;
    if (chain_height < 1)
        return;

    atomic_store(&svc->progress.reverify_active, true);
    printf("[bg-valid] entering always-on sampled re-verify loop (1..%d)\n",
           chain_height);
    event_emitf(EV_SYNC_STATE_CHANGE, 0,
                "bg_validation reverify start ceiling=%d", chain_height);

    while (!atomic_load(&svc->stop_requested)) {
        bg_validation_supervisor_heartbeat(svc);

        int ceiling = active_chain_height(&ms->chain_active);
        if (ceiling < 1)
            ceiling = chain_height;
        int h = 1 + (int)(rng_u64() % (uint64_t)ceiling);

        struct block_index *pindex = NULL;
        struct block blk;
        block_init(&blk);
        if (bg_validation_read_body_resilient(
                svc, h, datadir, BG_VALIDATION_COMPLETE, &blk, &pindex)) {
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
     * behind the node's liveness threads (lane/os-armor). */
    zcl_thread_qos_background();

    bg_validation_supervisor_heartbeat(svc);

    int32_t seed_floor = 0;
    bool seed_floor_found = false;
    external_seeded = reducer_seed_floor_height_read(
        progress_store_db(), &seed_floor, &seed_floor_found) &&
        seed_floor_found && seed_floor > 0;

    int start_height = load_progress(&svc->progress_store);
    if (start_height < 0) {
        coverage_complete = save_coverage_version(
            &svc->progress_store, BG_VALIDATION_COVERAGE_VERSION);
        start_height = external_seeded ? seed_floor + 1 : 0;
        if (external_seeded) {
            printf("[bg-valid] seed floor at height %d — starting above "
                   "the checkpoint-certified seeded extent\n", seed_floor);
            event_emitf(EV_SYNC_STATE_CHANGE, 0,
                        "bg_validation seed_floor from=%d", seed_floor);
        }
    } else {
        coverage_complete = bg_validation_coverage_version_current(
            load_coverage_version(&svc->progress_store));
        if (coverage_complete) {
            start_height++; /* Resume from next unverified block. */
        } else {
            bool cursor_cleared = svc->progress_store.save_progress &&
                svc->progress_store.save_progress(
                    svc->progress_store.self, -1);
            coverage_complete = cursor_cleared && save_coverage_version(
                &svc->progress_store, BG_VALIDATION_COVERAGE_VERSION);
            start_height = external_seeded ? seed_floor + 1 : 0;
            LOG_WARN("bg_validation",
                     "[bg-valid] legacy coverage cursor refused; restarting "
                     "walk from h=%d",
                     start_height);
        }
    }

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
    int64_t ls = load_skips(&svc->progress_store);
    int64_t total_skips = ls < 0 ? 0 : ls;
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
        struct block blk;
        block_init(&blk);
        if (!bg_validation_read_body_resilient(
                svc, h, datadir, BG_VALIDATION_RUNNING, &blk, &pindex)) {
            coverage_complete = false;
            break;
        }

        int64_t block_sigs = 0, block_proofs = 0, block_skips = 0;
        enum bg_validation_block_outcome outcome =
            bg_validation_validate_canonical_block(
                ms, h, &blk, pindex, datadir, params, num_workers,
                svc->max_script_batch, &block_sigs, &block_proofs,
                &block_skips);
        if (outcome == BG_VALIDATION_BLOCK_ORPHAN) {
            block_free(&blk);
            h--;
            continue;
        }
        if (outcome == BG_VALIDATION_BLOCK_INVALID) {
            fprintf(stderr, "[bg-valid] VALIDATION FAILURE at height %d\n", h);
            atomic_store(&svc->progress.state, BG_VALIDATION_FAILED);
            block_free(&blk);
            bg_validation_supervisor_done();
            return NULL;
        }

        block_free(&blk);
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
#ifdef __GLIBC__
            malloc_trim(0);
#endif
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

        struct zcl_result authority =
            bg_validation_authority_publish(svc, external_seeded, true);
        if (!authority.ok)
            printf("[bg-valid] COMPLETE without full-history authority: %s\n",
                   authority.message);

        /* Keep the thread alive as the sampled re-verify witness. */
        bg_validation_supervisor_done();
        bg_validation_sampled_reverify_loop(svc, chain_height, datadir,
                                            params, num_workers);
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

void bg_validation_init(struct bg_validation_service *svc,
                        struct main_state *ms,
                        struct node_db *ndb,
                        const char *datadir,
                        const struct chain_params *params)
{
    memset(svc, 0, sizeof(*svc));
    svc->ms = ms;
    svc->ndb = ndb;
    svc->datadir = datadir;
    svc->params = params;
    svc->thread_started = false;
    atomic_store(&svc->stop_requested, false);

    /* Bind the crash-resume cursor store to the (already-open) node DB.
     * The sqlite adapter is the only code that names the DB for this
     * subsystem; the cursor key/semantics are unchanged. */
    bg_validation_store_sqlite_bind(ndb, &svc->progress_store);

    /* Worker count + per-block script batch cap both come from the
     * hw_profile organ (lib/util/src/hw_profile.c) — measured physical
     * core count and measured RAM instead of ad hoc sysconf() calls
     * duplicated in this file. Same clamps as before ([2,4] workers;
     * batch capped at 10000 below 8 GiB, unlimited at/above it) — this is
     * a re-source, not a behavior change, on any machine with >=8 physical
     * cores (the clamp already dominated the old nproc/2 formula there).
     * pread()-based disk I/O is fully thread-safe, so multiple workers
     * can read blocks concurrently without the old FILE* cache races.
     *
     * hw_bench_verify_workers then refines the topology-derived worker
     * count with a MEASURED random-read latency (lib/util/src/hw_bench.c):
     * unchanged when unmeasured or on fast storage, scaled down (never
     * below 1, never above the topology count) when the boot-time 4KB
     * pread probe found slow/contended storage — fewer concurrent
     * verify workers means less I/O thrashing on that class of disk. */
    hw_profile_init(svc->datadir);
    hw_bench_init(svc->datadir);
    svc->num_workers =
        hw_bench_verify_workers(hw_profile_verify_workers(hw_profile_physical_cores()));
    svc->max_script_batch = hw_profile_script_batch_cap(hw_profile_ram_bytes());

    atomic_store(&svc->progress.state, BG_VALIDATION_IDLE);
    atomic_store(&svc->progress.verified_height, -1);
    atomic_store(&svc->progress.chain_height, 0);
    atomic_store(&svc->progress.sigs_verified, 0);
    atomic_store(&svc->progress.proofs_verified, 0);
    atomic_store(&svc->progress.blocks_per_sec, 0);
    atomic_store(&svc->progress.reverify_active, false);
    atomic_store(&svc->progress.reverify_passes, 0);
    atomic_store(&svc->progress.reverify_fails, 0);
    atomic_store(&svc->progress.reverify_height, 0);
}

bool bg_validation_start(struct bg_validation_service *svc)
{
    if (!svc || svc->thread_started)
        LOG_FAIL("bg_validation", "bg_validation_start: null svc or thread already started");

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
    /* Five seconds is a diagnostic deadline. Retain ownership until the
     * validation worker exits so its dependencies cannot be freed live. */
    struct timespec ts;
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
