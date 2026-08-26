/* Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright (c) 2014-2017 The Zcash developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 *
 * Background Full Validation Service
 * -----------------------------------
 * After fast sync (FlyClient + SHA3 snapshot), the node is operational at tip
 * within ~44 seconds. This background service then walks every locally-derived
 * block and fully validates every signature, script, zk-SNARK proof, and
 * Equihash solution in it. A fresh walk starts above the external-seed floor
 * (REDUCER_SEED_FLOOR_HEIGHT_KEY — the checkpoint-certified seeded extent,
 * which carries no undo data to script-verify against; written ONCE, only by
 * a genuine external-seed path — cold-import wedge heal / bundle install —
 * deliberately NOT the trusted base, which tip_finalize keeps raising toward
 * tip). A from-genesis or reindexed datadir declares no floor and is walked
 * from genesis — that full-history walk is the replay-canary --from=genesis
 * exact tier.
 *
 * Design:
 *   - Runs in a dedicated background thread, low priority
 *   - Uses a thread pool (checkqueue) for parallel script verification
 *   - Saves progress to SQLite every 1000 blocks for crash-resume
 *   - Resets g_deferred_proof_validation_below_height to -1 when complete (full verification)
 *   - Does NOT modify the UTXO set — read-only validation pass
 *   - Emits events for observability (EV_BG_VALIDATION_PROGRESS)
 */

#ifndef ZCL_BG_VALIDATION_SERVICE_H
#define ZCL_BG_VALIDATION_SERVICE_H

#include <stdbool.h>
#include <stdint.h>
#include <stdatomic.h>
#include <pthread.h>

#include "ports/bg_validation_store_port.h"

struct main_state;
struct coins_view_cache;
struct node_db;
struct active_chain;
struct chain_params;
struct block;
struct block_index;

enum bg_validation_state {
    BG_VALIDATION_IDLE = 0,      /* not started */
    BG_VALIDATION_RUNNING,       /* actively verifying blocks */
    BG_VALIDATION_PAUSED,        /* paused (e.g. during reorg) */
    BG_VALIDATION_COMPLETE,      /* all blocks fully verified */
    BG_VALIDATION_FAILED,        /* validation failure detected */
};

enum bg_validation_block_outcome {
    BG_VALIDATION_BLOCK_VALID = 0,
    BG_VALIDATION_BLOCK_INVALID,
    BG_VALIDATION_BLOCK_ORPHAN,
};

struct bg_validation_progress {
    _Atomic int verified_height;       /* last fully-verified block */
    _Atomic int chain_height;          /* current chain tip height */
    _Atomic int64_t sigs_verified;     /* total ECDSA sigs checked */
    _Atomic int64_t proofs_verified;   /* total zk-SNARK proofs checked */
    _Atomic int64_t blocks_per_sec;    /* recent throughput */
    /* Non-coinbase txs whose script sigs could NOT be verified because the
     * block's undo (revXXXXX.dat) was missing/mismatched. These blocks still
     * advance verified_height (header/structure/shielded proofs checked) but
     * are NOT fully script-verified — keeps the "verified" claim honest.
     * Expected for post-snapshot blocks (no rev file), not a failure. */
    _Atomic int64_t script_verif_skipped_no_undo;
    _Atomic int state;                 /* enum bg_validation_state */
    /* ── Always-on sampled re-verify (after BG_VALIDATION_COMPLETE) ──
     * Once the genesis→tip walk completes, the thread does NOT exit; it enters
     * a low-rate loop that re-runs the proof/script verification over RANDOM
     * already-verified heights. A silent bit-rot / miscompile / memory
     * corruption of previously-passed work then becomes a NAMED event instead
     * of a quiet regression. */
    _Atomic bool    reverify_active;   /* in the sampled re-verify loop */
    _Atomic int64_t reverify_passes;   /* sampled heights that re-verified OK */
    _Atomic int64_t reverify_fails;    /* sampled heights that FAILED re-verify */
    _Atomic int     reverify_height;   /* last height sampled */
};

struct bg_validation_service {
    /* References (not owned) */
    struct main_state *ms;
    struct node_db *ndb;
    const char *datadir;
    const struct chain_params *params;

    /* Crash-resume cursor storage behind a port; bound from `ndb` in
     * bg_validation_init. The adapter is the only sqlite-aware code. */
    struct bg_validation_store_port progress_store;

    /* Thread management */
    pthread_t thread;
    bool thread_started;
    _Atomic bool stop_requested;

    /* Worker thread pool for parallel script verification */
    int num_workers;

    /* Maximum script check items per batch (0 = unlimited).
     * Caps per-block RAM usage on memory-constrained machines. */
    size_t max_script_batch;

    /* Progress tracking */
    struct bg_validation_progress progress;
};

/* Initialize the service (does not start the thread). */
void bg_validation_init(struct bg_validation_service *svc,
                        struct main_state *ms,
                        struct node_db *ndb,
                        const char *datadir,
                        const struct chain_params *params);

/* Start the background validation thread. Returns false on failure. */
bool bg_validation_start(struct bg_validation_service *svc);

/* Request graceful stop and join the thread. */
void bg_validation_stop(struct bg_validation_service *svc);

/* Get current progress snapshot (lock-free atomic reads). */
struct bg_validation_progress bg_validation_get_progress(
    const struct bg_validation_service *svc);

/* Get human-readable state name. */
const char *bg_validation_state_name(enum bg_validation_state state);

/* Record the outcome of ONE sampled re-verify of an already-verified height.
 * On success bumps reverify_passes and returns true (keep sampling). On failure
 * bumps reverify_fails, flips state to BG_VALIDATION_FAILED, raises the PERMANENT
 * blocker `bg_validation.reverify_failed`, and returns false (stop the loop) —
 * previously-proven consensus history must never regress. Exposed for tests. */
bool bg_validation_record_reverify(struct bg_validation_service *svc,
                                   int height, bool verify_ok);

#ifdef ZCL_TESTING
/* Proves the restart shortcut accepts only the current coverage schema. */
bool bg_validation_test_coverage_version_current(int64_t version);
typedef bool (*bg_validation_test_body_read_fn)(
    struct block *, const struct block_index *, const char *);
typedef void (*bg_validation_test_sleep_fn)(int);
void bg_validation_test_set_body_repair_stubs(
    bg_validation_test_body_read_fn read_fn,
    bg_validation_test_sleep_fn sleep_fn);
typedef bool (*bg_validation_test_validate_fn)(
    const struct block *, struct block_index *, const char *,
    const struct chain_params *, int, size_t,
    int64_t *, int64_t *, int64_t *);
void bg_validation_test_set_validate_stub(
    bg_validation_test_validate_fn validate_fn);
enum bg_validation_block_outcome bg_validation_validate_canonical_block(
    struct main_state *ms, int height, const struct block *block,
    struct block_index *index, const char *datadir,
    const struct chain_params *params, int num_workers,
    size_t max_script_batch, int64_t *sigs_out, int64_t *proofs_out,
    int64_t *skips_out);
bool bg_validation_read_body_resilient(
    struct bg_validation_service *svc, int height, const char *datadir,
    enum bg_validation_state ready_state, struct block *block,
    struct block_index **index_out);
#endif

/* Reset validation progress and restart from block 0. */
void bg_validation_reset(struct bg_validation_service *svc);

/* Global instance pointer — set by boot_services, read by RPC handlers. */
extern struct bg_validation_service *g_bg_validation;

/* `z23 dumpstate bg_validation` — verification progress snapshot.
 * See CLAUDE.md "Adding state introspection". Reentrant-safe. */
struct json_value;
bool bg_validation_dump_state_json(struct json_value *out, const char *key);

#endif
