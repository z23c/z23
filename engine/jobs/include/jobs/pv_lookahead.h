/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * pv_lookahead — cross-height shielded-proof pre-verification for the OFFLINE
 * -mint-anchor fold.
 *
 * proof_validate is the mint fold's slowest stage (~13-18ms/block, serial on
 * the single drive thread) while proof verification is a pure function of
 * (block bytes, verifying keys). This pool runs N supervised workers that read
 * block bodies AHEAD of the drive cursor (the same lock-free active_chain_at +
 * pread path bg_validation already exercises concurrently), verify every
 * shielded proof with the SAME effective verifier the stage would use, and
 * cache the per-height verdict keyed by (height, block_hash).
 *
 * Bit-identical semantics by construction:
 *   - a verdict is consumed only on an exact (height, block_hash, verifier,
 *     verifier_user) match — a reorg or verifier swap is a cache MISS, never a
 *     wrong verdict; on any miss the stage verifies inline exactly as today;
 *   - a body/data gap at one height does not stop workers from verifying later
 *     readable heights in the same window.  The skipped height remains an
 *     ordinary cache miss that the serial drive retries inline; globally
 *     unavailable verifier parameters still hold the pool at that height;
 *   - internal_error results (allocation/verifier faults) are NEVER cached, so
 *     the stage's TL-2 HOLD path always runs inline;
 *   - the verdict carries the counter deltas of the serial stop-at-first-
 *     failure reduce, applied by the drive in serial height order.
 *
 * SCOPE GATE: pv_lookahead_start is reached only through
 * proof_validate_lookahead_start (proof_validate_stage.h). Its production
 * callers are engine/composition/src/boot_mint_anchor.c (the offline -mint-anchor fold,
 * always) and engine/composition/src/boot_pv_lookahead.c (the live/replay reducer path,
 * only under -pv-lookahead, default off). When the pool is not running
 * pv_lookahead_take is a single relaxed atomic load. */

#ifndef ZCL_JOBS_PV_LOOKAHEAD_H
#define ZCL_JOBS_PV_LOOKAHEAD_H

#include "core/uint256.h"
#include "jobs/proof_validate_stage.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct main_state;

struct pv_lookahead_verdict {
    int ok;                     /* 0/1; internal_error verdicts are never cached */
    size_t sapling_spends_total;
    size_t sapling_outputs_total;
    size_t sprout_joinsplits_total;
    struct uint256 first_failure_txid;
    const char *first_failure_proof_type;   /* static literal or NULL */
    /* Success-counter deltas accumulated by the worker's reduce in original tx
     * order with the serial sweep's stop-at-first-failure semantics; the drive
     * applies them at consume time so the stage counters match a serial fold
     * at every block boundary. */
    uint64_t spends_verified;
    uint64_t outputs_verified;
    uint64_t sprout_groth16_verified;
    uint64_t sprout_phgr13_verified;
    uint64_t binding_sig_verified;
};

/* Fixed lookahead window (heights ahead of the drive cursor workers may
 * verify); also the verdict ring capacity. Workers stall when full. */
#define PV_LOOKAHEAD_WINDOW 256

/* Start the pool: min(cores-2, 8) workers (>=1), env ZCL_PV_WORKERS override
 * (clamped 1..16). `reader`/`reader_user` NULL selects the production pread
 * path (deliberately bypassing block_parse_cache so lookahead reads never
 * evict the entries the other stages share). `verifier`/`verifier_user` must
 * be the stage's effective pair — pv_lookahead_take re-checks it. Returns
 * false (pool stays off; the fold runs serially) on any spawn/alloc failure.
 * Refuses a double start. */
bool pv_lookahead_start(struct main_state *ms, const char *datadir,
                        stage_block_reader_fn reader, void *reader_user,
                        proof_validate_tx_verify_fn verifier,
                        void *verifier_user);

/* Signal stop, join every worker, release the ring. Idempotent; safe when the
 * pool never started. */
void pv_lookahead_stop(void);

/* Consume the cached verdict for (height, block_hash) if the pool is running,
 * the verifier pair matches the pool's, and the slot is an exact match. On a
 * hit copies the verdict to *out, frees the slot, and returns true. Any other
 * outcome is a miss (false) — the caller verifies inline. */
bool pv_lookahead_take(int height, const struct uint256 *block_hash,
                       proof_validate_tx_verify_fn verifier,
                       void *verifier_user,
                       struct pv_lookahead_verdict *out);

/* Telemetry: consume-time hits/misses (counted only while running) and the
 * number of currently populated slots (tests use it to await warm-up). */
uint64_t pv_lookahead_hit_total(void);
uint64_t pv_lookahead_miss_total(void);
uint64_t pv_lookahead_populated(void);

/* See CLAUDE.md "Adding state introspection". Reentrant-safe. Reports the
 * pool's running flag, worker count, window, queue depth (warmed-not-consumed
 * verdicts), cache hits/misses/hit_rate, verdicts_produced, pre-verify
 * throughput (blk/s), and supervisor liveness-tree membership. */
struct json_value;
bool pv_lookahead_dump_state_json(struct json_value *out, const char *key);

#endif /* ZCL_JOBS_PV_LOOKAHEAD_H */
