/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * seal_rewind — the state-seal ring's REWIND CONSUMER. The seal ring
 * (storage/seal_kv.h) persists a self-verified coins_sha3 every ~1000 blocks;
 * until now nothing could REWIND to one. This is the executable consumer: given
 * a target height H below the applied frontier, reset the reducer to the NEAREST
 * self-verified seal at/below H so a forward drive re-folds only [G, H] from
 * on-disk PoW-verified bodies — O(delta from the nearest seal) recovery instead
 * of an O(chain) fold from the single compiled SHA3 checkpoint.
 *
 * The rewind is a DEEP generalization of the reorg unwind (utxo_apply_delta_
 * reorg.c): it replays the retained inverse deltas down to the seal, but where
 * the reorg path proves its base by active-chain hash agreement, this proves it
 * by RE-DERIVING the coins set at G and requiring it reproduce the seal's stored
 * coins_sha3 — a self-derived proof, never trust of the stored value alone. A
 * seal whose commitment does not reproduce is REFUSED (the rewind rolls back and
 * leaves the reducer untouched), so a torn anchor self-heals on any datadir. */

#ifndef ZCL_JOBS_SEAL_REWIND_H
#define ZCL_JOBS_SEAL_REWIND_H

#include <stdbool.h>
#include <stdint.h>

struct sqlite3;

/* Why a rewind did NOT reset the reducer. SEAL_REWIND_OK means it did. */
enum seal_rewind_refusal {
    SEAL_REWIND_OK = 0,
    SEAL_REWIND_NO_BASE,             /* no self-valid seal at/below H */
    SEAL_REWIND_ABOVE_FRONTIER,      /* seal at/above the applied frontier — nothing to unwind */
    SEAL_REWIND_BELOW_FLOOR,         /* seal height < the finality floor — refused */
    SEAL_REWIND_COMMITMENT_MISMATCH, /* re-derived coins_sha3 != seal.coins_sha3 — torn seal */
    SEAL_REWIND_STORE_ERROR,         /* a durable-store / inverse-delta error */
};

struct seal_rewind_result {
    bool     rewound;         /* the reducer cursors + coins were reset to the seal */
    bool     base_found;      /* a self-valid seal at/below H existed */
    bool     coins_verified;  /* the re-derived coins_sha3 reproduced the seal's */
    enum seal_rewind_refusal refusal;
    int32_t  target_h;        /* the requested rewind target H */
    int32_t  seal_height;     /* G, the selected seal (-1 if none) */
    int32_t  cursor_before;   /* utxo_apply cursor at entry (next height to apply) */
    int32_t  unwound_heights; /* count of block heights inverse-applied */
};

/* Rewind the reducer to the NEAREST self-verified seal at or below H so a later
 * forward drive re-folds [G, H] from on-disk bodies. All steps run under ONE
 * progress.kv BEGIN IMMEDIATE (atomic or nothing):
 *   1. select the nearest self-valid seal G <= H (seal_kv_nearest_rewind_base);
 *   2. replay the retained inverse deltas for [G, cursor-1] into coins_kv so the
 *      set reflects coins_applied_height == G;
 *   3. SELF-VERIFY: recompute coins_kv_commitment over the re-derived set and
 *      REFUSE (rollback) unless it reproduces the seal's stored coins_sha3;
 *   4. on match, drop the now-invalid utxo_apply log/delta/nullifier/anchor rows
 *      above G, force the utxo_apply + tip_finalize cursors down to G, and pull
 *      coins_applied_height back to G.
 *
 * `floor` is the height the rewind may never cross (pass reducer_frontier_floor()
 * in production; 0 in a from-genesis / testnet context). A seal below `floor`
 * is refused so the rewind never crosses the irreversible finality boundary.
 *
 * Never touches upstream header/script/proof logs — their [G, H] verdicts stay
 * valid because the seal domain is the UTXO set — and never DELETES tip_finalize_
 * log rows (only its cursor moves), preserving the served-floor evidence.
 *
 * Returns false only on a NULL arg; every other outcome (including a clean
 * refusal) returns true with *out describing what happened. */
bool seal_rewind_to_nearest(struct sqlite3 *db, int32_t H, int32_t floor,
                            struct seal_rewind_result *out);

#endif /* ZCL_JOBS_SEAL_REWIND_H */
