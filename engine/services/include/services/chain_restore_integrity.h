/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Chain Restore Integrity — post-restore validation and health checks. */

#ifndef ZCL_CHAIN_RESTORE_INTEGRITY_H
#define ZCL_CHAIN_RESTORE_INTEGRITY_H

#include "core/uint256.h"
#include <stdbool.h>

struct main_state;

struct chain_restore_validation {
    bool coins_hash_valid;       /* hash is not null */
    bool anchor_in_map;          /* anchor found in block_map */
    bool chain_tip_set;          /* active_chain_tip != NULL */
    bool tip_matches_expected;   /* tip height == expected height */
    bool all_ok;                 /* all checks passed */
};

void chain_restore_validate(struct chain_restore_validation *out,
                            const struct main_state *ms,
                            const struct uint256 *expected_hash,
                            int expected_height);

/* `tip_window_holes` is the number of NULL active_chain slots in the
 * range [max(0, tip - CHAIN_INTEGRITY_TIP_WINDOW), tip]. Holes below
 * this window are an expected by-product of the capped pprev walk
 * during live boot (only ~10k entries populated near the tip on a
 * 3M-block chain) and are not corruption — they get filled on demand
 * by code that needs ancestor lookups.
 *
 * boot fail-fast gate honors `tip_window_holes`,
 * not `active_chain_holes`. The latter is informational and stays
 * positive on every live-tip-only boot. */
#define CHAIN_INTEGRITY_TIP_WINDOW 10000

struct chain_integrity_result {
    int  zero_nbits_count;
    int  active_chain_holes;      /* total NULL slots in [0, tip] */
    int  active_chain_mismatches; /* slots whose block_index height != slot */
    int  tip_window_holes;        /* NULL slots in [tip-WINDOW, tip] */
    int  tip_height;
    int  first_nbits_zero_height; /* -1 if none */
    int  first_hole_height;       /* -1 if none (overall) */
    int  first_mismatch_height;   /* -1 if none */
    int  first_tip_window_hole;   /* -1 if none (within window) */
    bool tip_slot_ok;             /* active_chain_at(tip_height) == tip */
    bool tip_real;                /* tip has BLOCK_HAVE_DATA and nBits != 0 */
    /* ok = zero_nbits_count==0 && tip_window_holes==0 &&
     *      active_chain_mismatches==0 && tip_slot_ok && tip_real.
     * The boolean terms MUST appear in any failure report: a failure with
     * all four counters zero is undiagnosable unless the booleans are
     * surfaced too. */
    bool ok;
};

/* Reads the active-chain slots as one writer-serialized snapshot. The block
 * map's process-lifetime objects remain lock-free; only the bounded slot walk
 * takes active_chain.write_lock, and it performs no nested authority lookup. */
void chain_integrity_check_post_restore(struct chain_integrity_result *out,
                                        const struct main_state *ms);

/* Classification of a post-restore integrity result for the boot
 * finalize gate.
 *
 *   CLEAN         — nothing wrong.
 *   RECONCILABLE  — active_chain window holes only (no zero-nbits, no
 *                   height/pprev mismatch). Normal coins-application
 *                   lag: headers/bodies are ahead of the applied tip.
 *                   NEVER fatal — the node serves DEGRADED while the
 *                   normal reducer/frontier path reconciles it forward.
 *   UNRECOVERABLE — zero nbits in the tip window, or active_chain
 *                   height/pprev mismatches. True structural
 *                   corruption: stays fatal (LOUD) unless -allow-degraded.
 *
 * Pure function of the result struct so the boot gate and its unit
 * test share one predicate. A NULL result is UNRECOVERABLE (fail
 * closed). */
enum chain_integrity_class {
    CHAIN_INTEGRITY_CLEAN = 0,
    CHAIN_INTEGRITY_RECONCILABLE,
    CHAIN_INTEGRITY_UNRECOVERABLE,
};

enum chain_integrity_class
chain_integrity_classify(const struct chain_integrity_result *r);

#endif
