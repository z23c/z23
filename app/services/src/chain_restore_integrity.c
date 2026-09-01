/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Chain Restore Integrity — post-restore validation and health checks. */

// one-result-type-ok:diagnostic-out-structs — E2 (one way out): both public
// entry points return void and produce a single domain output struct each
// (struct chain_restore_validation, struct chain_integrity_result). Each
// struct carries its own ok/all_ok verdict plus the per-check diagnostic
// breakdown (zero_nbits_count, hole/mismatch heights, ...) used by callers and
// exposed through `z23 dumpstate boot`. There is no fallible bool/int surface;
// rich verdict to zcl_result would discard the breakdown the boot fail-fast
// gate switches on. chain_integrity records via
// chain_restore_record_integrity_result() for diagnostics.

#include "services/chain_restore_integrity.h"
#include "services/chain_restore_boot_snapshot.h"
#include "validation/main_state.h"
#include "validation/chainstate.h"
#include "chain/chain.h"
#include <string.h>

void chain_restore_validate(struct chain_restore_validation *out,
                            const struct main_state *ms,
                            const struct uint256 *expected_hash,
                            int expected_height)
{
    memset(out, 0, sizeof(*out));

    out->coins_hash_valid = expected_hash && !uint256_is_null(expected_hash);

    if (expected_hash) {
        struct block_index *found = block_map_find(
            &ms->map_block_index, expected_hash);
        out->anchor_in_map = (found != NULL);
    }

    struct block_index *tip = active_chain_tip(&ms->chain_active);
    out->chain_tip_set = (tip != NULL);

    if (tip && expected_height > 0)
        out->tip_matches_expected = (tip->nHeight == expected_height);

    out->all_ok = out->coins_hash_valid
               && out->anchor_in_map
               && out->chain_tip_set
               && out->tip_matches_expected;
}

void chain_integrity_check_post_restore(struct chain_integrity_result *out,
                                        const struct main_state *ms)
{
    memset(out, 0, sizeof(*out));
    out->first_nbits_zero_height = -1;
    out->first_hole_height = -1;
    out->first_mismatch_height = -1;
    out->first_tip_window_hole = -1;

    if (!ms) {
        out->ok = false;
        return;
    }

    /* every pindex with on-disk data must have nBits != 0.
     *
     * skip nBits=0 entries that have no BLOCK_HAVE_DATA bit.
     * Those are metadata-anchor placeholders left by chain_restore when
     * coins_best_block was unrecoverable from disk. They never enter
     * validation walks (no header is loaded), so a zero nBits on them
     * is harmless. Failing the integrity gate on such an entry —
     * which is the only thing we ever WRITE during the anchor-recovery
     * path — would crash-loop the node forever. */
    size_t iter = 0;
    struct block_index *pi;
    while (block_map_next(&ms->map_block_index, &iter, NULL, &pi)) {
        if (!pi || pi->nHeight <= 0)
            continue;
        if (!(pi->nStatus & BLOCK_HAVE_DATA))
            continue;
        if (pi->nBits == 0) {
            out->zero_nbits_count++;
            if (out->first_nbits_zero_height < 0 ||
                pi->nHeight < out->first_nbits_zero_height)
                out->first_nbits_zero_height = pi->nHeight;
        }
    }

    /* chain_active.chain[h] non-NULL for h in [0, tip].
     *
     * The reducer widens and collapses this window while the condition engine
     * polls it. Reading every slot lock-free is memory-safe (retired arrays
     * remain alive), but it is not a coherent observation: a poll can combine
     * the old height/slots with the new window and manufacture one transient
     * pprev mismatch. `chain_integrity_failed` classifies any mismatch as
     * unrecoverable and launches a disk restore under cs_main, pausing live
     * sync for minutes. Capture the finalized height/tip before taking the
     * leaf writer lock, then hold that lock only for the bounded pointer scan.
     * No other lock or authority lookup occurs inside the critical section. */
    out->tip_height = active_chain_height(&ms->chain_active);
    struct block_index *tip = active_chain_tip(&ms->chain_active);
    int window_lo = out->tip_height - CHAIN_INTEGRITY_TIP_WINDOW;
    if (window_lo < 0) window_lo = 0;
    struct active_chain *chain = (struct active_chain *)&ms->chain_active;
    zcl_mutex_lock(&chain->write_lock);
    for (int h = 0; h <= out->tip_height; h++) {
        struct block_index *at = active_chain_at(chain, h);
        if (at == NULL) {
            out->active_chain_holes++;
            if (out->first_hole_height < 0 || h < out->first_hole_height)
                out->first_hole_height = h;
            if (h >= window_lo) {
                out->tip_window_holes++;
                if (out->first_tip_window_hole < 0 ||
                    h < out->first_tip_window_hole)
                    out->first_tip_window_hole = h;
            }
        } else if (at->nHeight != h) {
            out->active_chain_mismatches++;
            if (out->first_mismatch_height < 0 ||
                h < out->first_mismatch_height)
                out->first_mismatch_height = h;
        } else if (h > 0) {
            struct block_index *prev = active_chain_at(chain, h - 1);
            /* A sparse live-tip window can intentionally omit `prev` while
             * `at->pprev` still names the correct block-map object. The hole
             * is already counted above and is reconcilable; absence is not
             * evidence that the stored ancestry conflicts. A null/wrong-
             * height pprev or disagreement with a PRESENT slot remains
             * unrecoverable. */
            if (!at->pprev || at->pprev->nHeight != h - 1 ||
                (prev && at->pprev != prev)) {
                out->active_chain_mismatches++;
                if (out->first_mismatch_height < 0 ||
                    h < out->first_mismatch_height)
                    out->first_mismatch_height = h;
            }
        }
    }

    /* `ok` reflects operational health.
     *
     * Holes deep below the tip can appear during live-tip-only boot and
     * remain diagnostic, but the near-tip window must be dense because
     * RPC lookups and staged sync use active_chain_at(height) directly.
     * A height mismatch anywhere is also unsafe: callers believe the
     * slot index is the canonical height. */
    out->tip_slot_ok =
        (out->tip_height < 0) ||
        (active_chain_at(chain, out->tip_height) == tip);
    zcl_mutex_unlock(&chain->write_lock);
    out->tip_real =
        !tip || ((tip->nStatus & BLOCK_HAVE_DATA) && tip->nBits != 0);
    out->ok = (out->zero_nbits_count == 0 &&
               out->tip_window_holes == 0 &&
               out->active_chain_mismatches == 0 &&
               out->tip_slot_ok && out->tip_real);

    /* Cache the result for `z23 dumpstate boot`. */
    chain_restore_record_integrity_result(out);
}

enum chain_integrity_class
chain_integrity_classify(const struct chain_integrity_result *r)
{
    if (!r)
        return CHAIN_INTEGRITY_UNRECOVERABLE;   /* fail closed */
    if (r->zero_nbits_count > 0 || r->active_chain_mismatches > 0)
        return CHAIN_INTEGRITY_UNRECOVERABLE;
    if (r->tip_window_holes > 0)
        return CHAIN_INTEGRITY_RECONCILABLE;
    return CHAIN_INTEGRITY_CLEAN;
}
