/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Chain restore planner — deterministic, side-effect-light planning for
 * chain tip restoration. */

// one-result-type-ok:single-plan-out-struct — E2 (one way out): the sole
// public entry point `chain_restore_plan()` returns void and emits one
// domain output, struct chain_restore_plan, which carries the next_state
// (enum chain_restore_state, incl. CHAIN_RESTORE_FAILED) plus the full
// decision payload and a human-readable `reason[128]`. There is no fallible
// bool/int surface to lose a reason; collapsing the plan to zcl_result would
// drop the action fields the caller switches on. Every branch fills `reason`
// and records via chain_restore_record_plan_result() for native dump-state
// inspection.

#include "services/chain_restore_planner.h"
#include "services/chain_restore_boot_snapshot.h"

#include <stdio.h>
#include <string.h>

void chain_restore_plan(struct chain_restore_plan *out,
                        const struct chain_restore_input *in)
{
    memset(out, 0, sizeof(*out));

    /* Null hash → nothing to restore */
    if (uint256_is_null(&in->coins_best_hash)) {
        out->next_state = CHAIN_RESTORE_FAILED;
        out->should_skip_activate = true;
        snprintf(out->reason, sizeof(out->reason),
                 "coins_best_block is null — no UTXO state");
        chain_restore_record_plan_result(out);
        return;
    }

    /* Path A: hash found in block_map with valid height */
    if (in->hash_found_in_map && in->found_height > 0) {
        out->next_state = CHAIN_RESTORE_FOUND_IN_INDEX;
        out->should_set_chain_tip = true;
        out->should_set_best_header = true;
        out->should_skip_activate = true;
        out->anchor_height = in->found_height;
        out->anchor_hash = in->coins_best_hash;
        snprintf(out->reason, sizeof(out->reason),
                 "found in block index at h=%d", in->found_height);
        chain_restore_record_plan_result(out);
        return;
    }

    /* Path B: hash NOT in block_map but we know UTXO height */
    if (in->utxo_max_height > 0) {
        out->next_state = CHAIN_RESTORE_ANCHOR_CREATED;
        out->should_create_anchor = true;
        out->should_set_snapshot_anchor = true;
        out->should_skip_activate = true;
        out->anchor_height = in->utxo_max_height;
        out->anchor_hash = in->coins_best_hash;
        snprintf(out->reason, sizeof(out->reason),
                 "anchor at h=%d (hash not in index, %s)",
                 in->utxo_max_height,
                 in->source == CHAIN_RESTORE_SRC_LDB_IMPORT ? "LDB import"
                 : in->source == CHAIN_RESTORE_SRC_SNAPSHOT ? "snapshot"
                 : "boot");
        chain_restore_record_plan_result(out);
        return;
    }

    /* Path C: no height info at all */
    out->next_state = CHAIN_RESTORE_FAILED;
    out->should_skip_activate = true;
    snprintf(out->reason, sizeof(out->reason),
             "coins_best_block set but height unknown — awaiting P2P");
    chain_restore_record_plan_result(out);
}
