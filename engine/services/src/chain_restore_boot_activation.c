/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Chain Restore Boot Activation — pure boot activate/skip decision. */

// one-result-type-ok:single-decision-out-struct — E2 (one way out): the sole
// entry point `boot_should_activate_chain()` returns void and produces one
// domain output, struct boot_activation_decision, carrying should_activate
// plus enum activation_skip_reason (the skip cause travels with the
// decision). It owns no fallible bool/int surface; this is a pure,
// deterministic predicate over its inputs, not a service operation.

#include "services/chain_restore_boot_activation.h"
#include <string.h>

void boot_should_activate_chain(struct boot_activation_decision *out,
                                int chain_tip_height,
                                int64_t utxo_count,
                                size_t block_index_size,
                                bool legacy_import,
                                bool anchor_was_created)
{
    memset(out, 0, sizeof(*out));
    out->chain_height = chain_tip_height;
    out->utxo_count = utxo_count;
    out->block_index_size = block_index_size;

    if (legacy_import) {
        out->should_activate = false;
        out->reason = ACTIVATE_SKIP_LEGACY_IMPORT;
        return;
    }

    if (anchor_was_created) {
        out->should_activate = false;
        out->reason = ACTIVATE_SKIP_ANCHOR_CREATED;
        return;
    }

    /* No UTXOs + many headers = awaiting P2P snapshot.
     * Connecting blocks from genesis would mark valid blocks FAILED. */
    if (utxo_count < 100000 && chain_tip_height == 0
        && block_index_size > 1000) {
        out->should_activate = false;
        out->reason = ACTIVATE_SKIP_NO_UTXOS_AWAITING;
        return;
    }

    out->should_activate = true;
    out->reason = ACTIVATE_OK;
}
