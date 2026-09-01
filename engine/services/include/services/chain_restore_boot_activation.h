/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Chain Restore Boot Activation — pure boot activate/skip decision. */

#ifndef ZCL_CHAIN_RESTORE_BOOT_ACTIVATION_H
#define ZCL_CHAIN_RESTORE_BOOT_ACTIVATION_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

enum activation_skip_reason {
    ACTIVATE_OK = 0,
    ACTIVATE_SKIP_LEGACY_IMPORT,
    ACTIVATE_SKIP_ANCHOR_CREATED,
    ACTIVATE_SKIP_NO_UTXOS_AWAITING,
    ACTIVATE_SKIP_REINDEX,
};

struct boot_activation_decision {
    bool should_activate;
    enum activation_skip_reason reason;
    int  chain_height;
    int64_t utxo_count;
    size_t  block_index_size;
};

/* Single function replaces 5 scattered skip_activate mutations.
 * Called once at boot, right before reducer activation. */
void boot_should_activate_chain(struct boot_activation_decision *out,
                                int chain_tip_height,
                                int64_t utxo_count,
                                size_t block_index_size,
                                bool legacy_import,
                                bool anchor_was_created);

#endif
