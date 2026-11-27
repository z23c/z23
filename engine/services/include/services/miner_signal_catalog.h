/* purpose: Canonically bind miner ballot slots to a network and round. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZCL_SERVICES_MINER_SIGNAL_CATALOG_H
#define ZCL_SERVICES_MINER_SIGNAL_CATALOG_H

#include "base/result.h"
#include "services/miner_signal_round.h"
#include <stddef.h>
#include <stdint.h>

/* Caller supplies the exact network/fork ID and genesis bytes, pinned by its
 * deployment configuration. IDs and rule revisions are raw bytes, not hex. */
struct miner_signal_catalog_entry {
    uint8_t rule_revision[32];
    int32_t activation;
};
struct miner_signal_catalog {
    uint8_t network_id[32];
    uint8_t genesis[32];
    int32_t start, window;
    size_t count;
    const struct miner_signal_catalog_entry *entries;
};

/* v1 byte encoding, exactly: ASCII "Z23-CATALOG-V1" without NUL; 32 raw
 * network_id bytes; 32 raw genesis bytes; LE32 start, window, count, 95,
 * 100, 1; then count entries, each 32 raw rule_revision bytes and LE32
 * activation. SHA3-256 produces the catalog bytes used in ballot scripts.
 * Version 1 requires >=95/100 of the complete window and >=1 complete
 * post-window old-rule block: activation > start + window. Entries are
 * strictly ascending unsigned bytewise by rule_revision; sorting is the
 * caller's responsibility. Both network and genesis must be nonzero.
 *
 * The entire catalog is checked before writing the selected schedule. On
 * failure *out is untouched. This is pure encoding, not network authority,
 * rule validation, deployment approval, or consensus activation. */
struct zcl_result miner_signal_catalog_select(const struct miner_signal_catalog *catalog,
                                              size_t slot,
                                              struct miner_signal_schedule *out);
#endif
