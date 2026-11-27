/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
/* Evaluate one miner-signalled migration on a selected chain branch. */
#ifndef ZCL_SERVICES_MINER_SIGNAL_ROUND_H
#define ZCL_SERVICES_MINER_SIGNAL_ROUND_H

#include "base/result.h"
#include "core/uint256.h"
#include <stdbool.h>
#include <stdint.h>

struct transaction;

/* One independently scheduled proposal in a catalog of 1..256 slots. */
struct miner_signal_schedule {
    int32_t start, window, activation;
    uint16_t slots, slot;
    uint8_t catalog[32];
};

enum miner_signal_phase {
    MINER_SIGNAL_VOTING,
    MINER_SIGNAL_EXPIRED,
    MINER_SIGNAL_LOCKED_IN,
    MINER_SIGNAL_ACTIVE
};

/* A branch-local tally after parent_height. Preserve the parent snapshot for
 * disconnect. Callers must obtain both block identities and the coinbase from
 * the same fully validated block. Missing data is an error, never silence. */
struct miner_signal_tally {
    struct miner_signal_schedule schedule;
    int32_t parent_height, votes;
    struct uint256 parent_hash;
};

struct zcl_result miner_signal_schedule_valid(const struct miner_signal_schedule *schedule);
/* Once all window blocks are tallied, the caller may query any subsequent
 * candidate height on a verified descendant branch. */
struct zcl_result miner_signal_phase_at(const struct miner_signal_tally *tally, int32_t candidate_height,
                           enum miner_signal_phase *out);
struct zcl_result miner_signal_begin(const struct miner_signal_schedule *schedule,
                        int32_t parent_height, const struct uint256 *parent_hash,
                        struct miner_signal_tally *out);
struct zcl_result miner_signal_connect(const struct miner_signal_tally *parent, int32_t height,
                          const struct uint256 *prev_hash, const struct uint256 *hash,
                          const struct transaction *coinbase, struct miner_signal_tally *out);
enum miner_signal_phase miner_signal_next_phase(const struct miner_signal_tally *tally);

#endif
