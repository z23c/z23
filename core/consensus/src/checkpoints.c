/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Pure checkpoint matching. Replays from inputs alone — no clock,
 * no RNG, no I/O, no state reads. Extracted from
 * core/modules/chain/src/checkpoints.c. The single clock read in the legacy
 * `guess_verification_progress` was lifted to a parameter
 * (`now_unix_sec`); the lib/ wrapper holds the `platform_time_wall_time_t()`
 * call and forwards.
 *
 * See the header for the contract of each function and the
 * rationale for what stayed in lib/. */

#include "domain/consensus/checkpoints.h"

#include "chain/checkpoints.h"
#include "core/uint256.h"

static const double DOMAIN_SIGCHECK_VERIFICATION_FACTOR = 5.0;

bool domain_consensus_checkpoints_hash_at_height(
        const struct checkpoint_data *data,
        int height,
        struct uint256 *out_hash)
{
    if (!data || !out_hash)
        return false;
    for (int i = 0; i < data->nEntries; i++) {
        if (data->entries[i].height == height) {
            *out_hash = data->entries[i].hash;
            return true;
        }
    }
    return false;
}

int domain_consensus_checkpoints_last_height(
        const struct checkpoint_data *data)
{
    if (!data || data->nEntries == 0)
        return -1;
    /* Entries are ascending-height in practice (chainparams.c).
     * Defensive scan in case that ever gets shuffled. */
    int best = -1;
    for (int i = 0; i < data->nEntries; i++) {
        if (data->entries[i].height > best)
            best = data->entries[i].height;
    }
    return best;
}

bool domain_consensus_checkpoints_validate_header(
        const struct checkpoint_data *data,
        int height,
        const struct uint256 *hash)
{
    if (!data || !hash)
        return true;  /* degenerate: nothing to check */
    struct uint256 expected;
    if (!domain_consensus_checkpoints_hash_at_height(data, height, &expected))
        return true;  /* no checkpoint at this height */
    return uint256_cmp(hash, &expected) == 0;
}

int domain_consensus_checkpoints_total_blocks_estimate(
        const struct checkpoint_data *data)
{
    if (!data || data->nEntries == 0)
        return 0;
    return data->entries[data->nEntries - 1].height;
}

double domain_consensus_checkpoints_progress_at_now(
        const struct checkpoint_data *data,
        uint64_t pindex_chain_tx,
        int64_t  pindex_time_seconds,
        int64_t  now_unix_sec,
        bool     fSigchecks)
{
    if (!data)
        return 0.0;

    double fSigcheckFactor = fSigchecks ? DOMAIN_SIGCHECK_VERIFICATION_FACTOR : 1.0;
    double fWorkBefore = 0.0;
    double fWorkAfter  = 0.0;

    if ((int64_t)pindex_chain_tx <= data->nTransactionsLastCheckpoint) {
        double nCheapBefore     = (double)pindex_chain_tx;
        double nCheapAfter      = (double)data->nTransactionsLastCheckpoint - nCheapBefore;
        double nExpensiveAfter  = (double)(now_unix_sec - data->nTimeLastCheckpoint) /
                                  86400.0 * data->fTransactionsPerDay;
        fWorkBefore = nCheapBefore;
        fWorkAfter  = nCheapAfter + nExpensiveAfter * fSigcheckFactor;
    } else {
        double nCheapBefore     = (double)data->nTransactionsLastCheckpoint;
        double nExpensiveBefore = (double)pindex_chain_tx - nCheapBefore;
        double nExpensiveAfter  = (double)(now_unix_sec - pindex_time_seconds) /
                                  86400.0 * data->fTransactionsPerDay;
        fWorkBefore = nCheapBefore + nExpensiveBefore * fSigcheckFactor;
        fWorkAfter  = nExpensiveAfter * fSigcheckFactor;
    }

    /* Defensive against divide-by-zero. The historical implementation
     * silently produced inf/NaN here; we'd rather return a clean 0.0. */
    double denom = fWorkBefore + fWorkAfter;
    if (denom <= 0.0)
        return 0.0;
    return fWorkBefore / denom;
}
