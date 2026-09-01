/* Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 *
 * Epoch-I thin wrapper. The pure sigop-counting arithmetic lives in
 * domain/consensus/sigops.{h,c}; this file preserves the legacy
 * uint64_t-returning signatures so existing callers stay unchanged
 * while the domain functions return a typed zcl_result.
 *
 * The P2SH wrapper performs the prevout resolution against the
 * coins_view_cache here (IO/state-touching), then calls the pure
 * domain counter with a resolved-prevouts array — keeping the
 * hexagonal seam clean. */

#include "validation/sigops.h"

#include "domain/consensus/sigops.h"

#include "coins/coins_view.h"
#include "primitives/transaction.h"
#include "script/script.h"
#include "script/script_flags.h"
#include "util/safe_alloc.h"

#include <stdio.h>
#include <stdlib.h>

uint64_t get_legacy_sig_op_count(const struct transaction *tx, uint32_t flags)
{
    uint64_t count = 0;
    struct zcl_result r = domain_consensus_tx_legacy_sig_op_count(tx, flags, &count);
    if (!r.ok) {
        /* Preserve legacy fail-safe behaviour: a null tx returns 0.
         * The domain function already populated zcl_result with a
         * precise reason. */
        fprintf(stderr,  // obs-ok:legacy-wrapper-preserves-pre-extraction-stderr
                "FATAL: get_legacy_sig_op_count failed: %s\n",
                r.message[0] ? r.message : "(no message)");
        return 0;
    }
    return count;
}

uint64_t get_p2sh_sig_op_count(const struct transaction *tx,
                                struct coins_view_cache *view,
                                uint32_t flags)
{
    /* Replicate the gating *before* allocating a prevouts array —
     * matches the domain contract and avoids any allocation in the
     * common pre-P2SH / coinbase paths. */
    if (!tx)
        return 0;
    if ((flags & SCRIPT_VERIFY_P2SH) == 0)
        return 0;
    if (transaction_is_coinbase(tx))
        return 0;
    if (tx->num_vin == 0)
        return 0;

    /* Resolve every prevout up front (the IO/state-touching step).
     * The domain function is pure on the resolved array. */
    const struct tx_out **prevouts =
        zcl_malloc(tx->num_vin * sizeof(*prevouts), "p2sh_sigops_prevouts");
    if (!prevouts) {
        fprintf(stderr,  // obs-ok:legacy-wrapper-preserves-pre-extraction-stderr
                "FATAL: get_p2sh_sig_op_count: prevouts alloc failed (vin=%zu)\n",
                tx->num_vin);
        return 0;
    }
    for (size_t i = 0; i < tx->num_vin; i++)
        prevouts[i] = coins_view_cache_get_output_for(view, &tx->vin[i]);

    uint64_t count = 0;
    struct zcl_result r = domain_consensus_tx_p2sh_sig_op_count(
            tx, prevouts, flags, &count);
    free(prevouts);

    if (!r.ok) {
        fprintf(stderr,  // obs-ok:legacy-wrapper-preserves-pre-extraction-stderr
                "FATAL: get_p2sh_sig_op_count failed: %s\n",
                r.message[0] ? r.message : "(no message)");
        return 0;
    }
    return count;
}
