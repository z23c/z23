/* Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 *
 * CheckTransaction — context-free transaction validation.
 *
 * The pure structural rules now live in domain/consensus/tx_structural.{c,h};
 * this file is the thin core/modules/validation wrapper that:
 *   1. delegates to the domain function (no UTXO/clock/RNG/proofs there)
 *   2. translates the typed zcl_result + (reject_reason, dos) pair back
 *      into the legacy `validation_state` byte-identically (DoS scores
 *      and reject_reason strings are tx-relay-visible)
 *   3. owns the side effects the domain refuses: metrics + event emit
 *
 * Callers see the exact same signature, return value, and reject
 * semantics as before. */

#include "validation/check_transaction.h"
#include "domain/consensus/tx_structural.h"
#include "core/uint256.h"
#include "metrics/metrics.h"
#include "event/event.h"

static bool check_transaction_ctx(const struct transaction *tx,
                                  struct validation_state *state,
                                  enum domain_tx_check_context ctx)
{
    if (!transaction_is_coinbase(tx))
        metrics_increment_tx_validated();

    struct domain_consensus_tx_structural_failure failure = {0};
    struct zcl_result r =
        domain_consensus_check_transaction_structural(tx, ctx, &failure);

    bool ok = r.ok;
    if (!ok) {
        /* Translate domain failure -> legacy validation_state with
         * byte-identical reject_reason and DoS score. Mirrors the
         * pre-extraction REJECT_IF/REJECT_UNLESS expansion exactly. */
        const char *reason = failure.reject_reason ? failure.reject_reason : "";
        validation_state_dos(state, failure.dos, false, REJECT_INVALID,
                             reason, false, NULL);
    }

    /* Emit on invalid (DoS-able) rejections. Skip MODE_ERROR (fatal,
     * internal failures unrelated to consensus) and successful runs.
     * Payload format: "hash=<64hex> reason=<name> dos=<n>".
     * Hash lets consensus_reject_index key rejections by txid so
     * a native reject-explanation command can answer why it was rejected. */
    if (!ok && state && state->mode == MODE_INVALID &&
        state->reject_reason[0] != '\0') {
        char hex[65];
        uint256_get_hex(&tx->hash, hex);
        event_emitf(EV_CONSENSUS_REJECT_TX, 0,
                    "hash=%s reason=%s dos=%d",
                    hex, state->reject_reason, state->dos);
    }
    return ok;
}

bool check_transaction(const struct transaction *tx,
                       struct validation_state *state)
{
    return check_transaction_ctx(tx, state, DOMAIN_TX_CTX_STANDALONE);
}

bool check_transaction_in_block(const struct transaction *tx,
                                struct validation_state *state)
{
    return check_transaction_ctx(tx, state, DOMAIN_TX_CTX_BLOCK);
}
