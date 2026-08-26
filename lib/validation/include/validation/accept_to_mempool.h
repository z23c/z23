/* Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#ifndef ZCL_ACCEPT_TO_MEMPOOL_H
#define ZCL_ACCEPT_TO_MEMPOOL_H

#include "primitives/transaction.h"
#include "consensus/params.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* accept_to_mempool — the ONE shared mempool-acceptance gate.
 *
 * Before this existed, the P2P `tx` handler (lib/net/src/msg_tx.c) and
 * the RPC sendrawtransaction handler (app/controllers) each had their
 * own partial accept path. Both ran check_transaction (structural) and
 * — on the P2P side only — inputs-exist + min-relay-fee. NEITHER ran
 * the cryptographic checks: per-input scriptSig verification
 * (verify_script) and the shielded-proof / JoinSplit-signature
 * verification in contextual_check_transaction. The result: a tx with a
 * structurally-valid shape, existing prevouts, but an INVALID signature
 * or a forged Sapling/Sprout proof was added to the mempool and fluffed
 * network-wide; only block-connect later rejected it. An invalid-sig
 * flood thus wasted every node's bandwidth and mempool space.
 *
 * This helper closes that gap with a single code path used by BOTH
 * callers. It runs, in order:
 *   1. check_transaction              (structural / context-free)
 *   2. contextual_check_transaction   (JoinSplit Ed25519 sig, Sapling
 *                                      Groth16 spend/output proofs +
 *                                      binding sig, Sprout zk-SNARKs)
 *   3. next-block finality             (height + tip median-time-past)
 *   4. (with a live coins view) inputs-exist, value/fee sanity,
 *      min-relay-fee, and per-input verify_script (the transparent
 *      signature check that was missing) BEFORE add+relay.
 *
 * connect_block remains the consensus backstop and re-verifies
 * everything at block time — this helper is mempool admission policy,
 * not a consensus relaxation. It NEVER admits a tx that connect_block
 * would reject; it only rejects (some) txs earlier, so they are never
 * relayed.
 *
 * Parameters are plain primitives so the helper lives in lib/validation
 * (a layer both lib/net and app/controllers already depend on) without
 * pulling in either caller's context struct:
 *   - pool       : destination mempool (required)
 *   - coins_tip  : live UTXO + shielded-anchor view (required).
 *   - main_state : chain tip, for next-block height / branch id (required).
 *   - params     : chain params / upgrade schedule (required).
 *   - tx         : the candidate. Its hash must already be computed by
 *                  the caller (transaction_compute_hash).
 *
 * Any missing required context returns MEMPOOL_ACCEPT_INTERNAL_ERROR and the
 * transaction is not inserted. Returns one of enum mempool_accept_result. The caller maps the result
 * onto its own reject reason / peer scoring / RPC error string. */
enum mempool_accept_result {
    MEMPOOL_ACCEPT_OK = 0,
    MEMPOOL_ACCEPT_INVALID,         /* structural / proof / script failed */
    MEMPOOL_ACCEPT_DUPLICATE,       /* already in mempool */
    MEMPOOL_ACCEPT_CONFLICT,        /* double-spend vs current mempool */
    MEMPOOL_ACCEPT_BELOW_FEE,       /* fee < min_relay_fee */
    MEMPOOL_ACCEPT_MISSING_INPUTS,  /* unknown inputs (orphan) */
    MEMPOOL_ACCEPT_NONFINAL,        /* nLockTime not final for next block */
    MEMPOOL_ACCEPT_EXPIRING_SOON,   /* expiry falls inside relay horizon */
    MEMPOOL_ACCEPT_INTERNAL_ERROR,  /* mempool full / OOM / bad args */
    /* We could not CHECK it — the shielded verifying keys are not
     * installed, or the verification context could not be allocated.
     * NOT an acceptance: the transaction is rejected and never relayed.
     * It is simply not the sender's fault, so it must never be scored.
     *
     * Un-steerable by a peer: every condition behind this result is a
     * property of THIS node (a boot-time key latch, an allocation), not
     * of the bytes the peer sent, so a peer cannot craft a transaction
     * that lands here while another lands on MEMPOOL_ACCEPT_INVALID.
     * Either every shielded transaction is unverifiable right now or
     * none is. Volume abuse during such a window is bounded separately
     * by the relay layer's per-peer rate limit, not by this enum. */
    MEMPOOL_ACCEPT_UNVERIFIABLE,
};

struct tx_mempool;
struct coins_view_cache;
struct main_state;
struct chain_params;

enum mempool_accept_result accept_to_mempool(
    struct tx_mempool *pool,
    struct coins_view_cache *coins_tip,
    struct main_state *main_state,
    const struct chain_params *params,
    struct transaction *tx);

/* Same gate with one bounded, non-secret reject token for operator-created
 * transactions. The ordinary P2P callers keep the compact enum-only API. */
enum mempool_accept_result accept_to_mempool_detailed(
    struct tx_mempool *pool,
    struct coins_view_cache *coins_tip,
    struct main_state *main_state,
    const struct chain_params *params,
    struct transaction *tx,
    char *detail_out,
    size_t detail_cap);

#endif /* ZCL_ACCEPT_TO_MEMPOOL_H */
