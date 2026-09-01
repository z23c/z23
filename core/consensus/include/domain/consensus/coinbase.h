/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rhett Creighton
 *
 * domain/consensus/coinbase.h — pure coinbase-transaction shaping.
 *
 * Given (height, extra_nonce, total_fees, subsidy, miner script,
 * consensus_params), build the canonical coinbase `struct transaction`
 * that the mining template emits:
 *
 *   - vin[0].prevout = null (OUTPOINT_NULL, n = 0xffffffff)
 *   - vin[0].script_sig encodes the BIP34 3-byte height push
 *     followed by either an OP_0 placeholder (pre-extra-nonce shape,
 *     emitted by `create_new_block` before `increment_extra_nonce`)
 *     or the canonical extra-nonce push (post-`increment_extra_nonce`
 *     shape).
 *   - vout[0].script_pub_key = caller-supplied miner script
 *   - vout[0].value = subsidy + total_fees
 *   - version / version_group_id selected by epoch (pre-Overwinter
 *     stays at v1 group_id=0; Overwinter -> v3/0x03C48270;
 *     Sapling -> v4/0x892F2085) — version is left untouched if the
 *     epoch is pre-Overwinter so the caller's prior init wins.
 *   - expiry_height = 0
 *
 * NO clock, NO RNG, NO IO, NO mempool reads. Extra-nonce and total_fees
 * are caller-supplied; nTime + nBits are header-level fields filled by
 * the orchestrator (`create_new_block`) and are NOT touched here. The
 * caller pre-allocates vin[1] / vout[1] (allocation is an adapter
 * concern, not a domain concern); this function fills the fields and
 * recomputes the transaction hash.
 *
 * Replays from inputs alone: same `(height, extra_nonce, fees, subsidy,
 * miner_script, params)` always produces a transaction with the same
 * serialized bytes and the same `.hash`.
 *
 * What is NOT here (deliberately): mempool greedy packing, sigop
 * accounting, fee summation, header timestamp/nBits, merkle-root
 * computation, broadcast / process_new_block. Those remain block-
 * template *orchestration* in `core/modules/mining/src/miner.c::create_new_block`
 * because they touch the live UTXO cache, mempool, chain tip, and
 * wall-clock.
 *
 * Layering: depends only on primitives/transaction.h, script/script.h,
 * consensus/params.h, consensus/upgrades.h, core/amount.h,
 * util/result.h. No callbacks into lib/ services.
 */

#ifndef ZCL_DOMAIN_CONSENSUS_COINBASE_H
#define ZCL_DOMAIN_CONSENSUS_COINBASE_H

#include <stdbool.h>
#include <stdint.h>

#include "util/result.h"

struct transaction;
struct script;
struct consensus_params;

/* Write the BIP34 height-push + OP_0 placeholder scriptSig form into
 * `out`. This is the byte-identical scriptSig that legacy
 * `create_new_block` puts on the coinbase BEFORE
 * `increment_extra_nonce` is called the first time:
 *
 *     [ 0x03, h[0], h[1], h[2], OP_0 ]            -> size 5
 *
 * Caller guarantees `out` is a writable `struct script`. Pure.
 *
 * Returns DOMAIN_CONSENSUS_COINBASE_ERR_NULL_OUT     if out == NULL,
 *         DOMAIN_CONSENSUS_COINBASE_ERR_NEG_HEIGHT   if n_height < 0,
 *         DOMAIN_CONSENSUS_COINBASE_ERR_HEIGHT_RANGE if n_height does
 *           not fit in 24 bits (the BIP34 3-byte serialisation that
 *           legacy mining uses; equihash mainnet has not reached 2^24).
 */
struct zcl_result domain_consensus_coinbase_script_sig_placeholder(
        int n_height,
        struct script *out);

/* Write the BIP34 height-push + extra-nonce push scriptSig form into
 * `out`. Byte-identical to legacy `increment_extra_nonce`:
 *
 *     [ 0x03, h[0], h[1], h[2],
 *       en_len, en[0], ..., en[en_len-1] ]
 *
 * where `en_len` is the minimal little-endian byte length of
 * `extra_nonce` (between 1 and 4 — a zero nonce still serialises as
 * one zero byte to match legacy semantics) and the bytes are
 * little-endian. Pure.
 *
 * Same error codes as the placeholder variant.
 */
struct zcl_result domain_consensus_coinbase_script_sig_with_extra_nonce(
        int n_height,
        uint32_t extra_nonce,
        struct script *out);

/* Inputs for `domain_consensus_coinbase_build`. Grouping the scalars
 * keeps the call site readable. */
struct domain_consensus_coinbase_inputs {
    int                            n_height;       /* >=0 and < 2^24 */
    int64_t                        subsidy;        /* satoshis, >= 0 */
    int64_t                        total_fees;     /* satoshis, >= 0 */
    const struct script           *miner_script;   /* coinbase vout[0] script */
    const struct consensus_params *params;
};

/* Build the canonical coinbase transaction into `out_tx`. The caller
 * MUST have already populated `out_tx` with exactly one vin and one
 * vout (e.g. via `transaction_alloc(out_tx, 1, 1)`); this function
 * does NOT allocate. The vin/vout pointers must be non-NULL.
 *
 * On success returns ZCL_OK and fills:
 *   - out_tx->vin[0].prevout         = null outpoint
 *   - out_tx->vin[0].script_sig      = placeholder shape (height + OP_0)
 *   - out_tx->vin[0].sequence        = left untouched (caller default)
 *   - out_tx->vout[0].script_pub_key = *in.miner_script
 *   - out_tx->vout[0].value          = in.subsidy + in.total_fees
 *   - out_tx->version, version_group_id, overwintered per epoch
 *   - out_tx->expiry_height          = 0
 *   - out_tx->hash                   = recomputed
 *
 * Pure: depends only on the inputs. No clock, RNG, or I/O.
 *
 * Errors:
 *   DOMAIN_CONSENSUS_COINBASE_ERR_NULL_OUT       out_tx == NULL
 *   DOMAIN_CONSENSUS_COINBASE_ERR_NULL_PARAMS    in.params == NULL
 *   DOMAIN_CONSENSUS_COINBASE_ERR_NULL_SCRIPT    in.miner_script == NULL
 *   DOMAIN_CONSENSUS_COINBASE_ERR_NEG_HEIGHT     in.n_height < 0
 *   DOMAIN_CONSENSUS_COINBASE_ERR_HEIGHT_RANGE   in.n_height >= 2^24
 *   DOMAIN_CONSENSUS_COINBASE_ERR_NEG_FEES       in.total_fees < 0
 *   DOMAIN_CONSENSUS_COINBASE_ERR_NEG_SUBSIDY    in.subsidy < 0
 *   DOMAIN_CONSENSUS_COINBASE_ERR_NOT_PREALLOC   out_tx->num_vin != 1
 *                                                or num_vout != 1, or
 *                                                vin/vout == NULL
 */
struct zcl_result domain_consensus_coinbase_build(
        const struct domain_consensus_coinbase_inputs *in,
        struct transaction *out_tx);

/* Error codes used by domain/consensus/coinbase.{c,h}. Stable across
 * builds; new codes are appended. Returned via zcl_result.code. */
enum domain_consensus_coinbase_err {
    DOMAIN_CONSENSUS_COINBASE_ERR_NULL_OUT      = 1701,
    DOMAIN_CONSENSUS_COINBASE_ERR_NULL_PARAMS   = 1702,
    DOMAIN_CONSENSUS_COINBASE_ERR_NULL_SCRIPT   = 1703,
    DOMAIN_CONSENSUS_COINBASE_ERR_NEG_HEIGHT    = 1704,
    DOMAIN_CONSENSUS_COINBASE_ERR_HEIGHT_RANGE  = 1705,
    DOMAIN_CONSENSUS_COINBASE_ERR_NEG_FEES      = 1706,
    DOMAIN_CONSENSUS_COINBASE_ERR_NEG_SUBSIDY   = 1707,
    DOMAIN_CONSENSUS_COINBASE_ERR_NOT_PREALLOC  = 1708,
};

#endif /* ZCL_DOMAIN_CONSENSUS_COINBASE_H */
