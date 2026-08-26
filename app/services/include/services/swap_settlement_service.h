/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Swap settlement service — build + sign the transaction that spends an
 * HTLC P2SH funding output.
 *
 * Two settlement paths, both spending the single funding UTXO the operator
 * paid into the contract's P2SH address:
 *
 *   redeem  — the claim branch (OP_IF): prove knowledge of the 32-byte
 *             secret preimage + sign with the recipient key. lock_time = 0,
 *             sequence = 0xFFFFFFFF.
 *   refund  — the timeout branch (OP_ELSE): sign with the refunder key after
 *             the CLTV locktime. lock_time = locktime, sequence = 0xFFFFFFFE
 *             (non-final so OP_CHECKLOCKTIMEVERIFY is enforced).
 *
 * The signature covers the FULL 97-byte HTLC contract as the scriptCode
 * (BIP16 P2SH redeem-script sighash) at amount = funding_value, under the
 * Sapling sighash for the given consensus branch id. The resulting scriptSig
 * is the dcrdex-compatible push sequence built by htlc_build_*_scriptsig.
 *
 * These functions are PURE with respect to node state: they take the key
 * material + funding facts by value and hand back a fully-formed
 * `struct transaction`. Broadcast, coins lookup, and keystore resolution are
 * the controller's job. This keeps the settlement crypto hermetically
 * testable against verify_script without a live chain. */

#ifndef ZCL_SERVICES_SWAP_SETTLEMENT_SERVICE_H
#define ZCL_SERVICES_SWAP_SETTLEMENT_SERVICE_H

#include "primitives/transaction.h"
#include "script/script.h"
#include "util/result.h"
#include <stdint.h>

struct privkey;
struct pubkey;

/* Inputs shared by both settlement paths. `contract` is the 97-byte HTLC
 * redeem script; `dest_spk` is the scriptPubKey the settled value is paid to
 * (typically P2PKH to the settling key). `funding_value` is the value of the
 * P2SH output being spent; `fee` is deducted from it. */
struct swap_settle_ctx {
    const uint8_t  *contract;
    size_t          contract_len;
    struct outpoint funding;
    int64_t         funding_value;
    int64_t         fee;
    struct script   dest_spk;
    uint32_t        branch_id;
    uint32_t        expiry_height;
};

/* Build + sign the redeem (claim-with-secret) transaction. Signs input 0
 * with `key`/`pub` over the contract scriptCode and embeds `secret`.
 * `out_tx` is initialized by the callee; the caller owns it and must
 * transaction_free() it. Returns a non-ok result on any failure (bad
 * money range, sign failure, scriptSig overflow).
 *
 * POST-CONDITION, both builders: out_tx is transaction_init()ed on EVERY
 * return, including every failure, whenever out_tx itself is non-NULL. So
 * transaction_free(out_tx) is always safe and never walks the caller's prior
 * stack contents. Do not add a failure return above that init — a caller's
 * `struct transaction tx;` is uninitialized garbage until this call touches
 * it, and freeing garbage is a wild walk through transaction_free(). This is
 * the class that made compact_block_reconstruct() remotely exploitable
 * (bce343876): a fresh stack reads as zero, so it only fires once the frame
 * has been dirtied by earlier work. */
struct zcl_result swap_settlement_build_redeem(const struct swap_settle_ctx *c,
                                               const struct privkey *key,
                                               const struct pubkey *pub,
                                               const uint8_t secret[32],
                                               struct transaction *out_tx);

/* Build + sign the refund (reclaim-after-locktime) transaction. Sets
 * lock_time = `locktime` and a non-final sequence so CLTV is enforced. The
 * caller is responsible for checking that the chain height has reached
 * `locktime` before broadcasting; this function refuses locktime == 0 but
 * does not know the current height. */
struct zcl_result swap_settlement_build_refund(const struct swap_settle_ctx *c,
                                               const struct privkey *key,
                                               const struct pubkey *pub,
                                               uint32_t locktime,
                                               struct transaction *out_tx);

#endif /* ZCL_SERVICES_SWAP_SETTLEMENT_SERVICE_H */
