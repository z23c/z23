/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * simnet_contract — HTLC / escrow contract overlay over the deterministic
 * simnet.
 *
 * Builds P2SH-wrapped Hash Time-Locked Contracts (core/modules/script/htlc.c) and
 * drives them through the RAM-only simnet: fund the contract in a minted
 * block, redeem it with the secret preimage, or refund it after the absolute
 * CLTV height passes. All timelocks are ABSOLUTE block heights (no OP_CSV),
 * matching the sovereign-service roadmap §7.
 *
 * WHAT IS ENFORCED IN-SIM vs SKIPPED — read before asserting anything:
 *
 *   simnet mints at checkpoint-covered heights, so connect_block runs with
 *   expensive_checks=false (see sim/simnet.h). That means the per-input
 *   SCRIPT is NOT executed during a mint — the OP_SHA256/OP_EQUALVERIFY
 *   preimage guard and the OP_CHECKLOCKTIMEVERIFY refund guard are both
 *   bypassed at connect time. What IS still enforced through the real
 *   consensus code:
 *     - structural block/tx checks in connect_block (value in >= value out,
 *       no duplicate/missing inputs, coinbase maturity, MoneyRange);
 *     - the tx-level nLockTime finality rule at mempool admission, via
 *       domain_consensus_tx_is_final() (simnet_mempool.c). A refund tx sets
 *       nLockTime=locktime + a non-final sequence, so it is REJECTED with
 *       SIMNET_MEMPOOL_REJECT_NONFINAL until the tip reaches the locktime.
 *       This is the real predicate that makes an early refund fail; it is a
 *       transaction-admission rule, distinct from the script-level CLTV op.
 *
 *   Because the preimage guard is a SCRIPT op (skipped in-sim), a
 *   wrong-preimage redeem would be silently ACCEPTED by an in-sim mint. To
 *   verify the preimage guard for real we run the production script
 *   interpreter directly via simnet_contract_check_redeem_script() — never a
 *   faked in-sim rejection.
 */

#ifndef ZCL_SIM_SIMNET_CONTRACT_H
#define ZCL_SIM_SIMNET_CONTRACT_H

#include "script/htlc.h"
#include "script/script.h"
#include "sim/simnet.h"
#include "sim/simnet_wallet.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct transaction;
struct uint256;

/* A fully-materialized HTLC: the secret, both parties' pubkeys + derived
 * pubkey-hashes, the redeem script (contract) and the P2SH scriptPubKey that
 * funds it. recipient_pkh/refunder_pkh are HASH160 of the respective pubkeys,
 * so a redeem/refund scriptSig carrying those pubkeys satisfies the script's
 * OP_HASH160 guard — this makes simnet_contract_check_redeem_script isolate
 * the preimage equality as the ONLY variable under test. */
struct simnet_contract_htlc {
    uint8_t  secret[32];
    uint8_t  secret_hash[32];
    uint8_t  recipient_pubkey[33];
    uint8_t  refunder_pubkey[33];
    uint8_t  recipient_pkh[20];
    uint8_t  refunder_pkh[20];
    uint32_t locktime;                    /* absolute CLTV refund height   */
    uint8_t  contract[HTLC_CONTRACT_SIZE]; /* redeem script                */
    size_t   contract_len;
    struct script p2sh;                   /* scriptPubKey funding the HTLC */
};

/* Materialize an HTLC from a caller-provided 32-byte secret and both parties'
 * 33-byte compressed pubkeys (all deterministic from the seed tape in tests).
 * Computes secret_hash=SHA256(secret), the two pubkey-hashes, the 97-byte
 * redeem script and its P2SH scriptPubKey. Returns false (and logs) on a bad
 * argument or if the script builder produces the wrong size. */
bool simnet_contract_htlc_init(struct simnet_contract_htlc *c,
                               const uint8_t secret[32],
                               const uint8_t recipient_pubkey[33],
                               const uint8_t refunder_pubkey[33],
                               uint32_t locktime);

/* (a) Fund the HTLC: enqueue a payment of `value` from `funder` to the
 * contract's P2SH output and mint it into the next simnet block. The funded
 * coin lands at `out->txid`:0. `funder` must already hold >= value + fee.
 * Returns false (and logs) if the send is rejected or the mint fails. */
bool simnet_contract_fund(struct simnet *s, struct simnet_wallet *funder,
                          const struct simnet_contract_htlc *c, int64_t value,
                          struct simnet_tx_result *out);

/* (b) Build a redeem-path spend of `fund_txid`:0 (worth `fund_value`) paying
 * `pay_to`, carrying `preimage` in the scriptSig. Sets nLockTime=0 and
 * sequence=0 (final). Fee is the simnet default rate. The caller owns `tx`
 * and must transaction_free() it. Enqueue via simnet_mempool_add() and mint.
 * Passing a wrong `preimage` still builds a structurally valid tx (the
 * preimage guard is a script op, skipped in-sim — see the header note); use
 * simnet_contract_check_redeem_script() to verify the guard for real. */
bool simnet_contract_build_redeem(struct transaction *tx,
                                  const struct uint256 *fund_txid,
                                  int64_t fund_value,
                                  const struct simnet_contract_htlc *c,
                                  const uint8_t preimage[32],
                                  const struct script *pay_to,
                                  struct simnet_tx_result *out);

/* (c) Build a refund-path spend of `fund_txid`:0 paying `pay_to`. Sets
 * nLockTime=c->locktime and sequence=0xFFFFFFFE, so the tx is non-final (and
 * rejected by mempool admission) until the tip reaches c->locktime. The
 * caller owns `tx` and must transaction_free() it. */
bool simnet_contract_build_refund(struct transaction *tx,
                                  const struct uint256 *fund_txid,
                                  int64_t fund_value,
                                  const struct simnet_contract_htlc *c,
                                  const struct script *pay_to,
                                  struct simnet_tx_result *out);

/* Run the PRODUCTION script interpreter (verify_script with
 * SCRIPT_VERIFY_P2SH) over the redeem path using `preimage`, with a
 * signature-accepting checker so the ONLY variable is the preimage equality.
 * Returns true iff the redeem script accepts. `out_script_err` (may be NULL)
 * receives the ScriptError as an int — a wrong preimage yields
 * SCRIPT_ERR_EQUALVERIFY. This is the real, verified reason a wrong-preimage
 * redeem is invalid; in-sim connect_block (expensive_checks=false) would not
 * surface it. */
bool simnet_contract_check_redeem_script(const struct simnet_contract_htlc *c,
                                         const uint8_t preimage[32],
                                         int *out_script_err);

#ifdef __cplusplus
}
#endif

#endif /* ZCL_SIM_SIMNET_CONTRACT_H */
