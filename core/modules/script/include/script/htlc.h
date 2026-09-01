/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * HTLC (Hash Time-Locked Contract) — Atomic swap infrastructure.
 *
 * P2SH-wrapped scripts using only existing consensus opcodes:
 *   OP_SHA256 + OP_EQUALVERIFY + OP_CHECKSIG (claim path)
 *   OP_CHECKLOCKTIMEVERIFY + OP_DROP + OP_CHECKSIG (refund path)
 *
 * Cross-chain compatible: ZCL, BTC, LTC, DOGE all support these opcodes. */

#ifndef ZCL_SCRIPT_HTLC_H
#define ZCL_SCRIPT_HTLC_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

/* Supported chains for atomic swaps */
enum swap_chain {
    SWAP_CHAIN_ZCL  = 0,
    SWAP_CHAIN_BTC  = 1,
    SWAP_CHAIN_LTC  = 2,
    SWAP_CHAIN_DOGE = 3,
};

/* Chain parameters for address encoding */
struct swap_chain_params {
    const char *name;
    const char *ticker;
    uint8_t p2pkh_prefix[2];    /* address version bytes */
    uint8_t p2sh_prefix[2];     /* P2SH address version bytes */
    uint8_t prefix_len;          /* 1 for BTC/LTC/DOGE, 2 for ZCL */
};

/* Get chain params by enum */
const struct swap_chain_params *swap_get_chain_params(enum swap_chain chain);

/* Parse chain name string to enum. Returns -1 on error. */
int swap_parse_chain(const char *name);

/* Swap contract states */
enum swap_state {
    SWAP_PENDING  = 0,
    SWAP_FUNDED   = 1,
    SWAP_REDEEMED = 2,
    SWAP_REFUNDED = 3,
    SWAP_EXPIRED  = 4,
};

/* Swap roles */
enum swap_role {
    SWAP_INITIATOR   = 0,
    SWAP_PARTICIPANT = 1,
};

/* HTLC contract parameters */
struct htlc_params {
    uint8_t  secret_hash[32];    /* SHA256 of the secret */
    uint8_t  recipient_pkh[20];  /* pubkey hash of the claimer */
    uint8_t  refunder_pkh[20];   /* pubkey hash of the refunder */
    uint32_t locktime;           /* absolute block height for refund */
};

/* ── HTLC Script Builder ────────────────────────────────────────── */

/* Build an HTLC redeem script.
 * Returns script length, or 0 on error.
 *
 * Script:
 *   OP_IF
 *     OP_SHA256 <secret_hash> OP_EQUALVERIFY
 *     OP_DUP OP_HASH160 <recipient_pkh> OP_EQUALVERIFY OP_CHECKSIG
 *   OP_ELSE
 *     <locktime> OP_CHECKLOCKTIMEVERIFY OP_DROP
 *     OP_DUP OP_HASH160 <refunder_pkh> OP_EQUALVERIFY OP_CHECKSIG
 *   OP_ENDIF */
size_t htlc_build_script(const struct htlc_params *params,
                         uint8_t *out, size_t out_len);

/* Compute P2SH address from redeem script for a given chain. */
bool htlc_p2sh_address(const uint8_t *redeem_script, size_t script_len,
                       enum swap_chain chain,
                       char *addr_out, size_t addr_len);

/* Generate a random 32-byte secret and compute its SHA256 hash. */
void htlc_generate_secret(uint8_t secret[32], uint8_t secret_hash[32]);

/* Extract the secret (preimage) from a claim transaction's scriptSig. */
bool htlc_extract_secret(const uint8_t *script_sig, size_t sig_len,
                         uint8_t secret_out[32]);

/* ── Swap State ─────────────────────────────────────────────────── */

/* ── Locktime Conventions (from dcrdex) ──────────────────────────── *
 * Initiator (maker): 20 hours = ~960 ZCL blocks (75s each)
 * Participant (taker): 8 hours = ~384 ZCL blocks
 * BTC/LTC: use Unix timestamps instead of block heights.
 * Initiator locktime must be > 2x participant locktime. */
#define SWAP_LOCKTIME_INITIATOR_BLOCKS   960   /* ~20 hours at 75s blocks */
#define SWAP_LOCKTIME_PARTICIPANT_BLOCKS 384   /* ~8 hours at 75s blocks */

/* ── Redeem/Refund ScriptSig Builders ───────────────────────────── *
 * Format from dcrdex RedeemP2SHContract / RefundP2SHContract:
 *   Redeem: <sig> <pubkey> <secret> OP_1 <redeemscript>
 *   Refund: <sig> <pubkey> OP_0 <redeemscript>
 *
 * The redeem tx must set nLockTime=0, nSequence=0.
 * The refund tx must set nLockTime=locktime, nSequence=0xFFFFFFFE. */

/* Build P2SH redeem scriptSig (claim with secret).
 * Returns bytes written to out, or 0 on error. */
size_t htlc_build_redeem_scriptsig(uint8_t *out, size_t out_len,
                                   const uint8_t *sig, size_t sig_len,
                                   const uint8_t *pubkey, size_t pubkey_len,
                                   const uint8_t secret[32],
                                   const uint8_t *contract, size_t contract_len);

/* Build P2SH refund scriptSig (reclaim after locktime).
 * Returns bytes written to out, or 0 on error. */
size_t htlc_build_refund_scriptsig(uint8_t *out, size_t out_len,
                                   const uint8_t *sig, size_t sig_len,
                                   const uint8_t *pubkey, size_t pubkey_len,
                                   const uint8_t *contract, size_t contract_len);

/* Extract 20-byte pubkey hash from a base58check address.
 * Handles both 1-byte prefix (BTC/LTC/DOGE) and 2-byte prefix (ZCL).
 * Returns true on success. */
bool htlc_address_to_pkh(const char *address, enum swap_chain chain,
                         uint8_t pkh_out[20]);

/* Contract size is always exactly 97 bytes (dcrdex SwapContractSize). */
#define HTLC_CONTRACT_SIZE 97

/* Compute swap_id from participants + secret_hash */
void swap_compute_id(const char *my_addr, const char *counter_addr,
                     const uint8_t secret_hash[32], char out[65]);

#endif
