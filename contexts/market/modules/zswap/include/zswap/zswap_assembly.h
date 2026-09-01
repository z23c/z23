/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: the deterministic two-party assembler for the atomic
 * ZSLP-token/ZCL yardsale swap.
 *
 * A seller's signed ad (zswap_quote.v1, see zswap/zswap_quote.h) names the
 * exact trade: token_amount base units of token_id for zcl_amount sats.
 * Because the token and the ZCL settle on the SAME chain there is no HTLC:
 * ONE transaction spends both parties' inputs, and SIGHASH_ALL makes a
 * half-signed copy worthless to anyone but its other signer. Both nodes
 * independently assemble the BYTE-IDENTICAL unsigned transaction from
 * (ad, buyer accept, seller accept) so that only signatures cross the wire.
 *
 * Canonical form (pinned here, identical on both nodes):
 *   Inputs:  the seller's token inputs first (sorted by outpoint: txid bytes
 *            ascending in node-internal order, then vout ascending), then the
 *            buyer's ZCL inputs under the same ordering. v1: the seller
 *            contributes EXACTLY ONE token input holding exactly token_amount
 *            (no partial fills, no token change — a token input holding more
 *            would burn the remainder under the SLP validity overlay, so the
 *            seller-side caller must pre-check the coin with
 *            slp_classify_tx_output before accepting).
 *   Outputs, fixed role order:
 *     [0] OP_RETURN ZSLP SEND declaring exactly one quantity = token_amount
 *         of token_id (slp_build_send, lokad conventions — the same shape
 *         zslp_command_build_token_send_tx composes).
 *     [1] ZSWAP_TOKEN_DUST_ZAT (546) to the buyer's token receive address —
 *         this is the output the SEND pays token_amount to.
 *     [2] zcl_amount sats to the seller's ZCL receive address.
 *     [3] seller change = seller_token_input.value - 546, only when > 0.
 *     [4] buyer change = sum(buyer inputs) - zcl_amount - fee_sats, only
 *         when > 0. The buyer pays the network fee out of his change; the
 *         exact fee is an explicit accept field, never negotiated.
 *   Envelope: Overwintered Sapling v4 (version 4, SAPLING_VERSION_GROUP_ID),
 *   lock_time 0, expiry_height 0 (no tx expiry — the ceremony's deadline
 *   lives in the ad), value_balance 0, every input sequence UINT32_MAX.
 *
 * The assembler is a pure function of its arguments: no I/O, no wallet, no
 * chain-state lookups. The only ambient dependency is address decoding,
 * which reads the process-wide chain params (chain_params_get) exactly like
 * the repo's canonical validators (engine/models/src/shared_validators.c).
 *
 * assembly_root = SHA3-256(ZSWAP_ASSEMBLY_DOMAIN || NUL || quote_root ||
 * canonical(buyer_accept) || canonical(seller_accept)) commits the whole
 * accept tuple against a specific signed ad: two nodes that agree on the
 * root have assembled — or will assemble — the same transaction from the
 * same data. The canonical accept serializations (exposed below) are the
 * exact byte layouts the zswap_ceremony wires reuse, and they sort the
 * input lists by outpoint so the root is input-order independent.
 */

#ifndef ZCL_ZSWAP_ZSWAP_ASSEMBLY_H
#define ZCL_ZSWAP_ZSWAP_ASSEMBLY_H

#include "primitives/transaction.h"
#include "zswap/zswap_quote.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define ZSWAP_ASSEMBLY_VERSION 1u
#define ZSWAP_ASSEMBLY_DOMAIN "zcl.zswap.assembly.v1"

/* v1 bounds. Standard prevout scripts only: P2PKH is 25 bytes, P2SH 23; the
 * cap leaves headroom without admitting arbitrary scripts onto ceremony
 * wires. A swap funds at most 16 buyer ZCL inputs. */
#define ZSWAP_MAX_INPUT_SCRIPT_BYTES 128u
#define ZSWAP_MAX_BUYER_INPUTS 16u

/* The dust output carrying the SLP SEND quantity to the buyer — mirrors the
 * ZSLP_DUST_ZAT convention in engine/services/src/zslp_command_service.c. */
#define ZSWAP_TOKEN_DUST_ZAT 546LL

/* Base58Check address strings ride the ceremony wires in fixed 64-byte
 * fields: the NUL-terminated text plus zero padding. ZCL transparent
 * addresses are 35 chars; 63 is generous headroom. */
#define ZSWAP_ADDRESS_FIELD_BYTES 64u
#define ZSWAP_ADDRESS_MAX_CHARS (ZSWAP_ADDRESS_FIELD_BYTES - 1u)

/* One party's contribution to the swap: a specific prevout being spent.
 * txid is node-internal byte order (the same convention as
 * transaction.hash, zslp token ids, and node.db). script_pub_key is the
 * prevout's raw scriptPubKey (needed for change math, sighash, and seller
 * signature verification). */
struct zswap_swap_input {
    uint8_t txid[32];
    uint32_t vout;
    int64_t value_sats; /* > 0 */
    uint16_t script_len; /* 1..ZSWAP_MAX_INPUT_SCRIPT_BYTES */
    uint8_t script_pub_key[ZSWAP_MAX_INPUT_SCRIPT_BYTES];
};

/* The buyer's accept data (zswap_accept.v1 payload): his ZCL inputs, where
 * the token dust goes, where his change goes, and the exact fee he pays.
 * deadline_unix must equal the ad's expires_unix so a stale ceremony dies
 * with the ad. */
struct zswap_buyer_accept {
    struct zswap_swap_input inputs[ZSWAP_MAX_BUYER_INPUTS];
    size_t num_inputs; /* 1..ZSWAP_MAX_BUYER_INPUTS */
    char token_recv_address[ZSWAP_ADDRESS_FIELD_BYTES];
    char change_address[ZSWAP_ADDRESS_FIELD_BYTES];
    uint64_t fee_sats; /* > 0 */
    int64_t deadline_unix; /* > 0, == ad.expires_unix */
};

/* The seller's accept data (zswap_partial.v1 terms): his single token
 * input, where the zcl_amount payment goes, and where his change goes. */
struct zswap_seller_accept {
    struct zswap_swap_input token_input; /* value >= ZSWAP_TOKEN_DUST_ZAT */
    char zcl_recv_address[ZSWAP_ADDRESS_FIELD_BYTES];
    char change_address[ZSWAP_ADDRESS_FIELD_BYTES];
    int64_t deadline_unix; /* > 0, == ad.expires_unix */
};

/* The assembled swap: the canonical unsigned transaction plus the role map
 * (which input index is the seller's, which vout plays which role; -1 for
 * an omitted optional change output). */
struct zswap_assembly {
    struct transaction tx;
    size_t seller_input_count; /* v1: always 1; seller inputs lead vin[] */
    size_t buyer_input_count;
    int vout_slp_opreturn;   /* always 0 */
    int vout_token_dust;     /* always 1 */
    int vout_seller_payment; /* always 2 */
    int vout_seller_change;  /* 3, or -1 when the token input is exact dust */
    int vout_buyer_change;   /* 3 or 4, or -1 when the buyer is exact */
    int64_t fee_sats;
};

enum zswap_assembly_error {
    ZSWAP_ASSEMBLY_OK = 0,
    ZSWAP_ASSEMBLY_ERR_NULL,
    ZSWAP_ASSEMBLY_ERR_AD,              /* ad fails zswap_quote_validate */
    ZSWAP_ASSEMBLY_ERR_DEADLINE,        /* deadline unset or != ad.expires */
    ZSWAP_ASSEMBLY_ERR_BUYER_INPUT_COUNT, /* 0 or > ZSWAP_MAX_BUYER_INPUTS */
    ZSWAP_ASSEMBLY_ERR_INPUT_VALUE,     /* a prevout value_sats <= 0 */
    ZSWAP_ASSEMBLY_ERR_INPUT_SCRIPT,    /* script_len 0 or over the cap */
    ZSWAP_ASSEMBLY_ERR_INPUT_ORDER,     /* duplicate outpoint (intra/cross) */
    ZSWAP_ASSEMBLY_ERR_SELLER_DUST,     /* token input < ZSWAP_TOKEN_DUST_ZAT */
    ZSWAP_ASSEMBLY_ERR_ADDRESS,         /* an address fails decode_destination */
    ZSWAP_ASSEMBLY_ERR_FEE,             /* fee_sats == 0 */
    ZSWAP_ASSEMBLY_ERR_INSUFFICIENT,    /* buyer inputs < zcl_amount + fee */
    ZSWAP_ASSEMBLY_ERR_OVERFLOW,        /* value math leaves int64 range */
    ZSWAP_ASSEMBLY_ERR_SLP_SCRIPT,      /* slp_build_send refused */
    ZSWAP_ASSEMBLY_ERR_ALLOC,           /* transaction allocation failed */
};

const char *zswap_assembly_error_string(enum zswap_assembly_error error);

/* Structural validation of accept data: sizes, counts, nonzero fields,
 * NUL-terminated-and-zero-padded address strings of plausible length. Does
 * NOT decode the addresses (zswap_assemble does) and does not compare the
 * deadline against an ad (no ad in scope). */
enum zswap_assembly_error zswap_buyer_accept_validate(
    const struct zswap_buyer_accept *buyer);
enum zswap_assembly_error zswap_seller_accept_validate(
    const struct zswap_seller_accept *seller);

/* Canonical serialization of accept data. Input lists are emitted SORTED by
 * outpoint (txid bytes asc, then vout asc), so the bytes are independent of
 * the order the caller collected them in. *out_len receives the exact size.
 * NULL pointers return ERR_NULL; a short buffer returns ERR_OVERFLOW and
 * nothing is written. */
enum zswap_assembly_error zswap_buyer_accept_serialize(
    const struct zswap_buyer_accept *buyer,
    uint8_t *out, size_t out_cap, size_t *out_len);
enum zswap_assembly_error zswap_seller_accept_serialize(
    const struct zswap_seller_accept *seller,
    uint8_t *out, size_t out_cap, size_t *out_len);

/* Exact canonical sizes for given input counts (validation bounds the
 * script lengths, so these are computable up front). */
size_t zswap_buyer_accept_serialized_size(const struct zswap_buyer_accept *b);
size_t zswap_seller_accept_serialized_size(const struct zswap_seller_accept *s);

/* assembly_root: SHA3-256 over the domain-separated accept tuple, binding
 * both parties' accept data to one signed ad's quote_root. */
enum zswap_assembly_error zswap_assembly_root(
    const uint8_t quote_root[32],
    const struct zswap_buyer_accept *buyer,
    const struct zswap_seller_accept *seller,
    uint8_t out[32]);

/* Assemble the canonical unsigned swap transaction. Validates the ad
 * structurally (zswap_quote_validate), both accepts, deadline equality with
 * the ad, address decodability under the current chain params, the v1 input
 * shape, and the money math; refuses anything else with a named error. On
 * any error *out is left zeroed (no partial transaction to leak into a
 * broadcast path). */
enum zswap_assembly_error zswap_assemble(
    const struct zswap_quote_v1 *ad,
    const struct zswap_buyer_accept *buyer,
    const struct zswap_seller_accept *seller,
    struct zswap_assembly *out);

/* Release the assembled transaction (transaction_free + zero). */
void zswap_assembly_free(struct zswap_assembly *assembly);

/* Serialize a (partially) signed swap transaction into out; *out_len
 * receives the exact byte count. Returns false when out_cap is too small or
 * serialization fails. */
bool zswap_assembly_tx_serialize(const struct transaction *tx,
                                 uint8_t *out, size_t out_cap,
                                 size_t *out_len);

/* The SIGHASH_ALL sighash for one input of the assembled transaction, via
 * the repo's consensus sighash (precompute_tx_data + signature_hash).
 * branch_id is caller-supplied and must be the consensus branch id at the
 * broadcast height (consensus_current_epoch_branch_id) — both parties sign
 * under the same branch or the signatures will not verify. */
bool zswap_assembly_input_sighash(const struct transaction *tx,
                                  size_t input_index,
                                  const uint8_t *script_pub_key,
                                  size_t script_len,
                                  int64_t value_sats,
                                  uint32_t branch_id,
                                  uint8_t out[32]);

#endif /* ZCL_ZSWAP_ZSWAP_ASSEMBLY_H */
