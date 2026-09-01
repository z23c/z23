/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: the 2-message atomic ZSLP-token/ZCL yardsale swap ceremony —
 * zswap_accept.v1 (buyer→seller) and zswap_partial.v1 (seller→buyer).
 *
 * Both nodes are online together. The seller's signed ad (zswap_quote.v1)
 * names the exact trade; the ceremony exchanges ONLY the accept data and
 * one signature, because both nodes deterministically assemble the same
 * unsigned transaction (zswap/zswap_assembly.h) and SIGHASH_ALL makes a
 * half-signed copy worthless to anyone else.
 *
 *   msg1 buyer→seller zswap_accept.v1: quote_root + the buyer's accept data
 *        (his ZCL inputs, token receive address, change address, the exact
 *        fee he pays, deadline). NO signatures yet — the buyer signs last.
 *   msg2 seller→buyer zswap_partial.v1: quote_root + assembly_root + the
 *        seller's accept data (his single token input, ZCL receive address,
 *        change address, deadline) + his pubkey and SIGHASH_ALL signature
 *        for the token input.
 *
 * Seller side: assemble, verify the transaction pays him exactly the ad
 * terms (zswap_ceremony_seller_verify_assembly), sign ONLY his token input,
 * respond. Buyer side: re-derive the assembly_root, re-assemble, verify
 * every term against the signed ad byte-for-byte, verify the seller's
 * signature over the full-transaction sighash and its binding to the token
 * input's script, insert it, sign his own inputs, broadcast (broadcast is
 * a later slice — this module is transport-agnostic wire + handler logic).
 *
 * Safety: either party walking away before both signatures exist means no
 * transaction and no loss. A seller double-spending his advertised input
 * mid-ceremony surfaces as the buyer's mempool rejection — again no loss.
 * deadline_unix in both messages equals the ad's expires_unix: a stale
 * ceremony dies with the ad.
 *
 * Wire style mirrors zswap_quote.v1: fixed magic, schema version, exact
 * sizes (trailing bytes rejected), outputs zeroed on any decode error.
 * The accept-data byte layouts ARE the canonical serializations from
 * zswap_assembly (sorted input lists — decode refuses an unsorted wire),
 * so assembly_root verification needs no second format.
 */

#ifndef ZCL_ZSWAP_ZSWAP_CEREMONY_H
#define ZCL_ZSWAP_ZSWAP_CEREMONY_H

#include "keys/key.h"
#include "zswap/zswap_assembly.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define ZSWAP_ACCEPT_VERSION 1u
#define ZSWAP_PARTIAL_VERSION 1u

/* P2P message commands (max 12 bytes), the ceremony companions of
 * ZSWAP_MSG_QUOTE (zswap/zswap_yardsale.h). One zswapaccept message carries
 * exactly one zswap_accept.v1 wire; one zswappartial message carries exactly
 * one zswap_partial.v1 wire. Both ride the same gossip idiom as the ads:
 * dedup-on-content bounds loops, and settlement stays bilateral — an
 * intermediary only ever relays bytes it cannot read into or alter
 * profitably (SIGHASH_ALL binds every signature to the whole transaction). */
#define ZSWAP_MSG_ACCEPT "zswapaccept"
#define ZSWAP_MSG_PARTIAL "zswappartial"

/* The ingress verdict a ceremony-wire handler returns through its injected
 * port (the int-carry convention mirrors enum zswap_yardsale_ingest over the
 * zswapquote port seam): DROP consumes or refuses the wire, RELAY forwards
 * it once to the remaining peers, RESPOND floods out_wire back — used by the
 * seller to answer an accept with his partial. */
enum zswap_ceremony_wire_result {
    ZSWAP_CEREMONY_WIRE_DROP = 0,
    ZSWAP_CEREMONY_WIRE_RELAY,
    ZSWAP_CEREMONY_WIRE_RESPOND,
};

/* Upper bounds for buffer sizing; exact sizes are computed per message by
 * zswap_accept_wire_size / zswap_partial_wire_size. */
#define ZSWAP_ACCEPT_WIRE_MAX_BYTES 2955u
#define ZSWAP_PARTIAL_WIRE_MAX_BYTES 490u

/* The seller's signature rides the wire as DER || sighash byte, exactly as
 * it will appear in the scriptSig push. v1 accepts SIGHASH_ALL only. */
#define ZSWAP_SIG_FIELD_BYTES 73u
#define ZSWAP_SIG_MIN_BYTES 9u

struct zswap_accept_v1 {
    uint16_t schema_version;
    uint8_t quote_root[32];
    struct zswap_buyer_accept buyer;
};

struct zswap_partial_v1 {
    uint16_t schema_version;
    uint8_t quote_root[32];
    uint8_t assembly_root[32];
    struct zswap_seller_accept seller;
    uint8_t seller_pubkey[33]; /* compressed secp256k1 */
    uint8_t sig_len;           /* DER + 1 sighash byte */
    uint8_t signature[ZSWAP_SIG_FIELD_BYTES]; /* zero-padded */
};

enum zswap_ceremony_error {
    ZSWAP_CEREMONY_OK = 0,
    ZSWAP_CEREMONY_ERR_NULL,
    ZSWAP_CEREMONY_ERR_VERSION,
    ZSWAP_CEREMONY_ERR_WIRE_SIZE,
    ZSWAP_CEREMONY_ERR_WIRE_MAGIC,
    ZSWAP_CEREMONY_ERR_ROOT_ZERO,
    ZSWAP_CEREMONY_ERR_ACCEPT,       /* accept data fails validation */
    ZSWAP_CEREMONY_ERR_INPUT_ORDER,  /* wire inputs not in canonical order */
    ZSWAP_CEREMONY_ERR_PUBKEY,       /* malformed seller pubkey field */
    ZSWAP_CEREMONY_ERR_SIG_FIELD,    /* sig_len out of range / bad padding */
    ZSWAP_CEREMONY_ERR_SIGHASH_TYPE, /* trailing sig byte != SIGHASH_ALL */
    ZSWAP_CEREMONY_ERR_AD,           /* ad invalid (structural / too early) */
    ZSWAP_CEREMONY_ERR_EXPIRED,      /* ceremony or ad past its deadline */
    ZSWAP_CEREMONY_ERR_QUOTE_ROOT,   /* wire root does not match the ad */
    ZSWAP_CEREMONY_ERR_DEADLINE,     /* deadline != ad.expires_unix */
    ZSWAP_CEREMONY_ERR_ASSEMBLY_ROOT,/* recomputed root != partial's root */
    ZSWAP_CEREMONY_ERR_ASSEMBLY,     /* the assembler refused this tuple */
    ZSWAP_CEREMONY_ERR_TERMS,        /* tx does not pay the exact ad terms */
    ZSWAP_CEREMONY_ERR_SCRIPT_TYPE,  /* an input script is not P2PKH */
    ZSWAP_CEREMONY_ERR_KEY_MISMATCH, /* key/pubkey does not own the input */
    ZSWAP_CEREMONY_ERR_SIGNATURE,    /* ECDSA verification failed */
    ZSWAP_CEREMONY_ERR_SIGN,         /* signing failed */
    ZSWAP_CEREMONY_ERR_INPUT_INDEX,  /* input index out of range */
};

const char *zswap_ceremony_error_string(enum zswap_ceremony_error error);

/* ── msg1 zswap_accept.v1 ──────────────────────────────────────────── */

enum zswap_ceremony_error zswap_accept_validate(
    const struct zswap_accept_v1 *accept);

/* Exact wire size for this message (inputs are serialized in canonical
 * sorted order; encode sorts a copy). */
size_t zswap_accept_wire_size(const struct zswap_accept_v1 *accept);

enum zswap_ceremony_error zswap_accept_encode(
    const struct zswap_accept_v1 *accept,
    uint8_t *out, size_t out_cap, size_t *out_len);

/* Strict decode: exact parse (trailing bytes rejected), wrong magic /
 * version / unsorted input list / non-canonical address padding all named
 * errors. On any error *out is zeroed. */
enum zswap_ceremony_error zswap_accept_decode(
    const uint8_t *wire, size_t wire_len, struct zswap_accept_v1 *out);

/* ── msg2 zswap_partial.v1 ─────────────────────────────────────────── */

enum zswap_ceremony_error zswap_partial_validate(
    const struct zswap_partial_v1 *partial);

size_t zswap_partial_wire_size(const struct zswap_partial_v1 *partial);

enum zswap_ceremony_error zswap_partial_encode(
    const struct zswap_partial_v1 *partial,
    uint8_t *out, size_t out_cap, size_t *out_len);

enum zswap_ceremony_error zswap_partial_decode(
    const uint8_t *wire, size_t wire_len, struct zswap_partial_v1 *out);

/* ── state-machine helpers ─────────────────────────────────────────── */

/* SELLER side, term check: the assembled transaction must pay the exact ad
 * terms — vout[0] the SLP SEND for token_amount of the ad's token, vout[1]
 * the dust to the buyer's token address, vout[2] EXACTLY zcl_amount to the
 * seller's own receive address, change outputs exactly the input arithmetic
 * of the accept data, the inputs exactly the agreed outpoints, the envelope
 * exactly the canonical Sapling-v4 shape. The ad must be usable at now_unix
 * and both deadlines must equal ad.expires_unix. Any shortchange — a
 * mutated amount, a swapped seller address, a skimmed change output — is
 * ZSWAP_CEREMONY_ERR_TERMS. */
enum zswap_ceremony_error zswap_ceremony_seller_verify_assembly(
    const struct zswap_quote_v1 *ad,
    const struct zswap_buyer_accept *buyer,
    const struct zswap_seller_accept *seller,
    const struct zswap_assembly *assembly,
    int64_t now_unix);

/* Sign one input of the swap transaction with a raw P2PKH key
 * (SIGHASH_ALL, deterministic RFC6979 nonce via privkey_sign). The prevout
 * script must be TX_PUBKEYHASH and the key must own it — a key that does
 * not match the script's key hash is ERR_KEY_MISMATCH, never a worthless
 * signature. The scriptSig is inserted in place. branch_id must be the
 * consensus branch at broadcast height, identical for both signers. */
enum zswap_ceremony_error zswap_ceremony_sign_input_p2pkh(
    struct transaction *tx, size_t input_index,
    const uint8_t *script_pub_key, size_t script_len,
    int64_t value_sats, uint32_t branch_id,
    const struct privkey *key);

/* SELLER side, full msg2 builder: verify the ad is live at now_unix and the
 * accept names this ad's root, assemble the swap, verify it pays the exact
 * ad terms (a node never signs a transaction that shortchanges itself),
 * sign the token input, and fill *partial (quote_root, assembly_root,
 * terms, pubkey, signature). out_assembly, when non-NULL, receives a copy
 * of the unsigned assembly for local inspection. On any error both outputs
 * are zeroed. */
enum zswap_ceremony_error zswap_ceremony_seller_build_partial(
    const struct zswap_quote_v1 *ad,
    const struct zswap_accept_v1 *accept,
    const struct zswap_seller_accept *seller_terms,
    const struct privkey *seller_key,
    uint32_t branch_id,
    int64_t now_unix,
    struct zswap_partial_v1 *partial,
    struct zswap_assembly *out_assembly);

/* BUYER side, full msg2 handler: the ad must be live at now_unix (a stale
 * ceremony dies with the ad), both wires must name the ad's quote_root, the
 * recomputed assembly_root must match the partial's, the assembler must
 * accept the tuple, the assembly must pay the exact ad terms, and the
 * seller's signature must verify over the full-transaction SIGHASH_ALL
 * sighash of input 0 under a pubkey bound to the token input's script
 * (low-S, SIGHASH_ALL trailing byte). On success *tx_out receives the
 * assembled transaction with ONLY the seller's signature inserted — the
 * buyer then signs his own inputs (zswap_ceremony_sign_input_p2pkh) and
 * checks zswap_ceremony_all_inputs_signed before broadcast. On ANY error
 * *tx_out is left zeroed: an aborted ceremony leaves zero state. */
enum zswap_ceremony_error zswap_ceremony_buyer_verify_partial(
    const struct zswap_quote_v1 *ad,
    const struct zswap_accept_v1 *accept,
    const struct zswap_partial_v1 *partial,
    uint32_t branch_id,
    int64_t now_unix,
    struct transaction *tx_out);

/* True when every input carries a non-empty scriptSig — the completeness
 * gate the buyer checks before broadcast. */
bool zswap_ceremony_all_inputs_signed(const struct transaction *tx);

#endif /* ZCL_ZSWAP_ZSWAP_CEREMONY_H */
