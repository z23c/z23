/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Canonical signed quote wire (zswap_quote.v1) for atomic
 * ZSLP-token/ZCL P2P swaps.
 *
 * A seller publishes a zswap_quote to advertise: "I will sell token_amount
 * base units of ZSLP token token_id for zcl_amount satoshis ZCL." The quote
 * is a self-authenticating gossip object: the seller's Ed25519 key signs the
 * canonical domain-separated body, so any peer can verify it standalone —
 * no chain state, no session, no trusted directory. It is not a second
 * identity system: signing reuses the same core/modules/crypto Ed25519 primitives
 * and SHA3-256 domain-separated root conventions as contexts/wallet/modules/zid and contexts/commons/modules/vcs.
 *
 * Wire layout (exact, fixed width, little-endian integers):
 *   body (146 bytes):
 *     magic                       8   {'Z','S','W','Q','T','E','\r','\n'}
 *     schema_version              2   == ZSWAP_QUOTE_VERSION
 *     network_genesis_root       32   chain the quote lives on
 *     seller_pubkey               32   seller Ed25519 public key (the signer)
 *     nonce                       8   != 0; uniqueness / replay hygiene
 *     token_id                   32   ZSLP token id (node-internal byte order,
 *                                     same convention as zslp/slp.h)
 *     token_amount                8   token base units for sale, > 0
 *     zcl_amount                  8   satoshis asked for the WHOLE
 *                                     token_amount, > 0
 *     issued_unix                 8   > 0
 *     expires_unix                8   > issued_unix, and at most
 *                                     ZSWAP_QUOTE_MAX_LIFETIME_SECS after it
 *   seller_signature             64   Ed25519 over body_root by seller_pubkey
 * Total wire: 210 bytes.
 *
 * body_root = SHA3-256("zcl.zswap.quote.v1" || NUL || body) is the exact
 * statement the seller signs. The quote's own root — the dedup key a
 * Stage-2 yardsale cache indexes by — commits the full wire including the
 * signature:
 *   root = SHA3-256("zcl.zswap.quote.root.v1" || NUL || wire).
 *
 * Semantics:
 *   A quote is usable only inside [issued_unix, expires_unix): early use is
 *   NOT_YET_VALID, use at or after expiry is EXPIRED. Lifetimes are capped
 *   at ZSWAP_QUOTE_MAX_LIFETIME_SECS structurally (a quote is a live
 *   for-sale sign with a short fuse — a seller that still wants to sell
 *   re-issues with a fresh nonce).
 *   Replay hygiene at the codec level is the nonce plus the root: two
 *   quotes that differ only in nonce have different roots, and a byte-
 *   identical re-gossip has the same root, so a yardsale cache dedups on root
 *   and never needs a heuristic. The codec deliberately does NOT keep a
 *   seen-set — that is the Stage-2 yardsale cache's job.
 */

#ifndef ZCL_ZSWAP_ZSWAP_QUOTE_H
#define ZCL_ZSWAP_ZSWAP_QUOTE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define ZSWAP_QUOTE_VERSION 1u
#define ZSWAP_QUOTE_DOMAIN "zcl.zswap.quote.v1"
#define ZSWAP_QUOTE_ROOT_DOMAIN "zcl.zswap.quote.root.v1"

#define ZSWAP_QUOTE_BODY_BYTES 146u
#define ZSWAP_QUOTE_WIRE_BYTES 210u

/* Maximum wall-clock lifetime of a quote: 60 seconds. Quotes are live P2P
 * advertisements; a longer-lived offer is re-issued, not extended. */
#define ZSWAP_QUOTE_MAX_LIFETIME_SECS 60LL

enum zswap_quote_error {
    ZSWAP_QUOTE_OK = 0,
    ZSWAP_QUOTE_ERR_NULL,
    ZSWAP_QUOTE_ERR_VERSION,
    ZSWAP_QUOTE_ERR_WIRE_SIZE,
    ZSWAP_QUOTE_ERR_WIRE_MAGIC,
    ZSWAP_QUOTE_ERR_ROOT_ZERO,
    ZSWAP_QUOTE_ERR_PUBKEY_ZERO,
    ZSWAP_QUOTE_ERR_TOKEN_ID_ZERO,
    ZSWAP_QUOTE_ERR_NONCE,
    ZSWAP_QUOTE_ERR_AMOUNT,
    ZSWAP_QUOTE_ERR_TIME_ORDER,
    ZSWAP_QUOTE_ERR_LIFETIME,
    ZSWAP_QUOTE_ERR_SIGNATURE,
    ZSWAP_QUOTE_ERR_KEY_MISMATCH,
    ZSWAP_QUOTE_ERR_NETWORK_MISMATCH,
    ZSWAP_QUOTE_ERR_EXPIRED,
    ZSWAP_QUOTE_ERR_NOT_YET_VALID,
};

const char *zswap_quote_error_string(enum zswap_quote_error error);

struct zswap_quote_v1 {
    uint16_t schema_version;
    uint8_t network_genesis_root[32];
    uint8_t seller_pubkey[32];
    uint64_t nonce;
    uint8_t token_id[32];
    uint64_t token_amount;
    uint64_t zcl_amount;
    int64_t issued_unix;
    int64_t expires_unix;
    uint8_t seller_signature[64];
};

/* Structural validation. validate() requires the signature to be non-zero;
 * validate_at() additionally rejects use before issued_unix (NOT_YET_VALID)
 * or at/after expires_unix (EXPIRED). Neither checks the signature
 * cryptographically — that is verify_at()'s job. */
enum zswap_quote_error zswap_quote_validate(
    const struct zswap_quote_v1 *quote);
enum zswap_quote_error zswap_quote_validate_at(
    const struct zswap_quote_v1 *quote, int64_t now_unix);

enum zswap_quote_error zswap_quote_encode(
    const struct zswap_quote_v1 *quote,
    uint8_t out[ZSWAP_QUOTE_WIRE_BYTES]);
/* Exact-size only: a short or trailing wire is WIRE_SIZE, a wrong leading
 * magic is WIRE_MAGIC, an unsupported schema_version is VERSION. On any
 * error *out is zeroed. */
enum zswap_quote_error zswap_quote_decode(
    const uint8_t *wire, size_t wire_len, struct zswap_quote_v1 *out);

/* The 32-byte statement the seller signs (body only). */
enum zswap_quote_error zswap_quote_body_root(
    const struct zswap_quote_v1 *quote, uint8_t out[32]);
/* The quote's own id: commits the full signed wire. A yardsale cache dedups
 * on this value. */
enum zswap_quote_error zswap_quote_root(
    const struct zswap_quote_v1 *quote, uint8_t out[32]);

/* Sign the body root with the seller key. The seller public key is re-derived
 * from seller_secret and must equal quote->seller_pubkey (KEY_MISMATCH
 * otherwise) — a secret that does not produce the claimed pubkey must never
 * seal, since the resulting signature would be unverifiable garbage. Ed25519
 * signing is deterministic (RFC 8032), so sealing is byte deterministic. */
enum zswap_quote_error zswap_quote_seal(
    struct zswap_quote_v1 *quote, const uint8_t seller_secret[32]);

/* Full verification: structural validity at now_unix, the expected network
 * genesis root is pinned, and the Ed25519 signature verifies over the body
 * root under the embedded seller_pubkey. The seller is self-authenticating —
 * any key may advertise; pinning WHICH seller is accepted is the caller's
 * policy, not the codec's. */
enum zswap_quote_error zswap_quote_verify_at(
    const struct zswap_quote_v1 *quote,
    const uint8_t expected_network_genesis[32], int64_t now_unix);

#endif /* ZCL_ZSWAP_ZSWAP_QUOTE_H */
