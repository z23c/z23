/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Property receipts — the R in PRINCIPAL → PROPERTY → RIGHTS → ACTION →
 * RECEIPT. A receipt is the only durable evidence that an action was
 * authorized and performed, so it has three properties and this file is where
 * all three are made true:
 *
 *   CANONICAL   One action serializes to exactly one byte string. Every field
 *               is fixed-width big-endian or a fixed-length NUL-padded buffer,
 *               so there is no length-prefix ambiguity, no locale, no float,
 *               and no room for two encodings of the same fact. The digest of
 *               those bytes is `body_hash`.
 *
 *   HASH-CHAINED  `chain_hash = SHA3-256(prev_chain_hash || body_hash)`, where
 *               prev_chain_hash is the previous receipt's chain_hash in THIS
 *               grant's chain (all-zero for seq 1). Editing, deleting, or
 *               reordering any receipt breaks every later link, and the break
 *               is localized: verification names the first bad sequence number.
 *
 *   SIGNED      Ed25519 over `chain_hash` (crypto/ed25519.h — the project's own
 *               C23 implementation; no external dependency). The signer's
 *               public key travels in the receipt so a receipt is
 *               self-describing, but VERIFICATION MUST PIN THE KEY: a forger
 *               who rewrites a receipt can also re-sign it with a key of their
 *               own, so metaverse_receipt_verify takes the expected signer
 *               pubkey as an argument and a mismatch is a named failure.
 *               Trusting the embedded key would make the signature decorative.
 *
 * IDEMPOTENCY is not enforced here — it cannot be, because it is a property of
 * a STORE ("has this key already been committed?"). `idempotency_key` is
 * carried in the canonical body so that a replayed commit which returns the
 * stored receipt is provably returning the receipt for the same request; the
 * store-side rule lives in services/property_grant_service.h.
 *
 * Pure: no clock, no filesystem, no allocation. */

#ifndef ZCL_METAVERSE_PROPERTY_RECEIPT_H
#define ZCL_METAVERSE_PROPERTY_RECEIPT_H

#include "metaverse/property_grant.h"
#include "metaverse/property_id.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define METAVERSE_HASH_LEN 32
#define METAVERSE_SIG_LEN 64
#define METAVERSE_PUBKEY_LEN 32

/* Caller-chosen, at most 64 chars. Empty means "no idempotency key", and the
 * service then treats the commit as non-replayable rather than silently
 * collapsing distinct commits onto one empty key. */
#define METAVERSE_IDEMPOTENCY_KEY_MAX 64

/* Canonical body is a fixed-size record; this is its exact length, asserted at
 * compile time in the .c so a field added without updating it cannot compile.
 * 8 (domain tag) + 8 (seq) + 33 + 129 + 129 + 65 (ids, NUL-padded) + 4 (kind)
 * + 32 (root) + 4 (action) + 5*8 (values/revision/height/time/spent)
 * + 32 (prev_chain_hash) = 484. */
#define METAVERSE_RECEIPT_BODY_LEN 484

struct metaverse_receipt {
    uint64_t seq;                                   /* 1-based, per grant */
    char grant_id[METAVERSE_GRANT_ID_LEN + 1];
    char actor[METAVERSE_PRINCIPAL_MAX + 1];
    char counterparty[METAVERSE_PRINCIPAL_MAX + 1];
    char idempotency_key[METAVERSE_IDEMPOTENCY_KEY_MAX + 1];

    struct metaverse_property_id property;
    enum metaverse_action action;

    int64_t value_zat;
    /* The property revision this action was committed AGAINST. A receipt that
     * names a revision the catalog has since moved past is still valid
     * evidence — it says what was true when it was signed. */
    int64_t property_revision;
    int64_t height;
    int64_t unix_time;

    /* Grant state AFTER this action, so an auditor can replay the budget from
     * the chain alone without the grant record. */
    int64_t grant_spent_after_zat;

    uint8_t prev_chain_hash[METAVERSE_HASH_LEN];
    uint8_t body_hash[METAVERSE_HASH_LEN];
    uint8_t chain_hash[METAVERSE_HASH_LEN];
    uint8_t signer_pubkey[METAVERSE_PUBKEY_LEN];
    uint8_t signature[METAVERSE_SIG_LEN];
};

/* Named verification outcomes. Tests assert these tokens exactly. */
enum metaverse_receipt_status {
    METAVERSE_RECEIPT_OK = 0,
    METAVERSE_RECEIPT_BAD_ARGS,
    METAVERSE_RECEIPT_BODY_HASH_MISMATCH,   /* a field was edited */
    METAVERSE_RECEIPT_CHAIN_BROKEN,         /* prev_chain_hash does not link */
    METAVERSE_RECEIPT_CHAIN_HASH_MISMATCH,  /* chain_hash not derived correctly */
    METAVERSE_RECEIPT_SEQ_OUT_OF_ORDER,
    METAVERSE_RECEIPT_SIGNER_UNEXPECTED,    /* re-signed with a foreign key */
    METAVERSE_RECEIPT_SIGNATURE_INVALID,
    METAVERSE_RECEIPT_STATUS_COUNT
};

const char *metaverse_receipt_status_token(enum metaverse_receipt_status s);

/* Serialize the canonical body of `r` into `out` (needs
 * METAVERSE_RECEIPT_BODY_LEN bytes). Covers every semantic field and the
 * prev_chain_hash; it does NOT cover body_hash, chain_hash, or the signature,
 * which are derived from it. Deterministic for a given receipt. */
bool metaverse_receipt_body_bytes(const struct metaverse_receipt *r,
                                 uint8_t *out, size_t out_cap);

/* Fill body_hash / chain_hash / signer_pubkey / signature.
 *
 * `prev_chain_hash` is the previous receipt's chain_hash, or NULL for the first
 * receipt in a grant's chain (treated as 32 zero bytes). `r->seq` must already
 * be set. `sk`/`pk` are an ed25519 keypair from ed25519_keypair(). */
bool metaverse_receipt_seal(struct metaverse_receipt *r,
                           const uint8_t *prev_chain_hash,
                           const uint8_t sk[METAVERSE_PUBKEY_LEN],
                           const uint8_t pk[METAVERSE_PUBKEY_LEN]);

/* Verify ONE receipt: recompute the body hash, recompute the chain hash from
 * the receipt's own prev_chain_hash, pin the signer, and check the signature.
 * `expected_signer` is mandatory — see the header note on why the embedded key
 * cannot be trusted. */
enum metaverse_receipt_status metaverse_receipt_verify(
    const struct metaverse_receipt *r,
    const uint8_t expected_signer[METAVERSE_PUBKEY_LEN]);

/* Verify a whole chain, in ascending seq order. Additionally requires that
 * seq is 1,2,3,… with no gaps and that each receipt's prev_chain_hash equals
 * the previous receipt's chain_hash (all-zero for the first). On failure,
 * *out_bad_index (when non-NULL) receives the 0-based index of the first
 * receipt that failed — a tamper report has to say WHERE. */
enum metaverse_receipt_status metaverse_receipt_chain_verify(
    const struct metaverse_receipt *chain, size_t count,
    const uint8_t expected_signer[METAVERSE_PUBKEY_LEN],
    size_t *out_bad_index);

/* Lowercase hex of a 32-byte hash into `out` (needs 65 bytes). */
bool metaverse_hash_hex(const uint8_t h[METAVERSE_HASH_LEN],
                       char *out, size_t out_cap);

#endif /* ZCL_METAVERSE_PROPERTY_RECEIPT_H */
