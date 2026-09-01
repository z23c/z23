/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Property receipts — canonical serialization, the hash chain, and the
 * Ed25519 seal. Pure: no clock, no filesystem, no allocation. */

#include "metaverse/property_receipt.h"

#include "base/hex.h"
#include "base/log_macros.h"
#include "base/serialize_le.h"
#include "crypto/ed25519.h"
#include "crypto/sha3.h"

#include <string.h>

#define RECEIPT_LOG "metaverse.receipt"

/* Domain separation: these bytes prefix every receipt body, so a receipt
 * digest can never collide with any other SHA3-256 commitment in the node. */
static const uint8_t k_receipt_domain[8] = {
    'Z', 'C', 'L', 'R', 'C', 'P', 'T', '1'
};

static const char *const k_status_tokens[METAVERSE_RECEIPT_STATUS_COUNT] = {
    "OK",
    "RECEIPT_BAD_ARGS",
    "RECEIPT_BODY_HASH_MISMATCH",
    "RECEIPT_CHAIN_BROKEN",
    "RECEIPT_CHAIN_HASH_MISMATCH",
    "RECEIPT_SEQ_OUT_OF_ORDER",
    "RECEIPT_SIGNER_UNEXPECTED",
    "RECEIPT_SIGNATURE_INVALID",
};

const char *metaverse_receipt_status_token(enum metaverse_receipt_status s)
{
    if (s < 0 || s >= METAVERSE_RECEIPT_STATUS_COUNT) return "UNKNOWN_STATUS";
    return k_status_tokens[s];
}

/* ── Canonical body ─────────────────────────────────────────────────────── */

/* Every writer below advances `*off`; the static assert on the total is what
 * makes a forgotten field a compile error rather than a silent hash change. */
static void put_bytes(uint8_t *out, size_t *off, const void *src, size_t n)
{
    memcpy(out + *off, src, n);
    *off += n;
}

/* Fixed-width NUL-padded string field: the padding is part of the commitment,
 * so "ab" and "ab\0junk" cannot both hash to the same body. */
static void put_str(uint8_t *out, size_t *off, const char *s, size_t width)
{
    memset(out + *off, 0, width);
    if (s) {
        size_t n = strnlen(s, width);
        memcpy(out + *off, s, n);
    }
    *off += width;
}

/* Network byte order through the one byte-order codec (base/serialize_le.h),
 * so the receipt body cannot drift from every other big-endian record in the
 * tree — a hand-rolled shift ladder here would be a second definition of the
 * same encoding. */
static void put_u32be(uint8_t *out, size_t *off, uint32_t v)
{
    zcl_write_u32_be(out + *off, v);
    *off += 4;
}

static void put_u64be(uint8_t *out, size_t *off, uint64_t v)
{
    zcl_write_u64_be(out + *off, v);
    *off += 8;
}

/* Two's-complement, big-endian. Negative values are representable so a
 * malformed receipt still serializes deterministically rather than aborting
 * inside a hash function. */
static void put_i64be(uint8_t *out, size_t *off, int64_t v)
{
    put_u64be(out, off, (uint64_t)v);
}

#define RECEIPT_BODY_COMPUTED \
    (sizeof(k_receipt_domain) + 8u \
     + (size_t)(METAVERSE_GRANT_ID_LEN + 1) \
     + (size_t)(METAVERSE_PRINCIPAL_MAX + 1) * 2u \
     + (size_t)(METAVERSE_IDEMPOTENCY_KEY_MAX + 1) \
     + 4u + METAVERSE_ROOT_BYTES + 4u + 8u * 5u + METAVERSE_HASH_LEN)

_Static_assert(RECEIPT_BODY_COMPUTED == METAVERSE_RECEIPT_BODY_LEN,
               "METAVERSE_RECEIPT_BODY_LEN must equal the sum of the canonical "
               "field widths — a field was added or resized without updating it");

bool metaverse_receipt_body_bytes(const struct metaverse_receipt *r,
                                 uint8_t *out, size_t out_cap)
{
    if (!r || !out)
        LOG_FAIL(RECEIPT_LOG, "body bytes: NULL receipt or output");
    if (out_cap < METAVERSE_RECEIPT_BODY_LEN)
        LOG_FAIL(RECEIPT_LOG, "body bytes: buffer %zu < %d", out_cap,
                 METAVERSE_RECEIPT_BODY_LEN);

    size_t off = 0;
    put_bytes(out, &off, k_receipt_domain, sizeof(k_receipt_domain));
    put_u64be(out, &off, r->seq);
    put_str(out, &off, r->grant_id, METAVERSE_GRANT_ID_LEN + 1);
    put_str(out, &off, r->actor, METAVERSE_PRINCIPAL_MAX + 1);
    put_str(out, &off, r->counterparty, METAVERSE_PRINCIPAL_MAX + 1);
    put_str(out, &off, r->idempotency_key, METAVERSE_IDEMPOTENCY_KEY_MAX + 1);
    put_u32be(out, &off, (uint32_t)r->property.kind);
    put_bytes(out, &off, r->property.root, METAVERSE_ROOT_BYTES);
    /* The action's stable BIT, which is what enum metaverse_action now holds
     * and what a grant persists. There is no second numbering to translate
     * from, so a receipt and the grant that authorized it name the action
     * with the same 32-bit value. */
    put_u32be(out, &off, (uint32_t)r->action);
    put_i64be(out, &off, r->value_zat);
    put_i64be(out, &off, r->property_revision);
    put_i64be(out, &off, r->height);
    put_i64be(out, &off, r->unix_time);
    put_i64be(out, &off, r->grant_spent_after_zat);
    put_bytes(out, &off, r->prev_chain_hash, METAVERSE_HASH_LEN);

    if (off != METAVERSE_RECEIPT_BODY_LEN)
        LOG_FAIL(RECEIPT_LOG, "body bytes: wrote %zu, expected %d", off,
                 METAVERSE_RECEIPT_BODY_LEN);
    return true;
}

static void chain_hash_of(const uint8_t prev[METAVERSE_HASH_LEN],
                          const uint8_t body[METAVERSE_HASH_LEN],
                          uint8_t out[METAVERSE_HASH_LEN])
{
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    sha3_256_write(&ctx, prev, METAVERSE_HASH_LEN);
    sha3_256_write(&ctx, body, METAVERSE_HASH_LEN);
    sha3_256_finalize(&ctx, out);
}

bool metaverse_receipt_seal(struct metaverse_receipt *r,
                           const uint8_t *prev_chain_hash,
                           const uint8_t sk[METAVERSE_PUBKEY_LEN],
                           const uint8_t pk[METAVERSE_PUBKEY_LEN])
{
    if (!r || !sk || !pk)
        LOG_FAIL(RECEIPT_LOG, "seal: NULL receipt or key material");
    if (r->seq == 0)
        LOG_FAIL(RECEIPT_LOG, "seal: seq must be 1-based, got 0");

    if (prev_chain_hash)
        memcpy(r->prev_chain_hash, prev_chain_hash, METAVERSE_HASH_LEN);
    else
        memset(r->prev_chain_hash, 0, METAVERSE_HASH_LEN);

    uint8_t body[METAVERSE_RECEIPT_BODY_LEN];
    if (!metaverse_receipt_body_bytes(r, body, sizeof(body)))
        LOG_FAIL(RECEIPT_LOG, "seal: canonical body serialization failed");

    sha3_256(body, sizeof(body), r->body_hash);
    chain_hash_of(r->prev_chain_hash, r->body_hash, r->chain_hash);
    memcpy(r->signer_pubkey, pk, METAVERSE_PUBKEY_LEN);
    ed25519_sign(r->signature, r->chain_hash, METAVERSE_HASH_LEN, sk, pk);
    return true;
}

enum metaverse_receipt_status metaverse_receipt_verify(
    const struct metaverse_receipt *r,
    const uint8_t expected_signer[METAVERSE_PUBKEY_LEN])
{
    if (!r || !expected_signer) return METAVERSE_RECEIPT_BAD_ARGS;
    if (r->seq == 0) return METAVERSE_RECEIPT_SEQ_OUT_OF_ORDER;

    uint8_t body[METAVERSE_RECEIPT_BODY_LEN];
    if (!metaverse_receipt_body_bytes(r, body, sizeof(body)))
        return METAVERSE_RECEIPT_BAD_ARGS;

    uint8_t body_hash[METAVERSE_HASH_LEN];
    sha3_256(body, sizeof(body), body_hash);
    if (memcmp(body_hash, r->body_hash, METAVERSE_HASH_LEN) != 0)
        return METAVERSE_RECEIPT_BODY_HASH_MISMATCH;

    uint8_t chain_hash[METAVERSE_HASH_LEN];
    chain_hash_of(r->prev_chain_hash, r->body_hash, chain_hash);
    if (memcmp(chain_hash, r->chain_hash, METAVERSE_HASH_LEN) != 0)
        return METAVERSE_RECEIPT_CHAIN_HASH_MISMATCH;

    /* Pin the key. A forger can re-sign a rewritten receipt with their own
     * key; only comparing against the expected signer catches that. */
    if (memcmp(r->signer_pubkey, expected_signer, METAVERSE_PUBKEY_LEN) != 0)
        return METAVERSE_RECEIPT_SIGNER_UNEXPECTED;

    if (!ed25519_verify(r->signature, r->chain_hash, METAVERSE_HASH_LEN,
                        r->signer_pubkey))
        return METAVERSE_RECEIPT_SIGNATURE_INVALID;

    return METAVERSE_RECEIPT_OK;
}

enum metaverse_receipt_status metaverse_receipt_chain_verify(
    const struct metaverse_receipt *chain, size_t count,
    const uint8_t expected_signer[METAVERSE_PUBKEY_LEN],
    size_t *out_bad_index)
{
    if (out_bad_index) *out_bad_index = 0;
    if (!chain || !expected_signer) return METAVERSE_RECEIPT_BAD_ARGS;
    if (count == 0) return METAVERSE_RECEIPT_OK;  /* the empty chain verifies */

    uint8_t prev[METAVERSE_HASH_LEN];
    memset(prev, 0, sizeof(prev));

    for (size_t i = 0; i < count; i++) {
        const struct metaverse_receipt *r = &chain[i];
        if (r->seq != (uint64_t)(i + 1)) {
            if (out_bad_index) *out_bad_index = i;
            return METAVERSE_RECEIPT_SEQ_OUT_OF_ORDER;
        }
        if (memcmp(r->prev_chain_hash, prev, METAVERSE_HASH_LEN) != 0) {
            if (out_bad_index) *out_bad_index = i;
            return METAVERSE_RECEIPT_CHAIN_BROKEN;
        }
        enum metaverse_receipt_status s =
            metaverse_receipt_verify(r, expected_signer);
        if (s != METAVERSE_RECEIPT_OK) {
            if (out_bad_index) *out_bad_index = i;
            return s;
        }
        memcpy(prev, r->chain_hash, METAVERSE_HASH_LEN);
    }
    return METAVERSE_RECEIPT_OK;
}

bool metaverse_hash_hex(const uint8_t h[METAVERSE_HASH_LEN],
                       char *out, size_t out_cap)
{
    if (!h || !out || out_cap < (METAVERSE_HASH_LEN * 2 + 1))
        LOG_FAIL(RECEIPT_LOG, "hash hex: NULL arg or buffer too small");
    zcl_hex_encode(h, METAVERSE_HASH_LEN, out);
    return true;
}
