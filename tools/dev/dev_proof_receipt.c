/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Canonical fixed-width signed local development acceptance
 *          receipts.
 *
 * v1 sealed a receipt with a keyless SHA3-256 digest, so admission trusted
 * whoever last wrote the cache file. v2 keeps that record byte for byte and
 * appends a fixed signer trailer: the producer's Ed25519 public key and its
 * signature over the whole sealed v1 body. The digest still says what the
 * proof covered; the signature now says who ran it. */

#include "dev_proof_receipt.h"

#include "dev_proof_signer.h"

#include "base/hex.h"
#include "base/serialize_le.h"
#include "sha3/sha3.h"

#include <stdio.h>
#include <string.h>

#define PROOF_MAGIC "Z23PRF1\0"
#define PROOF_MAGIC_BYTES 8u
#define PROOF_VERSION_UNSIGNED 1u
#define PROOF_VERSION 2u
#define PROOF_POLICY_VERSION ZCL_DEV_PROOF_POLICY_VERSION
#define PROOF_FIXED_ROOTS 10u
#define PROOF_DIMENSION_WIRE_BYTES 52u
#define PROOF_SEAL_OFFSET \
    (ZCL_DEV_PROOF_UNSIGNED_WIRE_BYTES - ZCL_DEV_PROOF_ROOT_BYTES)
/* What the Ed25519 signature covers: a domain string and the entire sealed
 * v1 body, whose last 32 bytes are the v1 digest. Signing the body rather
 * than the digest alone means a single flipped byte anywhere in the record —
 * including in the stored seal — is refused as signature_invalid instead of
 * as some downstream structural surprise. */
#define PROOF_SIGN_DOMAIN "zcl.dev_proof_receipt.v2"
#define PROOF_SIGN_DOMAIN_BYTES (sizeof(PROOF_SIGN_DOMAIN) - 1u)
#define PROOF_SIGN_MESSAGE_BYTES \
    (PROOF_SIGN_DOMAIN_BYTES + ZCL_DEV_PROOF_UNSIGNED_WIRE_BYTES)
/* The child receipt is untouched by v2: same magic, same version, same
 * bytes, so a proof that only re-seals its parent does not orphan the
 * children it already wrote. */
#define CHILD_MAGIC "Z23CHD1\0"
#define CHILD_VERSION 1u
#define CHILD_SEAL_OFFSET \
    (ZCL_DEV_PROOF_CHILD_WIRE_BYTES - ZCL_DEV_PROOF_ROOT_BYTES)
#define VERDICT_MAGIC "Z23VLF1\0"
#define VERDICT_VERSION 1u
#define VERDICT_SIGN_DOMAIN "zcl.dev_verdict_leaf.v1"
#define VERDICT_ROOT_DOMAIN "zcl.dev_verdict_leaf_root.v1"
#define VERDICT_SIGN_MESSAGE_BYTES \
    ((sizeof(VERDICT_SIGN_DOMAIN) - 1u) + \
     ZCL_DEV_VERDICT_LEAF_UNSIGNED_WIRE_BYTES)

static bool root_nonzero(const uint8_t root[ZCL_DEV_PROOF_ROOT_BYTES])
{
    uint8_t any = 0;
    for (size_t i = 0; i < ZCL_DEV_PROOF_ROOT_BYTES; i++) any |= root[i];
    return any != 0;
}

static bool dimension_complete(const struct zcl_dev_proof_dimension *dim)
{
    if (!dim || dim->failed != 0 || dim->skipped != 0 ||
        dim->ran > dim->selected || dim->reused > dim->selected ||
        dim->ran + dim->reused != dim->selected)
        return false;
    return dim->selected == 0 || root_nonzero(dim->receipt_root);
}

const char *zcl_dev_proof_dimension_name(enum zcl_dev_proof_dimension_id id)
{
    switch (id) {
    case ZCL_DEV_PROOF_GENERATED: return "generated";
    case ZCL_DEV_PROOF_COMPILE: return "compile";
    case ZCL_DEV_PROOF_LINT: return "lint";
    case ZCL_DEV_PROOF_TEST: return "test";
    }
    return "unknown";
}

bool zcl_dev_proof_oid_decode(const char *hex,
                              uint8_t out[ZCL_DEV_PROOF_OID_MAX],
                              uint8_t *out_len)
{
    size_t hex_len = hex ? strlen(hex) : 0;
    if (!out || !out_len || (hex_len != 40 && hex_len != 64) ||
        !zcl_hex_decode_lower(hex, out, hex_len / 2))
        return false;
    if (hex_len / 2 < ZCL_DEV_PROOF_OID_MAX)
        memset(out + hex_len / 2, 0, ZCL_DEV_PROOF_OID_MAX - hex_len / 2);
    *out_len = (uint8_t)(hex_len / 2);
    return true;
}

bool zcl_dev_proof_oid_encode(const uint8_t oid[ZCL_DEV_PROOF_OID_MAX],
                              uint8_t oid_len, char *out, size_t out_size)
{
    if (!oid || !out || (oid_len != 20 && oid_len != 32) ||
        out_size < (size_t)oid_len * 2u + 1u)
        return false;
    zcl_hex_encode(oid, oid_len, out);
    return true;
}

static void put_u32(uint8_t **cursor, uint32_t value)
{
    zcl_write_u32_le(*cursor, value);
    *cursor += 4;
}

static void put_u64(uint8_t **cursor, uint64_t value)
{
    zcl_write_u64_le(*cursor, value);
    *cursor += 8;
}

static uint32_t get_u32(const uint8_t **cursor)
{
    uint32_t value = zcl_read_u32_le(*cursor);
    *cursor += 4;
    return value;
}

static uint64_t get_u64(const uint8_t **cursor)
{
    uint64_t value = zcl_read_u64_le(*cursor);
    *cursor += 8;
    return value;
}

static void put_bytes(uint8_t **cursor, const void *bytes, size_t len)
{
    memcpy(*cursor, bytes, len);
    *cursor += len;
}

static void get_bytes(const uint8_t **cursor, void *bytes, size_t len)
{
    memcpy(bytes, *cursor, len);
    *cursor += len;
}

/* The v1 body, always stamped with the current version. Every digest, every
 * signature and the first 664 bytes of every stored record come from here,
 * so there is exactly one canonical encoding of a receipt. */
static bool serialize_body(const struct zcl_dev_acceptance_receipt_v1 *receipt,
                           uint8_t out[ZCL_DEV_PROOF_UNSIGNED_WIRE_BYTES])
{
    if (!receipt || !out)
        return false;
    uint8_t *p = out;
    put_bytes(&p, PROOF_MAGIC, PROOF_MAGIC_BYTES);
    put_u32(&p, PROOF_VERSION);
    *p++ = receipt->local_commit_len;
    *p++ = receipt->remote_base_len;
    *p++ = 0;
    *p++ = 0;
    put_bytes(&p, receipt->local_commit, ZCL_DEV_PROOF_OID_MAX);
    put_bytes(&p, receipt->remote_base, ZCL_DEV_PROOF_OID_MAX);
    const uint8_t *roots[PROOF_FIXED_ROOTS] = {
        receipt->source_root, receipt->source_cas_root,
        receipt->mutation_root, receipt->changed_set_root,
        receipt->impact_policy_root, receipt->compiler_root,
        receipt->flags_root, receipt->environment_root,
        receipt->build_graph_root, receipt->child_set_root,
    };
    for (size_t i = 0; i < PROOF_FIXED_ROOTS; i++)
        put_bytes(&p, roots[i], ZCL_DEV_PROOF_ROOT_BYTES);
    for (size_t i = 0; i < ZCL_DEV_PROOF_DIMENSIONS; i++) {
        const struct zcl_dev_proof_dimension *dim = &receipt->dimensions[i];
        put_bytes(&p, dim->receipt_root, ZCL_DEV_PROOF_ROOT_BYTES);
        put_u32(&p, dim->selected);
        put_u32(&p, dim->ran);
        put_u32(&p, dim->reused);
        put_u32(&p, dim->failed);
        put_u32(&p, dim->skipped);
    }
    put_u64(&p, receipt->created_unix);
    put_u64(&p, receipt->elapsed_ms);
    put_u32(&p, receipt->policy_version);
    put_u32(&p, receipt->complete);
    put_bytes(&p, receipt->seal, ZCL_DEV_PROOF_ROOT_BYTES);
    return (size_t)(p - out) == ZCL_DEV_PROOF_UNSIGNED_WIRE_BYTES;
}

bool zcl_dev_proof_receipt_serialize(
    const struct zcl_dev_acceptance_receipt_v1 *receipt,
    uint8_t out[ZCL_DEV_PROOF_WIRE_BYTES])
{
    if (!receipt || !out || !receipt->has_signature ||
        !serialize_body(receipt, out))
        return false;
    uint8_t *p = out + ZCL_DEV_PROOF_UNSIGNED_WIRE_BYTES;
    put_bytes(&p, receipt->signer_pubkey, ZCL_DEV_PROOF_PUBKEY_BYTES);
    put_bytes(&p, receipt->signature, ZCL_DEV_PROOF_SIGNATURE_BYTES);
    return (size_t)(p - out) == ZCL_DEV_PROOF_WIRE_BYTES;
}

bool zcl_dev_proof_receipt_parse(
    const uint8_t *wire, size_t wire_len,
    struct zcl_dev_acceptance_receipt_v1 *out)
{
    bool signed_record;
    if (wire_len == ZCL_DEV_PROOF_WIRE_BYTES)
        signed_record = true;
    else if (wire_len == ZCL_DEV_PROOF_UNSIGNED_WIRE_BYTES)
        signed_record = false;
    else
        return false;
    if (!wire || !out || memcmp(wire, PROOF_MAGIC, PROOF_MAGIC_BYTES) != 0)
        return false;
    const uint8_t *p = wire + PROOF_MAGIC_BYTES;
    if (get_u32(&p) !=
        (signed_record ? PROOF_VERSION : PROOF_VERSION_UNSIGNED))
        return false;
    memset(out, 0, sizeof(*out));
    out->local_commit_len = *p++;
    out->remote_base_len = *p++;
    if (*p++ != 0 || *p++ != 0 ||
        (out->local_commit_len != 20 && out->local_commit_len != 32) ||
        (out->remote_base_len != 20 && out->remote_base_len != 32))
        return false;
    get_bytes(&p, out->local_commit, ZCL_DEV_PROOF_OID_MAX);
    get_bytes(&p, out->remote_base, ZCL_DEV_PROOF_OID_MAX);
    uint8_t *roots[PROOF_FIXED_ROOTS] = {
        out->source_root, out->source_cas_root, out->mutation_root,
        out->changed_set_root, out->impact_policy_root, out->compiler_root,
        out->flags_root, out->environment_root, out->build_graph_root,
        out->child_set_root,
    };
    for (size_t i = 0; i < PROOF_FIXED_ROOTS; i++)
        get_bytes(&p, roots[i], ZCL_DEV_PROOF_ROOT_BYTES);
    for (size_t i = 0; i < ZCL_DEV_PROOF_DIMENSIONS; i++) {
        struct zcl_dev_proof_dimension *dim = &out->dimensions[i];
        get_bytes(&p, dim->receipt_root, ZCL_DEV_PROOF_ROOT_BYTES);
        dim->selected = get_u32(&p);
        dim->ran = get_u32(&p);
        dim->reused = get_u32(&p);
        dim->failed = get_u32(&p);
        dim->skipped = get_u32(&p);
    }
    out->created_unix = get_u64(&p);
    out->elapsed_ms = get_u64(&p);
    out->policy_version = get_u32(&p);
    out->complete = get_u32(&p);
    get_bytes(&p, out->seal, ZCL_DEV_PROOF_ROOT_BYTES);
    if (signed_record) {
        get_bytes(&p, out->signer_pubkey, ZCL_DEV_PROOF_PUBKEY_BYTES);
        get_bytes(&p, out->signature, ZCL_DEV_PROOF_SIGNATURE_BYTES);
        out->has_signature = true;
    }
    return (size_t)(p - wire) == wire_len;
}

static bool receipt_digest(const struct zcl_dev_acceptance_receipt_v1 *receipt,
                           uint8_t out[ZCL_DEV_PROOF_ROOT_BYTES])
{
    struct zcl_dev_acceptance_receipt_v1 copy;
    uint8_t wire[ZCL_DEV_PROOF_UNSIGNED_WIRE_BYTES];
    if (!receipt || !out)
        return false;
    copy = *receipt;
    memset(copy.seal, 0, sizeof(copy.seal));
    if (!serialize_body(&copy, wire))
        return false;
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    static const uint8_t domain[] = "zcl.dev_acceptance_receipt.v1";
    sha3_256_write(&sha, domain, sizeof(domain) - 1);
    sha3_256_write(&sha, wire, PROOF_SEAL_OFFSET);
    sha3_256_finalize(&sha, out);
    return true;
}

/* The exact bytes the signer signs and the verifier checks. */
static bool receipt_sign_message(
    const struct zcl_dev_acceptance_receipt_v1 *receipt,
    uint8_t out[PROOF_SIGN_MESSAGE_BYTES])
{
    if (!receipt || !out)
        return false;
    memcpy(out, PROOF_SIGN_DOMAIN, PROOF_SIGN_DOMAIN_BYTES);
    return serialize_body(receipt, out + PROOF_SIGN_DOMAIN_BYTES);
}

bool zcl_dev_proof_receipt_seal(struct zcl_dev_acceptance_receipt_v1 *receipt)
{
    uint8_t message[PROOF_SIGN_MESSAGE_BYTES];
    const char *why = NULL;
    if (!receipt)
        return false;
    /* Seal over a record that carries no signature yet, so the digest a
     * verifier recomputes never depends on the signature covering it. */
    receipt->has_signature = false;
    memset(receipt->signer_pubkey, 0, sizeof(receipt->signer_pubkey));
    memset(receipt->signature, 0, sizeof(receipt->signature));
    if (!receipt_digest(receipt, receipt->seal) ||
        !receipt_sign_message(receipt, message))
        return false;
    if (!zcl_dev_proof_signer_sign(message, sizeof(message),
                                   receipt->signer_pubkey,
                                   receipt->signature, &why)) {
        memset(receipt->signer_pubkey, 0, sizeof(receipt->signer_pubkey));
        memset(receipt->signature, 0, sizeof(receipt->signature));
        return false; /* no unsigned fallback: an unsealed receipt is a NO */
    }
    receipt->has_signature = true;
    return true;
}

bool zcl_dev_proof_receipt_child_set_root(
    const struct zcl_dev_acceptance_receipt_v1 *receipt,
    uint8_t out[ZCL_DEV_PROOF_ROOT_BYTES])
{
    if (!receipt || !out) return false;
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    static const uint8_t domain[] = "zcl.dev_proof_child_set.v1";
    sha3_256_write(&sha, domain, sizeof(domain));
    for (size_t i = 0; i < ZCL_DEV_PROOF_DIMENSIONS; i++) {
        const struct zcl_dev_proof_dimension *dim = &receipt->dimensions[i];
        uint8_t counts[20];
        zcl_write_u32_le(counts, dim->selected);
        zcl_write_u32_le(counts + 4, dim->ran);
        zcl_write_u32_le(counts + 8, dim->reused);
        zcl_write_u32_le(counts + 12, dim->failed);
        zcl_write_u32_le(counts + 16, dim->skipped);
        sha3_256_write(&sha, dim->receipt_root, sizeof(dim->receipt_root));
        sha3_256_write(&sha, counts, sizeof(counts));
    }
    sha3_256_finalize(&sha, out);
    return true;
}

static bool fail(char *why, size_t why_len, const char *message)
{
    if (why && why_len)
        (void)snprintf(why, why_len, "%s", message);
    return false;
}

bool zcl_dev_proof_receipt_validate(
    const struct zcl_dev_acceptance_receipt_v1 *receipt,
    const char *local_commit, const char *remote_base,
    char *why, size_t why_len)
{
    uint8_t local[ZCL_DEV_PROOF_OID_MAX], base[ZCL_DEV_PROOF_OID_MAX];
    uint8_t local_len = 0, base_len = 0, seal[ZCL_DEV_PROOF_ROOT_BYTES];
    if (!receipt || !zcl_dev_proof_oid_decode(local_commit, local, &local_len) ||
        !zcl_dev_proof_oid_decode(remote_base, base, &base_len))
        return fail(why, why_len, "receipt_identity_invalid");
    if (receipt->local_commit_len != local_len ||
        receipt->remote_base_len != base_len ||
        memcmp(receipt->local_commit, local, local_len) != 0 ||
        memcmp(receipt->remote_base, base, base_len) != 0)
        return fail(why, why_len, "receipt_commit_or_base_mismatch");
    /* Identity of the signer is decided before anything the record claims
     * about itself, so a forged or edited record is named as forged rather
     * than as whichever structural check its edit happened to trip. The one
     * check that runs first is the commit/base pair above: a correctly
     * signed receipt for a different push is a mismatch, not a forgery. */
    if (!receipt->has_signature)
        return fail(why, why_len, ZCL_DEV_PROOF_SIGNER_WHY_UNSIGNED);
    uint8_t message[PROOF_SIGN_MESSAGE_BYTES];
    const char *signer_why = NULL;
    if (!receipt_sign_message(receipt, message))
        return fail(why, why_len, "receipt_encoding_failed");
    if (!zcl_dev_proof_signer_verify(message, sizeof(message),
                                     receipt->signer_pubkey,
                                     receipt->signature, &signer_why))
        return fail(why, why_len,
                    signer_why ? signer_why
                               : ZCL_DEV_PROOF_SIGNER_WHY_SIGNATURE_INVALID);
    /* Named before completeness, and named for what it is: a receipt whose
     * roots were derived under a policy this build does not implement is
     * refused, never silently compared against roots that mean something
     * else. A receipt from a NEWER policy gets its own name -- calling it
     * old would be a lie, and re-running the proof is not the fix for it. */
    if (receipt->policy_version < PROOF_POLICY_VERSION)
        return fail(why, why_len, "receipt_schema_old");
    if (receipt->policy_version > PROOF_POLICY_VERSION)
        return fail(why, why_len, "receipt_schema_newer_than_this_build");
    if (receipt->complete != 1)
        return fail(why, why_len, "receipt_policy_incomplete");
    const uint8_t *roots[PROOF_FIXED_ROOTS] = {
        receipt->source_root, receipt->source_cas_root,
        receipt->mutation_root, receipt->changed_set_root,
        receipt->impact_policy_root, receipt->compiler_root,
        receipt->flags_root, receipt->environment_root,
        receipt->build_graph_root, receipt->child_set_root,
    };
    for (size_t i = 0; i < PROOF_FIXED_ROOTS; i++)
        if (!root_nonzero(roots[i]))
            return fail(why, why_len, "receipt_required_root_missing");
    for (size_t i = 0; i < ZCL_DEV_PROOF_DIMENSIONS; i++)
        if (!dimension_complete(&receipt->dimensions[i]))
            return fail(why, why_len, "receipt_dimension_incomplete");
    uint8_t child_set[ZCL_DEV_PROOF_ROOT_BYTES];
    if (!zcl_dev_proof_receipt_child_set_root(receipt, child_set) ||
        memcmp(child_set, receipt->child_set_root, sizeof(child_set)) != 0)
        return fail(why, why_len, "receipt_child_set_mismatch");
    if (!receipt_digest(receipt, seal) ||
        memcmp(seal, receipt->seal, sizeof(seal)) != 0)
        return fail(why, why_len, "receipt_seal_mismatch");
    if (why && why_len) why[0] = 0;
    return true;
}

bool zcl_dev_proof_child_receipt_create(
    enum zcl_dev_proof_dimension_id id,
    struct zcl_dev_proof_dimension *dimension,
    uint8_t out[ZCL_DEV_PROOF_CHILD_WIRE_BYTES])
{
    if (!dimension || !out || id < ZCL_DEV_PROOF_GENERATED ||
        id > ZCL_DEV_PROOF_TEST || dimension->selected == 0 ||
        !root_nonzero(dimension->receipt_root))
        return false;
    uint8_t *p = out;
    put_bytes(&p, CHILD_MAGIC, PROOF_MAGIC_BYTES);
    put_u32(&p, CHILD_VERSION);
    put_u32(&p, (uint32_t)id);
    put_bytes(&p, dimension->receipt_root, ZCL_DEV_PROOF_ROOT_BYTES);
    put_u32(&p, dimension->selected);
    put_u32(&p, dimension->ran);
    put_u32(&p, dimension->reused);
    put_u32(&p, dimension->failed);
    put_u32(&p, dimension->skipped);
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    static const uint8_t domain[] = "zcl.dev_proof_child_receipt.v1";
    sha3_256_write(&sha, domain, sizeof(domain) - 1);
    sha3_256_write(&sha, out, CHILD_SEAL_OFFSET);
    sha3_256_finalize(&sha, dimension->receipt_root);
    put_bytes(&p, dimension->receipt_root, ZCL_DEV_PROOF_ROOT_BYTES);
    return (size_t)(p - out) == ZCL_DEV_PROOF_CHILD_WIRE_BYTES;
}

bool zcl_dev_proof_child_receipt_validate(
    const uint8_t *wire, size_t wire_len,
    enum zcl_dev_proof_dimension_id id,
    const struct zcl_dev_proof_dimension *dimension)
{
    if (!wire || !dimension || wire_len != ZCL_DEV_PROOF_CHILD_WIRE_BYTES ||
        memcmp(wire, CHILD_MAGIC, PROOF_MAGIC_BYTES) != 0)
        return false;
    const uint8_t *p = wire + PROOF_MAGIC_BYTES;
    if (get_u32(&p) != CHILD_VERSION || get_u32(&p) != (uint32_t)id)
        return false;
    uint8_t evidence[ZCL_DEV_PROOF_ROOT_BYTES], seal[ZCL_DEV_PROOF_ROOT_BYTES];
    get_bytes(&p, evidence, sizeof(evidence));
    uint32_t selected = get_u32(&p), ran = get_u32(&p);
    uint32_t reused = get_u32(&p), failed = get_u32(&p);
    uint32_t skipped = get_u32(&p);
    get_bytes(&p, seal, sizeof(seal));
    if ((size_t)(p - wire) != wire_len || !root_nonzero(evidence) ||
        selected != dimension->selected || ran != dimension->ran ||
        reused != dimension->reused || failed != dimension->failed ||
        skipped != dimension->skipped ||
        memcmp(seal, dimension->receipt_root, sizeof(seal)) != 0)
        return false;
    struct sha3_256_ctx sha;
    uint8_t expected[ZCL_DEV_PROOF_ROOT_BYTES];
    sha3_256_init(&sha);
    static const uint8_t domain[] = "zcl.dev_proof_child_receipt.v1";
    sha3_256_write(&sha, domain, sizeof(domain) - 1);
    sha3_256_write(&sha, wire, CHILD_SEAL_OFFSET);
    sha3_256_finalize(&sha, expected);
    return memcmp(expected, seal, sizeof(seal)) == 0;
}

static bool verdict_fail(char *why, size_t why_len, const char *message)
{
    (void)fprintf(stderr, "dev-verdict-leaf: %s\n", message);
    if (why && why_len) (void)snprintf(why, why_len, "%s", message);
    return false;
}

static bool verdict_nonzero(const uint8_t *bytes, size_t len)
{
    uint8_t any = 0;
    for (size_t i = 0; i < len; i++) any |= bytes[i];
    return any != 0;
}

static bool verdict_group_char(unsigned char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9') || c == '.' || c == '_' ||
           c == '-' || c == '/';
}

static bool verdict_group_text(const char *group, size_t *len_out)
{
    if (!group) return false;
    size_t len = 0;
    while (len <= ZCL_DEV_VERDICT_LEAF_GROUP_MAX && group[len]) {
        if (!verdict_group_char((unsigned char)group[len])) return false;
        len++;
    }
    if (len == 0 || len > ZCL_DEV_VERDICT_LEAF_GROUP_MAX) return false;
    if (len_out) *len_out = len;
    return true;
}

static bool verdict_payload_valid(const struct zcl_dev_verdict_leaf_v1 *leaf)
{
    if (!leaf ||
        (leaf->verdict != ZCL_DEV_VERDICT_LEAF_PASS &&
         leaf->verdict != ZCL_DEV_VERDICT_LEAF_FAIL) ||
        leaf->group_len == 0 ||
        leaf->group_len > ZCL_DEV_VERDICT_LEAF_GROUP_MAX ||
        !verdict_nonzero(leaf->key, sizeof(leaf->key)) ||
        leaf->observed_unix == 0 || leaf->log_seq == 0)
        return false;
    for (size_t i = 0; i < leaf->group_len; i++)
        if (!verdict_group_char((unsigned char)leaf->group[i])) return false;
    for (size_t i = leaf->group_len; i < sizeof(leaf->group); i++)
        if (leaf->group[i] != 0) return false;
    bool have_prev = verdict_nonzero(leaf->prev_log_head,
                                     sizeof(leaf->prev_log_head));
    return (leaf->log_seq == 1 && !have_prev) ||
           (leaf->log_seq > 1 && have_prev);
}

static bool verdict_body(
    const struct zcl_dev_verdict_leaf_v1 *leaf,
    uint8_t out[ZCL_DEV_VERDICT_LEAF_UNSIGNED_WIRE_BYTES])
{
    if (!out || !verdict_payload_valid(leaf)) return false;
    uint8_t *p = out;
    put_bytes(&p, VERDICT_MAGIC, 8);
    put_u32(&p, VERDICT_VERSION);
    *p++ = (uint8_t)leaf->verdict;
    *p++ = leaf->group_len;
    *p++ = 0;
    *p++ = 0;
    put_bytes(&p, leaf->key, sizeof(leaf->key));
    put_bytes(&p, leaf->group, sizeof(leaf->group));
    put_u64(&p, leaf->observed_unix);
    put_u64(&p, leaf->elapsed_ms);
    put_u64(&p, leaf->log_seq);
    put_bytes(&p, leaf->prev_log_head, sizeof(leaf->prev_log_head));
    return (size_t)(p - out) == ZCL_DEV_VERDICT_LEAF_UNSIGNED_WIRE_BYTES;
}

static bool verdict_message(const struct zcl_dev_verdict_leaf_v1 *leaf,
                            uint8_t out[VERDICT_SIGN_MESSAGE_BYTES])
{
    memcpy(out, VERDICT_SIGN_DOMAIN, sizeof(VERDICT_SIGN_DOMAIN) - 1u);
    return verdict_body(leaf, out + sizeof(VERDICT_SIGN_DOMAIN) - 1u);
}

bool zcl_dev_verdict_leaf_sign(struct zcl_dev_verdict_leaf_v1 *leaf,
                               char *why, size_t why_len)
{
    uint8_t message[VERDICT_SIGN_MESSAGE_BYTES];
    const char *signer_why = NULL;
    if (!leaf)
        return verdict_fail(why, why_len, ZCL_DEV_VERDICT_WHY_ARGUMENTS);
    leaf->has_signature = false;
    memset(leaf->producer_pubkey, 0, sizeof(leaf->producer_pubkey));
    memset(leaf->signature, 0, sizeof(leaf->signature));
    if (!verdict_message(leaf, message))
        return verdict_fail(why, why_len, ZCL_DEV_VERDICT_WHY_ENCODING);
    if (!zcl_dev_proof_signer_sign(message, sizeof(message),
                                   leaf->producer_pubkey, leaf->signature,
                                   &signer_why))
        return verdict_fail(why, why_len, signer_why ? signer_why :
                            ZCL_DEV_VERDICT_WHY_UNSIGNED);
    leaf->has_signature = true;
    if (why && why_len) why[0] = 0;
    return true;
}

bool zcl_dev_verdict_leaf_serialize(
    const struct zcl_dev_verdict_leaf_v1 *leaf,
    uint8_t out[ZCL_DEV_VERDICT_LEAF_WIRE_BYTES],
    char *why, size_t why_len)
{
    if (!leaf || !out)
        return verdict_fail(why, why_len, ZCL_DEV_VERDICT_WHY_ARGUMENTS);
    if (!leaf->has_signature ||
        !verdict_nonzero(leaf->producer_pubkey,
                         sizeof(leaf->producer_pubkey)) ||
        !verdict_nonzero(leaf->signature, sizeof(leaf->signature)))
        return verdict_fail(why, why_len, ZCL_DEV_VERDICT_WHY_UNSIGNED);
    if (!verdict_body(leaf, out))
        return verdict_fail(why, why_len, ZCL_DEV_VERDICT_WHY_ENCODING);
    uint8_t *p = out + ZCL_DEV_VERDICT_LEAF_UNSIGNED_WIRE_BYTES;
    put_bytes(&p, leaf->producer_pubkey, sizeof(leaf->producer_pubkey));
    put_bytes(&p, leaf->signature, sizeof(leaf->signature));
    if (why && why_len) why[0] = 0;
    if ((size_t)(p - out) != ZCL_DEV_VERDICT_LEAF_WIRE_BYTES)
        return verdict_fail(why, why_len, ZCL_DEV_VERDICT_WHY_ENCODING);
    return true;
}

bool zcl_dev_verdict_leaf_parse(
    const uint8_t *wire, size_t wire_len,
    struct zcl_dev_verdict_leaf_v1 *out, char *why, size_t why_len)
{
    if (!out)
        return verdict_fail(why, why_len, ZCL_DEV_VERDICT_WHY_ARGUMENTS);
    memset(out, 0, sizeof(*out));
    if (!wire || wire_len != ZCL_DEV_VERDICT_LEAF_WIRE_BYTES)
        return verdict_fail(why, why_len, ZCL_DEV_VERDICT_WHY_FRAMING);
    if (memcmp(wire, VERDICT_MAGIC, 8) != 0 ||
        zcl_read_u32_le(wire + 8) != VERDICT_VERSION)
        return verdict_fail(why, why_len, ZCL_DEV_VERDICT_WHY_SCHEMA);
    if (wire[14] != 0 || wire[15] != 0)
        return verdict_fail(why, why_len, ZCL_DEV_VERDICT_WHY_ENCODING);

    struct zcl_dev_verdict_leaf_v1 parsed;
    memset(&parsed, 0, sizeof(parsed));
    parsed.verdict = (enum zcl_dev_verdict_leaf_verdict)wire[12];
    parsed.group_len = wire[13];
    memcpy(parsed.key, wire + 16, sizeof(parsed.key));
    memcpy(parsed.group, wire + 48, sizeof(parsed.group));
    parsed.observed_unix = zcl_read_u64_le(wire + 176);
    parsed.elapsed_ms = zcl_read_u64_le(wire + 184);
    parsed.log_seq = zcl_read_u64_le(wire + 192);
    memcpy(parsed.prev_log_head, wire + 200, sizeof(parsed.prev_log_head));
    memcpy(parsed.producer_pubkey, wire + 232,
           sizeof(parsed.producer_pubkey));
    memcpy(parsed.signature, wire + 264, sizeof(parsed.signature));
    parsed.has_signature = true;
    if (!verdict_payload_valid(&parsed))
        return verdict_fail(why, why_len, ZCL_DEV_VERDICT_WHY_ENCODING);
    *out = parsed;
    if (why && why_len) why[0] = 0;
    return true;
}

bool zcl_dev_verdict_leaf_verify(
    const struct zcl_dev_verdict_leaf_v1 *leaf,
    const uint8_t expected_key[ZCL_DEV_VERDICT_LEAF_KEY_BYTES],
    const char *expected_group, char *why, size_t why_len)
{
    uint8_t message[VERDICT_SIGN_MESSAGE_BYTES];
    const char *signer_why = NULL;
    size_t expected_len = 0;
    if (!leaf || !expected_key ||
        !verdict_group_text(expected_group, &expected_len))
        return verdict_fail(why, why_len, ZCL_DEV_VERDICT_WHY_ARGUMENTS);
    if (!verdict_payload_valid(leaf))
        return verdict_fail(why, why_len, ZCL_DEV_VERDICT_WHY_ENCODING);
    if (memcmp(leaf->key, expected_key, sizeof(leaf->key)) != 0)
        return verdict_fail(why, why_len, ZCL_DEV_VERDICT_WHY_KEY);
    if (leaf->group_len != expected_len ||
        memcmp(leaf->group, expected_group, expected_len) != 0)
        return verdict_fail(why, why_len, ZCL_DEV_VERDICT_WHY_GROUP);
    if (!leaf->has_signature ||
        !verdict_nonzero(leaf->producer_pubkey,
                         sizeof(leaf->producer_pubkey)) ||
        !verdict_nonzero(leaf->signature, sizeof(leaf->signature)))
        return verdict_fail(why, why_len, ZCL_DEV_VERDICT_WHY_UNSIGNED);
    if (!verdict_message(leaf, message))
        return verdict_fail(why, why_len, ZCL_DEV_VERDICT_WHY_ENCODING);
    if (!zcl_dev_proof_signer_verify(message, sizeof(message),
                                     leaf->producer_pubkey, leaf->signature,
                                     &signer_why))
        return verdict_fail(why, why_len, signer_why ? signer_why :
                            ZCL_DEV_PROOF_SIGNER_WHY_SIGNATURE_INVALID);
    if (why && why_len) why[0] = 0;
    return true;
}

bool zcl_dev_verdict_leaf_root(
    const struct zcl_dev_verdict_leaf_v1 *leaf,
    uint8_t out[ZCL_DEV_PROOF_ROOT_BYTES], char *why, size_t why_len)
{
    uint8_t wire[ZCL_DEV_VERDICT_LEAF_WIRE_BYTES];
    if (!out)
        return verdict_fail(why, why_len, ZCL_DEV_VERDICT_WHY_ARGUMENTS);
    memset(out, 0, ZCL_DEV_PROOF_ROOT_BYTES);
    if (!zcl_dev_verdict_leaf_serialize(leaf, wire, why, why_len))
        return false;
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)VERDICT_ROOT_DOMAIN,
                   sizeof(VERDICT_ROOT_DOMAIN) - 1u);
    sha3_256_write(&sha, wire, sizeof(wire));
    sha3_256_finalize(&sha, out);
    if (why && why_len) why[0] = 0;
    return true;
}
