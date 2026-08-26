/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: canonical signed zcl.moderation.node_attestation.v1 wire object --
 * one node's verifiable sign-off on one piece of content under one profile.
 *
 * Shape rules live in ONE function (attest_shape) which both sign and
 * validate call, so a statement that cannot be validated can never be
 * produced by signing. Every helper here is pure; the file touches no global
 * state and no clock, which is what lets a reader verify a statement offline
 * and what keeps this module structurally unreachable from consensus. */

#include "vcs/moderation_attestation.h"

#include "base/cleanse.h"
#include "base/serialize_le.h"
#include "crypto/ed25519.h"
#include "crypto/sha3.h"

#include <string.h>

static const uint8_t attest_magic[8] = {'Z', 'M', 'A', 'T', 'T', '1', 0, 0};
static const char attest_signature_domain[] =
    ZCL_MODERATION_ATTESTATION_SIGNATURE_DOMAIN;

const char *zcl_moderation_error_string(enum zcl_moderation_error error)
{
    switch (error) {
    case ZCL_MODERATION_OK: return "ok";
    case ZCL_MODERATION_NULL: return "null-argument";
    case ZCL_MODERATION_SIZE: return "wire-size";
    case ZCL_MODERATION_MAGIC: return "wire-magic";
    case ZCL_MODERATION_VERSION: return "schema-version";
    case ZCL_MODERATION_FLAGS: return "flags";
    case ZCL_MODERATION_ENUM: return "closed-enum";
    case ZCL_MODERATION_ROOT: return "root";
    case ZCL_MODERATION_TIME: return "validity-window";
    case ZCL_MODERATION_SIGNATURE: return "signature";
    case ZCL_MODERATION_CHAIN: return "supersession-chain";
    case ZCL_MODERATION_LIMIT: return "capacity";
    case ZCL_MODERATION_NOMEM: return "allocation";
    }
    return "unknown-moderation-error";
}

const char *zcl_moderation_verdict_string(
    enum zcl_moderation_verdict_v1 verdict)
{
    switch (verdict) {
    case ZCL_MODERATION_VERDICT_UNREVIEWED: return "unreviewed";
    case ZCL_MODERATION_VERDICT_REVIEWED_OK: return "reviewed_ok";
    case ZCL_MODERATION_VERDICT_HIDDEN: return "hidden";
    case ZCL_MODERATION_VERDICT_COUNT: break;
    }
    return "unknown";
}

const char *zcl_moderation_reason_string(enum zcl_moderation_reason_v1 reason)
{
    switch (reason) {
    case ZCL_MODERATION_REASON_UNREVIEWED:
        return "no attestation reaches this reader; unreviewed is not served";
    case ZCL_MODERATION_REASON_SELF_HIDDEN:
        return "this node's own sign-off hides it; local policy is final";
    case ZCL_MODERATION_REASON_SELF_OK:
        return "this node's own sign-off is reviewed_ok";
    case ZCL_MODERATION_REASON_LOCAL_TRUST_DISABLED:
        return "no local trust threshold configured; remote sign-off counts "
               "for nothing here";
    case ZCL_MODERATION_REASON_TRUSTED_VETO:
        return "a locally trusted reviewer says hidden";
    case ZCL_MODERATION_REASON_TRUSTED_QUORUM:
        return "locally configured threshold of trusted reviewers say "
               "reviewed_ok";
    case ZCL_MODERATION_REASON_NO_QUORUM:
        return "fewer trusted reviewers than the locally configured threshold";
    case ZCL_MODERATION_REASON_COUNT: break;
    }
    return "unknown-moderation-reason";
}

static bool attest_nonzero(const uint8_t *bytes, size_t count)
{
    uint8_t any = 0;
    if (!bytes) return false;
    for (size_t i = 0; i < count; i++) any |= bytes[i];
    return any != 0;
}

static enum zcl_moderation_error attest_literal_root(
    const char *domain, size_t domain_len, const char *literal,
    size_t literal_len, uint8_t out[32])
{
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)domain, domain_len + 1u);
    sha3_256_write(&sha, (const uint8_t *)literal, literal_len + 1u);
    sha3_256_finalize(&sha, out);
    return ZCL_MODERATION_OK;
}

enum zcl_moderation_error zcl_moderation_profile_root_v1(
    const char *profile_name, uint8_t out[32])
{
    if (out) memset(out, 0, 32);
    if (!profile_name || !out) return ZCL_MODERATION_NULL;
    size_t len = strnlen(profile_name, ZCL_MODERATION_PROFILE_NAME_MAX + 1u);
    /* Empty is not a profile, and an over-long name is refused rather than
     * truncated: a truncating hash would collide two distinct profiles. */
    if (len == 0 || len > ZCL_MODERATION_PROFILE_NAME_MAX)
        return ZCL_MODERATION_LIMIT;
    static const char domain[] = ZCL_MODERATION_PROFILE_NAME_DOMAIN;
    return attest_literal_root(domain, sizeof(domain) - 1u, profile_name, len,
                               out);
}

enum zcl_moderation_error zcl_moderation_policy_root_v1(
    const char *policy_text, uint8_t out[32])
{
    if (out) memset(out, 0, 32);
    if (!policy_text || !out) return ZCL_MODERATION_NULL;
    size_t len = strlen(policy_text);
    if (len == 0) return ZCL_MODERATION_LIMIT;
    static const char domain[] = ZCL_MODERATION_POLICY_TEXT_DOMAIN;
    return attest_literal_root(domain, sizeof(domain) - 1u, policy_text, len,
                               out);
}

/* The single shape authority. require_signature is false only from within
 * sign(), where the signature field is deliberately still zero. */
static enum zcl_moderation_error attest_shape(
    const struct zcl_moderation_attestation_v1 *attestation,
    bool require_signature)
{
    if (!attestation) return ZCL_MODERATION_NULL;
    if (attestation->schema_version != ZCL_MODERATION_ATTESTATION_VERSION)
        return ZCL_MODERATION_VERSION;
    /* v1 defines no flags. An unknown bit means the writer knew something
     * this reader does not, so the reader refuses instead of guessing. */
    if (attestation->flags != 0) return ZCL_MODERATION_FLAGS;
    if (attestation->reserved != 0) return ZCL_MODERATION_ENUM;
    if (attestation->verdict >= ZCL_MODERATION_VERDICT_COUNT)
        return ZCL_MODERATION_ENUM;
    if (attestation->sequence == 0 || attestation->reviewed_height == 0)
        return ZCL_MODERATION_TIME;
    if (attestation->reviewed_mtp <= 0 ||
        attestation->expires_mtp <= attestation->reviewed_mtp)
        return ZCL_MODERATION_TIME;
    /* Signed arithmetic: compare by subtraction against the cap rather than
     * adding to reviewed_mtp, so a hostile reviewed_mtp near INT64_MAX cannot
     * overflow the check itself. */
    if (attestation->expires_mtp - attestation->reviewed_mtp >
        ZCL_MODERATION_MAX_LIFETIME_SECS)
        return ZCL_MODERATION_TIME;
    if (!attest_nonzero(attestation->content_root, 32) ||
        !attest_nonzero(attestation->profile_root, 32) ||
        !attest_nonzero(attestation->policy_root, 32) ||
        !attest_nonzero(attestation->signer_pubkey, 32))
        return ZCL_MODERATION_ROOT;
    /* sequence 1 is a first statement and has no predecessor; anything above
     * it must name what it supersedes, so the order is tamper-evident. */
    if ((attestation->sequence == 1u &&
         attest_nonzero(attestation->predecessor_root, 32)) ||
        (attestation->sequence > 1u &&
         !attest_nonzero(attestation->predecessor_root, 32)))
        return ZCL_MODERATION_CHAIN;
    if (require_signature && !attest_nonzero(attestation->signature, 64))
        return ZCL_MODERATION_SIGNATURE;
    return ZCL_MODERATION_OK;
}

static size_t attest_write_body(
    const struct zcl_moderation_attestation_v1 *attestation, uint8_t *wire)
{
    size_t off = 0;
    memcpy(wire + off, attest_magic, sizeof(attest_magic));
    off += sizeof(attest_magic);
    zcl_write_u16_le(wire + off, attestation->schema_version); off += 2;
    zcl_write_u16_le(wire + off, attestation->flags); off += 2;
    zcl_write_u16_le(wire + off, attestation->verdict); off += 2;
    zcl_write_u16_le(wire + off, attestation->reserved); off += 2;
    zcl_write_u64_le(wire + off, attestation->sequence); off += 8;
    zcl_write_u64_le(wire + off, attestation->reviewed_height); off += 8;
    zcl_write_u64_le(wire + off, (uint64_t)attestation->reviewed_mtp);
    off += 8;
    zcl_write_u64_le(wire + off, (uint64_t)attestation->expires_mtp); off += 8;
    memcpy(wire + off, attestation->content_root, 32); off += 32;
    memcpy(wire + off, attestation->profile_root, 32); off += 32;
    memcpy(wire + off, attestation->policy_root, 32); off += 32;
    memcpy(wire + off, attestation->predecessor_root, 32); off += 32;
    memcpy(wire + off, attestation->signer_pubkey, 32); off += 32;
    return off;
}

#define ATTEST_SIG_DOMAIN_LEN (sizeof(attest_signature_domain) - 1u)
#define ATTEST_PREIMAGE_BYTES \
    (ATTEST_SIG_DOMAIN_LEN + ZCL_MODERATION_ATTESTATION_BODY_BYTES)

static size_t attest_build_preimage(
    const struct zcl_moderation_attestation_v1 *attestation,
    uint8_t preimage[ATTEST_PREIMAGE_BYTES])
{
    memcpy(preimage, attest_signature_domain, ATTEST_SIG_DOMAIN_LEN);
    size_t body_len =
        attest_write_body(attestation, preimage + ATTEST_SIG_DOMAIN_LEN);
    return ATTEST_SIG_DOMAIN_LEN + body_len;
}

static bool attest_signature_valid(
    const struct zcl_moderation_attestation_v1 *attestation)
{
    uint8_t preimage[ATTEST_PREIMAGE_BYTES];
    size_t len = attest_build_preimage(attestation, preimage);
    bool valid = ed25519_verify(attestation->signature, preimage, len,
                                attestation->signer_pubkey);
    memory_cleanse(preimage, sizeof(preimage));
    return valid;
}

enum zcl_moderation_error zcl_moderation_attestation_v1_validate(
    const struct zcl_moderation_attestation_v1 *attestation)
{
    enum zcl_moderation_error error = attest_shape(attestation, true);
    if (error != ZCL_MODERATION_OK) return error;
    return attest_signature_valid(attestation) ? ZCL_MODERATION_OK
                                               : ZCL_MODERATION_SIGNATURE;
}

enum zcl_moderation_error zcl_moderation_attestation_v1_sign(
    struct zcl_moderation_attestation_v1 *attestation,
    const uint8_t signer_seed[32])
{
    if (!attestation || !signer_seed) return ZCL_MODERATION_NULL;
    uint8_t secret[32];
    ed25519_keypair(attestation->signer_pubkey, secret, signer_seed);
    memset(attestation->signature, 0, sizeof(attestation->signature));
    enum zcl_moderation_error error = attest_shape(attestation, false);
    if (error != ZCL_MODERATION_OK) {
        memory_cleanse(secret, sizeof(secret));
        return error;
    }
    uint8_t preimage[ATTEST_PREIMAGE_BYTES];
    size_t len = attest_build_preimage(attestation, preimage);
    ed25519_sign(attestation->signature, preimage, len, secret,
                 attestation->signer_pubkey);
    memory_cleanse(secret, sizeof(secret));
    memory_cleanse(preimage, sizeof(preimage));
    /* Sign never returns OK for something validate would refuse. */
    return zcl_moderation_attestation_v1_validate(attestation);
}

enum zcl_moderation_error zcl_moderation_attestation_v1_encode(
    const struct zcl_moderation_attestation_v1 *attestation,
    uint8_t *wire, size_t wire_capacity, size_t *wire_len)
{
    if (wire_len) *wire_len = 0;
    if (!wire || !wire_len) return ZCL_MODERATION_NULL;
    enum zcl_moderation_error error =
        zcl_moderation_attestation_v1_validate(attestation);
    if (error != ZCL_MODERATION_OK) return error;
    if (wire_capacity < ZCL_MODERATION_ATTESTATION_WIRE_BYTES)
        return ZCL_MODERATION_SIZE;
    size_t off = attest_write_body(attestation, wire);
    memcpy(wire + off, attestation->signature, 64);
    off += 64;
    if (off != ZCL_MODERATION_ATTESTATION_WIRE_BYTES)
        return ZCL_MODERATION_SIZE;
    *wire_len = off;
    return ZCL_MODERATION_OK;
}

enum zcl_moderation_error zcl_moderation_attestation_v1_decode(
    struct zcl_moderation_attestation_v1 *out,
    const uint8_t *wire, size_t wire_len)
{
    if (!out || !wire) return ZCL_MODERATION_NULL;
    memset(out, 0, sizeof(*out));
    /* Exact length only. A short buffer is a truncated record and a long one
     * carries trailing bytes nobody signed; both fail before any parse. */
    if (wire_len != ZCL_MODERATION_ATTESTATION_WIRE_BYTES)
        return ZCL_MODERATION_SIZE;
    if (memcmp(wire, attest_magic, sizeof(attest_magic)) != 0)
        return ZCL_MODERATION_MAGIC;
    size_t off = sizeof(attest_magic);
    out->schema_version = zcl_read_u16_le(wire + off); off += 2;
    out->flags = zcl_read_u16_le(wire + off); off += 2;
    out->verdict = zcl_read_u16_le(wire + off); off += 2;
    out->reserved = zcl_read_u16_le(wire + off); off += 2;
    out->sequence = zcl_read_u64_le(wire + off); off += 8;
    out->reviewed_height = zcl_read_u64_le(wire + off); off += 8;
    out->reviewed_mtp = (int64_t)zcl_read_u64_le(wire + off); off += 8;
    out->expires_mtp = (int64_t)zcl_read_u64_le(wire + off); off += 8;
    memcpy(out->content_root, wire + off, 32); off += 32;
    memcpy(out->profile_root, wire + off, 32); off += 32;
    memcpy(out->policy_root, wire + off, 32); off += 32;
    memcpy(out->predecessor_root, wire + off, 32); off += 32;
    memcpy(out->signer_pubkey, wire + off, 32); off += 32;
    memcpy(out->signature, wire + off, 64); off += 64;
    enum zcl_moderation_error error =
        off == wire_len ? zcl_moderation_attestation_v1_validate(out)
                        : ZCL_MODERATION_SIZE;
    if (error != ZCL_MODERATION_OK) memset(out, 0, sizeof(*out));
    return error;
}

enum zcl_moderation_error zcl_moderation_attestation_v1_root(
    const struct zcl_moderation_attestation_v1 *attestation, uint8_t out[32])
{
    if (out) memset(out, 0, 32);
    if (!attestation || !out) return ZCL_MODERATION_NULL;
    uint8_t wire[ZCL_MODERATION_ATTESTATION_WIRE_BYTES];
    size_t wire_len = 0;
    enum zcl_moderation_error error = zcl_moderation_attestation_v1_encode(
        attestation, wire, sizeof(wire), &wire_len);
    if (error != ZCL_MODERATION_OK) return error;
    struct sha3_256_ctx sha;
    static const char domain[] = ZCL_MODERATION_ATTESTATION_ROOT_DOMAIN;
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)domain, sizeof(domain));
    sha3_256_write(&sha, wire, wire_len);
    sha3_256_finalize(&sha, out);
    memory_cleanse(wire, sizeof(wire));
    return ZCL_MODERATION_OK;
}
