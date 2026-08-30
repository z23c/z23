/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: canonical signed commons_admission.v1 wire object. */

#include "vcs/zcode_family_admission.h"

#include "base/bytes.h"
#include "base/cleanse.h"
#include "base/serialize_le.h"
#include "crypto/ed25519.h"
#include "crypto/sha3.h"

#include <string.h>

static const uint8_t admission_magic[8] = {'Z','C','A','D','M','1',0,0};
static const char admission_signature_domain[] =
    "zcl.zcode.commons_admission.signature.v1";

static bool admission_zero(const uint8_t *bytes, size_t count)
{
    return !zcl_bytes_any_set(bytes, count);
}

const char *vcs_zcode_family_admission_error_string(
    enum vcs_zcode_family_admission_error error)
{
    switch (error) {
    case VCS_ZCODE_FAMILY_ADMISSION_OK: return "ok";
    case VCS_ZCODE_FAMILY_ADMISSION_NULL: return "null-argument";
    case VCS_ZCODE_FAMILY_ADMISSION_SIZE: return "wire-size";
    case VCS_ZCODE_FAMILY_ADMISSION_MAGIC: return "wire-magic";
    case VCS_ZCODE_FAMILY_ADMISSION_VERSION: return "schema-version";
    case VCS_ZCODE_FAMILY_ADMISSION_FLAGS: return "flags";
    case VCS_ZCODE_FAMILY_ADMISSION_ENUM: return "closed-enum";
    case VCS_ZCODE_FAMILY_ADMISSION_ROOT: return "root";
    case VCS_ZCODE_FAMILY_ADMISSION_TIME: return "chain-time";
    case VCS_ZCODE_FAMILY_ADMISSION_SIGNATURE: return "signature";
    case VCS_ZCODE_FAMILY_ADMISSION_ORDER: return "canonical-order";
    case VCS_ZCODE_FAMILY_ADMISSION_CHAIN: return "admission-chain";
    case VCS_ZCODE_FAMILY_ADMISSION_LIMIT: return "capacity";
    case VCS_ZCODE_FAMILY_ADMISSION_NOMEM: return "allocation";
    case VCS_ZCODE_FAMILY_ADMISSION_OVERFLOW: return "generation-overflow";
    }
    return "unknown-family-admission-error";
}

static bool admission_pass_state(uint16_t state)
{
    return state >= VCS_ZCODE_ADMISSION_SELF_SCREENED &&
           state <= VCS_ZCODE_ADMISSION_RESILIENT_PASS;
}

static enum vcs_zcode_family_admission_error admission_shape(
    const struct vcs_zcode_commons_admission_v1 *admission,
    bool require_signature)
{
    if (!admission) return VCS_ZCODE_FAMILY_ADMISSION_NULL;
    if (admission->schema_version != 1)
        return VCS_ZCODE_FAMILY_ADMISSION_VERSION;
    if (admission->flags != VCS_ZCODE_COMMONS_REQUIRED_FLAGS)
        return VCS_ZCODE_FAMILY_ADMISSION_FLAGS;
    if (admission->state > VCS_ZCODE_ADMISSION_REORGED ||
        admission->tier > VCS_ZCODE_MODERATION_TIER_RESILIENT_PASS ||
        admission->coverage_complete > 1 ||
        admission->closure_complete > 1 || admission->reserved != 0)
        return VCS_ZCODE_FAMILY_ADMISSION_ENUM;
    if (!admission->sequence || !admission->decided_height ||
        admission->decided_mtp <= 0 ||
        admission->expires_height < admission->decided_height ||
        admission->expires_mtp < admission->decided_mtp)
        return VCS_ZCODE_FAMILY_ADMISSION_TIME;
    if (!zcl_bytes_any_set(admission->content_root, 32) ||
        !zcl_bytes_any_set(admission->dependency_closure_root, 32) ||
        !zcl_bytes_any_set(admission->family_policy_root, 32) ||
        !zcl_bytes_any_set(admission->moderation_set_root, 32) ||
        !zcl_bytes_any_set(admission->panel_root, 32) ||
        !zcl_bytes_any_set(admission->evidence_root, 32) ||
        !zcl_bytes_any_set(admission->signer_pubkey, 32))
        return VCS_ZCODE_FAMILY_ADMISSION_ROOT;
    if ((admission->sequence == 1 &&
         !admission_zero(admission->predecessor_admission_root, 32)) ||
        (admission->sequence > 1 &&
         !zcl_bytes_any_set(admission->predecessor_admission_root, 32)))
        return VCS_ZCODE_FAMILY_ADMISSION_CHAIN;
    if (admission_pass_state(admission->state)) {
        uint16_t expected = (uint16_t)(VCS_ZCODE_ADMISSION_SELF_SCREENED +
                                       admission->tier);
        if (admission->state != expected || !admission->coverage_complete ||
            !admission->closure_complete)
            return VCS_ZCODE_FAMILY_ADMISSION_CHAIN;
    }
    if (require_signature &&
        !zcl_bytes_any_set(admission->signature, 64))
        return VCS_ZCODE_FAMILY_ADMISSION_SIGNATURE;
    return VCS_ZCODE_FAMILY_ADMISSION_OK;
}

static size_t admission_write_unsigned(
    const struct vcs_zcode_commons_admission_v1 *admission, uint8_t *wire)
{
    size_t off = 0;
    memcpy(wire + off, admission_magic, sizeof(admission_magic)); off += 8;
    zcl_write_u16_le(wire + off, admission->schema_version); off += 2;
    zcl_write_u16_le(wire + off, admission->flags); off += 2;
    zcl_write_u16_le(wire + off, admission->state); off += 2;
    zcl_write_u16_le(wire + off, admission->tier); off += 2;
    wire[off++] = admission->coverage_complete;
    wire[off++] = admission->closure_complete;
    zcl_write_u16_le(wire + off, admission->reserved); off += 2;
    zcl_write_u64_le(wire + off, admission->sequence); off += 8;
    zcl_write_u64_le(wire + off, admission->decided_height); off += 8;
    zcl_write_u64_le(wire + off, (uint64_t)admission->decided_mtp); off += 8;
    zcl_write_u64_le(wire + off, admission->expires_height); off += 8;
    zcl_write_u64_le(wire + off, (uint64_t)admission->expires_mtp); off += 8;
    memcpy(wire + off, admission->content_root, 32u * 8u); off += 32u * 8u;
    return off;
}

static bool admission_signature_valid(
    const struct vcs_zcode_commons_admission_v1 *admission)
{
    uint8_t wire[VCS_ZCODE_COMMONS_ADMISSION_WIRE_BYTES];
    uint8_t preimage[sizeof(admission_signature_domain) - 1u +
                     VCS_ZCODE_COMMONS_ADMISSION_WIRE_BYTES];
    size_t unsigned_len = admission_write_unsigned(admission, wire);
    size_t domain_len = sizeof(admission_signature_domain) - 1u;
    memcpy(preimage, admission_signature_domain, domain_len);
    memcpy(preimage + domain_len, wire, unsigned_len);
    bool valid = ed25519_verify(admission->signature, preimage,
                                domain_len + unsigned_len,
                                admission->signer_pubkey);
    memory_cleanse(wire, sizeof(wire));
    memory_cleanse(preimage, sizeof(preimage));
    return valid;
}

enum vcs_zcode_family_admission_error vcs_zcode_commons_admission_v1_validate(
    const struct vcs_zcode_commons_admission_v1 *admission)
{
    enum vcs_zcode_family_admission_error error =
        admission_shape(admission, true);
    if (error != VCS_ZCODE_FAMILY_ADMISSION_OK) return error;
    return admission_signature_valid(admission)
        ? VCS_ZCODE_FAMILY_ADMISSION_OK
        : VCS_ZCODE_FAMILY_ADMISSION_SIGNATURE;
}

enum vcs_zcode_family_admission_error vcs_zcode_commons_admission_v1_sign(
    struct vcs_zcode_commons_admission_v1 *admission,
    const uint8_t signer_seed[32])
{
    if (!admission || !signer_seed) return VCS_ZCODE_FAMILY_ADMISSION_NULL;
    uint8_t secret[32];
    ed25519_keypair(admission->signer_pubkey, secret, signer_seed);
    memset(admission->signature, 0, sizeof(admission->signature));
    enum vcs_zcode_family_admission_error error =
        admission_shape(admission, false);
    if (error != VCS_ZCODE_FAMILY_ADMISSION_OK) {
        memory_cleanse(secret, sizeof(secret));
        return error;
    }
    uint8_t wire[VCS_ZCODE_COMMONS_ADMISSION_WIRE_BYTES];
    uint8_t preimage[sizeof(admission_signature_domain) - 1u +
                     VCS_ZCODE_COMMONS_ADMISSION_WIRE_BYTES];
    size_t unsigned_len = admission_write_unsigned(admission, wire);
    size_t domain_len = sizeof(admission_signature_domain) - 1u;
    memcpy(preimage, admission_signature_domain, domain_len);
    memcpy(preimage + domain_len, wire, unsigned_len);
    ed25519_sign(admission->signature, preimage, domain_len + unsigned_len,
                 secret, admission->signer_pubkey);
    memory_cleanse(secret, sizeof(secret));
    memory_cleanse(wire, sizeof(wire));
    memory_cleanse(preimage, sizeof(preimage));
    return vcs_zcode_commons_admission_v1_validate(admission);
}

enum vcs_zcode_family_admission_error vcs_zcode_commons_admission_v1_encode(
    const struct vcs_zcode_commons_admission_v1 *admission,
    uint8_t *wire, size_t wire_capacity, size_t *wire_len)
{
    if (wire_len) *wire_len = 0;
    if (!wire || !wire_len) return VCS_ZCODE_FAMILY_ADMISSION_NULL;
    enum vcs_zcode_family_admission_error error =
        vcs_zcode_commons_admission_v1_validate(admission);
    if (error != VCS_ZCODE_FAMILY_ADMISSION_OK) return error;
    if (wire_capacity < VCS_ZCODE_COMMONS_ADMISSION_WIRE_BYTES)
        return VCS_ZCODE_FAMILY_ADMISSION_SIZE;
    size_t off = admission_write_unsigned(admission, wire);
    memcpy(wire + off, admission->signature, 64); off += 64;
    *wire_len = off;
    return off == VCS_ZCODE_COMMONS_ADMISSION_WIRE_BYTES
        ? VCS_ZCODE_FAMILY_ADMISSION_OK
        : VCS_ZCODE_FAMILY_ADMISSION_SIZE;
}

enum vcs_zcode_family_admission_error vcs_zcode_commons_admission_v1_decode(
    struct vcs_zcode_commons_admission_v1 *out,
    const uint8_t *wire, size_t wire_len)
{
    if (!out || !wire) return VCS_ZCODE_FAMILY_ADMISSION_NULL;
    memset(out, 0, sizeof(*out));
    if (wire_len != VCS_ZCODE_COMMONS_ADMISSION_WIRE_BYTES)
        return VCS_ZCODE_FAMILY_ADMISSION_SIZE;
    if (memcmp(wire, admission_magic, sizeof(admission_magic)) != 0)
        return VCS_ZCODE_FAMILY_ADMISSION_MAGIC;
    size_t off = 8;
    out->schema_version = zcl_read_u16_le(wire + off); off += 2;
    out->flags = zcl_read_u16_le(wire + off); off += 2;
    out->state = zcl_read_u16_le(wire + off); off += 2;
    out->tier = zcl_read_u16_le(wire + off); off += 2;
    out->coverage_complete = wire[off++];
    out->closure_complete = wire[off++];
    out->reserved = zcl_read_u16_le(wire + off); off += 2;
    out->sequence = zcl_read_u64_le(wire + off); off += 8;
    out->decided_height = zcl_read_u64_le(wire + off); off += 8;
    out->decided_mtp = (int64_t)zcl_read_u64_le(wire + off); off += 8;
    out->expires_height = zcl_read_u64_le(wire + off); off += 8;
    out->expires_mtp = (int64_t)zcl_read_u64_le(wire + off); off += 8;
    memcpy(out->content_root, wire + off, 32u * 8u); off += 32u * 8u;
    memcpy(out->signature, wire + off, 64); off += 64;
    enum vcs_zcode_family_admission_error error =
        off == wire_len ? vcs_zcode_commons_admission_v1_validate(out)
                        : VCS_ZCODE_FAMILY_ADMISSION_SIZE;
    if (error != VCS_ZCODE_FAMILY_ADMISSION_OK)
        memset(out, 0, sizeof(*out));
    return error;
}

enum vcs_zcode_family_admission_error vcs_zcode_commons_admission_v1_root(
    const struct vcs_zcode_commons_admission_v1 *admission,
    uint8_t out[32])
{
    if (out) memset(out, 0, 32);
    if (!admission || !out) return VCS_ZCODE_FAMILY_ADMISSION_NULL;
    uint8_t wire[VCS_ZCODE_COMMONS_ADMISSION_WIRE_BYTES];
    size_t wire_len = 0;
    enum vcs_zcode_family_admission_error error =
        vcs_zcode_commons_admission_v1_encode(
            admission, wire, sizeof(wire), &wire_len);
    if (error != VCS_ZCODE_FAMILY_ADMISSION_OK) return error;
    struct sha3_256_ctx sha;
    static const char domain[] = VCS_ZCODE_COMMONS_ADMISSION_V1_DOMAIN;
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)domain, sizeof(domain));
    sha3_256_write(&sha, wire, wire_len);
    sha3_256_finalize(&sha, out);
    memory_cleanse(wire, sizeof(wire));
    return VCS_ZCODE_FAMILY_ADMISSION_OK;
}
