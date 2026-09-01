/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: canonical signed simulation-only ZC23 creation claim object. */
#include "vcs/zcode_creation_claim.h"

#include "base/bytes.h"
#include "base/cleanse.h"
#include "base/serialize_le.h"
#include "crypto/ed25519.h"
#include "vcs/signed_evidence.h"

#include <stdbool.h>
#include <string.h>

static const uint8_t claim_magic[8] =
    {'Z','C','C','L','M','2',0,0};

static enum vcs_zcode_creation_claim_error claim_shape(
    const struct vcs_zcode_creation_claim_wire_v2 *claim,
    bool require_signature)
{
    const uint16_t allowed_flags =
        VCS_ZCODE_CLAIM_V2_REQUIRED_FLAGS |
        VCS_ZCODE_CLAIM_V2_INVALIDATING_FLAGS;
    if (!claim) return VCS_ZCODE_CREATION_CLAIM_NULL;
    if (claim->schema_version != VCS_ZCODE_CREATION_CLAIM_V2_VERSION)
        return VCS_ZCODE_CREATION_CLAIM_V2_VERSION_ERROR;
    if ((claim->flags & (uint16_t)~allowed_flags) != 0)
        return VCS_ZCODE_CREATION_CLAIM_FLAGS;
    if (claim->category >= VCS_ZCODE_COMMONS_CATEGORY_COUNT ||
        claim->reserved != 0)
        return VCS_ZCODE_CREATION_CLAIM_ENUM;
    const uint8_t *roots[] = {
        claim->recipient_binding_root, claim->workspace_lineage_root,
        claim->semantic_lineage_root, claim->evidence_root,
        claim->commons_admission_root, claim->signer_pubkey,
    };
    for (size_t i = 0; i < sizeof(roots) / sizeof(roots[0]); i++)
        if (!zcl_bytes_any_set(roots[i], 32))
            return VCS_ZCODE_CREATION_CLAIM_ROOT;
    if (claim->maturity_height == 0 || claim->maturity_mtp <= 0)
        return VCS_ZCODE_CREATION_CLAIM_TIME;
    if (require_signature && !zcl_bytes_any_set(claim->signature, 64))
        return VCS_ZCODE_CREATION_CLAIM_SIGNATURE;
    return VCS_ZCODE_CREATION_CLAIM_OK;
}

static size_t claim_write_unsigned(
    const struct vcs_zcode_creation_claim_wire_v2 *claim,
    uint8_t wire[VCS_ZCODE_CREATION_CLAIM_UNSIGNED_BYTES])
{
    size_t off = 0;
    memcpy(wire + off, claim_magic, sizeof(claim_magic)); off += 8;
    zcl_write_u16_le(wire + off, claim->schema_version); off += 2;
    zcl_write_u16_le(wire + off, claim->flags); off += 2;
    zcl_write_u16_le(wire + off, claim->category); off += 2;
    zcl_write_u16_le(wire + off, claim->reserved); off += 2;
    memcpy(wire + off, claim->recipient_binding_root, 32); off += 32;
    memcpy(wire + off, claim->workspace_lineage_root, 32); off += 32;
    memcpy(wire + off, claim->semantic_lineage_root, 32); off += 32;
    memcpy(wire + off, claim->evidence_root, 32); off += 32;
    memcpy(wire + off, claim->commons_admission_root, 32); off += 32;
    zcl_write_u64_le(wire + off, claim->maturity_height); off += 8;
    zcl_write_u64_le(wire + off, (uint64_t)claim->maturity_mtp); off += 8;
    memcpy(wire + off, claim->signer_pubkey, 32); off += 32;
    return off;
}

static enum vcs_zcode_creation_claim_error claim_signing_root(
    const struct vcs_zcode_creation_claim_wire_v2 *claim, uint8_t out[32])
{
    enum vcs_zcode_creation_claim_error error = claim_shape(claim, false);
    if (error != VCS_ZCODE_CREATION_CLAIM_OK) return error;
    uint8_t wire[VCS_ZCODE_CREATION_CLAIM_UNSIGNED_BYTES];
    size_t wire_len = claim_write_unsigned(claim, wire);
    if (wire_len != sizeof(wire)) return VCS_ZCODE_CREATION_CLAIM_WIRE_SIZE;
    static const char domain[] = VCS_ZCODE_CREATION_CLAIM_SIGNING_DOMAIN;
    return vcs_signed_evidence_root(
               domain, sizeof(domain), wire, wire_len, out)
        ? VCS_ZCODE_CREATION_CLAIM_OK : VCS_ZCODE_CREATION_CLAIM_NULL;
}

enum vcs_zcode_creation_claim_error
vcs_zcode_creation_claim_wire_v2_validate(
    const struct vcs_zcode_creation_claim_wire_v2 *claim)
{
    enum vcs_zcode_creation_claim_error error = claim_shape(claim, true);
    if (error != VCS_ZCODE_CREATION_CLAIM_OK) return error;
    uint8_t root[32];
    error = claim_signing_root(claim, root);
    if (error != VCS_ZCODE_CREATION_CLAIM_OK) return error;
    bool valid = vcs_signed_evidence_verify_root(
        root, claim->signature, claim->signer_pubkey,
        claim->signer_pubkey);
    memory_cleanse(root, sizeof(root));
    return valid ? VCS_ZCODE_CREATION_CLAIM_OK
                 : VCS_ZCODE_CREATION_CLAIM_SIGNATURE;
}

enum vcs_zcode_creation_claim_error
vcs_zcode_creation_claim_wire_v2_sign(
    struct vcs_zcode_creation_claim_wire_v2 *claim,
    const uint8_t signer_seed[32])
{
    if (!claim || !signer_seed) return VCS_ZCODE_CREATION_CLAIM_NULL;
    uint8_t secret[32], root[32];
    ed25519_keypair(claim->signer_pubkey, secret, signer_seed);
    memset(claim->signature, 0, sizeof(claim->signature));
    enum vcs_zcode_creation_claim_error error =
        claim_signing_root(claim, root);
    if (error == VCS_ZCODE_CREATION_CLAIM_OK &&
        !vcs_signed_evidence_seal_root(
            root, secret, claim->signer_pubkey, claim->signature))
        error = VCS_ZCODE_CREATION_CLAIM_NULL;
    memory_cleanse(secret, sizeof(secret));
    memory_cleanse(root, sizeof(root));
    return error == VCS_ZCODE_CREATION_CLAIM_OK
        ? vcs_zcode_creation_claim_wire_v2_validate(claim) : error;
}

enum vcs_zcode_creation_claim_error
vcs_zcode_creation_claim_wire_v2_encode(
    const struct vcs_zcode_creation_claim_wire_v2 *claim,
    uint8_t *wire, size_t wire_capacity, size_t *wire_len)
{
    if (wire_len) *wire_len = 0;
    if (!wire || !wire_len) return VCS_ZCODE_CREATION_CLAIM_NULL;
    enum vcs_zcode_creation_claim_error error =
        vcs_zcode_creation_claim_wire_v2_validate(claim);
    if (error != VCS_ZCODE_CREATION_CLAIM_OK) return error;
    if (wire_capacity < VCS_ZCODE_CREATION_CLAIM_WIRE_BYTES)
        return VCS_ZCODE_CREATION_CLAIM_WIRE_SIZE;
    size_t off = claim_write_unsigned(claim, wire);
    memcpy(wire + off, claim->signature, 64); off += 64;
    if (off != VCS_ZCODE_CREATION_CLAIM_WIRE_BYTES)
        return VCS_ZCODE_CREATION_CLAIM_WIRE_SIZE;
    *wire_len = off;
    return VCS_ZCODE_CREATION_CLAIM_OK;
}

enum vcs_zcode_creation_claim_error
vcs_zcode_creation_claim_wire_v2_decode(
    struct vcs_zcode_creation_claim_wire_v2 *out,
    const uint8_t *wire, size_t wire_len)
{
    if (out) memset(out, 0, sizeof(*out));
    if (!out || !wire) return VCS_ZCODE_CREATION_CLAIM_NULL;
    if (wire_len != VCS_ZCODE_CREATION_CLAIM_WIRE_BYTES)
        return VCS_ZCODE_CREATION_CLAIM_WIRE_SIZE;
    if (memcmp(wire, claim_magic, sizeof(claim_magic)) != 0)
        return VCS_ZCODE_CREATION_CLAIM_MAGIC_ERROR;
    struct vcs_zcode_creation_claim_wire_v2 decoded = {0};
    size_t off = 8;
    decoded.schema_version = zcl_read_u16_le(wire + off); off += 2;
    decoded.flags = zcl_read_u16_le(wire + off); off += 2;
    decoded.category = zcl_read_u16_le(wire + off); off += 2;
    decoded.reserved = zcl_read_u16_le(wire + off); off += 2;
    memcpy(decoded.recipient_binding_root, wire + off, 32); off += 32;
    memcpy(decoded.workspace_lineage_root, wire + off, 32); off += 32;
    memcpy(decoded.semantic_lineage_root, wire + off, 32); off += 32;
    memcpy(decoded.evidence_root, wire + off, 32); off += 32;
    memcpy(decoded.commons_admission_root, wire + off, 32); off += 32;
    decoded.maturity_height = zcl_read_u64_le(wire + off); off += 8;
    decoded.maturity_mtp = (int64_t)zcl_read_u64_le(wire + off); off += 8;
    memcpy(decoded.signer_pubkey, wire + off, 32); off += 32;
    memcpy(decoded.signature, wire + off, 64); off += 64;
    enum vcs_zcode_creation_claim_error error =
        off == wire_len ? vcs_zcode_creation_claim_wire_v2_validate(&decoded)
                        : VCS_ZCODE_CREATION_CLAIM_WIRE_SIZE;
    if (error != VCS_ZCODE_CREATION_CLAIM_OK) return error;
    *out = decoded;
    return VCS_ZCODE_CREATION_CLAIM_OK;
}

enum vcs_zcode_creation_claim_error
vcs_zcode_creation_claim_wire_v2_root(
    const struct vcs_zcode_creation_claim_wire_v2 *claim, uint8_t out[32])
{
    if (out) memset(out, 0, 32);
    if (!claim || !out) return VCS_ZCODE_CREATION_CLAIM_NULL;
    uint8_t wire[VCS_ZCODE_CREATION_CLAIM_WIRE_BYTES];
    size_t wire_len = 0;
    enum vcs_zcode_creation_claim_error error =
        vcs_zcode_creation_claim_wire_v2_encode(
            claim, wire, sizeof(wire), &wire_len);
    if (error != VCS_ZCODE_CREATION_CLAIM_OK) return error;
    static const char domain[] = VCS_ZCODE_CREATION_CLAIM_V2_DOMAIN;
    return vcs_signed_evidence_root(domain, sizeof(domain), wire, wire_len,
                                    out)
               ? VCS_ZCODE_CREATION_CLAIM_OK
               : VCS_ZCODE_CREATION_CLAIM_NULL;
}

void vcs_zcode_creation_claim_wire_v2_selection(
    const struct vcs_zcode_creation_claim_wire_v2 *claim,
    const uint8_t claim_root[32], struct vcs_zcode_creation_claim_v2 *out)
{
    if (!out) return;
    memset(out, 0, sizeof(*out));
    if (!claim || !claim_root) return;
    out->schema_version = VCS_ZCODE_CREATION_CLAIM_V2_VERSION;
    out->flags = claim->flags;
    out->category = claim->category;
    memcpy(out->claim_root, claim_root, 32);
    memcpy(out->recipient_binding_root, claim->recipient_binding_root, 32);
    memcpy(out->workspace_lineage_root, claim->workspace_lineage_root, 32);
    memcpy(out->semantic_lineage_root, claim->semantic_lineage_root, 32);
    memcpy(out->evidence_root, claim->evidence_root, 32);
    memcpy(out->commons_admission_root, claim->commons_admission_root, 32);
    out->maturity_height = claim->maturity_height;
    out->maturity_mtp = claim->maturity_mtp;
}
