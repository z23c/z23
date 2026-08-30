/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: signed evidence basis for local C23 productivity sharing. */

#include "vcs/zcode_c23_corpus.h"

#include "base/bytes.h"
#include "base/cleanse.h"
#include "base/serialize_le.h"
#include "crypto/ed25519.h"
#include "vcs/signed_evidence.h"

#include <string.h>

static const uint8_t receipt_magic[8] = {'Z','C','P','R','1',0,0,0};
static const char receipt_signature_domain[] =
    "zcl.zcode.productivity_receipt.signature.v1";

static enum vcs_zcode_c23_error receipt_shape(
    const struct vcs_zcode_productivity_receipt_v1 *receipt,
    bool require_signature)
{
    if (!receipt) return VCS_ZCODE_C23_NULL;
    if (receipt->schema_version != 1) return VCS_ZCODE_C23_VERSION;
    if (receipt->flags != VCS_ZCODE_C23_CORPUS_REQUIRED_FLAGS)
        return VCS_ZCODE_C23_FLAGS;
    if (receipt->evidence_mask != VCS_ZCODE_PRODUCTIVITY_REQUIRED_MASK ||
        receipt->reserved != 0)
        return VCS_ZCODE_C23_POLICY;
    if (!receipt->completed_height || receipt->completed_mtp <= 0)
        return VCS_ZCODE_C23_TIME;
    const uint8_t *roots[] = {
        receipt->work_root, receipt->acceptance_root, receipt->release_root,
        receipt->admission_root, receipt->package_root,
        receipt->checkpoint_root, receipt->signer_pubkey,
    };
    for (size_t i = 0; i < sizeof(roots) / sizeof(roots[0]); i++)
        if (!zcl_bytes_any_set(roots[i], 32)) return VCS_ZCODE_C23_ROOT;
    if (require_signature && !zcl_bytes_any_set(receipt->signature, 64))
        return VCS_ZCODE_C23_SIGNATURE;
    return VCS_ZCODE_C23_OK;
}

static size_t receipt_write_unsigned(
    const struct vcs_zcode_productivity_receipt_v1 *receipt,
    uint8_t wire[260])
{
    size_t off = 0;
    memcpy(wire + off, receipt_magic, 8); off += 8;
    zcl_write_u16_le(wire + off, receipt->schema_version); off += 2;
    zcl_write_u16_le(wire + off, receipt->flags); off += 2;
    zcl_write_u32_le(wire + off, receipt->evidence_mask); off += 4;
    zcl_write_u32_le(wire + off, receipt->reserved); off += 4;
    zcl_write_u64_le(wire + off, receipt->completed_height); off += 8;
    zcl_write_u64_le(wire + off, (uint64_t)receipt->completed_mtp); off += 8;
    memcpy(wire + off, receipt->work_root, 32); off += 32;
    memcpy(wire + off, receipt->acceptance_root, 32); off += 32;
    memcpy(wire + off, receipt->release_root, 32); off += 32;
    memcpy(wire + off, receipt->admission_root, 32); off += 32;
    memcpy(wire + off, receipt->package_root, 32); off += 32;
    memcpy(wire + off, receipt->checkpoint_root, 32); off += 32;
    memcpy(wire + off, receipt->signer_pubkey, 32); off += 32;
    return off;
}

static enum vcs_zcode_c23_error receipt_signing_root(
    const struct vcs_zcode_productivity_receipt_v1 *receipt,
    uint8_t out[32])
{
    enum vcs_zcode_c23_error error = receipt_shape(receipt, false);
    if (error != VCS_ZCODE_C23_OK) return error;
    uint8_t wire[260];
    size_t wire_len = receipt_write_unsigned(receipt, wire);
    return vcs_signed_evidence_root(
               receipt_signature_domain,
               sizeof(receipt_signature_domain) - 1u,
               wire, wire_len, out)
        ? VCS_ZCODE_C23_OK : VCS_ZCODE_C23_NULL;
}

enum vcs_zcode_c23_error vcs_zcode_productivity_receipt_v1_validate(
    const struct vcs_zcode_productivity_receipt_v1 *receipt)
{
    enum vcs_zcode_c23_error error = receipt_shape(receipt, true);
    if (error != VCS_ZCODE_C23_OK) return error;
    uint8_t root[32];
    error = receipt_signing_root(receipt, root);
    if (error != VCS_ZCODE_C23_OK) return error;
    bool valid = vcs_signed_evidence_verify_root(
        root, receipt->signature, receipt->signer_pubkey,
        receipt->signer_pubkey);
    memory_cleanse(root, sizeof(root));
    return valid ? VCS_ZCODE_C23_OK : VCS_ZCODE_C23_SIGNATURE;
}

enum vcs_zcode_c23_error vcs_zcode_productivity_receipt_v1_sign(
    struct vcs_zcode_productivity_receipt_v1 *receipt,
    const uint8_t signer_seed[32])
{
    if (!receipt || !signer_seed) return VCS_ZCODE_C23_NULL;
    uint8_t secret[32], root[32];
    ed25519_keypair(receipt->signer_pubkey, secret, signer_seed);
    memset(receipt->signature, 0, sizeof(receipt->signature));
    enum vcs_zcode_c23_error error = receipt_signing_root(receipt, root);
    if (error == VCS_ZCODE_C23_OK &&
        !vcs_signed_evidence_seal_root(
            root, secret, receipt->signer_pubkey, receipt->signature))
        error = VCS_ZCODE_C23_NULL;
    memory_cleanse(secret, sizeof(secret));
    memory_cleanse(root, sizeof(root));
    return error == VCS_ZCODE_C23_OK
        ? vcs_zcode_productivity_receipt_v1_validate(receipt) : error;
}

enum vcs_zcode_c23_error vcs_zcode_productivity_receipt_v1_encode(
    const struct vcs_zcode_productivity_receipt_v1 *receipt,
    uint8_t *wire, size_t wire_capacity, size_t *wire_len)
{
    if (wire_len) *wire_len = 0;
    if (!wire || !wire_len) return VCS_ZCODE_C23_NULL;
    enum vcs_zcode_c23_error error =
        vcs_zcode_productivity_receipt_v1_validate(receipt);
    if (error != VCS_ZCODE_C23_OK) return error;
    if (wire_capacity < VCS_ZCODE_PRODUCTIVITY_RECEIPT_WIRE_BYTES)
        return VCS_ZCODE_C23_SIZE;
    size_t off = receipt_write_unsigned(receipt, wire);
    memcpy(wire + off, receipt->signature, 64); off += 64;
    *wire_len = off;
    return off == VCS_ZCODE_PRODUCTIVITY_RECEIPT_WIRE_BYTES
        ? VCS_ZCODE_C23_OK : VCS_ZCODE_C23_SIZE;
}

enum vcs_zcode_c23_error vcs_zcode_productivity_receipt_v1_decode(
    struct vcs_zcode_productivity_receipt_v1 *out,
    const uint8_t *wire, size_t wire_len)
{
    if (!out || !wire) return VCS_ZCODE_C23_NULL;
    memset(out, 0, sizeof(*out));
    if (wire_len != VCS_ZCODE_PRODUCTIVITY_RECEIPT_WIRE_BYTES)
        return VCS_ZCODE_C23_SIZE;
    if (memcmp(wire, receipt_magic, 8) != 0)
        return VCS_ZCODE_C23_MAGIC;
    size_t off = 8;
    out->schema_version = zcl_read_u16_le(wire + off); off += 2;
    out->flags = zcl_read_u16_le(wire + off); off += 2;
    out->evidence_mask = zcl_read_u32_le(wire + off); off += 4;
    out->reserved = zcl_read_u32_le(wire + off); off += 4;
    out->completed_height = zcl_read_u64_le(wire + off); off += 8;
    out->completed_mtp = (int64_t)zcl_read_u64_le(wire + off); off += 8;
    memcpy(out->work_root, wire + off, 32); off += 32;
    memcpy(out->acceptance_root, wire + off, 32); off += 32;
    memcpy(out->release_root, wire + off, 32); off += 32;
    memcpy(out->admission_root, wire + off, 32); off += 32;
    memcpy(out->package_root, wire + off, 32); off += 32;
    memcpy(out->checkpoint_root, wire + off, 32); off += 32;
    memcpy(out->signer_pubkey, wire + off, 32); off += 32;
    memcpy(out->signature, wire + off, 64); off += 64;
    enum vcs_zcode_c23_error error = off == wire_len
        ? vcs_zcode_productivity_receipt_v1_validate(out)
        : VCS_ZCODE_C23_SIZE;
    if (error != VCS_ZCODE_C23_OK) memset(out, 0, sizeof(*out));
    return error;
}

enum vcs_zcode_c23_error vcs_zcode_productivity_receipt_v1_root(
    const struct vcs_zcode_productivity_receipt_v1 *receipt,
    uint8_t out[32])
{
    if (out) memset(out, 0, 32);
    if (!receipt || !out) return VCS_ZCODE_C23_NULL;
    uint8_t wire[VCS_ZCODE_PRODUCTIVITY_RECEIPT_WIRE_BYTES];
    size_t wire_len = 0;
    enum vcs_zcode_c23_error error =
        vcs_zcode_productivity_receipt_v1_encode(
            receipt, wire, sizeof(wire), &wire_len);
    if (error != VCS_ZCODE_C23_OK) return error;
    static const char domain[] = VCS_ZCODE_PRODUCTIVITY_RECEIPT_V1_DOMAIN;
    return vcs_signed_evidence_root(domain, sizeof(domain), wire, wire_len,
                                    out)
               ? VCS_ZCODE_C23_OK : VCS_ZCODE_C23_NULL;
}

bool vcs_zcode_productivity_receipt_v1_shareable(
    const struct vcs_zcode_productivity_receipt_v1 *receipt,
    const struct vcs_zcode_productivity_verify_context_v1 *verify)
{
    if (!verify || !verify->prove_chain ||
        vcs_zcode_productivity_receipt_v1_validate(receipt) !=
            VCS_ZCODE_C23_OK ||
        verify->current_height < receipt->completed_height ||
        verify->current_mtp < receipt->completed_mtp)
        return false;
    return verify->prove_chain(verify->prove_chain_ctx, receipt);
}
