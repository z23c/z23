/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Dual-signed verified-byte receipt codec. Pure: no store, book, or
 * network. See vcs/service_receipt.h. */

#include "vcs/service_receipt.h"

#include "base/log_macros.h"
#include "crypto/sha3.h"

#include <secp256k1.h>
#include <string.h>

static const uint8_t receipt_id_domain[] = VCS_SERVICE_RECEIPT_DOMAIN "\0";

static secp256k1_context *receipt_verify_ctx;

static void receipt_verify_ctx_init(void)
{
    if (!receipt_verify_ctx)
        receipt_verify_ctx =
            secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
}

void vcs_service_receipt_id(const struct vcs_service_receipt *receipt,
                            uint8_t id_out[VCS_SERVICE_RECEIPT_ID_BYTES])
{
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    sha3_256_write(&ctx, receipt_id_domain, sizeof(receipt_id_domain));
    sha3_256_write(&ctx, receipt->uploader_pubkey,
                   VCS_SERVICE_RECEIPT_PUBKEY_BYTES);
    sha3_256_write(&ctx, receipt->downloader_pubkey,
                   VCS_SERVICE_RECEIPT_PUBKEY_BYTES);
    sha3_256_write(&ctx, receipt->package_root,
                   VCS_SERVICE_RECEIPT_ROOT_BYTES);
    {
        /* Fixed-width little-endian scalars: no host packing drift. */
        uint8_t buf[8];
        uint64_t u = receipt->verified_bytes;
        for (int i = 0; i < 8; i++) {
            buf[i] = (uint8_t)(u & 0xffu);
            u >>= 8;
        }
        sha3_256_write(&ctx, buf, sizeof(buf));
        int64_t s = receipt->day_start;
        for (int i = 0; i < 8; i++) {
            buf[i] = (uint8_t)((uint64_t)s & 0xffu);
            s >>= 8;
        }
        sha3_256_write(&ctx, buf, sizeof(buf));
        s = receipt->day_end;
        for (int i = 0; i < 8; i++) {
            buf[i] = (uint8_t)((uint64_t)s & 0xffu);
            s >>= 8;
        }
        sha3_256_write(&ctx, buf, sizeof(buf));
    }
    sha3_256_write(&ctx, receipt->session_nonce,
                   VCS_SERVICE_RECEIPT_NONCE_BYTES);
    sha3_256_finalize(&ctx, id_out);
}

enum vcs_service_receipt_error vcs_service_receipt_sign(
    struct vcs_service_receipt *receipt,
    enum vcs_service_receipt_role role, void *secp_sign_ctx,
    const uint8_t secret_key[32])
{
    secp256k1_context *ctx = secp_sign_ctx;
    if (!receipt || !secp_sign_ctx || !secret_key)
        LOG_RETURN(VCS_SERVICE_RECEIPT_ERR_NULL, "vcs.service-receipt",
                   "sign: null argument role=%d", (int)role);

    uint8_t id[VCS_SERVICE_RECEIPT_ID_BYTES];
    vcs_service_receipt_id(receipt, id);

    secp256k1_ecdsa_signature sig;
    if (secp256k1_ecdsa_sign(ctx, &sig, id, secret_key, NULL, NULL) != 1)
        LOG_RETURN(VCS_SERVICE_RECEIPT_ERR_SIGN, "vcs.service-receipt",
                   "sign: secp256k1 refused (bad secret?)");

    uint8_t *out = role == VCS_SERVICE_RECEIPT_UPLOADER
                       ? receipt->uploader_signature
                       : receipt->downloader_signature;
    if (secp256k1_ecdsa_signature_serialize_compact(ctx, out, &sig) != 1)
        LOG_RETURN(VCS_SERVICE_RECEIPT_ERR_SIGN, "vcs.service-receipt",
                   "sign: compact serialize failed");

    /* Force low-S so both signatures are canonical like release ones. */
    secp256k1_ecdsa_signature normalized;
    if (!secp256k1_ecdsa_signature_parse_compact(ctx, &normalized, out))
        LOG_RETURN(VCS_SERVICE_RECEIPT_ERR_SIGN, "vcs.service-receipt",
                   "sign: compact reparse failed");
    secp256k1_ecdsa_signature_normalize(ctx, &normalized, &normalized);
    if (!secp256k1_ecdsa_signature_serialize_compact(ctx, out,
                                                     &normalized))
        LOG_RETURN(VCS_SERVICE_RECEIPT_ERR_SIGN, "vcs.service-receipt",
                   "sign: normalized serialize failed");
    return VCS_SERVICE_RECEIPT_OK;
}

static const uint8_t receipt_half_order[32] = {
    0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d,
    0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b, 0x20, 0xa0,
};

/* s (big-endian, second half of the compact signature) must be <= n/2. */
static bool receipt_low_s(
    const uint8_t signature[VCS_SERVICE_RECEIPT_SIG_BYTES])
{
    return memcmp(signature + 32, receipt_half_order,
                  sizeof(receipt_half_order)) <= 0;
}

static enum vcs_service_receipt_error receipt_fields_valid(
    const struct vcs_service_receipt *r)
{
    receipt_verify_ctx_init();
    secp256k1_pubkey up, down;
    if (!secp256k1_ec_pubkey_parse(receipt_verify_ctx, &up,
                                   r->uploader_pubkey,
                                   VCS_SERVICE_RECEIPT_PUBKEY_BYTES))
        return VCS_SERVICE_RECEIPT_ERR_PUBKEY;
    if (!secp256k1_ec_pubkey_parse(receipt_verify_ctx, &down,
                                   r->downloader_pubkey,
                                   VCS_SERVICE_RECEIPT_PUBKEY_BYTES))
        return VCS_SERVICE_RECEIPT_ERR_PUBKEY;
    if (memcmp(r->uploader_pubkey, r->downloader_pubkey,
               VCS_SERVICE_RECEIPT_PUBKEY_BYTES) == 0)
        return VCS_SERVICE_RECEIPT_ERR_PUBKEY;
    if (r->verified_bytes == 0 || r->day_start > r->day_end)
        return VCS_SERVICE_RECEIPT_ERR_ARGS;
    bool all_zero = true;
    for (size_t i = 0; i < VCS_SERVICE_RECEIPT_NONCE_BYTES; i++)
        if (r->session_nonce[i] != 0) {
            all_zero = false;
            break;
        }
    if (all_zero)
        return VCS_SERVICE_RECEIPT_ERR_ARGS;
    return VCS_SERVICE_RECEIPT_OK;
}

enum vcs_service_receipt_error vcs_service_receipt_serialize(
    const struct vcs_service_receipt *r, uint8_t *out, size_t cap)
{
    if (!r || !out)
        LOG_RETURN(VCS_SERVICE_RECEIPT_ERR_NULL, "vcs.service-receipt",
                   "serialize: null argument");
    if (cap < VCS_SERVICE_RECEIPT_WIRE_BYTES)
        LOG_RETURN(VCS_SERVICE_RECEIPT_ERR_WIRE, "vcs.service-receipt",
                   "serialize: cap %zu < %u", cap,
                   (unsigned)VCS_SERVICE_RECEIPT_WIRE_BYTES);

    size_t off = 0;
    memcpy(out + off, VCS_SERVICE_RECEIPT_MAGIC, 4);
    off += 4;
    memcpy(out + off, r->uploader_pubkey,
           VCS_SERVICE_RECEIPT_PUBKEY_BYTES);
    off += VCS_SERVICE_RECEIPT_PUBKEY_BYTES;
    memcpy(out + off, r->downloader_pubkey,
           VCS_SERVICE_RECEIPT_PUBKEY_BYTES);
    off += VCS_SERVICE_RECEIPT_PUBKEY_BYTES;
    memcpy(out + off, r->package_root, VCS_SERVICE_RECEIPT_ROOT_BYTES);
    off += VCS_SERVICE_RECEIPT_ROOT_BYTES;
    uint64_t u = r->verified_bytes;
    for (int i = 0; i < 8; i++) {
        out[off + i] = (uint8_t)(u & 0xffu);
        u >>= 8;
    }
    off += 8;
    int64_t s = r->day_start;
    for (int i = 0; i < 8; i++) {
        out[off + i] = (uint8_t)((uint64_t)s & 0xffu);
        s >>= 8;
    }
    off += 8;
    s = r->day_end;
    for (int i = 0; i < 8; i++) {
        out[off + i] = (uint8_t)((uint64_t)s & 0xffu);
        s >>= 8;
    }
    off += 8;
    memcpy(out + off, r->session_nonce,
           VCS_SERVICE_RECEIPT_NONCE_BYTES);
    off += VCS_SERVICE_RECEIPT_NONCE_BYTES;
    memcpy(out + off, r->uploader_signature,
           VCS_SERVICE_RECEIPT_SIG_BYTES);
    off += VCS_SERVICE_RECEIPT_SIG_BYTES;
    memcpy(out + off, r->downloader_signature,
           VCS_SERVICE_RECEIPT_SIG_BYTES);
    return VCS_SERVICE_RECEIPT_OK;
}

enum vcs_service_receipt_error vcs_service_receipt_parse(
    const uint8_t *wire, size_t len, struct vcs_service_receipt *out)
{
    if (!wire || !out)
        LOG_RETURN(VCS_SERVICE_RECEIPT_ERR_NULL, "vcs.service-receipt",
                   "parse: null argument");
    memset(out, 0, sizeof(*out));
    if (len != VCS_SERVICE_RECEIPT_WIRE_BYTES ||
        memcmp(wire, VCS_SERVICE_RECEIPT_MAGIC, 4) != 0)
        LOG_RETURN(VCS_SERVICE_RECEIPT_ERR_WIRE, "vcs.service-receipt",
                   "parse: len %zu magic mismatch", len);

    size_t off = 4;
    memcpy(out->uploader_pubkey, wire + off,
           VCS_SERVICE_RECEIPT_PUBKEY_BYTES);
    off += VCS_SERVICE_RECEIPT_PUBKEY_BYTES;
    memcpy(out->downloader_pubkey, wire + off,
           VCS_SERVICE_RECEIPT_PUBKEY_BYTES);
    off += VCS_SERVICE_RECEIPT_PUBKEY_BYTES;
    memcpy(out->package_root, wire + off,
           VCS_SERVICE_RECEIPT_ROOT_BYTES);
    off += VCS_SERVICE_RECEIPT_ROOT_BYTES;
    uint64_t u = 0;
    for (int i = 7; i >= 0; i--)
        u = (u << 8) | wire[off + i];
    out->verified_bytes = u;
    off += 8;
    uint64_t d0 = 0;
    uint64_t d1 = 0;
    for (int i = 7; i >= 0; i--)
        d0 = (d0 << 8) | wire[off + i];
    out->day_start = (int64_t)d0;
    off += 8;
    for (int i = 7; i >= 0; i--)
        d1 = (d1 << 8) | wire[off + i];
    out->day_end = (int64_t)d1;
    off += 8;
    memcpy(out->session_nonce, wire + off,
           VCS_SERVICE_RECEIPT_NONCE_BYTES);
    off += VCS_SERVICE_RECEIPT_NONCE_BYTES;
    memcpy(out->uploader_signature, wire + off,
           VCS_SERVICE_RECEIPT_SIG_BYTES);
    off += VCS_SERVICE_RECEIPT_SIG_BYTES;
    memcpy(out->downloader_signature, wire + off,
           VCS_SERVICE_RECEIPT_SIG_BYTES);
    return receipt_fields_valid(out);
}

enum vcs_service_receipt_error vcs_service_receipt_verify(
    const uint8_t *wire, size_t len, struct vcs_service_receipt *out)
{
    struct vcs_service_receipt tmp;
    enum vcs_service_receipt_error e =
        vcs_service_receipt_parse(wire, len, &tmp);
    if (e != VCS_SERVICE_RECEIPT_OK)
        return e;

    uint8_t id[VCS_SERVICE_RECEIPT_ID_BYTES];
    vcs_service_receipt_id(&tmp, id);

    receipt_verify_ctx_init();
    const uint8_t *pubkeys[2] = {tmp.uploader_pubkey,
                                 tmp.downloader_pubkey};
    const uint8_t *signatures[2] = {tmp.uploader_signature,
                                    tmp.downloader_signature};
    for (size_t p = 0; p < 2; p++) {
        if (!receipt_low_s(signatures[p]))
            LOG_RETURN(VCS_SERVICE_RECEIPT_ERR_SIG_LOW_S,
                       "vcs.service-receipt",
                       "verify: party %zu signature not low-S", p);
        secp256k1_pubkey pubkey;
        if (!secp256k1_ec_pubkey_parse(receipt_verify_ctx, &pubkey,
                                       pubkeys[p],
                                       VCS_SERVICE_RECEIPT_PUBKEY_BYTES))
            return VCS_SERVICE_RECEIPT_ERR_PUBKEY;
        secp256k1_ecdsa_signature sig;
        if (!secp256k1_ecdsa_signature_parse_compact(
                receipt_verify_ctx, &sig, signatures[p]))
            return VCS_SERVICE_RECEIPT_ERR_SIG_VERIFY;
        if (!secp256k1_ecdsa_verify(receipt_verify_ctx, &sig, id,
                                    &pubkey))
            LOG_RETURN(VCS_SERVICE_RECEIPT_ERR_SIG_VERIFY,
                       "vcs.service-receipt",
                       "verify: party %zu signature does not verify", p);
    }
    if (out)
        *out = tmp;
    return VCS_SERVICE_RECEIPT_OK;
}

enum vcs_service_receipt_error vcs_service_receipt_verify_role(
    const struct vcs_service_receipt *receipt,
    enum vcs_service_receipt_role role)
{
    if (!receipt)
        LOG_RETURN(VCS_SERVICE_RECEIPT_ERR_NULL, "vcs.service-receipt",
                   "verify_role: null receipt");
    const uint8_t *pub = role == VCS_SERVICE_RECEIPT_UPLOADER
                             ? receipt->uploader_pubkey
                             : receipt->downloader_pubkey;
    const uint8_t *sig = role == VCS_SERVICE_RECEIPT_UPLOADER
                             ? receipt->uploader_signature
                             : receipt->downloader_signature;
    bool any = false;
    for (size_t i = 0; i < VCS_SERVICE_RECEIPT_SIG_BYTES; i++)
        if (sig[i] != 0) {
            any = true;
            break;
        }
    if (!any)
        LOG_RETURN(VCS_SERVICE_RECEIPT_ERR_SIG_VERIFY, "vcs.service-receipt",
                   "verify_role: missing signature role=%d", (int)role);
    if (!receipt_low_s(sig))
        LOG_RETURN(VCS_SERVICE_RECEIPT_ERR_SIG_LOW_S, "vcs.service-receipt",
                   "verify_role: signature not low-S role=%d", (int)role);
    uint8_t id[VCS_SERVICE_RECEIPT_ID_BYTES];
    vcs_service_receipt_id(receipt, id);
    receipt_verify_ctx_init();
    secp256k1_pubkey pubkey;
    if (!secp256k1_ec_pubkey_parse(receipt_verify_ctx, &pubkey, pub,
                                   VCS_SERVICE_RECEIPT_PUBKEY_BYTES))
        return VCS_SERVICE_RECEIPT_ERR_PUBKEY;
    secp256k1_ecdsa_signature parsed;
    if (!secp256k1_ecdsa_signature_parse_compact(receipt_verify_ctx, &parsed,
                                                 sig))
        return VCS_SERVICE_RECEIPT_ERR_SIG_VERIFY;
    if (!secp256k1_ecdsa_verify(receipt_verify_ctx, &parsed, id, &pubkey))
        LOG_RETURN(VCS_SERVICE_RECEIPT_ERR_SIG_VERIFY, "vcs.service-receipt",
                   "verify_role: signature does not verify role=%d",
                   (int)role);
    return VCS_SERVICE_RECEIPT_OK;
}
