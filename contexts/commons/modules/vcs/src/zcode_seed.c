/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: canonical dual-signed c23.seed.v1 credential and maturity gate. */
#include "vcs/zcode_seed.h"

#include "base/bytes.h"
#include "base/checked.h"
#include "codec/cursor.h"
#include "crypto/ed25519.h"
#include "vcs/signed_evidence.h"

#include <secp256k1.h>
#include <string.h>

static const uint8_t seed_magic[8] =
    {'C','2','3','S','E','E','D','\n'};

static secp256k1_context *seed_ctx;

__attribute__((constructor))
static void seed_ctx_init(void)
{
    seed_ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN |
                                        SECP256K1_CONTEXT_VERIFY);
}

__attribute__((destructor))
static void seed_ctx_destroy(void)
{
    if (seed_ctx) secp256k1_context_destroy(seed_ctx);
}

static const uint8_t seed_half_order[32] = {
    0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d,
    0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b, 0x20, 0xa0,
};

static bool seed_pubkey_valid(const uint8_t pubkey[33])
{
    secp256k1_pubkey parsed;
    return pubkey && seed_ctx &&
        secp256k1_ec_pubkey_parse(seed_ctx, &parsed, pubkey, 33) == 1;
}

static bool seed_signature_low_s(const uint8_t signature[64])
{
    return memcmp(signature + 32, seed_half_order,
                  sizeof(seed_half_order)) <= 0;
}

const char *vcs_c23_seed_error_string(enum vcs_c23_seed_error error)
{
    switch (error) {
    case VCS_C23_SEED_OK: return "ok";
    case VCS_C23_SEED_ERR_NULL: return "null";
    case VCS_C23_SEED_ERR_VERSION: return "version";
    case VCS_C23_SEED_ERR_FLAGS: return "flags";
    case VCS_C23_SEED_ERR_SOURCE_CLASSIFICATION:
        return "source_classification";
    case VCS_C23_SEED_ERR_ROOT: return "root";
    case VCS_C23_SEED_ERR_PUBKEY: return "pubkey";
    case VCS_C23_SEED_ERR_ORDER: return "order";
    case VCS_C23_SEED_ERR_TIME: return "time";
    case VCS_C23_SEED_ERR_SEQUENCE: return "sequence";
    case VCS_C23_SEED_ERR_WIRE_SIZE: return "wire_size";
    case VCS_C23_SEED_ERR_MAGIC: return "magic";
    case VCS_C23_SEED_ERR_RESERVED: return "reserved";
    case VCS_C23_SEED_ERR_SIGNATURE: return "signature";
    case VCS_C23_SEED_ERR_KEY_MISMATCH: return "key_mismatch";
    case VCS_C23_SEED_ERR_OVERFLOW: return "overflow";
    case VCS_C23_SEED_ERR_IMMATURE: return "immature";
    case VCS_C23_SEED_ERR_REORG: return "reorg";
    }
    return "unknown";
}

static enum vcs_c23_seed_error seed_fields(
    const struct vcs_c23_seed_v1 *seed, bool require_signatures)
{
    if (!seed) return VCS_C23_SEED_ERR_NULL;
    if (seed->schema_version != VCS_C23_SEED_VERSION)
        return VCS_C23_SEED_ERR_VERSION;
    if (seed->flags != VCS_C23_SEED_REQUIRED_FLAGS)
        return VCS_C23_SEED_ERR_FLAGS;
    if (seed->source_flags != 0)
        return VCS_C23_SEED_ERR_SOURCE_CLASSIFICATION;
    const uint8_t *const roots[] = {
        seed->network_genesis_root, seed->contributor_binding_root,
        seed->package_root, seed->release_root,
        seed->dependency_lock_root, seed->license_evidence_root,
        seed->semantic_fingerprint_root, seed->novelty_evidence_root,
        seed->target_capsule_root, seed->compiler_capsule_roots[0],
        seed->compiler_capsule_roots[1], seed->build_report_roots[0],
        seed->build_report_roots[1], seed->dht_replication_root,
        seed->challenge_opening_hash,
    };
    for (size_t i = 0; i < sizeof(roots) / sizeof(roots[0]); i++)
        if (!zcl_bytes_any_set(roots[i], 32)) return VCS_C23_SEED_ERR_ROOT;
    if (!zcl_bytes_any_set(seed->zid_pubkey, 32) ||
        !seed_pubkey_valid(seed->zcl_pubkey))
        return VCS_C23_SEED_ERR_PUBKEY;
    if (memcmp(seed->compiler_capsule_roots[0],
               seed->compiler_capsule_roots[1], 32) >= 0 ||
        memcmp(seed->build_report_roots[0],
               seed->build_report_roots[1], 32) == 0)
        return VCS_C23_SEED_ERR_ORDER;
    if (seed->challenge_opening_height == 0 ||
        seed->challenge_opening_mtp <= 0 ||
        seed->created_unix < seed->challenge_opening_mtp)
        return VCS_C23_SEED_ERR_TIME;
    if (seed->sequence == 0) return VCS_C23_SEED_ERR_SEQUENCE;
    if (require_signatures) {
        if (!zcl_bytes_any_set(seed->zid_signature,
                          sizeof(seed->zid_signature)) ||
            !zcl_bytes_any_set(seed->zcl_signature,
                          sizeof(seed->zcl_signature)) ||
            !seed_signature_low_s(seed->zcl_signature))
            return VCS_C23_SEED_ERR_SIGNATURE;
    }
    return VCS_C23_SEED_OK;
}

enum vcs_c23_seed_error vcs_c23_seed_validate(
    const struct vcs_c23_seed_v1 *seed)
{
    return seed_fields(seed, true);
}

static enum vcs_c23_seed_error seed_body(
    const struct vcs_c23_seed_v1 *seed,
    uint8_t out[VCS_C23_SEED_BODY_BYTES])
{
    if (!out) return VCS_C23_SEED_ERR_NULL;
    enum vcs_c23_seed_error error = seed_fields(seed, false);
    if (error != VCS_C23_SEED_OK) return error;
    struct zcl_codec_writer writer;
    zcl_codec_writer_init(&writer, out, VCS_C23_SEED_BODY_BYTES);
    bool ok = zcl_codec_write_bytes(&writer, seed_magic, 8) &&
        zcl_codec_write_u16le(&writer, seed->schema_version) &&
        zcl_codec_write_u16le(&writer, seed->flags) &&
        zcl_codec_write_u16le(&writer, seed->source_flags) &&
        zcl_codec_write_u16le(&writer, 0) &&
        zcl_codec_write_bytes(&writer, seed->network_genesis_root, 32) &&
        zcl_codec_write_bytes(&writer, seed->contributor_binding_root, 32) &&
        zcl_codec_write_bytes(&writer, seed->zid_pubkey, 32) &&
        zcl_codec_write_bytes(&writer, seed->zcl_pubkey, 33) &&
        zcl_codec_write_bytes(&writer, seed->package_root, 32) &&
        zcl_codec_write_bytes(&writer, seed->release_root, 32) &&
        zcl_codec_write_bytes(&writer, seed->dependency_lock_root, 32) &&
        zcl_codec_write_bytes(&writer, seed->license_evidence_root, 32) &&
        zcl_codec_write_bytes(&writer, seed->semantic_fingerprint_root, 32) &&
        zcl_codec_write_bytes(&writer, seed->novelty_evidence_root, 32) &&
        zcl_codec_write_bytes(&writer, seed->target_capsule_root, 32) &&
        zcl_codec_write_bytes(&writer, seed->compiler_capsule_roots[0], 32) &&
        zcl_codec_write_bytes(&writer, seed->compiler_capsule_roots[1], 32) &&
        zcl_codec_write_bytes(&writer, seed->build_report_roots[0], 32) &&
        zcl_codec_write_bytes(&writer, seed->build_report_roots[1], 32) &&
        zcl_codec_write_bytes(&writer, seed->dht_replication_root, 32) &&
        zcl_codec_write_u64le(&writer, seed->challenge_opening_height) &&
        zcl_codec_write_bytes(&writer, seed->challenge_opening_hash, 32) &&
        zcl_codec_write_i64le(&writer, seed->challenge_opening_mtp) &&
        zcl_codec_write_i64le(&writer, seed->created_unix) &&
        zcl_codec_write_u64le(&writer, seed->sequence);
    size_t written = 0;
    return ok && zcl_codec_writer_finish(&writer, &written) &&
           written == VCS_C23_SEED_BODY_BYTES
        ? VCS_C23_SEED_OK : VCS_C23_SEED_ERR_WIRE_SIZE;
}

enum vcs_c23_seed_error vcs_c23_seed_body_root(
    const struct vcs_c23_seed_v1 *seed, uint8_t out[32])
{
    if (out) memset(out, 0, 32);
    if (!out) return VCS_C23_SEED_ERR_NULL;
    uint8_t body[VCS_C23_SEED_BODY_BYTES];
    enum vcs_c23_seed_error error = seed_body(seed, body);
    if (error != VCS_C23_SEED_OK) return error;
    static const char domain[] = VCS_C23_SEED_BODY_DOMAIN;
    return vcs_signed_evidence_root(
               domain, sizeof(domain), body, sizeof(body), out)
        ? VCS_C23_SEED_OK : VCS_C23_SEED_ERR_NULL;
}

enum vcs_c23_seed_error vcs_c23_seed_serialize(
    const struct vcs_c23_seed_v1 *seed,
    uint8_t out[VCS_C23_SEED_WIRE_BYTES])
{
    if (!out) return VCS_C23_SEED_ERR_NULL;
    enum vcs_c23_seed_error error = vcs_c23_seed_validate(seed);
    if (error != VCS_C23_SEED_OK) return error;
    error = seed_body(seed, out);
    if (error != VCS_C23_SEED_OK) return error;
    memcpy(out + VCS_C23_SEED_BODY_BYTES, seed->zid_signature, 64);
    memcpy(out + VCS_C23_SEED_BODY_BYTES + 64, seed->zcl_signature, 64);
    return VCS_C23_SEED_OK;
}

enum vcs_c23_seed_error vcs_c23_seed_parse(
    const uint8_t *wire, size_t wire_len, struct vcs_c23_seed_v1 *out)
{
    if (out) memset(out, 0, sizeof(*out));
    if (!wire || !out) return VCS_C23_SEED_ERR_NULL;
    if (wire_len != VCS_C23_SEED_WIRE_BYTES)
        return VCS_C23_SEED_ERR_WIRE_SIZE;
    struct vcs_c23_seed_v1 parsed;
    memset(&parsed, 0, sizeof(parsed));
    struct zcl_codec_reader reader;
    zcl_codec_reader_init(&reader, wire, wire_len);
    uint8_t magic[8]; uint16_t reserved = 0;
    bool ok = zcl_codec_read_bytes(&reader, magic, 8) &&
        zcl_codec_read_u16le(&reader, &parsed.schema_version) &&
        zcl_codec_read_u16le(&reader, &parsed.flags) &&
        zcl_codec_read_u16le(&reader, &parsed.source_flags) &&
        zcl_codec_read_u16le(&reader, &reserved) &&
        zcl_codec_read_bytes(&reader, parsed.network_genesis_root, 32) &&
        zcl_codec_read_bytes(&reader, parsed.contributor_binding_root, 32) &&
        zcl_codec_read_bytes(&reader, parsed.zid_pubkey, 32) &&
        zcl_codec_read_bytes(&reader, parsed.zcl_pubkey, 33) &&
        zcl_codec_read_bytes(&reader, parsed.package_root, 32) &&
        zcl_codec_read_bytes(&reader, parsed.release_root, 32) &&
        zcl_codec_read_bytes(&reader, parsed.dependency_lock_root, 32) &&
        zcl_codec_read_bytes(&reader, parsed.license_evidence_root, 32) &&
        zcl_codec_read_bytes(&reader, parsed.semantic_fingerprint_root, 32) &&
        zcl_codec_read_bytes(&reader, parsed.novelty_evidence_root, 32) &&
        zcl_codec_read_bytes(&reader, parsed.target_capsule_root, 32) &&
        zcl_codec_read_bytes(&reader, parsed.compiler_capsule_roots[0], 32) &&
        zcl_codec_read_bytes(&reader, parsed.compiler_capsule_roots[1], 32) &&
        zcl_codec_read_bytes(&reader, parsed.build_report_roots[0], 32) &&
        zcl_codec_read_bytes(&reader, parsed.build_report_roots[1], 32) &&
        zcl_codec_read_bytes(&reader, parsed.dht_replication_root, 32) &&
        zcl_codec_read_u64le(&reader, &parsed.challenge_opening_height) &&
        zcl_codec_read_bytes(&reader, parsed.challenge_opening_hash, 32) &&
        zcl_codec_read_i64le(&reader, &parsed.challenge_opening_mtp) &&
        zcl_codec_read_i64le(&reader, &parsed.created_unix) &&
        zcl_codec_read_u64le(&reader, &parsed.sequence) &&
        zcl_codec_read_bytes(&reader, parsed.zid_signature, 64) &&
        zcl_codec_read_bytes(&reader, parsed.zcl_signature, 64) &&
        zcl_codec_reader_finish(&reader);
    if (!ok) return VCS_C23_SEED_ERR_WIRE_SIZE;
    if (memcmp(magic, seed_magic, 8) != 0) return VCS_C23_SEED_ERR_MAGIC;
    if (reserved != 0) return VCS_C23_SEED_ERR_RESERVED;
    enum vcs_c23_seed_error error = vcs_c23_seed_validate(&parsed);
    if (error != VCS_C23_SEED_OK) return error;
    *out = parsed;
    return VCS_C23_SEED_OK;
}

enum vcs_c23_seed_error vcs_c23_seed_root(
    const struct vcs_c23_seed_v1 *seed, uint8_t out[32])
{
    if (out) memset(out, 0, 32);
    if (!out) return VCS_C23_SEED_ERR_NULL;
    uint8_t wire[VCS_C23_SEED_WIRE_BYTES];
    enum vcs_c23_seed_error error = vcs_c23_seed_serialize(seed, wire);
    if (error != VCS_C23_SEED_OK) return error;
    static const char domain[] = VCS_C23_SEED_DOMAIN;
    return vcs_signed_evidence_root(
               domain, sizeof(domain), wire, sizeof(wire), out)
        ? VCS_C23_SEED_OK : VCS_C23_SEED_ERR_NULL;
}

enum vcs_c23_seed_error vcs_c23_seed_seal(
    struct vcs_c23_seed_v1 *seed, const uint8_t zid_secret[32],
    const uint8_t zid_pubkey[32], const uint8_t zcl_secret[32])
{
    if (!seed || !zid_secret || !zid_pubkey || !zcl_secret)
        return VCS_C23_SEED_ERR_NULL;
    uint8_t derived_zid[32], derived_secret[32];
    ed25519_keypair(derived_zid, derived_secret, zid_secret);
    if (memcmp(derived_zid, zid_pubkey, 32) != 0 ||
        memcmp(seed->zid_pubkey, zid_pubkey, 32) != 0)
        return VCS_C23_SEED_ERR_KEY_MISMATCH;
    secp256k1_pubkey derived;
    if (!seed_ctx || !secp256k1_ec_pubkey_create(
            seed_ctx, &derived, zcl_secret))
        return VCS_C23_SEED_ERR_PUBKEY;
    uint8_t serialized[33]; size_t serialized_len = sizeof(serialized);
    (void)secp256k1_ec_pubkey_serialize(
        seed_ctx, serialized, &serialized_len, &derived,
        SECP256K1_EC_COMPRESSED);
    if (serialized_len != sizeof(serialized) ||
        memcmp(serialized, seed->zcl_pubkey, sizeof(serialized)) != 0)
        return VCS_C23_SEED_ERR_KEY_MISMATCH;
    enum vcs_c23_seed_error error = seed_fields(seed, false);
    if (error != VCS_C23_SEED_OK) return error;
    uint8_t root[32];
    error = vcs_c23_seed_body_root(seed, root);
    if (error != VCS_C23_SEED_OK) return error;
    if (!vcs_signed_evidence_seal_root(
            root, zid_secret, zid_pubkey, seed->zid_signature))
        return VCS_C23_SEED_ERR_NULL;
    secp256k1_ecdsa_signature signature;
    if (!secp256k1_ecdsa_sign(seed_ctx, &signature, root, zcl_secret,
                              NULL, NULL))
        return VCS_C23_SEED_ERR_SIGNATURE;
    (void)secp256k1_ecdsa_signature_normalize(seed_ctx, &signature,
                                              &signature);
    (void)secp256k1_ecdsa_signature_serialize_compact(
        seed_ctx, seed->zcl_signature, &signature);
    return vcs_c23_seed_validate(seed);
}

enum vcs_c23_seed_error vcs_c23_seed_verify(
    const struct vcs_c23_seed_v1 *seed)
{
    enum vcs_c23_seed_error error = vcs_c23_seed_validate(seed);
    if (error != VCS_C23_SEED_OK) return error;
    uint8_t root[32];
    error = vcs_c23_seed_body_root(seed, root);
    if (error != VCS_C23_SEED_OK) return error;
    if (!vcs_signed_evidence_verify_root(
            root, seed->zid_signature, seed->zid_pubkey,
            seed->zid_pubkey))
        return VCS_C23_SEED_ERR_SIGNATURE;
    secp256k1_pubkey pubkey;
    secp256k1_ecdsa_signature signature;
    if (!secp256k1_ec_pubkey_parse(seed_ctx, &pubkey, seed->zcl_pubkey, 33) ||
        !secp256k1_ecdsa_signature_parse_compact(
            seed_ctx, &signature, seed->zcl_signature) ||
        !secp256k1_ecdsa_verify(seed_ctx, &signature, root, &pubkey))
        return VCS_C23_SEED_ERR_SIGNATURE;
    return VCS_C23_SEED_OK;
}

enum vcs_c23_seed_error vcs_c23_seed_maturity(
    const struct vcs_c23_seed_v1 *seed, uint64_t active_height,
    int64_t active_mtp, vcs_c23_seed_anchor_active_fn anchor_is_active,
    void *opaque, uint64_t *maturity_height_out,
    int64_t *maturity_mtp_out)
{
    if (maturity_height_out) *maturity_height_out = 0;
    if (maturity_mtp_out) *maturity_mtp_out = 0;
    if (!seed || !anchor_is_active || !maturity_height_out ||
        !maturity_mtp_out)
        return VCS_C23_SEED_ERR_NULL;
    enum vcs_c23_seed_error error = vcs_c23_seed_verify(seed);
    if (error != VCS_C23_SEED_OK) return error;
    uint64_t maturity_height = 0;
    if (!zcl_u64_add(seed->challenge_opening_height,
                     VCS_C23_SEED_CHALLENGE_BLOCKS, &maturity_height) ||
        seed->challenge_opening_mtp >
            INT64_MAX - VCS_C23_SEED_CHALLENGE_SECONDS)
        return VCS_C23_SEED_ERR_OVERFLOW;
    int64_t maturity_mtp = seed->challenge_opening_mtp +
                           VCS_C23_SEED_CHALLENGE_SECONDS;
    if (!anchor_is_active(opaque, seed->challenge_opening_height,
                          seed->challenge_opening_hash))
        return VCS_C23_SEED_ERR_REORG;
    if (active_height < maturity_height || active_mtp < maturity_mtp)
        return VCS_C23_SEED_ERR_IMMATURE;
    *maturity_height_out = maturity_height;
    *maturity_mtp_out = maturity_mtp;
    return VCS_C23_SEED_OK;
}
