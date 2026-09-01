/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: contributor_binding.v1 (frozen) and contributor_binding.v2
 * (three-signature rotation + delayed recovery) implementation. See
 * vcs/zcode_contributor_binding.h for the wire layout and semantics. */

#include "vcs/zcode_contributor_binding.h"

#include "base/bytes.h"
#include "base/serialize_le.h"
#include "core/hash.h"
#include "crypto/ed25519.h"
#include "vcs/signed_evidence.h"

#include <secp256k1.h>
#include <string.h>

static const uint8_t binding_magic[8] = {'Z','C','B','I','N','D','\r','\n'};

/* The vendored libsecp256k1 archive does not export the
 * secp256k1_context_static symbol, so this layer keeps its own context,
 * created once at load time — the same pattern as
 * contexts/commons/modules/vcs/src/package_release.c. Seal needs SIGN; verify needs VERIFY. */
static secp256k1_context *binding_ctx;

__attribute__((constructor))
static void binding_ctx_init(void)
{
    binding_ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN |
                                           SECP256K1_CONTEXT_VERIFY);
}

__attribute__((destructor))
static void binding_ctx_destroy(void)
{
    if (binding_ctx)
        secp256k1_context_destroy(binding_ctx);
}

/* secp256k1 group order half, n/2, big-endian: the low-S bound. A canonical
 * v1 signature carries s <= n/2; anything above is a malleated encoding. */
static const uint8_t binding_half_order[32] = {
    0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d,
    0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b, 0x20, 0xa0,
};

static bool root_nonzero(const uint8_t root[32])
{
    return zcl_bytes_any_set(root, 32);
}

static void put_bytes(uint8_t *wire, size_t *off, const void *src, size_t len)
{
    memcpy(wire + *off, src, len);
    *off += len;
}

static void put_u16(uint8_t *wire, size_t *off, uint16_t value)
{
    zcl_write_u16_le(wire + *off, value);
    *off += 2;
}

static void put_u64(uint8_t *wire, size_t *off, uint64_t value)
{
    zcl_write_u64_le(wire + *off, value);
    *off += 8;
}

static void get_bytes(const uint8_t *wire, size_t *off, void *out, size_t len)
{
    memcpy(out, wire + *off, len);
    *off += len;
}

static uint16_t get_u16(const uint8_t *wire, size_t *off)
{
    uint16_t value = zcl_read_u16_le(wire + *off);
    *off += 2;
    return value;
}

static uint64_t get_u64(const uint8_t *wire, size_t *off)
{
    uint64_t value = zcl_read_u64_le(wire + *off);
    *off += 8;
    return value;
}

/* s (big-endian, second half of the compact signature) must be <= n/2. */
static bool binding_signature_low_s(const uint8_t signature[64])
{
    return memcmp(signature + 32, binding_half_order,
                  sizeof(binding_half_order)) <= 0;
}

static bool binding_zcl_pubkey_valid(const uint8_t pubkey[33])
{
    secp256k1_pubkey parsed;
    return pubkey &&
           secp256k1_ec_pubkey_parse(binding_ctx, &parsed, pubkey, 33) == 1;
}

const char *vcs_zcode_binding_error_string(enum vcs_zcode_binding_error error)
{
    switch (error) {
    case VCS_ZCODE_BINDING_OK: return "ok";
    case VCS_ZCODE_BINDING_ERR_NULL: return "null-argument";
    case VCS_ZCODE_BINDING_ERR_VERSION: return "schema-version";
    case VCS_ZCODE_BINDING_ERR_WIRE_SIZE: return "wire-size";
    case VCS_ZCODE_BINDING_ERR_WIRE_MAGIC: return "wire-magic";
    case VCS_ZCODE_BINDING_ERR_ROOT_ZERO: return "root-zero";
    case VCS_ZCODE_BINDING_ERR_PUBKEY_ZERO: return "pubkey-zero";
    case VCS_ZCODE_BINDING_ERR_PUBKEY_INVALID: return "pubkey-invalid";
    case VCS_ZCODE_BINDING_ERR_KEY_ID_MISMATCH: return "key-id-mismatch";
    case VCS_ZCODE_BINDING_ERR_PREDECESSOR: return "predecessor-invalid";
    case VCS_ZCODE_BINDING_ERR_SEQUENCE: return "sequence-invalid";
    case VCS_ZCODE_BINDING_ERR_OPERATION: return "operation-invalid";
    case VCS_ZCODE_BINDING_ERR_TIME_ORDER: return "time-order-invalid";
    case VCS_ZCODE_BINDING_ERR_SIGNATURE: return "signature-invalid";
    case VCS_ZCODE_BINDING_ERR_KEY_MISMATCH: return "key-mismatch";
    case VCS_ZCODE_BINDING_ERR_NETWORK_MISMATCH:
        return "network-genesis-mismatch";
    case VCS_ZCODE_BINDING_ERR_IDENTITY_MISMATCH:
        return "identity-root-mismatch";
    case VCS_ZCODE_BINDING_ERR_EXPIRED: return "object-expired";
    case VCS_ZCODE_BINDING_ERR_REVOKED: return "binding-revoked-terminal";
    case VCS_ZCODE_BINDING_ERR_LINKAGE: return "successor-linkage-invalid";
    case VCS_ZCODE_BINDING_ERR_NOT_YET_VALID: return "not-yet-valid";
    case VCS_ZCODE_BINDING_ERR_RECOVERY_DELAY: return "recovery-delay";
    case VCS_ZCODE_BINDING_ERR_RECOVERY_PENDING: return "recovery-pending";
    case VCS_ZCODE_BINDING_ERR_RETIRED_KEY_REUSE:
        return "retired-key-reuse";
    case VCS_ZCODE_BINDING_ERR_SIG_SLOT: return "signature-slot-invalid";
    }
    return "unknown";
}

static enum vcs_zcode_binding_error binding_fields(
    const struct vcs_zcode_contributor_binding_v1 *binding,
    bool require_signatures)
{
    if (!binding) return VCS_ZCODE_BINDING_ERR_NULL;
    if (binding->schema_version != VCS_ZCODE_CONTRIBUTOR_BINDING_VERSION)
        return VCS_ZCODE_BINDING_ERR_VERSION;
    if (!root_nonzero(binding->network_genesis_root))
        return VCS_ZCODE_BINDING_ERR_ROOT_ZERO;
    if (!root_nonzero(binding->zid_pubkey))
        return VCS_ZCODE_BINDING_ERR_PUBKEY_ZERO;
    if (binding->operation < VCS_ZCODE_BINDING_ACTIVE ||
        binding->operation > VCS_ZCODE_BINDING_REVOKE)
        return VCS_ZCODE_BINDING_ERR_OPERATION;
    if (binding->sequence == 0)
        return VCS_ZCODE_BINDING_ERR_SEQUENCE;
    if (binding->operation == VCS_ZCODE_BINDING_ACTIVE) {
        if (binding->sequence != 1)
            return VCS_ZCODE_BINDING_ERR_SEQUENCE;
        if (root_nonzero(binding->predecessor_root))
            return VCS_ZCODE_BINDING_ERR_PREDECESSOR;
    } else {
        if (binding->sequence == 1)
            return VCS_ZCODE_BINDING_ERR_SEQUENCE;
        if (!root_nonzero(binding->predecessor_root))
            return VCS_ZCODE_BINDING_ERR_PREDECESSOR;
    }
    /* The zcl key must be a real curve point and the key id its hash160.
     * REVOKE keeps the key it retires so the binding stays standalone
     * verifiable; the chain gate — not field validation — is what makes a
     * revoke terminal and bars an implicit replacement key. */
    if (!binding_zcl_pubkey_valid(binding->zcl_pubkey))
        return VCS_ZCODE_BINDING_ERR_PUBKEY_INVALID;
    uint8_t want_key_id[20];
    hash160(binding->zcl_pubkey, sizeof(binding->zcl_pubkey), want_key_id);
    if (memcmp(binding->zcl_key_id, want_key_id, sizeof(want_key_id)) != 0)
        return VCS_ZCODE_BINDING_ERR_KEY_ID_MISMATCH;
    if (binding->issued_unix <= 0 ||
        binding->expires_unix <= binding->issued_unix)
        return VCS_ZCODE_BINDING_ERR_TIME_ORDER;
    if (require_signatures) {
        if (!zcl_bytes_any_set(binding->zid_signature,
                           sizeof(binding->zid_signature)))
            return VCS_ZCODE_BINDING_ERR_SIGNATURE;
        if (!zcl_bytes_any_set(binding->zcl_signature,
                           sizeof(binding->zcl_signature)))
            return VCS_ZCODE_BINDING_ERR_SIGNATURE;
    }
    return VCS_ZCODE_BINDING_OK;
}

enum vcs_zcode_binding_error vcs_zcode_contributor_binding_validate(
    const struct vcs_zcode_contributor_binding_v1 *binding)
{
    return binding_fields(binding, true);
}

enum vcs_zcode_binding_error vcs_zcode_contributor_binding_validate_at(
    const struct vcs_zcode_contributor_binding_v1 *binding, int64_t now_unix)
{
    enum vcs_zcode_binding_error error =
        vcs_zcode_contributor_binding_validate(binding);
    if (error != VCS_ZCODE_BINDING_OK) return error;
    /* A binding is usable only inside [issued_unix, expires_unix): early use
     * is NOT_YET_VALID, use at or after expiry is EXPIRED. */
    if (now_unix < binding->issued_unix)
        return VCS_ZCODE_BINDING_ERR_NOT_YET_VALID;
    if (now_unix >= binding->expires_unix)
        return VCS_ZCODE_BINDING_ERR_EXPIRED;
    return VCS_ZCODE_BINDING_OK;
}

static enum vcs_zcode_binding_error binding_body(
    const struct vcs_zcode_contributor_binding_v1 *binding,
    uint8_t out[VCS_ZCODE_CONTRIBUTOR_BINDING_BODY_BYTES])
{
    enum vcs_zcode_binding_error error = binding_fields(binding, false);
    if (error != VCS_ZCODE_BINDING_OK || !out)
        return out ? error : VCS_ZCODE_BINDING_ERR_NULL;
    size_t off = 0;
    put_bytes(out, &off, binding_magic, sizeof(binding_magic));
    put_u16(out, &off, binding->schema_version);
    put_bytes(out, &off, binding->network_genesis_root, 32);
    put_bytes(out, &off, binding->zid_pubkey, 32);
    put_bytes(out, &off, binding->zcl_pubkey, 33);
    put_bytes(out, &off, binding->zcl_key_id, 20);
    put_bytes(out, &off, binding->predecessor_root, 32);
    put_u64(out, &off, binding->sequence);
    put_u64(out, &off, (uint64_t)binding->issued_unix);
    put_u64(out, &off, (uint64_t)binding->expires_unix);
    out[off++] = binding->operation;
    return off == VCS_ZCODE_CONTRIBUTOR_BINDING_BODY_BYTES
               ? VCS_ZCODE_BINDING_OK : VCS_ZCODE_BINDING_ERR_WIRE_SIZE;
}

enum vcs_zcode_binding_error vcs_zcode_contributor_binding_serialize(
    const struct vcs_zcode_contributor_binding_v1 *binding,
    uint8_t out[VCS_ZCODE_CONTRIBUTOR_BINDING_WIRE_BYTES])
{
    enum vcs_zcode_binding_error error =
        vcs_zcode_contributor_binding_validate(binding);
    if (error != VCS_ZCODE_BINDING_OK || !out)
        return out ? error : VCS_ZCODE_BINDING_ERR_NULL;
    error = binding_body(binding, out);
    if (error != VCS_ZCODE_BINDING_OK) return error;
    memcpy(out + VCS_ZCODE_CONTRIBUTOR_BINDING_BODY_BYTES,
           binding->zid_signature, 64);
    memcpy(out + VCS_ZCODE_CONTRIBUTOR_BINDING_BODY_BYTES + 64,
           binding->zcl_signature, 64);
    return VCS_ZCODE_BINDING_OK;
}

enum vcs_zcode_binding_error vcs_zcode_contributor_binding_parse(
    const uint8_t *wire, size_t len,
    struct vcs_zcode_contributor_binding_v1 *out)
{
    if (!wire || !out) return VCS_ZCODE_BINDING_ERR_NULL;
    memset(out, 0, sizeof(*out));
    if (len != VCS_ZCODE_CONTRIBUTOR_BINDING_WIRE_BYTES)
        return VCS_ZCODE_BINDING_ERR_WIRE_SIZE;
    if (memcmp(wire, binding_magic, sizeof(binding_magic)) != 0)
        return VCS_ZCODE_BINDING_ERR_WIRE_MAGIC;
    size_t off = sizeof(binding_magic);
    out->schema_version = get_u16(wire, &off);
    get_bytes(wire, &off, out->network_genesis_root, 32);
    get_bytes(wire, &off, out->zid_pubkey, 32);
    get_bytes(wire, &off, out->zcl_pubkey, 33);
    get_bytes(wire, &off, out->zcl_key_id, 20);
    get_bytes(wire, &off, out->predecessor_root, 32);
    out->sequence = get_u64(wire, &off);
    out->issued_unix = (int64_t)get_u64(wire, &off);
    out->expires_unix = (int64_t)get_u64(wire, &off);
    out->operation = wire[off++];
    get_bytes(wire, &off, out->zid_signature, 64);
    get_bytes(wire, &off, out->zcl_signature, 64);
    enum vcs_zcode_binding_error error =
        vcs_zcode_contributor_binding_validate(out);
    if (error != VCS_ZCODE_BINDING_OK) memset(out, 0, sizeof(*out));
    return error;
}

enum vcs_zcode_binding_error vcs_zcode_contributor_binding_body_root(
    const struct vcs_zcode_contributor_binding_v1 *binding, uint8_t out[32])
{
    uint8_t body[VCS_ZCODE_CONTRIBUTOR_BINDING_BODY_BYTES];
    enum vcs_zcode_binding_error error = binding_body(binding, body);
    if (error != VCS_ZCODE_BINDING_OK || !out)
        return out ? error : VCS_ZCODE_BINDING_ERR_NULL;
    static const char domain[] = VCS_ZCODE_CONTRIBUTOR_BINDING_DOMAIN;
    return vcs_signed_evidence_root(domain, sizeof(domain), body,
                                    sizeof(body), out)
               ? VCS_ZCODE_BINDING_OK : VCS_ZCODE_BINDING_ERR_NULL;
}

enum vcs_zcode_binding_error vcs_zcode_contributor_binding_root(
    const struct vcs_zcode_contributor_binding_v1 *binding, uint8_t out[32])
{
    uint8_t wire[VCS_ZCODE_CONTRIBUTOR_BINDING_WIRE_BYTES];
    enum vcs_zcode_binding_error error =
        vcs_zcode_contributor_binding_serialize(binding, wire);
    if (error != VCS_ZCODE_BINDING_OK || !out)
        return out ? error : VCS_ZCODE_BINDING_ERR_NULL;
    static const char domain[] = VCS_ZCODE_CONTRIBUTOR_BINDING_ROOT_DOMAIN;
    return vcs_signed_evidence_root(domain, sizeof(domain), wire,
                                    sizeof(wire), out)
               ? VCS_ZCODE_BINDING_OK : VCS_ZCODE_BINDING_ERR_NULL;
}

enum vcs_zcode_binding_error vcs_zcode_contributor_binding_seal(
    struct vcs_zcode_contributor_binding_v1 *binding,
    const uint8_t zid_secret[32], const uint8_t zid_pubkey[32],
    const uint8_t zcl_secret[32])
{
    if (!binding || !zid_secret || !zid_pubkey || !zcl_secret)
        return VCS_ZCODE_BINDING_ERR_NULL;
    if (!root_nonzero(zid_pubkey)) return VCS_ZCODE_BINDING_ERR_PUBKEY_ZERO;
    /* The ZID public key is re-derived from the supplied secret: a secret
     * that does not produce the claimed pubkey must never seal — the
     * resulting signature would be unverifiable garbage under either key. */
    uint8_t zid_derived_pk[32], zid_derived_sk[32];
    ed25519_keypair(zid_derived_pk, zid_derived_sk, zid_secret);
    if (memcmp(zid_derived_pk, zid_pubkey, 32) != 0)
        return VCS_ZCODE_BINDING_ERR_KEY_MISMATCH;
    if (memcmp(binding->zid_pubkey, zid_pubkey, 32) != 0)
        return VCS_ZCODE_BINDING_ERR_KEY_MISMATCH;

    /* The zcl secret must derive the embedded zcl key — a seal under a
     * different key would be an unverifiable binding. */
    secp256k1_pubkey derived;
    if (!secp256k1_ec_pubkey_create(binding_ctx, &derived, zcl_secret))
        return VCS_ZCODE_BINDING_ERR_PUBKEY_INVALID;
    uint8_t derived_ser[33];
    size_t derived_len = sizeof(derived_ser);
    (void)secp256k1_ec_pubkey_serialize(
        binding_ctx, derived_ser, &derived_len, &derived,
        SECP256K1_EC_COMPRESSED);
    if (derived_len != sizeof(binding->zcl_pubkey) ||
        memcmp(binding->zcl_pubkey, derived_ser,
               sizeof(binding->zcl_pubkey)) != 0)
        return VCS_ZCODE_BINDING_ERR_KEY_MISMATCH;

    enum vcs_zcode_binding_error error = binding_fields(binding, false);
    if (error != VCS_ZCODE_BINDING_OK) return error;

    uint8_t root[32];
    error = vcs_zcode_contributor_binding_body_root(binding, root);
    if (error != VCS_ZCODE_BINDING_OK) return error;

    if (!vcs_signed_evidence_seal_root(root, zid_secret, zid_pubkey,
                                       binding->zid_signature))
        return VCS_ZCODE_BINDING_ERR_SIGNATURE;

    secp256k1_ecdsa_signature signature;
    if (!secp256k1_ecdsa_sign(binding_ctx, &signature, root, zcl_secret,
                              NULL, NULL))
        return VCS_ZCODE_BINDING_ERR_SIGNATURE;
    /* Canonicalize to low-S so the sealed wire is byte deterministic. */
    (void)secp256k1_ecdsa_signature_normalize(binding_ctx, &signature,
                                              &signature);
    (void)secp256k1_ecdsa_signature_serialize_compact(
        binding_ctx, binding->zcl_signature, &signature);
    return VCS_ZCODE_BINDING_OK;
}

/* Both signatures over the body root, no expiry gate: the ZID Ed25519
 * signature under the embedded zid_pubkey, then the low-S canonical
 * secp256k1 signature under the embedded zcl_pubkey. */
static enum vcs_zcode_binding_error binding_verify_sigs(
    const struct vcs_zcode_contributor_binding_v1 *binding)
{
    uint8_t root[32];
    enum vcs_zcode_binding_error error =
        vcs_zcode_contributor_binding_body_root(binding, root);
    if (error != VCS_ZCODE_BINDING_OK) return error;

    if (!vcs_signed_evidence_verify_root(root, binding->zid_signature,
                                         binding->zid_pubkey,
                                         binding->zid_pubkey))
        return VCS_ZCODE_BINDING_ERR_SIGNATURE;

    if (!binding_signature_low_s(binding->zcl_signature))
        return VCS_ZCODE_BINDING_ERR_SIGNATURE;
    secp256k1_pubkey pubkey;
    if (!secp256k1_ec_pubkey_parse(binding_ctx, &pubkey, binding->zcl_pubkey,
                                   sizeof(binding->zcl_pubkey)))
        return VCS_ZCODE_BINDING_ERR_PUBKEY_INVALID;
    secp256k1_ecdsa_signature signature;
    (void)secp256k1_ecdsa_signature_parse_compact(binding_ctx, &signature,
                                                  binding->zcl_signature);
    if (!secp256k1_ecdsa_verify(binding_ctx, &signature, root, &pubkey))
        return VCS_ZCODE_BINDING_ERR_SIGNATURE;
    return VCS_ZCODE_BINDING_OK;
}

enum vcs_zcode_binding_error vcs_zcode_contributor_binding_verify(
    const struct vcs_zcode_contributor_binding_v1 *binding,
    const uint8_t expected_network_genesis[32],
    const uint8_t expected_zid_pubkey[32], int64_t now_unix)
{
    enum vcs_zcode_binding_error error =
        vcs_zcode_contributor_binding_validate_at(binding, now_unix);
    if (error != VCS_ZCODE_BINDING_OK) return error;
    if (!expected_network_genesis ||
        memcmp(binding->network_genesis_root, expected_network_genesis,
               32) != 0)
        return VCS_ZCODE_BINDING_ERR_NETWORK_MISMATCH;
    if (!expected_zid_pubkey ||
        memcmp(binding->zid_pubkey, expected_zid_pubkey, 32) != 0)
        return VCS_ZCODE_BINDING_ERR_IDENTITY_MISMATCH;
    return binding_verify_sigs(binding);
}

enum vcs_zcode_binding_error vcs_zcode_contributor_binding_validate_successor(
    const struct vcs_zcode_contributor_binding_v1 *prior,
    const struct vcs_zcode_contributor_binding_v1 *next, int64_t now_unix)
{
    if (!prior || !next) return VCS_ZCODE_BINDING_ERR_NULL;
    enum vcs_zcode_binding_error error =
        vcs_zcode_contributor_binding_validate(prior);
    if (error != VCS_ZCODE_BINDING_OK) return error;
    error = vcs_zcode_contributor_binding_validate_at(next, now_unix);
    if (error != VCS_ZCODE_BINDING_OK) return error;

    if (memcmp(prior->network_genesis_root, next->network_genesis_root,
               32) != 0)
        return VCS_ZCODE_BINDING_ERR_NETWORK_MISMATCH;
    if (memcmp(prior->zid_pubkey, next->zid_pubkey, 32) != 0)
        return VCS_ZCODE_BINDING_ERR_IDENTITY_MISMATCH;
    /* A revoked binding is terminal: revocation cannot create a replacement
     * key implicitly, and nothing may succeed it. */
    if (prior->operation == VCS_ZCODE_BINDING_REVOKE)
        return VCS_ZCODE_BINDING_ERR_REVOKED;
    /* A successor can only rotate or revoke — a fresh ACTIVE would fork the
     * chain back to sequence 1. */
    if (next->operation == VCS_ZCODE_BINDING_ACTIVE)
        return VCS_ZCODE_BINDING_ERR_OPERATION;

    uint8_t prior_root[32];
    error = vcs_zcode_contributor_binding_root(prior, prior_root);
    if (error != VCS_ZCODE_BINDING_OK) return error;
    if (memcmp(next->predecessor_root, prior_root, sizeof(prior_root)) != 0)
        return VCS_ZCODE_BINDING_ERR_PREDECESSOR;
    /* Exact +1 sequencing rejects both replay (same sequence) and skips. */
    if (next->sequence != prior->sequence + 1)
        return VCS_ZCODE_BINDING_ERR_SEQUENCE;
    /* Time must move forward along the chain: a successor issued at or
     * before its predecessor is a reordering, not a rotation. */
    if (next->issued_unix <= prior->issued_unix)
        return VCS_ZCODE_BINDING_ERR_TIME_ORDER;

    if (next->operation == VCS_ZCODE_BINDING_ROTATE) {
        if (memcmp(prior->zcl_pubkey, next->zcl_pubkey, 33) == 0)
            return VCS_ZCODE_BINDING_ERR_LINKAGE;
    } else { /* REVOKE retires the SAME key; it never names a replacement. */
        if (memcmp(prior->zcl_pubkey, next->zcl_pubkey, 33) != 0 ||
            memcmp(prior->zcl_key_id, next->zcl_key_id, 20) != 0)
            return VCS_ZCODE_BINDING_ERR_LINKAGE;
    }

    error = binding_verify_sigs(prior);
    if (error != VCS_ZCODE_BINDING_OK) return error;
    return binding_verify_sigs(next);
}

/* ── contributor_binding.v2 ─────────────────────────────────────────────
 * Three-signature rotation (ZID + old ZCL + new ZCL), a delayed RECOVER
 * path for a lost ZCL key, and the retired-key reuse ban. v1 above is
 * frozen; nothing here feeds back into it. See the header for the wire
 * layout and the per-operation slot contract. */

static const uint8_t binding_magic_v2[8] = {'Z','C','B','N','D','2','\r','\n'};

/* Sign the 32-byte body root with a secp256k1 secret, low-S normalized:
 * byte deterministic. */
static bool binding_secp_sign_v2(const uint8_t root[32],
                                 const uint8_t secret[32], uint8_t out[64])
{
    secp256k1_ecdsa_signature signature;
    if (!secp256k1_ecdsa_sign(binding_ctx, &signature, root, secret,
                              NULL, NULL))
        return false;
    (void)secp256k1_ecdsa_signature_normalize(binding_ctx, &signature,
                                              &signature);
    (void)secp256k1_ecdsa_signature_serialize_compact(binding_ctx, out,
                                                      &signature);
    return true;
}

/* A v2 slot signature must be low-S canonical and verify under the given
 * compressed pubkey over the body root. */
static bool binding_secp_verify_v2(const uint8_t signature[64],
                                   const uint8_t root[32],
                                   const uint8_t pubkey33[33])
{
    if (!binding_signature_low_s(signature)) return false;
    secp256k1_pubkey pubkey;
    if (!secp256k1_ec_pubkey_parse(binding_ctx, &pubkey, pubkey33, 33))
        return false;
    secp256k1_ecdsa_signature parsed;
    (void)secp256k1_ecdsa_signature_parse_compact(binding_ctx, &parsed,
                                                  signature);
    return secp256k1_ecdsa_verify(binding_ctx, &parsed, root, &pubkey) == 1;
}

static bool binding_derive_zcl_pubkey_v2(const uint8_t secret[32],
                                         uint8_t out33[33])
{
    secp256k1_pubkey derived;
    if (!secp256k1_ec_pubkey_create(binding_ctx, &derived, secret))
        return false;
    size_t len = 33;
    (void)secp256k1_ec_pubkey_serialize(binding_ctx, out33, &len, &derived,
                                        SECP256K1_EC_COMPRESSED);
    return len == 33;
}

static enum vcs_zcode_binding_error binding_fields_v2(
    const struct vcs_zcode_contributor_binding_v2 *binding,
    bool require_signatures)
{
    if (!binding) return VCS_ZCODE_BINDING_ERR_NULL;
    if (binding->schema_version != VCS_ZCODE_CONTRIBUTOR_BINDING_V2_VERSION)
        return VCS_ZCODE_BINDING_ERR_VERSION;
    if (!root_nonzero(binding->network_genesis_root))
        return VCS_ZCODE_BINDING_ERR_ROOT_ZERO;
    if (!root_nonzero(binding->zid_pubkey))
        return VCS_ZCODE_BINDING_ERR_PUBKEY_ZERO;
    if (binding->operation < VCS_ZCODE_BINDING_ACTIVE ||
        binding->operation > VCS_ZCODE_BINDING_RECOVER)
        return VCS_ZCODE_BINDING_ERR_OPERATION;
    if (binding->sequence == 0)
        return VCS_ZCODE_BINDING_ERR_SEQUENCE;
    if (binding->operation == VCS_ZCODE_BINDING_ACTIVE) {
        if (binding->sequence != 1)
            return VCS_ZCODE_BINDING_ERR_SEQUENCE;
        if (root_nonzero(binding->predecessor_root))
            return VCS_ZCODE_BINDING_ERR_PREDECESSOR;
    } else {
        if (binding->sequence == 1)
            return VCS_ZCODE_BINDING_ERR_SEQUENCE;
        if (!root_nonzero(binding->predecessor_root))
            return VCS_ZCODE_BINDING_ERR_PREDECESSOR;
    }
    /* Same standalone-verifiability contract as v1: the zcl key must be a
     * real curve point and the key id its hash160. */
    if (!binding_zcl_pubkey_valid(binding->zcl_pubkey))
        return VCS_ZCODE_BINDING_ERR_PUBKEY_INVALID;
    uint8_t want_key_id[20];
    hash160(binding->zcl_pubkey, sizeof(binding->zcl_pubkey), want_key_id);
    if (memcmp(binding->zcl_key_id, want_key_id, sizeof(want_key_id)) != 0)
        return VCS_ZCODE_BINDING_ERR_KEY_ID_MISMATCH;
    if (binding->issued_unix <= 0 ||
        binding->expires_unix <= binding->issued_unix)
        return VCS_ZCODE_BINDING_ERR_TIME_ORDER;
    /* Only RECOVER carries an activation time, and it must leave the full
     * recovery delay between issue and activation. */
    if (binding->operation == VCS_ZCODE_BINDING_RECOVER) {
        if (binding->activation_unix <
            binding->issued_unix + VCS_ZCODE_BINDING_RECOVERY_DELAY_SECS)
            return VCS_ZCODE_BINDING_ERR_RECOVERY_DELAY;
    } else if (binding->activation_unix != 0) {
        return VCS_ZCODE_BINDING_ERR_OPERATION;
    }
    if (require_signatures) {
        if (!zcl_bytes_any_set(binding->zid_signature,
                           sizeof(binding->zid_signature)))
            return VCS_ZCODE_BINDING_ERR_SIGNATURE;
        bool current_signed =
            zcl_bytes_any_set(binding->zcl_current_signature,
                          sizeof(binding->zcl_current_signature));
        bool new_signed =
            zcl_bytes_any_set(binding->zcl_new_signature,
                          sizeof(binding->zcl_new_signature));
        /* Slot shape per operation: ACTIVE/ROTATE sign both, REVOKE signs
         * only current, RECOVER signs only new. */
        bool shape_ok;
        switch (binding->operation) {
        case VCS_ZCODE_BINDING_ACTIVE:
        case VCS_ZCODE_BINDING_ROTATE:
            shape_ok = current_signed && new_signed;
            break;
        case VCS_ZCODE_BINDING_REVOKE:
            shape_ok = current_signed && !new_signed;
            break;
        default: /* RECOVER */
            shape_ok = !current_signed && new_signed;
            break;
        }
        if (!shape_ok)
            return VCS_ZCODE_BINDING_ERR_SIG_SLOT;
    }
    return VCS_ZCODE_BINDING_OK;
}

enum vcs_zcode_binding_error vcs_zcode_contributor_binding_validate_v2(
    const struct vcs_zcode_contributor_binding_v2 *binding)
{
    return binding_fields_v2(binding, true);
}

enum vcs_zcode_binding_error vcs_zcode_contributor_binding_validate_at_v2(
    const struct vcs_zcode_contributor_binding_v2 *binding, int64_t now_unix)
{
    enum vcs_zcode_binding_error error =
        vcs_zcode_contributor_binding_validate_v2(binding);
    if (error != VCS_ZCODE_BINDING_OK) return error;
    /* Same liveness window as v1: usable inside [issued, expires). The
     * RECOVER activation gate (now >= activation_unix) is a chain-gate
     * rule, enforced by validate_successor_v2. */
    if (now_unix < binding->issued_unix)
        return VCS_ZCODE_BINDING_ERR_NOT_YET_VALID;
    if (now_unix >= binding->expires_unix)
        return VCS_ZCODE_BINDING_ERR_EXPIRED;
    return VCS_ZCODE_BINDING_OK;
}

static enum vcs_zcode_binding_error binding_body_v2(
    const struct vcs_zcode_contributor_binding_v2 *binding,
    uint8_t out[VCS_ZCODE_CONTRIBUTOR_BINDING_V2_BODY_BYTES])
{
    enum vcs_zcode_binding_error error = binding_fields_v2(binding, false);
    if (error != VCS_ZCODE_BINDING_OK || !out)
        return out ? error : VCS_ZCODE_BINDING_ERR_NULL;
    size_t off = 0;
    put_bytes(out, &off, binding_magic_v2, sizeof(binding_magic_v2));
    put_u16(out, &off, binding->schema_version);
    put_bytes(out, &off, binding->network_genesis_root, 32);
    put_bytes(out, &off, binding->zid_pubkey, 32);
    put_bytes(out, &off, binding->zcl_pubkey, 33);
    put_bytes(out, &off, binding->zcl_key_id, 20);
    put_bytes(out, &off, binding->predecessor_root, 32);
    put_u64(out, &off, binding->sequence);
    put_u64(out, &off, (uint64_t)binding->issued_unix);
    put_u64(out, &off, (uint64_t)binding->expires_unix);
    out[off++] = binding->operation;
    put_u64(out, &off, (uint64_t)binding->activation_unix);
    return off == VCS_ZCODE_CONTRIBUTOR_BINDING_V2_BODY_BYTES
               ? VCS_ZCODE_BINDING_OK : VCS_ZCODE_BINDING_ERR_WIRE_SIZE;
}

enum vcs_zcode_binding_error vcs_zcode_contributor_binding_serialize_v2(
    const struct vcs_zcode_contributor_binding_v2 *binding,
    uint8_t out[VCS_ZCODE_CONTRIBUTOR_BINDING_V2_WIRE_BYTES])
{
    enum vcs_zcode_binding_error error =
        vcs_zcode_contributor_binding_validate_v2(binding);
    if (error != VCS_ZCODE_BINDING_OK || !out)
        return out ? error : VCS_ZCODE_BINDING_ERR_NULL;
    error = binding_body_v2(binding, out);
    if (error != VCS_ZCODE_BINDING_OK) return error;
    memcpy(out + VCS_ZCODE_CONTRIBUTOR_BINDING_V2_BODY_BYTES,
           binding->zid_signature, 64);
    memcpy(out + VCS_ZCODE_CONTRIBUTOR_BINDING_V2_BODY_BYTES + 64,
           binding->zcl_current_signature, 64);
    memcpy(out + VCS_ZCODE_CONTRIBUTOR_BINDING_V2_BODY_BYTES + 128,
           binding->zcl_new_signature, 64);
    return VCS_ZCODE_BINDING_OK;
}

enum vcs_zcode_binding_error vcs_zcode_contributor_binding_parse_v2(
    const uint8_t *wire, size_t len,
    struct vcs_zcode_contributor_binding_v2 *out)
{
    if (!wire || !out) return VCS_ZCODE_BINDING_ERR_NULL;
    memset(out, 0, sizeof(*out));
    if (len != VCS_ZCODE_CONTRIBUTOR_BINDING_V2_WIRE_BYTES)
        return VCS_ZCODE_BINDING_ERR_WIRE_SIZE;
    if (memcmp(wire, binding_magic_v2, sizeof(binding_magic_v2)) != 0)
        return VCS_ZCODE_BINDING_ERR_WIRE_MAGIC;
    size_t off = sizeof(binding_magic_v2);
    out->schema_version = get_u16(wire, &off);
    get_bytes(wire, &off, out->network_genesis_root, 32);
    get_bytes(wire, &off, out->zid_pubkey, 32);
    get_bytes(wire, &off, out->zcl_pubkey, 33);
    get_bytes(wire, &off, out->zcl_key_id, 20);
    get_bytes(wire, &off, out->predecessor_root, 32);
    out->sequence = get_u64(wire, &off);
    out->issued_unix = (int64_t)get_u64(wire, &off);
    out->expires_unix = (int64_t)get_u64(wire, &off);
    out->operation = wire[off++];
    out->activation_unix = (int64_t)get_u64(wire, &off);
    get_bytes(wire, &off, out->zid_signature, 64);
    get_bytes(wire, &off, out->zcl_current_signature, 64);
    get_bytes(wire, &off, out->zcl_new_signature, 64);
    enum vcs_zcode_binding_error error =
        vcs_zcode_contributor_binding_validate_v2(out);
    if (error != VCS_ZCODE_BINDING_OK) memset(out, 0, sizeof(*out));
    return error;
}

enum vcs_zcode_binding_error vcs_zcode_contributor_binding_body_root_v2(
    const struct vcs_zcode_contributor_binding_v2 *binding, uint8_t out[32])
{
    uint8_t body[VCS_ZCODE_CONTRIBUTOR_BINDING_V2_BODY_BYTES];
    enum vcs_zcode_binding_error error = binding_body_v2(binding, body);
    if (error != VCS_ZCODE_BINDING_OK || !out)
        return out ? error : VCS_ZCODE_BINDING_ERR_NULL;
    static const char domain[] = VCS_ZCODE_CONTRIBUTOR_BINDING_V2_DOMAIN;
    return vcs_signed_evidence_root(domain, sizeof(domain), body,
                                    sizeof(body), out)
               ? VCS_ZCODE_BINDING_OK : VCS_ZCODE_BINDING_ERR_NULL;
}

enum vcs_zcode_binding_error vcs_zcode_contributor_binding_root_v2(
    const struct vcs_zcode_contributor_binding_v2 *binding, uint8_t out[32])
{
    uint8_t wire[VCS_ZCODE_CONTRIBUTOR_BINDING_V2_WIRE_BYTES];
    enum vcs_zcode_binding_error error =
        vcs_zcode_contributor_binding_serialize_v2(binding, wire);
    if (error != VCS_ZCODE_BINDING_OK || !out)
        return out ? error : VCS_ZCODE_BINDING_ERR_NULL;
    static const char domain[] = VCS_ZCODE_CONTRIBUTOR_BINDING_V2_ROOT_DOMAIN;
    return vcs_signed_evidence_root(domain, sizeof(domain), wire,
                                    sizeof(wire), out)
               ? VCS_ZCODE_BINDING_OK : VCS_ZCODE_BINDING_ERR_NULL;
}

enum vcs_zcode_binding_error vcs_zcode_contributor_binding_seal_v2(
    struct vcs_zcode_contributor_binding_v2 *binding,
    const uint8_t zid_secret[32], const uint8_t zid_pubkey[32],
    const uint8_t current_zcl_secret[32], const uint8_t new_zcl_secret[32])
{
    if (!binding || !zid_secret || !zid_pubkey)
        return VCS_ZCODE_BINDING_ERR_NULL;
    if (!root_nonzero(zid_pubkey)) return VCS_ZCODE_BINDING_ERR_PUBKEY_ZERO;
    /* Same pin as v1: a secret that does not derive the claimed ZID pubkey
     * must never seal. */
    uint8_t zid_derived_pk[32], zid_derived_sk[32];
    ed25519_keypair(zid_derived_pk, zid_derived_sk, zid_secret);
    if (memcmp(zid_derived_pk, zid_pubkey, 32) != 0)
        return VCS_ZCODE_BINDING_ERR_KEY_MISMATCH;
    if (memcmp(binding->zid_pubkey, zid_pubkey, 32) != 0)
        return VCS_ZCODE_BINDING_ERR_KEY_MISMATCH;

    enum vcs_zcode_binding_error error = binding_fields_v2(binding, false);
    if (error != VCS_ZCODE_BINDING_OK) return error;

    /* Pin the secrets to the slots before signing anything. The embedded
     * zcl_pubkey is always the NEW key (the initial key for ACTIVE, the
     * retiring key for REVOKE); a ROTATE's current secret is the old key
     * and is pinned by the chain gate against the predecessor, not here. */
    uint8_t derived_ser[33];
    switch (binding->operation) {
    case VCS_ZCODE_BINDING_ACTIVE:
        if (!current_zcl_secret || !new_zcl_secret)
            return VCS_ZCODE_BINDING_ERR_NULL;
        if (!binding_derive_zcl_pubkey_v2(current_zcl_secret, derived_ser) ||
            memcmp(binding->zcl_pubkey, derived_ser, 33) != 0)
            return VCS_ZCODE_BINDING_ERR_KEY_MISMATCH;
        if (!binding_derive_zcl_pubkey_v2(new_zcl_secret, derived_ser) ||
            memcmp(binding->zcl_pubkey, derived_ser, 33) != 0)
            return VCS_ZCODE_BINDING_ERR_KEY_MISMATCH;
        break;
    case VCS_ZCODE_BINDING_ROTATE:
        if (!current_zcl_secret || !new_zcl_secret)
            return VCS_ZCODE_BINDING_ERR_NULL;
        if (!binding_derive_zcl_pubkey_v2(new_zcl_secret, derived_ser) ||
            memcmp(binding->zcl_pubkey, derived_ser, 33) != 0)
            return VCS_ZCODE_BINDING_ERR_KEY_MISMATCH;
        break;
    case VCS_ZCODE_BINDING_REVOKE:
        if (!current_zcl_secret)
            return VCS_ZCODE_BINDING_ERR_NULL;
        if (!binding_derive_zcl_pubkey_v2(current_zcl_secret, derived_ser) ||
            memcmp(binding->zcl_pubkey, derived_ser, 33) != 0)
            return VCS_ZCODE_BINDING_ERR_KEY_MISMATCH;
        memset(binding->zcl_new_signature, 0,
               sizeof(binding->zcl_new_signature));
        break;
    default: /* RECOVER — the old key is presumed lost. */
        if (current_zcl_secret)
            return VCS_ZCODE_BINDING_ERR_SIG_SLOT;
        if (!new_zcl_secret)
            return VCS_ZCODE_BINDING_ERR_NULL;
        if (!binding_derive_zcl_pubkey_v2(new_zcl_secret, derived_ser) ||
            memcmp(binding->zcl_pubkey, derived_ser, 33) != 0)
            return VCS_ZCODE_BINDING_ERR_KEY_MISMATCH;
        memset(binding->zcl_current_signature, 0,
               sizeof(binding->zcl_current_signature));
        break;
    }

    uint8_t root[32];
    error = vcs_zcode_contributor_binding_body_root_v2(binding, root);
    if (error != VCS_ZCODE_BINDING_OK) return error;

    if (!vcs_signed_evidence_seal_root(root, zid_secret, zid_pubkey,
                                       binding->zid_signature))
        return VCS_ZCODE_BINDING_ERR_SIGNATURE;

    switch (binding->operation) {
    case VCS_ZCODE_BINDING_ACTIVE:
    case VCS_ZCODE_BINDING_ROTATE:
        if (!binding_secp_sign_v2(root, current_zcl_secret,
                                  binding->zcl_current_signature) ||
            !binding_secp_sign_v2(root, new_zcl_secret,
                                  binding->zcl_new_signature))
            return VCS_ZCODE_BINDING_ERR_SIGNATURE;
        break;
    case VCS_ZCODE_BINDING_REVOKE:
        if (!binding_secp_sign_v2(root, current_zcl_secret,
                                  binding->zcl_current_signature))
            return VCS_ZCODE_BINDING_ERR_SIGNATURE;
        break;
    default: /* RECOVER */
        if (!binding_secp_sign_v2(root, new_zcl_secret,
                                  binding->zcl_new_signature))
            return VCS_ZCODE_BINDING_ERR_SIGNATURE;
        break;
    }
    return VCS_ZCODE_BINDING_OK;
}

/* Verify the signatures over the v2 body root, no expiry gate. The ZID
 * signature verifies under the embedded zid_pubkey and the new slot under
 * the embedded zcl_pubkey wherever it must be signed. The current slot
 * signs under the embedded key for ACTIVE/REVOKE and under the PRIOR
 * link's key for ROTATE — pass prior to check that slot, NULL for the
 * standalone subset. RECOVER's current slot is zero by construction. */
static enum vcs_zcode_binding_error binding_verify_sigs_v2(
    const struct vcs_zcode_contributor_binding_v2 *binding,
    const struct vcs_zcode_contributor_binding_v2 *prior)
{
    uint8_t root[32];
    enum vcs_zcode_binding_error error =
        vcs_zcode_contributor_binding_body_root_v2(binding, root);
    if (error != VCS_ZCODE_BINDING_OK) return error;

    if (!vcs_signed_evidence_verify_root(root, binding->zid_signature,
                                         binding->zid_pubkey,
                                         binding->zid_pubkey))
        return VCS_ZCODE_BINDING_ERR_SIGNATURE;

    switch (binding->operation) {
    case VCS_ZCODE_BINDING_ACTIVE:
        if (!binding_secp_verify_v2(binding->zcl_current_signature, root,
                                    binding->zcl_pubkey) ||
            !binding_secp_verify_v2(binding->zcl_new_signature, root,
                                    binding->zcl_pubkey))
            return VCS_ZCODE_BINDING_ERR_SIGNATURE;
        break;
    case VCS_ZCODE_BINDING_ROTATE:
        if (prior &&
            !binding_secp_verify_v2(binding->zcl_current_signature, root,
                                    prior->zcl_pubkey))
            return VCS_ZCODE_BINDING_ERR_SIGNATURE;
        if (!binding_secp_verify_v2(binding->zcl_new_signature, root,
                                    binding->zcl_pubkey))
            return VCS_ZCODE_BINDING_ERR_SIGNATURE;
        break;
    case VCS_ZCODE_BINDING_REVOKE:
        if (!binding_secp_verify_v2(binding->zcl_current_signature, root,
                                    binding->zcl_pubkey))
            return VCS_ZCODE_BINDING_ERR_SIGNATURE;
        break;
    default: /* RECOVER */
        if (!binding_secp_verify_v2(binding->zcl_new_signature, root,
                                    binding->zcl_pubkey))
            return VCS_ZCODE_BINDING_ERR_SIGNATURE;
        break;
    }
    return VCS_ZCODE_BINDING_OK;
}

enum vcs_zcode_binding_error vcs_zcode_contributor_binding_verify_v2(
    const struct vcs_zcode_contributor_binding_v2 *binding,
    const uint8_t expected_network_genesis[32],
    const uint8_t expected_zid_pubkey[32], int64_t now_unix)
{
    enum vcs_zcode_binding_error error =
        vcs_zcode_contributor_binding_validate_at_v2(binding, now_unix);
    if (error != VCS_ZCODE_BINDING_OK) return error;
    if (!expected_network_genesis ||
        memcmp(binding->network_genesis_root, expected_network_genesis,
               32) != 0)
        return VCS_ZCODE_BINDING_ERR_NETWORK_MISMATCH;
    if (!expected_zid_pubkey ||
        memcmp(binding->zid_pubkey, expected_zid_pubkey, 32) != 0)
        return VCS_ZCODE_BINDING_ERR_IDENTITY_MISMATCH;
    return binding_verify_sigs_v2(binding, NULL);
}

enum vcs_zcode_binding_error
vcs_zcode_contributor_binding_validate_successor_v2(
    const struct vcs_zcode_contributor_binding_v2 *prior,
    const struct vcs_zcode_contributor_binding_v2 *next, int64_t now_unix)
{
    if (!prior || !next) return VCS_ZCODE_BINDING_ERR_NULL;
    enum vcs_zcode_binding_error error =
        vcs_zcode_contributor_binding_validate_v2(prior);
    if (error != VCS_ZCODE_BINDING_OK) return error;
    error = vcs_zcode_contributor_binding_validate_at_v2(next, now_unix);
    if (error != VCS_ZCODE_BINDING_OK) return error;

    if (memcmp(prior->network_genesis_root, next->network_genesis_root,
               32) != 0)
        return VCS_ZCODE_BINDING_ERR_NETWORK_MISMATCH;
    if (memcmp(prior->zid_pubkey, next->zid_pubkey, 32) != 0)
        return VCS_ZCODE_BINDING_ERR_IDENTITY_MISMATCH;
    /* Terminal as in v1: nothing may succeed a revoked binding. */
    if (prior->operation == VCS_ZCODE_BINDING_REVOKE)
        return VCS_ZCODE_BINDING_ERR_REVOKED;
    if (next->operation == VCS_ZCODE_BINDING_ACTIVE)
        return VCS_ZCODE_BINDING_ERR_OPERATION;

    uint8_t prior_root[32];
    error = vcs_zcode_contributor_binding_root_v2(prior, prior_root);
    if (error != VCS_ZCODE_BINDING_OK) return error;
    if (memcmp(next->predecessor_root, prior_root, sizeof(prior_root)) != 0)
        return VCS_ZCODE_BINDING_ERR_PREDECESSOR;
    if (next->sequence != prior->sequence + 1)
        return VCS_ZCODE_BINDING_ERR_SEQUENCE;
    /* Issue time must strictly increase along the chain. */
    if (next->issued_unix <= prior->issued_unix)
        return VCS_ZCODE_BINDING_ERR_TIME_ORDER;

    switch (next->operation) {
    case VCS_ZCODE_BINDING_ROTATE:
        /* A ROTATE that keeps the old key is not a rotation. */
        if (memcmp(prior->zcl_pubkey, next->zcl_pubkey, 33) == 0)
            return VCS_ZCODE_BINDING_ERR_LINKAGE;
        break;
    case VCS_ZCODE_BINDING_REVOKE:
        /* REVOKE retires the SAME key; it never names a replacement. */
        if (memcmp(prior->zcl_pubkey, next->zcl_pubkey, 33) != 0 ||
            memcmp(prior->zcl_key_id, next->zcl_key_id, 20) != 0)
            return VCS_ZCODE_BINDING_ERR_LINKAGE;
        break;
    default: /* RECOVER — recovering to the same (presumed lost) key is not
              * a recovery. */
        if (memcmp(prior->zcl_pubkey, next->zcl_pubkey, 33) == 0)
            return VCS_ZCODE_BINDING_ERR_LINKAGE;
        /* A RECOVER link is not effective until its activation time. The
         * activation-vs-issue delay itself is structural (validate_v2). */
        if (now_unix < next->activation_unix)
            return VCS_ZCODE_BINDING_ERR_RECOVERY_PENDING;
        break;
    }

    error = binding_verify_sigs_v2(prior, NULL);
    if (error != VCS_ZCODE_BINDING_OK) return error;
    return binding_verify_sigs_v2(next, prior);
}

enum vcs_zcode_binding_error vcs_zcode_contributor_binding_validate_chain_v2(
    const struct vcs_zcode_contributor_binding_v2 *links, size_t count,
    int64_t now_unix)
{
    if (!links || count == 0) return VCS_ZCODE_BINDING_ERR_NULL;
    /* A chain opens with ACTIVE; anything else is a fork attempt. */
    if (links[0].operation != VCS_ZCODE_BINDING_ACTIVE)
        return VCS_ZCODE_BINDING_ERR_OPERATION;
    enum vcs_zcode_binding_error error =
        vcs_zcode_contributor_binding_validate_v2(&links[0]);
    if (error != VCS_ZCODE_BINDING_OK) return error;

    for (size_t i = 1; i < count; i++) {
        error = vcs_zcode_contributor_binding_validate_successor_v2(
            &links[i - 1], &links[i], now_unix);
        if (error != VCS_ZCODE_BINDING_OK) return error;
        /* Retired-key reuse ban: the key that any earlier ROTATE replaced
         * or RECOVER abandoned (links[j-1] for each successor j) — and the
         * key a REVOKE retires, which equals its predecessor's — must
         * never reappear as a later link's zcl_pubkey. */
        for (size_t j = 1; j <= i; j++) {
            if ((links[j].operation == VCS_ZCODE_BINDING_ROTATE ||
                 links[j].operation == VCS_ZCODE_BINDING_RECOVER) &&
                memcmp(links[i].zcl_pubkey, links[j - 1].zcl_pubkey,
                       33) == 0)
                return VCS_ZCODE_BINDING_ERR_RETIRED_KEY_REUSE;
        }
    }
    return VCS_ZCODE_BINDING_OK;
}
