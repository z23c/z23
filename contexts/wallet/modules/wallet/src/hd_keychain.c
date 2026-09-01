/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * BIP32 HD keychain — thin wrapper layer.
 *
 * Pure derivation math (HMAC-SHA512, secp256k1 chain) lives in
 * contexts/wallet/domain/key_derivation.{c,h}. This file:
 *   - generates seeds via the platform RNG (impure — stays here);
 *   - serializes xpub/xprv via encoding/base58 (encoding, not math);
 *   - presents the original bool-returning API for legacy callers.
 */

#include "wallet/hd_keychain.h"

#include "domain/wallet/key_derivation.h"
#include "core/random.h"
#include "domain/encoding/base58.h"
#include "support/cleanse.h"
#include "util/log_macros.h"

#include <string.h>

#define DOMAIN "hd"

/* BIP32 serialized key is 78 bytes: 4 version + 74 ext_key payload */
#define BIP32_SERIALIZED_SIZE 78

/* ── Seed generation (impure: platform RNG) ───────────────────────── */

bool hd_generate_seed(unsigned char *seed_out, size_t seed_len)
{
    GUARD_NOT_NULL(seed_out, DOMAIN, "seed_out");
    GUARD(seed_len >= HD_SEED_MIN_BYTES && seed_len <= HD_SEED_MAX_BYTES,
          DOMAIN, "seed_len out of range: %zu", seed_len);

    GetRandBytes(seed_out, seed_len);
    return true;
}

/* ── Master key creation (delegates to pure domain) ───────────────── */

bool hd_master_from_seed(struct ext_key *master_out,
                         const unsigned char *seed, size_t seed_len)
{
    struct zcl_result r =
            domain_wallet_master_from_seed(master_out, seed, seed_len);
    if (!r.ok)
        LOG_FAIL(DOMAIN, "hd_master_from_seed: %s", r.message);
    return true;
}

/* ── Path parsing (delegates) ─────────────────────────────────────── */

int hd_parse_path(const char *path, uint32_t *indices_out, int max_indices)
{
    int count = 0;
    struct zcl_result r = domain_wallet_parse_path(path, indices_out,
                                                   max_indices, &count);
    if (!r.ok)
        return -1;
    return count;
}

/* ── Path derivation (delegates) ──────────────────────────────────── */

bool hd_derive_path(const struct ext_key *parent, struct ext_key *child_out,
                    const uint32_t *indices, int num_indices)
{
    struct zcl_result r = domain_wallet_derive_path(parent, child_out,
                                                    indices, num_indices);
    if (!r.ok)
        LOG_FAIL(DOMAIN, "hd_derive_path: %s", r.message);
    return true;
}

bool hd_derive_path_str(const struct ext_key *master, struct ext_key *child_out,
                        const char *path)
{
    GUARD_NOT_NULL(path, DOMAIN, "path");

    uint32_t indices[HD_MAX_PATH_COMPONENTS];
    int count = 0;
    struct zcl_result r = domain_wallet_parse_path(path, indices,
                                                   HD_MAX_PATH_COMPONENTS,
                                                   &count);
    if (!r.ok)
        LOG_FAIL(DOMAIN, "invalid path '%s': %s", path, r.message);

    return hd_derive_path(master, child_out, indices, count);
}

bool hd_derive_child_index(const struct ext_key *parent,
                           struct ext_key *child_out, uint32_t index)
{
    struct zcl_result r = domain_wallet_derive_child_index(parent, child_out,
                                                           index);
    if (!r.ok)
        LOG_FAIL(DOMAIN, "hd_derive_child_index: %s", r.message);
    return true;
}

/* ── Public key path derivation (delegates) ───────────────────────── */

bool hd_derive_pubkey_path(const struct ext_pubkey *parent,
                           struct ext_pubkey *child_out,
                           const uint32_t *indices, int num_indices)
{
    struct zcl_result r = domain_wallet_derive_pubkey_path(parent, child_out,
                                                           indices, num_indices);
    if (!r.ok)
        LOG_FAIL(DOMAIN, "hd_derive_pubkey_path: %s", r.message);
    return true;
}

/* ── Serialization (encoding/base58 wrappers, not derivation math) ── */

bool hd_serialize_xprv(const struct ext_key *ek,
                       const unsigned char version[4],
                       char *out, size_t out_size)
{
    GUARD_NOT_NULL(ek, DOMAIN, "ek");
    GUARD_NOT_NULL(version, DOMAIN, "version");
    GUARD_NOT_NULL(out, DOMAIN, "out");
    GUARD(out_size >= HD_XKEY_STRING_SIZE,
          DOMAIN, "out_size too small: %zu", out_size);

    unsigned char data[BIP32_SERIALIZED_SIZE];
    memcpy(data, version, 4);

    unsigned char payload[BIP32_EXTKEY_SIZE];
    ext_key_encode(ek, payload);
    memcpy(data + 4, payload, BIP32_EXTKEY_SIZE);

    size_t written = 0;
    if (!domain_encoding_base58check_encode(data, BIP32_SERIALIZED_SIZE, out, out_size, &written)) {
        memory_cleanse(data, sizeof(data));
        LOG_FAIL(DOMAIN, "base58check_encode failed for xprv");
    }

    memory_cleanse(data, sizeof(data));
    return true;
}

bool hd_serialize_xpub(const struct ext_pubkey *epk,
                       const unsigned char version[4],
                       char *out, size_t out_size)
{
    GUARD_NOT_NULL(epk, DOMAIN, "epk");
    GUARD_NOT_NULL(version, DOMAIN, "version");
    GUARD_NOT_NULL(out, DOMAIN, "out");
    GUARD(out_size >= HD_XKEY_STRING_SIZE,
          DOMAIN, "out_size too small: %zu", out_size);

    unsigned char data[BIP32_SERIALIZED_SIZE];
    memcpy(data, version, 4);

    unsigned char payload[BIP32_EXTKEY_SIZE];
    if (!ext_pubkey_encode(epk, payload))
        LOG_FAIL(DOMAIN, "ext_pubkey_encode failed for xpub "
                 "(key is not a 33-byte compressed public key)");
    memcpy(data + 4, payload, BIP32_EXTKEY_SIZE);

    size_t written = 0;
    if (!domain_encoding_base58check_encode(data, BIP32_SERIALIZED_SIZE, out, out_size, &written))
        LOG_FAIL(DOMAIN, "base58check_encode failed for xpub");

    return true;
}

bool hd_deserialize_xprv(const char *str,
                         const unsigned char expected_version[4],
                         struct ext_key *ek_out)
{
    GUARD_NOT_NULL(str, DOMAIN, "str");
    GUARD_NOT_NULL(expected_version, DOMAIN, "expected_version");
    GUARD_NOT_NULL(ek_out, DOMAIN, "ek_out");

    unsigned char data[BIP32_SERIALIZED_SIZE + 4]; /* extra room for safety */
    size_t decoded_len = 0;

    if (!domain_encoding_base58check_decode(str, data, sizeof(data), &decoded_len))
        LOG_FAIL(DOMAIN, "base58check_decode failed for xprv");

    if (decoded_len != BIP32_SERIALIZED_SIZE)
        LOG_FAIL(DOMAIN, "unexpected decoded length: %zu (expected %d)",
                 decoded_len, BIP32_SERIALIZED_SIZE);

    if (memcmp(data, expected_version, 4) != 0)
        LOG_FAIL(DOMAIN, "version mismatch in xprv");

    ext_key_decode(ek_out, data + 4);

    if (!privkey_is_valid(&ek_out->key)) {
        memory_cleanse(data, sizeof(data));
        LOG_FAIL(DOMAIN, "decoded xprv has invalid private key");
    }

    memory_cleanse(data, sizeof(data));
    return true;
}

bool hd_deserialize_xpub(const char *str,
                         const unsigned char expected_version[4],
                         struct ext_pubkey *epk_out)
{
    GUARD_NOT_NULL(str, DOMAIN, "str");
    GUARD_NOT_NULL(expected_version, DOMAIN, "expected_version");
    GUARD_NOT_NULL(epk_out, DOMAIN, "epk_out");

    unsigned char data[BIP32_SERIALIZED_SIZE + 4];
    size_t decoded_len = 0;

    if (!domain_encoding_base58check_decode(str, data, sizeof(data), &decoded_len))
        LOG_FAIL(DOMAIN, "base58check_decode failed for xpub");

    if (decoded_len != BIP32_SERIALIZED_SIZE)
        LOG_FAIL(DOMAIN, "unexpected decoded length: %zu (expected %d)",
                 decoded_len, BIP32_SERIALIZED_SIZE);

    if (memcmp(data, expected_version, 4) != 0)
        LOG_FAIL(DOMAIN, "version mismatch in xpub");

    ext_pubkey_decode(epk_out, data + 4);

    if (!pubkey_is_valid(&epk_out->pubkey))
        LOG_FAIL(DOMAIN, "decoded xpub has invalid public key");

    return true;
}

/* ── Address generation helpers ───────────────────────────────────── */

struct key_id hd_get_key_id(const struct ext_key *ek)
{
    struct pubkey pk;
    privkey_get_pubkey(&ek->key, &pk);
    return pubkey_get_id(&pk);
}
