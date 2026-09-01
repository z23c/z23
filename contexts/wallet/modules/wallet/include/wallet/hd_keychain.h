/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * BIP32 HD keychain — master seed to account/change/address derivation.
 * Wraps the low-level ext_key / ext_pubkey primitives from keys/key.h
 * into a wallet-friendly API with path parsing and serialization.
 */

#ifndef ZCL_WALLET_HD_KEYCHAIN_H
#define ZCL_WALLET_HD_KEYCHAIN_H

#include "keys/key.h"
#include "keys/pubkey.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* BIP32 hardened child flag */
#define BIP32_HARDENED 0x80000000u

/* Recommended seed lengths (bytes) */
#define HD_SEED_MIN_BYTES 16
#define HD_SEED_MAX_BYTES 64
#define HD_SEED_DEFAULT_BYTES 32

/* Max derivation depth (BIP32 uses uint8 for depth, max 255) */
#define HD_MAX_DEPTH 255

/* Max path components in a derivation path string (e.g. m/44'/147'/0'/0/5) */
#define HD_MAX_PATH_COMPONENTS 16

/* Serialized xpub/xpriv string buffer size (base58check of 78 bytes) */
#define HD_XKEY_STRING_SIZE 120

/* ── Seed generation ──────────────────────────────────────────────── */

/* Generate a cryptographically random seed.
 * seed_out must be at least seed_len bytes.
 * seed_len must be in [HD_SEED_MIN_BYTES, HD_SEED_MAX_BYTES]. */
bool hd_generate_seed(unsigned char *seed_out, size_t seed_len);

/* ── Master key creation ──────────────────────────────────────────── */

/* Initialize an ext_key as a BIP32 master key from raw seed bytes.
 * Uses HMAC-SHA512("Bitcoin seed", seed) per BIP32 spec. */
bool hd_master_from_seed(struct ext_key *master_out,
                         const unsigned char *seed, size_t seed_len);

/* ── Path derivation ──────────────────────────────────────────────── */

/* Parse a BIP32 path string like "m/44'/147'/0'/0/5" into an array
 * of child indices (with hardened flag set where appropriate).
 * Returns number of components parsed, or -1 on error. */
int hd_parse_path(const char *path, uint32_t *indices_out, int max_indices);

/* Derive a child ext_key by walking a sequence of child indices.
 * parent must be a valid ext_key (private). */
bool hd_derive_path(const struct ext_key *parent, struct ext_key *child_out,
                    const uint32_t *indices, int num_indices);

/* Derive a child ext_key from a path string.
 * Convenience wrapper: parses path then derives. */
bool hd_derive_path_str(const struct ext_key *master, struct ext_key *child_out,
                        const char *path);

/* Derive the next child key at a given base path + incrementing index.
 * E.g. base "m/44'/147'/0'/0" with index 7 derives m/44'/147'/0'/0/7. */
bool hd_derive_child_index(const struct ext_key *parent,
                           struct ext_key *child_out, uint32_t index);

/* ── Public key derivation ────────────────────────────────────────── */

/* Derive a child ext_pubkey by walking non-hardened indices.
 * Returns false if any index is hardened (requires private key). */
bool hd_derive_pubkey_path(const struct ext_pubkey *parent,
                           struct ext_pubkey *child_out,
                           const uint32_t *indices, int num_indices);

/* ── Serialization (xpub / xpriv) ────────────────────────────────── */

/* Serialize an ext_key to xprv string (base58check with version prefix).
 * version is a 4-byte prefix (e.g. 0x0488ADE4 for mainnet xprv).
 * out must be at least HD_XKEY_STRING_SIZE bytes. */
bool hd_serialize_xprv(const struct ext_key *ek,
                       const unsigned char version[4],
                       char *out, size_t out_size);

/* Serialize an ext_pubkey to xpub string.
 * version is a 4-byte prefix (e.g. 0x0488B21E for mainnet xpub). */
bool hd_serialize_xpub(const struct ext_pubkey *epk,
                       const unsigned char version[4],
                       char *out, size_t out_size);

/* Deserialize an xprv string back to ext_key.
 * expected_version is checked against the decoded prefix. */
bool hd_deserialize_xprv(const char *str,
                         const unsigned char expected_version[4],
                         struct ext_key *ek_out);

/* Deserialize an xpub string back to ext_pubkey. */
bool hd_deserialize_xpub(const char *str,
                         const unsigned char expected_version[4],
                         struct ext_pubkey *epk_out);

/* ── Address generation helpers ───────────────────────────────────── */

/* Get the key_id for a derived ext_key. */
struct key_id hd_get_key_id(const struct ext_key *ek);

#endif /* ZCL_WALLET_HD_KEYCHAIN_H */
