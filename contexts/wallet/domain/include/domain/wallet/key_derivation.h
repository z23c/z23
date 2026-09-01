/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rhett Creighton
 *
 * contexts/wallet/domain/key_derivation.h — pure BIP32/BIP44 hierarchical key
 * derivation.
 *
 * Given a seed (or an existing extended key) and a derivation path,
 * compute the child extended key. This is pure HMAC-SHA512 +
 * secp256k1 point arithmetic with no I/O, no clock, no RNG, no
 * persistence:
 *
 *   - seed → master ext_key:    HMAC-SHA512("Bitcoin seed", seed)
 *   - parent → child ext_key:   BIP32 CKDpriv / CKDpub
 *   - path walk:                array of child indices, deterministic chain
 *   - BIP44 helpers:            m/44'/coin'/account'/change/index
 *   - path string parsing:      "m/44'/147'/0'/0/5" → uint32_t[]
 *
 * The wallet's seed *generation* (random) lives in contexts/wallet/ behind
 * the platform.rng port; serialization to xpub/xprv strings lives in
 * contexts/wallet/ behind encoding/base58 (Base58Check is not derivation
 * math). This header covers only the pure math.
 *
 * Layering: contexts/wallet/domain/ may #include from util/, core/, crypto/,
 * keys/, primitives/. The fact this code depends only on keys/ and
 * util/ is what makes it eligible to live here.
 *
 * The contexts/wallet/ headers (wallet/hd_keychain.h, wallet/bip44.h)
 * remain the public API for wallet callers; their .c files are thin
 * wrappers preserving exact existing signatures.
 */

#ifndef ZCL_DOMAIN_WALLET_KEY_DERIVATION_H
#define ZCL_DOMAIN_WALLET_KEY_DERIVATION_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "keys/key.h"
#include "keys/pubkey.h"
#include "util/result.h"

/* BIP32 hardened-child flag (high bit of child index). */
#define DOMAIN_WALLET_BIP32_HARDENED  0x80000000u

/* Seed length bounds per BIP32: 128/256/512 bits, with 256 typical. */
#define DOMAIN_WALLET_SEED_MIN_BYTES      16
#define DOMAIN_WALLET_SEED_MAX_BYTES      64
#define DOMAIN_WALLET_SEED_DEFAULT_BYTES  32

/* BIP32 stores depth in a uint8 — 255 is the absolute ceiling. */
#define DOMAIN_WALLET_MAX_DEPTH           255

/* Buffer size for parse_path output; matches contexts/wallet/modules/wallet history. */
#define DOMAIN_WALLET_MAX_PATH_COMPONENTS 16

/* BIP44 fixed constants. */
#define DOMAIN_WALLET_BIP44_PURPOSE       44u
#define DOMAIN_WALLET_BIP44_ZCL_COIN      147u    /* SLIP-0044 */
#define DOMAIN_WALLET_BIP44_EXTERNAL      0u
#define DOMAIN_WALLET_BIP44_INTERNAL      1u
#define DOMAIN_WALLET_BIP44_MAX_ACCOUNT   0x7FFFFFFFu
#define DOMAIN_WALLET_BIP44_MAX_INDEX     0x7FFFFFFFu

/* ── Error codes (stable, appended on extension) ──────────────────── */

enum domain_wallet_key_derivation_err {
    DOMAIN_WALLET_KEY_DERIVATION_ERR_NULL_OUT       = 1201,
    DOMAIN_WALLET_KEY_DERIVATION_ERR_NULL_PARENT    = 1202,
    DOMAIN_WALLET_KEY_DERIVATION_ERR_NULL_SEED      = 1203,
    DOMAIN_WALLET_KEY_DERIVATION_ERR_NULL_INDICES   = 1204,
    DOMAIN_WALLET_KEY_DERIVATION_ERR_NULL_PATH      = 1205,
    DOMAIN_WALLET_KEY_DERIVATION_ERR_NULL_BUF       = 1206,
    DOMAIN_WALLET_KEY_DERIVATION_ERR_SEED_LEN       = 1207,
    DOMAIN_WALLET_KEY_DERIVATION_ERR_DEPTH          = 1208,
    DOMAIN_WALLET_KEY_DERIVATION_ERR_INVALID_MASTER = 1209,
    DOMAIN_WALLET_KEY_DERIVATION_ERR_DERIVE_FAIL    = 1210,
    DOMAIN_WALLET_KEY_DERIVATION_ERR_HARDENED_PUB   = 1211,
    DOMAIN_WALLET_KEY_DERIVATION_ERR_PATH_SYNTAX    = 1212,
    DOMAIN_WALLET_KEY_DERIVATION_ERR_PATH_TOOLONG   = 1213,
    DOMAIN_WALLET_KEY_DERIVATION_ERR_BAD_RANGE      = 1214,
    DOMAIN_WALLET_KEY_DERIVATION_ERR_BUF_TOO_SMALL  = 1215,
};

/* ── Master key from seed ─────────────────────────────────────────── */

/* Compute the BIP32 master extended key from raw seed bytes.
 *
 *   seed_len must be in [DOMAIN_WALLET_SEED_MIN_BYTES,
 *                        DOMAIN_WALLET_SEED_MAX_BYTES].
 *
 * On success, *master_out holds a valid private master key (depth=0,
 * child=0) and ZCL_OK is returned. On failure returns:
 *   ERR_NULL_OUT        master_out == NULL
 *   ERR_NULL_SEED       seed == NULL
 *   ERR_SEED_LEN        seed_len out of range
 *   ERR_INVALID_MASTER  the derived scalar was 0 or >= n (≈2^-127 odds)
 *
 * Pure: HMAC-SHA512("Bitcoin seed", seed). No clock, RNG, or I/O. */
struct zcl_result domain_wallet_master_from_seed(
        struct ext_key *master_out,
        const unsigned char *seed,
        size_t seed_len);

/* ── Path derivation (private) ────────────────────────────────────── */

/* Walk a sequence of child indices from `parent`. parent must be a
 * private ext_key. Hardened indices have bit 31 set.
 *
 * num_indices == 0 returns *parent unchanged (identity).
 *
 * Errors:
 *   ERR_NULL_OUT        child_out == NULL
 *   ERR_NULL_PARENT     parent == NULL
 *   ERR_NULL_INDICES    indices == NULL while num_indices > 0
 *   ERR_DEPTH           num_indices < 0 or > MAX_DEPTH
 *   ERR_DERIVE_FAIL     ext_key_derive failed at depth (1-in-2^127) */
struct zcl_result domain_wallet_derive_path(
        const struct ext_key *parent,
        struct ext_key *child_out,
        const uint32_t *indices,
        int num_indices);

/* Single-step convenience: derive one child by index. */
struct zcl_result domain_wallet_derive_child_index(
        const struct ext_key *parent,
        struct ext_key *child_out,
        uint32_t index);

/* ── Path derivation (public) ─────────────────────────────────────── */

/* Walk a sequence of non-hardened child indices from `parent`
 * (BIP32 CKDpub). Hardened indices (high bit set) return
 * ERR_HARDENED_PUB.
 *
 * Errors mirror domain_wallet_derive_path plus ERR_HARDENED_PUB. */
struct zcl_result domain_wallet_derive_pubkey_path(
        const struct ext_pubkey *parent,
        struct ext_pubkey *child_out,
        const uint32_t *indices,
        int num_indices);

/* ── Path string parsing ──────────────────────────────────────────── */

/* Parse a BIP32 path string like "m/44'/147'/0'/0/5" into a list of
 * child indices. The hardened markers `'`, `h`, and `H` set bit 31.
 *
 *   path:           NUL-terminated path string. Leading "m" or "m/"
 *                   is optional; "m" alone yields 0 components.
 *   indices_out:    caller buffer of `max_indices` slots.
 *   max_indices:    must be > 0.
 *   *count_out:     number of components parsed (0..max_indices).
 *
 * Errors:
 *   ERR_NULL_PATH       path == NULL
 *   ERR_NULL_INDICES    indices_out == NULL
 *   ERR_NULL_OUT        count_out == NULL
 *   ERR_BAD_RANGE       max_indices <= 0
 *   ERR_PATH_TOOLONG    more components than max_indices
 *   ERR_PATH_SYNTAX     malformed numeric, trailing slash, etc. */
struct zcl_result domain_wallet_parse_path(
        const char *path,
        uint32_t *indices_out,
        int max_indices,
        int *count_out);

/* ── BIP44 helpers ────────────────────────────────────────────────── */

/* Derive m/44'/147'/account'.
 * `account` must be ≤ BIP44_MAX_ACCOUNT (will be hardened internally).
 * master must be a private ext_key (typically depth=0).            */
struct zcl_result domain_wallet_bip44_derive_account(
        const struct ext_key *master,
        struct ext_key *account_out,
        uint32_t account);

/* Derive m/44'/147'/account'/change. `change` must be 0 (external)
 * or 1 (internal). */
struct zcl_result domain_wallet_bip44_derive_chain(
        const struct ext_key *master,
        struct ext_key *chain_out,
        uint32_t account,
        uint32_t change);

/* Derive m/44'/147'/account'/change/index. Same constraints. */
struct zcl_result domain_wallet_bip44_derive_key(
        const struct ext_key *master,
        struct ext_key *key_out,
        uint32_t account,
        uint32_t change,
        uint32_t index);

/* Format a BIP44 path string into `buf`. Writes
 * "m/44'/147'/<account>'/<change>/<index>".
 *
 * On success *written_out is set to the number of bytes written
 * (excluding the trailing NUL).
 *
 * Errors:
 *   ERR_NULL_BUF        buf == NULL
 *   ERR_NULL_OUT        written_out == NULL
 *   ERR_BUF_TOO_SMALL   buf_size == 0 or result wouldn't fit */
struct zcl_result domain_wallet_bip44_format_path(
        char *buf,
        size_t buf_size,
        uint32_t account,
        uint32_t change,
        uint32_t index,
        int *written_out);

#endif /* ZCL_DOMAIN_WALLET_KEY_DERIVATION_H */
