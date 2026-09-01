/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rhett Creighton
 *
 * Pure BIP32 / BIP44 hierarchical key derivation. Replays from
 * (seed, path) alone — no clock, RNG, allocation, or I/O.
 *
 * The math (HMAC-SHA512 chain code, secp256k1 scalar add) is
 * provided by keys/key.h's ext_key_set_master() and
 * ext_key_derive() / ext_pubkey_derive() primitives. This file
 * gives them a typed contract via zcl_result and a path-aware
 * walking layer.
 */

#include "domain/wallet/key_derivation.h"

#include "support/cleanse.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── Master key from seed ─────────────────────────────────────────── */

struct zcl_result domain_wallet_master_from_seed(
        struct ext_key *master_out,
        const unsigned char *seed,
        size_t seed_len)
{
    if (!master_out)
        return ZCL_ERR(DOMAIN_WALLET_KEY_DERIVATION_ERR_NULL_OUT,
                       "master_from_seed: null master_out");
    if (!seed)
        return ZCL_ERR(DOMAIN_WALLET_KEY_DERIVATION_ERR_NULL_SEED,
                       "master_from_seed: null seed");
    if (seed_len < DOMAIN_WALLET_SEED_MIN_BYTES ||
        seed_len > DOMAIN_WALLET_SEED_MAX_BYTES)
        return ZCL_ERR(DOMAIN_WALLET_KEY_DERIVATION_ERR_SEED_LEN,
                       "master_from_seed: seed_len out of range: %zu", seed_len);

    /* Pure HMAC-SHA512("Bitcoin seed", seed); writes master_out. */
    ext_key_set_master(master_out, seed, (unsigned int)seed_len);

    if (!privkey_is_valid(&master_out->key))
        return ZCL_ERR(DOMAIN_WALLET_KEY_DERIVATION_ERR_INVALID_MASTER,
                       "master_from_seed: derived master scalar invalid (seed_len=%zu)",
                       seed_len);

    return ZCL_OK;
}

/* ── Path derivation (private) ────────────────────────────────────── */

struct zcl_result domain_wallet_derive_path(
        const struct ext_key *parent,
        struct ext_key *child_out,
        const uint32_t *indices,
        int num_indices)
{
    if (!parent)
        return ZCL_ERR(DOMAIN_WALLET_KEY_DERIVATION_ERR_NULL_PARENT,
                       "derive_path: null parent");
    if (!child_out)
        return ZCL_ERR(DOMAIN_WALLET_KEY_DERIVATION_ERR_NULL_OUT,
                       "derive_path: null child_out");
    if (num_indices < 0 || num_indices > DOMAIN_WALLET_MAX_DEPTH)
        return ZCL_ERR(DOMAIN_WALLET_KEY_DERIVATION_ERR_DEPTH,
                       "derive_path: num_indices out of range: %d", num_indices);
    if (num_indices > 0 && !indices)
        return ZCL_ERR(DOMAIN_WALLET_KEY_DERIVATION_ERR_NULL_INDICES,
                       "derive_path: null indices with num_indices=%d", num_indices);

    if (num_indices == 0) {
        *child_out = *parent;
        return ZCL_OK;
    }

    struct ext_key current = *parent;
    for (int i = 0; i < num_indices; i++) {
        struct ext_key next;
        if (!ext_key_derive(&current, &next, indices[i])) {
            /* current/next hold derived BIP32 private scalars + chain
             * codes; wipe both secret intermediates on the error path. */
            memory_cleanse(&next, sizeof(next));
            memory_cleanse(&current, sizeof(current));
            return ZCL_ERR(DOMAIN_WALLET_KEY_DERIVATION_ERR_DERIVE_FAIL,
                           "derive_path: ext_key_derive failed at depth %d index 0x%08x",
                           i, indices[i]);
        }
        current = next;
        memory_cleanse(&next, sizeof(next));
    }

    *child_out = current;
    /* current's last read is the copy above; wipe the secret intermediate. */
    memory_cleanse(&current, sizeof(current));
    return ZCL_OK;
}

struct zcl_result domain_wallet_derive_child_index(
        const struct ext_key *parent,
        struct ext_key *child_out,
        uint32_t index)
{
    if (!parent)
        return ZCL_ERR(DOMAIN_WALLET_KEY_DERIVATION_ERR_NULL_PARENT,
                       "derive_child_index: null parent");
    if (!child_out)
        return ZCL_ERR(DOMAIN_WALLET_KEY_DERIVATION_ERR_NULL_OUT,
                       "derive_child_index: null child_out");

    if (!ext_key_derive(parent, child_out, index))
        return ZCL_ERR(DOMAIN_WALLET_KEY_DERIVATION_ERR_DERIVE_FAIL,
                       "derive_child_index: ext_key_derive failed at index 0x%08x",
                       index);
    return ZCL_OK;
}

/* ── Path derivation (public) ─────────────────────────────────────── */

struct zcl_result domain_wallet_derive_pubkey_path(
        const struct ext_pubkey *parent,
        struct ext_pubkey *child_out,
        const uint32_t *indices,
        int num_indices)
{
    if (!parent)
        return ZCL_ERR(DOMAIN_WALLET_KEY_DERIVATION_ERR_NULL_PARENT,
                       "derive_pubkey_path: null parent");
    if (!child_out)
        return ZCL_ERR(DOMAIN_WALLET_KEY_DERIVATION_ERR_NULL_OUT,
                       "derive_pubkey_path: null child_out");
    if (num_indices < 0 || num_indices > DOMAIN_WALLET_MAX_DEPTH)
        return ZCL_ERR(DOMAIN_WALLET_KEY_DERIVATION_ERR_DEPTH,
                       "derive_pubkey_path: num_indices out of range: %d", num_indices);
    if (num_indices > 0 && !indices)
        return ZCL_ERR(DOMAIN_WALLET_KEY_DERIVATION_ERR_NULL_INDICES,
                       "derive_pubkey_path: null indices with num_indices=%d", num_indices);

    if (num_indices == 0) {
        *child_out = *parent;
        return ZCL_OK;
    }

    struct ext_pubkey current = *parent;
    for (int i = 0; i < num_indices; i++) {
        if (indices[i] & DOMAIN_WALLET_BIP32_HARDENED)
            return ZCL_ERR(DOMAIN_WALLET_KEY_DERIVATION_ERR_HARDENED_PUB,
                           "derive_pubkey_path: hardened index 0x%08x at depth %d "
                           "requires private key", indices[i], i);
        struct ext_pubkey next;
        if (!ext_pubkey_derive(&current, &next, indices[i]))
            return ZCL_ERR(DOMAIN_WALLET_KEY_DERIVATION_ERR_DERIVE_FAIL,
                           "derive_pubkey_path: ext_pubkey_derive failed at depth %d index %u",
                           i, indices[i]);
        current = next;
    }

    *child_out = current;
    return ZCL_OK;
}

/* ── Path string parsing ──────────────────────────────────────────── */

struct zcl_result domain_wallet_parse_path(
        const char *path,
        uint32_t *indices_out,
        int max_indices,
        int *count_out)
{
    if (!path)
        return ZCL_ERR(DOMAIN_WALLET_KEY_DERIVATION_ERR_NULL_PATH,
                       "parse_path: null path");
    if (!indices_out)
        return ZCL_ERR(DOMAIN_WALLET_KEY_DERIVATION_ERR_NULL_INDICES,
                       "parse_path: null indices_out");
    if (!count_out)
        return ZCL_ERR(DOMAIN_WALLET_KEY_DERIVATION_ERR_NULL_OUT,
                       "parse_path: null count_out");
    if (max_indices <= 0)
        return ZCL_ERR(DOMAIN_WALLET_KEY_DERIVATION_ERR_BAD_RANGE,
                       "parse_path: bad max_indices=%d", max_indices);

    const char *p = path;

    /* Skip optional leading "m" or "m/" */
    if (*p == 'm' || *p == 'M') {
        p++;
        if (*p == '/') {
            p++;
            if (*p == '\0')
                return ZCL_ERR(DOMAIN_WALLET_KEY_DERIVATION_ERR_PATH_SYNTAX,
                               "parse_path: trailing slash after master marker");
        }
    }

    if (*p == '\0') {
        *count_out = 0;
        return ZCL_OK;
    }

    int count = 0;
    while (*p != '\0') {
        if (count >= max_indices)
            return ZCL_ERR(DOMAIN_WALLET_KEY_DERIVATION_ERR_PATH_TOOLONG,
                           "parse_path: more than %d components in '%s'",
                           max_indices, path);

        char *endptr;
        errno = 0;
        unsigned long val = strtoul(p, &endptr, 10);
        if (errno != 0 || endptr == p || val > 0x7FFFFFFFu)
            return ZCL_ERR(DOMAIN_WALLET_KEY_DERIVATION_ERR_PATH_SYNTAX,
                           "parse_path: invalid numeric component in '%s'", path);

        uint32_t index = (uint32_t)val;

        /* Hardened marker: ', h, or H. */
        if (*endptr == '\'' || *endptr == 'h' || *endptr == 'H') {
            index |= DOMAIN_WALLET_BIP32_HARDENED;
            endptr++;
        }

        indices_out[count++] = index;

        if (*endptr == '/') {
            endptr++;
            if (*endptr == '\0')
                return ZCL_ERR(DOMAIN_WALLET_KEY_DERIVATION_ERR_PATH_SYNTAX,
                               "parse_path: trailing slash in '%s'", path);
        } else if (*endptr != '\0') {
            return ZCL_ERR(DOMAIN_WALLET_KEY_DERIVATION_ERR_PATH_SYNTAX,
                           "parse_path: unexpected character '%c' in '%s'",
                           *endptr, path);
        }

        p = endptr;
    }

    *count_out = count;
    return ZCL_OK;
}

/* ── BIP44 helpers ────────────────────────────────────────────────── */

struct zcl_result domain_wallet_bip44_derive_account(
        const struct ext_key *master,
        struct ext_key *account_out,
        uint32_t account)
{
    if (!master)
        return ZCL_ERR(DOMAIN_WALLET_KEY_DERIVATION_ERR_NULL_PARENT,
                       "bip44_derive_account: null master");
    if (!account_out)
        return ZCL_ERR(DOMAIN_WALLET_KEY_DERIVATION_ERR_NULL_OUT,
                       "bip44_derive_account: null account_out");
    if (account > DOMAIN_WALLET_BIP44_MAX_ACCOUNT)
        return ZCL_ERR(DOMAIN_WALLET_KEY_DERIVATION_ERR_BAD_RANGE,
                       "bip44_derive_account: account too large: %u", account);

    uint32_t indices[3] = {
        DOMAIN_WALLET_BIP44_PURPOSE  | DOMAIN_WALLET_BIP32_HARDENED,
        DOMAIN_WALLET_BIP44_ZCL_COIN | DOMAIN_WALLET_BIP32_HARDENED,
        account                      | DOMAIN_WALLET_BIP32_HARDENED,
    };
    return domain_wallet_derive_path(master, account_out, indices, 3);
}

struct zcl_result domain_wallet_bip44_derive_chain(
        const struct ext_key *master,
        struct ext_key *chain_out,
        uint32_t account,
        uint32_t change)
{
    if (!master)
        return ZCL_ERR(DOMAIN_WALLET_KEY_DERIVATION_ERR_NULL_PARENT,
                       "bip44_derive_chain: null master");
    if (!chain_out)
        return ZCL_ERR(DOMAIN_WALLET_KEY_DERIVATION_ERR_NULL_OUT,
                       "bip44_derive_chain: null chain_out");
    if (account > DOMAIN_WALLET_BIP44_MAX_ACCOUNT)
        return ZCL_ERR(DOMAIN_WALLET_KEY_DERIVATION_ERR_BAD_RANGE,
                       "bip44_derive_chain: account too large: %u", account);
    if (change != DOMAIN_WALLET_BIP44_EXTERNAL &&
        change != DOMAIN_WALLET_BIP44_INTERNAL)
        return ZCL_ERR(DOMAIN_WALLET_KEY_DERIVATION_ERR_BAD_RANGE,
                       "bip44_derive_chain: change must be 0 or 1, got %u", change);

    uint32_t indices[4] = {
        DOMAIN_WALLET_BIP44_PURPOSE  | DOMAIN_WALLET_BIP32_HARDENED,
        DOMAIN_WALLET_BIP44_ZCL_COIN | DOMAIN_WALLET_BIP32_HARDENED,
        account                      | DOMAIN_WALLET_BIP32_HARDENED,
        change,
    };
    return domain_wallet_derive_path(master, chain_out, indices, 4);
}

struct zcl_result domain_wallet_bip44_derive_key(
        const struct ext_key *master,
        struct ext_key *key_out,
        uint32_t account,
        uint32_t change,
        uint32_t index)
{
    if (!master)
        return ZCL_ERR(DOMAIN_WALLET_KEY_DERIVATION_ERR_NULL_PARENT,
                       "bip44_derive_key: null master");
    if (!key_out)
        return ZCL_ERR(DOMAIN_WALLET_KEY_DERIVATION_ERR_NULL_OUT,
                       "bip44_derive_key: null key_out");
    if (account > DOMAIN_WALLET_BIP44_MAX_ACCOUNT)
        return ZCL_ERR(DOMAIN_WALLET_KEY_DERIVATION_ERR_BAD_RANGE,
                       "bip44_derive_key: account too large: %u", account);
    if (change != DOMAIN_WALLET_BIP44_EXTERNAL &&
        change != DOMAIN_WALLET_BIP44_INTERNAL)
        return ZCL_ERR(DOMAIN_WALLET_KEY_DERIVATION_ERR_BAD_RANGE,
                       "bip44_derive_key: change must be 0 or 1, got %u", change);
    if (index > DOMAIN_WALLET_BIP44_MAX_INDEX)
        return ZCL_ERR(DOMAIN_WALLET_KEY_DERIVATION_ERR_BAD_RANGE,
                       "bip44_derive_key: index too large: %u", index);

    uint32_t indices[5] = {
        DOMAIN_WALLET_BIP44_PURPOSE  | DOMAIN_WALLET_BIP32_HARDENED,
        DOMAIN_WALLET_BIP44_ZCL_COIN | DOMAIN_WALLET_BIP32_HARDENED,
        account                      | DOMAIN_WALLET_BIP32_HARDENED,
        change,
        index,
    };
    return domain_wallet_derive_path(master, key_out, indices, 5);
}

struct zcl_result domain_wallet_bip44_format_path(
        char *buf,
        size_t buf_size,
        uint32_t account,
        uint32_t change,
        uint32_t index,
        int *written_out)
{
    if (!buf)
        return ZCL_ERR(DOMAIN_WALLET_KEY_DERIVATION_ERR_NULL_BUF,
                       "bip44_format_path: null buf");
    if (!written_out)
        return ZCL_ERR(DOMAIN_WALLET_KEY_DERIVATION_ERR_NULL_OUT,
                       "bip44_format_path: null written_out");
    if (buf_size == 0)
        return ZCL_ERR(DOMAIN_WALLET_KEY_DERIVATION_ERR_BUF_TOO_SMALL,
                       "bip44_format_path: zero-size buffer");

    int n = snprintf(buf, buf_size, "m/44'/147'/%u'/%u/%u",
                     account, change, index);
    if (n < 0 || (size_t)n >= buf_size)
        return ZCL_ERR(DOMAIN_WALLET_KEY_DERIVATION_ERR_BUF_TOO_SMALL,
                       "bip44_format_path: buf_size=%zu insufficient for path",
                       buf_size);

    *written_out = n;
    return ZCL_OK;
}
