/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * BIP44 multi-account hierarchy — thin wrapper layer.
 *
 * Pure derivation math (path-building + ext_key walk) lives in
 * contexts/wallet/domain/key_derivation.{c,h}. This file preserves the
 * original bool-returning API for legacy callers and adds the
 * keypair extraction step (privkey_get_pubkey) that touches the
 * keys/ adapter directly.
 *
 * Path: m/44'/147'/account'/change/index
 */

#include "wallet/bip44.h"

#include "domain/wallet/key_derivation.h"
#include "support/cleanse.h"
#include "util/log_macros.h"

#include <stdio.h>
#include <string.h>

#define DOMAIN "bip44"

bool bip44_derive_account(const struct ext_key *master,
                          struct ext_key *account_out,
                          uint32_t account)
{
    struct zcl_result r = domain_wallet_bip44_derive_account(
            master, account_out, account);
    if (!r.ok)
        LOG_FAIL(DOMAIN, "bip44_derive_account: %s", r.message);
    return true;
}

bool bip44_derive_chain(const struct ext_key *master,
                        struct ext_key *chain_out,
                        uint32_t account, uint32_t change)
{
    struct zcl_result r = domain_wallet_bip44_derive_chain(
            master, chain_out, account, change);
    if (!r.ok)
        LOG_FAIL(DOMAIN, "bip44_derive_chain: %s", r.message);
    return true;
}

bool bip44_derive_key(const struct ext_key *master,
                      struct ext_key *key_out,
                      uint32_t account, uint32_t change, uint32_t index)
{
    struct zcl_result r = domain_wallet_bip44_derive_key(
            master, key_out, account, change, index);
    if (!r.ok)
        LOG_FAIL(DOMAIN, "bip44_derive_key: %s", r.message);
    return true;
}

bool bip44_derive_keypair(const struct ext_key *master,
                          struct privkey *priv_out,
                          struct pubkey *pub_out,
                          uint32_t account, uint32_t change, uint32_t index)
{
    GUARD_NOT_NULL(priv_out, DOMAIN, "priv_out");
    GUARD_NOT_NULL(pub_out, DOMAIN, "pub_out");

    struct ext_key child;
    struct zcl_result r = domain_wallet_bip44_derive_key(
            master, &child, account, change, index);
    if (!r.ok) {
        memory_cleanse(&child, sizeof(child));
        LOG_FAIL(DOMAIN, "bip44_derive_keypair: %s", r.message);
    }

    *priv_out = child.key;
    if (!privkey_get_pubkey(&child.key, pub_out)) {
        memory_cleanse(&child, sizeof(child));
        LOG_FAIL(DOMAIN, "failed to get pubkey for account=%u change=%u index=%u",
                 account, change, index);
    }

    memory_cleanse(&child, sizeof(child));
    return true;
}

int bip44_format_path(char *buf, size_t buf_size,
                      uint32_t account, uint32_t change, uint32_t index)
{
    int written = 0;
    struct zcl_result r = domain_wallet_bip44_format_path(
            buf, buf_size, account, change, index, &written);
    if (!r.ok)
        return -1;
    return written;
}
