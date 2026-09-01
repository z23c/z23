/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The recovery-phrase seed: installing it, adopting it, previewing it.
 *
 * Three operations, one subject — the single 32-byte seed a twelve-word
 * recovery phrase determines:
 *
 *   install  (wallet_init_from_recovery_phrase) — turn a phrase into that
 *            seed and root BOTH key trees on it, Sapling via ZIP32 and
 *            transparent via BIP32, on a wallet that has minted nothing yet.
 *
 *   adopt    (wallet_hd_adopt_seed) — a seed just read off disk becomes this
 *            wallet's HD master only if derivation proves it governs the keys
 *            already in the keystore, and the HD counters are then recovered
 *            by scanning the keystore rather than trusting a stored number.
 *
 *   preview  (wallet_seed_address_at) — the address a seed produces at one
 *            BIP44 index, computed without touching any wallet state.
 *
 * The contracts (what each returns, what it refuses, and why declining to
 * adopt is the safe answer for a pre-phrase wallet) are on the declarations
 * in wallet/wallet.h; this file is the derivation, not the contract.
 */

#include "wallet/wallet.h"

#include "wallet/bip44.h"
#include "wallet/mnemonic.h"
#include "keys/key.h"
#include "keys/pubkey.h"
#include "support/cleanse.h"
#include "util/log_macros.h"

#include <stdint.h>
#include <string.h>

bool wallet_seed_address_at(const unsigned char seed[32], uint32_t account,
                            uint32_t change, uint32_t index,
                            char *addr_out, size_t addr_size)
{
    GUARD_NOT_NULL(seed, "wallet", "seed");
    GUARD_NOT_NULL(addr_out, "wallet", "addr_out");

    struct ext_key master;
    if (!hd_master_from_seed(&master, seed, 32)) {
        memory_cleanse(&master, sizeof(master));
        LOG_FAIL("wallet", "seed_address_at: master derivation failed");
    }

    struct privkey priv;
    struct pubkey pub;
    privkey_init(&priv);
    bool ok = bip44_derive_keypair(&master, &priv, &pub, account, change,
                                   index);
    memory_cleanse(&master, sizeof(master));
    memory_cleanse(priv.vch, 32);
    if (!ok)
        LOG_FAIL("wallet", "seed_address_at: derive %u/%u failed",
                 change, index);

    return wallet_pubkey_to_addr(&pub, addr_out, addr_size);
}

bool wallet_init_from_recovery_phrase(struct wallet *w, const char *phrase)
{
    GUARD_NOT_NULL(w, "wallet", "wallet");
    GUARD_NOT_NULL(phrase, "wallet", "phrase");

    /* Validate before deriving so a typo is refused as a typo. The phrase
     * itself never reaches the log — only the fact that it failed. */
    if (!mnemonic_validate(phrase))
        LOG_FAIL("wallet", "recovery phrase failed BIP39 validation "
                           "(word count, wordlist, or checksum)");

    uint8_t seed[MNEMONIC_WALLET_SEED_SIZE];
    if (!mnemonic_to_wallet_seed(phrase, NULL, seed)) {
        memory_cleanse(seed, sizeof(seed));
        LOG_FAIL("wallet", "recovery phrase: seed derivation failed");
    }

    /* One seed, both trees: Sapling (ZIP32) and transparent (BIP32). */
    bool ok = sapling_keystore_set_seed(&w->sapling_keys, seed)
              && wallet_init_hd(w, seed, sizeof(seed));
    memory_cleanse(seed, sizeof(seed));
    if (!ok)
        LOG_FAIL("wallet", "recovery phrase: seed install failed");
    return true;
}

/* Highest index the counter scan will walk. The keystore itself holds at
 * most MAX_KEYSTORE_KEYS entries, so a contiguous run can never be longer
 * than that and the scan always terminates on a real gap first. */
#define WALLET_HD_SCAN_LIMIT MAX_KEYSTORE_KEYS

/* Count the leading run of derived keys already present in the keystore.
 * Stops at the first index that is absent — the next index to hand out. */
static uint32_t wallet_hd_scan_counter(const struct wallet *w,
                                       const struct ext_key *master,
                                       uint32_t change)
{
    uint32_t next = 0;
    for (uint32_t i = 0; i < (uint32_t)WALLET_HD_SCAN_LIMIT; i++) {
        struct privkey priv;
        struct pubkey pub;
        privkey_init(&priv);
        bool derived = bip44_derive_keypair(master, &priv, &pub,
                                            w->hd_account, change, i);
        memory_cleanse(priv.vch, 32);
        if (!derived)
            break;
        struct key_id kid = pubkey_get_id(&pub);
        if (!keystore_have_key(&w->keystore, &kid))
            break;
        next = i + 1;
    }
    return next;
}

bool wallet_hd_adopt_seed(struct wallet *w, const unsigned char seed[32])
{
    GUARD_NOT_NULL(w, "wallet", "wallet");
    GUARD_NOT_NULL(seed, "wallet", "seed");

    struct ext_key master;
    if (!hd_master_from_seed(&master, seed, 32)) {
        memory_cleanse(&master, sizeof(master));
        LOG_FAIL("wallet", "adopt_seed: master derivation failed");
    }

    /* Does this seed govern the keys that are already here? Only external
     * index 0 can answer that, and only by deriving it. */
    bool governs = (w->keystore.num_keys == 0);
    if (!governs) {
        struct privkey priv;
        struct pubkey pub;
        privkey_init(&priv);
        bool derived = bip44_derive_keypair(&master, &priv, &pub, 0,
                                            BIP44_EXTERNAL, 0);
        memory_cleanse(priv.vch, 32);
        if (derived) {
            struct key_id kid = pubkey_get_id(&pub);
            governs = keystore_have_key(&w->keystore, &kid);
        }
    }
    if (!governs) {
        /* A wallet created before recovery phrases. Leave its derivation
         * exactly as it was — legacy random keys, no HD master. */
        memory_cleanse(&master, sizeof(master));
        return false;
    }

    zcl_mutex_lock(&w->cs);
    w->master_key = master;
    w->has_master_key = true;
    w->hd_account = 0;
    zcl_mutex_unlock(&w->cs);

    /* Recover the counters from the keystore rather than storing them: the
     * keys on disk ARE the record of how many indices were handed out. */
    uint32_t ext = wallet_hd_scan_counter(w, &master, BIP44_EXTERNAL);
    uint32_t in = wallet_hd_scan_counter(w, &master, BIP44_INTERNAL);
    zcl_mutex_lock(&w->cs);
    w->hd_external_counter = ext;
    w->hd_internal_counter = in;
    zcl_mutex_unlock(&w->cs);

    memory_cleanse(&master, sizeof(master));
    return true;
}
