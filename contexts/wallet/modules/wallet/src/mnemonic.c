/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * BIP39 mnemonic seed phrases — thin wrapper layer.
 *
 * Pure encoding/validation/PBKDF2 math + the BIP39 English wordlist
 * live in contexts/wallet/domain/mnemonic.{c,h}. This file:
 *   - generates entropy via the platform RNG (impure — stays here);
 *   - cleanses sensitive intermediates with support/cleanse;
 *   - presents the original bool-returning API for legacy callers.
 *
 * Specification: https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
 */

#include "wallet/mnemonic.h"

#include "domain/wallet/mnemonic.h"
#include "core/random.h"
#include "support/cleanse.h"
#include "util/log_macros.h"

#include <string.h>

#define DOMAIN "mnemonic"

/* ── Wordlist access (delegates) ──────────────────────────────────── */

const char *mnemonic_wordlist_get(int index)
{
    return domain_wallet_mnemonic_wordlist_get(index);
}

int mnemonic_wordlist_find(const char *word)
{
    return domain_wallet_mnemonic_wordlist_find(word);
}

/* ── Generation (impure: platform RNG) ────────────────────────────── */

bool mnemonic_generate(int word_count, char *phrase_out, size_t phrase_size)
{
    GUARD_NOT_NULL(phrase_out, DOMAIN, "phrase_out");

    size_t entropy_len =
            domain_wallet_mnemonic_entropy_bytes_for_words(word_count);
    if (entropy_len == 0)
        LOG_FAIL(DOMAIN, "invalid word count: %d (must be 12/15/18/21/24)",
                 word_count);

    uint8_t entropy[32];
    GetRandBytes(entropy, entropy_len);

    size_t written = 0;
    struct zcl_result r = domain_wallet_mnemonic_from_entropy(
            entropy, entropy_len, phrase_out, phrase_size, &written);
    memory_cleanse(entropy, sizeof(entropy));
    if (!r.ok)
        LOG_FAIL(DOMAIN, "mnemonic_generate: %s", r.message);
    return true;
}

bool mnemonic_from_entropy(const uint8_t *entropy, size_t entropy_len,
                           char *phrase_out, size_t phrase_size)
{
    GUARD_NOT_NULL(entropy, DOMAIN, "entropy");
    GUARD_NOT_NULL(phrase_out, DOMAIN, "phrase_out");

    size_t written = 0;
    struct zcl_result r = domain_wallet_mnemonic_from_entropy(
            entropy, entropy_len, phrase_out, phrase_size, &written);
    if (!r.ok)
        LOG_FAIL(DOMAIN, "mnemonic_from_entropy: %s", r.message);
    return true;
}

/* ── Validation (delegates) ───────────────────────────────────────── */

bool mnemonic_validate(const char *phrase)
{
    GUARD_NOT_NULL(phrase, DOMAIN, "phrase");

    struct zcl_result r = domain_wallet_mnemonic_validate(phrase);
    if (!r.ok)
        LOG_FAIL(DOMAIN, "mnemonic_validate: %s", r.message);
    return true;
}

/* ── Seed derivation (delegates) ──────────────────────────────────── */

bool mnemonic_to_seed(const char *phrase, const char *passphrase,
                      uint8_t seed_out[MNEMONIC_SEED_SIZE])
{
    GUARD_NOT_NULL(phrase, DOMAIN, "phrase");
    GUARD_NOT_NULL(seed_out, DOMAIN, "seed_out");

    struct zcl_result r = domain_wallet_mnemonic_to_seed(
            phrase, passphrase, seed_out, MNEMONIC_SEED_SIZE);
    if (!r.ok)
        LOG_FAIL(DOMAIN, "mnemonic_to_seed: %s", r.message);
    return true;
}

bool mnemonic_to_wallet_seed(const char *phrase, const char *passphrase,
                             uint8_t seed_out[MNEMONIC_WALLET_SEED_SIZE])
{
    GUARD_NOT_NULL(phrase, DOMAIN, "phrase");
    GUARD_NOT_NULL(seed_out, DOMAIN, "seed_out");

    uint8_t full[MNEMONIC_SEED_SIZE];
    struct zcl_result r = domain_wallet_mnemonic_to_seed(
            phrase, passphrase, full, sizeof(full));
    if (!r.ok) {
        memory_cleanse(full, sizeof(full));
        /* r.message describes the shape that was wrong (word count,
         * checksum) and never contains the phrase itself. */
        LOG_FAIL(DOMAIN, "mnemonic_to_wallet_seed: %s", r.message);
    }

    memcpy(seed_out, full, MNEMONIC_WALLET_SEED_SIZE);
    memory_cleanse(full, sizeof(full));
    return true;
}
