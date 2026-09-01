/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rhett Creighton
 *
 * contexts/wallet/domain/mnemonic.h — pure BIP39 mnemonic encoding + PBKDF2 seed.
 *
 * Given entropy bytes (or a mnemonic phrase) and an optional passphrase,
 * encode/decode BIP39 mnemonics and derive the 512-bit BIP39 seed.
 * This is pure SHA-256 (checksum) + PBKDF2-HMAC-SHA512 + wordlist lookup
 * with no I/O, no clock, no RNG, no persistence:
 *
 *   - entropy → mnemonic:    ENT bits + (ENT/32) checksum bits → 11-bit words
 *   - mnemonic → entropy:    inverse mapping, validates checksum
 *   - validation:            words-in-list + checksum verification
 *   - PBKDF2 seed:           "mnemonic"+passphrase salt, 2048 SHA-512 rounds
 *   - wordlist:              BIP39 English 2048-word list (lookup + index)
 *
 * The wallet's *random* entropy generation (impure: platform.rng) stays
 * in contexts/wallet/. Buffer cleansing (memory_cleanse, support/cleanse) is
 * a property of the caller's lifetime, not derivation math, so the
 * wrappers do it. This header covers only the pure math + wordlist.
 *
 * Layering: contexts/wallet/domain/ may #include from util/, core/, crypto/,
 * keys/, primitives/. This file depends only on crypto/ and util/.
 *
 * The contexts/wallet/ header (wallet/mnemonic.h) remains the public API for
 * wallet callers; its .c file is a thin wrapper preserving the existing
 * bool-returning signatures (and GUARD_NOT_NULL / LOG_FAIL behaviour).
 */

#ifndef ZCL_DOMAIN_WALLET_MNEMONIC_H
#define ZCL_DOMAIN_WALLET_MNEMONIC_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "util/result.h"

/* BIP39 fixed constants (per the canonical spec). */
#define DOMAIN_WALLET_BIP39_WORDLIST_SIZE   2048
#define DOMAIN_WALLET_BIP39_SEED_BYTES      64   /* PBKDF2-HMAC-SHA512 output */
#define DOMAIN_WALLET_BIP39_PBKDF2_ROUNDS   2048u
#define DOMAIN_WALLET_BIP39_MAX_WORDS       24
#define DOMAIN_WALLET_BIP39_MIN_WORDS       12

/* Entropy length bounds (in bytes): {16, 20, 24, 28, 32}. */
#define DOMAIN_WALLET_BIP39_ENTROPY_MIN     16
#define DOMAIN_WALLET_BIP39_ENTROPY_MAX     32

/* Conservative bound on the phrase string size including trailing NUL.
 * 24 words × max-word-length (8 chars: "satoshi"/"abandon" etc) + 23
 * separators + NUL = ~216 in practice; round up generously. */
#define DOMAIN_WALLET_BIP39_PHRASE_MAX      512

/* ── Error codes (stable, appended on extension) ──────────────────── */

enum domain_wallet_mnemonic_err {
    DOMAIN_WALLET_MNEMONIC_ERR_NULL_OUT       = 1301,
    DOMAIN_WALLET_MNEMONIC_ERR_NULL_ENTROPY   = 1302,
    DOMAIN_WALLET_MNEMONIC_ERR_NULL_PHRASE    = 1303,
    DOMAIN_WALLET_MNEMONIC_ERR_NULL_SEED      = 1304,
    DOMAIN_WALLET_MNEMONIC_ERR_NULL_BUF       = 1305,
    DOMAIN_WALLET_MNEMONIC_ERR_ENTROPY_LEN    = 1306,
    DOMAIN_WALLET_MNEMONIC_ERR_BUF_TOO_SMALL  = 1307,
    DOMAIN_WALLET_MNEMONIC_ERR_BAD_WORD_COUNT = 1308,
    DOMAIN_WALLET_MNEMONIC_ERR_UNKNOWN_WORD   = 1309,
    DOMAIN_WALLET_MNEMONIC_ERR_CHECKSUM       = 1310,
    DOMAIN_WALLET_MNEMONIC_ERR_PHRASE_LEN     = 1311,
    DOMAIN_WALLET_MNEMONIC_ERR_BAD_RANGE      = 1312,
    DOMAIN_WALLET_MNEMONIC_ERR_NON_ASCII      = 1313,
};

/* ── Canonical form ───────────────────────────────────────────────── */

/* Normalise a mnemonic into the ONE form every derivation in this tree
 * runs on: words separated by exactly one ASCII space, no leading or
 * trailing whitespace.
 *
 * Why this exists. BIP39 derives the seed by running PBKDF2 over the
 * phrase BYTES. So "  abandon  abandon" and "abandon abandon" are
 * different inputs and derive different seeds — and because the word
 * tokeniser skips runs of spaces, the sloppy one still passes checksum
 * validation. A user pasting their words out of a text file, a chat
 * message or a photo transcription therefore got a valid-looking, empty,
 * WRONG wallet and was told it worked. Collapsing the whitespace first,
 * in one place both validation and derivation go through, is what closes
 * that.
 *
 * What is normalised: leading/trailing ASCII whitespace is dropped and
 * every internal run of ASCII whitespace (space, tab, newline, carriage
 * return, vertical tab, form feed) collapses to a single space.
 *
 * What is NOT normalised, deliberately:
 *
 *   - UNICODE. BIP39 specifies NFKD over UTF-8, which needs the Unicode
 *     decomposition tables; this tree ships no Unicode library and takes
 *     no external dependency to get one, so NFKD is NOT implemented. It
 *     is also not needed for what this node accepts: the BIP39 English
 *     wordlist is pure lowercase ASCII, and NFKD is the identity on
 *     ASCII. Rather than half-implement it, any phrase carrying a byte
 *     ≥ 0x80 is REFUSED with ERR_NON_ASCII — a loud "this node cannot
 *     normalise that phrase" instead of a silent derivation from
 *     un-normalised bytes, which is the failure this whole function
 *     exists to prevent. A non-English wordlist would need real NFKD
 *     before it could be accepted.
 *
 *   - CASE. The seed is defined over the literal phrase, so folding case
 *     here would silently deviate from BIP39. It costs nothing to leave
 *     alone: every phrase this node emits is lowercase, and a
 *     capitalised word fails the wordlist lookup loudly (ERR_UNKNOWN_WORD)
 *     rather than deriving a wrong seed.
 *
 * `out` is NUL-terminated on success and *written_out (optional) carries
 * the length excluding the NUL. An all-whitespace or empty phrase
 * normalises to the empty string and is left for the word-count check to
 * refuse.
 *
 * Errors:
 *   ERR_NULL_PHRASE     phrase == NULL
 *   ERR_NULL_BUF        out == NULL or out_size == 0
 *   ERR_BUF_TOO_SMALL   the normalised phrase does not fit in out_size
 *   ERR_NON_ASCII       a byte ≥ 0x80 (see above)
 *
 * Pure. */
struct zcl_result domain_wallet_mnemonic_normalize(const char *phrase,
                                                   char *out,
                                                   size_t out_size,
                                                   size_t *written_out);

/* ── Wordlist (BIP39 English) ─────────────────────────────────────── */

/* Return the word at `index` in the BIP39 English wordlist.
 *
 *   index in [0, DOMAIN_WALLET_BIP39_WORDLIST_SIZE).
 *
 * Returns NULL if index is out of range. Pure: a static const lookup. */
const char *domain_wallet_mnemonic_wordlist_get(int index);

/* Look up `word` in the BIP39 English wordlist. Returns the index in
 * [0, DOMAIN_WALLET_BIP39_WORDLIST_SIZE) on success, or -1 on miss
 * (or if word == NULL).
 *
 * Pure: binary search over the sorted static list. */
int domain_wallet_mnemonic_wordlist_find(const char *word);

/* ── Entropy → mnemonic ───────────────────────────────────────────── */

/* Encode `entropy_len` bytes of entropy into a BIP39 mnemonic phrase.
 *
 *   entropy_len ∈ {16, 20, 24, 28, 32} (yields 12/15/18/21/24 words).
 *   phrase_out: caller buffer, NUL-terminated on success.
 *   phrase_size: capacity of phrase_out (must include room for NUL).
 *   *written_out: on success, bytes written excluding NUL.
 *
 * Errors:
 *   ERR_NULL_ENTROPY    entropy == NULL
 *   ERR_NULL_BUF        phrase_out == NULL
 *   ERR_NULL_OUT        written_out == NULL
 *   ERR_ENTROPY_LEN     entropy_len not in the allowed set
 *   ERR_BUF_TOO_SMALL   phrase_size insufficient for the resulting phrase
 *
 * Pure: SHA-256 over entropy for the checksum, plus wordlist lookup. */
struct zcl_result domain_wallet_mnemonic_from_entropy(
        const uint8_t *entropy,
        size_t entropy_len,
        char *phrase_out,
        size_t phrase_size,
        size_t *written_out);

/* ── Mnemonic → entropy (round-trip primitive) ────────────────────── */

/* Decode a BIP39 mnemonic phrase to raw entropy bytes. Validates the
 * checksum as part of decoding; an invalid checksum returns ERR_CHECKSUM
 * and *entropy_len_out is left zero.
 *
 *   phrase: NUL-terminated, space-separated words.
 *   entropy_out: caller buffer of at least entropy_capacity bytes.
 *   entropy_capacity: must be ≥ DOMAIN_WALLET_BIP39_ENTROPY_MAX (32).
 *   *entropy_len_out: bytes written on success.
 *
 * Errors:
 *   ERR_NULL_PHRASE     phrase == NULL
 *   ERR_NULL_OUT        entropy_out or entropy_len_out == NULL
 *   ERR_BUF_TOO_SMALL   entropy_capacity < 32
 *   ERR_PHRASE_LEN      phrase string length exceeds the internal cap
 *   ERR_BAD_WORD_COUNT  not 12/15/18/21/24 words
 *   ERR_UNKNOWN_WORD    a token is not in the BIP39 English wordlist
 *   ERR_CHECKSUM        checksum bits don't match SHA-256 prefix
 *
 * Pure. */
struct zcl_result domain_wallet_mnemonic_to_entropy(
        const char *phrase,
        uint8_t *entropy_out,
        size_t entropy_capacity,
        size_t *entropy_len_out);

/* ── Validation ───────────────────────────────────────────────────── */

/* Validate a BIP39 mnemonic phrase. Equivalent to mnemonic_to_entropy
 * but without exposing the decoded entropy buffer.
 *
 * Same error codes as mnemonic_to_entropy (minus the buf-too-small/null
 * cases that don't apply). */
struct zcl_result domain_wallet_mnemonic_validate(const char *phrase);

/* ── PBKDF2 seed derivation ───────────────────────────────────────── */

/* Derive a 512-bit BIP39 seed from a mnemonic phrase and optional
 * passphrase. Uses PBKDF2-HMAC-SHA512, 2048 rounds, salt =
 * "mnemonic" || passphrase.
 *
 * The PHRASE is run through domain_wallet_mnemonic_normalize() first, so
 * a phrase with a leading space, a trailing newline, doubled spaces or
 * tab separators derives the SAME seed as the canonical spelling instead
 * of a different, valid-looking, empty wallet. Read that function's
 * contract for exactly what is and is not normalised — in particular,
 * full NFKD is not implemented and a non-ASCII phrase is refused.
 *
 * The PASSPHRASE is used as-given: it is an arbitrary secret string, not
 * a list of words, and collapsing whitespace in it would change a
 * deliberate secret.
 *
 *   phrase: NUL-terminated mnemonic phrase.
 *   passphrase: NUL-terminated; NULL is treated as "".
 *   seed_out: caller buffer, exactly DOMAIN_WALLET_BIP39_SEED_BYTES.
 *   seed_capacity: must be ≥ DOMAIN_WALLET_BIP39_SEED_BYTES.
 *
 * Errors:
 *   ERR_NULL_PHRASE     phrase == NULL
 *   ERR_NULL_SEED       seed_out == NULL
 *   ERR_BUF_TOO_SMALL   seed_capacity < 64
 *   ERR_PHRASE_LEN      passphrase length pushes the salt past the cap,
 *                       or the phrase exceeds DOMAIN_WALLET_BIP39_PHRASE_MAX
 *   ERR_NON_ASCII       the phrase carries a byte ≥ 0x80
 *
 * Pure: the BIP39 spec defines this as derivation, not generation. */
struct zcl_result domain_wallet_mnemonic_to_seed(
        const char *phrase,
        const char *passphrase,
        uint8_t *seed_out,
        size_t seed_capacity);

/* ── Bytes-needed introspection ───────────────────────────────────── */

/* Map a word_count ∈ {12,15,18,21,24} to its entropy byte count
 * ({16,20,24,28,32}). Returns 0 on bad input.
 *
 * Convenience for callers sizing buffers before encoding. */
size_t domain_wallet_mnemonic_entropy_bytes_for_words(int word_count);

#endif /* ZCL_DOMAIN_WALLET_MNEMONIC_H */
