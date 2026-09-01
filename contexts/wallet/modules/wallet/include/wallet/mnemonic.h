/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * BIP39 mnemonic seed phrases — 12/24 word generation + validation.
 *
 * Generates entropy, maps to words from the BIP39 English wordlist,
 * validates checksums, and derives 512-bit seeds via PBKDF2-HMAC-SHA512
 * (2048 iterations, salt = "mnemonic" + passphrase).
 */

#ifndef ZCL_WALLET_MNEMONIC_H
#define ZCL_WALLET_MNEMONIC_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* BIP39 word counts and corresponding entropy sizes */
#define MNEMONIC_12_WORDS   12   /* 128 bits entropy + 4 bit checksum */
#define MNEMONIC_15_WORDS   15   /* 160 bits entropy + 5 bit checksum */
#define MNEMONIC_18_WORDS   18   /* 192 bits entropy + 6 bit checksum */
#define MNEMONIC_21_WORDS   21   /* 224 bits entropy + 7 bit checksum */
#define MNEMONIC_24_WORDS   24   /* 256 bits entropy + 8 bit checksum */

/* Max buffer sizes */
#define MNEMONIC_MAX_PHRASE_SIZE 512  /* max phrase string length */
#define MNEMONIC_SEED_SIZE 64         /* PBKDF2 output: 512 bits */

/* BIP39 wordlist size */
#define BIP39_WORDLIST_SIZE 2048

/* ── Generation ───────────────────────────────────────────────────── */

/* Generate a new BIP39 mnemonic phrase.
 * word_count must be 12, 15, 18, 21, or 24.
 * phrase_out must be at least MNEMONIC_MAX_PHRASE_SIZE bytes.
 * Returns true on success. */
bool mnemonic_generate(int word_count, char *phrase_out, size_t phrase_size);

/* Generate a mnemonic from provided entropy bytes.
 * entropy_len must be 16, 20, 24, 28, or 32 bytes.
 * Useful for deterministic testing. */
bool mnemonic_from_entropy(const uint8_t *entropy, size_t entropy_len,
                           char *phrase_out, size_t phrase_size);

/* ── Validation ───────────────────────────────────────────────────── */

/* Validate a BIP39 mnemonic phrase.
 * Checks: correct word count, all words in wordlist, valid checksum.
 * Returns true if the mnemonic is valid. */
bool mnemonic_validate(const char *phrase);

/* ── Seed derivation ──────────────────────────────────────────────── */

/* Derive a 512-bit seed from a mnemonic phrase and optional passphrase.
 * Uses PBKDF2-HMAC-SHA512 with 2048 iterations.
 * passphrase may be NULL or "" for no passphrase.
 * seed_out must be at least MNEMONIC_SEED_SIZE (64) bytes. */
bool mnemonic_to_seed(const char *phrase, const char *passphrase,
                      uint8_t seed_out[MNEMONIC_SEED_SIZE]);

/* Size of the wallet seed a recovery phrase determines. */
#define MNEMONIC_WALLET_SEED_SIZE 32

/* Derive THE wallet seed a recovery phrase determines: the first 32 bytes
 * of the BIP39 512-bit seed above.
 *
 * Why 32 and not 64. This wallet persists exactly one seed per wallet, and
 * that column is 32 bytes wide (`wallet_seed.seed`, engine/models/src/
 * database_schema.c) because ZIP32 — the Sapling key tree — takes a 32-byte
 * seed. Both key trees this wallet grows hang off that one value: the
 * shielded tree through zip32_xsk_master(seed, 32) and the transparent tree
 * through hd_master_from_seed(seed, 32). Truncating BIP39's output here is
 * what lets ONE recovery phrase reproduce BOTH, with no second copy of the
 * secret stored anywhere.
 *
 * This mapping is a wire contract: change it and every phrase already
 * written down stops restoring its wallet. It has exactly one definition,
 * this function, and both the create side and the restore side call it.
 *
 * The phrase is normalised before derivation
 * (domain_wallet_mnemonic_normalize, one place, no caller can bypass it):
 * leading and trailing whitespace dropped, internal whitespace runs
 * collapsed to one space. So a phrase pasted out of a text file with a
 * trailing newline, doubled spaces or tab separators derives the SAME
 * seed as the canonical spelling rather than a valid-looking empty
 * wallet. Unicode NFKD is NOT implemented; a phrase carrying a byte
 * ≥ 0x80 is refused outright rather than derived from un-normalised
 * bytes. See the domain header for the full rationale.
 *
 * Returns false (and cleanses) on an invalid phrase or a NULL argument;
 * never logs, echoes, or otherwise reproduces the phrase. */
bool mnemonic_to_wallet_seed(const char *phrase, const char *passphrase,
                             uint8_t seed_out[MNEMONIC_WALLET_SEED_SIZE]);

/* ── Wordlist access ──────────────────────────────────────────────── */

/* Get a word from the BIP39 English wordlist by index (0-2047).
 * Returns NULL if index is out of range. */
const char *mnemonic_wordlist_get(int index);

/* Look up a word in the BIP39 English wordlist.
 * Returns the index (0-2047) or -1 if not found. */
int mnemonic_wordlist_find(const char *word);

#endif /* ZCL_WALLET_MNEMONIC_H */
