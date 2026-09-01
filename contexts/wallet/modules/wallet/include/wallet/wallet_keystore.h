/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Wallet keystore — passphrase-based AES-256-GCM encryption at rest.
 *
 * The legacy wallet stores private keys (transparent WIF + Sapling
 * spending keys) in plain text in the SQLite wallet DB.  An attacker
 * with read access to the wallet file can drain every coin.  This
 * module is the primitive layer for fixing that: a single-blob
 * encrypt/decrypt API that any wallet path can call to wrap a key
 * before it hits disk.
 *
 * Cryptographic design:
 *
 *   - PBKDF2-HMAC-SHA512 for passphrase → key derivation, OpenSSL
 *     `PKCS5_PBKDF2_HMAC` with SHA-512.  Default 200_000 iterations
 *     (operator-tunable up to 10M for enterprise threat models).
 *     Random 16-byte salt, generated per encrypt call.
 *
 *   - AES-256-GCM via OpenSSL EVP for the AEAD, with a fresh random
 *     12-byte nonce per encrypt and a 16-byte authentication tag.
 *     Empty AAD (no associated data — every byte that matters is in
 *     the ciphertext).
 *
 *   - Envelope format on disk (binary):
 *
 *       offset  len  field
 *       ------  ---  -----
 *       0       4    magic       "WKS1"
 *       4       4    version     uint32 BE (currently 1)
 *       8       4    kdf_iters   uint32 BE
 *       12      4    reserved    must be 0 (room for KDF id)
 *       16      16   salt        random per-encrypt
 *       32      12   nonce       random per-encrypt
 *       44      16   auth_tag    GCM tag
 *       60      N    ciphertext  AES-256-GCM(plaintext)
 *
 *     Total envelope size = 60 + plaintext_len bytes.
 *
 * Threat model:
 *
 *   - Disk theft / backup leak: encrypted-at-rest blob is useless
 *     without the passphrase.  PBKDF2 200k iters costs ~150 ms on
 *     a modern CPU, putting a brute-force attack on a 30-char
 *     passphrase out of reach.
 *
 *   - Tampered ciphertext: GCM auth tag fails decrypt, returns
 *     false instead of returning garbage that the caller might
 *     treat as a valid key.
 *
 *   - Side-channel: this module makes NO claims about constant-time
 *     decryption.  OpenSSL EVP is the upstream standard; if a
 *     stronger guarantee is needed, swap to a constant-time impl
 *     under the same API.
 *
 * NON-goals (for this commit):
 *
 *   - Wiring the live wallet save/load path through this module.
 *     The wallet code is 3500 lines spread across keystore.c +
 *     wallet.c + wallet_db.c + wallet_sqlite.c + wallet_key.c, and
 *     a careful refactor needs its own session with regression
 *     coverage on every controller that touches a key.  This
 *     commit ships the primitives and the tests; the integration
 *     is a follow-up.
 */

#ifndef ZCL_WALLET_KEYSTORE_AT_REST_H
#define ZCL_WALLET_KEYSTORE_AT_REST_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define WKS_MAGIC          "WKS1"
#define WKS_MAGIC_LEN      4
#define WKS_HEADER_LEN     60
#define WKS_SALT_LEN       16
#define WKS_NONCE_LEN      12
#define WKS_TAG_LEN        16
#define WKS_KEY_LEN        32

#define WKS_DEFAULT_ITERS  200000
#define WKS_MIN_ITERS      10000
#define WKS_MAX_ITERS      10000000

/* Compute the envelope size for a given plaintext length. */
static inline size_t wks_envelope_size(size_t plaintext_len)
{
    return WKS_HEADER_LEN + plaintext_len;
}

/* Encrypt `plaintext` (plen bytes) under `passphrase` and write the
 * envelope into `out`.  `out_cap` must be at least
 * wks_envelope_size(plen) bytes.  On success returns true and writes
 * the envelope length into *out_len.  On any failure (RNG, KDF,
 * AEAD, buffer too small, NULL passphrase) returns false. */
bool wks_encrypt(const uint8_t *plaintext, size_t plen,
                  const char *passphrase,
                  uint32_t kdf_iterations,
                  uint8_t *out, size_t out_cap, size_t *out_len);

/* Decrypt an envelope produced by wks_encrypt.  Writes plaintext
 * into `out`; `out_cap` must be at least env_len - WKS_HEADER_LEN.
 * Returns false on:
 *   - bad magic / unsupported version
 *   - too-small envelope
 *   - too-small output buffer
 *   - wrong passphrase (GCM tag fails)
 *   - tampered ciphertext (GCM tag fails)
 */
bool wks_decrypt(const uint8_t *envelope, size_t env_len,
                  const char *passphrase,
                  uint8_t *out, size_t out_cap, size_t *out_len);

/* Inspection helper for tests + tooling: read the kdf_iterations
 * value from a header without decrypting.  Returns 0 on a malformed
 * envelope. */
uint32_t wks_envelope_iterations(const uint8_t *envelope, size_t env_len);

/* Convenience: returns the configured default iteration count
 * (honours `ZCL_WALLET_KDF_ITERS` env override clamped to
 * [WKS_MIN_ITERS, WKS_MAX_ITERS]). */
uint32_t wks_default_iterations(void);

/* ── Encryption-at-rest creation policy ───────────────────────── *
 *
 * Wallet private material (transparent WIF keys, Sapling spending
 * keys, HD seed) is written to node.db plaintext unless a passphrase
 * is supplied (ZCL_WALLET_PASSPHRASE). Silently minting a brand-new
 * plaintext wallet is a funds-safety footgun, so the first-run
 * creation path must consult this policy before generating the
 * initial keypool.
 *
 * The decision is purely environment-driven (no wallet handle
 * needed) so it is trivially testable and consistent with the other
 * ZCL_WALLET_* knobs read by this module:
 *
 *   - ZCL_WALLET_PASSPHRASE   non-empty  -> ENCRYPTED
 *   - ZCL_ALLOW_PLAINTEXT_WALLET set/true -> PLAINTEXT_OPTIN
 *     (the node maps the `-allow-plaintext-wallet` CLI flag onto
 *      this env var; treated as false when unset, empty, or "0")
 *   - otherwise                          -> REFUSE
 *
 * Backward compatibility: an EXISTING plaintext wallet must keep
 * opening. REFUSE only blocks creating a NEW plaintext wallet; the
 * caller loads existing keys regardless and merely warns. */
enum wallet_at_rest_policy {
    WALLET_AT_REST_ENCRYPTED = 0,   /* passphrase present */
    WALLET_AT_REST_PLAINTEXT_OPTIN, /* explicit loud opt-in */
    WALLET_AT_REST_REFUSE,          /* no passphrase, no opt-in */
};

/* Evaluate the creation policy from the environment. Pure/reentrant. */
enum wallet_at_rest_policy wallet_at_rest_creation_policy(void);

#ifdef __cplusplus
}
#endif

#endif /* ZCL_WALLET_KEYSTORE_AT_REST_H */
