/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ACME's signing layer: base64url (RFC 4648 §5, unpadded), the EC P-256
 * account key, the RFC 7638 JWK thumbprint, and flattened JWS with ES256
 * (RFC 7515 / RFC 7518).
 *
 * Every request an ACME client makes after fetching the directory is a POST
 * whose body is a flattened JWS. The protected header carries `alg`, the
 * anti-replay `nonce`, the request `url`, and EITHER the full public `jwk`
 * (only for newAccount and revokeCert) OR the account `kid` returned by
 * newAccount. Getting that choice wrong is the single most common way an
 * ACME client fails, so the two shapes are separate arguments here rather
 * than a flag: pass kid=NULL to embed the jwk.
 *
 * ES256 signatures are the raw 64-byte R||S concatenation, NOT the DER
 * SEQUENCE OpenSSL produces. The conversion happens here, once.
 */

#ifndef ZCL_ACME_JWS_H
#define ZCL_ACME_JWS_H

#include "net/acme_b64url.h"

#include <openssl/evp.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* ── the account key ─────────────────────────────────────────────────── */

/* Generate a fresh EC P-256 key. Caller owns it (EVP_PKEY_free). */
EVP_PKEY *acme_account_key_generate(void);

/* Load a PEM private key and refuse anything that is not EC P-256 — ES256 is
 * the only algorithm this client signs with, and a key of another type would
 * produce signatures the CA rejects with no useful message. */
EVP_PKEY *acme_account_key_load(const char *pem_path);

/* Write the key to `pem_path` with 0600 permissions, via a temporary file in
 * the same directory renamed into place. */
bool acme_account_key_save(const EVP_PKEY *key, const char *pem_path);

/* Load `pem_path` if it exists and is usable; otherwise generate and save a
 * new key. This is the account identity — losing it means losing the ACME
 * account, so it is created once and never rotated implicitly. */
EVP_PKEY *acme_account_key_load_or_create(const char *pem_path);

/* ── JWK ─────────────────────────────────────────────────────────────── */

/* Canonical RFC 7638 JWK: members in lexicographic order, no whitespace.
 * The byte-exact form matters — the thumbprint is a hash of these bytes. */
bool acme_jwk_json(const EVP_PKEY *key, char *out, size_t out_len);

/* SHA-256 of the canonical JWK (RFC 7638). This is the value that appears
 * base64url-encoded in every key authorization. */
bool acme_jwk_thumbprint(const EVP_PKEY *key, uint8_t out[32]);

/* ── JWS ─────────────────────────────────────────────────────────────── */

/* Raw ES256: SHA-256 the message, sign, and return R||S as 64 bytes. */
bool acme_es256_sign(const EVP_PKEY *key, const void *msg, size_t msg_len,
                     uint8_t sig[64]);

/* Build the protected header JSON. `kid` NULL embeds the public jwk (the
 * newAccount shape); non-NULL uses the account URL (every other request). */
char *acme_jws_protected_header(const EVP_PKEY *key, const char *kid,
                                const char *nonce, const char *url);

/* Build the flattened JWS request body. `payload_json` NULL produces the
 * POST-as-GET shape, whose payload is the empty string rather than the
 * base64url of "". Returns a heap string the caller frees. */
char *acme_jws_body(const EVP_PKEY *key, const char *kid, const char *nonce,
                    const char *url, const char *payload_json);

#endif /* ZCL_ACME_JWS_H */
