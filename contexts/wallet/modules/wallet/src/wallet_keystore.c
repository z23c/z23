/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Wallet keystore — implementation.  See wallet_keystore.h for the
 * design notes and envelope format. */

#include "wallet/wallet_keystore.h"

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <stdlib.h>
#include <string.h>

/* ── Helpers ────────────────────────────────────────────────── */

static void put_u32_be(uint8_t *out, uint32_t v)
{
    out[0] = (uint8_t)(v >> 24);
    out[1] = (uint8_t)(v >> 16);
    out[2] = (uint8_t)(v >> 8);
    out[3] = (uint8_t)(v);
}

static uint32_t get_u32_be(const uint8_t *in)
{
    return ((uint32_t)in[0] << 24) | ((uint32_t)in[1] << 16) |
           ((uint32_t)in[2] << 8)  | ((uint32_t)in[3]);
}

uint32_t wks_default_iterations(void)
{
    const char *e = getenv("ZCL_WALLET_KDF_ITERS");
    if (!e || !*e) return WKS_DEFAULT_ITERS;
    char *end = NULL;
    long v = strtol(e, &end, 10);
    if (end == e) return WKS_DEFAULT_ITERS;
    if (v < (long)WKS_MIN_ITERS) return WKS_MIN_ITERS;
    if (v > (long)WKS_MAX_ITERS) return WKS_MAX_ITERS;
    return (uint32_t)v;
}

enum wallet_at_rest_policy wallet_at_rest_creation_policy(void)
{
    /* A non-empty passphrase means keys are wrapped before they hit
     * disk — the safe default. */
    const char *pass = getenv("ZCL_WALLET_PASSPHRASE");
    if (pass && *pass) return WALLET_AT_REST_ENCRYPTED;

    /* Explicit, loud opt-in to a plaintext wallet. Treat unset, empty,
     * and "0" as "not opted in". */
    const char *optin = getenv("ZCL_ALLOW_PLAINTEXT_WALLET");
    if (optin && *optin && strcmp(optin, "0") != 0)
        return WALLET_AT_REST_PLAINTEXT_OPTIN;

    return WALLET_AT_REST_REFUSE;
}

static bool derive_key(const char *passphrase, const uint8_t salt[WKS_SALT_LEN],
                        uint32_t iters, uint8_t key_out[WKS_KEY_LEN])
{
    if (!passphrase || iters < WKS_MIN_ITERS || iters > WKS_MAX_ITERS)
        return false;
    int rc = PKCS5_PBKDF2_HMAC(passphrase, (int)strlen(passphrase),
                                salt, (int)WKS_SALT_LEN,
                                (int)iters,
                                EVP_sha512(),
                                (int)WKS_KEY_LEN, key_out);
    return rc == 1;
}

/* ── Encrypt ────────────────────────────────────────────────── */

bool wks_encrypt(const uint8_t *plaintext, size_t plen,
                  const char *passphrase,
                  uint32_t kdf_iterations,
                  uint8_t *out, size_t out_cap, size_t *out_len)
{
    if (!plaintext && plen > 0) return false;
    if (!passphrase) return false;
    if (!out || !out_len) return false;
    if (out_cap < wks_envelope_size(plen)) return false;
    if (kdf_iterations == 0) kdf_iterations = wks_default_iterations();
    if (kdf_iterations < WKS_MIN_ITERS) kdf_iterations = WKS_MIN_ITERS;
    if (kdf_iterations > WKS_MAX_ITERS) kdf_iterations = WKS_MAX_ITERS;

    uint8_t salt[WKS_SALT_LEN];
    uint8_t nonce[WKS_NONCE_LEN];
    uint8_t key[WKS_KEY_LEN];
    uint8_t tag[WKS_TAG_LEN];

    if (RAND_bytes(salt, (int)sizeof(salt)) != 1) return false;
    if (RAND_bytes(nonce, (int)sizeof(nonce)) != 1) return false;

    if (!derive_key(passphrase, salt, kdf_iterations, key)) {
        OPENSSL_cleanse(key, sizeof(key));
        return false;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        OPENSSL_cleanse(key, sizeof(key));
        return false;
    }

    bool ok = false;
    int outl = 0;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto done;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                             (int)sizeof(nonce), NULL) != 1) goto done;
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) goto done;

    /* Write header first so we can encrypt directly into out + WKS_HEADER_LEN. */
    memcpy(out + 0, WKS_MAGIC, WKS_MAGIC_LEN);
    put_u32_be(out + 4,  1);                /* version */
    put_u32_be(out + 8,  kdf_iterations);
    put_u32_be(out + 12, 0);                /* reserved */
    memcpy(out + 16, salt,  WKS_SALT_LEN);
    memcpy(out + 32, nonce, WKS_NONCE_LEN);
    /* tag goes at offset 44 once we have it */

    if (plen > 0) {
        if (EVP_EncryptUpdate(ctx,
                               out + WKS_HEADER_LEN, &outl,
                               plaintext, (int)plen) != 1) goto done;
        if ((size_t)outl != plen) goto done;
    }

    int final_len = 0;
    uint8_t tmp[16];
    if (EVP_EncryptFinal_ex(ctx, tmp, &final_len) != 1) goto done;
    /* GCM produces no extra final bytes; defensive check anyway. */
    if (final_len != 0) goto done;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG,
                             (int)sizeof(tag), tag) != 1) goto done;
    memcpy(out + 44, tag, WKS_TAG_LEN);

    *out_len = wks_envelope_size(plen);
    ok = true;

done:
    EVP_CIPHER_CTX_free(ctx);
    OPENSSL_cleanse(key, sizeof(key));
    return ok;
}

/* ── Decrypt ────────────────────────────────────────────────── */

bool wks_decrypt(const uint8_t *envelope, size_t env_len,
                  const char *passphrase,
                  uint8_t *out, size_t out_cap, size_t *out_len)
{
    if (!envelope || env_len < WKS_HEADER_LEN) return false;
    if (!passphrase) return false;
    if (!out || !out_len) return false;

    if (memcmp(envelope, WKS_MAGIC, WKS_MAGIC_LEN) != 0) return false;
    uint32_t version = get_u32_be(envelope + 4);
    if (version != 1) return false;
    uint32_t iters = get_u32_be(envelope + 8);
    if (iters < WKS_MIN_ITERS || iters > WKS_MAX_ITERS) return false;

    const uint8_t *salt  = envelope + 16;
    const uint8_t *nonce = envelope + 32;
    const uint8_t *tag   = envelope + 44;

    size_t ct_len = env_len - WKS_HEADER_LEN;
    if (out_cap < ct_len) return false;

    uint8_t key[WKS_KEY_LEN];
    if (!derive_key(passphrase, salt, iters, key)) {
        OPENSSL_cleanse(key, sizeof(key));
        return false;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        OPENSSL_cleanse(key, sizeof(key));
        return false;
    }

    bool ok = false;
    int outl = 0;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto done;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                             WKS_NONCE_LEN, NULL) != 1) goto done;
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) goto done;

    if (ct_len > 0) {
        if (EVP_DecryptUpdate(ctx,
                               out, &outl,
                               envelope + WKS_HEADER_LEN, (int)ct_len) != 1)
            goto done;
        if ((size_t)outl != ct_len) goto done;
    }

    /* Set the expected tag, then finalise.  GCM verification happens
     * inside EVP_DecryptFinal_ex; a non-1 return means tamper / wrong
     * passphrase / wrong nonce. */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG,
                             WKS_TAG_LEN, (void *)(uintptr_t)tag) != 1)
        goto done;

    int final_len = 0;
    uint8_t tmp[16];
    if (EVP_DecryptFinal_ex(ctx, tmp, &final_len) != 1) goto done;
    if (final_len != 0) goto done;

    *out_len = ct_len;
    ok = true;

done:
    EVP_CIPHER_CTX_free(ctx);
    OPENSSL_cleanse(key, sizeof(key));
    return ok;
}

uint32_t wks_envelope_iterations(const uint8_t *envelope, size_t env_len)
{
    if (!envelope || env_len < WKS_HEADER_LEN) return 0;
    if (memcmp(envelope, WKS_MAGIC, WKS_MAGIC_LEN) != 0) return 0;
    uint32_t version = get_u32_be(envelope + 4);
    if (version != 1) return 0;
    return get_u32_be(envelope + 8);
}
