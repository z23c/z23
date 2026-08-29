/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * base64url, the EC P-256 account key, RFC 7638 thumbprints, and flattened
 * ES256 JWS. See net/acme_jws.h for the contract.
 *
 * base64url is written out here rather than driven through OpenSSL's EVP
 * base64 BIO: the EVP encoder emits the standard alphabet with padding and
 * line breaks, so every call would need three fixups, and the decoder is
 * lenient about characters JWS must reject. A 40-line table encoder that is
 * exactly RFC 4648 §5 is both smaller and strict.
 */

#if !defined(_WIN32)
#define _XOPEN_SOURCE 700
#endif

#include "acme_jws.h"

#include "net/acme_b64url.h"

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/sha.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if !defined(_WIN32)
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#endif

#include "base/log_macros.h"
#include "base/safe_alloc.h"

/* ── the account key ─────────────────────────────────────────────────── */

/* One place decides what "an ACME account key" means for this node. */
static bool key_is_p256(const EVP_PKEY *key)
{
    if (!key)
        return false;
    if (EVP_PKEY_get_base_id(key) != EVP_PKEY_EC)
        return false;
    char group[64] = {0};
    size_t glen = 0;
    if (EVP_PKEY_get_utf8_string_param(key, OSSL_PKEY_PARAM_GROUP_NAME, group,
                                       sizeof(group), &glen) != 1)
        return false;
    return strcmp(group, "prime256v1") == 0 || strcmp(group, "P-256") == 0;
}

EVP_PKEY *acme_account_key_generate(void)
{
    EVP_PKEY *key = EVP_EC_gen("P-256");
    if (!key)
        LOG_NULL("acme", "cannot generate an EC P-256 ACME account key");
    return key;
}

EVP_PKEY *acme_account_key_load(const char *pem_path)
{
    if (!pem_path)
        LOG_NULL("acme", "cannot load an account key without a path");
    FILE *f = fopen(pem_path, "rb");
    if (!f)
        return NULL; /* absent is a normal first-run state, not an error */
    EVP_PKEY *key = PEM_read_PrivateKey(f, NULL, NULL, NULL);
    fclose(f);
    if (!key)
        LOG_NULL("acme", "cannot read a private key from %s", pem_path);
    if (!key_is_p256(key)) {
        EVP_PKEY_free(key);
        LOG_NULL("acme",
                 "refusing the account key at %s: ES256 requires EC P-256 and "
                 "this key is a different algorithm", pem_path);
    }
    return key;
}

bool acme_account_key_save(const EVP_PKEY *key, const char *pem_path)
{
    if (!key || !pem_path)
        LOG_FAIL("acme", "cannot save an account key without a key and a path");
    char tmp[1024];
    const int n = snprintf(tmp, sizeof(tmp), "%s.tmp", pem_path);
    if (n < 0 || (size_t)n >= sizeof(tmp))
        LOG_FAIL("acme", "account key path is too long to stage a temporary file");

    FILE *f = NULL;
#if !defined(_WIN32)
    /* O_EXCL with mode 0600: the private key never exists, even briefly, at
     * permissions another local account could read. */
    (void)unlink(tmp);
    const int fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL, S_IRUSR | S_IWUSR);
    if (fd < 0)
        LOG_FAIL("acme", "cannot create %s for the account key", tmp);
    f = fdopen(fd, "wb");
    if (!f) {
        close(fd);
        LOG_FAIL("acme", "cannot buffer writes to %s", tmp);
    }
#else
    f = fopen(tmp, "wb");
    if (!f)
        LOG_FAIL("acme", "cannot create %s for the account key", tmp);
#endif

    /* EVP_PKEY is const in this API because writing must not mutate the key;
     * the OpenSSL 3.0 writer takes a non-const pointer it does not modify. */
    const int wrote = PEM_write_PrivateKey(f, (EVP_PKEY *)key, NULL, NULL, 0,
                                           NULL, NULL);
    if (wrote != 1) {
        fclose(f);
        remove(tmp);
        LOG_FAIL("acme", "cannot serialize the account key to %s", tmp);
    }
    if (fflush(f) != 0) {
        fclose(f);
        remove(tmp);
        LOG_FAIL("acme", "cannot flush the account key to %s", tmp);
    }
    fclose(f);
    if (rename(tmp, pem_path) != 0) {
        remove(tmp);
        LOG_FAIL("acme", "cannot move the account key into place at %s", pem_path);
    }
    return true;
}

EVP_PKEY *acme_account_key_load_or_create(const char *pem_path)
{
    EVP_PKEY *key = acme_account_key_load(pem_path);
    if (key)
        return key;
    key = acme_account_key_generate();
    if (!key)
        return NULL;
    if (!acme_account_key_save(key, pem_path)) {
        EVP_PKEY_free(key);
        LOG_NULL("acme",
                 "generated an account key but could not persist it at %s; "
                 "refusing to register an identity this node would forget",
                 pem_path);
    }
    return key;
}

/* ── JWK ─────────────────────────────────────────────────────────────── */

static bool p256_coordinates(const EVP_PKEY *key, uint8_t x[32], uint8_t y[32])
{
    if (!key_is_p256(key))
        LOG_FAIL("acme", "refusing a JWK for a key that is not EC P-256");
    BIGNUM *bx = NULL;
    BIGNUM *by = NULL;
    if (EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_EC_PUB_X, &bx) != 1 ||
        EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_EC_PUB_Y, &by) != 1) {
        BN_free(bx);
        BN_free(by);
        LOG_FAIL("acme", "cannot read the public point of the account key");
    }
    const bool ok = BN_bn2binpad(bx, x, 32) == 32 && BN_bn2binpad(by, y, 32) == 32;
    BN_free(bx);
    BN_free(by);
    if (!ok)
        LOG_FAIL("acme", "account key coordinates do not fit 32 bytes each");
    return true;
}

bool acme_jwk_json(const EVP_PKEY *key, char *out, size_t out_len)
{
    if (!out || out_len == 0)
        return false;
    out[0] = '\0';
    uint8_t x[32];
    uint8_t y[32];
    if (!p256_coordinates(key, x, y))
        return false;
    char bx[64];
    char by[64];
    if (acme_b64url_encode(x, sizeof(x), bx, sizeof(bx)) == 0 ||
        acme_b64url_encode(y, sizeof(y), by, sizeof(by)) == 0)
        LOG_FAIL("acme", "cannot base64url the account key coordinates");
    /* RFC 7638 §3.3: only crv, kty, x, y, in lexicographic order, no space. */
    const int n = snprintf(out, out_len,
                           "{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"%s\",\"y\":\"%s\"}",
                           bx, by);
    if (n < 0 || (size_t)n >= out_len)
        LOG_FAIL("acme", "JWK does not fit a %zu-byte buffer", out_len);
    return true;
}

bool acme_jwk_thumbprint(const EVP_PKEY *key, uint8_t out[32])
{
    char jwk[256];
    if (!acme_jwk_json(key, jwk, sizeof(jwk)))
        return false;
    SHA256((const unsigned char *)jwk, strlen(jwk), out);
    return true;
}

/* ── JWS ─────────────────────────────────────────────────────────────── */

bool acme_es256_sign(const EVP_PKEY *key, const void *msg, size_t msg_len,
                     uint8_t sig[64])
{
    if (!key || (!msg && msg_len) || !sig)
        LOG_FAIL("acme", "cannot sign without a key and a message");
    memset(sig, 0, 64);

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx)
        LOG_FAIL("acme", "cannot allocate a signing context");
    unsigned char *der = NULL;
    size_t der_len = 0;
    bool ok = false;
    if (EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, (EVP_PKEY *)key) != 1)
        goto out;
    if (EVP_DigestSign(ctx, NULL, &der_len, msg, msg_len) != 1 || der_len == 0)
        goto out;
    der = zcl_malloc(der_len, "acme_es256_der");
    if (!der)
        goto out;
    if (EVP_DigestSign(ctx, der, &der_len, msg, msg_len) != 1)
        goto out;
    {
        const unsigned char *p = der;
        ECDSA_SIG *ecsig = d2i_ECDSA_SIG(NULL, &p, (long)der_len);
        if (!ecsig)
            goto out;
        const BIGNUM *r = NULL;
        const BIGNUM *s = NULL;
        ECDSA_SIG_get0(ecsig, &r, &s);
        ok = r && s && BN_bn2binpad(r, sig, 32) == 32 &&
             BN_bn2binpad(s, sig + 32, 32) == 32;
        ECDSA_SIG_free(ecsig);
    }
out:
    free(der);
    EVP_MD_CTX_free(ctx);
    if (!ok)
        LOG_FAIL("acme", "ES256 signing failed");
    return true;
}

char *acme_jws_protected_header(const EVP_PKEY *key, const char *kid,
                                const char *nonce, const char *url)
{
    if (!key || !url)
        LOG_NULL("acme", "cannot build a protected header without a key and a url");
    char jwk[256];
    if (!kid && !acme_jwk_json(key, jwk, sizeof(jwk)))
        return NULL;

    /* A nonce or url carrying a quote or backslash would break out of the
     * JSON string; both come from the CA, so refuse rather than escape. */
    const char *checked[3] = {kid, nonce, url};
    for (size_t i = 0; i < 3; i++) {
        for (const char *p = checked[i]; p && *p; p++) {
            if (*p == '"' || *p == '\\' || (unsigned char)*p < 0x20)
                LOG_NULL("acme",
                         "refusing a protected header field carrying a quote, "
                         "backslash or control byte");
        }
    }

    const size_t cap = 1024 + (kid ? strlen(kid) : sizeof(jwk)) +
                       (nonce ? strlen(nonce) : 0) + strlen(url);
    char *out = zcl_malloc(cap, "acme_jws_protected");
    if (!out)
        LOG_NULL("acme", "cannot allocate a protected header");
    int n;
    if (kid) {
        n = nonce ? snprintf(out, cap,
                             "{\"alg\":\"ES256\",\"kid\":\"%s\",\"nonce\":\"%s\","
                             "\"url\":\"%s\"}", kid, nonce, url)
                  : snprintf(out, cap,
                             "{\"alg\":\"ES256\",\"kid\":\"%s\",\"url\":\"%s\"}",
                             kid, url);
    } else {
        n = nonce ? snprintf(out, cap,
                             "{\"alg\":\"ES256\",\"jwk\":%s,\"nonce\":\"%s\","
                             "\"url\":\"%s\"}", jwk, nonce, url)
                  : snprintf(out, cap,
                             "{\"alg\":\"ES256\",\"jwk\":%s,\"url\":\"%s\"}",
                             jwk, url);
    }
    if (n < 0 || (size_t)n >= cap) {
        free(out);
        LOG_NULL("acme", "protected header does not fit its buffer");
    }
    return out;
}

char *acme_jws_body(const EVP_PKEY *key, const char *kid, const char *nonce,
                    const char *url, const char *payload_json)
{
    char *protected_json = acme_jws_protected_header(key, kid, nonce, url);
    if (!protected_json)
        return NULL;

    const size_t protected_len = strlen(protected_json);
    const size_t payload_len = payload_json ? strlen(payload_json) : 0;
    const size_t b64_protected_len = acme_b64url_encoded_len(protected_len);
    /* POST-as-GET (RFC 8555 §6.3): the payload member is "", not b64url(""). */
    const size_t b64_payload_len =
        payload_json ? acme_b64url_encoded_len(payload_len) : 0;

    char *out = NULL;
    char *b64_protected = zcl_malloc(b64_protected_len + 1, "acme_jws_b64p");
    char *b64_payload = zcl_malloc(b64_payload_len + 1, "acme_jws_b64pl");
    if (!b64_protected || !b64_payload)
        goto done;
    if (acme_b64url_encode(protected_json, protected_len, b64_protected,
                           b64_protected_len + 1) != b64_protected_len)
        goto done;
    b64_payload[0] = '\0';
    if (payload_json &&
        acme_b64url_encode(payload_json, payload_len, b64_payload,
                           b64_payload_len + 1) != b64_payload_len)
        goto done;

    {
        const size_t signing_len = b64_protected_len + 1 + b64_payload_len;
        char *signing_input = zcl_malloc(signing_len + 1, "acme_jws_input");
        if (!signing_input)
            goto done;
        memcpy(signing_input, b64_protected, b64_protected_len);
        signing_input[b64_protected_len] = '.';
        memcpy(signing_input + b64_protected_len + 1, b64_payload, b64_payload_len);
        signing_input[signing_len] = '\0';

        uint8_t raw[64];
        const bool signed_ok =
            acme_es256_sign(key, signing_input, signing_len, raw);
        free(signing_input);
        if (!signed_ok)
            goto done;

        char b64_sig[128];
        if (acme_b64url_encode(raw, sizeof(raw), b64_sig, sizeof(b64_sig)) == 0)
            goto done;

        const size_t cap = b64_protected_len + b64_payload_len + sizeof(b64_sig) + 64;
        out = zcl_malloc(cap, "acme_jws_body");
        if (!out)
            goto done;
        const int n = snprintf(out, cap,
                               "{\"protected\":\"%s\",\"payload\":\"%s\","
                               "\"signature\":\"%s\"}",
                               b64_protected, b64_payload, b64_sig);
        if (n < 0 || (size_t)n >= cap) {
            free(out);
            out = NULL;
            goto done;
        }
    }

done:
    free(protected_json);
    free(b64_protected);
    free(b64_payload);
    if (!out)
        LOG_NULL("acme", "cannot build the JWS request body");
    return out;
}
