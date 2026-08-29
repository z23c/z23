/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The TLS-ALPN-01 (RFC 8737) challenge certificate.
 *
 * The certificate this file builds is never inspected as the in-memory X509
 * the builder returned. It is serialized to DER and parsed back first, so
 * every assertion below is made against the bytes a certificate authority
 * would actually receive on the wire. A structure that was correct only in
 * memory — an extension attached but not encoded, a criticality flag set on
 * the wrong object — would pass a same-object check and fail at the CA.
 */

#include "test/test_core.h"

#include "net/acme_challenge.h"
#include "net/acme_b64url.h"

#include <openssl/asn1.h>
#include <openssl/objects.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <stdio.h>
#include <string.h>

#define AC_CHECK(name, expr) do {                        \
    printf("acme_challenge: %s... ", (name));            \
    if (expr) { printf("OK\n"); }                        \
    else { printf("FAIL\n"); failures++; }               \
} while (0)

/* Round-trip through DER so every later assertion reads the wire form. */
static X509 *reparse(X509 *cert)
{
    unsigned char *der = NULL;
    const int n = i2d_X509(cert, &der);
    if (n <= 0 || !der)
        return NULL;
    const unsigned char *p = der;
    X509 *back = d2i_X509(NULL, &p, n);
    OPENSSL_free(der);
    return back;
}

int test_acme_challenge(void)
{
    int failures = 0;

    /* ── the key authorization ─────────────────────────────────────── */
    uint8_t thumbprint[32];
    for (size_t i = 0; i < 32; i++)
        thumbprint[i] = (uint8_t)(i * 7 + 1);

    char authz[512];
    AC_CHECK("key authorization builds",
             acme_key_authorization("evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ",
                                    thumbprint, authz, sizeof(authz)));
    {
        char expect[512];
        char b64[64];
        acme_b64url_encode(thumbprint, 32, b64, sizeof(b64));
        snprintf(expect, sizeof(expect), "evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ.%s", b64);
        AC_CHECK("key authorization is \"<token>.<base64url(thumbprint)>\"",
                 strcmp(authz, expect) == 0);
    }
    {
        char small[8];
        AC_CHECK("a buffer too small for the key authorization is refused",
                 !acme_key_authorization("token", thumbprint, small, sizeof(small)));
        AC_CHECK("a token with a '.' is refused (it would forge the separator)",
                 !acme_key_authorization("tok.en", thumbprint, authz, sizeof(authz)));
        AC_CHECK("a token with a quote is refused",
                 !acme_key_authorization("tok\"en", thumbprint, authz, sizeof(authz)));
        AC_CHECK("an empty token is refused",
                 !acme_key_authorization("", thumbprint, authz, sizeof(authz)));
        AC_CHECK("a NULL token is refused",
                 !acme_key_authorization(NULL, thumbprint, authz, sizeof(authz)));
    }

    /* Rebuild the good one — the refusal legs above clobbered the buffer. */
    if (!acme_key_authorization("evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ", thumbprint,
                                authz, sizeof(authz)))
        return failures + 1;

    uint8_t digest[32];
    AC_CHECK("the challenge digest computes",
             acme_alpn_challenge_digest(authz, digest));
    {
        uint8_t direct[32];
        SHA256((const unsigned char *)authz, strlen(authz), direct);
        AC_CHECK("the digest is exactly SHA-256 of the key authorization",
                 memcmp(digest, direct, 32) == 0);
    }

    /* ── the certificate, read back from DER ───────────────────────── */
    X509 *cert = NULL;
    EVP_PKEY *key = NULL;
    const bool built = acme_alpn_challenge_certificate("node.example.org", authz,
                                                       &cert, &key);
    AC_CHECK("the challenge certificate builds", built && cert && key);
    if (!built || !cert || !key) {
        X509_free(cert);
        EVP_PKEY_free(key);
        return failures + 1;
    }

    X509 *wire = reparse(cert);
    AC_CHECK("the certificate survives a DER round trip", wire != NULL);
    if (!wire) {
        X509_free(cert);
        EVP_PKEY_free(key);
        return failures + 1;
    }

    AC_CHECK("the wire certificate is X.509 v3", X509_get_version(wire) == 2);
    AC_CHECK("the subjectAltName covers the domain",
             X509_check_host(wire, "node.example.org", 0, 0, NULL) == 1);
    AC_CHECK("the subjectAltName does NOT cover another domain",
             X509_check_host(wire, "other.example.org", 0, 0, NULL) != 1);
    AC_CHECK("the certificate is self-signed by its own key",
             X509_verify(wire, key) == 1);

    {
        ASN1_OBJECT *want = OBJ_txt2obj(ACME_ID_OID_TEXT, 1);
        AC_CHECK("the acmeIdentifier OID resolves", want != NULL);
        const int idx = want ? X509_get_ext_by_OBJ(wire, want, -1) : -1;
        AC_CHECK("the wire certificate carries an extension at 1.3.6.1.5.5.7.1.31",
                 idx >= 0);
        X509_EXTENSION *ext = idx >= 0 ? X509_get_ext(wire, idx) : NULL;
        AC_CHECK("that extension is marked CRITICAL",
                 ext && X509_EXTENSION_get_critical(ext) == 1);

        ASN1_OCTET_STRING *raw = ext ? X509_EXTENSION_get_data(ext) : NULL;
        AC_CHECK("the extension carries a value", raw != NULL);
        if (raw) {
            const unsigned char *p = ASN1_STRING_get0_data(raw);
            const int n = ASN1_STRING_length(raw);
            ASN1_OCTET_STRING *inner = d2i_ASN1_OCTET_STRING(NULL, &p, n);
            AC_CHECK("the extension value is a DER OCTET STRING", inner != NULL);
            AC_CHECK("the OCTET STRING holds exactly 32 bytes",
                     inner && ASN1_STRING_length(inner) == 32);
            AC_CHECK("those 32 bytes are SHA-256 of the key authorization",
                     inner && ASN1_STRING_length(inner) == 32 &&
                     memcmp(ASN1_STRING_get0_data(inner), digest, 32) == 0);
            /* The inner DER must consume the whole extnValue: trailing bytes
             * after a well-formed OCTET STRING would be a second, unnoticed
             * payload. */
            AC_CHECK("nothing trails the OCTET STRING inside extnValue",
                     inner && p == ASN1_STRING_get0_data(raw) + n);
            ASN1_OCTET_STRING_free(inner);
        } else {
            failures += 4;
        }
        ASN1_OBJECT_free(want);
    }

    {
        /* A different key authorization must produce different payload bytes;
         * otherwise the challenge would be answerable by anyone. */
        char other_authz[512];
        uint8_t other_thumb[32];
        memset(other_thumb, 0xAB, sizeof(other_thumb));
        X509 *c2 = NULL;
        EVP_PKEY *k2 = NULL;
        const bool ok =
            acme_key_authorization("evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ",
                                   other_thumb, other_authz, sizeof(other_authz)) &&
            acme_alpn_challenge_certificate("node.example.org", other_authz,
                                            &c2, &k2);
        uint8_t d2[32];
        AC_CHECK("a different account key yields a different challenge digest",
                 ok && acme_alpn_challenge_digest(other_authz, d2) &&
                 memcmp(d2, digest, 32) != 0);
        X509_free(c2);
        EVP_PKEY_free(k2);
    }

    /* ── refusals ──────────────────────────────────────────────────── */
    {
        X509 *c = (X509 *)1;
        EVP_PKEY *k = (EVP_PKEY *)1;
        AC_CHECK("a domain with a slash is refused",
                 !acme_alpn_challenge_certificate("node.example.org/x", authz, &c, &k) &&
                 c == NULL && k == NULL);
        AC_CHECK("an empty domain is refused",
                 !acme_alpn_challenge_certificate("", authz, &c, &k));
        AC_CHECK("a NULL domain is refused",
                 !acme_alpn_challenge_certificate(NULL, authz, &c, &k));
        AC_CHECK("a label over 63 characters is refused",
                 !acme_alpn_challenge_certificate(
                     "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                     ".example.org", authz, &c, &k));
        AC_CHECK("an empty key authorization is refused",
                 !acme_alpn_challenge_certificate("node.example.org", "", &c, &k));
    }

    /* ── the armed state ───────────────────────────────────────────── */
    {
        AC_CHECK("the responder starts disarmed", !acme_alpn_challenge_armed());
        AC_CHECK("arming succeeds",
                 acme_alpn_challenge_arm("node.example.org", authz));
        AC_CHECK("the responder reports armed", acme_alpn_challenge_armed());
        AC_CHECK("re-arming for another name succeeds",
                 acme_alpn_challenge_arm("other.example.org", authz));
        acme_alpn_challenge_disarm();
        AC_CHECK("disarming clears the armed state", !acme_alpn_challenge_armed());
        acme_alpn_challenge_disarm();
        AC_CHECK("disarming twice is harmless", !acme_alpn_challenge_armed());
        AC_CHECK("arming with a bad domain leaves the responder disarmed",
                 !acme_alpn_challenge_arm("bad domain", authz) &&
                 !acme_alpn_challenge_armed());
    }

    /* ── the node/worker handoff file ──────────────────────────────── */
    {
        char dir[512];
        char path[640];
        test_make_tmpdir(dir, sizeof(dir), "acme_challenge", "handoff");
        snprintf(path, sizeof(path), "%s/challenge.txt", dir);

        char domain[ACME_MAX_DOMAIN + 1];
        char authz_back[ACME_MAX_KEY_AUTHZ];
        AC_CHECK("reading an absent handoff file is not an error, just absent",
                 !acme_arm_file_read(path, domain, sizeof(domain), authz_back,
                                     sizeof(authz_back)));
        AC_CHECK("the worker writes the handoff pair",
                 acme_arm_file_write(path, "node.example.org", authz));
        AC_CHECK("the node reads back exactly what the worker wrote",
                 acme_arm_file_read(path, domain, sizeof(domain), authz_back,
                                    sizeof(authz_back)) &&
                 strcmp(domain, "node.example.org") == 0 &&
                 strcmp(authz_back, authz) == 0);
        AC_CHECK("arming straight from the handoff file works",
                 acme_alpn_challenge_arm_from_file(path) &&
                 acme_alpn_challenge_armed());
        acme_alpn_challenge_disarm();

        AC_CHECK("a handoff carrying a newline in a field is refused at write",
                 !acme_arm_file_write(path, "node.example.org", "bad\nvalue"));
        AC_CHECK("a handoff carrying a shell metacharacter is refused at write",
                 !acme_arm_file_write(path, "node.example.org", "a;rm -rf /"));
        AC_CHECK("a handoff with no domain is refused at write",
                 !acme_arm_file_write(path, "", authz));

        {
            FILE *f = fopen(path, "wb");
            if (f) {
                fputs("domain=node.example.org\n", f);
                fclose(f);
            }
            AC_CHECK("a handoff missing the keyauth line is refused at read",
                     !acme_arm_file_read(path, domain, sizeof(domain),
                                         authz_back, sizeof(authz_back)) &&
                     domain[0] == '\0');
            AC_CHECK("and arming from it leaves the responder disarmed",
                     !acme_alpn_challenge_arm_from_file(path) &&
                     !acme_alpn_challenge_armed());
        }
        {
            FILE *f = fopen(path, "wb");
            if (f) {
                fputs("domain=node.example.org\nkeyauth=has space\n", f);
                fclose(f);
            }
            AC_CHECK("a handoff whose value carries a space is refused at read",
                     !acme_arm_file_read(path, domain, sizeof(domain),
                                         authz_back, sizeof(authz_back)));
        }
        AC_CHECK("clearing removes the handoff file",
                 acme_arm_file_clear(path) &&
                 !acme_arm_file_read(path, domain, sizeof(domain), authz_back,
                                     sizeof(authz_back)));
        AC_CHECK("clearing an already-absent handoff is harmless",
                 acme_arm_file_clear(path));
        test_rm_rf(dir);
    }

    /* ── the front-door seam ───────────────────────────────────────── */
    {
        AC_CHECK("installing on no TLS context is refused", !acme_alpn_install(NULL));
        SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
        AC_CHECK("the responder installs on a server context",
                 ctx && acme_alpn_install(ctx));
        SSL_CTX_free(ctx);
    }

    X509_free(wire);
    X509_free(cert);
    EVP_PKEY_free(key);
    return failures;
}
