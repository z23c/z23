/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The certificate worker's offline protocol assertions: the RFC 7638 JWK
 * thumbprint, ES256 JWS, the recorded ACME response fixtures, and the CSR.
 *
 * The signature legs do not trust our own signer: every signature produced
 * here is fed back through OpenSSL's verifier over the exact bytes the CA
 * would verify ("<b64url protected>.<b64url payload>"), after being
 * re-encoded from the raw 64-byte R||S form into the DER sequence OpenSSL
 * expects. A signer that agreed only with itself would pass a round-trip
 * test and fail against Let's Encrypt; this one cannot.
 *
 * The wire legs are fed recorded response bodies. The good ones are the
 * shapes Boulder actually returns, trimmed to the members this client
 * reads; the rest are the shapes a broken or hostile endpoint returns, and
 * they are the point — a parser that only ever sees well-formed input is a
 * parser whose refusals have never been executed. A live staging run cannot
 * produce a missing member or a 4 KB URL on demand.
 */

#include "acme_selftest.h"

#include "acme_jws.h"
#include "acme_protocol.h"

#include "json/json.h"

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "platform/temp_directory.h"

#include <dirent.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

/* A private scratch directory, and its removal. Removal is local rather than
 * borrowed from lib/test: this program is not linked against the test
 * harness. The CREATE is not local, because mkdtemp(3) is POSIX-only — the
 * mingw CRT neither declares nor exports it — and this worker now ships for
 * Windows too. platform_temp_directory_create() is the seam's own answer to
 * exactly that, and it is race-free on both arms (see its header). */
static bool selftest_tmpdir(char *buf, size_t n)
{
    return platform_temp_directory_create("zcl-acme-selftest-", buf, n);
}

static void selftest_rmrf(const char *dir)
{
    DIR *d = opendir(dir);
    if (!d)
        return;
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (ent->d_name[0] == '.' &&
            (ent->d_name[1] == '\0' ||
             (ent->d_name[1] == '.' && ent->d_name[2] == '\0')))
            continue;
        char path[1024];
        if (snprintf(path, sizeof(path), "%s/%s", dir, ent->d_name) <
            (int)sizeof(path))
            unlink(path);
    }
    closedir(d);
    rmdir(dir);
}

#define AJ_CHECK(name, expr) do {                    \
    printf("acme_jws: %s... ", (name));              \
    if (expr) { printf("OK\n"); }                    \
    else { printf("FAIL\n"); failures++; }           \
} while (0)

/* Verify a raw R||S ES256 signature the way a CA does: rebuild the DER
 * sequence and hand it to OpenSSL over the same message bytes. */
static bool verify_es256(EVP_PKEY *key, const void *msg, size_t msg_len,
                         const uint8_t sig[64])
{
    ECDSA_SIG *ecsig = ECDSA_SIG_new();
    BIGNUM *r = BN_bin2bn(sig, 32, NULL);
    BIGNUM *s = BN_bin2bn(sig + 32, 32, NULL);
    unsigned char *der = NULL;
    bool ok = false;
    if (!ecsig || !r || !s)
        goto done;
    if (ECDSA_SIG_set0(ecsig, r, s) != 1)
        goto done;
    r = NULL;
    s = NULL;
    {
        const int der_len = i2d_ECDSA_SIG(ecsig, &der);
        if (der_len <= 0)
            goto done;
        EVP_MD_CTX *ctx = EVP_MD_CTX_new();
        if (!ctx)
            goto done;
        ok = EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, key) == 1 &&
             EVP_DigestVerify(ctx, der, (size_t)der_len, msg, msg_len) == 1;
        EVP_MD_CTX_free(ctx);
    }
done:
    OPENSSL_free(der);
    BN_free(r);
    BN_free(s);
    ECDSA_SIG_free(ecsig);
    return ok;
}


static int selftest_jws(void)
{
    int failures = 0;

    /* ── the account key and its JWK ───────────────────────────────── */
    EVP_PKEY *key = acme_account_key_generate();
    AJ_CHECK("an EC P-256 account key is generated", key != NULL);
    if (!key)
        return failures + 1;

    char jwk[256];
    AJ_CHECK("the JWK renders", acme_jwk_json(key, jwk, sizeof(jwk)));
    AJ_CHECK("the JWK members are in RFC 7638 lexicographic order with no space",
             strncmp(jwk, "{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"", 31) == 0 &&
             strstr(jwk, "\",\"y\":\"") != NULL &&
             strchr(jwk, ' ') == NULL);
    {
        struct json_value doc = {0};
        const bool parsed = json_read(&doc, jwk, strlen(jwk));
        const struct json_value *x = parsed ? json_get(&doc, "x") : NULL;
        const struct json_value *y = parsed ? json_get(&doc, "y") : NULL;
        uint8_t raw[64];
        size_t xn = 0;
        size_t yn = 0;
        AJ_CHECK("x and y are 32-byte base64url coordinates",
                 x && y && json_get_str(x) && json_get_str(y) &&
                 acme_b64url_decode(json_get_str(x), raw, sizeof(raw), &xn) &&
                 acme_b64url_decode(json_get_str(y), raw, sizeof(raw), &yn) &&
                 xn == 32 && yn == 32);
        json_free(&doc);
    }
    {
        uint8_t t1[32];
        uint8_t t2[32];
        uint8_t direct[32];
        AJ_CHECK("the thumbprint computes", acme_jwk_thumbprint(key, t1));
        AJ_CHECK("the thumbprint is stable across calls",
                 acme_jwk_thumbprint(key, t2) && memcmp(t1, t2, 32) == 0);
        SHA256((const unsigned char *)jwk, strlen(jwk), direct);
        AJ_CHECK("the thumbprint is exactly SHA-256 of the canonical JWK",
                 memcmp(t1, direct, 32) == 0);

        EVP_PKEY *other = acme_account_key_generate();
        uint8_t t3[32];
        AJ_CHECK("a different key has a different thumbprint",
                 other && acme_jwk_thumbprint(other, t3) &&
                 memcmp(t1, t3, 32) != 0);
        EVP_PKEY_free(other);
    }

    /* ── raw ES256 ─────────────────────────────────────────────────── */
    {
        static const char msg[] = "the CA will verify exactly these bytes";
        uint8_t sig[64];
        AJ_CHECK("ES256 signs", acme_es256_sign(key, msg, sizeof(msg) - 1, sig));
        AJ_CHECK("OpenSSL verifies the raw R||S signature",
                 verify_es256(key, msg, sizeof(msg) - 1, sig));
        uint8_t tampered[64];
        memcpy(tampered, sig, 64);
        tampered[0] ^= 0x01;
        AJ_CHECK("a flipped bit in R fails verification",
                 !verify_es256(key, msg, sizeof(msg) - 1, tampered));
        memcpy(tampered, sig, 64);
        tampered[63] ^= 0x01;
        AJ_CHECK("a flipped bit in S fails verification",
                 !verify_es256(key, msg, sizeof(msg) - 1, tampered));
        AJ_CHECK("a different message fails verification",
                 !verify_es256(key, "other", 5, sig));
    }

    /* ── the flattened JWS the CA actually receives ────────────────── */
    {
        char *body = acme_jws_body(key, NULL, "nonceAAA",
                                   "https://ca.example/acme/new-acct",
                                   "{\"termsOfServiceAgreed\":true}");
        AJ_CHECK("newAccount JWS builds", body != NULL);
        if (body) {
            struct json_value doc = {0};
            const bool parsed = json_read(&doc, body, strlen(body));
            const struct json_value *p = parsed ? json_get(&doc, "protected") : NULL;
            const struct json_value *pl = parsed ? json_get(&doc, "payload") : NULL;
            const struct json_value *sg = parsed ? json_get(&doc, "signature") : NULL;
            AJ_CHECK("the JWS is a flattened object with all three members",
                     p && pl && sg && json_get_str(p) && json_get_str(pl) &&
                     json_get_str(sg));
            if (p && pl && sg && json_get_str(p) && json_get_str(pl) && json_get_str(sg)) {
                char header[512];
                size_t hn = 0;
                AJ_CHECK("the protected header decodes",
                         acme_b64url_decode(json_get_str(p), header,
                                            sizeof(header) - 1, &hn));
                header[hn] = '\0';
                AJ_CHECK("newAccount embeds the jwk and no kid",
                         strstr(header, "\"alg\":\"ES256\"") &&
                         strstr(header, "\"jwk\":{\"crv\":\"P-256\"") &&
                         strstr(header, "\"kid\"") == NULL &&
                         strstr(header, "\"nonce\":\"nonceAAA\"") &&
                         strstr(header, "\"url\":\"https://ca.example/acme/new-acct\""));

                char payload[256];
                size_t pn = 0;
                AJ_CHECK("the payload decodes to the JSON we handed in",
                         acme_b64url_decode(json_get_str(pl), payload,
                                            sizeof(payload) - 1, &pn) &&
                         pn == strlen("{\"termsOfServiceAgreed\":true}") &&
                         memcmp(payload, "{\"termsOfServiceAgreed\":true}", pn) == 0);

                /* The signing input is the two base64url members joined by a
                 * dot — the CA reconstructs it from the wire exactly so. */
                char input[2048];
                const int in_len = snprintf(input, sizeof(input), "%s.%s",
                                            json_get_str(p), json_get_str(pl));
                uint8_t sig[64];
                size_t sn = 0;
                AJ_CHECK("the signature decodes to 64 raw bytes",
                         acme_b64url_decode(json_get_str(sg), sig, sizeof(sig), &sn) &&
                         sn == 64);
                AJ_CHECK("the signature verifies over \"<protected>.<payload>\"",
                         in_len > 0 &&
                         verify_es256(key, input, (size_t)in_len, sig));
            } else {
                failures += 5;
            }
            json_free(&doc);
            free(body);
        }
    }

    {
        char *body = acme_jws_body(key, "https://ca.example/acct/17", "nonceBBB",
                                   "https://ca.example/acme/authz/9", NULL);
        AJ_CHECK("POST-as-GET JWS builds", body != NULL);
        if (body) {
            struct json_value doc = {0};
            const bool parsed = json_read(&doc, body, strlen(body));
            const struct json_value *p = parsed ? json_get(&doc, "protected") : NULL;
            const struct json_value *pl = parsed ? json_get(&doc, "payload") : NULL;
            AJ_CHECK("POST-as-GET sends an EMPTY payload member, not b64url(\"\")",
                     pl && json_get_str(pl) && json_get_str(pl)[0] == '\0');
            char header[512];
            size_t hn = 0;
            AJ_CHECK("a kid request carries kid and no jwk",
                     p && json_get_str(p) &&
                     acme_b64url_decode(json_get_str(p), header,
                                        sizeof(header) - 1, &hn) &&
                     (header[hn] = '\0', true) &&
                     strstr(header, "\"kid\":\"https://ca.example/acct/17\"") &&
                     strstr(header, "\"jwk\"") == NULL);
            json_free(&doc);
            free(body);
        }
    }

    /* ── refusals ──────────────────────────────────────────────────── */
    {
        char *body = acme_jws_body(key, NULL, "nonce\"injected",
                                   "https://ca.example/x", "{}");
        AJ_CHECK("a nonce carrying a quote is refused, not escaped", body == NULL);
        free(body);
        body = acme_jws_body(key, "kid\\bad", "nonce", "https://ca.example/x", "{}");
        AJ_CHECK("a kid carrying a backslash is refused", body == NULL);
        free(body);
        body = acme_jws_body(key, NULL, "nonce", NULL, "{}");
        AJ_CHECK("a JWS with no url is refused", body == NULL);
        free(body);
    }

    /* ── the account key on disk ───────────────────────────────────── */
    {
        char dir[512];
        char path[640];
        if (!selftest_tmpdir(dir, sizeof(dir))) {
            printf("acme_jws: cannot create a scratch directory\n");
            return failures + 1;
        }
        snprintf(path, sizeof(path), "%s/account.pem", dir);

        AJ_CHECK("loading an absent account key is not an error, just absent",
                 acme_account_key_load(path) == NULL);
        EVP_PKEY *created = acme_account_key_load_or_create(path);
        AJ_CHECK("the account key is created on first use", created != NULL);
        EVP_PKEY *reloaded = acme_account_key_load(path);
        AJ_CHECK("the account key reloads", reloaded != NULL);
        if (created && reloaded) {
            uint8_t a[32];
            uint8_t b[32];
            AJ_CHECK("the reloaded key is the same identity",
                     acme_jwk_thumbprint(created, a) &&
                     acme_jwk_thumbprint(reloaded, b) && memcmp(a, b, 32) == 0);
        } else {
            failures++;
        }
        EVP_PKEY_free(created);
        EVP_PKEY_free(reloaded);

        /* An RSA key would sign with RS256; ES256 would be a lie. */
        char rsa_path[640];
        snprintf(rsa_path, sizeof(rsa_path), "%s/rsa.pem", dir);
        EVP_PKEY *rsa = EVP_PKEY_Q_keygen(NULL, NULL, "RSA", (size_t)2048);
        if (rsa) {
            FILE *f = fopen(rsa_path, "wb");
            if (f) {
                PEM_write_PrivateKey(f, rsa, NULL, NULL, 0, NULL, NULL);
                fclose(f);
            }
            EVP_PKEY_free(rsa);
            AJ_CHECK("a non-P-256 account key is refused, not used with ES256",
                     acme_account_key_load(rsa_path) == NULL);
            EVP_PKEY *wrong = acme_account_key_load_or_create(rsa_path);
            AJ_CHECK("an existing wrong-algorithm account key is never replaced",
                     wrong == NULL && acme_account_key_load(rsa_path) == NULL);
            EVP_PKEY_free(wrong);
        } else {
            printf("acme_jws: RSA keygen unavailable; algorithm refusal not exercised\n");
            failures++;
        }
        selftest_rmrf(dir);
    }

    EVP_PKEY_free(key);
    return failures;
}

#define AP_CHECK(name, expr) do {                        \
    printf("acme_protocol: %s... ", (name));             \
    if (expr) { printf("OK\n"); }                        \
    else { printf("FAIL\n"); failures++; }               \
} while (0)

/* ── recorded fixtures ───────────────────────────────────────────────── */

static const char FIXTURE_DIRECTORY[] =
    "{\n"
    "  \"keyChange\": \"https://acme-staging-v02.api.letsencrypt.org/acme/key-change\",\n"
    "  \"meta\": {\n"
    "    \"caaIdentities\": [\"letsencrypt.org\"],\n"
    "    \"termsOfService\": \"https://letsencrypt.org/documents/LE-SA-v1.4.pdf\",\n"
    "    \"website\": \"https://letsencrypt.org/docs/staging-environment/\"\n"
    "  },\n"
    "  \"newAccount\": \"https://acme-staging-v02.api.letsencrypt.org/acme/new-acct\",\n"
    "  \"newNonce\": \"https://acme-staging-v02.api.letsencrypt.org/acme/new-nonce\",\n"
    "  \"newOrder\": \"https://acme-staging-v02.api.letsencrypt.org/acme/new-order\",\n"
    "  \"renewalInfo\": \"https://acme-staging-v02.api.letsencrypt.org/get/draft-ietf-acme-ari-03/renewalInfo\",\n"
    "  \"revokeCert\": \"https://acme-staging-v02.api.letsencrypt.org/acme/revoke-cert\"\n"
    "}";

static const char FIXTURE_ORDER_PENDING[] =
    "{\n"
    "  \"status\": \"pending\",\n"
    "  \"expires\": \"2026-09-05T18:22:41Z\",\n"
    "  \"identifiers\": [{\"type\": \"dns\", \"value\": \"node.example.org\"}],\n"
    "  \"authorizations\": [\n"
    "    \"https://acme-staging-v02.api.letsencrypt.org/acme/authz-v3/14592841\"\n"
    "  ],\n"
    "  \"finalize\": \"https://acme-staging-v02.api.letsencrypt.org/acme/finalize/1234/5678\"\n"
    "}";

static const char FIXTURE_ORDER_VALID[] =
    "{\"status\":\"valid\","
    "\"expires\":\"2026-09-05T18:22:41Z\","
    "\"identifiers\":[{\"type\":\"dns\",\"value\":\"node.example.org\"}],"
    "\"authorizations\":[\"https://ca.example/authz/1\"],"
    "\"finalize\":\"https://ca.example/finalize/1\","
    "\"certificate\":\"https://ca.example/cert/abcd\"}";

static const char FIXTURE_AUTHZ[] =
    "{\n"
    "  \"identifier\": {\"type\": \"dns\", \"value\": \"node.example.org\"},\n"
    "  \"status\": \"pending\",\n"
    "  \"expires\": \"2026-09-05T18:22:41Z\",\n"
    "  \"challenges\": [\n"
    "    {\"type\": \"http-01\",\n"
    "     \"url\": \"https://ca.example/chall-v3/1/A\",\n"
    "     \"status\": \"pending\",\n"
    "     \"token\": \"kkTvcJHtHzAoYFwULCyMOaMSXEmoQCFmuoLfeAyDMYc\"},\n"
    "    {\"type\": \"dns-01\",\n"
    "     \"url\": \"https://ca.example/chall-v3/1/B\",\n"
    "     \"status\": \"pending\",\n"
    "     \"token\": \"kkTvcJHtHzAoYFwULCyMOaMSXEmoQCFmuoLfeAyDMYc\"},\n"
    "    {\"type\": \"tls-alpn-01\",\n"
    "     \"url\": \"https://ca.example/chall-v3/1/C\",\n"
    "     \"status\": \"pending\",\n"
    "     \"token\": \"kkTvcJHtHzAoYFwULCyMOaMSXEmoQCFmuoLfeAyDMYc\"}\n"
    "  ]\n"
    "}";

static const char FIXTURE_AUTHZ_NO_ALPN[] =
    "{\"identifier\":{\"type\":\"dns\",\"value\":\"node.example.org\"},"
    "\"status\":\"pending\","
    "\"challenges\":[{\"type\":\"http-01\",\"url\":\"https://ca.example/c/1\","
    "\"status\":\"pending\",\"token\":\"abc\"}]}";

static const char FIXTURE_PROBLEM_BADNONCE[] =
    "{\"type\":\"urn:ietf:params:acme:error:badNonce\","
    "\"detail\":\"JWS has an invalid anti-replay nonce: \\\"oFvnlFP1\\\"\","
    "\"status\":400}";

static int selftest_wire(void)
{
    int failures = 0;

    /* ── directory ─────────────────────────────────────────────────── */
    {
        struct acme_directory d;
        AP_CHECK("a recorded staging directory parses",
                 acme_directory_parse(FIXTURE_DIRECTORY,
                                      sizeof(FIXTURE_DIRECTORY) - 1, &d));
        AP_CHECK("newNonce is picked out",
                 strcmp(d.new_nonce,
                        "https://acme-staging-v02.api.letsencrypt.org/acme/new-nonce") == 0);
        AP_CHECK("newAccount is picked out",
                 strcmp(d.new_account,
                        "https://acme-staging-v02.api.letsencrypt.org/acme/new-acct") == 0);
        AP_CHECK("newOrder is picked out",
                 strcmp(d.new_order,
                        "https://acme-staging-v02.api.letsencrypt.org/acme/new-order") == 0);

        static const char missing[] =
            "{\"newAccount\":\"https://ca.example/a\","
            "\"newOrder\":\"https://ca.example/o\"}";
        AP_CHECK("a directory missing newNonce is refused",
                 !acme_directory_parse(missing, sizeof(missing) - 1, &d) &&
                 d.new_account[0] == '\0');

        static const char wrong_type[] =
            "{\"newNonce\":42,\"newAccount\":\"https://ca.example/a\","
            "\"newOrder\":\"https://ca.example/o\"}";
        AP_CHECK("a numeric newNonce is refused, not coerced",
                 !acme_directory_parse(wrong_type, sizeof(wrong_type) - 1, &d));

        static const char nested[] =
            "{\"newNonce\":{\"href\":\"https://ca.example/n\"},"
            "\"newAccount\":\"https://ca.example/a\","
            "\"newOrder\":\"https://ca.example/o\"}";
        AP_CHECK("an object where a URL belongs is refused",
                 !acme_directory_parse(nested, sizeof(nested) - 1, &d));

        AP_CHECK("a non-object body is refused",
                 !acme_directory_parse("[1,2,3]", 7, &d));
        AP_CHECK("a truncated body is refused",
                 !acme_directory_parse("{\"newNonce\":", 12, &d));
        AP_CHECK("an empty body is refused", !acme_directory_parse("", 0, &d));
        AP_CHECK("a NULL body is refused", !acme_directory_parse(NULL, 10, &d));

        /* An overlong URL must be REFUSED, never truncated: a shortened URL
         * is a request to a different endpoint. */
        static char huge[4096];
        const int n = snprintf(huge, sizeof(huge),
                               "{\"newNonce\":\"https://ca.example/");
        memset(huge + n, 'n', sizeof(huge) - (size_t)n - 4);
        memcpy(huge + sizeof(huge) - 4, "\"}", 3);
        AP_CHECK("a URL past the cap is refused, not truncated",
                 !acme_directory_parse(huge, strlen(huge), &d));
    }

    /* ── order ─────────────────────────────────────────────────────── */
    {
        struct acme_order o;
        AP_CHECK("a pending order parses",
                 acme_order_parse(FIXTURE_ORDER_PENDING,
                                  sizeof(FIXTURE_ORDER_PENDING) - 1, &o));
        AP_CHECK("its status is pending", strcmp(o.status, "pending") == 0);
        AP_CHECK("it lists one authorization", o.num_authorizations == 1);
        AP_CHECK("the authorization URL is exact",
                 strcmp(o.authorizations[0],
                        "https://acme-staging-v02.api.letsencrypt.org/acme/authz-v3/14592841") == 0);
        AP_CHECK("a pending order names no certificate", o.certificate[0] == '\0');

        AP_CHECK("a valid order parses",
                 acme_order_parse(FIXTURE_ORDER_VALID,
                                  sizeof(FIXTURE_ORDER_VALID) - 1, &o));
        AP_CHECK("a valid order names its certificate",
                 strcmp(o.certificate, "https://ca.example/cert/abcd") == 0);

        static const char no_authz[] =
            "{\"status\":\"pending\",\"finalize\":\"https://ca.example/f\","
            "\"authorizations\":[]}";
        AP_CHECK("an order with an empty authorizations array is refused",
                 !acme_order_parse(no_authz, sizeof(no_authz) - 1, &o));

        static const char not_array[] =
            "{\"status\":\"pending\",\"finalize\":\"https://ca.example/f\","
            "\"authorizations\":\"https://ca.example/a\"}";
        AP_CHECK("an authorizations member that is a string is refused",
                 !acme_order_parse(not_array, sizeof(not_array) - 1, &o));

        static const char mixed[] =
            "{\"status\":\"pending\",\"finalize\":\"https://ca.example/f\","
            "\"authorizations\":[\"https://ca.example/a\",7]}";
        AP_CHECK("a non-string authorization entry is refused",
                 !acme_order_parse(mixed, sizeof(mixed) - 1, &o) &&
                 o.num_authorizations == 0);

        static const char no_finalize[] =
            "{\"status\":\"pending\",\"authorizations\":[\"https://ca.example/a\"]}";
        AP_CHECK("an order with no finalize URL is refused",
                 !acme_order_parse(no_finalize, sizeof(no_finalize) - 1, &o));

        static const char too_many[] =
            "{\"status\":\"pending\",\"finalize\":\"https://ca.example/f\","
            "\"authorizations\":[\"a\",\"b\",\"c\",\"d\",\"e\",\"f\",\"g\",\"h\",\"i\"]}";
        AP_CHECK("more authorizations than this client handles is refused",
                 !acme_order_parse(too_many, sizeof(too_many) - 1, &o));
    }

    /* ── authorization ─────────────────────────────────────────────── */
    {
        char identifier[256];
        char status[32];
        struct acme_challenge ch;
        AP_CHECK("a recorded authorization parses",
                 acme_authorization_parse(FIXTURE_AUTHZ, sizeof(FIXTURE_AUTHZ) - 1,
                                          identifier, sizeof(identifier),
                                          status, sizeof(status), &ch));
        AP_CHECK("the identifier is the DNS name",
                 strcmp(identifier, "node.example.org") == 0);
        AP_CHECK("the status is pending", strcmp(status, "pending") == 0);
        AP_CHECK("the tls-alpn-01 challenge is the one selected",
                 strcmp(ch.url, "https://ca.example/chall-v3/1/C") == 0);
        AP_CHECK("its token comes through intact",
                 strcmp(ch.token, "kkTvcJHtHzAoYFwULCyMOaMSXEmoQCFmuoLfeAyDMYc") == 0);

        AP_CHECK("an authorization offering no tls-alpn-01 is REFUSED, not "
                 "downgraded to http-01",
                 !acme_authorization_parse(FIXTURE_AUTHZ_NO_ALPN,
                                           sizeof(FIXTURE_AUTHZ_NO_ALPN) - 1,
                                           identifier, sizeof(identifier),
                                           status, sizeof(status), &ch) &&
                 ch.url[0] == '\0');

        static const char ip_identifier[] =
            "{\"identifier\":{\"type\":\"ip\",\"value\":\"198.51.100.7\"},"
            "\"status\":\"pending\",\"challenges\":[{\"type\":\"tls-alpn-01\","
            "\"url\":\"https://ca.example/c\",\"status\":\"pending\",\"token\":\"t\"}]}";
        AP_CHECK("a non-DNS identifier is refused",
                 !acme_authorization_parse(ip_identifier, sizeof(ip_identifier) - 1,
                                           identifier, sizeof(identifier),
                                           status, sizeof(status), &ch));

        static const char no_token[] =
            "{\"identifier\":{\"type\":\"dns\",\"value\":\"node.example.org\"},"
            "\"status\":\"pending\",\"challenges\":[{\"type\":\"tls-alpn-01\","
            "\"url\":\"https://ca.example/c\",\"status\":\"pending\"}]}";
        AP_CHECK("a tls-alpn-01 challenge with no token is refused",
                 !acme_authorization_parse(no_token, sizeof(no_token) - 1,
                                           identifier, sizeof(identifier),
                                           status, sizeof(status), &ch));

        static const char null_challenges[] =
            "{\"identifier\":{\"type\":\"dns\",\"value\":\"n.example\"},"
            "\"status\":\"pending\",\"challenges\":null}";
        AP_CHECK("a null challenges member is refused",
                 !acme_authorization_parse(null_challenges,
                                           sizeof(null_challenges) - 1,
                                           identifier, sizeof(identifier),
                                           status, sizeof(status), &ch));

        static const char scalar_challenge[] =
            "{\"identifier\":{\"type\":\"dns\",\"value\":\"n.example\"},"
            "\"status\":\"pending\",\"challenges\":[1,2,3]}";
        AP_CHECK("challenge entries that are not objects are refused",
                 !acme_authorization_parse(scalar_challenge,
                                           sizeof(scalar_challenge) - 1,
                                           identifier, sizeof(identifier),
                                           status, sizeof(status), &ch));
    }

    /* ── problem documents ─────────────────────────────────────────── */
    {
        char type[512];
        char detail[512];
        AP_CHECK("a badNonce problem parses",
                 acme_problem_parse(FIXTURE_PROBLEM_BADNONCE,
                                    sizeof(FIXTURE_PROBLEM_BADNONCE) - 1,
                                    type, sizeof(type), detail, sizeof(detail)));
        AP_CHECK("the problem type is exact",
                 strcmp(type, "urn:ietf:params:acme:error:badNonce") == 0);
        AP_CHECK("the escaped quotes in detail survive the parser",
                 strstr(detail, "\"oFvnlFP1\"") != NULL);

        static const char no_detail[] =
            "{\"type\":\"urn:ietf:params:acme:error:serverInternal\"}";
        AP_CHECK("a problem with no detail still parses",
                 acme_problem_parse(no_detail, sizeof(no_detail) - 1, type,
                                    sizeof(type), detail, sizeof(detail)) &&
                 detail[0] == '\0');
        AP_CHECK("an ordinary object with no type is not a problem document",
                 !acme_problem_parse("{\"status\":\"valid\"}", 18, type,
                                     sizeof(type), detail, sizeof(detail)));
    }

    /* ── the CSR ───────────────────────────────────────────────────── */
    {
        EVP_PKEY *key = acme_account_key_generate();
        uint8_t *der = NULL;
        size_t der_len = 0;
        AP_CHECK("a CSR builds",
                 key && acme_csr_der(key, "node.example.org", &der, &der_len) &&
                 der && der_len > 0);
        if (der) {
            const unsigned char *p = der;
            X509_REQ *req = d2i_X509_REQ(NULL, &p, (long)der_len);
            AP_CHECK("the CSR is parsable DER", req != NULL);
            AP_CHECK("the CSR consumes exactly its declared length",
                     req && p == der + der_len);
            AP_CHECK("the CSR signature verifies under its own key",
                     req && X509_REQ_verify(req, key) == 1);
            if (req) {
                STACK_OF(X509_EXTENSION) *exts = X509_REQ_get_extensions(req);
                bool san_ok = false;
                if (exts) {
                    for (int i = 0; i < sk_X509_EXTENSION_num(exts); i++) {
                        X509_EXTENSION *e = sk_X509_EXTENSION_value(exts, i);
                        if (OBJ_obj2nid(X509_EXTENSION_get_object(e)) !=
                            NID_subject_alt_name)
                            continue;
                        GENERAL_NAMES *names = X509V3_EXT_d2i(e);
                        if (names) {
                            for (int j = 0; j < sk_GENERAL_NAME_num(names); j++) {
                                GENERAL_NAME *gn = sk_GENERAL_NAME_value(names, j);
                                int gtype = 0;
                                ASN1_STRING *val = GENERAL_NAME_get0_value(gn, &gtype);
                                if (gtype == GEN_DNS && val &&
                                    ASN1_STRING_length(val) == 16 &&
                                    memcmp(ASN1_STRING_get0_data(val),
                                           "node.example.org", 16) == 0)
                                    san_ok = true;
                            }
                            GENERAL_NAMES_free(names);
                        }
                    }
                    sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
                }
                AP_CHECK("the CSR carries a subjectAltName dNSName for the domain",
                         san_ok);
                X509_REQ_free(req);
            } else {
                failures++;
            }
            free(der);
        } else {
            failures += 4;
        }
        uint8_t *none = (uint8_t *)1;
        size_t none_len = 1;
        AP_CHECK("a CSR with no domain is refused",
                 !acme_csr_der(key, NULL, &none, &none_len) && none == NULL);
        AP_CHECK("a CSR with no key is refused",
                 !acme_csr_der(NULL, "node.example.org", &none, &none_len));
        EVP_PKEY_free(key);
    }

    /* ── the issued chain ──────────────────────────────────────────── */
    {
        size_t count = 0;
        AP_CHECK("an empty chain is refused",
                 !acme_chain_is_wellformed("", 0, &count));
        AP_CHECK("a chain of prose is refused",
                 !acme_chain_is_wellformed("not a certificate\n", 18, &count));
        static const char truncated_pem[] =
            "-----BEGIN CERTIFICATE-----\nMIIB\n";
        AP_CHECK("a truncated PEM block is refused",
                 !acme_chain_is_wellformed(truncated_pem,
                                           sizeof(truncated_pem) - 1, &count));

        /* A real chain, built the way the CA returns one: concatenated PEM,
         * leaf first. These are certificates OpenSSL actually parses, not a
         * fixture string that only looks like one. */
        X509 *leaf = NULL;
        X509 *intermediate = NULL;
        EVP_PKEY *k1 = NULL;
        EVP_PKEY *k2 = NULL;
        if (acme_selftest_selfsigned("leaf.example.org", &leaf, &k1) &&
            acme_selftest_selfsigned("ca.example.org", &intermediate, &k2)) {
            BIO *one = BIO_new(BIO_s_mem());
            char *one_pem = NULL;
            long one_len = 0;
            size_t one_count = 0;
            if (one && PEM_write_bio_X509(one, leaf) == 1)
                one_len = BIO_get_mem_data(one, &one_pem);
            AP_CHECK("a single-certificate chain is well-formed and counted as 1",
                     one_pem && one_len > 0 &&
                     acme_chain_is_wellformed(one_pem, (size_t)one_len, &one_count) &&
                     one_count == 1);
            BIO_free(one);

            BIO *two = BIO_new(BIO_s_mem());
            char *two_pem = NULL;
            long two_len = 0;
            if (two && PEM_write_bio_X509(two, leaf) == 1 &&
                PEM_write_bio_X509(two, intermediate) == 1)
                two_len = BIO_get_mem_data(two, &two_pem);
            AP_CHECK("a concatenated two-certificate chain is counted as 2",
                     two_pem && two_len > 0 &&
                     acme_chain_is_wellformed(two_pem, (size_t)two_len, &count) &&
                     count == 2);
            AP_CHECK("a chain past the byte cap is refused",
                     two_pem &&
                     !acme_chain_is_wellformed(two_pem, ACME_MAX_CHAIN_BYTES + 1,
                                               &count));
            BIO_free(two);
        } else {
            failures += 3;
        }
        X509_free(leaf);
        X509_free(intermediate);
        EVP_PKEY_free(k1);
        EVP_PKEY_free(k2);
    }

    return failures;
}

int acme_selftest_protocol(void)
{
    return selftest_jws() + selftest_wire();
}
