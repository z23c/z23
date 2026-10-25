/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ACME wire-object parsing and the CSR. Pure functions of bytes; see
 * net/acme_protocol.h.
 */

#if !defined(_WIN32)
#define _XOPEN_SOURCE 700
#endif

#include "acme_protocol.h"

#include "json/json.h"

#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <stdlib.h>
#include <string.h>

#include "base/log_macros.h"
#include "base/safe_alloc.h"

/* A JSON body from a CA is untrusted input. Cap it before the parser sees
 * it — the parser allocates per token, and nothing legitimate is close. */
#define ACME_MAX_JSON (128u * 1024u)

/* Copy a required string member into a fixed field. Refuses a wrong type and
 * a value that would be truncated: a silently shortened URL is a request to
 * the wrong endpoint, which is worse than a clean failure. */
static bool copy_member(const struct json_value *obj, const char *key,
                        char *out, size_t out_len, bool required)
{
    out[0] = '\0';
    const struct json_value *v = json_get(obj, key);
    if (!v) {
        if (required)
            LOG_FAIL("acme", "response is missing the required member \"%s\"", key);
        return true;
    }
    if (v->type != JSON_STR)
        LOG_FAIL("acme", "response member \"%s\" is not a string", key);
    const char *s = json_get_str(v);
    if (!s)
        LOG_FAIL("acme", "response member \"%s\" holds no text", key);
    const size_t n = strlen(s);
    if (n + 1 > out_len)
        LOG_FAIL("acme", "response member \"%s\" is %zu bytes; the cap is %zu",
                 key, n, out_len - 1);
    memcpy(out, s, n + 1);
    return true;
}

static bool read_json(const char *json, size_t len, struct json_value *out)
{
    struct json_value fresh = {0};
    *out = fresh;
    if (!json)
        LOG_FAIL("acme", "cannot parse a null response body");
    if (len == 0)
        LOG_FAIL("acme", "cannot parse an empty response body");
    if (len > ACME_MAX_JSON)
        LOG_FAIL("acme", "refusing a %zu-byte JSON body: over the %u-byte cap",
                 len, ACME_MAX_JSON);
    if (!json_read(out, json, len))
        LOG_FAIL("acme", "response body is not valid JSON");
    if (out->type != JSON_OBJ) {
        json_free(out);
        LOG_FAIL("acme", "response body is not a JSON object");
    }
    return true;
}

bool acme_directory_parse(const char *json, size_t len,
                          struct acme_directory *out)
{
    if (!out)
        return false;
    memset(out, 0, sizeof(*out));
    struct json_value doc = {0};
    if (!read_json(json, len, &doc))
        return false;
    const bool ok =
        copy_member(&doc, "newNonce", out->new_nonce, sizeof(out->new_nonce), true) &&
        copy_member(&doc, "newAccount", out->new_account, sizeof(out->new_account), true) &&
        copy_member(&doc, "newOrder", out->new_order, sizeof(out->new_order), true);
    json_free(&doc);
    if (!ok) {
        memset(out, 0, sizeof(*out));
        return false;
    }
    return true;
}

enum {
    ORDER_AUTHZ_OK = 0,
    ORDER_AUTHZ_NOT_ARRAY = 1,
    ORDER_AUTHZ_BAD_COUNT = 2,
    ORDER_AUTHZ_BAD_URL = 3
};

/* Copy authorizations[] into out. On a bad entry, *detail is the value the
 * caller's warning prints (the array length, or the index that failed) and
 * the return is the matching reason. A mid-array failure leaves the earlier
 * URLs in place; the caller wipes out when it refuses the order. */
static int order_copy_authorizations(const struct json_value *doc,
                                     struct acme_order *out, size_t *detail)
{
    const struct json_value *authz = json_get(doc, "authorizations");
    if (!authz || authz->type != JSON_ARR)
        return ORDER_AUTHZ_NOT_ARRAY;
    if (json_size(authz) == 0 || json_size(authz) > ACME_MAX_AUTHZ) {
        *detail = json_size(authz);
        return ORDER_AUTHZ_BAD_COUNT;
    }
    for (size_t i = 0; i < json_size(authz); i++) {
        const struct json_value *item = json_at(authz, i);
        const char *s = (item && item->type == JSON_STR) ? json_get_str(item)
                                                         : NULL;
        if (!s || strlen(s) + 1 > ACME_MAX_URL) {
            *detail = i;
            return ORDER_AUTHZ_BAD_URL;
        }
        memcpy(out->authorizations[i], s, strlen(s) + 1);
        out->num_authorizations = i + 1;
    }
    return ORDER_AUTHZ_OK;
}

bool acme_order_parse(const char *json, size_t len, struct acme_order *out)
{
    if (!out)
        return false;
    memset(out, 0, sizeof(*out));
    struct json_value doc = {0};
    if (!read_json(json, len, &doc))
        return false;

    bool ok = copy_member(&doc, "status", out->status, sizeof(out->status), true) &&
              copy_member(&doc, "finalize", out->finalize, sizeof(out->finalize), true) &&
              copy_member(&doc, "certificate", out->certificate,
                          sizeof(out->certificate), false);
    if (ok) {
        size_t detail = 0;
        const int why = order_copy_authorizations(&doc, out, &detail);
        if (why == ORDER_AUTHZ_NOT_ARRAY) {
            LOG_WARN("acme", "order carries no authorizations array");
        } else if (why == ORDER_AUTHZ_BAD_COUNT) {
            LOG_WARN("acme",
                     "order lists %zu authorizations; this client handles 1..%d",
                     detail, ACME_MAX_AUTHZ);
        } else if (why == ORDER_AUTHZ_BAD_URL) {
            LOG_WARN("acme", "authorization %zu is not a URL within the cap", detail);
        }
        ok = why == ORDER_AUTHZ_OK;
    }
    json_free(&doc);
    if (!ok) {
        memset(out, 0, sizeof(*out));
        LOG_FAIL("acme", "refusing a malformed order object");
    }
    return true;
}

enum {
    AUTHZ_ID_OK = 0,
    AUTHZ_ID_MISSING = 1,
    AUTHZ_ID_NOT_DNS = 2,
    AUTHZ_ID_BAD_MEMBER = 3
};

enum {
    AUTHZ_CH_OK = 0,
    AUTHZ_CH_NO_ARRAY = 1,
    AUTHZ_CH_NONE = 2
};

/* One challenges[] entry. SKIP keeps scanning: the entry is not an object,
 * its type could not be read, or the type is not tls-alpn-01. STOP is the
 * break: this entry is tls-alpn-01 but url, token, or status failed, and a
 * later entry must not be tried. COPIED means those three fields are in out. */
enum {
    CHALLENGE_SKIP = 0,
    CHALLENGE_COPIED = 1,
    CHALLENGE_STOP = 2
};

static bool authorization_args_present(const char *identifier, size_t identifier_len,
                                       const char *status, size_t status_len,
                                       const struct acme_challenge *out)
{
    if (!identifier || !status || !out || identifier_len == 0 || status_len == 0)
        return false;
    return true;
}

static int authorization_read_identifier(const struct json_value *doc,
                                         char *identifier, size_t identifier_len,
                                         char *type, size_t type_len)
{
    const struct json_value *ident = json_get(doc, "identifier");
    if (!ident || ident->type != JSON_OBJ)
        return AUTHZ_ID_MISSING;
    if (!copy_member(ident, "type", type, type_len, true) ||
        !copy_member(ident, "value", identifier, identifier_len, true))
        return AUTHZ_ID_BAD_MEMBER;
    if (strcmp(type, "dns") != 0)
        return AUTHZ_ID_NOT_DNS;
    return AUTHZ_ID_OK;
}

static int authorization_take_tls_alpn(const struct json_value *ch,
                                       struct acme_challenge *out)
{
    if (!ch || ch->type != JSON_OBJ)
        return CHALLENGE_SKIP;
    char type[64];
    if (!copy_member(ch, "type", type, sizeof(type), true))
        return CHALLENGE_SKIP;
    if (strcmp(type, "tls-alpn-01") != 0)
        return CHALLENGE_SKIP;
    if (!copy_member(ch, "url", out->url, sizeof(out->url), true) ||
        !copy_member(ch, "token", out->token, sizeof(out->token), true) ||
        !copy_member(ch, "status", out->status, sizeof(out->status), true))
        return CHALLENGE_STOP;
    return CHALLENGE_COPIED;
}

static int authorization_read_challenges(const struct json_value *doc,
                                         struct acme_challenge *out)
{
    const struct json_value *challenges = json_get(doc, "challenges");
    if (!challenges || challenges->type != JSON_ARR || json_size(challenges) == 0)
        return AUTHZ_CH_NO_ARRAY;
    bool found = false;
    for (size_t i = 0; i < json_size(challenges) && !found; i++) {
        const int took = authorization_take_tls_alpn(json_at(challenges, i), out);
        if (took == CHALLENGE_STOP)
            break;
        if (took == CHALLENGE_COPIED)
            found = true;
    }
    if (!found)
        return AUTHZ_CH_NONE;
    return AUTHZ_CH_OK;
}

bool acme_authorization_parse(const char *json, size_t len,
                              char *identifier, size_t identifier_len,
                              char *status, size_t status_len,
                              struct acme_challenge *out)
{
    if (!authorization_args_present(identifier, identifier_len, status, status_len, out))
        return false;
    identifier[0] = '\0';
    status[0] = '\0';
    memset(out, 0, sizeof(*out));

    struct json_value doc = {0};
    if (!read_json(json, len, &doc))
        return false;

    bool ok = copy_member(&doc, "status", status, status_len, true);
    if (ok) {
        char type[32] = {0};
        const int why = authorization_read_identifier(&doc, identifier, identifier_len,
                                                      type, sizeof(type));
        if (why == AUTHZ_ID_MISSING) {
            LOG_WARN("acme", "authorization carries no identifier object");
        } else if (why == AUTHZ_ID_NOT_DNS) {
            LOG_WARN("acme",
                     "refusing an identifier of type \"%s\": tls-alpn-01 "
                     "validates a DNS name and nothing else", type);
        }
        ok = why == AUTHZ_ID_OK;
    }
    if (ok) {
        const int why = authorization_read_challenges(&doc, out);
        if (why == AUTHZ_CH_NO_ARRAY) {
            LOG_WARN("acme", "authorization carries no challenges array");
        } else if (why == AUTHZ_CH_NONE) {
            LOG_WARN("acme",
                     "authorization offers no usable tls-alpn-01 challenge; "
                     "this node has no port 80 and no registrar API, so no "
                     "other challenge type can be answered");
        }
        ok = why == AUTHZ_CH_OK;
    }

    json_free(&doc);
    if (!ok) {
        identifier[0] = '\0';
        status[0] = '\0';
        memset(out, 0, sizeof(*out));
        LOG_FAIL("acme", "refusing an authorization this client cannot answer");
    }
    return true;
}

bool acme_problem_parse(const char *json, size_t len,
                        char *type, size_t type_len,
                        char *detail, size_t detail_len)
{
    if (!type || !detail || type_len == 0 || detail_len == 0)
        return false;
    type[0] = '\0';
    detail[0] = '\0';
    struct json_value doc = {0};
    if (!read_json(json, len, &doc))
        return false;
    const bool ok = copy_member(&doc, "type", type, type_len, true) &&
                    copy_member(&doc, "detail", detail, detail_len, false);
    json_free(&doc);
    if (!ok) {
        type[0] = '\0';
        detail[0] = '\0';
        return false;
    }
    return true;
}

/* ── the CSR ─────────────────────────────────────────────────────────── */

/* Every pointer is owned here until a step adopts it and nulls the field.
 * Cleanup frees every field, so null means already adopted or never allocated. */
struct csr_parts {
    X509_REQ *req;
    STACK_OF(X509_EXTENSION) *exts;
    X509_EXTENSION *san;
    GENERAL_NAMES *names;
    GENERAL_NAME *name;
    ASN1_IA5STRING *dns;
    unsigned char *buf;
};

static bool csr_objects_new(struct csr_parts *p)
{
    p->req = X509_REQ_new();
    p->exts = sk_X509_EXTENSION_new_null();
    p->names = GENERAL_NAMES_new();
    p->name = GENERAL_NAME_new();
    p->dns = ASN1_IA5STRING_new();
    if (!p->req || !p->exts || !p->names || !p->name || !p->dns)
        return false;
    return true;
}

static bool csr_build_request(struct csr_parts *p, const char *domain)
{
    if (X509_REQ_set_version(p->req, 0) != 1)
        return false;
    if (X509_NAME_add_entry_by_txt(X509_REQ_get_subject_name(p->req), "CN",
                                   MBSTRING_ASC, (const unsigned char *)domain,
                                   -1, -1, 0) != 1)
        return false;
    if (ASN1_STRING_set(p->dns, domain, (int)strlen(domain)) != 1)
        return false;
    GENERAL_NAME_set0_value(p->name, GEN_DNS, p->dns);
    p->dns = NULL;
    if (sk_GENERAL_NAME_push(p->names, p->name) <= 0)
        return false;
    p->name = NULL;
    p->san = X509V3_EXT_i2d(NID_subject_alt_name, 0, p->names);
    if (!p->san || sk_X509_EXTENSION_push(p->exts, p->san) <= 0)
        return false;
    p->san = NULL;
    if (X509_REQ_add_extensions(p->req, p->exts) != 1)
        return false;
    return true;
}

static bool csr_sign_and_export(struct csr_parts *p, EVP_PKEY *key,
                                uint8_t **der, size_t *der_len)
{
    if (X509_REQ_set_pubkey(p->req, key) != 1)
        return false;
    if (X509_REQ_sign(p->req, key, EVP_sha256()) == 0)
        return false;
    const int n = i2d_X509_REQ(p->req, &p->buf);
    if (n <= 0 || !p->buf)
        return false;
    uint8_t *copy = zcl_malloc((size_t)n, "acme_csr_der");
    if (!copy)
        return false;
    memcpy(copy, p->buf, (size_t)n);
    *der = copy;
    *der_len = (size_t)n;
    return true;
}

bool acme_csr_der(const EVP_PKEY *key, const char *domain,
                  uint8_t **der, size_t *der_len)
{
    if (!der || !der_len)
        return false;
    *der = NULL;
    *der_len = 0;
    if (!key || !domain || !domain[0])
        LOG_FAIL("acme", "cannot build a CSR without a key and a domain");
    if (strlen(domain) > ACME_MAX_URL)
        LOG_FAIL("acme", "refusing a domain of %zu bytes in a CSR", strlen(domain));

    struct csr_parts parts = {0};
    bool ok = false;

    if (!csr_objects_new(&parts))
        goto done;
    if (!csr_build_request(&parts, domain))
        goto done;
    if (!csr_sign_and_export(&parts, (EVP_PKEY *)key, der, der_len))
        goto done;
    ok = true;

done:
    OPENSSL_free(parts.buf);
    ASN1_IA5STRING_free(parts.dns);
    GENERAL_NAME_free(parts.name);
    GENERAL_NAMES_free(parts.names);
    X509_EXTENSION_free(parts.san);
    sk_X509_EXTENSION_pop_free(parts.exts, X509_EXTENSION_free);
    X509_REQ_free(parts.req);
    if (!ok)
        LOG_FAIL("acme", "cannot build a CSR for %s", domain);
    return true;
}

bool acme_chain_is_wellformed(const char *pem, size_t len, size_t *count)
{
    if (count)
        *count = 0;
    if (!pem || len == 0)
        LOG_FAIL("acme", "refusing an empty certificate chain");
    if (len > ACME_MAX_CHAIN_BYTES)
        LOG_FAIL("acme", "refusing a %zu-byte certificate chain: over the cap", len);
    BIO *bio = BIO_new_mem_buf(pem, (int)len);
    if (!bio)
        LOG_FAIL("acme", "cannot wrap the certificate chain for parsing");
    size_t n = 0;
    for (;;) {
        X509 *cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
        if (!cert)
            break;
        X509_free(cert);
        n++;
        if (n > 16)
            break;
    }
    BIO_free(bio);
    if (n == 0)
        LOG_FAIL("acme", "certificate chain holds no parsable certificate");
    if (n > 16)
        LOG_FAIL("acme", "certificate chain holds more than 16 certificates");
    if (count)
        *count = n;
    return true;
}
