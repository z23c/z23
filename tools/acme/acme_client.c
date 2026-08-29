/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The ACME v2 order flow. See net/acme_client.h for the precondition that
 * matters (the 443 listener must be up, with the responder installed).
 *
 * Structure: a session holds the account key, the current anti-replay nonce,
 * and the account URL. `post()` is the only place that signs, sends, and
 * harvests a new nonce, so nonce handling exists once rather than at each of
 * the seven request sites.
 */

#if !defined(_WIN32)
#define _XOPEN_SOURCE 700
#endif

#include "acme_client.h"

#include "net/acme_arm_file.h"
#include "acme_jws.h"
#include "acme_protocol.h"
#include "tls_client.h"

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#if !defined(_WIN32)
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#endif

#include "platform/time_compat.h"

#include "base/log_macros.h"
#include "base/safe_alloc.h"

#define ACME_DEFAULT_TIMEOUT_MS      30000
#define ACME_DEFAULT_POLL_ATTEMPTS   40
#define ACME_DEFAULT_POLL_INTERVAL_MS 3000
#define ACME_MAX_NONCE               256
#define ACME_USER_AGENT              "zclassic23-acme/1"

struct acme_session {
    const struct acme_client_config *cfg;
    EVP_PKEY *account_key;
    struct acme_directory dir;
    char nonce[ACME_MAX_NONCE];
    char account_url[ACME_MAX_URL];
    int timeout_ms;
    int poll_attempts;
    int poll_interval_ms;
};


/* Report the CA's own words when a request fails. A problem document is far
 * more useful than "HTTP 400", and it is the only place the reason for a
 * failed validation is ever stated. */
static void log_problem(const char *what, const struct tls_client_response *r)
{
    char type[ACME_MAX_URL];
    char detail[ACME_MAX_DETAIL];
    if (r->body && acme_problem_parse(r->body, r->body_len, type, sizeof(type),
                                      detail, sizeof(detail)))
        LOG_WARN("acme", "%s failed: status=%d type=%s detail=%s", what, r->status,
                 type, detail[0] ? detail : "(none)");
    else
        LOG_WARN("acme", "%s failed: status=%d (no problem document)", what,
                 r->status);
}

static void harvest_nonce(struct acme_session *s,
                          const struct tls_client_response *r)
{
    char nonce[ACME_MAX_NONCE];
    if (tls_client_response_header(r, "Replay-Nonce", nonce, sizeof(nonce)) &&
        nonce[0])
        snprintf(s->nonce, sizeof(s->nonce), "%s", nonce);
}

static bool fetch_directory(struct acme_session *s)
{
    struct tls_client_request req = {
        .method = "GET",
        .url = s->cfg->directory_url ? s->cfg->directory_url
                                     : ACME_DIRECTORY_LETSENCRYPT,
        .user_agent = ACME_USER_AGENT,
        .timeout_ms = s->timeout_ms,
    };
    struct tls_client_response resp = {0};
    if (!tls_client_fetch(&req, &resp))
        LOG_FAIL("acme", "cannot reach the ACME directory at %s", req.url);
    bool ok = false;
    if (resp.status != 200)
        log_problem("directory", &resp);
    else
        ok = acme_directory_parse(resp.body, resp.body_len, &s->dir);
    harvest_nonce(s, &resp);
    tls_client_response_free(&resp);
    if (!ok)
        LOG_FAIL("acme", "the ACME directory did not describe the endpoints this "
                         "client needs");
    return true;
}

static bool refresh_nonce(struct acme_session *s)
{
    struct tls_client_request req = {
        .method = "HEAD",
        .url = s->dir.new_nonce,
        .user_agent = ACME_USER_AGENT,
        .timeout_ms = s->timeout_ms,
    };
    struct tls_client_response resp = {0};
    if (!tls_client_fetch(&req, &resp))
        LOG_FAIL("acme", "cannot reach the newNonce endpoint");
    s->nonce[0] = '\0';
    harvest_nonce(s, &resp);
    tls_client_response_free(&resp);
    if (!s->nonce[0])
        LOG_FAIL("acme", "the CA issued no anti-replay nonce; every signed "
                         "request would be rejected");
    return true;
}

/* One signed POST. `payload` NULL means POST-as-GET. Retries exactly once on
 * badNonce, which is the one error RFC 8555 §6.5 says a client should retry
 * without operator involvement. */
static bool post(struct acme_session *s, const char *url, const char *payload,
                 struct tls_client_response *out)
{
    memset(out, 0, sizeof(*out));
    if (!s->nonce[0] && !refresh_nonce(s))
        return false;

    for (int attempt = 0; attempt < 2; attempt++) {
        const char *kid = s->account_url[0] ? s->account_url : NULL;
        char *body = acme_jws_body(s->account_key, kid, s->nonce, url, payload);
        if (!body)
            LOG_FAIL("acme", "cannot sign a request to %s", url);

        struct tls_client_request req = {
            .method = "POST",
            .url = url,
            .content_type = "application/jose+json",
            .body = body,
            .body_len = strlen(body),
            .user_agent = ACME_USER_AGENT,
            .timeout_ms = s->timeout_ms,
        };
        struct tls_client_response resp = {0};
        const bool sent = tls_client_fetch(&req, &resp);
        free(body);
        if (!sent)
            LOG_FAIL("acme", "cannot reach %s", url);
        harvest_nonce(s, &resp);

        if (resp.status == 400 && resp.body) {
            char type[ACME_MAX_URL];
            char detail[ACME_MAX_DETAIL];
            if (acme_problem_parse(resp.body, resp.body_len, type, sizeof(type),
                                   detail, sizeof(detail)) &&
                strcmp(type, "urn:ietf:params:acme:error:badNonce") == 0 &&
                attempt == 0) {
                tls_client_response_free(&resp);
                if (!s->nonce[0] && !refresh_nonce(s))
                    return false;
                continue;
            }
        }
        *out = resp;
        return true;
    }
    LOG_FAIL("acme", "the CA rejected two consecutive nonces for %s", url);
}

static bool register_account(struct acme_session *s)
{
    char payload[512];
    const char *email = s->cfg->contact_email;
    if (email && email[0]) {
        for (const char *p = email; *p; p++) {
            if (*p == '"' || *p == '\\' || (unsigned char)*p < 0x20)
                LOG_FAIL("acme", "refusing a contact address carrying a quote, "
                                 "backslash or control byte");
        }
        const int n = snprintf(payload, sizeof(payload),
                               "{\"termsOfServiceAgreed\":true,"
                               "\"contact\":[\"mailto:%s\"]}", email);
        if (n < 0 || (size_t)n >= sizeof(payload))
            LOG_FAIL("acme", "contact address is too long for the account request");
    } else {
        snprintf(payload, sizeof(payload), "{\"termsOfServiceAgreed\":true}");
    }

    struct tls_client_response resp = {0};
    if (!post(s, s->dir.new_account, payload, &resp))
        return false;
    bool ok = false;
    if (resp.status == 200 || resp.status == 201) {
        char location[ACME_MAX_URL];
        if (tls_client_response_header(&resp, "Location", location, sizeof(location)) &&
            location[0]) {
            snprintf(s->account_url, sizeof(s->account_url), "%s", location);
            ok = true;
        } else {
            LOG_WARN("acme", "the CA created an account but named no Location");
        }
    } else {
        log_problem("newAccount", &resp);
    }
    tls_client_response_free(&resp);
    if (!ok)
        LOG_FAIL("acme", "cannot establish an ACME account");
    return true;
}

static bool create_order(struct acme_session *s, struct acme_order *order,
                         char *order_url, size_t order_url_len)
{
    char payload[ACME_MAX_DOMAIN + 64];
    const int n = snprintf(payload, sizeof(payload),
                           "{\"identifiers\":[{\"type\":\"dns\",\"value\":\"%s\"}]}",
                           s->cfg->domain);
    if (n < 0 || (size_t)n >= sizeof(payload))
        LOG_FAIL("acme", "domain does not fit an order request");

    struct tls_client_response resp = {0};
    if (!post(s, s->dir.new_order, payload, &resp))
        return false;
    bool ok = false;
    if (resp.status == 201 || resp.status == 200) {
        char location[ACME_MAX_URL];
        if (tls_client_response_header(&resp, "Location", location,
                                       sizeof(location)) && location[0]) {
            snprintf(order_url, order_url_len, "%s", location);
            ok = acme_order_parse(resp.body, resp.body_len, order);
        } else {
            LOG_WARN("acme", "the CA opened an order but named no Location");
        }
    } else {
        log_problem("newOrder", &resp);
    }
    tls_client_response_free(&resp);
    if (!ok)
        LOG_FAIL("acme", "cannot open an ACME order for %s", s->cfg->domain);
    return true;
}

/* POST-as-GET a resource and hand the caller the body. */
static bool fetch_resource(struct acme_session *s, const char *url,
                           struct tls_client_response *out)
{
    if (!post(s, url, NULL, out))
        return false;
    if (out->status != 200) {
        log_problem(url, out);
        tls_client_response_free(out);
        LOG_FAIL("acme", "cannot read %s", url);
    }
    return true;
}

static bool answer_authorization(struct acme_session *s, const char *authz_url,
                                 const uint8_t thumbprint[32])
{
    struct tls_client_response resp = {0};
    if (!fetch_resource(s, authz_url, &resp))
        return false;

    char identifier[ACME_MAX_DOMAIN + 1];
    char status[ACME_MAX_STATUS];
    struct acme_challenge challenge = {0};
    const bool parsed = acme_authorization_parse(resp.body, resp.body_len,
                                                 identifier, sizeof(identifier),
                                                 status, sizeof(status),
                                                 &challenge);
    tls_client_response_free(&resp);
    if (!parsed)
        return false;

    if (strcmp(status, "valid") == 0)
        return true; /* already validated within the CA's reuse window */

    char key_authz[ACME_MAX_TOKEN + 64];
    if (!acme_key_authorization(challenge.token, thumbprint, key_authz,
                                sizeof(key_authz)))
        return false;
    if (!acme_arm_file_write(s->cfg->handoff_path, identifier, key_authz))
        return false;

    bool ok = false;
    struct tls_client_response poke = {0};
    /* RFC 8555 §7.5.1: an empty JSON object tells the CA to start validating. */
    if (post(s, challenge.url, "{}", &poke)) {
        if (poke.status == 200 || poke.status == 202)
            ok = true;
        else
            log_problem("challenge", &poke);
        tls_client_response_free(&poke);
    }

    for (int i = 0; ok && i < s->poll_attempts; i++) {
        platform_sleep_ms(s->poll_interval_ms);
        struct tls_client_response check = {0};
        if (!fetch_resource(s, authz_url, &check)) {
            ok = false;
            break;
        }
        char ident2[ACME_MAX_DOMAIN + 1];
        char status2[ACME_MAX_STATUS];
        struct acme_challenge ch2 = {0};
        const bool reparsed = acme_authorization_parse(check.body, check.body_len,
                                                       ident2, sizeof(ident2),
                                                       status2, sizeof(status2),
                                                       &ch2);
        tls_client_response_free(&check);
        if (!reparsed) {
            ok = false;
            break;
        }
        if (strcmp(status2, "valid") == 0)
            break;
        if (strcmp(status2, "pending") != 0 && strcmp(status2, "processing") != 0) {
            LOG_WARN("acme", "authorization for %s ended in status \"%s\"",
                     identifier, status2);
            ok = false;
            break;
        }
        if (i + 1 == s->poll_attempts) {
            LOG_WARN("acme", "authorization for %s never left \"%s\"", identifier,
                     status2);
            ok = false;
        }
    }

    (void)acme_arm_file_clear(s->cfg->handoff_path);
    if (!ok)
        LOG_FAIL("acme", "the CA did not validate %s over tls-alpn-01", identifier);
    return true;
}

static bool finalize_order(struct acme_session *s, const struct acme_order *order,
                           const char *order_url, const EVP_PKEY *cert_key,
                           char *certificate_url, size_t certificate_url_len)
{
    uint8_t *der = NULL;
    size_t der_len = 0;
    if (!acme_csr_der(cert_key, s->cfg->domain, &der, &der_len))
        return false;

    const size_t b64_len = acme_b64url_encoded_len(der_len);
    char *payload = zcl_malloc(b64_len + 32, "acme_finalize_payload");
    char *b64 = zcl_malloc(b64_len + 1, "acme_finalize_csr");
    bool ok = false;
    if (payload && b64 &&
        acme_b64url_encode(der, der_len, b64, b64_len + 1) == b64_len) {
        const int n = snprintf(payload, b64_len + 32, "{\"csr\":\"%s\"}", b64);
        ok = n > 0 && (size_t)n < b64_len + 32;
    }
    free(der);
    free(b64);
    if (!ok) {
        free(payload);
        LOG_FAIL("acme", "cannot build the finalize request for %s", s->cfg->domain);
    }

    struct tls_client_response resp = {0};
    const bool sent = post(s, order->finalize, payload, &resp);
    free(payload);
    if (!sent)
        return false;
    ok = resp.status == 200 || resp.status == 202;
    if (!ok)
        log_problem("finalize", &resp);
    tls_client_response_free(&resp);
    if (!ok)
        LOG_FAIL("acme", "the CA refused the CSR for %s", s->cfg->domain);

    certificate_url[0] = '\0';
    for (int i = 0; i < s->poll_attempts; i++) {
        struct tls_client_response check = {0};
        if (!fetch_resource(s, order_url, &check))
            return false;
        struct acme_order refreshed = {0};
        const bool parsed = acme_order_parse(check.body, check.body_len, &refreshed);
        tls_client_response_free(&check);
        if (!parsed)
            return false;
        if (strcmp(refreshed.status, "valid") == 0) {
            if (!refreshed.certificate[0])
                LOG_FAIL("acme", "the order is valid but names no certificate");
            snprintf(certificate_url, certificate_url_len, "%s",
                     refreshed.certificate);
            return true;
        }
        if (strcmp(refreshed.status, "processing") != 0 &&
            strcmp(refreshed.status, "ready") != 0)
            LOG_FAIL("acme", "the order for %s ended in status \"%s\"",
                     s->cfg->domain, refreshed.status);
        platform_sleep_ms(s->poll_interval_ms);
    }
    LOG_FAIL("acme", "the order for %s never became valid", s->cfg->domain);
}

/* Write one file atomically at `mode`. Both outputs of an issuance land this
 * way, so a crash mid-renewal cannot leave a certificate paired with the
 * wrong key. */
static bool write_private(const char *path, const void *data, size_t len,
                          bool secret)
{
    char tmp[1024];
    const int n = snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    if (n < 0 || (size_t)n >= sizeof(tmp))
        LOG_FAIL("acme", "path is too long to stage a temporary file: %s", path);

    FILE *f = NULL;
#if !defined(_WIN32)
    (void)unlink(tmp);
    const mode_t mode = secret ? (S_IRUSR | S_IWUSR)
                               : (S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    const int fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL, mode);
    if (fd < 0)
        LOG_FAIL("acme", "cannot create %s", tmp);
    f = fdopen(fd, "wb");
    if (!f) {
        close(fd);
        LOG_FAIL("acme", "cannot buffer writes to %s", tmp);
    }
#else
    (void)secret;
    f = fopen(tmp, "wb");
    if (!f)
        LOG_FAIL("acme", "cannot create %s", tmp);
#endif
    const bool wrote = len == 0 || fwrite(data, 1, len, f) == len;
    const bool flushed = fflush(f) == 0;
    fclose(f);
    if (!wrote || !flushed) {
        remove(tmp);
        LOG_FAIL("acme", "cannot write %zu bytes to %s", len, tmp);
    }
    if (rename(tmp, path) != 0) {
        remove(tmp);
        LOG_FAIL("acme", "cannot move %s into place", path);
    }
    return true;
}

static bool write_key_pem(const EVP_PKEY *key, const char *path)
{
    BIO *bio = BIO_new(BIO_s_mem());
    if (!bio)
        LOG_FAIL("acme", "cannot buffer the certificate key");
    bool ok = PEM_write_bio_PrivateKey(bio, (EVP_PKEY *)key, NULL, NULL, 0,
                                       NULL, NULL) == 1;
    char *data = NULL;
    const long len = ok ? BIO_get_mem_data(bio, &data) : 0;
    ok = ok && len > 0 && data && write_private(path, data, (size_t)len, true);
    BIO_free(bio);
    if (!ok)
        LOG_FAIL("acme", "cannot write the certificate key to %s", path);
    return true;
}

/* WHAT "ISSUED" HAS TO MEAN, AND WHY THE WORKER CHECKS IT.
 *
 * The node adopts a renewed certificate with no restart: its front door
 * watches this exact pair of paths and swaps the running TLS context the
 * moment their file identity changes (net/https_server.h). That makes this
 * function the seam where a renewal becomes end-to-end rather than two
 * halves that happen to exist -- so "success" here is defined as "the node's
 * next connection will serve this", not "two files were written".
 *
 * The three checks below are exactly the three the node's ssl_ctx_build()
 * makes, asked here of the bytes on disk. A pair that fails any of them is
 * refused by the node and the front door keeps serving the OLD certificate,
 * which is the right behaviour there and a silent half-renewal here -- so it
 * is reported as a failure by the program that caused it. The fourth check
 * is not the node's: a leaf that names itself as its own issuer is a
 * self-signed placeholder, never something a certificate authority issued,
 * and writing one to the CA-issued path would defeat the whole point of
 * keeping those two paths distinct. */
static bool issued_pair_is_servable(const char *cert_path, const char *key_path)
{
    FILE *cf = fopen(cert_path, "rb");
    X509 *leaf = cf ? PEM_read_X509(cf, NULL, NULL, NULL) : NULL;
    if (cf)
        fclose(cf);
    if (!leaf)
        LOG_FAIL("acme", "the chain written to %s does not read back as a "
                         "certificate", cert_path);

    FILE *kf = fopen(key_path, "rb");
    EVP_PKEY *key = kf ? PEM_read_PrivateKey(kf, NULL, NULL, NULL) : NULL;
    if (kf)
        fclose(kf);

    const bool key_ok = key != NULL;
    const bool matches = key_ok && X509_check_private_key(leaf, key) == 1;
    const bool ca_issued =
        X509_NAME_cmp(X509_get_issuer_name(leaf), X509_get_subject_name(leaf))
        != 0;
    EVP_PKEY_free(key);
    X509_free(leaf);

    if (!key_ok)
        LOG_FAIL("acme", "the key written to %s does not read back as a "
                         "private key", key_path);
    if (!matches)
        LOG_FAIL("acme", "the key at %s does not belong to the certificate at "
                         "%s; the node would refuse this pair and keep serving "
                         "the certificate it already has", key_path, cert_path);
    if (!ca_issued)
        LOG_FAIL("acme", "the leaf written to %s names itself as its own "
                         "issuer; that is a self-signed certificate, not one a "
                         "certificate authority issued", cert_path);
    return true;
}


bool acme_client_obtain(const struct acme_client_config *cfg)
{
    if (!cfg)
        LOG_FAIL("acme", "cannot run an order without a configuration");
    if (!cfg->domain || !cfg->domain[0])
        LOG_FAIL("acme", "cannot run an order without a domain");
    if (strlen(cfg->domain) > ACME_MAX_DOMAIN)
        LOG_FAIL("acme", "refusing a domain of %zu bytes", strlen(cfg->domain));
    if (!cfg->account_key_path || !cfg->cert_path || !cfg->cert_key_path ||
        !cfg->handoff_path || !cfg->handoff_path[0])
        LOG_FAIL("acme",
                 "cannot run an order without paths for the account key, the "
                 "certificate, its key, and the challenge handoff the node reads");
    if (!cfg->agree_terms_of_service)
        LOG_FAIL("acme",
                 "refusing to create an ACME account: RFC 8555 requires agreeing "
                 "to the CA's terms of service, and only an operator can do that");
    if (!tls_client_trust_store())
        LOG_FAIL("acme",
                 "no CA trust store on this host; the certificate authority's own "
                 "identity could not be checked");

    struct acme_session s = {
        .cfg = cfg,
        .timeout_ms = cfg->timeout_ms > 0 ? cfg->timeout_ms : ACME_DEFAULT_TIMEOUT_MS,
        .poll_attempts = cfg->poll_attempts > 0 ? cfg->poll_attempts
                                                : ACME_DEFAULT_POLL_ATTEMPTS,
        .poll_interval_ms = cfg->poll_interval_ms > 0 ? cfg->poll_interval_ms
                                                      : ACME_DEFAULT_POLL_INTERVAL_MS,
    };
    s.account_key = acme_account_key_load_or_create(cfg->account_key_path);
    if (!s.account_key)
        LOG_FAIL("acme", "cannot open the ACME account key at %s",
                 cfg->account_key_path);

    uint8_t thumbprint[32];
    EVP_PKEY *cert_key = NULL;
    char order_url[ACME_MAX_URL] = "";
    char certificate_url[ACME_MAX_URL] = "";
    struct acme_order order = {0};
    bool ok = false;

    if (!acme_jwk_thumbprint(s.account_key, thumbprint))
        goto done;
    if (!fetch_directory(&s))
        goto done;
    if (!refresh_nonce(&s))
        goto done;
    if (!register_account(&s))
        goto done;
    if (!create_order(&s, &order, order_url, sizeof(order_url)))
        goto done;

    for (size_t i = 0; i < order.num_authorizations; i++) {
        if (!answer_authorization(&s, order.authorizations[i], thumbprint))
            goto done;
    }

    cert_key = EVP_EC_gen("P-256");
    if (!cert_key) {
        LOG_WARN("acme", "cannot generate a key for the new certificate");
        goto done;
    }
    if (!finalize_order(&s, &order, order_url, cert_key, certificate_url,
                        sizeof(certificate_url)))
        goto done;

    {
        struct tls_client_response chain = {0};
        if (!fetch_resource(&s, certificate_url, &chain))
            goto done;
        size_t count = 0;
        const bool wellformed =
            acme_chain_is_wellformed(chain.body, chain.body_len, &count);
        /* Key first, then chain: a reader that sees the new chain must never
         * find the old key beside it. */
        ok = wellformed && write_key_pem(cert_key, cfg->cert_key_path) &&
             write_private(cfg->cert_path, chain.body, chain.body_len, false) &&
             issued_pair_is_servable(cfg->cert_path, cfg->cert_key_path);
        if (ok)
            LOG_INFO("acme", "issued a %zu-certificate chain for %s", count,
                     cfg->domain);
        tls_client_response_free(&chain);
    }

done:
    (void)acme_arm_file_clear(cfg->handoff_path);
    EVP_PKEY_free(cert_key);
    EVP_PKEY_free(s.account_key);
    if (!ok)
        LOG_FAIL("acme", "no certificate was issued for %s", cfg->domain);
    return true;
}
