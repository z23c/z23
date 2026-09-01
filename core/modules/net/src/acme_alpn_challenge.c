/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * TLS-ALPN-01 responder. See net/acme_challenge.h for what the CA expects.
 *
 * The whole hook into the front door is acme_alpn_install(): one ALPN
 * selection callback. Everything else — the armed state, the ephemeral key,
 * the certificate — lives here, so core/modules/net/src/https_server.c gains a single
 * line and no new concept. The certificate SKELETON is not built here: it is
 * the one in core/modules/net/src/acme_selfsigned.c, shared with the boot placeholder,
 * so there is a single answer to "what does a certificate this node signs
 * look like".
 */

#if !defined(_WIN32)
#define _XOPEN_SOURCE 700
#endif

#include "net/acme_challenge.h"

#include "net/acme_arm_file.h"
#include "net/acme_b64url.h"
#include "net/acme_selfsigned.h"

#include <openssl/asn1.h>
#include <openssl/err.h>
#include <openssl/objects.h>
#include <openssl/sha.h>
#include <openssl/x509v3.h>

#include <ctype.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#include "base/log_macros.h"

/* ── pure pieces ─────────────────────────────────────────────────────── */



bool acme_alpn_challenge_digest(const char *key_authz, uint8_t out[32])
{
    if (!key_authz || !key_authz[0] || !out)
        LOG_FAIL("acme", "cannot hash an empty key authorization");
    SHA256((const unsigned char *)key_authz, strlen(key_authz), out);
    return true;
}

/* ── the challenge certificate ───────────────────────────────────────── */

/* RFC 8737 §3: extnValue is the DER encoding of an OCTET STRING holding the
 * digest — so the digest is wrapped twice, once by ASN.1 here and once by
 * the extension's own extnValue OCTET STRING. Returns an extension the
 * caller owns; the skeleton around it (key, serial, validity, subject,
 * subjectAltName, self-issuance, signature) is built by the one builder in
 * acme_selfsigned.c, which is also what writes the boot placeholder. */
static X509_EXTENSION *make_acme_identifier(const uint8_t digest[32])
{
    ASN1_OCTET_STRING *payload = ASN1_OCTET_STRING_new();
    ASN1_OCTET_STRING *wrapper = NULL;
    ASN1_OBJECT *obj = NULL;
    X509_EXTENSION *ext = NULL;
    unsigned char *der = NULL;

    if (!payload)
        goto done;
    if (ASN1_OCTET_STRING_set(payload, digest, 32) != 1)
        goto done;
    const int der_len = i2d_ASN1_OCTET_STRING(payload, &der);
    if (der_len <= 0 || !der)
        goto done;
    wrapper = ASN1_OCTET_STRING_new();
    if (!wrapper || ASN1_OCTET_STRING_set(wrapper, der, der_len) != 1)
        goto done;
    obj = OBJ_txt2obj(ACME_ID_OID_TEXT, 1);
    if (!obj)
        goto done;
    ext = X509_EXTENSION_create_by_OBJ(NULL, obj, 1 /* critical */, wrapper);

done:
    ASN1_OBJECT_free(obj);
    ASN1_OCTET_STRING_free(wrapper);
    OPENSSL_free(der);
    ASN1_OCTET_STRING_free(payload);
    return ext;
}

bool acme_alpn_challenge_certificate(const char *domain, const char *key_authz,
                                     X509 **out_cert, EVP_PKEY **out_key)
{
    if (!out_cert || !out_key)
        return false;
    *out_cert = NULL;
    *out_key = NULL;
    if (!acme_domain_is_ldh(domain))
        LOG_FAIL("acme", "refusing to build a challenge certificate for a "
                         "domain that is not a plain LDH name");
    uint8_t digest[32];
    if (!acme_alpn_challenge_digest(key_authz, digest))
        return false;

    X509_EXTENSION *ext = make_acme_identifier(digest);
    if (!ext)
        LOG_FAIL("acme", "cannot attach the acmeIdentifier extension");

    /* Backdated an hour so a CA whose clock runs behind ours still sees a
     * valid certificate; short-lived because it exists for one handshake.
     * No subject O: a challenge certificate is presented only to a CA that
     * is mid-validation, never to a browser, and the CA reads the
     * acmeIdentifier extension, not the name. */
    const struct acme_selfsigned_spec spec = {
        .domain = domain,
        .organization = NULL,
        .backdate_seconds = 3600,
        .lifetime_seconds = 7 * 24 * 3600,
        .extra = ext,
    };
    const bool ok = acme_selfsigned_build(&spec, out_cert, out_key);
    X509_EXTENSION_free(ext);
    if (!ok)
        LOG_FAIL("acme", "cannot build the TLS-ALPN-01 challenge certificate "
                         "for %s", domain);
    return true;
}

/* ── the armed state ─────────────────────────────────────────────────── */

static pthread_mutex_t g_armed_mutex = PTHREAD_MUTEX_INITIALIZER;
static char g_handoff_path[1024] = "";
static char g_armed_domain[ACME_MAX_DOMAIN + 1] = "";
static X509 *g_armed_cert = NULL;
static EVP_PKEY *g_armed_key = NULL;

static void armed_clear_locked(void)
{
    X509_free(g_armed_cert);
    EVP_PKEY_free(g_armed_key);
    g_armed_cert = NULL;
    g_armed_key = NULL;
    g_armed_domain[0] = '\0';
}

bool acme_alpn_challenge_arm(const char *domain, const char *key_authz)
{
    X509 *cert = NULL;
    EVP_PKEY *key = NULL;
    if (!acme_alpn_challenge_certificate(domain, key_authz, &cert, &key))
        return false;
    pthread_mutex_lock(&g_armed_mutex);
    armed_clear_locked();
    g_armed_cert = cert;
    g_armed_key = key;
    snprintf(g_armed_domain, sizeof(g_armed_domain), "%s", domain);
    pthread_mutex_unlock(&g_armed_mutex);
    return true;
}

void acme_alpn_challenge_disarm(void)
{
    pthread_mutex_lock(&g_armed_mutex);
    armed_clear_locked();
    pthread_mutex_unlock(&g_armed_mutex);
}

bool acme_alpn_challenge_armed(void)
{
    pthread_mutex_lock(&g_armed_mutex);
    const bool armed = g_armed_cert != NULL;
    pthread_mutex_unlock(&g_armed_mutex);
    return armed;
}

void acme_alpn_challenge_set_handoff_file(const char *path)
{
    pthread_mutex_lock(&g_armed_mutex);
    snprintf(g_handoff_path, sizeof(g_handoff_path), "%s", path ? path : "");
    pthread_mutex_unlock(&g_armed_mutex);
}

bool acme_alpn_challenge_arm_from_file(const char *path)
{
    char domain[ACME_MAX_DOMAIN + 1];
    char key_authz[ACME_MAX_KEY_AUTHZ];
    if (!acme_arm_file_read(path, domain, sizeof(domain), key_authz,
                            sizeof(key_authz)))
        return false;
    return acme_alpn_challenge_arm(domain, key_authz);
}

/* Take a reference to the armed material when `servername` matches. */
static bool armed_take(const char *servername, X509 **cert, EVP_PKEY **key)
{
    bool ok = false;
    pthread_mutex_lock(&g_armed_mutex);
    if (g_armed_cert && g_armed_key && servername) {
        size_t i = 0;
        for (; g_armed_domain[i] && servername[i]; i++) {
            if (tolower((unsigned char)g_armed_domain[i]) !=
                tolower((unsigned char)servername[i]))
                break;
        }
        if (g_armed_domain[i] == '\0' && servername[i] == '\0' &&
            X509_up_ref(g_armed_cert) == 1) {
            if (EVP_PKEY_up_ref(g_armed_key) == 1) {
                *cert = g_armed_cert;
                *key = g_armed_key;
                ok = true;
            } else {
                X509_free(g_armed_cert);
            }
        }
    }
    pthread_mutex_unlock(&g_armed_mutex);
    return ok;
}

/* ── the front-door seam ─────────────────────────────────────────────── */

static bool alpn_list_offers(const unsigned char *in, unsigned int inlen,
                             const char *proto)
{
    const size_t plen = strlen(proto);
    unsigned int i = 0;
    while (i < inlen) {
        const unsigned int len = in[i];
        if (len == 0 || i + 1 + len > inlen)
            return false;
        if (len == plen && memcmp(in + i + 1, proto, plen) == 0)
            return true;
        i += 1 + len;
    }
    return false;
}

static int alpn_select(SSL *ssl, const unsigned char **out, unsigned char *outlen,
                       const unsigned char *in, unsigned int inlen, void *arg)
{
    (void)arg;
    if (!alpn_list_offers(in, inlen, ACME_ALPN_PROTOCOL))
        return SSL_TLSEXT_ERR_NOACK;

    const char *servername = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
    X509 *cert = NULL;
    EVP_PKEY *key = NULL;
    if (!armed_take(servername, &cert, &key)) {
        /* Nothing armed in this process. The worker that computed the key
         * authorization is a separate program (tools/acme), so the only
         * place it could have put one is the handoff file. Read it here and
         * nowhere else: this is the one code path where a client has already
         * proven it is speaking ACME validation, not browsing. */
        char path[sizeof(g_handoff_path)];
        pthread_mutex_lock(&g_armed_mutex);
        snprintf(path, sizeof(path), "%s", g_handoff_path);
        pthread_mutex_unlock(&g_armed_mutex);
        if (path[0] && acme_alpn_challenge_arm_from_file(path))
            armed_take(servername, &cert, &key);
    }
    if (!cert || !key) {
        /* Offering acme-tls/1 while no validation is in flight is either a
         * scanner or a stale retry. Do not negotiate it, and do not present
         * a challenge certificate — the ordinary certificate is served. */
        return SSL_TLSEXT_ERR_NOACK;
    }

    /* The ALPN callback runs before the server chooses its certificate, so
     * an SSL-scoped certificate set here is the one presented on this
     * connection only; the listener's own SSL_CTX is untouched. */
    const bool installed = SSL_use_certificate(ssl, cert) == 1 &&
                           SSL_use_PrivateKey(ssl, key) == 1;
    X509_free(cert);
    EVP_PKEY_free(key);
    if (!installed) {
        LOG_WARN("acme", "cannot present the challenge certificate on this connection");
        return SSL_TLSEXT_ERR_NOACK;
    }

    static const unsigned char selected[] = ACME_ALPN_PROTOCOL;
    *out = selected;
    *outlen = (unsigned char)(sizeof(selected) - 1);
    return SSL_TLSEXT_ERR_OK;
}

bool acme_alpn_install(SSL_CTX *ctx)
{
    if (!ctx)
        LOG_FAIL("acme", "cannot install the TLS-ALPN-01 responder without a TLS context");
    SSL_CTX_set_alpn_select_cb(ctx, alpn_select, NULL);
    return true;
}
