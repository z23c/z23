/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The certificate half of the public front door: the one place a TLS context
 * is built, the counted references that let a renewed certificate replace it
 * under live traffic, the per-name (SNI) contexts, and the report of whether
 * what is served is self-signed. Moved out of https_server.c unchanged;
 * https_server.c keeps the listeners, the worker pool and request serving,
 * and reaches this file only through https_server_internal.h. */

#if !defined(_WIN32)
#define _XOPEN_SOURCE 700
#endif
#include "net/acme_challenge.h"
#include "net/acme_selfsigned.h"
#include "net/https_server.h"
#include "https_server_internal.h"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#if !defined(_WIN32)
#include <strings.h>
#endif
#include "util/log_macros.h"

/* The TLS context in service. Guarded by g_cert_mutex (below): it can be
 * replaced under live traffic when a renewed certificate lands on disk. */
static SSL_CTX *g_ssl_ctx = NULL;

/* ── The served certificate, and swapping it under live traffic ───────
 *
 * See net/https_server.h for why the front door watches the certificate
 * FILE and when it looks. This section owns three things: the one place a
 * TLS context is ever built, the reference discipline that lets a context be
 * replaced while handshakes are in flight, and the honest report of whether
 * what is being served was vouched for by anybody. */

/* Enough of a file to notice it was replaced. rename() from a freshly
 * created temporary — which is how both the certificate worker and the
 * placeholder writer publish — always yields a new inode, so st_ino carries
 * the change even when size and mtime happen to repeat. Size and mtime are
 * kept beside it because st_ino is not meaningful on Windows. */
struct cert_file_id {
    bool     present;
    uint64_t dev;
    uint64_t ino;
    uint64_t size;
    int64_t  mtime_sec;
};

/* Guards g_ssl_ctx, the watched paths, and the last-seen file identities.
 * Held only for pointer work and small copies — never across a file read, a
 * context build, or a handshake. Lock order: g_https_state_mutex may be held
 * while taking this; never the other way round. */
static pthread_mutex_t g_cert_mutex = PTHREAD_MUTEX_INITIALIZER;
static char g_watch_cert[1024] = "";
static char g_watch_key[1024] = "";
static struct cert_file_id g_seen_cert;
static struct cert_file_id g_seen_key;
static _Atomic bool g_cert_self_signed = false;

static bool cert_file_id_read(const char *path, struct cert_file_id *out)
{
    memset(out, 0, sizeof(*out));
    struct stat st;
    if (!path || !path[0] || stat(path, &st) != 0)
        return false;
    out->present = true;
    out->dev = (uint64_t)st.st_dev;
    out->ino = (uint64_t)st.st_ino;
    out->size = (uint64_t)(st.st_size < 0 ? 0 : st.st_size);
    out->mtime_sec = (int64_t)st.st_mtime;
    return true;
}

/* Field by field, deliberately: a memcmp over this struct would also read
 * whatever the compiler put in the padding between the members. */
static bool cert_file_id_same(const struct cert_file_id *a,
                              const struct cert_file_id *b)
{
    return a->present == b->present && a->dev == b->dev && a->ino == b->ino &&
           a->size == b->size && a->mtime_sec == b->mtime_sec;
}

/* ── More than one name on one listener (TLS SNI) ─────────────────────
 *
 * WHY. One host can be asked for by more than one name — an explorer at one
 * name and an installer origin at another — and a certificate authority
 * issues per name. With a single context the name that is not in the
 * certificate fails the handshake with a name mismatch, which is a hard
 * failure the client cannot work around.
 *
 * WHAT IS ADDED, AND WHAT IS NOT. Each ADDITIONAL name gets its own entry
 * here: its own watched pair, its own last-seen file identity, its own
 * SSL_CTX built by the same https_ssl_ctx_build() as the default. The default
 * context above is unchanged and stays the answer for every case that is not
 * an exact match — no name configured, no SNI sent, or a name nobody
 * configured. A server with no additional names never reaches any of this;
 * the callback returns before it looks at anything, so the wire is byte for
 * byte what it was.
 *
 * LOCKING. The same g_cert_mutex as the default context, for the same
 * reason and with the same discipline: held for pointer work and small
 * copies only, never across a file read, a context build, or a handshake.
 * Every reader takes a counted reference (sni_ctx_acquire) before using a
 * context, so a reload racing an in-flight handshake drops a reference
 * rather than freeing something in use.
 *
 * Entries are append-only for the life of a listener — a name is added, its
 * certificate is replaced in place, and the whole table is torn down in
 * https_ssl_ctx_retire_all(). Slot indices are therefore stable, which is what
 * lets the refresh below drop the lock between reading a slot and
 * publishing into it. */
#define HTTPS_MAX_SNI_NAMES 8

struct sni_cert {
    char name[256];                 /* the name in SNI, as configured */
    char cert[1024];
    char key[1024];
    SSL_CTX *ctx;                   /* NULL until the pair first loads */
    struct cert_file_id seen_cert;
    struct cert_file_id seen_key;
};

/* Guarded by g_cert_mutex. g_sni_count only ever grows, and only under that
 * mutex; it is read without it in exactly one place (the fast path of the
 * servername callback) where a stale zero costs nothing but a default
 * certificate on one handshake — hence the atomic mirror. */
static struct sni_cert g_sni[HTTPS_MAX_SNI_NAMES];
static unsigned g_sni_count = 0;
static _Atomic unsigned g_sni_names_configured = 0;

/* SNI names are ASCII (LDH) and case-insensitive; a client is free to send
 * any case. Deliberately not strcasecmp(): that one is locale-sensitive, and
 * a locale where 'I' does not lowercase to 'i' would silently change which
 * certificate a host serves. */
static bool sni_name_equal(const char *a, const char *b)
{
    if (!a || !b)
        return false;
    size_t i = 0;
    for (; a[i] && b[i]; i++) {
        unsigned char ca = (unsigned char)a[i];
        unsigned char cb = (unsigned char)b[i];
        if (ca >= 'A' && ca <= 'Z') ca = (unsigned char)(ca - 'A' + 'a');
        if (cb >= 'A' && cb <= 'Z') cb = (unsigned char)(cb - 'A' + 'a');
        if (ca != cb)
            return false;
    }
    return a[i] == '\0' && b[i] == '\0';
}

/* A counted reference to the context configured for `name`, or NULL when no
 * such name is configured or its pair has not loaded yet. Caller frees. */
static SSL_CTX *sni_ctx_acquire(const char *name)
{
    SSL_CTX *ctx = NULL;
    pthread_mutex_lock(&g_cert_mutex);
    for (unsigned i = 0; i < g_sni_count; i++) {
        if (!sni_name_equal(g_sni[i].name, name))
            continue;
        ctx = g_sni[i].ctx;
        if (ctx && SSL_CTX_up_ref(ctx) != 1)
            ctx = NULL;
        break;
    }
    pthread_mutex_unlock(&g_cert_mutex);
    return ctx;
}

/* Pick the certificate for the name this client asked for.
 *
 * ORDER AGAINST TLS-ALPN-01, WHICH MATTERS MORE THAN ANYTHING ELSE HERE.
 * OpenSSL runs the extension finalisers in extension order, and server_name
 * comes before application_layer_protocol_negotiation — so this callback
 * runs FIRST and the ALPN callback (acme_alpn_install) runs after it. That
 * is the right way round, and it is the reason the ACME challenge still
 * wins: this callback swaps the connection's SSL_CTX, which resets the
 * connection's certificate to the new context's; the ALPN callback then sets
 * an SSL-SCOPED certificate with SSL_use_certificate(), which overrides the
 * context's for this connection only. A per-name context therefore cannot
 * displace a challenge certificate. It also cannot lose the ALPN callback
 * itself: every context, default and per-name, is built by https_ssl_ctx_build()
 * and so carries the same acme_alpn_install() responder. If the order were
 * ever the other way round the challenge certificate would be discarded and
 * no certificate could be renewed — test_https_sni_select asserts the
 * outcome from the wire rather than trusting this paragraph.
 *
 * NOACK, not an alert, for every case that keeps the default certificate.
 * Refusing the handshake because a name is unknown would take a bare-IP
 * client, an old client that sends no SNI, and any name the operator has not
 * configured off the server entirely. The default certificate is served
 * instead and the server simply does not claim to have accepted the name —
 * which is exactly the wire behaviour of a server with no callback at all,
 * so the single-certificate default is unchanged. */
static int sni_servername_cb(SSL *ssl, int *al, void *arg)
{
    (void)arg;
    (void)al;
    if (atomic_load(&g_sni_names_configured) == 0)
        return SSL_TLSEXT_ERR_NOACK;

    const char *name = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
    if (!name || !name[0])
        return SSL_TLSEXT_ERR_NOACK;

    SSL_CTX *ctx = sni_ctx_acquire(name);
    if (!ctx)
        return SSL_TLSEXT_ERR_NOACK;

    /* SSL_set_SSL_CTX takes its own reference; ours is released right after,
     * so the connection holds exactly one and a concurrent reload frees
     * nothing that is still in use. */
    const bool swapped = SSL_set_SSL_CTX(ssl, ctx) != NULL;
    SSL_CTX_free(ctx);
    if (!swapped) {
        LOG_WARN("https", "cannot present the certificate configured for "
                          "this name; serving the default one");
        return SSL_TLSEXT_ERR_NOACK;
    }
    return SSL_TLSEXT_ERR_OK;
}

/* THE one place a TLS context is built. Start and reload both come through
 * here, so a reloaded context cannot quietly differ from the one the
 * listener started with — same minimum protocol version, same TLS-ALPN-01
 * responder, same certificate/key correspondence check. Returns NULL having
 * touched nothing global; the caller keeps whatever it was already serving. */
SSL_CTX *https_ssl_ctx_build(const char *cert_path, const char *key_path)
{
    const char *why = NULL;
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        LOG_NULL("https", "SSL_CTX_new failed");
    }

    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);

    /* TLS-ALPN-01 responder (RFC 8737). One call: the module owns the armed
     * state and the challenge certificate, and presents it only while an ACME
     * validation is in flight for the name in SNI. Port 80 is deliberately not
     * forwarded here, so this is the only challenge type the node can answer
     * -- see net/acme_challenge.h. */
    /* Certificate selection by the name the client asked for. Installed on
     * EVERY context, default and per-name alike, so that whichever context a
     * connection lands on is shaped identically — and, in particular, still
     * carries the TLS-ALPN-01 responder installed just above. */
    SSL_CTX_set_tlsext_servername_callback(ctx, sni_servername_cb);

    if (!acme_alpn_install(ctx))
        why = "the TLS-ALPN-01 certificate responder could not be installed";
    else if (SSL_CTX_use_certificate_chain_file(ctx, cert_path) <= 0)
        why = "the certificate chain did not load";
    else if (SSL_CTX_use_PrivateKey_file(ctx, key_path, SSL_FILETYPE_PEM) <= 0)
        why = "the private key did not load";
    else if (!SSL_CTX_check_private_key(ctx))
        why = "the private key does not belong to the certificate";

    if (why) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        LOG_NULL("https", "cert=%s key=%s: %s", cert_path, key_path, why);
    }
    return ctx;
}

/* The leaf the context will actually present. Self-issued means nobody
 * vouched for it — see net/acme_selfsigned.h. */
static bool ssl_ctx_leaf_is_self_issued(SSL_CTX *ctx)
{
    return ctx && acme_certificate_is_self_issued(SSL_CTX_get0_certificate(ctx));
}

/* Take a counted reference to the context currently in service. The caller
 * must SSL_CTX_free() it. Holding a reference is what makes the swap below
 * safe: a context is never freed while anyone still holds one. */
SSL_CTX *https_ssl_ctx_acquire(void)
{
    pthread_mutex_lock(&g_cert_mutex);
    SSL_CTX *ctx = g_ssl_ctx;
    if (ctx && SSL_CTX_up_ref(ctx) != 1)
        ctx = NULL;
    pthread_mutex_unlock(&g_cert_mutex);
    return ctx;
}

/* Publish `ctx` and retire the previous one.
 *
 * WHY THIS IS ATOMIC FROM A CLIENT'S POINT OF VIEW. The new context is fully
 * built and its key/certificate correspondence already checked before this
 * runs, so what is published is never half-configured. The pointer swap
 * itself happens under one mutex, and every connection reads that pointer
 * exactly once (https_ssl_ctx_acquire) before its handshake, so a connection sees
 * one whole context or the other — never a certificate from one and a key
 * from the next.
 *
 * WHY NOTHING IN FLIGHT BREAKS. Retiring the old context is a reference
 * DROP, not a free: SSL_new() took its own reference for every handshake and
 * every open connection using it, so the old context stays alive until the
 * last of them finishes. */
static void ssl_ctx_install(SSL_CTX *ctx, const struct cert_file_id *cert_id,
                            const struct cert_file_id *key_id)
{
    const bool self_signed = ssl_ctx_leaf_is_self_issued(ctx);
    pthread_mutex_lock(&g_cert_mutex);
    SSL_CTX *old = g_ssl_ctx;
    g_ssl_ctx = ctx;
    if (cert_id)
        g_seen_cert = *cert_id;
    if (key_id)
        g_seen_key = *key_id;
    atomic_store(&g_cert_self_signed, self_signed);
    pthread_mutex_unlock(&g_cert_mutex);
    if (old)
        SSL_CTX_free(old);
}

void https_ssl_ctx_retire_all(void)
{
    SSL_CTX *retired[HTTPS_MAX_SNI_NAMES];
    unsigned retired_n = 0;

    pthread_mutex_lock(&g_cert_mutex);
    SSL_CTX *old = g_ssl_ctx;
    g_ssl_ctx = NULL;
    g_watch_cert[0] = '\0';
    g_watch_key[0] = '\0';
    memset(&g_seen_cert, 0, sizeof(g_seen_cert));
    memset(&g_seen_key, 0, sizeof(g_seen_key));
    /* The per-name table goes with it: a stopped listener holds no name.
     * References are collected and dropped outside the lock, the same
     * discipline the default context uses. */
    for (unsigned i = 0; i < g_sni_count; i++) {
        if (g_sni[i].ctx)
            retired[retired_n++] = g_sni[i].ctx;
    }
    memset(g_sni, 0, sizeof(g_sni));
    g_sni_count = 0;
    atomic_store(&g_sni_names_configured, 0u);
    atomic_store(&g_cert_self_signed, false);
    pthread_mutex_unlock(&g_cert_mutex);
    if (old)
        SSL_CTX_free(old);
    for (unsigned i = 0; i < retired_n; i++)
        SSL_CTX_free(retired[i]);
}

/* Say which of the two kinds is on the wire. A self-signed certificate makes
 * every browser refuse the page, so the operator will be looking for this
 * line; it must name what to do about it rather than merely complain. */
static void announce_certificate(const char *cert_path, bool self_signed,
                                 bool at_start)
{
    if (!self_signed) {
        printf("HTTPS: %s certificate issued by a certificate authority: %s\n",
               at_start ? "serving the" : "now serving the renewed", cert_path);
        return;
    }
    printf("HTTPS: ***** SERVING A SELF-SIGNED CERTIFICATE *****\n"
           "HTTPS: %s names itself as its own issuer, so no browser will\n"
           "HTTPS: accept it and `curl https://...` will refuse it. This is the\n"
           "HTTPS: placeholder that lets the TLS-ALPN-01 listener exist before a\n"
           "HTTPS: certificate authority has ever answered — it is what makes the\n"
           "HTTPS: FIRST certificate obtainable with no human. Run\n"
           "HTTPS:   zclassic23-acme obtain --domain <name> --agree-tos ...\n"
           "HTTPS: and the front door swaps to the issued certificate with no\n"
           "HTTPS: restart. Until then this host is NOT serving valid HTTPS.\n",
           cert_path);
}

/* Build the pair at these paths and put it in service, or keep what is
 * already there. Never leaves the server without a context. */
static bool cert_swap_from(const char *cert_path, const char *key_path)
{
    /* Identities first: a file that changes while the context is being built
     * must still look changed on the next inspection. */
    struct cert_file_id cert_id;
    struct cert_file_id key_id;
    (void)cert_file_id_read(cert_path, &cert_id);
    (void)cert_file_id_read(key_path, &key_id);

    SSL_CTX *ctx = https_ssl_ctx_build(cert_path, key_path);
    if (!ctx)
        LOG_FAIL("https", "refusing to put the pair at %s into service; the "
                          "front door keeps serving the certificate it has",
                 cert_path);

    const bool self_signed = ssl_ctx_leaf_is_self_issued(ctx);
    ssl_ctx_install(ctx, &cert_id, &key_id);
    announce_certificate(cert_path, self_signed, false);
    return true;
}

void https_server_watch_certificate(const char *cert_path, const char *key_path)
{
    if (!cert_path || !cert_path[0] || !key_path || !key_path[0]) {
        LOG_WARN("https", "a certificate pair to watch needs both a "
                          "certificate path and a key path; the front door "
                          "keeps watching whatever it watched before");
        return;
    }
    pthread_mutex_lock(&g_cert_mutex);
    snprintf(g_watch_cert, sizeof(g_watch_cert), "%s", cert_path);
    snprintf(g_watch_key, sizeof(g_watch_key), "%s", key_path);
    /* A newly named pair has not been inspected yet, whatever was inspected
     * before. Absent is a real observation: it is what makes the pair being
     * CREATED later register as a change. */
    memset(&g_seen_cert, 0, sizeof(g_seen_cert));
    memset(&g_seen_key, 0, sizeof(g_seen_key));
    pthread_mutex_unlock(&g_cert_mutex);
}

bool https_server_watch_certificate_for_name(const char *name,
                                             const char *cert_path,
                                             const char *key_path)
{
    if (!name || !cert_path || !cert_path[0] || !key_path || !key_path[0])
        LOG_FAIL("https", "a name needs both a certificate path and a key "
                          "path before it can be served");
    /* The same predicate the challenge certificate builder uses. A name that
     * is not a plain LDH name cannot appear in SNI from any client that
     * matters, and refusing it here is also what keeps a configured name
     * from being anything but a name. */
    if (!acme_domain_is_ldh(name))
        LOG_FAIL("https", "refusing to serve a certificate for a name that is "
                          "not a plain LDH domain name");
    if (strlen(name) >= sizeof(g_sni[0].name) ||
        strlen(cert_path) >= sizeof(g_sni[0].cert) ||
        strlen(key_path) >= sizeof(g_sni[0].key))
        LOG_FAIL("https", "the certificate paths for %s do not fit", name);

    bool ok = false;
    pthread_mutex_lock(&g_cert_mutex);
    unsigned slot = g_sni_count;
    for (unsigned i = 0; i < g_sni_count; i++) {
        if (sni_name_equal(g_sni[i].name, name)) {
            slot = i;
            break;
        }
    }
    if (slot < HTTPS_MAX_SNI_NAMES) {
        snprintf(g_sni[slot].name, sizeof(g_sni[slot].name), "%s", name);
        snprintf(g_sni[slot].cert, sizeof(g_sni[slot].cert), "%s", cert_path);
        snprintf(g_sni[slot].key, sizeof(g_sni[slot].key), "%s", key_path);
        /* Newly named, so nothing has been inspected yet — the same reset
         * the default watch does, and for the same reason: absent is a real
         * observation, and it is what makes the pair APPEARING a change.
         * Any context already in service for this name stays in service
         * until a loadable pair replaces it. */
        memset(&g_sni[slot].seen_cert, 0, sizeof(g_sni[slot].seen_cert));
        memset(&g_sni[slot].seen_key, 0, sizeof(g_sni[slot].seen_key));
        if (slot == g_sni_count)
            g_sni_count++;
        atomic_store(&g_sni_names_configured, g_sni_count);
        ok = true;
    }
    pthread_mutex_unlock(&g_cert_mutex);
    if (!ok)
        LOG_FAIL("https", "the front door serves at most %d additional names; "
                          "%s was not added",
                 HTTPS_MAX_SNI_NAMES, name);
    return true;
}

static bool sni_slot_claim(unsigned i, const char *name, const struct cert_file_id *cert_id,
                           const struct cert_file_id *key_id)
{
    pthread_mutex_lock(&g_cert_mutex);
    const bool claimed = i < g_sni_count &&
                         sni_name_equal(g_sni[i].name, name) &&
                         (!cert_file_id_same(&g_sni[i].seen_cert, cert_id) ||
                          !cert_file_id_same(&g_sni[i].seen_key, key_id));
    if (claimed) {
        g_sni[i].seen_cert = *cert_id;
        g_sni[i].seen_key = *key_id;
    }
    pthread_mutex_unlock(&g_cert_mutex);
    return claimed;
}

/* One pass over the per-name table, same shape as the default pair's refresh
 * below: read the slot under the lock, stat outside it, claim the
 * observation under the lock so two workers racing build one context, build
 * outside it, publish under it. Returns true when at least one name's
 * context was actually replaced.
 *
 * A name whose pair is absent or unloadable is skipped, not fatal, and does
 * not disturb any other name — the point of separate contexts is that one
 * name's certificate expiring, renewing, or arriving late is invisible to
 * every other name and to the default. */
static bool sni_certificates_refresh(void)
{
    bool swapped = false;

    for (unsigned i = 0; i < HTTPS_MAX_SNI_NAMES; i++) {
        char name[sizeof(g_sni[0].name)];
        char cert_path[sizeof(g_sni[0].cert)];
        char key_path[sizeof(g_sni[0].key)];
        struct cert_file_id seen_cert;
        struct cert_file_id seen_key;

        pthread_mutex_lock(&g_cert_mutex);
        const bool live = i < g_sni_count;
        if (live) {
            snprintf(name, sizeof(name), "%s", g_sni[i].name);
            snprintf(cert_path, sizeof(cert_path), "%s", g_sni[i].cert);
            snprintf(key_path, sizeof(key_path), "%s", g_sni[i].key);
            seen_cert = g_sni[i].seen_cert;
            seen_key = g_sni[i].seen_key;
        }
        pthread_mutex_unlock(&g_cert_mutex);
        if (!live)
            break;

        struct cert_file_id cert_id;
        struct cert_file_id key_id;
        (void)cert_file_id_read(cert_path, &cert_id);
        (void)cert_file_id_read(key_path, &key_id);
        if (!cert_id.present || !key_id.present)
            continue;
        if (cert_file_id_same(&cert_id, &seen_cert) &&
            cert_file_id_same(&key_id, &seen_key))
            continue;

        if (!sni_slot_claim(i, name, &cert_id, &key_id))
            continue;

        SSL_CTX *ctx = https_ssl_ctx_build(cert_path, key_path);
        if (!ctx) {
            LOG_WARN("https", "refusing to serve %s from the pair at %s; the "
                              "front door keeps whatever it had for that name",
                     name, cert_path);
            continue;
        }

        SSL_CTX *old = NULL;
        pthread_mutex_lock(&g_cert_mutex);
        if (i < g_sni_count && sni_name_equal(g_sni[i].name, name)) {
            old = g_sni[i].ctx;
            g_sni[i].ctx = ctx;
            ctx = NULL;
        }
        pthread_mutex_unlock(&g_cert_mutex);
        if (ctx) {
            /* The slot was renamed underneath us. Nothing was published. */
            SSL_CTX_free(ctx);
            continue;
        }
        if (old)
            SSL_CTX_free(old);
        swapped = true;
        printf("HTTPS: serving %s from its own certificate at %s\n",
               name, cert_path);
    }
    return swapped;
}

bool https_server_reload_certificate(void)
{
    char cert_path[sizeof(g_watch_cert)];
    char key_path[sizeof(g_watch_key)];
    pthread_mutex_lock(&g_cert_mutex);
    snprintf(cert_path, sizeof(cert_path), "%s", g_watch_cert);
    snprintf(key_path, sizeof(key_path), "%s", g_watch_key);
    pthread_mutex_unlock(&g_cert_mutex);
    if (!cert_path[0] || !key_path[0])
        LOG_FAIL("https", "no certificate pair is being watched, so there is "
                          "nothing to reload");
    return cert_swap_from(cert_path, key_path);
}

bool https_server_certificate_refresh(void)
{
    char cert_path[sizeof(g_watch_cert)];
    char key_path[sizeof(g_watch_key)];
    struct cert_file_id seen_cert;
    struct cert_file_id seen_key;

    pthread_mutex_lock(&g_cert_mutex);
    const bool serving = g_ssl_ctx != NULL && g_watch_cert[0] && g_watch_key[0];
    snprintf(cert_path, sizeof(cert_path), "%s", g_watch_cert);
    snprintf(key_path, sizeof(key_path), "%s", g_watch_key);
    seen_cert = g_seen_cert;
    seen_key = g_seen_key;
    pthread_mutex_unlock(&g_cert_mutex);
    if (!serving)
        return false;

    /* Every additional name is renewed on the same trigger and by the same
     * discipline as the default pair. Done FIRST and unconditionally, so a
     * default pair that never changes cannot starve a name whose certificate
     * did. With no additional names configured this is a single load of a
     * zeroed counter and returns immediately. */
    const bool sni_swapped = sni_certificates_refresh();

    struct cert_file_id cert_id;
    struct cert_file_id key_id;
    (void)cert_file_id_read(cert_path, &cert_id);
    (void)cert_file_id_read(key_path, &key_id);
    /* Not there yet is the normal state of a node waiting for its first
     * certificate. Not an error, and not worth a line. */
    if (!cert_id.present || !key_id.present)
        return sni_swapped;
    if (cert_file_id_same(&cert_id, &seen_cert) &&
        cert_file_id_same(&key_id, &seen_key))
        return sni_swapped;

    /* Claim the observation before doing the work. Two worker threads racing
     * here means exactly one builds a context; and a pair that fails to load
     * is not looked at again until the files themselves change, so a broken
     * certificate cannot turn every connection into a log line. */
    pthread_mutex_lock(&g_cert_mutex);
    const bool claimed = !cert_file_id_same(&g_seen_cert, &cert_id) ||
                         !cert_file_id_same(&g_seen_key, &key_id);
    if (claimed) {
        g_seen_cert = cert_id;
        g_seen_key = key_id;
    }
    pthread_mutex_unlock(&g_cert_mutex);
    if (!claimed)
        return sni_swapped;

    return cert_swap_from(cert_path, key_path) || sni_swapped;
}

bool https_server_certificate_is_self_signed(void)
{
    return atomic_load(&g_cert_self_signed);
}

/* Put the context https_server_start_on_port() just built into service and
 * record the watched pair. Called once per start, under the start lock and
 * before any listener thread exists. */
void https_ssl_ctx_start_serving(SSL_CTX *ctx, const char *cert_path,
                                 const char *key_path)
{
    /* The watched pair defaults to the one the caller handed us, but a watch
     * set BEFORE start wins: that is how boot serves a self-signed
     * placeholder while watching for the CA-issued pair to appear. */
    pthread_mutex_lock(&g_cert_mutex);
    if (!g_watch_cert[0] || !g_watch_key[0]) {
        snprintf(g_watch_cert, sizeof(g_watch_cert), "%s", cert_path);
        snprintf(g_watch_key, sizeof(g_watch_key), "%s", key_path);
    }
    char watch_cert[sizeof(g_watch_cert)];
    char watch_key[sizeof(g_watch_key)];
    snprintf(watch_cert, sizeof(watch_cert), "%s", g_watch_cert);
    snprintf(watch_key, sizeof(watch_key), "%s", g_watch_key);
    pthread_mutex_unlock(&g_cert_mutex);

    /* Record the watched pair as it is RIGHT NOW, before any connection can
     * arrive. When it is the pair just loaded, nothing looks changed and no
     * connection rebuilds anything. When it is absent -- the placeholder
     * case -- absent is the recorded observation, so the pair APPEARING is
     * the change that triggers the swap. */
    struct cert_file_id watch_cert_id;
    struct cert_file_id watch_key_id;
    (void)cert_file_id_read(watch_cert, &watch_cert_id);
    (void)cert_file_id_read(watch_key, &watch_key_id);
    ssl_ctx_install(ctx, &watch_cert_id, &watch_key_id);
    announce_certificate(cert_path, https_server_certificate_is_self_signed(),
                         true);
}
