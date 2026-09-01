/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Public HTTPS server — serves the block explorer.
 * Uses OpenSSL for TLS. HTTP port redirects to HTTPS.
 * Bounded worker pool prevents unbounded detached thread growth.
 *
 * Listens on high ports (8443/8080) to avoid needing root or setcap on the node.
 * For public 443/80 access, a tiny capped userspace forwarder maps the ports
 * (the node stays unprivileged). See tools/zcl_portfwd.c,
 * platform/deploy/systemd/zcl-portfwd.service, and docs/BLOCK_EXPLORER_HOSTING.md. */

#if !defined(_WIN32)
#define _XOPEN_SOURCE 700
#endif
#include "net/acme_challenge.h"
#include "net/acme_selfsigned.h"
#include "net/https_frontdoor.h"
#include "net/https_server.h"
#include "https_server_internal.h"
#include "net/site_routes.h"
#include "platform/socket_compat.h"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/time.h>
#include "util/log_macros.h"
#include "util/safe_alloc.h"
#include "util/thread_registry.h"
#include "util/thread_liveness.h"
#include "util/write_all.h"
#include "metrics/prometheus_metrics.h"

/* The TLS context in service. Guarded by g_cert_mutex (below): it can be
 * replaced under live traffic when a renewed certificate lands on disk. */
static SSL_CTX *g_ssl_ctx = NULL;
static platform_socket_t g_https_fd = PLATFORM_SOCKET_INVALID;
static platform_socket_t g_http_fd = PLATFORM_SOCKET_INVALID;
static pthread_t g_https_thread;
static pthread_t g_http_thread;
static pthread_t g_worker_threads[16];
static unsigned g_worker_threads_started = 0;
static bool g_https_thread_started = false;
static bool g_http_thread_started = false;
static _Atomic bool g_running = false;
static _Atomic int g_https_port = 0;
static char g_hostname[256] = "";
static pthread_mutex_t g_https_state_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_client_queue_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_client_queue_cv = PTHREAD_COND_INITIALIZER;

/* Supervisor liveness for the 3 HTTPS/HTTP threads. Root children (not
 * supervisor_register_in_domain(...)): core/modules/net cannot include the app-side
 * supervisors/domains.h without a lib-layering violation — see
 * util/thread_liveness.h. All three legitimately idle (accept() blocks with
 * no deterministic timeout; the worker pool blocks on a queue condvar), so
 * they are liveness-only (no deadline, no progress gate) — present on the
 * tree, heartbeat when they do work, never falsely flagged for a quiet
 * cycle. g_worker_threads spawns N workers under one name ("zcl_https_wkr");
 * they share ONE contract — any worker's heartbeat proves at least one
 * worker loop is alive, the simplest honest claim for a pool. */
static struct thread_liveness_child g_https_wkr_liveness    = { .id = SUPERVISOR_INVALID_ID };
static struct thread_liveness_child g_https_listen_liveness = { .id = SUPERVISOR_INVALID_ID };
static struct thread_liveness_child g_http_listen_liveness  = { .id = SUPERVISOR_INVALID_ID };

/* Connection limit — prevents OOM under heavy load.
 * Each connection mallocs HTTPS_RESPONSE_BUFFER_SIZE for response data. */
#define MAX_HTTPS_CONNECTIONS 64
#define HTTPS_RESPONSE_BUFFER_SIZE (1024 * 1024)
static _Atomic int g_active_connections = 0;
static struct https_frontdoor_queue g_client_queue;

static bool client_queue_push(const struct https_frontdoor_client *client)
{
    pthread_mutex_lock(&g_client_queue_mutex);
    bool ok = https_frontdoor_queue_push(&g_client_queue, client);
    pthread_cond_signal(&g_client_queue_cv);
    pthread_mutex_unlock(&g_client_queue_mutex);
    return ok;
}

static bool client_queue_pop(struct https_frontdoor_client *client)
{
    pthread_mutex_lock(&g_client_queue_mutex);
    while (g_client_queue.len == 0 && atomic_load(&g_running))
        pthread_cond_wait(&g_client_queue_cv, &g_client_queue_mutex);
    bool ok = https_frontdoor_queue_pop(&g_client_queue, client);
    pthread_mutex_unlock(&g_client_queue_mutex);
    return ok;
}

static void client_queue_close_all(void)
{
    pthread_mutex_lock(&g_client_queue_mutex);
    https_frontdoor_queue_close_all(&g_client_queue);
    pthread_mutex_unlock(&g_client_queue_mutex);
}

/* Written once by https_server_start_on_port() before any listener thread
 * exists, then read-only for the process lifetime — no lock needed. */
const char *https_server_configured_hostname(void)
{
    return g_hostname;
}


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
 * SSL_CTX built by the same ssl_ctx_build() as the default. The default
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
 * ssl_ctx_retire_all(). Slot indices are therefore stable, which is what
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
 * itself: every context, default and per-name, is built by ssl_ctx_build()
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
static SSL_CTX *ssl_ctx_build(const char *cert_path, const char *key_path)
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
static SSL_CTX *ssl_ctx_acquire(void)
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
 * exactly once (ssl_ctx_acquire) before its handshake, so a connection sees
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

static void ssl_ctx_retire_all(void)
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

    SSL_CTX *ctx = ssl_ctx_build(cert_path, key_path);
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

        pthread_mutex_lock(&g_cert_mutex);
        const bool claimed = i < g_sni_count &&
                             sni_name_equal(g_sni[i].name, name) &&
                             (!cert_file_id_same(&g_sni[i].seen_cert, &cert_id) ||
                              !cert_file_id_same(&g_sni[i].seen_key, &key_id));
        if (claimed) {
            g_sni[i].seen_cert = cert_id;
            g_sni[i].seen_key = key_id;
        }
        pthread_mutex_unlock(&g_cert_mutex);
        if (!claimed)
            continue;

        SSL_CTX *ctx = ssl_ctx_build(cert_path, key_path);
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

/* ── HTTP helpers ─────────────────────────────────────────── */

/* SSL_write may not accept the whole buffer at once — write in chunks. */
static void https_write_all(SSL *ssl, const unsigned char *buf, size_t n)
{
    size_t written = 0;
    while (written < n) {
        size_t chunk = n - written;
        if (chunk > 16384) chunk = 16384;
        int w = SSL_write(ssl, buf + written, (int)chunk);
        if (w <= 0) break;
        written += (size_t)w;
    }
}

/* App-mount handler prototypes — expanded from net/site_routes.def, the
 * single registry (core/modules/net never includes app/ headers). The same def
 * also generates the dispatch below, the onion twin in onion_service.c,
 * and the ratelimit classification in onion_ratelimit.c. */
#define SITE_ROUTE(id, prefix, handler, flavor, methods, cost, rkey, \
                   nav_app, nav_onion, grid, nav_label, nav_href, nav_id, \
                   grid_desc, fail_body, app_id) \
    ZCL_SITE_EXTERN_##flavor(handler)
#include "net/site_routes.def"
#undef SITE_ROUTE

/* ── HTTPS handler ────────────────────────────────────────── */

static void handle_https_client(SSL *ssl, platform_socket_t fd,
                                int64_t deadline_ms)
{
    struct https_frontdoor_ssl_reader reader = {
        .ssl = ssl, .fd = fd, .deadline_ms = deadline_ms,
    };
    char line[4096];
    if (!https_frontdoor_read_line(&reader, https_frontdoor_ssl_read_byte,
                                   line, sizeof(line), deadline_ms))
        return;

    char method[16] = "", path[2048] = "";
    if (sscanf(line, "%15s %2047s", method, path) != 2)
        return;

    /* Read remaining headers (discard). Cap the count so a peer streaming
     * endless headers cannot pin this thread. */
    int hdr_count = 0;
    bool headers_complete = false;
    while (https_frontdoor_read_line(&reader,
                                     https_frontdoor_ssl_read_byte,
                                     line, sizeof(line), deadline_ms)) {
        if (line[0] == '\0') {
            headers_complete = true;
            break;
        }
        if (++hdr_count > HTTP_MAX_REQUEST_HEADERS) return;
    }
    if (!headers_complete)
        return;
    if (!platform_socket_set_nonblocking(fd, false))
        return;

    /* Only serve GET requests to explorer routes */
    if (strcmp(method, "GET") != 0 && strcmp(method, "HEAD") != 0) {
        const char *resp =
            "HTTP/1.1 405 Method Not Allowed\r\n"
            "Content-Type: text/plain\r\n"
            "Connection: close\r\n\r\n"
            "Only GET is supported.\n";
        SSL_write(ssl, resp, (int)strlen(resp));
        return;
    }

    /* Redirect root to explorer */
    if (strcmp(path, "/") == 0) {
        const char *resp =
            "HTTP/1.1 302 Found\r\n"
            "Location: /explorer\r\n"
            "Connection: close\r\n\r\n";
        SSL_write(ssl, resp, (int)strlen(resp));
        return;
    }

    /* Prometheus /metrics endpoint on HTTPS */
    if (strcmp(path, "/metrics") == 0) {
        size_t cap = 131072;
        char *mbuf = zcl_malloc(cap, "https_metrics_buf");
        if (!mbuf) return;
        size_t n = metrics_prometheus_render_prometheus(mbuf, cap);
        char hdr[256];
        int hlen = snprintf(hdr, sizeof(hdr),
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/plain; version=0.0.4; charset=utf-8\r\n"
            "Connection: close\r\n"
            "Content-Length: %zu\r\n\r\n", n);
        SSL_write(ssl, hdr, hlen);
        size_t written = 0;
        while (written < n) {
            size_t chunk = n - written;
            if (chunk > 16384) chunk = 16384;
            int w = SSL_write(ssl, mbuf + written, (int)chunk);
            if (w <= 0) break;
            written += (size_t)w;
        }
        free(mbuf);
        return;
    }

    /* Operator-private API gate — this clearnet 0.0.0.0 listener is
     * untrusted ingress, and the API router cannot authenticate (it
     * never sees headers or peer identity — see api_handle_request),
     * so the gate lives here. The onion service exposes no /api;
     * wallet_gui calls explorer_handle_request in-process and is
     * unaffected. Deliberately no Access-Control-Allow-Origin
     * header on the refusal. */
    if (strncmp(path, "/api", 4) == 0) {
        extern bool api_route_is_operator_private(const char *path);
        if (api_route_is_operator_private(path)) {
            const char *resp =
                "HTTP/1.1 403 Forbidden\r\n"
                "Content-Type: engine/application/json\r\n"
                "Connection: close\r\n\r\n"
                "{\"error\":\"operator-private endpoint: "
                "not served on the public listener\"}";
            SSL_write(ssl, resp, (int)strlen(resp));
            return;
        }
    }

    /* App MVC mounts — expanded from net/site_routes.def in registry
     * order. This listener is GET/HEAD-only (checked above), so every
     * row's POST surface (the store's order mints, the names register,
     * the yardsale ceremony) stays onion-only; the store and market_chunk
     * mounts are onion-only and expand to nothing here. PLAIN rows prefix-match
     * with no boundary guard; DATADIR and FAILCLOSED rows keep their
     * path[N] ∈ {NUL, '/', '?'} guard; DATADIR passes NULL for the
     * datadir (the handler resolves GetDataDir(true) itself — this
     * listener carries no datadir context); FAILCLOSED turns a handler 0
     * into a 503 carrying the row's fail_body. */
#define ZCL_HTTPS_DISPATCH_STORE(id, prefix, handler, fail_body) \
    /* onion-only mount — this listener never serves it */
#define ZCL_HTTPS_DISPATCH_ONIONCLOSED(id, prefix, handler, fail_body) \
    /* onion-only mount — this listener never serves it */
#define ZCL_HTTPS_DISPATCH_PLAIN(id, prefix, handler, fail_body) \
    if (strncmp(path, prefix, sizeof(prefix) - 1) == 0) { \
        unsigned char *buf = zcl_malloc(HTTPS_RESPONSE_BUFFER_SIZE, \
                                        "https_" #id "_buf"); \
        if (!buf) return; \
        size_t site_n_ = handler(method, path, NULL, 0, buf, \
                                 HTTPS_RESPONSE_BUFFER_SIZE); \
        if (site_n_ > 0) \
            https_write_all(ssl, buf, site_n_); \
        free(buf); \
        return; \
    }
#define ZCL_HTTPS_DISPATCH_DATADIR(id, prefix, handler, fail_body) \
    if (strncmp(path, prefix, sizeof(prefix) - 1) == 0 && \
        (path[sizeof(prefix) - 1] == 0 || path[sizeof(prefix) - 1] == '/' || \
         path[sizeof(prefix) - 1] == '?')) { \
        unsigned char *buf = zcl_malloc(HTTPS_RESPONSE_BUFFER_SIZE, \
                                        "https_" #id "_buf"); \
        if (!buf) return; \
        size_t site_n_ = handler(method, path, NULL, 0, buf, \
                                 HTTPS_RESPONSE_BUFFER_SIZE, NULL); \
        if (site_n_ > 0) \
            https_write_all(ssl, buf, site_n_); \
        free(buf); \
        return; \
    }
#define ZCL_HTTPS_DISPATCH_FAILCLOSED(id, prefix, handler, fail_body) \
    if (strncmp(path, prefix, sizeof(prefix) - 1) == 0 && \
        (path[sizeof(prefix) - 1] == 0 || path[sizeof(prefix) - 1] == '/' || \
         path[sizeof(prefix) - 1] == '?')) { \
        unsigned char *buf = zcl_malloc(HTTPS_RESPONSE_BUFFER_SIZE, \
                                        "https_" #id "_buf"); \
        if (!buf) return; \
        size_t site_n_ = handler(method, path, NULL, 0, buf, \
                                 HTTPS_RESPONSE_BUFFER_SIZE); \
        if (site_n_ > 0) { \
            https_write_all(ssl, buf, site_n_); \
        } else { \
            const char *resp = \
                "HTTP/1.1 503 Service Unavailable\r\n" \
                "Content-Type: text/plain\r\n" \
                "Connection: close\r\n\r\n" fail_body; \
            SSL_write(ssl, resp, (int)strlen(resp)); \
        } \
        free(buf); \
        return; \
    }
#define SITE_ROUTE(id, prefix, handler, flavor, methods, cost, rkey, \
                   nav_app, nav_onion, grid, nav_label, nav_href, nav_id, \
                   grid_desc, fail_body, app_id) \
    ZCL_HTTPS_DISPATCH_##flavor(id, prefix, handler, fail_body)
#include "net/site_routes.def"
#undef SITE_ROUTE
#undef ZCL_HTTPS_DISPATCH_FAILCLOSED
#undef ZCL_HTTPS_DISPATCH_ONIONCLOSED
#undef ZCL_HTTPS_DISPATCH_DATADIR
#undef ZCL_HTTPS_DISPATCH_PLAIN
#undef ZCL_HTTPS_DISPATCH_STORE

    extern const char *explorer_canonical_shortcut(const char *path);

    /* Explorer + API routes — call the explorer handler (which delegates /api/) */
    if (strncmp(path, "/explorer", 9) == 0 ||
        strncmp(path, "/api", 4) == 0 ||
        explorer_canonical_shortcut(path) != NULL) {
        extern size_t explorer_handle_request(const char *, const char *,
            const unsigned char *, size_t, unsigned char *, size_t);

        unsigned char *buf = zcl_malloc(HTTPS_RESPONSE_BUFFER_SIZE,
                                        "https_resp_buf");
        if (!buf) return;

        size_t n = explorer_handle_request(method, path, NULL, 0, buf,
                                           HTTPS_RESPONSE_BUFFER_SIZE);
        if (n > 0) {
            /* Write in chunks — SSL_write may not accept large buffers at once */
            size_t written = 0;
            while (written < n) {
                size_t chunk = n - written;
                if (chunk > 16384) chunk = 16384;
                int w = SSL_write(ssl, buf + written, (int)chunk);
                if (w <= 0) break;
                written += (size_t)w;
            }
        } else {
            const char *resp =
                "HTTP/1.1 404 Not Found\r\n"
                "Content-Type: text/plain\r\n"
                "Connection: close\r\n\r\n"
                "Not found.\n";
            SSL_write(ssl, resp, (int)strlen(resp));
        }
        free(buf);
        return;
    }

    /* Anything else → 404 */
    const char *resp =
        "HTTP/1.1 302 Found\r\n"
        "Location: /explorer\r\n"
        "Connection: close\r\n\r\n";
    SSL_write(ssl, resp, (int)strlen(resp));
}

static void handle_https_client_fd(platform_socket_t fd, int64_t deadline_ms)
{
    atomic_fetch_add(&g_active_connections, 1);

    if (!platform_socket_set_nonblocking(fd, true)) {
        platform_socket_close(fd);
        atomic_fetch_sub(&g_active_connections, 1);
        return;
    }
    /* Adopt a renewed certificate before this connection is handshaked, not
     * after. Cheap: one stat() of each watched file unless something actually
     * changed, and the connection that would otherwise have been served a
     * superseded certificate is the one that triggers the swap. */
    (void)https_server_certificate_refresh();

    /* One read of the context pointer, with a reference taken, so a swap
     * running concurrently cannot free the context out from under this
     * handshake. SSL_new() takes its own reference; ours is released as soon
     * as it has. */
    SSL_CTX *ctx = ssl_ctx_acquire();
    if (!ctx) {
        platform_socket_close(fd);
        atomic_fetch_sub(&g_active_connections, 1);
        return;
    }
    SSL *ssl = SSL_new(ctx);
    SSL_CTX_free(ctx);
    if (!ssl) {
        platform_socket_close(fd);
        atomic_fetch_sub(&g_active_connections, 1);
        return;
    }

    /* The condition is computed into a variable rather than split across the
     * #if arms of a single `if (`. Both spellings compile, but the split form
     * opens a brace in each arm and closes it in neither, so any tool that
     * counts braces without evaluating the preprocessor double-counts and
     * loses track of which function it is in for the rest of the file --
     * which is exactly how check-log-macro-return-type came to report five
     * correct LOG_FAIL uses as errors. */
#if defined(_WIN32)
    /* Winsock's SOCKET is handle-sized; SSL_set_fd takes an int, so refuse a
     * descriptor that cannot round-trip instead of truncating it. */
    const bool fd_bound = (uintptr_t)fd <= INT_MAX &&
                          SSL_set_fd(ssl, (int)(uintptr_t)fd) == 1;
#else
    const bool fd_bound = SSL_set_fd(ssl, fd) == 1;
#endif
    if (!fd_bound) {
        SSL_free(ssl);
        platform_socket_close(fd);
        atomic_fetch_sub(&g_active_connections, 1);
        return;
    }

    if (!https_frontdoor_ssl_accept(ssl, fd, deadline_ms)) {
        SSL_free(ssl);
        platform_socket_close(fd);
        atomic_fetch_sub(&g_active_connections, 1);
        return;
    }

    handle_https_client(ssl, fd, deadline_ms);

    SSL_shutdown(ssl);
    SSL_free(ssl);
    platform_socket_close(fd);
    atomic_fetch_sub(&g_active_connections, 1);
}

static void *https_listen_fn(void *arg)
{
    (void)arg;
    while (g_running) {
        struct sockaddr_in client_addr;
        size_t addr_len = sizeof(client_addr);
        platform_socket_t client_fd = platform_socket_accept(
            g_https_fd, (struct sockaddr *)&client_addr, &addr_len);
        thread_liveness_beat(&g_https_listen_liveness, -1);
        if (client_fd == PLATFORM_SOCKET_INVALID) {
            continue;
        }

        /* Reject if too many concurrent connections (prevents OOM) */
        if (atomic_load(&g_active_connections) >= MAX_HTTPS_CONNECTIONS) {
            const char *busy = "HTTP/1.1 503 Service Unavailable\r\n"
                "Retry-After: 5\r\nConnection: close\r\n\r\n";
            /* Best-effort courtesy status: this connection is being closed
             * either way, and the alternative to a partial 503 is a bare RST,
             * which the client already handles. Not worth logging — an
             * attacker driving us to the connection cap would then also
             * control our log volume. */
            (void)platform_socket_send_all(client_fd, busy, strlen(busy));
            platform_socket_close(client_fd);
            continue;
        }

        /* Slowloris protection: 15s timeout for HTTPS requests.
         * Heavy pages (HODL, stats) are pre-cached so serve instantly. */
        (void)platform_socket_set_receive_timeout(client_fd, 15000);
        (void)platform_socket_set_send_timeout(client_fd, 15000);

        int64_t deadline_ms = 0;
        if (!https_frontdoor_deadline_start(&deadline_ms)) {
            platform_socket_close(client_fd);
            continue;
        }
        struct https_frontdoor_client ca = {
            .fd = client_fd,
            .tls = true,
            .deadline_ms = deadline_ms,
        };
        if (!client_queue_push(&ca)) {
            const char *busy = "HTTP/1.1 503 Service Unavailable\r\n"
                "Retry-After: 5\r\nConnection: close\r\n\r\n";
            /* Best-effort: see the connection-cap branch above. */
            (void)platform_socket_send_all(client_fd, busy, strlen(busy));
            platform_socket_close(client_fd);
        }
    }
    return NULL;
}

/* ── HTTP listener (port 80) ──────────────────────────────── */
/* The requests this accepts are served by https_server_redirect.c. */

static void *http_listen_fn(void *arg)
{
    (void)arg;
    while (g_running) {
        struct sockaddr_in client_addr;
        size_t addr_len = sizeof(client_addr);
        platform_socket_t client_fd = platform_socket_accept(
            g_http_fd, (struct sockaddr *)&client_addr, &addr_len);
        thread_liveness_beat(&g_http_listen_liveness, -1);
        if (client_fd == PLATFORM_SOCKET_INVALID) {
            continue;
        }

        (void)platform_socket_set_receive_timeout(client_fd, 5000);

        int64_t deadline_ms = 0;
        if (!https_frontdoor_deadline_start(&deadline_ms)) {
            platform_socket_close(client_fd);
            continue;
        }
        struct https_frontdoor_client ca = {
            .fd = client_fd,
            .tls = false,
            .deadline_ms = deadline_ms,
        };
        if (!client_queue_push(&ca)) {
            const char *busy = "HTTP/1.1 503 Service Unavailable\r\n"
                "Retry-After: 5\r\nConnection: close\r\n\r\n";
            /* Best-effort: see https_listen_fn(). */
            (void)platform_socket_send_all(client_fd, busy, strlen(busy));
            platform_socket_close(client_fd);
        }
    }
    return NULL;
}

static void *https_worker_fn(void *arg)
{
    (void)arg;

    while (atomic_load(&g_running)) {
        struct https_frontdoor_client ca;

        if (!client_queue_pop(&ca))
            break;
        thread_liveness_beat(&g_https_wkr_liveness, -1);
        if (ca.fd == PLATFORM_SOCKET_INVALID)
            continue;
        if (!https_frontdoor_deadline_active(ca.deadline_ms)) {
            platform_socket_close(ca.fd);
            continue;
        }
        if (ca.tls)
            handle_https_client_fd(ca.fd, ca.deadline_ms);
        else
            https_server_handle_http_client_fd(ca.fd, ca.deadline_ms);
    }

    return NULL;
}

/* ── Bind helper ──────────────────────────────────────────── */

static platform_socket_t bind_port(uint16_t port, bool any_addr)
{
    platform_socket_t fd = platform_socket_open(AF_INET, SOCK_STREAM, 0,
                                                true, false);
    if (fd == PLATFORM_SOCKET_INVALID)
        LOG_ERR("https", "socket() failed");

    (void)platform_socket_set_reuse_address(fd, true);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = any_addr ? htonl(INADDR_ANY) : htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(port);

    if (platform_socket_bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        platform_socket_close(fd);
        LOG_ERR("https", "bind port %u failed", port);
    }
    if (platform_socket_listen(fd, 32) != 0) {
        platform_socket_close(fd);
        LOG_ERR("https", "listen on port %u failed", port);
    }
    return fd;
}

/* ── Public API ───────────────────────────────────────────── */

bool https_server_start_on_port(const char *cert_path, const char *key_path,
                                const char *hostname, int https_port, int http_port)
{
    unsigned started_workers = 0;

#if !defined(_WIN32)
    signal(SIGPIPE, SIG_IGN);
#endif

    pthread_mutex_lock(&g_https_state_mutex);
    if (atomic_load(&g_running) || g_https_thread_started) {
        pthread_mutex_unlock(&g_https_state_mutex);
        return true;
    }

    if (hostname)
        snprintf(g_hostname, sizeof(g_hostname), "%s", hostname);

    /* Init OpenSSL */
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    /* Built into a local, not into the global: nothing is in service until
     * the ports are bound, and a start that fails leaves no half-configured
     * context behind. ssl_ctx_build() is the same call the reload path makes. */
    SSL_CTX *ctx = ssl_ctx_build(cert_path, key_path);
    if (!ctx) {
        pthread_mutex_unlock(&g_https_state_mutex);
        LOG_ERROR("https", "the front door has no usable certificate pair at "
                           "cert=%s key=%s and will not listen", cert_path,
                  key_path);
        return false;
    }

    /* Bind HTTPS port (iptables redirects 443→default 8443) */
    g_https_fd = bind_port(https_port, true);
    if (g_https_fd == PLATFORM_SOCKET_INVALID) {
        SSL_CTX_free(ctx);
        pthread_mutex_unlock(&g_https_state_mutex);
        LOG_ERROR("https", "cannot bind HTTPS port %d", https_port);
        return false;
    }

    /* Bind HTTP port for redirect */
    g_http_fd = bind_port(http_port, true);
    if (g_http_fd == PLATFORM_SOCKET_INVALID) {
        fprintf(stderr, "HTTPS: cannot bind port %d, HTTP redirect won't work\n",  // obs-ok:bind-failure-non-fatal
                http_port);
        /* Non-fatal — continue with HTTPS only */
    }

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

    atomic_store(&g_running, true);
    atomic_store(&g_https_port, https_port);
    g_client_queue = (struct https_frontdoor_queue){0};
    atomic_store(&g_active_connections, 0);

    for (unsigned i = 0; i < (sizeof(g_worker_threads) / sizeof(g_worker_threads[0])); i++) {
        if (thread_registry_spawn("zcl_https_wkr", https_worker_fn,
                                      NULL, &g_worker_threads[i]) != 0) {
            fprintf(stderr, "HTTPS: worker thread failed\n");  // obs-ok:thread-spawn-fallback-logged
            break;
        }
        started_workers++;
        if (i == 0)
            thread_liveness_register(&g_https_wkr_liveness, "zcl_https_wkr", 0, 0);
    }
    g_worker_threads_started = started_workers;
    if (g_worker_threads_started == 0) {
        atomic_store(&g_running, false);
        platform_socket_close(g_https_fd);
        g_https_fd = PLATFORM_SOCKET_INVALID;
        if (g_http_fd != PLATFORM_SOCKET_INVALID) {
            platform_socket_close(g_http_fd);
            g_http_fd = PLATFORM_SOCKET_INVALID;
        }
        ssl_ctx_retire_all();
        pthread_mutex_unlock(&g_https_state_mutex);
        LOG_ERROR("https", "no worker threads could be started");
        return false;
    }

    if (thread_registry_spawn("zcl_https_listen", https_listen_fn, NULL,
                                  &g_https_thread) != 0) {
        platform_socket_close(g_https_fd);
        g_https_fd = PLATFORM_SOCKET_INVALID;
        atomic_store(&g_running, false);
        pthread_cond_broadcast(&g_client_queue_cv);
        pthread_mutex_unlock(&g_https_state_mutex);
        for (unsigned i = 0; i < g_worker_threads_started; i++)
            pthread_join(g_worker_threads[i], NULL);
        g_worker_threads_started = 0;
        ssl_ctx_retire_all();
        LOG_ERROR("https", "thread_registry_spawn failed for HTTPS listen thread");
        return false;
    }
    g_https_thread_started = true;
    thread_liveness_register(&g_https_listen_liveness, "zcl_https_listen", 0, 0);

    if (g_http_fd != PLATFORM_SOCKET_INVALID) {
        if (thread_registry_spawn("zcl_http_listen", http_listen_fn, NULL,
                                      &g_http_thread) != 0) {
            fprintf(stderr, "HTTPS: HTTP redirect thread failed\n");  // obs-ok:thread-spawn-fallback-logged
            platform_socket_close(g_http_fd);
            g_http_fd = PLATFORM_SOCKET_INVALID;
        } else {
            g_http_thread_started = true;
            thread_liveness_register(&g_http_listen_liveness, "zcl_http_listen", 0, 0);
        }
    }
    pthread_mutex_unlock(&g_https_state_mutex);

    printf("HTTPS server listening on 0.0.0.0:%d (TLS)\n", https_port);
    if (g_http_fd != PLATFORM_SOCKET_INVALID)
        printf("HTTP redirect on 0.0.0.0:%d -> https://%s\n", http_port, g_hostname);

    return true;
}

bool https_server_start(const char *cert_path, const char *key_path,
                         const char *hostname)
{
    return https_server_start_on_port(cert_path, key_path, hostname, 8443, 8080);
}

void https_server_stop(void)
{
    pthread_t https_thread;
    pthread_t http_thread;
    pthread_t worker_threads[sizeof(g_worker_threads) / sizeof(g_worker_threads[0])];
    unsigned worker_threads_started = 0;
    bool have_https_thread = false;
    bool have_http_thread = false;
    platform_socket_t https_fd = PLATFORM_SOCKET_INVALID;
    platform_socket_t http_fd = PLATFORM_SOCKET_INVALID;

    pthread_mutex_lock(&g_https_state_mutex);
    if (!atomic_load(&g_running) && !g_https_thread_started &&
        !g_http_thread_started && g_worker_threads_started == 0) {
        pthread_mutex_unlock(&g_https_state_mutex);
        return;
    }
    atomic_store(&g_running, false);
    atomic_store(&g_https_port, 0);
    https_fd = g_https_fd;
    http_fd = g_http_fd;
    g_https_fd = PLATFORM_SOCKET_INVALID;
    g_http_fd = PLATFORM_SOCKET_INVALID;
    if (g_https_thread_started) {
        https_thread = g_https_thread;
        g_https_thread_started = false;
        have_https_thread = true;
    }
    if (g_http_thread_started) {
        http_thread = g_http_thread;
        g_http_thread_started = false;
        have_http_thread = true;
    }
    worker_threads_started = g_worker_threads_started;
    for (unsigned i = 0; i < worker_threads_started; i++)
        worker_threads[i] = g_worker_threads[i];
    g_worker_threads_started = 0;
    pthread_mutex_unlock(&g_https_state_mutex);

    if (https_fd != PLATFORM_SOCKET_INVALID) {
        platform_socket_shutdown_both(https_fd);
        platform_socket_close(https_fd);
    }
    if (http_fd != PLATFORM_SOCKET_INVALID) {
        platform_socket_shutdown_both(http_fd);
        platform_socket_close(http_fd);
    }
    pthread_cond_broadcast(&g_client_queue_cv);
    client_queue_close_all();

    if (have_https_thread) {
        pthread_join(https_thread, NULL);
        thread_liveness_retire(&g_https_listen_liveness);
    }
    if (have_http_thread) {
        pthread_join(http_thread, NULL);
        thread_liveness_retire(&g_http_listen_liveness);
    }
    for (unsigned i = 0; i < worker_threads_started; i++)
        pthread_join(worker_threads[i], NULL);
    if (worker_threads_started > 0)
        thread_liveness_retire(&g_https_wkr_liveness);
    ssl_ctx_retire_all();
    printf("HTTPS server stopped.\n");
}

/* ── Deferred HTTPS start (after IBD completes) ──────────── */

bool https_server_is_running(void)
{
    return atomic_load(&g_running);
}

int https_server_port(void)
{
    return atomic_load(&g_https_port);
}
