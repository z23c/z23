/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * A renewed certificate reaching a RUNNING front door, graded from the
 * outside — over real TLS, by a real client, against the real listener.
 *
 * WHY A REAL CLIENT AND NOT A UNIT CALL. The claim being tested is "the swap
 * is atomic from a client's point of view", and only a client can say that.
 * The proof rests on a property of TLS itself: a server signs the handshake
 * with the private key belonging to the certificate it presented, and the
 * client verifies that signature against the certificate's public key. So a
 * context that ever served certificate A with key B does not produce a
 * mismatched page — it produces a FAILED HANDSHAKE. "Every one of N
 * concurrent handshakes succeeded while the certificate was being swapped
 * underneath them" is therefore exactly the statement "no client was ever
 * served a half-swapped context", not a proxy for it.
 *
 * The TLS-client symbols this file links are why lib/test objects are
 * excluded from test_cold_join_sovereign P2's scan: the node itself must
 * never carry them, and it does not — the swap in core/modules/net/src/https_server.c
 * is server-side only. This test is not shipped.
 *
 * The certificates here are self-signed on purpose and the client verifies
 * nothing: what is under test is WHICH certificate arrives and whether the
 * handshake completes, not whether anybody vouched for it.
 */

#include "test/test_core.h"

#include "net/acme_selfsigned.h"
#include "net/https_server.h"

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include "platform/socket_compat.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define CR_CHECK(name, expr) do {                          \
    printf("acme_cert_reload: %s... ", (name));            \
    if (expr) { printf("OK\n"); }                          \
    else { printf("FAIL\n"); failures++; }                 \
} while (0)

#define ALPHA "alpha.example"
#define BRAVO "bravo.example"

static _Atomic int g_port = 0;

static uint16_t free_port(void)
{
    platform_socket_t fd = platform_socket_open(AF_INET, SOCK_STREAM, 0,
                                                true, false);
    if (fd == PLATFORM_SOCKET_INVALID)
        return 0;
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(0);
    uint16_t port = 0;
    if (platform_socket_bind(fd, (struct sockaddr *)&addr,
                             sizeof(addr)) == 0) {
        size_t len = sizeof(addr);
        if (platform_socket_local_address(fd, (struct sockaddr *)&addr,
                                          &len) == 0)
            port = ntohs(addr.sin_port);
    }
    platform_socket_close(fd);
    return port;
}

/* One TLS connection, left open. The caller closes it. */
struct conn {
    platform_socket_t fd;
    SSL_CTX *ctx;
    SSL *ssl;
    char cn[256];
};

static void conn_close(struct conn *c)
{
    if (c->ssl) {
        SSL_shutdown(c->ssl);
        SSL_free(c->ssl);
    }
    if (c->ctx)
        SSL_CTX_free(c->ctx);
    if (c->fd != PLATFORM_SOCKET_INVALID)
        platform_socket_close(c->fd);
    c->ssl = NULL;
    c->ctx = NULL;
    c->fd = PLATFORM_SOCKET_INVALID;
}

/* Connect, handshake, record the leaf's subject CN. Returns false when the
 * handshake did not complete — which is what a mismatched certificate and
 * key looks like from out here. */
static bool conn_open(struct conn *c)
{
    memset(c, 0, sizeof(*c));
    c->fd = PLATFORM_SOCKET_INVALID;

    const int port = atomic_load(&g_port);
    if (port <= 0)
        return false;

    c->fd = platform_socket_open(AF_INET, SOCK_STREAM, 0, true, false);
    if (c->fd == PLATFORM_SOCKET_INVALID)
        return false;
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons((uint16_t)port);
    if (platform_socket_connect(c->fd, (struct sockaddr *)&addr,
                                sizeof(addr)) != 0) {
        conn_close(c);
        return false;
    }

    c->ctx = SSL_CTX_new(TLS_client_method());
    c->ssl = c->ctx ? SSL_new(c->ctx) : NULL;
    if (!c->ssl || SSL_set_fd(c->ssl, (int)(intptr_t)c->fd) != 1) {
        conn_close(c);
        return false;
    }
    if (SSL_connect(c->ssl) != 1) {
        ERR_clear_error();
        conn_close(c);
        return false;
    }
    X509 *leaf = SSL_get1_peer_certificate(c->ssl);
    if (!leaf) {
        conn_close(c);
        return false;
    }
    const int n = X509_NAME_get_text_by_NID(X509_get_subject_name(leaf),
                                            NID_commonName, c->cn,
                                            (int)sizeof(c->cn));
    X509_free(leaf);
    if (n <= 0) {
        conn_close(c);
        return false;
    }
    return true;
}

/* GET / on an already-open connection. The front door answers a bare "/"
 * with a 302 to /explorer and touches no chain state, so this exercises the
 * connection without needing a node behind it. */
static bool conn_get_root(struct conn *c)
{
    static const char req[] = "GET / HTTP/1.1\r\nHost: x\r\n\r\n";
    if (SSL_write(c->ssl, req, (int)(sizeof(req) - 1)) <= 0)
        return false;
    char buf[512] = "";
    const int n = SSL_read(c->ssl, buf, (int)sizeof(buf) - 1);
    if (n <= 0)
        return false;
    buf[n] = '\0';
    return strstr(buf, "HTTP/1.1 302") != NULL;
}

/* Which certificate is on the wire right now, or NULL when the handshake
 * failed. Result points into a caller-owned buffer. */
static bool served_cn(char *out, size_t out_len)
{
    struct conn c;
    if (!conn_open(&c))
        return false;
    snprintf(out, out_len, "%s", c.cn);
    conn_close(&c);
    return true;
}

/* ── the concurrency leg ─────────────────────────────────────────────── */

struct hammer {
    pthread_t thread;
    int rounds;
    int handshakes_failed;
    int saw_alpha;
    int saw_bravo;
    int saw_other;
};

static pthread_mutex_t g_hammer_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_hammer_cond = PTHREAD_COND_INITIALIZER;
static bool g_hammer_start = false;
static int g_hammer_completed = 0;

static void *hammer_fn(void *arg)
{
    struct hammer *h = arg;

    pthread_mutex_lock(&g_hammer_lock);
    while (!g_hammer_start)
        pthread_cond_wait(&g_hammer_cond, &g_hammer_lock);
    pthread_mutex_unlock(&g_hammer_lock);

    for (int round = 0; round < h->rounds; round++) {
        struct conn c;
        if (!conn_open(&c)) {
            h->handshakes_failed++;
            continue;
        }
        if (strcmp(c.cn, ALPHA) == 0)
            h->saw_alpha++;
        else if (strcmp(c.cn, BRAVO) == 0)
            h->saw_bravo++;
        else
            h->saw_other++;
        conn_close(&c);
    }

    pthread_mutex_lock(&g_hammer_lock);
    g_hammer_completed++;
    pthread_cond_broadcast(&g_hammer_cond);
    pthread_mutex_unlock(&g_hammer_lock);
    return NULL;
}

int test_acme_cert_reload(void)
{
    int failures = 0;

    char dir[512];
    char a_cert[640], a_key[640], b_cert[640], b_key[640];
    char junk[640], absent[640];
    test_make_tmpdir(dir, sizeof(dir), "acme_cert_reload", "pairs");
    snprintf(a_cert, sizeof(a_cert), "%s/alpha.pem", dir);
    snprintf(a_key, sizeof(a_key), "%s/alpha-key.pem", dir);
    snprintf(b_cert, sizeof(b_cert), "%s/bravo.pem", dir);
    snprintf(b_key, sizeof(b_key), "%s/bravo-key.pem", dir);
    snprintf(junk, sizeof(junk), "%s/junk.pem", dir);
    snprintf(absent, sizeof(absent), "%s/never-written.pem", dir);

    CR_CHECK("a first certificate pair is written",
             acme_selfsigned_write(a_cert, a_key, ALPHA));
    CR_CHECK("a second, distinguishable pair is written",
             acme_selfsigned_write(b_cert, b_key, BRAVO));
    {
        FILE *f = fopen(junk, "wb");
        if (f) {
            fputs("-----BEGIN CERTIFICATE-----\nnot base64\n", f);
            fclose(f);
        }
    }

    const uint16_t https_port = free_port();
    const uint16_t http_port = free_port();
    CR_CHECK("two free ports were found", https_port != 0 && http_port != 0);
    if (https_port == 0 || http_port == 0) {
        test_rm_rf(dir);
        return failures;
    }
    atomic_store(&g_port, (int)https_port);

    CR_CHECK("the front door starts on the first pair",
             https_server_start_on_port(a_cert, a_key, ALPHA, (int)https_port,
                                        (int)http_port));
    if (!https_server_is_running()) {
        printf("acme_cert_reload: SKIP (the listener did not come up on port "
               "%u; nothing further was asserted in this run)\n",
               (unsigned)https_port);
        https_server_stop();
        test_rm_rf(dir);
        return failures;
    }

    /* ── what is being served, and whether the node says so ────────── */
    {
        char cn[256] = "";
        CR_CHECK("a client completes a handshake", served_cn(cn, sizeof(cn)));
        CR_CHECK("and is served the first certificate", strcmp(cn, ALPHA) == 0);
        CR_CHECK("the node reports that it is self-signed, not CA-issued",
                 https_server_certificate_is_self_signed());
    }

    /* ── the swap ──────────────────────────────────────────────────── */
    {
        CR_CHECK("nothing changed on disk means nothing is reloaded",
                 !https_server_certificate_refresh());

        https_server_watch_certificate(b_cert, b_key);
        CR_CHECK("watching a different pair makes the next refresh swap it in",
                 https_server_certificate_refresh());
        char cn[256] = "";
        CR_CHECK("a new client is served the second certificate",
                 served_cn(cn, sizeof(cn)) && strcmp(cn, BRAVO) == 0);
        CR_CHECK("and a second refresh finds nothing more to do",
                 !https_server_certificate_refresh());
    }

    /* ── a connection already established must not break ───────────── */
    {
        struct conn held;
        CR_CHECK("a connection is opened and its handshake completed",
                 conn_open(&held) && strcmp(held.cn, BRAVO) == 0);
        https_server_watch_certificate(a_cert, a_key);
        CR_CHECK("the certificate is swapped while it is open",
                 https_server_certificate_refresh());
        CR_CHECK("the OPEN connection still serves its request",
                 conn_get_root(&held));
        conn_close(&held);
        char cn[256] = "";
        CR_CHECK("while a new connection gets the swapped-in certificate",
                 served_cn(cn, sizeof(cn)) && strcmp(cn, ALPHA) == 0);
    }

    /* ── what a reload REFUSES, and what it keeps serving ──────────── */
    {
        char cn[256] = "";

        https_server_watch_certificate(a_cert, b_key);
        CR_CHECK("a certificate whose key is not its own is refused",
                 !https_server_certificate_refresh());
        CR_CHECK("and the front door keeps serving what it had",
                 served_cn(cn, sizeof(cn)) && strcmp(cn, ALPHA) == 0);
        CR_CHECK("a forced reload refuses the same mismatched pair",
                 !https_server_reload_certificate());

        https_server_watch_certificate(absent, a_key);
        CR_CHECK("a pair that is not on disk is not an error and not a swap",
                 !https_server_certificate_refresh());
        CR_CHECK("a forced reload of an absent certificate is refused",
                 !https_server_reload_certificate());
        CR_CHECK("and the front door still serves what it had",
                 served_cn(cn, sizeof(cn)) && strcmp(cn, ALPHA) == 0);

        https_server_watch_certificate(junk, a_key);
        CR_CHECK("a file that is not a certificate is refused",
                 !https_server_certificate_refresh());
        CR_CHECK("and the front door still serves what it had",
                 served_cn(cn, sizeof(cn)) && strcmp(cn, ALPHA) == 0);

        https_server_watch_certificate(NULL, NULL);
        CR_CHECK("naming half a pair to watch changes nothing",
                 !https_server_certificate_refresh() &&
                 served_cn(cn, sizeof(cn)) && strcmp(cn, ALPHA) == 0);

        /* Back to a good pair: the refusals above must not have wedged it. */
        https_server_watch_certificate(b_cert, b_key);
        CR_CHECK("a good pair after those refusals still swaps in",
                 https_server_reload_certificate() &&
                 served_cn(cn, sizeof(cn)) && strcmp(cn, BRAVO) == 0);
    }

    /* ── the atomicity claim, under concurrent handshakes ──────────── */
    {
        struct hammer workers[4];
        memset(workers, 0, sizeof(workers));
        pthread_mutex_lock(&g_hammer_lock);
        g_hammer_start = false;
        g_hammer_completed = 0;
        pthread_mutex_unlock(&g_hammer_lock);
        bool spawned = true;
        size_t spawned_count = 0;
        for (size_t i = 0; i < sizeof(workers) / sizeof(workers[0]); i++) {
            workers[i].rounds = 30;
            if (pthread_create(&workers[i].thread, NULL, hammer_fn,
                               &workers[i]) != 0) {
                workers[i].rounds = 0;
                spawned = false;
            } else
                spawned_count++;
        }

        pthread_mutex_lock(&g_hammer_lock);
        g_hammer_start = true;
        pthread_cond_broadcast(&g_hammer_cond);
        pthread_mutex_unlock(&g_hammer_lock);

        int flips = 0;
        for (;;) {
            int completed;
            if (flips % 2 == 0)
                https_server_watch_certificate(a_cert, a_key);
            else
                https_server_watch_certificate(b_cert, b_key);
            (void)https_server_certificate_refresh();
            flips++;

            pthread_mutex_lock(&g_hammer_lock);
            completed = g_hammer_completed;
            pthread_mutex_unlock(&g_hammer_lock);
            if (flips >= 60 && completed == (int)spawned_count)
                break;
        }
        int failed = 0, alpha = 0, bravo = 0, other = 0;
        for (size_t i = 0; i < sizeof(workers) / sizeof(workers[0]); i++) {
            if (workers[i].rounds == 0 && !spawned)
                continue;
            pthread_join(workers[i].thread, NULL);
            failed += workers[i].handshakes_failed;
            alpha += workers[i].saw_alpha;
            bravo += workers[i].saw_bravo;
            other += workers[i].saw_other;
        }
        printf("acme_cert_reload: %d handshakes during %d swaps "
               "(alpha=%d bravo=%d other=%d failed=%d)\n",
               alpha + bravo + other + failed, flips,
               alpha, bravo, other, failed);
        CR_CHECK("every thread was started", spawned);
        CR_CHECK("four workers each attempted exactly 30 handshakes",
                 alpha + bravo + other + failed == 4 * 30);
        /* A mismatched certificate and key cannot produce a page: it
         * produces a handshake failure. Zero failures IS the atomicity
         * claim. */
        CR_CHECK("no handshake failed while the certificate was swapping",
                 failed == 0);
        CR_CHECK("every certificate served was one whole pair or the other",
                 other == 0);
        CR_CHECK("enough handshakes ran for that to mean something",
                 alpha + bravo >= 100);
        /* Without this the run above could have proved only that nothing
         * ever changed. */
        CR_CHECK("and BOTH certificates were actually observed on the wire",
                 alpha > 0 && bravo > 0);
    }

    https_server_stop();
    CR_CHECK("the front door stops", !https_server_is_running());
    test_rm_rf(dir);
    return failures;
}
