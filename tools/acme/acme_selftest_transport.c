/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The pure half of tools/acme/tls_client.c: URL parsing and HTTP/1.1
 * response framing. Both are fed bytes straight from a buffer, so every
 * hostile shape a certificate authority (or something pretending to be one)
 * could send is reachable here without a socket.
 *
 * The last leg is not pure: it stands up a loopback TLS server presenting a
 * certificate that chains to nothing in the trust store, and asserts the
 * client REFUSES it. That is the one property of this module that cannot be
 * argued from bytes — a verification flag that is set but ineffective looks
 * identical from the outside until something malicious is on the wire.
 */

#if !defined(_WIN32)
/* mkdtemp, INADDR_LOOPBACK, and other BSD extensions are hidden under
 * strict POSIX feature-test macros on Darwin. */
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif
#ifndef _DARWIN_C_SOURCE
#define _DARWIN_C_SOURCE
#endif
#endif

#include "acme_selftest.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#include "tls_client.h"

#include "platform/socket_compat.h"

#include <openssl/ssl.h>
#include <openssl/x509.h>

/* On Windows, <wincrypt.h> (pulled in transitively by <windows.h> through
 * platform/socket_compat.h) defines X509_NAME as the object-like macro
 * ((LPCSTR) 7), which would rewrite the OpenSSL X509_NAME type used below
 * into a cast expression. Drop the macro — this file means the OpenSSL type. */
#if defined(_WIN32) && defined(X509_NAME)
#undef X509_NAME
#endif

#if !defined(_WIN32)
#include <errno.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* fork() can transiently fail with EAGAIN under per-uid RLIMIT_NPROC
 * pressure when the suite runs many workers. Retry briefly rather than
 * reporting a process-table shortage as a verification failure. */
static pid_t fork_with_retry(void)
{
    for (int attempt = 0; attempt < 50; attempt++) {
        const pid_t pid = fork();
        if (pid >= 0 || errno != EAGAIN)
            return pid;
        struct timespec ts = {.tv_sec = 0, .tv_nsec = 20 * 1000 * 1000};
        nanosleep(&ts, NULL);
    }
    return -1;
}

#endif

/* A throwaway self-signed certificate. Built here rather than borrowed
 * from the node's challenge module: this program has no business linking
 * the responder, and the proofs that use it only need "a well-formed
 * certificate that chains to nothing". */
bool acme_selftest_selfsigned(const char *cn, X509 **out_cert,
                              EVP_PKEY **out_key)
{
    *out_cert = NULL;
    *out_key = NULL;
    EVP_PKEY *key = EVP_EC_gen("P-256");
    X509 *cert = X509_new();
    bool ok = false;
    if (!key || !cert)
        goto done;
    if (X509_set_version(cert, 2) != 1 ||
        ASN1_INTEGER_set(X509_get_serialNumber(cert), 1) != 1)
        goto done;
    if (!X509_gmtime_adj(X509_getm_notBefore(cert), -3600) ||
        !X509_gmtime_adj(X509_getm_notAfter(cert), 3600))
        goto done;
    if (X509_set_pubkey(cert, key) != 1)
        goto done;
    {
        X509_NAME *subject = X509_get_subject_name(cert);
        if (X509_NAME_add_entry_by_txt(subject, "CN", MBSTRING_ASC,
                                       (const unsigned char *)cn, -1, -1, 0) != 1 ||
            X509_set_issuer_name(cert, subject) != 1)
            goto done;
    }
    ok = X509_sign(cert, key, EVP_sha256()) != 0;
done:
    if (!ok) {
        X509_free(cert);
        EVP_PKEY_free(key);
        return false;
    }
    *out_cert = cert;
    *out_key = key;
    return true;
}

#include <stdio.h>
#include <string.h>

#define TC_CHECK(name, expr) do {                        \
    printf("tls_client: %s... ", (name));                \
    if (expr) { printf("OK\n"); }                        \
    else { printf("FAIL\n"); failures++; }               \
} while (0)

static bool parse_ok(const char *url, const char *host, int port, const char *path)
{
    struct tls_client_url u;
    if (!tls_client_url_parse(url, &u))
        return false;
    return strcmp(u.host, host) == 0 && u.port == port && strcmp(u.path, path) == 0;
}

static bool parse_refused(const char *url)
{
    struct tls_client_url u;
    return !tls_client_url_parse(url, &u);
}

int acme_selftest_transport(void)
{
    int failures = 0;

    /* ── URL parsing ───────────────────────────────────────────────── */
    TC_CHECK("bare host defaults to 443 and /",
             parse_ok("https://acme-v02.api.letsencrypt.org",
                      "acme-v02.api.letsencrypt.org", 443, "/"));
    TC_CHECK("host with path",
             parse_ok("https://example.org/directory", "example.org", 443,
                      "/directory"));
    TC_CHECK("explicit port",
             parse_ok("https://example.org:8443/acme/new-order", "example.org",
                      8443, "/acme/new-order"));
    TC_CHECK("path keeps its query string",
             parse_ok("https://example.org/a?b=c", "example.org", 443, "/a?b=c"));
    TC_CHECK("IPv6 literal without a port",
             parse_ok("https://[2001:db8::1]/x", "2001:db8::1", 443, "/x"));
    TC_CHECK("IPv6 literal with a port",
             parse_ok("https://[2001:db8::1]:8443/", "2001:db8::1", 8443, "/"));

    TC_CHECK("http:// is refused (no downgrade path exists)",
             parse_refused("http://example.org/"));
    TC_CHECK("a scheme-less URL is refused", parse_refused("example.org/"));
    TC_CHECK("file:// is refused", parse_refused("file:///etc/passwd"));
    TC_CHECK("an empty host is refused", parse_refused("https:///directory"));
    TC_CHECK("userinfo in the authority is refused",
             parse_refused("https://user:pass@example.org/"));
    TC_CHECK("an empty port is refused", parse_refused("https://example.org:/"));
    TC_CHECK("a non-numeric port is refused",
             parse_refused("https://example.org:https/"));
    TC_CHECK("a port over 65535 is refused",
             parse_refused("https://example.org:70000/"));
    TC_CHECK("an unterminated IPv6 literal is refused",
             parse_refused("https://[2001:db8::1/"));
    TC_CHECK("junk after an IPv6 literal is refused",
             parse_refused("https://[2001:db8::1]x/"));
    TC_CHECK("a CR in the request target is refused (request smuggling)",
             parse_refused("https://example.org/a\rHost: evil"));
    TC_CHECK("a LF in the request target is refused",
             parse_refused("https://example.org/a\nX: y"));
    TC_CHECK("NULL URL is refused", parse_refused(NULL));
    {
        char big[TLS_CLIENT_MAX_HOST + 64];
        memset(big, 'a', sizeof(big));
        memcpy(big, "https://", 8);
        big[sizeof(big) - 1] = '\0';
        TC_CHECK("an oversized host is refused, not truncated", parse_refused(big));
    }
    {
        char big[TLS_CLIENT_MAX_PATH + 64];
        const int n = snprintf(big, sizeof(big), "https://example.org/");
        memset(big + n, 'p', sizeof(big) - (size_t)n - 1);
        big[sizeof(big) - 1] = '\0';
        TC_CHECK("an oversized path is refused, not truncated", parse_refused(big));
    }

    /* ── response framing: Content-Length ──────────────────────────── */
    {
        static const char raw[] =
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: engine/application/json\r\n"
            "Replay-Nonce:   oFvnlFP1wIhRlYS2jTaXbA  \r\n"
            "Content-Length: 13\r\n"
            "\r\n"
            "{\"status\":1}\n";
        struct tls_client_response r;
        const bool ok = tls_client_response_parse(raw, sizeof(raw) - 1, &r);
        TC_CHECK("content-length response parses", ok);
        if (ok) {
            TC_CHECK("status is 200", r.status == 200);
            TC_CHECK("body length matches Content-Length", r.body_len == 13);
            TC_CHECK("body content is exact",
                     memcmp(r.body, "{\"status\":1}\n", 13) == 0);
            char v[128];
            TC_CHECK("header lookup is case-insensitive",
                     tls_client_response_header(&r, "replay-NONCE", v, sizeof(v)) &&
                     strcmp(v, "oFvnlFP1wIhRlYS2jTaXbA") == 0);
            TC_CHECK("an absent header reports absent",
                     !tls_client_response_header(&r, "Location", v, sizeof(v)));
            TC_CHECK("a header value too long for the buffer is refused",
                     !tls_client_response_header(&r, "Content-Type", v, 4));
            tls_client_response_free(&r);
            TC_CHECK("free zeroes the response",
                     r.body == NULL && r.headers == NULL && r.body_len == 0);
        } else {
            failures += 5;
        }
    }

    /* ── response framing: chunked ─────────────────────────────────── */
    {
        static const char raw[] =
            "HTTP/1.1 201 Created\r\n"
            "Transfer-Encoding: chunked\r\n"
            "Location: https://ca.example/acct/1\r\n"
            "\r\n"
            "5\r\nhello\r\n"
            "6\r\n world\r\n"
            "0\r\n\r\n";
        struct tls_client_response r;
        const bool ok = tls_client_response_parse(raw, sizeof(raw) - 1, &r);
        TC_CHECK("chunked response parses", ok);
        if (ok) {
            TC_CHECK("chunked status is 201", r.status == 201);
            TC_CHECK("chunks are concatenated in order",
                     r.body_len == 11 && memcmp(r.body, "hello world", 11) == 0);
            char v[128];
            TC_CHECK("Location survives chunked framing",
                     tls_client_response_header(&r, "Location", v, sizeof(v)) &&
                     strcmp(v, "https://ca.example/acct/1") == 0);
            tls_client_response_free(&r);
        } else {
            failures += 3;
        }
    }

    /* ── response framing: refusals ────────────────────────────────── */
    {
        struct tls_client_response r;
        static const char no_status[] = "Content-Length: 0\r\n\r\n";
        TC_CHECK("a body with no status line is refused",
                 !tls_client_response_parse(no_status, sizeof(no_status) - 1, &r));

        static const char bad_version[] = "HTTP/2.0 200 OK\r\n\r\n";
        TC_CHECK("an unknown HTTP version is refused",
                 !tls_client_response_parse(bad_version, sizeof(bad_version) - 1, &r));

        static const char no_blank[] = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n";
        TC_CHECK("an unterminated header block is refused",
                 !tls_client_response_parse(no_blank, sizeof(no_blank) - 1, &r));

        static const char desync[] =
            "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n"
            "Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n";
        TC_CHECK("chunked AND content-length together is refused (desync)",
                 !tls_client_response_parse(desync, sizeof(desync) - 1, &r));

        static const char truncated[] =
            "HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nshort";
        TC_CHECK("a body shorter than Content-Length is refused",
                 !tls_client_response_parse(truncated, sizeof(truncated) - 1, &r));

        static const char huge[] =
            "HTTP/1.1 200 OK\r\nContent-Length: 99999999\r\n\r\n";
        TC_CHECK("a Content-Length past the cap is refused",
                 !tls_client_response_parse(huge, sizeof(huge) - 1, &r));

        static const char neg[] =
            "HTTP/1.1 200 OK\r\nContent-Length: -1\r\n\r\n";
        TC_CHECK("a negative Content-Length is refused",
                 !tls_client_response_parse(neg, sizeof(neg) - 1, &r));

        static const char badchunk[] =
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\nab\r\n0\r\n\r\n";
        TC_CHECK("a non-hex chunk size is refused",
                 !tls_client_response_parse(badchunk, sizeof(badchunk) - 1, &r));

        static const char unterminated_chunk[] =
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n";
        TC_CHECK("a chunked body with no terminating zero chunk is refused",
                 !tls_client_response_parse(unterminated_chunk,
                                            sizeof(unterminated_chunk) - 1, &r));

        TC_CHECK("an empty buffer is refused",
                 !tls_client_response_parse("", 0, &r));
        TC_CHECK("a NULL buffer is refused",
                 !tls_client_response_parse(NULL, 10, &r));
    }

    /* ── completeness predicate: what the read loop stops on ───────── */
    {
        static const char msg[] =
            "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nabcd";
        const size_t total = sizeof(msg) - 1;
        bool early_false = true;
        for (size_t i = 0; i < total; i++) {
            if (tls_client_response_complete(msg, i))
                early_false = false;
        }
        TC_CHECK("no prefix of a message is reported complete", early_false);
        TC_CHECK("the whole message is reported complete",
                 tls_client_response_complete(msg, total));

        static const char nolen[] = "HTTP/1.1 200 OK\r\nServer: x\r\n\r\nbody";
        TC_CHECK("a response with no framing header never self-reports complete",
                 !tls_client_response_complete(nolen, sizeof(nolen) - 1));

        static const char chunked[] =
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n";
        TC_CHECK("a finished chunked message is reported complete",
                 tls_client_response_complete(chunked, sizeof(chunked) - 1));
        TC_CHECK("a chunked message missing its terminator is not complete",
                 !tls_client_response_complete(chunked, sizeof(chunked) - 6));
    }

    /* ── fail-closed transport refusals (no socket is opened) ──────── */
    {
        struct tls_client_response r;
        TC_CHECK("fetch with no request is refused", !tls_client_fetch(NULL, &r));
        struct tls_client_request req = {.url = "http://example.org/"};
        TC_CHECK("fetch over plain http is refused before any connect",
                 !tls_client_fetch(&req, &r));
        struct tls_client_request nourl = {.method = "GET"};
        TC_CHECK("fetch with no URL is refused", !tls_client_fetch(&nourl, &r));
        struct tls_client_request lying = {
            .url = "https://example.invalid/", .body = NULL, .body_len = 16};
        TC_CHECK("a request declaring a body it does not carry is refused",
                 !tls_client_fetch(&lying, &r));
    }


    /* ── verification is really on: an untrusted chain is refused ───── */
#if !defined(_WIN32)
    {
        /* The strongest offline statement this file can make. A local TLS
         * server presents a perfectly well-formed certificate that chains to
         * nothing in the trust store. If tls_client_fetch() returned a body
         * here, verification would be decorative.
         *
         * The child reports, over a pipe, that it accepted a TCP connection
         * and entered the TLS handshake. Without that report a refusal could
         * mean "nothing was listening", which would prove nothing at all. */
        int report[2];
        X509 *cert = NULL;
        EVP_PKEY *key = NULL;
        platform_socket_t listener = PLATFORM_SOCKET_INVALID;
        int port = 0;

        const bool ready = pipe(report) == 0 &&
                           acme_selftest_selfsigned("localhost", &cert, &key);
        if (ready) {
            struct sockaddr_in addr;
            memset(&addr, 0, sizeof(addr));
            addr.sin_family = AF_INET;
            addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            addr.sin_port = 0;
            listener = platform_socket_open(AF_INET, SOCK_STREAM, 0, true, false);
            if (listener != PLATFORM_SOCKET_INVALID &&
                (platform_socket_bind(listener, (struct sockaddr *)&addr,
                                      sizeof(addr)) != 0 ||
                 platform_socket_listen(listener, 4) != 0)) {
                platform_socket_close(listener);
                listener = PLATFORM_SOCKET_INVALID;
            }
            if (listener != PLATFORM_SOCKET_INVALID) {
                struct sockaddr_storage bound;
                size_t bound_len = sizeof(bound);
                if (platform_socket_local_address(listener,
                                                  (struct sockaddr *)&bound,
                                                  &bound_len) == 0)
                    port = ntohs(((struct sockaddr_in *)&bound)->sin_port);
            }
        }
        TC_CHECK("a loopback TLS server is available for the refusal proof",
                 ready && listener != PLATFORM_SOCKET_INVALID && port > 0);

        if (ready && listener != PLATFORM_SOCKET_INVALID && port > 0) {
            const pid_t child = fork_with_retry();
            if (child == 0) {
                close(report[0]);
                SSL_CTX *sctx = SSL_CTX_new(TLS_server_method());
                if (sctx) {
                    SSL_CTX_use_certificate(sctx, cert);
                    SSL_CTX_use_PrivateKey(sctx, key);
                }
                struct sockaddr_storage peer;
                size_t peer_len = sizeof(peer);
                platform_socket_t conn = platform_socket_accept(
                    listener, (struct sockaddr *)&peer, &peer_len);
                if (conn != PLATFORM_SOCKET_INVALID) {
                    const char mark = 'A';
                    ssize_t ignored = write(report[1], &mark, 1);
                    (void)ignored;
                    if (sctx) {
                        SSL *ssl = SSL_new(sctx);
                        if (ssl) {
                            SSL_set_fd(ssl, conn);
                            SSL_accept(ssl);
                            SSL_free(ssl);
                        }
                    }
                    platform_socket_close(conn);
                }
                close(report[1]);
                _exit(0);
            }
            close(report[1]);

            char url[64];
            snprintf(url, sizeof(url), "https://127.0.0.1:%d/", port);
            struct tls_client_request req = {.url = url, .timeout_ms = 8000};
            struct tls_client_response r;
            const bool fetched = tls_client_fetch(&req, &r);
            tls_client_response_free(&r);

            char mark = 0;
            const ssize_t got = read(report[0], &mark, 1);
            close(report[0]);
            if (child > 0) {
                int status = 0;
                waitpid(child, &status, 0);
            }

            TC_CHECK("the loopback server really saw the connection",
                     got == 1 && mark == 'A');
            TC_CHECK("a certificate that chains to nothing trusted is REFUSED",
                     !fetched);
        } else {
            failures += 2;
            if (ready) {
                close(report[0]);
                close(report[1]);
            }
        }
        if (listener != PLATFORM_SOCKET_INVALID)
            platform_socket_close(listener);
        X509_free(cert);
        EVP_PKEY_free(key);
    }
#else
    printf("tls_client: UNOBSERVED (the loopback untrusted-chain refusal proof "
           "is POSIX-only; this build is Windows)\n");
#endif

    return failures;
}
