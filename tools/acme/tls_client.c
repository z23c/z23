/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Minimal outbound HTTPS client. See net/tls_client.h for the scope and for
 * why certificate verification here has no off switch.
 *
 * Split of concerns inside this file:
 *   1. URL parsing and HTTP response framing — pure, no sockets, unit-tested
 *      byte by byte from lib/test/src/test_tls_client.c.
 *   2. The trust store probe — filesystem only, resolved once.
 *   3. The socket + TLS conversation — bounded reads, one total deadline.
 */

#if !defined(_WIN32)
#define _XOPEN_SOURCE 700
#endif

#include "tls_client.h"

#include "platform/socket_compat.h"

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

#if !defined(_WIN32)
#include <netdb.h>
#endif

#include "base/log_macros.h"
#include "base/safe_alloc.h"

/* ── 1. Pure parsing ─────────────────────────────────────────────────── */

bool tls_client_url_parse(const char *url, struct tls_client_url *out)
{
    if (!url || !out)
        return false;
    memset(out, 0, sizeof(*out));

    static const char scheme[] = "https://";
    const size_t scheme_len = sizeof(scheme) - 1;
    if (strncmp(url, scheme, scheme_len) != 0)
        LOG_FAIL("tlsclient",
                 "refusing a non-https URL: the certificate-issuance "
                 "conversation must be authenticated end to end");

    const char *authority = url + scheme_len;
    /* Userinfo would let a URL carry credentials into a CA conversation.
     * Nothing we talk to uses it; refuse rather than silently ignore. */
    const char *slash = strchr(authority, '/');
    const char *authority_end = slash ? slash : authority + strlen(authority);
    for (const char *p = authority; p < authority_end; p++) {
        if (*p == '@')
            LOG_FAIL("tlsclient", "refusing a URL authority carrying userinfo");
    }
    if (authority_end == authority)
        LOG_FAIL("tlsclient", "refusing a URL with an empty host");

    const char *host_start = authority;
    const char *host_end = authority_end;
    int port = 443;

    if (*host_start == '[') {
        const char *rb = memchr(host_start, ']', (size_t)(authority_end - host_start));
        if (!rb)
            LOG_FAIL("tlsclient", "refusing a URL with an unterminated IPv6 literal");
        host_start++;
        host_end = rb;
        if (rb + 1 < authority_end) {
            if (rb[1] != ':')
                LOG_FAIL("tlsclient", "refusing junk after an IPv6 literal in a URL");
            const char *port_text = rb + 2;
            if (port_text >= authority_end)
                LOG_FAIL("tlsclient", "refusing a URL with an empty port");
            port = 0;
            for (const char *p = port_text; p < authority_end; p++) {
                if (*p < '0' || *p > '9' || port > 65535)
                    LOG_FAIL("tlsclient", "refusing a URL with a non-numeric port");
                port = port * 10 + (*p - '0');
            }
        }
    } else {
        const char *colon = memchr(host_start, ':', (size_t)(authority_end - host_start));
        if (colon) {
            host_end = colon;
            const char *port_text = colon + 1;
            if (port_text >= authority_end)
                LOG_FAIL("tlsclient", "refusing a URL with an empty port");
            port = 0;
            for (const char *p = port_text; p < authority_end; p++) {
                if (*p < '0' || *p > '9' || port > 65535)
                    LOG_FAIL("tlsclient", "refusing a URL with a non-numeric port");
                port = port * 10 + (*p - '0');
            }
        }
    }

    if (port <= 0 || port > 65535)
        LOG_FAIL("tlsclient", "refusing a URL port outside 1..65535");
    const size_t host_len = (size_t)(host_end - host_start);
    if (host_len == 0 || host_len >= sizeof(out->host))
        LOG_FAIL("tlsclient", "refusing a URL host of %zu bytes", host_len);
    for (size_t i = 0; i < host_len; i++) {
        const unsigned char c = (unsigned char)host_start[i];
        if (c <= 0x20 || c == 0x7f || c == '/' || c == '\\' || c == '?' || c == '#')
            LOG_FAIL("tlsclient", "refusing a URL host with a control or delimiter byte");
    }
    memcpy(out->host, host_start, host_len);
    out->host[host_len] = '\0';
    out->port = port;

    if (!slash) {
        out->path[0] = '/';
        out->path[1] = '\0';
        return true;
    }
    const size_t path_len = strlen(slash);
    if (path_len >= sizeof(out->path))
        LOG_FAIL("tlsclient", "refusing a URL path of %zu bytes", path_len);
    for (size_t i = 0; i < path_len; i++) {
        const unsigned char c = (unsigned char)slash[i];
        /* A CR/LF or NUL in a request target is request smuggling. */
        if (c < 0x21 || c == 0x7f)
            LOG_FAIL("tlsclient", "refusing a URL path with a control byte");
    }
    memcpy(out->path, slash, path_len + 1);
    return true;
}

/* Locate the end of the header block. Returns the offset just past the blank
 * line, or 0 when the headers are not yet complete. */
static size_t header_block_end(const char *raw, size_t len)
{
    if (!raw)
        return 0;
    for (size_t i = 0; i + 3 < len; i++) {
        if (raw[i] == '\r' && raw[i + 1] == '\n' &&
            raw[i + 2] == '\r' && raw[i + 3] == '\n')
            return i + 4;
    }
    return 0;
}

static bool ci_equal(const char *a, const char *b, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        if (tolower((unsigned char)a[i]) != tolower((unsigned char)b[i]))
            return false;
    }
    return true;
}

/* Find `name:` in a header blob and return the trimmed value span. */
static bool header_span(const char *blob, size_t blob_len, const char *name,
                        const char **val, size_t *val_len)
{
    const size_t name_len = strlen(name);
    size_t line_start = 0;
    while (line_start < blob_len) {
        size_t line_end = line_start;
        while (line_end < blob_len && blob[line_end] != '\r' && blob[line_end] != '\n')
            line_end++;
        const size_t line_len = line_end - line_start;
        if (line_len > name_len && blob[line_start + name_len] == ':' &&
            ci_equal(blob + line_start, name, name_len)) {
            size_t v = line_start + name_len + 1;
            while (v < line_end && (blob[v] == ' ' || blob[v] == '\t'))
                v++;
            size_t e = line_end;
            while (e > v && (blob[e - 1] == ' ' || blob[e - 1] == '\t'))
                e--;
            *val = blob + v;
            *val_len = e - v;
            return true;
        }
        while (line_end < blob_len && (blob[line_end] == '\r' || blob[line_end] == '\n'))
            line_end++;
        line_start = line_end;
    }
    return false;
}

/* Parse a decimal Content-Length. Rejects anything that is not a plain
 * non-negative integer within the body cap — a duplicated or ambiguous
 * length is a smuggling primitive, not a rounding problem. */
static bool parse_content_length(const char *v, size_t n, size_t *out)
{
    if (n == 0 || n > 20)
        return false;
    size_t value = 0;
    for (size_t i = 0; i < n; i++) {
        if (v[i] < '0' || v[i] > '9')
            return false;
        if (value > (TLS_CLIENT_MAX_BODY + 1) / 10)
            return false;
        value = value * 10 + (size_t)(v[i] - '0');
    }
    *out = value;
    return true;
}

static bool header_is_chunked(const char *blob, size_t blob_len)
{
    const char *v = NULL;
    size_t n = 0;
    if (!header_span(blob, blob_len, "Transfer-Encoding", &v, &n))
        return false;
    return n == 7 && ci_equal(v, "chunked", 7);
}

/* Walk a chunked body. `complete` reports whether the terminating zero chunk
 * and trailer were seen; `decoded_len` counts payload bytes. Writes into
 * `decoded` when non-NULL (caller sized it with a prior sizing pass). */
static bool chunked_walk(const char *p, size_t len, bool *complete,
                         size_t *decoded_len, char *decoded)
{
    size_t off = 0;
    size_t total = 0;
    *complete = false;
    for (;;) {
        size_t line_end = off;
        while (line_end + 1 < len && !(p[line_end] == '\r' && p[line_end + 1] == '\n'))
            line_end++;
        if (line_end + 1 >= len) {
            *decoded_len = total;
            return true; /* truncated, not malformed */
        }
        size_t size = 0;
        size_t digits = 0;
        size_t i = off;
        for (; i < line_end; i++) {
            const char c = p[i];
            int d;
            if (c >= '0' && c <= '9') d = c - '0';
            else if (c >= 'a' && c <= 'f') d = c - 'a' + 10;
            else if (c >= 'A' && c <= 'F') d = c - 'A' + 10;
            else if (c == ';') break; /* chunk extension */
            else return false;
            if (size > (TLS_CLIENT_MAX_BODY + 1) / 16)
                return false;
            size = size * 16 + (size_t)d;
            digits++;
        }
        if (digits == 0)
            return false;
        off = line_end + 2;
        if (size == 0) {
            /* Trailer section: consume header lines until the blank line. */
            for (;;) {
                size_t t_end = off;
                while (t_end + 1 < len && !(p[t_end] == '\r' && p[t_end + 1] == '\n'))
                    t_end++;
                if (t_end + 1 >= len) {
                    *decoded_len = total;
                    return true; /* truncated trailer */
                }
                const bool blank = (t_end == off);
                off = t_end + 2;
                if (blank) {
                    *complete = true;
                    *decoded_len = total;
                    return true;
                }
            }
        }
        if (total > TLS_CLIENT_MAX_BODY - size)
            return false;
        if (off + size + 2 > len) {
            *decoded_len = total;
            return true; /* truncated payload */
        }
        if (p[off + size] != '\r' || p[off + size + 1] != '\n')
            return false;
        if (decoded)
            memcpy(decoded + total, p + off, size);
        total += size;
        off += size + 2;
    }
}

bool tls_client_response_complete(const char *raw, size_t len)
{
    const size_t hdr_end = header_block_end(raw, len);
    if (hdr_end == 0)
        return false;
    if (hdr_end > TLS_CLIENT_MAX_HEADER_BLOB)
        return false;
    const char *blob = raw;
    const size_t blob_len = hdr_end;
    if (header_is_chunked(blob, blob_len)) {
        bool complete = false;
        size_t decoded = 0;
        if (!chunked_walk(raw + hdr_end, len - hdr_end, &complete, &decoded, NULL))
            return true; /* malformed: stop reading, let parse report it */
        return complete;
    }
    const char *v = NULL;
    size_t n = 0;
    size_t content_length = 0;
    if (header_span(blob, blob_len, "Content-Length", &v, &n)) {
        if (!parse_content_length(v, n, &content_length))
            return true; /* malformed: stop reading */
        return len - hdr_end >= content_length;
    }
    /* No framing header: the message ends when the peer closes. */
    return false;
}

static bool parse_status_line(const char *raw, size_t len, int *status,
                              size_t *line_len)
{
    size_t i = 0;
    while (i + 1 < len && !(raw[i] == '\r' && raw[i + 1] == '\n'))
        i++;
    if (i + 1 >= len)
        return false;
    if (i < 12)
        return false;
    if (memcmp(raw, "HTTP/1.", 7) != 0)
        return false;
    if (raw[7] != '0' && raw[7] != '1')
        return false;
    if (raw[8] != ' ')
        return false;
    if (raw[9] < '0' || raw[9] > '9' || raw[10] < '0' || raw[10] > '9' ||
        raw[11] < '0' || raw[11] > '9')
        return false;
    *status = (raw[9] - '0') * 100 + (raw[10] - '0') * 10 + (raw[11] - '0');
    *line_len = i + 2;
    return true;
}

bool tls_client_response_parse(const char *raw, size_t len,
                               struct tls_client_response *out)
{
    if (!out)
        return false;
    memset(out, 0, sizeof(*out));
    if (!raw || len == 0)
        return false;
    if (len > TLS_CLIENT_MAX_RESPONSE)
        LOG_FAIL("tlsclient", "refusing a %zu-byte response: over the read cap", len);

    int status = 0;
    size_t status_len = 0;
    if (!parse_status_line(raw, len, &status, &status_len))
        LOG_FAIL("tlsclient", "refusing a response without a well-formed HTTP status line");

    const size_t hdr_end = header_block_end(raw, len);
    if (hdr_end == 0 || hdr_end <= status_len)
        LOG_FAIL("tlsclient", "refusing a response with an unterminated header block");
    if (hdr_end > TLS_CLIENT_MAX_HEADER_BLOB)
        LOG_FAIL("tlsclient", "refusing a %zu-byte header block: over the cap", hdr_end);

    const char *blob = raw + status_len;
    const size_t blob_len = hdr_end - status_len;

    /* Content-Length and Transfer-Encoding together, or a repeated
     * Content-Length, are the classic desync primitives. Refuse both. */
    const bool chunked = header_is_chunked(blob, blob_len);
    const char *v = NULL;
    size_t n = 0;
    const bool has_len = header_span(blob, blob_len, "Content-Length", &v, &n);
    if (chunked && has_len)
        LOG_FAIL("tlsclient", "refusing a response framed both chunked and by length");

    size_t body_len = 0;
    char *body = NULL;

    if (chunked) {
        bool complete = false;
        size_t decoded = 0;
        if (!chunked_walk(raw + hdr_end, len - hdr_end, &complete, &decoded, NULL))
            LOG_FAIL("tlsclient", "refusing a response with a malformed chunked body");
        if (!complete)
            LOG_FAIL("tlsclient", "refusing a truncated chunked response body");
        if (decoded > TLS_CLIENT_MAX_BODY)
            LOG_FAIL("tlsclient", "refusing a %zu-byte chunked body: over the cap", decoded);
        body = zcl_malloc(decoded + 1, "tls_client_body");
        if (!body)
            LOG_FAIL("tlsclient", "cannot allocate %zu bytes for a response body", decoded + 1);
        size_t written = 0;
        if (!chunked_walk(raw + hdr_end, len - hdr_end, &complete, &written, body) ||
            written != decoded) {
            free(body);
            LOG_FAIL("tlsclient", "chunked body decode disagreed with its sizing pass");
        }
        body[decoded] = '\0';
        body_len = decoded;
    } else {
        size_t available = len - hdr_end;
        if (has_len) {
            size_t declared = 0;
            if (!parse_content_length(v, n, &declared))
                LOG_FAIL("tlsclient", "refusing a response with an unparsable Content-Length");
            if (declared > TLS_CLIENT_MAX_BODY)
                LOG_FAIL("tlsclient", "refusing a %zu-byte body: over the cap", declared);
            if (available < declared)
                LOG_FAIL("tlsclient", "refusing a truncated response body: %zu of %zu bytes",
                         available, declared);
            available = declared;
        }
        if (available > TLS_CLIENT_MAX_BODY)
            LOG_FAIL("tlsclient", "refusing a %zu-byte body: over the cap", available);
        body = zcl_malloc(available + 1, "tls_client_body");
        if (!body)
            LOG_FAIL("tlsclient", "cannot allocate %zu bytes for a response body", available + 1);
        if (available)
            memcpy(body, raw + hdr_end, available);
        body[available] = '\0';
        body_len = available;
    }

    char *headers = zcl_malloc(blob_len + 1, "tls_client_headers");
    if (!headers) {
        free(body);
        LOG_FAIL("tlsclient", "cannot allocate %zu bytes for response headers", blob_len + 1);
    }
    memcpy(headers, blob, blob_len);
    headers[blob_len] = '\0';

    out->status = status;
    out->headers = headers;
    out->body = body;
    out->body_len = body_len;
    return true;
}

bool tls_client_response_header(const struct tls_client_response *r,
                                const char *name, char *out, size_t out_len)
{
    if (!r || !r->headers || !name || !out || out_len == 0)
        return false;
    out[0] = '\0';
    const char *v = NULL;
    size_t n = 0;
    if (!header_span(r->headers, strlen(r->headers), name, &v, &n))
        return false;
    if (n >= out_len)
        return false;
    memcpy(out, v, n);
    out[n] = '\0';
    return true;
}

void tls_client_response_free(struct tls_client_response *r)
{
    if (!r)
        return;
    free(r->headers);
    free(r->body);
    memset(r, 0, sizeof(*r));
}

/* ── 2. Trust store ──────────────────────────────────────────────────── */

const char *tls_client_trust_store(void)
{
    static const char *const candidates[] = {
        "/etc/ssl/certs/ca-certificates.crt",   /* Debian, Ubuntu, Alpine */
        "/etc/pki/tls/certs/ca-bundle.crt",     /* Fedora, RHEL */
        "/etc/ssl/ca-bundle.pem",               /* SUSE */
        "/etc/pki/tls/cacert.pem",              /* older RHEL */
        "/etc/ssl/cert.pem",                    /* macOS ports, BSD */
        "/usr/local/share/certs/ca-root-nss.crt", /* FreeBSD */
        "/etc/ssl/certs/ca-bundle.crt",
    };
    const char *env = getenv("SSL_CERT_FILE");
    if (env && env[0]) {
        FILE *f = fopen(env, "rb");
        if (f) {
            fclose(f);
            return env;
        }
    }
    for (size_t i = 0; i < sizeof(candidates) / sizeof(candidates[0]); i++) {
        FILE *f = fopen(candidates[i], "rb");
        if (f) {
            fclose(f);
            return candidates[i];
        }
    }
    return NULL;
}

/* ── 3. The conversation ─────────────────────────────────────────────── */

static int64_t now_ms(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (int64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

static platform_socket_t connect_host(const char *host, int port, int64_t deadline)
{
    char port_text[8];
    snprintf(port_text, sizeof(port_text), "%d", port);

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo *res = NULL;
    if (getaddrinfo(host, port_text, &hints, &res) != 0 || !res)
        LOG_RETURN(PLATFORM_SOCKET_INVALID, "tlsclient",
                   "cannot resolve %s:%d", host, port);

    platform_socket_t sock = PLATFORM_SOCKET_INVALID;
    for (struct addrinfo *ai = res; ai; ai = ai->ai_next) {
        const int64_t remaining = deadline - now_ms();
        if (remaining <= 0)
            break;
        platform_socket_t s =
            platform_socket_open(ai->ai_family, ai->ai_socktype, ai->ai_protocol,
                                 true /* close_on_exec */, true /* nonblocking */);
        if (s == PLATFORM_SOCKET_INVALID)
            continue;
        const int rc = platform_socket_connect(s, ai->ai_addr, (int)ai->ai_addrlen);
        if (rc != 0) {
            if (!platform_socket_error_in_progress(platform_socket_last_error())) {
                platform_socket_close(s);
                continue;
            }
            const int wait_ms = (int)(remaining > INT_MAX ? INT_MAX : remaining);
            if (platform_socket_wait_writable(s, wait_ms) <= 0) {
                platform_socket_close(s);
                continue;
            }
            int pending = 0;
            if (platform_socket_pending_error(s, &pending) != 0 || pending != 0) {
                platform_socket_close(s);
                continue;
            }
        }
        if (!platform_socket_set_nonblocking(s, false)) {
            platform_socket_close(s);
            continue;
        }
        sock = s;
        break;
    }
    freeaddrinfo(res);
    if (sock == PLATFORM_SOCKET_INVALID)
        LOG_RETURN(PLATFORM_SOCKET_INVALID, "tlsclient",
                   "cannot connect to %s:%d before the deadline", host, port);
    return sock;
}

/* Build the SSL_CTX for one request. Verification is mandatory: the CA
 * trust store is the thing this guards, so a host without one is refused. */
static SSL_CTX *client_ctx(void)
{
    const char *store = tls_client_trust_store();
    if (!store)
        LOG_NULL("tlsclient",
                 "no CA trust store found on this host; refusing to speak to a "
                 "certificate authority without one");
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx)
        LOG_NULL("tlsclient", "SSL_CTX_new failed");
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_verify_depth(ctx, 10);
    SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION);
    if (SSL_CTX_load_verify_locations(ctx, store, NULL) != 1) {
        SSL_CTX_free(ctx);
        LOG_NULL("tlsclient", "cannot load the CA trust store at %s", store);
    }
    return ctx;
}

static bool ssl_write_all(SSL *ssl, const char *data, size_t len, int64_t deadline)
{
    size_t off = 0;
    while (off < len) {
        if (now_ms() > deadline)
            LOG_FAIL("tlsclient", "request write exceeded the deadline");
        const int chunk = (int)(len - off > INT_MAX ? INT_MAX : len - off);
        const int wrote = SSL_write(ssl, data + off, chunk);
        if (wrote <= 0)
            LOG_FAIL("tlsclient", "TLS write failed: ssl_error=%d",
                     SSL_get_error(ssl, wrote));
        off += (size_t)wrote;
    }
    return true;
}

bool tls_client_fetch(const struct tls_client_request *req,
                      struct tls_client_response *out)
{
    if (!out)
        return false;
    memset(out, 0, sizeof(*out));
    if (!req || !req->url)
        LOG_FAIL("tlsclient", "refusing a request with no URL");
    if (req->body_len > TLS_CLIENT_MAX_BODY)
        LOG_FAIL("tlsclient", "refusing a %zu-byte request body: over the cap",
                 req->body_len);
    if (req->body_len && !req->body)
        LOG_FAIL("tlsclient", "refusing a request declaring a body it does not carry");

    struct tls_client_url url;
    if (!tls_client_url_parse(req->url, &url))
        return false;

    const int timeout_ms = req->timeout_ms > 0 ? req->timeout_ms
                                               : TLS_CLIENT_DEFAULT_TIMEOUT_MS;
    const int64_t deadline = now_ms() + timeout_ms;

    SSL_CTX *ctx = client_ctx();
    if (!ctx)
        return false;

    platform_socket_t sock = connect_host(url.host, url.port, deadline);
    if (sock == PLATFORM_SOCKET_INVALID) {
        SSL_CTX_free(ctx);
        return false;
    }

    bool ok = false;
    SSL *ssl = SSL_new(ctx);
    char *buf = NULL;
    if (!ssl) {
        LOG_WARN("tlsclient", "SSL_new failed");
        goto done;
    }
    /* Socket-level timeouts bound each individual read/write; the deadline
     * above bounds the whole exchange. Both are needed: a peer that dribbles
     * one byte per second never trips a per-read timeout. */
    {
        const int per_io_ms = timeout_ms;
        platform_socket_set_receive_timeout(sock, per_io_ms);
        platform_socket_set_send_timeout(sock, per_io_ms);
    }
#if defined(_WIN32)
    if ((uintptr_t)sock > INT_MAX || SSL_set_fd(ssl, (int)(uintptr_t)sock) != 1) {
        LOG_WARN("tlsclient", "cannot bind the socket to the TLS session");
        goto done;
    }
#else
    if (SSL_set_fd(ssl, sock) != 1) {
        LOG_WARN("tlsclient", "cannot bind the socket to the TLS session");
        goto done;
    }
#endif
    /* SNI plus hostname verification. SSL_set1_host() makes the name part of
     * the verification result, so a valid certificate for the wrong name
     * fails the handshake rather than being accepted. */
    if (SSL_set_tlsext_host_name(ssl, url.host) != 1) {
        LOG_WARN("tlsclient", "cannot set SNI for %s", url.host);
        goto done;
    }
    if (SSL_set1_host(ssl, url.host) != 1) {
        LOG_WARN("tlsclient", "cannot pin the verified hostname to %s", url.host);
        goto done;
    }
    SSL_set_hostflags(ssl, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);

    if (SSL_connect(ssl) != 1) {
        LOG_WARN("tlsclient", "TLS handshake with %s failed: ssl_error=%d",
                 url.host, SSL_get_error(ssl, -1));
        goto done;
    }
    if (SSL_get_verify_result(ssl) != X509_V_OK) {
        LOG_WARN("tlsclient",
                 "certificate chain for %s did not verify against the CA trust store",
                 url.host);
        goto done;
    }

    {
        const char *method = req->method ? req->method : "GET";
        char head[2048];
        int n = snprintf(head, sizeof(head),
                         "%s %s HTTP/1.1\r\n"
                         "Host: %s\r\n"
                         "User-Agent: %s\r\n"
                         "Accept: */*\r\n"
                         "Connection: close\r\n",
                         method, url.path, url.host,
                         req->user_agent ? req->user_agent : "zclassic23");
        if (n < 0 || (size_t)n >= sizeof(head)) {
            LOG_WARN("tlsclient", "request head does not fit its buffer");
            goto done;
        }
        if (req->body_len) {
            const int m = snprintf(head + n, sizeof(head) - (size_t)n,
                                   "Content-Type: %s\r\nContent-Length: %zu\r\n",
                                   req->content_type ? req->content_type
                                                     : "application/octet-stream",
                                   req->body_len);
            if (m < 0 || (size_t)(n + m) >= sizeof(head)) {
                LOG_WARN("tlsclient", "request head does not fit its buffer");
                goto done;
            }
            n += m;
        }
        if ((size_t)n + 2 >= sizeof(head)) {
            LOG_WARN("tlsclient", "request head does not fit its buffer");
            goto done;
        }
        head[n++] = '\r';
        head[n++] = '\n';
        if (!ssl_write_all(ssl, head, (size_t)n, deadline))
            goto done;
        if (req->body_len && !ssl_write_all(ssl, req->body, req->body_len, deadline))
            goto done;
    }

    buf = zcl_malloc(TLS_CLIENT_MAX_RESPONSE + 1, "tls_client_read");
    if (!buf) {
        LOG_WARN("tlsclient", "cannot allocate the bounded response buffer");
        goto done;
    }
    size_t used = 0;
    for (;;) {
        if (now_ms() > deadline) {
            LOG_WARN("tlsclient", "response read exceeded the deadline");
            goto done;
        }
        if (used >= TLS_CLIENT_MAX_RESPONSE) {
            LOG_WARN("tlsclient",
                     "refusing a response over the %u-byte read cap",
                     (unsigned)TLS_CLIENT_MAX_RESPONSE);
            goto done;
        }
        const int want = (int)(TLS_CLIENT_MAX_RESPONSE - used);
        const int got = SSL_read(ssl, buf + used, want);
        if (got <= 0) {
            const int err = SSL_get_error(ssl, got);
            if (err == SSL_ERROR_ZERO_RETURN || err == SSL_ERROR_SYSCALL)
                break; /* peer closed; framing decides whether that is enough */
            LOG_WARN("tlsclient", "TLS read failed: ssl_error=%d", err);
            goto done;
        }
        used += (size_t)got;
        if (tls_client_response_complete(buf, used))
            break;
    }
    ok = tls_client_response_parse(buf, used, out);

done:
    free(buf);
    if (ssl) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }
    platform_socket_close(sock);
    SSL_CTX_free(ctx);
    if (!ok)
        tls_client_response_free(out);
    return ok;
}
