/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Minimal HTTPS client — enough to talk to an ACME v2 certificate authority
 * and nothing more.
 *
 * The node issues and renews its own TLS certificate (see net/acme_client.h),
 * which means it has to make outbound HTTPS requests to a public CA. Nothing
 * in the tree did that before: vendor/tor has a client, but it is Tor's, not
 * ours, and the node's own front door (net/https_server.h) is a server.
 *
 * SCOPE, deliberately small:
 *   - HTTP/1.1 over TLS 1.2+, one request per connection, `Connection: close`.
 *   - GET / HEAD / POST with an in-memory body.
 *   - Content-Length and chunked response framing.
 *   - Every read is bounded and every request carries a total deadline.
 *
 * NOT in scope: redirects, keep-alive, cookies, compression, proxies,
 * streaming bodies. An ACME server needs none of them.
 *
 * VERIFICATION IS FAIL-CLOSED AND HAS NO OFF SWITCH. There is deliberately no
 * "insecure" flag on struct tls_client_request: this client's whole job is to
 * fetch a certificate that the rest of the internet will then trust, so an
 * unverified answer is worse than no answer. When no CA trust store can be
 * found on the host the client refuses the request rather than proceeding —
 * the refusal names the trust store, never the caller.
 */

#ifndef ZCL_ACME_TLS_CLIENT_H
#define ZCL_ACME_TLS_CLIENT_H

#include <stdbool.h>
#include <stddef.h>

/* Bounds. An ACME directory, order, or certificate chain is a few kilobytes;
 * these caps are ~50x that and exist so a hostile or broken peer cannot make
 * the node allocate without limit. */
#define TLS_CLIENT_MAX_BODY        (256u * 1024u)
#define TLS_CLIENT_MAX_HEADER_BLOB (32u * 1024u)
#define TLS_CLIENT_MAX_RESPONSE    (TLS_CLIENT_MAX_BODY + TLS_CLIENT_MAX_HEADER_BLOB)
#define TLS_CLIENT_MAX_HOST        256
#define TLS_CLIENT_MAX_PATH        1024
#define TLS_CLIENT_DEFAULT_TIMEOUT_MS 30000

struct tls_client_url {
    char host[TLS_CLIENT_MAX_HOST];
    char path[TLS_CLIENT_MAX_PATH];  /* always begins with '/' */
    int  port;
};

/* Pure. Parse an absolute https:// URL. Any other scheme is refused — this
 * client protects a certificate-issuance conversation, and that conversation
 * is not allowed to happen in the clear. */
bool tls_client_url_parse(const char *url, struct tls_client_url *out);

struct tls_client_response {
    int    status;       /* HTTP status line code */
    char  *headers;      /* raw header block, NUL-terminated, no status line */
    char  *body;         /* NUL-terminated for convenience; use body_len */
    size_t body_len;
};

void tls_client_response_free(struct tls_client_response *r);

/* Pure. Parse a complete in-memory HTTP/1.1 response (status line, headers,
 * de-chunked body). Refuses a message whose declared body exceeds
 * TLS_CLIENT_MAX_BODY, whose header blob exceeds TLS_CLIENT_MAX_HEADER_BLOB,
 * or whose framing is malformed. `out` is left zeroed on failure. */
bool tls_client_response_parse(const char *raw, size_t len,
                               struct tls_client_response *out);

/* Pure. True once `raw[0..len)` holds a whole response message under the
 * framing its own headers declare. Used by the read loop to know when to
 * stop; exported because it is the part worth testing byte by byte. */
bool tls_client_response_complete(const char *raw, size_t len);

/* Case-insensitive lookup of a single header value. Values are copied with
 * surrounding whitespace stripped. Returns false when absent or too long. */
bool tls_client_response_header(const struct tls_client_response *r,
                                const char *name, char *out, size_t out_len);

struct tls_client_request {
    const char *method;        /* "GET", "HEAD", "POST"; NULL means GET */
    const char *url;           /* absolute https:// URL */
    const char *content_type;  /* optional; only sent with a body */
    const char *body;          /* optional request body */
    size_t      body_len;
    const char *user_agent;    /* optional */
    int         timeout_ms;    /* total deadline; <= 0 selects the default */
};

/* Perform one request. Returns false on any transport, TLS, verification,
 * framing, or bound failure; `out` is zeroed in that case. A non-2xx HTTP
 * status is NOT a failure — it is returned in out->status, because ACME uses
 * 4xx bodies (`urn:ietf:params:acme:error:badNonce`) as protocol messages. */
bool tls_client_fetch(const struct tls_client_request *req,
                      struct tls_client_response *out);

/* The CA trust store this process will verify against, or NULL when the host
 * has none that we could find. NULL means tls_client_fetch() refuses. */
const char *tls_client_trust_store(void);

#endif /* ZCL_ACME_TLS_CLIENT_H */
