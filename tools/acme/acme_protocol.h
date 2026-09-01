/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The ACME v2 (RFC 8555) wire objects, and the CSR.
 *
 * Everything here is a pure function of bytes: hand it a response body and
 * it either fills a fixed-size struct or refuses. No sockets, no clock, no
 * global state — which is what makes the recorded-fixture tests in
 * tests/harness/src/test_acme_protocol.c able to cover the hostile cases (a
 * missing field, a wrong type, an oversized URL, a challenge array with no
 * tls-alpn-01 member) that a live staging run would never produce on demand.
 *
 * Fixed-size fields, not heap strings, on purpose: every one of these values
 * comes from a remote party, and a cap that the parser enforces is easier to
 * reason about than a length the caller has to remember to check.
 */

#ifndef ZCL_ACME_PROTOCOL_H
#define ZCL_ACME_PROTOCOL_H

#include <openssl/evp.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define ACME_MAX_URL         512
#define ACME_MAX_STATUS      32
#define ACME_MAX_TOKEN       256
#define ACME_MAX_AUTHZ       8
#define ACME_MAX_DETAIL      512
/* A full chain is a leaf plus one or two intermediates — a few kilobytes.
 * The cap is generous and exists so a hostile endpoint cannot hand the node
 * an unbounded "certificate". */
#define ACME_MAX_CHAIN_BYTES (64u * 1024u)

/* The directory object: the three endpoints this client uses. `new_nonce` is
 * mandatory even though some CAs also hand out a nonce on every response —
 * without it the first POST has nothing to replay-protect. */
struct acme_directory {
    char new_nonce[ACME_MAX_URL];
    char new_account[ACME_MAX_URL];
    char new_order[ACME_MAX_URL];
};

bool acme_directory_parse(const char *json, size_t len,
                          struct acme_directory *out);

struct acme_order {
    char   status[ACME_MAX_STATUS];
    char   finalize[ACME_MAX_URL];
    char   certificate[ACME_MAX_URL];   /* empty until status is "valid" */
    char   authorizations[ACME_MAX_AUTHZ][ACME_MAX_URL];
    size_t num_authorizations;
};

bool acme_order_parse(const char *json, size_t len, struct acme_order *out);

struct acme_challenge {
    char status[ACME_MAX_STATUS];
    char token[ACME_MAX_TOKEN];
    char url[ACME_MAX_URL];
};

/* Pull the identifier value and the tls-alpn-01 challenge out of an
 * authorization object. Refuses an authorization that offers no tls-alpn-01
 * challenge: this node cannot answer http-01 (no port 80) or dns-01 (no
 * registrar API), so silently picking another type would produce a
 * validation that can never succeed. */
bool acme_authorization_parse(const char *json, size_t len,
                              char *identifier, size_t identifier_len,
                              char *status, size_t status_len,
                              struct acme_challenge *out);

/* RFC 7807 problem document. Returns false when the body is not one. */
bool acme_problem_parse(const char *json, size_t len,
                        char *type, size_t type_len,
                        char *detail, size_t detail_len);

/* A PKCS#10 CSR in DER, signed by `key`, with the domain in both the subject
 * CN and a subjectAltName. The CA reads the SAN; the CN is for humans
 * reading the certificate later. Caller frees *der with free(). */
bool acme_csr_der(const EVP_PKEY *key, const char *domain,
                  uint8_t **der, size_t *der_len);

/* Concatenated PEM certificates as returned by the ACME certificate
 * endpoint, validated: at least one parsable certificate, leaf first. */
bool acme_chain_is_wellformed(const char *pem, size_t len, size_t *count);

#endif /* ZCL_ACME_PROTOCOL_H */
