/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * TLS-ALPN-01 (RFC 8737) — the challenge responder.
 *
 * WHY THIS CHALLENGE AND NOT ANOTHER. The node's port forwarder is 443-only
 * by design (docs/BLOCK_EXPLORER_HOSTING.md), so HTTP-01 — which the CA
 * fetches over port 80 — cannot work here. DNS-01 needs a registrar API,
 * which is an external dependency the project does not take. TLS-ALPN-01
 * runs entirely over 443, the one port already forwarded, and is answered by
 * the TLS server we already own.
 *
 * HOW IT WORKS. The CA opens a TLS connection to the domain on 443, sends
 * SNI for the name under validation, and offers exactly one ALPN protocol:
 * "acme-tls/1". A server that means to answer the challenge must negotiate
 * that protocol and present a self-signed certificate that
 *   - carries a subjectAltName dNSName for the domain, and
 *   - carries a CRITICAL extension at OID 1.3.6.1.5.5.7.1.31 whose value is
 *     a DER OCTET STRING holding SHA-256(key authorization).
 * The CA then closes the connection. Nothing is ever served over it.
 *
 * The certificate is armed for the duration of one validation and disarmed
 * immediately after. While disarmed, a client offering "acme-tls/1" gets no
 * ALPN acknowledgement and the ordinary explorer certificate — the challenge
 * certificate is never presented to an ordinary browser.
 */

#ifndef ZCL_NET_ACME_CHALLENGE_H
#define ZCL_NET_ACME_CHALLENGE_H

#include "net/acme_arm_file.h"

#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* The one ALPN protocol identifier RFC 8737 defines, and the OID the
 * challenge certificate must carry. */
#define ACME_ALPN_PROTOCOL "acme-tls/1"
#define ACME_ID_OID_TEXT   "1.3.6.1.5.5.7.1.31"

/* Pure. SHA-256 of the key authorization — the exact 32 bytes the challenge
 * certificate's acmeIdentifier extension must carry. */
bool acme_alpn_challenge_digest(const char *key_authz, uint8_t out[32]);

/* Build the self-signed challenge certificate and its ephemeral key. Both
 * are owned by the caller. */
bool acme_alpn_challenge_certificate(const char *domain, const char *key_authz,
                                     X509 **out_cert, EVP_PKEY **out_key);

/* Arm the responder for one domain and key authorization. Replaces any
 * previous arming. Safe to call while the listener is serving. */
bool acme_alpn_challenge_arm(const char *domain, const char *key_authz);

/* Disarm. Idempotent; always call it when a validation finishes, including
 * on the failure path. */
void acme_alpn_challenge_disarm(void);

/* True while a challenge certificate would be presented. */
bool acme_alpn_challenge_armed(void);

/* Point the responder at the handoff file the certificate worker writes
 * (net/acme_arm_file.h). NULL or "" detaches it. Set once, before the
 * listener starts; the responder reads the file lazily, and only when a
 * client has actually negotiated "acme-tls/1", so an ordinary browser
 * handshake never touches the filesystem. */
void acme_alpn_challenge_set_handoff_file(const char *path);

/* Arm directly from a handoff file, ignoring any configured path. Returns
 * false when the file is absent or does not hold a usable pair. */
bool acme_alpn_challenge_arm_from_file(const char *path);

/* Install the ALPN selection hook on a server SSL_CTX. This is the whole
 * seam into the front door: one call, at context construction. */
bool acme_alpn_install(SSL_CTX *ctx);

#endif /* ZCL_NET_ACME_CHALLENGE_H */
