/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The self-signed certificate the node signs for itself, and the two things
 * it is used for.
 *
 * WHY THIS EXISTS AT ALL — the bootstrap deadlock. TLS-ALPN-01 (RFC 8737) is
 * answered BY the node's own 443 listener, and that listener refuses to bind
 * without key material. So a brand-new host with no certificate could never
 * get one: no certificate, no listener; no listener, no validation; no
 * validation, no certificate. Something has to break the cycle, and the only
 * thing that can break it without a human is a certificate the node makes
 * for itself. The challenge response does not depend on that certificate
 * being trusted by anybody — the CA replaces it wholesale for the duration
 * of the validation handshake — it depends only on a listener existing to do
 * the replacing.
 *
 * WHY IT LIVES IN THE NODE AND NOT IN THE CERTIFICATE WORKER. The deadlock
 * is a boot-time property of the node: the listener has to come up on a host
 * where `zclassic23-acme` may not even be installed, and requiring an
 * operator to run a second program before the node can listen is exactly the
 * manual step this whole effort removes. Nothing here is a TLS client and
 * nothing here consults a trust store — it is X509_new(), EVP_EC_gen() and
 * X509_sign(), the same three calls the TLS-ALPN-01 responder beside it
 * already makes (acme_alpn_challenge.c) — so putting it in the node costs
 * the sovereignty property nothing. test_cold_join_sovereign P2 stays green
 * on its own terms, not by exemption.
 *
 * A PLACEHOLDER IS NEVER QUIETLY PASSED OFF AS A REAL CERTIFICATE. Three
 * independent things say so, and none of them is a flag somebody remembered
 * to set:
 *   - on disk it is not at the CA-issued path at all. The pair written here
 *     is `self-signed-placeholder.pem` / `self-signed-placeholder-key.pem`;
 *     `fullchain.pem` and `privkey.pem` stay reserved for a real answer from
 *     a real authority, and the node prefers them the instant they appear.
 *   - in the certificate, the subject carries ACME_SELFSIGNED_ORGANIZATION
 *     in plain words, readable with `openssl x509 -noout -subject`.
 *   - at runtime the front door reports which it is serving from an
 *     INTRINSIC property — issuer equals subject — so a hand-placed
 *     self-signed certificate an operator dropped in is announced just as
 *     loudly as one this file wrote.
 */

#ifndef ZCL_NET_ACME_SELFSIGNED_H
#define ZCL_NET_ACME_SELFSIGNED_H

#include <openssl/x509.h>

#include <stdbool.h>

/* Goes in the subject as O=. Deliberately a sentence, not a code: whoever
 * reads it is looking at a certificate they did not expect.
 *
 * It must also FIT. X.509 caps organizationName at ub_organization_name
 * (64), and OpenSSL does not truncate an over-long value -- it refuses the
 * entry outright. A 69-byte sentence here made X509_NAME_add_entry_by_txt()
 * fail, so set_subject() failed, so acme_selfsigned_write() never wrote the
 * placeholder pair at all. That is not a cosmetic bug: the placeholder is
 * the only thing that breaks the certificate bootstrap deadlock, so a brand
 * new host could never obtain its first certificate. The failure was
 * invisible on any host that already had one. Hence the assertion: this
 * length is load-bearing, and the compiler now says so. */
#define ACME_SELFSIGNED_ORGANIZATION \
    "Z23 SELF-SIGNED PLACEHOLDER - NOT FROM A CERTIFICATE AUTHORITY"

static_assert(sizeof(ACME_SELFSIGNED_ORGANIZATION) - 1 <= ub_organization_name,
              "O= must fit X.509 ub_organization_name, or OpenSSL refuses it "
              "and the node cannot write its self-signed placeholder");

/* The name used when the operator set no -httpsdomain. A placeholder is
 * presented to nobody who checks it, so the value only has to be a legal
 * LDH name; this one also reads correctly in a log line. */
#define ACME_SELFSIGNED_DEFAULT_CN "localhost"

/* Ten years. Not laziness, and not a security position: nothing trusts this
 * certificate, so its expiry protects nobody. What a short expiry WOULD do
 * is close the ALPN door — an expired placeholder means a listener that
 * refuses to start, which means the TLS-ALPN-01 challenge can never be
 * answered, which is precisely the deadlock this file exists to break. The
 * placeholder therefore outlives any plausible gap before a real
 * certificate arrives. */
#define ACME_SELFSIGNED_LIFETIME_SECONDS (10 * 365 * 24 * 3600L)

/* Pure. An LDH domain name, one to 253 bytes, labels of at most 63. Shared
 * with the TLS-ALPN-01 responder because both sign a certificate carrying
 * the name and both compare it against TLS SNI. */
bool acme_domain_is_ldh(const char *domain);

/* What a self-signed certificate is made of. `extra`, when non-NULL, is
 * added before signing — that is how the TLS-ALPN-01 responder attaches its
 * critical acmeIdentifier extension without duplicating any of this. */
struct acme_selfsigned_spec {
    const char *domain;          /* subject CN and subjectAltName dNSName */
    const char *organization;    /* subject O, or NULL for none */
    long backdate_seconds;       /* notBefore = now - this */
    long lifetime_seconds;       /* notAfter  = now + this */
    X509_EXTENSION *extra;       /* attached before signing, or NULL */
};

/* Build and sign one. A fresh P-256 key each time; both objects are owned by
 * the caller. */
bool acme_selfsigned_build(const struct acme_selfsigned_spec *spec,
                           X509 **out_cert, EVP_PKEY **out_key);

/* Pure-ish. True when the certificate's issuer equals its subject. This is
 * the honest test for "nobody vouched for this": a certificate an authority
 * issued names that authority as issuer, and cannot name itself. */
bool acme_certificate_is_self_issued(X509 *cert);

/* Same question, asked of the leaf (first) certificate in a PEM file.
 * Returns false when the file is absent or unparsable — an unreadable file
 * is not evidence of anything, and the caller that cares is already
 * refusing it for a better reason. */
bool acme_certificate_file_is_self_issued(const char *pem_path);

/* Write a placeholder pair. The key is written first and 0600, the
 * certificate second and 0644, both through a temporary file and rename():
 * a reader that sees the certificate always finds the matching key beside
 * it, never the other way round. Overwrites whatever was at those paths. */
bool acme_selfsigned_write(const char *cert_path, const char *key_path,
                           const char *domain);

/* Write one only if a usable pair is not already there. "Usable" means both
 * files parse AND the key matches the certificate — a truncated write or a
 * half-copied datadir is replaced rather than served. Returns true when a
 * usable pair exists at those paths afterwards. */
bool acme_selfsigned_ensure(const char *cert_path, const char *key_path,
                            const char *domain);

#endif /* ZCL_NET_ACME_SELFSIGNED_H */
