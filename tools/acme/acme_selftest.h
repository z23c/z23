/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The certificate worker's own offline assertions.
 *
 * These cannot live in lib/test with the rest of the suite: the suite's
 * object tree is scanned by test_cold_join_sovereign P2, which asserts that
 * no Z23-authored object outside lib/test carries an undefined reference to
 * a TLS-client or CA-trust-store entry point. Compiling tls_client.c into
 * the test binary would put such an object under a scanned path and turn
 * that property red. So the assertions travel with the program they cover,
 * and lib/test/src/test_acme_worker.c RUNS this program and grades its
 * output — the coverage stays in the suite, the symbols do not.
 *
 * Each function returns the number of failed checks (0 = clean) and prints
 * one line per check.
 */

#ifndef ZCL_ACME_SELFTEST_H
#define ZCL_ACME_SELFTEST_H

#include <openssl/evp.h>
#include <openssl/x509.h>

#include <stdbool.h>

/* URL parsing, HTTP/1.1 response framing, the fail-closed transport
 * refusals, and a loopback server whose certificate chains to nothing. */
int acme_selftest_transport(void);

/* A throwaway self-signed certificate, shared by the two selftest units. */
bool acme_selftest_selfsigned(const char *cn, X509 **cert, EVP_PKEY **key);

/* base64url against RFC 4648, the RFC 7638 thumbprint, ES256 JWS verified
 * back with OpenSSL, the recorded ACME response fixtures, and the CSR. */
int acme_selftest_protocol(void);

#endif /* ZCL_ACME_SELFTEST_H */
