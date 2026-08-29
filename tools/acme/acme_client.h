/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The ACME v2 (RFC 8555) order flow, over TLS-ALPN-01.
 *
 * THIS DOES NOT RUN IN THE NODE, AND MUST NOT. Talking to a certificate
 * authority means being a TLS client with a CA trust store, which means
 * being able to be told who to trust by whoever ships that trust store.
 * The node refuses that property outright — test_cold_join_sovereign P2
 * asserts that no Z23-authored object the node links carries an undefined
 * reference to any TLS-client or trust-store entry point — so issuance
 * lives in a separate program (tools/acme, `zclassic23-acme`), the same way
 * package verification lives in `zclassic23-package-verify`.
 *
 * That is the right place for the trust boundary, not a compromise. A public
 * CA is only ever consulted for the OPTIONAL clearnet convenience surface:
 * the small HTTPS front door that serves the install script to a stranger
 * with a browser. The sovereign paths — onion service, peer-to-peer,
 * consensus validation — never touch a CA at all, and this program has no
 * way to reach them: it reads no chain state, opens no datadir, and writes
 * exactly two files plus one handoff line.
 *
 * One call runs the whole conversation: fetch the directory, take a nonce,
 * register (or re-find) the account, open an order for the domain, hand the
 * node the key authorization for the tls-alpn-01 challenge, finalize with a
 * CSR, and write the issued chain and its key to disk. The node then loads
 * those two files exactly as it loads any other certificate — which is all
 * it ever knew how to do.
 *
 * PRECONDITION, and it is the one that actually bites: the node's HTTPS
 * listener must already be serving on the port the domain's 443 reaches,
 * with acme_alpn_install() called on its SSL_CTX and its handoff file set to
 * the same path as `handoff_path` below. The CA validates by connecting back
 * to 443 — if nothing is listening, or the two halves disagree about the
 * handoff path, every order fails validation with a message about the
 * connection rather than about this client.
 *
 * The flow is synchronous and bounded: every request carries a deadline and
 * every poll loop has a fixed attempt count.
 */

#ifndef ZCL_ACME_CLIENT_H
#define ZCL_ACME_CLIENT_H

#include <stdbool.h>

#define ACME_DIRECTORY_LETSENCRYPT \
    "https://acme-v02.api.letsencrypt.org/directory"
#define ACME_DIRECTORY_LETSENCRYPT_STAGING \
    "https://acme-staging-v02.api.letsencrypt.org/directory"

struct acme_client_config {
    /* NULL selects the Let's Encrypt production directory. Point this at the
     * staging directory for anything that is not a real deployment: staging
     * issues untrusted certificates but has far looser rate limits, and a
     * rate-limited production account is a week-long outage. */
    const char *directory_url;

    const char *domain;             /* the single name to issue for */
    const char *account_key_path;   /* EC P-256 PEM; created on first run */
    const char *cert_path;          /* full chain, PEM, leaf first */
    const char *cert_key_path;      /* the issued certificate's private key */
    const char *contact_email;      /* optional; "" and NULL both mean none */

    /* The one channel to the node: net/acme_arm_file.h. The node must be
     * configured with the SAME path, or its responder has nothing to
     * present and every validation fails. */
    const char *handoff_path;

    int  timeout_ms;                /* per request; <= 0 selects the default */
    int  poll_attempts;             /* <= 0 selects the default */
    int  poll_interval_ms;          /* <= 0 selects the default */

    /* RFC 8555 §7.3.1: an account cannot be created without agreeing to the
     * CA's terms. There is no default for this — an operator says so. */
    bool agree_terms_of_service;
};

/* Run the whole order. Returns true only when a chain was issued AND written
 * to cfg->cert_path with its key at cfg->cert_key_path. Any failure leaves
 * the existing files untouched: a half-renewed certificate pair is worse
 * than an old one. */
bool acme_client_obtain(const struct acme_client_config *cfg);

#endif /* ZCL_ACME_CLIENT_H */
