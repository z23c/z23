/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The one file the node and the certificate worker share.
 *
 * Issuance runs in a separate program (tools/acme) so the node never becomes
 * a TLS client and never learns to trust a certificate authority. But the CA
 * validates by connecting back to the node's own 443 listener, so the node
 * has to know one thing the worker computed: the key authorization for the
 * name under validation. That is this file, and it is the ENTIRE interface
 * between the two halves.
 *
 * Format, two lines, deliberately boring so an operator can read it:
 *
 *     domain=node.example.org
 *     keyauth=<token>.<base64url(account key thumbprint)>
 *
 * NOT A SECRET. The key authorization is derived from a challenge token the
 * CA published and the public thumbprint of the account key. Knowing it lets
 * someone answer a challenge only for a name they ALSO control the DNS and
 * port 443 of — at which point they did not need this file. It is written
 * 0600 anyway, because narrow is the right default and costs nothing.
 *
 * The worker writes it before telling the CA to validate, and clears it when
 * the order finishes either way. The node reads it lazily, only when a client
 * actually negotiates "acme-tls/1".
 */

#ifndef ZCL_NET_ACME_ARM_FILE_H
#define ZCL_NET_ACME_ARM_FILE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* The longest DNS name, and a challenge token plus a dot plus a 43-character
 * base64url thumbprint. Shared by both halves because both halves handle
 * these two exact strings and nothing else. */
#define ACME_MAX_DOMAIN     253
#define ACME_MAX_KEY_AUTHZ  512

/* Pure. Key authorization (RFC 8555 §8.1): "<token>.<base64url(thumbprint)>".
 * Refuses a token carrying anything outside the base64url alphabet — the
 * token comes from the CA and ends up inside a certificate the node signs
 * and presents. Lives beside the handoff file because it IS the value that
 * file carries: the worker computes it, the node consumes it. */
bool acme_key_authorization(const char *token, const uint8_t thumbprint[32],
                            char *out, size_t out_len);

/* Write the pair atomically (temporary file, then rename). */
bool acme_arm_file_write(const char *path, const char *domain,
                         const char *key_authz);

/* Read it back. Returns false when the file is absent, malformed, oversized,
 * or carries a byte outside the small alphabet these two fields may use —
 * this parses a file another process wrote, so it refuses rather than
 * repairs. */
bool acme_arm_file_read(const char *path, char *domain, size_t domain_len,
                        char *key_authz, size_t key_authz_len);

/* Remove it. Missing is success — this runs on the failure path too. */
bool acme_arm_file_clear(const char *path);

#endif /* ZCL_NET_ACME_ARM_FILE_H */
