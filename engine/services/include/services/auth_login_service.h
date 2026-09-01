/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Auth login service: challenge/response public-key login for the multi-user
 * server. Issue mints a random single-use nonce and renders a domain-tagged
 * canonical message; verify rebuilds that exact message, recovers/verifies the
 * signer, constant-time matches the claimed address, atomically consumes the
 * nonce, upserts the principal, and mints a session (role -> caps/ceiling from
 * the single authz policy table). The signed message is hashed under the
 * "\x18ZClassic Signed Message:\n" magic so a login signature can never double
 * as a transaction pre-image. */

#ifndef ZCL_SERVICES_AUTH_LOGIN_SERVICE_H
#define ZCL_SERVICES_AUTH_LOGIN_SERVICE_H

#include "models/principal.h"
#include "models/auth_challenge.h"
#include "kernel/command_registry.h"
#include "util/result.h"

#include <stddef.h>
#include <stdint.h>

struct node_db;
struct uint256;

/* Compute the 32-byte hash a secp256k1 client signs for `message_body` — the
 * double-SHA256 over the domain-tagged pre-image (magic || compact_size ||
 * body). A client/test signs this with privkey_sign_compact; the server
 * recovers the signer from the same hash. Exposed so the two sides can never
 * disagree on the pre-image construction. Returns false on overflow. */
bool auth_login_signable_hash(const char *message_body, struct uint256 *out);

/* Default challenge lifetime. */
#define AUTH_CHALLENGE_TTL_SECONDS 300

/* The canonical message rendering has a bounded size. */
#define AUTH_MESSAGE_MAX 512

struct auth_challenge_issued {
    char nonce_hex[AUTH_CHALLENGE_NONCE_HEX_MAX + 1];
    char message[AUTH_MESSAGE_MAX];   /* the exact text the client must sign */
    int64_t issued_at;
    int64_t expires_at;
};

struct auth_session {
    char account[PRINCIPAL_ADDRESS_MAX + 1];   /* the principal address */
    enum principal_role role;
    uint64_t granted_capabilities;
    enum zcl_command_authority authority_ceiling;
    bool newly_registered;
};

/* Issue a login challenge for `address` on `server_id`. Generates a random
 * 32-byte nonce, persists it (expiry = now + AUTH_CHALLENGE_TTL_SECONDS), and
 * renders the canonical message into `out`. */
struct zcl_result auth_login_challenge(struct node_db *ndb,
                                       const char *server_id,
                                       const char *address,
                                       struct auth_challenge_issued *out);

/* Verify a signed challenge and mint a session.
 *   sig/sig_len : 65-byte compact recoverable ECDSA (secp256k1) OR 64-byte
 *                 raw ed25519 signature.
 *   pubkey_hex  : REQUIRED for ed25519 (recovery is impossible); ignored for
 *                 secp256k1 (the key is recovered from the signature).
 * On success: consumes the nonce (single-use), upserts/loads the principal,
 * stamps last_login, and fills `out`. Fails closed (generic message, no
 * unknown-address-vs-bad-signature timing distinction) on any mismatch. */
struct zcl_result auth_login_verify(struct node_db *ndb,
                                    const char *server_id,
                                    const char *address,
                                    const char *nonce_hex,
                                    const uint8_t *sig, size_t sig_len,
                                    const char *pubkey_hex,
                                    struct auth_session *out);

#endif
