/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

/* Agent session service — the minting half of
 * docs/work/agent-spend-policy-design.md ("Minting + presentation"). Owns the
 * workflow around the agent_sessions model (models/agent_session.h): minting
 * a scoped spend-authority grant for an existing principal, listing grants,
 * and revoking a grant by its full session id. The vault session leaves
 * (tools/command/native_vault_session_command.c) are thin handlers over this
 * service; the enforcement half lives in services/agent_spend_policy.h.
 *
 * Token hygiene: a session_id is a bearer grant. It crosses the service
 * boundary in full exactly once — out of mint — and is never echoed back
 * afterwards: list renders it redacted (first 8 chars + "…") and revoke
 * requires the caller to present it. */

#ifndef ZCL_SERVICES_AGENT_SESSION_SERVICE_H
#define ZCL_SERVICES_AGENT_SESSION_SERVICE_H

#include "models/agent_session.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* What the minting operator asked for, already normalized by the handler:
 * caps are zatoshis (the handler parses the ZCL-decimal inputs) and
 * expires_in_seconds is a TTL from mint time (0 = never expires). */
struct agent_session_mint_request {
    char account[AGENT_SESSION_ACCOUNT_MAX + 1];   /* principals.address */
    int64_t max_per_tx_zat;                        /* [0, MAX_ZAT] */
    int64_t max_per_window_zat;                    /* [0, MAX_ZAT] */
    int64_t reserve_floor_zat;                     /* dev custody floor */
    int64_t window_seconds;                        /* > 0 */
    char recipient_allowlist[AGENT_SESSION_ALLOWLIST_MAX + 1]; /* "" = any */
    int64_t expires_in_seconds;                    /* 0 = never */
    char wallet_scope[5];                          /* required dev|prod */
};

/* Refusal tokens written to `why` (handlers map them onto named errors;
 * tests assert these exactly):
 *   BAD_ARGS         — a required field is NULL/empty or out of range
 *   DB_UNAVAILABLE   — the runtime node_db is not open
 *   UNKNOWN_ACCOUNT  — no principal row for req->account
 *   RNG_FAILED       — the 128-bit session id could not be drawn uniquely
 *   PERSIST_FAILED   — the AR save rejected or failed
 *   SESSION_INVALID  — (revoke) no session row for the presented id */

/* Mint one session grant. Verifies req->account names an existing principal,
 * draws a 128-bit random session id rendered as 32 lowercase hex chars,
 * fills the defaults (window accounting zeroed and anchored at now,
 * created_at=now, expires_at=now+expires_in_seconds or 0, revoked=0) and
 * persists through agent_session_save. On success out_session_id carries the
 * id — the ONE time the full token is returned. Returns false with a token
 * from the list above in `why`; every refusal is LOG_FAIL'd with context. */
bool agent_session_service_mint(const struct agent_session_mint_request *req,
                                char out_session_id[AGENT_SESSION_ID_MAX + 1],
                                char *why, size_t why_cap);

/* Page cap for one list call. */
#define AGENT_SESSION_LIST_MAX 64

/* Load up to AGENT_SESSION_LIST_MAX sessions: for `account` when it is
 * non-empty, across every principal's account otherwise. Returns the row
 * count (rows carry the FULL session id — redaction is the presentation
 * layer's job, see agent_session_redact_id), or -1 when the runtime node_db
 * is unavailable (LOG_ERR'd with context). */
int agent_session_service_list(const char *account,
                               struct db_agent_session *out, size_t max);

/* Revoke the grant named by the full session_id. Returns false with a token
 * from the list above in `why` (SESSION_INVALID when no such session exists,
 * PERSIST_FAILED when the save fails); idempotent on an already-revoked
 * session. */
bool agent_session_service_revoke(const char *session_id,
                                  char *why, size_t why_cap);

/* Authorize one spend against the grant, and debit the rolling window when
 * `commit`. Thin wrapper over agent_session_authorize on the runtime node_db —
 * so it runs ONLY in the process that owns node.db (the node). Every other
 * process reaches this through the `agentsession` RPC
 * (controllers/agent_session_client.h), which is why the check and the debit
 * are one call rather than a check the caller follows with a write: a
 * round-trip in between would be exactly the race the model's mutex exists to
 * prevent. Returns AGENT_SESSION_AUTHZ_STORE when node_db is unavailable. */
enum agent_session_authz agent_session_service_authorize(
    const char *session_id, int64_t amount_zat, const char *recipient,
    const char *wallet_scope, bool commit, bool canonical_plan,
    int64_t *window_remaining_zat, int64_t *charged_zat);

/* Credit a debit back (the spend it paid for never happened). Node-side, same
 * runtime-node_db constraint as authorize. */
bool agent_session_service_release(const char *session_id, int64_t amount_zat);

/* Bind and enforce a bounded grant on the canonical durable intent path.
 * `recipient` is the one reviewed effect accepted by the bounded CLI surface;
 * the row supplies the exact recipient total, maximum fee, wallet identity and
 * scope. authorize_intent persists a once-only debit before commit/submit and
 * reports whether a pre-broadcast handler failure should call release_intent. */
bool agent_session_service_bind_intent(
    const char *session_id, const uint8_t plan_id[32], const char *recipient,
    char *why, size_t why_cap);

/* Node-side plan preflight for a canonical intent. Checks the exact total
 * (recipient value plus maximum fee), every recipient, wallet binding,
 * expiry, and grant caps without debiting. Returns the owner-reviewed dev
 * reserve floor that the atomic reservation must enforce. */
bool agent_session_service_plan_intent(
    const char *session_id, const char *wallet_scope,
    int64_t reservation_zat, const char *const *recipients,
    size_t recipient_count, int64_t *reserve_floor_zat,
    char *why, size_t why_cap);
bool agent_session_service_authorize_intent(
    const char *session_id, const uint8_t plan_id[32],
    bool *debit_managed, int64_t *charged_zat,
    char *why, size_t why_cap);
bool agent_session_service_release_intent(
    const char *session_id, const uint8_t plan_id[32]);

/* Node-internal crash/async settlement. Loads the bearer binding from the
 * durable intent row and credits it only while the row proves no signed or
 * broadcast transaction can exist. The token never crosses an RPC or CLI
 * boundary. A row with no bounded-session debit is an idempotent no-op. */
bool agent_session_service_release_bound_intent(
    struct node_db *ndb, const uint8_t plan_id[32]);

/* Render a session id for display: exactly the first 8 chars + "…" — the
 * only form in which a token may appear after mint. */
void agent_session_redact_id(const char *session_id, char *out,
                             size_t out_cap);

/* Machine-readable name for an authorization verdict. These are the tokens
 * the dispatch gates put in `error.code`, so they are part of the CLI
 * contract; tests assert them exactly. */
const char *agent_session_authz_token(enum agent_session_authz v);

#endif
