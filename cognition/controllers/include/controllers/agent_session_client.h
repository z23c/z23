/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Agent-session client — how a process that does NOT own node.db reaches the
 * agent_sessions store: over the node's `agentsession` RPC
 * (controllers/agent_session_controller.h).
 *
 * Every caller of this header is in the CLI process: the two dispatch policy
 * gates and the vault.session.* leaves. None of them has an open node.db, and
 * the node must remain the single writer of this table, so the store is
 * reached the same way every spend already is — one loopback RPC. That also
 * means a bounded agent's spend cannot be authorized while the node is down,
 * which is the correct posture: the spend itself could not happen either.
 *
 * Fail-closed: any transport failure, any malformed answer, any refusal
 * returns false with a machine token in `why`. There is no "assume allowed"
 * branch anywhere below. */

#ifndef ZCL_CONTROLLERS_AGENT_SESSION_CLIENT_H
#define ZCL_CONTROLLERS_AGENT_SESSION_CLIENT_H

#include "models/agent_session.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* `why` tokens: the service/model vocabulary (SESSION_INVALID,
 * POLICY_TX_LIMIT, POLICY_WINDOW_LIMIT, POLICY_RECIPIENT, POLICY_STORE,
 * BAD_ARGS, UNKNOWN_ACCOUNT, RNG_FAILED, PERSIST_FAILED, DB_UNAVAILABLE)
 * plus NODE_UNREACHABLE when the RPC itself did not complete. */

/* Mint a grant. Fields are already normalized zatoshi/second integers.
 * out_session_id receives the full token on success. */
bool agent_session_client_mint(const char *account, int64_t max_per_tx_zat,
                               int64_t max_per_window_zat,
                               int64_t reserve_floor_zat,
                               int64_t window_seconds,
                               const char *recipient_allowlist,
                               int64_t expires_in_seconds,
                               const char *wallet_scope,
                               char out_session_id[AGENT_SESSION_ID_MAX + 1],
                               char *why, size_t why_cap);

/* Load up to `max` grants (for `account`, or all when NULL/empty). Returns the
 * row count, or -1 with a `why` token. Rows carry the FULL session id;
 * redaction is the presentation layer's job. */
int agent_session_client_list(const char *account,
                              struct db_agent_session *out, size_t max,
                              char *why, size_t why_cap);

/* Revoke by full token. */
bool agent_session_client_revoke(const char *session_id, char *why,
                                 size_t why_cap);

/* Authorize one spend and, when `commit`, debit the rolling window — one
 * round trip, because the node performs the check and the debit as a single
 * indivisible step (see agent_session_authorize). `window_remaining_zat` is
 * optional. */
bool agent_session_client_authorize(const char *session_id, int64_t amount_zat,
                                    const char *recipient,
                                    const char *wallet_scope, bool commit,
                                    bool canonical_plan,
                                    int64_t *window_remaining_zat,
                                    int64_t *charged_zat,
                                    char *why, size_t why_cap);

/* Credit a debit back after the spend it paid for did not happen. */
bool agent_session_client_release(const char *session_id, int64_t amount_zat);

/* Canonical durable-intent grant lifecycle. plan_id is display-order 64-hex;
 * no helper ever returns or logs the bearer session id. */
bool agent_session_client_bind_intent(
    const char *session_id, const char *plan_id, const char *recipient,
    char *why, size_t why_cap);
bool agent_session_client_authorize_intent(
    const char *session_id, const char *plan_id,
    bool *debit_managed, int64_t *charged_zat,
    char *why, size_t why_cap);
bool agent_session_client_release_intent(
    const char *session_id, const char *plan_id);

#endif
