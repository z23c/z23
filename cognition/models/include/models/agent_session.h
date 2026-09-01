/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Agent session: a scoped, revocable spend-authority grant minted by the
 * local operator for an AI agent. One row per session grant, bound to a
 * principal (`account`); the session carries its own cap set (per-tx limit,
 * rolling-window limit, recipient allowlist) so one principal can run
 * low-limit routine sessions and high-limit operator sessions side by side.
 * Policies deliberately do NOT live on the principal row — principal.c
 * recomputes caps from role on every save. App-layer policy only: never
 * consulted by consensus. See docs/work/agent-spend-policy-design.md. */

#ifndef ZCL_DB_MODEL_AGENT_SESSION_H
#define ZCL_DB_MODEL_AGENT_SESSION_H

#include "models/database.h"
#include "models/activerecord.h"
#include "models/wallet_identity.h"
#include <stdbool.h>
#include <stdint.h>

enum {
    AGENT_SESSION_ID_MAX = 32,        /* 128-bit random, hex */
    AGENT_SESSION_ACCOUNT_MAX = 95,   /* transparent t-addr fits under this */
    AGENT_SESSION_ALLOWLIST_MAX = 1023, /* CSV of t-/zs-addresses */
};

/* Upper bound on window_seconds. Without one, `window_start + window_seconds`
 * overflows int64 for a large value, the roll comparison then reads as "the
 * window already elapsed" on every check, and the rolling cap silently stops
 * existing. A year is longer than any plausible agent grant, and the roll is
 * computed as a subtraction (`now - window_start >= window_seconds`) so it
 * stays overflow-free even for the largest accepted value. Enforced in
 * agent_session_validate, at the mint surface, and by the table CHECK. */
#define AGENT_SESSION_WINDOW_SECONDS_MAX 31536000LL

/* Spend caps are zatoshis in [0, MAX_MONEY]; MAX_MONEY (21M ZCL) doubles as
 * "unbounded" — both limits are mandatory, no NULL/0-disable sentinel. */
#define AGENT_SESSION_MAX_ZAT 2100000000000000LL
#define AGENT_SESSION_DEV_RESERVE_DEFAULT_ZAT 25000000LL

struct db_agent_session {
    char session_id[AGENT_SESSION_ID_MAX + 1];       /* PRIMARY KEY (hex) */
    char account[AGENT_SESSION_ACCOUNT_MAX + 1];     /* FK principals(address) */
    int64_t max_per_tx_zat;
    int64_t max_per_window_zat;
    /* Owner-reviewed dev-wallet balance that this grant may never reserve
     * below. Defaults to the historical 0.25-ZCL lab floor. */
    int64_t reserve_floor_zat;
    int64_t window_seconds;                          /* > 0 */
    int64_t window_start_epoch;                      /* rolling window anchor */
    int64_t spent_in_window_zat;                     /* accumulated in window */
    char recipient_allowlist[AGENT_SESSION_ALLOWLIST_MAX + 1]; /* "" = any */
    int64_t created_at;
    int64_t expires_at;                              /* 0 = never */
    int revoked;                                     /* 0/1 */
    /* Empty only on pre-v52 rows. Those rows remain readable and revocable,
     * but no money authorization may infer a wallet for them. */
    char wallet_scope[5];                            /* "dev" | "prod" */
    char wallet_instance_id[WALLET_INSTANCE_ID_HEX_LEN + 1];
    char wallet_genesis[WALLET_GENESIS_HEX_LEN + 1];
    int64_t lifetime_spent_zat;                       /* never window-reset */
};

/* Lazily-initialized callback registry (before_validate hook). */
struct ar_callbacks *db_agent_session_callbacks(void);

/* Populate errors with any validation failures. Returns true iff s is valid:
 * session_id exactly 32 hex chars; account present/printable/within bounds;
 * both caps, reserve_floor_zat and spent_in_window_zat within
 * [0, AGENT_SESSION_MAX_ZAT];
 * window_seconds > 0; expires_at non-negative; revoked in {0,1}. */
bool agent_session_validate(const struct db_agent_session *s,
                            struct ar_errors *errors);

/* True iff `recipient` is an exact comma-separated token of the allowlist CSV.
 * Exact-token, never substring: a prefix of a listed address is a DIFFERENT
 * address, and matching it would let a near-miss recipient be paid. */
bool agent_session_allowlisted(const char *csv, const char *recipient);

/* Upsert s. before_validate normalizes (trims strings, defaults created_at),
 * then validate + INSERT OR REPLACE via the AR lifecycle. Returns false on
 * bad args/veto/validation/DB. */
bool agent_session_save(struct node_db *ndb, const struct db_agent_session *s);

/* SELECT by primary-key session_id. Returns true and fills out on hit. */
bool agent_session_find(struct node_db *ndb, const char *session_id,
                        struct db_agent_session *out);

/* Load up to max sessions for `account` ordered by created_at ascending.
 * Returns count. */
int agent_session_list_for_account(struct node_db *ndb, const char *account,
                                   struct db_agent_session *out, size_t max);

/* Total session count. */
int agent_session_count(struct node_db *ndb);

/* Mark the session revoked (idempotent). Returns false when the session does
 * not exist or the save fails. */
bool agent_session_revoke(struct node_db *ndb, const char *session_id);

/* Outcome of agent_session_authorize — one enum so the caller renders the
 * refusal instead of guessing it from a bool. */
enum agent_session_authz {
    AGENT_SESSION_AUTHZ_OK = 0,
    AGENT_SESSION_AUTHZ_INVALID,       /* missing, revoked, or expired */
    AGENT_SESSION_AUTHZ_TX_LIMIT,      /* over max_per_tx_zat */
    AGENT_SESSION_AUTHZ_WINDOW_LIMIT,  /* over max_per_window_zat */
    AGENT_SESSION_AUTHZ_RECIPIENT,     /* not on a non-empty allowlist */
    AGENT_SESSION_AUTHZ_WALLET_UNBOUND,/* legacy session has no binding */
    AGENT_SESSION_AUTHZ_WALLET_MISMATCH,/* requested/current wallet differs */
    AGENT_SESSION_AUTHZ_STORE,         /* bad args or the store rejected it */
};

/* Check one spend against the session's caps and, when `commit`, debit the
 * rolling window — CHECK AND DEBIT IN ONE STEP.
 *
 * The whole operation is serialized on a process-local mutex and the debit is
 * a targeted UPDATE of only the two window columns, guarded by `revoked=0`.
 * Both properties are load-bearing:
 *   - a check that read `spent`, returned, and let a second caller read the
 *     same `spent` before either wrote let N concurrent invocations each pass
 *     a cap they jointly blew through;
 *   - a debit that rewrote the whole row (INSERT OR REPLACE) put `revoked`
 *     back to whatever it read, so a revocation landing between the read and
 *     the write was silently undone — losing the emergency lever to a routine
 *     spend. Nothing outside the grant surface may write an authority column.
 * The node process is the only writer of this table (every other process
 * reaches it over the `agentsession` RPC), so one process-local mutex is the
 * single-writer boundary.
 *
 * `recipient` may be NULL; a non-empty allowlist then refuses. The window
 * rolls when `now_epoch - window_start_epoch >= window_seconds` (subtraction,
 * never a sum — see AGENT_SESSION_WINDOW_SECONDS_MAX). `window_remaining_zat`
 * is optional and is filled on OK with what is left after this authorization.
 * `commit=false` evaluates without writing anything. */
enum agent_session_authz agent_session_authorize(
    struct node_db *ndb, const char *session_id, int64_t amount_zat,
    const char *recipient, const char *wallet_scope,
    const struct wallet_identity_row *current_wallet,
    int64_t now_epoch, bool commit,
    int64_t *window_remaining_zat);

/* Same cap/window/identity check after a canonical vault intent has already
 * persisted this exact session binding and validated its one reviewed
 * recipient. This is node-internal commit recovery only; it deliberately does
 * not re-read a plaintext recipient from the encrypted plan. */
enum agent_session_authz agent_session_authorize_bound_intent(
    struct node_db *ndb, const char *session_id, int64_t amount_zat,
    const char *wallet_scope,
    const struct wallet_identity_row *current_wallet,
    int64_t now_epoch, bool commit,
    int64_t *window_remaining_zat);

/* Give a debit back: the spend it paid for never happened (a plan-only
 * preview, a handler that failed, a broadcast that never went out). Subtracts
 * from the current window only — clamped at zero, and only while the window
 * anchor still matches, so a release can never manufacture headroom in a
 * window it did not spend in. Guarded by `revoked=0` like the debit. */
bool agent_session_release(struct node_db *ndb, const char *session_id,
                           int64_t amount_zat, int64_t now_epoch);

/* True iff the session exists, is not revoked, and is not expired at
 * now_epoch (expires_at == 0 never expires). */
bool agent_session_is_usable(struct node_db *ndb, const char *session_id,
                             int64_t now_epoch);

/* Sum the durable lifetime allocation for one wallet scope. Returns -1 when
 * the store is unavailable; zero is a real known zero. */
int64_t agent_session_scope_lifetime_spent(struct node_db *ndb,
                                           const char *wallet_scope);

/* Bounded JSON dump for `dumpstate agent_sessions` (count + per-session
 * projection; recipient allowlist echoed, no secret material exists). */
struct json_value;
bool agent_session_dump_state_json(struct json_value *out, const char *key);

#endif
