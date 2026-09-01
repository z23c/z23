/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

/* See services/agent_session_service.h for the contract. One note on shape:
 * mint joins against principals(address) — node.db runs PRAGMA
 * foreign_keys=ON, so saving a session for a missing principal would fail at
 * the INSERT anyway; the explicit find turns that into a named refusal
 * (UNKNOWN_ACCOUNT) instead of a bare constraint error. */
// one-result-type-ok:session-lifecycle — the signatures mirror the model and
// policy layers they sit between (agent_session_save/agent_spend_policy_check:
// bool + a machine-readable `why` token the tests assert exactly); the vault
// handlers map the token onto the reply's named error, so the failure reason
// already travels with the failure.

#include "services/agent_session_service.h"

#include "base/hex.h"
#include "base/log_macros.h"
#include "base/safe_alloc.h"
#include "config/runtime.h"
#include "crypto/random_secret.h"
#include "models/database.h"
#include "models/principal.h"
#include "models/vault_intent.h"
#include "models/wallet_identity.h"
#include "services/vault_read.h"
#include "services/wallet_money_service.h"
#include "wallet/wallet.h"
#include "platform/time_compat.h"

#include <stdio.h>
#include <pthread.h>
#include <string.h>

#define ASS_TAG "agent_session_service"

/* Redraw bound on a session-id collision: a 128-bit hit is ~impossible, but
 * agent_session_save is an INSERT OR REPLACE upsert, so a hit would silently
 * overwrite the collided grant — redraw instead. */
#define ASS_MINT_DRAWS 4

/* Serializes the cross-row session-window + intent-debit transaction. The
 * lower agent-session model separately serializes ordinary window writes. */
static pthread_mutex_t g_ass_intent_lock = PTHREAD_MUTEX_INITIALIZER;

static void ass_why(char *why, size_t why_cap, const char *token)
{
    if (why && why_cap > 0)
        (void)snprintf(why, why_cap, "%s", token);
}

static bool ass_refuse(const char *token, const char *detail, char *why,
                       size_t why_cap)
{
    /* why is written BEFORE LOG_FAIL — the macro returns from the function,
     * so anything after it is dead code. */
    ass_why(why, why_cap, token);
    LOG_FAIL(ASS_TAG, "%s: %s", token, detail ? detail : "");
}

bool agent_session_service_mint(const struct agent_session_mint_request *req,
                                char out_session_id[AGENT_SESSION_ID_MAX + 1],
                                char *why, size_t why_cap)
{
    if (!req || !out_session_id || !req->account[0] ||
        req->max_per_tx_zat < 0 || req->max_per_tx_zat > AGENT_SESSION_MAX_ZAT ||
        req->max_per_window_zat < 0 ||
        req->max_per_window_zat > AGENT_SESSION_MAX_ZAT ||
        req->reserve_floor_zat < 0 ||
        req->reserve_floor_zat > AGENT_SESSION_MAX_ZAT ||
        req->window_seconds <= 0 || req->expires_in_seconds < 0 ||
        (strcmp(req->wallet_scope, "dev") != 0 &&
         strcmp(req->wallet_scope, "prod") != 0))
        return ass_refuse("BAD_ARGS", "mint request field missing or out of "
                                      "range", why, why_cap);

    struct node_db *ndb = app_runtime_node_db();
    if (!app_runtime_node_db_handle_open(ndb))
        return ass_refuse("DB_UNAVAILABLE",
                          "runtime node_db unavailable to mint a session",
                          why, why_cap);

    struct db_principal principal;
    if (!db_principal_find(ndb, req->account, &principal))
        return ass_refuse("UNKNOWN_ACCOUNT", req->account, why, why_cap);

    struct wallet_identity_row identity;
    if (!wallet_identity_find(ndb, &identity))
        return ass_refuse("WALLET_IDENTITY_UNKNOWN",
                          "the node has no persistent wallet identity",
                          why, why_cap);
    const char *expected_lane = strcmp(req->wallet_scope, "prod") == 0
        ? "canonical" : "dev";
    if (strcmp(identity.operator_lane, expected_lane) != 0)
        return ass_refuse("WALLET_SCOPE_MISMATCH",
                          "requested scope does not match this node's "
                          "operator lane", why, why_cap);
    char genesis[WALLET_GENESIS_HEX_LEN + 1];
    wallet_identity_genesis_hex(&identity, genesis);

    const int64_t now = (int64_t)platform_time_wall_time_t();
    for (int draw = 0; draw < ASS_MINT_DRAWS; draw++) {
        uint8_t raw[AGENT_SESSION_ID_MAX / 2];
        char sid[AGENT_SESSION_ID_MAX + 1];
        if (!zcl_random_secret_bytes(raw, sizeof(raw), "agent_session_id"))
            return ass_refuse("RNG_FAILED",
                              "could not draw a 128-bit session id",
                              why, why_cap);
        zcl_hex_encode(raw, sizeof(raw), sid);

        struct db_agent_session existing;
        if (agent_session_find(ndb, sid, &existing))
            continue; /* collision: redraw rather than upsert over a grant */

        struct db_agent_session s;
        memset(&s, 0, sizeof(s));
        snprintf(s.session_id, sizeof(s.session_id), "%s", sid);
        snprintf(s.account, sizeof(s.account), "%s", req->account);
        s.max_per_tx_zat = req->max_per_tx_zat;
        s.max_per_window_zat = req->max_per_window_zat;
        s.reserve_floor_zat = req->reserve_floor_zat;
        s.window_seconds = req->window_seconds;
        s.window_start_epoch = now;
        s.spent_in_window_zat = 0;
        snprintf(s.recipient_allowlist, sizeof(s.recipient_allowlist), "%s",
                 req->recipient_allowlist);
        s.created_at = now;
        s.expires_at =
            req->expires_in_seconds > 0 ? now + req->expires_in_seconds : 0;
        s.revoked = 0;
        snprintf(s.wallet_scope, sizeof(s.wallet_scope), "%s",
                 req->wallet_scope);
        snprintf(s.wallet_instance_id, sizeof(s.wallet_instance_id), "%s",
                 identity.wallet_instance_id);
        snprintf(s.wallet_genesis, sizeof(s.wallet_genesis), "%s", genesis);

        if (!agent_session_save(ndb, &s))
            return ass_refuse("PERSIST_FAILED",
                              "the agent_sessions save rejected the grant",
                              why, why_cap);
        memcpy(out_session_id, sid, sizeof(sid));
        return true;
    }
    return ass_refuse("RNG_FAILED",
                      "every drawn session id collided with a live grant",
                      why, why_cap);
}

int agent_session_service_list(const char *account,
                               struct db_agent_session *out, size_t max)
{
    if (!out || max == 0)
        LOG_ERR(ASS_TAG, "agent_session_service_list: bad args");
    if (max > AGENT_SESSION_LIST_MAX)
        max = AGENT_SESSION_LIST_MAX;

    struct node_db *ndb = app_runtime_node_db();
    if (!app_runtime_node_db_handle_open(ndb))
        LOG_ERR(ASS_TAG, "runtime node_db unavailable to list sessions");

    if (account && account[0])
        return agent_session_list_for_account(ndb, account, out, max);

    /* All accounts: walk the principal table and fold each account's page
     * into the caller's buffer until it fills. */
    struct db_principal *principals =
        zcl_malloc(sizeof(*principals) * AGENT_SESSION_LIST_MAX,
                   "agent_session_service_list principals");
    if (!principals)
        LOG_ERR(ASS_TAG, "could not allocate the principal page");
    int nprincipals = db_principal_list(ndb, principals, AGENT_SESSION_LIST_MAX);
    size_t used = 0;
    for (int i = 0; i < nprincipals && used < max; i++) {
        int n = agent_session_list_for_account(ndb, principals[i].address,
                                               out + used, max - used);
        if (n > 0)
            used += (size_t)n;
    }
    free(principals);
    return (int)used;
}

bool agent_session_service_revoke(const char *session_id,
                                  char *why, size_t why_cap)
{
    if (!session_id || !session_id[0])
        return ass_refuse("BAD_ARGS", "revoke requires the full session id",
                          why, why_cap);

    struct node_db *ndb = app_runtime_node_db();
    if (!app_runtime_node_db_handle_open(ndb))
        return ass_refuse("DB_UNAVAILABLE",
                          "runtime node_db unavailable to revoke a session",
                          why, why_cap);

    struct db_agent_session s;
    if (!agent_session_find(ndb, session_id, &s))
        return ass_refuse("SESSION_INVALID", "no session row for the "
                                             "presented id", why, why_cap);
    if (!agent_session_revoke(ndb, session_id))
        return ass_refuse("PERSIST_FAILED",
                          "the agent_sessions save could not mark the grant "
                          "revoked", why, why_cap);
    return true;
}

enum agent_session_authz agent_session_service_authorize(
    const char *session_id, int64_t amount_zat, const char *recipient,
    const char *wallet_scope, bool commit, bool canonical_plan,
    int64_t *window_remaining_zat, int64_t *charged_zat)
{
    if (charged_zat)
        *charged_zat = 0;
    struct node_db *ndb = app_runtime_node_db();
    if (!app_runtime_node_db_handle_open(ndb) ||
        (canonical_plan && commit))
        LOG_RETURN(AGENT_SESSION_AUTHZ_STORE, ASS_TAG,
                   "invalid runtime/canonical-plan authorization context");
    struct wallet_identity_row identity;
    if (!wallet_identity_find(ndb, &identity))
        LOG_RETURN(AGENT_SESSION_AUTHZ_WALLET_MISMATCH, ASS_TAG,
                   "wallet identity unavailable while authorizing spend");
    struct wallet *wallet = app_runtime_wallet();
    if (!wallet)
        LOG_RETURN(AGENT_SESSION_AUTHZ_STORE, ASS_TAG,
                   "runtime wallet unavailable while authorizing spend");
    int64_t max_fee_zat = wallet_default_fee(wallet);
    if (max_fee_zat < 0 || amount_zat > AGENT_SESSION_MAX_ZAT - max_fee_zat)
        LOG_RETURN(AGENT_SESSION_AUTHZ_STORE, ASS_TAG,
                   "wallet fee is invalid or overflows the requested value");
    int64_t charge_zat = amount_zat + max_fee_zat;

    struct vault_snapshot custody;
    struct zcl_result snapshot = vault_read_snapshot(ndb, &custody);
    if (!snapshot.ok)
        LOG_RETURN(AGENT_SESSION_AUTHZ_STORE, ASS_TAG,
                   "authoritative custody snapshot failed: %s",
                   snapshot.message);
    for (int i = 0; i < VAULT_CLASS_COUNT; i++) {
        if (custody.rows[i].is_money && !custody.rows[i].determined)
            LOG_RETURN(AGENT_SESSION_AUTHZ_STORE, ASS_TAG,
                       "money class %s is undetermined: %s",
                       custody.rows[i].class_name,
                       custody.rows[i].reason);
    }
    if (strcmp(wallet_scope, "dev") == 0) {
        struct wallet_money_snapshot money;
        struct zcl_result mr = wallet_money_snapshot_build(
            ndb, app_runtime_main_state(), wallet_scope, &money);
        if (!mr.ok || !money.complete ||
            strcmp(money.status, "CURRENT") != 0)
            LOG_RETURN(AGENT_SESSION_AUTHZ_STORE, ASS_TAG,
                       "development money snapshot is not current: %s",
                       mr.ok ? money.reason : mr.message);
        int64_t available = money.agent_available_zat;
        if (canonical_plan) {
            struct db_agent_session session;
            if (!agent_session_find(ndb, session_id, &session))
                LOG_RETURN(AGENT_SESSION_AUTHZ_INVALID, ASS_TAG,
                           "canonical plan grant is unavailable");
            available = wallet_money_agent_available_for_floor(
                &money, session.reserve_floor_zat);
        }
        if (charge_zat > available)
            LOG_RETURN(AGENT_SESSION_AUTHZ_WALLET_MISMATCH, ASS_TAG,
                       "development reserve or lab allocation would be exceeded");
    }

    enum agent_session_authz verdict = agent_session_authorize(
        ndb, session_id, charge_zat, recipient,
                                   wallet_scope, &identity,
                                   (int64_t)platform_time_wall_time_t(),
                                   commit, window_remaining_zat);
    if (verdict == AGENT_SESSION_AUTHZ_OK && charged_zat)
        *charged_zat = charge_zat;
    return verdict;
}

bool agent_session_service_release(const char *session_id, int64_t amount_zat)
{
    struct node_db *ndb = app_runtime_node_db();
    if (!app_runtime_node_db_handle_open(ndb))
        LOG_FAIL(ASS_TAG, "runtime node_db unavailable to release a debit");
    return agent_session_release(ndb, session_id, amount_zat,
                                 (int64_t)platform_time_wall_time_t());
}

static enum agent_session_authz ass_authorize_exact_intent(
    struct node_db *ndb, const struct vault_intent_row *row,
    const char *session_id, const char *recipient, bool commit,
    int64_t *window_remaining_zat)
{
    struct wallet_identity_row identity;
    if (!wallet_identity_find(ndb, &identity))
        return AGENT_SESSION_AUTHZ_WALLET_MISMATCH;
    if (!row || row->reserved_zat <= 0 ||
        row->reserved_zat != row->recipient_value_zat + row->max_fee_zat)
        return AGENT_SESSION_AUTHZ_STORE;
    if (commit)
        return agent_session_authorize_bound_intent(
            ndb, session_id, row->reserved_zat, row->wallet_scope,
            &identity, (int64_t)platform_time_wall_time_t(), true,
            window_remaining_zat);
    return agent_session_authorize(
        ndb, session_id, row->reserved_zat, recipient, row->wallet_scope,
        &identity, (int64_t)platform_time_wall_time_t(), false,
        window_remaining_zat);
}

bool agent_session_service_plan_intent(
    const char *session_id, const char *wallet_scope,
    int64_t reservation_zat, const char *const *recipients,
    size_t recipient_count, int64_t *reserve_floor_zat,
    char *why, size_t why_cap)
{
    if (reserve_floor_zat) *reserve_floor_zat = 0;
    struct node_db *ndb = app_runtime_node_db();
    if (!app_runtime_node_db_handle_open(ndb) || !session_id ||
        !session_id[0] || !wallet_scope || !wallet_scope[0] ||
        reservation_zat <= 0 || !recipients || recipient_count == 0)
        return ass_refuse("BAD_ARGS", "intent preflight requires grant, "
                          "scope, reservation, and recipients", why, why_cap);
    struct wallet_identity_row identity;
    if (!wallet_identity_find(ndb, &identity))
        return ass_refuse("POLICY_WALLET_MISMATCH",
                          "wallet identity is unavailable", why, why_cap);
    int64_t remaining = 0;
    for (size_t i = 0; i < recipient_count; i++) {
        if (!recipients[i] || !recipients[i][0])
            return ass_refuse("BAD_ARGS", "intent recipient is empty",
                              why, why_cap);
        enum agent_session_authz verdict = agent_session_authorize(
            ndb, session_id, i == 0 ? reservation_zat : 0,
            recipients[i], wallet_scope, &identity,
            (int64_t)platform_time_wall_time_t(), false, &remaining);
        if (verdict != AGENT_SESSION_AUTHZ_OK)
            return ass_refuse(agent_session_authz_token(verdict),
                              "grant refused canonical intent planning",
                              why, why_cap);
    }
    struct db_agent_session session;
    if (!agent_session_find(ndb, session_id, &session))
        return ass_refuse("SESSION_INVALID", "grant disappeared during "
                          "intent preflight", why, why_cap);
    if (reserve_floor_zat)
        *reserve_floor_zat = session.reserve_floor_zat;
    return true;
}

bool agent_session_service_bind_intent(
    const char *session_id, const uint8_t plan_id[32], const char *recipient,
    char *why, size_t why_cap)
{
    struct node_db *ndb = app_runtime_node_db();
    if (!app_runtime_node_db_handle_open(ndb) || !session_id || !plan_id ||
        !recipient || !recipient[0])
        return ass_refuse("BAD_ARGS", "intent binding requires grant, plan, "
                          "and reviewed recipient", why, why_cap);
    struct vault_intent_row row;
    if (!vault_intent_find(ndb, plan_id, &row) ||
        row.state != VAULT_INTENT_PLANNED)
        return ass_refuse("PLAN_NOT_BINDABLE", "intent is not a durable "
                          "planned row", why, why_cap);
    if (row.agent_session_id[0] &&
        strcmp(row.agent_session_id, session_id) != 0)
        return ass_refuse("POLICY_INTENT_SESSION", "intent is bound to a "
                          "different grant", why, why_cap);
    int64_t remaining = 0;
    enum agent_session_authz verdict = ass_authorize_exact_intent(
        ndb, &row, session_id, recipient, false, &remaining);
    if (verdict != AGENT_SESSION_AUTHZ_OK)
        return ass_refuse(agent_session_authz_token(verdict),
                          "grant refused the exact intent reservation",
                          why, why_cap);
    if (row.agent_session_id[0])
        return true;
    if (!vault_intent_bind_agent_session(
            ndb, plan_id, session_id,
            (int64_t)platform_time_wall_time_t()))
        return ass_refuse("PERSIST_FAILED", "intent grant binding was not "
                          "persisted", why, why_cap);
    return true;
}

bool agent_session_service_authorize_intent(
    const char *session_id, const uint8_t plan_id[32],
    bool *debit_managed, int64_t *charged_zat,
    char *why, size_t why_cap)
{
    if (debit_managed) *debit_managed = false;
    if (charged_zat) *charged_zat = 0;
    struct node_db *ndb = app_runtime_node_db();
    if (!app_runtime_node_db_handle_open(ndb) || !session_id || !plan_id)
        return ass_refuse("BAD_ARGS", "intent authorization requires grant "
                          "and plan", why, why_cap);

    bool ok = false;
    pthread_mutex_lock(&g_ass_intent_lock);
    do {
        struct vault_intent_row row;
        if (!vault_intent_find(ndb, plan_id, &row)) {
            ass_why(why, why_cap, "PLAN_NOT_FOUND");
            break;
        }
        if (!row.agent_session_id[0] ||
            strcmp(row.agent_session_id, session_id) != 0) {
            ass_why(why, why_cap, "POLICY_INTENT_SESSION");
            break;
        }
        if (row.state >= VAULT_INTENT_MEMPOOL_ACCEPTED &&
            row.state <= VAULT_INTENT_REORGED) {
            ok = true; /* exact transaction already owns the debit */
            break;
        }
        if (row.state != VAULT_INTENT_PLANNED &&
            row.state != VAULT_INTENT_PROVING) {
            ass_why(why, why_cap, "PLAN_NOT_COMMITTABLE");
            break;
        }
        if (debit_managed) *debit_managed = true;
        if (row.agent_debited_zat == row.reserved_zat) {
            ok = true; /* crash/retry resumes the existing debit */
            break;
        }
        if (row.agent_debited_zat != 0 || !node_db_begin_immediate(ndb)) {
            ass_why(why, why_cap, "POLICY_STORE");
            break;
        }
        int64_t remaining = 0;
        enum agent_session_authz verdict = ass_authorize_exact_intent(
            ndb, &row, session_id, NULL, true, &remaining);
        if (verdict != AGENT_SESSION_AUTHZ_OK ||
            !vault_intent_mark_agent_debited(
                ndb, plan_id, session_id, row.reserved_zat,
                (int64_t)platform_time_wall_time_t()) ||
            !node_db_commit(ndb)) {
            (void)node_db_rollback(ndb);
            ass_why(why, why_cap,
                    verdict == AGENT_SESSION_AUTHZ_OK
                        ? "POLICY_STORE" : agent_session_authz_token(verdict));
            break;
        }
        if (charged_zat) *charged_zat = row.reserved_zat;
        ok = true;
    } while (0);
    pthread_mutex_unlock(&g_ass_intent_lock);
    if (!ok)
        LOG_ERROR(ASS_TAG, "intent authorization refused: %s",
                  why && why[0] ? why : "POLICY_STORE");
    return ok;
}

static bool ass_release_intent(struct node_db *ndb, const char *session_id,
                               const uint8_t plan_id[32], bool bound_only)
{
    if (!ndb || !ndb->open || !plan_id || (!bound_only && !session_id))
        LOG_FAIL(ASS_TAG, "release intent: invalid argument");
    bool ok = false;
    pthread_mutex_lock(&g_ass_intent_lock);
    do {
        struct vault_intent_row row;
        if (!vault_intent_find(ndb, plan_id, &row))
            break;
        if (!row.agent_session_id[0]) {
            ok = bound_only;
            break;
        }
        if (!bound_only && strcmp(row.agent_session_id, session_id) != 0)
            break;
        if (row.agent_debited_zat == 0) {
            ok = true;
            break;
        }
        /* Once proving owns durable bytes, or the transaction reached the
         * network, recovery—not credit—is the only safe action. */
        if (row.state == VAULT_INTENT_PROVING ||
            (row.state >= VAULT_INTENT_MEMPOOL_ACCEPTED &&
             row.state <= VAULT_INTENT_REORGED)) {
            ok = true;
            break;
        }
        if (!node_db_begin_immediate(ndb))
            break;
        if (!agent_session_release(
                ndb, row.agent_session_id, row.agent_debited_zat,
                (int64_t)platform_time_wall_time_t()) ||
            !vault_intent_clear_agent_debit(
                ndb, plan_id, row.agent_session_id,
                (int64_t)platform_time_wall_time_t()) ||
            !node_db_commit(ndb)) {
            (void)node_db_rollback(ndb);
            break;
        }
        ok = true;
    } while (0);
    pthread_mutex_unlock(&g_ass_intent_lock);
    if (!ok)
        LOG_FAIL(ASS_TAG, "release intent: exact debit could not be released");
    return true;
}

bool agent_session_service_release_intent(
    const char *session_id, const uint8_t plan_id[32])
{
    struct node_db *ndb = app_runtime_node_db();
    if (!app_runtime_node_db_handle_open(ndb))
        LOG_FAIL(ASS_TAG, "release intent: runtime node_db unavailable");
    return ass_release_intent(ndb, session_id, plan_id, false);
}

bool agent_session_service_release_bound_intent(
    struct node_db *ndb, const uint8_t plan_id[32])
{
    return ass_release_intent(ndb, NULL, plan_id, true);
}

const char *agent_session_authz_token(enum agent_session_authz v)
{
    switch (v) {
    case AGENT_SESSION_AUTHZ_OK:            return "OK";
    case AGENT_SESSION_AUTHZ_INVALID:       return "SESSION_INVALID";
    case AGENT_SESSION_AUTHZ_TX_LIMIT:      return "POLICY_TX_LIMIT";
    case AGENT_SESSION_AUTHZ_WINDOW_LIMIT:  return "POLICY_WINDOW_LIMIT";
    case AGENT_SESSION_AUTHZ_RECIPIENT:     return "POLICY_RECIPIENT";
    case AGENT_SESSION_AUTHZ_WALLET_UNBOUND:return "POLICY_WALLET_UNBOUND";
    case AGENT_SESSION_AUTHZ_WALLET_MISMATCH:return "POLICY_WALLET_MISMATCH";
    case AGENT_SESSION_AUTHZ_STORE:         return "POLICY_STORE";
    }
    return "POLICY_STORE";
}

void agent_session_redact_id(const char *session_id, char *out,
                             size_t out_cap)
{
    if (!out || out_cap == 0)
        return;
    if (!session_id || !session_id[0]) {
        (void)snprintf(out, out_cap, "(none)");
        return;
    }
    /* 8 visible chars + U+2026 HORIZONTAL ELLIPSIS: enough to tell two
     * grants apart in a list, never enough to present. */
    (void)snprintf(out, out_cap, "%.8s\xe2\x80\xa6", session_id);
}
