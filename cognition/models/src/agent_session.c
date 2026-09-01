/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Agent session model (scoped agent spend-authority grant). One row per
 * minted session. before_validate only normalizes (trims strings, defaults
 * created_at); validate asserts the cap ranges — nothing is clamped, an
 * out-of-range cap is rejected, never silently narrowed. All writes go
 * through the AR lifecycle; all reads through AR_QUERY_* helpers. See
 * docs/work/agent-spend-policy-design.md. */

#include "platform/time_compat.h"
#include "util/log_macros.h"
#include "models/agent_session.h"
#include "models/model_text.h"
#include "config/runtime.h"
#include "json/json.h"
#include <pthread.h>
#include <string.h>

DEFINE_MODEL_CALLBACKS(agent_session)

/* before_validate: normalize only — trim the text fields and default
 * created_at. Caps are NOT clamped here; validate rejects out-of-range
 * values so a caller can never smuggle an over-cap policy past the CHECK. */
static bool agent_session_before_validate(void *record, void *ctx)
{
    struct db_agent_session *s = record;
    (void)ctx;
    if (!s)
        return false;
    model_trim_ascii(s->session_id);
    model_trim_ascii(s->account);
    model_trim_ascii(s->recipient_allowlist);
    model_trim_ascii(s->wallet_scope);
    model_trim_ascii(s->wallet_instance_id);
    model_trim_ascii(s->wallet_genesis);
    if (s->created_at == 0)
        s->created_at = (int64_t)platform_time_wall_time_t();
    return true;
}

DEFINE_MODEL_BEFORE_VALIDATE_READY(agent_session, agent_session_before_validate)

bool agent_session_validate(const struct db_agent_session *s,
                            struct ar_errors *errors)
{
    ar_errors_clear(errors);
    validates_string_present(errors, s->session_id, "session_id");
    validates_string_present(errors, s->account, "account");
    validates_custom(errors,
        zcl_is_hex_string(s->session_id, AGENT_SESSION_ID_MAX),
        "session_id", "is not a 32-char hex session id");
    validates_custom(errors,
        strlen(s->account) <= AGENT_SESSION_ACCOUNT_MAX,
        "account", "exceeds max length");
    validates_custom(errors,
        model_string_is_printable(s->account),
        "account", "contains non-printable characters");
    validates_money_range(errors, s, max_per_tx_zat, AGENT_SESSION_MAX_ZAT);
    validates_money_range(errors, s, max_per_window_zat, AGENT_SESSION_MAX_ZAT);
    validates_money_range(errors, s, reserve_floor_zat, AGENT_SESSION_MAX_ZAT);
    validates_positive(errors, s, window_seconds);
    validates_custom(errors,
        s->window_seconds <= AGENT_SESSION_WINDOW_SECONDS_MAX,
        "window_seconds", "exceeds the one-year window bound");
    validates_non_negative(errors, s, window_start_epoch);
    validates_money_range(errors, s, spent_in_window_zat, AGENT_SESSION_MAX_ZAT);
    validates_money_range(errors, s, lifetime_spent_zat,
                          AGENT_SESSION_MAX_ZAT);
    validates_custom(errors,
        strlen(s->recipient_allowlist) <= AGENT_SESSION_ALLOWLIST_MAX,
        "recipient_allowlist", "exceeds max length");
    validates_non_negative(errors, s, expires_at);
    validates_custom(errors, s->revoked == 0 || s->revoked == 1,
        "revoked", "is not 0 or 1");
    const bool unbound = s->wallet_scope[0] == '\0' &&
        s->wallet_instance_id[0] == '\0' && s->wallet_genesis[0] == '\0';
    const bool bound =
        (strcmp(s->wallet_scope, "dev") == 0 ||
         strcmp(s->wallet_scope, "prod") == 0) &&
        zcl_is_hex_string(s->wallet_instance_id,
                          WALLET_INSTANCE_ID_HEX_LEN) &&
        zcl_is_hex_string(s->wallet_genesis, WALLET_GENESIS_HEX_LEN);
    validates_custom(errors, unbound || bound, "wallet_binding",
                     "must be wholly empty or a complete dev/prod binding");
    return !ar_errors_any(errors);
}

bool agent_session_allowlisted(const char *csv, const char *recipient)
{
    if (!csv || !recipient || !recipient[0])
        return false; /* raw-return-ok:absent-recipient-is-a-negative-predicate */
    size_t want = strlen(recipient);
    const char *p = csv;
    while (*p) {
        const char *comma = strchr(p, ',');
        size_t len = comma ? (size_t)(comma - p) : strlen(p);
        if (len == want && memcmp(p, recipient, want) == 0)
            return true;
        if (!comma)
            break;
        p = comma + 1;
    }
    return false; /* raw-return-ok:not-listed-is-a-legitimate-negative-predicate */
}

bool agent_session_save(struct node_db *ndb, const struct db_agent_session *s)
{
    sqlite3_stmt *st = NULL;
    struct ar_callbacks *cbs;

    if (!ndb || !ndb->open || !s) {
        LOG_FAIL("model", "agent_session_save: bad args");
        return false;
    }
    cbs = agent_session_callbacks_ready();
    AR_ADHOC_SAVE(ndb, st,
        "INSERT OR REPLACE INTO agent_sessions "
        "(session_id,account,max_per_tx_zat,max_per_window_zat,"
        "window_seconds,window_start_epoch,spent_in_window_zat,"
        "recipient_allowlist,created_at,expires_at,revoked,wallet_scope,"
        "wallet_instance_id,wallet_genesis,lifetime_spent_zat,"
        "reserve_floor_zat) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        cbs, "agent_session", s, agent_session_validate,
        AR_BIND_TEXT(st, 1, s->session_id);
        AR_BIND_TEXT(st, 2, s->account);
        AR_BIND_INT(st, 3, s->max_per_tx_zat);
        AR_BIND_INT(st, 4, s->max_per_window_zat);
        AR_BIND_INT(st, 5, s->window_seconds);
        AR_BIND_INT(st, 6, s->window_start_epoch);
        AR_BIND_INT(st, 7, s->spent_in_window_zat);
        AR_BIND_TEXT(st, 8, s->recipient_allowlist);
        AR_BIND_INT(st, 9, s->created_at);
        AR_BIND_INT(st, 10, s->expires_at);
        AR_BIND_INT(st, 11, s->revoked);
        AR_BIND_TEXT(st, 12, s->wallet_scope);
        AR_BIND_TEXT(st, 13, s->wallet_instance_id);
        AR_BIND_TEXT(st, 14, s->wallet_genesis);
        AR_BIND_INT(st, 15, s->lifetime_spent_zat);
        AR_BIND_INT(st, 16, s->reserve_floor_zat));
}

static void agent_session_read_row(struct db_agent_session *out,
                                   sqlite3_stmt *st)
{
    AR_READ_STR(st, 0, out->session_id, sizeof(out->session_id));
    AR_READ_STR(st, 1, out->account, sizeof(out->account));
    out->max_per_tx_zat = AR_COL_INT(st, 2);
    out->max_per_window_zat = AR_COL_INT(st, 3);
    out->window_seconds = AR_COL_INT(st, 4);
    out->window_start_epoch = AR_COL_INT(st, 5);
    out->spent_in_window_zat = AR_COL_INT(st, 6);
    AR_READ_STR(st, 7, out->recipient_allowlist,
                sizeof(out->recipient_allowlist));
    out->created_at = AR_COL_INT(st, 8);
    out->expires_at = AR_COL_INT(st, 9);
    out->revoked = (int)AR_COL_INT(st, 10);
    AR_READ_STR(st, 11, out->wallet_scope, sizeof(out->wallet_scope));
    AR_READ_STR(st, 12, out->wallet_instance_id,
                sizeof(out->wallet_instance_id));
    AR_READ_STR(st, 13, out->wallet_genesis, sizeof(out->wallet_genesis));
    out->lifetime_spent_zat = AR_COL_INT(st, 14);
    out->reserve_floor_zat = AR_COL_INT(st, 15);
}

#define AGENT_SESSION_COLS \
    "session_id,account,max_per_tx_zat,max_per_window_zat,window_seconds," \
    "window_start_epoch,spent_in_window_zat,recipient_allowlist," \
    "created_at,expires_at,revoked,wallet_scope,wallet_instance_id," \
    "wallet_genesis,lifetime_spent_zat,reserve_floor_zat"

bool agent_session_find(struct node_db *ndb, const char *session_id,
                        struct db_agent_session *out)
{
    sqlite3_stmt *st = NULL;
    if (!ndb || !ndb->open || !session_id || !out) {
        LOG_FAIL("model", "agent_session_find: bad args");
        return false;
    }
    AR_QUERY_ONE_BOOL(ndb, st,
        "SELECT " AGENT_SESSION_COLS " FROM agent_sessions WHERE session_id=?",
        AR_BIND_TEXT(st, 1, session_id),
        agent_session_read_row(out, st));
}

int agent_session_list_for_account(struct node_db *ndb, const char *account,
                                   struct db_agent_session *out, size_t max)
{
    sqlite3_stmt *st = NULL;
    if (!ndb || !ndb->open || !account || !out || max == 0)
        return 0;
    AR_QUERY_LIST(ndb, st,
        "SELECT " AGENT_SESSION_COLS " FROM agent_sessions WHERE account=? "
        "ORDER BY created_at ASC LIMIT ?",
        out, max,
        AR_BIND_TEXT(st, 1, account);
        AR_BIND_INT(st, 2, (int64_t)max),
        agent_session_read_row(&out[count], st));
}

int agent_session_count(struct node_db *ndb)
{
    if (!ndb || !ndb->open)
        return 0;
    AR_QUERY_COUNT_SQL(ndb, "SELECT COUNT(*) FROM agent_sessions");
}

bool agent_session_revoke(struct node_db *ndb, const char *session_id)
{
    struct db_agent_session s;
    if (!ndb || !ndb->open || !session_id) {
        LOG_FAIL("model", "agent_session_revoke: bad args");
        return false;
    }
    if (!agent_session_find(ndb, session_id, &s))
        return false; /* raw-return-ok:session-not-found-is-a-normal-lookup-miss */
    if (s.revoked)
        return true; /* idempotent */
    s.revoked = 1;
    return agent_session_save(ndb, &s);
}

/* Write ONLY the two rolling-window columns, and only while the grant is
 * live. Never touches revoked/expires_at/the caps: the spend path has no
 * business restating authority it merely read. Zero rows changed (revoked in
 * the meantime, or the row is gone) is a refusal, not a silent success. */
static bool as_write_window(struct node_db *ndb, const char *session_id,
                            int64_t window_start, int64_t spent,
                            int64_t lifetime_spent)
{
    sqlite3_stmt *st = NULL;
    AR_EXEC_CHANGED_BOOL(ndb, st,
        "UPDATE agent_sessions SET window_start_epoch=?,"
        "spent_in_window_zat=?,lifetime_spent_zat=? "
        "WHERE session_id=? AND revoked=0",
        AR_BIND_INT(st, 1, window_start);
        AR_BIND_INT(st, 2, spent);
        AR_BIND_INT(st, 3, lifetime_spent);
        AR_BIND_TEXT(st, 4, session_id));
}

int64_t agent_session_scope_lifetime_spent(struct node_db *ndb,
                                           const char *wallet_scope)
{
    sqlite3_stmt *st = NULL;
    if (!ndb || !ndb->open || !wallet_scope || !wallet_scope[0])
        LOG_ERR("model", "agent_session_scope_lifetime_spent: bad args");
    AR_PREPARE_RET(ndb, st,
        "SELECT COALESCE(SUM(lifetime_spent_zat),0) FROM agent_sessions "
        "WHERE wallet_scope=?", -1);
    AR_BIND_TEXT(st, 1, wallet_scope);
    int64_t total = -1;
    if (AR_STEP_ROW(st))
        total = AR_COL_INT(st, 0);
    AR_FINALIZE(st);
    return total;
}

/* The single-writer boundary for the rolling window. Held across the read and
 * the write so a cap check and its debit are one indivisible step; see
 * agent_session_authorize in models/agent_session.h for why. */
static pthread_mutex_t g_agent_session_window_lock = PTHREAD_MUTEX_INITIALIZER;

static enum agent_session_authz agent_session_authorize_internal(
    struct node_db *ndb, const char *session_id, int64_t amount_zat,
    const char *recipient, const char *wallet_scope,
    const struct wallet_identity_row *current_wallet,
    int64_t now_epoch, bool commit, bool recipient_already_bound,
    int64_t *window_remaining_zat)
{
    if (window_remaining_zat)
        *window_remaining_zat = 0;
    if (!ndb || !ndb->open || !session_id || !session_id[0] ||
        amount_zat < 0 || amount_zat > AGENT_SESSION_MAX_ZAT) {
        LOG_RETURN(AGENT_SESSION_AUTHZ_STORE, "model",
                   "agent_session_authorize: bad args");
    }

    enum agent_session_authz verdict = AGENT_SESSION_AUTHZ_STORE;
    pthread_mutex_lock(&g_agent_session_window_lock);
    do {
        struct db_agent_session s;
        if (!agent_session_find(ndb, session_id, &s) || s.revoked ||
            (s.expires_at != 0 && now_epoch >= s.expires_at)) {
            verdict = AGENT_SESSION_AUTHZ_INVALID;
            break;
        }
        if (!s.wallet_scope[0] || !s.wallet_instance_id[0] ||
            !s.wallet_genesis[0]) {
            verdict = AGENT_SESSION_AUTHZ_WALLET_UNBOUND;
            break;
        }
        if (!wallet_scope || !wallet_scope[0] || !current_wallet) {
            verdict = AGENT_SESSION_AUTHZ_WALLET_MISMATCH;
            break;
        }
        char current_genesis[WALLET_GENESIS_HEX_LEN + 1];
        wallet_identity_genesis_hex(current_wallet, current_genesis);
        if (strcmp(s.wallet_scope, wallet_scope) != 0 ||
            strcmp(s.wallet_instance_id,
                   current_wallet->wallet_instance_id) != 0 ||
            strcmp(s.wallet_genesis, current_genesis) != 0) {
            verdict = AGENT_SESSION_AUTHZ_WALLET_MISMATCH;
            break;
        }
        if (amount_zat > s.max_per_tx_zat) {
            verdict = AGENT_SESSION_AUTHZ_TX_LIMIT;
            break;
        }
        /* Roll by SUBTRACTION so no window_seconds value can overflow the
         * comparison and disable the cap. */
        int64_t window_start = s.window_start_epoch;
        int64_t spent = s.spent_in_window_zat;
        if (window_start < 0 || now_epoch - window_start >= s.window_seconds) {
            window_start = now_epoch;
            spent = 0;
        }
        if (spent + amount_zat > s.max_per_window_zat) {
            verdict = AGENT_SESSION_AUTHZ_WINDOW_LIMIT;
            break;
        }
        if (!recipient_already_bound && s.recipient_allowlist[0] &&
            (!recipient || !recipient[0] ||
             !agent_session_allowlisted(s.recipient_allowlist, recipient))) {
            verdict = AGENT_SESSION_AUTHZ_RECIPIENT;
            break;
        }
        int64_t scope_lifetime =
            agent_session_scope_lifetime_spent(ndb, s.wallet_scope);
        if (scope_lifetime < 0 || scope_lifetime > AGENT_SESSION_MAX_ZAT - amount_zat) {
            verdict = AGENT_SESSION_AUTHZ_STORE;
            break;
        }
        /* The development-lab allocation is global across sessions and never
         * resets with a rate window. Fees are included in amount_zat by the
         * node-side service before this model is called. */
        if (strcmp(s.wallet_scope, "dev") == 0 &&
            scope_lifetime + amount_zat > 5000000) {
            verdict = AGENT_SESSION_AUTHZ_WINDOW_LIMIT;
            break;
        }
        if (commit &&
            !as_write_window(ndb, session_id, window_start,
                             spent + amount_zat,
                             s.lifetime_spent_zat + amount_zat)) {
            verdict = AGENT_SESSION_AUTHZ_STORE;
            break;
        }
        if (window_remaining_zat)
            *window_remaining_zat =
                s.max_per_window_zat - (spent + amount_zat);
        verdict = AGENT_SESSION_AUTHZ_OK;
    } while (0);
    pthread_mutex_unlock(&g_agent_session_window_lock);
    return verdict; /* raw-return-ok:enum-verdict-every-branch-set-above */
}

enum agent_session_authz agent_session_authorize(
    struct node_db *ndb, const char *session_id, int64_t amount_zat,
    const char *recipient, const char *wallet_scope,
    const struct wallet_identity_row *current_wallet,
    int64_t now_epoch, bool commit,
    int64_t *window_remaining_zat)
{
    return agent_session_authorize_internal(
        ndb, session_id, amount_zat, recipient, wallet_scope, current_wallet,
        now_epoch, commit, false, window_remaining_zat);
}

enum agent_session_authz agent_session_authorize_bound_intent(
    struct node_db *ndb, const char *session_id, int64_t amount_zat,
    const char *wallet_scope,
    const struct wallet_identity_row *current_wallet,
    int64_t now_epoch, bool commit,
    int64_t *window_remaining_zat)
{
    return agent_session_authorize_internal(
        ndb, session_id, amount_zat, NULL, wallet_scope, current_wallet,
        now_epoch, commit, true, window_remaining_zat);
}

bool agent_session_release(struct node_db *ndb, const char *session_id,
                           int64_t amount_zat, int64_t now_epoch)
{
    if (!ndb || !ndb->open || !session_id || !session_id[0] ||
        amount_zat < 0) {
        LOG_FAIL("model", "agent_session_release: bad args");
        return false;
    }
    bool ok = false;
    pthread_mutex_lock(&g_agent_session_window_lock);
    do {
        struct db_agent_session s;
        if (!agent_session_find(ndb, session_id, &s))
            break;
        /* Only the window this debit was taken from can be credited back. A
         * rolled window already forgot the debit, so releasing into the new
         * one would hand the session budget it never earned. */
        if (s.window_start_epoch < 0 ||
            now_epoch - s.window_start_epoch >= s.window_seconds) {
            ok = true;
            break;
        }
        int64_t spent = s.spent_in_window_zat - amount_zat;
        if (spent < 0)
            spent = 0;
        int64_t lifetime = s.lifetime_spent_zat - amount_zat;
        if (lifetime < 0)
            lifetime = 0;
        ok = as_write_window(ndb, session_id, s.window_start_epoch, spent,
                             lifetime);
    } while (0);
    pthread_mutex_unlock(&g_agent_session_window_lock);
    if (!ok)
        LOG_FAIL("model", "agent_session_release: could not credit back %lld "
                          "zat", (long long)amount_zat);
    return ok;
}

bool agent_session_is_usable(struct node_db *ndb, const char *session_id,
                             int64_t now_epoch)
{
    struct db_agent_session s;
    if (!ndb || !ndb->open || !session_id)
        return false;
    if (!agent_session_find(ndb, session_id, &s))
        return false; /* raw-return-ok:session-not-found-is-a-normal-lookup-miss */
    if (s.revoked)
        return false; /* raw-return-ok:revoked-is-a-legitimate-negative-predicate */
    if (s.expires_at != 0 && now_epoch >= s.expires_at)
        return false; /* raw-return-ok:expired-is-a-legitimate-negative-predicate */
    return true;
}

bool agent_session_dump_state_json(struct json_value *out, const char *key)
{
    struct node_db *ndb = app_runtime_node_db();
    if (key && key[0] != '\0') {
        /* Key form: a session_id — dump that one session's projection. */
        if (ndb && ndb->open) {
            struct db_agent_session s;
            bool found = agent_session_find(ndb, key, &s);
            json_push_kv_bool(out, "db_open", true);
            json_push_kv_bool(out, "found", found);
            if (found) {
                json_push_kv_str(out, "session_id", s.session_id);
                json_push_kv_str(out, "account", s.account);
                json_push_kv_int(out, "max_per_tx_zat", s.max_per_tx_zat);
                json_push_kv_int(out, "max_per_window_zat",
                                 s.max_per_window_zat);
                json_push_kv_int(out, "reserve_floor_zat",
                                 s.reserve_floor_zat);
                json_push_kv_int(out, "window_seconds", s.window_seconds);
                json_push_kv_int(out, "window_start_epoch",
                                 s.window_start_epoch);
                json_push_kv_int(out, "spent_in_window_zat",
                                 s.spent_in_window_zat);
                json_push_kv_int(out, "expires_at", s.expires_at);
                json_push_kv_bool(out, "revoked", s.revoked != 0);
                json_push_kv_str(out, "wallet_scope", s.wallet_scope);
                json_push_kv_str(out, "wallet_instance_id",
                                 s.wallet_instance_id);
                json_push_kv_bool(out, "wallet_bound",
                                  s.wallet_instance_id[0] != '\0');
                json_push_kv_int(out, "lifetime_spent_zat",
                                 s.lifetime_spent_zat);
            }
            return true;
        }
        json_push_kv_bool(out, "db_open", false);
        json_push_kv_bool(out, "found", false);
        return true;
    }
    json_push_kv_bool(out, "db_open", ndb && ndb->open);
    if (!ndb || !ndb->open) {
        json_push_kv_int(out, "count", 0);
        return true;
    }
    json_push_kv_int(out, "count", agent_session_count(ndb));
    return true;
}
