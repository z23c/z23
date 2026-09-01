/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Auth-challenge model (single-use login nonce). See auth_challenge.h. The
 * consume is one atomic UPDATE guarded by sqlite3_changes(), so a nonce can be
 * spent at most once. All writes go through the AR lifecycle. */

#include "util/log_macros.h"
#include "models/auth_challenge.h"
#include "models/query_builder.h"
#include "config/runtime.h"
#include "json/json.h"
#include <string.h>

DEFINE_MODEL_CALLBACKS(auth_challenge)

static bool auth_challenge_is_hex(const char *s)
{
    if (!s || !s[0])
        return false;
    for (const char *p = s; *p; p++) {
        char c = *p;
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
              (c >= 'A' && c <= 'F')))
            return false;
    }
    return true;
}

bool db_auth_challenge_validate(const struct db_auth_challenge *c,
                                struct ar_errors *errors)
{
    ar_errors_clear(errors);
    validates_string_present(errors, c->nonce_hex, "nonce_hex");
    validates_string_present(errors, c->address, "address");
    validates_custom(errors, auth_challenge_is_hex(c->nonce_hex),
        "nonce_hex", "is not a hex string");
    validates_custom(errors, strlen(c->nonce_hex) <= AUTH_CHALLENGE_NONCE_HEX_MAX,
        "nonce_hex", "exceeds max length");
    validates_custom(errors, strlen(c->address) <= AUTH_CHALLENGE_ADDRESS_MAX,
        "address", "exceeds max length");
    validates_non_negative(errors, c, issued_at);
    validates_custom(errors, c->expires_at > c->issued_at,
        "expires_at", "must be after issued_at");
    return !ar_errors_any(errors);
}

bool db_auth_challenge_save(struct node_db *ndb,
                            const struct db_auth_challenge *c)
{
    struct ar_callbacks *cbs;
    if (!ndb || !ndb->open || !c) {
        LOG_FAIL("model", "db_auth_challenge_save: bad args");
        return false;
    }
    cbs = db_auth_challenge_callbacks();
    struct qb q;
    qb_insert(&q, QB_T_auth_challenges, QB_INSERT_OR_REPLACE);
    qb_value_text(&q, QB_C_auth_challenges_nonce_hex, c->nonce_hex);
    qb_value_text(&q, QB_C_auth_challenges_address, c->address);
    qb_value_int(&q, QB_C_auth_challenges_issued_at, c->issued_at);
    qb_value_int(&q, QB_C_auth_challenges_expires_at, c->expires_at);
    qb_value_int(&q, QB_C_auth_challenges_consumed, c->consumed ? 1 : 0);
    /* ar-lifecycle-ok:qb-adhoc-save-expands-to-AR_BEGIN_SAVE-and-AR_FINISH_SAVE */
    QB_ADHOC_SAVE(ndb, &q, s, cbs, "auth_challenge", c,
                  db_auth_challenge_validate);
}

bool db_auth_challenge_find(struct node_db *ndb, const char *nonce_hex,
                            struct db_auth_challenge *out)
{
    if (!ndb || !ndb->open || !nonce_hex || !out) {
        LOG_FAIL("model", "db_auth_challenge_find: bad args");
        return false;
    }
    struct qb q;
    qb_select(&q, QB_T_auth_challenges);
    qb_select_column(&q, QB_C_auth_challenges_nonce_hex);
    qb_select_column(&q, QB_C_auth_challenges_address);
    qb_select_column(&q, QB_C_auth_challenges_issued_at);
    qb_select_column(&q, QB_C_auth_challenges_expires_at);
    qb_select_column(&q, QB_C_auth_challenges_consumed);
    qb_where_text(&q, QB_C_auth_challenges_nonce_hex, QB_EQ, nonce_hex);
    QB_QUERY_ONE_BOOL(ndb, &q, s,
        AR_READ_STR(s, 0, out->nonce_hex, sizeof(out->nonce_hex));
        AR_READ_STR(s, 1, out->address, sizeof(out->address));
        out->issued_at = AR_COL_INT(s, 2);
        out->expires_at = AR_COL_INT(s, 3);
        out->consumed = AR_COL_INT(s, 4) != 0);
}

bool db_auth_challenge_consume(struct node_db *ndb, const char *nonce_hex,
                               const char *address, int64_t now)
{
    if (!ndb || !ndb->open || !nonce_hex || !address) {
        LOG_FAIL("model", "db_auth_challenge_consume: bad args");
        return false;
    }
    struct qb q;
    qb_update(&q, QB_T_auth_challenges);
    qb_set_int(&q, QB_C_auth_challenges_consumed, 1);
    qb_where_text(&q, QB_C_auth_challenges_nonce_hex, QB_EQ, nonce_hex);
    qb_where_text(&q, QB_C_auth_challenges_address, QB_EQ, address);
    qb_where_int(&q, QB_C_auth_challenges_consumed, QB_EQ, 0);
    qb_where_int(&q, QB_C_auth_challenges_expires_at, QB_GT, now);
    QB_EXEC_CHANGED_BOOL(ndb, &q, s);
}

int db_auth_challenge_reap(struct node_db *ndb, int64_t cutoff)
{
    sqlite3_stmt *s = NULL;
    if (!ndb || !ndb->open)
        return 0;
    struct qb q;
    qb_delete(&q, QB_T_auth_challenges);
    qb_group_begin(&q, QB_OR);
    qb_where_int(&q, QB_C_auth_challenges_issued_at, QB_LT, cutoff);
    qb_where_int(&q, QB_C_auth_challenges_consumed, QB_EQ, 1);
    qb_group_end(&q);
    if (!QB_PREPARE(ndb, &q, s)) {
        LOG_WARN("model", "db_auth_challenge_reap: %s", qb_error(&q));
        return 0;
    }
    int removed = 0;
    if (AR_STEP_DONE(s))
        removed = sqlite3_changes(ndb->db);
    AR_FINALIZE(s);
    return removed;
}

int db_auth_challenge_pending_count(struct node_db *ndb)
{
    if (!ndb || !ndb->open)
        return 0;
    struct qb q;
    qb_select(&q, QB_T_auth_challenges);
    qb_select_count_star(&q);
    qb_where_int(&q, QB_C_auth_challenges_consumed, QB_EQ, 0);
    QB_QUERY_COUNT(ndb, &q, s);
}

bool auth_challenge_dump_state_json(struct json_value *out, const char *key)
{
    (void)key;
    struct node_db *ndb = app_runtime_node_db();
    json_push_kv_bool(out, "db_open", ndb && ndb->open);
    json_push_kv_int(out, "pending",
                     ndb && ndb->open ? db_auth_challenge_pending_count(ndb) : 0);
    return true;
}
