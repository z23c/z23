/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: ActiveRecord persistence for the yardsale wallet-glue
 *          plan/commit idempotency ledger. See models/yardsale_plan.h. */

#include "models/yardsale_plan.h"

#include "util/log_macros.h"

#include <stdio.h>
#include <string.h>

DEFINE_MODEL_CALLBACKS(yardsale_plan)

static bool yardsale_hex64(const char *value)
{
    if (!value || strlen(value) != 64)
        return false;
    for (size_t i = 0; i < 64; i++)
        if (!((value[i] >= '0' && value[i] <= '9') ||
              (value[i] >= 'a' && value[i] <= 'f')))
            return false;
    return true;
}

static bool yardsale_payload_hex_valid(const char *payload_hex)
{
    if (!payload_hex)
        return false;
    size_t len = strlen(payload_hex);
    if (len == 0 || (len & 1u) != 0 || len >= YARDSALE_PLAN_PAYLOAD_HEX_MAX)
        return false;
    for (size_t i = 0; i < len; i++)
        if (!((payload_hex[i] >= '0' && payload_hex[i] <= '9') ||
              (payload_hex[i] >= 'a' && payload_hex[i] <= 'f')))
            return false;
    return true;
}

static bool yardsale_state_valid(const char *state)
{
    return state &&
           (strcmp(state, YARDSALE_PLAN_STATE_PLANNED) == 0 ||
            strcmp(state, YARDSALE_PLAN_STATE_ARMING) == 0 ||
            strcmp(state, YARDSALE_PLAN_STATE_COMMITTED) == 0 ||
            strcmp(state, YARDSALE_PLAN_STATE_EXPIRED) == 0);
}

static bool yardsale_plan_claim_write(
    struct node_db *ndb, struct db_yardsale_plan *claimed,
    int64_t now_unix, bool *completed)
{
    sqlite3_stmt *st = NULL;
    struct ar_callbacks *cbs = db_yardsale_plan_callbacks();
    AR_BEGIN_SAVE(cbs, "yardsale_plan", claimed,
                  db_yardsale_plan_validate);
    AR_PREPARE_BOOL(ndb, st,
        "UPDATE yardsale_plans SET state='ARMING',result='' "
        "WHERE request_hash=? AND payload_hex=? AND state='PLANNED' "
        "AND expires_unix>=? RETURNING 1");
    AR_BIND_TEXT(st, 1, claimed->request_hash);
    AR_BIND_TEXT(st, 2, claimed->payload_hex);
    AR_BIND_INT(st, 3, now_unix);
    int rc = sqlite3_step(st); // raw-sql-ok:atomic-plan-claim
    bool won = rc == SQLITE_ROW && sqlite3_column_int(st, 0) == 1;
    if (won)
        rc = sqlite3_step(st); // raw-sql-ok:finish-returning-claim
    *completed = rc == SQLITE_DONE;
    if (!*completed)
        LOG_ERROR("model", "yardsale plan claim failed: %s",
                  sqlite3_errmsg(ndb->db));
    AR_FINALIZE(st);
    AR_FINISH_SAVE(cbs, claimed, won && *completed);
}

enum db_yardsale_plan_claim_result db_yardsale_plan_claim(
    struct node_db *ndb, struct db_yardsale_plan *row, int64_t now_unix)
{
    if (!ndb || !ndb->open || !row || now_unix < 0)
        LOG_RETURN(DB_YARDSALE_PLAN_CLAIM_ERROR, "model",
                   "yardsale plan claim: bad args");
    struct db_yardsale_plan claimed = *row;
    snprintf(claimed.state, sizeof(claimed.state), "%s",
             YARDSALE_PLAN_STATE_ARMING);
    claimed.result[0] = '\0';
    bool completed = false;
    if (yardsale_plan_claim_write(ndb, &claimed, now_unix, &completed)) {
        *row = claimed;
        return DB_YARDSALE_PLAN_CLAIMED;
    }
    if (!completed)
        return DB_YARDSALE_PLAN_CLAIM_ERROR;
    return DB_YARDSALE_PLAN_CLAIM_REFUSED;
}

bool db_yardsale_plan_validate(
    const struct db_yardsale_plan *row, struct ar_errors *errors)
{
    ar_errors_clear(errors);
    if (!row) {
        validates_custom(errors, false, "record", "is null");
        return false;
    }
    validates_custom(errors, yardsale_hex64(row->plan_root), "plan_root",
                     "must be a SHA3 root");
    validates_custom(errors,
                     strcmp(row->kind, YARDSALE_PLAN_KIND_ARM) == 0 ||
                         strcmp(row->kind, YARDSALE_PLAN_KIND_BUY) == 0,
                     "kind", "must be arm or buy");
    validates_custom(errors, yardsale_hex64(row->request_hash),
                     "request_hash", "must be a SHA3 request identity");
    validates_custom(errors, yardsale_payload_hex_valid(row->payload_hex),
                     "payload_hex", "must be even-length lowercase hex");
    validates_custom(errors, yardsale_state_valid(row->state), "state",
                     "must be PLANNED, ARMING, COMMITTED, or EXPIRED");
    validates_custom(errors,
                     (strcmp(row->state, YARDSALE_PLAN_STATE_COMMITTED) ==
                      0) == (row->result[0] != '\0'),
                     "state_result", "only COMMITTED carries a result");
    validates_custom(errors, row->expires_unix > 0, "expires_unix",
                     "must be positive");
    validates_non_negative(errors, row, created_at);
    return !ar_errors_any(errors);
}

bool db_yardsale_plan_save(
    struct node_db *ndb, const struct db_yardsale_plan *row)
{
    sqlite3_stmt *st = NULL;
    if (!ndb || !ndb->open || !row)
        LOG_FAIL("model", "db_yardsale_plan_save: bad args");
    AR_ADHOC_SAVE(ndb, st,
        "INSERT INTO yardsale_plans "
        "(plan_root,kind,request_hash,payload_hex,result,state,"
        "expires_unix,created_at) VALUES(?,?,?,?,?,?,?,?) "
        "ON CONFLICT(plan_root) DO UPDATE SET "
        "payload_hex=excluded.payload_hex,result=excluded.result,"
        "state=excluded.state,expires_unix=excluded.expires_unix",
        db_yardsale_plan_callbacks(), "yardsale_plan", row,
        db_yardsale_plan_validate,
        AR_BIND_TEXT(st, 1, row->plan_root);
        AR_BIND_TEXT(st, 2, row->kind);
        AR_BIND_TEXT(st, 3, row->request_hash);
        AR_BIND_TEXT(st, 4, row->payload_hex);
        AR_BIND_TEXT(st, 5, row->result);
        AR_BIND_TEXT(st, 6, row->state);
        AR_BIND_INT(st, 7, row->expires_unix);
        AR_BIND_INT(st, 8, row->created_at));
}

static void plan_read(struct db_yardsale_plan *out, sqlite3_stmt *st)
{
    AR_READ_STR(st, 0, out->plan_root, sizeof(out->plan_root));
    AR_READ_STR(st, 1, out->kind, sizeof(out->kind));
    AR_READ_STR(st, 2, out->request_hash, sizeof(out->request_hash));
    AR_READ_STR(st, 3, out->payload_hex, sizeof(out->payload_hex));
    AR_READ_STR(st, 4, out->result, sizeof(out->result));
    AR_READ_STR(st, 5, out->state, sizeof(out->state));
    out->expires_unix = AR_COL_INT(st, 6);
    out->created_at = AR_COL_INT(st, 7);
}

#define YARDSALE_PLAN_COLS \
    "plan_root,kind,request_hash,payload_hex,result,state," \
    "expires_unix,created_at"

bool db_yardsale_plan_find_by_request(
    struct node_db *ndb, const char *request_hash,
    struct db_yardsale_plan *out)
{
    sqlite3_stmt *st = NULL;
    if (!ndb || !ndb->open || !request_hash || !out)
        return false;
    AR_QUERY_ONE_BOOL(ndb, st,
        "SELECT " YARDSALE_PLAN_COLS " FROM yardsale_plans "
        "WHERE request_hash=?",
        AR_BIND_TEXT(st, 1, request_hash), plan_read(out, st));
}

bool db_yardsale_plan_find(
    struct node_db *ndb, const char *plan_root,
    struct db_yardsale_plan *out)
{
    sqlite3_stmt *st = NULL;
    if (!ndb || !ndb->open || !plan_root || !out)
        return false;
    AR_QUERY_ONE_BOOL(ndb, st,
        "SELECT " YARDSALE_PLAN_COLS " FROM yardsale_plans "
        "WHERE plan_root=?",
        AR_BIND_TEXT(st, 1, plan_root), plan_read(out, st));
}
