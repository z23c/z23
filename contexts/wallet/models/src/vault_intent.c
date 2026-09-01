/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: persist encrypted, idempotent transaction-intent state. */

#include "models/vault_intent.h"

#include "models/database.h"
#include "models/agent_session.h"
#include "models/model_text.h"
#include "util/log_macros.h"

#include <string.h>

DEFINE_MODEL_CALLBACKS(vault_intent)
DEFINE_MODEL_CALLBACKS(vault_intent_raw)
DEFINE_MODEL_CALLBACKS(vault_intent_input)

struct vault_intent_raw_row {
    const uint8_t *plan_id;
    const uint8_t *raw_tx;
    size_t raw_tx_len;
};

static bool vault_intent_raw_validate(const struct vault_intent_raw_row *r,
                                      struct ar_errors *errors)
{
    ar_errors_clear(errors);
    validates_custom(errors, r && r->plan_id, "plan_id", "is absent");
    validates_custom(errors, r && r->raw_tx && r->raw_tx_len > 0 &&
                     r->raw_tx_len <= VAULT_INTENT_RAW_MAX, "raw_tx",
                     "has invalid length");
    return !ar_errors_any(errors);
}

struct vault_intent_input_row {
    const uint8_t *plan_id;
    const struct vault_intent_input *input;
};

static bool vault_intent_input_validate(
    const struct vault_intent_input_row *r, struct ar_errors *errors)
{
    ar_errors_clear(errors);
    validates_custom(errors, r && r->plan_id, "plan_id", "is absent");
    validates_custom(errors, r && r->input, "input", "is absent");
    return !ar_errors_any(errors);
}

static bool vault_intent_inputs_release_terminal(struct node_db *ndb)
{
    struct vault_intent_input_row row = {0};
    sqlite3_stmt *s = NULL;
    AR_ADHOC_DESTROY(ndb, s,
        "DELETE FROM vault_intent_inputs WHERE plan_id IN ("
        "SELECT plan_id FROM vault_intents WHERE state IN (3,4,6,7,8))",
        db_vault_intent_input_callbacks(), &row, );
}

static bool vault_intent_input_save(
    struct node_db *ndb, const uint8_t plan_id[32],
    const struct vault_intent_input *input)
{
    struct vault_intent_input_row row = {
        .plan_id = plan_id, .input = input,
    };
    sqlite3_stmt *s = NULL;
    AR_ADHOC_SAVE(ndb, s,
        "INSERT INTO vault_intent_inputs(plan_id,txid,vout) VALUES(?,?,?)",
        db_vault_intent_input_callbacks(), "vault_intent_input", &row,
        vault_intent_input_validate,
        AR_BIND_BLOB(s, 1, plan_id, 32);
        AR_BIND_BLOB(s, 2, input->txid, 32);
        AR_BIND_INT(s, 3, input->vout));
}

bool vault_intent_validate(const struct vault_intent_row *r,
                           struct ar_errors *errors)
{
    ar_errors_clear(errors);
    if (!r) {
        ar_errors_add(errors, "intent", "is NULL");
        return false; // raw-return-ok:null record cannot be validated
    }
    validates_presence_of(errors, r, plan_id);
    validates_presence_of(errors, r, digest);
    validates_range(errors, r, state, VAULT_INTENT_PLANNED,
                    VAULT_INTENT_FAILED);
    validates_range(errors, r, route, VAULT_INTENT_ROUTE_PRIVATE,
                    VAULT_INTENT_ROUTE_MIXED);
    validates_non_negative(errors, r, created_at);
    validates_custom(errors, r->expires_at > r->created_at, "expires_at",
                     "must be after created_at");
    validates_non_negative(errors, r, anchor_height);
    validates_presence_of(errors, r, anchor_hash);
    validates_custom(errors, r->encrypted_payload_len >= 32 &&
                     r->encrypted_payload_len <= VAULT_INTENT_PAYLOAD_MAX,
                     "encrypted_payload", "has invalid length");
    validates_custom(errors, strlen(r->error_code) <= VAULT_INTENT_ERROR_MAX &&
                     (r->error_code[0] == '\0' ||
                      model_string_is_printable(r->error_code)), "error_code",
                     "is invalid");
    const bool legacy = r->wallet_scope[0] == '\0' &&
        r->wallet_instance_id[0] == '\0' && r->wallet_genesis[0] == '\0' &&
        !r->has_snapshot_root && r->recipient_value_zat == 0 &&
        r->max_fee_zat == 0 && r->reserved_zat == 0;
    const bool bound =
        (strcmp(r->wallet_scope, "dev") == 0 ||
         strcmp(r->wallet_scope, "prod") == 0 ||
         strcmp(r->wallet_scope, "test") == 0) &&
        zcl_is_hex_string(r->wallet_instance_id,
                          WALLET_INSTANCE_ID_HEX_LEN) &&
        zcl_is_hex_string(r->wallet_genesis, WALLET_GENESIS_HEX_LEN) &&
        r->has_snapshot_root && r->recipient_value_zat >= 0 &&
        r->max_fee_zat >= 0 &&
        r->recipient_value_zat <= INT64_MAX - r->max_fee_zat &&
        r->recipient_value_zat + r->max_fee_zat > 0 &&
        r->reserved_zat == r->recipient_value_zat + r->max_fee_zat;
    validates_custom(errors, legacy || bound, "custody_binding",
                     "must be wholly legacy-empty or a complete reservation");
    const bool application_empty = r->application_kind[0] == '\0' &&
        r->idempotency_key[0] == '\0' && !r->has_request_digest;
    const bool application_bound = bound &&
        r->application_kind[0] != '\0' &&
        strlen(r->application_kind) <= VAULT_INTENT_APPLICATION_MAX &&
        model_string_is_printable(r->application_kind) &&
        r->idempotency_key[0] != '\0' &&
        strlen(r->idempotency_key) <= VAULT_INTENT_IDEMPOTENCY_MAX &&
        model_string_is_printable(r->idempotency_key) &&
        r->has_request_digest;
    validates_custom(errors, application_empty || application_bound,
                     "application_binding",
                     "must be wholly empty or kind, idempotency, and digest");
    validates_custom(errors, legacy || r->recipient_value_zat > 0 ||
                     application_bound, "fee_only_intent",
                     "requires a named idempotent application workflow");
    const bool agent_empty = r->agent_session_id[0] == '\0' &&
        r->agent_debited_zat == 0;
    const bool agent_bound = bound &&
        zcl_is_hex_string(r->agent_session_id, AGENT_SESSION_ID_MAX) &&
        (r->agent_debited_zat == 0 ||
         r->agent_debited_zat == r->reserved_zat);
    validates_custom(errors, agent_empty || agent_bound, "agent_binding",
                     "must be empty or bind one exact reservation debit");
    return !ar_errors_any(errors);
}

bool vault_intent_save(struct node_db *ndb, const struct vault_intent_row *r)
{
    if (!ndb || !ndb->open || !r)
        LOG_FAIL("vault_intent", "save: invalid argument");
    sqlite3_stmt *s = NULL;
    AR_ADHOC_SAVE(ndb, s,
        "INSERT INTO vault_intents"
        "(plan_id,digest,state,route,created_at,expires_at,anchor_height,"
        "anchor_hash,encrypted_payload,txid,confirm_height,confirm_hash,"
        "error_code,updated_at,wallet_scope,wallet_instance_id,wallet_genesis,"
        "snapshot_root,recipient_value_zat,max_fee_zat,reserved_zat,"
        "application_kind,idempotency_key,request_digest,agent_session_id,"
        "agent_debited_zat) "
        "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) "
        "ON CONFLICT(plan_id) DO UPDATE SET "
        "digest=excluded.digest,state=excluded.state,route=excluded.route,"
        "created_at=excluded.created_at,expires_at=excluded.expires_at,"
        "anchor_height=excluded.anchor_height,anchor_hash=excluded.anchor_hash,"
        "encrypted_payload=excluded.encrypted_payload,txid=excluded.txid,"
        "confirm_height=excluded.confirm_height,"
        "confirm_hash=excluded.confirm_hash,error_code=excluded.error_code,"
        "updated_at=excluded.updated_at,wallet_scope=excluded.wallet_scope,"
        "wallet_instance_id=excluded.wallet_instance_id,"
        "wallet_genesis=excluded.wallet_genesis,"
        "snapshot_root=excluded.snapshot_root,"
        "recipient_value_zat=excluded.recipient_value_zat,"
        "max_fee_zat=excluded.max_fee_zat,reserved_zat=excluded.reserved_zat,"
        "application_kind=excluded.application_kind,"
        "idempotency_key=excluded.idempotency_key,"
        "request_digest=excluded.request_digest,"
        "agent_session_id=excluded.agent_session_id,"
        "agent_debited_zat=excluded.agent_debited_zat",
        db_vault_intent_callbacks(), "vault_intent", r,
        vault_intent_validate,
        AR_BIND_BLOB(s, 1, r->plan_id, 32);
        AR_BIND_BLOB(s, 2, r->digest, 32);
        AR_BIND_INT(s, 3, r->state);
        AR_BIND_INT(s, 4, r->route);
        AR_BIND_INT(s, 5, r->created_at);
        AR_BIND_INT(s, 6, r->expires_at);
        AR_BIND_INT(s, 7, r->anchor_height);
        AR_BIND_BLOB(s, 8, r->anchor_hash, 32);
        AR_BIND_BLOB(s, 9, r->encrypted_payload, r->encrypted_payload_len);
        if (r->has_txid) AR_BIND_BLOB(s, 10, r->txid, 32);
        else AR_BIND_NULL(s, 10);
        AR_BIND_INT(s, 11, r->confirm_height);
        if (r->has_confirm_hash) AR_BIND_BLOB(s, 12, r->confirm_hash, 32);
        else AR_BIND_NULL(s, 12);
        AR_BIND_TEXT(s, 13, r->error_code);
        AR_BIND_INT(s, 14, r->updated_at);
        AR_BIND_TEXT(s, 15, r->wallet_scope);
        AR_BIND_TEXT(s, 16, r->wallet_instance_id);
        AR_BIND_TEXT(s, 17, r->wallet_genesis);
        if (r->has_snapshot_root) AR_BIND_BLOB(s, 18, r->snapshot_root, 32);
        else AR_BIND_NULL(s, 18);
        AR_BIND_INT(s, 19, r->recipient_value_zat);
        AR_BIND_INT(s, 20, r->max_fee_zat);
        AR_BIND_INT(s, 21, r->reserved_zat);
        AR_BIND_TEXT(s, 22, r->application_kind);
        AR_BIND_TEXT(s, 23, r->idempotency_key);
        if (r->has_request_digest)
            AR_BIND_BLOB(s, 24, r->request_digest, 32);
        else AR_BIND_NULL(s, 24);
        AR_BIND_TEXT(s, 25, r->agent_session_id);
        AR_BIND_INT(s, 26, r->agent_debited_zat));
}

static bool vault_intent_reserve_internal(
    struct node_db *ndb, const struct vault_intent_row *r,
    int64_t confirmed_zat, const uint8_t *raw_tx, size_t raw_tx_len,
    const struct vault_intent_input *inputs, size_t input_count,
    bool require_expected_reserved, int64_t expected_reserved_zat)
{
    if (!ndb || !ndb->open || !r || confirmed_zat < 0 ||
        (require_expected_reserved && expected_reserved_zat < 0) ||
        r->reserved_zat <= 0 || (raw_tx && (raw_tx_len == 0 ||
        raw_tx_len > VAULT_INTENT_RAW_MAX)) || (!raw_tx && raw_tx_len != 0) ||
        (input_count > 0 && !inputs) || input_count > 4096)
        LOG_FAIL("vault_intent", "reserve: invalid argument");
    if (!node_db_begin_immediate(ndb))
        return false; /* raw-return-ok:busy is a fail-closed reservation */
    bool inputs_ready = vault_intent_inputs_release_terminal(ndb);
    int64_t reserved = vault_intent_reserved_total_at(
        ndb, r->wallet_scope, r->wallet_instance_id, r->created_at);
    int64_t direct_lifetime = agent_session_scope_lifetime_spent(
        ndb, r->wallet_scope);
    int64_t completed = vault_intent_unbound_completed_total(
        ndb, r->wallet_scope, r->wallet_instance_id);
    bool allowed = reserved >= 0 && direct_lifetime >= 0 && completed >= 0 &&
        (!require_expected_reserved || reserved == expected_reserved_zat) &&
        reserved <= INT64_MAX - r->reserved_zat &&
        direct_lifetime <= INT64_MAX - completed;
    if (allowed && strcmp(r->wallet_scope, "dev") == 0) {
        const int64_t next = reserved + r->reserved_zat;
        const int64_t lifetime = direct_lifetime + completed;
        int64_t reserve_floor = VAULT_INTENT_DEV_RESERVE_FLOOR_ZAT;
        if (r->agent_session_id[0]) {
            struct db_agent_session session;
            allowed = agent_session_find(
                    ndb, r->agent_session_id, &session) &&
                !session.revoked &&
                (session.expires_at == 0 || r->created_at < session.expires_at) &&
                strcmp(session.wallet_scope, r->wallet_scope) == 0 &&
                strcmp(session.wallet_instance_id,
                       r->wallet_instance_id) == 0 &&
                strcmp(session.wallet_genesis, r->wallet_genesis) == 0;
            if (allowed)
                reserve_floor = session.reserve_floor_zat;
        }
        allowed = allowed && confirmed_zat >= reserve_floor &&
            next <= confirmed_zat - reserve_floor &&
            lifetime <= VAULT_INTENT_DEV_LIFETIME_CAP_ZAT &&
            next <= VAULT_INTENT_DEV_LIFETIME_CAP_ZAT - lifetime;
    } else if (allowed) {
        allowed = reserved + r->reserved_zat <= confirmed_zat;
    }
    bool saved = inputs_ready && allowed && vault_intent_save(ndb, r) &&
        (!raw_tx || vault_intent_store_raw(ndb, r->plan_id,
                                           raw_tx, raw_tx_len));
    for (size_t i = 0; saved && i < input_count; i++)
        saved = vault_intent_input_save(ndb, r->plan_id, &inputs[i]);
    if (!saved || !node_db_commit(ndb)) {
        (void)node_db_rollback(ndb);
        return false; /* raw-return-ok:nothing was reserved */
    }
    return true;
}

bool vault_intent_reserve(struct node_db *ndb,
                          const struct vault_intent_row *r,
                          int64_t confirmed_zat)
{
    return vault_intent_reserve_internal(
        ndb, r, confirmed_zat, NULL, 0, NULL, 0, false, 0);
}

bool vault_intent_reserve_bound(struct node_db *ndb,
                                const struct vault_intent_row *r,
                                int64_t confirmed_zat,
                                int64_t expected_reserved_zat)
{
    return vault_intent_reserve_internal(
        ndb, r, confirmed_zat, NULL, 0, NULL, 0, true,
        expected_reserved_zat);
}

bool vault_intent_reserve_with_raw(struct node_db *ndb,
                                   const struct vault_intent_row *r,
                                   int64_t confirmed_zat,
                                   const uint8_t *raw_tx,
                                   size_t raw_tx_len)
{
    return vault_intent_reserve_internal(
        ndb, r, confirmed_zat, raw_tx, raw_tx_len, NULL, 0, false, 0);
}

bool vault_intent_reserve_with_raw_inputs(
    struct node_db *ndb, const struct vault_intent_row *r,
    int64_t confirmed_zat, const uint8_t *raw_tx, size_t raw_tx_len,
    const struct vault_intent_input *inputs, size_t input_count)
{
    return vault_intent_reserve_internal(
        ndb, r, confirmed_zat, raw_tx, raw_tx_len, inputs, input_count,
        false, 0);
}

static void intent_read(struct vault_intent_row *r, sqlite3_stmt *s)
{
    memset(r, 0, sizeof(*r));
    AR_READ_BLOB(s, 0, r->plan_id, 32);
    AR_READ_BLOB(s, 1, r->digest, 32);
    r->state = (enum vault_intent_state)AR_COL_INT(s, 2);
    r->route = (enum vault_intent_route)AR_COL_INT(s, 3);
    r->created_at = AR_COL_INT(s, 4);
    r->expires_at = AR_COL_INT(s, 5);
    r->anchor_height = (int32_t)AR_COL_INT(s, 6);
    AR_READ_BLOB(s, 7, r->anchor_hash, 32);
    int plen = AR_COL_BYTES(s, 8);
    if (plen > 0 && plen <= VAULT_INTENT_PAYLOAD_MAX) {
        AR_READ_BLOB(s, 8, r->encrypted_payload, (size_t)plen);
        r->encrypted_payload_len = (size_t)plen;
    }
    if (AR_COL_BYTES(s, 9) == 32) {
        AR_READ_BLOB(s, 9, r->txid, 32);
        r->has_txid = true;
    }
    r->confirm_height = (int32_t)AR_COL_INT(s, 10);
    if (AR_COL_BYTES(s, 11) == 32) {
        AR_READ_BLOB(s, 11, r->confirm_hash, 32);
        r->has_confirm_hash = true;
    }
    AR_READ_STR(s, 12, r->error_code, sizeof(r->error_code));
    r->updated_at = AR_COL_INT(s, 13);
    AR_READ_STR(s, 14, r->wallet_scope, sizeof(r->wallet_scope));
    AR_READ_STR(s, 15, r->wallet_instance_id,
                sizeof(r->wallet_instance_id));
    AR_READ_STR(s, 16, r->wallet_genesis, sizeof(r->wallet_genesis));
    if (AR_COL_BYTES(s, 17) == 32) {
        AR_READ_BLOB(s, 17, r->snapshot_root, 32);
        r->has_snapshot_root = true;
    }
    r->recipient_value_zat = AR_COL_INT(s, 18);
    r->max_fee_zat = AR_COL_INT(s, 19);
    r->reserved_zat = AR_COL_INT(s, 20);
    AR_READ_STR(s, 21, r->application_kind, sizeof(r->application_kind));
    AR_READ_STR(s, 22, r->idempotency_key, sizeof(r->idempotency_key));
    if (AR_COL_BYTES(s, 23) == 32) {
        AR_READ_BLOB(s, 23, r->request_digest, 32);
        r->has_request_digest = true;
    }
    AR_READ_STR(s, 24, r->agent_session_id,
                sizeof(r->agent_session_id));
    r->agent_debited_zat = AR_COL_INT(s, 25);
}

#define INTENT_COLUMNS "plan_id,digest,state,route,created_at,expires_at," \
    "anchor_height,anchor_hash,encrypted_payload,txid,confirm_height," \
    "confirm_hash,error_code,updated_at,wallet_scope,wallet_instance_id," \
    "wallet_genesis,snapshot_root,recipient_value_zat,max_fee_zat,reserved_zat," \
    "application_kind,idempotency_key,request_digest,agent_session_id," \
    "agent_debited_zat"

bool vault_intent_find(struct node_db *ndb, const uint8_t plan_id[32],
                       struct vault_intent_row *out)
{
    if (!ndb || !ndb->open || !plan_id || !out)
        LOG_FAIL("vault_intent", "find: invalid argument");
    sqlite3_stmt *s = NULL;
    AR_QUERY_ONE_BOOL(ndb, s,
        "SELECT " INTENT_COLUMNS " FROM vault_intents WHERE plan_id=?",
        AR_BIND_BLOB(s, 1, plan_id, 32), intent_read(out, s));
}

bool vault_intent_find_application_idempotency(
    struct node_db *ndb, const char *wallet_scope,
    const char *application_kind, const char *idempotency_key,
    struct vault_intent_row *out)
{
    if (!ndb || !ndb->open || !wallet_scope || !wallet_scope[0] ||
        !application_kind || !application_kind[0] || !idempotency_key ||
        !idempotency_key[0] || !out)
        LOG_FAIL("vault_intent", "find application idempotency: invalid argument");
    sqlite3_stmt *s = NULL;
    AR_QUERY_ONE_BOOL(ndb, s,
        "SELECT " INTENT_COLUMNS " FROM vault_intents "
        "WHERE wallet_scope=? AND application_kind=? AND idempotency_key=?",
        AR_BIND_TEXT(s, 1, wallet_scope);
        AR_BIND_TEXT(s, 2, application_kind);
        AR_BIND_TEXT(s, 3, idempotency_key), intent_read(out, s));
}

int vault_intent_list(struct node_db *ndb, struct vault_intent_row *out,
                      size_t max)
{
    if (!ndb || !ndb->open || (!out && max))
        LOG_ERR("vault_intent", "list: invalid argument");
    sqlite3_stmt *s = NULL;
    AR_QUERY_LIST(ndb, s,
        "SELECT " INTENT_COLUMNS " FROM vault_intents "
        "ORDER BY created_at DESC LIMIT 100", out, max, ;,
        intent_read(&out[count], s));
}

bool vault_intent_claim_commit(struct node_db *ndb,
                               const uint8_t plan_id[32], int64_t now_unix)
{
    if (!ndb || !ndb->open || !plan_id || now_unix < 0)
        LOG_FAIL("vault_intent", "claim: invalid argument");
    sqlite3_stmt *s = NULL;
    AR_EXEC_CHANGED_BOOL(ndb, s,
        "UPDATE vault_intents SET state=?,updated_at=? WHERE plan_id=? "
        "AND state=? AND expires_at>?",
        AR_BIND_INT(s, 1, VAULT_INTENT_PROVING);
        AR_BIND_INT(s, 2, now_unix);
        AR_BIND_BLOB(s, 3, plan_id, 32);
        AR_BIND_INT(s, 4, VAULT_INTENT_PLANNED);
        AR_BIND_INT(s, 5, now_unix));
}

bool vault_intent_reclaim_proving(struct node_db *ndb,
                                  const uint8_t plan_id[32],
                                  int64_t stale_before_unix,
                                  int64_t now_unix)
{
    if (!ndb || !ndb->open || !plan_id || stale_before_unix < 0 ||
        now_unix < stale_before_unix)
        LOG_FAIL("vault_intent", "reclaim: invalid argument");
    sqlite3_stmt *s = NULL;
    AR_EXEC_CHANGED_BOOL(ndb, s,
        "UPDATE vault_intents SET state=?,error_code='',updated_at=? "
        "WHERE plan_id=? AND state=? AND updated_at<=? AND NOT EXISTS "
        "(SELECT 1 FROM vault_intent_raw r WHERE r.plan_id=vault_intents.plan_id)",
        AR_BIND_INT(s, 1, VAULT_INTENT_PLANNED);
        AR_BIND_INT(s, 2, now_unix);
        AR_BIND_BLOB(s, 3, plan_id, 32);
        AR_BIND_INT(s, 4, VAULT_INTENT_PROVING);
        AR_BIND_INT(s, 5, stale_before_unix));
}

bool vault_intent_record_planned_error(struct node_db *ndb,
                                       const uint8_t plan_id[32],
                                       const char *error_code,
                                       int64_t now_unix)
{
    if (!ndb || !ndb->open || !plan_id || !error_code ||
        strlen(error_code) > VAULT_INTENT_ERROR_MAX || now_unix < 0)
        LOG_FAIL("vault_intent", "record planned error: invalid argument");
    sqlite3_stmt *s = NULL;
    AR_EXEC_CHANGED_BOOL(ndb, s,
        "UPDATE vault_intents SET error_code=?,updated_at=? "
        "WHERE plan_id=? AND state=?",
        AR_BIND_TEXT(s, 1, error_code);
        AR_BIND_INT(s, 2, now_unix);
        AR_BIND_BLOB(s, 3, plan_id, 32);
        AR_BIND_INT(s, 4, VAULT_INTENT_PLANNED));
}

bool vault_intent_cancel_planned(struct node_db *ndb,
                                 const uint8_t plan_id[32],
                                 int64_t now_unix)
{
    if (!ndb || !ndb->open || !plan_id || now_unix < 0)
        LOG_FAIL("vault_intent", "cancel planned: invalid argument");
    sqlite3_stmt *s = NULL;
    AR_EXEC_CHANGED_BOOL(ndb, s,
        "UPDATE vault_intents SET state=?,error_code='CANCELLED_BY_OWNER',"
        "updated_at=? WHERE plan_id=? AND state=?",
        AR_BIND_INT(s, 1, VAULT_INTENT_FAILED);
        AR_BIND_INT(s, 2, now_unix);
        AR_BIND_BLOB(s, 3, plan_id, 32);
        AR_BIND_INT(s, 4, VAULT_INTENT_PLANNED));
}

bool vault_intent_set_state(struct node_db *ndb, const uint8_t plan_id[32],
                            enum vault_intent_state state,
                            const uint8_t txid[32], const char *error_code,
                            int64_t now_unix)
{
    if (!ndb || !ndb->open || !plan_id || state < VAULT_INTENT_PLANNED ||
        state > VAULT_INTENT_FAILED || now_unix < 0)
        LOG_FAIL("vault_intent", "set_state: invalid argument");
    sqlite3_stmt *s = NULL;
    AR_EXEC_CHANGED_BOOL(ndb, s,
        "UPDATE vault_intents SET state=?,txid=?,error_code=?,updated_at=? "
        "WHERE plan_id=?",
        AR_BIND_INT(s, 1, state);
        if (txid) AR_BIND_BLOB(s, 2, txid, 32); else AR_BIND_NULL(s, 2);
        AR_BIND_TEXT(s, 3, error_code ? error_code : "");
        AR_BIND_INT(s, 4, now_unix);
        AR_BIND_BLOB(s, 5, plan_id, 32));
}

bool vault_intent_expire_due(struct node_db *ndb, int64_t now_unix)
{
    if (!ndb || !ndb->open || now_unix < 0)
        LOG_FAIL("vault_intent", "expire: invalid argument");
    sqlite3_stmt *s = NULL;
    AR_EXEC_BOOL(ndb, s,
        "UPDATE vault_intents SET state=?,error_code='PLAN_EXPIRED',"
        "updated_at=? WHERE state=? AND expires_at<=?",
        AR_BIND_INT(s, 1, VAULT_INTENT_EXPIRED);
        AR_BIND_INT(s, 2, now_unix);
        AR_BIND_INT(s, 3, VAULT_INTENT_PLANNED);
        AR_BIND_INT(s, 4, now_unix));
}

bool vault_intent_set_confirmation(
    struct node_db *ndb, const uint8_t plan_id[32],
    enum vault_intent_state state, int32_t confirm_height,
    const uint8_t confirm_hash[32], int64_t now_unix)
{
    if (!ndb || !ndb->open || !plan_id || !confirm_hash ||
        (state != VAULT_INTENT_CONFIRMED &&
         state != VAULT_INTENT_FINALIZED) || confirm_height < 0)
        LOG_FAIL("vault_intent", "set_confirmation: invalid argument");
    sqlite3_stmt *s = NULL;
    AR_EXEC_CHANGED_BOOL(ndb, s,
        "UPDATE vault_intents SET state=?,confirm_height=?,confirm_hash=?,"
        "error_code='',updated_at=? WHERE plan_id=?",
        AR_BIND_INT(s, 1, state);
        AR_BIND_INT(s, 2, confirm_height);
        AR_BIND_BLOB(s, 3, confirm_hash, 32);
        AR_BIND_INT(s, 4, now_unix);
        AR_BIND_BLOB(s, 5, plan_id, 32));
}

bool vault_intent_store_raw(struct node_db *ndb, const uint8_t plan_id[32],
                            const uint8_t *raw_tx, size_t raw_tx_len)
{
    if (!ndb || !ndb->open)
        LOG_FAIL("vault_intent", "store_raw: database unavailable");
    struct vault_intent_raw_row row = {
        .plan_id = plan_id, .raw_tx = raw_tx, .raw_tx_len = raw_tx_len
    };
    sqlite3_stmt *s = NULL;
    AR_ADHOC_SAVE(ndb, s,
        "INSERT OR REPLACE INTO vault_intent_raw(plan_id,raw_tx) VALUES(?,?)",
        db_vault_intent_raw_callbacks(), "vault_intent_raw", &row,
        vault_intent_raw_validate,
        AR_BIND_BLOB(s, 1, plan_id, 32);
        AR_BIND_BLOB(s, 2, raw_tx, raw_tx_len));
}

bool vault_intent_load_raw(struct node_db *ndb, const uint8_t plan_id[32],
                           uint8_t *out, size_t out_cap, size_t *out_len)
{
    if (!ndb || !ndb->open || !plan_id || !out || !out_len)
        LOG_FAIL("vault_intent", "load_raw: invalid argument");
    sqlite3_stmt *s = NULL;
    AR_PREPARE_BOOL(ndb, s,
        "SELECT raw_tx FROM vault_intent_raw WHERE plan_id=?");
    AR_BIND_BLOB(s, 1, plan_id, 32);
    if (!AR_STEP_ROW(s)) {
        AR_FINALIZE(s);
        return false; // raw-return-ok:no prepared transaction is a valid state
    }
    int n = AR_COL_BYTES(s, 0);
    if (n <= 0 || (size_t)n > out_cap) {
        AR_FINALIZE(s);
        LOG_FAIL("vault_intent", "load_raw: invalid size %d", n);
    }
    AR_READ_BLOB(s, 0, out, (size_t)n);
    *out_len = (size_t)n;
    AR_FINALIZE(s);
    return true;
}

bool vault_intent_has_raw(struct node_db *ndb, const uint8_t plan_id[32])
{
    if (!ndb || !ndb->open || !plan_id)
        LOG_FAIL("vault_intent", "has_raw: invalid argument");
    sqlite3_stmt *s = NULL;
    AR_QUERY_ONE_BOOL(ndb, s,
        "SELECT 1 FROM vault_intent_raw WHERE plan_id=?",
        AR_BIND_BLOB(s, 1, plan_id, 32), ;);
}

bool vault_intent_bind_agent_session(
    struct node_db *ndb, const uint8_t plan_id[32], const char *session_id,
    int64_t now_unix)
{
    if (!ndb || !ndb->open || !plan_id ||
        !zcl_is_hex_string(session_id, AGENT_SESSION_ID_MAX) || now_unix < 0)
        LOG_FAIL("vault_intent", "bind agent: invalid argument");
    sqlite3_stmt *s = NULL;
    AR_EXEC_CHANGED_BOOL(ndb, s,
        "UPDATE vault_intents SET agent_session_id=?,updated_at=? "
        "WHERE plan_id=? AND state=? AND agent_debited_zat=0 AND "
        "(agent_session_id='' OR agent_session_id=?)",
        AR_BIND_TEXT(s, 1, session_id);
        AR_BIND_INT(s, 2, now_unix);
        AR_BIND_BLOB(s, 3, plan_id, 32);
        AR_BIND_INT(s, 4, VAULT_INTENT_PLANNED);
        AR_BIND_TEXT(s, 5, session_id));
}

bool vault_intent_mark_agent_debited(
    struct node_db *ndb, const uint8_t plan_id[32], const char *session_id,
    int64_t amount_zat, int64_t now_unix)
{
    if (!ndb || !ndb->open || !plan_id ||
        !zcl_is_hex_string(session_id, AGENT_SESSION_ID_MAX) ||
        amount_zat <= 0 || now_unix < 0)
        LOG_FAIL("vault_intent", "mark agent debit: invalid argument");
    sqlite3_stmt *s = NULL;
    AR_EXEC_CHANGED_BOOL(ndb, s,
        "UPDATE vault_intents SET agent_debited_zat=?,updated_at=? "
        "WHERE plan_id=? AND agent_session_id=? AND agent_debited_zat=0 "
        "AND reserved_zat=? AND state IN (?,?)",
        AR_BIND_INT(s, 1, amount_zat);
        AR_BIND_INT(s, 2, now_unix);
        AR_BIND_BLOB(s, 3, plan_id, 32);
        AR_BIND_TEXT(s, 4, session_id);
        AR_BIND_INT(s, 5, amount_zat);
        AR_BIND_INT(s, 6, VAULT_INTENT_PLANNED);
        AR_BIND_INT(s, 7, VAULT_INTENT_PROVING));
}

bool vault_intent_clear_agent_debit(
    struct node_db *ndb, const uint8_t plan_id[32], const char *session_id,
    int64_t now_unix)
{
    if (!ndb || !ndb->open || !plan_id ||
        !zcl_is_hex_string(session_id, AGENT_SESSION_ID_MAX) || now_unix < 0)
        LOG_FAIL("vault_intent", "clear agent debit: invalid argument");
    sqlite3_stmt *s = NULL;
    AR_EXEC_CHANGED_BOOL(ndb, s,
        "UPDATE vault_intents SET agent_debited_zat=0,updated_at=? "
        "WHERE plan_id=? AND agent_session_id=? AND agent_debited_zat>0 "
        "AND state IN (0,6,7,8)",
        AR_BIND_INT(s, 1, now_unix);
        AR_BIND_BLOB(s, 2, plan_id, 32);
        AR_BIND_TEXT(s, 3, session_id));
}

static int64_t vault_intent_reserved_total_query(
    struct node_db *ndb, const char *wallet_scope,
    const char *wallet_instance_id, bool apply_expiry, int64_t now_unix)
{
    sqlite3_stmt *s = NULL;
    if (!ndb || !ndb->open || !wallet_scope || !wallet_scope[0] ||
        !wallet_instance_id || !wallet_instance_id[0])
        LOG_ERR("vault_intent", "reserved_total: invalid argument");
    AR_PREPARE_RET(ndb, s,
        "SELECT COALESCE(SUM(reserved_zat),0) FROM vault_intents "
        "WHERE wallet_scope=? AND wallet_instance_id=? "
        "AND state IN (0,1,2,5) "
        "AND (?=0 OR state!=0 OR expires_at>?)", -1);
    AR_BIND_TEXT(s, 1, wallet_scope);
    AR_BIND_TEXT(s, 2, wallet_instance_id);
    AR_BIND_INT(s, 3, apply_expiry ? 1 : 0);
    AR_BIND_INT(s, 4, now_unix);
    int64_t total = -1;
    if (AR_STEP_ROW(s))
        total = AR_COL_INT(s, 0);
    AR_FINALIZE(s);
    return total;
}

int64_t vault_intent_reserved_total(struct node_db *ndb,
                                    const char *wallet_scope,
                                    const char *wallet_instance_id)
{
    return vault_intent_reserved_total_query(
        ndb, wallet_scope, wallet_instance_id, false, 0);
}

int64_t vault_intent_reserved_total_at(struct node_db *ndb,
                                       const char *wallet_scope,
                                       const char *wallet_instance_id,
                                       int64_t now_unix)
{
    if (now_unix < 0)
        LOG_ERR("vault_intent", "reserved_total_at: invalid observation time");
    return vault_intent_reserved_total_query(
        ndb, wallet_scope, wallet_instance_id, true, now_unix);
}

int64_t vault_intent_unbound_completed_total(
    struct node_db *ndb, const char *wallet_scope,
    const char *wallet_instance_id)
{
    if (!ndb || !ndb->open || !wallet_scope || !wallet_scope[0] ||
        !wallet_instance_id || !wallet_instance_id[0])
        LOG_ERR("vault_intent", "unbound_completed_total: invalid argument");
    sqlite3_stmt *s = NULL;
    AR_PREPARE_RET(ndb, s,
        "SELECT COALESCE(SUM(reserved_zat),0) FROM vault_intents "
        "WHERE wallet_scope=? AND wallet_instance_id=? AND state IN (3,4) "
        "AND agent_session_id=''",
        -1);
    AR_BIND_TEXT(s, 1, wallet_scope);
    AR_BIND_TEXT(s, 2, wallet_instance_id);
    int64_t total = -1;
    if (AR_STEP_ROW(s))
        total = AR_COL_INT(s, 0);
    AR_FINALIZE(s);
    return total;
}

const char *vault_intent_state_name(enum vault_intent_state state)
{
    static const char *const names[] = {
        "planned", "proving", "mempool_accepted", "confirmed", "finalized",
        "reorged", "conflicted", "expired", "failed"
    };
    return state >= VAULT_INTENT_PLANNED && state <= VAULT_INTENT_FAILED
        ? names[state] : "failed";
}
