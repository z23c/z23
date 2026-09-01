/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Root-bound async proof events in the existing build ledger. */

#include "models/build_proof_event.h"

#include "base/hex.h"
#include "base/serialize_le.h"
#include "crypto/sha3.h"
#include "models/model_text.h"
#include "platform/time_compat.h"
#include "util/log_macros.h"

#include <string.h>
#include <stdio.h>
#include <limits.h>

DEFINE_MODEL_CALLBACKS(build_proof_event)

static const char *const k_states[] = {
    "REQUESTED", "PEER_DISCOVERED", "RUNNING", "REMOTE_GREEN",
    "REMOTE_RED", "RECEIPT_VERIFIED", "REPRODUCED", "SUPERSEDED",
    "READY_FOR_ACCEPTANCE", "CONTEXT_READY",
};

static bool proof_event_hex(const char *value, bool optional)
{
    if (optional && value && !value[0]) return true;
    if (!value || strlen(value) != BUILD_PROOF_EVENT_ROOT_HEX) return false;
    for (size_t i = 0; i < BUILD_PROOF_EVENT_ROOT_HEX; i++)
        if (!((value[i] >= '0' && value[i] <= '9') ||
              (value[i] >= 'a' && value[i] <= 'f')))
            return false;
    return true;
}

static int proof_event_state_code(const char *state)
{
    if (!state) return -1;
    for (size_t i = 0; i < sizeof(k_states) / sizeof(k_states[0]); i++)
        if (strcmp(state, k_states[i]) == 0) return (int)i + 1;
    return -1;
}

static bool proof_event_before_validate(void *record, void *ctx)
{
    struct db_build_proof_event *row = record;
    (void)ctx;
    if (!row) return false;
    model_trim_ascii(row->state);
    if (row->created_at == 0)
        row->created_at = (int64_t)platform_time_wall_unix();
    return true;
}

DEFINE_MODEL_BEFORE_VALIDATE_READY(
    build_proof_event, proof_event_before_validate)

bool db_build_proof_event_root(
    const struct db_build_proof_event *row,
    char out_hex[BUILD_PROOF_EVENT_ROOT_HEX + 1])
{
    if (!row || !out_hex || proof_event_state_code(row->state) < 0 ||
        !proof_event_hex(row->prior_event_root, true) ||
        !proof_event_hex(row->action_id, false) ||
        !proof_event_hex(row->source_root_sha3, true) ||
        !proof_event_hex(row->task_root_sha3, false) ||
        !proof_event_hex(row->candidate_root_sha3, false) ||
        !proof_event_hex(row->proof_policy_root_sha3, false) ||
        !proof_event_hex(row->context_root_sha3, true) ||
        !proof_event_hex(row->receipt_root_sha3, true) ||
        row->workspace[0] != '/' ||
        strlen(row->workspace) > BUILD_PROOF_EVENT_WORKSPACE_MAX ||
        row->deadline_at < 0 || row->elapsed_us < 0 || row->created_at <= 0)
        return false;
    static const char domain_v1[] = "zcl.build_proof_event.v1";
    static const char domain_v2[] = "zcl.build_proof_event.v2";
    struct sha3_256_ctx sha;
    uint8_t digest[32], root[32], number[8], state;
    sha3_256_init(&sha);
    const char *domain = row->source_root_sha3[0] ? domain_v2 : domain_v1;
    sha3_256_write(&sha, (const uint8_t *)domain, sizeof(domain_v1));
    const char *roots[] = {
        row->prior_event_root, row->action_id, row->source_root_sha3,
        row->task_root_sha3,
        row->candidate_root_sha3, row->proof_policy_root_sha3,
        row->context_root_sha3, row->receipt_root_sha3,
    };
    for (size_t i = 0; i < sizeof(roots) / sizeof(roots[0]); i++) {
        if (i == 2u && !row->source_root_sha3[0]) continue;
        memset(root, 0, sizeof(root));
        if (roots[i][0] && !zcl_hex_decode_lower(roots[i], root, 32))
            return false;
        sha3_256_write(&sha, root, sizeof(root));
    }
    size_t workspace_len = strlen(row->workspace);
    zcl_write_u64_le(number, workspace_len);
    sha3_256_write(&sha, number, sizeof(number));
    sha3_256_write(&sha, (const uint8_t *)row->workspace, workspace_len);
    state = (uint8_t)proof_event_state_code(row->state);
    sha3_256_write(&sha, &state, sizeof(state));
    zcl_write_u64_le(number, row->peer_id);
    sha3_256_write(&sha, number, sizeof(number));
    zcl_write_u64_le(number, row->request_id);
    sha3_256_write(&sha, number, sizeof(number));
    zcl_write_i64_le(number, row->deadline_at);
    sha3_256_write(&sha, number, sizeof(number));
    zcl_write_i64_le(number, row->elapsed_us);
    sha3_256_write(&sha, number, sizeof(number));
    zcl_write_i64_le(number, row->created_at);
    sha3_256_write(&sha, number, sizeof(number));
    sha3_256_finalize(&sha, digest);
    zcl_hex_encode(digest, sizeof(digest), out_hex);
    return true;
}

bool db_build_proof_event_validate(
    const struct db_build_proof_event *row, struct ar_errors *errors)
{
    ar_errors_clear(errors);
    if (!row) {
        validates_custom(errors, false, "record", "is null");
        return false;
    }
    char expected[BUILD_PROOF_EVENT_ROOT_HEX + 1];
    validates_custom(errors, proof_event_hex(row->event_root, false),
                     "event_root", "must be a lowercase SHA3 root");
    validates_custom(errors, proof_event_hex(row->prior_event_root, true),
                     "prior_event_root", "must be empty or a SHA3 root");
    validates_custom(errors, proof_event_hex(row->action_id, false),
                     "action_id", "must be a lowercase action root");
    validates_custom(errors, proof_event_hex(row->source_root_sha3, true),
                     "source_root_sha3", "must be empty or a source root");
    validates_custom(errors, proof_event_hex(row->task_root_sha3, false),
                     "task_root_sha3", "must be a lowercase task root");
    validates_custom(errors,
                     proof_event_hex(row->candidate_root_sha3, false),
                     "candidate_root_sha3", "must be a candidate root");
    validates_custom(errors,
                     proof_event_hex(row->proof_policy_root_sha3, false),
                     "proof_policy_root_sha3", "must be a policy root");
    validates_custom(errors, proof_event_hex(row->context_root_sha3, true),
                     "context_root_sha3", "must be empty or a context root");
    validates_custom(errors, proof_event_hex(row->receipt_root_sha3, true),
                     "receipt_root_sha3", "must be empty or a receipt root");
    validates_custom(errors, row->workspace[0] == '/' &&
                     strlen(row->workspace) <= BUILD_PROOF_EVENT_WORKSPACE_MAX,
                     "workspace", "must be an absolute local locator");
    validates_custom(errors, proof_event_state_code(row->state) > 0,
                     "state", "is not an async proof state");
    validates_custom(errors, row->peer_id <= (uint64_t)INT64_MAX, "peer_id",
                     "must fit the local peer-session identity");
    validates_non_negative(errors, row, deadline_at);
    validates_non_negative(errors, row, elapsed_us);
    validates_custom(errors, row->created_at > 0, "created_at",
                     "must be positive");
    validates_custom(errors,
                     db_build_proof_event_root(row, expected) &&
                         strcmp(expected, row->event_root) == 0,
                     "event_root", "does not bind the event fields");
    return !ar_errors_any(errors);
}

bool db_build_proof_event_save(
    struct node_db *ndb, const struct db_build_proof_event *row)
{
    sqlite3_stmt *st = NULL;
    if (!ndb || !ndb->open || !row)
        LOG_FAIL("model", "db_build_proof_event_save: bad args");
    uint8_t request_id[8];
    zcl_write_u64_le(request_id, row->request_id);
    AR_ADHOC_SAVE(ndb, st,
        "INSERT INTO build_proof_events "
        "(event_root,prior_event_root,action_id,source_root_sha3,task_root_sha3,"
        "candidate_root_sha3,proof_policy_root_sha3,context_root_sha3,"
        "receipt_root_sha3,workspace,state,peer_id,request_id,deadline_at,elapsed_us,"
        "created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        build_proof_event_callbacks_ready(), "build_proof_event", row,
        db_build_proof_event_validate,
        AR_BIND_TEXT(st, 1, row->event_root);
        AR_BIND_TEXT(st, 2, row->prior_event_root);
        AR_BIND_TEXT(st, 3, row->action_id);
        AR_BIND_TEXT(st, 4, row->source_root_sha3);
        AR_BIND_TEXT(st, 5, row->task_root_sha3);
        AR_BIND_TEXT(st, 6, row->candidate_root_sha3);
        AR_BIND_TEXT(st, 7, row->proof_policy_root_sha3);
        AR_BIND_TEXT(st, 8, row->context_root_sha3);
        AR_BIND_TEXT(st, 9, row->receipt_root_sha3);
        AR_BIND_TEXT(st, 10, row->workspace);
        AR_BIND_TEXT(st, 11, row->state);
        AR_BIND_INT(st, 12, row->peer_id);
        AR_BIND_BLOB(st, 13, request_id, sizeof(request_id));
        AR_BIND_INT(st, 14, row->deadline_at);
        AR_BIND_INT(st, 15, row->elapsed_us);
        AR_BIND_INT(st, 16, row->created_at));
}

static bool proof_event_read(sqlite3_stmt *st,
                             struct db_build_proof_event *out)
{
    memset(out, 0, sizeof(*out));
#define PROOF_EVENT_TEXT(column, field) do { \
    const unsigned char *value = sqlite3_column_text(st, (column)); \
    if (!value) return false; \
    (void)snprintf(out->field, sizeof(out->field), "%s", value); \
} while (0)
    PROOF_EVENT_TEXT(0, event_root);
    PROOF_EVENT_TEXT(1, prior_event_root);
    PROOF_EVENT_TEXT(2, action_id);
    PROOF_EVENT_TEXT(3, source_root_sha3);
    PROOF_EVENT_TEXT(4, task_root_sha3);
    PROOF_EVENT_TEXT(5, candidate_root_sha3);
    PROOF_EVENT_TEXT(6, proof_policy_root_sha3);
    PROOF_EVENT_TEXT(7, context_root_sha3);
    PROOF_EVENT_TEXT(8, receipt_root_sha3);
    PROOF_EVENT_TEXT(9, workspace);
    PROOF_EVENT_TEXT(10, state);
#undef PROOF_EVENT_TEXT
    out->peer_id = (uint64_t)sqlite3_column_int64(st, 11);
    const uint8_t *request_id = sqlite3_column_blob(st, 12);
    if (!request_id || sqlite3_column_bytes(st, 12) != 8) return false;
    out->request_id = zcl_read_u64_le(request_id);
    out->deadline_at = sqlite3_column_int64(st, 13);
    out->elapsed_us = sqlite3_column_int64(st, 14);
    out->created_at = sqlite3_column_int64(st, 15);
    struct ar_errors errors;
    return db_build_proof_event_validate(out, &errors);
}

static const char k_event_select[] =
    "SELECT event_root,prior_event_root,action_id,source_root_sha3,task_root_sha3,"
    "candidate_root_sha3,proof_policy_root_sha3,context_root_sha3,"
    "receipt_root_sha3,workspace,state,peer_id,request_id,deadline_at,elapsed_us,"
    "created_at "
    "FROM build_proof_events ";

bool db_build_proof_event_latest(
    struct node_db *ndb, const char *action_id,
    struct db_build_proof_event *out)
{
    if (!ndb || !ndb->open || !action_id || !out) return false;
    char sql[768];
    (void)snprintf(sql, sizeof(sql), "%s%s", k_event_select,
                   "WHERE action_id=? ORDER BY rowid DESC LIMIT 1");
    sqlite3_stmt *st = NULL;
    AR_PREPARE_BOOL(ndb, st, sql);
    AR_BIND_TEXT(st, 1, action_id);
    bool ok = AR_STEP_ROW(st) && proof_event_read(st, out);
    AR_FINALIZE(st);
    return ok;
}

bool db_build_proof_event_requested(
    struct node_db *ndb, const char *action_id, uint64_t request_id_value,
    struct db_build_proof_event *out)
{
    if (!ndb || !ndb->open || !action_id || !out) return false;
    char sql[768];
    (void)snprintf(sql, sizeof(sql), "%s%s", k_event_select,
        "WHERE action_id=? AND state='REQUESTED' AND request_id=? LIMIT 1");
    sqlite3_stmt *st = NULL;
    AR_PREPARE_BOOL(ndb, st, sql);
    uint8_t request_id[8];
    zcl_write_u64_le(request_id, request_id_value);
    AR_BIND_TEXT(st, 1, action_id);
    AR_BIND_BLOB(st, 2, request_id, sizeof(request_id));
    bool ok = AR_STEP_ROW(st) && proof_event_read(st, out);
    AR_FINALIZE(st);
    return ok;
}

int db_build_proof_events_pending(
    struct node_db *ndb, struct db_build_proof_event *out, size_t max)
{
    if (!ndb || !ndb->open || !out || max == 0) return 0;
    static const char sql[] =
        "SELECT e.event_root,e.prior_event_root,e.action_id,e.source_root_sha3,e.task_root_sha3,"
        "e.candidate_root_sha3,e.proof_policy_root_sha3,e.context_root_sha3,"
        "e.receipt_root_sha3,e.workspace,e.state,e.peer_id,e.request_id,e.deadline_at,"
        "e.elapsed_us,e.created_at FROM build_proof_events e WHERE NOT EXISTS "
        "(SELECT 1 FROM build_proof_events newer WHERE "
        "newer.action_id=e.action_id AND newer.rowid>e.rowid) AND e.state "
        "NOT IN ('REPRODUCED','SUPERSEDED',"
        "'READY_FOR_ACCEPTANCE') ORDER BY e.created_at,e.action_id LIMIT ?";
    sqlite3_stmt *st = NULL;
    AR_PREPARE_RET(ndb, st, sql, 0);
    AR_BIND_INT(st, 1, max);
    int count = 0;
    while ((size_t)count < max && AR_STEP_ROW(st)) {
        if (!proof_event_read(st, &out[count])) {
            AR_FINALIZE(st);
            return 0;
        }
        count++;
    }
    AR_FINALIZE(st);
    return count;
}

int db_build_proof_events_for_task(
    struct node_db *ndb, const char *task_root,
    struct db_build_proof_event *out, size_t max)
{
    if (!ndb || !ndb->open || !task_root || !out || max == 0) return 0;
    static const char sql[] =
        "SELECT e.event_root,e.prior_event_root,e.action_id,e.source_root_sha3,e.task_root_sha3,"
        "e.candidate_root_sha3,e.proof_policy_root_sha3,e.context_root_sha3,"
        "e.receipt_root_sha3,e.workspace,e.state,e.peer_id,e.request_id,e.deadline_at,"
        "e.elapsed_us,e.created_at FROM build_proof_events e WHERE "
        "e.task_root_sha3=? "
        "AND NOT EXISTS (SELECT 1 FROM build_proof_events newer WHERE "
        "newer.action_id=e.action_id AND newer.rowid>e.rowid) "
        "ORDER BY e.created_at,e.action_id LIMIT ?";
    sqlite3_stmt *st = NULL;
    AR_PREPARE_RET(ndb, st, sql, 0);
    AR_BIND_TEXT(st, 1, task_root);
    AR_BIND_INT(st, 2, max);
    int count = 0;
    while ((size_t)count < max && AR_STEP_ROW(st)) {
        if (!proof_event_read(st, &out[count])) {
            AR_FINALIZE(st);
            return 0;
        }
        count++;
    }
    AR_FINALIZE(st);
    return count;
}

int db_build_proof_events_for_action(
    struct node_db *ndb, const char *action_id,
    struct db_build_proof_event *out, size_t max)
{
    if (!ndb || !ndb->open || !action_id || !out || max == 0) return 0;
    char sql[768];
    (void)snprintf(sql, sizeof(sql), "%s%s", k_event_select,
                   "WHERE action_id=? ORDER BY rowid LIMIT ?");
    sqlite3_stmt *st = NULL;
    AR_PREPARE_RET(ndb, st, sql, 0);
    AR_BIND_TEXT(st, 1, action_id);
    AR_BIND_INT(st, 2, max);
    int count = 0;
    while ((size_t)count < max && AR_STEP_ROW(st)) {
        if (!proof_event_read(st, &out[count])) {
            AR_FINALIZE(st);
            return 0;
        }
        count++;
    }
    AR_FINALIZE(st);
    return count;
}
