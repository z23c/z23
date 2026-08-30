/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ActiveRecord persistence and deterministic relationships for immutable,
 * host-scoped signed App events. */
// suffix-ok:immutable-signed-app-event-model

#include "models/app_event.h"
#include "models/query_builder.h"

#include "util/log_macros.h"

#include <limits.h>
#include <sqlite3.h>
#include <string.h>

DEFINE_MODEL_CALLBACKS(app_event)

/* Three projections, each matching one row reader below. Naming the column
 * order once is the point: a reader and its SELECT can no longer drift. */

/* app_event_existing() — every signed field, no cursor. */
static const enum qb_column k_app_event_signed_cols[] = {
    QB_C_app_events_app_id,            QB_C_app_events_topic,
    QB_C_app_events_kind,              QB_C_app_events_chain_id,
    QB_C_app_events_author_key_id,     QB_C_app_events_author_pubkey,
    QB_C_app_events_sequence,          QB_C_app_events_previous_event_id,
    QB_C_app_events_created_at,        QB_C_app_events_payload,
    QB_C_app_events_signature,         QB_C_app_events_signature_len,
};

/* app_event_read() — the full row. */
static const enum qb_column k_app_event_full_cols[] = {
    QB_C_app_events_receive_cursor,    QB_C_app_events_event_id,
    QB_C_app_events_app_id,            QB_C_app_events_topic,
    QB_C_app_events_kind,              QB_C_app_events_chain_id,
    QB_C_app_events_author_key_id,     QB_C_app_events_author_pubkey,
    QB_C_app_events_sequence,          QB_C_app_events_previous_event_id,
    QB_C_app_events_created_at,        QB_C_app_events_payload,
    QB_C_app_events_signature,         QB_C_app_events_signature_len,
    QB_C_app_events_received_at,
};

/* app_event_ref_read() — the index-only listing row. */
static const enum qb_column k_app_event_ref_cols[] = {
    QB_C_app_events_receive_cursor,    QB_C_app_events_event_id,
    QB_C_app_events_app_id,            QB_C_app_events_topic,
    QB_C_app_events_kind,              QB_C_app_events_author_key_id,
    QB_C_app_events_sequence,          QB_C_app_events_previous_event_id,
    QB_C_app_events_created_at,        QB_C_app_events_received_at,
};

#define QB_NCOLS(a) (sizeof(a) / sizeof((a)[0]))

static const uint8_t g_empty_payload[1] = {0};

static bool bytes_nonzero(const uint8_t *bytes, size_t len)
{
    uint8_t any = 0;
    if (!bytes)
        return false;
    for (size_t i = 0; i < len; i++)
        any |= bytes[i];
    return any != 0;
}

static bool bounded_token(const char *value, size_t max_len)
{
    if (!value)
        return false;
    const char *end = memchr(value, 0, max_len + 1);
    if (!end || end == value)
        return false;
    for (const unsigned char *p = (const unsigned char *)value;
         p < (const unsigned char *)end; p++) {
        if ((*p >= '0' && *p <= '9') ||
            (*p >= 'A' && *p <= 'Z') ||
            (*p >= 'a' && *p <= 'z') ||
            *p == '_' || *p == '-' || *p == '.')
            continue;
        return false;
    }
    return true;
}

static bool app_event_signature_valid(
    const struct zcl_app_signed_event_v1 *event,
    const struct zcl_app_event_scope_v1 *scope)
{
    char why[256];
    return scope && zcl_app_signed_event_v1_verify(
        event, scope, why, sizeof(why));
}

bool db_app_event_validate(const struct db_app_event *record,
                           struct ar_errors *errors)
{
    ar_errors_clear(errors);
    if (!record) {
        validates_custom(errors, false, "app_event", "is null");
        return false;
    }
    const struct zcl_app_signed_event_v1 *event = &record->event;
    validates_custom(errors, event->struct_size >= sizeof(*event),
                     "struct_size", "is too small");
    validates_custom(errors, event->version == ZCL_APP_SIGNED_EVENT_V1,
                     "version", "is unsupported");
    validates_custom(errors, bounded_token(event->app_id, ZCL_APP_ID_MAX),
                     "app_id", "is not canonical");
    validates_custom(errors, bounded_token(event->topic, ZCL_APP_TOPIC_MAX),
                     "topic", "is not canonical");
    validates_custom(errors, event->kind > 0,
                     "kind", "must be positive");
    validates_custom(errors, event->sequence > 0 && event->sequence <= INT64_MAX,
                     "sequence", "is outside storage range");
    validates_custom(errors,
                     event->created_at > 0 && event->created_at <= INT64_MAX,
                     "created_at", "is outside storage range");
    validates_custom(errors, bytes_nonzero(event->event_id, 32),
                     "event_id", "is empty");
    validates_custom(errors, bytes_nonzero(event->chain_id, 32),
                     "chain_id", "is empty");
    validates_custom(errors, bytes_nonzero(event->author_key_id, 20),
                     "author_key_id", "is empty");
    validates_custom(errors,
                     event->payload.len <= ZCL_APP_EVENT_PAYLOAD_MAX &&
                     (event->payload.len == 0 || event->payload.data),
                     "payload", "is absent or oversized");
    validates_custom(errors,
                     event->signature_len >= 8 &&
                     event->signature_len <= ZCL_APP_EVENT_SIGNATURE_MAX,
                     "signature", "length is invalid");
    validates_custom(errors, record->receive_cursor >= 0,
                     "receive_cursor", "must be non-negative");
    validates_custom(errors, record->received_at > 0,
                     "received_at", "must be positive");
    return !ar_errors_any(errors);
}

static bool column_blob_equals(sqlite3_stmt *s, int column,
                               const void *bytes, size_t len)
{
    const void *stored = sqlite3_column_blob(s, column);
    int stored_len = sqlite3_column_bytes(s, column);
    return stored_len == (int)len &&
        (len == 0 || (stored && memcmp(stored, bytes, len) == 0));
}

static bool column_text_equals(sqlite3_stmt *s, int column, const char *text)
{
    const char *stored = (const char *)sqlite3_column_text(s, column);
    return stored && text && strcmp(stored, text) == 0;
}

enum app_event_existing_state {
    APP_EVENT_ABSENT = 0,
    APP_EVENT_SAME = 1,
    APP_EVENT_CONFLICT = 2,
    APP_EVENT_READ_ERROR = 3,
};

static enum app_event_existing_state app_event_existing(
    struct node_db *ndb, const struct zcl_app_signed_event_v1 *event)
{
    struct qb q;
    qb_select(&q, QB_T_app_events);
    qb_select_columns(&q, k_app_event_signed_cols,
                      QB_NCOLS(k_app_event_signed_cols));
    qb_where_blob(&q, QB_C_app_events_event_id, QB_EQ, event->event_id, 32);
    sqlite3_stmt *s = NULL;
    if (!QB_PREPARE(ndb, &q, s)) {
        LOG_WARN("app_event", "existing-event query prepare failed: %s",
                 qb_error(&q));
        return APP_EVENT_READ_ERROR;
    }
    int rc = sqlite3_step(s); // raw-sql-ok:model-read-only-existence
    if (rc == SQLITE_DONE) {
        sqlite3_finalize(s);
        return APP_EVENT_ABSENT;
    }
    if (rc != SQLITE_ROW) {
        LOG_WARN("app_event", "existing-event query failed rc=%d: %s",
                 rc, sqlite3_errmsg(ndb->db));
        sqlite3_finalize(s);
        return APP_EVENT_READ_ERROR;
    }
    bool same = column_text_equals(s, 0, event->app_id) &&
        column_text_equals(s, 1, event->topic) &&
        AR_COL_INT(s, 2) == (int64_t)event->kind &&
        column_blob_equals(s, 3, event->chain_id, 32) &&
        column_blob_equals(s, 4, event->author_key_id, 20) &&
        column_blob_equals(s, 5, event->author_pubkey, 33) &&
        AR_COL_INT(s, 6) == (int64_t)event->sequence &&
        column_blob_equals(s, 7, event->previous_event_id, 32) &&
        AR_COL_INT(s, 8) == (int64_t)event->created_at &&
        column_blob_equals(s, 9, event->payload.data, event->payload.len) &&
        column_blob_equals(s, 10, event->signature, event->signature_len) &&
        AR_COL_INT(s, 11) == (int64_t)event->signature_len;
    sqlite3_finalize(s);
    return same ? APP_EVENT_SAME : APP_EVENT_CONFLICT;
}

bool db_app_event_save(struct node_db *ndb,
                       const struct db_app_event *record,
                       const struct zcl_app_event_scope_v1 *scope)
{
    if (!ndb || !ndb->open || !record || !scope)
        LOG_FAIL("app_event", "save requires database, event, and host scope");
    struct ar_callbacks *cbs = db_app_event_callbacks();
    struct ar_errors errors;
    if (!db_app_event_validate(record, &errors))
        LOG_FAIL("app_event", "validation failed: %s",
                 ar_errors_full(&errors));
    if (!app_event_signature_valid(&record->event, scope))
        LOG_FAIL("app_event", "signature, identity, or host scope is invalid");

    const struct zcl_app_signed_event_v1 *event = &record->event;
    AR_BEGIN_SAVE(cbs, "app_event", record, db_app_event_validate);

    static const enum qb_column k_conflict[] = { QB_C_app_events_event_id };
    struct qb q;
    qb_insert(&q, QB_T_app_events, QB_INSERT_PLAIN);
    qb_value_blob(&q, QB_C_app_events_event_id, event->event_id, 32);
    qb_value_text(&q, QB_C_app_events_app_id, event->app_id);
    qb_value_text(&q, QB_C_app_events_topic, event->topic);
    qb_value_int(&q, QB_C_app_events_kind, event->kind);
    qb_value_blob(&q, QB_C_app_events_chain_id, event->chain_id, 32);
    qb_value_blob(&q, QB_C_app_events_author_key_id, event->author_key_id, 20);
    qb_value_blob(&q, QB_C_app_events_author_pubkey, event->author_pubkey, 33);
    qb_value_int(&q, QB_C_app_events_sequence, (int64_t)event->sequence);
    qb_value_blob(&q, QB_C_app_events_previous_event_id,
                  event->previous_event_id, 32);
    qb_value_int(&q, QB_C_app_events_created_at, (int64_t)event->created_at);
    qb_value_blob(&q, QB_C_app_events_payload,
                  event->payload.len ? event->payload.data : g_empty_payload,
                  event->payload.len);
    qb_value_blob(&q, QB_C_app_events_signature, event->signature,
                  event->signature_len);
    qb_value_int(&q, QB_C_app_events_signature_len, event->signature_len);
    qb_value_int(&q, QB_C_app_events_received_at, record->received_at);
    qb_on_conflict_do_nothing(&q, k_conflict, 1);
    qb_returning(&q, QB_C_app_events_event_id);

    sqlite3_stmt *s = NULL;
    if (!QB_PREPARE(ndb, &q, s))
        LOG_FAIL("app_event", "atomic event insert refused: %s",
                 qb_error(&q));
    int rc = sqlite3_step(s); // raw-sql-ok:ar-lifecycle-conflict-returning
    bool inserted = rc == SQLITE_ROW;
    AR_FINALIZE(s);
    if (!inserted && rc != SQLITE_DONE)
        LOG_FAIL("app_event", "atomic event insert failed rc=%d: %s",
                 rc, sqlite3_errmsg(ndb->db));
    if (!inserted) {
        enum app_event_existing_state existing = app_event_existing(
            ndb, event);
        if (existing == APP_EVENT_CONFLICT)
            LOG_FAIL("app_event",
                     "event_id already belongs to different bytes");
        if (existing != APP_EVENT_SAME)
            LOG_FAIL("app_event", "could not establish event_id ownership");
    }
    AR_FINISH_SAVE(cbs, record, true);
}

static bool app_event_read(sqlite3_stmt *s, struct db_app_event *out,
                           uint8_t *payload, size_t payload_capacity)
{
    if (!s || !out)
        return false;
    int payload_len = AR_COL_BYTES(s, 11);
    int signature_len = AR_COL_BYTES(s, 12);
    int signature_len_column = (int)AR_COL_INT(s, 13);
    const void *payload_blob = sqlite3_column_blob(s, 11);
    if (AR_COL_BYTES(s, 1) != 32 || AR_COL_BYTES(s, 5) != 32 ||
        AR_COL_BYTES(s, 6) != 20 || AR_COL_BYTES(s, 7) != 33 ||
        AR_COL_BYTES(s, 9) != 32 || payload_len < 0 ||
        (size_t)payload_len > ZCL_APP_EVENT_PAYLOAD_MAX ||
        (size_t)payload_len > payload_capacity ||
        signature_len < 8 ||
        signature_len > (int)ZCL_APP_EVENT_SIGNATURE_MAX ||
        signature_len != signature_len_column ||
        (payload_len > 0 && (!payload || !payload_blob)))
        return false;
    memset(out, 0, sizeof(*out));
    out->receive_cursor = AR_COL_INT(s, 0);
    out->event.struct_size = sizeof(out->event);
    out->event.version = ZCL_APP_SIGNED_EVENT_V1;
    AR_READ_BLOB(s, 1, out->event.event_id, 32);
    AR_READ_STR(s, 2, out->event.app_id, sizeof(out->event.app_id));
    AR_READ_STR(s, 3, out->event.topic, sizeof(out->event.topic));
    out->event.kind = (uint32_t)AR_COL_INT(s, 4);
    AR_READ_BLOB(s, 5, out->event.chain_id, 32);
    AR_READ_BLOB(s, 6, out->event.author_key_id, 20);
    AR_READ_BLOB(s, 7, out->event.author_pubkey, 33);
    out->event.sequence = (uint64_t)AR_COL_INT(s, 8);
    AR_READ_BLOB(s, 9, out->event.previous_event_id, 32);
    out->event.created_at = (uint64_t)AR_COL_INT(s, 10);
    if (payload_len > 0)
        memcpy(payload, payload_blob, (size_t)payload_len);
    out->event.payload.data = payload;
    out->event.payload.len = (size_t)payload_len;
    AR_READ_BLOB(s, 12, out->event.signature, (size_t)signature_len);
    out->event.signature_len = (uint32_t)signature_len;
    out->received_at = AR_COL_INT(s, 14);
    return true;
}

bool db_app_event_find(struct node_db *ndb, const uint8_t event_id[32],
                       const struct zcl_app_event_scope_v1 *scope,
                       struct db_app_event *out,
                       uint8_t *payload, size_t payload_capacity)
{
    if (!ndb || !ndb->open || !event_id || !scope || !out ||
        (!payload && payload_capacity > 0))
        LOG_FAIL("app_event", "find requires valid arguments");
    struct qb q;
    qb_select(&q, QB_T_app_events);
    qb_select_columns(&q, k_app_event_full_cols,
                      QB_NCOLS(k_app_event_full_cols));
    qb_where_blob(&q, QB_C_app_events_event_id, QB_EQ, event_id, 32);
    sqlite3_stmt *s = NULL;
    if (!QB_PREPARE(ndb, &q, s))
        LOG_FAIL("app_event", "find refused: %s", qb_error(&q));
    if (!AR_STEP_ROW(s)) {
        AR_FINALIZE(s);
        return false;
    }
    bool ok = app_event_read(s, out, payload, payload_capacity);
    AR_FINALIZE(s);
    struct ar_errors errors;
    if (ok)
        ok = db_app_event_validate(out, &errors) &&
             app_event_signature_valid(&out->event, scope);
    if (!ok)
        LOG_FAIL("app_event",
                 "stored event is corrupt, unverifiable, or payload buffer is short");
    return true;
}

int db_app_event_count(struct node_db *ndb, const char *app_id,
                       const char *topic_or_null)
{
    if (!ndb || !ndb->open || !bounded_token(app_id, ZCL_APP_ID_MAX))
        return 0;
    bool by_topic = topic_or_null && topic_or_null[0];
    if (by_topic && !bounded_token(topic_or_null, ZCL_APP_TOPIC_MAX))
        return 0;
    struct qb q;
    qb_select(&q, QB_T_app_events);
    qb_select_count_star(&q);
    qb_where_text(&q, QB_C_app_events_app_id, QB_EQ, app_id);
    if (by_topic)
        qb_where_text(&q, QB_C_app_events_topic, QB_EQ, topic_or_null);
    QB_QUERY_COUNT(ndb, &q, s);
}

static void app_event_ref_read(sqlite3_stmt *s,
                               struct db_app_event_ref *out)
{
    memset(out, 0, sizeof(*out));
    out->receive_cursor = AR_COL_INT(s, 0);
    AR_READ_BLOB(s, 1, out->event_id, 32);
    AR_READ_STR(s, 2, out->app_id, sizeof(out->app_id));
    AR_READ_STR(s, 3, out->topic, sizeof(out->topic));
    out->kind = (uint32_t)AR_COL_INT(s, 4);
    AR_READ_BLOB(s, 5, out->author_key_id, 20);
    out->sequence = (uint64_t)AR_COL_INT(s, 6);
    AR_READ_BLOB(s, 7, out->previous_event_id, 32);
    out->created_at = AR_COL_INT(s, 8);
    out->received_at = AR_COL_INT(s, 9);
}

int db_app_event_topic_after(struct node_db *ndb,
                             const char *app_id, const char *topic,
                             int64_t after_cursor,
                             struct db_app_event_ref *out, size_t max)
{
    if (!ndb || !ndb->open || !out || max == 0 || after_cursor < 0 ||
        !bounded_token(app_id, ZCL_APP_ID_MAX) ||
        !bounded_token(topic, ZCL_APP_TOPIC_MAX))
        return 0;
    struct qb q;
    qb_select(&q, QB_T_app_events);
    qb_select_columns(&q, k_app_event_ref_cols,
                      QB_NCOLS(k_app_event_ref_cols));
    qb_where_text(&q, QB_C_app_events_app_id, QB_EQ, app_id);
    qb_where_text(&q, QB_C_app_events_topic, QB_EQ, topic);
    qb_where_int(&q, QB_C_app_events_receive_cursor, QB_GT, after_cursor);
    qb_order_by(&q, QB_C_app_events_receive_cursor, QB_ASC);
    qb_limit(&q, (int64_t)max);
    QB_QUERY_LIST(ndb, &q, s, out, max, app_event_ref_read(s, &out[count]));
}

bool db_app_event_previous(struct node_db *ndb,
                           const struct db_app_event *record,
                           const struct zcl_app_event_scope_v1 *scope,
                           struct db_app_event *out,
                           uint8_t *payload, size_t payload_capacity)
{
    if (!ndb || !ndb->open || !record || !scope || !out ||
        record->event.sequence <= 1)
        return false;
    if (!db_app_event_find(ndb, record->event.previous_event_id,
                           scope,
                           out, payload, payload_capacity))
        return false;
    if (strcmp(out->event.app_id, record->event.app_id) != 0 ||
        strcmp(out->event.topic, record->event.topic) != 0 ||
        memcmp(out->event.chain_id, record->event.chain_id, 32) != 0 ||
        memcmp(out->event.author_key_id,
               record->event.author_key_id, 20) != 0 ||
        out->event.sequence == UINT64_MAX ||
        out->event.sequence + 1 != record->event.sequence)
        LOG_FAIL("app_event", "previous-event relationship identity drifted");
    return true;
}

int db_app_event_successors(struct node_db *ndb,
                            const struct db_app_event *record,
                            const struct zcl_app_event_scope_v1 *scope,
                            struct db_app_event_ref *out, size_t max)
{
    if (!ndb || !ndb->open || !record || !scope || !out || max == 0 ||
        record->event.sequence >= (uint64_t)INT64_MAX ||
        !app_event_signature_valid(&record->event, scope))
        return 0;
    struct qb q;
    qb_select(&q, QB_T_app_events);
    qb_select_columns(&q, k_app_event_ref_cols,
                      QB_NCOLS(k_app_event_ref_cols));
    qb_where_text(&q, QB_C_app_events_app_id, QB_EQ, record->event.app_id);
    qb_where_text(&q, QB_C_app_events_topic, QB_EQ, record->event.topic);
    qb_where_blob(&q, QB_C_app_events_chain_id, QB_EQ,
                  record->event.chain_id, 32);
    qb_where_blob(&q, QB_C_app_events_author_key_id, QB_EQ,
                  record->event.author_key_id, 20);
    qb_where_blob(&q, QB_C_app_events_previous_event_id, QB_EQ,
                  record->event.event_id, 32);
    qb_where_int(&q, QB_C_app_events_sequence, QB_EQ,
                 (int64_t)(record->event.sequence + 1));
    qb_order_by(&q, QB_C_app_events_event_id, QB_ASC);
    qb_limit(&q, (int64_t)max);
    QB_QUERY_LIST(ndb, &q, s, out, max, app_event_ref_read(s, &out[count]));
}
