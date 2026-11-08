/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Owner-consented local hosting state; this model never publishes. */
#include "models/app_host_intent.h"
#include "models/database.h"
#include "models/db_txn.h"
#include "models/query_builder.h"
#include "models/model_fields.h"
#include "models/def/app_host_intent_fields.def"
#include "vcs/app_offer.h"
#include "base/safe_alloc.h"
#include <limits.h>
#include <sqlite3.h>
#include <stdlib.h>
#include <string.h>

#define HOST_SLOT_SECONDS INT64_C(43200)
#define HOST_TTL_SECONDS 86400u

DEFINE_MODEL_CALLBACKS(app_host_intent)

static bool host_nonzero(const uint8_t *p, size_t n)
{
    uint8_t any = 0;
    for (size_t i = 0; i < n; ++i) any |= p[i];
    return any != 0;
}

static bool host_binding_valid(const struct app_host_binding *b)
{
    if (!b || !b->recurring || !host_nonzero(b->local_host, sizeof(b->local_host)) ||
        strnlen(b->name, sizeof(b->name)) == sizeof(b->name) ||
        strnlen(b->publisher, sizeof(b->publisher)) == sizeof(b->publisher) ||
        strnlen(b->release_root, sizeof(b->release_root)) == sizeof(b->release_root) ||
        strnlen(b->carrier_root, sizeof(b->carrier_root)) == sizeof(b->carrier_root) ||
        strnlen(b->sha256, sizeof(b->sha256)) == sizeof(b->sha256)) return false;
    struct zcl_app_offer o = {0};
    memcpy(o.name, b->name, sizeof(o.name));
    memcpy(o.publisher, b->publisher, sizeof(o.publisher));
    memcpy(o.root, b->release_root, sizeof(o.root));
    memcpy(o.carrier, b->carrier_root, sizeof(o.carrier));
    memcpy(o.sha256, b->sha256, sizeof(o.sha256));
    o.size = b->size;
    memcpy(o.onion, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion:1", 65);
    return zcl_app_offer_valid(&o);
}

static bool host_offer_matches(const struct app_host_binding *b,
    const struct zcl_app_offer *o, const char *endpoint)
{
    return !strcmp(o->name, b->name) && !strcmp(o->publisher, b->publisher) &&
        !strcmp(o->root, b->release_root) && !strcmp(o->carrier, b->carrier_root) &&
        !strcmp(o->sha256, b->sha256) && o->size == b->size &&
        !strcmp(o->onion, endpoint);
}

static bool host_post_bound(const struct db_app_host_intent *r,
                            const struct fleet_board_post *post)
{
    return post->kind == FLEET_BOARD_KIND_OFFER && post->scope == FLEET_BOARD_SCOPE_PUBLIC &&
        !strcmp(post->room, "apps") && post->ttl == HOST_TTL_SECONDS &&
        post->created_at <= (uint64_t)(INT64_MAX - HOST_TTL_SECONDS) &&
        !memcmp(post->host_pubkey, r->binding.local_host, 32) &&
        !memcmp(post->id, r->pending_id, 32) && !memcmp(post->id, r->slot_post_id, 32) &&
        post->created_at == r->pending_created_at && r->pending_generation == r->generation &&
        r->renewal_slot == (int64_t)(post->created_at / HOST_SLOT_SECONDS) + 1;
}

static bool host_wire_valid(const struct db_app_host_intent *r,
                            struct fleet_board_post *post)
{
    struct zcl_app_offer offer = {0};
    uint8_t canonical[APP_HOST_WIRE_MAX];
    size_t canonical_len = 0;
    if (!r->pending || r->pending_wire_len == 0 || r->pending_wire_len > APP_HOST_WIRE_MAX ||
        fleet_board_post_decode(r->pending_wire, r->pending_wire_len, post) != FLEET_BOARD_OK ||
        !host_post_bound(r, post) ||
        !zcl_app_offer_parse(post->text, post->text_len, &offer) ||
        fleet_board_post_encode(post, canonical, sizeof(canonical), &canonical_len) != FLEET_BOARD_OK ||
        canonical_len != r->pending_wire_len || memcmp(canonical, r->pending_wire, canonical_len)) return false;
    return host_offer_matches(&r->binding, &offer, r->slot_endpoint);
}

static void host_validate_pending(const struct db_app_host_intent *r, struct ar_errors *errors)
{
    if (r->pending) {
        struct fleet_board_post post = {0};
        validates_custom(errors, r->enabled && host_wire_valid(r, &post), "pending", "is invalid or unbound");
    } else {
        validates_custom(errors, !r->pending_wire_len && !host_nonzero(r->pending_id, 32) &&
            !r->pending_created_at && !r->pending_generation, "pending", "is inconsistent");
    }
}

static void host_validate_state(const struct db_app_host_intent *r, struct ar_errors *errors)
{
    bool endpoint_ok = strnlen(r->slot_endpoint, sizeof(r->slot_endpoint)) < sizeof(r->slot_endpoint);
    if (endpoint_ok && r->renewal_slot == 0)
        endpoint_ok = !r->slot_endpoint[0] && !host_nonzero(r->slot_post_id, 32) && !r->replacement_count;
    else if (endpoint_ok)
        endpoint_ok = vcs_app_offer_peer_is_onion(r->slot_endpoint) && host_nonzero(r->slot_post_id, 32);
    validates_custom(errors, endpoint_ok, "slot", "is inconsistent");
    if (!r->enabled)
        validates_custom(errors, !r->pending && !r->due_at && !r->retry_count && !r->renewal_slot,
                         "enabled", "disabled intent has work");
    host_validate_pending(r, errors);
}

bool db_app_host_intent_validate(const struct db_app_host_intent *r,
                                 struct ar_errors *errors)
{
    ar_errors_clear(errors);
    if (!r) { validates_custom(errors, false, "record", "is null"); return false; }
    validates_custom(errors, host_binding_valid(&r->binding), "binding", "is invalid");
    validates_custom(errors, r->generation > 0 && r->due_at >= 0 && r->renewal_slot >= 0,
                     "generation", "or timing is invalid");
    validates_custom(errors, !r->enabled || r->generation < INT64_MAX,
                     "generation", "must allow revocation");
    validates_custom(errors, r->retry_count <= APP_HOST_RETRY_MAX &&
        r->replacement_count <= APP_HOST_REPLACEMENT_MAX, "retry", "or replacement is invalid");
    host_validate_state(r, errors);
    return !ar_errors_any(errors);
}

#define HOST_INDEX(kind, col, member, extra) ZCL_MF_CAT(HOST_COL_, col),
enum host_column_index { ZCL_MODEL_EXPAND(HOST_INDEX, APP_HOST_INTENT_FIELDS) };
#define HOST_QB_COLUMN(kind, col, member, extra) ZCL_MF_CAT(QB_C_app_host_intents_, col),
static const enum qb_column k_host_columns[] = {
    ZCL_MODEL_EXPAND(HOST_QB_COLUMN, APP_HOST_INTENT_FIELDS)
};
#define HOST_NCOLS (sizeof(k_host_columns) / sizeof(k_host_columns[0]))

static bool host_text(sqlite3_stmt *s, int col, char *out, size_t cap)
{
    if (sqlite3_column_type(s, col) != SQLITE_TEXT) return false;
    const char *v = AR_COL_TEXT(s, col); int n = AR_COL_BYTES(s, col);
    if (!v || n < 0 || (size_t)n >= cap || strlen(v) != (size_t)n) return false;
    memcpy(out, v, (size_t)n + 1u); return true;
}

static bool host_blob(sqlite3_stmt *s, int col, uint8_t *out, size_t exact)
{
    if (sqlite3_column_type(s, col) != SQLITE_BLOB || AR_COL_BYTES(s, col) != (int)exact) return false;
    const void *v = sqlite3_column_blob(s, col);
    if (exact && !v) return false;
    if (exact) memcpy(out, v, exact);
    return true;
}

static bool host_ints(sqlite3_stmt *s)
{
    static const int cols[] = {HOST_COL_size, HOST_COL_recurring, HOST_COL_enabled,
        HOST_COL_generation, HOST_COL_due_at, HOST_COL_renewal_slot,
        HOST_COL_retry_count, HOST_COL_replacement_count, HOST_COL_pending,
        HOST_COL_pending_created_at, HOST_COL_pending_generation};
    for (size_t i = 0; i < sizeof(cols)/sizeof(cols[0]); ++i)
        if (sqlite3_column_type(s, cols[i]) != SQLITE_INTEGER) return false;
    return true;
}

static bool host_read_identity(sqlite3_stmt *s, struct db_app_host_intent *r)
{
    if (!host_ints(s) || !host_blob(s, HOST_COL_local_host, r->binding.local_host, 32) ||
        !host_text(s, HOST_COL_carrier_root, r->binding.carrier_root, sizeof(r->binding.carrier_root)) ||
        !host_text(s, HOST_COL_name, r->binding.name, sizeof(r->binding.name)) ||
        !host_text(s, HOST_COL_publisher, r->binding.publisher, sizeof(r->binding.publisher)) ||
        !host_text(s, HOST_COL_release_root, r->binding.release_root, sizeof(r->binding.release_root)) ||
        !host_text(s, HOST_COL_sha256, r->binding.sha256, sizeof(r->binding.sha256)) ||
        !host_text(s, HOST_COL_slot_endpoint, r->slot_endpoint, sizeof(r->slot_endpoint)) ||
        !host_blob(s, HOST_COL_slot_post_id, r->slot_post_id, 32) ||
        !host_blob(s, HOST_COL_pending_id, r->pending_id, 32)) return false;
    return true;
}

static bool host_read_flags(int64_t recurring, int64_t enabled, int64_t pending,
                            int64_t retry, int64_t replacements)
{
    return (recurring == 0 || recurring == 1) && (enabled == 0 || enabled == 1) &&
        (pending == 0 || pending == 1) && retry >= 0 && retry <= APP_HOST_RETRY_MAX &&
        replacements >= 0 && replacements <= APP_HOST_REPLACEMENT_MAX;
}

static bool host_read(sqlite3_stmt *s, struct db_app_host_intent *r)
{
    memset(r, 0, sizeof(*r));
    if (!host_read_identity(s, r)) return false;
    int64_t recurring = AR_COL_INT(s,HOST_COL_recurring), enabled = AR_COL_INT(s,HOST_COL_enabled);
    int64_t pending = AR_COL_INT(s,HOST_COL_pending), retry = AR_COL_INT(s,HOST_COL_retry_count);
    int64_t replacements = AR_COL_INT(s,HOST_COL_replacement_count), created = AR_COL_INT(s,HOST_COL_pending_created_at);
    int bytes = AR_COL_BYTES(s,HOST_COL_pending_wire);
    if (!host_read_flags(recurring,enabled,pending,retry,replacements) || created < 0 ||
        bytes < 0 || (size_t)bytes > sizeof(r->pending_wire) ||
        !host_blob(s,HOST_COL_pending_wire,r->pending_wire,(size_t)bytes)) return false;
    r->binding.size = AR_COL_INT(s,HOST_COL_size); r->binding.recurring = recurring != 0;
    r->enabled = enabled != 0; r->generation = AR_COL_INT(s,HOST_COL_generation);
    r->due_at = AR_COL_INT(s,HOST_COL_due_at); r->renewal_slot = AR_COL_INT(s,HOST_COL_renewal_slot);
    r->retry_count = (uint32_t)retry; r->replacement_count = (uint32_t)replacements;
    r->pending = pending != 0; r->pending_wire_len = (size_t)bytes;
    r->pending_created_at = (uint64_t)created; r->pending_generation = AR_COL_INT(s,HOST_COL_pending_generation);
    struct ar_errors errors; return db_app_host_intent_validate(r, &errors);
}

static void host_key(struct qb *q, const uint8_t host[32], const char *carrier)
{
    qb_where_blob(q, QB_C_app_host_intents_local_host, QB_EQ, host, 32);
    qb_where_text(q, QB_C_app_host_intents_carrier_root, QB_EQ, carrier);
}

enum app_host_result db_app_host_intent_find(struct node_db *db,
    const uint8_t host[32], const char *carrier, struct db_app_host_intent *out)
{
    if (out) memset(out, 0, sizeof(*out));
    if (!db || !db->open || !host || !host_nonzero(host, 32) ||
        !vcs_app_offer_hex_valid(carrier, 32) || !out) return APP_HOST_INVALID;
    struct qb q; qb_select(&q, QB_T_app_host_intents);
    qb_select_columns(&q, k_host_columns, HOST_NCOLS); host_key(&q, host, carrier);
    sqlite3_stmt *s = NULL;
    if (!QB_PREPARE(db, &q, s)) return APP_HOST_STORAGE;
    /* Checked step is needed: absence and a failed read are different states. */
    int rc = sqlite3_step(s); // raw-sql-ok:checked-read-status
    if (rc == SQLITE_DONE) { AR_FINALIZE(s); return APP_HOST_NOT_FOUND; }
    if (rc != SQLITE_ROW) { AR_FINALIZE(s); return APP_HOST_STORAGE; }
    struct db_app_host_intent row;
    bool valid = host_read(s, &row);
    rc = sqlite3_step(s); // raw-sql-ok:checked-read-status
    AR_FINALIZE(s);
    if (!valid) return APP_HOST_CORRUPT;
    if (rc != SQLITE_DONE) return APP_HOST_STORAGE;
    *out = row; return APP_HOST_OK;
}

static enum app_host_result host_due_rows(sqlite3_stmt *s, struct db_app_host_intent *rows,
    size_t capacity, struct db_app_host_intent *out, size_t *count, bool *more)
{
    size_t n = 0; int rc;
    while ((rc = sqlite3_step(s)) == SQLITE_ROW) { // raw-sql-ok:checked-read-status
        if (n > capacity || !host_read(s, &rows[n])) return APP_HOST_CORRUPT;
        ++n;
    }
    if (rc != SQLITE_DONE) return APP_HOST_STORAGE;
    *more = n > capacity; *count = n < capacity ? n : capacity;
    memcpy(out, rows, *count * sizeof(*out)); return APP_HOST_OK;
}

enum app_host_result db_app_host_intent_due(struct node_db *db, const uint8_t host[32], int64_t now,
    struct db_app_host_intent *out, size_t capacity, size_t *count, bool *more)
{
    if (count) *count = 0;
    if (more) *more = false;
    if (!db || !db->open || !host || !host_nonzero(host,32) || now < 0 || !out || !count || !more ||
        !capacity || capacity > APP_HOST_DUE_MAX) return APP_HOST_INVALID;
    memset(out, 0, capacity * sizeof(*out));
    struct db_app_host_intent *rows = zcl_calloc(capacity + 1u, sizeof(*rows), "app_host_intent/due");
    if (!rows) return APP_HOST_STORAGE;
    struct qb q; qb_select(&q, QB_T_app_host_intents);
    qb_select_columns(&q, k_host_columns, HOST_NCOLS);
    qb_where_blob(&q, QB_C_app_host_intents_local_host, QB_EQ, host, 32);
    qb_where_int(&q, QB_C_app_host_intents_enabled, QB_EQ, 1);
    qb_where_int(&q, QB_C_app_host_intents_due_at, QB_LE, now);
    qb_order_by(&q, QB_C_app_host_intents_due_at, QB_ASC);
    qb_order_by(&q, QB_C_app_host_intents_local_host, QB_ASC);
    qb_order_by(&q, QB_C_app_host_intents_carrier_root, QB_ASC);
    qb_limit(&q, (int64_t)capacity + 1);
    sqlite3_stmt *s = NULL; enum app_host_result result = APP_HOST_STORAGE;
    if (QB_PREPARE(db, &q, s)) {
        result = host_due_rows(s, rows, capacity, out, count, more);
        AR_FINALIZE(s);
    }
    free(rows); return result;
}

static bool host_binding_same(const struct app_host_binding *a, const struct app_host_binding *b)
{
    return !memcmp(a->local_host,b->local_host,32) && !strcmp(a->carrier_root,b->carrier_root) &&
        !strcmp(a->name,b->name) && !strcmp(a->publisher,b->publisher) &&
        !strcmp(a->release_root,b->release_root) && !strcmp(a->sha256,b->sha256) &&
        a->size == b->size && a->recurring == b->recurring;
}

static void host_values(struct qb *q, const struct db_app_host_intent *r)
{
    qb_value_blob(q,QB_C_app_host_intents_local_host,r->binding.local_host,32);
    qb_value_text(q,QB_C_app_host_intents_carrier_root,r->binding.carrier_root);
    qb_value_text(q,QB_C_app_host_intents_name,r->binding.name);
    qb_value_text(q,QB_C_app_host_intents_publisher,r->binding.publisher);
    qb_value_text(q,QB_C_app_host_intents_release_root,r->binding.release_root);
    qb_value_text(q,QB_C_app_host_intents_sha256,r->binding.sha256);
    qb_value_int(q,QB_C_app_host_intents_size,r->binding.size);
    qb_value_int(q,QB_C_app_host_intents_recurring,r->binding.recurring);
    qb_value_int(q,QB_C_app_host_intents_enabled,r->enabled);
    qb_value_int(q,QB_C_app_host_intents_generation,r->generation);
    qb_value_int(q,QB_C_app_host_intents_due_at,r->due_at);
    qb_value_int(q,QB_C_app_host_intents_renewal_slot,r->renewal_slot);
    qb_value_int(q,QB_C_app_host_intents_retry_count,r->retry_count);
    qb_value_int(q,QB_C_app_host_intents_replacement_count,r->replacement_count);
    qb_value_text(q,QB_C_app_host_intents_slot_endpoint,r->slot_endpoint);
    qb_value_blob(q,QB_C_app_host_intents_slot_post_id,r->slot_post_id,32);
    qb_value_int(q,QB_C_app_host_intents_pending,r->pending);
    qb_value_blob(q,QB_C_app_host_intents_pending_wire,r->pending_wire,r->pending_wire_len);
    qb_value_blob(q,QB_C_app_host_intents_pending_id,r->pending_id,32);
    qb_value_int(q,QB_C_app_host_intents_pending_created_at,(int64_t)r->pending_created_at);
    qb_value_int(q,QB_C_app_host_intents_pending_generation,r->pending_generation);
}

static void host_sets(struct qb *q, const struct db_app_host_intent *r)
{
    qb_set_int(q,QB_C_app_host_intents_enabled,r->enabled);
    qb_set_int(q,QB_C_app_host_intents_generation,r->generation);
    qb_set_int(q,QB_C_app_host_intents_due_at,r->due_at);
    qb_set_int(q,QB_C_app_host_intents_renewal_slot,r->renewal_slot);
    qb_set_int(q,QB_C_app_host_intents_retry_count,r->retry_count);
    qb_set_int(q,QB_C_app_host_intents_replacement_count,r->replacement_count);
    qb_set_text(q,QB_C_app_host_intents_slot_endpoint,r->slot_endpoint);
    qb_set_blob(q,QB_C_app_host_intents_slot_post_id,r->slot_post_id,32);
    qb_set_int(q,QB_C_app_host_intents_pending,r->pending);
    qb_set_blob(q,QB_C_app_host_intents_pending_wire,r->pending_wire,r->pending_wire_len);
    qb_set_blob(q,QB_C_app_host_intents_pending_id,r->pending_id,32);
    qb_set_int(q,QB_C_app_host_intents_pending_created_at,(int64_t)r->pending_created_at);
    qb_set_int(q,QB_C_app_host_intents_pending_generation,r->pending_generation);
}

static bool host_save(struct node_db *db, const struct db_app_host_intent *row,
                      bool create, int64_t old_generation)
{
    struct ar_callbacks *cbs = db_app_host_intent_callbacks();
    AR_BEGIN_SAVE(cbs, "app_host_intent", row, db_app_host_intent_validate);
    struct qb q;
    if (create) { qb_insert(&q, QB_T_app_host_intents, QB_INSERT_PLAIN); host_values(&q, row); }
    else {
        qb_update(&q, QB_T_app_host_intents); host_sets(&q, row);
        host_key(&q, row->binding.local_host, row->binding.carrier_root);
        qb_where_int(&q, QB_C_app_host_intents_generation, QB_EQ, old_generation);
    }
    sqlite3_stmt *s = NULL;
    if (!QB_PREPARE(db, &q, s)) return false;
    bool ok = AR_STEP_DONE(s); AR_FINALIZE(s);
    ok = ok && sqlite3_changes(db->db) == 1;
    AR_FINISH_SAVE(cbs, row, ok);
}

static enum app_host_result host_begin(struct node_db *db, struct db_txn **txn)
{
    if (!db || !db->open) return APP_HOST_INVALID;
    struct node_db_status status; node_db_get_status(db, &status);
    if (status.tx_open) return APP_HOST_BUSY;
    *txn = db_txn_begin(db, "app-host-intent");
    return *txn ? APP_HOST_OK : APP_HOST_STORAGE;
}

static enum app_host_result host_finish(struct db_txn *txn, enum app_host_result result)
{
    if (result == APP_HOST_OK) return db_txn_commit(txn) ? APP_HOST_OK : APP_HOST_STORAGE;
    db_txn_rollback(txn); return result;
}

static void host_clear_pending(struct db_app_host_intent *r)
{
    r->pending = false; r->pending_wire_len = 0;
    memset(r->pending_wire, 0, sizeof(r->pending_wire));
    memset(r->pending_id, 0, sizeof(r->pending_id));
    r->pending_created_at = 0; r->pending_generation = 0;
}

static enum app_host_result host_enable_existing(enum app_host_result result,
    bool create, int64_t expected, const struct db_app_host_intent *row,
    const struct app_host_binding *binding)
{
    if (create) return expected == 0 ? APP_HOST_OK : APP_HOST_STALE;
    if (result != APP_HOST_OK) return result;
    if (row->generation != expected) return APP_HOST_STALE;
    return !host_binding_same(&row->binding, binding) || row->enabled ? APP_HOST_CONFLICT : APP_HOST_OK;
}

enum app_host_result db_app_host_intent_enable(struct node_db *db,
    const struct app_host_binding *binding, int64_t expected_generation, int64_t due_at)
{
    if (!host_binding_valid(binding) || expected_generation < 0 || due_at < 0 ||
        expected_generation >= INT64_MAX - 1) return APP_HOST_INVALID;
    struct db_txn *txn = NULL; enum app_host_result result = host_begin(db, &txn);
    if (result != APP_HOST_OK) return result;
    struct db_app_host_intent row;
    result = db_app_host_intent_find(db, binding->local_host, binding->carrier_root, &row);
    bool create = result == APP_HOST_NOT_FOUND;
    result = host_enable_existing(result, create, expected_generation, &row, binding);
    if (create && result == APP_HOST_OK) { memset(&row,0,sizeof(row)); row.binding = *binding; }
    if (result == APP_HOST_OK) {
        row.enabled = true; row.generation = expected_generation + 1; row.due_at = due_at;
        row.retry_count = 0; row.renewal_slot = 0; row.replacement_count = 0;
        row.slot_endpoint[0] = 0; memset(row.slot_post_id,0,32); host_clear_pending(&row);
        if (!host_save(db,&row,create,expected_generation)) result = APP_HOST_STORAGE;
    }
    return host_finish(txn,result);
}

static enum app_host_result host_locked_row(struct node_db *db, const uint8_t host[32],
    const char *carrier, int64_t generation, struct db_app_host_intent *row)
{
    if (generation <= 0) return APP_HOST_INVALID;
    enum app_host_result result = db_app_host_intent_find(db,host,carrier,row);
    if (result != APP_HOST_OK) return result;
    if (row->generation != generation) return APP_HOST_STALE;
    return row->enabled ? APP_HOST_OK : APP_HOST_CONFLICT;
}

static bool host_new_wire(struct db_app_host_intent *row, const char *endpoint,
                          const uint8_t *wire, size_t wire_len, int64_t now)
{
    if (!endpoint || strnlen(endpoint,sizeof(row->slot_endpoint)) >= sizeof(row->slot_endpoint) ||
        !vcs_app_offer_peer_is_onion(endpoint) || !wire || !wire_len ||
        wire_len > sizeof(row->pending_wire) || now < 0) return false;
    struct fleet_board_post post = {0};
    if (fleet_board_post_decode(wire,wire_len,&post) != FLEET_BOARD_OK ||
        post.created_at > (uint64_t)(INT64_MAX - HOST_TTL_SECONDS) ||
        post.created_at > (uint64_t)now || (int64_t)post.created_at + HOST_TTL_SECONDS <= now ||
        (int64_t)(post.created_at / HOST_SLOT_SECONDS) != now / HOST_SLOT_SECONDS) return false;
    row->renewal_slot = (int64_t)(post.created_at / HOST_SLOT_SECONDS) + 1;
    memcpy(row->slot_endpoint,endpoint,strlen(endpoint)+1u);
    memcpy(row->slot_post_id,post.id,32); row->pending = true;
    memcpy(row->pending_wire,wire,wire_len); row->pending_wire_len = wire_len;
    memcpy(row->pending_id,post.id,32); row->pending_created_at = post.created_at;
    row->pending_generation = row->generation;
    return host_wire_valid(row,&post);
}

static bool host_wire_input(const char *endpoint, const uint8_t *wire, size_t len, int64_t now)
{
    return now >= 0 && endpoint &&
        strnlen(endpoint, APP_HOST_ENDPOINT_MAX + 1u) <= APP_HOST_ENDPOINT_MAX &&
        vcs_app_offer_peer_is_onion(endpoint) && wire && len && len <= APP_HOST_WIRE_MAX;
}

static enum app_host_result host_reserve_row(struct node_db *db,
    struct db_app_host_intent *row, int64_t generation, int64_t slot,
    int64_t now, const char *endpoint, const uint8_t *wire, size_t wire_len)
{
    if (row->pending) {
        return row->renewal_slot == slot && !strcmp(row->slot_endpoint,endpoint) &&
            row->pending_wire_len == wire_len && !memcmp(row->pending_wire,wire,wire_len)
            ? APP_HOST_OK : APP_HOST_CONFLICT;
    }
    int64_t previous = row->renewal_slot;
    if (slot < previous || (slot == previous &&
        (!strcmp(row->slot_endpoint,endpoint) || row->replacement_count >= APP_HOST_REPLACEMENT_MAX)))
        return APP_HOST_CONFLICT;
    if (slot == previous) ++row->replacement_count;
    else row->replacement_count = 0;
    if (!host_new_wire(row,endpoint,wire,wire_len,now) || row->renewal_slot != slot)
        return APP_HOST_INVALID;
    return host_save(db,row,false,generation) ? APP_HOST_OK : APP_HOST_STORAGE;
}

enum app_host_result db_app_host_intent_reserve(struct node_db *db,
    const uint8_t host[32], const char *carrier, int64_t generation,
    int64_t slot, int64_t now, const char *endpoint, const uint8_t *wire, size_t wire_len)
{
    if (slot <= 0 || !host_wire_input(endpoint,wire,wire_len,now))
        return APP_HOST_INVALID;
    struct db_txn *txn = NULL; enum app_host_result result = host_begin(db,&txn);
    if (result != APP_HOST_OK) return result;
    struct db_app_host_intent row;
    result = host_locked_row(db,host,carrier,generation,&row);
    if (result == APP_HOST_OK)
        result = host_reserve_row(db,&row,generation,slot,now,endpoint,wire,wire_len);
    return host_finish(txn,result);
}

static bool host_replacement_allowed(const struct db_app_host_intent *row,
                                     const char *endpoint, int64_t slot)
{
    return strcmp(row->slot_endpoint, endpoint) && slot >= row->renewal_slot &&
        (slot > row->renewal_slot || row->replacement_count < APP_HOST_REPLACEMENT_MAX);
}

enum app_host_result db_app_host_intent_replace_absent(struct node_db *db,
    const uint8_t host[32], const char *carrier, int64_t generation,
    const uint8_t old_id[32], int64_t now, const char *endpoint,
    const uint8_t *wire, size_t wire_len)
{
    if (!old_id || !host_nonzero(old_id,32) || !host_wire_input(endpoint,wire,wire_len,now))
        return APP_HOST_INVALID;
    struct db_txn *txn = NULL; enum app_host_result result = host_begin(db,&txn);
    if (result != APP_HOST_OK) return result;
    struct db_app_host_intent row;
    result = host_locked_row(db,host,carrier,generation,&row);
    if (result == APP_HOST_OK && (!row.pending || memcmp(row.pending_id,old_id,32))) result = APP_HOST_STALE;
    int64_t new_slot = now / HOST_SLOT_SECONDS + 1;
    if (result == APP_HOST_OK && !host_replacement_allowed(&row,endpoint,new_slot))
        result = APP_HOST_CONFLICT;
    if (result == APP_HOST_OK) {
        int64_t old_slot = row.renewal_slot;
        row.replacement_count = new_slot == old_slot ? row.replacement_count + 1u : 0;
        if (!host_new_wire(&row,endpoint,wire,wire_len,now) || row.renewal_slot != new_slot)
            result = APP_HOST_INVALID;
        else if (!host_save(db,&row,false,generation)) result = APP_HOST_STORAGE;
    }
    return host_finish(txn,result);
}

static bool host_pending_matches(const struct db_app_host_intent *row, const uint8_t *id)
{
    return id ? row->pending && !memcmp(row->pending_id,id,32) : !row->pending;
}

static enum app_host_result host_schedule(struct node_db *db, const uint8_t host[32],
    const char *carrier, int64_t generation, const uint8_t *id,
    int64_t due_at, uint32_t retry_count, bool clear)
{
    if (due_at < 0 || retry_count > APP_HOST_RETRY_MAX || (clear && !id)) return APP_HOST_INVALID;
    struct db_txn *txn = NULL; enum app_host_result result = host_begin(db,&txn);
    if (result != APP_HOST_OK) return result;
    struct db_app_host_intent row;
    result = host_locked_row(db,host,carrier,generation,&row);
    if (result == APP_HOST_OK && !host_pending_matches(&row,id)) result = APP_HOST_STALE;
    if (result == APP_HOST_OK && !clear && retry_count < row.retry_count) result = APP_HOST_INVALID;
    if (result == APP_HOST_OK) {
        row.due_at = due_at; row.retry_count = retry_count;
        if (clear) host_clear_pending(&row);
        if (!host_save(db,&row,false,generation)) result = APP_HOST_STORAGE;
    }
    return host_finish(txn,result);
}

enum app_host_result db_app_host_intent_reconcile(struct node_db *db,
    const uint8_t host[32], const char *carrier, int64_t generation,
    const uint8_t id[32], int64_t due_at, uint32_t retry_count)
{ return host_schedule(db,host,carrier,generation,id,due_at,retry_count,true); }

enum app_host_result db_app_host_intent_defer(struct node_db *db,
    const uint8_t host[32], const char *carrier, int64_t generation,
    const uint8_t id[32], int64_t due_at, uint32_t retry_count)
{ return host_schedule(db,host,carrier,generation,id,due_at,retry_count,false); }

enum app_host_result db_app_host_intent_retire_expired(struct node_db *db,
    const uint8_t host[32], const char *carrier, int64_t generation,
    const uint8_t id[32], int64_t now)
{
    if (!id || now < 0) return APP_HOST_INVALID;
    struct db_txn *txn = NULL; enum app_host_result result = host_begin(db,&txn);
    if (result != APP_HOST_OK) return result;
    struct db_app_host_intent row;
    result = host_locked_row(db,host,carrier,generation,&row);
    if (result == APP_HOST_OK && (!row.pending || memcmp(row.pending_id,id,32))) result = APP_HOST_STALE;
    if (result == APP_HOST_OK && (int64_t)row.pending_created_at + HOST_TTL_SECONDS > now)
        result = APP_HOST_CONFLICT;
    if (result == APP_HOST_OK) {
        host_clear_pending(&row);
        if (!host_save(db,&row,false,generation)) result = APP_HOST_STORAGE;
    }
    return host_finish(txn,result);
}

enum app_host_result db_app_host_intent_disable(struct node_db *db,
    const uint8_t host[32], const char *carrier, int64_t generation)
{
    if (generation <= 0 || generation == INT64_MAX) return APP_HOST_INVALID;
    struct db_txn *txn = NULL; enum app_host_result result = host_begin(db,&txn);
    if (result != APP_HOST_OK) return result;
    struct db_app_host_intent row;
    result = host_locked_row(db,host,carrier,generation,&row);
    if (result == APP_HOST_OK) {
        row.enabled = false; row.generation++; row.due_at = 0; row.renewal_slot = 0;
        row.retry_count = 0; row.replacement_count = 0; row.slot_endpoint[0] = 0;
        memset(row.slot_post_id,0,32); host_clear_pending(&row);
        if (!host_save(db,&row,false,generation)) result = APP_HOST_STORAGE;
    }
    return host_finish(txn,result);
}
