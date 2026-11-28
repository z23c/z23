/* purpose: Persist and audit the private Ironwood frontier checkpoint chain. */
/* Copyright 2026 Rhett Creighton - Apache License 2.0 */
#include "storage/ironwood_frontier_store.h"
#include "sha3/sha3.h"
#include "base/serialize_le.h"
#include "util/log_macros.h"
#include "util/ar_step_readonly.h"
#include <sqlite3.h>
#include <limits.h>
#include <string.h>

#define ICS_LIMIT UINT64_C(4294967296)

struct row {
    int64_t height;
    uint8_t block[32], parent[32], root[32], digest[32];
    uint64_t count;
    size_t len;
    uint8_t data[IRONWOOD_CHECKPOINT_MAX_BYTES];
};
static bool payload_valid(const struct row *r)
{
    if (!r->len) return true;
    if (r->count > ICS_LIMIT || r->len < 9 || r->data[0] != 1) return false;
    uint8_t n[8]; zcl_write_u64_le(n, r->count);
    if (memcmp(n, r->data + 1, 8)) return false;
    unsigned bits = 0;
    for (uint64_t v = r->count; v; v >>= 1) bits += (unsigned)(v & 1);
    return r->len == 9 + 32 * (size_t)bits;
}
static void row_digest(const struct row *r, uint8_t out[32])
{
    uint8_t b[32 * 3 + 24 + IRONWOOD_CHECKPOINT_MAX_BYTES];
    zcl_write_u64_le(b, (uint64_t)r->height); zcl_write_u64_le(b + 8, r->count);
    zcl_write_u64_le(b + 16, r->len);
    memcpy(b + 24, r->block, 32); memcpy(b + 56, r->parent, 32);
    memcpy(b + 88, r->root, 32); memcpy(b + 120, r->data, r->len);
    zcl_sha3_256(b, 120 + r->len, out);
}
static bool read_fixed_fields(sqlite3_stmt *s, struct row *r)
{
    const int columns[] = {1, 2, 3, 6};
    uint8_t *outputs[] = {r->block, r->parent, r->root, r->digest};
    for (size_t i = 0; i < sizeof(columns) / sizeof(columns[0]); i++) {
        int column = columns[i];
        if (sqlite3_column_type(s, column) != SQLITE_BLOB) return false;
        const void *blob = sqlite3_column_blob(s, column);
        if (!blob || sqlite3_column_bytes(s, column) != 32) return false;
        memcpy(outputs[i], blob, 32);
    }
    return true;
}
static bool read_fields(sqlite3_stmt *s, struct row *r)
{
    if (sqlite3_column_type(s, 0) != SQLITE_INTEGER ||
        sqlite3_column_type(s, 4) != SQLITE_INTEGER) return false;
    r->height = sqlite3_column_int64(s, 0);
    int64_t count = sqlite3_column_int64(s, 4);
    if (r->height < -1 || count < 0 || (uint64_t)count > ICS_LIMIT ||
        !read_fixed_fields(s, r)) return false;
    r->count = (uint64_t)count;
    return true;
}
static bool read_payload(sqlite3_stmt *s, struct row *r)
{
    int type = sqlite3_column_type(s, 5);
    int len = sqlite3_column_bytes(s, 5);
    if ((type != SQLITE_NULL && type != SQLITE_BLOB) || len < 0 ||
        len > IRONWOOD_CHECKPOINT_MAX_BYTES || (type == SQLITE_BLOB && !len))
        return false;
    r->len = (size_t)len;
    if (r->len) {
        const void *payload = sqlite3_column_blob(s, 5);
        if (!payload) return false;
        memcpy(r->data, payload, r->len);
    }
    return true;
}
static bool read_row(sqlite3_stmt *s, struct row *r)
{
    if (!read_fields(s, r) || !read_payload(s, r)) return false;
    uint8_t digest[32]; row_digest(r, digest);
    return payload_valid(r) && !memcmp(digest, r->digest, 32);
}
static bool state(sqlite3 *db, int64_t *tip, int64_t *generation)
{
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(db, "SELECT tip,generation FROM ironwood_checkpoint_state WHERE id=1", -1, &s, NULL) != SQLITE_OK) return false;
    int rc = sqlite3_step(s); // raw-sql-ok:progress-kv-kernel-store
    bool ok = rc == SQLITE_ROW && sqlite3_column_type(s, 0) == SQLITE_INTEGER &&
        sqlite3_column_type(s, 1) == SQLITE_INTEGER;
    if (ok) { *tip = sqlite3_column_int64(s, 0); *generation = sqlite3_column_int64(s, 1); ok = *tip >= -1 && *generation >= 0; }
    sqlite3_finalize(s); return ok;
}
static bool valid_session(struct ironwood_checkpoint_session *session, int64_t *tip)
{
    int64_t generation;
    return session && session->db && session->audited &&
        !sqlite3_get_autocommit(session->db) && state(session->db, tip, &generation) && generation == session->generation;
}
static bool write_row(sqlite3 *db, struct row *r)
{
    sqlite3_stmt *s = NULL;
    row_digest(r, r->digest);
    if (sqlite3_prepare_v2(db, "INSERT INTO ironwood_checkpoints(height,block,parent,root,leaf_count,payload,digest) VALUES(?,?,?,?,?,?,?)", -1, &s, NULL) != SQLITE_OK) return false;
    bool ok = sqlite3_bind_int64(s, 1, r->height) == SQLITE_OK &&
        sqlite3_bind_blob(s, 2, r->block, 32, SQLITE_TRANSIENT) == SQLITE_OK &&
        sqlite3_bind_blob(s, 3, r->parent, 32, SQLITE_TRANSIENT) == SQLITE_OK &&
        sqlite3_bind_blob(s, 4, r->root, 32, SQLITE_TRANSIENT) == SQLITE_OK &&
        sqlite3_bind_int64(s, 5, (int64_t)r->count) == SQLITE_OK &&
        (r->len ? sqlite3_bind_blob(s, 6, r->data, (int)r->len, SQLITE_TRANSIENT) : sqlite3_bind_null(s, 6)) == SQLITE_OK &&
        sqlite3_bind_blob(s, 7, r->digest, 32, SQLITE_TRANSIENT) == SQLITE_OK;
    if (ok) ok = sqlite3_step(s) == SQLITE_DONE; // raw-sql-ok:progress-kv-kernel-store
    sqlite3_finalize(s); return ok;
}
/* 0: absent; 1: complete; -1: partial or unreadable. Index names are
 * checked both globally and against their owning table. */
static int checkpoint_schema_state(sqlite3 *db)
{
    static const char sql[] =
        "SELECT (SELECT count(*) FROM sqlite_master WHERE type='table' AND name IN ('ironwood_checkpoints','ironwood_checkpoint_state')),"
        "(SELECT count(*) FROM sqlite_master WHERE type='index' AND name IN ('ironwood_checkpoints_root','ironwood_checkpoints_payload')),"
        "(SELECT count(*) FROM sqlite_master WHERE type='index' AND tbl_name='ironwood_checkpoints' AND name IN ('ironwood_checkpoints_root','ironwood_checkpoints_payload')),"
        "(SELECT count(*) FROM sqlite_master WHERE name IN ('ironwood_checkpoints','ironwood_checkpoint_state','ironwood_checkpoints_root','ironwood_checkpoints_payload'))";
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &s, NULL) != SQLITE_OK) return -1;
    enum zcl_step step = ar_step_checked(s, "Ironwood checkpoint schema probe", NULL);
    int tables = step == ZCL_STEP_ROW ? sqlite3_column_int(s, 0) : -1;
    int indexes = step == ZCL_STEP_ROW ? sqlite3_column_int(s, 1) : -1;
    int owned = step == ZCL_STEP_ROW ? sqlite3_column_int(s, 2) : -1;
    int names = step == ZCL_STEP_ROW ? sqlite3_column_int(s, 3) : -1;
    sqlite3_finalize(s);
    if (names == 0 && tables == 0 && indexes == 0) return 0;
    return names == 4 && tables == 2 && indexes == 2 && owned == 2 ? 1 : -1;
}
bool ironwood_checkpoint_ensure_schema(struct sqlite3 *db)
{
    if (!db || sqlite3_get_autocommit(db)) return false;
    int existing = checkpoint_schema_state(db);
    if (existing == 1) return true;
    if (existing != 0) return false;
    return sqlite3_exec(db,
        "CREATE TABLE ironwood_checkpoint_state(id INTEGER PRIMARY KEY CHECK(id=1),tip INTEGER NOT NULL,generation INTEGER NOT NULL);"
        "CREATE TABLE ironwood_checkpoints(height INTEGER PRIMARY KEY,block BLOB NOT NULL,parent BLOB NOT NULL,root BLOB NOT NULL,leaf_count INTEGER NOT NULL,payload BLOB,digest BLOB NOT NULL);"
        "CREATE INDEX ironwood_checkpoints_root ON ironwood_checkpoints(root,height);"
        "CREATE INDEX ironwood_checkpoints_payload ON ironwood_checkpoints(height) WHERE payload IS NOT NULL;",
        NULL, NULL, NULL) == SQLITE_OK;
}
enum ironwood_checkpoint_probe_result ironwood_checkpoint_probe(struct sqlite3 *db)
{
    if (!db || sqlite3_get_autocommit(db)) return IRONWOOD_CHECKPOINT_PROBE_ERROR;
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(db, "SELECT (SELECT count(*) FROM ironwood_checkpoint_state),(SELECT count(*) FROM ironwood_checkpoints)", -1, &s, NULL) != SQLITE_OK) return IRONWOOD_CHECKPOINT_PROBE_ERROR;
    int rc = sqlite3_step(s); // raw-sql-ok:progress-kv-kernel-store
    int64_t states = rc == SQLITE_ROW ? sqlite3_column_int64(s, 0) : -1;
    int64_t rows = rc == SQLITE_ROW ? sqlite3_column_int64(s, 1) : -1;
    sqlite3_finalize(s);
    if (!states && !rows) return IRONWOOD_CHECKPOINT_UNINITIALIZED;
    int64_t tip, generation;
    if (states == 1 && rows > 0 && state(db, &tip, &generation)) return IRONWOOD_CHECKPOINT_PRESENT;
    return IRONWOOD_CHECKPOINT_PROBE_ERROR;
}

bool ironwood_checkpoint_begin_replay(struct sqlite3 *db, const uint8_t parent_hash[32], const uint8_t empty_root[32])
{
    if (!db || !parent_hash || !empty_root || sqlite3_get_autocommit(db) ||
        ironwood_checkpoint_probe(db) != IRONWOOD_CHECKPOINT_UNINITIALIZED) return false;
    if (sqlite3_exec(db, "INSERT INTO ironwood_checkpoint_state(id,tip,generation) VALUES(1,-1,0)", NULL, NULL, NULL) != SQLITE_OK) return false;
    struct row r = {.height = -1, .len = 9};
    memcpy(r.block, parent_hash, 32); memcpy(r.root, empty_root, 32); r.data[0] = 1;
    return write_row(db, &r);
}
static bool last_row(sqlite3 *db, int64_t height, struct row *r)
{
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(db, "SELECT height,block,parent,root,leaf_count,payload,digest FROM ironwood_checkpoints WHERE height=?", -1, &s, NULL) != SQLITE_OK) return false;
    bool ok = sqlite3_bind_int64(s, 1, height) == SQLITE_OK &&
        ar_step_checked(s, "Ironwood checkpoint by height", NULL) == ZCL_STEP_ROW && read_row(s, r); // raw-sql-ok:progress-kv-kernel-store
    sqlite3_finalize(s); return ok;
}
static bool next_valid(const struct row *prev, const struct row *r)
{
    return prev->height < INT64_MAX && r->height == prev->height + 1 && !memcmp(r->parent, prev->block, 32) &&
        r->count >= prev->count &&
        (r->count != prev->count || !memcmp(r->root, prev->root, 32)) &&
        (r->len || (r->count == prev->count && !memcmp(r->root, prev->root, 32)));
}
static bool valid_audit_row(const struct row *prev, const struct row *current, bool first)
{
    if (first) return current->height == -1 && current->count == 0 && current->len == 9;
    return next_valid(prev, current);
}
bool ironwood_checkpoint_audit(struct sqlite3 *db, struct ironwood_checkpoint_session *session)
{
    if (!db || !session || sqlite3_get_autocommit(db) || checkpoint_schema_state(db) != 1) return false;
    int64_t tip, generation;
    if (!state(db, &tip, &generation)) return false;
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(db, "SELECT height,block,parent,root,leaf_count,payload,digest FROM ironwood_checkpoints ORDER BY height", -1, &s, NULL) != SQLITE_OK) return false;
    struct row prev = {0}, current = {0};
    bool first = true, ok = true;
    int rc;
    while ((rc = sqlite3_step(s)) == SQLITE_ROW) { // raw-sql-ok:progress-kv-kernel-store
        if (!read_row(s, &current) || !valid_audit_row(&prev, &current, first)) { ok = false; break; }
        prev = current; first = false;
    }
    if (rc != SQLITE_DONE || first || prev.height != tip) ok = false;
    sqlite3_finalize(s);
    if (!ok) return false;
    struct ironwood_checkpoint_session staged = {.db = db, .generation = generation, .audited = true};
    *session = staged; return true;
}
bool ironwood_checkpoint_refresh(struct sqlite3 *db, struct ironwood_checkpoint_session *session)
{
    int64_t tip;
    if (!db || !session || sqlite3_get_autocommit(db)) return false;
    if (session->db == db && valid_session(session, &tip)) return true;
    return ironwood_checkpoint_audit(db, session);
}

static bool update_tip(sqlite3 *db, int64_t old_generation, int64_t tip)
{
    sqlite3_stmt *s = NULL;
    if (old_generation == INT64_MAX || sqlite3_prepare_v2(db, "UPDATE ironwood_checkpoint_state SET tip=?,generation=generation+1 WHERE id=1 AND generation=?", -1, &s, NULL) != SQLITE_OK) return false;
    bool ok = sqlite3_bind_int64(s, 1, tip) == SQLITE_OK &&
        sqlite3_bind_int64(s, 2, old_generation) == SQLITE_OK &&
        sqlite3_step(s) == SQLITE_DONE && sqlite3_changes(db) == 1; // raw-sql-ok:progress-kv-kernel-store
    sqlite3_finalize(s); return ok;
}
static bool append_inputs(int64_t tip, int64_t height, const uint8_t *block_hash,
    const uint8_t *parent_hash, const uint8_t *root, uint64_t count,
    const uint8_t *payload, size_t payload_size)
{
    return block_hash && parent_hash && root && tip != INT64_MAX &&
        height == tip + 1 && count <= ICS_LIMIT &&
        payload_size <= IRONWOOD_CHECKPOINT_MAX_BYTES &&
        ((payload && payload_size) || (!payload && !payload_size));
}

bool ironwood_checkpoint_append(struct ironwood_checkpoint_session *session,
    int64_t height, const uint8_t block_hash[32], const uint8_t parent_hash[32],
    const uint8_t root[32], uint64_t count, const uint8_t *payload, size_t payload_size)
{
    int64_t tip;
    if (!valid_session(session, &tip) ||
        !append_inputs(tip, height, block_hash, parent_hash, root, count, payload, payload_size)) return false;
    struct row prev = {0}, current = {.height = height, .count = count, .len = payload_size};
    if (!last_row(session->db, tip, &prev)) return false;
    memcpy(current.block, block_hash, 32); memcpy(current.parent, parent_hash, 32);
    memcpy(current.root, root, 32);
    if (payload_size) memcpy(current.data, payload, payload_size);
    if (!payload_valid(&current) || !next_valid(&prev, &current)) return false;
    if (!write_row(session->db, &current) || !update_tip(session->db, session->generation, height)) {
        session->audited = false; return false;
    }
    session->generation++; return true;
}
static enum ironwood_checkpoint_result select_row(sqlite3 *db, int64_t height,
    const uint8_t *root, struct row *selected)
{
    const char *sql = root ?
        "SELECT height,block,parent,root,leaf_count,payload,digest FROM ironwood_checkpoints WHERE root=? AND height>=0 AND height<? ORDER BY height DESC LIMIT 1" :
        "SELECT height,block,parent,root,leaf_count,payload,digest FROM ironwood_checkpoints WHERE height<? ORDER BY height DESC LIMIT 1";
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &s, NULL) != SQLITE_OK) return IRONWOOD_CHECKPOINT_ERROR;
    int index = 1;
    bool ok = !root || sqlite3_bind_blob(s, index++, root, 32, SQLITE_TRANSIENT) == SQLITE_OK;
    ok = ok && sqlite3_bind_int64(s, index, height) == SQLITE_OK;
    int rc = ok ? sqlite3_step(s) : SQLITE_ERROR; // raw-sql-ok:progress-kv-kernel-store
    ok = rc == SQLITE_ROW && read_row(s, selected);
    sqlite3_finalize(s);
    if (rc == SQLITE_DONE) return IRONWOOD_CHECKPOINT_MISSING;
    if (!ok || (!root && selected->height != height - 1)) return IRONWOOD_CHECKPOINT_ERROR;
    return IRONWOOD_CHECKPOINT_FOUND;
}
static bool resolve_payload(sqlite3 *db, const struct row *selected, struct row *payload)
{
    *payload = *selected;
    if (selected->len) return true;
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(db, "SELECT height,block,parent,root,leaf_count,payload,digest FROM ironwood_checkpoints WHERE height<? AND payload IS NOT NULL ORDER BY height DESC LIMIT 1", -1, &s, NULL) != SQLITE_OK) return false;
    bool ok = sqlite3_bind_int64(s, 1, selected->height) == SQLITE_OK &&
        ar_step_checked(s, "Ironwood checkpoint payload", NULL) == ZCL_STEP_ROW && read_row(s, payload); // raw-sql-ok:progress-kv-kernel-store
    sqlite3_finalize(s);
    return ok && payload->count == selected->count && !memcmp(payload->root, selected->root, 32);
}
static enum ironwood_checkpoint_result lookup(struct ironwood_checkpoint_session *session,
    int64_t candidate_height, const uint8_t *root, struct ironwood_checkpoint *out)
{
    int64_t tip;
    if (!out || candidate_height < 0 || !valid_session(session, &tip)) return IRONWOOD_CHECKPOINT_INCOMPLETE;
    if (tip == INT64_MAX || candidate_height > tip + 1) return IRONWOOD_CHECKPOINT_INCOMPLETE;
    struct row selected = {0}, payload = {0};
    enum ironwood_checkpoint_result result = select_row(session->db, candidate_height, root, &selected);
    if (result != IRONWOOD_CHECKPOINT_FOUND) return result;
    if (!resolve_payload(session->db, &selected, &payload)) return IRONWOOD_CHECKPOINT_ERROR;
    struct ironwood_checkpoint staged = {.height = selected.height, .count = selected.count, .payload_size = payload.len};
    memcpy(staged.block_hash, selected.block, 32); memcpy(staged.root, selected.root, 32);
    memcpy(staged.payload, payload.data, payload.len); *out = staged;
    return IRONWOOD_CHECKPOINT_FOUND;
}
enum ironwood_checkpoint_result ironwood_checkpoint_latest_before(struct ironwood_checkpoint_session *session, int64_t height, struct ironwood_checkpoint *out)
{ return lookup(session, height, NULL, out); }
enum ironwood_checkpoint_result ironwood_checkpoint_find_root(struct ironwood_checkpoint_session *session, int64_t height, const uint8_t root[32], struct ironwood_checkpoint *out)
{ return root ? lookup(session, height, root, out) : IRONWOOD_CHECKPOINT_ERROR; }
static bool checkpoint_tables_empty(sqlite3 *db)
{
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(db, "SELECT 1 FROM ironwood_checkpoints UNION ALL SELECT 1 FROM ironwood_checkpoint_state LIMIT 1", -1, &s, NULL) != SQLITE_OK) return false;
    bool empty = sqlite3_step(s) == SQLITE_DONE; // raw-sql-ok:progress-kv-kernel-store
    sqlite3_finalize(s); return empty;
}
static bool delete_suffix(sqlite3 *db, int64_t first, int64_t last, int64_t tip)
{
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(db, "DELETE FROM ironwood_checkpoints WHERE height>=? AND height<=?", -1, &s, NULL) != SQLITE_OK) return false;
    bool ok = sqlite3_bind_int64(s, 1, first) == SQLITE_OK &&
        sqlite3_bind_int64(s, 2, last) == SQLITE_OK && sqlite3_step(s) == SQLITE_DONE; // raw-sql-ok:progress-kv-kernel-store
    if (ok) ok = (int64_t)sqlite3_changes(db) == tip - first + 1;
    sqlite3_finalize(s); return ok;
}
bool ironwood_checkpoint_delete_range(struct sqlite3 *db, int64_t first, int64_t last)
{
    if (!db || first < 0 || last < first) return false;
    int schema = checkpoint_schema_state(db);
    if (schema == 0) return true;
    if (schema != 1) return false;
    int64_t tip, generation;
    if (!state(db, &tip, &generation)) return checkpoint_tables_empty(db);
    if (sqlite3_get_autocommit(db)) return false;
    if (tip < first) return true;
    if (tip > last || tip - first > INT_MAX - 1) return false;
    struct row tail = {0}, parent = {0};
    if (!last_row(db, tip, &tail) || !last_row(db, first - 1, &parent)) return false;
    return delete_suffix(db, first, last, tip) && update_tip(db, generation, first - 1);
}
