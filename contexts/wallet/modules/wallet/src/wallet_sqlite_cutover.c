/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: wallet transaction encoding and cutover completion. */

#include "base/serialize_le.h"
#include "core/serialize.h"
#include "models/activerecord.h"
#include "models/ar_after_commit.h"
#include "models/database.h"
#include "sha3/sha3.h"
#include "wallet_sqlite_internal.h"
#include "util/ar_step_readonly.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"
#include <limits.h>
#include <sqlite3.h>
#include <stdlib.h>
#include <string.h>


static bool wsql_height_missing_floor_is_legacy(struct wallet_sqlite *ws)
{
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(ws->db, "SELECT value FROM node_state WHERE key=?", -1, &s, NULL) != SQLITE_OK) return false;
    bool bound = sqlite3_bind_text(s, 1, "schema_version", -1, SQLITE_STATIC) == SQLITE_OK;
    int rc = bound ? AR_STEP_ROW_READONLY(s) : SQLITE_ERROR;
    bool ok = rc == SQLITE_DONE;
    if (rc == SQLITE_ROW && sqlite3_column_type(s, 0) == SQLITE_BLOB &&
        sqlite3_column_bytes(s, 0) == (int)sizeof(int32_t) && sqlite3_column_blob(s, 0)) {
        int32_t version;
        memcpy(&version, sqlite3_column_blob(s, 0), sizeof(version));
        ok = version >= 0 && version < 88;
    }
    sqlite3_finalize(s);
    return ok;
}

static bool wsql_height_floor(struct wallet_sqlite *ws, int32_t *floor)
{
    sqlite3_stmt *s = NULL;
    *floor = 0;
    if (sqlite3_prepare_v2(ws->db, "SELECT value FROM node_state WHERE key=?", -1, &s, NULL) != SQLITE_OK) return false;
    bool bound = sqlite3_bind_text(s, 1, "schema_compat_floor", -1, SQLITE_STATIC) == SQLITE_OK;
    int rc = bound ? AR_STEP_ROW_READONLY(s) : SQLITE_ERROR;
    bool ok = rc == SQLITE_DONE && wsql_height_missing_floor_is_legacy(ws);
    if (rc == SQLITE_ROW && sqlite3_column_type(s, 0) == SQLITE_BLOB &&
        sqlite3_column_bytes(s, 0) == (int)sizeof(*floor) && sqlite3_column_blob(s, 0)) {
        memcpy(floor, sqlite3_column_blob(s, 0), sizeof(*floor));
        ok = *floor >= 0;
    }
    sqlite3_finalize(s);
    return ok;
}

static bool wsql_height_int_state(struct wallet_sqlite *ws, const char *key, int32_t *value);

/* The legacy column holds confirmation depth. Version 2 holds absolute
 * height and pairs it with the exact wallet depth reference in node_state. */
static bool wsql_decode_height_marker(sqlite3_stmt *s, int32_t floor, int *reference)
{
    if (floor < 88 || sqlite3_column_type(s, 0) != SQLITE_BLOB || sqlite3_column_bytes(s, 0) != 8) return false;
    const uint8_t *p = sqlite3_column_blob(s, 0);
    if (!p || memcmp(p, "WHT2", 4)) return false;
    uint32_t h = zcl_read_u32_le(p + 4);
    if (h > INT_MAX) return false;
    *reference = (int)h;
    return true;
}

enum wallet_height_encoding wallet_sqlite_height_encoding(
    struct wallet_sqlite *ws, int *reference_height)
{
    if (!ws || !ws->open || !ws->db || !reference_height) return WALLET_HEIGHT_ERROR;
    int32_t floor = 0;
    if (!wsql_height_floor(ws, &floor)) return WALLET_HEIGHT_ERROR;
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(ws->db, "SELECT value FROM node_state WHERE key='wallet_height_encoding_v2'", -1, &s, NULL) != SQLITE_OK)
        return WALLET_HEIGHT_ERROR;
    int rc = AR_STEP_ROW_READONLY(s);
    if (rc == SQLITE_DONE) { sqlite3_finalize(s); return floor >= 88 ? WALLET_HEIGHT_ERROR : WALLET_HEIGHT_LEGACY; }
    int parsed_reference = 0;
    bool valid = rc == SQLITE_ROW && wsql_decode_height_marker(s, floor, &parsed_reference);
    sqlite3_finalize(s);
    int32_t version = 0;
    if (!valid || !wsql_height_int_state(ws, "schema_version", &version) || version < floor)
        return WALLET_HEIGHT_ERROR;
    *reference_height = parsed_reference;
    return WALLET_HEIGHT_V2;
}

bool wsql_write_height_encoding(struct wallet_sqlite *ws, int height)
{
    if (height < 0) return false;
    uint32_t h = (uint32_t)height;
    uint8_t value[8] = {'W', 'H', 'T', '2'};
    zcl_write_u32_le(value + 4, h);
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(ws->db, "INSERT INTO node_state(key,value) VALUES('wallet_height_encoding_v2',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", -1, &s, NULL) != SQLITE_OK) return false;
    bool ok = sqlite3_bind_blob(s, 1, value, sizeof(value), SQLITE_TRANSIENT) == SQLITE_OK && AR_STEP_WRITE(s) == SQLITE_DONE;
    sqlite3_finalize(s);
    return ok;
}

static bool wsql_height_int_state(struct wallet_sqlite *ws, const char *key, int32_t *value)
{
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(ws->db, "SELECT value FROM node_state WHERE key=?", -1, &s, NULL) != SQLITE_OK) return false;
    bool ok = sqlite3_bind_text(s, 1, key, -1, SQLITE_STATIC) == SQLITE_OK &&
        ar_step_checked(s, "wallet cutover: read", NULL) == ZCL_STEP_ROW && sqlite3_column_type(s, 0) == SQLITE_BLOB &&
        sqlite3_column_bytes(s, 0) == (int)sizeof(*value);
    if (ok) memcpy(value, sqlite3_column_blob(s, 0), sizeof(*value));
    sqlite3_finalize(s);
    return ok;
}

static bool wsql_height_raise_floor(struct wallet_sqlite *ws)
{
    int32_t version = 0, floor = 0;
    if (!wsql_height_int_state(ws, "schema_version", &version) || version < 88 ||
        !wsql_height_int_state(ws, "schema_compat_floor", &floor) || floor < 0 || floor > version)
        return false;
    if (floor >= 88) return true;
    floor = 88;
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(ws->db, "UPDATE node_state SET value=? WHERE key=?", -1, &s, NULL) != SQLITE_OK) return false;
    bool ok = sqlite3_bind_blob(s, 1, &floor, sizeof(floor), SQLITE_TRANSIENT) == SQLITE_OK &&
        sqlite3_bind_text(s, 2, "schema_compat_floor", -1, SQLITE_STATIC) == SQLITE_OK &&
        AR_STEP_WRITE(s) == SQLITE_DONE && sqlite3_changes(ws->db) == 1;
    sqlite3_finalize(s);
    return ok;
}

static bool wsql_height_row_value(sqlite3_stmt *read, int reference,
                                  wallet_height_resolver resolve, void *ctx, int *height)
{
    const uint8_t zero[32] = {0};
    const uint8_t *hash = sqlite3_column_blob(read, 1);
    int type = sqlite3_column_type(read, 1);
    if (type != SQLITE_NULL && (type != SQLITE_BLOB || !hash || sqlite3_column_bytes(read, 1) != 32)) return false;
    if (hash && memcmp(hash, zero, 32))
        return resolve(ctx, hash, height) && *height >= 0 && *height <= reference;
    return sqlite3_column_type(read, 2) == SQLITE_NULL ||
        (sqlite3_column_type(read, 2) == SQLITE_INTEGER && sqlite3_column_int64(read, 2) == 0);
}

static bool wsql_height_resolve_row(sqlite3_stmt *read, sqlite3_stmt *write,
                                    int reference, wallet_height_resolver resolve, void *ctx)
{
    const uint8_t *id = sqlite3_column_blob(read, 0);
    if (!id || sqlite3_column_type(read, 0) != SQLITE_BLOB || sqlite3_column_bytes(read, 0) != 32) return false;
    int height = 0;
    if (!wsql_height_row_value(read, reference, resolve, ctx, &height)) return false;
    sqlite3_reset(write); sqlite3_clear_bindings(write);
    return sqlite3_bind_int(write, 1, height) == SQLITE_OK &&
        sqlite3_bind_blob(write, 2, id, 32, SQLITE_TRANSIENT) == SQLITE_OK &&
        AR_STEP_WRITE(write) == SQLITE_DONE && sqlite3_changes(sqlite3_db_handle(write)) == 1;
}

static bool wsql_height_resolve_rows(struct wallet_sqlite *ws, int reference,
                                     wallet_height_resolver resolve, void *ctx)
{
    sqlite3_stmt *read = NULL, *write = NULL;
    bool ok = sqlite3_prepare_v2(ws->db, "SELECT txid,block_hash,block_height FROM wallet_transactions", -1, &read, NULL) == SQLITE_OK &&
        sqlite3_prepare_v2(ws->db, "UPDATE wallet_transactions SET block_height=? WHERE txid=?", -1, &write, NULL) == SQLITE_OK;
    int rc = SQLITE_DONE;
    while (ok && (rc = AR_STEP_ROW_READONLY(read)) == SQLITE_ROW)
        ok = wsql_height_resolve_row(read, write, reference, resolve, ctx);
    if (ok && rc != SQLITE_DONE) ok = false;
    sqlite3_finalize(write); sqlite3_finalize(read);
    return ok;
}

bool wallet_sqlite_activate_height_v2_in_open_tx(
    struct wallet_sqlite *ws, int reference_height, wallet_height_resolver resolve, void *ctx)
{
    int old_reference = 0;
    if (!ws || !ws->open || !ws->db || !resolve || reference_height < 0 ||
        sqlite3_txn_state(ws->db, "main") != SQLITE_TXN_WRITE ||
        wallet_sqlite_height_encoding(ws, &old_reference) != WALLET_HEIGHT_LEGACY)
        return false;
    return wsql_height_resolve_rows(ws, reference_height, resolve, ctx) &&
        wsql_height_raise_floor(ws) && wsql_write_height_encoding(ws, reference_height);
}

static bool wsql_height_rebase_in_open_tx(struct wallet_sqlite *ws, int reference,
    wallet_height_resolver resolve, void *ctx)
{
    int previous = -1;
    return ws && ws->db && resolve && reference >= 0 &&
        sqlite3_txn_state(ws->db, "main") == SQLITE_TXN_WRITE &&
        wallet_sqlite_height_encoding(ws, &previous) == WALLET_HEIGHT_V2 &&
        wsql_height_resolve_rows(ws, reference, resolve, ctx) && wsql_write_height_encoding(ws, reference);
}

/* ── Transactions ──────────────────────────────────────────────── */

static bool wsql_tx_reference_invalid(const struct wallet_tx *wtx, bool v2, int reference, bool confirmed)
{
    return v2 && ((confirmed && (wtx->confirms <= 0 || reference < wtx->confirms - 1)) ||
                  (!confirmed && wtx->confirms != 0));
}

bool wsql_write_tx_reference(struct wallet_sqlite *ws,
                              const struct wallet_tx *wtx, bool v2, int reference)
{
    if (!ws || !ws->open)
        LOG_FAIL("wallet_sqlite", "write_tx: not open");

    struct byte_stream bs;
    stream_init(&bs, 512);
    transaction_serialize(&wtx->tx, &bs);

    sqlite3_stmt *s = ws->stmt_tx_write;
    sqlite3_reset(s);
    sqlite3_bind_blob(s, 1, wtx->tx.hash.data, 32, SQLITE_STATIC);
    sqlite3_bind_blob(s, 2, bs.data, (int)bs.size, SQLITE_STATIC);
    sqlite3_bind_blob(s, 3, wtx->hash_block.data, 32, SQLITE_STATIC);
    const uint8_t zero[32] = {0};
    bool confirmed = memcmp(wtx->hash_block.data, zero, 32) != 0;
    if (wsql_tx_reference_invalid(wtx, v2, reference, confirmed)) { sqlite3_reset(s); sqlite3_clear_bindings(s); stream_free(&bs); return false; }
    int stored = v2 && confirmed ? reference - (wtx->confirms - 1) :
                 (v2 ? 0 : (wtx->confirms > 0 ? wtx->confirms : 0));
    sqlite3_bind_int(s, 4, stored);
    sqlite3_bind_int64(s, 5, wtx->time_received);
    sqlite3_bind_int(s, 6, wtx->from_me ? 1 : 0);

    bool ok = AR_STEP_WRITE(s) == SQLITE_DONE;
    char error[256] = {0};
    if (!ok) snprintf(error, sizeof(error), "%s", sqlite3_errmsg(ws->db));
    int reset = sqlite3_reset(s);
    int cleared = sqlite3_clear_bindings(s);
    stream_free(&bs);
    if (!ok) LOG_FAIL("wallet_sqlite", "write_tx: step failed: %s", error);
    return reset == SQLITE_OK && cleared == SQLITE_OK;
}

bool wallet_sqlite_write_tx(struct wallet_sqlite *ws, const struct wallet_tx *wtx)
{
    int reference = 0;
    if (wallet_sqlite_height_encoding(ws, &reference) != WALLET_HEIGHT_LEGACY)
        return false;
    return wsql_write_tx_reference(ws, wtx, false, 0);
}

static bool wsql_v2_hash(sqlite3_stmt *s, struct wallet_tx *wtx, bool *confirmed)
{
    const uint8_t zero[32] = {0};
    int type = sqlite3_column_type(s, 2);
    const void *hash = sqlite3_column_blob(s, 2);
    if (type != SQLITE_NULL && (type != SQLITE_BLOB || !hash || sqlite3_column_bytes(s, 2) != 32)) return false;
    *confirmed = hash && memcmp(hash, zero, 32);
    if (*confirmed) memcpy(wtx->hash_block.data, hash, 32);
    return true;
}

static bool wsql_decode_v2_depth(sqlite3_stmt *s, struct wallet_tx *wtx, int reference)
{
    bool confirmed = false;
    if (!wsql_v2_hash(s, wtx, &confirmed)) return false;
    int height_type = sqlite3_column_type(s, 3);
    if (!confirmed && height_type == SQLITE_NULL) { wtx->confirms = 0; return true; }
    if (height_type != SQLITE_INTEGER) return false;
    int64_t height = sqlite3_column_int64(s, 3);
    if (height < 0 || height > reference || (!confirmed && height != 0)) return false;
    if (confirmed && reference - height >= INT_MAX) return false;
    wtx->confirms = confirmed ? reference - (int)height + 1 : 0;
    return true;
}

struct wsql_tx_stage {
    struct wallet_tx *rows;
    size_t count, capacity;
};

static void wsql_stage_free(struct wsql_tx_stage *stage)
{
    for (size_t i = 0; i < stage->count; i++) transaction_free(&stage->rows[i].tx);
    free(stage->rows);
}

static bool wsql_stage_append(struct wsql_tx_stage *stage, struct wallet_tx *row)
{
    if (stage->count == MAX_WALLET_TX) return false;
    if (stage->count == stage->capacity) {
        size_t cap = stage->capacity ? stage->capacity * 2 : 16;
        if (cap > MAX_WALLET_TX) cap = MAX_WALLET_TX;
        void *p = zcl_realloc(stage->rows, cap * sizeof(*stage->rows), "wallet height rows");
        if (!p) return false;
        stage->rows = p; stage->capacity = cap;
    }
    stage->rows[stage->count++] = *row;
    transaction_init(&row->tx);
    return true;
}

static bool wsql_stage_read_row(sqlite3_stmt *s, int reference, struct wsql_tx_stage *stage)
{
    struct wallet_tx row = {0};
    if (!wsql_decode_v2_depth(s, &row, reference)) return false;
    int raw_len = sqlite3_column_bytes(s, 1);
    const void *raw = sqlite3_column_blob(s, 1), *id = sqlite3_column_blob(s, 0);
    if (!raw || raw_len < 10 || sqlite3_column_type(s, 0) != SQLITE_BLOB ||
        !id || sqlite3_column_bytes(s, 0) != 32) return false;
    row.time_received = sqlite3_column_int64(s, 4);
    row.from_me = sqlite3_column_int(s, 5) != 0;
    struct byte_stream bs; stream_init_from_data(&bs, raw, (size_t)raw_len);
    transaction_init(&row.tx);
    bool ok = transaction_deserialize(&row.tx, &bs);
    if (ok) ok = !memcmp(id, row.tx.hash.data, 32);
    row.used = true;
    if (ok) ok = wsql_stage_append(stage, &row);
    transaction_free(&row.tx); stream_free(&bs);
    return ok;
}

static bool wsql_stage_read_legacy_row(sqlite3_stmt *s, struct wsql_tx_stage *stage)
{
    int raw_len = sqlite3_column_bytes(s, 1);
    const void *raw = sqlite3_column_blob(s, 1);
    if (!raw || raw_len < 10) return true;
    struct wallet_tx row = {0};
    const void *hash = sqlite3_column_blob(s, 2);
    if (hash && sqlite3_column_bytes(s, 2) >= 32) memcpy(row.hash_block.data, hash, 32);
    row.confirms = sqlite3_column_int(s, 3);
    row.time_received = sqlite3_column_int64(s, 4);
    row.from_me = sqlite3_column_int(s, 5) != 0;
    struct byte_stream bs; stream_init_from_data(&bs, raw, (size_t)raw_len);
    transaction_init(&row.tx);
    bool decoded = transaction_deserialize(&row.tx, &bs);
    bool ok = true;
    if (decoded) { row.used = true; ok = wsql_stage_append(stage, &row); }
    transaction_free(&row.tx); stream_free(&bs);
    return ok;
}

static bool wsql_stage_read(struct wallet_sqlite *ws, int reference, bool v2, struct wsql_tx_stage *stage)
{
    sqlite3_stmt *s = ws->stmt_tx_read;
    sqlite3_reset(s);
    int rc;
    bool ok = true;
    while ((rc = AR_STEP_ROW_READONLY(s)) == SQLITE_ROW)
        if (!(v2 ? wsql_stage_read_row(s, reference, stage) : wsql_stage_read_legacy_row(s, stage))) { ok = false; break; }
    if (rc != SQLITE_DONE) ok = false;
    sqlite3_reset(s);
    return ok;
}

#define WSQL_STAGE_INDEX_SIZE (MAX_WALLET_TX * 2u)
#define WSQL_STAGE_MAX_PROBES 128u
struct wsql_stage_entry { uint32_t slot_plus, stage_plus; };

static size_t wsql_stage_hash(const struct uint256 *id)
{
    uint32_t h = 2166136261u;
    for (size_t i = 0; i < 32; i++) h = (h ^ id->data[i]) * 16777619u;
    return h & (WSQL_STAGE_INDEX_SIZE - 1u);
}

static struct wsql_stage_entry *wsql_stage_find(struct wsql_stage_entry *table,
    const struct wallet *w, const struct wsql_tx_stage *stage, const struct uint256 *id)
{
    size_t start = wsql_stage_hash(id);
    for (size_t i = 0; i < WSQL_STAGE_MAX_PROBES; i++) {
        struct wsql_stage_entry *e = &table[(start + i) & (WSQL_STAGE_INDEX_SIZE - 1u)];
        if (!e->slot_plus) return e;
        const struct uint256 *key = e->stage_plus ? &stage->rows[e->stage_plus - 1].tx.hash :
            &w->map_wallet[e->slot_plus - 1].tx.hash;
        if (uint256_eq(key, id)) return e;
    }
    return NULL;
}

static bool wsql_stage_index_wallet(const struct wallet *w, const struct wsql_tx_stage *stage,
                                    struct wsql_stage_entry *table, int reference, bool check_reference)
{
    bool any = false;
    for (size_t i = 0; i < MAX_WALLET_TX; i++) {
        if (!w->map_wallet[i].used) continue;
        any = true;
        struct wsql_stage_entry *e = wsql_stage_find(table, w, stage, &w->map_wallet[i].tx.hash);
        if (!e || e->slot_plus) return false;
        e->slot_plus = (uint32_t)i + 1u;
    }
    return !check_reference || !any || w->best_block_height == reference;
}

static bool wsql_stage_plan(const struct wallet *w, const struct wsql_tx_stage *stage,
                            struct wsql_stage_entry *table, uint32_t *slots, int reference, bool check_reference)
{
    if (!wsql_stage_index_wallet(w, stage, table, reference, check_reference)) return false;
    size_t next_free = 0;
    for (size_t i = 0; i < stage->count; i++) {
        struct wsql_stage_entry *e = wsql_stage_find(table, w, stage, &stage->rows[i].tx.hash);
        if (!e) return false;
        if (!e->slot_plus) {
            while (next_free < MAX_WALLET_TX && w->map_wallet[next_free].used) next_free++;
            if (next_free == MAX_WALLET_TX) return false;
            e->slot_plus = (uint32_t)next_free++ + 1u;
            e->stage_plus = (uint32_t)i + 1u;
        }
        slots[i] = e->slot_plus - 1u;
    }
    return true;
}

static bool wsql_height_row_matches(const struct wallet_tx *a, const struct wallet_tx *b,
    int reference, wallet_height_resolver resolve, void *ctx)
{
    const uint8_t zero[32] = {0}; int height = 0;
    if (!b->used || !uint256_eq(&a->tx.hash, &b->tx.hash) ||
        memcmp(a->hash_block.data, b->hash_block.data, 32) || a->confirms != b->confirms) return false;
    return !memcmp(a->hash_block.data, zero, 32) ||
        (resolve(ctx, a->hash_block.data, &height) && height >= 0 && height <= reference &&
         reference - height < INT_MAX && a->confirms == reference - height + 1);
}

static bool wsql_height_rows_match_wallet(struct wallet_sqlite *ws, const struct wallet *w,
    int reference, wallet_height_resolver resolve, void *ctx)
{
    struct wsql_tx_stage stage = {0};
    struct wsql_stage_entry *index = zcl_calloc(WSQL_STAGE_INDEX_SIZE, sizeof(*index), "wallet height index");
    uint32_t *slots = zcl_malloc(MAX_WALLET_TX * sizeof(*slots), "wallet height slots");
    bool ok = index && slots && wsql_stage_read(ws, reference, true, &stage) &&
        wsql_stage_plan(w, &stage, index, slots, reference, true);
    size_t used = 0;
    for (size_t i = 0; i < MAX_WALLET_TX; ++i) if (w->map_wallet[i].used) used++;
    if (ok && used != stage.count) ok = false;
    for (size_t i = 0; ok && i < stage.count; ++i) {
        ok = wsql_height_row_matches(&stage.rows[i], &w->map_wallet[slots[i]], reference, resolve, ctx);
    }
    free(slots); free(index); wsql_stage_free(&stage);
    return ok;
}

static bool wsql_height_prepare_encoding(struct wallet_sqlite *ws, int reference,
    wallet_height_resolver resolve, void *ctx)
{
    int previous = -1;
    enum wallet_height_encoding encoding = wallet_sqlite_height_encoding(ws, &previous);
    if (encoding == WALLET_HEIGHT_LEGACY)
        return wallet_sqlite_activate_height_v2_in_open_tx(ws, reference, resolve, ctx);
    return encoding == WALLET_HEIGHT_V2 && previous == reference;
}

bool wallet_sqlite_cutover_height_prepare_in_open_tx(struct wallet_sqlite *ws,
    const struct wallet *w, int reference, const uint8_t hash[32], wallet_height_resolver resolve, void *ctx)
{
    int resolved = -1;
    if (!ws || !ws->db || !w || !hash || !resolve || reference < 0 || w->best_block_height != reference ||
        sqlite3_txn_state(ws->db, "main") != SQLITE_TXN_WRITE || !resolve(ctx, hash, &resolved) || resolved != reference) return false;
    return wsql_height_prepare_encoding(ws, reference, resolve, ctx) &&
        wsql_height_rows_match_wallet(ws, w, reference, resolve, ctx) &&
        resolve(ctx, hash, &resolved) && resolved == reference;
}

static void wsql_stage_transfer(struct wallet *w, struct wsql_tx_stage *stage, const uint32_t *slots)
{
    for (size_t i = 0; i < stage->count; i++) {
        struct wallet_tx *src = &stage->rows[i], *dst = &w->map_wallet[slots[i]];
        if (dst->used) {
            dst->hash_block = src->hash_block; dst->confirms = src->confirms;
            wallet_mark_dirty(dst);
        } else {
            *dst = *src; transaction_init(&src->tx); w->num_wallet_tx++;
        }
    }
}

struct wsql_snapshot_work {
    struct wsql_tx_stage stage;
    struct wsql_stage_entry *table;
    uint32_t *slots;
    enum wallet_height_encoding encoding;
    int reference;
};

static bool wsql_snapshot_prepare(struct wallet_sqlite *ws, struct wsql_snapshot_work *work)
{
    work->encoding = wallet_sqlite_height_encoding(ws, &work->reference);
    bool v2 = work->encoding == WALLET_HEIGHT_V2;
    if (work->encoding == WALLET_HEIGHT_ERROR ||
        (v2 && wallet_sqlite_validate_scan_state(ws) != WALLET_SCAN_STATE_OK) ||
        !wsql_stage_read(ws, work->reference, v2, &work->stage)) return false;
    work->table = zcl_calloc(WSQL_STAGE_INDEX_SIZE, sizeof(*work->table), "wallet tx index");
    if (work->stage.count)
        work->slots = zcl_malloc(work->stage.count * sizeof(*work->slots), "wallet tx slots");
    return work->table && (!work->stage.count || work->slots);
}

static void wsql_snapshot_work_free(struct wsql_snapshot_work *work)
{
    free(work->slots); free(work->table); wsql_stage_free(&work->stage);
}

static bool wsql_read_txs_snapshot(struct wallet_sqlite *ws, struct wallet *w)
{
    sqlite3_mutex *mutex = sqlite3_db_mutex(ws->db);
    if (!mutex || sqlite3_mutex_try(mutex) != SQLITE_OK) return false;
    if (!sqlite3_get_autocommit(ws->db)) { sqlite3_mutex_leave(mutex); return false; }
    if (sqlite3_exec(ws->db, "SAVEPOINT wallet_v2_snapshot", NULL, NULL, NULL) != SQLITE_OK) {
        if (!sqlite3_get_autocommit(ws->db)) abort();
        sqlite3_mutex_leave(mutex); return false;
    }
    struct wsql_snapshot_work work = {0};
    bool ok = wsql_snapshot_prepare(ws, &work);
    bool held = ok && zcl_mutex_trylock(&w->cs);
    if (held) ok = wsql_stage_plan(w, &work.stage, work.table, work.slots, work.reference,
                                   work.encoding == WALLET_HEIGHT_V2);
    else ok = false;
    if (!wsql_snapshot_release(ws->db, WSQL_SNAPSHOT_V2)) ok = false;
    if (ok) {
        wsql_stage_transfer(w, &work.stage, work.slots);
        if (work.encoding == WALLET_HEIGHT_V2) w->best_block_height = work.reference;
    }
    if (held) zcl_mutex_unlock(&w->cs);
    wsql_snapshot_work_free(&work);
    sqlite3_mutex_leave(mutex);
    return ok;
}

bool wallet_sqlite_read_txs(struct wallet_sqlite *ws, struct wallet *w)
{
    return ws && ws->open && ws->db && w && wsql_read_txs_snapshot(ws, w);
}

/* ── Best block / scan height ──────────────────────────────────── */

bool wallet_sqlite_write_scan_height(struct wallet_sqlite *ws, int height)
{
    if (!ws || !ws->open)
        LOG_FAIL("wallet_sqlite", "write_scan_height: not open");
    sqlite3_stmt *s = ws->stmt_scan_height_write;
    sqlite3_reset(s);
    int32_t h = (int32_t)height;
    sqlite3_bind_blob(s, 1, &h, 4, SQLITE_TRANSIENT);
    bool ok = AR_STEP_WRITE(s) == SQLITE_DONE;
    if (!ok)
        LOG_FAIL("wallet_sqlite", "write_scan_height: step failed: %s",
                 sqlite3_errmsg(ws->db));
    return true;
}

bool wallet_sqlite_read_scan_height(struct wallet_sqlite *ws, int *height)
{
    if (!ws || !ws->open) return false;
    sqlite3_stmt *s = ws->stmt_scan_height_read;
    sqlite3_reset(s);
    bool ok = false;
    if (ar_step_checked(s, "wallet cutover: read", NULL) == ZCL_STEP_ROW) {
        const void *data = sqlite3_column_blob(s, 0);
        if (data && sqlite3_column_bytes(s, 0) >= 4) {
            int32_t h;
            memcpy(&h, data, 4);
            *height = h;
            ok = true;
        }
    }
    sqlite3_reset(s);
    return ok;
}

/* The caller owns the open write transaction and exclusive connection. */
static bool wsql_cutover_scripts_stored(struct wallet_sqlite *ws, const struct wallet *w)
{
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(ws->db, "SELECT redeem_script FROM wallet_scripts WHERE script_hash=?", -1, &s, NULL) != SQLITE_OK)
        return false;
    bool ok = true;
    for (size_t i = 0; ok && i < w->keystore.num_scripts; i++) {
        const struct script_entry *e = &w->keystore.scripts[i];
        if (!e->used) continue;
        sqlite3_reset(s);
        ok = sqlite3_bind_blob(s, 1, e->script_id.data, 20, SQLITE_STATIC) == SQLITE_OK &&
             ar_step_checked(s, "wallet cutover: read", NULL) == ZCL_STEP_ROW && sqlite3_column_type(s, 0) == SQLITE_BLOB &&
             sqlite3_column_bytes(s, 0) == (int)e->redeem_script.size &&
             (e->redeem_script.size == 0 || memcmp(sqlite3_column_blob(s, 0),
                 e->redeem_script.data, e->redeem_script.size) == 0) &&
             ar_step_checked(s, "wallet cutover: read completion", NULL) == ZCL_STEP_DONE;
    }
    if (sqlite3_finalize(s) != SQLITE_OK) ok = false;
    return ok;
}

static bool wsql_cutover_delete_fence(struct wallet_sqlite *ws)
{
    sqlite3_stmt *s = NULL;
    const char *keys[] = {"wallet_scan_incomplete", "wallet_cutover_binding"};
    if (sqlite3_prepare_v2(ws->db, "DELETE FROM node_state WHERE key=?", -1, &s, NULL) != SQLITE_OK)
        return false;
    bool ok = true;
    for (size_t i = 0; ok && i < 2; i++) {
        sqlite3_reset(s);
        ok = sqlite3_bind_text(s, 1, keys[i], -1, SQLITE_STATIC) == SQLITE_OK &&
             AR_STEP_WRITE(s) == SQLITE_DONE && sqlite3_changes(ws->db) == 1;
    }
    if (sqlite3_finalize(s) != SQLITE_OK) ok = false;
    return ok;
}

static bool wsql_cutover_generation_matches(struct wallet_readiness ready,
    const struct wallet_cutover_binding *expected, bool present, uint64_t generation)
{
    return ready.state == WALLET_READINESS_PENDING && present && ready.generation_present &&
        ready.generation == generation && expected->old_generation != UINT64_MAX &&
        generation == expected->old_generation + 1;
}

static bool wsql_cutover_state_matches(struct wallet_sqlite *ws, struct wallet *w,
    const struct wallet_cutover_binding *expected, bool present, uint64_t generation,
    int height, bool require_best)
{
    struct wallet_cutover_binding actual;
    struct wallet_scan_marker marker;
    struct wallet_readiness ready = wallet_readiness_get_locked(w);
    if (wallet_sqlite_cutover_read(ws, &actual) != WALLET_CUTOVER_PENDING ||
        !wallet_cutover_binding_equal(&actual, expected) || !w->scan_retry.pending ||
        !wallet_sqlite_read_scan_marker(ws, &marker)) return false;
    if (marker.from != w->scan_retry.from || marker.since != w->scan_retry.since ||
        strcmp(marker.blocker, w->scan_retry.blocker[0] ? w->scan_retry.blocker : "-") != 0)
        return false;
    return wsql_cutover_generation_matches(ready, expected, present, generation) &&
        (!require_best || height == w->best_block_height) && height >= expected->target_height;
}

static struct zcl_result wsql_cutover_write_locked(struct wallet_sqlite *ws,
    struct wallet *w, const struct wallet_cutover_binding *expected,
    bool present, uint64_t generation, int height)
{
    if (!wsql_cutover_state_matches(ws, w, expected, present, generation, height, true) ||
        !wsql_used_entries_stored(ws, w, false) || !wsql_cutover_scripts_stored(ws, w))
        return ZCL_ERR(WSQL_WRITE_FAIL, "cutover state or durable keys unavailable");
    struct wsql_flush_halt h = wsql_flush_write_keypool_and_tx(ws, w, true);
    if (h.halt || !wallet_sqlite_write_scan_height(ws, height) ||
        !wsql_cutover_delete_fence(ws))
        return ZCL_ERR(WSQL_WRITE_FAIL, "cutover projection write failed");
    return wsql_flush_commit_txn(ws);
}

static void wsql_cutover_unlock(struct wallet *w, bool wallet, bool key, bool sapling)
{
    if (sapling) zcl_mutex_unlock(&w->sapling_keys.cs);
    if (key) zcl_mutex_unlock(&w->keystore.cs);
    if (wallet) zcl_mutex_unlock(&w->cs);
}

static struct zcl_result wsql_cutover_verified_write(struct wallet_sqlite *ws,
    struct wallet *w, const struct wallet_cutover_binding *expected,
    bool present, uint64_t generation, int height, const uint8_t identity[32])
{
    uint8_t current[32];
    if (!wallet_readiness_can_complete_locked(w, present, generation) ||
        !wallet_scan_identity_locked(w, current) || memcmp(current, identity, sizeof(current)) != 0)
        return ZCL_ERR(WSQL_WRITE_FAIL, "cutover scan identity or readiness changed");
    struct zcl_result result = wsql_cutover_write_locked(ws, w, expected, present, generation, height);
    if (result.ok) {
        if (strcmp(w->scan_retry.blocker, WALLET_BIRTHDAY_PENDING) == 0)
            w->initial_scan_floor = 0;
        memset(&w->scan_retry, 0, sizeof(w->scan_retry));
        wallet_readiness_complete_locked(w);
    }
    return result;
}

static bool wsql_cutover_tx_valid(struct wallet_sqlite *ws, struct wallet *w,
    const struct wallet_cutover_binding *expected, const uint8_t *identity, int height)
{
    return sqlite3_txn_state(ws->db, "main") == SQLITE_TXN_WRITE &&
           w && expected && !expected->history_identity_present && identity && height >= 0;
}

static struct zcl_result wsql_cutover_complete_impl(
    struct wallet_sqlite *ws, struct wallet *w,
    const struct wallet_cutover_binding *expected, bool generation_present,
    uint64_t generation, int completed_height, const uint8_t scan_identity[32],
    bool (*validator)(void *, struct wallet *, sqlite3 *), void *validator_ctx, bool required)
{
    if (!ws || !ws->open || !ws->db || sqlite3_get_autocommit(ws->db))
        return ZCL_ERR(WSQL_TXN_BEGIN_FAIL, "cutover completion requires an open owned transaction");
    struct zcl_result result = ZCL_ERR(WSQL_WRITE_FAIL, "cutover completion refused");
    bool wallet_held = false, key_held = false, sapling_held = false;
    if (!wsql_cutover_tx_valid(ws, w, expected, scan_identity, completed_height)) goto finish;
    if (!(wallet_held = zcl_mutex_trylock(&w->cs))) goto finish;
    if (!(key_held = zcl_mutex_trylock(&w->keystore.cs))) goto finish;
    if (!(sapling_held = zcl_mutex_trylock(&w->sapling_keys.cs))) goto finish;
    if (required && (!validator || !validator(validator_ctx, w, ws->db))) goto finish;
    result = wsql_cutover_verified_write(ws, w, expected, generation_present,
                                         generation, completed_height, scan_identity);
finish:
    if (!result.ok && sqlite3_get_autocommit(ws->db) == 0 &&
        sqlite3_exec(ws->db, "ROLLBACK", NULL, NULL, NULL) != SQLITE_OK)
        result = ZCL_ERR(WSQL_WRITE_FAIL, "cutover completion rollback failed");
    wsql_cutover_unlock(w, wallet_held, key_held, sapling_held);
    return result;
}

struct zcl_result wallet_sqlite_cutover_complete_flush_in_open_tx_r(
    struct wallet_sqlite *ws, struct wallet *w,
    const struct wallet_cutover_binding *expected, bool generation_present,
    uint64_t generation, int completed_height, const uint8_t scan_identity[32])
{
    return wsql_cutover_complete_impl(ws, w, expected, generation_present,
        generation, completed_height, scan_identity, NULL, NULL, false);
}

struct zcl_result wallet_sqlite_cutover_complete_checked_in_open_tx_r(
    struct wallet_sqlite *ws, struct wallet *w,
    const struct wallet_cutover_binding *expected, bool generation_present,
    uint64_t generation, int completed_height, const uint8_t scan_identity[32],
    bool (*validator)(void *, struct wallet *, sqlite3 *), void *validator_ctx)
{
    return wsql_cutover_complete_impl(ws, w, expected, generation_present,
        generation, completed_height, scan_identity, validator, validator_ctx, true);
}

bool wallet_cutover_v2_plan_init(struct wallet_cutover_v2_plan *plan, size_t capacity)
{
    if (!plan || capacity > MAX_WALLET_TX) return false;
    memset(plan, 0, sizeof(*plan));
    if (capacity) plan->entries = zcl_calloc(capacity, sizeof(*plan->entries), "cutover depth entries");
    plan->index = zcl_calloc(WSQL_STAGE_INDEX_SIZE, sizeof(struct wsql_stage_entry), "cutover tx index");
    plan->slot_index = zcl_calloc(MAX_WALLET_TX, sizeof(uint32_t), "cutover slot index");
    plan->active_spent = zcl_calloc(SPENT_SET_BUCKETS, sizeof(struct spent_outpoint), "cutover active spends");
    plan->confirmed_spent = zcl_calloc(SPENT_SET_BUCKETS, sizeof(struct spent_outpoint), "cutover confirmed spends");
    if ((capacity && !plan->entries) || !plan->index || !plan->slot_index || !plan->active_spent || !plan->confirmed_spent) {
        wallet_cutover_v2_plan_free(plan); return false;
    }
    plan->capacity = capacity;
    return true;
}

void wallet_cutover_v2_plan_free(struct wallet_cutover_v2_plan *plan)
{
    if (!plan) return;
    free(plan->entries); free(plan->index); free(plan->slot_index);
    free(plan->active_spent); free(plan->confirmed_spent); memset(plan, 0, sizeof(*plan));
}

const struct wallet_cutover_v2_entry *wallet_cutover_v2_plan_find(
    const struct wallet_cutover_v2_plan *plan, const struct wallet *w, const uint8_t txid[32])
{
    if (!plan || !plan->index || !plan->slot_index || !w || !txid) return NULL;
    struct uint256 key; memcpy(key.data, txid, 32);
    struct wsql_tx_stage empty = {0};
    struct wsql_stage_entry *found = wsql_stage_find(plan->index, w, &empty, &key);
    if (!found || !found->slot_plus) return NULL;
    uint32_t n = ((const uint32_t *)plan->slot_index)[found->slot_plus - 1];
    if (!n || n > plan->count) return NULL;
    const struct wallet_cutover_v2_entry *entry = &plan->entries[n - 1];
    return entry->slot == found->slot_plus - 1 && !memcmp(entry->txid, txid, 32) ? entry : NULL;
}

static size_t wsql_spent_hash(const uint8_t txid[32], uint32_t vout)
{
    uint32_t h = 0;
    for (size_t i = 0; i < 8; i++) { uint32_t word; memcpy(&word, txid + i * 4, 4); h ^= word; }
    return (h ^ (vout * 2654435761u)) % SPENT_SET_BUCKETS;
}

static struct spent_outpoint *wsql_spent_slot(struct spent_outpoint *set,
                                               const uint8_t txid[32], uint32_t vout)
{
    size_t start = wsql_spent_hash(txid, vout);
    for (size_t i = 0; i < 128; i++) {
        struct spent_outpoint *entry = &set[(start + i) % SPENT_SET_BUCKETS];
        if (!entry->occupied || (entry->vout == vout && !memcmp(entry->txid.data, txid, 32))) return entry;
    }
    return NULL;
}

bool wallet_cutover_v2_plan_mark_spent(struct wallet_cutover_v2_plan *plan,
    const uint8_t txid[32], uint32_t vout, bool confirmed)
{
    if (!plan || !plan->active_spent || !plan->confirmed_spent || !txid || plan->spends_ready) return false;
    struct spent_outpoint *active = wsql_spent_slot(plan->active_spent, txid, vout);
    struct spent_outpoint *chain = confirmed ? wsql_spent_slot(plan->confirmed_spent, txid, vout) : NULL;
    if (!active || (confirmed && !chain)) return false;
    if (!active->occupied) {
        memcpy(active->txid.data, txid, 32); active->vout = vout; active->occupied = true;
        plan->active_spent_count++;
    }
    if (chain && !chain->occupied) {
        memcpy(chain->txid.data, txid, 32); chain->vout = vout; chain->occupied = true;
    }
    return true;
}

bool wallet_cutover_v2_plan_has_spent(const struct wallet_cutover_v2_plan *plan,
    const uint8_t txid[32], uint32_t vout, bool confirmed_only)
{
    if (!plan || !txid) return false;
    struct spent_outpoint *set = confirmed_only ? plan->confirmed_spent : plan->active_spent;
    if (!set) return false;
    struct spent_outpoint *entry = wsql_spent_slot(set, txid, vout);
    return entry && entry->occupied;
}

void wallet_cutover_v2_plan_finish_spends(struct wallet_cutover_v2_plan *plan)
{
    if (plan) plan->spends_ready = true;
}

static bool wsql_v2_spent_digest(const struct wallet *w, uint8_t out[32])
{
    struct sha3_256_ctx hash; sha3_256_init(&hash);
    const uint8_t domain[] = "z23-wallet-spent-set-v1";
    sha3_256_write(&hash, domain, sizeof(domain) - 1);
    size_t count = 0;
    for (size_t i = 0; i < SPENT_SET_BUCKETS; i++) {
        const struct spent_outpoint *entry = &w->spent_set[i];
        if (!entry->occupied) continue;
        uint32_t n = entry->vout;
        uint8_t value[4];
        zcl_write_u32_le(value, n);
        sha3_256_write(&hash, entry->txid.data, 32); sha3_256_write(&hash, value, sizeof(value));
        count++;
    }
    if (count != w->num_spent) return false;
    sha3_256_finalize(&hash, out);
    return true;
}

static bool wsql_v2_plan_entry(struct wallet_cutover_v2_plan *plan,
    const struct wallet_cutover_v2_request *r, const struct wallet_tx *tx, size_t slot)
{
    if (plan->count == plan->capacity) return false;
    const uint8_t zero[32] = {0};
    bool confirmed = memcmp(tx->hash_block.data, zero, 32) != 0;
    int height = 0, depth = 0;
    if (confirmed) {
        if (!r->resolve(r->chain_ctx, tx->hash_block.data, &height) || height < 0 ||
            height > r->reference_height || r->reference_height - height >= INT_MAX) return false;
        depth = r->reference_height - height + 1;
    } else if (tx->confirms != 0) return false;
    struct wallet_cutover_v2_entry *e = &plan->entries[plan->count];
    e->slot = (uint32_t)slot; memcpy(e->txid, tx->tx.hash.data, 32);
    memcpy(e->block_hash, tx->hash_block.data, 32);
    e->old_depth = tx->confirms; e->new_depth = depth;
    ((uint32_t *)plan->slot_index)[slot] = (uint32_t)++plan->count;
    return true;
}

static bool wsql_v2_plan_prepare(struct wallet *w, const struct wallet_cutover_v2_request *r,
                                  struct wallet_cutover_v2_plan *plan)
{
    if (!plan->index || !plan->slot_index || !plan->active_spent || !plan->confirmed_spent ||
        (plan->capacity && !plan->entries)) return false;
    memset(plan->index, 0, WSQL_STAGE_INDEX_SIZE * sizeof(struct wsql_stage_entry));
    memset(plan->slot_index, 0, MAX_WALLET_TX * sizeof(uint32_t));
    memset(plan->active_spent, 0, SPENT_SET_BUCKETS * sizeof(struct spent_outpoint));
    memset(plan->confirmed_spent, 0, SPENT_SET_BUCKETS * sizeof(struct spent_outpoint));
    plan->active_spent_count = 0; plan->spends_ready = false;
    if (!wsql_v2_spent_digest(w, plan->old_spent_digest)) return false;
    plan->count = 0; plan->reference_height = r->reference_height;
    plan->old_best_height = w->best_block_height;
    memcpy(plan->reference_hash, r->reference_hash, 32);
    memcpy(plan->scan_identity, r->scan_identity, 32);
    struct wsql_tx_stage empty = {0};
    if (!wsql_stage_index_wallet(w, &empty, plan->index, 0, false)) return false;
    for (size_t i = 0; i < MAX_WALLET_TX; i++)
        if (w->map_wallet[i].used && !wsql_v2_plan_entry(plan, r, &w->map_wallet[i], i)) return false;
    return true;
}

static bool wsql_v2_entry_depth_current(const struct wallet_cutover_v2_request *r,
                                        const struct wallet_cutover_v2_entry *entry)
{
    const uint8_t zero[32] = {0};
    if (!memcmp(entry->block_hash, zero, 32)) return entry->new_depth == 0;
    int height = -1;
    return r->resolve(r->chain_ctx, entry->block_hash, &height) && height >= 0 &&
        height <= r->reference_height && r->reference_height - height < INT_MAX &&
        entry->new_depth == r->reference_height - height + 1;
}

static bool wsql_v2_plan_context_current(struct wallet *w, const struct wallet_cutover_v2_request *r,
                                          const struct wallet_cutover_v2_plan *plan)
{
    uint8_t identity[32]; int reference = -1;
    uint8_t spent_digest[32];
    return r->reference_height == plan->reference_height && w->best_block_height == plan->old_best_height &&
        !memcmp(r->reference_hash, plan->reference_hash, 32) && !memcmp(r->scan_identity, plan->scan_identity, 32) &&
        r->endpoint_current(r->chain_ctx, r->reference_height, r->reference_hash) &&
        r->resolve(r->chain_ctx, r->reference_hash, &reference) && reference == r->reference_height &&
         wallet_scan_identity_locked(w, identity) && !memcmp(identity, plan->scan_identity, 32) &&
        wsql_v2_spent_digest(w, spent_digest) && !memcmp(spent_digest, plan->old_spent_digest, 32);
}

static bool wsql_v2_plan_entries_current(struct wallet *w, const struct wallet_cutover_v2_request *r,
                                          const struct wallet_cutover_v2_plan *plan)
{
    size_t seen = 0;
    for (size_t i = 0; i < MAX_WALLET_TX; i++) {
        const struct wallet_tx *tx = &w->map_wallet[i];
        uint32_t n = ((const uint32_t *)plan->slot_index)[i];
        if (!tx->used) { if (n) return false; continue; }
        if (!n || n > plan->count) return false;
        const struct wallet_cutover_v2_entry *e = &plan->entries[n - 1];
        if (e->slot != i || memcmp(e->txid, tx->tx.hash.data, 32) ||
            memcmp(e->block_hash, tx->hash_block.data, 32) || e->old_depth != tx->confirms ||
            !wsql_v2_entry_depth_current(r, e)) return false;
        seen++;
    }
    return seen == plan->count;
}

static bool wsql_v2_plan_current(struct wallet *w, const struct wallet_cutover_v2_request *r,
                                  const struct wallet_cutover_v2_plan *plan)
{
    return wsql_v2_plan_context_current(w, r, plan) && wsql_v2_plan_entries_current(w, r, plan);
}

static bool wsql_v2_db_row_matches(sqlite3_stmt *s, struct wallet *w,
                                    const struct wallet_cutover_v2_plan *plan)
{
    const void *id = sqlite3_column_blob(s, 0), *hash = sqlite3_column_blob(s, 1);
    if (sqlite3_column_type(s, 0) != SQLITE_BLOB || !id || sqlite3_column_bytes(s, 0) != 32 ||
        sqlite3_column_type(s, 1) != SQLITE_BLOB || !hash || sqlite3_column_bytes(s, 1) != 32) return false;
    struct uint256 key; memcpy(key.data, id, 32);
    struct wsql_tx_stage empty = {0};
    struct wsql_stage_entry *e = wsql_stage_find(plan->index, w, &empty, &key);
    if (!e || !e->slot_plus) return false;
    uint32_t n = ((const uint32_t *)plan->slot_index)[e->slot_plus - 1];
    return n && n <= plan->count && !memcmp(hash, plan->entries[n - 1].block_hash, 32);
}

static bool wsql_v2_db_matches_plan(struct wallet_sqlite *ws, struct wallet *w,
                                     const struct wallet_cutover_v2_plan *plan)
{
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(ws->db, "SELECT txid,block_hash FROM wallet_transactions", -1, &s, NULL) != SQLITE_OK) return false;
    size_t count = 0; int rc; bool ok = true;
    while ((rc = AR_STEP_ROW_READONLY(s)) == SQLITE_ROW) {
        if (!wsql_v2_db_row_matches(s, w, plan)) { ok = false; break; }
        count++;
    }
    if (rc != SQLITE_DONE || count != plan->count) ok = false;
    sqlite3_finalize(s);
    return ok;
}

static void wsql_v2_plan_apply(struct wallet *w, const struct wallet_cutover_v2_plan *plan)
{
    memcpy(w->spent_set, plan->active_spent, sizeof(w->spent_set));
    w->num_spent = plan->active_spent_count;
    for (size_t i = 0; i < plan->count; i++) {
        struct wallet_tx *tx = &w->map_wallet[plan->entries[i].slot];
        tx->confirms = plan->entries[i].new_depth;
        wallet_mark_dirty(tx);
    }
    w->best_block_height = plan->reference_height;
}

static bool wsql_node_tx_marked(struct node_db *ndb)
{
    if (!ndb->state_mutex_init || !zcl_mutex_trylock(&ndb->state_mutex)) return false;
    bool open = ndb->tx_open;
    zcl_mutex_unlock(&ndb->state_mutex);
    return open;
}

static bool wsql_v2_owned_tx(struct wallet_sqlite *ws, struct node_db *ndb)
{
    return ws && ws->open && ws->db && ndb && ndb->open && ndb->db == ws->db &&
        ar_after_commit_depth() == 1 && ar_after_commit_pending() == 0 &&
        sqlite3_txn_state(ws->db, "main") == SQLITE_TXN_WRITE &&
        wsql_node_tx_marked(ndb);
}

static bool wsql_v2_request_valid(struct wallet *w, const struct wallet_cutover_v2_request *r,
                                  struct wallet_cutover_v2_plan *plan)
{
    return w && r && plan && r->binding && r->resolve && r->endpoint_current &&
        r->holds_valid && r->project && r->reference_height >= 0;
}

static bool wsql_cutover_record_completed(struct wallet_sqlite *ws,
                                          const struct wallet_cutover_binding *binding)
{
    if (!binding->history_identity_present) return true;
    int32_t version = 0, floor = 0;
    if (!wsql_height_int_state(ws, "schema_version", &version) ||
        !wsql_height_int_state(ws, "schema_compat_floor", &floor) ||
        version != NODE_DB_SCHEMA_LATEST || floor < WALLET_BOUND_CUTOVER_SCHEMA_VERSION || floor > version) return false;
    sqlite3_stmt *s = NULL;
    const char *sql = "INSERT INTO node_state(key,value) SELECT 'wallet_cutover_completed',value "
        "FROM node_state WHERE key='wallet_cutover_binding' AND length(value)=178 AND substr(value,1,1)=x'02'";
    if (sqlite3_prepare_v2(ws->db, sql, -1, &s, NULL) != SQLITE_OK) return false;
    bool ok = AR_STEP_WRITE(s) == SQLITE_DONE && sqlite3_changes(ws->db) == 1;
    if (sqlite3_finalize(s) != SQLITE_OK) ok = false;
    return ok;
}

/* Persist verified plan depths without mutating wallet RAM before commit. */
static bool wsql_v2_write_planned_txs(struct wallet_sqlite *ws, struct wallet *w,
    const struct wallet_cutover_v2_request *r, const struct wallet_cutover_v2_plan *plan)
{
    int previous = 0;
    enum wallet_height_encoding encoding = wallet_sqlite_height_encoding(ws, &previous);
    if (encoding == WALLET_HEIGHT_ERROR || !wallet_sqlite_replace_keypool_locked(ws, w, false)) return false;
    for (size_t i = 0; i < plan->count; ++i) {
        const struct wallet_cutover_v2_entry *entry = &plan->entries[i];
        struct wallet_tx staged = w->map_wallet[entry->slot];
        staged.confirms = entry->new_depth;
        if (!wsql_write_tx_reference(ws, &staged, encoding == WALLET_HEIGHT_V2,
                                     r->reference_height)) return false;
    }
    return true;
}

static bool wsql_v2_projection_preflight(struct wallet_sqlite *ws, struct wallet *w,
    const struct wallet_cutover_v2_request *r, struct wallet_cutover_v2_plan *plan)
{
    if (!wsql_cutover_state_matches(ws, w, r->binding, r->generation_present, r->generation, r->reference_height, false)) return false;
    if (!wsql_used_entries_stored(ws, w, false)) return false;
    if (!wsql_cutover_scripts_stored(ws, w)) return false;
    if (!wsql_v2_write_planned_txs(ws, w, r, plan)) return false;
    return wsql_v2_db_matches_plan(ws, w, plan);
}

static bool wsql_v2_write_projection(struct wallet_sqlite *ws, struct node_db *ndb, struct wallet *w,
    const struct wallet_cutover_v2_request *r, struct wallet_cutover_v2_plan *plan)
{
    if (!wsql_v2_projection_preflight(ws, w, r, plan)) return false;
    int previous = -1;
    enum wallet_height_encoding encoding = wallet_sqlite_height_encoding(ws, &previous);
    bool height_ok = encoding == WALLET_HEIGHT_LEGACY ?
        wallet_sqlite_activate_height_v2_in_open_tx(ws, r->reference_height, r->resolve, r->chain_ctx) :
        encoding == WALLET_HEIGHT_V2 && wsql_height_rebase_in_open_tx(ws, r->reference_height, r->resolve, r->chain_ctx);
    if (!height_ok) return false;
    bool projected = r->project(r->projection_ctx, ndb, w, plan);
    if (sqlite3_txn_state(ws->db, "main") != SQLITE_TXN_WRITE || ar_after_commit_depth() != 1) {
        LOG_ERROR("wallet_sqlite", "cutover projection changed transaction ownership");
        abort();
    }
    if (!projected) return false;
    if (ar_after_commit_pending() > 1) return false;
    if (!wallet_sqlite_write_scan_height(ws, r->reference_height)) return false;
    if (!wsql_cutover_record_completed(ws, r->binding)) return false;
    if (!wsql_cutover_delete_fence(ws)) return false;
    return true;
}

static bool wsql_v2_plan_spends_valid(const struct wallet_cutover_v2_plan *plan)
{
    if (!plan->spends_ready || !plan->active_spent || !plan->confirmed_spent) return false;
    const struct spent_outpoint *active = plan->active_spent, *confirmed = plan->confirmed_spent;
    size_t count = 0;
    for (size_t i = 0; i < SPENT_SET_BUCKETS; i++) {
        if (active[i].occupied) {
            if (!wallet_cutover_v2_plan_has_spent(plan, active[i].txid.data, active[i].vout, false)) return false;
            count++;
        }
        if (confirmed[i].occupied &&
            (!wallet_cutover_v2_plan_has_spent(plan, confirmed[i].txid.data, confirmed[i].vout, true) ||
             !wallet_cutover_v2_plan_has_spent(plan, confirmed[i].txid.data, confirmed[i].vout, false))) return false;
    }
    return count == plan->active_spent_count;
}

static bool wsql_v2_authorized_write(struct wallet_sqlite *ws, struct node_db *ndb, struct wallet *w,
    const struct wallet_cutover_v2_request *r, struct wallet_cutover_v2_plan *plan)
{
    if (!wallet_readiness_can_complete_locked(w, r->generation_present, r->generation)) return false;
    if (!r->holds_valid(r->holds_ctx, w, ws->db)) return false;
    if (!wsql_v2_plan_prepare(w, r, plan)) return false;
    if (!wsql_v2_plan_current(w, r, plan)) return false;
    if (!wsql_v2_write_projection(ws, ndb, w, r, plan)) return false;
    if (!wsql_v2_plan_spends_valid(plan)) return false;
    if (!wsql_v2_plan_current(w, r, plan)) return false;
    if (!r->holds_valid(r->holds_ctx, w, ws->db)) return false;
    return true;
}

struct zcl_result wallet_sqlite_cutover_complete_v2_in_open_tx_r(
    struct wallet_sqlite *ws, struct node_db *ndb, struct wallet *w,
    const struct wallet_cutover_v2_request *r, struct wallet_cutover_v2_plan *plan)
{
    if (!wsql_v2_owned_tx(ws, ndb))
        return ZCL_ERR(WSQL_TXN_BEGIN_FAIL, "cutover v2 requires matching tracked write transaction");
    bool wallet_held = false, key_held = false, sapling_held = false, committed = false;
    if (!wsql_v2_request_valid(w, r, plan)) goto finish;
    if (!(wallet_held = zcl_mutex_trylock(&w->cs))) goto finish;
    if (!(key_held = zcl_mutex_trylock(&w->keystore.cs))) goto finish;
    if (!(sapling_held = zcl_mutex_trylock(&w->sapling_keys.cs))) goto finish;
    if (!wsql_v2_authorized_write(ws, ndb, w, r, plan)) goto finish;
    if (!node_db_commit(ndb)) goto finish;
    committed = true;
    wsql_v2_plan_apply(w, plan);
    if (strcmp(w->scan_retry.blocker, WALLET_BIRTHDAY_PENDING) == 0) w->initial_scan_floor = 0;
    memset(&w->scan_retry, 0, sizeof(w->scan_retry));
    wallet_readiness_complete_locked(w);
finish:
    if (!committed) {
        (void)node_db_rollback(ndb);
        if (!sqlite3_get_autocommit(ws->db)) {
            LOG_ERROR("wallet_sqlite", "cutover v2 rollback left a live transaction");
            abort();
        }
    }
    wsql_cutover_unlock(w, wallet_held, key_held, sapling_held);
    return committed ? ZCL_OK : ZCL_ERR(WSQL_WRITE_FAIL, "cutover v2 completion refused");
}
