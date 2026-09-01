/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ActiveRecord model + resolve API for the sovereign-identity anchor
 * projection (zid_identities) — see models/zid_identity.h for field
 * semantics and the threading contract. Writes go through AR_ADHOC_SAVE;
 * reads through the AR_QUERY_* helpers. No raw sqlite3_step here. */

#include "models/zid_identity.h"

#include "config/runtime.h"
#include "encoding/utilstrencodings.h"
#include "json/json.h"
#include "util/log_macros.h"
#include "util/subsystem_snapshot.h"

#include <pthread.h>
#include <sqlite3.h>
#include <stdatomic.h>
#include <string.h>

#define ZID_IDENTITY_COLS \
    "master_pubkey,anchor_txid,anchor_height,status,successor_pubkey," \
    "source,name,owner_address,updated_height"

DEFINE_MODEL_CALLBACKS(zid_identity)

/* ── Validation ────────────────────────────────────────────────────── */

static bool zid_str_eq(const char *a, const char *b)
{
    return a && b && strcmp(a, b) == 0;
}

static bool zid_blob_is_zero(const uint8_t *p, size_t n)
{
    for (size_t i = 0; i < n; i++)
        if (p[i]) return false;
    return true;
}

bool db_zid_identity_validate(const struct zid_identity *r,
                              struct ar_errors *errors)
{
    ar_errors_clear(errors);
    if (!r) {
        ar_errors_add(errors, "row", "is NULL");
        return false;
    }

    const bool rotated = zid_str_eq(r->status, ZID_IDENTITY_STATUS_ROTATED);
    const bool status_known =
        rotated ||
        zid_str_eq(r->status, ZID_IDENTITY_STATUS_ACTIVE) ||
        zid_str_eq(r->status, ZID_IDENTITY_STATUS_REVOKED);
    validates_custom(errors, status_known, "status",
                     "must be one of active|rotated|revoked");

    validates_custom(errors, r->has_successor == rotated, "successor_pubkey",
                     "must be present if and only if status is 'rotated'");
    validates_custom(errors,
                     !r->has_successor ||
                         !zid_blob_is_zero(r->successor_pubkey, 32),
                     "successor_pubkey", "is present but all-zero");

    const bool source_known =
        zid_str_eq(r->source, ZID_IDENTITY_SOURCE_ZNAM_TEXT) ||
        zid_str_eq(r->source, ZID_IDENTITY_SOURCE_ZID_OVERLAY);
    validates_custom(errors, source_known, "source",
                     "must be one of znam_text|zid_overlay");

    validates_non_negative(errors, r, anchor_height);
    validates_non_negative(errors, r, updated_height);

    return !ar_errors_any(errors);
}

/* ── Save ──────────────────────────────────────────────────────────── */

bool db_zid_identity_save(struct node_db *ndb, const struct zid_identity *row)
{
    if (!ndb || !ndb->open)
        LOG_FAIL("zid_identity", "db_zid_identity_save: db not open");
    if (!row)
        LOG_FAIL("zid_identity", "db_zid_identity_save: row is NULL");

    struct ar_callbacks *cbs = db_zid_identity_callbacks();
    sqlite3_stmt *s = NULL;
    AR_ADHOC_SAVE(ndb, s,
        "INSERT OR REPLACE INTO zid_identities(" ZID_IDENTITY_COLS ")"
        " VALUES(?,?,?,?,?,?,?,?,?)",
        cbs, "zid_identity", row, db_zid_identity_validate,
        AR_BIND_BLOB(s, 1, row->master_pubkey, 32);
        AR_BIND_BLOB(s, 2, row->anchor_txid, 32);
        AR_BIND_INT(s, 3, row->anchor_height);
        AR_BIND_TEXT(s, 4, row->status);
        if (row->has_successor)
            AR_BIND_BLOB(s, 5, row->successor_pubkey, 32);
        else
            AR_BIND_NULL(s, 5);
        AR_BIND_TEXT(s, 6, row->source);
        if (row->name[0])
            AR_BIND_TEXT(s, 7, row->name);
        else
            AR_BIND_NULL(s, 7);
        if (row->owner_address[0])
            AR_BIND_TEXT(s, 8, row->owner_address);
        else
            AR_BIND_NULL(s, 8);
        AR_BIND_INT(s, 9, row->updated_height));
}

/* ── Read API ──────────────────────────────────────────────────────── */

static void zid_row_from_stmt(sqlite3_stmt *s, struct zid_identity *out)
{
    memset(out, 0, sizeof(*out));

    const void *pk = sqlite3_column_blob(s, 0);
    if (pk && sqlite3_column_bytes(s, 0) == 32)
        memcpy(out->master_pubkey, pk, 32);

    const void *tx = sqlite3_column_blob(s, 1);
    if (tx && sqlite3_column_bytes(s, 1) == 32)
        memcpy(out->anchor_txid, tx, 32);

    out->anchor_height = (int32_t)sqlite3_column_int(s, 2);
    AR_READ_STR(s, 3, out->status, sizeof(out->status));

    const void *sp = sqlite3_column_blob(s, 4);
    if (sp && sqlite3_column_bytes(s, 4) == 32) {
        memcpy(out->successor_pubkey, sp, 32);
        out->has_successor = true;
    }

    AR_READ_STR(s, 5, out->source, sizeof(out->source));
    AR_READ_STR(s, 6, out->name, sizeof(out->name));
    AR_READ_STR(s, 7, out->owner_address, sizeof(out->owner_address));
    out->updated_height = (int32_t)sqlite3_column_int(s, 8);
}

bool db_zid_identity_find(struct node_db *ndb, const uint8_t pubkey[32],
                          struct zid_identity *out)
{
    if (!ndb || !ndb->open)
        LOG_FAIL("zid_identity", "db_zid_identity_find: db not open");
    if (!pubkey || !out)
        LOG_FAIL("zid_identity",
                 "db_zid_identity_find: null arg (pubkey=%p out=%p)",
                 (const void *)pubkey, (void *)out);

    sqlite3_stmt *s = NULL;
    AR_QUERY_ONE_BOOL(ndb, s,
        "SELECT " ZID_IDENTITY_COLS " FROM zid_identities"
        " WHERE master_pubkey=?",
        AR_BIND_BLOB(s, 1, pubkey, 32),
        zid_row_from_stmt(s, out));
}

bool db_zid_identity_find_by_name(struct node_db *ndb, const char *name,
                                  struct zid_identity *out)
{
    if (!ndb || !ndb->open)
        LOG_FAIL("zid_identity", "db_zid_identity_find_by_name: db not open");
    if (!name || !name[0] || !out)
        LOG_FAIL("zid_identity",
                 "db_zid_identity_find_by_name: null/empty arg (out=%p)",
                 (void *)out);

    sqlite3_stmt *s = NULL;
    AR_QUERY_ONE_BOOL(ndb, s,
        "SELECT " ZID_IDENTITY_COLS " FROM zid_identities"
        " WHERE name=? ORDER BY anchor_height DESC, master_pubkey ASC"
        " LIMIT 1",
        AR_BIND_TEXT(s, 1, name),
        zid_row_from_stmt(s, out));
}

int db_zid_identity_list(struct node_db *ndb, struct zid_identity *out,
                         int max, int offset)
{
    if (!ndb || !ndb->open)
        LOG_RETURN(0, "zid_identity", "db_zid_identity_list: db not open");
    if (!out)
        LOG_RETURN(0, "zid_identity", "db_zid_identity_list: out is NULL");
    if (max <= 0 || offset < 0)
        LOG_RETURN(0, "zid_identity",
                   "db_zid_identity_list: bad page (max=%d offset=%d)",
                   max, offset);

    sqlite3_stmt *s = NULL;
    AR_QUERY_LIST(ndb, s,
        "SELECT " ZID_IDENTITY_COLS " FROM zid_identities"
        " ORDER BY anchor_height DESC, master_pubkey ASC"
        " LIMIT ? OFFSET ?",
        out, (size_t)max,
        AR_BIND_INT(s, 1, max);
        AR_BIND_INT(s, 2, offset),
        zid_row_from_stmt(s, &out[count]));
}

int64_t db_zid_identity_count(struct node_db *ndb)
{
    if (!ndb || !ndb->open) return 0;
    sqlite3_stmt *s = NULL;
    AR_QUERY_INT64_BOUND(ndb, s, "SELECT COUNT(*) FROM zid_identities",
                         (void)0);
}

int64_t db_zid_identity_count_by_status(struct node_db *ndb,
                                        const char *status)
{
    if (!ndb || !ndb->open || !status || !status[0]) return 0;
    sqlite3_stmt *s = NULL;
    AR_QUERY_INT64_BOUND(ndb, s,
        "SELECT COUNT(*) FROM zid_identities WHERE status=?",
        AR_BIND_TEXT(s, 1, status));
}

bool db_zid_identity_truncate(struct node_db *ndb)
{
    if (!ndb || !ndb->open)
        LOG_FAIL("zid_identity", "db_zid_identity_truncate: db not open");
    if (!node_db_exec(ndb, "DELETE FROM zid_identities"))
        LOG_FAIL("zid_identity", "db_zid_identity_truncate: DELETE failed");
    return true;
}

/* ── `z23 ops state --subsystem=zid_identities` ─────────────── */

static void zid_push_row(struct json_value *out, const struct zid_identity *r)
{
    char hex[65] = {0};
    HexStr(r->master_pubkey, 32, false, hex, sizeof(hex));
    json_push_kv_str(out, "master_pubkey", hex);
    HexStr(r->anchor_txid, 32, false, hex, sizeof(hex));
    json_push_kv_str(out, "anchor_txid", hex);
    json_push_kv_int(out, "anchor_height", r->anchor_height);
    json_push_kv_str(out, "status", r->status);
    if (r->has_successor) {
        HexStr(r->successor_pubkey, 32, false, hex, sizeof(hex));
        json_push_kv_str(out, "successor_pubkey", hex);
    }
    json_push_kv_str(out, "source", r->source);
    json_push_kv_str(out, "name", r->name);
    json_push_kv_str(out, "owner_address", r->owner_address);
    json_push_kv_int(out, "updated_height", r->updated_height);
}

/* ── The anchor-status change signal ───────────────────────────────
 *
 * See models/zid_identity.h for what this is for. The publish envelope is
 * the shared seqlock (util/subsystem_snapshot.h) so the three fields read
 * back coherently; the counter a poller actually watches is one atomic and
 * needs no bracket at all.
 *
 * The seqlock's parity is only coherent with ONE writer in flight. The block
 * fold is single-threaded, so that holds today — but it is enforced with a
 * lock here rather than assumed of every future caller. The lock is held for
 * two atomic stores and is never taken by a reader, so it cannot park the
 * fold and cannot be the thing a poller blocks behind. */
static pthread_mutex_t g_status_pub_lock = PTHREAD_MUTEX_INITIALIZER;
static struct zcl_snapshot_env g_status_env = ZCL_SNAPSHOT_ENV_INIT;

uint64_t zid_identity_status_generation(void)
{
    return atomic_load(&g_status_env.generation);
}

void zid_identity_note_status_change(int height)
{
    pthread_mutex_lock(&g_status_pub_lock);
    zcl_snapshot_publish_begin(&g_status_env);
    zcl_snapshot_publish_end(&g_status_env, (int64_t)height);
    pthread_mutex_unlock(&g_status_pub_lock);
}

void zid_identity_status_signal_read(struct zid_identity_status_signal *out)
{
    if (!out) {
        LOG_WARN("zid_identity", "status_signal_read: out is NULL");
        return;
    }
    memset(out, 0, sizeof(*out));
    out->last_height = -1;

    for (int i = 0; i < ZCL_SNAPSHOT_READ_MAX_RETRIES; i++) {
        uint64_t seq = 0;
        if (!zcl_snapshot_read_try(&g_status_env, &seq))
            continue;
        out->generation   = atomic_load(&g_status_env.generation);
        out->last_height  = atomic_load(&g_status_env.last_height);
        out->published_us = atomic_load(&g_status_env.published_us);
        if (zcl_snapshot_read_ok(&g_status_env, seq))
            return;
    }
    /* A writer kept intervening. The values just read may be torn, so they
     * are reported as the last-known snapshot and the fallback is counted —
     * never a spin, never an empty answer. */
    zcl_snapshot_note_torn(&g_status_env);
}

bool zid_identity_dump_state_json(struct json_value *out, const char *key)
{
    if (!out)
        LOG_FAIL("zid_identity", "dump_state_json: out is NULL");
    json_set_object(out);

    struct node_db *ndb = app_runtime_node_db();
    const bool db_open = ndb && ndb->open;
    json_push_kv_bool(out, "db_open", db_open);

    if (key && key[0]) {
        json_push_kv_str(out, "key", key);
        struct zid_identity row;
        memset(&row, 0, sizeof(row));
        bool found = false;
        if (db_open) {
            uint8_t pk[32];
            if (strlen(key) == 64 && IsHex(key) &&
                ParseHex(key, pk, sizeof(pk)) == 32)
                found = db_zid_identity_find(ndb, pk, &row);
            else
                found = db_zid_identity_find_by_name(ndb, key, &row);
        }
        json_push_kv_bool(out, "found", found);
        if (found) zid_push_row(out, &row);
        return true;
    }

    int64_t total = db_zid_identity_count(ndb);
    json_push_kv_int(out, "total_rows", total);
    json_push_kv_int(out, "active_rows",
                     db_zid_identity_count_by_status(
                         ndb, ZID_IDENTITY_STATUS_ACTIVE));
    json_push_kv_int(out, "rotated_rows",
                     db_zid_identity_count_by_status(
                         ndb, ZID_IDENTITY_STATUS_ROTATED));
    json_push_kv_int(out, "revoked_rows",
                     db_zid_identity_count_by_status(
                         ndb, ZID_IDENTITY_STATUS_REVOKED));
    return true;
}
