/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ActiveRecord model + read API for the on-chain node directory projection
 * (onion_directory) — see models/onion_directory.h for field semantics and the
 * threading contract. Writes go through AR_ADHOC_SAVE; reads through the
 * AR_QUERY_* helpers. No raw sqlite3_step here. */

#include "models/onion_directory.h"

#include "config/runtime.h"
#include "encoding/utilstrencodings.h"
#include "json/json.h"
#include "net/onion_peer_merge.h"
#include "util/log_macros.h"

#include <sqlite3.h>
#include <string.h>

#define ONION_DIRECTORY_COLS \
    "hostname,txid,height,owner_address,master_pubkey,status,updated_height"

DEFINE_MODEL_CALLBACKS(onion_directory)

/* ── Validation ────────────────────────────────────────────────────── */

static bool od_str_eq(const char *a, const char *b)
{
    return a && b && strcmp(a, b) == 0;
}

static bool od_blob_is_zero(const uint8_t *p, size_t n)
{
    for (size_t i = 0; i < n; i++)
        if (p[i]) return false;
    return true;
}

bool db_onion_directory_validate(const struct db_onion_directory *r,
                                 struct ar_errors *errors)
{
    ar_errors_clear(errors);
    if (!r) {
        ar_errors_add(errors, "row", "is NULL");
        return false;
    }

    /* The LAST line of defence, and deliberately the same predicate core/modules/net
     * dials against: a hostname reaches this table only from attacker-payable
     * chain data, so it is validated at parse, at project, and again here. */
    validates_custom(errors, onion_hostname_valid(r->hostname), "hostname",
                     "must be a Tor v3 onion hostname (56 base32 + .onion)");

    const bool status_known =
        od_str_eq(r->status, ONION_DIRECTORY_STATUS_ACTIVE) ||
        od_str_eq(r->status, ONION_DIRECTORY_STATUS_RETIRED);
    validates_custom(errors, status_known, "status",
                     "must be one of active|retired");

    validates_custom(errors,
                     !r->has_pubkey || !od_blob_is_zero(r->master_pubkey, 32),
                     "master_pubkey", "is present but all-zero");

    validates_non_negative(errors, r, height);
    validates_non_negative(errors, r, updated_height);

    return !ar_errors_any(errors);
}

/* ── Save ──────────────────────────────────────────────────────────── */

bool db_onion_directory_save(struct node_db *ndb,
                             const struct db_onion_directory *row)
{
    if (!ndb || !ndb->open)
        LOG_FAIL("onion_directory", "db_onion_directory_save: db not open");
    if (!row)
        LOG_FAIL("onion_directory", "db_onion_directory_save: row is NULL");

    struct ar_callbacks *cbs = db_onion_directory_callbacks();
    sqlite3_stmt *s = NULL;
    AR_ADHOC_SAVE(ndb, s,
        "INSERT OR REPLACE INTO onion_directory(" ONION_DIRECTORY_COLS ")"
        " VALUES(?,?,?,?,?,?,?)",
        cbs, "onion_directory", row, db_onion_directory_validate,
        AR_BIND_TEXT(s, 1, row->hostname);
        AR_BIND_BLOB(s, 2, row->txid, 32);
        AR_BIND_INT(s, 3, row->height);
        if (row->owner_address[0])
            AR_BIND_TEXT(s, 4, row->owner_address);
        else
            AR_BIND_NULL(s, 4);
        if (row->has_pubkey)
            AR_BIND_BLOB(s, 5, row->master_pubkey, 32);
        else
            AR_BIND_NULL(s, 5);
        AR_BIND_TEXT(s, 6, row->status);
        AR_BIND_INT(s, 7, row->updated_height));
}

/* ── Read API ──────────────────────────────────────────────────────── */

static void od_row_from_stmt(sqlite3_stmt *s, struct db_onion_directory *out)
{
    memset(out, 0, sizeof(*out));

    AR_READ_STR(s, 0, out->hostname, sizeof(out->hostname));

    const void *tx = sqlite3_column_blob(s, 1);
    if (tx && sqlite3_column_bytes(s, 1) == 32)
        memcpy(out->txid, tx, 32);

    out->height = (int32_t)sqlite3_column_int(s, 2);
    AR_READ_STR(s, 3, out->owner_address, sizeof(out->owner_address));

    const void *pk = sqlite3_column_blob(s, 4);
    if (pk && sqlite3_column_bytes(s, 4) == 32) {
        memcpy(out->master_pubkey, pk, 32);
        out->has_pubkey = true;
    }

    AR_READ_STR(s, 5, out->status, sizeof(out->status));
    out->updated_height = (int32_t)sqlite3_column_int(s, 6);
}

bool db_onion_directory_find(struct node_db *ndb, const char *hostname,
                             struct db_onion_directory *out)
{
    if (!ndb || !ndb->open)
        LOG_FAIL("onion_directory", "db_onion_directory_find: db not open");
    if (!hostname || !hostname[0] || !out)
        LOG_FAIL("onion_directory",
                 "db_onion_directory_find: null/empty arg (out=%p)",
                 (void *)out);

    sqlite3_stmt *s = NULL;
    AR_QUERY_ONE_BOOL(ndb, s,
        "SELECT " ONION_DIRECTORY_COLS " FROM onion_directory"
        " WHERE hostname=?",
        AR_BIND_TEXT(s, 1, hostname),
        od_row_from_stmt(s, out));
}

int db_onion_directory_list_active(struct node_db *ndb,
                                   struct db_onion_directory *out,
                                   int max, int offset)
{
    if (!ndb || !ndb->open)
        LOG_RETURN(0, "onion_directory",
                   "db_onion_directory_list_active: db not open");
    if (!out)
        LOG_RETURN(0, "onion_directory",
                   "db_onion_directory_list_active: out is NULL");
    if (max <= 0 || offset < 0)
        LOG_RETURN(0, "onion_directory",
                   "db_onion_directory_list_active: bad page (max=%d"
                   " offset=%d)", max, offset);

    sqlite3_stmt *s = NULL;
    AR_QUERY_LIST(ndb, s,
        /* SENIORITY FIRST. `height` is the height that first REGISTERed the
         * hostname (models/onion_directory.h), i.e. the seniority signal —
         * so the senior row is the SMALLEST height, and this page must be
         * ASC. It was DESC, which is newest-first: since the page is bounded
         * (the peer-discovery read asks for 64) that handed the whole slate
         * to whoever registered most recently and evicted every
         * long-standing node, at the cost of one cheap OP_RETURN per slot.
         * The header documents seniority; the query now agrees with it. */
        "SELECT " ONION_DIRECTORY_COLS " FROM onion_directory"
        " WHERE status=? ORDER BY height ASC, hostname ASC"
        " LIMIT ? OFFSET ?",
        out, (size_t)max,
        AR_BIND_TEXT(s, 1, ONION_DIRECTORY_STATUS_ACTIVE);
        AR_BIND_INT(s, 2, max);
        AR_BIND_INT(s, 3, offset),
        od_row_from_stmt(s, &out[count]));
}

int64_t db_onion_directory_count(struct node_db *ndb)
{
    if (!ndb || !ndb->open) return 0;
    sqlite3_stmt *s = NULL;
    AR_QUERY_INT64_BOUND(ndb, s, "SELECT COUNT(*) FROM onion_directory",
                         (void)0);
}

int64_t db_onion_directory_count_by_status(struct node_db *ndb,
                                           const char *status)
{
    if (!ndb || !ndb->open || !status || !status[0]) return 0;
    sqlite3_stmt *s = NULL;
    AR_QUERY_INT64_BOUND(ndb, s,
        "SELECT COUNT(*) FROM onion_directory WHERE status=?",
        AR_BIND_TEXT(s, 1, status));
}

bool db_onion_directory_truncate(struct node_db *ndb)
{
    if (!ndb || !ndb->open)
        LOG_FAIL("onion_directory",
                 "db_onion_directory_truncate: db not open");
    if (!node_db_exec(ndb, "DELETE FROM onion_directory"))
        LOG_FAIL("onion_directory",
                 "db_onion_directory_truncate: DELETE failed");
    return true;
}

/* ── `z23 ops state --subsystem=onion_directory` ────────────── */

static void od_push_row(struct json_value *out,
                        const struct db_onion_directory *r)
{
    char hex[65] = {0};
    json_push_kv_str(out, "hostname", r->hostname);
    HexStr(r->txid, 32, false, hex, sizeof(hex));
    json_push_kv_str(out, "txid", hex);
    json_push_kv_int(out, "height", r->height);
    json_push_kv_str(out, "owner_address", r->owner_address);
    if (r->has_pubkey) {
        HexStr(r->master_pubkey, 32, false, hex, sizeof(hex));
        json_push_kv_str(out, "master_pubkey", hex);
    }
    json_push_kv_str(out, "status", r->status);
    json_push_kv_int(out, "updated_height", r->updated_height);
}

bool onion_directory_dump_state_json(struct json_value *out, const char *key)
{
    if (!out)
        LOG_FAIL("onion_directory", "dump_state_json: out is NULL");
    json_set_object(out);

    struct node_db *ndb = app_runtime_node_db();
    const bool db_open = ndb && ndb->open;
    json_push_kv_bool(out, "db_open", db_open);

    if (key && key[0]) {
        json_push_kv_str(out, "key", key);
        struct db_onion_directory row;
        memset(&row, 0, sizeof(row));
        bool found = db_open && db_onion_directory_find(ndb, key, &row);
        json_push_kv_bool(out, "found", found);
        if (found) od_push_row(out, &row);
        return true;
    }

    json_push_kv_int(out, "total_rows", db_onion_directory_count(ndb));
    json_push_kv_int(out, "active_rows",
                     db_onion_directory_count_by_status(
                         ndb, ONION_DIRECTORY_STATUS_ACTIVE));
    json_push_kv_int(out, "retired_rows",
                     db_onion_directory_count_by_status(
                         ndb, ONION_DIRECTORY_STATUS_RETIRED));
    return true;
}
