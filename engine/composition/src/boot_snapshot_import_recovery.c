/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Resume only the exact mirror transaction recorded by the snapshot importer. */
#include "boot_snapshot_import_internal.h"
#include "config/boot_snapshot_import.h"
#include "config/boot_consensus_bundle_marker.h"
#include "consensus_state_proof_prefix.h"
#include "base/serialize_le.h"
#include "coins/utxo_commitment.h"
#include "jobs/reducer_frontier.h"
#include "jobs/stage_row_itag.h"
#include "models/database.h"
#include "services/reindex_epilogue.h"
#include "storage/coins_kv.h"
#include "storage/progress_store.h"
#include "util/ar_step_readonly.h"
#include <limits.h>
#include <sqlite3.h>
#include <stdio.h>
#include <string.h>

static const uint8_t pending_magic[8] = {'Z','2','3','S','N','A','P',1};

bool snapshot_import_pending_load(struct node_db *ndb,
    struct snapshot_import_pending *p, bool *found)
{
    uint8_t bytes[96];
    size_t len = 0;
    memset(p, 0, sizeof(*p));
    if (!ndb || !ndb->open || !ndb->db ||
        !snapshot_node_blob(ndb, SNAPSHOT_IMPORT_PENDING_KEY, bytes, sizeof(bytes), &len, found))
        return false;
    if (!*found)
        return true;
    if (len != sizeof(bytes) || memcmp(bytes, pending_magic, 8) != 0 ||
        zcl_read_u32_le(bytes + 12) != 0 || zcl_read_u32_le(bytes + 8) == 0 ||
        zcl_read_u32_le(bytes + 8) >= INT32_MAX ||
        zcl_read_u64_le(bytes + 16) != 0 || zcl_read_u64_le(bytes + 24) < 1000 ||
        zcl_read_u64_le(bytes + 24) > INT64_MAX)
        return false;
    p->height = (int32_t)zcl_read_u32_le(bytes + 8);
    p->generation = zcl_read_u64_le(bytes + 16);
    p->count = zcl_read_u64_le(bytes + 24);
    memcpy(p->hash, bytes + 32, 32);
    memcpy(p->root, bytes + 64, 32);
    return true;
}

bool snapshot_import_pending_save(struct node_db *ndb,
    const struct snapshot_import_pending *p)
{
    uint8_t bytes[96] = {0};
    if (sqlite3_get_autocommit(ndb->db))
        return false;
    memcpy(bytes, pending_magic, 8);
    zcl_write_u32_le(bytes + 8, (uint32_t)p->height);
    zcl_write_u64_le(bytes + 16, p->generation);
    zcl_write_u64_le(bytes + 24, p->count);
    memcpy(bytes + 32, p->hash, 32);
    memcpy(bytes + 64, p->root, 32);
    return node_db_state_set(ndb, SNAPSHOT_IMPORT_PENDING_KEY, bytes, sizeof(bytes));
}

bool boot_snapshot_import_pending_or_error(struct node_db *ndb)
{
    struct snapshot_import_pending p;
    bool found = false;
    return !snapshot_import_pending_load(ndb, &p, &found) || found;
}

static bool recovery_meta(sqlite3 *db, const char *key, uint8_t *out,
                          size_t cap, size_t *len, bool *found)
{
    bool exists = false;
    *found = false;
    *len = 0;
    return snapshot_table_exists(db, "progress_meta", &exists) &&
        (!exists || progress_meta_get_blob_exact(db, key, out, cap, len, found));
}

static bool recovery_u64(sqlite3 *db, const char *key, uint64_t *value, bool *found)
{
    uint8_t bytes[8];
    size_t len;
    if (!recovery_meta(db, key, bytes, sizeof(bytes), &len, found) ||
        (*found && len != sizeof(bytes)))
        return false;
    *value = *found ? zcl_read_u64_le(bytes) : 0;
    return true;
}

static bool recovery_absent(sqlite3 *db, const char *key)
{
    uint8_t bytes[32];
    size_t len;
    bool found;
    return recovery_meta(db, key, bytes, sizeof(bytes), &len, &found) && !found;
}

static bool recovery_mirror(struct node_db *ndb, const struct snapshot_import_pending *p)
{
    uint8_t root[32];
    uint64_t count = 0;
    int64_t rows = -1;
    utxo_commitment_sha3_compute(ndb->db, root, &count);
    return node_db_utxo_count_checked(ndb, &rows) && rows >= 0 &&
        (uint64_t)rows == p->count && count == p->count && memcmp(root, p->root, 32) == 0;
}

struct recovery_coin_state {
    uint64_t generation, applied;
    bool have_applied, have_stamp;
    uint8_t stamp[1];
    size_t stamp_len;
    int64_t count;
};

static bool recovery_coin_state_read(sqlite3 *db, struct recovery_coin_state *s)
{
    bool exists = false;
    memset(s, 0, sizeof(*s));
    if (!coins_kv_get_authority_generation(db, &s->generation) ||
        !recovery_u64(db, COINS_APPLIED_HEIGHT_KEY, &s->applied, &s->have_applied) ||
        !recovery_meta(db, COINS_KV_MIGRATION_COMPLETE_KEY, s->stamp, sizeof(s->stamp),
                       &s->stamp_len, &s->have_stamp) ||
        !recovery_absent(db, COINS_KV_SELF_FOLDED_KEY) ||
        !snapshot_table_exists(db, "coins", &exists))
        return false;
    s->count = exists ? coins_kv_count_sqlite(db) : 0;
    return s->count >= 0;
}

static bool recovery_coins(sqlite3 *db, const struct snapshot_import_pending *p,
                            bool *reset_required)
{
    struct recovery_coin_state s;
    if (!recovery_coin_state_read(db, &s))
        return false;
    *reset_required = s.generation == p->generation;
    if (*reset_required)
        return s.count == 0 && !s.have_stamp && (!s.have_applied || s.applied == 1);
    if (s.generation != p->generation + 1)
        return false;
    if (!s.have_stamp)
        return s.count == 0 && !s.have_applied;
    if (s.stamp_len != 1 || s.stamp[0] != 1 ||
        (uint64_t)s.count != p->count || (s.have_applied && s.applied != (uint64_t)p->height + 1))
        return false;
    uint8_t root[32];
    return coins_kv_commitment(db, root) == 0 && memcmp(root, p->root, 32) == 0;
}

static bool recovery_trusted(sqlite3 *db, const struct snapshot_import_pending *p,
                              bool terminal)
{
    uint64_t height = 0;
    bool have_height = false, have_hash = false;
    uint8_t hash[32];
    size_t len;
    if (!recovery_u64(db, REDUCER_TRUSTED_BASE_HEIGHT_KEY, &height, &have_height) ||
        !recovery_meta(db, REDUCER_TRUSTED_BASE_HASH_KEY, hash, sizeof(hash), &len, &have_hash))
        return false;
    if (!have_height)
        return !terminal && !have_hash;
    return height == (uint64_t)p->height &&
        (have_hash ? len == 32 && memcmp(hash, p->hash, 32) == 0 : !terminal);
}

/* Rows produced by the epilogue are exact anchors; neither real application
 * receipts nor an advanced finalization may be overwritten by recovery. */
static bool recovery_log_status(sqlite3_stmt *s, bool genesis)
{
    const void *status = sqlite3_column_text(s, 1);
    int n = sqlite3_column_bytes(s, 1);
    return sqlite3_column_type(s, 1) == SQLITE_TEXT && status &&
        (genesis || (n == 6 && memcmp(status, "anchor", 6) == 0));
}

static bool recovery_log_receipt(sqlite3_stmt *s, const char *table,
    const struct snapshot_import_pending *p, bool allow_anchor)
{
    int64_t h = sqlite3_column_int64(s, 0);
    const void *status = sqlite3_column_text(s, 1);
    int n = sqlite3_column_bytes(s, 1);
    bool height_ok = h == 0 || (allow_anchor && h == p->height);
    return sqlite3_column_type(s, 0) == SQLITE_INTEGER && height_ok &&
        sqlite3_column_type(s, 2) == SQLITE_INTEGER && sqlite3_column_int(s, 2) == 1 &&
        recovery_log_status(s, h == 0) &&
        stage_row_itag_verify(table, h, 1, status, (size_t)n,
            sqlite3_column_blob(s, 3), (size_t)sqlite3_column_bytes(s, 3)) == STAGE_ROW_ITAG_MATCH;
}

static bool recovery_log_zero_delta(sqlite3_stmt *s)
{
    for (int i = 5; i < 9; i++)
        if (sqlite3_column_type(s, i) != SQLITE_INTEGER || sqlite3_column_int64(s, i) != 0)
            return false;
    return true;
}

static bool recovery_log_tip_hash(sqlite3_stmt *s, const struct snapshot_import_pending *p)
{
    return sqlite3_column_int64(s, 0) == 0 ||
        (sqlite3_column_type(s, 4) == SQLITE_BLOB && sqlite3_column_bytes(s, 4) == 32 &&
         memcmp(sqlite3_column_blob(s, 4), p->hash, 32) == 0);
}

static bool recovery_log(sqlite3 *db, const char *table,
    const struct snapshot_import_pending *p, bool finalize, bool allow_anchor)
{
    bool exists = false;
    if (!snapshot_table_exists(db, table, &exists))
        return false;
    if (!exists)
        return true;
    const char *sql = finalize ?
        "SELECT height,status,ok,itag,tip_hash,work_delta_high,work_delta_low,"
        "utxo_size_after,reorg_depth FROM tip_finalize_log" :
        "SELECT height,status,ok,itag,NULL,spent_count,added_count,total_value_delta,0 FROM utxo_apply_log";
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &s, NULL) != SQLITE_OK)
        return false;
    bool ok = true;
    int rc;
    while ((rc = sqlite3_step(s)) == SQLITE_ROW) { // raw-sql-ok:read-only-introspection
        if (!recovery_log_receipt(s, table, p, allow_anchor) ||
            !recovery_log_zero_delta(s) ||
            (finalize && !recovery_log_tip_hash(s, p))) {
            ok = false;
            break;
        }
    }
    sqlite3_finalize(s);
    return ok && rc == SQLITE_DONE;
}

static bool recovery_cursor_independent(const char *name)
{
    return strcmp(name, "header_admit") == 0 || strcmp(name, "validate_headers") == 0 ||
        strcmp(name, "body_fetch") == 0;
}

static bool recovery_cursor_value(const char *name, int64_t cursor,
    const struct snapshot_import_pending *p, bool terminal, bool allow_anchor)
{
    bool apply = strcmp(name, "utxo_apply") == 0;
    bool finalize = strcmp(name, "tip_finalize") == 0;
    int64_t target = finalize ? p->height : (int64_t)p->height + 1;
    if (terminal)
        return (apply || finalize) ? cursor == target : cursor >= target;
    return recovery_cursor_independent(name) || cursor == 0 || (!finalize && cursor == 1) ||
        (allow_anchor && cursor == target);
}

static bool recovery_cursors(sqlite3 *db, const struct snapshot_import_pending *p,
                              bool terminal, bool allow_anchor)
{
    bool exists = false;
    if (!snapshot_table_exists(db, "stage_cursor", &exists))
        return false;
    if (!exists)
        return !terminal;
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(db,
        "SELECT name,cursor FROM stage_cursor WHERE name IN('header_admit','validate_headers',"
        "'body_fetch','body_persist','script_validate','proof_validate','utxo_apply','tip_finalize')",
        -1, &s, NULL) != SQLITE_OK)
        return false;
    int rows = 0, rc;
    bool ok = true;
    while ((rc = sqlite3_step(s)) == SQLITE_ROW) { // raw-sql-ok:read-only-introspection
        const char *name = (const char *)sqlite3_column_text(s, 0);
        int64_t cursor = sqlite3_column_int64(s, 1);
        if (!name || sqlite3_column_type(s, 1) != SQLITE_INTEGER || cursor < 0 ||
            !recovery_cursor_value(name, cursor, p, terminal, allow_anchor))
            ok = false;
        rows++;
    }
    sqlite3_finalize(s);
    return ok && rc == SQLITE_DONE && (!terminal || rows == 8);
}

static bool recovery_terminal_coins(sqlite3 *db, const struct snapshot_import_pending *p)
{
    uint64_t generation;
    int32_t applied = -1;
    uint8_t root[32];
    return coins_kv_get_authority_generation(db, &generation) && generation == p->generation + 1 &&
        coins_kv_is_proven_authority(db, &applied) && applied == p->height + 1 &&
        coins_kv_count_sqlite(db) == (int64_t)p->count && coins_kv_commitment(db, root) == 0 &&
        memcmp(root, p->root, 32) == 0;
}

static bool recovery_terminal_caches(struct node_db *ndb, const struct snapshot_import_pending *p)
{
    int32_t height = -1;
    uint8_t stamp[32], best[32];
    uint64_t count = 0;
    size_t len = 0;
    bool found = false;
    return utxo_commitment_sha3_load(ndb->db, stamp, &height, &count) && height == p->height &&
        count == p->count && memcmp(stamp, p->root, 32) == 0 &&
        snapshot_node_blob(ndb, "coins_best_block", best, sizeof(best), &len, &found) && found &&
        len == 32 && memcmp(best, p->hash, 32) == 0;
}

static bool recovery_terminal(struct node_db *ndb, const struct snapshot_import_pending *p)
{
    sqlite3 *db = progress_store_db();
    int32_t hstar = -1, served = -1;
    return recovery_terminal_coins(db, p) && recovery_terminal_caches(ndb, p) &&
        recovery_trusted(db, p, true) && recovery_cursors(db, p, true, true) &&
        reducer_frontier_compute_hstar(db, &hstar, &served) && hstar == p->height && served == p->height;
}

static bool recovery_no_install(sqlite3 *db, struct node_db *ndb, const char *datadir)
{
    struct consensus_state_proof_prefix prefix;
    if (!consensus_state_proof_prefix_load(db, &prefix) || prefix.present)
        return false;
    if (datadir && !snapshot_import_directory_bound(datadir))
        return false;
    const char *path = sqlite3_db_filename(ndb->db, "main");
    const char *leaf = path ? strrchr(path, '/') : NULL;
#if defined(_WIN32)
    const char *back = path ? strrchr(path, '\\') : NULL;
    if (!leaf || (back && back > leaf)) leaf = back;
#endif
    if (!leaf || (size_t)(leaf - path) >= PATH_MAX)
        return false;
    char directory[PATH_MAX];
    size_t len = leaf == path ? 1u : (size_t)(leaf - path);
#if defined(_WIN32)
    if (len == 2 && path[1] == ':')
        len++;
#endif
    memcpy(directory, path, len);
    directory[len] = '\0';
    return !boot_consensus_bundle_marker_exists(directory);
}

bool snapshot_import_no_installed_state(struct node_db *ndb)
{
    return recovery_no_install(progress_store_db(), ndb, NULL);
}

static bool recovery_bound_mirror(struct node_db *ndb, const char *datadir,
    const struct snapshot_import_pending *pending)
{
    sqlite3 *db = progress_store_db();
    return snapshot_import_store_bound(ndb) && sqlite3_get_autocommit(ndb->db) &&
        sqlite3_get_autocommit(db) && recovery_no_install(db, ndb, datadir) &&
        snapshot_import_shielded_pristine(ndb) && recovery_mirror(ndb, pending);
}

static bool recovery_authority_compatible(sqlite3 *db,
    const struct snapshot_import_pending *pending, bool *reset_required)
{
    if (!recovery_coins(db, pending, reset_required))
        return false;
    if (*reset_required && (!recovery_absent(db, REDUCER_TRUSTED_BASE_HEIGHT_KEY) ||
                            !recovery_absent(db, REDUCER_TRUSTED_BASE_HASH_KEY)))
        return false;
    return recovery_trusted(db, pending, false) &&
        recovery_log(db, "utxo_apply_log", pending, false, !*reset_required) &&
        recovery_log(db, "tip_finalize_log", pending, true, !*reset_required) &&
        recovery_cursors(db, pending, false, !*reset_required);
}

static struct zcl_result snapshot_import_recover_locked(struct node_db *ndb,
    const char *datadir, bool *recovered)
{
    *recovered = false;
    struct snapshot_import_pending pending;
    bool found = false;
    if (!snapshot_import_pending_load(ndb, &pending, &found))
        return ZCL_ERR(-1, "snapshot recovery: malformed or unreadable pending record; preserve datadir and diagnose a copy");
    if (!found)
        return ZCL_OK;
    sqlite3 *db = progress_store_db();
    if (!recovery_bound_mirror(ndb, datadir, &pending))
        return ZCL_ERR(-1, "snapshot recovery: store identity, provenance or mirror mismatch; preserve datadir and diagnose a copy");
    bool reset_required = false;
    if (!recovery_authority_compatible(db, &pending, &reset_required))
        return ZCL_ERR(-1, "snapshot recovery: authority advanced or conflicts with pending import; preserve datadir and diagnose a copy");
    if (!recovery_terminal(ndb, &pending)) {
        uint64_t expected = pending.generation + (reset_required ? 0u : 1u);
        if (!reindex_epilogue_resume_imported_snapshot(ndb,
            sqlite3_db_filename(ndb->db, "main"), pending.height, pending.hash, expected, reset_required))
            return ZCL_ERR(-1, "snapshot recovery: authority epilogue incomplete; pending record retained");
        /* The raise-only seed API does not fill a missing hash when height
         * already equals H (a possible interrupted height/hash pair). */
        bool have_hash = false;
        uint8_t hash[32];
        size_t len;
        if (!recovery_meta(db, REDUCER_TRUSTED_BASE_HASH_KEY, hash, sizeof(hash), &len, &have_hash) ||
            (!have_hash && !progress_meta_set(db, REDUCER_TRUSTED_BASE_HASH_KEY, pending.hash, 32)))
            return ZCL_ERR(-1, "snapshot recovery: trusted hash completion failed; pending record retained");
    }
    if (!recovery_terminal(ndb, &pending) ||
        !node_db_state_delete(ndb, SNAPSHOT_IMPORT_PENDING_KEY))
        return ZCL_ERR(-1, "snapshot recovery: terminal verification or pending retirement failed; preserve datadir");
    *recovered = true;
    return ZCL_OK;
}

struct zcl_result snapshot_import_recover(struct node_db *ndb,
    const char *datadir, bool *recovered)
{
    /* Serialize shared-handle SQL through classification and completion.
     * The mutex is recursive; each epilogue phase retains its own transaction. */
    progress_store_tx_lock();
    struct zcl_result result = snapshot_import_recover_locked(ndb, datadir, recovered);
    progress_store_tx_unlock();
    return result;
}
