/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 *
 * ar-validate-skip:connection-handle-not-a-row
 *   struct node_db wraps the SQLite connection plus a registry of
 *   cached prepared statements. It is not a row record, so the
 *   validates_* / AR_BEGIN_SAVE lifecycle does not apply. Row-level
 *   validation lives on the models that *use* this handle.
 *
 *   models/database_validators.{c,h} holds the shared field validators
 *   (range checks, address syntax, …) that row models invoke from
 *   their own validates_* paths. */

#include "platform/time_compat.h"
#include "platform/os_proc.h"
#include "util/log_macros.h"
#include "util/db_txn_trace.h"
#include "util/hw_profile.h"
#include "models/database.h"
#include "models/database_lifetime.h"
#include "models/database_owner_lease.h"
#include "models/database_internal.h"
#include "models/database_validators.h"
#include <errno.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static int64_t db_now_seconds(void)
{
    return (int64_t)platform_time_wall_time_t();
}

static int64_t db_now_ms(void)
{
    struct timespec ts;
    platform_time_monotonic_timespec(&ts);
    return ts.tv_sec * 1000LL + ts.tv_nsec / 1000000LL;
}

static void node_db_state_init(struct node_db *ndb)
{
    if (!ndb)
        return;
    zcl_mutex_init(&ndb->state_mutex);
    ndb->state_mutex_init = true;
    ndb->tx_open = false;
    ndb->turbo_mode = false;
    ndb->last_activity_time = db_now_seconds();
    ndb->last_sqlite_rc = SQLITE_OK;
    snprintf(ndb->last_op, sizeof(ndb->last_op), "%s", "open");
}

static void node_db_state_destroy(struct node_db *ndb)
{
    if (!ndb || !ndb->state_mutex_init)
        return;
    zcl_mutex_destroy(&ndb->state_mutex);
    ndb->state_mutex_init = false;
}

/* Execute `sql`, logging any error with `where` context.  Returns the
 * sqlite3 rc so callers can make tolerance decisions.  Wrapping
 * sqlite3_exec ensures the rc is never silently discarded — a dropped
 * rc hides schema-migration and turbo-mode failures. */
int db_exec_checked(sqlite3 *db, const char *sql, const char *where)
{
    char *err = NULL;
    int rc = sqlite3_exec(db, sql, NULL, NULL, &err);
    if (rc != SQLITE_OK) {
        LOG_WARN("db", "[db] %s failed: %s (sql=%s)", where, err ? err : "(no errmsg)", sql);
    }
    sqlite3_free(err);
    return rc;
}

/* Like db_exec_checked but tolerates a known-benign error substring
 * (e.g. "duplicate column name" when re-applying idempotent ALTERs).
 * Returns SQLITE_OK on tolerated failure so callers can treat it as
 * success; returns the original rc otherwise. */
int db_exec_tolerant(sqlite3 *db, const char *sql, const char *where,
                     const char *tolerable_substr)
{
    char *err = NULL;
    int rc = sqlite3_exec(db, sql, NULL, NULL, &err);
    if (rc != SQLITE_OK) {
        if (tolerable_substr && err && strstr(err, tolerable_substr)) {
            sqlite3_free(err);
            return SQLITE_OK;
        }
        LOG_WARN("db", "[db] %s failed: %s (sql=%s)", where, err ? err : "(no errmsg)", sql);
    }
    sqlite3_free(err);
    return rc;
}

/*
 * Stamp the activity/rc/op snapshot fields under state_mutex. When
 * flag_field is non-NULL it is assigned flag_value inside the same lock
 * acquisition so the mode change and the activity stamp stay atomic.
 */
static void node_db_stamp_activity(struct node_db *ndb, bool *flag_field,
                                   bool flag_value, const char *op, int rc)
{
    if (!ndb || !ndb->state_mutex_init)
        return;
    zcl_mutex_lock(&ndb->state_mutex);
    if (flag_field)
        *flag_field = flag_value;
    ndb->last_activity_time = db_now_seconds();
    ndb->last_sqlite_rc = rc;
    if (op && op[0]) {
        snprintf(ndb->last_op, sizeof(ndb->last_op), "%s", op);
    }
    zcl_mutex_unlock(&ndb->state_mutex);
}

void node_db_note_activity(struct node_db *ndb, const char *op, int rc)
{
    node_db_stamp_activity(ndb, NULL, false, op, rc);
}

void node_db_note_tx_state(struct node_db *ndb, bool tx_open,
                           const char *op, int rc)
{
    node_db_stamp_activity(ndb, ndb ? &ndb->tx_open : NULL, tx_open, op, rc);
}

void node_db_note_turbo_mode(struct node_db *ndb, bool turbo_mode,
                             const char *op, int rc)
{
    node_db_stamp_activity(ndb, ndb ? &ndb->turbo_mode : NULL, turbo_mode,
                           op, rc);
}

static bool prepare_statements(struct node_db *ndb)
{
    sqlite3 *db = ndb->db;
    int rc;

#define PREP(field, sql) do { \
    rc = sqlite3_prepare_v2(db, sql, -1, &ndb->field, NULL); \
    if (rc != SQLITE_OK) { \
        LOG_FAIL("db", "db: prepare %s: %s", #field, \
                sqlite3_errmsg(db)); \
    } \
} while (0)

    PREP(stmt_utxo_insert,
         "INSERT OR REPLACE INTO utxos"
         "(txid,vout,value,script,script_type,"
         "address_hash,height,is_coinbase)"
         " VALUES(?,?,?,?,?,?,?,?)");

    PREP(stmt_snapshot_staging_insert,
         "INSERT OR REPLACE INTO snapshot_staging_utxos"
         "(txid,vout,value,script,script_type,"
         "address_hash,height,is_coinbase)"
         " VALUES(?,?,?,?,?,?,?,?)");

    PREP(stmt_utxo_delete,
         "DELETE FROM utxos WHERE txid=? AND vout=?");

    PREP(stmt_utxo_find,
         "SELECT value,script,script_type,"
         "address_hash,height,is_coinbase"
         " FROM utxos WHERE txid=? AND vout=?");

    PREP(stmt_block_insert,
         "INSERT OR REPLACE INTO blocks"
         "(hash,height,prev_hash,version,merkle_root,"
         "time,bits,nonce,solution,chain_work,status,"
         "file_num,data_pos,undo_pos,num_tx,"
         "sapling_root,sprout_root,"
         "sapling_value,sprout_value)"
         " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)");

    PREP(stmt_block_by_hash,
         "SELECT height,prev_hash,version,merkle_root,"
         "time,bits,nonce,solution,chain_work,status,"
         "file_num,data_pos,undo_pos,num_tx,"
         "sapling_root,sprout_root,"
         "sapling_value,sprout_value"
         " FROM blocks WHERE hash=?");

    PREP(stmt_block_by_height,
         "SELECT hash,prev_hash,version,merkle_root,"
         "time,bits,nonce,solution,chain_work,status,"
         "file_num,data_pos,undo_pos,num_tx,"
         "sapling_root,sprout_root,"
         "sapling_value,sprout_value"
         " FROM blocks WHERE height=?"
         " AND status>=3 LIMIT 1");

    PREP(stmt_tx_insert,
         "INSERT OR REPLACE INTO transactions"
         "(txid,block_hash,block_height,"
         "tx_index,file_num,file_pos,is_coinbase)"
         " VALUES(?,?,?,?,?,?,?)");

    PREP(stmt_tx_find,
         "SELECT block_hash,block_height,tx_index,"
         "file_num,file_pos,is_coinbase"
         " FROM transactions WHERE txid=?");

    PREP(stmt_wallet_utxo_insert,
         "INSERT OR REPLACE INTO wallet_utxos"
         "(txid,vout,value,address_hash,"
         "script,height,is_coinbase)"
         " VALUES(?,?,?,?,?,?,?)");

    PREP(stmt_wallet_utxo_spend,
         "UPDATE wallet_utxos"
         " SET spent_txid=?,spent_vin=?"
         " WHERE txid=? AND vout=?");

    PREP(stmt_wallet_balance,
         "SELECT COALESCE(SUM(value),0)"
         " FROM wallet_utxos"
         " WHERE spent_txid IS NULL");

    PREP(stmt_nullifier_insert,
         "INSERT OR IGNORE INTO"
         " sapling_nullifiers(nullifier)"
         " VALUES(?)");

    PREP(stmt_nullifier_exists,
         "SELECT 1 FROM sapling_nullifiers"
         " WHERE nullifier=?");

    PREP(stmt_state_set,
         "INSERT OR REPLACE INTO"
         " node_state(key,value) VALUES(?,?)");

    PREP(stmt_state_get,
         "SELECT value FROM node_state"
         " WHERE key=?");

    /* Peer model */
    PREP(stmt_peer_save,
         "INSERT OR REPLACE INTO peers"
         "(ip,port,services,last_seen,last_try,attempts,source,"
         "bandwidth_score,is_zcl23)"
         " VALUES(?,?,?,?,?,?,?,?,?)");

    PREP(stmt_peer_find,
         "SELECT id,ip,port,services,last_seen,last_try,attempts,"
         "source,bandwidth_score,is_zcl23"
         " FROM peers WHERE ip=? AND port=?");

    PREP(stmt_peer_delete,
         "DELETE FROM peers WHERE ip=? AND port=?");

    PREP(stmt_peer_count,
         "SELECT COUNT(*) FROM peers");

    /* File service model */
    PREP(stmt_file_service_save,
         "INSERT OR REPLACE INTO file_services"
         " (ip, port, p2p_port, last_seen, is_zcl23)"
         " VALUES(?, ?, ?, ?, ?)");

    PREP(stmt_file_service_find,
         "SELECT ip, port, p2p_port, last_seen, is_zcl23"
         " FROM file_services WHERE ip=? AND port=?");

    /* Explorer projection inserts (full per-block indexer). All
     * INSERT OR REPLACE keyed on their natural PK so a reindex / restart
     * re-walk overwrites the row, never double-inserts. node.db only —
     * none of these touch coins_kv / progress.kv / consensus. */
    PREP(stmt_txo_insert,
         "INSERT OR REPLACE INTO tx_outputs"
         "(txid,vout,value,script_type,address_hash,block_height)"
         " VALUES(?,?,?,?,?,?)");

    PREP(stmt_txi_insert,
         "INSERT OR REPLACE INTO tx_inputs"
         "(txid,vin_index,prev_txid,prev_vout,block_height)"
         " VALUES(?,?,?,?,?)");

    PREP(stmt_opret_insert,
         "INSERT OR REPLACE INTO op_returns"
         "(txid,block_height,script,is_slp) VALUES(?,?,?,?)");

    PREP(stmt_sspend_insert,
         "INSERT OR REPLACE INTO sapling_spends"
         "(txid,spend_index,cv,anchor,nullifier,rk,block_height)"
         " VALUES(?,?,?,?,?,?,?)");

    PREP(stmt_soutput_insert,
         "INSERT OR REPLACE INTO sapling_outputs"
         "(txid,output_index,cv,cm,ephemeral_key,block_height)"
         " VALUES(?,?,?,?,?,?)");

    PREP(stmt_js_insert,
         "INSERT OR REPLACE INTO joinsplits"
         "(txid,js_index,vpub_old,vpub_new,anchor,block_height)"
         " VALUES(?,?,?,?,?,?)");

    PREP(stmt_spnf_insert,
         "INSERT OR REPLACE INTO sprout_nullifiers"
         "(nullifier,txid,block_height) VALUES(?,?,?)");

    PREP(stmt_vint_insert,
         "INSERT OR REPLACE INTO view_integrity"
         "(height,sha3_hash) VALUES(?,?)");

#undef PREP
    return true;
}

/* node.db cache_size/mmap_size derive from measured RAM (util/hw_profile.h),
 * clamped to this file's historical ceilings (64 MiB / 256 MiB) — same fixed
 * values on any >=2 GiB-RAM box, scaling DOWN on constrained ones per
 * test_db_pragma_tuning. Do NOT raise the mmap ceiling without rereading the
 * boot_index.c:306 landmine (stale mmap pages can SIGSEGV above 256 MB). */
#define ZCL_NODE_DB_CACHE_CEIL_KIB     (64 * 1024)            /* 64 MiB */
#define ZCL_NODE_DB_MMAP_CEILING_BYTES (256LL * 1024 * 1024)  /* 256 MiB */
#define ZCL_NODE_DB_CONSTRAINED_BYTES  (4LL * 1024 * 1024 * 1024)
#define ZCL_NODE_DB_MIDRANGE_BYTES     (8LL * 1024 * 1024 * 1024)
#define ZCL_NODE_DB_MIDRANGE_MMAP      (64LL * 1024 * 1024)
#define ZCL_NODE_DB_BUSY_TIMEOUT_MS 10000

static int64_t db_effective_ram_bytes(void)
{
    hw_profile_init(NULL);
    int64_t ram = hw_profile_ram_bytes();
    struct os_proc_mem mem;
    if (!os_proc_mem_read(&mem))
        return ram;
    int64_t cap = mem.cgroup_high > 0 ? mem.cgroup_high : mem.cgroup_max;
    if (cap > 0 && (ram <= 0 || cap < ram))
        ram = cap;
    return ram;
}

int64_t node_db_recommended_mmap_bytes(void)
{
    int64_t ram = db_effective_ram_bytes();
    if (ram > 0 && ram <= ZCL_NODE_DB_CONSTRAINED_BYTES)
        return 0;
    int64_t ceiling = ram > 0 && ram <= ZCL_NODE_DB_MIDRANGE_BYTES
        ? ZCL_NODE_DB_MIDRANGE_MMAP : ZCL_NODE_DB_MMAP_CEILING_BYTES;
    return hw_profile_sqlite_mmap_bytes(ram, 0, ceiling);
}

bool node_db_apply_readonly_tuning(sqlite3 *db)
{
    if (!db)
        LOG_FAIL("db", "readonly tuning requires an open SQLite handle");
    char pragma[64];
    (void)snprintf(pragma, sizeof(pragma), "PRAGMA mmap_size=%lld",
                   (long long)node_db_recommended_mmap_bytes());
    return db_exec_checked(db, pragma, "readonly_mmap_tuning") == SQLITE_OK;
}

static void db_set_pragmas(sqlite3 *db)
{
    int64_t ram = db_effective_ram_bytes();
    int64_t cache_ceiling = ram > 0 && ram <= ZCL_NODE_DB_CONSTRAINED_BYTES
        ? 16 * 1024 : ZCL_NODE_DB_CACHE_CEIL_KIB;
    int64_t cache_kib = hw_profile_sqlite_cache_kib(
        ram, 16 * 1024, cache_ceiling);
    /* The live WAL-backed node.db is concurrently read and checkpointed by
     * multiple supervised services. A mapped database page can become
     * invalid underneath sqlite3_step when the mutable file is truncated,
     * which the kernel reports as SIGBUS rather than an SQLite error. Keep
     * mmap for explicitly read-only copied/stopped handles, but never map the
     * live mutable authority ledger. */
    int64_t mmap_bytes = 0;

    /* One exec call to keep the PRAGMA batch atomic with respect to
     * other threads that might latch onto the connection immediately
     * after open_raw returns. */
    char sql[512];
    snprintf(sql, sizeof(sql),
        "PRAGMA journal_mode=WAL;"
        "PRAGMA synchronous=NORMAL;"
        "PRAGMA cache_size=-%lld;"      /* negative → KiB units */
        "PRAGMA mmap_size=%lld;"
        "PRAGMA temp_store=MEMORY;"
        "PRAGMA foreign_keys=ON",
        (long long)cache_kib,
        (long long)mmap_bytes);
    sqlite3_exec(db, sql, NULL, NULL, NULL);
    sqlite3_busy_timeout(db, ZCL_NODE_DB_BUSY_TIMEOUT_MS);
}

/* The db_long_op_progress struct + the maintenance-op progress/registry
 * machinery (db_long_op_start/finish, db_exec_checked_progress, and the
 * busy-op publication that backs node_db_long_op_active) live in
 * database_long_op.c; the shared declarations are in database_internal.h. */

/* Tier-2 fast restart: optional quick_check-skip probe (see database.h). */
static node_db_quick_check_skip_probe_fn g_quick_check_skip_probe;

void node_db_set_quick_check_skip_probe(node_db_quick_check_skip_probe_fn fn)
{
    g_quick_check_skip_probe = fn;
}

static bool db_quick_check_ok(sqlite3 *db, const char *path)
{
    sqlite3_stmt *stmt = NULL;
    bool ok = false;
    struct db_long_op_progress progress;
    db_long_op_start(db, &progress, "quick_check", path);

    int rc = sqlite3_prepare_v2(db, "PRAGMA quick_check(1)", -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        db_long_op_finish(db, &progress, false, rc);
        LOG_FAIL("db", "db: quick_check prepare failed: %s",
                sqlite3_errmsg(db));
    }
    rc = sqlite3_step(stmt);  // raw-sql-ok:read-only-introspection
    if (rc == SQLITE_ROW) {
        const unsigned char *txt = sqlite3_column_text(stmt, 0);
        ok = txt && strcmp((const char *)txt, "ok") == 0;
        if (!ok && txt) {
            LOG_WARN("db", "db: quick_check failed: %s", txt);
        }
    } else {
        LOG_WARN("db", "db: quick_check step failed: %s", sqlite3_errmsg(db));
    }
    sqlite3_finalize(stmt);
    db_long_op_finish(db, &progress, ok, rc);
    return ok;
}

static void db_quarantine_one(const char *path, const char *suffix)
{
    char dst[1400];
    if (access(path, F_OK) != 0) return;
    snprintf(dst, sizeof(dst), "%s.%s", path, suffix);
    if (db_lifetime_rename(path, dst, "node_db.quarantine",
                           DB_LIFETIME_BACKING_OWNER, 0) == 0) {
        LOG_INFO("db", "db: quarantined %s -> %s", path, dst);
    } else {
        LOG_WARN("db", "db: failed to quarantine %s: %s", path, strerror(errno));
    }
}

static void db_quarantine_files(const char *path)
{
    char wal[1200];
    char shm[1200];
    char suffix[64];
    time_t now = platform_time_wall_time_t();
    struct tm tmv;
    gmtime_r(&now, &tmv);
    strftime(suffix, sizeof(suffix), "corrupt-%Y%m%dT%H%M%SZ", &tmv);

    snprintf(wal, sizeof(wal), "%s-wal", path);
    snprintf(shm, sizeof(shm), "%s-shm", path);

    db_quarantine_one(path, suffix);
    db_quarantine_one(wal, suffix);
    db_quarantine_one(shm, suffix);
}

static bool db_open_raw(sqlite3 **db_out, const char *path)
{
    int rc = sqlite3_open_v2(path, db_out,
        SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX,
        NULL);
    if (rc != SQLITE_OK) {
        LOG_WARN("db", "db: cannot open %s: %s", path, sqlite3_errmsg(*db_out));
        sqlite3_close(*db_out);
        *db_out = NULL;
        return false;
    }
    db_set_pragmas(*db_out);
    return true;
}

static void finalize_statements(struct node_db *ndb)
{
    sqlite3_finalize(ndb->stmt_utxo_insert);
    sqlite3_finalize(ndb->stmt_snapshot_staging_insert);
    sqlite3_finalize(ndb->stmt_utxo_delete);
    sqlite3_finalize(ndb->stmt_utxo_find);
    sqlite3_finalize(ndb->stmt_block_insert);
    sqlite3_finalize(ndb->stmt_block_by_hash);
    sqlite3_finalize(ndb->stmt_block_by_height);
    sqlite3_finalize(ndb->stmt_tx_insert);
    sqlite3_finalize(ndb->stmt_tx_find);
    sqlite3_finalize(ndb->stmt_wallet_utxo_insert);
    sqlite3_finalize(ndb->stmt_wallet_utxo_spend);
    sqlite3_finalize(ndb->stmt_wallet_balance);
    sqlite3_finalize(ndb->stmt_nullifier_insert);
    sqlite3_finalize(ndb->stmt_nullifier_exists);
    sqlite3_finalize(ndb->stmt_state_set);
    sqlite3_finalize(ndb->stmt_state_get);
    sqlite3_finalize(ndb->stmt_peer_save);
    sqlite3_finalize(ndb->stmt_peer_find);
    sqlite3_finalize(ndb->stmt_peer_delete);
    sqlite3_finalize(ndb->stmt_peer_count);
    sqlite3_finalize(ndb->stmt_file_service_save);
    sqlite3_finalize(ndb->stmt_file_service_find);
    sqlite3_finalize(ndb->stmt_txo_insert);
    sqlite3_finalize(ndb->stmt_txi_insert);
    sqlite3_finalize(ndb->stmt_opret_insert);
    sqlite3_finalize(ndb->stmt_sspend_insert);
    sqlite3_finalize(ndb->stmt_soutput_insert);
    sqlite3_finalize(ndb->stmt_js_insert);
    sqlite3_finalize(ndb->stmt_spnf_insert);
    sqlite3_finalize(ndb->stmt_vint_insert);
}

/* Close the half-open handle and return false (uniform open-failure exit).
 * Leaves the struct harmless to node_db_close(): db NULLed, open false, and
 * the state mutex destroyed — a caller may close unconditionally on any open
 * failure, and a repeated close is then a guarded no-op. */
static bool node_db_open_abort(struct node_db *ndb)
{
    if (ndb->db) {
        struct db_lifetime_scope scope;
        db_lifetime_scope_enter(
            &scope,
            ndb->lifetime_owner[0] ? ndb->lifetime_owner : "node_db.abort",
            ndb->lifetime_backing_owner ? DB_LIFETIME_BACKING_OWNER
                                        : DB_LIFETIME_HANDLE_OWNER,
            ndb->lifetime_generation);
        sqlite3_close(ndb->db);
        db_lifetime_scope_leave(&scope);
        ndb->db = NULL;
    }
    ndb->open = false;
    node_db_state_destroy(ndb);
    node_db_owner_lease_release(ndb);
    return false;
}

/* Shared open path. boot_ceremony=true is the one-time boot open (quick_check +
 * migration banner + staging cleanup); false is a runtime reopen that skips all
 * three and names itself (see node_db_open_runtime). */
static bool node_db_open_impl(struct node_db *ndb, const char *path,
                              bool boot_ceremony, const char *reason)
{
    memset(ndb, 0, sizeof(*ndb));
    ndb->lifetime_owner_lease_slot = -1;
    if (path)
        snprintf(ndb->path, sizeof(ndb->path), "%s", path);
    node_db_state_init(ndb);
    if (!db_lifetime_install())
        return node_db_open_abort(ndb);
    ndb->lifetime_backing_owner = boot_ceremony;
    (void)snprintf(ndb->lifetime_owner, sizeof(ndb->lifetime_owner), "%s",
                   boot_ceremony ? "node_db.canonical" : reason);
    /* Every mutable handle explicitly joins the pathname lease.  In-process
     * runtime helpers share the canonical owner's lease; a one-shot process
     * cannot open the live node database behind that owner's back. */
    if (!node_db_owner_lease_acquire(ndb, true))
        return node_db_open_abort(ndb);

    /* No anonymous DB open: a reopen names who/why so it cannot look like a
     * silent boot loop in a filtered log. */
    if (!boot_ceremony)
        LOG_INFO("db", "db: runtime reopen (reason=%s) path=%s",
                 reason ? reason : "(unnamed)", path ? path : "(null)");

    /* Existing-file preflight happens before db_open_raw's
     * READWRITE|CREATE open and journal_mode=WAL pragma.  UNKNOWN is distinct
     * from fresh: a malformed/missing/contradictory marker on an existing
     * store must never be interpreted as schema 0 and migrated in place. */
    struct node_db_schema_preflight preflight =
        node_db_schema_preflight_existing(path);
    if (preflight.state == NODE_DB_SCHEMA_PREFLIGHT_NEWER) {
        node_db_log_newer_schema_refusal((int)preflight.version);
        return node_db_open_abort(ndb);
    }
    if (preflight.state == NODE_DB_SCHEMA_PREFLIGHT_UNKNOWN) {
        node_db_log_unknown_schema_refusal(preflight.detail);
        return node_db_open_abort(ndb);
    }

    struct db_lifetime_scope open_scope;
    db_lifetime_scope_enter(
        &open_scope, ndb->lifetime_owner,
        boot_ceremony ? DB_LIFETIME_BACKING_OWNER
                      : DB_LIFETIME_HANDLE_OWNER,
        0);
    bool raw_opened = db_open_raw(&ndb->db, path);
    ndb->lifetime_generation = db_lifetime_scope_generation();
    db_lifetime_scope_leave(&open_scope);
    if (!raw_opened)
        return node_db_open_abort(ndb);
    if (boot_ceremony) {
        /* Skip-probe: true = verified-clean skip or unclean/unverified
         * deferral (probe logs which). False = run blocking PRAGMA. */
        bool skip_quick_check = g_quick_check_skip_probe && path &&
                                g_quick_check_skip_probe(path);
        if (!skip_quick_check) {
            int64_t t_qc = db_now_ms();
            bool qc_ok = db_quick_check_ok(ndb->db, path);
            printf("[boot]   %-28s %lldms\n", "sqlite.quick_check",
                   (long long)(db_now_ms() - t_qc));
            if (!qc_ok) {
                LOG_INFO("db", "db: %s is malformed; rebuilding fresh SQLite state",
                         path);
                sqlite3_close(ndb->db);
                ndb->db = NULL;
                db_quarantine_files(path);
                if (!node_db_owner_lease_rebind(ndb))
                    return node_db_open_abort(ndb);
                db_lifetime_scope_enter(
                    &open_scope, ndb->lifetime_owner,
                    boot_ceremony ? DB_LIFETIME_BACKING_OWNER
                                  : DB_LIFETIME_HANDLE_OWNER,
                    ndb->lifetime_generation);
                raw_opened = db_open_raw(&ndb->db, path);
                ndb->lifetime_generation = db_lifetime_scope_generation();
                db_lifetime_scope_leave(&open_scope);
                if (!raw_opened)
                    return node_db_open_abort(ndb);
            }
        }
    }

    if (!create_schema(ndb))
        return node_db_open_abort(ndb);

    ndb->open = true; /* node_db_migrate uses node_db_state_* helpers. */
    /* Runtime reopen is already at current schema — suppress the banner. */
    ndb->suppress_migrate_banner = !boot_ceremony;
    int migrated = node_db_migrate(ndb, NULL);
    ndb->suppress_migrate_banner = false;
    ndb->open = false;
    if (migrated < 0)
        return node_db_open_abort(ndb);
    /* Crash recovery: staged snapshot rows are never authoritative across
     * process lifetimes. BOOT-only (a reopen must not re-run it every cycle). */
    if (boot_ceremony &&
        (db_exec_checked_progress(ndb->db,
            "DELETE FROM snapshot_staging_utxos",
            "snapshot_staging_boot_cleanup", path) != SQLITE_OK ||
         db_exec_checked_progress(ndb->db,
            "DELETE FROM node_state WHERE key LIKE 'snapshot_staging_%'",
            "snapshot_staging_state_boot_cleanup", path) != SQLITE_OK))
        return node_db_open_abort(ndb);
    if (!prepare_statements(ndb))
        return node_db_open_abort(ndb);

    ndb->open = true;
    db_register_all_validators();                  /* idempotent per process */
    zcl_db_txn_trace_register(ndb->db, "node_db"); /* ZCL_DB_TXN_TRACE opt-in */
    node_db_note_activity(ndb, "open", SQLITE_OK);
    return true;
}

bool node_db_open(struct node_db *ndb, const char *path)
{
    return node_db_open_impl(ndb, path, /*boot_ceremony=*/true, "boot");
}
bool node_db_open_runtime(struct node_db *ndb, const char *path,
                          const char *reason)
{
    /* Mandatory reason (LOG_FAIL returns false; LOG_ERR would return -1). */
    if (!reason || reason[0] == '\0') {
        memset(ndb, 0, sizeof(*ndb));
        LOG_FAIL("db", "node_db_open_runtime: reason is mandatory (path=%s)",
                 path ? path : "(null)");
    }
    return node_db_open_impl(ndb, path, /*boot_ceremony=*/false, reason);
}

bool node_db_open_existing_runtime(struct node_db *ndb, const char *path,
                                   const char *reason)
{
    if (!ndb)
        LOG_FAIL("db", "node_db_open_existing_runtime: output is required");
    memset(ndb, 0, sizeof(*ndb));
    ndb->lifetime_owner_lease_slot = -1;
    if (!path || !path[0] || !reason || !reason[0])
        LOG_FAIL("db", "node_db_open_existing_runtime: path and reason are "
                 "mandatory");

    (void)snprintf(ndb->path, sizeof(ndb->path), "%s", path);
    node_db_state_init(ndb);
    if (!db_lifetime_install())
        return node_db_open_abort(ndb);
    (void)snprintf(ndb->lifetime_owner, sizeof(ndb->lifetime_owner), "%s",
                   reason);
    ndb->lifetime_backing_owner = false;
    if (!node_db_owner_lease_acquire(ndb, false))
        return node_db_open_abort(ndb);
    LOG_INFO("db", "db: lightweight runtime reopen (reason=%s) path=%s",
             reason, path);

    struct db_lifetime_scope open_scope;
    db_lifetime_scope_enter(&open_scope, ndb->lifetime_owner,
                            DB_LIFETIME_HANDLE_OWNER, 0);
    int rc = sqlite3_open_v2(path, &ndb->db,
        SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX, NULL);
    ndb->lifetime_generation = db_lifetime_scope_generation();
    if (rc != SQLITE_OK || !ndb->db) {
        LOG_WARN("db", "lightweight runtime reopen failed: %s",
                 ndb->db ? sqlite3_errmsg(ndb->db) : "no sqlite handle");
        db_lifetime_scope_leave(&open_scope);
        return node_db_open_abort(ndb);
    }
    /* The boot connection already selected WAL for the database. These are
     * connection-local settings only: no journal-mode transition, mapped live
     * pages, schema DDL, migration, or full cached-statement preparation on a
     * periodic open. A small cache prevents a short-lived poller from competing
     * with the canonical connection for the lane's memory ceiling. */
    (void)sqlite3_exec(ndb->db,
        "PRAGMA synchronous=NORMAL;"
        "PRAGMA cache_size=-2048;"
        "PRAGMA mmap_size=0;"
        "PRAGMA temp_store=MEMORY;"
        "PRAGMA foreign_keys=ON",
        NULL, NULL, NULL);
    (void)sqlite3_busy_timeout(ndb->db, ZCL_NODE_DB_BUSY_TIMEOUT_MS);
    ndb->open = true;

    int schema = node_db_schema_version(ndb);
    if (schema != NODE_DB_MAX_SCHEMA) {
        LOG_WARN("db", "lightweight runtime reopen refused schema=%d "
                 "expected=%d reason=%s", schema, NODE_DB_MAX_SCHEMA, reason);
        ndb->open = false;
        db_lifetime_scope_leave(&open_scope);
        return node_db_open_abort(ndb);
    }

    db_register_all_validators();
    zcl_db_txn_trace_register(ndb->db, reason);
    node_db_note_activity(ndb, "open_existing_runtime", SQLITE_OK);
    db_lifetime_scope_leave(&open_scope);
    return true;
}

void node_db_close(struct node_db *ndb)
{
    if (!ndb)
        return;
    if (!ndb->open) {
        node_db_state_destroy(ndb);
        return;
    }
    node_db_note_activity(ndb, "close", SQLITE_OK);
    zcl_db_txn_trace_unregister(ndb->db);
    finalize_statements(ndb);
    /* sqlite3_close() returns SQLITE_BUSY if any prepared statement/backup on
     * this handle is un-finalized; a leaked handle keeps its txn + WAL lock
     * alive for the process (an "unreachable silent halt"). Finalize every
     * leftover stmt via sqlite3_next_stmt() and retry the close. */
    struct db_lifetime_scope close_scope;
    db_lifetime_scope_enter(
        &close_scope,
        ndb->lifetime_owner[0] ? ndb->lifetime_owner : "node_db.close",
        ndb->lifetime_backing_owner ? DB_LIFETIME_BACKING_OWNER
                                    : DB_LIFETIME_HANDLE_OWNER,
        ndb->lifetime_generation);
    int close_rc = sqlite3_close(ndb->db);
    if (close_rc == SQLITE_BUSY) {
        int leaked = 0;
        sqlite3_stmt *s;
        while ((s = sqlite3_next_stmt(ndb->db, NULL)) != NULL) {
            const char *sql = sqlite3_sql(s);
            LOG_WARN("db",
                "node_db_close: leaked prepared statement blocked close: %s",
                sql ? sql : "(null)");
            sqlite3_finalize(s);
            leaked++;
        }
        close_rc = sqlite3_close(ndb->db);
        LOG_WARN("db",
            "node_db_close: SQLITE_BUSY on close (%d leaked stmt(s) finalized); "
            "retry rc=%d", leaked, close_rc);
    }
    db_lifetime_scope_leave(&close_scope);
    ndb->open = false;
    node_db_state_destroy(ndb);
    node_db_owner_lease_release(ndb);
}

/* node_db_state_*, node_db_schema_version, and node_db_migrate live
 * in database_migrate.c (the KV store + migration runner). */
