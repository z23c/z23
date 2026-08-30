/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * consensus_db — one-time, integrity-verified migration of the reducer's
 * consensus kernel atomic set out of progress.kv into a dedicated
 * consensus.db. See storage/consensus_db.h for the contract and the
 * writer-contention rationale.
 *
 * This module sits BELOW the AR lifecycle for the same reason progress_store
 * and coins_kv do: it manipulates the kernel primitive store itself (schema
 * creation + a raw table-to-table copy), not a model. Its direct sqlite3_*
 * calls carry the kernel-store marker used by progress_store.c / coins_kv.c. */

#include "storage/consensus_db.h"

#include "base/hex.h"
#include "storage/anchor_kv.h"
#include "storage/coins_kv.h"
#include "storage/nullifier_kv.h"
#include "storage/progress_store.h"
#include "util/log_macros.h"
#include "util/stage.h"

#include <sqlite3.h>

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#ifdef ZCL_TESTING
#include <stdatomic.h>
#endif

#ifdef ZCL_TESTING
/* Test seams: count the progress.kv open+ATTACH cycle in the drop path and the
 * BEGIN IMMEDIATE write-lock acquisitions, so a test can assert that a steady-
 * state (post-flip) finalize short-circuits (no open) and that an already-drained
 * drop takes no write transaction (ndrop==0 ⇒ no BEGIN). */
_Atomic unsigned long g_consensus_db_drop_pdb_opens = 0;
_Atomic unsigned long g_consensus_db_drop_txn_begins = 0;
#endif

/* The kernel atomic set, in the stable order the fingerprint indexes.  These
 * are exactly the tables committed together on the reducer batch-commit path
 * (see utxo_apply_stage.c: coins/anchors/nullifiers authored inside the same
 * BEGIN IMMEDIATE as the stage_cursor advance and the progress_meta writes). */
static const char *const KERNEL_TABLES[CONSENSUS_DB_KERNEL_TABLE_COUNT] = {
    "coins",           /* 0 — carries the SHA3 UTXO commitment */
    "sprout_anchors",  /* 1 */
    "sapling_anchors", /* 2 */
    "anchor_state",    /* 3 */
    "nullifiers",      /* 4 */
    "progress_meta",   /* 5 */
    "stage_cursor",    /* 6 */
};

/* Class C — the projection tables written through projection_store (the SECOND
 * handle to progress.kv), NOT the kernel handle. These STAY in progress.kv and
 * must NEVER be copied into consensus.db or dropped from progress.kv. This is
 * the ONLY exclusion list the migration consults: the move set is "every source
 * table that is not one of these" (plus not a sqlite_ internal), so a new
 * kernel table can never be silently missed.
 *
 * NOTE created_outputs is deliberately NOT here: it is written by body_persist
 * and read by script_validate through the KERNEL handle, so it is a kernel-file
 * table (its post-commit prune + replay-backfill run on the kernel connection).
 * Only address_index / txindex (+ their _state rows) are written exclusively
 * through projection_store. */
const char *const consensus_db_projection_stay[
    CONSENSUS_DB_PROJECTION_STAY_COUNT] = {
    "address_index",
    "address_index_state",
    "txindex",
    "txindex_state",
};

/* Class B + D — the non-fingerprinted tables written INSIDE kernel txs (Class B:
 * the stage *_log journals + utxo_apply_delta, read back as consensus gates by
 * the reducer frontier) or cleared atomically with kernel installs (Class D: the
 * producer session/receipt rows). Documentation + a positive assertion target
 * only: the copy loop moves them because they are not projection-STAY tables,
 * not because they appear here. Kept so the intended move set is self-describing
 * and a regression that stops moving one is caught by the assertion. */
static const char *const KERNEL_COPY_EXTRA[] = {
    "validate_headers_log",
    "header_admit_log",
    "body_fetch_log",
    "body_persist_log",
    "script_validate_log",
    "proof_validate_log",
    "utxo_apply_log",
    "tip_finalize_log",
    "utxo_apply_delta",
    "header_solution_repair",
    "consensus_state_producer_session",
    "consensus_state_source_receipt",
};
#define KERNEL_COPY_EXTRA_COUNT \
    (sizeof(KERNEL_COPY_EXTRA) / sizeof(KERNEL_COPY_EXTRA[0]))

static bool cdb_is_projection_stay(const char *name)
{
    for (size_t i = 0; i < CONSENSUS_DB_PROJECTION_STAY_COUNT; i++)
        if (strcmp(name, consensus_db_projection_stay[i]) == 0)
            return true;
    return false;
}

static bool cdb_is_fingerprint_kernel(const char *name)
{
    for (size_t i = 0; i < CONSENSUS_DB_KERNEL_TABLE_COUNT; i++)
        if (strcmp(name, KERNEL_TABLES[i]) == 0)
            return true;
    return false;
}

/* Optional message helper — errbuf may be NULL. */
static void cdb_set_err(char *errbuf, size_t errcap, const char *fmt, ...)
{
    if (!errbuf || errcap == 0)
        return;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(errbuf, errcap, fmt, ap);
    va_end(ap);
}

static bool cdb_table_exists(sqlite3 *db, const char *name)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(
            db,
            "SELECT 1 FROM sqlite_schema WHERE type='table' AND name=?1",
            -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_text(st, 1, name, -1, SQLITE_STATIC);
    bool found = sqlite3_step(st) == SQLITE_ROW; // raw-sql-ok:progress-kv-kernel-store
    sqlite3_finalize(st);
    return found;
}

/* Durable row count of `table`. A missing table (or a prepare error) yields 0
 * so a source that never created an optional kernel table compares equal to a
 * freshly schema-ensured, empty destination table. */
static int64_t cdb_table_count(sqlite3 *db, const char *table)
{
    if (!cdb_table_exists(db, table))
        return 0;
    char sql[96];
    /* `table` is only ever from the fixed KERNEL_TABLES list — no injection. */
    snprintf(sql, sizeof(sql), "SELECT COUNT(*) FROM %s", table);
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK)
        return 0;
    int64_t n = 0;
    if (sqlite3_step(st) == SQLITE_ROW) // raw-sql-ok:progress-kv-kernel-store
        n = sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    return n;
}

bool consensus_db_read_kernel_stats(sqlite3 *db,
                                    struct consensus_db_kernel_stats *out,
                                    char *errbuf, size_t errcap)
{
    if (!db || !out)
        LOG_FAIL("consensus_db", "read_kernel_stats: NULL db/out");

    memset(out, 0, sizeof(*out));

    if (!cdb_table_exists(db, "coins")) {
        cdb_set_err(errbuf, errcap,
                    "consensus_db: no coins table (uninitialised kernel)");
        return false;
    }

    /* Canonical SHA3-256 UTXO commitment over `coins`.  Reads the on-disk
     * table directly (this runs before the coins_ram overlay is bound); if the
     * overlay WERE active coins_kv_commitment would answer from RAM, so this is
     * documented as an overlay-absent primitive. */
    if (coins_kv_commitment(db, out->coins_commit) != 0) {
        cdb_set_err(errbuf, errcap,
                    "consensus_db: coins sha3 commitment read failed");
        return false;
    }

    for (size_t i = 0; i < CONSENSUS_DB_KERNEL_TABLE_COUNT; i++)
        out->table_rows[i] = cdb_table_count(db, KERNEL_TABLES[i]);

    return true;
}

bool consensus_db_kernel_stats_match(const struct consensus_db_kernel_stats *a,
                                     const struct consensus_db_kernel_stats *b,
                                     char *errbuf, size_t errcap)
{
    if (!a || !b)
        LOG_FAIL("consensus_db", "kernel_stats_match: NULL operand");

    if (memcmp(a->coins_commit, b->coins_commit, 32) != 0) {
        char ha[65], hb[65];
        zcl_hex_encode(a->coins_commit, 32, ha);
        zcl_hex_encode(b->coins_commit, 32, hb);
        cdb_set_err(errbuf, errcap,
                    "consensus_db: coins sha3 commitment mismatch src=%s dst=%s",
                    ha, hb);
        return false;
    }

    for (size_t i = 0; i < CONSENSUS_DB_KERNEL_TABLE_COUNT; i++) {
        if (a->table_rows[i] != b->table_rows[i]) {
            cdb_set_err(errbuf, errcap,
                        "consensus_db: %s row count mismatch src=%lld dst=%lld",
                        KERNEL_TABLES[i], (long long)a->table_rows[i],
                        (long long)b->table_rows[i]);
            return false;
        }
    }
    return true;
}

/* Create every kernel table on the destination via the SAME CREATE TABLE text
 * the live store uses, so an `INSERT INTO main.T SELECT * FROM src.T` copy
 * aligns column-for-column. */
static bool cdb_ensure_kernel_schema(sqlite3 *db)
{
    return coins_kv_ensure_schema(db) &&
           anchor_kv_ensure_schema(db) &&
           nullifier_kv_ensure_schema(db) &&
           progress_meta_table_ensure(db) &&
           stage_table_ensure(db);
}

/* Copy one kernel table src.<name> → main.<name> (both already schema-ensured
 * on the dest connection with src ATTACHed).  A source that lacks an optional
 * table is a clean no-op — the empty dest table then matches its 0-row source
 * count during verification. */
static bool cdb_copy_table(sqlite3 *db, const char *name, char *errbuf,
                           size_t errcap)
{
    if (!cdb_table_exists(db, name)) /* checks main.<name> — always present */
        LOG_FAIL("consensus_db", "copy_table: dest %s missing after ensure",
                 name);

    /* Existence of src.<name>: query the src schema explicitly. */
    sqlite3_stmt *chk = NULL;
    if (sqlite3_prepare_v2(
            db,
            "SELECT 1 FROM src.sqlite_schema WHERE type='table' AND name=?1",
            -1, &chk, NULL) != SQLITE_OK) {
        cdb_set_err(errbuf, errcap, "consensus_db: src schema probe failed: %s",
                    sqlite3_errmsg(db));
        return false;
    }
    sqlite3_bind_text(chk, 1, name, -1, SQLITE_STATIC);
    bool src_has = sqlite3_step(chk) == SQLITE_ROW; // raw-sql-ok:progress-kv-kernel-store
    sqlite3_finalize(chk);
    if (!src_has)
        return true; /* nothing to copy for this table */

    char sql[128];
    snprintf(sql, sizeof(sql), "INSERT INTO main.%s SELECT * FROM src.%s",
             name, name);
    char *err = NULL;
    if (sqlite3_exec(db, sql, NULL, NULL, &err) != SQLITE_OK) {
        cdb_set_err(errbuf, errcap, "consensus_db: copy %s failed: %s", name,
                    err ? err : "(no message)");
        if (err) sqlite3_free(err);
        return false;
    }
    if (err) sqlite3_free(err);
    return true;
}

/* Row count of `schema`.`table` (schema is "main" or "src"). A missing table or
 * prepare error yields -1 (distinct from a real 0-row count). */
static int64_t cdb_qualified_count(sqlite3 *db, const char *schema,
                                   const char *table)
{
    char sql[160];
    /* `schema` is a fixed literal, `table` is only ever a sqlite_schema name
     * enumerated from this same DB — no injection surface. */
    snprintf(sql, sizeof(sql), "SELECT COUNT(*) FROM %s.\"%s\"", schema, table);
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK)
        return -1;
    int64_t n = -1;
    if (sqlite3_step(st) == SQLITE_ROW) // raw-sql-ok:progress-kv-kernel-store
        n = sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    return n;
}

/* Recreate the exact schema objects (table DDL + its explicit indexes/triggers)
 * for src.<name> onto the destination `main`, using the source's own CREATE
 * text so an `INSERT INTO main.<name> SELECT * FROM src.<name>` aligns
 * column-for-column, then copy the rows. Used for the non-fingerprinted kernel
 * tables (Class B/D) whose schema-ensure functions live above this layer. The
 * dest table is assumed absent (fingerprint tables are handled separately and
 * excluded by the caller). */
static bool cdb_ddl_copy_table(sqlite3 *db, const char *name, char *errbuf,
                               size_t errcap)
{
    /* 1) table DDL from the source. */
    sqlite3_stmt *q = NULL;
    if (sqlite3_prepare_v2(
            db,
            "SELECT sql FROM src.sqlite_schema "
            "WHERE type='table' AND name=?1 AND sql IS NOT NULL",
            -1, &q, NULL) != SQLITE_OK) {
        cdb_set_err(errbuf, errcap, "consensus_db: src ddl probe failed: %s",
                    sqlite3_errmsg(db));
        return false;
    }
    sqlite3_bind_text(q, 1, name, -1, SQLITE_STATIC);
    const char *ddl = NULL;
    char ddl_buf[4096];
    ddl_buf[0] = '\0';
    if (sqlite3_step(q) == SQLITE_ROW) { // raw-sql-ok:progress-kv-kernel-store
        const unsigned char *t = sqlite3_column_text(q, 0);
        if (t) {
            snprintf(ddl_buf, sizeof(ddl_buf), "%s", (const char *)t);
            ddl = ddl_buf;
        }
    }
    sqlite3_finalize(q);
    if (!ddl || !ddl[0]) {
        cdb_set_err(errbuf, errcap,
                    "consensus_db: %s has no copyable CREATE ddl", name);
        return false;
    }

    char *err = NULL;
    if (sqlite3_exec(db, ddl, NULL, NULL, &err) != SQLITE_OK) {
        cdb_set_err(errbuf, errcap, "consensus_db: create %s on dest failed: %s",
                    name, err ? err : "(no message)");
        if (err) sqlite3_free(err);
        return false;
    }
    if (err) { sqlite3_free(err); err = NULL; }

    /* 2) rows. */
    char ins[160];
    snprintf(ins, sizeof(ins), "INSERT INTO main.\"%s\" SELECT * FROM src.\"%s\"",
             name, name);
    if (sqlite3_exec(db, ins, NULL, NULL, &err) != SQLITE_OK) {
        cdb_set_err(errbuf, errcap, "consensus_db: copy %s rows failed: %s",
                    name, err ? err : "(no message)");
        if (err) sqlite3_free(err);
        return false;
    }
    if (err) { sqlite3_free(err); err = NULL; }

    /* 3) explicit indexes/triggers (auto-indexes carry sql IS NULL and are
     *    recreated implicitly by the table DDL — skip them). */
    sqlite3_stmt *ix = NULL;
    if (sqlite3_prepare_v2(
            db,
            "SELECT sql FROM src.sqlite_schema "
            "WHERE type IN('index','trigger') AND tbl_name=?1 "
            "AND sql IS NOT NULL",
            -1, &ix, NULL) != SQLITE_OK) {
        cdb_set_err(errbuf, errcap, "consensus_db: %s index probe failed: %s",
                    name, sqlite3_errmsg(db));
        return false;
    }
    sqlite3_bind_text(ix, 1, name, -1, SQLITE_STATIC);
    bool ok = true;
    while (ok && sqlite3_step(ix) == SQLITE_ROW) { // raw-sql-ok:progress-kv-kernel-store
        const unsigned char *t = sqlite3_column_text(ix, 0);
        if (!t) continue;
        char one[2048];
        snprintf(one, sizeof(one), "%s", (const char *)t);
        if (sqlite3_exec(db, one, NULL, NULL, &err) != SQLITE_OK) {
            cdb_set_err(errbuf, errcap,
                        "consensus_db: %s index create failed: %s", name,
                        err ? err : "(no message)");
            if (err) sqlite3_free(err);
            ok = false;
        }
        if (err) { sqlite3_free(err); err = NULL; }
    }
    sqlite3_finalize(ix);
    return ok;
}

/* Copy every source (progress.kv) table that is NOT a projection STAY table into
 * the destination consensus.db (src already ATTACHed as `src`, the 7 fingerprint
 * tables already schema-ensured on `main`). The 7 fingerprint tables copy via
 * cdb_copy_table (schema-ensured dest); all other non-STAY tables DDL-copy. This
 * enumerate-and-exclude shape is the completeness guarantee: any table reached
 * through the kernel handle moves, so nothing is left behind for the repointed
 * kernel handle to auto-recreate empty. */
static bool cdb_copy_nonstay_tables(sqlite3 *db, char *errbuf, size_t errcap)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(
            db,
            "SELECT name FROM src.sqlite_schema "
            "WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name",
            -1, &st, NULL) != SQLITE_OK) {
        cdb_set_err(errbuf, errcap, "consensus_db: src table enumerate failed: %s",
                    sqlite3_errmsg(db));
        return false;
    }
    bool ok = true;
    while (ok && sqlite3_step(st) == SQLITE_ROW) { // raw-sql-ok:progress-kv-kernel-store
        const unsigned char *nm = sqlite3_column_text(st, 0);
        if (!nm) continue;
        char name[128];
        snprintf(name, sizeof(name), "%s", (const char *)nm);
        if (cdb_is_projection_stay(name))
            continue;                              /* Class C — stays in progress.kv */
        if (cdb_is_fingerprint_kernel(name))
            ok = cdb_copy_table(db, name, errbuf, errcap);   /* schema-ensured */
        else
            ok = cdb_ddl_copy_table(db, name, errbuf, errcap); /* Class B/D + any */
    }
    sqlite3_finalize(st);
    return ok;
}

/* Prove the copy is complete: for every source non-STAY table, the destination
 * row count EQUALS the source. This is the row-level completeness proof that
 * backs the enumerate-and-exclude copy (the 7-table SHA3 fingerprint covers the
 * kernel atomic set; this covers the Class B/D tables too). */
static bool cdb_verify_nonstay_counts(sqlite3 *db, char *errbuf, size_t errcap)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(
            db,
            "SELECT name FROM src.sqlite_schema "
            "WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name",
            -1, &st, NULL) != SQLITE_OK) {
        cdb_set_err(errbuf, errcap, "consensus_db: verify enumerate failed: %s",
                    sqlite3_errmsg(db));
        return false;
    }
    bool ok = true;
    while (ok && sqlite3_step(st) == SQLITE_ROW) { // raw-sql-ok:progress-kv-kernel-store
        const unsigned char *nm = sqlite3_column_text(st, 0);
        if (!nm) continue;
        char name[128];
        snprintf(name, sizeof(name), "%s", (const char *)nm);
        if (cdb_is_projection_stay(name))
            continue;
        int64_t sc = cdb_qualified_count(db, "src", name);
        int64_t dc = cdb_qualified_count(db, "main", name);
        if (sc != dc) {
            cdb_set_err(errbuf, errcap,
                        "consensus_db: %s row count mismatch src=%lld dst=%lld",
                        name, (long long)sc, (long long)dc);
            ok = false;
        }
    }
    sqlite3_finalize(st);
    if (!ok)
        return false;

    /* Positive assertion: every documented Class B/D table that EXISTS in the
     * source MUST exist in the destination (guards a regression that stops
     * moving one — e.g. a name accidentally added to the STAY list). */
    sqlite3_stmt *chk = NULL;
    if (sqlite3_prepare_v2(
            db, "SELECT 1 FROM src.sqlite_schema WHERE type='table' AND name=?1",
            -1, &chk, NULL) != SQLITE_OK) {
        cdb_set_err(errbuf, errcap, "consensus_db: extra-table probe failed: %s",
                    sqlite3_errmsg(db));
        return false;
    }
    for (size_t i = 0; ok && i < KERNEL_COPY_EXTRA_COUNT; i++) {
        sqlite3_reset(chk);
        sqlite3_bind_text(chk, 1, KERNEL_COPY_EXTRA[i], -1, SQLITE_STATIC);
        bool src_has = sqlite3_step(chk) == SQLITE_ROW; // raw-sql-ok:progress-kv-kernel-store
        if (src_has && !cdb_table_exists(db, KERNEL_COPY_EXTRA[i])) {
            cdb_set_err(errbuf, errcap,
                        "consensus_db: kernel table %s present in source but "
                        "missing from consensus.db (incomplete migration)",
                        KERNEL_COPY_EXTRA[i]);
            ok = false;
        }
    }
    sqlite3_finalize(chk);
    return ok;
}

static void cdb_unlink_family(const char *base)
{
    char p[1200];
    (void)unlink(base);
    snprintf(p, sizeof(p), "%s-wal", base);
    (void)unlink(p);
    snprintf(p, sizeof(p), "%s-shm", base);
    (void)unlink(p);
    snprintf(p, sizeof(p), "%s-journal", base);
    (void)unlink(p);
}

bool consensus_db_migrate_from_progress(const char *datadir, char *errbuf,
                                        size_t errcap)
{
    if (!datadir || !datadir[0])
        LOG_FAIL("consensus_db", "migrate: empty datadir");

    char cpath[1024];
    char ppath[1024];
    char tpath[1040];
    int n = snprintf(cpath, sizeof(cpath), "%s/%s", datadir,
                     CONSENSUS_DB_FILENAME);
    if (n <= 0 || (size_t)n >= sizeof(cpath))
        LOG_FAIL("consensus_db", "migrate: consensus.db path too long");
    n = snprintf(ppath, sizeof(ppath), "%s/progress.kv", datadir);
    if (n <= 0 || (size_t)n >= sizeof(ppath))
        LOG_FAIL("consensus_db", "migrate: progress.kv path too long");
    n = snprintf(tpath, sizeof(tpath), "%s.tmp", cpath);
    if (n <= 0 || (size_t)n >= sizeof(tpath))
        LOG_FAIL("consensus_db", "migrate: tmp path too long");

    /* Idempotent: already migrated. */
    if (access(cpath, F_OK) == 0)
        return true;

    /* Fresh node: no progress.kv to migrate — boot creates consensus.db. */
    if (access(ppath, F_OK) != 0)
        return true;

    /* 1) Fingerprint the SOURCE, then close it before the ATTACH copy so the
     *    WAL file has a single writer/owner during the copy. */
    struct consensus_db_kernel_stats src_stats;
    {
        sqlite3 *src = NULL;
        if (sqlite3_open_v2(ppath, &src,
                            SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX,
                            NULL) != SQLITE_OK) {
            cdb_set_err(errbuf, errcap, "consensus_db: open source %s failed: %s",
                        ppath, src ? sqlite3_errmsg(src) : "(open)");
            if (src) sqlite3_close(src);
            return false;
        }
        if (!cdb_table_exists(src, "coins")) {
            /* progress.kv present but uninitialised — nothing to migrate. */
            sqlite3_close(src);
            return true;
        }
        bool ok = consensus_db_read_kernel_stats(src, &src_stats, errbuf, errcap);
        sqlite3_close(src);
        if (!ok)
            return false;
    }

    /* 2) Build consensus.db.tmp fresh and copy the atomic set into it.  Use a
     *    rollback journal (default) so the finished file is self-contained —
     *    no -wal to carry across the rename; progress_store switches the real
     *    consensus.db to WAL on its first open. */
    cdb_unlink_family(tpath);
    sqlite3 *dst = NULL;
    if (sqlite3_open_v2(tpath, &dst,
                        SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE |
                            SQLITE_OPEN_FULLMUTEX,
                        NULL) != SQLITE_OK) {
        cdb_set_err(errbuf, errcap, "consensus_db: create %s failed: %s", tpath,
                    dst ? sqlite3_errmsg(dst) : "(open)");
        if (dst) sqlite3_close(dst);
        cdb_unlink_family(tpath);
        return false;
    }

    bool ok = cdb_ensure_kernel_schema(dst);
    if (!ok)
        cdb_set_err(errbuf, errcap, "consensus_db: dest schema ensure failed");

    if (ok) {
        char *err = NULL;
        char attach[1200];
        snprintf(attach, sizeof(attach), "ATTACH DATABASE '%s' AS src", ppath);
        if (sqlite3_exec(dst, attach, NULL, NULL, &err) != SQLITE_OK) {
            cdb_set_err(errbuf, errcap, "consensus_db: attach source failed: %s",
                        err ? err : "(no message)");
            if (err) sqlite3_free(err);
            ok = false;
        }
        if (err) { sqlite3_free(err); err = NULL; }

        if (ok && sqlite3_exec(dst, "BEGIN IMMEDIATE", NULL, NULL, &err) !=
                      SQLITE_OK) {
            cdb_set_err(errbuf, errcap, "consensus_db: dest BEGIN failed: %s",
                        err ? err : "(no message)");
            if (err) sqlite3_free(err);
            ok = false;
        }
        if (err) { sqlite3_free(err); err = NULL; }

        /* Copy every non-projection source table: the 7 fingerprint tables plus
         * the Class B/D tables written inside kernel txs. Enumerate-and-exclude
         * so a kernel table can never be silently missed. */
        if (ok)
            ok = cdb_copy_nonstay_tables(dst, errbuf, errcap);

        const char *fini = ok ? "COMMIT" : "ROLLBACK";
        if (sqlite3_exec(dst, fini, NULL, NULL, &err) != SQLITE_OK) {
            if (ok)
                cdb_set_err(errbuf, errcap, "consensus_db: dest COMMIT failed: %s",
                            err ? err : "(no message)");
            ok = false;
        }
        if (err) { sqlite3_free(err); err = NULL; }

        /* 3) Verify while `src` is still ATTACHed: the 7-table SHA3 fingerprint
         *    AND every copied table's row count EQUAL the source. */
        if (ok) {
            struct consensus_db_kernel_stats dst_stats;
            ok = consensus_db_read_kernel_stats(dst, &dst_stats, errbuf, errcap) &&
                 consensus_db_kernel_stats_match(&src_stats, &dst_stats, errbuf,
                                                 errcap) &&
                 cdb_verify_nonstay_counts(dst, errbuf, errcap);
        }

        (void)sqlite3_exec(dst, "DETACH DATABASE src", NULL, NULL, NULL);
    }

    sqlite3_close(dst);

    if (!ok) {
        /* Refuse: never leave a half-migrated consensus.db. progress.kv is
         * untouched, so the caller can retry or fall back. */
        cdb_unlink_family(tpath);
        return false;
    }

    /* 4) Atomically publish. */
    if (rename(tpath, cpath) != 0) {
        cdb_set_err(errbuf, errcap, "consensus_db: rename %s -> %s failed: %s",
                    tpath, cpath, strerror(errno));
        cdb_unlink_family(tpath);
        return false;
    }
    return true;
}

bool consensus_db_drop_migrated_from_progress(const char *datadir, char *errbuf,
                                              size_t errcap)
{
    if (!datadir || !datadir[0])
        LOG_FAIL("consensus_db", "drop: empty datadir");

    char cpath[1024];
    char ppath[1024];
    int n = snprintf(cpath, sizeof(cpath), "%s/%s", datadir,
                     CONSENSUS_DB_FILENAME);
    if (n <= 0 || (size_t)n >= sizeof(cpath))
        LOG_FAIL("consensus_db", "drop: consensus.db path too long");
    n = snprintf(ppath, sizeof(ppath), "%s/progress.kv", datadir);
    if (n <= 0 || (size_t)n >= sizeof(ppath))
        LOG_FAIL("consensus_db", "drop: progress.kv path too long");

    /* Fresh node / already-clean: no progress.kv to prune. */
    if (access(ppath, F_OK) != 0)
        return true;

    /* The kernel authority MUST already live in consensus.db before its old copy
     * is dropped from progress.kv — otherwise a crash here would leave the
     * kernel homeless. */
    if (access(cpath, F_OK) != 0) {
        cdb_set_err(errbuf, errcap,
                    "consensus_db: refusing drop — consensus.db absent");
        return false;
    }

    sqlite3 *pdb = NULL;
#ifdef ZCL_TESTING
    atomic_fetch_add(&g_consensus_db_drop_pdb_opens, 1);
#endif
    if (sqlite3_open_v2(ppath, &pdb,
                        SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX,
                        NULL) != SQLITE_OK) {
        cdb_set_err(errbuf, errcap, "consensus_db: drop open %s failed: %s",
                    ppath, pdb ? sqlite3_errmsg(pdb) : "(open)");
        if (pdb) sqlite3_close(pdb);
        return false;
    }

    char *err = NULL;
    char attach[1200];
    snprintf(attach, sizeof(attach), "ATTACH DATABASE '%s' AS cdb", cpath);
    bool ok = sqlite3_exec(pdb, attach, NULL, NULL, &err) == SQLITE_OK;
    if (!ok)
        cdb_set_err(errbuf, errcap, "consensus_db: drop attach failed: %s",
                    err ? err : "(no message)");
    if (err) { sqlite3_free(err); err = NULL; }

    /* consensus.db must carry the kernel (coins) — proof it is the authority. */
    if (ok && cdb_qualified_count(pdb, "cdb", "coins") < 0) {
        cdb_set_err(errbuf, errcap,
                    "consensus_db: refusing drop — consensus.db has no coins");
        ok = false;
    }

    /* Collect the progress.kv tables to drop: every non-projection table that is
     * ALSO present in consensus.db (proof it was migrated). Snapshot the names
     * first (cannot DROP while stepping the schema cursor). */
    char names[64][128];
    size_t ndrop = 0;
    if (ok) {
        sqlite3_stmt *st = NULL;
        if (sqlite3_prepare_v2(
                pdb,
                "SELECT name FROM main.sqlite_schema "
                "WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name",
                -1, &st, NULL) != SQLITE_OK) {
            cdb_set_err(errbuf, errcap, "consensus_db: drop enumerate failed: %s",
                        sqlite3_errmsg(pdb));
            ok = false;
        } else {
            while (sqlite3_step(st) == SQLITE_ROW && // raw-sql-ok:progress-kv-kernel-store
                   ndrop < sizeof(names) / sizeof(names[0])) {
                const unsigned char *nm = sqlite3_column_text(st, 0);
                if (!nm) continue;
                char name[128];
                snprintf(name, sizeof(name), "%s", (const char *)nm);
                if (cdb_is_projection_stay(name))
                    continue;                        /* Class C — keep */
                if (cdb_qualified_count(pdb, "cdb", name) < 0)
                    continue;                        /* not migrated — keep */
                snprintf(names[ndrop], sizeof(names[ndrop]), "%s", name);
                ndrop++;
            }
            sqlite3_finalize(st);
        }
    }

    /* Only take the write transaction when there is something to drop. In the
     * post-flip steady state ndrop==0 (the migrated tables are already gone), so
     * skip the BEGIN IMMEDIATE write-lock entirely. */
    if (ok && ndrop > 0) {
#ifdef ZCL_TESTING
        atomic_fetch_add(&g_consensus_db_drop_txn_begins, 1);
#endif
        if (sqlite3_exec(pdb, "BEGIN IMMEDIATE", NULL, NULL, &err) != SQLITE_OK) {
            cdb_set_err(errbuf, errcap, "consensus_db: drop BEGIN failed: %s",
                        err ? err : "(no message)");
            ok = false;
        }
        if (err) { sqlite3_free(err); err = NULL; }
    }

    for (size_t i = 0; ok && i < ndrop; i++) {
        char sql[192];
        snprintf(sql, sizeof(sql), "DROP TABLE IF EXISTS main.\"%s\"", names[i]);
        if (sqlite3_exec(pdb, sql, NULL, NULL, &err) != SQLITE_OK) {
            cdb_set_err(errbuf, errcap, "consensus_db: drop %s failed: %s",
                        names[i], err ? err : "(no message)");
            ok = false;
        }
        if (err) { sqlite3_free(err); err = NULL; }
    }

    if (ndrop > 0) {
        const char *fini = ok ? "COMMIT" : "ROLLBACK";
        if (sqlite3_exec(pdb, fini, NULL, NULL, &err) != SQLITE_OK && ok) {
            cdb_set_err(errbuf, errcap, "consensus_db: drop COMMIT failed: %s",
                        err ? err : "(no message)");
            ok = false;
        }
        if (err) { sqlite3_free(err); err = NULL; }
    }

    (void)sqlite3_exec(pdb, "DETACH DATABASE cdb", NULL, NULL, NULL);
    sqlite3_close(pdb);
    return ok;
}

bool consensus_db_write_schema_marker(sqlite3 *cdb, char *errbuf, size_t errcap)
{
    if (!cdb) {
        cdb_set_err(errbuf, errcap, "consensus_db: schema marker — NULL handle");
        return false;
    }
    uint32_t v = (uint32_t)CONSENSUS_DB_SCHEMA_VERSION;
    uint8_t le[4] = {(uint8_t)(v & 0xff), (uint8_t)((v >> 8) & 0xff),
                     (uint8_t)((v >> 16) & 0xff), (uint8_t)((v >> 24) & 0xff)};
    if (!progress_meta_set(cdb, CONSENSUS_DB_SCHEMA_VERSION_KEY, le, sizeof(le))) {
        cdb_set_err(errbuf, errcap, "consensus_db: schema marker write failed");
        return false;
    }
    return true;
}

/* Read the durable schema-marker version, if any. Returns false (out=0) on a
 * missing/short/coerced value or a NULL handle — the same fail-closed read
 * both consensus_db_schema_already_flipped and
 * consensus_db_schema_is_downgrade build on. */
static bool cdb_read_schema_marker(sqlite3 *cdb, uint32_t *out)
{
    if (out) *out = 0;
    if (!cdb)
        return false;
    uint8_t le[4];
    size_t got = 0;
    bool found = false;
    if (!progress_meta_get_blob_exact(cdb, CONSENSUS_DB_SCHEMA_VERSION_KEY,
                                      le, sizeof(le), &got, &found))
        return false;
    if (!found || got != sizeof(le))
        return false;
    if (out)
        *out = (uint32_t)le[0] | ((uint32_t)le[1] << 8) |
               ((uint32_t)le[2] << 16) | ((uint32_t)le[3] << 24);
    return true;
}

/* True when consensus.db already carries the current flip marker — i.e. a prior
 * boot completed the flip. Reads only the durable BLOB marker (fail-closed on a
 * missing/short/coerced value), no progress.kv touch. */
static bool consensus_db_schema_already_flipped(sqlite3 *cdb)
{
    uint32_t v = 0;
    return cdb_read_schema_marker(cdb, &v) &&
           v == (uint32_t)CONSENSUS_DB_SCHEMA_VERSION;
}

bool consensus_db_schema_is_downgrade(sqlite3 *cdb, uint32_t *out_marker_version,
                                      char *errbuf, size_t errcap)
{
    if (out_marker_version) *out_marker_version = 0;
    uint32_t v = 0;
    if (!cdb_read_schema_marker(cdb, &v))
        return false;  /* no marker yet, or unreadable — not a downgrade */
    if (out_marker_version) *out_marker_version = v;
    if (v <= (uint32_t)CONSENSUS_DB_SCHEMA_VERSION)
        return false;
    cdb_set_err(errbuf, errcap,
                "consensus.db schema marker is v%u but this binary is v%u "
                "(binary downgrade against a newer datadir) — refusing to "
                "re-flip or overwrite the marker; run the newer binary "
                "against this datadir", v, (unsigned)CONSENSUS_DB_SCHEMA_VERSION);
    return true;
}

bool consensus_db_finalize_flip(const char *datadir, sqlite3 *cdb, char *errbuf,
                                size_t errcap)
{
    /* A FUTURE marker means this binary is older than the one that last wrote
     * consensus.db. Treating that as "not yet flipped" would silently re-run
     * drop_migrated_from_progress and overwrite the newer marker with this
     * binary's OLDER version — a loud refusal here, not a silent re-flip. */
    if (consensus_db_schema_is_downgrade(cdb, NULL, errbuf, errcap))
        return false;
    /* Steady-state short-circuit: once the durable marker records the flip, the
     * migrated progress.kv tables are already gone. Skip the progress.kv
     * open+ATTACH+lock cycle every subsequent boot would otherwise pay. */
    if (consensus_db_schema_already_flipped(cdb))
        return true;
    if (!consensus_db_drop_migrated_from_progress(datadir, errbuf, errcap))
        return false;
    return consensus_db_write_schema_marker(cdb, errbuf, errcap);
}

bool consensus_db_kernel_store_path(const char *datadir, char *out, size_t cap)
{
    if (!datadir || !datadir[0] || !out || cap == 0) {
        if (out && cap) out[0] = '\0';
        return false;
    }
    int n = snprintf(out, cap, "%s/%s", datadir, CONSENSUS_DB_FILENAME);
    if (n > 0 && (size_t)n < cap && access(out, F_OK) == 0)
        return true;
    n = snprintf(out, cap, "%s/%s", datadir,
                 CONSENSUS_DB_LEGACY_KERNEL_FILENAME);
    if (n <= 0 || (size_t)n >= cap) {
        out[0] = '\0';
        return false;
    }
    return true;
}
