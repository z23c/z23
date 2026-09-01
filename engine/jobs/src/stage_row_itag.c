/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * stage_row_itag — implementation. See stage_row_itag.h. */

#include "jobs/stage_row_itag.h"

#include "storage/progress_store.h"
#include "crypto/sha3.h"
#include "util/log_macros.h"

#include <sqlite3.h>
#include <stdio.h>
#include <string.h>

/* The three logs whose reducer_frontier verdict parses `status` into VERIFIED
 * (mirrors reducer_frontier.c:log_success_requires_full_validation). Only for
 * these does the tag fold `status` in. Kept here as the single source of truth
 * so write / backfill / verify never disagree on the covered fields. */
static bool itag_covers_status(const char *table)
{
    return strcmp(table, "script_validate_log") == 0 ||
           strcmp(table, "proof_validate_log") == 0 ||
           strcmp(table, "utxo_apply_log") == 0;
}

static void put_u64_le(uint8_t out[8], uint64_t v)
{
    for (int i = 0; i < 8; i++)
        out[i] = (uint8_t)(v >> (8 * i));
}

static void put_u32_le(uint8_t out[4], uint32_t v)
{
    for (int i = 0; i < 4; i++)
        out[i] = (uint8_t)(v >> (8 * i));
}

void stage_row_itag_compute(const char *log_table, int64_t height, int ok,
                            const void *status, size_t status_len,
                            uint8_t out[STAGE_ROW_ITAG_LEN])
{
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);

    /* Domain-separate by table name so an identical (height, ok, status) in a
     * different log produces a different tag. The 0x00 terminator closes the
     * variable-length table name unambiguously. */
    if (log_table)
        sha3_256_write(&ctx, (const unsigned char *)log_table,
                       strlen(log_table));
    unsigned char sep = 0x00;
    sha3_256_write(&ctx, &sep, 1);

    uint8_t hbuf[8];
    put_u64_le(hbuf, (uint64_t)height);
    sha3_256_write(&ctx, hbuf, sizeof(hbuf));

    unsigned char okb = ok ? 1 : 0;
    sha3_256_write(&ctx, &okb, 1);

    /* Length-prefixed status so a status boundary can never be confused with
     * the surrounding fixed-width fields. Folded in only for the covered logs. */
    if (log_table && itag_covers_status(log_table)) {
        uint32_t n = (status && status_len) ? (uint32_t)status_len : 0;
        uint8_t lbuf[4];
        put_u32_le(lbuf, n);
        sha3_256_write(&ctx, lbuf, sizeof(lbuf));
        if (n)
            sha3_256_write(&ctx, (const unsigned char *)status, n);
    }

    unsigned char digest[SHA3_256_OUTPUT_SIZE];
    sha3_256_finalize(&ctx, digest);
    memcpy(out, digest, STAGE_ROW_ITAG_LEN);
}

enum stage_row_itag_verdict stage_row_itag_verify(
    const char *log_table, int64_t height, int ok,
    const void *status, size_t status_len,
    const void *tag, size_t tag_len)
{
    if (!tag || tag_len != STAGE_ROW_ITAG_LEN)
        return STAGE_ROW_ITAG_ABSENT;
    uint8_t expect[STAGE_ROW_ITAG_LEN];
    stage_row_itag_compute(log_table, height, ok, status, status_len, expect);
    /* Fixed-length compare; timing is irrelevant (accidental-corruption model,
     * not a secret-dependent path). */
    return memcmp(expect, tag, STAGE_ROW_ITAG_LEN) == 0
               ? STAGE_ROW_ITAG_MATCH
               : STAGE_ROW_ITAG_MISMATCH;
}

/* ── one-time backfill ─────────────────────────────────────────────────── */

static bool itag_backfill_done_flag(sqlite3 *db, const char *table)
{
    char key[80];
    int n = snprintf(key, sizeof(key), "itag_bf:%s", table);
    if (n <= 0 || (size_t)n >= sizeof(key))
        return false;
    uint8_t f = 0;
    size_t got = 0;
    bool found = false;
    if (!progress_meta_get_blob_exact(db, key, &f, sizeof(f), &got, &found))
        return false;  // raw-return-ok:read-error-reruns-backfill (safe: re-scan)
    return found && got == 1 && f == 1;
}

static bool itag_backfill_set_flag(sqlite3 *db, const char *table)
{
    char key[80];
    int n = snprintf(key, sizeof(key), "itag_bf:%s", table);
    if (n <= 0 || (size_t)n >= sizeof(key))
        return false;
    uint8_t one = 1;
    return progress_meta_set_in_tx(db, key, &one, sizeof(one));
}

bool stage_row_itag_backfill(sqlite3 *db, const char *table)
{
    if (!db || !table || !table[0])
        LOG_FAIL("stage_itag", "backfill: NULL/empty db or table");

    progress_store_tx_lock();

    /* The done-flag lives in progress_meta. Production always has it (opened by
     * progress_store_open); ensure it here so a bare test db that calls a stage
     * ensure_schema directly still gets a working flag rather than a rolled-back
     * backfill. Idempotent CREATE TABLE IF NOT EXISTS. */
    if (!progress_meta_table_ensure(db)) {
        progress_store_tx_unlock();
        LOG_FAIL("stage_itag", "backfill: progress_meta ensure failed for %s",
                 table);
    }

    if (itag_backfill_done_flag(db, table)) {
        progress_store_tx_unlock();
        return true;  /* already migrated on a prior boot — O(1) skip */
    }

    /* Own a transaction when we are not already inside one (the ensure_schema
     * callers run in autocommit under the recursive progress lock). If a BEGIN
     * fails because a batch/txn is already open, ride the enclosing txn: the
     * itag-NULL predicate keeps the UPDATE correct and the flag commits with
     * whatever owns the outer txn. */
    char *err = NULL;
    bool began = sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, &err)
                 == SQLITE_OK;
    if (err) sqlite3_free(err);

    bool covers = itag_covers_status(table);
    char sel[128];
    /* Scan in PRIMARY KEY (height) order and update the non-key `itag` column of
     * the current row in place — the canonical safe "update-as-you-scan" pattern
     * (the cursor never revisits or skips because height, the b-tree key, is
     * untouched). Deliberately NOT filtered on `itag IS NULL`: modifying the very
     * column a query filters on mid-scan is implementation-defined in SQLite, and
     * re-tagging an already-tagged row just rewrites the identical deterministic
     * tag. This runs once (flag-guarded), so the full scan is a one-time O(rows). */
    int sn = snprintf(sel, sizeof(sel),
                      "SELECT height, ok%s FROM %s ORDER BY height",
                      covers ? ", status" : "", table);
    if (sn <= 0 || sn >= (int)sizeof(sel)) {
        if (began) sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
        progress_store_tx_unlock();
        LOG_FAIL("stage_itag", "backfill: select sql overflow for %s", table);
    }

    sqlite3_stmt *sst = NULL;
    if (sqlite3_prepare_v2(db, sel, -1, &sst, NULL) != SQLITE_OK) {
        if (began) sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
        progress_store_tx_unlock();
        LOG_FAIL("stage_itag", "backfill: prepare select %s failed: %s",
                 table, sqlite3_errmsg(db));
    }

    /* target table is a fixed identifier from ensure_schema, not user input;
     * the concat cannot inject. */
    sqlite3_stmt *ust = NULL;
    char upd[96];
    int un = snprintf(upd, sizeof(upd),
                      "UPDATE %s SET itag = ? WHERE height = ?", table);
    if (un <= 0 || un >= (int)sizeof(upd)) {
        sqlite3_finalize(sst);
        if (began) sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
        progress_store_tx_unlock();
        LOG_FAIL("stage_itag", "backfill: update sql overflow for %s", table);
    }
    if (sqlite3_prepare_v2(db, upd, -1, &ust, NULL) != SQLITE_OK) {
        sqlite3_finalize(sst);
        if (began) sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
        progress_store_tx_unlock();
        LOG_FAIL("stage_itag", "backfill: prepare update %s failed: %s",
                 table, sqlite3_errmsg(db));
    }

    bool ok_all = true;
    int64_t backfilled = 0;
    while (true) {
        int rc = sqlite3_step(sst);  // raw-sql-ok:progress-kv-kernel-store
        if (rc == SQLITE_ROW) {
            int64_t height = sqlite3_column_int64(sst, 0);
            int okv = sqlite3_column_type(sst, 1) == SQLITE_INTEGER
                          ? sqlite3_column_int(sst, 1) : 0;
            const void *status = NULL;
            size_t status_len = 0;
            if (covers && sqlite3_column_type(sst, 2) == SQLITE_TEXT) {
                status = sqlite3_column_text(sst, 2);
                status_len = (size_t)sqlite3_column_bytes(sst, 2);
            }
            uint8_t tag[STAGE_ROW_ITAG_LEN];
            stage_row_itag_compute(table, height, okv, status, status_len, tag);

            sqlite3_reset(ust);
            sqlite3_clear_bindings(ust);
            sqlite3_bind_blob(ust, 1, tag, STAGE_ROW_ITAG_LEN, SQLITE_STATIC);
            sqlite3_bind_int64(ust, 2, (sqlite3_int64)height);
            int urc = sqlite3_step(ust);  // raw-sql-ok:progress-kv-kernel-store
            if (urc != SQLITE_DONE) {
                LOG_WARN("stage_itag",
                         "[stage_itag] backfill update %s h=%lld rc=%d",
                         table, (long long)height, urc);
                ok_all = false;
                break;
            }
            backfilled++;
        } else if (rc == SQLITE_DONE) {
            break;
        } else {
            LOG_WARN("stage_itag",
                     "[stage_itag] backfill scan %s failed rc=%d: %s",
                     table, rc, sqlite3_errmsg(db));
            ok_all = false;
            break;
        }
    }
    sqlite3_finalize(sst);
    sqlite3_finalize(ust);

    if (ok_all)
        ok_all = itag_backfill_set_flag(db, table);

    if (began) {
        const char *fini = ok_all ? "COMMIT" : "ROLLBACK";
        char *cerr = NULL;
        if (sqlite3_exec(db, fini, NULL, NULL, &cerr) != SQLITE_OK) {
            if (cerr) sqlite3_free(cerr);
            progress_store_tx_unlock();
            LOG_FAIL("stage_itag", "backfill: %s %s failed", fini, table);
        }
        if (cerr) sqlite3_free(cerr);
    }
    progress_store_tx_unlock();

    if (!ok_all)
        return false;  // raw-return-ok:logged-above (inner LOG_WARN named cause)
    if (backfilled > 0)
        LOG_INFO("stage_itag",
                 "[stage_itag] backfilled %lld itag rows in %s",
                 (long long)backfilled, table);
    return true;
}
