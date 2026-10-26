/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * p2_invariant_check — assert the P2 self-heal invariant on a progress.kv:
 *
 *     coins_applied_height (progress_meta key, LE int64 blob)
 *         ==  stage_cursor('utxo_apply').cursor
 *
 * coins_applied_height is the contiguous applied-coins frontier counter that P2
 * co-commits inside the SAME transaction as every utxo_apply cursor move
 * (successful forward apply, reorg-unwind), the boot backfill, and the
 * header-solution poison_rewind. Failed verdicts hold both cursor and frontier.
 * If the two ever drift, the dual-authority disease P2 exists to kill has
 * returned.
 *
 * READ-ONLY. Opens with SQLITE_OPEN_READONLY; on a COPY left by a kill-9'd node
 * the present -wal holds the true committed state and a read-only connection
 * honors it. Pass --immutable to read the main db file ONLY (no -wal, no locks)
 * when pointing at a LIVE datadir you must not contend with — accepting that
 * recent WAL-only commits are invisible.
 *
 * This is the offline counterpart to `z23 dumpstate` introspection:
 * use it precisely in the kill-9 window when no node is running to ask.
 *
 * Usage:  build/bin/p2_invariant_check <datadir-or-progress.kv> [--immutable] [--quiet]
 * Exit:   0 = invariant HOLDS (both present and equal)
 *         1 = MISMATCH (drift, or malformed blob, or cursor missing)
 *         2 = coins_applied_height ABSENT (pre-P2 datadir — not a violation)
 *         3 = usage / open / read error
 */
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#include "sqlite3.h"

static int usage(void)
{
    fprintf(stderr,
            "usage: p2_invariant_check <datadir-or-progress.kv> "
            "[--immutable] [--quiet]\n");
    return 3;
}

static bool is_regular_file(const char *p)
{
    struct stat st;
    return stat(p, &st) == 0 && S_ISREG(st.st_mode);
}

static bool is_dir(const char *p)
{
    struct stat st;
    return stat(p, &st) == 0 && S_ISDIR(st.st_mode);
}

/* Success transfers a prepared statement to the caller, with ROW or DONE
 * distinguished explicitly. Every failure finalizes it before DB cleanup. */
static bool query_first_row(sqlite3 *db, const char *sql, const char *context,
                             sqlite3_stmt **st, bool *has_row)
{
    *st = NULL;
    *has_row = false;
    int rc = sqlite3_prepare_v2(db, sql, -1, st, NULL);
    if (rc == SQLITE_OK) {
        rc = sqlite3_step(*st); // raw-sql-ok:standalone-dev-tool
        if (rc == SQLITE_ROW || rc == SQLITE_DONE) {
            *has_row = rc == SQLITE_ROW;
            return true;
        }
    }
    fprintf(stderr, "%s read failed: %s\n", context, sqlite3_errmsg(db));
    sqlite3_finalize(*st);
    *st = NULL;
    return false;
}

int main(int argc, char **argv)
{
    const char *arg = NULL;
    bool immutable = false, quiet = false;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--immutable") == 0) immutable = true;
        else if (strcmp(argv[i], "--quiet") == 0) quiet = true;
        else if (argv[i][0] == '-' && argv[i][1] == '-') return usage();
        else if (!arg) arg = argv[i];
        else return usage();
    }
    if (!arg) return usage();

    char path[4096];
    if (is_dir(arg)) {
        /* Kernel-store path semantics (consensus_db_kernel_store_path): on a
         * flipped datadir the reducer kernel (stage_cursor, progress_meta, the
         * stage *_log journals this tool reads) lives in consensus.db and was
         * dropped from progress.kv — so prefer consensus.db when present and
         * fall back to the legacy progress.kv only when it is absent. */
        snprintf(path, sizeof(path), "%s/consensus.db", arg);
        if (!is_regular_file(path))
            snprintf(path, sizeof(path), "%s/progress.kv", arg);
    } else {
        snprintf(path, sizeof(path), "%s", arg);
    }
    if (!is_regular_file(path)) {
        fprintf(stderr, "kernel store (consensus.db/progress.kv) not found: %s\n",
                path);
        return 3;
    }

    char uri[4200];
    snprintf(uri, sizeof(uri), "file:%s?%s", path,
             immutable ? "immutable=1" : "mode=ro");

    sqlite3 *db = NULL;
    int rc = sqlite3_open_v2(uri, &db,
                             SQLITE_OPEN_READONLY | SQLITE_OPEN_URI, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "open failed (%s): %s\n", uri, sqlite3_errmsg(db));
        sqlite3_close(db);
        return 3;
    }

    /* utxo_apply cursor (next height to apply; [0,cursor) applied). */
    bool cursor_present = false;
    int64_t apply_cursor = 0;
    sqlite3_stmt *st = NULL;
    bool has_row = false;
    if (!query_first_row(db,
            "SELECT cursor FROM stage_cursor WHERE name='utxo_apply'",
            "stage_cursor", &st, &has_row)) {
        sqlite3_close(db);
        return 3;
    }
    if (has_row && sqlite3_column_type(st, 0) != SQLITE_NULL) {
        cursor_present = true;
        apply_cursor = sqlite3_column_int64(st, 0);
    }
    sqlite3_finalize(st);

    /* coins_applied_height (LE int64 blob). */
    bool frontier_absent = true;
    bool frontier_malformed = false;
    int64_t frontier = 0;
    st = NULL;
    if (!query_first_row(db,
            "SELECT value FROM progress_meta WHERE key='coins_applied_height'",
            "progress_meta", &st, &has_row)) {
        sqlite3_close(db);
        return 3;
    }
    if (has_row && sqlite3_column_type(st, 0) != SQLITE_NULL) {
        frontier_absent = false;
        const void *blob = sqlite3_column_blob(st, 0);
        int n = sqlite3_column_bytes(st, 0);
        if (blob && n == 8) {
            uint64_t v = 0;
            const unsigned char *b = (const unsigned char *)blob;
            for (int i = 0; i < 8; i++) v |= (uint64_t)b[i] << (8 * i);
            frontier = (int64_t)v; /* LE int64, value stored via le64_put */
        } else {
            frontier_malformed = true;
        }
    }
    sqlite3_finalize(st);
    sqlite3_close(db);

    if (!quiet) {
        printf("p2_invariant_check  [%s | %s]\n", path,
               immutable ? "immutable=1" : "mode=ro");
        if (cursor_present)
            printf("  stage_cursor('utxo_apply') = %lld\n",
                   (long long)apply_cursor);
        else
            printf("  stage_cursor('utxo_apply') = (absent)\n");
        if (frontier_absent)
            printf("  coins_applied_height       = ABSENT (pre-P2)\n");
        else if (frontier_malformed)
            printf("  coins_applied_height       = MALFORMED blob\n");
        else
            printf("  coins_applied_height       = %lld\n",
                   (long long)frontier);
    }

    if (frontier_malformed) {
        fprintf(stderr, "  VERDICT: MISMATCH — coins_applied_height blob "
                        "malformed (want 8 bytes)\n");
        return 1;
    }
    if (frontier_absent) {
        if (!quiet)
            printf("  VERDICT: ABSENT — pre-P2 datadir, not a violation\n");
        return 2;
    }
    if (!cursor_present) {
        fprintf(stderr, "  VERDICT: MISMATCH — coins_applied_height=%lld but "
                        "no utxo_apply cursor\n", (long long)frontier);
        return 1;
    }
    if (frontier == apply_cursor) {
        if (!quiet)
            printf("  VERDICT: HOLDS — coins_applied_height == utxo_apply "
                   "cursor (%lld)\n", (long long)frontier);
        return 0;
    }
    fprintf(stderr, "  VERDICT: MISMATCH — coins_applied_height=%lld != "
                    "utxo_apply cursor=%lld (drift=%lld)\n",
            (long long)frontier, (long long)apply_cursor,
            (long long)(frontier - apply_cursor));
    return 1;
}
