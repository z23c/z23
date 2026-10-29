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

/* Parse argv into one path argument and the --immutable/--quiet flags.
 * Returns false on any unknown option, a second path, or no path. */
static bool parse_args(int argc, char **argv, const char **arg,
                       bool *immutable, bool *quiet)
{
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--immutable") == 0) *immutable = true;
        else if (strcmp(argv[i], "--quiet") == 0) *quiet = true;
        else if (argv[i][0] == '-' && argv[i][1] == '-') return false;
        else if (!*arg) *arg = argv[i];
        else return false;
    }
    return *arg != NULL;
}

/* Resolve the datadir or file argument to the store path to open. */
static bool resolve_store_path(const char *arg, char *path, size_t cap)
{
    if (is_dir(arg)) {
        /* Kernel-store path semantics (consensus_db_kernel_store_path): on a
         * flipped datadir the reducer kernel (stage_cursor, progress_meta, the
         * stage *_log journals this tool reads) lives in consensus.db and was
         * dropped from progress.kv — so prefer consensus.db when present and
         * fall back to the legacy progress.kv only when it is absent. */
        snprintf(path, cap, "%s/consensus.db", arg);
        if (!is_regular_file(path))
            snprintf(path, cap, "%s/progress.kv", arg);
    } else {
        snprintf(path, cap, "%s", arg);
    }
    return is_regular_file(path);
}

/* Open the store read-only (or immutable). On failure the handle is closed
 * here and the caller only returns its usage/open error code. */
static bool open_store(const char *path, bool immutable, sqlite3 **db)
{
    char uri[4200];
    snprintf(uri, sizeof(uri), "file:%s?%s", path,
             immutable ? "immutable=1" : "mode=ro");

    int rc = sqlite3_open_v2(uri, db,
                             SQLITE_OPEN_READONLY | SQLITE_OPEN_URI, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "open failed (%s): %s\n", uri, sqlite3_errmsg(*db));
        sqlite3_close(*db);
        return false;
    }
    return true;
}

/* What the two counters read as, for the report and the verdict. */
struct p2_state {
    bool cursor_present;
    int64_t apply_cursor;
    bool frontier_absent;
    bool frontier_malformed;
    int64_t frontier;
};

/* Decode an 8-byte LE int64 blob; false when it is not exactly 8 bytes. */
static bool decode_frontier_blob(const void *blob, int n, int64_t *out)
{
    if (!blob || n != 8) return false;
    uint64_t v = 0;
    const unsigned char *b = (const unsigned char *)blob;
    for (int i = 0; i < 8; i++) v |= (uint64_t)b[i] << (8 * i);
    *out = (int64_t)v; /* LE int64, value stored via le64_put */
    return true;
}

static bool read_apply_cursor(sqlite3 *db, struct p2_state *s)
{
    /* utxo_apply cursor (next height to apply; [0,cursor) applied). */
    sqlite3_stmt *st = NULL;
    bool has_row = false;
    if (!query_first_row(db,
            "SELECT cursor FROM stage_cursor WHERE name='utxo_apply'",
            "stage_cursor", &st, &has_row))
        return false;
    if (has_row && sqlite3_column_type(st, 0) != SQLITE_NULL) {
        s->cursor_present = true;
        s->apply_cursor = sqlite3_column_int64(st, 0);
    }
    sqlite3_finalize(st);
    return true;
}

static bool read_frontier(sqlite3 *db, struct p2_state *s)
{
    /* coins_applied_height (LE int64 blob). */
    sqlite3_stmt *st = NULL;
    bool has_row = false;
    if (!query_first_row(db,
            "SELECT value FROM progress_meta WHERE key='coins_applied_height'",
            "progress_meta", &st, &has_row))
        return false;
    if (has_row && sqlite3_column_type(st, 0) != SQLITE_NULL) {
        s->frontier_absent = false;
        const void *blob = sqlite3_column_blob(st, 0);
        int n = sqlite3_column_bytes(st, 0);
        if (!decode_frontier_blob(blob, n, &s->frontier))
            s->frontier_malformed = true;
    }
    sqlite3_finalize(st);
    return true;
}

static void print_state(const char *path, bool immutable,
                        const struct p2_state *s)
{
    printf("p2_invariant_check  [%s | %s]\n", path,
           immutable ? "immutable=1" : "mode=ro");
    if (s->cursor_present)
        printf("  stage_cursor('utxo_apply') = %lld\n",
               (long long)s->apply_cursor);
    else
        printf("  stage_cursor('utxo_apply') = (absent)\n");
    if (s->frontier_absent)
        printf("  coins_applied_height       = ABSENT (pre-P2)\n");
    else if (s->frontier_malformed)
        printf("  coins_applied_height       = MALFORMED blob\n");
    else
        printf("  coins_applied_height       = %lld\n",
               (long long)s->frontier);
}

static int verdict(bool quiet, const struct p2_state *s)
{
    if (s->frontier_malformed) {
        fprintf(stderr, "  VERDICT: MISMATCH — coins_applied_height blob "
                        "malformed (want 8 bytes)\n");
        return 1;
    }
    if (s->frontier_absent) {
        if (!quiet)
            printf("  VERDICT: ABSENT — pre-P2 datadir, not a violation\n");
        return 2;
    }
    if (!s->cursor_present) {
        fprintf(stderr, "  VERDICT: MISMATCH — coins_applied_height=%lld but "
                        "no utxo_apply cursor\n", (long long)s->frontier);
        return 1;
    }
    if (s->frontier == s->apply_cursor) {
        if (!quiet)
            printf("  VERDICT: HOLDS — coins_applied_height == utxo_apply "
                   "cursor (%lld)\n", (long long)s->frontier);
        return 0;
    }
    fprintf(stderr, "  VERDICT: MISMATCH — coins_applied_height=%lld != "
                    "utxo_apply cursor=%lld (drift=%lld)\n",
            (long long)s->frontier, (long long)s->apply_cursor,
            (long long)(s->frontier - s->apply_cursor));
    return 1;
}

int main(int argc, char **argv)
{
    const char *arg = NULL;
    bool immutable = false, quiet = false;
    if (!parse_args(argc, argv, &arg, &immutable, &quiet)) return usage();

    char path[4096];
    if (!resolve_store_path(arg, path, sizeof(path))) {
        fprintf(stderr, "kernel store (consensus.db/progress.kv) not found: %s\n",
                path);
        return 3;
    }

    sqlite3 *db = NULL;
    if (!open_store(path, immutable, &db)) return 3;

    struct p2_state s = {.frontier_absent = true};
    if (!read_apply_cursor(db, &s) || !read_frontier(db, &s)) {
        sqlite3_close(db);
        return 3;
    }
    sqlite3_close(db);

    if (!quiet) print_state(path, immutable, &s);
    return verdict(quiet, &s);
}
