/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * dev.index sqlite store: schema, open, and per-source incremental ingest.
 * See native_dev_index_ingest.h.
 *
 * This module owns its own sqlite3 handle to its own database file and sits
 * below the ActiveRecord layer the same way engine/modules/storage/src/
 * progress_store.c's kernel-store handle does (see that file's header
 * comment and DEFENSIVE_CODING.md Sec 1): index.db is not a node.db model,
 * it is a brand-new standalone store with its own FTS5 schema that the
 * fixed node.db AR models cannot express. Every direct sqlite3_step call below
 * carries the `// raw-sql-ok:index-store` marker check_raw_sqlite.sh reads.
 *
 * IDENTITY, NOT CURSOR: a `rows` row is only ever added once for a given
 * (source_id, row_key) pair, where row_key is a SHA3-256 hash of the row's
 * raw line bytes (dev_index_row_key). The byte-offset cursor is only an
 * optimisation for where to start reading; every insert still goes through
 * `INSERT ... ON CONFLICT(source_id, row_key) DO NOTHING`, so re-reading a
 * line the store has already seen (a rename, a restart-from-0, a second
 * `ingest` call) can never duplicate it. Each cursor also carries a SHA3-256
 * hash of the file's own first `byte_offset` bytes as of the last successful
 * ingest; the next ingest re-hashes those same bytes off the (possibly
 * renamed, possibly rewritten) file on disk and only trusts the saved
 * offset when the two hashes match — an inode change alone (a `mv` onto the
 * same content) does not force a restart, and a same-size in-place rewrite
 * (content changed, inode and size unchanged) is not missed. See
 * docs/INDEX.md.
 */

#include "command/native_dev_index_ingest.h"

#include "base/safe_alloc.h"
#include "command/native_dev_index_identity.h"
#include "command/native_dev_index_parse.h"
#include "platform/directory_compat.h"
#include "services/evidence_ledger_row.h"

#include <sha3/sha3.h>
#include <sqlite3.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

/* Days from the civil epoch (1970-01-01) to (y, m, d): Howard Hinnant's
 * days_from_civil. Portable ts->unix-seconds without libc timegm(), which
 * Windows does not provide. See tools/dev/fleet_observe.c for the same
 * primitive (not yet a shared package — see its convergence note). */
static int64_t dev_index_days_from_civil(int64_t y, int m, int d)
{
    y -= (m <= 2);
    int64_t era = (y >= 0 ? y : y - 399) / 400;
    int64_t yoe = y - era * 400;
    int64_t doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
    int64_t doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + doe - 719468;
}

#define DEV_INDEX_DB_HOME_REL ".local/state/zclassic23"
#define DEV_INDEX_MAX_FILES 256u
#define DVI_TXN_ERR_MAX 160u
#define DEV_INDEX_SCHEMA_VERSION 2

/* One source's file list, heap-allocated (256 * 1024 bytes is too large a
 * stack frame for a leaf that a hooked watcher may run with a small
 * thread stack). Freed by the caller with plain free(). */
static char (*dev_index_alloc_files(void))[1024]
{
    return zcl_malloc(DEV_INDEX_MAX_FILES * sizeof(char[1024]),
                      "dev_index_files");
}

static void dev_index_set_err(char *err, size_t cap, const char *fmt,
                              const char *detail)
{
    if (!err || cap == 0)
        return;
    (void)snprintf(err, cap, fmt, detail ? detail : "");
}

bool dev_index_db_path(const char *index_override,
                       const char *state_root_override, bool create,
                       char *out, size_t cap)
{
    if (!out || cap == 0)
        return false;
    char path[1024];
    if (index_override && index_override[0]) {
        if ((size_t)snprintf(path, sizeof(path), "%s", index_override) >=
            sizeof(path))
            return false;
    } else {
        char root[1024];
        if (state_root_override && state_root_override[0]) {
            if ((size_t)snprintf(root, sizeof(root), "%s",
                                 state_root_override) >= sizeof(root))
                return false;
        } else if (!evidence_ledger_home_rel_dir(DEV_INDEX_DB_HOME_REL, root,
                                                 sizeof(root))) {
            return false;
        }
        if ((size_t)snprintf(path, sizeof(path), "%s/index/index.db", root) >=
            sizeof(path))
            return false;
    }
    if (create) {
        char *slash = strrchr(path, '/');
        if (slash) {
            char dir[1024];
            size_t dlen = (size_t)(slash - path);
            if (dlen >= sizeof(dir))
                return false;
            memcpy(dir, path, dlen);
            dir[dlen] = '\0';
            if (dir[0] && !platform_directory_ensure(dir, 0700))
                return false;
        }
    }
    return (size_t)snprintf(out, cap, "%s", path) < cap;
}

static bool dev_index_exec(sqlite3 *db, const char *sql, char *err,
                           size_t err_cap)
{
    char *msg = NULL;
    if (sqlite3_exec(db, sql, NULL, NULL, &msg) != SQLITE_OK) {
        dev_index_set_err(err, err_cap, "schema error: %s",
                          msg ? msg : "unknown");
        sqlite3_free(msg);
        return false;
    }
    return true;
}

static int dev_index_read_user_version(sqlite3 *db)
{
    sqlite3_stmt *st = NULL;
    int version = 0;
    if (sqlite3_prepare_v2(db, "PRAGMA user_version", -1, &st, NULL) ==
        SQLITE_OK) {
        if (sqlite3_step(st) == SQLITE_ROW) // raw-sql-ok:index-store
            version = sqlite3_column_int(st, 0);
        sqlite3_finalize(st);
    }
    return version;
}

/* Creates the schema fresh, or migrates by dropping and recreating our own
 * tables when the on-disk schema version does not match: index.db is a
 * disposable local cache (never custody data), so a version bump just
 * means "rebuild it by re-ingesting", not an in-place ALTER. */
static bool dev_index_migrate_schema(sqlite3 *db, char *err, size_t err_cap)
{
    if (!dev_index_exec(db, "PRAGMA journal_mode=WAL", err, err_cap) ||
        !dev_index_exec(db, "PRAGMA synchronous=NORMAL", err, err_cap))
        return false;

    if (dev_index_read_user_version(db) != DEV_INDEX_SCHEMA_VERSION) {
        static const char *const drops[] = {
            "DROP TABLE IF EXISTS rows_fts",
            "DROP TABLE IF EXISTS rows",
            "DROP TABLE IF EXISTS cursors",
        };
        for (size_t i = 0; i < sizeof(drops) / sizeof(drops[0]); i++)
            if (!dev_index_exec(db, drops[i], err, err_cap))
                return false;
    }

    static const char *const schema[] = {
        "CREATE TABLE IF NOT EXISTS cursors ("
        " source_id TEXT NOT NULL, file_path TEXT NOT NULL,"
        " inode INTEGER NOT NULL DEFAULT 0, size INTEGER NOT NULL DEFAULT 0,"
        " byte_offset INTEGER NOT NULL DEFAULT 0, prefix_hash BLOB,"
        " rows_skipped_total INTEGER NOT NULL DEFAULT 0,"
        " PRIMARY KEY (source_id, file_path))",
        "CREATE TABLE IF NOT EXISTS rows ("
        " id INTEGER PRIMARY KEY AUTOINCREMENT,"
        " source_id TEXT NOT NULL, seq INTEGER NOT NULL,"
        " ts TEXT NOT NULL DEFAULT '', kind TEXT NOT NULL DEFAULT '',"
        " field_a TEXT NOT NULL DEFAULT '', field_b TEXT NOT NULL DEFAULT '',"
        " field_c TEXT NOT NULL DEFAULT '', text TEXT NOT NULL,"
        " row_key BLOB NOT NULL)",
        "CREATE UNIQUE INDEX IF NOT EXISTS rows_dedupe_idx"
        " ON rows(source_id, row_key)",
        "CREATE INDEX IF NOT EXISTS rows_source_idx ON rows(source_id, seq)",
        "CREATE INDEX IF NOT EXISTS rows_ts_idx ON rows(source_id, ts)",
        ("CREATE VIRTUAL TABLE IF NOT EXISTS rows_fts USING "
         "fts5(doc, tokenize=\"unicode61 tokenchars ':'\")"),
    };
    for (size_t i = 0; i < sizeof(schema) / sizeof(schema[0]); i++)
        if (!dev_index_exec(db, schema[i], err, err_cap))
            return false;

    char pragma[64];
    (void)snprintf(pragma, sizeof(pragma), "PRAGMA user_version=%d",
                   DEV_INDEX_SCHEMA_VERSION);
    return dev_index_exec(db, pragma, err, err_cap);
}

bool dev_index_db_open(bool create, const char *index_override,
                       const char *state_root_override, sqlite3 **out_db,
                       bool *out_missing, char *err, size_t err_cap)
{
    if (out_missing)
        *out_missing = false;
    if (!out_db)
        return false;
    *out_db = NULL;
    char path[1024];
    if (!dev_index_db_path(index_override, state_root_override, create, path,
                           sizeof(path))) {
        dev_index_set_err(err, err_cap, "could not resolve index.db path%s",
                          "");
        return false;
    }

    if (!create) {
        struct stat st;
        if (stat(path, &st) != 0) {
            if (out_missing)
                *out_missing = true;
            return true; /* honest "no index yet": nothing touched */
        }
    }

    sqlite3 *db = NULL;
    int flags = create ? (SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE)
                       : SQLITE_OPEN_READONLY;
    if (sqlite3_open_v2(path, &db, flags, NULL) != SQLITE_OK) {
        dev_index_set_err(err, err_cap, "sqlite3_open_v2 failed: %s",
                          db ? sqlite3_errmsg(db) : "no handle");
        if (db)
            sqlite3_close(db);
        return false;
    }

    if (create) {
        if (!dev_index_migrate_schema(db, err, err_cap)) {
            sqlite3_close(db);
            return false;
        }
    } else if (dev_index_read_user_version(db) != DEV_INDEX_SCHEMA_VERSION) {
        sqlite3_close(db);
        if (out_missing)
            *out_missing = true;
        return true; /* stale schema: report "no index", never repair here */
    }
    *out_db = db;
    return true;
}

void dev_index_db_close(sqlite3 *db)
{
    if (db)
        sqlite3_close(db);
}

/* ── parsed-row shape + insertion ───────────────────────────────────── */

static void dev_index_copy(char *dst, size_t cap, const char *src)
{
    if (!src) {
        dst[0] = '\0';
        return;
    }
    (void)snprintf(dst, cap, "%s", src);
}

/* Returns 1 when a new row (and its rows_fts twin) was inserted, 0 when
 * (source_id, row_key) already existed (silently ignored, by design — see
 * this file's header comment), -1 on a real error. */
static int dev_index_insert_row(sqlite3 *db, const char *source_id,
                                int64_t seq, const struct dev_index_fields *f,
                                const char *text,
                                const unsigned char row_key[SHA3_256_OUTPUT_SIZE])
{
    char doc[DEV_INDEX_TEXT_MAX + DEV_INDEX_KV_MAX + 2];
    (void)snprintf(doc, sizeof(doc), "%s %s", text, f->kv);

    sqlite3_stmt *st = NULL;
    static const char *sql =
        "INSERT INTO rows(source_id, seq, ts, kind, field_a, field_b,"
        " field_c, text, row_key) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)"
        " ON CONFLICT(source_id, row_key) DO NOTHING";
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_text(st, 1, source_id, -1, SQLITE_STATIC);
    sqlite3_bind_int64(st, 2, seq);
    sqlite3_bind_text(st, 3, f->ts, -1, SQLITE_STATIC);
    sqlite3_bind_text(st, 4, f->kind, -1, SQLITE_STATIC);
    sqlite3_bind_text(st, 5, f->a, -1, SQLITE_STATIC);
    sqlite3_bind_text(st, 6, f->b, -1, SQLITE_STATIC);
    sqlite3_bind_text(st, 7, f->c, -1, SQLITE_STATIC);
    sqlite3_bind_text(st, 8, text, -1, SQLITE_STATIC);
    sqlite3_bind_blob(st, 9, row_key, SHA3_256_OUTPUT_SIZE, SQLITE_STATIC);
    int rc = sqlite3_step(st); // raw-sql-ok:index-store
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE)
        return -1;
    if (sqlite3_changes(db) == 0)
        return 0; /* identical (source_id, row_key) already present */
    int64_t row_id = sqlite3_last_insert_rowid(db);

    static const char *fts_sql = "INSERT INTO rows_fts(rowid, doc) VALUES (?1,?2)";
    if (sqlite3_prepare_v2(db, fts_sql, -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, row_id);
    sqlite3_bind_text(st, 2, doc, -1, SQLITE_STATIC);
    rc = sqlite3_step(st); // raw-sql-ok:index-store
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? 1 : -1;
}

/* ── line reader: complete lines only, offset-precise ───────────────── */

static int dev_index_read_line(FILE *fp, char *buf, size_t buf_cap,
                               long *end_offset)
{
    long start = ftell(fp);
    if (start < 0)
        return -1;
    if (!fgets(buf, (int)buf_cap, fp)) {
        if (feof(fp)) {
            (void)fseek(fp, start, SEEK_SET);
            return 0;
        }
        return -1;
    }
    size_t len = strlen(buf);
    bool got_newline = len > 0 && buf[len - 1] == '\n';
    if (got_newline) {
        buf[--len] = '\0';
        if (len > 0 && buf[len - 1] == '\r')
            buf[len - 1] = '\0';
    } else {
        bool found = false;
        int c;
        while ((c = fgetc(fp)) != EOF) {
            if (c == '\n') {
                found = true;
                break;
            }
        }
        if (!found) {
            (void)fseek(fp, start, SEEK_SET);
            return 0;
        }
    }
    long end = ftell(fp);
    if (end < 0)
        return -1;
    *end_offset = end;
    return 1;
}

static bool dev_index_stat_file(const char *path, int64_t *inode,
                                int64_t *size)
{
    struct stat st;
    if (stat(path, &st) != 0)
        return false;
    *inode = (int64_t)st.st_ino;
    *size = (int64_t)st.st_size;
    return true;
}

/* Reads every complete line from `fp` (already seeked to `offset`),
 * inserting one `rows` row per line whose (source_id, row_key) is new
 * (dev_index_insert_row silently ignores an already-seen one), until EOF or
 * an error. A line that fails to parse is counted in *rows_skipped and
 * otherwise ignored — never fatal. Fills *end_offset with the byte position
 * to save as the new cursor. Split out of dev_index_ingest_file so that
 * function stays open/seek/close plus one call, not an inline read loop. */
static bool dev_index_ingest_lines(sqlite3 *db, const struct dev_index_source *src,
                                   FILE *fp, int64_t offset, long *end_offset,
                                   int64_t *rows_added, int64_t *rows_skipped,
                                   const char *path, char *err, size_t err_cap)
{
    char line[DEV_INDEX_LINE_MAX];
    *end_offset = offset;
    int64_t seq = dev_index_next_seq(db, src->id);
    for (;;) {
        long before = ftell(fp);
        int rc = dev_index_read_line(fp, line, sizeof(line), end_offset);
        if (rc < 0) {
            dev_index_set_err(err, err_cap, "read error on %s", path);
            return false;
        }
        if (rc == 0) {
            *end_offset = before;
            return true;
        }
        struct dev_index_fields f;
        if (!dev_index_parse_line(src, line, &f)) {
            (*rows_skipped)++;
            continue;
        }
        unsigned char row_key[SHA3_256_OUTPUT_SIZE];
        dev_index_row_key(src->id, line, row_key);
        int inserted = dev_index_insert_row(db, src->id, seq, &f, line, row_key);
        if (inserted < 0) {
            dev_index_set_err(err, err_cap, "insert failed for %s", path);
            return false;
        }
        if (inserted > 0) {
            seq++;
            (*rows_added)++;
        }
    }
}

static bool dev_index_ingest_file(sqlite3 *db, const struct dev_index_source *src,
                                  const char *path, int64_t *rows_added,
                                  int64_t *rows_skipped, char *err,
                                  size_t err_cap)
{
    int64_t inode = 0, size = 0;
    if (!dev_index_stat_file(path, &inode, &size))
        return true; /* file vanished between list and read: not an error */

    struct dev_index_cursor cursor;
    if (!dev_index_get_cursor(db, src->id, path, &cursor)) {
        dev_index_set_err(err, err_cap, "cursor read failed for %s", path);
        return false;
    }
    int64_t offset = dev_index_trusted_offset(&cursor, path, size);

    FILE *fp = fopen(path, "rb");
    if (!fp)
        return true; /* unreadable right now: skip, try again next ingest */
    if (offset > 0 && fseek(fp, offset, SEEK_SET) != 0) {
        fclose(fp);
        dev_index_set_err(err, err_cap, "seek failed for %s", path);
        return false;
    }

    long end_offset = offset;
    int64_t local_skipped = 0;
    bool ok = dev_index_ingest_lines(db, src, fp, offset, &end_offset,
                                     rows_added, &local_skipped, path, err,
                                     err_cap);
    fclose(fp);
    if (!ok)
        return false;

    unsigned char new_hash[SHA3_256_OUTPUT_SIZE];
    if (!dev_index_hash_prefix(path, end_offset, new_hash)) {
        dev_index_set_err(err, err_cap, "hash failed for %s", path);
        return false;
    }
    int64_t total_skipped = cursor.rows_skipped_total + local_skipped;
    if (!dev_index_set_cursor(db, src->id, path, end_offset, inode, size,
                              new_hash, total_skipped)) {
        dev_index_set_err(err, err_cap, "cursor write failed for %s", path);
        return false;
    }
    *rows_skipped += local_skipped;
    return true;
}

bool dev_index_ingest_source(sqlite3 *db, const struct dev_index_source *src,
                             const char *state_root_override,
                             struct dev_index_ingest_result *result,
                             char *err, size_t err_cap)
{
    result->source_id = src->id;
    result->files_seen = 0;
    result->rows_added = 0;
    result->rows_skipped = 0;
    char (*files)[1024] = dev_index_alloc_files();
    if (!files) {
        dev_index_set_err(err, err_cap, "out of memory listing files%s", "");
        return false;
    }
    size_t n = dev_index_source_list_files(src, state_root_override, files,
                                           DEV_INDEX_MAX_FILES,
                                           sizeof(files[0]));
    result->files_seen = (int64_t)n;

    /* One transaction for the whole source: an implicit-autocommit INSERT
     * per row was measured forcing one WAL-checkpoint-adjacent fsync per
     * row (D-state disk waits, effectively a hang on a real *.log file).
     * A single BEGIN/COMMIT around every file's rows is the fix; a lost
     * connection mid-batch loses the whole batch, which is fine here
     * because the cursor is only advanced (dev_index_set_cursor) inside
     * this same transaction, so nothing is ever double-counted. */
    if (!dev_index_exec(db, "BEGIN IMMEDIATE", err, err_cap)) {
        free(files);
        return false;
    }
    bool ok = true;
    for (size_t i = 0; i < n && ok; i++)
        ok = dev_index_ingest_file(db, src, files[i], &result->rows_added,
                                   &result->rows_skipped, err, err_cap);
    free(files);
    char txn_err[DVI_TXN_ERR_MAX];
    if (ok) {
        ok = dev_index_exec(db, "COMMIT", txn_err, sizeof(txn_err));
        if (!ok)
            dev_index_set_err(err, err_cap, "commit failed: %s", txn_err);
    } else {
        (void)dev_index_exec(db, "ROLLBACK", txn_err, sizeof(txn_err));
    }
    return ok;
}

/* ── status ──────────────────────────────────────────────────────────── */

bool dev_index_source_status(sqlite3 *db, const struct dev_index_source *src,
                             const char *state_root_override,
                             int64_t now_wall_ms,
                             struct dev_index_source_status *out, char *err,
                             size_t err_cap)
{
    memset(out, 0, sizeof(*out));
    out->source_id = src->id;

    sqlite3_stmt *st = NULL;
    static const char *count_sql =
        "SELECT COUNT(*), MAX(ts) FROM rows WHERE source_id=?1";
    if (sqlite3_prepare_v2(db, count_sql, -1, &st, NULL) != SQLITE_OK) {
        dev_index_set_err(err, err_cap, "status query failed: %s",
                          sqlite3_errmsg(db));
        return false;
    }
    sqlite3_bind_text(st, 1, src->id, -1, SQLITE_STATIC);
    if (sqlite3_step(st) == SQLITE_ROW) { // raw-sql-ok:index-store
        out->rows = sqlite3_column_int64(st, 0);
        const unsigned char *ts = sqlite3_column_text(st, 1);
        if (ts && ts[0]) {
            dev_index_copy(out->newest_ts, sizeof(out->newest_ts),
                          (const char *)ts);
            out->has_rows = true;
        }
    }
    sqlite3_finalize(st);

    out->seconds_since_newest = -1;
    if (out->has_rows) {
        int y, mo, d, h, mi, se;
        if (sscanf(out->newest_ts, "%d-%d-%dT%d:%d:%d", &y, &mo, &d, &h, &mi,
                  &se) == 6) {
            int64_t newest_s =
                dev_index_days_from_civil(y, mo, d) * 86400 + h * 3600 +
                mi * 60 + se;
            out->seconds_since_newest = now_wall_ms / 1000 - newest_s;
        }
    }

    char (*files)[1024] = dev_index_alloc_files();
    if (!files) {
        dev_index_set_err(err, err_cap, "out of memory listing files%s", "");
        return false;
    }
    size_t n = dev_index_source_list_files(src, state_root_override, files,
                                           DEV_INDEX_MAX_FILES,
                                           sizeof(files[0]));
    for (size_t i = 0; i < n; i++) {
        int64_t inode = 0, size = 0;
        if (!dev_index_stat_file(files[i], &inode, &size))
            continue;
        struct dev_index_cursor cursor;
        if (!dev_index_get_cursor(db, src->id, files[i], &cursor))
            continue;
        int64_t offset = cursor.found ? cursor.byte_offset : 0;
        if (size > offset)
            out->bytes_behind += size - offset;
        if (cursor.found)
            out->rows_skipped += cursor.rows_skipped_total;
    }
    free(files);
    return true;
}
