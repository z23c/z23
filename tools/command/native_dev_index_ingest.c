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
 */

#include "command/native_dev_index_ingest.h"

#include "base/safe_alloc.h"
#include "json/json.h"
#include "platform/directory_compat.h"
#include "services/evidence_ledger_row.h"

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

#define DEV_INDEX_DB_ENV "ZCL_INDEX_STATE_DIR"
#define DEV_INDEX_DB_HOME_REL ".local/state/zclassic23"
#define DEV_INDEX_LINE_MAX 8192u
#define DEV_INDEX_TEXT_MAX 4000u
#define DEV_INDEX_KV_MAX 2048u
#define DEV_INDEX_MAX_FILES 256u
#define DVI_TXN_ERR_MAX 160u

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

bool dev_index_db_path(char *out, size_t cap)
{
    char root[1024];
    if (!evidence_ledger_resolve_path(DEV_INDEX_DB_ENV, DEV_INDEX_DB_HOME_REL,
                                      "index/index.db", root, sizeof(root)))
        return false;
    char *slash = strrchr(root, '/');
    if (slash) {
        char dir[1024];
        size_t dlen = (size_t)(slash - root);
        if (dlen >= sizeof(dir))
            return false;
        memcpy(dir, root, dlen);
        dir[dlen] = '\0';
        if (!platform_directory_ensure(dir, 0700))
            return false;
    }
    return (size_t)snprintf(out, cap, "%s", root) < cap;
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

bool dev_index_db_open(sqlite3 **out_db, char *err, size_t err_cap)
{
    if (!out_db)
        return false;
    *out_db = NULL;
    char path[1024];
    if (!dev_index_db_path(path, sizeof(path))) {
        dev_index_set_err(err, err_cap, "could not resolve index.db path%s",
                          "");
        return false;
    }
    sqlite3 *db = NULL;
    if (sqlite3_open_v2(path, &db,
                        SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL) !=
        SQLITE_OK) {
        dev_index_set_err(err, err_cap, "sqlite3_open_v2 failed: %s",
                          db ? sqlite3_errmsg(db) : "no handle");
        if (db)
            sqlite3_close(db);
        return false;
    }
    static const char *const schema[] = {
        "PRAGMA journal_mode=WAL",
        "PRAGMA synchronous=NORMAL",
        "CREATE TABLE IF NOT EXISTS cursors ("
        " source_id TEXT NOT NULL, file_path TEXT NOT NULL,"
        " inode INTEGER NOT NULL DEFAULT 0, size INTEGER NOT NULL DEFAULT 0,"
        " byte_offset INTEGER NOT NULL DEFAULT 0,"
        " PRIMARY KEY (source_id, file_path))",
        "CREATE TABLE IF NOT EXISTS rows ("
        " id INTEGER PRIMARY KEY AUTOINCREMENT,"
        " source_id TEXT NOT NULL, seq INTEGER NOT NULL,"
        " ts TEXT NOT NULL DEFAULT '', kind TEXT NOT NULL DEFAULT '',"
        " field_a TEXT NOT NULL DEFAULT '', field_b TEXT NOT NULL DEFAULT '',"
        " field_c TEXT NOT NULL DEFAULT '', text TEXT NOT NULL)",
        "CREATE INDEX IF NOT EXISTS rows_source_idx ON rows(source_id, seq)",
        "CREATE INDEX IF NOT EXISTS rows_ts_idx ON rows(source_id, ts)",
        ("CREATE VIRTUAL TABLE IF NOT EXISTS rows_fts USING "
         "fts5(doc, tokenize=\"unicode61 tokenchars ':'\")"),
    };
    for (size_t i = 0; i < sizeof(schema) / sizeof(schema[0]); i++) {
        if (!dev_index_exec(db, schema[i], err, err_cap)) {
            sqlite3_close(db);
            return false;
        }
    }
    *out_db = db;
    return true;
}

void dev_index_db_close(sqlite3 *db)
{
    if (db)
        sqlite3_close(db);
}

/* ── cursor bookkeeping ──────────────────────────────────────────────── */

struct dev_index_cursor {
    int64_t byte_offset;
    int64_t inode;
    int64_t size;
    bool found;
};

static bool dev_index_get_cursor(sqlite3 *db, const char *source_id,
                                 const char *file_path,
                                 struct dev_index_cursor *out)
{
    memset(out, 0, sizeof(*out));
    sqlite3_stmt *st = NULL;
    static const char *sql =
        "SELECT byte_offset, inode, size FROM cursors "
        "WHERE source_id=?1 AND file_path=?2";
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_text(st, 1, source_id, -1, SQLITE_STATIC);
    sqlite3_bind_text(st, 2, file_path, -1, SQLITE_STATIC);
    int rc = sqlite3_step(st); // raw-sql-ok:index-store
    if (rc == SQLITE_ROW) {
        out->byte_offset = sqlite3_column_int64(st, 0);
        out->inode = sqlite3_column_int64(st, 1);
        out->size = sqlite3_column_int64(st, 2);
        out->found = true;
    }
    sqlite3_finalize(st);
    return rc == SQLITE_ROW || rc == SQLITE_DONE;
}

static bool dev_index_set_cursor(sqlite3 *db, const char *source_id,
                                 const char *file_path, int64_t offset,
                                 int64_t inode, int64_t size)
{
    sqlite3_stmt *st = NULL;
    static const char *sql =
        "INSERT INTO cursors(source_id, file_path, inode, size, byte_offset)"
        " VALUES (?1,?2,?3,?4,?5)"
        " ON CONFLICT(source_id, file_path) DO UPDATE SET"
        " inode=excluded.inode, size=excluded.size,"
        " byte_offset=excluded.byte_offset";
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_text(st, 1, source_id, -1, SQLITE_STATIC);
    sqlite3_bind_text(st, 2, file_path, -1, SQLITE_STATIC);
    sqlite3_bind_int64(st, 3, inode);
    sqlite3_bind_int64(st, 4, size);
    sqlite3_bind_int64(st, 5, offset);
    int rc = sqlite3_step(st); // raw-sql-ok:index-store
    sqlite3_finalize(st);
    return rc == SQLITE_DONE;
}

static int64_t dev_index_next_seq(sqlite3 *db, const char *source_id)
{
    sqlite3_stmt *st = NULL;
    static const char *sql =
        "SELECT COALESCE(MAX(seq),0)+1 FROM rows WHERE source_id=?1";
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK)
        return 1;
    sqlite3_bind_text(st, 1, source_id, -1, SQLITE_STATIC);
    int64_t next = 1;
    if (sqlite3_step(st) == SQLITE_ROW) // raw-sql-ok:index-store
        next = sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    return next;
}

/* ── parsed-row shape + insertion ───────────────────────────────────── */

struct dev_index_fields {
    char ts[32];
    char kind[32];
    char a[128];
    char b[128];
    char c[128];
    char kv[DEV_INDEX_KV_MAX];
};

static void dev_index_kv_add(struct dev_index_fields *f, const char *key,
                             const char *value)
{
    if (!value || !value[0])
        return;
    size_t used = strlen(f->kv);
    if (used + 2 >= sizeof(f->kv))
        return;
    (void)snprintf(f->kv + used, sizeof(f->kv) - used, "%s%s:%s",
                  used ? " " : "", key, value);
}

static bool dev_index_insert_row(sqlite3 *db, const char *source_id,
                                 int64_t seq, const struct dev_index_fields *f,
                                 const char *text)
{
    char doc[DEV_INDEX_TEXT_MAX + DEV_INDEX_KV_MAX + 2];
    (void)snprintf(doc, sizeof(doc), "%s %s", text, f->kv);

    sqlite3_stmt *st = NULL;
    static const char *sql =
        "INSERT INTO rows(source_id, seq, ts, kind, field_a, field_b,"
        " field_c, text) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)";
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_text(st, 1, source_id, -1, SQLITE_STATIC);
    sqlite3_bind_int64(st, 2, seq);
    sqlite3_bind_text(st, 3, f->ts, -1, SQLITE_STATIC);
    sqlite3_bind_text(st, 4, f->kind, -1, SQLITE_STATIC);
    sqlite3_bind_text(st, 5, f->a, -1, SQLITE_STATIC);
    sqlite3_bind_text(st, 6, f->b, -1, SQLITE_STATIC);
    sqlite3_bind_text(st, 7, f->c, -1, SQLITE_STATIC);
    sqlite3_bind_text(st, 8, text, -1, SQLITE_STATIC);
    int rc = sqlite3_step(st); // raw-sql-ok:index-store
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE)
        return false;
    int64_t row_id = sqlite3_last_insert_rowid(db);

    static const char *fts_sql = "INSERT INTO rows_fts(rowid, doc) VALUES (?1,?2)";
    if (sqlite3_prepare_v2(db, fts_sql, -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int64(st, 1, row_id);
    sqlite3_bind_text(st, 2, doc, -1, SQLITE_STATIC);
    rc = sqlite3_step(st); // raw-sql-ok:index-store
    sqlite3_finalize(st);
    return rc == SQLITE_DONE;
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

/* ── per-format field extraction ─────────────────────────────────────── */

static void dev_index_copy(char *dst, size_t cap, const char *src)
{
    if (!src) {
        dst[0] = '\0';
        return;
    }
    (void)snprintf(dst, cap, "%s", src);
}

static bool dev_index_parse_board(const char *line,
                                  struct dev_index_fields *f)
{
    struct json_value v;
    json_init(&v);
    if (!json_read(&v, line, strlen(line)) || v.type != JSON_OBJ) {
        json_free(&v);
        return false;
    }
    dev_index_copy(f->ts, sizeof(f->ts), json_get_str(json_get(&v, "ts")));
    dev_index_copy(f->kind, sizeof(f->kind),
                  json_get_str(json_get(&v, "kind")));
    dev_index_copy(f->a, sizeof(f->a), json_get_str(json_get(&v, "host")));
    dev_index_copy(f->b, sizeof(f->b), json_get_str(json_get(&v, "agent")));
    dev_index_copy(f->c, sizeof(f->c), json_get_str(json_get(&v, "ref")));
    for (size_t i = 0; i < v.num_children; i++) {
        if (v.children[i].type != JSON_STR)
            continue;
        dev_index_kv_add(f, v.keys[i], json_get_str(&v.children[i]));
    }
    json_free(&v);
    return true;
}

static bool dev_index_parse_landing(const char *line,
                                    struct dev_index_fields *f)
{
    struct json_value v;
    json_init(&v);
    if (!json_read(&v, line, strlen(line)) || v.type != JSON_OBJ) {
        json_free(&v);
        return false;
    }
    dev_index_copy(f->ts, sizeof(f->ts), json_get_str(json_get(&v, "ts")));
    dev_index_copy(f->kind, sizeof(f->kind),
                  json_get_str(json_get(&v, "state")));
    dev_index_copy(f->a, sizeof(f->a),
                  json_get_str(json_get(&v, "worktree")));
    dev_index_copy(f->b, sizeof(f->b), json_get_str(json_get(&v, "note")));
    dev_index_copy(f->c, sizeof(f->c), json_get_str(json_get(&v, "phase")));
    for (size_t i = 0; i < v.num_children; i++) {
        if (v.children[i].type != JSON_STR)
            continue;
        dev_index_kv_add(f, v.keys[i], json_get_str(&v.children[i]));
    }
    json_free(&v);
    return true;
}

/* Split `line` on '\t' in place (writes NULs into a caller-owned scratch
 * copy) and fill `out[i]` with a pointer into that copy for i < *n. */
#define DEV_INDEX_TSV_MAX_COLS 22u
static void dev_index_split_tsv(char *scratch, const char *out[],
                                size_t *n)
{
    *n = 0;
    char *cur = scratch;
    out[(*n)++] = cur;
    while (*cur && *n < DEV_INDEX_TSV_MAX_COLS) {
        if (*cur == '\t') {
            *cur = '\0';
            out[(*n)++] = cur + 1;
        }
        cur++;
    }
}

static bool dev_index_parse_experiment(const char *line,
                                       struct dev_index_fields *f)
{
    if (strncmp(line, "ts\tkind\t", 8) == 0)
        return false; /* the header line, never indexed */
    char scratch[DEV_INDEX_LINE_MAX];
    dev_index_copy(scratch, sizeof(scratch), line);
    const char *cols[DEV_INDEX_TSV_MAX_COLS];
    size_t n = 0;
    dev_index_split_tsv(scratch, cols, &n);
    if (n < 18)
        return false;
    dev_index_copy(f->ts, sizeof(f->ts), cols[0]);
    dev_index_copy(f->kind, sizeof(f->kind), cols[1]);
    dev_index_copy(f->a, sizeof(f->a), cols[3]);  /* task_id */
    dev_index_copy(f->b, sizeof(f->b), cols[6]);  /* executor */
    dev_index_copy(f->c, sizeof(f->c), cols[17]); /* outcome */
    static const char *const enum_cols[] = {
        "ts", "kind", "box", "task_id", "task_class", "story",
        "executor", "harness", "model", "effort", "outcome",
    };
    static const size_t enum_idx[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 17};
    for (size_t i = 0; i < sizeof(enum_idx) / sizeof(enum_idx[0]); i++)
        if (enum_idx[i] < n)
            dev_index_kv_add(f, enum_cols[i], cols[enum_idx[i]]);
    return true;
}

/* A log line's leading token is a timestamp often enough to be worth
 * indexing, but plenty of lines start with anything else (a progress bar,
 * a bare word). Only trust it when it looks like "YYYY-MM-DDTHH:MM:SS" —
 * digits and separators in the right places — so a non-timestamp leading
 * token leaves ts empty (searchable in `text`, just not sortable) instead
 * of polluting MAX(ts) with an arbitrary string. */
/* Compares tok[0..18] against the "YYYY-MM-DDTHH:MM:SS" shape (digit
 * positions collapse to 'D', position 10 accepts 'T' or ' ') instead of a
 * long if/else chain over each position — one loop, one memcmp. */
static bool dev_index_looks_like_iso_ts(const char *tok, size_t len)
{
    static const char shape[19] = "DDDD-DD-DD?DD:DD:DD";
    if (len < sizeof(shape))
        return false;
    char got[sizeof(shape)];
    for (size_t i = 0; i < sizeof(shape); i++)
        got[i] = (tok[i] >= '0' && tok[i] <= '9') ? 'D' : tok[i];
    if (got[10] == 'T' || got[10] == ' ')
        got[10] = '?';
    return memcmp(got, shape, sizeof(shape)) == 0;
}

static bool dev_index_ident_start(char c)
{
    return c == '_' || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
}

static bool dev_index_ident_char(char c)
{
    return dev_index_ident_start(c) || (c >= '0' && c <= '9');
}

/* Advance *p to the next `key=value` token (identifier key, non-space
 * value run) and fill key/val. Returns false once the line is exhausted.
 * Split out of dev_index_parse_log so that function stays one loop plus
 * one call instead of a nested scan. */
static bool dev_index_next_kv_token(const char **p, char *key, size_t key_cap,
                                    char *val, size_t val_cap)
{
    while (**p) {
        if (!dev_index_ident_start(**p)) {
            (*p)++;
            continue;
        }
        const char *key_start = *p;
        const char *eq = *p;
        while (dev_index_ident_char(*eq))
            eq++;
        if (*eq != '=') {
            *p = eq;
            continue;
        }
        const char *val_start = eq + 1;
        const char *val_end = val_start;
        while (*val_end && *val_end != ' ' && *val_end != '\t')
            val_end++;
        *p = val_end;
        size_t klen = (size_t)(eq - key_start);
        size_t vlen = (size_t)(val_end - val_start);
        if (vlen == 0 || klen >= key_cap || vlen >= val_cap)
            continue;
        memcpy(key, key_start, klen);
        key[klen] = '\0';
        memcpy(val, val_start, vlen);
        val[vlen] = '\0';
        return true;
    }
    return false;
}

static bool dev_index_parse_log(const char *line, struct dev_index_fields *f)
{
    memset(f, 0, sizeof(*f));
    const char *sp = strchr(line, ' ');
    size_t ts_len = sp ? (size_t)(sp - line) : 0;
    if (ts_len > 0 && ts_len < sizeof(f->ts) &&
       dev_index_looks_like_iso_ts(line, ts_len)) {
        memcpy(f->ts, line, ts_len);
        f->ts[ts_len] = '\0';
    }
    dev_index_copy(f->kind, sizeof(f->kind), "log");
    const char *p = line;
    char key[48], val[64];
    int found = 0;
    while (found < 16 &&
          dev_index_next_kv_token(&p, key, sizeof(key), val, sizeof(val))) {
        dev_index_kv_add(f, key, val);
        found++;
    }
    return true;
}

static bool dev_index_parse_line(const struct dev_index_source *src,
                                 const char *line, struct dev_index_fields *f)
{
    memset(f, 0, sizeof(*f));
    switch (src->kind) {
    case DEV_INDEX_KIND_BOARD_ROWS:
        return dev_index_parse_board(line, f);
    case DEV_INDEX_KIND_LANDING_OUTCOMES:
        return dev_index_parse_landing(line, f);
    case DEV_INDEX_KIND_EXPERIMENT_ROWS:
        return dev_index_parse_experiment(line, f);
    case DEV_INDEX_KIND_LOG_LINES:
        return dev_index_parse_log(line, f);
    }
    return false;
}

/* ── per-file ingest ─────────────────────────────────────────────────── */

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
 * inserting one `rows` row per parsed line, until EOF or an error. Fills
 * *end_offset with the byte position to save as the new cursor. Split out
 * of dev_index_ingest_file so that function stays open/seek/close plus one
 * call, not an inline read loop. */
static bool dev_index_ingest_lines(sqlite3 *db, const struct dev_index_source *src,
                                   FILE *fp, int64_t offset, long *end_offset,
                                   int64_t *rows_added, const char *path,
                                   char *err, size_t err_cap)
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
        if (!dev_index_parse_line(src, line, &f))
            continue;
        if (!dev_index_insert_row(db, src->id, seq, &f, line)) {
            dev_index_set_err(err, err_cap, "insert failed for %s", path);
            return false;
        }
        seq++;
        (*rows_added)++;
    }
}

static bool dev_index_ingest_file(sqlite3 *db, const struct dev_index_source *src,
                                  const char *path, int64_t *rows_added,
                                  char *err, size_t err_cap)
{
    int64_t inode = 0, size = 0;
    if (!dev_index_stat_file(path, &inode, &size))
        return true; /* file vanished between list and read: not an error */

    struct dev_index_cursor cursor;
    if (!dev_index_get_cursor(db, src->id, path, &cursor)) {
        dev_index_set_err(err, err_cap, "cursor read failed for %s", path);
        return false;
    }
    int64_t offset = cursor.byte_offset;
    if (cursor.found && (size < offset || cursor.inode != inode))
        offset = 0; /* rotated or shrunk: restart from 0 */

    FILE *fp = fopen(path, "rb");
    if (!fp)
        return true; /* unreadable right now: skip, try again next ingest */
    if (offset > 0 && fseek(fp, offset, SEEK_SET) != 0) {
        fclose(fp);
        dev_index_set_err(err, err_cap, "seek failed for %s", path);
        return false;
    }

    long end_offset = offset;
    bool ok = dev_index_ingest_lines(db, src, fp, offset, &end_offset,
                                     rows_added, path, err, err_cap);
    fclose(fp);
    if (!ok)
        return false;
    if (!dev_index_set_cursor(db, src->id, path, end_offset, inode, size)) {
        dev_index_set_err(err, err_cap, "cursor write failed for %s", path);
        return false;
    }
    return true;
}

bool dev_index_ingest_source(sqlite3 *db, const struct dev_index_source *src,
                             struct dev_index_ingest_result *result,
                             char *err, size_t err_cap)
{
    result->source_id = src->id;
    result->files_seen = 0;
    result->rows_added = 0;
    char (*files)[1024] = dev_index_alloc_files();
    if (!files) {
        dev_index_set_err(err, err_cap, "out of memory listing files%s", "");
        return false;
    }
    size_t n = dev_index_source_list_files(src, files, DEV_INDEX_MAX_FILES,
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
                                   err, err_cap);
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
    size_t n = dev_index_source_list_files(src, files, DEV_INDEX_MAX_FILES,
                                           sizeof(files[0]));
    for (size_t i = 0; i < n; i++) {
        int64_t inode = 0, size = 0;
        if (!dev_index_stat_file(files[i], &inode, &size))
            continue;
        struct dev_index_cursor cursor;
        if (!dev_index_get_cursor(db, src->id, files[i], &cursor))
            continue;
        int64_t offset = (cursor.found && cursor.inode == inode)
                             ? cursor.byte_offset
                             : 0;
        if (size > offset)
            out->bytes_behind += size - offset;
    }
    free(files);
    return true;
}
