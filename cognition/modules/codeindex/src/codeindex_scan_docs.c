/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Scan the prose of docs tree .md, AGENTS.md and README.md into the
 * sealed codeindex docs table (path, title, first paragraph, headings,
 * line count, content hash). */

#include "codeindex_priv.h"
#include "codeindex/codeindex_docs.h"

#include "util/log_macros.h"
#include "util/safe_alloc.h"
#include "util/str_suffix.h"

#include <sqlite3.h>

#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if !defined(_WIN32)
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

/* A prose file larger than this is skipped with a warning rather than read
 * into memory; the largest tracked doc is far below it. */
#define CI_DOC_FILE_CAP ((size_t)16u << 20)
#define CI_DOC_PATH_ALLOC 512
#define CI_DOC_COUNT_CAP 16384

struct doc_paths {
    char (*v)[CI_DOC_PATH_ALLOC];
    size_t n, cap;
};

static bool doc_paths_push(struct doc_paths *p, const char *path)
{
    if (strlen(path) >= CI_DOC_PATH_ALLOC) return true; /* unindexable */
    if (p->n >= CI_DOC_COUNT_CAP)
        LOG_FAIL("codeindex", "prose file count exceeds %d", CI_DOC_COUNT_CAP);
    if (p->n == p->cap) {
        size_t cap = p->cap ? p->cap * 2 : 256;
        void *next = zcl_realloc(p->v, cap * sizeof(*p->v), "ci_doc_paths");
        if (!next) return false;
        p->v = next;
        p->cap = cap;
    }
    memcpy(p->v[p->n++], path, strlen(path) + 1);
    return true;
}

static int doc_path_cmp(const void *a, const void *b)
{
    return strcmp(a, b);
}

static bool doc_name_pruned(const char *name)
{
#define SOURCE_PRUNE_DIR(name_) if (strcmp(name, name_) == 0) return true;
#define SOURCE_INVENTORY_PRUNE_DIR(name_)
#include "codeindex/source_prune_dirs.def"
#undef SOURCE_INVENTORY_PRUNE_DIR
#undef SOURCE_PRUNE_DIR
    return false;
}

/* docs tree .md, or an AGENTS.md / README.md anywhere under a scanned root. */
static bool doc_wanted(const char *reldir, const char *name)
{
    if (strcmp(name, "AGENTS.md") == 0 || strcmp(name, "README.md") == 0)
        return true;
    return strlen(name) > 3 && zcl_str_has_suffix(name, ".md") &&
           (strcmp(reldir, "docs") == 0 || strncmp(reldir, "docs/", 5) == 0);
}

static bool doc_collect_dir(const char *root, const char *reldir, bool recurse,
                            struct doc_paths *out);

static bool doc_collect_entry(const char *root, const char *reldir,
                              const char *name, bool recurse,
                              struct doc_paths *out)
{
    if (name[0] == '.') return true;
    char child[CI_DOC_PATH_ALLOC], full[CI_PATH_MAX];
    int n = reldir[0] ? snprintf(child, sizeof(child), "%s/%s", reldir, name)
                      : snprintf(child, sizeof(child), "%s", name);
    if (n <= 0 || (size_t)n >= sizeof(child)) return true;
    int m = snprintf(full, sizeof(full), "%s/%s", root, child);
    struct stat st;
    if (m <= 0 || (size_t)m >= sizeof(full) || lstat(full, &st) != 0)
        return true;
    if (S_ISDIR(st.st_mode))
        return !recurse || doc_name_pruned(name) ||
               doc_collect_dir(root, child, true, out);
    if (S_ISREG(st.st_mode) && doc_wanted(reldir, name))
        return doc_paths_push(out, child);
    return true;
}

static bool doc_collect_dir(const char *root, const char *reldir, bool recurse,
                            struct doc_paths *out)
{
    char full[CI_PATH_MAX];
    int n = reldir[0] ? snprintf(full, sizeof(full), "%s/%s", root, reldir)
                      : snprintf(full, sizeof(full), "%s", root);
    if (n <= 0 || (size_t)n >= sizeof(full)) return false;
    DIR *dir = opendir(full);
    if (!dir) return errno == ENOENT;
    bool ok = true;
    struct dirent *entry;
    while (ok && (entry = readdir(dir)) != NULL)
        ok = doc_collect_entry(root, reldir, entry->d_name, recurse, out);
    (void)closedir(dir);
    return ok;
}

/* Sorted, repo-relative prose paths. The source roots plus apps/ are walked
 * recursively; the checkout root contributes only its own AGENTS.md and
 * README.md so sibling worktrees nested under it are never indexed. */
static bool doc_enumerate(const char *root, struct doc_paths *out)
{
    static const char *const roots[] = {
#define SOURCE_ROOT(name_) name_,
#include "codeindex/source_roots.def"
#undef SOURCE_ROOT
        "apps",
    };
    bool ok = doc_collect_dir(root, "", false, out);
    for (size_t i = 0; ok && i < sizeof(roots) / sizeof(roots[0]); i++)
        ok = doc_collect_dir(root, roots[i], true, out);
    if (ok && out->n > 1)
        qsort(out->v, out->n, sizeof(out->v[0]), doc_path_cmp);
    return ok;
}

/* Read one regular file whole; *out is zcl_malloc'ed (never NULL on true). */
static bool doc_read_file(const char *root, const char *relpath, char **out,
                          size_t *len_out)
{
    char full[CI_PATH_MAX];
    int n = snprintf(full, sizeof(full), "%s/%s", root, relpath);
    if (n <= 0 || (size_t)n >= sizeof(full)) return false;
    int fd = open(full, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return false;
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size < 0 ||
        (uint64_t)st.st_size > CI_DOC_FILE_CAP) {
        (void)close(fd);
        return false;
    }
    size_t size = (size_t)st.st_size, got = 0;
    char *buf = zcl_malloc(size ? size : 1, "ci_doc_buf");
    while (buf && got < size) {
        ssize_t r = read(fd, buf + got, size - got);
        if (r <= 0) break;
        got += (size_t)r;
    }
    (void)close(fd);
    if (!buf || got != size) {
        free(buf);
        return false;
    }
    *out = buf;
    *len_out = size;
    return true;
}
#endif /* !_WIN32 */

/* ── parsing ──────────────────────────────────────────────────────────── */

/* Append `text` to a capped field with `sep` between parts. A part that does
 * not fit is cut at a UTF-8 boundary and the field ends in a visible "...";
 * returns false once the field is full. */
static bool doc_append(char *field, size_t cap, const char *sep,
                       const char *text, size_t text_len)
{
    size_t used = strlen(field);
    size_t sep_len = used ? strlen(sep) : 0;
    if (used + 1 >= cap) return false;
    if (used + sep_len + text_len + 1 <= cap) {
        memcpy(field + used, sep, sep_len);
        memcpy(field + used + sep_len, text, text_len);
        field[used + sep_len + text_len] = '\0';
        return true;
    }
    size_t room = cap - used - sep_len - 1;
    if (room <= 3) return false;
    size_t keep = room - 3;
    while (keep > 0 && ((unsigned char)text[keep] & 0xC0u) == 0x80u) keep--;
    memcpy(field + used, sep, sep_len);
    memcpy(field + used + sep_len, text, keep);
    memcpy(field + used + sep_len + keep, "...", 4);
    return false;
}

struct doc_line {
    const char *p;
    size_t len;
};

static struct doc_line doc_trim(const char *p, size_t len)
{
    while (len > 0 && (isspace((unsigned char)*p))) { p++; len--; }
    while (len > 0 && isspace((unsigned char)p[len - 1])) len--;
    return (struct doc_line){p, len};
}

/* ATX heading level of a trimmed line, 0 when it is not one. */
static int doc_heading_level(struct doc_line line)
{
    size_t level = 0;
    while (level < line.len && line.p[level] == '#') level++;
    if (level == 0 || level > 6 || level >= line.len || line.p[level] != ' ')
        return 0;
    return (int)level;
}

static bool doc_is_fence(struct doc_line line)
{
    return line.len >= 3 && (strncmp(line.p, "```", 3) == 0 ||
                             strncmp(line.p, "~~~", 3) == 0);
}

struct doc_state {
    struct ci_doc *row;
    bool in_fence;
    bool have_title;
    bool paragraph_open;
    bool paragraph_done;
};

static void doc_on_heading(struct doc_state *st, struct doc_line line,
                           int level)
{
    struct doc_line text = doc_trim(line.p + level, line.len - (size_t)level);
    if (text.len == 0) return;
    if (level == 1 && !st->have_title) {
        size_t n = text.len < sizeof(st->row->title) - 1
                       ? text.len : sizeof(st->row->title) - 1;
        memcpy(st->row->title, text.p, n);
        st->row->title[n] = '\0';
        st->have_title = true;
    }
    (void)doc_append(st->row->headings, sizeof(st->row->headings), " | ",
                     text.p, text.len);
    if (st->paragraph_open) st->paragraph_done = true;
}

/* A prose line that belongs to the first paragraph: not a table row, an HTML
 * tag, a rule or a front-matter fence. */
static bool doc_is_prose(struct doc_line line)
{
    char first = line.p[0];
    if (first == '|' || first == '<') return false;
    return !(line.len >= 3 && strncmp(line.p, "---", 3) == 0);
}

static void doc_on_text(struct doc_state *st, struct doc_line line)
{
    if (st->paragraph_done || !doc_is_prose(line)) return;
    st->paragraph_open = true;
    if (!doc_append(st->row->summary, sizeof(st->row->summary), " ", line.p,
                    line.len))
        st->paragraph_done = true;
}

static void doc_on_line(struct doc_state *st, struct doc_line line)
{
    if (doc_is_fence(line)) {
        st->in_fence = !st->in_fence;
        if (st->paragraph_open) st->paragraph_done = true;
        return;
    }
    if (st->in_fence) return;
    if (line.len == 0) {
        if (st->paragraph_open) st->paragraph_done = true;
        return;
    }
    int level = doc_heading_level(line);
    if (level > 0) doc_on_heading(st, line, level);
    else doc_on_text(st, line);
}

/* Parse markdown `buf` into the title, first-paragraph and headings fields.
 * The first paragraph is the first run of prose lines outside code fences. */
static void doc_parse(const char *buf, size_t len, struct ci_doc *row)
{
    struct doc_state st = {.row = row};
    size_t at = 0;
    while (at < len) {
        size_t end = at;
        while (end < len && buf[end] != '\n') end++;
        doc_on_line(&st, doc_trim(buf + at, end - at));
        at = end + 1;
    }
}

/* ── storage ──────────────────────────────────────────────────────────── */

static bool doc_insert(sqlite3 *db, const struct ci_doc *row,
                       const uint8_t sha[32])
{
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT OR REPLACE INTO docs(path,title,summary,headings,"
            "line_count,content_sha3) VALUES(?,?,?,?,?,?)", -1, &stmt,
            NULL) != SQLITE_OK)
        return false;
    bool ok = sqlite3_bind_text(stmt, 1, row->path, -1, SQLITE_TRANSIENT) ==
                  SQLITE_OK &&
              sqlite3_bind_text(stmt, 2, row->title, -1, SQLITE_TRANSIENT) ==
                  SQLITE_OK &&
              sqlite3_bind_text(stmt, 3, row->summary, -1, SQLITE_TRANSIENT) ==
                  SQLITE_OK &&
              sqlite3_bind_text(stmt, 4, row->headings, -1,
                                SQLITE_TRANSIENT) == SQLITE_OK &&
              sqlite3_bind_int(stmt, 5, row->line_count) == SQLITE_OK &&
              sqlite3_bind_blob(stmt, 6, sha, 32, SQLITE_TRANSIENT) ==
                  SQLITE_OK &&
              sqlite3_step(stmt) == SQLITE_DONE; // raw-sql-ok:codeindex-derived
    sqlite3_finalize(stmt);
    return ok;
}

#if !defined(_WIN32)
static bool doc_store_one(sqlite3 *db, const char *root, const char *relpath)
{
    char *buf = NULL;
    size_t len = 0;
    if (!doc_read_file(root, relpath, &buf, &len)) {
        LOG_WARN("codeindex", "prose file skipped (unreadable or over cap): %s",
                 relpath);
        return true;
    }
    struct ci_doc row;
    memset(&row, 0, sizeof(row));
    snprintf(row.path, sizeof(row.path), "%s", relpath);
    row.line_count = ci_scan_count_lines(buf, len);
    doc_parse(buf, len, &row);
    uint8_t sha[32];
    ci_scan_hash_contents(buf, len, sha);
    free(buf);
    return strlen(relpath) < sizeof(row.path) && doc_insert(db, &row, sha);
}

bool ci_docs_refresh(struct ci_store *store, const char *root)
{
    if (!store || !root) LOG_FAIL("codeindex", "null arg to docs_refresh");
    sqlite3 *db = ci_store_db(store);
    struct doc_paths paths = {0};
    bool ok = db && sqlite3_exec(db, "DELETE FROM docs", NULL, NULL, NULL) ==
                        SQLITE_OK &&
              doc_enumerate(root, &paths);
    for (size_t i = 0; ok && i < paths.n; i++)
        ok = doc_store_one(db, root, paths.v[i]);
    free(paths.v);
    if (!ok) LOG_FAIL("codeindex", "prose scan failed under %s", root);
    return true;
}

bool ci_docs_hash_file(const char *root, const char *relpath, uint8_t out[32])
{
    char *buf = NULL;
    size_t len = 0;
    if (!root || !relpath || !out || !doc_read_file(root, relpath, &buf, &len))
        return false;
    ci_scan_hash_contents(buf, len, out);
    free(buf);
    return true;
}
#else
/* The prose walk is POSIX-only for now; a Windows generation carries an empty
 * docs table, which its readers report as "no prose indexed". */
bool ci_docs_refresh(struct ci_store *store, const char *root)
{
    (void)root;
    sqlite3 *db = store ? ci_store_db(store) : NULL;
    return db && sqlite3_exec(db, "DELETE FROM docs", NULL, NULL, NULL) ==
                     SQLITE_OK;
}

bool ci_docs_hash_file(const char *root, const char *relpath, uint8_t out[32])
{
    (void)root;
    (void)relpath;
    (void)out;
    return false;
}
#endif
