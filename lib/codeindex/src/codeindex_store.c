/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * codeindex_store — the derived-state SQLite store for the code index.
 *
 * ── OUTSIDE the node.db ActiveRecord lifecycle by design ──
 * index.kv is a dedicated single-writer SQLite file at
 * <root>/.codeindex/index.kv, below the AR layer — exactly like lib/vcs's
 * index.kv, progress.kv, and seal_kv. Its rows are NOT AR models; routing
 * them through AR would be a category error. Raw sqlite3_step here therefore
 * carries the `// raw-sql-ok:codeindex-derived` marker, and the whole store
 * is recomputable from the source tree by codeindex_rebuild
 * ("recompute, never repair"). Canonical generations are opened through a
 * validated owner-controlled directory + immutable inode capability, never a
 * second pathname lookup. Each symbol row carries a row_sha3 checksum so a
 * corrupted row is caught on read (verify-on-read). */

#include "codeindex_priv.h"

#include "platform/fd_path.h"
#include "platform/positioned_file.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"

#include <sqlite3.h>

#include <errno.h>
#if !defined(_WIN32)
#include <fcntl.h>
#endif
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#if defined(_WIN32)
#include <io.h>
#else
#include <unistd.h>
#endif

struct ci_store {
    sqlite3        *db;
    pthread_mutex_t lock;   /* recursive: held begin..commit; reads take briefly */
    int             bound_fd; /* immutable canonical inode, -1 for :memory: */
    bool            readonly;
};

sqlite3 *ci_store_db(struct ci_store *s) { return s ? s->db : NULL; }
void ci_store_lock(struct ci_store *s) { if (s) pthread_mutex_lock(&s->lock); }
void ci_store_unlock(struct ci_store *s) { if (s) pthread_mutex_unlock(&s->lock); }

/* ── open / schema ──────────────────────────────────────────────────── */

struct ci_store *ci_store_open_path(const char *dbpath)
{
    if (!dbpath || !dbpath[0])
        LOG_NULL("codeindex", "null dbpath");
#if defined(_WIN32)
    if (strcmp(dbpath, ":memory:") != 0)
        return NULL;
#endif

    struct ci_store *s = zcl_calloc(1, sizeof(*s), "ci_store");
    if (!s)
        LOG_NULL("codeindex", "calloc ci_store");

    s->bound_fd = -1;
    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&s->lock, &attr);
    pthread_mutexattr_destroy(&attr);

    if (sqlite3_open(dbpath, &s->db) != SQLITE_OK) {
        fprintf(stderr, "[codeindex] sqlite3_open %s: %s\n",  // obs-ok:codeindex-open-failure
                dbpath, s->db ? sqlite3_errmsg(s->db) : "(no handle)");
        if (s->db) sqlite3_close(s->db);
        pthread_mutex_destroy(&s->lock);
        free(s);
        return NULL;
    }
    if (!ci_store_apply_pragmas(s->db) || !ci_store_ensure_schema(s->db)) {
        sqlite3_close(s->db);
        pthread_mutex_destroy(&s->lock);
        free(s);
        LOG_NULL("codeindex", "store open: pragmas/schema failed");
    }
    return s;
}

struct ci_store *ci_store_open(const char *root)
{
    if (!root || !root[0])
        LOG_NULL("codeindex", "null root");
#if defined(_WIN32)
    struct platform_positioned_file file;
    struct platform_positioned_file_snapshot before, after;
    platform_positioned_file_init(&file);
    if (!platform_positioned_file_open_beneath(
            &file, root, ".codeindex/index.kv"))
        return NULL;
    uint64_t image_size = 0;
    if (!platform_positioned_file_is_private(&file) ||
        !platform_positioned_file_snapshot(&file, &before) ||
        !platform_positioned_file_size(&file, &image_size) || image_size == 0 ||
        image_size > INT64_MAX || image_size > (uint64_t)SIZE_MAX) {
        platform_positioned_file_close(&file);
        return NULL;
    }
    unsigned char *image = sqlite3_malloc64((sqlite3_uint64)image_size);
    if (!image) {
        platform_positioned_file_close(&file);
        return NULL;
    }
    size_t done = 0;
    while (done < (size_t)image_size) {
        int64_t read = platform_positioned_file_read(
            &file, image + done, (size_t)image_size - done, done);
        if (read <= 0) break;
        done += (size_t)read;
    }
    bool stable = done == (size_t)image_size &&
        platform_positioned_file_snapshot(&file, &after) &&
        before.size == after.size && before.volume == after.volume &&
        before.file_low == after.file_low && before.file_high == after.file_high &&
        before.modified_seconds == after.modified_seconds &&
        before.modified_nanoseconds == after.modified_nanoseconds &&
        before.changed_seconds == after.changed_seconds &&
        before.changed_nanoseconds == after.changed_nanoseconds;
    platform_positioned_file_close(&file);
    if (!stable) {
        sqlite3_free(image);
        return NULL;
    }
    struct ci_store *s = zcl_calloc(1, sizeof(*s), "ci_store_readonly");
    if (!s) { sqlite3_free(image); return NULL; }
    s->bound_fd = -1;
    s->readonly = true;
    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&s->lock, &attr);
    pthread_mutexattr_destroy(&attr);
    int flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE |
                SQLITE_OPEN_FULLMUTEX | SQLITE_OPEN_MEMORY;
    int opened = sqlite3_open_v2(":memory:", &s->db, flags, NULL);
    int loaded = opened == SQLITE_OK
        ? sqlite3_deserialize(s->db, "main", image,
                              (sqlite3_int64)image_size,
                              (sqlite3_int64)image_size,
                              SQLITE_DESERIALIZE_FREEONCLOSE |
                                  SQLITE_DESERIALIZE_READONLY)
        : SQLITE_ERROR;
    if (opened != SQLITE_OK || loaded != SQLITE_OK) {
        if (s->db) sqlite3_close(s->db);
        sqlite3_free(image);
        pthread_mutex_destroy(&s->lock);
        free(s);
        return NULL;
    }
    (void)sqlite3_busy_timeout(s->db, 5000);
    return s;
#else
    char dir[CI_PATH_MAX];
    int dn = snprintf(dir, sizeof(dir), "%s/.codeindex", root);
    if (dn <= 0 || (size_t)dn >= sizeof(dir))
        LOG_NULL("codeindex", "root too long");
    int dirfd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (dirfd < 0) {
        if (errno == ENOENT) return NULL;
        LOG_NULL("codeindex", "open canonical directory failed: %s",
                 strerror(errno));
    }
    struct stat dir_st;
    if (fstat(dirfd, &dir_st) != 0 || !S_ISDIR(dir_st.st_mode) ||
        dir_st.st_uid != geteuid() ||
        (dir_st.st_mode & (S_IWGRP | S_IWOTH))) {
        close(dirfd);
        LOG_NULL("codeindex",
                 "canonical directory is not an owner-controlled capability");
    }

    /* Open relative to the validated directory and bind SQLite to this exact
     * descriptor via /proc/self/fd. There is no lstat(path) -> reopen(path)
     * window, and immutable=1 prevents legacy WAL/SHM names from influencing
     * a published read-only generation. */
    int fd = openat(dirfd, "index.kv", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    int open_saved = errno;
    close(dirfd);
    if (fd < 0) {
        if (open_saved == ENOENT) return NULL;
        LOG_NULL("codeindex", "open canonical index failed: %s",
                 strerror(open_saved));
    }
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_nlink != 1 ||
        st.st_uid != geteuid() || (st.st_mode & (S_IWGRP | S_IWOTH))) {
        close(fd);
        LOG_NULL("codeindex",
                 "canonical index is not a private owner-controlled inode");
    }

    struct ci_store *s = zcl_calloc(1, sizeof(*s), "ci_store_readonly");
    if (!s) {
        close(fd);
        LOG_NULL("codeindex", "calloc readonly ci_store");
    }
    s->bound_fd = fd;
    s->readonly = true;
    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&s->lock, &attr);
    pthread_mutexattr_destroy(&attr);

    /* Name the bound descriptor through the one fd-naming shim
     * (platform/fd_path.h): /proc/self/fd/N on Linux, /dev/fd/N on Darwin.
     * The fd stays the authority; the URI only reopens it read-only. */
    char fd_name[64];
    if (!platform_fd_path(fd_name, sizeof(fd_name), fd, NULL)) {
        close(fd);
        pthread_mutex_destroy(&s->lock);
        free(s);
        LOG_NULL("codeindex", "canonical fd cannot be named");
    }
    char uri[128];
    int un = snprintf(uri, sizeof(uri),
                      "file:%s?mode=ro&immutable=1", fd_name);
    if (un <= 0 || (size_t)un >= sizeof(uri)) {
        close(fd);
        pthread_mutex_destroy(&s->lock);
        free(s);
        LOG_NULL("codeindex", "canonical fd URI overflow");
    }
    int flags = SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX | SQLITE_OPEN_URI;
    if (sqlite3_open_v2(uri, &s->db, flags, NULL) != SQLITE_OK) {
        if (s->db) sqlite3_close(s->db);
        close(fd);
        pthread_mutex_destroy(&s->lock);
        free(s);
        return NULL;
    }
    (void)sqlite3_busy_timeout(s->db, 5000);
    return s;
#endif
}

bool ci_store_write_image_fd(struct ci_store *s, int fd)
{
    if (!s || fd < 0)
        LOG_FAIL("codeindex", "invalid store/image fd");

#if defined(_WIN32)
    (void)s;
    (void)fd;
    return false;
#else
    pthread_mutex_lock(&s->lock);
    sqlite3_int64 image_size = 0;
    unsigned char *image = sqlite3_serialize(s->db, "main", &image_size, 0);
    bool ok = image && image_size > 0 &&
              (sqlite3_int64)(off_t)image_size == image_size;
    int saved = ok ? 0 : EOVERFLOW;

    if (ok && ftruncate(fd, 0) != 0) {
        ok = false;
        saved = errno;
    }
    sqlite3_int64 offset = 0;
    while (ok && offset < image_size) {
        sqlite3_int64 left = image_size - offset;
        size_t chunk = left > INT64_C(1048576)
            ? (size_t)INT64_C(1048576) : (size_t)left;
        ssize_t wrote = pwrite(fd, image + offset, chunk, (off_t)offset);
        if (wrote < 0 && errno == EINTR)
            continue;
        if (wrote <= 0) {
            ok = false;
            saved = wrote < 0 ? errno : EIO;
            break;
        }
        offset += wrote;
    }
    if (ok && ftruncate(fd, (off_t)image_size) != 0) {
        ok = false;
        saved = errno;
    }
    if (image) sqlite3_free(image);
    pthread_mutex_unlock(&s->lock);

    if (!ok)
        LOG_FAIL("codeindex", "serialize staging image failed: %s",
                 strerror(saved));
    return true;
#endif
}

void ci_store_close(struct ci_store *s)
{
    if (!s) return;
    if (s->db) sqlite3_close(s->db);
    if (s->bound_fd >= 0) {
#if defined(_WIN32)
        _close(s->bound_fd);
#else
        close(s->bound_fd);
#endif
    }
    pthread_mutex_destroy(&s->lock);
    free(s);
}

/* ── transaction control ────────────────────────────────────────────── */

bool ci_store_begin(struct ci_store *s)
{
    if (!s) LOG_FAIL("codeindex", "null store");
    if (s->readonly) return false;
    pthread_mutex_lock(&s->lock);
    char *err = NULL;
    if (sqlite3_exec(s->db, "BEGIN IMMEDIATE", NULL, NULL, &err) != SQLITE_OK) {
        if (err) sqlite3_free(err);
        pthread_mutex_unlock(&s->lock);
        LOG_FAIL("codeindex", "BEGIN IMMEDIATE failed");
    }
    return true;
}

bool ci_store_commit(struct ci_store *s)
{
    if (!s) LOG_FAIL("codeindex", "null store");
    char *err = NULL;
    bool ok = sqlite3_exec(s->db, "COMMIT", NULL, NULL, &err) == SQLITE_OK;
    if (err) sqlite3_free(err);
    pthread_mutex_unlock(&s->lock);
    if (!ok) LOG_FAIL("codeindex", "COMMIT failed");
    return true;
}

bool ci_store_rollback(struct ci_store *s)
{
    if (!s) LOG_FAIL("codeindex", "null store");
    char *err = NULL;
    sqlite3_exec(s->db, "ROLLBACK", NULL, NULL, &err);
    if (err) sqlite3_free(err);
    pthread_mutex_unlock(&s->lock);
    return true;
}

bool ci_store_clear(struct ci_store *s)
{
    if (!s) LOG_FAIL("codeindex", "null store");
    if (s->readonly) return false;
    char *err = NULL;
    if (sqlite3_exec(s->db,
        "DELETE FROM files; DELETE FROM symbols; DELETE FROM includes;"
        " DELETE FROM refs; DELETE FROM groups; DELETE FROM meta;",
        NULL, NULL, &err) != SQLITE_OK) {
        if (err) sqlite3_free(err);
        LOG_FAIL("codeindex", "clear tables");
    }
    return true;
}

/* ── writes ─────────────────────────────────────────────────────────── */

bool ci_store_put_file(struct ci_store *s, const struct ci_file *f,
                       const uint8_t content_sha3[32], int64_t mtime,
                       int64_t *out_file_id)
{
    if (s && s->readonly) return false;
    if (!s || !f || !content_sha3)
        LOG_FAIL("codeindex", "null arg to put_file");
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(s->db,
        "INSERT OR REPLACE INTO files(path,\"group\",purpose,content_sha3,mtime)"
        " VALUES(?,?,?,?,?)", -1, &stmt, NULL) != SQLITE_OK)
        LOG_FAIL("codeindex", "prepare put_file: %s", sqlite3_errmsg(s->db));
    sqlite3_bind_text(stmt, 1, f->path, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, f->group, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, f->purpose, -1, SQLITE_TRANSIENT);
    sqlite3_bind_blob(stmt, 4, content_sha3, 32, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 5, mtime);
    int rc = sqlite3_step(stmt);  // raw-sql-ok:codeindex-derived
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE)
        LOG_FAIL("codeindex", "step put_file rc=%d", rc);
    if (out_file_id) *out_file_id = sqlite3_last_insert_rowid(s->db);
    return true;
}

bool ci_store_put_symbol(struct ci_store *s, const struct ci_symbol *sym)
{
    if (s && s->readonly) return false;
    if (!s || !sym)
        LOG_FAIL("codeindex", "null arg to put_symbol");
    uint8_t row[32];
    ci_symbol_row_hash(sym, row);
    char kindstr[2] = { sym->kind, '\0' };
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(s->db,
        "INSERT INTO symbols(name,kind,def_path,def_line,decl_path,decl_line,"
        "signature,doc,guard,\"group\",partial,row_sha3)"
        " VALUES(?,?,?,?,?,?,?,?,?,?,?,?)", -1, &stmt, NULL) != SQLITE_OK)
        LOG_FAIL("codeindex", "prepare put_symbol: %s", sqlite3_errmsg(s->db));
    sqlite3_bind_text(stmt, 1, sym->name, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, kindstr, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, sym->def_path, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 4, sym->def_line);
    sqlite3_bind_text(stmt, 5, sym->decl_path, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 6, sym->decl_line);
    sqlite3_bind_text(stmt, 7, sym->signature, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 8, sym->doc, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 9, sym->guard, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 10, sym->group, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 11, sym->partial ? 1 : 0);
    sqlite3_bind_blob(stmt, 12, row, 32, SQLITE_TRANSIENT);
    int rc = sqlite3_step(stmt);  // raw-sql-ok:codeindex-derived
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE)
        LOG_FAIL("codeindex", "step put_symbol rc=%d", rc);
    return true;
}

bool ci_store_put_include(struct ci_store *s, int64_t file_id,
                          const char *dep_path)
{
    if (s && s->readonly) return false;
    if (!s || !dep_path)
        LOG_FAIL("codeindex", "null arg to put_include");
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(s->db,
        "INSERT OR IGNORE INTO includes(file_id,dep_path) VALUES(?,?)",
        -1, &stmt, NULL) != SQLITE_OK)
        LOG_FAIL("codeindex", "prepare put_include: %s", sqlite3_errmsg(s->db));
    sqlite3_bind_int64(stmt, 1, file_id);
    sqlite3_bind_text(stmt, 2, dep_path, -1, SQLITE_TRANSIENT);
    int rc = sqlite3_step(stmt);  // raw-sql-ok:codeindex-derived
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE)
        LOG_FAIL("codeindex", "step put_include rc=%d", rc);
    return true;
}

bool ci_store_put_ref(struct ci_store *s, const char *callee,
                      const char *ref_file, int ref_line,
                      const char *enclosing)
{
    if (s && s->readonly) return false;
    if (!s || !callee || !ref_file)
        LOG_FAIL("codeindex", "null arg to put_ref");
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(s->db,
        "INSERT INTO refs(callee_name,ref_file,ref_line,enclosing)"
        " VALUES(?,?,?,?)",
        -1, &stmt, NULL) != SQLITE_OK)
        LOG_FAIL("codeindex", "prepare put_ref: %s", sqlite3_errmsg(s->db));
    sqlite3_bind_text(stmt, 1, callee, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, ref_file, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 3, ref_line);
    sqlite3_bind_text(stmt, 4, enclosing ? enclosing : "", -1, SQLITE_TRANSIENT);
    int rc = sqlite3_step(stmt);  // raw-sql-ok:codeindex-derived
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE)
        LOG_FAIL("codeindex", "step put_ref rc=%d", rc);
    return true;
}

bool ci_store_put_group(struct ci_store *s, const struct ci_group *g)
{
    if (s && s->readonly) return false;
    if (!s || !g)
        LOG_FAIL("codeindex", "null arg to put_group");
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(s->db,
        "INSERT OR REPLACE INTO groups(path,kind,parent,purpose)"
        " VALUES(?,?,?,?)", -1, &stmt, NULL) != SQLITE_OK)
        LOG_FAIL("codeindex", "prepare put_group: %s", sqlite3_errmsg(s->db));
    sqlite3_bind_text(stmt, 1, g->path, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, g->kind, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, g->parent, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, g->purpose, -1, SQLITE_TRANSIENT);
    int rc = sqlite3_step(stmt);  // raw-sql-ok:codeindex-derived
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE)
        LOG_FAIL("codeindex", "step put_group rc=%d", rc);
    return true;
}

bool ci_store_meta_set(struct ci_store *s, const char *k, const void *v,
                       size_t vlen)
{
    if (s && s->readonly) return false;
    if (!s || !k || !k[0] || (vlen > 0 && !v))
        LOG_FAIL("codeindex", "null arg to meta_set");
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(s->db,
        "INSERT OR REPLACE INTO meta(k,v) VALUES(?,?)",
        -1, &stmt, NULL) != SQLITE_OK)
        LOG_FAIL("codeindex", "prepare meta_set: %s", sqlite3_errmsg(s->db));
    sqlite3_bind_text(stmt, 1, k, -1, SQLITE_TRANSIENT);
    sqlite3_bind_blob(stmt, 2, v ? v : "", (int)vlen, SQLITE_TRANSIENT);
    int rc = sqlite3_step(stmt);  // raw-sql-ok:codeindex-derived
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE)
        LOG_FAIL("codeindex", "step meta_set rc=%d", rc);
    return true;
}

/* ── reads ──────────────────────────────────────────────────────────── */

bool ci_store_meta_get(struct ci_store *s, const char *k, void *buf,
                       size_t cap, size_t *outlen, bool *found)
{
    if (found) *found = false;
    if (outlen) *outlen = 0;
    if (!s || !k || !k[0])
        LOG_FAIL("codeindex", "null arg to meta_get");
    pthread_mutex_lock(&s->lock);
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(s->db, "SELECT v FROM meta WHERE k=?",
                           -1, &stmt, NULL) != SQLITE_OK) {
        pthread_mutex_unlock(&s->lock);
        LOG_FAIL("codeindex", "prepare meta_get");
    }
    sqlite3_bind_text(stmt, 1, k, -1, SQLITE_TRANSIENT);
    bool ok = true;
    int rc = sqlite3_step(stmt);  // raw-sql-ok:codeindex-derived
    if (rc == SQLITE_ROW) {
        if (found) *found = true;
        int n = sqlite3_column_bytes(stmt, 0);
        const void *b = sqlite3_column_blob(stmt, 0);
        if (outlen) *outlen = (size_t)n;
        if (buf && cap > 0 && b) {
            size_t copy = (size_t)n < cap ? (size_t)n : cap;
            if (copy > 0) memcpy(buf, b, copy);
        }
    } else if (rc != SQLITE_DONE) {
        ok = false;
    }
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&s->lock);
    if (!ok) LOG_FAIL("codeindex", "step meta_get");
    return true;
}

/* Fill a ci_symbol from a stepped row and verify its integrity checksum.
 * Returns false (row rejected) if the recomputed hash mismatches the stored
 * row_sha3 — verify-on-read. */
bool ci_store_fill_symbol(sqlite3_stmt *stmt, struct ci_symbol *out)
{
    memset(out, 0, sizeof(*out));
    const unsigned char *t;
    t = sqlite3_column_text(stmt, 0);  ci_cpy(out->name, sizeof(out->name), (const char *)t);
    t = sqlite3_column_text(stmt, 1);  out->kind = (t && t[0]) ? (char)t[0] : 'D';
    t = sqlite3_column_text(stmt, 2);  ci_cpy(out->def_path, sizeof(out->def_path), (const char *)t);
    out->def_line = sqlite3_column_int(stmt, 3);
    t = sqlite3_column_text(stmt, 4);  ci_cpy(out->decl_path, sizeof(out->decl_path), (const char *)t);
    out->decl_line = sqlite3_column_int(stmt, 5);
    t = sqlite3_column_text(stmt, 6);  ci_cpy(out->signature, sizeof(out->signature), (const char *)t);
    t = sqlite3_column_text(stmt, 7);  ci_cpy(out->doc, sizeof(out->doc), (const char *)t);
    t = sqlite3_column_text(stmt, 8);  ci_cpy(out->guard, sizeof(out->guard), (const char *)t);
    t = sqlite3_column_text(stmt, 9);  ci_cpy(out->group, sizeof(out->group), (const char *)t);
    out->partial = sqlite3_column_int(stmt, 10) != 0;

    const void *rb = sqlite3_column_blob(stmt, 11);
    int rn = sqlite3_column_bytes(stmt, 11);
    uint8_t want[32];
    ci_symbol_row_hash(out, want);
    if (!rb || rn != 32 || memcmp(rb, want, 32) != 0)
        return false;  /* corrupted row */
    return true;
}

bool ci_store_symbol_by_name(struct ci_store *s, const char *name,
                             struct ci_symbol *out, bool *found)
{
    if (found) *found = false;
    if (!s || !name || !out)
        LOG_FAIL("codeindex", "null arg to symbol_by_name");
    pthread_mutex_lock(&s->lock);
    sqlite3_stmt *stmt = NULL;
    /* Prefer a definition over a bare declaration, then lowest def_line. */
    if (sqlite3_prepare_v2(s->db,
        "SELECT " CI_SYM_COLS " FROM symbols WHERE name=?"
        " ORDER BY (def_path='') ASC, def_line ASC, def_path ASC LIMIT 1",
        -1, &stmt, NULL) != SQLITE_OK) {
        pthread_mutex_unlock(&s->lock);
        LOG_FAIL("codeindex", "prepare symbol_by_name");
    }
    sqlite3_bind_text(stmt, 1, name, -1, SQLITE_TRANSIENT);
    bool ok = true;
    int rc = sqlite3_step(stmt);  // raw-sql-ok:codeindex-derived
    if (rc == SQLITE_ROW) {
        if (ci_store_fill_symbol(stmt, out)) {
            if (found) *found = true;
        }  /* corrupted → leave found=false */
    } else if (rc != SQLITE_DONE) {
        ok = false;
    }
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&s->lock);
    if (!ok) LOG_FAIL("codeindex", "step symbol_by_name");
    return true;
}

int ci_store_find_symbols(struct ci_store *s, const char *q,
                          struct ci_symbol *out, int cap)
{
    if (!s || !q || !out || cap <= 0)
        LOG_ERR("codeindex", "bad arg to find_symbols");
    /* Rank: exact(0) < prefix(1) < substring(2); then name, def_path. */
    char like[300];
    snprintf(like, sizeof(like), "%%%s%%", q);
    char pfx[300];
    snprintf(pfx, sizeof(pfx), "%s%%", q);
    pthread_mutex_lock(&s->lock);
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(s->db,
        "SELECT " CI_SYM_COLS ", "
        "  CASE WHEN name=?1 THEN 0 WHEN name LIKE ?2 THEN 1 ELSE 2 END AS rank"
        " FROM symbols WHERE name LIKE ?3"
        " ORDER BY rank ASC, name ASC, (def_path='') ASC, def_path ASC, def_line ASC",
        -1, &stmt, NULL) != SQLITE_OK) {
        pthread_mutex_unlock(&s->lock);
        LOG_ERR("codeindex", "prepare find_symbols");
    }
    sqlite3_bind_text(stmt, 1, q, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, pfx, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, like, -1, SQLITE_TRANSIENT);
    int n = 0;
    int rc;
    while (n < cap && (rc = sqlite3_step(stmt)) == SQLITE_ROW) {  // raw-sql-ok:codeindex-derived
        if (ci_store_fill_symbol(stmt, &out[n]))
            n++;  /* skip corrupted rows */
    }
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&s->lock);
    return n;
}

int ci_store_refs_by_callee(struct ci_store *s, const char *callee,
                            struct ci_ref *out, int cap)
{
    if (!s || !callee || !out || cap <= 0)
        LOG_ERR("codeindex", "bad arg to refs_by_callee");
    pthread_mutex_lock(&s->lock);
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(s->db,
        "SELECT callee_name,ref_file,ref_line,enclosing FROM refs"
        " WHERE callee_name=? ORDER BY ref_file ASC, ref_line ASC",
        -1, &stmt, NULL) != SQLITE_OK) {
        pthread_mutex_unlock(&s->lock);
        LOG_ERR("codeindex", "prepare refs_by_callee");
    }
    sqlite3_bind_text(stmt, 1, callee, -1, SQLITE_TRANSIENT);
    int n = 0;
    int rc;
    while (n < cap && (rc = sqlite3_step(stmt)) == SQLITE_ROW) {  // raw-sql-ok:codeindex-derived
        memset(&out[n], 0, sizeof(out[n]));
        ci_cpy(out[n].callee, sizeof(out[n].callee),
            (const char *)sqlite3_column_text(stmt, 0));
        ci_cpy(out[n].ref_file, sizeof(out[n].ref_file),
            (const char *)sqlite3_column_text(stmt, 1));
        out[n].ref_line = sqlite3_column_int(stmt, 2);
        ci_cpy(out[n].enclosing, sizeof(out[n].enclosing),
            (const char *)sqlite3_column_text(stmt, 3));
        n++;
    }
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&s->lock);
    return n;
}

int ci_store_refs_by_enclosing(struct ci_store *s, const char *enclosing,
                               struct ci_ref *out, int cap)
{
    if (!s || !enclosing || !out || cap <= 0)
        LOG_ERR("codeindex", "bad arg to refs_by_enclosing");
    pthread_mutex_lock(&s->lock);
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(s->db,
        "SELECT callee_name,ref_file,ref_line,enclosing FROM refs"
        " WHERE enclosing=? ORDER BY ref_file ASC, ref_line ASC",
        -1, &stmt, NULL) != SQLITE_OK) {
        pthread_mutex_unlock(&s->lock);
        LOG_ERR("codeindex", "prepare refs_by_enclosing");
    }
    sqlite3_bind_text(stmt, 1, enclosing, -1, SQLITE_TRANSIENT);
    int n = 0;
    int rc;
    while (n < cap && (rc = sqlite3_step(stmt)) == SQLITE_ROW) {  // raw-sql-ok:codeindex-derived
        memset(&out[n], 0, sizeof(out[n]));
        ci_cpy(out[n].callee, sizeof(out[n].callee),
            (const char *)sqlite3_column_text(stmt, 0));
        ci_cpy(out[n].ref_file, sizeof(out[n].ref_file),
            (const char *)sqlite3_column_text(stmt, 1));
        out[n].ref_line = sqlite3_column_int(stmt, 2);
        ci_cpy(out[n].enclosing, sizeof(out[n].enclosing),
            (const char *)sqlite3_column_text(stmt, 3));
        n++;
    }
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&s->lock);
    return n;
}

bool ci_store_file_by_path(struct ci_store *s, const char *path,
                           struct ci_file *out, bool *found)
{
    if (found) *found = false;
    if (!s || !path || !out)
        LOG_FAIL("codeindex", "null arg to file_by_path");
    pthread_mutex_lock(&s->lock);
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(s->db,
        "SELECT path,\"group\",purpose FROM files WHERE path=?",
        -1, &stmt, NULL) != SQLITE_OK) {
        pthread_mutex_unlock(&s->lock);
        LOG_FAIL("codeindex", "prepare file_by_path");
    }
    sqlite3_bind_text(stmt, 1, path, -1, SQLITE_TRANSIENT);
    bool ok = true;
    int rc = sqlite3_step(stmt);  // raw-sql-ok:codeindex-derived
    if (rc == SQLITE_ROW) {
        memset(out, 0, sizeof(*out));
        ci_cpy(out->path, sizeof(out->path), (const char *)sqlite3_column_text(stmt, 0));
        ci_cpy(out->group, sizeof(out->group), (const char *)sqlite3_column_text(stmt, 1));
        ci_cpy(out->purpose, sizeof(out->purpose), (const char *)sqlite3_column_text(stmt, 2));
        if (found) *found = true;
    } else if (rc != SQLITE_DONE) {
        ok = false;
    }
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&s->lock);
    if (!ok) LOG_FAIL("codeindex", "step file_by_path");
    return true;
}

int ci_store_list_groups(struct ci_store *s, struct ci_group *out, int cap)
{
    if (!s || !out || cap <= 0)
        LOG_ERR("codeindex", "bad arg to list_groups");
    pthread_mutex_lock(&s->lock);
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(s->db,
        "SELECT path,kind,parent,purpose FROM groups ORDER BY path ASC",
        -1, &stmt, NULL) != SQLITE_OK) {
        pthread_mutex_unlock(&s->lock);
        LOG_ERR("codeindex", "prepare list_groups");
    }
    int n = 0;
    int rc;
    while (n < cap && (rc = sqlite3_step(stmt)) == SQLITE_ROW) {  // raw-sql-ok:codeindex-derived
        memset(&out[n], 0, sizeof(out[n]));
        ci_cpy(out[n].path, sizeof(out[n].path), (const char *)sqlite3_column_text(stmt, 0));
        ci_cpy(out[n].kind, sizeof(out[n].kind), (const char *)sqlite3_column_text(stmt, 1));
        ci_cpy(out[n].parent, sizeof(out[n].parent), (const char *)sqlite3_column_text(stmt, 2));
        ci_cpy(out[n].purpose, sizeof(out[n].purpose), (const char *)sqlite3_column_text(stmt, 3));
        n++;
    }
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&s->lock);
    return n;
}

int ci_store_files_in_group(struct ci_store *s, const char *group,
                            struct ci_file *out, int cap)
{
    if (!s || !group || !out || cap <= 0)
        LOG_ERR("codeindex", "bad arg to files_in_group");
    pthread_mutex_lock(&s->lock);
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(s->db,
        "SELECT path,\"group\",purpose FROM files WHERE \"group\"=?"
        " ORDER BY path ASC",
        -1, &stmt, NULL) != SQLITE_OK) {
        pthread_mutex_unlock(&s->lock);
        LOG_ERR("codeindex", "prepare files_in_group");
    }
    sqlite3_bind_text(stmt, 1, group, -1, SQLITE_TRANSIENT);
    int n = 0;
    int rc;
    while (n < cap && (rc = sqlite3_step(stmt)) == SQLITE_ROW) {  // raw-sql-ok:codeindex-derived
        memset(&out[n], 0, sizeof(out[n]));
        ci_cpy(out[n].path, sizeof(out[n].path), (const char *)sqlite3_column_text(stmt, 0));
        ci_cpy(out[n].group, sizeof(out[n].group), (const char *)sqlite3_column_text(stmt, 1));
        ci_cpy(out[n].purpose, sizeof(out[n].purpose), (const char *)sqlite3_column_text(stmt, 2));
        n++;
    }
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&s->lock);
    return n;
}

int ci_store_count_files_in_group(struct ci_store *s, const char *group,
                                  bool recursive)
{
    if (!s || !group)
        LOG_ERR("codeindex", "bad arg to count_files_in_group");
    pthread_mutex_lock(&s->lock);
    sqlite3_stmt *stmt = NULL;
    /* Direct: only files stamped with EXACTLY this group. Recursive: also
     * every descendant group ("lib/net" under "lib") via the "<group>/%"
     * prefix, so a parent aggregates its children's file totals. */
    const char *sql = recursive
        ? "SELECT COUNT(*) FROM files WHERE \"group\"=? OR \"group\" LIKE ?||'/%'"
        : "SELECT COUNT(*) FROM files WHERE \"group\"=?";
    if (sqlite3_prepare_v2(s->db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        pthread_mutex_unlock(&s->lock);
        LOG_ERR("codeindex", "prepare count_files_in_group");
    }
    sqlite3_bind_text(stmt, 1, group, -1, SQLITE_TRANSIENT);
    if (recursive)
        sqlite3_bind_text(stmt, 2, group, -1, SQLITE_TRANSIENT);
    int n = 0;
    bool ok = true;
    int rc = sqlite3_step(stmt);  // raw-sql-ok:codeindex-derived
    if (rc == SQLITE_ROW)
        n = sqlite3_column_int(stmt, 0);
    else if (rc != SQLITE_DONE)
        ok = false;
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&s->lock);
    if (!ok) LOG_ERR("codeindex", "step count_files_in_group");
    return n;
}

int ci_store_symbols_in_file(struct ci_store *s, const char *path,
                             struct ci_symbol *out, int cap)
{
    if (!s || !path || !out || cap <= 0)
        LOG_ERR("codeindex", "bad arg to symbols_in_file");
    pthread_mutex_lock(&s->lock);
    sqlite3_stmt *stmt = NULL;
    /* A .c file owns its definitions (def_path); a header owns declarations
     * (decl_path). Match either, definitions first, then source order. */
    if (sqlite3_prepare_v2(s->db,
        "SELECT " CI_SYM_COLS " FROM symbols"
        " WHERE def_path=?1 OR decl_path=?1"
        " ORDER BY (def_path=?1) DESC, def_line ASC, decl_line ASC, name ASC",
        -1, &stmt, NULL) != SQLITE_OK) {
        pthread_mutex_unlock(&s->lock);
        LOG_ERR("codeindex", "prepare symbols_in_file");
    }
    sqlite3_bind_text(stmt, 1, path, -1, SQLITE_TRANSIENT);
    int n = 0;
    int rc;
    while (n < cap && (rc = sqlite3_step(stmt)) == SQLITE_ROW) {  // raw-sql-ok:codeindex-derived
        if (ci_store_fill_symbol(stmt, &out[n]))
            n++;  /* skip corrupted rows */
    }
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&s->lock);
    return n;
}

int ci_store_includes_of_file(struct ci_store *s, const char *path,
                              char (*out)[256], int cap)
{
    if (!s || !path || !out || cap <= 0)
        LOG_ERR("codeindex", "bad arg to includes_of_file");
    pthread_mutex_lock(&s->lock);
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(s->db,
        "SELECT i.dep_path FROM includes i JOIN files f ON f.id=i.file_id"
        " WHERE f.path=? ORDER BY i.dep_path ASC",
        -1, &stmt, NULL) != SQLITE_OK) {
        pthread_mutex_unlock(&s->lock);
        LOG_ERR("codeindex", "prepare includes_of_file");
    }
    sqlite3_bind_text(stmt, 1, path, -1, SQLITE_TRANSIENT);
    int n = 0;
    int rc;
    while (n < cap && (rc = sqlite3_step(stmt)) == SQLITE_ROW) {  // raw-sql-ok:codeindex-derived
        ci_cpy(out[n], 256, (const char *)sqlite3_column_text(stmt, 0));
        n++;
    }
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&s->lock);
    return n;
}

int ci_store_dependents_of_file(struct ci_store *s, const char *dep_path,
                                char (*out)[256], int cap)
{
    if (!s || !dep_path || !out || cap <= 0)
        LOG_ERR("codeindex", "bad arg to dependents_of_file");
    pthread_mutex_lock(&s->lock);
    sqlite3_stmt *stmt = NULL;
    /* The mirror of ci_store_includes_of_file. Each row of `includes` is a
     * (translation unit -> prerequisite) pair the COMPILER recorded, and a
     * depfile's prerequisite list is already transitively flattened, so one
     * equality probe answers the whole reverse question: every TU whose bytes
     * the compiler read `dep_path` for, however many headers deep. */
    if (sqlite3_prepare_v2(s->db,
        "SELECT DISTINCT f.path FROM includes i JOIN files f ON f.id=i.file_id"
        " WHERE i.dep_path=? ORDER BY f.path ASC",
        -1, &stmt, NULL) != SQLITE_OK) {
        pthread_mutex_unlock(&s->lock);
        LOG_ERR("codeindex", "prepare dependents_of_file");
    }
    sqlite3_bind_text(stmt, 1, dep_path, -1, SQLITE_TRANSIENT);
    int n = 0;
    int rc;
    while (n < cap && (rc = sqlite3_step(stmt)) == SQLITE_ROW) {  // raw-sql-ok:codeindex-derived
        ci_cpy(out[n], 256, (const char *)sqlite3_column_text(stmt, 0));
        n++;
    }
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&s->lock);
    return n;
}

int64_t ci_store_include_edge_count(struct ci_store *s)
{
    if (!s)
        LOG_ERR("codeindex", "null store to include_edge_count");
    pthread_mutex_lock(&s->lock);
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(s->db, "SELECT COUNT(*) FROM includes", -1, &stmt,
                           NULL) != SQLITE_OK) {
        pthread_mutex_unlock(&s->lock);
        LOG_ERR("codeindex", "prepare include_edge_count");
    }
    int64_t count = -1;
    if (sqlite3_step(stmt) == SQLITE_ROW)  // raw-sql-ok:codeindex-derived
        count = sqlite3_column_int64(stmt, 0);
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&s->lock);
    if (count < 0)
        LOG_ERR("codeindex", "read include_edge_count");
    return count;
}
