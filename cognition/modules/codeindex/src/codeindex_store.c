/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * codeindex_store — the derived-state SQLite store for the code index.
 *
 * ── OUTSIDE the node.db ActiveRecord lifecycle by design ──
 * index.kv is a dedicated single-writer SQLite file at
 * <root>/.codeindex/index.kv, below the AR layer — exactly like contexts/commons/modules/vcs's
 * index.kv, progress.kv, and seal_kv. Its rows are NOT AR models; routing
 * them through AR would be a category error. Raw sqlite3_step here therefore
 * carries the `// raw-sql-ok:codeindex-derived` marker, and the whole store
 * is recomputable from the source tree by codeindex_rebuild
 * ("recompute, never repair"). Canonical generations are opened through a
 * validated owner-controlled directory + immutable inode capability, never a
 * second pathname lookup. Each symbol row carries a row_sha3 checksum so a
 * corrupted row is caught on read (verify-on-read). */

#include "codeindex_store_internal.h"

#include "platform/fd_path.h"
#include "platform/positioned_file.h"
#include "platform/read_mapping.h"
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

#if defined(__linux__)
extern ssize_t copy_file_range(int, off_t *, int, off_t *, size_t,
                               unsigned int);
#endif

/* The handle layout now lives in codeindex_store_internal.h, shared with the
 * read half in codeindex_store_read.c. */

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
    platform_positioned_file_init(&s->bound_file);
    platform_read_mapping_init(&s->mapping);
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
        LOG_NULL("codeindex", "published Windows index is not a private bounded file");
    }
    struct platform_read_mapping mapping;
    platform_read_mapping_init(&mapping);
    if (!platform_read_mapping_open_positioned(
            &mapping, &file, (size_t)image_size)) {
        platform_positioned_file_close(&file);
        LOG_NULL("codeindex", "map published Windows index image size=%llu",
                 (unsigned long long)image_size);
    }
    bool stable = platform_positioned_file_snapshot(&file, &after) &&
        platform_positioned_file_snapshot_equal(&before, &after);
    if (!stable) {
        platform_read_mapping_close(&mapping);
        platform_positioned_file_close(&file);
        LOG_NULL("codeindex", "published Windows index changed while reading");
    }
    struct ci_store *s = zcl_calloc(1, sizeof(*s), "ci_store_readonly");
    if (!s) {
        platform_read_mapping_close(&mapping);
        platform_positioned_file_close(&file);
        LOG_NULL("codeindex", "allocate readonly Windows store");
    }
    s->bound_fd = -1;
    s->bound_file = file;
    s->mapping = mapping;
    s->has_bound_file = true;
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
        ? sqlite3_deserialize(s->db, "main", (unsigned char *)mapping.data,
                              (sqlite3_int64)image_size,
                              (sqlite3_int64)image_size,
                              SQLITE_DESERIALIZE_READONLY)
        : SQLITE_ERROR;
    if (opened != SQLITE_OK || loaded != SQLITE_OK) {
        fprintf(stderr,  // obs-ok:codeindex-open-failure
                "[codeindex] Windows deserialize failed open_rc=%d "
                "load_rc=%d image_size=%llu error=%s\n", opened, loaded,
                (unsigned long long)image_size,
                s->db ? sqlite3_errmsg(s->db) : "(no handle)");
        if (s->db) sqlite3_close(s->db);
        platform_read_mapping_close(&s->mapping);
        platform_positioned_file_close(&s->bound_file);
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
    return ci_store_open_readonly_fd(fd);
#endif
}

#if !defined(_WIN32)
struct ci_store *ci_store_open_readonly_fd(int fd)
{
    if (fd < 0)
        LOG_NULL("codeindex", "invalid readonly store fd");

    struct ci_store *s = zcl_calloc(1, sizeof(*s), "ci_store_readonly");
    if (!s) {
        close(fd);
        LOG_NULL("codeindex", "calloc readonly ci_store");
    }
    s->bound_fd = fd;
    platform_positioned_file_init(&s->bound_file);
    platform_read_mapping_init(&s->mapping);
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
}
#endif

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

bool ci_store_copy_image_fd(struct ci_store *s, int fd)
{
#if defined(_WIN32)
    (void)s;
    (void)fd;
    return false;
#else
    if (!s || s->bound_fd < 0 || fd < 0)
        LOG_FAIL("codeindex", "invalid source/staging fd for clone");
    struct stat st;
    if (fstat(s->bound_fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size <= 0)
        LOG_FAIL("codeindex", "inspect source generation for clone");
#if defined(__linux__)
    off_t input_offset = 0, output_offset = 0;
    bool kernel_copy = true;
    while (output_offset < st.st_size) {
        size_t want = st.st_size - output_offset < (off_t)(16 * 1024 * 1024)
            ? (size_t)(st.st_size - output_offset) : (size_t)(16 * 1024 * 1024);
        ssize_t copied = copy_file_range(s->bound_fd, &input_offset, fd,
                                         &output_offset, want, 0);
        if (copied < 0 && errno == EINTR) continue;
        if (copied <= 0) {
            kernel_copy = false;
            break;
        }
    }
    if (kernel_copy && output_offset == st.st_size) {
        if (ftruncate(fd, st.st_size) != 0)
            LOG_FAIL("codeindex", "truncate kernel-cloned generation");
        return true;
    }
    if (output_offset != 0)
        LOG_FAIL("codeindex", "partial kernel generation clone");
#endif
    unsigned char buf[1024 * 1024];
    off_t offset = 0;
    while (offset < st.st_size) {
        size_t want = (st.st_size - offset) < (off_t)sizeof(buf)
            ? (size_t)(st.st_size - offset) : sizeof(buf);
        ssize_t got = pread(s->bound_fd, buf, want, offset);
        if (got < 0 && errno == EINTR) continue;
        if (got <= 0)
            LOG_FAIL("codeindex", "read source generation for clone");
        size_t done = 0;
        while (done < (size_t)got) {
            ssize_t put = pwrite(fd, buf + done, (size_t)got - done,
                                 offset + (off_t)done);
            if (put < 0 && errno == EINTR) continue;
            if (put <= 0)
                LOG_FAIL("codeindex", "write staging generation clone");
            done += (size_t)put;
        }
        offset += got;
    }
    if (ftruncate(fd, st.st_size) != 0)
        LOG_FAIL("codeindex", "truncate staging generation clone");
    return true;
#endif
}

struct ci_store *ci_store_open_rw_fd(int fd)
{
#if defined(_WIN32)
    (void)fd;
    return NULL;
#else
    if (fd < 0) LOG_NULL("codeindex", "invalid staging fd");
    char fd_name[64], uri[128];
    if (!platform_fd_path(fd_name, sizeof(fd_name), fd, NULL) ||
        snprintf(uri, sizeof(uri), "file:%s?mode=rw", fd_name) <= 0)
        LOG_NULL("codeindex", "staging fd cannot be named");
    struct ci_store *s = zcl_calloc(1, sizeof(*s), "ci_store_staging");
    if (!s) LOG_NULL("codeindex", "allocate staging store");
    s->bound_fd = -1;
    platform_positioned_file_init(&s->bound_file);
    platform_read_mapping_init(&s->mapping);
    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&s->lock, &attr);
    pthread_mutexattr_destroy(&attr);
    int flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX | SQLITE_OPEN_URI;
    if (sqlite3_open_v2(uri, &s->db, flags, NULL) != SQLITE_OK) {
        if (s->db) sqlite3_close(s->db);
        pthread_mutex_destroy(&s->lock);
        free(s);
        return NULL;
    }
    char *err = NULL;
    if (sqlite3_exec(s->db,
                     "PRAGMA journal_mode=OFF; PRAGMA synchronous=OFF;",
                     NULL, NULL, &err) != SQLITE_OK) {
        if (err) sqlite3_free(err);
        ci_store_close(s);
        return NULL;
    }
    return s;
#endif
}

bool ci_store_write_image_child(struct ci_store *s,
                                struct platform_directory_child *child)
{
    if (!s || !child)
        LOG_FAIL("codeindex", "invalid store/image child");

    pthread_mutex_lock(&s->lock);
    sqlite3_int64 image_size = 0;
    unsigned char *image = sqlite3_serialize(s->db, "main", &image_size, 0);
    bool ok = image && image_size > 0 &&
              (uint64_t)image_size <= (uint64_t)SIZE_MAX &&
              platform_directory_child_truncate(child, 0);
    uint64_t offset = 0;
    while (ok && offset < (uint64_t)image_size) {
        uint64_t left = (uint64_t)image_size - offset;
        size_t chunk = left > UINT64_C(1048576)
            ? (size_t)UINT64_C(1048576) : (size_t)left;
        ok = platform_directory_child_write_exact(child, image + offset,
                                                  chunk, offset);
        offset += ok ? chunk : 0;
    }
    if (ok)
        ok = platform_directory_child_truncate(child,
                                                (uint64_t)image_size);
    if (image) sqlite3_free(image);
    pthread_mutex_unlock(&s->lock);
    if (!ok)
        LOG_FAIL("codeindex", "serialize staging image to retained child failed");
    return true;
}

void ci_store_close(struct ci_store *s)
{
    if (!s) return;
    if (s->db) sqlite3_close(s->db);
    platform_read_mapping_close(&s->mapping);
    if (s->has_bound_file)
        platform_positioned_file_close(&s->bound_file);
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
        " DELETE FROM refs; DELETE FROM groups; DELETE FROM scan_shards;"
        " DELETE FROM meta;",
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
