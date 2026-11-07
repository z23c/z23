/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: Persist and validate revisioned owner selections of exact app versions.
 */
#include "command/app_selection.h"
#include "base/serialize_le.h"
#include "models/activerecord.h"
#include "platform/directory_compat.h"
#include "util/sync.h"
#include <stdatomic.h>
#include "sha3/sha3.h"
#include <errno.h>
#include <stdio.h>
#include <string.h>
#if !defined(_WIN32)
#include <fcntl.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <unistd.h>
#endif

#define AS_DOMAIN "zcl.app_selection.v1"
#define AS_TAG 24u
#define AS_BODY (AS_TAG + 8u + 33u + 2u * APP_SELECTION_PATH_MAX + 8u * 32u)
#define AS_WIRE (AS_BODY + 32u)
static struct ar_callbacks as_callbacks;
static zcl_once_t as_callbacks_once = ZCL_ONCE_INIT;
static void as_callbacks_init(void) { ar_callbacks_init(&as_callbacks); }
struct ar_callbacks *db_app_selection_callbacks(void)
{
    return zcl_once_call(&as_callbacks_once, as_callbacks_init) ? &as_callbacks : NULL;
}
#if defined(ZCL_TESTING)
static void (*as_swap_hook)(const char *);
static bool as_fail_directory_sync;
void app_selection_test_swap_hook(void (*hook)(const char *)) { as_swap_hook = hook; }
void app_selection_test_fail_directory_sync(bool fail) { as_fail_directory_sync = fail; }
#endif

bool app_selection_route_reserved(const char *name)
{
    return name && strncmp(name, "kept:", 5) == 0;
}
bool app_selection_route_valid(const char *name)
{
    if (!app_selection_route_reserved(name)) return false;
    size_t n = strnlen(name, APP_SELECTION_ID_MAX + 1u);
    return n > 5 && n <= APP_SELECTION_ID_MAX && name[5] != '-' &&
        strspn(name + 5, "abcdefghijklmnopqrstuvwxyz0123456789-") == n - 5;
}
static bool as_id(const char *s)
{
    if (app_selection_route_reserved(s)) return app_selection_route_valid(s);
    size_t n = s ? strnlen(s, APP_SELECTION_ID_MAX + 1u) : 0;
    return n && n <= APP_SELECTION_ID_MAX &&
        strspn(s, "abcdefghijklmnopqrstuvwxyz0123456789-") == n;
}
/* '@' cannot occur in a legacy id; wire identities retain the full route. */
static void as_stem(const char *app, char stem[40])
{
    if (app_selection_route_reserved(app)) (void)snprintf(stem, 40, "@kept-%s", app + 5);
    else (void)snprintf(stem, 40, "%s", app);
}
static bool as_path(const char *s)
{
    size_t n = strnlen(s, APP_SELECTION_PATH_MAX);
    if (!n || n >= APP_SELECTION_PATH_MAX || s[0] != '/' || (n > 1 && s[n-1] == '/')) return false;
    for (size_t i = 0; i < n; ++i) if ((unsigned char)s[i] < 32 || s[i] == 127) return false;
    return !strstr(s, "//") && !strstr(s, "/./") && !strstr(s, "/../") &&
        !(n >= 2 && !strcmp(s + n - 2, "/.")) && !(n >= 3 && !strcmp(s + n - 3, "/.."));
}
static bool as_nonzero(const uint8_t root[32])
{
    for (size_t i = 0; i < 32; ++i) if (root[i]) return true;
    return false;
}
static bool as_valid(const struct app_selection *s, struct ar_errors *errors)
{
    ar_errors_clear(errors);
    validates_custom(errors, as_id(s->app), "app", "must be a canonical app id");
    validates_custom(errors, as_path(s->copy) && as_path(s->datadir), "path", "must be bounded absolute canonical paths");
    const uint8_t *roots[] = {s->fork, s->parent, s->version, s->package,
                              s->env, s->dependencies, s->record, s->image};
    for (size_t i = 0; i < 8; ++i)
        validates_custom(errors, as_nonzero(roots[i]), "root", "must be nonzero");
    validates_custom(errors, s->revision > 0, "revision", "must be positive");
    return !ar_errors_any(errors);
}
static bool as_canonical_dirs(const struct app_selection *s)
{
    char copy[APP_SELECTION_PATH_MAX], data[APP_SELECTION_PATH_MAX];
    return platform_directory_canonical_real(s->copy, copy, sizeof(copy)) &&
        platform_directory_canonical_real(s->datadir, data, sizeof(data)) &&
        !strcmp(copy, s->copy) && !strcmp(data, s->datadir);
}
static void as_hash(const uint8_t *wire, uint8_t out[32])
{
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)AS_DOMAIN, sizeof(AS_DOMAIN));
    sha3_256_write(&sha, wire, AS_BODY);
    sha3_256_finalize(&sha, out);
}
static void as_encode(const struct app_selection *s, uint8_t wire[AS_WIRE])
{
    memset(wire, 0, AS_WIRE);
    memcpy(wire, AS_DOMAIN, sizeof(AS_DOMAIN));
    uint8_t *p = wire + AS_TAG;
    zcl_write_u64_le(p, s->revision); p += 8;
    memcpy(p, s->app, strlen(s->app)); p += 33;
    memcpy(p, s->copy, strlen(s->copy)); p += APP_SELECTION_PATH_MAX;
    memcpy(p, s->datadir, strlen(s->datadir)); p += APP_SELECTION_PATH_MAX;
    const uint8_t *roots[] = {s->fork, s->parent, s->version, s->package,
                              s->env, s->dependencies, s->record, s->image};
    for (size_t i = 0; i < 8; ++i, p += 32) memcpy(p, roots[i], 32);
    as_hash(wire, wire + AS_BODY);
}
static bool as_decode(const uint8_t wire[AS_WIRE], struct app_selection *out)
{
    uint8_t hash[32], canonical[AS_WIRE];
    as_hash(wire, hash);
    if (memcmp(hash, wire + AS_BODY, 32)) return false;
    memset(out, 0, sizeof(*out));
    const uint8_t *p = wire + AS_TAG;
    out->revision = zcl_read_u64_le(p); p += 8;
    memcpy(out->app, p, 33); p += 33;
    memcpy(out->copy, p, APP_SELECTION_PATH_MAX); p += APP_SELECTION_PATH_MAX;
    memcpy(out->datadir, p, APP_SELECTION_PATH_MAX); p += APP_SELECTION_PATH_MAX;
    uint8_t *roots[] = {out->fork, out->parent, out->version, out->package,
                        out->env, out->dependencies, out->record, out->image};
    for (size_t i = 0; i < 8; ++i, p += 32) memcpy(roots[i], p, 32);
    struct ar_errors errors;
    if (!as_valid(out, &errors)) return false;
    as_encode(out, canonical);
    return memcmp(canonical, wire, AS_WIRE) == 0;
}
#if !defined(_WIN32)
static int as_directory(const char *dir)
{
    if (!dir || dir[0] != '/') { errno = EINVAL; return -1; }
    int fd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return -1;
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISDIR(st.st_mode) || st.st_uid != getuid() || (st.st_mode & 077) != 0) {
        close(fd); errno = EACCES; return -1;
    }
    return fd;
}
static enum app_selection_result as_read_fd(int dirfd, const char *app, struct app_selection *out)
{
    char name[64], stem[40]; as_stem(app, stem);
    (void)snprintf(name, sizeof(name), "%s.selection", stem);
    int fd = openat(dirfd, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return errno == ENOENT ? APP_SELECTION_ABSENT : APP_SELECTION_IO;
    struct stat st;
    if (fstat(fd, &st) != 0) { close(fd); return APP_SELECTION_IO; }
    if (!S_ISREG(st.st_mode) || st.st_uid != getuid() || (st.st_mode & 0777) != 0600 || st.st_size != AS_WIRE) {
        close(fd); return APP_SELECTION_INVALID;
    }
    uint8_t wire[AS_WIRE]; size_t at = 0;
    while (at < sizeof(wire)) {
        ssize_t got = read(fd, wire + at, sizeof(wire) - at);
        if (got < 0 && errno == EINTR) continue;
        if (got <= 0) { close(fd); return APP_SELECTION_IO; }
        at += (size_t)got;
    }
    if (close(fd) != 0) return APP_SELECTION_IO;
    if (!as_decode(wire, out) || strcmp(out->app, app)) return APP_SELECTION_INVALID;
    return APP_SELECTION_OK;
}
static bool as_sync(int fd)
{
    int rc;
    do { rc = fsync(fd); } while (rc < 0 && errno == EINTR);
    return rc == 0;
}
static bool as_write_all(int fd, const uint8_t *buf, size_t len)
{
    for (size_t at = 0; at < len;) {
        ssize_t n = write(fd, buf + at, len - at);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return false;
        at += (size_t)n;
    }
    return true;
}
static atomic_uint as_temp_counter;
static int as_temp_open(int dirfd, const char *app, char name[96])
{
    char stem[40]; as_stem(app, stem);
    for (unsigned i = 0; i < 32; ++i) {
        unsigned serial = atomic_fetch_add(&as_temp_counter, 1);
        (void)snprintf(name, 96, ".%s.sel.%ld.%u", stem, (long)getpid(), serial);
        int fd = openat(dirfd, name, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
        if (fd >= 0 || errno != EEXIST) return fd;
    }
    return -1;
}
/* All names, including the temp and destination, are resolved relative to
 * the retained and verified directory used for locking and the CAS read. */
static bool as_publish(int dirfd, const struct app_selection *s)
{
    char name[64], temp[96], stem[40]; uint8_t wire[AS_WIRE];
    as_stem(s->app, stem);
    (void)snprintf(name, sizeof(name), "%s.selection", stem);
    as_encode(s, wire);
    int fd = as_temp_open(dirfd, s->app, temp);
    if (fd < 0) return false;
    bool ok = as_write_all(fd, wire, sizeof(wire)) && as_sync(fd);
    if (close(fd) != 0) ok = false;
    if (ok) ok = renameat(dirfd, temp, dirfd, name) == 0;
    if (!ok) { (void)unlinkat(dirfd, temp, 0); return false; }
#if defined(ZCL_TESTING)
    if (as_fail_directory_sync) { errno = EIO; return false; }
#endif
    return as_sync(dirfd);
}
static bool as_write(int dirfd, const struct app_selection *s)
{
    struct ar_callbacks *cbs = db_app_selection_callbacks();
    if (!cbs) return false;
    AR_BEGIN_SAVE(cbs, "app_selection", s, as_valid);
    bool ok = as_publish(dirfd, s);
    AR_FINISH_SAVE(cbs, s, ok);
}
/* A replaced pathname is not the directory whose lock and record we hold. */
static bool as_directory_current(const char *dir, int retained)
{
    struct stat before, after;
    int fresh = as_directory(dir);
    if (fresh < 0) return false;
    bool ok = fstat(retained, &before) == 0 && fstat(fresh, &after) == 0 &&
              before.st_dev == after.st_dev && before.st_ino == after.st_ino;
    close(fresh);
    return ok;
}
static int as_lock(int dirfd, const char *app)
{
    char name[64], stem[40]; as_stem(app, stem);
    (void)snprintf(name, sizeof(name), "%s.selection.lock", stem);
    int fd = openat(dirfd, name, O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) return -1;
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_uid != getuid() || (st.st_mode & 0777) != 0600) {
        close(fd); errno = EACCES; return -1;
    }
    int rc;
    do { rc = flock(fd, LOCK_EX); } while (rc < 0 && errno == EINTR);
    if (rc != 0) { close(fd); return -1; }
    return fd;
}

static enum app_selection_result as_route_add(int dirfd, const char *file,
    struct app_selection_routes *routes)
{
    size_t len = strlen(file);
    if (strncmp(file, "@kept-", 6) || len < 16 || strcmp(file + len - 10, ".selection"))
        return APP_SELECTION_OK;
    size_t id_len = len - 16;
    if (!id_len || id_len > APP_SELECTION_ID_MAX - 5 || routes->count == APP_SELECTION_ROUTES_MAX)
        return APP_SELECTION_INVALID;
    char route[APP_SELECTION_ID_MAX + 1u];
    (void)snprintf(route, sizeof(route), "kept:%.*s", (int)id_len, file + 6);
    if (!app_selection_route_valid(route)) return APP_SELECTION_INVALID;
    struct app_selection selection;
    enum app_selection_result result = as_read_fd(dirfd, route, &selection);
    if (result != APP_SELECTION_OK) return result == APP_SELECTION_ABSENT ? APP_SELECTION_IO : result;
    size_t at = routes->count;
    while (at && strcmp(routes->names[at - 1], route) > 0) {
        memcpy(routes->names[at], routes->names[at - 1], sizeof(routes->names[0]));
        --at;
    }
    (void)snprintf(routes->names[at], sizeof(routes->names[at]), "%s", route);
    ++routes->count;
    return APP_SELECTION_OK;
}
static enum app_selection_result as_routes_read(DIR *directory, struct app_selection_routes *routes)
{
    for (size_t scanned = 0; scanned < 4096; ++scanned) {
        errno = 0;
        struct dirent *entry = readdir(directory);
        if (!entry) return errno ? APP_SELECTION_IO : APP_SELECTION_OK;
        enum app_selection_result result = as_route_add(dirfd(directory), entry->d_name, routes);
        if (result != APP_SELECTION_OK) return result;
    }
    return APP_SELECTION_INVALID; /* Explicit scan bound, never a partial list. */
}

static enum app_selection_result as_locked_save(const char *dir, int dirfd,
    uint64_t expected, const struct app_selection *next, struct app_selection *out)
{
    int lockfd = as_lock(dirfd, next->app);
    if (lockfd < 0) return APP_SELECTION_IO;
#if defined(ZCL_TESTING)
    if (as_swap_hook) as_swap_hook(dir);
#endif
    struct app_selection current;
    enum app_selection_result result = as_read_fd(dirfd, next->app, &current);
    if ((result == APP_SELECTION_ABSENT && expected != 0) ||
        (result == APP_SELECTION_OK && current.revision != expected)) result = APP_SELECTION_STALE;
    else if (result == APP_SELECTION_ABSENT || result == APP_SELECTION_OK) {
        bool published = as_directory_current(dir, dirfd) && as_write(dirfd, next);
        result = published && as_directory_current(dir, dirfd) ? APP_SELECTION_OK : APP_SELECTION_IO;
        if (result == APP_SELECTION_OK) *out = *next;
    }
    close(lockfd);
    return result;
}

#endif

enum app_selection_result app_selection_routes_load(const char *dir, struct app_selection_routes *out)
{
    if (!out) return APP_SELECTION_INVALID;
    memset(out, 0, sizeof(*out));
#if defined(_WIN32)
    (void)dir;
    return APP_SELECTION_OK; /* No selection persistence on this platform. */
#else
    int fd = as_directory(dir);
    if (fd < 0) return errno == ENOENT ? APP_SELECTION_OK : APP_SELECTION_IO;
    DIR *directory = fdopendir(fd);
    if (!directory) { close(fd); return APP_SELECTION_IO; }
    struct app_selection_routes routes = {0};
    enum app_selection_result result = as_routes_read(directory, &routes);
    if (!as_directory_current(dir, fd)) result = APP_SELECTION_IO;
    if (closedir(directory) != 0) result = APP_SELECTION_IO;
    if (result == APP_SELECTION_OK) *out = routes;
    return result;
#endif
}

enum app_selection_result app_selection_load(const char *dir, const char *app,
                                              struct app_selection *out)
{
    if (!as_id(app) || !out) return APP_SELECTION_INVALID;
    memset(out, 0, sizeof(*out));
#if defined(_WIN32)
    (void)dir;
    return APP_SELECTION_IO;
#else
    int fd = as_directory(dir);
    if (fd < 0) return errno == ENOENT ? APP_SELECTION_ABSENT : APP_SELECTION_IO;
    enum app_selection_result result = as_read_fd(fd, app, out);
    close(fd);
    return result;
#endif
}

enum app_selection_result app_selection_save(const char *dir, uint64_t expected,
    const struct app_selection *selection, struct app_selection *out)
{
    if (!selection || !out || !as_id(selection->app) || expected == UINT64_MAX)
        return APP_SELECTION_INVALID;
#if defined(_WIN32)
    (void)dir;
    return APP_SELECTION_IO;
#else
    struct app_selection next = *selection;
    next.revision = expected + 1;
    struct ar_errors errors;
    if (!as_valid(&next, &errors) || !as_canonical_dirs(&next)) return APP_SELECTION_INVALID;
    int dirfd = as_directory(dir);
    if (dirfd < 0) return APP_SELECTION_IO;
    enum app_selection_result result = as_locked_save(dir, dirfd, expected, &next, out);
    close(dirfd);
    return result;
#endif
}
