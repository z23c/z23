/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Resident DEV_RESTART builder. Make freezes the compiler/link action once;
 * the watcher compiles only changed C translation units, substitutes their
 * objects ahead of one generation-frozen relocatable base, links directly, and
 * executes one bounded command-runtime probe. The same owner then links an
 * exact-source test candidate and runs the complete affected proof set cold,
 * without accepting cached verdicts. It never starts Make or a shell and
 * never publishes to a service, datadir, wallet, or release path.
 */

#define _GNU_SOURCE
#include "devloop.h"
#include "devloop_early.h"
#include "test_group_catalog.h"

#include "base/checked.h"
#include "base/hex.h"
#include "crypto/sha256.h"
#include "json/json.h"
#include "platform/directory_compat.h"
#include "platform/directory_transaction.h"
#include "platform/positioned_file.h"
#include "platform/private_directory.h"
#include "platform/process_lock.h"
#include "platform/time_compat.h"
#include "util/safe_alloc.h"
#include "util/spawn.h"
#include "util/thread_registry.h"

#include <errno.h>
#include <ctype.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#if defined(_WIN32)
#include <io.h>
#include <windows.h>
#endif

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define RR_TEXT_MAX 16384
#define RR_ARG_MAX 512
#define RR_SOURCE_MAX 32
#define RR_OVERLAY_MAX (RR_SOURCE_MAX + 1)
#define RR_EXACT_GROUP_MAX 128
/* Finite aggregate proof budget, distinct from the runner's per-group
 * silence watchdog. A valid closure can include a group weighted at 312
 * seconds (vcs_devloop) and over a hundred groups; 300 seconds can reject a
 * valid closure before that group's expected duration. Preserve full selection
 * and accounting; the weight is not an observed completed runtime. */
#if defined(__APPLE__)
/* On the admitted 16 GiB Darwin host, a cold scale group took 966 seconds
 * and a 57-group proof with one cache hit took 991 seconds. Their sum is a
 * cold-path estimate, not a completed cold proof. Allow finite headroom for
 * that closure; the runner's silence watchdog and full accounting still apply. */
#define RR_PROOF_TIMEOUT_MS 3600000
#else
#define RR_PROOF_TIMEOUT_MS 900000
#endif
#define RR_IMMEDIATE_GROUP_MAX 32
#define RR_DEP_MAX 256
#define RR_DEP_PATH 512

struct rr_plan {
    char root[PATH_MAX];
    char cc[512];
    char compiler_id[65];
    char base_generation[65];
    char cflags[RR_TEXT_MAX];
    char ldflags[4096];
    char libs[4096];
    char obj_dir[PATH_MAX];
    char link_rsp[PATH_MAX];
    char base_reloc[PATH_MAX];
    char test_cflags[RR_TEXT_MAX];
    char test_ldflags[4096];
    char test_libs[4096];
    char test_obj_dir[PATH_MAX];
    char test_link_rsp[PATH_MAX];
    char test_base_reloc[PATH_MAX];
#if defined(_WIN32)
    struct platform_positioned_file_snapshot stamp;
#else
    struct stat stamp;
#endif
    bool loaded;
};

struct rr_overlay {
    char source[ZCL_DEVLOOP_PATH_MAX];
    char base_object[PATH_MAX];
    char overlay_object[PATH_MAX];
    char source_sha256[65];
};

static pthread_mutex_t g_rr_mu = PTHREAD_MUTEX_INITIALIZER;
static struct rr_plan g_rr_plan;

/* One warm watcher owns this process. Remember the last affected RED in
 * memory so the next edit in the same checkout runs that exact group before
 * catalog/default owner order. This is scheduling evidence only: no test is
 * removed, cached as proof, or persisted across watcher generations. */
struct rr_failure_priority {
    char root[PATH_MAX];
    char group[ZCL_TEST_GROUP_FULL_MAX];
    bool present;
};

static struct rr_failure_priority g_rr_failure_priority;

static bool rr_bytes_contain(const unsigned char *data, size_t data_len,
                             const char *needle)
{
    size_t needle_len = needle ? strlen(needle) : 0;
    if (!data || needle_len == 0 || needle_len > data_len)
        return false;
    for (size_t i = 0; i <= data_len - needle_len; i++)
        if (memcmp(data + i, needle, needle_len) == 0)
            return true;
    return false;
}

#if defined(_WIN32)
static atomic_uint_fast64_t g_rr_temp_nonce = 1;

static bool rr_parent_leaf(const char *path, char parent[PATH_MAX],
                           char leaf[PLATFORM_DIRECTORY_CHILD_LEAF_MAX + 1u])
{
    if (!path || !path[0] || strlen(path) >= PATH_MAX)
        return false;
    const char *slash = strrchr(path, '/');
    const char *backslash = strrchr(path, '\\');
    if (!slash || (backslash && backslash > slash)) slash = backslash;
    if (!slash || slash == path || !slash[1] ||
        strlen(slash + 1) > PLATFORM_DIRECTORY_CHILD_LEAF_MAX)
        return false;
    size_t parent_len = (size_t)(slash - path);
    memcpy(parent, path, parent_len);
    parent[parent_len] = 0;
    (void)snprintf(leaf, PLATFORM_DIRECTORY_CHILD_LEAF_MAX + 1u, "%s",
                   slash + 1);
    return true;
}

static bool rr_create_temp_child(
    struct platform_directory_transaction *directory, const char *suffix,
    struct platform_directory_child *child,
    char leaf[PLATFORM_DIRECTORY_CHILD_LEAF_MAX + 1u])
{
    for (unsigned int attempt = 0; attempt < 64; attempt++) {
        uint64_t nonce = atomic_fetch_add_explicit(
            &g_rr_temp_nonce, 1, memory_order_relaxed);
        int n = snprintf(leaf, PLATFORM_DIRECTORY_CHILD_LEAF_MAX + 1u,
                         ".restart-%016llx-%02x%s",
                         (unsigned long long)nonce, attempt,
                         suffix ? suffix : "");
        if (n <= 0 || n > (int)PLATFORM_DIRECTORY_CHILD_LEAF_MAX)
            return false;
        platform_directory_child_init(child);
        if (platform_directory_child_create(directory, leaf, child))
            return true;
        platform_directory_child_close(child);
    }
    return false;
}
#endif

static void rr_why(char *why, size_t why_len, const char *message)
{
    if (why && why_len)
        (void)snprintf(why, why_len, "%s", message ? message : "unknown");
}

#if defined(_WIN32)
typedef struct platform_positioned_file_snapshot rr_file_stamp;
#else
typedef struct stat rr_file_stamp;
#endif

static bool rr_regular(const char *path, rr_file_stamp *out)
{
#if defined(_WIN32)
    struct platform_positioned_file file;
    struct platform_positioned_file_snapshot snapshot;
    platform_positioned_file_init(&file);
    bool ok = path && platform_positioned_file_open(&file, path) &&
              platform_positioned_file_snapshot(&file, &snapshot);
    platform_positioned_file_close(&file);
    if (ok && out) *out = snapshot;
    return ok;
#else
    struct stat st;
    if (!path || lstat(path, &st) != 0 || !S_ISREG(st.st_mode) ||
        S_ISLNK(st.st_mode))
        return false;
    if (out) *out = st;
    return true;
#endif
}

static bool rr_directory(const char *path)
{
#if defined(_WIN32)
    return path && platform_directory_probe_real(path) ==
                       PLATFORM_DIRECTORY_PROBE_OK;
#else
    struct stat st;
    return path && lstat(path, &st) == 0 && S_ISDIR(st.st_mode) &&
           !S_ISLNK(st.st_mode);
#endif
}

#if defined(_WIN32)
static char *rr_mkdirs_win32_scan_start(char *copy)
{
    if (((copy[0] >= 'A' && copy[0] <= 'Z') ||
         (copy[0] >= 'a' && copy[0] <= 'z')) && copy[1] == ':' &&
        copy[2] == '/')
        return copy + 3;
    if (copy[0] == '/')
        return copy + 1;
    return NULL;
}

static bool rr_mkdirs_win32_walk(char *copy, char *scan)
{
    for (char *p = scan; *p; p++) {
        if (*p != '/') continue;
        *p = 0;
        enum platform_directory_probe_result probe =
            platform_directory_probe_real(copy);
        if (probe == PLATFORM_DIRECTORY_PROBE_MISSING) {
            if (!platform_private_directory_ensure(copy)) return false;
        } else if (probe != PLATFORM_DIRECTORY_PROBE_OK) {
            return false;
        }
        *p = '/';
    }
    return true;
}

static bool rr_mkdirs_win32_finish(const char *copy)
{
    enum platform_directory_probe_result probe =
        platform_directory_probe_real(copy);
    return probe == PLATFORM_DIRECTORY_PROBE_OK ||
           (probe == PLATFORM_DIRECTORY_PROBE_MISSING &&
            platform_private_directory_ensure(copy));
}

static bool rr_mkdirs_win32(const char *path)
{
    char copy[PATH_MAX];
    if (!path || !path[0] || strlen(path) >= sizeof(copy))
        return false;
    (void)snprintf(copy, sizeof(copy), "%s", path);
    for (char *p = copy; *p; p++)
        if (*p == '\\') *p = '/';
    char *scan = rr_mkdirs_win32_scan_start(copy);
    if (!scan) return false;
    if (!rr_mkdirs_win32_walk(copy, scan)) return false;
    return rr_mkdirs_win32_finish(copy);
}
#else
static bool rr_mkdirs_posix(const char *path)
{
    char copy[PATH_MAX];
    struct stat st;
    if (!path || path[0] != '/' || strlen(path) >= sizeof(copy))
        return false;
    (void)snprintf(copy, sizeof(copy), "%s", path);
    for (char *p = copy + 1; *p; p++) {
        if (*p != '/') continue;
        *p = 0;
        if (mkdir(copy, 0700) != 0 &&
            (errno != EEXIST || lstat(copy, &st) != 0 ||
             !S_ISDIR(st.st_mode) || S_ISLNK(st.st_mode)))
            return false;
        *p = '/';
    }
    return mkdir(copy, 0700) == 0 ||
           (errno == EEXIST && lstat(copy, &st) == 0 &&
            S_ISDIR(st.st_mode) && !S_ISLNK(st.st_mode));
}
#endif

static bool rr_mkdirs(const char *path)
{
#if defined(_WIN32)
    return rr_mkdirs_win32(path);
#else
    return rr_mkdirs_posix(path);
#endif
}

static bool rr_dep_chars_ok(const char *path)
{
    if (!path || !path[0] || strstr(path, "..") || strchr(path, '\\'))
        return false;
    for (const unsigned char *p = (const unsigned char *)path; *p; p++)
        if (*p < 0x20)
            return false;
    return true;
}

static bool rr_safe_relative(const char *path)
{
    return rr_dep_chars_ok(path) && path[0] != '/';
}

/* An absolute compiler-listed file, such as gcc's implicit
 * /usr/include/stdc-predef.h. The path is hashed where the compiler wrote
 * it. A trailing slash, an empty path, traversal, or a backslash stays out. */
static bool rr_safe_absolute(const char *path)
{
    size_t n;
    if (!rr_dep_chars_ok(path) || path[0] != '/')
        return false;
    n = strlen(path);
    return n > 1 && path[n - 1] != '/';
}

static bool rr_dep_path_ok(const char *path)
{
    return rr_safe_relative(path) || rr_safe_absolute(path);
}

static bool rr_hex64(const char *value)
{
    if (!value || strlen(value) != 64) return false;
    for (size_t i = 0; i < 64; i++)
        if (!((value[i] >= '0' && value[i] <= '9') ||
              (value[i] >= 'a' && value[i] <= 'f')))
            return false;
    return true;
}

static bool rr_line(char *dst, size_t cap, const char *line,
                    const char *prefix)
{
    size_t prefix_len = strlen(prefix);
    if (strncmp(line, prefix, prefix_len) != 0)
        return false;
    const char *value = line + prefix_len;
    size_t len = strcspn(value, "\r\n");
    if (len == 0 || len >= cap)
        return false;
    memcpy(dst, value, len);
    dst[len] = 0;
    return true;
}

static bool rr_join_root(const char *root, const char *rel,
                         char out[PATH_MAX])
{
    return rr_safe_relative(rel) &&
           snprintf(out, PATH_MAX, "%s/%s", root, rel) < PATH_MAX;
}

/* Resolve one compiler-listed dependency to the file whose bytes enter the
 * object key. A tree-relative path stays under root. An absolute path is
 * the compiler's own path and must already be a regular file. */
static bool rr_dep_resolve(const char *root, const char *dep,
                           char out[PATH_MAX])
{
    size_t n;
    if (dep && dep[0] == '/') {
        if (!rr_safe_absolute(dep))
            return false;
        n = strlen(dep);
        if (n >= PATH_MAX || !rr_regular(dep, NULL))
            return false;
        memcpy(out, dep, n + 1);
        return true;
    }
    return rr_join_root(root, dep, out);
}

static bool rr_stat_equal(const rr_file_stamp *a, const rr_file_stamp *b)
{
#if defined(_WIN32)
    return platform_positioned_file_snapshot_equal(a, b);
#else
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino &&
           a->st_size == b->st_size &&
           a->st_mtim.tv_sec == b->st_mtim.tv_sec &&
           a->st_mtim.tv_nsec == b->st_mtim.tv_nsec;
#endif
}

static bool rr_stamp_newer(const rr_file_stamp *left,
                           const rr_file_stamp *right)
{
#if defined(_WIN32)
    return left->modified_seconds > right->modified_seconds ||
           (left->modified_seconds == right->modified_seconds &&
            left->modified_nanoseconds > right->modified_nanoseconds);
#else
    return left->st_mtim.tv_sec > right->st_mtim.tv_sec ||
           (left->st_mtim.tv_sec == right->st_mtim.tv_sec &&
            left->st_mtim.tv_nsec > right->st_mtim.tv_nsec);
#endif
}

static bool rr_stamp_size(const rr_file_stamp *stamp, uint64_t *size)
{
#if defined(_WIN32)
    if (!stamp || !size) return false;
    *size = stamp->size;
    return true;
#else
    if (!stamp || !size || stamp->st_size < 0) return false;
    *size = (uint64_t)stamp->st_size;
    return true;
#endif
}

static bool rr_flush_stream(FILE *stream)
{
    if (!stream || fflush(stream) != 0) return false;
#if defined(_WIN32)
    intptr_t handle = _get_osfhandle(_fileno(stream));
    return handle != -1 && FlushFileBuffers((HANDLE)handle) != 0;
#else
    return fsync(fileno(stream)) == 0;
#endif
}

static bool rr_plan_load_locked_paths(const char *root, char path[PATH_MAX],
                                      char makefile[PATH_MAX], char *why,
                                      size_t why_len)
{
    if (snprintf(path, PATH_MAX, "%s/build/dev-loop/restart.env", root) >=
            PATH_MAX ||
        snprintf(makefile, PATH_MAX, "%s/Makefile", root) >= PATH_MAX) {
        rr_why(why, why_len, "restart action-plan path overflow");
        return false;
    }
    return true;
}

static bool rr_plan_load_locked_check_stamps(const char *path,
                                             const char *makefile,
                                             rr_file_stamp *stamp, char *why,
                                             size_t why_len)
{
    rr_file_stamp make_st;
    if (!rr_regular(path, stamp) || !rr_regular(makefile, &make_st)) {
        rr_why(why, why_len,
               "restart action plan absent; run make dev-bin once");
        return false;
    }
    if (rr_stamp_newer(&make_st, stamp)) {
        rr_why(why, why_len,
               "restart action plan stale after build-system change");
        return false;
    }
    return true;
}

static bool rr_plan_load_locked_from_cache(const char *root,
                                           const rr_file_stamp *stamp,
                                           struct rr_plan *out,
                                           bool *cache_hit,
                                           int64_t *elapsed_us,
                                           int64_t started)
{
    if (g_rr_plan.loaded && strcmp(g_rr_plan.root, root) == 0 &&
        rr_stat_equal(&g_rr_plan.stamp, stamp)) {
        *out = g_rr_plan;
        *cache_hit = true;
        *elapsed_us = platform_time_monotonic_us() - started;
        return true;
    }
    return false;
}

/* Table-driven match for each "KEY=value" line, so the parse loop is a loop
 * over data rather than a long if/else-if chain. */
static const struct {
    size_t offset;
    size_t cap;
    const char *prefix;
} k_rr_plan_fields[] = {
    {offsetof(struct rr_plan, cc), 512, "CC="},
    {offsetof(struct rr_plan, compiler_id), 65, "COMPILER_ID="},
    {offsetof(struct rr_plan, base_generation), 65, "BASE_GENERATION="},
    {offsetof(struct rr_plan, cflags), RR_TEXT_MAX, "DEV_CFLAGS="},
    {offsetof(struct rr_plan, ldflags), 4096, "DEV_LDFLAGS="},
    {offsetof(struct rr_plan, libs), 4096, "DEV_LIBS="},
    {offsetof(struct rr_plan, obj_dir), PATH_MAX, "DEV_OBJ_DIR="},
    {offsetof(struct rr_plan, link_rsp), PATH_MAX, "DEV_LINK_RSP="},
    {offsetof(struct rr_plan, base_reloc), PATH_MAX, "DEV_BASE_RELOC="},
    {offsetof(struct rr_plan, test_cflags), RR_TEXT_MAX, "TEST_CFLAGS="},
    {offsetof(struct rr_plan, test_ldflags), 4096, "TEST_LDFLAGS="},
    {offsetof(struct rr_plan, test_libs), 4096, "TEST_LIBS="},
    {offsetof(struct rr_plan, test_obj_dir), PATH_MAX, "TEST_OBJ_DIR="},
    {offsetof(struct rr_plan, test_link_rsp), PATH_MAX, "TEST_LINK_RSP="},
    {offsetof(struct rr_plan, test_base_reloc), PATH_MAX,
     "TEST_BASE_RELOC="},
};

static bool rr_plan_load_locked_apply_field(struct rr_plan *next,
                                            const char *line)
{
    for (size_t i = 0; i < sizeof(k_rr_plan_fields) / sizeof(k_rr_plan_fields[0]);
         i++) {
        char *dest = (char *)next + k_rr_plan_fields[i].offset;
        if (rr_line(dest, k_rr_plan_fields[i].cap, line,
                    k_rr_plan_fields[i].prefix))
            return true;
    }
    return false;
}

/* Read one physical record, including bytes hidden after a NUL or '#'.
 * The caller supplies a buffer with room for a record and its terminator. */
static int rr_plan_record(FILE *f, char *line, size_t cap)
{
    size_t n = 0;
    int c, previous = 0;
    bool malformed = false;
    while ((c = fgetc(f)) != EOF) {
        if (c == 0) malformed = true;
        if (c == '\n') break;
        if (previous == '\r') malformed = true;
        previous = c;
        if (n < cap - 1) line[n++] = (char)c;
        else malformed = true;
    }
    line[n] = 0;
    if (ferror(f) || malformed) return -1;
    if (n == 0 && c == EOF) return 0;
    /* A CR is a terminator only at the end of the measured record. */
    if (n && line[n - 1] == '\r') line[--n] = 0;
    return 1;
}

static bool rr_plan_load_locked_parse(const char *path, struct rr_plan *next,
                                      bool *read_error, char *why,
                                      size_t why_len)
{
    *read_error = false;
    FILE *f = fopen(path, "rb");
    if (!f) {
        rr_why(why, why_len, "restart action plan could not be opened");
        return false;
    }
    char line[RR_TEXT_MAX + 32];
    int status;
    while ((status = rr_plan_record(f, line, sizeof(line))) > 0) {
        if (line[0] == '#' || line[0] == 0)
            continue;
        if (rr_plan_load_locked_apply_field(next, line))
            continue;
        fclose(f);
        rr_why(why, why_len, "restart action plan has an unknown field");
        return false;
    }
    *read_error = ferror(f) != 0;
    fclose(f);
    if (status < 0) {
        rr_why(why, why_len, "restart action plan has a malformed record");
        return false;
    }
    return true;
}

static bool rr_plan_load_locked_verify_stable(const char *path,
                                              const rr_file_stamp *stamp,
                                              char *why, size_t why_len)
{
    rr_file_stamp stable_stamp;
    if (!rr_regular(path, &stable_stamp) ||
        !rr_stat_equal(stamp, &stable_stamp)) {
        rr_why(why, why_len,
               "restart action plan changed while it was being read");
        return false;
    }
    return true;
}

static bool rr_plan_load_locked_validate_dev(const char *root,
                                             struct rr_plan *next)
{
    char obj_full[PATH_MAX], rsp_full[PATH_MAX], base_reloc_full[PATH_MAX];
    return next->cc[0] && rr_hex64(next->compiler_id) &&
           rr_hex64(next->base_generation) && next->cflags[0] &&
           next->ldflags[0] && next->libs[0] &&
           rr_join_root(root, next->obj_dir, obj_full) &&
           rr_join_root(root, next->link_rsp, rsp_full) &&
           rr_join_root(root, next->base_reloc, base_reloc_full) &&
           rr_directory(obj_full) && rr_regular(rsp_full, NULL) &&
           rr_regular(base_reloc_full, NULL) &&
           strstr(next->cflags, "-DZCL_DEV_BUILD");
}

static bool rr_plan_load_locked_validate_test(const char *root,
                                              struct rr_plan *next)
{
    char test_obj_full[PATH_MAX], test_rsp_full[PATH_MAX];
    char test_base_reloc_full[PATH_MAX];
    return next->test_cflags[0] && next->test_ldflags[0] &&
           next->test_libs[0] &&
           rr_join_root(root, next->test_obj_dir, test_obj_full) &&
           rr_join_root(root, next->test_link_rsp, test_rsp_full) &&
           rr_join_root(root, next->test_base_reloc, test_base_reloc_full) &&
           rr_directory(test_obj_full) && rr_regular(test_rsp_full, NULL) &&
           rr_regular(test_base_reloc_full, NULL) &&
           strstr(next->test_cflags, "-DZCL_TESTING");
}

static bool rr_plan_load_locked_validate(const char *root,
                                         struct rr_plan *next,
                                         bool read_error, char *why,
                                         size_t why_len)
{
    if (read_error || !rr_plan_load_locked_validate_dev(root, next) ||
        !rr_plan_load_locked_validate_test(root, next)) {
        rr_why(why, why_len,
               "restart action plan incomplete or its object graph is absent");
        return false;
    }
    return true;
}

static bool rr_plan_load_locked_check_lto(struct rr_plan *next, char *why,
                                          size_t why_len)
{
    if (strstr(next->cflags, "-flto") || strstr(next->ldflags, "-flto") ||
        strstr(next->cflags, "-fuse-linker-plugin") ||
        strstr(next->ldflags, "-fuse-linker-plugin") ||
        strstr(next->test_cflags, "-flto") ||
        strstr(next->test_ldflags, "-flto") ||
        strstr(next->test_cflags, "-fuse-linker-plugin") ||
        strstr(next->test_ldflags, "-fuse-linker-plugin")) {
        rr_why(why, why_len,
               "restart action plan contains release-only LTO flags");
        return false;
    }
    return true;
}

static bool rr_plan_load_locked(const char *root, struct rr_plan *out,
                                bool *cache_hit, int64_t *elapsed_us,
                                char *why, size_t why_len)
{
    int64_t started = platform_time_monotonic_us();
    char path[PATH_MAX], makefile[PATH_MAX];
    if (!rr_plan_load_locked_paths(root, path, makefile, why, why_len))
        return false;
    rr_file_stamp stamp;
    if (!rr_plan_load_locked_check_stamps(path, makefile, &stamp, why,
                                          why_len))
        return false;
    if (rr_plan_load_locked_from_cache(root, &stamp, out, cache_hit,
                                       elapsed_us, started))
        return true;
    struct rr_plan next = {0};
    bool read_error = false;
    if (!rr_plan_load_locked_parse(path, &next, &read_error, why, why_len))
        return false;
    if (!rr_plan_load_locked_verify_stable(path, &stamp, why, why_len))
        return false;
    if (!rr_plan_load_locked_validate(root, &next, read_error, why, why_len))
        return false;
    if (!rr_plan_load_locked_check_lto(&next, why, why_len))
        return false;
    (void)snprintf(next.root, sizeof(next.root), "%s", root);
    next.stamp = stamp;
    next.loaded = true;
    g_rr_plan = next;
    *out = next;
    *cache_hit = false;
    *elapsed_us = platform_time_monotonic_us() - started;
    return true;
}

static bool rr_sha256_file(const char *path, char out[65])
{
    FILE *f = fopen(path, "rb");
    if (!f) return false;
    struct sha256_ctx sha;
    unsigned char digest[SHA256_OUTPUT_SIZE], buf[65536];
    sha256_init(&sha);
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0)
        sha256_write(&sha, buf, n);
    bool ok = ferror(f) == 0;
    fclose(f);
    if (!ok) return false;
    sha256_finalize(&sha, digest);
    zcl_hex_encode(digest, sizeof(digest), out);
    return true;
}

static void rr_sha256_bytes(const void *data, size_t len, char out[65])
{
    struct sha256_ctx sha;
    unsigned char digest[SHA256_OUTPUT_SIZE];
    sha256_init(&sha);
    sha256_write(&sha, data, len);
    sha256_finalize(&sha, digest);
    zcl_hex_encode(digest, sizeof(digest), out);
}

static void rr_key_field(struct sha256_ctx *ctx, const char *label,
                         const void *data, size_t len)
{
    uint64_t n = (uint64_t)len;
    sha256_write(ctx, (const unsigned char *)label, strlen(label) + 1);
    sha256_write(ctx, (const unsigned char *)&n, sizeof(n));
    if (len)
        sha256_write(ctx, data, len);
}

static bool rr_normalize_root(const char *text, const char *root,
                              char *out, size_t out_len)
{
    static const char marker[] = "${WORKTREE}";
    size_t root_len = strlen(root), used = 0;
    const char *cursor = text;
    while (*cursor) {
        const char *match = strstr(cursor, root);
        size_t chunk = match ? (size_t)(match - cursor) : strlen(cursor);
        if (chunk >= out_len - used)
            return false;
        memcpy(out + used, cursor, chunk);
        used += chunk;
        if (!match)
            break;
        if (sizeof(marker) - 1 >= out_len - used)
            return false;
        memcpy(out + used, marker, sizeof(marker) - 1);
        used += sizeof(marker) - 1;
        cursor = match + root_len;
    }
    out[used] = 0;
    return true;
}

static bool rr_cache_root(char out[PATH_MAX])
{
    const char *configured = getenv("ZCL_DEV_ARTIFACT_CACHE");
    const char *home = getenv("HOME");
    int n;
    if (configured && configured[0] == '/') {
        n = snprintf(out, PATH_MAX, "%s/restart-v1", configured);
    } else {
        if (!home || home[0] != '/')
            return false;
        n = snprintf(out, PATH_MAX,
                     "%s/.cache/zclassic23/dev-artifacts/restart-v1", home);
    }
    return n > 0 && n < PATH_MAX && rr_mkdirs(out);
}

static bool rr_cache_key_normalize(const struct rr_plan *plan,
                                   const char *root,
                                   char cc[], size_t cc_cap,
                                   char cflags[], size_t cflags_cap,
                                   char ldflags[], size_t ldflags_cap,
                                   char libs[], size_t libs_cap)
{
    return rr_normalize_root(plan->cc, root, cc, cc_cap) &&
           rr_normalize_root(plan->cflags, root, cflags, cflags_cap) &&
           rr_normalize_root(plan->ldflags, root, ldflags, ldflags_cap) &&
           rr_normalize_root(plan->libs, root, libs, libs_cap);
}

static bool rr_cache_key_base_reloc(const struct rr_plan *plan,
                                    const char *root, char hash_out[65])
{
    char full[PATH_MAX];
    return rr_join_root(root, plan->base_reloc, full) &&
           rr_regular(full, NULL) &&
           rr_sha256_file(full, hash_out);
}

/* A token ends at whitespace or clean EOF; no shortened token is usable. */
static int rr_response_token(FILE *f, char token[4096], size_t *length)
{
    *length = 0;
    token[0] = 0;
    int c;
    do {
        c = fgetc(f);
    } while (c != EOF && isspace((unsigned char)c));
    while (c != EOF && !isspace((unsigned char)c)) {
        if (c == 0 || *length == 4095) {
            fprintf(stderr, "restart response: NUL or oversized token\n");
            token[0] = 0;
            return -1;
        }
        token[(*length)++] = (char)c;
        c = fgetc(f);
    }
    token[*length] = 0;
    if (ferror(f)) {
        fprintf(stderr, "restart response: input read failed\n");
        return -1;
    }
    return *length ? 1 : 0;
}

static bool rr_cache_key_scan_inputs(FILE *f, const char *root,
                                     struct sha256_ctx *ctx)
{
    char token[4096];
    bool ok = true;
    size_t length;
    int status = 0;
    while (ok && (status = rr_response_token(f, token, &length)) == 1) {
        rr_key_field(ctx, "link_input", token, length);
        if (strncmp(token, "build/dev-loop/restart-objects/", 31) == 0 ||
            strncmp(token, "build/dev-loop/restart-test-objects/", 36) == 0) {
            char full[PATH_MAX], hash[65];
            ok = rr_join_root(root, token, full) && rr_regular(full, NULL) &&
                 rr_sha256_file(full, hash);
            if (ok)
                rr_key_field(ctx, "overlay_sha256", hash, strlen(hash));
        }
    }
    return ok && status == 0;
}

static bool rr_cache_key(const struct rr_plan *plan, const char *root,
                         const char *rsp, char out[65])
{
    static const char domain[] = "zcl.dev_artifact_cache.restart.v2";
    char cc[sizeof(plan->cc)], cflags[sizeof(plan->cflags)];
    char ldflags[sizeof(plan->ldflags)], libs[sizeof(plan->libs)];
    if (!rr_cache_key_normalize(plan, root, cc, sizeof(cc), cflags,
                                sizeof(cflags), ldflags, sizeof(ldflags),
                                libs, sizeof(libs)))
        return false;
    FILE *f = fopen(rsp, "r");
    if (!f)
        return false;
    struct sha256_ctx ctx;
    unsigned char digest[SHA256_OUTPUT_SIZE];
    sha256_init(&ctx);
    rr_key_field(&ctx, "domain", domain, sizeof(domain) - 1);
    rr_key_field(&ctx, "compiler", plan->compiler_id,
                 strlen(plan->compiler_id));
    rr_key_field(&ctx, "base_generation", plan->base_generation,
                 strlen(plan->base_generation));
    rr_key_field(&ctx, "cc", cc, strlen(cc));
    rr_key_field(&ctx, "cflags", cflags, strlen(cflags));
    rr_key_field(&ctx, "ldflags", ldflags, strlen(ldflags));
    rr_key_field(&ctx, "libs", libs, strlen(libs));
    char base_reloc_hash[65];
    if (!rr_cache_key_base_reloc(plan, root, base_reloc_hash)) {
        fclose(f);
        return false;
    }
    rr_key_field(&ctx, "link_mode", "overlay_base_v1", 15);
    rr_key_field(&ctx, "base_reloc_sha256", base_reloc_hash,
                 strlen(base_reloc_hash));
    bool ok = rr_cache_key_scan_inputs(f, root, &ctx);
    fclose(f);
    if (!ok)
        return false;
    sha256_finalize(&ctx, digest);
    zcl_hex_encode(digest, sizeof(digest), out);
    return true;
}

/* Terminal metadata reads must distinguish clean EOF from I/O failure. */
bool zcl_devloop_restart_metadata_end(FILE *f);
bool zcl_devloop_restart_metadata_end(FILE *f)
{
    return fgetc(f) == EOF && !ferror(f);
}

static bool rr_read_hash(const char *path, char out[65])
{
    out[0] = 0;
    FILE *f = fopen(path, "r");
    if (!f)
        return false;
    char extra = 0;
    bool ok = fscanf(f, "%64[0-9a-f]%c", out, &extra) == 2 &&
              strlen(out) == 64 && extra == '\n' &&
              zcl_devloop_restart_metadata_end(f);
    fclose(f);
    if (!ok) out[0] = 0;
    return ok;
}

#if !defined(_WIN32)
static bool rr_force_cache_copy_for_test(void)
{
    const char *force_copy = getenv("ZCL_DEVLOOP_TEST_FORCE_CACHE_COPY");
    return force_copy && strcmp(force_copy, "1") == 0;
}
#endif

/* The operator may place the shared cache on a different filesystem from
 * the worktree. Publish an immutable, rehashed copy when hard links cannot
 * cross that boundary. */
#if defined(_WIN32)
static bool rr_copy_publish_win32_open(
    const char *source, const char *target, char parent[PATH_MAX],
    char target_leaf[PLATFORM_DIRECTORY_CHILD_LEAF_MAX + 1u],
    struct platform_positioned_file *input,
    struct platform_positioned_file_snapshot *before,
    struct platform_directory_transaction *directory,
    struct platform_directory_child *staged,
    char staged_leaf[PLATFORM_DIRECTORY_CHILD_LEAF_MAX + 1u])
{
    return rr_parent_leaf(target, parent, target_leaf) &&
           platform_positioned_file_open(input, source) &&
           platform_positioned_file_snapshot(input, before) &&
           before->size <= SIZE_MAX &&
           platform_directory_transaction_open(directory, parent) &&
           rr_create_temp_child(directory, ".bin", staged, staged_leaf);
}

static bool rr_copy_publish_win32_copy_loop(
    struct platform_positioned_file *input,
    struct platform_directory_child *staged, uint64_t total_size)
{
    unsigned char buffer[32u * 1024u];
    uint64_t offset = 0;
    bool ok = true;
    while (ok && offset < total_size) {
        size_t wanted = total_size - offset > sizeof(buffer)
                            ? sizeof(buffer) : (size_t)(total_size - offset);
        int64_t got = platform_positioned_file_read(input, buffer, wanted,
                                                    offset);
        ok = got == (int64_t)wanted &&
             platform_directory_child_write_exact(staged, buffer, wanted,
                                                   offset);
        offset += ok ? wanted : 0;
    }
    return ok;
}

static bool rr_copy_publish_win32_finalize(
    struct platform_positioned_file *input,
    struct platform_positioned_file_snapshot *before,
    struct platform_directory_transaction *directory,
    struct platform_directory_child *staged,
    const char target_leaf[PLATFORM_DIRECTORY_CHILD_LEAF_MAX + 1u],
    const char staged_leaf[PLATFORM_DIRECTORY_CHILD_LEAF_MAX + 1u],
    const char *target, const char expected_sha256[65], bool ok)
{
    struct platform_positioned_file_snapshot after;
    ok = ok && platform_positioned_file_snapshot(input, &after) &&
         platform_positioned_file_snapshot_equal(before, &after) &&
         platform_directory_child_truncate(staged, before->size) &&
         platform_directory_child_flush(staged);
    platform_positioned_file_close(input);
    if (ok)
        ok = platform_directory_child_replace(directory, staged,
                                              target_leaf, true);
    platform_directory_child_close(staged);
    if (!ok && staged_leaf[0])
        (void)platform_directory_child_unlink(directory, staged_leaf, true);
    ok = ok && platform_directory_transaction_flush(directory);
    platform_directory_transaction_close(directory);
    char actual[65];
    if (ok)
        ok = rr_sha256_file(target, actual) &&
             strcmp(actual, expected_sha256) == 0;
    if (!ok && rr_regular(target, NULL))
        ok = rr_sha256_file(target, actual) &&
             strcmp(actual, expected_sha256) == 0;
    return ok;
}

static bool rr_copy_publish_win32(const char *source, const char *target,
                                  const char expected_sha256[65])
{
    char parent[PATH_MAX], target_leaf[PLATFORM_DIRECTORY_CHILD_LEAF_MAX + 1u];
    struct platform_positioned_file input;
    struct platform_positioned_file_snapshot before;
    struct platform_directory_transaction directory;
    struct platform_directory_child staged;
    char staged_leaf[PLATFORM_DIRECTORY_CHILD_LEAF_MAX + 1u] = {0};
    platform_positioned_file_init(&input);
    platform_directory_transaction_init(&directory);
    platform_directory_child_init(&staged);
    bool ok = rr_copy_publish_win32_open(source, target, parent, target_leaf,
                                         &input, &before, &directory, &staged,
                                         staged_leaf);
    ok = ok && rr_copy_publish_win32_copy_loop(&input, &staged, before.size);
    return rr_copy_publish_win32_finalize(&input, &before, &directory,
                                          &staged, target_leaf, staged_leaf,
                                          target, expected_sha256, ok);
}
#else
static bool rr_copy_publish_posix_open(const char *source, const char *target,
                                       char temp[PATH_MAX],
                                       int *source_fd_out, int *temp_fd_out)
{
    int n = snprintf(temp, PATH_MAX, "%s.tmp.XXXXXX", target);
    if (n <= 0 || n >= PATH_MAX)
        return false;
    int source_fd = open(source, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    struct stat source_st;
    if (source_fd < 0 || fstat(source_fd, &source_st) != 0 ||
        !S_ISREG(source_st.st_mode)) {
        if (source_fd >= 0) close(source_fd);
        return false;
    }
    int temp_fd = mkostemp(temp, O_CLOEXEC);
    if (temp_fd < 0) {
        close(source_fd);
        return false;
    }
    *source_fd_out = source_fd;
    *temp_fd_out = temp_fd;
    return true;
}

static bool rr_copy_publish_posix_copy(int source_fd, int temp_fd)
{
    unsigned char buffer[32u * 1024u];
    bool ok = true;
    for (;;) {
        ssize_t got = read(source_fd, buffer, sizeof(buffer));
        if (got == 0)
            break;
        if (got < 0) {
            if (errno == EINTR) continue;
            ok = false;
            break;
        }
        size_t written = 0;
        while (written < (size_t)got) {
            ssize_t put = write(temp_fd, buffer + written,
                                (size_t)got - written);
            if (put < 0 && errno == EINTR)
                continue;
            if (put <= 0) {
                ok = false;
                break;
            }
            written += (size_t)put;
        }
        if (!ok) break;
    }
    if (close(source_fd) != 0)
        ok = false;
    return ok;
}

static bool rr_copy_publish_posix_finalize(const char *temp,
                                           const char *target, int temp_fd,
                                           const char expected_sha256[65],
                                           bool ok)
{
    if (ok && (fchmod(temp_fd, 0555) != 0 || fsync(temp_fd) != 0))
        ok = false;
    if (close(temp_fd) != 0)
        ok = false;
    char actual[65];
    if (ok && (!rr_sha256_file(temp, actual) ||
               strcmp(actual, expected_sha256) != 0))
        ok = false;
    if (ok && link(temp, target) != 0) {
        if (errno != EEXIST || !rr_regular(target, NULL) ||
            !rr_sha256_file(target, actual) ||
            strcmp(actual, expected_sha256) != 0 ||
            chmod(target, 0555) != 0)
            ok = false;
    }
    return ok;
}

static bool rr_copy_publish_posix(const char *source, const char *target,
                                  const char expected_sha256[65])
{
    char temp[PATH_MAX];
    int source_fd, temp_fd;
    if (!rr_copy_publish_posix_open(source, target, temp, &source_fd,
                                    &temp_fd))
        return false;
    bool ok = rr_copy_publish_posix_copy(source_fd, temp_fd);
    ok = rr_copy_publish_posix_finalize(temp, target, temp_fd,
                                        expected_sha256, ok);
    (void)unlink(temp);
    return ok;
}
#endif

static bool rr_copy_publish(const char *source, const char *target,
                            const char expected_sha256[65])
{
#if defined(_WIN32)
    return rr_copy_publish_win32(source, target, expected_sha256);
#else
    return rr_copy_publish_posix(source, target, expected_sha256);
#endif
}

static bool rr_link_or_copy_publish(const char *source, const char *target,
                                    const char expected_sha256[65])
{
#if defined(_WIN32)
    return rr_copy_publish(source, target, expected_sha256);
#else
    if (!rr_force_cache_copy_for_test() && link(source, target) == 0)
        return chmod(target, 0555) == 0;
    int link_errno = rr_force_cache_copy_for_test() ? EXDEV : errno;
    if (link_errno == EEXIST) {
        char actual[65];
        return rr_regular(target, NULL) && rr_sha256_file(target, actual) &&
               strcmp(actual, expected_sha256) == 0 &&
               chmod(target, 0555) == 0;
    }
    if (link_errno != EXDEV)
        return false;
    return rr_copy_publish(source, target, expected_sha256);
#endif
}

#if defined(_WIN32)
typedef struct platform_process_lock rr_cache_lock_handle;
#else
typedef int rr_cache_lock_handle;
#endif

static bool rr_cache_lock(const char *cache_root, const char key[65],
                         rr_cache_lock_handle *held,
                         char binary[PATH_MAX], char hash[PATH_MAX])
{
    char lock[PATH_MAX];
    if (snprintf(lock, sizeof(lock), "%s/%s.lock", cache_root, key) >=
            (int)sizeof(lock) ||
        snprintf(binary, PATH_MAX, "%s/%s.bin", cache_root, key) >= PATH_MAX ||
        snprintf(hash, PATH_MAX, "%s/%s.sha256", cache_root, key) >= PATH_MAX)
        return false;
#if defined(_WIN32)
    platform_process_lock_init(held);
    return platform_process_lock_try_acquire(held, lock, true);
#else
    int fd = open(lock, O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
    struct stat st;
    if (fd < 0 || fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) ||
        flock(fd, LOCK_EX) != 0) {
        if (fd >= 0) close(fd);
        return false;
    }
    *held = fd;
    return true;
#endif
}

static void rr_cache_unlock(rr_cache_lock_handle *held)
{
#if defined(_WIN32)
    platform_process_lock_release(held);
#else
    (void)flock(*held, LOCK_UN);
    (void)close(*held);
    *held = -1;
#endif
}

static bool rr_publish_candidate(const char *root, const char *candidate_dir,
                                 const char *source, const char hash[65],
                                 char out[PATH_MAX])
{
    char candidates[PATH_MAX];
    if (snprintf(candidates, sizeof(candidates), "%s/%s", root,
                 candidate_dir) >= (int)sizeof(candidates) ||
        !rr_mkdirs(candidates) ||
        snprintf(out, PATH_MAX, "%s/%s-zclassic23-dev", candidates,
                 hash) >= PATH_MAX)
        return false;
    return rr_link_or_copy_publish(source, out, hash);
}

static bool rr_cache_lookup(const char *root, const char *candidate_dir,
                            const char *cache_binary, const char *cache_hash,
                            char out[PATH_MAX])
{
    char expected[65], actual[65];
    return rr_regular(cache_binary, NULL) && rr_regular(cache_hash, NULL) &&
           rr_read_hash(cache_hash, expected) &&
           rr_sha256_file(cache_binary, actual) &&
           strcmp(expected, actual) == 0 &&
           rr_publish_candidate(root, candidate_dir, cache_binary, actual, out);
}

#if defined(_WIN32)
static bool rr_cache_publish_win32(const char *cache_hash,
                                   const char hash[65])
{
    char parent[PATH_MAX], leaf[PLATFORM_DIRECTORY_CHILD_LEAF_MAX + 1u];
    struct platform_directory_transaction directory;
    struct platform_directory_child staged;
    char staged_leaf[PLATFORM_DIRECTORY_CHILD_LEAF_MAX + 1u] = {0};
    platform_directory_transaction_init(&directory);
    platform_directory_child_init(&staged);
    char line[66];
    (void)snprintf(line, sizeof(line), "%s\n", hash);
    bool ok = rr_parent_leaf(cache_hash, parent, leaf) &&
              platform_directory_transaction_open(&directory, parent) &&
              rr_create_temp_child(&directory, ".sha256", &staged,
                                   staged_leaf) &&
              platform_directory_child_write_exact(&staged, line, 65, 0) &&
              platform_directory_child_truncate(&staged, 65) &&
              platform_directory_child_flush(&staged) &&
              platform_directory_child_replace(&directory, &staged, leaf,
                                               false);
    platform_directory_child_close(&staged);
    if (!ok && staged_leaf[0])
        (void)platform_directory_child_unlink(&directory, staged_leaf, true);
    ok = ok && platform_directory_transaction_flush(&directory);
    platform_directory_transaction_close(&directory);
    return ok;
}
#else
static bool rr_cache_publish_posix(const char *cache_hash,
                                   const char hash[65])
{
    char temp[PATH_MAX];
    int n = snprintf(temp, sizeof(temp), "%s.tmp.%ld", cache_hash,
                     (long)getpid());
    if (n <= 0 || n >= (int)sizeof(temp))
        return false;
    (void)unlink(temp);
    int fd = open(temp, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                  0600);
    if (fd < 0)
        return false;
    char line[66];
    (void)snprintf(line, sizeof(line), "%s\n", hash);
    bool ok = write(fd, line, 65) == 65 && fsync(fd) == 0;
    int close_rc = close(fd);
    ok = ok && close_rc == 0;
    if (!ok || rename(temp, cache_hash) != 0) {
        (void)unlink(temp);
        return false;
    }
    return true;
}
#endif

static bool rr_cache_publish(const char *cache_binary, const char *cache_hash,
                             const char *built, const char hash[65])
{
    if (!rr_link_or_copy_publish(built, cache_binary, hash))
        return false;
#if defined(_WIN32)
    return rr_cache_publish_win32(cache_hash, hash);
#else
    return rr_cache_publish_posix(cache_hash, hash);
#endif
}

static bool rr_temp(char out[PATH_MAX], const char *dir, const char *suffix)
{
#if defined(_WIN32)
    struct platform_directory_transaction directory;
    struct platform_directory_child child;
    char leaf[PLATFORM_DIRECTORY_CHILD_LEAF_MAX + 1u];
    platform_directory_transaction_init(&directory);
    platform_directory_child_init(&child);
    bool ok = strlen(dir) < PATH_MAX &&
              platform_directory_transaction_open(&directory, dir) &&
              rr_create_temp_child(&directory, suffix, &child, leaf);
    platform_directory_child_close(&child);
    if (ok) {
        int n = snprintf(out, PATH_MAX, "%s/%s", dir, leaf);
        ok = n > 0 && n < PATH_MAX &&
             platform_directory_transaction_flush(&directory);
    }
    platform_directory_transaction_close(&directory);
    return ok;
#else
    int n = snprintf(out, PATH_MAX, "%s/.restart-XXXXXX%s", dir, suffix);
    if (n <= 0 || n >= PATH_MAX) return false;
    int fd = mkstemps(out, (int)strlen(suffix));
    if (fd < 0) return false;
    close(fd);
    return true;
#endif
}

static bool rr_overlay_object_safe(const char *path)
{
    static const char *const forbidden[] = {
        ".preinit_array", ".init_array", ".fini_array",
    };
    FILE *f = fopen(path, "rb");
    if (!f)
        return false;
    unsigned char buf[65536 + 32];
    size_t carry = 0;
    bool safe = true;
    while (safe) {
        size_t n = fread(buf + carry, 1, 65536, f);
        size_t total = carry + n;
        for (size_t i = 0; i < sizeof(forbidden) / sizeof(forbidden[0]); i++)
            if (rr_bytes_contain(buf, total, forbidden[i])) {
                safe = false;
                break;
            }
        if (n < 65536)
            break;
        carry = total < 31 ? total : 31;
        memmove(buf, buf + total - carry, carry);
    }
    safe = safe && ferror(f) == 0;
    fclose(f);
    return safe;
}

static bool rr_write_overlay_response_open(const char *root, const char *rsp,
                                           char out[PATH_MAX], FILE **in_out,
                                           FILE **dst_out, char *why,
                                           size_t why_len)
{
    char dir[PATH_MAX];
    if (snprintf(dir, sizeof(dir), "%s/build/dev-loop", root) >=
            (int)sizeof(dir) || !rr_temp(out, dir, ".overlays.rsp")) {
        rr_why(why, why_len, "could not prepare overlay-only link response");
        return false;
    }
    FILE *in = fopen(rsp, "r"), *dst = fopen(out, "w");
    if (!in || !dst) {
        if (in) fclose(in);
        if (dst) fclose(dst);
        (void)unlink(out);
        rr_why(why, why_len, "could not open overlay-only link response");
        return false;
    }
    *in_out = in;
    *dst_out = dst;
    return true;
}

static bool rr_write_overlay_response_scan(FILE *in, FILE *dst,
                                           const char *root, size_t *count)
{
    char token[4096], full[PATH_MAX];
    bool ok = true;
    *count = 0;
    size_t length;
    int status = 0;
    while (ok && (status = rr_response_token(in, token, &length)) == 1) {
        bool overlay =
            strncmp(token, "build/dev-loop/restart-objects/", 31) == 0 ||
            strncmp(token, "build/dev-loop/restart-test-objects/", 36) == 0;
        if (!overlay) {
#if defined(__APPLE__)
            /* Darwin links the complete substituted graph, without the
             * aggregate base. Ordinary canonical objects may own initializers;
             * overlay safety remains mandatory for every changed object. */
            ok = rr_join_root(root, token, full) && rr_regular(full, NULL) &&
                 fprintf(dst, "%s\n", token) > 0;
#endif
            continue;
        }
        ok = rr_join_root(root, token, full) && rr_regular(full, NULL) &&
             rr_overlay_object_safe(full) && fprintf(dst, "%s\n", token) > 0;
        if (ok)
            (*count)++;
    }
    return ok && status == 0 && *count > 0 && rr_flush_stream(dst);
}

static bool rr_write_overlay_response(const char *root, const char *rsp,
                                      char out[PATH_MAX], char *why,
                                      size_t why_len)
{
    FILE *in, *dst;
    if (!rr_write_overlay_response_open(root, rsp, out, &in, &dst, why,
                                        why_len))
        return false;
    size_t count;
    bool ok = rr_write_overlay_response_scan(in, dst, root, &count);
    fclose(in);
    fclose(dst);
    if (!ok) {
        (void)unlink(out);
        rr_why(why, why_len,
               "overlay link input is missing, unreadable, or owns process initialization");
    }
    return ok;
}

static bool rr_source_is_c(const char *path)
{
    size_t n = path ? strlen(path) : 0;
    return rr_safe_relative(path) && n > 2 && strcmp(path + n - 2, ".c") == 0;
}

static bool rr_compile_one_prepare(const char *root,
                                   struct rr_overlay *overlay,
                                   char source_full[PATH_MAX],
                                   char before_hash[65],
                                   char overlay_dir[PATH_MAX],
                                   char temp_o[PATH_MAX],
                                   char temp_d[PATH_MAX],
                                   char *why, size_t why_len)
{
    if (!rr_join_root(root, overlay->source, source_full) ||
        !rr_regular(source_full, NULL) ||
        !rr_sha256_file(source_full, before_hash)) {
        rr_why(why, why_len, "restart source is absent or not a regular file");
        return false;
    }
    (void)snprintf(overlay_dir, PATH_MAX, "%s", overlay->overlay_object);
    char *slash = strrchr(overlay_dir, '/');
    if (!slash) return false;
    *slash = 0;
    if (!rr_mkdirs(overlay_dir)) {
        rr_why(why, why_len, "could not prepare confined restart object directory");
        return false;
    }
    if (!rr_temp(temp_o, overlay_dir, ".o") ||
        !rr_temp(temp_d, overlay_dir, ".d")) {
        rr_why(why, why_len, "could not allocate restart compile temporaries");
        return false;
    }
    return true;
}

/* Decode Make's trusted shell-word encoding without invoking a shell or
 * expanding variables, substitutions or globs. Output never exceeds input. */
static bool rr_argument_escape(char **read, char **write, char quote)
{
    char c = **read;
    if (!c) return false;
    if (quote == '"' && !strchr("$`\"\\\n", c)) *(*write)++ = '\\';
    if (c != '\n') *(*write)++ = c;
    ++*read;
    return true;
}

static bool rr_argument_word(char **read, char **write)
{
    char quote = 0;
    while (**read) {
        char c = **read;
        if (!quote && isspace((unsigned char)c)) break;
        ++*read;
        if (c == '\\' && quote != '\'') {
            if (!rr_argument_escape(read, write, quote)) return false;
        } else if (c == quote) quote = 0;
        else if (!quote && (c == '\'' || c == '"')) quote = c;
        else *(*write)++ = c;
    }
    return quote == 0;
}

static bool rr_arguments(char *text, const char **argv, size_t capacity,
                          size_t *count)
{
    *count = 0;
    if (!capacity) return false;
    argv[0] = NULL;
    char *read = text, *write = text;
    while (*read) {
        while (isspace((unsigned char)*read)) ++read;
        if (!*read) break;
        if (*count >= capacity - 1) return false;
        argv[(*count)++] = write;
        if (!rr_argument_word(&read, &write)) return false;
        /* Save the next input before its delimiter can be overwritten. */
        while (isspace((unsigned char)*read)) ++read;
        *write++ = '\0';
    }
    argv[*count] = NULL;
    return true;
}

#ifdef ZCL_TESTING
bool zcl_devloop_restart_arguments_test(char *text, const char **argv,
                                       size_t capacity, size_t *count);
bool zcl_devloop_restart_arguments_test(char *text, const char **argv,
                                       size_t capacity, size_t *count)
{
    return rr_arguments(text, argv, capacity, count);
}
#endif

struct rr_compile_argv_buf {
    char cc[512], flags[RR_TEXT_MAX];
    const char *argv[RR_ARG_MAX], *flagv[RR_ARG_MAX];
    size_t argc;
};

static bool rr_compile_one_build_argv(const struct rr_plan *plan,
                                      const char *const *extra_flags,
                                      size_t extra_flag_count,
                                      const char *temp_d, const char *temp_o,
                                      const char *source,
                                      struct rr_compile_argv_buf *b,
                                      char *why, size_t why_len)
{
    (void)snprintf(b->cc, sizeof(b->cc), "%s", plan->cc);
    (void)snprintf(b->flags, sizeof(b->flags), "%s", plan->cflags);
    size_t flagc = 0;
    if (!rr_arguments(b->cc, b->argv, RR_ARG_MAX, &b->argc) ||
        !rr_arguments(b->flags, b->flagv, RR_ARG_MAX, &flagc)) {
        rr_why(why, why_len, "restart compile action has malformed or excessive arguments");
        return false;
    }
    if (!b->argc || b->argc + flagc + extra_flag_count + 9 >= RR_ARG_MAX) {
        rr_why(why, why_len, "restart compile action exceeds argv bound");
        return false;
    }
    for (size_t i = 0; i < flagc; i++) b->argv[b->argc++] = b->flagv[i];
    for (size_t i = 0; i < extra_flag_count; i++)
        b->argv[b->argc++] = extra_flags[i];
    b->argv[b->argc++] = "-MD"; b->argv[b->argc++] = "-MF";
    b->argv[b->argc++] = temp_d;
    b->argv[b->argc++] = "-c"; b->argv[b->argc++] = "-o";
    b->argv[b->argc++] = temp_o;
    b->argv[b->argc++] = source; b->argv[b->argc] = NULL;
    return true;
}

static bool rr_compile_one_run(const char *root, const char **argv,
                               struct zcl_devloop_process_result *process,
                               int64_t *elapsed_us, int64_t *startup_us,
                               int64_t *body_us, const char *source_full,
                               const char *before_hash, char after_hash[65],
                               const char *temp_o, const char *temp_d,
                               char *why, size_t why_len)
{
    int64_t started = platform_time_monotonic_us();
    bool ran = zcl_devloop_process_run(root, argv, 30000, process);
    *elapsed_us += platform_time_monotonic_us() - started;
    *startup_us += process->startup_us;
    *body_us += process->body_us;
    bool ok = ran && !process->timed_out && !process->term_signal &&
              process->exit_code == 0 && rr_regular(temp_o, NULL) &&
              rr_regular(temp_d, NULL) &&
              rr_sha256_file(source_full, after_hash) &&
              strcmp(before_hash, after_hash) == 0;
    if (!ok) {
        (void)unlink(temp_o); (void)unlink(temp_d);
        rr_why(why, why_len, ran ? "restart compile failed or source changed"
                                : "restart compiler could not be executed");
        return false;
    }
    return true;
}

static bool rr_compile_one_publish_object(struct rr_overlay *overlay,
                                          const char *temp_o,
                                          const char *temp_d,
                                          char marker[PATH_MAX],
                                          char *why, size_t why_len)
{
    if (snprintf(marker, PATH_MAX, "%s.source", overlay->overlay_object) >=
        PATH_MAX) {
        (void)unlink(temp_o); (void)unlink(temp_d);
        rr_why(why, why_len, "restart overlay marker path overflow");
        return false;
    }
    (void)unlink(marker);
    (void)unlink(overlay->overlay_object);
    if (rename(temp_o, overlay->overlay_object) != 0) {
        (void)unlink(temp_o); (void)unlink(temp_d);
        rr_why(why, why_len, "could not publish restart overlay object");
        return false;
    }
    (void)chmod(overlay->overlay_object, 0444);
    return true;
}

/* One translation unit's compiler-listed prerequisites. The bytes live on
 * the heap: 256 paths must not sit on a restart worker stack. */
struct rr_dep_list {
    size_t count;
    char path[RR_DEP_MAX][RR_DEP_PATH];
};

static bool rr_dep_push(struct rr_dep_list *deps, const char *tok)
{
    size_t n = tok ? strlen(tok) : 0;
    if (!deps || n == 0 || n >= RR_DEP_PATH || deps->count >= RR_DEP_MAX ||
        !rr_dep_path_ok(tok))
        return false;
    memcpy(deps->path[deps->count], tok, n + 1);
    deps->count++;
    return true;
}

static char *rr_dep_token(char **cursor)
{
    char *s = *cursor;
    while (*s == ' ' || *s == '\t' || *s == '\r' || *s == '\n')
        s++;
    if (!*s) {
        *cursor = s;
        return NULL;
    }
    char *start = s;
    while (*s && *s != ' ' && *s != '\t' && *s != '\r' && *s != '\n')
        s++;
    if (*s) {
        *s = 0;
        s++;
    }
    *cursor = s;
    return start;
}

static bool rr_depfile_load(const char *path, char **text_out, size_t *n_out)
{
    FILE *f = fopen(path, "r");
    char *text = f ? zcl_calloc((1u << 20), 1, "restart depfile") : NULL;
    if (!f || !text) {
        if (f) fclose(f);
        free(text);
        return false;
    }
    size_t n = fread(text, 1, (1u << 20) - 1, f);
    bool ok = ferror(f) == 0 && feof(f);
    fclose(f);
    if (!ok) {
        free(text);
        return false;
    }
    *text_out = text;
    *n_out = n;
    return true;
}

static void rr_depfile_flatten(char *text, size_t n)
{
    for (size_t i = 0; i + 1 < n; i++) {
        if (text[i] == '\\' && (text[i + 1] == '\n' || text[i + 1] == '\r'))
            text[i] = text[i + 1] = ' ';
    }
}

static char *rr_depfile_colon(char *text)
{
    char *colon = strchr(text, ':');
    while (colon && colon[1] && !strchr(" \t\r\n", colon[1]))
        colon = strchr(colon + 1, ':');
    return colon;
}

static bool rr_depfile_tokens(char *text, struct rr_dep_list *deps)
{
    char *colon = rr_depfile_colon(text);
    bool ok = colon != NULL;
    char *cursor = ok ? colon + 1 : text;
    for (char *tok = ok ? rr_dep_token(&cursor) : NULL; ok && tok;
         tok = rr_dep_token(&cursor)) {
        if (tok[strlen(tok) - 1] == ':')
            break;
        ok = rr_dep_push(deps, tok);
    }
    return ok && deps->count > 0;
}

/* Prerequisites of a compiler depfile, in listed order. Continuations are
 * flattened first. A path the restart builder will not hash fails closed. */
static bool rr_depfile_read(const char *path, struct rr_dep_list *deps)
{
    char *text = NULL;
    size_t n = 0;
    if (!rr_depfile_load(path, &text, &n))
        return false;
    rr_depfile_flatten(text, n);
    bool ok = rr_depfile_tokens(text, deps);
    free(text);
    return ok;
}

/* Freshness of one object: this plan's compiler and flags, plus the current
 * bytes of each compiler-listed dependency. The whole-tree base generation
 * is not an input. Callers still seal that generation into the link cache. */
static bool rr_object_input_key(const struct rr_plan *plan, const char *root,
                                const struct rr_dep_list *deps, char out[65])
{
    static const char domain[] = "zcl.devloop.restart.object_inputs.v1";
    struct sha256_ctx ctx;
    unsigned char digest[SHA256_OUTPUT_SIZE];
    if (!plan || !deps || !rr_hex64(plan->compiler_id) || !plan->cflags[0])
        return false;
    sha256_init(&ctx);
    rr_key_field(&ctx, "domain", domain, sizeof(domain) - 1);
    rr_key_field(&ctx, "compiler", plan->compiler_id, strlen(plan->compiler_id));
    rr_key_field(&ctx, "cflags", plan->cflags, strlen(plan->cflags));
    for (size_t i = 0; i < deps->count; i++) {
        char full[PATH_MAX], hash[65];
        if (!rr_dep_resolve(root, deps->path[i], full) ||
            !rr_sha256_file(full, hash))
            return false;
        rr_key_field(&ctx, "dep", deps->path[i], strlen(deps->path[i]));
        rr_key_field(&ctx, "dep_sha256", hash, 64);
    }
    sha256_finalize(&ctx, digest);
    zcl_hex_encode(digest, sizeof(digest), out);
    return rr_hex64(out);
}

static bool rr_deps_publish(const char *overlay_object,
                            const struct rr_dep_list *deps, char *why,
                            size_t why_len)
{
    char dir[PATH_MAX], final_path[PATH_MAX], temp[PATH_MAX];
    if (snprintf(final_path, sizeof(final_path), "%s.deps", overlay_object) >=
            (int)sizeof(final_path) ||
        snprintf(dir, sizeof(dir), "%s", overlay_object) >= (int)sizeof(dir)) {
        rr_why(why, why_len, "restart dependency list path overflow");
        return false;
    }
    char *slash = strrchr(dir, '/');
    if (!slash) {
        rr_why(why, why_len, "restart dependency list path overflow");
        return false;
    }
    *slash = 0;
    if (!rr_temp(temp, dir, ".deps")) {
        rr_why(why, why_len, "could not allocate restart dependency list");
        return false;
    }
    FILE *out = fopen(temp, "w");
    bool ok = out != NULL;
    for (size_t i = 0; ok && i < deps->count; i++)
        ok = fprintf(out, "%s\n", deps->path[i]) > 0;
    ok = ok && rr_flush_stream(out);
    if (out) fclose(out);
    if (!ok || rename(temp, final_path) != 0) {
        (void)unlink(temp);
        rr_why(why, why_len, "could not publish restart dependency list");
        return false;
    }
    (void)chmod(final_path, 0444);
    return true;
}

static bool rr_deps_load(const char *overlay_object, struct rr_dep_list *deps)
{
    char path[PATH_MAX], line[RR_DEP_PATH + 2];
    if (snprintf(path, sizeof(path), "%s.deps", overlay_object) >=
        (int)sizeof(path))
        return false;
    FILE *f = fopen(path, "r");
    if (!f) return false;
    bool ok = true;
    while (ok && fgets(line, sizeof(line), f)) {
        size_t n = strlen(line);
        if (n == 0 || line[n - 1] != '\n' || n == 1) {
            ok = false;
            break;
        }
        line[n - 1] = 0;
        ok = rr_dep_push(deps, line);
    }
    ok = ok && ferror(f) == 0 && feof(f) && deps->count > 0;
    fclose(f);
    return ok;
}

static bool rr_compile_one_publish_marker(const char *input_key,
                                          struct rr_overlay *overlay,
                                          const char *overlay_dir,
                                          const char *temp_d,
                                          const char *marker,
                                          const char after_hash[65],
                                          char *why, size_t why_len)
{
    (void)snprintf(overlay->source_sha256, sizeof(overlay->source_sha256),
                   "%s", after_hash);
    char marker_temp[PATH_MAX];
    if (!rr_hex64(input_key) || !rr_temp(marker_temp, overlay_dir, ".source")) {
        (void)unlink(overlay->overlay_object); (void)unlink(temp_d);
        rr_why(why, why_len, "could not allocate restart overlay marker");
        return false;
    }
    FILE *marker_file = fopen(marker_temp, "w");
    bool marker_ok = marker_file &&
        fprintf(marker_file, "%s %s\n", input_key, after_hash) == 130 &&
        rr_flush_stream(marker_file);
    if (marker_file) fclose(marker_file);
    if (!marker_ok || rename(marker_temp, marker) != 0) {
        (void)unlink(marker_temp); (void)unlink(overlay->overlay_object);
        (void)unlink(temp_d);
        rr_why(why, why_len, "could not publish restart overlay marker");
        return false;
    }
    (void)chmod(marker, 0444);
    (void)unlink(temp_d);
    return true;
}

static bool rr_compile_one(const struct rr_plan *plan, const char *root,
                           struct rr_overlay *overlay,
                           const char *const *extra_flags,
                           size_t extra_flag_count,
                           struct zcl_devloop_process_result *process,
                           int64_t *elapsed_us, int64_t *startup_us,
                           int64_t *body_us, char *why, size_t why_len)
{
    char source_full[PATH_MAX], before_hash[65], after_hash[65];
    char overlay_dir[PATH_MAX], temp_o[PATH_MAX], temp_d[PATH_MAX];
    if (!rr_compile_one_prepare(root, overlay, source_full, before_hash,
                                overlay_dir, temp_o, temp_d, why, why_len))
        return false;
    struct rr_compile_argv_buf buf;
    if (!rr_compile_one_build_argv(plan, extra_flags, extra_flag_count,
                                   temp_d, temp_o, overlay->source, &buf,
                                   why, why_len)) {
        (void)unlink(temp_o); (void)unlink(temp_d);
        return false;
    }
    if (!rr_compile_one_run(root, buf.argv, process, elapsed_us, startup_us,
                            body_us, source_full, before_hash, after_hash,
                            temp_o, temp_d, why, why_len))
        return false;
    struct rr_dep_list *deps = zcl_calloc(1, sizeof(*deps),
                                          "restart object deps");
    char input_key[65];
    if (!deps || !rr_depfile_read(temp_d, deps) ||
        !rr_object_input_key(plan, root, deps, input_key)) {
        free(deps);
        (void)unlink(temp_o);
        (void)unlink(temp_d);
        rr_why(why, why_len,
               "restart object inputs are not a closed dependency list");
        return false;
    }
    char marker[PATH_MAX];
    if (!rr_compile_one_publish_object(overlay, temp_o, temp_d, marker, why,
                                       why_len)) {
        free(deps);
        return false;
    }
    if (!rr_deps_publish(overlay->overlay_object, deps, why, why_len)) {
        (void)unlink(overlay->overlay_object);
        (void)unlink(temp_d);
        free(deps);
        return false;
    }
    free(deps);
    if (!rr_compile_one_publish_marker(input_key, overlay, overlay_dir, temp_d,
                                       marker, after_hash, why, why_len)) {
        char deps_path[PATH_MAX];
        if (snprintf(deps_path, sizeof(deps_path), "%s.deps",
                     overlay->overlay_object) < (int)sizeof(deps_path))
            (void)unlink(deps_path);
        return false;
    }
    return true;
}

static bool rr_overlay_for_base_paths(const struct rr_plan *plan,
                                      const char *root,
                                      const char *base_object,
                                      const char *overlay_prefix,
                                      char overlay_relative[PATH_MAX],
                                      char source[PATH_MAX],
                                      char marker[PATH_MAX])
{
    size_t prefix_len = strlen(plan->obj_dir);
    size_t token_len = strlen(base_object);
    if (strncmp(base_object, plan->obj_dir, prefix_len) != 0 ||
        base_object[prefix_len] != '/' || token_len < 3 ||
        strcmp(base_object + token_len - 2, ".o") != 0)
        return false;
    const char *stem = base_object + prefix_len + 1;
    char overlay[PATH_MAX];
    if (snprintf(source, PATH_MAX, "%s", stem) >= PATH_MAX)
        return false;
    size_t source_len = strlen(source);
    source[source_len - 1] = 'c';
    if (snprintf(overlay_relative, PATH_MAX, "%s/%s",
                 overlay_prefix, stem) >= PATH_MAX ||
        snprintf(overlay, sizeof(overlay), "%s/%s", root,
                 overlay_relative) >= (int)sizeof(overlay) ||
        snprintf(marker, PATH_MAX, "%s.source", overlay) >= PATH_MAX ||
        !rr_regular(overlay, NULL) || !rr_regular(marker, NULL))
        return false;
    return true;
}

static bool rr_overlay_marker_parsed(const char *marker, char generation[65],
                                     char expected[65])
{
    FILE *f = fopen(marker, "r");
    if (!f)
        return false;
    char extra = 0;
    bool parsed = fscanf(f, "%64[0-9a-f] %64[0-9a-f]%c", generation, expected,
                         &extra) == 3 &&
                  extra == '\n' && zcl_devloop_restart_metadata_end(f);
    fclose(f);
    return parsed;
}

static bool rr_overlay_object_of_marker(const char *marker,
                                        char object[PATH_MAX])
{
    size_t marker_len = strlen(marker);
    static const char suffix[] = ".source";
    size_t suffix_len = sizeof(suffix) - 1;
    if (marker_len <= suffix_len ||
        strcmp(marker + marker_len - suffix_len, suffix) != 0 ||
        marker_len - suffix_len >= PATH_MAX)
        return false;
    memcpy(object, marker, marker_len - suffix_len);
    object[marker_len - suffix_len] = 0;
    return true;
}

static bool rr_overlay_inputs_match(const struct rr_plan *plan,
                                    const char *root, const char *object,
                                    const char *generation, char input_key[65])
{
    struct rr_dep_list *deps =
        zcl_calloc(1, sizeof(*deps), "restart overlay deps");
    bool ok = deps && rr_deps_load(object, deps) &&
              rr_object_input_key(plan, root, deps, input_key) &&
              strcmp(generation, input_key) == 0;
    free(deps);
    return ok;
}

static bool rr_overlay_source_hash_matches(const char *root, const char *source,
                                           const char *expected)
{
    char source_full[PATH_MAX], actual[65];
    return rr_join_root(root, source, source_full) &&
           rr_regular(source_full, NULL) &&
           rr_sha256_file(source_full, actual) &&
           strcmp(actual, expected) == 0;
}

static bool rr_overlay_for_base_verify(const struct rr_plan *plan,
                                       const char *root, const char *source,
                                       const char *marker)
{
    char generation[65] = {0}, expected[65] = {0}, object[PATH_MAX];
    char input_key[65] = {0};
    return rr_overlay_marker_parsed(marker, generation, expected) &&
           rr_overlay_object_of_marker(marker, object) &&
           rr_overlay_inputs_match(plan, root, object, generation,
                                   input_key) &&
           rr_overlay_source_hash_matches(root, source, expected);
}

/* `*present_out` reports whether a persistent overlay object and its
 * `.source` marker physically exist for `base_object` from some earlier
 * generation, independent of whether that overlay verifies. Most link
 * tokens never reach this true: they were never overlaid, and the caller
 * must treat that ordinary case as silent. A token that DOES set it true
 * but still returns false from this function once carried a proof that no
 * longer verifies, and the caller must not treat that case as silent. */
static bool rr_overlay_for_base(const struct rr_plan *plan, const char *root,
                                const char *base_object,
                                const char *overlay_prefix,
                                char overlay_relative[PATH_MAX],
                                bool *present_out)
{
    char source[PATH_MAX], marker[PATH_MAX];
    bool present = rr_overlay_for_base_paths(plan, root, base_object,
                                             overlay_prefix, overlay_relative,
                                             source, marker);
    if (present_out)
        *present_out = present;
    if (!present)
        return false;
    return rr_overlay_for_base_verify(plan, root, source, marker);
}

static bool rr_source_is_test_only(const char *source)
{
    static const char prefix[] = "tests/harness/";
    return source && strncmp(source, prefix, sizeof(prefix) - 1) == 0;
}

static bool rr_write_response_open(const struct rr_plan *plan,
                                   const char *root, char out[PATH_MAX],
                                   FILE **in_out, FILE **dst_out,
                                   char *why, size_t why_len)
{
    char rsp_full[PATH_MAX], dir[PATH_MAX];
    if (!rr_join_root(root, plan->link_rsp, rsp_full) ||
        snprintf(dir, sizeof(dir), "%s/build/dev-loop", root) >=
            (int)sizeof(dir) || !rr_mkdirs(dir) || !rr_temp(out, dir, ".rsp")) {
        rr_why(why, why_len, "could not prepare restart link response");
        return false;
    }
    FILE *in = fopen(rsp_full, "r"), *dst = fopen(out, "w");
    if (!in || !dst) {
        if (in) fclose(in);
        if (dst) fclose(dst);
        (void)unlink(out);
        rr_why(why, why_len, "could not open restart link response");
        return false;
    }
    *in_out = in;
    *dst_out = dst;
    return true;
}

/* Resolve the response line for one linker input token: prefer a live
 * overlay for this build's plan, else a persistent overlay from a prior
 * generation, else the original object path. Fails closed: if a persistent
 * overlay physically exists for `token` but does not verify, the original
 * object path is still written (the link must proceed with something), but
 * `*unresolved` is set so the caller cannot report this run as trustworthy.
 * A token with no persistent overlay at all is the ordinary case and never
 * sets it. */
static void rr_write_response_resolve(const struct rr_plan *plan,
                                      const char *root,
                                      const struct rr_overlay *overlays,
                                      size_t overlay_count,
                                      const char *overlay_prefix,
                                      const char *token, bool *seen,
                                      char persistent_overlay[PATH_MAX],
                                      const char **write_path_out,
                                      bool *unresolved)
{
    for (size_t i = 0; i < overlay_count; i++) {
        if (strcmp(token, overlays[i].base_object) == 0) {
            const char *write_path = overlays[i].overlay_object;
            /* Linker cwd is root; retain a worktree-relative response. */
            size_t root_len = strlen(root);
            if (strncmp(write_path, root, root_len) == 0 &&
                write_path[root_len] == '/')
                write_path += root_len + 1;
            seen[i] = true;
            *write_path_out = write_path;
            return;
        }
    }
    bool present = false;
    bool verified = rr_overlay_for_base(plan, root, token, overlay_prefix,
                                        persistent_overlay, &present);
    if (verified) {
        *write_path_out = persistent_overlay;
        return;
    }
    if (present)
        *unresolved = true;
    *write_path_out = token;
}

static bool rr_write_response_scan(const struct rr_plan *plan,
                                   const char *root, FILE *in, FILE *dst,
                                   const struct rr_overlay *overlays,
                                   size_t overlay_count,
                                   const char *overlay_prefix, bool *seen,
                                   bool *unresolved)
{
    char token[4096];
    bool ok = true;
    size_t length;
    int status = 0;
    while (ok && (status = rr_response_token(in, token, &length)) == 1) {
        char persistent_overlay[PATH_MAX];
        const char *write_path;
        rr_write_response_resolve(plan, root, overlays, overlay_count,
                                  overlay_prefix, token, seen,
                                  persistent_overlay, &write_path,
                                  unresolved);
        ok = fprintf(dst, "%s\n", write_path) > 0;
    }
    return ok && status == 0 && rr_flush_stream(dst);
}

/* Stream seam exercises the production response writer without a linker. */
bool zcl_devloop_restart_response_stream_test(FILE *in, FILE *dst);
bool zcl_devloop_restart_response_stream_test(FILE *in, FILE *dst)
{
    const struct rr_plan plan = {0};
    bool seen = false, unresolved = false;
    return rr_write_response_scan(&plan, ".", in, dst, NULL, 0,
                                  "", &seen, &unresolved);
}

static bool rr_write_response_check_seen(const struct rr_overlay *overlays,
                                         size_t overlay_count,
                                         const bool *seen,
                                         bool allow_test_only_omission,
                                         bool ok)
{
    for (size_t i = 0; i < overlay_count; i++)
        ok = ok && (seen[i] || (allow_test_only_omission &&
                                rr_source_is_test_only(overlays[i].source)));
    return ok;
}

static bool rr_write_response(const struct rr_plan *plan, const char *root,
                              const struct rr_overlay *overlays,
                              size_t overlay_count, const char *overlay_prefix,
                              bool allow_test_only_omission,
                              char out[PATH_MAX],
                              bool *unresolved,
                              char *why, size_t why_len)
{
    FILE *in, *dst;
    if (!rr_write_response_open(plan, root, out, &in, &dst, why, why_len))
        return false;
    bool seen[RR_OVERLAY_MAX] = {0};
    bool ok = rr_write_response_scan(plan, root, in, dst, overlays,
                                     overlay_count, overlay_prefix, seen,
                                     unresolved);
    fclose(in); fclose(dst);
    ok = rr_write_response_check_seen(overlays, overlay_count, seen,
                                      allow_test_only_omission, ok);
    if (!ok) {
        (void)unlink(out);
        rr_why(why, why_len,
               "restart link response did not contain every changed object");
    }
    return ok;
}

struct rr_link_argv_buf {
    char cc[512], cflags[RR_TEXT_MAX], flags[4096], libs[4096];
    char rsp_arg[PATH_MAX + 2];
    const char *argv[RR_ARG_MAX], *cflagv[RR_ARG_MAX];
    const char *flagv[RR_ARG_MAX], *libv[RR_ARG_MAX];
    size_t argc;
};

static bool rr_link_build_argv(const struct rr_plan *plan, const char *temp,
                               const char *overlay_rsp,
                               struct rr_link_argv_buf *b,
                               char *why, size_t why_len)
{
    (void)snprintf(b->cc, sizeof(b->cc), "%s", plan->cc);
    (void)snprintf(b->cflags, sizeof(b->cflags), "%s", plan->cflags);
    (void)snprintf(b->flags, sizeof(b->flags), "%s", plan->ldflags);
    (void)snprintf(b->libs, sizeof(b->libs), "%s", plan->libs);
    (void)snprintf(b->rsp_arg, sizeof(b->rsp_arg), "@%s", overlay_rsp);
    size_t cflagc = 0, flagc = 0, libc = 0;
    if (!rr_arguments(b->cc, b->argv, RR_ARG_MAX, &b->argc) ||
        !rr_arguments(b->cflags, b->cflagv, RR_ARG_MAX, &cflagc) ||
        !rr_arguments(b->flags, b->flagv, RR_ARG_MAX, &flagc) ||
        !rr_arguments(b->libs, b->libv, RR_ARG_MAX, &libc)) {
        rr_why(why, why_len, "restart link action has malformed or excessive arguments");
        return false;
    }
    if (!b->argc || b->argc + cflagc + flagc + libc + 6 >= RR_ARG_MAX) {
        rr_why(why, why_len, "restart link action exceeds argv bound");
        return false;
    }
    for (size_t i = 0; i < cflagc; i++) b->argv[b->argc++] = b->cflagv[i];
    for (size_t i = 0; i < flagc; i++) b->argv[b->argc++] = b->flagv[i];
    b->argv[b->argc++] = "-o"; b->argv[b->argc++] = temp;
    b->argv[b->argc++] = b->rsp_arg;
#if !defined(__APPLE__)
    b->argv[b->argc++] = plan->base_reloc;
    b->argv[b->argc++] = "-Wl,--allow-multiple-definition";
#endif
    /* Darwin consumes the complete substituted object response exactly once;
     * adding the aggregate base duplicates symbols and needs GNU-only flags. */
    for (size_t i = 0; i < libc; i++) b->argv[b->argc++] = b->libv[i];
    b->argv[b->argc] = NULL;
    return true;
}

static bool rr_link_run_and_publish(const char *root, const char *candidate_dir,
                                    const char *temp, const char *overlay_rsp,
                                    char binary[PATH_MAX],
                                    const char **argv,
                                    uint32_t *linker_processes,
                                    uint32_t *complete_graph_linker_processes,
                                    struct zcl_devloop_process_result *process,
                                    int64_t *elapsed_us, int64_t *startup_us,
                                    int64_t *body_us, char *why,
                                    size_t why_len)
{
    (*linker_processes)++;
#if defined(__APPLE__)
    (*complete_graph_linker_processes)++;
#else
    (void)complete_graph_linker_processes;
#endif
    int64_t started = platform_time_monotonic_us();
    bool ran = zcl_devloop_process_run(root, argv, 30000, process);
    *elapsed_us = platform_time_monotonic_us() - started;
    *startup_us = process->startup_us;
    *body_us = process->body_us;
    (void)unlink(overlay_rsp);
    if (!ran || process->timed_out || process->term_signal ||
        process->exit_code != 0 || !rr_regular(temp, NULL)) {
        (void)unlink(temp);
        rr_why(why, why_len, "restart candidate link failed");
        return false;
    }
    char hash[65];
    if (!rr_sha256_file(temp, hash) ||
        !rr_publish_candidate(root, candidate_dir, temp, hash, binary)) {
        (void)unlink(temp);
        rr_why(why, why_len, "could not address restart candidate");
        return false;
    }
    (void)unlink(temp);
    return true;
}

static bool rr_link(const struct rr_plan *plan, const char *root,
                    const char *rsp, const char *candidate_dir,
                    char binary[PATH_MAX],
                    uint32_t *linker_processes,
                    uint32_t *complete_graph_linker_processes,
                    struct zcl_devloop_process_result *process,
                    int64_t *elapsed_us, int64_t *startup_us,
                    int64_t *body_us, char *why, size_t why_len)
{
    char dir[PATH_MAX], temp[PATH_MAX];
    if (snprintf(dir, sizeof(dir), "%s/build/dev-loop", root) >=
            (int)sizeof(dir) || !rr_temp(temp, dir, ".bin")) {
        rr_why(why, why_len, "could not allocate restart binary temporary");
        return false;
    }
    char overlay_rsp[PATH_MAX] = {0};
    if (!rr_write_overlay_response(root, rsp, overlay_rsp, why, why_len)) {
        (void)unlink(temp);
        return false;
    }
    struct rr_link_argv_buf buf;
    if (!rr_link_build_argv(plan, temp, overlay_rsp, &buf, why, why_len)) {
        (void)unlink(temp);
        (void)unlink(overlay_rsp);
        return false;
    }
    return rr_link_run_and_publish(root, candidate_dir, temp, overlay_rsp,
                                   binary, buf.argv, linker_processes,
                                   complete_graph_linker_processes,
                                   process, elapsed_us, startup_us, body_us,
                                   why, why_len);
}

static bool rr_link_cached(const struct rr_plan *plan, const char *root,
                           const char *rsp, const char *candidate_dir,
                           char binary[PATH_MAX], char cache_key[65],
                           bool *cache_hit, uint32_t *linker_processes,
                           uint32_t *complete_graph_linker_processes,
                           struct zcl_devloop_process_result *process,
                           int64_t *elapsed_us, int64_t *startup_us,
                           int64_t *body_us, char *why, size_t why_len)
{
    *cache_hit = false;
    if (!rr_cache_key(plan, root, rsp, cache_key)) {
        rr_why(why, why_len, "could not derive exact restart artifact key");
        return false;
    }
    char cache_root[PATH_MAX] = {0}, cache_binary[PATH_MAX] = {0};
    char cache_hash[PATH_MAX] = {0};
    rr_cache_lock_handle cache_lock;
#if !defined(_WIN32)
    cache_lock = -1;
#endif
    bool cache_locked = false;
    if (rr_cache_root(cache_root))
        cache_locked = rr_cache_lock(cache_root, cache_key, &cache_lock,
                                     cache_binary, cache_hash);
    if (cache_locked &&
        rr_cache_lookup(root, candidate_dir, cache_binary, cache_hash,
                        binary)) {
        *cache_hit = true;
        rr_cache_unlock(&cache_lock);
        return true;
    }
    if (cache_locked) {
        /* With the per-key lock held, an unverifiable pair is stale or
         * corrupt rather than a publisher in flight. Repair it from a new
         * exact link; never accept one side alone. */
        (void)unlink(cache_binary);
        (void)unlink(cache_hash);
    }
    bool ok = rr_link(plan, root, rsp, candidate_dir, binary,
                      linker_processes, complete_graph_linker_processes, process,
                      elapsed_us, startup_us, body_us, why, why_len);
    if (ok && cache_locked) {
        char hash[65];
        ok = rr_sha256_file(binary, hash) &&
             rr_cache_publish(cache_binary, cache_hash, binary, hash);
        if (!ok)
            rr_why(why, why_len,
                   "restart artifact cache publication failed");
    }
    if (cache_locked)
        rr_cache_unlock(&cache_lock);
    return ok;
}

static bool rr_source_record_valid(const struct dev_source_record *source)
{
    return source && source->cas_present &&
           rr_hex64(source->cas_root_sha3) && rr_hex64(source->source_id) &&
           rr_hex64(source->mutation_id);
}

static bool rr_overlay_init(const struct rr_plan *plan, const char *root,
                            const char *source, const char *overlay_prefix,
                            struct rr_overlay *overlay, char *why,
                            size_t why_len)
{
    size_t n = source ? strlen(source) : 0;
    if (!rr_source_is_c(source) || n >= ZCL_DEVLOOP_PATH_MAX) {
        rr_why(why, why_len, "restart overlay source is invalid");
        return false;
    }
    (void)snprintf(overlay->source, sizeof(overlay->source), "%s", source);
    char stem[ZCL_DEVLOOP_PATH_MAX];
    (void)snprintf(stem, sizeof(stem), "%s", source);
    stem[n - 1] = 'o';
    if (snprintf(overlay->base_object, sizeof(overlay->base_object),
                 "%s/%s", plan->obj_dir, stem) >=
            (int)sizeof(overlay->base_object) ||
        snprintf(overlay->overlay_object, sizeof(overlay->overlay_object),
                 "%s/%s/%s", root, overlay_prefix, stem) >=
            (int)sizeof(overlay->overlay_object)) {
        rr_why(why, why_len, "restart object path overflow");
        return false;
    }
    return true;
}

static bool rr_identity_flags(const struct dev_source_record *source,
                              char source_flag[96], char mutation_flag[104],
                              char cas_flag[104], char clean_flag[24])
{
    if (!rr_source_record_valid(source))
        return false;
    int source_n = snprintf(source_flag, 96,
                            "-DZCL_BUILD_SOURCE_ID=\"%s\"",
                            source->source_id);
    int mutation_n = snprintf(mutation_flag, 104,
                              "-DZCL_BUILD_SOURCE_MUTATION=\"%s\"",
                              source->mutation_id);
    int cas_n = snprintf(cas_flag, 104,
                         "-DZCL_BUILD_SOURCE_CAS_SHA3=\"%s\"",
                         source->cas_root_sha3);
    int clean_n = snprintf(clean_flag, 24, "-DZCL_BUILD_CLEAN=1");
    return source_n > 0 && source_n < 96 &&
           mutation_n > 0 && mutation_n < 104 && cas_n > 0 && cas_n < 104 &&
           clean_n > 0 && clean_n < 24;
}

static bool rr_prepare_overlays(
    const struct rr_plan *plan, const char *root,
    const char *const *source_tus, size_t source_count,
    const struct dev_source_record *epoch_source, const char *overlay_prefix,
    struct rr_overlay *overlays, size_t *overlay_count,
    struct zcl_devloop_process_result *process, uint32_t *compiler_processes,
    int64_t *compile_us, int64_t *startup_us, int64_t *body_us,
    char *why, size_t why_len)
{
    static const char identity_source[] = "platform/modules/util/src/clientversion.c";
    char source_flag[96], mutation_flag[104], cas_flag[104], clean_flag[24];
    if (!rr_identity_flags(epoch_source, source_flag, mutation_flag, cas_flag,
                           clean_flag)) {
        rr_why(why, why_len,
               "restart epoch source CAS record is missing or malformed");
        return false;
    }
    const char *identity_flags[] = {
        source_flag, mutation_flag, cas_flag, clean_flag,
    };
    bool identity_seen = false;
    size_t count = 0;
    for (size_t i = 0; i < source_count; i++) {
        bool identity = strcmp(source_tus[i], identity_source) == 0;
        if (!rr_overlay_init(plan, root, source_tus[i], overlay_prefix,
                             &overlays[count], why, why_len))
            return false;
        (*compiler_processes)++;
        if (!rr_compile_one(plan, root, &overlays[count],
                            identity ? identity_flags : NULL,
                            identity ? 4 : 0, process, compile_us,
                            startup_us, body_us,
                            why, why_len))
            return false;
        identity_seen = identity_seen || identity;
        count++;
    }
    if (!identity_seen) {
        if (count >= RR_OVERLAY_MAX ||
            !rr_overlay_init(plan, root, identity_source, overlay_prefix,
                             &overlays[count], why, why_len))
            return false;
        (*compiler_processes)++;
        if (!rr_compile_one(plan, root, &overlays[count], identity_flags, 4,
                            process, compile_us, startup_us, body_us,
                            why, why_len))
            return false;
        count++;
    }
    *overlay_count = count;
    return true;
}

struct rr_restart_build_ctx {
    const char *repo_root;
    const char *const *source_tus;
    size_t source_count;
    struct zcl_devloop_restart_build_receipt *receipt;
    struct zcl_devloop_process_result *process;
    char *why;
    size_t why_len;
    bool guard_source;
    const struct dev_source_record *epoch_source;
    int64_t started;
    char root[PATH_MAX];
    struct rr_plan plan;
    struct dev_source_record source_before;
    const struct dev_source_record *identity;
};

static bool rr_restart_build_validate_inputs(struct rr_restart_build_ctx *ctx)
{
    if (!ctx->repo_root || !ctx->source_tus || !ctx->receipt || !ctx->process ||
        ctx->source_count == 0 || ctx->source_count > RR_SOURCE_MAX) {
        rr_why(ctx->why, ctx->why_len,
               "restart source set is empty or exceeds its bound");
        return false;
    }
    memset(ctx->receipt, 0, sizeof(*ctx->receipt));
    memset(ctx->process, 0, sizeof(*ctx->process));
    struct zcl_devloop_plan classification;
    if (!zcl_devloop_plan_files(ctx->source_tus, ctx->source_count,
                                &classification)) {
        rr_why(ctx->why, ctx->why_len, "restart source set is invalid");
        return false;
    }
    if (classification.consensus_risk) {
        rr_why(ctx->why, ctx->why_len,
               "consensus-risk input is excluded from fast restart");
        return false;
    }
    for (size_t i = 0; i < ctx->source_count; i++) {
        if (!rr_source_is_c(ctx->source_tus[i])) {
            rr_why(ctx->why, ctx->why_len,
                   "fast restart currently requires changed C translation units");
            return false;
        }
    }
    return true;
}

static bool rr_restart_build_resolve_root_and_plan(
    struct rr_restart_build_ctx *ctx)
{
    if (!platform_directory_canonical_real(ctx->repo_root, ctx->root,
                                           sizeof(ctx->root))) {
        rr_why(ctx->why, ctx->why_len,
               "restart checkout root could not be resolved");
        return false;
    }
    pthread_mutex_lock(&g_rr_mu);
    bool plan_ok = rr_plan_load_locked(ctx->root, &ctx->plan,
                                       &ctx->receipt->plan_cache_hit,
                                       &ctx->receipt->plan_load_us, ctx->why,
                                       ctx->why_len);
    pthread_mutex_unlock(&g_rr_mu);
    return plan_ok;
}

static bool rr_restart_build_capture_before(struct rr_restart_build_ctx *ctx)
{
    if (ctx->guard_source) ctx->receipt->source_guard_captures++;
    if (ctx->guard_source &&
        (!zcl_dev_source_cas_capture(ctx->root, &ctx->source_before) ||
         !ctx->source_before.cas_present)) {
        rr_why(ctx->why, ctx->why_len,
               "restart source snapshot could not be captured before compile");
        return false;
    }
    ctx->identity = ctx->epoch_source ? ctx->epoch_source
                                      : &ctx->source_before;
    if (!rr_source_record_valid(ctx->identity)) {
        rr_why(ctx->why, ctx->why_len,
               "restart epoch source CAS record is unavailable");
        return false;
    }
    (void)snprintf(ctx->receipt->source_cas_sha3,
                   sizeof(ctx->receipt->source_cas_sha3), "%s",
                   ctx->identity->cas_root_sha3);
    return true;
}

static bool rr_restart_build_compile_and_link(struct rr_restart_build_ctx *ctx)
{
    struct rr_overlay *overlays = zcl_calloc(RR_OVERLAY_MAX, sizeof(*overlays),
                                             "restart overlays");
    if (!overlays) {
        rr_why(ctx->why, ctx->why_len, "restart overlay allocation failed");
        return false;
    }
    const char *runtime_sources[RR_SOURCE_MAX];
    size_t runtime_source_count = 0;
    for (size_t i = 0; i < ctx->source_count; i++)
        if (!rr_source_is_test_only(ctx->source_tus[i]))
            runtime_sources[runtime_source_count++] = ctx->source_tus[i];
    if (runtime_source_count == 0) {
        free(overlays);
        rr_why(ctx->why, ctx->why_len,
               "restart source set contains no runtime translation unit");
        return false;
    }
    size_t overlay_count = 0;
    bool ok = rr_prepare_overlays(
        &ctx->plan, ctx->root, runtime_sources, runtime_source_count,
        ctx->identity, "build/dev-loop/restart-objects", overlays,
        &overlay_count, ctx->process, &ctx->receipt->compiler_processes,
        &ctx->receipt->compile_us, &ctx->receipt->compile_startup_us,
        &ctx->receipt->compile_body_us, ctx->why, ctx->why_len);
    ctx->receipt->source_identity_overlay = ok;
    char rsp[PATH_MAX] = {0};
    /* The runnable candidate build has no FOCUSED_GREEN verdict of its own
     * to gate; a stale-overlay fallback here surfaces at the proof step
     * below instead, where it is not silent. */
    bool unresolved = false;
    if (ok && !rr_write_response(&ctx->plan, ctx->root, overlays,
                                 overlay_count, "build/dev-loop/restart-objects",
                                 true, rsp, &unresolved, ctx->why, ctx->why_len))
        ok = false;
    if (ok) {
        ok = rr_link_cached(&ctx->plan, ctx->root, rsp,
                            "build/dev-loop/restart-candidates",
                            ctx->receipt->artifact_path,
                            ctx->receipt->artifact_cache_key,
                            &ctx->receipt->artifact_cache_hit,
                            &ctx->receipt->linker_processes,
                            &ctx->receipt->complete_graph_linker_processes, ctx->process,
                            &ctx->receipt->link_us,
                            &ctx->receipt->link_startup_us,
                            &ctx->receipt->link_body_us, ctx->why,
                            ctx->why_len);
    }
    if (rsp[0]) (void)unlink(rsp);
    free(overlays);
    if (!ok)
        ctx->receipt->total_us = platform_time_monotonic_us() - ctx->started;
    return ok;
}

static bool rr_restart_build_verify_after(struct rr_restart_build_ctx *ctx)
{
    if (ctx->guard_source) ctx->receipt->source_guard_captures++;
    struct dev_source_record source_after = {0};
    if (ctx->guard_source &&
        (!zcl_dev_source_cas_capture(ctx->root, &source_after) ||
         !source_after.cas_present ||
         strcmp(ctx->source_before.cas_root_sha3,
                source_after.cas_root_sha3) != 0)) {
        rr_why(ctx->why, ctx->why_len,
               "restart source snapshot changed during candidate build");
        ctx->receipt->total_us = platform_time_monotonic_us() - ctx->started;
        return false;
    }
    if (!rr_sha256_file(ctx->receipt->artifact_path,
                        ctx->receipt->artifact_sha256)) {
        rr_why(ctx->why, ctx->why_len,
               "restart candidate could not be rehashed");
        return false;
    }
    return true;
}

static void rr_restart_build_probe(struct rr_restart_build_ctx *ctx)
{
    const char *probe_argv[] = {
        ctx->receipt->artifact_path, "discover", "help", NULL
    };
    ctx->receipt->probe_processes = 1;
    int64_t probe_started = platform_time_monotonic_us();
    bool probed = zcl_devloop_process_run(ctx->root, probe_argv, 5000,
                                          ctx->process);
    ctx->receipt->probe_us = platform_time_monotonic_us() - probe_started;
    ctx->receipt->probe_startup_us = ctx->process->startup_us;
    ctx->receipt->probe_body_us = ctx->process->body_us;
    ctx->receipt->candidate_probe_passed = probed &&
        !ctx->process->timed_out && !ctx->process->term_signal &&
        ctx->process->exit_code == 0;
    (void)snprintf(ctx->receipt->probe, sizeof(ctx->receipt->probe), "%s",
                   "discover.help");
}

static bool rr_restart_build(
    const char *repo_root, const char *const *source_tus, size_t source_count,
    struct zcl_devloop_restart_build_receipt *receipt,
    struct zcl_devloop_process_result *process,
    char *why, size_t why_len, bool guard_source,
    const struct dev_source_record *epoch_source)
{
    struct rr_restart_build_ctx ctx = {
        .repo_root = repo_root, .source_tus = source_tus,
        .source_count = source_count, .receipt = receipt,
        .process = process, .why = why, .why_len = why_len,
        .guard_source = guard_source, .epoch_source = epoch_source,
        .started = platform_time_monotonic_us(),
    };
    if (why && why_len) why[0] = 0;
    if (!rr_restart_build_validate_inputs(&ctx))
        return false;
    if (!rr_restart_build_resolve_root_and_plan(&ctx))
        return false;
    if (!rr_restart_build_capture_before(&ctx))
        return false;
    if (!rr_restart_build_compile_and_link(&ctx))
        return false;
    if (!rr_restart_build_verify_after(&ctx))
        return false;
    rr_restart_build_probe(&ctx);
    receipt->changed_sources = (uint32_t)source_count;
    receipt->total_us = platform_time_monotonic_us() - ctx.started;
    if (!receipt->candidate_probe_passed) {
        rr_why(why, why_len, "restart candidate command-runtime probe failed");
        return false;
    }
    return true;
}

bool zcl_devloop_restart_build(
    const char *repo_root, const char *const *source_tus, size_t source_count,
    struct zcl_devloop_restart_build_receipt *receipt,
    struct zcl_devloop_process_result *process,
    char *why, size_t why_len)
{
    return rr_restart_build(repo_root, source_tus, source_count, receipt,
                            process, why, why_len, true, NULL);
}

static bool rr_append_group(char out[4096], const char *group)
{
    size_t used = strlen(out);
    int wrote = snprintf(out + used, 4096 - used, "%s%s",
                         used ? "," : "", group);
    return wrote > 0 && (size_t)wrote < 4096 - used;
}

static bool rr_collect_groups_expand(const struct zcl_devloop_plan *plan,
                                     char exact[][ZCL_TEST_GROUP_FULL_MAX],
                                     size_t *total_out,
                                     size_t *immediate_total_out,
                                     bool *truncated_out)
{
    const char *why = NULL;
    *truncated_out = false;
    if (!zcl_devloop_plan_proof_admissible(plan, &why))
        return false;
    /* A universal closure selects the whole catalog, whatever its listed
     * closure groups say; only the path floor can run in the foreground. */
    if (plan->closure_universal) {
        *total_out = zcl_test_group_catalog_count();
        *truncated_out = true;
        return false;
    }
    const char *ids[ZCL_DEVLOOP_MAX_PLAN_GROUPS * 2];
    size_t id_count = 0;
    for (size_t i = 0; i < plan->path_groups_len; i++)
        ids[id_count++] = plan->path_groups[i];
    for (size_t i = 0; i < plan->closure_groups_len; i++)
        ids[id_count++] = plan->closure_groups[i];
    bool truncated = false;
    size_t total = zcl_test_group_expand_plan(ids, id_count, exact,
                                               RR_EXACT_GROUP_MAX,
                                               &truncated);
    if (total == SIZE_MAX || total == 0)
        return false;
    *total_out = total;
    if (truncated) {
        *truncated_out = true;
        return false;
    }
    size_t immediate_total = 0;
    for (size_t i = 0; i < total; i++)
        if (!zcl_test_group_is_integration_only(exact[i]))
            immediate_total++;
    *immediate_total_out = immediate_total;
    return true;
}

static bool rr_collect_groups_is_path_owned(const struct zcl_devloop_plan *plan,
                                            const char *group)
{
    for (size_t p = 0; p < plan->path_groups_len; p++)
        if (zcl_test_group_plan_selects(plan->path_groups[p], group))
            return true;
    return false;
}

static bool rr_collect_groups_classify(
    const struct zcl_devloop_plan *plan, bool immediate_only,
    bool tier_closure, const char exact[][ZCL_TEST_GROUP_FULL_MAX],
    size_t total, char out[4096], uint32_t *count, char deferred[4096],
    uint32_t *deferred_count, bool *bounded_deferred)
{
    for (size_t i = 0; i < total; i++) {
        bool path_owned = rr_collect_groups_is_path_owned(plan, exact[i]);
        bool integration = zcl_test_group_is_integration_only(exact[i]);
        if (immediate_only && (integration || (tier_closure && !path_owned))) {
            if (!rr_append_group(deferred, exact[i])) return false;
            (*deferred_count)++;
            if (!integration)
                *bounded_deferred = true;
            continue;
        }
        if (!rr_append_group(out, exact[i])) return false;
        (*count)++;
    }
    return *count > 0;
}

/* The complete selection is too wide to enumerate here. The reflex can still
 * run the complete explicit path floor, exactly as it does when a narrower
 * closure exceeds the resident bound: select it on its own, record how many
 * groups the whole plan selects, and leave the rest to the conservative
 * proof. Nothing here claims more than group_count of groups_selected. */
static bool rr_collect_path_floor(const struct zcl_devloop_plan *plan,
                                  char exact[][ZCL_TEST_GROUP_FULL_MAX],
                                  size_t selected, char out[4096],
                                  uint32_t *count, uint32_t *deferred_count,
                                  bool *bounded_deferred)
{
    const char *ids[ZCL_DEVLOOP_MAX_PLAN_GROUPS];
    size_t id_count = 0;
    for (size_t i = 0; i < plan->path_groups_len; i++)
        ids[id_count++] = plan->path_groups[i];
    bool truncated = false;
    size_t floor_count = id_count ? zcl_test_group_expand_plan_immediate(
        ids, id_count, exact, RR_EXACT_GROUP_MAX, &truncated) : 0;
    if (floor_count == SIZE_MAX || floor_count == 0 || truncated ||
        floor_count >= selected)
        return false;
    for (size_t i = 0; i < floor_count; i++) {
        if (!rr_append_group(out, exact[i])) return false;
        (*count)++;
    }
    *deferred_count = (uint32_t)(selected - floor_count);
    *bounded_deferred = true;
    return true;
}

static bool rr_collect_groups(const struct zcl_devloop_plan *plan,
                              bool immediate_only,
                              char out[4096], uint32_t *count,
                              char deferred[4096], uint32_t *deferred_count,
                              bool *bounded_deferred, uint32_t *selected)
{
    if (!plan || !out || !count || !deferred || !deferred_count ||
        !bounded_deferred || !selected)
        return false;
    out[0] = 0;
    deferred[0] = 0;
    *count = 0;
    *deferred_count = 0;
    *bounded_deferred = false;
    *selected = 0;
    char exact[RR_EXACT_GROUP_MAX][ZCL_TEST_GROUP_FULL_MAX];
    size_t total = 0, immediate_total = 0;
    bool truncated = false;
    if (!rr_collect_groups_expand(plan, exact, &total, &immediate_total,
                                  &truncated)) {
        if (!immediate_only || !truncated || total > UINT32_MAX)
            return false;
        *selected = (uint32_t)total;
        return rr_collect_path_floor(plan, exact, total, out, count,
                                     deferred_count, bounded_deferred);
    }
    *selected = (uint32_t)total;
    bool tier_closure = immediate_only &&
        immediate_total > RR_IMMEDIATE_GROUP_MAX;
    return rr_collect_groups_classify(plan, immediate_only, tier_closure,
                                      exact, total, out, count, deferred,
                                      deferred_count, bounded_deferred);
}

/* How many non-integration groups the whole plan selects: the size a
 * complete focused run has to reach. */
static uint32_t rr_immediate_selected(const struct zcl_devloop_plan *plan)
{
    size_t n = 0;
    if (plan->closure_universal) {
        for (size_t i = 0; i < zcl_test_group_catalog_count(); i++)
            n += zcl_test_group_is_integration_only(
                     zcl_test_group_catalog_at(i)) ? 0u : 1u;
    } else {
        const char *ids[ZCL_DEVLOOP_MAX_PLAN_GROUPS * 2];
        size_t id_count = 0;
        for (size_t i = 0; i < plan->path_groups_len; i++)
            ids[id_count++] = plan->path_groups[i];
        for (size_t i = 0; i < plan->closure_groups_len; i++)
            ids[id_count++] = plan->closure_groups[i];
        bool truncated = false;
        n = zcl_test_group_expand_plan_immediate(ids, id_count, NULL, 0,
                                                 &truncated);
    }
    return n == SIZE_MAX ? 0u : n > UINT32_MAX ? UINT32_MAX : (uint32_t)n;
}

static bool rr_plan_matches_sources(const struct zcl_devloop_plan *plan,
                                    const char *const *sources,
                                    size_t source_count)
{
    struct zcl_devloop_plan expected;
    if (!plan || plan->file_count != source_count ||
        !zcl_devloop_plan_files(sources, source_count, &expected) ||
        expected.consensus_risk || expected.docs_only ||
        expected.path_groups_len != plan->path_groups_len)
        return false;
    for (size_t i = 0; i < expected.path_groups_len; i++)
        if (strcmp(expected.path_groups[i], plan->path_groups[i]) != 0)
            return false;
    return true;
}

static bool rr_summary_value(const char *summary, const char *key,
                             uint32_t *out)
{
    if (!summary || !key || !out) return false;
    const char *line = strstr(summary, "SUITE VERDICT ");
    if (!line) return false;
    const char *at = strstr(line, key);
    if (!at) return false;
    at += strlen(key);
    if (*at < '0' || *at > '9') return false;
    errno = 0;
    char *end = NULL;
    unsigned long value = strtoul(at, &end, 10);
    if (errno || !end || end == at || value > UINT32_MAX ||
        (*end != ' ' && *end != '\n' && *end != 0))
        return false;
    *out = (uint32_t)value;
    return true;
}

static bool rr_group_list_contains(const char *groups, const char *group)
{
    if (!groups || !group || !group[0]) return false;
    size_t want = strlen(group);
    for (const char *at = groups; *at;) {
        const char *end = strchr(at, ',');
        size_t len = end ? (size_t)(end - at) : strlen(at);
        if (len == want && memcmp(at, group, want) == 0)
            return true;
        if (!end) break;
        at = end + 1;
    }
    return false;
}

static bool rr_failure_priority_select(
    const char *root, const char *groups, const char *direct_group,
    char out[ZCL_TEST_GROUP_FULL_MAX], char reason[64])
{
    bool previous = false;
    pthread_mutex_lock(&g_rr_mu);
    if (g_rr_failure_priority.present &&
        strcmp(g_rr_failure_priority.root, root) == 0 &&
        rr_group_list_contains(groups, g_rr_failure_priority.group)) {
        (void)snprintf(out, ZCL_TEST_GROUP_FULL_MAX, "%s",
                       g_rr_failure_priority.group);
        previous = true;
    }
    pthread_mutex_unlock(&g_rr_mu);
    if (previous) {
        (void)snprintf(reason, 64, "%s", "previous_failure");
        return true;
    }
    if (!direct_group || !rr_group_list_contains(groups, direct_group))
        return false;
    (void)snprintf(out, ZCL_TEST_GROUP_FULL_MAX, "%s", direct_group);
    (void)snprintf(reason, 64, "%s", "direct_owner_invariant");
    return true;
}

static void rr_failure_priority_store(const char *root, const char *group)
{
    if (!root || !group || !group[0])
        return;
    pthread_mutex_lock(&g_rr_mu);
    (void)snprintf(g_rr_failure_priority.root,
                   sizeof(g_rr_failure_priority.root), "%s", root);
    (void)snprintf(g_rr_failure_priority.group,
                   sizeof(g_rr_failure_priority.group), "%s", group);
    g_rr_failure_priority.present = true;
    pthread_mutex_unlock(&g_rr_mu);
}

static void rr_failure_priority_clear(const char *root, const char *group)
{
    pthread_mutex_lock(&g_rr_mu);
    if (g_rr_failure_priority.present && root && group &&
        strcmp(g_rr_failure_priority.root, root) == 0 &&
        strcmp(g_rr_failure_priority.group, group) == 0)
        memset(&g_rr_failure_priority, 0, sizeof(g_rr_failure_priority));
    pthread_mutex_unlock(&g_rr_mu);
}

static bool rr_failed_group_from_output(
    const char *output, const char *selected_groups,
    char out[ZCL_TEST_GROUP_FULL_MAX])
{
    static const char marker[] = "Failed groups:\n";
    const char *section = output ? strstr(output, marker) : NULL;
    if (!section)
        return false;
    section += sizeof(marker) - 1;
    if (strncmp(section, "  - ", 4) != 0)
        return false;
    const char *name = section + 4;
    const char *colon = strchr(name, ':');
    size_t len = colon ? (size_t)(colon - name) : 0;
    if (len == 0 || len >= ZCL_TEST_GROUP_FULL_MAX)
        return false;
    char candidate[ZCL_TEST_GROUP_FULL_MAX];
    memcpy(candidate, name, len);
    candidate[len] = 0;
    if (!rr_group_list_contains(selected_groups, candidate))
        return false;
    (void)snprintf(out, ZCL_TEST_GROUP_FULL_MAX, "%s", candidate);
    return true;
}

struct rr_prove_ctx {
    const char *repo_root;
    const char *const *source_tus;
    size_t source_count;
    const struct zcl_devloop_plan *proof_plan;
    struct zcl_devloop_restart_proof_receipt *receipt;
    struct zcl_devloop_process_result *process;
    char *why;
    size_t why_len;
    bool immediate_only;
    bool guard_source;
    const struct dev_source_record *epoch_source;
    /* The early feedback stage (devloop_early.h); NULL receipt: none. */
    const struct zcl_devloop_early_plan *early_plan;
    struct zcl_devloop_early_receipt *early;
    int64_t started;
    char root[PATH_MAX];
    struct rr_plan plan;
    struct dev_source_record source_before;
    const struct dev_source_record *identity;
};

static bool rr_prove_validate_inputs(struct rr_prove_ctx *ctx)
{
    if (!ctx->repo_root || !ctx->source_tus || !ctx->proof_plan ||
        !ctx->receipt || !ctx->process || ctx->source_count == 0 ||
        ctx->source_count > RR_SOURCE_MAX) {
        rr_why(ctx->why, ctx->why_len, "restart proof source set is invalid");
        return false;
    }
    memset(ctx->receipt, 0, sizeof(*ctx->receipt));
    memset(ctx->process, 0, sizeof(*ctx->process));
    return true;
}

static bool rr_prove_select_groups(struct rr_prove_ctx *ctx)
{
    int64_t selection_started = platform_time_monotonic_us();
    if (!rr_plan_matches_sources(ctx->proof_plan, ctx->source_tus,
                                 ctx->source_count)) {
        rr_why(ctx->why, ctx->why_len,
               "affected proof plan does not match the changed source set");
        return false;
    }
    if (!rr_collect_groups(ctx->proof_plan, ctx->immediate_only,
                           ctx->receipt->groups, &ctx->receipt->group_count,
                           ctx->receipt->deferred_groups,
                           &ctx->receipt->deferred_group_count,
                           &ctx->receipt->bounded_proof_deferred,
                           &ctx->receipt->groups_selected)) {
        rr_why(ctx->why, ctx->why_len,
               "affected proof plan is incomplete or has no exact groups");
        return false;
    }
    if (ctx->immediate_only &&
        ctx->receipt->group_count > RR_IMMEDIATE_GROUP_MAX) {
        rr_why(ctx->why, ctx->why_len,
               "affected immediate proof set exceeds resident bound");
        return false;
    }
    ctx->receipt->groups_immediate_selected =
        rr_immediate_selected(ctx->proof_plan);
    rr_sha256_bytes(ctx->receipt->groups, strlen(ctx->receipt->groups),
                    ctx->receipt->groups_sha256);
    if (ctx->receipt->deferred_groups[0])
        rr_sha256_bytes(ctx->receipt->deferred_groups,
                        strlen(ctx->receipt->deferred_groups),
                        ctx->receipt->deferred_groups_sha256);
    for (size_t i = 0; i < ctx->source_count; i++) {
        if (!rr_source_is_c(ctx->source_tus[i])) {
            rr_why(ctx->why, ctx->why_len,
                   "restart proof requires changed C translation units");
            return false;
        }
    }
    ctx->receipt->selection_us =
        platform_time_monotonic_us() - selection_started;
    return true;
}

static bool rr_prove_resolve_plan(struct rr_prove_ctx *ctx)
{
    if (!platform_directory_canonical_real(ctx->repo_root, ctx->root,
                                           sizeof(ctx->root))) {
        rr_why(ctx->why, ctx->why_len,
               "restart proof checkout root could not be resolved");
        return false;
    }
    struct rr_plan base = {0};
    bool cache_hit = false;
    int64_t plan_us = 0;
    pthread_mutex_lock(&g_rr_mu);
    bool plan_ok = rr_plan_load_locked(ctx->root, &base, &cache_hit, &plan_us,
                                       ctx->why, ctx->why_len);
    pthread_mutex_unlock(&g_rr_mu);
    (void)cache_hit;
    (void)plan_us;
    if (!plan_ok) return false;

    ctx->plan = base;
    (void)snprintf(ctx->plan.cflags, sizeof(ctx->plan.cflags), "%s",
                   base.test_cflags);
    (void)snprintf(ctx->plan.ldflags, sizeof(ctx->plan.ldflags), "%s",
                   base.test_ldflags);
    (void)snprintf(ctx->plan.libs, sizeof(ctx->plan.libs), "%s",
                   base.test_libs);
    (void)snprintf(ctx->plan.obj_dir, sizeof(ctx->plan.obj_dir), "%s",
                   base.test_obj_dir);
    (void)snprintf(ctx->plan.link_rsp, sizeof(ctx->plan.link_rsp), "%s",
                   base.test_link_rsp);
    (void)snprintf(ctx->plan.base_reloc, sizeof(ctx->plan.base_reloc), "%s",
                   base.test_base_reloc);
    return true;
}

static bool rr_prove_capture_before(struct rr_prove_ctx *ctx)
{
    if (ctx->guard_source) ctx->receipt->source_guard_captures++;
    if (ctx->guard_source &&
        (!zcl_dev_source_cas_capture(ctx->root, &ctx->source_before) ||
         !ctx->source_before.cas_present)) {
        rr_why(ctx->why, ctx->why_len,
               "proof source snapshot could not be captured before compile");
        return false;
    }
    ctx->identity = ctx->epoch_source ? ctx->epoch_source
                                      : &ctx->source_before;
    if (!rr_source_record_valid(ctx->identity)) {
        rr_why(ctx->why, ctx->why_len,
               "proof epoch source CAS record is unavailable");
        return false;
    }
    (void)snprintf(ctx->receipt->source_cas_sha3,
                   sizeof(ctx->receipt->source_cas_sha3), "%s",
                   ctx->identity->cas_root_sha3);
    return true;
}

static bool rr_prove_compile_and_link(struct rr_prove_ctx *ctx)
{
    struct rr_overlay *overlays = zcl_calloc(RR_OVERLAY_MAX, sizeof(*overlays),
                                             "restart proof overlays");
    if (!overlays) {
        rr_why(ctx->why, ctx->why_len,
               "restart proof overlay allocation failed");
        return false;
    }
    size_t overlay_count = 0;
    bool ok = rr_prepare_overlays(
        &ctx->plan, ctx->root, ctx->source_tus, ctx->source_count,
        ctx->identity, "build/dev-loop/restart-test-objects", overlays,
        &overlay_count, ctx->process, &ctx->receipt->compiler_processes,
        &ctx->receipt->compile_us, &ctx->receipt->compile_startup_us,
        &ctx->receipt->compile_body_us, ctx->why, ctx->why_len);
    ctx->receipt->source_identity_overlay = ok;
    char rsp[PATH_MAX] = {0};
    bool unresolved = false;
    if (ok && !rr_write_response(&ctx->plan, ctx->root, overlays,
                                 overlay_count,
                                 "build/dev-loop/restart-test-objects", false,
                                 rsp, &unresolved, ctx->why, ctx->why_len))
        ok = false;
    /* Fail closed: a proof whose link silently fell back to a stale base
     * object for a source with an unverified persistent overlay must not
     * be reported to the caller as trustworthy. */
    ctx->receipt->source_overlay_unresolved = unresolved;
    if (ok) {
        ok = rr_link_cached(&ctx->plan, ctx->root, rsp,
                            "build/dev-loop/restart-test-candidates",
                            ctx->receipt->artifact_path,
                            ctx->receipt->artifact_cache_key,
                            &ctx->receipt->artifact_cache_hit,
                            &ctx->receipt->linker_processes,
                            &ctx->receipt->complete_graph_linker_processes, ctx->process,
                            &ctx->receipt->link_us,
                            &ctx->receipt->link_startup_us,
                            &ctx->receipt->link_body_us, ctx->why,
                            ctx->why_len);
    }
    if (rsp[0]) (void)unlink(rsp);
    free(overlays);
    if (!ok)
        ctx->receipt->total_us = platform_time_monotonic_us() - ctx->started;
    return ok;
}

/* The receipt names the executed bytes by their SHA-256 at rehash and by the
 * inode that held them. A run is attributed to that hash only while the same
 * inode still sits at the candidate path afterwards. */
struct rr_artifact_stamp {
    uint64_t dev, ino, size;
    int64_t ctime_sec, ctime_nsec;
};

static bool rr_artifact_identity(const char *path,
                                 struct rr_artifact_stamp *out)
{
    memset(out, 0, sizeof(*out));
#if defined(_WIN32)
    return rr_regular(path, NULL);
#else
    rr_file_stamp st;
    if (!rr_regular(path, &st))
        return false;
    out->dev = (uint64_t)st.st_dev;
    out->ino = (uint64_t)st.st_ino;
    out->size = (uint64_t)st.st_size;
#if defined(__APPLE__)
    out->ctime_sec = (int64_t)st.st_ctimespec.tv_sec;
    out->ctime_nsec = (int64_t)st.st_ctimespec.tv_nsec;
#else
    out->ctime_sec = (int64_t)st.st_ctim.tv_sec;
    out->ctime_nsec = (int64_t)st.st_ctim.tv_nsec;
#endif
    return true;
#endif
}

static bool rr_prove_capture_identity(struct rr_prove_ctx *ctx)
{
    struct rr_artifact_stamp stamp;
    if (!rr_artifact_identity(ctx->receipt->artifact_path, &stamp))
        return false;
    ctx->receipt->artifact_dev = stamp.dev;
    ctx->receipt->artifact_ino = stamp.ino;
    ctx->receipt->artifact_size = stamp.size;
    ctx->receipt->artifact_ctime_sec = stamp.ctime_sec;
    ctx->receipt->artifact_ctime_nsec = stamp.ctime_nsec;
    return true;
}

static bool rr_stamp_matches_receipt(
    const struct rr_artifact_stamp *stamp,
    const struct zcl_devloop_restart_proof_receipt *receipt)
{
    return stamp->dev == receipt->artifact_dev &&
        stamp->ino == receipt->artifact_ino &&
        stamp->size == receipt->artifact_size &&
        stamp->ctime_sec == receipt->artifact_ctime_sec &&
        stamp->ctime_nsec == receipt->artifact_ctime_nsec;
}

/* Any result, green or red, is attributed to the rehashed bytes only while
 * the same unmodified inode still sits at the candidate path. */
static bool rr_prove_recheck_identity(struct rr_prove_ctx *ctx)
{
    struct rr_artifact_stamp stamp;
    if (rr_artifact_identity(ctx->receipt->artifact_path, &stamp) &&
        rr_stamp_matches_receipt(&stamp, ctx->receipt))
        return true;
    ctx->receipt->immediate_proof_complete = false;
    ctx->receipt->proof_complete = false;
    rr_why(ctx->why, ctx->why_len,
           "affected proof candidate was replaced during its run");
    fprintf(stderr, "[devloop] restart proof: candidate %s changed identity "
            "during its run\n", ctx->receipt->artifact_path);
    return false;
}

static bool rr_prove_verify_after(struct rr_prove_ctx *ctx)
{
    if (ctx->guard_source) ctx->receipt->source_guard_captures++;
    struct dev_source_record source_after = {0};
    if ((ctx->guard_source &&
         (!zcl_dev_source_cas_capture(ctx->root, &source_after) ||
          !source_after.cas_present ||
          strcmp(ctx->source_before.cas_root_sha3,
                 source_after.cas_root_sha3) != 0)) ||
        !rr_prove_capture_identity(ctx) ||
        !rr_sha256_file(ctx->receipt->artifact_path,
                        ctx->receipt->artifact_sha256) ||
        !rr_prove_recheck_identity(ctx)) {
        rr_why(ctx->why, ctx->why_len,
               "proof source changed or its candidate could not be rehashed");
        ctx->receipt->total_us = platform_time_monotonic_us() - ctx->started;
        return false;
    }
    return true;
}

struct rr_prove_test_args {
    char exact[4096 + 16];
    const char *argv[RR_SOURCE_MAX + 5];
    char changed[RR_SOURCE_MAX][ZCL_DEVLOOP_PATH_MAX + 24];
    size_t argc;
};

/* The exact story has already run in HOT_SHADOW. Within affected proof,
 * run the last RED for this checkout/task first when it is still selected;
 * otherwise run the direct owner invariant. The complete batch still runs
 * afterward and accounts for every required group. */
static bool rr_prove_build_test_args(struct rr_prove_ctx *ctx,
                                     struct rr_prove_test_args *ta)
{
    if (snprintf(ta->exact, sizeof(ta->exact), "--exact=%s",
                ctx->receipt->groups) >= (int)sizeof(ta->exact)) {
        rr_why(ctx->why, ctx->why_len,
               "affected proof selector exceeds its bound");
        return false;
    }
    ta->argv[0] = ctx->receipt->artifact_path;
    ta->argv[1] = ta->exact;
    ta->argv[2] = "--cache";
    ta->argv[3] = "--cache-snapshot";
    ta->argc = 4;
    for (size_t i = 0; i < ctx->source_count; i++) {
        if (snprintf(ta->changed[i], sizeof(ta->changed[i]),
                     "--changed-source=%s", ctx->source_tus[i]) >=
            (int)sizeof(ta->changed[i])) {
            rr_why(ctx->why, ctx->why_len,
                   "changed source selector exceeds its bound");
            return false;
        }
        ta->argv[ta->argc++] = ta->changed[i];
    }
    ta->argv[ta->argc] = NULL;
    return true;
}

static bool rr_prove_priority_run_and_parse(
    const char *root, const char **priority_argv,
    struct zcl_devloop_process_result *priority_process,
    uint32_t *ran_count, uint32_t *cached, uint32_t *failed, uint32_t *skips)
{
    bool priority_ran = zcl_devloop_process_run_test(
        root, priority_argv, RR_PROOF_TIMEOUT_MS, priority_process);
    bool priority_summary = priority_ran &&
        rr_summary_value(priority_process->output, "groups_ran=",
                         ran_count) &&
        rr_summary_value(priority_process->output, "groups_cached=",
                         cached) &&
        rr_summary_value(priority_process->output, "groups_failed=",
                         failed) &&
        rr_summary_value(priority_process->output, "self_skips=", skips);
    return priority_summary && !priority_process->timed_out &&
        !priority_process->term_signal && priority_process->exit_code == 0 &&
        *ran_count + *cached == 1 && *failed == 0 && *skips == 0;
}

/* Name the priority group and the reason it ran first, so a stale
 * previous_failure group cannot read as a verdict on the unrelated edit
 * that triggered this restart. */
static void rr_prove_priority_why(char *why, size_t why_len,
                                  const char *reason, const char *group)
{
    if (!why || !why_len)
        return;
    if (strcmp(reason, "previous_failure") == 0) {
        (void)snprintf(why, why_len,
                       "previously failing group %s is still red (runs "
                       "first until it passes)",
                       group);
        return;
    }
    (void)snprintf(why, why_len,
                   "failure-first direct owner group %s failed", group);
}

static bool rr_prove_run_priority(struct rr_prove_ctx *ctx,
                                  struct rr_prove_test_args *ta)
{
    char direct_full[ZCL_TEST_GROUP_FULL_MAX] = {0};
    const char *direct_group = ctx->proof_plan->proof_group &&
        zcl_test_group_resolve_exact(ctx->proof_plan->proof_group,
                                     direct_full)
            ? direct_full : NULL;
    char priority_full[ZCL_TEST_GROUP_FULL_MAX] = {0};
    char priority_reason[64] = {0};
    bool have_priority = rr_failure_priority_select(
        ctx->root, ctx->receipt->groups, direct_group, priority_full,
        priority_reason);
    if (!have_priority)
        return true;
    char priority_exact[ZCL_TEST_GROUP_FULL_MAX + 16];
    if (snprintf(priority_exact, sizeof(priority_exact), "--exact=%s",
                priority_full) >= (int)sizeof(priority_exact)) {
        rr_why(ctx->why, ctx->why_len,
               "priority group selector exceeds its bound");
        return false;
    }
    const char *priority_argv[RR_SOURCE_MAX + 5] = {
        ctx->receipt->artifact_path, priority_exact, "--cache",
        "--cache-snapshot",
    };
    for (size_t i = 0; i < ctx->source_count; i++)
        priority_argv[4 + i] = ta->changed[i];
    priority_argv[4 + ctx->source_count] = NULL;
    struct zcl_devloop_process_result priority_process = {0};
    int64_t priority_started = platform_time_monotonic_us();
    ctx->receipt->test_processes++;
    uint32_t priority_ran_count = 0, priority_cached = 0;
    uint32_t priority_failed = 0, priority_skips = 0;
    bool priority_ok = rr_prove_priority_run_and_parse(
        ctx->root, priority_argv, &priority_process, &priority_ran_count,
        &priority_cached, &priority_failed, &priority_skips);
    ctx->receipt->priority_test_us =
        platform_time_monotonic_us() - priority_started;
    (void)snprintf(ctx->receipt->priority_group,
                   sizeof(ctx->receipt->priority_group), "%s", priority_full);
    (void)snprintf(ctx->receipt->priority_reason,
                   sizeof(ctx->receipt->priority_reason), "%s",
                   priority_reason);
    if (!priority_ok) {
        if (!priority_process.cancelled)
            rr_failure_priority_store(ctx->root, priority_full);
        *ctx->process = priority_process;
        ctx->receipt->test_us += ctx->receipt->priority_test_us;
        ctx->receipt->test_startup_us += priority_process.startup_us;
        ctx->receipt->test_body_us += priority_process.body_us;
        ctx->receipt->groups_ran = priority_ran_count;
        ctx->receipt->groups_cached = priority_cached;
        ctx->receipt->groups_failed = priority_failed;
        ctx->receipt->self_skips = priority_skips;
        ctx->receipt->total_us = platform_time_monotonic_us() - ctx->started;
        rr_prove_priority_why(ctx->why, ctx->why_len, priority_reason,
                              priority_full);
        return false;
    }
    if (strcmp(priority_reason, "previous_failure") == 0)
        rr_failure_priority_clear(ctx->root, priority_full);
    return true;
}

static void rr_prove_run_main_test(struct rr_prove_ctx *ctx,
                                   struct rr_prove_test_args *ta,
                                   bool *ran_out, bool *summary_ok_out,
                                   bool *accounted_out)
{
    ctx->receipt->test_processes++;
    int64_t test_started = platform_time_monotonic_us();
    bool ran = zcl_devloop_process_run_test(ctx->root, ta->argv, RR_PROOF_TIMEOUT_MS,
                                            ctx->process);
    ctx->receipt->test_us += platform_time_monotonic_us() - test_started;
    ctx->receipt->test_startup_us += ctx->process->startup_us;
    ctx->receipt->test_body_us += ctx->process->body_us;
    bool summary_ok = ran &&
        rr_summary_value(ctx->process->output, "groups_ran=",
                         &ctx->receipt->groups_ran) &&
        rr_summary_value(ctx->process->output, "groups_cached=",
                         &ctx->receipt->groups_cached) &&
        rr_summary_value(ctx->process->output, "groups_failed=",
                         &ctx->receipt->groups_failed) &&
        rr_summary_value(ctx->process->output, "self_skips=",
                         &ctx->receipt->self_skips);
    bool accounted = summary_ok &&
        ctx->receipt->groups_ran <= ctx->receipt->group_count &&
        ctx->receipt->groups_cached ==
            ctx->receipt->group_count - ctx->receipt->groups_ran;
    ctx->receipt->immediate_proof_complete = ran && !ctx->process->timed_out &&
        !ctx->process->term_signal && ctx->process->exit_code == 0 &&
        accounted && ctx->receipt->groups_failed == 0 &&
        ctx->receipt->self_skips == 0;
    ctx->receipt->integration_proof_deferred =
        ctx->receipt->deferred_group_count > 0;
    ctx->receipt->proof_complete = ctx->receipt->immediate_proof_complete &&
        !ctx->receipt->integration_proof_deferred &&
        !ctx->receipt->source_overlay_unresolved;
    ctx->receipt->total_us = platform_time_monotonic_us() - ctx->started;
    *ran_out = ran;
    *summary_ok_out = summary_ok;
    *accounted_out = accounted;
}

static void rr_prove_report_failure(struct rr_prove_ctx *ctx, bool ran,
                                    bool summary_ok, bool accounted)
{
    char failed_group[ZCL_TEST_GROUP_FULL_MAX];
    if (!ctx->process->cancelled && rr_failed_group_from_output(
            ctx->process->output, ctx->receipt->groups, failed_group))
        rr_failure_priority_store(ctx->root, failed_group);
    char detail[256];
    if (!ran) {
        rr_why(ctx->why, ctx->why_len,
               "affected proof runner could not be executed");
    } else if (ctx->process->timed_out) {
        (void)snprintf(detail, sizeof(detail),
                       "affected proof runner exceeded the %d ms bound",
                       RR_PROOF_TIMEOUT_MS);
        rr_why(ctx->why, ctx->why_len, detail);
    } else if (ctx->process->term_signal) {
        (void)snprintf(detail, sizeof(detail),
                       "affected proof runner terminated by signal %d",
                       ctx->process->term_signal);
        rr_why(ctx->why, ctx->why_len, detail);
    } else if (summary_ok && ctx->receipt->groups_failed > 0) {
        (void)snprintf(
            detail, sizeof(detail),
            "affected proofs failed: %u of %u exact groups failed; see process_output",
            ctx->receipt->groups_failed, ctx->receipt->group_count);
        rr_why(ctx->why, ctx->why_len, detail);
    } else if (summary_ok && ctx->receipt->self_skips > 0) {
        (void)snprintf(
            detail, sizeof(detail),
            "affected proofs incomplete: %u exact groups self-skipped; see process_output",
            ctx->receipt->self_skips);
        rr_why(ctx->why, ctx->why_len, detail);
    } else if (!summary_ok) {
        rr_why(ctx->why, ctx->why_len,
               "affected proof runner omitted the canonical suite summary");
    } else if (!accounted) {
        rr_why(ctx->why, ctx->why_len,
               "affected proof runner did not account for every exact group");
    } else {
        (void)snprintf(
            detail, sizeof(detail),
            "affected proof runner exited %d despite a zero-failure summary",
            ctx->process->exit_code);
        rr_why(ctx->why, ctx->why_len, detail);
    }
}

/* Priority and main runs, then one identity check that covers every result:
 * a replaced candidate voids a red as surely as a green. */
static bool rr_prove_run_tests(struct rr_prove_ctx *ctx,
                               struct rr_prove_test_args *ta)
{
    bool priority_ok = rr_prove_run_priority(ctx, ta);
    bool ran = false, summary_ok = false, accounted = false;
    if (priority_ok)
        rr_prove_run_main_test(ctx, ta, &ran, &summary_ok, &accounted);
    if (!rr_prove_recheck_identity(ctx))
        return false;
    if (!priority_ok)
        return false;
    if (!ctx->receipt->immediate_proof_complete) {
        rr_prove_report_failure(ctx, ran, summary_ok, accounted);
        return false;
    }
    return true;
}

/* FEEDBACK ONLY. After the full plan was admitted and selected and its
 * candidate rehashed, the facts groups run on those same bytes before the
 * full plan does. The stage reads the selected groups only to skip a set
 * that would merely repeat them; it never writes the proof receipt, the
 * test cache (its runner gets --no-cache) or the failure-first store, so
 * the full plan runs exactly as it would without it. */
static void rr_prove_run_early(struct rr_prove_ctx *ctx)
{
    if (!ctx->early)
        return;
    /* What the candidate was built from keys the stage's closure-unchanged
     * skipping; it reads nothing the full plan reads afterwards. */
    const struct zcl_devloop_early_toolchain tc = {
        .compiler_id = ctx->plan.compiler_id,
        .base_generation = ctx->plan.base_generation,
        .cflags = ctx->plan.cflags,
        .ldflags = ctx->plan.ldflags,
        .libs = ctx->plan.libs,
        .sources = ctx->source_tus,
        .source_count = ctx->source_count,
    };
    zcl_devloop_early_run_keyed(ctx->root, ctx->receipt->artifact_path,
                                ctx->receipt->artifact_sha256,
                                ctx->early_plan, ctx->receipt->groups,
                                ctx->started, &tc, ctx->early);
}

/* The full plan's measures beside the early stage's, from the same
 * origin. */
static bool rr_prove_run_full(struct rr_prove_ctx *ctx,
                              struct rr_prove_test_args *ta)
{
    int64_t full_started = platform_time_monotonic_us();
    bool ok = rr_prove_run_tests(ctx, ta);
    if (ctx->early) {
        ctx->early->full_first_exec_us =
            full_started - (ctx->early->origin_us ? ctx->early->origin_us
                                                  : ctx->started);
        ctx->early->full_wall_us = platform_time_monotonic_us() - full_started;
    }
    return ok;
}

struct rr_prove_early_io {
    const struct zcl_devloop_early_plan *plan;
    struct zcl_devloop_early_receipt *receipt;
};

static bool rr_restart_prove(
    const char *repo_root, const char *const *source_tus, size_t source_count,
    const struct zcl_devloop_plan *proof_plan,
    struct zcl_devloop_restart_proof_receipt *receipt,
    struct zcl_devloop_process_result *process,
    char *why, size_t why_len, bool immediate_only, bool guard_source,
    const struct dev_source_record *epoch_source,
    struct rr_prove_early_io early)
{
    struct rr_prove_ctx ctx = {
        .repo_root = repo_root, .source_tus = source_tus,
        .source_count = source_count, .proof_plan = proof_plan,
        .receipt = receipt, .process = process, .why = why,
        .why_len = why_len, .immediate_only = immediate_only,
        .guard_source = guard_source, .epoch_source = epoch_source,
        .early_plan = early.plan, .early = early.receipt,
        .started = platform_time_monotonic_us(),
    };
    if (why && why_len) why[0] = 0;
    if (early.receipt) {
        memset(early.receipt, 0, sizeof(*early.receipt));
        zcl_devloop_early_skip(early.receipt, "full_plan_not_reached", "");
    }
    if (!rr_prove_validate_inputs(&ctx))
        return false;
    if (!rr_prove_select_groups(&ctx))
        return false;
    if (!rr_prove_resolve_plan(&ctx))
        return false;
    if (!rr_prove_capture_before(&ctx))
        return false;
    if (!rr_prove_compile_and_link(&ctx))
        return false;
    if (!rr_prove_verify_after(&ctx))
        return false;
    struct rr_prove_test_args ta = {0};
    if (!rr_prove_build_test_args(&ctx, &ta))
        return false;
    rr_prove_run_early(&ctx);
    return rr_prove_run_full(&ctx, &ta);
}

static const struct rr_prove_early_io k_rr_no_early = {0};

bool zcl_devloop_restart_prove(
    const char *repo_root, const char *const *source_tus, size_t source_count,
    const struct zcl_devloop_plan *proof_plan,
    struct zcl_devloop_restart_proof_receipt *receipt,
    struct zcl_devloop_process_result *process,
    char *why, size_t why_len)
{
    return rr_restart_prove(repo_root, source_tus, source_count, proof_plan,
                            receipt, process, why, why_len, false, true, NULL,
                            k_rr_no_early);
}

bool zcl_devloop_restart_prove_immediate(
    const char *repo_root, const char *const *source_tus, size_t source_count,
    const struct zcl_devloop_plan *proof_plan,
    struct zcl_devloop_restart_proof_receipt *receipt,
    struct zcl_devloop_process_result *process,
    char *why, size_t why_len)
{
    return rr_restart_prove(repo_root, source_tus, source_count, proof_plan,
                            receipt, process, why, why_len, true, true, NULL,
                            k_rr_no_early);
}

bool zcl_devloop_restart_prove_early(
    const char *repo_root, const char *const *source_tus, size_t source_count,
    const struct zcl_devloop_plan *proof_plan,
    const struct zcl_devloop_early_plan *early_plan,
    struct zcl_devloop_restart_proof_receipt *receipt,
    struct zcl_devloop_early_receipt *early,
    struct zcl_devloop_process_result *process, char *why, size_t why_len)
{
    struct rr_prove_early_io io = { .plan = early_plan, .receipt = early };
    return rr_restart_prove(repo_root, source_tus, source_count, proof_plan,
                            receipt, process, why, why_len, false, true, NULL,
                            io);
}

static void rr_output_preview(const struct zcl_devloop_process_result *process,
                              char out[1025])
{
    size_t n = process ? process->output_len : 0;
    if (n > 1024) n = 1024;
    if (n) memcpy(out, process->output + process->output_len - n, n);
    out[n] = 0;
}

static void rr_emit_event_source_bytes(struct json_value *doc,
                                       const char *root,
                                       const char *const *sources,
                                       size_t source_count,
                                       uint64_t source_guard_bytes_read,
                                       uint64_t source_bytes_total,
                                       bool source_byte_accounting_complete)
{
    uint64_t changed_source_bytes = 0;
    bool changed_bytes_complete = true;
    for (size_t i = 0; i < source_count; i++) {
        char full[PATH_MAX];
        rr_file_stamp stamp;
        uint64_t size = 0, next = 0;
        if (!rr_join_root(root, sources[i], full) ||
            !rr_regular(full, &stamp) || !rr_stamp_size(&stamp, &size) ||
            !zcl_u64_add(changed_source_bytes, size, &next)) {
            changed_bytes_complete = false;
            break;
        }
        changed_source_bytes = next;
    }
    source_byte_accounting_complete = source_byte_accounting_complete &&
        changed_bytes_complete && source_guard_bytes_read <= INT64_MAX &&
        source_bytes_total <= INT64_MAX && changed_source_bytes <= INT64_MAX;
    (void)json_push_kv_bool(doc, "source_byte_accounting_complete",
                            source_byte_accounting_complete);
    if (source_byte_accounting_complete) {
        (void)json_push_kv_int(doc, "source_guard_bytes_read",
                               (int64_t)source_guard_bytes_read);
        (void)json_push_kv_int(doc, "source_bytes_total",
                               (int64_t)source_bytes_total);
        (void)json_push_kv_int(doc, "changed_source_bytes",
                               (int64_t)changed_source_bytes);
    }
}

static void rr_emit_event_files_array(struct json_value *doc,
                                      const char *const *sources,
                                      size_t source_count)
{
    struct json_value files;
    json_init(&files); json_set_array(&files);
    for (size_t i = 0; i < source_count; i++) {
        struct json_value item;
        json_init(&item); json_set_str(&item, sources[i]);
        (void)json_push_back(&files, &item); json_free(&item);
    }
    (void)json_push_kv(doc, "files", &files); json_free(&files);
}

static void rr_emit_event_process_fields(
    struct json_value *doc, const char *why,
    const struct zcl_devloop_process_result *process)
{
    if (why && why[0])
        (void)json_push_kv_str(doc, "failure_capsule", why);
    if (process && process->output_len) {
        char preview[1025];
        rr_output_preview(process, preview);
        (void)json_push_kv_str(doc, "process_output", preview);
        (void)json_push_kv_bool(doc, "process_output_truncated",
                                process->output_len > 1024 ||
                                process->output_truncated);
    }
    if (process) {
        (void)json_push_kv_int(doc, "process_startup_us",
                               process->startup_us);
        (void)json_push_kv_int(doc, "process_body_us", process->body_us);
        (void)json_push_kv_int(doc, "process_first_output_us",
                               process->first_output_us);
    }
}

static void rr_emit_event_build_receipt(
    struct json_value *receipt,
    const struct zcl_devloop_restart_build_receipt *build)
{
    (void)json_push_kv_str(receipt, "schema",
                           "zcl.dev_restart_build_receipt.v1");
    if (build->artifact_path[0])
        (void)json_push_kv_str(receipt, "artifact_path",
                               build->artifact_path);
    if (build->artifact_sha256[0])
        (void)json_push_kv_str(receipt, "artifact_sha256",
                               build->artifact_sha256);
    if (build->artifact_cache_key[0])
        (void)json_push_kv_str(receipt, "artifact_cache_key",
                               build->artifact_cache_key);
    if (build->source_cas_sha3[0])
        (void)json_push_kv_str(receipt, "source_cas_sha3",
                               build->source_cas_sha3);
    (void)json_push_kv_bool(receipt, "source_identity_overlay",
                            build->source_identity_overlay);
    (void)json_push_kv_str(receipt, "probe", build->probe);
    (void)json_push_kv_bool(receipt, "candidate_probe_passed",
                            build->candidate_probe_passed);
    (void)json_push_kv_bool(receipt, "plan_cache_hit",
                            build->plan_cache_hit);
    (void)json_push_kv_bool(receipt, "artifact_cache_hit",
                            build->artifact_cache_hit);
    (void)json_push_kv_int(receipt, "changed_sources",
                           build->changed_sources);
    (void)json_push_kv_int(receipt, "compiler_processes",
                           build->compiler_processes);
    (void)json_push_kv_int(receipt, "linker_processes",
                           build->linker_processes);
    (void)json_push_kv_int(receipt, "complete_graph_linker_processes",
                           build->complete_graph_linker_processes);
    (void)json_push_kv_int(receipt, "probe_processes",
                           build->probe_processes);
    (void)json_push_kv_int(receipt, "source_guard_captures",
                           build->source_guard_captures);
    (void)json_push_kv_int(receipt, "plan_load_us",
                           build->plan_load_us);
    (void)json_push_kv_int(receipt, "compile_us", build->compile_us);
    (void)json_push_kv_int(receipt, "compile_startup_us",
                           build->compile_startup_us);
    (void)json_push_kv_int(receipt, "compile_body_us",
                           build->compile_body_us);
    (void)json_push_kv_int(receipt, "link_us", build->link_us);
    (void)json_push_kv_int(receipt, "link_startup_us",
                           build->link_startup_us);
    (void)json_push_kv_int(receipt, "link_body_us",
                           build->link_body_us);
    (void)json_push_kv_int(receipt, "probe_us", build->probe_us);
    (void)json_push_kv_int(receipt, "probe_startup_us",
                           build->probe_startup_us);
    (void)json_push_kv_int(receipt, "probe_body_us",
                           build->probe_body_us);
    (void)json_push_kv_int(receipt, "build_total_us", build->total_us);
}

static void rr_emit_event_proof_receipt(
    struct json_value *receipt,
    const struct zcl_devloop_restart_proof_receipt *proof)
{
    (void)json_push_kv_str(receipt, "schema",
                           "zcl.dev_restart_proof_receipt.v1");
    if (proof->artifact_path[0])
        (void)json_push_kv_str(receipt, "artifact_path",
                               proof->artifact_path);
    if (proof->artifact_sha256[0])
        (void)json_push_kv_str(receipt, "artifact_sha256",
                               proof->artifact_sha256);
    if (proof->artifact_cache_key[0])
        (void)json_push_kv_str(receipt, "artifact_cache_key",
                               proof->artifact_cache_key);
    if (proof->source_cas_sha3[0])
        (void)json_push_kv_str(receipt, "source_cas_sha3",
                               proof->source_cas_sha3);
    (void)json_push_kv_bool(receipt, "source_identity_overlay",
                            proof->source_identity_overlay);
    if (proof->groups_sha256[0])
        (void)json_push_kv_str(receipt, "exact_groups_sha256",
                               proof->groups_sha256);
    if (proof->deferred_groups_sha256[0])
        (void)json_push_kv_str(receipt,
                               "deferred_groups_sha256",
                               proof->deferred_groups_sha256);
    if (proof->priority_group[0])
        (void)json_push_kv_str(receipt, "priority_group",
                               proof->priority_group);
    if (proof->priority_reason[0])
        (void)json_push_kv_str(receipt, "priority_reason",
                               proof->priority_reason);
    (void)json_push_kv_bool(receipt, "proof_complete",
                            proof->proof_complete);
    (void)json_push_kv_bool(receipt, "artifact_cache_hit",
                            proof->artifact_cache_hit);
    (void)json_push_kv_bool(receipt, "immediate_proof_complete",
                            proof->immediate_proof_complete);
    (void)json_push_kv_bool(receipt, "integration_proof_deferred",
                            proof->integration_proof_deferred);
    (void)json_push_kv_bool(receipt, "bounded_proof_deferred",
                            proof->bounded_proof_deferred);
    (void)json_push_kv_int(receipt, "group_count", proof->group_count);
    (void)json_push_kv_int(receipt, "groups_immediate_selected",
                           proof->groups_immediate_selected);
    (void)json_push_kv_int(receipt, "groups_selected",
                           proof->groups_selected);
    (void)json_push_kv_int(receipt, "artifact_dev",
                           (int64_t)proof->artifact_dev);
    (void)json_push_kv_int(receipt, "artifact_size",
                           (int64_t)proof->artifact_size);
    (void)json_push_kv_int(receipt, "artifact_ctime_sec",
                           proof->artifact_ctime_sec);
    (void)json_push_kv_int(receipt, "artifact_ctime_nsec",
                           proof->artifact_ctime_nsec);
    (void)json_push_kv_int(receipt, "artifact_ino",
                           (int64_t)proof->artifact_ino);
    (void)json_push_kv_int(receipt, "deferred_group_count",
                           proof->deferred_group_count);
    (void)json_push_kv_int(receipt, "groups_ran", proof->groups_ran);
    (void)json_push_kv_int(receipt, "groups_cached",
                           proof->groups_cached);
    (void)json_push_kv_int(receipt, "groups_failed",
                           proof->groups_failed);
    (void)json_push_kv_int(receipt, "self_skips", proof->self_skips);
    (void)json_push_kv_int(receipt, "compiler_processes",
                           proof->compiler_processes);
    (void)json_push_kv_int(receipt, "linker_processes",
                           proof->linker_processes);
    (void)json_push_kv_int(receipt, "complete_graph_linker_processes",
                           proof->complete_graph_linker_processes);
    (void)json_push_kv_int(receipt, "test_processes",
                           proof->test_processes);
    (void)json_push_kv_int(receipt, "source_guard_captures",
                           proof->source_guard_captures);
    (void)json_push_kv_int(receipt, "selection_us",
                           proof->selection_us);
    (void)json_push_kv_int(receipt, "compile_us", proof->compile_us);
    (void)json_push_kv_int(receipt, "compile_startup_us",
                           proof->compile_startup_us);
    (void)json_push_kv_int(receipt, "compile_body_us",
                           proof->compile_body_us);
    (void)json_push_kv_int(receipt, "link_us", proof->link_us);
    (void)json_push_kv_int(receipt, "link_startup_us",
                           proof->link_startup_us);
    (void)json_push_kv_int(receipt, "link_body_us",
                           proof->link_body_us);
    (void)json_push_kv_int(receipt, "test_us", proof->test_us);
    (void)json_push_kv_int(receipt, "test_startup_us",
                           proof->test_startup_us);
    (void)json_push_kv_int(receipt, "test_body_us",
                           proof->test_body_us);
    (void)json_push_kv_int(receipt, "priority_test_us",
                           proof->priority_test_us);
    (void)json_push_kv_int(receipt, "proof_total_us", proof->total_us);
}

/* Complete means every non-integration group the plan selects ran, against
 * a link that never fell back off an unverified persistent overlay. */
static bool rr_proof_partial(
    const struct zcl_devloop_restart_proof_receipt *proof)
{
    return proof->bounded_proof_deferred ||
        proof->source_overlay_unresolved ||
        proof->group_count < proof->groups_immediate_selected;
}

/* Top-level scope of a focused verdict, readable without the receipt: how
 * many groups ran against how many the plan selects, and which bytes ran.
 * No restart event carries acceptance or publication authority. */
static void rr_emit_event_focused_scope(
    struct json_value *doc, const char *status,
    const struct zcl_devloop_restart_proof_receipt *proof)
{
    (void)json_push_kv_bool(doc, "receipt_authority", false);
    /* Only a runner that actually executed has a scope to report. */
    if (!proof || proof->group_count == 0 || proof->test_processes == 0 ||
        strcmp(status, "fallback_ready") == 0)
        return;
    (void)json_push_kv_str(doc, "focused_scope",
                           rr_proof_partial(proof) ? "partial" : "complete");
    (void)json_push_kv_int(doc, "groups_run", proof->group_count);
    (void)json_push_kv_int(doc, "groups_selected", proof->groups_selected);
    (void)json_push_kv_int(doc, "groups_immediate_selected",
                           proof->groups_immediate_selected);
    if (proof->artifact_sha256[0])
        (void)json_push_kv_str(doc, "probe_candidate_sha256",
                               proof->artifact_sha256);
}

static void rr_emit_event_next_action(struct json_value *doc,
                                      const char *status)
{
    (void)json_push_kv_str(
        doc, "agent_next_action",
        strcmp(status, "feedback_ready") == 0
            ? "candidate runtime and immediate affected proofs are green; run integration proofs before acceptance"
            : strcmp(status, "focused_partial") == 0
                ? "candidate path-floor proofs are green; groups_run of groups_selected ran and the conservative proof decides the rest"
            : strcmp(status, "reflex_ready") == 0
                ? "candidate compile, link, and probe are green; affected proof is running asynchronously"
            : strcmp(status, "impact_ready") == 0
                ? "impact is classified; source identity and candidate diagnostics are running"
            : strcmp(status, "superseded") == 0
                ? "a newer save changed the source during this proof; wait for the latest verdict"
            : strcmp(status, "fallback_ready") == 0
                ? "resident proof was unavailable; conservative integration proof is running"
            : "repair the named restart refusal; no service or source was replaced");
}

static bool rr_emit_event_publish(const char *root, char *wire, size_t n)
{
    char state_why[160] = {0};
    int64_t epoch = 0;
    if (zcl_devloop_cycle_stream_publish(root, wire, n, &epoch,
                                         state_why, sizeof(state_why))) {
        (void)fwrite(wire, 1, n, stdout); (void)fflush(stdout);
        if (!zcl_devloop_cycle_stream_seal(
                root, epoch, state_why, sizeof(state_why))) {
            fprintf(stderr,
                    "[devloop] async restart journal flush failed: %s\n",
                    state_why[0] ? state_why : "unknown");
            return false;
        }
        return true;
    }
    /* Standalone unit/API callers do not own a resident ring. Preserve their
     * durable behavior; the actual watcher always initializes the ring before
     * reaching this path, so reflex feedback never takes this fallback. */
    if (!zcl_devloop_cycle_state_write(root, wire, n, state_why,
                                       sizeof(state_why))) {
        fprintf(stderr, "[devloop] restart receipt persistence failed: %s\n",
                state_why[0] ? state_why : "unknown");
        return false;
    }
    (void)fwrite(wire, 1, n, stdout); (void)fflush(stdout);
    return true;
}

static bool rr_emit_event(
    const char *root, const char *const *sources, size_t source_count,
    const char *status, const char *phase, int64_t elapsed_us,
    enum zcl_devloop_publish_mode requested_mode,
    const struct zcl_devloop_restart_build_receipt *build,
    const struct zcl_devloop_restart_proof_receipt *proof,
    const struct zcl_devloop_process_result *process, const char *why,
    int64_t source_guard_us, uint32_t source_guard_captures,
    uint64_t source_guard_bytes_read, uint64_t source_bytes_total,
    bool source_byte_accounting_complete,
    int64_t impact_us, int64_t closure_us, bool closure_refresh_deferred,
    bool feedback_parallel, const struct zcl_devloop_early_receipt *early)
{
    const char *progress_phase = zcl_devloop_progress_phase(status, phase);
    struct json_value doc, receipt;
    json_init(&doc); json_set_object(&doc);
    (void)json_push_kv_str(&doc, "schema", "zcl.dev_cycle.v1");
    (void)json_push_kv_str(&doc, "producer", "resident-restart-authority");
    (void)json_push_kv_str(&doc, "status", status);
    (void)json_push_kv_str(&doc, "action", "restart");
    (void)json_push_kv_str(&doc, "reason", "process_restart_candidate");
    (void)json_push_kv_str(&doc, "phase", progress_phase);
    (void)json_push_kv_str(&doc, "stage_detail", phase);
    if (zcl_devloop_event_edit_epoch()[0])
        (void)json_push_kv_str(&doc, "edit_epoch",
                               zcl_devloop_event_edit_epoch());
    (void)json_push_kv_bool(&doc, "runtime_published", false);
    (void)json_push_kv_bool(&doc, "publication_requested",
                            zcl_devloop_publish_mode_applies(requested_mode));
    (void)json_push_kv_bool(&doc, "proof_complete",
                            proof && proof->proof_complete);
    (void)json_push_kv_bool(&doc, "immediate_proof_complete",
                            proof && proof->immediate_proof_complete);
    (void)json_push_kv_bool(&doc, "integration_proof_deferred",
                            proof && proof->integration_proof_deferred);
    (void)json_push_kv_bool(&doc, "bounded_proof_deferred",
                            proof && proof->bounded_proof_deferred);
    (void)json_push_kv_bool(&doc, "closure_refresh_deferred",
                            closure_refresh_deferred);
    (void)json_push_kv_bool(&doc, "feedback_parallel", feedback_parallel);
    (void)json_push_kv_int(&doc, "elapsed_us", elapsed_us);
    (void)json_push_kv_int(&doc, "elapsed_ms", elapsed_us / 1000);
    (void)json_push_kv_int(&doc, "source_guard_us", source_guard_us);
    (void)json_push_kv_int(&doc, "source_guard_captures",
                           source_guard_captures);
    (void)json_push_kv_int(&doc, "impact_us", impact_us);
    rr_emit_event_source_bytes(&doc, root, sources, source_count,
                               source_guard_bytes_read, source_bytes_total,
                               source_byte_accounting_complete);
    (void)json_push_kv_int(&doc, "closure_us", closure_us);
    (void)json_push_kv_int(&doc, "file_count", (int64_t)source_count);
    rr_emit_event_files_array(&doc, sources, source_count);
    rr_emit_event_process_fields(&doc, why, process);
    if (build) {
        json_init(&receipt); json_set_object(&receipt);
        rr_emit_event_build_receipt(&receipt, build);
        (void)json_push_kv(&doc, "build_receipt", &receipt);
        json_free(&receipt);
    }
    if (proof) {
        json_init(&receipt); json_set_object(&receipt);
        rr_emit_event_proof_receipt(&receipt, proof);
        (void)json_push_kv(&doc, "proof_receipt", &receipt);
        json_free(&receipt);
    }
    rr_emit_event_focused_scope(&doc, status, proof);
    zcl_devloop_early_json(early, &doc);
    rr_emit_event_next_action(&doc, status);
    char wire[16384];
    size_t n = json_write(&doc, wire, sizeof(wire) - 1);
    json_free(&doc);
    if (!n) return false;
    wire[n++] = '\n'; wire[n] = 0;
    return rr_emit_event_publish(root, wire, n);
}

struct rr_event_ctx {
    const char *repo_root;
    const char *const *source_tus;
    size_t source_count;
    enum zcl_devloop_publish_mode publish_mode;
    int64_t started;
    int64_t impact_us;
    struct zcl_devloop_plan plan;
    int64_t source_guard_us;
    uint64_t source_guard_bytes_read;
    uint64_t source_bytes_total;
    bool source_byte_accounting_complete;
    int64_t closure_us;
    uint32_t source_guard_captures;
    struct zcl_devloop_restart_build_receipt build;
    struct zcl_devloop_restart_proof_receipt proof;
    struct zcl_devloop_process_result build_process;
    struct zcl_devloop_process_result proof_process;
    char why[512];
    struct dev_source_record source_before, source_after;
    bool source_superseded;
    /* Feedback only: never read by any verdict below. */
    struct zcl_devloop_early_receipt early;
    bool *focused_complete;
};

static bool rr_event_validate(const char *repo_root,
                              const char *const *source_tus,
                              size_t source_count, struct rr_event_ctx *ctx)
{
    if (!repo_root || !source_tus || source_count == 0 ||
        source_count > RR_SOURCE_MAX)
        return false;
    int64_t impact_started = ctx->started;
    if (!zcl_devloop_plan_files(source_tus, source_count, &ctx->plan) ||
        ctx->plan.docs_only || ctx->plan.consensus_risk)
        return false;
    ctx->impact_us = platform_time_monotonic_us() - impact_started;
    for (size_t i = 0; i < source_count; i++)
        if (!rr_source_is_c(source_tus[i]))
            return false;
    bool has_runtime_source = false;
    for (size_t i = 0; i < source_count; i++)
        has_runtime_source = has_runtime_source ||
            !rr_source_is_test_only(source_tus[i]);
    return has_runtime_source;
}

/* The resident watcher has already published the immutable edit epoch and
 * IMPACT_READY before entering this compiler lane. Keep the measured path
 * classification cost in later receipts, but never emit a duplicate
 * latest-value impact event from the slower proof stage. */
static bool rr_event_build_phase(struct rr_event_ctx *ctx)
{
    int64_t guard_started = platform_time_monotonic_us();
    ctx->source_guard_captures++;
    bool ok = zcl_dev_source_cas_capture(ctx->repo_root, &ctx->source_before) &&
              ctx->source_before.cas_present;
    if (ok) {
        ctx->source_guard_bytes_read = ctx->source_before.cas_bytes_read;
        ctx->source_bytes_total = ctx->source_before.cas_bytes_total;
    }
    ctx->source_guard_us += platform_time_monotonic_us() - guard_started;
    if (!ok)
        rr_why(ctx->why, sizeof(ctx->why),
               "restart epoch source snapshot could not be captured");
    int64_t closure_started = platform_time_monotonic_us();
    if (ok) {
        const char *closure_reason = "";
        bool closure_added = zcl_devloop_plan_add_closure_snapshot(
            ctx->repo_root, ctx->source_tus, ctx->source_count, &ctx->plan);
        bool closure_admissible = closure_added &&
            zcl_devloop_plan_proof_admissible(&ctx->plan, &closure_reason);
        if (!closure_admissible) {
            char detail[256];
            (void)snprintf(
                detail, sizeof(detail), "affected proof closure refused: %s",
                closure_added && closure_reason && closure_reason[0]
                    ? closure_reason : "closure_unavailable");
            rr_why(ctx->why, sizeof(ctx->why), detail);
            ok = false;
        }
    }
    ctx->closure_us = platform_time_monotonic_us() - closure_started;
    if (ok)
        ok = rr_restart_build(ctx->repo_root, ctx->source_tus,
                              ctx->source_count, &ctx->build,
                              &ctx->build_process, ctx->why, sizeof(ctx->why),
                              false, &ctx->source_before);
    return ok;
}

static bool rr_event_verify_after_build(struct rr_event_ctx *ctx)
{
    int64_t guard_started = platform_time_monotonic_us();
    ctx->source_guard_captures++;
    bool ok = zcl_dev_source_cas_capture(ctx->repo_root, &ctx->source_after) &&
              ctx->source_after.cas_present &&
              strcmp(ctx->source_before.cas_root_sha3,
                     ctx->source_after.cas_root_sha3) == 0;
    ctx->source_guard_us += platform_time_monotonic_us() - guard_started;
    uint64_t combined_bytes = 0;
    ctx->source_byte_accounting_complete = ok &&
        ctx->source_after.cas_bytes_total == ctx->source_bytes_total &&
        zcl_u64_add(ctx->source_guard_bytes_read,
                    ctx->source_after.cas_bytes_read, &combined_bytes);
    if (ctx->source_byte_accounting_complete)
        ctx->source_guard_bytes_read = combined_bytes;
    if (!ok)
        rr_why(ctx->why, sizeof(ctx->why),
               "restart epoch source changed during reflex build");
    return ok;
}

static int rr_event_handle_build_failure(struct rr_event_ctx *ctx)
{
    bool fallback_pending = strstr(ctx->why, "proof closure refused:") ||
        strstr(ctx->why, "proof plan is incomplete") ||
        strstr(ctx->why, "proof set exceeds resident bound") ||
        strstr(ctx->why, "action plan stale");
    if (fallback_pending) {
        ctx->proof.integration_proof_deferred = true;
        ctx->proof.bounded_proof_deferred = true;
    }
    bool emitted = rr_emit_event(
        ctx->repo_root, ctx->source_tus, ctx->source_count,
        fallback_pending ? "fallback_ready" : "rejected",
        fallback_pending ? "conservative_proof_selected"
                         : "compile_link_probe",
        platform_time_monotonic_us() - ctx->started, ctx->publish_mode,
        ctx->build.changed_sources ? &ctx->build : NULL, &ctx->proof,
        &ctx->build_process, ctx->why, ctx->source_guard_us,
        ctx->source_guard_captures, ctx->source_guard_bytes_read,
        ctx->source_bytes_total, ctx->source_byte_accounting_complete,
        ctx->impact_us, ctx->closure_us, ctx->plan.closure_snapshot, false,
        NULL);
    if (!emitted)
        return ZCL_DEVLOOP_RESTART_EVENT_ERROR;
    return fallback_pending ? ZCL_DEVLOOP_RESTART_EVENT_FALLBACK_PENDING
                            : ZCL_DEVLOOP_RESTART_EVENT_FINAL;
}

static bool rr_event_prove_phase(struct rr_event_ctx *ctx)
{
    ctx->why[0] = 0;
    struct rr_prove_early_io early = {
        .plan = zcl_devloop_early_plan_resident(
            ctx->repo_root, ctx->source_tus, ctx->source_count),
        .receipt = &ctx->early,
    };
    bool ok = rr_restart_prove(ctx->repo_root, ctx->source_tus,
                               ctx->source_count, &ctx->plan, &ctx->proof,
                               &ctx->proof_process, ctx->why,
                               sizeof(ctx->why), true, false,
                               &ctx->source_before, early);
    /* Without its plan the stage skips; the full plan ran regardless. */
    if (!early.plan)
        zcl_devloop_early_skip(&ctx->early, "out_of_memory",
                               "early feedback plan");
    free((void *)early.plan);
    if (!ok)
        return false;
    int64_t guard_started = platform_time_monotonic_us();
    ctx->source_guard_captures++;
    bool captured = zcl_dev_source_cas_capture(ctx->repo_root,
                                               &ctx->source_after) &&
        ctx->source_after.cas_present;
    ok = captured && strcmp(ctx->source_before.cas_root_sha3,
                            ctx->source_after.cas_root_sha3) == 0;
    ctx->source_guard_us += platform_time_monotonic_us() - guard_started;
    uint64_t combined_bytes = 0;
    ctx->source_byte_accounting_complete = ok &&
        ctx->source_byte_accounting_complete &&
        ctx->source_after.cas_bytes_total == ctx->source_bytes_total &&
        zcl_u64_add(ctx->source_guard_bytes_read,
                    ctx->source_after.cas_bytes_read, &combined_bytes);
    if (ctx->source_byte_accounting_complete)
        ctx->source_guard_bytes_read = combined_bytes;
    /* Only a snapshot that was taken and differs proves a newer save. A
     * snapshot that could not be taken proves nothing about the epoch. */
    ctx->source_superseded = captured && !ok;
    if (!captured)
        rr_why(ctx->why, sizeof(ctx->why),
               "restart epoch source snapshot could not be recaptured after "
               "affected proof");
    else if (!ok)
        rr_why(ctx->why, sizeof(ctx->why),
               "restart epoch source changed during affected proof");
    return ok;
}

/* Refusals that leave the candidate unjudged. The conservative proof, which
 * the watcher still schedules, decides it. */
static bool rr_why_leaves_proof_pending(const char *why)
{
    return strstr(why, "proof plan is incomplete") ||
        strstr(why, "proof set exceeds resident bound") ||
        strstr(why, "action plan stale") ||
        strstr(why, "candidate was replaced during its run") ||
        strstr(why, "source snapshot could not be recaptured");
}

/* A green run of the complete path floor with the rest of the selection
 * deferred is partial evidence, never FOCUSED_GREEN. */
static const char *rr_focused_status(
    bool ok, bool fallback,
    const struct zcl_devloop_restart_proof_receipt *proof)
{
    if (ok)
        return rr_proof_partial(proof) ? "focused_partial"
                                             : "feedback_ready";
    return fallback ? "fallback_ready" : "rejected";
}

static const char *rr_focused_detail(
    bool ok, bool fallback,
    const struct zcl_devloop_restart_proof_receipt *proof)
{
    if (ok)
        return rr_proof_partial(proof) ? "path_floor_affected_proofs"
                                             : "immediate_affected_proofs";
    return fallback ? "conservative_proof_selected" : "affected_proofs";
}

static int rr_event_superseded(struct rr_event_ctx *ctx)
{
    bool emitted = rr_emit_event(
        ctx->repo_root, ctx->source_tus, ctx->source_count, "superseded",
        "source_epoch_cas", platform_time_monotonic_us() - ctx->started,
        ctx->publish_mode, &ctx->build, NULL, &ctx->build_process, ctx->why,
        ctx->source_guard_us, ctx->source_guard_captures,
        ctx->source_guard_bytes_read, ctx->source_bytes_total, false,
        ctx->impact_us, ctx->closure_us, ctx->plan.closure_snapshot, false,
        NULL);
    return emitted ? ZCL_DEVLOOP_RESTART_EVENT_CANCELLED
                   : ZCL_DEVLOOP_RESTART_EVENT_ERROR;
}

static int rr_event_finish(struct rr_event_ctx *ctx, bool ok)
{
    if (ctx->proof_process.cancelled || zcl_devloop_process_cancel_requested())
        return ZCL_DEVLOOP_RESTART_EVENT_CANCELLED;
    /* A newer save landed while this epoch's proof ran. Its result belongs
     * to no current source: terminate this epoch as SUPERSEDED here, since
     * the watcher only does so when it has already queued the change. */
    if (ctx->source_superseded)
        return rr_event_superseded(ctx);
    bool fallback_pending = !ok && rr_why_leaves_proof_pending(ctx->why);
    if (fallback_pending) {
        ctx->proof.integration_proof_deferred = true;
        ctx->proof.bounded_proof_deferred = true;
    }
    bool emitted = rr_emit_event(
        ctx->repo_root, ctx->source_tus, ctx->source_count,
        rr_focused_status(ok, fallback_pending, &ctx->proof),
        rr_focused_detail(ok, fallback_pending, &ctx->proof),
        platform_time_monotonic_us() - ctx->started, ctx->publish_mode,
        &ctx->build, &ctx->proof,
        ctx->proof_process.output_len ? &ctx->proof_process
                                      : &ctx->build_process,
        ctx->why, ctx->source_guard_us, ctx->source_guard_captures,
        ctx->source_guard_bytes_read, ctx->source_bytes_total,
        ctx->source_byte_accounting_complete, ctx->impact_us, ctx->closure_us,
        ctx->plan.closure_snapshot, false, &ctx->early);
    if (!emitted)
        return ZCL_DEVLOOP_RESTART_EVENT_ERROR;
    if (ok) {
        /* FOCUSED_GREEN, never a partial: the verdict ran every selected
         * immediate group against these exact bytes, and the link that
         * fed them never silently fell back off an unresolved persistent
         * overlay for a source this restart did not itself recompile. */
        *ctx->focused_complete = !rr_proof_partial(&ctx->proof);
        return ZCL_DEVLOOP_RESTART_EVENT_PROOF_PENDING;
    }
    return fallback_pending ? ZCL_DEVLOOP_RESTART_EVENT_FALLBACK_PENDING
                            : ZCL_DEVLOOP_RESTART_EVENT_FINAL;
}

int zcl_devloop_restart_event(const char *repo_root,
                              const char *const *source_tus,
                              size_t source_count,
                              enum zcl_devloop_publish_mode publish_mode)
{
    bool focused_complete = false;
    return zcl_devloop_restart_event_proving(repo_root, source_tus,
                                             source_count, publish_mode,
                                             &focused_complete);
}

int zcl_devloop_restart_event_proving(const char *repo_root,
                                      const char *const *source_tus,
                                      size_t source_count,
                                      enum zcl_devloop_publish_mode publish_mode,
                                      bool *focused_complete)
{
    bool ignored = false;
    struct rr_event_ctx ctx = {
        .repo_root = repo_root, .source_tus = source_tus,
        .source_count = source_count, .publish_mode = publish_mode,
        .started = platform_time_monotonic_us(),
        .focused_complete = focused_complete ? focused_complete : &ignored,
    };
    *ctx.focused_complete = false;
    if (!rr_event_validate(repo_root, source_tus, source_count, &ctx))
        return 0;
    bool ok = rr_event_build_phase(&ctx);
    if (ok)
        ok = rr_event_verify_after_build(&ctx);
    if (ctx.build_process.cancelled || zcl_devloop_process_cancel_requested())
        return 2;
    if (!ok)
        return rr_event_handle_build_failure(&ctx);

    /* REFLEX ends at a source-bound candidate probe. Affected tests are a
     * separate proof stage and may be slow; persist the useful candidate
     * result first so `dev drive` never waits on them. */
    if (!rr_emit_event(
            ctx.repo_root, ctx.source_tus, ctx.source_count, "reflex_ready",
            "candidate_probe", platform_time_monotonic_us() - ctx.started,
            ctx.publish_mode, &ctx.build, NULL, &ctx.build_process, "",
            ctx.source_guard_us, ctx.source_guard_captures,
            ctx.source_guard_bytes_read, ctx.source_bytes_total,
            ctx.source_byte_accounting_complete, ctx.impact_us,
            ctx.closure_us, ctx.plan.closure_snapshot, false, NULL))
        return ZCL_DEVLOOP_RESTART_EVENT_ERROR;

    ok = rr_event_prove_phase(&ctx);
    return rr_event_finish(&ctx, ok);
}
static bool rr_story_applicable(const char *repo_root,
                                const char *const *source_tus,
                                size_t source_count,
                                struct zcl_devloop_plan *plan)
{
    if (!repo_root || !source_tus || source_count == 0 ||
        source_count > RR_SOURCE_MAX)
        return false;
    if (!zcl_devloop_plan_files(source_tus, source_count, plan) ||
        plan->docs_only || plan->consensus_risk)
        return false;
    return true;
}

static bool rr_story_prepare_closure(const char *repo_root,
                                     const char *const *source_tus,
                                     size_t source_count,
                                     struct zcl_devloop_plan *plan,
                                     char why[512])
{
    const char *closure_reason = "";
    bool closure_ok = zcl_devloop_plan_add_closure_snapshot(
        repo_root, source_tus, source_count, plan) &&
        zcl_devloop_plan_proof_admissible(plan, &closure_reason);
    if (!closure_ok) {
        (void)snprintf(why, 512,
                       "affected proof closure refused: %s",
                       closure_reason && closure_reason[0]
                           ? closure_reason : "closure_unavailable");
    }
    return closure_ok;
}

static int rr_story_finish(const char *repo_root,
                           const char *const *source_tus,
                           size_t source_count,
                           enum zcl_devloop_publish_mode publish_mode,
                           int64_t started, struct zcl_devloop_plan *plan,
                           struct zcl_devloop_restart_proof_receipt *proof,
                           struct zcl_devloop_process_result *process,
                           char why[512], bool ok)
{
    if (process->cancelled || zcl_devloop_process_cancel_requested())
        return ZCL_DEVLOOP_RESTART_EVENT_CANCELLED;
    bool fallback = !ok &&
        (rr_why_leaves_proof_pending(why) ||
         strstr(why, "proof closure refused:"));
    if (fallback) {
        proof->integration_proof_deferred = true;
        proof->bounded_proof_deferred = true;
    }
    bool emitted = rr_emit_event(
        repo_root, source_tus, source_count,
        rr_focused_status(ok, fallback, proof),
        rr_focused_detail(ok, fallback, proof),
        platform_time_monotonic_us() - started, publish_mode, NULL, proof,
        process, why, 0, proof->source_guard_captures, 0, 0, false,
        0, 0, plan->closure_snapshot, false, NULL);
    if (!emitted)
        return ZCL_DEVLOOP_RESTART_EVENT_ERROR;
    if (ok)
        return ZCL_DEVLOOP_RESTART_EVENT_PROOF_PENDING;
    return fallback ? ZCL_DEVLOOP_RESTART_EVENT_FALLBACK_PENDING
                    : ZCL_DEVLOOP_RESTART_EVENT_FINAL;
}

int zcl_devloop_restart_story_prove_event(
    const char *repo_root, const char *const *source_tus,
    size_t source_count, enum zcl_devloop_publish_mode publish_mode)
{
    struct zcl_devloop_plan plan;
    if (!rr_story_applicable(repo_root, source_tus, source_count, &plan))
        return ZCL_DEVLOOP_RESTART_EVENT_NOT_APPLICABLE;
    int64_t started = platform_time_monotonic_us();
    char why[512] = {0};
    bool closure_ok = rr_story_prepare_closure(repo_root, source_tus,
                                               source_count, &plan, why);
    struct zcl_devloop_restart_proof_receipt proof = {0};
    struct zcl_devloop_process_result process = {0};
    bool ok = closure_ok && rr_restart_prove(
        repo_root, source_tus, source_count, &plan, &proof, &process,
        why, sizeof(why), true, true, NULL, k_rr_no_early);
    return rr_story_finish(repo_root, source_tus, source_count, publish_mode,
                           started, &plan, &proof, &process, why, ok);
}
