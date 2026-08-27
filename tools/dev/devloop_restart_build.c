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
#include "test_group_catalog.h"

#include "base/checked.h"
#include "base/hex.h"
#include "crypto/sha256.h"
#include "json/json.h"
#include "platform/time_compat.h"
#include "util/safe_alloc.h"
#include "util/spawn.h"
#include "util/thread_registry.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define RR_TEXT_MAX 16384
#define RR_ARG_MAX 512
#define RR_SOURCE_MAX 32
#define RR_OVERLAY_MAX (RR_SOURCE_MAX + 1)
#define RR_EXACT_GROUP_MAX 128
#define RR_IMMEDIATE_GROUP_MAX 32

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
    struct stat stamp;
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

static void rr_why(char *why, size_t why_len, const char *message)
{
    if (why && why_len)
        (void)snprintf(why, why_len, "%s", message ? message : "unknown");
}

static bool rr_regular(const char *path, struct stat *out)
{
    struct stat st;
    if (!path || lstat(path, &st) != 0 || !S_ISREG(st.st_mode) ||
        S_ISLNK(st.st_mode))
        return false;
    if (out) *out = st;
    return true;
}

static bool rr_directory(const char *path)
{
    struct stat st;
    return path && lstat(path, &st) == 0 && S_ISDIR(st.st_mode) &&
           !S_ISLNK(st.st_mode);
}

static bool rr_mkdirs(const char *path)
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

static bool rr_safe_relative(const char *path)
{
    if (!path || !path[0] || path[0] == '/' || strstr(path, "..") ||
        strchr(path, '\\'))
        return false;
    for (const unsigned char *p = (const unsigned char *)path; *p; p++)
        if (*p < 0x20)
            return false;
    return true;
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

static bool rr_stat_equal(const struct stat *a, const struct stat *b)
{
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino &&
           a->st_size == b->st_size &&
           a->st_mtim.tv_sec == b->st_mtim.tv_sec &&
           a->st_mtim.tv_nsec == b->st_mtim.tv_nsec;
}

static bool rr_plan_load_locked(const char *root, struct rr_plan *out,
                                bool *cache_hit, int64_t *elapsed_us,
                                char *why, size_t why_len)
{
    int64_t started = platform_time_monotonic_us();
    char path[PATH_MAX], makefile[PATH_MAX];
    if (snprintf(path, sizeof(path), "%s/build/dev-loop/restart.env", root) >=
            (int)sizeof(path) ||
        snprintf(makefile, sizeof(makefile), "%s/Makefile", root) >=
            (int)sizeof(makefile)) {
        rr_why(why, why_len, "restart action-plan path overflow");
        return false;
    }
    struct stat stamp, make_st;
    if (!rr_regular(path, &stamp) || !rr_regular(makefile, &make_st)) {
        rr_why(why, why_len,
               "restart action plan absent; run make dev-bin once");
        return false;
    }
    if (make_st.st_mtim.tv_sec > stamp.st_mtim.tv_sec ||
        (make_st.st_mtim.tv_sec == stamp.st_mtim.tv_sec &&
         make_st.st_mtim.tv_nsec > stamp.st_mtim.tv_nsec)) {
        rr_why(why, why_len,
               "restart action plan stale after build-system change");
        return false;
    }
    if (g_rr_plan.loaded && strcmp(g_rr_plan.root, root) == 0 &&
        rr_stat_equal(&g_rr_plan.stamp, &stamp)) {
        *out = g_rr_plan;
        *cache_hit = true;
        *elapsed_us = platform_time_monotonic_us() - started;
        return true;
    }
    FILE *f = fopen(path, "r");
    if (!f) {
        rr_why(why, why_len, "restart action plan could not be opened");
        return false;
    }
    struct rr_plan next = {0};
    char line[RR_TEXT_MAX + 32];
    while (fgets(line, sizeof(line), f)) {
        if (line[0] == '#' || line[0] == '\n' || line[0] == '\r')
            continue;
        if (rr_line(next.cc, sizeof(next.cc), line, "CC=") ||
            rr_line(next.compiler_id, sizeof(next.compiler_id), line,
                    "COMPILER_ID=") ||
            rr_line(next.base_generation, sizeof(next.base_generation), line,
                    "BASE_GENERATION=") ||
            rr_line(next.cflags, sizeof(next.cflags), line, "DEV_CFLAGS=") ||
            rr_line(next.ldflags, sizeof(next.ldflags), line,
                    "DEV_LDFLAGS=") ||
            rr_line(next.libs, sizeof(next.libs), line, "DEV_LIBS=") ||
            rr_line(next.obj_dir, sizeof(next.obj_dir), line,
                    "DEV_OBJ_DIR=") ||
            rr_line(next.link_rsp, sizeof(next.link_rsp), line,
                    "DEV_LINK_RSP=") ||
            rr_line(next.base_reloc, sizeof(next.base_reloc), line,
                    "DEV_BASE_RELOC=") ||
            rr_line(next.test_cflags, sizeof(next.test_cflags), line,
                    "TEST_CFLAGS=") ||
            rr_line(next.test_ldflags, sizeof(next.test_ldflags), line,
                    "TEST_LDFLAGS=") ||
            rr_line(next.test_libs, sizeof(next.test_libs), line,
                    "TEST_LIBS=") ||
            rr_line(next.test_obj_dir, sizeof(next.test_obj_dir), line,
                    "TEST_OBJ_DIR=") ||
            rr_line(next.test_link_rsp, sizeof(next.test_link_rsp), line,
                    "TEST_LINK_RSP=") ||
            rr_line(next.test_base_reloc, sizeof(next.test_base_reloc), line,
                    "TEST_BASE_RELOC="))
            continue;
        fclose(f);
        rr_why(why, why_len, "restart action plan has an unknown field");
        return false;
    }
    bool read_error = ferror(f) != 0;
    fclose(f);
    char obj_full[PATH_MAX], rsp_full[PATH_MAX], base_reloc_full[PATH_MAX];
    char test_obj_full[PATH_MAX], test_rsp_full[PATH_MAX];
    char test_base_reloc_full[PATH_MAX];
    if (read_error || !next.cc[0] || !rr_hex64(next.compiler_id) ||
        !rr_hex64(next.base_generation) ||
        !next.cflags[0] || !next.ldflags[0] || !next.libs[0] ||
        !rr_join_root(root, next.obj_dir, obj_full) ||
        !rr_join_root(root, next.link_rsp, rsp_full) ||
        !rr_join_root(root, next.base_reloc, base_reloc_full) ||
        !rr_directory(obj_full) || !rr_regular(rsp_full, NULL) ||
        !rr_regular(base_reloc_full, NULL) ||
        !strstr(next.cflags, "-DZCL_DEV_BUILD") ||
        !next.test_cflags[0] || !next.test_ldflags[0] ||
        !next.test_libs[0] ||
        !rr_join_root(root, next.test_obj_dir, test_obj_full) ||
        !rr_join_root(root, next.test_link_rsp, test_rsp_full) ||
        !rr_join_root(root, next.test_base_reloc, test_base_reloc_full) ||
        !rr_directory(test_obj_full) || !rr_regular(test_rsp_full, NULL) ||
        !rr_regular(test_base_reloc_full, NULL) ||
        !strstr(next.test_cflags, "-DZCL_TESTING")) {
        rr_why(why, why_len,
               "restart action plan incomplete or its object graph is absent");
        return false;
    }
    if (strstr(next.cflags, "-flto") || strstr(next.ldflags, "-flto") ||
        strstr(next.cflags, "-fuse-linker-plugin") ||
        strstr(next.ldflags, "-fuse-linker-plugin") ||
        strstr(next.test_cflags, "-flto") ||
        strstr(next.test_ldflags, "-flto") ||
        strstr(next.test_cflags, "-fuse-linker-plugin") ||
        strstr(next.test_ldflags, "-fuse-linker-plugin")) {
        rr_why(why, why_len,
               "restart action plan contains release-only LTO flags");
        return false;
    }
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

static bool rr_cache_key(const struct rr_plan *plan, const char *root,
                         const char *rsp, char out[65])
{
    static const char domain[] = "zcl.dev_artifact_cache.restart.v2";
    char cc[sizeof(plan->cc)], cflags[sizeof(plan->cflags)];
    char ldflags[sizeof(plan->ldflags)], libs[sizeof(plan->libs)];
    if (!rr_normalize_root(plan->cc, root, cc, sizeof(cc)) ||
        !rr_normalize_root(plan->cflags, root, cflags, sizeof(cflags)) ||
        !rr_normalize_root(plan->ldflags, root, ldflags, sizeof(ldflags)) ||
        !rr_normalize_root(plan->libs, root, libs, sizeof(libs)))
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
    char base_reloc_full[PATH_MAX], base_reloc_hash[65];
    if (!rr_join_root(root, plan->base_reloc, base_reloc_full) ||
        !rr_regular(base_reloc_full, NULL) ||
        !rr_sha256_file(base_reloc_full, base_reloc_hash)) {
        fclose(f);
        return false;
    }
    rr_key_field(&ctx, "link_mode", "overlay_base_v1", 15);
    rr_key_field(&ctx, "base_reloc_sha256", base_reloc_hash,
                 strlen(base_reloc_hash));
    char token[4096];
    bool ok = true;
    while (ok && fscanf(f, "%4095s", token) == 1) {
        rr_key_field(&ctx, "link_input", token, strlen(token));
        if (strncmp(token, "build/dev-loop/restart-objects/", 31) == 0 ||
            strncmp(token, "build/dev-loop/restart-test-objects/", 36) == 0) {
            char full[PATH_MAX], hash[65];
            ok = rr_join_root(root, token, full) && rr_regular(full, NULL) &&
                 rr_sha256_file(full, hash);
            if (ok)
                rr_key_field(&ctx, "overlay_sha256", hash, strlen(hash));
        }
    }
    ok = ok && !ferror(f);
    fclose(f);
    if (!ok)
        return false;
    sha256_finalize(&ctx, digest);
    zcl_hex_encode(digest, sizeof(digest), out);
    return true;
}

static bool rr_read_hash(const char *path, char out[65])
{
    FILE *f = fopen(path, "r");
    if (!f)
        return false;
    char extra = 0;
    bool ok = fscanf(f, "%64[0-9a-f]%c", out, &extra) == 2 &&
              strlen(out) == 64 && extra == '\n' && fgetc(f) == EOF;
    fclose(f);
    if (!ok) out[0] = 0;
    return ok;
}

static bool rr_force_cache_copy_for_test(void)
{
    const char *force_copy = getenv("ZCL_DEVLOOP_TEST_FORCE_CACHE_COPY");
    return force_copy && strcmp(force_copy, "1") == 0;
}

/* The operator may place the shared cache on a different filesystem from
 * the worktree. Publish an immutable, rehashed copy when hard links cannot
 * cross that boundary. */
static bool rr_copy_publish(const char *source, const char *target,
                            const char expected_sha256[65])
{
    char temp[PATH_MAX];
    int n = snprintf(temp, sizeof(temp), "%s.tmp.XXXXXX", target);
    if (n <= 0 || n >= (int)sizeof(temp))
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
    (void)unlink(temp);
    return ok;
}

static bool rr_link_or_copy_publish(const char *source, const char *target,
                                    const char expected_sha256[65])
{
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
}

static int rr_cache_lock(const char *cache_root, const char key[65],
                         char binary[PATH_MAX], char hash[PATH_MAX])
{
    char lock[PATH_MAX];
    if (snprintf(lock, sizeof(lock), "%s/%s.lock", cache_root, key) >=
            (int)sizeof(lock) ||
        snprintf(binary, PATH_MAX, "%s/%s.bin", cache_root, key) >= PATH_MAX ||
        snprintf(hash, PATH_MAX, "%s/%s.sha256", cache_root, key) >= PATH_MAX)
        return -1;
    int fd = open(lock, O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
    struct stat st;
    if (fd < 0 || fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) ||
        flock(fd, LOCK_EX) != 0) {
        if (fd >= 0) close(fd);
        return -1;
    }
    return fd;
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

static bool rr_cache_publish(const char *cache_binary, const char *cache_hash,
                             const char *built, const char hash[65])
{
    if (!rr_link_or_copy_publish(built, cache_binary, hash))
        return false;
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

static bool rr_temp(char out[PATH_MAX], const char *dir, const char *suffix)
{
    int n = snprintf(out, PATH_MAX, "%s/.restart-XXXXXX%s", dir, suffix);
    if (n <= 0 || n >= PATH_MAX) return false;
    int fd = mkstemps(out, (int)strlen(suffix));
    if (fd < 0) return false;
    close(fd);
    return true;
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
            if (memmem(buf, total, forbidden[i], strlen(forbidden[i]))) {
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

static bool rr_write_overlay_response(const char *root, const char *rsp,
                                      char out[PATH_MAX], char *why,
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
    char token[4096], full[PATH_MAX];
    size_t count = 0;
    bool ok = true;
    while (ok && fscanf(in, "%4095s", token) == 1) {
        bool overlay =
            strncmp(token, "build/dev-loop/restart-objects/", 31) == 0 ||
            strncmp(token, "build/dev-loop/restart-test-objects/", 36) == 0;
        if (!overlay)
            continue;
        ok = rr_join_root(root, token, full) && rr_regular(full, NULL) &&
             rr_overlay_object_safe(full) && fprintf(dst, "%s\n", token) > 0;
        if (ok)
            count++;
    }
    ok = ok && count > 0 && !ferror(in) && fflush(dst) == 0 &&
         fsync(fileno(dst)) == 0;
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

static bool rr_compile_one(const struct rr_plan *plan, const char *root,
                           struct rr_overlay *overlay,
                           const char *const *extra_flags,
                           size_t extra_flag_count,
                           struct zcl_devloop_process_result *process,
                           int64_t *elapsed_us, int64_t *startup_us,
                           int64_t *body_us, char *why, size_t why_len)
{
    char source_full[PATH_MAX], before_hash[65], after_hash[65];
    if (!rr_join_root(root, overlay->source, source_full) ||
        !rr_regular(source_full, NULL) ||
        !rr_sha256_file(source_full, before_hash)) {
        rr_why(why, why_len, "restart source is absent or not a regular file");
        return false;
    }
    char overlay_dir[PATH_MAX];
    (void)snprintf(overlay_dir, sizeof(overlay_dir), "%s", overlay->overlay_object);
    char *slash = strrchr(overlay_dir, '/');
    if (!slash) return false;
    *slash = 0;
    if (!rr_mkdirs(overlay_dir)) {
        rr_why(why, why_len, "could not prepare confined restart object directory");
        return false;
    }
    char temp_o[PATH_MAX], temp_d[PATH_MAX];
    if (!rr_temp(temp_o, overlay_dir, ".o") ||
        !rr_temp(temp_d, overlay_dir, ".d")) {
        rr_why(why, why_len, "could not allocate restart compile temporaries");
        return false;
    }
    char cc[sizeof(plan->cc)], flags[sizeof(plan->cflags)];
    (void)snprintf(cc, sizeof(cc), "%s", plan->cc);
    (void)snprintf(flags, sizeof(flags), "%s", plan->cflags);
    const char *argv[RR_ARG_MAX], *flagv[RR_ARG_MAX];
    size_t argc = zcl_argv_split(cc, argv, RR_ARG_MAX);
    size_t flagc = zcl_argv_split(flags, flagv, RR_ARG_MAX);
    if (!argc || argc + flagc + extra_flag_count + 9 >= RR_ARG_MAX) {
        (void)unlink(temp_o); (void)unlink(temp_d);
        rr_why(why, why_len, "restart compile action exceeds argv bound");
        return false;
    }
    for (size_t i = 0; i < flagc; i++) argv[argc++] = flagv[i];
    for (size_t i = 0; i < extra_flag_count; i++)
        argv[argc++] = extra_flags[i];
    argv[argc++] = "-MD"; argv[argc++] = "-MF"; argv[argc++] = temp_d;
    argv[argc++] = "-c"; argv[argc++] = "-o"; argv[argc++] = temp_o;
    argv[argc++] = overlay->source; argv[argc] = NULL;
    int64_t started = platform_time_monotonic_us();
    bool ran = zcl_devloop_process_run(root, argv, 30000, process);
    *elapsed_us += platform_time_monotonic_us() - started;
    *startup_us += process->startup_us;
    *body_us += process->body_us;
    bool ok = ran && !process->timed_out && !process->term_signal &&
              process->exit_code == 0 && rr_regular(temp_o, NULL) &&
              rr_regular(temp_d, NULL) && rr_sha256_file(source_full, after_hash) &&
              strcmp(before_hash, after_hash) == 0;
    if (!ok) {
        (void)unlink(temp_o); (void)unlink(temp_d);
        rr_why(why, why_len, ran ? "restart compile failed or source changed"
                                : "restart compiler could not be executed");
        return false;
    }
    char marker[PATH_MAX];
    if (snprintf(marker, sizeof(marker), "%s.source", overlay->overlay_object) >=
        (int)sizeof(marker)) {
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
    (void)snprintf(overlay->source_sha256,
                   sizeof(overlay->source_sha256), "%s", after_hash);
    char marker_temp[PATH_MAX];
    if (!rr_temp(marker_temp, overlay_dir, ".source") ) {
        (void)unlink(overlay->overlay_object); (void)unlink(temp_d);
        rr_why(why, why_len, "could not allocate restart overlay marker");
        return false;
    }
    FILE *marker_file = fopen(marker_temp, "w");
    bool marker_ok = marker_file &&
        fprintf(marker_file, "%s %s\n", plan->base_generation,
                after_hash) == 130 &&
        fflush(marker_file) == 0 && fsync(fileno(marker_file)) == 0;
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

static bool rr_overlay_for_base(const struct rr_plan *plan, const char *root,
                                const char *base_object,
                                const char *overlay_prefix,
                                char overlay_relative[PATH_MAX])
{
    size_t prefix_len = strlen(plan->obj_dir);
    size_t token_len = strlen(base_object);
    if (strncmp(base_object, plan->obj_dir, prefix_len) != 0 ||
        base_object[prefix_len] != '/' || token_len < 3 ||
        strcmp(base_object + token_len - 2, ".o") != 0)
        return false;
    const char *stem = base_object + prefix_len + 1;
    char source[PATH_MAX], overlay[PATH_MAX], marker[PATH_MAX];
    if (snprintf(source, sizeof(source), "%s", stem) >= (int)sizeof(source))
        return false;
    size_t source_len = strlen(source);
    source[source_len - 1] = 'c';
    if (snprintf(overlay_relative, PATH_MAX, "%s/%s",
                 overlay_prefix, stem) >= PATH_MAX ||
        snprintf(overlay, sizeof(overlay), "%s/%s", root,
                 overlay_relative) >= (int)sizeof(overlay) ||
        snprintf(marker, sizeof(marker), "%s.source", overlay) >=
            (int)sizeof(marker) || !rr_regular(overlay, NULL) ||
        !rr_regular(marker, NULL))
        return false;
    FILE *f = fopen(marker, "r");
    if (!f) return false;
    char generation[65] = {0}, expected[65] = {0}, extra = 0;
    bool parsed = fscanf(f, "%64[0-9a-f] %64[0-9a-f]%c", generation,
                         expected, &extra) == 3 && extra == '\n' &&
                  fgetc(f) == EOF;
    fclose(f);
    char source_full[PATH_MAX], actual[65];
    return parsed && strcmp(generation, plan->base_generation) == 0 &&
           rr_join_root(root, source, source_full) &&
           rr_regular(source_full, NULL) &&
           rr_sha256_file(source_full, actual) && strcmp(actual, expected) == 0;
}

static bool rr_source_is_test_only(const char *source)
{
    static const char prefix[] = "lib/test/";
    return source && strncmp(source, prefix, sizeof(prefix) - 1) == 0;
}

static bool rr_write_response(const struct rr_plan *plan, const char *root,
                              const struct rr_overlay *overlays,
                              size_t overlay_count, const char *overlay_prefix,
                              bool allow_test_only_omission,
                              char out[PATH_MAX],
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
    bool seen[RR_OVERLAY_MAX] = {0};
    char token[4096];
    bool ok = true;
    while (ok && fscanf(in, "%4095s", token) == 1) {
        const char *write_path = token;
        char persistent_overlay[PATH_MAX];
        bool current = false;
        for (size_t i = 0; i < overlay_count; i++) {
            if (strcmp(token, overlays[i].base_object) == 0) {
                write_path = overlays[i].overlay_object;
                /* Linker cwd is root; retain a worktree-relative response. */
                size_t root_len = strlen(root);
                if (strncmp(write_path, root, root_len) == 0 &&
                    write_path[root_len] == '/')
                    write_path += root_len + 1;
                seen[i] = true;
                current = true;
                break;
            }
        }
        if (!current && rr_overlay_for_base(plan, root, token, overlay_prefix,
                                            persistent_overlay))
            write_path = persistent_overlay;
        ok = fprintf(dst, "%s\n", write_path) > 0;
    }
    ok = ok && !ferror(in) && fflush(dst) == 0 && fsync(fileno(dst)) == 0;
    fclose(in); fclose(dst);
    for (size_t i = 0; i < overlay_count; i++)
        ok = ok && (seen[i] || (allow_test_only_omission &&
                                rr_source_is_test_only(overlays[i].source)));
    if (!ok) {
        (void)unlink(out);
        rr_why(why, why_len,
               "restart link response did not contain every changed object");
    }
    return ok;
}

static bool rr_link(const struct rr_plan *plan, const char *root,
                    const char *rsp, const char *candidate_dir,
                    char binary[PATH_MAX],
                    uint32_t *linker_processes,
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
    char cc[sizeof(plan->cc)], cflags[sizeof(plan->cflags)];
    char flags[sizeof(plan->ldflags)];
    char libs[sizeof(plan->libs)], rsp_arg[PATH_MAX + 2];
    (void)snprintf(cc, sizeof(cc), "%s", plan->cc);
    (void)snprintf(cflags, sizeof(cflags), "%s", plan->cflags);
    (void)snprintf(flags, sizeof(flags), "%s", plan->ldflags);
    (void)snprintf(libs, sizeof(libs), "%s", plan->libs);
    (void)snprintf(rsp_arg, sizeof(rsp_arg), "@%s", overlay_rsp);
    const char *argv[RR_ARG_MAX], *cflagv[RR_ARG_MAX];
    const char *flagv[RR_ARG_MAX], *libv[RR_ARG_MAX];
    size_t argc = zcl_argv_split(cc, argv, RR_ARG_MAX);
    size_t cflagc = zcl_argv_split(cflags, cflagv, RR_ARG_MAX);
    size_t flagc = zcl_argv_split(flags, flagv, RR_ARG_MAX);
    size_t libc = zcl_argv_split(libs, libv, RR_ARG_MAX);
    if (!argc || argc + cflagc + flagc + libc + 6 >= RR_ARG_MAX) {
        (void)unlink(temp);
        (void)unlink(overlay_rsp);
        rr_why(why, why_len, "restart link action exceeds argv bound");
        return false;
    }
    for (size_t i = 0; i < cflagc; i++) argv[argc++] = cflagv[i];
    for (size_t i = 0; i < flagc; i++) argv[argc++] = flagv[i];
    argv[argc++] = "-o"; argv[argc++] = temp; argv[argc++] = rsp_arg;
    argv[argc++] = plan->base_reloc;
    argv[argc++] = "-Wl,--allow-multiple-definition";
    for (size_t i = 0; i < libc; i++) argv[argc++] = libv[i];
    argv[argc] = NULL;
    (*linker_processes)++;
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

static bool rr_link_cached(const struct rr_plan *plan, const char *root,
                           const char *rsp, const char *candidate_dir,
                           char binary[PATH_MAX], char cache_key[65],
                           bool *cache_hit, uint32_t *linker_processes,
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
    int cache_fd = -1;
    if (rr_cache_root(cache_root))
        cache_fd = rr_cache_lock(cache_root, cache_key,
                                 cache_binary, cache_hash);
    if (cache_fd >= 0 &&
        rr_cache_lookup(root, candidate_dir, cache_binary, cache_hash,
                        binary)) {
        *cache_hit = true;
        (void)flock(cache_fd, LOCK_UN);
        (void)close(cache_fd);
        return true;
    }
    if (cache_fd >= 0) {
        /* With the per-key lock held, an unverifiable pair is stale or
         * corrupt rather than a publisher in flight. Repair it from a new
         * exact link; never accept one side alone. */
        (void)unlink(cache_binary);
        (void)unlink(cache_hash);
    }
    bool ok = rr_link(plan, root, rsp, candidate_dir, binary,
                      linker_processes, process,
                      elapsed_us, startup_us, body_us, why, why_len);
    if (ok && cache_fd >= 0) {
        char hash[65];
        ok = rr_sha256_file(binary, hash) &&
             rr_cache_publish(cache_binary, cache_hash, binary, hash);
        if (!ok)
            rr_why(why, why_len,
                   "restart artifact cache publication failed");
    }
    if (cache_fd >= 0) {
        (void)flock(cache_fd, LOCK_UN);
        (void)close(cache_fd);
    }
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
    static const char identity_source[] = "lib/util/src/clientversion.c";
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

static bool rr_restart_build(
    const char *repo_root, const char *const *source_tus, size_t source_count,
    struct zcl_devloop_restart_build_receipt *receipt,
    struct zcl_devloop_process_result *process,
    char *why, size_t why_len, bool guard_source,
    const struct dev_source_record *epoch_source)
{
    int64_t started = platform_time_monotonic_us();
    if (why && why_len) why[0] = 0;
    if (!repo_root || !source_tus || !receipt || !process ||
        source_count == 0 || source_count > RR_SOURCE_MAX) {
        rr_why(why, why_len, "restart source set is empty or exceeds its bound");
        return false;
    }
    memset(receipt, 0, sizeof(*receipt));
    memset(process, 0, sizeof(*process));
    struct zcl_devloop_plan classification;
    if (!zcl_devloop_plan_files(source_tus, source_count, &classification)) {
        rr_why(why, why_len, "restart source set is invalid");
        return false;
    }
    if (classification.consensus_risk) {
        rr_why(why, why_len,
               "consensus-risk input is excluded from fast restart");
        return false;
    }
    for (size_t i = 0; i < source_count; i++) {
        if (!rr_source_is_c(source_tus[i])) {
            rr_why(why, why_len,
                   "fast restart currently requires changed C translation units");
            return false;
        }
    }
    char root[PATH_MAX];
    if (!realpath(repo_root, root)) {
        rr_why(why, why_len, "restart checkout root could not be resolved");
        return false;
    }
    struct rr_plan plan = {0};
    pthread_mutex_lock(&g_rr_mu);
    bool plan_ok = rr_plan_load_locked(root, &plan, &receipt->plan_cache_hit,
                                       &receipt->plan_load_us, why, why_len);
    pthread_mutex_unlock(&g_rr_mu);
    if (!plan_ok) return false;

    struct dev_source_record source_before = {0}, source_after = {0};
    if (guard_source) receipt->source_guard_captures++;
    if (guard_source &&
        (!zcl_dev_source_cas_capture(root, &source_before) ||
         !source_before.cas_present)) {
        rr_why(why, why_len,
               "restart source snapshot could not be captured before compile");
        return false;
    }

    const struct dev_source_record *identity =
        epoch_source ? epoch_source : &source_before;
    if (!rr_source_record_valid(identity)) {
        rr_why(why, why_len,
               "restart epoch source CAS record is unavailable");
        return false;
    }
    (void)snprintf(receipt->source_cas_sha3,
                   sizeof(receipt->source_cas_sha3), "%s",
                   identity->cas_root_sha3);

    struct rr_overlay *overlays = zcl_calloc(RR_OVERLAY_MAX, sizeof(*overlays),
                                              "restart overlays");
    if (!overlays) {
        rr_why(why, why_len, "restart overlay allocation failed");
        return false;
    }
    const char *runtime_sources[RR_SOURCE_MAX];
    size_t runtime_source_count = 0;
    for (size_t i = 0; i < source_count; i++)
        if (!rr_source_is_test_only(source_tus[i]))
            runtime_sources[runtime_source_count++] = source_tus[i];
    if (runtime_source_count == 0) {
        free(overlays);
        rr_why(why, why_len,
               "restart source set contains no runtime translation unit");
        return false;
    }
    size_t overlay_count = 0;
    bool ok = rr_prepare_overlays(
        &plan, root, runtime_sources, runtime_source_count, identity,
        "build/dev-loop/restart-objects", overlays, &overlay_count, process,
        &receipt->compiler_processes, &receipt->compile_us,
        &receipt->compile_startup_us, &receipt->compile_body_us,
        why, why_len);
    receipt->source_identity_overlay = ok;
    char rsp[PATH_MAX] = {0};
    if (ok && !rr_write_response(&plan, root, overlays, overlay_count,
                                 "build/dev-loop/restart-objects", true, rsp,
                                 why, why_len))
        ok = false;
    if (ok) {
        ok = rr_link_cached(&plan, root, rsp,
                            "build/dev-loop/restart-candidates",
                            receipt->artifact_path,
                            receipt->artifact_cache_key,
                            &receipt->artifact_cache_hit,
                            &receipt->linker_processes, process,
                            &receipt->link_us, &receipt->link_startup_us,
                            &receipt->link_body_us, why, why_len);
    }
    if (rsp[0]) (void)unlink(rsp);
    free(overlays);
    if (!ok) {
        receipt->total_us = platform_time_monotonic_us() - started;
        return false;
    }
    if (guard_source) receipt->source_guard_captures++;
    if (guard_source &&
        (!zcl_dev_source_cas_capture(root, &source_after) ||
         !source_after.cas_present ||
         strcmp(source_before.cas_root_sha3, source_after.cas_root_sha3) != 0)) {
        rr_why(why, why_len,
               "restart source snapshot changed during candidate build");
        receipt->total_us = platform_time_monotonic_us() - started;
        return false;
    }
    if (!rr_sha256_file(receipt->artifact_path, receipt->artifact_sha256)) {
        rr_why(why, why_len, "restart candidate could not be rehashed");
        return false;
    }
    const char *probe_argv[] = {
        receipt->artifact_path, "discover", "help", NULL
    };
    receipt->probe_processes = 1;
    int64_t probe_started = platform_time_monotonic_us();
    bool probed = zcl_devloop_process_run(root, probe_argv, 5000, process);
    receipt->probe_us = platform_time_monotonic_us() - probe_started;
    receipt->probe_startup_us = process->startup_us;
    receipt->probe_body_us = process->body_us;
    receipt->candidate_probe_passed = probed && !process->timed_out &&
        !process->term_signal && process->exit_code == 0;
    (void)snprintf(receipt->probe, sizeof(receipt->probe), "%s",
                   "discover.help");
    receipt->changed_sources = (uint32_t)source_count;
    receipt->total_us = platform_time_monotonic_us() - started;
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

static bool rr_collect_groups(const struct zcl_devloop_plan *plan,
                              bool immediate_only,
                              char out[4096], uint32_t *count,
                              char deferred[4096], uint32_t *deferred_count,
                              bool *bounded_deferred)
{
    if (!plan || !out || !count || !deferred || !deferred_count ||
        !bounded_deferred)
        return false;
    out[0] = 0;
    deferred[0] = 0;
    *count = 0;
    *deferred_count = 0;
    *bounded_deferred = false;
    const char *why = NULL;
    if (!zcl_devloop_plan_proof_admissible(plan, &why))
        return false;
    const char *ids[ZCL_DEVLOOP_MAX_PLAN_GROUPS * 2];
    size_t id_count = 0;
    for (size_t i = 0; i < plan->path_groups_len; i++)
        ids[id_count++] = plan->path_groups[i];
    for (size_t i = 0; i < plan->closure_groups_len; i++)
        ids[id_count++] = plan->closure_groups[i];
    char exact[RR_EXACT_GROUP_MAX][ZCL_TEST_GROUP_FULL_MAX];
    bool truncated = false;
    size_t total = zcl_test_group_expand_plan(ids, id_count, exact,
                                               RR_EXACT_GROUP_MAX,
                                               &truncated);
    if (total == SIZE_MAX || total == 0 || truncated)
        return false;
    size_t immediate_total = 0;
    for (size_t i = 0; i < total; i++)
        if (!zcl_test_group_is_integration_only(exact[i]))
            immediate_total++;
    bool tier_closure = immediate_only &&
        immediate_total > RR_IMMEDIATE_GROUP_MAX;
    for (size_t i = 0; i < total; i++) {
        bool path_owned = false;
        for (size_t p = 0; p < plan->path_groups_len; p++)
            if (zcl_test_group_plan_selects(plan->path_groups[p], exact[i])) {
                path_owned = true;
                break;
            }
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

static bool rr_restart_prove(
    const char *repo_root, const char *const *source_tus, size_t source_count,
    const struct zcl_devloop_plan *proof_plan,
    struct zcl_devloop_restart_proof_receipt *receipt,
    struct zcl_devloop_process_result *process,
    char *why, size_t why_len, bool immediate_only, bool guard_source,
    const struct dev_source_record *epoch_source)
{
    int64_t started = platform_time_monotonic_us();
    if (why && why_len) why[0] = 0;
    if (!repo_root || !source_tus || !proof_plan || !receipt || !process ||
        source_count == 0 || source_count > RR_SOURCE_MAX) {
        rr_why(why, why_len, "restart proof source set is invalid");
        return false;
    }
    memset(receipt, 0, sizeof(*receipt));
    memset(process, 0, sizeof(*process));
    int64_t selection_started = platform_time_monotonic_us();
    if (!rr_plan_matches_sources(proof_plan, source_tus, source_count)) {
        rr_why(why, why_len,
               "affected proof plan does not match the changed source set");
        return false;
    }
    if (!rr_collect_groups(proof_plan, immediate_only, receipt->groups,
                           &receipt->group_count, receipt->deferred_groups,
                           &receipt->deferred_group_count,
                           &receipt->bounded_proof_deferred)) {
        rr_why(why, why_len,
               "affected proof plan is incomplete or has no exact groups");
        return false;
    }
    if (immediate_only && receipt->group_count > RR_IMMEDIATE_GROUP_MAX) {
        rr_why(why, why_len,
               "affected immediate proof set exceeds resident bound");
        return false;
    }
    rr_sha256_bytes(receipt->groups, strlen(receipt->groups),
                    receipt->groups_sha256);
    if (receipt->deferred_group_count > 0)
        rr_sha256_bytes(receipt->deferred_groups,
                        strlen(receipt->deferred_groups),
                        receipt->deferred_groups_sha256);
    for (size_t i = 0; i < source_count; i++) {
        if (!rr_source_is_c(source_tus[i])) {
            rr_why(why, why_len,
                   "restart proof requires changed C translation units");
            return false;
        }
    }
    receipt->selection_us =
        platform_time_monotonic_us() - selection_started;
    char root[PATH_MAX];
    if (!realpath(repo_root, root)) {
        rr_why(why, why_len, "restart proof checkout root could not be resolved");
        return false;
    }
    struct rr_plan base = {0};
    bool cache_hit = false;
    int64_t plan_us = 0;
    pthread_mutex_lock(&g_rr_mu);
    bool plan_ok = rr_plan_load_locked(root, &base, &cache_hit, &plan_us,
                                       why, why_len);
    pthread_mutex_unlock(&g_rr_mu);
    (void)cache_hit;
    (void)plan_us;
    if (!plan_ok) return false;

    struct rr_plan plan = base;
    (void)snprintf(plan.cflags, sizeof(plan.cflags), "%s", base.test_cflags);
    (void)snprintf(plan.ldflags, sizeof(plan.ldflags), "%s", base.test_ldflags);
    (void)snprintf(plan.libs, sizeof(plan.libs), "%s", base.test_libs);
    (void)snprintf(plan.obj_dir, sizeof(plan.obj_dir), "%s", base.test_obj_dir);
    (void)snprintf(plan.link_rsp, sizeof(plan.link_rsp), "%s",
                   base.test_link_rsp);
    (void)snprintf(plan.base_reloc, sizeof(plan.base_reloc), "%s",
                   base.test_base_reloc);

    struct dev_source_record source_before = {0}, source_after = {0};
    if (guard_source) receipt->source_guard_captures++;
    if (guard_source &&
        (!zcl_dev_source_cas_capture(root, &source_before) ||
         !source_before.cas_present)) {
        rr_why(why, why_len,
               "proof source snapshot could not be captured before compile");
        return false;
    }
    const struct dev_source_record *identity =
        epoch_source ? epoch_source : &source_before;
    if (!rr_source_record_valid(identity)) {
        rr_why(why, why_len, "proof epoch source CAS record is unavailable");
        return false;
    }
    (void)snprintf(receipt->source_cas_sha3,
                   sizeof(receipt->source_cas_sha3), "%s",
                   identity->cas_root_sha3);
    struct rr_overlay *overlays = zcl_calloc(RR_OVERLAY_MAX,
                                              sizeof(*overlays),
                                              "restart proof overlays");
    if (!overlays) {
        rr_why(why, why_len, "restart proof overlay allocation failed");
        return false;
    }
    size_t overlay_count = 0;
    bool ok = rr_prepare_overlays(
        &plan, root, source_tus, source_count, identity,
        "build/dev-loop/restart-test-objects", overlays, &overlay_count,
        process, &receipt->compiler_processes, &receipt->compile_us,
        &receipt->compile_startup_us, &receipt->compile_body_us,
        why, why_len);
    receipt->source_identity_overlay = ok;
    char rsp[PATH_MAX] = {0};
    if (ok && !rr_write_response(&plan, root, overlays, overlay_count,
                                 "build/dev-loop/restart-test-objects", false,
                                 rsp,
                                 why, why_len))
        ok = false;
    if (ok) {
        ok = rr_link_cached(&plan, root, rsp,
                            "build/dev-loop/restart-test-candidates",
                            receipt->artifact_path,
                            receipt->artifact_cache_key,
                            &receipt->artifact_cache_hit,
                            &receipt->linker_processes, process,
                            &receipt->link_us, &receipt->link_startup_us,
                            &receipt->link_body_us, why, why_len);
    }
    if (rsp[0]) (void)unlink(rsp);
    free(overlays);
    if (!ok) {
        receipt->total_us = platform_time_monotonic_us() - started;
        return false;
    }
    if (guard_source) receipt->source_guard_captures++;
    if ((guard_source &&
         (!zcl_dev_source_cas_capture(root, &source_after) ||
          !source_after.cas_present ||
          strcmp(source_before.cas_root_sha3,
                 source_after.cas_root_sha3) != 0)) ||
        !rr_sha256_file(receipt->artifact_path, receipt->artifact_sha256)) {
        rr_why(why, why_len,
               "proof source changed or its candidate could not be rehashed");
        receipt->total_us = platform_time_monotonic_us() - started;
        return false;
    }
    char exact[sizeof(receipt->groups) + 16];
    if (snprintf(exact, sizeof(exact), "--exact=%s", receipt->groups) >=
        (int)sizeof(exact)) {
        rr_why(why, why_len, "affected proof selector exceeds its bound");
        return false;
    }
    const char *test_argv[RR_SOURCE_MAX + 5] = {
        receipt->artifact_path, exact, "--cache", "--cache-snapshot",
    };
    char changed_args[RR_SOURCE_MAX][ZCL_DEVLOOP_PATH_MAX + 24];
    size_t test_argc = 4;
    for (size_t i = 0; i < source_count; i++) {
        if (snprintf(changed_args[i], sizeof(changed_args[i]),
                     "--changed-source=%s", source_tus[i]) >=
            (int)sizeof(changed_args[i])) {
            rr_why(why, why_len, "changed source selector exceeds its bound");
            return false;
        }
        test_argv[test_argc++] = changed_args[i];
    }
    test_argv[test_argc] = NULL;
    /* The exact story has already run in HOT_SHADOW. Within affected proof,
     * run the last RED for this checkout/task first when it is still selected;
     * otherwise run the direct owner invariant. The complete batch still runs
     * afterward and accounts for every required group. */
    char direct_full[ZCL_TEST_GROUP_FULL_MAX] = {0};
    const char *direct_group = proof_plan->proof_group &&
        zcl_test_group_resolve_exact(proof_plan->proof_group, direct_full)
            ? direct_full : NULL;
    char priority_full[ZCL_TEST_GROUP_FULL_MAX] = {0};
    char priority_reason[64] = {0};
    bool have_priority = rr_failure_priority_select(
        root, receipt->groups, direct_group, priority_full, priority_reason);
    if (have_priority) {
        char priority_exact[ZCL_TEST_GROUP_FULL_MAX + 16];
        if (snprintf(priority_exact, sizeof(priority_exact), "--exact=%s",
                     priority_full) >= (int)sizeof(priority_exact)) {
            rr_why(why, why_len, "priority group selector exceeds its bound");
            return false;
        }
        const char *priority_argv[RR_SOURCE_MAX + 5] = {
            receipt->artifact_path, priority_exact, "--cache",
            "--cache-snapshot",
        };
        for (size_t i = 0; i < source_count; i++)
            priority_argv[4 + i] = changed_args[i];
        priority_argv[4 + source_count] = NULL;
        struct zcl_devloop_process_result priority_process = {0};
        int64_t priority_started = platform_time_monotonic_us();
        receipt->test_processes++;
        bool priority_ran = zcl_devloop_process_run_test(
            root, priority_argv, 300000, &priority_process);
        receipt->priority_test_us =
            platform_time_monotonic_us() - priority_started;
        (void)snprintf(receipt->priority_group,
                       sizeof(receipt->priority_group), "%s", priority_full);
        (void)snprintf(receipt->priority_reason,
                       sizeof(receipt->priority_reason), "%s",
                       priority_reason);
        uint32_t priority_ran_count = 0, priority_cached = 0;
        uint32_t priority_failed = 0, priority_skips = 0;
        bool priority_summary = priority_ran &&
            rr_summary_value(priority_process.output, "groups_ran=",
                             &priority_ran_count) &&
            rr_summary_value(priority_process.output, "groups_cached=",
                             &priority_cached) &&
            rr_summary_value(priority_process.output, "groups_failed=",
                             &priority_failed) &&
            rr_summary_value(priority_process.output, "self_skips=",
                             &priority_skips);
        bool priority_ok = priority_summary && !priority_process.timed_out &&
            !priority_process.term_signal && priority_process.exit_code == 0 &&
            priority_ran_count + priority_cached == 1 &&
            priority_failed == 0 && priority_skips == 0;
        if (!priority_ok) {
            if (!priority_process.cancelled)
                rr_failure_priority_store(root, priority_full);
            *process = priority_process;
            receipt->test_us += receipt->priority_test_us;
            receipt->test_startup_us += priority_process.startup_us;
            receipt->test_body_us += priority_process.body_us;
            receipt->groups_ran = priority_ran_count;
            receipt->groups_cached = priority_cached;
            receipt->groups_failed = priority_failed;
            receipt->self_skips = priority_skips;
            receipt->total_us = platform_time_monotonic_us() - started;
            rr_why(why, why_len,
                   "failure-first direct owner invariant failed");
            return false;
        }
        if (strcmp(priority_reason, "previous_failure") == 0)
            rr_failure_priority_clear(root, priority_full);
    }
    receipt->test_processes++;
    int64_t test_started = platform_time_monotonic_us();
    bool ran = zcl_devloop_process_run_test(root, test_argv, 300000, process);
    receipt->test_us += platform_time_monotonic_us() - test_started;
    receipt->test_startup_us += process->startup_us;
    receipt->test_body_us += process->body_us;
    bool summary_ok = ran &&
        rr_summary_value(process->output, "groups_ran=",
                         &receipt->groups_ran) &&
        rr_summary_value(process->output, "groups_cached=",
                         &receipt->groups_cached) &&
        rr_summary_value(process->output, "groups_failed=",
                         &receipt->groups_failed) &&
        rr_summary_value(process->output, "self_skips=",
                         &receipt->self_skips);
    bool accounted = summary_ok &&
        receipt->groups_ran <= receipt->group_count &&
        receipt->groups_cached ==
            receipt->group_count - receipt->groups_ran;
    receipt->immediate_proof_complete = ran && !process->timed_out &&
        !process->term_signal && process->exit_code == 0 && accounted &&
        receipt->groups_failed == 0 && receipt->self_skips == 0;
    receipt->integration_proof_deferred = receipt->deferred_group_count > 0;
    receipt->proof_complete = receipt->immediate_proof_complete &&
        !receipt->integration_proof_deferred;
    receipt->total_us = platform_time_monotonic_us() - started;
    if (!receipt->immediate_proof_complete) {
        char failed_group[ZCL_TEST_GROUP_FULL_MAX];
        if (!process->cancelled && rr_failed_group_from_output(
                process->output, receipt->groups, failed_group))
            rr_failure_priority_store(root, failed_group);
        char detail[256];
        if (!ran) {
            rr_why(why, why_len,
                   "affected proof runner could not be executed");
        } else if (process->timed_out) {
            rr_why(why, why_len,
                   "affected proof runner exceeded the 300000 ms bound");
        } else if (process->term_signal) {
            (void)snprintf(detail, sizeof(detail),
                           "affected proof runner terminated by signal %d",
                           process->term_signal);
            rr_why(why, why_len, detail);
        } else if (summary_ok && receipt->groups_failed > 0) {
            (void)snprintf(
                detail, sizeof(detail),
                "affected proofs failed: %u of %u exact groups failed; see process_output",
                receipt->groups_failed, receipt->group_count);
            rr_why(why, why_len, detail);
        } else if (summary_ok && receipt->self_skips > 0) {
            (void)snprintf(
                detail, sizeof(detail),
                "affected proofs incomplete: %u exact groups self-skipped; see process_output",
                receipt->self_skips);
            rr_why(why, why_len, detail);
        } else if (!summary_ok) {
            rr_why(why, why_len,
                   "affected proof runner omitted the canonical suite summary");
        } else if (!accounted) {
            rr_why(why, why_len,
                   "affected proof runner did not account for every exact group");
        } else {
            (void)snprintf(
                detail, sizeof(detail),
                "affected proof runner exited %d despite a zero-failure summary",
                process->exit_code);
            rr_why(why, why_len, detail);
        }
        return false;
    }
    return true;
}


bool zcl_devloop_restart_prove(
    const char *repo_root, const char *const *source_tus, size_t source_count,
    const struct zcl_devloop_plan *proof_plan,
    struct zcl_devloop_restart_proof_receipt *receipt,
    struct zcl_devloop_process_result *process,
    char *why, size_t why_len)
{
    return rr_restart_prove(repo_root, source_tus, source_count, proof_plan,
                            receipt, process, why, why_len, false, true, NULL);
}

bool zcl_devloop_restart_prove_immediate(
    const char *repo_root, const char *const *source_tus, size_t source_count,
    const struct zcl_devloop_plan *proof_plan,
    struct zcl_devloop_restart_proof_receipt *receipt,
    struct zcl_devloop_process_result *process,
    char *why, size_t why_len)
{
    return rr_restart_prove(repo_root, source_tus, source_count, proof_plan,
                            receipt, process, why, why_len, true, true, NULL);
}

static void rr_output_preview(const struct zcl_devloop_process_result *process,
                              char out[1025])
{
    size_t n = process ? process->output_len : 0;
    if (n > 1024) n = 1024;
    if (n) memcpy(out, process->output + process->output_len - n, n);
    out[n] = 0;
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
    bool feedback_parallel)
{
    const char *progress_phase = zcl_devloop_progress_phase(status, phase);
    struct json_value doc, files, receipt;
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
    uint64_t changed_source_bytes = 0;
    bool changed_bytes_complete = true;
    for (size_t i = 0; i < source_count; i++) {
        char full[PATH_MAX];
        struct stat st;
        uint64_t next = 0;
        if (!rr_join_root(root, sources[i], full) ||
            !rr_regular(full, &st) || st.st_size < 0 ||
            !zcl_u64_add(changed_source_bytes, (uint64_t)st.st_size, &next)) {
            changed_bytes_complete = false;
            break;
        }
        changed_source_bytes = next;
    }
    source_byte_accounting_complete = source_byte_accounting_complete &&
        changed_bytes_complete && source_guard_bytes_read <= INT64_MAX &&
        source_bytes_total <= INT64_MAX && changed_source_bytes <= INT64_MAX;
    (void)json_push_kv_bool(&doc, "source_byte_accounting_complete",
                            source_byte_accounting_complete);
    if (source_byte_accounting_complete) {
        (void)json_push_kv_int(&doc, "source_guard_bytes_read",
                               (int64_t)source_guard_bytes_read);
        (void)json_push_kv_int(&doc, "source_bytes_total",
                               (int64_t)source_bytes_total);
        (void)json_push_kv_int(&doc, "changed_source_bytes",
                               (int64_t)changed_source_bytes);
    }
    (void)json_push_kv_int(&doc, "closure_us", closure_us);
    (void)json_push_kv_int(&doc, "file_count", (int64_t)source_count);
    json_init(&files); json_set_array(&files);
    for (size_t i = 0; i < source_count; i++) {
        struct json_value item;
        json_init(&item); json_set_str(&item, sources[i]);
        (void)json_push_back(&files, &item); json_free(&item);
    }
    (void)json_push_kv(&doc, "files", &files); json_free(&files);
    if (why && why[0])
        (void)json_push_kv_str(&doc, "failure_capsule", why);
    if (process && process->output_len) {
        char preview[1025];
        rr_output_preview(process, preview);
        (void)json_push_kv_str(&doc, "process_output", preview);
        (void)json_push_kv_bool(&doc, "process_output_truncated",
                                process->output_len > 1024 ||
                                process->output_truncated);
    }
    if (process) {
        (void)json_push_kv_int(&doc, "process_startup_us",
                               process->startup_us);
        (void)json_push_kv_int(&doc, "process_body_us", process->body_us);
        (void)json_push_kv_int(&doc, "process_first_output_us",
                               process->first_output_us);
    }
    if (build) {
        json_init(&receipt); json_set_object(&receipt);
        (void)json_push_kv_str(&receipt, "schema",
                               "zcl.dev_restart_build_receipt.v1");
        if (build->artifact_path[0])
            (void)json_push_kv_str(&receipt, "artifact_path",
                                   build->artifact_path);
        if (build->artifact_sha256[0])
            (void)json_push_kv_str(&receipt, "artifact_sha256",
                                   build->artifact_sha256);
        if (build->artifact_cache_key[0])
            (void)json_push_kv_str(&receipt, "artifact_cache_key",
                                   build->artifact_cache_key);
        if (build->source_cas_sha3[0])
            (void)json_push_kv_str(&receipt, "source_cas_sha3",
                                   build->source_cas_sha3);
        (void)json_push_kv_bool(&receipt, "source_identity_overlay",
                                build->source_identity_overlay);
        (void)json_push_kv_str(&receipt, "probe", build->probe);
        (void)json_push_kv_bool(&receipt, "candidate_probe_passed",
                                build->candidate_probe_passed);
        (void)json_push_kv_bool(&receipt, "plan_cache_hit",
                                build->plan_cache_hit);
        (void)json_push_kv_bool(&receipt, "artifact_cache_hit",
                                build->artifact_cache_hit);
        (void)json_push_kv_int(&receipt, "changed_sources",
                               build->changed_sources);
        (void)json_push_kv_int(&receipt, "compiler_processes",
                               build->compiler_processes);
        (void)json_push_kv_int(&receipt, "linker_processes",
                               build->linker_processes);
        (void)json_push_kv_int(&receipt, "complete_graph_linker_processes",
                               build->complete_graph_linker_processes);
        (void)json_push_kv_int(&receipt, "probe_processes",
                               build->probe_processes);
        (void)json_push_kv_int(&receipt, "source_guard_captures",
                               build->source_guard_captures);
        (void)json_push_kv_int(&receipt, "plan_load_us",
                               build->plan_load_us);
        (void)json_push_kv_int(&receipt, "compile_us", build->compile_us);
        (void)json_push_kv_int(&receipt, "compile_startup_us",
                               build->compile_startup_us);
        (void)json_push_kv_int(&receipt, "compile_body_us",
                               build->compile_body_us);
        (void)json_push_kv_int(&receipt, "link_us", build->link_us);
        (void)json_push_kv_int(&receipt, "link_startup_us",
                               build->link_startup_us);
        (void)json_push_kv_int(&receipt, "link_body_us",
                               build->link_body_us);
        (void)json_push_kv_int(&receipt, "probe_us", build->probe_us);
        (void)json_push_kv_int(&receipt, "probe_startup_us",
                               build->probe_startup_us);
        (void)json_push_kv_int(&receipt, "probe_body_us",
                               build->probe_body_us);
        (void)json_push_kv_int(&receipt, "build_total_us", build->total_us);
        (void)json_push_kv(&doc, "build_receipt", &receipt);
        json_free(&receipt);
    }
    if (proof) {
        json_init(&receipt); json_set_object(&receipt);
        (void)json_push_kv_str(&receipt, "schema",
                               "zcl.dev_restart_proof_receipt.v1");
        if (proof->artifact_path[0])
            (void)json_push_kv_str(&receipt, "artifact_path",
                                   proof->artifact_path);
        if (proof->artifact_sha256[0])
            (void)json_push_kv_str(&receipt, "artifact_sha256",
                                   proof->artifact_sha256);
        if (proof->artifact_cache_key[0])
            (void)json_push_kv_str(&receipt, "artifact_cache_key",
                                   proof->artifact_cache_key);
        if (proof->source_cas_sha3[0])
            (void)json_push_kv_str(&receipt, "source_cas_sha3",
                                   proof->source_cas_sha3);
        (void)json_push_kv_bool(&receipt, "source_identity_overlay",
                                proof->source_identity_overlay);
        if (proof->groups_sha256[0])
            (void)json_push_kv_str(&receipt, "exact_groups_sha256",
                                   proof->groups_sha256);
        if (proof->deferred_groups_sha256[0])
            (void)json_push_kv_str(&receipt,
                                   "deferred_groups_sha256",
                                   proof->deferred_groups_sha256);
        if (proof->priority_group[0])
            (void)json_push_kv_str(&receipt, "priority_group",
                                   proof->priority_group);
        if (proof->priority_reason[0])
            (void)json_push_kv_str(&receipt, "priority_reason",
                                   proof->priority_reason);
        (void)json_push_kv_bool(&receipt, "proof_complete",
                                proof->proof_complete);
        (void)json_push_kv_bool(&receipt, "artifact_cache_hit",
                                proof->artifact_cache_hit);
        (void)json_push_kv_bool(&receipt, "immediate_proof_complete",
                                proof->immediate_proof_complete);
        (void)json_push_kv_bool(&receipt, "integration_proof_deferred",
                                proof->integration_proof_deferred);
        (void)json_push_kv_bool(&receipt, "bounded_proof_deferred",
                                proof->bounded_proof_deferred);
        (void)json_push_kv_int(&receipt, "group_count", proof->group_count);
        (void)json_push_kv_int(&receipt, "deferred_group_count",
                               proof->deferred_group_count);
        (void)json_push_kv_int(&receipt, "groups_ran", proof->groups_ran);
        (void)json_push_kv_int(&receipt, "groups_cached",
                               proof->groups_cached);
        (void)json_push_kv_int(&receipt, "groups_failed",
                               proof->groups_failed);
        (void)json_push_kv_int(&receipt, "self_skips", proof->self_skips);
        (void)json_push_kv_int(&receipt, "compiler_processes",
                               proof->compiler_processes);
        (void)json_push_kv_int(&receipt, "linker_processes",
                               proof->linker_processes);
        (void)json_push_kv_int(&receipt, "complete_graph_linker_processes",
                               proof->complete_graph_linker_processes);
        (void)json_push_kv_int(&receipt, "test_processes",
                               proof->test_processes);
        (void)json_push_kv_int(&receipt, "source_guard_captures",
                               proof->source_guard_captures);
        (void)json_push_kv_int(&receipt, "selection_us",
                               proof->selection_us);
        (void)json_push_kv_int(&receipt, "compile_us", proof->compile_us);
        (void)json_push_kv_int(&receipt, "compile_startup_us",
                               proof->compile_startup_us);
        (void)json_push_kv_int(&receipt, "compile_body_us",
                               proof->compile_body_us);
        (void)json_push_kv_int(&receipt, "link_us", proof->link_us);
        (void)json_push_kv_int(&receipt, "link_startup_us",
                               proof->link_startup_us);
        (void)json_push_kv_int(&receipt, "link_body_us",
                               proof->link_body_us);
        (void)json_push_kv_int(&receipt, "test_us", proof->test_us);
        (void)json_push_kv_int(&receipt, "test_startup_us",
                               proof->test_startup_us);
        (void)json_push_kv_int(&receipt, "test_body_us",
                               proof->test_body_us);
        (void)json_push_kv_int(&receipt, "priority_test_us",
                               proof->priority_test_us);
        (void)json_push_kv_int(&receipt, "proof_total_us", proof->total_us);
        (void)json_push_kv(&doc, "proof_receipt", &receipt);
        json_free(&receipt);
    }
    (void)json_push_kv_str(
        &doc, "agent_next_action",
        strcmp(status, "feedback_ready") == 0
            ? "candidate runtime and immediate affected proofs are green; run integration proofs before acceptance"
            : strcmp(status, "reflex_ready") == 0
                ? "candidate compile, link, and probe are green; affected proof is running asynchronously"
            : strcmp(status, "impact_ready") == 0
                ? "impact is classified; source identity and candidate diagnostics are running"
            : strcmp(status, "fallback_ready") == 0
                ? "resident proof was unavailable; conservative integration proof is running"
            : "repair the named restart refusal; no service or source was replaced");
    char wire[16384];
    size_t n = json_write(&doc, wire, sizeof(wire) - 1);
    json_free(&doc);
    if (!n) return false;
    wire[n++] = '\n'; wire[n] = 0;
    char state_why[160] = {0};
    int64_t epoch = 0;
    if (zcl_devloop_cycle_stream_publish(root, wire, n, &epoch,
                                         state_why, sizeof(state_why))) {
        (void)fwrite(wire, 1, n, stdout); (void)fflush(stdout);
        if (!zcl_devloop_cycle_stream_flush_through(
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

int zcl_devloop_restart_event(const char *repo_root,
                              const char *const *source_tus,
                              size_t source_count,
                              enum zcl_devloop_publish_mode publish_mode)
{
    if (!repo_root || !source_tus || source_count == 0 ||
        source_count > RR_SOURCE_MAX)
        return 0;
    int64_t started = platform_time_monotonic_us();
    int64_t impact_started = started;
    struct zcl_devloop_plan plan;
    if (!zcl_devloop_plan_files(source_tus, source_count, &plan) ||
        plan.docs_only || plan.consensus_risk)
        return 0;
    int64_t impact_us = platform_time_monotonic_us() - impact_started;
    for (size_t i = 0; i < source_count; i++)
        if (!rr_source_is_c(source_tus[i]))
            return 0;
    bool has_runtime_source = false;
    for (size_t i = 0; i < source_count; i++)
        has_runtime_source = has_runtime_source ||
            !rr_source_is_test_only(source_tus[i]);
    if (!has_runtime_source)
        return 0;
    /* The resident watcher has already published the immutable edit epoch and
     * IMPACT_READY before entering this compiler lane. Keep the measured path
     * classification cost in later receipts, but never emit a duplicate
     * latest-value impact event from the slower proof stage. */
    int64_t source_guard_us = 0;
    uint64_t source_guard_bytes_read = 0;
    uint64_t source_bytes_total = 0;
    bool source_byte_accounting_complete = false;
    int64_t closure_us = 0;
    uint32_t source_guard_captures = 0;
    struct zcl_devloop_restart_build_receipt build = {0};
    struct zcl_devloop_restart_proof_receipt proof = {0};
    struct zcl_devloop_process_result build_process = {0};
    struct zcl_devloop_process_result proof_process = {0};
    char why[512] = {0};
    struct dev_source_record source_before = {0}, source_after = {0};
    int64_t guard_started = platform_time_monotonic_us();
    source_guard_captures++;
    bool ok = zcl_dev_source_cas_capture(repo_root, &source_before) &&
              source_before.cas_present;
    if (ok) {
        source_guard_bytes_read = source_before.cas_bytes_read;
        source_bytes_total = source_before.cas_bytes_total;
    }
    source_guard_us += platform_time_monotonic_us() - guard_started;
    if (!ok)
        rr_why(why, sizeof(why),
               "restart epoch source snapshot could not be captured");
    int64_t closure_started = platform_time_monotonic_us();
    if (ok) {
        const char *closure_reason = "";
        bool closure_added = zcl_devloop_plan_add_closure_snapshot(
            repo_root, source_tus, source_count, &plan);
        bool closure_admissible = closure_added &&
            zcl_devloop_plan_proof_admissible(&plan, &closure_reason);
        if (!closure_admissible) {
            char detail[256];
            (void)snprintf(
                detail, sizeof(detail), "affected proof closure refused: %s",
                closure_added && closure_reason && closure_reason[0]
                    ? closure_reason : "closure_unavailable");
            rr_why(why, sizeof(why), detail);
            ok = false;
        }
    }
    closure_us = platform_time_monotonic_us() - closure_started;
    if (ok)
        ok = rr_restart_build(repo_root, source_tus, source_count, &build,
                              &build_process, why, sizeof(why), false,
                              &source_before);
    if (ok) {
        guard_started = platform_time_monotonic_us();
        source_guard_captures++;
        ok = zcl_dev_source_cas_capture(repo_root, &source_after) &&
             source_after.cas_present &&
             strcmp(source_before.cas_root_sha3,
                    source_after.cas_root_sha3) == 0;
        source_guard_us += platform_time_monotonic_us() - guard_started;
        uint64_t combined_bytes = 0;
        source_byte_accounting_complete = ok &&
            source_after.cas_bytes_total == source_bytes_total &&
            zcl_u64_add(source_guard_bytes_read,
                        source_after.cas_bytes_read, &combined_bytes);
        if (source_byte_accounting_complete)
            source_guard_bytes_read = combined_bytes;
        if (!ok)
            rr_why(why, sizeof(why),
                   "restart epoch source changed during reflex build");
    }
    if (build_process.cancelled || zcl_devloop_process_cancel_requested())
        return 2;
    bool fallback_pending = !ok &&
        (strstr(why, "proof closure refused:") ||
         strstr(why, "proof plan is incomplete") ||
         strstr(why, "proof set exceeds resident bound") ||
         strstr(why, "action plan stale"));
    if (fallback_pending) {
        proof.integration_proof_deferred = true;
        proof.bounded_proof_deferred = true;
    }
    if (!ok) {
        bool emitted = rr_emit_event(
            repo_root, source_tus, source_count,
            fallback_pending ? "fallback_ready" : "rejected",
            fallback_pending ? "conservative_proof_selected"
                             : "compile_link_probe",
            platform_time_monotonic_us() - started, publish_mode,
            build.changed_sources ? &build : NULL, &proof, &build_process,
            why, source_guard_us, source_guard_captures,
            source_guard_bytes_read, source_bytes_total,
            source_byte_accounting_complete, impact_us, closure_us,
            plan.closure_snapshot, false);
        if (!emitted)
            return ZCL_DEVLOOP_RESTART_EVENT_ERROR;
        return fallback_pending ? ZCL_DEVLOOP_RESTART_EVENT_FALLBACK_PENDING
                                : ZCL_DEVLOOP_RESTART_EVENT_FINAL;
    }

    /* REFLEX ends at a source-bound candidate probe. Affected tests are a
     * separate proof stage and may be slow; persist the useful candidate
     * result first so `dev drive` never waits on them. */
    if (!rr_emit_event(
            repo_root, source_tus, source_count, "reflex_ready",
            "candidate_probe", platform_time_monotonic_us() - started,
            publish_mode, &build, NULL, &build_process, "",
            source_guard_us, source_guard_captures,
            source_guard_bytes_read, source_bytes_total,
            source_byte_accounting_complete, impact_us, closure_us,
            plan.closure_snapshot, false))
        return ZCL_DEVLOOP_RESTART_EVENT_ERROR;

    why[0] = 0;
    ok = rr_restart_prove(repo_root, source_tus, source_count, &plan,
                          &proof, &proof_process, why, sizeof(why), true,
                          false, &source_before);
    if (ok) {
        guard_started = platform_time_monotonic_us();
        source_guard_captures++;
        ok = zcl_dev_source_cas_capture(repo_root, &source_after) &&
             source_after.cas_present &&
             strcmp(source_before.cas_root_sha3,
                    source_after.cas_root_sha3) == 0;
        source_guard_us += platform_time_monotonic_us() - guard_started;
        uint64_t combined_bytes = 0;
        source_byte_accounting_complete = ok &&
            source_byte_accounting_complete &&
            source_after.cas_bytes_total == source_bytes_total &&
            zcl_u64_add(source_guard_bytes_read,
                        source_after.cas_bytes_read, &combined_bytes);
        if (source_byte_accounting_complete)
            source_guard_bytes_read = combined_bytes;
        if (!ok)
            rr_why(why, sizeof(why),
                   "restart epoch source changed during affected proof");
    }
    if (proof_process.cancelled || zcl_devloop_process_cancel_requested())
        return ZCL_DEVLOOP_RESTART_EVENT_CANCELLED;
    fallback_pending = !ok &&
        (strstr(why, "proof plan is incomplete") ||
         strstr(why, "proof set exceeds resident bound") ||
         strstr(why, "action plan stale"));
    if (fallback_pending) {
        proof.integration_proof_deferred = true;
        proof.bounded_proof_deferred = true;
    }
    bool emitted = rr_emit_event(
        repo_root, source_tus, source_count,
        ok ? "feedback_ready" :
             fallback_pending ? "fallback_ready" : "rejected",
        ok ? "immediate_affected_proofs" :
             fallback_pending ? "conservative_proof_selected"
                              : "affected_proofs",
        platform_time_monotonic_us() - started, publish_mode, &build,
        &proof, proof_process.output_len ? &proof_process : &build_process,
        why, source_guard_us, source_guard_captures,
        source_guard_bytes_read, source_bytes_total,
        source_byte_accounting_complete, impact_us, closure_us,
        plan.closure_snapshot, false);
    if (!emitted)
        return ZCL_DEVLOOP_RESTART_EVENT_ERROR;
    if (ok)
        return ZCL_DEVLOOP_RESTART_EVENT_PROOF_PENDING;
    return fallback_pending ? ZCL_DEVLOOP_RESTART_EVENT_FALLBACK_PENDING
                            : ZCL_DEVLOOP_RESTART_EVENT_FINAL;
}

int zcl_devloop_restart_story_prove_event(
    const char *repo_root, const char *const *source_tus,
    size_t source_count, enum zcl_devloop_publish_mode publish_mode)
{
    if (!repo_root || !source_tus || source_count == 0 ||
        source_count > RR_SOURCE_MAX)
        return ZCL_DEVLOOP_RESTART_EVENT_NOT_APPLICABLE;
    int64_t started = platform_time_monotonic_us();
    struct zcl_devloop_plan plan;
    char why[512] = {0};
    if (!zcl_devloop_plan_files(source_tus, source_count, &plan) ||
        plan.docs_only || plan.consensus_risk) {
        return ZCL_DEVLOOP_RESTART_EVENT_NOT_APPLICABLE;
    }
    const char *closure_reason = "";
    bool closure_ok = zcl_devloop_plan_add_closure_snapshot(
        repo_root, source_tus, source_count, &plan) &&
        zcl_devloop_plan_proof_admissible(&plan, &closure_reason);
    if (!closure_ok) {
        (void)snprintf(why, sizeof(why),
                       "affected proof closure refused: %s",
                       closure_reason && closure_reason[0]
                           ? closure_reason : "closure_unavailable");
    }
    struct zcl_devloop_restart_proof_receipt proof = {0};
    struct zcl_devloop_process_result process = {0};
    bool ok = closure_ok && rr_restart_prove(
        repo_root, source_tus, source_count, &plan, &proof, &process,
        why, sizeof(why), true, true, NULL);
    if (process.cancelled || zcl_devloop_process_cancel_requested())
        return ZCL_DEVLOOP_RESTART_EVENT_CANCELLED;
    bool fallback = !ok &&
        (strstr(why, "proof plan is incomplete") ||
         strstr(why, "proof set exceeds resident bound") ||
         strstr(why, "action plan stale") ||
         strstr(why, "proof closure refused:"));
    if (fallback) {
        proof.integration_proof_deferred = true;
        proof.bounded_proof_deferred = true;
    }
    bool emitted = rr_emit_event(
        repo_root, source_tus, source_count,
        ok ? "feedback_ready" : fallback ? "fallback_ready" : "rejected",
        ok ? "immediate_affected_proofs" :
             fallback ? "conservative_proof_selected" : "affected_proofs",
        platform_time_monotonic_us() - started, publish_mode, NULL, &proof,
        &process, why, 0, proof.source_guard_captures, 0, 0, false,
        0, 0, plan.closure_snapshot, false);
    if (!emitted)
        return ZCL_DEVLOOP_RESTART_EVENT_ERROR;
    if (ok)
        return ZCL_DEVLOOP_RESTART_EVENT_PROOF_PENDING;
    return fallback ? ZCL_DEVLOOP_RESTART_EVENT_FALLBACK_PENDING
                    : ZCL_DEVLOOP_RESTART_EVENT_FINAL;
}
