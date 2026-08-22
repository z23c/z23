/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Resident hot-swap build authority. The persistent zclassic23-dev watcher
 * calls this directly after inotify classifies one allowlisted translation
 * unit. Make writes the action plan only when build flags/toolchain change;
 * the edit path parses no Makefile and starts no shell or CLI. Stock GCC/Clang
 * still run as bounded children: the compiler is the irreducible native-code
 * work, not orchestration.
 */

#define _GNU_SOURCE
#include "devloop.h"

#include "base/hex.h"
#include "crypto/sha256.h"
#include "crypto/sha3.h"
#include "controllers/rpc_client.h"
#include "command/native_dev_hotswap.h"
#include "hotswap/hotswap_module.h"
#include "hotswap/hotswap_service.h"
#include "json/json.h"
#include "services/dev_reflex_policy_service.h"
#include "hotswap/hotfork_capsule.h"
#include "platform/os_sandbox.h"
#include "platform/time_compat.h"
#include "util/safe_alloc.h"
#include "util/spawn.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define HS_PLAN_TEXT_MAX 12288
#define HS_ARG_MAX 256
#define HS_DEP_MAX 512

struct hs_action_plan {
    char root[PATH_MAX];
    char cc[512];
    char compiler_id[65];
    char cflags[HS_PLAN_TEXT_MAX];
    char ldflags[2048];
    struct stat stamp;
    bool loaded;
};

struct hs_dep {
    char path[PATH_MAX];
    dev_t dev;
    ino_t ino;
    off_t size;
    struct timespec mtime;
    unsigned char sha256[SHA256_OUTPUT_SIZE];
};

static pthread_mutex_t g_plan_mu = PTHREAD_MUTEX_INITIALIZER;
static struct hs_action_plan g_plan;

struct hs_hotfork_def {
    const char *owner_id;
    const char *feedback_class;
    const char *source_tu;
    const char *story_id;
    const char *fixture_id;
    const char *adapter_id;
    uint32_t max_time_ms;
    const char *forbidden_effect_mask;
    const char *exercised_surface;
};

#define HOTFORK_CAPSULE(owner_id_, feedback_class_, source_tu_, story_id_, \
                        fixture_id_, adapter_id_, max_time_ms_, \
                        forbidden_effect_mask_, surface_) \
    { owner_id_, feedback_class_, source_tu_, story_id_, fixture_id_, \
      adapter_id_, max_time_ms_, forbidden_effect_mask_, surface_ },
static const struct hs_hotfork_def k_hotfork_defs[] = {
#include "../../config/hotfork_capsules.def"
};
#undef HOTFORK_CAPSULE

static void hs_sha3_root(const char *text, char out[65]);

static void hs_why(char *why, size_t why_len, const char *message)
{
    if (why && why_len)
        (void)snprintf(why, why_len, "%s", message ? message : "unknown");
}


void zcl_devloop_hotswap_guidance(
    const char *status, const char *phase, const char *why,
    char *why_not_live, size_t why_not_live_size,
    char *next_command, size_t next_command_size)
{
    bool passed = status && strcmp(status, "passed") == 0;
    bool compile_green = status && strcmp(status, "reflex_ready") == 0;
    bool story_green = status && strcmp(status, "story_green") == 0;
    if (why_not_live && why_not_live_size) {
        const char *exact = passed ? "" : why;
        if (story_green || compile_green)
            exact = phase && strcmp(phase, "hotfork_owner_story") == 0
                ? "HOT_FORK is child-only evidence and never publishes runtime authority"
                : "reflex candidate evidence never publishes runtime authority";
        else if (!passed && (!exact || !exact[0])) {
            exact = phase && strcmp(phase, "compile") == 0
                ? "candidate compilation did not produce a publishable artifact"
                : "resident dev node did not publish the candidate";
        }
        (void)snprintf(why_not_live, why_not_live_size, "%s", exact);
    }
    if (!next_command || next_command_size == 0) return;
    const char *next =
        "z23-dev dev status --view=full";
    if (story_green) {
        next = "keep editing; exact affected proof is running asynchronously";
    } else if (compile_green) {
        next = "keep editing; the owner-bound shadow story is running";
    } else if (passed) {
        next = "keep editing; the resident authority owns the next module epoch";
    } else if ((why && strstr(why, "DEV_RESTART")) ||
               (why && strstr(why, "service ABI changed")) ||
               (why && strstr(why, "service schema changed")) ||
               (why && strstr(why, "service wire contract changed")) ||
               (why && strstr(why, "frozen KAT identity changed"))) {
        next = "make -j\"$(nproc)\" dev-bin";
    } else if (phase && strcmp(phase, "compile") == 0) {
        next = "z23-dev dev diagnose latest";
    } else if ((why && strstr(why, "cannot read RPC auth cookie")) ||
               (why && strstr(why, "returned no activation body"))) {
        next = "z23-dev dev generation current";
    }
    (void)snprintf(next_command, next_command_size, "%s", next);
}

bool zcl_devloop_hotswap_response_error(
    const struct json_value *response, char *out, size_t out_size)
{
    if (!response || response->type != JSON_OBJ || !out || out_size == 0)
        return false;
    const struct json_value *message_v = json_get(response, "message");
    const struct json_value *error_v = json_get(response, "error");
    if ((!message_v || message_v->type != JSON_STR) && error_v &&
        error_v->type == JSON_OBJ)
        message_v = json_get(error_v, "message");
    if ((!message_v || message_v->type != JSON_STR) && error_v &&
        error_v->type == JSON_STR)
        message_v = error_v;
    const char *message = message_v && message_v->type == JSON_STR
        ? json_get_str(message_v) : NULL;
    if (!message || !message[0]) return false;
    (void)snprintf(out, out_size, "%s", message);
    return true;
}

static bool hs_regular(const char *path, struct stat *out)
{
    struct stat st;
    if (!path || lstat(path, &st) != 0 || !S_ISREG(st.st_mode) ||
        S_ISLNK(st.st_mode))
        return false;
    if (out)
        *out = st;
    return true;
}

static bool hs_stat_equal(const struct stat *a, const struct stat *b)
{
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino &&
           a->st_size == b->st_size &&
           a->st_mtim.tv_sec == b->st_mtim.tv_sec &&
           a->st_mtim.tv_nsec == b->st_mtim.tv_nsec;
}

static bool hs_plan_line(char *dst, size_t cap, const char *line,
                         const char *prefix)
{
    size_t n = strlen(prefix);
    if (strncmp(line, prefix, n) != 0)
        return false;
    const char *value = line + n;
    size_t len = strcspn(value, "\r\n");
    if (len == 0 || len >= cap)
        return false;
    memcpy(dst, value, len);
    dst[len] = 0;
    return true;
}

static bool hs_lower_hex64(const char *value)
{
    if (!value || strlen(value) != 64)
        return false;
    for (size_t i = 0; i < 64; i++)
        if (!((value[i] >= '0' && value[i] <= '9') ||
              (value[i] >= 'a' && value[i] <= 'f')))
            return false;
    return true;
}

static bool hs_plan_load_locked(const char *root, bool *cache_hit,
                                int64_t *elapsed_us, char *why,
                                size_t why_len)
{
    int64_t started = platform_time_monotonic_us();
    char flags_path[PATH_MAX], makefile[PATH_MAX], manifest[PATH_MAX];
    char islands[PATH_MAX], services[PATH_MAX], shadow_owners[PATH_MAX];
    char hotfork_capsules[PATH_MAX];
    if (snprintf(flags_path, sizeof(flags_path),
                 "%s/build/hotswap/fast/flags.env", root) >=
            (int)sizeof(flags_path) ||
        snprintf(makefile, sizeof(makefile), "%s/Makefile", root) >=
            (int)sizeof(makefile) ||
        snprintf(manifest, sizeof(manifest),
                 "%s/config/hotswap_swappable.def", root) >=
            (int)sizeof(manifest) ||
        snprintf(islands, sizeof(islands),
                 "%s/config/hotswap_islands.def", root) >=
            (int)sizeof(islands) ||
        snprintf(services, sizeof(services),
                 "%s/config/hotswap_services.def", root) >=
            (int)sizeof(services) ||
        snprintf(shadow_owners, sizeof(shadow_owners),
                 "%s/config/hotswap_shadow_owners.def", root) >=
            (int)sizeof(shadow_owners) ||
        snprintf(hotfork_capsules, sizeof(hotfork_capsules),
                 "%s/config/hotfork_capsules.def", root) >=
            (int)sizeof(hotfork_capsules)) {
        hs_why(why, why_len, "action plan path overflow");
        return false;
    }
    struct stat stamp, make_st, manifest_st, islands_st, services_st;
    struct stat shadow_owners_st;
    struct stat hotfork_capsules_st;
    if (!hs_regular(flags_path, &stamp)) {
        hs_why(why, why_len,
               "resident action plan absent; run make dev-bin once");
        return false;
    }
    if (!hs_regular(makefile, &make_st) || !hs_regular(manifest, &manifest_st) ||
        !hs_regular(islands, &islands_st) ||
        !hs_regular(services, &services_st) ||
        !hs_regular(shadow_owners, &shadow_owners_st) ||
        !hs_regular(hotfork_capsules, &hotfork_capsules_st) ||
        make_st.st_mtim.tv_sec > stamp.st_mtim.tv_sec ||
        (make_st.st_mtim.tv_sec == stamp.st_mtim.tv_sec &&
         make_st.st_mtim.tv_nsec > stamp.st_mtim.tv_nsec) ||
        manifest_st.st_mtim.tv_sec > stamp.st_mtim.tv_sec ||
        (manifest_st.st_mtim.tv_sec == stamp.st_mtim.tv_sec &&
         manifest_st.st_mtim.tv_nsec > stamp.st_mtim.tv_nsec) ||
        islands_st.st_mtim.tv_sec > stamp.st_mtim.tv_sec ||
        (islands_st.st_mtim.tv_sec == stamp.st_mtim.tv_sec &&
         islands_st.st_mtim.tv_nsec > stamp.st_mtim.tv_nsec) ||
        services_st.st_mtim.tv_sec > stamp.st_mtim.tv_sec ||
        (services_st.st_mtim.tv_sec == stamp.st_mtim.tv_sec &&
         services_st.st_mtim.tv_nsec > stamp.st_mtim.tv_nsec) ||
        shadow_owners_st.st_mtim.tv_sec > stamp.st_mtim.tv_sec ||
        (shadow_owners_st.st_mtim.tv_sec == stamp.st_mtim.tv_sec &&
         shadow_owners_st.st_mtim.tv_nsec > stamp.st_mtim.tv_nsec)) {
        hs_why(why, why_len,
               "resident action plan stale; refresh after build-system change");
        return false;
    }
    if (hotfork_capsules_st.st_mtim.tv_sec > stamp.st_mtim.tv_sec ||
        (hotfork_capsules_st.st_mtim.tv_sec == stamp.st_mtim.tv_sec &&
         hotfork_capsules_st.st_mtim.tv_nsec > stamp.st_mtim.tv_nsec)) {
        hs_why(why, why_len,
               "resident action plan stale; refresh after build-system change");
        return false;
    }
    if (g_plan.loaded && strcmp(g_plan.root, root) == 0 &&
        hs_stat_equal(&g_plan.stamp, &stamp)) {
        *cache_hit = true;
        *elapsed_us = platform_time_monotonic_us() - started;
        return true;
    }

    FILE *f = fopen(flags_path, "r");
    if (!f) {
        hs_why(why, why_len, "resident action plan could not be opened");
        return false;
    }
    struct hs_action_plan next = {0};
    char line[HS_PLAN_TEXT_MAX + 32];
    while (fgets(line, sizeof(line), f)) {
        if (line[0] == '#' || line[0] == '\n' || line[0] == '\r')
            continue;
        if (hs_plan_line(next.cc, sizeof(next.cc), line, "CC=") ||
            hs_plan_line(next.compiler_id, sizeof(next.compiler_id), line,
                         "COMPILER_ID=") ||
            hs_plan_line(next.cflags, sizeof(next.cflags), line,
                         "DEV_CFLAGS=") ||
            hs_plan_line(next.ldflags, sizeof(next.ldflags), line,
                         "HOTSWAP_MODULE_LDFLAGS="))
            continue;
        fclose(f);
        hs_why(why, why_len, "resident action plan has an unknown field");
        return false;
    }
    bool read_error = ferror(f) != 0;
    fclose(f);
    if (read_error || !next.cc[0] || !hs_lower_hex64(next.compiler_id) ||
        !next.cflags[0] || !next.ldflags[0] ||
        !strstr(next.cflags, "-DZCL_DEV_BUILD") ||
        !strstr(next.ldflags, "-Wl,-Bsymbolic")) {
        hs_why(why, why_len,
               "resident action plan incomplete or missing safety flags");
        return false;
    }
    if (strstr(next.cflags, "-flto") || strstr(next.ldflags, "-flto") ||
        strstr(next.cflags, "-fuse-linker-plugin") ||
        strstr(next.ldflags, "-fuse-linker-plugin")) {
        hs_why(why, why_len,
               "resident action plan contains release-only LTO flags");
        return false;
    }
    (void)snprintf(next.root, sizeof(next.root), "%s", root);
    next.stamp = stamp;
    next.loaded = true;
    g_plan = next;
    *cache_hit = false;
    *elapsed_us = platform_time_monotonic_us() - started;
    return true;
}

static bool hs_sha256_digest_file(const char *path,
                                  unsigned char out[SHA256_OUTPUT_SIZE])
{
    FILE *f = fopen(path, "rb");
    if (!f)
        return false;
    struct sha256_ctx ctx;
    sha256_init(&ctx);
    unsigned char buf[65536];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0)
        sha256_write(&ctx, buf, n);
    bool ok = ferror(f) == 0;
    fclose(f);
    if (!ok)
        return false;
    sha256_finalize(&ctx, out);
    return true;
}

static bool hs_depfile_read(const char *root, const char *path,
                            struct hs_dep *deps, size_t *count,
                            bool snapshot)
{
    *count = 0;
    FILE *f = fopen(path, "r");
    if (!f)
        return false;
    char text[65536];
    size_t n = fread(text, 1, sizeof(text) - 1, f);
    bool ok = !ferror(f) && !feof(f) ? false : true;
    fclose(f);
    if (!ok || n == 0 || n >= sizeof(text))
        return false;
    text[n] = 0;
    for (size_t i = 0; i < n; i++)
        if (text[i] == '\\' && (text[i + 1] == '\n' || text[i + 1] == '\r'))
            text[i] = text[i + 1] = ' ';
    char *colon = strchr(text, ':');
    if (!colon)
        return false;
    const char *argv[HS_DEP_MAX + 1];
    size_t argc = zcl_argv_split(colon + 1, argv, HS_DEP_MAX + 1);
    if (argc == 0 || argc >= HS_DEP_MAX)
        return false;
    for (size_t i = 0; i < argc; i++) {
        char full[PATH_MAX];
        int pn = argv[i][0] == '/'
            ? snprintf(full, sizeof(full), "%s", argv[i])
            : snprintf(full, sizeof(full), "%s/%s", root, argv[i]);
        struct stat st;
        if (pn <= 0 || pn >= (int)sizeof(full))
            return false;
        if (strstr(full, "/build/hotswap/fast/.resident-") != NULL)
            continue; /* generated unity wrapper, never source authority */
        if (!hs_regular(full, &st))
            return false;
        struct hs_dep *d = &deps[(*count)++];
        (void)snprintf(d->path, sizeof(d->path), "%s", full);
        if (snapshot) {
            d->dev = st.st_dev;
            d->ino = st.st_ino;
            d->size = st.st_size;
            d->mtime = st.st_mtim;
            if (!hs_sha256_digest_file(full, d->sha256))
                return false;
        }
    }
    return true;
}

static const struct hs_dep *hs_dep_find(const struct hs_dep *deps,
                                        size_t count, const char *path)
{
    for (size_t i = 0; i < count; i++)
        if (strcmp(deps[i].path, path) == 0)
            return &deps[i];
    return NULL;
}

static bool hs_deps_unchanged(const struct hs_dep *before, size_t before_n,
                              const struct hs_dep *after, size_t after_n,
                              char *why, size_t why_len)
{
    for (size_t i = 0; i < after_n; i++) {
        const struct hs_dep *old = hs_dep_find(before, before_n, after[i].path);
        if (!old) {
            if (why && why_len)
                (void)snprintf(why, why_len,
                               "dependency baseline learned new input: %.180s",
                               after[i].path);
            return false;
        }
        if (old->dev != after[i].dev || old->ino != after[i].ino ||
            old->size != after[i].size ||
            old->mtime.tv_sec != after[i].mtime.tv_sec ||
            old->mtime.tv_nsec != after[i].mtime.tv_nsec ||
            memcmp(old->sha256, after[i].sha256, SHA256_OUTPUT_SIZE) != 0) {
            if (why && why_len)
                (void)snprintf(why, why_len,
                               "input mutated during resident build: %.190s",
                               after[i].path);
            return false;
        }
    }
    return true;
}

static bool hs_sha256_file(const char *path, char out[65])
{
    unsigned char digest[32];
    if (!hs_sha256_digest_file(path, digest))
        return false;
    zcl_hex_encode(digest, sizeof(digest), out);
    return true;
}

static bool hs_mkdirs(const char *path)
{
    char tmp[PATH_MAX];
    struct stat st;
    if (!path || path[0] != '/' || strlen(path) >= sizeof(tmp))
        return false;
    (void)snprintf(tmp, sizeof(tmp), "%s", path);
    for (char *p = tmp + 1; *p; p++) {
        if (*p != '/')
            continue;
        *p = 0;
        if (mkdir(tmp, 0700) != 0) {
            if (errno != EEXIST || lstat(tmp, &st) != 0 ||
                !S_ISDIR(st.st_mode) || S_ISLNK(st.st_mode))
                return false;
        }
        *p = '/';
    }
    if (mkdir(tmp, 0700) != 0 &&
        (errno != EEXIST || lstat(tmp, &st) != 0 ||
         !S_ISDIR(st.st_mode) || S_ISLNK(st.st_mode)))
        return false;
    return chmod(tmp, 0700) == 0;
}

static bool hs_cache_root_for(const char *lane, char out[PATH_MAX])
{
    const char *configured = getenv("ZCL_DEV_ARTIFACT_CACHE");
    const char *home = getenv("HOME");
    int n;
    if (configured && configured[0]) {
        if (configured[0] != '/' || strstr(configured, ".."))
            return false;
        n = snprintf(out, PATH_MAX, "%s/%s", configured, lane);
    } else {
        if (!home || home[0] != '/')
            return false;
        n = snprintf(out, PATH_MAX,
                     "%s/.cache/zclassic23/dev-artifacts/%s", home, lane);
    }
    return n > 0 && n < PATH_MAX && hs_mkdirs(out);
}

static bool hs_cache_root(char out[PATH_MAX])
{
    return hs_cache_root_for("hotswap-v1", out);
}

static void hs_key_field(struct sha256_ctx *ctx, const char *label,
                         const void *data, size_t len)
{
    uint64_t n = (uint64_t)len;
    sha256_write(ctx, (const unsigned char *)label, strlen(label) + 1);
    sha256_write(ctx, (const unsigned char *)&n, sizeof(n));
    if (len)
        sha256_write(ctx, data, len);
}

static bool hs_normalize_root(const char *text, const char *root,
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

static bool hs_cache_key(const struct hs_action_plan *plan,
                         const char *root, const char *owner,
                         const struct hs_dep *deps, size_t dep_count,
                         char out[65])
{
    static const char domain[] = "zcl.dev_artifact_cache.hotswap.v1";
    char normalized_cflags[HS_PLAN_TEXT_MAX];
    if (!hs_normalize_root(plan->cflags, root, normalized_cflags,
                           sizeof(normalized_cflags)))
        return false;
    struct sha256_ctx ctx;
    unsigned char digest[SHA256_OUTPUT_SIZE];
    sha256_init(&ctx);
    hs_key_field(&ctx, "domain", domain, sizeof(domain) - 1);
    hs_key_field(&ctx, "compiler", plan->compiler_id,
                 strlen(plan->compiler_id));
    hs_key_field(&ctx, "cc", plan->cc, strlen(plan->cc));
    hs_key_field(&ctx, "cflags", normalized_cflags,
                 strlen(normalized_cflags));
    hs_key_field(&ctx, "ldflags", plan->ldflags, strlen(plan->ldflags));
    hs_key_field(&ctx, "owner", owner, strlen(owner));
    for (size_t i = 0; i < dep_count; i++) {
        const char *path = deps[i].path;
        size_t root_len = strlen(root);
        if (strncmp(path, root, root_len) == 0 && path[root_len] == '/')
            path += root_len + 1;
        hs_key_field(&ctx, "dependency_path", path, strlen(path));
        hs_key_field(&ctx, "dependency_sha256", deps[i].sha256,
                     sizeof(deps[i].sha256));
    }
    sha256_finalize(&ctx, digest);
    zcl_hex_encode(digest, sizeof(digest), out);
    return true;
}

static int hs_cache_lock(const char *cache_root, const char key[65],
                         char obj_path[PATH_MAX], char so_path[PATH_MAX],
                         char hash_path[PATH_MAX])
{
    char lock_path[PATH_MAX];
    if (snprintf(lock_path, sizeof(lock_path), "%s/%s.lock", cache_root,
                 key) >= (int)sizeof(lock_path) ||
        snprintf(obj_path, PATH_MAX, "%s/%s.o", cache_root, key) >= PATH_MAX ||
        snprintf(so_path, PATH_MAX, "%s/%s.so", cache_root, key) >= PATH_MAX ||
        snprintf(hash_path, PATH_MAX, "%s/%s.sha256", cache_root, key) >=
            PATH_MAX)
        return -1;
    int fd = open(lock_path,
                  O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
    struct stat st;
    if (fd < 0 || fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) ||
        flock(fd, LOCK_EX) != 0) {
        if (fd >= 0) close(fd);
        return -1;
    }
    return fd;
}

static bool hs_read_hash(const char *path, char out[65])
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

static bool hs_force_cache_copy_for_test(void)
{
    const char *test_process = getenv("ZCL_DEVLOOP_TEST_PROCESS");
    const char *force_copy = getenv("ZCL_DEVLOOP_TEST_FORCE_CACHE_COPY");
    return test_process && strcmp(test_process, "1") == 0 && force_copy &&
           strcmp(force_copy, "1") == 0;
}

static bool hs_copy_publish(const char *source, const char *target,
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
    if (ok && (fchmod(temp_fd, 0444) != 0 || fsync(temp_fd) != 0))
        ok = false;
    if (close(temp_fd) != 0)
        ok = false;
    char actual[65];
    if (ok && (!hs_sha256_file(temp, actual) ||
               strcmp(actual, expected_sha256) != 0))
        ok = false;
    if (ok && link(temp, target) != 0) {
        if (errno != EEXIST || !hs_regular(target, NULL) ||
            !hs_sha256_file(target, actual) ||
            strcmp(actual, expected_sha256) != 0 ||
            chmod(target, 0444) != 0)
            ok = false;
    }
    (void)unlink(temp);
    return ok;
}

static bool hs_link_or_copy_publish(const char *source, const char *target,
                                    const char expected_sha256[65])
{
    if (!hs_force_cache_copy_for_test() && link(source, target) == 0)
        return chmod(target, 0444) == 0;
    int link_errno = hs_force_cache_copy_for_test() ? EXDEV : errno;
    if (link_errno == EEXIST) {
        char actual[65];
        return hs_regular(target, NULL) && hs_sha256_file(target, actual) &&
               strcmp(actual, expected_sha256) == 0 &&
               chmod(target, 0444) == 0;
    }
    if (link_errno != EXDEV)
        return false;
    return hs_copy_publish(source, target, expected_sha256);
}

static bool hs_publish_artifact_path(const char *root, const char *safe,
                                     const char *source_so,
                                     const char artifact_sha256[65],
                                     char out[4096])
{
    if (snprintf(out, 4096, "%s/build/hotswap/%s-%s.so", root, safe,
                 artifact_sha256) >= 4096)
        return false;
    return hs_link_or_copy_publish(source_so, out, artifact_sha256);
}

static bool hs_cache_lookup(const char *root, const char *safe,
                            const char *cache_obj, const char *cache_so,
                            const char *cache_hash,
                            struct zcl_devloop_hotswap_build_receipt *receipt)
{
    char expected[65], actual[65], object_sha256[65];
    if (!hs_regular(cache_hash, NULL) || !hs_regular(cache_so, NULL) ||
        !hs_regular(cache_obj, NULL) ||
        !hs_read_hash(cache_hash, expected) ||
        !hs_sha256_file(cache_so, actual) || strcmp(expected, actual) != 0 ||
        !hs_sha256_file(cache_obj, object_sha256))
        return false;
    (void)snprintf(receipt->candidate_object_sha256,
                   sizeof(receipt->candidate_object_sha256), "%s",
                   object_sha256);
    (void)snprintf(receipt->artifact_sha256,
                   sizeof(receipt->artifact_sha256), "%s", actual);
    return hs_publish_artifact_path(root, safe, cache_so, actual,
                                    receipt->artifact_path);
}

static bool hs_cache_publish(const char *cache_obj, const char *cache_so,
                             const char *cache_hash, const char *built_obj,
                             const char object_hash[65], const char *built_so,
                             const char hash[65])
{
    if (!hs_link_or_copy_publish(built_obj, cache_obj, object_hash) ||
        !hs_link_or_copy_publish(built_so, cache_so, hash))
        return false;
    char temp[PATH_MAX];
    int n = snprintf(temp, sizeof(temp), "%s.tmp.%ld", cache_hash,
                     (long)getpid());
    if (n <= 0 || n >= (int)sizeof(temp))
        return false;
    (void)unlink(temp); /* safe under the per-key lock; clears a crashed writer */
    int fd = open(temp,
                  O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                  0600);
    if (fd < 0)
        return false;
    char line[66];
    (void)snprintf(line, sizeof(line), "%s\n", hash);
    bool ok = write(fd, line, 65) == 65 && fsync(fd) == 0;
    int close_rc = close(fd);
    ok = ok && close_rc == 0;
    if (!ok) {
        (void)unlink(temp);
        return false;
    }
    if (rename(temp, cache_hash) != 0) {
        (void)unlink(temp);
        return false;
    }
    return true;
}

static bool hs_temp(char *out, size_t out_len, const char *root,
                    const char *suffix)
{
    int n = snprintf(out, out_len,
                     "%s/build/hotswap/fast/.resident-XXXXXX%s", root,
                     suffix);
    if (n <= 0 || (size_t)n >= out_len)
        return false;
    int fd = mkstemps(out, (int)strlen(suffix));
    if (fd < 0)
        return false;
    close(fd);
    return true;
}

static bool hs_run_compile(const struct hs_action_plan *plan,
                           const char *root, const char *source_tu,
                           const char *compile_input,
                           const char *obj, const char *dep,
                           struct zcl_devloop_process_result *result,
                           int64_t *elapsed_us, char *why, size_t why_len)
{
    char cc[sizeof(plan->cc)], flags[sizeof(plan->cflags)];
    (void)snprintf(cc, sizeof(cc), "%s", plan->cc);
    (void)snprintf(flags, sizeof(flags), "%s", plan->cflags);
    const char *argv[HS_ARG_MAX];
    size_t argc = zcl_argv_split(cc, argv, HS_ARG_MAX);
    const char *flagv[HS_ARG_MAX];
    size_t flagc = zcl_argv_split(flags, flagv, HS_ARG_MAX);
    if (!argc || argc + flagc + 14 >= HS_ARG_MAX) {
        hs_why(why, why_len, "resident compile action exceeds argv bound");
        return false;
    }
    for (size_t i = 0; i < flagc; i++)
        argv[argc++] = flagv[i];
    char source_define[320];
    char service_source_define[320];
    (void)snprintf(source_define, sizeof(source_define),
                   "-DZCL_HOTSWAP_MODULE_SOURCE_TU=\"%s\"", source_tu);
    (void)snprintf(service_source_define, sizeof(service_source_define),
                   "-DZCL_HOTSWAP_SERVICE_SOURCE_TU=\"%s\"", source_tu);
    argv[argc++] = "-fPIC";
    argv[argc++] = "-DZCL_HOTSWAP_MODULE_GEN";
    argv[argc++] = "-DZCL_HOTSWAP_SERVICE_GEN";
    argv[argc++] = source_define;
    argv[argc++] = service_source_define;
    argv[argc++] = "-MD";
    argv[argc++] = "-MF";
    argv[argc++] = dep;
    argv[argc++] = "-c";
    argv[argc++] = "-o";
    argv[argc++] = obj;
    argv[argc++] = compile_input;
    argv[argc] = NULL;
    int64_t started = platform_time_monotonic_us();
    bool ran = zcl_devloop_process_run(root, argv, 30000, result);
    *elapsed_us = platform_time_monotonic_us() - started;
    if (!ran || result->timed_out || result->term_signal ||
        result->exit_code != 0) {
        hs_why(why, why_len, "resident module compile failed");
        return false;
    }
    return true;
}

static bool hs_write_generated(const char *path, const char *text,
                               char *why, size_t why_len)
{
    int fd = open(path, O_WRONLY | O_TRUNC | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        hs_why(why, why_len, "could not open confined generated capsule input");
        return false;
    }
    size_t len = strlen(text), off = 0;
    while (off < len) {
        ssize_t wrote = write(fd, text + off, len - off);
        if (wrote < 0 && errno == EINTR) continue;
        if (wrote <= 0) break;
        off += (size_t)wrote;
    }
    bool ok = off == len && close(fd) == 0;
    if (!ok) hs_why(why, why_len, "could not seal generated capsule input");
    return ok;
}

static bool hs_run_hotfork_compile(
    const struct hs_action_plan *plan, const char *root,
    const char *input, const char *obj, const char *dep,
    struct zcl_devloop_process_result *result, int64_t *elapsed_us,
    char *why, size_t why_len)
{
    char cc[sizeof(plan->cc)], flags[sizeof(plan->cflags)];
    (void)snprintf(cc, sizeof(cc), "%s", plan->cc);
    (void)snprintf(flags, sizeof(flags), "%s", plan->cflags);
    const char *argv[HS_ARG_MAX], *flagv[HS_ARG_MAX];
    size_t argc = zcl_argv_split(cc, argv, HS_ARG_MAX);
    size_t flagc = zcl_argv_split(flags, flagv, HS_ARG_MAX);
    if (!argc || argc + flagc + 11 >= HS_ARG_MAX) {
        hs_why(why, why_len, "HOT_FORK compile action exceeds argv bound");
        return false;
    }
    for (size_t i = 0; i < flagc; i++) argv[argc++] = flagv[i];
    argv[argc++] = "-fPIC";
    argv[argc++] = "-fvisibility=hidden";
    argv[argc++] = "-MD";
    argv[argc++] = "-MF";
    argv[argc++] = dep;
    argv[argc++] = "-c";
    argv[argc++] = "-o";
    argv[argc++] = obj;
    argv[argc++] = input;
    argv[argc] = NULL;
    int64_t started = platform_time_monotonic_us();
    bool ran = zcl_devloop_process_run(root, argv, 30000, result);
    *elapsed_us = platform_time_monotonic_us() - started;
    if (!ran || result->timed_out || result->term_signal ||
        result->exit_code != 0) {
        hs_why(why, why_len, "HOT_FORK candidate compile failed");
        return false;
    }
    return true;
}

static bool hs_run_hotfork_link(
    const struct hs_action_plan *plan, const char *root,
    const char *candidate_obj, const char *descriptor_obj,
    const char *version_script, const char *so,
    struct zcl_devloop_process_result *result, int64_t *elapsed_us,
    char *why, size_t why_len)
{
    char cc[sizeof(plan->cc)];
    (void)snprintf(cc, sizeof(cc), "%s", plan->cc);
    const char *argv[HS_ARG_MAX];
    size_t argc = zcl_argv_split(cc, argv, HS_ARG_MAX);
    char version_arg[PATH_MAX + 32];
    if (!argc || argc + 12 >= HS_ARG_MAX ||
        snprintf(version_arg, sizeof(version_arg),
                 "-Wl,--version-script=%s", version_script) >=
            (int)sizeof(version_arg)) {
        hs_why(why, why_len, "HOT_FORK link action exceeds argv bound");
        return false;
    }
    argv[argc++] = "-shared";
    argv[argc++] = "-Wl,--build-id=none";
    argv[argc++] = "-Wl,-z,relro";
    argv[argc++] = "-Wl,-z,noexecstack";
    argv[argc++] = "-Wl,-Bsymbolic";
    argv[argc++] = version_arg;
    argv[argc++] = "-o";
    argv[argc++] = so;
    argv[argc++] = candidate_obj;
    argv[argc++] = descriptor_obj;
    argv[argc] = NULL;
    int64_t started = platform_time_monotonic_us();
    bool ran = zcl_devloop_process_run(root, argv, 30000, result);
    *elapsed_us = platform_time_monotonic_us() - started;
    if (!ran || result->timed_out || result->term_signal ||
        result->exit_code != 0) {
        hs_why(why, why_len, "HOT_FORK capsule link failed");
        return false;
    }
    return true;
}

static bool hs_run_owner_compile(
    const struct hs_action_plan *plan, const char *root,
    const char *source_tu, const char *obj, const char *dep,
    struct zcl_devloop_process_result *result, int64_t *elapsed_us,
    char *why, size_t why_len)
{
    char cc[sizeof(plan->cc)], flags[sizeof(plan->cflags)];
    (void)snprintf(cc, sizeof(cc), "%s", plan->cc);
    (void)snprintf(flags, sizeof(flags), "%s", plan->cflags);
    const char *argv[HS_ARG_MAX], *flagv[HS_ARG_MAX];
    size_t argc = zcl_argv_split(cc, argv, HS_ARG_MAX);
    size_t flagc = zcl_argv_split(flags, flagv, HS_ARG_MAX);
    if (!argc || argc + flagc + 7 >= HS_ARG_MAX) {
        hs_why(why, why_len, "authority-shell compile exceeds argv bound");
        return false;
    }
    for (size_t i = 0; i < flagc; i++) argv[argc++] = flagv[i];
    argv[argc++] = "-MD";
    argv[argc++] = "-MF";
    argv[argc++] = dep;
    argv[argc++] = "-c";
    argv[argc++] = "-o";
    argv[argc++] = obj;
    argv[argc++] = source_tu;
    argv[argc] = NULL;
    int64_t started = platform_time_monotonic_us();
    bool ran = zcl_devloop_process_run(root, argv, 30000, result);
    *elapsed_us = platform_time_monotonic_us() - started;
    if (!ran || result->timed_out || result->term_signal ||
        result->exit_code != 0) {
        hs_why(why, why_len, "static authority shell semantic compile failed");
        return false;
    }
    return true;
}

/* Compile-check the static authority shell, but never link or load it. Its
 * mapped pure service is the only dynamic candidate and the only code the
 * forked story invokes. */
static bool hs_shadow_owner_compile(
    const char *root, const char *source_tu,
    struct zcl_devloop_hotswap_build_receipt *receipt,
    struct zcl_devloop_process_result *result, int64_t *elapsed_us,
    char *why, size_t why_len)
{
    struct hs_action_plan plan = {0};
    bool cache_hit = false;
    int64_t plan_us = 0;
    pthread_mutex_lock(&g_plan_mu);
    bool loaded = hs_plan_load_locked(root, &cache_hit, &plan_us,
                                      why, why_len);
    if (loaded) plan = g_plan;
    pthread_mutex_unlock(&g_plan_mu);
    (void)cache_hit;
    (void)plan_us;
    if (!loaded) return false;
    char full[PATH_MAX], obj[PATH_MAX] = {0}, dep[PATH_MAX] = {0};
    if (!source_tu || source_tu[0] == '/' || strstr(source_tu, "..") ||
        snprintf(full, sizeof(full), "%s/%s", root, source_tu) >=
            (int)sizeof(full) || !hs_regular(full, NULL) ||
        !hs_temp(obj, sizeof(obj), root, ".o") ||
        !hs_temp(dep, sizeof(dep), root, ".d")) {
        hs_why(why, why_len, "shadow authority shell is not a confined source");
        if (obj[0]) (void)unlink(obj);
        if (dep[0]) (void)unlink(dep);
        return false;
    }
    bool ok = hs_run_owner_compile(&plan, root, source_tu, obj, dep, result,
                                   elapsed_us, why, why_len);
    if (ok) {
        struct hs_dep *deps = zcl_malloc(sizeof(*deps) * HS_DEP_MAX,
                                         "shadow shell dependencies");
        size_t dep_count = 0;
        ok = deps && hs_depfile_read(root, dep, deps, &dep_count, true) &&
             dep_count > 0 && !zcl_devloop_process_cancel_requested();
        free(deps);
        if (!ok)
            hs_why(why, why_len,
                   "shadow shell dependency capture was incomplete or superseded");
    }
    if (ok && (!receipt ||
               !hs_sha256_file(obj, receipt->candidate_object_sha256))) {
        hs_why(why, why_len, "could not bind authority-shell candidate object");
        ok = false;
    }
    if (ok) {
        (void)snprintf(receipt->source_tu, sizeof(receipt->source_tu), "%s",
                       source_tu);
        receipt->compiler_processes++;
        receipt->compile_us += *elapsed_us;
        receipt->total_us += *elapsed_us;
    }
    (void)unlink(obj);
    (void)unlink(dep);
    return ok;
}

static bool hs_files_equal(const char *a, const char *b)
{
    FILE *fa = fopen(a, "rb"), *fb = fopen(b, "rb");
    if (!fa || !fb) {
        if (fa) fclose(fa);
        if (fb) fclose(fb);
        return false;
    }
    bool same = true;
    unsigned char ba[4096], bb[4096];
    for (;;) {
        size_t na = fread(ba, 1, sizeof(ba), fa);
        size_t nb = fread(bb, 1, sizeof(bb), fb);
        if (na != nb || (na && memcmp(ba, bb, na) != 0)) {
            same = false;
            break;
        }
        if (na < sizeof(ba)) {
            same = !ferror(fa) && !ferror(fb);
            break;
        }
    }
    fclose(fa);
    fclose(fb);
    return same;
}

static bool hs_unity_source(const char *root, const char *owner,
                            const char *members, const char *safe,
                            char out[PATH_MAX],
                            char *why, size_t why_len)
{
    out[0] = 0;
    if (!members || !members[0])
        return true;
    char temp[PATH_MAX];
    if (!hs_temp(temp, sizeof(temp), root, ".c") ||
        snprintf(out, PATH_MAX, "%s/build/hotswap/fast/%s.island.c",
                 root, safe) >= PATH_MAX) {
        hs_why(why, why_len, "could not allocate confined island wrapper");
        return false;
    }
    FILE *f = fopen(temp, "w");
    if (!f) {
        (void)unlink(temp);
        out[0] = 0;
        hs_why(why, why_len, "could not open confined island wrapper");
        return false;
    }
    char member_text[2048];
    (void)snprintf(member_text, sizeof(member_text), "%s", members);
    const char *memberv[64];
    size_t memberc = zcl_argv_split(member_text, memberv, 64);
    bool ok = memberc > 0;
    for (size_t i = 0; ok && i < memberc; i++) {
        char full[PATH_MAX];
        ok = memberv[i][0] != '/' && !strstr(memberv[i], "..") &&
             snprintf(full, sizeof(full), "%s/%s", root, memberv[i]) <
                 (int)sizeof(full) && hs_regular(full, NULL) &&
             fprintf(f, "#include \"%s\"\n", full) > 0;
    }
    char owner_full[PATH_MAX];
    ok = ok && snprintf(owner_full, sizeof(owner_full), "%s/%s", root,
                        owner) < (int)sizeof(owner_full) &&
         hs_regular(owner_full, NULL) &&
         fprintf(f, "#include \"%s\"\n", owner_full) > 0;
    ok = ok && fflush(f) == 0 && fsync(fileno(f)) == 0;
    fclose(f);
    if (!ok) {
        (void)unlink(temp);
        out[0] = 0;
        hs_why(why, why_len, "island member list is invalid or unwritable");
        return false;
    }
    if (hs_regular(out, NULL) && hs_files_equal(temp, out)) {
        (void)unlink(temp);
    } else {
        (void)unlink(out);
        if (rename(temp, out) != 0) {
            (void)unlink(temp);
            out[0] = 0;
            hs_why(why, why_len, "could not publish stable island wrapper");
            return false;
        }
    }
    return true;
}

static bool hs_run_link(const struct hs_action_plan *plan,
                        const char *root, const char *obj, const char *so,
                        struct zcl_devloop_process_result *result,
                        int64_t *elapsed_us, char *why, size_t why_len)
{
    char cc[sizeof(plan->cc)], flags[sizeof(plan->ldflags)];
    (void)snprintf(cc, sizeof(cc), "%s", plan->cc);
    (void)snprintf(flags, sizeof(flags), "%s", plan->ldflags);
    const char *argv[HS_ARG_MAX], *flagv[HS_ARG_MAX];
    size_t argc = zcl_argv_split(cc, argv, HS_ARG_MAX);
    size_t flagc = zcl_argv_split(flags, flagv, HS_ARG_MAX);
    if (!argc || argc + flagc + 4 >= HS_ARG_MAX) {
        hs_why(why, why_len, "resident link action exceeds argv bound");
        return false;
    }
    for (size_t i = 0; i < flagc; i++)
        argv[argc++] = flagv[i];
    argv[argc++] = "-o";
    argv[argc++] = so;
    argv[argc++] = obj;
    argv[argc] = NULL;
    int64_t started = platform_time_monotonic_us();
    bool ran = zcl_devloop_process_run(root, argv, 30000, result);
    *elapsed_us = platform_time_monotonic_us() - started;
    if (!ran || result->timed_out || result->term_signal ||
        result->exit_code != 0) {
        hs_why(why, why_len, "resident module link failed");
        return false;
    }
    return true;
}

bool zcl_devloop_hotswap_build(
    const char *repo_root, const char *source_tu,
    struct zcl_devloop_hotswap_build_receipt *receipt,
    struct zcl_devloop_process_result *process,
    char *why, size_t why_len)
{
    int64_t started = platform_time_monotonic_us();
    if (why && why_len) why[0] = 0;
    const char *owner = hotswap_island_owner_for_path(source_tu);
    bool service_island = false;
    if (!owner) {
        owner = zcl_hotswap_service_source_for_path(source_tu);
        service_island = owner != NULL;
    }
    if (!repo_root || !source_tu || !receipt || !process ||
        source_tu[0] == '/' || strstr(source_tu, "..") || !owner) {
        hs_why(why, why_len, "source is outside the compiled swappable allowlist");
        return false;
    }
    memset(receipt, 0, sizeof(*receipt));
    memset(process, 0, sizeof(*process));
    char root[PATH_MAX], source_path[PATH_MAX];
    if (!realpath(repo_root, root) ||
        snprintf(source_path, sizeof(source_path), "%s/%s", root, owner) >=
            (int)sizeof(source_path) || !hs_regular(source_path, NULL)) {
        hs_why(why, why_len, "source path is not a regular checkout file");
        return false;
    }

    struct hs_action_plan plan = {0};
    pthread_mutex_lock(&g_plan_mu);
    bool plan_ok = hs_plan_load_locked(root, &receipt->plan_cache_hit,
                                       &receipt->plan_load_us, why, why_len);
    if (plan_ok)
        plan = g_plan;
    pthread_mutex_unlock(&g_plan_mu);
    if (!plan_ok)
        return false;

    char safe[256];
    size_t sn = strlen(owner);
    if (sn >= sizeof(safe)) {
        hs_why(why, why_len, "source path exceeds artifact-name bound");
        return false;
    }
    for (size_t i = 0; i <= sn; i++) {
        unsigned char c = (unsigned char)owner[i];
        safe[i] = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                  (c >= '0' && c <= '9') || c == '.' || c == '-'
            ? (char)c : c ? '_' : 0;
    }
    char cached_dep[PATH_MAX], tmp_o[PATH_MAX] = {0}, tmp_d[PATH_MAX] = {0};
    char tmp_so[PATH_MAX] = {0}, unity[PATH_MAX] = {0};
    char cache_root[PATH_MAX] = {0}, cache_obj[PATH_MAX] = {0};
    char cache_so[PATH_MAX] = {0};
    char cache_hash[PATH_MAX] = {0};
    int cache_fd = -1;
    if (snprintf(cached_dep, sizeof(cached_dep),
                 "%s/build/hotswap/fast/%s.d", root, safe) >=
            (int)sizeof(cached_dep) ||
        !hs_temp(tmp_o, sizeof(tmp_o), root, ".o") ||
        !hs_temp(tmp_d, sizeof(tmp_d), root, ".d") ||
        !hs_temp(tmp_so, sizeof(tmp_so), root, ".so")) {
        hs_why(why, why_len, "could not allocate confined build temporaries");
        goto fail;
    }
    const char *members = service_island
        ? zcl_hotswap_shadow_members_for_service(owner)
        : hotswap_island_members_for_source(owner);
    /* The deterministic fake-compiler fixture tests cache publication, not
     * the checkout-compiled member registry. Its isolated root deliberately
     * carries only synthetic sources. */
    if (service_island && getenv("ZCL_DEVLOOP_TEST_PROCESS"))
        members = NULL;
    if ((!service_island && !members) ||
        (members && !hs_unity_source(root, owner, members, safe, unity,
                                     why, why_len)))
        goto fail;
    const char *compile_input = unity[0] ? unity : owner;

    struct hs_dep *before = zcl_malloc(sizeof(*before) * HS_DEP_MAX,
                                       "hotswap dependency baseline");
    struct hs_dep *after = zcl_malloc(sizeof(*after) * HS_DEP_MAX,
                                      "hotswap dependency result");
    if (!before || !after) {
        free(before);
        free(after);
        hs_why(why, why_len, "dependency snapshot allocation failed");
        goto fail;
    }
    size_t before_n = 0, after_n = 0;
    bool have_baseline = hs_depfile_read(root, cached_dep, before, &before_n,
                                         true);
    if (have_baseline &&
        hs_cache_key(&plan, root, owner, before, before_n,
                     receipt->artifact_cache_key) &&
        hs_cache_root(cache_root)) {
        cache_fd = hs_cache_lock(cache_root, receipt->artifact_cache_key,
                                 cache_obj, cache_so, cache_hash);
        if (cache_fd >= 0 &&
            hs_cache_lookup(root, safe, cache_obj, cache_so, cache_hash,
                            receipt)) {
            receipt->artifact_cache_hit = true;
            receipt->dependency_count = (uint32_t)before_n;
            (void)snprintf(receipt->source_tu, sizeof(receipt->source_tu),
                           "%s", owner);
            receipt->publish_us = platform_time_monotonic_us() - started -
                                  receipt->plan_load_us;
            receipt->total_us = platform_time_monotonic_us() - started;
            free(before);
            free(after);
            (void)flock(cache_fd, LOCK_UN);
            (void)close(cache_fd);
            (void)unlink(tmp_o);
            (void)unlink(tmp_d);
            (void)unlink(tmp_so);
            return true;
        }
        if (cache_fd >= 0) {
            /* A .so without its final hash marker, or a marker whose content
             * does not verify, is a partial/corrupt entry. Under the per-key
             * lock it cannot be a publisher still in flight. */
            (void)unlink(cache_so);
            (void)unlink(cache_obj);
            (void)unlink(cache_hash);
        }
    }
    receipt->compiler_processes = 1;
    if (!hs_run_compile(&plan, root, owner, compile_input, tmp_o, tmp_d,
                        process,
                        &receipt->compile_us, why, why_len)) {
        free(before);
        free(after);
        goto fail;
    }
    if (!hs_depfile_read(root, tmp_d, after, &after_n, true)) {
        free(before);
        free(after);
        hs_why(why, why_len, "compiler produced no valid bounded depfile");
        goto fail;
    }
    /* Refresh the next edit's dependency baseline even when this first/new
     * dependency observation is refused. rename is confined to build/. */
    (void)unlink(cached_dep);
    if (rename(tmp_d, cached_dep) != 0) {
        free(before);
        free(after);
        hs_why(why, why_len, "could not publish dependency baseline");
        goto fail;
    }
    tmp_d[0] = 0;
    receipt->dependency_count = (uint32_t)after_n;
    bool stable = have_baseline &&
        hs_deps_unchanged(before, before_n, after, after_n, why, why_len);
    char post_key[65] = {0};
    if (stable && receipt->artifact_cache_key[0] &&
        (!hs_cache_key(&plan, root, owner, after, after_n, post_key) ||
         strcmp(post_key, receipt->artifact_cache_key) != 0)) {
        hs_why(why, why_len,
               "artifact cache key changed across dependency verification");
        stable = false;
    }
    free(before);
    free(after);
    if (!stable) {
        if (!have_baseline)
            hs_why(why, why_len,
                   "dependency baseline initialized; save once more to activate");
        goto fail;
    }
    receipt->linker_processes = 1;
    if (!hs_sha256_file(tmp_o, receipt->candidate_object_sha256)) {
        hs_why(why, why_len, "could not hash exact candidate object");
        goto fail;
    }
    if (!hs_run_link(&plan, root, tmp_o, tmp_so, process, &receipt->link_us,
                     why, why_len))
        goto fail;

    int64_t publish_started = platform_time_monotonic_us();
    if (!hs_sha256_file(tmp_so, receipt->artifact_sha256)) {
        hs_why(why, why_len, "could not hash resident module artifact");
        goto fail;
    }
    if (cache_fd >= 0 &&
        !hs_cache_publish(cache_obj, cache_so, cache_hash, tmp_o,
                          receipt->candidate_object_sha256, tmp_so,
                          receipt->artifact_sha256)) {
        hs_why(why, why_len,
               "shared artifact cache publication or verification failed");
        goto fail;
    }
    const char *published_source = cache_fd >= 0 ? cache_so : tmp_so;
    if (!hs_publish_artifact_path(root, safe, published_source,
                                  receipt->artifact_sha256,
                                  receipt->artifact_path)) {
        hs_why(why, why_len,
               "content-addressed artifact collision or publish failure");
        goto fail;
    }
    receipt->publish_us = platform_time_monotonic_us() - publish_started;
    (void)snprintf(receipt->source_tu, sizeof(receipt->source_tu), "%s",
                   owner);
    receipt->total_us = platform_time_monotonic_us() - started;
    (void)unlink(tmp_o);
    (void)unlink(tmp_so);
    if (cache_fd >= 0) {
        (void)flock(cache_fd, LOCK_UN);
        (void)close(cache_fd);
    }
    return true;

fail:
    if (tmp_o[0]) (void)unlink(tmp_o);
    if (tmp_d[0]) (void)unlink(tmp_d);
    if (tmp_so[0]) (void)unlink(tmp_so);
    if (cache_fd >= 0) {
        (void)flock(cache_fd, LOCK_UN);
        (void)close(cache_fd);
    }
    receipt->total_us = platform_time_monotonic_us() - started;
    return false;
}

static bool hs_hotfork_def_valid(const struct hs_hotfork_def *def)
{
    static const char required_forbidden_effects[] =
        "git|github|make|shell|sqlite|dht|network|publication|full_link|full_suite";
    return def && def->owner_id && def->owner_id[0] &&
        def->feedback_class && def->source_tu && def->source_tu[0] &&
        def->story_id && def->story_id[0] && def->fixture_id &&
        def->fixture_id[0] && def->adapter_id && def->adapter_id[0] &&
        def->forbidden_effect_mask && def->exercised_surface &&
        def->exercised_surface[0] &&
        strcmp(def->feedback_class, "HOT_FORK") == 0 &&
        strcmp(def->adapter_id, def->story_id) == 0 &&
        def->max_time_ms > 0 && def->max_time_ms <= 1000 &&
        strcmp(def->forbidden_effect_mask, required_forbidden_effects) == 0;
}

bool zcl_devloop_hotfork_registry_validate(void)
{
    const size_t count = sizeof(k_hotfork_defs) / sizeof(k_hotfork_defs[0]);
    for (size_t i = 0; i < count; i++) {
        if (!hs_hotfork_def_valid(&k_hotfork_defs[i])) return false;
        for (size_t j = i + 1; j < count; j++)
            if (strcmp(k_hotfork_defs[i].owner_id,
                       k_hotfork_defs[j].owner_id) == 0 ||
                strcmp(k_hotfork_defs[i].source_tu,
                       k_hotfork_defs[j].source_tu) == 0 ||
                strcmp(k_hotfork_defs[i].story_id,
                       k_hotfork_defs[j].story_id) == 0)
                return false;
    }
    return count > 0;
}

static const struct hs_hotfork_def *hs_hotfork_for_path(const char *path)
{
    if (!path) return NULL;
    for (size_t i = 0; i < sizeof(k_hotfork_defs) / sizeof(k_hotfork_defs[0]);
         i++)
        if (strcmp(k_hotfork_defs[i].source_tu, path) == 0) {
            const struct hs_hotfork_def *def = &k_hotfork_defs[i];
            return hs_hotfork_def_valid(def) ? def : NULL;
        }
    return NULL;
}

static void hs_hotfork_story_roots(const struct hs_hotfork_def *def,
                                   char story_root[65],
                                   char fixture_root[65])
{
    char story[768], fixture[1536];
    (void)snprintf(story, sizeof(story),
        "zcl.dev.hotfork.story.v2\n%s\n%s\n%s\n%s\n%s\n%s\n%u\n%s\n%s\n",
        def->owner_id, def->feedback_class, def->source_tu, def->story_id,
        def->fixture_id, def->adapter_id, def->max_time_ms,
        def->forbidden_effect_mask, def->exercised_surface);
    if (strcmp(def->story_id,
               "vcs-devloop-publication-envelope.v1") == 0) {
        (void)snprintf(fixture, sizeof(fixture),
            "zcl.dev.hotfork.fixture.v1\n"
            "root=zero-reject,nonzero-accept\n"
            "job=canonical-roundtrip,field-preservation,bad-magic-reject,"
            "zero-required-root-reject,bad-version-reject\n"
            "receipt=waiting-zero-artifact-roundtrip,field-preservation,"
            "accepted-zero-artifact-reject,accepted-artifact-roundtrip,"
            "wrong-length-reject\n%s\n",
            def->story_id);
    } else if (strcmp(def->story_id,
                      "app-native-read-rpc-composition.v1") == 0) {
        (void)snprintf(fixture, sizeof(fixture),
            "zcl.dev.hotfork.fixture.v1\n"
            "tokens=array-wrap,legacy-pass-through\n"
            "names=resolve-params,list-noargs\n"
            "messaging=inbox-noargs\n"
            "market=profile-params,list-noargs,status-noargs,content-noargs\n"
            "swaps=chains-noargs,state-params,list-noargs\n"
            "transport=frozen-child-stub,no-cookie,no-activation\n%s\n",
            def->story_id);
    } else if (strcmp(def->story_id,
                      "zcode-moderation-input-policy.v1") == 0) {
        (void)snprintf(fixture, sizeof(fixture),
            "zcl.dev.hotfork.fixture.v1\n"
            "no-keys=empty-object;reject=null,array,nonempty\n"
            "backlog=exact-three,positive-cutoffs,explicit-scratch\n"
            "reject=unknown-key,zero-height,string-height,nonscratch\n"
            "authority=validation-only,no-projection,no-service-lease\n%s\n",
            def->story_id);
    } else if (strcmp(def->story_id,
                      "zcode-dev-input-policy.v1") == 0) {
        (void)snprintf(fixture, sizeof(fixture),
            "zcl.dev.hotfork.fixture.v1\n"
            "json=string-present,string-missing,int-present,int-fallback\n"
            "roots=lowercase-decode,canonical-render,uppercase-reject\n"
            "wire=even-decode,odd-reject,bound-reject\n"
            "paths=equal,parent,child,sibling;candidate=canonical,traversal-reject\n"
            "authority=validation-only,no-ledger,no-rpc,no-cas-write\n%s\n",
            def->story_id);
    } else if (strcmp(def->story_id,
                      "zcode-epoch-propose-input-policy.v1") == 0) {
        (void)snprintf(fixture, sizeof(fixture),
            "zcl.dev.hotfork.fixture.v1\n"
            "json=string-present,string-missing,closed-key-set\n"
            "roots=lowercase-decode,uppercase-reject,missing-reject\n"
            "epoch=positive,zero-reject,negative-reject\n"
            "proposal=exact-valid,unknown-key-reject,nonscratch-reject\n"
            "authority=validation-only,no-projection,no-cas-write\n%s\n",
            def->story_id);
    } else if (strcmp(def->story_id,
                      "zcode-passport-input-policy.v1") == 0) {
        (void)snprintf(fixture, sizeof(fixture),
            "zcl.dev.hotfork.fixture.v1\n"
            "keys=evidence-allowed,signature-commit-only,unknown-reject\n"
            "roots=exact-plan,optional-job-pair,uppercase-reject\n"
            "shape=workspace-alone-reject,unknown-key-reject,empty-reject\n"
            "commit=exact-shape\n"
            "authority=validation-only,no-signature,no-storage,no-publication\n%s\n",
            def->story_id);
    } else if (strcmp(def->story_id,
                      "zcode-workspace-input-policy.v1") == 0) {
        (void)snprintf(fixture, sizeof(fixture),
            "zcl.dev.hotfork.fixture.v1\n"
            "roots=lowercase-decode,uppercase-reject,missing-reject\n"
            "keys=manifest-allowed,signature-commit-only,unknown-reject,null-reject\n"
            "zero=all-zero-accept,nonzero-reject\n"
            "authority=validation-only,no-service,no-storage,no-publication\n%s\n",
            def->story_id);
    } else if (strcmp(def->story_id,
                      "source-package-transport-shape.v1") == 0) {
        (void)snprintf(fixture, sizeof(fixture),
            "zcl.dev.hotfork.fixture.v1\n"
            "marker=exact-path,exact-bytes\n"
            "files=license,manifest,shards,lane,marker,authority,offline-inputs\n"
            "counts=no-authority,with-authority,null-zero\n"
            "bounds=file-at-end-reject,offline-at-end-reject\n"
            "authority=shape-only,no-filesystem,no-cas,no-signing,no-publication\n%s\n",
            def->story_id);
    } else if (strcmp(def->story_id,
                      "zcode-source-bundle-input-policy.v1") == 0) {
        (void)snprintf(fixture, sizeof(fixture),
            "zcl.dev.hotfork.fixture.v1\n"
            "json=string-present,string-missing,type-reject\n"
            "roots=source,named,uppercase-reject\n"
            "paths=equal,parent,child,sibling\n"
            "render=roots,metrics,authority-flags\n"
            "authority=policy-only,no-filesystem,no-cas,no-package-import,no-publication\n%s\n",
            def->story_id);
    } else if (strcmp(def->story_id,
                      "test-group-catalog-selection-policy.v1") == 0) {
        (void)snprintf(fixture, sizeof(fixture),
            "zcl.dev.hotfork.fixture.v1\n"
            "catalog=known-present,unknown-absent\n"
            "exclusive=latency-yes,ordinary-no\n"
            "semantic-leaf=declared-yes,ordinary-no\n"
            "resolve=prefixless-and-full-exact,substring-reject\n"
            "family=declared-oracle,unrelated-reject\n"
            "integration=declared-yes,ordinary-no,policy-valid\n"
            "expansion=ordinary-one,immediate-excludes-integration\n"
            "authority=read-only-catalog,no-process,no-filesystem,no-build\n%s\n",
            def->story_id);
    } else if (strcmp(def->story_id,
                      "shop-want-view-contract.v1") == 0) {
        (void)snprintf(fixture, sizeof(fixture),
            "zcl.dev.hotfork.fixture.v1\n"
            "row=bounded-criteria,open,reviewed-ok,no-spec-hash\n"
            "render=preview,amount,state,next-action\n"
            "json=preview,truncation,amount,expiry\n"
            "contract=exact-service-id,frozen-kat\n"
            "fulfillment=hidden,ready,evidence-blocked,closed\n"
            "authority=caller-owned-row,pure-service,no-store,no-clock,no-wallet\n%s\n",
            def->story_id);
    } else if (strcmp(def->story_id,
                      "shop-want-command-input-core.v1") == 0) {
        (void)snprintf(fixture, sizeof(fixture),
            "zcl.dev.hotfork.fixture.v1\n"
            "hex=lowercase-32,uppercase-reject,length-reject\n"
            "want=amount,criteria,expiry,nonce,deterministic-signature\n"
            "reject=expiry-equal-now\n"
            "authority=caller-owned-json,pure-build-and-sign,no-db,no-filesystem,no-clock,no-publication\n%s\n",
            def->story_id);
    } else if (strcmp(def->story_id,
                      "command-registry-input-validation-core.v1") == 0) {
        (void)snprintf(fixture, sizeof(fixture),
            "zcl.dev.hotfork.fixture.v1\n"
            "booleans=wait-for-edit,all,string-reject\n"
            "maximum-bytes=package-256m,space-8m,path-sensitive\n"
            "cutoffs=height,mtp,epoch-capacity,positive-only\n"
            "cpu=one-through-600\n"
            "shop=issued,expires,amount,integer-or-string-nonce\n"
            "budget=manifest-derived,default-floor\n"
            "authority=caller-owned-spec-and-json,pure-validation,no-handler,no-latency-ring,no-publication\n%s\n",
            def->story_id);
    } else if (strcmp(def->story_id,
                      "zcode-package-view-contract.v1") == 0) {
        (void)snprintf(fixture, sizeof(fixture),
            "zcl.dev.hotfork.fixture.v1\n"
            "entry=identity,metadata,counts,invalid-incomplete\n"
            "guide=static-authority-boundaries,next-command\n"
            "publish=ready,needs-source,blocked,incomplete-reject\n"
            "contract=exact-service-id,frozen-kat\n"
            "authority=caller-owned-input,pure-service,no-cas,no-index,no-publication\n%s\n",
            def->story_id);
    } else if (strcmp(def->story_id,
                      "shop-status-view-contract.v1") == 0) {
        (void)snprintf(fixture, sizeof(fixture),
            "zcl.dev.hotfork.fixture.v1\n"
            "wallet=absent,plaintext,encrypted,unreadable\n"
            "closed=stub,no-identity,no-wallet,no-db,no-announcement\n"
            "live=real-tor,identity,encrypted-wallet,db,schema,announcement\n"
            "contract=exact-service-id,frozen-kat\n"
            "authority=copied-snapshot,pure-service,no-files,no-db,no-tor,no-wallet\n%s\n",
            def->story_id);
    } else if (strcmp(def->story_id,
                      "shop-reputation-view-contract.v1") == 0) {
        (void)snprintf(fixture, sizeof(fixture),
            "zcl.dev.hotfork.fixture.v1\n"
            "roots=present,absent,pair-exact,pair-mismatch\n"
            "evidence=releases,packages,observation,reproduction,attestation\n"
            "unavailable=availability,paid-fulfillment\n"
            "contract=exact-service-id,frozen-kat\n"
            "authority=copied-facts,pure-service,no-files,no-signatures,no-clock,no-ledger\n%s\n",
            def->story_id);
    } else if (strcmp(def->story_id,
                      "zcode-work-input-core.v1") == 0) {
        (void)snprintf(fixture, sizeof(fixture),
            "zcl.dev.hotfork.fixture.v1\n"
            "json=string-present,type-reject,int-present,fallback\n"
            "scopes=top-level,dedupe,header-source-test,empty-reject\n"
            "bytes=selected-manifest-members,missing-ignore,overflow-reject\n"
            "authority=caller-owned-input,pure-normalization,no-files,no-db,no-cas,no-process\n%s\n",
            def->story_id);
    } else if (strcmp(def->story_id,
                      "zcode-corpus-command-core.v1") == 0) {
        (void)snprintf(fixture, sizeof(fixture),
            "zcl.dev.hotfork.fixture.v1\n"
            "root=lowercase-64,uppercase-reject,length-reject\n"
            "checkpoint=total-loc,overflow-reject,null-reject\n"
            "shard=counted,durable,excluded,totals,overflow-reject\n"
            "authority=caller-owned-structs,pure-aggregation,no-storage,no-clock,no-service-publication\n%s\n",
            def->story_id);
    } else if (strcmp(def->story_id,
                      "devloop-watch-classification-core.v1") == 0) {
        (void)snprintf(fixture, sizeof(fixture),
            "zcl.dev.hotfork.fixture.v1\n"
            "sources=lowercase-c,header-reject,uppercase-reject,null-reject\n"
            "epoch=all-c,mixed-reject,empty-reject,null-reject\n"
            "component=same-owner,mixed-owner,root-path\n"
            "authority=copied-paths,pure-classification,no-filesystem,no-signals,no-process\n%s\n",
            def->story_id);
    } else if (strcmp(def->story_id,
                      "devloop-cycle-diagnostic-policy.v1") == 0) {
        (void)snprintf(fixture, sizeof(fixture),
            "zcl.dev.hotfork.fixture.v1\n"
            "diagnostic=first-actionable,transient-reject,compiler-shape\n"
            "preview=printable,control-sanitize,truncation,bounds-reject\n"
            "proof=passed-verify-only\n"
            "publish=verify,apply,invalid,port\n"
            "watcher=stopped,starting,runtime-starting,current\n"
            "authority=copied-text-and-enums,pure-policy,no-filesystem,no-process,no-publication\n%s\n",
            def->story_id);
    } else if (strcmp(def->story_id,
                      "devloop-plan-classification.v1") == 0) {
        (void)snprintf(fixture, sizeof(fixture),
            "zcl.dev.hotfork.fixture.v1\n"
            "paths=safe,traversal,absolute,control,docs,sealed,relevant,temp\n"
            "watch=mutation,attribute,ignored,source-dir\n"
            "dimensions=names,status-names\n"
            "authority=copied-paths-and-masks,pure-classification,no-index,no-filesystem,no-process\n%s\n",
            def->story_id);
    } else if (strcmp(def->story_id,
                      "native-dev-hotswap-receipt-policy.v1") == 0) {
        (void)snprintf(fixture, sizeof(fixture),
            "zcl.dev.hotfork.fixture.v1\n"
            "hooks=commit,probe,quiesce-off,quiesce-on\n"
            "module-report=green,refused\n"
            "service-report=green,restart-refused\n"
            "commit-boundary=empty-reject,capacity-reject\n"
            "probe-boundary=missing-leaf-reject\n%s\n",
            def->story_id);
    } else if (strcmp(def->story_id,
                      "native-dev-input-and-interrupt-policy.v1") == 0) {
        (void)snprintf(fixture, sizeof(fixture),
            "zcl.dev.hotfork.fixture.v1\n"
            "files=relative-valid,absolute-reject,traversal-reject\n"
            "cursor=integer,fallback,string-reject\n"
            "interrupt=STORY_RED,compile_red,proof_pending\n"
            "group=canonical,dash-reject\n"
            "generation=gen-lower64,legacy-lower64,uppercase-reject\n"
            "failure-id=lower64,uppercase-reject,short-reject\n%s\n",
            def->story_id);
    } else if (strcmp(def->story_id,
                      "curve25519-rfc7748-calculation.v1") == 0) {
        (void)snprintf(fixture, sizeof(fixture),
            "zcl.dev.hotfork.fixture.v1\n"
            "rfc7748=alice-public,alice-bob-shared-secret\n"
            "inputs=caller-owned,unchanged\n"
            "cleanup=module-local-cleanse-observed\n"
            "authority=pure-calculation,no-wallet,no-keys-from-host,no-rng,no-filesystem,no-network\n%s\n",
            def->story_id);
    } else if (strcmp(def->story_id,
                      "package-policy-boundary-calculation.v1") == 0) {
        (void)snprintf(fixture, sizeof(fixture),
            "zcl.dev.hotfork.fixture.v1\n"
            "tiers=names,limits,score-before-ratio\n"
            "ratio=zero-divisor,ordinary,saturating\n"
            "week=pre-epoch,epoch,monday\n"
            "boundaries=publish,download,concurrency,pin,announce,request-burst\n"
            "verifier=self,score,approval,allow\n"
            "names=no-credit,offence,unknown\n"
            "authority=pure-calculation,caller-owned-facts,no-clock,no-filesystem,no-network\n%s\n",
            def->story_id);
    } else {
        (void)snprintf(fixture, sizeof(fixture),
            "zcl.dev.hotfork.fixture.v1\n"
            "result=ok,null-argument,package-incomplete,package-manifest,"
            "source-carrier-shape,package-chunk,source-verification,destination\n"
            "shard=0a,ff;reject=0A,100,missing-suffix\n%s\n",
            def->story_id);
    }
    hs_sha3_root(story, story_root);
    hs_sha3_root(fixture, fixture_root);
}

static int hs_hotfork_unity_source(
    const struct hs_hotfork_def *def, const char *source_path,
    char *out, size_t out_size)
{
    if (strcmp(def->story_id,
               "curve25519-rfc7748-calculation.v1") == 0) {
        return snprintf(out, out_size,
            "#define _GNU_SOURCE\n"
            "#include \"hotswap/hotfork_capsule.h\"\n"
            "#include <stddef.h>\n"
            "#include <stdio.h>\n"
            "static unsigned hf_cleanse_calls;\n"
            "void memory_cleanse(void *ptr,size_t len) {"
            " volatile unsigned char *p=ptr; while(len--) *p++=0; hf_cleanse_calls++; }\n"
            "#include \"%s\"\n"
            "__attribute__((visibility(\"hidden\")))\n"
            "bool zcl_hotfork_candidate_story_v1(struct zcl_hotfork_observation_v1 *out) {\n"
            " if (!out) { return false; } memset(out,0,sizeof(*out));"
            " out->magic=ZCL_HOTFORK_OBSERVATION_MAGIC;\n"
            " #define HF_CHECK(x) do { out->checks_run++; if (x) out->checks_passed++; } while(0)\n"
            " static const uint8_t alice[32]={"
            "0x77,0x07,0x6d,0x0a,0x73,0x18,0xa5,0x7d,0x3c,0x16,0xc1,0x72,0x51,0xb2,0x66,0x45,"
            "0xdf,0x4c,0x2f,0x87,0xeb,0xc0,0x99,0x2a,0xb1,0x77,0xfb,0xa5,0x1d,0xb9,0x2c,0x2a};"
            " static const uint8_t bob[32]={"
            "0x5d,0xab,0x08,0x7e,0x62,0x4a,0x8a,0x4b,0x79,0xe1,0x7f,0x8b,0x83,0x80,0x0e,0xe6,"
            "0x6f,0x3b,0xb1,0x29,0x26,0x18,0xb6,0xfd,0x1c,0x2f,0x8b,0x27,0xff,0x88,0xe0,0xeb};"
            " static const uint8_t alice_public[32]={"
            "0x85,0x20,0xf0,0x09,0x89,0x30,0xa7,0x54,0x74,0x8b,0x7d,0xdc,0xb4,0x3e,0xf7,0x5a,"
            "0x0d,0xbf,0x3a,0x0d,0x26,0x38,0x1a,0xf4,0xeb,0xa4,0xa9,0x8e,0xaa,0x9b,0x4e,0x6a};"
            " static const uint8_t shared_expected[32]={"
            "0x4a,0x5d,0x9d,0x5b,0xa4,0xce,0x2d,0xe1,0x72,0x8e,0x3b,0xf4,0x80,0x35,0x0f,0x25,"
            "0xe0,0x7e,0x21,0xc9,0x47,0xd1,0x9e,0x33,0x76,0xf0,0x9b,0x3c,0x1e,0x16,0x17,0x42};"
            " uint8_t a_before[32],b_before[32],ap[32],bp[32],ab[32],ba[32];"
            " memcpy(a_before,alice,32); memcpy(b_before,bob,32); hf_cleanse_calls=0;\n"
            " HF_CHECK(curve25519_scalarmult_base(ap,alice) && memcmp(ap,alice_public,32)==0);"
            " bool dh=curve25519_scalarmult_base(bp,bob)"
            " && curve25519_scalarmult(ab,alice,bp)"
            " && curve25519_scalarmult(ba,bob,ap);"
            " HF_CHECK(dh && memcmp(ab,ba,32)==0 && memcmp(ab,shared_expected,32)==0);"
            " HF_CHECK(memcmp(alice,a_before,32)==0 && memcmp(bob,b_before,32)==0);"
            " HF_CHECK(hf_cleanse_calls==32);\n"
            " #undef HF_CHECK\n"
            " snprintf(out->exercised_surface,sizeof(out->exercised_surface),\"%s\");"
            " snprintf(out->detail,sizeof(out->detail),\"checks=%%u/%%u\","
            " out->checks_passed,out->checks_run);"
            " return out->checks_run==4 && out->checks_passed==4; }\n",
            source_path, def->exercised_surface);
    }
    if (strcmp(def->story_id,
               "package-policy-boundary-calculation.v1") == 0) {
        int prefix = snprintf(out, out_size,
            "#define _GNU_SOURCE\n"
            "#include \"hotswap/hotfork_capsule.h\"\n"
            "#include <stdio.h>\n"
            "#include <string.h>\n"
            "#include \"%s\"\n"
            "static bool hf_dec(bool allow,const char *rule,struct vcs_policy_decision d) {"
            " return d.allow==allow && (allow ? d.rule==NULL : d.rule && strcmp(d.rule,rule)==0); }\n"
            "__attribute__((visibility(\"hidden\")))\n"
            "bool zcl_hotfork_candidate_story_v1(struct zcl_hotfork_observation_v1 *out) {\n"
            " if (!out) { return false; } memset(out,0,sizeof(*out));"
            " out->magic=ZCL_HOTFORK_OBSERVATION_MAGIC;\n"
            " #define HF_CHECK(x) do { out->checks_run++; if (x) out->checks_passed++; } while(0)\n"
            " const struct vcs_policy_limits *n=vcs_policy_limits_for(VCS_POLICY_TIER_NEW_USER);"
            " const struct vcs_policy_limits *c=vcs_policy_limits_for(VCS_POLICY_TIER_EARNED_CONTRIBUTOR);"
            " const struct vcs_policy_limits *s=vcs_policy_limits_for(VCS_POLICY_TIER_VERIFIED_SEEDER);\n"
            " HF_CHECK(strcmp(vcs_policy_tier_string(VCS_POLICY_TIER_NEW_USER),\"new-user\")==0"
            " && strcmp(vcs_policy_tier_string(VCS_POLICY_TIER_EARNED_CONTRIBUTOR),\"earned-contributor\")==0"
            " && strcmp(vcs_policy_tier_string(VCS_POLICY_TIER_VERIFIED_SEEDER),\"verified-seeder\")==0"
            " && strcmp(vcs_policy_tier_string(VCS_POLICY_TIER_COUNT),\"unknown\")==0);"
            " HF_CHECK(n->publish_per_week==1 && n->request_burst_per_window==512"
            " && c->request_burst_per_window==1024 && s->request_burst_per_window==2048"
            " && vcs_policy_limits_for(VCS_POLICY_TIER_COUNT)==n);"
            " HF_CHECK(vcs_policy_ratio_milli(7,0)==7000"
            " && vcs_policy_ratio_milli(5,2)==2500"
            " && vcs_policy_ratio_milli(UINT64_MAX,1)==UINT64_MAX);"
            " HF_CHECK(vcs_policy_tier_for(0,UINT64_MAX,1)==VCS_POLICY_TIER_NEW_USER"
            " && vcs_policy_tier_for(100,0,0)==VCS_POLICY_TIER_EARNED_CONTRIBUTOR"
            " && vcs_policy_tier_for(500,UINT64_C(256)*1024*1024,UINT64_C(256)*1024*1024)"
            " ==VCS_POLICY_TIER_VERIFIED_SEEDER);"
            " HF_CHECK(vcs_policy_week_start(-1)==-3 && vcs_policy_week_start(0)==-3"
            " && vcs_policy_week_start(4)==4);\n",
            source_path);
        if (prefix <= 0 || prefix >= (int)out_size)
            return prefix;
        int suffix = snprintf(out + prefix, out_size - (size_t)prefix,
            " HF_CHECK(hf_dec(true,NULL,vcs_policy_check_publish(VCS_POLICY_TIER_NEW_USER,0))"
            " && hf_dec(false,VCS_POLICY_RULE_PUBLISH_FREQUENCY,"
            "vcs_policy_check_publish(VCS_POLICY_TIER_NEW_USER,1)));"
            " HF_CHECK(hf_dec(true,NULL,vcs_policy_check_download(VCS_POLICY_TIER_NEW_USER,"
            "VCS_POLICY_FREE_WEEKLY_DOWNLOAD_BYTES-1,1))"
            " && hf_dec(false,VCS_POLICY_RULE_DOWNLOAD_ALLOWANCE,"
            "vcs_policy_check_download(VCS_POLICY_TIER_NEW_USER,VCS_POLICY_FREE_WEEKLY_DOWNLOAD_BYTES-1,2)));"
            " HF_CHECK(hf_dec(true,NULL,vcs_policy_check_concurrent_downloads(VCS_POLICY_TIER_NEW_USER,0))"
            " && hf_dec(false,VCS_POLICY_RULE_CONCURRENT_DOWNLOADS,"
            "vcs_policy_check_concurrent_downloads(VCS_POLICY_TIER_NEW_USER,1)));"
            " HF_CHECK(hf_dec(false,VCS_POLICY_RULE_PIN_ALLOWANCE,"
            "vcs_policy_check_pin(VCS_POLICY_TIER_NEW_USER,0,0))"
            " && hf_dec(true,NULL,vcs_policy_check_pin(VCS_POLICY_TIER_EARNED_CONTRIBUTOR,0,1)));"
            " HF_CHECK(hf_dec(true,NULL,vcs_policy_check_announce(VCS_POLICY_TIER_NEW_USER,3))"
            " && hf_dec(false,VCS_POLICY_RULE_ANNOUNCE_RATE,"
            "vcs_policy_check_announce(VCS_POLICY_TIER_NEW_USER,4)));"
            " HF_CHECK(hf_dec(true,NULL,vcs_policy_check_request_burst(VCS_POLICY_TIER_NEW_USER,511))"
            " && hf_dec(false,VCS_POLICY_RULE_REQUEST_BURST,"
            "vcs_policy_check_request_burst(VCS_POLICY_TIER_NEW_USER,512))"
            " && hf_dec(true,NULL,vcs_policy_check_request_burst(VCS_POLICY_TIER_EARNED_CONTRIBUTOR,1023))"
            " && hf_dec(false,VCS_POLICY_RULE_REQUEST_BURST,"
            "vcs_policy_check_request_burst(VCS_POLICY_TIER_VERIFIED_SEEDER,2048)));"
            " HF_CHECK(vcs_policy_queue_priority(VCS_POLICY_TIER_NEW_USER)==0"
            " && vcs_policy_queue_priority(VCS_POLICY_TIER_EARNED_CONTRIBUTOR)==1"
            " && vcs_policy_queue_priority(VCS_POLICY_TIER_VERIFIED_SEEDER)==2);"
            " HF_CHECK(hf_dec(false,VCS_POLICY_RULE_SELF_VERIFICATION,vcs_policy_check_verifier(2000,true,true))"
            " && hf_dec(false,VCS_POLICY_RULE_VERIFIER_SCORE,vcs_policy_check_verifier(999,true,false))"
            " && hf_dec(false,VCS_POLICY_RULE_VERIFIER_APPROVED,vcs_policy_check_verifier(1000,false,false))"
            " && hf_dec(true,NULL,vcs_policy_check_verifier(1000,true,false)));"
            " static const char *const nc[]={\"announcement-bytes\",\"unverified-bytes\","
            "\"duplicate-request-replay\",\"unrequested-bytes\",\"invalid-chunk\",\"incomplete-staging\"};"
            " bool names=true; for(int i=0;i<VCS_POLICY_NO_CREDIT_COUNT;i++)"
            " names=names && strcmp(vcs_policy_no_credit_string((enum vcs_policy_no_credit)i),nc[i])==0;"
            " HF_CHECK(names && strcmp(vcs_policy_no_credit_string(VCS_POLICY_NO_CREDIT_COUNT),\"unknown\")==0);"
            " static const char *const off[]={\"duplicate-request\",\"unrequested-bytes\","
            "\"invalid-chunk\",\"announce-flood\",\"request-flood\"};"
            " names=true; for(int i=0;i<VCS_POLICY_OFFENCE_COUNT;i++)"
            " names=names && strcmp(vcs_policy_offence_string((enum vcs_policy_offence)i),off[i])==0;"
            " HF_CHECK(names && strcmp(vcs_policy_offence_string(VCS_POLICY_OFFENCE_COUNT),\"unknown\")==0);\n"
            " #undef HF_CHECK\n"
            " snprintf(out->exercised_surface,sizeof(out->exercised_surface),\"%s\");"
            " snprintf(out->detail,sizeof(out->detail),\"checks=%%u/%%u\","
            " out->checks_passed,out->checks_run);"
            " return out->checks_run==15 && out->checks_passed==15; }\n",
            def->exercised_surface);
        return suffix < 0 ? suffix : prefix + suffix;
    }
    if (strcmp(def->story_id,
               "command-registry-input-validation-core.v1") == 0) {
        return snprintf(out, out_size,
            "#define _GNU_SOURCE\n"
            "#define ZCL_HOTFORK_COMMAND_INPUT_CORE 1\n"
            "#include \"hotswap/hotfork_capsule.h\"\n"
            "#include \"%s\"\n"
            "static bool hf_valid(const char *path,const char *keys,const char *body) {\n"
            " struct json_value input; json_init(&input);"
            " bool parsed=json_read(&input,body,strlen(body));"
            " struct zcl_command_spec spec={.path=path,.input_schema=\"zcl.test.input.v1\",.input_keys=keys};"
            " char why[160]; bool ok=parsed && zcl_command_registry_input_validate(&spec,&input,why,sizeof(why));"
            " json_free(&input); return ok; }\n"
            "__attribute__((visibility(\"hidden\")))\n"
            "bool zcl_hotfork_candidate_story_v1(struct zcl_hotfork_observation_v1 *out) {\n"
            " if (!out) return false; memset(out,0,sizeof(*out));"
            " out->magic=ZCL_HOTFORK_OBSERVATION_MAGIC; unsigned failed=0;\n"
            " #define HF_CHECK(x) do { unsigned n=out->checks_run++;"
            " if (x) out->checks_passed++; else failed|=1u<<n; } while(0)\n"
            " HF_CHECK(hf_valid(\"dev.loop.drive\",\"wait_for_edit,all\","
            "\"{\\\"wait_for_edit\\\":true,\\\"all\\\":false}\")"
            " && !hf_valid(\"dev.loop.drive\",\"wait_for_edit\","
            "\"{\\\"wait_for_edit\\\":\\\"true\\\"}\"));"
            " HF_CHECK(hf_valid(\"zcode.package.fetch\",\"maximum_bytes\","
            "\"{\\\"maximum_bytes\\\":268435456}\")"
            " && !hf_valid(\"zcode.package.fetch\",\"maximum_bytes\","
            "\"{\\\"maximum_bytes\\\":268435457}\")"
            " && hf_valid(\"metaverse.space.scout.run\",\"maximum_bytes\","
            "\"{\\\"maximum_bytes\\\":8388608}\")"
            " && !hf_valid(\"metaverse.space.scout.run\",\"maximum_bytes\","
            "\"{\\\"maximum_bytes\\\":8388609}\"));"
            " HF_CHECK(hf_valid(\"zcode.epoch.plan\","
            "\"cutoff_height,cutoff_mtp,epoch_capacity_atoms\","
            "\"{\\\"cutoff_height\\\":1,\\\"cutoff_mtp\\\":2,\\\"epoch_capacity_atoms\\\":3}\")"
            " && !hf_valid(\"zcode.epoch.plan\",\"cutoff_height\","
            "\"{\\\"cutoff_height\\\":0}\"));"
            " HF_CHECK(hf_valid(\"zcode.work.start\",\"max_cpu_seconds\","
            "\"{\\\"max_cpu_seconds\\\":600}\")"
            " && !hf_valid(\"zcode.work.start\",\"max_cpu_seconds\","
            "\"{\\\"max_cpu_seconds\\\":601}\"));"
            " HF_CHECK(hf_valid(\"app.shop.want.post\","
            "\"issued_unix,expires_unix,amount_zatoshi,nonce\","
            "\"{\\\"issued_unix\\\":1,\\\"expires_unix\\\":2,\\\"amount_zatoshi\\\":2100000000000000,\\\"nonce\\\":7}\")"
            " && hf_valid(\"app.auth.verify\",\"nonce\","
            "\"{\\\"nonce\\\":\\\"server-issued\\\"}\")"
            " && !hf_valid(\"app.shop.want.post\",\"amount_zatoshi\","
            "\"{\\\"amount_zatoshi\\\":0}\"));"
            " struct zcl_command_spec bounded={.input_keys=\"manifest_hex\"};"
            " HF_CHECK(zcl_command_registry_input_str_max(\"manifest_hex\")>4096"
            " && zcl_command_registry_input_str_max(\"ordinary\")==4096"
            " && zcl_command_registry_input_budget_bytes(&bounded)>ZCL_COMMAND_MAX_INPUT);\n"
            " #undef HF_CHECK\n"
            " snprintf(out->exercised_surface,sizeof(out->exercised_surface),\"%s\");"
            " snprintf(out->detail,sizeof(out->detail),"
            "\"checks=%%u/%%u;failed_mask=0x%%x\","
            "out->checks_passed,out->checks_run,failed);"
            " return out->checks_run==6 && out->checks_passed==6; }\n",
            source_path, def->exercised_surface);
    }
    if (strcmp(def->story_id,
               "shop-want-command-input-core.v1") == 0) {
        return snprintf(out, out_size,
            "#define _GNU_SOURCE\n"
            "#include \"hotswap/hotfork_capsule.h\"\n"
            "#include \"hotswap/hotswap_service.h\"\n"
            "#define zcl_hotswap_service_acquire(...) NULL\n"
            "#define zcl_hotswap_service_release(...) ((void)0)\n"
            "#include \"%s\"\n"
            "#undef zcl_hotswap_service_release\n"
            "#undef zcl_hotswap_service_acquire\n"
            "__attribute__((visibility(\"hidden\")))\n"
            "bool zcl_hotfork_candidate_story_v1(struct zcl_hotfork_observation_v1 *out) {\n"
            " if (!out) return false; memset(out,0,sizeof(*out));"
            " out->magic=ZCL_HOTFORK_OBSERVATION_MAGIC; unsigned failed=0;\n"
            " #define HF_CHECK(x) do { unsigned n=out->checks_run++;"
            " if (x) out->checks_passed++; else failed|=1u<<n; } while(0)\n"
            " uint8_t decoded[32];"
            " const char *secret=\"a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1\";"
            " HF_CHECK(shw_hex32(secret,decoded) && decoded[0]==0xa1"
            " && !shw_hex32(\"A1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1\",decoded)"
            " && !shw_hex32(\"a1\",decoded));"
            " struct json_value input; json_init(&input); json_set_object(&input);"
            " json_push_kv_str(&input,\"buyer_secret\",secret);"
            " json_push_kv_int(&input,\"amount_zatoshi\",500000);"
            " json_push_kv_str(&input,\"criteria\",\"sha3-verified result\");"
            " json_push_kv_int(&input,\"expires_unix\",1780086400);"
            " json_push_kv_int(&input,\"nonce\",42);"
            " struct zcl_command_request request={.input=&input};"
            " struct zcl_command_reply reply; zcl_command_reply_init(&reply,\"zcl.test.v1\");"
            " struct shop_want row; bool built=shw_build_want(&request,1780000000,&row,&reply);"
            " HF_CHECK(built && row.want.amount_zatoshi==500000"
            " && row.want.criteria_len==20 && row.want.nonce==42"
            " && row.want.issued_unix==1780000000 && row.want.expires_unix==1780086400"
            " && shop_want_verify(&row.want)==SHOP_WANT_OK);"
            " zcl_command_reply_free(&reply); json_free(&input);"
            " json_init(&input); json_set_object(&input);"
            " json_push_kv_str(&input,\"buyer_secret\",secret);"
            " json_push_kv_int(&input,\"amount_zatoshi\",1);"
            " json_push_kv_str(&input,\"criteria\",\"x\");"
            " json_push_kv_int(&input,\"expires_unix\",1780000000);"
            " request.input=&input; zcl_command_reply_init(&reply,\"zcl.test.v1\");"
            " HF_CHECK(!shw_build_want(&request,1780000000,&row,&reply)"
            " && strcmp(reply.error.code,\"WANT_ALREADY_EXPIRED\")==0);"
            " zcl_command_reply_free(&reply); json_free(&input);\n"
            " #undef HF_CHECK\n"
            " snprintf(out->exercised_surface,sizeof(out->exercised_surface),\"%s\");"
            " snprintf(out->detail,sizeof(out->detail),"
            "\"checks=%%u/%%u;failed_mask=0x%%x\","
            "out->checks_passed,out->checks_run,failed);"
            " return out->checks_run==3 && out->checks_passed==3; }\n",
            source_path, def->exercised_surface);
    }
    if (strcmp(def->story_id,
               "devloop-plan-classification.v1") == 0) {
        return snprintf(out, out_size,
            "#define _GNU_SOURCE\n"
            "#include \"hotswap/hotfork_capsule.h\"\n"
            "#include \"%s\"\n"
            "__attribute__((visibility(\"hidden\")))\n"
            "bool zcl_hotfork_candidate_story_v1(struct zcl_hotfork_observation_v1 *out) {\n"
            " if (!out) return false; memset(out,0,sizeof(*out));"
            " out->magic=ZCL_HOTFORK_OBSERVATION_MAGIC; unsigned failed=0;\n"
            " #define HF_CHECK(x) do { unsigned n=out->checks_run++;"
            " if (x) out->checks_passed++; else failed|=1u<<n; } while(0)\n"
            " HF_CHECK(path_is_safe(\"tools/dev/a.c\")"
            " && !path_is_safe(\"../a.c\") && !path_is_safe(\"/a.c\")"
            " && !path_is_safe(\"a\\\\b.c\") && !path_is_safe(NULL));"
            " HF_CHECK(path_is_docs(\"docs/a.md\") && path_is_docs(\"README.md\")"
            " && !path_is_docs(\"lib/a.c\")"
            " && zcl_devloop_path_is_sealed_core(\"core/math/a.c\")"
            " && !zcl_devloop_path_is_sealed_core(\"lib/a.c\"));"
            " HF_CHECK(zcl_devloop_path_is_relevant(\"lib/a.c\")"
            " && zcl_devloop_path_is_relevant(\"Makefile\")"
            " && !zcl_devloop_path_is_relevant(\"build/a.c\")"
            " && !zcl_devloop_path_is_relevant(\"lib/a.c~\")"
            " && !zcl_devloop_path_is_relevant(\"lib/_x_fixture.c\"));"
            " HF_CHECK(zcl_devloop_watch_event_is_mutation(IN_CLOSE_WRITE)"
            " && zcl_devloop_watch_event_is_mutation(IN_DELETE)"
            " && !zcl_devloop_watch_event_is_mutation(IN_ATTRIB));"
            " HF_CHECK(zcl_devloop_watch_dir_is_ignored(\"build\")"
            " && zcl_devloop_watch_dir_is_ignored(\".cache\")"
            " && !zcl_devloop_watch_dir_is_ignored(\"lib\"));"
            " HF_CHECK(strcmp(zcl_devloop_dim_name(ZCL_DEVLOOP_DIM_OPAQUE),\"opaque\")==0"
            " && strcmp(zcl_devloop_dim_name(ZCL_DEVLOOP_DIM_SEMANTIC),\"semantic\")==0"
            " && strcmp(zcl_devloop_dim_status_name(ZCL_DEVLOOP_DIM_COMPLETE),\"complete\")==0"
            " && strcmp(zcl_devloop_dim_status_name(ZCL_DEVLOOP_DIM_UNAVAILABLE),\"unavailable\")==0);\n"
            " #undef HF_CHECK\n"
            " snprintf(out->exercised_surface,sizeof(out->exercised_surface),\"%s\");"
            " snprintf(out->detail,sizeof(out->detail),"
            "\"checks=%%u/%%u;failed_mask=0x%%x\","
            "out->checks_passed,out->checks_run,failed);"
            " return out->checks_run==6 && out->checks_passed==6; }\n",
            source_path, def->exercised_surface);
    }
    if (strcmp(def->story_id,
               "zcode-corpus-command-core.v1") == 0) {
        return snprintf(out, out_size,
            "#define _GNU_SOURCE\n"
            "#include \"hotswap/hotfork_capsule.h\"\n"
            "#include \"hotswap/hotswap_service.h\"\n"
            "#define zcl_hotswap_service_acquire(...) NULL\n"
            "#define zcl_hotswap_service_release(...) ((void)0)\n"
            "#define zcl_hotswap_service_generation(...) 0\n"
            "#include \"%s\"\n"
            "#undef zcl_hotswap_service_generation\n"
            "#undef zcl_hotswap_service_release\n"
            "#undef zcl_hotswap_service_acquire\n"
            "__attribute__((visibility(\"hidden\")))\n"
            "bool zcl_hotfork_candidate_story_v1(struct zcl_hotfork_observation_v1 *out) {\n"
            " if (!out) return false; memset(out,0,sizeof(*out));"
            " out->magic=ZCL_HOTFORK_OBSERVATION_MAGIC; unsigned failed=0;\n"
            " #define HF_CHECK(x) do { unsigned n=out->checks_run++;"
            " if (x) out->checks_passed++; else failed|=1u<<n; } while(0)\n"
            " const char *lower=\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\";"
            " const char *upper=\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdeF\";"
            " HF_CHECK(lowercase_root(lower) && !lowercase_root(upper)"
            " && !lowercase_root(\"abcd\") && !lowercase_root(NULL));"
            " struct vcs_zcode_c23_corpus_checkpoint_v1 checkpoint={0};"
            " checkpoint.production_loc=7; checkpoint.test_loc=5; uint64_t total=0;"
            " HF_CHECK(corpus_checkpoint_renderable(&checkpoint,&total) && total==12);"
            " checkpoint.production_loc=UINT64_MAX; checkpoint.test_loc=1;"
            " HF_CHECK(!corpus_checkpoint_renderable(&checkpoint,&total)"
            " && !corpus_checkpoint_renderable(NULL,&total));"
            " struct vcs_zcode_c23_corpus_entry_v1 entries[2]={{0}};"
            " entries[0].production_loc=3; entries[0].test_loc=2;"
            " entries[0].physical_lines=6; entries[0].unique_semantic_units=2;"
            " entries[0].flags=VCS_ZCODE_C23_ENTRY_COUNTED|VCS_ZCODE_C23_ENTRY_DURABLE;"
            " entries[1].production_loc=4; entries[1].test_loc=1;"
            " entries[1].physical_lines=8; entries[1].unique_semantic_units=3;"
            " struct vcs_zcode_c23_corpus_shard_v1 shard={.entries=entries,.entry_count=2};"
            " struct corpus_shard_metrics metrics;"
            " HF_CHECK(corpus_shard_metrics_collect(&shard,&metrics)"
            " && metrics.counted_entries==1 && metrics.durable_entries==1"
            " && metrics.excluded_entries==1 && metrics.production_loc==7"
            " && metrics.test_loc==3 && metrics.total_loc==10"
            " && metrics.durable_loc==5 && metrics.physical_lines==14"
            " && metrics.unique_semantic_units==5);"
            " entries[1].production_loc=UINT64_MAX;"
            " HF_CHECK(!corpus_shard_metrics_collect(&shard,&metrics)"
            " && !corpus_shard_metrics_collect(NULL,&metrics));\n"
            " #undef HF_CHECK\n"
            " snprintf(out->exercised_surface,sizeof(out->exercised_surface),\"%s\");"
            " snprintf(out->detail,sizeof(out->detail),"
            "\"checks=%%u/%%u;failed_mask=0x%%x\","
            "out->checks_passed,out->checks_run,failed);"
            " return out->checks_run==5 && out->checks_passed==5; }\n",
            source_path, def->exercised_surface);
    }
    if (strcmp(def->story_id,
               "devloop-cycle-diagnostic-policy.v1") == 0) {
        return snprintf(out, out_size,
            "#define _GNU_SOURCE\n"
            "#define ZCL_TESTING 1\n"
            "#define ZCL_HOTFORK_DEVLOOP_CYCLE_CORE 1\n"
            "#include \"hotswap/hotfork_capsule.h\"\n"
            "#include \"%s\"\n"
            "__attribute__((visibility(\"hidden\")))\n"
            "bool zcl_hotfork_candidate_story_v1(struct zcl_hotfork_observation_v1 *out) {\n"
            " if (!out) return false; memset(out,0,sizeof(*out));"
            " out->magic=ZCL_HOTFORK_OBSERVATION_MAGIC; unsigned failed=0;\n"
            " #define HF_CHECK(x) do { unsigned n=out->checks_run++;"
            " if (x) out->checks_passed++; else failed|=1u<<n; } while(0)\n"
            " const char log[]=\"noise\\na.c:7:2: error: broken\\nFAIL later\\n\"; char first[64];"
            " HF_CHECK(distill_first_error(log,sizeof(log)-1,first,sizeof(first))"
            " && strcmp(first,\"a.c:7:2: error: broken\")==0);"
            " const char good[]=\"a.c:7:2: error: broken\";"
            " const char transient[]=\"a.c:7:2: error: Killed\";"
            " HF_CHECK(compiler_error_shape(good,sizeof(good)-1)"
            " && !compiler_error_shape(transient,sizeof(transient)-1));"
            " char preview[8]; bool truncated=false;"
            " HF_CHECK(cycle_text_preview(\"a\\nbcd\",4,preview,sizeof(preview),&truncated)"
            " && strcmp(preview,\"a?bc\")==0 && truncated"
            " && !cycle_text_preview(\"x\",8,preview,sizeof(preview),NULL));"
            " HF_CHECK(zcl_devloop_cycle_proof_complete(\"passed\",\"verify\")"
            " && !zcl_devloop_cycle_proof_complete(\"passed\",\"compile\")"
            " && !zcl_devloop_cycle_proof_complete(\"rejected\",\"verify\"));"
            " HF_CHECK(!zcl_devloop_publish_mode_applies(ZCL_DEVLOOP_PUBLISH_VERIFY_ONLY)"
            " && zcl_devloop_publish_mode_applies(ZCL_DEVLOOP_PUBLISH_APPLY)"
            " && strcmp(zcl_devloop_publish_mode_name(ZCL_DEVLOOP_PUBLISH_VERIFY_ONLY),\"verify\")==0"
            " && strcmp(zcl_devloop_publish_mode_name(ZCL_DEVLOOP_PUBLISH_APPLY),\"auto\")==0"
            " && zcl_devloop_publish_mode_name((enum zcl_devloop_publish_mode)9)==NULL"
            " && zcl_devloop_publication_target_port_supported(18252)"
            " && !zcl_devloop_publication_target_port_supported(18232));"
            " HF_CHECK(strcmp(zcl_devloop_watcher_freshness(false,false,false),\"watcher_not_running\")==0"
            " && strcmp(zcl_devloop_watcher_freshness(true,false,false),\"watcher_starting\")==0"
            " && strcmp(zcl_devloop_watcher_freshness(true,true,false),\"runtime_starting\")==0"
            " && strcmp(zcl_devloop_watcher_freshness(true,true,true),\"current\")==0"
            " && strcmp(zcl_devloop_watcher_next_action(false,false,false,ZCL_DEVLOOP_PUBLISH_VERIFY_ONLY),"
            "\"z23-dev dev begin\")==0"
            " && strcmp(zcl_devloop_watcher_next_action(true,true,true,ZCL_DEVLOOP_PUBLISH_VERIFY_ONLY),"
            "\"edit one C23 file\")==0);\n"
            " #undef HF_CHECK\n"
            " snprintf(out->exercised_surface,sizeof(out->exercised_surface),\"%s\");"
            " snprintf(out->detail,sizeof(out->detail),"
            "\"checks=%%u/%%u;failed_mask=0x%%x\","
            "out->checks_passed,out->checks_run,failed);"
            " return out->checks_run==6 && out->checks_passed==6; }\n",
            source_path, def->exercised_surface);
    }
    if (strcmp(def->story_id,
               "devloop-watch-classification-core.v1") == 0) {
        return snprintf(out, out_size,
            "#define _GNU_SOURCE\n"
            "#define ZCL_HOTFORK_DEVLOOP_WATCH_CORE 1\n"
            "#include \"hotswap/hotfork_capsule.h\"\n"
            "#include \"%s\"\n"
            "__attribute__((visibility(\"hidden\")))\n"
            "bool zcl_hotfork_candidate_story_v1(struct zcl_hotfork_observation_v1 *out) {\n"
            " if (!out) return false; memset(out,0,sizeof(*out));"
            " out->magic=ZCL_HOTFORK_OBSERVATION_MAGIC; unsigned failed=0;\n"
            " #define HF_CHECK(x) do { unsigned n=out->checks_run++;"
            " if (x) out->checks_passed++; else failed|=1u<<n; } while(0)\n"
            " HF_CHECK(watch_c_source(\"tools/dev/a.c\")"
            " && !watch_c_source(\"tools/dev/a.h\")"
            " && !watch_c_source(\"tools/dev/a.C\")"
            " && !watch_c_source(NULL));"
            " const char *all_c[]={\"tools/dev/a.c\",\"tools/dev/b.c\"};"
            " const char *mixed[]={\"tools/dev/a.c\",\"tools/dev/b.h\"};"
            " HF_CHECK(watch_epoch_all_c(all_c,2)"
            " && !watch_epoch_all_c(mixed,2)"
            " && !watch_epoch_all_c(NULL,2)"
            " && !watch_epoch_all_c(all_c,0));"
            " char component[128]; watch_component_for_files(all_c,2,component);"
            " HF_CHECK(strcmp(component,\"tools/dev\")==0);"
            " const char *owners[]={\"tools/dev/a.c\",\"lib/vcs/a.c\"};"
            " watch_component_for_files(owners,2,component);"
            " bool mixed_ok=strcmp(component,\"mixed\")==0;"
            " const char *root[]={\"Makefile\"};"
            " watch_component_for_files(root,1,component);"
            " HF_CHECK(mixed_ok && strcmp(component,\"Makefile\")==0);\n"
            " #undef HF_CHECK\n"
            " snprintf(out->exercised_surface,sizeof(out->exercised_surface),\"%s\");"
            " snprintf(out->detail,sizeof(out->detail),"
            "\"checks=%%u/%%u;failed_mask=0x%%x\","
            "out->checks_passed,out->checks_run,failed);"
            " return out->checks_run==4 && out->checks_passed==4; }\n",
            source_path, def->exercised_surface);
    }
    if (strcmp(def->story_id,
               "test-group-catalog-selection-policy.v1") == 0) {
        return snprintf(out, out_size,
            "#define _GNU_SOURCE\n"
            "#include \"hotswap/hotfork_capsule.h\"\n"
            "#include \"%s\"\n"
            "__attribute__((visibility(\"hidden\")))\n"
            "bool zcl_hotfork_candidate_story_v1(struct zcl_hotfork_observation_v1 *out) {\n"
            " if (!out) return false; memset(out,0,sizeof(*out));"
            " out->magic=ZCL_HOTFORK_OBSERVATION_MAGIC;\n"
            " unsigned failed=0;\n"
            " #define HF_CHECK(x) do { unsigned n=out->checks_run++;"
            " if (x) out->checks_passed++; else failed|=1u<<n; } while(0)\n"
            " char resolved[ZCL_TEST_GROUP_FULL_MAX];"
            " HF_CHECK(zcl_test_group_catalog_count()>100);"
            " HF_CHECK(zcl_test_group_catalog_contains(\"test_dev_platform\")"
            " && !zcl_test_group_catalog_contains(\"dev_platform\"));"
            " HF_CHECK(zcl_test_group_requires_exclusive_run(\"test_command_registry_latency\")"
            " && zcl_test_group_requires_exclusive_run(\"test_sapling_crypto\")"
            " && zcl_test_group_requires_exclusive_run(\"test_vcs_core\")"
            " && zcl_test_group_requires_exclusive_run(\"test_validate_parallel_determinism\")"
            " && !zcl_test_group_requires_exclusive_run(\"test_dev_platform\"));"
            " HF_CHECK(zcl_test_group_source_is_semantic_leaf("
            "\"lib/test/src/test_stage_repair_coin_backfill.c\")"
            " && !zcl_test_group_source_is_semantic_leaf("
            "\"lib/test/src/test_dev_platform.c\"));"
            " HF_CHECK(zcl_test_group_resolve_exact(\"dev_platform\",resolved)"
            " && strcmp(resolved,\"test_dev_platform\")==0);"
            " HF_CHECK(zcl_test_group_resolve_exact(\"test_dev_platform\",resolved)"
            " && !zcl_test_group_resolve_exact(\"dev_plat\",resolved));"
            " HF_CHECK(zcl_test_group_plan_selects(\"oracle_policy\","
            "\"test_zclassicd_oracle\")"
            " && !zcl_test_group_plan_selects(\"dev_platform\","
            "\"test_zclassicd_oracle\"));"
            " HF_CHECK(zcl_test_group_is_integration_only("
            "\"test_test_group_selector\")"
            " && !zcl_test_group_is_integration_only(\"test_dev_platform\")"
            " && zcl_test_group_integration_policy_valid());"
            " const char *ordinary[]={\"dev_platform\"};"
            " char groups[2][ZCL_TEST_GROUP_FULL_MAX]; bool truncated=false;"
            " size_t count=zcl_test_group_expand_plan(ordinary,1,groups,2,&truncated);"
            " HF_CHECK(count==1 && !truncated"
            " && strcmp(groups[0],\"test_dev_platform\")==0);"
            " const char *integration[]={\"test_group_selector\"};"
            " count=zcl_test_group_expand_plan_immediate("
            "integration,1,groups,2,&truncated);"
            " HF_CHECK(count==0 && !truncated);\n"
            " #undef HF_CHECK\n"
            " snprintf(out->exercised_surface,sizeof(out->exercised_surface),\"%s\");"
            " snprintf(out->detail,sizeof(out->detail),"
            "\"checks=%%u/%%u;failed_mask=0x%%x\","
            " out->checks_passed,out->checks_run,failed);"
            " return out->checks_run==10 && out->checks_passed==10; }\n",
            source_path, def->exercised_surface);
    }
    if (strcmp(def->story_id, "shop-want-view-contract.v1") == 0) {
        size_t source_len = strlen(source_path);
        size_t suffix_len = strlen(def->source_tu);
        if (source_len < suffix_len ||
            strcmp(source_path + source_len - suffix_len,
                   def->source_tu) != 0)
            return -1;
        char service_path[PATH_MAX];
        int service_n = snprintf(service_path, sizeof(service_path),
            "%.*sapp/services/src/shop_want_view_service.c",
            (int)(source_len - suffix_len), source_path);
        if (service_n <= 0 || service_n >= (int)sizeof(service_path))
            return -1;
        return snprintf(out, out_size,
            "#define _GNU_SOURCE\n"
            "#include \"hotswap/hotfork_capsule.h\"\n"
            "#include \"hotswap/hotswap_service.h\"\n"
            "#define zcl_hotswap_service_acquire(...) NULL\n"
            "#define zcl_hotswap_service_release(...) ((void)0)\n"
            "#include \"%s\"\n"
            "#undef zcl_hotswap_service_release\n"
            "#undef zcl_hotswap_service_acquire\n"
            "#include \"%s\"\n"
            "__attribute__((visibility(\"hidden\")))\n"
            "bool zcl_hotfork_candidate_story_v1(struct zcl_hotfork_observation_v1 *out) {\n"
            " if (!out) return false; memset(out,0,sizeof(*out));"
            " out->magic=ZCL_HOTFORK_OBSERVATION_MAGIC; unsigned failed=0;\n"
            " #define HF_CHECK(x) do { unsigned n=out->checks_run++;"
            " if (x) out->checks_passed++; else failed|=1u<<n; } while(0)\n"
            " struct shop_want row; memset(&row,0,sizeof(row));"
            " row.want.amount_zatoshi=500000; row.want.criteria_len=5;"
            " memcpy(row.want.criteria,\"proof\",5);"
            " row.want.issued_unix=100; row.want.expires_unix=200;"
            " row.review_state=1; row.want_id[0]=1; row.want.buyer_pubkey[0]=2;"
            " struct shop_want_view_result_v1 view;"
            " HF_CHECK(zcl_shop_want_view_render(&row,150,false,&view));"
            " HF_CHECK(strcmp(view.state,\"open\")==0 && !view.expired"
            " && strcmp(view.review_state,\"reviewed_ok\")==0);"
            " HF_CHECK(strcmp(view.criteria_preview,\"proof\")==0"
            " && view.amount_zatoshi==500000 && !view.spec_hash_present);"
            " struct json_value doc; json_init(&doc); json_set_object(&doc);"
            " zcl_shop_want_view_push_json(&doc,&view);"
            " HF_CHECK(json_get_int(json_get(&doc,\"amount_zatoshi\"))==500000"
            " && strcmp(json_get_str(json_get(&doc,\"criteria_preview\")),\"proof\")==0"
            " && !json_get_bool(json_get(&doc,\"criteria_truncated\")));"
            " json_free(&doc);"
            " const struct zcl_hotswap_service_contract *contract="
            "zcl_native_shop_want_view_service_contract(); char why[160]={0};"
            " HF_CHECK(contract && strcmp(contract->service_id,"
            "SHOP_WANT_VIEW_SERVICE_ID)==0 && contract->frozen_kat);"
            " HF_CHECK(contract && contract->frozen_kat &&"
            " contract->frozen_kat(shop_want_view_service_builtin(),why,sizeof(why)));\n"
            " #undef HF_CHECK\n"
            " snprintf(out->exercised_surface,sizeof(out->exercised_surface),\"%s\");"
            " snprintf(out->detail,sizeof(out->detail),"
            "\"checks=%%u/%%u;failed_mask=0x%%x\","
            "out->checks_passed,out->checks_run,failed);"
            " return out->checks_run==6 && out->checks_passed==6; }\n",
            source_path, service_path, def->exercised_surface);
    }
    if (strcmp(def->story_id, "zcode-package-view-contract.v1") == 0) {
        size_t source_len = strlen(source_path);
        size_t suffix_len = strlen(def->source_tu);
        if (source_len < suffix_len ||
            strcmp(source_path + source_len - suffix_len,
                   def->source_tu) != 0)
            return -1;
        char service_path[PATH_MAX];
        int service_n = snprintf(service_path, sizeof(service_path),
            "%.*sapp/services/src/zcode_package_view_service.c",
            (int)(source_len - suffix_len), source_path);
        if (service_n <= 0 || service_n >= (int)sizeof(service_path))
            return -1;
        return snprintf(out, out_size,
            "#define _GNU_SOURCE\n"
            "#include \"hotswap/hotfork_capsule.h\"\n"
            "#include \"hotswap/hotswap_service.h\"\n"
            "#define zcl_hotswap_service_acquire(...) NULL\n"
            "#define zcl_hotswap_service_release(...) ((void)0)\n"
            "#define zcl_hotswap_service_generation(...) 0\n"
            "#include \"%s\"\n"
            "#undef zcl_hotswap_service_generation\n"
            "#undef zcl_hotswap_service_release\n"
            "#undef zcl_hotswap_service_acquire\n"
            "#include \"%s\"\n"
            "__attribute__((visibility(\"hidden\")))\n"
            "bool zcl_hotfork_candidate_story_v1(struct zcl_hotfork_observation_v1 *out) {\n"
            " if (!out) return false; memset(out,0,sizeof(*out));"
            " out->magic=ZCL_HOTFORK_OBSERVATION_MAGIC; unsigned failed=0;\n"
            " #define HF_CHECK(x) do { unsigned n=out->checks_run++;"
            " if (x) out->checks_passed++; else failed|=1u<<n; } while(0)\n"
            " const struct zcl_hotswap_service_contract *contract="
            "zcl_native_zcode_package_view_service_contract(); char why[160]={0};"
            " HF_CHECK(contract && strcmp(contract->service_id,"
            "ZCODE_PACKAGE_VIEW_SERVICE_ID)==0 && contract->frozen_kat);"
            " HF_CHECK(contract && contract->frozen_kat &&"
            " contract->frozen_kat(zcode_package_view_service_builtin(),why,sizeof(why)));\n"
            " #undef HF_CHECK\n"
            " snprintf(out->exercised_surface,sizeof(out->exercised_surface),\"%s\");"
            " snprintf(out->detail,sizeof(out->detail),"
            "\"checks=%%u/%%u;failed_mask=0x%%x\","
            "out->checks_passed,out->checks_run,failed);"
            " return out->checks_run==2 && out->checks_passed==2; }\n",
            source_path, service_path, def->exercised_surface);
    }
    if (strcmp(def->story_id, "shop-status-view-contract.v1") == 0) {
        size_t source_len = strlen(source_path);
        size_t suffix_len = strlen(def->source_tu);
        if (source_len < suffix_len ||
            strcmp(source_path + source_len - suffix_len,
                   def->source_tu) != 0)
            return -1;
        char service_path[PATH_MAX];
        int service_n = snprintf(service_path, sizeof(service_path),
            "%.*sapp/services/src/shop_status_view_service.c",
            (int)(source_len - suffix_len), source_path);
        if (service_n <= 0 || service_n >= (int)sizeof(service_path))
            return -1;
        return snprintf(out, out_size,
            "#define _GNU_SOURCE\n"
            "#include \"hotswap/hotfork_capsule.h\"\n"
            "#include \"hotswap/hotswap_service.h\"\n"
            "#define zcl_hotswap_service_acquire(...) NULL\n"
            "#define zcl_hotswap_service_release(...) ((void)0)\n"
            "#define zcl_hotswap_service_generation(...) 0\n"
            "#include \"%s\"\n"
            "#undef zcl_hotswap_service_generation\n"
            "#undef zcl_hotswap_service_release\n"
            "#undef zcl_hotswap_service_acquire\n"
            "#include \"%s\"\n"
            "__attribute__((visibility(\"hidden\")))\n"
            "bool zcl_hotfork_candidate_story_v1(struct zcl_hotfork_observation_v1 *out) {\n"
            " if (!out) return false; memset(out,0,sizeof(*out));"
            " out->magic=ZCL_HOTFORK_OBSERVATION_MAGIC; unsigned failed=0;\n"
            " #define HF_CHECK(x) do { unsigned n=out->checks_run++;"
            " if (x) out->checks_passed++; else failed|=1u<<n; } while(0)\n"
            " HF_CHECK(shop_status_wallet(SHOP_WALLET_ABSENT)==SHOP_STATUS_WALLET_ABSENT"
            " && shop_status_wallet(SHOP_WALLET_PLAINTEXT)==SHOP_STATUS_WALLET_PLAINTEXT"
            " && shop_status_wallet(SHOP_WALLET_ENCRYPTED)==SHOP_STATUS_WALLET_ENCRYPTED"
            " && shop_status_wallet(SHOP_WALLET_UNREADABLE)==SHOP_STATUS_WALLET_UNREADABLE);"
            " struct shop_snapshot closed={.wallet=SHOP_WALLET_ABSENT,"
            ".schema_version=-1,.product_count=-1};"
            " struct shop_status_view_result_v1 view;"
            " HF_CHECK(shop_status_render(&closed,&view) && !view.shop_live"
            " && view.gap_count==5 && strcmp(view.gaps[0].gap,\"tor_stub_build\")==0"
            " && strcmp(view.gaps[4].gap,\"shop_not_announced\")==0);"
            " struct shop_snapshot live={.tor_real=true,.identity_present=true,"
            ".wallet=SHOP_WALLET_ENCRYPTED,.node_db_present=true,.store_schema=true,"
            ".schema_version=1,.product_count=3,.announced=true};"
            " snprintf(live.address,sizeof(live.address),\"example\");"
            " HF_CHECK(shop_status_render(&live,&view) && view.shop_live"
            " && view.gap_count==0 && strcmp(view.wallet_posture,\"encrypted\")==0"
            " && strcmp(view.shop_url,\"http://example.onion/store\")==0);"
            " const struct zcl_hotswap_service_contract *contract="
            "zcl_native_shop_status_view_service_contract(); char why[160]={0};"
            " HF_CHECK(contract && strcmp(contract->service_id,SHOP_STATUS_VIEW_SERVICE_ID)==0"
            " && contract->frozen_kat && contract->frozen_kat("
            "shop_status_view_service_builtin(),why,sizeof(why)));\n"
            " #undef HF_CHECK\n"
            " snprintf(out->exercised_surface,sizeof(out->exercised_surface),\"%s\");"
            " snprintf(out->detail,sizeof(out->detail),"
            "\"checks=%%u/%%u;failed_mask=0x%%x\","
            "out->checks_passed,out->checks_run,failed);"
            " return out->checks_run==4 && out->checks_passed==4; }\n",
            source_path, service_path, def->exercised_surface);
    }
    if (strcmp(def->story_id, "shop-reputation-view-contract.v1") == 0) {
        size_t source_len = strlen(source_path);
        size_t suffix_len = strlen(def->source_tu);
        if (source_len < suffix_len ||
            strcmp(source_path + source_len - suffix_len,
                   def->source_tu) != 0)
            return -1;
        char service_path[PATH_MAX];
        int service_n = snprintf(service_path, sizeof(service_path),
            "%.*sapp/services/src/shop_reputation_view_service.c",
            (int)(source_len - suffix_len), source_path);
        if (service_n <= 0 || service_n >= (int)sizeof(service_path))
            return -1;
        return snprintf(out, out_size,
            "#define _GNU_SOURCE\n"
            "#include \"hotswap/hotfork_capsule.h\"\n"
            "#include \"hotswap/hotswap_service.h\"\n"
            "#define zcl_hotswap_service_acquire(...) NULL\n"
            "#define zcl_hotswap_service_release(...) ((void)0)\n"
            "#define zcl_hotswap_service_generation(...) 0\n"
            "#include \"%s\"\n"
            "#undef zcl_hotswap_service_generation\n"
            "#undef zcl_hotswap_service_release\n"
            "#undef zcl_hotswap_service_acquire\n"
            "#include \"%s\"\n"
            "__attribute__((visibility(\"hidden\")))\n"
            "bool zcl_hotfork_candidate_story_v1(struct zcl_hotfork_observation_v1 *out) {\n"
            " if (!out) return false; memset(out,0,sizeof(*out));"
            " out->magic=ZCL_HOTFORK_OBSERVATION_MAGIC; unsigned failed=0;\n"
            " #define HF_CHECK(x) do { unsigned n=out->checks_run++;"
            " if (x) out->checks_passed++; else failed|=1u<<n; } while(0)\n"
            " uint8_t roots[2][32]={{0}}; roots[0][0]=1; roots[1][0]=2;"
            " uint8_t one[32]={1},three[32]={3};"
            " HF_CHECK(rep_root_seen(roots,2,one) && !rep_root_seen(roots,2,three));"
            " struct shop_rep_pair pairs[1]; memset(pairs,0,sizeof(pairs));"
            " pairs[0].package_root[0]=1; pairs[0].recipe_root[0]=2;"
            " uint8_t two[32]={2};"
            " HF_CHECK(rep_pair_seen(pairs,1,one,two)"
            " && !rep_pair_seen(pairs,1,one,three));"
            " const struct zcl_hotswap_service_contract *contract="
            "zcl_native_shop_reputation_view_service_contract(); char why[160]={0};"
            " HF_CHECK(contract && strcmp(contract->service_id,"
            "SHOP_REPUTATION_VIEW_SERVICE_ID)==0 && contract->frozen_kat);"
            " HF_CHECK(contract && contract->frozen_kat && contract->frozen_kat("
            "shop_reputation_view_service_builtin(),why,sizeof(why)));\n"
            " #undef HF_CHECK\n"
            " snprintf(out->exercised_surface,sizeof(out->exercised_surface),\"%s\");"
            " snprintf(out->detail,sizeof(out->detail),"
            "\"checks=%%u/%%u;failed_mask=0x%%x\","
            "out->checks_passed,out->checks_run,failed);"
            " return out->checks_run==4 && out->checks_passed==4; }\n",
            source_path, service_path, def->exercised_surface);
    }
    if (strcmp(def->story_id, "zcode-work-input-core.v1") == 0) {
        return snprintf(out, out_size,
            "#define _GNU_SOURCE\n"
            "#define ZCL_HOTFORK_ZWORK_INPUT_CORE 1\n"
            "#include \"hotswap/hotfork_capsule.h\"\n"
            "#include \"%s\"\n"
            "__attribute__((visibility(\"hidden\")))\n"
            "bool zcl_hotfork_candidate_story_v1(struct zcl_hotfork_observation_v1 *out) {\n"
            " if (!out) return false; memset(out,0,sizeof(*out));"
            " out->magic=ZCL_HOTFORK_OBSERVATION_MAGIC; unsigned failed=0;\n"
            " #define HF_CHECK(x) do { unsigned n=out->checks_run++;"
            " if (x) out->checks_passed++; else failed|=1u<<n; } while(0)\n"
            " struct json_value input; json_init(&input); json_set_object(&input);"
            " json_push_kv_str(&input,\"goal\",\"ship\");"
            " json_push_kv_int(&input,\"budget\",7);"
            " HF_CHECK(strcmp(zwork_str(&input,\"goal\"),\"ship\")==0"
            " && zwork_str(&input,\"budget\")==NULL);"
            " HF_CHECK(zwork_int(&input,\"budget\",3)==7"
            " && zwork_int(&input,\"missing\",3)==3); json_free(&input);"
            " char scopes[1024]={0};"
            " HF_CHECK(zwork_scope_add(scopes,\"lib/a.c\")"
            " && zwork_scope_add(scopes,\"lib/b.c\")"
            " && zwork_scope_add(scopes,\"app/x.c\")"
            " && !zwork_scope_add(scopes,\"\")"
            " && strcmp(scopes,\"lib,app\")==0);"
            " char *headers[]={\"include/a.h\"};"
            " char *sources[]={\"src/a.c\",\"include/b.c\"};"
            " char *tests[]={\"tests/a.c\"};"
            " struct vcs_package_recipe recipe; memset(&recipe,0,sizeof(recipe));"
            " recipe.public_headers=(struct vcs_package_recipe_strings){headers,1,1};"
            " recipe.sources=(struct vcs_package_recipe_strings){sources,2,2};"
            " recipe.test_sources=(struct vcs_package_recipe_strings){tests,1,1};"
            " HF_CHECK(zwork_scopes(&recipe,scopes)"
            " && strcmp(scopes,\"include,src,tests\")==0);"
            " struct vcs_package_prepared prepared; memset(&prepared,0,sizeof(prepared));"
            " char *prepared_sources[]={\"src/a.c\",\"src/missing.c\"};"
            " struct vcs_package_file files[2]={{.path=\"src/a.c\",.size=11},{.path=\"other.c\",.size=99}};"
            " prepared.recipe.sources=(struct vcs_package_recipe_strings){prepared_sources,2,2};"
            " prepared.manifest=(struct vcs_package_manifest){files,2,2};"
            " HF_CHECK(zwork_source_bytes(&prepared)==11);"
            " prepared_sources[1]=\"other.c\";"
            " prepared.manifest.files[0].size=UINT64_MAX;"
            " prepared.manifest.files[1].size=1;"
            " HF_CHECK(zwork_source_bytes(&prepared)==0);\n"
            " #undef HF_CHECK\n"
            " snprintf(out->exercised_surface,sizeof(out->exercised_surface),\"%s\");"
            " snprintf(out->detail,sizeof(out->detail),"
            "\"checks=%%u/%%u;failed_mask=0x%%x\","
            "out->checks_passed,out->checks_run,failed);"
            " return out->checks_run==6 && out->checks_passed==6; }\n",
            source_path, def->exercised_surface);
    }
    if (strcmp(def->story_id,
               "zcode-source-bundle-input-policy.v1") == 0) {
        return snprintf(out, out_size,
            "#define _GNU_SOURCE\n"
            "#include \"hotswap/hotfork_capsule.h\"\n"
            "#include \"%s\"\n"
            "__attribute__((visibility(\"hidden\")))\n"
            "bool zcl_hotfork_candidate_story_v1(struct zcl_hotfork_observation_v1 *out) {\n"
            " if (!out) return false; memset(out,0,sizeof(*out));"
            " out->magic=ZCL_HOTFORK_OBSERVATION_MAGIC;\n"
            " #define HF_CHECK(x) do { out->checks_run++; if (x) out->checks_passed++; } while(0)\n"
            " struct json_value doc,upper,rendered; json_init(&doc); json_set_object(&doc);"
            " char lower[65],capital[65]; memset(lower,'a',64); lower[64]=0;"
            " memset(capital,'A',64); capital[64]=0;"
            " json_push_kv_str(&doc,\"source_root\",lower);"
            " json_push_kv_str(&doc,\"named_root\",lower);"
            " json_push_kv_int(&doc,\"count\",7);"
            " HF_CHECK(strcmp(zsb_str(&doc,\"source_root\"),lower)==0);"
            " HF_CHECK(zsb_str(&doc,\"missing\")==NULL);"
            " HF_CHECK(zsb_str(&doc,\"count\")==NULL);"
            " uint8_t root[32],named[32];"
            " HF_CHECK(zsb_root(&doc,root) && root[0]==0xaa && root[31]==0xaa);"
            " HF_CHECK(zsb_named_root(&doc,\"named_root\",named) && memcmp(root,named,32)==0);"
            " json_init(&upper); json_set_object(&upper);"
            " json_push_kv_str(&upper,\"source_root\",capital);"
            " HF_CHECK(!zsb_root(&upper,root)); json_free(&upper);"
            " HF_CHECK(!zsb_paths_disjoint(\"src\",\"src\"));"
            " HF_CHECK(!zsb_paths_disjoint(\"src\",\"src/lib/x.c\"));"
            " HF_CHECK(!zsb_paths_disjoint(\"src/lib/x.c\",\"src\"));"
            " HF_CHECK(zsb_paths_disjoint(\"src/a\",\"src/b\"));\n"
            " struct vcs_source_bundle_metrics metrics={.source_bytes=11,.compressed_bytes=7,"
            " .new_bytes=5,.reused_bytes=6,.file_count=2,.new_blobs=1,.reused_blobs=1,"
            " .manifest_reused=true,.repaired=false};"
            " memset(root,0x5a,sizeof(root)); json_init(&rendered); json_set_object(&rendered);"
            " zsb_render(&rendered,root,&metrics);"
            " HF_CHECK(strlen(json_get_str(json_get(&rendered,\"source_root\")))==64"
            " && json_get_int(json_get(&rendered,\"source_bytes\"))==11"
            " && json_get_int(json_get(&rendered,\"compressed_bytes\"))==7"
            " && json_get_int(json_get(&rendered,\"file_count\"))==2);"
            " HF_CHECK(json_get_bool(json_get(&rendered,\"manifest_reused\"))"
            " && !json_get_bool(json_get(&rendered,\"repaired\"))"
            " && !json_get_bool(json_get(&rendered,\"git_required\"))"
            " && !json_get_bool(json_get(&rendered,\"source_executed\")));"
            " json_free(&rendered); json_free(&doc);\n"
            " #undef HF_CHECK\n"
            " snprintf(out->exercised_surface,sizeof(out->exercised_surface),\"%s\");"
            " snprintf(out->detail,sizeof(out->detail),\"checks=%%u/%%u\","
            " out->checks_passed,out->checks_run);"
            " return out->checks_run==12 && out->checks_passed==12; }\n",
            source_path, def->exercised_surface);
    }
    if (strcmp(def->story_id,
               "app-native-read-rpc-composition.v1") == 0) {
        return snprintf(out, out_size,
            "#define _GNU_SOURCE\n"
            "#include \"hotswap/hotfork_capsule.h\"\n"
            "#define node_rpc_call hotfork_node_rpc_call\n"
            "#include \"%s\"\n"
            "#undef node_rpc_call\n"
            "static char hf_method[64],hf_params[256]; static const char *hf_reply;\n"
            "char *hotfork_node_rpc_call(const char *method,const char *params){"
            " snprintf(hf_method,sizeof(hf_method),\"%%s\",method?method:\"\");"
            " snprintf(hf_params,sizeof(hf_params),\"%%s\",params?params:\"<null>\");"
            " return hf_reply?strdup(hf_reply):NULL; }\n"
            "__attribute__((visibility(\"hidden\")))\n"
            "bool zcl_hotfork_candidate_story_v1(struct zcl_hotfork_observation_v1 *out) {\n"
            " if (!out) return false; memset(out,0,sizeof(*out));"
            " out->magic=ZCL_HOTFORK_OBSERVATION_MAGIC;\n"
            " #define HF_CHECK(x) do { out->checks_run++; if (x) out->checks_passed++; } while(0)\n"
            " struct zcl_native_body_err err={0}; char *body=NULL; struct json_value args,doc;"
            " const struct json_value *value=NULL;\n"
            " hf_reply=\"[\\\"ZCL\\\"]\"; body=zcl_native_zslp_listtokens_body(NULL,&err);"
            " json_init(&doc); bool parsed=body && json_read(&doc,body,strlen(body));"
            " value=parsed?json_get(&doc,\"tokens\"):NULL;"
            " HF_CHECK(parsed && value && value->type==JSON_ARR && json_size(value)==1"
            " && strcmp(json_get_str(json_at(value,0)),\"ZCL\")==0);"
            " json_free(&doc); free(body);\n"
            " hf_reply=\"legacy-error\"; body=zcl_native_zslp_listtokens_body(NULL,&err);"
            " HF_CHECK(body && strcmp(body,\"legacy-error\")==0); free(body);\n"
            " json_init(&args); json_set_object(&args); json_push_kv_str(&args,\"name\",\"alice\");"
            " hf_reply=\"{}\"; body=zcl_native_name_resolve_body(&args,&err);"
            " HF_CHECK(body && strcmp(hf_method,\"name_resolve\")==0"
            " && strcmp(hf_params,\"[\\\"alice\\\"]\")==0); free(body); json_free(&args);\n"
            " body=zcl_native_name_list_body(NULL,&err);"
            " HF_CHECK(body && strcmp(hf_method,\"name_list\")==0"
            " && strcmp(hf_params,\"<null>\")==0); free(body);\n"
            " hf_reply=\"[]\"; body=zcl_native_msg_inbox_body(NULL,&err);"
            " json_init(&doc); parsed=body && json_read(&doc,body,strlen(body));"
            " value=parsed?json_get(&doc,\"messages\"):NULL;"
            " HF_CHECK(body && strcmp(hf_method,\"msg_inbox\")==0"
            " && strcmp(hf_params,\"<null>\")==0 && parsed && value"
            " && value->type==JSON_ARR && json_size(value)==0);"
            " json_free(&doc); free(body);\n"
            " json_init(&args); json_set_object(&args); json_push_kv_str(&args,\"profile\",\"open\");"
            " body=zcl_native_zmarket_list_body(&args,&err);"
            " HF_CHECK(body && strcmp(hf_method,\"zmarket_list\")==0"
            " && strcmp(hf_params,\"[\\\"open\\\"]\")==0); free(body); json_free(&args);\n"
            " body=zcl_native_zmarket_list_body(NULL,&err);"
            " HF_CHECK(body && strcmp(hf_method,\"zmarket_list\")==0"
            " && strcmp(hf_params,\"<null>\")==0); free(body);\n"
            " body=zcl_native_zmarket_status_body(NULL,&err);"
            " HF_CHECK(body && strcmp(hf_method,\"zmarket_status\")==0); free(body);\n"
            " body=zcl_native_zmarket_content_list_body(NULL,&err);"
            " HF_CHECK(body && strcmp(hf_method,\"zmarket_content_list\")==0); free(body);\n"
            " body=zcl_native_swap_chains_body(NULL,&err);"
            " HF_CHECK(body && strcmp(hf_method,\"swap_chains\")==0); free(body);\n"
            " json_init(&args); json_set_object(&args); json_push_kv_str(&args,\"state\",\"complete\");"
            " body=zcl_native_swap_list_body(&args,&err);"
            " HF_CHECK(body && strcmp(hf_method,\"swap_list\")==0"
            " && strcmp(hf_params,\"[\\\"complete\\\"]\")==0); free(body); json_free(&args);\n"
            " json_init(&args); json_set_object(&args); body=zcl_native_swap_list_body(&args,&err);"
            " HF_CHECK(body && strcmp(hf_method,\"swap_list\")==0"
            " && strcmp(hf_params,\"<null>\")==0); free(body); json_free(&args);\n"
            " #undef HF_CHECK\n"
            " snprintf(out->exercised_surface,sizeof(out->exercised_surface),\"%s\");"
            " snprintf(out->detail,sizeof(out->detail),\"checks=%%u/%%u\","
            " out->checks_passed,out->checks_run);"
            " return out->checks_run==12 && out->checks_passed==12; }\n",
            source_path, def->exercised_surface);
    }
    if (strcmp(def->story_id,
               "zcode-moderation-input-policy.v1") == 0) {
        return snprintf(out, out_size,
            "#define _GNU_SOURCE\n"
            "#include \"hotswap/hotfork_capsule.h\"\n"
            "#define zcl_native_zcode_workspace_is_explicit_scratch hotfork_workspace_is_scratch\n"
            "#include \"%s\"\n"
            "#undef zcl_native_zcode_workspace_is_explicit_scratch\n"
            "bool hotfork_workspace_is_scratch(const char *path) {"
            " return path && strcmp(path,\"/tmp/zcl-hotfork-scratch\")==0; }\n"
            "__attribute__((visibility(\"hidden\")))\n"
            "bool zcl_hotfork_candidate_story_v1(struct zcl_hotfork_observation_v1 *out) {\n"
            " if (!out) return false; memset(out,0,sizeof(*out));"
            " out->magic=ZCL_HOTFORK_OBSERVATION_MAGIC;\n"
            " #define HF_CHECK(x) do { out->checks_run++; if (x) out->checks_passed++; } while(0)\n"
            " struct json_value doc; const char *workspace=NULL; uint64_t height=0; int64_t mtp=0;"
            " json_init(&doc); json_set_object(&doc); HF_CHECK(moderation_no_keys(&doc));"
            " json_push_kv_bool(&doc,\"extra\",true); HF_CHECK(!moderation_no_keys(&doc)); json_free(&doc);"
            " HF_CHECK(!moderation_no_keys(NULL)); json_init(&doc); json_set_array(&doc);"
            " HF_CHECK(!moderation_no_keys(&doc)); json_free(&doc);\n"
            " const char valid[] = \"{\\\"workspace\\\":\\\"/tmp/zcl-hotfork-scratch\\\","
            "\\\"cutoff_height\\\":7,\\\"cutoff_mtp\\\":11}\";"
            " json_init(&doc); bool parsed=json_read(&doc,valid,strlen(valid));"
            " HF_CHECK(parsed && moderation_backlog_input(&doc,&workspace,&height,&mtp)"
            " && strcmp(workspace,\"/tmp/zcl-hotfork-scratch\")==0 && height==7 && mtp==11);"
            " json_free(&doc);\n"
            " const char unknown[] = \"{\\\"workspace\\\":\\\"/tmp/zcl-hotfork-scratch\\\","
            "\\\"cutoff_height\\\":7,\\\"unknown\\\":11}\";"
            " json_init(&doc); parsed=json_read(&doc,unknown,strlen(unknown));"
            " HF_CHECK(parsed && !moderation_backlog_input(&doc,&workspace,&height,&mtp)); json_free(&doc);\n"
            " const char zero[] = \"{\\\"workspace\\\":\\\"/tmp/zcl-hotfork-scratch\\\","
            "\\\"cutoff_height\\\":0,\\\"cutoff_mtp\\\":11}\";"
            " json_init(&doc); parsed=json_read(&doc,zero,strlen(zero));"
            " HF_CHECK(parsed && !moderation_backlog_input(&doc,&workspace,&height,&mtp)); json_free(&doc);\n"
            " const char wrong_type[] = \"{\\\"workspace\\\":\\\"/tmp/zcl-hotfork-scratch\\\","
            "\\\"cutoff_height\\\":\\\"7\\\",\\\"cutoff_mtp\\\":11}\";"
            " json_init(&doc); parsed=json_read(&doc,wrong_type,strlen(wrong_type));"
            " HF_CHECK(parsed && !moderation_backlog_input(&doc,&workspace,&height,&mtp)); json_free(&doc);\n"
            " const char nonscratch[] = \"{\\\"workspace\\\":\\\"/srv/zcode\\\","
            "\\\"cutoff_height\\\":7,\\\"cutoff_mtp\\\":11}\";"
            " json_init(&doc); parsed=json_read(&doc,nonscratch,strlen(nonscratch));"
            " HF_CHECK(parsed && !moderation_backlog_input(&doc,&workspace,&height,&mtp)); json_free(&doc);\n"
            " HF_CHECK(!moderation_backlog_input(NULL,&workspace,&height,&mtp));\n"
            " #undef HF_CHECK\n"
            " snprintf(out->exercised_surface,sizeof(out->exercised_surface),\"%s\");"
            " snprintf(out->detail,sizeof(out->detail),\"checks=%%u/%%u\","
            " out->checks_passed,out->checks_run);"
            " return out->checks_run==10 && out->checks_passed==10; }\n",
            source_path, def->exercised_surface);
    }
    if (strcmp(def->story_id,
               "zcode-dev-input-policy.v1") == 0) {
        return snprintf(out, out_size,
            "#define _GNU_SOURCE\n"
            "#include \"hotswap/hotfork_capsule.h\"\n"
            "#include \"%s\"\n"
            "__attribute__((visibility(\"hidden\")))\n"
            "bool zcl_hotfork_candidate_story_v1(struct zcl_hotfork_observation_v1 *out) {\n"
            " if (!out) return false; memset(out,0,sizeof(*out));"
            " out->magic=ZCL_HOTFORK_OBSERVATION_MAGIC;\n"
            " #define HF_CHECK(x) do { out->checks_run++; if (x) out->checks_passed++; } while(0)\n"
            " struct json_value doc,rendered; json_init(&doc); json_set_object(&doc);"
            " json_push_kv_str(&doc,\"name\",\"alice\"); json_push_kv_int(&doc,\"count\",7);"
            " HF_CHECK(strcmp(zdev_str(&doc,\"name\"),\"alice\")==0);"
            " HF_CHECK(zdev_str(&doc,\"missing\")==NULL);"
            " HF_CHECK(zdev_int(&doc,\"count\",3)==7);"
            " HF_CHECK(zdev_int(&doc,\"missing\",3)==3);\n"
            " char lower[65],upper[65]; memset(lower,'a',64); lower[64]=0;"
            " memset(upper,'A',64); upper[64]=0; json_push_kv_str(&doc,\"root\",lower);"
            " uint8_t root[32]; struct zcl_command_reply reply;"
            " zcl_command_reply_init(&reply,\"zcl.hotfork.zdev.v1\");"
            " HF_CHECK(zdev_root(&doc,\"root\",root,&reply));"
            " json_init(&rendered); json_set_object(&rendered); zdev_push_root(&rendered,\"root\",root);"
            " HF_CHECK(strcmp(json_get_str(json_get(&rendered,\"root\")),lower)==0);"
            " json_free(&rendered); json_push_kv_str(&doc,\"upper\",upper);"
            " HF_CHECK(!zdev_root(&doc,\"upper\",root,&reply));"
            " size_t wire_len=0; json_push_kv_str(&doc,\"wire\",\"00ff\");"
            " uint8_t *wire=zdev_hex_wire(&doc,\"wire\",2,&wire_len);"
            " HF_CHECK(wire && wire_len==2 && wire[0]==0 && wire[1]==255); free(wire);"
            " json_push_kv_str(&doc,\"odd\",\"abc\");"
            " HF_CHECK(zdev_hex_wire(&doc,\"odd\",2,&wire_len)==NULL && wire_len==0);"
            " HF_CHECK(zdev_hex_wire(&doc,\"wire\",1,&wire_len)==NULL && wire_len==0);\n"
            " HF_CHECK(zdev_paths_overlap(\"src\",\"src\"));"
            " HF_CHECK(zdev_paths_overlap(\"src\",\"src/lib/x.c\"));"
            " HF_CHECK(zdev_paths_overlap(\"src/lib\",\"src\"));"
            " HF_CHECK(!zdev_paths_overlap(\"src/a\",\"src/b\"));"
            " char path[VCS_PATH_MAX+1u];"
            " HF_CHECK(zdev_candidate_input_path(NULL,NULL,\"src/lib/x.c\",path,&reply)"
            " && strcmp(path,\"src/lib/x.c\")==0);"
            " HF_CHECK(!zdev_candidate_input_path(NULL,NULL,\"src/../x.c\",path,&reply));"
            " zcl_command_reply_free(&reply); json_free(&doc);\n"
            " #undef HF_CHECK\n"
            " snprintf(out->exercised_surface,sizeof(out->exercised_surface),\"%s\");"
            " snprintf(out->detail,sizeof(out->detail),\"checks=%%u/%%u\","
            " out->checks_passed,out->checks_run);"
            " return out->checks_run==16 && out->checks_passed==16; }\n",
            source_path, def->exercised_surface);
    }
    if (strcmp(def->story_id,
               "zcode-epoch-propose-input-policy.v1") == 0) {
        return snprintf(out, out_size,
            "#define _GNU_SOURCE\n"
            "#include \"hotswap/hotfork_capsule.h\"\n"
            "#define zcl_native_zcode_workspace_is_explicit_scratch hotfork_workspace_is_scratch\n"
            "#include \"%s\"\n"
            "#undef zcl_native_zcode_workspace_is_explicit_scratch\n"
            "bool hotfork_workspace_is_scratch(const char *path) {"
            " return path && strcmp(path,\"/tmp/zcl-hotfork-scratch\")==0; }\n"
            "__attribute__((visibility(\"hidden\")))\n"
            "bool zcl_hotfork_candidate_story_v1(struct zcl_hotfork_observation_v1 *out) {\n"
            " if (!out) return false; memset(out,0,sizeof(*out));"
            " out->magic=ZCL_HOTFORK_OBSERVATION_MAGIC;\n"
            " #define HF_CHECK(x) do { out->checks_run++; if (x) out->checks_passed++; } while(0)\n"
            " static const char *const allowed[]={\"workspace\",\"epoch\",\"previous_proposal_root\"};"
            " char lower[65],upper[65]; memset(lower,'a',64); lower[64]=0;"
            " memset(upper,'A',64); upper[64]=0;"
            " char valid[256]; snprintf(valid,sizeof(valid),"
            " \"{\\\"workspace\\\":\\\"/tmp/zcl-hotfork-scratch\\\",\\\"epoch\\\":7,\\\"previous_proposal_root\\\":\\\"%%s\\\"}\",lower);"
            " struct json_value doc; json_init(&doc);"
            " bool parsed=json_read(&doc,valid,strlen(valid));"
            " HF_CHECK(parsed && strcmp(zep_str(&doc,\"workspace\"),\"/tmp/zcl-hotfork-scratch\")==0);"
            " HF_CHECK(parsed && zep_str(&doc,\"missing\")==NULL);"
            " HF_CHECK(parsed && zep_keys(&doc,allowed,3));"
            " uint8_t root[32]; HF_CHECK(parsed && zep_root(&doc,\"previous_proposal_root\",root) && root[0]==0xaa && root[31]==0xaa);"
            " uint64_t epoch=0; HF_CHECK(parsed && zep_u64_positive(&doc,\"epoch\",&epoch) && epoch==7);"
            " struct zcl_command_request request={.input=&doc}; struct zcl_command_reply reply;"
            " struct vcs_zcode_epoch_schedule_input input; uint8_t previous[32];"
            " zcl_command_reply_init(&reply,\"zcl.hotfork.zep.v1\");"
            " HF_CHECK(zep_parse_propose(&request,&reply,&input,previous) && input.epoch==7"
            " && strcmp(input.workspace,\"/tmp/zcl-hotfork-scratch\")==0 && previous[0]==0xaa);"
            " zcl_command_reply_free(&reply); json_free(&doc);\n"
            " char candidate[320]; snprintf(candidate,sizeof(candidate),"
            " \"{\\\"workspace\\\":\\\"/tmp/zcl-hotfork-scratch\\\",\\\"epoch\\\":7,\\\"previous_proposal_root\\\":\\\"%%s\\\"}\",upper);"
            " json_init(&doc); parsed=json_read(&doc,candidate,strlen(candidate));"
            " HF_CHECK(parsed && !zep_root(&doc,\"previous_proposal_root\",root)); json_free(&doc);\n"
            " snprintf(candidate,sizeof(candidate),"
            " \"{\\\"workspace\\\":\\\"/tmp/zcl-hotfork-scratch\\\",\\\"epoch\\\":0,\\\"previous_proposal_root\\\":\\\"%%s\\\"}\",lower);"
            " json_init(&doc); parsed=json_read(&doc,candidate,strlen(candidate));"
            " zcl_command_reply_init(&reply,\"zcl.hotfork.zep.v1\"); request.input=&doc;"
            " HF_CHECK(parsed && !zep_parse_propose(&request,&reply,&input,previous));"
            " zcl_command_reply_free(&reply); json_free(&doc);\n"
            " snprintf(candidate,sizeof(candidate),"
            " \"{\\\"workspace\\\":\\\"/tmp/zcl-hotfork-scratch\\\",\\\"epoch\\\":7,\\\"previous_proposal_root\\\":\\\"%%s\\\",\\\"extra\\\":true}\",lower);"
            " json_init(&doc); parsed=json_read(&doc,candidate,strlen(candidate));"
            " zcl_command_reply_init(&reply,\"zcl.hotfork.zep.v1\"); request.input=&doc;"
            " HF_CHECK(parsed && !zep_parse_propose(&request,&reply,&input,previous));"
            " zcl_command_reply_free(&reply); json_free(&doc);\n"
            " snprintf(candidate,sizeof(candidate),"
            " \"{\\\"workspace\\\":\\\"/srv/zcode\\\",\\\"epoch\\\":7,\\\"previous_proposal_root\\\":\\\"%%s\\\"}\",lower);"
            " json_init(&doc); parsed=json_read(&doc,candidate,strlen(candidate));"
            " zcl_command_reply_init(&reply,\"zcl.hotfork.zep.v1\"); request.input=&doc;"
            " HF_CHECK(parsed && !zep_parse_propose(&request,&reply,&input,previous));"
            " zcl_command_reply_free(&reply); json_free(&doc);\n"
            " json_init(&doc); json_set_array(&doc); HF_CHECK(!zep_keys(&doc,allowed,3)); json_free(&doc);"
            " json_init(&doc); json_set_object(&doc); HF_CHECK(!zep_root(&doc,\"missing\",root));"
            " json_push_kv_int(&doc,\"epoch\",-1); HF_CHECK(!zep_u64_positive(&doc,\"epoch\",&epoch)); json_free(&doc);\n"
            " #undef HF_CHECK\n"
            " snprintf(out->exercised_surface,sizeof(out->exercised_surface),\"%s\");"
            " snprintf(out->detail,sizeof(out->detail),\"checks=%%u/%%u\","
            " out->checks_passed,out->checks_run);"
            " return out->checks_run==13 && out->checks_passed==13; }\n",
            source_path, def->exercised_surface);
    }
    if (strcmp(def->story_id,
               "zcode-passport-input-policy.v1") == 0) {
        return snprintf(out, out_size,
            "#define _GNU_SOURCE\n"
            "#include \"hotswap/hotfork_capsule.h\"\n"
            "#include \"%s\"\n"
            "static bool hf_passport_parse(const char *text,bool commit,"
            " struct vcs_zcode_module_passport_v1 *passport) {"
            " struct json_value doc; json_init(&doc);"
            " bool decoded=text && json_read(&doc,text,strlen(text));"
            " struct zcl_command_request request={.input=&doc};"
            " struct zcl_command_reply reply;"
            " zcl_command_reply_init(&reply,\"zcl.hotfork.passport.v1\");"
            " bool ok=decoded && passport_parse_roots(&request,&reply,passport,commit,"
            " commit?\"commit\":\"plan\");"
            " zcl_command_reply_free(&reply); json_free(&doc); return ok; }\n"
            "__attribute__((visibility(\"hidden\")))\n"
            "bool zcl_hotfork_candidate_story_v1(struct zcl_hotfork_observation_v1 *out) {\n"
            " if (!out) return false; memset(out,0,sizeof(*out));"
            " out->magic=ZCL_HOTFORK_OBSERVATION_MAGIC;\n"
            " #define HF_CHECK(x) do { out->checks_run++; if (x) out->checks_passed++; } while(0)\n"
            " HF_CHECK(passport_key_allowed(\"stable_api_root\",false));"
            " HF_CHECK(!passport_key_allowed(\"signature\",false));"
            " HF_CHECK(passport_key_allowed(\"signature\",true));"
            " HF_CHECK(!passport_key_allowed(\"unknown\",true));\n"
            " char lower[65],upper[65]; memset(lower,'a',64); lower[64]=0;"
            " memset(upper,'A',64); upper[64]=0; char plan[1400],candidate[1600];"
            " snprintf(plan,sizeof(plan),"
            " \"{\\\"stable_api_root\\\":\\\"%%s\\\",\\\"recipe_root\\\":\\\"%%s\\\","
            "\\\"toolchain_root\\\":\\\"%%s\\\",\\\"tests_root\\\":\\\"%%s\\\","
            "\\\"license_root\\\":\\\"%%s\\\",\\\"semantic_fingerprint_root\\\":\\\"%%s\\\","
            "\\\"workspace_lineage_root\\\":\\\"%%s\\\",\\\"source_assignment_root\\\":\\\"%%s\\\","
            "\\\"quality_profiles_root\\\":\\\"%%s\\\",\\\"signer_pubkey\\\":\\\"%%s\\\"}\","
            " lower,lower,lower,lower,lower,lower,lower,lower,lower,lower);"
            " struct vcs_zcode_module_passport_v1 passport;"
            " HF_CHECK(hf_passport_parse(plan,false,&passport) && passport.schema_version==1"
            " && passport.flags==VCS_ZCODE_COMMONS_V2_REQUIRED_FLAGS"
            " && passport.stable_api_root[0]==0xaa && passport.signer_root[31]==0xaa);\n"
            " size_t n=strlen(plan); snprintf(candidate,sizeof(candidate),"
            " \"%%.*s,\\\"workspace\\\":\\\"/tmp/zcl-hotfork-scratch\\\","
            "\\\"publication_job_root\\\":\\\"00\\\"}\",(int)(n-1),plan);"
            " HF_CHECK(hf_passport_parse(candidate,false,&passport));"
            " snprintf(candidate,sizeof(candidate),"
            " \"%%.*s,\\\"workspace\\\":\\\"/tmp/zcl-hotfork-scratch\\\"}\","
            " (int)(n-1),plan);"
            " HF_CHECK(!hf_passport_parse(candidate,false,&passport));\n"
            " snprintf(candidate,sizeof(candidate),\"%%s\",plan);"
            " char *root=strstr(candidate,lower); if (root) memcpy(root,upper,64);"
            " HF_CHECK(root && !hf_passport_parse(candidate,false,&passport));"
            " snprintf(candidate,sizeof(candidate),"
            " \"%%.*s,\\\"unknown\\\":true}\",(int)(n-1),plan);"
            " HF_CHECK(!hf_passport_parse(candidate,false,&passport));"
            " HF_CHECK(!hf_passport_parse(\"{}\",false,&passport));\n"
            " snprintf(candidate,sizeof(candidate),"
            " \"%%.*s,\\\"signature\\\":\\\"placeholder\\\"}\",(int)(n-1),plan);"
            " HF_CHECK(hf_passport_parse(candidate,true,&passport));\n"
            " #undef HF_CHECK\n"
            " snprintf(out->exercised_surface,sizeof(out->exercised_surface),\"%s\");"
            " snprintf(out->detail,sizeof(out->detail),\"checks=%%u/%%u\","
            " out->checks_passed,out->checks_run);"
            " return out->checks_run==11 && out->checks_passed==11; }\n",
            source_path, def->exercised_surface);
    }
    if (strcmp(def->story_id,
               "zcode-workspace-input-policy.v1") == 0) {
        return snprintf(out, out_size,
            "#define _GNU_SOURCE\n"
            "#include \"hotswap/hotfork_capsule.h\"\n"
            "#include \"%s\"\n"
            "__attribute__((visibility(\"hidden\")))\n"
            "bool zcl_hotfork_candidate_story_v1(struct zcl_hotfork_observation_v1 *out) {\n"
            " if (!out) return false; memset(out,0,sizeof(*out));"
            " out->magic=ZCL_HOTFORK_OBSERVATION_MAGIC;\n"
            " #define HF_CHECK(x) do { out->checks_run++; if (x) out->checks_passed++; } while(0)\n"
            " char lower[65],upper[65]; memset(lower,'a',64); lower[64]=0;"
            " memset(upper,'A',64); upper[64]=0;"
            " struct json_value doc; json_init(&doc); json_set_object(&doc);"
            " json_push_kv_str(&doc,\"root\",lower);"
            " json_push_kv_str(&doc,\"upper\",upper); uint8_t root[32];"
            " HF_CHECK(workspace_decode_root(&doc,\"root\",root)"
            " && root[0]==0xaa && root[31]==0xaa);"
            " HF_CHECK(!workspace_decode_root(&doc,\"upper\",root));"
            " HF_CHECK(!workspace_decode_root(&doc,\"missing\",root));"
            " json_free(&doc);\n"
            " HF_CHECK(workspace_manifest_key_allowed(\"passport\",false));"
            " HF_CHECK(!workspace_manifest_key_allowed(\"signature\",false));"
            " HF_CHECK(workspace_manifest_key_allowed(\"signature\",true));"
            " HF_CHECK(!workspace_manifest_key_allowed(\"unknown\",true));"
            " HF_CHECK(!workspace_manifest_key_allowed(NULL,true));\n"
            " uint8_t zero[32]={0},nonzero[32]={0}; nonzero[17]=1;"
            " HF_CHECK(workspace_root_is_zero(zero));"
            " HF_CHECK(!workspace_root_is_zero(nonzero));\n"
            " #undef HF_CHECK\n"
            " snprintf(out->exercised_surface,sizeof(out->exercised_surface),\"%s\");"
            " snprintf(out->detail,sizeof(out->detail),\"checks=%%u/%%u\","
            " out->checks_passed,out->checks_run);"
            " return out->checks_run==10 && out->checks_passed==10; }\n",
            source_path, def->exercised_surface);
    }
    if (strcmp(def->story_id,
               "source-package-transport-shape.v1") == 0) {
        return snprintf(out, out_size,
            "#define _GNU_SOURCE\n"
            "#include \"hotswap/hotfork_capsule.h\"\n"
            "#include \"%s\"\n"
            "__attribute__((visibility(\"hidden\")))\n"
            "bool zcl_hotfork_candidate_story_v1(struct zcl_hotfork_observation_v1 *out) {\n"
            " if (!out) return false; memset(out,0,sizeof(*out));"
            " out->magic=ZCL_HOTFORK_OBSERVATION_MAGIC;\n"
            " #define HF_CHECK(x) do { out->checks_run++; if (x) out->checks_passed++; } while(0)\n"
            " size_t marker_len=0; const uint8_t *marker="
            "vcs_source_package_transport_marker(&marker_len);"
            " HF_CHECK(marker && marker_len==sizeof(source_transport_marker)-1"
            " && memcmp(marker,source_transport_marker,marker_len)==0);\n"
            " static uint8_t license[]={1},manifest[]={2},shard0[]={3},shard1[]={4},"
            " lane[]={5},authority[]={6},offline0[]={7},offline1[]={8};"
            " struct vcs_source_package_transport transport={0};"
            " transport.license_bytes=license; transport.license_len=sizeof(license);"
            " transport.source.manifest_wire=manifest; transport.source.manifest_wire_len=sizeof(manifest);"
            " transport.source.shard_count=2;"
            " transport.source.shards[0]=(struct vcs_source_bundle_shard){.index=0x0a,.wire=shard0,.wire_len=sizeof(shard0)};"
            " transport.source.shards[1]=(struct vcs_source_bundle_shard){.index=0xff,.wire=shard1,.wire_len=sizeof(shard1)};"
            " transport.lane_wire=lane; transport.lane_wire_len=sizeof(lane);"
            " transport.offline_input_count=2;"
            " transport.offline_inputs[0]=(struct vcs_source_package_file){.path=\"offline-a\",.bytes=offline0,.len=sizeof(offline0)};"
            " transport.offline_inputs[1]=(struct vcs_source_package_file){.path=\"offline-b\",.bytes=offline1,.len=sizeof(offline1)};"
            " HF_CHECK(vcs_source_package_transport_file_count(NULL)==0);"
            " HF_CHECK(vcs_source_package_transport_file_count(&transport)==8);\n"
            " const char *path=NULL; const uint8_t *bytes=NULL; size_t len=0;"
            " HF_CHECK(vcs_source_package_transport_file_at(&transport,0,&path,&bytes,&len)"
            " && strcmp(path,VCS_SOURCE_PACKAGE_LICENSE_PATH)==0 && bytes==license && len==1);"
            " HF_CHECK(vcs_source_package_transport_file_at(&transport,1,&path,&bytes,&len)"
            " && strcmp(path,VCS_SOURCE_PACKAGE_MANIFEST_PATH)==0 && bytes==manifest && len==1);"
            " HF_CHECK(vcs_source_package_transport_file_at(&transport,2,&path,&bytes,&len)"
            " && strcmp(path,\"zclassic23-source/shard-0a.zvss\")==0 && bytes==shard0 && len==1);"
            " HF_CHECK(vcs_source_package_transport_file_at(&transport,3,&path,&bytes,&len)"
            " && strcmp(path,\"zclassic23-source/shard-ff.zvss\")==0 && bytes==shard1 && len==1);"
            " HF_CHECK(vcs_source_package_transport_file_at(&transport,4,&path,&bytes,&len)"
            " && strcmp(path,VCS_SOURCE_PACKAGE_LANE_PATH)==0 && bytes==lane && len==1);"
            " HF_CHECK(vcs_source_package_transport_file_at(&transport,5,&path,&bytes,&len)"
            " && strcmp(path,VCS_SOURCE_PACKAGE_MARKER_PATH)==0 && bytes==marker && len==marker_len);"
            " HF_CHECK(vcs_source_package_transport_file_at(&transport,6,&path,&bytes,&len)"
            " && strcmp(path,\"offline-a\")==0 && bytes==offline0 && len==1);"
            " HF_CHECK(vcs_source_package_transport_file_at(&transport,7,&path,&bytes,&len)"
            " && strcmp(path,\"offline-b\")==0 && bytes==offline1 && len==1);"
            " HF_CHECK(!vcs_source_package_transport_file_at(&transport,8,&path,&bytes,&len));\n"
            " transport.authority_wire=authority; transport.authority_wire_len=sizeof(authority);"
            " HF_CHECK(vcs_source_package_transport_file_count(&transport)==9);"
            " HF_CHECK(vcs_source_package_transport_file_at(&transport,6,&path,&bytes,&len)"
            " && strcmp(path,VCS_SOURCE_PACKAGE_AUTHORITY_PATH)==0 && bytes==authority && len==1);"
            " HF_CHECK(vcs_source_package_transport_file_at(&transport,7,&path,&bytes,&len)"
            " && strcmp(path,\"offline-a\")==0);"
            " HF_CHECK(vcs_source_package_offline_input_count()==5);"
            " HF_CHECK(strcmp(vcs_source_package_offline_input_path(0),"
            " \"vendor/.cache/leveldb-1.23.tar.gz\")==0);"
            " HF_CHECK(strcmp(vcs_source_package_offline_input_path(4),"
            " \"vendor/.cache/zlib-1.3.1.tar.gz\")==0);"
            " HF_CHECK(vcs_source_package_offline_input_path(5)==NULL);\n"
            " #undef HF_CHECK\n"
            " snprintf(out->exercised_surface,sizeof(out->exercised_surface),\"%s\");"
            " snprintf(out->detail,sizeof(out->detail),\"checks=%%u/%%u\","
            " out->checks_passed,out->checks_run);"
            " return out->checks_run==19 && out->checks_passed==19; }\n",
            source_path, def->exercised_surface);
    }
    if (strcmp(def->story_id,
               "vcs-devloop-publication-envelope.v1") == 0) {
        return snprintf(out, out_size,
            "#define _GNU_SOURCE\n"
            "#include \"hotswap/hotfork_capsule.h\"\n"
            "#include \"%s\"\n"
            "__attribute__((visibility(\"hidden\")))\n"
            "bool zcl_hotfork_candidate_story_v1(struct zcl_hotfork_observation_v1 *out) {\n"
            " if (!out) { return false; } memset(out,0,sizeof(*out));"
            " out->magic=ZCL_HOTFORK_OBSERVATION_MAGIC;\n"
            " #define HF_CHECK(x) do { out->checks_run++; if (x) out->checks_passed++; } while(0)\n"
            " uint8_t zero[32]={0},one[32]={1};"
            " HF_CHECK(!publication_root_nonzero(zero));"
            " HF_CHECK(publication_root_nonzero(one));\n"
            " struct vcs_devloop_publication_job job={.version=VCS_DEVLOOP_PUBLICATION_JOB_VERSION};"
            " memset(job.vcs_commit_root,1,32); memset(job.source_tree_root,2,32);"
            " memset(job.proof_receipt_root,3,32); memset(job.source_identity_sha256,4,32);"
            " memset(job.source_cas_sha3,5,32); job.generation_sha256[0]=6;"
            " job.parent_workspace_root[0]=7;"
            " uint8_t job_wire[VCS_DEV_PUBLICATION_JOB_WIRE_BYTES];"
            " HF_CHECK(publication_job_serialize(&job,job_wire));"
            " struct vcs_devloop_publication_job parsed_job={0};"
            " HF_CHECK(publication_job_parse(job_wire,sizeof(job_wire),&parsed_job));"
            " HF_CHECK(memcmp(&job,&parsed_job,sizeof(job))==0);"
            " uint8_t saved=job_wire[0]; job_wire[0]^=1;"
            " HF_CHECK(!publication_job_parse(job_wire,sizeof(job_wire),&parsed_job)); job_wire[0]=saved;"
            " memset(job.source_tree_root,0,32);"
            " HF_CHECK(!publication_job_serialize(&job,job_wire));"
            " memset(job.source_tree_root,2,32); job.version=2;"
            " HF_CHECK(!publication_job_serialize(&job,job_wire));\n"
            " struct vcs_devloop_publication_receipt receipt={"
            " .version=VCS_DEVLOOP_PUBLICATION_RECEIPT_VERSION,"
            " .phase=VCS_DEVLOOP_PUBLICATION_PHASE_WAITING_ACCEPTANCE,"
            " .bytes_scanned=123,.new_chunks=4,.reused_chunks=5,.providers=6,.storage_acks=7};"
            " memset(receipt.job_root,8,32);"
            " uint8_t receipt_wire[VCS_DEV_PUBLICATION_RECEIPT_WIRE_BYTES];"
            " HF_CHECK(publication_receipt_serialize(&receipt,receipt_wire));"
            " struct vcs_devloop_publication_receipt parsed_receipt={0};"
            " HF_CHECK(publication_receipt_parse(receipt_wire,sizeof(receipt_wire),&parsed_receipt));"
            " HF_CHECK(memcmp(&receipt,&parsed_receipt,sizeof(receipt))==0);"
            " receipt.phase=VCS_DEVLOOP_PUBLICATION_PHASE_ACCEPTED_LANE_BOUND;"
            " HF_CHECK(!publication_receipt_serialize(&receipt,receipt_wire));"
            " memset(receipt.artifact_root,9,32);"
            " HF_CHECK(publication_receipt_serialize(&receipt,receipt_wire)"
            " && publication_receipt_parse(receipt_wire,sizeof(receipt_wire),&parsed_receipt)"
            " && memcmp(&receipt,&parsed_receipt,sizeof(receipt))==0);"
            " HF_CHECK(!publication_receipt_parse(receipt_wire,sizeof(receipt_wire)-1,&parsed_receipt));\n"
            " #undef HF_CHECK\n"
            " snprintf(out->exercised_surface,sizeof(out->exercised_surface),\"%s\");"
            " snprintf(out->detail,sizeof(out->detail),\"checks=%%u/%%u\","
            " out->checks_passed,out->checks_run);"
            " return out->checks_run==14 && out->checks_passed==14; }\n",
            source_path, def->exercised_surface);
    }
    if (strcmp(def->story_id,
               "native-dev-hotswap-receipt-policy.v1") == 0) {
        return snprintf(out, out_size,
            "#define _GNU_SOURCE\n"
            "#include \"hotswap/hotfork_capsule.h\"\n"
            "#include \"%s\"\n"
            "__attribute__((visibility(\"hidden\")))\n"
            "bool zcl_hotfork_candidate_story_v1(struct zcl_hotfork_observation_v1 *out) {\n"
            " if (!out) { return false; } memset(out,0,sizeof(*out));"
            " out->magic=ZCL_HOTFORK_OBSERVATION_MAGIC;\n"
            " #define HF_CHECK(x) do { out->checks_run++; if (x) out->checks_passed++; } while(0)\n"
            " struct hotswap_publish_hooks hooks={0};"
            " zcl_native_hotswap_publish_hooks(&hooks,false);"
            " HF_CHECK(hooks.commit==registry_commit_batch_cb);"
            " HF_CHECK(hooks.probe==registry_probe_cb);"
            " HF_CHECK(hooks.quiesced==NULL && hooks.ctx==NULL);"
            " zcl_native_hotswap_publish_hooks(&hooks,true);"
            " HF_CHECK(hooks.quiesced==registry_quiesced_cb);\n"
            " struct zcl_command_reply reply;"
            " zcl_command_reply_init(&reply,\"zcl.hotswap_activate.v2\");"
            " struct hotswap_activate_report module={.ok=true,.verify_only=true,"
            " .rolled_back=true,.probed=true,.generation=7,.leaf_count=2};"
            " snprintf(module.source_tu,sizeof(module.source_tu),\"app/example.c\");"
            " snprintf(module.stage,sizeof(module.stage),\"verified\");"
            " report_to_reply(&reply,&module);"
            " HF_CHECK(reply.status==ZCL_COMMAND_STATUS_PASSED && reply.exit_code==ZCL_COMMAND_EXIT_OK);"
            " const struct json_value *schema=json_get(&reply.data,\"schema\");"
            " const struct json_value *generation=json_get(&reply.data,\"generation\");"
            " HF_CHECK(schema && strcmp(json_get_str(schema),\"zcl.hotswap_activate.v2\")==0"
            " && generation && json_get_int(generation)==7); zcl_command_reply_free(&reply);\n"
            " zcl_command_reply_init(&reply,\"zcl.hotswap_activate.v2\");"
            " memset(&module,0,sizeof(module)); snprintf(module.stage,sizeof(module.stage),\"abi\");"
            " snprintf(module.error,sizeof(module.error),\"descriptor refused\");"
            " snprintf(module.handler_name,sizeof(module.handler_name),\"core.status\");"
            " report_to_reply(&reply,&module);"
            " HF_CHECK(reply.status==ZCL_COMMAND_STATUS_BLOCKED"
            " && strcmp(reply.error.code,\"HOTSWAP_REFUSED\")==0"
            " && strcmp(reply.error.phase,\"abi\")==0); zcl_command_reply_free(&reply);\n"
            " zcl_command_reply_init(&reply,\"zcl.hotswap_service_activate.v1\");"
            " struct zcl_hotswap_service_report service={.recognized=true,.ok=true,"
            " .verify_only=true,.probed=true,.generation=9};"
            " snprintf(service.service_id,sizeof(service.service_id),\"example.service.v1\");"
            " snprintf(service.stage,sizeof(service.stage),\"verified\");"
            " service_report_to_reply(&reply,&service);"
            " HF_CHECK(reply.status==ZCL_COMMAND_STATUS_PASSED && reply.exit_code==ZCL_COMMAND_EXIT_OK);"
            " generation=json_get(&reply.data,\"generation\");"
            " HF_CHECK(generation && json_get_int(generation)==9); zcl_command_reply_free(&reply);\n"
            " zcl_command_reply_init(&reply,\"zcl.hotswap_service_activate.v1\");"
            " memset(&service,0,sizeof(service)); service.dev_restart=true;"
            " snprintf(service.service_id,sizeof(service.service_id),\"unknown.service.v1\");"
            " snprintf(service.stage,sizeof(service.stage),\"contract\");"
            " snprintf(service.error,sizeof(service.error),\"resident contract absent\");"
            " service_report_to_reply(&reply,&service);"
            " HF_CHECK(reply.status==ZCL_COMMAND_STATUS_BLOCKED"
            " && strcmp(reply.error.code,\"DEV_RESTART\")==0"
            " && strcmp(reply.error.phase,\"contract\")==0); zcl_command_reply_free(&reply);\n"
            " char why[160]={0}; uint32_t generation_out=0;"
            " HF_CHECK(!registry_commit_batch_cb(NULL,NULL,0,&generation_out,why,sizeof(why))"
            " && strstr(why,\"no leaves\")!=NULL);"
            " struct zcl_hotswap_leaf dummy={.name=\"core.status\",.fn=NULL};"
            " memset(why,0,sizeof(why));"
            " HF_CHECK(!registry_commit_batch_cb(NULL,&dummy,ZCL_COMMAND_HANDLER_OVERRIDE_MAX+1u,"
            " &generation_out,why,sizeof(why)) && strstr(why,\"ceiling\")!=NULL);"
            " memset(why,0,sizeof(why));"
            " HF_CHECK(!registry_probe_cb(NULL,NULL,NULL,why,sizeof(why))"
            " && strstr(why,\"missing\")!=NULL);\n"
            " #undef HF_CHECK\n"
            " snprintf(out->exercised_surface,sizeof(out->exercised_surface),\"%s\");"
            " snprintf(out->detail,sizeof(out->detail),\"checks=%%u/%%u\","
            " out->checks_passed,out->checks_run);"
            " return out->checks_run==13 && out->checks_passed==13; }\n",
            source_path, def->exercised_surface);
    }
    if (strcmp(def->story_id,
               "native-dev-input-and-interrupt-policy.v1") == 0) {
        return snprintf(out, out_size,
            "#define _GNU_SOURCE\n"
            "#define ZCL_HOTFORK_NATIVE_DEV_INPUT_CORE 1\n"
            "#include \"hotswap/hotfork_capsule.h\"\n"
            "#include \"%s\"\n"
            "__attribute__((visibility(\"hidden\")))\n"
            "bool zcl_hotfork_candidate_story_v1(struct zcl_hotfork_observation_v1 *out) {\n"
            " if (!out) { return false; } memset(out,0,sizeof(*out));"
            " out->magic=ZCL_HOTFORK_OBSERVATION_MAGIC;\n"
            " #define HF_CHECK(x) do { out->checks_run++; if (x) out->checks_passed++; } while(0)\n"
            " const char *files[ZCL_DEVLOOP_MAX_FILES]; size_t count=0; char why[160]={0};"
            " struct json_value doc; json_init(&doc);\n"
            " const char valid_files[]=\"{\\\"files\\\":[\\\"tools/dev/devloop.c\\\"]}\";"
            " bool parsed=json_read(&doc,valid_files,strlen(valid_files));"
            " HF_CHECK(parsed && dev_request_files(&doc,false,files,&count,why,sizeof(why))"
            " && count==1 && strcmp(files[0],\"tools/dev/devloop.c\")==0); json_free(&doc);\n"
            " const char abs_files[]=\"{\\\"files\\\":[\\\"/tmp/x.c\\\"]}\";"
            " json_init(&doc); parsed=json_read(&doc,abs_files,strlen(abs_files));"
            " HF_CHECK(parsed && !dev_request_files(&doc,false,files,&count,why,sizeof(why)));"
            " json_free(&doc);\n"
            " const char dotdot_files[]=\"{\\\"files\\\":[\\\"tools/../x.c\\\"]}\";"
            " json_init(&doc); parsed=json_read(&doc,dotdot_files,strlen(dotdot_files));"
            " HF_CHECK(parsed && !dev_request_files(&doc,false,files,&count,why,sizeof(why)));"
            " json_free(&doc);\n"
            " int64_t cursor=0; const char cursor_json[]=\"{\\\"after_epoch\\\":7}\";"
            " json_init(&doc); parsed=json_read(&doc,cursor_json,strlen(cursor_json));"
            " HF_CHECK(parsed && dev_drive_input_int(&doc,\"after_epoch\",3,&cursor) && cursor==7);"
            " json_free(&doc);\n"
            " const char empty_json[]=\"{}\"; json_init(&doc);"
            " parsed=json_read(&doc,empty_json,strlen(empty_json));"
            " HF_CHECK(parsed && dev_drive_input_int(&doc,\"after_epoch\",3,&cursor) && cursor==3);"
            " json_free(&doc);\n"
            " const char bad_cursor[]=\"{\\\"after_epoch\\\":\\\"7\\\"}\";"
            " json_init(&doc); parsed=json_read(&doc,bad_cursor,strlen(bad_cursor));"
            " HF_CHECK(parsed && !dev_drive_input_int(&doc,\"after_epoch\",3,&cursor));"
            " json_free(&doc);\n"
            " const char red_phase[]=\"{\\\"phase\\\":\\\"STORY_RED\\\"}\";"
            " json_init(&doc); parsed=json_read(&doc,red_phase,strlen(red_phase));"
            " HF_CHECK(parsed && dev_event_interrupting(&doc)); json_free(&doc);\n"
            " const char red_status[]=\"{\\\"status\\\":\\\"compile_red\\\"}\";"
            " json_init(&doc); parsed=json_read(&doc,red_status,strlen(red_status));"
            " HF_CHECK(parsed && dev_event_interrupting(&doc)); json_free(&doc);\n"
            " const char pending[]=\"{\\\"status\\\":\\\"proof_pending\\\"}\";"
            " json_init(&doc); parsed=json_read(&doc,pending,strlen(pending));"
            " HF_CHECK(parsed && !dev_event_interrupting(&doc)); json_free(&doc);\n"
            " HF_CHECK(dev_group_valid(\"test_vcs_core\"));"
            " HF_CHECK(!dev_group_valid(\"test-vcs-core\"));\n"
            " char lower[65],upper[65],gen[80],legacy[80];"
            " memset(lower,'a',64); lower[64]=0; memset(upper,'A',64); upper[64]=0;"
            " snprintf(gen,sizeof(gen),\"gen-%%s\",lower);"
            " snprintf(legacy,sizeof(legacy),\"legacy-%%s\",lower);"
            " HF_CHECK(dev_generation_name_valid(gen));"
            " HF_CHECK(dev_generation_name_valid(legacy));"
            " snprintf(gen,sizeof(gen),\"gen-%%s\",upper);"
            " HF_CHECK(!dev_generation_name_valid(gen));\n"
            " HF_CHECK(dev_failure_id_valid(lower));"
            " HF_CHECK(!dev_failure_id_valid(upper)); lower[63]=0;"
            " HF_CHECK(!dev_failure_id_valid(lower));\n"
            " #undef HF_CHECK\n"
            " snprintf(out->exercised_surface,sizeof(out->exercised_surface),\"%s\");"
            " snprintf(out->detail,sizeof(out->detail),\"checks=%%u/%%u\","
            " out->checks_passed,out->checks_run);"
            " return out->checks_run==17 && out->checks_passed==17; }\n",
            source_path, def->exercised_surface);
    }
    return snprintf(out, out_size,
        "#define _GNU_SOURCE\n"
        "#include \"hotswap/hotfork_capsule.h\"\n"
        "#include \"%s\"\n"
        "__attribute__((visibility(\"hidden\")))\n"
        "bool zcl_hotfork_candidate_story_v1(struct zcl_hotfork_observation_v1 *out) {\n"
        " static const char *const expected[] = {\"ok\",\"null-argument\","
        "\"package-incomplete\",\"package-manifest\",\"source-carrier-shape\","
        "\"package-chunk\",\"source-verification\",\"destination\"};\n"
        " if (!out) { return false; } memset(out,0,sizeof(*out));"
        " out->magic=ZCL_HOTFORK_OBSERVATION_MAGIC;\n"
        " for (unsigned i=0;i<8;i++) { out->checks_run++;"
        " if (strcmp(vcs_source_package_checkout_result_string("
        "(enum vcs_source_package_checkout_result)i),expected[i])==0)"
        " out->checks_passed++; }\n"
        " uint16_t shard=0; out->checks_run++;"
        " if (source_checkout_shard_index(\"zclassic23-source/shard-0a.zvss\",&shard)"
        " && shard==10) out->checks_passed++;\n"
        " out->checks_run++; if (source_checkout_shard_index("
        "\"zclassic23-source/shard-ff.zvss\",&shard) && shard==255)"
        " out->checks_passed++;\n"
        " static const char *const bad[]={\"zclassic23-source/shard-0A.zvss\","
        "\"zclassic23-source/shard-100.zvss\",\"zclassic23-source/shard-0a\"};\n"
        " for(unsigned i=0;i<3;i++){out->checks_run++;"
        " if(!source_checkout_shard_index(bad[i],&shard))out->checks_passed++;}\n"
        " snprintf(out->exercised_surface,sizeof(out->exercised_surface),"
        "\"%s\"); snprintf(out->detail,sizeof(out->detail),"
        "\"checks=%%u/%%u\",out->checks_passed,out->checks_run);"
        " return out->checks_run==13 && out->checks_passed==13; }\n",
        source_path, def->exercised_surface);
}

static bool hs_hotfork_build(
    const char *repo_root, const struct hs_hotfork_def *def,
    struct zcl_devloop_hotswap_build_receipt *receipt,
    struct zcl_devloop_process_result *process, char *why, size_t why_len)
{
    int64_t started = platform_time_monotonic_us();
    memset(receipt, 0, sizeof(*receipt));
    memset(process, 0, sizeof(*process));
    char root[PATH_MAX], source_path[PATH_MAX];
    if (!repo_root || !def || !realpath(repo_root, root) ||
        strpbrk(root, "\"\\") ||
        snprintf(source_path, sizeof(source_path), "%s/%s", root,
                 def->source_tu) >= (int)sizeof(source_path) ||
        !hs_regular(source_path, NULL)) {
        hs_why(why, why_len, "HOT_FORK source is not a confined regular file");
        return false;
    }
    struct hs_action_plan plan = {0};
    pthread_mutex_lock(&g_plan_mu);
    bool plan_ok = hs_plan_load_locked(root, &receipt->plan_cache_hit,
                                       &receipt->plan_load_us, why, why_len);
    if (plan_ok) plan = g_plan;
    pthread_mutex_unlock(&g_plan_mu);
    if (!plan_ok) return false;

    char safe[256], key_owner[384];
    size_t source_len = strlen(def->source_tu);
    if (source_len >= sizeof(safe)) {
        hs_why(why, why_len, "HOT_FORK owner exceeds identity bound");
        return false;
    }
    for (size_t i = 0; i <= source_len; i++) {
        unsigned char c = (unsigned char)def->source_tu[i];
        safe[i] = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                  (c >= '0' && c <= '9') || c == '.' || c == '-'
            ? (char)c : c ? '_' : 0;
    }
    char cached_dep[PATH_MAX], unity[PATH_MAX] = {0}, descriptor[PATH_MAX] = {0};
    char candidate_obj[PATH_MAX] = {0}, descriptor_obj[PATH_MAX] = {0};
    char dep[PATH_MAX] = {0}, descriptor_dep[PATH_MAX] = {0};
    char version_script[PATH_MAX] = {0}, so[PATH_MAX] = {0};
    char cache_root[PATH_MAX] = {0}, cache_obj[PATH_MAX] = {0};
    char cache_so[PATH_MAX] = {0}, cache_hash[PATH_MAX] = {0};
    int cache_fd = -1;
    if (!hs_temp(unity, sizeof(unity), root, ".c") ||
        !hs_temp(descriptor, sizeof(descriptor), root, ".c") ||
        !hs_temp(candidate_obj, sizeof(candidate_obj), root, ".o") ||
        !hs_temp(descriptor_obj, sizeof(descriptor_obj), root, ".o") ||
        !hs_temp(dep, sizeof(dep), root, ".d") ||
        !hs_temp(descriptor_dep, sizeof(descriptor_dep), root, ".d") ||
        !hs_temp(version_script, sizeof(version_script), root, ".map") ||
        !hs_temp(so, sizeof(so), root, ".so")) {
        hs_why(why, why_len, "could not allocate HOT_FORK build inputs");
        goto fail;
    }
    char unity_text[8192];
    int unity_n = hs_hotfork_unity_source(
        def, source_path, unity_text, sizeof(unity_text));
    if (unity_n <= 0 || unity_n >= (int)sizeof(unity_text) ||
        !hs_write_generated(unity, unity_text, why, why_len))
        goto fail;
    char adapter_root[65];
    hs_sha3_root(unity_text, adapter_root);
    if (snprintf(key_owner, sizeof(key_owner), "HOT_FORK:%s:%s",
                 def->source_tu, adapter_root) >= (int)sizeof(key_owner) ||
        snprintf(cached_dep, sizeof(cached_dep),
                 "%s/build/hotswap/fast/%s-%s.hotfork.d", root, safe,
                 adapter_root) >= (int)sizeof(cached_dep)) {
        hs_why(why, why_len, "HOT_FORK adapter identity exceeds bound");
        goto fail;
    }

    struct hs_dep *before = zcl_malloc(sizeof(*before) * HS_DEP_MAX,
                                       "HOT_FORK dependency baseline");
    struct hs_dep *after = zcl_malloc(sizeof(*after) * HS_DEP_MAX,
                                      "HOT_FORK dependency result");
    if (!before || !after) {
        free(before); free(after);
        hs_why(why, why_len, "HOT_FORK dependency allocation failed");
        goto fail;
    }
    size_t before_n = 0, after_n = 0;
    bool have_baseline = hs_depfile_read(root, cached_dep, before, &before_n,
                                         true);
    if (have_baseline &&
        hs_cache_key(&plan, root, key_owner, before, before_n,
                     receipt->artifact_cache_key) &&
        hs_cache_root_for("hotfork-v1", cache_root)) {
        cache_fd = hs_cache_lock(cache_root, receipt->artifact_cache_key,
                                 cache_obj, cache_so, cache_hash);
        if (cache_fd >= 0 &&
            hs_cache_lookup(root, safe, cache_obj, cache_so, cache_hash,
                            receipt)) {
            receipt->artifact_cache_hit = true;
            receipt->dependency_count = (uint32_t)before_n;
            (void)snprintf(receipt->source_tu, sizeof(receipt->source_tu),
                           "%s", def->source_tu);
            receipt->total_us = platform_time_monotonic_us() - started;
            free(before); free(after);
            goto success;
        }
        if (cache_fd >= 0) {
            (void)unlink(cache_obj); (void)unlink(cache_so);
            (void)unlink(cache_hash);
        }
    }
    receipt->compiler_processes = 1;
    if (!hs_run_hotfork_compile(&plan, root, unity, candidate_obj, dep,
                                process, &receipt->compile_us,
                                why, why_len) ||
        !hs_depfile_read(root, dep, after, &after_n, true)) {
        free(before); free(after);
        goto fail;
    }
    /* A newly declared owner has no dependency baseline yet. Discover the
     * exact closure once, snapshot it, then compile again inside this same
     * bounded action. The second pass is the proof that no dependency moved
     * while the accepted candidate object was produced; requiring a human or
     * agent to save identical bytes twice is neither a safety property nor a
     * useful first-edit experience. */
    if (!have_baseline) {
        memcpy(before, after, after_n * sizeof(*after));
        before_n = after_n;
        if (!hs_cache_key(&plan, root, key_owner, before, before_n,
                          receipt->artifact_cache_key) ||
            !hs_cache_root_for("hotfork-v1", cache_root)) {
            free(before); free(after);
            hs_why(why, why_len,
                   "could not bind cold HOT_FORK dependency closure");
            goto fail;
        }
        cache_fd = hs_cache_lock(cache_root, receipt->artifact_cache_key,
                                 cache_obj, cache_so, cache_hash);
        if (cache_fd >= 0 &&
            hs_cache_lookup(root, safe, cache_obj, cache_so, cache_hash,
                            receipt)) {
            receipt->artifact_cache_hit = true;
            receipt->dependency_count = (uint32_t)before_n;
            (void)unlink(cached_dep);
            if (rename(dep, cached_dep) != 0) {
                free(before); free(after);
                hs_why(why, why_len,
                       "could not publish cold HOT_FORK dependency baseline");
                goto fail;
            }
            dep[0] = 0;
            (void)snprintf(receipt->source_tu, sizeof(receipt->source_tu),
                           "%s", def->source_tu);
            receipt->total_us = platform_time_monotonic_us() - started;
            free(before); free(after);
            goto success;
        }
        if (cache_fd >= 0) {
            (void)unlink(cache_obj); (void)unlink(cache_so);
            (void)unlink(cache_hash);
        }
        int64_t stable_compile_us = 0;
        receipt->compiler_processes++;
        if (!hs_run_hotfork_compile(&plan, root, unity, candidate_obj, dep,
                                    process, &stable_compile_us,
                                    why, why_len) ||
            !hs_depfile_read(root, dep, after, &after_n, true)) {
            free(before); free(after);
            goto fail;
        }
        receipt->compile_us += stable_compile_us;
    }
    (void)unlink(cached_dep);
    if (rename(dep, cached_dep) != 0) {
        free(before); free(after);
        hs_why(why, why_len, "could not publish HOT_FORK dependency baseline");
        goto fail;
    }
    dep[0] = 0;
    receipt->dependency_count = (uint32_t)after_n;
    bool stable = hs_deps_unchanged(before, before_n, after, after_n,
                                    why, why_len);
    char post_key[65] = {0};
    if (stable && receipt->artifact_cache_key[0] &&
        (!hs_cache_key(&plan, root, key_owner, after, after_n, post_key) ||
         strcmp(post_key, receipt->artifact_cache_key) != 0))
        stable = false;
    free(before); free(after);
    if (!stable) {
        goto fail;
    }
    if (!hs_sha256_file(candidate_obj, receipt->candidate_object_sha256)) {
        hs_why(why, why_len, "could not hash HOT_FORK candidate object");
        goto fail;
    }
    char story_root[65], fixture_root[65];
    hs_hotfork_story_roots(def, story_root, fixture_root);
    char descriptor_text[4096];
    int descriptor_n = snprintf(descriptor_text, sizeof(descriptor_text),
        "#include \"hotswap/hotfork_capsule.h\"\n"
        "extern bool zcl_hotfork_candidate_story_v1("
        "struct zcl_hotfork_observation_v1 *);\n"
        "__attribute__((visibility(\"default\"))) const struct "
        "zcl_hotfork_capsule_v1 zcl_hotfork_capsule_v1={"
        ".abi_version=ZCL_HOTFORK_CAPSULE_ABI_V1,"
        ".descriptor_size=sizeof(struct zcl_hotfork_capsule_v1),"
        ".owner_id=\"%s\",.source_tu=\"%s\","
        ".candidate_object_root=\"%s\",.story_id=\"%s\","
        ".story_root=\"%s\",.story_fixture_root=\"%s\","
        ".run_story=zcl_hotfork_candidate_story_v1};\n",
        def->owner_id, def->source_tu, receipt->candidate_object_sha256,
        def->story_id, story_root, fixture_root);
    static const char map_text[] =
        "ZCL_HOTFORK_1 { global: zcl_hotfork_capsule_v1; local: *; };\n";
    int64_t descriptor_compile_us = 0;
    if (descriptor_n <= 0 || descriptor_n >= (int)sizeof(descriptor_text) ||
        !hs_write_generated(descriptor, descriptor_text, why, why_len) ||
        !hs_write_generated(version_script, map_text, why, why_len) ||
        !hs_run_hotfork_compile(&plan, root, descriptor, descriptor_obj,
                                descriptor_dep, process,
                                &descriptor_compile_us, why, why_len))
        goto fail;
    receipt->compile_us += descriptor_compile_us;
    receipt->compiler_processes++;
    receipt->linker_processes = 1;
    if (!hs_run_hotfork_link(&plan, root, candidate_obj, descriptor_obj,
                             version_script, so, process, &receipt->link_us,
                             why, why_len) ||
        !hs_sha256_file(so, receipt->artifact_sha256))
        goto fail;
    int64_t publish_started = platform_time_monotonic_us();
    if (cache_fd >= 0 &&
        !hs_cache_publish(cache_obj, cache_so, cache_hash, candidate_obj,
                          receipt->candidate_object_sha256, so,
                          receipt->artifact_sha256)) {
        hs_why(why, why_len, "HOT_FORK cache publication failed");
        goto fail;
    }
    const char *published = cache_fd >= 0 ? cache_so : so;
    if (!hs_publish_artifact_path(root, safe, published,
                                  receipt->artifact_sha256,
                                  receipt->artifact_path)) {
        hs_why(why, why_len, "HOT_FORK artifact publication failed");
        goto fail;
    }
    receipt->publish_us = platform_time_monotonic_us() - publish_started;
    (void)snprintf(receipt->source_tu, sizeof(receipt->source_tu), "%s",
                   def->source_tu);
    receipt->total_us = platform_time_monotonic_us() - started;

success:
    if (cache_fd >= 0) {
        (void)flock(cache_fd, LOCK_UN); (void)close(cache_fd);
    }
    (void)unlink(unity); (void)unlink(descriptor);
    (void)unlink(candidate_obj); (void)unlink(descriptor_obj);
    if (dep[0]) (void)unlink(dep);
    (void)unlink(descriptor_dep); (void)unlink(version_script); (void)unlink(so);
    return true;

fail:
    if (cache_fd >= 0) {
        (void)flock(cache_fd, LOCK_UN); (void)close(cache_fd);
    }
    if (unity[0]) (void)unlink(unity);
    if (descriptor[0]) (void)unlink(descriptor);
    if (candidate_obj[0]) (void)unlink(candidate_obj);
    if (descriptor_obj[0]) (void)unlink(descriptor_obj);
    if (dep[0]) (void)unlink(dep);
    if (descriptor_dep[0]) (void)unlink(descriptor_dep);
    if (version_script[0]) (void)unlink(version_script);
    if (so[0]) (void)unlink(so);
    receipt->total_us = platform_time_monotonic_us() - started;
    return false;
}

static void hs_json_text_preview(const char *input, char out[1025])
{
    size_t n = input ? strlen(input) : 0;
    if (n > 1024) n = 1024;
    if (n) memcpy(out, input, n);
    out[n] = 0;
}

static bool hs_resident_call(const char *artifact, bool activate,
                             struct json_value *response, int64_t *elapsed_us,
                             char *why, size_t why_len)
{
    const char *home = getenv("HOME");
    char datadir[PATH_MAX];
    if (!home || !home[0] ||
        snprintf(datadir, sizeof(datadir), "%s/.zclassic-c23-dev", home) >=
            (int)sizeof(datadir)) {
        hs_why(why, why_len, "HOME cannot resolve the isolated dev datadir");
        return false;
    }
    node_rpc_client_init(datadir, 18252);
    struct json_value params, path, flag;
    json_init(&params);
    json_set_array(&params);
    json_init(&path);
    json_set_str(&path, artifact);
    (void)json_push_back(&params, &path);
    json_free(&path);
    json_init(&flag);
    json_set_bool(&flag, activate);
    (void)json_push_back(&params, &flag);
    json_free(&flag);
    char params_json[PATH_MAX + 64];
    size_t params_n = json_write(&params, params_json, sizeof(params_json));
    json_free(&params);
    if (!params_n) {
        hs_why(why, why_len, "resident activation request exceeded its bound");
        return false;
    }
    int64_t started = platform_time_monotonic_us();
    char *raw = node_rpc_call("dev_hotswap_native", params_json);
    *elapsed_us = platform_time_monotonic_us() - started;
    if (!raw) {
        hs_why(why, why_len, "resident dev node returned no activation body");
        return false;
    }
    json_init(response);
    bool parsed = json_read(response, raw, strlen(raw)) &&
                  response->type == JSON_OBJ;
    free(raw);
    if (!parsed) {
        json_free(response);
        hs_why(why, why_len, "resident dev node returned malformed activation JSON");
        return false;
    }
    const struct json_value *ok_v = json_get(response, "ok");
    if (!ok_v || ok_v->type != JSON_BOOL || !json_get_bool(ok_v)) {
        char response_error[512];
        if (zcl_devloop_hotswap_response_error(
                response, response_error, sizeof(response_error)))
            hs_why(why, why_len, response_error);
        else
            hs_why(why, why_len, "resident refused the candidate");
        return false;
    }
    const struct json_value *activated_v = json_get(response, "activated");
    if (activate && (!activated_v || activated_v->type != JSON_BOOL ||
                     !json_get_bool(activated_v))) {
        hs_why(why, why_len,
               "resident verified but did not activate the candidate");
        return false;
    }
    return true;
}

struct hs_shadow_wire {
    uint32_t magic;
    char runtime_module_sha256[65];
    struct zcl_hotswap_service_report report;
};

#define HS_SHADOW_WIRE_MAGIC UINT32_C(0x48535331)

/* The watcher itself is the persistent shadow parent: contracts, registry,
 * dependency state, and immutable fixtures are already resident. Each
 * candidate gets a disposable fork, maps only the tiny service .so, runs the
 * resident-frozen KAT, reports one fixed-size result, and exits. No exec, RPC,
 * node, wallet, SQLite, network, publication, or full-program link exists on
 * this path. */
static void hs_sha3_root(const char *text, char out[65])
{
    uint8_t digest[32];
    sha3_256((const uint8_t *)text, strlen(text), digest);
    zcl_hex_encode(digest, sizeof(digest), out);
}

static bool hs_shadow_probe(
                            const char *source,
                            const struct zcl_devloop_hotswap_build_receipt *build,
                            struct json_value *response,
                            int64_t *elapsed_us,
                            char *why, size_t why_len)
{
    int pipefd[2] = {-1, -1};
    int64_t started = platform_time_monotonic_us();
    const char *artifact = build ? build->artifact_path : NULL;
    const char *story_id = source
        ? zcl_hotswap_service_probe_for_source(source) : NULL;
    if (!source || !story_id || !story_id[0] || !build ||
        strlen(build->candidate_object_sha256) != 64 ||
        strlen(build->artifact_sha256) != 64 || !artifact || !response ||
        !elapsed_us ||
        pipe2(pipefd, O_CLOEXEC | O_NONBLOCK) != 0) {
        hs_why(why, why_len, "shadow runner pipe unavailable");
        return false;
    }
    pid_t child = fork();
    if (child < 0) {
        close(pipefd[0]); close(pipefd[1]);
        hs_why(why, why_len, "shadow runner fork unavailable");
        return false;
    }
    if (child == 0) {
        close(pipefd[0]);
        struct hs_shadow_wire wire = {.magic = HS_SHADOW_WIRE_MAGIC};
        if (hs_sha256_file(artifact, wire.runtime_module_sha256))
            (void)zcl_native_hotswap_service_probe_local(
                artifact, &wire.report);
        const uint8_t *p = (const uint8_t *)&wire;
        size_t left = sizeof(wire);
        while (left > 0) {
            ssize_t wrote = write(pipefd[1], p, left);
            if (wrote > 0) {
                p += (size_t)wrote;
                left -= (size_t)wrote;
            } else if (wrote < 0 && errno == EINTR) {
                continue;
            } else {
                break;
            }
        }
        close(pipefd[1]);
        _exit(left == 0 ? 0 : 125);
    }
    close(pipefd[1]);
    struct hs_shadow_wire wire;
    memset(&wire, 0, sizeof(wire));
    uint8_t *dst = (uint8_t *)&wire;
    size_t have = 0;
    bool timed_out = false, cancelled = false;
    const int64_t deadline = started + 1000000;
    while (have < sizeof(wire)) {
        if (zcl_devloop_process_cancel_requested()) {
            cancelled = true;
            break;
        }
        int64_t remaining = deadline - platform_time_monotonic_us();
        if (remaining <= 0) {
            timed_out = true;
            break;
        }
        int wait_ms = remaining > 10000 ? 10 : (int)((remaining + 999) / 1000);
        struct pollfd pfd = {.fd = pipefd[0], .events = POLLIN | POLLHUP};
        int ready = poll(&pfd, 1, wait_ms);
        if (ready < 0 && errno == EINTR) continue;
        if (ready < 0) break;
        if (ready == 0) continue;
        ssize_t got = read(pipefd[0], dst + have, sizeof(wire) - have);
        if (got > 0) have += (size_t)got;
        else if (got == 0) break;
        else if (errno != EAGAIN && errno != EINTR) break;
    }
    close(pipefd[0]);
    if (timed_out || cancelled || have != sizeof(wire))
        (void)kill(child, SIGKILL);
    int status = 0;
    pid_t waited;
    do {
        waited = waitpid(child, &status, 0);
    } while (waited < 0 && errno == EINTR);
    *elapsed_us = platform_time_monotonic_us() - started;
    bool valid = waited == child && !timed_out && !cancelled &&
        have == sizeof(wire) &&
        wire.magic == HS_SHADOW_WIRE_MAGIC && WIFEXITED(status) &&
        WEXITSTATUS(status) == 0 &&
        strcmp(wire.runtime_module_sha256, build->artifact_sha256) == 0;
    bool ok = valid && wire.report.recognized && wire.report.ok &&
        wire.report.verify_only && wire.report.probed &&
        !wire.report.activated;
    json_init(response); json_set_object(response);
    char story_preimage[768], fixture_preimage[512], observation[768];
    char story_root[65] = {0}, fixture_root[65] = {0};
    char observation_root[65] = {0};
    int story_n = snprintf(story_preimage, sizeof(story_preimage),
        "zcl.dev.story.v1\n%s\n%s\n%s\n", source, story_id,
        valid ? wire.report.service_id : "invalid");
    int fixture_n = snprintf(fixture_preimage, sizeof(fixture_preimage),
        "zcl.dev.story.fixture.v1\n%s\n%s\n", story_id,
        valid ? wire.report.service_id : "invalid");
    int observation_n = snprintf(observation, sizeof(observation),
        "zcl.dev.story.observation.v1\n%s\n%s\n%d\n%d\n%d\n%d\n%s\n",
        valid ? wire.report.service_id : "invalid",
        valid ? wire.report.stage : "invalid", wire.report.recognized,
        wire.report.ok, wire.report.verify_only, wire.report.probed,
        wire.runtime_module_sha256);
    if (story_n <= 0 || story_n >= (int)sizeof(story_preimage) ||
        fixture_n <= 0 || fixture_n >= (int)sizeof(fixture_preimage) ||
        observation_n <= 0 || observation_n >= (int)sizeof(observation))
        ok = false;
    else {
        hs_sha3_root(story_preimage, story_root);
        hs_sha3_root(fixture_preimage, fixture_root);
        hs_sha3_root(observation, observation_root);
    }
    (void)json_push_kv_str(response, "schema", "zcl.dev_shadow_story.v2");
    (void)json_push_kv_str(response, "mode", "HOT_SHADOW_CORE");
    (void)json_push_kv_str(response, "feedback_class", "HOT_SHADOW_CORE");
    (void)json_push_kv_str(response, "status", ok ? "green" : "red");
    (void)json_push_kv_bool(response, "forked", true);
    (void)json_push_kv_bool(response, "exec_process", false);
    (void)json_push_kv_bool(response, "activated", false);
    (void)json_push_kv_bool(response, "forbidden_effects_absent", true);
    (void)json_push_kv_str(response, "candidate_object_root",
                           build->candidate_object_sha256);
    (void)json_push_kv_str(response, "candidate_module_root",
                           build->artifact_sha256);
    (void)json_push_kv_bool(response, "candidate_bytes_executed",
                            valid && wire.report.recognized);
    (void)json_push_kv_str(response, "story_id", story_id);
    (void)json_push_kv_str(response, "story_root", story_root);
    (void)json_push_kv_str(response, "story_fixture_root", fixture_root);
    (void)json_push_kv_str(response, "observation_root", observation_root);
    (void)json_push_kv_str(response, "exercised_owner_surface", source);
    (void)json_push_kv_int(response, "elapsed_us", *elapsed_us);
    if (valid) {
        (void)json_push_kv_str(response, "service_id",
                               wire.report.service_id);
        (void)json_push_kv_str(response, "probe_stage", wire.report.stage);
    }
    if (!ok) {
        const char *message = cancelled ? "shadow story superseded" :
            timed_out ? "shadow story exceeded 1000 ms" :
            valid && wire.report.error[0] ? wire.report.error :
            "shadow story worker returned no valid frozen-KAT receipt";
        hs_why(why, why_len, message);
        (void)json_push_kv_str(response, "error", message);
    }
    return ok;
}

struct hs_hotfork_wire {
    uint32_t magic;
    bool descriptor_valid;
    bool sandboxed;
    bool candidate_executed;
    bool story_ok;
    char runtime_module_sha256[65];
    struct zcl_hotfork_observation_v1 observation;
};

#define HS_HOTFORK_WIRE_MAGIC UINT32_C(0x48465731)

static bool hs_hotfork_descriptor_matches(
    const struct zcl_hotfork_capsule_v1 *capsule,
    const struct hs_hotfork_def *def,
    const struct zcl_devloop_hotswap_build_receipt *build)
{
    char story_root[65], fixture_root[65];
    hs_hotfork_story_roots(def, story_root, fixture_root);
    return capsule && capsule->abi_version == ZCL_HOTFORK_CAPSULE_ABI_V1 &&
        capsule->descriptor_size == sizeof(*capsule) && capsule->owner_id &&
        strcmp(capsule->owner_id, def->owner_id) == 0 && capsule->source_tu &&
        strcmp(capsule->source_tu, def->source_tu) == 0 &&
        capsule->candidate_object_root &&
        strcmp(capsule->candidate_object_root,
               build->candidate_object_sha256) == 0 && capsule->story_id &&
        strcmp(capsule->story_id, def->story_id) == 0 &&
        capsule->story_root && strcmp(capsule->story_root, story_root) == 0 &&
        capsule->story_fixture_root &&
        strcmp(capsule->story_fixture_root, fixture_root) == 0 &&
        capsule->run_story;
}

bool zcl_devloop_hotfork_descriptor_validate(
    const char *source_tu, const char *candidate_object_root,
    const struct zcl_hotfork_capsule_v1 *capsule)
{
    const struct hs_hotfork_def *def = hs_hotfork_for_path(source_tu);
    struct zcl_devloop_hotswap_build_receipt receipt = {0};
    if (!def || !hs_lower_hex64(candidate_object_root)) return false;
    (void)snprintf(receipt.candidate_object_sha256,
                   sizeof(receipt.candidate_object_sha256), "%s",
                   candidate_object_root);
    return hs_hotfork_descriptor_matches(capsule, def, &receipt);
}

static bool hs_hotfork_child_confine(int report_fd)
{
    long max_fd = sysconf(_SC_OPEN_MAX);
    if (max_fd < 0 || max_fd > 65536) max_fd = 4096;
    for (int fd = 0; fd < (int)max_fd; fd++)
        if (fd != report_fd) (void)close(fd);
    if (!os_sandbox_no_new_privs()) return false;
    struct zcl_result landlock = os_sandbox_landlock_restrict(NULL, 0);
    if (!landlock.ok) return false;
    size_t denied_count = 0;
    const int *denied = os_sandbox_session_denied_syscalls(&denied_count);
    struct zcl_result seccomp =
        os_sandbox_seccomp_deny(denied, denied_count, true);
    return seccomp.ok;
}

struct hs_hotfork_visit_ctx {
    const struct hs_hotfork_def *def;
    const struct zcl_devloop_hotswap_build_receipt *build;
    struct hs_hotfork_wire *wire;
    int report_fd;
};

static bool hs_hotfork_visit(
    const struct zcl_hotfork_capsule_v1 *capsule, void *opaque)
{
    struct hs_hotfork_visit_ctx *ctx = opaque;
    ctx->wire->descriptor_valid =
        hs_hotfork_descriptor_matches(capsule, ctx->def, ctx->build);
    if (!ctx->wire->descriptor_valid)
        return false;
    ctx->wire->sandboxed = hs_hotfork_child_confine(ctx->report_fd);
    if (!ctx->wire->sandboxed)
        return false;
    ctx->wire->candidate_executed = true;
    ctx->wire->story_ok = capsule->run_story(&ctx->wire->observation);
    return ctx->wire->story_ok;
}

static bool hs_hotfork_probe(
    const struct hs_hotfork_def *def,
    const struct zcl_devloop_hotswap_build_receipt *build,
    struct json_value *response, int64_t *elapsed_us,
    char *why, size_t why_len)
{
    int pipefd[2] = {-1, -1};
    int64_t started = platform_time_monotonic_us();
    if (!def || !build || !response || !elapsed_us ||
        pipe2(pipefd, O_CLOEXEC | O_NONBLOCK) != 0) {
        hs_why(why, why_len, "HOT_FORK report pipe unavailable");
        return false;
    }
    pid_t child = fork();
    if (child < 0) {
        close(pipefd[0]); close(pipefd[1]);
        hs_why(why, why_len, "HOT_FORK child unavailable");
        return false;
    }
    if (child == 0) {
        close(pipefd[0]);
        struct hs_hotfork_wire wire = {.magic = HS_HOTFORK_WIRE_MAGIC};
        struct hs_hotfork_visit_ctx visit = {
            .def = def, .build = build, .wire = &wire,
            .report_fd = pipefd[1],
        };
        (void)zcl_hotswap_hotfork_visit_so(
            build->artifact_path, build->artifact_sha256,
            hs_hotfork_visit, &visit, wire.runtime_module_sha256);
        const uint8_t *cursor = (const uint8_t *)&wire;
        size_t left = sizeof(wire);
        while (left > 0) {
            ssize_t wrote = write(pipefd[1], cursor, left);
            if (wrote > 0) {
                cursor += (size_t)wrote; left -= (size_t)wrote;
            } else if (wrote < 0 && errno == EINTR) {
                continue;
            } else break;
        }
        _exit(left == 0 ? 0 : 125);
    }
    close(pipefd[1]);
    struct hs_hotfork_wire wire = {0};
    uint8_t *dst = (uint8_t *)&wire;
    size_t have = 0;
    bool timed_out = false, cancelled = false;
    const int64_t deadline = started + (int64_t)def->max_time_ms * 1000;
    while (have < sizeof(wire)) {
        if (zcl_devloop_process_cancel_requested()) {
            cancelled = true; break;
        }
        int64_t remaining = deadline - platform_time_monotonic_us();
        if (remaining <= 0) { timed_out = true; break; }
        struct pollfd pfd = {.fd = pipefd[0], .events = POLLIN | POLLHUP};
        int wait_ms = remaining > 10000 ? 10 : (int)((remaining + 999) / 1000);
        int ready = poll(&pfd, 1, wait_ms);
        if (ready < 0 && errno == EINTR) continue;
        if (ready < 0) break;
        if (ready == 0) continue;
        ssize_t got = read(pipefd[0], dst + have, sizeof(wire) - have);
        if (got > 0) have += (size_t)got;
        else if (got == 0) break;
        else if (errno != EAGAIN && errno != EINTR) break;
    }
    close(pipefd[0]);
    if (timed_out || cancelled || have != sizeof(wire))
        (void)kill(child, SIGKILL);
    int status = 0;
    pid_t waited;
    do { waited = waitpid(child, &status, 0); }
    while (waited < 0 && errno == EINTR);
    *elapsed_us = platform_time_monotonic_us() - started;
    int child_signal = waited == child && WIFSIGNALED(status)
        ? WTERMSIG(status) : 0;
    int child_exit_code = waited == child && WIFEXITED(status)
        ? WEXITSTATUS(status) : -1;
    bool valid = waited == child && WIFEXITED(status) &&
        WEXITSTATUS(status) == 0 && !timed_out && !cancelled &&
        have == sizeof(wire) && wire.magic == HS_HOTFORK_WIRE_MAGIC &&
        strcmp(wire.runtime_module_sha256, build->artifact_sha256) == 0;
    bool ok = valid && wire.descriptor_valid && wire.sandboxed &&
        wire.candidate_executed && wire.story_ok &&
        wire.observation.magic == ZCL_HOTFORK_OBSERVATION_MAGIC &&
        wire.observation.checks_run > 0 &&
        wire.observation.checks_run == wire.observation.checks_passed &&
        strcmp(wire.observation.exercised_surface,
               def->exercised_surface) == 0;
    char story_root[65], fixture_root[65], observation_root[65];
    hs_hotfork_story_roots(def, story_root, fixture_root);
    char observation[768];
    (void)snprintf(observation, sizeof(observation),
        "zcl.dev.hotfork.observation.v1\n%s\n%u\n%u\n%s\n%s\n",
        def->owner_id, wire.observation.checks_run,
        wire.observation.checks_passed,
        wire.observation.exercised_surface, wire.observation.detail);
    hs_sha3_root(observation, observation_root);
    json_init(response); json_set_object(response);
    (void)json_push_kv_str(response, "schema", "zcl.dev_hotfork_story.v1");
    (void)json_push_kv_str(response, "mode", "HOT_FORK");
    (void)json_push_kv_str(response, "feedback_class", def->feedback_class);
    (void)json_push_kv_str(response, "status", ok ? "green" : "red");
    (void)json_push_kv_bool(response, "forked", true);
    (void)json_push_kv_bool(response, "activated", false);
    (void)json_push_kv_bool(response, "sandboxed", wire.sandboxed);
    (void)json_push_kv_bool(response, "network_blocked", wire.sandboxed);
    (void)json_push_kv_bool(response, "datadir_blocked", wire.sandboxed);
    (void)json_push_kv_bool(response, "forbidden_effects_absent", ok);
    (void)json_push_kv_str(response, "candidate_object_root",
                           build->candidate_object_sha256);
    (void)json_push_kv_str(response, "candidate_module_root",
                           build->artifact_sha256);
    (void)json_push_kv_str(response, "loaded_mapping_root",
                           wire.runtime_module_sha256);
    (void)json_push_kv_bool(response, "candidate_bytes_executed",
                            wire.candidate_executed);
    (void)json_push_kv_str(response, "story_id", def->story_id);
    (void)json_push_kv_str(response, "story_fixture_id", def->fixture_id);
    (void)json_push_kv_str(response, "story_adapter", def->adapter_id);
    (void)json_push_kv_int(response, "story_timeout_ms", def->max_time_ms);
    (void)json_push_kv_str(response, "forbidden_effect_mask",
                           def->forbidden_effect_mask);
    (void)json_push_kv_str(response, "story_root", story_root);
    (void)json_push_kv_str(response, "story_fixture_root", fixture_root);
    (void)json_push_kv_str(response, "observation_root", observation_root);
    (void)json_push_kv_str(response, "exercised_owner_surface",
                           def->exercised_surface);
    (void)json_push_kv_int(response, "story_checks_run",
                           wire.observation.checks_run);
    (void)json_push_kv_int(response, "story_checks_passed",
                           wire.observation.checks_passed);
    (void)json_push_kv_str(response, "story_detail",
                           wire.observation.detail);
    (void)json_push_kv_int(response, "elapsed_us", *elapsed_us);
    (void)json_push_kv_int(response, "child_signal", child_signal);
    (void)json_push_kv_int(response, "child_exit_code", child_exit_code);
    if (!ok) {
        char timeout_message[96];
        char signal_message[96];
        char exit_message[96];
        (void)snprintf(timeout_message, sizeof(timeout_message),
                       "HOT_FORK story exceeded %u ms", def->max_time_ms);
        (void)snprintf(signal_message, sizeof(signal_message),
                       "HOT_FORK child terminated by signal %d", child_signal);
        (void)snprintf(exit_message, sizeof(exit_message),
                       "HOT_FORK child exited with code %d", child_exit_code);
        const char *message = cancelled ? "HOT_FORK story superseded" :
            timed_out ? timeout_message :
            child_signal ? signal_message :
            child_exit_code > 0 ? exit_message :
            !valid ? "HOT_FORK child returned no valid bounded receipt" :
            !wire.descriptor_valid ? "HOT_FORK descriptor binding mismatch" :
            !wire.sandboxed ? "HOT_FORK authority sandbox unavailable" :
            "HOT_FORK candidate story rejected its frozen fixture";
        hs_why(why, why_len, message);
        (void)json_push_kv_str(response, "error", message);
    }
    return ok;
}

static bool hs_story_receipt_valid(
    const char *source, const struct zcl_devloop_hotswap_build_receipt *build,
    const struct json_value *resident)
{
    if (!source || !build || !resident || resident->type != JSON_OBJ)
        return false;
    const char *schema = json_get_str(json_get(resident, "schema"));
    const char *feedback = json_get_str(json_get(resident, "feedback_class"));
    const char *object = json_get_str(json_get(resident,
                                               "candidate_object_root"));
    const char *module = json_get_str(json_get(resident,
                                               "candidate_module_root"));
    const char *loaded = json_get_str(json_get(resident,
                                               "loaded_mapping_root"));
    const char *story_id = json_get_str(json_get(resident, "story_id"));
    const char *story = json_get_str(json_get(resident, "story_root"));
    const char *fixture = json_get_str(json_get(resident,
                                                "story_fixture_root"));
    const char *observation = json_get_str(json_get(resident,
                                                    "observation_root"));
    const char *surface = json_get_str(json_get(resident,
                                                "exercised_owner_surface"));
    const char *fixture_id =
        json_get_str(json_get(resident, "story_fixture_id"));
    const char *adapter = json_get_str(json_get(resident, "story_adapter"));
    const char *forbidden =
        json_get_str(json_get(resident, "forbidden_effect_mask"));
    const struct hs_hotfork_def *hotfork = hs_hotfork_for_path(source);
    bool class_ok = feedback &&
        (strcmp(feedback, "HOT_SHADOW_CORE") == 0 ||
         strcmp(feedback, "HOT_FORK") == 0);
    bool surface_ok = surface && surface[0] && feedback &&
        (strcmp(feedback, "HOT_FORK") == 0 || strcmp(surface, source) == 0);
    bool schema_ok = schema &&
        (strcmp(schema, "zcl.dev_shadow_story.v2") == 0 ||
         strcmp(schema, "zcl.dev_hotfork_story.v1") == 0);
    bool manifest_ok = !feedback || strcmp(feedback, "HOT_FORK") != 0 ||
        (hotfork && fixture_id && adapter && forbidden && loaded && module &&
         strcmp(loaded, module) == 0 &&
         strcmp(fixture_id, hotfork->fixture_id) == 0 &&
         strcmp(adapter, hotfork->adapter_id) == 0 &&
         json_get_int(json_get(resident, "story_timeout_ms")) ==
             hotfork->max_time_ms &&
         strcmp(forbidden, hotfork->forbidden_effect_mask) == 0);
    return schema_ok && class_ok && manifest_ok &&
        object && strcmp(object, build->candidate_object_sha256) == 0 &&
        module && strcmp(module, build->artifact_sha256) == 0 &&
        story_id && story_id[0] && story && strlen(story) == 64 &&
        fixture && strlen(fixture) == 64 && observation &&
        strlen(observation) == 64 && surface_ok &&
        json_get_bool(json_get(resident, "candidate_bytes_executed")) &&
        json_get_bool(json_get(resident, "forbidden_effects_absent"));
}

static bool hs_proof_handoff(
    const char *source, size_t changed_path_count,
    const struct zcl_devloop_hotswap_build_receipt *build,
    const struct json_value *resident, struct json_value *out)
{
    const char *source_epoch = zcl_devloop_event_edit_epoch();
    if (!source || !source_epoch || strlen(source_epoch) != 64 || !build ||
        !build->artifact_sha256[0] || !resident || resident->type != JSON_OBJ ||
        !out || changed_path_count == 0 || changed_path_count > UINT32_MAX ||
        !hs_story_receipt_valid(source, build, resident))
        return false;
    const char *feedback_class =
        json_get_str(json_get(resident, "feedback_class"));
    const char *story_root = json_get_str(json_get(resident, "story_root"));
    const char *fixture_root =
        json_get_str(json_get(resident, "story_fixture_root"));
    const char *observation_root =
        json_get_str(json_get(resident, "observation_root"));
    char candidate_preimage[160];
    int candidate_n = snprintf(candidate_preimage, sizeof(candidate_preimage),
        "zcl.dev.candidate.v1\n%s\n", build->artifact_sha256);
    uint8_t digest[32];
    char candidate_epoch[65], evidence_sha3[65], inputs_sha3[65];
    if (candidate_n <= 0 || (size_t)candidate_n >= sizeof(candidate_preimage))
        return false;
    sha3_256((const uint8_t *)candidate_preimage, (size_t)candidate_n, digest);
    zcl_hex_encode(digest, sizeof(digest), candidate_epoch);
    char evidence[8192];
    size_t evidence_n = json_write(resident, evidence, sizeof(evidence));
    if (!evidence_n) return false;
    sha3_256((const uint8_t *)evidence, evidence_n, digest);
    zcl_hex_encode(digest, sizeof(digest), evidence_sha3);
    char inputs[768];
    int inputs_n = snprintf(inputs, sizeof(inputs),
        "zcl.dev.proof-inputs.v1\n%s\n%s\n%s\naffected_proof\n%zu\n",
        candidate_epoch, source_epoch, source, changed_path_count);
    if (inputs_n <= 0 || (size_t)inputs_n >= sizeof(inputs)) return false;
    sha3_256((const uint8_t *)inputs, (size_t)inputs_n, digest);
    zcl_hex_encode(digest, sizeof(digest), inputs_sha3);
    struct dev_reflex_proof_handoff_v2 handoff = {0};
    (void)snprintf(handoff.candidate_epoch,
                   sizeof(handoff.candidate_epoch), "%s", candidate_epoch);
    (void)snprintf(handoff.source_epoch, sizeof(handoff.source_epoch), "%s",
                   source_epoch);
    (void)snprintf(handoff.affected_component,
                   sizeof(handoff.affected_component), "%s", source);
    (void)snprintf(handoff.action, sizeof(handoff.action), "%s",
                   "affected_proof");
    (void)snprintf(handoff.proof_inputs_sha3,
                   sizeof(handoff.proof_inputs_sha3), "%s", inputs_sha3);
    (void)snprintf(handoff.focused_evidence_sha3,
                   sizeof(handoff.focused_evidence_sha3), "%s",
                   evidence_sha3);
    (void)snprintf(handoff.feedback_class,
                   sizeof(handoff.feedback_class), "%s", feedback_class);
    (void)snprintf(handoff.candidate_object_root,
                   sizeof(handoff.candidate_object_root), "%s",
                   build->candidate_object_sha256);
    (void)snprintf(handoff.candidate_module_root,
                   sizeof(handoff.candidate_module_root), "%s",
                   build->artifact_sha256);
    (void)snprintf(handoff.story_root, sizeof(handoff.story_root), "%s",
                   story_root);
    (void)snprintf(handoff.story_fixture_root,
                   sizeof(handoff.story_fixture_root), "%s", fixture_root);
    (void)snprintf(handoff.observation_root,
                   sizeof(handoff.observation_root), "%s", observation_root);
    handoff.affected_file_count = (uint32_t)changed_path_count;
    handoff.compile_green = true;
    handoff.story_obtained = true;
    char why[160] = {0};
    const struct dev_reflex_policy_service_v1 *policy =
        dev_reflex_policy_service_builtin();
    if (!policy->handoff_validate(&handoff, why, sizeof(why))) return false;
    json_init(out); json_set_object(out);
    return json_push_kv_str(out, "schema", "zcl.dev_proof_handoff.v2") &&
        json_push_kv_str(out, "candidate_epoch", handoff.candidate_epoch) &&
        json_push_kv_str(out, "source_epoch", handoff.source_epoch) &&
        json_push_kv_str(out, "affected_component",
                         handoff.affected_component) &&
        json_push_kv_str(out, "action", handoff.action) &&
        json_push_kv_str(out, "proof_inputs_sha3",
                         handoff.proof_inputs_sha3) &&
        json_push_kv_str(out, "focused_evidence_sha3",
                         handoff.focused_evidence_sha3) &&
        json_push_kv_str(out, "feedback_class", handoff.feedback_class) &&
        json_push_kv_str(out, "candidate_object_root",
                         handoff.candidate_object_root) &&
        json_push_kv_str(out, "candidate_module_root",
                         handoff.candidate_module_root) &&
        json_push_kv_str(out, "story_root", handoff.story_root) &&
        json_push_kv_str(out, "story_fixture_root",
                         handoff.story_fixture_root) &&
        json_push_kv_str(out, "observation_root",
                         handoff.observation_root) &&
        json_push_kv_int(out, "affected_file_count",
                         handoff.affected_file_count) &&
        json_push_kv_bool(out, "compile_green", true) &&
        json_push_kv_bool(out, "story_obtained", true) &&
        json_push_kv_bool(out, "reflex_final", true);
}

static bool hs_emit_event(const char *root, const char *source,
                          size_t changed_path_count,
                          const char *status, const char *phase,
                          bool published, int64_t elapsed_us,
                          const struct zcl_devloop_hotswap_build_receipt *build,
                          int64_t activation_us,
                          const struct json_value *resident,
                          const struct zcl_devloop_process_result *process,
                          const char *why, bool flush_after)
{
    struct json_value doc, receipt;
    json_init(&doc);
    json_set_object(&doc);
    (void)json_push_kv_str(&doc, "schema", "zcl.dev_cycle.v1");
    (void)json_push_kv_str(&doc, "producer", "resident-build-authority");
    (void)json_push_kv_str(&doc, "status", status);
    (void)json_push_kv_str(&doc, "action", "hotswap");
    const bool service_island =
        zcl_hotswap_service_source_for_path(source) != NULL;
    (void)json_push_kv_str(
        &doc, "reason", service_island
            ? (changed_path_count > 1 ? "single_service_island_batch"
                                      : "single_service_island")
            : (changed_path_count > 1 ? "single_stateless_island_batch"
                                      : "single_stateless_provider"));
    (void)json_push_kv_str(&doc, "phase",
                           zcl_devloop_progress_phase(status, phase));
    (void)json_push_kv_str(&doc, "stage_detail", phase);
    const char *resident_class = resident && resident->type == JSON_OBJ
        ? json_get_str(json_get(resident, "feedback_class")) : NULL;
    const char *feedback_class = resident_class && resident_class[0]
        ? resident_class : "COMPILE_ONLY";
    (void)json_push_kv_str(&doc, "feedback_class", feedback_class);
    if (zcl_devloop_event_edit_epoch()[0])
        (void)json_push_kv_str(&doc, "edit_epoch",
                               zcl_devloop_event_edit_epoch());
    (void)json_push_kv_bool(&doc, "runtime_published", published);
    (void)json_push_kv_int(&doc, "changed_path_count",
                           (int64_t)changed_path_count);
    (void)json_push_kv_bool(&doc, "atomic_batch_generation",
                            changed_path_count > 1 && published);
    (void)json_push_kv_int(&doc, "elapsed_us", elapsed_us);
    (void)json_push_kv_int(&doc, "elapsed_ms", elapsed_us / 1000);
    (void)json_push_kv_int(&doc, "make_processes", 0);
    (void)json_push_kv_int(&doc, "shell_processes", 0);
    (void)json_push_kv_int(&doc, "git_operations", 0);
    (void)json_push_kv_int(&doc, "publication_operations", 0);
    (void)json_push_kv_int(&doc, "remote_operations", 0);
    (void)json_push_kv_int(&doc, "network_operations", 0);
    (void)json_push_kv_int(&doc, "storage_ack_waits", 0);
    (void)json_push_kv_int(&doc, "full_program_links", 0);
    (void)json_push_kv_int(&doc, "sqlite_operations", 0);
    (void)json_push_kv_int(&doc, "full_tree_scans", 0);
    (void)json_push_kv_str(&doc, "source_tu", source);
    if (why && why[0])
        (void)json_push_kv_str(&doc, "failure_capsule", why);
    if (process && process->output_len) {
        char preview[1025];
        hs_json_text_preview(process->output, preview);
        (void)json_push_kv_str(&doc, "compiler_output", preview);
        (void)json_push_kv_bool(&doc, "compiler_output_truncated",
                                process->output_len > 1024 ||
                                process->output_truncated);
    }
    if (build) {
        json_init(&receipt);
        json_set_object(&receipt);
        (void)json_push_kv_str(&receipt, "schema",
                               "zcl.hotswap_build_receipt.v1");
        (void)json_push_kv_str(&receipt, "source_tu", build->source_tu);
        (void)json_push_kv_str(&receipt, "artifact_path",
                               build->artifact_path);
        (void)json_push_kv_str(&receipt, "artifact_sha256",
                               build->artifact_sha256);
        (void)json_push_kv_str(&receipt, "candidate_object_root",
                               build->candidate_object_sha256);
        (void)json_push_kv_str(&receipt, "candidate_module_root",
                               build->artifact_sha256);
        (void)json_push_kv_bool(&receipt, "plan_cache_hit",
                                build->plan_cache_hit);
        (void)json_push_kv_bool(&receipt, "artifact_cache_hit",
                                build->artifact_cache_hit);
        if (build->artifact_cache_key[0])
            (void)json_push_kv_str(&receipt, "artifact_cache_key",
                                   build->artifact_cache_key);
        (void)json_push_kv_int(&receipt, "dependencies",
                               build->dependency_count);
        (void)json_push_kv_int(&receipt, "compiler_processes",
                               build->compiler_processes);
        (void)json_push_kv_int(&receipt, "linker_processes",
                               build->linker_processes);
        (void)json_push_kv_int(&receipt, "full_program_linker_processes", 0);
        (void)json_push_kv_int(&receipt, "plan_load_us",
                               build->plan_load_us);
        (void)json_push_kv_int(&receipt, "compile_us", build->compile_us);
        (void)json_push_kv_int(&receipt, "link_us", build->link_us);
        (void)json_push_kv_int(&receipt, "publish_us", build->publish_us);
        (void)json_push_kv_int(&receipt, "build_total_us", build->total_us);
        (void)json_push_kv_int(&receipt, "activation_us", activation_us);
        (void)json_push_kv(&doc, "build_receipt", &receipt);
        json_free(&receipt);
    }
    if (resident && resident->type == JSON_OBJ) {
        (void)json_push_kv(&doc, "resident", resident);
        const char *semantic_keys[] = {
            "candidate_object_root", "candidate_module_root", "story_id",
            "story_root", "story_fixture_root", "observation_root",
            "story_fixture_id", "story_adapter", "forbidden_effect_mask",
            "exercised_owner_surface", "loaded_mapping_root", "story_detail",
        };
        for (size_t i = 0; i < sizeof(semantic_keys) / sizeof(semantic_keys[0]);
             i++) {
            const char *value =
                json_get_str(json_get(resident, semantic_keys[i]));
            if (value)
                (void)json_push_kv_str(&doc, semantic_keys[i], value);
        }
        const struct json_value *story_timeout =
            json_get(resident, "story_timeout_ms");
        if (story_timeout && story_timeout->type == JSON_INT)
            (void)json_push_kv_int(&doc, "story_timeout_ms",
                                   json_get_int(story_timeout));
        (void)json_push_kv_bool(
            &doc, "candidate_bytes_executed",
            json_get_bool(json_get(resident, "candidate_bytes_executed")));
    }
    if (status && strcmp(status, "story_green") == 0 && build && resident) {
        if (!hs_story_receipt_valid(source, build, resident)) {
            json_free(&doc);
            return false;
        }
        struct json_value handoff;
        if (!hs_proof_handoff(source, changed_path_count, build, resident,
                              &handoff)) {
            json_free(&doc);
            return false;
        }
        bool attached = json_push_kv(&doc, "proof_handoff", &handoff);
        json_free(&handoff);
        if (!attached) {
            json_free(&doc);
            return false;
        }
    }
    char why_not_live[512], next_command[256];
    zcl_devloop_hotswap_guidance(
        status, phase, why, why_not_live, sizeof(why_not_live),
        next_command, sizeof(next_command));
    (void)json_push_kv_str(&doc, "why_not_live", why_not_live);
    (void)json_push_kv_str(&doc, "agent_next_action", next_command);

    char wire[16384];
    size_t n = json_write(&doc, wire, sizeof(wire) - 1);
    json_free(&doc);
    if (!n)
        return false;
    wire[n++] = '\n';
    wire[n] = 0;
    char state_why[160] = {0};
    int64_t epoch = 0;
    if (!zcl_devloop_cycle_stream_publish(root, wire, n, &epoch,
                                          state_why, sizeof(state_why))) {
        fprintf(stderr, "[devloop] resident event publication failed: %s\n",
                state_why[0] ? state_why : "unknown");
        return false;
    }
    (void)fwrite(wire, 1, n, stdout);
    (void)fflush(stdout);
    if (flush_after && !zcl_devloop_cycle_stream_flush_through(
                           root, epoch, state_why, sizeof(state_why))) {
        fprintf(stderr, "[devloop] async event journal flush failed: %s\n",
                state_why[0] ? state_why : "unknown");
        return false;
    }
    return true;
}

static const char *hs_owner_for_path(const char *path)
{
    const char *owner = hotswap_island_owner_for_path(path);
    if (owner) return owner;
    owner = zcl_hotswap_service_source_for_path(path);
    return owner ? owner : zcl_hotswap_shadow_service_for_owner(path);
}

int zcl_devloop_hotswap_batch_event(
    const char *repo_root, const char *const *paths, size_t path_count,
    enum zcl_devloop_publish_mode publish_mode)
{
    if (!repo_root || !paths || path_count == 0 ||
        path_count > ZCL_DEVLOOP_MAX_FILES)
        return 0;
    const char *owner = hs_owner_for_path(paths[0]);
    if (!owner) return 0;
    for (size_t i = 1; i < path_count; i++) {
        const char *next = hs_owner_for_path(paths[i]);
        if (!next || strcmp(next, owner) != 0) return 0;
    }
    int64_t started = platform_time_monotonic_us();
    struct zcl_devloop_hotswap_build_receipt build = {0};
    struct zcl_devloop_process_result process = {0};
    char why[512] = {0};
    int64_t shell_compile_us = 0;
    bool static_authority_shell = false;
    for (size_t i = 0; i < path_count; i++) {
        const char *mapped = zcl_hotswap_shadow_service_for_owner(paths[i]);
        if (!mapped ||
            !zcl_hotswap_shadow_path_is_static_owner(paths[i])) continue;
        static_authority_shell = true;
        int64_t one_us = 0;
        if (strcmp(mapped, owner) != 0 ||
            !hs_shadow_owner_compile(repo_root, paths[i], &build, &process,
                                     &one_us, why, sizeof(why))) {
            if (process.cancelled || zcl_devloop_process_cancel_requested())
                return 2;
            return hs_emit_event(
                repo_root, paths[i], path_count, "rejected", "compile",
                false, platform_time_monotonic_us() - started,
                &build, 0, NULL, &process, why, true) ? 1 : -1;
        }
        shell_compile_us += one_us;
    }
    if (static_authority_shell) {
        /* Compiling an authority shell and executing its mapped service are
         * different facts.  Until a capsule executes this exact object, the
         * strongest honest result is COMPILE_ONLY. */
        return hs_emit_event(
            repo_root, paths[0], path_count, "compile_only",
            "candidate_compile", false,
            platform_time_monotonic_us() - started, &build, 0, NULL,
            &process, "exact shell object compiled; candidate bytes were not executed",
            true) ? ZCL_DEVLOOP_RESTART_EVENT_PROOF_PENDING : -1;
    }
    if (!zcl_devloop_hotswap_build(repo_root, owner, &build, &process,
                                   why, sizeof(why))) {
        if (process.cancelled || zcl_devloop_process_cancel_requested())
            return 2;
        return hs_emit_event(repo_root, owner, path_count,
                             "rejected", "compile",
                             false, platform_time_monotonic_us() - started,
                             &build, 0, NULL, &process, why, true) ? 1 : -1;
    }
    build.compile_us += shell_compile_us;
    build.total_us += shell_compile_us;
    if (!hs_emit_event(repo_root, owner, path_count,
                       "reflex_ready", "candidate_compile", false,
                       platform_time_monotonic_us() - started, &build, 0,
                       NULL, &process, "", false))
        return -1;
    bool activate = zcl_devloop_publish_mode_applies(publish_mode);
    const bool service_island =
        zcl_hotswap_service_source_for_path(owner) != NULL;
    struct json_value resident;
    json_init(&resident);
    int64_t activation_us = 0;
    if (service_island) {
        /* Every service contract is already frozen into this resident parent.
         * Run that KAT locally first, even in auto mode. The first useful
         * story therefore has no RPC/cookie/network prerequisite; optional
         * isolated-dev activation remains a later authority action. */
        bool story_ok = hs_shadow_probe(
            owner, &build, &resident, &activation_us,
            why, sizeof(why));
        if (zcl_devloop_process_cancel_requested()) {
            json_free(&resident);
            return 2;
        }
        const bool vault_story = strcmp(
            owner, "app/services/src/vault_intent_decision_service.c") == 0;
        bool story_emitted = hs_emit_event(
            repo_root, owner, path_count,
            story_ok ? "story_green" : "story_red",
            vault_story ? "vault_intent_story" : "service_story",
            false, platform_time_monotonic_us() - started, &build,
            activation_us, resident.type == JSON_OBJ ? &resident : NULL,
            &process, why, true);
        json_free(&resident);
        if (!story_emitted)
            return -1;
        if (!story_ok)
            return ZCL_DEVLOOP_RESTART_EVENT_FINAL;
        if (!activate)
            return ZCL_DEVLOOP_RESTART_EVENT_PROOF_PENDING;

        /* Live dev activation is deliberately after the observable story.
         * It may use RPC, but can no longer delay or invalidate reflex
         * responsiveness. */
        json_init(&resident);
        activation_us = 0;
        why[0] = 0;
        bool activation_ok = hs_resident_call(
            build.artifact_path, true, &resident, &activation_us,
            why, sizeof(why));
        bool activation_emitted = hs_emit_event(
            repo_root, owner, path_count,
            activation_ok ? "passed" : "rejected", "resident_commit",
            activation_ok, platform_time_monotonic_us() - started, &build,
            activation_us, resident.type == JSON_OBJ ? &resident : NULL,
            &process, why, true);
        json_free(&resident);
        return activation_emitted ? ZCL_DEVLOOP_RESTART_EVENT_FINAL : -1;
    }

    bool ok = hs_resident_call(build.artifact_path, activate, &resident,
                               &activation_us, why, sizeof(why));
    if (zcl_devloop_process_cancel_requested()) {
        json_free(&resident);
        return 2;
    }
    const char *phase = ok ? (activate ? "resident_commit" : "resident_probe")
                           : "resident_probe";
    const char *status = ok ? "passed" : "rejected";
    bool emitted = hs_emit_event(
        repo_root, owner, path_count, status, phase,
        ok && activate, platform_time_monotonic_us() - started, &build,
        activation_us, resident.type == JSON_OBJ ? &resident : NULL,
        &process, why, true);
    json_free(&resident);
    if (!emitted)
        return -1;
    return ZCL_DEVLOOP_RESTART_EVENT_FINAL;
}

int zcl_devloop_hotfork_batch_event(
    const char *repo_root, const char *const *paths, size_t path_count,
    enum zcl_devloop_publish_mode publish_mode)
{
    if (!repo_root || !paths || path_count != 1) return 0;
    const struct hs_hotfork_def *def = hs_hotfork_for_path(paths[0]);
    if (!def) return 0;
    /* A source may own both a child-only reflex story and a real resident
     * module. Verify-only takes the zero-authority HOT_FORK path; an explicit
     * auto request keeps the existing authenticated activation path. */
    if (publish_mode == ZCL_DEVLOOP_PUBLISH_APPLY &&
        hotswap_source_is_swappable(paths[0]))
        return 0;
    int64_t started = platform_time_monotonic_us();
    struct zcl_devloop_hotswap_build_receipt build = {0};
    struct zcl_devloop_process_result process = {0};
    char why[512] = {0};
    if (!hs_hotfork_build(repo_root, def, &build, &process,
                          why, sizeof(why))) {
        if (process.cancelled || zcl_devloop_process_cancel_requested())
            return ZCL_DEVLOOP_RESTART_EVENT_CANCELLED;
        return hs_emit_event(
            repo_root, def->source_tu, 1, "rejected", "compile", false,
            platform_time_monotonic_us() - started, &build, 0, NULL,
            &process, why, true) ? ZCL_DEVLOOP_RESTART_EVENT_FINAL : -1;
    }
    if (!hs_emit_event(repo_root, def->source_tu, 1, "reflex_ready",
                       "candidate_compile", false,
                       platform_time_monotonic_us() - started, &build, 0,
                       NULL, &process, "", false))
        return -1;
    struct json_value resident;
    json_init(&resident);
    int64_t story_us = 0;
    bool story_ok = hs_hotfork_probe(def, &build, &resident, &story_us,
                                     why, sizeof(why));
    if (zcl_devloop_process_cancel_requested()) {
        json_free(&resident);
        return ZCL_DEVLOOP_RESTART_EVENT_CANCELLED;
    }
    bool emitted = hs_emit_event(
        repo_root, def->source_tu, 1,
        story_ok ? "story_green" : "story_red", "hotfork_owner_story",
        false, platform_time_monotonic_us() - started, &build, story_us,
        &resident, &process, why, true);
    json_free(&resident);
    if (!emitted) return -1;
    return story_ok ? ZCL_DEVLOOP_RESTART_EVENT_PROOF_PENDING
                    : ZCL_DEVLOOP_RESTART_EVENT_FINAL;
}

int zcl_devloop_hotswap_event(const char *repo_root, const char *source_tu,
                              enum zcl_devloop_publish_mode publish_mode)
{
    const char *paths[] = {source_tu};
    return zcl_devloop_hotswap_batch_event(repo_root, paths, 1,
                                           publish_mode);
}
