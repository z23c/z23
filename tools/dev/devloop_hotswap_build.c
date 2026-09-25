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
#include "hotfork_unity.h"
#include "devloop_action_root.h"

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
#include "devloop_reflex_runner.h"
#include "platform/os_sandbox.h"
#include "platform/directory_compat.h"
#include "platform/path_compat.h"
#include "platform/time_compat.h"
#include "platform/pipe_compat.h"
#include "util/safe_alloc.h"
#include "util/spawn.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#if !defined(_WIN32)
#include <poll.h>
#endif
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <io.h>
#ifndef O_CLOEXEC
#define O_CLOEXEC _O_NOINHERIT
#endif
#ifndef O_NOFOLLOW
/* Existing inputs are reparse-checked by hs_regular().  Newly created cache
 * leaves use O_EXCL or live below a component-validated cache directory. */
#define O_NOFOLLOW 0
#endif
#else
#include <sys/file.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#endif
#include <sys/stat.h>
#include <unistd.h>

#if defined(_WIN32)
/* flock(2) over LockFileEx on the fd's backing handle: exclusive byte-range
 * lock at offset 0, blocking unless LOCK_NB, unlocked by LOCK_UN on the same
 * range. Covers the build-cache lock below; not a general flock. */
#define LOCK_EX 2
#define LOCK_NB 4
#define LOCK_UN 8
static int hs_flock(int fd, int op)
{
    HANDLE h = (HANDLE)_get_osfhandle(fd);
    if (h == INVALID_HANDLE_VALUE) {
        errno = EBADF;
        return -1;
    }
    if (op & LOCK_UN)
        return UnlockFile(h, 0, 0, 1, 0) ? 0 : -1;
    OVERLAPPED ov;
    memset(&ov, 0, sizeof(ov));
    DWORD flags = LOCKFILE_EXCLUSIVE_LOCK;
    if (op & LOCK_NB)
        flags |= LOCKFILE_FAIL_IMMEDIATELY;
    return LockFileEx(h, flags, 0, 1, 0, &ov) ? 0 : -1;
}
#define flock(fd, op) hs_flock((fd), (op))
#endif

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define HS_PLAN_TEXT_MAX 12288
#define HS_ARG_MAX 256
#define HS_DEP_MAX 512

struct hs_action_plan {
    char root[PATH_MAX];
    char cc[512];
    char cxx[512];
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

/* `source_tu` is the OWNER translation unit — the capsule's identity in every
 * receipt — and `sibling_tus` is the rest of its TU SET: a '|'-separated list
 * of repo-relative .c paths, "" when the owner stands alone. The set exists
 * because the capsule links without --no-undefined and is dlopen'ed
 * RTLD_LAZY: a rule the story exercises that lives in a TU outside the set
 * resolves from the RESIDENT binary, so a mutation in that TU cannot change
 * the story's answer and the capsule reports STORY_GREEN for a mutation it
 * claims to catch. Every TU in the set is #included into the capsule, and an
 * edit to any of them selects this capsule. The TU-list helpers and bounds
 * (ZCL_HOTFORK_UNITY_*) live in hotfork_unity.h beside the unity renderer.
 * `adapter_id` names the story adapter file the renderer derives. */

struct hs_hotfork_def {
    const char *owner_id;
    const char *feedback_class;
    const char *source_tu;
    const char *sibling_tus;
    const char *story_id;
    const char *fixture_id;
    const char *adapter_id;
    uint32_t max_time_ms;
    const char *forbidden_effect_mask;
    const char *exercised_surface;
};

#define HOTFORK_CAPSULE(owner_id_, feedback_class_, source_tu_, sibling_tus_, \
                        story_id_, fixture_id_, adapter_id_, max_time_ms_, \
                        forbidden_effect_mask_, surface_) \
    { owner_id_, feedback_class_, source_tu_, sibling_tus_, story_id_, \
      fixture_id_, adapter_id_, max_time_ms_, forbidden_effect_mask_, \
      surface_ },
static const struct hs_hotfork_def k_hotfork_defs[] = {
#include "../../engine/composition/hotfork_capsules.def"
};
#undef HOTFORK_CAPSULE

static void hs_sha3_root(const char *text, char out[65]);

static void hs_why(char *why, size_t why_len, const char *message)
{
    if (why && why_len)
        (void)snprintf(why, why_len, "%s", message ? message : "unknown");
}


static const char *hs_hotswap_guidance_why_not_live(
    const char *status, const char *phase, const char *why, bool passed,
    bool compile_green, bool story_green)
{
    const char *exact = passed ? "" : why;
    if (story_green || compile_green)
        return phase && strcmp(phase, "hotfork_owner_story") == 0
            ? "HOT_FORK is child-only evidence and never publishes runtime authority"
            : "reflex candidate evidence never publishes runtime authority";
    if (!passed && (!exact || !exact[0]))
        return phase && strcmp(phase, "compile") == 0
            ? "candidate compilation did not produce a publishable artifact"
            : "resident dev node did not publish the candidate";
    (void)status;
    return exact;
}

/* A build-config-changing rejection asks for a rebuild before anything else
 * is worth trying; recognise it by its distinct why-text. */
static bool hs_hotswap_guidance_needs_rebuild(const char *why)
{
    return why && (strstr(why, "DEV_RESTART") ||
        strstr(why, "service ABI changed") ||
        strstr(why, "service schema changed") ||
        strstr(why, "service wire contract changed") ||
        strstr(why, "frozen KAT identity changed"));
}

static bool hs_hotswap_guidance_needs_generation(const char *why)
{
    return why && (strstr(why, "cannot read RPC auth cookie") ||
        strstr(why, "returned no activation body"));
}

static const char *hs_hotswap_guidance_next_command(
    const char *phase, const char *why, bool passed, bool compile_green,
    bool story_green)
{
    if (story_green)
        return "keep editing; exact affected proof is running asynchronously";
    if (compile_green)
        return "keep editing; the owner-bound shadow story is running";
    if (passed)
        return "keep editing; the resident authority owns the next module epoch";
    if (hs_hotswap_guidance_needs_rebuild(why))
        return "make -j\"$(getconf _NPROCESSORS_ONLN)\" dev-bin";
    if (phase && strcmp(phase, "compile") == 0)
        return "z23-dev dev diagnose latest";
    if (hs_hotswap_guidance_needs_generation(why))
        return "z23-dev dev generation current";
    return "z23-dev dev status --view=full";
}

void zcl_devloop_hotswap_guidance(
    const char *status, const char *phase, const char *why,
    char *why_not_live, size_t why_not_live_size,
    char *next_command, size_t next_command_size)
{
    bool passed = status && strcmp(status, "passed") == 0;
    bool compile_green = status && strcmp(status, "reflex_ready") == 0;
    bool story_green = status && strcmp(status, "story_green") == 0;
    if (why_not_live && why_not_live_size)
        (void)snprintf(why_not_live, why_not_live_size, "%s",
                       hs_hotswap_guidance_why_not_live(
                           status, phase, why, passed, compile_green,
                           story_green));
    if (!next_command || next_command_size == 0) return;
    (void)snprintf(next_command, next_command_size, "%s",
                   hs_hotswap_guidance_next_command(
                       phase, why, passed, compile_green, story_green));
}

static const struct json_value *hs_response_message_field(
    const struct json_value *response)
{
    const struct json_value *message_v = json_get(response, "message");
    const struct json_value *error_v = json_get(response, "error");
    if ((!message_v || message_v->type != JSON_STR) && error_v &&
        error_v->type == JSON_OBJ)
        message_v = json_get(error_v, "message");
    if ((!message_v || message_v->type != JSON_STR) && error_v &&
        error_v->type == JSON_STR)
        message_v = error_v;
    return message_v;
}

bool zcl_devloop_hotswap_response_error(
    const struct json_value *response, char *out, size_t out_size)
{
    if (!response || response->type != JSON_OBJ || !out || out_size == 0)
        return false;
    const struct json_value *message_v = hs_response_message_field(response);
    const char *message = message_v && message_v->type == JSON_STR
        ? json_get_str(message_v) : NULL;
    if (!message || !message[0]) return false;
    (void)snprintf(out, out_size, "%s", message);
    return true;
}

static bool hs_regular(const char *path, struct stat *out)
{
    struct stat st;
#if defined(_WIN32)
    DWORD attributes = path ? GetFileAttributesA(path) : INVALID_FILE_ATTRIBUTES;
    if (!path || attributes == INVALID_FILE_ATTRIBUTES ||
        (attributes & (FILE_ATTRIBUTE_DIRECTORY |
                       FILE_ATTRIBUTE_REPARSE_POINT)) != 0 ||
        stat(path, &st) != 0 || !S_ISREG(st.st_mode))
        return false;
#else
    if (!path || lstat(path, &st) != 0 || !S_ISREG(st.st_mode) ||
        S_ISLNK(st.st_mode))
        return false;
#endif
    if (out)
        *out = st;
    return true;
}

static bool hs_stat_equal(const struct stat *a, const struct stat *b)
{
#if defined(_WIN32)
    /* UCRT struct stat has second-resolution st_mtime and no st_mtim. */
    return a->st_size == b->st_size &&
           a->st_mtime == b->st_mtime;
#else
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino &&
           a->st_size == b->st_size &&
           a->st_mtim.tv_sec == b->st_mtim.tv_sec &&
           a->st_mtim.tv_nsec == b->st_mtim.tv_nsec;
#endif
}

static bool hs_mtime_after(const struct stat *a, const struct stat *b)
{
#if defined(_WIN32)
    /* Second-resolution comparison; see hs_stat_equal. */
    return a->st_mtime > b->st_mtime;
#else
    return a->st_mtim.tv_sec > b->st_mtim.tv_sec ||
           (a->st_mtim.tv_sec == b->st_mtim.tv_sec &&
            a->st_mtim.tv_nsec > b->st_mtim.tv_nsec);
#endif
}

static int hs_link(const char *existing, const char *linkpath)
{
#if defined(_WIN32)
    if (CreateHardLinkA(linkpath, existing, NULL))
        return 0;
    DWORD err = GetLastError();
    if (err == ERROR_FILE_EXISTS || err == ERROR_ALREADY_EXISTS)
        errno = EEXIST;
    else if (err == ERROR_NOT_SAME_DEVICE)
        errno = EXDEV;
    else
        errno = EIO;
    return -1;
#else
    return link(existing, linkpath);
#endif
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

static bool hs_plan_apply_field(struct hs_action_plan *plan, const char *line)
{
    return hs_plan_line(plan->cc, sizeof(plan->cc), line, "CC=") ||
           hs_plan_line(plan->cxx, sizeof(plan->cxx), line, "CXX=") ||
           hs_plan_line(plan->compiler_id, sizeof(plan->compiler_id), line,
                        "COMPILER_ID=") ||
           hs_plan_line(plan->cflags, sizeof(plan->cflags), line,
                        "DEV_CFLAGS=") ||
           hs_plan_line(plan->ldflags, sizeof(plan->ldflags), line,
                        "HOTSWAP_MODULE_LDFLAGS=");
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
                 "%s/build/hotswap-fast/flags.env", root) >=
            (int)sizeof(flags_path) ||
        snprintf(makefile, sizeof(makefile), "%s/Makefile", root) >=
            (int)sizeof(makefile) ||
        snprintf(manifest, sizeof(manifest),
                 "%s/engine/composition/hotswap_swappable.def", root) >=
            (int)sizeof(manifest) ||
        snprintf(islands, sizeof(islands),
                 "%s/engine/composition/hotswap_islands.def", root) >=
            (int)sizeof(islands) ||
        snprintf(services, sizeof(services),
                 "%s/engine/composition/hotswap_services.def", root) >=
            (int)sizeof(services) ||
        snprintf(shadow_owners, sizeof(shadow_owners),
                 "%s/engine/composition/hotswap_shadow_owners.def", root) >=
            (int)sizeof(shadow_owners) ||
        snprintf(hotfork_capsules, sizeof(hotfork_capsules),
                 "%s/engine/composition/hotfork_capsules.def", root) >=
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
        hs_mtime_after(&make_st, &stamp) ||
        hs_mtime_after(&manifest_st, &stamp) ||
        hs_mtime_after(&islands_st, &stamp) ||
        hs_mtime_after(&services_st, &stamp) ||
        hs_mtime_after(&shadow_owners_st, &stamp)) {
        hs_why(why, why_len,
               "resident action plan stale; refresh after build-system change");
        return false;
    }
    if (hs_mtime_after(&hotfork_capsules_st, &stamp)) {
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
        if (hs_plan_apply_field(&next, line))
            continue;
        fclose(f);
        hs_why(why, why_len, "resident action plan has an unknown field");
        return false;
    }
    bool read_error = ferror(f) != 0;
    fclose(f);
    if (read_error || !next.cc[0] || !next.cxx[0] ||
        !hs_lower_hex64(next.compiler_id) ||
        !next.cflags[0] || !next.ldflags[0] ||
        !strstr(next.cflags, "-DZCL_DEV_BUILD") ||
        !strstr(next.ldflags, "-Wl,-Bsymbolic") ||
        !strstr(next.ldflags, "-nostartfiles")) {
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

/* Resolve one depfile argv token to a confined path and, when a snapshot is
 * requested, record its identity for later mutation detection. Returns
 * false on a hard error; a generated unity wrapper is skipped (not an
 * error) by leaving *skip true. */
static bool hs_depfile_resolve_entry(const char *root, const char *arg,
                                     bool snapshot, bool *skip,
                                     struct hs_dep *d)
{
    *skip = false;
    char full[PATH_MAX];
    int pn = arg[0] == '/'
        ? snprintf(full, sizeof(full), "%s", arg)
        : snprintf(full, sizeof(full), "%s/%s", root, arg);
    struct stat st;
    if (pn <= 0 || pn >= (int)sizeof(full))
        return false;
    if (strstr(full, "/build/hotswap-fast/.resident-") != NULL) {
        *skip = true; /* generated unity wrapper, never source authority */
        return true;
    }
    if (!hs_regular(full, &st))
        return false;
    (void)snprintf(d->path, sizeof(d->path), "%s", full);
    if (!snapshot)
        return true;
    d->dev = st.st_dev;
    d->ino = st.st_ino;
    d->size = st.st_size;
#if defined(_WIN32)
    d->mtime.tv_sec = st.st_mtime;
    d->mtime.tv_nsec = 0;
#else
    d->mtime = st.st_mtim;
#endif
    return hs_sha256_digest_file(full, d->sha256);
}

/* Read a Makefile-style depfile whole and line-continuation-fold it in
 * place; returns the colon-delimited prerequisite list, or NULL on any
 * read, size, or shape failure. */
static char *hs_depfile_load(const char *path, char *text, size_t text_size)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return NULL;
    size_t n = fread(text, 1, text_size - 1, f);
    bool ok = !ferror(f) && !feof(f) ? false : true;
    fclose(f);
    if (!ok || n == 0 || n >= text_size)
        return NULL;
    text[n] = 0;
    for (size_t i = 0; i < n; i++)
        if (text[i] == '\\' && (text[i + 1] == '\n' || text[i + 1] == '\r'))
            text[i] = text[i + 1] = ' ';
    return strchr(text, ':');
}

static bool hs_depfile_read(const char *root, const char *path,
                            struct hs_dep *deps, size_t *count,
                            bool snapshot)
{
    *count = 0;
    char text[65536];
    char *colon = hs_depfile_load(path, text, sizeof(text));
    if (!colon)
        return false;
    const char *argv[HS_DEP_MAX + 1];
    size_t argc = zcl_argv_split(colon + 1, argv, HS_DEP_MAX + 1);
    if (argc == 0 || argc >= HS_DEP_MAX)
        return false;
    for (size_t i = 0; i < argc; i++) {
        bool skip = false;
        struct hs_dep *d = &deps[*count];
        if (!hs_depfile_resolve_entry(root, argv[i], snapshot, &skip, d))
            return false;
        if (!skip)
            (*count)++;
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

static bool hs_dep_entry_mutated(const struct hs_dep *old,
                                 const struct hs_dep *cur)
{
    return old->dev != cur->dev || old->ino != cur->ino ||
        old->size != cur->size ||
        old->mtime.tv_sec != cur->mtime.tv_sec ||
        old->mtime.tv_nsec != cur->mtime.tv_nsec ||
        memcmp(old->sha256, cur->sha256, SHA256_OUTPUT_SIZE) != 0;
}

static bool hs_deps_unchanged(const struct hs_dep *before, size_t before_n,
                              const struct hs_dep *after, size_t after_n,
                              char *why, size_t why_len)
{
    if (before_n != after_n) {
        if (why && why_len)
            (void)snprintf(why, why_len,
                           "dependency closure size changed: %zu -> %zu",
                           before_n, after_n);
        return false;
    }
    for (size_t i = 0; i < after_n; i++) {
        const struct hs_dep *old = hs_dep_find(before, before_n, after[i].path);
        if (!old) {
            if (why && why_len)
                (void)snprintf(why, why_len,
                               "dependency baseline learned new input: %.180s",
                               after[i].path);
            return false;
        }
        if (hs_dep_entry_mutated(old, &after[i])) {
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

#if defined(_WIN32)
static bool hs_mkdirs_win32(const char *path)
{
    char tmp[PATH_MAX];
    if (!platform_path_is_absolute(path) || strlen(path) >= sizeof(tmp) ||
        strstr(path, ".."))
        return false;
    (void)snprintf(tmp, sizeof(tmp), "%s", path);
    for (char *p = tmp; *p; ++p)
        if (*p == '\\') *p = '/';
    char *start = tmp + 3; /* drive-qualified roots are the supported cache */
    if (!(tmp[0] && tmp[1] == ':' && tmp[2] == '/'))
        return false;
    for (char *p = start; *p; ++p) {
        if (*p != '/') continue;
        *p = 0;
        bool ok = platform_directory_ensure(tmp, 0700);
        *p = '/';
        if (!ok) return false;
    }
    return platform_directory_ensure(tmp, 0700);
}
#else
static bool hs_mkdirs_posix_component(char *tmp, char *p, struct stat *st)
{
    *p = 0;
    bool ok = mkdir(tmp, 0700) == 0 ||
        (errno == EEXIST && lstat(tmp, st) == 0 && S_ISDIR(st->st_mode) &&
         !S_ISLNK(st->st_mode));
    *p = '/';
    return ok;
}

static bool hs_mkdirs_posix(const char *path)
{
    char tmp[PATH_MAX];
    struct stat st;
    if (!path || path[0] != '/' || strlen(path) >= sizeof(tmp))
        return false;
    (void)snprintf(tmp, sizeof(tmp), "%s", path);
    for (char *p = tmp + 1; *p; p++) {
        if (*p != '/')
            continue;
        if (!hs_mkdirs_posix_component(tmp, p, &st))
            return false;
    }
    if (mkdir(tmp, 0700) != 0 &&
        (errno != EEXIST || lstat(tmp, &st) != 0 ||
         !S_ISDIR(st.st_mode) || S_ISLNK(st.st_mode)))
        return false;
    return chmod(tmp, 0700) == 0;
}
#endif

static bool hs_mkdirs(const char *path)
{
#if defined(_WIN32)
    return hs_mkdirs_win32(path);
#else
    return hs_mkdirs_posix(path);
#endif
}

static bool hs_cache_root_for(const char *lane, char out[PATH_MAX])
{
    const char *configured = getenv("ZCL_DEV_ARTIFACT_CACHE");
#if defined(_WIN32)
    const char *home = getenv("USERPROFILE");
#else
    const char *home = getenv("HOME");
#endif
    int n;
    if (configured && configured[0]) {
        if (!platform_path_is_absolute(configured) || strstr(configured, ".."))
            return false;
        n = snprintf(out, PATH_MAX, "%s/%s", configured, lane);
    } else {
        if (!platform_path_is_absolute(home))
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

static bool hs_copy_write_all(int temp_fd, const unsigned char *buffer,
                              size_t got)
{
    size_t written = 0;
    while (written < got) {
        ssize_t put = write(temp_fd, buffer + written, got - written);
        if (put < 0 && errno == EINTR)
            continue;
        if (put <= 0)
            return false;
        written += (size_t)put;
    }
    return true;
}

static bool hs_copy_stream(int source_fd, int temp_fd)
{
    unsigned char buffer[32u * 1024u];
    for (;;) {
        ssize_t got = read(source_fd, buffer, sizeof(buffer));
        if (got == 0)
            return true;
        if (got < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        if (!hs_copy_write_all(temp_fd, buffer, (size_t)got))
            return false;
    }
}

/* Verify the freshly written read-only temp file's digest, then publish it
 * under target by hardlink; if target was concurrently published by another
 * builder, that is success too provided its content already matches.
 *
 * Candidate artifacts are reflex inputs, not acceptance evidence: every
 * consumer re-verifies them by content (the cache lookup re-hashes, the
 * story compares its loaded mapping root), so publication never waits for a
 * storage acknowledgement; on a host with busy disks an fsync here was the
 * largest stage between a save and its story. */
static bool hs_copy_publish_finish(const char *temp, const char *target,
                                   const char expected_sha256[65])
{
    char actual[65];
    if (!hs_sha256_file(temp, actual) || strcmp(actual, expected_sha256) != 0)
        return false;
    if (hs_link(temp, target) == 0)
        return true;
    return errno == EEXIST && hs_regular(target, NULL) &&
        hs_sha256_file(target, actual) &&
        strcmp(actual, expected_sha256) == 0 &&
        chmod(target, 0444) == 0;
}

/* Open the confined source regular file read-only and allocate the sealed
 * temp file next to target. On failure both fds are closed/absent and
 * source_fd and temp_fd are left negative. */
static bool hs_copy_publish_open(const char *source, char temp[PATH_MAX],
                                 int *source_fd, int *temp_fd)
{
    *source_fd = open(source, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    struct stat source_st;
    if (*source_fd < 0 || fstat(*source_fd, &source_st) != 0 ||
        !S_ISREG(source_st.st_mode)) {
        if (*source_fd >= 0) close(*source_fd);
        *source_fd = -1;
        return false;
    }
#if defined(_WIN32)
    *temp_fd = mkstemp(temp);
#else
    *temp_fd = mkostemp(temp, O_CLOEXEC);
#endif
    if (*temp_fd < 0) {
        close(*source_fd);
        *source_fd = -1;
        return false;
    }
    return true;
}

static bool hs_copy_publish(const char *source, const char *target,
                            const char expected_sha256[65])
{
    char temp[PATH_MAX];
    int n = snprintf(temp, sizeof(temp), "%s.tmp.XXXXXX", target);
    if (n <= 0 || n >= (int)sizeof(temp))
        return false;
    int source_fd, temp_fd;
    if (!hs_copy_publish_open(source, temp, &source_fd, &temp_fd))
        return false;
    bool ok = hs_copy_stream(source_fd, temp_fd);
    if (close(source_fd) != 0)
        ok = false;
#if defined(_WIN32)
    if (ok && _chmod(temp, _S_IREAD) != 0)
#else
    if (ok && fchmod(temp_fd, 0444) != 0)
#endif
        ok = false;
    if (close(temp_fd) != 0)
        ok = false;
    ok = ok && hs_copy_publish_finish(temp, target, expected_sha256);
    (void)unlink(temp);
    return ok;
}

static bool hs_link_or_copy_publish(const char *source, const char *target,
                                    const char expected_sha256[65])
{
    if (!hs_force_cache_copy_for_test() && hs_link(source, target) == 0)
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
    char dir[PATH_MAX];
    /* The action plan lives in build/hotswap-fast/, a sibling, so publishing
     * a module is what creates build/hotswap/. */
    if (snprintf(dir, sizeof(dir), "%s/build/hotswap", root) >=
            (int)sizeof(dir) ||
        !platform_directory_ensure(dir, 0700))
        return false;
    if (snprintf(out, 4096, "%s/build/hotswap/%s-%s.so", root, safe,
                 artifact_sha256) >= 4096)
        return false;
    /* The worktree copy is always a fresh single-link file: build/hotswap/
     * is one of the trees check-no-hardlink-seeding refuses to find a
     * multiply-linked file in, and a hardlink from the host-wide artifact
     * cache is exactly that. Only the cache itself shares links. */
    return hs_copy_publish(source_so, out, artifact_sha256);
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
    /* No storage acknowledgement: hs_cache_lookup() re-hashes the .so against
     * this line, so a torn entry is a miss that recompiles, never a hit. */
    char line[66];
    (void)snprintf(line, sizeof(line), "%s\n", hash);
    bool ok = write(fd, line, 65) == 65;
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
                     "%s/build/hotswap-fast/.resident-XXXXXX%s", root,
                     suffix);
    if (n <= 0 || (size_t)n >= out_len)
        return false;
#if defined(_WIN32)
    /* No mkstemps: generate with mkstemp on the stem, then move the
       created file onto the suffixed name. */
    size_t suffix_len = strlen(suffix);
    size_t out_len_used = strlen(out);
    char stem[PATH_MAX];
    if (out_len_used < suffix_len || out_len_used - suffix_len >= sizeof(stem))
        return false;
    memcpy(stem, out, out_len_used - suffix_len);
    stem[out_len_used - suffix_len] = '\0';
    int fd = mkstemp(stem);
    if (fd < 0)
        return false;
    close(fd);
    if (snprintf(out, out_len, "%s%s", stem, suffix) <= 0 ||
        rename(stem, out) != 0) {
        (void)unlink(stem);
        return false;
    }
    return true;
#else
    int fd = mkstemps(out, (int)strlen(suffix));
    if (fd < 0)
        return false;
    close(fd);
    return true;
#endif
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
    if (!argc || argc + 13 >= HS_ARG_MAX ||
        snprintf(version_arg, sizeof(version_arg),
                 "-Wl,--version-script=%s", version_script) >=
            (int)sizeof(version_arg)) {
        hs_why(why, why_len, "HOT_FORK link action exceeds argv bound");
        return false;
    }
    argv[argc++] = "-shared";
    argv[argc++] = "-nostartfiles";
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
static bool hs_shadow_owner_paths_prepare(
    const char *root, const char *source_tu, char full[PATH_MAX],
    char obj[PATH_MAX], char dep[PATH_MAX])
{
    return source_tu && source_tu[0] != '/' && !strstr(source_tu, "..") &&
        snprintf(full, PATH_MAX, "%s/%s", root, source_tu) < PATH_MAX &&
        hs_regular(full, NULL) &&
        hs_temp(obj, PATH_MAX, root, ".o") &&
        hs_temp(dep, PATH_MAX, root, ".d");
}

static bool hs_shadow_owner_deps_captured(const char *root, const char *dep)
{
    struct hs_dep *deps = zcl_malloc(sizeof(*deps) * HS_DEP_MAX,
                                     "shadow shell dependencies");
    size_t dep_count = 0;
    bool ok = deps && hs_depfile_read(root, dep, deps, &dep_count, true) &&
        dep_count > 0 && !zcl_devloop_process_cancel_requested();
    free(deps);
    return ok;
}

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
    if (!hs_shadow_owner_paths_prepare(root, source_tu, full, obj, dep)) {
        hs_why(why, why_len, "shadow authority shell is not a confined source");
        if (obj[0]) (void)unlink(obj);
        if (dep[0]) (void)unlink(dep);
        return false;
    }
    bool ok = hs_run_owner_compile(&plan, root, source_tu, obj, dep, result,
                                   elapsed_us, why, why_len);
    if (ok) {
        ok = hs_shadow_owner_deps_captured(root, dep);
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

static bool hs_unity_source_write_members(
    FILE *f, const char *root, const char *members, const char *owner)
{
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
    /* A compile input consumed at once; hs_unity_source_publish() replaces
     * any differing wrapper, so it needs no storage acknowledgement. */
    return ok && fflush(f) == 0;
}

static bool hs_unity_source_publish(const char *temp, char out[PATH_MAX],
                                    char *why, size_t why_len)
{
    if (hs_regular(out, NULL) && hs_files_equal(temp, out)) {
        (void)unlink(temp);
        return true;
    }
    (void)unlink(out);
    if (rename(temp, out) != 0) {
        (void)unlink(temp);
        out[0] = 0;
        hs_why(why, why_len, "could not publish stable island wrapper");
        return false;
    }
    return true;
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
        snprintf(out, PATH_MAX, "%s/build/hotswap-fast/%s.island.c",
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
    bool ok = hs_unity_source_write_members(f, root, members, owner);
    fclose(f);
    if (!ok) {
        (void)unlink(temp);
        out[0] = 0;
        hs_why(why, why_len, "island member list is invalid or unwritable");
        return false;
    }
    return hs_unity_source_publish(temp, out, why, why_len);
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
    if (!platform_directory_canonical_real(repo_root, root, sizeof(root)) ||
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
                 "%s/build/hotswap-fast/%s.d", root, safe) >=
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
            zcl_devloop_action_root_hotswap(root, owner, plan.cc, plan.cflags,
                                            plan.ldflags, cached_dep, receipt);
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
    /* A cold watcher has no dependency baseline. Discover the exact closure,
     * bind its cache key, then either reuse a verified artifact or compile a
     * second time in this same bounded action. The second depfile proves that
     * the accepted object was built from the closure just observed; requiring
     * another filesystem save adds operator latency without adding evidence. */
    if (!have_baseline) {
        memcpy(before, after, after_n * sizeof(*after));
        before_n = after_n;
        if (!hs_cache_key(&plan, root, owner, before, before_n,
                          receipt->artifact_cache_key) ||
            !hs_cache_root(cache_root)) {
            free(before);
            free(after);
            hs_why(why, why_len,
                   "could not bind cold dependency closure");
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
            if (rename(tmp_d, cached_dep) != 0) {
                free(before);
                free(after);
                hs_why(why, why_len,
                       "could not publish cold dependency baseline");
                goto fail;
            }
            tmp_d[0] = 0;
            (void)snprintf(receipt->source_tu,
                           sizeof(receipt->source_tu), "%s", owner);
            receipt->publish_us = platform_time_monotonic_us() - started -
                                  receipt->plan_load_us -
                                  receipt->compile_us;
            receipt->total_us = platform_time_monotonic_us() - started;
            free(before);
            free(after);
            (void)flock(cache_fd, LOCK_UN);
            (void)close(cache_fd);
            (void)unlink(tmp_o);
            (void)unlink(tmp_so);
            zcl_devloop_action_root_hotswap(root, owner, plan.cc, plan.cflags,
                                            plan.ldflags, cached_dep, receipt);
            return true;
        }
        if (cache_fd >= 0) {
            (void)unlink(cache_so);
            (void)unlink(cache_obj);
            (void)unlink(cache_hash);
        }
        int64_t stable_compile_us = 0;
        receipt->compiler_processes++;
        if (!hs_run_compile(&plan, root, owner, compile_input, tmp_o, tmp_d,
                            process, &stable_compile_us, why, why_len) ||
            !hs_depfile_read(root, tmp_d, after, &after_n, true)) {
            free(before);
            free(after);
            goto fail;
        }
        receipt->compile_us += stable_compile_us;
    }
    /* Publish the dependency proof for exact reuse by later saves. */
    (void)unlink(cached_dep);
    if (rename(tmp_d, cached_dep) != 0) {
        free(before);
        free(after);
        hs_why(why, why_len, "could not publish dependency baseline");
        goto fail;
    }
    tmp_d[0] = 0;
    receipt->dependency_count = (uint32_t)after_n;
    bool stable = hs_deps_unchanged(before, before_n, after, after_n,
                                    why, why_len);
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
    zcl_devloop_action_root_hotswap(root, owner, plan.cc, plan.cflags,
                                    plan.ldflags, cached_dep, receipt);
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
    zcl_devloop_action_root_hotswap(root, owner, plan.cc, plan.cflags,
                                    plan.ldflags, NULL, receipt);
    return false;
}

/* True when `path` is the owner TU or any sibling of this capsule. */
static bool hs_hotfork_def_owns_path(const struct hs_hotfork_def *def,
                                     const char *path)
{
    if (!def || !path || !path[0]) return false;
    if (strcmp(def->source_tu, path) == 0) return true;
    char tu[ZCL_HOTFORK_UNITY_TU_MAX];
    size_t count = zcl_hotfork_tu_list_count(def->sibling_tus);
    for (size_t i = 0; i < count; i++)
        if (zcl_hotfork_tu_list_at(def->sibling_tus, i, tu, sizeof(tu)) &&
            strcmp(tu, path) == 0)
            return true;
    return false;
}

/* A sibling list is valid when it is present, bounded, and every entry is a
 * confined repo-relative path that is not the owner restated. */
static bool hs_hotfork_siblings_valid(const struct hs_hotfork_def *def)
{
    if (!def->sibling_tus) return false;
    size_t count = zcl_hotfork_tu_list_count(def->sibling_tus);
    if (count > ZCL_HOTFORK_UNITY_SIBLING_MAX) return false;
    char tu[ZCL_HOTFORK_UNITY_TU_MAX];
    for (size_t i = 0; i < count; i++)
        if (!zcl_hotfork_tu_list_at(def->sibling_tus, i, tu, sizeof(tu)) ||
            tu[0] == '/' || strstr(tu, "..") ||
            strcmp(tu, def->source_tu) == 0)
            return false;
    return true;
}

/* True when the two capsules claim any TU in common. One path belongs to at
 * most one capsule, because hs_hotfork_for_path() returns the first match. */
static bool hs_hotfork_defs_share_tu(const struct hs_hotfork_def *a,
                                     const struct hs_hotfork_def *b)
{
    if (hs_hotfork_def_owns_path(b, a->source_tu)) return true;
    char tu[ZCL_HOTFORK_UNITY_TU_MAX];
    size_t count = zcl_hotfork_tu_list_count(a->sibling_tus);
    for (size_t i = 0; i < count; i++)
        if (zcl_hotfork_tu_list_at(a->sibling_tus, i, tu, sizeof(tu)) &&
            hs_hotfork_def_owns_path(b, tu))
            return true;
    return false;
}

static bool hs_hotfork_def_fields_present(const struct hs_hotfork_def *def)
{
    return def && def->owner_id && def->owner_id[0] &&
        def->feedback_class && def->source_tu && def->source_tu[0] &&
        def->story_id && def->story_id[0] && def->fixture_id &&
        def->fixture_id[0] && def->adapter_id && def->adapter_id[0] &&
        def->forbidden_effect_mask && def->exercised_surface &&
        def->exercised_surface[0];
}

static bool hs_hotfork_def_valid(const struct hs_hotfork_def *def)
{
    static const char required_forbidden_effects[] =
        "git|github|make|shell|sqlite|dht|network|publication|full_link|full_suite";
    return hs_hotfork_def_fields_present(def) &&
        hs_hotfork_siblings_valid(def) &&
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
                hs_hotfork_defs_share_tu(&k_hotfork_defs[i],
                                         &k_hotfork_defs[j]) ||
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
        if (hs_hotfork_def_owns_path(&k_hotfork_defs[i], path)) {
            const struct hs_hotfork_def *def = &k_hotfork_defs[i];
            return hs_hotfork_def_valid(def) ? def : NULL;
        }
    return NULL;
}

struct hs_hotfork_fixture_template {
    const char *story_id;
    const char *fixture_text;
};

static const struct hs_hotfork_fixture_template k_hotfork_fixture_templates[] = {
    { "vcs-devloop-publication-envelope.v1",
            "zcl.dev.hotfork.fixture.v1\n"
            "root=zero-reject,nonzero-accept\n"
            "job=canonical-roundtrip,field-preservation,bad-magic-reject,"
            "zero-required-root-reject,bad-version-reject\n"
            "receipt=waiting-zero-artifact-roundtrip,field-preservation,"
            "accepted-zero-artifact-reject,accepted-artifact-roundtrip,"
            "wrong-length-reject\n%s\n",
    },
    { "app-native-read-rpc-composition.v1",
            "zcl.dev.hotfork.fixture.v1\n"
            "tokens=array-wrap,legacy-pass-through\n"
            "names=resolve-params,list-noargs\n"
            "messaging=inbox-noargs\n"
            "market=profile-params,list-noargs,status-noargs,content-noargs\n"
            "swaps=chains-noargs,state-params,list-noargs\n"
            "transport=frozen-child-stub,no-cookie,no-activation\n%s\n",
    },
    { "zcode-moderation-input-policy.v1",
            "zcl.dev.hotfork.fixture.v1\n"
            "no-keys=empty-object;reject=null,array,nonempty\n"
            "backlog=exact-three,positive-cutoffs,explicit-scratch\n"
            "reject=unknown-key,zero-height,string-height,nonscratch\n"
            "authority=validation-only,no-projection,no-service-lease\n%s\n",
    },
    { "zcode-dev-input-policy.v1",
            "zcl.dev.hotfork.fixture.v1\n"
            "json=string-present,string-missing,int-present,int-fallback\n"
            "roots=lowercase-decode,canonical-render,uppercase-reject\n"
            "wire=even-decode,odd-reject,bound-reject\n"
            "paths=equal,parent,child,sibling;candidate=canonical,traversal-reject\n"
            "authority=validation-only,no-ledger,no-rpc,no-cas-write\n%s\n",
    },
    { "zcode-epoch-propose-input-policy.v1",
            "zcl.dev.hotfork.fixture.v1\n"
            "json=string-present,string-missing,closed-key-set\n"
            "roots=lowercase-decode,uppercase-reject,missing-reject\n"
            "epoch=positive,zero-reject,negative-reject\n"
            "proposal=exact-valid,unknown-key-reject,nonscratch-reject\n"
            "authority=validation-only,no-projection,no-cas-write\n%s\n",
    },
    { "zcode-passport-input-policy.v1",
            "zcl.dev.hotfork.fixture.v1\n"
            "keys=evidence-allowed,signature-commit-only,unknown-reject\n"
            "roots=exact-plan,optional-job-pair,uppercase-reject\n"
            "shape=workspace-alone-reject,unknown-key-reject,empty-reject\n"
            "commit=exact-shape\n"
            "authority=validation-only,no-signature,no-storage,no-publication\n%s\n",
    },
    { "zcode-workspace-input-policy.v1",
            "zcl.dev.hotfork.fixture.v1\n"
            "roots=lowercase-decode,uppercase-reject,missing-reject\n"
            "keys=manifest-allowed,signature-commit-only,unknown-reject,null-reject\n"
            "zero=all-zero-accept,nonzero-reject\n"
            "authority=validation-only,no-service,no-storage,no-publication\n%s\n",
    },
    { "source-package-transport-shape.v1",
            "zcl.dev.hotfork.fixture.v1\n"
            "marker=exact-path,exact-bytes\n"
            "files=license,manifest,shards,lane,marker,authority,offline-inputs\n"
            "counts=no-authority,with-authority,null-zero\n"
            "bounds=file-at-end-reject,offline-at-end-reject\n"
            "authority=shape-only,no-filesystem,no-cas,no-signing,no-publication\n%s\n",
    },
    { "zcode-source-bundle-input-policy.v1",
            "zcl.dev.hotfork.fixture.v1\n"
            "json=string-present,string-missing,type-reject\n"
            "roots=source,named,uppercase-reject\n"
            "paths=equal,parent,child,sibling\n"
            "render=roots,metrics,authority-flags\n"
            "authority=policy-only,no-filesystem,no-cas,no-package-import,no-publication\n%s\n",
    },
    { "test-group-catalog-selection-policy.v1",
            "zcl.dev.hotfork.fixture.v1\n"
            "catalog=known-present,unknown-absent\n"
            "exclusive=latency-yes,ordinary-no\n"
            "semantic-leaf=declared-yes,ordinary-no\n"
            "resolve=prefixless-and-full-exact,substring-reject\n"
            "family=declared-oracle,unrelated-reject\n"
            "integration=declared-yes,ordinary-no,policy-valid\n"
            "expansion=ordinary-one,immediate-excludes-integration\n"
            "authority=read-only-catalog,no-process,no-filesystem,no-build\n%s\n",
    },
    { "shop-want-view-contract.v1",
            "zcl.dev.hotfork.fixture.v1\n"
            "row=bounded-criteria,open,reviewed-ok,no-spec-hash\n"
            "render=preview,amount,state,next-action\n"
            "json=preview,truncation,amount,expiry\n"
            "contract=exact-service-id,frozen-kat\n"
            "fulfillment=hidden,ready,evidence-blocked,closed\n"
            "authority=caller-owned-row,pure-service,no-store,no-clock,no-wallet\n%s\n",
    },
    { "shop-want-command-input-core.v1",
            "zcl.dev.hotfork.fixture.v1\n"
            "hex=lowercase-32,uppercase-reject,length-reject\n"
            "want=amount,criteria,expiry,nonce,deterministic-signature\n"
            "reject=expiry-equal-now\n"
            "authority=caller-owned-json,pure-build-and-sign,no-db,no-filesystem,no-clock,no-publication\n%s\n",
    },
    { "command-registry-input-validation-core.v1",
            "zcl.dev.hotfork.fixture.v1\n"
            "booleans=wait-for-edit,all,string-reject\n"
            "maximum-bytes=package-256m,space-8m,path-sensitive\n"
            "cutoffs=height,mtp,epoch-capacity,positive-only\n"
            "cpu=one-through-600\n"
            "shop=issued,expires,amount,integer-or-string-nonce\n"
            "budget=manifest-derived,default-floor\n"
            "authority=caller-owned-spec-and-json,pure-validation,no-handler,no-latency-ring,no-publication\n%s\n",
    },
    { "zcode-package-view-contract.v1",
            "zcl.dev.hotfork.fixture.v1\n"
            "entry=identity,metadata,counts,invalid-incomplete\n"
            "guide=static-authority-boundaries,next-command\n"
            "publish=ready,needs-source,blocked,incomplete-reject\n"
            "contract=exact-service-id,frozen-kat\n"
            "authority=caller-owned-input,pure-service,no-cas,no-index,no-publication\n%s\n",
    },
    { "shop-status-view-contract.v1",
            "zcl.dev.hotfork.fixture.v1\n"
            "wallet=absent,plaintext,encrypted,unreadable\n"
            "closed=stub,no-identity,no-wallet,no-db,no-announcement\n"
            "live=real-tor,identity,encrypted-wallet,db,schema,announcement\n"
            "contract=exact-service-id,frozen-kat\n"
            "authority=copied-snapshot,pure-service,no-files,no-db,no-tor,no-wallet\n%s\n",
    },
    { "shop-reputation-view-contract.v1",
            "zcl.dev.hotfork.fixture.v1\n"
            "roots=present,absent,pair-exact,pair-mismatch\n"
            "evidence=releases,packages,observation,reproduction,attestation\n"
            "unavailable=availability,paid-fulfillment\n"
            "contract=exact-service-id,frozen-kat\n"
            "authority=copied-facts,pure-service,no-files,no-signatures,no-clock,no-ledger\n%s\n",
    },
    { "zcode-work-input-core.v1",
            "zcl.dev.hotfork.fixture.v1\n"
            "json=string-present,type-reject,int-present,fallback\n"
            "scopes=top-level,dedupe,header-source-test,empty-reject\n"
            "bytes=selected-manifest-members,missing-ignore,overflow-reject\n"
            "authority=caller-owned-input,pure-normalization,no-files,no-db,no-cas,no-process\n%s\n",
    },
    { "zcode-corpus-command-core.v1",
            "zcl.dev.hotfork.fixture.v1\n"
            "root=lowercase-64,uppercase-reject,length-reject\n"
            "checkpoint=total-loc,overflow-reject,null-reject\n"
            "shard=counted,durable,excluded,totals,overflow-reject\n"
            "authority=caller-owned-structs,pure-aggregation,no-storage,no-clock,no-service-publication\n%s\n",
    },
    { "devloop-watch-classification-core.v1",
            "zcl.dev.hotfork.fixture.v1\n"
            "sources=lowercase-c,header-reject,uppercase-reject,null-reject\n"
            "epoch=all-c,mixed-reject,empty-reject,null-reject\n"
            "component=same-owner,mixed-owner,root-path\n"
            "authority=copied-paths,pure-classification,no-filesystem,no-signals,no-process\n%s\n",
    },
    { "devloop-cycle-diagnostic-policy.v1",
            "zcl.dev.hotfork.fixture.v1\n"
            "diagnostic=first-actionable,transient-reject,compiler-shape\n"
            "preview=printable,control-sanitize,truncation,bounds-reject\n"
            "proof=passed-verify-only\n"
            "publish=verify,apply,invalid,port\n"
            "watcher=stopped,starting,runtime-starting,current\n"
            "authority=copied-text-and-enums,pure-policy,no-filesystem,no-process,no-publication\n%s\n",
    },
    { "devloop-plan-classification.v1",
            "zcl.dev.hotfork.fixture.v1\n"
            "paths=safe,traversal,absolute,control,docs,sealed,relevant,temp\n"
            "watch=mutation,attribute,ignored,source-dir\n"
            "dimensions=names,status-names\n"
            "authority=copied-paths-and-masks,pure-classification,no-index,no-filesystem,no-process\n%s\n",
    },
    { "native-dev-hotswap-receipt-policy.v1",
            "zcl.dev.hotfork.fixture.v1\n"
            "hooks=commit,probe,quiesce-off,quiesce-on\n"
            "module-report=green,refused\n"
            "service-report=green,restart-refused\n"
            "commit-boundary=empty-reject,capacity-reject\n"
            "probe-boundary=missing-leaf-reject\n%s\n",
    },
    { "native-dev-input-and-interrupt-policy.v1",
            "zcl.dev.hotfork.fixture.v1\n"
            "files=relative-valid,absolute-reject,traversal-reject\n"
            "cursor=integer,fallback,string-reject\n"
            "interrupt=STORY_RED,compile_red,proof_pending\n"
            "group=canonical,dash-reject\n"
            "generation=gen-lower64,legacy-lower64,uppercase-reject\n"
            "failure-id=lower64,uppercase-reject,short-reject\n%s\n",
    },
    { "curve25519-rfc7748-calculation.v1",
            "zcl.dev.hotfork.fixture.v1\n"
            "rfc7748=alice-public,alice-bob-shared-secret\n"
            "inputs=caller-owned,unchanged\n"
            "cleanup=module-local-cleanse-observed\n"
            "authority=pure-calculation,no-wallet,no-keys-from-host,no-rng,no-filesystem,no-network\n%s\n",
    },
    { "package-policy-boundary-calculation.v1",
            "zcl.dev.hotfork.fixture.v1\n"
            "tiers=names,limits,score-before-ratio\n"
            "ratio=zero-divisor,ordinary,saturating\n"
            "week=pre-epoch,epoch,monday\n"
            "boundaries=publish,download,concurrency,pin,announce,request-burst\n"
            "verifier=self,score,approval,allow\n"
            "names=no-credit,offence,unknown\n"
            "authority=pure-calculation,caller-owned-facts,no-clock,no-filesystem,no-network\n%s\n",
    },
};

static const char *hs_hotfork_fixture_template_for(const char *story_id)
{
    for (size_t i = 0;
         i < sizeof(k_hotfork_fixture_templates) /
             sizeof(k_hotfork_fixture_templates[0]); i++)
        if (strcmp(k_hotfork_fixture_templates[i].story_id, story_id) == 0)
            return k_hotfork_fixture_templates[i].fixture_text;
    return
        "zcl.dev.hotfork.fixture.v1\n"
        "result=ok,null-argument,package-incomplete,package-manifest,"
        "source-carrier-shape,package-chunk,source-verification,destination\n"
        "shard=0a,ff;reject=0A,100,missing-suffix\n%s\n";
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
    (void)snprintf(fixture, sizeof(fixture),
        hs_hotfork_fixture_template_for(def->story_id), def->story_id);
    hs_sha3_root(story, story_root);
    hs_sha3_root(fixture, fixture_root);
}

/* Renders one capsule's unity translation unit through the shared renderer
 * in hotfork_unity.h: the owner (and sibling) TUs bracketed by the story
 * adapter file tools/dev/hotfork_stories/<adapter_id>.inc. The adapter is
 * real C compiled with the resident action plan's DEV_CFLAGS (-Wall -Werror)
 * and by check-hotfork-stories on every lint-fast, so an owner API change
 * turns that gate red instead of silently disabling the story. `source_path`
 * is `<root>/<owner TU>`; the root prefix is recovered from it. */
static int hs_hotfork_unity_source(
    const struct hs_hotfork_def *def, const char *source_path,
    char *out, size_t out_size)
{
    size_t source_len = strlen(source_path);
    size_t owner_len = strlen(def->source_tu);
    char root[PATH_MAX];
    if (source_len <= owner_len || source_len - owner_len >= sizeof(root) ||
        strcmp(source_path + source_len - owner_len, def->source_tu) != 0)
        return -1;
    memcpy(root, source_path, source_len - owner_len);
    root[source_len - owner_len] = 0;
    return zcl_hotfork_unity_render(root, def->source_tu, def->sibling_tus,
                                    def->adapter_id, def->exercised_surface,
                                    out, out_size);
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
    if (!repo_root || !def ||
        !platform_directory_canonical_real(repo_root, root, sizeof(root)) ||
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
    char unity_text[ZCL_HOTFORK_UNITY_MAX];
    int unity_n = hs_hotfork_unity_source(
        def, source_path, unity_text, sizeof(unity_text));
    if (unity_n <= 0 || unity_n >= (int)sizeof(unity_text)) {
        hs_why(why, why_len, "HOT_FORK capsule unity did not resolve");
        goto fail;
    }
    if (!hs_write_generated(unity, unity_text, why, why_len))
        goto fail;
    char adapter_root[65];
    hs_sha3_root(unity_text, adapter_root);
    if (snprintf(key_owner, sizeof(key_owner), "HOT_FORK:%s:%s",
                 def->source_tu, adapter_root) >= (int)sizeof(key_owner) ||
        snprintf(cached_dep, sizeof(cached_dep),
                 "%s/build/hotswap-fast/%s-%s.hotfork.d", root, safe,
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
    zcl_devloop_action_root_hotfork(root, def->source_tu, plan.cc, plan.cflags,
                                    unity, cached_dep, receipt);
    (void)unlink(unity); (void)unlink(descriptor);
    (void)unlink(candidate_obj); (void)unlink(descriptor_obj);
    if (dep[0]) (void)unlink(dep);
    (void)unlink(descriptor_dep); (void)unlink(version_script); (void)unlink(so);
    return true;

fail:
    if (cache_fd >= 0) {
        (void)flock(cache_fd, LOCK_UN); (void)close(cache_fd);
    }
    zcl_devloop_action_root_hotfork(root, def->source_tu, plan.cc, plan.cflags,
                                    unity, NULL, receipt);
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

static size_t hs_resident_call_params(const char *artifact, bool activate,
                                      char *out, size_t out_size)
{
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
    size_t n = json_write(&params, out, out_size);
    json_free(&params);
    return n;
}

/* Validate a parsed resident response: it must report ok, and when the
 * caller asked to activate the candidate the resident must confirm it did. */
static bool hs_resident_response_ok(const struct json_value *response,
                                    bool activate, char *why, size_t why_len)
{
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
    char params_json[PATH_MAX + 64];
    size_t params_n = hs_resident_call_params(artifact, activate, params_json,
                                              sizeof(params_json));
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
    return hs_resident_response_ok(response, activate, why, why_len);
}

/* Candidate stories never execute in this process, and never in a fork of it.
 * HOT_SHADOW and HOT_FORK both hand the exact sealed image to the clean-zygote
 * reflex runner (devloop_reflex_runner.h): a fresh exec of this image with an
 * empty environment and one control socket, whose disposable child confines
 * itself BEFORE mapping candidate bytes. Frozen contracts and fixtures are the
 * runner's own copies from this same image. No RPC, node, wallet, SQLite,
 * network, publication, or full-program link exists on this path, and an
 * unavailable runner is an unavailable story, never an unconfined one.
 *
 * The stage fields below (load_or_spawn_us/execute_us/module_hash_us) keep
 * the same JSON contract a resident-fork prior version wrote, for
 * tools/dev/reflex-reactor-bench.sh's stage breakdown: load_or_spawn_us is
 * everything before the story runs (runner fork + confinement + dlopen),
 * execute_us is the story itself, and module_hash_us is the sealed image's
 * one digest computation, which now happens once in this process before the
 * runner ever sees the artifact (zcl_reflex_runner_outcome.seal_us) rather
 * than again inside a resident fork. */
static void hs_shadow_append_metrics(struct json_value *response,
                                     const struct zcl_reflex_runner_outcome *run,
                                     bool valid)
{
    (void)json_push_kv_int(response, "load_or_spawn_us",
                           valid ? run->fork_us + run->confine_us +
                                   run->dlopen_us : 0);
    (void)json_push_kv_int(response, "execute_us",
                           valid ? run->story_us : 0);
    (void)json_push_kv_int(response, "module_hash_us",
                           valid ? run->seal_us : 0);
}
static void hs_sha3_root(const char *text, char out[65])
{
    uint8_t digest[32];
    sha3_256((const uint8_t *)text, strlen(text), digest);
    zcl_hex_encode(digest, sizeof(digest), out);
}

#if !defined(_WIN32)
static const char *hs_runner_status(bool ok,
                                    const struct zcl_reflex_runner_outcome *run)
{
    if (ok) return "green";
    return run->available ? "red" : "unavailable";
}

static bool hs_runner_forked(const struct zcl_reflex_runner_outcome *run)
{
    return run->available && (run->report_complete || run->child_signal != 0 ||
                              run->child_exit_code >= 0);
}

/* Measured isolation and stage timings, identical for both story kinds. */
static void hs_runner_receipt(struct json_value *response,
                              const struct zcl_reflex_runner_outcome *run)
{
    const struct zcl_reflex_child_report *r = &run->report;
    (void)json_push_kv_str(response, "runner", "zygote_exec");
    (void)json_push_kv_bool(response, "runner_available", run->available);
    (void)json_push_kv_bool(response, "runner_warm", run->runner_warm);
    (void)json_push_kv_int(response, "runner_pid", run->runner_pid);
    (void)json_push_kv_int(response, "runner_deny_probes_killed",
                           run->runner_deny_probes);
    (void)json_push_kv_int(response, "env_inherited_count",
                           run->env_inherited_count);
    (void)json_push_kv_int(response, "inherited_fd_count",
                           run->inherited_fd_count);
    (void)json_push_kv_bool(response, "address_space_fresh",
                            run->address_space_fresh);
    (void)json_push_kv_bool(response, "sealed_image", run->seals_verified);
    (void)json_push_kv_bool(response, "sandboxed", r->sandboxed);
    (void)json_push_kv_bool(response, "network_blocked", r->sandboxed);
    (void)json_push_kv_bool(response, "datadir_blocked", r->sandboxed);
    (void)json_push_kv_bool(response, "confined_before_load", r->sandboxed);
    (void)json_push_kv_bool(response, "wx_enforced", r->wx_installed);
    (void)json_push_kv_int(response, "runner_spawn_us", run->spawn_us);
    (void)json_push_kv_int(response, "runner_seal_us", run->seal_us);
    (void)json_push_kv_int(response, "runner_fork_us", run->fork_us);
    (void)json_push_kv_int(response, "runner_confine_us", run->confine_us);
    (void)json_push_kv_int(response, "runner_dlopen_us", run->dlopen_us);
    (void)json_push_kv_int(response, "runner_story_us", run->story_us);
    (void)json_push_kv_int(response, "runner_total_us", run->runner_total_us);
    (void)json_push_kv_int(response, "child_signal", run->child_signal);
    (void)json_push_kv_int(response, "child_exit_code", run->child_exit_code);
}

static bool hs_shadow_roots(const char *source, const char *story_id,
                            const struct zcl_reflex_runner_outcome *run,
                            bool valid, char story_root[65],
                            char fixture_root[65], char observation_root[65])
{
    const struct zcl_hotswap_service_report *svc = &run->report.service;
    const char *service_id = valid ? svc->service_id : "invalid";
    char story_preimage[768], fixture_preimage[512], observation[768];
    int story_n = snprintf(story_preimage, sizeof(story_preimage),
        "zcl.dev.story.v1\n%s\n%s\n%s\n", source, story_id, service_id);
    int fixture_n = snprintf(fixture_preimage, sizeof(fixture_preimage),
        "zcl.dev.story.fixture.v1\n%s\n%s\n", story_id, service_id);
    int observation_n = snprintf(observation, sizeof(observation),
        "zcl.dev.story.observation.v1\n%s\n%s\n%d\n%d\n%d\n%d\n%s\n",
        service_id, valid ? svc->stage : "invalid", svc->recognized, svc->ok,
        svc->verify_only, svc->probed, run->report.runtime_module_sha256);
    if (story_n <= 0 || story_n >= (int)sizeof(story_preimage) ||
        fixture_n <= 0 || fixture_n >= (int)sizeof(fixture_preimage) ||
        observation_n <= 0 || observation_n >= (int)sizeof(observation))
        return false;
    hs_sha3_root(story_preimage, story_root);
    hs_sha3_root(fixture_preimage, fixture_root);
    hs_sha3_root(observation, observation_root);
    return true;
}

static void hs_shadow_failure(const struct zcl_reflex_runner_outcome *run,
                              bool valid, char *out, size_t out_len)
{
    const char *service_error = run->report.service.error;
    if (run->cancelled)
        (void)snprintf(out, out_len, "shadow story superseded");
    else if (run->timed_out)
        (void)snprintf(out, out_len, "shadow story exceeded 1000 ms");
    else if (!run->available)
        (void)snprintf(out, out_len, "reflex runner unavailable: %s",
                       run->reason[0] ? run->reason : "unknown");
    else if (valid && service_error[0])
        (void)snprintf(out, out_len, "%s", service_error);
    else if (run->reason[0])
        (void)snprintf(out, out_len, "%s", run->reason);
    else
        (void)snprintf(out, out_len, "shadow story worker returned no valid "
                                     "frozen-KAT receipt");
}

static void hs_shadow_receipt_body(
    struct json_value *response, const char *source, const char *story_id,
    const struct zcl_devloop_hotswap_build_receipt *build,
    const struct zcl_reflex_runner_outcome *run, bool ok, bool valid)
{
    const struct zcl_reflex_child_report *r = &run->report;
    (void)json_push_kv_str(response, "schema", "zcl.dev_shadow_story.v2");
    (void)json_push_kv_str(response, "mode", "HOT_SHADOW_CORE");
    (void)json_push_kv_str(response, "feedback_class", "HOT_SHADOW_CORE");
    (void)json_push_kv_str(response, "status", hs_runner_status(ok, run));
    (void)json_push_kv_bool(response, "forked", hs_runner_forked(run));
    (void)json_push_kv_bool(response, "exec_process", false);
    (void)json_push_kv_bool(response, "activated", false);
    (void)json_push_kv_bool(response, "forbidden_effects_absent",
                            run->available && r->sandboxed);
    (void)json_push_kv_str(response, "candidate_object_root",
                           build->candidate_object_sha256);
    (void)json_push_kv_str(response, "candidate_module_root",
                           build->artifact_sha256);
    (void)json_push_kv_str(response, "loaded_mapping_root",
                           r->runtime_module_sha256);
    (void)json_push_kv_bool(response, "candidate_bytes_executed",
                            valid && r->candidate_executed);
    hs_shadow_append_metrics(response, run, valid);
    (void)json_push_kv_str(response, "story_id", story_id);
    (void)json_push_kv_str(response, "exercised_owner_surface", source);
}

static bool hs_shadow_receipt(
    const char *source, const char *story_id,
    const struct zcl_devloop_hotswap_build_receipt *build,
    const struct zcl_reflex_runner_outcome *run, int64_t elapsed_us,
    struct json_value *response, char *why, size_t why_len)
{
    const struct zcl_reflex_child_report *r = &run->report;
    bool valid = run->available && run->report_complete &&
        strcmp(r->runtime_module_sha256, build->artifact_sha256) == 0;
    char story_root[65] = {0}, fixture_root[65] = {0};
    char observation_root[65] = {0};
    bool ok = hs_shadow_roots(source, story_id, run, valid, story_root,
                              fixture_root, observation_root) && run->green;
    json_init(response); json_set_object(response);
    hs_shadow_receipt_body(response, source, story_id, build, run, ok, valid);
    (void)json_push_kv_str(response, "story_root", story_root);
    (void)json_push_kv_str(response, "story_fixture_root", fixture_root);
    (void)json_push_kv_str(response, "observation_root", observation_root);
    (void)json_push_kv_int(response, "elapsed_us", elapsed_us);
    hs_runner_receipt(response, run);
    if (valid) {
        (void)json_push_kv_str(response, "service_id", r->service.service_id);
        (void)json_push_kv_str(response, "probe_stage", r->service.stage);
    }
    if (!ok) {
        char message[256];
        hs_shadow_failure(run, valid, message, sizeof(message));
        hs_why(why, why_len, message);
        (void)json_push_kv_str(response, "error", message);
    }
    return ok;
}
#endif /* !_WIN32 */

static bool hs_shadow_probe(
                            const char *source,
                            const struct zcl_devloop_hotswap_build_receipt *build,
                            struct json_value *response,
                            int64_t *elapsed_us,
                            char *why, size_t why_len)
{
#if defined(_WIN32)
    /* The shadow story runs only in the Linux clean-zygote reflex runner
     * (exec'd runner, sealed memfd, Landlock/seccomp child, ELF module);
     * none of that exists on this lane. Report unavailable honestly —
     * never a fake green or red story. */
    (void)source;
    (void)build;
    if (elapsed_us) *elapsed_us = 0;
    json_init(response); json_set_object(response);
    (void)json_push_kv_str(response, "schema", "zcl.dev_shadow_story.v2");
    (void)json_push_kv_str(response, "mode", "HOT_SHADOW_CORE");
    (void)json_push_kv_str(response, "feedback_class", "HOT_SHADOW_CORE");
    (void)json_push_kv_str(response, "status", "unavailable");
    (void)json_push_kv_bool(response, "forked", false);
    const char *message = "shadow runner unavailable on Windows "
                          "(fork + ELF module probe)";
    hs_why(why, why_len, message);
    (void)json_push_kv_str(response, "error", message);
    return false;
#else
    int64_t started = platform_time_monotonic_us();
    const char *story_id = source
        ? zcl_hotswap_service_probe_for_source(source) : NULL;
    if (!source || !story_id || !story_id[0] || !build ||
        strlen(build->candidate_object_sha256) != 64 ||
        strlen(build->artifact_sha256) != 64 || !response || !elapsed_us) {
        hs_why(why, why_len, "shadow runner input invalid");
        return false;
    }
    const struct zcl_reflex_runner_spec spec = {
        .mode = ZCL_REFLEX_MODE_HOT_SHADOW,
        .artifact_path = build->artifact_path,
        .artifact_sha256 = build->artifact_sha256,
        .owner_id = story_id,
        .source_tu = source,
        .candidate_object_root = build->candidate_object_sha256,
        .story_id = story_id,
        .timeout_ms = 1000,
    };
    struct zcl_reflex_runner_outcome run;
    (void)zcl_reflex_runner_run(&spec, &run);
    *elapsed_us = platform_time_monotonic_us() - started;
    return hs_shadow_receipt(source, story_id, build, &run, *elapsed_us,
                             response, why, why_len);
#endif
}

static bool hs_hotfork_descriptor_identity_matches(
    const struct zcl_hotfork_capsule_v1 *capsule,
    const struct hs_hotfork_def *def,
    const struct zcl_devloop_hotswap_build_receipt *build)
{
    return capsule && capsule->abi_version == ZCL_HOTFORK_CAPSULE_ABI_V1 &&
        capsule->descriptor_size == sizeof(*capsule) && capsule->owner_id &&
        strcmp(capsule->owner_id, def->owner_id) == 0 && capsule->source_tu &&
        strcmp(capsule->source_tu, def->source_tu) == 0 &&
        capsule->candidate_object_root &&
        strcmp(capsule->candidate_object_root,
               build->candidate_object_sha256) == 0;
}

static bool hs_hotfork_descriptor_story_matches(
    const struct zcl_hotfork_capsule_v1 *capsule,
    const struct hs_hotfork_def *def)
{
    char story_root[65], fixture_root[65];
    hs_hotfork_story_roots(def, story_root, fixture_root);
    return capsule->story_id && strcmp(capsule->story_id, def->story_id) == 0 &&
        capsule->story_root && strcmp(capsule->story_root, story_root) == 0 &&
        capsule->story_fixture_root &&
        strcmp(capsule->story_fixture_root, fixture_root) == 0 &&
        capsule->run_story;
}

static bool hs_hotfork_descriptor_matches(
    const struct zcl_hotfork_capsule_v1 *capsule,
    const struct hs_hotfork_def *def,
    const struct zcl_devloop_hotswap_build_receipt *build)
{
    return hs_hotfork_descriptor_identity_matches(capsule, def, build) &&
        hs_hotfork_descriptor_story_matches(capsule, def);
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

#if !defined(_WIN32)
static void hs_hotfork_process_failure(
    const struct hs_hotfork_def *def,
    const struct zcl_reflex_runner_outcome *run, char *out, size_t out_len)
{
    if (run->cancelled)
        (void)snprintf(out, out_len, "HOT_FORK story superseded");
    else if (run->timed_out)
        (void)snprintf(out, out_len, "HOT_FORK story exceeded %u ms",
                       def->max_time_ms);
    else if (!run->available)
        (void)snprintf(out, out_len, "HOT_FORK runner unavailable: %s",
                       run->reason[0] ? run->reason : "unknown");
    else if (run->child_signal)
        (void)snprintf(out, out_len, "HOT_FORK child terminated by signal %d",
                       run->child_signal);
    else if (run->child_exit_code > 0)
        (void)snprintf(out, out_len, "HOT_FORK child exited with code %d",
                       run->child_exit_code);
    else
        out[0] = '\0';
}

static const char *hs_hotfork_candidate_failure(
    const struct zcl_reflex_runner_outcome *run,
    const struct zcl_devloop_hotswap_build_receipt *build)
{
    const struct zcl_reflex_child_report *r = &run->report;
    if (!run->report_complete ||
        strcmp(r->runtime_module_sha256, build->artifact_sha256) != 0)
        return "HOT_FORK child returned no valid bounded receipt";
    if (!r->sandboxed) return "HOT_FORK authority sandbox unavailable";
    if (!r->descriptor_valid) return "HOT_FORK descriptor binding mismatch";
    if (!r->wx_installed) return "HOT_FORK W^X layer unavailable";
    if (!run->address_space_fresh || run->env_inherited_count ||
        run->inherited_fd_count)
        return "HOT_FORK runner isolation not proven";
    return "HOT_FORK candidate story rejected its frozen fixture";
}

static void hs_hotfork_receipt_body(
    struct json_value *response, const struct hs_hotfork_def *def,
    const struct zcl_devloop_hotswap_build_receipt *build,
    const struct zcl_reflex_runner_outcome *run, bool ok)
{
    const struct zcl_reflex_child_report *r = &run->report;
    (void)json_push_kv_str(response, "schema", "zcl.dev_hotfork_story.v1");
    (void)json_push_kv_str(response, "mode", "HOT_FORK");
    (void)json_push_kv_str(response, "feedback_class", def->feedback_class);
    (void)json_push_kv_str(response, "status", hs_runner_status(ok, run));
    (void)json_push_kv_bool(response, "forked", hs_runner_forked(run));
    (void)json_push_kv_bool(response, "activated", false);
    (void)json_push_kv_bool(response, "forbidden_effects_absent", ok);
    (void)json_push_kv_str(response, "candidate_object_root",
                           build->candidate_object_sha256);
    (void)json_push_kv_str(response, "candidate_module_root",
                           build->artifact_sha256);
    (void)json_push_kv_str(response, "loaded_mapping_root",
                           r->runtime_module_sha256);
    (void)json_push_kv_bool(response, "candidate_bytes_executed",
                            r->candidate_executed);
    (void)json_push_kv_str(response, "story_id", def->story_id);
    (void)json_push_kv_str(response, "story_fixture_id", def->fixture_id);
    (void)json_push_kv_str(response, "story_adapter", def->adapter_id);
    (void)json_push_kv_int(response, "story_timeout_ms", def->max_time_ms);
    (void)json_push_kv_str(response, "forbidden_effect_mask",
                           def->forbidden_effect_mask);
    (void)json_push_kv_str(response, "exercised_owner_surface",
                           def->exercised_surface);
    (void)json_push_kv_int(response, "story_checks_run",
                           r->observation.checks_run);
    (void)json_push_kv_int(response, "story_checks_passed",
                           r->observation.checks_passed);
    (void)json_push_kv_str(response, "story_detail", r->observation.detail);
}

static bool hs_hotfork_receipt(
    const struct hs_hotfork_def *def,
    const struct zcl_devloop_hotswap_build_receipt *build,
    const struct zcl_reflex_runner_outcome *run, int64_t elapsed_us,
    struct json_value *response, char *why, size_t why_len)
{
    const struct zcl_reflex_child_report *r = &run->report;
    bool ok = run->green &&
        strcmp(r->observation.exercised_surface, def->exercised_surface) == 0;
    char story_root[65], fixture_root[65], observation_root[65];
    hs_hotfork_story_roots(def, story_root, fixture_root);
    char observation[768];
    (void)snprintf(observation, sizeof(observation),
        "zcl.dev.hotfork.observation.v1\n%s\n%u\n%u\n%s\n%s\n",
        def->owner_id, r->observation.checks_run,
        r->observation.checks_passed, r->observation.exercised_surface,
        r->observation.detail);
    hs_sha3_root(observation, observation_root);
    json_init(response); json_set_object(response);
    hs_hotfork_receipt_body(response, def, build, run, ok);
    (void)json_push_kv_str(response, "story_root", story_root);
    (void)json_push_kv_str(response, "story_fixture_root", fixture_root);
    (void)json_push_kv_str(response, "observation_root", observation_root);
    (void)json_push_kv_int(response, "elapsed_us", elapsed_us);
    hs_runner_receipt(response, run);
    if (!ok) {
        char message[256];
        hs_hotfork_process_failure(def, run, message, sizeof(message));
        if (!message[0])
            (void)snprintf(message, sizeof(message), "%s",
                           hs_hotfork_candidate_failure(run, build));
        hs_why(why, why_len, message);
        (void)json_push_kv_str(response, "error", message);
    }
    return ok;
}

static bool hs_hotfork_probe(
    const struct hs_hotfork_def *def,
    const struct zcl_devloop_hotswap_build_receipt *build,
    struct json_value *response, int64_t *elapsed_us,
    char *why, size_t why_len)
{
    int64_t started = platform_time_monotonic_us();
    if (!def || !build || !response || !elapsed_us) {
        hs_why(why, why_len, "HOT_FORK input invalid");
        return false;
    }
    char story_root[65], fixture_root[65];
    hs_hotfork_story_roots(def, story_root, fixture_root);
    const struct zcl_reflex_runner_spec spec = {
        .mode = ZCL_REFLEX_MODE_HOT_FORK,
        .artifact_path = build->artifact_path,
        .artifact_sha256 = build->artifact_sha256,
        .owner_id = def->owner_id,
        .source_tu = def->source_tu,
        .candidate_object_root = build->candidate_object_sha256,
        .story_id = def->story_id,
        .story_root = story_root,
        .story_fixture_root = fixture_root,
        .timeout_ms = def->max_time_ms,
    };
    struct zcl_reflex_runner_outcome run;
    (void)zcl_reflex_runner_run(&spec, &run);
    *elapsed_us = platform_time_monotonic_us() - started;
    return hs_hotfork_receipt(def, build, &run, *elapsed_us, response, why,
                              why_len);
}
#else /* _WIN32 */
/* HOT_FORK candidates run only in a confined child of the Linux
 * clean-zygote reflex runner; none of that machinery exists on this lane.
 * Report unavailable honestly. */
static bool hs_hotfork_probe(
    const struct hs_hotfork_def *def,
    const struct zcl_devloop_hotswap_build_receipt *build,
    struct json_value *response, int64_t *elapsed_us,
    char *why, size_t why_len)
{
    (void)def;
    (void)build;
    if (elapsed_us) *elapsed_us = 0;
    json_init(response); json_set_object(response);
    (void)json_push_kv_str(response, "schema", "zcl.dev_hotfork_story.v2");
    (void)json_push_kv_str(response, "status", "unavailable");
    (void)json_push_kv_bool(response, "forked", false);
    const char *message = "HOT_FORK runner unavailable on Windows "
                          "(clean-zygote runner + seccomp/landlock + ELF module)";
    hs_why(why, why_len, message);
    (void)json_push_kv_str(response, "error", message);
    return false;
}
#endif

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

static bool hs_proof_handoff_args_valid(
    const char *source, const char *source_epoch, size_t changed_path_count,
    const struct zcl_devloop_hotswap_build_receipt *build,
    const struct json_value *resident, const struct json_value *out)
{
    return source && source_epoch && strlen(source_epoch) == 64 && build &&
        build->artifact_sha256[0] && resident &&
        resident->type == JSON_OBJ && out && changed_path_count != 0 &&
        changed_path_count <= UINT32_MAX &&
        hs_story_receipt_valid(source, build, resident);
}

static bool hs_proof_handoff_emit_identity(
    struct json_value *out, const struct dev_reflex_proof_handoff_v2 *handoff)
{
    return json_push_kv_str(out, "schema", "zcl.dev_proof_handoff.v2") &&
        json_push_kv_str(out, "candidate_epoch", handoff->candidate_epoch) &&
        json_push_kv_str(out, "source_epoch", handoff->source_epoch) &&
        json_push_kv_str(out, "affected_component",
                         handoff->affected_component) &&
        json_push_kv_str(out, "action", handoff->action) &&
        json_push_kv_str(out, "proof_inputs_sha3",
                         handoff->proof_inputs_sha3) &&
        json_push_kv_str(out, "focused_evidence_sha3",
                         handoff->focused_evidence_sha3) &&
        json_push_kv_str(out, "feedback_class", handoff->feedback_class);
}

static bool hs_proof_handoff_emit_evidence(
    struct json_value *out, const struct dev_reflex_proof_handoff_v2 *handoff)
{
    return json_push_kv_str(out, "candidate_object_root",
                            handoff->candidate_object_root) &&
        json_push_kv_str(out, "candidate_module_root",
                         handoff->candidate_module_root) &&
        json_push_kv_str(out, "story_root", handoff->story_root) &&
        json_push_kv_str(out, "story_fixture_root",
                         handoff->story_fixture_root) &&
        json_push_kv_str(out, "observation_root",
                         handoff->observation_root) &&
        json_push_kv_int(out, "affected_file_count",
                         handoff->affected_file_count) &&
        json_push_kv_bool(out, "compile_green", true) &&
        json_push_kv_bool(out, "story_obtained", true) &&
        json_push_kv_bool(out, "reflex_final", true);
}

static bool hs_proof_handoff_emit(
    struct json_value *out, const struct dev_reflex_proof_handoff_v2 *handoff)
{
    return hs_proof_handoff_emit_identity(out, handoff) &&
        hs_proof_handoff_emit_evidence(out, handoff);
}

static bool hs_proof_handoff(
    const char *source, size_t changed_path_count,
    const struct zcl_devloop_hotswap_build_receipt *build,
    const struct json_value *resident, struct json_value *out)
{
    const char *source_epoch = zcl_devloop_event_edit_epoch();
    if (!hs_proof_handoff_args_valid(source, source_epoch, changed_path_count,
                                     build, resident, out))
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
    return hs_proof_handoff_emit(out, &handoff);
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
    (void)json_push_kv_int(&doc, "event_monotonic_us",
                           platform_time_monotonic_us());
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
        zcl_devloop_action_root_emit(&receipt, build);
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
        path_count > ZCL_DEVLOOP_WATCH_MAX_FILES)
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
            owner, "contexts/wallet/services/src/vault_intent_decision_service.c") == 0;
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

static int hs_hotfork_owner_story_event(
    const char *repo_root, const struct hs_hotfork_def *def,
    struct zcl_devloop_hotswap_build_receipt *build,
    struct zcl_devloop_process_result *process, int64_t started)
{
    struct json_value resident;
    json_init(&resident);
    int64_t story_us = 0;
    char why[512] = {0};
    bool story_ok = hs_hotfork_probe(def, build, &resident, &story_us,
                                     why, sizeof(why));
    if (zcl_devloop_process_cancel_requested()) {
        json_free(&resident);
        return ZCL_DEVLOOP_RESTART_EVENT_CANCELLED;
    }
    bool emitted = hs_emit_event(
        repo_root, def->source_tu, 1,
        story_ok ? "story_green" : "story_red", "hotfork_owner_story",
        false, platform_time_monotonic_us() - started, build, story_us,
        &resident, process, why, true);
    json_free(&resident);
    if (!emitted) return -1;
    return story_ok ? ZCL_DEVLOOP_RESTART_EVENT_PROOF_PENDING
                    : ZCL_DEVLOOP_RESTART_EVENT_FINAL;
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
    return hs_hotfork_owner_story_event(repo_root, def, &build, &process,
                                        started);
}

int zcl_devloop_hotswap_event(const char *repo_root, const char *source_tu,
                              enum zcl_devloop_publish_mode publish_mode)
{
    const char *paths[] = {source_tu};
    return zcl_devloop_hotswap_batch_event(repo_root, paths, 1,
                                           publish_mode);
}
