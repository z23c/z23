/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Content-addressed storage of zcl.action_preimage.v2 objects, the per-unit
 * "what changed since last time" cause, and the hotload compile hook that
 * reports an action_root in every hot-swap build receipt, and the same
 * derivation (never stored) that the hot-swap artifact cache key binds.
 * Nothing here changes what the build runs.
 */

#if !defined(_WIN32)
#define _GNU_SOURCE
#endif

#include "devloop_action_root.h"

#include "devloop.h"

#include "base/hex.h"
#include "base/safe_alloc.h"
#include "hotswap/hotfork_capsule.h"
#include "hotswap/hotswap.h"
#include "hotswap/hotswap_module.h"
#include "hotswap/hotswap_service.h"
#include "json/json.h"
#include "platform/directory_compat.h"
#include "platform/path_compat.h"
#include "platform/time_compat.h"
#include "sha3/sha3.h"
#include "util/spawn.h"

#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif
#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif
#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

#define ARS_ARG_MAX 512
#define ARS_SYSTEM_DIR_MAX 32

static void ars_why(char *why, size_t len, const char *what, const char *arg)
{
    if (why && len && !why[0])
        (void)snprintf(why, len, "%s%s%.150s", what, arg ? ": " : "",
                       arg ? arg : "");
}

/* ---- content store ----------------------------------------------------- */

static bool ars_mkdirs(char *path)
{
    for (char *p = path + 1; *p; p++) {
        if (*p != '/')
            continue;
        *p = '\0';
        bool ok = platform_directory_ensure(path, 0700);
        *p = '/';
        if (!ok)
            return false;
    }
    return platform_directory_ensure(path, 0700);
}

bool zcl_action_root_store_dir(char *out, size_t cap)
{
    const char *configured = getenv("ZCL_DEV_ARTIFACT_CACHE");
#if defined(_WIN32)
    const char *home = getenv("USERPROFILE");
#else
    const char *home = getenv("HOME");
#endif
    int n = -1;
    if (configured && configured[0]) {
        if (platform_path_is_absolute(configured) && !strstr(configured, ".."))
            n = snprintf(out, cap, "%s/%s", configured,
                         ZCL_ACTION_ROOT_STORE_LANE);
    } else if (home && platform_path_is_absolute(home)) {
        n = snprintf(out, cap, "%s/.cache/zclassic23/dev-artifacts/%s", home,
                     ZCL_ACTION_ROOT_STORE_LANE);
    }
    return n > 0 && (size_t)n < cap && ars_mkdirs(out);
}

/* Write-then-rename so a reader never sees a partial object. */
static bool ars_write_atomic(const char *path, const void *data, size_t len)
{
    char temp[PATH_MAX];
    if (snprintf(temp, sizeof(temp), "%s.tmp-XXXXXX", path) >=
        (int)sizeof(temp))
        return false;
    int fd = mkstemp(temp);
    if (fd < 0)
        return false;
    const uint8_t *p = data;
    size_t done = 0;
    while (done < len) {
        ssize_t w = write(fd, p + done, len - done);
        if (w <= 0)
            break;
        done += (size_t)w;
    }
    bool ok = close(fd) == 0 && done == len && rename(temp, path) == 0;
    if (!ok)
        (void)unlink(temp);
    return ok;
}

static uint8_t *ars_read(const char *path, size_t max, size_t *len)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    struct stat st;
    if (fd < 0)
        return NULL;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size <= 0 ||
        (uint64_t)st.st_size > max) {
        close(fd);
        return NULL;
    }
    size_t want = (size_t)st.st_size, done = 0;
    uint8_t *buf = zcl_malloc(want, "action root stored object");
    while (buf && done < want) {
        ssize_t r = read(fd, buf + done, want - done);
        if (r <= 0)
            break;
        done += (size_t)r;
    }
    close(fd);
    if (!buf || done != want) {
        free(buf);
        return NULL;
    }
    *len = want;
    return buf;
}

static bool ars_hex64(const char *hex)
{
    uint8_t raw[32];
    return hex && strlen(hex) == 64 && zcl_hex_decode_lower(hex, raw, 32);
}

static bool ars_object_path(const char *store_dir, const char *root_hex,
                            char out[PATH_MAX])
{
    return ars_hex64(root_hex) &&
           snprintf(out, PATH_MAX, "%s/%s.preimage", store_dir, root_hex) <
               PATH_MAX;
}

bool zcl_action_root_load(const char *store_dir, const char *root_hex,
                          uint8_t **bytes, size_t *len,
                          char *why, size_t why_len)
{
    char path[PATH_MAX];
    uint8_t root[32];
    char derived[65];
    *bytes = NULL;
    *len = 0;
    if (!store_dir || !ars_object_path(store_dir, root_hex, path)) {
        ars_why(why, why_len, "stored preimage name is invalid", root_hex);
        return false;
    }
    uint8_t *data = ars_read(path, VCS_ACTION_PREIMAGE_V2_MAX_BYTES, len);
    if (!data || !vcs_action_root_v2_from_bytes(data, *len, root, why,
                                                why_len)) {
        free(data);
        ars_why(why, why_len, "stored preimage is unreadable or invalid",
                root_hex);
        return false;
    }
    zcl_hex_encode(root, 32, derived);
    if (strcmp(derived, root_hex) != 0) {
        free(data);
        ars_why(why, why_len, "stored preimage does not re-derive its name",
                root_hex);
        return false;
    }
    *bytes = data;
    return true;
}

/* Map a repo-relative unit path to one safe file-name component. */
static bool ars_safe_name(const char *unit, char safe[256])
{
    size_t n = unit ? strlen(unit) : 0;
    if (n == 0 || n >= 256)
        return false;
    for (size_t i = 0; i <= n; i++) {
        unsigned char c = (unsigned char)unit[i];
        bool keep = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                    (c >= '0' && c <= '9') || c == '.' || c == '-' || !c;
        safe[i] = keep ? (char)c : '_';
    }
    return true;
}

/* Safe single-component file name for one unit (repo-relative path). */
static bool ars_unit_file(const char *store_dir, const char *unit,
                          char out[PATH_MAX])
{
    char safe[256], dir[PATH_MAX];
    return ars_safe_name(unit, safe) &&
           snprintf(dir, sizeof(dir), "%s/last", store_dir) <
               (int)sizeof(dir) && ars_mkdirs(dir) &&
           snprintf(out, PATH_MAX, "%s/%s.root", dir, safe) < PATH_MAX;
}

static void ars_cause(const char *store_dir, const char *previous,
                      const struct zcl_action_root_result *result,
                      char *cause, size_t cause_len)
{
    uint8_t *old = NULL;
    size_t old_len = 0;
    enum vcs_action_field_v2 field = VCS_ACTION_FIELD_V2_NONE;
    const char *text = "previous_unreadable";
    if (!previous[0])
        text = "first";
    else if (strcmp(previous, result->root_hex) == 0)
        text = "hit";
    else if (zcl_action_root_load(store_dir, previous, &old, &old_len, NULL,
                                  0) &&
             vcs_action_preimage_v2_first_diff(old, old_len,
                                               result->preimage,
                                               result->preimage_len, &field) &&
             vcs_action_field_v2_name(field))
        text = vcs_action_field_v2_name(field);
    free(old);
    (void)snprintf(cause, cause_len, "%s", text);
}

bool zcl_action_root_record(const char *store_dir, const char *unit,
                            const struct zcl_action_root_result *result,
                            char *cause, size_t cause_len,
                            char *why, size_t why_len)
{
    char object[PATH_MAX], last[PATH_MAX], previous[65] = {0};
    struct stat st;
    if (!store_dir || !result || !result->preimage || !cause ||
        !ars_object_path(store_dir, result->root_hex, object) ||
        !ars_unit_file(store_dir, unit, last)) {
        ars_why(why, why_len, "action root store path unavailable", unit);
        return false;
    }
    if (stat(object, &st) != 0 &&
        !ars_write_atomic(object, result->preimage, result->preimage_len)) {
        ars_why(why, why_len, "could not store action preimage", object);
        return false;
    }
    size_t prev_len = 0;
    uint8_t *prev = ars_read(last, 65, &prev_len);
    if (prev && prev_len == 65 && prev[64] == '\n') {
        memcpy(previous, prev, 64);
        if (!ars_hex64(previous))
            previous[0] = '\0';
    }
    free(prev);
    ars_cause(store_dir, previous, result, cause, cause_len);
    char line[66];
    (void)snprintf(line, sizeof(line), "%s\n", result->root_hex);
    if (!ars_write_atomic(last, line, 65)) {
        ars_why(why, why_len, "could not record latest action root", last);
        return false;
    }
    return true;
}

/* ---- hotload compile hook ---------------------------------------------- */

/* What the compiler driver reports about itself, asked once per driver:
 * its built-in #include <...> list, its sysroot, and the ld / collect2 it
 * runs for a link. */
#define ARS_TARGETS_MAX 1024

/* Libraries a -shared link pulls in without naming them; their bytes are
 * bound beside the capsule's crt/libgcc/libc.so.6. */
static const char *const k_ars_implicit[] = {
    "libc.so", "libc.so.6", "libc_nonshared.a", "libgcc.a", "libgcc_s.so",
    "libgcc_s.so.1",
};
#define ARS_IMPLICIT_N (sizeof(k_ars_implicit) / sizeof(k_ars_implicit[0]))

struct ars_driver {
    char driver[512];
    char targets[ARS_TARGETS_MAX]; /* the plan's target flags, asked with */
    uint8_t bytes[32]; /* ars_driver_bytes of `driver` when captured */
    char dirs[ARS_SYSTEM_DIR_MAX][PATH_MAX];
    size_t count;
    /* Built-in dirs the driver skipped as nonexistent: one appearing moves
     * the search list, so it forces a re-capture. */
    char absent[ARS_SYSTEM_DIR_MAX][PATH_MAX];
    size_t absent_n;
    char implicit[ARS_IMPLICIT_N][PATH_MAX]; /* "" when not found */
    char sysroot[PATH_MAX];
    char ld[PATH_MAX];
    char collect2[PATH_MAX];
    bool valid;
};

static pthread_mutex_t g_driver_mu = PTHREAD_MUTEX_INITIALIZER;
static struct ars_driver g_driver;

/* Admit one built-in search entry of `n` bytes at `p`, or name why not:
 * an entry that will not fit a path buffer or the caller's array is an
 * overflow, one the lexer would rewrite is noncanonical. Either refuses
 * the whole list rather than drop or approximate one entry, since a root
 * derived from a partial or rewritten search list is not the real one. */
static const char *ars_builtin_entry(const char *p, size_t n,
                                     char dirs[][PATH_MAX], size_t dirs_cap,
                                     size_t *count)
{
    char dir[PATH_MAX];
    if (n >= PATH_MAX || *count >= dirs_cap)
        return "builtin_dir_overflow";
    (void)snprintf(dir, sizeof(dir), "%.*s", (int)n, p);
    if (!zcl_action_root_builtin_dir_canonical(dir))
        return "builtin_dir_noncanonical";
    memcpy(dirs[(*count)++], dir, n + 1);
    return NULL;
}

/* Step `*cursor` (a newline inside the search list) to the next non-empty
 * entry before `end`: its first byte and its length without leading spaces
 * or a " (framework directory)" suffix. False once the list is exhausted. */
static bool ars_builtin_next(const char **cursor, const char *end,
                             const char **line, size_t *len)
{
    const char *p = *cursor;
    while (p && p < end) {
        p++;
        while (*p == ' ')
            p++;
        size_t n = strcspn(p, "\r\n");
        const char *framework = strstr(p, " (framework directory)");
        if (framework && (size_t)(framework - p) < n)
            n = (size_t)(framework - p);
        const char *at = p;
        p = strchr(p, '\n');
        if (at < end && n > 0) {
            *cursor = p;
            *line = at;
            *len = n;
            return true;
        }
    }
    *cursor = p;
    return false;
}

bool zcl_action_root_parse_builtin_dirs(const char *out,
                                        char dirs[][PATH_MAX],
                                        size_t dirs_cap, size_t *count_out,
                                        char *miss)
{
    size_t count = 0;
    const char *refused = NULL;
    if (miss)
        miss[0] = '\0';
    if (count_out)
        *count_out = 0;
    const char *p = strstr(out, "#include <...> search starts here:");
    const char *end = strstr(out, "End of search list.");
    if (!p || !end || end < p)
        return false;
    p = strchr(p, '\n');
    const char *line = NULL;
    size_t n = 0;
    while (!refused && ars_builtin_next(&p, end, &line, &n))
        refused = ars_builtin_entry(line, n, dirs, dirs_cap, &count);
    if (refused) {
        if (miss)
            (void)snprintf(miss, 40, "%s", refused);
        return false;
    }
    if (count_out)
        *count_out = count;
    return count > 0;
}

static void ars_absent_parse(const char *out, const char *end,
                             struct ars_driver *sd)
{
    static const char mark[] = "ignoring nonexistent directory \"";
    sd->absent_n = 0;
    for (const char *p = strstr(out, mark);
         p && p < end && sd->absent_n < ARS_SYSTEM_DIR_MAX;
         p = strstr(p, mark)) {
        p += sizeof(mark) - 1;
        size_t n = strcspn(p, "\"\r\n");
        if (p[n] == '"' && n > 0 && n < PATH_MAX && p[0] == '/')
            (void)snprintf(sd->absent[sd->absent_n++], PATH_MAX, "%.*s",
                           (int)n, p);
    }
}

/* The nonexistent dirs the driver skipped, then the surviving search list
 * through the testable, refusing parser above. */
static bool ars_system_parse(const char *out, struct ars_driver *sd,
                             char miss[40])
{
    ars_absent_parse(out, out + strlen(out), sd);
    return zcl_action_root_parse_builtin_dirs(out, sd->dirs,
                                              ARS_SYSTEM_DIR_MAX, &sd->count,
                                              miss);
}

#if !defined(_WIN32)
/* Run `cc <target flags...> <args...>` and capture merged output. */
static bool ars_driver_ask(const struct ars_driver *d, const char *const *args,
                           char *capture, size_t cap)
{
    char text[512], targets[ARS_TARGETS_MAX];
    const char *argv[ARS_ARG_MAX];
    (void)snprintf(text, sizeof(text), "%s", d->driver);
    (void)snprintf(targets, sizeof(targets), "%s", d->targets);
    size_t argc = zcl_argv_split(text, argv, ARS_ARG_MAX / 2);
    argc += zcl_argv_split(targets, argv + argc, ARS_ARG_MAX / 4);
    for (size_t i = 0; argc && args[i] && argc < ARS_ARG_MAX - 1; i++)
        argv[argc++] = args[i];
    argv[argc] = NULL;
    bool timed_out = false;
    return argc > 1 &&
           zcl_spawn_capture_merged_observed(argv, capture, cap, 10000,
                                             &timed_out) == 0 &&
           !timed_out;
}

/* First output line of `cc <arg>`, trimmed; "" when the line is empty. */
static bool ars_driver_line(const struct ars_driver *d, const char *arg,
                            char out[PATH_MAX])
{
    char capture[PATH_MAX];
    const char *args[] = { arg, NULL };
    if (!ars_driver_ask(d, args, capture, sizeof(capture)))
        return false;
    size_t n = strcspn(capture, "\r\n");
    while (n > 0 && capture[n - 1] == ' ')
        n--;
    return snprintf(out, PATH_MAX, "%.*s", (int)n, capture) < PATH_MAX;
}

/* A driver that prints a bare program name runs it from PATH; resolve it
 * the same way. The answer is recorded by content, so PATH itself never
 * enters the preimage. */
static bool ars_resolve_program(char path[PATH_MAX])
{
    if (strchr(path, '/'))
        return path[0] == '/' && access(path, X_OK) == 0;
    const char *env = getenv("PATH");
    char name[256];
    if (!env || !path[0] || snprintf(name, sizeof(name), "%s", path) >=
                                (int)sizeof(name))
        return false;
    for (const char *p = env; *p;) {
        size_t n = strcspn(p, ":");
        char candidate[PATH_MAX];
        struct stat st;
        if (n > 0 && p[0] == '/' &&
            snprintf(candidate, sizeof(candidate), "%.*s/%s", (int)n, p,
                     name) < (int)sizeof(candidate) &&
            stat(candidate, &st) == 0 && S_ISREG(st.st_mode) &&
            access(candidate, X_OK) == 0) {
            (void)snprintf(path, PATH_MAX, "%s", candidate);
            return true;
        }
        p += n + (p[n] == ':');
    }
    return false;
}

/* `cc -print-file-name=X` echoes X back when it finds nothing. */
static bool ars_implicit_capture(struct ars_driver *d)
{
    for (size_t i = 0; i < ARS_IMPLICIT_N; i++) {
        char arg[64];
        (void)snprintf(arg, sizeof(arg), "-print-file-name=%s",
                       k_ars_implicit[i]);
        if (!ars_driver_line(d, arg, d->implicit[i]))
            return false;
        if (d->implicit[i][0] != '/')
            d->implicit[i][0] = '\0';
    }
    return true;
}

static bool ars_driver_capture(const char *cc, const char *targets,
                               struct ars_driver *d, char miss[40])
{
    static const char *const search[] = { "-xc", "-E", "-v", "/dev/null",
                                          NULL };
    char capture[16384];
    memset(d, 0, sizeof(*d));
    if (miss)
        miss[0] = '\0';
    (void)snprintf(d->driver, sizeof(d->driver), "%s", cc);
    (void)snprintf(d->targets, sizeof(d->targets), "%s", targets);
    if (!ars_driver_ask(d, search, capture, sizeof(capture)))
        return false;
    if (!ars_system_parse(capture, d, miss))
        return false;
    if (!ars_driver_line(d, "-print-sysroot", d->sysroot) ||
        !ars_driver_line(d, "-print-prog-name=ld", d->ld) ||
        !ars_resolve_program(d->ld) ||
        !ars_driver_line(d, "-print-prog-name=collect2", d->collect2) ||
        !ars_implicit_capture(d))
        return false;
    /* Only an absolute answer is a collect2 this driver runs; a driver
     * without one (Clang) echoes the bare name back. */
    if (d->collect2[0] != '/' || access(d->collect2, X_OK) != 0)
        d->collect2[0] = '\0';
    return true;
}

/* The captured built-in list still describes the disk: every listed dir
 * exists and every skipped one is still absent. */
static bool ars_absent_still(const struct ars_driver *d)
{
    for (size_t i = 0; i < d->count; i++)
        if (access(d->dirs[i], F_OK) != 0)
            return false;
    for (size_t i = 0; i < d->absent_n; i++)
        if (access(d->absent[i], F_OK) == 0)
            return false;
    return true;
}
#endif

/* SHA3 over the implicit link libraries, re-read every derivation (the
 * digest memo keys on stat, so an unchanged file is not re-hashed). */
static bool ars_implicit_sha3(const struct ars_driver *d, uint8_t out[32])
{
    static const char domain[] = "zcl.action_root.hotload_implicit_libs.v1";
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)domain, sizeof(domain));
    for (size_t i = 0; i < ARS_IMPLICIT_N; i++) {
        uint8_t digest[32] = {0};
        uint8_t found = d->implicit[i][0] != '\0';
        if (found && !zcl_action_root_file_sha3(d->implicit[i], digest))
            return false;
        sha3_256_write(&sha, (const uint8_t *)k_ars_implicit[i],
                       strlen(k_ars_implicit[i]) + 1);
        sha3_256_write(&sha, &found, 1);
        sha3_256_write(&sha, digest, sizeof(digest));
    }
    sha3_256_finalize(&sha, out);
    return true;
}

/* The plan's flags that can move the driver's built-in dirs, sysroot or
 * linker (-m..., --target=, -target X), asked with every driver query. */
static bool ars_targets(const char *cflags, const char *ldflags,
                        char out[ARS_TARGETS_MAX])
{
    const char *const lists[] = { cflags, ldflags };
    size_t o = 0;
    out[0] = '\0';
    for (size_t l = 0; l < 2; l++) {
        char text[16384];
        const char *w[ARS_ARG_MAX];
        if (snprintf(text, sizeof(text), "%s", lists[l] ? lists[l] : "") >=
            (int)sizeof(text))
            return false;
        size_t n = zcl_argv_split(text, w, ARS_ARG_MAX);
        for (size_t i = 0; i < n; i++) {
            bool pair = strcmp(w[i], "-target") == 0 && i + 1 < n;
            if (strncmp(w[i], "-m", 2) != 0 &&
                strncmp(w[i], "--target", 8) != 0 && !pair)
                continue;
            int k = snprintf(out + o, ARS_TARGETS_MAX - o, "%s%s%s%s",
                             o ? " " : "", w[i], pair ? " " : "",
                             pair ? w[i + 1] : "");
            if (k < 0 || (size_t)k >= ARS_TARGETS_MAX - o)
                return false;
            o += (size_t)k;
            i += pair;
        }
    }
    return true;
}

#if !defined(_WIN32)
/* The plan's compiler command may be a wrapper ("zcc cc", a script): every
 * program word it names is resolved as execvp would and bound by the SHA3 of
 * its bytes, so new bytes at the same path move the toolchain root. A word
 * that is not an option and does not resolve to a program misses. */
static bool ars_driver_bytes(const char *cc, uint8_t out[32])
{
    static const char domain[] = "zcl.action_root.hotload_driver.v1";
    char text[512];
    const char *argv[ARS_ARG_MAX];
    if (snprintf(text, sizeof(text), "%s", cc) >= (int)sizeof(text))
        return false;
    size_t argc = zcl_argv_split(text, argv, ARS_ARG_MAX);
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)domain, sizeof(domain));
    size_t programs = 0;
    for (size_t i = 0; i < argc; i++) {
        char path[PATH_MAX];
        uint8_t digest[32];
        if (argv[i][0] == '-')
            continue;
        if (snprintf(path, sizeof(path), "%s", argv[i]) >= (int)sizeof(path) ||
            !ars_resolve_program(path) ||
            !zcl_action_root_file_sha3(path, digest))
            return false;
        sha3_256_write(&sha, digest, sizeof(digest));
        programs++;
    }
    sha3_256_finalize(&sha, out);
    return programs > 0;
}
#endif

/* Driver facts are re-captured whenever the driver's bytes or the plan's
 * target flags change, a built-in dir it skipped as nonexistent appears, or
 * the built-in search list becomes uncanonical; `miss` names the refusal. */
static bool ars_driver_facts(const char *cc, const char *targets,
                             struct ars_driver *out, char miss[40])
{
#if defined(_WIN32)
    (void)cc;
    (void)targets;
    (void)out;
    if (miss)
        miss[0] = '\0';
    return false;
#else
    if (miss)
        miss[0] = '\0';
    uint8_t bytes[32];
    if (!ars_driver_bytes(cc, bytes))
        return false;
    pthread_mutex_lock(&g_driver_mu);
    bool ok = g_driver.valid && strcmp(g_driver.driver, cc) == 0 &&
              strcmp(g_driver.targets, targets) == 0 &&
              memcmp(g_driver.bytes, bytes, sizeof(bytes)) == 0 &&
              ars_absent_still(&g_driver);
    if (!ok) {
        ok = ars_driver_capture(cc, targets, &g_driver, miss);
        memcpy(g_driver.bytes, bytes, sizeof(bytes));
        g_driver.valid = ok;
    }
    if (ok)
        *out = g_driver;
    pthread_mutex_unlock(&g_driver_mu);
    return ok;
#endif
}

/* The first prerequisite of a depfile is the compiled input. */
static bool ars_depfile_input(const char *depfile, char out[PATH_MAX])
{
    char text[PATH_MAX * 2];
    FILE *f = fopen(depfile, "r");
    size_t n = f ? fread(text, 1, sizeof(text) - 1, f) : 0;
    if (f)
        fclose(f);
    text[n] = '\0';
    for (size_t i = 0; i + 1 < n; i++)
        if (text[i] == '\\' && (text[i + 1] == '\n' || text[i + 1] == '\r'))
            text[i] = text[i + 1] = ' ';
    char *colon = strchr(text, ':');
    while (colon && colon[1] && !strchr(" \t\r\n", colon[1]))
        colon = strchr(colon + 1, ':');
    if (!colon)
        return false;
    char *p = colon + 1 + strspn(colon + 1, " \t\r\n");
    size_t len = strcspn(p, " \t\r\n");
    return len > 0 && len < PATH_MAX &&
           snprintf(out, PATH_MAX, "%.*s", (int)len, p) > 0;
}

struct ars_argv {
    char cc[512];
    char cflags[16384];
    char source_define[320];
    char service_define[320];
    char input[PATH_MAX];
    char unity_token[320];
    const char *v[ARS_ARG_MAX];
    size_t n;
    char link_cc[512];
    char ldflags[4096];
    const char *link[ARS_ARG_MAX];
    size_t link_n;
};

/* Mirror of hs_run_compile() in devloop_hotswap_build.c: the same driver,
 * flags and appended arguments, with the temporary object and depfile
 * replaced by their declared virtual outputs. */
static bool ars_hotswap_argv(const char *owner, const char *cc,
                             const char *cflags, const char *depfile,
                             struct ars_argv *a)
{
    (void)snprintf(a->cc, sizeof(a->cc), "%s", cc);
    (void)snprintf(a->cflags, sizeof(a->cflags), "%s", cflags);
    (void)snprintf(a->source_define, sizeof(a->source_define),
                   "-DZCL_HOTSWAP_MODULE_SOURCE_TU=\"%s\"", owner);
    (void)snprintf(a->service_define, sizeof(a->service_define),
                   "-DZCL_HOTSWAP_SERVICE_SOURCE_TU=\"%s\"", owner);
    if (!ars_depfile_input(depfile, a->input))
        return false;
    a->n = zcl_argv_split(a->cc, a->v, ARS_ARG_MAX);
    size_t flagc = zcl_argv_split(a->cflags, a->v + a->n,
                                  ARS_ARG_MAX - a->n);
    a->n += flagc;
    static const char *const tail[] = {
        "-fPIC", "-DZCL_HOTSWAP_MODULE_GEN", "-DZCL_HOTSWAP_SERVICE_GEN",
    };
    if (a->n == 0 || a->n + 16 >= ARS_ARG_MAX)
        return false;
    for (size_t i = 0; i < sizeof(tail) / sizeof(tail[0]); i++)
        a->v[a->n++] = tail[i];
    a->v[a->n++] = a->source_define;
    a->v[a->n++] = a->service_define;
    a->v[a->n++] = "-MD";
    a->v[a->n++] = "-MF";
    a->v[a->n++] = "@out/depfile";
    a->v[a->n++] = "-c";
    a->v[a->n++] = "-o";
    a->v[a->n++] = "@out/object";
    a->v[a->n++] = a->input;
    a->v[a->n] = NULL;
    return true;
}

/* Mirror of hs_run_link(): driver, link flags, -o module, the object. */
static bool ars_hotswap_link_argv(const char *cc, const char *ldflags,
                                  struct ars_argv *a)
{
    (void)snprintf(a->link_cc, sizeof(a->link_cc), "%s", cc);
    if (snprintf(a->ldflags, sizeof(a->ldflags), "%s", ldflags) >=
        (int)sizeof(a->ldflags))
        return false;
    a->link_n = zcl_argv_split(a->link_cc, a->link, ARS_ARG_MAX);
    a->link_n += zcl_argv_split(a->ldflags, a->link + a->link_n,
                                ARS_ARG_MAX - a->link_n);
    if (a->link_n == 0 || a->link_n + 4 >= ARS_ARG_MAX)
        return false;
    a->link[a->link_n++] = "-o";
    a->link[a->link_n++] = "@out/module";
    a->link[a->link_n++] = "@out/object";
    a->link[a->link_n] = NULL;
    return true;
}

#if !defined(_WIN32)
extern char **environ;
#endif

/* The environment the compile child inherits (zcl_devloop_process_run
 * passes the watcher's own environment through execvp). */
static const char *const *ars_environ(void)
{
#if defined(_WIN32)
    return NULL; /* unreachable: the driver probe refuses first */
#else
    return (const char *const *)environ;
#endif
}

/* Mirror of hs_run_hotfork_compile(): the capsule unity is compiled from a
 * temporary .resident-* spelling, recorded under the stable token
 * build/hotswap-fast/<owner>.hotfork-unity.c (a virtual generated input). */
static bool ars_hotfork_argv(const char *root, const char *owner,
                             const char *cc, const char *cflags,
                             struct ars_argv *a)
{
    char safe[256];
    (void)snprintf(a->cc, sizeof(a->cc), "%s", cc);
    (void)snprintf(a->cflags, sizeof(a->cflags), "%s", cflags);
    if (!ars_safe_name(owner, safe) ||
        snprintf(a->unity_token, sizeof(a->unity_token),
                 "build/hotswap-fast/%s.hotfork-unity.c", safe) >=
            (int)sizeof(a->unity_token) ||
        snprintf(a->input, sizeof(a->input), "%s/%s", root, a->unity_token) >=
            (int)sizeof(a->input))
        return false;
    a->n = zcl_argv_split(a->cc, a->v, ARS_ARG_MAX);
    a->n += zcl_argv_split(a->cflags, a->v + a->n, ARS_ARG_MAX - a->n);
    static const char *const tail[] = {
        "-fPIC", "-fvisibility=hidden", "-MD", "-MF", "@out/depfile",
        "-c", "-o", "@out/object",
    };
    size_t tail_n = sizeof(tail) / sizeof(tail[0]);
    if (a->n == 0 || a->n + tail_n + 2 >= ARS_ARG_MAX)
        return false;
    for (size_t i = 0; i < tail_n; i++)
        a->v[a->n++] = tail[i];
    a->v[a->n++] = a->input;
    a->v[a->n] = NULL;
    return true;
}

/* Mirror of hs_run_hotfork_link(): no plan link flags; the version script,
 * module, candidate object and descriptor object are declared outputs. */
static bool ars_hotfork_link_argv(const char *cc, struct ars_argv *a)
{
    (void)snprintf(a->link_cc, sizeof(a->link_cc), "%s", cc);
    a->link_n = zcl_argv_split(a->link_cc, a->link, ARS_ARG_MAX);
    static const char *const tail[] = {
        "-shared", "-nostartfiles", "-Wl,--build-id=none", "-Wl,-z,relro",
        "-Wl,-z,noexecstack", "-Wl,-Bsymbolic",
        "-Wl,--version-script=@out/version-script", "-o", "@out/module",
        "@out/object", "@out/descriptor",
    };
    size_t tail_n = sizeof(tail) / sizeof(tail[0]);
    if (a->link_n == 0 || a->link_n + tail_n + 1 >= ARS_ARG_MAX)
        return false;
    for (size_t i = 0; i < tail_n; i++)
        a->link[a->link_n++] = tail[i];
    a->link[a->link_n] = NULL;
    return true;
}

/* What differs between the hot-swap module action and the HOT_FORK capsule
 * action: stage, the ABI the artifact is loaded against, and the policy. */
struct ars_stage {
    const char *kind;
    uint32_t version;
    uint32_t abi_generation;
    const struct vcs_action_abi_v2 *abi;
    size_t abi_count;
    const char *policy;
    size_t policy_len;
};

/* The generation a hotload module is loaded against is the host ABI; the
 * module and service ABIs are listed by name beside it. */
static const struct vcs_action_abi_v2 g_hotswap_abi[] = {
    { "hotswap_host", ZCL_HOTSWAP_HOST_ABI_V4 },
    { "hotswap_module", ZCL_HOTSWAP_MODULE_ABI_V3 },
    { "hotswap_service", ZCL_HOTSWAP_SERVICE_ABI_V1 },
};
static const struct vcs_action_abi_v2 g_hotfork_abi[] = {
    { "hotfork_capsule", ZCL_HOTFORK_CAPSULE_ABI_V1 },
};
static const char g_hotswap_policy[] =
    "zcl.action_policy.v2\0hotswap.compile+link;timeout_ms=30000;"
    "env=inherited-allowlist;network=ambient";
static const char g_hotfork_policy[] =
    "zcl.action_policy.v2\0hotfork.compile+descriptor+link;timeout_ms=30000;"
    "env=inherited-allowlist;network=ambient";

static const struct ars_stage g_hotswap_stage = {
    ZCL_ACTION_ROOT_STAGE_HOTSWAP, ZCL_ACTION_ROOT_STAGE_HOTSWAP_VERSION,
    ZCL_HOTSWAP_HOST_ABI_V4, g_hotswap_abi,
    sizeof(g_hotswap_abi) / sizeof(g_hotswap_abi[0]), g_hotswap_policy,
    sizeof(g_hotswap_policy),
};
static const struct ars_stage g_hotfork_stage = {
    ZCL_ACTION_ROOT_STAGE_HOTFORK, ZCL_ACTION_ROOT_STAGE_HOTFORK_VERSION,
    ZCL_HOTFORK_CAPSULE_ABI_V1, g_hotfork_abi,
    sizeof(g_hotfork_abi) / sizeof(g_hotfork_abi[0]), g_hotfork_policy,
    sizeof(g_hotfork_policy),
};

struct ars_hook {
    struct ars_argv argv;
    struct ars_driver driver;
    const char *system_dirs[ARS_SYSTEM_DIR_MAX];
    struct vcs_toolchain_capsule_v1 capsule;
    struct zcl_action_root_request req;
};

struct ars_compile {
    const char *root, *owner, *cc, *cflags, *ldflags, *depfile;
    const char *unity; /* HOT_FORK: the live unity file; NULL for hot-swap */
    const struct zcl_action_root_t0 *t0; /* the compile start, or NULL */
};

/* The first miss wins: a stable code plus a human detail. */
struct ars_miss {
    char code[40];
    char why[192];
};

static void ars_miss_set(struct ars_miss *m, const char *code,
                         const char *what, const char *arg)
{
    if (!m->code[0])
        (void)snprintf(m->code, sizeof(m->code), "%s", code);
    ars_why(m->why, sizeof(m->why), what, arg);
}

static bool ars_hook_argv(struct ars_hook *h, const struct ars_compile *k)
{
    if (k->unity)
        return ars_hotfork_argv(k->root, k->owner, k->cc, k->cflags,
                                &h->argv) &&
               ars_hotfork_link_argv(k->cc, &h->argv);
    return ars_hotswap_argv(k->owner, k->cc, k->cflags, k->depfile,
                            &h->argv) &&
           ars_hotswap_link_argv(k->cc, k->ldflags, &h->argv);
}

/* A plan word "@file" makes the driver read more arguments from a file the
 * root does not hash ("@out/..." are the derivation's own declared outputs,
 * so a plan that spells one is refused too). */
static bool ars_response_file(const char *words)
{
    for (const char *p = words; p && *p; p++)
        if (*p == '@' && (p == words || strchr(" \t\"'", p[-1])))
            return true;
    return false;
}

/* Plan flags follow the driver words in argv; one that does not start with
 * '-' would read as another driver word. Empty flags are fine. */
static bool ars_options_first(const char *words)
{
    const char *p = words ? words + strspn(words, " \t") : "";
    return !*p || *p == '-';
}

static bool ars_hook_inputs(struct ars_hook *h, const struct ars_compile *k,
                            struct ars_miss *m)
{
    struct zcl_action_root_request *r = &h->req;
    uint8_t capsule_root[32];
    if (!vcs_toolchain_capsule_v1_capture(&h->capsule) ||
        !vcs_toolchain_capsule_v1_root(&h->capsule, capsule_root)) {
        ars_miss_set(m, "toolchain_unavailable",
                     "toolchain capsule unavailable", NULL);
        return false;
    }
    if (ars_response_file(k->cc) || ars_response_file(k->cflags) ||
        ars_response_file(k->ldflags) || !ars_options_first(k->cflags) ||
        !ars_options_first(k->ldflags)) {
        ars_miss_set(m, "argv_unrecognised",
                     "the plan names a response file, or its flags start "
                     "with a word the driver would take as an input", NULL);
        return false;
    }
    char targets[ARS_TARGETS_MAX];
    uint8_t implicit[32];
    char driver_miss[40] = {0};
    if (!ars_targets(k->cflags, k->unity ? NULL : k->ldflags, targets) ||
        !ars_driver_facts(k->cc, targets, &h->driver, driver_miss) ||
        !ars_implicit_sha3(&h->driver, implicit)) {
        if (driver_miss[0])
            ars_miss_set(m, driver_miss,
                         "compiler driver's built-in include search is not "
                         "a canonical, capacity-fitting list", k->cc);
        else
            ars_miss_set(m, "driver_facts_unavailable",
                         "compiler driver facts, program bytes or implicit "
                         "libraries unavailable", k->cc);
        return false;
    }
    /* The capsule is the host toolchain; the plan's own driver command (a
     * wrapper, a cache, another compiler) is bound by its program bytes, and
     * the libraries its links pull in unnamed by theirs. */
    static const char domain[] = "zcl.action_root.hotload_toolchain.v2";
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)domain, sizeof(domain));
    sha3_256_write(&sha, capsule_root, sizeof(capsule_root));
    sha3_256_write(&sha, h->driver.bytes, sizeof(h->driver.bytes));
    sha3_256_write(&sha, implicit, sizeof(implicit));
    sha3_256_finalize(&sha, r->toolchain_root);
    if (!ars_hook_argv(h, k)) {
        ars_miss_set(m, "argv_unavailable",
                     "compile argv or depfile input unavailable", k->depfile);
        return false;
    }
    return true;
}

static void ars_hook_request(struct ars_hook *h, const struct ars_compile *k)
{
    const struct ars_stage *st = k->unity ? &g_hotfork_stage
                                          : &g_hotswap_stage;
    struct zcl_action_root_request *r = &h->req;
    for (size_t i = 0; i < h->driver.count; i++)
        h->system_dirs[i] = h->driver.dirs[i];
    r->root = k->root;
    r->stage_kind = st->kind;
    r->stage_version = st->version;
    r->argv = h->argv.v;
    r->argc = h->argv.n;
    r->depfile = k->depfile;
    r->virtual_input_token = k->unity ? h->argv.unity_token : NULL;
    r->virtual_input_path = k->unity;
    r->system_dirs = h->system_dirs;
    r->system_dir_count = h->driver.count;
    r->sysroot = h->driver.sysroot;
    memcpy(r->sysroot_objects_sha3, h->capsule.sysroot_sha3, 32);
    r->linker = (struct zcl_action_root_linker){
        .links = true, .ld = h->driver.ld,
        .collect2 = h->driver.collect2[0] ? h->driver.collect2 : NULL,
        .argv = h->argv.link, .argc = h->argv.link_n,
    };
    r->environ = ars_environ();
    if (k->t0)
        r->compile_t0 = *k->t0;
    r->abi_generation = st->abi_generation;
    r->abi = st->abi;
    r->abi_count = st->abi_count;
    r->policy.present = true;
    zcl_sha3_256((const unsigned char *)st->policy, st->policy_len,
                 r->policy.root);
}

/* A build that did not complete never observed this attempt's closure, and
 * a depfile that is gone names nothing: both are misses, not roots. */
static bool ars_hook_closure_known(const struct ars_compile *k,
                                   struct ars_miss *m)
{
    if (!k->root || !k->owner || !k->cc || !k->cflags || !k->ldflags) {
        ars_miss_set(m, "request_incomplete",
                     "hotload compile identity is incomplete", NULL);
        return false;
    }
    if (!k->depfile) {
        ars_miss_set(m, "closure_unobserved",
                     "the build did not complete, so this attempt's "
                     "dependency closure was never observed", k->owner);
        return false;
    }
    if (access(k->depfile, F_OK) != 0) {
        ars_miss_set(m, "depfile_missing", "dependency file is absent",
                     k->owner);
        return false;
    }
    return true;
}

static bool ars_hook_derive(const struct ars_compile *k,
                            struct zcl_action_root_result *result,
                            struct ars_miss *m)
{
    if (!ars_hook_closure_known(k, m))
        return false;
    struct ars_hook *h = zcl_calloc(1, sizeof(*h), "action root hook");
    if (!h) {
        ars_miss_set(m, "out_of_memory", "action root hook allocation failed",
                     NULL);
        return false;
    }
    bool ok = ars_hook_inputs(h, k, m);
    if (ok) {
        ars_hook_request(h, k);
        ok = zcl_action_root_derive(&h->req, result);
        if (!ok)
            ars_miss_set(m, result->miss[0] ? result->miss : "encode_refused",
                         result->why[0] ? result->why : "action root refused",
                         NULL);
    }
    free(h);
    return ok;
}

static void ars_hook_store(const char *unit,
                           const struct zcl_action_root_result *result,
                           struct zcl_devloop_hotswap_build_receipt *receipt,
                           struct ars_miss *m)
{
    char store[PATH_MAX];
    if (zcl_action_root_store_dir(store, sizeof(store)) &&
        zcl_action_root_record(store, unit, result,
                               receipt->action_root_cause,
                               sizeof(receipt->action_root_cause), m->why,
                               sizeof(m->why)))
        (void)snprintf(receipt->action_root, sizeof(receipt->action_root),
                       "%s", result->root_hex);
    else
        ars_miss_set(m, "store_unavailable", "action root store unavailable",
                     NULL);
}

static void ars_hook_run(const struct ars_compile *k, const char *unit,
                         struct zcl_devloop_hotswap_build_receipt *receipt)
{
    receipt->action_root[0] = '\0';
    receipt->action_root_cause[0] = '\0';
    receipt->action_root_miss[0] = '\0';
    receipt->action_root_miss_detail[0] = '\0';
    struct ars_miss m = {0};
    struct zcl_action_root_result result = {0};
    int64_t started = platform_time_monotonic_us();
    bool derived = ars_hook_derive(k, &result, &m);
    receipt->action_root_us = platform_time_monotonic_us() - started;
    receipt->action_root_probes = result.probes;
    receipt->action_root_present = result.present;
    int64_t store_started = platform_time_monotonic_us();
    if (derived)
        ars_hook_store(unit, &result, receipt, &m);
    receipt->action_root_store_us =
        platform_time_monotonic_us() - store_started;
    if (!receipt->action_root[0]) {
        receipt->action_root_cause[0] = '\0';
        ars_miss_set(&m, "unclassified", "action root missed", NULL);
        (void)snprintf(receipt->action_root_miss,
                       sizeof(receipt->action_root_miss), "%s", m.code);
        (void)snprintf(receipt->action_root_miss_detail,
                       sizeof(receipt->action_root_miss_detail), "%s", m.why);
    }
    zcl_action_root_result_free(&result);
}

void zcl_devloop_action_root_hotswap(
    const char *root, const char *owner, const char *cc, const char *cflags,
    const char *ldflags, const char *depfile,
    const struct zcl_action_root_t0 *t0,
    struct zcl_devloop_hotswap_build_receipt *receipt)
{
    if (!receipt)
        return;
    const struct ars_compile k = { root, owner, cc, cflags, ldflags, depfile,
                                   NULL, t0 };
    ars_hook_run(&k, owner, receipt);
}

void zcl_devloop_action_root_hotfork(
    const char *root, const char *owner, const char *cc, const char *cflags,
    const char *unity, const char *depfile,
    const struct zcl_action_root_t0 *t0,
    struct zcl_devloop_hotswap_build_receipt *receipt)
{
    if (!receipt)
        return;
    char unit[320];
    (void)snprintf(unit, sizeof(unit), "hotfork:%s", owner ? owner : "");
    const struct ars_compile k = { root, owner, cc, cflags, "",
                                   depfile, unity ? unity : "", t0 };
    ars_hook_run(&k, unit, receipt);
}

bool zcl_devloop_action_root_key(
    const char *root, const char *owner, const char *cc, const char *cflags,
    const char *ldflags, const char *unity, const char *depfile,
    const struct zcl_action_root_t0 *t0, char root_hex[65], char miss[40])
{
    if (!root_hex || !miss)
        return false;
    root_hex[0] = '\0';
    miss[0] = '\0';
    const struct ars_compile k = { root, owner, cc, cflags,
                                   unity ? "" : ldflags, depfile, unity, t0 };
    struct ars_miss m = {0};
    struct zcl_action_root_result result = {0};
    bool ok = ars_hook_derive(&k, &result, &m);
    if (ok)
        (void)snprintf(root_hex, 65, "%s", result.root_hex);
    else
        (void)snprintf(miss, 40, "%s", m.code[0] ? m.code : "unclassified");
    zcl_action_root_result_free(&result);
    return ok;
}

void zcl_devloop_action_root_emit(
    struct json_value *receipt_json,
    const struct zcl_devloop_hotswap_build_receipt *build)
{
    if (!receipt_json || !build)
        return;
    if (build->cache_key_action_root[0] || build->cache_key_miss[0]) {
        (void)json_push_kv_str(receipt_json, "artifact_cache_key_schema",
                               "zcl.dev_artifact_cache.hotswap.v2");
        if (build->cache_key_action_root[0])
            (void)json_push_kv_str(receipt_json,
                                   "artifact_cache_key_action_root",
                                   build->cache_key_action_root);
        else
            (void)json_push_kv_str(receipt_json, "artifact_cache_key_miss",
                                   build->cache_key_miss);
        (void)json_push_kv_int(receipt_json, "artifact_cache_key_us",
                               build->cache_key_us);
    }
    if (!build->action_root[0] && !build->action_root_miss[0])
        return;
    (void)json_push_kv_str(receipt_json, "action_root_schema",
                           VCS_ACTION_PREIMAGE_V2_MAGIC);
    if (build->action_root[0]) {
        (void)json_push_kv_str(receipt_json, "action_root",
                               build->action_root);
        (void)json_push_kv_str(receipt_json, "action_root_cause",
                               build->action_root_cause);
    } else {
        struct json_value none;
        json_init(&none);
        json_set_null(&none);
        (void)json_push_kv(receipt_json, "action_root", &none);
        json_free(&none);
        (void)json_push_kv_str(receipt_json, "action_root_cause", "miss");
        (void)json_push_kv_str(receipt_json, "action_root_miss_reason",
                               build->action_root_miss);
        (void)json_push_kv_str(receipt_json, "action_root_miss_detail",
                               build->action_root_miss_detail);
    }
    (void)json_push_kv_int(receipt_json, "action_root_ms",
                           build->action_root_us / 1000);
    (void)json_push_kv_int(receipt_json, "action_root_us",
                           build->action_root_us);
    (void)json_push_kv_int(receipt_json, "action_root_store_us",
                           build->action_root_store_us);
    (void)json_push_kv_int(receipt_json, "action_root_probes",
                           build->action_root_probes);
    (void)json_push_kv_int(receipt_json, "action_root_present",
                           build->action_root_present);
}
