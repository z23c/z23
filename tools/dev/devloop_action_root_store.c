/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Content-addressed storage of zcl.action_preimage.v2 objects, the per-unit
 * "what changed since last time" cause, and the hotload compile hook that
 * reports an action_root in every hot-swap build receipt. Emission only:
 * nothing here changes the artifact cache key or what the build does.
 */

#if !defined(_WIN32)
#define _GNU_SOURCE
#endif

#include "devloop_action_root.h"

#include "devloop.h"

#include "base/hex.h"
#include "base/safe_alloc.h"
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

/* Safe single-component file name for one unit (repo-relative path). */
static bool ars_unit_file(const char *store_dir, const char *unit,
                          char out[PATH_MAX])
{
    char safe[256];
    size_t n = unit ? strlen(unit) : 0;
    if (n == 0 || n >= sizeof(safe))
        return false;
    for (size_t i = 0; i <= n; i++) {
        unsigned char c = (unsigned char)unit[i];
        bool keep = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                    (c >= '0' && c <= '9') || c == '.' || c == '-' || !c;
        safe[i] = keep ? (char)c : '_';
    }
    char dir[PATH_MAX];
    return snprintf(dir, sizeof(dir), "%s/last", store_dir) <
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

/* The compiler's built-in #include <...> list, asked once per driver. */
struct ars_system_dirs {
    char driver[512];
    char dirs[ARS_SYSTEM_DIR_MAX][PATH_MAX];
    size_t count;
    bool valid;
};

static pthread_mutex_t g_system_mu = PTHREAD_MUTEX_INITIALIZER;
static struct ars_system_dirs g_system;

static bool ars_system_parse(const char *out, struct ars_system_dirs *sd)
{
    const char *p = strstr(out, "#include <...> search starts here:");
    const char *end = strstr(out, "End of search list.");
    if (!p || !end || end < p)
        return false;
    p = strchr(p, '\n');
    sd->count = 0;
    while (p && p < end && sd->count < ARS_SYSTEM_DIR_MAX) {
        p++;
        while (*p == ' ') p++;
        size_t n = strcspn(p, "\r\n");
        const char *framework = strstr(p, " (framework directory)");
        if (framework && (size_t)(framework - p) < n)
            n = (size_t)(framework - p);
        if (p < end && n > 0 && n < PATH_MAX && p[0] == '/')
            (void)snprintf(sd->dirs[sd->count++], PATH_MAX, "%.*s", (int)n,
                           p);
        p = strchr(p, '\n');
    }
    return sd->count > 0;
}

static bool ars_system_dirs(const char *cc, struct ars_system_dirs *out)
{
#if defined(_WIN32)
    (void)cc;
    (void)out;
    return false;
#else
    pthread_mutex_lock(&g_system_mu);
    bool ok = g_system.valid && strcmp(g_system.driver, cc) == 0;
    if (!ok) {
        char text[512], capture[16384];
        const char *argv[ARS_ARG_MAX];
        (void)snprintf(text, sizeof(text), "%s", cc);
        size_t argc = zcl_argv_split(text, argv, ARS_ARG_MAX - 5);
        argv[argc++] = "-xc";
        argv[argc++] = "-E";
        argv[argc++] = "-v";
        argv[argc++] = "/dev/null";
        argv[argc] = NULL;
        bool timed_out = false;
        memset(&g_system, 0, sizeof(g_system));
        ok = argc > 4 &&
             zcl_spawn_capture_merged_observed(argv, capture, sizeof(capture),
                                               10000, &timed_out) == 0 &&
             !timed_out && ars_system_parse(capture, &g_system);
        g_system.valid = ok;
        (void)snprintf(g_system.driver, sizeof(g_system.driver), "%s", cc);
    }
    if (ok)
        *out = g_system;
    pthread_mutex_unlock(&g_system_mu);
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
    const char *v[ARS_ARG_MAX];
    size_t n;
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

#if !defined(_WIN32)
extern char **environ;
#endif

/* The environment the compile child inherits (zcl_devloop_process_run
 * passes the watcher's own environment through execvp). */
static const char *const *ars_environ(void)
{
#if defined(_WIN32)
    return NULL; /* unreachable: the include search probe refuses first */
#else
    return (const char *const *)environ;
#endif
}

static void ars_policy_root(uint8_t out[32])
{
    static const char policy[] =
        "zcl.action_policy.v2\0hotswap.compile;timeout_ms=30000;"
        "env=inherited-allowlist;network=ambient";
    zcl_sha3_256((const unsigned char *)policy, sizeof(policy), out);
}

struct ars_hook {
    struct ars_argv argv;
    struct ars_system_dirs system;
    const char *system_dirs[ARS_SYSTEM_DIR_MAX];
    struct vcs_toolchain_capsule_v1 capsule;
    struct zcl_action_root_request req;
};

static bool ars_hook_request(struct ars_hook *h, const char *root,
                             const char *owner, const char *cc,
                             const char *cflags, const char *depfile,
                             char *why, size_t why_len)
{
    static const struct vcs_action_abi_v2 abi[] = {
        { "hotswap_host", ZCL_HOTSWAP_HOST_ABI_V4 },
        { "hotswap_module", ZCL_HOTSWAP_MODULE_ABI_V3 },
        { "hotswap_service", ZCL_HOTSWAP_SERVICE_ABI_V1 },
    };
    struct zcl_action_root_request *r = &h->req;
    if (!vcs_toolchain_capsule_v1_capture(&h->capsule) ||
        !vcs_toolchain_capsule_v1_root(&h->capsule, r->toolchain_root)) {
        ars_why(why, why_len, "toolchain capsule unavailable", NULL);
        return false;
    }
    if (!ars_system_dirs(cc, &h->system)) {
        ars_why(why, why_len, "compiler include search list unavailable", cc);
        return false;
    }
    if (!ars_hotswap_argv(owner, cc, cflags, depfile, &h->argv)) {
        ars_why(why, why_len, "compile argv or depfile input unavailable",
                depfile);
        return false;
    }
    for (size_t i = 0; i < h->system.count; i++)
        h->system_dirs[i] = h->system.dirs[i];
    r->root = root;
    r->stage_kind = ZCL_ACTION_ROOT_STAGE_HOTSWAP;
    r->stage_version = ZCL_ACTION_ROOT_STAGE_HOTSWAP_VERSION;
    r->argv = h->argv.v;
    r->argc = h->argv.n;
    r->depfile = depfile;
    r->system_dirs = h->system_dirs;
    r->system_dir_count = h->system.count;
    r->environ = ars_environ();
    r->abi = abi;
    r->abi_count = sizeof(abi) / sizeof(abi[0]);
    r->policy.present = true;
    ars_policy_root(r->policy.root);
    return true;
}

static bool ars_hook_derive(const char *root, const char *owner,
                            const char *cc, const char *cflags,
                            const char *depfile,
                            struct zcl_action_root_result *result,
                            char *why, size_t why_len)
{
    if (!root || !owner || !cc || !cflags || !depfile) {
        ars_why(why, why_len, "hotload compile identity is incomplete", NULL);
        return false;
    }
    struct ars_hook *h = zcl_calloc(1, sizeof(*h), "action root hook");
    if (!h) {
        ars_why(why, why_len, "action root hook allocation failed", NULL);
        return false;
    }
    bool ok = ars_hook_request(h, root, owner, cc, cflags, depfile, why,
                               why_len) &&
              zcl_action_root_derive(&h->req, result);
    if (!ok)
        ars_why(why, why_len,
                result->why[0] ? result->why : "action root refused", NULL);
    free(h);
    return ok;
}

static void ars_hook_store(const char *owner,
                           const struct zcl_action_root_result *result,
                           struct zcl_devloop_hotswap_build_receipt *receipt,
                           char *why, size_t why_len)
{
    char store[PATH_MAX];
    if (zcl_action_root_store_dir(store, sizeof(store)) &&
        zcl_action_root_record(store, owner, result,
                               receipt->action_root_cause,
                               sizeof(receipt->action_root_cause), why,
                               why_len))
        (void)snprintf(receipt->action_root, sizeof(receipt->action_root),
                       "%s", result->root_hex);
    else
        ars_why(why, why_len, "action root store unavailable", NULL);
}

void zcl_devloop_action_root_hotswap(
    const char *root, const char *owner, const char *cc, const char *cflags,
    const char *depfile, struct zcl_devloop_hotswap_build_receipt *receipt)
{
    if (!receipt)
        return;
    receipt->action_root[0] = '\0';
    receipt->action_root_cause[0] = '\0';
    receipt->action_root_refused[0] = '\0';
    char why[192] = {0};
    struct zcl_action_root_result result = {0};
    int64_t started = platform_time_monotonic_us();
    bool derived = ars_hook_derive(root, owner, cc, cflags, depfile, &result,
                                   why, sizeof(why));
    receipt->action_root_us = platform_time_monotonic_us() - started;
    receipt->action_root_probes = result.probes;
    receipt->action_root_present = result.present;
    int64_t store_started = platform_time_monotonic_us();
    if (derived)
        ars_hook_store(owner, &result, receipt, why, sizeof(why));
    receipt->action_root_store_us =
        platform_time_monotonic_us() - store_started;
    if (!receipt->action_root[0])
        (void)snprintf(receipt->action_root_refused,
                       sizeof(receipt->action_root_refused), "%s", why);
    zcl_action_root_result_free(&result);
}

void zcl_devloop_action_root_emit(
    struct json_value *receipt_json,
    const struct zcl_devloop_hotswap_build_receipt *build)
{
    if (!receipt_json || !build ||
        (!build->action_root[0] && !build->action_root_refused[0]))
        return;
    (void)json_push_kv_str(receipt_json, "action_root_schema",
                           VCS_ACTION_PREIMAGE_V2_MAGIC);
    if (build->action_root[0]) {
        (void)json_push_kv_str(receipt_json, "action_root",
                               build->action_root);
        (void)json_push_kv_str(receipt_json, "action_root_cause",
                               build->action_root_cause);
    } else {
        (void)json_push_kv_str(receipt_json, "action_root_refused",
                               build->action_root_refused);
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
