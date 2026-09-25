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
struct ars_driver {
    char driver[512];
    char dirs[ARS_SYSTEM_DIR_MAX][PATH_MAX];
    size_t count;
    char sysroot[PATH_MAX];
    char ld[PATH_MAX];
    char collect2[PATH_MAX];
    bool valid;
};

static pthread_mutex_t g_driver_mu = PTHREAD_MUTEX_INITIALIZER;
static struct ars_driver g_driver;

static bool ars_system_parse(const char *out, struct ars_driver *sd)
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

#if !defined(_WIN32)
/* Run `cc <args...>` and capture merged output. */
static bool ars_driver_ask(const char *cc, const char *const *args,
                           char *capture, size_t cap)
{
    char text[512];
    const char *argv[ARS_ARG_MAX];
    (void)snprintf(text, sizeof(text), "%s", cc);
    size_t argc = zcl_argv_split(text, argv, ARS_ARG_MAX - 8);
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
static bool ars_driver_line(const char *cc, const char *arg, char out[PATH_MAX])
{
    char capture[PATH_MAX];
    const char *args[] = { arg, NULL };
    if (!ars_driver_ask(cc, args, capture, sizeof(capture)))
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

static bool ars_driver_capture(const char *cc, struct ars_driver *d)
{
    static const char *const search[] = { "-xc", "-E", "-v", "/dev/null",
                                          NULL };
    char capture[16384];
    memset(d, 0, sizeof(*d));
    (void)snprintf(d->driver, sizeof(d->driver), "%s", cc);
    if (!ars_driver_ask(cc, search, capture, sizeof(capture)) ||
        !ars_system_parse(capture, d) ||
        !ars_driver_line(cc, "-print-sysroot", d->sysroot) ||
        !ars_driver_line(cc, "-print-prog-name=ld", d->ld) ||
        !ars_resolve_program(d->ld) ||
        !ars_driver_line(cc, "-print-prog-name=collect2", d->collect2))
        return false;
    /* Only an absolute answer is a collect2 this driver runs; a driver
     * without one (Clang) echoes the bare name back. */
    if (d->collect2[0] != '/' || access(d->collect2, X_OK) != 0)
        d->collect2[0] = '\0';
    return true;
}
#endif

static bool ars_driver_facts(const char *cc, struct ars_driver *out)
{
#if defined(_WIN32)
    (void)cc;
    (void)out;
    return false;
#else
    pthread_mutex_lock(&g_driver_mu);
    bool ok = g_driver.valid && strcmp(g_driver.driver, cc) == 0;
    if (!ok) {
        ok = ars_driver_capture(cc, &g_driver);
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

static void ars_policy_root(uint8_t out[32])
{
    static const char policy[] =
        "zcl.action_policy.v2\0hotswap.compile+link;timeout_ms=30000;"
        "env=inherited-allowlist;network=ambient";
    zcl_sha3_256((const unsigned char *)policy, sizeof(policy), out);
}

struct ars_hook {
    struct ars_argv argv;
    struct ars_driver driver;
    const char *system_dirs[ARS_SYSTEM_DIR_MAX];
    struct vcs_toolchain_capsule_v1 capsule;
    struct zcl_action_root_request req;
};

/* The generation a hotload module is loaded against is the host ABI; the
 * module and service ABIs are listed by name beside it. */
static const struct vcs_action_abi_v2 g_hotswap_abi[] = {
    { "hotswap_host", ZCL_HOTSWAP_HOST_ABI_V4 },
    { "hotswap_module", ZCL_HOTSWAP_MODULE_ABI_V3 },
    { "hotswap_service", ZCL_HOTSWAP_SERVICE_ABI_V1 },
};

struct ars_compile {
    const char *root, *owner, *cc, *cflags, *ldflags, *depfile;
};

static bool ars_hook_inputs(struct ars_hook *h, const struct ars_compile *k,
                            char *why, size_t why_len)
{
    struct zcl_action_root_request *r = &h->req;
    if (!vcs_toolchain_capsule_v1_capture(&h->capsule) ||
        !vcs_toolchain_capsule_v1_root(&h->capsule, r->toolchain_root)) {
        ars_why(why, why_len, "toolchain capsule unavailable", NULL);
        return false;
    }
    if (!ars_driver_facts(k->cc, &h->driver)) {
        ars_why(why, why_len, "compiler driver facts unavailable", k->cc);
        return false;
    }
    if (!ars_hotswap_argv(k->owner, k->cc, k->cflags, k->depfile,
                          &h->argv) ||
        !ars_hotswap_link_argv(k->cc, k->ldflags, &h->argv)) {
        ars_why(why, why_len, "compile argv or depfile input unavailable",
                k->depfile);
        return false;
    }
    return true;
}

static bool ars_hook_request(struct ars_hook *h, const struct ars_compile *k,
                             char *why, size_t why_len)
{
    struct zcl_action_root_request *r = &h->req;
    if (!ars_hook_inputs(h, k, why, why_len))
        return false;
    for (size_t i = 0; i < h->driver.count; i++)
        h->system_dirs[i] = h->driver.dirs[i];
    r->root = k->root;
    r->stage_kind = ZCL_ACTION_ROOT_STAGE_HOTSWAP;
    r->stage_version = ZCL_ACTION_ROOT_STAGE_HOTSWAP_VERSION;
    r->argv = h->argv.v;
    r->argc = h->argv.n;
    r->depfile = k->depfile;
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
    r->abi_generation = ZCL_HOTSWAP_HOST_ABI_V4;
    r->abi = g_hotswap_abi;
    r->abi_count = sizeof(g_hotswap_abi) / sizeof(g_hotswap_abi[0]);
    r->policy.present = true;
    ars_policy_root(r->policy.root);
    return true;
}

static bool ars_hook_derive(const struct ars_compile *k,
                            struct zcl_action_root_result *result,
                            char *why, size_t why_len)
{
    if (!k->root || !k->owner || !k->cc || !k->cflags || !k->ldflags ||
        !k->depfile) {
        ars_why(why, why_len, "hotload compile identity is incomplete", NULL);
        return false;
    }
    struct ars_hook *h = zcl_calloc(1, sizeof(*h), "action root hook");
    if (!h) {
        ars_why(why, why_len, "action root hook allocation failed", NULL);
        return false;
    }
    bool ok = ars_hook_request(h, k, why, why_len) &&
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
    const char *ldflags, const char *depfile,
    struct zcl_devloop_hotswap_build_receipt *receipt)
{
    if (!receipt)
        return;
    receipt->action_root[0] = '\0';
    receipt->action_root_cause[0] = '\0';
    receipt->action_root_refused[0] = '\0';
    char why[192] = {0};
    struct zcl_action_root_result result = {0};
    const struct ars_compile k = { root, owner, cc, cflags, ldflags,
                                   depfile };
    int64_t started = platform_time_monotonic_us();
    bool derived = ars_hook_derive(&k, &result, why, sizeof(why));
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
