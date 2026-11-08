/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: run an app copy's make fragment out of tree under lab_exec and
 *          root its declared input closure (see command/app_build_make.h). */

#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif

#include "command/app_build_make.h"
#include "command/app_toolchain.h"

#include "base/safe_alloc.h"
#include "command/lab_exec.h"
#include "platform/directory_compat.h"
#include "platform/positioned_file.h"
#include "platform/temp_directory.h"
#include "sha3/sha3.h"
#include "util/file_io.h"
#include "util/path_util.h"
#include "util/spawn.h"
#include "vcs/build_action.h"
#include "vcs/package_manifest.h"

#include <dirent.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define ABM_PATH 4400
#define ABM_QUERY_TIMEOUT_MS 60000u
#define ABM_BUILD_TIMEOUT_MS 600000u
#define ABM_DEPFILE_MAX (4u << 20)
#define ABM_INPUT_MAX (64u << 20)
#define ABM_DEPFILE_DEPTH 8
#define ABM_DECLARED_DOMAIN "zcl.app_build.declared_closure.v1"
#define ABM_NONE_DOMAIN "zcl.app_build.closure.none.v1"
#define ABM_GRAPH "zcl.app_build.make_graph.v1: make app APP_OUT=@out"
#define ABM_HARNESS "zcl.app_build.harness.v1: print-app-closure"
#define ABM_POLICY "zcl.app_build.policy.v1: lab_exec.compile"

static void abm_why(char *why, size_t cap, const char *fmt, ...)
{
    va_list ap;
    if (!why || cap == 0)
        return;
    va_start(ap, fmt);
    (void)vsnprintf(why, cap, fmt, ap);
    va_end(ap);
}

bool app_build_make_confinable(void)
{
    return lab_sandbox_available();
}

void app_build_closure_free(struct app_build_closure *c)
{
    if (!c)
        return;
    while (c->paths && c->count > 0)
        free(c->paths[--c->count]);
    free(c->paths);
    c->paths = NULL;
}

/* ── the confined make child ─────────────────────────────────────────── */

static const char *abm_make_path(void)
{
    static const char *const candidates[] = {"/usr/bin/make", "/bin/make",
                                             "/usr/local/bin/make"};
    for (size_t i = 0; i < sizeof(candidates) / sizeof(candidates[0]); i++)
        if (access(candidates[i], X_OK) == 0)
            return candidates[i];
    return NULL;
}

/* System tools read and execute; the copy read-only; `writable` (or none)
 * read, write and create. */
static size_t abm_rules(const char *copy_dir, const char *writable,
                        struct os_sandbox_path_rule r[10])
{
    static const char *const system_dirs[] = {"/usr", "/lib", "/lib64",
                                              "/bin"};
    struct stat st;
    size_t n = 0;
    for (size_t i = 0; i < sizeof(system_dirs) / sizeof(system_dirs[0]); i++)
        if (stat(system_dirs[i], &st) == 0 && S_ISDIR(st.st_mode))
            r[n++] = (struct os_sandbox_path_rule){
                .path = system_dirs[i], .allow_read = true,
                .allow_execute = true};
    r[n++] = (struct os_sandbox_path_rule){.path = "/etc/ld.so.cache",
                                           .allow_read = true};
    r[n++] = (struct os_sandbox_path_rule){.path = "/dev/null",
                                           .allow_read = true,
                                           .allow_write = true};
    r[n++] = (struct os_sandbox_path_rule){.path = copy_dir,
                                           .allow_read = true};
    if (writable)
        r[n++] = (struct os_sandbox_path_rule){
            .path = writable, .allow_read = true, .allow_write = true,
            .allow_create = true};
    return n;
}

struct abm_child {
    const char *argv[8];
    const char *env[8];
    char out_arg[ABM_PATH + 16];
    char tmpdir[ABM_PATH + 16];
    char home[ABM_PATH + 16];
    char kit_out[ABM_PATH];
};

static size_t abm_kit_rules(const struct app_toolchain *kit, bool writable,
    struct os_sandbox_path_rule rules[10])
{
    static const char *const dirs[] = {"/usr", "/lib", "/lib64", "/bin"};
    size_t count = 0;
    for (size_t i = 0; i < sizeof(dirs)/sizeof(dirs[0]); ++i) {
        size_t n = strlen(dirs[i]);
        for (size_t j = 0; j < kit->manifest.count; ++j) {
            const char *path = kit->manifest.entries[j].path + 6;
            if (strncmp(path, dirs[i], n) || path[n] != '/') continue;
            rules[count++] = (struct os_sandbox_path_rule){.path = dirs[i],
                .allow_read = true, .allow_execute = true};
            break;
        }
    }
    if (app_toolchain_member(kit, "/etc/ld.so.cache"))
        rules[count++] = (struct os_sandbox_path_rule){.path = "/etc/ld.so.cache", .allow_read = true};
    rules[count++] = (struct os_sandbox_path_rule){.path = "/dev/null", .allow_read = true, .allow_write = true};
    rules[count++] = (struct os_sandbox_path_rule){.path = "/source", .allow_read = true};
    if (writable) rules[count++] = (struct os_sandbox_path_rule){.path = "/work",
        .allow_read = true, .allow_write = true, .allow_create = true};
    return count;
}

static bool abm_kit_output(struct abm_child *c, const struct app_build_make *m,
                           const char *out_dir)
{
    char work[ABM_PATH], output[ABM_PATH];
    if (!platform_directory_canonical_real(m->work_dir, work, sizeof(work)) ||
        !platform_directory_canonical_real(out_dir, output, sizeof(output))) return false;
    size_t n = strlen(work);
    if (strncmp(output, work, n) || output[n] != '/' ||
        !vcs_package_path_valid(output + n + 1)) return false;
    int written = snprintf(c->kit_out, sizeof(c->kit_out), "/work/%s", output + n + 1);
    return written > 0 && (size_t)written < sizeof(c->kit_out);
}

static bool abm_child_init(struct abm_child *c, const struct app_build_make *m,
                           const char *target, const char *out_dir)
{
    bool kit = m->kit && m->kit->selected;
    const char *make = kit ? "/usr/bin/make" : abm_make_path();
    const char *scratch = out_dir ? out_dir : "/nonexistent";
    memset(c, 0, sizeof(*c));
    if (kit && out_dir) {
        if (!abm_kit_output(c, m, out_dir)) return false;
        out_dir = c->kit_out; scratch = out_dir;
    }
    if (!make)
        return false;
    (void)snprintf(c->tmpdir, sizeof(c->tmpdir), "TMPDIR=%s", scratch);
    (void)snprintf(c->home, sizeof(c->home), "HOME=%s", scratch);
    size_t a = 0;
    c->argv[a++] = make;
    c->argv[a++] = "--no-print-directory";
    c->argv[a++] = "-C";
    c->argv[a++] = kit ? "/source" : m->copy_dir;
    if (out_dir) {
        int n = snprintf(c->out_arg, sizeof(c->out_arg), "APP_OUT=%s",
                         out_dir);
        if (n <= 0 || (size_t)n >= sizeof(c->out_arg))
            return false;
        c->argv[a++] = c->out_arg;
    }
    c->argv[a++] = target;
    c->argv[a] = NULL;
    const char *env[] = {"PATH=/usr/bin:/bin", "LC_ALL=C", c->tmpdir, c->home,
                         "SOURCE_DATE_EPOCH=0", "CCACHE_DISABLE=1",
                         "ZCC_DISABLE=1", NULL};
    memcpy(c->env, env, sizeof(env));
    return true;
}

/* A host lab_exec cannot run children on (not Linux): the plain bounded
 * spawn, unconfined, merged output. */
static void abm_run_plain(const struct abm_child *c, const char *cwd,
                          uint32_t timeout_ms, struct lab_proc *p)
{
    bool timed_out = false;
    int rc = zcl_spawn_capture_merged_in_dir_observed(
        c->argv, cwd, p->out, LAB_CAPTURE_MAX, (int)timeout_ms, &timed_out);
    p->launch = rc < 0 && !timed_out ? LAB_LAUNCH_FAILED : LAB_LAUNCHED;
    p->exit_code = rc;
    p->timed_out = timed_out;
    p->out_len = strnlen(p->out, LAB_CAPTURE_MAX);
}

static bool abm_kit_root_prepare(const struct app_build_make *m, bool writable,
    char mount_dir[PLATFORM_TEMP_PATH_MAX], struct os_sandbox_kit_root *root,
    char *why, size_t why_cap)
{
    *root = (struct os_sandbox_kit_root){0};
    if (!m->confine || !m->kit->files ||
        m->kit->file_count != m->kit->manifest.count ||
        !platform_temp_directory_create("z23-kit-root-", mount_dir, PLATFORM_TEMP_PATH_MAX)) {
        abm_why(why, why_cap, "selected kit requires sealed files and a private confined root");
        return false;
    }
    *root = (struct os_sandbox_kit_root){.files = m->kit->files,
        .count = m->kit->file_count, .mount_dir = mount_dir,
        .source_dir = m->copy_dir, .work_dir = writable ? m->work_dir : NULL};
    return true;
}

static bool abm_launch_result(const struct lab_proc *p, bool kit,
    const char *target, char *why, size_t why_cap)
{
    if (p->launch == LAB_LAUNCHED) return true;
    abm_why(why, why_cap, "make %s did not start: %s", target,
            !kit && p->launch == LAB_LAUNCH_UNCONFINED
                ? "the confinement could not be applied, so it never ran"
                : p->detail);
    return false;
}

/* Run one make target; true when it launched (p holds its outcome).
 * *unconfined reports a run with no confinement applied. */
static bool abm_spawn(const struct app_build_make *m, const char *target,
                      const char *out_dir, struct lab_proc *p,
                      bool *unconfined, char *why, size_t why_cap)
{
    struct abm_child c;
    struct os_sandbox_path_rule rules[10];
    bool kit = m->kit && m->kit->selected;
    char mount_dir[PLATFORM_TEMP_PATH_MAX] = "";
    struct os_sandbox_kit_root root = {0};
    if (!abm_child_init(&c, m, target, out_dir)) {
        abm_why(why, why_cap, "no make program at /usr/bin, /bin or "
                              "/usr/local/bin, or the output path is too long");
        return false;
    }
    size_t n_rules;
    if (kit) {
        if (!abm_kit_root_prepare(m, out_dir != NULL, mount_dir, &root, why, why_cap)) return false;
        n_rules = abm_kit_rules(m->kit, out_dir != NULL, rules);
    } else n_rules = abm_rules(m->copy_dir, out_dir ? m->work_dir : NULL, rules);
    struct lab_spawn spawn = {
        .profile = LAB_PROFILE_COMPILE, .confine = m->confine,
        .argv = c.argv, .env = c.env, .cwd = kit ? "/source" : m->copy_dir, .rules = rules,
        .n_rules = n_rules, .kit_root = kit ? &root : NULL,
        .timeout_ms = out_dir ? ABM_BUILD_TIMEOUT_MS : ABM_QUERY_TIMEOUT_MS,
        .as_bytes = OS_SANDBOX_RLIMIT_KEEP, .fsize_bytes = 1024u << 20,
        .nofile = 512, .watch_dir = out_dir ? m->work_dir : NULL,
        .watch_max_bytes = 4ull << 30,
    };
    *unconfined = !m->confine;
    lab_spawn_run(&spawn, p);
    if (mount_dir[0] && rmdir(mount_dir) != 0) {
        abm_why(why, why_cap, "private compiler mount directory cleanup failed");
        return false;
    }
    if (!kit && p->launch == LAB_LAUNCH_UNSUPPORTED) {
        lab_proc_reset(p);
        *unconfined = true;
        abm_run_plain(&c, m->copy_dir, spawn.timeout_ms, p);
    }
    return abm_launch_result(p, kit, target, why, why_cap);
}

static bool abm_exited_ok(const struct lab_proc *p)
{
    return !p->timed_out && !p->disk_exceeded && p->term_signal == 0 &&
           p->exit_code == 0;
}

/* ── the declared closure ────────────────────────────────────────────── */

/* Root-level stores are not covered by the package root. */
static bool abm_store_segment(const char *segment, size_t len)
{
    static const char *const stores[] = {"build", ".zvcs", ".codeindex"};
    for (size_t i = 0; i < sizeof(stores) / sizeof(stores[0]); i++)
        if (strlen(stores[i]) == len && memcmp(segment, stores[i], len) == 0)
            return true;
    return false;
}

/* A declared input the package root covers: canonical, not a local store. */
static bool abm_declarable(const char *path)
{
    size_t n = strcspn(path, "/");
    return vcs_package_path_valid(path) &&
           !(path[n] == '/' && abm_store_segment(path, n));
}

/* The first index whose path is not below `path` (the list stays sorted). */
static size_t abm_lower_bound(const struct app_build_closure *c,
                              const char *path)
{
    size_t lo = 0, hi = c->count;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2u;
        if (strcmp(c->paths[mid], path) < 0)
            lo = mid + 1u;
        else
            hi = mid;
    }
    return lo;
}

static bool abm_declared(const struct app_build_closure *c, const char *path)
{
    size_t at = abm_lower_bound(c, path);
    return at < c->count && strcmp(c->paths[at], path) == 0;
}

/* Insert in sorted order; a repeated path is kept once. */
static bool abm_push(struct app_build_closure *c, const char *path)
{
    if (abm_declared(c, path))
        return true;
    if (c->count >= APP_BUILD_CLOSURE_MAX)
        return false;
    if (!c->paths) {
        c->paths = zcl_calloc(APP_BUILD_CLOSURE_MAX, sizeof(char *),
                              "app.build.closure_list");
        if (!c->paths)
            return false;
    }
    char *copy = zcl_strdup(path, "app.build.closure_path");
    if (!copy)
        return false;
    size_t at = abm_lower_bound(c, path);
    memmove(&c->paths[at + 1u], &c->paths[at],
            (c->count - at) * sizeof(char *));
    c->paths[at] = copy;
    c->count++;
    return true;
}

/* Split the query output into canonical paths ("./" stripped). */
static bool abm_parse(char *text, struct app_build_closure *c, char *why,
                      size_t why_cap)
{
    char *save = NULL;
    for (char *line = strtok_r(text, "\r\n", &save); line;
         line = strtok_r(NULL, "\r\n", &save)) {
        while (*line == ' ' || *line == '\t')
            line++;
        size_t len = strcspn(line, " \t");
        if (len == 0)
            continue;
        if (len > 2 && strncmp(line, "./", 2) == 0) {
            line += 2;
            len -= 2;
        }
        line[len] = '\0';
        if (!abm_declarable(line)) {
            abm_why(why, why_cap, "print-app-closure named '%s', which is not "
                                  "a package path in the copy", line);
            return false;
        }
        if (!abm_push(c, line)) {
            abm_why(why, why_cap, "print-app-closure named more than %u "
                                  "inputs, or the list could not be "
                                  "allocated", APP_BUILD_CLOSURE_MAX);
            return false;
        }
    }
    return true;
}

/* SHA3-256 of one regular, unlinked-by-symlink copy file. */
static bool abm_hash_file(const char *copy_dir, const char *rel,
                          uint8_t out[32])
{
    char path[ABM_PATH];
    struct stat st;
    uint8_t *bytes = NULL;
    size_t len = 0;
    int n = snprintf(path, sizeof(path), "%s/%s", copy_dir, rel);
    /* The copy already prepared as a package, which refuses symlinks and
     * special files; lstat keeps a later swap from being followed. */
    if (n <= 0 || (size_t)n >= sizeof(path) || lstat(path, &st) != 0 ||
        !S_ISREG(st.st_mode) ||
        !zcl_read_whole_file(path, ABM_INPUT_MAX, &bytes, &len, "app.build"))
        return false;
    zcl_sha3_256(bytes, len, out);
    free(bytes);
    return true;
}

static void abm_named(const char *text, const uint8_t *extra,
                      size_t extra_len, uint8_t out[32])
{
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)text, strlen(text) + 1u);
    if (extra)
        sha3_256_write(&sha, extra, extra_len);
    sha3_256_finalize(&sha, out);
}

static bool abm_root(const struct app_build_make *m,
                     struct app_build_closure *c, char *why, size_t why_cap)
{
    struct vcs_build_input_closure_v1 closure;
    struct sha3_256_ctx sha;
    uint8_t count_le[4] = {(uint8_t)c->count, (uint8_t)(c->count >> 8),
                           (uint8_t)(c->count >> 16),
                           (uint8_t)(c->count >> 24)};
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)ABM_DECLARED_DOMAIN,
                   sizeof(ABM_DECLARED_DOMAIN));
    sha3_256_write(&sha, count_le, sizeof(count_le));
    for (size_t i = 0; i < c->count; i++) {
        uint8_t file[32];
        if (!abm_hash_file(m->copy_dir, c->paths[i], file)) {
            abm_why(why, why_cap, "declared input '%s' is not a readable "
                                  "regular file in the copy", c->paths[i]);
            return false;
        }
        sha3_256_write(&sha, (const uint8_t *)c->paths[i],
                       strlen(c->paths[i]) + 1u);
        sha3_256_write(&sha, file, sizeof(file));
    }
    sha3_256_finalize(&sha, closure.positive_sha3);
    abm_named(ABM_NONE_DOMAIN, (const uint8_t *)"negative", 8,
              closure.negative_sha3);
    abm_named(ABM_NONE_DOMAIN, (const uint8_t *)"generated", 9,
              closure.generated_sha3);
    abm_named(ABM_GRAPH, NULL, 0, closure.build_graph_sha3);
    abm_named(ABM_HARNESS, NULL, 0, closure.harness_sha3);
    abm_named(ABM_POLICY, NULL, 0, closure.policy_sha3);
    if (!vcs_build_input_closure_v1_root(&closure, c->root)) {
        abm_why(why, why_cap, "the declared closure has no root");
        return false;
    }
    return true;
}

bool app_build_closure_query(const struct app_build_make *m,
                             struct app_build_closure *out, char *why,
                             size_t why_cap)
{
    struct lab_proc p;
    bool unconfined = false;
    memset(out, 0, sizeof(*out));
    if (!m || !m->copy_dir || !lab_proc_init(&p)) {
        abm_why(why, why_cap, "closure query setup failed");
        return false;
    }
    bool ok = abm_spawn(m, "print-app-closure", NULL, &p, &unconfined, why,
                        why_cap);
    if (ok && (!abm_exited_ok(&p) || p.out_cut)) {
        abm_why(why, why_cap, "make print-app-closure %s: %.160s",
                p.out_cut ? "printed more than the query bound"
                          : "failed", p.err_len ? p.err : p.out);
        ok = false;
    }
    ok = ok && abm_parse(p.out, out, why, why_cap);
    lab_proc_free(&p);
    if (ok && out->count == 0) {
        abm_why(why, why_cap, "make print-app-closure declared no inputs");
        ok = false;
    }
    ok = ok && abm_root(m, out, why, why_cap);
    if (!ok)
        app_build_closure_free(out);
    return ok;
}

/* ── the build ───────────────────────────────────────────────────────── */

/* The last APP_BUILD_TAIL_MAX bytes of stderr, where compiler and make
 * diagnostics land, else of stdout. */
static void abm_tail(const struct lab_proc *p, char *tail)
{
    size_t err_len = p->err ? strnlen(p->err, LAB_CAPTURE_MAX) : 0;
    const char *src = err_len ? p->err : (p->out ? p->out : "");
    size_t len = err_len ? err_len : strnlen(src, LAB_CAPTURE_MAX);
    size_t from = len > APP_BUILD_TAIL_MAX ? len - APP_BUILD_TAIL_MAX : 0;
    memcpy(tail, src + from, len - from);
    tail[len - from] = '\0';
}

void app_build_make_run(const struct app_build_make *m, const char *out_dir,
                        struct app_build_make_result *r)
{
    struct lab_proc p;
    memset(r, 0, sizeof(*r));
    if (!m || !m->copy_dir || !m->work_dir || !out_dir ||
        !lab_proc_init(&p)) {
        abm_why(r->why, sizeof(r->why), "build setup failed");
        return;
    }
    if (abm_spawn(m, APP_BUILD_IMAGE_NAME, out_dir, &p, &r->unconfined,
                  r->why, sizeof(r->why))) {
        abm_tail(&p, r->tail);
        r->ok = abm_exited_ok(&p);
        if (!r->ok)
            abm_why(r->why, sizeof(r->why),
                    "make app %s (exit %d%s%s)",
                    p.timed_out ? "timed out" : "failed", p.exit_code,
                    p.term_signal ? ", signal " : "",
                    lab_signal_name(p.term_signal));
    }
    lab_proc_free(&p);
}

/* ── depfile check ───────────────────────────────────────────────────── */

struct abm_depcheck {
    const struct app_toolchain *kit;
    const struct app_build_closure *c;
    char root[ABM_PATH];
    size_t depfiles;
    char *why;
    size_t why_cap;
};

/* Resolve filesystem aliases before membership checks. The no-follow regular
 * file open refuses leaf symlinks; handle-bound paths expose parent escapes. */
static bool abm_file_path(const char *input, char canonical[ABM_PATH])
{
    struct platform_positioned_file file;
    platform_positioned_file_init(&file);
    if (!platform_positioned_file_open(&file, input))
        return false;
    bool resolved = platform_positioned_file_path(&file, canonical, ABM_PATH);
    platform_positioned_file_close(&file);
    return resolved;
}

static bool abm_inside(const struct abm_depcheck *d, const char *path)
{
    size_t len = strlen(d->root);
    return strncmp(path, d->root, len) == 0 &&
           (path[len] == '/' || path[len] == '\0');
}

static bool abm_local_prereq(struct abm_depcheck *d, const char *token)
{
    char path[ABM_PATH], canonical[ABM_PATH];
    const char *input = token;
    if (token[0] != '/') {
        if (!zcl_path_join(path, sizeof(path), d->root, token))
            return false;
        input = path;
    }
    bool resolved = abm_file_path(input, canonical);
    size_t root_len = strlen(d->root);
    return resolved && strncmp(canonical, d->root, root_len) == 0 &&
           canonical[root_len] == '/' &&
           abm_declared(d->c, canonical + root_len + 1u);
}

/* Resolve before deciding external policy. POSIX system headers may have a
 * symlink leaf; resolution alone grants no input identity or byte coverage.
 * Windows keeps the maintained no-reparse regular-file resolver. */
static bool abm_absolute_path(const char *token, char canonical[ABM_PATH])
{
#if defined(_WIN32)
    return abm_file_path(token, canonical);
#else
    char *resolved = realpath(token, NULL);
    if (!resolved) return false;
    int n = snprintf(canonical, ABM_PATH, "%s", resolved);
    free(resolved);
    return n > 0 && (size_t)n < ABM_PATH;
#endif
}

/* An aliased spelling may enter the copy before a later .. or symlink
 * escapes. Check original traversal prefixes, not just its final location. */
static bool abm_traverses_copy(const struct abm_depcheck *d, const char *token)
{
    char prefix[ABM_PATH], resolved[ABM_PATH];
    int n = snprintf(prefix, sizeof(prefix), "%s", token);
    if (n <= 0 || (size_t)n >= sizeof(prefix)) return true;
    for (char *slash = strchr(prefix + 1, '/'); slash;
         slash = strchr(slash + 1, '/')) {
        *slash = '\0';
        bool inside = platform_directory_canonical_real(prefix, resolved,
            sizeof(resolved)) && abm_inside(d, resolved);
        *slash = '/';
        if (inside) return true;
    }
    return false;
}

/* Reject paths that traverse a root-level store even if a later .. or
 * symlink reaches a declared file. Resolve each parent so an absolute
 * alias of the copy root is subject to the same rule. */
static bool abm_store_traversal(const struct abm_depcheck *d, const char *token)
{
    char path[ABM_PATH], resolved[ABM_PATH];
    if (token[0] == '/') {
        int n = snprintf(path, sizeof(path), "%s", token);
        if (n <= 0 || (size_t)n >= sizeof(path)) return true;
    } else if (!zcl_path_join(path, sizeof(path), d->root, token)) {
        return true;
    }
    for (char *slash = strchr(path + 1, '/'); slash; slash = strchr(slash + 1, '/')) {
        const char *segment = slash + 1;
        size_t len = strcspn(segment, "/");
        if (segment[len] != '/' || !abm_store_segment(segment, len)) continue;
        *slash = '\0';
        bool at_root = platform_directory_canonical_real(path, resolved, sizeof(resolved)) &&
                       strcmp(resolved, d->root) == 0;
        *slash = '/';
        if (at_root) return true;
    }
    return false;
}

/* Resolve lexical compiler paths inside the sealed namespace, never through
 * the host's realpath or its external-header allowance. */
static bool abm_kit_prereq_path(const char *token, char path[ABM_PATH])
{
    size_t used = 0;
    path[0] = 0;
    const char *part = token + 1;
    while (*part) {
        size_t n = strcspn(part, "/");
        if (n == 2 && !memcmp(part, "..", 2)) {
            if (!used || !strcmp(path, "/source")) return false;
            while (used && path[used - 1] != '/') --used;
            if (used) --used;
            path[used] = 0;
        } else if (n && !(n == 1 && *part == '.')) {
            if (used + n + 1 >= ABM_PATH) return false;
            path[used++] = '/'; memcpy(path + used, part, n); used += n; path[used] = 0;
        }
        part += n; if (*part) ++part;
    }
    return used != 0;
}

static bool abm_kit_prereq_ok(struct abm_depcheck *d, const char *token)
{
    if (!strncmp(token, "/source/", 8)) {
        if (!abm_store_traversal(d, token + 8) && abm_local_prereq(d, token + 8)) return true;
        abm_why(d->why, d->why_cap, "kit source prerequisite is undeclared or escapes: %s", token);
        return false;
    }
    char path[ABM_PATH];
    if (abm_kit_prereq_path(token, path) && app_toolchain_member(d->kit, path)) return true;
    abm_why(d->why, d->why_cap, "kit build read an undeclared source or compiler input: %s", token);
    return false;
}

/* The external-absolute allowance is existing policy, not capsule proof.
 * A relative or copy-prefixed path must never escape into that allowance. */
static bool abm_prereq_ok(struct abm_depcheck *d, const char *token)
{
    if (d->kit && d->kit->selected && token[0] == '/') return abm_kit_prereq_ok(d, token);
    if (abm_store_traversal(d, token)) {
        abm_why(d->why, d->why_cap, "the build read '%s' through an excluded local store", token);
        return false;
    }
    if (token[0] == '/') {
        char canonical[ABM_PATH];
        if (abm_absolute_path(token, canonical) && !abm_inside(d, canonical) &&
            !abm_traverses_copy(d, token))
            return true;
    }
    if (abm_local_prereq(d, token))
        return true;
    abm_why(d->why, d->why_cap, "the build read '%s', which does not resolve "
            "to a declared regular input inside the source copy", token);
    return false;
}

static bool abm_depfile_check(struct abm_depcheck *d, const char *path)
{
    char *text = NULL;
    size_t len = 0;
    if (!zcl_read_whole_file_text(path, ABM_DEPFILE_MAX, &text, &len,
                                  "app.build")) {
        abm_why(d->why, d->why_cap, "depfile %s is unreadable", path);
        return false;
    }
    bool ok = true;
    char *save = NULL;
    for (char *t = strtok_r(text, " \t\r\n", &save); t && ok;
         t = strtok_r(NULL, " \t\r\n", &save)) {
        size_t tl = strlen(t);
        if (strcmp(t, "\\") == 0 || t[tl - 1u] == ':')
            continue;
        ok = abm_prereq_ok(d, t);
    }
    free(text);
    d->depfiles++;
    return ok;
}

static bool abm_is_depfile(const char *name)
{
    size_t n = strlen(name);
    return n > 2 && strcmp(name + n - 2, ".d") == 0;
}

static bool abm_walk(struct abm_depcheck *d, const char *dir, int depth)
{
    DIR *dh = opendir(dir);
    if (!dh) {
        abm_why(d->why, d->why_cap, "cannot list %s", dir);
        return false;
    }
    bool ok = true;
    struct dirent *e;
    while (ok && (e = readdir(dh)) != NULL) {
        char path[ABM_PATH];
        struct stat st;
        if (e->d_name[0] == '.' ||
            snprintf(path, sizeof(path), "%s/%s", dir, e->d_name) >=
                (int)sizeof(path) ||
            lstat(path, &st) != 0)
            continue;
        if (S_ISDIR(st.st_mode) && depth < ABM_DEPFILE_DEPTH)
            ok = abm_walk(d, path, depth + 1);
        else if (S_ISREG(st.st_mode) && abm_is_depfile(e->d_name))
            ok = abm_depfile_check(d, path);
    }
    (void)closedir(dh);
    return ok;
}

bool app_build_depfiles_declared(const struct app_build_make *m,
                                 const char *out_dir,
                                 const struct app_build_closure *c, char *why,
                                 size_t why_cap)
{
    struct abm_depcheck d = {.c = c, .why = why, .why_cap = why_cap};
    if (!m || !m->copy_dir || !out_dir || !c)
        return false;
    d.kit = m->kit;
    if (!platform_directory_canonical_real(m->copy_dir, d.root, sizeof(d.root))) {
        abm_why(why, why_cap, "the source copy directory cannot be resolved");
        return false;
    }
    if (!abm_walk(&d, out_dir, 0))
        return false;
    if (d.depfiles == 0) {
        abm_why(why, why_cap, "the build left no -MD depfile under APP_OUT, "
                              "so what it read is unproven");
        return false;
    }
    return true;
}
