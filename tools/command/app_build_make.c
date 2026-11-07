/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: run an app copy's make fragment out of tree under lab_exec and
 *          root its declared input closure (see command/app_build_make.h). */

#include "command/app_build_make.h"

#include "base/safe_alloc.h"
#include "command/lab_exec.h"
#include "sha3/sha3.h"
#include "util/file_io.h"
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
};

static bool abm_child_init(struct abm_child *c, const struct app_build_make *m,
                           const char *target, const char *out_dir)
{
    const char *make = abm_make_path();
    const char *scratch = out_dir ? out_dir : "/nonexistent";
    memset(c, 0, sizeof(*c));
    if (!make)
        return false;
    (void)snprintf(c->tmpdir, sizeof(c->tmpdir), "TMPDIR=%s", scratch);
    (void)snprintf(c->home, sizeof(c->home), "HOME=%s", scratch);
    size_t a = 0;
    c->argv[a++] = make;
    c->argv[a++] = "--no-print-directory";
    c->argv[a++] = "-C";
    c->argv[a++] = m->copy_dir;
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

/* Run one make target; true when it launched (p holds its outcome).
 * *unconfined reports a run with no confinement applied. */
static bool abm_spawn(const struct app_build_make *m, const char *target,
                      const char *out_dir, struct lab_proc *p,
                      bool *unconfined, char *why, size_t why_cap)
{
    struct abm_child c;
    struct os_sandbox_path_rule rules[10];
    if (!abm_child_init(&c, m, target, out_dir)) {
        abm_why(why, why_cap, "no make program at /usr/bin, /bin or "
                              "/usr/local/bin, or the output path is too long");
        return false;
    }
    struct lab_spawn spawn = {
        .profile = LAB_PROFILE_COMPILE, .confine = m->confine,
        .argv = c.argv, .env = c.env, .cwd = m->copy_dir, .rules = rules,
        .n_rules = abm_rules(m->copy_dir, out_dir ? m->work_dir : NULL, rules),
        .timeout_ms = out_dir ? ABM_BUILD_TIMEOUT_MS : ABM_QUERY_TIMEOUT_MS,
        .as_bytes = OS_SANDBOX_RLIMIT_KEEP, .fsize_bytes = 1024u << 20,
        .nofile = 512, .watch_dir = out_dir ? m->work_dir : NULL,
        .watch_max_bytes = 4ull << 30,
    };
    *unconfined = !m->confine;
    lab_spawn_run(&spawn, p);
    if (p->launch == LAB_LAUNCH_UNSUPPORTED) {
        lab_proc_reset(p);
        *unconfined = true;
        abm_run_plain(&c, m->copy_dir, spawn.timeout_ms, p);
    }
    if (p->launch != LAB_LAUNCHED) {
        abm_why(why, why_cap, "make %s did not start: %s", target,
                p->launch == LAB_LAUNCH_UNCONFINED
                    ? "the confinement could not be applied, so it never ran"
                    : p->detail);
        return false;
    }
    return true;
}

static bool abm_exited_ok(const struct lab_proc *p)
{
    return !p->timed_out && !p->disk_exceeded && p->term_signal == 0 &&
           p->exit_code == 0;
}

/* ── the declared closure ────────────────────────────────────────────── */

/* A declared input the package root covers: canonical, not a local store. */
static bool abm_declarable(const char *path)
{
    static const char *const stores[] = {"build/", ".zvcs/", ".codeindex/"};
    if (!vcs_package_path_valid(path))
        return false;
    for (size_t i = 0; i < sizeof(stores) / sizeof(stores[0]); i++)
        if (strncmp(path, stores[i], strlen(stores[i])) == 0)
            return false;
    return true;
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
    const struct app_build_make *m;
    const struct app_build_closure *c;
    size_t copy_len;
    size_t depfiles;
    char *why;
    size_t why_cap;
};

/* Lexically fold "." and ".." segments of a copy-relative path the way the
 * compiler spelled it (a source's `#include "../x.h"` lands in a depfile
 * as "dir/sub/../x.h"). The copy holds no symlinks (it prepared as a
 * package), so the folded path names the same file. False when the path
 * climbs above the copy or does not fit. */
static bool abm_fold_segment(const char *seg, size_t n, char *out, size_t cap,
                             size_t *len)
{
    if (n == 0 || (n == 1 && seg[0] == '.'))
        return true;
    if (n == 2 && seg[0] == '.' && seg[1] == '.') {
        if (*len == 0)
            return false;
        while (*len > 0 && out[*len - 1u] != '/')
            (*len)--;
        *len = *len > 0 ? *len - 1u : 0;
        return true;
    }
    if (*len + 1u + n + 1u > cap)
        return false;
    if (*len)
        out[(*len)++] = '/';
    memcpy(out + *len, seg, n);
    *len += n;
    return true;
}

static bool abm_fold(const char *rel, char *out, size_t cap)
{
    size_t len = 0;
    while (*rel) {
        size_t seg = strcspn(rel, "/");
        if (!abm_fold_segment(rel, seg, out, cap, &len))
            return false;
        rel += seg + (rel[seg] == '/' ? 1u : 0u);
    }
    out[len] = '\0';
    return len > 0;
}

/* One prerequisite: declared, or a system file outside the copy. */
static bool abm_prereq_ok(struct abm_depcheck *d, const char *token)
{
    const char *rel = token;
    char folded[ABM_PATH];
    if (token[0] == '/') {
        if (strncmp(token, d->m->copy_dir, d->copy_len) != 0 ||
            token[d->copy_len] != '/')
            return true;
        rel = token + d->copy_len + 1u;
    }
    if (abm_fold(rel, folded, sizeof(folded)) &&
        abm_declared(d->c, folded))
        return true;
    abm_why(d->why, d->why_cap, "the build read '%s', which "
                                "print-app-closure does not declare", rel);
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
    struct abm_depcheck d = {.m = m, .c = c, .why = why, .why_cap = why_cap};
    if (!m || !m->copy_dir || !out_dir || !c)
        return false;
    d.copy_len = strlen(m->copy_dir);
    if (!abm_walk(&d, out_dir, 0))
        return false;
    if (d.depfiles == 0) {
        abm_why(why, why_cap, "the build left no -MD depfile under APP_OUT, "
                              "so what it read is unproven");
        return false;
    }
    return true;
}
