/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: Snapshot half of the action-root reuse study: materialize one
 * commit's exact bytes, read its own Makefile's compile argv, and derive a
 * v2 action root (or an explicit MISS) for every dev-profile compile.
 *
 * Two closures per action. A: the depfile the study's one real dev build
 * wrote, used only when the snapshot's own preprocessor reports exactly the
 * same ordered prerequisites (otherwise MISS depfile-stale). B: the
 * snapshot's own `cc -MM` list under the same argv, never stale.
 */

#if !defined(_WIN32)
#define _GNU_SOURCE
#endif

#include "action_root_reuse_study.h"
#include "devloop_action_root.h"

#include "base/safe_alloc.h"
#include "platform/time_compat.h"
#include "util/spawn.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ST_ZERO64 \
    "0000000000000000000000000000000000000000000000000000000000000000"

extern char **environ;

/* ---- small utilities --------------------------------------------------- */

bool st_list_push(struct st_list *l, const char *s)
{
    if (l->n == l->cap) {
        size_t cap = l->cap ? l->cap * 2 : 64;
        char **g = zcl_realloc(l->v, cap * sizeof(*g), "study list");
        if (!g)
            return false;
        l->v = g;
        l->cap = cap;
    }
    char *copy = zcl_strdup(s, "study list item");
    if (!copy)
        return false;
    l->v[l->n++] = copy;
    return true;
}

void st_list_free(struct st_list *l)
{
    for (size_t i = 0; i < l->n; i++)
        free(l->v[i]);
    free(l->v);
    memset(l, 0, sizeof(*l));
}

bool st_list_has(const struct st_list *l, const char *s)
{
    for (size_t i = 0; i < l->n; i++)
        if (strcmp(l->v[i], s) == 0)
            return true;
    return false;
}

static int st_i64_cmp(const void *a, const void *b)
{
    int64_t x = *(const int64_t *)a, y = *(const int64_t *)b;
    return (x > y) - (x < y);
}

void st_sample(struct st_samples *s, int64_t v)
{
    if (s->n == s->cap) {
        size_t cap = s->cap ? s->cap * 2 : 4096;
        int64_t *g = zcl_realloc(s->v, cap * sizeof(*g), "study samples");
        if (!g)
            return;
        s->v = g;
        s->cap = cap;
    }
    s->v[s->n++] = v;
}

int64_t st_pct(struct st_samples *s, unsigned pct)
{
    if (s->n == 0)
        return 0;
    qsort(s->v, s->n, sizeof(*s->v), st_i64_cmp);
    size_t at = (s->n * pct + 99) / 100;
    return s->v[at ? at - 1 : 0];
}

int64_t st_sum(const struct st_samples *s)
{
    int64_t t = 0;
    for (size_t i = 0; i < s->n; i++)
        t += s->v[i];
    return t;
}

char *st_read_file(const char *path, size_t max, size_t *len)
{
    FILE *f = fopen(path, "rb");
    if (!f)
        return NULL;
    char *buf = zcl_malloc(max + 1, "study file read");
    size_t n = buf ? fread(buf, 1, max + 1, f) : 0;
    bool ok = buf && !ferror(f) && n <= max;
    fclose(f);
    if (!ok) {
        free(buf);
        return NULL;
    }
    buf[n] = '\0';
    if (len)
        *len = n;
    return buf;
}

/* ---- process runner ---------------------------------------------------- */

/* Run argv with stdout+stderr captured; true when it exited 0. */
bool st_run(const char *const *argv, size_t cap, struct st_proc *p)
{
    memset(p, 0, sizeof(*p));
    p->exit_code = -1;
    p->out = zcl_malloc(cap + 1, "study process output");
    if (!p->out)
        return false;
    struct zcl_spawn_binary_observation obs = {0};
    struct zcl_result r = zcl_spawn_capture_binary_merged(
        argv, p->out, cap, ST_TIMEOUT_MS, &obs);
    p->len = obs.output_len <= cap ? obs.output_len : cap;
    p->out[p->len] = '\0';
    if (obs.exit_observed)
        p->exit_code = obs.exit_code;
    return r.ok && obs.exit_observed && obs.exit_code == 0;
}

void st_proc_free(struct st_proc *p)
{
    free(p->out);
    memset(p, 0, sizeof(*p));
}

bool st_run_quiet(const char *const *argv)
{
    struct st_proc p;
    bool ok = st_run(argv, ST_SMALL_CAP, &p);
    if (!ok)
        fprintf(stderr, "study: %s failed (exit %d): %.400s\n", argv[0],
                p.exit_code, p.out ? p.out : "");
    st_proc_free(&p);
    return ok;
}

bool st_rm_rf(const char *path)
{
    const char *argv[] = { "rm", "-rf", "--", path, NULL };
    return st_run_quiet(argv);
}

bool st_mkdir_p(const char *path)
{
    const char *argv[] = { "mkdir", "-p", "--", path, NULL };
    return st_run_quiet(argv);
}

/* First line of a command's output, trimmed. */
bool st_run_line(const char *const *argv, char *out, size_t cap)
{
    struct st_proc p;
    bool ok = st_run(argv, ST_SMALL_CAP, &p);
    if (ok) {
        size_t n = strcspn(p.out, "\r\n");
        (void)snprintf(out, cap, "%.*s", (int)n, p.out);
    }
    st_proc_free(&p);
    return ok;
}

/* ---- toolchain facts (constant for the whole study) -------------------- */

/* The `#include <...> search starts here:` list of `cc -E -v`. */
static bool st_parse_system_dirs(char *text, struct st_toolchain *t)
{
    char *start = strstr(text, "#include <...> search starts here:");
    char *end = start ? strstr(start, "End of search list.") : NULL;
    if (!start || !end)
        return false;
    *end = '\0';
    char *save = NULL;
    char *line = strtok_r(strchr(start, '\n'), "\n", &save);
    for (; line && t->dir_count < ST_SYSDIR_MAX;
         line = strtok_r(NULL, "\n", &save)) {
        while (*line == ' ')
            line++;
        if (line[0] != '/')
            continue;
        char *res = realpath(line, NULL);
        (void)snprintf(t->dirs[t->dir_count], PATH_MAX, "%s",
                       res ? res : line);
        free(res);
        t->dir_ptr[t->dir_count] = t->dirs[t->dir_count];
        t->dir_count++;
    }
    return t->dir_count > 0;
}

bool st_toolchain_capture(struct st_toolchain *t)
{
    struct vcs_toolchain_capsule_v1 capsule;
    memset(t, 0, sizeof(*t));
    if (!vcs_toolchain_capsule_v1_capture(&capsule) ||
        !vcs_toolchain_capsule_v1_root(&capsule, t->root)) {
        fprintf(stderr, "study: toolchain capsule unavailable\n");
        return false;
    }
    memcpy(t->sysroot_objects, capsule.sysroot_sha3, 32);
    const char *probe[] = { "cc", "-xc", "-E", "-v", "/dev/null", NULL };
    struct st_proc p;
    bool ok = st_run(probe, ST_SMALL_CAP, &p) &&
              st_parse_system_dirs(p.out, t);
    st_proc_free(&p);
    const char *sysroot[] = { "cc", "-print-sysroot", NULL };
    ok = ok && st_run_line(sysroot, t->sysroot, sizeof(t->sysroot));
    if (!ok)
        fprintf(stderr, "study: compiler driver facts unavailable\n");
    return ok;
}

/* ---- shell-word splitting of one make dry-run command ------------------ */

/* Split one POSIX shell command (quotes and backslashes only; the dry-run
 * lines this reads carry no expansions) into owned words. */
static bool st_shell_split(const char *s, struct st_list *out)
{
    size_t cap = strlen(s) + 1;
    char *word = zcl_malloc(cap, "study shell word");
    if (!word)
        return false;
    size_t w = 0;
    bool in_word = false, ok = true;
    char quote = 0;
    for (const char *p = s; ok && *p; p++) {
        char c = *p;
        if (quote == '\'') {
            if (c == '\'')
                quote = 0;
            else
                word[w++] = c;
            continue;
        }
        if (c == '\\' && p[1] &&
            (!quote || strchr("\"\\$`", p[1]))) {
            word[w++] = *++p;
            in_word = true;
            continue;
        }
        if (quote == '"') {
            if (c == '"')
                quote = 0;
            else
                word[w++] = c;
            continue;
        }
        if (c == '\'' || c == '"') {
            quote = c;
            in_word = true;
            continue;
        }
        if (c == ' ' || c == '\t' || c == '\n') {
            if (in_word) {
                word[w] = '\0';
                ok = st_list_push(out, word);
                w = 0;
                in_word = false;
            }
            continue;
        }
        word[w++] = c;
        in_word = true;
    }
    if (ok && in_word) {
        word[w] = '\0';
        ok = st_list_push(out, word);
    }
    free(word);
    return ok && quote == 0;
}

/* ---- one compile action ------------------------------------------------ */

static void st_tu_free(struct st_tu *t)
{
    free(t->src);
    st_list_free(&t->argv);
    st_list_free(&t->deps);
    free(t->pre);
    memset(t, 0, sizeof(*t));
}

void st_snap_free(struct st_snap *s)
{
    for (size_t i = 0; i < s->n; i++)
        st_tu_free(&s->tu[i]);
    free(s->tu);
    free(s->test_flags);
    s->tu = NULL;
    s->n = 0;
    s->test_flags = NULL;
}

/* Replace every spelling of the snapshot root in `in` with "@root". */
static char *st_rootless(const char *in, const char *root)
{
    size_t rl = strlen(root), n = strlen(in);
    char *out = zcl_malloc(n + 64 + n / 4, "study rootless text");
    if (!out)
        return NULL;
    size_t o = 0;
    for (size_t i = 0; i < n;) {
        if (strncmp(in + i, root, rl) == 0) {
            memcpy(out + o, "@root", 5);
            o += 5;
            i += rl;
        } else {
            out[o++] = in[i++];
        }
    }
    out[o] = '\0';
    return out;
}

static bool st_basename_is(const char *path, const char *name)
{
    const char *slash = strrchr(path, '/');
    return strcmp(slash ? slash + 1 : path, name) == 0;
}

/* Words of one dry-run record: ZSTUDY_ARGV dep OBJ SRC ... -- CC flags. */
static bool st_tu_from_words(const struct st_list *w, struct st_tu *t)
{
    size_t dash = 0;
    for (size_t i = 0; i < w->n && !dash; i++)
        if (strcmp(w->v[i], "--") == 0)
            dash = i;
    if (w->n < 5 || !dash || dash + 2 >= w->n)
        return false;
    size_t cc = dash + 1;
    if (st_basename_is(w->v[cc], "zcc"))
        cc++; /* the in-tree compile cache wrapper execs the next word */
    t->src = zcl_strdup(w->v[3], "study tu source");
    if (!t->src || cc >= w->n)
        return false;
    bool ok = st_list_push(&t->argv, w->v[cc]);
    t->flag_lo = 1;
    for (size_t i = cc + 1; ok && i < w->n; i++) {
        ok = st_list_push(&t->argv, w->v[i]);
        if (strncmp(w->v[i], "-DZCL_BUILD_SOURCE_ID=", 22) == 0)
            t->identity = true;
    }
    t->flag_hi = t->argv.n;
    static const char *const tail[] = {
        "-MMD", "-MP", "-MF", "@out/depfile", "-MT", "@out/object",
        "-c", "-o", "@out/object",
    };
    for (size_t i = 0; ok && i < sizeof(tail) / sizeof(tail[0]); i++)
        ok = st_list_push(&t->argv, tail[i]);
    return ok && st_list_push(&t->argv, t->src);
}

/* Join one record's backslash-newline continuations. */
static char *st_join_record(char *start, char **next)
{
    char *p = start;
    for (;;) {
        char *nl = strchr(p, '\n');
        if (!nl) {
            *next = p + strlen(p);
            return start;
        }
        if (nl > start && nl[-1] == '\\') {
            nl[-1] = ' ';
            *nl = ' ';
            p = nl + 1;
            continue;
        }
        *nl = '\0';
        *next = nl + 1;
        return start;
    }
}

static bool st_parse_records(char *text, struct st_snap *s)
{
    s->tu = zcl_calloc(ST_MAX_SNAP_TUS, sizeof(*s->tu), "study tus");
    if (!s->tu)
        return false;
    char *p = text;
    while (*p) {
        char *next = NULL;
        char *line = st_join_record(p, &next);
        p = next;
        if (strncmp(line, "ZSTUDY_ARGV dep ", 16) != 0)
            continue;
        if (s->n >= ST_MAX_SNAP_TUS)
            return false;
        struct st_list words = {0};
        bool ok = st_shell_split(line, &words) &&
                  st_tu_from_words(&words, &s->tu[s->n]);
        st_list_free(&words);
        if (!ok)
            return false;
        s->n++;
    }
    return s->n > 0;
}

/* ---- snapshot materialization ------------------------------------------ */

static bool st_snap_archive(const struct st_ctx *c, struct st_snap *s)
{
    int64_t t0 = platform_time_monotonic_us();
    const char *archive[] = { "git", "-C", c->repo, "archive",
                              "--format=tar", "-o", s->tar, s->sha, NULL };
    const char *extract[] = { "tar", "-xf", s->tar, "-C", s->dir, NULL };
    bool ok = st_rm_rf(s->dir) && st_mkdir_p(s->dir) &&
              st_run_quiet(archive) && st_run_quiet(extract);
    s->archive_us = platform_time_monotonic_us() - t0;
    if (!ok)
        (void)snprintf(s->why, sizeof(s->why), "archive or extract failed");
    return ok;
}

/* The snapshot's own Makefile, dry-run: every dev object's exact compile
 * command and the test-fast profile flags. Nothing compiles; the parse may
 * (re)generate the tracked view headers exactly as a real build would. */
static bool st_snap_parse(const struct st_ctx *c, struct st_snap *s)
{
    char vars[PATH_MAX], vars_arg[PATH_MAX + 32];
    (void)snprintf(vars, sizeof(vars), "%s.vars", s->dir);
    (void)snprintf(vars_arg, sizeof(vars_arg), "ZSTUDY_VARS=%s", vars);
    const char *argv[] = {
        "env", "-u", "MAKEFLAGS", "-u", "MFLAGS", "-u", "MAKELEVEL",
        "make", "-C", s->dir, "-n", "--no-print-directory",
        "BUILD_SOURCE_RECORD=" ST_ZERO64 " 1 " ST_ZERO64,
        "ZCL_BOOTSTRAP_HELPER_ONLY=1", "ZCL_TOR_LINK_REQUESTED=",
        "BUILD_FAST_EPOCH_OBJECT_COMMAND=ZSTUDY_ARGV", vars_arg,
        "--eval=.SECONDEXPANSION:",
        "--eval=zstudy-objs: $$(DEV_OBJS)",
        "--eval=zstudy-vars: ; $(file >$(ZSTUDY_VARS),"
        "$(TEST_FAST_CFLAGS))",
        "zstudy-vars", "zstudy-objs", NULL,
    };
    int64_t t0 = platform_time_monotonic_us();
    struct st_proc p;
    bool ok = st_run(argv, ST_MAKE_CAP, &p) && st_parse_records(p.out, s);
    if (ok && c->max_actions && s->n > c->max_actions) {
        for (size_t i = c->max_actions; i < s->n; i++)
            st_tu_free(&s->tu[i]);
        s->n = c->max_actions;
    }
    s->parse_us = platform_time_monotonic_us() - t0;
    if (!ok)
        (void)snprintf(s->why, sizeof(s->why),
                       "snapshot Makefile dry-run failed (exit %d): %.180s",
                       p.exit_code, p.out ? p.out : "");
    st_proc_free(&p);
    char *flags = ok ? st_read_file(vars, ST_SMALL_CAP, NULL) : NULL;
    s->test_flags = flags ? st_rootless(flags, s->dir) : NULL;
    free(flags);
    return ok && s->test_flags;
}

/* Tracked bytes unchanged by the parse: `tar -d` against the archive. */
static void st_snap_verify(struct st_snap *s)
{
    const char *argv[] = { "tar", "-df", s->tar, "-C", s->dir, NULL };
    struct st_proc p;
    s->immutable = st_run(argv, ST_SMALL_CAP, &p);
    st_proc_free(&p);
}

/* ---- per-action work --------------------------------------------------- */

struct st_job {
    const struct st_ctx *c;
    struct st_snap *s;
    bool forced;          /* also derive from the build depfile regardless */
    bool keep_deps;
    atomic_size_t next;
};

static void st_build_depfile(const struct st_ctx *c, const struct st_tu *t,
                             char out[PATH_MAX])
{
    size_t n = strlen(t->src);
    (void)snprintf(out, PATH_MAX, "%s/%.*s.d", c->build_obj,
                   (int)(n > 2 ? n - 2 : n), t->src);
}

static void st_snap_depfile(const struct st_snap *s, size_t i,
                            char out[PATH_MAX])
{
    (void)snprintf(out, PATH_MAX, "%s/%zu.d", s->depdir, i);
}

/* Ordered prerequisites of a depfile's first rule. */
bool st_depfile_list(const char *path, struct st_list *out)
{
    size_t len = 0;
    char *text = st_read_file(path, 4u * 1024u * 1024u, &len);
    if (!text)
        return false;
    for (size_t i = 0; i + 1 < len; i++)
        if (text[i] == '\\' && (text[i + 1] == '\n' || text[i + 1] == '\r'))
            text[i] = text[i + 1] = ' ';
    char *colon = strchr(text, ':');
    while (colon && colon[1] && !strchr(" \t\r\n", colon[1]))
        colon = strchr(colon + 1, ':');
    bool ok = colon != NULL;
    char *save = NULL;
    for (char *tok = ok ? strtok_r(colon + 1, " \t\r\n", &save) : NULL;
         ok && tok; tok = strtok_r(NULL, " \t\r\n", &save)) {
        if (tok[strlen(tok) - 1] == ':')
            break;
        ok = st_list_push(out, tok);
    }
    free(text);
    return ok && out->n > 0;
}

static bool st_lists_equal(const struct st_list *a, const struct st_list *b)
{
    if (a->n != b->n)
        return false;
    for (size_t i = 0; i < a->n; i++)
        if (strcmp(a->v[i], b->v[i]) != 0)
            return false;
    return true;
}

/* `cc <flags> -MM` in the snapshot: its exact prerequisite list. */
static bool st_preprocess(const struct st_snap *s, struct st_tu *t,
                          const char *depfile, char *why, size_t why_len)
{
    const char *argv[ST_MAX_ARGS];
    size_t n = 0;
    argv[n++] = "env";
    argv[n++] = "-C";
    argv[n++] = s->dir;
    argv[n++] = t->argv.v[0];
    for (size_t i = t->flag_lo; i < t->flag_hi && n + 8 < ST_MAX_ARGS; i++)
        argv[n++] = t->argv.v[i];
    argv[n++] = "-MM";
    argv[n++] = "-MF";
    argv[n++] = depfile;
    argv[n++] = "-MT";
    argv[n++] = "@out/object";
    argv[n++] = t->src;
    argv[n] = NULL;
    int64_t t0 = platform_time_monotonic_us();
    struct st_proc p;
    bool ok = st_run(argv, ST_SMALL_CAP, &p);
    t->pp_us = platform_time_monotonic_us() - t0;
    if (!ok)
        (void)snprintf(why, why_len, "%.*s", (int)strcspn(p.out, "\n"),
                       p.out ? p.out : "");
    st_proc_free(&p);
    return ok;
}

static void st_miss(struct st_outcome *o, const char *reason)
{
    o->state = ST_MISS;
    (void)snprintf(o->reason, sizeof(o->reason), "%s", reason);
}

/* A derive refusal names its class before ": <path>". */
static void st_miss_from_why(struct st_outcome *o, const char *why)
{
    size_t n = strcspn(why, ":");
    char cls[96];
    (void)snprintf(cls, sizeof(cls), "derive: %.*s", (int)n, why);
    st_miss(o, cls);
}

static bool st_derive(const struct st_ctx *c, const struct st_snap *s,
                      const struct st_tu *t, const char *depfile,
                      struct st_outcome *o, uint8_t **pre, size_t *pre_len)
{
    struct zcl_action_root_request req = {
        .root = s->dir,
        .stage_kind = ST_STAGE_KIND,
        .stage_version = ST_STAGE_VERSION,
        .argv = (const char *const *)t->argv.v,
        .argc = t->argv.n,
        .depfile = depfile,
        .system_dirs = c->tc.dir_ptr,
        .system_dir_count = c->tc.dir_count,
        .sysroot = c->tc.sysroot,
        .linker = { .links = false },
        .environ = (const char *const *)environ,
    };
    memcpy(req.toolchain_root, c->tc.root, 32);
    memcpy(req.sysroot_objects_sha3, c->tc.sysroot_objects, 32);
    struct zcl_action_root_result r;
    bool ok = zcl_action_root_derive(&req, &r);
    o->us = r.derive_us;
    if (!ok) {
        st_miss_from_why(o, r.why);
        return false;
    }
    o->state = ST_ROOT;
    memcpy(o->root, r.root, 32);
    if (pre) {
        *pre = r.preimage;
        *pre_len = r.preimage_len;
        r.preimage = NULL;
    }
    zcl_action_root_result_free(&r);
    return true;
}

static void st_tu_protocol_b(struct st_job *j, struct st_tu *t,
                             const char *snapdep, const char *pp_why)
{
    if (!t->pp_ok) {
        char reason[96];
        (void)snprintf(reason, sizeof(reason), "preprocess-failed%s%.60s",
                       pp_why[0] ? ": " : "", pp_why);
        st_miss(&t->b, reason);
        return;
    }
    (void)st_derive(j->c, j->s, t, snapdep, &t->b, &t->pre, &t->pre_len);
}

static void st_tu_protocol_a(struct st_job *j, struct st_tu *t,
                             const char *builddep)
{
    if (!t->build_dep)
        st_miss(&t->a, "no-build-depfile");
    else if (!t->pp_ok)
        st_miss(&t->a, "preprocess-failed");
    else if (!t->lists_equal)
        st_miss(&t->a, "depfile-stale");
    else
        (void)st_derive(j->c, j->s, t, builddep, &t->a, NULL, NULL);
    if (j->forced && t->build_dep)
        (void)st_derive(j->c, j->s, t, builddep, &t->forced, NULL, NULL);
    else if (j->forced)
        st_miss(&t->forced, "no-build-depfile");
}

static void st_tu_run(struct st_job *j, size_t i)
{
    struct st_tu *t = &j->s->tu[i];
    if (t->identity) {
        static const char why[] = "argv-binds-source-identity";
        st_miss(&t->a, why);
        st_miss(&t->b, why);
        st_miss(&t->forced, why);
        return;
    }
    char snapdep[PATH_MAX], builddep[PATH_MAX], pp_why[160] = {0};
    st_snap_depfile(j->s, i, snapdep);
    st_build_depfile(j->c, t, builddep);
    struct st_list build = {0}, snap = {0};
    t->build_dep = st_depfile_list(builddep, &build);
    t->pp_ok = st_preprocess(j->s, t, snapdep, pp_why, sizeof(pp_why)) &&
               st_depfile_list(snapdep, &snap);
    t->lists_equal = t->pp_ok && t->build_dep && st_lists_equal(&build, &snap);
    st_tu_protocol_b(j, t, snapdep, pp_why);
    st_tu_protocol_a(j, t, builddep);
    if (j->keep_deps) {
        t->deps = snap;
        memset(&snap, 0, sizeof(snap));
    }
    st_list_free(&build);
    st_list_free(&snap);
}

static void *st_worker(void *arg)
{
    struct st_job *j = arg;
    for (;;) {
        size_t i = atomic_fetch_add(&j->next, 1);
        if (i >= j->s->n)
            break;
        st_tu_run(j, i);
    }
    return NULL;
}

static bool st_snap_actions(const struct st_ctx *c, struct st_snap *s,
                            bool forced, bool keep_deps)
{
    (void)snprintf(s->depdir, sizeof(s->depdir), "%s.deps", s->dir);
    if (!st_rm_rf(s->depdir) || !st_mkdir_p(s->depdir))
        return false;
    struct st_job job = { .c = c, .s = s, .forced = forced,
                          .keep_deps = keep_deps };
    atomic_init(&job.next, 0);
    pthread_t th[64];
    unsigned n = c->jobs ? c->jobs : 1;
    if (n > 64)
        n = 64;
    unsigned started = 0;
    for (; started < n; started++)
        if (pthread_create(&th[started], NULL, st_worker, &job) != 0)
            break;
    if (started == 0)
        (void)st_worker(&job);
    for (unsigned i = 0; i < started; i++)
        pthread_join(th[i], NULL);
    return true;
}


bool st_snap_load(const struct st_ctx *c, struct st_snap *s,
                  st_mutate_fn mutate, void *arg, bool forced,
                  bool keep_deps)
{
    (void)snprintf(s->dir, sizeof(s->dir), "%s/snap-%s", c->scratch,
                   s->label);
    if (!s->tar[0])
        (void)snprintf(s->tar, sizeof(s->tar), "%s/%s.tar", c->scratch,
                       s->sha);
    s->ok = st_snap_archive(c, s);
    if (s->ok && mutate && !mutate(c, s, arg)) {
        (void)snprintf(s->why, sizeof(s->why), "seeded mutation failed");
        s->ok = false;
    }
    s->ok = s->ok && st_snap_parse(c, s);
    if (s->ok)
        st_snap_verify(s);
    s->ok = s->ok && st_snap_actions(c, s, forced, keep_deps);
    fprintf(c->log, "snapshot %s %s ok=%d immutable=%d tus=%zu "
            "archive_us=%lld parse_us=%lld %s\n", s->label, s->sha, s->ok,
            s->immutable, s->n, (long long)s->archive_us,
            (long long)s->parse_us, s->why);
    fflush(c->log);
    printf("study: snapshot %s %.12s ok=%d actions=%zu\n", s->label, s->sha,
           s->ok, s->n);
    fflush(stdout);
    return s->ok;
}

void st_snap_drop(struct st_snap *s)
{
    (void)st_rm_rf(s->dir);
    (void)st_rm_rf(s->depdir);
    char vars[PATH_MAX + 8];
    (void)snprintf(vars, sizeof(vars), "%s.vars", s->dir);
    (void)st_rm_rf(vars);
}


void st_snap_init(struct st_snap *s, const char *label, const char *sha)
{
    memset(s, 0, sizeof(*s));
    (void)snprintf(s->label, sizeof(s->label), "%s", label);
    (void)snprintf(s->sha, sizeof(s->sha), "%s", sha);
}
