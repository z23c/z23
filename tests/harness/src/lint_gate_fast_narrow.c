/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: registered harness for the lint-fast changed-file narrowing.
 * Spawns build/bin/z23-lint on a fixture. A narrowed pass is not a
 * whole-tree proof.
 */
#define _POSIX_C_SOURCE 200809L

#include "test/test_core.h"

#if defined(ZCL_TESTING) && !defined(_WIN32)

#include "lint_gate_selftests.h"
#include "lint/lintc/lintc.h"
#include "lint/lintc/run_priv.h"
#include "util/spawn.h"

#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static const char k_lfc_fake[] =
    "#!/bin/sh\n"
    "src= opt=\n"
    "for a do case $a in *control.c|*probe.c) src=$a;; -O0|-O2) opt=$a;; esac; done\n"
    "case $src in *control.c) name=control; echo x >> \"$FMD_CTL\";; "
    "*) name=$(sed -n 's/.*&\\([a-zA-Z_]*\\);.*/\\1/p' \"$src\");; esac\n"
    "printf '%s %s\\n' \"$opt\" \"$name\" >> \"$FMD_TRACE\"\n"
    "if [ \"$name\" = control ]; then\n"
    " n=$(wc -l < \"$FMD_CTL\")\n"
    " [ \"$FMD_MODE:$n\" = initial:1 ] && exit 1\n"
    " [ \"$FMD_MODE:$n\" = final:2 ] && exit 1\n"
    " [ \"$FMD_MODE:$n\" = fixture:2 ] && : > \"${src%/*}/st\"\n"
    " exit 0\nfi\n"
    "[ \"$FMD_MODE\" = exec127 ] && exit 127\n"
    "[ \"$FMD_MODE\" = exec126 ] && exit 126\n"
    "[ \"$FMD_MODE\" = signal ] && kill -TERM $$\n"
    "[ \"$FMD_MODE\" != empty ] && [ \"$name:$opt\" = realpath:-O0 ] && exit 1\n"
    "exit 0\n";

static const char *const k_lfc_env[] = {
    "GIT_DIR", "GIT_INDEX_FILE", "GIT_WORK_TREE", "GIT_COMMON_DIR",
    "GIT_OBJECT_DIRECTORY", "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "ZCL_API_KEY_SCAN_FILES", "ZCL_LINT_PRODUCTION_SCAN",
    "ZCL_REPO_SHAPE_ROOT", "ZCL_REPO_SHAPE_MAKEFILE", "ZCL_REPO_SHAPE_MODULE_DEF",
    "ZCL_LINT_REPO_ROOT", "CC", "FMD_TRACE", "FMD_CTL", "FMD_MODE",
    NULL
};

static const char *const k_lfc_nak_src[] = {
    "tools/lint/lintc/gate_git_scan_a.c", NULL
};
static const char *const k_lfc_fmd_src[] = {
    "tools/lint/lintc/gate_fortify_masked_decls.c", NULL
};
static const char *const k_lfc_crs_src[] = {
    "tools/lint/lintc/gate_raw_sqlite.c",
    "tools/lint/lintc/gate_raw_sqlite_ctx.c",
    "tools/lint/lintc/gate_raw_sqlite_exec.c",
    "tools/lint/lintc/gate_raw_sqlite_priv.h",
    NULL
};

struct lfc_gate {
    const char *name;
    int verify;
    const char *const *src;
};

static const struct lfc_gate k_lfc_gates[] = {
    { "check-no-api-keys", 0, k_lfc_nak_src },
    { "check-fortify-masked-decls", 1, k_lfc_fmd_src },
    { "check-raw-sqlite", 0, k_lfc_crs_src },
};

struct lfc_fix {
    char dir[PATH_MAX];
    char bin[PATH_MAX];
    char cc[PATH_MAX];
    char trace[PATH_MAX];
    char ctl[PATH_MAX];
    int tracked_c;
};

struct lfc_env {
    const char *name;
    char *value;
    int present;
};

struct lfc_cmd {
    char flag[PATH_MAX];
    char gatearg[160];
    const char *av[6];
};

static int lfc_env_count(void)
{
    int n = 0;
    while (k_lfc_env[n])
        n++;
    return n;
}

static int lfc_save(struct lfc_env *e, int n)
{
    for (int i = 0; i < n; i++) {
        const char *v = getenv(e[i].name);
        e[i].present = v != NULL;
        e[i].value = NULL;
        if (!v)
            continue;
        e[i].value = malloc(strlen(v) + 1);
        if (!e[i].value)
            return 1;
        memcpy(e[i].value, v, strlen(v) + 1);
    }
    return 0;
}

static int lfc_restore(struct lfc_env *e, int n)
{
    int bad = 0;
    for (int i = 0; i < n; i++) {
        if (e[i].present && e[i].value)
            bad |= setenv(e[i].name, e[i].value, 1) != 0;
        else if (!e[i].present)
            bad |= unsetenv(e[i].name) != 0;
        free(e[i].value);
    }
    return bad;
}

static int lfc_clear(struct lfc_env *e, int n)
{
    for (int i = 0; i < n; i++) {
        if (unsetenv(e[i].name) != 0)
            return 1;
    }
    return 0;
}

static int lfc_arm(const struct lfc_fix *fx)
{
    if (setenv("CC", fx->cc, 1) != 0)
        return 1;
    if (setenv("FMD_TRACE", fx->trace, 1) != 0)
        return 1;
    if (setenv("FMD_CTL", fx->ctl, 1) != 0)
        return 1;
    if (setenv("FMD_MODE", "masked", 1) != 0)
        return 1;
    return 0;
}

static int lfc_spawn(const struct lfc_fix *fx, const char *const *argv,
                     char *out, size_t cap, int timeout_ms)
{
    int n = lfc_env_count();
    struct lfc_env env[16];
    bool timeout = false;
    int rc, bad;
    if (n > 16)
        return -1;
    for (int i = 0; i < n; i++)
        env[i].name = k_lfc_env[i];
    if (lfc_save(env, n))
        return -1;
    bad = lfc_clear(env, n);
    if (!bad)
        bad = lfc_arm(fx);
    rc = bad ? -1 : zcl_spawn_capture_merged_in_dir_observed(
             argv, fx->dir, out, cap, timeout_ms, &timeout);
    bad |= lfc_restore(env, n);
    if (timeout)
        return -1;
    return bad ? -1 : rc;
}

static int lfc_mkdir(const char *path)
{
    char buf[PATH_MAX];
    size_t n = strlen(path);
    if (n == 0 || n >= sizeof buf)
        return 1;
    memcpy(buf, path, n + 1);
    for (size_t i = 1; i < n; i++) {
        if (buf[i] != '/')
            continue;
        buf[i] = '\0';
        if (mkdir(buf, 0700) != 0 && errno != EEXIST)
            return 1;
        buf[i] = '/';
    }
    if (mkdir(buf, 0700) != 0 && errno != EEXIST)
        return 1;
    return 0;
}

static int lfc_rel(const struct lfc_fix *fx, const char *rel, const char *text)
{
    char path[PATH_MAX];
    if (snprintf(path, sizeof path, "%s/%s", fx->dir, rel) >= (int)sizeof path)
        return 1;
    return write_file(path, text) != 0;
}

/* The credential is assembled at runtime so this source holds no key. */
static int lfc_bad(const char *path)
{
    FILE *f = fopen(path, "w");
    int i;
    if (!f)
        return 1;
    if (fputs("#include <stdlib.h>\nvoid bad(void){ realpath(0,0); sqlite3_step(0); }\n", f) < 0) {
        fclose(f);
        return 1;
    }
    fputc('s', f);
    fputc('k', f);
    fputc('-', f);
    for (i = 0; i < 32; i++)
        fputc('a', f);
    fputc('\n', f);
    i = ferror(f);
    if (fclose(f) != 0)
        return 1;
    return i ? 1 : 0;
}

static int lfc_dirs(const struct lfc_fix *fx)
{
    static const char *const rels[] = {
        "core", "cognition", "contexts/wallet", "engine/controllers",
        "engine/services", "engine/composition", "platform/modules/base",
        "tools/lint/lintc", NULL
    };
    for (int i = 0; rels[i]; i++) {
        char path[PATH_MAX];
        if (snprintf(path, sizeof path, "%s/%s", fx->dir, rels[i]) >= (int)sizeof path)
            return 1;
        if (lfc_mkdir(path))
            return 1;
    }
    return 0;
}

static int lfc_sources(struct lfc_fix *fx)
{
    static const char *const stubs[] = {
        "tools/lint/lintc/gate_git_scan_a.c",
        "tools/lint/lintc/gate_fortify_masked_decls.c",
        "tools/lint/lintc/gate_raw_sqlite.c",
        "tools/lint/lintc/gate_raw_sqlite_ctx.c",
        "tools/lint/lintc/gate_raw_sqlite_exec.c",
        NULL
    };
    for (int i = 0; stubs[i]; i++) {
        if (lfc_rel(fx, stubs[i], "int stub;\n"))
            return 1;
        fx->tracked_c++;
    }
    if (lfc_rel(fx, "tools/lint/lintc/gate_raw_sqlite_priv.h", "int stub;\n"))
        return 1;
    if (lfc_rel(fx, "engine/controllers/keep_a.c", "int keep_a;\n"))
        return 1;
    if (lfc_rel(fx, "engine/services/keep_b.c", "int keep_b;\n"))
        return 1;
    if (lfc_rel(fx, "tools/clean_ok.c", "int clean_ok(void){return 0;}\n"))
        return 1;
    fx->tracked_c += 3;
    if (lfc_rel(fx, "Makefile", "PRODUCT_CONTEXTS = wallet\nAPP_DIRS = controllers services\n"))
        return 1;
    if (lfc_rel(fx, "engine/composition/lib_module_order.def", "LIB_MODULE(\"base\")\n"))
        return 1;
    return 0;
}

static int lfc_pads(struct lfc_fix *fx, int n)
{
    char path[PATH_MAX];
    if (snprintf(path, sizeof path, "%s/pad", fx->dir) >= (int)sizeof path)
        return 1;
    if (lfc_mkdir(path))
        return 1;
    for (int i = 0; i < n; i++) {
        char file[PATH_MAX];
        if (snprintf(file, sizeof file, "%s/pad/p%04d.c", fx->dir, i) >= (int)sizeof file)
            return 1;
        if (write_file(file, "int pad;\n") != 0)
            return 1;
        fx->tracked_c++;
    }
    return 0;
}

static int lfc_cc(struct lfc_fix *fx)
{
    if (snprintf(fx->cc, sizeof fx->cc, "%s/cc", fx->dir) >= (int)sizeof fx->cc)
        return 1;
    if (snprintf(fx->trace, sizeof fx->trace, "%s/trace", fx->dir) >= (int)sizeof fx->trace)
        return 1;
    if (snprintf(fx->ctl, sizeof fx->ctl, "%s/control", fx->dir) >= (int)sizeof fx->ctl)
        return 1;
    if (write_file(fx->cc, k_lfc_fake) != 0)
        return 1;
    if (chmod(fx->cc, 0700) != 0)
        return 1;
    return 0;
}

static int lfc_commit(const struct lfc_fix *fx)
{
    char out[4096];
    const char *init[] = { "git", "-c", "init.defaultBranch=main", "init", "-q", NULL };
    const char *add[] = { "git", "add", "-A", NULL };
    const char *commit[] = {
        "git", "-c", "user.email=t@example.com", "-c", "user.name=t",
        "-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null",
        "commit", "-q", "-m", "fixture", NULL
    };
    const char *ref[] = { "git", "update-ref", "refs/remotes/origin/main", "HEAD", NULL };
    if (lfc_spawn(fx, init, out, sizeof out, 60000))
        return 1;
    if (lfc_spawn(fx, add, out, sizeof out, 60000))
        return 1;
    if (lfc_spawn(fx, commit, out, sizeof out, 60000))
        return 1;
    if (lfc_spawn(fx, ref, out, sizeof out, 60000))
        return 1;
    return 0;
}

/* A violator the wide raw-sqlite walk never opens, plus a deleted path
 * git diff would still name. Both stay out of the intersection. */
static int lfc_outside_files(const struct lfc_fix *fx)
{
    char path[PATH_MAX];
    if (snprintf(path, sizeof path, "%s/tests", fx->dir) >= (int)sizeof path)
        return 1;
    if (lfc_mkdir(path))
        return 1;
    if (snprintf(path, sizeof path, "%s/tests/outside_bad.c", fx->dir) >= (int)sizeof path)
        return 1;
    if (lfc_bad(path))
        return 1;
    return lfc_rel(fx, "set_outside.txt",
                   "tests/outside_bad.c\ntools/missing_bad.c\n");
}

static int lfc_sets(const struct lfc_fix *fx)
{
    if (lfc_rel(fx, "set_bad.txt", "tools/fresh_bad.c\n"))
        return 1;
    if (lfc_rel(fx, "set_clean.txt", "tools/clean_ok.c\n"))
        return 1;
    if (lfc_rel(fx, "set_empty.txt", ""))
        return 1;
    if (lfc_outside_files(fx))
        return 1;
    return 0;
}

static int lfc_prepare(struct lfc_fix *fx)
{
    char bad1[PATH_MAX], bad2[PATH_MAX];
    fx->tracked_c = 0;
    if (!test_mkdtemp(fx->dir, sizeof fx->dir, "lint_fast_changed"))
        return 1;
    if (repo_path(fx->bin, sizeof fx->bin, "build/bin/z23-lint") != 0)
        return 1;
    if (lfc_dirs(fx) || lfc_sources(fx) || lfc_pads(fx, 1000))
        return 1;
    if (snprintf(bad1, sizeof bad1, "%s/tools/fresh_bad.c", fx->dir) >= (int)sizeof bad1)
        return 1;
    if (snprintf(bad2, sizeof bad2, "%s/tools/old_bad.c", fx->dir) >= (int)sizeof bad2)
        return 1;
    if (lfc_bad(bad1) || lfc_bad(bad2))
        return 1;
    fx->tracked_c += 2;
    if (lfc_cc(fx) || lfc_commit(fx) || lfc_sets(fx))
        return 1;
    return 0;
}

static void lfc_fill(struct lfc_cmd *c, const struct lfc_fix *fx,
                     const char *gate, int verify, const char *set, int fast)
{
    int n = 0;
    c->av[n++] = fx->bin;
    if (fast) {
        c->av[n++] = "fast-scan";
        snprintf(c->gatearg, sizeof c->gatearg, "--gate=%s", gate);
        c->av[n++] = c->gatearg;
    } else {
        c->av[n++] = gate;
        if (verify)
            c->av[n++] = "--verify";
    }
    if (set) {
        snprintf(c->flag, sizeof c->flag, "--changed-files=%s/%s", fx->dir, set);
        c->av[n++] = c->flag;
    }
    c->av[n] = NULL;
}

static int lfc_run(const struct lfc_fix *fx, const char *gate, int verify,
                   const char *set, int fast, char *out, size_t cap)
{
    struct lfc_cmd c;
    lfc_fill(&c, fx, gate, verify, set, fast);
    return lfc_spawn(fx, c.av, out, cap, 120000);
}

static int lfc_has(const char *out, const char *s)
{
    return out && strstr(out, s) != NULL;
}

static int lfc_examined(const char *out)
{
    const char *p;
    int n = -1;
    if (!out)
        return -1;
    p = strstr(out, "examined-files:");
    if (!p || sscanf(p, "examined-files: %d", &n) != 1)
        return -1;
    return n;
}

static void lfc_banner(const char *gate, const char *mode, int rc, const char *out)
{
    printf("gate=%s mode=%s exit=%d examined=%d names-changed=%d names-unchanged=%d\n",
           gate, mode, rc, lfc_examined(out), lfc_has(out, "fresh_bad.c"),
           lfc_has(out, "old_bad.c"));
    printf("CAPTURE %s %s\n%s\nENDCAPTURE\n", gate, mode, out ? out : "");
}

static int lfc_narrow_fail(const struct lfc_fix *fx, const struct lfc_gate *g,
                           char *a, char *b, size_t cap)
{
    struct lfc_cmd c;
    int ra, rb, ea, eb;
    lfc_fill(&c, fx, g->name, g->verify, "set_bad.txt", 0);
    ra = lfc_spawn(fx, c.av, a, cap, 120000);
    lfc_banner(g->name, "narrowed", ra, a);
    lfc_banner(g->name, "one-file", ra, a);
    rb = lfc_spawn(fx, c.av, b, cap, 120000);
    lfc_banner(g->name, "narrowed-again", rb, b);
    ea = lfc_examined(a);
    eb = lfc_examined(b);
    if (ra != 1 || rb != ra || ea != 1 || eb != ea)
        return 1;
    if (!lfc_has(a, "fresh_bad.c") || lfc_has(a, "old_bad.c"))
        return 1;
    if (!lfc_has(b, "fresh_bad.c") || lfc_has(b, "old_bad.c"))
        return 1;
    if (!lfc_has(a, "scan-floor: 0") || !lfc_has(b, "scan-floor: 0"))
        return 1;
    return 0;
}

static int lfc_clean(const struct lfc_fix *fx, const struct lfc_gate *g,
                     char *out, size_t cap)
{
    int rc = lfc_run(fx, g->name, g->verify, "set_clean.txt", 0, out, cap);
    lfc_banner(g->name, "narrowed-clean", rc, out);
    if (rc != 0 || lfc_examined(out) != 1)
        return 1;
    if (lfc_has(out, "old_bad.c") || lfc_has(out, "fresh_bad.c"))
        return 1;
    if (!lfc_has(out, "scan-floor: 0"))
        return 1;
    return 0;
}

static int lfc_empty(const struct lfc_fix *fx, const struct lfc_gate *g,
                     char *out, size_t cap)
{
    int rc = lfc_run(fx, g->name, g->verify, "set_empty.txt", 0, out, cap);
    lfc_banner(g->name, "empty", rc, out);
    if (rc != 0 || lfc_examined(out) != 0)
        return 1;
    if (!lfc_has(out, "examined-files: 0") || !lfc_has(out, "scan-floor: 0"))
        return 1;
    return 0;
}

static int lfc_wide(const struct lfc_fix *fx, const struct lfc_gate *g,
                    const char *floor, int min_examined, int exact,
                    char *out, size_t cap)
{
    int rc = lfc_run(fx, g->name, g->verify, NULL, 0, out, cap);
    int n = lfc_examined(out);
    lfc_banner(g->name, "unnarrowed", rc, out);
    if (rc != 1 || !lfc_has(out, "old_bad.c") || !lfc_has(out, floor))
        return 1;
    if (lfc_has(out, "scan set is"))
        return 1;
    if (exact)
        return n != min_examined;
    return n < min_examined;
}

static int lfc_dirty(const struct lfc_fix *fx, const char *const *rels)
{
    for (int i = 0; rels[i]; i++) {
        char path[PATH_MAX];
        FILE *f;
        if (snprintf(path, sizeof path, "%s/%s", fx->dir, rels[i]) >= (int)sizeof path)
            return 1;
        f = fopen(path, "a");
        if (!f)
            return 1;
        fputc('\n', f);
        if (fclose(f) != 0)
            return 1;
    }
    return 0;
}

static int lfc_restore_stubs(const char *dir, const char *const *rels)
{
    for (int i = 0; rels[i]; i++) {
        char path[PATH_MAX];
        if (snprintf(path, sizeof path, "%s/%s", dir, rels[i]) >= (int)sizeof path)
            return 1;
        if (write_file(path, "int stub;\n") != 0)
            return 1;
    }
    return 0;
}

static int lfc_differs(const struct lfc_fix *fx, const struct lfc_gate *g,
                       const char *floor, char *out, size_t cap)
{
    int rc, n;
    if (lfc_dirty(fx, g->src))
        return 1;
    rc = lfc_run(fx, g->name, 0, "set_bad.txt", 1, out, cap);
    lfc_banner(g->name, "source-differs", rc, out);
    n = lfc_examined(out);
    if (lfc_restore_stubs(fx->dir, g->src))
        return 1;
    if (rc != 1 || !lfc_has(out, "old_bad.c") || n <= 1)
        return 1;
    if (!lfc_has(out, floor))
        return 1;
    if (g->verify && n != fx->tracked_c)
        return 1;
    if (!g->verify && strcmp(g->name, "check-no-api-keys") == 0 && n < 1000)
        return 1;
    return 0;
}

static int lfc_sqlite_bounds(const struct lfc_fix *fx, const struct lfc_gate *g,
                             char *out, size_t cap)
{
    int rc;
    if (strcmp(g->name, "check-raw-sqlite") != 0)
        return 0;
    rc = lfc_run(fx, g->name, g->verify, "set_outside.txt", 0, out, cap);
    lfc_banner(g->name, "outside", rc, out);
    if (rc != 0 || lfc_examined(out) != 0)
        return 1;
    if (lfc_has(out, "outside_bad.c") || lfc_has(out, "missing_bad.c"))
        return 1;
    if (!lfc_has(out, "examined-files: 0") || !lfc_has(out, "scan-floor: 0"))
        return 1;
    return 0;
}

static int lfc_one(const struct lfc_fix *fx, const struct lfc_gate *g,
                   const char *floor, int min_ex, int exact,
                   char *a, char *b, size_t cap)
{
    if (lfc_narrow_fail(fx, g, a, b, cap))
        return 1;
    if (lfc_sqlite_bounds(fx, g, a, cap))
        return 1;
    if (lfc_clean(fx, g, a, cap))
        return 1;
    if (lfc_empty(fx, g, a, cap))
        return 1;
    if (lfc_wide(fx, g, floor, min_ex, exact, a, cap))
        return 1;
    if (lfc_differs(fx, g, floor, a, cap))
        return 1;
    return 0;
}

static int lfc_all(struct lfc_fix *fx)
{
    char *a = malloc(1 << 16);
    char *b = malloc(1 << 16);
    int bad;
    if (!a || !b) {
        free(a);
        free(b);
        return 1;
    }
    bad = lfc_one(fx, &k_lfc_gates[0], "scan-floor: 1000", 1000, 0, a, b, 1 << 16);
    if (!bad)
        bad = lfc_one(fx, &k_lfc_gates[1], "scan-floor: whole", fx->tracked_c, 1, a, b, 1 << 16);
    if (!bad)
        bad = lfc_one(fx, &k_lfc_gates[2], "scan-floor: 2", 2, 0, a, b, 1 << 16);
    free(a);
    free(b);
    return bad;
}

static void lfc_cleanup(const struct lfc_fix *fx)
{
    const char *argv[] = { "rm", "-rf", "--", fx->dir, NULL };
    char out[256];
    bool timeout = false;
    if (fx->dir[0] == '\0')
        return;
    (void)zcl_spawn_capture_merged_in_dir_observed(argv, "/", out, sizeof out, 60000, &timeout);
}

static int lfc_quoted_paths(const struct lfc_fix *fx)
{
    static const char *const sets[] = {
        "tools/clean_ok.c\n\"tools/tab\\tbad.c\"\n",
        "\"tools/line\\nbad.c\"\n",
        "\"tools/\\303\\251.c\"\n",
    };
    char out[1 << 16];
    for (size_t i = 0; i < sizeof(sets) / sizeof(sets[0]); i++) {
        if (lfc_rel(fx, "set_quoted.txt", sets[i]))
            return 1;
        for (size_t j = 0; j < sizeof(k_lfc_gates) / sizeof(k_lfc_gates[0]); j++) {
            const struct lfc_gate *g = &k_lfc_gates[j];
            int rc = lfc_run(fx, g->name, g->verify, "set_quoted.txt", 0,
                             out, sizeof(out));
            lfc_banner(g->name, "quoted-path-fallback", rc, out);
            if (rc != 1 || !lfc_has(out, "old_bad.c") ||
                !lfc_has(out, "using whole-tree scan"))
                return 1;
        }
    }
    return 0;
}

static int lfc_command_paths(void)
{
    static const char *const paths[] = {
        "set&&other", "set$HOME", "set'quote", "set\"quote",
        "set\\backslash", "set space", "set\twith\ncontrols",
    };
    for (size_t i = 0; i < sizeof(paths) / sizeof(paths[0]); i++) {
        struct lr_plan plan;
        char cmd[LR_CMD] = "gate", expected[256], err[256];
        (void)snprintf(expected, sizeof expected, "--changed-files=%s", paths[i]);
        if (lint_fast_append_changed(cmd, sizeof cmd, paths[i]) ||
            lr_parse_command(cmd, NULL, &plan, err, sizeof err))
            return 1;
        if (plan.nsteps != 1 || plan.steps[0].argc != 2 ||
            strcmp(plan.steps[0].argv[1], expected) != 0)
            return 1;
    }
    return 0;
}

int t_lint_fast_changed_files(void)
{
    int failures = 0;
    struct lfc_fix fx;
    memset(&fx, 0, sizeof fx);
    TEST("lint fast path narrows per-file gates to the changed set") {
        ASSERT(lfc_prepare(&fx) == 0);
        ASSERT(lfc_all(&fx) == 0);
        ASSERT(lfc_quoted_paths(&fx) == 0);
        ASSERT(lfc_command_paths() == 0);
        PASS();
    } _test_next:;
    lfc_cleanup(&fx);
    return failures;
}

#else

typedef int zcl_lint_gate_fast_narrow_unit;

#endif
