/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: `z23-lint select --dry` and `z23-lint premise` — print, per
 * gate and unit, the candidate premise root, the verified base's root,
 * whether the unit would inherit, and why. Information only: nothing in
 * this tree reads these rows back as a verdict, and nothing is persisted.
 *
 *   z23-lint select --dry --base=<commit> [--root=DIR] [--objects=REPO]
 *       [--remote=LOCATOR] [--ref=REF] [--scratch=DIR] [--depth=N]
 *       [--gate=NAME]... [--summary] [--no-landlock]
 *   z23-lint premise --gate=NAME --unit=PATH [--root=DIR]
 *
 * One JSON object per line on stdout: schema zcl.lint_selection.dry.v1 per
 * unit, zcl.lint_selection.dry_summary.v1 per gate.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include "premise.h"
#include "base/hex.h"

#include <errno.h>
#include <fcntl.h>
#include <regex.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "platform/os_sandbox.h"

enum selection_units {
    SELECTION_UNITS_NODE_C23_WINDOWS,
    SELECTION_UNITS_CLANG_ORACLE,
    SELECTION_UNITS_FILES,   /* per-file: filter paths, unit premise = own bytes */
    SELECTION_UNITS_TUS,     /* per-TU: filter paths, unit premise = closure */
};

struct selection_gate_row {
    const char *name;
    enum selection_units units;
    const char *filter;
    const char *gate_files;
    const char *make_vars;
    const char *baselines;
};

#define SELECTION_REMOTE(url) static const char k_remote[] = url;
#define SELECTION_POLICY(path)
#define SELECTION_GATE(n, u, r, f, m, b)
#include "selection_gates.def"
#undef SELECTION_REMOTE
#undef SELECTION_POLICY
#undef SELECTION_GATE

#define SELECTION_REMOTE(url)
#define SELECTION_POLICY(path) path,
#define SELECTION_GATE(n, u, r, f, m, b)
static const char *const k_policy[] = {
#include "selection_gates.def"
};
#undef SELECTION_POLICY
#undef SELECTION_GATE

#define SELECTION_POLICY(path)
#define SELECTION_GATE(n, u, r, f, m, b) { n, u, r, f, m, b },
static const struct selection_gate_row k_rows[] = {
#include "selection_gates.def"
};
#undef SELECTION_REMOTE
#undef SELECTION_POLICY
#undef SELECTION_GATE

/* The clang-portability gate's own coverage oracle: its scan must equal
 * this set (allowance 0), so it is the gate's exact unit list. */
static const char k_clang_oracle[] =
    "^((engine|cognition|contexts/[^/]+)/(models|controllers|views|services|"
    "supervisors|conditions|jobs)/src/[^/]+\\.c|((core|engine|cognition|"
    "platform|contexts/[^/]+)/modules/[^/]+/src/[^/]+\\.c)|core/(consensus|"
    "params|math|chainparams)/src/[^/]+\\.c|(contexts/wallet/domain|"
    "platform/domain/encoding)/src/[^/]+\\.c|engine/application/[^/]+/src/"
    "[^/]+\\.c|engine/composition/src/[^/]+\\.c|platform/adapters/outbound/"
    "persistence/src/[^/]+\\.c|tools/(dev|command)/[^/]+\\.c|engine/entry/"
    "[^/]+\\.c)$";

struct strv {
    char **v;
    size_t n;
};

static int strv_add(struct strv *s, const char *p, size_t n)
{
    char **grown = realloc(s->v, (s->n + 1) * sizeof *grown); // raw-alloc-ok:lint-runtime
    char *copy = malloc(n + 1); // raw-alloc-ok:lint-runtime
    if (!grown || !copy) {
        if (grown)
            s->v = grown;
        free(copy);
        return 2;
    }
    memcpy(copy, p, n);
    copy[n] = '\0';
    grown[s->n++] = copy;
    s->v = grown;
    return 0;
}

static void strv_free(struct strv *s)
{
    for (size_t i = 0; i < s->n; i++)
        free(s->v[i]);
    free(s->v);
    memset(s, 0, sizeof *s);
}

static int strv_split(struct strv *s, const char *text)
{
    int rc = 0;
    for (const char *p = text; rc == 0 && *p;) {
        while (*p == ' ')
            p++;
        const char *q = p;
        while (*q && *q != ' ')
            q++;
        if (q > p)
            rc = strv_add(s, p, (size_t)(q - p));
        p = q;
    }
    return rc;
}

static int cmp_str(const void *a, const void *b)
{
    return strcmp(*(char *const *)a, *(char *const *)b);
}

static void strv_sort_unique(struct strv *s)
{
    if (s->n < 2)
        return;
    qsort(s->v, s->n, sizeof *s->v, cmp_str);
    size_t w = 1;
    for (size_t i = 1; i < s->n; i++) {
        if (strcmp(s->v[i], s->v[w - 1]) == 0)
            free(s->v[i]);
        else
            s->v[w++] = s->v[i];
    }
    s->n = w;
}

struct gate_spec {
    struct premise_gate g;
    struct strv files, vars, baselines;
};

static int spec_build(struct gate_spec *sp, const struct selection_gate_row *r)
{
    memset(sp, 0, sizeof *sp);
    int rc = 0;
    for (size_t i = 0; rc == 0 && i < sizeof k_policy / sizeof *k_policy; i++)
        rc = strv_add(&sp->files, k_policy[i], strlen(k_policy[i]));
    if (rc == 0)
        rc = strv_split(&sp->files, r->gate_files);
    if (rc == 0)
        rc = strv_split(&sp->vars, r->make_vars);
    if (rc == 0)
        rc = strv_split(&sp->baselines, r->baselines);
    sp->g = (struct premise_gate){
        .name = r->name,
        .gate_files = (const char *const *)sp->files.v,
        .n_gate_files = sp->files.n,
        .make_vars = (const char *const *)sp->vars.v,
        .n_make_vars = sp->vars.n,
        .baselines = (const char *const *)sp->baselines.v,
        .n_baselines = sp->baselines.n,
        .unit_self = r->units == SELECTION_UNITS_FILES,
    };
    return rc;
}

static void spec_free(struct gate_spec *sp)
{
    strv_free(&sp->files);
    strv_free(&sp->vars);
    strv_free(&sp->baselines);
}

static void make_child(const char *root, int out_fd)
{
    int null_fd = open("/dev/null", O_RDWR);
    if (chdir(root) != 0 || dup2(out_fd, 1) < 0 || dup2(null_fd, 2) < 0)
        _exit(127);
    unsetenv("MAKEFLAGS");
    unsetenv("MFLAGS");
    unsetenv("MAKELEVEL");
    execlp("make", "make", "-s", "ZCL_TARGET=windows-x86_64",
           "print-node-c23-srcs", (char *)NULL);
    _exit(127);
}

static int read_lines_c(int fd, struct strv *out)
{
    FILE *f = fdopen(fd, "r");
    if (!f)
        return 2;
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    int rc = 0;
    while (rc == 0 && (n = getline(&line, &cap, f)) >= 0) {
        while (n > 0 && (line[n - 1] == '\n' || line[n - 1] == ' '))
            line[--n] = '\0';
        if (n > 2 && strcmp(line + n - 2, ".c") == 0)
            rc = strv_add(out, line, (size_t)n);
    }
    free(line);
    fclose(f);
    return rc;
}

/* The exact TU list the cross-syntax gate compiles: the Makefile's own
 * windows NODE_C23_SRCS, filtered to .c paths the same way the gate does. */
static int units_node_c23(const char *root, struct strv *out, FILE *err)
{
    int p[2];
    if (pipe(p) != 0)
        return 2;
    fflush(NULL);
    pid_t pid = fork();
    if (pid == 0) {
        close(p[0]);
        make_child(root, p[1]);
    }
    close(p[1]);
    int rc = pid < 0 ? 2 : read_lines_c(p[0], out);
    int st = 0;
    while (pid > 0 && waitpid(pid, &st, 0) < 0 && errno == EINTR)
        ;
    if (rc == 0 && (!WIFEXITED(st) || WEXITSTATUS(st) != 0 || out->n == 0)) {
        fprintf(err, "select: make print-node-c23-srcs failed in %s\n", root);
        rc = 2;
    }
    return rc;
}

/* Every candidate path the pattern matches; skip_fixtures drops paths with a
 * "/_" component, as the clang oracle does. A per-file gate names a pattern
 * that is a superset of what it scans: a scanned path outside the unit set
 * would never be rerun. */
static int units_regex(const struct premise_tree *t, const char *pattern,
                       bool skip_fixtures, struct strv *out, FILE *err)
{
    regex_t re;
    if (regcomp(&re, pattern, REG_EXTENDED | REG_NOSUB) != 0) {
        fprintf(err, "select: unit pattern does not compile: %s\n", pattern);
        return 2;
    }
    int rc = 0;
    for (size_t i = 0; rc == 0 && i < t->count; i++) {
        const char *path = t->entries[i].path;
        if (!(skip_fixtures && strstr(path, "/_"))
            && regexec(&re, path, 0, NULL, 0) == 0)
            rc = strv_add(out, path, strlen(path));
    }
    regfree(&re);
    return rc;
}

static void json_str(FILE *out, const char *s)
{
    fputc('"', out);
    for (; *s; s++) {
        if (*s == '"' || *s == '\\')
            fputc('\\', out);
        if ((unsigned char)*s < 0x20)
            fprintf(out, "\\u%04x", (unsigned)(unsigned char)*s);
        else
            fputc(*s, out);
    }
    fputc('"', out);
}

static void print_unit(FILE *out, const char *gate, const struct premise_unit *u)
{
    char a[2 * PREMISE_HASH_BYTES + 1], b[2 * PREMISE_HASH_BYTES + 1];
    zcl_hex_encode(u->action_root, PREMISE_HASH_BYTES, a);
    zcl_hex_encode(u->base_root, PREMISE_HASH_BYTES, b);
    fputs("{\"schema\":\"zcl.lint_selection.dry.v1\",\"gate\":", out);
    json_str(out, gate);
    fputs(",\"unit\":", out);
    json_str(out, u->unit);
    fprintf(out, ",\"action_root\":\"%s\",\"base_root\":", a);
    if (u->base_root_known)
        fprintf(out, "\"%s\"", b);
    else
        fputs("null", out);
    fprintf(out, ",\"would_inherit\":%s,\"reason\":",
            u->would_inherit ? "true" : "false");
    json_str(out, u->reason);
    fputs("}\n", out);
}

struct select_opts {
    struct premise_base_opts base;
    const char *root;
    const char *gates[8];
    size_t ngates;
    bool dry;
    bool summary;
    bool no_landlock;
    const char *unit;
};

static void print_summary(FILE *out, const struct select_opts *o,
                          const struct premise_session *s, const char *gate,
                          const struct premise_unit *u, size_t n)
{
    size_t inherit = 0;
    for (size_t i = 0; i < n; i++)
        inherit += u[i].would_inherit;
    fputs("{\"schema\":\"zcl.lint_selection.dry_summary.v1\",\"gate\":", out);
    json_str(out, gate);
    fprintf(out, ",\"base\":\"%s\",\"units\":%zu,\"would_inherit\":%zu,"
                 "\"fresh\":%zu,\"selection\":\"%s\",\"disabled_reason\":",
            o->base.base, n, inherit, n - inherit,
            s->disabled[0] ? "disabled" : "enabled");
    json_str(out, s->disabled);
    fputs("}\n", out);
}

static bool gate_wanted(const struct select_opts *o, const char *name)
{
    if (o->ngates == 0)
        return true;
    for (size_t i = 0; i < o->ngates; i++)
        if (strcmp(o->gates[i], name) == 0)
            return true;
    return false;
}

static int gate_units(const struct select_opts *o, struct premise_session *s,
                      const struct selection_gate_row *r, struct strv *units,
                      FILE *err)
{
    int rc = 0;
    if (r->units == SELECTION_UNITS_NODE_C23_WINDOWS)
        rc = units_node_c23(o->root, units, err);
    else if (r->units == SELECTION_UNITS_CLANG_ORACLE)
        rc = units_regex(&s->cand, k_clang_oracle, true, units, err);
    else
        rc = units_regex(&s->cand, r->filter[0] ? r->filter : ".", false,
                         units, err);
    strv_sort_unique(units);
    return rc;
}

static int select_gate(const struct select_opts *o, struct premise_session *s,
                       const struct selection_gate_row *r, FILE *out, FILE *err)
{
    struct gate_spec sp;
    struct strv units = { 0 };
    int rc = spec_build(&sp, r);
    if (rc == 0)
        rc = gate_units(o, s, r, &units, err);
    struct premise_unit *u = rc ? NULL : calloc(units.n ? units.n : 1, sizeof *u); // raw-alloc-ok:lint-runtime
    if (rc == 0 && !u)
        rc = 2;
    for (size_t i = 0; rc == 0 && i < units.n; i++)
        u[i].unit = units.v[i];
    if (rc == 0)
        rc = premise_gate_eval(s, &sp.g, u, units.n, err);
    for (size_t i = 0; rc == 0 && !o->summary && i < units.n; i++)
        print_unit(out, r->name, &u[i]);
    if (rc == 0)
        print_summary(out, o, s, r->name, u, units.n);
    free(u);
    strv_free(&units);
    spec_free(&sp);
    return rc;
}

static bool opt_val(const char *arg, const char *name, const char **out)
{
    size_t n = strlen(name);
    if (strncmp(arg, name, n) != 0 || arg[n] != '=')
        return false;
    *out = arg + n + 1;
    return true;
}

static int parse_flag(struct select_opts *o, const char *a)
{
    const char *v = NULL;
    if (strcmp(a, "--dry") == 0)
        o->dry = true;
    else if (strcmp(a, "--summary") == 0)
        o->summary = true;
    else if (strcmp(a, "--no-landlock") == 0)
        o->no_landlock = true;
    else if (opt_val(a, "--depth", &v))
        o->base.depth = (unsigned)strtoul(v, NULL, 10);
    else if (opt_val(a, "--gate", &v) && o->ngates < 8)
        o->gates[o->ngates++] = v;
    else
        return 2;
    return 0;
}

static int parse_opts(struct select_opts *o, int argc, char **argv)
{
    memset(o, 0, sizeof *o);
    o->root = ".";
    o->base.remote = k_remote;
    struct { const char *name; const char **slot; } k[] = {
        { "--base", &o->base.base }, { "--root", &o->root },
        { "--objects", &o->base.objects }, { "--remote", &o->base.remote },
        { "--ref", &o->base.ref }, { "--scratch", &o->base.scratch },
        { "--unit", &o->unit },
    };
    for (int i = 0; i < argc; i++) {
        bool hit = false;
        for (size_t j = 0; !hit && j < sizeof k / sizeof *k; j++)
            hit = opt_val(argv[i], k[j].name, k[j].slot);
        if (!hit && parse_flag(o, argv[i])) {
            fprintf(stderr, "z23-lint: unknown argument %s\n", argv[i]);
            return 2;
        }
    }
    if (!o->base.objects)
        o->base.objects = o->root;
    return 0;
}

static int ensure_scratch(struct select_opts *o, char *buf, size_t cap)
{
    if (o->base.scratch)
        return 0;
    int k = snprintf(buf, cap, "%s/build", o->root);
    if (k < 0 || (size_t)k + 9 >= cap || (mkdir(buf, 0755) != 0 && errno != EEXIST))
        return 2;
    strcat(buf, "/scratch");
    if (mkdir(buf, 0700) != 0 && errno != EEXIST)
        return 2;
    o->base.scratch = buf;
    return 0;
}

int lint_select_main(int argc, char **argv)
{
    struct select_opts o;
    char scratch[PREMISE_PATH_MAX];
    if (parse_opts(&o, argc, argv) || !o.dry || !o.base.base) {
        fprintf(stderr, "z23-lint: usage: z23-lint select --dry --base=<commit> "
                        "[--root=DIR] [--objects=REPO] [--remote=LOCATOR] "
                        "[--ref=REF] [--scratch=DIR] [--depth=N] [--gate=NAME]... "
                        "[--summary] [--no-landlock]\n");
        return 2;
    }
    if (ensure_scratch(&o, scratch, sizeof scratch)) {
        fprintf(stderr, "select: cannot create scratch under %s/build\n", o.root);
        return 2;
    }
    struct premise_session s;
    /* Inheritance needs the unit-exec domain: no Landlock, nothing inherits. */
    bool confined = !o.no_landlock && os_sandbox_landlock_abi() >= 1;
    int rc = premise_session_open(&s, o.root, &o.base, confined, stderr);
    for (size_t i = 0; rc == 0 && i < sizeof k_rows / sizeof *k_rows; i++)
        if (gate_wanted(&o, k_rows[i].name))
            rc = select_gate(&o, &s, &k_rows[i], stdout, stderr);
    premise_session_close(&s);
    return rc;
}

int lint_premise_main(int argc, char **argv)
{
    struct select_opts o;
    if (parse_opts(&o, argc, argv) || o.ngates != 1 || !o.unit) {
        fprintf(stderr, "z23-lint: usage: z23-lint premise --gate=NAME "
                        "--unit=PATH [--root=DIR]\n");
        return 2;
    }
    const struct selection_gate_row *r = NULL;
    for (size_t i = 0; i < sizeof k_rows / sizeof *k_rows; i++)
        if (strcmp(k_rows[i].name, o.gates[0]) == 0)
            r = &k_rows[i];
    struct gate_spec sp;
    struct premise_session s;
    if (!r || spec_build(&sp, r)) {
        fprintf(stderr, "premise: unknown gate %s\n", o.gates[0]);
        return 2;
    }
    int rc = premise_session_open(&s, o.root, NULL, false, stderr);
    if (rc == 0)
        rc = premise_unit_grants(&s, &sp.g, o.unit, stdout, stderr);
    premise_session_close(&s);
    spec_free(&sp);
    return rc;
}
