/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: gate family — the core/ barrier pass of check-core-include-boundary
 * (W0 of docs/work/CORE_BARRIER_PLAN.md). Every #include in every source file
 * under core/ is resolved BY FILE LOCATION on the include path the Makefile
 * builds with (ZCL_ALL_INCLUDES, mirrored in k_cb_path below; quote includes
 * try the includer's own directory first), then classified: inside core/,
 * libc/OS (an angle include found on no project directory), outside core/
 * (vendor/ included), or unresolved (a quote include found nowhere). An
 * outside target listed in tools/lint/core_barrier_allow.txt is allowed. Every
 * other outside or unresolved include is an edge keyed `<core file> <token>`;
 * RATCHET: an edge missing from tools/lint/core_barrier_baseline.txt fails,
 * and a baseline row whose edge is gone fails as STALE (shrink-only).
 * A token found on the path both inside and outside core/ is counted as
 * ambiguous: the first directory wins, as it does for the compiler.
 *
 * NOT DONE: the undefined-symbol pass over core/ objects (extern
 * declarations and weak symbols an include does not show). It needs built
 * objects, so it is not hermetic; the plan's 19 kept-to-N symbol references
 * stay unmeasured by this gate.
 *
 * Modes: (default) check | --write-baseline | --print-include-path.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include "base/safe_alloc.h"
#include "lintc.h"

enum { CB_KEY = RS_PATH * 2, CB_LINE = 8192, CB_FLOOR = 100, CB_CACHE = 8192 };
enum { CB_INSIDE = 1, CB_OUTSIDE, CB_SYS, CB_UNRES };

static const char k_cb_gate[] = "check_core_include_boundary";
static const char k_cb_allow[] = "tools/lint/core_barrier_allow.txt";
static const char k_cb_base[] = "tools/lint/core_barrier_baseline.txt";

/* The module-directory rule for the C/S vs N split (the plan's whole-N
 * modules); every other core/ file counts as consensus (C or S). */
static const char *const k_cb_n_mods[] = {
    "core/modules/net/", "core/modules/noise/", "core/modules/sync/",
    "core/modules/mining/", "core/modules/policy/"
};

struct cb_rows { char (*r)[CB_KEY]; int n, cap; };
struct cb_edge { char key[CB_KEY]; char res[RS_PATH]; int kind; };
struct cb_edges { struct cb_edge *v; int n, cap; };
struct cb_memo { char tok[RS_PATH]; char res[RS_PATH]; int kind, ambig, used; };
typedef int (*cb_exists_fn)(const char *path, void *ctx);
struct cb_env {
    const struct cb_rows *dirs;
    const struct cb_rows *allow;
    cb_exists_fn exists;
    void *fsctx;
    struct cb_memo *memo;
};
struct cb_stats { int files, inside, sys, outside, allowed, unres, ambig; };
struct cb_scan {
    const struct cb_env *env;
    struct cb_edges *found;
    struct cb_stats st;
    const char *file;
};
struct cb_cmp { int neu, neu_cs, stale, cs, n; };

/* ── small containers ─────────────────────────────────────────────────── */

static int cb_rows_add(struct cb_rows *s, const char *row)
{
    if (strlen(row) >= CB_KEY)
        return die("z23-lint: core barrier row too long: %s\n", row);
    if (s->n == s->cap) {
        int cap = s->cap ? s->cap * 2 : 256;
        void *p = zcl_realloc(s->r, (size_t)cap * sizeof s->r[0], "cb_rows");
        if (!p)
            return die("z23-lint: core barrier: out of memory%s\n", "");
        s->r = p;
        s->cap = cap;
    }
    memcpy(s->r[s->n++], row, strlen(row) + 1);
    return 0;
}

static int cb_rowcmp(const void *a, const void *b)
{
    return strcmp((const char *)a, (const char *)b);
}

static void cb_rows_sort(struct cb_rows *s)
{
    if (s->n > 1)
        qsort(s->r, (size_t)s->n, sizeof s->r[0], cb_rowcmp);
}

static int cb_rows_has(const struct cb_rows *s, const char *row)
{
    return s->n > 0
           && bsearch(row, s->r, (size_t)s->n, sizeof s->r[0], cb_rowcmp);
}

static int cb_edgecmp(const void *a, const void *b)
{
    return strcmp(((const struct cb_edge *)a)->key,
                  ((const struct cb_edge *)b)->key);
}

static int cb_edge_add(struct cb_edges *e, const char *key, const char *res,
                       int kind)
{
    if (e->n == e->cap) {
        int cap = e->cap ? e->cap * 2 : 512;
        void *p = zcl_realloc(e->v, (size_t)cap * sizeof e->v[0], "cb_edges");
        if (!p)
            return die("z23-lint: core barrier: out of memory%s\n", "");
        e->v = p;
        e->cap = cap;
    }
    struct cb_edge *x = &e->v[e->n++];
    snprintf(x->key, sizeof x->key, "%s", key);
    snprintf(x->res, sizeof x->res, "%s", res);
    x->kind = kind;
    return 0;
}

/* ── include path ─────────────────────────────────────────────────────── */

static int cb_path_add(const char *dir, void *ctx)
{
    return cb_rows_add(ctx, dir);
}

static int cb_path_build(struct cb_rows *dirs)
{
    dirs->n = 0;
    return core_barrier_include_path(cb_path_add, dirs);
}

/* ── resolution ───────────────────────────────────────────────────────── */

/* Collapse "." and ".." segments in place; a ".." above the root fails. */
static int cb_norm(char *p)
{
    char out[RS_PATH], *seg, *save = NULL;
    size_t n = 0;
    out[0] = '\0';
    for (seg = strtok_r(p, "/", &save); seg; seg = strtok_r(NULL, "/", &save)) {
        if (strcmp(seg, ".") == 0)
            continue;
        if (strcmp(seg, "..") == 0) {
            char *sl = strrchr(out, '/');
            if (n == 0)
                return 1;
            n = sl ? (size_t)(sl - out) : 0;
            out[n] = '\0';
            continue;
        }
        size_t k = strlen(seg);
        if (n + k + 2 >= sizeof out)
            return 1;
        if (n)
            out[n++] = '/';
        memcpy(out + n, seg, k + 1);
        n += k;
    }
    memcpy(p, out, n + 1);
    return 0;
}

static int cb_join(char *out, const char *dir, size_t dlen, const char *tok)
{
    if (ovf(snprintf(out, RS_PATH, "%.*s%s%s", (int)dlen, dir,
                     dlen ? "/" : "", tok), RS_PATH))
        return 1;
    return cb_norm(out);
}

static int cb_kind_of(const char *path)
{
    return strncmp(path, "core/", 5) == 0 ? CB_INSIDE : CB_OUTSIDE;
}

/* Search the -I list for tok: first hit wins; a later hit on the other side
 * of the barrier marks the token ambiguous. Memoized per token. */
static void cb_search(const struct cb_env *env, const char *tok,
                      struct cb_memo *m)
{
    char cand[RS_PATH];
    m->kind = 0;
    m->ambig = 0;
    if (core_barrier_vendor_installed(tok)) {
        /* too long to name: unresolved (kind 0), reported, never clean */
        if (!ovf(snprintf(m->res, sizeof m->res, "vendor/include/%s", tok),
                 sizeof m->res))
            m->kind = CB_OUTSIDE;
        return;
    }
    for (int i = 0; i < env->dirs->n && !m->ambig; i++) {
        if (cb_join(cand, env->dirs->r[i], strlen(env->dirs->r[i]), tok)
            || !env->exists(cand, env->fsctx))
            continue;
        if (m->kind == 0) {
            snprintf(m->res, sizeof m->res, "%s", cand);
            m->kind = cb_kind_of(cand);
        } else if (cb_kind_of(cand) != m->kind) {
            m->ambig = 1;
        }
    }
}

static unsigned cb_hash(const char *s)
{
    unsigned h = 2166136261u;
    while (*s)
        h = (h ^ (unsigned char)*s++) * 16777619u;
    return h;
}

static const struct cb_memo *cb_lookup(const struct cb_env *env,
                                       const char *tok)
{
    unsigned h = cb_hash(tok) % CB_CACHE;
    for (int probe = 0; probe < CB_CACHE; probe++, h = (h + 1) % CB_CACHE) {
        struct cb_memo *m = &env->memo[h];
        if (m->used && strcmp(m->tok, tok) == 0)
            return m;
        if (!m->used) {
            m->used = 1;
            snprintf(m->tok, sizeof m->tok, "%s", tok);
            cb_search(env, tok, m);
            return m;
        }
    }
    return NULL;
}

/* Resolve one include; out gets the repo path (or "?" when none). */
static int cb_resolve(const struct cb_env *env, const char *file,
                      const char *tok, int quoted, char *out, int *ambig)
{
    const char *sl = strrchr(file, '/');
    const struct cb_memo *m;
    *ambig = 0;
    if (quoted && !cb_join(out, file, sl ? (size_t)(sl - file) : 0, tok)
        && env->exists(out, env->fsctx))
        return cb_kind_of(out);
    m = cb_lookup(env, tok);
    if (!m) {
        fputs("z23-lint: core barrier: token cache full\n", stderr);
        return -1;
    }
    if (m->kind) {
        snprintf(out, RS_PATH, "%s", m->res);
        *ambig = m->ambig;
        return m->kind;
    }
    snprintf(out, RS_PATH, "?");
    return quoted ? CB_UNRES : CB_SYS;
}

/* ── scanning ─────────────────────────────────────────────────────────── */

static const char *cb_ws(const char *p)
{
    while (*p == ' ' || *p == '\t')
        p++;
    return p;
}

/* The operand of an `#include` / `#include_next` directive, or NULL when the
 * line is not one (`#includes` in prose is not). */
static const char *cb_directive(const char *line)
{
    const char *p = cb_ws(line);
    if (*p++ != '#')
        return NULL;
    p = cb_ws(p);
    if (strncmp(p, "include", 7) != 0)
        return NULL;
    p += 7;
    if (strncmp(p, "_next", 5) == 0)
        p += 5;
    if (*p != ' ' && *p != '\t' && *p != '"' && *p != '<')
        return NULL;
    return cb_ws(p);
}

/* A computed (`#include MACRO`) or malformed operand: its first word, so it
 * is reported as unresolved instead of skipped. 3, or 0 when empty. */
static int cb_computed(const char *p, char *tok, size_t cap)
{
    size_t n = strcspn(p, " \t/");
    if (n == 0 || n >= cap)
        return 0;
    memcpy(tok, p, n);
    tok[n] = '\0';
    return 3;
}

/* Parse an include line; 1 quoted, 2 angle, 3 computed, 0 none. */
static int cb_parse(const char *line, char *tok, size_t cap)
{
    const char *p = cb_directive(line), *e;
    char close;
    if (!p)
        return 0;
    if (*p != '"' && *p != '<')
        return cb_computed(p, tok, cap);
    close = *p == '"' ? '"' : '>';
    e = strchr(p + 1, close);
    if (!e || (size_t)(e - p - 1) >= cap || e == p + 1)
        return cb_computed(p, tok, cap);
    memcpy(tok, p + 1, (size_t)(e - p - 1));
    tok[e - p - 1] = '\0';
    return close == '"' ? 1 : 2;
}

static int cb_outside(struct cb_scan *s, const char *key, const char *res)
{
    s->st.outside++;
    if (cb_rows_has(s->env->allow, res)) {
        s->st.allowed++;
        return 0;
    }
    return cb_edge_add(s->found, key, res, CB_OUTSIDE);
}

static int cb_line(struct cb_scan *s, const char *line)
{
    char tok[RS_PATH], res[RS_PATH], key[CB_KEY];
    int ambig, form = cb_parse(line, tok, sizeof tok), kind;
    if (!form)
        return 0;
    ambig = 0;
    snprintf(res, sizeof res, "?");
    kind = form == 3 ? CB_UNRES
                     : cb_resolve(s->env, s->file, tok, form == 1, res, &ambig);
    if (kind < 0)
        return 2;
    s->st.ambig += ambig;
    if (kind == CB_INSIDE)
        s->st.inside++;
    if (kind == CB_SYS)
        s->st.sys++;
    if (kind == CB_INSIDE || kind == CB_SYS)
        return 0;
    if (ovf(snprintf(key, sizeof key, "%s %s", s->file, tok), sizeof key))
        return 2;
    if (kind == CB_OUTSIDE)
        return cb_outside(s, key, res);
    s->st.unres++;
    return cb_edge_add(s->found, key, res, CB_UNRES);
}

static int cb_scan_text(struct cb_scan *s, const char *file, const char *text)
{
    char line[CB_LINE];
    int rc = 0;
    s->file = file;
    s->st.files++;
    for (const char *p = text; rc == 0 && *p;) {
        const char *nl = strchr(p, '\n');
        size_t n = nl ? (size_t)(nl - p) : strlen(p);
        if (n >= sizeof line)
            return die("z23-lint: source line too long: %s\n", file);
        memcpy(line, p, n);
        line[n] = '\0';
        rc = cb_line(s, line);
        p += n + (nl ? 1 : 0);
    }
    return rc;
}

static int cb_scan_file(const char *path, void *ctx)
{
    struct cb_scan *s = ctx;
    FILE *f;
    char line[CB_LINE];
    int rc = 0;
    if (lint_path_is_excluded(path))
        return 0;
    f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "z23-lint: UNPROVEN — cannot read %s\n", path);
        return 2;
    }
    s->file = path;
    s->st.files++;
    while (rc == 0 && fgets(line, (int)sizeof line, f)) {
        size_t n = strlen(line);
        if (n + 1 >= sizeof line && line[n - 1] != '\n')
            rc = die("z23-lint: source line too long: %s\n", path);
        else
            rc = cb_line(s, line);
    }
    if (rc == 0 && ferror(f))
        rc = die("z23-lint: read failed: %s\n", path);
    if (fclose(f) != 0 && rc == 0)
        rc = die("z23-lint: fclose failed: %s\n", path);
    return rc;
}

static int cb_src_name(const char *p)
{
    size_t n = strlen(p);
    if (n >= 2 && p[n - 2] == '.' && (p[n - 1] == 'c' || p[n - 1] == 'h'))
        return 1;
    return n >= 4 && (strcmp(p + n - 4, ".inc") == 0
                      || strcmp(p + n - 4, ".def") == 0);
}

static int cb_on_index(const char *path, int stage, void *ctx)
{
    if (stage != 0 || strncmp(path, "core/", 5) != 0 || !cb_src_name(path))
        return 0;
    return cb_scan_file(path, ctx);
}

/* Production: git-tracked files (an index this reader cannot fully read is
 * UNPROVEN 2). Full/dev scan and fixtures: walk core/ on disk. */
static int cb_scan_tree(struct cb_scan *s)
{
    char badext[5] = "";
    int rc;
    if (!lint_prod_scan())
        return walk_src("core", 3, cb_scan_file, s);
    rc = lint_git_index_foreach(cb_on_index, s, badext);
    if (badext[0]) {
        fprintf(stderr, "z23-lint: UNPROVEN — the git index carries a "
                        "mandatory extension ('%s') this reader does not "
                        "interpret; refusing to grade a partial file list.\n",
                badext);
        return 2;
    }
    return rc;
}

/* ── rows files ───────────────────────────────────────────────────────── */

static int cb_load_cb(void *ctx, const char *line, size_t len)
{
    char row[CB_KEY];
    size_t a = 0;
    while (len && (line[len - 1] == '\n' || line[len - 1] == '\r'
                   || line[len - 1] == ' ' || line[len - 1] == '\t'))
        len--;
    while (a < len && (line[a] == ' ' || line[a] == '\t'))
        a++;
    if (a == len || line[a] == '#')
        return 0;
    if (len - a >= sizeof row)
        return die("z23-lint: core barrier row too long%s\n", "");
    memcpy(row, line + a, len - a);
    row[len - a] = '\0';
    return cb_rows_add(ctx, row);
}

static int cb_load(struct cb_rows *s, const char *path)
{
    int rc = lc_each_line(path, cb_load_cb, s, 0);
    if (rc) {
        fprintf(stderr, "%s: FATAL — cannot read %s\n", k_cb_gate, path);
        return 2;
    }
    cb_rows_sort(s);
    return 0;
}

static int cb_is_n(const char *key)
{
    for (size_t i = 0; i < sizeof k_cb_n_mods / sizeof k_cb_n_mods[0]; i++)
        if (strncmp(key, k_cb_n_mods[i], strlen(k_cb_n_mods[i])) == 0)
            return 1;
    return 0;
}

/* Merge the sorted found edges against the sorted baseline. */
static void cb_compare(const struct cb_edges *f, const struct cb_rows *base,
                       struct cb_cmp *c, FILE *out)
{
    int i = 0, j = 0;
    memset(c, 0, sizeof *c);
    while (i < f->n || j < base->n) {
        int d = i >= f->n ? 1 : j >= base->n ? -1
                                             : strcmp(f->v[i].key, base->r[j]);
        if (d > 0) {
            fprintf(out, "STALE %s  (edge gone: delete this row)\n",
                    base->r[j++]);
            c->stale++;
            continue;
        }
        const struct cb_edge *e = &f->v[i++];
        int n = cb_is_n(e->key);
        c->n += n;
        c->cs += !n;
        if (d == 0) {
            j++;
            continue;
        }
        c->neu++;
        c->neu_cs += !n;
        fprintf(out, "NEW   %s -> %s  [%s file]\n", e->key,
                e->kind == CB_UNRES ? "UNRESOLVED" : e->res,
                n ? "N" : "C/S");
    }
}

/* ── evaluation ───────────────────────────────────────────────────────── */

static void cb_summary(const struct cb_stats *st, const struct cb_cmp *c,
                       int nfound)
{
    printf("%s: barrier — %d core files; %d outside includes, %d allowed, "
           "%d edges (%d from C/S, %d from N); new %d (%d from C/S), "
           "stale %d, unresolved %d, ambiguous %d; symbol pass not run\n",
           k_cb_gate, st->files, st->outside + st->unres, st->allowed, nfound,
           c->cs, c->n, c->neu, c->neu_cs, c->stale, st->unres, st->ambig);
}

static int cb_verdict(const struct cb_cmp *c, FILE *out)
{
    if (c->neu == 0 && c->stale == 0)
        return 0;
    fprintf(out,
            "\n%s: core barrier RATCHET failed. core/ may include only core/,\n"
            "libc/OS headers and the headers in %s.\n"
            "  NEW edge: delete the include, move the needed code into core/,\n"
            "  or invert the dependency (a port the engine implements).\n"
            "  STALE row: the edge is gone; delete its row from %s.\n"
            "  A reviewed regeneration: z23-lint check-core-include-boundary "
            "--write-baseline\n",
            k_cb_gate, k_cb_allow, k_cb_base);
    return 1;
}

static int cb_allow_present(const struct cb_env *env)
{
    int bad = 0;
    for (int i = 0; i < env->allow->n; i++)
        if (!env->exists(env->allow->r[i], env->fsctx)) {
            fprintf(stderr, "%s: FATAL — allowlisted header %s does not "
                            "exist; fix %s\n", k_cb_gate, env->allow->r[i],
                    k_cb_allow);
            bad = 2;
        }
    return bad;
}

static int cb_real_exists(const char *path, void *ctx)
{
    struct stat st;
    (void)ctx;
    return stat(path, &st) == 0 && S_ISREG(st.st_mode);
}

struct cb_state {
    struct cb_rows dirs, allow, base;
    struct cb_edges found;
    struct cb_env env;
    struct cb_scan scan;
};

static void cb_state_free(struct cb_state *s)
{
    free(s->dirs.r);
    free(s->allow.r);
    free(s->base.r);
    free(s->found.v);
    free(s->env.memo);
}

static int cb_state_init(struct cb_state *s, cb_exists_fn fn, void *fsctx)
{
    memset(s, 0, sizeof *s);
    s->env.memo = zcl_calloc(CB_CACHE, sizeof s->env.memo[0], "cb_memo");
    if (!s->env.memo)
        return die("z23-lint: core barrier: out of memory%s\n", "");
    s->env.dirs = &s->dirs;
    s->env.allow = &s->allow;
    s->env.exists = fn;
    s->env.fsctx = fsctx;
    s->scan.env = &s->env;
    s->scan.found = &s->found;
    return 0;
}

/* Sort the edges and fold repeats: one file including one token twice (an
 * #if/#else pair) is one edge. */
static void cb_finish_scan(struct cb_state *s)
{
    int w = 0;
    if (s->found.n > 1)
        qsort(s->found.v, (size_t)s->found.n, sizeof s->found.v[0],
              cb_edgecmp);
    for (int i = 0; i < s->found.n; i++)
        if (w == 0 || strcmp(s->found.v[w - 1].key, s->found.v[i].key) != 0)
            s->found.v[w++] = s->found.v[i];
    s->found.n = w;
}

static int cb_grade(struct cb_state *s, FILE *out)
{
    struct cb_cmp c;
    cb_finish_scan(s);
    cb_compare(&s->found, &s->base, &c, out);
    cb_summary(&s->scan.st, &c, s->found.n);
    return cb_verdict(&c, out);
}

static int cb_write_baseline(struct cb_state *s)
{
    FILE *f;
    int bad;
    cb_finish_scan(s);
    f = fopen(k_cb_base, "w");
    if (!f)
        return die("z23-lint: cannot write %s\n", k_cb_base);
    fputs("# check-core-include-boundary barrier baseline: every #include in\n"
          "# core/ that resolves outside core/ (by file location on the\n"
          "# Makefile include path) or nowhere, and is not allowlisted in\n"
          "# tools/lint/core_barrier_allow.txt. Rows are `<core file> "
          "<token>`.\n"
          "# RATCHET, shrink-only: a new edge fails; a row whose edge is gone\n"
          "# fails as STALE. GENERATED — never hand-edit; regenerate with:\n"
          "#   build/bin/z23-lint check-core-include-boundary "
          "--write-baseline\n", f);
    for (int i = 0; i < s->found.n; i++)
        fprintf(f, "%s\n", s->found.v[i].key);
    bad = ferror(f);
    if (fclose(f) != 0 || bad)
        return die("z23-lint: write failed: %s\n", k_cb_base);
    printf("%s: wrote %d edge row(s) to %s\n", k_cb_gate, s->found.n,
           k_cb_base);
    return 0;
}

static int cb_print_path(void)
{
    struct cb_rows dirs = {0};
    int rc = cb_path_build(&dirs);
    for (int i = 0; rc == 0 && i < dirs.n; i++)
        printf("%s\n", dirs.r[i]);
    free(dirs.r);
    return rc;
}

static int cb_prepare(struct cb_state *s, int write)
{
    int rc = cb_path_build(&s->dirs);
    if (rc == 0)
        rc = cb_load(&s->allow, k_cb_allow);
    if (rc == 0)
        rc = cb_allow_present(&s->env);
    if (rc == 0 && !write)
        rc = cb_load(&s->base, k_cb_base);
    if (rc == 0)
        rc = cb_scan_tree(&s->scan);
    if (rc == 0)
        rc = gate_require_scanned(s->scan.st.files, CB_FLOOR,
                                  "check-core-include-boundary",
                                  "core/ barrier pass scanned too few files");
    return rc;
}

int core_barrier_main(int argc, char **argv)
{
    struct cb_state s;
    int write = argc >= 1 && strcmp(argv[0], "--write-baseline") == 0;
    int rc;
    if (argc >= 1 && strcmp(argv[0], "--print-include-path") == 0)
        return cb_print_path();
    if (!lintc_is_dir("core")) {
        printf("%s: barrier — no core/ tree present (W0 posture)\n",
               k_cb_gate);
        return 0;
    }
    if (cb_state_init(&s, cb_real_exists, NULL))
        return 2;
    rc = cb_prepare(&s, write);
    if (rc == 0)
        rc = write ? cb_write_baseline(&s) : cb_grade(&s, stdout);
    cb_state_free(&s);
    return rc;
}

/* ── selftest: an in-memory tree, no disk I/O ─────────────────────────── */

static const char *const k_cb_st_tree[] = {
    "core/consensus/src/a.c", "core/consensus/src/local.h",
    "core/consensus/include/consensus/x.h",
    "core/modules/net/src/n.c",
    "platform/modules/util/include/util/log_macros.h",
    "platform/modules/util/include/util/foo.h",
    "engine/modules/storage/include/storage/db.h", NULL
};

static int cb_st_exists(const char *path, void *ctx)
{
    const char *const *t = ctx;
    for (; *t; t++)
        if (strcmp(*t, path) == 0)
            return 1;
    return 0;
}

struct cb_st_case {
    const char *name, *file, *text, *base_row;
    int want_rc, want_new, want_stale, want_unres, want_allowed;
};

static int cb_st_setup(struct cb_state *s, const struct cb_st_case *k)
{
    static const char *const dirs[] = {
        "core/consensus/include", "platform/modules/util/include",
        "engine/modules/storage/include"
    };
    int rc = cb_state_init(s, cb_st_exists, (void *)k_cb_st_tree);
    for (size_t i = 0; rc == 0 && i < sizeof dirs / sizeof dirs[0]; i++)
        rc = cb_rows_add(&s->dirs, dirs[i]);
    if (rc == 0)
        rc = cb_rows_add(&s->allow,
                         "platform/modules/util/include/util/log_macros.h");
    if (rc == 0 && k->base_row)
        rc = cb_rows_add(&s->base, k->base_row);
    return rc;
}

static int cb_st_one(const struct cb_st_case *k, FILE *sink)
{
    struct cb_state s;
    struct cb_cmp c;
    int rc = cb_st_setup(&s, k), bad;
    if (rc == 0)
        rc = cb_scan_text(&s.scan, k->file, k->text);
    if (rc) {
        cb_state_free(&s);
        return 1;
    }
    cb_finish_scan(&s);
    cb_compare(&s.found, &s.base, &c, sink);
    rc = cb_verdict(&c, sink);
    bad = rc != k->want_rc || c.neu != k->want_new || c.stale != k->want_stale
          || s.scan.st.unres != k->want_unres
          || s.scan.st.allowed != k->want_allowed;
    if (bad)
        fprintf(stderr, "%s selftest: case '%s' rc=%d new=%d stale=%d "
                        "unres=%d allowed=%d\n", k_cb_gate, k->name, rc,
                c.neu, c.stale, s.scan.st.unres, s.scan.st.allowed);
    cb_state_free(&s);
    return bad;
}

static const struct cb_st_case k_cb_st_cases[] = {
    { "clean", "core/consensus/src/a.c",
      "#include \"consensus/x.h\"\n#include \"local.h\"\n"
      "# include <stdint.h>\n", NULL, 0, 0, 0, 0, 0 },
    { "new outside include fails", "core/consensus/src/a.c",
      "#include \"util/foo.h\"\n", NULL, 1, 1, 0, 0, 0 },
    { "allowlisted include passes", "core/consensus/src/a.c",
      "#include \"util/log_macros.h\"\n", NULL, 0, 0, 0, 0, 1 },
    { "baselined edge passes", "core/modules/net/src/n.c",
      "#include \"storage/db.h\"\n", "core/modules/net/src/n.c storage/db.h",
      0, 0, 0, 0, 0 },
    { "vanished baseline edge is STALE", "core/consensus/src/a.c",
      "#include \"consensus/x.h\"\n", "core/consensus/src/a.c util/foo.h",
      1, 0, 1, 0, 0 },
    { "unresolved quote include is reported", "core/consensus/src/a.c",
      "#include \"nowhere/gone.h\"\n", NULL, 1, 1, 0, 1, 0 },
    { "dot-dot resolves by location", "core/consensus/src/a.c",
      "#include \"../include/consensus/x.h\"\n", NULL, 0, 0, 0, 0, 0 },
    { "computed include is unresolved, never skipped",
      "core/consensus/src/a.c", "#include DB_HEADER\n", NULL, 1, 1, 0, 1, 0 },
    { "include_next resolves like include", "core/consensus/src/a.c",
      "#include_next <util/foo.h>\n", NULL, 1, 1, 0, 0, 0 },
    { "prose #includes line is not a directive", "core/consensus/src/a.c",
      "#includes are counted\n", NULL, 0, 0, 0, 0, 0 },
    { "make-vendor header is outside, installed or not",
      "core/modules/net/src/n.c", "#include <openssl/ssl.h>\n", NULL,
      1, 1, 0, 0, 0 },
};

int core_barrier_selftests(void)
{
    FILE *sink = fopen("/dev/null", "w");
    int bad = 0;
    if (!sink)
        return die("z23-lint: cannot open /dev/null%s\n", "");
    for (size_t i = 0; i < sizeof k_cb_st_cases / sizeof k_cb_st_cases[0]; i++)
        bad |= cb_st_one(&k_cb_st_cases[i], sink);
    fclose(sink);
    return st_ok(bad, "check_core_include_boundary barrier selftest: PASS — "
                      "clean tree passes, a new outside include fails, an "
                      "allowlisted include passes, a baselined edge passes, "
                      "a vanished baseline edge is STALE, unresolved and "
                      "computed includes are reported\n");
}
