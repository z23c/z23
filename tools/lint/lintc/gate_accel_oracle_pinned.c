/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Gate: check-accel-oracle-pinned. Every ISA-dispatched implementation file
 * that the sealed consensus core reaches must be pinned by a differential
 * oracle in the test suite.
 *
 * The core seal (core/MANIFEST.sha3) freezes the TEXT of the consensus
 * predicates, not the arithmetic beneath them: core/ includes public module
 * headers whose implementations carry AVX2/AVX-512 code paths. Editing one
 * changes what a sealed predicate computes without moving a byte in core/.
 * The property that must hold is that each such file is pinned, by a test
 * that runs, to a portable reference producing identical output.
 *
 * Four legs:
 *   1. Discovery. Recompute the include closure of core/ over module
 *      implementation files (lib/<x>/include/<inc>/<stem>.h maps to
 *      lib/<x>/src/<stem>*.c), keep the members carrying an ISA dispatch
 *      (the file plus its private same-directory headers) and require each
 *      one to appear in tools/lint/accel_oracle_registry.txt.
 *   2. No stale rows. A registry row must name a file that exists, is still
 *      in the closure and is still ISA-dispatched.
 *   3. Oracle present and running. The oracle carries the marker line
 *      "ACCEL-ORACLE: <impl>" and its group is registered in the test
 *      group catalog.
 *   4. Oracle still wired. The oracle names at least one function the
 *      implementation exports.
 *
 * Known limit: an accelerator reached only through a private same-directory
 * header is invisible to the discovery leg; give it a public header or add
 * its row by hand.
 *
 * Exit codes: 0 pass, 1 FAIL, 2 FATAL (missing input, hollow scan, read
 * failure). Every scan carries a floor; a collapsed scan is exit 2, never a
 * quiet pass.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <ctype.h>
#include <errno.h>
#include <glob.h>
#include <regex.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include "gate_accel_oracle_pinned_priv.h"
#include "lintc.h"

#define AOP_GATE "check-accel-oracle-pinned"

static const char k_aop_isa_re[] =
    "<(immintrin|x86intrin|cpuid)\\.h>|__builtin_cpu_supports|"
    "__attribute__[[:space:]]*\\(\\([[:space:]]*target[[:space:]]*\\(";
static const char k_aop_inc_re[] = "#include[[:space:]]+\"[^\"]+\"";
static const char k_aop_inc_nq_re[] = "#include[[:space:]]+\"[^\"/]+\"";
static const char k_aop_skip_isa[] = "platform/modules/util/src/hw_profile.c";
static const char *const k_aop_tops[] = { "core", "engine", "cognition",
                                          "platform", "contexts" };

struct aop_vec { char **v; size_t n, cap; };
struct aop_ent { char *key; struct aop_vec impls; };
struct aop_pair { char *oracle, *group; };
struct aop_row { char *impl; struct aop_pair *p; size_t n, cap; };

struct aop_ctx {
    const struct aop_cfg *cfg;
    regex_t re_inc, re_inc_nq, re_isa;
    struct aop_ent *ent;
    size_t n_ent, cap_ent;
    int hdr_count;
    struct aop_vec work, seen, isa, seeds;
    struct aop_row *row;
    size_t n_row, cap_row;
    int rows;
    int fail;
};

static int aop_oom(void)
{
    return die("z23-lint: out of memory\n", "");
}

static int aop_vec_push(struct aop_vec *s, const char *str)
{
    if (s->n == s->cap) {
        size_t nc = s->cap ? s->cap * 2 : 16;
        char **nv = realloc(s->v, nc * sizeof *nv); // raw-alloc-ok:lint-runtime
        if (!nv)
            return aop_oom();
        s->v = nv;
        s->cap = nc;
    }
    char *dup = strdup(str);
    if (!dup)
        return aop_oom();
    s->v[s->n++] = dup;
    return 0;
}

static int aop_vec_has(const struct aop_vec *s, const char *str)
{
    for (size_t i = 0; i < s->n; i++)
        if (strcmp(s->v[i], str) == 0)
            return 1;
    return 0;
}

static void aop_vec_free(struct aop_vec *s)
{
    for (size_t i = 0; i < s->n; i++)
        free(s->v[i]);
    free(s->v);
    *s = (struct aop_vec){ 0 };
}

static int aop_cmp(const void *a, const void *b)
{
    return strcmp(*(char *const *)a, *(char *const *)b);
}

static int aop_row_cmp(const void *a, const void *b)
{
    return strcmp(((const struct aop_row *)a)->impl,
                  ((const struct aop_row *)b)->impl);
}

/* Sorts byte-wise and drops duplicates. */
static void aop_vec_sort_uniq(struct aop_vec *s)
{
    size_t w = 0;
    if (s->n == 0)
        return;
    qsort(s->v, s->n, sizeof *s->v, aop_cmp);
    for (size_t i = 0; i < s->n; i++) {
        if (w > 0 && strcmp(s->v[w - 1], s->v[i]) == 0)
            free(s->v[i]);
        else
            s->v[w++] = s->v[i];
    }
    s->n = w;
}

static int aop_is_file(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0 && S_ISREG(st.st_mode);
}

static void aop_bad(struct aop_ctx *c, const char *fmt, ...)
{
    va_list ap;
    c->fail = 1;
    fputs("FAIL: ", stderr);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
}

/* ── quoted-include extraction ─────────────────────────────────────────── */

/* Adds the text between the quotes of every match of re on line. */
static int aop_line_includes(const regex_t *re, const char *line,
                             struct aop_vec *out)
{
    regmatch_t m;
    while (*line && regexec(re, line, 1, &m, 0) == 0) {
        const char *q1 = memchr(line + m.rm_so, '"', (size_t)(m.rm_eo - m.rm_so));
        const char *end = line + m.rm_eo;
        if (q1) {
            char inner[RS_PATH];
            size_t n = (size_t)(end - 1 - (q1 + 1));
            if (n >= sizeof inner)
                return die("z23-lint: include path too long: %s\n", line);
            memcpy(inner, q1 + 1, n);
            inner[n] = '\0';
            if (aop_vec_push(out, inner))
                return 2;
        }
        line = end;
    }
    return 0;
}

/* Quoted includes of one file. An unreadable file yields nothing, as the
 * script's `2>/dev/null` did. */
static int aop_file_includes(const char *path, const regex_t *re,
                             struct aop_vec *out)
{
    FILE *f = fopen(path, "r");
    char *line = NULL;
    size_t cap = 0;
    int rc = 0;
    if (!f) {
        fprintf(stderr, "z23-lint: cannot read %s: %s\n", path, strerror(errno));
        return 2; /* an unreadable tracked source is a FATAL, never an empty seed set */
    }
    while (rc == 0 && getline(&line, &cap, f) >= 0)
        rc = aop_line_includes(re, line, out);
    free(line);
    if (rc == 0 && ferror(f))
        rc = die("z23-lint: read failed: %s\n", path);
    fclose(f);
    if (rc == 0)
        aop_vec_sort_uniq(out);
    return rc;
}

/* ── module directories and the header-to-implementation index ─────────── */

static int aop_module_cb(const char *path, void *vctx)
{
    struct aop_vec *dirs = vctx;
    const char *slash = strrchr(path, '/');
    size_t pre;
    if (!slash || slash[1] == '\0')
        return 0;
    pre = (size_t)(slash - path);
    if (pre < 8 || strncmp(path + pre - 8, "/modules", 8) != 0)
        return 0;
    return aop_vec_push(dirs, path);
}

/* Module directories <top>/.../modules/<name> at depth 2-4 below each top. */
static int aop_module_dirs(struct aop_vec *dirs)
{
    char cmd[1024] = "find";
    size_t used = strlen(cmd);
    int any = 0;
    int rc;
    for (size_t i = 0; i < sizeof k_aop_tops / sizeof k_aop_tops[0]; i++) {
        struct stat st;
        if (stat(k_aop_tops[i], &st) != 0 || !S_ISDIR(st.st_mode))
            continue;
        used += (size_t)snprintf(cmd + used, sizeof cmd - used, " %s",
                                 k_aop_tops[i]);
        any = 1;
    }
    if (!any)
        return 0;
    if (ovf(snprintf(cmd + used, sizeof cmd - used,
                     " -mindepth 2 -maxdepth 4 -type d -path '*/modules/*'"
                     " -print0 2>/dev/null"), sizeof cmd - used))
        return 2;
    rc = each_zpath_st(cmd, 1, aop_module_cb, dirs);
    aop_vec_sort_uniq(dirs);
    return rc;
}

static struct aop_ent *aop_ent_find(struct aop_ctx *c, const char *key)
{
    for (size_t i = 0; i < c->n_ent; i++)
        if (strcmp(c->ent[i].key, key) == 0)
            return &c->ent[i];
    return NULL;
}

/* The entry for key, emptied if it already existed (a later header with the
 * same key replaces the earlier mapping). */
static struct aop_ent *aop_ent_slot(struct aop_ctx *c, const char *key)
{
    struct aop_ent *e = aop_ent_find(c, key);
    if (e) {
        aop_vec_free(&e->impls);
        return e;
    }
    if (c->n_ent == c->cap_ent) {
        size_t nc = c->cap_ent ? c->cap_ent * 2 : 64;
        struct aop_ent *ne = realloc(c->ent, nc * sizeof *ne); // raw-alloc-ok:lint-runtime
        if (!ne)
            return NULL;
        c->ent = ne;
        c->cap_ent = nc;
    }
    e = &c->ent[c->n_ent];
    *e = (struct aop_ent){ .key = strdup(key) };
    if (!e->key)
        return NULL;
    c->n_ent++;
    return e;
}

/* An absent src directory is valid for a header-only module. All other
 * traversal errors must abort glob instead of silently shrinking discovery. */
static int aop_glob_error(const char *path, int error)
{
    (void)path;
    return error != ENOENT;
}

static int aop_add_impls(struct aop_ent *e, const char *libdir, const char *stem)
{
    char pat[RS_PATH * 2];
    glob_t g;
    int rc = 0;
    if (ovf(snprintf(pat, sizeof pat, "%s/src/%s*.c", libdir, stem), sizeof pat))
        return 2;
    int gr = glob(pat, 0, aop_glob_error, &g);
    if (gr == GLOB_NOMATCH) {
        globfree(&g);
        return 0;
    }
    if (gr != 0) {
        globfree(&g);
        fprintf(stderr, "z23-lint: glob failed for %s (%s)\n", pat,
                gr == GLOB_NOSPACE ? "out of memory" : "read error");
        return 2;
    }
    for (size_t i = 0; rc == 0 && i < g.gl_pathc; i++) {
        if (!aop_is_file(g.gl_pathv[i])) {
            fprintf(stderr, "z23-lint: glob match %s exists but is not a regular file\n",
                    g.gl_pathv[i]);
            rc = 2;
            break;
        }
        rc = aop_vec_push(&e->impls, g.gl_pathv[i]);
    }
    globfree(&g);
    return rc;
}

/* A tracked header lib/<x>/include/<inc>/<stem>.h. */
static int aop_header_cb(const char *h, void *vctx)
{
    struct aop_ctx *c = vctx;
    const char *mod = strstr(h, "/modules/");
    const char *inc = strstr(h, "/include/");
    const char *base = strrchr(h, '/') + 1;
    char libdir[RS_PATH], stem[RS_NAME];
    size_t sl = strlen(base);
    if (!mod || !inc || inc < mod + 9 || sl < 3 || strcmp(base + sl - 2, ".h") != 0)
        return 0;
    sl -= 2;
    if ((size_t)(inc - h) >= sizeof libdir || sl >= sizeof stem)
        return die("z23-lint: header path too long: %s\n", h);
    memcpy(libdir, h, (size_t)(inc - h));
    libdir[inc - h] = '\0';
    memcpy(stem, base, sl);
    stem[sl] = '\0';
    struct aop_ent *e = aop_ent_slot(c, inc + 9);
    if (!e)
        return aop_oom();
    c->hdr_count++;
    return aop_add_impls(e, libdir, stem);
}

static int aop_index_dir(struct aop_ctx *c, const char *dir)
{
    char spec[RS_PATH * 2], q[RS_PATH * 2 + 8], cmd[RS_PATH * 2 + 64];
    if (ovf(snprintf(spec, sizeof spec, "%s/include/*.h", dir), sizeof spec)
        || sh_single_quote(spec, q, sizeof q)
        || ovf(snprintf(cmd, sizeof cmd, "git ls-files -z -- %s", q), sizeof cmd))
        return 2;
    return each_zpath(cmd, aop_header_cb, c);
}

static int aop_build_index(struct aop_ctx *c)
{
    struct aop_vec dirs = { 0 };
    int rc = aop_module_dirs(&dirs);
    for (size_t i = 0; rc == 0 && i < dirs.n; i++)
        rc = aop_index_dir(c, dirs.v[i]);
    aop_vec_free(&dirs);
    if (rc)
        return rc;
    return gate_require_scanned(c->hdr_count, c->cfg->hdr_floor, AOP_GATE,
        "expected >=100 reusable-module headers; the include tree moved.");
}

/* ── leg 1a: include closure of core/ ──────────────────────────────────── */

/* Queues the implementation files of every indexed include in incs. */
static int aop_queue_impls(struct aop_ctx *c, const struct aop_vec *incs,
                           int skip_seen)
{
    for (size_t i = 0; i < incs->n; i++) {
        struct aop_ent *e = aop_ent_find(c, incs->v[i]);
        for (size_t k = 0; e && k < e->impls.n; k++) {
            if (skip_seen && aop_vec_has(&c->seen, e->impls.v[k]))
                continue;
            if (aop_vec_push(&c->work, e->impls.v[k]))
                return 2;
        }
    }
    return 0;
}

static int aop_seed_cb(const char *path, void *vctx)
{
    struct aop_ctx *c = vctx;
    return aop_file_includes(path, &c->re_inc, &c->seeds);
}

static int aop_walk_closure(struct aop_ctx *c)
{
    for (size_t head = 0; head < c->work.n; head++) {
        struct aop_vec incs = { 0 };
        const char *f = c->work.v[head];
        int rc;
        if (aop_vec_has(&c->seen, f))
            continue;
        if (aop_vec_push(&c->seen, f))
            return 2;
        rc = aop_file_includes(f, &c->re_inc, &incs);
        if (rc == 0)
            rc = aop_queue_impls(c, &incs, 1);
        aop_vec_free(&incs);
        if (rc)
            return rc;
    }
    return 0;
}

static int aop_build_closure(struct aop_ctx *c)
{
    int rc = each_zpath("git ls-files -z -- core/", aop_seed_cb, c);
    if (rc)
        return rc;
    aop_vec_sort_uniq(&c->seeds);
    if (aop_queue_impls(c, &c->seeds, 0))
        return 2;
    rc = gate_require_scanned((int)c->work.n, c->cfg->work_floor, AOP_GATE,
        "core/ resolved to almost no lib implementation files; core/ moved or emptied.");
    if (rc == 0)
        rc = aop_walk_closure(c);
    if (rc == 0)
        rc = gate_require_scanned((int)c->seen.n, c->cfg->closure_floor, AOP_GATE,
            "the core/ include closure collapsed; the resolver or the tree layout moved.");
    return rc;
}

/* ── leg 1b: ISA-dispatched closure members ────────────────────────────── */

struct aop_isa_ctx { const regex_t *re; int hit; };

/* lc_each_line callback: stops at the first ISA line; a regexec result
 * other than match/no-match is an error, never a quiet "no match". */
static int aop_isa_line(void *vctx, const char *line, size_t len)
{
    struct aop_isa_ctx *x = vctx;
    int r = regexec(x->re, line, 0, NULL, 0);
    (void)len;
    if (r == REG_NOMATCH)
        return 0;
    if (r != 0)
        return -1;
    x->hit = 1;
    return 1;
}

/* 1 when any line of the listed files matches the ISA pattern; an open or
 * read failure is FATAL (never a quiet "no match"), as a grep error was. */
static int aop_files_isa(struct aop_ctx *c, const struct aop_vec *files, int *hit)
{
    struct aop_isa_ctx x = { &c->re_isa, 0 };
    for (size_t i = 0; i < files->n && !x.hit; i++) {
        if (lc_each_line(files->v[i], aop_isa_line, &x, 0) != 0) {
            fprintf(stderr, "gate_grep: FATAL — grep failed (exit 2) for: %s\n"
                    "  A grep error (bad flag, unreadable file, regex unsupported by\n"
                    "  this grep) was about to be masked as 'no match'. Refusing to\n"
                    "  report 'clean' off a broken scan.\n", files->v[i]);
            return 2;
        }
    }
    *hit = x.hit;
    return 0;
}

/* 1 for a regular file to scan, 0 for an include that does not exist (an
 * include outside the tree is not ours to scan), 2 FATAL for any other stat
 * failure or an existing path that is not a regular file. */
static int aop_include_kind(const char *path)
{
    struct stat st;
    if (stat(path, &st) != 0) {
        if (errno == ENOENT)
            return 0;
        fprintf(stderr, AOP_GATE ": FATAL — cannot stat scanned include %s: %s\n",
                path, strerror(errno));
        return 2;
    }
    if (!S_ISREG(st.st_mode)) {
        fprintf(stderr, AOP_GATE ": FATAL — scanned include %s exists but is "
                "not a regular file\n", path);
        return 2;
    }
    return 1;
}

/* The file plus the private same-directory headers it includes as "name.h". */
static int aop_scan_list(struct aop_ctx *c, const char *f, struct aop_vec *scan)
{
    struct aop_vec incs = { 0 };
    char dir[RS_PATH], path[RS_PATH * 2];
    const char *slash = strrchr(f, '/');
    size_t dl = slash ? (size_t)(slash - f) : 0;
    int rc = aop_vec_push(scan, f);
    if (rc == 0 && dl >= sizeof dir)
        return die("z23-lint: path too long: %s\n", f);
    memcpy(dir, f, dl);
    dir[dl] = '\0';
    if (rc == 0)
        rc = aop_file_includes(f, &c->re_inc_nq, &incs);
    for (size_t i = 0; rc == 0 && i < incs.n; i++) {
        if (ovf(snprintf(path, sizeof path, "%s/%s", dir, incs.v[i]), sizeof path))
            rc = 2;
        else if ((rc = aop_include_kind(path)) == 1)
            rc = aop_vec_push(scan, path);
        else if (rc == 0)
            continue;
    }
    aop_vec_free(&incs);
    return rc;
}

static int aop_build_isa(struct aop_ctx *c)
{
    for (size_t i = 0; i < c->seen.n; i++) {
        struct aop_vec scan = { 0 };
        int hit = 0;
        int rc;
        if (strcmp(c->seen.v[i], k_aop_skip_isa) == 0)
            continue;
        rc = aop_scan_list(c, c->seen.v[i], &scan);
        if (rc == 0)
            rc = aop_files_isa(c, &scan, &hit);
        if (rc == 0 && hit)
            rc = aop_vec_push(&c->isa, c->seen.v[i]);
        aop_vec_free(&scan);
        if (rc)
            return rc;
    }
    aop_vec_sort_uniq(&c->isa);
    return gate_require_scanned((int)c->isa.n, c->cfg->isa_floor, AOP_GATE,
        "no ISA-dispatched file found under sealed core/ — the detector regex broke.");
}

/* ── registry ──────────────────────────────────────────────────────────── */

static struct aop_row *aop_row_for(struct aop_ctx *c, const char *impl)
{
    for (size_t i = 0; i < c->n_row; i++)
        if (strcmp(c->row[i].impl, impl) == 0)
            return &c->row[i];
    if (c->n_row == c->cap_row) {
        size_t nc = c->cap_row ? c->cap_row * 2 : 16;
        struct aop_row *nr = realloc(c->row, nc * sizeof *nr); // raw-alloc-ok:lint-runtime
        if (!nr)
            return NULL;
        c->row = nr;
        c->cap_row = nc;
    }
    c->row[c->n_row] = (struct aop_row){ .impl = strdup(impl) };
    return c->row[c->n_row].impl ? &c->row[c->n_row++] : NULL;
}

static int aop_row_add(struct aop_ctx *c, const char *const tok[3])
{
    struct aop_row *r = aop_row_for(c, tok[0]);
    if (!r)
        return aop_oom();
    if (r->n == r->cap) {
        size_t nc = r->cap ? r->cap * 2 : 2;
        struct aop_pair *np = realloc(r->p, nc * sizeof *np); // raw-alloc-ok:lint-runtime
        if (!np)
            return aop_oom();
        r->p = np;
        r->cap = nc;
    }
    r->p[r->n].oracle = strdup(tok[1]);
    r->p[r->n].group = strdup(tok[2]);
    if (!r->p[r->n].oracle || !r->p[r->n].group)
        return aop_oom();
    r->n++;
    c->rows++;
    return 0;
}

/* Splits a comment-stripped line on whitespace; returns the field count and
 * keeps the first three in tok (the rest are counted only). */
static int aop_split(char *line, const char *tok[3])
{
    int n = 0;
    char *save = NULL;
    for (char *t = strtok_r(line, " \t\r\n\v\f", &save); t;
         t = strtok_r(NULL, " \t\r\n\v\f", &save)) {
        if (n < 3)
            tok[n] = t;
        n++;
    }
    return n;
}

static int aop_registry_line(struct aop_ctx *c, char *line)
{
    char shown[1024], *hash = strchr(line, '#');
    const char *tok[3] = { 0 };
    int n;
    if (hash)
        *hash = '\0';
    line[strcspn(line, "\n")] = '\0';
    snprintf(shown, sizeof shown, "%s", line);
    n = aop_split(line, tok);
    if (n == 0)
        return 0;
    if (n != 3) {
        aop_bad(c, "%s: malformed row (want '<impl.c> <oracle.c> <group>'): %s",
                c->cfg->registry, shown);
        return 0;
    }
    return aop_row_add(c, tok);
}

static int aop_load_registry(struct aop_ctx *c)
{
    FILE *f = fopen(c->cfg->registry, "r");
    char *line = NULL;
    size_t cap = 0;
    int rc = 0;
    if (!f)
        return die("z23-lint: cannot open %s\n", c->cfg->registry);
    while (rc == 0 && getline(&line, &cap, f) >= 0)
        rc = aop_registry_line(c, line);
    if (rc == 0 && ferror(f))
        rc = die("z23-lint: read failed: %s\n", c->cfg->registry);
    free(line);
    fclose(f);
    if (rc)
        return rc;
    return gate_require_scanned(c->rows, c->cfg->rows_floor, AOP_GATE,
        "the registry lost rows; the registry may only shrink when an accelerator is deleted.");
}

/* ── legs 1c and 2 ─────────────────────────────────────────────────────── */

static void aop_leg_unregistered(struct aop_ctx *c)
{
    for (size_t i = 0; i < c->isa.n; i++) {
        int found = 0;
        for (size_t k = 0; k < c->n_row; k++)
            found |= strcmp(c->row[k].impl, c->isa.v[i]) == 0;
        if (!found)
            aop_bad(c, "%s is ISA-dispatched and reachable from sealed core/, but has no\n"
                    "      row in %s. Editing it changes what a sealed consensus predicate\n"
                    "      computes while check-core-seal stays green. Write a differential oracle\n"
                    "      that pins it to a portable reference and add the row.",
                    c->isa.v[i], c->cfg->registry);
    }
}

static void aop_leg_stale(struct aop_ctx *c)
{
    for (size_t i = 0; i < c->n_row; i++) {
        const char *f = c->row[i].impl;
        if (!aop_is_file(f))
            aop_bad(c, "%s names '%s', which does not exist. Delete the row if the\n"
                    "      accelerator is gone.", c->cfg->registry, f);
        else if (!aop_vec_has(&c->seen, f))
            aop_bad(c, "%s names '%s', which sealed core/ no longer reaches.\n"
                    "      Delete the row deliberately (and say why in the commit) rather than\n"
                    "      leaving the registry describing a path that is not there.",
                    c->cfg->registry, f);
        else if (!aop_vec_has(&c->isa, f))
            aop_bad(c, "%s names '%s', which no longer carries an ISA dispatch.\n"
                    "      Either the accelerator was removed (delete the row) or the detector\n"
                    "      needs updating for a new intrinsic form.", c->cfg->registry, f);
    }
}

/* ── legs 3 and 4 ──────────────────────────────────────────────────────── */

/* Whole file as a NUL-terminated string; NULL when unreadable, with errno
 * set to why (ENOENT only when the file is absent). */
static char *aop_slurp(const char *path)
{
    char *buf = NULL;
    size_t len = 0, cap = 0, n;
    int err = 0;
    errno = 0;
    FILE *f = fopen(path, "r");
    if (!f)
        return NULL;
    for (;;) {
        if (len + 4097 > cap) {
            char *nb = realloc(buf, cap = cap ? cap * 2 : 8192); // raw-alloc-ok:lint-runtime
            if (!nb) {
                err = ENOMEM;
                break;
            }
            buf = nb;
        }
        n = fread(buf + len, 1, cap - len - 1, f);
        len += n;
        if (n == 0)
            break;
    }
    if (!err && ferror(f))
        err = errno ? errno : EIO;
    if (err) {
        free(buf);
        buf = NULL;
    } else {
        buf[len] = '\0';
    }
    fclose(f);
    errno = err;
    return buf;
}

static int aop_idc(int ch)
{
    return isalnum((unsigned char)ch) || ch == '_';
}

/* The text before the first '(' is a letter or '_' followed by
 * [A-Za-z0-9_ *]. */
static int aop_export_prefix(const char *line, size_t len)
{
    if (!(isalpha((unsigned char)line[0]) || line[0] == '_'))
        return 0;
    for (size_t i = 0; i < len; i++)
        if (!aop_idc(line[i]) && line[i] != ' ' && line[i] != '*')
            return 0;
    return 1;
}

static int aop_lower_ident(const char *s, size_t n)
{
    if (n == 0 || !(islower((unsigned char)s[0]) || s[0] == '_'))
        return 0;
    for (size_t i = 1; i < n; i++)
        if (!(islower((unsigned char)s[i]) || isdigit((unsigned char)s[i])
              || s[i] == '_'))
            return 0;
    return 1;
}

/* 1 when line holds a definition-shaped prefix "<type> <name>(" and stores
 * the name in sym: the prefix ends in a separator and a lowercase
 * identifier. */
static int aop_export_name(const char *line, char *sym, size_t cap)
{
    const char *paren = strchr(line, '(');
    size_t len, t;
    if (!paren)
        return 0;
    len = (size_t)(paren - line);
    if (!aop_export_prefix(line, len))
        return 0;
    for (t = len; t > 0 && line[t - 1] != ' ' && line[t - 1] != '*'; t--)
        ;
    if (t < 2 || len - t >= cap || !aop_lower_ident(line + t, len - t))
        return 0;
    memcpy(sym, line + t, len - t);
    sym[len - t] = '\0';
    return 1;
}

/* Exported (non-static, non-typedef) function names defined by path. */
static int aop_exports(const char *path, struct aop_vec *syms)
{
    FILE *f = fopen(path, "r");
    char *line = NULL, sym[RS_NAME];
    size_t cap = 0;
    int rc = 0;
    if (!f) {
        fprintf(stderr, "z23-lint: cannot read %s: %s\n", path, strerror(errno));
        return 2; /* an unreadable impl yields no exports: refuse, never skip the leg */
    }
    while (rc == 0 && getline(&line, &cap, f) >= 0) {
        if (strncmp(line, "static", 6) == 0 || strncmp(line, "typedef", 7) == 0)
            continue;
        if (aop_export_name(line, sym, sizeof sym))
            rc = aop_vec_push(syms, sym);
    }
    if (rc == 0 && ferror(f))
        rc = die("z23-lint: read failed: %s\n", path);
    free(line);
    fclose(f);
    aop_vec_sort_uniq(syms);
    return rc;
}

/* sym as a whole word anywhere in text. */
static int aop_has_word(const char *text, const char *sym)
{
    size_t n = strlen(sym);
    for (const char *p = strstr(text, sym); p; p = strstr(p + 1, sym)) {
        int before = p == text || !aop_idc(p[-1]);
        if (before && !aop_idc(p[n]))
            return 1;
    }
    return 0;
}

static int aop_any_export(const char *oracle_text, const struct aop_vec *syms)
{
    for (size_t i = 0; i < syms->n; i++)
        if (aop_has_word(oracle_text, syms->v[i]))
            return 1;
    return 0;
}

static int aop_check_pair(struct aop_ctx *c, const char *impl,
                           const struct aop_pair *p, const struct aop_vec *syms,
                           const char *catalog)
{
    char marker[RS_PATH + 32], group[RS_NAME + 32];
    char *text = aop_slurp(p->oracle);
    if (!text) {
        if (errno != ENOENT) {
            fprintf(stderr, "z23-lint: cannot read %s: %s\n", p->oracle,
                    errno == ENOMEM ? "out of memory" : strerror(errno));
            return 2;
        }
        aop_bad(c, "%s is pinned by '%s', which does not exist. An\n"
                "      accelerator under sealed core/ with no oracle is unprotected: nothing\n"
                "      else in the tree checks it against a portable reference.",
                impl, p->oracle);
        return 0;
    }
    snprintf(marker, sizeof marker, "ACCEL-ORACLE: %s", impl);
    snprintf(group, sizeof group, "ZCL_TEST_GROUP(%s)", p->group);
    if (!strstr(text, marker))
        aop_bad(c, "%s does not carry the marker line 'ACCEL-ORACLE: %s'.\n"
                "      The marker is what makes the pin visible from the test file itself.",
                p->oracle, impl);
    if (!strstr(catalog, group))
        aop_bad(c, "test group '%s' (oracle %s) is not registered as\n"
                "      ZCL_TEST_GROUP(%s) in %s, so it never runs. A compiled-but-undispatched\n"
                "      oracle proves nothing.", p->group, p->oracle, p->group,
                c->cfg->catalog);
    if (syms->n > 0 && !aop_any_export(text, syms))
        aop_bad(c, "%s references no function exported by %s. The pin is\n"
                "      nominal only — a renamed entry point would leave this oracle green while\n"
                "      testing code the node no longer calls.", p->oracle, impl);
    free(text);
    return 0;
}

static int aop_leg_oracles(struct aop_ctx *c)
{
    char *catalog = aop_slurp(c->cfg->catalog);
    if (!catalog)
        return die("z23-lint: cannot read %s\n", c->cfg->catalog);
    for (size_t i = 0; i < c->n_row; i++) {
        struct aop_vec syms = { 0 };
        if (!aop_is_file(c->row[i].impl))
            continue;
        if (aop_exports(c->row[i].impl, &syms)) {
            aop_vec_free(&syms);
            free(catalog);
            return 2;
        }
        int rc = 0;
        for (size_t k = 0; rc == 0 && k < c->row[i].n; k++)
            rc = aop_check_pair(c, c->row[i].impl, &c->row[i].p[k], &syms, catalog);
        aop_vec_free(&syms);
        if (rc) {
            free(catalog);
            return rc;
        }
    }
    free(catalog);
    return 0;
}

/* ── driver ────────────────────────────────────────────────────────────── */

static int aop_ctx_init(struct aop_ctx *c, const struct aop_cfg *cfg)
{
    *c = (struct aop_ctx){ .cfg = cfg };
    if (reg_fail(&c->re_inc, regcomp(&c->re_inc, k_aop_inc_re, REG_EXTENDED))
        || reg_fail(&c->re_inc_nq, regcomp(&c->re_inc_nq, k_aop_inc_nq_re, REG_EXTENDED))
        || reg_fail(&c->re_isa, regcomp(&c->re_isa, k_aop_isa_re, REG_EXTENDED | REG_NOSUB)))
        return 2;
    return 0;
}

static void aop_ctx_free(struct aop_ctx *c)
{
    regfree(&c->re_inc);
    regfree(&c->re_inc_nq);
    regfree(&c->re_isa);
    for (size_t i = 0; i < c->n_ent; i++) {
        free(c->ent[i].key);
        aop_vec_free(&c->ent[i].impls);
    }
    free(c->ent);
    for (size_t i = 0; i < c->n_row; i++) {
        for (size_t k = 0; k < c->row[i].n; k++) {
            free(c->row[i].p[k].oracle);
            free(c->row[i].p[k].group);
        }
        free(c->row[i].p);
        free(c->row[i].impl);
    }
    free(c->row);
    aop_vec_free(&c->work);
    aop_vec_free(&c->seen);
    aop_vec_free(&c->isa);
    aop_vec_free(&c->seeds);
}

static int aop_inputs_present(const struct aop_cfg *cfg)
{
    if (!aop_is_file(cfg->registry)) {
        fprintf(stderr, AOP_GATE ": FATAL — missing %s\n", cfg->registry);
        return 2;
    }
    if (!aop_is_file(cfg->catalog)) {
        fprintf(stderr, AOP_GATE ": FATAL — missing %s\n", cfg->catalog);
        return 2;
    }
    return 0;
}

static int aop_scan(struct aop_ctx *c)
{
    int rc = aop_build_index(c);
    if (rc == 0)
        rc = aop_build_closure(c);
    if (rc == 0)
        rc = aop_build_isa(c);
    if (rc == 0)
        rc = aop_load_registry(c);
    if (rc == 0) {
        qsort(c->row, c->n_row, sizeof *c->row, aop_row_cmp);
        aop_leg_unregistered(c);
        aop_leg_stale(c);
        rc = aop_leg_oracles(c);
    }
    return rc;
}

static int aop_verdict(const struct aop_ctx *c)
{
    if (c->fail) {
        fputs("\nThe consensus-core seal (core/MANIFEST.sha3) covers the predicate\n"
              "TEXT, not the accelerated arithmetic beneath it. This gate is what\n"
              "covers the arithmetic. See docs/CONSENSUS_PARITY_DOCTRINE.md.\n", stderr);
        return 1;
    }
    printf("  OK: %zu ISA-dispatched file(s) reachable from sealed core/ "
           "(closure %zu files), each pinned by a dispatched differential oracle.\n",
           c->isa.n, c->seen.n);
    return 0;
}

int aop_run_cfg(const struct aop_cfg *cfg)
{
    struct aop_ctx c;
    int rc = aop_inputs_present(cfg);
    if (rc == 0)
        rc = aop_ctx_init(&c, cfg);
    if (rc)
        return rc;
    rc = aop_scan(&c);
    if (rc == 0)
        rc = aop_verdict(&c);
    aop_ctx_free(&c);
    return rc;
}

int check_accel_oracle_pinned_run(int argc, char **argv)
{
    static const struct aop_cfg cfg = {
        "tools/lint/accel_oracle_registry.txt",
        "tools/dev/test_group_catalog.def", 100, 5, 30, 4, 4
    };
    (void)argc;
    (void)argv;
    return aop_run_cfg(&cfg);
}
