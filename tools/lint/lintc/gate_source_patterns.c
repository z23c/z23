/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Gates: check-result-discard
 * Source-pattern ratchet gates of the C23 lint runtime: shrink-only gates
 * that walk production sources, key each surviving instance of a forbidden
 * pattern, and refuse any key a baseline file does not already carry.
 * Default landing spot for a FUTURE gate port of the same shape; a
 * filesystem-tree-walking gate that is not a ratchet still joins
 * gate_tree_walk.c, and a ratchet that fits gate_ratchet_ports.c follows the
 * landing policy in that family's header.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <ctype.h>
#include <dirent.h>
#include <fnmatch.h>
#include <locale.h>
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "lintc.h"

/* check-result-discard — port of tools/lint/check_result_discard.sh (now a
 * shim). struct zcl_result is [[nodiscard]], so the compiler fences off NEW
 * bare discards, but a C23 void cast suppresses the diagnostic silently. This
 * gate is a shrink-only ratchet over the surviving cast discards: it derives
 * every zcl_result-returning function from the tree, counts each
 * "(void)<fn>(...)" call site not excused by a result-discard-ok comment,
 * keys it as "<relpath>::<fn>", and fails only when a previously-unseen key
 * appears vs tools/lint/result_discard_baseline.txt. Scan dirs are
 * overridable via ZCL_RESULT_DISCARD_SCAN_DIRS_FOR_TEST; the baseline is
 * regenerated with ZCL_LINT_MODE=UPDATE.
 * Parity notes: the shell pipeline ends in sort -u / comm under the ambient
 * locale, so the run function enters the environment locale and orders all
 * key sets with strcoll; the grep 2>/dev/null error suppression maps to
 * silently skipping unreadable dirs/files; the production-scan exclusion
 * args map to basename predicates (grep --exclude / --exclude-dir). */

#define RD_MAX_FNS 2048
#define RD_FN 96
#define RD_MAX_KEYS 8192
#define RD_KEY 640
#define RD_PAT (RD_MAX_FNS * (RD_FN + 1) + 64)

static char g_rd_fns[RD_MAX_FNS][RD_FN];
static int g_rd_nfns;
static char g_rd_keys[RD_MAX_KEYS][RD_KEY];
static int g_rd_nkeys;
static char g_rd_pat[RD_PAT];

static int rd_cmp(const void *a, const void *b)
{ return strcoll(a, b); }

/* sort -u: locale-collated ascending, collation-equal duplicates collapse.
 * set is n rows of row bytes each, all NUL-terminated. */
static void rd_sort_uniq(char *set, size_t row, int *n)
{
    if (*n <= 0)
        return;
    qsort(set, (size_t)*n, row, rd_cmp);
    int w = 0;
    for (int r = 1; r < *n; r++)
        if (strcoll(set + (size_t)w * row, set + (size_t)r * row) != 0)
            memmove(set + (size_t)++w * row, set + (size_t)r * row, row);
    *n = w + 1;
}

/* grep --exclude-dir=<base> semantics, active only under a production scan. */
static int rd_excl_dir(const char *base)
{
    static const char *const skip[] = {
        "planted", "build", "vendor", ".claude", "test-tmp"
    };
    if (!lint_prod_scan())
        return 0;
    for (size_t i = 0; i < sizeof skip / sizeof skip[0]; i++)
        if (strcmp(base, skip[i]) == 0)
            return 1;
    return 0;
}

/* grep --exclude='_*fixture*.[ch]' basename-glob semantics. */
static int rd_excl_file(const char *base)
{
    if (!lint_prod_scan())
        return 0;
    return fnmatch("_*fix" "ture*.c", base, 0) == 0
        || fnmatch("_*fix" "ture*.h", base, 0) == 0;
}

struct rd_ctx {
    regex_t *re;     /* pass 1: fn-decl pattern; pass 2: discard pattern */
    regex_t *ok_re;  /* pass 2 only: comment-ok exclusion */
    int pass2;
};

static int rd_scan_file(const char *path, const struct rd_ctx *ctx)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return 0; /* grep 2>/dev/null: an unreadable file contributes nothing */
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    int rc = 0;
    while ((n = getline(&line, &cap, f)) >= 0) {
        regmatch_t m[2];
        if (!ctx->pass2) {
            /* grep -hoE: every non-overlapping match on the line yields one
             * candidate; sed then keeps the function-name group. */
            size_t off = 0;
            while (regexec(ctx->re, line + off, 2, m, 0) == 0) {
                size_t len = (size_t)(m[1].rm_eo - m[1].rm_so);
                if (len >= RD_FN || g_rd_nfns >= RD_MAX_FNS) {
                    rc = die("z23-lint: result-discard scan overflow\n", "");
                    break;
                }
                memcpy(g_rd_fns[g_rd_nfns], line + off + m[1].rm_so, len);
                g_rd_fns[g_rd_nfns][len] = '\0';
                g_rd_nfns++;
                off += (size_t)m[0].rm_eo;
            }
        } else {
            /* grep -nE prints the line once; the fn extraction keeps the
             * FIRST cast match on the line (grep -oE ... | head -1). */
            if (regexec(ctx->re, line, 2, m, 0) != 0)
                continue;
            if (regexec(ctx->ok_re, line, 0, NULL, 0) == 0)
                continue;
            if (g_rd_nkeys >= RD_MAX_KEYS) {
                rc = die("z23-lint: result-discard key overflow\n", "");
                break;
            }
            const char *p = path;
            if (p[0] == '.' && p[1] == '/')
                p += 2; /* ${file#./} */
            int k = snprintf(g_rd_keys[g_rd_nkeys], RD_KEY, "%s::%.*s", p,
                             (int)(m[1].rm_eo - m[1].rm_so),
                             line + m[1].rm_so);
            if (ovf(k, RD_KEY)) {
                rc = 2;
                break;
            }
            g_rd_nkeys++;
        }
        if (rc)
            break;
    }
    free(line);
    fclose(f);
    return rc;
}

static int rd_walk(const char *dir, int hdrs, const struct rd_ctx *ctx)
{
    struct dirent **names = NULL;
    int n = scandir(dir, &names, NULL, alphasort);
    if (n < 0)
        return 0; /* grep 2>/dev/null: an unreadable dir contributes nothing */
    int rc = 0;
    for (int i = 0; i < n; i++) {
        const char *name = names[i]->d_name;
        if (rc == 0 && strcmp(name, ".") != 0 && strcmp(name, "..") != 0) {
            char path[4096];
            struct stat st;
            size_t nl = strlen(name);
            int k = snprintf(path, sizeof path, "%s/%s", dir, name);
            if (k < 0 || (size_t)k >= sizeof path)
                rc = die("z23-lint: path too long: %s\n", dir);
            else if (lstat(path, &st) != 0)
                rc = 0; /* vanished mid-scan: grep would just lose the race */
            else if (S_ISDIR(st.st_mode)) {
                if (!rd_excl_dir(name))
                    rc = rd_walk(path, hdrs, ctx);
            } else if (S_ISREG(st.st_mode) && nl >= 2 && name[nl - 2] == '.'
                       && (name[nl - 1] == 'c' || (hdrs && name[nl - 1] == 'h'))
                       && !rd_excl_file(name))
                rc = rd_scan_file(path, ctx);
        }
        free(names[i]);
    }
    free(names);
    return rc;
}

static int rd_compile_fn(regex_t *re)
{
    return reg_fail(re, regcomp(re,
        "struct zcl_" "result[[:space:]]+([a-zA-Z_][a-zA-Z0-9_]*)"
        "[[:space:]]*\\(", REG_EXTENDED));
}

static int rd_compile_ok(regex_t *re)
{
    return reg_fail(re, regcomp(re,
        "(//|/\\*)[[:space:]]*result-discard-" "ok:", REG_EXTENDED));
}

/* Build "\(void\)[[:space:]]*(<f1>|<f2>|...)[[:space:]]*\(" from the sorted
 * unique fn set and compile it. Alternation order is unobservable: the
 * trailing paren anchor makes every fn match unambiguous. */
static int rd_compile_discard(regex_t *re)
{
    size_t used = 0;
    int k = snprintf(g_rd_pat, sizeof g_rd_pat, "%s", "\\(vo" "id\\)[[:space:]]*(");
    if (ovf(k, sizeof g_rd_pat))
        return 2;
    used = (size_t)k;
    for (int i = 0; i < g_rd_nfns; i++) {
        k = snprintf(g_rd_pat + used, sizeof g_rd_pat - used, "%s%s",
                     i ? "|" : "", g_rd_fns[i]);
        if (ovf(k, sizeof g_rd_pat - used))
            return 2;
        used += (size_t)k;
    }
    k = snprintf(g_rd_pat + used, sizeof g_rd_pat - used, "%s",
                 ")[[:space:]]*\\(");
    if (ovf(k, sizeof g_rd_pat - used))
        return 2;
    return reg_fail(re, regcomp(re, g_rd_pat, REG_EXTENDED));
}

static int rd_for_each_dir(const char *dirs, int hdrs, const struct rd_ctx *ctx)
{
    char dbuf[4096];
    if (ovf(snprintf(dbuf, sizeof dbuf, "%s", dirs), sizeof dbuf))
        return 2;
    int rc = 0;
    for (char *save = NULL, *d = strtok_r(dbuf, " \t\n", &save);
         d && rc == 0; d = strtok_r(NULL, " \t\n", &save)) {
        struct stat st;
        if (stat(d, &st) == 0 && S_ISDIR(st.st_mode)) /* [ -d ] || continue */
            rc = rd_walk(d, hdrs, ctx);
    }
    return rc;
}

/* grep -vE '^[[:space:]]*#|^[[:space:]]*$' line filter. */
static int rd_skip_line(const char *s)
{
    while (*s && isspace((unsigned char)*s))
        s++;
    return *s == '#' || *s == '\0';
}

static int rd_base_read(char base[][RD_KEY], int *nb)
{
    *nb = 0;
    FILE *f = fopen("tools/lint/result_discard_baseline.txt", "r");
    if (!f)
        return 0; /* grep 2>/dev/null: a missing baseline is an empty set */
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    int rc = 0;
    while ((n = getline(&line, &cap, f)) >= 0) {
        while (n > 0 && (line[n - 1] == '\n'))
            line[--n] = '\0';
        if (rd_skip_line(line))
            continue;
        if (*nb >= RD_MAX_KEYS || (size_t)n >= RD_KEY) {
            rc = die("z23-lint: result-discard baseline overflow\n", "");
            break;
        }
        memcpy(base[*nb], line, (size_t)n + 1);
        (*nb)++;
    }
    free(line);
    fclose(f);
    return rc;
}

static int rd_update(void)
{
    static const char *const hdr[] = {
        "# check_result_discard RATCHET baseline (shrink-only).",
        "# Stable key = <relpath>::<discarded_fn>. A cast discard of a",
        ("# [[nodiscard]] struct zcl_result:  (vo" "id)fn(...);  with no reason."),
        "# Fix one by stating the reason:",
        "#   ZCL_IGNORE_RESULT(fn(...), \"why the failure is safe to drop\");",
        "# Regenerate after fixing some:",
        "#   ZCL_LINT_MODE=UPDATE ./tools/lint/check_result_discard.sh",
    };
    FILE *f = fopen("tools/lint/result_discard_baseline.txt", "w");
    if (!f)
        return die("z23-lint: cannot write result-discard baseline\n", "");
    int rc = 0;
    for (size_t i = 0; i < sizeof hdr / sizeof hdr[0]; i++)
        if (fprintf(f, "%s\n", hdr[i]) < 0) {
            rc = die("z23-lint: write failed\n", "");
            break;
        }
    if (rc == 0 && g_rd_nkeys == 0) {
        if (fputc('\n', f) == EOF) /* printf '%s\n' "" emits one blank line */
            rc = die("z23-lint: write failed\n", "");
    }
    for (int i = 0; rc == 0 && i < g_rd_nkeys; i++)
        if (fprintf(f, "%s\n", g_rd_keys[i]) < 0)
            rc = die("z23-lint: write failed\n", "");
    if (fclose(f) != 0 && rc == 0)
        rc = die("z23-lint: write failed\n", "");
    if (rc)
        return rc;
    printf("check_result_discard: baseline updated (%d entries)\n", g_rd_nkeys);
    return 0;
}

static int rd_fail_mode(void)
{
    static char base[RD_MAX_KEYS][RD_KEY];
    int nb = 0;
    int rc = rd_base_read(base, &nb);
    if (rc)
        return rc;
    rd_sort_uniq((char *)base, RD_KEY, &nb);
    /* comm -23 CUR BASE: keys present in the scan but absent from baseline. */
    int bi = 0, nnew = 0, ngone = 0;
    for (int i = 0; i < g_rd_nkeys; i++) {
        while (bi < nb && strcoll(base[bi], g_rd_keys[i]) < 0) {
            if (strstr(base[bi], "::") != NULL)
                ngone++;
            bi++;
        }
        if (bi < nb && strcoll(base[bi], g_rd_keys[i]) == 0)
            bi++;
        else
            nnew++;
    }
    while (bi < nb) {
        if (strstr(base[bi], "::") != NULL)
            ngone++;
        bi++;
    }
    if (nnew) {
        fputs("FAIL: new (vo" "id)-cast discard of a [[nodiscard]] struct zcl_result.\n"
              "State why the failure is safe to drop:\n"
              "  ZCL_IGNORE_RESULT(<call>, \"<reason>\");   (util/result.h)\n"
              "or mark the line // result-discard-" "ok:<reason> if the macro cannot be used:\n",
              stdout);
        bi = 0;
        for (int i = 0; i < g_rd_nkeys; i++) {
            while (bi < nb && strcoll(base[bi], g_rd_keys[i]) < 0)
                bi++;
            if (bi < nb && strcoll(base[bi], g_rd_keys[i]) == 0)
                bi++;
            else if (fprintf(stdout, "%s\n", g_rd_keys[i]) < 0)
                return die("z23-lint: write failed\n", "");
        }
        return 1;
    }
    int nbase = 0;
    for (int i = 0; i < nb; i++)
        if (strstr(base[i], "::") != NULL)
            nbase++;
    printf("  OK: no new zcl_result cast discard (%d tracked; baseline %d)\n",
           g_rd_nkeys, nbase);
    if (ngone > 0)
        printf("  (ratchet: %d fixed since baseline — run ZCL_LINT_MODE=UPDATE to shrink)\n",
               ngone);
    return 0;
}

int check_result_discard_run(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    setlocale(LC_ALL, ""); /* sort/comm in the original obey the ambient locale */
    const char *dirs = getenv("ZCL_RESULT_DISCARD_SCAN_DIRS_FOR_TEST");
    if (!dirs)
        dirs = "app config core lib domain application adapters ports tools";
    const char *mode = getenv("ZCL_LINT_MODE");

    g_rd_nfns = 0;
    g_rd_nkeys = 0;
    regex_t fnre;
    int rc = rd_compile_fn(&fnre);
    if (rc)
        return rc;
    struct rd_ctx c1 = { .re = &fnre, .ok_re = NULL, .pass2 = 0 };
    rc = rd_for_each_dir(dirs, 1, &c1);
    regfree(&fnre);
    if (rc)
        return rc;
    rd_sort_uniq((char *)g_rd_fns, RD_FN, &g_rd_nfns);
    if (g_rd_nfns > 0) {
        regex_t disre, okre;
        rc = rd_compile_discard(&disre);
        if (rc)
            return rc;
        rc = rd_compile_ok(&okre);
        if (rc) {
            regfree(&disre);
            return rc;
        }
        struct rd_ctx c2 = { .re = &disre, .ok_re = &okre, .pass2 = 1 };
        rc = rd_for_each_dir(dirs, 0, &c2);
        regfree(&disre);
        regfree(&okre);
        if (rc)
            return rc;
        rd_sort_uniq((char *)g_rd_keys, RD_KEY, &g_rd_nkeys);
    } /* empty alternation: scan() contributes nothing */
    if (mode && strcmp(mode, "UPDATE") == 0)
        return rd_update();
    return rd_fail_mode();
}

static int rd_want(const char *tag, int got, int w, const char *s)
{
    if (got != w) {
        fprintf(stderr, "%s selftest: want %d: %s\n", tag, w, s);
        return 1;
    }
    return 0;
}

/* First fn-decl match's name group, or NULL. */
static const char *rd_fn_of(regex_t *re, const char *line, char *out, size_t cap)
{
    regmatch_t m[2];
    if (regexec(re, line, 2, m, 0) != 0)
        return NULL;
    size_t len = (size_t)(m[1].rm_eo - m[1].rm_so);
    if (len >= cap)
        return NULL;
    memcpy(out, line + m[1].rm_so, len);
    out[len] = '\0';
    return out;
}

int check_result_discard_selftest(void)
{
    const char *t = "check_result_discard";
    regex_t fnre, disre, okre;
    int cr = rd_compile_fn(&fnre);
    if (cr)
        return cr;
    if ((cr = rd_compile_ok(&okre)) != 0) {
        regfree(&fnre);
        return cr;
    }
    g_rd_nfns = 2;
    memcpy(g_rd_fns[0], "zcl_alpha", 10);
    memcpy(g_rd_fns[1], "zcl_beta_2", 11);
    cr = rd_compile_discard(&disre);
    if (cr) {
        regfree(&fnre);
        regfree(&okre);
        return cr;
    }
    char fn[RD_FN];
    regmatch_t m[2];
    /* Each probe computes into its own local first: combining them into one
     * | chain up front would leave the shared fn/m buffers indeterminately
     * sequenced across arguments. */
    const char *cast = "    (vo" "id)zcl_alpha(x);";
    int c1 = rd_fn_of(&fnre, "struct zcl_" "result zcl_foo_bar(",
                      fn, sizeof fn) != NULL && strcmp(fn, "zcl_foo_bar") == 0;
    int c2 = rd_fn_of(&fnre, "struct zcl_" "result  _a9  (int x)",
                      fn, sizeof fn) != NULL && strcmp(fn, "_a9") == 0;
    int c3 = rd_fn_of(&fnre, "x = sizeof(struct zcl_"
                      "result);", fn, sizeof fn) == NULL;
    int c4 = rd_fn_of(&fnre, "struct zcl_"
                      "resultfoo(", fn, sizeof fn) == NULL;
    int c5 = regexec(&disre, cast, 2, m, 0) == 0 && m[1].rm_so >= 0
          && (size_t)(m[1].rm_eo - m[1].rm_so) == 9
          && memcmp(cast + m[1].rm_so, "zcl_alpha", 9) == 0;
    int c6 = regexec(&disre, "\t(vo" "id)  zcl_beta_2  (", 2, m, 0) == 0
          && m[1].rm_so >= 0 && (size_t)(m[1].rm_eo - m[1].rm_so) == 10;
    int c7 = regexec(&disre, "(vo" "id)zcl_alpha2(x);", 0, NULL, 0) != 0;
    int c8 = regexec(&disre, "zcl_alpha(x);", 0, NULL, 0) != 0;
    int c9 = regexec(&okre, "(vo" "id)zcl_alpha(x); // result-discard-"
                     "ok: best-effort", 0, NULL, 0) == 0;
    int c10 = regexec(&okre, "(vo" "id)zcl_alpha(x); /* result-discard-"
                      "ok: x", 0, NULL, 0) == 0;
    int c11 = regexec(&okre, "(vo" "id)zcl_alpha(x); result-discard-"
                      "ok:", 0, NULL, 0) != 0;
    int bad = rd_want(t, c1, 1, "decl extracts fn")
            | rd_want(t, c2, 1, "decl with extra spaces")
            | rd_want(t, c3, 1, "no ident+paren after the type")
            | rd_want(t, c4, 1, "missing whitespace after the type")
            | rd_want(t, c5, 1, "bare cast discard matches and names the fn")
            | rd_want(t, c6, 1, "cast with whitespace matches")
            | rd_want(t, c7, 1, "name prefix without paren does not match")
            | rd_want(t, c8, 1, "uncast call does not match")
            | rd_want(t, c9, 1, "comment-ok excludes //")
            | rd_want(t, c10, 1, "comment-ok excludes /*")
            | rd_want(t, c11, 1, "bare marker without comment does not exclude")
            | rd_want(t, rd_skip_line("# c"), 1, "comment line")
            | rd_want(t, rd_skip_line("   # c"), 1, "indented comment line")
            | rd_want(t, rd_skip_line("   "), 1, "blank line")
            | rd_want(t, rd_skip_line("core/a.c::zcl_alpha"), 0, "key line");
    regfree(&fnre);
    regfree(&disre);
    regfree(&okre);
    /* sort -u: dedup and locale-invariant ascending order. */
    static char set[3][RD_KEY];
    memcpy(set[0], "core/b.c::zcl_alpha", 20);
    memcpy(set[1], "core/a.c::zcl_beta_2", 21);
    memcpy(set[2], "core/b.c::zcl_alpha", 20);
    int n = 3;
    rd_sort_uniq((char *)set, RD_KEY, &n);
    bad |= rd_want(t, n == 2 && strcmp(set[0], "core/a.c::zcl_beta_2") == 0
                       && strcmp(set[1], "core/b.c::zcl_alpha") == 0, 1,
                   "sort -u dedups and orders");
    g_rd_nfns = 0;
    return st_ok(bad, "check_result_discard selftest: OK\n");
}

