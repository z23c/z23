/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Gates: check-result-discard, check-wallet-raw-prepare-log
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

static int rd_walk(const char *dir, int hdrs, const struct rd_ctx *ctx);

static int rd_is_src(const char *name, size_t nl, int hdrs)
{
    return nl >= 2 && name[nl - 2] == '.'
        && (name[nl - 1] == 'c' || (hdrs && name[nl - 1] == 'h'));
}

static int rd_walk_entry(const char *dir, const char *name, int hdrs,
                         const struct rd_ctx *ctx)
{
    char path[4096];
    struct stat st;
    size_t nl = strlen(name);
    int k = snprintf(path, sizeof path, "%s/%s", dir, name);
    int rc = 0;
    if (k < 0 || (size_t)k >= sizeof path)
        rc = die("z23-lint: path too long: %s\n", dir);
    else if (lstat(path, &st) != 0)
        rc = 0; /* vanished mid-scan: grep would just lose the race */
    else if (S_ISDIR(st.st_mode)) {
        if (!rd_excl_dir(name))
            rc = rd_walk(path, hdrs, ctx);
    } else if (S_ISREG(st.st_mode) && rd_is_src(name, nl, hdrs)
               && !rd_excl_file(name))
        rc = rd_scan_file(path, ctx);
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
        if (rc == 0 && strcmp(name, ".") != 0 && strcmp(name, "..") != 0)
            rc = rd_walk_entry(dir, name, hdrs, ctx);
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

static void rd_comm_count(char base[][RD_KEY], int nb, int *nnew, int *ngone)
{
    int bi = 0;
    *nnew = 0;
    *ngone = 0;
    for (int i = 0; i < g_rd_nkeys; i++) {
        while (bi < nb && strcoll(base[bi], g_rd_keys[i]) < 0) {
            if (strstr(base[bi], "::") != NULL)
                (*ngone)++;
            bi++;
        }
        if (bi < nb && strcoll(base[bi], g_rd_keys[i]) == 0)
            bi++;
        else
            (*nnew)++;
    }
    while (bi < nb) {
        if (strstr(base[bi], "::") != NULL)
            (*ngone)++;
        bi++;
    }
}

static int rd_print_new_keys(char base[][RD_KEY], int nb)
{
    int bi = 0;
    for (int i = 0; i < g_rd_nkeys; i++) {
        while (bi < nb && strcoll(base[bi], g_rd_keys[i]) < 0)
            bi++;
        if (bi < nb && strcoll(base[bi], g_rd_keys[i]) == 0)
            bi++;
        else if (fprintf(stdout, "%s\n", g_rd_keys[i]) < 0)
            return die("z23-lint: write failed\n", "");
    }
    return 0;
}

static int rd_count_base_keys(char base[][RD_KEY], int nb)
{
    int nbase = 0;
    for (int i = 0; i < nb; i++)
        if (strstr(base[i], "::") != NULL)
            nbase++;
    return nbase;
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
    int nnew = 0, ngone = 0;
    rd_comm_count(base, nb, &nnew, &ngone);
    if (nnew) {
        fputs("FAIL: new (vo" "id)-cast discard of a [[nodiscard]] struct zcl_result.\n"
              "State why the failure is safe to drop:\n"
              "  ZCL_IGNORE_RESULT(<call>, \"<reason>\");   (util/result.h)\n"
              "or mark the line // result-discard-" "ok:<reason> if the macro cannot be used:\n",
              stdout);
        rc = rd_print_new_keys(base, nb);
        if (rc)
            return rc;
        return 1;
    }
    int nbase = rd_count_base_keys(base, nb);
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


/* check-wallet-raw-prepare-log — port of
 * tools/lint/check_wallet_raw_prepare_log.sh (now a shim). A bare
 * sqlite3_prepare_v2() call (one NOT inside an if-condition) whose
 * prepared-stmt NULL check returns without logging is forbidden: the gate
 * opens a 12-line window after each bare prepare, watches for an
 * "if (!stmt)" guard, and reports "<relpath>::<enclosing_function>" when the
 * guarded return carries no LOG_(FAIL|ERR|NULL|RETURN|WARN) between prepare
 * and return. Shrink-only ratchet against
 * tools/lint/wallet_raw_prepare_log_baseline.txt; ZCL_LINT_MODE=UPDATE
 * regenerates. Parity notes: the awk original strips the record newline
 * before matching, so every regex below runs on a newline-stripped line;
 * sort -u / comm run under the ambient locale, so the run function enters
 * the environment locale and orders key sets with strcoll; grep 2>/dev/null
 * maps to silently skipping unreadable/missing dirs and files; the
 * production-scan grep args map to basename predicates (--exclude-dir
 * matches at any depth). The awk machine reads only files containing the
 * prepare literal; scanning every *.c instead yields byte-identical output
 * because a file without the literal can never open a window. The scan
 * roots are contexts/wallet (the original's app/ lib/ roots do not exist in
 * this tree, so the gate could never fire); ZCL_WALLET_RAW_PREPARE_SCAN_
 * DIRS_FOR_TEST overrides them for the selftest and fixtures, and an empty
 * prepare-token scan now fails closed instead of passing vacuously. */

#define WRPL_MAX_KEYS 4096
#define WRPL_KEY 640
#define WRPL_FUNC 128

static char g_wrpl_keys[WRPL_MAX_KEYS][WRPL_KEY];
static int g_wrpl_nkeys;
static int g_wrpl_tok_files; /* files that carried the prepare token (floor) */

static int wrpl_cmp(const void *a, const void *b)
{ return strcoll(a, b); }

/* sort -u: locale-collated ascending, collation-equal duplicates collapse. */
static void wrpl_sort_uniq(char *set, size_t row, int *n)
{
    if (*n <= 0)
        return;
    qsort(set, (size_t)*n, row, wrpl_cmp);
    int w = 0;
    for (int r = 1; r < *n; r++)
        if (strcoll(set + (size_t)w * row, set + (size_t)r * row) != 0)
            memmove(set + (size_t)++w * row, set + (size_t)r * row, row);
    *n = w + 1;
}

/* grep --exclude-dir=<base> semantics, active only under a production scan. */
static int wrpl_excl_dir(const char *base)
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
static int wrpl_excl_file(const char *base)
{
    if (!lint_prod_scan())
        return 0;
    return fnmatch("_*fix" "ture*.c", base, 0) == 0
        || fnmatch("_*fix" "ture*.h", base, 0) == 0;
}

struct wrpl_re {
    regex_t semi;  /* ;[ \t]*$            — prototype ender */
    regex_t log;   /* LOG_(FAIL|ERR|NULL|RETURN|WARN) */
    regex_t ret;   /* return[ \t;(] */
    regex_t guard; /* if \( *! *[A-Za-z_][A-Za-z0-9_]* *\) */
    regex_t cond;  /* (^|[^A-Za-z0-9_])if[ \t]*\(  — prepare inside if */
};

static void wrpl_free(struct wrpl_re *r, int n)
{
    regex_t *re[] = { &r->semi, &r->log, &r->ret, &r->guard, &r->cond };
    for (int i = 0; i < n && i < 5; i++)
        regfree(re[i]);
}

static int wrpl_compile(struct wrpl_re *r)
{
    static const char *const pat[] = {
        ";[ \t]*$",
        ("LOG_"
            "(FAIL|ERR|NULL|RETURN|WARN)"),
        "return[ \t;(]",
        "if \\( *! *[A-Za-z_][A-Za-z0-9_]* *\\)",
        "(^|[^A-Za-z0-9_])if[ \t]*\\(",
    };
    regex_t *re[] = { &r->semi, &r->log, &r->ret, &r->guard, &r->cond };
    for (int i = 0; i < 5; i++) {
        int err = regcomp(re[i], pat[i], REG_EXTENDED);
        if (err) {
            wrpl_free(r, i);
            return reg_fail(re[i], err);
        }
    }
    return 0;
}

struct wrpl_st {
    char curfunc[WRPL_FUNC], pfunc[WRPL_FUNC];
    int prep, gp, since, gsince, logseen, saw_tok;
};

static int wrpl_report(const char *path, const char *func)
{
    if (g_wrpl_nkeys >= WRPL_MAX_KEYS)
        return die("z23-lint: raw-prepare key overflow\n", "");
    int k = snprintf(g_wrpl_keys[g_wrpl_nkeys], WRPL_KEY, "%s::%s", path, func);
    if (ovf(k, WRPL_KEY))
        return 2;
    g_wrpl_nkeys++;
    return 0;
}

static int wrpl_ident_start(unsigned char c)
{
    return isalpha(c) || c == '_';
}

static int wrpl_head_sep(char c)
{
    return c == ' ' || c == '\t' || c == '*';
}

static void wrpl_strip_trailing_blank(char *head, size_t *hl)
{
    while (*hl > 0 && (head[*hl - 1] == ' ' || head[*hl - 1] == '\t'))
        head[--*hl] = '\0';
}

static int wrpl_head_last_part(const char *head, size_t hl,
                               const char **last, size_t *last_len)
{
    int nparts = 0;
    *last = NULL;
    *last_len = 0;
    for (size_t i = 0; i < hl;) {
        if (wrpl_head_sep(head[i])) {
            i++;
            continue;
        }
        size_t start = i;
        while (i < hl && !wrpl_head_sep(head[i]))
            i++;
        nparts++;
        *last = head + start;
        *last_len = i - start;
    }
    return nparts;
}

static int wrpl_ident_ok(const char *s, size_t n)
{
    if (n == 0 || n >= WRPL_FUNC)
        return 0;
    if (!wrpl_ident_start((unsigned char)s[0]))
        return 0;
    for (size_t i = 1; i < n; i++)
        if (!isalnum((unsigned char)s[i]) && s[i] != '_')
            return 0;
    return 1;
}

/* Enclosing-function detection: a column-0 definition header ("<type> name(")
 * that does not end in ';' (which would be a prototype). head = text before
 * the first '(', trailing blanks stripped, split on [ \t*]+ runs; the name is
 * the last of >=2 parts when it is an identifier. */
static void wrpl_curfunc(struct wrpl_st *st, const struct wrpl_re *r,
                         const char *line)
{
    unsigned char c0 = (unsigned char)line[0];
    if (!wrpl_ident_start(c0))
        return;
    const char *paren = strchr(line, '(');
    if (!paren || regexec(&r->semi, line, 0, NULL, 0) == 0)
        return;
    char head[4096];
    size_t hl = (size_t)(paren - line);
    if (hl >= sizeof head)
        return; /* absurd header: awk would split it, we decline to track */
    memcpy(head, line, hl);
    head[hl] = '\0';
    wrpl_strip_trailing_blank(head, &hl);
    const char *last = NULL;
    size_t last_len = 0;
    int nparts = wrpl_head_last_part(head, hl, &last, &last_len);
    if (nparts < 2 || !wrpl_ident_ok(last, last_len))
        return;
    memcpy(st->curfunc, last, last_len);
    st->curfunc[last_len] = '\0';
}

static int wrpl_report_if_unlogged(struct wrpl_st *st, const char *path)
{
    if (!st->logseen && wrpl_report(path, st->pfunc))
        return 2;
    return 0;
}

static int wrpl_advance_guarded(struct wrpl_st *st, const char *path, int hasret)
{
    st->gsince++;
    if (hasret) {
        if (wrpl_report_if_unlogged(st, path))
            return 2;
        st->prep = 0;
        st->gp = 0;
    } else if (st->gsince > 4) {
        st->prep = 0;
        st->gp = 0;
    }
    return 0;
}

static int wrpl_advance_unguarded(struct wrpl_st *st, const struct wrpl_re *r,
                                  const char *path, const char *line, int hasret)
{
    if (regexec(&r->guard, line, 0, NULL, 0) == 0) {
        if (hasret) {
            if (wrpl_report_if_unlogged(st, path))
                return 2;
            st->prep = 0;
        } else if (regexec(&r->log, line, 0, NULL, 0) == 0) {
            st->prep = 0;
        } else {
            st->gp = 1;
            st->gsince = 0;
        }
    }
    return 0;
}

static int wrpl_advance_window(struct wrpl_st *st, const struct wrpl_re *r,
                               const char *path, const char *line)
{
    st->since++;
    if (st->since > 12) {
        st->prep = 0;
        st->gp = 0;
    } else {
        if (regexec(&r->log, line, 0, NULL, 0) == 0)
            st->logseen = 1;
        int hasret = regexec(&r->ret, line, 0, NULL, 0) == 0;
        if (st->gp) {
            if (wrpl_advance_guarded(st, path, hasret))
                return 2;
        } else if (wrpl_advance_unguarded(st, r, path, line, hasret))
            return 2;
    }
    return 0;
}

static void wrpl_open_bare_prepare(struct wrpl_st *st, const struct wrpl_re *r,
                                  const char *line)
{
    /* open a window only for a BARE prepare (not inside an if-condition) */
    if (strstr(line, "sqlite3_prepare_" "v2(") != NULL) {
        st->saw_tok = 1; /* grep -l semantics: the token anywhere counts */
        if (regexec(&r->cond, line, 0, NULL, 0) != 0) {
            st->prep = 1;
            st->since = 0;
            st->logseen = 0;
            st->gp = 0;
            memcpy(st->pfunc, st->curfunc, WRPL_FUNC);
        }
    }
}

/* One newline-stripped line through the awk state machine. */
static int wrpl_line(struct wrpl_st *st, const struct wrpl_re *r,
                     const char *path, const char *line)
{
    wrpl_curfunc(st, r, line);
    if (st->prep) {
        if (wrpl_advance_window(st, r, path, line))
            return 2;
    }
    wrpl_open_bare_prepare(st, r, line);
    return 0;
}

static int wrpl_scan_file(const char *path, const struct wrpl_re *r)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return 0; /* grep 2>/dev/null: an unreadable file contributes nothing */
    struct wrpl_st st;
    memset(&st, 0, sizeof st);
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    int rc = 0;
    while ((n = getline(&line, &cap, f)) >= 0) {
        if (n > 0 && line[n - 1] == '\n')
            line[--n] = '\0'; /* awk records carry no newline */
        if (wrpl_line(&st, r, path, line)) {
            rc = 2;
            break;
        }
    }
    free(line);
    fclose(f);
    if (st.saw_tok)
        g_wrpl_tok_files++;
    return rc;
}

static int wrpl_walk(const char *dir, const struct wrpl_re *r);

static int wrpl_is_c(const char *name, size_t nl)
{
    return nl >= 2 && name[nl - 2] == '.' && name[nl - 1] == 'c';
}

static int wrpl_walk_entry(const char *dir, const char *name,
                           const struct wrpl_re *r)
{
    char path[4096];
    struct stat st;
    size_t nl = strlen(name);
    int k = snprintf(path, sizeof path, "%s/%s", dir, name);
    int rc = 0;
    if (k < 0 || (size_t)k >= sizeof path)
        rc = die("z23-lint: path too long: %s\n", dir);
    else if (lstat(path, &st) != 0)
        rc = 0; /* vanished mid-scan: grep would just lose the race */
    else if (S_ISDIR(st.st_mode)) {
        if (!wrpl_excl_dir(name))
            rc = wrpl_walk(path, r);
    } else if (S_ISREG(st.st_mode) && wrpl_is_c(name, nl)
               && !wrpl_excl_file(name))
        rc = wrpl_scan_file(path, r);
    return rc;
}

static int wrpl_walk(const char *dir, const struct wrpl_re *r)
{
    struct dirent **names = NULL;
    int n = scandir(dir, &names, NULL, alphasort);
    if (n < 0)
        return 0; /* grep 2>/dev/null: an unreadable dir contributes nothing */
    int rc = 0;
    for (int i = 0; i < n; i++) {
        const char *name = names[i]->d_name;
        if (rc == 0 && strcmp(name, ".") != 0 && strcmp(name, "..") != 0)
            rc = wrpl_walk_entry(dir, name, r);
        free(names[i]);
    }
    free(names);
    return rc;
}

static int wrpl_for_each_dir(const char *dirs, const struct wrpl_re *r)
{
    char dbuf[4096];
    if (ovf(snprintf(dbuf, sizeof dbuf, "%s", dirs), sizeof dbuf))
        return 2;
    int rc = 0;
    for (char *save = NULL, *d = strtok_r(dbuf, " \t\n", &save);
         d && rc == 0; d = strtok_r(NULL, " \t\n", &save)) {
        struct stat st;
        if (stat(d, &st) == 0 && S_ISDIR(st.st_mode)) /* [ -d ] || continue */
            rc = wrpl_walk(d, r);
    }
    return rc;
}

/* grep -vE '^[[:space:]]*#|^[[:space:]]*$' line filter. */
static int wrpl_skip_line(const char *s)
{
    while (*s && isspace((unsigned char)*s))
        s++;
    return *s == '#' || *s == '\0';
}

static int wrpl_base_read(char base[][WRPL_KEY], int *nb)
{
    *nb = 0;
    FILE *f = fopen("tools/lint/wallet_raw_prepare_log_baseline.txt", "r");
    if (!f)
        return 0; /* grep 2>/dev/null: a missing baseline is an empty set */
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    int rc = 0;
    while ((n = getline(&line, &cap, f)) >= 0) {
        while (n > 0 && line[n - 1] == '\n')
            line[--n] = '\0';
        if (wrpl_skip_line(line))
            continue;
        if (*nb >= WRPL_MAX_KEYS || (size_t)n >= WRPL_KEY) {
            rc = die("z23-lint: raw-prepare baseline overflow\n", "");
            break;
        }
        memcpy(base[*nb], line, (size_t)n + 1);
        (*nb)++;
    }
    free(line);
    fclose(f);
    return rc;
}

static int wrpl_update(void)
{
    static const char *const hdr[] = {
        "# check_wallet_raw_prepare_log RATCHET baseline (shrink-only).",
        "# Stable key = <relpath>::<enclosing_function>. A swallowed prepare:",
        ("#   sqlite3_prepare_" "v2(...); if (!stmt) return ...;   with no LOG_*."),
        "# Regenerate after fixing some: ZCL_LINT_MODE=UPDATE ./tools/lint/check_wallet_raw_prepare_log.sh",
    };
    FILE *f = fopen("tools/lint/wallet_raw_prepare_log_baseline.txt", "w");
    if (!f)
        return die("z23-lint: cannot write raw-prepare baseline\n", "");
    int rc = 0;
    for (size_t i = 0; i < sizeof hdr / sizeof hdr[0]; i++)
        if (fprintf(f, "%s\n", hdr[i]) < 0) {
            rc = die("z23-lint: write failed\n", "");
            break;
        }
    if (rc == 0 && g_wrpl_nkeys == 0) {
        if (fputc('\n', f) == EOF) /* printf '%s\n' "" emits one blank line */
            rc = die("z23-lint: write failed\n", "");
    }
    for (int i = 0; rc == 0 && i < g_wrpl_nkeys; i++)
        if (fprintf(f, "%s\n", g_wrpl_keys[i]) < 0)
            rc = die("z23-lint: write failed\n", "");
    if (fclose(f) != 0 && rc == 0)
        rc = die("z23-lint: write failed\n", "");
    if (rc)
        return rc;
    printf("check_wallet_raw_prepare_log: baseline updated (%d entries)\n",
           g_wrpl_nkeys);
    return 0;
}

static void wrpl_comm_count(char base[][WRPL_KEY], int nb, int *nnew, int *ngone)
{
    int bi = 0;
    *nnew = 0;
    *ngone = 0;
    for (int i = 0; i < g_wrpl_nkeys; i++) {
        while (bi < nb && strcoll(base[bi], g_wrpl_keys[i]) < 0) {
            if (strstr(base[bi], "::") != NULL)
                (*ngone)++;
            bi++;
        }
        if (bi < nb && strcoll(base[bi], g_wrpl_keys[i]) == 0)
            bi++;
        else
            (*nnew)++;
    }
    while (bi < nb) {
        if (strstr(base[bi], "::") != NULL)
            (*ngone)++;
        bi++;
    }
}

static int wrpl_print_new_keys(char base[][WRPL_KEY], int nb)
{
    int bi = 0;
    for (int i = 0; i < g_wrpl_nkeys; i++) {
        while (bi < nb && strcoll(base[bi], g_wrpl_keys[i]) < 0)
            bi++;
        if (bi < nb && strcoll(base[bi], g_wrpl_keys[i]) == 0)
            bi++;
        else if (fprintf(stdout, "%s\n", g_wrpl_keys[i]) < 0)
            return die("z23-lint: write failed\n", "");
    }
    return 0;
}

static int wrpl_count_base_keys(char base[][WRPL_KEY], int nb)
{
    int nbase = 0;
    for (int i = 0; i < nb; i++)
        if (strstr(base[i], "::") != NULL)
            nbase++;
    return nbase;
}

static int wrpl_fail_mode(void)
{
    static char base[WRPL_MAX_KEYS][WRPL_KEY];
    int nb = 0;
    int rc = wrpl_base_read(base, &nb);
    if (rc)
        return rc;
    wrpl_sort_uniq((char *)base, WRPL_KEY, &nb);
    /* comm -23 CUR BASE: keys present in the scan but absent from baseline. */
    int nnew = 0, ngone = 0;
    wrpl_comm_count(base, nb, &nnew, &ngone);
    if (nnew) {
        fputs("FAIL: new raw sqlite3_prepare_" "v2() with an unlogged NULL-check return.\n"
              "      Log the failure via LOG_FAIL/LOG_RETURN/LOG_ERR/LOG_NULL/LOG_WARN\n"
              "      between the prepare and the 'if (!stmt)' return, or route the\n"
              "      prepare through the AR_* lifecycle macros (activerecord.h):\n",
              stdout);
        rc = wrpl_print_new_keys(base, nb);
        if (rc)
            return rc;
        return 1;
    }
    int nbase = wrpl_count_base_keys(base, nb);
    printf("  OK: no new unlogged raw-prepare NULL-check (%d tracked; baseline %d)\n",
           g_wrpl_nkeys, nbase);
    if (ngone > 0)
        printf("  (ratchet: %d fixed since baseline — run ZCL_LINT_MODE=UPDATE to shrink)\n",
               ngone);
    return 0;
}

int check_wallet_raw_prepare_log_run(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    setlocale(LC_ALL, ""); /* sort/comm in the original obey the ambient locale */
    const char *dirs = getenv("ZCL_WALLET_RAW_PREPARE_SCAN_DIRS_FOR_TEST");
    if (!dirs)
        dirs = "contexts/wallet";
    const char *mode = getenv("ZCL_LINT_MODE");
    g_wrpl_nkeys = 0;
    g_wrpl_tok_files = 0;
    struct wrpl_re r;
    int rc = wrpl_compile(&r);
    if (rc)
        return rc;
    rc = wrpl_for_each_dir(dirs, &r);
    wrpl_free(&r, 5);
    if (rc)
        return rc;
    /* Scan floor: the shell original passed silently when its grep set came
     * back empty — and its app/ lib/ roots do not exist in this tree, so the
     * gate could never fire. An empty prepare-token scan here means the
     * wallet root moved or the token was renamed; refuse to pass vacuously. */
    if (g_wrpl_tok_files == 0) {
        fprintf(stderr, "check_wallet_raw_prepare_log: FATAL — scan found no "
                        "sqlite3_prepare_" "v2( under %s (the gate would pass "
                        "vacuously)\n", dirs);
        return 2;
    }
    wrpl_sort_uniq((char *)g_wrpl_keys, WRPL_KEY, &g_wrpl_nkeys);
    if (mode && strcmp(mode, "UPDATE") == 0)
        return wrpl_update();
    return wrpl_fail_mode();
}

static int wrpl_want(const char *tag, int got, int w, const char *s)
{
    if (got != w) {
        fprintf(stderr, "%s selftest: want %d: %s\n", tag, w, s);
        return 1;
    }
    return 0;
}

/* Feed a synthetic newline-free "file" through the machine, one line per
 * array element; returns the number of keys emitted (in g_wrpl_keys). */
static int wrpl_feed(struct wrpl_st *st, const struct wrpl_re *r,
                     const char *path, const char *const *lines, int n)
{
    memset(st, 0, sizeof *st);
    g_wrpl_nkeys = 0;
    int rc = 0;
    for (int i = 0; i < n && rc == 0; i++)
        rc = wrpl_line(st, r, path, lines[i]);
    return rc;
}

int check_wallet_raw_prepare_log_selftest(void)
{
    const char *t = "check_wallet_raw_prepare_log";
    struct wrpl_re r;
    int cr = wrpl_compile(&r);
    if (cr)
        return cr;
    struct wrpl_st st;
    int bad = 0;

    /* bare prepare, guarded return on the guard line, no LOG_*: violation */
    static const char *const f1[] = {
        "int wallet_open(void) {",
        "    sqlite3_stmt *s = 0;",
        ("    sqlite3_prepare_" "v2(db, sql, -1, &s, 0);"),
        "    if (!s) return 0;",
        "    return 1;",
        "}",
    };
    bad |= wrpl_feed(&st, &r, "app/x.c", f1, 6)
        | wrpl_want(t, g_wrpl_nkeys == 1
                        && strcmp(g_wrpl_keys[0], "app/x.c::wallet_open") == 0,
                    1, "unguarded-logless prepare reports file::func");

    /* LOG_RETURN on the guard line: compliant */
    static const char *const f2[] = {
        "int wallet_open(void) {",
        "    sqlite3_stmt *s = 0;",
        ("    sqlite3_prepare_" "v2(db, sql, -1, &s, 0);"),
        "    if (!s) LOG_RETURN(0, \"prep\");",
        "}",
    };
    bad |= wrpl_feed(&st, &r, "app/x.c", f2, 5)
        | wrpl_want(t, g_wrpl_nkeys, 0, "LOG_RETURN on guard line complies");

    /* LOG between prepare and a split guard/return: compliant */
    static const char *const f3[] = {
        "int wallet_open(void) {",
        "    sqlite3_stmt *s = 0;",
        ("    sqlite3_prepare_" "v2(db, sql, -1, &s, 0);"),
        "    LOG_ERR(\"prep failed\");",
        "    if (!s)",
        "        return 0;",
        "}",
    };
    bad |= wrpl_feed(&st, &r, "app/x.c", f3, 7)
        | wrpl_want(t, g_wrpl_nkeys, 0, "LOG before split guard complies");

    /* split guard/return without LOG: violation */
    static const char *const f4[] = {
        "static int wallet_close(void)",
        "{",
        "    sqlite3_stmt *s = 0;",
        ("    sqlite3_prepare_" "v2(db, sql, -1, &s, 0);"),
        "    if (!s)",
        "        return 0;",
        "    return 1;",
        "}",
    };
    bad |= wrpl_feed(&st, &r, "app/x.c", f4, 8)
        | wrpl_want(t, g_wrpl_nkeys == 1
                        && strcmp(g_wrpl_keys[0], "app/x.c::wallet_close") == 0,
                    1, "split guard/return without LOG reports");

    /* prepare inside an if-condition opens no window */
    static const char *const f5[] = {
        "int wallet_open(void) {",
        "    sqlite3_stmt *s = 0;",
        ("    if (sqlite3_prepare_" "v2(db, sql, -1, &s, 0) != 0)"),
        "        return 0;",
        "}",
    };
    bad |= wrpl_feed(&st, &r, "app/x.c", f5, 5)
        | wrpl_want(t, g_wrpl_nkeys, 0, "if-condition prepare ignored");

    /* window expiry: guard+return 13 lines after the prepare is out of range */
    static const char *const f6[] = {
        "int wallet_open(void) {",
        "    sqlite3_stmt *s = 0;",
        ("    sqlite3_prepare_" "v2(db, sql, -1, &s, 0);"),
        "    int a0=0;", "    int a1=0;", "    int a2=0;", "    int a3=0;",
        "    int a4=0;", "    int a5=0;", "    int a6=0;", "    int a7=0;",
        "    int a8=0;", "    int a9=0;", "    int aa=0;", "    int ab=0;",
        "    if (!s) return 0;",
        "}",
    };
    bad |= wrpl_feed(&st, &r, "app/x.c", f6, 17)
        | wrpl_want(t, g_wrpl_nkeys, 0, "guard 13 lines out is out of window");

    /* guard-body deadline: return on the 5th line after the guard reports,
     * on the 6th the window is already closed */
    static const char *const f7[] = {
        "int wallet_open(void) {",
        "    sqlite3_stmt *s = 0;",
        ("    sqlite3_prepare_" "v2(db, sql, -1, &s, 0);"),
        "    if (!s)",
        "        a0();", "        a1();", "        a2();", "        a3();",
        "        return 0;",
        "}",
    };
    bad |= wrpl_feed(&st, &r, "app/x.c", f7, 10)
        | wrpl_want(t, g_wrpl_nkeys, 1, "return 5 lines after guard reports");
    static const char *const f8[] = {
        "int wallet_open(void) {",
        "    sqlite3_stmt *s = 0;",
        ("    sqlite3_prepare_" "v2(db, sql, -1, &s, 0);"),
        "    if (!s)",
        "        a0();", "        a1();", "        a2();", "        a3();",
        "        a4();",
        "        return 0;",
        "}",
    };
    bad |= wrpl_feed(&st, &r, "app/x.c", f8, 11)
        | wrpl_want(t, g_wrpl_nkeys, 0, "return 6 lines after guard is dead");

    /* no space after if: not a guard (window just expires) */
    static const char *const f9[] = {
        "int wallet_open(void) {",
        "    sqlite3_stmt *s = 0;",
        ("    sqlite3_prepare_" "v2(db, sql, -1, &s, 0);"),
        "    if(!s) return 0;",
        "}",
    };
    bad |= wrpl_feed(&st, &r, "app/x.c", f9, 5)
        | wrpl_want(t, g_wrpl_nkeys, 0, "if(!s) without space is not a guard");

    /* a prototype does not become the enclosing function; file scope keys
     * carry an empty function side */
    static const char *const f10[] = {
        "int wallet_proto(int x);",
        "static sqlite3_stmt *s;",
        "int f(void) {",
        ("    sqlite3_prepare_" "v2(db, sql, -1, &s, 0);"),
        "    if (!s) return 0;",
        "}",
    };
    bad |= wrpl_feed(&st, &r, "app/x.c", f10, 6)
        | wrpl_want(t, g_wrpl_nkeys == 1
                        && strcmp(g_wrpl_keys[0], "app/x.c::f") == 0,
                    1, "prototype does not rename the enclosing function");

    wrpl_free(&r, 5);
    g_wrpl_nkeys = 0;

    /* Scan floor: an empty prepare-token scan fails closed (rc 2); the real
     * wallet root carries the token and the clean tree passes. docs/adr is
     * markdown-only by convention, so its scan set is empty by construction. */
    setenv("ZCL_LINT_MODE", "FAIL", 1);
    setenv("ZCL_WALLET_RAW_PREPARE_SCAN_DIRS_FOR_TEST", "docs/adr", 1);
    bad |= wrpl_want(t, check_wallet_raw_prepare_log_run(0, NULL), 2,
                     "an empty prepare-token scan fails closed");
    setenv("ZCL_WALLET_RAW_PREPARE_SCAN_DIRS_FOR_TEST", "contexts/wallet", 1);
    bad |= wrpl_want(t, check_wallet_raw_prepare_log_run(0, NULL), 0,
                     "the wallet root carries the prepare token");
    unsetenv("ZCL_WALLET_RAW_PREPARE_SCAN_DIRS_FOR_TEST");
    unsetenv("ZCL_LINT_MODE");
    g_wrpl_nkeys = 0;
    return st_ok(bad, "check_wallet_raw_prepare_log selftest: OK\n");
}

