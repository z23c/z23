/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Gates: check-no-new-borrowed-seed, check-silent-errors-bool,
 * check-no-raw-sqlite-in-controllers, check-no-orphan-placement
 * Default landing spot for a FUTURE gate port: a shrink-only caller-baseline
 * ratchet (walk_src over production roots plus a comment-stripped baseline
 * file) joins this family. A filesystem-tree-walking gate that is not a
 * ratchet still joins gate_tree_walk.c; this file exists because
 * gate_tree_walk.c is already at the ~1500-line family cap.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <ctype.h>
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "lintc.h"

enum { NBS_MAX = 512, NBS_PATH = RS_PATH };

static const char k_nbs_def[] =
    "engine/modules/storage/src/coins_kv_boot_rebuild.c";
static const char k_nbs_base[] =
    "tools/lint/borrowed_seed_caller_baseline.txt";
static const char *const k_nbs_roots[] = {
    "core", "engine", "contexts", "cognition", "platform", "tools"
};

struct nbs_set { char n[NBS_MAX][NBS_PATH]; int count; };
struct nbs_acc { const char *sym; const char *def; struct nbs_set *callers; };

static void nbs_sym(char *buf, size_t cap)
{
    (void)snprintf(buf, cap, "%s%s", "coins_kv_seed_from_node_db", "(");
}

static int nbs_has(const struct nbs_set *s, const char *path)
{
    for (int i = 0; i < s->count; i++) {
        if (strcmp(s->n[i], path) == 0)
            return 1;
    }
    return 0;
}

static int nbs_add(struct nbs_set *s, const char *path)
{
    size_t n = strlen(path);
    if (nbs_has(s, path))
        return 0;
    if (s->count >= NBS_MAX || n >= NBS_PATH)
        return die("z23-lint: derived buffer overflow\n", "");
    memcpy(s->n[s->count++], path, n + 1);
    return 0;
}

static int nbs_cmp(const void *a, const void *b)
{
    return strcmp((const char *)a, (const char *)b);
}

static int nbs_load_list(const char *path, struct nbs_set *s)
{
    s->count = 0;
    FILE *f = fopen(path, "r");
    if (!f)
        return 0;
    char *line = NULL;
    size_t cap = 0;
    int rc = 0;
    while (rc == 0 && getline(&line, &cap, f) >= 0) {
        char *h = strchr(line, '#'), *p = line;
        if (h)
            *h = '\0';
        while (*p && isspace((unsigned char)*p))
            p++;
        size_t n = strlen(p);
        while (n && isspace((unsigned char)p[n - 1]))
            p[--n] = '\0';
        if (n)
            rc = nbs_add(s, p);
    }
    return fin(f, line, path, rc);
}

static int nbs_text_has_sym(const char *text, const char *sym)
{
    return text && sym && strstr(text, sym) != NULL;
}

static int nbs_file_has_sym(const char *path, const char *sym)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return 0;
    char *line = NULL;
    size_t cap = 0;
    int found = 0;
    while (!found && getline(&line, &cap, f) >= 0)
        found = strstr(line, sym) != NULL;
    (void)fin(f, line, path, 0);
    return found;
}

static int nbs_on_file(const char *path, void *ctx)
{
    struct nbs_acc *a = ctx;
    static const char pfx[] = "tests/harness/include/test/";
    if (strcmp(path, a->def) == 0)
        return 0;
    if (strncmp(path, pfx, sizeof pfx - 1) == 0)
        return 0;
    if (lint_path_is_excluded(path))
        return 0;
    if (!nbs_file_has_sym(path, a->sym))
        return 0;
    return nbs_add(a->callers, path);
}

static int nbs_hollow(FILE *out, const char *sym)
{
    if (fprintf(out,
                "check_no_new_borrowed_seed: FATAL — '%s' no longer found in %s.\n",
                sym, k_nbs_def) < 0
        || fputs("  - If the borrowed seed was DELETED (the sovereign cure landed), delete\n",
                 out) < 0
        || fprintf(out, "    this gate, its Makefile wiring, and %s.\n",
                   k_nbs_base) < 0
        || fputs("  - If it was RENAMED/MOVED, update DEF_FILE/SYMBOL here so the ratchet\n",
                 out) < 0
        || fputs("    keeps firing. A gate that matches nothing is a hollow gate.\n",
                 out) < 0)
        return die("z23-lint: write failed\n", "");
    return 2;
}

static int nbs_walk_roots(struct nbs_acc *a)
{
    int rc = 0;
    for (size_t i = 0; rc == 0 && i < sizeof k_nbs_roots / sizeof k_nbs_roots[0]; i++)
        rc = walk_src(k_nbs_roots[i], 0, nbs_on_file, a);
    return rc;
}

static int nbs_collect_new(const struct nbs_set *callers, const struct nbs_set *base,
                           struct nbs_set *newc)
{
    for (int i = 0; i < callers->count; i++) {
        if (!nbs_has(base, callers->n[i])) {
            int rc = nbs_add(newc, callers->n[i]);
            if (rc)
                return rc;
        }
    }
    return 0;
}

static int nbs_collect_stale(const struct nbs_set *base, const char *sym,
                             struct nbs_set *stale)
{
    for (int i = 0; i < base->count; i++) {
        if (!nbs_file_has_sym(base->n[i], sym)) {
            int rc = nbs_add(stale, base->n[i]);
            if (rc)
                return rc;
        }
    }
    return 0;
}

static int nbs_report_clean(FILE *out, int base_count)
{
    if (fprintf(out,
                "check_no_new_borrowed_seed: clean — %d grandfathered caller(s), no new ones\n",
                base_count) < 0)
        return die("z23-lint: write failed\n", "");
    return 0;
}

static int nbs_report_new(FILE *out, const struct nbs_set *newc)
{
    if (fprintf(out,
                "check_no_new_borrowed_seed: %d NEW caller(s) of the borrowed seed:\n",
                newc->count) < 0)
        return die("z23-lint: write failed\n", "");
    for (int i = 0; i < newc->count; i++) {
        if (fprintf(out, "  %s\n", newc->n[i]) < 0)
            return die("z23-lint: write failed\n", "");
    }
    if (fputc('\n', out) == EOF
        || fputs("Do NOT add a new coins_kv_seed_from_node_db caller — the borrow is being\n",
                 out) < 0
        || fputs("DELETED (the self-verified-tip cure). Self-derive the coin set (from the\n",
                 out) < 0
        || fputs("minted anchor snapshot / a from-genesis fold) instead. If a caller is\n",
                 out) < 0
        || fprintf(out,
                   "genuinely unavoidable for now, add its path to %s (last resort).\n",
                   k_nbs_base) < 0)
        return die("z23-lint: write failed\n", "");
    return 0;
}

static int nbs_report_stale(FILE *out, const struct nbs_set *stale)
{
    if (fprintf(out,
                "check_no_new_borrowed_seed: %d STALE baseline entry(ies) (no longer call it):\n",
                stale->count) < 0)
        return die("z23-lint: write failed\n", "");
    for (int i = 0; i < stale->count; i++) {
        if (fprintf(out, "  %s\n", stale->n[i]) < 0)
            return die("z23-lint: write failed\n", "");
    }
    if (fputc('\n', out) == EOF
        || fprintf(out,
                   "A caller was removed — good. Delete its line from %s so the\n",
                   k_nbs_base) < 0
        || fputs("ratchet reflects the smaller set.\n", out) < 0)
        return die("z23-lint: write failed\n", "");
    return 0;
}

static int nbs_scan(FILE *out)
{
    char sym[64];
    nbs_sym(sym, sizeof sym);
    if (!nbs_file_has_sym(k_nbs_def, sym))
        return nbs_hollow(out, sym);
    struct nbs_set base = {0}, callers = {0}, newc = {0}, stale = {0};
    int rc = nbs_load_list(k_nbs_base, &base);
    if (rc)
        return rc;
    struct nbs_acc a = { .sym = sym, .def = k_nbs_def, .callers = &callers };
    rc = nbs_walk_roots(&a);
    if (rc)
        return rc;
    qsort(callers.n, (size_t)callers.count, NBS_PATH, nbs_cmp);
    rc = nbs_collect_new(&callers, &base, &newc);
    if (rc)
        return rc;
    rc = nbs_collect_stale(&base, sym, &stale);
    if (rc)
        return rc;
    if (newc.count == 0 && stale.count == 0)
        return nbs_report_clean(out, base.count);
    if (fputc('\n', out) == EOF)
        return die("z23-lint: write failed\n", "");
    if (newc.count) {
        rc = nbs_report_new(out, &newc);
        if (rc)
            return rc;
    }
    if (stale.count) {
        rc = nbs_report_stale(out, &stale);
        if (rc)
            return rc;
    }
    return 1;
}

int check_no_new_borrowed_seed_run(int argc, char **argv)
{
    if (argc < 1 || !argv[0] || !argv[0][0])
        return nbs_scan(stdout);
    char cwd[4096];
    if (!getcwd(cwd, sizeof cwd))
        return die("z23-lint: getcwd failed\n", "");
    if (chdir(argv[0]) != 0)
        return die("z23-lint: cannot scan %s\n", argv[0]);
    int rc = nbs_scan(stdout);
    if (chdir(cwd) != 0 && rc == 0)
        rc = die("z23-lint: getcwd failed\n", "");
    return rc;
}

static int nbs_st_excl(const char *path, int prod, int want)
{
    const char *old = getenv("ZCL_LINT_PRODUCTION_SCAN");
    char saved[16];
    int had = 0;
    if (old) {
        if (ovf(snprintf(saved, sizeof saved, "%s", old), sizeof saved))
            return 1;
        had = 1;
    }
    int bad = 0;
    if (prod) {
        if (setenv("ZCL_LINT_PRODUCTION_SCAN", "1", 1) != 0)
            bad = 1;
    } else if (unsetenv("ZCL_LINT_PRODUCTION_SCAN") != 0)
        bad = 1;
    if (!bad)
        bad = lint_path_is_excluded(path) != want;
    if (had)
        (void)setenv("ZCL_LINT_PRODUCTION_SCAN", saved, 1);
    else
        (void)unsetenv("ZCL_LINT_PRODUCTION_SCAN");
    return bad;
}

int check_no_new_borrowed_seed_selftest(void)
{
    char sym[64];
    nbs_sym(sym, sizeof sym);
    char hit[128], miss[64];
    int bad = 0;
    if (ovf(snprintf(hit, sizeof hit, "int f%sint x) { return 0; }\n", sym),
            sizeof hit)
        || ovf(snprintf(miss, sizeof miss, "%s", "int g(void) { return 1; }\n"),
               sizeof miss))
        return 1;
    bad |= !nbs_text_has_sym(hit, sym);
    bad |= nbs_text_has_sym(miss, sym);
    static const char *const k_excl[] = {
        "tools/lint/fixtures/planted/x.c",
        "build/x.c",
        "vendor/x.c",
        "test-tmp/x.c",
        "engine/services/src/_xfixture.c"
    };
    for (size_t i = 0; i < sizeof k_excl / sizeof k_excl[0]; i++)
        bad |= nbs_st_excl(k_excl[i], 1, 1) | nbs_st_excl(k_excl[i], 0, 0);
    struct nbs_set base = {0}, callers = {0}, newc = {0}, stale = {0};
    bad |= nbs_add(&base, "in.c") || nbs_add(&base, "gone.c");
    bad |= nbs_add(&callers, "in.c") || nbs_add(&callers, "fresh.c");
    for (int i = 0; i < callers.count; i++) {
        if (!nbs_has(&base, callers.n[i]))
            bad |= nbs_add(&newc, callers.n[i]);
    }
    for (int i = 0; i < base.count; i++) {
        int exists = nbs_has(&callers, base.n[i]);
        if (!exists)
            bad |= nbs_add(&stale, base.n[i]);
    }
    bad |= newc.count != 1 || strcmp(newc.n[0], "fresh.c") != 0;
    bad |= stale.count != 1 || strcmp(stale.n[0], "gone.c") != 0;
    bad |= !nbs_has(&base, "in.c") || nbs_has(&base, "fresh.c");
    return st_ok(bad, "check_no_new_borrowed_seed selftest: OK\n");
}

enum { SBE_MAX = 128, SBE_KEY = 160, SBE_CALL = 96 };
static const char k_sbe_base[] = "tools/lint/silent_bool_errors_baseline.txt";
static const char k_sbe_guard[] = "if \\(![A-Za-z_][A-Za-z0-9_]*\\(";

struct sbe_set { char n[SBE_MAX][SBE_KEY]; int count; };
struct sbe_acc { regex_t *re; struct sbe_set *cur; };

static void sbe_chomp(char *s)
{
    size_t n = strlen(s);
    while (n && (s[n - 1] == '\n' || s[n - 1] == '\r'))
        s[--n] = '\0';
}

static int sbe_has(const struct sbe_set *s, const char *key)
{
    for (int i = 0; i < s->count; i++) {
        if (strcmp(s->n[i], key) == 0)
            return 1;
    }
    return 0;
}

static int sbe_add(struct sbe_set *s, const char *key)
{
    size_t n = strlen(key);
    if (sbe_has(s, key))
        return 0;
    if (s->count >= SBE_MAX || n >= SBE_KEY)
        return die("z23-lint: derived buffer overflow\n", "");
    memcpy(s->n[s->count++], key, n + 1);
    return 0;
}

static int sbe_cmp(const void *a, const void *b)
{
    return strcmp((const char *)a, (const char *)b);
}

static void sbe_sort(struct sbe_set *s)
{
    if (s->count > 1)
        qsort(s->n, (size_t)s->count, SBE_KEY, sbe_cmp);
}

static int sbe_load(struct sbe_set *s, const char *path)
{
    s->count = 0;
    FILE *f = fopen(path, "r");
    if (!f)
        return 0;
    char *line = NULL;
    size_t cap = 0;
    int rc = 0;
    while (rc == 0 && getline(&line, &cap, f) >= 0) {
        char *h = strchr(line, '#'), *p = line;
        if (h)
            *h = '\0';
        while (*p && isspace((unsigned char)*p))
            p++;
        size_t n = strlen(p);
        while (n && isspace((unsigned char)p[n - 1]))
            p[--n] = '\0';
        if (n)
            rc = sbe_add(s, p);
    }
    return fin(f, line, path, rc);
}

static int sbe_split_ws(const char *s, char out[][RS_PATH], int max, int *n)
{
    *n = 0;
    while (*s) {
        while (*s && isspace((unsigned char)*s))
            s++;
        if (!*s)
            break;
        const char *e = s;
        while (*e && !isspace((unsigned char)*e))
            e++;
        size_t len = (size_t)(e - s);
        if (*n >= max || len >= RS_PATH)
            return die("z23-lint: derived buffer overflow\n", "");
        memcpy(out[*n], s, len);
        out[*n][len] = '\0';
        (*n)++;
        s = e;
    }
    return 0;
}

static int sbe_hit_drop(const char *line)
{
    static const char *const tok[] = {
        "LOG_ERR", "LOG_FAIL", "LOG_RETURN", "LOG_WARN", "LOG_NULL", "log_json"
    };
    for (size_t i = 0; i < sizeof tok / sizeof tok[0]; i++) {
        if (strstr(line, tok[i]))
            return 1;
    }
    return strstr(line, "// raw-return-ok:") != NULL
        || strstr(line, "/* raw-return-ok:") != NULL;
}

static int sbe_prev_drop(const char *pl)
{
    return !pl || !pl[0] || strstr(pl, "LOG_") != NULL
        || strstr(pl, "log_json") != NULL
        || strstr(pl, "raw-return-ok:") != NULL;
}

/* Match helpers return 1 for a hit, 0 for no hit, and -1 for an error. */
static int sbe_extract_call(const regex_t *re, const char *pl, char *out, size_t cap)
{
    regmatch_t m;
    if (regexec(re, pl, 1, &m, 0) != 0)
        return 0;
    size_t n = (size_t)(m.rm_eo - m.rm_so);
    if (n < 6)
        return 0;
    const char *span = pl + m.rm_so;
    /* strip leading "if (!" and trailing "(" */
    size_t ident = n - 6;
    if (ident == 0)
        return 0;
    if (ident >= cap)
        return -die("z23-lint: derived buffer overflow\n", "");
    memcpy(out, span + 5, ident);
    out[ident] = '\0';
    return 1;
}

static int sbe_pair_key(const regex_t *re, const char *prev, const char *hit,
                        const char *rel, char *out, size_t cap)
{
    char call[SBE_CALL];
    if (sbe_hit_drop(hit) || sbe_prev_drop(prev))
        return 0;
    int match = sbe_extract_call(re, prev, call, sizeof call);
    if (match <= 0)
        return match;
    if (rel[0] == '.' && rel[1] == '/')
        rel += 2;
    return ovf(snprintf(out, cap, "%s::%s", rel, call), cap) ? -1 : 1;
}

static int sbe_scan_stream(FILE *f, const char *path, struct sbe_acc *a)
{
    char *cur = NULL, *prev = NULL;
    size_t ccap = 0, pcap = 0;
    int have = 0, rc = 0;
    while (rc == 0 && getline(&cur, &ccap, f) >= 0) {
        sbe_chomp(cur);
        if (strstr(cur, "return false;") && have) {
            char key[SBE_KEY];
            int match = sbe_pair_key(a->re, prev, cur, path, key, sizeof key);
            if (match < 0)
                rc = 1;
            else if (match > 0)
                rc = sbe_add(a->cur, key);
        }
        char *tmp = prev;
        size_t tcap = pcap;
        prev = cur;
        pcap = ccap;
        cur = tmp;
        ccap = tcap;
        have = 1;
    }
    free(cur);
    free(prev);
    return rc;
}

static int sbe_on_file(const char *path, void *ctx)
{
    if (lint_path_is_excluded(path))
        return 0;
    FILE *f = fopen(path, "r");
    if (!f)
        return die("z23-lint: cannot open %s\n", path);
    int rc = sbe_scan_stream(f, path, ctx);
    return fin(f, NULL, path, rc);
}

static int sbe_scan_dirs(char dirs[][RS_PATH], int nd, regex_t *re,
                         struct sbe_set *cur)
{
    struct sbe_acc a = { .re = re, .cur = cur };
    int rc = 0;
    for (int i = 0; rc == 0 && i < nd; i++) {
        struct stat st;
        if (stat(dirs[i], &st) != 0 || !S_ISDIR(st.st_mode))
            continue;
        rc = walk_src(dirs[i], 0, sbe_on_file, &a);
    }
    return rc;
}

static int sbe_update(const struct sbe_set *cur)
{
    FILE *f = fopen(k_sbe_base, "w");
    if (!f)
        return die("z23-lint: cannot open %s\n", k_sbe_base);
    int rc = 0;
    if (fputs("# check_silent_bool_errors RATCHET baseline (shrink-only).\n", f) < 0
        || fputs("# Stable key = <relpath>::<guarded_call>. A swallowed call failure:\n",
                 f) < 0
        || fputs("#   if (!call(...)) return false;   with no LOG_* and no // raw-return-ok:\n",
                 f) < 0
        || fputs("# Regenerate after fixing some: ZCL_LINT_MODE=UPDATE ./tools/lint/check_silent_bool_errors.sh\n",
                 f) < 0)
        rc = die("z23-lint: write failed\n", "");
    for (int i = 0; rc == 0 && i < cur->count; i++) {
        if (fprintf(f, "%s\n", cur->n[i]) < 0)
            rc = die("z23-lint: write failed\n", "");
    }
    if (fclose(f) != 0 && rc == 0)
        rc = die("z23-lint: fclose failed: %s\n", k_sbe_base);
    if (rc)
        return rc;
    int n = 0;
    for (int i = 0; i < cur->count; i++) {
        if (strstr(cur->n[i], "::"))
            n++;
    }
    if (printf("check_silent_bool_errors: baseline updated (%d entries)\n", n) < 0)
        return die("z23-lint: write failed\n", "");
    return 0;
}

static int sbe_count_new(const struct sbe_set *cur, const struct sbe_set *base)
{
    int n_new = 0;
    for (int i = 0; i < cur->count; i++) {
        if (strstr(cur->n[i], "::") && !sbe_has(base, cur->n[i]))
            n_new++;
    }
    return n_new;
}

static int sbe_print_new(const struct sbe_set *cur, const struct sbe_set *base)
{
    if (puts("FAIL: new silent call-guard 'return false' (log the failure via LOG_WARN/LOG_FAIL, or mark // raw-return-ok:<reason>):")
        == EOF)
        return die("z23-lint: write failed\n", "");
    for (int i = 0; i < cur->count; i++) {
        if (strstr(cur->n[i], "::") && !sbe_has(base, cur->n[i])
            && puts(cur->n[i]) == EOF)
            return die("z23-lint: write failed\n", "");
    }
    return 1;
}

static void sbe_tally_ok(const struct sbe_set *cur, const struct sbe_set *base,
                         int *n_cur, int *n_base, int *gone)
{
    *n_cur = 0;
    *n_base = 0;
    *gone = 0;
    for (int i = 0; i < cur->count; i++) {
        if (strstr(cur->n[i], "::"))
            (*n_cur)++;
    }
    for (int i = 0; i < base->count; i++) {
        if (strstr(base->n[i], "::")) {
            (*n_base)++;
            if (!sbe_has(cur, base->n[i]))
                (*gone)++;
        }
    }
}

static int sbe_report(const struct sbe_set *cur, const struct sbe_set *base)
{
    int n_new = sbe_count_new(cur, base);
    if (n_new)
        return sbe_print_new(cur, base);
    int n_cur = 0, n_base = 0, gone = 0;
    sbe_tally_ok(cur, base, &n_cur, &n_base, &gone);
    if (printf("  OK: no new silent call-guard return-false (%d tracked; baseline %d)\n",
               n_cur, n_base) < 0)
        return die("z23-lint: write failed\n", "");
    if (gone > 0
        && printf("  (ratchet: %d fixed since baseline — run ZCL_LINT_MODE=UPDATE to shrink)\n",
                  gone) < 0)
        return die("z23-lint: write failed\n", "");
    return 0;
}

int check_silent_errors_bool_run(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    const char *mode = getenv("ZCL_LINT_MODE");
    if (!mode || !mode[0])
        mode = "FAIL";
    regex_t re;
    int rc = compile_pat(&re, REG_EXTENDED, k_sbe_guard, "", "", "");
    if (rc)
        return rc;
    char dirs[RS_MAX][RS_PATH];
    int nd = 0;
    const char *env = getenv("ZCL_SILENT_BOOL_SCAN_DIRS_FOR_TEST");
    if (env && env[0])
        rc = sbe_split_ws(env, dirs, RS_MAX, &nd);
    else
        rc = repo_shape_dirs("app", "src", dirs, RS_MAX, &nd);
    struct sbe_set cur = {0}, base = {0};
    if (rc == 0)
        rc = sbe_scan_dirs(dirs, nd, &re, &cur);
    sbe_sort(&cur);
    if (rc == 0 && strcmp(mode, "UPDATE") == 0) {
        rc = sbe_update(&cur);
        regfree(&re);
        return rc;
    }
    if (rc == 0)
        rc = sbe_load(&base, k_sbe_base);
    sbe_sort(&base);
    if (rc == 0)
        rc = sbe_report(&cur, &base);
    regfree(&re);
    return rc;
}

static int sbe_boundary_scan(regex_t *re, const char *path, const char *call,
                             int overflow, size_t key_len)
{
    FILE *f = tmpfile();
    if (!f)
        return 1;
    if (fprintf(f, "if (!%s())\n    return false;\n", call) < 0
        || fseek(f, 0, SEEK_SET) != 0) {
        fclose(f);
        return 1;
    }
    struct sbe_set cur = {0};
    struct sbe_acc a = { .re = re, .cur = &cur };
    int rc = sbe_scan_stream(f, path, &a);
    int bad = ferror(f) != 0;
    bad |= fclose(f) != 0;
    if (overflow)
        return bad || rc == 0 || cur.count != 0;
    return bad || rc != 0 || cur.count != 1
        || strlen(cur.n[0]) != key_len;
}

static int sbe_boundary_selftest(regex_t *re)
{
    /* The key includes "::ok_call" (9 bytes), plus its terminator. */
    char path[SBE_KEY - 9 + 1];
    memset(path, 'a', sizeof path - 1);
    path[sizeof path - 1] = '\0';
    path[sizeof path - 2] = '\0';
    int bad = sbe_boundary_scan(re, path, "ok_call", 0, 159);
    path[sizeof path - 2] = 'a';
    bad |= sbe_boundary_scan(re, path, "ok_call", 1, 160);
    char call[SBE_CALL + 1];
    memset(call, 'a', sizeof call - 1);
    call[sizeof call - 1] = '\0';
    call[sizeof call - 2] = '\0';
    bad |= sbe_boundary_scan(re, "a.c", call, 0, 100);
    call[sizeof call - 2] = 'a';
    bad |= sbe_boundary_scan(re, "a.c", call, 1, 101);
    return bad;
}

int check_silent_errors_bool_selftest(void)
{
    regex_t re;
    int rc = compile_pat(&re, REG_EXTENDED, k_sbe_guard, "", "", "");
    if (rc)
        return rc;
    int bad = sbe_boundary_selftest(&re);
    bad |= !sbe_hit_drop("        return false; LOG_WARN(\"x\");");
    bad |= !sbe_hit_drop("        return false; // raw-return-ok:reason");
    bad |= sbe_hit_drop("        return false;");
    char call[SBE_CALL], key[SBE_KEY];
    bad |= !sbe_extract_call(&re, "    if (!foo_bar(", call, sizeof call)
        || strcmp(call, "foo_bar") != 0;
    bad |= !sbe_pair_key(&re, "    if (!ok_call(", "        return false;",
                         "engine/jobs/src/x.c", key, sizeof key)
        || strcmp(key, "engine/jobs/src/x.c::ok_call") != 0;
    bad |= sbe_pair_key(&re, "    if (ok)", "        return false;", "a.c",
                        key, sizeof key);
    bad |= sbe_pair_key(&re, "    if (!ok_call() LOG_WARN(\"x\");",
                        "        return false;", "a.c", key, sizeof key);
    struct sbe_set cur = {0}, base = {0};
    bad |= sbe_add(&base, "a.c::keep") || sbe_add(&base, "b.c::gone");
    bad |= sbe_add(&cur, "a.c::keep") || sbe_add(&cur, "c.c::fresh");
    sbe_sort(&cur);
    sbe_sort(&base);
    int n_new = 0, gone = 0, match = 0;
    for (int i = 0; i < cur.count; i++) {
        if (sbe_has(&base, cur.n[i]))
            match++;
        else
            n_new++;
    }
    for (int i = 0; i < base.count; i++) {
        if (!sbe_has(&cur, base.n[i]))
            gone++;
    }
    bad |= match != 1 || n_new != 1 || gone != 1;
    bad |= strcmp(cur.n[1], "c.c::fresh") != 0;
    regfree(&re);
    return st_ok(bad, "check_silent_errors_bool selftest: OK\n");
}

enum { SQL_HIT = 512, SQL_LINE = 768 };
static const char k_sql_base[] =
    "tools/lint/no_raw_sqlite_in_controllers_baseline.txt";
static const char k_sql_re[] =
    "(^|[^[:alnum:]_])sqlite3_prepare_v[23]([^[:alnum:]_]|$)"
    "|(^|[^[:alnum:]_])sqlite3_exec([^[:alnum:]_]|$)";
static const char k_sql_ok[] = "// raw-controller-sql-ok";
static const char k_sql_name[] = "check_no_raw_sqlite_in_controllers";

static int sql_glob(const char *s, const char *p)
{
    if (*p == '\0')
        return *s == '\0';
    if (*p == '*') {
        while (*p == '*')
            p++;
        if (*p == '\0')
            return 1;
        for (; *s; s++) {
            if (sql_glob(s, p))
                return 1;
        }
        return sql_glob(s, p);
    }
    if (*s != '\0' && *s == *p)
        return sql_glob(s + 1, p + 1);
    return 0;
}

static int sql_is_sync(const char *file)
{
    return sql_glob(file, "*/controllers/src/sync_controller*.c")
        || sql_glob(file, "*/controllers/src/sync_controller*.h")
        || sql_glob(file, "*/controllers/include/controllers/sync_controller*.h");
}

static int sql_match_line(const regex_t *re, const char *line)
{
    return regexec(re, line, 0, NULL, 0) == 0;
}

static void sql_feed(const char *pat, size_t *i, int *found, int c)
{
    if (*found)
        return;
    if (c == (unsigned char)pat[*i]) {
        (*i)++;
        if (pat[*i] == '\0')
            *found = 1;
        return;
    }
    if (*i == 0)
        return;
    *i = 0;
    sql_feed(pat, i, found, c);
}

static int sql_receipt_text(const char *text)
{
    static const char k_vi[] = "view_integrity";
    static const char k_sh[] = "sha3_hash";
    static const char k_ht[] = "height=?";
    size_t vi = 0, sh = 0, ht = 0;
    int fvi = 0, fsh = 0, fht = 0;
    for (const unsigned char *p = (const unsigned char *)text; *p; p++) {
        int c = *p;
        if (c == '"' || isspace(c))
            continue;
        if (c >= 'A' && c <= 'Z')
            c += 'a' - 'A';
        sql_feed(k_vi, &vi, &fvi, c);
        sql_feed(k_sh, &sh, &fsh, c);
        sql_feed(k_ht, &ht, &fht, c);
    }
    return fvi && (fsh || fht);
}

static int sql_receipt_file(const char *path, int *hit)
{
    FILE *f = fopen(path, "r");
    if (!f) {
        fprintf(stderr,
                "check_no_raw_sqlite_in_controllers: FATAL — receipt-owner normalization failed for %s\n",
                path);
        return 2;
    }
    static const char k_vi[] = "view_integrity";
    static const char k_sh[] = "sha3_hash";
    static const char k_ht[] = "height=?";
    size_t vi = 0, sh = 0, ht = 0;
    int fvi = 0, fsh = 0, fht = 0, c;
    while ((c = fgetc(f)) != EOF) {
        if (c == '"' || isspace((unsigned char)c))
            continue;
        if (c >= 'A' && c <= 'Z')
            c += 'a' - 'A';
        sql_feed(k_vi, &vi, &fvi, c);
        sql_feed(k_sh, &sh, &fsh, c);
        sql_feed(k_ht, &ht, &fht, c);
    }
    int err = ferror(f);
    if (fclose(f) != 0)
        err = 1;
    if (err) {
        fprintf(stderr,
                "check_no_raw_sqlite_in_controllers: FATAL — receipt-owner normalization failed for %s\n",
                path);
        return 2;
    }
    *hit = fvi && (fsh || fht);
    return 0;
}

static int sql_is_violation(const char *mode, const char *file, const char *line,
                            const struct sr_set *base)
{
    if (sql_is_sync(file))
        return 1;
    if (strstr(line, k_sql_ok))
        return 0;
    if (strcmp(mode, "RATCHET") == 0 && sr_has(base, file))
        return 0;
    return 1;
}

struct sql_scan {
    regex_t *re;
    char hits[SQL_HIT][SQL_LINE];
    int nhits, nfiles, failed;
};

static int sql_on_ctrl(const char *path, void *ctx)
{
    struct sql_scan *a = ctx;
    a->nfiles++;
    if (lint_path_is_excluded(path))
        return 0;
    FILE *f = fopen(path, "r");
    if (!f) {
        fprintf(stderr,
                "check_no_raw_sqlite_in_controllers: FATAL — controller scan failed (grep=2)\n");
        a->failed = 1;
        return 2;
    }
    char *line = NULL;
    size_t cap = 0;
    int lineno = 0, rc = 0;
    while (rc == 0 && getline(&line, &cap, f) >= 0) {
        lineno++;
        if (!sql_match_line(a->re, line))
            continue;
        sbe_chomp(line);
        if (a->nhits >= SQL_HIT)
            rc = die("z23-lint: derived buffer overflow\n", "");
        else if (ovf(snprintf(a->hits[a->nhits], SQL_LINE, "%s:%d:%s", path,
                              lineno, line),
                     SQL_LINE))
            rc = 2;
        else
            a->nhits++;
    }
    return fin(f, line, path, rc);
}

struct sql_ctx {
    char rec[SQL_HIT][SQL_LINE];
    int nrec, nfiles, failed;
};

static int sql_on_ctx(const char *path, void *ctx)
{
    struct sql_ctx *a = ctx;
    a->nfiles++;
    int hit = 0;
    int rc = sql_receipt_file(path, &hit);
    if (rc) {
        a->failed = 1;
        return rc;
    }
    if (!hit)
        return 0;
    if (a->nrec >= SQL_HIT)
        return die("z23-lint: derived buffer overflow\n", "");
    return ovf(snprintf(a->rec[a->nrec++], SQL_LINE,
                        "%s: owns view_integrity storage-column/exact-height knowledge",
                        path),
               SQL_LINE);
}

static int sql_add_root(char out[][RS_PATH], int max, int *n, const char *path)
{
    for (int i = 0; i < *n; i++) {
        if (strcmp(out[i], path) == 0)
            return 0;
    }
    if (*n >= max)
        return die("z23-lint: derived buffer overflow\n", "");
    return ovf(snprintf(out[(*n)++], RS_PATH, "%s", path), RS_PATH);
}

static int sql_walk_roots(char roots[][RS_PATH], int n, int hdrs,
                          int (*fn)(const char *, void *), void *ctx)
{
    int rc = 0;
    for (int i = 0; rc == 0 && i < n; i++)
        rc = walk_src(roots[i], hdrs, fn, ctx);
    return rc;
}

static const char *sql_mode(void)
{
    const char *m = getenv("ZCL_LINT_MODE");
    return (m && m[0]) ? m : "WARN";
}

static int sql_summary(int v, const char *mode)
{
    if (printf("[check_no_raw_sqlite_in_controllers] %d violation(s) found (mode: %s)\n",
               v, mode) < 0
        || puts("[check_no_raw_sqlite_in_controllers] use projection_* or models; sync-controller sources permit no direct prepare/exec exception; view_integrity storage-column knowledge is model-only")
           == EOF)
        return die("z23-lint: write failed\n", "");
    if (strcmp(mode, "RATCHET") == 0
        && puts("[check_no_raw_sqlite_in_controllers] baselined files in tools/lint/no_raw_sqlite_in_controllers_baseline.txt (ratchet may only shrink)")
           == EOF)
        return die("z23-lint: write failed\n", "");
    return 0;
}

static int sql_ctrl_scan(char ctrl[][RS_PATH], int nc, struct sql_scan *scan)
{
    int rc = sql_walk_roots(ctrl, nc, 1, sql_on_ctrl, scan);
    if (rc || scan->failed) {
        if (scan->failed)
            return 2;
        fprintf(stderr,
                "check_no_raw_sqlite_in_controllers: FATAL — source enumeration failed (find=%d)\n",
                rc);
        return 2;
    }
    return gate_require_scanned(scan->nfiles, 1, k_sql_name,
                                "expected controller C/header sources");
}

static int sql_ctx_scan(char ctrl[][RS_PATH], int nc, char svc[][RS_PATH], int ns,
                        struct sql_ctx *cacc)
{
    char ctxr[RS_MAX][RS_PATH];
    int nctx = 0;
    int rc = 0;
    for (int i = 0; rc == 0 && i < nc; i++)
        rc = sql_add_root(ctxr, RS_MAX, &nctx, ctrl[i]);
    for (int i = 0; rc == 0 && i < ns; i++)
        rc = sql_add_root(ctxr, RS_MAX, &nctx, svc[i]);
    if (rc == 0 && nctx > 1)
        qsort(ctxr, (size_t)nctx, RS_PATH, nbs_cmp);
    if (rc == 0)
        rc = sql_walk_roots(ctxr, nctx, 1, sql_on_ctx, cacc);
    if (rc || cacc->failed) {
        if (!cacc->failed)
            fprintf(stderr,
                    "check_no_raw_sqlite_in_controllers: FATAL — context enumeration failed (find=%d)\n",
                    rc);
        return 2;
    }
    return gate_require_scanned(cacc->nfiles, 2,
                                "check_no_raw_sqlite_in_controllers.receipt_owner",
                                "expected controller and service C/header sources");
}

static int sql_emit_hits(const char *mode, const struct sql_scan *scan,
                         const struct sr_set *base, int *violations)
{
    int rc = 0;
    for (int i = 0; rc == 0 && i < scan->nhits; i++) {
        const char *line = scan->hits[i];
        char file[RS_PATH];
        const char *colon = strchr(line, ':');
        size_t fl = colon ? (size_t)(colon - line) : strlen(line);
        if (fl >= sizeof file) {
            rc = die("z23-lint: derived buffer overflow\n", "");
            break;
        }
        memcpy(file, line, fl);
        file[fl] = '\0';
        if (!sql_is_violation(mode, file, line, base))
            continue;
        (*violations)++;
        if (fprintf(stderr, "%s\n", line) < 0)
            rc = die("z23-lint: write failed\n", "");
    }
    return rc;
}

static int sql_emit_receipts(const struct sql_ctx *cacc, int *violations)
{
    int rc = 0;
    for (int i = 0; rc == 0 && i < cacc->nrec; i++) {
        (*violations)++;
        if (fprintf(stderr, "%s\n", cacc->rec[i]) < 0)
            rc = die("z23-lint: write failed\n", "");
    }
    return rc;
}

static int sql_grade(int rc, int violations, const char *mode)
{
    if (rc)
        return rc;
    if (violations > 0 && (strcmp(mode, "FAIL") == 0 || strcmp(mode, "RATCHET") == 0))
        return 1;
    return 0;
}

int check_no_raw_sqlite_in_controllers_run(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    const char *mode = sql_mode();
    char ctrl[RS_MAX][RS_PATH], svc[RS_MAX][RS_PATH];
    int nc = 0, ns = 0;
    int rc = repo_shape_room_dirs("controllers", ctrl, RS_MAX, &nc);
    if (rc)
        return rc;
    regex_t re;
    rc = compile_pat(&re, REG_EXTENDED, k_sql_re, "", "", "");
    if (rc)
        return rc;
    struct sql_scan scan = { .re = &re };
    rc = sql_ctrl_scan(ctrl, nc, &scan);
    if (rc) {
        regfree(&re);
        return rc;
    }
    rc = repo_shape_room_dirs("services", svc, RS_MAX, &ns);
    if (rc) {
        regfree(&re);
        return rc;
    }
    struct sql_ctx cacc = {0};
    rc = sql_ctx_scan(ctrl, nc, svc, ns, &cacc);
    if (rc) {
        regfree(&re);
        return rc;
    }
    struct sr_set base = {0};
    rc = sr_load(&base, k_sql_base);
    int violations = 0;
    if (rc == 0)
        rc = sql_emit_hits(mode, &scan, &base, &violations);
    if (rc == 0)
        rc = sql_emit_receipts(&cacc, &violations);
    if (rc == 0)
        rc = sql_summary(violations, mode);
    regfree(&re);
    return sql_grade(rc, violations, mode);
}

int check_no_raw_sqlite_in_controllers_selftest(void)
{
    regex_t re;
    int rc = compile_pat(&re, REG_EXTENDED, k_sql_re, "", "", "");
    if (rc)
        return rc;
    const char *t = "check_no_raw_sqlite_in_controllers";
    int bad = want(t, &re, "sqlite3_prepare_v2(db, sql, -1, &st, 0);", 1)
            | want(t, &re, "sqlite3_prepare_v3(db, sql, -1, 0, &st, 0);", 1)
            | want(t, &re, "sqlite3_exec(db, sql, 0, 0, 0);", 1)
            | want(t, &re, "my_sqlite3_execute(db);", 0)
            | want(t, &re, "int sqlite3_exec_count;", 0);
    bad |= !sql_is_sync("engine/controllers/src/sync_controller.c");
    bad |= !sql_is_sync("engine/controllers/src/sync_controller_e10.c");
    bad |= !sql_is_sync(
        "engine/controllers/include/controllers/sync_controller.h");
    bad |= sql_is_sync("engine/services/src/sync_controller.c");
    bad |= sql_is_sync("engine/controllers/src/wallet_controller.c");
    bad |= !sql_receipt_text("SELECT sha3_hash FROM view_integrity;");
    bad |= !sql_receipt_text("SELECT * FROM view_\" \"integrity WHERE height = ?;");
    bad |= sql_receipt_text("mentions view_integrity only");
    struct sr_set base = {0};
    bad |= sr_add(&base, "engine/controllers/src/old.c");
    bad |= sql_is_violation("RATCHET", "engine/controllers/src/old.c",
                            "sqlite3_exec(db, sql, 0, 0, 0);", &base) != 0;
    bad |= sql_is_violation("RATCHET", "engine/controllers/src/new.c",
                            "sqlite3_exec(db, sql, 0, 0, 0);", &base) != 1;
    bad |= sql_is_violation("RATCHET", "engine/controllers/src/new.c",
                            "sqlite3_exec(db, sql, 0, 0, 0); // raw-controller-sql-ok",
                            &base) != 0;
    bad |= sql_is_violation("RATCHET",
                            "engine/controllers/src/sync_controller.c",
                            "sqlite3_exec(db, sql, 0, 0, 0); // raw-controller-sql-ok",
                            &base) != 1;
    regfree(&re);
    return st_ok(bad, "check_no_raw_sqlite_in_controllers selftest: OK\n");
}

static const char *const k_op_tops[] = {
    "core", "engine", "contexts", "cognition", "platform", "tools", "tests"
};
static const char k_op_ls[] = "git ls-files -z -- '*.c' '*.h'";
static const char k_op_base[] = "tools/lint/orphan_placement_baseline.txt";
static const char k_op_msg[] =
    "%s: orphan placement — resolves to the catch-all 'root' group; move it under a known top "
    "(lib/<mod>, app/<shape>, core, config, tools, domain, adapters, ports)\n";

static int op_excluded(const char *f)
{
    static const char *const pfx[] = {
        "apps/", "vendor/", "build/", "tests/harness/fixtures/",
        "contexts/commons/packages/"
    };
    for (size_t i = 0; i < sizeof pfx / sizeof pfx[0]; i++)
        if (!strncmp(f, pfx[i], strlen(pfx[i])))
            return 1;
    const char *b = strrchr(f, '/');
    b = b ? b + 1 : f;
    return *b == '_';
}

static int op_placed(const char *f)
{
    for (size_t i = 0; i < sizeof k_op_tops / sizeof k_op_tops[0]; i++) {
        size_t n = strlen(k_op_tops[i]);
        if (!strncmp(f, k_op_tops[i], n) && f[n] == '/')
            return 1;
    }
    return 0;
}

static int op_allow(const char *mode, const struct sr_set *base, const char *f)
{
    return strcmp(mode, "FAIL") != 0 && sr_has(base, f);
}

static const char *op_mode(void)
{
    const char *m = getenv("ZCL_LINT_MODE");
    return (m && m[0]) ? m : "WARN";
}

struct op_acc {
    const char *mode;
    const struct sr_set *base;
    int scanned, considered, violations, allowlisted;
};

static int op_one(struct op_acc *a, const char *f)
{
    a->scanned++;
    if (op_excluded(f))
        return 0;
    a->considered++;
    if (op_placed(f))
        return 0;
    if (op_allow(a->mode, a->base, f)) {
        a->allowlisted++;
        return 0;
    }
    a->violations++;
    return fprintf(stderr, k_op_msg, f) < 0 ? die("z23-lint: write failed\n", "") : 0;
}

static int op_on_path(const char *path, void *ctx)
{
    return op_one(ctx, path);
}

static int op_env(struct op_acc *a, const char *env)
{
    const char *p = env;
    while (*p) {
        while (*p == ' ' || *p == '\t' || *p == '\n')
            p++;
        if (!*p)
            break;
        const char *s = p;
        while (*p && *p != ' ' && *p != '\t' && *p != '\n')
            p++;
        size_t n = (size_t)(p - s);
        char path[4096];
        if (n >= sizeof path)
            return die("z23-lint: path too long: %s\n", "ZCL_ORPHAN_PLACEMENT_FILES");
        memcpy(path, s, n);
        path[n] = '\0';
        int rc = op_one(a, path);
        if (rc)
            return rc;
    }
    return 0;
}

static int op_report(const struct op_acc *a)
{
    if (printf("[check_no_orphan_placement] scanned %d tracked source(s), considered %d after excludes\n",
               a->scanned, a->considered) < 0
        || printf("[check_no_orphan_placement] %d violation(s) found (mode: %s)\n",
                  a->violations, a->mode) < 0)
        return die("z23-lint: write failed\n", "");
    if (a->allowlisted > 0
        && printf("[check_no_orphan_placement] %d allowlisted violation(s) ignored\n",
                  a->allowlisted) < 0)
        return die("z23-lint: write failed\n", "");
    if (a->violations > 0
        && puts("[check_no_orphan_placement] give the file an obvious home, or (shrink-only) write to tools/lint/orphan_placement_baseline.txt")
           == EOF)
        return die("z23-lint: write failed\n", "");
    return 0;
}

int check_no_orphan_placement_run(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    struct sr_set base = {0};
    int rc = sr_load(&base, k_op_base);
    if (rc)
        return rc;
    struct op_acc a = { .mode = op_mode(), .base = &base };
    const char *env = getenv("ZCL_ORPHAN_PLACEMENT_FILES");
    int floor = 1500;
    if (env && env[0]) {
        floor = 1;
        rc = op_env(&a, env);
    } else {
        rc = each_zpath(k_op_ls, op_on_path, &a);
    }
    if (rc)
        return rc;
    rc = gate_require_scanned(a.scanned, floor, "check-no-orphan-placement",
                              "git ls-files returned too few .c/.h — run from repo root inside the worktree?");
    if (rc)
        return rc;
    rc = op_report(&a);
    if (rc)
        return rc;
    if (a.violations > 0
        && (strcmp(a.mode, "FAIL") == 0 || strcmp(a.mode, "RATCHET") == 0))
        return 1;
    return 0;
}

int check_no_orphan_placement_selftest(void)
{
    int bad = 0;
    bad |= !op_excluded("apps/x.c");
    bad |= !op_excluded("vendor/x.c");
    bad |= !op_excluded("build/x.c");
    bad |= !op_excluded("tests/harness/fixtures/x.c");
    bad |= !op_excluded("contexts/commons/packages/x.c");
    bad |= !op_excluded("core/src/_hidden.c");
    bad |= op_excluded("core/modules/util/src/placed.c");
    for (size_t i = 0; i < sizeof k_op_tops / sizeof k_op_tops[0]; i++) {
        char p[80];
        if (snprintf(p, sizeof p, "%s/foo.c", k_op_tops[i]) >= (int)sizeof p)
            bad = 1;
        else
            bad |= !op_placed(p);
    }
    bad |= op_placed("docs/examples/01_mint_and_spend.c");
    struct sr_set base = {0};
    bad |= sr_add(&base, "orphan.c");
    bad |= !op_allow("WARN", &base, "orphan.c");
    bad |= !op_allow("RATCHET", &base, "orphan.c");
    bad |= op_allow("FAIL", &base, "orphan.c");
    return st_ok(bad, "check_no_orphan_placement selftest: OK\n");
}
