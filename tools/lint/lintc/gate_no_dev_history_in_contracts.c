/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: gate — check-no-dev-history-in-contracts (replaces
 * tools/scripts/check_no_dev_history_in_contracts.sh). No .h header under
 * an include dir, and no .def table, may carry stale dev-history
 * phrasing ("STEP-0 STATUS", "stub bodies"/"stub body", "lane <N><letter>",
 * "future slice") once the real body has landed — an agent or operator
 * trusts a header over the .c body and concludes shipped work is still
 * unimplemented. HARD gate with an independent git-index coverage floor
 * (ZCL_NDH_SCAN_ROOT, ZCL_NDH_COVERAGE_ALLOWANCE seams), no baseline.
 * Split 2026-09-07 out of gate_narrative_integrity_fences.c (pure move,
 * no code change) — see check-no-uncited-victory in the sibling file
 * gate_no_uncited_victory.c for the paired narrative-integrity gate this
 * file used to share a translation unit with.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <dirent.h>
#include <errno.h>
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "lintc.h"
enum { NI_MAX = 4096, NI_PATH = 512, NI_VMAX = 256, NI_VLINE = 1024 };
static const char k_ndh[] = "check-no-dev-history-in-contracts";
static const char k_ndh_hint[] =
    "no in-scope *.h (**/include/**) or *.def file found -- was a dir renamed/moved?";
static const char k_ndh_cov_hint[] =
    "Re-run from a clean checkout. If a listed file genuinely left this "
    "gate's scope, move it under an allowlisted path (docs/, vendor/, a "
    "test/tests component, a *_test.* name) — raising "
    "ZCL_NDH_COVERAGE_ALLOWANCE is a last resort and needs the reason "
    "written down.";
static const char k_ndh_specs[] = "*/include/*.h include/*.h *.def";
static const char k_ndh_lane[] = "lane [0-9][A-Z]?";
static const char *const k_ndh_fix[] = {
    "STEP-0 STATUS", "stub bodies", "stub body", NULL, "future slice"
};
static char g_ndh_pool[NI_MAX][NI_PATH], g_ndh_exp[NI_MAX][NI_PATH];
static char g_ndh_miss[20][NI_PATH], g_ndh_badext[5];
static int g_ndh_n, g_ndh_ne;
static int ni_row_cmp(const void *a, const void *b)
{ return strcmp(a, b); }
static const char *ni_base(const char *p)
{ const char *s = strrchr(p, '/'); return s ? s + 1 : p; }
static int ni_has_comp(const char *p, const char *w)
{
    size_t wl = strlen(w);
    for (const char *s = p; *s; ) {
        const char *sl = strchr(s, '/');
        size_t n = sl ? (size_t)(sl - s) : strlen(s);
        if (n == wl && memcmp(s, w, wl) == 0) return 1;
        if (!sl) break;
        s = sl + 1;
    }
    return 0;
}
static int ni_allow(const char *p)
{
    if (strncmp(p, "docs/", 5) == 0 || strstr(p, "/docs/") != NULL) return 1;
    if (strncmp(p, "vendor/", 7) == 0 || strstr(p, "/vendor/") != NULL) return 1;
    if (ni_has_comp(p, "test") || ni_has_comp(p, "tests")) return 1;
    return strstr(ni_base(p), "_test.") != NULL;
}
static int ni_prod_skip(const char *rel)
{
    size_t pl = strlen(k_planted);
    if (!lint_prod_scan()) return 0;
    if (strcmp(rel, k_planted) == 0
        || (strncmp(rel, k_planted, pl) == 0 && rel[pl] == '/'))
        return 1;
    return ni_has_comp(rel, "build") || ni_has_comp(rel, "vendor")
        || ni_has_comp(rel, ".claude") || ni_has_comp(rel, "test-tmp");
}
static int ni_is_h(const char *rel)
{ size_t n = strlen(rel); return n >= 2 && rel[n - 2] == '.' && rel[n - 1] == 'h' && (strncmp(rel, "include/", 8) == 0 || strstr(rel, "/include/") != NULL); }
static int ni_is_def(const char *rel)
{ size_t n = strlen(rel); return n >= 4 && memcmp(rel + n - 4, ".def", 4) == 0; }
static int ndh_add(const char *rel)
{ return g_ndh_n >= NI_MAX ? die("z23-lint: scan-set overflow\n", "") : ovf(snprintf(g_ndh_pool[g_ndh_n++], NI_PATH, "%s", rel), NI_PATH); }
static int ndh_join(char *dst, size_t cap, const char *dir, const char *name)
{
    size_t n = strlen(dir);
    if (n == 0 || (n == 1 && dir[0] == '.'))
        return ovf(snprintf(dst, cap, "%s", name), cap);
    if (n > 0 && dir[n - 1] == '/')
        return ovf(snprintf(dst, cap, "%s%s", dir, name), cap);
    return ovf(snprintf(dst, cap, "%s/%s", dir, name), cap);
}
static int ndh_walk(const char *phys, const char *rel);
static int ndh_entry(const char *phys, const char *rel, const char *nm)
{
    char p2[4096], r2[NI_PATH];
    if (ndh_join(p2, sizeof p2, phys, nm) || ndh_join(r2, sizeof r2, rel, nm))
        return 2;
    if (ni_prod_skip(r2)) return 0;
    struct stat st;
    if (lstat(p2, &st) != 0) return die("z23-lint: cannot stat %s\n", p2);
    if (S_ISDIR(st.st_mode)) return ndh_walk(p2, r2);
    if (!S_ISREG(st.st_mode)) return 0;
    if (lint_path_is_excluded(r2) || ni_allow(r2)) return 0;
    return (ni_is_h(r2) || ni_is_def(r2)) ? ndh_add(r2) : 0;
}
static int ndh_walk(const char *phys, const char *rel)
{
    struct dirent **names = NULL;
    int n = scandir(phys, &names, NULL, alphasort);
    if (n < 0)
        return errno == ENOENT ? 0 : die("z23-lint: cannot scan %s\n", phys);
    int rc = 0;
    for (int i = 0; i < n; i++) {
        const char *nm = names[i]->d_name;
        if (rc == 0 && strcmp(nm, ".") != 0 && strcmp(nm, "..") != 0)
            rc = ndh_entry(phys, rel, nm);
        free(names[i]);
    }
    free(names);
    return rc;
}
static int ndh_oracle_match(const char *path)
{
    size_t n = strlen(path);
    if (n >= 4 && memcmp(path + n - 4, ".def", 4) == 0) return 1;
    if (n < 2 || memcmp(path + n - 2, ".h", 2) != 0) return 0;
    return strncmp(path, "include/", 8) == 0 || strstr(path, "/include/") != NULL;
}
static int ndh_oracle_add(const char *path, int stage, void *ctx)
{
    (void)stage; (void)ctx;
    if (!ndh_oracle_match(path) || ni_allow(path)) return 0;
    if (g_ndh_ne >= NI_MAX) return die("z23-lint: scan-set overflow\n", "");
    return ovf(snprintf(g_ndh_exp[g_ndh_ne++], NI_PATH, "%s", path), NI_PATH);
}
static int ndh_uniq_rows(char rows[][NI_PATH], int n)
{
    if (n <= 1) return n;
    qsort(rows, (size_t)n, NI_PATH, ni_row_cmp);
    int w = 1;
    for (int i = 1; i < n; i++)
        if (strcmp(rows[i], rows[w - 1]) != 0) {
            if (w != i) memcpy(rows[w], rows[i], NI_PATH);
            w++;
        }
    return w;
}
static int ndh_cov_partial(int nact, int nexp, int nmiss, const char *allow)
{
    fprintf(stderr, "%s: UNPROVEN — the scan reached %d of the %d\n"
            "  entries an independent oracle says it should have reached;\n"
            "  %d missing, above the shrink-only allowance of\n"
            "  %s recorded in ZCL_NDH_COVERAGE_ALLOWANCE.\n"
            "  This is a PARTIAL scan: not a clean one, and not a violating\n"
            "  one. 'I scanned less than my subject' is a third answer — the\n"
            "  gate never ran over the code it claims to cover, so it cannot\n"
            "  report either verdict. A file-count floor cannot see this;\n"
            "  the count stayed large.\n  Not reached (first 20 of %d):\n",
            k_ndh, nact, nexp, nmiss, allow, nmiss);
    int show = nmiss < 20 ? nmiss : 20;
    for (int i = 0; i < show; i++) fprintf(stderr, "    %s\n", g_ndh_miss[i]);
    if (nmiss > 20) fprintf(stderr, "    ... and %d more\n", nmiss - 20);
    fprintf(stderr, "  %s\n", k_ndh_cov_hint);
    return 2;
}
static int ndh_cov_stale(int nexp, int nmiss, const char *allow)
{
    fprintf(stderr, "%s: VIOLATION — the coverage allowance is stale: the "
            "scan now\n  misses only %d of %d expected entries, below\n"
            "  ZCL_NDH_COVERAGE_ALLOWANCE=%s.\n"
            "  Coverage improved without lowering the allowance. An allowance\n"
            "  that may only ever rise stops meaning 'what we measured' and\n"
            "  starts meaning 'whatever nobody lowered' — a ratchet that\n"
            "  rusts shut. Lower ZCL_NDH_COVERAGE_ALLOWANCE to %d, with "
            "the reason, in the\n  same commit.\n",
            k_ndh, nmiss, nexp, allow, nmiss);
    return 1;
}
static int ndh_missing(int nact, int nexp)
{
    int i = 0, j = 0, m = 0, stored = 0;
    while (j < nexp) {
        int c = i < nact ? strcmp(g_ndh_exp[j], g_ndh_pool[i]) : -1;
        if (i < nact && c > 0) { i++; continue; }
        if (c == 0) { i++; j++; continue; }
        if (stored < 20
            && ovf(snprintf(g_ndh_miss[stored], NI_PATH, "%s", g_ndh_exp[j]),
                   NI_PATH))
            return 2;
        if (stored < 20) stored++;
        m++; j++;
    }
    return m;
}
static int ndh_coverage(void)
{
    (void)lint_prod_scan();
    g_ndh_ne = 0;
    g_ndh_badext[0] = '\0';
    int rc = lint_git_index_foreach(ndh_oracle_add, NULL, g_ndh_badext);
    if (rc) {
        fprintf(stderr, "%s: UNPROVEN — the coverage oracle could not run:\n"
                "  'git ls-files -- %s' exited %d.\n"
                "  Without an independent expectation this gate cannot tell a\n"
                "  complete scan from a partial one, so it refuses to grade\n"
                "  either way. Run it from inside the checkout.\n",
                k_ndh, k_ndh_specs, 128);
        return 2;
    }
    g_ndh_ne = ndh_uniq_rows(g_ndh_exp, g_ndh_ne);
    if (g_ndh_ne == 0) {
        fprintf(stderr, "%s: UNPROVEN — the coverage oracle is empty: git "
                "tracks no\n  file matching: %s\n"
                "  An empty expectation would pass every scan, including a "
                "scan\n  of nothing. Refusing to vouch for coverage off a "
                "hollow\n  oracle. Fix the pathspec, or drop the coverage "
                "check if the\n  set is genuinely gone.\n", k_ndh, k_ndh_specs);
        return 2;
    }
    int nact = ndh_uniq_rows(g_ndh_pool, g_ndh_n);
    g_ndh_n = nact;
    int nmiss = ndh_missing(nact, g_ndh_ne);
    if (nmiss < 0) return 2;
    const char *allow = env_or("ZCL_NDH_COVERAGE_ALLOWANCE", "0");
    char *end = NULL;
    errno = 0;
    long al = strtol(allow, &end, 10);
    if (errno == ERANGE || end == allow || (end && *end))
        return die("z23-lint: bad ZCL_NDH_COVERAGE_ALLOWANCE\n", "");
    if ((long)nmiss > al) return ndh_cov_partial(nact, g_ndh_ne, nmiss, allow);
    if ((long)nmiss < al) return ndh_cov_stale(g_ndh_ne, nmiss, allow);
    return 0;
}
static int ndh_scan_phrase(const char *path, FILE *f, const char *pat, int ere,
                           regex_t *re, char v[][NI_VLINE], int *nv)
{
    if (fseek(f, 0, SEEK_SET) != 0) return die("z23-lint: fseek failed\n", "");
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    int lineno = 0, rc = 0;
    while (rc == 0 && (n = getline(&line, &cap, f)) >= 0) {
        lineno++;
        while (n > 0 && (line[n - 1] == '\n' || line[n - 1] == '\r'))
            line[--n] = '\0';
        int hit = ere ? (regexec(re, line, 0, NULL, 0) == 0)
                      : (strstr(line, pat) != NULL);
        if (!hit) continue;
        if (*nv >= NI_VMAX) { rc = die("z23-lint: scan-set overflow\n", ""); break; }
        int k = snprintf(v[*nv], NI_VLINE, "%s:%d:%s  [/%s/]", path, lineno, line, pat);
        if (ovf(k, NI_VLINE)) { rc = 2; break; }
        (*nv)++;
    }
    int err = ferror(f);
    free(line);
    if (rc) return rc;
    return err ? die("z23-lint: cannot open %s\n", path) : 0;
}
static int ndh_scan_file(const char *path, regex_t *lane, char v[][NI_VLINE], int *nv)
{
    FILE *f = fopen(path, "r");
    if (!f) return die("z23-lint: cannot open %s\n", path);
    int rc = 0;
    for (int p = 0; rc == 0 && p < 5; p++) {
        int ere = (p == 3);
        rc = ndh_scan_phrase(path, f, ere ? k_ndh_lane : k_ndh_fix[p], ere, lane, v, nv);
    }
    fclose(f);
    return rc;
}
static int ndh_scan_body(void)
{
    (void)lint_prod_scan();
    g_ndh_n = 0;
    const char *root = env_or("ZCL_NDH_SCAN_ROOT", ".");
    const char *rel0 = (strcmp(root, ".") == 0 || strcmp(root, "./") == 0) ? "" : root;
    int rc = ndh_walk(root, rel0);
    if (rc) return rc;
    qsort(g_ndh_pool, (size_t)g_ndh_n, NI_PATH, ni_row_cmp);
    rc = gate_require_scanned(g_ndh_n, 1, k_ndh, k_ndh_hint);
    if (rc) return rc;
    if (strcmp(env_or("ZCL_NDH_COVERAGE", "1"), "1") == 0) {
        rc = ndh_coverage();
        if (rc) return rc;
    }
    if (strcmp(env_or("ZCL_NDH_COVERAGE_ONLY", "0"), "1") == 0) {
        printf("%s: coverage-only PASS (%d in-scope file(s) reached)\n", k_ndh, g_ndh_n);
        return 0;
    }
    regex_t lane;
    rc = reg_fail(&lane, regcomp(&lane, k_ndh_lane, REG_EXTENDED | REG_NOSUB));
    if (rc) return rc;
    char v[NI_VMAX][NI_VLINE];
    int nv = 0;
    for (int i = 0; rc == 0 && i < g_ndh_n; i++)
        rc = ndh_scan_file(g_ndh_pool[i], &lane, v, &nv);
    regfree(&lane);
    if (rc) return rc;
    if (nv > 0) {
        printf("%s: FAIL — dev-history phrasing in %d production contract line(s)\n\n",
               k_ndh, nv);
        for (int i = 0; i < nv; i++) printf("  %s\n", v[i]);
        fputs("\nDev-history phrasing (\"STEP-0 STATUS\", \"stub bod(y|ies)\", "
              "\"lane <N><letter>\",\n\"future slice\") is INCORRECT MODEL CONTEXT "
              "once the real work has landed —\nan agent or operator reading the "
              "header trusts it over the .c body. Rewrite\nthe comment to describe "
              "the CURRENT contract plus any remaining invariant,\nwithout lane "
              "numbers / STEP-N status / 'future slice' phrasing. Dated\nnarrative "
              "belongs in git history or docs/work/*, never in a production\n"
              "header or .def table.\n", stdout);
        return 1;
    }
    printf("%s: clean — %d in-scope file(s) (*.h under **/include/**, *.def), "
           "no dev-history phrasing\n", k_ndh, g_ndh_n);
    return 0;
}
static int ni_quiet(int (*fn)(void), int *code)
{
    FILE *t = tmpfile();
    if (!t) return die("z23-lint: tmpfile failed\n", "");
    fflush(stdout); fflush(stderr);
    int fd = fileno(t);
    int ou = dup(STDOUT_FILENO), eu = dup(STDERR_FILENO);
    if (ou < 0 || eu < 0 || dup2(fd, STDOUT_FILENO) < 0 || dup2(fd, STDERR_FILENO) < 0)
        return die("z23-lint: dup2 failed\n", "");
    *code = fn();
    fflush(stdout); fflush(stderr);
    if (dup2(ou, STDOUT_FILENO) < 0 || dup2(eu, STDERR_FILENO) < 0)
        return die("z23-lint: dup2 failed\n", "");
    close(ou); close(eu); fclose(t);
    return 0;
}
struct ni_snap { char val[4096]; int set; };
static const char *const k_ndh_vars[] = {
    "ZCL_LINT_PRODUCTION_SCAN", "ZCL_NDH_COVERAGE_ONLY", "ZCL_NDH_SCAN_ROOT",
    "ZCL_NDH_COVERAGE_ALLOWANCE", "ZCL_NDH_COVERAGE"
};
enum { NDH_NVARS = (int)(sizeof k_ndh_vars / sizeof k_ndh_vars[0]) };
static int ni_snap_save(struct ni_snap *s)
{
    for (int i = 0; i < NDH_NVARS; i++) {
        const char *e = getenv(k_ndh_vars[i]);
        s[i].set = e != NULL;
        if (e && ovf(snprintf(s[i].val, sizeof s[i].val, "%s", e), sizeof s[i].val))
            return 2;
    }
    return 0;
}
static int ni_snap_restore(struct ni_snap *s)
{
    for (int i = 0; i < NDH_NVARS; i++) {
        int rc = s[i].set ? setenv(k_ndh_vars[i], s[i].val, 1) : unsetenv(k_ndh_vars[i]);
        if (rc != 0) return die("z23-lint: setenv failed\n", "");
    }
    return 0;
}
static int ni_apply(const char *const *assigns)
{
    for (; *assigns; assigns++) {
        char buf[4096];
        if (ovf(snprintf(buf, sizeof buf, "%s", *assigns), sizeof buf)) return 2;
        char *eq = strchr(buf, '=');
        if (!eq) return die("z23-lint: setenv failed\n", "");
        *eq = '\0';
        if (setenv(buf, eq + 1, 1) != 0) return die("z23-lint: setenv failed\n", "");
    }
    return 0;
}
static int ndh_cov_case(int want, const char *msg, const char *const *assigns,
                        struct ni_snap *snap)
{
    int rc = ni_snap_restore(snap);
    if (rc == 0) rc = ni_apply(assigns);
    int code = 0;
    if (rc == 0) rc = ni_quiet(ndh_scan_body, &code);
    if (rc) return rc;
    if (code != want) {
        fprintf(stderr, "%s: SELFTEST FAILED — %s (wanted exit %d, got %d)\n",
                k_ndh, msg, want, code);
        return 2;
    }
    return 0;
}
static int ndh_cov_selftest(void)
{
    static const char *const c1[] = {
        "ZCL_LINT_PRODUCTION_SCAN=1", "ZCL_NDH_COVERAGE_ONLY=1", NULL
    };
    static const char *const c2[] = {
        "ZCL_LINT_PRODUCTION_SCAN=1", "ZCL_NDH_COVERAGE_ONLY=1",
        "ZCL_NDH_SCAN_ROOT=lib", NULL
    };
    static const char *const c3[] = {
        "ZCL_LINT_PRODUCTION_SCAN=1", "ZCL_NDH_COVERAGE_ONLY=1",
        "ZCL_NDH_COVERAGE_ALLOWANCE=1", NULL
    };
    struct ni_snap snap[NDH_NVARS];
    int rc = ni_snap_save(snap);
    if (rc == 0)
        rc = ndh_cov_case(0, "the complete scan did not pass its coverage expectation",
                          c1, snap);
    if (rc == 0)
        rc = ndh_cov_case(2, "a scan narrowed to one subtree was not UNPROVEN", c2, snap);
    if (rc == 0)
        rc = ndh_cov_case(1, "an allowance above the true shortfall was silently tolerated",
                          c3, snap);
    int rest = ni_snap_restore(snap);
    if (rc == 0) rc = rest;
    if (rc == 0)
        fputs("[check-no-dev-history-in-contracts] SELFTEST PASS (a full scan "
              "passes coverage, a scan narrowed to one subtree is UNPROVEN "
              "exit 2, and an allowance above the true shortfall is a "
              "stale-ratchet exit 1)\n", stdout);
    return rc;
}
static int ndh_st_one(const char *root, const char *body, int want)
{
    char path[4096], scan[4096];
    if (ovf(snprintf(path, sizeof path, "%s/include/x.h", root), sizeof path)) return 2;
    int rc = csr_write(path, body);
    if (rc) return rc;
    if (ovf(snprintf(scan, sizeof scan, "ZCL_NDH_SCAN_ROOT=%s", root), sizeof scan))
        return 2;
    const char *as2[] = { "ZCL_NDH_COVERAGE=0", "ZCL_LINT_PRODUCTION_SCAN=0", scan, NULL };
    struct ni_snap snap[NDH_NVARS];
    rc = ni_snap_save(snap);
    if (rc == 0) rc = ni_apply(as2);
    int code = 0;
    if (rc == 0) rc = ni_quiet(ndh_scan_body, &code);
    int rest = ni_snap_restore(snap);
    if (rc == 0) rc = rest;
    return rc ? rc : (code == want ? 0 : 1);
}
static int ndh_st_planted(void)
{
    if (csr_mkdirs("test-tmp")) return 2;
    char tmpl[] = "test-tmp/ndh_st.XXXXXX";
    char *tmp = mkdtemp(tmpl);
    if (!tmp) return die("z23-lint: mkdir failed: %s\n", "test-tmp");
    int bad = ndh_st_one(tmp, "/* STEP-0 STATUS: contract + stub bodies */\n", 1);
    bad |= ndh_st_one(tmp, "/* current contract: real body */\n", 0);
    (void)rap_rm_rf(tmp);
    return bad ? 1 : 0;
}
int check_no_dev_history_in_contracts_run(int argc, char **argv)
{
    if (argc >= 1 && argv[0] && strcmp(argv[0], "--selftest") == 0)
        return ndh_cov_selftest();
    return ndh_scan_body();
}
int check_no_dev_history_in_contracts_selftest(void)
{
    int rc = ndh_st_planted();
    if (rc) {
        fputs("check-no-dev-history-in-contracts: planted selftest failed\n", stderr);
        return rc;
    }
    return ndh_cov_selftest();
}
