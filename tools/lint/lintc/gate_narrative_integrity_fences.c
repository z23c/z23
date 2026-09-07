/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: gate family — narrative-integrity fences
 * (check-no-dev-history-in-contracts, check-no-uncited-victory).
 * No production surface may carry a stale or uncited claim: include-dir
 * headers and .def tables (dev-history phrases) and docs/HANDOFF.md
 * (uncited victory phrases). HARD. 2026-09-06 shared-theme family file.
 * Coverage is inline (no C gate_require_coverage). GNU grep -w is a C
 * [A-Za-z0-9_] position check. Acceptance is make lint, not lint-fast.
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
enum { NI_MAX = 4096, NI_PATH = 512, NI_VMAX = 256, NI_VLINE = 1024,
       NUV_DOC = 65536, NUV_HIT = 16, NUV_HLEN = 64 };
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
static const char k_nuv_cite[] =
    "uptime-ledger|slo-summary:|verdict=pass|wall_clock_seconds|"
    "gap_vs_oracle|(ts=|\"ts\"[[:space:]]*:[[:space:]]*)[0-9]|victory-ok:";
static const char *const k_nuv_v[] = {
    "at tip", "at-tip", "reaches tip", "holds tip", "fully synced", "cured",
    "unwedged", "wedge cleared", "wedge closed", "wedge fixed",
    "soak window open", "soak window running", "proven live", "live-proven",
    "stable at tip"
};
enum { NUV_NV = (int)(sizeof k_nuv_v / sizeof k_nuv_v[0]) };
static char g_ndh_pool[NI_MAX][NI_PATH], g_ndh_exp[NI_MAX][NI_PATH];
static char g_ndh_miss[20][NI_PATH], g_ndh_badext[5];
static int g_ndh_n, g_ndh_ne;
static int ni_ws(unsigned char c)
{ return c == ' ' || c == '\t' || c == '\n' || c == '\v' || c == '\f' || c == '\r'; }
static int ni_wc(unsigned char c)
{ return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_'; }
static char ni_foldc(char c)
{ return (c >= 'A' && c <= 'Z') ? (char)(c - 'A' + 'a') : c; }
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
static int nuv_find(const char *fold, size_t from, size_t n, const char *pat,
                    size_t plen, size_t *at)
{
    if (plen == 0 || from + plen > n) return 0;
    for (size_t i = from; i + plen <= n; i++) {
        if (memcmp(fold + i, pat, plen) != 0) continue;
        if (i > 0 && ni_wc((unsigned char)fold[i - 1])) continue;
        if (i + plen < n && ni_wc((unsigned char)fold[i + plen])) continue;
        *at = i;
        return 1;
    }
    return 0;
}
static int nuv_next(const char *fold, size_t from, size_t n, size_t *at,
                    size_t *plen, int *pi)
{
    size_t best = n + 1, bl = 0;
    int bp = -1;
    for (int p = 0; p < NUV_NV; p++) {
        size_t pl = strlen(k_nuv_v[p]), pos = 0;
        if (nuv_find(fold, from, n, k_nuv_v[p], pl, &pos) && pos < best) {
            best = pos; bp = p; bl = pl;
        }
    }
    if (bp < 0) return 0;
    *at = best; *plen = bl; *pi = bp;
    return 1;
}
static int nuv_check_para(const char *doc, int s, int e, const char *text,
                          size_t n, regex_t *cite, int *found)
{
    char fold[NUV_DOC];
    if (n >= sizeof fold) return die("z23-lint: derived buffer overflow\n", "");
    for (size_t i = 0; i < n; i++) fold[i] = ni_foldc(text[i]);
    fold[n] = '\0';
    char hits[NUV_HIT][NUV_HLEN];
    int nh = 0;
    size_t from = 0, at = 0, plen = 0;
    int pi = 0;
    while (nuv_next(fold, from, n, &at, &plen, &pi)) {
        if (nh >= NUV_HIT) return die("z23-lint: scan-set overflow\n", "");
        if (ovf(snprintf(hits[nh], NUV_HLEN, "%.*s", (int)plen, text + at), NUV_HLEN))
            return 2;
        nh++;
        from = at + plen;
    }
    if (nh == 0 || regexec(cite, fold, 0, NULL, 0) == 0) return 0;
    qsort(hits, (size_t)nh, NUV_HLEN, ni_row_cmp);
    int w = 1;
    for (int i = 1; i < nh; i++)
        if (strcmp(hits[i], hits[w - 1]) != 0) {
            if (w != i) memcpy(hits[w], hits[i], NUV_HLEN);
            w++;
        }
    char joined[512];
    size_t used = 0;
    joined[0] = '\0';
    for (int i = 0; i < w; i++) {
        int k = snprintf(joined + used, sizeof joined - used, "%s%s", i ? "," : "", hits[i]);
        if (ovf(k, sizeof joined - used)) return 2;
        used += (size_t)k;
    }
    (*found)++;
    printf("  %s:%d-%d: uncited victory phrase(s): %s\n", ni_base(doc), s, e, joined);
    return 0;
}
static int nuv_append(char *para, size_t *plen, const char *ls, const char *p, int nl)
{
    size_t add = (size_t)(p - ls);
    if (*plen + (nl ? 1 : 0) + add >= NUV_DOC)
        return die("z23-lint: derived buffer overflow\n", "");
    if (nl) para[(*plen)++] = '\n';
    memcpy(para + *plen, ls, add);
    *plen += add;
    return 0;
}
static int nuv_blank(const char *ls, const char *p)
{ for (; ls < p; ls++) if (!ni_ws((unsigned char)*ls)) return 0; return 1; }
static int nuv_paras(const char *doc, const char *buf, size_t n, regex_t *cite)
{
    int found = 0, lineno = 1, pstart = 0, active = 0, rc = 0;
    const char *ls = buf, *p = buf, *end = buf + n;
    char para[NUV_DOC];
    size_t plen = 0;
    while (rc == 0 && p <= end) {
        int at_eof = (p == end), is_nl = (!at_eof && *p == '\n');
        if (!at_eof && !is_nl) { p++; continue; }
        int blank = nuv_blank(ls, p);
        if (blank) {
            if (active) {
                para[plen] = '\0';
                rc = nuv_check_para(doc, pstart, lineno - 1, para, plen, cite, &found);
                active = 0; plen = 0;
            }
        } else if (!active) {
            pstart = lineno; plen = 0;
            rc = nuv_append(para, &plen, ls, p, 0);
            active = 1;
        } else {
            rc = nuv_append(para, &plen, ls, p, 1);
        }
        if (at_eof) break;
        lineno++; p++; ls = p;
    }
    if (rc == 0 && active) {
        para[plen] = '\0';
        rc = nuv_check_para(doc, pstart, lineno, para, plen, cite, &found);
    }
    if (rc) return rc;
    if (!found) return 0;
    printf("\nFAIL: %d uncited victory claim(s) in %s.\n", found, doc);
    fputs("  This repo shipped 9+ false 'cured / at tip' claims (~103 wedge-\n"
          "  FIXED -> re-wedge cycles). Cite a real proof in the SAME paragraph\n"
          "  (VERDICT=PASS, gap_vs_oracle, uptime-ledger, a ts= stamp, slo-summary:,\n"
          "  WALL_CLOCK_SECONDS) or, for HISTORICAL narration only, add\n"
          "  <!-- victory-ok: <reason> -->. Never override a current-state claim.\n",
          stdout);
    return 1;
}
static int nuv_scan_doc(const char *doc)
{
    struct stat st;
    if (stat(doc, &st) != 0 || !S_ISREG(st.st_mode)) {
        printf("FAIL: %s is missing — the victory-claim scan set is empty.\n", doc);
        fputs("      This is the one live-state page; it must exist and carry\n"
              "      current node state, or an uncited claim could hide here.\n", stdout);
        return 2;
    }
    FILE *f = fopen(doc, "r");
    if (!f) return die("z23-lint: cannot open %s\n", doc);
    char buf[NUV_DOC];
    size_t n = fread(buf, 1, sizeof buf - 1, f);
    int err = ferror(f);
    fclose(f);
    if (err) return die("z23-lint: cannot open %s\n", doc);
    if (n == sizeof buf - 1) return die("z23-lint: derived buffer overflow\n", "");
    buf[n] = '\0';
    int nlines = 0;
    for (size_t i = 0; i < n; i++) if (buf[i] == '\n') nlines++;
    if (nlines < 10) {
        printf("FAIL: %s has %d lines (< 10) — hollow scan set.\n", doc, nlines);
        fputs("      The live-state page must carry real current state, not a\n"
              "      stub; a near-empty file would pass this gate vacuously.\n", stdout);
        return 2;
    }
    regex_t cite;
    int rc = reg_fail(&cite, regcomp(&cite, k_nuv_cite, REG_EXTENDED | REG_NOSUB));
    if (rc) return rc;
    rc = nuv_paras(doc, buf, n, &cite);
    regfree(&cite);
    return rc;
}
static const char *nuv_doc(void)
{
    const char *mode = getenv("ZCL_LINT_MODE");
    struct stat st;
    if (mode && mode[0] && stat(mode, &st) == 0 && S_ISREG(st.st_mode)) return mode;
    return "docs/HANDOFF.md";
}
int check_no_uncited_victory_run(int argc, char **argv)
{
    (void)argc; (void)argv;
    const char *doc = nuv_doc();
    int rc = nuv_scan_doc(doc);
    if (rc == 0) printf("  OK: no uncited victory claim in %s\n", doc);
    return rc;
}
#define NUV_FILL \
    "Filler line one to clear the hollow-gate line floor.\n" \
    "Filler line two to clear the hollow-gate line floor.\n" \
    "Filler line three to clear the hollow-gate line floor.\n" \
    "Filler line four to clear the hollow-gate line floor.\n" \
    "Filler line five to clear the hollow-gate line floor.\n"
static const char k_nuv_clean[] =
    "# HANDOFF — current state\n\n"
    "The canonical node is blocked. H* has not advanced for 13 days.\n"
    "Primary blocker: catchup_stalled, a downstream symptom of the fold blocker.\n\n"
    "The wedge root cause is closed in code; the live apply is pending the owner\n"
    "gate. The tip_finalize rate bug is still open and gates any catch-up.\n\n"
    "Read the live node before trusting this file.\n"
    "Verify with typed status commands.\nDo not deploy on unit-test green alone.\n";
static const char k_nuv_uncited[] =
    "# HANDOFF — current state\n\n"
    "The node is at tip and holding. Everything is fine now.\n"
    "No further action is required and we can move on.\n\n" NUV_FILL;
static const char k_nuv_cited[] =
    "# HANDOFF — current state\n\n"
    "The soak run reached tip and held: VERDICT=PASS, gap_vs_oracle=0,\n"
    "WALL_CLOCK_SECONDS=54, ts=1690000000. This is a ledgered proof.\n\n" NUV_FILL;
static const char k_nuv_over[] =
    "# HANDOFF — current state\n\n"
    "The old July claim that the wedge was cured is historical, not current.\n"
    "<!-- victory-ok: narrating a superseded false-victory, not a live claim -->\n\n"
    NUV_FILL;
static char g_nuv_path[NI_PATH];
static int nuv_scan_g(void) { return nuv_scan_doc(g_nuv_path); }
static int nuv_st_case(const char *root, const char *name, const char *body, int want)
{ int got = 0, rc;
    if (ovf(snprintf(g_nuv_path, sizeof g_nuv_path, "%s/%s", root, name), sizeof g_nuv_path))
        return 2;
    if (body && (rc = csr_write(g_nuv_path, body)) != 0) return rc;
    rc = ni_quiet(nuv_scan_g, &got);
    if (rc) return rc;
    if (got != want) {
        fprintf(stderr, "  FAIL: %s expected rc=%d got rc=%d\n", name, want, got);
        return 1;
    }
    printf("  ok: %s (rc=%d)\n", name, got);
    return 0;
}
int check_no_uncited_victory_selftest(void)
{
    if (csr_mkdirs("test-tmp")) return 2;
    char tmpl[] = "test-tmp/nuv_st.XXXXXX";
    char *tmp = mkdtemp(tmpl);
    if (!tmp) return die("z23-lint: mkdir failed: %s\n", "test-tmp");
    int bad = nuv_st_case(tmp, "clean.md", k_nuv_clean, 0); // error-doc-ref-ok: planted selftest fixture
    bad |= nuv_st_case(tmp, "uncited.md", k_nuv_uncited, 1); // error-doc-ref-ok: planted selftest fixture
    bad |= nuv_st_case(tmp, "cited.md", k_nuv_cited, 0); // error-doc-ref-ok: planted selftest fixture
    bad |= nuv_st_case(tmp, "override.md", k_nuv_over, 0); // error-doc-ref-ok: planted selftest fixture
    bad |= nuv_st_case(tmp, "short.md", "too short\n", 2); // error-doc-ref-ok: planted selftest fixture
    bad |= nuv_st_case(tmp, "does-not-exist", NULL, 2);
    (void)rap_rm_rf(tmp);
    if (bad) { fputs("selftest: FAIL\n", stdout); return 1; }
    fputs("selftest: PASS\n", stdout);
    return 0;
}
