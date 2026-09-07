/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: gate family — check-hex-codec-single of the C23 lint runtime,
 * replacing tools/lint/check_hex_codec_single.sh. RATCHET gate (file
 * granularity, shrink-only baseline): base-16 encode/decode of a byte
 * buffer must live only in platform/modules/base/include/base/hex.h. A
 * file elsewhere is flagged when it carries an ENCODER shape (a hex-digit
 * table together with a high-nibble index) or a DECODER shape (a nibble-
 * ladder subtraction or a two-digit-hex scanf format). The scan walks the
 * filesystem directly (like the original script's `find`, never through
 * the git index) so it needs no .git at all; a coverage self-check (an
 * independent expectation read from the native git-index reader, in
 * memory, no subprocess) proves the walk did not silently lose surface —
 * missing more than the shrink-only allowance is UNPROVEN, missing less
 * is a stale ratchet. Without a .git to read (the make_lint_gates sandbox
 * lane's hardlink clone), the coverage oracle reports UNPROVEN exactly as
 * the original script's `git ls-files` would without one; the scan itself
 * is unaffected either way.
 * --selftest lives in the sibling gate_hex_codec_single_selftest.c.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "lintc.h"

enum { HCS_MAXF = 4096, HCS_PATH = RS_PATH, HCS_MAXR = RS_MAX, HCS_LINE = 8192 };

static const char k_hcs_gate[] = "check_hex_codec_single";
static const char k_hcs_base_default[] = "tools/lint/hex_codec_baseline.txt";
static const char k_hcs_re_table[] = "0123456789(abcdef|ABCDEF)";
static const char k_hcs_re_nibble[] = ">> *4[])]";
static const char k_hcs_re_ladder[] = "- *'[aA]' *\\+ *10";
static const char k_hcs_re_scanf[] = "\"%2x\"";
static const char *const k_hcs_fixed_roots[] = {
    "engine/composition", "engine/entry", "tools"
};

/* ── scan roots ───────────────────────────────────────────────────────── */

static int hcs_default_roots(char out[][RS_PATH], int max, int *n)
{
    static char libs[HCS_MAXR][RS_PATH];
    int nlibs = 0, rc;
    *n = 0;
    rc = repo_shape_dirs("app", "", out, max, n);
    if (rc)
        return rc;
    rc = repo_shape_dirs("lib", "", libs, HCS_MAXR, &nlibs);
    if (rc)
        return rc;
    for (int i = 0; i < nlibs; i++) {
        if (*n >= max)
            return die("z23-lint: scan-root overflow\n", "");
        if (ovf(snprintf(out[*n], RS_PATH, "%s", libs[i]), RS_PATH))
            return 2;
        (*n)++;
    }
    for (size_t i = 0; i < sizeof k_hcs_fixed_roots / sizeof k_hcs_fixed_roots[0]; i++) {
        if (*n >= max)
            return die("z23-lint: scan-root overflow\n", "");
        if (ovf(snprintf(out[*n], RS_PATH, "%s", k_hcs_fixed_roots[i]), RS_PATH))
            return 2;
        (*n)++;
    }
    return 0;
}

static int hcs_split_roots(const char *s, char out[][RS_PATH], int max, int *n)
{
    const char *p = s;
    *n = 0;
    while (*p) {
        while (*p == ' ' || *p == '\t')
            p++;
        if (!*p)
            break;
        const char *e = p;
        while (*e && *e != ' ' && *e != '\t')
            e++;
        size_t len = (size_t)(e - p);
        if (*n >= max)
            return die("z23-lint: scan-root overflow\n", "");
        if (len >= RS_PATH)
            return die("z23-lint: scan root too long\n", "");
        memcpy(out[*n], p, len);
        out[*n][len] = '\0';
        (*n)++;
        p = e;
    }
    return 0;
}

/* ── the exclusion carve-outs, shared by the scan side and the oracle ──── */

static int hcs_excluded(const char *path)
{
    return strncmp(path, "platform/modules/base/", 22) == 0
        || strncmp(path, "contexts/commons/packages/", 27) == 0
        || strncmp(path, "tests/harness/include/test/", 28) == 0;
}

/* ── the scan: a plain recursive filesystem walk, never the git index ──── */

struct hcs_walk_ctx { char (*out)[HCS_PATH]; int max; int *n; };

static int hcs_walk(const char *dir, struct hcs_walk_ctx *c);

static int hcs_walk_entry(const char *dir, const char *nm, struct hcs_walk_ctx *c)
{
    char path[4096];
    struct stat st;
    int k;
    size_t nl;
    if (strcmp(nm, ".") == 0 || strcmp(nm, "..") == 0)
        return 0;
    k = snprintf(path, sizeof path, "%s/%s", dir, nm);
    if (k < 0 || (size_t)k >= sizeof path)
        return die("z23-lint: path too long: %s\n", dir);
    if (lstat(path, &st) != 0)
        return die("z23-lint: cannot stat %s\n", path);
    if (S_ISDIR(st.st_mode))
        return hcs_walk(path, c);
    if (!S_ISREG(st.st_mode))
        return 0;
    nl = strlen(path);
    if (nl < 2 || path[nl - 2] != '.' || (path[nl - 1] != 'c' && path[nl - 1] != 'h'))
        return 0;
    if (hcs_excluded(path))
        return 0;
    if (*c->n >= c->max)
        return die("z23-lint: scan-set overflow\n", "");
    if (nl >= HCS_PATH)
        return die("z23-lint: path too long: %s\n", path);
    memcpy(c->out[*c->n], path, nl + 1);
    (*c->n)++;
    return 0;
}

static int hcs_walk(const char *dir, struct hcs_walk_ctx *c)
{
    struct dirent **names = NULL;
    int cnt = scandir(dir, &names, NULL, alphasort);
    int rc = 0, i;
    if (cnt < 0)
        return errno == ENOENT ? 0 : die("z23-lint: cannot scan %s\n", dir);
    for (i = 0; i < cnt; i++) {
        if (rc == 0)
            rc = hcs_walk_entry(dir, names[i]->d_name, c);
        free(names[i]);
    }
    free(names);
    return rc;
}

static int hcs_path_cmp(const void *a, const void *b)
{ return strcmp((const char *)a, (const char *)b); }

static int hcs_collect(char roots[][RS_PATH], int nroots, char out[][HCS_PATH],
                       int max, int *n)
{
    struct hcs_walk_ctx c = { out, max, n };
    struct stat st;
    int rc = 0;
    *n = 0;
    for (int i = 0; rc == 0 && i < nroots; i++) {
        if (stat(roots[i], &st) != 0 || !S_ISDIR(st.st_mode))
            continue;
        rc = hcs_walk(roots[i], &c);
    }
    if (rc == 0)
        qsort(out, (size_t)*n, HCS_PATH, hcs_path_cmp);
    return rc;
}

static int hcs_sort_uniq(char arr[][HCS_PATH], int n)
{
    qsort(arr, (size_t)n, HCS_PATH, hcs_path_cmp);
    int w = 0;
    for (int i = 0; i < n; i++) {
        if (w == 0 || strcmp(arr[w - 1], arr[i]) != 0) {
            if (w != i)
                memcpy(arr[w], arr[i], HCS_PATH);
            w++;
        }
    }
    return w;
}

/* ── the coverage self-check (git-oracle vs. the fs scan, in memory) ───── */

struct hcs_oracle_ctx {
    char (*roots)[RS_PATH];
    int nroots;
    char (*out)[HCS_PATH];
    int max;
    int *n;
};

static int hcs_oracle_match(const char *path, char roots[][RS_PATH], int nroots)
{
    size_t pl = strlen(path);
    if (pl < 3 || path[pl - 2] != '.' || (path[pl - 1] != 'c' && path[pl - 1] != 'h'))
        return 0;
    if (hcs_excluded(path))
        return 0;
    for (int i = 0; i < nroots; i++) {
        size_t rl = strlen(roots[i]);
        if (pl > rl + 1 && strncmp(path, roots[i], rl) == 0 && path[rl] == '/')
            return 1;
    }
    return 0;
}

static int hcs_on_oracle(const char *path, int stage, void *ctx)
{
    struct hcs_oracle_ctx *c = ctx;
    if (stage != 0)
        return 0;
    if (!hcs_oracle_match(path, c->roots, c->nroots))
        return 0;
    if (*c->n >= c->max)
        return die("z23-lint: scan-set overflow\n", "");
    size_t n = strlen(path);
    if (n >= HCS_PATH)
        return die("z23-lint: path too long: %s\n", path);
    memcpy(c->out[*c->n], path, n + 1);
    (*c->n)++;
    return 0;
}

static int hcs_oracle_badext(const char *badext)
{
    fprintf(stderr,
            "%s: UNPROVEN — the git index carries a mandatory\n"
            "  extension ('%s') this native reader does not interpret;\n"
            "  reading past it could silently yield a PARTIAL file list\n"
            "  (a split index's shared entries, a sparse directory's\n"
            "  collapsed trees). Refusing to grade. Re-create the index\n"
            "  without split-index/sparse extensions, or teach\n"
            "  lint_git_index_foreach the extension first.\n", k_hcs_gate, badext);
    return 2;
}

static int hcs_cov_oracle(char roots[][RS_PATH], int nroots, char exp[][HCS_PATH],
                          int *nexp)
{
    char badext[5] = "";
    struct hcs_oracle_ctx cc = { roots, nroots, exp, HCS_MAXF, nexp };
    *nexp = 0;
    int rc = lint_git_index_foreach(hcs_on_oracle, &cc, badext);
    if (rc && badext[0])
        return hcs_oracle_badext(badext);
    if (rc) {
        fprintf(stderr,
                "%s: UNPROVEN — the coverage oracle could not run:\n"
                "  'git ls-files' over the declared scan roots exited "
                "nonzero.\n"
                "  Without an independent expectation this gate cannot "
                "tell a\n  complete scan from a partial one, so it "
                "refuses to grade\n  either way. Run it from inside the "
                "checkout.\n", k_hcs_gate);
        return 2;
    }
    *nexp = hcs_sort_uniq(exp, *nexp);
    if (*nexp == 0) {
        fprintf(stderr,
                "%s: UNPROVEN — the coverage oracle is empty: git tracks "
                "no\n  file matching the declared scan roots.\n"
                "  An empty expectation would pass every scan, including "
                "a scan\n  of nothing. Refusing to vouch for coverage off "
                "a hollow\n  oracle. Fix the pathspec, or drop the "
                "coverage check if the\n  set is genuinely gone.\n",
                k_hcs_gate);
        return 2;
    }
    return 0;
}

static int hcs_missing(char act[][HCS_PATH], int nact, char exp[][HCS_PATH], int nexp,
                       char miss[][HCS_PATH], int *outm)
{
    int i = 0, j = 0, m = 0;
    while (j < nexp) {
        if (i < nact) {
            int c = strcmp(exp[j], act[i]);
            if (c > 0) { i++; continue; }
            if (c == 0) { i++; j++; continue; }
        }
        if (m >= HCS_MAXF)
            return die("z23-lint: scan-set overflow\n", "");
        memcpy(miss[m], exp[j], HCS_PATH);
        m++;
        j++;
    }
    *outm = m;
    return 0;
}

/* bash `[` integer operand: optional whitespace/sign, then digits only. */
static int hcs_allowance_parse(const char *s, long *v)
{
    const char *p = s;
    while (*p && isspace((unsigned char)*p))
        p++;
    if (*p == '+' || *p == '-')
        p++;
    if (!isdigit((unsigned char)*p))
        return 1;
    errno = 0;
    char *end = NULL;
    *v = strtol(p, &end, 10);
    if (errno == ERANGE || !end)
        return 1;
    while (*end && isspace((unsigned char)*end))
        end++;
    return *end != '\0';
}

static int hcs_cov_partial(int nact, int nexp, int nmiss, const char *allow,
                           char miss[][HCS_PATH])
{
    fprintf(stderr,
            "%s: UNPROVEN — the scan reached %d of the %d\n"
            "  entries an independent oracle says it should have "
            "reached;\n  %d missing, above the shrink-only allowance of\n"
            "  %s recorded in ZCL_HEX_CODEC_COVERAGE_ALLOWANCE.\n"
            "  This is a PARTIAL scan: not a clean one, and not a "
            "violating\n  one. Not reached (first 20 of %d):\n",
            k_hcs_gate, nact, nexp, nmiss, allow, nmiss);
    int show = nmiss < 20 ? nmiss : 20;
    for (int i = 0; i < show; i++)
        fprintf(stderr, "    %s\n", miss[i]);
    if (nmiss > 20)
        fprintf(stderr, "    ... and %d more\n", nmiss - 20);
    return 2;
}

static int hcs_cov_stale(int nexp, int nmiss, const char *allow)
{
    fprintf(stderr,
            "%s: VIOLATION — the coverage allowance is stale: the scan "
            "now\n  misses only %d of %d expected entries, below\n"
            "  ZCL_HEX_CODEC_COVERAGE_ALLOWANCE=%s.\n"
            "  Coverage improved without lowering the allowance. Lower "
            "ZCL_HEX_CODEC_COVERAGE_ALLOWANCE to %d, with the reason, in "
            "the\n  same commit.\n", k_hcs_gate, nmiss, nexp, allow, nmiss);
    return 1;
}

static int hcs_coverage(char droots[][RS_PATH], int ndroots, char files[][HCS_PATH],
                        int nfiles)
{
    static char exp[HCS_MAXF][HCS_PATH];
    static char actu[HCS_MAXF][HCS_PATH];
    static char miss[HCS_MAXF][HCS_PATH];
    int nexp = 0, nact, nmiss = 0, rc;
    rc = hcs_cov_oracle(droots, ndroots, exp, &nexp);
    if (rc)
        return rc;
    memcpy(actu, files, sizeof actu[0] * (size_t)nfiles);
    nact = hcs_sort_uniq(actu, nfiles);
    rc = hcs_missing(actu, nact, exp, nexp, miss, &nmiss);
    if (rc)
        return rc;
    const char *allow_s = env_or("ZCL_HEX_CODEC_COVERAGE_ALLOWANCE", "0");
    long allow = 0;
    if (hcs_allowance_parse(allow_s, &allow)) {
        fprintf(stderr, "%s: FATAL — invalid ZCL_HEX_CODEC_COVERAGE_ALLOWANCE "
                "'%s'\n", k_hcs_gate, allow_s);
        return 2;
    }
    if ((long)nmiss > allow)
        return hcs_cov_partial(nact, nexp, nmiss, allow_s, miss);
    if ((long)nmiss < allow)
        return hcs_cov_stale(nexp, nmiss, allow_s);
    return 0;
}

/* ── the two shape detectors ─────────────────────────────────────────── */

struct hcs_regs { const regex_t *ladder, *scanf_re, *table, *nibble; };
struct hcs_flags { int has_dec, has_tbl, has_nib; };

static int hcs_flags_done(const struct hcs_flags *fl)
{ return fl->has_dec || (fl->has_tbl && fl->has_nib); }

/* Test one already-read line against the four detector regexes, updating
 * whichever flags have not already latched. Split out of hcs_scan_file so
 * the loop that owns it stays under the complexity cap. */
static void hcs_scan_line(const char *line, const struct hcs_regs *re,
                          struct hcs_flags *fl)
{
    if (!fl->has_dec && (regexec(re->ladder, line, 0, NULL, 0) == 0
                         || regexec(re->scanf_re, line, 0, NULL, 0) == 0))
        fl->has_dec = 1;
    if (!fl->has_tbl && regexec(re->table, line, 0, NULL, 0) == 0)
        fl->has_tbl = 1;
    if (!fl->has_nib && regexec(re->nibble, line, 0, NULL, 0) == 0)
        fl->has_nib = 1;
}

/* Read one line into `line` (stripped of its trailing newline); sets *eof
 * when the file is exhausted. */
static int hcs_read_line(FILE *f, const char *path, char *line, size_t cap,
                         int *eof)
{
    size_t n;
    if (!fgets(line, (int)cap, f)) {
        *eof = 1;
        return 0;
    }
    *eof = 0;
    n = strlen(line);
    if (n + 1 >= cap && (n == 0 || line[n - 1] != '\n'))
        return die("z23-lint: source line too long: %s\n", path);
    if (n && line[n - 1] == '\n')
        line[--n] = '\0';
    return 0;
}

static int hcs_scan_file(const char *path, const struct hcs_regs *re, int *found)
{
    FILE *f = fopen(path, "r");
    char line[HCS_LINE];
    struct hcs_flags fl = {0};
    int rc = 0, eof = 0;
    *found = 0;
    if (!f) {
        fprintf(stderr, "z23-lint: UNPROVEN — cannot read %s\n", path);
        return 2;
    }
    while (rc == 0) {
        rc = hcs_read_line(f, path, line, sizeof line, &eof);
        if (rc || eof)
            break;
        hcs_scan_line(line, re, &fl);
        if (hcs_flags_done(&fl))
            break;
    }
    if (rc == 0 && ferror(f))
        rc = die("z23-lint: read failed: %s\n", path);
    if (fclose(f) != 0 && rc == 0)
        rc = die("z23-lint: fclose failed: %s\n", path);
    if (rc)
        return rc;
    *found = hcs_flags_done(&fl);
    return 0;
}

static int hcs_compile(regex_t *ladder, regex_t *scanf_re, regex_t *table,
                       regex_t *nibble)
{
    int rc = reg_fail(ladder, regcomp(ladder, k_hcs_re_ladder, REG_EXTENDED));
    if (rc)
        return rc;
    rc = reg_fail(scanf_re, regcomp(scanf_re, k_hcs_re_scanf, REG_EXTENDED));
    if (rc) { regfree(ladder); return rc; }
    rc = reg_fail(table, regcomp(table, k_hcs_re_table, REG_EXTENDED));
    if (rc) { regfree(ladder); regfree(scanf_re); return rc; }
    rc = reg_fail(nibble, regcomp(nibble, k_hcs_re_nibble, REG_EXTENDED));
    if (rc) { regfree(ladder); regfree(scanf_re); regfree(table); return rc; }
    return 0;
}

/* ── baseline + report ───────────────────────────────────────────────── */

static void hcs_bln_sort(struct bln_set *s)
{ qsort(s->n, (size_t)s->count, BLN_ROW, hcs_path_cmp); }

static int hcs_write_baseline(const struct bln_set *found, const char *path)
{
    FILE *f = fopen(path, "w");
    struct bln_set sorted = *found;
    if (!f)
        return die("z23-lint: cannot open %s\n", path);
    hcs_bln_sort(&sorted);
    fputs("# check_hex_codec_single baseline — production files that "
          "still carry their own\n"
          "# hex encode/decode instead of "
          "platform/modules/base/include/base/hex.h.\n"
          "# One path per line. THE LIST MAY ONLY SHRINK.\n#\n"
          "# Fix a row by deleting the private codec and calling:\n"
          "#   zcl_hex_encode(in, len, out)          lowercase, "
          "NUL-terminated\n"
          "#   zcl_hex_decode(hex, out, want)        exact length, "
          "[0-9a-fA-F]\n"
          "#   zcl_hex_decode_lower(hex, out, want)  canonical form "
          "only\n"
          "#   zcl_hex_decode_n(hex, out, cap, &n)   1..cap bytes\n"
          "# then delete the line here. Adding a row is not a fix.\n"
          "# Regenerate: ZCL_LINT_MODE=UPDATE tools/lint/"
          "check_hex_codec_single.sh\n", f);
    for (int i = 0; i < sorted.count; i++)
        fprintf(f, "%s\n", sorted.n[i]);
    if (fclose(f) != 0)
        return die("z23-lint: fclose failed: %s\n", path);
    printf("[%s] baseline UPDATED: %s\n", k_hcs_gate, path);
    return 0;
}

static int hcs_report(struct bln_set *violations, struct bln_set *stale,
                      const char *base_path, const char *mode, int nfiles,
                      int found_count, int baseline_count)
{
    int fail = 0;
    hcs_bln_sort(violations);
    hcs_bln_sort(stale);
    if (violations->count > 0) {
        printf("\n[%s] %d file(s) carry a private hex encoder or\n"
               "        decoder outside platform/modules/base:\n",
               k_hcs_gate, violations->count);
        for (int i = 0; i < violations->count; i++)
            printf("  %s\n", violations->n[i]);
        printf("\n  Delete it and include \"base/hex.h\" instead:\n"
               "    zcl_hex_encode(in, len, out)          lowercase, "
               "NUL-terminated\n"
               "    zcl_hex_decode(hex, out, want)        exact length, "
               "[0-9a-fA-F]\n"
               "    zcl_hex_decode_lower(hex, out, want)  canonical "
               "(lowercase) only,\n"
               "                                          for on-disk "
               "names\n"
               "    zcl_hex_decode_n(hex, out, cap, &n)   1..cap bytes\n"
               "    zcl_hex_nibble(c, allow_upper)        one character, "
               "for parsing\n"
               "                                          a length-"
               "delimited slice\n"
               "  Adding a row to %s is NOT a fix; the list may only "
               "shrink.\n", base_path);
        fail = 1;
    }
    if (stale->count > 0) {
        printf("\n[%s] %d STALE baseline row(s) — the file no longer\n"
               "        carries a private hex codec. Delete them from "
               "%s:\n", k_hcs_gate, stale->count, base_path);
        for (int i = 0; i < stale->count; i++)
            printf("  %s\n", stale->n[i]);
        fail = 1;
    }
    if (fail && strcmp(mode, "FAIL") == 0)
        return 1;
    printf("[%s] PASS (%d files scanned, %d still carrying a private "
           "codec, all %d baselined)\n", k_hcs_gate, nfiles, found_count,
           baseline_count);
    return 0;
}

/* ── the gate ─────────────────────────────────────────────────────────── */

static int hcs_floor_hint(char roots[][RS_PATH], int n, char *out, size_t cap)
{
    size_t used = 0;
    int k = snprintf(out, cap, "%s", "no production .c/.h under: ");
    if (k < 0 || (size_t)k >= cap)
        return die("z23-lint: derived buffer overflow\n", "");
    used = (size_t)k;
    for (int i = 0; i < n; i++) {
        k = snprintf(out + used, cap - used, "%s%s", i > 0 ? " " : "", roots[i]);
        if (k < 0 || (size_t)k >= cap - used)
            return die("z23-lint: derived buffer overflow\n", "");
        used += (size_t)k;
    }
    return 0;
}

static int hcs_active_roots(char droots[][RS_PATH], int ndroots,
                            char sroots[][RS_PATH], int *nsroots)
{
    const char *ovr = getenv("ZCL_HEX_CODEC_SCAN_ROOTS");
    if (ovr && ovr[0])
        return hcs_split_roots(ovr, sroots, HCS_MAXR, nsroots);
    for (int i = 0; i < ndroots; i++)
        memcpy(sroots[i], droots[i], RS_PATH);
    *nsroots = ndroots;
    return 0;
}

static int hcs_detect(char files[][HCS_PATH], int nfiles, struct bln_set *found)
{
    regex_t ladder, scanf_re, table, nibble;
    struct hcs_regs re;
    int rc = hcs_compile(&ladder, &scanf_re, &table, &nibble);
    if (rc)
        return rc;
    re.ladder = &ladder;
    re.scanf_re = &scanf_re;
    re.table = &table;
    re.nibble = &nibble;
    found->count = 0;
    for (int i = 0; rc == 0 && i < nfiles; i++) {
        int hit = 0;
        rc = hcs_scan_file(files[i], &re, &hit);
        if (rc == 0 && hit)
            rc = bln_add(found, files[i]);
    }
    regfree(&ladder);
    regfree(&scanf_re);
    regfree(&table);
    regfree(&nibble);
    return rc;
}

static int hcs_diff_baseline(const struct bln_set *found, const struct bln_set *base,
                             struct bln_set *violations, struct bln_set *stale)
{
    int rc = 0;
    violations->count = 0;
    stale->count = 0;
    for (int i = 0; rc == 0 && i < found->count; i++)
        if (!bln_has(base, found->n[i]))
            rc = bln_add(violations, found->n[i]);
    for (int i = 0; rc == 0 && i < base->count; i++)
        if (!bln_has(found, base->n[i]))
            rc = bln_add(stale, base->n[i]);
    return rc;
}

int check_hex_codec_single_run(int argc, char **argv)
{
    static char droots[HCS_MAXR][RS_PATH], sroots[HCS_MAXR][RS_PATH];
    static char files[HCS_MAXF][HCS_PATH];
    static struct bln_set found = {0}, base = {0}, violations = {0}, stale = {0};
    int ndroots = 0, nsroots = 0, nfiles = 0, rc;
    (void)argc;
    (void)argv;
    rc = hcs_default_roots(droots, HCS_MAXR, &ndroots);
    if (rc)
        return rc;
    rc = hcs_active_roots(droots, ndroots, sroots, &nsroots);
    if (rc)
        return rc;
    rc = hcs_collect(sroots, nsroots, files, HCS_MAXF, &nfiles);
    if (rc)
        return rc;
    char hint[4096];
    rc = hcs_floor_hint(sroots, nsroots, hint, sizeof hint);
    if (rc)
        return rc;
    long floor_v = 800;
    hcs_allowance_parse(env_or("ZCL_HEX_CODEC_FILE_FLOOR", "800"), &floor_v);
    rc = gate_require_scanned(nfiles, (int)floor_v, k_hcs_gate, hint);
    if (rc)
        return rc;
    if (strcmp(env_or("ZCL_HEX_CODEC_COVERAGE", "1"), "1") == 0) {
        rc = hcs_coverage(droots, ndroots, files, nfiles);
        if (rc)
            return rc;
    }
    rc = hcs_detect(files, nfiles, &found);
    if (rc)
        return rc;
    const char *base_path = env_or("ZCL_HEX_CODEC_BASELINE", k_hcs_base_default);
    const char *mode = clock_mode();
    if (strcmp(mode, "UPDATE") == 0)
        return hcs_write_baseline(&found, base_path);
    rc = bln_load(&base, base_path);
    if (rc)
        return rc;
    rc = hcs_diff_baseline(&found, &base, &violations, &stale);
    if (rc)
        return rc;
    return hcs_report(&violations, &stale, base_path, mode, nfiles, found.count,
                      base.count);
}

