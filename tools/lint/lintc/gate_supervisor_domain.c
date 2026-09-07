/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Gates: check-supervisor-domain
 * Single-gate family, three files under the 700-line family ceiling:
 * gate_supervisor_domain.c (this file) holds the find mirror, the
 * git-oracle coverage check, and the gate entry;
 * gate_supervisor_domain_scan.c holds the native main scan (the ERE over
 * the scan roots, its traversal, diagnostics, and the four row filters);
 * and gate_supervisor_domain_workers.c holds the boot-worker lock-in and
 * the gate's --selftest probes. Placement ruling (2026-09-06, Linux side):
 * the small-pattern, ratchet, tree-walk, and git-scan families are claimed
 * or full, so new ports land in their own files; the older in-file routing
 * comments that would have folded this gate into an existing family are
 * overridden by that ruling.
 */

/* ── check-supervisor-domain ─────────────────────────────────────────────
 * Byte-parity C23 port of tools/lint/check_supervisor_domain.sh (Gate #21:
 * production supervisor registration must specify a domain, plus the boot
 * background-worker lock-in on engine/composition/src/boot_*.c).
 *
 * Semantic mapping (this file):
 * - Scan roots: ZCL_SUPDOM_SCAN_ROOTS, IFS-split like `read -r -a`
 *   (sd_split), default "core engine contexts cognition platform".
 * - The fail-loud floor: `find <roots> -type f -name '*.c' 2>/dev/null`
 *   is sd_walk (diagnostics dropped like the shell's 2>/dev/null, symlinks
 *   never followed as in find -P, a root that is itself a *.c file counts,
 *   a trailing-slash root joins without a doubled slash) feeding the shared
 *   gate_require_scanned, which already prints the gate_lib.sh text
 *   byte-for-byte.
 * - The coverage block (ZCL_SUPDOM_COVERAGE, default on):
 *   gate_require_git_coverage reimplemented in memory. The per-declared-
 *   root git emptiness probes are sd_root_probes; the git-ls-files oracle
 *   is sd_cov_oracle (rc != 0 -> the "could not run" UNPROVEN, empty ->
 *   the "hollow oracle" UNPROVEN); both sets are LC_ALL=C sorted+deduped
 *   (qsort/strcmp, sd_sort_uniq); comm -13 is the sd_missing merge; and
 *   gate_require_coverage's three-way verdict stands: missing > allowance
 *   is the partial-scan UNPROVEN naming the first 20 (exit 2), missing <
 *   allowance is the stale-ratchet VIOLATION (exit 1), equal passes. The
 *   allowance string is printed verbatim, as the shell's $ expansion did.
 *   gate_lib.sh's mktemp scratch dirs are gone (the compare is in memory);
 *   their two FATALs were environment failures, never gate verdicts.
 * - ZCL_SUPDOM_COVERAGE_ONLY=1 prints the coverage-only PASS line with the
 *   RAW find count (${#supdom_files[@]}), not the deduped one.
 * - The main scan is native (gate_supervisor_domain_scan.c): a
 *   readdir-order depth-first walk of the roots (fts with no comparison
 *   function, which is what GNU grep -r uses), per-line regexec of the
 *   ERE with [[:space:]] standing in for grep's whitespace escape (an
 *   identical match set: every byte under the scan roots is ASCII), the
 *   --include='*.c' basename glob, and the scan_exclusions.sh exclude
 *   globs (basename fnmatch, applied even to explicit root operands,
 *   exactly like grep 3.11) when ZCL_LINT_PRODUCTION_SCAN=1. grep's own
 *   open/read diagnostics are reproduced byte-for-byte on stderr and any
 *   such failure is the exit >= 2 FATAL block (exit 2), the partial rows
 *   discarded exactly like the shell's captured RAW on that branch.
 * - The four `grep -v` filters and the violation report (hits + the
 *   "N violation(s) (mode: M)" line, both stdout) live with the scan;
 *   the report exits 1 only when ZCL_LINT_MODE is FAIL (default; an
 *   empty value is FAIL, matching ${VAR:-FAIL}).
 * - The boot-worker lock-in and --selftest: gate_supervisor_domain_workers.c.
 *
 * Preserved latent defects / parity notes:
 * - A non-numeric ZCL_SUPDOM_COVERAGE_ALLOWANCE does NOT fail the gate:
 *   bash's `[ -gt ]`/`[ -lt ]` each print "tools/lint/gate_lib.sh:
 *   line 307/327: [: <val>: integer expression expected" and read as false,
 *   so coverage silently PASSES with two stderr lines. Reproduced
 *   byte-exactly, gate_lib.sh line numbers included, along with bash's
 *   operand grammar (sd_allowance_parse: optional surrounding whitespace,
 *   optional sign, decimal digits; empty/0x../junk/out-of-range all error).
 * - The 'platform/modules/util/src/supervisor.c' filter's dots match any
 *   character (regex, not fixed string) — a latent over-exclusion,
 *   reproduced, not repaired.
 * - File names containing a newline: the shell's mapfile/printf pipeline
 *   counts LINES (such a file reads as several entries and mismatches the
 *   git oracle); the port counts FILES. No such name exists in the tree.
 * - The shell was unbounded; the port's fixed pools (scan set, oracle
 *   capture, and the scan file's RAW/HITS buffers) fail closed with die().
 * - The ZCL_GATE_SCAN_LOG audit hook of gate_lib.sh is not reproduced
 *   (lib.c precedent: "Non-parity: no ZCL_GATE_SCAN_LOG").
 */

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "lintc.h"

/* The boot-worker half of the gate (gate_supervisor_domain_workers.c). */
int supervisor_domain_workers_run(const char *mode);

/* The native main scan (gate_supervisor_domain_scan.c). */
int supervisor_domain_scan_run(const char *mode, const char *const *roots,
                               int nroots);

static const char k_sd_name[] = "check_supervisor_domain";
static const char k_sd_roots_default[] =
    "core engine contexts cognition platform";
static const char *const k_sd_roots[] = {
    "core", "engine", "contexts", "cognition", "platform"
};
#define SD_NROOTS (sizeof k_sd_roots / sizeof k_sd_roots[0])
static const char k_sd_specs[] =
    "core/*.c engine/*.c contexts/*.c cognition/*.c platform/*.c";
static const char k_sd_cov_hint[] =
    "Re-run from a clean checkout. If a listed file genuinely left this "
    "gate's scope, move it out of core engine contexts cognition platform "
    "— raising ZCL_SUPDOM_COVERAGE_ALLOWANCE is a last resort and needs "
    "the reason written down.";

enum { SD_MAXF = 24576, SD_POOL = 1 << 20, SD_RAW = 1 << 20,
       SD_CMD = 16384 };

static char g_sd_pool[SD_POOL];        /* the realized find set */
static size_t g_sd_used;
static const char *g_sd_files[SD_MAXF];
static int g_sd_nfiles;
static char g_sd_git[SD_RAW];          /* the oracle capture */
static const char *g_sd_evec[SD_MAXF]; /* its lines */
static const char *g_sd_miss[SD_MAXF]; /* the comm -13 result */
static char g_sd_roots_buf[8192];
static const char *g_sd_rvec[64];
static int g_sd_nroots;

/* ── small buffer/path utilities ───────────────────────────────────────── */

static int sd_cat(char *buf, size_t cap, size_t *n, const char *s)
{
    if (*n >= cap)
        return die("z23-lint: derived buffer overflow\n", "");
    int k = snprintf(buf + *n, cap - *n, "%s", s);
    if (k < 0 || (size_t)k >= cap - *n)
        return die("z23-lint: derived buffer overflow\n", "");
    *n += (size_t)k;
    return 0;
}

static int sd_catq(char *buf, size_t cap, size_t *n, const char *arg)
{
    char q[8192];
    int rc = sh_single_quote(arg, q, sizeof q);
    if (rc == 0)
        rc = sd_cat(buf, cap, n, q);
    return rc;
}

static int sd_pool_add(const char *path)
{
    if (g_sd_nfiles >= SD_MAXF)
        return die("z23-lint: scan-set overflow\n", "");
    size_t n = strlen(path) + 1;
    if (g_sd_used + n > SD_POOL)
        return die("z23-lint: derived buffer overflow\n", "");
    char *dst = g_sd_pool + g_sd_used;
    memcpy(dst, path, n);
    g_sd_files[g_sd_nfiles++] = dst;
    g_sd_used += n;
    return 0;
}

/* IFS-split (space/tab/newline, runs collapse) like `read -r -a`. */
int sd_split_words(const char *s, char *buf, size_t cap,
                   const char **vec, int max, int *out_n)
{
    if (ovf(snprintf(buf, cap, "%s", s), cap))
        return 2;
    int n = 0;
    char *p = buf;
    while (*p) {
        while (*p == ' ' || *p == '\t' || *p == '\n')
            p++;
        if (!*p)
            break;
        if (n >= max)
            return die("z23-lint: scan-set overflow\n", "");
        vec[n++] = p;
        while (*p && *p != ' ' && *p != '\t' && *p != '\n')
            p++;
        if (*p)
            *p++ = '\0';
    }
    *out_n = n;
    return 0;
}

static int sd_ptr_cmp(const void *a, const void *b)
{
    return strcmp(*(const char *const *)a, *(const char *const *)b);
}

/* LC_ALL=C sort -u: bytewise order, exact-duplicate collapse. */
static int sd_sort_uniq(const char **v, int n)
{
    qsort(v, (size_t)n, sizeof v[0], sd_ptr_cmp);
    int w = 0;
    for (int i = 0; i < n; i++) {
        if (w > 0 && strcmp(v[w - 1], v[i]) == 0)
            continue;
        v[w++] = v[i];
    }
    return w;
}

/* ── the find mirror ───────────────────────────────────────────────────── */

/* find <root> -type f -name '*.c' 2>/dev/null: diagnostics dropped, so a
 * missing or unreadable entry is skipped, never fatal; symlinks are not
 * followed; a root that is itself a *.c regular file counts. */
static int sd_walk(const char *root);

static int sd_walk_entry(const char *root, const char *nm)
{
    size_t rl = strlen(root);
    char path[4096];
    int k = snprintf(path, sizeof path, "%s%s%s", root,
                     rl > 0 && root[rl - 1] == '/' ? "" : "/", nm);
    if (k < 0 || (size_t)k >= sizeof path)
        return die("z23-lint: path too long: %s\n", root);
    return sd_walk(path);
}

static int sd_walk(const char *root)
{
    struct stat st;
    if (lstat(root, &st) != 0)
        return 0;
    if (S_ISREG(st.st_mode)) {
        size_t nl = strlen(root);
        if (nl >= 2 && root[nl - 2] == '.' && root[nl - 1] == 'c')
            return sd_pool_add(root);
        return 0;
    }
    if (!S_ISDIR(st.st_mode))
        return 0;
    struct dirent **names = NULL;
    int n = scandir(root, &names, NULL, alphasort);
    if (n < 0)
        return 0;
    int rc = 0;
    for (int i = 0; i < n && rc == 0; i++) {
        const char *nm = names[i]->d_name;
        if (strcmp(nm, ".") != 0 && strcmp(nm, "..") != 0)
            rc = sd_walk_entry(root, nm);
        free(names[i]);
    }
    free(names);
    return rc;
}

/* ── the coverage check (gate_require_git_coverage, in memory) ─────────── */

/* git ls-files --cached -- <quoted specs> 2>/dev/null, stdout captured. */
static int sd_git_ls(const char *quoted, char *out, size_t cap, int *code)
{
    char cmd[SD_CMD];
    size_t n = 0;
    int rc = sd_cat(cmd, sizeof cmd, &n, "git ls-files --cached -- ");
    rc |= sd_cat(cmd, sizeof cmd, &n, quoted);
    rc |= sd_cat(cmd, sizeof cmd, &n, " 2>/dev/null");
    if (rc)
        return rc;
    return capture_cmd(cmd, out, cap, code);
}

/* The per-declared-root non-emptiness probes: a renamed/emptied root would
 * empty the find and the pathspec together, so refuse to grade. */
static int sd_root_probes(void)
{
    for (size_t i = 0; i < SD_NROOTS; i++) {
        char spec[640], q[1400];
        int code = 0;
        int rc = ovf(snprintf(spec, sizeof spec, "%s/*.c", k_sd_roots[i]),
                     sizeof spec);
        if (rc == 0)
            rc = sh_single_quote(spec, q, sizeof q);
        if (rc == 0)
            rc = sd_git_ls(q, g_sd_git, sizeof g_sd_git, &code);
        if (rc)
            return rc;
        if (g_sd_git[0] == '\0') {
            fprintf(stderr, "%s: UNPROVEN — declared scan root\n"
                    "  '%s' tracks no *.c at all. A renamed/emptied\n"
                    "  root removes its surface from BOTH the find and the\n"
                    "  expectation, so the shortfall cancels and reads clean.\n"
                    "  Refusing to grade. Fix SUPDOM_ROOTS_DEFAULT, or drop the\n"
                    "  root if the code is genuinely gone.\n",
                    k_sd_name, k_sd_roots[i]);
            return 2;
        }
    }
    return 0;
}

/* Split the captured oracle output into lines (in place) and sort -u it. */
static int sd_oracle_lines(int *out_n)
{
    int n = 0;
    char *p = g_sd_git;
    while (*p) {
        if (n >= SD_MAXF)
            return die("z23-lint: scan-set overflow\n", "");
        g_sd_evec[n++] = p;
        char *nl = strchr(p, '\n');
        if (!nl)
            break;
        *nl = '\0';
        p = nl + 1;
    }
    *out_n = sd_sort_uniq(g_sd_evec, n);
    return 0;
}

/* comm -13 actual expected, both already sorted unique: entries the
 * independent oracle expected but the scan never reached. */
static int sd_missing(int nact, int nexp, int *out_m)
{
    int i = 0, j = 0, m = 0;
    while (j < nexp) {
        if (i < nact) {
            int c = strcmp(g_sd_evec[j], g_sd_files[i]);
            if (c > 0) {
                i++;
                continue;
            }
            if (c == 0) {
                i++;
                j++;
                continue;
            }
        }
        if (m >= SD_MAXF)
            return die("z23-lint: scan-set overflow\n", "");
        g_sd_miss[m++] = g_sd_evec[j++];
    }
    *out_m = m;
    return 0;
}

/* bash `[` integer operand: optional surrounding whitespace, an optional
 * sign, then decimal digits; empty, 0x.., trailing junk, and out-of-range
 * all read as "integer expression expected". Returns 1 when invalid. */
static int sd_allowance_parse(const char *s, long *v)
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

static int sd_cov_partial(int nact, int nexp, int nmiss, const char *allow)
{
    fprintf(stderr, "%s: UNPROVEN — the scan reached %d of the %d\n"
            "  entries an independent oracle says it should have reached;\n"
            "  %d missing, above the shrink-only allowance of\n"
            "  %s recorded in ZCL_SUPDOM_COVERAGE_ALLOWANCE.\n"
            "  This is a PARTIAL scan: not a clean one, and not a violating\n"
            "  one. 'I scanned less than my subject' is a third answer — the\n"
            "  gate never ran over the code it claims to cover, so it cannot\n"
            "  report either verdict. A file-count floor cannot see this;\n"
            "  the count stayed large.\n"
            "  Not reached (first 20 of %d):\n",
            k_sd_name, nact, nexp, nmiss, allow, nmiss);
    int show = nmiss < 20 ? nmiss : 20;
    for (int i = 0; i < show; i++)
        fprintf(stderr, "    %s\n", g_sd_miss[i]);
    if (nmiss > 20)
        fprintf(stderr, "    ... and %d more\n", nmiss - 20);
    fprintf(stderr, "  %s\n", k_sd_cov_hint);
    return 2;
}

static int sd_cov_stale(int nexp, int nmiss, const char *allow)
{
    fprintf(stderr, "%s: VIOLATION — the coverage allowance is stale: the "
            "scan now\n  misses only %d of %d expected entries, below\n"
            "  ZCL_SUPDOM_COVERAGE_ALLOWANCE=%s.\n"
            "  Coverage improved without lowering the allowance. An allowance\n"
            "  that may only ever rise stops meaning 'what we measured' and\n"
            "  starts meaning 'whatever nobody lowered' — a ratchet that\n"
            "  rusts shut. Lower ZCL_SUPDOM_COVERAGE_ALLOWANCE to %d, with "
            "the reason, in the\n  same commit.\n",
            k_sd_name, nmiss, nexp, allow, nmiss);
    return 1;
}

/* The git-index oracle: all five per-root *.c pathspecs in one call, its
 * rc and emptiness mapped to the two UNPROVEN blocks. */
static int sd_cov_oracle(int *out_nexp)
{
    char quoted[SD_CMD];
    size_t qn = 0;
    quoted[0] = '\0';
    int rc = 0;
    for (size_t i = 0; rc == 0 && i < SD_NROOTS; i++) {
        char spec[640];
        rc = ovf(snprintf(spec, sizeof spec, "%s/*.c", k_sd_roots[i]),
                 sizeof spec);
        if (rc == 0 && i > 0)
            rc = sd_cat(quoted, sizeof quoted, &qn, " ");
        if (rc == 0)
            rc = sd_catq(quoted, sizeof quoted, &qn, spec);
    }
    int code = 0;
    if (rc == 0)
        rc = sd_git_ls(quoted, g_sd_git, sizeof g_sd_git, &code);
    if (rc)
        return rc;
    if (code != 0) {
        fprintf(stderr, "%s: UNPROVEN — the coverage oracle could not run:\n"
                "  'git ls-files -- %s' exited %d.\n"
                "  Without an independent expectation this gate cannot tell a\n"
                "  complete scan from a partial one, so it refuses to grade\n"
                "  either way. Run it from inside the checkout.\n",
                k_sd_name, k_sd_specs, code);
        return 2;
    }
    rc = sd_oracle_lines(out_nexp);
    if (rc)
        return rc;
    if (*out_nexp == 0) {
        fprintf(stderr, "%s: UNPROVEN — the coverage oracle is empty: git "
                "tracks no\n  file matching: %s\n"
                "  An empty expectation would pass every scan, including a "
                "scan\n  of nothing. Refusing to vouch for coverage off a "
                "hollow\n  oracle. Fix the pathspec, or drop the coverage "
                "check if the\n  set is genuinely gone.\n",
                k_sd_name, k_sd_specs);
        return 2;
    }
    return 0;
}

static int sd_coverage(void)
{
    int rc = sd_root_probes();
    int nexp = 0, nmiss = 0, nact = 0;
    if (rc == 0)
        rc = sd_cov_oracle(&nexp);
    if (rc == 0) {
        nact = sd_sort_uniq(g_sd_files, g_sd_nfiles);
        rc = sd_missing(nact, nexp, &nmiss);
    }
    if (rc)
        return rc;
    const char *allow = env_or("ZCL_SUPDOM_COVERAGE_ALLOWANCE", "0");
    long al = 0;
    if (sd_allowance_parse(allow, &al)) {
        fprintf(stderr, "tools/lint/gate_lib.sh: line 307: [: %s: integer "
                "expression expected\ntools/lint/gate_lib.sh: line 327: "
                "[: %s: integer expression expected\n", allow, allow);
        return 0;
    }
    if ((long)nmiss > al)
        return sd_cov_partial(nact, nexp, nmiss, allow);
    if ((long)nmiss < al)
        return sd_cov_stale(nexp, nmiss, allow);
    return 0;
}

/* ── the gate ──────────────────────────────────────────────────────────── */

static int sd_floor(void)
{
    char hint[8192];
    size_t n = 0;
    int rc = sd_cat(hint, sizeof hint, &n, "no *.c under: ");
    for (int i = 0; rc == 0 && i < g_sd_nroots; i++) {
        if (i > 0)
            rc = sd_cat(hint, sizeof hint, &n, " ");
        if (rc == 0)
            rc = sd_cat(hint, sizeof hint, &n, g_sd_rvec[i]);
    }
    if (rc)
        return rc;
    return gate_require_scanned(g_sd_nfiles, 1, k_sd_name, hint);
}

static int sd_run_body(void)
{
    int rc = sd_split_words(env_or("ZCL_SUPDOM_SCAN_ROOTS", k_sd_roots_default),
                            g_sd_roots_buf, sizeof g_sd_roots_buf, g_sd_rvec,
                            64, &g_sd_nroots);
    for (int i = 0; rc == 0 && i < g_sd_nroots; i++)
        rc = sd_walk(g_sd_rvec[i]);
    if (rc == 0)
        rc = sd_floor();
    if (rc == 0 && strcmp(env_or("ZCL_SUPDOM_COVERAGE", "1"), "1") == 0)
        rc = sd_coverage();
    if (rc)
        return rc;
    if (strcmp(env_or("ZCL_SUPDOM_COVERAGE_ONLY", "0"), "1") == 0) {
        printf("[%s] coverage-only: PASS (%d files reached)\n", k_sd_name,
               g_sd_nfiles);
        return 0;
    }
    const char *mode = env_or("ZCL_LINT_MODE", "FAIL");
    rc = supervisor_domain_scan_run(mode, g_sd_rvec, g_sd_nroots);
    if (rc == 0)
        rc = supervisor_domain_workers_run(mode);
    if (rc == 0)
        fputs("[check_supervisor_domain] PASS\n", stdout);
    return rc;
}

int check_supervisor_domain_run(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    char root[4096];
    int rc = cic_repo_root(root, sizeof root);
    if (rc == 0 && chdir(root) != 0)
        rc = 2;
    if (rc == 0)
        rc = sd_run_body();
    return rc;
}
