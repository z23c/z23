/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Gates: check-thread-supervision
 * Single-gate family, three files under the 700-line family ceiling:
 * gate_thread_supervision.c (this file) holds the find mirror, the
 * git-oracle coverage check, and the gate entry;
 * gate_thread_supervision_scan.c holds the baseline loader, the native
 * per-file spawn-site scan, and the verdict report; and
 * gate_thread_supervision_workers.c holds the gate's --selftest probes.
 * Placement ruling (2026-09-06, Linux side): new ports land in their own
 * files; the older in-file routing comments are overridden by that ruling.
 */

/* ── check-thread-supervision ─────────────────────────────────────────────
 * Byte-parity C23 port of tools/lint/check_thread_supervision.sh (Gate #23:
 * every long-running thread spawned via thread_registry_spawn( must be
 * SUPERVISED — its TU registers a liveness contract or the spawn line (or
 * the line above) carries a '// supervised:<child>' marker — MARKED-EXEMPT
 * ('// thread-supervision-ok:<reason>' on the spawn line or the line
 * above), or BASELINED in tools/lint/thread_supervision_baseline.txt
 * (shrink-only: a stale or newly-redundant entry also fails)). Spawn-free
 * per the fleet ruling: no subprocess runs anywhere in this gate.
 *
 * Semantic mapping (this file):
 * - Scan roots: ZCL_THREADSUP_SCAN_ROOTS, IFS-split like `read -r -a`
 *   (the supervisor-domain family's sd_split_words), default
 *   "core engine contexts cognition platform"; env_or's unset-or-empty
 *   fallback matches ${VAR:-default}.
 * - The find pipeline: `find <roots> -type f -name '*.c' 2>/dev/null` is
 *   ts_walk (diagnostics dropped like the shell's 2>/dev/null, symlinks
 *   never followed as in find -P, a root that is itself a *.c file counts,
 *   a trailing-slash root joins without a doubled slash, a duplicated root
 *   is scanned again and counts twice). The four `grep -v` filters are
 *   ts_dropped: '/test/' and '/vendor/' are fixed substrings, 'fuzz' is an
 *   ASCII-fold substring (grep -i under LC_ALL=C), and the two seam files
 *   keep BRE regexec semantics (their dots match any character — a latent
 *   over-exclusion, reproduced, not repaired; the supervisor-domain
 *   precedent). lint_filter_excluded is lint_path_is_excluded per path
 *   (same ERE, one path per line, only when ZCL_LINT_PRODUCTION_SCAN=1).
 *   The trailing `sort` is a byte-order strcmp qsort — the deliberate,
 *   deterministic replacement for the shell's locale-collation sort;
 *   identical under LC_ALL=C, the A/B fixture locale on both sides. No -u:
 *   duplicate rows (a duplicated root) survive, exactly like the shell.
 * - The fail-loud floor is the shared gate_require_scanned, byte-identical
 *   to gate_lib.sh's text, with the shell's hint naming the roots in use.
 * - The coverage block (ZCL_THREADSUP_COVERAGE, default on):
 *   gate_require_git_coverage reimplemented in memory, with NO subprocess:
 *   the ls-files oracle reads .git/index natively via lint_git_index_foreach
 *   (index order, byte-sorted by name then stage, exactly ls-files order;
 *   each per-root pathspec — literal root, slash, then '*.c', a star that
 *   crosses '/' — is exactly prefix plus ".c" suffix, verified
 *   byte-identical against real git by the supervisor-domain port). The
 *   pathspec-magic exclusions on the oracle side are LITERAL: a '/test/'
 *   or '/vendor/' component substring, an ASCII-fold 'fuzz' substring, and
 *   the two seam files by byte equality — NOT the find side's regex (the
 *   shell's own asymmetry: `grep -v` is a regex, ':(exclude)<path>' is
 *   literal). The per-declared-root emptiness probes are ts_root_probes,
 *   derived from the fixed default roots, never the override; a reader
 *   failure there reads as EMPTY (the shell's `|| true` mask) and hits the
 *   per-root UNPROVEN — except a MANDATORY-extension refusal, which is
 *   named (ts_oracle_badext; the verifier-ruled native-only block, the
 *   sd_oracle_badext pattern). A reader failure on the main oracle maps to
 *   the "could not run" UNPROVEN reporting git's generic fatal code 128
 *   (the shell discarded git's stderr, so no diagnostic may precede the
 *   block). Both sets are LC_ALL=C sort -u (qsort/strcmp, ts_sort_uniq);
 *   the shell's actual set is deduped on a COPY (ts_act) so the raw file
 *   vector — duplicates and all — still feeds the scan, exactly like the
 *   shell's ${files[@]}; comm -13 is the ts_missing merge; and
 *   gate_require_coverage's three-way verdict stands: missing > allowance
 *   is the partial-scan UNPROVEN naming the first 20 (exit 2), missing <
 *   allowance is the stale-ratchet VIOLATION (exit 1), equal passes. The
 *   allowance string is printed verbatim, as the shell's $ expansion did.
 * - ZCL_THREADSUP_COVERAGE_ONLY=1 prints the coverage-only PASS line with
 *   the RAW find count (${#files[@]}), not the deduped one.
 * - The baseline loader, the per-file spawn-site scan, and the verdict
 *   report live in gate_thread_supervision_scan.c; the --selftest probes
 *   live in gate_thread_supervision_workers.c.
 *
 * Preserved latent defects / parity notes:
 * - REPAIRED BY VERIFIER RULING (the model-column-drift precedent,
 *   f7e1d583f): the shell baseline loop `while read -r name _rest` silently
 *   DROPS an unterminated final baseline line (read fails at EOF without
 *   the delimiter, so the body never runs for it) — a fail-open defect,
 *   since a dropped row is neither matched nor stale-checked. The port
 *   reads the final row like the others. The A/B harness classifies that
 *   one fixture EXPECTED-DIVERGE; every other input stays byte-identical.
 * - An unreadable but REGULAR baseline, or one whose touch fails (a
 *   missing parent): the shell dies on the failed redirection / touch with
 *   bash's or touch's own message and exit 1; the port die()s exit 2.
 *   Environment failure, not a gate verdict (the model-column-drift
 *   precedent). A baseline that is a DIRECTORY: touch succeeds (setting
 *   times on a directory is allowed) and the redirection then fails
 *   "Is a directory", exit 1; the port die()s exit 2.
 * - Stale-row report order: the shell iterates a bash ASSOCIATIVE array
 *   (hash order, unspecified); the port emits baseline FILE order.
 *   Identical for zero or one stale row; a multi-stale report orders
 *   differently (the controller-private-headers / model-column-drift
 *   precedent — bash's bucket order is not a stable contract).
 * - An unreadable scan file reproduces grep's own
 *   "grep: <path>: <strerror>" on stderr, once per grep the shell runs
 *   against it (the coverage probe and the row scan — two identical
 *   lines), with no records: the shell never checks those greps' exit
 *   codes, so an unreadable file's spawn sites are invisible (a fail-open
 *   corner, reproduced byte-exactly like the model-column-drift port's
 *   `|| true` funnel; in the real tree the git coverage oracle bounds the
 *   blast radius to readability, since find still lists the file).
 * - File names containing a newline: the shell's mapfile/printf pipeline
 *   counts LINES (such a file reads as several entries and mismatches the
 *   git oracle); the port counts FILES. No such name exists in the tree.
 * - The oracle's "could not run" UNPROVEN reports 128 (git's generic
 *   fatal code) where the shell printed git's real exit code, and the
 *   native index reader assumes the SHA-1 entry layout — any other object
 *   format desyncs its structural checks and fails closed into that same
 *   UNPROVEN.
 * - The shell was unbounded; the port's fixed pools (scan set, oracle
 *   capture, record/name/baseline pools) fail closed with die() —
 *   environment exhaustion, not a verdict.
 * - The ZCL_GATE_SCAN_LOG audit hook of gate_lib.sh is not reproduced
 *   (lib.c precedent: "Non-parity: no ZCL_GATE_SCAN_LOG"). gate_lib.sh's
 *   mktemp scratch dirs are gone (the compare is in memory); their two
 *   FATALs were environment failures, never gate verdicts.
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

/* IFS-split helper shared with the supervisor-domain family. */
int sd_split_words(const char *s, char *buf, size_t cap,
                   const char **vec, int max, int *out_n);

/* The baseline, the spawn-site scan, and the verdict
 * (gate_thread_supervision_scan.c). */
int thread_supervision_scan_run(const char *const *files, int nfiles);

static const char k_ts_name[] = "check_thread_supervision";
static const char k_ts_roots_default[] =
    "core engine contexts cognition platform";
static const char *const k_ts_roots[] = {
    "core", "engine", "contexts", "cognition", "platform"
};
#define TS_NROOTS (sizeof k_ts_roots / sizeof k_ts_roots[0])
static const char k_ts_specs_all[] =
    "core/*.c engine/*.c contexts/*.c cognition/*.c platform/*.c"
    " :(exclude)*/test/*"
    " :(exclude,icase)*fuzz*"
    " :(exclude)*/vendor/*"
    " :(exclude)platform/modules/util/src/thread_registry.c"
    " :(exclude)platform/modules/util/src/supervisor.c";
static const char k_ts_cov_hint[] =
    "Re-run from a clean checkout. If a listed file genuinely left this "
    "gate's scope, move it out of core engine contexts cognition platform "
    "or add its exclusion to BOTH the find pipeline and the pathspec list "
    "above — raising ZCL_THREADSUP_COVERAGE_ALLOWANCE is a last resort "
    "and needs the reason written down.";

enum { TS_MAXF = 24576, TS_POOL = 1 << 20, TS_RAW = 1 << 20 };

static char g_ts_pool[TS_POOL];        /* the realized find set */
static size_t g_ts_used;
static const char *g_ts_files[TS_MAXF];
static int g_ts_nfiles;
static char g_ts_git[TS_RAW];          /* the oracle capture */
static size_t g_ts_git_used;
static const char *g_ts_evec[TS_MAXF]; /* its lines */
static const char *g_ts_act[TS_MAXF];  /* the dedupe copy of the scan set */
static const char *g_ts_miss[TS_MAXF]; /* the comm -13 result */
static char g_ts_roots_buf[8192];
static const char *g_ts_rvec[64];
static int g_ts_nroots;
static regex_t g_ts_seam[2];           /* the two seam-file BRE filters */

/* ── small buffer/path utilities ───────────────────────────────────────── */

static int ts_pool_add(const char *path)
{
    if (g_ts_nfiles >= TS_MAXF)
        return die("z23-lint: scan-set overflow\n", "");
    size_t n = strlen(path) + 1;
    if (g_ts_used + n > TS_POOL)
        return die("z23-lint: derived buffer overflow\n", "");
    char *dst = g_ts_pool + g_ts_used;
    memcpy(dst, path, n);
    g_ts_files[g_ts_nfiles++] = dst;
    g_ts_used += n;
    return 0;
}

static int ts_ptr_cmp(const void *a, const void *b)
{
    return strcmp(*(const char *const *)a, *(const char *const *)b);
}

/* LC_ALL=C sort -u: bytewise order, exact-duplicate collapse. */
static int ts_sort_uniq(const char **v, int n)
{
    qsort(v, (size_t)n, sizeof v[0], ts_ptr_cmp);
    int w = 0;
    for (int i = 0; i < n; i++) {
        if (w > 0 && strcmp(v[w - 1], v[i]) == 0)
            continue;
        v[w++] = v[i];
    }
    return w;
}

/* grep -i 'fuzz' under LC_ALL=C: ASCII-fold substring. */
static int ts_has_fuzz(const char *s)
{
    for (size_t i = 0; s[i]; i++) {
        char f[4];
        for (int k = 0; k < 4; k++) {
            unsigned char c = (unsigned char)s[i + k];
            f[k] = (char)(c >= 'A' && c <= 'Z' ? c + 32 : c);
        }
        if (memcmp(f, "fuzz", 4) == 0)
            return 1;
    }
    return 0;
}

/* ── the find mirror ───────────────────────────────────────────────────── */

/* The four `grep -v` filters plus lint_filter_excluded, per path: fixed
 * substrings for /test/ and /vendor/, the ASCII-fold fuzz, the two seam
 * files as BRE (their dots match any character, exactly like the shell),
 * then the production-scan exclusion ERE. */
static int ts_dropped(const char *path)
{
    if (strstr(path, "/test/") || ts_has_fuzz(path)
        || strstr(path, "/vendor/"))
        return 1;
    if (regexec(&g_ts_seam[0], path, 0, NULL, 0) == 0
        || regexec(&g_ts_seam[1], path, 0, NULL, 0) == 0)
        return 1;
    return lint_path_is_excluded(path);
}

/* find <root> -type f -name '*.c' 2>/dev/null: diagnostics dropped, so a
 * missing or unreadable entry is skipped, never fatal; symlinks are not
 * followed; a root that is itself a *.c regular file counts. The pipeline's
 * trailing sort makes traversal order irrelevant, so the walk keeps the
 * supervisor-domain family's scandir shape. */
static int ts_walk(const char *root);

static int ts_walk_entry(const char *root, const char *nm)
{
    size_t rl = strlen(root);
    char path[4096];
    int k = snprintf(path, sizeof path, "%s%s%s", root,
                     rl > 0 && root[rl - 1] == '/' ? "" : "/", nm);
    if (k < 0 || (size_t)k >= sizeof path)
        return die("z23-lint: path too long: %s\n", root);
    return ts_walk(path);
}

static int ts_walk(const char *root)
{
    struct stat st;
    if (lstat(root, &st) != 0)
        return 0;
    if (S_ISREG(st.st_mode)) {
        size_t nl = strlen(root);
        if (nl >= 2 && root[nl - 2] == '.' && root[nl - 1] == 'c'
            && !ts_dropped(root))
            return ts_pool_add(root);
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
            rc = ts_walk_entry(root, nm);
        free(names[i]);
    }
    free(names);
    return rc;
}

/* ── the coverage check (gate_require_git_coverage, in memory) ─────────── */

/* The mandatory index extension the reader last refused on ("" when the
 * last read was clean or failed for another reason). */
static char g_ts_badext[5];

/* A mandatory index extension ('link', 'sdir') the native reader refuses:
 * named per the verifier ruling, since reading past it could yield a
 * silently PARTIAL file list. The shell's real git interprets those
 * extensions, so this block has no shell counterpart — it is the native
 * reader failing closed where the shell could afford not to. */
static int ts_oracle_badext(void)
{
    fprintf(stderr, "%s: UNPROVEN — the git index carries a mandatory\n"
            "  extension ('%s') this native reader does not interpret;\n"
            "  reading past it could silently yield a PARTIAL file list\n"
            "  (a split index's shared entries, a sparse directory's\n"
            "  collapsed trees). Refusing to grade. Re-create the index\n"
            "  without split-index/sparse extensions, or teach\n"
            "  lint_git_index_foreach the extension first.\n",
            k_ts_name, g_ts_badext);
    return 2;
}

static const char *g_ts_probe_root;

/* The pathspec-magic exclusions on the oracle side, LITERAL (the shell's
 * own asymmetry with the find side's regex filters): the '/test/' and
 * '/vendor/' component substrings, the fold-case fuzz substring, and the
 * two seam files by byte equality. */
static int ts_oracle_excluded(const char *path)
{
    if (strstr(path, "/test/") || ts_has_fuzz(path)
        || strstr(path, "/vendor/"))
        return 1;
    return strcmp(path, "platform/modules/util/src/thread_registry.c") == 0
        || strcmp(path, "platform/modules/util/src/supervisor.c") == 0;
}

/* One index entry against the per-root '*.c' pathspecs: root prefix, a
 * slash, the ".c" suffix. In probe mode (a single root, no exclusions —
 * the shell's per-root probes carry no :(exclude) specs) the first match
 * ends the walk. */
static int ts_oracle_match(const char *path)
{
    size_t pl = strlen(path);
    for (size_t i = 0; i < TS_NROOTS; i++) {
        const char *r = g_ts_probe_root ? g_ts_probe_root : k_ts_roots[i];
        size_t rl = strlen(r);
        if (pl >= rl + 3 && strncmp(path, r, rl) == 0 && path[rl] == '/'
            && strcmp(path + pl - 2, ".c") == 0
            && (g_ts_probe_root || !ts_oracle_excluded(path)))
            return 1;
        if (g_ts_probe_root)
            break;
    }
    return 0;
}

static int ts_oracle_add(const char *path, int stage, void *ctx)
{
    (void)stage;
    (void)ctx;
    if (!ts_oracle_match(path))
        return 0;
    size_t n = strlen(path);
    if (g_ts_git_used + n + 2 > sizeof g_ts_git)
        return die("z23-lint: derived buffer overflow\n", "");
    memcpy(g_ts_git + g_ts_git_used, path, n);
    g_ts_git_used += n;
    g_ts_git[g_ts_git_used++] = '\n';
    g_ts_git[g_ts_git_used] = '\0';
    return g_ts_probe_root != NULL;
}

/* The per-declared-root non-emptiness probes: a renamed/emptied root would
 * empty the find and the pathspec together, so refuse to grade. The shell
 * masks git's rc with `|| true` here — a failed oracle reads as EMPTY and
 * hits this same UNPROVEN, so a native reader failure does too — except a
 * MANDATORY-extension refusal, which is named instead (verifier ruling). */
static int ts_root_probes(void)
{
    for (size_t i = 0; i < TS_NROOTS; i++) {
        g_ts_git_used = 0;
        g_ts_git[0] = '\0';
        g_ts_probe_root = k_ts_roots[i];
        (void)lint_git_index_foreach(ts_oracle_add, NULL, g_ts_badext);
        g_ts_probe_root = NULL;
        if (g_ts_badext[0])
            return ts_oracle_badext();
        if (g_ts_git[0] == '\0') {
            fprintf(stderr, "%s: UNPROVEN — declared scan root\n"
                    "  '%s' tracks no *.c at all. A renamed/emptied\n"
                    "  root removes its surface from BOTH the find and the\n"
                    "  expectation, so the shortfall cancels and reads clean.\n"
                    "  Refusing to grade. Fix THREADSUP_ROOTS_DEFAULT, or "
                    "drop the\n  root if the code is genuinely gone.\n",
                    k_ts_name, k_ts_roots[i]);
            return 2;
        }
    }
    return 0;
}

/* Split the captured oracle output into lines (in place) and sort -u it. */
static int ts_oracle_lines(int *out_n)
{
    int n = 0;
    char *p = g_ts_git;
    while (*p) {
        if (n >= TS_MAXF)
            return die("z23-lint: scan-set overflow\n", "");
        g_ts_evec[n++] = p;
        char *nl = strchr(p, '\n');
        if (!nl)
            break;
        *nl = '\0';
        p = nl + 1;
    }
    *out_n = ts_sort_uniq(g_ts_evec, n);
    return 0;
}

/* comm -13 actual expected, both already sorted unique: entries the
 * independent oracle expected but the scan never reached. The shell's
 * actual side is `sort -u` of the raw find set; the raw vector itself is
 * left untouched for the scan (a duplicated root still scans twice). */
static int ts_missing(int nact, int nexp, int *out_m)
{
    int i = 0, j = 0, m = 0;
    while (j < nexp) {
        if (i < nact) {
            int c = strcmp(g_ts_evec[j], g_ts_act[i]);
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
        if (m >= TS_MAXF)
            return die("z23-lint: scan-set overflow\n", "");
        g_ts_miss[m++] = g_ts_evec[j++];
    }
    *out_m = m;
    return 0;
}

/* bash `[` integer operand: optional surrounding whitespace, an optional
 * sign, then decimal digits; empty, 0x.., trailing junk, and out-of-range
 * all read as "integer expression expected". Returns 1 when invalid. */
static int ts_allowance_parse(const char *s, long *v)
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

static int ts_cov_partial(int nact, int nexp, int nmiss, const char *allow)
{
    fprintf(stderr, "%s: UNPROVEN — the scan reached %d of the %d\n"
            "  entries an independent oracle says it should have reached;\n"
            "  %d missing, above the shrink-only allowance of\n"
            "  %s recorded in ZCL_THREADSUP_COVERAGE_ALLOWANCE.\n"
            "  This is a PARTIAL scan: not a clean one, and not a violating\n"
            "  one. 'I scanned less than my subject' is a third answer — the\n"
            "  gate never ran over the code it claims to cover, so it cannot\n"
            "  report either verdict. A file-count floor cannot see this;\n"
            "  the count stayed large.\n"
            "  Not reached (first 20 of %d):\n",
            k_ts_name, nact, nexp, nmiss, allow, nmiss);
    int show = nmiss < 20 ? nmiss : 20;
    for (int i = 0; i < show; i++)
        fprintf(stderr, "    %s\n", g_ts_miss[i]);
    if (nmiss > 20)
        fprintf(stderr, "    ... and %d more\n", nmiss - 20);
    fprintf(stderr, "  %s\n", k_ts_cov_hint);
    return 2;
}

static int ts_cov_stale(int nexp, int nmiss, const char *allow)
{
    fprintf(stderr, "%s: VIOLATION — the coverage allowance is stale: the "
            "scan now\n  misses only %d of %d expected entries, below\n"
            "  ZCL_THREADSUP_COVERAGE_ALLOWANCE=%s.\n"
            "  Coverage improved without lowering the allowance. An allowance\n"
            "  that may only ever rise stops meaning 'what we measured' and\n"
            "  starts meaning 'whatever nobody lowered' — a ratchet that\n"
            "  rusts shut. Lower ZCL_THREADSUP_COVERAGE_ALLOWANCE to %d, with "
            "the reason, in the\n  same commit.\n",
            k_ts_name, nmiss, nexp, allow, nmiss);
    return 1;
}

/* The git-index oracle: the five per-root *.c pathspecs plus the five
 * :(exclude) specs in one index pass, its failure and emptiness mapped to
 * the two UNPROVEN blocks. The shell printed real git's exit code; the
 * native reader fails silently (the shell sent git's stderr to /dev/null,
 * so no diagnostic may precede this block), and the block reports git's
 * generic fatal code 128 — unreachable on any structurally valid index. */
static int ts_cov_oracle(int *out_nexp)
{
    g_ts_git_used = 0;
    g_ts_git[0] = '\0';
    int rc = lint_git_index_foreach(ts_oracle_add, NULL, g_ts_badext);
    if (rc && g_ts_badext[0])
        return ts_oracle_badext();
    if (rc) {
        fprintf(stderr, "%s: UNPROVEN — the coverage oracle could not run:\n"
                "  'git ls-files -- %s' exited %d.\n"
                "  Without an independent expectation this gate cannot tell a\n"
                "  complete scan from a partial one, so it refuses to grade\n"
                "  either way. Run it from inside the checkout.\n",
                k_ts_name, k_ts_specs_all, 128);
        return 2;
    }
    rc = ts_oracle_lines(out_nexp);
    if (rc)
        return rc;
    if (*out_nexp == 0) {
        fprintf(stderr, "%s: UNPROVEN — the coverage oracle is empty: git "
                "tracks no\n  file matching: %s\n"
                "  An empty expectation would pass every scan, including a "
                "scan\n  of nothing. Refusing to vouch for coverage off a "
                "hollow\n  oracle. Fix the pathspec, or drop the coverage "
                "check if the\n  set is genuinely gone.\n",
                k_ts_name, k_ts_specs_all);
        return 2;
    }
    return 0;
}

static int ts_coverage(void)
{
    int rc = ts_root_probes();
    int nexp = 0, nmiss = 0, nact = 0;
    if (rc == 0)
        rc = ts_cov_oracle(&nexp);
    if (rc == 0) {
        memcpy(g_ts_act, g_ts_files,
               sizeof g_ts_files[0] * (size_t)g_ts_nfiles);
        nact = ts_sort_uniq(g_ts_act, g_ts_nfiles);
        rc = ts_missing(nact, nexp, &nmiss);
    }
    if (rc)
        return rc;
    const char *allow = env_or("ZCL_THREADSUP_COVERAGE_ALLOWANCE", "0");
    long al = 0;
    if (ts_allowance_parse(allow, &al)) {
        fprintf(stderr, "tools/lint/gate_lib.sh: line 307: [: %s: integer "
                "expression expected\ntools/lint/gate_lib.sh: line 327: "
                "[: %s: integer expression expected\n", allow, allow);
        return 0;
    }
    if ((long)nmiss > al)
        return ts_cov_partial(nact, nexp, nmiss, allow);
    if ((long)nmiss < al)
        return ts_cov_stale(nexp, nmiss, allow);
    return 0;
}

/* ── the gate ──────────────────────────────────────────────────────────── */

static int ts_floor(void)
{
    char hint[8192];
    size_t n = 0;
    int k = snprintf(hint, sizeof hint, "%s", "no *.c under: ");
    if (k < 0 || (size_t)k >= sizeof hint)
        return die("z23-lint: derived buffer overflow\n", "");
    n = (size_t)k;
    for (int i = 0; i < g_ts_nroots; i++) {
        k = snprintf(hint + n, sizeof hint - n, "%s%s", i > 0 ? " " : "",
                     g_ts_rvec[i]);
        if (k < 0 || (size_t)k >= sizeof hint - n)
            return die("z23-lint: derived buffer overflow\n", "");
        n += (size_t)k;
    }
    k = snprintf(hint + n, sizeof hint - n, "%s",
                 " — was a production dir renamed/moved?");
    if (k < 0 || (size_t)k >= sizeof hint - n)
        return die("z23-lint: derived buffer overflow\n", "");
    return gate_require_scanned(g_ts_nfiles, 1, k_ts_name, hint);
}

static int ts_run_body(void)
{
    int rc = sd_split_words(env_or("ZCL_THREADSUP_SCAN_ROOTS",
                                   k_ts_roots_default),
                            g_ts_roots_buf, sizeof g_ts_roots_buf, g_ts_rvec,
                            64, &g_ts_nroots);
    for (int i = 0; rc == 0 && i < g_ts_nroots; i++)
        rc = ts_walk(g_ts_rvec[i]);
    if (rc == 0) {
        qsort(g_ts_files, (size_t)g_ts_nfiles, sizeof g_ts_files[0],
              ts_ptr_cmp);
        rc = ts_floor();
    }
    if (rc == 0 && strcmp(env_or("ZCL_THREADSUP_COVERAGE", "1"), "1") == 0)
        rc = ts_coverage();
    if (rc)
        return rc;
    if (strcmp(env_or("ZCL_THREADSUP_COVERAGE_ONLY", "0"), "1") == 0) {
        printf("%s: coverage-only PASS (%d files reached)\n", k_ts_name,
               g_ts_nfiles);
        return 0;
    }
    return thread_supervision_scan_run(g_ts_files, g_ts_nfiles);
}

int check_thread_supervision_run(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    char root[4096];
    int rc = cic_repo_root(root, sizeof root);
    if (rc == 0 && chdir(root) != 0)
        rc = 2;
    if (rc == 0)
        rc = reg_fail(&g_ts_seam[0], regcomp(&g_ts_seam[0],
                      "platform/modules/util/src/thread_registry.c", 0));
    if (rc == 0)
        rc = reg_fail(&g_ts_seam[1], regcomp(&g_ts_seam[1],
                      "platform/modules/util/src/supervisor.c", 0));
    if (rc == 0)
        rc = ts_run_body();
    regfree(&g_ts_seam[0]);
    regfree(&g_ts_seam[1]);
    return rc;
}
