/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Gates: check-controller-private-headers
 * Single-gate family, two files under the 700-line family ceiling:
 * gate_controller_private_headers.c (this file) holds the gate body — the
 * collect mirror, the per-file include scan, the baseline loader, the
 * shrink-only verdict — and gate_controller_private_headers_workers.c holds
 * the gate's --selftest probes. Placement ruling (2026-09-06, Linux side):
 * the small-pattern, ratchet, tree-walk, and git-scan families are claimed
 * or full, so new ports land in their own files; the older in-file routing
 * comments that would have folded this gate into an existing family are
 * overridden by that ruling.
 */

/* ── check-controller-private-headers ──────────────────────────────────────
 * Byte-parity C23 port of tools/lint/check_controller_private_headers.sh
 * (a header named controllers/<owner>_internal.h or <owner>_private.h
 * belongs to the dynamically-derived <owner> source family; every include
 * from outside that family, outside another *_internal.h/_private.h
 * controller header, and outside test code is an external private
 * dependency pinned by an exact shrink-only baseline — new and stale rows
 * both fail).
 *
 * Semantic mapping (original at 7bb688840):
 * - Env: ZCL_CONTROLLER_PRIVATE_SCAN_ROOT (default ".", `:-` so empty reads
 *   as "."), ZCL_CONTROLLER_PRIVATE_HEADER_ROOT (default empty),
 *   ZCL_CONTROLLER_PRIVATE_BASELINE (default
 *   tools/lint/controller_private_header_baseline.txt) — env_or's
 *   unset-or-empty fallback matches ${VAR:-...} exactly.
 * - collect_files is cph_collect: in "." mode the REAL
 *   `git ls-files -- '*.c' '*.h'`, otherwise the REAL
 *   `find "$SCAN_ROOT" -type f \( -name '*.c' -o -name '*.h' \) | sort`,
 *   both through capture_cmd with the same argv, so traversal order, the
 *   ambient-locale sort, and stderr diagnostics (inherited) are identical
 *   by construction. The pipeline's exit status is ignored exactly as the
 *   shell's mapfile ignored its process substitution (even under
 *   pipefail the substitution's rc never reached mapfile).
 * - display_path is cph_display: strip the literal prefix "$SCAN_ROOT/"
 *   only when it truly prefixes the collected path. A trailing-slash scan
 *   root never matches (find prints no doubled slash), so the prefix stays
 *   — exactly like ${file#"$SCAN_ROOT"/}.
 * - is_test_path is cph_is_test: the six bash case patterns via fnmatch
 *   without FNM_PATHNAME ('*' crosses '/', as in bash case).
 * - The per-file `grep -nE <ere> "$file" || true` piped through the sed
 *   extraction `s@^[0-9]+:...\1@p` is ONE capture-group ERE per line
 *   (cph_scan_file): the sed pattern sees grep's "N:" prefix and is
 *   otherwise the same ERE with the include path captured, and every
 *   grep-matched line also matches the sed pattern, so group 1 is the
 *   include — both sides resolve the ERE with glibc regexec. An open
 *   failure reproduces grep's own "grep: <file>: <strerror>" diagnostic
 *   and is swallowed like the shell's `|| true`.
 * - The exclusion predicates keep the original's exact anchoring: the
 *   composing-private-header skip is a *_internal/_private suffix case on
 *   the includer's extensionless basename; the owning-family skip applies
 *   only under a ".../controllers/src/..." path and matches base == owner
 *   or owner_* (cph_exempt). owner = include leaf minus %_internal.h then
 *   %_private.h; base = basename minus ${base%.*} (from the LAST dot).
 * - Edge format is the shell's printf '%s:#include "%s"\n' — always the
 *   quoted form, even when the source line used angle brackets.
 * - The private-header presence check: with HEADER_ROOT, the REAL
 *   `find "$HEADER_ROOT" -maxdepth 1 -type f \( -name '*_internal.h' -o
 *   -name '*_private.h' \) -print` (unsorted, rc ignored) counted by lines;
 *   without it, the grep -E '(^|/)controllers/include/controllers/...
 *   _internal|private.h$' over the RAW collected paths (the (^|/) anchor
 *   sees the still-unstripped scan-root prefix). Only the count is used.
 * - Preflight order and text are the shell's: scan root missing, no C/H
 *   inputs, header root missing, no private headers, baseline missing —
 *   all UNPROVEN exit 2.
 * - `scan_external_edges | sort -u` runs under the AMBIENT locale (the
 *   script sets no LC_ALL): qsort by strcoll after the caller's
 *   setlocale(LC_COLLATE, ""), and collation-equal lines collapse the way
 *   sort -u drops them — the gate_framework_shape.c /
 *   gate_zclassicd_reach.c precedent.
 * - Verdict: no new and no stale -> the stdout PASS line with the
 *   post-sort -u edge count; otherwise the FAIL block(s) on stderr (new
 *   edges in sorted order first, then stale rows) and exit 1.
 *
 * Baseline: NOT a lint_base_load / lint_base_load_set client. Rows are
 * verbatim edge strings with no :M pin, so the exact-pin ratchet contract
 * does not apply; and the set loader would trim whitespace, strip '#'
 * ANYWHERE, collapse duplicates silently, and treat a missing file as an
 * empty set — while this gate skips only lines whose first non-blank
 * character is '#', keeps rows byte-verbatim (trailing whitespace never
 * matches an edge), fails UNPROVEN exit 2 on a duplicate row, fails
 * UNPROVEN on an unreadable baseline, and fails on STALE rows (no
 * superset allowance). cph_load_baseline keeps the shell's true
 * semantics.
 *
 * Preserved latent defects / parity notes:
 * - `while IFS= read -r row` silently DROPS an unterminated final baseline
 *   line (read fails at EOF without the delimiter, so the loop body never
 *   runs for it). Reproduced byte-exactly: cph_load_baseline requires the
 *   '\n'. Flagged, not repaired.
 * - Stale-row report order: the shell iterates a bash ASSOCIATIVE array,
 *   i.e. hash order (unspecified); the port emits baseline FILE order.
 *   Identical for zero or one stale row; a multi-stale report orders
 *   differently. bash's bucket order is not a stable contract, so this is
 *   documented rather than mimicked.
 * - `[ -r "$BASELINE" ]` passes for a readable DIRECTORY; the shell then
 *   dies in the read loop with bash's "Is a directory" redirection error
 *   (exit 1). The port's fopen succeeds and the first getline fails with
 *   EISDIR: fin() reports "z23-lint: read failed" exit 2. Pathological
 *   environment failure, not a gate verdict.
 * - A NUL-bearing source reads as "Binary file ... matches" under grep and
 *   yields no edges; the port scans it line-wise. No such file is tracked.
 * - A newline inside a file name: the shell's mapfile counts LINES, the
 *   port counts the same lines (identical); only a name with a TRAILING
 *   newline differs (capture_cmd strips the trailing run). No such name
 *   exists in the tree.
 * - The shell was unbounded; the port's fixed pools (capture, edges,
 *   baseline rows) fail closed with die().
 * - capture_cmd maps a signalled child to exit 127 where the shell
 *   recorded 128+sig; the collect/presence exit codes are ignored on both
 *   sides, so this is unreachable here.
 */

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <errno.h>
#include <fnmatch.h>
#include <locale.h>
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "lintc.h"

static const char k_cph_name[] = "check_controller_private_headers";
static const char k_cph_baseline_default[] =
    "tools/lint/controller_private_header_baseline.txt";

enum { CPH_MAXF = 8192, CPH_RAW = 1 << 20, CPH_MAXE = 8192,
       CPH_EPOOL = 1 << 20, CPH_MAXB = 4096, CPH_BPOOL = 1 << 20,
       CPH_CMD = 16384, CPH_LINE = 8192, CPH_HDRS = 262144 };

static char g_cph_raw[CPH_RAW];       /* the collect capture, split in place */
static const char *g_cph_files[CPH_MAXF];
static int g_cph_nfiles;
static char g_cph_epool[CPH_EPOOL];   /* the realized edges */
static size_t g_cph_eused;
static const char *g_cph_edges[CPH_MAXE];
static int g_cph_nedges;
static const char *g_cph_new[CPH_MAXE]; /* the new-edge report */
static char g_cph_bpool[CPH_BPOOL];   /* the verbatim baseline rows */
static size_t g_cph_bused;
static const char *g_cph_rows[CPH_MAXB];
static int g_cph_seen[CPH_MAXB];
static int g_cph_nrows;
static regex_t g_cph_inc;     /* the grep+sed include matcher, one capture */
static regex_t g_cph_comment; /* the baseline's ^[[:space:]]*# skip */
static regex_t g_cph_priv;    /* the private-header path grep */

/* ── small buffer/path utilities ───────────────────────────────────────── */

static int cph_cat(char *buf, size_t cap, size_t *n, const char *s)
{
    if (*n >= cap)
        return die("z23-lint: derived buffer overflow\n", "");
    int k = snprintf(buf + *n, cap - *n, "%s", s);
    if (k < 0 || (size_t)k >= cap - *n)
        return die("z23-lint: derived buffer overflow\n", "");
    *n += (size_t)k;
    return 0;
}

static int cph_pool(char *pool, size_t cap, size_t *used, const char *s,
                    const char **out)
{
    size_t n = strlen(s) + 1;
    if (*used + n > cap)
        return die("z23-lint: derived buffer overflow\n", "");
    char *dst = pool + *used;
    memcpy(dst, s, n);
    *used += n;
    *out = dst;
    return 0;
}

/* ── collect_files ─────────────────────────────────────────────────────── */

/* Split the capture into its mapfile entries, in place: interior empty
 * lines are entries too, as they were for mapfile. */
static int cph_split(void)
{
    int n = 0;
    char *p = g_cph_raw;
    while (*p) {
        if (n >= CPH_MAXF)
            return die("z23-lint: scan-set overflow\n", "");
        g_cph_files[n++] = p;
        char *nl = strchr(p, '\n');
        if (!nl)
            break;
        *nl = '\0';
        p = nl + 1;
    }
    g_cph_nfiles = n;
    return 0;
}

static int cph_collect(const char *root)
{
    char cmd[CPH_CMD];
    size_t n = 0;
    cmd[0] = '\0';
    int rc = 0;
    if (strcmp(root, ".") == 0) {
        rc = cph_cat(cmd, sizeof cmd, &n, "git ls-files -- '*.c' '*.h'");
    } else {
        char q[8192];
        rc = sh_single_quote(root, q, sizeof q);
        if (rc == 0)
            rc = cph_cat(cmd, sizeof cmd, &n, "find ");
        if (rc == 0)
            rc = cph_cat(cmd, sizeof cmd, &n, q);
        if (rc == 0)
            rc = cph_cat(cmd, sizeof cmd, &n,
                         " -type f \\( -name '*.c' -o -name '*.h' \\) | sort");
    }
    int code = 0;
    if (rc == 0)
        rc = capture_cmd(cmd, g_cph_raw, sizeof g_cph_raw, &code);
    if (rc == 0)
        rc = cph_split();
    return rc;
}

/* display_path: see the file header for the trailing-slash case. */
static const char *cph_display(const char *file, const char *root)
{
    if (strcmp(root, ".") == 0)
        return file;
    size_t rl = strlen(root);
    if (strncmp(file, root, rl) == 0 && file[rl] == '/')
        return file + rl + 1;
    return file;
}

/* is_test_path: the six bash case patterns; fnmatch without FNM_PATHNAME
 * lets '*' cross '/', like bash's case. */
static int cph_is_test(const char *path)
{
    static const char *const pats[] = {
        "tests/*", "lib/test/*", "*/test/*", "*/tests/*",
        "*/test_*.c", "*/test_*.h",
    };
    for (size_t i = 0; i < sizeof pats / sizeof pats[0]; i++)
        if (fnmatch(pats[i], path, 0) == 0)
            return 1;
    return 0;
}

/* ── scan_external_edges ───────────────────────────────────────────────── */

/* owner = include leaf minus %_internal.h, then minus %_private.h. */
static int cph_owner(const char *include, char *out, size_t cap)
{
    const char *leaf = strrchr(include, '/');
    leaf = leaf ? leaf + 1 : include;
    if (ovf(snprintf(out, cap, "%s", leaf), cap))
        return 2;
    size_t n = strlen(out);
    if (n >= 11 && strcmp(out + n - 11, "_internal.h") == 0)
        out[n -= 11] = '\0';
    if (n >= 10 && strcmp(out + n - 10, "_private.h") == 0)
        out[n - 10] = '\0';
    return 0;
}

/* base = display-path basename minus ${base%.*} (from the LAST dot). */
static int cph_base(const char *path, char *out, size_t cap)
{
    const char *leaf = strrchr(path, '/');
    leaf = leaf ? leaf + 1 : path;
    if (ovf(snprintf(out, cap, "%s", leaf), cap))
        return 2;
    char *dot = strrchr(out, '.');
    if (dot)
        *dot = '\0';
    return 0;
}

/* The two exclusion predicates, anchoring preserved: a composing private
 * header (base ends _internal/_private), then — only under a path matching
 * the controllers/src/ shape — the owning family (base == owner or
 * owner_*). */
static int cph_exempt(const char *path, const char *base, const char *owner)
{
    if (fnmatch("*_internal", base, 0) == 0
        || fnmatch("*_private", base, 0) == 0)
        return 1;
    if (fnmatch("*/controllers/src/*", path, 0) != 0)
        return 0;
    size_t bl = strlen(base), ol = strlen(owner);
    if (bl == ol && memcmp(base, owner, ol) == 0)
        return 1;
    return bl > ol && memcmp(base, owner, ol) == 0 && base[ol] == '_';
}

static int cph_edge_add(const char *path, const char *include)
{
    if (g_cph_nedges >= CPH_MAXE)
        return die("z23-lint: scan-set overflow\n", "");
    char buf[CPH_LINE];
    if (ovf(snprintf(buf, sizeof buf, "%s:#include \"%s\"", path, include),
            sizeof buf))
        return 2;
    return cph_pool(g_cph_epool, sizeof g_cph_epool, &g_cph_eused, buf,
                    &g_cph_edges[g_cph_nedges++]);
}

static int cph_scan_file(const char *file, const char *root)
{
    if (!*file)
        return 0;
    const char *path = cph_display(file, root);
    if (cph_is_test(path))
        return 0;
    FILE *f = fopen(file, "r");
    if (!f) {
        fprintf(stderr, "grep: %s: %s\n", file, strerror(errno));
        return 0;
    }
    char *line = NULL;
    size_t cap = 0;
    ssize_t len;
    int rc = 0;
    while (rc == 0 && (len = getline(&line, &cap, f)) >= 0) {
        regmatch_t m[2];
        if (regexec(&g_cph_inc, line, 2, m, 0) != 0)
            continue;
        size_t il = (size_t)(m[1].rm_eo - m[1].rm_so);
        if (il >= 4096) {
            rc = die("z23-lint: derived buffer overflow\n", "");
            break;
        }
        char inc[4096], owner[4096], base[4096];
        memcpy(inc, line + m[1].rm_so, il);
        inc[il] = '\0';
        rc = cph_owner(inc, owner, sizeof owner);
        if (rc == 0)
            rc = cph_base(path, base, sizeof base);
        if (rc == 0 && !cph_exempt(path, base, owner))
            rc = cph_edge_add(path, inc);
    }
    return fin(f, line, file, rc);
}

/* ── the private-header presence check ─────────────────────────────────── */

static int cph_count_lines(const char *buf, int *out)
{
    int n = 0;
    for (const char *p = buf; *p; ) {
        n++;
        const char *nl = strchr(p, '\n');
        if (!nl)
            break;
        p = nl + 1;
    }
    *out = n;
    return 0;
}

static int cph_priv_via_find(const char *hroot, int *out)
{
    char q[8192], cmd[CPH_CMD];
    size_t cn = 0;
    cmd[0] = '\0';
    int rc = sh_single_quote(hroot, q, sizeof q);
    if (rc == 0)
        rc = cph_cat(cmd, sizeof cmd, &cn, "find ");
    if (rc == 0)
        rc = cph_cat(cmd, sizeof cmd, &cn, q);
    if (rc == 0)
        rc = cph_cat(cmd, sizeof cmd, &cn,
                     " -maxdepth 1 -type f \\( -name '*_internal.h'"
                     " -o -name '*_private.h' \\) -print");
    static char buf[CPH_HDRS];
    int code = 0;
    if (rc == 0)
        rc = capture_cmd(cmd, buf, sizeof buf, &code);
    if (rc == 0)
        rc = cph_count_lines(buf, out);
    return rc;
}

static int cph_count_private(const char *hroot, int *out)
{
    if (hroot[0])
        return cph_priv_via_find(hroot, out);
    int n = 0;
    for (int i = 0; i < g_cph_nfiles; i++)
        n += regexec(&g_cph_priv, g_cph_files[i], 0, NULL, 0) == 0;
    *out = n;
    return 0;
}

/* ── the baseline (local loader; see the file header for why) ──────────── */

static int cph_baseline_row(const char *row)
{
    if (!*row || regexec(&g_cph_comment, row, 0, NULL, 0) == 0)
        return 0;
    for (int i = 0; i < g_cph_nrows; i++) {
        if (strcmp(g_cph_rows[i], row) == 0) {
            fprintf(stderr, "[%s] UNPROVEN: duplicate baseline row: %s\n",
                    k_cph_name, row);
            return 2;
        }
    }
    if (g_cph_nrows >= CPH_MAXB)
        return die("z23-lint: baseline overflow\n", "");
    int rc = cph_pool(g_cph_bpool, sizeof g_cph_bpool, &g_cph_bused, row,
                      &g_cph_rows[g_cph_nrows]);
    if (rc == 0)
        g_cph_seen[g_cph_nrows++] = 0;
    return rc;
}

static int cph_load_baseline(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return die("z23-lint: cannot open %s\n", path);
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    int rc = 0;
    g_cph_nrows = 0;
    while (rc == 0 && (n = getline(&line, &cap, f)) >= 0) {
        if (n == 0 || line[n - 1] != '\n')
            continue;
        line[n - 1] = '\0';
        rc = cph_baseline_row(line);
    }
    return fin(f, line, path, rc);
}

static int cph_base_find(const char *edge)
{
    for (int i = 0; i < g_cph_nrows; i++)
        if (strcmp(g_cph_rows[i], edge) == 0)
            return i;
    return -1;
}

/* ── the verdict ───────────────────────────────────────────────────────── */

static int cph_cmp(const void *a, const void *b)
{
    return strcoll(*(const char *const *)a, *(const char *const *)b);
}

/* sort -u under the ambient locale (the caller setlocale()s first):
 * collation-equal lines collapse the way sort -u drops them. */
static void cph_sort_uniq(void)
{
    qsort(g_cph_edges, (size_t)g_cph_nedges, sizeof g_cph_edges[0], cph_cmp);
    int w = 0;
    for (int i = 0; i < g_cph_nedges; i++) {
        if (w > 0 && strcoll(g_cph_edges[w - 1], g_cph_edges[i]) == 0)
            continue;
        g_cph_edges[w++] = g_cph_edges[i];
    }
    g_cph_nedges = w;
}

static int cph_verdict(void)
{
    int nnew = 0, nstale = 0;
    for (int i = 0; i < g_cph_nedges; i++) {
        int idx = cph_base_find(g_cph_edges[i]);
        if (idx >= 0)
            g_cph_seen[idx] = 1;
        else
            g_cph_new[nnew++] = g_cph_edges[i];
    }
    for (int i = 0; i < g_cph_nrows; i++)
        nstale += !g_cph_seen[i];
    if (nnew == 0 && nstale == 0) {
        printf("[%s] PASS (%d exact external edge(s), all in shrink-only "
               "baseline)\n", k_cph_name, g_cph_nedges);
        return 0;
    }
    if (nnew > 0) {
        fprintf(stderr, "[%s] FAIL: new controller-private dependency "
                "edge(s):\n", k_cph_name);
        for (int i = 0; i < nnew; i++)
            fprintf(stderr, "  %s\n", g_cph_new[i]);
    }
    if (nstale > 0) {
        fprintf(stderr, "[%s] FAIL: stale baseline row(s); remove paid-down "
                "debt:\n", k_cph_name);
        for (int i = 0; i < g_cph_nrows; i++)
            if (!g_cph_seen[i])
                fprintf(stderr, "  %s\n", g_cph_rows[i]);
    }
    return 1;
}

/* ── the gate ──────────────────────────────────────────────────────────── */

static int cph_dir(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0 && S_ISDIR(st.st_mode);
}

static int cph_preflight(const char *root, const char *hroot,
                         const char *baseline)
{
    if (!cph_dir(root)) {
        fprintf(stderr, "[%s] UNPROVEN: scan root missing: %s\n", k_cph_name,
                root);
        return 2;
    }
    int rc = cph_collect(root);
    if (rc)
        return rc;
    if (g_cph_nfiles == 0) {
        fprintf(stderr, "[%s] UNPROVEN: scan root has no C/H inputs: %s\n",
                k_cph_name, root);
        return 2;
    }
    if (hroot[0] && !cph_dir(hroot)) {
        fprintf(stderr, "[%s] UNPROVEN: controller header root missing: %s\n",
                k_cph_name, hroot);
        return 2;
    }
    int npriv = 0;
    rc = cph_count_private(hroot, &npriv);
    if (rc)
        return rc;
    if (npriv == 0) {
        fprintf(stderr, "[%s] UNPROVEN: no controller private headers in "
                "maintained source\n", k_cph_name);
        return 2;
    }
    if (access(baseline, R_OK) != 0) {
        fprintf(stderr, "[%s] UNPROVEN: baseline missing: %s\n", k_cph_name,
                baseline);
        return 2;
    }
    return 0;
}

static int cph_body(void)
{
    const char *root = env_or("ZCL_CONTROLLER_PRIVATE_SCAN_ROOT", ".");
    const char *hroot = env_or("ZCL_CONTROLLER_PRIVATE_HEADER_ROOT", "");
    const char *baseline = env_or("ZCL_CONTROLLER_PRIVATE_BASELINE",
                                  k_cph_baseline_default);
    int rc = cph_preflight(root, hroot, baseline);
    if (rc == 0)
        rc = cph_load_baseline(baseline);
    for (int i = 0; rc == 0 && i < g_cph_nfiles; i++)
        rc = cph_scan_file(g_cph_files[i], root);
    if (rc == 0) {
        (void)setlocale(LC_COLLATE, "");
        cph_sort_uniq();
        rc = cph_verdict();
    }
    return rc;
}

static int cph_comp(void)
{
    int cr = compile_pat(&g_cph_inc, REG_EXTENDED,
                         "^[[:space:]]*#include[[:space:]]+[\"<](",
                         "controllers/[^\">]+_(internal|private)\\.h",
                         ")[\">]", "");
    if (cr)
        return cr;
    cr = compile_pat(&g_cph_comment, REG_EXTENDED, "^[[:space:]]*#",
                     "", "", "");
    if (cr) {
        regfree(&g_cph_inc);
        return cr;
    }
    cr = compile_pat(&g_cph_priv, REG_EXTENDED,
                     "(^|/)controllers/include/controllers/",
                     "[^/]+_(internal|private)\\.h$", "", "");
    if (cr)
        drop2(&g_cph_inc, &g_cph_comment);
    return cr;
}

int check_controller_private_headers_run(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    char root[4096];
    int rc = cic_repo_root(root, sizeof root);
    if (rc == 0 && chdir(root) != 0)
        rc = 2;
    if (rc == 0)
        rc = cph_comp();
    if (rc == 0) {
        rc = cph_body();
        drop3(&g_cph_inc, &g_cph_comment, &g_cph_priv);
    }
    return rc;
}
