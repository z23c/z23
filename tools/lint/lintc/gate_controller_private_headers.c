/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Gates: check-controller-private-headers
 * Single-gate family, three files under the 700-line family ceiling:
 * gate_controller_private_headers.c (this file) holds the gate body — the
 * baseline loader, the byte-order sort, the shrink-only verdict, the
 * preflight, the gate entry; gate_controller_private_headers_scan.c holds
 * the native collect (git index / find mirror), the per-file include
 * scan, and the private-header presence count; and
 * gate_controller_private_headers_workers.c holds the gate's --selftest
 * probes. Placement ruling (2026-09-06, Linux side): the small-pattern,
 * ratchet, tree-walk, and git-scan families are claimed or full, so new
 * ports land in their own files; the older in-file routing comments that
 * would have folded this gate into an existing family are overridden by
 * that ruling.
 */

/* ── check-controller-private-headers ──────────────────────────────────────
 * Byte-parity C23 port of tools/lint/check_controller_private_headers.sh
 * (a header named controllers/<owner>_internal.h or <owner>_private.h
 * belongs to the dynamically-derived <owner> source family; every include
 * from outside that family, outside another *_internal.h/_private.h
 * controller header, and outside test code is an external private
 * dependency pinned by an exact shrink-only baseline — new and stale rows
 * both fail). Spawn-free per the verifier ruling on 0a5eb681d: no
 * subprocess runs anywhere in this gate.
 *
 * Semantic mapping (original at 7bb688840):
 * - Env: ZCL_CONTROLLER_PRIVATE_SCAN_ROOT (default ".", `:-` so empty reads
 *   as "."), ZCL_CONTROLLER_PRIVATE_HEADER_ROOT (default empty),
 *   ZCL_CONTROLLER_PRIVATE_BASELINE (default
 *   tools/lint/controller_private_header_baseline.txt) — env_or's
 *   unset-or-empty fallback matches ${VAR:-...} exactly.
 * - collect_files, the per-file include scan, and the private-header
 *   presence count are native — gate_controller_private_headers_scan.c
 *   carries their mapping notes.
 * - Preflight order and text are the shell's: scan root missing, no C/H
 *   inputs, header root missing, no private headers, baseline missing —
 *   all UNPROVEN exit 2.
 * - `scan_external_edges | sort -u` is qsort by strcmp with
 *   exact-duplicate collapse: BYTE order is the deliberate, deterministic
 *   replacement for the shell's locale-dependent sort -u — the gate must
 *   report the same order on every node. Identical under LC_ALL=C, which
 *   is the A/B fixture locale on both sides.
 * - Verdict: no new and no stale -> the stdout PASS line with the
 *   post-sort -u edge count; otherwise the FAIL block(s) on stderr (new
 *   edges in sorted order first, then stale rows) and exit 1.
 * - --selftest: gate_controller_private_headers_workers.c; the inner gate
 *   re-invocations go through the runtime's self-exec helper, unchanged.
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
 *   newline. Flagged, not repaired.
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
 * - The shell was unbounded; the port's fixed pools (file set, edges,
 *   baseline rows) fail closed with die().
 * - mktemp failure: shell exit 1 with mktemp's text; port die() exit 2
 *   (environment failure, the describe-budget precedent).
 * The scan-side parity notes (a silent git-index failure reading as the
 * empty list, find's locale-sensitive quoting, NUL-bearing files,
 * newline-in-filename) live in gate_controller_private_headers_scan.c.
 */

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "lintc.h"

/* The native collect + include scan (gate_controller_private_headers_scan.c). */
int cphs_comp(void);
void cphs_drop(void);
int cphs_collect(const char *root);
int cphs_nfiles(void);
int cphs_count_private(const char *hroot, int *out);
int cphs_scan_all(const char *root);
void cphs_sort_uniq(void);
const char *const *cphs_edges(int *out_n);

static const char k_cph_name[] = "check_controller_private_headers";
static const char k_cph_baseline_default[] =
    "tools/lint/controller_private_header_baseline.txt";

enum { CPH_MAXB = 4096, CPH_BPOOL = 1 << 20, CPH_MAXE = 8192 };

static char g_cph_bpool[CPH_BPOOL];   /* the verbatim baseline rows */
static size_t g_cph_bused;
static const char *g_cph_rows[CPH_MAXB];
static int g_cph_seen[CPH_MAXB];
static int g_cph_nrows;
static const char *g_cph_new[CPH_MAXE]; /* the new-edge report */
static regex_t g_cph_comment; /* the baseline's ^[[:space:]]*# skip */

/* ── the baseline (local loader; see the file header for why) ──────────── */

static int cph_pool_row(const char *row, const char **out)
{
    size_t n = strlen(row) + 1;
    if (g_cph_bused + n > sizeof g_cph_bpool)
        return die("z23-lint: derived buffer overflow\n", "");
    char *dst = g_cph_bpool + g_cph_bused;
    memcpy(dst, row, n);
    g_cph_bused += n;
    *out = dst;
    return 0;
}

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
    int rc = cph_pool_row(row, &g_cph_rows[g_cph_nrows]);
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

static int cph_verdict(void)
{
    int nedges = 0;
    const char *const *edges = cphs_edges(&nedges);
    int nnew = 0, nstale = 0;
    for (int i = 0; i < nedges; i++) {
        int idx = cph_base_find(edges[i]);
        if (idx >= 0)
            g_cph_seen[idx] = 1;
        else
            g_cph_new[nnew++] = edges[i];
    }
    for (int i = 0; i < g_cph_nrows; i++)
        nstale += !g_cph_seen[i];
    if (nnew == 0 && nstale == 0) {
        printf("[%s] PASS (%d exact external edge(s), all in shrink-only "
               "baseline)\n", k_cph_name, nedges);
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
    int rc = cphs_collect(root);
    if (rc)
        return rc;
    if (cphs_nfiles() == 0) {
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
    rc = cphs_count_private(hroot, &npriv);
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
    /* The shell runs collect_files TWICE: once into mapfile for the
     * preflight (cph_preflight above), then again inside
     * scan_external_edges — so find's diagnostics surface twice. This
     * second collection replaces the file set the scan iterates. */
    if (rc == 0)
        rc = cphs_collect(root);
    if (rc == 0)
        rc = cphs_scan_all(root);
    if (rc == 0) {
        cphs_sort_uniq();
        rc = cph_verdict();
    }
    return rc;
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
        rc = compile_pat(&g_cph_comment, REG_EXTENDED, "^[[:space:]]*#",
                         "", "", "");
    if (rc == 0)
        rc = cphs_comp();
    if (rc == 0) {
        rc = cph_body();
        cphs_drop();
        regfree(&g_cph_comment);
    }
    return rc;
}
