/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Gates: check-model-column-drift
 * Single-gate family, two files under the 700-line family ceiling:
 * gate_model_column_drift.c (this file) holds the gate body — the scan-root
 * derivation, the native per-file distinct-literal-column-index scan, the
 * baseline loader, the shrink-only stale check, the verdict, and the gate
 * entry; gate_model_column_drift_workers.c holds the gate's --selftest
 * probes.
 */

/* ── check-model-column-drift ──────────────────────────────────────────────
 * Byte-parity C23 port of tools/lint/check_model_column_drift.sh (a model
 * must not hand-maintain the column indices of a multi-column row read: any
 * model source reading TWO OR MORE DISTINCT literal column indices through
 * AR_READ_BLOB / AR_READ_STR / AR_COL_INT / AR_COL_BYTES / AR_COL_TEXT /
 * AR_COL_DOUBLE is flagged; RATCHET pins the pre-existing set in
 * tools/lint/model_column_drift_baseline.txt, which may only SHRINK — a new
 * violator fails, and a baselined file that stopped violating fails as
 * stale). Spawn-free per the fleet ruling: no subprocess runs anywhere in
 * this gate's scan path; the original never shelled out to sqlite3 (it is a
 * pure text scan), so no native data-source binding was needed.
 *
 * Semantic mapping (original at HEAD~ of the port commit):
 * - Env: ZCL_LINT_MODE via env_or's unset-or-empty fallback, matching
 *   ${ZCL_LINT_MODE:-WARN}; ZCL_MODEL_DRIFT_ROOT is a set-and-nonempty test
 *   ([ -n "${VAR:-}" ]), selftest isolation only; ZCL_MODEL_DRIFT_BASELINE
 *   falls back to the shell's $SCRIPT_DIR-relative ABSOLUTE default
 *   "<root>/tools/lint/model_column_drift_baseline.txt" — the root comes
 *   from the runtime's exe-path resolver, which equals the shell's
 *   cd-and-pwd path on a symlink-free checkout path.
 * - Scan roots: repo_shape_room_dirs("models") with "/src" appended per
 *   room and the shell's [ -d ] filter (stat, so a symlinked room src is
 *   followed), or the env override verbatim. The root floor (2 production,
 *   1 with the override) and the scanned-file floor (20) are the runtime's
 *   gate_require_scanned, byte-identical to gate_lib.sh's text.
 * - The per-root bash *.c glob under each scan root: a readdir collect of dot-free
 *   *.c names joined as root + "/" + name (a trailing-slash root yields the
 *   shell's doubled slash verbatim), filtered by stat() to regular files
 *   (bash's [ -f ] follows symlinks, so a symlinked model source scans and
 *   a broken one is skipped), then a BYTE-ORDER strcmp qsort — the
 *   deliberate, deterministic replacement for the shell's locale-collation
 *   glob sort; identical under LC_ALL=C, the A/B fixture locale on both
 *   sides. rel = the collected path minus ONE leading "./" (${f#./}).
 *   A missing or unreadable root dir is the shell's silent unexpanded glob:
 *   it contributes nothing and no diagnostic.
 * - distinct_literal_indices: the `grep -vE '//[[:space:]]*model-columns-ok:'
 *   | grep -oE '(MACROS)\([A-Za-z_][A-Za-z0-9_.>()-]*,[[:space:]]*[0-9]+'
 *   | grep -oE '[0-9]+$' | sort -u | grep -c .` pipeline is one regexec
 *   pass per kept line: the exception filter drops the whole line, then -o
 *   is leftmost-longest matches with the scan resuming past each match (the
 *   pattern can never match empty, so there is no empty-match step), and the
 *   trailing digit run of each match is the literal index. Distinctness is
 *   by STRING (the shell's sort -u is byte-wise), so "01" and "1" are two
 *   distinct indices.
 * - An unreadable file reproduces grep's own "grep: <path>: <strerror>" on
 *   stderr, swallowed by the shell's `|| true`, with n=0. A mid-file read
 *   error keeps the partial count (the shell pipeline kept the partial
 *   stream) and prints the same diagnostic.
 * - A NUL-bearing file is binary to grep: the -v filter then suppresses
 *   ALL normal output and, when at least one line is selected (does NOT
 *   contain the exception), prints "grep: <path>: binary file matches" on
 *   STDERR (an empirical probe of the real binary, matching the
 *   supervisor-domain port's finding) — so the gate sees n=0 plus that one
 *   note. Reproduced by a whole-file NUL pre-pass (grep's is
 *   per-32-KiB-buffer, which differs only for a file whose NUL and
 *   selected line sit in different buffers — no such file exists in the
 *   tree); the selected-line test is NUL-segment-wise, exact because the
 *   exception ERE itself contains no NUL.
 * - The baseline keeps gate_load_list_file's true semantics via a LOCAL
 *   loader (not lint_base_load_set): '#' truncates ANYWHERE on the line,
 *   both ends are whitespace-trimmed, blanks are skipped, a missing or
 *   non-regular file is an empty set ([[ -f ]] gates the read), and a
 *   duplicate line increments the reported entry COUNT but not the set.
 *   lint_base_load_set would not fit: its set is superset-allowed with no
 *   stale notion, while this gate FAILS on a stale entry, and its dedup
 *   loses the shell's raw line count.
 * - Verdict: WARN reports and always exits 0; RATCHET exits 1 on any
 *   unbaselined violator or any stale entry; FAIL exits 1 on any violator,
 *   baseline ignored. The summary, fix, and baseline lines are the shell's
 *   byte-for-byte; any other mode string passes through verbatim.
 *
 * Preserved latent defects / parity notes:
 * - `while IFS= read -r line` silently DROPS an unterminated final baseline
 *   line (read fails at EOF without the delimiter, so the loop body never
 *   runs for it). Reproduced byte-exactly: mcd_base_load requires the
 *   newline. Flagged, not repaired.
 * - Stale-row report order: the shell iterates a bash ASSOCIATIVE array,
 *   i.e. hash order (unspecified); the port emits baseline FILE order.
 *   Identical for zero or one stale row; a multi-stale report orders
 *   differently. bash's bucket order is not a stable contract, so this is
 *   documented rather than mimicked (the controller-private-headers
 *   precedent).
 * - An unreadable but REGULAR baseline: the shell dies on the failed
 *   redirection with bash's own message and exit 1; the port die()s exit 2.
 *   Environment failure, not a gate verdict (the
 *   controller-private-headers precedent).
 * - The ZCL_GATE_SCAN_LOG audit rows gate_lib.sh's gate_require_scanned
 *   appends are not emitted (the runtime helper's established behavior;
 *   the hook is off by default).
 * - repo_shape.sh's source-time architecture parse runs in the shell even
 *   when ZCL_MODEL_DRIFT_ROOT overrides the scan root; the port only
 *   derives rooms on the production path. Both are silent on a healthy
 *   tree; the failure texts (repo-shape FATAL, repo_shape_room_dirs FATAL)
 *   are byte-identical through the same runtime helpers when they do fire.
 * - The shell was unbounded; the fixed pools (violating files, baseline
 *   rows, one root's file set, per-file distinct indices) fail closed with
 *   die() — environment exhaustion, not a verdict.
 * - mktemp failure in --selftest: shell exit 1 with mktemp's text; port
 *   die() exit 2 (environment failure, the describe-budget precedent).
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

static const char k_mcd_name[] = "check_model_column_drift";
static const char k_mcd_baseline_leaf[] =
    "/tools/lint/model_column_drift_baseline.txt";

enum { MCD_MAXV = 8192, MCD_VPOOL = 1 << 20, MCD_MAXB = 4096,
       MCD_BPOOL = 1 << 20, MCD_MAXF = 8192, MCD_FPOOL = 1 << 20,
       MCD_MAXIDX = 512, MCD_IDX = 64 };

static char g_mcd_vpool[MCD_VPOOL];  /* violating file rels, scan order */
static size_t g_mcd_vused;
static const char *g_mcd_v[MCD_MAXV];
static int g_mcd_nv;
static char g_mcd_bpool[MCD_BPOOL];  /* baseline keys, file order, deduped */
static size_t g_mcd_bused;
static const char *g_mcd_b[MCD_MAXB];
static int g_mcd_nb;
static int g_mcd_bcount;             /* the shell's raw entry count */
static char g_mcd_fpool[MCD_FPOOL];  /* one root's collected *.c paths */
static size_t g_mcd_fused;
static const char *g_mcd_f[MCD_MAXF];
static int g_mcd_nf;
static char g_mcd_idx[MCD_MAXIDX][MCD_IDX]; /* one file's distinct indices */
static int g_mcd_nidx;
static int g_mcd_scanned;
static regex_t g_mcd_read;           /* the read-macro ERE */
static regex_t g_mcd_excl;           /* the // model-columns-ok: filter */

/* ── small buffer utilities ────────────────────────────────────────────── */

static int mcd_pool(char *pool, size_t cap, size_t *used, const char *s,
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

static int mcd_ptr_cmp(const void *a, const void *b)
{
    return strcmp(*(const char *const *)a, *(const char *const *)b);
}

/* ── the baseline (local loader; see the file header for why) ──────────── */

/* One raw baseline line: '#' truncates anywhere, both ends trim, blanks
 * skip; a duplicate still increments the count but not the set. */
static int mcd_base_line(char *line)
{
    char *h = strchr(line, '#');
    if (h)
        *h = '\0';
    char *p = line;
    while (*p && isspace((unsigned char)*p))
        p++;
    size_t n = strlen(p);
    while (n && isspace((unsigned char)p[n - 1]))
        p[--n] = '\0';
    if (!n)
        return 0;
    g_mcd_bcount++;
    for (int i = 0; i < g_mcd_nb; i++)
        if (strcmp(g_mcd_b[i], p) == 0)
            return 0;
    if (g_mcd_nb >= MCD_MAXB)
        return die("z23-lint: baseline overflow\n", "");
    return mcd_pool(g_mcd_bpool, sizeof g_mcd_bpool, &g_mcd_bused, p,
                    &g_mcd_b[g_mcd_nb++]);
}

static int mcd_base_load(const char *path)
{
    g_mcd_nb = 0;
    g_mcd_bused = 0;
    g_mcd_bcount = 0;
    struct stat st;
    if (stat(path, &st) != 0 || !S_ISREG(st.st_mode))
        return 0;
    FILE *f = fopen(path, "r");
    if (!f)
        return die("z23-lint: cannot open %s\n", path);
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    int rc = 0;
    while (rc == 0 && (n = getline(&line, &cap, f)) >= 0) {
        if (line[n - 1] != '\n')
            continue;
        line[n - 1] = '\0';
        rc = mcd_base_line(line);
    }
    return fin(f, line, path, rc);
}

static int mcd_base_has(const char *rel)
{
    for (int i = 0; i < g_mcd_nb; i++)
        if (strcmp(g_mcd_b[i], rel) == 0)
            return 1;
    return 0;
}

/* ── the per-file distinct-literal-index scan ──────────────────────────── */

/* The trailing digit run of one -o match, inserted as a STRING: the
 * shell's sort -u is byte-wise, so "01" and "1" are two distinct indices. */
static int mcd_idx_add(const char *match, size_t len)
{
    size_t b = len;
    while (b > 0 && match[b - 1] >= '0' && match[b - 1] <= '9')
        b--;
    size_t n = len - b;
    if (n == 0 || n >= MCD_IDX)
        return die("z23-lint: derived buffer overflow\n", "");
    for (int i = 0; i < g_mcd_nidx; i++)
        if (strlen(g_mcd_idx[i]) == n
            && memcmp(g_mcd_idx[i], match + b, n) == 0)
            return 0;
    if (g_mcd_nidx >= MCD_MAXIDX)
        return die("z23-lint: scan-set overflow\n", "");
    memcpy(g_mcd_idx[g_mcd_nidx], match + b, n);
    g_mcd_idx[g_mcd_nidx][n] = '\0';
    g_mcd_nidx++;
    return 0;
}

/* grep -oE over one kept line: leftmost-longest matches, the scan resuming
 * past each; the pattern can never match empty, so no empty-match step. */
static int mcd_line(const char *line)
{
    regmatch_t m[1];
    const char *p = line;
    while (regexec(&g_mcd_read, p, 1, m, 0) == 0) {
        int rc = mcd_idx_add(p + m[0].rm_so,
                             (size_t)(m[0].rm_eo - m[0].rm_so));
        if (rc)
            return rc;
        p += m[0].rm_eo;
    }
    return 0;
}

/* Pass 1: is this file binary to grep? A NUL anywhere flags it (grep's
 * per-buffer rule, exact for files under one 32 KiB buffer). Leaves the
 * stream rewound for pass 2. */
static int mcd_has_nul(FILE *f, int *out)
{
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    int found = 0;
    while (!found && (n = getline(&line, &cap, f)) >= 0)
        found = memchr(line, '\0', (size_t)n) != NULL;
    free(line);
    rewind(f);
    *out = found;
    return 0;
}

/* Pass 2 for a binary file: grep -vE "matches" (and notes it on stderr)
 * when at least one line is SELECTED, i.e. does not contain the exception;
 * the note replaces all normal output, so the downstream count is 0 either
 * way. NUL-segment-wise testing is exact because the exception ERE itself
 * contains no NUL. */
static int mcd_binary_note(const char *path, FILE *f)
{
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    int selected = 0;
    while (!selected && (n = getline(&line, &cap, f)) >= 0) {
        int line_match = 0;
        const char *end = line + n;
        for (const char *seg = line; !line_match && seg < end;
             seg += strlen(seg) + 1)
            line_match = regexec(&g_mcd_excl, seg, 0, NULL, 0) == 0;
        selected = !line_match;
    }
    free(line);
    if (selected)
        fprintf(stderr, "grep: %s: binary file matches\n", path);
    return 0;
}

/* distinct_literal_indices, natively. An unreadable file is grep's own
 * stderr diagnostic (swallowed by the shell's `|| true`) with n=0; a binary
 * file is n=0 plus grep's binary note when it selects a line (see the file
 * header). */
static int mcd_count_file(const char *path, int *out_n)
{
    *out_n = 0;
    FILE *f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "grep: %s: %s\n", path, strerror(errno));
        return 0;
    }
    int binary = 0;
    int rc = mcd_has_nul(f, &binary);
    if (rc == 0 && binary) {
        rc = mcd_binary_note(path, f);
        (void)fclose(f);
        return rc;
    }
    if (rc == 0 && !binary) {
        char *line = NULL;
        size_t cap = 0;
        ssize_t n;
        g_mcd_nidx = 0;
        while (rc == 0 && (n = getline(&line, &cap, f)) >= 0) {
            if (n > 0 && line[n - 1] == '\n')
                line[--n] = '\0';
            if (regexec(&g_mcd_excl, line, 0, NULL, 0) != 0)
                rc = mcd_line(line);
        }
        if (ferror(f))
            fprintf(stderr, "grep: %s: %s\n", path, strerror(errno));
        free(line);
        if (rc == 0)
            *out_n = g_mcd_nidx;
    }
    fclose(f);
    return rc;
}

static int mcd_violating_add(const char *rel)
{
    if (g_mcd_nv >= MCD_MAXV)
        return die("z23-lint: scan-set overflow\n", "");
    return mcd_pool(g_mcd_vpool, sizeof g_mcd_vpool, &g_mcd_vused, rel,
                    &g_mcd_v[g_mcd_nv++]);
}

/* ── the per-root glob scan ────────────────────────────────────────────── */

/* One readdir entry: the bash "*.c" glob never matches a dotfile; the
 * [ -f ] filter is stat, so a symlinked source scans. */
static int mcd_root_entry(const char *root, const char *nm)
{
    if (nm[0] == '.')
        return 0;
    size_t nl = strlen(nm);
    if (nl < 3 || strcmp(nm + nl - 2, ".c") != 0)
        return 0;
    char path[4096];
    int k = snprintf(path, sizeof path, "%s/%s", root, nm);
    if (k < 0 || (size_t)k >= sizeof path)
        return die("z23-lint: path too long: %s\n", root);
    struct stat st;
    if (stat(path, &st) != 0 || !S_ISREG(st.st_mode))
        return 0;
    if (g_mcd_nf >= MCD_MAXF)
        return die("z23-lint: scan-set overflow\n", "");
    return mcd_pool(g_mcd_fpool, sizeof g_mcd_fpool, &g_mcd_fused, path,
                    &g_mcd_f[g_mcd_nf++]);
}

/* The glob collect: a missing or unreadable root is the shell's silent
 * unexpanded pattern — nothing collected, no diagnostic. */
static int mcd_root_collect(const char *root)
{
    g_mcd_nf = 0;
    g_mcd_fused = 0;
    DIR *d = opendir(root);
    if (!d)
        return 0;
    int rc = 0;
    struct dirent *de;
    while (rc == 0 && (de = readdir(d)) != NULL)
        rc = mcd_root_entry(root, de->d_name);
    closedir(d);
    if (rc == 0)
        qsort(g_mcd_f, (size_t)g_mcd_nf, sizeof g_mcd_f[0], mcd_ptr_cmp);
    return rc;
}

/* One root's files in glob (byte) order: count, record violators, and
 * report each unbaselined one exactly like the shell's stderr line. */
static int mcd_scan_root(const char *root, const char *mode, int *violations)
{
    int rc = mcd_root_collect(root);
    for (int i = 0; rc == 0 && i < g_mcd_nf; i++) {
        const char *f = g_mcd_f[i];
        const char *rel = strncmp(f, "./", 2) == 0 ? f + 2 : f;
        int n = 0;
        g_mcd_scanned++;
        rc = mcd_count_file(f, &n);
        if (rc || n < 2)
            continue;
        rc = mcd_violating_add(rel);
        if (rc)
            break;
        if (strcmp(mode, "RATCHET") == 0 && mcd_base_has(rel))
            continue;
        (*violations)++;
        if (fprintf(stderr, "%s: %d distinct hand-written column indices "
                    "in row reads\n", rel, n) < 0)
            rc = die("z23-lint: write failed\n", "");
    }
    return rc;
}

/* ── the verdict ───────────────────────────────────────────────────────── */

/* Shrink-only: a baselined file that no longer violates must lose its
 * line. The shell iterates bash hash order; the port emits baseline FILE
 * order (identical for zero or one stale row — see the file header). */
static int mcd_stale_report(int *out)
{
    *out = 0;
    for (int i = 0; i < g_mcd_nb; i++) {
        int still = 0;
        for (int j = 0; j < g_mcd_nv && !still; j++)
            still = strcmp(g_mcd_v[j], g_mcd_b[i]) == 0;
        if (still)
            continue;
        (*out)++;
        if (fprintf(stderr, "%s: baselined but NO LONGER violates — "
                    "delete its baseline line\n", g_mcd_b[i]) < 0)
            return die("z23-lint: write failed\n", "");
    }
    return 0;
}

static int mcd_summary(const char *mode, const char *bpath, int violations,
                       int stale)
{
    int bad = printf("[%s] scanned %d model file(s), %d with hand-written "
                     "column indices, %d unbaselined, %d stale baseline "
                     "entry(ies) (mode: %s)\n", k_mcd_name, g_mcd_scanned,
                     g_mcd_nv, violations, stale, mode) < 0;
    if (!bad)
        bad = printf("[%s] fix: declare the fields once in "
                     "engine/models/include/models/def/<model>_fields.def "
                     "and derive the mapping (models/model_fields.h)\n",
                     k_mcd_name) < 0;
    if (!bad && strcmp(mode, "RATCHET") == 0)
        bad = printf("[%s] baseline: %s (%d entry(ies), may only SHRINK)\n",
                     k_mcd_name, bpath, g_mcd_bcount) < 0;
    if (bad)
        return die("z23-lint: write failed\n", "");
    if (strcmp(mode, "FAIL") == 0 && violations > 0)
        return 1;
    if (strcmp(mode, "RATCHET") == 0 && (violations > 0 || stale > 0))
        return 1;
    return 0;
}

/* ── the gate ──────────────────────────────────────────────────────────── */

/* SCAN_ROOTS: the env override verbatim, else every existing
 * <authority>/models room with an existing src/ leaf. */
static int mcd_roots(const char *envroot, char roots[][RS_PATH + 8],
                     int *out_n)
{
    *out_n = 0;
    if (envroot) {
        if (ovf(snprintf(roots[0], RS_PATH + 8, "%s", envroot), RS_PATH + 8))
            return 2;
        *out_n = 1;
        return 0;
    }
    char rooms[RS_AUTH][RS_PATH];
    int nrooms = 0;
    int rc = repo_shape_room_dirs("models", rooms, RS_AUTH, &nrooms);
    for (int i = 0; rc == 0 && i < nrooms; i++) {
        char cand[RS_PATH + 8];
        if (ovf(snprintf(cand, sizeof cand, "%s/src", rooms[i]),
                sizeof cand)) {
            rc = 2;
            break;
        }
        struct stat st;
        if (stat(cand, &st) == 0 && S_ISDIR(st.st_mode)) {
            memcpy(roots[*out_n], cand, strlen(cand) + 1);
            (*out_n)++;
        }
    }
    return rc;
}

static int mcd_body(const char *root_dir)
{
    const char *mode = env_or("ZCL_LINT_MODE", "WARN");
    const char *envroot = getenv("ZCL_MODEL_DRIFT_ROOT");
    if (envroot && !envroot[0])
        envroot = NULL;
    char bdef[4352];
    if (ovf(snprintf(bdef, sizeof bdef, "%s%s", root_dir,
                     k_mcd_baseline_leaf), sizeof bdef))
        return 2;
    const char *bpath = env_or("ZCL_MODEL_DRIFT_BASELINE", bdef);
    static char roots[RS_AUTH][RS_PATH + 8];
    int nroots = 0;
    int rc = mcd_roots(envroot, roots, &nroots);
    if (rc == 0)
        rc = gate_require_scanned(nroots, envroot ? 1 : 2, k_mcd_name,
                                  "physical model-room set came back hollow");
    if (rc == 0)
        rc = mcd_base_load(bpath);
    g_mcd_scanned = 0;
    g_mcd_nv = 0;
    g_mcd_vused = 0;
    int violations = 0;
    for (int i = 0; rc == 0 && i < nroots; i++)
        rc = mcd_scan_root(roots[i], mode, &violations);
    if (rc == 0)
        rc = gate_require_scanned(g_mcd_scanned, 20, k_mcd_name,
                                  "engine/models/src should hold dozens of "
                                  "model sources");
    int stale = 0;
    if (rc == 0 && strcmp(mode, "RATCHET") == 0)
        rc = mcd_stale_report(&stale);
    if (rc)
        return rc;
    return mcd_summary(mode, bpath, violations, stale);
}

int check_model_column_drift_run(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    char root[4096];
    int rc = cic_repo_root(root, sizeof root);
    if (rc == 0 && chdir(root) != 0)
        rc = 2;
    if (rc == 0)
        rc = compile_pat(&g_mcd_excl, REG_EXTENDED,
                         "//[[:space:]]*model-columns-ok:", "", "", "");
    if (rc == 0)
        rc = compile_pat(&g_mcd_read, REG_EXTENDED,
                         "(AR_READ_BLOB|AR_READ_STR|AR_COL_INT|AR_COL_BYTES"
                         "|AR_COL_TEXT|AR_COL_DOUBLE)",
                         "\\([A-Za-z_][A-Za-z0-9_.>()-]*,"
                         "[[:space:]]*[0-9]+", "", "");
    if (rc == 0)
        rc = mcd_body(root);
    regfree(&g_mcd_excl);
    regfree(&g_mcd_read);
    return rc;
}
