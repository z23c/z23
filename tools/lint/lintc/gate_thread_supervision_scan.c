/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Gates: check-thread-supervision
 * Second file of the check-thread-supervision family (the 700-line family
 * ceiling split): the baseline loader, the native per-file spawn-site
 * scan, and the verdict report. The find mirror, the git-oracle coverage
 * check, the gate entry, and the family's parity notes live in
 * gate_thread_supervision.c; the --selftest probes live in
 * gate_thread_supervision_workers.c.
 */

/* ── the baseline, the records scan, and the verdict ─────────────────────
 * Byte-parity port of the second half of tools/lint/
 * check_thread_supervision.sh:
 *
 * - BASELINE: ZCL_THREADSUP_BASELINE falls back to the shell's
 *   cwd-relative default tools/lint/thread_supervision_baseline.txt (the
 *   shell cd's to the repo root first; the gate entry did the same).
 *   `[ -f ] || touch`: a missing baseline is CREATED empty; an existing
 *   non-regular one is touched (a no-op verdict-wise — the read below
 *   then fails, see the divergence note in the family header).
 * - The load loop: `read -r name _rest` takes the first space/tab-delimited
 *   token (leading runs skipped; \r is NOT IFS whitespace and stays part
 *   of the token); a blank token or one starting with '#' is skipped; the
 *   assoc-array insert dedups the SET while baseline_count still counts
 *   every row, duplicates included. REPAIRED BY VERIFIER RULING: an
 *   unterminated final row is honored (the shell silently drops it — a
 *   fail-open defect; the model-column-drift precedent, commit f7e1d583f).
 * - The records pass: per file, cov is `grep -qE` of the liveness-contract
 *   ERE over the whole file; each `grep -nE thread_registry_spawn(` row is
 *   marked when the line itself or the line above (sed -n '$((n-1))p')
 *   matches the marker ERE; the thread name is the sed BRE substitution
 *   's/.*thread_registry_spawn[[:space:]]*([[:space:]]*"\([^"]*\)".*\/\1/p'
 *   — reproduced as ONE regexec of the ERE translation, whose POSIX
 *   leftmost-longest semantics give the same answer sed's backtracking
 *   does (the LAST spawn call on the line that is followed by a quoted
 *   literal wins; pinned by A/B fixtures with two calls per line).
 * - A NUL-bearing file is binary to grep: the -q coverage probe still
 *   answers (match anywhere, no output), while the -nE row scan prints no
 *   stdout rows and notes "grep: <path>: binary file matches" on STDERR
 *   when the ERE matches (an empirical probe of the real binary, matching
 *   the supervisor-domain port's finding). Reproduced by a whole-file NUL
 *   pre-pass (grep's is per-32-KiB-buffer, which differs only for a file
 *   whose NUL and match sit in different buffers — no such file exists in
 *   the tree); segment-wise testing is exact because the EREs themselves
 *   contain no NUL.
 * - The verdict: covered-or-marked sites that are ALSO baselined are
 *   REDUNDANT; uncovered baselined sites are hits; anything else is a NEW
 *   unaccounted thread; baselined names never seen uncovered (and not
 *   redundant) are STALE. All report text is the shell's byte-for-byte on
 *   stdout; the stale rows emit in baseline FILE order where the shell
 *   used bash hash order (see the family header). Exit 1 on any failure
 *   class, 0 on the clean line.
 */

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <errno.h>
#include <fcntl.h>
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "lintc.h"

static const char k_tss_name[] = "check_thread_supervision";
static const char k_tss_bdef[] = "tools/lint/thread_supervision_baseline.txt";

enum { TSS_MAXB = 4096, TSS_BPOOL = 1 << 20, TSS_MAXR = 16384,
       TSS_NPOOL = 1 << 20, TSS_VPOOL = 1 << 20, TSS_MAXV = 16384 };

static char g_tss_bpool[TSS_BPOOL];    /* baseline keys, file order, deduped */
static size_t g_tss_bused;
static const char *g_tss_b[TSS_MAXB];
static int g_tss_nb;
static int g_tss_bcount;               /* the shell's raw row count */
static char g_tss_appeared[TSS_MAXB];  /* seen at any spawn site */
static char g_tss_hit[TSS_MAXB];       /* seen as an UNCOVERED spawn site */
static const char *g_tss_rf[TSS_MAXR]; /* one record per spawn-site line */
static long g_tss_rl[TSS_MAXR];
static char g_tss_rcov[TSS_MAXR];
static char g_tss_rmk[TSS_MAXR];
static const char *g_tss_rn[TSS_MAXR]; /* the extracted name ("" if none) */
static int g_tss_nr;
static char g_tss_npool[TSS_NPOOL];
static size_t g_tss_nused;
static const char *g_tss_new[TSS_MAXV];    /* NEW report rows, scan order */
static int g_tss_nnew;
static const char *g_tss_red[TSS_MAXV];    /* REDUNDANT rows, scan order */
static int g_tss_nred;
static const char *g_tss_stale[TSS_MAXB];  /* STALE rows, baseline order */
static int g_tss_nstale;
static char g_tss_vpool[TSS_VPOOL];        /* the rendered report rows */
static size_t g_tss_vused;
static regex_t g_tss_cover, g_tss_marker, g_tss_spawn, g_tss_name;

/* ── the baseline ──────────────────────────────────────────────────────── */

/* `[ -f "$BASELINE" ] || touch "$BASELINE"`: a missing file is created
 * empty. A creation failure die()s exit 2 where the shell printed touch's
 * own message and exited 1 — environment failure, not a gate verdict (the
 * model-column-drift precedent). An existing non-regular path needs no
 * create (touch only sets times); the read below then fails. */
static int tss_touch(const char *path)
{
    struct stat st;
    if (stat(path, &st) == 0)
        return 0;
    int fd = open(path, O_WRONLY | O_CREAT, 0666);
    if (fd < 0)
        return die("z23-lint: cannot create baseline %s\n", path);
    if (close(fd) != 0)
        return die("z23-lint: write failed\n", "");
    return 0;
}

/* `read -r name _rest`: the first space/tab-delimited token after any
 * leading run; blank or '#'-led tokens skip. A duplicate row increments
 * the raw count but not the set. */
static int tss_base_line(const char *line)
{
    const char *p = line;
    while (*p == ' ' || *p == '\t')
        p++;
    size_t n = 0;
    while (p[n] && p[n] != ' ' && p[n] != '\t')
        n++;
    if (n == 0 || p[0] == '#')
        return 0;
    g_tss_bcount++;
    for (int i = 0; i < g_tss_nb; i++)
        if (strlen(g_tss_b[i]) == n && memcmp(g_tss_b[i], p, n) == 0)
            return 0;
    if (g_tss_nb >= TSS_MAXB || g_tss_bused + n + 1 > TSS_BPOOL)
        return die("z23-lint: baseline overflow\n", "");
    char *dst = g_tss_bpool + g_tss_bused;
    memcpy(dst, p, n);
    dst[n] = '\0';
    g_tss_b[g_tss_nb] = dst;
    g_tss_appeared[g_tss_nb] = 0;
    g_tss_hit[g_tss_nb] = 0;
    g_tss_nb++;
    g_tss_bused += n + 1;
    return 0;
}

/* getline honors an unterminated final row — the verifier-ruled repair of
 * the shell's silent drop. An unreadable regular baseline die()s exit 2
 * where the shell died on the failed redirection with exit 1 (environment
 * failure; the model-column-drift precedent). */
static int tss_base_load(const char *path)
{
    g_tss_nb = 0;
    g_tss_bused = 0;
    g_tss_bcount = 0;
    FILE *f = fopen(path, "r");
    if (!f)
        return die("z23-lint: cannot open %s\n", path);
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    int rc = 0;
    while (rc == 0 && (n = getline(&line, &cap, f)) >= 0) {
        if (line[n - 1] == '\n')
            line[n - 1] = '\0';
        rc = tss_base_line(line);
    }
    return fin(f, line, path, rc);
}

static int tss_base_find(const char *name)
{
    for (int i = 0; i < g_tss_nb; i++)
        if (strcmp(g_tss_b[i], name) == 0)
            return i;
    return -1;
}

/* ── the per-file records scan ─────────────────────────────────────────── */

/* grep's own open/read diagnostic, byte-for-byte. The shell runs two
 * greps against an unreadable file (the coverage probe and the row scan),
 * so the caller prints this once per probe. */
static void tss_grep_diag(const char *path, int errnum)
{
    fprintf(stderr, "grep: %s: %s\n", path, strerror(errnum));
}

/* Pass 1: is this file binary to grep? A NUL anywhere flags it (grep's
 * per-buffer rule, exact for files under one 32 KiB buffer). Leaves the
 * stream rewound for the next pass. */
static int tss_has_nul(FILE *f, int *out)
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

/* An ERE over one buffer, NUL-segment-wise: exact because the ERE itself
 * contains no NUL, so no match can span a NUL. */
static int tss_seg_match(const char *buf, ssize_t n, const regex_t *re)
{
    const char *end = buf + n;
    for (const char *seg = buf; seg < end; seg += strlen(seg) + 1)
        if (regexec(re, seg, 0, NULL, 0) == 0)
            return 1;
    return 0;
}

/* grep -qE over a binary file: the match verdict with output suppressed. */
static int tss_cover_binary(FILE *f)
{
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    int found = 0;
    while (!found && (n = getline(&line, &cap, f)) >= 0)
        found = tss_seg_match(line, n, &g_tss_cover);
    free(line);
    rewind(f);
    return found;
}

/* grep -nE over a binary file: no stdout rows ever; the stderr note when
 * the spawn ERE matches. */
static void tss_rows_binary(const char *path, FILE *f)
{
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    int matched = 0;
    while (!matched && (n = getline(&line, &cap, f)) >= 0)
        matched = tss_seg_match(line, n, &g_tss_spawn);
    free(line);
    if (matched)
        fprintf(stderr, "grep: %s: binary file matches\n", path);
}

/* The sed name extraction as one regexec: the ERE translation keeps POSIX
 * leftmost-longest, so the LAST spawn call followed by a quoted literal
 * wins, exactly like sed's backtracking. Returns the captured name (not
 * NUL-terminated) or len 0 when the line carries no quoted name. */
static void tss_name_of(const char *line, const char **p, size_t *n)
{
    regmatch_t m[2];
    *p = NULL;
    *n = 0;
    if (regexec(&g_tss_name, line, 2, m, 0) == 0 && m[1].rm_so >= 0) {
        *p = line + m[1].rm_so;
        *n = (size_t)(m[1].rm_eo - m[1].rm_so);
    }
}

static int tss_record_add(const char *path, long lno, int cov, int marked,
                          const char *nm, size_t nml)
{
    if (g_tss_nr >= TSS_MAXR || g_tss_nused + nml + 1 > TSS_NPOOL)
        return die("z23-lint: scan-set overflow\n", "");
    char *dst = g_tss_npool + g_tss_nused;
    memcpy(dst, nm, nml);
    dst[nml] = '\0';
    g_tss_nused += nml + 1;
    g_tss_rf[g_tss_nr] = path;
    g_tss_rl[g_tss_nr] = lno;
    g_tss_rcov[g_tss_nr] = (char)cov;
    g_tss_rmk[g_tss_nr] = (char)marked;
    g_tss_rn[g_tss_nr] = dst;
    g_tss_nr++;
    return 0;
}

/* One spawn-site line: the marker on the line itself or the line above,
 * then the sed name extraction, then the record. */
static int tss_row(const char *path, long lno, int cov, const char *line,
                   const char *prev, int have_prev)
{
    int marked = regexec(&g_tss_marker, line, 0, NULL, 0) == 0;
    if (!marked && have_prev)
        marked = regexec(&g_tss_marker, prev, 0, NULL, 0) == 0;
    const char *nm = NULL;
    size_t nml = 0;
    tss_name_of(line, &nm, &nml);
    return tss_record_add(path, lno, cov, marked, nm ? nm : "", nml);
}

/* The text-file passes: the coverage probe (cov), then the row scan with
 * the previous line kept for the marker-above check. */
static int tss_text_file(const char *path, FILE *f)
{
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    int cov = 0;
    while (!cov && (n = getline(&line, &cap, f)) >= 0) {
        if (line[n - 1] == '\n')
            line[n - 1] = '\0';
        cov = regexec(&g_tss_cover, line, 0, NULL, 0) == 0;
    }
    rewind(f);
    char prev[4096];
    int have_prev = 0;
    long lno = 0;
    int rc = 0;
    while (rc == 0 && (n = getline(&line, &cap, f)) >= 0) {
        lno++;
        if (line[n - 1] == '\n')
            line[--n] = '\0';
        if (regexec(&g_tss_spawn, line, 0, NULL, 0) == 0)
            rc = tss_row(path, lno, cov, line, prev, have_prev);
        if (rc == 0) {
            if ((size_t)n >= sizeof prev)
                rc = die("z23-lint: derived buffer overflow\n", "");
            else {
                memcpy(prev, line, (size_t)n + 1);
                have_prev = 1;
            }
        }
    }
    free(line);
    return rc;
}

/* One file as the shell's per-file greps see it: an open failure is
 * grep's own diagnostic once per probe (the coverage probe, then the row
 * scan) with no records, exactly like the shell, which never checks those
 * exit codes. A binary file keeps the coverage verdict but yields no
 * rows, plus grep's stderr note when the spawn ERE matches. */
static int tss_scan_file(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f) {
        int e = errno;
        tss_grep_diag(path, e);
        tss_grep_diag(path, e);
        return 0;
    }
    int binary = 0;
    int rc = tss_has_nul(f, &binary);
    if (rc == 0 && binary) {
        (void)tss_cover_binary(f);
        tss_rows_binary(path, f);
    }
    if (rc == 0 && !binary)
        rc = tss_text_file(path, f);
    if (ferror(f))
        tss_grep_diag(path, errno);
    fclose(f);
    return rc;
}

/* ── the verdict ───────────────────────────────────────────────────────── */

/* One rendered report row into the verdict pool. */
static int tss_row_store(const char **vec, int *nv, const char *text)
{
    if (*nv >= TSS_MAXV)
        return die("z23-lint: scan-set overflow\n", "");
    size_t n = strlen(text) + 1;
    if (g_tss_vused + n > sizeof g_tss_vpool)
        return die("z23-lint: derived buffer overflow\n", "");
    memcpy(g_tss_vpool + g_tss_vused, text, n);
    vec[(*nv)++] = g_tss_vpool + g_tss_vused;
    g_tss_vused += n;
    return 0;
}

/* The records loop: redundant-before-covered, hit, else NEW — in scan
 * order, with baseline_appeared marked for every baselined name seen at
 * any site. */
static int tss_evaluate(int *fail)
{
    int rc = 0;
    char buf[8192];
    for (int i = 0; rc == 0 && i < g_tss_nr; i++) {
        int bi = g_tss_rn[i][0] ? tss_base_find(g_tss_rn[i]) : -1;
        if (bi >= 0)
            g_tss_appeared[bi] = 1;
        if (g_tss_rcov[i] || g_tss_rmk[i]) {
            if (bi >= 0) {
                int k = snprintf(buf, sizeof buf,
                                 "%s (%s:%ld is now covered)", g_tss_rn[i],
                                 g_tss_rf[i], g_tss_rl[i]);
                rc = ovf(k, sizeof buf);
                if (rc == 0)
                    rc = tss_row_store(g_tss_red, &g_tss_nred, buf);
                *fail = 1;
            }
            continue;
        }
        if (bi >= 0) {
            g_tss_hit[bi] = 1;
            continue;
        }
        int k = snprintf(buf, sizeof buf, "%s:%ld  thread='%s'",
                         g_tss_rf[i], g_tss_rl[i],
                         g_tss_rn[i][0] ? g_tss_rn[i] : "<dynamic-name>");
        rc = ovf(k, sizeof buf);
        if (rc == 0)
            rc = tss_row_store(g_tss_new, &g_tss_nnew, buf);
        *fail = 1;
    }
    return rc;
}

/* Stale entries, in baseline FILE order (the shell's bash hash order is
 * unspecified — see the family header). */
static int tss_stale(int *fail)
{
    for (int i = 0; i < g_tss_nb; i++) {
        if (g_tss_hit[i] || g_tss_appeared[i])
            continue;
        g_tss_stale[g_tss_nstale++] = g_tss_b[i];
        *fail = 1;
    }
    return 0;
}

static void tss_emit_rows(const char *const *vec, int n)
{
    for (int i = 0; i < n; i++)
        printf("    %s\n", vec[i]);
}

static void tss_report_new(const char *baseline)
{
    if (g_tss_nnew == 0)
        return;
    printf("\n  NEW unaccounted long-running thread(s) (%d):\n",
           g_tss_nnew);
    tss_emit_rows(g_tss_new, g_tss_nnew);
    fputs("\n  Fix (preferred → fallback):\n"
          "    1. Supervise it: register a liveness contract via\n"
          "       util/thread_liveness.h (exemplar: "
          "engine/modules/health/src/heartbeat.c),\n"
          "       or add '// supervised:<child>' at the spawn site.\n"
          "    2. If short-lived/joined/one-shot: add\n"
          "       '// thread-supervision-ok:<reason>' at the spawn site.\n",
          stdout);
    printf("    3. Last resort: add '<name>  <disposition>  <why>' to %s.\n",
           baseline);
}

static int tss_body(const char *const *files, int nfiles)
{
    const char *baseline = env_or("ZCL_THREADSUP_BASELINE", k_tss_bdef);
    int rc = tss_touch(baseline);
    if (rc == 0)
        rc = tss_base_load(baseline);
    for (int i = 0; rc == 0 && i < nfiles; i++)
        rc = tss_scan_file(files[i]);
    int fail = 0;
    if (rc == 0)
        rc = tss_evaluate(&fail);
    if (rc == 0)
        rc = tss_stale(&fail);
    if (rc)
        return rc;
    if (!fail) {
        printf("%s: clean — %d baselined exemption(s), no new unaccounted "
               "threads\n", k_tss_name, g_tss_bcount);
        return 0;
    }
    fputs("\ncheck_thread_supervision: FAIL\n", stdout);
    tss_report_new(baseline);
    if (g_tss_nred > 0) {
        fputs("\n  REDUNDANT baseline entries (thread is now covered — "
              "remove them):\n", stdout);
        tss_emit_rows(g_tss_red, g_tss_nred);
    }
    if (g_tss_nstale > 0) {
        fputs("\n  STALE baseline entries (no matching uncovered spawn — "
              "remove them):\n", stdout);
        tss_emit_rows(g_tss_stale, g_tss_nstale);
    }
    fputs("\n", stdout);
    return 1;
}

static int tss_comp(void)
{
    int rc = compile_pat(&g_tss_cover, REG_EXTENDED,
                         "supervisor_register[[:space:]]*\\(|supervisor_",
                         "register_in_domain[[:space:]]*\\(|",
                         "thread_liveness_register[[:space:]]*\\(", "");
    if (rc == 0)
        rc = compile_pat(&g_tss_marker, REG_EXTENDED,
                         "//[[:space:]]*(supervised|thread-supervision-ok",
                         "):", "", "");
    if (rc == 0)
        rc = compile_pat(&g_tss_spawn, REG_EXTENDED,
                         "thread_registry_spawn[[:space:]]*\\(", "", "", "");
    if (rc == 0)
        rc = compile_pat(&g_tss_name, REG_EXTENDED,
                         ".*thread_registry_spawn[[:space:]]*\\(",
                         "[[:space:]]*\"([^\"]*)\".*", "", "");
    return rc;
}

int thread_supervision_scan_run(const char *const *files, int nfiles)
{
    int rc = tss_comp();
    if (rc == 0)
        rc = tss_body(files, nfiles);
    drop2(&g_tss_cover, &g_tss_marker);
    drop2(&g_tss_spawn, &g_tss_name);
    return rc;
}
