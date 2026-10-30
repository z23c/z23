/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: the compile sweep and verdict of the check-windows-cross-syntax
 * gate: the per-TU baseline and infra bookkeeping, the make-free worker pool
 * that runs each missed TU through the cross compiler, the stale-row and
 * verdict reports. Split out of gate_windows_cross_syntax.c for the 800-line
 * limit; the flow (wcs_begin) there calls wcs_sweep().
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include "lintc.h"
#include "gate_windows_cross_syntax_priv.h"

/* ── the compile sweep and verdict ──────────────────────────────────── */

struct wcs_infra { char src[WCS_PATH]; char rc[32]; char kind[40]; };

struct wcs_lists {
    char still[WCS_TUS][WCS_PATH]; int nstill;
    char newf[WCS_TUS][WCS_PATH]; int nnew;
    char skipg[WCS_TUS][WCS_PATH]; int nskipg;
    char skipo[WCS_TUS][WCS_PATH]; int nskipo;
    char cleanl[WCS_TUS][WCS_PATH]; int nclean;
    struct wcs_infra infra[WCS_TUS]; int ninfra;
};

static int lists_push(char arr[][WCS_PATH], int *n, const char *v)
{
    if (*n >= WCS_TUS) {
        fprintf(stderr, "%s: translation-unit table exceeds %d\n", k_wcs_gate,
                WCS_TUS);
        return 2;
    }
    if (wcs_copy(arr[*n], WCS_PATH, v)) {
        fprintf(stderr, "%s: path exceeds %d bytes: %s\n", k_wcs_gate,
                WCS_PATH, v);
        return 2;
    }
    (*n)++;
    return 0;
}

/* 0 with out set; 1 when the file is absent or empty; -1 when the first
 * token does not fit out. */
static int read_rc_file(const char *rcf, char *out, size_t cap)
{
    out[0] = '\0';
    FILE *f = fopen(rcf, "r");
    if (!f) return 1;
    static char line[64];
    int rc = 1;
    if (fgets(line, sizeof line, f)) {
        char *sp = line;
        while (*sp && *sp != ' ' && *sp != '\n') sp++;
        *sp = '\0';
        if (wcs_copy(out, cap, line)) rc = -1;
    }
    fclose(f);
    if (rc < 0) return -1;
    return out[0] ? 0 : 1;
}

static int in_baseline(const char *src)
{
    FILE *bf = fopen(k_wcs_baseline, "r");
    int known = 0;
    if (!bf) return 0;
    static char line[WCS_PATH];
    while (!known && fgets(line, sizeof line, bf)) {
        size_t l = strlen(line);
        if (l && line[l - 1] == '\n') line[--l] = '\0';
        if (strcmp(line, src) == 0) known = 1;
    }
    fclose(bf);
    return known;
}

static int push_infra(struct wcs_lists *L, const char *src, const char *rcs,
                      const char *kind)
{
    if (L->ninfra >= WCS_TUS) {
        fprintf(stderr, "%s: infrastructure table exceeds %d\n", k_wcs_gate,
                WCS_TUS);
        return 2;
    }
    struct wcs_infra *w = &L->infra[L->ninfra];
    if (wcs_copy(w->src, WCS_PATH, src) || wcs_copy(w->rc, sizeof w->rc, rcs) ||
        wcs_copy(w->kind, sizeof w->kind, kind)) {
        fprintf(stderr, "%s: infrastructure row exceeds its field: %s\n",
                k_wcs_gate, src);
        return 2;
    }
    L->ninfra++;
    return 0;
}

/* Grades one TU by its recorded kind. ERROR, or a missing openssl header
 * with openssl present, is graded against the baseline. */
static int classify_by_kind(const char *src, const char *rcs, const char *kind,
                            int ossl_absent,
                            struct wcs_lists *L)
{
    if (strcmp(kind, "CLEAN") == 0)
        return lists_push(L->cleanl, &L->nclean, src);
    if (strcmp(kind, "SKIP_GENERATED") == 0)
        return lists_push(L->skipg, &L->nskipg, src);
    if (strcmp(kind, "COMPILER_FAILURE") == 0 ||
        strcmp(kind, "MISSING_RESULT") == 0 ||
        strcmp(kind, "INCONSISTENT_SUCCESS") == 0)
        return push_infra(L, src, rcs, kind);
    if (ossl_absent && (strcmp(kind, "SKIP_OPENSSL") == 0 ||
                        strcmp(kind, "SKIP_HEADERS") == 0))
        return lists_push(L->skipo, &L->nskipo, src);
    int known = in_baseline(src);
    return lists_push(known ? L->still : L->newf,
                      known ? &L->nstill : &L->nnew, src);
}

static int classify_tu(const char *src, int ossl_absent,
                       struct wcs_lists *L)
{
    char log[WCS_PATH * 2], rc[WCS_PATH * 2], rcs[64], kind[40];
    struct stat st;
    if (wcs_paths_for(src, g_wcs_out, log, sizeof log, rc, sizeof rc) != 0)
        return 2;
    if (read_rc_file(rc, rcs, sizeof rcs) < 0) {
        fprintf(stderr, "%s: result row exceeds %d bytes: %s\n", k_wcs_gate,
                (int)sizeof rcs, rc);
        return 2;
    }
    if (strcmp(rcs, "0") == 0 && (stat(log, &st) != 0 || st.st_size == 0))
        return lists_push(L->cleanl, &L->nclean, src);
    if (wcs_compile_kind(log, rcs, kind, sizeof kind) != 0) return 2;
    return classify_by_kind(src, rcs, kind, ossl_absent, L);
}

static int cmp_files(const void *a, const void *b)
{
    return strcmp((const char *)a, (const char *)b);
}

/* Strips the comment and surrounding blanks; returns the trimmed length
 * (0 means skip the row) and points *s at the first character. */
static size_t baseline_trim(char *line, char **s)
{
    char *h = strchr(line, '#');
    if (h) *h = '\0';
    *s = line;
    while (isspace((unsigned char)**s)) (*s)++;
    size_t l = strlen(*s);
    while (l && isspace((unsigned char)(*s)[l - 1])) (*s)[--l] = '\0';
    return l;
}

static int baseline_add(char rows[][WCS_PATH], int *n, const char *s)
{
    if (*n >= WCS_TUS) {
        fprintf(stderr, "%s: baseline table exceeds %d rows\n", k_wcs_gate,
                WCS_TUS);
        return -1;
    }
    if (wcs_copy(rows[*n], WCS_PATH, s)) {
        fprintf(stderr, "%s: baseline row exceeds %d bytes\n", k_wcs_gate,
                WCS_PATH);
        return -1;
    }
    (*n)++;
    return 0;
}

static void baseline_dedup(char rows[][WCS_PATH], int *n)
{
    qsort(rows, (size_t)*n, WCS_PATH, cmp_files);
    int u = 0;
    for (int i = 0; i < *n; i++) {
        if (u > 0 && strcmp(rows[u - 1], rows[i]) == 0) continue;
        if (u != i) memcpy(rows[u], rows[i], WCS_PATH);
        u++;
    }
    *n = u;
}

static int baseline_rows(char rows[][WCS_PATH], int *n)
{
    FILE *f = fopen(k_wcs_baseline, "r");
    if (!f) return -1;
    static char line[WCS_PATH];
    *n = 0;
    while (fgets(line, sizeof line, f)) {
        size_t raw = strlen(line);
        if (raw && line[raw - 1] != '\n' && !feof(f)) {
            fprintf(stderr, "%s: baseline row exceeds %d bytes\n", k_wcs_gate,
                    WCS_PATH);
            fclose(f);
            return -1;
        }
        char *s = NULL;
        if (baseline_trim(line, &s) == 0) continue;
        if (baseline_add(rows, n, s)) {
            fclose(f);
            return -1;
        }
    }
    fclose(f);
    baseline_dedup(rows, n);
    return 0;
}

static int row_known(const char rows[][WCS_PATH], int n, const char *v)
{
    for (int i = 0; i < n; i++)
        if (strcmp(rows[i], v) == 0) return 1;
    return 0;
}

static void report_infra(const struct wcs_lists *L)
{
    fprintf(stderr, "%s: UNPROVEN — %d compiler infrastructure failure(s); "
            "no affected translation unit is counted clean:\n", k_wcs_gate,
            L->ninfra);
    for (int i = 0; i < L->ninfra; i++) {
        fprintf(stderr, "  %s (compiler rc=%s, result=%s)\n",
                L->infra[i].src, L->infra[i].rc, L->infra[i].kind);
        char log[WCS_PATH * 2], rc[WCS_PATH * 2];
        wcs_paths_for(L->infra[i].src, g_wcs_out, log, sizeof log, rc, sizeof rc);
        FILE *f = fopen(log, "r");
        if (f) {
            static char line[WCS_LINE];
            int n = 0;
            while (n < 80 && fgets(line, sizeof line, f)) {
                fprintf(stderr, "    %s", line);
                n++;
            }
            fclose(f);
        } else {
            fprintf(stderr, "    (compiler produced no diagnostic output)\n");
        }
    }
    fprintf(stderr, "\n  Check compiler installation/DLL integrity, memory "
            "and process limits, then rerun. A baseline cannot excuse "
            "infrastructure failure.\n");
}

static void report_new(const struct wcs_lists *L)
{
    fprintf(stderr, "%s: FAIL — %d file(s) failed mingw -fsyntax-only "
            "(not baselined, not a skippable missing header):\n", k_wcs_gate,
            L->nnew);
    for (int i = 0; i < L->nnew; i++) {
        fprintf(stderr, "  %s\n", L->newf[i]);
        char log[WCS_PATH * 2], rc[WCS_PATH * 2];
        wcs_paths_for(L->newf[i], g_wcs_out, log, sizeof log, rc, sizeof rc);
        FILE *f = fopen(log, "r");
        if (f) {
            static char line[WCS_LINE];
            while (fgets(line, sizeof line, f))
                if (strstr(line, "fatal error:") || strstr(line, ": error:"))
                    fprintf(stderr, "    %s", line);
            fclose(f);
        }
    }
    fprintf(stderr, "\n  A Windows-only syntax error or a bad #include is "
            "exactly what\n  this gate exists to catch. Fix the source. Do "
            "not add the file\n  to %s unless the failure is not a Windows "
            "bug (and then\n  name why). The baseline may only shrink.\n",
            k_wcs_baseline);
}

static void report_stale(char rows[][WCS_PATH], int n, int *stale, int ns)
{
    (void)rows; (void)n;
    fprintf(stderr, "%s: FAIL — %d baseline entr(y|ies) now compile clean "
            "or are only a skippable missing header.\n  This baseline is "
            "shrink-only. Delete these lines from %s:\n", k_wcs_gate, ns,
            k_wcs_baseline);
    for (int i = 0; i < ns; i++)
        fprintf(stderr, "    %s\n", rows[stale[i]]);
}

static void build_compile_argv(char *src, size_t l, char **cargv)
{
    int na = 0;
    cargv[na++] = g_wcs_cc;
    for (int fi = 0; fi < g_wcs_nflag; fi++)
        cargv[na++] = g_wcs_flag[fi];
    if (strncmp(src, "tests/harness/include/test/", 27) == 0) {
        cargv[na++] = (char *)"-DZCL_TESTING";
        cargv[na++] = (char *)"-include";
        cargv[na++] = (char *)"test/windows_compat.h";
    } else if (strstr(src, "/tests/") && l > 2 &&
               strcmp(src + l - 2, ".c") == 0) {
        cargv[na++] = (char *)"-DZCL_TESTING";
    }
    cargv[na++] = src;
    cargv[na] = NULL;
}

static void compile_one(char *src, size_t l)
{
    char log[WCS_PATH * 2], rcf[WCS_PATH * 2];
    static char *cargv[WCS_ARGS];
    build_compile_argv(src, l, cargv);
    wcs_paths_for(src, g_wcs_out, log, sizeof log, rcf, sizeof rcf);
    wcs_cache_compile(log, rcf, g_wcs_cc, cargv, src);
}

static void worker_child(const char *misslist, int jobs, int k)
{
    FILE *mf = fopen(misslist, "r");
    if (!mf) _exit(0);
    static char src[WCS_PATH];
    int i = 0;
    while (fgets(src, sizeof src, mf)) {
        size_t l = strlen(src);
        if (l && src[l - 1] == '\n') src[--l] = '\0';
        if (l && (i % jobs) == k) compile_one(src, l);
        i++;
    }
    fclose(mf);
    _exit(0);
}

/* Retries wait only on EINTR; any other wait error, or a failed fork, is
 * returned as 2 after the children already started are reaped. */
static int reap_children(int started)
{
    int rc = 0;
    for (int k = 0; k < started; k++) {
        int st;
        for (;;) {
            if (wait(&st) >= 0) break;
            if (errno == EINTR) continue;
            rc = 2;
            break;
        }
    }
    return rc;
}

static int worker_run(int jobs)
{
    char misslist[WCS_PATH];
    if (ovf(snprintf(misslist, sizeof misslist, "%s/misses.txt", g_wcs_work),
            sizeof misslist))
        return 2;
    int started = 0;
    for (int k = 0; k < jobs; k++) {
        pid_t pid = fork();
        if (pid < 0) {
            fprintf(stderr, "%s: fork failed for worker %d\n", k_wcs_gate, k);
            reap_children(started);
            return 2;
        }
        if (pid == 0) worker_child(misslist, jobs, k);
        started++;
    }
    return reap_children(started);
}

static int jobs_from_env(void)
{
    const char *j = getenv("ZCL_WIN_CROSS_JOBS");
    if (!j || !j[0]) j = getenv("ZCL_CC_JOBS");
    int n = 0;
    if (j && j[0]) {
        n = atoi(j);
        if (n < 1) n = 4;
    } else {
        long np = sysconf(_SC_NPROCESSORS_ONLN);
        n = np > 0 ? (int)np : 4;
    }
    if (n < 1) n = 4;
    if (n > 32) n = 32;
    return n;
}

static int make_out_dirs(void)
{
    if (wcs_mkdirs_p(g_wcs_out) != 0) return 2;
    for (int i = 0; i < g_wcs_nsrc; i++) {
        char d[WCS_PATH * 2];
        char *sl = strrchr(g_wcs_src[i], '/');
        if (!sl) continue;
        if (ovf(snprintf(d, sizeof d, "%s/%.*s", g_wcs_out,
                         (int)(sl - g_wcs_src[i]), g_wcs_src[i]), sizeof d))
            return 2;
        if (wcs_mkdirs_p(d) != 0) return 2;
    }
    return 0;
}

static int count_logs(void)
{
    int logs = 0;
    for (int i = 0; i < g_wcs_nsrc; i++) {
        char log[WCS_PATH * 2], rc[WCS_PATH * 2];
        wcs_paths_for(g_wcs_src[i], g_wcs_out, log, sizeof log, rc, sizeof rc);
        struct stat st;
        if (stat(log, &st) == 0) logs++;
    }
    return logs;
}

static int infra_keeps_row(const struct wcs_lists *L, const char *row)
{
    for (int j = 0; j < L->ninfra; j++)
        if (strcmp(L->infra[j].src, row) == 0) return 1;
    return 0;
}

static int find_stale(const struct wcs_lists *L, char brows[][WCS_PATH],
                      int bn, int *stale)
{
    int ns = 0;
    for (int i = 0; i < bn; i++) {
        if (row_known(L->still, L->nstill, brows[i])) continue;
        if (infra_keeps_row(L, brows[i])) continue;
        stale[ns++] = i;
    }
    return ns;
}

static int classify_all(int ossl_absent, struct wcs_lists *L)
{
    for (int i = 0; i < g_wcs_nsrc; i++) {
        int rc = classify_tu(g_wcs_src[i], ossl_absent, L);
        if (rc) return rc;
    }
    return 0;
}

static int verdict(const struct wcs_lists *L, char brows[][WCS_PATH], int bn,
                   int *stale, int ns)
{
    int rc = 0;
    if (L->ninfra > 0) { rc = 2; report_infra(L); }
    if (L->nnew > 0) { if (rc == 0) rc = 1; report_new(L); }
    if (ns > 0) { if (rc == 0) rc = 1; report_stale(brows, bn, stale, ns); }
    if (rc != 0) {
        printf("%s: compiled %d file(s), %d clean, %d generated-header skip, "
               "%d openssl-header skip, %d baselined, %d new failure(s), "
               "%d infrastructure failure(s).\n", k_wcs_gate, g_wcs_nsrc,
               L->nclean, L->nskipg, L->nskipo, L->nstill, L->nnew, L->ninfra);
        return rc;
    }
    printf("%s: PASS (%d files compiled, %d clean, %d generated-header skip, "
           "%d openssl-header skip, %d baselined, 0 new failures)\n",
           k_wcs_gate, g_wcs_nsrc, L->nclean, L->nskipg, L->nskipo, L->nstill);
    return 0;
}

int wcs_sweep(void)
{
    char srclist[WCS_PATH], flagsnul[WCS_PATH], misslist[WCS_PATH];
    if (ovf(snprintf(srclist, sizeof srclist, "%s/srcs.txt", g_wcs_work),
            sizeof srclist) ||
        ovf(snprintf(flagsnul, sizeof flagsnul, "%s/flags.nul", g_wcs_work),
            sizeof flagsnul) ||
        ovf(snprintf(misslist, sizeof misslist, "%s/misses.txt", g_wcs_work),
            sizeof misslist))
        return 2;
    int jobs = jobs_from_env();
    if (make_out_dirs() != 0) return 2;
    if (wcs_cache_setup(k_wcs_gate, "tools/lint/lintc/gate_windows_cross_syntax.c",
                        g_wcs_cc, flagsnul, g_wcs_work, ".", NULL) != 0)
        return 2;
    if (wcs_cache_plan(srclist, misslist, g_wcs_out, 0) != 0) return 2;
    if (worker_run(jobs) != 0) return 2;
    wcs_cache_summary();
    int r = gate_require_scanned(count_logs(), g_wcs_nsrc, k_wcs_gate, "");
    if (r) return r;
    struct stat st;
    int ossl_absent = stat("vendor/include/openssl/ssl.h", &st) != 0;
    if (stat(k_wcs_baseline, &st) != 0) {
        fprintf(stderr, "%s: FATAL — baseline '%s' is missing.\n"
                "  Refusing to report clean with nothing to ratchet against.\n",
                k_wcs_gate, k_wcs_baseline);
        return 2;
    }
    static struct wcs_lists L;
    memset(&L, 0, sizeof L);
    r = classify_all(ossl_absent, &L);
    if (r) return r;
    static char brows[WCS_TUS][WCS_PATH];
    static int stale[WCS_TUS];
    int bn = 0;
    if (baseline_rows(brows, &bn) != 0) return 2;
    int ns = find_stale(&L, brows, bn, stale);
    return verdict(&L, brows, bn, stale, ns);
}

