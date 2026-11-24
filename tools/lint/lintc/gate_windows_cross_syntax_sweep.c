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
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include "base/safe_alloc.h"
#include "lintc.h"
#include "gate_windows_cross_syntax_priv.h"

/* ── the compile sweep and verdict ──────────────────────────────────── */

struct wcs_infra { char src[WCS_PATH]; char rc[32]; char kind[40]; };

struct wcs_lists {
    char still[WCS_TUS][WCS_PATH]; int nstill;
    char newf[WCS_TUS][WCS_PATH]; int nnew;
    int nskipg;
    int nskipo;
    int nclean;
    struct wcs_infra infra[WCS_TUS]; int ninfra;
};

static struct wcs_lists g_wcs_lists;

static void lists_reset(struct wcs_lists *L)
{
    L->nstill = L->nnew = L->nskipg = L->nskipo = L->nclean = L->ninfra = 0;
}

static int lists_push(char arr[][WCS_PATH], int *n, const char *v)
{
    if (*n >= WCS_TUS) {
        fprintf(stderr, "%s: translation-unit table exceeds %d\n", k_wcs_gate, WCS_TUS);
        return 2;
    }
    size_t len = strlen(v);
    if (len >= WCS_PATH) {
        fprintf(stderr, "%s: path exceeds %d bytes: %s\n", k_wcs_gate, WCS_PATH, v);
        return 2;
    }
    if (arr) memcpy(arr[*n], v, len + 1);
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
        return lists_push(NULL, &L->nclean, src);
    if (strcmp(kind, "SKIP_GENERATED") == 0)
        return lists_push(NULL, &L->nskipg, src);
    if (strcmp(kind, "COMPILER_FAILURE") == 0 ||
        strcmp(kind, "MISSING_RESULT") == 0 ||
        strcmp(kind, "INCONSISTENT_SUCCESS") == 0)
        return push_infra(L, src, rcs, kind);
    if (ossl_absent && (strcmp(kind, "SKIP_OPENSSL") == 0 ||
                        strcmp(kind, "SKIP_HEADERS") == 0))
        return lists_push(NULL, &L->nskipo, src);
    int known = in_baseline(src);
    return lists_push(known ? L->still : L->newf,
                      known ? &L->nstill : &L->nnew, src);
}

static int classify_tu(const char *src, int ossl_absent, unsigned char log_shape,
                       struct wcs_lists *L)
{
    char log[WCS_PATH * 2], rc[WCS_PATH * 2], rcs[64], kind[40];
    if (wcs_paths_for(src, g_wcs_out, log, sizeof log, rc, sizeof rc) != 0)
        return 2;
    if (read_rc_file(rc, rcs, sizeof rcs) < 0) {
        fprintf(stderr, "%s: result row exceeds %d bytes: %s\n", k_wcs_gate,
                (int)sizeof rcs, rc);
        return 2;
    }
    if (strcmp(rcs, "0") == 0 && log_shape == 1)
        return lists_push(NULL, &L->nclean, src);
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

/* Sealed files whose POSIX-only static helper stays in the TU. The Makefile
 * gives the same two objects -Wno-unused-function on a Windows host; the gate
 * must not hold them to a stricter rule than the product build does. */
static const char *const k_wcs_unused_exempt[] = {
    "core/modules/net/src/https_server_install.c",
    "core/modules/net/src/rom_fetch.c", NULL
};

static void build_compile_argv(char *src, size_t l, char **cargv)
{
    int na = 0;
    cargv[na++] = g_wcs_cc;
    for (int fi = 0; fi < g_wcs_nflag; fi++)
        cargv[na++] = g_wcs_flag[fi];
    if (wcs_name_in(src[0] == '.' && src[1] == '/' ? src + 2 : src,
                    k_wcs_unused_exempt))
        cargv[na++] = (char *)"-Wno-unused-function";
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

static void wcs_worker_child(char (*rows)[WCS_PATH], int count, _Atomic int *next)
{
    for (;;) {
        int i = atomic_fetch_add_explicit(next, 1, memory_order_relaxed);
        if (i >= count) break;
        compile_one(rows[i], strlen(rows[i]));
    }
    _exit(0);
}

/* Retries wait only on EINTR; any other wait error, or a failed fork, is
 * returned as 2 after the children already started are reaped. */
int wcs_reap_workers(const pid_t *pids, int count)
{
    int rc = 0;
    for (int k = 0; k < count; k++) {
        int st;
        if (pids[k] <= 0) { fprintf(stderr, "%s: invalid worker pid\n", k_wcs_gate); rc = 2; continue; }
        for (;;) {
            if (waitpid(pids[k], &st, 0) == pids[k]) {
                if (!WIFEXITED(st) || WEXITSTATUS(st) != 0) {
                    fprintf(stderr, "%s: worker %ld failed (status %d)\n", k_wcs_gate, (long)pids[k], st);
                    rc = 2;
                }
                break;
            }
            if (errno == EINTR) continue;
            fprintf(stderr, "%s: cannot wait for worker %ld: %s\n", k_wcs_gate, (long)pids[k], strerror(errno));
            rc = 2;
            break;
        }
    }
    return rc;
}

/* Append one validated path, bounded by the gate's TU and path limits. */
static int worker_list_append(char (**rows)[WCS_PATH], int *count,
                              int *capacity, const char *row, size_t len)
{
    if (!len || len >= WCS_PATH || *count >= WCS_TUS) return EINVAL;
    if (*count == *capacity) {
        int n = *capacity ? *capacity * 2 : 64;
        if (n > WCS_TUS) n = WCS_TUS;
        void *p = zcl_realloc(*rows, (size_t)n * sizeof **rows, "wcs_work_rows");
        if (!p) return ENOMEM;
        *rows = p;
        *capacity = n;
    }
    memcpy((*rows)[(*count)++], row, len + 1);
    return 0;
}

/* Read the full private miss list before forking. The extra byte distinguishes
 * a maximal unterminated path from an overlong row without a speculative read. */
static int worker_list_stream(FILE *f, char (**rows)[WCS_PATH], int *count)
{
    char row[WCS_PATH + 1];
    int capacity = 0;
    while (fgets(row, sizeof row, f)) {
        size_t len = strlen(row);
        if (len && row[len - 1] == '\n') row[--len] = '\0';
        int error = worker_list_append(rows, count, &capacity, row, len);
        if (error) return error;
    }
    return ferror(f) ? EIO : 0;
}

int wcs_worker_list_selftest(void)
{
    FILE *f = tmpfile();
    if (!f) return 2;
    for (int i = 0; i < WCS_PATH - 1; i++)
        if (fputc('x', f) == EOF) { fclose(f); return 2; }
    if (fflush(f) != 0 || fseek(f, 0, SEEK_SET) != 0) { fclose(f); return 2; }
    char (*rows)[WCS_PATH] = NULL;
    int count = 0;
    int rc = worker_list_stream(f, &rows, &count);
    int ok = rc == 0 && count == 1 && strlen(rows[0]) == WCS_PATH - 1;
    if (fclose(f) != 0) ok = 0;
    free(rows);
    rows = NULL;
    int cap = 0;
    count = WCS_TUS;
    ok = ok && worker_list_append(&rows, &count, &cap, "x", 1) == EINVAL;
    count = 0;
    ok = ok && worker_list_append(&rows, &count, &cap, "", 0) == EINVAL;
    ok = ok && worker_list_append(&rows, &count, &cap, "x", WCS_PATH) == EINVAL;
    free(rows);
    return ok ? 0 : 1;
}

static int worker_list_read(const char *path, char (**rows)[WCS_PATH])
{
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0) return -1;
    struct stat st;
    if (fstat(fd, &st) != 0) { close(fd); return -1; }
    if (!S_ISREG(st.st_mode)) { close(fd); errno = EINVAL; return -1; }
    FILE *f = fdopen(fd, "r");
    if (!f) { close(fd); return -1; }
    int count = 0;
    int read_error = worker_list_stream(f, rows, &count);
    int closed = fclose(f);
    if (read_error) { errno = read_error; return -1; }
    if (closed != 0) return -1;
    return count;
}

static int worker_index_unmap(_Atomic int *next)
{
    if (munmap(next, sizeof *next) == 0) return 0;
    fprintf(stderr, "%s: cannot unmap shared work index: %s\n", k_wcs_gate, strerror(errno));
    return 2;
}

int wcs_worker_run(const char *misslist, int jobs, int *started_out)
{
    int started = 0;
    if (started_out) *started_out = 0;
    if (jobs < 1 || jobs > 32) { errno = EINVAL; return 2; }
    char (*rows)[WCS_PATH] = NULL;
    int count = worker_list_read(misslist, &rows);
    if (count < 0) {
        fprintf(stderr, "%s: cannot read miss list %s: %s\n",
                k_wcs_gate, misslist, strerror(errno));
        free(rows);
        return 2;
    }
    if (!count) { free(rows); return 0; }
    if (count < jobs) jobs = count;
    _Atomic int *next = mmap(NULL, sizeof *next, PROT_READ | PROT_WRITE,
                             MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (next == MAP_FAILED) {
        fprintf(stderr, "%s: cannot map shared work index: %s\n", k_wcs_gate, strerror(errno));
        free(rows); return 2;
    }
    atomic_init(next, 0);
    if (!atomic_is_lock_free(next)) {
        fprintf(stderr, "%s: shared work index is not lock-free\n", k_wcs_gate);
        (void)worker_index_unmap(next); free(rows); return 2;
    }
    pid_t pids[32];
    for (int k = 0; k < jobs; k++) {
        pid_t pid = fork();
        if (pid < 0) {
            fprintf(stderr, "%s: fork failed for worker %d\n", k_wcs_gate, k);
            atomic_store_explicit(next, count, memory_order_relaxed);
            wcs_reap_workers(pids, started);
            (void)worker_index_unmap(next); free(rows);
            return 2;
        }
        if (pid == 0) wcs_worker_child(rows, count, next);
        pids[started++] = pid;
        if (started_out) *started_out = started;
    }
    int rc = wcs_reap_workers(pids, started);
    if (worker_index_unmap(next) != 0) rc = 2;
    free(rows);
    return rc;
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

/* 0 is missing/nonregular; 1 is an empty regular log; 2 is nonempty. */
int wcs_log_shape(const char *path)
{
    struct stat st;
    if (stat(path, &st) != 0 || !S_ISREG(st.st_mode)) return 0;
    return st.st_size == 0 ? 1 : 2;
}

static int count_logs(unsigned char *shapes)
{
    int logs = 0;
    for (int i = 0; i < g_wcs_nsrc; i++) {
        char log[WCS_PATH * 2], rc[WCS_PATH * 2];
        if (wcs_paths_for(g_wcs_src[i], g_wcs_out, log, sizeof log, rc, sizeof rc)) return -1;
        shapes[i] = (unsigned char)wcs_log_shape(log);
        if (shapes[i]) logs++;
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

static int classify_all(int ossl_absent, const unsigned char *shapes, struct wcs_lists *L)
{
    for (int i = 0; i < g_wcs_nsrc; i++) {
        int rc = classify_tu(g_wcs_src[i], ossl_absent, shapes[i], L);
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

/* The second verdict must ignore old rows without clearing unused storage. */
int wcs_lists_selftest(void)
{
    struct wcs_lists *L = &g_wcs_lists;
    char brows[1][WCS_PATH] = {"old.c"};
    int stale[1];
    L->nstill = L->nnew = L->nskipg = L->nskipo = L->nclean = L->ninfra = 1;
    memcpy(L->still[0], "old.c", sizeof "old.c");
    memcpy(L->newf[0], "old.c", sizeof "old.c");
    memcpy(L->infra[0].src, "old.c", sizeof "old.c");
    L->newf[WCS_TUS - 1][0] = 'X';
    lists_reset(L);
    int ok = L->nstill == 0 && L->nnew == 0 && L->nskipg == 0 &&
             L->nskipo == 0 && L->nclean == 0 && L->ninfra == 0 &&
             L->newf[WCS_TUS - 1][0] == 'X';
    if (ok) ok = find_stale(L, brows, 1, stale) == 1 && stale[0] == 0;
    if (ok) ok = lists_push(L->newf, &L->nnew, "new.c") == 0 &&
                 L->nnew == 1 && strcmp(L->newf[0], "new.c") == 0;
    lists_reset(L);
    if (!ok) fprintf(stderr, "%s: verdict reset self-test failed\n", k_wcs_gate);
    return ok ? 0 : 1;
}

static int wcs_sweep_inner(void)
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
    if (wcs_worker_run(misslist, jobs, NULL) != 0) return 2;
    wcs_cache_summary();
    unsigned char shapes[WCS_TUS];
    int r = gate_require_scanned(count_logs(shapes), g_wcs_nsrc, k_wcs_gate, "");
    if (r) return r;
    struct stat st;
    int ossl_absent = stat("vendor/include/openssl/ssl.h", &st) != 0;
    if (stat(k_wcs_baseline, &st) != 0) {
        fprintf(stderr, "%s: FATAL — baseline '%s' is missing.\n"
                "  Refusing to report clean with nothing to ratchet against.\n",
                k_wcs_gate, k_wcs_baseline);
        return 2;
    }
    struct wcs_lists *L = &g_wcs_lists;
    lists_reset(L);
    r = classify_all(ossl_absent, shapes, L);
    if (r) return r;
    static char brows[WCS_TUS][WCS_PATH];
    static int stale[WCS_TUS];
    int bn = 0;
    if (baseline_rows(brows, &bn) != 0) return 2;
    int ns = find_stale(L, brows, bn, stale);
    return verdict(L, brows, bn, stale, ns);
}


int wcs_sweep(void)
{
    int rc = wcs_sweep_inner();
    wcs_cache_release();
    return rc;
}
