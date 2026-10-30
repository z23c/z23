/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: gate check-pipefail-status-pipe — refuse NEW status-carrying
 * `... | grep -q` pipelines in scripts that set pipefail (any producer).
 * Shrink-only ratchet over tools/lint/pipefail_status_pipe_baseline.txt.
 * Ported from tools/lint/check_pipefail_status_pipe.sh (deleted). Selftest:
 * gate_pipefail_status_pipe_selftest.c.
 *
 * The scanner is a port of the shell-grammar tokeniser in the original awk:
 * quote-aware comment strip, then a split on statement/pipeline separators
 * (`;` `&&` `||` `|` `(` `)` `{` `}` then/do/else, newline unless a
 * continuation). It never anchors on line shape, indent or column, so a
 * reindented violation still counts. Only a -q grep stage counts (grep,
 * egrep, fgrep, gate_grep); a file without "pipefail" anywhere is exempt;
 * heredoc bodies are data, not code. Fail closed: unreadable file, line or
 * statement over the fixed buffers, or a broken scan set is exit 2.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <ctype.h>
#include <errno.h>
#include <glob.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdlib.h>
#include "lintc.h"
#include "gate_pipefail_status_pipe_priv.h"



static char psp_files[PSP_FILES][PSP_PATH];
static int psp_nfiles;

static char psp_rpath[PSP_ROWS][PSP_PATH];
static long psp_rcount[PSP_ROWS], psp_rline[PSP_ROWS];
static int psp_nrows;

static char psp_bpath[PSP_BASE][PSP_PATH], psp_bval[PSP_BASE][PSP_VAL];
static int psp_bn;

/* Bounded copy; an over-long value is a hard error (ovf), never truncated. */
static void psp_cpy(char *dst, size_t cap, const char *src)
{
    size_t n = strlen(src);
    ovf(n >= cap ? (int)cap : (int)n, cap);
    memcpy(dst, src, n + 1);
}

/* ── scan-set collection ─────────────────────────────────────────────── */
static void psp_add_file(const char *p)
{
    ovf(psp_nfiles, PSP_FILES);
    psp_cpy(psp_files[psp_nfiles], PSP_PATH, p);
    psp_nfiles++;
}

static void psp_glob_env(const char *spec)
{
    char tok[PSP_PATH];
    size_t o = 0;
    const char *p = spec;
    while (*p) {
        while (*p == ' ' || *p == '\t')
            p++;
        if (!*p)
            break;
        o = 0;
        while (*p && *p != ' ' && *p != '\t' && o + 1 < sizeof tok)
            tok[o++] = *p++;
        tok[o] = '\0';
        glob_t g;
        if (glob(tok, 0, NULL, &g) == 0) {
            for (size_t i = 0; i < g.gl_pathc && psp_nfiles < PSP_FILES; i++)
                psp_add_file(g.gl_pathv[i]);
        }
        globfree(&g);
    }
}

static int psp_git_ls_sh(void)
{
    int fd[2];
    if (pipe(fd) != 0)
        return 1;
    pid_t pid = fork();
    if (pid == 0) {
        dup2(fd[1], STDOUT_FILENO);
        close(fd[0]);
        close(fd[1]);
        char *av[] = { (char *)"git", (char *)"ls-files", (char *)"*.sh",
                       NULL };
        execvp("git", av);
        _exit(127);
    }
    close(fd[1]);
    static char buf[1 << 22];
    size_t got = 0;
    ssize_t r;
    while (got + 1 < sizeof buf &&
           (r = read(fd[0], buf + got, sizeof buf - 1 - got)) > 0)
        got += (size_t)r;
    close(fd[0]);
    int st = 0;
    waitpid(pid, &st, 0);
    if (r < 0 || !WIFEXITED(st) || WEXITSTATUS(st) != 0)
        return 1;
    buf[got] = '\0';
    char *save = NULL;
    for (char *ln = strtok_r(buf, "\n", &save); ln && psp_nfiles < PSP_FILES;
         ln = strtok_r(NULL, "\n", &save)) {
        struct stat sb;
        if (stat(ln, &sb) == 0 && S_ISREG(sb.st_mode))
            psp_add_file(ln);
    }
    return 0;
}

/* ── baseline (kv file: <path> <count>, '#' comments) ────────────────── */
static void psp_trim(char *s)
{
    size_t n = strlen(s);
    while (n > 0 && (s[n - 1] == ' ' || s[n - 1] == '\t' ||
                     s[n - 1] == '\n' || s[n - 1] == '\r'))
        s[--n] = '\0';
    size_t o = 0;
    while (s[o] == ' ' || s[o] == '\t')
        o++;
    if (o)
        memmove(s, s + o, n - o + 1);
}

static int psp_base_cb(void *ctx, const char *line, size_t n)
{
    (void)ctx;
    char buf[PSP_PATH + PSP_VAL];
    if (n >= sizeof buf)
        return psp_err2("baseline line", NULL, (long)sizeof buf);
    memcpy(buf, line, n);
    buf[n] = '\0';
    char *h = strchr(buf, '#');
    if (h)
        *h = '\0';
    psp_trim(buf);
    if (!buf[0])
        return 0;
    if (psp_bn >= PSP_BASE)
        return psp_err2("baseline rows", NULL, (long)PSP_BASE);
    char *sp = strchr(buf, ' ');
    char *sp2 = sp ? strrchr(buf, ' ') : NULL;
    if (!sp2) {
        psp_trim(buf);
        psp_cpy(psp_bpath[psp_bn], PSP_PATH, buf);
        psp_bval[psp_bn][0] = '\0';
    } else {
        *sp2 = '\0';
        psp_cpy(psp_bpath[psp_bn], PSP_PATH, buf);
        psp_cpy(psp_bval[psp_bn], PSP_VAL, sp2 + 1);
    }
    psp_bn++;
    return 0;
}


static int psp_cmp_str(const void *a, const void *b)
{
    return strcmp((const char *)a, (const char *)b);
}

/* ── the driver ──────────────────────────────────────────────────────── */
static char psp_viol[PSP_ROWS + 1][PSP_ROW];
static char psp_toler[PSP_ROWS][PSP_ROW];
static char psp_stale[PSP_BASE][PSP_ROW];
static int psp_nviol, psp_ntol, psp_nstale;

static int psp_collect(FILE *err, const char *gl, int floor)
{
    psp_nfiles = psp_bn = psp_nrows = 0;
    if (gl)
        psp_glob_env(gl);
    else if (psp_git_ls_sh()) {
        psp_nfiles = 0; /* git oracle broken: empty scan, floor fires */
    }
    if (psp_nfiles < floor) {
        fprintf(err, PSP_GATE ": FATAL — scan set is '%d' (< floor %d).\n"
                "  The scan producer (find/glob/grep) returned too little; a\n"
                "  scanned dir/file was likely renamed, moved, or deleted.\n"
                "  Refusing to report 'clean' off a hollow (empty) scan.\n"
                "  no *.sh files found — the scan set (git ls-files '*.sh') "
                "moved or emptied\n", psp_nfiles, floor);
        return 2;
    }
    for (int i = 0; i < psp_nfiles; i++) {
        long c = 0, fl = 0;
        if (psp_scan_file(psp_files[i], &c, &fl) == 2)
            return 2;
        if (c <= 0)
            continue;
        if (psp_nrows >= PSP_ROWS)
            return psp_err2("count rows", NULL, (long)PSP_ROWS);
        psp_cpy(psp_rpath[psp_nrows], PSP_PATH, psp_files[i]);
        psp_rcount[psp_nrows] = c;
        psp_rline[psp_nrows] = fl;
        psp_nrows++;
    }
    return 0;
}

static int psp_load_base(FILE *err, const char *base_p, int *sum)
{
    struct stat bst;
    int sr = stat(base_p, &bst);
    /* ENOENT or a non-regular file is an empty baseline (gate_load_kv_file) */
    int present = sr == 0 && S_ISREG(bst.st_mode);
    if ((sr != 0 && errno != ENOENT) ||
        (present && psp_each_line(base_p, psp_base_cb, NULL))) {
        fprintf(err, "[" PSP_GATE "] FATAL — cannot read baseline %s\n",
                base_p);
        return 2;
    }
    *sum = 0;
    for (int i = 0; i < psp_bn; i++) {
        const char *v = psp_bval[i];
        int ok = v[0] != '\0';
        for (const char *p = v; *p; p++)
            if (*p < '0' || *p > '9')
                ok = 0;
        if (!ok) {
            fprintf(err, "[" PSP_GATE "] FATAL — baseline row '%s' has a "
                    "non-numeric count '%s' in %s\n", psp_bpath[i], v,
                    base_p);
            return 2;
        }
        *sum += atoi(v);
    }
    return 0;
}

static long psp_classify(void)
{
    long total_sites = 0;
    psp_nviol = psp_ntol = psp_nstale = 0;
    static int hit[PSP_BASE];
    memset(hit, 0, sizeof hit);
    for (int r = 0; r < psp_nrows; r++) {
        total_sites += psp_rcount[r];
        int bi = -1;
        for (int i = 0; i < psp_bn; i++)
            if (strcmp(psp_bpath[i], psp_rpath[r]) == 0)
                bi = i;
        if (bi >= 0) {
            hit[bi] = 1;
            if (psp_rcount[r] <= (long)atoi(psp_bval[bi])) {
                viol_put(psp_toler[psp_ntol++], PSP_ROW, "%s (%ld/%s)",
                         psp_rpath[r], psp_rcount[r], psp_bval[bi]);
                continue;
            }
            viol_put(psp_viol[psp_nviol++], PSP_ROW,
                     "%s:%ld — %ld status-carrying grep -q pipeline(s), "
                     "baseline allows %s", psp_rpath[r], psp_rline[r],
                     psp_rcount[r], psp_bval[bi]);
        } else {
            viol_put(psp_viol[psp_nviol++], PSP_ROW,
                     "%s:%ld — %ld status-carrying grep -q pipeline(s), not "
                     "in the baseline (a new file may carry ZERO)",
                     psp_rpath[r], psp_rline[r], psp_rcount[r]);
        }
    }
    for (int i = 0; i < psp_bn; i++)
        if (!hit[i])
            viol_put(psp_stale[psp_nstale++], PSP_ROW,
                     "%s (baseline says %s, actual 0)", psp_bpath[i],
                     psp_bval[i]);
    return total_sites;
}

static void psp_ceiling(FILE *out, const char *base_p, int baseline_sum,
                        int ceiling)
{
    if (baseline_sum > ceiling) {
        fprintf(out, "\n[" PSP_GATE "] baseline sum (%d) exceeds the ratchet "
                "ceiling (%d)\n        in %s — the baseline was edited "
                "upward. Lower it back, or\n        lower RATCHET_CEILING in "
                "this script if the tolerated set has\n        genuinely "
                "shrunk (a change that belongs in code review, not a\n"
                "        quiet data-file edit).\n", baseline_sum, ceiling,
                base_p);
        viol_put(psp_viol[psp_nviol++], PSP_ROW,
                 "%s — baseline sum %d exceeds ceiling %d", base_p,
                 baseline_sum, ceiling);
    }
}

static int psp_update(FILE *err, FILE *out, const char *base_p)
{
        FILE *b = fopen(base_p, "w");
        if (!b) {
            fprintf(err, PSP_GATE ": cannot write baseline %s\n", base_p);
            return 2;
        }
        static char upd[PSP_ROWS][PSP_PATH + PSP_VAL];
        for (int r = 0; r < psp_nrows; r++)
            viol_put(upd[r], sizeof upd[r], "%s %ld", psp_rpath[r],
                     psp_rcount[r]);
        qsort(upd, (size_t)psp_nrows, sizeof upd[0], psp_cmp_str);
        fputs("# " PSP_GATE " baseline — scripts still deciding something "
              "on the exit\n# status of a `… | grep -q` pipeline (any "
              "producer) while\n# pipefail is set. Under pipefail a MATCH "
              "can report the producer's\n# SIGPIPE 141 instead of grep's 0, "
              "so the decision can silently invert.\n#\n# Format: <path> "
              "<count>.  COUNTS MAY ONLY SHRINK.\n#\n# Fix a row: use "
              "str_contains/str_lacks from tools/scripts/sh_str.sh, or\n# "
              "extract the match into a variable (drop -q, so grep drains "
              "stdin) and\n# test the STRING. For a REGEX needle, where "
              "str_contains (fixed-needle\n# only) does not apply, feed grep "
              "a here-string instead:\n#     grep -qE \"$RE\" <<<\""
              "$haystack\"\n# which is not a pipeline, so nothing can "
              "invert. Then lower or delete\n# the number here. Adding a row "
              "for a NEW file is not a fix — a file\n# with no row may carry "
              "ZERO.\n#\n# Regenerate: ZCL_LINT_MODE=UPDATE build/bin/z23-lint "
              "check-pipefail-status-pipe\n", b);
        for (int r = 0; r < psp_nrows; r++)
            fprintf(b, "%s\n", upd[r]);
        fclose(b);
        fprintf(out, "[" PSP_GATE "] baseline UPDATED: %s\n", base_p);
        return 0;
}

static int psp_report_viol(FILE *out, const char *base_p)
{
    if (psp_nviol > 0) {
        qsort(psp_viol, (size_t)psp_nviol, sizeof psp_viol[0], psp_cmp_str);
        fprintf(out, "\n[" PSP_GATE "] %d violation(s) — a new or grown "
                "status-carrying\n        `… | grep -q` pipeline under "
                "pipefail (any producer):\n", psp_nviol);
        for (int i = 0; i < psp_nviol; i++)
            fprintf(out, "  %s\n", psp_viol[i]);
        fputs("\n  grep -q writes nothing to stdout, so its exit status IS "
              "the decision —\n  and under pipefail a MATCH can surface the "
              "producer's SIGPIPE 141 instead of\n  grep's 0. Rewrite it one "
              "of three ways:\n    . tools/scripts/sh_str.sh   # then "
              "str_contains / str_lacks\n    grep -qE 'RE' <<<\"$out\"      "
              "    # here-string: not a pipeline\n    hit=$(printf "
              "'%s\\n' \"$out\" | grep 'RE' || true); [ -n \"$hit\" ]\n  The "
              "last two keep your exact regex and engine, and are the "
              "right\n  choice for an anchored or otherwise non-fixed-string "
              "match — never\n  rewrite a digest/signature validator into a "
              "different regex engine\n  to fix a bug a short single-value "
              "haystack cannot have.\n  Raising a number in ", out);
        fprintf(out, "%s is NOT a fix; counts may only shrink.\n", base_p);
        return 1;
    }
    return 0;
}

static int psp_report_stale(FILE *out, const char *base_p)
{
    if (psp_nstale > 0) {
        qsort(psp_stale, (size_t)psp_nstale, sizeof psp_stale[0], psp_cmp_str);
        fprintf(out, "\n[" PSP_GATE "] %d STALE baseline row(s) — the file "
                "no longer carries\n        this shape. Delete them from "
                "%s:\n", psp_nstale, base_p);
        for (int i = 0; i < psp_nstale; i++)
            fprintf(out, "  %s\n", psp_stale[i]);
        return 1;
    }
    return 0;
}

int psp_main(FILE *out, FILE *err)
{
    const char *mode = env_or("ZCL_LINT_MODE", "FAIL");
    const char *base_p = env_or("ZCL_PIPEFAIL_GATE_BASELINE",
                                "tools/lint/pipefail_status_pipe_baseline.txt");
    int ceiling = atoi(env_or("ZCL_PIPEFAIL_GATE_CEILING", "104"));
    const char *gl = getenv("ZCL_PIPEFAIL_GATE_SCAN_GLOB");
    int floor = atoi(env_or("ZCL_PIPEFAIL_GATE_FILE_FLOOR",
                            gl ? "1" : "200"));
    int baseline_sum = 0;
    if (psp_collect(err, gl, floor) || psp_load_base(err, base_p, &baseline_sum))
        return 2;
    int baseline_count = psp_bn;
    long total_sites = psp_classify();
    psp_ceiling(out, base_p, baseline_sum, ceiling);
    if (strcmp(mode, "UPDATE") == 0)
        return psp_update(err, out, base_p);
    int fail = psp_report_viol(out, base_p);
    fail |= psp_report_stale(out, base_p);
    if (fail && strcmp(mode, "FAIL") == 0)
        return 1;
    fprintf(out, "[" PSP_GATE "] PASS (%d *.sh files scanned, %d carrying "
            "the shape, %ld total, %d baselined file(s) summing to %d/%d, "
            "%d tolerated, no allow-comment mechanism exists)\n", psp_nfiles,
            psp_nrows, total_sites, baseline_count, baseline_sum, ceiling,
            psp_ntol);
    return 0;
}

int check_pipefail_status_pipe_run(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    return psp_main(stdout, stderr);
}
