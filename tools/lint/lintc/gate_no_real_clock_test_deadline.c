/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: C23 lint gate family — port of
 * tools/lint/check_no_real_clock_test_deadline.sh (check-no-real-clock-
 * test-deadline). Refuses, in tests/harness/src/ *.c sources, an
 * ASSERT/EXPECT/REQUIRE/ *CHECK() whose balanced-paren argument text calls
 * a real-clock reader and computes a difference (or calls difftime()), or
 * a sleep/usleep/nanosleep/platform_sleep_ms() call inside a fixed-
 * iteration for/while poll loop ("poll N times, sleeping between each"
 * used as a real-clock deadline) — unless the exact source line carries a
 * reviewed real-clock-marker comment (open-comment, "real-clock:", a
 * reason, close-comment). See the replaced script's header for the full
 * "why a separate gate" rationale; not repeated here.
 *
 * Single-gate family file. Production scan (ZCL_LINT_PRODUCTION_SCAN=1, set
 * by every `make check-*` target) walks git-tracked files under
 * tests/harness/src/ via the index; a full/dev scan (no production flag —
 * what every selftest and the make_lint_gates sandbox, a hardlink clone
 * without .git, exercises) globs the filesystem directly, matching the
 * repo's established fallback convention (see
 * gate_include_direction_fences.c). Selftests are in the sibling
 * gate_no_real_clock_test_deadline_selftest.c.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <errno.h>
#include <glob.h>
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "lintc.h"

enum { NRC_LOOP_MAX = 256, NRC_LINE = CSTRIP_LINE_MAX, NRC_VMAX = 512,
       NRC_VTEXT = RS_PATH + 160 };

static const char k_nrc_marker_pat[] =
    "/\\*[[:space:]]*real-clock:[[:space:]]*[^*]+\\*/";
static const char k_nrc_reader_pat[] =
    "(^|[^A-Za-z0-9_])(clock_gettime|gettimeofday|"
    "platform_time_monotonic_timespec|platform_time_wall_time_t|"
    "platform_time_monotonic_ms|platform_now_[A-Za-z0-9_]*|"
    "clock_now_monotonic_ns|clock_now_wall_ms|difftime)[[:space:]]*\\("
    "|(^|[^A-Za-z0-9_])time[[:space:]]*\\([[:space:]]*(NULL|0)[[:space:]]*\\)";
static const char k_nrc_sleep_pat[] =
    "(^|[^A-Za-z0-9_])(usleep|nanosleep|platform_sleep_ms|sleep)"
    "[[:space:]]*\\(";
static const char k_nrc_loopopen_pat[] =
    "(^|[^A-Za-z0-9_])(for|while)[[:space:]]*\\(.*(<|<=)[[:space:]]*"
    "[0-9]+.*\\)[[:space:]]*\\{[[:space:]]*$";
static const char k_nrc_assertopen_pat[] =
    "(^|[^A-Za-z0-9_])(ASSERT[A-Za-z0-9_]*|EXPECT[A-Za-z0-9_]*|"
    "REQUIRE[A-Za-z0-9_]*|[A-Za-z0-9_]*CHECK)[[:space:]]*\\(";

struct nrc_pats {
    regex_t marker, reader, sleep, loopopen, assertopen;
};

struct nrc_walk_state {
    int loopstack[NRC_LOOP_MAX];
    int loopdepth;
    int depth;
    struct cstrip cs;
};

struct nrc_acc {
    const struct nrc_pats *p;
    char viol[NRC_VMAX][NRC_VTEXT];
    int nviol;
    int markers;
    int files;
};

static int nrc_pats_compile(struct nrc_pats *p)
{
    if (reg_fail(&p->marker, regcomp(&p->marker, k_nrc_marker_pat,
                                     REG_EXTENDED)))
        return 2;
    if (reg_fail(&p->reader, regcomp(&p->reader, k_nrc_reader_pat,
                                     REG_EXTENDED))) {
        regfree(&p->marker);
        return 2;
    }
    if (reg_fail(&p->sleep, regcomp(&p->sleep, k_nrc_sleep_pat,
                                    REG_EXTENDED))) {
        drop2(&p->marker, &p->reader);
        return 2;
    }
    if (reg_fail(&p->loopopen, regcomp(&p->loopopen, k_nrc_loopopen_pat,
                                       REG_EXTENDED))) {
        drop3(&p->marker, &p->reader, &p->sleep);
        return 2;
    }
    if (reg_fail(&p->assertopen, regcomp(&p->assertopen,
                                         k_nrc_assertopen_pat,
                                         REG_EXTENDED))) {
        drop3(&p->marker, &p->reader, &p->sleep);
        regfree(&p->loopopen);
        return 2;
    }
    return 0;
}

static void nrc_pats_free(struct nrc_pats *p)
{
    drop3(&p->marker, &p->reader, &p->sleep);
    drop2(&p->loopopen, &p->assertopen);
}

static void nrc_strip_nl(char *line)
{
    size_t n = strlen(line);
    while (n > 0 && (line[n - 1] == '\n' || line[n - 1] == '\r'))
        line[--n] = '\0';
}

static int nrc_count_char(const char *s, char c)
{
    int n = 0;
    for (; *s; s++)
        if (*s == c)
            n++;
    return n;
}

/* Balance-count parens starting at buf[0] == '(' and return the length of
 * the balanced call text (inclusive of the matching ')'), or the whole
 * string when the parens never close on this line — the awk original's
 * `for (c = 1; c <= length(buf); c++) { ...; if (d2 == 0) break }` then
 * `substr(buf, 1, c)`. */
static size_t nrc_balanced_len(const char *buf)
{
    int depth = 0;
    size_t i = 0;
    for (; buf[i] != '\0'; i++) {
        if (buf[i] == '(') {
            depth++;
        } else if (buf[i] == ')') {
            depth--;
            if (depth == 0) {
                i++;
                return i;
            }
        }
    }
    return i;
}

static int nrc_note(struct nrc_acc *a, const char *path, int lineno,
                    const char *kind_text, const char *frag)
{
    if (a->nviol >= NRC_VMAX)
        return die("z23-lint: too many violations to report\n", "");
    int n = snprintf(a->viol[a->nviol], NRC_VTEXT, "%s:%d — %s: %s", path,
                     lineno, kind_text, frag);
    if (ovf(n, NRC_VTEXT))
        return 2;
    a->nviol++;
    return 0;
}

/* (B): a sleep/usleep/nanosleep/platform_sleep_ms call inside a fixed-
 * iteration for/while poll loop, maintained as a brace-depth loop stack —
 * see the script header for the shape this closes. */
static int nrc_loop_track(struct nrc_acc *a, struct nrc_walk_state *st,
                          const char *path, int lineno, const char *stripped,
                          int marker)
{
    int opens = nrc_count_char(stripped, '{');
    int closes = nrc_count_char(stripped, '}');
    if (regexec(&a->p->loopopen, stripped, 0, NULL, 0) == 0) {
        if (st->loopdepth >= NRC_LOOP_MAX)
            return die("z23-lint: loop-stack overflow\n", "");
        st->loopstack[st->loopdepth++] = st->depth + opens;
    }
    int rc = 0;
    if (regexec(&a->p->sleep, stripped, 0, NULL, 0) == 0 && st->loopdepth > 0
        && !marker)
        rc = nrc_note(a, path, lineno,
                      "sleep toward a fixed-iteration deadline", stripped);
    st->depth += opens - closes;
    while (st->loopdepth > 0 && st->loopstack[st->loopdepth - 1] > st->depth)
        st->loopdepth--;
    return rc;
}

/* (A): each ASSERT/EXPECT/REQUIRE/ *CHECK( occurrence on this (stripped)
 * line, balance-joined to its call text; an ELAPSED measurement (a reader
 * call combined with a `-`) or a difftime() call, unmarked, is a
 * violation. Multiple occurrences per line are scanned left to right,
 * mirroring the awk original's repeated match()/pos advance. */
static int nrc_assert_scan(struct nrc_acc *a, const char *path, int lineno,
                           const char *stripped, int marker)
{
    size_t pos = 0, len = strlen(stripped);
    int rc = 0;
    while (rc == 0 && pos < len) {
        regmatch_t rm;
        if (regexec(&a->p->assertopen, stripped + pos, 1, &rm, 0) != 0)
            break;
        size_t abs_end = pos + (size_t)rm.rm_eo;
        const char *buf = stripped + abs_end - 1; /* points at '(' */
        size_t blen = nrc_balanced_len(buf);
        char joined[NRC_LINE];
        if (blen >= sizeof joined)
            blen = sizeof joined - 1;
        memcpy(joined, buf, blen);
        joined[blen] = '\0';
        if (!marker) {
            if (regexec(&a->p->reader, joined, 0, NULL, 0) == 0
                && strchr(joined, '-') != NULL)
                rc = nrc_note(a, path, lineno,
                              "ASSERT/CHECK reads a real clock", joined);
            if (rc == 0 && strstr(joined, "difftime") != NULL)
                rc = nrc_note(a, path, lineno,
                              "ASSERT/CHECK reads a real clock", joined);
        }
        pos = abs_end;
    }
    return rc;
}

static int nrc_scan_stream(struct nrc_acc *a, const char *path, FILE *f)
{
    struct nrc_walk_state st;
    memset(&st, 0, sizeof st);
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    int lineno = 0, rc = 0;
    while (rc == 0 && (n = getline(&line, &cap, f)) >= 0) {
        lineno++;
        nrc_strip_nl(line);
        size_t rawlen = strlen(line);
        if (rawlen >= NRC_LINE) {
            rc = die("z23-lint: line too long: %s\n", path);
            break;
        }
        char stripped[NRC_LINE];
        if (!cstrip_line(&st.cs, line, rawlen, stripped, sizeof stripped)) {
            rc = die("z23-lint: line too long: %s\n", path);
            break;
        }
        int marker = regexec(&a->p->marker, line, 0, NULL, 0) == 0;
        if (marker)
            a->markers++;
        rc = nrc_loop_track(a, &st, path, lineno, stripped, marker);
        if (rc == 0)
            rc = nrc_assert_scan(a, path, lineno, stripped, marker);
    }
    return fin(f, line, path, rc);
}

static int nrc_scan_open(struct nrc_acc *a, const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f) {
        if (errno == EACCES)
            fprintf(stderr,
                    "check_no_real_clock_test_deadline: UNPROVEN — cannot "
                    "read %s\n", path);
        return die("z23-lint: cannot open %s\n", path);
    }
    a->files++;
    return nrc_scan_stream(a, path, f);
}

/* ── scan set ────────────────────────────────────────────────────────────
 * Production scan: git-tracked files directly under tests/harness/src/ (one
 * path segment past the prefix, matching the script's non-recursive
 * `git ls-files` non-recursive glob over tests/harness/src/). Full/dev
 * scan and the
 * ZCL_REAL_CLOCK_GATE_SCAN_GLOB override: glob(3) the filesystem directly —
 * `ls -1 $GLOB` semantics (GLOB_NOMATCH is zero files, not an error). */

struct nrc_idx_ctx {
    struct nrc_acc *acc;
    int rc;
};

static int nrc_dir_single_level(const char *path, const char *prefix)
{
    size_t pn = strlen(prefix);
    if (strncmp(path, prefix, pn) != 0)
        return 0;
    return strchr(path + pn, '/') == NULL;
}

static int nrc_on_index(const char *path, int stage, void *ctx)
{
    if (stage != 0)
        return 0;
    struct nrc_idx_ctx *c = ctx;
    if (c->rc)
        return 0;
    size_t n = strlen(path);
    if (n < 2 || path[n - 2] != '.' || path[n - 1] != 'c')
        return 0;
    if (!nrc_dir_single_level(path, "tests/harness/src/"))
        return 0;
    c->rc = nrc_scan_open(c->acc, path);
    return c->rc;
}

static int nrc_scan_index(struct nrc_acc *a)
{
    struct nrc_idx_ctx c = { a, 0 };
    char badext[5] = "";
    int rc = lint_git_index_foreach(nrc_on_index, &c, badext);
    if (c.rc)
        return c.rc;
    if (badext[0]) {
        fprintf(stderr,
                "check_no_real_clock_test_deadline: UNPROVEN — the git "
                "index carries a mandatory extension ('%s') this native "
                "reader does not interpret; refusing to grade.\n", badext);
        return 2;
    }
    return rc;
}

static int nrc_scan_glob(struct nrc_acc *a, const char *pattern)
{
    glob_t g;
    memset(&g, 0, sizeof g);
    int gr = glob(pattern, 0, NULL, &g);
    if (gr != 0 && gr != GLOB_NOMATCH) {
        globfree(&g);
        return die("z23-lint: glob failed for pattern\n", pattern);
    }
    int rc = 0;
    for (size_t i = 0; rc == 0 && i < g.gl_pathc; i++)
        rc = nrc_scan_open(a, g.gl_pathv[i]);
    globfree(&g);
    return rc;
}

static const char k_nrc_default_glob[] = "tests/harness/src/*.c";

static int nrc_collect(struct nrc_acc *a)
{
    const char *ov = getenv("ZCL_REAL_CLOCK_GATE_SCAN_GLOB");
    if (ov && ov[0])
        return nrc_scan_glob(a, ov);
    if (lint_prod_scan())
        return nrc_scan_index(a);
    return nrc_scan_glob(a, k_nrc_default_glob);
}

static int nrc_cmp(const void *a, const void *b)
{
    return strcmp((const char *)a, (const char *)b);
}

static int nrc_report(const struct nrc_acc *a, FILE *out, FILE *err,
                      const char *mode)
{
    if (a->nviol == 0) {
        return fprintf(out,
                       "[check_no_real_clock_test_deadline] PASS (%d "
                       "harness source file(s) scanned, %d real-clock "
                       "marker(s) seeded)\n",
                       a->files, a->markers) < 0
                   ? die("z23-lint: write failed\n", "")
                   : 0;
    }
    char rows[NRC_VMAX][NRC_VTEXT];
    memcpy(rows, a->viol, (size_t)a->nviol * NRC_VTEXT);
    qsort(rows, (size_t)a->nviol, NRC_VTEXT, nrc_cmp);
    if (fprintf(err, "\n[check_no_real_clock_test_deadline] %d unmarked "
                "real-clock test deadline(s) in tests/harness/src/*.c:\n",
                a->nviol) < 0)
        return die("z23-lint: write failed\n", "");
    for (int i = 0; i < a->nviol; i++)
        if (fprintf(err, "  %s\n", rows[i]) < 0)
            return die("z23-lint: write failed\n", "");
    if (fputs(
            "\n  A verdict a busy box can flip is measuring the box, not "
            "the code — see\n"
            "  tools/lint/check_no_wallclock_assertion.sh's header for the "
            "full case.\n"
            "  If this really is the one case in this file with no "
            "injected clock (a\n"
            "  real kernel/OS deadline), add a *reviewed* reason on the "
            "SAME line:\n"
            "    /* real-clock: <why this one line genuinely has no "
            "fake-clock seam> */\n"
            "  Otherwise: inject the fake clock this file's other cases "
            "already use, or\n"
            "  assert the OUTCOME and let a progress watchdog catch a "
            "true wedge (see\n"
            "  group_watchdog_expired() in "
            "tests/harness/src/test_parallel.c).\n",
            err) == EOF)
        return die("z23-lint: write failed\n", "");
    return strcmp(mode, "FAIL") == 0 ? 1 : 0;
}

static int nrc_run(FILE *out, FILE *err)
{
    struct nrc_pats p;
    if (nrc_pats_compile(&p))
        return 2;
    struct nrc_acc a;
    memset(&a, 0, sizeof a);
    a.p = &p;
    int rc = nrc_collect(&a);
    if (rc == 0) {
        int floor = -1;
        const char *fenv = getenv("ZCL_REAL_CLOCK_GATE_FILE_FLOOR");
        if (fenv && fenv[0])
            floor = atoi(fenv);
        else
            floor = getenv("ZCL_REAL_CLOCK_GATE_SCAN_GLOB") ? 1 : 500;
        rc = gate_require_scanned(a.files, floor,
                                  "check_no_real_clock_test_deadline",
                                  "Expected the harness's registered-group "
                                  "sources (tests/harness/src/*.c).");
    }
    if (rc == 0)
        rc = nrc_report(&a, out, err, env_or("ZCL_LINT_MODE", "FAIL"));
    nrc_pats_free(&p);
    return rc;
}

int check_no_real_clock_test_deadline_run(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    return nrc_run(stdout, stderr);
}

/* ── shared with the selftest sibling ─────────────────────────────────── */
int nrc_run_for_selftest(FILE *out, FILE *err);
int nrc_run_for_selftest(FILE *out, FILE *err) { return nrc_run(out, err); }
