/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: C23 lint gate (check-no-wallclock-assertion) — refuse NEW test
 * assertions whose PASS/FAIL verdict is decided by a reading of a real clock.
 * Mode: shrink-only ratchet with a closed allowlist (ZCL_LINT_MODE: FAIL
 * default | WARN | UPDATE). Ported from the shell gate of the same name; the
 * detector is gate_no_wallclock_assertion_scan.c, the selftest is
 * gate_no_wallclock_assertion_selftest.c.
 *
 * WHY THIS EXISTS
 * A test graded on wall-clock duration reports on the MACHINE, not on the
 * code. Measured on this tree, same commit and same binary:
 * test_make_lint_gates_heavy_02 FAILED at 48 s inside a 32-worker suite run
 * and PASSED at 64.0 s run standalone immediately afterwards. Load was the
 * only variable, and the failure carried no diagnostic beyond the timeout
 * expression. A sibling, test_binary_ab_fallback, graded three checks on
 * `elapsed < 250 ms`; on a 32-cpu box at loadavg 44 one of those calls was
 * measured at 66.3 ms — a quarter of the bound already, with nothing wrong.
 * The cost is not the red build. It is that everybody learns to read a red
 * result as "probably just the flake", and that is how a real failure gets
 * waved through. It is also the defect this project refuses to commit
 * against PEERS: reachability and speed must never collapse into one
 * pass/fail scalar, because a timeout encodes an economic assumption — an
 * SSD-shaped budget grades an honest slow machine as broken, and that is how
 * a network centralises. This project keeps slow boxes in its fleet ON
 * PURPOSE, because a slow box is the only instrument that shows where the
 * code assumes fast storage. Grading a CONTRIBUTOR's box the way we refuse
 * to grade a peer's is the same mistake pointed inward.
 *
 * WHAT IS COUNTED
 * One rule, chosen because it is precise rather than broad: an assertion
 * whose expression depends on a MEASURED INTERVAL — the difference between
 * two readings of a real clock. Bare timestamps are not intervals. An
 * explicit virtual clock shared by fixture and subject makes offset checks
 * independent of scheduling; a captured real timestamp alone does not (a
 * subject that samples the clock again can cross its expiry boundary while
 * the test waits). The detector conservatively flags clock-derived
 * subtraction; it does not prove which called functions sample a clock.
 * Counting bare timestamps too was tried and measured: 31 files, ~350 sites,
 * almost all of them the good idiom. A gate that noisy gets silenced, which
 * is the same failure as the flake it is trying to stop.
 *
 * A "clock reader" is one of clock_now_monotonic_ns / clock_now_wall_ms /
 * clock_gettime / gettimeofday / platform_time_monotonic_timespec /
 * platform_time_wall_time_t / difftime / time with a NULL argument, plus — computed per
 * file, to a fixpoint — any local helper whose body calls one, and any
 * variable that receives one's value, by assignment (`int64_t t = clock_...`)
 * or by out-parameter (a clock_gettime reader given &t0). Taint
 * propagates through arithmetic, so `elapsed = t1 - t0` is tainted and
 * `ASSERT(elapsed < 2.0)` is a violation.
 *
 * An "assertion" is any macro invocation named ASSERT*, EXPECT*, REQUIRE*,
 * or ending in CHECK. Invocations are joined across lines by counting
 * parentheses, so wrapping or reindenting does not dodge the gate.
 *
 * NOT violations by construction: VIRTUAL TIME (an explicit `now` passed into
 * the subject); CPU TIME (CLOCK_THREAD_CPUTIME_ID does not accrue while a
 * thread is descheduled); REPORTING (`printf("took %.3f ms", elapsed)`);
 * COMMENTS AND STRING LITERALS (stripped before matching).
 *
 * WHAT THIS GATE CANNOT DO
 *  - It does not see SLEEP-AND-CHECK races (`sleep_ms(50); ASSERT(done)`).
 *  - It does not see SHELL, nor a bound handed to an external tool.
 *  - It does not see a duration compared inside a HELPER the assertion calls:
 *    taint is intra-file, not interprocedural.
 *  - IT DOES NOT SEE A FIXED-ITERATION RETRY LOOP: test_onion_bootstrap.c
 *    polled `for (i = 0; i < 90; i++) { if (ready) break; sleep(1); }` and
 *    wrote `failures++` by hand — no assertion macro, no clock arithmetic.
 *    It FAILED inside a full gate run and PASSED standalone in 14.1 s on the
 *    same commit and binary: a 90 s bound on a 14 s operation LOOKS like a
 *    comfortable hang detector and still flipped. Bound >> typical is not
 *    evidence of load-independence. (check-no-real-clock-test-deadline now
 *    covers that shape in the harness's own sources.)
 *  - It does not see a hand-rolled `if (...) { failures++; }` verdict.
 *  - Proven local/formal declarations are scoped to their function and their
 *    visible lines; same-name locals in distinct blocks still share a
 *    summary, and unsupported declarators keep a conservative file-wide
 *    summary. Reading a clock can classify unrelated return values and
 *    output arguments as clock-derived within the calling function. This is
 *    a bounded source heuristic, not a complete data-flow proof.
 *
 * PRODUCTION, AND WHY THE SCAN SET IS A PARAMETER
 * The shape is not test-specific: a systemd watchdog that SIGABRTs a healthy
 * node because concurrent builds saturated the box is the same defect.
 * ZCL_WALLCLOCK_GATE_SCAN_GLOB points this detector at any tree. It is
 * deliberately NOT gating production: there a clock-vs-constant comparison is
 * also how every legitimate protocol timeout is written, so the honest rule
 * is narrower (a duration deciding a HEALTH verdict) and needs a reviewed
 * baseline of its own. Do not wire it up without that narrowing.
 *
 * THE ALLOWLIST IS CLOSED
 * There is NO per-line allow-comment, on purpose: an unbounded, never-reviewed
 * escape hatch would be used for exactly the cases that need a human. The
 * baseline file is the only route, it is shrink-only, and
 * WCA_RATCHET_CEILING caps its total sum so raising the ceiling is a visible
 * source diff rather than a quiet data-file edit.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <ctype.h>
#include <errno.h>
#include <glob.h>
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "gate_no_wallclock_assertion_priv.h"
#include "lintc.h"

/* Total clock-graded assertions tolerated across the whole allowlist. This is
 * the count measured when the gate was introduced; it may only go DOWN. */
enum { WCA_RATCHET_CEILING = 15, WCA_PROD_FLOOR = 800 };

static const char k_wca_default_allowlist[] =
    "tools/lint/wallclock_assertion_allowlist.txt";
static const char k_wca_path_re[] =
    "(^|/)(tests?)/.*\\.(c|h)$|^tests/harness/src/.*\\.(c|h)$";

struct wca_list { char **v; int n, cap; };
struct wca_row { char *path; int found, line; };
struct wca_rows { struct wca_row *v; int n, cap; };
struct wca_allow { char **path; long *val; int n, cap; };

static void *wca_xgrow(void *p, size_t bytes)
{
    return realloc(p, bytes); // raw-alloc-ok:lint-runtime
}

static char *wca_xdup(const char *s)
{
    size_t n = strlen(s) + 1;
    char *q = wca_xgrow(NULL, n);
    if (q)
        memcpy(q, s, n);
    return q;
}

static int wca_list_add(struct wca_list *l, const char *s)
{
    if (l->n == l->cap) {
        int nc = l->cap ? l->cap * 2 : 256;
        char **nv = wca_xgrow(l->v, (size_t)nc * sizeof *nv);
        if (!nv)
            return die("z23-lint: out of memory\n", "");
        l->v = nv;
        l->cap = nc;
    }
    l->v[l->n] = wca_xdup(s);
    if (!l->v[l->n])
        return die("z23-lint: out of memory\n", "");
    l->n++;
    return 0;
}

static void wca_list_free(struct wca_list *l)
{
    for (int i = 0; i < l->n; i++)
        free(l->v[i]);
    free(l->v);
    memset(l, 0, sizeof *l);
}

static int wca_cmp_str(const void *a, const void *b)
{
    return strcmp(*(char *const *)a, *(char *const *)b);
}

/* ── the scan set ─────────────────────────────────────────────────────── */

struct wca_idx { struct wca_list *out; const regex_t *re; };

static int wca_on_index(const char *path, int stage, void *ctx)
{
    struct wca_idx *c = ctx;
    if (stage != 0 || regexec(c->re, path, 0, NULL, 0) != 0)
        return 0;
    return wca_list_add(c->out, path);
}

static int wca_collect_index(struct wca_list *out)
{
    regex_t re;
    if (reg_fail(&re, regcomp(&re, k_wca_path_re, REG_EXTENDED | REG_NOSUB)))
        return 2;
    struct wca_idx c = { out, &re };
    char badext[5] = "";
    int rc = lint_git_index_foreach(wca_on_index, &c, badext);
    regfree(&re);
    if (badext[0]) {
        fprintf(stderr, WCA_GATE ": UNPROVEN — the git index carries a "
                "mandatory extension ('%s') this native reader does not "
                "interpret; refusing to grade.\n", badext);
        return 2;
    }
    return rc;
}

/* `ls -1 $GLOB` semantics: the value is split on whitespace, each word is a
 * pattern, and a pattern that matches nothing contributes nothing. */
static int wca_collect_glob(const char *pattern, struct wca_list *out)
{
    char *copy = wca_xdup(pattern);
    if (!copy)
        return die("z23-lint: out of memory\n", "");
    int rc = 0;
    char *save = NULL;
    for (char *w = strtok_r(copy, " \t\n", &save); w && rc == 0;
         w = strtok_r(NULL, " \t\n", &save)) {
        glob_t gl;
        memset(&gl, 0, sizeof gl);
        int gr = glob(w, 0, NULL, &gl);
        if (gr != 0 && gr != GLOB_NOMATCH)
            rc = die("z23-lint: glob failed for pattern %s\n", w);
        for (size_t i = 0; rc == 0 && gr == 0 && i < gl.gl_pathc; i++)
            rc = wca_list_add(out, gl.gl_pathv[i]);
        globfree(&gl);
    }
    free(copy);
    return rc;
}

static int wca_rows_add(struct wca_rows *r, const char *path,
                        const struct wca_hit *h)
{
    if (r->n == r->cap) {
        int nc = r->cap ? r->cap * 2 : 64;
        struct wca_row *nv = wca_xgrow(r->v, (size_t)nc * sizeof *nv);
        if (!nv)
            return die("z23-lint: out of memory\n", "");
        r->v = nv;
        r->cap = nc;
    }
    r->v[r->n].path = wca_xdup(path);
    if (!r->v[r->n].path)
        return die("z23-lint: out of memory\n", "");
    r->v[r->n].found = h->count;
    r->v[r->n].line = h->first_line;
    r->n++;
    return 0;
}

static void wca_rows_free(struct wca_rows *r)
{
    for (int i = 0; i < r->n; i++)
        free(r->v[i].path);
    free(r->v);
    memset(r, 0, sizeof *r);
}

/* ── the baseline (gate_load_kv_file: "<path> <count>") ──────────────── */

static int wca_allow_put(struct wca_allow *a, const char *key, long val)
{
    for (int i = 0; i < a->n; i++)
        if (strcmp(a->path[i], key) == 0) {
            a->val[i] = val;
            return 0;
        }
    if (a->n == a->cap) {
        int nc = a->cap ? a->cap * 2 : 64;
        char **np = wca_xgrow(a->path, (size_t)nc * sizeof *np);
        if (np)
            a->path = np;
        long *nv = wca_xgrow(a->val, (size_t)nc * sizeof *nv);
        if (nv)
            a->val = nv;
        if (!np || !nv)
            return die("z23-lint: out of memory\n", "");
        a->cap = nc;
    }
    a->path[a->n] = wca_xdup(key);
    if (!a->path[a->n])
        return die("z23-lint: out of memory\n", "");
    a->val[a->n++] = val;
    return 0;
}

static void wca_allow_free(struct wca_allow *a)
{
    for (int i = 0; i < a->n; i++)
        free(a->path[i]);
    free(a->path);
    free(a->val);
    memset(a, 0, sizeof *a);
}

static int wca_allow_line(struct wca_allow *a, char *line, const char *file)
{
    char *hash = strchr(line, '#');
    if (hash)
        *hash = '\0';
    char *b = line;
    while (*b && isspace((unsigned char)*b))
        b++;
    size_t n = strlen(b);
    while (n > 0 && isspace((unsigned char)b[n - 1]))
        b[--n] = '\0';
    if (n == 0)
        return 0;
    char *sp = strchr(b, ' ');
    const char *val = b;
    if (sp) {
        *sp = '\0';
        val = strrchr(sp + 1, ' ');
        val = val ? val + 1 : sp + 1;
    }
    char *end = NULL;
    errno = 0;
    long v = strtol(val, &end, 10);
    if (errno || end == val || *end || v < 0)
        return die("z23-lint: non-numeric allowlist count in %s\n", file);
    return wca_allow_put(a, b, v);
}

static int wca_allow_load(const char *path, struct wca_allow *a)
{
    FILE *f = fopen(path, "r");
    if (!f) {
        if (errno == ENOENT)
            return 0; /* a missing baseline is an empty set */
        return die("z23-lint: cannot open %s\n", path);
    }
    char *line = NULL;
    size_t cap = 0;
    ssize_t r;
    int rc = 0;
    while (rc == 0 && (r = getline(&line, &cap, f)) >= 0)
        rc = wca_allow_line(a, line, path);
    return fin(f, line, path, rc);
}

static long wca_allowed(const struct wca_allow *a, const char *path)
{
    for (int i = 0; i < a->n; i++)
        if (strcmp(a->path[i], path) == 0)
            return a->val[i];
    return 0;
}

/* ── verdict and report ──────────────────────────────────────────────── */

struct wca_verdict {
    struct wca_list viol, stale;
    long total_sites, allow_sum;
    int allow_count;
};

static int wca_judge(const struct wca_rows *rows, const struct wca_allow *al,
                     struct wca_verdict *v)
{
    for (int i = 0; i < rows->n; i++) {
        const struct wca_row *r = &rows->v[i];
        long allowed = wca_allowed(al, r->path);
        int rc = 0;
        v->total_sites += r->found;
        if (r->found > allowed) {
            char tmp[RS_PATH * 4];
            int n = snprintf(tmp, sizeof tmp,
                             "%s:%d — %d clock-graded assertion(s), "
                             "allowlist tolerates %ld", r->path, r->line,
                             r->found, allowed);
            rc = ovf(n, sizeof tmp) ? 2 : wca_list_add(&v->viol, tmp);
        }
        if (rc)
            return rc;
    }
    for (int i = 0; i < al->n; i++) {
        int hit = 0;
        v->allow_sum += al->val[i];
        v->allow_count++;
        for (int k = 0; k < rows->n && !hit; k++)
            hit = strcmp(rows->v[k].path, al->path[i]) == 0;
        if (!hit) {
            char tmp[RS_PATH * 4];
            int n = snprintf(tmp, sizeof tmp,
                             "%s (allowlist says %ld, actual 0)",
                             al->path[i], al->val[i]);
            int rc = ovf(n, sizeof tmp) ? 2 : wca_list_add(&v->stale, tmp);
            if (rc)
                return rc;
        }
    }
    return 0;
}

static int wca_say(FILE *out, const char *s)
{
    return fputs(s, out) == EOF ? die("z23-lint: write failed\n", "") : 0;
}

static int wca_print_sorted(FILE *out, struct wca_list *l)
{
    qsort(l->v, (size_t)l->n, sizeof *l->v, wca_cmp_str);
    for (int i = 0; i < l->n; i++)
        if (fprintf(out, "  %s\n", l->v[i]) < 0)
            return die("z23-lint: write failed\n", "");
    return 0;
}

static const char k_wca_advice[] =
    "\n"
    "  A verdict that a busy box can flip is measuring the box, not the code.\n"
    "  Do not widen the bound: a bigger magic number is the same defect with a\n"
    "  longer fuse, and it makes a genuine hang take longer to surface.\n"
    "  Pick the treatment that matches what the bound is actually for:\n"
    "    * hang detector (the bound is NOT the property) — assert the OUTCOME,\n"
    "      and let a progress watchdog catch a true wedge. See\n"
    "      run_gate_script_watched() in tests/harness/src/lint_gate_helpers.c and\n"
    "      group_watchdog_expired() in tests/harness/src/test_parallel.c: both bound\n"
    "      SILENCE, not runtime, so a slow box keeps passing.\n"
    "    * the speed IS the property — assert a load-independent proxy\n"
    "      (operation counts, bytes written, syscalls, iterations, progress\n"
    "      across N samples) and REPORT the wall-clock figure beside it.\n"
    "    * a sleep-and-check race — fix the race; wait on the EVENT, not the\n"
    "      clock.\n"
    "  Whatever you keep, make the failure message say what was measured, what\n"
    "  the bound was and what the load looked like, so the next reader can tell\n"
    "  a regression from a busy box in one glance.\n";

static int wca_report(const struct wca_cfg *c, struct wca_verdict *v)
{
    int fail = 0;
    FILE *o = c->out;
    if (v->viol.n > 0) {
        if (fprintf(o, "\n[" WCA_GATE "] %d violation(s) — a NEW or GROWN "
                    "test assertion\n        graded on a reading of a real "
                    "clock:\n", v->viol.n) < 0
            || wca_print_sorted(o, &v->viol) || wca_say(o, k_wca_advice)
            || fprintf(o, "  Raising a number in %s is NOT a fix; counts may "
                       "only shrink.\n", c->allowlist) < 0)
            return die("z23-lint: write failed\n", "");
        fail = 1;
    }
    if (v->stale.n > 0) {
        if (fprintf(o, "\n[" WCA_GATE "] %d STALE allowlist row(s) — the file "
                    "no longer carries\n        the shape. Delete them from "
                    "%s:\n", v->stale.n, c->allowlist) < 0
            || wca_print_sorted(o, &v->stale))
            return die("z23-lint: write failed\n", "");
        fail = 1;
    }
    if (v->allow_sum > c->ceiling) {
        if (fprintf(o, "\n[" WCA_GATE "] allowlist sum (%ld) exceeds the "
                    "ratchet ceiling (%ld)\n        in %s — the allowlist was "
                    "edited upward. Lower it back, or\n        lower "
                    "WCA_RATCHET_CEILING in "
                    "tools/lint/lintc/gate_no_wallclock_assertion.c if the "
                    "tolerated\n        set has genuinely shrunk (a change "
                    "that belongs in code review, not a\n        quiet "
                    "data-file edit).\n", v->allow_sum, c->ceiling,
                    c->allowlist) < 0)
            return die("z23-lint: write failed\n", "");
        fail = 1;
    }
    return fail;
}

static int wca_update(const struct wca_cfg *c, const struct wca_rows *rows)
{
    struct wca_list lines = { 0 };
    int rc = 0;
    for (int i = 0; rc == 0 && i < rows->n; i++) {
        char tmp[RS_PATH * 2];
        int n = snprintf(tmp, sizeof tmp, "%s %d", rows->v[i].path,
                         rows->v[i].found);
        rc = ovf(n, sizeof tmp) ? 2 : wca_list_add(&lines, tmp);
    }
    if (rc == 0) {
        qsort(lines.v, (size_t)lines.n, sizeof *lines.v, wca_cmp_str);
        FILE *f = fopen(c->allowlist, "w");
        if (!f)
            return die("z23-lint: cannot write %s\n", c->allowlist);
        fputs("# " WCA_GATE " allowlist — the reviewed set of test "
              "assertions still\n# graded on a reading of a real clock. "
              "Format: <path> <count>.\n# COUNTS MAY ONLY SHRINK. Adding a "
              "row for a NEW file is not a fix:\n# a file with no row may "
              "carry ZERO.\n#\n# Regenerate: ZCL_LINT_MODE=UPDATE "
              "./build/bin/z23-lint check-no-wallclock-assertion\n", f);
        for (int i = 0; i < lines.n; i++)
            fprintf(f, "%s\n", lines.v[i]);
        if (ferror(f) | (fclose(f) != 0))
            rc = die("z23-lint: write failed: %s\n", c->allowlist);
        else if (fprintf(c->out, "[" WCA_GATE "] allowlist UPDATED: %s\n",
                         c->allowlist) < 0)
            rc = die("z23-lint: write failed\n", "");
    }
    wca_list_free(&lines);
    return rc;
}

/* ── orchestration ───────────────────────────────────────────────────── */

static int wca_scan_all(const struct wca_list *files, struct wca_rows *rows)
{
    for (int i = 0; i < files->n; i++) {
        struct wca_hit h;
        if (wca_scan_file(files->v[i], &h)) {
            fputs(WCA_GATE ": FATAL — the detector failed. Refusing to "
                  "report\n  'clean' off a scan that did not run.\n", stderr);
            return 2;
        }
        if (h.count > 0 && wca_rows_add(rows, files->v[i], &h))
            return 2;
    }
    return 0;
}

static int wca_finish(const struct wca_cfg *c, const struct wca_list *files,
                      const struct wca_rows *rows, const struct wca_allow *al)
{
    struct wca_verdict v;
    memset(&v, 0, sizeof v);
    int rc = wca_judge(rows, al, &v);
    if (rc == 0 && strcmp(c->mode, "UPDATE") == 0) {
        wca_list_free(&v.viol);
        wca_list_free(&v.stale);
        return wca_update(c, rows);
    }
    int fail = rc == 0 ? wca_report(c, &v) : 0;
    if (rc != 0)
        fail = 0;
    else if (fail >= 2)
        rc = fail;
    else if (fail == 1 && strcmp(c->mode, "FAIL") == 0)
        rc = 1;
    else if (fprintf(c->out, "[" WCA_GATE "] PASS (%d test source file(s) "
                     "scanned, %d carrying a clock-graded assertion, %ld "
                     "total site(s), %d allowlisted file(s) summing to "
                     "%ld/%ld, no allow-comment mechanism exists)\n",
                     files->n, rows->n, v.total_sites, v.allow_count,
                     v.allow_sum, c->ceiling) < 0)
        rc = die("z23-lint: write failed\n", "");
    wca_list_free(&v.viol);
    wca_list_free(&v.stale);
    return rc;
}

int wca_run_cfg(const struct wca_cfg *c)
{
    struct wca_list files = { 0 };
    struct wca_rows rows = { 0 };
    struct wca_allow al = { 0 };
    int rc = wca_scan_init();
    if (rc)
        return rc;
    rc = c->glob ? wca_collect_glob(c->glob, &files)
                 : wca_collect_index(&files);
    if (rc == 0)
        rc = gate_require_scanned(files.n, c->floor, WCA_GATE,
                                  "Expected the tracked C test sources "
                                  "(tests/harness/src/**, **/tests/**).");
    if (rc == 0)
        rc = wca_scan_all(&files, &rows);
    if (rc == 0)
        rc = wca_allow_load(c->allowlist, &al);
    if (rc == 0)
        rc = wca_finish(c, &files, &rows, &al);
    wca_allow_free(&al);
    wca_rows_free(&rows);
    wca_list_free(&files);
    wca_scan_fini();
    return rc;
}

static int wca_env_long(const char *name, const char *e, long fallback,
                        long *out)
{
    if (!e || !e[0]) {
        *out = fallback;
        return 0;
    }
    char *end = NULL;
    errno = 0;
    long v = strtol(e, &end, 10);
    if (errno || end == e || *end)
        return die("z23-lint: non-numeric %s\n", name);
    *out = v;
    return 0;
}

int check_no_wallclock_assertion_run(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    struct wca_cfg c;
    long ceiling = 0, floor = 0;
    c.glob = env_or("ZCL_WALLCLOCK_GATE_SCAN_GLOB", NULL);
    c.allowlist = env_or("ZCL_WALLCLOCK_GATE_ALLOWLIST",
                         k_wca_default_allowlist);
    c.mode = env_or("ZCL_LINT_MODE", "FAIL");
    c.out = stdout;
    c.err = stderr;
    if (wca_env_long("ZCL_WALLCLOCK_GATE_CEILING",
                     getenv("ZCL_WALLCLOCK_GATE_CEILING"),
                     WCA_RATCHET_CEILING, &ceiling)
        || wca_env_long("ZCL_WALLCLOCK_GATE_FILE_FLOOR",
                        getenv("ZCL_WALLCLOCK_GATE_FILE_FLOOR"),
                        c.glob ? 1 : WCA_PROD_FLOOR, &floor))
        return 2;
    c.ceiling = ceiling;
    c.floor = (int)floor;
    return wca_run_cfg(&c);
}
