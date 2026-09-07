/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Gates: check-arm-symbol-single
 * Third file of the check-arm-symbol-single family (the 700-line family
 * ceiling split): the coverage oracle — capture_cmd, git ls-files,
 * byte-for-byte the shell's gate_require_git_coverage / gate_git_oracle /
 * gate_require_coverage chain (a producer the shell original also
 * spawned via gate_lib.sh). gate_arm_symbol_single.c holds the root list,
 * file collection, baseline ratchet, and the verdict;
 * gate_arm_symbol_single_analyzer.c holds the line-oriented function-
 * definition analyzer; gate_arm_symbol_single_selftest.c holds
 * --selftest.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "lintc.h"
#include "gate_arm_symbol_single_priv.h"

/* ── the coverage oracle: capture_cmd, git ls-files, byte-for-byte the
 * shell's gate_require_git_coverage / gate_git_oracle / gate_require_coverage
 * chain (a producer the shell original also spawned via gate_lib.sh) —
 * split into small single-purpose helpers to stay under the complexity
 * cap. ──────────────────────────────────────────────────────────────── */

enum { ASY_COVBUF = 1 << 20 };

/* Builds both the shell command (each pathspec single-quoted so the shell
 * running under popen() never glob-expands the literal "*") and the raw,
 * unquoted pathspec text used in diagnostics (bash's unquoted "$*"). */
static int asy_cov_build_cmd(char *cmd, size_t cmdcap, char *rawspec,
                             size_t rawcap)
{
    snprintf(cmd, cmdcap, "git ls-files --cached -- ");
    size_t cn = strlen(cmd), rn = 0;
    rawspec[0] = '\0';
    for (int i = 0; i < ASY_NROOTS_DEFAULT; i++) {
        char spec[ASY_ROOT + 8], q[ASY_ROOT + 16];
        snprintf(spec, sizeof spec, "%s/*.c", k_asy_roots_default[i]);
        if (sh_single_quote(spec, q, sizeof q))
            return 2;
        int k = snprintf(cmd + cn, cmdcap - cn, "%s%s", i ? " " : "", q);
        if (k < 0 || (size_t)k >= cmdcap - cn)
            return die("z23-lint: derived buffer overflow\n", "");
        cn += (size_t)k;
        int k2 = snprintf(rawspec + rn, rawcap - rn, "%s%s", i ? " " : "",
                          spec);
        if (k2 < 0 || (size_t)k2 >= rawcap - rn)
            return die("z23-lint: derived buffer overflow\n", "");
        rn += (size_t)k2;
    }
    snprintf(cmd + cn, cmdcap - cn, " 2>/dev/null");
    return 0;
}

static void asy_cov_report_oracle_failed(const char *rawspec, int code)
{
    fprintf(stderr, "%s: UNPROVEN — the coverage oracle could not run:\n",
            k_asy_gate);
    fprintf(stderr, "  'git ls-files -- %s' exited %d.\n", rawspec, code);
    fputs("  Without an independent expectation this gate cannot tell a\n"
          "  complete scan from a partial one, so it refuses to grade\n"
          "  either way. Run it from inside the checkout.\n", stderr);
}

static void asy_cov_report_oracle_empty(const char *rawspec)
{
    fprintf(stderr,
            "%s: UNPROVEN — the coverage oracle is empty: git tracks no\n",
            k_asy_gate);
    fprintf(stderr, "  file matching: %s\n", rawspec);
    fputs("  An empty expectation would pass every scan, including a scan\n"
          "  of nothing. Refusing to vouch for coverage off a hollow\n"
          "  oracle. Fix the pathspec, or drop the coverage check if the\n"
          "  set is genuinely gone.\n", stderr);
}

static int asy_files_add_dedup(struct asy_files *out, const char *item)
{
    for (int i = 0; i < out->n; i++)
        if (strcmp(out->p[i], item) == 0)
            return 0;
    return asy_files_add(out, item);
}

/* Parses capture_cmd's captured `git ls-files` output (one path per line)
 * into a deduped, sorted set. */
static int asy_cov_parse_expected(char *raw, struct asy_files *expected)
{
    expected->n = 0;
    char *save = NULL;
    for (char *ln = strtok_r(raw, "\n", &save); ln;
         ln = strtok_r(NULL, "\n", &save)) {
        if (!*ln)
            continue;
        if (asy_files_add_dedup(expected, ln))
            return 2;
    }
    asy_sort_files(expected);
    return 0;
}

static int asy_cov_build_actual(const struct asy_files *scanned,
                                struct asy_files *actual)
{
    actual->n = 0;
    for (int i = 0; i < scanned->n; i++)
        if (asy_files_add_dedup(actual, scanned->p[i]))
            return 2;
    asy_sort_files(actual);
    return 0;
}

static int asy_cov_compute_missing(const struct asy_files *expected,
                                   const struct asy_files *actual,
                                   char missing[][ASY_PATH])
{
    int nmiss = 0;
    for (int i = 0; i < expected->n; i++) {
        int found = 0;
        for (int j = 0; j < actual->n; j++)
            if (strcmp(actual->p[j], expected->p[i]) == 0) { found = 1; break; }
        if (!found && nmiss < ASY_MAXFILES)
            snprintf(missing[nmiss++], ASY_PATH, "%s", expected->p[i]);
    }
    return nmiss;
}

static void asy_cov_report_shortfall(int actual_n, int expected_n, int nmiss,
                                     int allowance,
                                     char missing[][ASY_PATH])
{
    fprintf(stderr, "%s: UNPROVEN — the scan reached %d of the %d\n",
           k_asy_gate, actual_n, expected_n);
    fprintf(stderr,
            "  entries an independent oracle says it should have reached;\n"
            "  %d missing, above the shrink-only allowance of\n"
            "  %d recorded in ZCL_ARM_SYMBOL_COVERAGE_ALLOWANCE.\n",
            nmiss, allowance);
    fputs("  This is a PARTIAL scan: not a clean one, and not a violating\n"
          "  one. 'I scanned less than my subject' is a third answer — the\n"
          "  gate never ran over the code it claims to cover, so it cannot\n"
          "  report either verdict. A file-count floor cannot see this;\n"
          "  the count stayed large.\n", stderr);
    fprintf(stderr, "  Not reached (first 20 of %d):\n", nmiss);
    int show = nmiss < 20 ? nmiss : 20;
    for (int i = 0; i < show; i++)
        fprintf(stderr, "    %s\n", missing[i]);
    if (nmiss > 20)
        fprintf(stderr, "    ... and %d more\n", nmiss - 20);
    fputs("  Re-run from a clean checkout. If a listed file genuinely left"
          " this gate's scope, move it out of core engine contexts"
          " cognition platform tools or record the exemption by lowering"
          " nothing and raising ZCL_ARM_SYMBOL_COVERAGE_ALLOWANCE only"
          " with the reason written down.\n", stderr);
}

static void asy_cov_report_stale(int nmiss, int expected_n, int allowance)
{
    fprintf(stderr,
            "%s: VIOLATION — the coverage allowance is stale: the scan now\n",
            k_asy_gate);
    fprintf(stderr,
            "  misses only %d of %d expected entries, below\n"
            "  ZCL_ARM_SYMBOL_COVERAGE_ALLOWANCE=%d.\n", nmiss, expected_n,
            allowance);
    fputs("  Coverage improved without lowering the allowance. An allowance\n"
          "  that may only ever rise stops meaning 'what we measured' and\n"
          "  starts meaning 'whatever nobody lowered' — a ratchet that\n"
          "  rusts shut. Lower ZCL_ARM_SYMBOL_COVERAGE_ALLOWANCE to that"
          " number, with the reason, in the same commit.\n", stderr);
}

int asy_coverage(const struct asy_files *scanned, int allowance)
{
    static char cmd[4096];
    static char rawspec[1024];
    if (asy_cov_build_cmd(cmd, sizeof cmd, rawspec, sizeof rawspec))
        return 2;

    static char raw[ASY_COVBUF];
    int code = 0;
    if (capture_cmd(cmd, raw, sizeof raw, &code))
        return 2;
    if (code != 0) {
        asy_cov_report_oracle_failed(rawspec, code);
        return 2;
    }

    static struct asy_files expected;
    if (asy_cov_parse_expected(raw, &expected))
        return 2;
    if (expected.n == 0) {
        asy_cov_report_oracle_empty(rawspec);
        return 2;
    }

    static struct asy_files actual;
    if (asy_cov_build_actual(scanned, &actual))
        return 2;

    static char missing[ASY_MAXFILES][ASY_PATH];
    int nmiss = asy_cov_compute_missing(&expected, &actual, missing);

    if (nmiss > allowance) {
        asy_cov_report_shortfall(actual.n, expected.n, nmiss, allowance,
                                 missing);
        return 2;
    }
    if (nmiss < allowance) {
        asy_cov_report_stale(nmiss, expected.n, allowance);
        return 1;
    }
    return 0;
}
