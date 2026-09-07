/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Gates: check-model-column-drift
 * Second file of the check-model-column-drift family (the 700-line family
 * ceiling split): the gate's --selftest probes. The gate body — the
 * scan-root derivation, the native distinct-literal-column-index scan, the
 * baseline loader, the shrink-only stale check, the verdict — and the
 * family's parity notes live in gate_model_column_drift.c.
 */

/* ── --selftest ────────────────────────────────────────────────────────────
 * Byte-parity port of the original script's --selftest block: a mktemp
 * fixture tree with 25 inert sources (so the anti-hollow floor of 20 is met
 * in every case) proves the drift shape is caught, that a single-column
 * scalar read, derived index NAMES, and the documented per-line
 * `// model-columns-ok:` exception pass, that a baselined violator is
 * tolerated and then fails as STALE once it stops violating, and that an
 * empty scan set fails closed — including the cases that must PASS, so an
 * unconditionally-failing gate cannot pose as a rail.
 *
 * Semantic mapping:
 * - mktemp -d "${TMPDIR:-/tmp}/model-column-drift-selftest.XXXXXX" is
 *   mcdw_setup's mkdtemp (env_or's unset-or-empty fallback matches
 *   ${TMPDIR:-/tmp}); the trailing rm -rf is rap_rm_rf on every path.
 * - Fixture directories are csr_mkdirs, files csr_write (both checked and
 *   parent-creating); the `rm -f` removals are mcdw_rm (unlink, ENOENT
 *   ignored).
 * - st_expect is mcdw_expect: all three ZCL_ assignments on every inner run
 *   via setenv (ZCL_LINT_MODE=RATCHET, the scan root, the baseline), then
 *   the gate FOR REAL through the runtime's self-exec helper with the
 *   streams merged (cic_invoke merge=1 is the call site's `2>&1`
 *   capture); the verdict checks are the shell's rc grading plus the
 *   fixed-string needle search, and the SELFTEST FAIL texts with the
 *   four-space-indented captured output are the shell's byte-for-byte
 *   (an empty capture still prints its one bare indented line, as
 *   `printf '%s\n' ""` does).
 * - A st_expect failure returns 1 and the shell CONTINUES through the
 *   remaining cases (`|| rc=1`); mcdw_run_case accumulates the same way.
 *   The final lines are "══ selftest: PASS (7/7) ══" or
 *   "══ selftest: FAIL ══", and the exit code is 0 or 1.
 *
 * Parity notes:
 * - mktemp failure: the shell exits 1 with mktemp's own message; the port
 *   die()s exit 2 (environment failure, not a gate verdict — the
 *   describe-budget precedent).
 * - The merged-output sink is bounded (64 KiB); the shell captured
 *   unboundedly. Overflow die()s, fail-closed.
 * - The port's setenv mutations persist in-process where the shell's `env`
 *   assignments were per-subprocess; every inner run sets all three
 *   variables and the process exits when the selftest ends, so no
 *   snapshot/restore is needed (the controller-private-headers precedent).
 */

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "lintc.h"

static const char k_mcdw_gate[] = "check-model-column-drift";
static char g_mcdw_tmp[4096];
enum { MCDW_SINK = 65536 };
static char g_mcdw_sink[MCDW_SINK];

static const char k_mcdw_drift[] =
    "AR_READ_BLOB(s, 0, out->a, 32);\nout->b = AR_COL_INT(s, 1);\n";

static int mcdw_path(char *buf, size_t cap, const char *rel)
{
    return ovf(snprintf(buf, cap, "%s/%s", g_mcdw_tmp, rel), cap);
}

static int mcdw_write(const char *rel, const char *text)
{
    char p[4096];
    int rc = mcdw_path(p, sizeof p, rel);
    if (rc == 0)
        rc = csr_write(p, text);
    return rc;
}

/* rm -f: a missing entry is not an error. */
static void mcdw_rm(const char *rel)
{
    char p[4096];
    if (mcdw_path(p, sizeof p, rel) == 0)
        (void)unlink(p);
}

/* printf '%s\n' "$out" | sed 's/^/    /': the capture (trailing newlines
 * already stripped by the self-exec helper), one four-space-indented line
 * per line — a bare indented line when the capture is empty. */
static void mcdw_dump(void)
{
    if (!g_mcdw_sink[0]) {
        puts("    ");
        return;
    }
    for (const char *p = g_mcdw_sink; *p; ) {
        const char *nl = strchr(p, '\n');
        if (!nl) {
            printf("    %s\n", p);
            break;
        }
        printf("    %.*s\n", (int)(nl - p), p);
        p = nl + 1;
    }
}

/* st_expect: the three ZCL_ assignments on every inner run, then the gate
 * for real; want_fail is the shell's pass|fail verdict, needle the
 * fixed-string grep -qF over the merged capture. */
static int mcdw_expect(const char *label, int want_fail, const char *needle,
                       const char *root, const char *baseline)
{
    if (setenv("ZCL_LINT_MODE", "RATCHET", 1) != 0
        || setenv("ZCL_MODEL_DRIFT_ROOT", root, 1) != 0
        || setenv("ZCL_MODEL_DRIFT_BASELINE", baseline, 1) != 0)
        return die("z23-lint: setenv failed\n", "");
    int code = 0;
    g_mcdw_sink[0] = '\0';
    int rc = cic_invoke(k_mcdw_gate, 1, g_mcdw_sink, sizeof g_mcdw_sink,
                        &code);
    if (rc)
        return rc;
    if (!want_fail && code != 0) {
        printf("SELFTEST FAIL: %s — expected a PASS, got exit %d\n", label,
               code);
        mcdw_dump();
        return 1;
    }
    if (want_fail && code == 0) {
        printf("SELFTEST FAIL: %s — expected a rejection, got a PASS\n",
               label);
        mcdw_dump();
        return 1;
    }
    if (needle && !strstr(g_mcdw_sink, needle)) {
        printf("SELFTEST FAIL: %s — verdict never named '%s'\n", label,
               needle);
        mcdw_dump();
        return 1;
    }
    printf("  selftest ok: %s\n", label);
    return 0;
}

/* `st_expect ... || rc=1`: a verdict mismatch accumulates and the remaining
 * cases still run; an environment failure (2) aborts. */
static int mcdw_run_case(const char *label, int want_fail,
                         const char *needle, const char *root,
                         const char *baseline, int *bad)
{
    int r = mcdw_expect(label, want_fail, needle, root, baseline);
    if (r == 2)
        return 2;
    if (r)
        *bad = 1;
    return 0;
}

static int mcdw_setup(void)
{
    const char *td = env_or("TMPDIR", "/tmp");
    if (ovf(snprintf(g_mcdw_tmp, sizeof g_mcdw_tmp,
                     "%s/model-column-drift-selftest.XXXXXX", td),
            sizeof g_mcdw_tmp))
        return 2;
    if (!mkdtemp(g_mcdw_tmp))
        return die("z23-lint: mktemp failed: %s\n", g_mcdw_tmp);
    char p[4096];
    int rc = mcdw_path(p, sizeof p, "src");
    if (rc == 0)
        rc = csr_mkdirs(p);
    if (rc == 0)
        rc = mcdw_path(p, sizeof p, "none");
    if (rc == 0)
        rc = csr_mkdirs(p);
    for (int i = 1; rc == 0 && i <= 25; i++) {
        char rel[64];
        snprintf(rel, sizeof rel, "src/inert_%d.c", i);
        rc = mcdw_write(rel, "/* inert */\n");
    }
    if (rc == 0)
        rc = mcdw_write("empty.txt", "");
    return rc;
}

/* A: two distinct literal indices IS the drift shape.
 * B: a single-column scalar read cannot drift and must NOT be flagged. */
static int mcdw_ab(const char *src, const char *empty, int *bad)
{
    int rc = mcdw_write("src/drifty.c", k_mcdw_drift);
    if (rc == 0)
        rc = mcdw_run_case("A: two hand-written column indices are caught",
                           1, "drifty.c", src, empty, bad);
    mcdw_rm("src/drifty.c");
    if (rc == 0)
        rc = mcdw_write("src/scalar.c", "int64_t total = AR_COL_INT(s, 0);\n");
    if (rc == 0)
        rc = mcdw_run_case("B: a single-column scalar read is not flagged",
                           0, NULL, src, empty, bad);
    return rc;
}

/* C: derived index NAMES are not literals and must pass — otherwise the
 *    gate would punish the very fix it asks for.
 * D: the documented per-line exception silences one read. */
static int mcdw_cd(const char *src, const char *empty, int *bad)
{
    int rc = mcdw_write("src/derived.c",
                        "AR_READ_BLOB(s, IX_a, out->a, 32);\n"
                        "out->b = AR_COL_INT(s, IX_b);\n");
    if (rc == 0)
        rc = mcdw_run_case("C: derived index names pass", 0, NULL, src,
                           empty, bad);
    if (rc == 0)
        rc = mcdw_write("src/excepted.c",
                        "AR_READ_BLOB(s, 0, out->a, 32); "
                        "// model-columns-ok: owning heap blob\n"
                        "out->b = AR_COL_INT(s, 1); "
                        "// model-columns-ok: computed\n");
    if (rc == 0)
        rc = mcdw_run_case("D: the // model-columns-ok: exception is "
                           "honoured", 0, NULL, src, empty, bad);
    mcdw_rm("src/excepted.c");
    return rc;
}

/* E: a baselined violator is tolerated; F: a baseline line whose file
 *    stopped violating is a failure, which is what makes the baseline
 *    shrink-only rather than a place to hide; G: an emptied scan set must
 *    fail LOUD, never report clean. */
static int mcdw_efg(const char *src, const char *none, const char *empty,
                    const char *base, int *bad)
{
    char bline[4352];
    int rc = ovf(snprintf(bline, sizeof bline, "%s/drifty.c\n", src),
                 sizeof bline);
    if (rc == 0)
        rc = mcdw_write("src/drifty.c", k_mcdw_drift);
    if (rc == 0)
        rc = mcdw_write("baseline.txt", bline);
    if (rc == 0)
        rc = mcdw_run_case("E: a baselined violator is tolerated", 0, NULL,
                           src, base, bad);
    mcdw_rm("src/drifty.c");
    if (rc == 0)
        rc = mcdw_run_case("F: a stale baseline entry is caught "
                           "(shrink-only)", 1, "NO LONGER violates", src,
                           base, bad);
    if (rc == 0)
        rc = mcdw_run_case("G: an empty scan set fails closed", 1, "FATAL",
                           none, empty, bad);
    return rc;
}

static int mcdw_cases(void)
{
    char src[4096], none[4096], empty[4096], base[4096];
    int rc = mcdw_path(src, sizeof src, "src");
    if (rc == 0)
        rc = mcdw_path(none, sizeof none, "none");
    if (rc == 0)
        rc = mcdw_path(empty, sizeof empty, "empty.txt");
    if (rc == 0)
        rc = mcdw_path(base, sizeof base, "baseline.txt");
    int bad = 0;
    if (rc == 0)
        rc = mcdw_ab(src, empty, &bad);
    if (rc == 0)
        rc = mcdw_cd(src, empty, &bad);
    if (rc == 0)
        rc = mcdw_efg(src, none, empty, base, &bad);
    if (rc)
        return rc;
    return bad;
}

int check_model_column_drift_selftest(void)
{
    char root[4096];
    int rc = cic_repo_root(root, sizeof root);
    if (rc == 0 && chdir(root) != 0)
        rc = 2;
    if (rc == 0)
        rc = mcdw_setup();
    if (rc == 0) {
        fputs("══ check-model-column-drift selftest ══\n", stdout);
        rc = mcdw_cases();
    }
    if (g_mcdw_tmp[0])
        (void)rap_rm_rf(g_mcdw_tmp);
    if (rc == 0)
        fputs("══ selftest: PASS (7/7) ══\n", stdout);
    else if (rc == 1)
        fputs("══ selftest: FAIL ══\n", stdout);
    return rc;
}
