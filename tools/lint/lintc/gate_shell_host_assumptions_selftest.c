/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: selftest for the check-shell-host-assumptions lint gate
 * (gate_shell_host_assumptions.c) — split into its own file so the gate
 * body stays under the family file's line ceiling.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "lintc.h"
#include "gate_shell_host_assumptions_priv.h"

/* ── selftest ─────────────────────────────────────────────────────────── */

static const char k_fixture[] =
    "#!/usr/bin/env bash\n"
    "# ss nproc stat -c sed -i are prose here.\n"
    "single='ss nproc stat -c sed -i'\n"
    "double=\"ss nproc stat -c sed -i\"\n"
    "true;# ss nproc stat -c sed -i are comments here too.\n"
    "command -v ss >/dev/null\n"
    "type -P nproc >/dev/null\n"
    "cat <<'IGNORED'\n"
    "ss -ltn\n"
    "nproc\n"
    "stat -c%s x\n"
    "sed -i x\n"
    "IGNORED\n"
    "ss -ltn\n"
    "jobs=\"$(nproc)\"\n"
    "stat -Lc%s artifact\n"
    "sed -Ei.bak 's/a/b/' file\n";

static int shl_hush_run(void)
{
    fflush(stdout);
    fflush(stderr);
    int n = open("/dev/null", O_WRONLY), o = dup(1), e = dup(2);
    if (n < 0 || o < 0 || e < 0) return die("z23-lint: tmpfile failed\n", "");
    int rc = 2;
    if (dup2(n, 1) >= 0 && dup2(n, 2) >= 0) rc = check_shell_host_assumptions_run(0, NULL);
    fflush(stdout);
    fflush(stderr);
    (void)dup2(o, 1); (void)dup2(e, 2);
    close(n); close(o); close(e);
    return rc;
}

struct shl_selftest_env {
    const char *work, *fixture, *baseline;
};

static int shl_setenv_common(const struct shl_selftest_env *e)
{
    return setenv("ZCL_SHELL_HOST_SCAN_DIR", e->work, 1) != 0
        || setenv("ZCL_SHELL_HOST_FILE_FLOOR", "1", 1) != 0
        || setenv("ZCL_SHELL_HOST_BASELINE", e->baseline, 1) != 0
        || setenv("ZCL_SHELL_HOST_SS_CEILING", "8", 1) != 0
        || setenv("ZCL_SHELL_HOST_NPROC_CEILING", "8", 1) != 0
        || setenv("ZCL_SHELL_HOST_STAT_CEILING", "8", 1) != 0
        || setenv("ZCL_SHELL_HOST_SED_CEILING", "8", 1) != 0;
}

static void shl_unsetenv_all(void)
{
    unsetenv("ZCL_SHELL_HOST_SCAN_DIR"); unsetenv("ZCL_SHELL_HOST_FILE_FLOOR");
    unsetenv("ZCL_SHELL_HOST_BASELINE"); unsetenv("ZCL_SHELL_HOST_SS_CEILING");
    unsetenv("ZCL_SHELL_HOST_NPROC_CEILING"); unsetenv("ZCL_SHELL_HOST_STAT_CEILING");
    unsetenv("ZCL_SHELL_HOST_SED_CEILING"); unsetenv("ZCL_LINT_MODE");
    unsetenv("ZCL_SHELL_HOST_BOOTSTRAP"); unsetenv("ZCL_SHELL_HOST_INJECT_SCAN_FAILURE");
    unsetenv("ZCL_SHELL_HOST_INJECT_SCAN_PATH"); unsetenv("ZCL_SHELL_HOST_INJECT_TRACKED_BASELINE");
}

static int shl_bootstrap_baseline(const struct shl_selftest_env *e)
{
    if (shl_setenv_common(e) || setenv("ZCL_LINT_MODE", "UPDATE", 1) != 0
        || setenv("ZCL_SHELL_HOST_BOOTSTRAP", "1", 1) != 0)
        return die("z23-lint: setenv failed\n", "");
    int rc = shl_hush_run();
    shl_unsetenv_all();
    return rc == 0 ? 0 : 1;
}

static int shl_baseline_has(const char *baseline, const char *kind, const char *path, int count)
{
    static struct shl_table t;
    int present = 0;
    if (shl_load_baseline(baseline, &t, &present) || !present) return 0;
    int idx = shl_table_find(&t, kind, path);
    return idx >= 0 && t.r[idx].count == count;
}

static int shl_check_bootstrap_counts(const struct shl_selftest_env *e, int *fails)
{
    int ok = shl_baseline_has(e->baseline, "ss", e->fixture, 7)
        && shl_baseline_has(e->baseline, "nproc", e->fixture, 7)
        && shl_baseline_has(e->baseline, "stat", e->fixture, 6)
        && shl_baseline_has(e->baseline, "sed", e->fixture, 6);
    if (!ok) {
        fprintf(stderr, "check_shell_host_assumptions: SELFTEST FAILED — "
                        "the scanner did not conservatively count fixture hits\n");
        (*fails)++;
        return 0;
    }
    return printf("  selftest ok: fixture hits counted conservatively\n") < 0
        ? die("z23-lint: write failed\n", "") : 0;
}

static int shl_positive_control(const struct shl_selftest_env *e, int *fails)
{
    if (shl_setenv_common(e)) return die("z23-lint: setenv failed\n", "");
    int rc = shl_hush_run();
    shl_unsetenv_all();
    if (rc != 0) {
        fprintf(stderr, "check_shell_host_assumptions: SELFTEST FAILED — "
                        "positive control did not pass\n");
        (*fails)++;
    } else if (printf("  selftest ok: positive control passes\n") < 0)
        return die("z23-lint: write failed\n", "");
    return 0;
}

static int shl_expect_rc(const struct shl_selftest_env *e, const char *extra_name,
                         const char *extra_val, int want_nonzero, const char *label,
                         int *fails)
{
    if (shl_setenv_common(e)) return die("z23-lint: setenv failed\n", "");
    if (extra_name && setenv(extra_name, extra_val, 1) != 0)
        return die("z23-lint: setenv failed\n", "");
    int rc = shl_hush_run();
    shl_unsetenv_all();
    int bad = want_nonzero ? (rc == 0) : (rc != 0);
    if (bad) {
        fprintf(stderr, "check_shell_host_assumptions: SELFTEST FAILED — %s\n", label);
        (*fails)++;
    } else if (printf("  selftest ok: %s\n", label) < 0)
        return die("z23-lint: write failed\n", "");
    return 0;
}

static int shl_selftest_paths(const char *tmp, char *fixture, char *baseline, char *saved,
                              char *fixture_saved)
{
    if (ovf(snprintf(fixture, 4096, "%s/fixture.sh", tmp), 4096)
        || ovf(snprintf(baseline, 4096, "%s/baseline.txt", tmp), 4096)
        || ovf(snprintf(saved, 4096, "%s/baseline.saved", tmp), 4096)
        || ovf(snprintf(fixture_saved, 4096, "%s/fixture.saved", tmp), 4096)
        || csr_write(fixture, k_fixture))
        return 1;
    return 0;
}

static int shl_copy_file(const char *from, const char *to)
{
    FILE *in = fopen(from, "r");
    if (!in) return 1;
    FILE *out = fopen(to, "w");
    if (!out) { fclose(in); return 1; }
    char buf[4096];
    size_t n;
    while ((n = fread(buf, 1, sizeof buf, in)) > 0) fwrite(buf, 1, n, out);
    fclose(in);
    fclose(out);
    return 0;
}

/* growth: append a stray nproc line, confirm it fails and UPDATE refuses
 * to authorize the growth (baseline unchanged). */
static int shl_selftest_growth_phase(const struct shl_selftest_env *e, const char *saved,
                                     const char *fixture_saved, int *fails)
{
    if (shl_copy_file(e->baseline, saved)) return 1;
    if (csr_write(fixture_saved, k_fixture)) return 1;
    FILE *f = fopen(e->fixture, "a");
    if (!f || fprintf(f, "\nnproc\n") < 0 || fclose(f) != 0) return 1;
    if (shl_expect_rc(e, NULL, NULL, 1, "a growth mutation fails", fails)) return 1;
    if (shl_expect_rc(e, "ZCL_LINT_MODE", "UPDATE", 1,
                      "UPDATE does not authorize growth", fails))
        return 1;

    static struct shl_table t1, t2;
    int p1 = 0, p2 = 0;
    if (shl_load_baseline(e->baseline, &t1, &p1) || shl_load_baseline(saved, &t2, &p2))
        return 1;
    if (t1.n != t2.n) {
        fprintf(stderr, "check_shell_host_assumptions: SELFTEST FAILED — "
                        "UPDATE changed the baseline on a failed run\n");
        (*fails)++;
    }
    return 0;
}

static int shl_selftest_injection_phase(const struct shl_selftest_env *e, int *fails)
{
    if (shl_expect_rc(e, "ZCL_SHELL_HOST_INJECT_SCAN_FAILURE", "1", 1,
                      "an injected scanner failure fails", fails))
        return 1;
    return shl_expect_rc(e, "ZCL_SHELL_HOST_INJECT_SCAN_PATH", e->fixture, 1,
                         "an injected mid-scan failure fails", fails);
}

static int shl_selftest_deleted_baseline_phase(const struct shl_selftest_env *e, int *fails)
{
    if (unlink(e->baseline) != 0 && errno != ENOENT) return 1;
    if (setenv("ZCL_SHELL_HOST_INJECT_TRACKED_BASELINE", "1", 1) != 0) return 1;
    if (shl_expect_rc(e, "ZCL_SHELL_HOST_BOOTSTRAP", "1", 1,
                      "a deleted tracked baseline refuses to regenerate", fails))
        return 1;
    unsetenv("ZCL_SHELL_HOST_INJECT_TRACKED_BASELINE");
    struct stat st;
    if (stat(e->baseline, &st) == 0) {
        fprintf(stderr, "check_shell_host_assumptions: SELFTEST FAILED — "
                        "the deleted-baseline refusal wrote a file\n");
        (*fails)++;
    }
    return 0;
}

static int shl_selftest_phases(const struct shl_selftest_env *e, const char *saved,
                               const char *fixture_saved, int *fails)
{
    if (shl_bootstrap_baseline(e)) {
        fprintf(stderr, "check_shell_host_assumptions: SELFTEST FAILED — bootstrap\n");
        (*fails)++;
    } else if (shl_check_bootstrap_counts(e, fails))
        return 1;

    if (shl_positive_control(e, fails)) return 1;
    if (shl_selftest_growth_phase(e, saved, fixture_saved, fails)) return 1;
    if (shl_selftest_injection_phase(e, fails)) return 1;
    return shl_selftest_deleted_baseline_phase(e, fails);
}

int check_shell_host_assumptions_selftest(void)
{
    char tmpl[4096];
    if (ovf(snprintf(tmpl, sizeof tmpl, "%s/z23-lint-shl.XXXXXX", env_or("TMPDIR", "/tmp")),
            sizeof tmpl))
        return 1;
    char *tmp = mkdtemp(tmpl);
    if (!tmp) return die("z23-lint: mkdir failed\n", "");

    char fixture[4096], baseline[4096], saved[4096], fixture_saved[4096];
    if (shl_selftest_paths(tmp, fixture, baseline, saved, fixture_saved)) {
        rap_rm_rf(tmp);
        return 1;
    }
    struct shl_selftest_env e = { tmp, fixture, baseline };
    int fails = 0;
    int hard_fail = shl_selftest_phases(&e, saved, fixture_saved, &fails);

    rap_rm_rf(tmp);
    if (hard_fail || fails) return 1;
    return printf("[%s] SELFTEST PASS (lexical=true growth=red update=shrink-only "
                 "scanner_failure=red)\n", k_gate) < 0
        ? die("z23-lint: write failed\n", "") : 0;
}
