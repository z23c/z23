/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: --selftest for check-sync-state-no-ordinal
 * (gate_sync_state_no_ordinal.c). Exercises the same git-grep scanner in a
 * private scratch repository (never inside a live source directory, so no
 * concurrent proof lint can observe the fixture): a clean untracked source
 * passes; untracked and tracked ordinal comparisons fail in both operand
 * orders; the SYNC_TRUST_STATE_COUNT sentinel recovers to clean; an empty
 * scan fails closed with exit 2. Ported from the --selftest mode of
 * tools/scripts/check_sync_state_no_ordinal.sh (deleted).
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>
#include "lintc.h"
#include "lintc_text.h"

/* Shared with gate_sync_state_no_ordinal.c (declared there, non-static so
 * this fixture driver can drive the exact production scan). */
int sno_scan(const char *cwd, FILE *out, int *nfiles);
int sno_wait(pid_t pid, int *st);

enum { SNOS_PATH = 1024 };

static const char k_snos_probe_rel[] = "engine/services/src/probe.c";
/* Under the shared exclusion filter's test-tmp/ pattern: git sees it, the
 * production scan must not count it. */
static const char k_snos_excluded_rel[] = "engine/test-tmp/sno_probe.c";
static const char k_snos_ordinal_text[] =
    "int f(int st) { return st >= " "SYNC_TRUST_SOVEREIGN; }\n";

struct snos_case {
    const char *name;
    const char *text;  /* written into probe.c; NULL removes the file */
    int tracked;       /* 1 stages the file with git add first */
    int want;          /* expected sno_scan return */
};

static const struct snos_case k_snos_cases[] = {
    { "clean untracked source",
      "int f(int st) { return st == SYNC_TRUST_SOVEREIGN; }\n", 0, 0 },
    /* The ordinal probes are split at the quote so this source never
     * contains the comparator-adjacent token the gate itself scans for. */
    { "untracked ordinal comparison",
      "int f(int st) { return st >= " "SYNC_TRUST_SOVEREIGN; }\n", 0, 1 },
    { "tracked ordinal comparison",
      "int f(int st) { return st >= " "SYNC_TRUST_SOVEREIGN; }\n", 1, 1 },
    { "reversed ordinal comparison",
      "int f(int st) { return SYNC_TRUST_SOVEREIGN" " <= st; }\n", 1, 1 },
    { "count sentinel recovers",
      "int f(int st) { return st < SYNC_TRUST_STATE_COUNT; }\n", 1, 0 },
    { "empty scan fails closed", NULL, 0, 2 },
};

/* Runs git with one or two arguments inside root; returns its exit status
 * or a negative code on spawn/wait failure. */
static int snos_git(const char *root, const char *a, const char *b)
{
    pid_t pid = fork();
    if (pid < 0)
        return -1;
    if (pid == 0) {
        char *av[4];
        int i = 0;
        av[i++] = (char *)"git";
        av[i++] = (char *)a;
        if (b)
            av[i++] = (char *)b;
        av[i] = NULL;
        if (chdir(root) != 0)
            _exit(126);
        execvp("git", av);
        _exit(127);
    }
    int st = 0;
    if (sno_wait(pid, &st) != 0)
        return -1;
    return WIFEXITED(st) ? WEXITSTATUS(st) : -1;
}

/* Plants (or removes) the probe fixture for one case. Returns 0 ok. */
static int snos_plant(const char *root, const struct snos_case *c)
{
    char path[SNOS_PATH];
    if (ovf(snprintf(path, sizeof path, "%s/%s", root, k_snos_probe_rel),
             sizeof path))
        return 2;
    if (!c->text) {
        if (unlink(path) == 0)
            return 0;
        return die("z23-lint: cannot remove %s\n", path);
    }
    int rc = csr_write(path, c->text);
    if (rc == 0 && c->tracked && snos_git(root, "add", k_snos_probe_rel) != 0)
        return die("z23-lint: git add failed in selftest repo %s\n", root);
    return rc;
}

/* Runs sno_scan with stdout and stderr both captured in sink, as the shell
 * selftest's output=$(... 2>&1) does, so an expected FATAL stays silent.
 * Returns the scan verdict, or 2 when the capture cannot be wired. */
static int snos_scan_captured(const char *root, FILE *sink)
{
    int nfiles = 0;
    fflush(stderr);
    int saved = dup(STDERR_FILENO);
    if (saved < 0)
        return 2;
    if (dup2(fileno(sink), STDERR_FILENO) < 0) {
        close(saved);
        return 2;
    }
    int got = sno_scan(root, sink, &nfiles);
    fflush(stderr);
    if (dup2(saved, STDERR_FILENO) < 0)
        got = 2;
    close(saved);
    return got;
}

/* Runs one case; returns 0 when sno_scan answered the expected verdict. */
static int snos_run_case(const char *root, const struct snos_case *c)
{
    int rc = snos_plant(root, c);
    if (rc)
        return rc;
    FILE *sink = tmpfile();
    if (!sink)
        return die("z23-lint: tmpfile failed\n", "");
    int got = snos_scan_captured(root, sink);
    fclose(sink);
    if (got != c->want) {
        fprintf(stderr,
                "check_sync_state_no_ordinal --selftest: FAIL %s: "
                "rc=%d want=%d\n", c->name, got, c->want);
        return 1;
    }
    printf("  ok %s (rc=%d)\n", c->name, got);
    return 0;
}

/* Scans with a planted violation under an excluded path (test-tmp/). git grep
 * sees it, the shared production filter drops it, so the scan is clean. The
 * file is removed again so later cases see only their own fixture. */
static int snos_excluded_case(const char *root)
{
    char path[SNOS_PATH];
    if (ovf(snprintf(path, sizeof path, "%s/%s", root, k_snos_excluded_rel),
             sizeof path))
        return 2;
    int rc = csr_write(path, k_snos_ordinal_text);
    if (rc)
        return rc;
    FILE *sink = tmpfile();
    if (!sink)
        return die("z23-lint: tmpfile failed\n", "");
    int got = snos_scan_captured(root, sink);
    fclose(sink);
    if (unlink(path) != 0)
        return die("z23-lint: cannot remove %s\n", path);
    if (got != 0) {
        fprintf(stderr, "check_sync_state_no_ordinal --selftest: FAIL "
                "excluded violation counted: rc=%d want=0\n", got);
        return 1;
    }
    printf("  ok violation under excluded path not counted (rc=%d)\n", got);
    return 0;
}

/* A hits scan that cannot run (missing working directory: git is never
 * exec'd, the child reports 126) must fail closed with rc 2. */
static int snos_failed_scan_case(const char *root)
{
    char missing[SNOS_PATH];
    if (ovf(snprintf(missing, sizeof missing, "%s/no-such-dir", root),
             sizeof missing))
        return 2;
    FILE *sink = tmpfile();
    if (!sink)
        return die("z23-lint: tmpfile failed\n", "");
    int got = snos_scan_captured(missing, sink);
    fclose(sink);
    if (got != 2) {
        fprintf(stderr, "check_sync_state_no_ordinal --selftest: FAIL "
                "failed hits scan: rc=%d want=2\n", got);
        return 1;
    }
    printf("  ok failed hits scan fails closed (rc=%d)\n", got);
    return 0;
}

/* Selftest body, run with ZCL_LINT_PRODUCTION_SCAN=1 so the shared exclusion
 * filter is live. Returns 0 when every case held. */
static int snos_run_all(const char *root)
{
    int bad = 0;
    for (size_t i = 0; i < sizeof k_snos_cases / sizeof k_snos_cases[0]; i++)
        bad |= snos_run_case(root, &k_snos_cases[i]) != 0;
    bad |= snos_excluded_case(root) != 0;
    bad |= snos_failed_scan_case(root) != 0;
    return bad;
}

int check_sync_state_no_ordinal_selftest(void)
{
    char root[SNOS_PATH];
    int rc = lct_scratch_dir(root, sizeof root, "sync-state-no-ordinal");
    if (rc)
        return rc;
    if (snos_git(root, "init", "-q") != 0) {
        rap_rm_rf(root);
        return die("z23-lint: git init failed for selftest repo %s\n",
                   root);
    }
    const char *prev = getenv("ZCL_LINT_PRODUCTION_SCAN");
    setenv("ZCL_LINT_PRODUCTION_SCAN", "1", 1);
    int bad = snos_run_all(root);
    if (prev)
        setenv("ZCL_LINT_PRODUCTION_SCAN", prev, 1);
    else
        unsetenv("ZCL_LINT_PRODUCTION_SCAN");
    rap_rm_rf(root);
    if (bad) {
        fputs("FAIL: check_sync_state_no_ordinal selftest\n", stderr);
        return 1;
    }
    return st_ok(0, "check_sync_state_no_ordinal --selftest: PASS\n");
}
