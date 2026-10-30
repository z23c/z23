/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: gate check-scanner-immunity — wf/dx-scanner-immunity regression
 * proof. Ported from tools/lint/selftest_scanner_immunity.sh (deleted).
 * Plants transient fixture files into an isolated scan root and proves the
 * exclusion mechanism of scan_exclusions.sh: a PRODUCTION scan
 * (ZCL_LINT_PRODUCTION_SCAN=1) ignores a mid-scan fixture, a SELFTEST-style
 * direct invocation still detects it, a REAL (non-fixture-named) violation
 * fails every mode, the scan recovers to clean, the stray-file gate leaves a
 * fixture-named untracked file alone, and an arbitrary-named untracked
 * stray file is distinctly named as "untracked stray file" rather than a
 * code violation. Child gates are exec'd directly (execve, never a shell).
 * Selftest: gate_scanner_immunity_selftest.c.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include "lintc.h"

enum { SI_PATH = 1024, SI_TEXT = 4096, SI_OUT = 16384, SI_MSG = 640,
       SI_ENVN = 256, SI_ENVL = 2048 };

static const char k_si_gate_bin[] = "build/bin/z23-lint";
static const char k_si_tag[] = "selftest_scanner_immunity";

extern char **environ;

struct si_env { const char *name; const char *val; };

static char si_scan_root[SI_PATH];
static char si_out[SI_OUT];
static int si_fail;

static const char k_si_race_text[] =
    "/* Transient lint-gate selftest fixture — regression proof only, never\n"
    " * committed. Named _x_fixture_tmp_.c per the shared convention in\n"
    " * tools/lint/scan_exclusions.sh (basename contains \"fixture\"). */\n"
    "#include <stdbool.h>\n"
    "static bool fixture_fallible_call(void) { return true; }\n"
    "bool _x_fixture_tmp_case(void)\n"
    "{\n"
    "    if (!fixture_fallible_call())\n"
    "        return false;\n"
    "    return true;\n"
    "}\n";

static const char k_si_race2_text[] =
    "/* Same race fixture as section 1, replanted to prove the STRAY gate\n"
    " * (not just check-silent-errors-bool) also leaves it alone. */\n"
    "static void race_fixture_probe(void) {}\n";

static const char k_si_real_text[] =
    "/* Deliberately NOT fixture-named (no \"fixture\" in the basename) — proves\n"
    " * the exclusion is scoped to the naming convention, not a blanket skip. */\n"
    "#include <stdbool.h>\n"
    "static bool real_fallible_call(void) { return true; }\n"
    "bool _test_regression_real_violation_scanner_immunity_case(void)\n"
    "{\n"
    "    if (!real_fallible_call())\n"
    "        return false;\n"
    "    return true;\n"
    "}\n";

static const char k_si_stray_text[] =
    "/* Untracked stray file — simulates crashed-agent debris left in a scanned\n"
    " * dir. Content is deliberately clean (no violations) so ANY failure this\n"
    " * causes on check_no_stray_untracked_source.sh must come from being\n"
    " * untracked, not from its content. */\n"
    "static void scanner_immunity_stray_probe(void) {}\n";

static int si_env_is(const char *entry, const char *name)
{
    size_t n = strlen(name);
    return strncmp(entry, name, n) == 0 && entry[n] == '=';
}

static int si_env_put(char *dst, const char *name, const char *val)
{
    return ovf(snprintf(dst, SI_ENVL, "%s=%s", name, val), (size_t)SI_ENVL)
               ? -1
               : 0;
}

/* Builds a full envp (static storage, no heap) from environ with the mod
 * entries applied: val != NULL sets/replaces, val == NULL unsets. Returns
 * the entry count, or -1 on overflow. nmod must be <= 16. */
static int si_env_build(char (*buf)[SI_ENVL], char **ptr, int max,
                        const struct si_env *mod, int nmod)
{
    unsigned char used[2] = { 0, 0 };
    int n = 0;
    for (char **e = environ; *e; e++) {
        int hit = -1;
        for (int j = 0; j < nmod; j++)
            if (si_env_is(*e, mod[j].name)) {
                hit = j;
                break;
            }
        if (hit >= 0) {
            if (!mod[hit].val)
                continue;
            used[hit / 8] |= (unsigned char)(1u << (hit % 8));
            if (si_env_put(buf[n], mod[hit].name, mod[hit].val))
                return -1;
        } else {
            size_t l = strlen(*e);
            if (l >= (size_t)SI_ENVL)
                return -1;
            memcpy(buf[n], *e, l + 1);
        }
        ptr[n] = buf[n];
        n++;
        if (n >= max)
            return -1;
    }
    for (int j = 0; j < nmod; j++) {
        if (!mod[j].val || (used[j / 8] & (unsigned char)(1u << (j % 8))))
            continue;
        if (si_env_put(buf[n], mod[j].name, mod[j].val))
            return -1;
        ptr[n] = buf[n];
        n++;
        if (n >= max)
            return -1;
    }
    ptr[n] = NULL;
    return n;
}

/* waitpid retried on EINTR only; any other failure is an error, never a
 * clean status. */
static int si_wait(pid_t pid, int *st)
{
    for (;;) {
        if (waitpid(pid, st, 0) >= 0)
            return 0;
        if (errno != EINTR)
            return -1;
    }
}

/* exec's path with argv and the modified environment, capturing both stdout
 * and stderr of the child into out. *code receives the child's exit status
 * (128 if killed by a signal). Returns 0 ran, 2 internal error. */
static int si_spawn(const char *path, char *const argv[],
                    const struct si_env *mod, int nmod, char *out, size_t cap,
                    int *code)
{
    static char env_buf[SI_ENVN][SI_ENVL];
    static char *env_ptr[SI_ENVN + 1];
    if (si_env_build(env_buf, env_ptr, SI_ENVN, mod, nmod) < 0) {
        fprintf(stderr, "%s: env array exceeds %d\n", k_si_tag, SI_ENVN);
        return 2;
    }
    FILE *tf = tmpfile();
    if (!tf)
        return die("z23-lint: tmpfile failed\n", "");
    pid_t pid = fork();
    if (pid < 0) {
        fclose(tf);
        return die("z23-lint: fork failed\n", "");
    }
    if (pid == 0) {
        if (dup2(fileno(tf), 1) < 0 || dup2(fileno(tf), 2) < 0)
            _exit(126);
        execve(path, argv, env_ptr);
        _exit(127);
    }
    int st = 0;
    if (si_wait(pid, &st) < 0) {
        fclose(tf);
        return die("z23-lint: waitpid failed\n", "");
    }
    if (fseek(tf, 0, SEEK_SET) != 0) {
        fclose(tf);
        return die("z23-lint: rewind of capture failed\n", "");
    }
    size_t r = fread(out, 1, cap - 1, tf);
    out[r] = '\0';
    fclose(tf);
    *code = WIFEXITED(st) ? WEXITSTATUS(st) : 128;
    return 0;
}

/* prod: "1" to set ZCL_LINT_PRODUCTION_SCAN, NULL to clear it. The scanvar
 * entry is always set to the isolated scan root. */
static int si_run_scan(const char *prod, const char *scanvar, const char *gate,
                       int *grc)
{
    struct si_env mod[2];
    mod[0].name = "ZCL_LINT_PRODUCTION_SCAN";
    mod[0].val = prod;
    mod[1].name = scanvar;
    mod[1].val = si_scan_root;
    char *argv[3] = { (char *)"z23-lint", (char *)gate, NULL };
    return si_spawn(k_si_gate_bin, argv, mod, 2, si_out, SI_OUT, grc);
}

static int si_run_prod(const char *gate, int *grc)
{
    return si_run_scan("1", "ZCL_SILENT_BOOL_SCAN_DIRS_FOR_TEST", gate, grc);
}

static int si_run_direct(const char *gate, int *grc)
{
    return si_run_scan(NULL, "ZCL_SILENT_BOOL_SCAN_DIRS_FOR_TEST", gate, grc);
}

/* The shell original inherited the caller's ZCL_LINT_PRODUCTION_SCAN. */
static int si_run_stray(int *grc)
{
    return si_run_scan(getenv("ZCL_LINT_PRODUCTION_SCAN"),
                       "ZCL_STRAY_SCAN_DIRS_FOR_TEST",
                       "check-no-stray-untracked-source", grc);
}

static int si_path_under(char *out, size_t cap, const char *root,
                         const char *leaf)
{
    return ovf(snprintf(out, cap, "%s/%s", root, leaf), cap) ? 2 : 0;
}

static void si_note(const char *s)
{
    printf("  [%s] %s\n", k_si_tag, s);
}

static void si_assert(const char *desc, int rc, int want_zero)
{
    int ok = (rc == 0) == (want_zero != 0);
    char msg[SI_MSG];
    int n;
    if (ok)
        n = snprintf(msg, sizeof msg, "PASS: %s", desc);
    else if (want_zero)
        n = snprintf(msg, sizeof msg, "FAIL: %s (rc=%d)", desc, rc);
    else
        n = snprintf(msg, sizeof msg, "FAIL: %s (rc=%d, expected nonzero)",
                     desc, rc);
    if (ovf(n, sizeof msg)) {
        fprintf(stderr, "%s: assert message exceeds %d\n", k_si_tag, SI_MSG);
        si_fail = 1;
        return;
    }
    si_note(msg);
    if (!ok)
        si_fail = 1;
}

static void si_dump(const char *out)
{
    const char *p = out;
    while (*p) {
        const char *nl = strchr(p, '\n');
        size_t n = nl ? (size_t)(nl - p) : strlen(p);
        printf("  %.*s\n", (int)n, p);
        p = nl ? nl + 1 : p + n;
    }
}

/* One output line s[0..n): the first occurrence of path must be followed,
 * on the same line, by the "untracked stray file" marker (grep "PATH.*marker"
 * of the shell original). */
static int si_line_names_stray(const char *s, size_t n, const char *path)
{
    static const char k_marker[] = "untracked stray file";
    size_t pl = strlen(path), ml = sizeof k_marker - 1;
    for (size_t i = 0; i + pl <= n; i++) {
        if (memcmp(s + i, path, pl) != 0)
            continue;
        for (size_t j = i + pl; j + ml <= n; j++)
            if (memcmp(s + j, k_marker, ml) == 0)
                return 1;
        return 0;
    }
    return 0;
}

int si_stray_output_names(const char *out, const char *path)
{
    const char *p = out;
    while (*p) {
        const char *nl = strchr(p, '\n');
        size_t n = nl ? (size_t)(nl - p) : strlen(p);
        if (si_line_names_stray(p, n, path))
            return 1;
        p = nl ? nl + 1 : p + n;
    }
    return 0;
}

static int si_section1(void)
{
    puts("== 1/5: race-fixture content (violates check-silent-errors-bool) ==");
    char path[SI_PATH];
    int rc = si_path_under(path, sizeof path, si_scan_root,
                           "_x_fixture_tmp_.c");
    if (rc)
        return rc;
    rc = csr_write(path, k_si_race_text);
    if (rc)
        return rc;
    int grc = 0;
    rc = si_run_prod("check-silent-errors-bool", &grc);
    if (rc)
        return rc;
    si_assert("PRODUCTION scan (ZCL_LINT_PRODUCTION_SCAN=1) ignores the "
              "mid-scan fixture", grc, 1);
    if (grc != 0) {
        si_note("  --- production scan output ---");
        si_dump(si_out);
    }
    rc = si_run_direct("check-silent-errors-bool", &grc);
    if (rc)
        return rc;
    si_assert("SELFTEST-style invocation still detects the fixture "
              "(unweakened)", grc, 0);
    if (grc == 0) {
        si_note("  --- selftest-style output (unexpected clean) ---");
        si_dump(si_out);
    }
    unlink(path);
    return 0;
}

static int si_section2(void)
{
    puts("== 2/5: a REAL violation (non-fixture name) still fails every mode ==");
    char path[SI_PATH];
    int rc = si_path_under(path, sizeof path, si_scan_root,
                           "_test_regression_real_violation_scanner_immunity.c");
    if (rc)
        return rc;
    rc = csr_write(path, k_si_real_text);
    if (rc)
        return rc;
    int grc = 0;
    rc = si_run_prod("check-silent-errors-bool", &grc);
    if (rc)
        return rc;
    si_assert("PRODUCTION scan still catches a REAL (non-fixture-named) "
              "violation", grc, 0);
    rc = si_run_direct("check-silent-errors-bool", &grc);
    if (rc)
        return rc;
    si_assert("SELFTEST-style scan still catches a REAL (non-fixture-named) "
              "violation", grc, 0);
    unlink(path);
    return 0;
}

static int si_section3(void)
{
    puts("== 3/5: gate recovers to clean once the real violation is removed ==");
    int grc = 0;
    int rc = si_run_prod("check-silent-errors-bool", &grc);
    if (rc)
        return rc;
    si_assert("PRODUCTION scan is clean again after cleanup", grc, 1);
    return 0;
}

static int si_section4(void)
{
    puts("== 4/5: 'make lint while a fixture is planted' stays clean (the stray "
         "gate itself) ==");
    char path[SI_PATH];
    int rc = si_path_under(path, sizeof path, si_scan_root,
                           "_x_fixture_tmp_.c");
    if (rc)
        return rc;
    rc = csr_write(path, k_si_race2_text);
    if (rc)
        return rc;
    int grc = 0;
    rc = si_run_stray(&grc);
    if (rc)
        return rc;
    si_assert("check_no_stray_untracked_source.sh ignores an untracked "
              "fixture-named file", grc, 1);
    if (grc != 0) {
        si_note("  --- unexpected stray-gate output ---");
        si_dump(si_out);
    }
    unlink(path);
    return 0;
}

static int si_section5(void)
{
    puts("== 5/5: untracked stray file is named distinctly, not as a code "
         "violation ==");
    char path[SI_PATH];
    int rc = si_path_under(path, sizeof path, si_scan_root,
                           "_test_regression_stray_untracked_scanner_immunity.c");
    if (rc)
        return rc;
    rc = csr_write(path, k_si_stray_text);
    if (rc)
        return rc;
    int grc = 0;
    rc = si_run_stray(&grc);
    if (rc)
        return rc;
    si_assert("check_no_stray_untracked_source.sh fails on the untracked file",
              grc, 0);
    char msg[SI_PATH + 96];
    int n = snprintf(msg, sizeof msg,
                     "PASS: output names '%s' as an untracked stray file "
                     "(not a code violation)", path);
    if (ovf(n, sizeof msg))
        return 2;
    if (si_stray_output_names(si_out, path))
        si_note(msg);
    else {
        si_note("FAIL: output does not distinctly name the stray file:");
        si_dump(si_out);
        si_fail = 1;
    }
    unlink(path);
    rc = si_run_stray(&grc);
    if (rc)
        return rc;
    si_assert("check_no_stray_untracked_source.sh is clean again after "
              "cleanup", grc, 1);
    return 0;
}

static void si_cleanup(void)
{
    char path[SI_PATH];
    static const char *const leaves[] = {
        "_x_fixture_tmp_.c",
        "_test_regression_real_violation_scanner_immunity.c",
        "_test_regression_stray_untracked_scanner_immunity.c",
    };
    for (size_t i = 0; i < sizeof leaves / sizeof leaves[0]; i++)
        if (si_path_under(path, sizeof path, si_scan_root, leaves[i]) == 0)
            unlink(path);
    rmdir(si_scan_root);
}

int check_scanner_immunity_run(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    mkdir(".cache", 0777);
    if (ovf(snprintf(si_scan_root, sizeof si_scan_root,
                     ".cache/scanner-immunity-selftest.XXXXXX"),
            sizeof si_scan_root))
        return 2;
    if (!mkdtemp(si_scan_root)) {
        fputs("selftest_scanner_immunity: could not create isolated scan "
              "root\n", stderr);
        return 1;
    }
    int rc = si_section1();
    if (!rc)
        rc = si_section2();
    if (!rc)
        rc = si_section3();
    if (!rc)
        rc = si_section4();
    if (!rc)
        rc = si_section5();
    si_cleanup();
    if (rc)
        return rc;
    putchar('\n');
    if (si_fail) {
        puts("selftest_scanner_immunity: FAILED — see [FAIL] lines above");
        return 1;
    }
    puts("selftest_scanner_immunity: ALL ASSERTIONS PASSED");
    return 0;
}
