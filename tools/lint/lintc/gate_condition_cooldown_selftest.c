/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: --selftest for check-condition-cooldown
 * (gate_condition_cooldown.c). Builds an isolated fixture tree under the
 * lint scratch dir (never /tmp) and proves each case of the shell original:
 * the recursion refusal; a cooldown-less network-dependent CRITICAL fixture
 * fires exit 2 and names the offender; removing it restores a clean pass;
 * cooldown_secs, the .progressing exemption, local-only, and COND_WARN all
 * pass; an empty scan dir is fail-loud. A permanent _keep.c filler keeps
 * the scan dir non-empty so the clean-pass cases exercise the real
 * 0-violations path, not the hollow-scan floor.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "lintc.h"
#include "lintc_text.h"

int ccd_run(FILE *out, FILE *err);

enum { CCDST_PATH = 1024, CCDST_TEXT = 4096, CCDST_OUT = 8192 };

static const char k_cdst_selftest[] = "ZCL_CONDITION_COOLDOWN_SELFTEST";
static const char k_cdst_scan[] = "ZCL_CONDITION_COOLDOWN_SCAN_DIR";
static const char k_cdst_name[] = "selftest_fixture_condition";

/* The condition fixture of the shell original: severity, cooldown line,
 * extra struct line, and one detect() body marker are caller-chosen. */
static int cdst_fixture(const char *path, const char *severity,
                        const char *cooldown_line, const char *extra,
                        const char *marker)
{
    char text[CCDST_TEXT];
    if (ovf(snprintf(text, sizeof text,
                     "/* selftest fixture — not a real condition */\n"
                     "#include \"framework/condition.h\"\n"
                     "\n"
                     "static bool detect_fixture(void)\n"
                     "{\n"
                     "    %s\n"
                     "    return false;\n"
                     "}\n"
                     "\n"
                     "static enum condition_remedy_result remedy_fixture(void)\n"
                     "{\n"
                     "    return COND_REMEDY_OK;\n"
                     "}\n"
                     "\n"
                     "static bool witness_fixture(int64_t target_at_detect)\n"
                     "{\n"
                     "    (void)target_at_detect;\n"
                     "    return false;\n"
                     "}\n"
                     "\n"
                     "static struct condition c_fixture = {\n"
                     "    .name = \"%s\",\n"
                     "    .severity = %s,\n"
                     "    .poll_secs = 5,\n"
                     "    .backoff_secs = 60,\n"
                     "    .max_attempts = 1,\n"
                     "    %s\n"
                     "    %s\n"
                     "    .detect = detect_fixture,\n"
                     "    .remedy = remedy_fixture,\n"
                     "    .witness = witness_fixture,\n"
                     "    .witness_window_secs = 60,\n"
                     "};\n",
                     marker, k_cdst_name, severity, cooldown_line, extra),
             sizeof text))
        return 2;
    return csr_write(path, text);
}

/* Reads a whole tmpfile back into buf (NUL-terminated). */
static void cdst_slurp(FILE *f, char *buf, size_t cap)
{
    rewind(f);
    size_t n = fread(buf, 1, cap - 1, f);
    buf[n] = '\0';
}

/* Runs the gate over dir with the selftest env cleared; returns rc via
 * *rc and the combined out/err text in buf. */
static void cdst_gate(const char *dir, int *rc, char *buf, size_t cap)
{
    unsetenv(k_cdst_selftest);
    setenv(k_cdst_scan, dir, 1);
    FILE *o = tmpfile(), *e = tmpfile();
    if (!o || !e)
        die("z23-lint: tmpfile failed\n", "");
    /* gate_require_scanned writes to fd 2 directly; capture it like the
     * shell's 2>&1 so a hollow-scan case stays quiet unless it fails. */
    fflush(stderr);
    int saved = dup(STDERR_FILENO);
    if (saved < 0 || dup2(fileno(e), STDERR_FILENO) < 0)
        die("z23-lint: cannot redirect stderr\n", "");
    *rc = ccd_run(o, e);
    fflush(stderr);
    if (dup2(saved, STDERR_FILENO) < 0)
        die("z23-lint: cannot restore stderr\n", "");
    close(saved);
    fflush(e);
    cdst_slurp(o, buf, cap);
    size_t n = strlen(buf);
    if (n < cap - 1)
        cdst_slurp(e, buf + n, cap - n);
    fclose(o);
    fclose(e);
    unsetenv(k_cdst_scan);
}

/* One expect_rc case: the gate over dir must exit want and, when needle is
 * set, its output must contain needle. Returns 0 when it does. */
static int cdst_expect_text(const char *name, int want, const char *dir,
                            const char *needle)
{
    static char buf[CCDST_OUT];
    int rc = 0;
    cdst_gate(dir, &rc, buf, sizeof buf);
    if (rc != want) {
        printf("SELFTEST FAIL: %s — expected exit %d, got %d\n", name, want,
               rc);
        printf("  --- gate output ---\n%.4000s", buf);
        return 1;
    }
    if (needle && !strstr(buf, needle)) {
        printf("SELFTEST FAIL: %s — output lacks \"%s\"\n", name, needle);
        return 1;
    }
    return 0;
}

static int cdst_expect(const char *name, int want, const char *dir,
                       int want_named)
{
    return cdst_expect_text(name, want, dir, want_named ? k_cdst_name : NULL);
}

/* Case 0: a child that inherits the self-test request must refuse before
 * scanning anything. */
static int cdst_case_recursion(void)
{
    const char *refusal = "FAIL: check_condition_cooldown self-test "
                          "recursion refused";
    static char buf[CCDST_OUT];
    int rc = 0;
    setenv(k_cdst_selftest, "1", 1);
    FILE *o = tmpfile(), *e = tmpfile();
    if (!o || !e)
        die("z23-lint: tmpfile failed\n", "");
    rc = ccd_run(o, e);
    cdst_slurp(o, buf, sizeof buf);
    size_t n = strlen(buf);
    if (n < sizeof buf - 1)
        cdst_slurp(e, buf + n, sizeof buf - n);
    fclose(o);
    fclose(e);
    unsetenv(k_cdst_selftest);
    if (rc != 2) {
        printf("SELFTEST FAIL: recursive self-test expected exit 2, got %d\n",
               rc);
        return 1;
    }
    if (!strstr(buf, refusal)) {
        printf("SELFTEST FAIL: recursive self-test refusal was not named\n");
        return 1;
    }
    return 0;
}

/* One fixture case: plant file under root, expect the gate to exit want,
 * remove it. A non-NULL then_clean also re-runs the gate on the emptied
 * dir and expects a clean pass. */
struct cdst_case {
    const char *file, *severity, *cooldown, *extra, *body;
    const char *name, *then_clean;
    int want, named;
};

static const struct cdst_case k_cdst_cases[] = {
    {"bad_fixture.c", "COND_CRITICAL", "", "",
     "int p = connman_max_peer_height(cm);",
     "network-dependent CRITICAL with no cooldown fires exit 2",
     "removing the fixture restores a clean pass", 2, 1},
    {"good_cooldown.c", "COND_CRITICAL", ".cooldown_secs = 600,", "",
     "int p = sync_monitor_connman();",
     "network-dependent CRITICAL with cooldown_secs passes", NULL, 0, 0},
    {"good_progressing.c", "COND_CRITICAL", "",
     ".progressing = progressing_fixture,",
     "int n = connman_get_node_count(cm);",
     "network-dependent CRITICAL with .progressing exemption passes", NULL,
     0, 0},
    {"local_only.c", "COND_CRITICAL", "", "", "int d = 0; (void)d;",
     "local-only CRITICAL with no network markers passes", NULL, 0, 0},
    {"warn_network.c", "COND_WARN", "", "",
     "int p = connman_max_peer_height(cm);",
     "network-dependent COND_WARN is out of scope, passes", NULL, 0, 0},
};

/* Runs one table case; returns its failure count, or -1 on a harness error. */
static int cdst_run_case(const char *root, const struct cdst_case *c)
{
    char path[CCDST_PATH];
    if (ovf(snprintf(path, sizeof path, "%s/%s", root, c->file),
            sizeof path))
        return -1;
    if (cdst_fixture(path, c->severity, c->cooldown, c->extra, c->body))
        return -1;
    int failures = cdst_expect(c->name, c->want, root, c->named) != 0;
    if (unlink(path) != 0) {
        die("z23-lint: cannot remove fixture %s\n", path);
        return -1;
    }
    if (c->then_clean)
        failures += cdst_expect(c->then_clean, 0, root, 0) != 0;
    return failures;
}

/* Plants the filler and the empty dir; returns 0 or a harness rc. */
static int cdst_setup(const char *root, char *empty, size_t cap)
{
    char path[CCDST_PATH];
    if (ovf(snprintf(empty, cap, "%s/empty", root), cap))
        return 2;
    if (mkdir(empty, 0755) != 0 && access(empty, F_OK) != 0)
        return die("z23-lint: cannot mkdir %s\n", empty);
    if (ovf(snprintf(path, sizeof path, "%s/_keep.c", root), sizeof path))
        return 2;
    return csr_write(path, "/* selftest filler — not a condition, keeps "
                           "the scan dir non-empty. */\n");
}

/* A condition file whose name is a macro resolved from a #define. */
static const char k_cdst_macro_src[] =
    "#define ZZ_COND_NAME \"macro_named_condition\"\n"
    "static struct condition c_fixture = {\n"
    "    .name = ZZ_COND_NAME,\n"
    "    .severity = COND_CRITICAL,\n"
    "};\n"
    "static int d(void) { return connman_max_peer_height(cm); }\n";

/* Plants text at root/file, runs the gate, removes it again; the file is
 * made unreadable first when unreadable is set. Returns failures or -1. */
static int cdst_raw_case(const char *root, const char *file, const char *text,
                         int unreadable, const char *name, const char *needle)
{
    char path[CCDST_PATH];
    if (ovf(snprintf(path, sizeof path, "%s/%s", root, file), sizeof path))
        return -1;
    if (csr_write(path, text))
        return -1;
    if (unreadable && chmod(path, 0) != 0)
        return -1;
    /* A reader that bypasses file modes (root) cannot see the failure. */
    int skip = unreadable && access(path, R_OK) == 0;
    int f = skip ? 0 : cdst_expect_text(name, 2, root, needle) != 0;
    if (unlink(path) != 0)
        return -1;
    return f;
}

/* Fail-closed cases: macro-resolved name, unreadable file, over-long line.
 * Returns the failure count, or -1 on a harness error. */
static int cdst_failclosed(const char *root)
{
    static char longline[CCDST_TEXT + 64];
    memset(longline, 'x', CCDST_TEXT + 32);
    longline[CCDST_TEXT + 32] = '\n';
    longline[CCDST_TEXT + 33] = '\0';
    int a = cdst_raw_case(root, "macro_name.c", k_cdst_macro_src, 0,
                          ".name = MACRO resolves through its #define",
                          "macro_named_condition");
    int b = cdst_raw_case(root, "unreadable.c", k_cdst_macro_src, 1,
                          "unreadable file is fail-closed, not skipped",
                          "cannot read");
    int c = cdst_raw_case(root, "longline.c", longline, 0,
                          "over-long line is fail-closed, not truncated",
                          "exceeds");
    return (a < 0 || b < 0 || c < 0) ? -1 : a + b + c;
}

int check_condition_cooldown_selftest(void)
{
    char root[CCDST_PATH], empty[CCDST_PATH];
    int rc = lct_scratch_dir(root, sizeof root, "condition-cooldown");
    if (rc)
        return rc;
    rc = cdst_setup(root, empty, sizeof empty);
    if (rc)
        return rc;
    int failures = cdst_case_recursion() != 0;
    for (size_t i = 0; i < sizeof k_cdst_cases / sizeof k_cdst_cases[0];
         i++) {
        int f = cdst_run_case(root, &k_cdst_cases[i]);
        if (f < 0)
            return 2;
        failures += f;
    }
    int fc = cdst_failclosed(root);
    if (fc < 0)
        return 2;
    failures += fc;
    failures += cdst_expect("empty scan dir is fail-loud, not a hollow pass",
                            2, empty, 0) != 0;
    rap_rm_rf(root);
    if (failures == 0) {
        printf("check_condition_cooldown: selftest OK (10/10 cases)\n");
        return 0;
    }
    printf("check_condition_cooldown: selftest FAILED (%d case(s))\n",
           failures);
    return 1;
}
