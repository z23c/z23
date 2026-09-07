/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: --selftest for check-windows-acceptance-guard
 * (gate_windows_acceptance_guard.c). Builds a fixture tree from the REAL
 * catalog with every declared TU correctly guarded (the parse under test
 * is the parse that runs in production), then mutates one file at a time
 * to prove each red case is caught and named, and that the floor refuses a
 * scan set below it. Fixtures live under
 * $HOME/.local/state/zclassic23/scratch (never /tmp — shared with gates
 * that fixture there), matching the shell original's own scratch contract.
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
#include "gate_windows_acceptance_guard_priv.h"

enum { WAGS_OUT = 65536 };

static int wags_write_guarded(const char *path, const char *name)
{
    char body[2048];
    if (ovf(snprintf(body, sizeof body,
                     "/* Fixture Copyright header spanning\n"
                     " * two comment lines like the real TUs. */\n"
                     "\n"
                     "#if defined(_WIN32)\n"
                     "\n"
                     "#include <stdio.h>\n"
                     "\n"
                     "int main(void)\n"
                     "{\n"
                     "    return 0;\n"
                     "}\n"
                     "\n"
                     "#else\n"
                     "typedef int %s_not_built;\n"
                     "#endif\n", name), sizeof body))
        return 2;
    return csr_write(path, body);
}

static const char *wags_basename_noext(const char *path)
{
    const char *slash = strrchr(path, '/');
    return slash ? slash + 1 : path;
}

/* strdup-free ".c"-stripped copy into a caller buffer. */
static int wags_stem(const char *path, char *out, size_t cap)
{
    const char *b = wags_basename_noext(path);
    size_t n = strlen(b);
    if (n > 2 && strcmp(b + n - 2, ".c") == 0) n -= 2;
    if (n >= cap) return die("z23-lint: name too long: %s\n", path);
    memcpy(out, b, n);
    out[n] = '\0';
    return 0;
}

static int wags_full(const char *dir, const char *rel, char *out, size_t cap)
{ return ovf(snprintf(out, cap, "%s/%s", dir, rel), cap) ? 2 : 0; }

static int wags_mkparents(const char *full)
{
    char dir[4096];
    const char *slash = strrchr(full, '/');
    if (!slash) return die("z23-lint: path too long: %s\n", full);
    size_t n = (size_t)(slash - full);
    if (n >= sizeof dir) return die("z23-lint: path too long: %s\n", full);
    memcpy(dir, full, n);
    dir[n] = '\0';
    return csr_mkdirs(dir);
}

static int wags_build_good(const char *repo_root, const char *d)
{
    char catdir[4096], catfull_src[4096], catfull_dst[4096];
    if (ovf(snprintf(catdir, sizeof catdir, "%s/platform/modules/platform/tests",
                     d), sizeof catdir))
        return 2;
    int rc = csr_mkdirs(catdir);
    if (rc) return rc;
    if (ovf(snprintf(catfull_src, sizeof catfull_src, "%s/%s", repo_root,
                     k_wag_catalog_rel), sizeof catfull_src)
        || ovf(snprintf(catfull_dst, sizeof catfull_dst, "%s/%s", d,
                        k_wag_catalog_rel), sizeof catfull_dst))
        return 2;
    char cmd[8192], q1[4200], q2[4200];
    if (sh_single_quote(catfull_src, q1, sizeof q1)
        || sh_single_quote(catfull_dst, q2, sizeof q2)
        || ovf(snprintf(cmd, sizeof cmd, "cp %s %s", q1, q2), sizeof cmd))
        return 2;
    int code = 0;
    char dump[256];
    rc = capture_cmd(cmd, dump, sizeof dump, &code);
    if (rc) return rc;
    if (code != 0)
        return die("z23-lint: cp of the catalog fixture failed\n", "");

    static struct wag_paths declared;
    declared.n = 0;
    rc = wag_catalog_sources(catfull_src, &declared);
    if (rc) return rc;
    for (int i = 0; rc == 0 && i < declared.n; i++) {
        char full[4096], stem[512];
        rc = wags_full(d, declared.v[i], full, sizeof full);
        if (rc == 0) rc = wags_mkparents(full);
        if (rc == 0) rc = wags_stem(declared.v[i], stem, sizeof stem);
        if (rc == 0) rc = wags_write_guarded(full, stem);
    }
    return rc;
}

static int wags_capture(const char *root, char *buf, size_t cap, int *rc)
{
    fflush(stdout);
    fflush(stderr);
    FILE *tf = tmpfile();
    if (!tf) return die("z23-lint: tmpfile failed\n", "");
    int tfd = fileno(tf);
    int saved_out = dup(STDOUT_FILENO);
    int saved_err = dup(STDERR_FILENO);
    if (saved_out < 0 || saved_err < 0)
        return die("z23-lint: dup failed\n", "");
    dup2(tfd, STDOUT_FILENO);
    dup2(tfd, STDERR_FILENO);
    *rc = wag_scan_root(root, tf);
    fflush(stdout);
    fflush(stderr);
    dup2(saved_out, STDOUT_FILENO);
    dup2(saved_err, STDERR_FILENO);
    close(saved_out);
    close(saved_err);
    int sr = csr_slurp(tf, buf, cap);
    fclose(tf);
    return sr;
}

static int wags_expect_green(const char *label, const char *d, int *fails)
{
    static char buf[WAGS_OUT];
    int rc = 0;
    if (wags_capture(d, buf, sizeof buf, &rc)) return 2;
    if (rc != 0) {
        fprintf(stderr, "check-windows-acceptance-guard: SELFTEST FAILED "
               "— %s (expected a PASS, got exit %d)\n%s\n", label, rc, buf);
        (*fails)++;
        return 0;
    }
    printf("  selftest ok (GREEN): %s\n", label);
    return 0;
}

static int wags_expect_red(const char *label, const char *needle,
                           const char *d, int *fails)
{
    static char buf[WAGS_OUT];
    int rc = 0;
    if (wags_capture(d, buf, sizeof buf, &rc)) return 2;
    if (rc == 0) {
        fprintf(stderr, "check-windows-acceptance-guard: SELFTEST FAILED "
               "— %s (expected a RED, got a PASS)\n", label);
        (*fails)++;
        return 0;
    }
    if (!strstr(buf, needle)) {
        fprintf(stderr, "check-windows-acceptance-guard: SELFTEST FAILED "
               "— %s (went red but never named '%s')\n%s\n", label, needle,
               buf);
        (*fails)++;
        return 0;
    }
    printf("  selftest ok (RED): %s\n", label);
    return 0;
}

static int wags_case_regression(const char *repo_root, const char *d,
                                int *fails)
{
    (void)repo_root;
    static struct wag_paths declared;
    declared.n = 0;
    char catfull[4096];
    if (ovf(snprintf(catfull, sizeof catfull, "%s/%s", d, k_wag_catalog_rel),
            sizeof catfull))
        return 2;
    int rc = wag_catalog_sources(catfull, &declared);
    if (rc || declared.n == 0) {
        fprintf(stderr, "SELF-TEST FAIL: catalog produced no tests/ source "
               "to mutate\n");
        (*fails)++;
        return rc;
    }
    const char *p = declared.v[0];
    char full[4096];
    rc = wags_full(d, p, full, sizeof full);
    if (rc) return rc;
    rc = csr_write(full, "/* Fixture Copyright header. */\n\n"
                        "#include <stdio.h>\n\n"
                        "int main(void)\n{\n    return 0;\n}\n");
    if (rc) return rc;
    rc = wags_expect_red("2. an unguarded main() (the b562857bc shape) is "
                         "caught and named", p, d, fails);
    if (rc) return rc;
    char stem[512];
    rc = wags_stem(p, stem, sizeof stem);
    if (rc) return rc;
    rc = wags_write_guarded(full, stem);
    if (rc) return rc;
    rc = wags_expect_green("3. restoring the guard restores the pass", d,
                           fails);
    if (rc) return rc;

    rc = csr_write(full, "/* Fixture Copyright header. */\n"
                        "#if defined(_WIN32)\n"
                        "#include <stdio.h>\n"
                        "int main(void) { return 0; }\n");
    if (rc) return rc;
    rc = wags_expect_red("4. a missing '#else ... #endif' tail is caught",
                         "guarded but the last non-comment line is not "
                         "'#endif'", d, fails);
    if (rc) return rc;
    return wags_write_guarded(full, stem);
}

static int wags_case_stray(const char *d, int *fails)
{
    char rel[128], full[4096];
    if (ovf(snprintf(rel, sizeof rel, "%s/stray_undeclared_windows_"
                     "acceptance.c", k_wag_harness_dir_rel), sizeof rel))
        return 2;
    int rc = wags_full(d, rel, full, sizeof full);
    if (rc) return rc;
    rc = wags_mkparents(full);
    if (rc) return rc;
    rc = csr_write(full, "int main(void) { return 0; }\n");
    if (rc) return rc;
    rc = wags_expect_red("5. an undeclared stray *_windows_acceptance.c is "
                         "caught by the glob", rel, d, fails);
    unlink(full);
    if (rc) return rc;
    rc = csr_write(full, "#include <stdio.h>\nint fixture_helper(void) "
                        "{ return 0; }\n");
    if (rc) return rc;
    rc = wags_expect_green("6. an unguarded file that defines no main() "
                           "passes", d, fails);
    unlink(full);
    return rc;
}

static int wags_write_floor_catalog(const char *path)
{
    char body[4096];
    size_t used = 0;
    int k = snprintf(body + used, sizeof body - used,
                     "ZCL_WINDOWS_ACCEPTANCE_TESTS := \\\n"
                     "\tf1 \\\n\tf2 \\\n\tf3 \\\n\tf4 \\\n\tf5 \\\n\tf6 "
                     "\\\n\tf7\n");
    if (ovf(k, sizeof body - used)) return 2;
    used += (size_t)k;
    for (int i = 1; i <= 7; i++) {
        k = snprintf(body + used, sizeof body - used,
                    "ZCL_WINDOWS_ACCEPTANCE_f%d_SOURCES := \\\n"
                    "\t%s/f%d_windows_acceptance.c \\\n"
                    "\tplatform/modules/platform/src/subject.c\n",
                    i, k_wag_harness_dir_rel, i);
        if (ovf(k, sizeof body - used)) return 2;
        used += (size_t)k;
    }
    return csr_write(path, body);
}

static int wags_case_floor(const char *d, int *fails)
{
    char catfull[4096];
    if (ovf(snprintf(catfull, sizeof catfull, "%s/%s", d, k_wag_catalog_rel),
            sizeof catfull))
        return 2;
    int rc = wags_mkparents(catfull);
    if (rc) return rc;
    rc = wags_write_floor_catalog(catfull);
    if (rc) return rc;
    for (int i = 1; i <= 7; i++) {
        char rel[128], full[4096], stem[64];
        if (ovf(snprintf(rel, sizeof rel, "%s/f%d_windows_acceptance.c",
                         k_wag_harness_dir_rel, i), sizeof rel))
            return 2;
        rc = wags_full(d, rel, full, sizeof full);
        if (rc == 0) rc = wags_mkparents(full);
        if (rc == 0) {
            if (ovf(snprintf(stem, sizeof stem, "f%d_windows_acceptance", i),
                    sizeof stem))
                return 2;
            rc = wags_write_guarded(full, stem);
        }
        if (rc) return rc;
    }
    return wags_expect_red("7. a scan below the floor of 8 refuses (exit 2)",
                           "floor", d, fails);
}

int check_windows_acceptance_guard_selftest(void)
{
    char repo_root[4096];
    int rc = cic_repo_root(repo_root, sizeof repo_root);
    if (rc) return rc;
    const char *scratch = env_or("ZCL_WINDOWS_ACCEPTANCE_GUARD_SCRATCH", "");
    char scratch_buf[4096];
    if (!scratch[0]) {
        const char *home = env_or("HOME", "");
        if (!home[0])
            return die("z23-lint: HOME is not set\n", "");
        if (ovf(snprintf(scratch_buf, sizeof scratch_buf,
                         "%s/.local/state/zclassic23/scratch", home),
                sizeof scratch_buf))
            return 2;
        scratch = scratch_buf;
    }
    rc = csr_mkdirs(scratch);
    if (rc) return rc;
    char tmpl[4096];
    if (ovf(snprintf(tmpl, sizeof tmpl,
                     "%s/windows-acceptance-guard-selftest.XXXXXX", scratch),
            sizeof tmpl))
        return 2;
    char *fixture_root = mkdtemp(tmpl);
    if (!fixture_root)
        return die("z23-lint: mkdir failed: %s\n", tmpl);

    char good[4096];
    int fails = 0;
    rc = ovf(snprintf(good, sizeof good, "%s/good", fixture_root),
            sizeof good);
    if (rc == 0) rc = csr_mkdirs(good);
    if (rc == 0) rc = wags_build_good(repo_root, good);
    if (rc == 0)
        rc = wags_expect_green("1. the real catalog with every declared TU "
                               "correctly guarded passes", good, &fails);
    if (rc == 0) rc = wags_case_regression(repo_root, good, &fails);
    if (rc == 0) rc = wags_case_stray(good, &fails);

    char floor_dir[4096];
    if (rc == 0
        && ovf(snprintf(floor_dir, sizeof floor_dir, "%s/floor",
                        fixture_root), sizeof floor_dir))
        rc = 2;
    if (rc == 0) rc = csr_mkdirs(floor_dir);
    if (rc == 0) rc = wags_case_floor(floor_dir, &fails);

    rap_rm_rf(fixture_root);
    if (rc) return rc;
    if (fails) return 1;
    return st_ok(0, "══ check-windows-acceptance-guard self-test: PASS "
                    "(7/7) — this gate is proven able to go red ══\n");
}
