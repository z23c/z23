/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: --selftest for check-lint-gate-wiring (gate_lint_gate_wiring.c).
 * Builds a scratch fixture tree carrying the REAL run_lint.sh and
 * lint_cache.sh (so --list and --print-command are the code under test,
 * not a mock) stripped of its real case table, plants one defect per case
 * (A-G) and asserts lgw_check_root() rejects it and names the offender,
 * then a positive control (H) that a correctly wired fixture passes.
 * Sandbox lives under getenv("TMPDIR") else "test-tmp", never /tmp.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "lintc.h"
#include "gate_lint_gate_wiring_priv.h"

enum { LGWS_BUF = 1 << 20 };

static int lgws_copy(const char *root, const char *rel, const char *dst_dir)
{
    char src[4096], dst[4096];
    if (ovf(snprintf(src, sizeof src, "%s/%s", root, rel), sizeof src)
        || ovf(snprintf(dst, sizeof dst, "%s/%s", dst_dir, rel), sizeof dst))
        return 2;
    FILE *f = fopen(src, "r");
    if (!f)
        return die("z23-lint: cannot open %s\n", src);
    static char buf[LGWS_BUF];
    size_t n = fread(buf, 1, sizeof buf - 1, f);
    int bad = ferror(f);
    fclose(f);
    if (bad)
        return die("z23-lint: read failed: %s\n", src);
    buf[n] = '\0';
    return csr_write(dst, buf);
}

/* Strips every existing case-table entry line so only the sentinels the
 * caller wires in are visible — otherwise every real gate would read as an
 * orphan in the fixture. Matches the SAME pattern --list's own self-grep
 * uses: 8-space indent, "check-<name>)", whitespace, "echo". */
/* True for a line matching --list's own self-grep: 8-space indent,
 * "check-<name>)", whitespace, "echo". */
static int lgws_is_table_line(const char *p)
{
    if (strncmp(p, "        check-", 14) != 0)
        return 0;
    const char *q = p + 14;
    while (*q && (islower((unsigned char)*q) || isdigit((unsigned char)*q) || *q == '-'))
        q++;
    if (q[0] != ')')
        return 0;
    while (*q == ' ' || *q == '\t' || *q == ')')
        q++;
    return strncmp(q, "echo", 4) == 0;
}
static int lgws_strip_table(char *text)
{
    static char out[LGWS_BUF];
    size_t used = 0;
    char *save = NULL;
    for (char *ln = strtok_r(text, "\n", &save); ln; ln = strtok_r(NULL, "\n", &save)) {
        if (lgws_is_table_line(ln))
            continue;
        size_t ll = strlen(ln);
        if (used + ll + 2 >= sizeof out)
            return die("z23-lint: fixture buffer overflow\n", "");
        memcpy(out + used, ln, ll);
        used += ll;
        out[used++] = '\n';
    }
    out[used] = '\0';
    memcpy(text, out, used + 1);
    return 0;
}

static int lgws_seed_dirs(const char *d)
{
    char toollint[4096], toolscripts[4096];
    if (ovf(snprintf(toollint, sizeof toollint, "%s/tools/lint/.keep", d), sizeof toollint)
        || ovf(snprintf(toolscripts, sizeof toolscripts, "%s/tools/scripts/.keep", d),
              sizeof toolscripts))
        return 2;
    return csr_write(toollint, "") || csr_write(toolscripts, "");
}
static int lgws_strip_driver(const char *d)
{
    char driver[4096];
    if (ovf(snprintf(driver, sizeof driver, "%s/tools/lint/run_lint.sh", d), sizeof driver))
        return 2;
    FILE *f = fopen(driver, "r");
    if (!f) return die("z23-lint: cannot open %s\n", driver);
    static char text[LGWS_BUF];
    size_t n = fread(text, 1, sizeof text - 1, f);
    int bad = ferror(f);
    fclose(f);
    if (bad) return die("z23-lint: read failed: %s\n", driver);
    text[n] = '\0';
    if (lgws_strip_table(text)) return 2;
    if (csr_write(driver, text)) return 2;
    return chmod(driver, 0700) != 0 ? die("z23-lint: chmod failed: %s\n", driver) : 0;
}
static int lgws_write_sentinels(const char *d)
{
    char sa[4096], sb[4096];
    if (ovf(snprintf(sa, sizeof sa, "%s/tools/lint/sentinel_a.sh", d), sizeof sa)
        || ovf(snprintf(sb, sizeof sb, "%s/tools/lint/sentinel_b.sh", d), sizeof sb))
        return 2;
    return csr_write(sa, "") || csr_write(sb, "");
}
static int lgws_make_fixture(const char *repo_root, const char *d)
{
    if (lgws_seed_dirs(d)) return 2;
    if (lgws_copy(repo_root, "tools/lint/run_lint.sh", d)) return 2;
    if (lgws_copy(repo_root, "tools/lint/lint_cache.sh", d)) return 2;
    if (lgws_strip_driver(d)) return 2;
    return lgws_write_sentinels(d);
}

static int lgws_write_makefile(const char *d, const char *const *gates, int n)
{
    static char body[LGWS_BUF];
    size_t used = 0;
    if (lgw_appendf_pub(body, sizeof body, &used, "LINT_GATES := \\\n"))
        return 2;
    for (int i = 0; i < n; i++) {
        const char *sep = (i == n - 1) ? "\n" : " \\\n";
        if (lgw_appendf_pub(body, sizeof body, &used, "    %s%s", gates[i], sep))
            return 2;
    }
    if (lgw_appendf_pub(body, sizeof body, &used, "\n"))
        return 2;
    for (int i = 0; i < n; i++)
        if (lgw_appendf_pub(body, sizeof body, &used, "%s:\n\t@true\n", gates[i]))
            return 2;
    char path[4096];
    if (ovf(snprintf(path, sizeof path, "%s/Makefile", d), sizeof path))
        return 2;
    return csr_write(path, body);
}

/* Inserts one case entry right before the driver's own `*) return 1 ;;`
 * default arm — the exact anchor the shell selftest used. */
static int lgws_wire(const char *d, const char *gate, const char *cmd)
{
    char driver[4096];
    if (ovf(snprintf(driver, sizeof driver, "%s/tools/lint/run_lint.sh", d), sizeof driver))
        return 2;
    FILE *f = fopen(driver, "r");
    if (!f) return die("z23-lint: cannot open %s\n", driver);
    static char text[LGWS_BUF];
    size_t n = fread(text, 1, sizeof text - 1, f);
    int bad = ferror(f);
    fclose(f);
    if (bad) return die("z23-lint: read failed: %s\n", driver);
    text[n] = '\0';
    const char *anchor = "        *) return 1 ;;";
    char *pos = strstr(text, anchor);
    if (!pos) return die("z23-lint: fixture driver has no default arm\n", "");
    static char merged[LGWS_BUF];
    size_t prelen = (size_t)(pos - text);
    int k = snprintf(merged, sizeof merged, "%.*s        %s)   echo '%s' ;;\n%s",
                     (int)prelen, text, gate, cmd, pos);
    if (ovf(k, sizeof merged)) return 2;
    if (csr_write(driver, merged)) return 2;
    return chmod(driver, 0700) != 0 ? die("z23-lint: chmod failed: %s\n", driver) : 0;
}

static int lgws_expect_reject(const char *label, const char *needle, const char *d,
                              int *fails)
{
    char path[4096];
    if (ovf(snprintf(path, sizeof path, "%s/.out", d), sizeof path)) return 2;
    FILE *o = fopen(path, "w+");
    if (!o) return die("z23-lint: cannot open %s\n", path);
    int rc = lgw_check_root(d, o);
    static char captured[LGWS_BUF];
    if (csr_slurp(o, captured, sizeof captured)) { fclose(o); return 2; }
    fclose(o);
    if (rc != 1) {
        fprintf(stderr, "SELFTEST FAIL: %s — expected exit 1, got %d.\n%s\n", label, rc,
               captured);
        (*fails)++;
        return 0;
    }
    if (!strstr(captured, needle)) {
        fprintf(stderr,
               "SELFTEST FAIL: %s — rejected, but never named '%s'.\n%s\n", label, needle,
               captured);
        (*fails)++;
        return 0;
    }
    printf("  selftest ok: %s\n", label);
    return 0;
}
static int lgws_expect_accept(const char *label, const char *d, int *fails)
{
    char path[4096];
    if (ovf(snprintf(path, sizeof path, "%s/.out", d), sizeof path)) return 2;
    FILE *o = fopen(path, "w+");
    if (!o) return die("z23-lint: cannot open %s\n", path);
    int rc = lgw_check_root(d, o);
    static char captured[LGWS_BUF];
    if (csr_slurp(o, captured, sizeof captured)) { fclose(o); return 2; }
    fclose(o);
    if (rc != 0) {
        fprintf(stderr, "SELFTEST FAIL: %s — expected a PASS, got %d.\n%s\n", label, rc,
               captured);
        (*fails)++;
        return 0;
    }
    printf("  selftest ok: %s\n", label);
    return 0;
}

static int lgws_case_a(const char *base, int *fails)
{
    char d[4096];
    if (ovf(snprintf(d, sizeof d, "%s/a", base), sizeof d)) return 2;
    if (csr_mkdirs(d)) return 2;
    char root[4096];
    if (cic_repo_root(root, sizeof root)) return 2;
    if (lgws_make_fixture(root, d)) return 2;
    const char *gates[] = { "check-sentinel-wired", "check-sentinel-unwired" };
    if (lgws_write_makefile(d, gates, 2)) return 2;
    if (lgws_wire(d, "check-sentinel-wired", "./tools/lint/sentinel_a.sh")) return 2;
    return lgws_expect_reject("A: a listed gate with no case-table entry is caught",
                              "check-sentinel-unwired", d, fails);
}
static int lgws_case_b(const char *base, int *fails)
{
    char d[4096];
    if (ovf(snprintf(d, sizeof d, "%s/b", base), sizeof d)) return 2;
    if (csr_mkdirs(d)) return 2;
    char root[4096];
    if (cic_repo_root(root, sizeof root)) return 2;
    if (lgws_make_fixture(root, d)) return 2;
    const char *gates[] = { "check-sentinel-wired" };
    if (lgws_write_makefile(d, gates, 1)) return 2;
    if (lgws_wire(d, "check-sentinel-wired", "./tools/lint/sentinel_a.sh")) return 2;
    if (lgws_wire(d, "check-sentinel-orphan", "./tools/lint/sentinel_b.sh")) return 2;
    return lgws_expect_reject("B: a case-table entry no gate list names is caught",
                              "check-sentinel-orphan", d, fails);
}
static int lgws_case_c(const char *base, int *fails)
{
    char d[4096];
    if (ovf(snprintf(d, sizeof d, "%s/c", base), sizeof d)) return 2;
    if (csr_mkdirs(d)) return 2;
    char root[4096];
    if (cic_repo_root(root, sizeof root)) return 2;
    if (lgws_make_fixture(root, d)) return 2;
    const char *gates[] = { "check-sentinel-wired" };
    if (lgws_write_makefile(d, gates, 1)) return 2;
    if (lgws_wire(d, "check-sentinel-wired", "./tools/lint/sentinel_a.sh")) return 2;
    if (lgws_wire(d, "check-sentinel-notgt", "./tools/lint/sentinel_b.sh")) return 2;
    char mpath[4096];
    if (ovf(snprintf(mpath, sizeof mpath, "%s/Makefile", d), sizeof mpath)) return 2;
    if (csr_write(mpath,
                  "LINT_GATES := \\\n"
                  "    check-sentinel-wired \\\n"
                  "    check-sentinel-notgt\n\n"
                  "check-sentinel-wired:\n\t@true\n"))
        return 2;
    return lgws_expect_reject("C: a listed gate with no Make target is caught",
                              "check-sentinel-notgt", d, fails);
}
static int lgws_case_d(const char *base, int *fails)
{
    char d[4096];
    if (ovf(snprintf(d, sizeof d, "%s/d", base), sizeof d)) return 2;
    if (csr_mkdirs(d)) return 2;
    char root[4096];
    if (cic_repo_root(root, sizeof root)) return 2;
    if (lgws_make_fixture(root, d)) return 2;
    const char *gates[] = { "check-sentinel-wired" };
    if (lgws_write_makefile(d, gates, 1)) return 2;
    if (lgws_wire(d, "check-sentinel-wired", "./tools/lint/does_not_exist.sh")) return 2;
    return lgws_expect_reject("D: a case entry naming a missing script is caught",
                              "does_not_exist.sh", d, fails);
}
static int lgws_case_e(const char *base, int *fails)
{
    char d[4096];
    if (ovf(snprintf(d, sizeof d, "%s/e", base), sizeof d)) return 2;
    if (csr_mkdirs(d)) return 2;
    char root[4096];
    if (cic_repo_root(root, sizeof root)) return 2;
    if (lgws_make_fixture(root, d)) return 2;
    char mpath[4096];
    if (ovf(snprintf(mpath, sizeof mpath, "%s/Makefile", d), sizeof mpath)) return 2;
    if (csr_write(mpath, "# no gate list here at all\n")) return 2;
    return lgws_expect_reject("E: an empty/unparseable LINT_GATES fails closed",
                              "LINT_GATES is empty", d, fails);
}
static int lgws_case_f(const char *base, int *fails)
{
    char d[4096];
    if (ovf(snprintf(d, sizeof d, "%s/f", base), sizeof d)) return 2;
    if (csr_mkdirs(d)) return 2;
    char root[4096];
    if (cic_repo_root(root, sizeof root)) return 2;
    if (lgws_make_fixture(root, d)) return 2;
    const char *gates[] = { "check-sentinel-wired" };
    if (lgws_write_makefile(d, gates, 1)) return 2;
    if (lgws_wire(d, "check-sentinel-wired", "./tools/lint/sentinel_a.sh")) return 2;
    char lintc_dir[4096], hpath[4096], big[4096];
    if (ovf(snprintf(lintc_dir, sizeof lintc_dir, "%s/tools/lint/lintc", d), sizeof lintc_dir)
        || ovf(snprintf(hpath, sizeof hpath, "%s/lintc.h", lintc_dir), sizeof hpath)
        || ovf(snprintf(big, sizeof big, "%s/gate_big.c", lintc_dir), sizeof big))
        return 2;
    if (csr_write(hpath, "#define LINT_FAMILY_CEILING 1500\n")) return 2;
    static char padbuf[1 << 16];
    size_t used = 0;
    for (int i = 0; i < 1501; i++)
        if (lgw_appendf_pub(padbuf, sizeof padbuf, &used, "int pad;\n"))
            return 2;
    if (csr_write(big, padbuf)) return 2;
    return lgws_expect_reject("F: a family file over the ceiling is caught", "gate_big.c",
                              d, fails);
}
static int lgws_case_g(const char *base, int *fails)
{
    char d[4096];
    if (ovf(snprintf(d, sizeof d, "%s/g", base), sizeof d)) return 2;
    if (csr_mkdirs(d)) return 2;
    char root[4096];
    if (cic_repo_root(root, sizeof root)) return 2;
    if (lgws_make_fixture(root, d)) return 2;
    const char *gates[] = { "check-sentinel-wired" };
    if (lgws_write_makefile(d, gates, 1)) return 2;
    if (lgws_wire(d, "check-sentinel-wired", "./tools/lint/sentinel_a.sh")) return 2;
    char lintc_dir[4096], hpath[4096], small[4096];
    if (ovf(snprintf(lintc_dir, sizeof lintc_dir, "%s/tools/lint/lintc", d), sizeof lintc_dir)
        || ovf(snprintf(hpath, sizeof hpath, "%s/lintc.h", lintc_dir), sizeof hpath)
        || ovf(snprintf(small, sizeof small, "%s/gate_small.c", lintc_dir), sizeof small))
        return 2;
    if (csr_write(hpath, "/* no ceiling here */\n")) return 2;
    if (csr_write(small, "int small;\n")) return 2;
    return lgws_expect_reject("G: a lintc.h without LINT_FAMILY_CEILING fails closed",
                              "LINT_FAMILY_CEILING", d, fails);
}
static int lgws_case_h(const char *base, int *fails)
{
    char d[4096];
    if (ovf(snprintf(d, sizeof d, "%s/h", base), sizeof d)) return 2;
    if (csr_mkdirs(d)) return 2;
    char root[4096];
    if (cic_repo_root(root, sizeof root)) return 2;
    if (lgws_make_fixture(root, d)) return 2;
    const char *gates[] = { "check-sentinel-wired", "check-sentinel-unwired" };
    if (lgws_write_makefile(d, gates, 2)) return 2;
    if (lgws_wire(d, "check-sentinel-wired", "./tools/lint/sentinel_a.sh")) return 2;
    if (lgws_wire(d, "check-sentinel-unwired",
                  "./tools/lint/sentinel_b.sh --selftest && ./tools/lint/sentinel_b.sh"))
        return 2;
    return lgws_expect_accept("H: a fully wired tree passes (positive control)", d, fails);
}

/* run_lint.sh cd's to its own resolved root before self-grepping $0, so a
 * relative fixture path stops resolving the moment it does. Always hand it
 * an absolute one. */
static const char *lgws_absolutize(char *d0, char *scratch, size_t cap, int *rc)
{
    if (d0[0] == '/')
        return d0;
    char cwd[4096];
    if (!getcwd(cwd, sizeof cwd)) {
        *rc = die("z23-lint: getcwd failed\n", "");
        return d0;
    }
    if (ovf(snprintf(scratch, cap, "%s/%s", cwd, d0), cap)) {
        *rc = 2;
        return d0;
    }
    return scratch;
}

typedef int (*lgws_case_fn)(const char *, int *);
static const lgws_case_fn k_lgws_cases[] = {
    lgws_case_a, lgws_case_b, lgws_case_c, lgws_case_d,
    lgws_case_e, lgws_case_f, lgws_case_g, lgws_case_h,
};

int check_lint_gate_wiring_selftest(void)
{
    char base[4096];
    if (ovf(snprintf(base, sizeof base, "%s/z23-lint-gate-wiring-selftest.XXXXXX",
                     env_or("TMPDIR", "test-tmp")), sizeof base))
        return 2;
    if (csr_mkdirs(env_or("TMPDIR", "test-tmp")))
        return 2;
    char *d0 = mkdtemp(base);
    if (!d0)
        return die("z23-lint: mkdtemp failed: %s\n", base);
    static char abs0[4096];
    int rc = 0;
    d0 = (char *)lgws_absolutize(d0, abs0, sizeof abs0, &rc);
    if (rc)
        return rc;

    printf("\xe2\x95\x90\xe2\x95\x90 check-lint-gate-wiring selftest \xe2\x95\x90\xe2\x95\x90\n");
    int fails = 0;
    size_t ncases = sizeof k_lgws_cases / sizeof k_lgws_cases[0];
    for (size_t i = 0; rc == 0 && i < ncases; i++)
        rc = k_lgws_cases[i](d0, &fails);
    rap_rm_rf(d0);
    if (rc) return rc;
    if (fails) {
        printf("\xe2\x95\x90\xe2\x95\x90 selftest: FAIL \xe2\x95\x90\xe2\x95\x90\n");
        return 1;
    }
    printf("\xe2\x95\x90\xe2\x95\x90 selftest: PASS (8/8) \xe2\x95\x90\xe2\x95\x90\n");
    return 0;
}
