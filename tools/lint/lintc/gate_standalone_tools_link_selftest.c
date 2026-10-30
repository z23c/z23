/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: native selftest for check-standalone-tools-link. Fixture
 * Makefiles and catalogs prove each reader accepts the real shapes and
 * fails closed on the damaged ones; the hermetic X11 policy suite stays in
 * tools/lint/selftest_standalone_tools_x11.sh, which the gate runs itself.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <stdio.h>
#include <string.h>
#include "lintc.h"
#include "gate_standalone_tools_link_priv.h"

int check_standalone_tools_link_run(int argc, char **argv);

static int stl_st_put(const char *dir, const char *name, const char *text)
{
    char p[STL_PATH];
    if (ovf(snprintf(p, sizeof p, "%s/%s", dir, name), sizeof p))
        return 1;
    return csr_write(p, text) != 0;
}

static int stl_st_path(const char *dir, const char *name, char *out, size_t cap)
{
    return ovf(snprintf(out, cap, "%s/%s", dir, name), cap);
}

static int stl_st_expect(const char *what, int got, int want)
{
    if (got == want)
        return 0;
    fprintf(stderr, "check-standalone-tools-link selftest: %s: got %d, want %d\n",
            what, got, want);
    return 1;
}

static int stl_st_scan(const char *dir)
{
    static struct stl_names t;
    char p[STL_PATH];
    int bad = stl_st_put(dir, "scan.mk",
        "BIN_DIR = build/bin\n"
        "FOO_BIN = $(BIN_DIR)/beta  \n"
        "CAND = $(BIN_DIR)/sub/x\n"
        "EP = $(BIN_DIR)/$(E)\n"
        "NOPE = other\n"
        "FOO_BIN = $(BIN_DIR)/late\n"
        "$(BIN_DIR)/alpha: dep\n"
        "$(BIN_DIR)/dot.exe:\n"
        "$(BIN_DIR)/bad/sub:\n"
        "$(FOO_BIN): dep\n"
        "$(CAND): dep\n"
        "$(EP): dep\n"
        "$(NOPE): dep\n"
        "$(lower): dep\n"
        "\t$(BIN_DIR)/indented:\n");
    bad |= stl_st_path(dir, "scan.mk", p, sizeof p);
    t.count = 0;
    bad |= stl_st_expect("scan rc", stl_scan_makefile(p, &t), 0);
    bad |= stl_st_expect("scan count", t.count, 3);
    bad |= stl_st_expect("scan alpha", stl_names_has(&t, "alpha"), 1);
    bad |= stl_st_expect("scan dot.exe", stl_names_has(&t, "dot.exe"), 1);
    bad |= stl_st_expect("scan first var definition wins", stl_names_has(&t, "beta"), 1);
    bad |= stl_st_expect("scan later definition ignored", stl_names_has(&t, "late"), 0);
    bad |= stl_st_expect("scan subdir skipped", stl_names_has(&t, "sub/x"), 0);
    bad |= stl_st_expect("scan unreadable", stl_scan_makefile("/nonexistent/Makefile", &t), 2);
    return bad;
}

static int stl_st_fuzz_one(const char *dir, const char *what, const char *text, int want)
{
    static struct stl_names fz;
    char p[STL_PATH];
    fz.count = 0;
    if (stl_st_put(dir, "fuzz.mk", text) || stl_st_path(dir, "fuzz.mk", p, sizeof p))
        return 1;
    return stl_st_expect(what, stl_load_fuzz(p, &fz), want);
}

static int stl_st_fuzz(const char *dir)
{
    static const char ci[] = "fuzz-ci: check-fuzz-ci-tools $(FUZZ_TARGETS)\n";
    char text[512];
    int bad = 0;
    snprintf(text, sizeof text, "FUZZ_TARGETS = $(BIN_DIR)/fuzz_a $(BIN_DIR)/fuzz_b2\n%s", ci);
    bad |= stl_st_fuzz_one(dir, "fuzz good", text, 0);
    snprintf(text, sizeof text, "FUZZ_TARGETS = $(BIN_DIR)/fuzz_a # note\n%s", ci);
    bad |= stl_st_fuzz_one(dir, "fuzz comment refused", text, 2);
    snprintf(text, sizeof text, "FUZZ_TARGETS = $(BIN_DIR)/fuzz_a\nFUZZ_TARGETS += $(BIN_DIR)/fuzz_b\n%s", ci);
    bad |= stl_st_fuzz_one(dir, "fuzz second assignment refused", text, 2);
    snprintf(text, sizeof text, "FUZZ_TARGETS = $(BIN_DIR)/notfuzz\n%s", ci);
    bad |= stl_st_fuzz_one(dir, "fuzz bad token refused", text, 2);
    snprintf(text, sizeof text, "FUZZ_TARGETS = $(BIN_DIR)/fuzz_\n%s", ci);
    bad |= stl_st_fuzz_one(dir, "fuzz bare prefix refused", text, 2);
    bad |= stl_st_fuzz_one(dir, "fuzz-ci missing refused",
                           "FUZZ_TARGETS = $(BIN_DIR)/fuzz_a\n", 2);
    bad |= stl_st_fuzz_one(dir, "fuzz-ci changed refused",
                           "FUZZ_TARGETS = $(BIN_DIR)/fuzz_a\nfuzz-ci: $(FUZZ_TARGETS)\n", 2);
    bad |= stl_st_fuzz_one(dir, "FUZZ_TARGETS missing refused", ci, 2);
    return bad;
}

static int stl_st_catalog(const char *dir)
{
    char p[STL_PATH];
    int bad = stl_st_put(dir, "win.mk",
        "# ZCL_WINDOWS_ACCEPTANCE_TESTS := fake\n"
        "# ZCL_WINDOWS_ACCEPTANCE_fake_SOURCES := tools/fake.c\n"
        "ZCL_WINDOWS_ACCEPTANCE_TESTS := one \\\n"
        "    two\n"
        "ZCL_WINDOWS_ACCEPTANCE_two_SOURCES := tools/a.c \\\n"
        "    tools/b.c\n"
        "ZCL_WINDOWS_ACCEPTANCE_one_SOURCES := tools/c.c\n");
    bad |= stl_st_path(dir, "win.mk", p, sizeof p);
    bad |= stl_st_expect("catalog covered", stl_windows_covers(p, "two", "tools/b.c"), 0);
    bad |= stl_st_expect("catalog single", stl_windows_covers(p, "one", "tools/c.c"), 0);
    bad |= stl_st_expect("catalog wrong source", stl_windows_covers(p, "one", "tools/b.c"), 2);
    bad |= stl_st_expect("catalog row not listed", stl_windows_covers(p, "three", "tools/c.c"), 1);
    bad |= stl_st_expect("catalog comment row not counted", stl_windows_covers(p, "fake", "tools/fake.c"), 1);
    bad |= stl_st_expect("catalog unreadable", stl_windows_covers("/nonexistent/win.mk", "one", "x"), -1);
    return bad;
}

static int stl_st_link_log(const char *dir)
{
    int bad = stl_st_put(dir, "link.log", "ld: internal error\n");
    bad |= stl_st_expect("link generic error unproven", stl_x11_link_check(dir), 2);
    bad |= stl_st_put(dir, "link.log",
        "/usr/bin/ld: cannot find -l:libX11.so.6: No such file or directory\n"
        "/usr/bin/ld: cannot find -l:libX11.so.6: No such file or directory\n");
    bad |= stl_st_expect("link repeated diagnostic unproven", stl_x11_link_check(dir), 2);
    bad |= stl_st_put(dir, "link.log", "collect2: error: ld returned 1 exit status\n");
    bad |= stl_st_expect("link without SONAME diagnostic unproven", stl_x11_link_check(dir), 2);
    return bad;
}

int check_standalone_tools_link_selftest(void)
{
    char dir[STL_PATH];
    char *bogus[] = { (char *)"--bogus" };
    if (stl_mkdtemp(dir, sizeof dir, "z23-lint-stl-selftest") != 0)
        return st_ok(1, "check_standalone_tools_link selftest: no scratch directory\n");
    int bad = stl_st_scan(dir);
    bad |= stl_st_fuzz(dir);
    bad |= stl_st_catalog(dir);
    bad |= stl_st_link_log(dir);
    bad |= stl_st_expect("unknown argument is fatal",
                         check_standalone_tools_link_run(1, bogus), 2);
    rap_rm_rf(dir);
    return st_ok(bad, "check_standalone_tools_link selftest: OK\n");
}
