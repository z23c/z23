/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: native selftest for check-standalone-tools-link. Fixture
 * Makefiles and catalogs prove each reader accepts the real shapes and
 * fails closed on the damaged ones; the hermetic X11 policy suite stays in
 * gate_standalone_tools_link_x11_suite.c, which the gate runs itself.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include "lintc.h"
#include "gate_standalone_tools_link_priv.h"
#include "gate_standalone_tools_link_x11_suite.h"

int check_standalone_tools_link_run(int argc, char **argv);
static int stl_st_put(const char *dir, const char *name, const char *text);
static int stl_st_path(const char *dir, const char *name, char *out, size_t cap);
static int stl_st_expect(const char *what, int got, int want);

static void stl_st_jobs_child(int fd, const char *marker, const char *value,
                               const char *cap, int build_only, const char *mode)
{
    if (dup2(fd, STDOUT_FILENO) < 0 || dup2(fd, STDERR_FILENO) < 0) _exit(99);
    close(fd);
    if (setenv("TMPDIR", marker, 1)) _exit(99);
    if (value ? setenv("ZCL_TOOLS_LINK_JOBS", value, 1) : unsetenv("ZCL_TOOLS_LINK_JOBS")) _exit(99);
    if (cap ? setenv("ZCL_BUILD_MAX_JOBS", cap, 1) : unsetenv("ZCL_BUILD_MAX_JOBS")) _exit(99);
    unsetenv(k_stl_x11_nested);
    int rc = stl_build_phase(NULL, 0, build_only, mode, 0);
    fflush(stdout);
    fflush(stderr);
    _exit(rc);
}

/* A regular file as TMPDIR prevents any accidental baseline build. The
 * selected refusal must name the input, before scratch or helper work. */
static int stl_st_invalid_jobs_one(const char *dir, int build_only, const char *mode,
                                    const char *value, const char *cap, const char *needle)
{
    char marker[STL_PATH], log[STL_PATH];
    if (ovf(snprintf(marker, sizeof marker, "%s/jobs-not-dir", dir), sizeof marker) ||
        ovf(snprintf(log, sizeof log, "%s/jobs-refusal.log", dir), sizeof log)) return 1;
    if (csr_write(marker, "retained") != 0) return 1;
    int fd = open(log, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) return 1;
    pid_t pid = fork();
    if (pid == 0) stl_st_jobs_child(fd, marker, value, cap, build_only, mode);
    close(fd);
    if (pid < 0) return 1;
    int rc = stl_wait(pid);
    FILE *f = fopen(log, "r");
    if (!f) return 1;
    char text[STL_TEXT];
    size_t n = fread(text, 1, sizeof text - 1u, f);
    bool ok = !ferror(f);
    if (fclose(f) != 0) ok = false;
    text[n] = '\0';
    if (rc == 2 && ok && strstr(text, needle)) return 0;
    fprintf(stderr, "check-standalone-tools-link selftest: invalid workers must refuse2 before scratch/helpers (build_only=%d mode=%s got=%d): %s\n",
            build_only, mode, rc, text);
    return 1;
}

static int stl_st_invalid_jobs(const char *dir)
{
    static const struct { const char *value, *cap, *needle; } cases[] = {
        {"+1", NULL, "ZCL_TOOLS_LINK_JOBS"},
        {"", NULL, "ZCL_TOOLS_LINK_JOBS"},
        {"9999999999999999999999999", NULL, "ZCL_TOOLS_LINK_JOBS"},
        {"2", "1", "request 2 exceeds ZCL_BUILD_MAX_JOBS cap 1"},
        {NULL, "bad", "ZCL_BUILD_MAX_JOBS"}
    };
    int bad = 0;
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        bad |= stl_st_invalid_jobs_one(dir, 0, "FAIL", cases[i].value, cases[i].cap, cases[i].needle);
        bad |= stl_st_invalid_jobs_one(dir, 0, "WARN", cases[i].value, cases[i].cap, cases[i].needle);
        bad |= stl_st_invalid_jobs_one(dir, 1, "WARN", cases[i].value, cases[i].cap, cases[i].needle);
    }
    return bad;
}

static int stl_st_job_selection(void)
{
    static const struct {
        const char *value, *cap;
        int rc, jobs;
    } cases[] = {
        {NULL, NULL, 0, 4}, {NULL, "1", 0, 1}, {NULL, "2", 0, 2},
        {NULL, "4", 0, 4}, {NULL, "16", 0, 4}, {NULL, "4294967295", 0, 4},
        {"1", NULL, 0, 1}, {"2", NULL, 0, 2}, {"4", NULL, 0, 4},
        {"8", NULL, 0, 8}, {"16", NULL, 0, 16}, {"01", NULL, 0, 1},
        {"1", "1", 0, 1}, {"1", "2", 0, 1}, {"2", "2", 0, 2},
        {"3", "2", 2, -73}, {"16", "1", 2, -73}, {"", NULL, 2, -73},
        {"0", NULL, 2, -73}, {"-1", NULL, 2, -73}, {"+1", NULL, 2, -73},
        {" 1", NULL, 2, -73}, {"1 ", NULL, 2, -73}, {"1\n", NULL, 2, -73},
        {"1junk", NULL, 2, -73}, {"0x1", NULL, 2, -73}, {"17", NULL, 2, -73},
        {"4294967295", NULL, 2, -73}, {"4294967296", NULL, 2, -73},
        {"99999999999999999999999", NULL, 2, -73},
        {NULL, "", 2, -73}, {NULL, "0", 2, -73}, {NULL, "-1", 2, -73},
        {NULL, "+2", 2, -73}, {NULL, "2x", 2, -73}, {NULL, "4294967296", 2, -73}
    };
    int bad = 0;
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        int jobs = -73;
        int rc = stl_select_jobs(cases[i].value, cases[i].cap, &jobs);
        bad |= stl_st_expect("worker selector status", rc, cases[i].rc);
        bad |= stl_st_expect("worker selector exact count / unchanged error output", jobs, cases[i].jobs);
    }
    return bad;
}

static int stl_st_dispatch_log(const char *path, int jobs, int failure)
{
    FILE *f = fopen(path, "r");
    if (!f) return 1;
    unsigned seen = 0;
    int bad = 0, count = 0;
    char line[128], expected[128];
    static const char *const names[] = {"first", "bad", "last"};
    while (fgets(line, sizeof line, f)) {
        int found = -1;
        for (int i = 0; i < 3; i++) {
            snprintf(expected, sizeof expected, "%s:-j%d\n", names[i], jobs);
            if (strcmp(line, expected) == 0) found = i;
        }
        if (found < 0) { bad = 1; continue; }
        unsigned bit = 1u << (unsigned)found;
        if (seen & bit) bad = 1;
        seen |= bit;
        if (jobs == 1 && found != count && failure) bad = 1;
        count++;
    }
    if (ferror(f)) bad = 1;
    if (fclose(f) != 0) bad = 1;
    unsigned want = failure ? 7u : 5u;
    return bad || seen != want;
}

/* Real GNU Make, not a fake launcher: independent goals expose the exact
 * forwarded worker flag, and -k must still finish the final goal after bad. */
static void stl_st_make_child(int fd, const char *absolute, const char *value,
                               const char *cap, int failure)
{
    if (chdir(absolute) != 0 || dup2(fd, STDOUT_FILENO) < 0 || dup2(fd, STDERR_FILENO) < 0) _exit(99);
    close(fd);
    if (setenv("TMPDIR", absolute, 1)) _exit(99);
    if (value ? setenv("ZCL_TOOLS_LINK_JOBS", value, 1) : unsetenv("ZCL_TOOLS_LINK_JOBS")) _exit(99);
    if (cap ? setenv("ZCL_BUILD_MAX_JOBS", cap, 1) : unsetenv("ZCL_BUILD_MAX_JOBS")) _exit(99);
    unsetenv(k_stl_x11_nested);
    char targets[3][STL_TGT] = {"first", "bad", "last"};
    if (!failure) snprintf(targets[1], sizeof targets[1], "last");
    int rc = stl_build_phase(targets, failure ? 3 : 2, 1, "FAIL", 0);
    fflush(stdout);
    fflush(stderr);
    _exit(rc);
}

static int stl_st_make_case(const char *dir, const char *value, const char *cap,
                            int jobs, int failure)
{
    char cwd[STL_PATH], absolute[STL_PATH], log[STL_PATH], dispatch[STL_PATH];
    if (!getcwd(cwd, sizeof cwd)) return 1;
    int n = dir[0] == '/' ? snprintf(absolute, sizeof absolute, "%s", dir)
                          : snprintf(absolute, sizeof absolute, "%s/%s", cwd, dir);
    if (ovf(n, sizeof absolute) || stl_st_path(absolute, "batch.log", log, sizeof log) ||
        stl_st_path(absolute, "dispatch.log", dispatch, sizeof dispatch)) return 1;
    if (csr_write(dispatch, "") != 0) return 1;
    int fd = open(log, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) return 1;
    pid_t pid = fork();
    if (pid == 0) stl_st_make_child(fd, absolute, value, cap, failure);
    close(fd);
    if (pid < 0) return 1;
    int bad = stl_st_expect("real make failure remains gate violation", stl_wait(pid), failure ? 1 : 0);
    bad |= stl_st_expect("real make exact worker flag, fanout and keep-going", stl_st_dispatch_log(dispatch, jobs, failure), 0);
    return bad;
}

static int stl_st_make_jobs(const char *dir)
{
    int bad = stl_st_put(dir, "Makefile",
        ".PHONY: first bad last\n"
        "first last:\n"
        "\t@printf '%s:%s\\n' '$@' '$(filter -j%,$(MAKEFLAGS))' >>dispatch.log\n"
        "bad:\n"
        "\t@printf '%s:%s\\n' '$@' '$(filter -j%,$(MAKEFLAGS))' >>dispatch.log\n"
        "\t@false\n");
    if (bad) return bad;
    static const struct { const char *value, *cap; int jobs; } cases[] = {
        {"1", NULL, 1}, {"2", NULL, 2}, {NULL, NULL, 4},
        {NULL, "1", 1}, {NULL, "2", 2}
    };
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        bad |= stl_st_make_case(dir, cases[i].value, cases[i].cap, cases[i].jobs, 0);
        bad |= stl_st_make_case(dir, cases[i].value, cases[i].cap, cases[i].jobs, 1);
    }
    return bad;
}

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
    static const char ci[] = "fuzz-ci: check-fuzz-ci-tools $(FUZZ_TARGETS) $(BIN_DIR)/run-fuzz-ci\n";
    char text[512];
    int bad = 0;
    snprintf(text, sizeof text, "FUZZ_TARGETS = $(BIN_DIR)/fuzz_a $(BIN_DIR)/fuzz_b2\n%s", ci);
    bad |= stl_st_fuzz_one(dir, "fuzz good", text, 0);
    snprintf(text, sizeof text, "FUZZ_TARGETS = $(BIN_DIR)/fuzz_a $(BIN_DIR)/fuzz_b2\n"
                                "fuzz-ci: check-fuzz-ci-tools $(FUZZ_TARGETS)\n");
    bad |= stl_st_fuzz_one(dir, "fuzz list without the native runner refused", text, 2);
    snprintf(text, sizeof text, "FUZZ_TARGETS = $(BIN_DIR)/fuzz_a $(BIN_DIR)/fuzz_b2\n"
                                "fuzz-ci: check-fuzz-ci-tools $(FUZZ_TARGETS) $(BIN_DIR)/run-fuzz-ci extra\n");
    bad |= stl_st_fuzz_one(dir, "fuzz list with an extra prerequisite refused", text, 2);
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

#define STL_ANDROID_BIND "ANDROID_SNAPSHOT_RECOVERY_BIN = $(BIN_DIR)/android_snapshot_recovery\n"
#define STL_ANDROID_CAND "ANDROID_SNAPSHOT_RECOVERY_CANDIDATE = $(BIN_DIR)/test-fast/epochs/$(TEST_FAST_COMPILE_EPOCH)/android_snapshot_recovery\n"
#define STL_ANDROID_TARGET "android-snapshot-recovery-build: $(ANDROID_SNAPSHOT_RECOVERY_BIN)\n"
#define STL_ANDROID_RULE "$(ANDROID_SNAPSHOT_RECOVERY_BIN): $(ANDROID_SNAPSHOT_RECOVERY_CANDIDATE) FORCE\n"
#define STL_ANDROID_CAND_RULE "$(ANDROID_SNAPSHOT_RECOVERY_CANDIDATE): $(VIEW_GEN_HEADERS) $(BUILD_IDENTITY_STAMP) \\\n" "    $(TEST_PARALLEL_FAST_OBJS)\n"
#define STL_ANDROID_ALL STL_ANDROID_BIND STL_ANDROID_CAND STL_ANDROID_TARGET STL_ANDROID_RULE STL_ANDROID_CAND_RULE
static int stl_st_android(const char *dir)
{
    static const struct { const char *text; int expected; } cases[] = {
        { ("ifeq ($(ZCL_TARGET),android-arm64)\n" STL_ANDROID_ALL "endif\n"), 0 },
        { ("ifeq ($(ZCL_TARGET),android-arm64)\n" STL_ANDROID_BIND STL_ANDROID_CAND STL_ANDROID_RULE STL_ANDROID_CAND_RULE "endif\n"), 1 },
        { ("ifeq ($(ZCL_TARGET),android-arm64)\n" STL_ANDROID_BIND STL_ANDROID_CAND "android-snapshot-recovery-build: $(OTHER_BIN)\n" STL_ANDROID_RULE STL_ANDROID_CAND_RULE "endif\n"), 1 },
        { ("ifeq ($(ZCL_TARGET),android-arm64)\n  endif # closed\n" STL_ANDROID_ALL), 1 },
        { ("ifeq ($(ZCL_TARGET),android-arm64)\n ifdef OTHER # nested\n" STL_ANDROID_ALL "endif\nendif\n"), 1 },
        { ("ifeq (outer,yes)\nifeq ($(ZCL_TARGET),android-arm64)\n" STL_ANDROID_ALL "endif\nendif\n"), 1 },
        { ("override\t private  define EXAMPLE\nifeq ($(ZCL_TARGET),android-arm64)\n" STL_ANDROID_ALL "endif\nendef\n"), 1 },
        { ("define EXAMPLE\nifeq ($(ZCL_TARGET),android-arm64)\n" STL_ANDROID_ALL "endif\nendef\n"), 1 },
        { ("ifeq ($(ZCL_TARGET),android-arm64)\n" STL_ANDROID_BIND STL_ANDROID_TARGET STL_ANDROID_RULE STL_ANDROID_CAND_RULE "endif\n"), 1 },
        { ("ifeq ($(ZCL_TARGET),android-arm64)\n" STL_ANDROID_BIND "ANDROID_SNAPSHOT_RECOVERY_CANDIDATE = $(BIN_DIR)/wrong\n" STL_ANDROID_TARGET STL_ANDROID_RULE STL_ANDROID_CAND_RULE "endif\n"), 1 },
        { ("ifeq ($(ZCL_TARGET),android-arm64)\n" STL_ANDROID_BIND STL_ANDROID_CAND STL_ANDROID_TARGET STL_ANDROID_RULE "endif\n"), 1 },
        { ("ifeq ($(ZCL_TARGET),android-arm64)\nX = \\\n" STL_ANDROID_ALL "endif\n"), 1 },
        { ("ifeq ($(ZCL_TARGET),android-arm64)\n" STL_ANDROID_ALL), -1 },
    };
    char p[STL_PATH];
    if (stl_st_path(dir, "android.mk", p, sizeof p) != 0) return 1;
    int bad = 0;
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        bad |= stl_st_put(dir, "android.mk", cases[i].text);
        bad |= stl_st_expect("Android target binding", stl_android_covers(p), cases[i].expected);
    }
    return bad;
}
#undef STL_ANDROID_ALL
#undef STL_ANDROID_CAND_RULE
#undef STL_ANDROID_RULE
#undef STL_ANDROID_TARGET
#undef STL_ANDROID_CAND
#undef STL_ANDROID_BIND

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

/* An inherited nested marker naming some other tree must refuse, never skip. */
static int stl_st_nested(void)
{
    char *old = getenv(k_stl_x11_nested);
    char saved[STL_PATH] = "";
    if (old && ovf(snprintf(saved, sizeof saved, "%s", old), sizeof saved))
        saved[0] = 0;
    setenv(k_stl_x11_nested, "/nonexistent-stl-x11-root", 1);
    int bad = stl_st_expect("nested marker for another root refused",
                            stl_build_phase(NULL, 0, 1, "FAIL", 1), 2);
    if (old)
        setenv(k_stl_x11_nested, saved, 1);
    else
        unsetenv(k_stl_x11_nested);
    return bad;
}

/* Run the key with a fake `tool` first on PATH; returns the key ("" on failure). */
static void stl_st_key_with_fake(const char *dir, const char *tool, const char *oldpath,
                                 char *key, size_t cap)
{
    char bin[STL_PATH], f[STL_PATH], np[STL_PATH * 2];
    key[0] = '\0';
    if (ovf(snprintf(bin, sizeof bin, "%s/fake-%s", dir, tool), sizeof bin) ||
        ovf(snprintf(f, sizeof f, "%s/%s", bin, tool), sizeof f) ||
        ovf(snprintf(np, sizeof np, "%s:%s", bin, oldpath), sizeof np) ||
        csr_write(f, "#!/bin/sh\necho fake-tool-version\n") != 0 || chmod(f, 0755) != 0)
        return;
    setenv("PATH", np, 1);
    stl_x11_key_in(dir, key, cap);
    setenv("PATH", oldpath, 1);
}

static int stl_st_stamp_bytes(const char *path, const char *key, const char *bytes,
                               size_t len, int want, const char *what)
{
    FILE *f = fopen(path, "wb");
    if (!f) return stl_st_expect("stamp fixture open", 1, 0);
    int bad = fwrite(bytes, 1, len, f) != len;
    if (fclose(f) != 0) bad = 1;
    if (bad) return stl_st_expect("stamp fixture write", 1, 0);
    return stl_st_expect(what, stl_stamp_hit(key, path, 1), want);
}

static int stl_st_stamp_contents(const char *dir)
{
    static const char key[] =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    char path[STL_PATH], bytes[256];
    if (stl_st_path(dir, "contents.stamp", path, sizeof path)) return 1;
    memset(bytes, '\n', sizeof bytes);
    memcpy(bytes, key, sizeof key - 1);
    int bad = stl_st_stamp_bytes(path, key, bytes, 64, 1, "stamp exact bytes hit");
    bad |= stl_st_stamp_bytes(path, key, bytes, 65, 1, "stamp newline hit");
    bad |= stl_st_stamp_bytes(path, key, bytes, 128, 1, "stamp bounded newlines hit");
    bad |= stl_st_stamp_bytes(path, key, bytes, 63, 0, "stamp short key misses");
    bad |= stl_st_stamp_bytes(path, key, bytes, 0, 0, "stamp empty file misses");
    bytes[64] = '\0';
    bytes[65] = 'x';
    bad |= stl_st_stamp_bytes(path, key, bytes, 66, 0, "stamp embedded NUL suffix misses");
    memset(bytes + 64, '\n', sizeof bytes - 64);
    bytes[sizeof bytes - 1] = 'x';
    bad |= stl_st_stamp_bytes(path, key, bytes, sizeof bytes, 0, "stamp unread suffix misses");
    bytes[sizeof bytes - 1] = '\n';
    bad |= stl_st_stamp_bytes(path, key, bytes, sizeof bytes, 0, "stamp oversized file misses");
    return bad;
}

/* The X11 selftest stamp: the key follows make and bash, a nested fixture run
 * never touches the shared stamp, a matching shared stamp is a hit. */
static int stl_st_stamp(const char *dir)
{
    char k0[128], k1[128], k2[128], k3[128], sh[STL_PATH], local[STL_PATH], xdg[STL_PATH];
    char oldpath[STL_PATH * 2] = "", oldxdg[STL_PATH] = "";
    const char *p = getenv("PATH"), *x = getenv("XDG_CACHE_HOME");
    int had_xdg = x != NULL, bad = 0;
    if (!p || ovf(snprintf(oldpath, sizeof oldpath, "%s", p), sizeof oldpath) ||
        (x && ovf(snprintf(oldxdg, sizeof oldxdg, "%s", x), sizeof oldxdg)) ||
        ovf(snprintf(xdg, sizeof xdg, "%s/xdg", dir), sizeof xdg) ||
        ovf(snprintf(local, sizeof local, "%s/absent.stamp", dir), sizeof local))
        return stl_st_expect("stamp env", 1, 0);
    stl_x11_key_in(dir, k0, sizeof k0);
    stl_x11_key_in(dir, k3, sizeof k3);
    stl_st_key_with_fake(dir, "make", oldpath, k1, sizeof k1);
    stl_st_key_with_fake(dir, "bash", oldpath, k2, sizeof k2);
    bad |= stl_st_expect("stamp key available", strlen(k0) == 64, 1);
    bad |= stl_st_expect("stamp key stable", strcmp(k0, k3) == 0, 1);
    bad |= stl_st_expect("stamp key follows make", strlen(k1) == 64 && strcmp(k0, k1) != 0, 1);
    bad |= stl_st_expect("stamp key follows bash", strlen(k2) == 64 && strcmp(k0, k2) != 0, 1);
    setenv("XDG_CACHE_HOME", xdg, 1);
    bad |= stl_st_expect("stamp shared path", stl_shared_stamp_for(k0, 0, sh, sizeof sh), 0);
    bad |= stl_st_expect("stamp nested has no shared path",
                         stl_shared_stamp_for(k0, 1, sh, sizeof sh), -1);
    bad |= stl_st_expect("stamp miss before write", stl_stamp_hit(k0, local, 0), 0);
    if (stl_shared_stamp_for(k0, 0, sh, sizeof sh) == 0)
        bad |= stl_st_expect("stamp write", csr_write(sh, k0), 0);
    bad |= stl_st_expect("stamp shared hit", stl_stamp_hit(k0, local, 0), 1);
    bad |= stl_st_expect("stamp changed key misses", stl_stamp_hit(k1, local, 0), 0);
    bad |= stl_st_expect("stamp nested ignores shared", stl_stamp_hit(k0, local, 1), 0);
    bad |= stl_st_expect("stamp read error is a miss", stl_stamp_file_has(dir, ""), 0);
    if (had_xdg)
        setenv("XDG_CACHE_HOME", oldxdg, 1);
    else
        unsetenv("XDG_CACHE_HOME");
    return bad;
}

int check_standalone_tools_link_selftest(void)
{
    char dir[STL_PATH];
    char *bogus[] = { (char *)"--bogus" };
    if (stl_mkdtemp(dir, sizeof dir, "z23-lint-stl-selftest") != 0)
        return st_ok(1, "check_standalone_tools_link selftest: no scratch directory\n");
    int bad = stl_st_invalid_jobs(dir);
    bad |= stl_st_job_selection();
    bad |= stl_st_make_jobs(dir);
    bad |= stl_st_scan(dir);
    bad |= stl_st_fuzz(dir);
    bad |= stl_st_catalog(dir);
    bad |= stl_st_android(dir);
    bad |= stl_st_link_log(dir);
    bad |= stl_st_nested();
    bad |= stl_st_stamp(dir);
    bad |= stl_st_stamp_contents(dir);
    bad |= stl_st_expect("unknown argument is fatal",
                         check_standalone_tools_link_run(1, bogus), 2);
    rap_rm_rf(dir);
    return st_ok(bad, "check_standalone_tools_link selftest: OK\n");
}
