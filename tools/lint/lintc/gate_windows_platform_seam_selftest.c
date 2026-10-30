/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: --selftest for check-windows-platform-seam
 * (gate_windows_platform_seam.c). Builds a fixture tree under
 * $HOME/.local/state/zclassic23/scratch (never a bare /tmp path): a fixture
 * Makefile with the Windows API floor, the platform defines and the
 * host-OS guard around LIB_SRCS; a seam directory with one exempt and
 * eight in-scope files; fifteen module include roots; and a baseline.
 * The fake compiler is "cat": it runs (so the tool is observed) but its
 * flag error output matches no diagnostic line, so every in-scope file
 * scores zero sites — which is exactly what the clean, improvement,
 * missing-baseline, UNOBSERVED and fail-closed cases need. A baseline
 * count below the live count is the one honest way to drive the
 * regression branch without a real mingw toolchain.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "lintc.h"

/* Modes mirrored from gate_windows_platform_seam.c; only SCAN (0) is used. */
#define WS2_SCAN 0

int wps_check_root(const char *root, FILE *out, FILE *err, int mode);
int check_windows_platform_seam_run(int argc, char **argv);

enum { WS2_PATH = 1024, WS2_NINC = 15 };

struct ws2_case {
    const char *name;
    int makefile;   /* 0 normal, 1 no host-OS guard, 2 no _WIN32_WINNT floor,
                       3 platform flags without the floor reference */
    int baseline;   /* 0 empty, 1 lists b.c with 2, 2 lists b.c with -1,
                       3 missing file */
    const char *cc; /* fake compiler to install as ZCL_MINGW_CC */
    int require;    /* 1 sets ZCL_REQUIRE_MINGW=1 */
    int want;       /* expected return of wps_check_root */
};

static const struct ws2_case k_ws2_cases[] = {
    { "clean fixture passes", 0, 0, "cat", 0, 0 },
    { "baseline improvement is noted, not fatal", 0, 1, "cat", 0, 0 },
    { "empty exemption parse fails closed", 1, 0, "cat", 0, 1 },
    { "missing _WIN32_WINNT floor fails", 2, 0, "cat", 0, 1 },
    { "platform flags without floor reference fail", 3, 0, "cat", 0, 1 },
    { "missing baseline is fatal", 0, 3, "cat", 0, 2 },
    { "absent compiler is UNOBSERVED, not a pass", 0, 0,
      "/nonexistent/z23-lint-no-such-cc", 0, 0 },
    { "absent required compiler fails acceptance", 0, 0,
      "/nonexistent/z23-lint-no-such-cc", 1, 2 },
    { "baseline count below live count is a regression", 0, 2, "cat", 0, 1 },
};

static const char *const k_ws2_names[] = {
    "a.c", "b.c", "c.c", "d.c", "e.c", "f.c", "g.c", "h.c",
};

static int ws2_write_makefile(const char *root, int variant)
{
    static const char normal[] =
        "ZCL_WINDOWS_API_FLOOR := -D_WIN32_WINNT=0x0601\n"
        "ZCL_PLATFORM_CPPFLAGS = -DZCL_PLAT $(ZCL_WINDOWS_API_FLOOR) \\\n"
        " -DZCL_PLAT2\n"
        "ifeq ($(ZCL_HOST_OS),Linux)\n"
        "LIB_SRCS += platform/modules/platform/src/os_sandbox_linux.c\n"
        "else\n"
        "LIB_SRCS := $(filter-out platform/modules/platform/src/os_sandbox_linux.c,$(LIB_SRCS))\n"
        "endif\n";
    static const char noguard[] =
        "ZCL_WINDOWS_API_FLOOR := -D_WIN32_WINNT=0x0601\n"
        "ZCL_PLATFORM_CPPFLAGS = -DZCL_PLAT $(ZCL_WINDOWS_API_FLOOR) \\\n"
        " -DZCL_PLAT2\n";
    static const char nowinnt[] =
        "ZCL_PLATFORM_CPPFLAGS = -DZCL_PLAT $(ZCL_WINDOWS_API_FLOOR) \\\n"
        " -DZCL_PLAT2\n"
        "ifeq ($(ZCL_HOST_OS),Linux)\n"
        "LIB_SRCS += platform/modules/platform/src/os_sandbox_linux.c\n"
        "else\n"
        "LIB_SRCS := $(filter-out platform/modules/platform/src/os_sandbox_linux.c,$(LIB_SRCS))\n"
        "endif\n";
    static const char noref[] =
        "ZCL_WINDOWS_API_FLOOR := -D_WIN32_WINNT=0x0601\n"
        "ZCL_PLATFORM_CPPFLAGS = -DZCL_PLAT \\\n"
        " -DZCL_PLAT2\n"
        "ifeq ($(ZCL_HOST_OS),Linux)\n"
        "LIB_SRCS += platform/modules/platform/src/os_sandbox_linux.c\n"
        "else\n"
        "LIB_SRCS := $(filter-out platform/modules/platform/src/os_sandbox_linux.c,$(LIB_SRCS))\n"
        "endif\n";
    const char *text = variant == 1   ? noguard
                       : variant == 2 ? nowinnt
                       : variant == 3 ? noref
                                      : normal;
    char path[WS2_PATH];
    if (ovf(snprintf(path, sizeof path, "%s/Makefile", root), sizeof path))
        return 2;
    return csr_write(path, text);
}

static int ws2_write_srcs(const char *root)
{
    char dir[WS2_PATH], path[WS2_PATH];
    size_t i;
    int rc;
    if (ovf(snprintf(dir, sizeof dir, "%s/platform/modules/platform/src", root),
            sizeof dir))
        return 2;
    rc = csr_mkdirs(dir);
    if (rc)
        return rc;
    for (i = 0; i < sizeof k_ws2_names / sizeof k_ws2_names[0]; i++) {
        if (ovf(snprintf(path, sizeof path, "%s/%s", dir, k_ws2_names[i]),
                sizeof path))
            return 2;
        rc = csr_write(path, "int zcl_ws2_fixture(void);\n");
        if (rc)
            return rc;
    }
    if (ovf(snprintf(path, sizeof path, "%s/os_sandbox_linux.c", dir),
            sizeof path))
        return 2;
    return csr_write(path, "int zcl_ws2_exempt(void);\n");
}

static int ws2_write_incs(const char *root)
{
    int i;
    for (i = 1; i <= WS2_NINC; i++) {
        char d[WS2_PATH];
        int rc;
        if (ovf(snprintf(d, sizeof d, "%s/core/modules/m%02d/include", root,
                         i),
                sizeof d))
            return 2;
        rc = csr_mkdirs(d);
        if (rc)
            return rc;
    }
    return 0;
}

static int ws2_write_baseline(const char *root, int variant)
{
    static const char empty[] = "# empty baseline\n";
    static const char two[] = "platform/modules/platform/src/b.c 2\n";
    static const char neg[] = "platform/modules/platform/src/b.c -1\n";
    const char *text = variant == 1 ? two : variant == 2 ? neg : empty;
    char dir[WS2_PATH], path[WS2_PATH];
    int rc;
    if (variant == 3)
        return 0;
    if (ovf(snprintf(dir, sizeof dir, "%s/tools/lint", root), sizeof dir))
        return 2;
    rc = csr_mkdirs(dir);
    if (rc)
        return rc;
    if (ovf(snprintf(path, sizeof path, "%s/windows_platform_seam_baseline.txt",
                     dir),
            sizeof path))
        return 2;
    return csr_write(path, text);
}

static int ws2_run_case(const char *root, const struct ws2_case *c)
{
    FILE *sink;
    int got, rc = ws2_write_makefile(root, c->makefile);
    if (rc == 0)
        rc = ws2_write_srcs(root);
    if (rc == 0)
        rc = ws2_write_incs(root);
    if (rc == 0)
        rc = ws2_write_baseline(root, c->baseline);
    if (rc) {
        fprintf(stderr,
                "check-windows-platform-seam selftest: fixture write failed"
                " for %s\n",
                c->name);
        return rc;
    }
    if (setenv("ZCL_MINGW_CC", c->cc, 1) != 0)
        return 2;
    if (c->require)
        (void)setenv("ZCL_REQUIRE_MINGW", "1", 1);
    else
        unsetenv("ZCL_REQUIRE_MINGW");
    sink = tmpfile();
    if (!sink)
        return 2;
    got = wps_check_root(root, sink, sink, WS2_SCAN);
    fclose(sink);
    unsetenv("ZCL_REQUIRE_MINGW");
    if (got != c->want) {
        fprintf(stderr,
                "check-windows-platform-seam selftest: %s: want rc=%d"
                " got rc=%d\n",
                c->name, c->want, got);
        return 1;
    }
    printf("  selftest ok: %s (rc=%d)\n", c->name, got);
    return 0;
}

static int ws2_case_root(const char *base, char *out, size_t cap)
{
    if (ovf(snprintf(out, cap, "%s/case", base), cap))
        return 2;
    rap_rm_rf(out);
    return csr_mkdirs(out);
}

static int ws2_scratch_base(char *out, size_t cap)
{
    char base[WS2_PATH];
    const char *home = getenv("HOME");
    if (!home || !home[0]) {
        fprintf(stderr,
                "z23-lint: HOME unset; cannot place selftest scratch\n");
        return 2;
    }
    if (ovf(snprintf(base, sizeof base,
                     "%s/.local/state/zclassic23/scratch", home),
            sizeof base))
        return 2;
    if (csr_mkdirs(base))
        return 2;
    if (ovf(snprintf(out, cap, "%s/z23-lint-win-seam.XXXXXX", base), cap))
        return 2;
    if (!mkdtemp(out)) {
        fprintf(stderr, "z23-lint: mkdtemp failed for selftest scratch\n");
        return 2;
    }
    return 0;
}

/* The two variables the cases overwrite, saved and restored so the real
 * compiler probe that follows sees the caller's environment. */
static char ws2_saved_req[64], ws2_saved_cc[WS2_PATH];
static int ws2_has_req, ws2_has_cc;

static void ws2_save_env(void)
{
    const char *r = getenv("ZCL_REQUIRE_MINGW");
    const char *c = getenv("ZCL_MINGW_CC");
    ws2_has_req = r && strlen(r) < sizeof ws2_saved_req;
    ws2_has_cc = c && strlen(c) < sizeof ws2_saved_cc;
    if (ws2_has_req)
        strcpy(ws2_saved_req, r);
    if (ws2_has_cc)
        strcpy(ws2_saved_cc, c);
}

static void ws2_restore_env(void)
{
    if (ws2_has_req)
        (void)setenv("ZCL_REQUIRE_MINGW", ws2_saved_req, 1);
    else
        unsetenv("ZCL_REQUIRE_MINGW");
    if (ws2_has_cc)
        (void)setenv("ZCL_MINGW_CC", ws2_saved_cc, 1);
    else
        unsetenv("ZCL_MINGW_CC");
}

static int ws2_run_cases(const char *base)
{
    char root[WS2_PATH];
    int bad = 0;
    size_t i;
    for (i = 0; i < sizeof k_ws2_cases / sizeof k_ws2_cases[0]; i++) {
        if (ws2_case_root(base, root, sizeof root))
            return 1;
        bad |= ws2_run_case(root, &k_ws2_cases[i]) != 0;
    }
    return bad;
}

int check_windows_platform_seam_selftest(void)
{
    char base[WS2_PATH];
    char *probe_argv[] = {"--self-test", NULL};
    int bad, rc = ws2_scratch_base(base, sizeof base);
    if (rc)
        return rc;
    ws2_save_env();
    bad = ws2_run_cases(base);
    ws2_restore_env();
    rap_rm_rf(base);
    if (bad) {
        fputs("FAIL: check-windows-platform-seam selftest\n", stderr);
        return 1;
    }
    printf("check-windows-platform-seam selftest: OK\n");
    /* The original --self-test: the real cross-compiler must reject a
     * POSIX-only translation unit and accept a clean one. */
    return check_windows_platform_seam_run(1, probe_argv);
}
