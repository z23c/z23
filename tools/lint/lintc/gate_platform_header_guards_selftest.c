// Copyright 2026 Rhett Creighton - Apache License 2.0
//
// purpose: --selftest for check-platform-header-guards. Builds a minimal
// but real fixture tree (LIB_SRCS host branch, Windows acceptance catalog,
// padding sources) per case and proves each failure class once: the literal
// macho defect, the positive control, wrong-platform guard, #else frames in
// both directions, a closed guard, comments, __has_include, build-exclusive
// files in both directions, an unparseable Makefile block, and a hollowed
// scan set. Fixtures live outside the repository, never inside it.

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "lintc.h"
#include "gate_platform_header_guards_priv.h"

static const char k_phgs_mk[] =
    "LIB_SRCS = $(wildcard platform/modules/*/src/*.c)\n"
    "ifneq ($(filter Linux,$(ZCL_HOST_OS)),)\n"
    "LIB_SRCS := $(filter-out platform/modules/platform/src/os_sandbox_stub.c,$(LIB_SRCS))\n"
    "else ifeq ($(ZCL_HOST_WINDOWS),1)\n"
    "LIB_SRCS := $(filter-out platform/modules/platform/src/os_sandbox_linux.c,$(LIB_SRCS))\n"
    "else\n"
    "LIB_SRCS := $(filter-out platform/modules/platform/src/os_sandbox_linux.c,$(LIB_SRCS))\n"
    "endif\n";

static const char k_phgs_pad[] =
    "#include <stdio.h>\n"
    "#if defined(__linux__)\n"
    "#include <sys/epoll.h>\n"
    "#endif\n";

struct phgs_case {
    const char *name, *needle, *probe, *sandbox, *mk;
    int drop_util, reject;
    const char *cat_tail;
};

static const struct phgs_case k_phgs_cases[] = {
    { "A: an unguarded <mach-o/fat.h> is caught", "mach-o/fat.h",
      "#include <stdio.h>\n#include <mach-o/fat.h>\n", NULL, NULL, 0, 1, NULL },
    { "B: the same include under #if defined(__APPLE__) passes", NULL,
      "#include <stdio.h>\n#if defined(__APPLE__)\n#include <mach-o/fat.h>\n#endif\n",
      NULL, NULL, 0, 0, NULL },
    { "C: <mach-o/fat.h> guarded by the Windows macro is caught",
      "mach-o/fat.h",
      "#include <stdio.h>\n#if defined(_WIN32)\n#include <mach-o/fat.h>\n#endif\n",
      NULL, NULL, 0, 1, NULL },
    { "D: an Apple header in the #else of #ifdef __APPLE__ is caught",
      "mach-o/fat.h",
      "#include <stdio.h>\n#ifdef __APPLE__\n#include <stdlib.h>\n#else\n#include <mach-o/fat.h>\n#endif\n",
      NULL, NULL, 0, 1, NULL },
    { "E: the #else of #ifndef __APPLE__ counts as the Apple branch", NULL,
      "#include <stdio.h>\n#ifndef __APPLE__\n#include <stdlib.h>\n#else\n#include <mach-o/fat.h>\n#endif\n",
      NULL, NULL, 0, 0, NULL },
    { "F: a closed __APPLE__ block earlier in the file does not cover a later include",
      "mach-o/fat.h",
      "#include <stdio.h>\n#if defined(__APPLE__)\n#define HOST_IS_APPLE 1\n#endif\n#include <mach-o/fat.h>\n",
      NULL, NULL, 0, 1, NULL },
    { "G: a header named inside a comment is not a finding", NULL,
      "#include <stdio.h>\n/* On Apple this would need #include <mach-o/fat.h>; it does not here. */\n",
      NULL, NULL, 0, 0, NULL },
    { "H: __has_include(<H>) around #include <H> passes", NULL,
      "#include <stdio.h>\n#if defined(__has_include)\n#  if __has_include(<linux/landlock.h>)\n#    include <linux/landlock.h>\n#  endif\n#endif\n",
      NULL, NULL, 0, 0, NULL },
    { "I: a Linux-exclusive source needs no __linux__ guard", NULL, NULL,
      "#include <stdio.h>\n#include <sys/epoll.h>\n", NULL, 0, 0, NULL },
    { "J: a Linux-exclusive source is still graded for Apple headers",
      "mach-o/fat.h", NULL,
      "#include <stdio.h>\n#include <mach-o/fat.h>\n", NULL, 0, 1, NULL },
    { "K: an unparseable LIB_SRCS host branch fails closed",
      "could not read the LIB_SRCS per-host branch", NULL, NULL,
      "LIB_SRCS = $(wildcard platform/modules/*/src/*.c)\n", 0, 1, NULL },
    { "M: a catalog line ending in a bare tests/<name> is not read past its end",
      NULL, NULL, NULL, NULL, 0, 0,
      "ZCL_WINDOWS_ACCEPTANCE_bare := platform/modules/platform/tests/bare\n" },
    { "L: an emptied scan set fails closed", "FATAL", NULL, NULL, NULL, 1, 1, NULL },
};

// Write content to <d>/<rel>.
static int phgs_put(const char *d, const char *rel, const char *content)
{
    char p[PHG_PATH];
    if (ovf(snprintf(p, sizeof p, "%s/%s", d, rel), sizeof p))
        return 2;
    return csr_write(p, content);
}

static int phgs_mkdirs(const char *d)
{
    const char *dirs[] = { "platform/modules/util/src",
                           "platform/modules/platform/src",
                           "platform/modules/platform/tests" };
    char p[PHG_PATH];
    for (size_t i = 0; i < 3; i++) {
        if (ovf(snprintf(p, sizeof p, "%s/%s", d, dirs[i]), sizeof p))
            return 2;
        int rc = csr_mkdirs(p);
        if (rc)
            return rc;
    }
    return 0;
}

// The Windows acceptance catalog and the twelve empty sources it names.
static int phgs_wincat(const char *d, const char *tail)
{
    char cat[4096], rel[PHG_PATH];
    size_t o = 0;
    for (int i = 1; i <= 12; i++)
        o += (size_t)snprintf(cat + o, sizeof cat - o,
                              "ZCL_WINDOWS_ACCEPTANCE_p%d_SOURCES := "
                              "platform/modules/platform/tests/p%d_windows_acceptance.c\n",
                              i, i);
    if (tail)
        o += (size_t)snprintf(cat + o, sizeof cat - o, "%s", tail);
    if (o >= sizeof cat)
        return 2;
    int rc = phgs_put(d, "platform/modules/platform/tests/windows_acceptance.mk",
                      cat);
    for (int i = 1; i <= 12 && !rc; i++) {
        if (ovf(snprintf(rel, sizeof rel, "platform/modules/platform/tests/"
                         "p%d_windows_acceptance.c", i), sizeof rel))
            return 2;
        rc = phgs_put(d, rel, "");
    }
    return rc;
}

static int phgs_pads(const char *d)
{
    char rel[PHG_PATH];
    for (int i = 1; i <= 8; i++) {
        if (ovf(snprintf(rel, sizeof rel, "platform/modules/util/src/pad%d.c",
                         i), sizeof rel))
            return 2;
        int rc = phgs_put(d, rel, k_phgs_pad);
        if (rc)
            return rc;
    }
    return 0;
}

static int phgs_fixture(const char *d, const struct phgs_case *c)
{
    char p[PHG_PATH];
    int rc = phgs_mkdirs(d);
    if (!rc)
        rc = phgs_put(d, "Makefile", c->mk ? c->mk : k_phgs_mk);
    if (!rc)
        rc = phgs_wincat(d, c->cat_tail);
    if (!rc)
        rc = phgs_pads(d);
    if (rc)
        return rc;
    if (c->drop_util) {
        if (ovf(snprintf(p, sizeof p, "%s/platform/modules/util/src", d),
                 sizeof p))
            return 2;
        return rap_rm_rf(p);
    }
    if (c->probe)
        rc = phgs_put(d, "platform/modules/util/src/probe.c", c->probe);
    if (!rc && c->sandbox)
        rc = phgs_put(d, "platform/modules/platform/src/os_sandbox_linux.c",
                      c->sandbox);
    return rc;
}

static void phgs_indent(const char *buf)
{
    for (const char *l = buf, *n; *l; l = n) {
        n = strchr(l, '\n');
        size_t len = n ? (size_t)(n - l) : strlen(l);
        printf("    %.*s\n", (int)len, l);
        if (!n)
            break;
        n++;
    }
}

// Run one case; selftest floors: src 10, cand 5, inc 10, seen 5, wincat 10.
static int phgs_run(const char *root, char letter, const struct phgs_case *c)
{
    char d[PHG_PATH];
    if (ovf(snprintf(d, sizeof d, "%s/%c", root, letter), sizeof d))
        return 2;
    int rc = phgs_fixture(d, c);
    if (rc)
        return rc;
    char *buf = NULL;
    size_t n = 0;
    FILE *f = open_memstream(&buf, &n);
    if (!f)
        return die("z23-lint: open_memstream failed\n", "");
    int got = phg_run_scan(d, 10, 5, 10, 5, 10, "quiet", f, f);
    fclose(f);
    int bad = 0;
    if (c->reject) {
        if (got == 0) {
            printf("SELFTEST FAIL: %s — expected rejection, got a PASS.\n",
                   c->name);
            bad = 1;
        } else if (c->needle && !strstr(buf ? buf : "", c->needle)) {
            printf("SELFTEST FAIL: %s — rejected, but never named '%s'.\n",
                   c->name, c->needle);
            printf("  A gate that fails without naming the offender is a "
                   "gate nobody can act on.\n");
            bad = 1;
        }
        if (!bad)
            printf("  selftest ok: %s\n", c->name);
    } else if (got != 0) {
        printf("SELFTEST FAIL: %s — expected a PASS, got rejection.\n",
               c->name);
        bad = 1;
    } else {
        printf("  selftest ok: %s\n", c->name);
    }
    if (bad && buf)
        phgs_indent(buf);
    free(buf);
    rap_rm_rf(d);
    return bad;
}

int check_platform_header_guards_selftest(void)
{
    char root[PHG_PATH];
    if (ovf(snprintf(root, sizeof root, "%s/z23-lint-platform-header-guards-selftest.XXXXXX",
                     env_or("TMPDIR", "/tmp")), sizeof root))
        return 2;
    if (!mkdtemp(root))
        return die("z23-lint: mkdtemp failed for selftest scratch\n", "");
    printf("══ check-platform-header-guards selftest ══\n");
    int rc = 0;
    const char letters[] = "abcdefghijklm";
    for (size_t i = 0; i < sizeof k_phgs_cases / sizeof k_phgs_cases[0]; i++)
        if (phgs_run(root, letters[i], &k_phgs_cases[i]))
            rc = 1;
    rap_rm_rf(root);
    if (rc == 0)
        printf("══ selftest: PASS (13/13) ══\n");
    else
        printf("══ selftest: FAIL ══\n");
    return rc;
}
