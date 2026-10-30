/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: gate - every standalone tool binary the Makefile knows how to
 * build must actually BUILD. `make lint`, `make test-parallel` and `make ci`
 * between them build the node, the test runners, the fuzzers and two lint
 * helpers, so every other $(BIN_DIR)/<tool> rule was reachable from no gate
 * and rotted silently (six standalone rules broke at once when logging and
 * allocation moved behind forwarding headers). The tool list is DERIVED from
 * the Makefile, fail-closed; the exempt tables below carry a reason per
 * entry, and CI fuzz exemptions are derived from the validated fuzz-ci
 * dependencies. Modes: the plain gate, --build-only (link every covered tool
 * and stop, no verdict) and --list-targets (print the covered targets).
 * Mode WARN | FAIL comes from ZCL_LINT_MODE (default FAIL).
 * Ported from tools/lint/check_standalone_tools_link.sh (deleted); the
 * Makefile readers live in _scan.c, the X11 probe in _x11.c, the build phase
 * in _build.c and the native selftest in _selftest.c.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "lintc.h"
#include "gate_standalone_tools_link_priv.h"

struct stl_pair { const char *name, *reason; };

/* A tool belongs here ONLY if an existing gate already builds it, or building
 * it needs something outside the base toolchain. Reason is mandatory. */
static const struct stl_pair k_exempt[] = {
    { "gen_templates", "built by every build (TMPL_GEN prerequisite)" },
    { "core_seal", "built by make lint (check-core-sealed)" },
    { "check_observability_pairing", "built by make lint (check-observability-pairing)" },
    { "crash_recovery_test", "built by make ci (test-crash)" },
    { "zcl-rpc", "built by make ci (test-crash)" },
    { "zclassic23-dev-asan", "sanitizer whole-node relink (make dev-asan)" },
    { "zclassic23-dev-tsan", "sanitizer whole-node relink (make dev-tsan)" },
    { "z23-dev-asan", "sanitizer whole-node relink (make dev-asan)" },
    { "z23-dev-tsan", "sanitizer whole-node relink (make dev-tsan)" },
    { "test_zcl", "whole-test relink (make test-parallel)" },
    { "z23-package-verify", "node-profile verifier relink (built by product and CI targets)" },
    { "z23-package-verify-dev", "dev companion links the whole dev object graph" },
    { "test_parallel", "built by make test-parallel" },
    { "test_parallel_fast", "built by make t-fast" },
    { "test-asan", "sanitizer whole-test relink (make test-asan)" },
    { "test-tsan", "sanitizer whole-test relink (make test-tsan)" },
    { "test_zcl_cov", "coverage whole-test relink (make coverage, in make ci)" },
    { "session", "whole-node relink over $(ALL_SRCS) - minutes, not seconds" },
    { "bot", "whole-node relink over $(ALL_SRCS) - minutes, not seconds" },
    { "zcl-blog", "needs webkit2gtk-4.1 via pkg-config (not a base toolchain dep)" },
    { "arena_view", "optional raylib GUI; needs raylib via pkg-config (not a base toolchain dep)" },
    { "z23-clang-manifest", "optional semantic sensor; needs libclang's C API (libclang-NN-dev, not a base toolchain dep)" },
};

/* Host-bound: the kernel or runtime primitive underneath the tool does not
 * exist on that host. Consulted only when building on THAT host. */
static const struct stl_pair k_darwin[] = {
    { "tunnel-static", "Linux ELF static-PIE artifact; native Mach-O tunnel remains required" },
    { "zcl-portfwd", "event loop sits on sys/epoll.h (Linux kernel API)" },
    { "z23-headless-run.exe", "Win32 PE launcher; #include <windows.h> + -municode, and its rule is inside ifeq ($(ZCL_HOST_WINDOWS),1) so it does not exist on this host" },
    { "native_ui_driver", "X11 UI transport; links -Wl,-l:libX11.so.6" },
};

/* Windows-only tools: on a POSIX host the Makefile has NO RULE for them. An
 * exemption with no replacement check is exactly the rot this gate exists to
 * stop, so each entry names (row, source) that the windows acceptance catalog
 * must still cross-compile, and the exemption is refused (exit 2) the moment
 * that coverage stops being real. */
struct stl_winonly { const char *name, *reason, *cover; };
static const struct stl_winonly k_winonly[] = {
    { "z23-headless-run.exe",
      "rule body lives only inside ifeq ($(ZCL_HOST_WINDOWS),1); the else arm defines no $(BIN_DIR) target, so make has no rule for it on a POSIX host — covered instead by check-windows-acceptance, which mingw-cross-links the source (see COVER)",
      "headless_run tools/dev/windows_headless_run.c" },
};
static const char k_catalog[] = "platform/modules/platform/tests/windows_acceptance.mk";

struct stl_host { int darwin, linux_os, windows; };

static const char *stl_pair_find(const struct stl_pair *t, size_t n, const char *name)
{
    for (size_t i = 0; i < n; i++)
        if (strcmp(t[i].name, name) == 0)
            return t[i].reason;
    return NULL;
}

static int stl_exempt(const char *name, const struct stl_names *fuzz)
{
    return stl_pair_find(k_exempt, sizeof k_exempt / sizeof k_exempt[0], name) ||
           stl_names_has(fuzz, name);
}

static int stl_exempt_count(const struct stl_names *fuzz)
{
    int n = (int)(sizeof k_exempt / sizeof k_exempt[0]);
    for (int i = 0; i < fuzz->count; i++)
        if (!stl_pair_find(k_exempt, sizeof k_exempt / sizeof k_exempt[0], fuzz->n[i]))
            n++;
    return n;
}

static void stl_host_detect(struct stl_host *h)
{
    char os[64];
    int code = 0;
    memset(h, 0, sizeof *h);
    if (capture_cmd("uname -s 2>/dev/null", os, sizeof os, &code) != 0 || code != 0)
        os[0] = '\0';
    h->darwin = strcmp(os, "Darwin") == 0;
    h->linux_os = strcmp(os, "Linux") == 0;
    h->windows = strncmp(os, "MINGW", 5) == 0 || strncmp(os, "MSYS", 4) == 0;
}

static int stl_cover_fatal(const char *name, const char *row, const char *src, int rc)
{
    fprintf(stderr, "%s: FATAL — %s is exempt here\n"
            "  because %s was supposed to keep\n"
            "  cross-compiling %s for Windows as row\n"
            "  '%s', and it no longer does:\n", k_stl_gate, name, k_catalog, src, row);
    if (rc == 1)
        fprintf(stderr, "    '%s' is not in ZCL_WINDOWS_ACCEPTANCE_TESTS,\n"
                "    so no make rule is generated and the SOURCES row is\n"
                "    inert — nothing compiles it.\n", row);
    else
        fprintf(stderr, "    ZCL_WINDOWS_ACCEPTANCE_%s_SOURCES does not\n"
                "    name %s (comment mentions do not count).\n", row, src);
    fputs("  The exemption has outlived its replacement check: nothing\n"
          "  on this host compiles that source any more, which is the\n"
          "  silent rot this gate exists to stop. Restore the catalog\n"
          "  row, or drop the exemption and give the tool a rule make\n"
          "  can build here.\n", stderr);
    return 2;
}

/* 0 = exempt on this host (replacement check confirmed), 2 = refused. */
static int stl_winonly_skip(const struct stl_winonly *w)
{
    char row[STL_NAME];
    const char *sp = strchr(w->cover, ' '), *src = strrchr(w->cover, ' ');
    if (!sp || sp == w->cover || sp != src || (size_t)(sp - w->cover) >= sizeof row) {
        fprintf(stderr, "%s: FATAL — %s is in\n"
                "  WINDOWS_ONLY_EXEMPT with no usable WINDOWS_ONLY_COVER\n"
                "  entry (expected \"<catalog row> <source path>\").\n"
                "  An exemption with no named replacement check is the rot\n"
                "  this gate exists to stop. Name the source another gate\n"
                "  still compiles, or delete the exemption.\n", k_stl_gate, w->name);
        return 2;
    }
    memcpy(row, w->cover, (size_t)(sp - w->cover));
    row[sp - w->cover] = '\0';
    src++;
    if (access(k_catalog, F_OK) != 0) {
        fprintf(stderr, "%s: FATAL — the windows acceptance\n"
                "  catalog %s is missing, so the\n"
                "  replacement check backing the %s exemption cannot be\n"
                "  confirmed to exist. Refusing to skip on an unproven claim.\n",
                k_stl_gate, k_catalog, w->name);
        return 2;
    }
    int rc = stl_windows_covers(k_catalog, row, src);
    if (rc != 0)
        return stl_cover_fatal(w->name, row, src, rc);
    fprintf(stderr, "[check_standalone_tools_link] windows-only-exempt %s: %s\n"
            "[check_standalone_tools_link]   replacement check CONFIRMED: %s row '%s' "
            "cross-compiles %s (make check-windows-acceptance)\n",
            w->name, w->reason, k_catalog, row, src);
    return 0;
}

static const struct stl_winonly *stl_winonly_find(const char *name)
{
    for (size_t i = 0; i < sizeof k_winonly / sizeof k_winonly[0]; i++)
        if (strcmp(k_winonly[i].name, name) == 0)
            return &k_winonly[i];
    return NULL;
}

enum { STL_BUILD = 0, STL_SKIP = 1, STL_FATAL = 2 };

/* Host-specific exemption of one non-exempt tool: STL_BUILD to build it. */
static int stl_host_route(const char *name, const struct stl_host *h)
{
    const char *why = h->darwin
        ? stl_pair_find(k_darwin, sizeof k_darwin / sizeof k_darwin[0], name) : NULL;
    if (why) {
        fprintf(stderr, "[check_standalone_tools_link] darwin-exempt %s: %s\n", name, why);
        return STL_SKIP;
    }
    if (h->linux_os && strcmp(name, "native_ui_driver") == 0) {
        /* Probe only this Linux tool; inherited env cannot manufacture an exemption. */
        int rc = stl_x11_linkable();
        if (rc == 1) {
            fprintf(stderr, "[check_standalone_tools_link] no-x11-runtime-exempt %s: "
                    "SONAME absent; canonical strict object compiled\n", name);
            return STL_SKIP;
        }
        if (rc != 0) {
            fprintf(stderr, "%s: FATAL - X11 runtime qualification failed\n", k_stl_gate);
            return STL_FATAL;
        }
    }
    const struct stl_winonly *w = stl_winonly_find(name);
    if (w && !h->windows)
        return stl_winonly_skip(w) == 0 ? STL_SKIP : STL_FATAL;
    return STL_BUILD;
}

static int stl_cmp(const void *a, const void *b)
{
    return strcmp((const char *)a, (const char *)b);
}

/* Partition the sorted tool list into covered (built) and exempt. */
static int stl_partition(struct stl_names *tools, const struct stl_names *fuzz,
                         const struct stl_host *h, char (*tg)[STL_TGT], int *nt)
{
    qsort(tools->n, (size_t)tools->count, STL_NAME, stl_cmp);
    *nt = 0;
    for (int i = 0; i < tools->count; i++) {
        const char *name = tools->n[i];
        if (h->darwin && strncmp(name, "fuzz_", 5) == 0 && !stl_exempt(name, fuzz)) {
            fprintf(stderr, "%s: FATAL — unclassified Darwin fuzz target %s\n",
                    k_stl_gate, name);
            return 2;
        }
        if (stl_exempt(name, fuzz))
            continue;
        int r = stl_host_route(name, h);
        if (r == STL_FATAL)
            return 2;
        if (r == STL_BUILD)
            snprintf(tg[(*nt)++], STL_TGT, "build/bin/%s", name);
    }
    return 0;
}

static int stl_parse_args(int argc, char **argv, int *build_only, int *list)
{
    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--build-only") == 0)
            *build_only = 1;
        else if (strcmp(argv[i], "--list-targets") == 0)
            *list = 1;
        else {
            fprintf(stderr, "%s: unknown argument '%s'\n", k_stl_gate, argv[i]);
            return 2;
        }
    }
    return 0;
}

static int stl_to_root(void)
{
    char root[STL_PATH];
    return cic_repo_root(root, sizeof root) != 0 || chdir(root) != 0 ? 2 : 0;
}

/* Derive the covered list: scan, validate fuzz-ci, partition, anti-hollow. */
static int stl_derive(struct stl_names *tools, struct stl_names *fuzz,
                      char (*tg)[STL_TGT], int *nt)
{
    struct stl_host host;
    int rc = stl_scan_makefile("Makefile", tools);
    if (rc == 0)
        rc = gate_require_scanned(tools->count, 20, k_stl_gate,
                                  "no $(BIN_DIR)/<tool> rules found in Makefile — did the rule spelling change?");
    if (rc == 0)
        rc = stl_load_fuzz("Makefile", fuzz);
    if (rc != 0)
        return rc;
    stl_host_detect(&host);
    rc = stl_partition(tools, fuzz, &host, tg, nt);
    if (rc != 0)
        return rc;
    /* The failure mode guarded: the exempt set quietly growing until the gate
     * builds almost nothing while still reporting clean. */
    return gate_require_scanned(*nt, 10, k_stl_gate,
                                "the exempt set has swallowed the gate — it is no longer proving anything");
}

int check_standalone_tools_link_run(int argc, char **argv)
{
    static struct stl_names tools, fuzz;
    static char tg[STL_MAX][STL_TGT];
    int build_only = 0, list = 0, nt = 0;
    setvbuf(stdout, NULL, _IONBF, 0);
    if (stl_parse_args(argc, argv, &build_only, &list) != 0 || stl_to_root() != 0)
        return 2;
    tools.count = fuzz.count = 0;
    int rc = stl_derive(&tools, &fuzz, tg, &nt);
    if (rc != 0)
        return rc;
    if (list) {
        if (build_only)
            return 2;
        for (int i = 0; i < nt; i++)
            puts(tg[i]);
        return 0;
    }
    printf("[check_standalone_tools_link] %d tool rule(s) in Makefile; %d exempt; building %d\n",
           tools.count, stl_exempt_count(&fuzz), nt);
    struct stl_host host;
    stl_host_detect(&host);
    return stl_build_phase(tg, nt, build_only, env_or("ZCL_LINT_MODE", "FAIL"),
                           host.linux_os);
}
