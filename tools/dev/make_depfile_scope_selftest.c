/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * Purpose: Prove real Makefile depfile selection and header invalidation.
 */
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <utime.h>
#include "make_depfile_scope_process.h"

static const char *root, *work;
static const char *profiles[] = {"build-only", "dev", "test-fast", "test-strict", "node-c23"};
static const char source_record[] =
    "0000000000000000000000000000000000000000000000000000000000000000 1 "
    "0000000000000000000000000000000000000000000000000000000000000000";

static void fail(const char *message)
{
    fprintf(stderr, "make-depfile-scope-selftest: FAIL: %s\n", message);
    exit(1);
}

/* This bounded arena owns argv and path strings until all children finish. */
static char *text(const char *format, ...)
{
    static char arena[1024][8192];
    static size_t used;
    if (used == 1024) fail("fixture string arena exhausted");
    char *out = arena[used++];
    va_list args;
    va_start(args, format);
    int n = vsnprintf(out, 8192, format, args);
    va_end(args);
    if (n < 0 || n >= 8192) fail("fixture string overflow");
    return out;
}

/* Make syntax needs escaping even though process arguments use no shell. */
static char *make_path(const char *path)
{
    char *out = text("%s", "");
    size_t n = 0;
    for (const char *p = path; *p; ++p) {
        if (*p == '\n' || *p == '\r' || n + 3 >= 8192)
            fail("unrepresentable Make fixture path");
        if (strchr(" \\#:", *p)) out[n++] = '\\';
        if (*p == '$') out[n++] = '$';
        out[n++] = *p;
    }
    out[n] = 0;
    return out;
}

static void put(const char *path, time_t stamp, const char *format, ...)
{
    FILE *file = fopen(path, "wb");
    if (!file) fail(text("cannot create %s: %s", path, strerror(errno)));
    va_list args;
    va_start(args, format);
    int n = vfprintf(file, format, args);
    va_end(args);
    if (fclose(file) != 0 || n < 0) fail("fixture write failed");
    struct utimbuf times = {stamp, stamp};
    if (stamp && utime(path, &times) != 0) fail("fixture timestamp failed");
}

static void directory(const char *path)
{
#ifdef _WIN32
    int rc = _mkdir(path);
#else
    int rc = mkdir(path, 0700);
#endif
    if (rc != 0 && errno != EEXIST) fail(text("cannot create directory %s", path));
}

static char *output(const char *path)
{
    FILE *file = fopen(path, "rb");
    if (!file || fseek(file, 0, SEEK_END) != 0) fail("cannot open probe output");
    long size = ftell(file);
    if (size < 0 || size > 128 * 1024 * 1024 || fseek(file, 0, SEEK_SET) != 0)
        fail("probe output size invalid");
    /* Standalone fixture: no node allocator/logging linkage; checked and freed by the caller. */
    char *data = malloc((size_t)size + 1); // raw-alloc-ok:standalone-test-fixture
    if (!data) fail("probe output allocation failed");
    size_t got = fread(data, 1, (size_t)size, file);
    int closed = fclose(file);
    if (got != (size_t)size || closed != 0) fail("probe output read failed");
    data[got] = 0;
    return data;
}

static void setup(void)
{
    for (size_t i = 0; i < 5; ++i) {
        char *object = text("%s/%s.o", work, profiles[i]);
        char *header = text("%s/%s.h", work, profiles[i]);
        put(object, 1577836800, "");
        put(header, 1609459200, "");
        put(text("%s/%s.d", work, profiles[i]), 1577836800,
            "%s: %s\n", make_path(object), make_path(header));
    }
    const char *ready[] = {"dev.complete", "test-fast.candidate", "test-fast.rsp",
        "test-strict.candidate", "test-strict.rsp", "node-c23.rsp"};
    for (size_t i = 0; i < 6; ++i) put(text("%s/%s", work, ready[i]), 1640995200, "");
    FILE *file = fopen(text("%s/probe.mk", work), "wb");
    if (!file) fail("cannot create probe Makefile");
    fprintf(file, "include %s/Makefile\n", make_path(root));
    for (size_t i = 0; i < 5; ++i)
        fprintf(file, "%s/%s.o:\n\t@echo ZCL_DEP_REBUILD=%s\n", make_path(work), profiles[i], profiles[i]);
    fprintf(file, "ZCL_DEP_PROBE_OBJECTS := ");
    for (size_t i = 0; i < 5; ++i) fprintf(file, "%s/%s.o ", make_path(work), profiles[i]);
    fprintf(file, "\nfast-compile build-only t-fast t dev-failure-execution-id: $(ZCL_DEP_PROBE_OBJECTS)\n"
        "t-hotswap hotswap-test-so: $(ZCL_DEP_PROBE_OBJECTS)\n\t@:\n"
        "zclassic23 z23 z23-package-verify help: $(ZCL_DEP_PROBE_OBJECTS)\n"
        "zcl-depfile-unknown zcl-depfile-default: $(ZCL_DEP_PROBE_OBJECTS)\n\t@:\n"
        ".DEFAULT_GOAL := zcl-depfile-default\n"
        "$(info ZCL_EPOCH_PROBE=[$(ZCL_EPOCH_PROFILES)])\n");
    if (ferror(file) || fclose(file) != 0) fail("probe Makefile write failed");
}

static void profile_probes(void)
{
    static const struct {const char *name; unsigned mask; const char *goals[4]; const char *epoch;} probes[] = {
        {"dev", 2, {"fast-compile"}, NULL}, {"build", 1, {"build-only"}, NULL},
        {"fast", 4, {"t-fast", "ONLY=boot_phase"}, NULL}, {"strict", 8, {"t", "ONLY=boot_phase"}, NULL},
        {"failure-id", 0, {"dev-failure-execution-id"}, NULL},
        {"hot-loop", 0, {"t-hotswap", "ONLY=boot_phase"}, NULL},
        {"hot-module", 0, {"hotswap-test-so"}, NULL},
        {"hot-both", 0, {"t-hotswap", "hotswap-test-so", "ONLY=boot_phase"}, NULL},
        {"hot-mixed", 31, {"t-hotswap", "t-fast", "ONLY=boot_phase"}, NULL},
        {"node", 16, {"zclassic23"}, "node-c23"}, {"node-alias", 16, {"z23"}, "node-c23"},
        {"verifier", 16, {"z23-package-verify"}, "node-c23"},
        {"mixed", 31, {"fast-compile", "build-only"}, NULL},
        {"unknown", 31, {"zcl-depfile-unknown"}, NULL}, {"default", 16, {NULL}, NULL},
        {"header-node", 16, {"contexts/explorer/views/include/views/site_css.h", "z23"}, "node-c23"},
        {"node-header", 16, {"z23", "contexts/explorer/views/include/views/site_css.h"}, "node-c23"},
        {"stamp-node", 16, {"build/identity/gen-stamps/site_css.stamp", "z23"}, "node-c23"},
        {"node-stamp", 16, {"z23", "build/identity/gen-stamps/site_css.stamp"}, "node-c23"},
        {"header-help", 31, {"contexts/explorer/views/include/views/site_css.h", "help"}, ""},
        {"help-header", 31, {"help", "contexts/explorer/views/include/views/site_css.h"}, ""},
        {"help", 31, {"help"}, ""},
        {"header-unknown", 31, {"contexts/explorer/views/include/views/site_css.h", "zcl-depfile-unknown"}, "build-only dev dev-asan dev-tsan test-fast test-strict test-asan test-tsan coverage node-c23"},
        {"header-mixed", 31, {"contexts/explorer/views/include/views/site_css.h", "fast-compile", "build-only"}, "build-only dev dev-asan dev-tsan test-fast test-strict test-asan test-tsan coverage node-c23"}
    };
    enum { count = sizeof(probes) / sizeof(probes[0]) };
    size_t children[count];
    const char *logs[count];
    for (size_t i = 0; i < count; ++i) {
        char *scratch = text("%s/%s.scratch", work, probes[i].name);
        directory(scratch);
        logs[i] = text("%s/%s.out", work, probes[i].name);
        const char *argv[48] = {"make", "-f", text("%s/probe.mk", work), "--no-print-directory", "-n",
            probes[i].epoch ? "BUILD_EPOCH_CLEAN_ONLY=0" : "ZCL_STANDALONE_CLEAN=1", text("BUILD_SOURCE_RECORD=%s", source_record),
            text("BUILD_DIR=%s/build", scratch), text("BIN_DIR=%s/build/bin", scratch),
            "VIEW_GEN_HEADERS=", "VIEW_GEN_HEADERS_EARLY=", "VENDOR_LIBS=", "ZCL_TOR=stub"};
        size_t n = 13;
        const char *variables[] = {"ALL_OBJS=build-only.o", "DEV_OBJS=dev.o", "DEV_OBJ_COMPLETE=dev.complete",
            "TEST_PARALLEL_FAST_OBJS=test-fast.o", "TEST_PARALLEL_FAST_CANDIDATE=test-fast.candidate",
            "TEST_PARALLEL_FAST_LINK_RSP=test-fast.rsp", "TEST_PARALLEL_REL_OBJS=test-strict.o",
            "TEST_PARALLEL_REL_CANDIDATE=test-strict.candidate", "TEST_PARALLEL_REL_LINK_RSP=test-strict.rsp",
            "NODE_C23_OBJS=node-c23.o", "NODE_C23_PACKAGE_VERIFY_OBJ=node-c23.o", "NODE_C23_LINK_RSP=node-c23.rsp"};
        for (size_t j = 0; j < 12; ++j) {
            const char *equal = strchr(variables[j], '=');
            argv[n++] = text("%.*s=%s/%s", (int)(equal - variables[j]), variables[j], work, equal + 1);
        }
        if (probes[i].epoch) {
            argv[n++] = "-o";
            argv[n++] = "contexts/explorer/views/include/views/site_css.h";
            argv[n++] = "-o";
            argv[n++] = "build/identity/gen-stamps/site_css.stamp";
            argv[n++] = "BUILD_COMPILER_ID=0000000000000000000000000000000000000000000000000000000000000000";
            argv[n++] = "BUILD_SYSTEM_ID=0000000000000000000000000000000000000000000000000000000000000000";
            argv[n++] = "zcl_compile_epoch=0000000000000000000000000000000000000000000000000000000000000000";
        }
        for (size_t j = 0; j < 4 && probes[i].goals[j]; ++j) argv[n++] = probes[i].goals[j];
        argv[n] = NULL;
        children[i] = probe_start(argv, logs[i], false);
    }
    bool failed = false;
    for (size_t i = 0; i < count; ++i) {
        if (probe_wait(children[i]) != 0) {
            char *data = output(logs[i]);
            fprintf(stderr, "%s\nMake probe failed: %s\n", data, probes[i].name);
            free(data);
            failed = true;
        }
    }
    if (failed) fail("Make profile probe failed");
    for (size_t i = 0; i < count; ++i) {
        char *data = output(logs[i]);
        if (probes[i].epoch && !strstr(data, text("ZCL_EPOCH_PROBE=[%s]", probes[i].epoch))) {
            fprintf(stderr, "%s\n", data);
            fail(text("probe=%s epoch expected=[%s]", probes[i].name, probes[i].epoch));
        }
        for (size_t j = 0; j < 5; ++j) {
            bool present = strstr(data, text("ZCL_DEP_REBUILD=%s", profiles[j])) != NULL;
            if (present != ((probes[i].mask & (1u << j)) != 0)) {
                fprintf(stderr, "%s\n", data);
                fail(text("probe=%s profile=%s present=%d expected=%d", probes[i].name, profiles[j],
                    present, (probes[i].mask & (1u << j)) != 0));
            }
        }
        free(data);
    }
    probe_count = 0; /* all profile children were reaped; reuse the bounded slots */
}

static void binding_probes(void)
{
    char *objects = text("%s/binding-objects", work);
    directory(objects);
    const char *parts[] = {"platform", "modules", "base", "src"};
    char *parent = objects;
    for (size_t i = 0; i < 4; ++i) {parent = text("%s/%s", parent, parts[i]); directory(parent);}
    char *object = text("%s/cleanse.o", parent);
    char *bin = text("%s/binding-bin", work);
    directory(bin);
    char *exporter = text("%s/native-tunnel-export", bin);
    char *header = text("%s/binding-actual-include.h", work);
    put(object, 1893456000, "");
    put(exporter, 1893456000, "");
    put(header, 0, "");
    put(text("%s/binding.d", work), 0, "%s: %s\n", make_path(object), make_path(header));
    char *makefile = text("%s/binding-probe.mk", work);
    put(makefile, 0, "include %s/Makefile\ninclude %s/binding.d\n", make_path(root), make_path(work));
    for (size_t i = 0; i < 3; ++i) {
        const char *argv[48] = {"make", "-f", makefile, "--no-print-directory", "-n",
            "-o", "Makefile", "-o", "tools/native_tunnel_sources.def",
            "-o", "contexts/wallet/views/include/views/wallet_templates_gen.h",
            "-o", "contexts/explorer/views/include/views/site_css.h",
            "-o", "contexts/commons/views/include/views/install_script_gen.h",
            "ZCL_STANDALONE_CLEAN=1", text("BUILD_SOURCE_RECORD=%s", source_record),
            "ZCL_EPOCH_PROFILES=", "ZCL_DEPFILE_PROFILES=", text("BUILD_DIR=%s/binding-build", work),
            text("BIN_DIR=%s", bin), text("OBJ_DIR=%s", objects), "BUILD_ONLY_LEASE=",
            "BUILD_FAST_EPOCH_OBJECT_PREREQ=", "BUILD_FAST_EPOCH_OBJECT_COMMAND=echo ZCL_BINDING_OBJECT_REBUILD",
            object, exporter, NULL};
        size_t n = 27;
        if (i) {argv[n++] = "-W"; argv[n++] = i == 1 ? "tools/dev/native_tunnel_export_binding.h" : header;}
        argv[n] = NULL;
        char *log = text("%s/binding-%zu.out", work, i);
        size_t child = probe_start(argv, log, false);
        int rc = probe_wait(child);
        char *data = output(log);
        bool rebuild = strstr(data, "ZCL_BINDING_OBJECT_REBUILD") != NULL;
        bool link = strstr(data, text("-o %s", exporter)) != NULL;
        if (rc != 0 || (i == 0 && (rebuild || link)) || (i == 1 && (rebuild || !link)) || (i == 2 && !rebuild)) {
            fprintf(stderr, "%s\n", data);
            fail(text("binding probe %zu failed (status=%d object=%d exporter=%d)", i, rc, rebuild, link));
        }
        free(data);
    }
}

static void profile_values(char *data, char **epoch, char **depfiles)
{
    char *line = data;
    while (line && *line) {
        char *next = strchr(line, '\n');
        if (next) *next++ = 0;
        const char *names[] = {"ZCL_EPOCH_PROFILES", "ZCL_DEPFILE_PROFILES"};
        for (size_t j = 0; j < 2; ++j) {
            size_t n = strlen(names[j]);
            if (strncmp(line, names[j], n) != 0 || line[n] != ' ') continue;
            char *value = line + n + 1;
            if (*value == ':') ++value;
            if (*value++ != '=') continue;
            if (*value == ' ') ++value;
            if (j == 0) *epoch = value; else *depfiles = value;
        }
        line = next;
    }
}

static void consistency_probes(void)
{
    const char *goals[] = {"lint", "lint-preflight", "ff", "dev-bin", "dev-proof-bundle",
        "fast-compile", "dev-build-only", "dev-package-verifier"};
    size_t children[8];
    const char *logs[8];
    for (size_t i = 0; i < 8; ++i) {
        /* A dry-run may remake included bootstrap Makefiles. These probes
         * inspect profile selection only and must not repair vendor inputs. */
        const char *argv[] = {"make", "-pn", "--no-print-directory",
                              "VENDOR_LIBS=", "ZCL_TOR=stub", goals[i], NULL};
        logs[i] = text("%s/consistency.%s", work, goals[i]);
        children[i] = probe_start(argv, logs[i], true);
    }
    /* -pn may fail because an unrelated prerequisite is absent. As in the
     * shell fixture, the computed variable records remain the authority. */
    for (size_t i = 0; i < 8; ++i) (void)probe_wait(children[i]);
    for (size_t i = 0; i < 8; ++i) {
        char *data = output(logs[i]);
        char *epoch = NULL, *depfiles = NULL;
        profile_values(data, &epoch, &depfiles);
        if (!epoch || !*epoch) fail(text("cannot read epoch profiles for goal %s", goals[i]));
        char *save = NULL;
        for (char *profile = strtok_r(epoch, " \t\r", &save); profile; profile = strtok_r(NULL, " \t\r", &save)) {
            char *needle = text(" %s ", profile);
            if (!depfiles || !strstr(text(" %s ", depfiles), needle))
                fail(text("goal %s builds %s but imports depfiles only for: %s", goals[i], profile, depfiles ? depfiles : "nothing"));
        }
        free(data);
    }
}

static const char *const tor_header_goals[] = {
    "contexts/wallet/views/include/views/wallet_templates_gen.h",
    "contexts/explorer/views/include/views/site_css.h",
    "contexts/commons/views/include/views/install_script_gen.h",
    "tools/dev/native_tunnel_export_binding.h",
    "build/identity/gen-stamps/wallet_templates.stamp",
    "build/identity/gen-stamps/site_css.stamp",
    "build/identity/gen-stamps/install_script.stamp",
    "build/identity/gen-stamps/native_tunnel_export_binding.stamp",
};

static size_t tor_probe_start(size_t i, const char *first, const char *second,
                              bool invalid, const char *log)
{
    const char *argv[48] = {"make", "-f", text("%s/probe.mk", work),
                            "--no-print-directory", "-n"};
    size_t n = 5;
    for (size_t j = 0; j < sizeof tor_header_goals / sizeof tor_header_goals[0]; j++) {
        argv[n++] = "-o";
        argv[n++] = tor_header_goals[j];
    }
    argv[n++] = "VENDOR_LIBS=";
    argv[n++] = "VIEW_GEN_HEADERS=";
    argv[n++] = "VIEW_GEN_HEADERS_EARLY=";
    argv[n++] = text("BUILD_SOURCE_RECORD=%s", source_record);
    argv[n++] = "BUILD_COMPILER_ID=0000000000000000000000000000000000000000000000000000000000000000";
    argv[n++] = "BUILD_SYSTEM_ID=0000000000000000000000000000000000000000000000000000000000000000";
    argv[n++] = "zcl_compile_epoch=0000000000000000000000000000000000000000000000000000000000000000";
    argv[n++] = invalid ? "ZCL_TOR=invalid" : "ZCL_TOR=full";
    argv[n++] = "ZCL_TOR_READY_PROBE=$(error TOR_SENTINEL)";
    argv[n++] = text("BUILD_DIR=%s/tor-%zu/build", work, i);
    if (first) argv[n++] = first;
    if (second) argv[n++] = second;
    argv[n] = NULL;
    return probe_start(argv, log, false);
}

static void tor_guard_probes(void)
{
    struct { const char *first, *second; bool sentinel, invalid; } cases[15] = {0};
    for (size_t i = 0; i < 8; i++) cases[i].first = tor_header_goals[i];
    cases[8].first = tor_header_goals[1]; cases[8].second = "help";
    cases[9].first = "help"; cases[9].second = tor_header_goals[1];
    cases[10].first = tor_header_goals[1]; cases[10].second = "z23"; cases[10].sentinel = true;
    cases[11].first = "z23"; cases[11].second = tor_header_goals[1]; cases[11].sentinel = true;
    cases[12].first = "zcl-depfile-unknown"; cases[12].sentinel = true;
    cases[13].sentinel = true;
    cases[14].first = tor_header_goals[1]; cases[14].invalid = true;
    size_t children[15];
    const char *logs[15];
    probe_count = 0; /* prior probes have all been reaped */
    for (size_t i = 0; i < 15; i++) {
        logs[i] = text("%s/tor-guard-%zu.out", work, i);
        children[i] = tor_probe_start(i, cases[i].first, cases[i].second,
                                      cases[i].invalid, logs[i]);
    }
    bool failed = false;
    for (size_t i = 0; i < 15; i++) {
        int rc = probe_wait(children[i]);
        char *data = output(logs[i]);
        bool sentinel = strstr(data, "TOR_SENTINEL") != NULL;
        bool invalid = strstr(data, "ZCL_TOR must be") != NULL;
        bool ok = cases[i].invalid ? rc == 2 && invalid && !sentinel :
                  cases[i].sentinel ? rc == 2 && sentinel : rc == 0 && !sentinel;
        if (!ok) {
            fprintf(stderr, "tor guard case=%zu rc=%d sentinel=%d invalid=%d\n%s\n",
                    i, rc, sentinel, invalid, data);
            failed = true;
        }
        free(data);
    }
    if (failed) fail("Tor bootstrap guard probe failed");
}

struct prime_case {
    const char *first, *second;
    bool sentinel;
};

static const struct prime_case prime_cases[] = {
    {"worktree-prime", NULL, false},
    {"worktree-prime-selftest", NULL, false},
    {"worktree-prime", "worktree-prime-selftest", false},
    {"worktree-prime-selftest", "worktree-prime", false},
    {"worktree-prime", "z23", true}, {"z23", "worktree-prime", true},
    {"worktree-prime", "help", true}, {"help", "worktree-prime", true},
    {"worktree-prime", "zcl-depfile-unknown", true},
    {"zcl-depfile-unknown", "worktree-prime", true},
    {NULL, NULL, true},
};

static size_t prime_probe_start(size_t i, bool capture, const char *log)
{
    const char *argv[40] = {"make", "-f", text("%s/probe.mk", work),
                            "--no-print-directory", "-n"};
    size_t n = 5;
    const char *old[] = {"worktree-prime", "worktree-prime-selftest", "z23", "help",
                         "zcl-depfile-unknown", "zcl-depfile-default"};
    for (size_t j = 0; j < sizeof old / sizeof old[0]; j++) {
        argv[n++] = "-o";
        argv[n++] = old[j];
    }
    argv[n++] = "VENDOR_LIBS=";
    argv[n++] = "VIEW_GEN_HEADERS=";
    argv[n++] = "VIEW_GEN_HEADERS_EARLY=";
    argv[n++] = "ZCL_TOR=stub";
    argv[n++] = "BUILD_COMPILER_ID=0000000000000000000000000000000000000000000000000000000000000000";
    argv[n++] = "BUILD_SYSTEM_ID=0000000000000000000000000000000000000000000000000000000000000000";
    argv[n++] = "zcl_compile_epoch=0000000000000000000000000000000000000000000000000000000000000000";
    argv[n++] = text("BUILD_DIR=%s/prime-%zu/build", work, i);
    argv[n++] = capture ? "VIEW_BOOTSTRAP_MK=" :
                          text("VIEW_BOOTSTRAP_MK=%s", make_path(text("%s/prime-view-sentinel.mk", work)));
    argv[n++] = capture ? "ZCL_SOURCE_IDENTITY_SESSION=$(error PRIME_CAPTURE_SENTINEL)" :
                          text("BUILD_SOURCE_RECORD=%s", source_record);
    if (prime_cases[i].first) argv[n++] = prime_cases[i].first;
    if (prime_cases[i].second) argv[n++] = prime_cases[i].second;
    argv[n] = NULL;
    return probe_start(argv, log, false);
}

static void prime_guard_probes(void)
{
    enum { count = sizeof prime_cases / sizeof prime_cases[0] };
    size_t children[2][count];
    const char *logs[2][count];
    put(text("%s/prime-view-sentinel.mk", work), 0, "%s\n", "$(error PRIME_VIEW_SENTINEL)");
    probe_count = 0; /* all previous probes were reaped */
    for (size_t mode = 0; mode < 2; mode++)
        for (size_t i = 0; i < count; i++) {
            logs[mode][i] = text("%s/prime-guard-%zu-%zu.out", work, mode, i);
            children[mode][i] = prime_probe_start(i, mode != 0, logs[mode][i]);
        }
    bool failed = false;
    for (size_t mode = 0; mode < 2; mode++)
        for (size_t i = 0; i < count; i++) {
            int rc = probe_wait(children[mode][i]);
            char *data = output(logs[mode][i]);
            const char *marker = mode ? "PRIME_CAPTURE_SENTINEL" : "PRIME_VIEW_SENTINEL";
            bool hit = strstr(data, marker) != NULL;
            bool ok = prime_cases[i].sentinel ? rc == 2 && hit : rc == 0 && !hit;
            if (!ok) {
                fprintf(stderr, "prime guard mode=%zu case=%zu rc=%d sentinel=%d\n%s\n",
                        mode, i, rc, hit, data);
                failed = true;
            }
            free(data);
        }
    if (failed) fail("worktree-prime parse guard probe failed");
}

/* These probes own their Make argv. A parent test build freezes its source
 * record through recursive Make flags; inheriting that override would skip
 * the source capture that the prime-guard sentinel is meant to exercise.
 * Keep explicit probe arguments and other build environment inputs intact. */
static void isolate_make_options(void)
{
    const char *const names[] = {"MAKEFLAGS", "MFLAGS", "MAKEOVERRIDES", "GNUMAKEFLAGS"};
    for (size_t i = 0; i < sizeof names / sizeof names[0]; i++) {
#ifdef _WIN32
        int rc = _putenv(text("%s=", names[i]));
#else
        int rc = unsetenv(names[i]);
#endif
        if (rc != 0) fail(text("cannot clear inherited %s: %s", names[i], strerror(errno)));
    }
}

int main(int argc, char **argv)
{
    if (argc != 3) fail("usage: make-depfile-scope-selftest ROOT WORK");
    root = argv[1]; work = argv[2];
    if (chdir(root) != 0) fail("cannot enter repository root");
    isolate_make_options();
    probe_install_cleanup();
    setup();
    profile_probes();
    binding_probes();
    consistency_probes();
    tor_guard_probes();
    prime_guard_probes();
    puts("make-depfile-scope-selftest: PASS header_rebuild=true single_goal_scoped=true node_c23_scoped=true hot_module_scoped=true mixed_unknown_all=true default_node_c23=true epoch_depfile_consistent=true tunnel_binding_scoped=true");
    return 0;
}
