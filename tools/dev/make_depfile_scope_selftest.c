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
        "zclassic23 z23 z23-package-verify: $(ZCL_DEP_PROBE_OBJECTS)\n"
        "zcl-depfile-unknown zcl-depfile-default: $(ZCL_DEP_PROBE_OBJECTS)\n\t@:\n"
        ".DEFAULT_GOAL := zcl-depfile-default\n");
    if (ferror(file) || fclose(file) != 0) fail("probe Makefile write failed");
}

static void profile_probes(void)
{
    static const struct {const char *name; unsigned mask; const char *goals[4];} probes[] = {
        {"dev", 2, {"fast-compile"}}, {"build", 1, {"build-only"}},
        {"fast", 4, {"t-fast", "ONLY=boot_phase"}}, {"strict", 8, {"t", "ONLY=boot_phase"}},
        {"failure-id", 0, {"dev-failure-execution-id"}},
        {"hot-loop", 0, {"t-hotswap", "ONLY=boot_phase"}},
        {"hot-module", 0, {"hotswap-test-so"}},
        {"hot-both", 0, {"t-hotswap", "hotswap-test-so", "ONLY=boot_phase"}},
        {"hot-mixed", 31, {"t-hotswap", "t-fast", "ONLY=boot_phase"}},
        {"node", 16, {"zclassic23"}}, {"node-alias", 16, {"z23"}},
        {"verifier", 16, {"z23-package-verify"}},
        {"mixed", 31, {"fast-compile", "build-only"}},
        {"unknown", 31, {"zcl-depfile-unknown"}}, {"default", 16, {NULL}}
    };
    size_t children[15];
    const char *logs[15];
    for (size_t i = 0; i < 15; ++i) {
        char *scratch = text("%s/%s.scratch", work, probes[i].name);
        directory(scratch);
        logs[i] = text("%s/%s.out", work, probes[i].name);
        const char *argv[48] = {"make", "-f", text("%s/probe.mk", work), "--no-print-directory", "-n",
            "ZCL_STANDALONE_CLEAN=1", text("BUILD_SOURCE_RECORD=%s", source_record),
            text("BUILD_DIR=%s/build", scratch), text("BIN_DIR=%s/build/bin", scratch),
            "VIEW_GEN_HEADERS=", "VIEW_GEN_HEADERS_EARLY=", "VENDOR_LIBS="};
        size_t n = 12;
        const char *variables[] = {"ALL_OBJS=build-only.o", "DEV_OBJS=dev.o", "DEV_OBJ_COMPLETE=dev.complete",
            "TEST_PARALLEL_FAST_OBJS=test-fast.o", "TEST_PARALLEL_FAST_CANDIDATE=test-fast.candidate",
            "TEST_PARALLEL_FAST_LINK_RSP=test-fast.rsp", "TEST_PARALLEL_REL_OBJS=test-strict.o",
            "TEST_PARALLEL_REL_CANDIDATE=test-strict.candidate", "TEST_PARALLEL_REL_LINK_RSP=test-strict.rsp",
            "NODE_C23_OBJS=node-c23.o", "NODE_C23_PACKAGE_VERIFY_OBJ=node-c23.o", "NODE_C23_LINK_RSP=node-c23.rsp"};
        for (size_t j = 0; j < 12; ++j) {
            const char *equal = strchr(variables[j], '=');
            argv[n++] = text("%.*s=%s/%s", (int)(equal - variables[j]), variables[j], work, equal + 1);
        }
        for (size_t j = 0; j < 4 && probes[i].goals[j]; ++j) argv[n++] = probes[i].goals[j];
        argv[n] = NULL;
        children[i] = probe_start(argv, logs[i], false);
    }
    bool failed = false;
    for (size_t i = 0; i < 15; ++i) {
        if (probe_wait(children[i]) != 0) {
            char *data = output(logs[i]);
            fprintf(stderr, "%s\nMake probe failed: %s\n", data, probes[i].name);
            free(data);
            failed = true;
        }
    }
    if (failed) fail("Make profile probe failed");
    for (size_t i = 0; i < 15; ++i) {
        char *data = output(logs[i]);
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
        const char *argv[] = {"make", "-pn", "--no-print-directory", goals[i], NULL};
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

int main(int argc, char **argv)
{
    if (argc != 3) fail("usage: make-depfile-scope-selftest ROOT WORK");
    root = argv[1]; work = argv[2];
    if (chdir(root) != 0) fail("cannot enter repository root");
    probe_install_cleanup();
    setup();
    profile_probes();
    binding_probes();
    consistency_probes();
    puts("make-depfile-scope-selftest: PASS header_rebuild=true single_goal_scoped=true node_c23_scoped=true hot_module_scoped=true mixed_unknown_all=true default_node_c23=true epoch_depfile_consistent=true tunnel_binding_scoped=true");
    return 0;
}
