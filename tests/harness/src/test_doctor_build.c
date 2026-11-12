/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Drives zcl_doctor_build, the shipped accelerator report. A private PATH
 * holds stub tools so each preference (preferred tool, fallback, absent)
 * is the real lookup, not a hardcoded row. */

#include "test/test_core.h"

#include "doctor_build.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static char g_saved_path[8192];
static int g_had_path;

static void doc_path_save(void)
{
    const char *cur = getenv("PATH");
    g_had_path = cur != NULL;
    g_saved_path[0] = '\0';
    if (cur)
        (void)snprintf(g_saved_path, sizeof g_saved_path, "%s", cur);
}

static void doc_path_restore(void)
{
    if (g_had_path)
        (void)setenv("PATH", g_saved_path, 1);
    else
        (void)unsetenv("PATH");
}

static int doc_stub(const char *dir, const char *name, const char *version)
{
    char path[512];
    FILE *file;
    int n = snprintf(path, sizeof path, "%s/%s", dir, name);
    if (n < 0 || n >= (int)sizeof path)
        return -1;
    file = fopen(path, "w");
    if (!file)
        return -1;
    if (fprintf(file,
                "#!/bin/sh\n"
                "if [ \"$1\" = --version ]; then printf '%%s\\n' '%s'; fi\n"
                "exit 0\n",
                version) < 0 ||
        fclose(file) != 0)
        return -1;
    return chmod(path, 0755);
}

static int doc_capture(char *out, size_t cap)
{
    int pipefd[2];
    ssize_t got;
    if (pipe(pipefd) != 0)
        return -1;
    if (zcl_doctor_build(pipefd[1]) != 0) {
        (void)close(pipefd[0]);
        (void)close(pipefd[1]);
        return -1;
    }
    (void)close(pipefd[1]);
    got = read(pipefd[0], out, cap - 1);
    (void)close(pipefd[0]);
    if (got < 0)
        return -1;
    out[got] = '\0';
    return 0;
}

static int test_doctor_build_cases(const char *root)
{
    int failures = 0;
    char preferred[512];
    char fallback[512];
    char empty[512];
    char text[8192];
    doc_path_save();
    TEST("doctor build: preferred tool, fallback, and a fully missing PATH") {
        (void)snprintf(preferred, sizeof preferred, "%s/preferred", root);
        (void)snprintf(fallback, sizeof fallback, "%s/fallback", root);
        (void)snprintf(empty, sizeof empty, "%s/empty", root);
        ASSERT(mkdir(preferred, 0755) == 0);
        ASSERT(mkdir(fallback, 0755) == 0);
        ASSERT(mkdir(empty, 0755) == 0);
        ASSERT(doc_stub(preferred, "ccache", "stub-ccache") == 0);
        ASSERT(doc_stub(preferred, "sccache", "stub-sccache") == 0);
        ASSERT(doc_stub(preferred, "mold", "stub-mold") == 0);
        ASSERT(doc_stub(preferred, "ld.lld", "stub-lld") == 0);
        ASSERT(doc_stub(preferred, "clang", "stub-clang") == 0);
        ASSERT(doc_stub(preferred, "inotifywait", "stub-inotify") == 0);
        ASSERT(doc_stub(preferred, "lcov", "stub-lcov") == 0);
        ASSERT(doc_stub(preferred, "gcovr", "stub-gcovr") == 0);
        ASSERT(doc_stub(preferred, "clangd", "stub-clangd") == 0);
        ASSERT(setenv("PATH", preferred, 1) == 0);
        ASSERT(doc_capture(text, sizeof text) == 0);
        ASSERT(strstr(text, "doctor-build: accelerator health") != NULL);
        ASSERT(strstr(text, "online CPUs") != NULL);
        ASSERT(strstr(text, "(stub-ccache)") != NULL);
        ASSERT(strstr(text, "(stub-mold)") != NULL);
        ASSERT(strstr(text, "(stub-lcov)") != NULL);
        ASSERT(strstr(text, "doctor-build: 6 present, 0 missing") != NULL);
        ASSERT(strstr(text, "[MISSING]") == NULL);
        ASSERT(doc_stub(fallback, "sccache", "fb-sccache") == 0);
        ASSERT(doc_stub(fallback, "ld.lld", "fb-lld") == 0);
        ASSERT(doc_stub(fallback, "clang", "fb-clang") == 0);
        ASSERT(doc_stub(fallback, "inotifywait", "fb-inotify") == 0);
        ASSERT(doc_stub(fallback, "gcovr", "fb-gcovr") == 0);
        ASSERT(doc_stub(fallback, "clangd", "fb-clangd") == 0);
        ASSERT(setenv("PATH", fallback, 1) == 0);
        ASSERT(doc_capture(text, sizeof text) == 0);
        ASSERT(strstr(text, "sccache") != NULL);
        ASSERT(strstr(text, "ld.lld") != NULL);
        ASSERT(strstr(text, "gcovr") != NULL);
        ASSERT(strstr(text, "(stub-ccache)") == NULL);
        ASSERT(strstr(text, "doctor-build: 6 present, 0 missing") != NULL);
        ASSERT(setenv("PATH", empty, 1) == 0);
        ASSERT(doc_capture(text, sizeof text) == 0);
        ASSERT(strstr(text, "[MISSING] ccache/sccache") != NULL);
        ASSERT(strstr(text, "[MISSING] mold/lld/gold") != NULL);
        ASSERT(strstr(text, "[MISSING] lcov/gcovr") != NULL);
        ASSERT(strstr(text, "doctor-build: 0 present, 6 missing") != NULL);
        ASSERT(strstr(text, "[ok]") == NULL);
        PASS();
    } _test_next:;
    doc_path_restore();
    return failures;
}

int test_doctor_build(void);
int test_doctor_build(void)
{
    char root[512];
    int failures;
    test_make_tmpdir(root, sizeof root, "doctor_build", "root");
    failures = test_doctor_build_cases(root);
    (void)test_rm_rf_recursive(root);
    if (failures == 0)
        printf("test_doctor_build: all passed\n");
    else
        printf("test_doctor_build: %d FAILED\n", failures);
    return failures;
}
