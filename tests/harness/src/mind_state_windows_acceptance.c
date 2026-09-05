/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Prove native Windows mind paths and repeated atomic state writes
 * against an isolated directory, including refusal to replace a directory. */
#if defined(_WIN32)
#include <stdio.h>
#include "mind.h"
#include "codeindex/codeindex.h"
#include "platform/private_directory.h"
#include <windows.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "mind_state_acceptance: FAIL line=%d %s\n", \
                __LINE__, #condition); \
        goto cleanup; \
    } \
} while (0)

static bool append_path(char *out, size_t cap, const char *root, const char *leaf)
{
    int n = snprintf(out, cap, "%s%s", root, leaf);
    return n > 0 && (size_t)n < cap;
}

/* This fixture exercises state-file publication, not a database generation.
 * Refusal decoration shares the owner TU; fail if it unexpectedly asks for
 * an index rather than silently substituting a fabricated source root. */
static bool unexpected_index_access;
bool codeindex_source_root_sha3(struct codeindex *ci, uint8_t out[32])
{
    (void)ci;
    (void)out;
    unexpected_index_access = true;
    fprintf(stderr, "mind_state_acceptance: unexpected index access\n");
    return false;
}

/* Every name is a known child of the directory this process created. Never
 * derive cleanup paths from the product's state resolver under test. */
static bool clean_fixture(const char *root)
{
    static const char *const leaves[] = {
        "\\.codeindex\\owner.v1", "\\.codeindex\\owner.v1.tmp",
        "\\.codeindex", "\\checkouts.v1", "\\checkouts.v1.tmp",
        "\\heartbeat.json", "\\heartbeat.json.tmp", "\\mind",
        "\\z23\\dev\\mind", "\\z23\\dev", "\\z23", ""
    };
    bool ok = true;
    for (size_t i = 0; i < sizeof(leaves) / sizeof(leaves[0]); ++i) {
        char path[ZCL_MIND_PATH_MAX];
        if (!append_path(path, sizeof(path), root, leaves[i])) {
            fprintf(stderr, "mind_state_acceptance: cleanup path too long\n");
            return false;
        }
        DWORD attributes = GetFileAttributesA(path);
        if (attributes == INVALID_FILE_ATTRIBUTES) {
            DWORD error = GetLastError();
            if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND)
                continue;
            ok = false;
        } else if (attributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (!RemoveDirectoryA(path)) ok = false;
        } else if (!DeleteFileA(path)) {
            ok = false;
        }
    }
    if (!ok) fprintf(stderr, "mind_state_acceptance: fixture cleanup failed\n");
    return ok;
}

static int run_fixture(void)
{
    char temporary[MAX_PATH], root[ZCL_MIND_PATH_MAX], state[ZCL_MIND_PATH_MAX];
    char heartbeat[ZCL_MIND_PATH_MAX], staging[ZCL_MIND_PATH_MAX];
    struct zcl_mind_registry reg = {0}, loaded = {0};
    struct zcl_mind_heartbeat beat = {0}, seen = {0};
    bool created = false;
    int rc = 1;
    DWORD n = GetTempPathA(sizeof(temporary), temporary);
    CHECK(n > 0 && n < sizeof(temporary));
    int written = snprintf(root, sizeof(root), "%sz23-mind-%lu-%llu", temporary,
        (unsigned long)GetCurrentProcessId(), (unsigned long long)GetTickCount64());
    CHECK(written > 0 && (size_t)written < sizeof(root));
    CHECK(platform_private_directory_create(root));
    created = true;
    /* Bound even the old implementation's fallback to this fixture. */
    CHECK(SetEnvironmentVariableA("ZCL_STATE_ROOT", root));
    CHECK(SetEnvironmentVariableA("ZCL_MIND_STATE_DIR", root));
    CHECK(_putenv_s("ZCL_STATE_ROOT", root) == 0);
    CHECK(_putenv_s("ZCL_MIND_STATE_DIR", root) == 0);
    CHECK(zcl_mind_state_dir(state, sizeof(state)));
    CHECK(strcmp(state, root) == 0);

    reg.count = 3;
    CHECK(append_path(reg.roots[0], sizeof(reg.roots[0]), root, ""));
    CHECK(append_path(reg.roots[1], sizeof(reg.roots[1]), "\\\\fixture-host\\share", "\\root"));
    CHECK(append_path(reg.roots[2], sizeof(reg.roots[2]), "C:", "relative"));
    CHECK(zcl_mind_registry_write(&reg));
    CHECK(zcl_mind_registry_load(&loaded));
    CHECK(loaded.count == 2);
    CHECK(strcmp(loaded.roots[0], reg.roots[0]) == 0);
    CHECK(strcmp(loaded.roots[1], reg.roots[1]) == 0);
    reg.count = 1;
    CHECK(append_path(reg.roots[0], sizeof(reg.roots[0]), root, "\\second"));
    CHECK(zcl_mind_registry_write(&reg));
    CHECK(zcl_mind_registry_load(&loaded));
    CHECK(loaded.count == 1 && strcmp(loaded.roots[0], reg.roots[0]) == 0);

    beat.pid = 11;
    beat.started_unix = 100;
    beat.beat_unix = 200;
    CHECK(zcl_mind_heartbeat_write(&beat));
    CHECK(zcl_mind_heartbeat_read(&seen));
    CHECK(seen.pid == 11 && seen.beat_unix == 200);
    beat.pid = 22;
    beat.beat_unix = 400;
    CHECK(zcl_mind_heartbeat_write(&beat));
    CHECK(zcl_mind_heartbeat_read(&seen));
    CHECK(seen.pid == 22 && seen.beat_unix == 400);

    long long pid = 0, time = 0;
    CHECK(codeindex_owner_claim(root, 111, 1000));
    CHECK(codeindex_owner_claim(root, 222, 2000));
    CHECK(codeindex_owner_read(root, &pid, &time));
    CHECK(pid == 222 && time == 2000);
    CHECK(!codeindex_owner_release(root, 111));
    CHECK(codeindex_owner_read(root, &pid, &time));
    CHECK(pid == 222 && time == 2000);
    CHECK(codeindex_owner_release(root, 222));
    CHECK(!codeindex_owner_read(root, &pid, &time));

    CHECK(append_path(heartbeat, sizeof(heartbeat), root, "\\heartbeat.json"));
    CHECK(append_path(staging, sizeof(staging), heartbeat, ".tmp"));
    CHECK(DeleteFileA(heartbeat));
    CHECK(CreateDirectoryA(heartbeat, NULL));
    CHECK(!zcl_mind_heartbeat_write(&beat));
    DWORD attributes = GetFileAttributesA(heartbeat);
    CHECK(attributes != INVALID_FILE_ATTRIBUTES &&
          (attributes & FILE_ATTRIBUTE_DIRECTORY));
    CHECK(GetFileAttributesA(staging) == INVALID_FILE_ATTRIBUTES);
    CHECK(GetLastError() == ERROR_FILE_NOT_FOUND);
    CHECK(!unexpected_index_access);
    rc = 0;
cleanup:
    if (created && !clean_fixture(root)) rc = 1;
    return rc;
}
int main(void)
{
    int rc = run_fixture();
    if (rc == 0) printf("mind_state_acceptance: PASS paths updates owner refusal\n");
    return rc;
}
#else
typedef int mind_state_windows_acceptance_not_built;
#endif
