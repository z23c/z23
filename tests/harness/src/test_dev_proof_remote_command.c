/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * Exercise the actual development command in isolated local fixtures. */
#include "test/test_core.h"
#include "test/host_tool_capture.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
int test_dev_proof_remote_command(void)
{
    int failures = 0;
    TEST("dev.proof.remote: missing assignment refuses") {
        char out[8192];
        const char *argv[] = {"build/bin/z23-dev.exe", "dev", "proof", "remote", "--input={}", NULL};
        int rc = test_host_tool_capture(argv, out, sizeof(out), 30000);
        ASSERT(rc > 0);
        ASSERT(strstr(out, "REMOTE_PROOF_REFUSED") != NULL || strstr(out, "INVALID_INPUT") != NULL);
        PASS();
    }
    return failures;
}
#else
#include <unistd.h>

static const char rcmd_hex[] =
    "1111111111111111111111111111111111111111111111111111111111111111";

static bool rcmd_input(char *out, size_t cap, const char *destination,
                       bool duplicate)
{
    int n = snprintf(out, cap,
        "--input={\"repository\":\"%s\",\"destination\":\"%s\","
        "\"bundle\":\"missing.bundle\",\"offer\":\"missing.offer\","
        "\"local_commit\":\"%s\",\"remote_base\":\"%s\","
        "\"bundle_sha256\":\"%s\",\"git_tree\":\"%s\","
        "\"source_id\":\"%s\",\"signer_pubkey\":\"%s\","
        "\"source_root\":\"%s\",\"source_cas_root\":\"%s\","
        "\"changed_set_root\":\"%s\",\"impact_policy_root\":\"%s\"%s}",
        destination, destination, rcmd_hex, rcmd_hex, rcmd_hex, rcmd_hex,
        rcmd_hex, rcmd_hex, rcmd_hex, rcmd_hex, rcmd_hex, rcmd_hex,
        duplicate ? ",\"source_id\":\"2222222222222222222222222222222222222222222222222222222222222222\"" : "");
    return n > 0 && (size_t)n < cap;
}

static int rcmd_run(const char *source, const char *input, char *out, size_t cap)
{
    char exe[4096], env[4200];
    if (!getcwd(exe, sizeof(exe))) return -1;
    size_t len = strlen(exe);
    int n = snprintf(exe + len, sizeof(exe) - len, "/build/bin/z23-dev");
    if (n <= 0 || (size_t)n >= sizeof(exe) - len) return -1;
    n = snprintf(env, sizeof(env), "ZCL_DEV_SOURCE_ROOT=%s", source);
    if (n <= 0 || (size_t)n >= sizeof(env)) return -1;
    const char *argv[] = {"/usr/bin/env", env, exe, "dev", "proof", "remote", input, NULL};
    return test_host_tool_capture(argv, out, cap, 30000);
}

int test_dev_proof_remote_command(void)
{
    int failures = 0;
    char source[1024], foreign[1024], input[8192], out[16384];
    test_make_tmpdir(source, sizeof(source), "dev_proof_remote_command", "source");
    test_make_tmpdir(foreign, sizeof(foreign), "dev_proof_remote_command", "foreign");

    TEST("dev.proof.remote: missing assignment refuses before placement") {
        int rc = rcmd_run(source, "--input={}", out, sizeof(out));
        ASSERT(rc > 0);
        ASSERT(strstr(out, "REMOTE_PROOF_REFUSED") != NULL || strstr(out, "INVALID_INPUT") != NULL);
        PASS();
    }
    TEST("dev.proof.remote: foreign destination refuses before placement") {
        ASSERT(rcmd_input(input, sizeof(input), foreign, false));
        int rc = rcmd_run(source, input, out, sizeof(out));
        ASSERT(rc > 0);
        ASSERT(strstr(out, "REMOTE_PROOF_REFUSED") != NULL);
        ASSERT(strstr(out, "remote_invalid_input") != NULL);
        PASS();
    }
    TEST("dev.proof.remote: duplicate pin refuses before placement") {
        ASSERT(rcmd_input(input, sizeof(input), source, true));
        int rc = rcmd_run(source, input, out, sizeof(out));
        ASSERT(rc > 0);
        ASSERT(strstr(out, "remote_invalid_input") != NULL || strstr(out, "INVALID_INPUT") != NULL);
        PASS();
    }
    return failures;
}
#endif
