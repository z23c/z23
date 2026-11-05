/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * Exercise the actual development command in isolated local fixtures. */
#include "test/test_core.h"
#include "test/host_tool_capture.h"
#include "dev_proof.h"
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
_test_next:;
    return failures;
}
#else
#include <sys/stat.h>
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

static int rcmd_run(const char *binary, const char *source, const char *input,
                    char *out, size_t cap)
{
    char env[4200], home[4200];
    const char *admission = getenv("DEVBUILD_ACTIVE");
    if (!admission || strcmp(admission, "z23") != 0) return -1;
    int n;
    n = snprintf(env, sizeof(env), "ZCL_DEV_SOURCE_ROOT=%s", source);
    if (n <= 0 || (size_t)n >= sizeof(env)) return -1;
    n = snprintf(home, sizeof(home), "HOME=%s", source);
    if (n <= 0 || (size_t)n >= sizeof(home)) return -1;
    const char *argv[] = {"/usr/bin/env", "-i", "PATH=/usr/bin:/bin", "LC_ALL=C",
        "DEVBUILD_ACTIVE=z23", home, env, binary, "dev", "proof", "remote", input, NULL};
    return test_host_tool_capture(argv, out, cap, 30000);
}

static bool rcmd_git(const char *dir, const char *const args[])
{
    const char *argv[20] = {"/usr/bin/git", "-C", dir, "-c", "user.name=Fixture",
        "-c", "user.email=fixture@example.invalid", "-c", "commit.gpgsign=false"};
    size_t used = 9;
    for (size_t i = 0; args[i]; i++) {
        if (used + 1 >= sizeof(argv) / sizeof(argv[0])) return false;
        argv[used++] = args[i];
    }
    argv[used] = NULL;
    char out[4096];
    return zcl_spawn_capture(argv, out, sizeof(out), 30000) == 0;
}

static bool rcmd_copy(const char *source, const char *destination)
{
    FILE *in = fopen(source, "rb"), *out = in ? fopen(destination, "wb") : NULL;
    if (!in || !out) { if (in) fclose(in); return false; }
    char buffer[65536];
    bool ok = true;
    for (;;) {
        size_t n = fread(buffer, 1, sizeof(buffer), in);
        if (n && fwrite(buffer, 1, n, out) != n) { ok = false; break; }
        if (n < sizeof(buffer)) { if (ferror(in)) ok = false; break; }
    }
    if (fclose(in) != 0) ok = false;
    if (fclose(out) != 0) ok = false;
    return ok && chmod(destination, 0700) == 0;
}

static bool rcmd_repository(const char *base, char *primary, size_t primary_cap,
                            char *linked, size_t linked_cap, char *binary, size_t binary_cap)
{
    char current[4096], source[4200], build[1200], bindir[1200], ignore[1200];
    if (!getcwd(current, sizeof(current))) return false;
    if (snprintf(source, sizeof(source), "%s/build/bin/z23-dev", current) >= (int)sizeof(source) ||
        snprintf(primary, primary_cap, "%s/primary", base) >= (int)primary_cap ||
        snprintf(linked, linked_cap, "%s/linked", base) >= (int)linked_cap ||
        snprintf(build, sizeof(build), "%s/build", primary) >= (int)sizeof(build) ||
        snprintf(bindir, sizeof(bindir), "%s/bin", build) >= (int)sizeof(bindir) ||
        snprintf(binary, binary_cap, "%s/z23-dev", bindir) >= (int)binary_cap ||
        snprintf(ignore, sizeof(ignore), "%s/.gitignore", primary) >= (int)sizeof(ignore)) return false;
    if (mkdir(primary, 0700) != 0 ||
        !rcmd_git(primary, (const char *const[]){"init", "-q", NULL})) return false;
    FILE *f = fopen(ignore, "w");
    if (!f) return false;
    bool ok = fputs("/build/\n/.cache/\n", f) >= 0;
    if (fclose(f) != 0) ok = false;
    return ok && rcmd_git(primary, (const char *const[]){"add", ".gitignore", NULL}) &&
        rcmd_git(primary, (const char *const[]){"commit", "-q", "-m", "fixture", NULL}) &&
        rcmd_git(primary, (const char *const[]){"worktree", "add", "-q", "--detach", linked, "HEAD", NULL}) &&
        mkdir(build, 0700) == 0 && mkdir(bindir, 0700) == 0 && rcmd_copy(source, binary);
}

int test_dev_proof_remote_command(void)
{
    int failures = 0;
    char source[1024], foreign[1024], input[8192], out[16384], current[4096], binary[4200];
    test_make_tmpdir(source, sizeof(source), "dev_proof_remote_command", "source");
    test_make_tmpdir(foreign, sizeof(foreign), "dev_proof_remote_command", "foreign");
    if (!getcwd(current, sizeof(current)) ||
        snprintf(binary, sizeof(binary), "%s/build/bin/z23-dev", current) >= (int)sizeof(binary))
        return 1;

    TEST("dev.proof.remote: missing assignment refuses before placement") {
        int rc = rcmd_run(binary, source, "--input={}", out, sizeof(out));
        ASSERT(rc > 0);
        ASSERT(strstr(out, "REMOTE_PROOF_REFUSED") != NULL || strstr(out, "INVALID_INPUT") != NULL);
        PASS();
    }
    TEST("dev.proof.remote: foreign destination refuses before placement") {
        ASSERT(rcmd_input(input, sizeof(input), foreign, false));
        int rc = rcmd_run(binary, source, input, out, sizeof(out));
        ASSERT(rc > 0);
        ASSERT(strstr(out, "REMOTE_PROOF_REFUSED") != NULL);
        ASSERT(strstr(out, "remote_invalid_input") != NULL);
        PASS();
    }
    TEST("dev.proof.remote: duplicate pin refuses before placement") {
        ASSERT(rcmd_input(input, sizeof(input), source, true));
        int rc = rcmd_run(binary, source, input, out, sizeof(out));
        ASSERT(rc > 0);
        ASSERT(strstr(out, "remote_invalid_input") != NULL || strstr(out, "INVALID_INPUT") != NULL);
        PASS();
    }
    TEST("dev.proof.remote: primary checkout is refused and linked busy is reported") {
        char base[1024], primary[1100], linked[1100], fixture_binary[1200], why[256] = {0};
        test_make_tmpdir(base, sizeof(base), "dev_proof_remote_command", "worktrees");
        ASSERT(rcmd_repository(base, primary, sizeof(primary), linked, sizeof(linked),
                               fixture_binary, sizeof(fixture_binary)));
        ASSERT(rcmd_input(input, sizeof(input), primary, false));
        int rc = rcmd_run(fixture_binary, primary, input, out, sizeof(out));
        ASSERT(rc > 0);
        ASSERT(strstr(out, "remote_destination_not_owned") != NULL);
        int guard = -1;
        ASSERT_EQ(zcl_dev_proof_execution_acquire(linked, &guard, why, sizeof(why)), 1);
        bool input_ok = rcmd_input(input, sizeof(input), linked, false);
        rc = input_ok ? rcmd_run(fixture_binary, linked, input, out, sizeof(out)) : -1;
        zcl_dev_proof_execution_release(guard);
        ASSERT(input_ok);
        ASSERT(rc > 0);
        ASSERT(strstr(out, "REMOTE_PROOF_BUSY") != NULL);
        PASS();
    }
_test_next:;
    return failures;
}
#endif
