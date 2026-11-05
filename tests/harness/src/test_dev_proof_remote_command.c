/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * Exercise the actual development command in isolated local fixtures. */
#include "test/test_core.h"
#include "test/host_tool_capture.h"
#include "dev_proof.h"
#include "base/safe_alloc.h"
#include "json/json.h"
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
#include "test/dev_proof_remote_fixture.h"
#include <errno.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static const char rcmd_hex[] =
    "1111111111111111111111111111111111111111111111111111111111111111";

static bool rcmd_input_paths(char *out, size_t cap, const char *destination,
                             const char *bundle, const char *offer, bool duplicate)
{
    int n = snprintf(out, cap,
        "--input={\"repository\":\"%s\",\"destination\":\"%s\","
        "\"bundle\":\"%s\",\"offer\":\"%s\","
        "\"local_commit\":\"%s\",\"remote_base\":\"%s\","
        "\"bundle_sha256\":\"%s\",\"git_tree\":\"%s\","
        "\"source_id\":\"%s\",\"signer_pubkey\":\"%s\","
        "\"source_root\":\"%s\",\"source_cas_root\":\"%s\","
        "\"changed_set_root\":\"%s\",\"impact_policy_root\":\"%s\"%s}",
        destination, destination, bundle, offer, rcmd_hex, rcmd_hex, rcmd_hex, rcmd_hex,
        rcmd_hex, rcmd_hex, rcmd_hex, rcmd_hex, rcmd_hex, rcmd_hex,
        duplicate ? ",\"source_id\":\"2222222222222222222222222222222222222222222222222222222222222222\"" : "");
    return n > 0 && (size_t)n < cap;
}

static bool rcmd_input(char *out, size_t cap, const char *destination, bool duplicate)
{
    return rcmd_input_paths(out, cap, destination, "missing.bundle", "missing.offer", duplicate);
}

static int rcmd_run_extra(const char *binary, const char *source, const char *input,
                          const char *extra, char *out, size_t cap)
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
        "DEVBUILD_ACTIVE=z23", home, env, extra ? extra : "LC_ALL=C",
        binary, "dev", "proof", "remote", input, NULL};
    return test_host_tool_capture(argv, out, cap, 30000);
}

static int rcmd_run(const char *binary, const char *source, const char *input,
                    char *out, size_t cap)
{
    return rcmd_run_extra(binary, source, input, NULL, out, cap);
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

static bool rcmd_snapshot(const char *output, const char *leaf, long expected_size)
{
    struct json_value envelope = {0};
    if (!json_read(&envelope, output, strlen(output))) return false;
    const struct json_value *error = json_get(&envelope, "error");
    const struct json_value *facts = json_get(error, "facts");
    const struct json_value *location = json_get(facts, "retained_input_observation");
    const char *dir = location && location->type == JSON_STR ? json_get_str(location) : NULL;
    char path[4096];
    int n = dir ? snprintf(path, sizeof(path), "%s/%s", dir, leaf) : -1;
    struct stat st;
    bool ok = n > 0 && (size_t)n < sizeof(path) &&
        (expected_size == -1 ? lstat(path, &st) != 0 && errno == ENOENT :
         lstat(path, &st) == 0 && S_ISREG(st.st_mode) &&
         (expected_size == -2 ? st.st_size > 0 : st.st_size == expected_size));
    json_free(&envelope);
    return ok;
}

static bool rcmd_real_input(char *out, size_t cap, const struct rpp_fixture *f,
                            const char *destination)
{
    const struct zcl_dev_proof_remote_assignment *a = &f->assignment;
    char signer[65], source[65], cas[65], changed[65], impact[65];
    zcl_hex_encode(a->expected.signer_pubkey, 32, signer);
    zcl_hex_encode(a->expected.source_root, 32, source);
    zcl_hex_encode(a->expected.source_cas_root, 32, cas);
    zcl_hex_encode(a->expected.changed_set_root, 32, changed);
    zcl_hex_encode(a->expected.impact_policy_root, 32, impact);
    int n = snprintf(out, cap,
        "--input={\"repository\":\"%s\",\"destination\":\"%s\","
        "\"bundle\":\"%s\",\"offer\":\"%s\","
        "\"local_commit\":\"%s\",\"remote_base\":\"%s\","
        "\"bundle_sha256\":\"%s\",\"git_tree\":\"%s\","
        "\"source_id\":\"%s\",\"signer_pubkey\":\"%s\","
        "\"source_root\":\"%s\",\"source_cas_root\":\"%s\","
        "\"changed_set_root\":\"%s\",\"impact_policy_root\":\"%s\"}",
        f->receiver, destination, f->bundle, f->offer, f->tip, f->base,
        a->bundle_sha256, a->git_tree, a->source_id, signer, source, cas,
        changed, impact);
    return n > 0 && (size_t)n < cap;
}

static bool rcmd_recovery_facts(const char *output, const struct rpp_fixture *f,
                                const char *linked)
{
    struct json_value envelope = {0};
    if (!json_read(&envelope, output, strlen(output))) return false;
    const struct json_value *error = json_get(&envelope, "error");
    const struct json_value *facts = json_get(error, "facts");
    const char *local = json_get_str(json_get(facts, "local_commit"));
    const char *base = json_get_str(json_get(facts, "remote_base"));
    const char *observation = json_get_str(json_get(facts, "retained_input_observation"));
    const char *producer = json_get_str(json_get(facts, "producer_executable"));
    const char *next = json_get_str(json_get(error, "next_action"));
    char expected[4096];
    int n = snprintf(expected, sizeof(expected), "%s/build/bin/z23-dev", linked);
    bool ok = n > 0 && (size_t)n < sizeof(expected) && strcmp(local, f->tip) == 0 &&
        strcmp(base, f->base) == 0 && observation[0] && strcmp(producer, expected) == 0 &&
        strstr(next, "dev.proof.retry") && strstr(next, "dev.proof.remote");
    json_free(&envelope);
    return ok;
}

static bool rcmd_repository_paths(const char *base, char *primary, size_t primary_cap,
    char *linked, size_t linked_cap, char *binary, size_t binary_cap,
    char source[4200], char build[1200], char bindir[1200], char ignore[1200])
{
    char current[4096];
    if (!getcwd(current, sizeof(current))) return false;
    if (snprintf(source, 4200, "%s/build/bin/z23-dev", current) >= 4200 ||
        snprintf(primary, primary_cap, "%s/primary", base) >= (int)primary_cap ||
        snprintf(linked, linked_cap, "%s/linked", base) >= (int)linked_cap ||
        snprintf(build, 1200, "%s/build", primary) >= 1200 ||
        snprintf(bindir, 1200, "%s/bin", build) >= 1200 ||
        snprintf(binary, binary_cap, "%s/z23-dev", bindir) >= (int)binary_cap ||
        snprintf(ignore, 1200, "%s/.gitignore", primary) >= 1200) return false;
    return true;
}

static bool rcmd_repository(const char *base, char *primary, size_t primary_cap,
                            char *linked, size_t linked_cap, char *binary, size_t binary_cap)
{
    char source[4200], build[1200], bindir[1200], ignore[1200];
    if (!rcmd_repository_paths(base, primary, primary_cap, linked, linked_cap,
                               binary, binary_cap, source, build, bindir, ignore)) return false;
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

static bool rcmd_recovery_prepare(const char *current, const char *binary,
    struct rpp_fixture *fixture, char linked[1024], char fixture_binary[1100],
    char input[8192])
{
    char build[1024], bindir[1024];
    return setenv("ZCL_DEVLOOP_TEST_PROCESS", "1", 1) == 0 &&
        rpp_setup(fixture, current) &&
        snprintf(linked, 1024, "%s/linked", fixture->root) > 0 &&
        RPP_GIT(fixture->receiver, NULL, 0, "worktree", "add", "-q", "--detach", linked, "HEAD") &&
        snprintf(build, sizeof(build), "%s/build", fixture->receiver) > 0 &&
        snprintf(bindir, sizeof(bindir), "%s/bin", build) > 0 &&
        snprintf(fixture_binary, 1100, "%s/z23-dev", bindir) > 0 &&
        mkdir(build, 0700) == 0 && mkdir(bindir, 0700) == 0 &&
        rcmd_copy(binary, fixture_binary) &&
        rcmd_real_input(input, 8192, fixture, linked);
}

static bool rcmd_recovery(const char *current, const char *binary)
{
    struct rpp_fixture fixture;
    char linked[1024], fixture_binary[1100], input[8192], out[16384];
    if (!rcmd_recovery_prepare(current, binary, &fixture, linked, fixture_binary, input)) return false;
    int rc = rcmd_run(fixture_binary, linked, input, out, sizeof(out));
    bool ok = rc > 0 &&
        (strstr(out, "proof_producer_source_mismatch") != NULL ||
         strstr(out, "proof_producer_source_id_unavailable") != NULL) &&
        rcmd_recovery_facts(out, &fixture, linked) &&
        rcmd_snapshot(out, "source.bundle", -2) &&
        rcmd_snapshot(out, "source.offer.json", -2);
    if (!ok) printf("remote recovery fixture rc=%d output=%s\n", rc, out);
    return ok;
}

struct rcmd_expect_fixture {
    char root[1024], primary[1200], linked[1200], binary[1400];
    char base[65], local[65], tree[65];
    struct dev_source_record source;
    uint8_t git_source[32], changed[32], impact[32];
};

/* A committed capture-helper fixture delegates to the maintained helper,
 * but can perform one deterministic concurrent-source mutation when armed.
 * No identity/root output is replaced or synthesized. */
static bool rcmd_expect_capture_fixture(struct rcmd_expect_fixture *f)
{
    char path[1400], original[1400];
    if (!rpp_path(path, sizeof(path), f->primary, "tools/dev/source-identity.sh") ||
        !rpp_path(original, sizeof(original), f->root, "capture-original") ||
        !rcmd_copy(path, original)) return false;
    FILE *in = fopen(original, "rb"), *out = in ? fopen(path, "wb") : NULL;
    if (!out) { if (in) fclose(in); return false; }
    bool ok = fputs("#!/usr/bin/env bash\n"
        "if test -f .cache/remote-expect-drift; then\n"
        "  rm .cache/remote-expect-drift\n"
        "  printf '\\nCapture-time mutation.\\n' >> README.md\n"
        "fi\n", out) >= 0;
    char bytes[8192]; size_t n;
    while ((n = fread(bytes, 1, sizeof(bytes), in)) != 0)
        if (fwrite(bytes, 1, n, out) != n) { ok = false; break; }
    if (ferror(in)) ok = false;
    if (fclose(in) != 0) ok = false;
    if (fclose(out) != 0) ok = false;
    return ok;
}

static bool rcmd_expect_commit(struct rcmd_expect_fixture *f)
{
    char readme[1400];
    if (!rpp_path(readme, sizeof(readme), f->primary, "README.md")) return false;
    FILE *file = fopen(readme, "ab");
    if (!file) return false;
    bool ok = fputs("\nRemote expectation full-source control.\n", file) >= 0;
    if (fclose(file) != 0) ok = false;
    return ok && rcmd_expect_capture_fixture(f) &&
        RPP_GIT(f->primary, NULL, 0, "add", "README.md", "tools/dev/source-identity.sh") &&
        RPP_GIT(f->primary, NULL, 0, "commit", "--quiet", "-m", "full-source expectation control") &&
        RPP_GIT(f->primary, f->local, sizeof(f->local), "rev-parse", "HEAD") &&
        RPP_GIT(f->primary, f->tree, sizeof(f->tree), "rev-parse", "HEAD^{tree}");
}

/* Source comes from an explicit Git commit, never the caller's dirty files.
 * Borrow immutable objects only; all checkout, index and private commits are
 * in this isolated repository. This is the full maintained source tree. */
static bool rcmd_expect_checkout(struct rcmd_expect_fixture *f, const char *current,
                                  const char *binary)
{
    memset(f, 0, sizeof(*f));
    test_make_tmpdir(f->root, sizeof(f->root), "dev_proof_remote_command", "full-source-expect");
    return rpp_path(f->primary, sizeof(f->primary), f->root, "primary") &&
        rpp_path(f->linked, sizeof(f->linked), f->root, "linked") &&
        rpp_path(f->binary, sizeof(f->binary), f->primary, "build/bin/z23-dev") &&
        RPP_GIT(current, f->base, sizeof(f->base), "rev-parse", "HEAD") &&
        RPP_GIT(current, NULL, 0, "clone", "--quiet", "--shared", "--no-checkout", current, f->primary) &&
        RPP_GIT(f->primary, NULL, 0, "checkout", "--quiet", "--detach", f->base) &&
        rcmd_expect_commit(f) &&
        RPP_GIT(f->primary, NULL, 0, "worktree", "add", "--quiet", "--detach", f->linked, f->local) &&
        rpp_parents(f->binary) && rcmd_copy(binary, f->binary);
}

static bool rcmd_expect_native(struct rcmd_expect_fixture *f)
{
    char scratch[1400], changed[1400], why[512] = {0};
    struct dev_source_record before = {0};
    bool ok = rpp_path(scratch, sizeof(scratch), f->root, "native-raw") &&
        rpp_path(changed, sizeof(changed), f->root, "native-changed") &&
        zcl_dev_source_identity_capture(f->linked, &before, why, sizeof(why)) &&
        zcl_dev_proof_source_plan_roots(f->linked, f->base, f->local, scratch, changed,
            f->git_source, f->changed, f->impact, why, sizeof(why)) &&
        zcl_dev_source_identity_capture(f->linked, &f->source, why, sizeof(why));
    if (!ok) printf("full-source native expectation prerequisite: %s\n", why);
    return ok && f->source.cas_present && f->source.cas_files_total > 1000u &&
        !strcmp(before.source_id, f->source.source_id) &&
        !strcmp(before.cas_root_sha3, f->source.cas_root_sha3) &&
        !strcmp(before.mutation_id, f->source.mutation_id);
}

static bool rcmd_expect_input_operation(const struct rcmd_expect_fixture *f, const char *base,
                              const char *extra, const char *operation, char input[8192])
{
    int n = snprintf(input, 8192,
        "--input={\"operation\":%s,\"repository\":\"%s\","
        "\"local_commit\":\"%s\",\"remote_base\":\"%s\",\"git_tree\":\"%s\","
        "\"signer_pubkey\":\"%s\"%s}", operation, f->primary, f->local, base, f->tree, rcmd_hex, extra);
    return n > 0 && n < 8192;
}

static bool rcmd_expect_input(const struct rcmd_expect_fixture *f, const char *base,
                              const char *extra, char input[8192])
{
    return rcmd_expect_input_operation(f, base, extra, "\"expect\"", input);
}

static int rcmd_expect_run(const struct rcmd_expect_fixture *f, const char *input,
                          const char *extra, char *out, size_t cap)
{
    char root[1400], home[1400], path[8192];
    int n = snprintf(root, sizeof(root), "ZCL_DEV_SOURCE_ROOT=%s", f->linked);
    int m = snprintf(home, sizeof(home), "HOME=%s", f->linked);
    int p = snprintf(path, sizeof(path), "PATH=%s", getenv("PATH") ? getenv("PATH") : "");
    if (n <= 0 || (size_t)n >= sizeof(root) || m <= 0 || (size_t)m >= sizeof(home) ||
        p <= 0 || (size_t)p >= sizeof(path)) return -1;
    const char *argv[] = {"/usr/bin/env", "-i", path, "LC_ALL=C",
        "DEVBUILD_ACTIVE=z23", home, root, extra ? extra : "LC_ALL=C",
        f->binary, "dev", "proof", "remote", input, NULL};
    return test_host_tool_capture(argv, out, cap, 120000);
}

static bool rcmd_expect_no_proof(const struct rcmd_expect_fixture *f)
{
    static const char *const names[] = {"receipts", "requests", "attempts"};
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        char path[1600];
        int n = snprintf(path, sizeof(path), "%s/.cache/zcl-dev-proof/%s", f->linked, names[i]);
        if (n <= 0 || (size_t)n >= sizeof(path)) return false;
        DIR *dir = opendir(path);
        if (!dir) { if (errno == ENOENT) continue; return false; }
        bool empty = true;
        for (;;) {
            errno = 0; struct dirent *entry = readdir(dir);
            if (!entry) { if (errno) empty = false; break; }
            if (strcmp(entry->d_name, ".") && strcmp(entry->d_name, "..")) { empty = false; break; }
        }
        if (closedir(dir) != 0 || !empty) return false;
    }
    return true;
}

static bool rcmd_expect_no_scratch(const struct rcmd_expect_fixture *f)
{
    char path[1600];
    if (!rpp_path(path, sizeof(path), f->linked, ".cache/zcl-dev-proof")) return false;
    DIR *dir = opendir(path);
    if (!dir) return false;
    bool ok = true;
    for (;;) {
        errno = 0;
        struct dirent *entry = readdir(dir);
        if (!entry) { if (errno) ok = false; break; }
        if (!strncmp(entry->d_name, "remote-expect-", 14)) { ok = false; break; }
    }
    if (closedir(dir) != 0) ok = false;
    return ok;
}

static bool rcmd_expect_refused(const char *out, const char *reason);

static bool rcmd_expect_git_config(struct rcmd_expect_fixture *f)
{
    static const char *const keys[] = {"filter.fixture.clean", "remote.fixture.promisor"};
    static const char *const reasons[] = {"remote_git_external_filter_or_config", "remote_git_lazy_fetch_config"};
    char input[8192], out[16384];
    if (!rcmd_expect_input(f, f->base, "", input)) return false;
    for (size_t i = 0; i < 2; i++) {
        if (!RPP_GIT(f->primary, NULL, 0, "config", keys[i], "true")) return false;
        int rc = rcmd_expect_run(f, input, NULL, out, sizeof(out));
        bool ok = rc > 0 && rcmd_expect_refused(out, reasons[i]);
        if (!RPP_GIT(f->primary, NULL, 0, "config", "--unset", keys[i]) || !ok) return false;
    }
    return rcmd_expect_no_scratch(f);
}

static bool rcmd_expect_field(const struct json_value *capsule, const char *key, const char *expected)
{
    const struct json_value *v = json_get(capsule, key);
    return v && v->type == JSON_STR && !strcmp(json_get_str(v), expected);
}

static bool rcmd_expect_roots(const struct rcmd_expect_fixture *f, const struct json_value *capsule)
{
    char source[65], changed[65], impact[65];
    zcl_hex_encode(f->git_source, 32, source);
    zcl_hex_encode(f->changed, 32, changed);
    zcl_hex_encode(f->impact, 32, impact);
    return rcmd_expect_field(capsule, "source_id", f->source.source_id) &&
        rcmd_expect_field(capsule, "source_root", source) &&
        rcmd_expect_field(capsule, "source_cas_root", f->source.cas_root_sha3) &&
        rcmd_expect_field(capsule, "changed_set_root", changed) &&
        rcmd_expect_field(capsule, "impact_policy_root", impact) && strcmp(source, f->source.source_id);
}

static bool rcmd_expect_capsule(const struct rcmd_expect_fixture *f, const char *out)
{
    struct json_value envelope = {0};
    if (!json_read(&envelope, out, strlen(out))) return false;
    const struct json_value *data = json_get(&envelope, "data");
    const struct json_value *capsule = json_get(data, "expectation");
    const struct json_value *executed = json_get(data, "proof_executed");
    bool ok = json_get_bool(json_get(&envelope, "ok")) &&
        rcmd_expect_field(data, "operation", "expect") &&
        rcmd_expect_field(data, "status", "EXPECTATION_READY") &&
        executed && executed->type == JSON_BOOL && !json_get_bool(executed) &&
        rcmd_expect_field(capsule, "local_commit", f->local) &&
        rcmd_expect_field(capsule, "remote_base", f->base) &&
        rcmd_expect_field(capsule, "git_tree", f->tree) &&
        rcmd_expect_field(capsule, "signer_pubkey", rcmd_hex) && rcmd_expect_roots(f, capsule);
    json_free(&envelope);
    return ok;
}

static bool rcmd_expect_refused(const char *out, const char *reason)
{
    struct json_value envelope = {0};
    if (!json_read(&envelope, out, strlen(out))) return false;
    const struct json_value *data = json_get(&envelope, "data");
    const struct json_value *error = json_get(&envelope, "error");
    bool ok = !json_get_bool(json_get(&envelope, "ok")) &&
        !json_get(data, "expectation") && !json_get(data, "source_root") &&
        rcmd_expect_field(error, "code", "REMOTE_PROOF_REFUSED") &&
        rcmd_expect_field(error, "evidence", reason) && !strstr(out, "EXPECTATION_READY");
    if (!ok) printf("expectation refusal mismatch expected=%s actual=%s\n", reason, out);
    json_free(&envelope);
    return ok;
}

static bool rcmd_expect_normalize_refused(const char *out, const char *message)
{
    struct json_value envelope = {0};
    if (!json_read(&envelope, out, strlen(out))) return false;
    const struct json_value *error = json_get(&envelope, "error");
    const struct json_value *mutated = json_get(error, "mutated");
    const struct json_value *data = json_get(&envelope, "data");
    bool ok = !json_get_bool(json_get(&envelope, "ok")) &&
        rcmd_expect_field(error, "code", "INVALID_INPUT") &&
        rcmd_expect_field(error, "phase", "normalize") &&
        rcmd_expect_field(error, "evidence", "dev.proof.remote") &&
        !strncmp(json_get_str(json_get(error, "message")), message, strlen(message)) &&
        mutated && mutated->type == JSON_BOOL && !json_get_bool(mutated) &&
        !json_get(data, "expectation") && !json_get(data, "source_root");
    if (!ok) printf("operation normalization mismatch expected=%s actual=%s\n", message, out);
    json_free(&envelope);
    return ok;
}

static bool rcmd_expect_operations(struct rcmd_expect_fixture *f)
{
    static const char *const operations[] = {"7", "\"\"", "\"unknown\""};
    static const char type_error[] = "invalid type or range for input key 'operation';";
    char input[8192], out[16384];
    for (size_t i = 0; i < 3; i++) {
        if (!rcmd_expect_input_operation(f, f->base, "", operations[i], input)) return false;
        int rc = rcmd_expect_run(f, input, NULL, out, sizeof(out));
        bool refused = i < 2 ? rcmd_expect_normalize_refused(out, type_error) :
            rcmd_expect_refused(out, "remote_unknown_operation");
        if (rc <= 0 || !refused) return false;
    }
    return true;
}

static bool rcmd_expect_authority(struct rcmd_expect_fixture *f)
{
    char input[8192], out[16384];
    if (!rcmd_expect_input(f, f->base, "", input)) return false;
    int rc = rcmd_expect_run(f, input, "DEVBUILD_ACTIVE=none", out, sizeof(out));
    if (rc <= 0 || !rcmd_expect_refused(out, "remote_host_admission_required")) return false;
    if (!rcmd_expect_input(f, f->base, ",\"operation\":\"expect\"", input)) return false;
    rc = rcmd_expect_run(f, input, NULL, out, sizeof(out));
    return rc > 0 && rcmd_expect_normalize_refused(out, "duplicate input key 'operation';") &&
        rcmd_expect_operations(f);
}

static bool rcmd_expect_sentinel_file(const char *git, const char *marker)
{
    FILE *file = fopen(git, "wb");
    if (!file) return false;
    bool written = fprintf(file, "#!/bin/sh\nprintf called > '%s'\nexit 87\n", marker) > 0;
    if (fclose(file) != 0) written = false;
    return written && chmod(git, 0700) == 0;
}

static bool rcmd_expect_path_sentinel(struct rcmd_expect_fixture *f)
{
    char dir[1400], git[1500], marker[1500], env[10000], input[8192], out[16384];
    if (!rpp_path(dir, sizeof(dir), f->root, "caller-bin") || mkdir(dir, 0700) != 0 ||
        !rpp_path(git, sizeof(git), dir, "git") ||
        !rpp_path(marker, sizeof(marker), f->root, "unexpected-git")) return false;
    int n = snprintf(env, sizeof(env), "PATH=%s:%s", dir, getenv("PATH") ? getenv("PATH") : "");
    if (!rcmd_expect_sentinel_file(git, marker) || n <= 0 || (size_t)n >= sizeof(env) ||
        !rcmd_expect_input(f, f->base, "", input)) return false;
    int rc = rcmd_expect_run(f, input, env, out, sizeof(out));
    return rc == 0 && rcmd_expect_capsule(f, out) && access(marker, F_OK) != 0 &&
        errno == ENOENT && rcmd_expect_no_scratch(f);
}

static bool rcmd_expect_capture_drift(struct rcmd_expect_fixture *f)
{
    char marker[1500], input[8192], out[16384];
    if (!rpp_path(marker, sizeof(marker), f->linked, ".cache/remote-expect-drift")) return false;
    FILE *file = fopen(marker, "wb");
    if (!file) return false;
    if (fclose(file) != 0 || !rcmd_expect_input(f, f->base, "", input)) return false;
    int rc = rcmd_expect_run(f, input, NULL, out, sizeof(out));
    /* README is outside the build-source hash inventory: the mandatory final
     * exact-clean check must still refuse this real capture-time mutation. */
    char diff[4096];
    bool changed = RPP_GIT(f->linked, diff, sizeof(diff), "diff", "--", "README.md") &&
        strstr(diff, "Capture-time mutation.");
    bool ok = rc > 0 && rcmd_expect_refused(out, "remote_expect_generation_changed") && changed &&
        access(marker, F_OK) != 0 && errno == ENOENT && rcmd_expect_no_scratch(f);
    if (!ok) printf("expectation capture drift rc=%d: %s\n", rc, out);
    return ok && RPP_GIT(f->linked, NULL, 0, "restore", "--", "README.md");
}

static bool rcmd_expect_negative(struct rcmd_expect_fixture *f)
{
    char input[8192], out[16384], path[1400];
    if (!rcmd_expect_input(f, f->local, "", input)) return false;
    int rc = rcmd_expect_run(f, input, NULL, out, sizeof(out));
    if (rc <= 0 || !rcmd_expect_refused(out, "changed_set_empty")) return false;
    if (!rpp_path(path, sizeof(path), f->linked, "README.md")) return false;
    FILE *file = fopen(path, "ab");
    if (!file) return false;
    bool dirty = fputs("\nUncommitted expectation drift.\n", file) >= 0;
    if (fclose(file) != 0) dirty = false;
    if (!dirty || !rcmd_expect_input(f, f->base, "", input)) return false;
    rc = rcmd_expect_run(f, input, NULL, out, sizeof(out));
    bool ok = rc > 0 && rcmd_expect_refused(out, "remote_expect_generation_not_exact_clean");
    if (!ok) printf("expectation dirty refusal rc=%d: %s\n", rc, out);
    return ok;
}

static bool rcmd_expect_control(struct rcmd_expect_fixture *f, const char *name,
                               bool (*run)(struct rcmd_expect_fixture *))
{
    bool ok = run(f);
    printf("expectation control %s: %s\n", name, ok ? "PASS" : "FAIL");
    return ok;
}

static bool rcmd_expect_controls(struct rcmd_expect_fixture *f)
{
    if (!rcmd_expect_no_scratch(f)) { puts("expectation scratch retirement: FAIL"); return false; }
    return rcmd_expect_control(f, "caller PATH sentinel", rcmd_expect_path_sentinel) &&
        rcmd_expect_control(f, "configured Git refusal", rcmd_expect_git_config) &&
        rcmd_expect_control(f, "capture-time drift", rcmd_expect_capture_drift) &&
        rcmd_expect_control(f, "admission and operation", rcmd_expect_authority) &&
        rcmd_expect_control(f, "empty change and dirty generation", rcmd_expect_negative) &&
        rcmd_expect_no_proof(f);
}

static bool rcmd_expect_full_source(const char *current, const char *binary)
{
    struct rcmd_expect_fixture *f = zcl_calloc(1, sizeof(*f), "full-source expect fixture");
    if (!f) return false;
    bool ok = setenv("ZCL_DEVLOOP_TEST_PROCESS", "1", 1) == 0 &&
        rcmd_expect_checkout(f, current, binary) && rcmd_expect_native(f);
    char input[8192], out[16384];
    if (ok) {
        ok = rcmd_expect_input(f, f->base, "", input);
        int rc = ok ? rcmd_expect_run(f, input, NULL, out, sizeof(out)) : -1;
        printf("full-source expect CLI rc=%d: %s\n", rc, rc >= 0 ? out : "capture failed");
        ok = rc == 0 && rcmd_expect_capsule(f, out);
    }
    if (ok) ok = rcmd_expect_controls(f);
    if (ok) ok = test_rm_rf_recursive(f->root) == 0;
    else printf("full-source expectation fixture retained: %s\n", f->root);
    free(f);
    return ok;
}

static int rcmd_test_expect_full_source(const char *current, const char *binary)
{
    int failures = 0;
    TEST("dev.proof.remote: full-source expectation uses native independent roots without executing proof") {
        fflush(NULL);
        pid_t child = fork();
        ASSERT(child >= 0);
        if (child == 0) {
            bool ok = rcmd_expect_full_source(current, binary);
            fflush(NULL);
            _exit(ok ? 0 : 1);
        }
        int status = 0;
        ASSERT_EQ(waitpid(child, &status, 0), child);
        ASSERT(WIFEXITED(status) && WEXITSTATUS(status) == 0);
        PASS();
    }
_test_next:;
    return failures;
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
        rc = rcmd_run_extra(fixture_binary, linked, input,
                            "LD_AUDIT=/nonexistent-z23-fixture.so", out, sizeof(out));
        ASSERT(rc > 0);
        ASSERT(strstr(out, "remote_git_environment_redirected") != NULL);
        char offer[1200], bundle[1200];
        ASSERT(snprintf(offer, sizeof(offer), "%s/large.offer", base) > 0);
        ASSERT(snprintf(bundle, sizeof(bundle), "%s/readable.bundle", base) > 0);
        FILE *readable = fopen(bundle, "wb");
        ASSERT(readable != NULL);
        bool bundle_written = fwrite("bundle", 1, 6, readable) == 6;
        bool bundle_closed = fclose(readable) == 0;
        ASSERT(bundle_written && bundle_closed);
        FILE *large = fopen(offer, "wb");
        ASSERT(large != NULL);
        bool written = fseek(large, 16384, SEEK_SET) == 0 && fputc('x', large) != EOF;
        bool closed = fclose(large) == 0;
        ASSERT(written && closed);
        ASSERT(rcmd_input_paths(input, sizeof(input), linked, bundle, offer, false));
        rc = rcmd_run(fixture_binary, linked, input, out, sizeof(out));
        ASSERT(rc > 0);
        ASSERT(strstr(out, "remote_transport_bytes_mismatch") != NULL);
        ASSERT(rcmd_snapshot(out, "source.offer.json", -1));
        ASSERT(rcmd_snapshot(out, "source.bundle", -1));
        large = fopen(offer, "wb");
        ASSERT(large != NULL);
        written = fseek(large, 16383, SEEK_SET) == 0 && fputc('x', large) != EOF;
        closed = fclose(large) == 0;
        ASSERT(written && closed);
        rc = rcmd_run(fixture_binary, linked, input, out, sizeof(out));
        ASSERT(rc > 0);
        ASSERT(strstr(out, "remote_transport_bytes_mismatch") != NULL);
        ASSERT(rcmd_snapshot(out, "source.offer.json", 16384));
        ASSERT(rcmd_snapshot(out, "source.bundle", 6));
        PASS();
    }
    TEST("dev.proof.remote: producer mismatch retains actionable recovery evidence") {
        fflush(NULL);
        pid_t child = fork();
        ASSERT(child >= 0);
        if (child == 0) {
            bool ok = rcmd_recovery(current, binary);
            fflush(NULL);
            _exit(ok ? 0 : 1);
        }
        int status = 0;
        ASSERT_EQ(waitpid(child, &status, 0), child);
        ASSERT(WIFEXITED(status) && WEXITSTATUS(status) == 0);
        PASS();
    }
    failures += rcmd_test_expect_full_source(current, binary);
_test_next:;
    return failures;
}
#endif
