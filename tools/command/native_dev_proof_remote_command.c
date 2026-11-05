/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * Purpose: owner-invoked placement and proof of one pinned remote source. */
#include "command/native_command.h"
#include "json/json.h"
#ifdef ZCL_DEV_BUILD
#include "base/bytes.h"
#include "base/hex.h"
#include "base/safe_alloc.h"
#include "command/native_dev_job.h"
#include "dev_proof_remote.h"
#include "platform/directory_compat.h"
#include "platform/positioned_file.h"
#include "platform/private_directory.h"
#include "platform/private_file.h"
#include "platform/os_proc.h"
#include "platform/temp_directory.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

static const char *remote_text(const struct json_value *input, const char *key)
{
    if (!input || input->type != JSON_OBJ) return NULL;
    const struct json_value *found = NULL;
    for (size_t i = 0; i < json_size(input); i++) {
        if (strcmp(input->keys[i], key) != 0) continue;
        if (found) return NULL;
        found = json_at(input, i);
    }
    return found && found->type == JSON_STR && json_get_str(found)[0]
        ? json_get_str(found) : NULL;
}

static bool remote_hex(const struct json_value *input, const char *key, uint8_t out[32])
{
    const char *s = remote_text(input, key);
    return s && strlen(s) == 64 && zcl_hex_decode_lower(s, out, 32);
}

static bool remote_copy_hex(const struct json_value *input, const char *key, char out[65])
{
    uint8_t decoded[32];
    const char *s = remote_text(input, key);
    if (!s || !remote_hex(input, key, decoded)) return false;
    memcpy(out, s, 65);
    return true;
}

static bool remote_oid(const char *s)
{
    if (!s) return false;
    size_t n = strlen(s);
    if (n != 40 && n != 64) return false;
    for (size_t i = 0; i < n; i++)
        if (!((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f')))
            return false;
    return true;
}

static bool remote_assignment(const struct json_value *input,
                              struct zcl_dev_proof_remote_assignment *a)
{
    a->repository = remote_text(input, "repository");
    a->destination = remote_text(input, "destination");
    a->bundle = remote_text(input, "bundle");
    a->offer = remote_text(input, "offer");
    a->expected.local_commit = remote_text(input, "local_commit");
    a->expected.remote_base = remote_text(input, "remote_base");
    return a->repository && a->destination && a->bundle && a->offer &&
        remote_oid(a->expected.local_commit) && remote_oid(a->expected.remote_base) &&
        remote_copy_hex(input, "bundle_sha256", a->bundle_sha256) &&
        remote_oid(remote_text(input, "git_tree")) &&
        snprintf(a->git_tree, sizeof(a->git_tree), "%s", remote_text(input, "git_tree")) > 0 &&
        remote_copy_hex(input, "source_id", a->source_id) &&
        remote_hex(input, "signer_pubkey", a->expected.signer_pubkey) &&
        remote_hex(input, "source_root", a->expected.source_root) &&
        remote_hex(input, "source_cas_root", a->expected.source_cas_root) &&
        remote_hex(input, "changed_set_root", a->expected.changed_set_root) &&
        remote_hex(input, "impact_policy_root", a->expected.impact_policy_root);
}

static bool remote_owner(void *ctx, const char *root, char *why, size_t cap)
{
    const char *expected = ctx;
    bool ok = root && expected && strcmp(root, expected) == 0 &&
        zcl_dev_job_linked_worktree_registered(root);
    if (!ok && why && cap) (void)snprintf(why, cap, "remote_destination_not_owned");
    return ok;
}

static void remote_fail(struct zcl_command_reply *reply, const char *phase,
                        const char *why, bool mutated, bool busy);

#if !defined(_WIN32)
struct remote_expectation {
    const char *local, *base, *tree, *repository;
    uint8_t signer[32], source[32], changed[32], impact[32];
    struct dev_source_record before, after;
    char scratch[4096], raw_changed[4200], changed_path[4200];
};

/* Existing helpers inherit the environment. Refuse redirection before they
 * inspect Git or execute the pinned source's bounded capture helper. */
static bool remote_expect_environment(char *why, size_t cap)
{
    const char *admission = getenv("DEVBUILD_ACTIVE");
    if (!admission || strcmp(admission, "z23")) {
        (void)snprintf(why, cap, "remote_host_admission_required");
        return false;
    }
    extern char **environ;
    static const char *const prefixes[] = {
        "GIT_", "LD_", "DYLD_", "BASH_ENV=", "ENV=", "ZCL_BIN_DIR=",
        "ZCL_SOURCE_IDENTITY_", "ZCL_SOVEREIGN_SOURCE_ROOT=",
    };
    for (char **entry = environ; entry && *entry; entry++)
        for (size_t i = 0; i < sizeof(prefixes) / sizeof(prefixes[0]); i++)
            if (!strncmp(*entry, prefixes[i], strlen(prefixes[i]))) {
                (void)snprintf(why, cap, "remote_git_environment_redirected");
                return false;
            }
    return true;
}

/* Only this child gets a fixed Git/helper search path. Preserve the admitted
 * caller's environment and avoid setenv() races in an embedding process. */
static const char **remote_expect_child_env(const char *root, char source[4200])
{
    extern char **environ;
    size_t count = 0;
    while (environ && environ[count]) count++;
    const char **env = zcl_calloc(count + 3u, sizeof(*env), "expect child environment");
    if (!env) return NULL;
    int n = snprintf(source, 4200, "ZCL_DEV_SOURCE_ROOT=%s", root);
    if (n <= 0 || n >= 4200) { free(env); return NULL; }
    size_t used = 0;
    for (size_t i = 0; i < count; i++)
        if (strncmp(environ[i], "PATH=", 5) && strncmp(environ[i], "ZCL_DEV_SOURCE_ROOT=", 20))
            env[used++] = environ[i];
    env[used++] = "PATH=/usr/bin:/bin";
    env[used] = source;
    return env;
}

static bool remote_expect_child_payload(const struct json_value *body)
{
    const struct json_value *executed = json_get(body, "proof_executed");
    const struct json_value *capsule = json_get(body, "expectation");
    return !strcmp(json_get_str(json_get(body, "operation")), "expect") &&
        !strcmp(json_get_str(json_get(body, "status")), "EXPECTATION_READY") &&
        executed && executed->type == JSON_BOOL && !json_get_bool(executed) &&
        capsule && capsule->type == JSON_OBJ;
}

static bool remote_expect_child_result(struct zcl_command_reply *reply,
    const struct zcl_devloop_process_result *process)
{
    struct json_value envelope = {0}, data = {0};
    bool parsed = !process->timed_out && !process->cancelled && !process->term_signal &&
        !process->output_truncated && json_read(&envelope, process->output, process->output_len);
    const struct json_value *body = json_get(&envelope, "data");
    bool ok = parsed && process->exit_code == 0 && json_get_bool(json_get(&envelope, "ok")) &&
        remote_expect_child_payload(body) && json_copy_checked(&data, body);
    if (ok) { json_free(&reply->data); reply->data = data; json_init(&data); }
    else {
        const struct json_value *error = json_get(&envelope, "error");
        const char *why = json_get_str(json_get(error, "evidence"));
        bool busy = !strcmp(json_get_str(json_get(error, "code")), "REMOTE_PROOF_BUSY");
        remote_fail(reply, "expect", why[0] ? why : "remote_expect_child_failed", true, busy);
        const struct json_value *retained = json_get(body, "retained_input_observation");
        if (retained && retained->type == JSON_STR)
            (void)json_push_kv_str(&reply->data, "retained_input_observation", json_get_str(retained));
    }
    json_free(&envelope); json_free(&data);
    return ok;
}

static void remote_expect_qualified_child(const struct zcl_command_request *request,
    struct zcl_command_reply *reply, const char *root)
{
    char input[16384] = "--input=", executable[4096], source[4200];
    size_t n = json_write(request->input, input + 8u, sizeof(input) - 8u);
    const char **env = n ? remote_expect_child_env(root, source) : NULL;
    struct zcl_devloop_process_result *process = zcl_calloc(1, sizeof(*process), "expect child result");
    bool ready = n && n < sizeof(input) - 8u && env && process &&
        os_proc_self_exe_open_path(executable, sizeof(executable));
    const char *argv[] = {executable, "dev", "proof", "remote", input, NULL};
    if (!ready || !zcl_devloop_process_run_env(root, argv, env, 600000, process))
        remote_fail(reply, "expect", "remote_expect_child_unavailable", false, false);
    else (void)remote_expect_child_result(reply, process);
    free(process); free(env);
}

static bool remote_expect_git(const char *root, const char *const args[],
                              char *out, size_t cap)
{
    const char *argv[20] = {"--no-optional-locks", "--no-replace-objects",
        "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false"};
    size_t used = 6;
    for (size_t i = 0; args[i]; i++) {
        if (used + 1u >= sizeof(argv) / sizeof(argv[0])) return false;
        argv[used++] = args[i];
    }
    argv[used] = NULL;
    out[0] = '\0';
    return zcl_native_dev_land_git(root, argv, out, cap, 30000) == 0 && strlen(out) < cap - 1u;
}

static bool remote_expect_git_equal(const char *root, const char *const args[],
                                    const char *expected)
{
    char value[4098];
    if (!remote_expect_git(root, args, value, sizeof(value))) return false;
    size_t n = strlen(value);
    if (!n || value[n - 1u] != '\n') return false;
    value[n - 1u] = '\0';
    return strcmp(value, expected) == 0;
}

static bool remote_expect_clean(const char *root, const struct remote_expectation *e)
{
    char expression[80], status[16384];
    int n = snprintf(expression, sizeof(expression), "%s^{tree}", e->local);
    const char *head[] = {"rev-parse", "--verify", "HEAD", NULL};
    const char *tree[] = {"rev-parse", "--verify", expression, NULL};
    const char *state[] = {"status", "--porcelain=v1", "--untracked-files=all", NULL};
    return n > 0 && (size_t)n < sizeof(expression) &&
        remote_expect_git_equal(root, head, e->local) &&
        remote_expect_git_equal(root, tree, e->tree) &&
        remote_expect_git(root, state, status, sizeof(status)) && !status[0];
}

static bool remote_expect_repository(const char *root, const char *repository)
{
    char canonical[4096], own[4098], other[4098];
    const char *args[] = {"rev-parse", "--path-format=absolute", "--git-common-dir", NULL};
    return repository && platform_directory_canonical_real(repository, canonical, sizeof(canonical)) &&
        remote_expect_git(root, args, own, sizeof(own)) &&
        remote_expect_git(canonical, args, other, sizeof(other)) && !strcmp(own, other);
}

static bool remote_expect_inputs(const struct json_value *input,
                                 struct remote_expectation *e)
{
    e->local = remote_text(input, "local_commit");
    e->base = remote_text(input, "remote_base");
    e->tree = remote_text(input, "git_tree");
    e->repository = remote_text(input, "repository");
    return remote_oid(e->local) && remote_oid(e->base) && remote_oid(e->tree) &&
        e->repository && remote_hex(input, "signer_pubkey", e->signer) &&
        zcl_bytes_any_set(e->signer, sizeof(e->signer));
}

static bool remote_expect_capture(const char *root, struct dev_source_record *out,
                                  char *why, size_t cap)
{
    struct dev_source_record native = {0};
    if (!zcl_dev_source_cas_capture(root, &native) || !native.cas_present) {
        (void)snprintf(why, cap, "remote_expect_native_cas_unavailable");
        return false;
    }
    if (!zcl_dev_source_identity_capture(root, out, why, cap)) return false;
    if (!out->cas_present || strcmp(native.cas_root_sha3, out->cas_root_sha3)) {
        (void)snprintf(why, cap, "remote_expect_source_changed_during_capture");
        return false;
    }
    return true;
}

static bool remote_expect_derive(const char *root, struct remote_expectation *e,
                                 char *why, size_t cap)
{
    char parent[4200];
    int n = snprintf(parent, sizeof(parent), "%s/.cache/zcl-dev-proof", root);
    if (n <= 0 || (size_t)n >= sizeof(parent) ||
        !platform_temp_directory_create_under(parent, "remote-expect-", e->scratch, sizeof(e->scratch))) {
        (void)snprintf(why, cap, "remote_expect_scratch_unavailable");
        return false;
    }
    n = snprintf(e->raw_changed, sizeof(e->raw_changed), "%s/raw", e->scratch);
    int m = snprintf(e->changed_path, sizeof(e->changed_path), "%s/changed", e->scratch);
    if (n <= 0 || (size_t)n >= sizeof(e->raw_changed) || m <= 0 || (size_t)m >= sizeof(e->changed_path)) {
        (void)snprintf(why, cap, "remote_expect_scratch_path_overflow");
        return false;
    }
    return zcl_dev_proof_source_plan_roots(root, e->base, e->local,
        e->raw_changed, e->changed_path, e->source, e->changed, e->impact, why, cap);
}

static bool remote_expect_stable(const struct remote_expectation *e)
{
    return !strcmp(e->before.source_id, e->after.source_id) &&
        !strcmp(e->before.cas_root_sha3, e->after.cas_root_sha3) &&
        !strcmp(e->before.mutation_id, e->after.mutation_id);
}

/* Only names allocated exclusively for this call may be removed. Unknown
 * retained files make remove_empty refuse, preserving diagnostic evidence. */
static bool remote_expect_retire(const struct remote_expectation *e)
{
    if (!e->scratch[0]) return true;
    bool raw = !e->raw_changed[0] || platform_private_file_unlink_missing_ok(e->raw_changed);
    bool changed = !e->changed_path[0] || platform_private_file_unlink_missing_ok(e->changed_path);
    return raw && changed && platform_private_directory_remove_empty(e->scratch);
}

static bool remote_expect_locked(const char *root, struct remote_expectation *e,
                                 char *why, size_t cap)
{
    if (!remote_owner((void *)root, root, why, cap) ||
        !remote_expect_repository(root, e->repository)) {
        (void)snprintf(why, cap, "remote_expect_generation_not_owned");
        return false;
    }
    if (!zcl_dev_proof_remote_git_policy_check(root, why, cap)) return false;
    if (!remote_expect_clean(root, e)) {
        (void)snprintf(why, cap, "remote_expect_generation_not_exact_clean");
        return false;
    }
    if (!remote_expect_capture(root, &e->before, why, cap) ||
        !remote_expect_derive(root, e, why, cap) ||
        !remote_expect_capture(root, &e->after, why, cap)) return false;
    if (!remote_expect_stable(e) || !remote_expect_clean(root, e) ||
        !remote_owner((void *)root, root, why, cap) ||
        !remote_expect_repository(root, e->repository)) {
        (void)snprintf(why, cap, "remote_expect_generation_changed");
        return false;
    }
    return true;
}

static bool remote_expect_hex(struct json_value *out, const char *name, const uint8_t bytes[32])
{
    char hex[65];
    zcl_hex_encode(bytes, 32, hex);
    return json_push_kv_str(out, name, hex);
}

static bool remote_expect_emit(struct zcl_command_reply *reply, const struct remote_expectation *e)
{
    struct json_value capsule = {0}, result = {0};
    json_set_object(&capsule); json_set_object(&result);
    bool ok = json_push_kv_str(&capsule, "local_commit", e->local) &&
        json_push_kv_str(&capsule, "remote_base", e->base) && json_push_kv_str(&capsule, "git_tree", e->tree) &&
        json_push_kv_str(&capsule, "source_id", e->before.source_id) &&
        json_push_kv_str(&capsule, "source_cas_root", e->before.cas_root_sha3) &&
        remote_expect_hex(&capsule, "signer_pubkey", e->signer) &&
        remote_expect_hex(&capsule, "source_root", e->source) &&
        remote_expect_hex(&capsule, "changed_set_root", e->changed) &&
        remote_expect_hex(&capsule, "impact_policy_root", e->impact) &&
        json_push_kv_str(&result, "operation", "expect") &&
        json_push_kv_str(&result, "status", "EXPECTATION_READY") &&
        json_push_kv_bool(&result, "proof_executed", false) &&
        json_push_kv(&result, "expectation", &capsule);
    if (ok) { json_free(&reply->data); reply->data = result; json_init(&result); }
    json_free(&capsule); json_free(&result);
    return ok;
}

static void remote_expect_command(const struct zcl_command_request *request,
    struct zcl_command_reply *reply, const char *root)
{
    struct remote_expectation *e = zcl_calloc(1, sizeof(*e), "remote expectation");
    char why[256] = "remote_expect_invalid_input";
    if (!e) { remote_fail(reply, "expect", "remote_expect_allocation_failed", false, false); return; }
    int guard = -1, acquired = -1;
    bool ok = remote_expect_inputs(request->input, e) && remote_expect_environment(why, sizeof(why));
    const char *path = getenv("PATH");
    if (ok && (!path || strcmp(path, "/usr/bin:/bin"))) {
        free(e); remote_expect_qualified_child(request, reply, root); return;
    }
    if (ok) acquired = zcl_dev_proof_execution_acquire(root, &guard, why, sizeof(why));
    if (ok && acquired == 1) { why[0] = '\0'; ok = remote_expect_locked(root, e, why, sizeof(why)); }
    else ok = false;
    if (!remote_expect_retire(e)) {
        ok = false; (void)snprintf(why, sizeof(why), "remote_expect_scratch_cleanup_failed");
        (void)json_push_kv_str(&reply->data, "retained_input_observation", e->scratch);
    }
    if (ok && !remote_expect_emit(reply, e)) {
        ok = false; (void)snprintf(why, sizeof(why), "remote_expect_output_failed");
    }
    zcl_dev_proof_execution_release(guard);
    if (!ok) remote_fail(reply, "expect", why[0] ? why : "remote_expect_derivation_failed",
                         acquired == 1, acquired == 0);
    free(e);
}

#else
static void remote_expect_command(const struct zcl_command_request *request,
    struct zcl_command_reply *reply, const char *root)
{
    (void)request; (void)root;
    remote_fail(reply, "expect", "remote_expect_platform_unavailable", false, false);
}
#endif

static bool remote_receipt(const char *root, const char *path,
                           uint8_t wire[ZCL_DEV_PROOF_WIRE_BYTES])
{
    size_t rootlen = strlen(root);
    if (strncmp(root, path, rootlen) || path[rootlen] != '/' || !path[rootlen + 1])
        return false;
    struct platform_positioned_file file;
    struct platform_positioned_file_snapshot before, after;
    platform_positioned_file_init(&file);
    bool ok = platform_positioned_file_open_beneath(&file, root, path + rootlen + 1) &&
        platform_positioned_file_is_current_user_only(&file) &&
        platform_positioned_file_snapshot(&file, &before) &&
        before.size == ZCL_DEV_PROOF_WIRE_BYTES &&
        platform_positioned_file_read(&file, wire, ZCL_DEV_PROOF_WIRE_BYTES, 0) ==
            ZCL_DEV_PROOF_WIRE_BYTES &&
        platform_positioned_file_snapshot(&file, &after) &&
        platform_positioned_file_snapshot_equal(&before, &after);
    platform_positioned_file_close(&file);
    return ok;
}

static void remote_fail(struct zcl_command_reply *reply, const char *phase,
                        const char *why, bool mutated, bool busy)
{
    zcl_command_reply_fail(reply, busy ? ZCL_COMMAND_STATUS_BLOCKED : ZCL_COMMAND_STATUS_FAILED,
        busy ? ZCL_COMMAND_EXIT_BLOCKED : ZCL_COMMAND_EXIT_FAILED,
        busy ? "REMOTE_PROOF_BUSY" : "REMOTE_PROOF_REFUSED", phase, busy,
        mutated, !strcmp(phase, "expect") ? "remote expectation was not completed" :
        "remote proof did not produce an independently verified PASS", why);
}

static bool remote_status_facts(struct json_value *facts,
    const struct zcl_dev_proof_status *status, const char *root)
{
    if (!status) return true;
    if (status->receipt_path[0] && !json_push_kv_str(facts, "receipt_path", status->receipt_path)) return false;
    if (status->log_dir[0] && !json_push_kv_str(facts, "log_dir", status->log_dir)) return false;
    if (strcmp(status->detail, "proof_producer_source_mismatch") != 0 &&
        strcmp(status->detail, "proof_producer_source_id_unavailable") != 0) return true;
    char executable[4096];
    int n = snprintf(executable, sizeof(executable), "%s/build/bin/z23-dev", root);
    return n > 0 && (size_t)n < sizeof(executable) &&
        json_push_kv_str(facts, "producer_executable", executable);
}

static bool remote_failure_facts(struct zcl_command_reply *reply,
    const struct zcl_dev_proof_remote_assignment *a,
    const struct zcl_dev_proof_remote_placement *placement,
    const struct zcl_dev_proof_status *status, const char *root)
{
    struct json_value facts = {0};
    json_set_object(&facts);
    bool ok = json_push_kv_str(&facts, "local_commit", a->expected.local_commit) &&
        json_push_kv_str(&facts, "remote_base", a->expected.remote_base);
    if (ok && placement->evidence_dir[0])
        ok = json_push_kv_str(&facts, "retained_input_observation", placement->evidence_dir);
    if (ok) ok = remote_status_facts(&facts, status, root);
    if (ok) ok = json_push_kv(&reply->data, "failure_facts", &facts);
    json_free(&facts);
    return ok;
}

static bool remote_failure_details(struct zcl_command_reply *reply,
    const struct zcl_dev_proof_remote_assignment *a,
    const struct zcl_dev_proof_remote_placement *placement,
    const struct zcl_dev_proof_status *status, const char *root)
{
    bool ok = remote_failure_facts(reply, a, placement, status, root);
    if (!ok)
        (void)snprintf(reply->error.next_action, sizeof(reply->error.next_action),
                       "Failure facts could not be serialized; preserve native proof artifacts before retry.");
    return ok;
}

static bool remote_prepare_command(struct zcl_command_reply *reply,
    const struct zcl_dev_proof_remote_assignment *a,
    struct zcl_dev_proof_remote_placement *placement, char *root,
    char *why, size_t why_cap)
{
    bool prepared = zcl_dev_proof_remote_prepare(a, remote_owner, root,
                                                  placement, why, why_cap);
    if (placement->evidence_dir[0] &&
        !json_push_kv_str(&reply->data, "retained_input_observation", placement->evidence_dir)) {
        remote_fail(reply, "output", "remote_evidence_output_failed",
                    placement->objects_imported || placement->placed, false);
        (void)remote_failure_details(reply, a, placement, NULL, root);
        return false;
    }
    if (!prepared) {
        remote_fail(reply, "prepare", why, placement->objects_imported || placement->placed,
                    strstr(why, "busy") != NULL);
        (void)remote_failure_details(reply, a, placement, NULL, root);
        return false;
    }
    return true;
}

static bool remote_emit_status(struct zcl_command_reply *reply,
    const struct zcl_dev_proof_remote_assignment *a,
    const struct zcl_dev_proof_status *status)
{
    return (!status->receipt_path[0] || json_push_kv_str(&reply->data, "receipt_path", status->receipt_path)) &&
        (!status->log_dir[0] || json_push_kv_str(&reply->data, "log_dir", status->log_dir)) &&
        json_push_kv_str(&reply->data, "local_commit", a->expected.local_commit) &&
        json_push_kv_str(&reply->data, "remote_base", a->expected.remote_base);
}

static void remote_execute_failure(struct zcl_command_reply *reply, int rc,
    const struct zcl_dev_proof_remote_assignment *a,
    const struct zcl_dev_proof_remote_placement *placement,
    const struct zcl_dev_proof_status *status, const char *root)
{
    remote_fail(reply, "execute", status->detail, true, rc == 0);
    bool have_facts = remote_failure_details(reply, a, placement, status, root);
    if (have_facts && (strcmp(status->detail, "proof_producer_source_mismatch") == 0 ||
        strcmp(status->detail, "proof_producer_source_id_unavailable") == 0))
        (void)snprintf(reply->error.next_action, sizeof(reply->error.next_action),
            "Build the candidate dev binary under admission, use it for "
            "dev.proof.retry on this exact pair when required, then repeat "
            "dev.proof.remote with the same assignment for receipt verification.");
}

static void remote_verify_result(struct zcl_command_reply *reply,
    const struct zcl_dev_proof_remote_assignment *a,
    const struct zcl_dev_proof_remote_placement *placement,
    const struct zcl_dev_proof_status *status, char *root, char *why, size_t why_cap)
{
    uint8_t wire[ZCL_DEV_PROOF_WIRE_BYTES];
    struct zcl_dev_acceptance_receipt_v1 receipt;
    if (!remote_receipt(root, status->receipt_path, wire)) {
        remote_fail(reply, "verify", "remote_receipt_missing_or_unsafe", true, false);
        (void)remote_failure_details(reply, a, placement, status, root);
        return;
    }
    if (!zcl_dev_proof_remote_verify(wire, sizeof(wire), &a->expected,
            zcl_dev_proof_host_toolchain_capture, root, &receipt, why, why_cap)) {
        remote_fail(reply, "verify", why, true, false);
        (void)remote_failure_details(reply, a, placement, status, root);
        return;
    }
    if (!json_push_kv_str(&reply->data, "status", "PASS")) {
        remote_fail(reply, "output", "remote_evidence_output_failed", true, false);
        (void)remote_failure_details(reply, a, placement, status, root);
    }
}

static void remote_execute_command(const struct zcl_command_request *request,
    struct zcl_command_reply *reply, char *root)
{
    struct zcl_dev_proof_remote_assignment a = {0};
    struct zcl_dev_proof_remote_placement placement = {0};
    struct zcl_dev_proof_status status = {0};
    char destination[4096], why[256] = "remote_invalid_input";
    if (!remote_assignment(request->input, &a) ||
        !platform_directory_canonical_real(a.destination, destination, sizeof(destination)) ||
        strcmp(root, destination) != 0) {
        remote_fail(reply, "input", why, false, false);
        return;
    }
    if (!remote_prepare_command(reply, &a, &placement, root, why, sizeof(why))) return;
    int rc = zcl_dev_proof_remote_execute(&a, &placement, remote_owner, root, &status);
    if (!remote_emit_status(reply, &a, &status)) {
        remote_fail(reply, "output", "remote_evidence_output_failed", true, false);
        (void)remote_failure_details(reply, &a, &placement, &status, root);
        return;
    }
    if (rc != 1 || status.state != ZCL_DEV_PROOF_STATE_PASSED) {
        remote_execute_failure(reply, rc, &a, &placement, &status, root);
        return;
    }
    remote_verify_result(reply, &a, &placement, &status, root, why, sizeof(why));
}
#endif

void zcl_native_handle_dev_proof_remote(const struct zcl_command_request *request,
                                        struct zcl_command_reply *reply)
{
#ifndef ZCL_DEV_BUILD
    (void)request;
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_BLOCKED,
        "DEV_BUILD_REQUIRED", "dispatch", false, false,
        "remote proof requires the dev binary", "make dev-bin");
#else
    char root[4096];
    const struct zcl_command_context *ctx = request ? request->context : NULL;
    if (!ctx || ctx->authority_ceiling < ZCL_COMMAND_AUTH_OWNER ||
        !platform_directory_canonical_real(zcl_native_source_root(request), root, sizeof(root))) {
        remote_fail(reply, "input", "remote_invalid_input", false, false);
        return;
    }
    const struct json_value *operation_value = json_get(request->input, "operation");
    const char *operation = remote_text(request->input, "operation");
    if (operation_value && (!operation || (strcmp(operation, "expect") && strcmp(operation, "execute")))) {
        remote_fail(reply, "input", operation ? "remote_unknown_operation" : "remote_invalid_operation", false, false);
        return;
    }
    if (operation && !strcmp(operation, "expect")) {
        remote_expect_command(request, reply, root);
        return;
    }
    remote_execute_command(request, reply, root);
#endif
}
