/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * Purpose: owner-invoked placement and proof of one pinned remote source. */
#include "command/native_command.h"
#include "json/json.h"
#ifdef ZCL_DEV_BUILD
#include "base/hex.h"
#include "command/native_dev_job.h"
#include "dev_proof_remote.h"
#include "platform/directory_compat.h"
#include "platform/positioned_file.h"
#include <string.h>
#include <stdio.h>

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
        mutated, "remote proof did not produce an independently verified PASS", why);
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
    struct zcl_dev_proof_remote_assignment a = {0};
    struct zcl_dev_proof_remote_placement placement = {0};
    struct zcl_dev_proof_status status = {0};
    char root[4096], destination[4096], why[256] = "remote_invalid_input";
    const struct zcl_command_context *ctx = request ? request->context : NULL;
    if (!ctx || ctx->authority_ceiling < ZCL_COMMAND_AUTH_OWNER ||
        !remote_assignment(request->input, &a) ||
        !platform_directory_canonical_real(zcl_native_source_root(request), root, sizeof(root)) ||
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
#endif
}
