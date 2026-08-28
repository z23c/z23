/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Typed zcode.science.work.execute command over the closed S4
 *          benchmark/reproduction executor (plan -> confirm:true commit ->
 *          receipt), feeding the landed S3 admission path. */

#include "command/native_command.h"
#include "command/native_zcode_policy.h"

#include "base/hex.h"
#include "json/json.h"
#include "models/database.h"
#include "platform/directory_compat.h"
#include "platform/time_compat.h"
#include "services/zcode_benchmark_executor.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ZSX_PATH_MAX 4096

static const char *zsx_str(const struct json_value *input, const char *key)
{
    const struct json_value *v = input ? json_get(input, key) : NULL;
    return v ? json_get_str(v) : NULL;
}

static int64_t zsx_int(const struct json_value *input, const char *key,
                       int64_t fallback)
{
    const struct json_value *v = input ? json_get(input, key) : NULL;
    return v ? json_get_int(v) : fallback;
}

static bool zsx_confirm(const struct json_value *input)
{
    const struct json_value *v = input ? json_get(input, "confirm") : NULL;
    return v && json_get_bool(v);
}

static void zsx_fail(struct zcl_command_reply *reply, const char *code,
                     const char *detail)
{
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                           ZCL_COMMAND_EXIT_INVALID, code, "validate", false,
                           false, detail, "zcode.science.work.execute");
}

static void zsx_fail_service(struct zcl_command_reply *reply,
                             const char *code, const char *message)
{
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                           ZCL_COMMAND_EXIT_FAILED, code, "commit", false,
                           false, message, "zcode.science.work.execute");
}

static const char *zsx_datadir(const struct json_value *input)
{
    const char *datadir = zsx_str(input, "datadir");
    if (!datadir || !datadir[0])
        datadir = zcl_native_command_datadir();
    return datadir;
}

static bool zsx_open_db(const char *datadir, struct node_db *ndb)
{
    char db_path[ZSX_PATH_MAX];
    int n = datadir
        ? snprintf(db_path, sizeof(db_path), "%s/node.db", datadir) : -1;
    return n > 0 && (size_t)n < sizeof(db_path) &&
           node_db_open(ndb, db_path);
}

static const char *zsx_workspace(const struct json_value *input,
                                 char *resolved, size_t resolved_size)
{
    const char *workspace = zsx_str(input, "workspace");
    char candidate[ZSX_PATH_MAX];
    if (workspace && workspace[0])
        return platform_directory_canonical_real(workspace, resolved,
                                                 resolved_size)
                   ? resolved : NULL;
    const char *datadir = zsx_datadir(input);
    if (!datadir || !datadir[0])
        return NULL;
    int n = snprintf(candidate, sizeof(candidate), "%s/zcode", datadir);
    return n > 0 && (size_t)n < sizeof(candidate) &&
                   platform_directory_canonical_real(candidate, resolved,
                                                     resolved_size)
               ? resolved : NULL;
}

static bool zsx_hex32(const char *hex, uint8_t out[32])
{
    return hex && strlen(hex) == 64 && zcl_hex_decode_lower(hex, out, 32);
}

static bool zsx_root_ok(const char *hex)
{
    uint8_t root[32];
    return hex && zsx_hex32(hex, root);
}

void zcl_native_handle_zcode_science_work_execute(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!request || !reply) return;
#if defined(_WIN32)
    /* The executor intentionally has no Windows implementation until its
     * restricted-token/Job-Object/network-denial sandbox is qualified.  Refuse
     * before policy, database, workspace, or execution side effects. */
    zsx_fail_service(
        reply, "WORK_EXECUTE_UNSUPPORTED",
        "science execution is disabled on Windows until the native sandbox "
        "passes adversarial qualification");
    return;
#endif
    const struct json_value *input = request->input;
    const char *original = zsx_str(input, "original_result_root");
    bool is_repro = original && original[0];
    /* Root grammar is checked for every field the caller supplied; the
     * executor enforces the per-kind required set. */
    const char *root_keys[] = {
        "study_root", "task_root", "candidate_root", "method_root",
        "original_result_root",
    };
    for (size_t i = 0; i < sizeof(root_keys) / sizeof(root_keys[0]); i++) {
        const char *value = zsx_str(input, root_keys[i]);
        if (value && value[0] && !zsx_root_ok(value)) {
            zsx_fail(reply, "BAD_ROOT",
                     "root fields must be 64 lowercase hex");
            return;
        }
    }
    if (is_repro) {
        if (!zsx_root_ok(zsx_str(input, "method_root"))) {
            zsx_fail(reply, "BAD_ROOT",
                     "a reproduction requires method_root");
            return;
        }
    } else {
        if (!zsx_root_ok(zsx_str(input, "study_root")) ||
            !zsx_root_ok(zsx_str(input, "task_root")) ||
            !zsx_root_ok(zsx_str(input, "candidate_root")) ||
            !zsx_root_ok(zsx_str(input, "method_root"))) {
            zsx_fail(reply, "BAD_ROOT",
                     "a benchmark run requires study_root, task_root, candidate_root, and method_root");
            return;
        }
    }
    struct zcode_benchmark_execute_request req;
    memset(&req, 0, sizeof(req));
    req.study_root_hex = zsx_str(input, "study_root");
    req.task_root_hex = zsx_str(input, "task_root");
    req.candidate_root_hex = zsx_str(input, "candidate_root");
    req.method_root_hex = zsx_str(input, "method_root");
    req.original_result_root_hex = is_repro ? original : NULL;
    req.action_kind = zsx_str(input, "action_kind");
    req.action_sequence = (uint64_t)zsx_int(input, "action_sequence", 1);
    req.result_sequence = (uint64_t)zsx_int(input, "result_sequence", 1);
    req.reproduction_sequence =
        (uint64_t)zsx_int(input, "reproduction_sequence", 1);
    req.challenge_block_height =
        (uint64_t)zsx_int(input, "challenge_block_height", 0);
    const char *challenge_hash = zsx_str(input, "challenge_block_hash");
    if (!challenge_hash ||
        !zsx_hex32(challenge_hash, req.challenge_block_hash) ||
        req.challenge_block_height == 0) {
        zsx_fail(reply, "BAD_CHALLENGE",
                 "challenge_block_height (>=1) and challenge_block_hash (64 lowercase hex) are required");
        return;
    }
    const char *reproducer = zsx_str(input, "reproducer_pubkey");
    if (reproducer &&
        !zsx_hex32(reproducer, req.reproducer_pubkey)) {
        zsx_fail(reply, "BAD_REPRODUCER",
                 "reproducer_pubkey must be 64 lowercase hex");
        return;
    }
    if (is_repro && !reproducer) {
        zsx_fail(reply, "BAD_REPRODUCER",
                 "a reproduction requires reproducer_pubkey");
        return;
    }
    req.now = zsx_int(input, "now_unix",
                      (int64_t)platform_time_wall_unix());
    req.confirm = zsx_confirm(input);
    req.hooks = NULL;
    struct vcs_zcode_sovereignty_subject subject;
    memset(&subject, 0, sizeof(subject));
    const char *authority_root = is_repro ? original : req.candidate_root_hex;
    if (!zsx_hex32(authority_root, subject.semantic_root)) {
        zsx_fail(reply, "BAD_ROOT", "execution authority root is invalid");
        return;
    }
    memcpy(subject.package_root, subject.semantic_root, 32);
    (void)snprintf(subject.service_type, sizeof(subject.service_type),
                   "science");
    char policy_error[192] = {0};
    if (!zcl_native_zcode_policy_allows(
            zsx_datadir(input), VCS_ZCODE_SOVEREIGNTY_EXECUTE, &subject,
            policy_error, sizeof(policy_error))) {
        zsx_fail_service(reply, "SOVEREIGNTY_DENIED",
                         policy_error[0] ? policy_error
                                         : "local policy denied EXECUTE");
        return;
    }
    char ws[ZSX_PATH_MAX];
    req.workspace = zsx_workspace(input, ws, sizeof(ws));
    if (!req.workspace) {
        zsx_fail(reply, "BAD_WORKSPACE",
                 "workspace must resolve to an existing directory");
        return;
    }
    struct node_db ndb = {0};
    if (!zsx_open_db(zsx_datadir(input), &ndb)) {
        zsx_fail_service(reply, "DATABASE_OPEN_FAILED",
                         "the science plan ledger could not be opened");
        return;
    }
    struct zcode_benchmark_execute_out out;
    struct zcl_result executed = zcode_benchmark_execute(&ndb, &req, &out);
    node_db_close(&ndb);
    if (!executed.ok) {
        zsx_fail_service(reply, "WORK_EXECUTE_REFUSED", executed.message);
        return;
    }
    (void)json_push_kv_str(&reply->data, "kind",
                           out.run.is_reproduction ? "reproduction"
                                                   : "result");
    if (!out.committed) {
        (void)json_push_kv_str(&reply->data, "plan_root",
                               out.plan.plan_root);
        (void)json_push_kv_str(&reply->data, "request_hash",
                               out.plan.request_hash);
        (void)json_push_kv_int(&reply->data, "expires_unix",
                               out.plan.expires_unix);
        (void)json_push_kv_bool(&reply->data, "already_planned",
                                out.plan.already_planned);
        (void)json_push_kv_str(&reply->data, "state", "PLANNED");
        (void)json_push_kv_str(&reply->data, "commit_command",
                               "zcode.science.work.execute");
    } else {
        (void)json_push_kv_str(&reply->data, "result_root",
                               out.commit.result_root);
        (void)json_push_kv_bool(&reply->data, "already_committed",
                                out.commit.already_committed);
        (void)json_push_kv_str(&reply->data, "state", "COMMITTED");
        (void)json_push_kv_str(&reply->data, "authority",
                               "CANONICAL_CAS_WIRE");
    }
    char hex[65];
    if (out.run.is_reproduction) {
        (void)json_push_kv_int(&reply->data, "verdict", out.run.verdict);
        zcl_hex_encode(out.run.reproduced_root, 32, hex);
        (void)json_push_kv_str(&reply->data, "reproduced_result_root", hex);
        zcl_hex_encode(out.run.reproduction_root, 32, hex);
        (void)json_push_kv_str(&reply->data, "reproduction_root", hex);
    } else {
        (void)json_push_kv_int(&reply->data, "status", out.run.result.status);
        zcl_hex_encode(out.run.result_root, 32, hex);
        (void)json_push_kv_str(&reply->data, "observation_root", hex);
    }
    zcl_hex_encode(out.run.manifest_root, 32, hex);
    (void)json_push_kv_str(&reply->data, "raw_sample_root", hex);
    zcl_hex_encode(out.run.sample_payload_root, 32, hex);
    (void)json_push_kv_str(&reply->data, "sample_payload_root", hex);
    zcl_hex_encode(out.run.evidence_root, 32, hex);
    (void)json_push_kv_str(&reply->data, "evidence_root", hex);
    zcl_hex_encode(out.run.hardware_profile_root, 32, hex);
    (void)json_push_kv_str(&reply->data, "hardware_profile_root", hex);
    (void)json_push_kv_str(&reply->data, "observation", "NEVER_TRUTH");
}
