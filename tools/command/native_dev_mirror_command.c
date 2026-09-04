/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Record declared optional Git mirror evidence from the dev CLI. */

#include "command/native_command.h"

#include "base/hex.h"
#include "json/json.h"
#include "vcs/vcs_devloop_mirror.h"

#include <stdlib.h>
#include <string.h>

static const char *dev_mirror_source_root(
    const struct zcl_command_request *request)
{
    if (request && request->context && request->context->source_root &&
        request->context->source_root[0])
        return request->context->source_root;
    const char *root = getenv("ZCL_DEV_SOURCE_ROOT");
    return root && root[0] ? root : ".";
}

void zcl_native_handle_dev_publication_mirror_record(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    const char *job_hex = json_get_str(json_get(request->input, "job_root"));
    const char *git_hex = json_get_str(json_get(request->input, "git_oid"));
    uint8_t job_root[32], git_oid[VCS_DEVLOOP_MIRROR_OID_MAX_BYTES] = {0};
    size_t git_oid_len = git_hex ? strlen(git_hex) / 2u : 0;
    char job_root_err[128];
    if (!zcl_native_require_hex64("job_root", job_hex, job_root, job_root_err,
                                  sizeof(job_root_err))) {
        zcl_command_reply_fail(
            reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
            "INVALID_JOB_ROOT", "normalize", false, false, job_root_err,
            job_hex ? job_hex : "missing job_root");
        return;
    }
    if (git_hex &&
        ((strlen(git_hex) != 40 && strlen(git_hex) != 64) ||
         !zcl_hex_decode_lower(git_hex, git_oid, git_oid_len))) {
        zcl_command_reply_fail(
            reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
            "INVALID_GIT_OID", "normalize", false, false,
            "optional git_oid must be 40 or 64 lowercase hexadecimal characters",
            git_hex);
        return;
    }
    uint8_t receipt_root[32];
    bool reused = false;
    if (!vcs_devloop_mirror_record(
            dev_mirror_source_root(request), job_root,
            git_oid_len > 0 ? git_oid : NULL, git_oid_len,
            receipt_root, &reused)) {
        zcl_command_reply_fail(
            reply, ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_BLOCKED,
            "MIRROR_RECEIPT_REFUSED", "record", false, false,
            "mirror evidence requires one exact provider-announced publication job and cannot replace an existing different receipt",
            job_hex);
        return;
    }
    char receipt_hex[65];
    zcl_hex_encode(receipt_root, 32, receipt_hex);
    (void)json_push_kv_str(&reply->data, "schema",
                           "zcl.dev_publication_mirror_record.v1");
    (void)json_push_kv_str(&reply->data, "status", "RECORDED_DECLARED");
    (void)json_push_kv_str(&reply->data, "publication_job_root", job_hex);
    (void)json_push_kv_str(&reply->data, "mirror_receipt_root",
                           receipt_hex);
    if (git_hex)
        (void)json_push_kv_str(&reply->data, "git_oid", git_hex);
    (void)json_push_kv_bool(&reply->data, "receipt_reused", reused);
    (void)json_push_kv_bool(&reply->data, "github_required", false);
    (void)json_push_kv_bool(&reply->data, "git_called", false);
    (void)json_push_kv_bool(&reply->data, "network_called", false);
    (void)json_push_kv_str(&reply->data, "next_command",
                           "z23-dev dev drive");
}
