/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Native command adapter for exact local push-proof receipts. */

#include "command/native_command.h"
#include "command/native_dev_loop_command.h"
#include "command/native_dev_proof_command.h"

#include "dev_proof.h"
#include "json/json.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef ZCL_DEV_BUILD
static const char *proof_source_root(const struct zcl_command_request *request)
{
    const struct json_value *root = request && request->input
        ? json_get(request->input, "root") : NULL;
    if (root && root->type == JSON_STR && json_get_str(root)[0])
        return json_get_str(root);
    if (request && request->context && request->context->source_root &&
        request->context->source_root[0])
        return request->context->source_root;
    const char *environment = getenv("ZCL_DEV_SOURCE_ROOT");
    return environment && environment[0] ? environment : ".";
}

static const char *proof_optional_text(const struct json_value *input,
                                       const char *key)
{
    if (!input || !key) return NULL;
    const struct json_value *value = json_get(input, key);
    return value && value->type == JSON_STR && json_get_str(value)[0]
        ? json_get_str(value) : NULL;
}

static void proof_emit_status(struct zcl_command_reply *reply,
                              const struct zcl_dev_proof_status *status,
                              bool add_wait_next)
{
    (void)json_push_kv_str(&reply->data, "schema",
                           "zcl.dev_proof_status.v1");
    (void)json_push_kv_str(&reply->data, "status",
                           zcl_dev_proof_state_name(status->state));
    if (status->local_commit[0])
        (void)json_push_kv_str(&reply->data, "local_commit",
                               status->local_commit);
    if (status->remote_base[0])
        (void)json_push_kv_str(&reply->data, "remote_base",
                               status->remote_base);
    if (status->receipt_path[0])
        (void)json_push_kv_str(&reply->data, "receipt_path",
                               status->receipt_path);
    if (status->detail[0])
        (void)json_push_kv_str(&reply->data, "detail", status->detail);
    if (status->worker_id > 1)
        (void)json_push_kv_int(&reply->data, "worker_id", status->worker_id);
    if (status->started_unix > 0)
        (void)json_push_kv_int(&reply->data, "started_unix",
                               status->started_unix);
    if (status->state == ZCL_DEV_PROOF_STATE_RUNNING)
        (void)json_push_kv_int(&reply->data, "eta_ms", status->eta_ms);
    (void)json_push_kv_bool(&reply->data, "receipt_reused",
                            status->receipt_reused);
    char input[192];
    int n = snprintf(input, sizeof(input),
                     "{\"local_commit\":\"%s\",\"remote_base\":\"%s\"}",
                     status->local_commit, status->remote_base);
    if (add_wait_next && n > 0 && (size_t)n < sizeof(input) &&
        status->state != ZCL_DEV_PROOF_STATE_PASSED &&
        status->state != ZCL_DEV_PROOF_STATE_INVALID &&
        status->local_commit[0] && status->remote_base[0])
        (void)zcl_command_reply_add_next(
            reply, "dev.proof.wait", input,
            "wait for the exact commit/base receipt without running push-time work");
}

static void proof_fail(struct zcl_command_reply *reply,
                       const struct zcl_dev_proof_status *status,
                       const char *code, const char *phase)
{
    proof_emit_status(reply, status, false);
    zcl_command_reply_fail(
        reply, ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_BLOCKED,
        code, phase, status->state == ZCL_DEV_PROOF_STATE_RUNNING, false,
        "the exact local commit and remote base do not have an admitted receipt",
        status->detail[0] ? status->detail : "exact_receipt_missing");
}
#endif

static void proof_status(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
#ifndef ZCL_DEV_BUILD
    (void)request;
    zcl_command_reply_fail(
        reply, ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_BLOCKED,
        "DEV_BUILD_REQUIRED", "dispatch", false, false,
        "proof receipt status requires the dev binary", "make dev-bin");
#else
    struct zcl_dev_proof_status status = {0};
    if (!zcl_dev_proof_status_read(
            proof_source_root(request),
            proof_optional_text(request->input, "local_commit"),
            proof_optional_text(request->input, "remote_base"), &status)) {
        proof_emit_status(reply, &status, true);
        zcl_command_reply_fail(
            reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
            "PROOF_STATUS_INVALID", "resolve", false, false,
            "could not resolve the exact local commit and remote base",
            status.detail);
        return;
    }
    proof_emit_status(reply, &status, true);
#endif
}

static void proof_ensure(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
#ifndef ZCL_DEV_BUILD
    (void)request;
    zcl_command_reply_fail(
        reply, ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_BLOCKED,
        "DEV_BUILD_REQUIRED", "dispatch", false, false,
        "background proof scheduling requires the dev binary", "make dev-bin");
#else
    struct zcl_dev_proof_status status = {0};
    if (!zcl_dev_proof_status_read(
            proof_source_root(request),
            proof_optional_text(request->input, "local_commit"),
            proof_optional_text(request->input, "remote_base"), &status) ||
        status.state == ZCL_DEV_PROOF_STATE_INVALID) {
        proof_emit_status(reply, &status, false);
        zcl_command_reply_fail(
            reply, ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_BLOCKED,
            "PROOF_WORKER_UNAVAILABLE", "preflight", false, false,
            "exact background verification is unavailable on this platform",
            status.detail[0] ? status.detail : "proof_worker_unavailable");
        return;
    }
    struct zcl_command_reply watcher;
    struct json_value watcher_input;
    json_init(&watcher_input);
    json_set_object(&watcher_input);
    bool watcher_input_ready =
        json_push_kv_str(&watcher_input, "root", proof_source_root(request)) &&
        json_push_kv_str(&watcher_input, "mode", "verify");
    if (!watcher_input_ready) {
        json_free(&watcher_input);
        proof_emit_status(reply, &status, false);
        zcl_command_reply_fail(
            reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INTERNAL,
            "PROOF_QUEUE_INPUT_FAILED", "schedule", true, false,
            "the resident watcher request could not be allocated",
            "retry proof enqueue");
        return;
    }
    struct zcl_command_request watcher_request = *request;
    watcher_request.input = &watcher_input;
    zcl_command_reply_init(&watcher, "zcl.dev_loop_status.v1");
    zcl_native_handle_dev_loop_start_async(&watcher_request, &watcher);
    const struct json_value *created = json_get(&watcher.data, "created");
    bool queue_ready = watcher.exit_code == ZCL_COMMAND_EXIT_OK &&
        ((created && created->type == JSON_BOOL && json_get_bool(created)) ||
         zcl_native_dev_loop_proof_queue_ready(proof_source_root(request)));
    zcl_command_reply_free(&watcher);
    json_free(&watcher_input);
    if (!queue_ready) {
        proof_emit_status(reply, &status, false);
        zcl_command_reply_fail(
            reply, ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_BLOCKED,
            "PROOF_QUEUE_OWNER_STALE", "schedule", true, false,
            "the resident watcher does not advertise the proof queue contract",
            "restart the development watcher with the current z23-dev binary");
        return;
    }
    if (!zcl_dev_proof_ensure(
            proof_source_root(request),
            proof_optional_text(request->input, "local_commit"),
            proof_optional_text(request->input, "remote_base"), &status)) {
        proof_emit_status(reply, &status, true);
        zcl_command_reply_fail(
            reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_FAILED,
            "PROOF_ENSURE_FAILED", "schedule", false, false,
            "could not schedule exact background verification", status.detail);
        return;
    }
    proof_emit_status(reply, &status, true);
#endif
}

static void proof_wait(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
#ifndef ZCL_DEV_BUILD
    (void)request;
    zcl_command_reply_fail(
        reply, ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_BLOCKED,
        "DEV_BUILD_REQUIRED", "dispatch", false, false,
        "proof receipt waiting requires the dev binary", "make dev-bin");
#else
    int64_t timeout_ms = 300000;
    const struct json_value *timeout = json_get(request->input, "timeout_ms");
    if (timeout && timeout->type == JSON_INT)
        timeout_ms = json_get_int(timeout);
    struct zcl_dev_proof_status status;
    if (timeout_ms < 1 || timeout_ms > 300000 ||
        !zcl_dev_proof_wait(
            proof_source_root(request),
            proof_optional_text(request->input, "local_commit"),
            proof_optional_text(request->input, "remote_base"),
            (int)timeout_ms, &status)) {
        memset(&status, 0, sizeof(status));
        status.state = ZCL_DEV_PROOF_STATE_INVALID;
        (void)snprintf(status.detail, sizeof(status.detail), "%s",
                       "timeout_ms_must_be_1_through_300000");
        proof_emit_status(reply, &status, false);
        zcl_command_reply_fail(
            reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
            "PROOF_WAIT_INVALID", "normalize", false, false,
            "proof wait input is invalid", status.detail);
        return;
    }
    if (status.state != ZCL_DEV_PROOF_STATE_PASSED) {
        proof_fail(reply, &status,
                   status.state == ZCL_DEV_PROOF_STATE_FAILED
                       ? "PROOF_FAILED" : "PROOF_WAIT_TIMEOUT",
                   status.state == ZCL_DEV_PROOF_STATE_FAILED ? "prove" : "wait");
        return;
    }
    proof_emit_status(reply, &status, false);
#endif
}

void zcl_native_dev_proof_dispatch(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    const char *path = request && request->spec ? request->spec->path : NULL;
    if (path && strcmp(path, "dev.proof.ensure") == 0)
        proof_ensure(request, reply);
    else if (path && strcmp(path, "dev.proof.status") == 0)
        proof_status(request, reply);
    else if (path && strcmp(path, "dev.proof.wait") == 0)
        proof_wait(request, reply);
    else
        zcl_command_reply_fail(
            reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
            "PROOF_COMMAND_INVALID", "dispatch", false, false,
            "proof dispatch requires an exact proof command path", "");
}
