/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Native dev.verify-change adapter. Execution exists only in a dev build;
 * release binaries retain the discoverable command contract but cannot spawn
 * a compiler or test process. */

#define _GNU_SOURCE
#include "command/native_command.h"
#include "command/native_dev_proof_command.h"

#include "devloop.h"
#include "json/json.h"
#include "platform/directory_compat.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef ZCL_DEV_BUILD
static const char *verify_source_root(
    const struct zcl_command_request *request)
{
    if (request && request->context && request->context->source_root &&
        request->context->source_root[0])
        return request->context->source_root;
    const char *root = getenv("ZCL_DEV_SOURCE_ROOT");
    return root && root[0] ? root : ".";
}

static void verify_first_error(const char *output, char out[256])
{
    const char *marker = strstr(output ? output : "", "FIRST-ERROR[");
    if (!marker) marker = output ? output : "verification produced no output";
    const char *end = strchr(marker, '\n');
    size_t len = end ? (size_t)(end - marker) : strlen(marker);
    if (len >= 256) len = 255;
    memcpy(out, marker, len);
    out[len] = '\0';
}
#endif

void zcl_native_handle_dev_verify_change(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    if (request && request->spec && request->spec->path &&
        strncmp(request->spec->path, "dev.proof.", 10) == 0) {
        zcl_native_dev_proof_dispatch(request, reply);
        return;
    }
#ifndef ZCL_DEV_BUILD
    (void)request;
    zcl_command_reply_fail(
        reply, ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_BLOCKED,
        "DEV_BUILD_REQUIRED", "dispatch", false, false,
        "changed-scope verification requires a dev build",
        "make dev-bin, then z23-dev dev verify-change");
#else
    char root[PATH_MAX];
    const char *source_root = verify_source_root(request);
    if (!platform_directory_canonical_real(source_root, root, sizeof(root))) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL,
                               "ROOT_RESOLVE_FAILED", "normalize", false,
                               false, "could not resolve the checkout root",
                               source_root);
        return;
    }
    const char *argv[] = {
        "make", "--no-print-directory", "verify-change", NULL,
    };
    struct zcl_devloop_process_result result;
    if (!zcl_devloop_process_run(root, argv, 900000, &result)) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL,
                               "VERIFY_CHANGE_EXEC_FAILED", "execute", true,
                               false, "could not execute changed-scope verification",
                               "");
        return;
    }
    bool passed = result.exit_code == 0 && result.term_signal == 0 &&
                  !result.timed_out;
    (void)json_push_kv_str(&reply->data, "schema",
                           "zcl.dev_verify_change.v1");
    (void)json_push_kv_bool(&reply->data, "passed", passed);
    (void)json_push_kv_int(&reply->data, "elapsed_ms", result.elapsed_ms);
    (void)json_push_kv_int(&reply->data, "exit_code", result.exit_code);
    (void)json_push_kv_bool(&reply->data, "timed_out", result.timed_out);
    (void)json_push_kv_str(&reply->data, "report", result.output);
    if (!passed) {
        char evidence[256];
        verify_first_error(result.output, evidence);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_FAILED,
                               "VERIFY_CHANGE_FAILED", "prove", true, false,
                               "changed-scope verification failed", evidence);
    }
#endif
}
