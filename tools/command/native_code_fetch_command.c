/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Install another checkout's verified codeindex generation into this
 * one, so a fresh worktree skips the cold index build. VERIFY, DON'T TRUST:
 * the fetched store is adopted only after its sealed source roots match a
 * fresh local computation; every refusal names the mismatched key and both
 * digests. */

#include "command/native_command.h"

#include "codeindex/codeindex_fetch.h"

#include "base/hex.h"
#include "json/json.h"
#include "platform/time_compat.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *fetch_source_root(
    const struct zcl_command_request *request)
{
    if (request && request->context && request->context->source_root &&
        request->context->source_root[0])
        return request->context->source_root;
    const char *root = getenv("ZCL_DEV_SOURCE_ROOT");
    return root && root[0] ? root : ".";
}

void zcl_native_handle_code_fetch(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    const char *from = json_get_str(json_get(request->input, "from"));
    if (!from || !from[0]) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "MISSING_FROM",
                               "normalize", false, false,
                               "code fetch requires a `from` checkout root, "
                               ".codeindex directory, or index.kv file", "");
        return;
    }

    const char *root = fetch_source_root(request);
    int64_t start_ms = platform_time_monotonic_ms();

    struct codeindex_fetch_report report;
    bool installed = codeindex_fetch_install(root, from, &report);
    int64_t elapsed_ms = platform_time_monotonic_ms() - start_ms;
    if (elapsed_ms < 0) elapsed_ms = 0;

    if (!installed) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_FAILED,
                               report.code[0] ? report.code : "FETCH_FAILED",
                               "verify", false, false,
                               report.message[0] ? report.message
                                                 : "the fetched code index "
                                                   "was refused",
                               report.evidence);
        return;
    }

    char source_hex[65], merkle_hex[65];
    zcl_hex_encode(report.source_root_sha3, 32, source_hex);
    zcl_hex_encode(report.source_merkle_root_sha3, 32, merkle_hex);

    (void)json_push_kv_bool(&reply->data, "installed", true);
    (void)json_push_kv_str(&reply->data, "from", from);
    (void)json_push_kv_str(&reply->data, "source_root_sha3", source_hex);
    (void)json_push_kv_str(&reply->data, "source_merkle_root_sha3",
                           merkle_hex);
    if (report.receipt_present) {
        (void)json_push_kv_int(&reply->data, "build_cold_ms",
                               report.build_cold_ms);
        (void)json_push_kv_int(&reply->data, "build_cold_files",
                               report.build_cold_files);
    }
    (void)json_push_kv_bool(&reply->data, "dep_restamped",
                            report.dep_restamped);
    (void)json_push_kv_bool(&reply->data, "adopted", report.adopted);
    (void)json_push_kv_int(&reply->data, "elapsed_ms", elapsed_ms);

    char summary[256];
    if (report.receipt_present)
        (void)snprintf(summary, sizeof(summary),
                       "installed the verified code index from %s "
                       "(cold build there cost %lld ms over %lld files); this "
                       "checkout's next open skips the cold build",
                       from, report.build_cold_ms, report.build_cold_files);
    else
        (void)snprintf(summary, sizeof(summary),
                       "installed the verified code index from %s; this "
                       "checkout's next open skips the cold build", from);
    (void)json_push_kv_str(&reply->data, "summary", summary);
}
