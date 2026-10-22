/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Read-only inner-loop guide for coding agents (`code.guide`).
 *
 * THE INVARIANT OF THIS FILE: with no input the handler reads no checkout,
 * datadir, wallet, compiler, or test state and renders the currently honest
 * edit/proof loop; any other input key is refused. Input (paths, topic,
 * budget) selects the task brief in native_code_brief.c. */

#include "command/native_command.h"

#include "command/native_code_brief.h"
#include "json/json.h"
#include "util/log_macros.h"

#include <string.h>

#define CG_TAG "native.code.guide"
#if defined(__APPLE__)
#define CG_PROOF_COMMAND "make -j2 t-fast-exact ONLY=<group>"
#else
#define CG_PROOF_COMMAND "make -j\"$(getconf _NPROCESSORS_ONLN)\" t-fast ONLY=<group>"
#endif

static bool cg_render_static(struct zcl_command_reply *reply)
{
    return json_push_kv_str(
               &reply->data, "start_command", "z23 code impact <file.c>") &&
        json_push_kv_str(&reply->data, "proof_command", CG_PROOF_COMMAND) &&
        json_push_kv_str(&reply->data, "lint_command", "make lint-fast") &&
        json_push_kv_str(&reply->data, "capability_inventory",
                         "build/gen/CAPABILITY_INVENTORY.jsonl") &&
        json_push_kv_str(&reply->data, "inventory_regenerate",
                         "make docs-capability-inventory") &&
        json_push_kv_str(&reply->data, "receipt_status_command",
                         "build/bin/z23-dev dev proof status") &&
        json_push_kv_str(&reply->data, "receipt_wait_command",
                         "build/bin/z23-dev dev proof wait") &&
        json_push_kv_str(&reply->data, "legacy_parity_command",
                         "make pre-push-ci") &&
        json_push_kv_str(&reply->data, "push_command",
                         "build/bin/z23-dev dev land submit --worktree=$PWD") &&
        json_push_kv_str(
            &reply->data, "never",
            "test_zcl; omit -datadir; stash; reset; force-push") &&
        json_push_kv_str(&reply->data, "docs", "docs/dev/DEVELOPING.md");
}

void zcl_native_handle_code_guide(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!reply)
        return;
    if (!request || !request->input || request->input->type != JSON_OBJ) {
        LOG_ERROR(CG_TAG, "BAD_CODE_GUIDE_INPUT: code guide input must be "
                          "an object");
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID,
                               "BAD_CODE_GUIDE_INPUT", "validate", false,
                               false, "code guide input must be an object",
                               "code.guide");
        return;
    }
    if (request->input->num_children != 0) {
        zcl_code_brief_render(request, reply);
        return;
    }
    if (!cg_render_static(reply)) {
        LOG_ERROR(CG_TAG, "CODE_GUIDE_OUTPUT: the develop guide could not "
                          "be rendered");
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "CODE_GUIDE_OUTPUT",
                               "render", false, false,
                               "the develop guide could not be rendered",
                               "code.guide");
    }
}
