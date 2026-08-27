/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Read-only inner-loop guide for coding agents (`code.guide`).
 *
 * THE INVARIANT OF THIS FILE: the handler reads no checkout, datadir, wallet,
 * compiler, or test state. It renders the currently honest edit/proof loop
 * and refuses extra input keys. */

#include "command/native_command.h"

#include "json/json.h"
#include "util/log_macros.h"

#include <string.h>

#define CG_TAG "native.code.guide"

void zcl_native_handle_code_guide(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!reply)
        return;
    if (!request || !request->input || request->input->type != JSON_OBJ ||
        request->input->num_children != 0) {
        LOG_ERROR(CG_TAG, "BAD_CODE_GUIDE_INPUT: code guide accepts no "
                          "input keys");
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID,
                               "BAD_CODE_GUIDE_INPUT", "validate", false,
                               false, "code guide accepts no input keys",
                               "code.guide");
        return;
    }
    bool ok = json_push_kv_str(
            &reply->data, "start_command", "z23 code impact <file.c>") &&
        json_push_kv_str(&reply->data, "proof_command",
                         "make -j\"$(getconf _NPROCESSORS_ONLN)\" t-fast ONLY=<group>") &&
        json_push_kv_str(&reply->data, "lint_command", "make lint-fast") &&
        json_push_kv_str(&reply->data, "push_command", "make pre-push-ci") &&
        json_push_kv_str(
            &reply->data, "never",
            "full make lint; test_zcl; omit -datadir; stash; restart") &&
        json_push_kv_str(&reply->data, "docs", "docs/DEVELOPING.md");
    if (!ok) {
        LOG_ERROR(CG_TAG, "CODE_GUIDE_OUTPUT: the develop guide could not "
                          "be rendered");
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "CODE_GUIDE_OUTPUT",
                               "render", false, false,
                               "the develop guide could not be rendered",
                               "code.guide");
    }
}
