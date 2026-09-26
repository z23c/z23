/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Physical compile identity checks before attach-index publication. */

#include "build_fabric_worker_internal.h"
#include "services/build_fabric_attach.h"
#include "vcs/build_action.h"

#include <string.h>

#if !defined(_WIN32)

bool bfw_attach_identity_capture(
    const char *workspace, const char *selected_verifier,
    uint8_t work_kind, bool package_action,
    struct build_fabric_executor_identity *out)
{
    bool compile_action = work_kind == VCS_ZCODE_WORK_BUILD && !package_action;
    if (!compile_action || !workspace || !selected_verifier || !out)
        return false;
    char selected[4096];
    struct zcl_result path = bfw_worker_path(workspace, selected,
                                             sizeof(selected));
    if (!path.ok || strcmp(selected, selected_verifier) != 0)
        return false;
    struct zcl_result tools = build_fabric_executor_host_tool_hashes(
        out->driver, out->backend, out->assembler);
    struct zcl_result runtime = build_fabric_executor_host_runtime_roots(
        workspace, out->runtime, out->verifier);
    return tools.ok && runtime.ok;
}

bool bfw_attach_identity_finish(
    const char *workspace, const char *selected_verifier, bool started,
    const struct build_fabric_executor_identity *before)
{
    if (!started || !before) return false;
    struct build_fabric_executor_identity after;
    return bfw_attach_identity_capture(workspace, selected_verifier,
                                       VCS_ZCODE_WORK_BUILD, false, &after) &&
           memcmp(before, &after, sizeof(after)) == 0;
}

void bfw_attach_publish_checked(
    bool stable, const char *workspace, const struct db_build_job *job,
    const struct db_build_action *action, const uint8_t input_root[32],
    const struct build_fabric_executor_identity *identity)
{
    if (stable)
        build_fabric_executor_key_publish_logged(
            workspace, job, action, input_root, identity);
}

#endif
