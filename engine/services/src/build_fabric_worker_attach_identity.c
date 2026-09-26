/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Physical compile identity checks before attach-index publication. */

#include "build_fabric_worker_internal.h"
#include "build_fabric_attach_identity_internal.h"
#include "services/build_fabric_attach.h"
#include "base/log_macros.h"
#include "vcs/build_action.h"

#include <string.h>

#if !defined(_WIN32)

static bool bfw_attach_identity_capture(
    const char *workspace, const char *selected_verifier,
    struct bfat_verifier_snapshot *snapshot,
    uint8_t work_kind, bool package_action,
    struct build_fabric_executor_identity *out)
{
    bool compile_action = work_kind == VCS_ZCODE_WORK_BUILD && !package_action;
    if (!compile_action || !workspace || !selected_verifier ||
        !snapshot || snapshot->fd < 0 || !out)
        return false;
    char selected[4096];
    struct zcl_result path = bfw_worker_path(workspace, selected,
                                             sizeof(selected));
    if (!path.ok || strcmp(selected, selected_verifier) != 0)
        return false;
    struct zcl_result tools = build_fabric_executor_host_tool_hashes(
        out->driver, out->backend, out->assembler);
    struct vcs_toolchain_capsule_v1 capsule;
    struct platform_toolchain_descriptor descriptor;
    if (!vcs_toolchain_capsule_v1_cached(&capsule, &descriptor)) return false;
    struct zcl_result runtime = bfat_runtime_roots_snapshot(workspace, &descriptor,
        snapshot, out->runtime, out->verifier);
    return tools.ok && runtime.ok;
}

static bool bfw_attach_identity_finish(
    const char *workspace, const char *selected_verifier,
    struct bfat_verifier_snapshot *snapshot, bool started,
    const struct build_fabric_executor_identity *before)
{
    if (!started || !before) return false;
    struct build_fabric_executor_identity after;
    return bfw_attach_identity_capture(workspace, selected_verifier, snapshot,
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

int bfw_attach_spawn(
    const char *workspace, const char *selected_verifier,
    uint8_t work_kind, bool package_action, const char *const argv[],
    char *capture, size_t capture_cap, int timeout_ms,
    zcl_spawn_cancel_fn should_cancel, void *cancel_ctx, bool *cancelled,
    struct build_fabric_executor_identity *identity, bool *stable)
{
    struct bfat_verifier_snapshot snapshot = { .fd = -1 };
    if (work_kind == VCS_ZCODE_WORK_BUILD && !package_action) {
        struct zcl_result opened = bfat_verifier_snapshot_open(
            selected_verifier, &snapshot);
        if (!opened.ok)
            LOG_WARN("build.fabric", "compile attach unavailable: %s",
                     opened.message);
    }
    *stable = bfw_attach_identity_capture(workspace, selected_verifier,
                                          &snapshot, work_kind,
                                          package_action, identity);
    int rc = snapshot.fd >= 0
        ? zcl_spawn_capture_cancelable_fd(
            snapshot.fd, argv, capture, capture_cap, timeout_ms,
            should_cancel, cancel_ctx, cancelled)
        : zcl_spawn_capture_cancelable(
            argv, capture, capture_cap, timeout_ms,
            should_cancel, cancel_ctx, cancelled);
    *stable = bfw_attach_identity_finish(workspace, selected_verifier,
                                          &snapshot, *stable, identity);
    bfat_verifier_snapshot_close(&snapshot);
    return rc;
}

#endif
