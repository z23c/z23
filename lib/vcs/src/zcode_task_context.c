/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: fixed-layout content.v2 carrier for posting a dev task — see
 * vcs/zcode_task_context.h for the layout and the doctrine. */

#include "vcs/zcode_task_context.h"

#include "base/safe_alloc.h"
#include "sha3/sha3.h"

#include <stdio.h>
#include <string.h>

const char *vcs_zcode_task_context_error_string(
    enum vcs_zcode_task_context_error error)
{
    switch (error) {
    case VCS_ZCODE_TASK_CONTEXT_OK: return "ok";
    case VCS_ZCODE_TASK_CONTEXT_NULL: return "null argument";
    case VCS_ZCODE_TASK_CONTEXT_TASK_WIRE:
        return "task wire does not parse";
    case VCS_ZCODE_TASK_CONTEXT_TASK_EXPIRED:
        return "task fails validation at the given time (expired or not "
               "yet valid)";
    case VCS_ZCODE_TASK_CONTEXT_GOAL:
        return "goal bytes are malformed or do not hash to task.goal_root";
    case VCS_ZCODE_TASK_CONTEXT_POLICY_WIRE:
        return "proof policy wire does not parse";
    case VCS_ZCODE_TASK_CONTEXT_POLICY_MISMATCH:
        return "proof policy roots somewhere other than "
               "task.proof_policy_root";
    case VCS_ZCODE_TASK_CONTEXT_MANIFEST:
        return "package is not the fixed three-file task-context carrier";
    case VCS_ZCODE_TASK_CONTEXT_STORE: return "package store refused";
    case VCS_ZCODE_TASK_CONTEXT_TASK_MISMATCH:
        return "context proves a different task than the expected root";
    }
    return "unknown";
}

/* ── wire rules (shared by export and admit) ────────────────────────── */

enum vcs_zcode_task_context_error vcs_zcode_task_context_verify_wires(
    const uint8_t *task_wire, size_t task_len, const uint8_t *goal,
    size_t goal_len, const uint8_t *policy_wire, size_t policy_len,
    int64_t now_unix, struct vcs_zcode_task_v1 *task_out,
    struct vcs_zcode_proof_policy_v1 *policy_out,
    uint8_t task_root_out[32])
{
    if (task_out) memset(task_out, 0, sizeof(*task_out));
    if (policy_out) memset(policy_out, 0, sizeof(*policy_out));
    if (task_root_out) memset(task_root_out, 0, 32);
    if (!task_wire || !goal || !policy_wire)
        return VCS_ZCODE_TASK_CONTEXT_NULL;
    struct vcs_zcode_task_v1 task;
    if (vcs_zcode_task_parse(task_wire, task_len, &task) !=
        VCS_ZCODE_DEV_OK)
        return VCS_ZCODE_TASK_CONTEXT_TASK_WIRE;
    enum vcs_zcode_dev_error at =
        vcs_zcode_task_validate_at(&task, now_unix);
    if (at == VCS_ZCODE_DEV_ERR_EXPIRY)
        return VCS_ZCODE_TASK_CONTEXT_TASK_EXPIRED;
    if (at != VCS_ZCODE_DEV_OK)
        return VCS_ZCODE_TASK_CONTEXT_TASK_WIRE;
    if (goal_len == 0 || goal_len > VCS_ZCODE_TASK_CONTEXT_GOAL_MAX ||
        memchr(goal, '\0', goal_len))
        return VCS_ZCODE_TASK_CONTEXT_GOAL;
    uint8_t goal_check[32];
    sha3_256(goal, goal_len, goal_check);
    if (memcmp(goal_check, task.goal_root, 32) != 0)
        return VCS_ZCODE_TASK_CONTEXT_GOAL;
    struct vcs_zcode_proof_policy_v1 policy;
    if (vcs_zcode_proof_policy_parse(policy_wire, policy_len, &policy) !=
        VCS_ZCODE_DEV_OK)
        return VCS_ZCODE_TASK_CONTEXT_POLICY_WIRE;
    if (vcs_zcode_proof_policy_validate(&policy) != VCS_ZCODE_DEV_OK)
        return VCS_ZCODE_TASK_CONTEXT_POLICY_WIRE;
    uint8_t policy_root[32];
    if (vcs_zcode_proof_policy_root(&policy, policy_root) !=
        VCS_ZCODE_DEV_OK ||
        memcmp(policy_root, task.proof_policy_root, 32) != 0)
        return VCS_ZCODE_TASK_CONTEXT_POLICY_MISMATCH;
    if (task_out) *task_out = task;
    if (policy_out) *policy_out = policy;
    if (task_root_out &&
        vcs_zcode_task_root(&task, task_root_out) != VCS_ZCODE_DEV_OK)
        return VCS_ZCODE_TASK_CONTEXT_TASK_WIRE;
    return VCS_ZCODE_TASK_CONTEXT_OK;
}

/* ── export ─────────────────────────────────────────────────────────── */

enum vcs_zcode_task_context_error vcs_zcode_task_context_export(
    const uint8_t *task_wire, size_t task_len, const uint8_t *goal,
    size_t goal_len, const uint8_t *policy_wire, size_t policy_len,
    struct vcs_package_store *store, int64_t now_unix, uint8_t root_out[32])
{
    if (root_out) memset(root_out, 0, 32);
    if (!store || !root_out)
        return VCS_ZCODE_TASK_CONTEXT_NULL;
    /* Publisher hygiene: refuse to export a context whose own bindings do
     * not hold. The receiver re-runs every rule, so this gate only stops
     * THIS node from publishing garbage. */
    struct vcs_zcode_task_v1 task;
    uint8_t task_root[32];
    enum vcs_zcode_task_context_error verified =
        vcs_zcode_task_context_verify_wires(
            task_wire, task_len, goal, goal_len, policy_wire, policy_len,
            now_unix, &task, NULL, task_root);
    if (verified != VCS_ZCODE_TASK_CONTEXT_OK)
        return verified;

    struct vcs_package_manifest manifest;
    vcs_package_manifest_init(&manifest);
    bool ok =
        vcs_package_content_add_file(
            &manifest, VCS_ZCODE_TASK_CONTEXT_TASK_PATH,
            VCS_PACKAGE_MODE_FILE, task_wire, task_len) &&
        vcs_package_content_add_file(
            &manifest, VCS_ZCODE_TASK_CONTEXT_GOAL_PATH,
            VCS_PACKAGE_MODE_FILE, goal, goal_len) &&
        vcs_package_content_add_file(
            &manifest, VCS_ZCODE_TASK_CONTEXT_POLICY_PATH,
            VCS_PACKAGE_MODE_FILE, policy_wire, policy_len);
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    uint8_t root[32] = {0};
    if (ok && (!vcs_package_manifest_serialize(&manifest, &wire,
                                                &wire_len) ||
               !vcs_package_manifest_root(&manifest, root)))
        ok = false;
    uint8_t stored_root[32] = {0};
    if (ok) {
        enum vcs_package_store_result r =
            vcs_package_store_put_manifest(store, wire, wire_len,
                                           stored_root);
        if (r != VCS_PACKAGE_STORE_OK ||
            memcmp(stored_root, root, 32) != 0)
            ok = false;
    }
    if (ok &&
        (vcs_package_content_put_file(
             store, root, VCS_ZCODE_TASK_CONTEXT_TASK_PATH, task_wire,
             task_len) != VCS_PACKAGE_STORE_OK ||
         vcs_package_content_put_file(
             store, root, VCS_ZCODE_TASK_CONTEXT_GOAL_PATH, goal,
             goal_len) != VCS_PACKAGE_STORE_OK ||
         vcs_package_content_put_file(
             store, root, VCS_ZCODE_TASK_CONTEXT_POLICY_PATH, policy_wire,
             policy_len) != VCS_PACKAGE_STORE_OK))
        ok = false;
    if (ok) {
        struct vcs_package_store_status status;
        /* bool return, not a store result code. */
        if (!vcs_package_store_package_status(store, root, &status) ||
            !status.complete)
            ok = false;
    }
    vcs_package_manifest_free(&manifest);
    free(wire);
    if (!ok)
        return VCS_ZCODE_TASK_CONTEXT_STORE;
    memcpy(root_out, root, 32);
    return VCS_ZCODE_TASK_CONTEXT_OK;
}

/* ── admit ──────────────────────────────────────────────────────────── */

/* Exactly the three fixed paths, each exactly once, with the sizes the
 * wires demand. The parses re-check content, so this is shape discipline,
 * not the integrity property — that is the re-rooted manifest plus
 * chunk-hashed reads below. */
static bool tc_manifest_shape_ok(const struct vcs_package_manifest *manifest)
{
    if (manifest->count != 3)
        return false;
    const struct vcs_package_file *task = NULL, *goal = NULL, *policy = NULL;
    for (size_t i = 0; i < manifest->count; i++) {
        const char *path = manifest->files[i].path;
        if (strcmp(path, VCS_ZCODE_TASK_CONTEXT_TASK_PATH) == 0)
            task = &manifest->files[i];
        else if (strcmp(path, VCS_ZCODE_TASK_CONTEXT_GOAL_PATH) == 0)
            goal = &manifest->files[i];
        else if (strcmp(path, VCS_ZCODE_TASK_CONTEXT_POLICY_PATH) == 0)
            policy = &manifest->files[i];
    }
    return task && goal && policy &&
           task->size == VCS_ZCODE_TASK_WIRE_BYTES &&
           policy->size == VCS_ZCODE_PROOF_POLICY_WIRE_BYTES &&
           goal->size >= 1u && goal->size <= VCS_ZCODE_TASK_CONTEXT_GOAL_MAX;
}

static enum vcs_zcode_task_context_error tc_read_member(
    struct vcs_package_store *store, const uint8_t root[32],
    const struct vcs_package_manifest *manifest, const char *path,
    uint8_t **out, size_t *out_len)
{
    for (uint32_t i = 0; i < manifest->count; i++)
        if (strcmp(manifest->files[i].path, path) == 0)
            return vcs_package_content_get_file_at(store, root, manifest, i,
                                                   out, out_len) ==
                           VCS_PACKAGE_STORE_OK
                       ? VCS_ZCODE_TASK_CONTEXT_OK
                       : VCS_ZCODE_TASK_CONTEXT_STORE;
    return VCS_ZCODE_TASK_CONTEXT_MANIFEST;
}

enum vcs_zcode_task_context_error vcs_zcode_task_context_admit(
    struct vcs_package_store *store, const uint8_t root[32],
    const uint8_t expect_task_root[32], int64_t now_unix,
    struct vcs_zcode_task_v1 *task_out,
    struct vcs_zcode_proof_policy_v1 *policy_out, uint8_t *goal_out,
    size_t goal_cap, size_t *goal_len_out, uint8_t task_root_out[32])
{
    if (task_out) memset(task_out, 0, sizeof(*task_out));
    if (policy_out) memset(policy_out, 0, sizeof(*policy_out));
    if (goal_out && goal_cap) memset(goal_out, 0, goal_cap);
    if (goal_len_out) *goal_len_out = 0;
    if (task_root_out) memset(task_root_out, 0, 32);
    if (!store || !root || (!goal_out && goal_cap))
        return VCS_ZCODE_TASK_CONTEXT_NULL;

    uint8_t *wire = NULL;
    size_t wire_len = 0;
    if (vcs_package_store_get_manifest_wire(store, root, &wire,
                                            &wire_len) !=
        VCS_PACKAGE_STORE_OK) {
        free(wire);
        return VCS_ZCODE_TASK_CONTEXT_STORE;
    }
    struct vcs_package_manifest manifest;
    enum vcs_zcode_task_context_error err = VCS_ZCODE_TASK_CONTEXT_OK;
    if (!vcs_package_manifest_parse(wire, wire_len, &manifest))
        err = VCS_ZCODE_TASK_CONTEXT_MANIFEST;
    uint8_t derived[32];
    if (err == VCS_ZCODE_TASK_CONTEXT_OK &&
        (!vcs_package_manifest_root(&manifest, derived) ||
         memcmp(derived, root, 32) != 0))
        err = VCS_ZCODE_TASK_CONTEXT_MANIFEST;
    if (err == VCS_ZCODE_TASK_CONTEXT_OK && !tc_manifest_shape_ok(&manifest))
        err = VCS_ZCODE_TASK_CONTEXT_MANIFEST;

    uint8_t *task_wire = NULL, *goal = NULL, *policy_wire = NULL;
    size_t task_len = 0, goal_len = 0, policy_len = 0;
    if (err == VCS_ZCODE_TASK_CONTEXT_OK)
        err = tc_read_member(store, root, &manifest,
                             VCS_ZCODE_TASK_CONTEXT_TASK_PATH, &task_wire,
                             &task_len);
    if (err == VCS_ZCODE_TASK_CONTEXT_OK)
        err = tc_read_member(store, root, &manifest,
                             VCS_ZCODE_TASK_CONTEXT_GOAL_PATH, &goal,
                             &goal_len);
    if (err == VCS_ZCODE_TASK_CONTEXT_OK)
        err = tc_read_member(store, root, &manifest,
                             VCS_ZCODE_TASK_CONTEXT_POLICY_PATH,
                             &policy_wire, &policy_len);

    uint8_t task_root[32];
    if (err == VCS_ZCODE_TASK_CONTEXT_OK) {
        struct vcs_zcode_task_v1 task;
        err = vcs_zcode_task_context_verify_wires(
            task_wire, task_len, goal, goal_len, policy_wire, policy_len,
            now_unix, &task, policy_out, task_root);
        if (err == VCS_ZCODE_TASK_CONTEXT_OK) {
            if (expect_task_root &&
                memcmp(task_root, expect_task_root, 32) != 0)
                err = VCS_ZCODE_TASK_CONTEXT_TASK_MISMATCH;
            else {
                if (task_out) *task_out = task;
                if (task_root_out) memcpy(task_root_out, task_root, 32);
                if (goal_len_out) *goal_len_out = goal_len;
                if (goal_out) {
                    size_t copied = goal_len < goal_cap ? goal_len : goal_cap;
                    memcpy(goal_out, goal, copied);
                }
            }
        }
    }
    free(task_wire);
    free(goal);
    free(policy_wire);
    vcs_package_manifest_free(&manifest);
    free(wire);
    return err;
}
