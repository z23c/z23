/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * zcode_task_context — post a dev task as an ORDINARY content.v2 package
 * (the transport-carrier pattern from fastobj_carrier). No new CAS object,
 * no new wire frame: the package swarm sees one manifest and immutable
 * chunks, and a deterministic root commits identical bytes.
 *
 * Inner layout (fixed, three small files):
 *   zcl-task-context.v1/task.wire          vcs_zcode_task_v1 wire (318 B)
 *   zcl-task-context.v1/goal.bin           goal bytes (task.goal_root preimage)
 *   zcl-task-context.v1/proof-policy.wire  vcs_zcode_proof_policy_v1 wire (36 B)
 *
 * A task object is deliberately unsigned: it is a content-addressed
 * constraint set, not an identity claim. The authenticity of a POSTING is
 * the signed DHT POINTER/PROVIDER pair in VCS_ZCODE_TASK_DHT_NAMESPACE
 * (governed by AGENT_SCOPE grants, like every other namespace); the
 * integrity of the task is the root. What this carrier adds is the part a
 * stranger cannot re-derive from the task wire alone — the goal preimage
 * and the proof policy bytes — bound so that sha3-256(goal.bin) equals
 * task.goal_root and the policy wire roots to task.proof_policy_root.
 * Every rule runs identically at export (publisher hygiene) and at admit
 * (the receiver-side property a stranger relies on), so a pulled context
 * re-proves itself from stored bytes alone.
 *
 * The work lane closes the loop through vcs_zcode_work_solution_admit:
 * a node that admits a task context runs the ordinary local work journey
 * against it, accepts its own work, and offers the resulting source
 * package root under VCS_ZCODE_WORK_DHT_NAMESPACE — keyed by the same
 * task root this carrier proves.
 */

#ifndef ZCL_VCS_ZCODE_TASK_CONTEXT_H
#define ZCL_VCS_ZCODE_TASK_CONTEXT_H

#include "vcs/package_content.h"
#include "vcs/package_store.h"
#include "vcs/zcode_dev.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define VCS_ZCODE_TASK_CONTEXT_PREFIX "zcl-task-context.v1"
#define VCS_ZCODE_TASK_CONTEXT_TASK_PATH \
    VCS_ZCODE_TASK_CONTEXT_PREFIX "/task.wire"
#define VCS_ZCODE_TASK_CONTEXT_GOAL_PATH \
    VCS_ZCODE_TASK_CONTEXT_PREFIX "/goal.bin"
#define VCS_ZCODE_TASK_CONTEXT_POLICY_PATH \
    VCS_ZCODE_TASK_CONTEXT_PREFIX "/proof-policy.wire"

/* The goal preimage bound by a task is human-scale by construction (the
 * work command already refuses anything larger or embedded-NUL). */
#define VCS_ZCODE_TASK_CONTEXT_GOAL_MAX 4096u

/* POINTER records here bind task root (semantic) -> context root
 * (transport); PROVIDER records on the context root say "ask me for these
 * bytes". The pair mirrors VCS_ZCODE_WORK_DHT_NAMESPACE. */
#define VCS_ZCODE_TASK_DHT_NAMESPACE "zclassic23.task"

enum vcs_zcode_task_context_error {
    VCS_ZCODE_TASK_CONTEXT_OK = 0,
    VCS_ZCODE_TASK_CONTEXT_NULL,
    /* task.wire does not parse or the task fails validate_at(now) — an
     * expired posting refuses export AND admit alike. */
    VCS_ZCODE_TASK_CONTEXT_TASK_WIRE,
    VCS_ZCODE_TASK_CONTEXT_TASK_EXPIRED,
    /* goal.bin is empty/oversized/embedded-NUL or does not hash to
     * task.goal_root. */
    VCS_ZCODE_TASK_CONTEXT_GOAL,
    /* proof-policy.wire does not parse, or parses to a root other than
     * task.proof_policy_root. */
    VCS_ZCODE_TASK_CONTEXT_POLICY_WIRE,
    VCS_ZCODE_TASK_CONTEXT_POLICY_MISMATCH,
    /* The stored package is not the fixed three-file carrier shape. */
    VCS_ZCODE_TASK_CONTEXT_MANIFEST,
    /* The store refused a read or write. */
    VCS_ZCODE_TASK_CONTEXT_STORE,
    /* Admit's expect_task_root does not match the verified task. */
    VCS_ZCODE_TASK_CONTEXT_TASK_MISMATCH,
};

const char *vcs_zcode_task_context_error_string(
    enum vcs_zcode_task_context_error error);

/* Every cross-binding rule, run identically by export and admit:
 * task.wire parses and passes vcs_zcode_task_validate_at(now); goal.bin
 * is 1..VCS_ZCODE_TASK_CONTEXT_GOAL_MAX bytes with no embedded NUL and
 * sha3-256's to task.goal_root; proof-policy.wire parses and roots to
 * task.proof_policy_root. Outputs are optional (NULL skips). */
enum vcs_zcode_task_context_error vcs_zcode_task_context_verify_wires(
    const uint8_t *task_wire, size_t task_len, const uint8_t *goal,
    size_t goal_len, const uint8_t *policy_wire, size_t policy_len,
    int64_t now_unix, struct vcs_zcode_task_v1 *task_out,
    struct vcs_zcode_proof_policy_v1 *policy_out,
    uint8_t task_root_out[32]);

/* Verify the wires (above), build the fixed-layout content.v2 carrier,
 * and admit manifest + chunks into `store` through the ordinary
 * verify-before-store paths. The carrier root is deterministic: the same
 * task context always produces the same root, so export is idempotent. */
enum vcs_zcode_task_context_error vcs_zcode_task_context_export(
    const uint8_t *task_wire, size_t task_len, const uint8_t *goal,
    size_t goal_len, const uint8_t *policy_wire, size_t policy_len,
    struct vcs_package_store *store, int64_t now_unix,
    uint8_t root_out[32]);

/* Re-derive the whole context from stored bytes, changing nothing: the
 * manifest loads, parses and roots to `root`; it is exactly the
 * three-file carrier shape; each file reconstructs from verified chunks;
 * and the wires re-pass every verify_wires rule. THIS is the property a
 * stranger relies on after fetching the package — a pulled context
 * re-proves its own task root from bytes alone. `expect_task_root` is
 * the receiver-side binding (NULL derives instead of checking, the same
 * contract as vcs_zcode_work_solution_admit). The goal bytes are copied
 * to goal_out (up to goal_cap; truncated with the full length reported
 * in goal_len_out when the cap is short). */
enum vcs_zcode_task_context_error vcs_zcode_task_context_admit(
    struct vcs_package_store *store, const uint8_t root[32],
    const uint8_t expect_task_root[32], int64_t now_unix,
    struct vcs_zcode_task_v1 *task_out,
    struct vcs_zcode_proof_policy_v1 *policy_out, uint8_t *goal_out,
    size_t goal_cap, size_t *goal_len_out, uint8_t task_root_out[32]);

#endif /* ZCL_VCS_ZCODE_TASK_CONTEXT_H */
