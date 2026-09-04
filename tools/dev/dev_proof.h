/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Exact commit/base proof scheduling and status interface. */

#ifndef ZCL_TOOLS_DEV_PROOF_H
#define ZCL_TOOLS_DEV_PROOF_H

#include "dev_proof_receipt.h"
#include "vcs/build_action.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

enum zcl_dev_proof_state {
    ZCL_DEV_PROOF_STATE_INVALID = -1,
    ZCL_DEV_PROOF_STATE_MISSING = 0,
    ZCL_DEV_PROOF_STATE_RUNNING,
    ZCL_DEV_PROOF_STATE_PASSED,
    ZCL_DEV_PROOF_STATE_FAILED,
};

struct zcl_dev_proof_status {
    enum zcl_dev_proof_state state;
    char local_commit[65];
    char remote_base[65];
    char receipt_path[4096];
    char log_dir[4096];
    char detail[256];
    int64_t started_unix;
    int64_t eta_ms;
    int64_t worker_id;
    bool receipt_reused;
};

struct zcl_dev_proof_child_action_inputs_v1 {
    const char *source_sha256_hex;
    const char *source_cas_sha3_hex;
    uint8_t toolchain_capsule_root[32];
    uint8_t flags_root[32];
    uint8_t environment_root[32];
    uint8_t build_graph_root[32];
    const char *selector;
    uint32_t selected;
};

const char *zcl_dev_proof_state_name(enum zcl_dev_proof_state state);
/* Admit a completed cycle only when its schema, canonical action inputs, and
 * one independently derived fixed-width root per selected proof dimension
 * exactly match. Duplicate critical JSON keys are always inadmissible. */
bool zcl_dev_proof_cycle_reuse_admissible(
    const char *body, size_t body_len, const char *source_cas,
    const char *proof_inputs_sha3,
    const struct zcl_dev_proof_dimension
        dimensions[ZCL_DEV_PROOF_DIMENSIONS]);
/* Derive the existing zcl.build_action.v1 identity for one local proof child.
 * This has no durable task, queue, worker, signing, or admission authority. */
bool zcl_dev_proof_child_action_v1(
    const struct zcl_dev_proof_child_action_inputs_v1 *inputs,
    enum zcl_dev_proof_dimension_id dimension,
    struct vcs_build_action_v1 *action, uint8_t action_root[32]);
/* Testing seam: materialize one generation dependency the way the proof does
 * — link() inside one filesystem, a faithful mode-preserving copy across
 * one. No proof, lease, or admission authority. */
bool zcl_dev_proof_dependency_materialize(const char *source,
                                          const char *target);
bool zcl_dev_proof_resolve_pair(const char *repo_root,
                                const char *requested_local,
                                const char *requested_base,
                                char local_commit[65],
                                char remote_base[65],
                                char *why, size_t why_len);
bool zcl_dev_proof_status_read(const char *repo_root,
                               const char *local_commit,
                               const char *remote_base,
                               struct zcl_dev_proof_status *out);
bool zcl_dev_proof_ensure(const char *repo_root,
                          const char *local_commit,
                          const char *remote_base,
                          struct zcl_dev_proof_status *out);
/* The singleton development watcher owns this queue. Notifications only
 * publish immutable pair requests; the resident owner claims and executes at
 * most one leased attempt at a time. */
bool zcl_dev_proof_queue_has_pending(const char *repo_root);
int zcl_dev_proof_queue_run_next(const char *repo_root,
                                 char *why, size_t why_len);
bool zcl_dev_proof_wait(const char *repo_root,
                        const char *local_commit,
                        const char *remote_base,
                        int timeout_ms,
                        struct zcl_dev_proof_status *out);

#if defined(ZCL_TESTING)
/* Seam for the selection regression: the same builder the proof worker uses,
 * so a test can prove a universal plan selects the whole catalog without
 * running a proof cycle. */
struct zcl_devloop_plan;
bool zcl_dev_proof_test_build_test_selector(
    const struct zcl_devloop_plan *plan, bool inventory_only,
    char *out, size_t out_size, uint32_t *count_out);
#endif

#endif
