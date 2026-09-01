/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: CAS artifact and signed receipt publication for fixed workers. */

#ifndef ZCL_SERVICES_BUILD_FABRIC_WORKER_EVIDENCE_H
#define ZCL_SERVICES_BUILD_FABRIC_WORKER_EVIDENCE_H

#include "models/build_fabric.h"
#include "util/result.h"
#include "vcs/build_execution_observation.h"
#include "vcs/zcode_dev.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct zcl_result build_fabric_worker_store_artifact(
    const char *workspace, const char *action_id, const uint8_t *bytes,
    size_t len, uint8_t manifest_root[32]);

/* ZCODE daemon work publishes an action-bound content.v2 carrier so its
 * output can cross the existing swarm. Hermetic/local fixtures without a
 * package store retain the legacy workspace artifact representation. */
struct zcl_result build_fabric_worker_store_transferable_output(
    const char *workspace, const char *action_id, bool zcode_context,
    const uint8_t *bytes, size_t len, uint8_t output_root[32]);

/* Persist the canonical physical observation after the output artifact has
 * been quarantined. The worker may return this root to its supervisor; this
 * function grants no cache or action-lifecycle authority. */
struct zcl_result build_fabric_worker_store_observation(
    const char *workspace,
    const struct vcs_build_execution_observation_v1 *observation,
    uint8_t observation_root[32]);

struct zcl_result build_fabric_worker_canonical_receipt(
    const char *workspace, const struct db_build_action *action,
    const struct vcs_zcode_task_v1 *task,
    const struct vcs_zcode_candidate_v1 *candidate,
    const uint8_t output_root[32], int64_t started, int64_t finished,
    const uint8_t evidence_root[32],
    uint8_t work_kind, uint8_t status, int exit_status,
    const char *confinement,
    const uint8_t signer_secret[32], const uint8_t signer_pubkey[32],
    char out_hex[65]);

#endif /* ZCL_SERVICES_BUILD_FABRIC_WORKER_EVIDENCE_H */
