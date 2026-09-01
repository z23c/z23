/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Background requester-local dispatch over the existing work swarm. */

#ifndef ZCL_CONFIG_BOOT_ZCODE_ASYNC_PROOF_H
#define ZCL_CONFIG_BOOT_ZCODE_ASYNC_PROOF_H

#include <stdint.h>

struct boot_svc_ctx;
struct vcs_zcode_work_node;
struct node_db;
struct vcs_zcode_work_request_v1;
struct vcs_zcode_work_result_v1;
struct vcs_zcode_work_progress_v1;
struct vcs_zcode_work_admission_v1;
struct rpc_table;

/* The live node is the sole writer of its proof ledger.  The typed CLI sends
 * an already-bounded improve/admit input over the authenticated loopback RPC;
 * the daemon re-runs the canonical handler against app_runtime_node_db(). */
void boot_zcode_async_proof_register_rpc(struct rpc_table *table);

void boot_zcode_async_proof_tick(
    struct boot_svc_ctx *svc, struct vcs_zcode_work_node *work, int64_t now);
void boot_zcode_async_proof_drain_admissions(
    struct vcs_zcode_work_node *work, int64_t now);
bool boot_zcode_async_proof_workspace(
    struct node_db *ndb, const struct vcs_zcode_work_request_v1 *request,
    char out[4096]);
bool boot_zcode_async_proof_observe_result(
    struct node_db *ndb, uint64_t peer,
    const struct vcs_zcode_work_request_v1 *request,
    const struct vcs_zcode_work_result_v1 *result,
    const char *receipt_root, int64_t verification_us, int64_t now);
bool boot_zcode_async_proof_observe_progress(
    struct node_db *ndb, uint64_t peer,
    const struct vcs_zcode_work_request_v1 *request,
    const struct vcs_zcode_work_progress_v1 *progress, int64_t now);
bool boot_zcode_async_proof_observe_admission(
    struct node_db *ndb, uint64_t peer,
    const struct vcs_zcode_work_request_v1 *request,
    const struct vcs_zcode_work_admission_v1 *admission, int64_t now);

#endif /* ZCL_CONFIG_BOOT_ZCODE_ASYNC_PROOF_H */
