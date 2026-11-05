/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * Purpose: verify returned proof receipts against independently pinned inputs. */
#ifndef ZCL_DEV_PROOF_REMOTE_H
#define ZCL_DEV_PROOF_REMOTE_H

#include "dev_proof_receipt.h"

/* Supplied by an authenticated caller, never copied from the returned receipt.
 * source_root is the receipt's Git-commit-derived root, NOT a Git tree,
 * captured source_id or ZVCS CAS root. Those identities must stay distinct.
 * These expectations do not establish source placement or permission to run. */
struct zcl_dev_proof_remote_expectation {
    const char *local_commit;
    const char *remote_base;
    uint8_t signer_pubkey[32];
    uint8_t source_root[32];
    uint8_t source_cas_root[32];
    uint8_t changed_set_root[32];
    uint8_t impact_policy_root[32];
};

/* Read-only native admission plus exact caller binding. capture must be the
 * receiver's trusted host-identity capture, not a callback fed returned roots.
 * Native admission owns signer trust, policy, pair and toolchain checks.
 * No cross-host mutation comparison or additional expiry policy is imposed.
 * On failure out is unchanged; why receives a native or remote_* refusal.
 * Success neither places source nor executes, imports or publishes evidence;
 * coverage/observation reuse and current-base confirmation remain separate. */
bool zcl_dev_proof_remote_verify(
    const uint8_t *wire, size_t wire_len,
    const struct zcl_dev_proof_remote_expectation *expected,
    zcl_dev_proof_host_toolchain_fn capture, void *capture_ctx,
    struct zcl_dev_acceptance_receipt_v1 *out,
    char *why, size_t why_len);

#endif
