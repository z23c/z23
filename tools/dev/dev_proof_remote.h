/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * Purpose: verify returned proof receipts against independently pinned inputs. */
#ifndef ZCL_DEV_PROOF_REMOTE_H
#define ZCL_DEV_PROOF_REMOTE_H

#include "dev_proof_receipt.h"
#include "dev_proof.h"
#include "devloop.h"

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
 * Native admission owns signer trust, policy, pair and foreign toolchain
 * checks. This wrapper additionally checks current identity for local-signed
 * returns, without changing native policy's legacy local-signer exception.
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

/* Only the existing LOCAL operator-authorized receiver may call placement.
 * Its callback binds the canonical destination to the invocation source root
 * and a registered existing linked lane, never canonical main. Neither a path
 * nor a cooperative claim is an authenticated writer-lifetime credential.
 * This module owns the existing proof execution guard during preparation and
 * execution rechecks; callers must not hold it across these calls. Automated
 * task dispatch is not authorized by this API. */
typedef bool (*zcl_dev_proof_remote_owner_check)(
    void *ctx, const char *root, char *why, size_t why_len);

struct zcl_dev_proof_remote_assignment {
    const char *repository;
    const char *destination;
    const char *bundle;
    const char *offer;
    struct zcl_dev_proof_remote_expectation expected;
    char bundle_sha256[65];
    char git_tree[65];
    char source_id[65];
};

/* Observation only, not an authority ticket. Progress/evidence survives
 * failure: object import and checkout are not an atomic transaction. Existing
 * branches are never changed; previous_head records the prior checkout. */
struct zcl_dev_proof_remote_placement {
    char canonical_root[4096];
    char common_git_dir[4096];
    char evidence_dir[4096];
    char previous_head[65];
    char local_commit[65];
    char remote_base[65];
    char git_tree[65];
    struct dev_source_record source;
    bool objects_imported;
    bool placed;
};

/* Both prepare and execute require existing host admission (operational
 * DEVBUILD_ACTIVE=z23 check, never an authority credential). Import a checked
 * Git bundle into an EXISTING owned clean Git workspace,
 * then nonforce checkout detached, without overwriting ignored files.
 * Refuses redirected Git environments and requires PATH=/usr/bin:/bin.
 * Private input snapshots are retained under the checkout's .cache/zcl-dev-proof,
 * in evidence_dir on success/failure, independently of admitted-job TMPDIR.
 * Caller retires them after final receipt/diagnostic handoff. No worktrees,
 * branches, queues, resets, cleaning, hooks or services are created. Native
 * source capture can refresh its ordinary development caches and execute its
 * bounded build helper only AFTER native CAS verifies the pinned source. */
bool zcl_dev_proof_remote_prepare(
    const struct zcl_dev_proof_remote_assignment *assignment,
    zcl_dev_proof_remote_owner_check owner_check, void *owner_ctx,
    struct zcl_dev_proof_remote_placement *out, char *why, size_t why_len);

/* Caller runs under existing host admission and the bound LOCAL context.
 * DEVBUILD_ACTIVE=z23 is checked as an operational precondition, NOT as an
 * authority credential. Revalidates placement and LOCAL mutation observation
 * under the execution guard, then releases it before native step acquires its
 * own guard and rechecks/seals source. Before returning PASSED, reacquires the
 * guard and rechecks destination identity and mutation; drift withholds remote
 * acceptance while preserving the native generation receipt. This is an
 * observation at settlement, not a lease against subsequent workspace changes.
 * Return 1 means settled, NOT PASS; inspect the
 * native status and separately verify the returned receipt/pinned roots.
 * 0 is busy; -1 is invalid/unavailable or a named execution/settlement NO_VERDICT. */
int zcl_dev_proof_remote_execute(
    const struct zcl_dev_proof_remote_assignment *assignment,
    const struct zcl_dev_proof_remote_placement *observed,
    zcl_dev_proof_remote_owner_check owner_check, void *owner_ctx,
    struct zcl_dev_proof_status *out);

#endif
