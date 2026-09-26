/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Durable signed receipt for one independently verified work pull.
 *
 * A work pull verifies that the source package named by a zclassic23.work
 * POINTER reconstructs to a proven accepted work solving exactly the task
 * the reader asked about. This header records that observation in the
 * existing canonical vcs_zcode_work_receipt_v1 object — no new wire, no new
 * ledger — with fixed field conventions:
 *
 *   task_root              the task the package's own chain proves (== asked)
 *   candidate_root         the accepted candidate of that chain
 *   action_root            SHA3(ACTION_DOMAIN || task_root || package_root):
 *                          the observation's lookup key, never its identity
 *   input_root             the fetched or already-held package root
 *   output_root            the reconstructed source root
 *   proof_policy_root      the task's proof policy
 *   toolchain_capsule_root the task's toolchain capsule
 *   lease_id               the POINTER record root that published it
 *   evidence_root          the accepted-work (PROVEN lane receipt) root
 *   confinement_root       SHA3 of the fixed CONFINEMENT statement
 *   work_kind/status       REPRODUCE / PASS, exit_status 0
 *   started/finished_unix  when the pull began / observed the verification
 *   signer_pubkey          the observer's key
 *
 * The receipt root is the existing work-receipt id. Receipts are written to
 * the workspace CAS at that root, and also at a locator address derived from
 * every bound root plus the observer key, so a repeated pull of the same
 * roots attaches to the first receipt instead of minting another. Only a
 * successful receiver-side admit can produce one. A receipt proves that this
 * observer verified these roots; it grants no acceptance, execution or
 * publication authority. */

#ifndef ZCL_VCS_ZCODE_WORK_PULL_RECEIPT_H
#define ZCL_VCS_ZCODE_WORK_PULL_RECEIPT_H

#include "vcs/package_store.h"
#include "vcs/source_package_checkout.h"
#include "vcs/zcode_dev.h"

#include <stdbool.h>
#include <stdint.h>

#define VCS_ZCODE_WORK_PULL_ACTION_DOMAIN "zcl.zcode.work_pull.action.v1"
#define VCS_ZCODE_WORK_PULL_LOCATOR_DOMAIN "zcl.zcode.work_pull.locator.v1"
#define VCS_ZCODE_WORK_PULL_CONFINEMENT                                     \
    "zcode-work-pull:reconstruct-verify;scratch=private,removed;"           \
    "execute=0;install=0;accept=0;publish=0"

enum vcs_zcode_work_pull_receipt_result {
    VCS_ZCODE_WORK_PULL_RECEIPT_OK = 0,
    VCS_ZCODE_WORK_PULL_RECEIPT_NULL,
    VCS_ZCODE_WORK_PULL_RECEIPT_NOT_VERIFIED,
    VCS_ZCODE_WORK_PULL_RECEIPT_NO_POINTER,
    VCS_ZCODE_WORK_PULL_RECEIPT_NO_OBSERVER,
    VCS_ZCODE_WORK_PULL_RECEIPT_TIME,
    VCS_ZCODE_WORK_PULL_RECEIPT_SEAL,
    VCS_ZCODE_WORK_PULL_RECEIPT_STORE,
    VCS_ZCODE_WORK_PULL_RECEIPT_NOT_FOUND,
    VCS_ZCODE_WORK_PULL_RECEIPT_CODEC,
    VCS_ZCODE_WORK_PULL_RECEIPT_ROOT_MISMATCH,
    VCS_ZCODE_WORK_PULL_RECEIPT_SIGNATURE,
    VCS_ZCODE_WORK_PULL_RECEIPT_NOT_PULL,
    VCS_ZCODE_WORK_PULL_RECEIPT_NOT_HELD,
    VCS_ZCODE_WORK_PULL_RECEIPT_CONTRADICTED,
};

const char *vcs_zcode_work_pull_receipt_result_string(
    enum vcs_zcode_work_pull_receipt_result result);

/* One pull observation. The caller fills the first five fields; the rest
 * are outputs. source/accepted roots are filled only when admit is OK; the
 * receipt and its root only when the call returns OK. */
struct vcs_zcode_work_pull_observation {
    uint8_t task_root[32];
    uint8_t package_root[32];
    uint8_t pointer_root[32];
    int64_t started_unix;
    int64_t observed_unix;
    enum vcs_zcode_work_admit_result admit;
    uint8_t source_root[32];
    uint8_t accepted_work_root[32];
    struct vcs_zcode_work_receipt_v1 receipt;
    uint8_t receipt_root[32];
    bool attached;
};

bool vcs_zcode_work_pull_action_root(const uint8_t task_root[32],
                                     const uint8_t package_root[32],
                                     uint8_t out[32]);

/* Run vcs_zcode_work_solution_admit with expect_task_root = task_root on
 * the held package, then — only on OK — seal and durably store the receipt
 * in workspace's CAS, or attach to the identical earlier observation by the
 * same observer. A NULL observer key still verifies (admit is reported) but
 * returns NO_OBSERVER and writes nothing. */
enum vcs_zcode_work_pull_receipt_result vcs_zcode_work_pull_observe(
    struct vcs_package_store *store, const char *workspace,
    const uint8_t observer_secret[32], const uint8_t observer_pubkey[32],
    struct vcs_zcode_work_pull_observation *io);

/* Structure, signature (by the receipt's own signer) and the fixed pull
 * conventions: REPRODUCE/PASS/exit 0, the derived action root and the fixed
 * confinement root. Signer trust is a separate policy decision. */
enum vcs_zcode_work_pull_receipt_result vcs_zcode_work_pull_receipt_check(
    const struct vcs_zcode_work_receipt_v1 *receipt);

/* Parse one exact 448-byte wire, rederive its root, require expected_root
 * when non-NULL, then apply receipt_check. Output is cleared on refusal. */
enum vcs_zcode_work_pull_receipt_result vcs_zcode_work_pull_receipt_decode(
    const uint8_t *wire, size_t wire_len, const uint8_t expected_root[32],
    struct vcs_zcode_work_receipt_v1 *out, uint8_t root_out[32]);

/* Bounded CAS read of the receipt at root, then decode against root. */
enum vcs_zcode_work_pull_receipt_result vcs_zcode_work_pull_receipt_load(
    const char *workspace, const uint8_t root[32],
    struct vcs_zcode_work_receipt_v1 *out);

/* Independently repeat the verification against a store holding the
 * package: NOT_HELD when it does not reconstruct here, CONTRADICTED when it
 * reconstructs to any root other than the ones the receipt binds. */
enum vcs_zcode_work_pull_receipt_result vcs_zcode_work_pull_receipt_reverify(
    struct vcs_package_store *store,
    const struct vcs_zcode_work_receipt_v1 *receipt);

#endif /* ZCL_VCS_ZCODE_WORK_PULL_RECEIPT_H */
