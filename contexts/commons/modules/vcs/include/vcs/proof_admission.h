/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Per-change admission over a list of build actions and proof
 *          obligations: reuse every one that is safely reusable, run the
 *          rest fresh, and report why in one parseable line.
 *
 * The frontier (which obligations a change touches) is computed by the
 * caller, for example tools/dev from its build plan and test catalog. This
 * entry point takes the filled key preimages and never widens trust: each
 * obligation is decided by vcs_proof_reuse_decide() under the same
 * candidate domain, current policy and artifact verification.
 *
 * Contract boundary: a caller's integration_edges field binds the callee's
 * contract_root, not its implementation bytes, so a private implementation
 * edit leaves caller compile and proof keys unchanged and reusable. An
 * obligation that EXECUTES callee bytes (a linked test group) binds the
 * callee implementation in dependency_closure and reruns.
 */

#ifndef ZCL_VCS_PROOF_ADMISSION_H
#define ZCL_VCS_PROOF_ADMISSION_H

#include "vcs/proof_reuse.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* The change being admitted. */
struct vcs_proof_change {
    const char *component_id;
    uint8_t contract_root_before[VCS_PROOF_ROOT_BYTES];
    uint8_t contract_root_after[VCS_PROOF_ROOT_BYTES];
    /* false: the frontier is unknown, so every obligation marked in_reach
     * runs fresh without consulting any ticket. */
    bool scope_known;
};

struct vcs_proof_obligation {
    const char *name;               /* unit or group, for reporting */
    const char *component_id;       /* owner of the obligation */
    enum vcs_proof_action_class action_class; /* BUILD or CHECK (proof) */
    const struct vcs_component_proof_key_v1 *preimage;
    bool integration_edge;          /* caller obligation over the change */
    bool in_reach;                  /* reachable from the changed component */
};

enum vcs_proof_admission_status {
    VCS_PROOF_ADMIT_REUSED = 0,
    VCS_PROOF_ADMIT_FRESH,
};

#define VCS_PROOF_ADMIT_WHY_UNKNOWN_SCOPE "unknown_scope"

struct vcs_proof_admission_result {
    enum vcs_proof_admission_status status;
    const char *reason;            /* decision reason or unknown_scope */
    struct vcs_proof_reuse_decision decision;
};

/* fallback_reason values, in precedence order. */
#define VCS_PROOF_FALLBACK_UNKNOWN_SCOPE "unknown-scope"
#define VCS_PROOF_FALLBACK_CONFLICT "conflict"
#define VCS_PROOF_FALLBACK_POLICY "policy"
#define VCS_PROOF_FALLBACK_DEPENDENCY "dependency-change"
#define VCS_PROOF_FALLBACK_NONE "none"

struct vcs_proof_admission_report {
    uint32_t build_total;
    uint32_t build_invalidated;
    uint32_t proof_total;
    uint32_t proof_invalidated;
    uint32_t proofs_reused;          /* all obligations reused */
    uint32_t proofs_fresh;           /* all obligations run fresh */
    uint32_t integration_edges_rerun;
    uint32_t false_hit_refusals;     /* artifact bytes did not match */
    const char *fallback_reason;
};

struct vcs_proof_admission_context {
    const struct vcs_proof_receiver *receiver;
    const struct vcs_proof_candidate_domain *domain;
    const struct vcs_proof_reuse_policy *policy;
    const struct vcs_proof_artifact_source *artifacts;
};

/* Decide every obligation. `results` must hold `count`. Returns false only
 * for caller errors (logged); a refused or conflicting obligation is a
 * FRESH result with its reason and a fallback in the report. */
bool vcs_proof_admission_run(const struct vcs_proof_admission_context *ctx,
                             const struct vcs_proof_change *change,
                             const struct vcs_proof_obligation *obligations,
                             size_t count,
                             struct vcs_proof_admission_result *results,
                             struct vcs_proof_admission_report *report);

/* One line, exactly these fields:
 *   component=<id> contract_root_before=<hex> contract_root_after=<hex>
 *   build_actions_invalidated=<n>/<total>
 *   proof_obligations_invalidated=<n>/<total> proofs_reused=<n>
 *   proofs_fresh=<n> integration_edges_rerun=<n>
 *   fallback_reason=<none|unknown-scope|policy|conflict|dependency-change>
 * Returns false when `cap` is too small (nothing partial is claimed). */
bool vcs_proof_admission_report_line(
    const struct vcs_proof_change *change,
    const struct vcs_proof_admission_report *report, char *buf, size_t cap);

#endif /* ZCL_VCS_PROOF_ADMISSION_H */
