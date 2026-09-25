/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Per-change admission of build actions and proof obligations over
 *          the proof reuse decision, with the one-line change report. */

#include "vcs/proof_admission.h"

#include "base/hex.h"
#include "base/log_macros.h"

#include <stdio.h>
#include <string.h>

#define PAD_LOG "vcs.proof_admission"
#define PAD_CLASS_CAP 64u

struct pad_flags {
    bool conflict;
    bool policy;
};

static bool pad_is_policy(const char *why)
{
    return why && (strcmp(why, VCS_PROOF_REUSE_WHY_POLICY) == 0 ||
                   strcmp(why, VCS_PROOF_REUSE_WHY_POLICY_ROOT) == 0);
}

static void pad_decide(const struct vcs_proof_admission_context *ctx,
                       const struct vcs_proof_obligation *o,
                       struct vcs_proof_admission_result *res,
                       struct pad_flags *flags)
{
    struct vcs_proof_ticket_class classes[PAD_CLASS_CAP];
    struct vcs_proof_reuse_request req = {
        .local = o->preimage,
        .action_class = o->action_class,
        .domain = ctx->domain,
        .policy = ctx->policy,
        .artifacts = ctx->artifacts,
    };
    if (!vcs_proof_reuse_decide(ctx->receiver, &req, classes, PAD_CLASS_CAP,
                                &res->decision))
        LOG_WARN(PAD_LOG, "obligation %s refused: %s",
                 o->name ? o->name : "(unnamed)", res->decision.reason);
    const struct vcs_proof_reuse_decision *d = &res->decision;
    bool reused = d->outcome == VCS_PROOF_REUSE_HIT_PASS ||
                  d->outcome == VCS_PROOF_REUSE_HIT_FAIL;
    res->status = reused ? VCS_PROOF_ADMIT_REUSED : VCS_PROOF_ADMIT_FRESH;
    res->reason = d->reason;
    if (d->outcome == VCS_PROOF_REUSE_REFUSE &&
        d->reason && strcmp(d->reason, VCS_PROOF_OBSERVATION_CONFLICT) == 0)
        flags->conflict = true;
    if (pad_is_policy(d->reason)) flags->policy = true;
}

static void pad_count(const struct vcs_proof_obligation *o,
                      const struct vcs_proof_admission_result *res,
                      struct vcs_proof_admission_report *rep)
{
    bool fresh = res->status == VCS_PROOF_ADMIT_FRESH;
    if (o->action_class == VCS_PROOF_ACTION_BUILD) {
        rep->build_total++;
        rep->build_invalidated += fresh ? 1u : 0u;
    } else {
        rep->proof_total++;
        rep->proof_invalidated += fresh ? 1u : 0u;
    }
    if (fresh) rep->proofs_fresh++;
    else rep->proofs_reused++;
    if (fresh && o->integration_edge) rep->integration_edges_rerun++;
    if (res->decision.false_hit_refused) rep->false_hit_refusals++;
}

static const char *pad_fallback(const struct vcs_proof_change *change,
                                const struct pad_flags *flags)
{
    if (!change->scope_known) return VCS_PROOF_FALLBACK_UNKNOWN_SCOPE;
    if (flags->conflict) return VCS_PROOF_FALLBACK_CONFLICT;
    if (flags->policy) return VCS_PROOF_FALLBACK_POLICY;
    if (memcmp(change->contract_root_before, change->contract_root_after,
               VCS_PROOF_ROOT_BYTES) != 0)
        return VCS_PROOF_FALLBACK_DEPENDENCY;
    return VCS_PROOF_FALLBACK_NONE;
}

static bool pad_valid(const struct vcs_proof_admission_context *ctx,
                      const struct vcs_proof_change *change,
                      const struct vcs_proof_obligation *obligations,
                      size_t count,
                      const struct vcs_proof_admission_result *results)
{
    if (!ctx || !ctx->receiver || !change || !change->component_id ||
        (count && (!obligations || !results)))
        return false;
    for (size_t i = 0; i < count; i++)
        if (!obligations[i].preimage || !obligations[i].component_id)
            return false;
    return true;
}

bool vcs_proof_admission_run(const struct vcs_proof_admission_context *ctx,
                             const struct vcs_proof_change *change,
                             const struct vcs_proof_obligation *obligations,
                             size_t count,
                             struct vcs_proof_admission_result *results,
                             struct vcs_proof_admission_report *report)
{
    if (!report) LOG_RETURN(false, PAD_LOG, "admission: no report buffer");
    memset(report, 0, sizeof(*report));
    report->fallback_reason = VCS_PROOF_FALLBACK_POLICY;
    if (!pad_valid(ctx, change, obligations, count, results))
        LOG_RETURN(false, PAD_LOG, "admission: arguments invalid (%zu)", count);
    struct pad_flags flags = {0};
    for (size_t i = 0; i < count; i++) {
        struct vcs_proof_admission_result *res = &results[i];
        memset(res, 0, sizeof(*res));
        if (!change->scope_known && obligations[i].in_reach) {
            res->status = VCS_PROOF_ADMIT_FRESH;
            res->reason = VCS_PROOF_ADMIT_WHY_UNKNOWN_SCOPE;
        } else {
            pad_decide(ctx, &obligations[i], res, &flags);
        }
        pad_count(&obligations[i], res, report);
    }
    report->fallback_reason = pad_fallback(change, &flags);
    return true;
}

bool vcs_proof_admission_report_line(
    const struct vcs_proof_change *change,
    const struct vcs_proof_admission_report *report, char *buf, size_t cap)
{
    if (!change || !report || !buf || cap == 0 || !change->component_id)
        LOG_RETURN(false, PAD_LOG, "report line: null argument");
    char before[65], after[65];
    zcl_hex_encode(change->contract_root_before, 32, before);
    zcl_hex_encode(change->contract_root_after, 32, after);
    int n = snprintf(buf, cap,
                     "component=%s contract_root_before=%s "
                     "contract_root_after=%s build_actions_invalidated=%u/%u "
                     "proof_obligations_invalidated=%u/%u proofs_reused=%u "
                     "proofs_fresh=%u integration_edges_rerun=%u "
                     "fallback_reason=%s",
                     change->component_id, before, after,
                     report->build_invalidated, report->build_total,
                     report->proof_invalidated, report->proof_total,
                     report->proofs_reused, report->proofs_fresh,
                     report->integration_edges_rerun,
                     report->fallback_reason ? report->fallback_reason :
                                               VCS_PROOF_FALLBACK_POLICY);
    if (n < 0 || (size_t)n >= cap) {
        buf[0] = 0;
        LOG_RETURN(false, PAD_LOG, "report line: %zu bytes too small", cap);
    }
    return true;
}
