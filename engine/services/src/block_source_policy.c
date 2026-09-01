/* Copyright 2026 Rhett Creighton - Apache License 2.0 */
// one-result-type-ok:pure-policy

#include "services/block_source_policy.h"

#include <stdio.h>
#include <string.h>

static void copy_text(char *dst, size_t dst_len, const char *src)
{
    if (!dst || dst_len == 0) return;
    if (!src) src = "";
    snprintf(dst, dst_len, "%s", src);
}

const char *bsp_source_name(enum bsp_source source)
{
    switch (source) {
        case BSP_SOURCE_NONE:              return "none";
        case BSP_SOURCE_P2P:               return "p2p";
        case BSP_SOURCE_SNAPSHOT:          return "snapshot";
        case BSP_SOURCE_LOCAL_IMPORT:      return "local_import";
        case BSP_SOURCE_ZCLASSICD_MIRROR:  return "zclassicd_mirror";
        case BSP_SOURCE_NUM:               break;
    }
    return "unknown";
}

const char *bsp_decision_result_name(enum bsp_decision_result result)
{
    switch (result) {
        case BSP_DECISION_WAIT:       return "wait";
        case BSP_DECISION_USE_SOURCE: return "use_source";
        case BSP_DECISION_BLOCKED:    return "blocked";
        case BSP_DECISION_RECOVER:    return "recover";
        case BSP_DECISION_NUM:        break;
    }
    return "unknown";
}

const char *bsp_source_trust_name(enum bsp_source source)
{
    switch (source) {
        case BSP_SOURCE_NONE:             return "none";
        case BSP_SOURCE_P2P:              return "native_peer_validated";
        case BSP_SOURCE_SNAPSHOT:         return "native_snapshot_proof_validated";
        case BSP_SOURCE_LOCAL_IMPORT:     return "local_consensus_import";
        case BSP_SOURCE_ZCLASSICD_MIRROR: return "bounded_advisory_fallback";
        case BSP_SOURCE_NUM:              break;
    }
    return "unknown";
}

static int source_base_score(enum bsp_source source)
{
    switch (source) {
        case BSP_SOURCE_P2P:              return 100;
        case BSP_SOURCE_SNAPSHOT:         return 85;
        case BSP_SOURCE_LOCAL_IMPORT:     return 75;
        case BSP_SOURCE_ZCLASSICD_MIRROR: return 45;
        default:                          return -1000;
    }
}

static bool mirror_fallback_allowed(const struct bsp_plan_input *in)
{
    if (!in) return false;
    if (in->local_retries_exhausted) return true;
    /* Concurrent-redundancy override: once mirror lag breaches the SLO
     * and zclassicd is reachable, the mirror MUST be allowed to pull
     * bodies regardless of local recovery state. The mirror is the
     * redundancy guarantee -- gating it behind "local fully exhausted"
     * makes it tertiary, not redundant. Bodies still validate through
     * local consensus; only the source is the mirror. */
    if (in->mirror_lag_sla_breach_blocks > 0) {
        const struct bsp_source_status *mir =
            &in->sources[BSP_SOURCE_ZCLASSICD_MIRROR];
        if (mir->available && mir->lag >= in->mirror_lag_sla_breach_blocks)
            return true;
    }
    return !in->local_recovery_active;
}

static int bounded_height_bonus(int local_height, int source_height)
{
    int gap = source_height - local_height;
    if (gap <= 0) return -20;
    if (gap > 10000) return 30;
    if (gap > 1000) return 20;
    return 10;
}

static int target_lag_penalty(const struct bsp_plan_input *in,
                              const struct bsp_source_status *s)
{
    if (!in || !s)
        return 0;
    if (in->target_height <= in->local_height)
        return 0;
    if (s->height <= in->local_height || s->height >= in->target_height)
        return 0;

    int lag = in->target_height - s->height;
    if (lag > 10000)
        return 70;
    if (lag > 1000)
        return 50;
    if (lag > 100)
        return 35;
    return 25;
}

static int failure_penalty(const struct bsp_source_status *s)
{
    if (!s)
        return 0;
    int64_t penalty = s->failures * 4 + s->timeouts * 6;
    if (penalty > 60)
        penalty = 60;
    return (int)penalty;
}

static int redundancy_bonus(const struct bsp_plan_input *in,
                            const struct bsp_source_status *s)
{
    if (!in || !s || s->source != BSP_SOURCE_ZCLASSICD_MIRROR)
        return 0;
    if (!mirror_fallback_allowed(in))
        return 0;
    if (in->mirror_lag_sla_breach_blocks <= 0)
        return 0;
    if (s->lag < in->mirror_lag_sla_breach_blocks)
        return 0;
    if (in->target_height <= in->local_height)
        return 0;
    if (s->height < in->target_height)
        return 0;

    return 30;
}

static void score_source(const struct bsp_plan_input *in,
                         struct bsp_source_status *s)
{
    if (!in || !s || s->source <= BSP_SOURCE_NONE ||
        s->source >= BSP_SOURCE_NUM || !s->available) {
        if (s)
            s->score = -1000;
        return;
    }
    if (s->blocked) {
        s->score = -900;
        return;
    }

    s->score_base = source_base_score(s->source);
    s->score_health = s->healthy ? 20 : -35;
    s->score_height = bounded_height_bonus(in->local_height, s->height);
    s->score_authorized = s->authorized ? 5 : 0;
    s->score_redundancy_bonus = redundancy_bonus(in, s);
    s->score_target_lag_penalty = target_lag_penalty(in, s);
    s->score_failure_penalty = failure_penalty(s);
    s->score_mirror_gate_penalty =
        s->source == BSP_SOURCE_ZCLASSICD_MIRROR &&
        !mirror_fallback_allowed(in) ? 100 : 0;

    s->score = s->score_base +
               s->score_health +
               s->score_height +
               s->score_authorized +
               s->score_redundancy_bonus -
               s->score_target_lag_penalty -
               s->score_failure_penalty -
               s->score_mirror_gate_penalty;
}

static const char *source_selection_blocker(const struct bsp_plan_input *in,
                                            const struct bsp_source_status *s)
{
    if (!in || !s) return "invalid_source";
    if (!s->available) return "unavailable";
    if (!s->healthy) return "unhealthy";
    if (s->blocked) return s->blocker[0] ? s->blocker : "blocked";
    if (s->height < 0) return "unknown_height";
    if (s->source == BSP_SOURCE_ZCLASSICD_MIRROR &&
        !mirror_fallback_allowed(in))
        return "local_recovery_gate";
    if (s->source == BSP_SOURCE_P2P &&
        in->best_header_height >= in->local_height &&
        s->height >= in->best_header_height)
        return "";
    if (in->target_height > in->local_height && s->height <= in->local_height)
        return "no_forward_progress";
    return "";
}

void block_source_policy_plan(const struct bsp_plan_input *in,
                              struct bsp_decision *out)
{
    if (!out) return;
    memset(out, 0, sizeof(*out));
    out->result = BSP_DECISION_RECOVER;
    out->selected_source = BSP_SOURCE_NONE;
    out->selected_score = -1000;
    copy_text(out->reason, sizeof(out->reason), "no_healthy_source");
    if (!in) {
        copy_text(out->blocker, sizeof(out->blocker), "null_input");
        return;
    }

    out->mirror_fallback_allowed = mirror_fallback_allowed(in);
    out->activation_allowed = false;
    out->local_height = in->local_height;
    out->best_header_height = in->best_header_height;
    out->target_height = in->target_height;
    out->projection_height = in->projection_height;
    out->projection_lag = in->projection_lag;
    out->projection_deferred = in->projection_deferred;
    copy_text(out->projection_state, sizeof(out->projection_state),
              in->projection_state);

    bool any_blocker = false;
    const char *first_blocker = NULL;

    for (int i = 0; i < BSP_SOURCE_NUM; i++) {
        out->sources[i] = in->sources[i];
        out->sources[i].source = (enum bsp_source)i;
        score_source(in, &out->sources[i]);
        const char *selection_blocker =
            source_selection_blocker(in, &out->sources[i]);
        out->sources[i].selectable =
            selection_blocker && selection_blocker[0] == '\0';
        copy_text(out->sources[i].selection_reason,
                  sizeof(out->sources[i].selection_reason),
                  selection_blocker ? selection_blocker : "invalid_source");
        if (out->sources[i].blocked && out->sources[i].blocker[0]) {
            any_blocker = true;
            if (!first_blocker) first_blocker = out->sources[i].blocker;
        }
        if (!out->sources[i].selectable)
            continue;
        if (out->sources[i].score > out->selected_score) {
            out->selected_source = out->sources[i].source;
            out->selected_score = out->sources[i].score;
        }
    }

    if (out->selected_source != BSP_SOURCE_NONE) {
        out->result = BSP_DECISION_USE_SOURCE;
        out->activation_allowed = true;
        snprintf(out->reason, sizeof(out->reason),
                 "selected_%s", bsp_source_name(out->selected_source));
        return;
    }

    if (in->local_recovery_active && !in->local_retries_exhausted) {
        out->result = BSP_DECISION_WAIT;
        copy_text(out->reason, sizeof(out->reason), "local_retries_pending");
        copy_text(out->blocker, sizeof(out->blocker), "local_recovery_gate");
        return;
    }

    if (any_blocker) {
        out->result = BSP_DECISION_BLOCKED;
        copy_text(out->reason, sizeof(out->reason), "source_blocked");
        copy_text(out->blocker, sizeof(out->blocker), first_blocker);
        return;
    }

    out->result = BSP_DECISION_RECOVER;
    copy_text(out->reason, sizeof(out->reason), "no_healthy_source");
}
