/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Pure reflex decisions over caller-owned immutable values. */
// one-result-type-ok:pure-vtable-uses-bounded-caller-owned-output-only

#include "services/dev_reflex_policy_service.h"

#include "hotswap/hotswap_service.h"
#include "json/json.h"

#include <stdio.h>
#include <string.h>

/* One row per wire status. A table keeps the vocabulary one list a reader can
 * audit, rather than a chain that grows a branch per stage. */
static const struct {
    const char *status;
    const char *phase;
} k_progress_phases[] = {
    { "edit_seen", "EDIT_SEEN" },
    { "impact_ready", "IMPACT_READY" },
    { "compile_green", "COMPILE_GREEN" },
    { "reflex_ready", "COMPILE_GREEN" },
    { "compile_only", "COMPILE_GREEN" },
    { "compile_red", "COMPILE_RED" },
    { "story_green", "STORY_GREEN" },
    { "story_red", "STORY_RED" },
    { "focused_green", "FOCUSED_GREEN" },
    { "feedback_ready", "FOCUSED_GREEN" },
    /* A path-floor run of a wider selection: never FOCUSED_GREEN. */
    { "focused_partial", "FOCUSED_PARTIAL" },
    { "focused_red", "FOCUSED_RED" },
    { "proof_pending", "PROOF_PENDING" },
    { "fallback_ready", "PROOF_PENDING" },
    { "superseded", "SUPERSEDED" },
};

static const char *progress_phase(const char *status, const char *detail)
{
    if (!status) return detail ? detail : "";
    for (size_t i = 0;
         i < sizeof(k_progress_phases) / sizeof(k_progress_phases[0]); i++)
        if (strcmp(status, k_progress_phases[i].status) == 0)
            return k_progress_phases[i].phase;
    if (strcmp(status, "rejected") == 0)
        return detail && strcmp(detail, "affected_proofs") == 0
            ? "FOCUSED_RED" : "COMPILE_RED";
    return detail ? detail : status;
}

static bool action_changing(const char *status, const char *source_tu)
{
    if (!status) return false;
    if (strcmp(status, "edit_seen") == 0 ||
        strcmp(status, "impact_ready") == 0 ||
        strcmp(status, "superseded") == 0)
        return false;
    /* COMPILE_GREEN is progress, not a behavior verdict. Every service island
     * now emits an owner-bound story immediately after it. */
    if (strcmp(status, "reflex_ready") == 0)
        return false;
    if (strcmp(status, "compile_only") == 0)
        return true;
    (void)source_tu;
    return true;
}

static bool copy_value(const struct json_value *from,
                       struct json_value *to, const char *from_key,
                       const char *to_key)
{
    const struct json_value *value = json_get(from, from_key);
    return !value || json_push_kv(to, to_key, value);
}

static bool reflex_status(const char *status)
{
    static const char *const statuses[] = {
        "edit_seen", "impact_ready", "reflex_ready", "compile_only",
        "story_green", "story_red",
    };
    if (!status) return false;
    for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); i++)
        if (strcmp(status, statuses[i]) == 0) return true;
    return false;
}

static const char *cycle_lane(const struct json_value *cycle, bool live)
{
    const char *status = json_get_str(json_get(cycle, "status"));
    const char *action = json_get_str(json_get(cycle, "action"));
    if (live) return "LIVE";
    if (reflex_status(status)) return "REFLEX";
    if (status && strcmp(status, "fallback_ready") == 0) return "VERIFY";
    if (action && strcmp(action, "restart") == 0) return "FAST_RESTART";
    return "VERIFY";
}

static bool project_cycle_fields(const struct json_value *cycle,
                                  struct json_value *compact)
{
    static const struct {
        const char *from, *to;
        bool boolean;
    } fields[] = {
        { "status", "status", false },
        { "phase", "event", false },
        { "edit_epoch", "edit_epoch", false },
        { "action", "action", false },
        { "elapsed_us", "feedback_us", false },
        { "elapsed_ms", "feedback_ms", false },
        { "feedback_class", "feedback_class", false },
        { "candidate_object_root", "candidate_object_root", false },
        { "candidate_module_root", "candidate_module_root", false },
        { "loaded_mapping_root", "loaded_mapping_root", false },
        { "candidate_bytes_executed", "candidate_bytes_executed", false },
        { "story_id", "story_id", false },
        { "story_root", "story_root", false },
        { "story_fixture_root", "story_fixture_root", false },
        { "story_fixture_id", "story_fixture_id", false },
        { "story_adapter", "story_adapter", false },
        { "story_timeout_ms", "story_timeout_ms", false },
        { "forbidden_effect_mask", "forbidden_effect_mask", false },
        { "observation_root", "observation_root", false },
        { "exercised_owner_surface", "exercised_owner_surface", false },
        { "story_detail", "story_detail", false },
        { "impact_us", "impact_us", false },
        { "closure_us", "closure_us", false },
        { "runtime_published", "runtime_published", true },
        { "proof_complete", "proof_complete", true },
        { "proof_scope", "proof_scope", false },
        { "source_id_sha256", "source_identity_sha256", false },
        { "vcs_commit", "zvcs_commit_root", false },
        { "proof_receipt_root", "proof_receipt_root", false },
        { "publication_job_root", "publication_job_root", false },
        { "publication_enqueue_us", "publication_enqueue_us", false },
    };
    for (size_t i = 0; i < sizeof(fields) / sizeof(fields[0]); i++) {
        bool ok = fields[i].boolean
            ? json_push_kv_bool(compact, fields[i].to,
                json_get_bool(json_get(cycle, fields[i].from)))
            : copy_value(cycle, compact, fields[i].from, fields[i].to);
        if (!ok) return false;
    }
    return true;
}

static const char *unpublished_reason(const struct json_value *cycle)
{
    const char *why = json_get_str(json_get(cycle, "why_not_live"));
    if (!why || !why[0])
        why = json_get_str(json_get(cycle, "failure_capsule"));
    if (!why || !why[0]) why = json_get_str(json_get(cycle, "reason"));
    return why && why[0] ? why : "runtime publication was not proven";
}

static bool project_cycle(const struct json_value *cycle,
                          int64_t epoch, struct json_value *compact)
{
    if (!cycle || cycle->type != JSON_OBJ || !compact || epoch < 0)
        return false;
    json_init(compact);
    json_set_object(compact);
    const bool live = json_get_bool(json_get(cycle, "runtime_published"));
    bool ok = json_push_kv_str(compact, "schema", "zcl.dev_drive.v1") &&
        json_push_kv_int(compact, "epoch", epoch) &&
        json_push_kv_str(compact, "lane", cycle_lane(cycle, live)) &&
        project_cycle_fields(cycle, compact);
    if (!ok) {
        json_free(compact);
        return false;
    }
    if (!live) {
        if (!json_push_kv_str(compact, "why_not_live",
                             unpublished_reason(cycle))) {
            json_free(compact);
            return false;
        }
    }
    return true;
}

static bool lower_hex_64(const char *value)
{
    if (!value || strlen(value) != 64) return false;
    for (size_t i = 0; i < 64; i++)
        if (!((value[i] >= '0' && value[i] <= '9') ||
              (value[i] >= 'a' && value[i] <= 'f')))
            return false;
    return true;
}

static const char *handoff_input_failure(
    const struct dev_reflex_proof_handoff_v2 *input)
{
    if (!lower_hex_64(input->candidate_epoch) ||
        !lower_hex_64(input->source_epoch))
        return "candidate/source epoch must be exact lowercase SHA3 roots";
    if (!input->affected_component[0] || !input->action[0] ||
        input->affected_file_count == 0)
        return "affected component, action, and file count are required";
    if (!lower_hex_64(input->proof_inputs_sha3))
        return "proof inputs must be one immutable SHA3 root";
    return NULL;
}

static const char *handoff_behavior_failure(
    const struct dev_reflex_proof_handoff_v2 *input)
{
    if (strcmp(input->feedback_class, "HOT_EXECUTE") != 0 &&
             strcmp(input->feedback_class, "HOT_SHADOW_CORE") != 0 &&
             strcmp(input->feedback_class, "HOT_FORK") != 0)
        return "proof handoff requires an exact behavior feedback class";
    if (!lower_hex_64(input->candidate_object_root) ||
             !lower_hex_64(input->candidate_module_root) ||
             !lower_hex_64(input->story_root) ||
             !lower_hex_64(input->story_fixture_root) ||
             !lower_hex_64(input->observation_root))
        return "candidate, story, fixture, and observation roots are required";
    if (!input->compile_green)
        return "compile-green evidence is required before proof handoff";
    return NULL;
}

static const char *handoff_story_failure(
    const struct dev_reflex_proof_handoff_v2 *input)
{
    if (input->story_obtained &&
             !lower_hex_64(input->focused_evidence_sha3))
        return "obtained story/focused evidence requires an exact SHA3 root";
    if (!input->story_obtained && input->focused_evidence_sha3[0])
        return "absent story evidence cannot carry a synthetic root";
    return NULL;
}

static bool handoff_validate(const struct dev_reflex_proof_handoff_v2 *input,
                             char *why, size_t why_size)
{
    const char *failure = "handoff is absent";
    if (input) {
        failure = handoff_input_failure(input);
        if (!failure) failure = handoff_behavior_failure(input);
        if (!failure) failure = handoff_story_failure(input);
    }
    if (!failure) return true;
    if (why && why_size) (void)snprintf(why, why_size, "%s", failure);
    return false;
}

static const struct dev_reflex_policy_service_v1 k_builtin = {
    .progress_phase = progress_phase,
    .action_changing = action_changing,
    .project_cycle = project_cycle,
    .handoff_validate = handoff_validate,
};

ZCL_HOTSWAP_SERVICE_EXPORT(
    DEV_REFLEX_POLICY_SERVICE_ID, k_builtin,
    DEV_REFLEX_POLICY_ABI, DEV_REFLEX_POLICY_SCHEMA,
    DEV_REFLEX_POLICY_WIRE, DEV_REFLEX_POLICY_KAT)

const struct dev_reflex_policy_service_v1 *
dev_reflex_policy_service_builtin(void)
{
    return &k_builtin;
}
