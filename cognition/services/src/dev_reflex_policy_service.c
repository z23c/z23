/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Pure reflex decisions over caller-owned immutable values. */
// one-result-type-ok:pure-vtable-uses-bounded-caller-owned-output-only

#include "services/dev_reflex_policy_service.h"

#include "hotswap/hotswap_service.h"
#include "json/json.h"

#include <stdio.h>
#include <string.h>

static const char *progress_phase(const char *status, const char *detail)
{
    if (!status) return detail ? detail : "";
    if (strcmp(status, "edit_seen") == 0) return "EDIT_SEEN";
    if (strcmp(status, "impact_ready") == 0) return "IMPACT_READY";
    if (strcmp(status, "compile_green") == 0 ||
        strcmp(status, "reflex_ready") == 0 ||
        strcmp(status, "compile_only") == 0) return "COMPILE_GREEN";
    if (strcmp(status, "compile_red") == 0) return "COMPILE_RED";
    if (strcmp(status, "story_green") == 0) return "STORY_GREEN";
    if (strcmp(status, "story_red") == 0) return "STORY_RED";
    if (strcmp(status, "focused_green") == 0 ||
        strcmp(status, "feedback_ready") == 0) return "FOCUSED_GREEN";
    if (strcmp(status, "focused_red") == 0) return "FOCUSED_RED";
    if (strcmp(status, "proof_pending") == 0 ||
        strcmp(status, "fallback_ready") == 0) return "PROOF_PENDING";
    if (strcmp(status, "superseded") == 0) return "SUPERSEDED";
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

static bool project_cycle(const struct json_value *cycle,
                          int64_t epoch, struct json_value *compact)
{
    if (!cycle || cycle->type != JSON_OBJ || !compact || epoch < 0)
        return false;
    json_init(compact);
    json_set_object(compact);
    const bool live = json_get_bool(json_get(cycle, "runtime_published"));
    const char *action = json_get_str(json_get(cycle, "action"));
    const char *status = json_get_str(json_get(cycle, "status"));
    const bool reflex = status &&
        (strcmp(status, "edit_seen") == 0 ||
         strcmp(status, "impact_ready") == 0 ||
         strcmp(status, "reflex_ready") == 0 ||
         strcmp(status, "compile_only") == 0 ||
         strcmp(status, "story_green") == 0 ||
         strcmp(status, "story_red") == 0);
    bool ok = json_push_kv_str(compact, "schema", "zcl.dev_drive.v1") &&
        json_push_kv_int(compact, "epoch", epoch) &&
        json_push_kv_str(compact, "lane", live ? "LIVE" :
            reflex ? "REFLEX" :
            status && strcmp(status, "fallback_ready") == 0 ? "VERIFY" :
            action && strcmp(action, "restart") == 0 ? "FAST_RESTART" :
            "VERIFY") &&
        copy_value(cycle, compact, "status", "status") &&
        copy_value(cycle, compact, "phase", "event") &&
        copy_value(cycle, compact, "edit_epoch", "edit_epoch") &&
        copy_value(cycle, compact, "action", "action") &&
        copy_value(cycle, compact, "elapsed_us", "feedback_us") &&
        copy_value(cycle, compact, "elapsed_ms", "feedback_ms") &&
        copy_value(cycle, compact, "feedback_class", "feedback_class") &&
        copy_value(cycle, compact, "candidate_object_root",
                   "candidate_object_root") &&
        copy_value(cycle, compact, "candidate_module_root",
                   "candidate_module_root") &&
        copy_value(cycle, compact, "loaded_mapping_root",
                   "loaded_mapping_root") &&
        copy_value(cycle, compact, "candidate_bytes_executed",
                   "candidate_bytes_executed") &&
        copy_value(cycle, compact, "story_id", "story_id") &&
        copy_value(cycle, compact, "story_root", "story_root") &&
        copy_value(cycle, compact, "story_fixture_root",
                   "story_fixture_root") &&
        copy_value(cycle, compact, "story_fixture_id", "story_fixture_id") &&
        copy_value(cycle, compact, "story_adapter", "story_adapter") &&
        copy_value(cycle, compact, "story_timeout_ms", "story_timeout_ms") &&
        copy_value(cycle, compact, "forbidden_effect_mask",
                   "forbidden_effect_mask") &&
        copy_value(cycle, compact, "observation_root", "observation_root") &&
        copy_value(cycle, compact, "exercised_owner_surface",
                   "exercised_owner_surface") &&
        copy_value(cycle, compact, "story_detail", "story_detail") &&
        copy_value(cycle, compact, "impact_us", "impact_us") &&
        copy_value(cycle, compact, "closure_us", "closure_us") &&
        json_push_kv_bool(compact, "runtime_published", live) &&
        json_push_kv_bool(compact, "proof_complete",
            json_get_bool(json_get(cycle, "proof_complete"))) &&
        copy_value(cycle, compact, "proof_scope", "proof_scope") &&
        copy_value(cycle, compact, "source_id_sha256",
                   "source_identity_sha256") &&
        copy_value(cycle, compact, "vcs_commit", "zvcs_commit_root") &&
        copy_value(cycle, compact, "proof_receipt_root",
                   "proof_receipt_root") &&
        copy_value(cycle, compact, "publication_job_root",
                   "publication_job_root") &&
        copy_value(cycle, compact, "publication_enqueue_us",
                   "publication_enqueue_us");
    if (!ok) {
        json_free(compact);
        return false;
    }
    if (!live) {
        const char *why = json_get_str(json_get(cycle, "why_not_live"));
        if (!why || !why[0])
            why = json_get_str(json_get(cycle, "failure_capsule"));
        if (!why || !why[0]) why = json_get_str(json_get(cycle, "reason"));
        if (!json_push_kv_str(compact, "why_not_live",
            why && why[0] ? why : "runtime publication was not proven")) {
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

static bool handoff_validate(const struct dev_reflex_proof_handoff_v2 *input,
                             char *why, size_t why_size)
{
    const char *failure = NULL;
    if (!input) failure = "handoff is absent";
    else if (!lower_hex_64(input->candidate_epoch) ||
             !lower_hex_64(input->source_epoch))
        failure = "candidate/source epoch must be exact lowercase SHA3 roots";
    else if (!input->affected_component[0] || !input->action[0] ||
             input->affected_file_count == 0)
        failure = "affected component, action, and file count are required";
    else if (!lower_hex_64(input->proof_inputs_sha3))
        failure = "proof inputs must be one immutable SHA3 root";
    else if (strcmp(input->feedback_class, "HOT_EXECUTE") != 0 &&
             strcmp(input->feedback_class, "HOT_SHADOW_CORE") != 0 &&
             strcmp(input->feedback_class, "HOT_FORK") != 0)
        failure = "proof handoff requires an exact behavior feedback class";
    else if (!lower_hex_64(input->candidate_object_root) ||
             !lower_hex_64(input->candidate_module_root) ||
             !lower_hex_64(input->story_root) ||
             !lower_hex_64(input->story_fixture_root) ||
             !lower_hex_64(input->observation_root))
        failure = "candidate, story, fixture, and observation roots are required";
    else if (!input->compile_green)
        failure = "compile-green evidence is required before proof handoff";
    else if (input->story_obtained &&
             !lower_hex_64(input->focused_evidence_sha3))
        failure = "obtained story/focused evidence requires an exact SHA3 root";
    else if (!input->story_obtained && input->focused_evidence_sha3[0])
        failure = "absent story evidence cannot carry a synthetic root";
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
