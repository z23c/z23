/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: native projection of the canonical local reflex/build verdict. */

#include "command/native_command.h"

#include "base/hex.h"
#include "json/json.h"
#include "presentation/model.h"
#include "services/package_lifecycle.h"
#include "util/log_macros.h"

#include <stdio.h>
#include <string.h>

#define NPD_LEAF "app.presentation.development"

static const char *npd_str(const struct json_value *object, const char *key)
{
    const struct json_value *value = object ? json_get(object, key) : NULL;
    return value && value->type == JSON_STR ? json_get_str(value) : NULL;
}

static bool npd_bool(const struct json_value *object, const char *key)
{
    const struct json_value *value = object ? json_get(object, key) : NULL;
    return value && value->type == JSON_BOOL && json_get_bool(value);
}

static bool npd_int(const struct json_value *object, const char *key,
                    int64_t *out)
{
    const struct json_value *value = object ? json_get(object, key) : NULL;
    if (!value || value->type != JSON_INT || !out) return false;
    *out = json_get_int(value);
    return *out >= 0;
}

static bool npd_root(const char *root)
{
    uint8_t decoded[32];
    return root && zcl_hex_decode_lower(root, decoded, sizeof(decoded));
}

static bool npd_package_facts(const char *receipt_hex,
                              struct json_value *facts,
                              char *why, size_t why_cap)
{
    uint8_t receipt_id[32];
    if (!zcl_native_require_hex64("receipt_id", receipt_hex, receipt_id, why,
                                  why_cap)) {
        return false;
    }
    struct vcs_package_build_receipt receipt;
    struct zcl_result read = package_lifecycle_receipt_read(
        zcl_native_command_datadir(), receipt_id, &receipt);
    if (!read.ok) {
        (void)snprintf(why, why_cap,
                       "canonical package receipt unavailable: %s",
                       read.message);
        return false;
    }
    char package_root[65];
    zcl_hex_encode(receipt.package_root, 32, package_root);
    const char *result = vcs_package_build_result_string(
        (enum vcs_package_build_result)receipt.result_class);
    const char *phase = receipt.result_class == VCS_PACKAGE_BUILD_RESULT_BUILD_FAIL
        ? "COMPILE_RED" : receipt.result_class == VCS_PACKAGE_BUILD_RESULT_TEST_FAIL
        ? "STORY_RED" : receipt.result_class == VCS_PACKAGE_BUILD_RESULT_TEST_PASS
        ? "STORY_GREEN" : "COMPILE_GREEN";
    bool passed = receipt.result_class == VCS_PACKAGE_BUILD_RESULT_BUILD_PASS ||
        receipt.result_class == VCS_PACKAGE_BUILD_RESULT_TEST_PASS;
    char toolchain[257];
    (void)snprintf(toolchain, sizeof(toolchain), "%s %s; %s",
                   receipt.compiler_id, receipt.compiler_version, result);
    json_set_object(facts);
    bool ok = json_push_kv_str(facts, "schema", "zcl.dev_cycle.v1") &&
        json_push_kv_str(facts, "status", passed ? "passed" : "rejected") &&
        json_push_kv_str(facts, "phase", phase) &&
        json_push_kv_str(facts, "edit_epoch", package_root) &&
        json_push_kv_str(facts, "candidate_object_root", package_root) &&
        json_push_kv_str(facts, "affected_component", "installed C23 package") &&
        json_push_kv_str(facts, "feedback_class",
            receipt.test_ran ? "ISOLATED_PACKAGE_TEST" :
                               "COMPILE_ONLY_PACKAGE_RECEIPT") &&
        json_push_kv_str(facts, "receipt_id", receipt_hex) &&
        json_push_kv_str(facts, "toolchain", toolchain) &&
        json_push_kv_str(facts, "result_class", result) &&
        json_push_kv_bool(facts, "candidate_bytes_executed", receipt.test_ran) &&
        json_push_kv_bool(facts, "proof_complete",
                          passed && receipt.test_ran) &&
        json_push_kv_str(facts, "agent_next_action",
            passed && receipt.test_ran
                ? "request independent reproduction for this exact candidate"
                : passed ? "add a sensitive candidate behavior story"
                         : "inspect the named package build or test mismatch");
    if (!passed)
        ok = ok && json_push_kv_str(facts, "failure_capsule", result);
    if (!ok) {
        (void)snprintf(why, why_cap,
                       "canonical package receipt could not be projected");
        return false;
    }
    return true;
}

static void npd_item(struct zcl_present_model_v1 *model, uint16_t kind,
                     uint16_t status, const char *id, const char *label,
                     const char *value)
{
    struct zcl_present_model_item_v1 *item =
        &model->items[model->item_count++];
    item->kind = kind;
    item->status = status;
    item->parent_index = ZCL_PRESENT_MODEL_PARENT_NONE;
    (void)snprintf(item->id, sizeof(item->id), "%s", id);
    (void)snprintf(item->label, sizeof(item->label), "%s", label);
    (void)snprintf(item->value, sizeof(item->value), "%s", value);
}

static int npd_phase(const char *status, const char *phase, bool *red)
{
    *red = false;
    if (!status || !phase) return -1;
    if (strcmp(phase, "EDIT_SEEN") == 0) return 1;
    if (strcmp(phase, "IMPACT_READY") == 0) return 2;
    if (strcmp(phase, "COMPILE_GREEN") == 0) return 3;
    if (strcmp(phase, "COMPILE_RED") == 0) { *red = true; return 3; }
    if (strcmp(phase, "STORY_GREEN") == 0) return 4;
    if (strcmp(phase, "STORY_RED") == 0) { *red = true; return 4; }
    if (strcmp(phase, "FOCUSED_GREEN") == 0) return 5;
    if (strcmp(phase, "FOCUSED_RED") == 0) { *red = true; return 5; }
    if (strcmp(phase, "PROOF_PENDING") == 0) return 5;
    if (strcmp(phase, "SUPERSEDED") == 0) { *red = true; return 0; }
    if (strcmp(status, "passed") == 0) return 5;
    if (strcmp(status, "rejected") == 0 || strcmp(status, "blocked") == 0) {
        *red = true;
        return 5;
    }
    return -1;
}

static void npd_stage(struct zcl_present_model_v1 *model, int number,
                      int current, bool observed, bool red, bool complete)
{
    static const char *const ids[] = {
        "", "edit", "impact", "compile", "behavior", "clean-proof"
    };
    static const char *const labels[] = {
        "", "LOCAL OBSERVATION - Edit captured",
        "LOCAL OBSERVATION - Impact closure",
        "LOCAL OBSERVATION - Candidate compile",
        "LOCAL OBSERVATION - Candidate behavior",
        "LOCAL OBSERVATION - Clean focused proof",
    };
    uint16_t status = number == current && red ? ZCL_PRESENT_STATUS_RED :
        observed ? ZCL_PRESENT_STATUS_GREEN :
        number == current ? ZCL_PRESENT_STATUS_INFO :
                            ZCL_PRESENT_STATUS_NEUTRAL;
    const char *value = number == current && red
        ? "named mismatch - candidate not selected"
        : complete ? "verified"
        : observed ? "observed"
        : number == current ? "waiting - no result in this event"
        : "not evidenced by this event";
    npd_item(model, ZCL_PRESENT_ITEM_PROGRESS, status,
             ids[number], labels[number], value);
    struct zcl_present_model_item_v1 *item =
        &model->items[model->item_count - 1u];
    item->numerator = observed ? 1u : 0u;
    item->denominator = 1u;
}

bool zcl_native_presentation_development_model_from_facts(
    const struct json_value *facts, struct zcl_present_model_v1 *model,
    char *why, size_t why_cap)
{
    const char *schema = npd_str(facts, "schema");
    const char *status = npd_str(facts, "status");
    const char *phase = npd_str(facts, "phase");
    const char *epoch = npd_str(facts, "edit_epoch");
    const char *source = npd_str(facts, "source_id_sha256");
    const char *candidate = npd_str(facts, "candidate_object_root");
    const char *component = npd_str(facts, "affected_component");
    const char *feedback = npd_str(facts, "feedback_class");
    const char *capsule = npd_str(facts, "failure_capsule");
    const char *next = npd_str(facts, "agent_next_action");
    const char *receipt = npd_str(facts, "receipt_id");
    const char *toolchain = npd_str(facts, "toolchain");
    const char *root = npd_root(epoch) ? epoch :
                       npd_root(source) ? source : candidate;
    bool red = false;
    int current = npd_phase(status, phase, &red);
    if (!facts || facts->type != JSON_OBJ || !schema ||
        strcmp(schema, "zcl.dev_cycle.v1") != 0 || !status ||
        strcmp(status, "unavailable") == 0 || current < 0 || !npd_root(root)) {
        (void)snprintf(why, why_cap,
                       "canonical exact development verdict is unavailable");
        return false;
    }
    bool proof_complete = npd_bool(facts, "proof_complete");
    zcl_present_model_init_v1(model, ZCL_PRESENT_MODEL_PROGRESS);
    (void)snprintf(model->request_id, sizeof(model->request_id),
                   "develop-%.12s", root);
    (void)snprintf(model->title, sizeof(model->title),
                   "Exact development consequence");
    (void)snprintf(model->summary, sizeof(model->summary),
                   "Canonical local event %s: %s%s", phase, status,
                   red ? " - named mismatch" : "");
    (void)snprintf(model->exact_root, sizeof(model->exact_root), "%s", root);
    bool candidate_executed = npd_bool(facts, "candidate_bytes_executed");
    bool stage_observed[] = {
        false,
        npd_root(root),
        (component && component[0]) || current == 2,
        current == 3 || current == 4 ||
            npd_root(candidate),
        current == 4 || (candidate_executed && feedback && feedback[0]),
        proof_complete || (current == 5 &&
            (strcmp(phase, "FOCUSED_GREEN") == 0 ||
             strcmp(phase, "FOCUSED_RED") == 0)),
    };
    for (int number = 1; number <= 5; number++)
        npd_stage(model, number, current, stage_observed[number],
                  red && number == current,
                  proof_complete && number == 5);

    char value[257];
    int64_t files = 0, elapsed = 0, compiler = 0, linker = 0;
    bool files_known = npd_int(facts, "changed_path_count", &files) ||
        npd_int(facts, "file_count", &files);
    bool elapsed_known = npd_int(facts, "elapsed_us", &elapsed);
    bool compiler_known = npd_int(facts, "compiler_processes", &compiler);
    bool linker_known = npd_int(facts, "linker_processes", &linker);
    if (files_known)
        (void)snprintf(value, sizeof(value), "%lld file(s); %s",
                       (long long)files,
                       component && component[0] ? component : "owner unknown");
    else
        (void)snprintf(value, sizeof(value), "file count unknown; %s",
                       component && component[0] ? component : "owner unknown");
    npd_item(model, ZCL_PRESENT_ITEM_KEY_VALUE,
             files_known && component && component[0]
                 ? ZCL_PRESENT_STATUS_INFO : ZCL_PRESENT_STATUS_YELLOW,
             "closure", "LOCAL OBSERVATION - Affected closure", value);
    npd_item(model, ZCL_PRESENT_ITEM_KEY_VALUE,
             npd_root(candidate) ? ZCL_PRESENT_STATUS_GREEN :
                                   ZCL_PRESENT_STATUS_YELLOW,
             "candidate", "LOCAL OBSERVATION - Candidate object",
             npd_root(candidate) ? candidate : "not emitted by this stage");
    char elapsed_text[32] = "unknown";
    char compiler_text[32] = "unknown";
    char linker_text[32] = "unknown";
    if (elapsed_known)
        (void)snprintf(elapsed_text, sizeof(elapsed_text), "%lld",
                       (long long)elapsed);
    if (compiler_known)
        (void)snprintf(compiler_text, sizeof(compiler_text), "%lld",
                       (long long)compiler);
    if (linker_known)
        (void)snprintf(linker_text, sizeof(linker_text), "%lld",
                       (long long)linker);
    (void)snprintf(value, sizeof(value), "%s us; compiler %s; linker %s",
                   elapsed_text, compiler_text, linker_text);
    npd_item(model, ZCL_PRESENT_ITEM_KEY_VALUE,
             elapsed_known && compiler_known && linker_known
                 ? ZCL_PRESENT_STATUS_INFO : ZCL_PRESENT_STATUS_YELLOW,
             "resources", "LOCAL OBSERVATION - Time and processes", value);
    if (receipt && receipt[0])
        npd_item(model, ZCL_PRESENT_ITEM_KEY_VALUE, ZCL_PRESENT_STATUS_GREEN,
                 "receipt", "LOCAL OBSERVATION - Build receipt", receipt);
    if (toolchain && toolchain[0])
        npd_item(model, ZCL_PRESENT_ITEM_KEY_VALUE, ZCL_PRESENT_STATUS_INFO,
                 "toolchain", "LOCAL OBSERVATION - Toolchain and verdict",
                 toolchain);
    npd_item(model, ZCL_PRESENT_ITEM_KEY_VALUE,
             feedback ? ZCL_PRESENT_STATUS_INFO : ZCL_PRESENT_STATUS_YELLOW,
             "behavior-class", "LOCAL OBSERVATION - Behavior lane",
             feedback && feedback[0] ? feedback : "not observed yet");
    npd_item(model, ZCL_PRESENT_ITEM_KEY_VALUE,
             red ? ZCL_PRESENT_STATUS_RED : ZCL_PRESENT_STATUS_NEUTRAL,
             "diagnostic", "LOCAL OBSERVATION - Mismatch",
             red ? (capsule && capsule[0] ? capsule : status) :
                   "none in this event");
    npd_item(model, ZCL_PRESENT_ITEM_KEY_VALUE, ZCL_PRESENT_STATUS_YELLOW,
             "unknown", "UNKNOWN - Independent reproduction",
             "Separate signed proof lane has not been joined to this local event");
    npd_item(model, ZCL_PRESENT_ITEM_KEY_VALUE, ZCL_PRESENT_STATUS_INFO,
             "next", "NEXT - One dominant agent action",
             next && next[0] ? next : "wait for the next canonical event");
    return zcl_present_model_validate_v1(model, why, why_cap);
}

static void npd_fail(struct zcl_command_reply *reply, const char *code,
                     const char *message)
{
    LOG_ERROR("native.presentation.development", "%s: %s", code, message);
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
        ZCL_COMMAND_EXIT_INVALID, code, "observe", true, false, message,
        NPD_LEAF);
}

void zcl_native_handle_presentation_development(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    const char *receipt_id = npd_str(request ? request->input : NULL,
                                     "receipt_id");
    struct zcl_command_reply facts;
    zcl_command_reply_init(&facts, "zcl.dev_cycle.v1");
    char fact_why[192] = {0};
    bool package_fact = receipt_id && receipt_id[0];
    if (package_fact) {
        if (!npd_package_facts(receipt_id, &facts.data,
                               fact_why, sizeof(fact_why))) {
            zcl_command_reply_free(&facts);
            npd_fail(reply, "PACKAGE_RECEIPT_UNAVAILABLE", fact_why);
            return;
        }
    } else {
        zcl_native_handle_dev_status(request, &facts);
    }
    if (facts.exit_code != ZCL_COMMAND_EXIT_OK) {
        zcl_command_reply_free(&facts);
        npd_fail(reply, "DEVELOPMENT_FACTS_UNAVAILABLE",
                 "the canonical local development verdict could not be read");
        return;
    }
    struct zcl_present_model_v1 model;
    char why[192];
    bool built = zcl_native_presentation_development_model_from_facts(
        &facts.data, &model, why, sizeof(why));
    char phase[32] = {0}, status[32] = {0};
    const char *fact_phase = npd_str(&facts.data, "phase");
    const char *fact_status = npd_str(&facts.data, "status");
    if (fact_phase) (void)snprintf(phase, sizeof(phase), "%s", fact_phase);
    if (fact_status) (void)snprintf(status, sizeof(status), "%s", fact_status);
    zcl_command_reply_free(&facts);
    if (!built) {
        npd_fail(reply, "DEVELOPMENT_MODEL_INVALID", why);
        return;
    }
    zcl_native_present_model(&model, NPD_LEAF, request->input, reply);
    if (reply->status == ZCL_COMMAND_STATUS_PASSED) {
        (void)json_push_kv_str(&reply->data, "fact_authority",
                              package_fact ? "local_package_build_receipt" :
                                             "local_dev_cycle_store");
        (void)json_push_kv_str(&reply->data, "event", phase);
        (void)json_push_kv_str(&reply->data, "verdict", status);
        (void)json_push_kv_str(&reply->data, "candidate_root",
                              model.exact_root);
        (void)json_push_kv_bool(&reply->data, "candidate_selected", false);
        (void)json_push_kv_bool(&reply->data,
                               "privileged_action_performed", false);
        if (package_fact)
            (void)json_push_kv_str(&reply->data, "receipt_id", receipt_id);
    }
}
