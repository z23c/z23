/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: `zcode work start` — the one command that turns a human goal into
 * a bounded canonical task, after first offering whatever is already
 * published. Split out of native_zcode_work_command.c so each function stays
 * under the cyclomatic-complexity cap; sibling declarations live in
 * native_zcode_work_priv.h. Start never writes the workspace: it composes
 * inputs for the existing planner and reports what came back. */

#include "command/native_command.h"
#include "native_zcode_work_priv.h"

#include "base/checked.h"
#include "base/hex.h"
#include "json/json.h"
#include "platform/directory_compat.h"
#include "platform/time_compat.h"
#include "services/zcode_goal_context_service.h"
#include "sha3/sha3.h"
#include "vcs/package_prepare.h"
#include "vcs/package_release.h"
#include "vcs/package_reuse.h"
#include "vcs/zcode_dev.h"
#include "vcs/zcode_dev_product.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Everything the request asked for, already bounded and defaulted. */
struct zwork_start_inputs {
    const char *workspace;
    const char *proof_datadir;
    const char *goal;
    const char *profile_name;
    const char *exact_symbol;
    const char *license;
    bool details;
    int64_t max_cpu_seconds;
};

/* What the reuse search decided, owned by the caller that renders it. */
struct zwork_start_reuse {
    struct json_value plan;
    struct json_value expert;
    bool complete;
    bool composed;
    char selected_root[65];
    char prepare_ref[VCS_PACKAGE_RELEASE_NAME_MAX +
                     VCS_PACKAGE_RELEASE_SEMVER_MAX + 2u];
};

/* The three canonical hex inputs the planner reads, plus the frozen model
 * policy root; all owned by one composition. */
struct zwork_plan_hex {
    char *lock;
    char *recipe;
    char *policy;
    char model[65];
};

static bool zwork_start_validate(const struct zcl_command_request *request,
                                 struct zwork_start_inputs *in,
                                 struct vcs_zcode_dev_profile *profile,
                                 struct zcl_command_reply *reply)
{
    in->workspace = zwork_str(request->input, "workspace");
    in->proof_datadir = zwork_str(request->input, "datadir");
    in->goal = zwork_str(request->input, "goal");
    in->details = zwork_bool(request->input, "details");
    in->profile_name = zwork_str(request->input, "profile");
    in->exact_symbol = zwork_str(request->input, "context_symbol");
    in->license = zwork_str(request->input, "license");
    in->max_cpu_seconds = zwork_int(request->input, "max_cpu_seconds", 600);
    const struct json_value *license_value = request->input
        ? json_get(request->input, "license") : NULL;
    if (!in->profile_name || !in->profile_name[0])
        in->profile_name = "standard";
    if (!in->workspace || !in->workspace[0] || !in->goal || !in->goal[0] ||
        in->max_cpu_seconds <= 0 || in->max_cpu_seconds > 600) {
        zwork_fail(reply, "MISSING_INPUT", "validate",
                   "work start requires workspace/goal and max_cpu_seconds in 1..600",
                   false, false);
        return false;
    }
    if (license_value &&
        (!in->license || !in->license[0] ||
         !vcs_package_release_license_allowed(in->license))) {
        zwork_fail(reply, "BAD_LICENSE_FILTER", "validate",
                   "license must be one exact allowlisted SPDX identifier",
                   false, false);
        return false;
    }
    if (!vcs_zcode_dev_profile_expand(in->profile_name, profile)) {
        zwork_fail(reply, "BAD_PROFILE", "validate",
                   "profile must be quick, standard, strong, or release",
                   false, false);
        return false;
    }
    return true;
}

/* A directory with no declared C23 package cannot host bounded work yet:
 * hand back the exact initialization step instead of guessing one. */
static void zwork_start_initialization(
    struct zcl_command_reply *reply, const struct zwork_start_inputs *in,
    const struct vcs_zcode_dev_profile *profile)
{
    struct json_value next_input;
    json_init(&next_input);
    json_set_object(&next_input);
    bool rendered =
        json_push_kv_str(&next_input, "workspace", in->workspace) &&
        json_push_kv_str(&reply->data, "work_id", "") &&
        json_push_kv_str(&reply->data, "goal", in->goal) &&
        json_push_kv_str(&reply->data, "state",
                         "INITIALIZATION_REQUIRED") &&
        json_push_kv_str(&reply->data, "stage",
                         "Initialize C23 package") &&
        json_push_kv_str(&reply->data, "profile", profile->name) &&
        json_push_kv_str(&reply->data, "authoritative_workspace",
                         "unchanged") &&
        json_push_kv_str(&reply->data, "next_safe_command",
                         "zcode project init plan") &&
        json_push_kv_bool(&reply->data, "details_available", false) &&
        zwork_add_next(
            reply, "zcode.project.init.plan", &next_input,
            "declare the C23 package before work can start");
    json_free(&next_input);
    if (!rendered)
        zwork_fail(reply, "WORK_OUTPUT_FAILED", "render",
                   "bounded initialization summary could not be rendered",
                   false, false);
}

/* A refused reuse search still reports what it did see, so the operator can
 * tell a too-wide license filter from an incomplete local index. */
static void zwork_start_reuse_refused(
    struct zcl_command_reply *reply, const char *license, bool truncated,
    bool incomplete, size_t indexed, size_t matched, size_t skipped)
{
    if (truncated || incomplete) {
        (void)json_push_kv_str(&reply->data, "license_filter", license);
        (void)json_push_kv_int(&reply->data, "packages_indexed",
                               (int64_t)indexed);
        (void)json_push_kv_int(&reply->data, "packages_filter_matched",
                               (int64_t)matched);
        (void)json_push_kv_int(&reply->data,
                               "package_release_rows_skipped",
                               (int64_t)skipped);
        (void)json_push_kv_int(&reply->data, "maximum_results",
                               VCS_PACKAGE_REUSE_MAX_INPUTS);
    }
    zwork_fail(
        reply,
        truncated ? "REUSE_SEARCH_TRUNCATED"
            : incomplete ? "REUSE_INDEX_INCOMPLETE"
                                   : "REUSE_PLAN_FAILED",
        "reuse",
        truncated
            ? "exact license search exceeded the bounded local result set"
            : incomplete
                ? "exact license search refused an incomplete local index"
            : "local package facts could not be ranked",
        false, false);
}

static bool zwork_start_reuse_search(
    const struct zcl_command_request *request,
    const struct zwork_start_inputs *in,
    struct vcs_package_prepared *prepared, struct zwork_start_reuse *reuse,
    struct zcl_command_reply *reply)
{
    bool truncated = false, incomplete = false;
    size_t indexed = 0, matched = 0, skipped = 0;
    if (zwork_reuse_render(request, in->goal, in->license, prepared,
                           &reuse->plan, &reuse->expert, &reuse->complete,
                           &reuse->composed, &truncated, &incomplete,
                           &indexed, &matched, &skipped,
                           reuse->selected_root, reuse->prepare_ref))
        return true;
    zwork_start_reuse_refused(reply, in->license, truncated, incomplete,
                              indexed, matched, skipped);
    return false;
}

/* A selected package that is not built yet must be used explicitly before
 * any new code is created. */
static bool zwork_start_prepare_reply(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply, const struct zwork_start_inputs *in,
    const struct vcs_zcode_dev_profile *profile,
    struct zwork_start_reuse *reuse)
{
    struct json_value next_input;
    bool rendered = zwork_use_next_input(
            request, reuse->prepare_ref, &next_input) &&
        json_push_kv_str(&reply->data, "work_id", "") &&
        json_push_kv_str(&reply->data, "goal", in->goal) &&
        json_push_kv_str(&reply->data, "state",
                         "REUSE_PREPARATION_REQUIRED") &&
        json_push_kv_str(&reply->data, "stage",
                         "Preparing reusable software") &&
        json_push_kv_str(&reply->data, "profile", profile->name) &&
        json_push_kv(&reply->data, "reuse_plan", &reuse->plan) &&
        json_push_kv_str(&reply->data, "authoritative_workspace",
                         "unchanged") &&
        json_push_kv_str(&reply->data, "next_safe_command",
                         "zcode use") &&
        json_push_kv_bool(&reply->data, "details_available", true) &&
        (!in->details || json_push_kv(
            &reply->data, "expert", &reuse->expert)) &&
        zwork_add_next(
            reply, "zcode.use", &next_input,
            "explicitly build and admit the selected reusable package");
    json_free(&next_input);
    return rendered;
}

/* The whole goal is already covered by an exact compatible package. */
static bool zwork_start_ready_reply(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply, const struct zwork_start_inputs *in,
    const struct vcs_zcode_dev_profile *profile,
    struct zwork_start_reuse *reuse)
{
    struct json_value next_input;
    json_init(&next_input);
    bool rendered = zwork_use_next_input(
            request, reuse->selected_root, &next_input) &&
        json_push_kv_str(&reply->data, "work_id", "") &&
        json_push_kv_str(&reply->data, "goal", in->goal) &&
        json_push_kv_str(&reply->data, "state", "REUSE_READY") &&
        json_push_kv_str(&reply->data, "stage", "Ready to use") &&
        json_push_kv_str(&reply->data, "profile", profile->name) &&
        json_push_kv(&reply->data, "reuse_plan", &reuse->plan) &&
        json_push_kv_str(&reply->data, "authoritative_workspace",
                         "unchanged") &&
        json_push_kv_str(&reply->data, "next_safe_command", "zcode use") &&
        json_push_kv_bool(&reply->data, "details_available", true) &&
        (!in->details || json_push_kv(
            &reply->data, "expert", &reuse->expert)) &&
        zwork_add_next(
            reply, "zcode.use", &next_input,
            "use the exact compatible package without copying a root");
    json_free(&next_input);
    return rendered;
}

static bool zwork_plan_fields(
    struct json_value *input, const char *workspace, const char *goal,
    const struct zwork_plan_hex *hex,
    const struct zcode_goal_selection *selection, const char *scopes,
    int64_t expires_unix, int64_t max_cpu_seconds)
{
    return json_push_kv_str(input, "mode", "plan") &&
        json_push_kv_str(input, "workspace", workspace) &&
        json_push_kv_str(input, "dependency_lock_hex", hex->lock) &&
        json_push_kv_str(input, "write_scope_csv", scopes) &&
        json_push_kv_str(input, "acceptance_recipe_hex", hex->recipe) &&
        json_push_kv_str(input, "model_policy_root", hex->model) &&
        json_push_kv_str(input, "goal", goal) &&
        json_push_kv_str(input, "proof_policy_hex", hex->policy) &&
        json_push_kv_str(input, "context_symbol",
                         selection->selected_symbol_id) &&
        json_push_kv_int(input, "expires_unix", expires_unix) &&
        json_push_kv_int(input, "max_cpu_seconds", max_cpu_seconds) &&
        json_push_kv_int(input, "max_context_bytes", 256 * 1024);
}

static bool zwork_plan_input(
    struct json_value *input, const char *workspace, const char *goal,
    const struct vcs_package_prepared *prepared,
    const struct vcs_zcode_dev_profile *profile,
    const struct zcode_goal_selection *selection, const char *scopes,
    int64_t expires_unix, int64_t max_cpu_seconds)
{
    uint8_t policy_wire[VCS_ZCODE_PROOF_POLICY_WIRE_BYTES];
    static const char model_policy[] =
        "zcode-product-v0.1:bounded-context;candidate-only-write;human-accept";
    uint8_t model_root[32];
    if (vcs_zcode_proof_policy_serialize(&profile->policy, policy_wire) !=
        VCS_ZCODE_DEV_OK)
        return false;
    sha3_256((const uint8_t *)model_policy, sizeof(model_policy), model_root);
    struct zwork_plan_hex hex;
    hex.lock = zwork_hex_alloc(prepared->lock_wire, prepared->lock_wire_len,
                               "zcode.work.lock_hex");
    hex.recipe = zwork_hex_alloc(prepared->recipe_wire,
                                 prepared->recipe_wire_len,
                                 "zcode.work.recipe_hex");
    hex.policy = zwork_hex_alloc(policy_wire, sizeof(policy_wire),
                                 "zcode.work.policy_hex");
    zcl_hex_encode(model_root, 32, hex.model);
    json_init(input); json_set_object(input);
    bool ok = hex.lock && hex.recipe && hex.policy &&
        zwork_plan_fields(input, workspace, goal, &hex, selection, scopes,
                          expires_unix, max_cpu_seconds);
    free(hex.policy); free(hex.recipe); free(hex.lock);
    return ok;
}

static bool zwork_selection_counts_json(
    struct json_value *out, const struct zcode_goal_selection *selection,
    const struct json_value *plan_data, uint64_t total_source_bytes)
{
    const struct json_value *bytes =
        json_get(plan_data, "agent_context_excerpt_bytes");
    const struct json_value *files =
        json_get(plan_data, "agent_context_files");
    int64_t selected_bytes = bytes && bytes->type == JSON_INT
        ? json_get_int(bytes) : 0;
    return json_push_kv_str(out, "symbol", selection->selected.name) &&
        json_push_kv_str(out, "why", selection->why) &&
        json_push_kv_int(out, "selected_context_bytes", selected_bytes) &&
        json_push_kv_int(out, "total_source_bytes",
                         (int64_t)total_source_bytes) &&
        json_push_kv_int(out, "selected_file_count",
                         files && files->type == JSON_INT
                             ? json_get_int(files) : 0) &&
        json_push_kv_int(out, "ranked_candidate_count",
                         (int64_t)selection->candidate_count) &&
        json_push_kv_int(out, "dropped_candidate_count",
                         (int64_t)selection->dropped_candidates);
}

static bool zwork_selection_retrieval_json(
    struct json_value *out, const struct zcode_goal_selection *selection,
    bool details)
{
    return json_push_kv_str(out, "retrieval", "bm25_story") &&
        json_push_kv_int(out, "retrieval_corpus_files",
                         (int64_t)selection->retrieval_corpus_files) &&
        json_push_kv_int(out, "retrieval_ranked_files",
                         (int64_t)selection->retrieval_ranked_files) &&
        json_push_kv_bool(out, "retrieval_truncated",
                          selection->retrieval_truncated) &&
        json_push_kv_int(out, "retrieval_us",
                         (int64_t)selection->retrieval_us) &&
        json_push_kv_bool(out, "budget_exhausted",
                          selection->budget_exhausted) &&
        json_push_kv_int(out, "generation_us",
                         (int64_t)selection->generation_us) &&
        (!details || (json_push_kv_str(
            out, "symbol_id", selection->selected_symbol_id) &&
            json_push_kv_int(out, "context_service_generation",
                             selection->service_generation)));
}

static bool zwork_render_selection(
    struct json_value *out, const struct zcode_goal_selection *selection,
    const struct json_value *plan_data, uint64_t total_source_bytes,
    bool details)
{
    json_init(out); json_set_object(out);
    return zwork_selection_counts_json(out, selection, plan_data,
                                       total_source_bytes) &&
        zwork_selection_retrieval_json(out, selection, details);
}

/* One bounded context selection plus the write scopes and expiry the
 * planner will freeze into the task. */
static bool zwork_start_context(
    const struct zwork_start_inputs *in,
    const struct vcs_package_prepared *prepared, bool reuse_composed,
    struct zcode_goal_selection *selection, char scopes[1024],
    uint64_t *expires, struct zcl_command_reply *reply)
{
    struct zcl_result selected = zcode_goal_context_select(
        in->workspace, in->goal, in->exact_symbol, selection);
    int64_t now = platform_time_wall_unix();
    if (selected.ok && zwork_scopes(prepared, reuse_composed, scopes) &&
        now > 0 && zcl_u64_add((uint64_t)now, 86400u, expires) &&
        *expires <= INT64_MAX)
        return true;
    zwork_fail(reply, "CONTEXT_SELECTION_FAILED", "context",
               selected.ok ? "project scopes or expiry could not be derived"
                           : selected.message,
               false, false);
    return false;
}

/* zcode.improve owns task-conflict classification; only those two named
 * coordination refusals survive as-is, everything else stays compact. */
static void zwork_start_plan_refused(const struct zcl_command_reply *inner,
                                     const char *workspace,
                                     struct zcl_command_reply *reply)
{
    bool coordination =
        strcmp(inner->error.code, "ACTIVE_TASK_CONFLICT") == 0 ||
        strcmp(inner->error.code, "TASK_CONFLICT_SCAN_INCOMPLETE") == 0;
    if (coordination) {
        if (!zwork_coordination_handoff(inner, workspace, reply))
            zwork_fail(reply, "WORK_COORDINATION_HANDOFF_FAILED", "render",
                       "the bounded canonical task-conflict handoff could not be preserved",
                       false, inner->error.mutated);
        return;
    }
    zwork_fail(
        reply,
        inner->error.code[0] ? inner->error.code : "WORK_PLAN_FAILED",
        inner->error.phase[0] ? inner->error.phase : "plan",
        inner->error.message[0] ? inner->error.message
                               : "existing task planner refused",
        inner->error.retryable, inner->error.mutated);
}

static bool zwork_start_summary_json(
    struct zcl_command_reply *reply, const char *work_id,
    const struct zwork_start_inputs *in,
    const struct vcs_zcode_dev_profile *profile, struct json_value *plan,
    struct json_value *context, struct json_value *expert)
{
    return json_push_kv_str(&reply->data, "work_id", work_id) &&
        json_push_kv_str(&reply->data, "goal", in->goal) &&
        json_push_kv_str(&reply->data, "state", "AWAITING_CANDIDATE") &&
        json_push_kv_str(&reply->data, "stage",
                         "Creating missing code") &&
        json_push_kv_str(&reply->data, "profile", profile->name) &&
        json_push_kv(&reply->data, "reuse_plan", plan) &&
        json_push_kv(&reply->data, "selected_context", context) &&
        json_push_kv_str(&reply->data, "authoritative_workspace",
                         "unchanged") &&
        json_push_kv_str(&reply->data, "next_safe_command",
                         "zcode work run") &&
        json_push_kv_bool(&reply->data, "details_available", true) &&
        (!in->details || json_push_kv(&reply->data, "expert", expert));
}

static bool zwork_start_next_json(struct zcl_command_reply *reply,
                                  const char *workspace, const char *work_id,
                                  const char *proof_datadir)
{
    struct json_value next_input;
    json_init(&next_input); json_set_object(&next_input);
    bool ok = json_push_kv_str(&next_input, "workspace", workspace) &&
        json_push_kv_str(&next_input, "work", work_id) &&
        (!proof_datadir || !proof_datadir[0] ||
         json_push_kv_str(&next_input, "datadir", proof_datadir)) &&
        zwork_add_next(
            reply, "zcode.work.run", &next_input,
            "create only the behavior the reuse plan still marks missing");
    json_free(&next_input);
    return ok;
}

static void zwork_start_admitted(
    struct zcl_command_reply *reply, const struct zwork_start_inputs *in,
    const struct vcs_zcode_dev_profile *profile,
    const struct vcs_package_prepared *prepared,
    const struct zcode_goal_selection *selection,
    const struct zcl_command_reply *inner, struct zwork_start_reuse *reuse)
{
    const struct json_value *task_root = json_get(&inner->data, "task_root");
    const char *task_hex = task_root ? json_get_str(task_root) : NULL;
    struct json_value context, expert;
    uint64_t source_bytes = zwork_source_bytes(prepared);
    bool ok = task_hex && strlen(task_hex) == 64 && source_bytes != 0 &&
        zwork_render_selection(&context, selection, &inner->data,
                               source_bytes, in->details);
    json_init(&expert);
    if (ok) {
        json_copy(&expert, &inner->data);
        ok = json_push_kv(&expert, "reuse", &reuse->expert);
    }
    char work_id[32] = {0};
    if (ok) (void)snprintf(work_id, sizeof(work_id), "work-%.12s", task_hex);
    ok = ok && zwork_start_summary_json(reply, work_id, in, profile,
                                        &reuse->plan, &context, &expert);
    ok = ok && zwork_start_next_json(reply, in->workspace, work_id,
                                     in->proof_datadir);
    json_free(&expert); json_free(&context);
    if (!ok)
        zwork_fail(reply, "WORK_OUTPUT_FAILED", "render",
                   "bounded human work summary could not be rendered",
                   false, true);
}

static void zwork_start_plan(const struct zwork_start_inputs *in,
                             const struct vcs_zcode_dev_profile *profile,
                             const struct vcs_package_prepared *prepared,
                             struct zwork_start_reuse *reuse,
                             struct zcl_command_reply *reply)
{
    struct zcode_goal_selection selection;
    char scopes[1024];
    uint64_t expires = 0;
    if (!zwork_start_context(in, prepared, reuse->composed, &selection,
                             scopes, &expires, reply))
        return;
    struct json_value plan_input;
    if (!zwork_plan_input(&plan_input, in->workspace, in->goal, prepared,
                          profile, &selection, scopes, (int64_t)expires,
                          in->max_cpu_seconds)) {
        zwork_fail(reply, "WORK_COMPOSE_FAILED", "compose",
                   "existing task inputs could not be composed", false, false);
        return;
    }
    struct zcl_command_request inner_request = { .input = &plan_input };
    struct zcl_command_reply inner;
    zcl_command_reply_init(&inner, "zcl.zcode_improve.v1");
    zcl_native_handle_zcode_improve(&inner_request, &inner);
    json_free(&plan_input);
    if (inner.status != ZCL_COMMAND_STATUS_PASSED)
        zwork_start_plan_refused(&inner, in->workspace, reply);
    else
        zwork_start_admitted(reply, in, profile, prepared, &selection,
                             &inner, reuse);
    zcl_command_reply_free(&inner);
}

/* Offer what already exists before creating anything: an unbuilt selected
 * package, a fully covered goal, or otherwise one bounded new task. */
static void zwork_start_planned(const struct zcl_command_request *request,
                                const struct zwork_start_inputs *in,
                                const struct vcs_zcode_dev_profile *profile,
                                struct vcs_package_prepared *prepared,
                                struct zcl_command_reply *reply)
{
    struct zwork_start_reuse reuse;
    if (!zwork_start_reuse_search(request, in, prepared, &reuse, reply))
        return;
    if (reuse.prepare_ref[0]) {
        if (!zwork_start_prepare_reply(request, reply, in, profile, &reuse))
            zwork_fail(reply, "WORK_OUTPUT_FAILED", "render",
                       "bounded reuse preparation summary could not be rendered",
                       false, false);
    } else if (reuse.complete) {
        if (!reuse.selected_root[0] ||
            !zwork_start_ready_reply(request, reply, in, profile, &reuse))
            zwork_fail(reply, "WORK_OUTPUT_FAILED", "render",
                       "bounded reuse summary could not be rendered",
                       false, false);
    } else {
        zwork_start_plan(in, profile, prepared, &reuse, reply);
    }
    json_free(&reuse.expert); json_free(&reuse.plan);
}

void zcl_native_handle_zcode_work_start(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!request || !reply) return;
    struct zwork_start_inputs in;
    struct vcs_zcode_dev_profile profile;
    if (!zwork_start_validate(request, &in, &profile, reply)) return;
    char canonical_workspace[ZWORK_PATH_MAX];
    if (!platform_directory_canonical_real(
            in.workspace, canonical_workspace,
            sizeof(canonical_workspace))) {
        zwork_fail(reply, "PROJECT_INSPECT_FAILED", "inspect",
                   "workspace must be a real directory", false, false);
        return;
    }
    in.workspace = canonical_workspace;
    char canonical_datadir[ZWORK_PATH_MAX];
    if (in.proof_datadir && in.proof_datadir[0]) {
        if (!platform_directory_canonical_real(
                in.proof_datadir, canonical_datadir, sizeof(canonical_datadir))) {
            zwork_fail(reply, "BAD_DATADIR", "validate",
                       "datadir must be a real directory", false, false);
            return;
        }
        in.proof_datadir = canonical_datadir;
    }
    if (!zwork_regular_package_config(in.workspace)) {
        zwork_start_initialization(reply, &in, &profile);
        return;
    }
    struct vcs_package_prepared prepared;
    char detail[256] = {0};
    if (!zwork_prepare(in.workspace, &prepared, detail, sizeof(detail))) {
        zwork_fail(reply, "PROJECT_INSPECT_FAILED", "inspect", detail,
                   false, false);
        return;
    }
    zwork_start_planned(request, &in, &profile, &prepared, reply);
    vcs_package_prepared_free(&prepared);
}
