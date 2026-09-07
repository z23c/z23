/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: The zcode.improve native adapter — plans or admits one immutable
 * ZBuild task/candidate/action tuple. Canonical objects, CAS writes, and the
 * ZBuild ledger commit form one fail-closed local admission transaction; no
 * candidate or proof is claimed by this planning command. Staged into named
 * helpers sharing one zdev_improve_ctx so each stays independently readable
 * while the whole handler still commits exactly the objects it always did. */

#include "command/native_command.h"
#include "command/native_zcode_dev_priv.h"

#include "controllers/rpc_client.h"
#include "base/hex.h"
#include "base/serialize_le.h"
#include "crypto/sha3.h"
#include "config/runtime.h"
#include "config/command_catalog.h"
#include "hotswap/hotswap_service.h"
#include "json/json.h"
#include "models/database.h"
#include "models/database_owner_lease.h"
#include "platform/directory_compat.h"
#include "platform/directory_transaction.h"
#include "platform/positioned_file.h"
#include "platform/private_directory.h"
#include "platform/private_file.h"
#include "platform/rng.h"
#include "platform/time_compat.h"
#include "services/build_fabric_service.h"
#include "services/build_fabric_async.h"
#include "services/build_fabric_worker.h"
#include "services/zcode_agent_context_service.h"
#include "services/zcode_lane_service.h"
#include "services/zcode_lane_view_service.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"
#include "vcs/build_action.h"
#include "vcs/build_artifact_manifest.h"
#include "vcs/package_accept.h"
#include "vcs/package_index.h"
#include "vcs/vcs.h"
#include "vcs/vcs_object.h"
#include "vcs/zcode_dev.h"
#include "vcs/zcode_lane.h"
#include "vcs/package_manifest.h"
#include "vcs/package_mapping.h"
#include "vcs/package_deps.h"
#include "vcs/package_recipe.h"
#include "vcs/package_store.h"
#include "vcs/source_package_transport.h"
#include "vcs/vcs_devloop.h"
#include "vcs/zcode_work_context.h"
#include "vcs/zcode_work_node.h"
#include "vcs/zcode_action_input.h"
#include "vcs/zcode_write_scope.h"
#include "vcs/zcode_patch.h"
#include "vcs/zcode_candidate_bundle.h"
#include "vcs/zcode_task_authority.h"
#include "vcs/zcode_task_authority_bundle.h"
#include "vcs/zcode_task_index.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if !defined(_WIN32)
#include <sys/stat.h>
#include <unistd.h>
#endif

struct zdev_improve_ctx {
    const char *workspace_arg;
    const char *datadir;
    const char *goal;
    const char *policy_hex;
    const char *lock_hex;
    const char *recipe_hex;
    const char *mode_arg;
    const char *mode;
    bool plan_only;
    bool explicit_admit;
    const char *context_symbol;
    const char *planned_task_root;
    const char *planned_context_root;
    const char *write_scope_csv;
    const char *action_kind;
    bool package_action;
    uint8_t work_kind;
    const char *fixed_input;
    const char *fixed_input_relpath;
    const char *candidate_workspace;
    char workspace[ZDEV_PATH_MAX];

    struct vcs_zcode_proof_policy_v1 policy;
    uint8_t policy_wire[VCS_ZCODE_PROOF_POLICY_WIRE_BYTES];
    uint8_t policy_root[32];

    struct vcs_zcode_task_v1 task;
    int64_t now;
    uint8_t task_wire[VCS_ZCODE_TASK_WIRE_BYTES];
    uint8_t task_root[32];

    struct zcode_agent_context_status agent_context;
    bool agent_context_ready;

    struct vcs_zcode_candidate_v1 candidate;
    uint8_t source_sha_check[32];
    char source_sha_hex[65];
    uint32_t changed_files;
    uint64_t patch_bytes;
    uint8_t candidate_wire[VCS_ZCODE_CANDIDATE_WIRE_BYTES];
    uint8_t candidate_root[32];

    char input_path[VCS_PATH_MAX + 1u];
    uint8_t *input_wire;
    size_t input_len;
    uint8_t input_root[32];
    const char *input_schema;

    const char *source_sha256;

    struct db_build_job job;
    struct db_build_action action;
    int64_t remote_peer;

    int64_t submit_started_us;
    int64_t request_creation_us;
    int64_t ledger_started_us;
    struct node_db local_ndb;
    struct node_db *ndb;
    bool owned;

    bool reproduction_needed;
    char reproduction_action_id[BUILD_FABRIC_ID_HEX + 1];
    char reproduction_job_id[BUILD_FABRIC_ID_HEX + 1];

    struct zcode_lane_status frontier_status;

    struct zcl_result planned;
    struct zcl_result reproduction_planned;
    struct zcl_result admitted;
    struct zcl_result submitted;
    struct zcl_result proof_requested;
    struct zcl_result reproduction_requested;

    struct db_build_proof_event proof_request;
    bool proof_request_created;
    struct db_build_proof_event reproduction_request;
    bool reproduction_request_created;

    int64_t local_submit_us;
    int64_t ledger_us;
};

static void zdev_coordination_refuse(
    struct zcl_command_reply *reply,
    const char *workspace, const struct vcs_zcode_task_conflict *conflict)
{
    const char *kind = conflict
        ? vcs_zcode_task_conflict_kind_string(conflict->kind) : "INCOMPLETE";
    const char *task_root = conflict && conflict->task_root_hex[0]
        ? conflict->task_root_hex : "zcode.tasks";
    char detail[256];
    (void)snprintf(detail, sizeof(detail),
        "%s: canonical task admission stopped before task/context persistence; "
        "assignment and active execution remain unobserved", kind);
    zcl_command_reply_fail(
        reply, ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_BLOCKED,
        conflict && conflict->kind != VCS_ZCODE_TASK_CONFLICT_INCOMPLETE
            ? "ACTIVE_TASK_CONFLICT" : "TASK_CONFLICT_SCAN_INCOMPLETE",
        "coordinate", false, true, detail, task_root);
    (void)json_push_kv_str(&reply->data, "conflict_kind", kind);
    (void)json_push_kv_str(
        &reply->data, "assignment_status", "UNOBSERVED");
    (void)json_push_kv_str(
        &reply->data, "active_execution", "UNOBSERVED");
    if (conflict) {
        (void)json_push_kv_str(&reply->data, "task_root",
                               conflict->task_root_hex);
        (void)json_push_kv_str(&reply->data, "source_root",
                               conflict->source_root_hex);
        (void)json_push_kv_str(&reply->data, "goal_root",
                               conflict->goal_root_hex);
        (void)json_push_kv_str(&reply->data, "write_scope_root",
                               conflict->write_scope_root_hex);
        (void)json_push_kv_str(&reply->data, "agent_context_root",
                               conflict->context_root_hex);
        (void)json_push_kv_str(&reply->data, "action_root",
                               conflict->action_root_hex);
        (void)json_push_kv_str(&reply->data, "work_receipt_root",
                               conflict->work_receipt_root_hex);
    }
    if (workspace && conflict && conflict->task_root_hex[0]) {
        struct json_value input_value;
        json_init(&input_value);
        json_set_object(&input_value);
        (void)json_push_kv_str(&input_value, "workspace", workspace);
        (void)json_push_kv_str(&input_value, "task_root",
                               conflict->task_root_hex);
        (void)json_push_kv_bool(&input_value, "details", true);
        char input[512];
        size_t input_len = json_write(&input_value, input, sizeof(input));
        if (input_len > 0 && input_len < sizeof(input))
            (void)zcl_command_reply_add_next(
                reply, "zcode.tasks", input,
                "Inspect the exact conflicting CAS task and its evidence roots.");
        json_free(&input_value);
    }
}

static const char *zdev_task_mismatch_field(
    const char *workspace, const uint8_t planned_root[32],
    const struct vcs_zcode_task_v1 *actual)
{
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    struct vcs_zcode_task_v1 planned;
    bool loaded = workspace && planned_root && actual &&
        vcs_object_load_raw_bounded(
            workspace, planned_root, VCS_ZCODE_TASK_WIRE_BYTES,
            &wire, &wire_len) == 0 &&
        vcs_zcode_task_parse(wire, wire_len, &planned) == VCS_ZCODE_DEV_OK;
    free(wire);
    if (!loaded) return "planned task object";
#define ZDEV_TASK_ROOT_DIFF(field) \
    if (memcmp(planned.field, actual->field, 32) != 0) return #field
    ZDEV_TASK_ROOT_DIFF(source_root);
    ZDEV_TASK_ROOT_DIFF(dependency_lock_root);
    ZDEV_TASK_ROOT_DIFF(toolchain_capsule_root);
    ZDEV_TASK_ROOT_DIFF(write_scope_root);
    ZDEV_TASK_ROOT_DIFF(acceptance_tests_root);
    ZDEV_TASK_ROOT_DIFF(proof_policy_root);
    ZDEV_TASK_ROOT_DIFF(model_policy_root);
    ZDEV_TASK_ROOT_DIFF(goal_root);
#undef ZDEV_TASK_ROOT_DIFF
#define ZDEV_TASK_VALUE_DIFF(field) \
    if (planned.field != actual->field) return #field
    ZDEV_TASK_VALUE_DIFF(schema_version);
    ZDEV_TASK_VALUE_DIFF(capabilities);
    ZDEV_TASK_VALUE_DIFF(max_changed_files);
    ZDEV_TASK_VALUE_DIFF(max_patch_bytes);
    ZDEV_TASK_VALUE_DIFF(max_context_bytes);
    ZDEV_TASK_VALUE_DIFF(max_cpu_seconds);
    ZDEV_TASK_VALUE_DIFF(max_memory_bytes);
    ZDEV_TASK_VALUE_DIFF(max_output_bytes);
    ZDEV_TASK_VALUE_DIFF(expires_unix);
#undef ZDEV_TASK_VALUE_DIFF
    return "canonical task bytes";
}

static void zdev_push_agent_context(
    struct json_value *out, const struct zcode_agent_context_status *context)
{
    (void)json_push_kv_str(out, "agent_context_root",
                           context->context_root_sha3);
    (void)json_push_kv_str(out, "agent_context_source_tree_root",
                           context->source_tree_root_sha3);
    (void)json_push_kv_str(out, "agent_context_symbol",
                           context->resolved_symbol);
    (void)json_push_kv_int(out, "agent_context_files",
                           (int64_t)context->file_count);
    (void)json_push_kv_int(out, "agent_context_excerpt_bytes",
                           (int64_t)context->excerpt_bytes);
    (void)json_push_kv_int(out, "agent_context_wire_bytes",
                           (int64_t)context->wire_bytes);
    (void)json_push_kv_bool(out, "agent_context_truncated",
                            context->truncated);
}

/* ── phase 1: parse and validate every raw input field ─────────────────── */

static bool zdev_improve_parse_mode(
    const struct zcl_command_request *request, struct zdev_improve_ctx *ctx,
    struct zcl_command_reply *reply)
{
    ctx->mode_arg = zdev_str(request->input, "mode");
    ctx->mode = ctx->mode_arg;
    if (!ctx->mode || !ctx->mode[0]) ctx->mode = "admit";
    ctx->plan_only = strcmp(ctx->mode, "plan") == 0;
    ctx->explicit_admit = ctx->mode_arg && strcmp(ctx->mode_arg, "admit") == 0;
    if (!ctx->plan_only && strcmp(ctx->mode, "admit") != 0) {
        zdev_fail(reply, "BAD_MODE", "mode must be plan or admit");
        return false;
    }
    return true;
}

static bool zdev_improve_parse_action_kind(
    const struct zcl_command_request *request, struct zdev_improve_ctx *ctx,
    struct zcl_command_reply *reply)
{
    ctx->action_kind = zdev_str(request->input, "action_kind");
    if (!ctx->action_kind || !ctx->action_kind[0])
        ctx->action_kind = VCS_BUILD_ACTION_KIND_V1;
    ctx->package_action =
        strcmp(ctx->action_kind, VCS_BUILD_ACTION_KIND_PACKAGE_V1) == 0;
    ctx->work_kind = vcs_build_action_v1_work_kind(ctx->action_kind);
    if (ctx->work_kind != VCS_ZCODE_WORK_BUILD &&
        ctx->work_kind != VCS_ZCODE_WORK_TEST &&
        ctx->work_kind != VCS_ZCODE_WORK_FUZZ) {
        zdev_fail(reply, "BAD_ACTION_KIND",
                  "action_kind must name the fixed compile, recipe-package, test, or fuzz executor");
        return false;
    }
    return true;
}

static bool zdev_improve_check_basic_fields(const struct zdev_improve_ctx *ctx)
{
    return ctx->workspace_arg && ctx->datadir && ctx->goal && ctx->goal[0] &&
        strlen(ctx->goal) <= 4096 && ctx->policy_hex;
}

static bool zdev_improve_check_plan_requirements(
    const struct zdev_improve_ctx *ctx)
{
    return !ctx->plan_only ||
        (ctx->context_symbol && ctx->context_symbol[0]);
}

static bool zdev_improve_check_explicit_admit_requirements(
    const struct zdev_improve_ctx *ctx)
{
    return !ctx->explicit_admit ||
        (ctx->context_symbol && ctx->context_symbol[0] &&
         ctx->planned_task_root && ctx->planned_task_root[0] &&
         ctx->planned_context_root && ctx->planned_context_root[0]);
}

static bool zdev_improve_check_scope_requirements(
    const struct zdev_improve_ctx *ctx)
{
    return !(ctx->plan_only || ctx->explicit_admit) ||
        (ctx->write_scope_csv && ctx->write_scope_csv[0] &&
         ctx->lock_hex && ctx->lock_hex[0] &&
         ctx->recipe_hex && ctx->recipe_hex[0]);
}

static bool zdev_improve_check_candidate_workspace_requirement(
    const struct zdev_improve_ctx *ctx)
{
    return !ctx->explicit_admit ||
        (ctx->candidate_workspace && ctx->candidate_workspace[0]);
}

static bool zdev_improve_check_fixed_input_requirement(
    const struct zdev_improve_ctx *ctx)
{
    return ctx->plan_only || ctx->package_action ||
        ctx->fixed_input || ctx->fixed_input_relpath;
}

static bool zdev_improve_required_inputs_present(
    const struct zdev_improve_ctx *ctx)
{
    return zdev_improve_check_basic_fields(ctx) &&
        zdev_improve_check_plan_requirements(ctx) &&
        zdev_improve_check_explicit_admit_requirements(ctx) &&
        zdev_improve_check_scope_requirements(ctx) &&
        zdev_improve_check_candidate_workspace_requirement(ctx) &&
        zdev_improve_check_fixed_input_requirement(ctx);
}

static bool zdev_improve_package_fixed_input_conflict(
    const struct zdev_improve_ctx *ctx)
{
    return ctx->package_action &&
        ((ctx->fixed_input && ctx->fixed_input[0]) ||
         (ctx->fixed_input_relpath && ctx->fixed_input_relpath[0]));
}

static bool zdev_improve_parse_request(
    const struct zcl_command_request *request, struct zcl_command_reply *reply,
    struct zdev_improve_ctx *ctx)
{
    ctx->workspace_arg = zdev_str(request->input, "workspace");
    ctx->datadir = zdev_str(request->input, "datadir");
    if (!ctx->datadir || !ctx->datadir[0])
        ctx->datadir = zcl_native_command_datadir();
    ctx->goal = zdev_str(request->input, "goal");
    ctx->policy_hex = zdev_str(request->input, "proof_policy_hex");
    ctx->lock_hex = zdev_str(request->input, "dependency_lock_hex");
    ctx->recipe_hex = zdev_str(request->input, "acceptance_recipe_hex");
    if (!zdev_improve_parse_mode(request, ctx, reply)) return false;
    if (!ctx->plan_only && zcl_native_forward_live_command(
            request, ctx->datadir, "zcode_work_admit",
            "LIVE_ADMISSION_FAILED", "admit", "zcode.improve", reply))
        return false;
    ctx->context_symbol = zdev_str(request->input, "context_symbol");
    ctx->planned_task_root = zdev_str(request->input, "planned_task_root");
    ctx->planned_context_root =
        zdev_str(request->input, "planned_context_root");
    ctx->write_scope_csv = zdev_str(request->input, "write_scope_csv");
    if (!zdev_improve_parse_action_kind(request, ctx, reply)) return false;
    ctx->fixed_input = zdev_str(request->input, "fixed_input_path");
    if (!ctx->fixed_input)
        ctx->fixed_input = zdev_str(request->input, "preprocessed_path");
    ctx->fixed_input_relpath =
        zdev_str(request->input, "fixed_input_relpath");
    ctx->candidate_workspace =
        zdev_str(request->input, "candidate_workspace");
    if (!zdev_improve_required_inputs_present(ctx)) {
        zdev_fail(reply, "MISSING_INPUT",
                  ctx->plan_only
                    ? "plan requires workspace, goal, proof policy, lock/recipe wires, and context_symbol"
                    : "explicit admit requires planned roots, candidate_workspace, context symbol, and a candidate-relative fixed input");
        return false;
    }
    if (zdev_improve_package_fixed_input_conflict(ctx)) {
        zdev_fail(reply, "BAD_ACTION_INPUT",
                  "recipe-package actions derive the whole candidate tree and accept no fixed executable");
        return false;
    }
    if (!platform_directory_canonical_real(
            ctx->workspace_arg, ctx->workspace, sizeof(ctx->workspace))) {
        zdev_fail(reply, "BAD_WORKSPACE",
                  "workspace must resolve to an existing directory");
        return false;
    }
    return true;
}

/* ── phase 2: build the immutable task object ───────────────────────────── */

static bool zdev_improve_policy_covers_work(
    const struct zdev_improve_ctx *ctx)
{
    return (ctx->policy.required_proofs & VCS_ZCODE_PROOF_COMPILE) &&
        !(ctx->work_kind == VCS_ZCODE_WORK_TEST &&
          !(ctx->policy.required_proofs & VCS_ZCODE_PROOF_TEST)) &&
        !(ctx->work_kind == VCS_ZCODE_WORK_FUZZ &&
          !(ctx->policy.required_proofs & VCS_ZCODE_PROOF_FUZZ));
}

static bool zdev_improve_parse_policy(
    struct zdev_improve_ctx *ctx, struct zcl_command_reply *reply)
{
    if (strlen(ctx->policy_hex) != sizeof(ctx->policy_wire) * 2u ||
        !zcl_hex_decode_lower(ctx->policy_hex, ctx->policy_wire,
                              sizeof(ctx->policy_wire)) ||
        vcs_zcode_proof_policy_parse(ctx->policy_wire,
                                     sizeof(ctx->policy_wire),
                                     &ctx->policy) != VCS_ZCODE_DEV_OK ||
        !zdev_improve_policy_covers_work(ctx)) {
        zdev_fail(reply, "BAD_PROOF_POLICY",
                  "proof_policy_hex must require compile and the requested proof kind");
        return false;
    }
    if (vcs_zcode_proof_policy_root(&ctx->policy, ctx->policy_root) !=
        VCS_ZCODE_DEV_OK) {
        zdev_fail(reply, "BAD_PROOF_POLICY", "proof policy root refused");
        return false;
    }
    return true;
}

static bool zdev_improve_build_source_root(
    const struct zcl_command_request *request, struct zdev_improve_ctx *ctx,
    struct zcl_command_reply *reply)
{
    if (!ctx->plan_only && !ctx->explicit_admit)
        return zdev_root(request->input, "source_root", ctx->task.source_root,
                         reply);
    if (!zdev_capture_source_root(ctx->workspace, ctx->task.source_root,
                                  reply))
        return false;
    const char *claimed_source = zdev_str(request->input, "source_root");
    if (!claimed_source || !claimed_source[0]) return true;
    uint8_t claimed_root[32];
    if (!zcl_hex_decode_lower(claimed_source, claimed_root, 32) ||
        memcmp(claimed_root, ctx->task.source_root, 32) != 0) {
        zdev_fail(reply, "SOURCE_ROOT_MISMATCH",
                  "source_root does not match the captured workspace tree");
        return false;
    }
    return true;
}

static bool zdev_improve_authority_claims_match(
    const struct zcl_command_request *request,
    const struct zdev_improve_ctx *ctx)
{
    const char *claimed_lock =
        zdev_str(request->input, "dependency_lock_root");
    const char *claimed_recipe =
        zdev_str(request->input, "acceptance_tests_root");
    uint8_t claimed[32];
    if (claimed_lock && claimed_lock[0] &&
        (!zcl_hex_decode_lower(claimed_lock, claimed, 32) ||
         memcmp(claimed, ctx->task.dependency_lock_root, 32) != 0))
        return false;
    if (claimed_recipe && claimed_recipe[0] &&
        (!zcl_hex_decode_lower(claimed_recipe, claimed, 32) ||
         memcmp(claimed, ctx->task.acceptance_tests_root, 32) != 0))
        return false;
    return true;
}

static bool zdev_improve_build_lock_recipe(
    const struct zcl_command_request *request, struct zdev_improve_ctx *ctx,
    struct zcl_command_reply *reply)
{
    if (!ctx->plan_only && !ctx->explicit_admit)
        return zdev_root(request->input, "dependency_lock_root",
                         ctx->task.dependency_lock_root, reply) &&
            zdev_root(request->input, "acceptance_tests_root",
                      ctx->task.acceptance_tests_root, reply);
    size_t lock_len = 0, recipe_len = 0;
    uint8_t *lock_wire = zdev_hex_wire(
        request->input, "dependency_lock_hex",
        VCS_PACKAGE_LOCK_MAX_WIRE_BYTES, &lock_len);
    uint8_t *recipe_wire = zdev_hex_wire(
        request->input, "acceptance_recipe_hex",
        VCS_PACKAGE_RECIPE_MAX_WIRE_BYTES, &recipe_len);
    enum vcs_zcode_task_authority_result authority =
        lock_wire && recipe_wire
            ? vcs_zcode_task_authority_store(
                  ctx->workspace, lock_wire, lock_len, recipe_wire,
                  recipe_len, ctx->task.dependency_lock_root,
                  ctx->task.acceptance_tests_root)
            : VCS_ZCODE_TASK_AUTHORITY_NULL;
    free(recipe_wire); free(lock_wire);
    if (authority != VCS_ZCODE_TASK_AUTHORITY_OK) {
        zdev_fail(reply, "TASK_AUTHORITY_REFUSED",
            vcs_zcode_task_authority_result_string(authority));
        return false;
    }
    if (!zdev_improve_authority_claims_match(request, ctx)) {
        zdev_fail(reply, "TASK_AUTHORITY_ROOT_MISMATCH",
                  "claimed lock/acceptance roots do not match their wires");
        return false;
    }
    return true;
}

static bool zdev_improve_build_write_scope(
    const struct zcl_command_request *request, struct zdev_improve_ctx *ctx,
    struct zcl_command_reply *reply)
{
    if (!ctx->plan_only && !ctx->explicit_admit)
        return zdev_root(request->input, "write_scope_root",
                         ctx->task.write_scope_root, reply);
    if (!zdev_capture_write_scope(ctx->workspace, ctx->write_scope_csv,
                                  ctx->task.write_scope_root, reply))
        return false;
    const char *claimed_scope = zdev_str(request->input, "write_scope_root");
    if (!claimed_scope || !claimed_scope[0]) return true;
    uint8_t claimed_root[32];
    if (!zcl_hex_decode_lower(claimed_scope, claimed_root, 32) ||
        memcmp(claimed_root, ctx->task.write_scope_root, 32) != 0) {
        zdev_fail(reply, "WRITE_SCOPE_ROOT_MISMATCH",
                  "write_scope_root does not match write_scope_csv");
        return false;
    }
    return true;
}

static bool zdev_improve_capture_toolchain(
    struct zdev_improve_ctx *ctx, struct zcl_command_reply *reply)
{
    struct vcs_toolchain_capsule_v1 capsule;
    if (!vcs_toolchain_capsule_v1_capture(&capsule) ||
        !vcs_toolchain_capsule_v1_root(&capsule,
                                       ctx->task.toolchain_capsule_root)) {
        zdev_fail(reply, "TOOLCHAIN_CAPTURE_FAILED",
                  "the fixed GCC toolchain capsule could not be captured");
        return false;
    }
    return true;
}

static void zdev_improve_apply_limits(
    const struct zcl_command_request *request, struct zdev_improve_ctx *ctx)
{
    ctx->task.capabilities = VCS_ZCODE_TASK_CAP_V1_MASK;
    ctx->task.max_changed_files = (uint32_t)zdev_int(
        request->input, "max_changed_files", 64);
    ctx->task.max_patch_bytes = (uint64_t)zdev_int(
        request->input, "max_patch_bytes", 16 * 1024 * 1024);
    ctx->task.max_context_bytes = (uint64_t)zdev_int(
        request->input, "max_context_bytes", 16 * 1024 * 1024);
    ctx->task.max_cpu_seconds = (uint32_t)zdev_int(
        request->input, "max_cpu_seconds", 600);
    ctx->task.max_memory_bytes = (uint64_t)zdev_int(
        request->input, "max_memory_bytes", UINT64_C(2048) * 1024u * 1024u);
    ctx->task.max_output_bytes = (uint64_t)zdev_int(
        request->input, "max_output_bytes", VCS_BUILD_ARTIFACT_MAX_BYTES);
    ctx->task.expires_unix = zdev_int(request->input, "expires_unix", 0);
}

static bool zdev_improve_finalize_task(
    struct zdev_improve_ctx *ctx, struct zcl_command_reply *reply)
{
    if (vcs_zcode_task_validate_at(&ctx->task, ctx->now) != VCS_ZCODE_DEV_OK) {
        zdev_fail(reply, "TASK_INVALID",
                  "task limits, capabilities, roots, or expiry are invalid");
        return false;
    }
    enum vcs_zcode_task_authority_result task_authority =
        vcs_zcode_task_authority_validate(ctx->workspace, &ctx->task);
    if (task_authority != VCS_ZCODE_TASK_AUTHORITY_OK) {
        zdev_fail(reply, "TASK_AUTHORITY_STALE",
            vcs_zcode_task_authority_result_string(task_authority));
        return false;
    }
    if (vcs_zcode_task_serialize(&ctx->task, ctx->task_wire) !=
            VCS_ZCODE_DEV_OK ||
        vcs_zcode_task_root(&ctx->task, ctx->task_root) != VCS_ZCODE_DEV_OK) {
        zdev_fail(reply, "TASK_INVALID",
                  "canonical task serialization failed");
        return false;
    }
    return true;
}

static bool zdev_improve_check_expected_task_root(
    struct zdev_improve_ctx *ctx, struct zcl_command_reply *reply)
{
    if (!ctx->explicit_admit) return true;
    uint8_t expected_task_root[32];
    if (zcl_hex_decode_lower(ctx->planned_task_root, expected_task_root, 32) &&
        memcmp(expected_task_root, ctx->task_root, 32) == 0)
        return true;
    char detail[160];
    const char *field = zcl_hex_decode_lower(
        ctx->planned_task_root, expected_task_root, 32)
        ? zdev_task_mismatch_field(ctx->workspace, expected_task_root,
                                   &ctx->task)
        : "planned_task_root encoding";
    (void)snprintf(detail, sizeof(detail),
                   "admit parameters changed planned %s", field);
    zdev_fail(reply, "PLANNED_TASK_MISMATCH", detail);
    return false;
}

static bool zdev_improve_build_task(
    const struct zcl_command_request *request, struct zdev_improve_ctx *ctx,
    struct zcl_command_reply *reply)
{
    ctx->task.schema_version = VCS_ZCODE_DEV_VERSION;
    if (!zdev_improve_parse_policy(ctx, reply)) return false;
    if (!zdev_improve_build_source_root(request, ctx, reply)) return false;
    if (!zdev_improve_build_lock_recipe(request, ctx, reply)) return false;
    if (!zdev_root(request->input, "model_policy_root",
                   ctx->task.model_policy_root, reply))
        return false;
    if (!zdev_improve_build_write_scope(request, ctx, reply)) return false;
    memcpy(ctx->task.proof_policy_root, ctx->policy_root, 32);
    sha3_256((const uint8_t *)ctx->goal, strlen(ctx->goal),
             ctx->task.goal_root);
    if (!zdev_improve_capture_toolchain(ctx, reply)) return false;
    zdev_improve_apply_limits(request, ctx);
    ctx->now = (int64_t)platform_time_wall_unix();
    if (!zdev_improve_finalize_task(ctx, reply)) return false;
    return zdev_improve_check_expected_task_root(ctx, reply);
}

/* ── phase 3: coordinate against other tasks, then persist CAS objects ──── */

static bool zdev_improve_coordinate(
    struct zdev_improve_ctx *ctx, struct zcl_command_reply *reply)
{
    struct vcs_zcode_task_index *coordination_index =
        vcs_zcode_task_index_build(ctx->workspace, ctx->now);
    if (!coordination_index) {
        zdev_coordination_refuse(reply, ctx->workspace, NULL);
        return false;
    }
    struct vcs_zcode_task_conflict conflict;
    enum vcs_zcode_task_conflict_kind conflict_kind =
        vcs_zcode_task_index_conflict(
            coordination_index, ctx->workspace, &ctx->task, &conflict);
    vcs_zcode_task_index_free(coordination_index);
    if (conflict_kind != VCS_ZCODE_TASK_CONFLICT_CLEAR) {
        zdev_coordination_refuse(reply, ctx->workspace, &conflict);
        return false;
    }
    return true;
}

static bool zdev_improve_store_task_objects(
    struct zdev_improve_ctx *ctx, struct zcl_command_reply *reply)
{
    if (!vcs_object_store_init(ctx->workspace) ||
        !vcs_object_put_addressed(ctx->workspace, ctx->policy_root,
                                  ctx->policy_wire, sizeof(ctx->policy_wire)) ||
        !vcs_object_put_addressed(ctx->workspace, ctx->task.goal_root,
                                  (const uint8_t *)ctx->goal,
                                  strlen(ctx->goal)) ||
        !vcs_object_put_addressed(ctx->workspace, ctx->task_root,
                                  ctx->task_wire, sizeof(ctx->task_wire))) {
        zdev_fail(reply, "CAS_WRITE_FAILED",
                  "canonical task handoff could not be stored atomically");
        return false;
    }
    return true;
}

/* ── phase 4: capture the agent context for the planned/admitted task ───── */

static bool zdev_improve_agent_context(
    const struct zcl_command_request *request, struct zdev_improve_ctx *ctx,
    struct zcl_command_reply *reply)
{
    (void)request;
    if (ctx->context_symbol && ctx->context_symbol[0]) {
        struct zcl_result captured = zcode_agent_context_capture(
            ctx->workspace, &ctx->task, ctx->task_root, ctx->context_symbol,
            &ctx->agent_context);
        if (!captured.ok) {
            zdev_fail(reply, "AGENT_CONTEXT_FAILED", captured.message);
            return false;
        }
        ctx->agent_context_ready = true;
    }
    if (!ctx->explicit_admit) return true;
    uint8_t expected_context_root[32], actual_context_root[32];
    if (zcl_hex_decode_lower(ctx->planned_context_root,
                             expected_context_root, 32) &&
        zcl_hex_decode_lower(ctx->agent_context.context_root_sha3,
                             actual_context_root, 32) &&
        memcmp(expected_context_root, actual_context_root, 32) == 0)
        return true;
    zdev_fail(reply, "PLANNED_CONTEXT_MISMATCH",
              "current source context does not match planned_context_root");
    return false;
}

/* ── phase 5: render the plan-only response ─────────────────────────────── */

static void zdev_improve_render_plan(
    struct zcl_command_reply *reply, const struct zdev_improve_ctx *ctx)
{
    zdev_push_root(&reply->data, "task_root", ctx->task_root);
    zdev_push_root(&reply->data, "proof_policy_root", ctx->policy_root);
    zdev_push_root(&reply->data, "toolchain_capsule_root",
                   ctx->task.toolchain_capsule_root);
    zdev_push_root(&reply->data, "model_policy_root",
                   ctx->task.model_policy_root);
    zdev_push_root(&reply->data, "dependency_lock_root",
                   ctx->task.dependency_lock_root);
    zdev_push_root(&reply->data, "acceptance_tests_root",
                   ctx->task.acceptance_tests_root);
    zdev_push_root(&reply->data, "source_root", ctx->task.source_root);
    zdev_push_root(&reply->data, "write_scope_root",
                   ctx->task.write_scope_root);
    zdev_push_agent_context(&reply->data, &ctx->agent_context);
    (void)json_push_kv_str(&reply->data, "mode", "plan");
    (void)json_push_kv_str(&reply->data, "state", "AWAITING_CANDIDATE");
    (void)json_push_kv_str(&reply->data, "authority",
                           "TASK_CONTEXT_AND_SCOPE_ROOTS");
    (void)json_push_kv_str(
        &reply->data, "next",
        "give the immutable task, agent_context, and write_scope roots to the user-selected adapter, then call mode=admit with its candidate roots; no model or tool authority is implied");
}

/* ── phase 6: build and validate the candidate object ───────────────────── */

static void zdev_improve_init_candidate(
    const struct zcl_command_request *request, struct zdev_improve_ctx *ctx)
{
    ctx->candidate.schema_version = VCS_ZCODE_DEV_VERSION;
    ctx->candidate.sequence =
        (uint64_t)zdev_int(request->input, "candidate_sequence", 1);
    ctx->candidate.created_unix = zdev_int(
        request->input, "candidate_created_unix", ctx->now);
    memcpy(ctx->candidate.task_root, ctx->task_root, 32);
    memcpy(ctx->candidate.base_source_root, ctx->task.source_root, 32);
}

static bool zdev_improve_candidate_claim_matches(
    const struct zcl_command_request *request, struct zdev_improve_ctx *ctx)
{
    const char *claimed_patch = zdev_str(request->input, "patch_root");
    const char *claimed_source =
        zdev_str(request->input, "candidate_source_root");
    uint8_t claim[32];
    if (claimed_patch && claimed_patch[0] &&
        (!zcl_hex_decode_lower(claimed_patch, claim, 32) ||
         memcmp(claim, ctx->candidate.patch_root, 32) != 0))
        return false;
    if (claimed_source && claimed_source[0] &&
        (!zcl_hex_decode_lower(claimed_source, claim, 32) ||
         memcmp(claim, ctx->candidate.candidate_source_root, 32) != 0))
        return false;
    zcl_hex_encode(ctx->source_sha_check, 32, ctx->source_sha_hex);
    const char *claimed_sha =
        zdev_str(request->input, "candidate_source_sha256");
    return !(claimed_sha && claimed_sha[0] &&
             (!zcl_hex_decode_lower(claimed_sha, claim, 32) ||
              memcmp(claim, ctx->source_sha_check, 32) != 0));
}

static bool zdev_improve_candidate_roots_explicit(
    const struct zcl_command_request *request, struct zdev_improve_ctx *ctx,
    struct zcl_command_reply *reply)
{
    if (!zdev_capture_candidate(
            ctx->workspace, ctx->candidate_workspace, &ctx->task,
            ctx->candidate.candidate_source_root, ctx->candidate.patch_root,
            ctx->source_sha_check, &ctx->changed_files, &ctx->patch_bytes,
            reply))
        return false;
    if (!zdev_improve_candidate_claim_matches(request, ctx)) {
        zdev_fail(reply, "CANDIDATE_ROOT_MISMATCH",
                  "claimed candidate roots do not match the captured workspace");
        return false;
    }
    return true;
}

static bool zdev_improve_candidate_roots(
    const struct zcl_command_request *request, struct zdev_improve_ctx *ctx,
    struct zcl_command_reply *reply)
{
    if (ctx->explicit_admit)
        return zdev_improve_candidate_roots_explicit(request, ctx, reply);
    return zdev_root(request->input, "patch_root", ctx->candidate.patch_root,
                     reply) &&
        zdev_root(request->input, "candidate_source_root",
                  ctx->candidate.candidate_source_root, reply);
}

static bool zdev_improve_finalize_candidate(
    struct zdev_improve_ctx *ctx, struct zcl_command_reply *reply)
{
    if (vcs_zcode_candidate_validate_for_task(
            &ctx->task, &ctx->candidate, ctx->now) != VCS_ZCODE_DEV_OK ||
        vcs_zcode_candidate_serialize(&ctx->candidate, ctx->candidate_wire) !=
            VCS_ZCODE_DEV_OK ||
        vcs_zcode_candidate_root(&ctx->candidate, ctx->candidate_root) !=
            VCS_ZCODE_DEV_OK) {
        zdev_fail(reply, "CANDIDATE_INVALID",
                  "canonical candidate serialization failed");
        return false;
    }
    enum vcs_zcode_task_authority_result task_authority =
        vcs_zcode_task_authority_validate_for_candidate(
            ctx->workspace, &ctx->task, &ctx->candidate);
    if (task_authority != VCS_ZCODE_TASK_AUTHORITY_OK) {
        zdev_fail(reply, "CANDIDATE_RECIPE_REFUSED",
            vcs_zcode_task_authority_result_string(task_authority));
        return false;
    }
    return true;
}

static bool zdev_improve_build_candidate(
    const struct zcl_command_request *request, struct zdev_improve_ctx *ctx,
    struct zcl_command_reply *reply)
{
    zdev_improve_init_candidate(request, ctx);
    if (!zdev_improve_candidate_roots(request, ctx, reply)) return false;
    if (!zdev_root(request->input, "adapter_policy_root",
                   ctx->candidate.adapter_policy_root, reply) ||
        !zdev_root(request->input, "author_pubkey",
                   ctx->candidate.author_pubkey, reply))
        return false;
    return zdev_improve_finalize_candidate(ctx, reply);
}

/* ── phase 7: derive, verify, and store the fixed action input ──────────── */

static enum vcs_zcode_action_input_result zdev_improve_derive_package_input(
    struct zdev_improve_ctx *ctx)
{
    struct vcs_zcode_package_action_input_v1 package_input;
    enum vcs_zcode_action_input_result input_result =
        vcs_zcode_package_action_input_derive(
            ctx->workspace, ctx->task_root, ctx->candidate_root, &ctx->task,
            &ctx->candidate, &package_input);
    ctx->input_len = VCS_ZCODE_PACKAGE_ACTION_INPUT_WIRE_BYTES;
    ctx->input_wire = zcl_malloc(ctx->input_len, "zcode.package_action_input");
    if (input_result == VCS_ZCODE_ACTION_INPUT_OK && !ctx->input_wire)
        input_result = VCS_ZCODE_ACTION_INPUT_ALLOC;
    if (input_result == VCS_ZCODE_ACTION_INPUT_OK)
        input_result = vcs_zcode_package_action_input_serialize(
            &package_input, ctx->input_wire);
    if (input_result == VCS_ZCODE_ACTION_INPUT_OK)
        input_result = vcs_zcode_package_action_input_root(
            &package_input, ctx->input_root);
    ctx->input_schema = "zcl.zcode.package_action_input.v1";
    return input_result;
}

/* Precondition: ctx->input_path is already resolved (see
 * zdev_improve_derive_input, which resolves it before branching here so a
 * bad path fails closed without touching input_result at all). */
static enum vcs_zcode_action_input_result zdev_improve_derive_normal_input(
    struct zdev_improve_ctx *ctx)
{
    struct vcs_zcode_action_input_v1 bound_input;
    enum vcs_zcode_action_input_result input_result =
        vcs_zcode_action_input_derive_cas(
            ctx->workspace, ctx->task_root, ctx->candidate_root, &ctx->task,
            &ctx->candidate, ctx->work_kind, ctx->input_path, &bound_input);
    if (input_result == VCS_ZCODE_ACTION_INPUT_OK)
        input_result = vcs_zcode_action_input_serialize(
            &bound_input, &ctx->input_wire, &ctx->input_len);
    if (input_result == VCS_ZCODE_ACTION_INPUT_OK)
        input_result = vcs_zcode_action_input_root(
            &bound_input, ctx->input_root);
    vcs_zcode_action_input_free(&bound_input);
    ctx->input_schema = "zcl.zcode.action_input.v1";
    return input_result;
}

static bool zdev_improve_candidate_stable(const struct zdev_improve_ctx *ctx)
{
    if (!ctx->explicit_admit) return true;
    uint8_t candidate_current[32];
    return vcs_tree_capture_into(ctx->candidate_workspace, ctx->workspace,
                                 candidate_current) == VCS_OK &&
        memcmp(candidate_current, ctx->candidate.candidate_source_root,
               32) == 0;
}

static bool zdev_improve_derive_input(
    const struct zcl_command_request *request, struct zdev_improve_ctx *ctx,
    struct zcl_command_reply *reply)
{
    (void)request;
    if (!ctx->package_action &&
        !zdev_candidate_input_path(
            ctx->candidate_workspace, ctx->fixed_input,
            ctx->fixed_input_relpath, ctx->input_path, reply))
        return false;
    enum vcs_zcode_action_input_result input_result = ctx->package_action
        ? zdev_improve_derive_package_input(ctx)
        : zdev_improve_derive_normal_input(ctx);
    if (input_result == VCS_ZCODE_ACTION_INPUT_OK &&
        ctx->input_len > ctx->task.max_context_bytes)
        input_result = VCS_ZCODE_ACTION_INPUT_LIMIT;
    bool stable = zdev_improve_candidate_stable(ctx);
    if (input_result == VCS_ZCODE_ACTION_INPUT_OK && stable) return true;
    free(ctx->input_wire);
    zdev_fail(reply,
              stable ? "CANDIDATE_INPUT_REFUSED" : "CANDIDATE_SOURCE_STALE",
              stable
                ? vcs_zcode_action_input_result_string(input_result)
                : "candidate workspace changed during action input capture");
    return false;
}

static bool zdev_improve_store_input(
    struct zdev_improve_ctx *ctx, struct zcl_command_reply *reply)
{
    bool stored = vcs_object_put_addressed(
            ctx->workspace, ctx->input_root, ctx->input_wire, ctx->input_len) &&
        vcs_object_put_addressed(ctx->workspace, ctx->candidate_root,
                                 ctx->candidate_wire,
                                 sizeof(ctx->candidate_wire));
    free(ctx->input_wire);
    if (!stored) {
        zdev_fail(reply, "CAS_WRITE_FAILED",
                  "canonical task inputs could not be stored atomically");
        return false;
    }
    return true;
}

/* ── phase 8: resolve the caller/derived candidate source sha256 ────────── */

static bool zdev_improve_resolve_source_sha(
    const struct zcl_command_request *request, struct zdev_improve_ctx *ctx,
    struct zcl_command_reply *reply)
{
    if (ctx->explicit_admit) {
        ctx->source_sha256 = ctx->source_sha_hex;
        return true;
    }
    ctx->source_sha256 = zdev_str(request->input, "candidate_source_sha256");
    char source_sha_err[128];
    if (!zcl_native_require_hex64(
            "candidate_source_sha256", ctx->source_sha256,
            ctx->source_sha_check, source_sha_err, sizeof(source_sha_err))) {
        zdev_fail(reply, "BAD_SOURCE_SHA256", source_sha_err);
        return false;
    }
    return true;
}

/* ── phase 9: build the fixed job/action ledger records ─────────────────── */

static bool zdev_improve_check_remote_peer(
    const struct zcl_command_request *request, struct zdev_improve_ctx *ctx,
    struct zcl_command_reply *reply)
{
    ctx->remote_peer = zdev_int(request->input, "remote_peer", 0);
    if (ctx->remote_peer < 0) {
        zdev_fail(reply, "BAD_REMOTE_PEER",
                  "remote_peer must be zero for discovery or a positive peer hint");
        return false;
    }
    return true;
}

static void zdev_improve_fill_job(
    const struct zcl_command_request *request, struct zdev_improve_ctx *ctx)
{
    memset(&ctx->job, 0, sizeof(ctx->job));
    (void)snprintf(ctx->job.source_sha256, sizeof(ctx->job.source_sha256),
                   "%s", ctx->source_sha256);
    zcl_hex_encode(ctx->candidate.candidate_source_root, 32,
                   ctx->job.source_cas_sha3);
    zcl_hex_encode(ctx->task.toolchain_capsule_root, 32,
                   ctx->job.toolchain_sha3);
    const char *profile = zdev_str(request->input, "profile");
    (void)snprintf(ctx->job.profile, sizeof(ctx->job.profile), "%s",
                   profile && profile[0] ? profile : "dev");
    (void)snprintf(ctx->job.state, sizeof(ctx->job.state), "PLANNED");
    ctx->job.created_at = ctx->job.updated_at = ctx->now;
}

static void zdev_improve_fill_action_core(struct zdev_improve_ctx *ctx)
{
    memset(&ctx->action, 0, sizeof(ctx->action));
    ctx->action.sequence = 0;
    (void)snprintf(ctx->action.kind, sizeof(ctx->action.kind), "%s",
                   ctx->action_kind);
    (void)snprintf(ctx->action.state, sizeof(ctx->action.state),
                   "SNAPSHOTTED");
    zcl_hex_encode(ctx->input_root, 32, ctx->action.input_root_sha3);
    zcl_hex_encode(ctx->task_root, 32, ctx->action.task_root_sha3);
    zcl_hex_encode(ctx->candidate_root, 32, ctx->action.candidate_root_sha3);
    zcl_hex_encode(ctx->policy_root, 32, ctx->action.proof_policy_root_sha3);
    (void)snprintf(ctx->action.target, sizeof(ctx->action.target), "%s",
                   VCS_BUILD_TARGET_V1);
    ctx->action.created_at = ctx->action.updated_at = ctx->now;
}

static bool zdev_improve_fill_action_descriptors(
    struct zdev_improve_ctx *ctx, struct zcl_command_reply *reply)
{
    uint8_t fixed_flags[32], fixed_environment[32];
    const char *workdir = NULL, *output = NULL, *resource = NULL;
    if (!vcs_build_action_v1_descriptors(
            ctx->action_kind, &workdir, &output, &resource) ||
        !vcs_build_action_v1_fixed_flags_root_for_kind(
            ctx->action_kind, fixed_flags) ||
        !vcs_build_action_v1_fixed_environment_root_for_kind(
            ctx->action_kind, fixed_environment)) {
        zdev_fail(reply, "ACTION_DESCRIPTOR_FAILED",
                  "fixed action descriptor is unavailable");
        return false;
    }
    zcl_hex_encode(fixed_flags, 32, ctx->action.flags_sha3);
    zcl_hex_encode(fixed_environment, 32, ctx->action.environment_sha3);
    (void)snprintf(ctx->action.virtual_workdir,
                   sizeof(ctx->action.virtual_workdir), "%s", workdir);
    (void)snprintf(ctx->action.declared_outputs,
                   sizeof(ctx->action.declared_outputs), "%s", output);
    (void)snprintf(ctx->action.resource_policy,
                   sizeof(ctx->action.resource_policy), "%s", resource);
    return true;
}

static bool zdev_improve_assign_ids(
    struct zdev_improve_ctx *ctx, struct zcl_command_reply *reply)
{
    if (!build_fabric_action_id(&ctx->job, &ctx->action,
                                ctx->action.action_id).ok ||
        !build_fabric_job_id(&ctx->job, ctx->action.action_id,
                             ctx->job.job_id).ok) {
        zdev_fail(reply, "ACTION_ID_FAILED",
                  "fixed build action identity refused");
        return false;
    }
    ctx->request_creation_us =
        platform_time_monotonic_us() - ctx->submit_started_us;
    (void)snprintf(ctx->action.job_id, sizeof(ctx->action.job_id), "%s",
                   ctx->job.job_id);
    return true;
}

static bool zdev_improve_build_job_action(
    const struct zcl_command_request *request, struct zdev_improve_ctx *ctx,
    struct zcl_command_reply *reply)
{
    if (!zdev_improve_check_remote_peer(request, ctx, reply)) return false;
    zdev_improve_fill_job(request, ctx);
    zdev_improve_fill_action_core(ctx);
    if (!zdev_improve_fill_action_descriptors(ctx, reply)) return false;
    return zdev_improve_assign_ids(ctx, reply);
}

/* ── phase 10: plan, admit the frontier lane, submit, and request proof ─── */

static bool zdev_improve_open_ledger(
    struct zdev_improve_ctx *ctx, struct zcl_command_reply *reply)
{
    ctx->ledger_started_us = platform_time_monotonic_us();
    char db_path[ZDEV_PATH_MAX];
    int dbn = snprintf(db_path, sizeof(db_path), "%s/node.db", ctx->datadir);
    ctx->ndb = zdev_runtime_owns_ledger(ctx->datadir)
        ? app_runtime_node_db() : &ctx->local_ndb;
    ctx->owned = ctx->ndb != &ctx->local_ndb;
    if (dbn <= 0 || (size_t)dbn >= sizeof(db_path) ||
        (!ctx->owned && !zdev_open_build_ledger(
            ctx->ndb, db_path, "zcode.improve"))) {
        zdev_fail(reply, "DATABASE_OPEN_FAILED",
                  "cannot open the task's ZBuild ledger");
        return false;
    }
    return true;
}

/* Plan the fixed action (and its reproduction sibling if the policy
 * requires two independent receipts) and admit it onto the frontier lane. */
static void zdev_improve_plan_and_admit(struct zdev_improve_ctx *ctx)
{
    ctx->planned = build_fabric_plan(ctx->ndb, &ctx->job, &ctx->action);
    ctx->reproduction_needed = ctx->owned && ctx->package_action &&
        (ctx->policy.minimum_compile_receipts >= 2u ||
         ctx->policy.minimum_test_receipts >= 2u);
    ctx->reproduction_action_id[0] = '\0';
    ctx->reproduction_job_id[0] = '\0';
    ctx->reproduction_planned = ctx->planned;
    if (ctx->planned.ok && ctx->reproduction_needed)
        ctx->reproduction_planned = build_fabric_plan_reproduction(
            ctx->ndb, ctx->action.action_id,
            VCS_BUILD_PACKAGE_PROFILE_STANDARD_B_V1, ctx->now,
            ctx->reproduction_action_id, ctx->reproduction_job_id);
    memset(&ctx->frontier_status, 0, sizeof(ctx->frontier_status));
    struct db_build_worker frontier_signer;
    uint8_t frontier_secret[32] = {0}, frontier_pubkey[32] = {0};
    ctx->admitted = ctx->reproduction_planned;
    if (ctx->reproduction_planned.ok) {
        ctx->admitted = build_fabric_worker_identity_load(
            ctx->datadir, &frontier_signer, frontier_secret, frontier_pubkey);
        if (ctx->admitted.ok)
            ctx->admitted = zcode_lane_advance(
                ctx->ndb, ctx->workspace, ctx->action.action_id,
                VCS_ZCODE_LANE_FRONTIER, ctx->now, frontier_secret,
                frontier_pubkey, &ctx->frontier_status);
    }
    memset(frontier_secret, 0, sizeof(frontier_secret));
}

/* Submit the admitted action (runtime-owned ledgers stay SNAPSHOTTED for
 * peer proof; see the comment below) and request async proof for it, and
 * for its reproduction sibling when one was planned. */
static void zdev_improve_submit_and_request_proof(struct zdev_improve_ctx *ctx)
{
    /* The runtime-owned action is immutable input for peer proof, not local
     * worker work. Keeping its canonical state SNAPSHOTTED prevents the
     * requester daemon from racing the selected peer and masking missing
     * remote evidence. Offline fixture ledgers retain explicit QUEUED
     * behavior for the local build-fabric interface. */
    ctx->submitted = ctx->admitted.ok && ctx->owned
        ? ZCL_OK : ctx->admitted.ok
            ? build_fabric_submit(ctx->ndb, ctx->job.job_id, ctx->now)
            : ctx->admitted;
    memset(&ctx->proof_request, 0, sizeof(ctx->proof_request));
    ctx->proof_request_created = false;
    int64_t request_elapsed_us =
        platform_time_monotonic_us() - ctx->submit_started_us;
    ctx->proof_requested = ctx->submitted.ok
        ? build_fabric_proof_request(
              ctx->ndb, ctx->action.action_id, ctx->workspace,
              (uint64_t)ctx->remote_peer,
              request_elapsed_us < 0 ? 0 : request_elapsed_us, ctx->now,
              &ctx->proof_request, &ctx->proof_request_created)
        : ctx->submitted;
    memset(&ctx->reproduction_request, 0, sizeof(ctx->reproduction_request));
    ctx->reproduction_request_created = false;
    ctx->reproduction_requested = ctx->proof_requested;
    if (ctx->proof_requested.ok && ctx->reproduction_needed)
        ctx->reproduction_requested = build_fabric_proof_request(
            ctx->ndb, ctx->reproduction_action_id, ctx->workspace, 0,
            request_elapsed_us < 0 ? 0 : request_elapsed_us, ctx->now,
            &ctx->reproduction_request, &ctx->reproduction_request_created);
}

static void zdev_improve_run_ledger_ops(struct zdev_improve_ctx *ctx)
{
    zdev_improve_plan_and_admit(ctx);
    zdev_improve_submit_and_request_proof(ctx);
    ctx->local_submit_us =
        platform_time_monotonic_us() - ctx->submit_started_us;
    ctx->ledger_us = platform_time_monotonic_us() - ctx->ledger_started_us;
    if (!ctx->owned) node_db_close(ctx->ndb);
}

/* Named ledger-op result/error-code pairs, tried in the exact original
 * priority order so the first stage that failed names the error. */
static bool zdev_improve_map_ledger_error(
    const struct zdev_improve_ctx *ctx, struct zcl_command_reply *reply)
{
    struct { const struct zcl_result *result; const char *code; } stages[] = {
        { &ctx->planned, "ZBUILD_PLAN_FAILED" },
        { &ctx->reproduction_planned, "REPRODUCTION_PLAN_FAILED" },
        { &ctx->admitted, "FRONTIER_ADMISSION_FAILED" },
        { &ctx->submitted, "ZBUILD_SUBMIT_FAILED" },
        { &ctx->proof_requested, "ASYNC_PROOF_REQUEST_FAILED" },
        { &ctx->reproduction_requested, "REPRODUCTION_REQUEST_FAILED" },
    };
    for (size_t i = 0; i < sizeof(stages) / sizeof(stages[0]); i++) {
        if (stages[i].result->ok) continue;
        zdev_fail(reply, stages[i].code, stages[i].result->message);
        return false;
    }
    return true;
}

static void zdev_improve_log_perf(const struct zdev_improve_ctx *ctx)
{
    LOG_INFO("zcode.proof_perf",
             "schema=zcl.async_proof_perf.v1 action=%s "
             "stage=foreground_return at_unix_us=%lld "
             "request_creation_us=%lld durable_lookup_dedup_us=%lld "
             "local_submit_us=%lld dedup_hit=%d",
             ctx->action.action_id, (long long)platform_time_realtime_us(),
             (long long)(ctx->request_creation_us < 0
                             ? 0 : ctx->request_creation_us),
             (long long)(ctx->ledger_us < 0 ? 0 : ctx->ledger_us),
             (long long)(ctx->local_submit_us < 0 ? 0 : ctx->local_submit_us),
             ctx->proof_request_created ? 0 : 1);
}

static bool zdev_improve_submit(
    struct zdev_improve_ctx *ctx, struct zcl_command_reply *reply)
{
    if (!zdev_improve_open_ledger(ctx, reply)) return false;
    zdev_improve_run_ledger_ops(ctx);
    if (!zdev_improve_map_ledger_error(ctx, reply)) return false;
    zdev_improve_log_perf(ctx);
    return true;
}

/* ── phase 11: render the admit response ────────────────────────────────── */

static void zdev_improve_render_reproduction(
    struct zcl_command_reply *reply, const struct zdev_improve_ctx *ctx)
{
    (void)json_push_kv_str(&reply->data, "reproduction_action_id",
                           ctx->reproduction_action_id);
    (void)json_push_kv_str(&reply->data, "reproduction_job_id",
                           ctx->reproduction_job_id);
    (void)json_push_kv_str(
        &reply->data, "reproduction_async_proof_event_root",
        ctx->reproduction_request.event_root);
    (void)json_push_kv_int(
        &reply->data, "reproduction_remote_request_id",
        (int64_t)ctx->reproduction_request.request_id);
    (void)json_push_kv_bool(
        &reply->data, "reproduction_request_deduplicated",
        !ctx->reproduction_request_created);
}

static void zdev_improve_render_admit(
    struct zcl_command_reply *reply, const struct zdev_improve_ctx *ctx)
{
    zdev_push_root(&reply->data, "task_root", ctx->task_root);
    zdev_push_root(&reply->data, "candidate_root", ctx->candidate_root);
    zdev_push_root(&reply->data, "candidate_source_root",
                   ctx->candidate.candidate_source_root);
    zdev_push_root(&reply->data, "patch_root", ctx->candidate.patch_root);
    zdev_push_root(&reply->data, "proof_policy_root", ctx->policy_root);
    zdev_push_root(&reply->data, "toolchain_capsule_root",
                   ctx->task.toolchain_capsule_root);
    zdev_push_root(&reply->data, "input_root", ctx->input_root);
    if (!ctx->package_action)
        (void)json_push_kv_str(&reply->data, "fixed_input_relpath",
                               ctx->input_path);
    (void)json_push_kv_str(&reply->data, "input_schema", ctx->input_schema);
    (void)json_push_kv_str(&reply->data, "job_id", ctx->job.job_id);
    (void)json_push_kv_str(&reply->data, "action_id", ctx->action.action_id);
    (void)json_push_kv_str(&reply->data, "action_kind", ctx->action_kind);
    (void)json_push_kv_int(&reply->data, "candidate_created_unix",
                           ctx->candidate.created_unix);
    (void)json_push_kv_str(&reply->data, "candidate_source_sha256",
                           ctx->source_sha256);
    (void)json_push_kv_str(&reply->data, "source_sha256_schema",
                           ctx->explicit_admit
                             ? VCS_SOURCE_MANIFEST_ID_SCHEMA
                             : "caller-provided-legacy");
    if (ctx->explicit_admit) {
        (void)json_push_kv_int(&reply->data, "changed_files",
                               ctx->changed_files);
        (void)json_push_kv_int(&reply->data, "patch_content_bytes",
                               (int64_t)ctx->patch_bytes);
    }
    (void)json_push_kv_str(&reply->data, "state",
                           ctx->owned ? "SNAPSHOTTED" : "QUEUED");
    (void)json_push_kv_str(&reply->data, "lane", ctx->frontier_status.lane_name);
    (void)json_push_kv_str(&reply->data, "lane_receipt_root",
                           ctx->frontier_status.receipt_root_sha3);
    if (ctx->agent_context_ready)
        zdev_push_agent_context(&reply->data, &ctx->agent_context);
    (void)json_push_kv_str(&reply->data, "mode", "admit");
    (void)json_push_kv_str(&reply->data, "async_proof_state",
                           ctx->proof_request.state);
    (void)json_push_kv_str(&reply->data, "async_proof_event_root",
                           ctx->proof_request.event_root);
    (void)json_push_kv_int(&reply->data, "remote_request_id",
                           (int64_t)ctx->proof_request.request_id);
    (void)json_push_kv_bool(&reply->data, "request_deduplicated",
                            !ctx->proof_request_created);
    if (ctx->reproduction_needed)
        zdev_improve_render_reproduction(reply, ctx);
    (void)json_push_kv_int(&reply->data, "foreground_request_creation_us",
                           ctx->request_creation_us < 0
                               ? 0 : ctx->request_creation_us);
    (void)json_push_kv_int(&reply->data, "durable_action_lookup_dedup_us",
                           ctx->ledger_us < 0 ? 0 : ctx->ledger_us);
    (void)json_push_kv_int(&reply->data, "local_submit_us",
                           ctx->local_submit_us < 0 ? 0 : ctx->local_submit_us);
    (void)json_push_kv_int(&reply->data, "local_first_feedback_us",
                           ctx->local_submit_us < 0 ? 0 : ctx->local_submit_us);
    (void)json_push_kv_str(&reply->data, "remote_outcome",
                           "BACKGROUND_PENDING");
    (void)json_push_kv_str(
        &reply->data, "next",
        "an enabled local or P2P worker may produce the candidate-bound fixed-action receipt; evidence evaluation, explicit acceptance, and publication remain required");
}

// long-function-ok:one-task-admission — canonical objects, CAS writes, and
// the ZBuild ledger commit form one fail-closed local admission transaction;
// no candidate or proof is claimed by this planning command.
void zcl_native_handle_zcode_improve(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!request || !reply) return;
    struct zdev_improve_ctx ctx = {0};
    ctx.submit_started_us = platform_time_monotonic_us();
    if (!zdev_improve_parse_request(request, reply, &ctx)) return;
    if (!zdev_improve_build_task(request, &ctx, reply)) return;
    if (!zdev_improve_coordinate(&ctx, reply)) return;
    if (!zdev_improve_store_task_objects(&ctx, reply)) return;
    if (!zdev_improve_agent_context(request, &ctx, reply)) return;
    if (ctx.plan_only) {
        zdev_improve_render_plan(reply, &ctx);
        return;
    }
    if (!zdev_improve_build_candidate(request, &ctx, reply)) return;
    if (!zdev_improve_derive_input(request, &ctx, reply)) return;
    if (!zdev_improve_store_input(&ctx, reply)) return;
    if (!zdev_improve_resolve_source_sha(request, &ctx, reply)) return;
    if (!zdev_improve_build_job_action(request, &ctx, reply)) return;
    if (!zdev_improve_submit(&ctx, reply)) return;
    zdev_improve_render_admit(reply, &ctx);
}
