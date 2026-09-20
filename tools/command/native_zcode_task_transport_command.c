/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Native handlers for the three `zcode task` transport leaves — how a
 * posted dev task MOVES between nodes so a stranger can pick it up:
 *
 *   zcode task offer   load one task's wires from the workspace CAS
 *                      (task wire, goal preimage, proof policy — each
 *                      re-hashed against its own address), bind them into
 *                      the fixed-layout task-context carrier, admit it to
 *                      the package store, and hand back the two
 *                      ready-to-run `zcode network publish` inputs that
 *                      make the PROBLEM discoverable
 *   zcode task pull    given a task root, resolve every task POINTER for
 *                      it, fetch each distinct context over the frozen
 *                      swarm codec, and re-verify each context against
 *                      exactly that root — returning the goal and proof
 *                      policy a remote agent needs to start work
 *   zcode task board   list what THIS node has seen posted in the task
 *                      namespace (local record-store projection, never a
 *                      peer query), enriching every row whose context is
 *                      already held and verified
 *
 * A task object is unsigned by design: it is a content-addressed
 * constraint set, not an identity claim. Record signatures identify the
 * publishing key; receiver verification binds the task bytes, and local
 * sovereignty policy decides visibility. AGENT_SCOPE remains dormant. The
 * carrier contributes the part a stranger
 * cannot re-derive from the task wire alone — the goal preimage and the
 * proof policy bytes — cross-bound so sha3(goal.bin) equals
 * task.goal_root and the policy wire roots to task.proof_policy_root.
 *
 * NO NEW WIRE MESSAGE EXISTS HERE AND NONE MAY BE ADDED. The context
 * rides the already-frozen 'zpkgswm' codec like any other package,
 * fetched by `zcode package fetch`. Discovery is two ordinary signed
 * records, and both are required (see zcode work offer for why either
 * record alone is a silent no-op at pull time); `offer` returns BOTH
 * inputs, provider first.
 *
 * THE ONE SECURITY PROPERTY ON THE PULL PATH is the receiver-side binding
 * check: every admit here passes the caller's task_root as
 * expect_task_root, never NULL. vcs_zcode_task_context_admit re-derives
 * the context from stored bytes and refuses unless the task the context
 * ITSELF proves equals the root the reader asked about — including a
 * liveness check, so an expired posting drops off every board that
 * re-verifies it. The publish-side gate is local hygiene and constrains
 * nobody else.
 *
 * PULLING IS NOT EXECUTING. A verified row means "this context provably
 * posts this task, this node holds the bytes, and here is the goal" —
 * nothing more. Doing the work is the ordinary local journey (zcode work
 * run against the task's roots); offering its result is zcode work offer.
 *
 * A row that fails stays in the report naming its rule. One bad pointer
 * never aborts the sweep — the other postings still land.
 *
 * This lives in its own translation unit rather than in
 * native_zcode_work_command.c so the posting half of the task surface has
 * one file beside its solution half. Bound by engine/composition/commands/zcode.def.
 */

#include "base/hex.h"
#include "base/log_macros.h"
#include "base/safe_alloc.h"
#include "command/native_command.h"
#include "command/native_zcode_transport_leaves.h"
#include "platform/directory_compat.h"

#include "json/json.h"
#include "platform/time_compat.h"
#include "sha3/sha3.h"
#include "vcs/package_store.h"
#include "vcs/package_content.h"
#include "vcs/source_package_checkout.h"
#include "vcs/vcs_object.h"
#include "vcs/zcode_dht_record.h"
#include "vcs/zcode_task_context.h"
#include "vcs/zcode_task_authority_bundle.h"
#include "vcs/zcode_write_scope.h"
#include "vcs/zcode_task_index.h"
#include "vcs/zcode_agent_context.h"
#include "vcs/vcs.h"
#include "services/zcode_agent_context_service.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Row cap for a pull report, the work lane's numbers: a namespace with
 * more live postings than this is a good problem; the reply says so
 * rather than truncating silently. */
#define ZTT_ROWS_DEFAULT 16u
#define ZTT_ROWS_CEILING 64u

/* Validity windows stamped into each ready-to-run publish input — same
 * per-kind derivation and reasoning as the work lane (a provider ad is a
 * short-lived claim about reachability right now; a pointer is a claim
 * about content that stays true). */
#define ZTT_PROVIDER_WINDOW_S VCS_ZCODE_DHT_PROVIDER_MAX_SECONDS
#define ZTT_POINTER_WINDOW_S UINT64_C(86400)

/* Fail the BUILD if either ceiling moves under us: an unpublishable input
 * handed out as "ready to run" is a defect that only shows up at the far
 * end of a two-command sequence. */
static_assert(ZTT_PROVIDER_WINDOW_S <= VCS_ZCODE_DHT_PROVIDER_MAX_SECONDS,
              "the provider publish input must be publishable as a PROVIDER "
              "record; an over-long window is refused and leaves the "
              "operator pointer-only");
static_assert(ZTT_POINTER_WINDOW_S <= VCS_ZCODE_DHT_POINTER_MAX_SECONDS,
              "the pointer publish input must be publishable as a POINTER "
              "record");

/* ── workspace CAS loads (address agreement is the caller's job here:
 * vcs_object_load_raw deliberately does not re-hash) ─────────────────── */

static uint8_t *ztt_load_object(const char *zcode_dir, const uint8_t root[32],
                                size_t max, size_t *len_out)
{
    *len_out = 0;
    uint8_t *bytes = NULL;
    size_t len = 0;
    if (vcs_object_load_raw_bounded(zcode_dir, root, max, &bytes, &len) != 0)
        return NULL;
    *len_out = len;
    return bytes;
}

/* The three wires one task needs, every one re-derived against its own
 * CAS address before the carrier will bind them. */
static bool ztt_load_context_wires(const char *zcode_dir,
                                   const uint8_t task_root[32],
                                   uint8_t **task_wire, size_t *task_len,
                                   uint8_t **goal, size_t *goal_len,
                                   uint8_t **policy_wire, size_t *policy_len,
                                   struct vcs_zcode_task_v1 *task_out)
{
    *task_wire = *goal = *policy_wire = NULL;
    *task_len = *goal_len = *policy_len = 0;
    uint8_t *tw = ztt_load_object(zcode_dir, task_root,
                                  VCS_ZCODE_TASK_WIRE_BYTES, task_len);
    struct vcs_zcode_task_v1 task;
    uint8_t derived[32];
    if (!tw ||
        vcs_zcode_task_parse(tw, *task_len, &task) != VCS_ZCODE_DEV_OK ||
        vcs_zcode_task_root(&task, derived) != VCS_ZCODE_DEV_OK ||
        memcmp(derived, task_root, 32) != 0) {
        free(tw);
        return false;
    }
    uint8_t *gl = ztt_load_object(zcode_dir, task.goal_root,
                                  VCS_ZCODE_TASK_CONTEXT_GOAL_MAX, goal_len);
    uint8_t check[32];
    if (!gl || *goal_len == 0 || memchr(gl, '\0', *goal_len)) {
        free(tw);
        free(gl);
        return false;
    }
    sha3_256(gl, *goal_len, check);
    if (memcmp(check, task.goal_root, 32) != 0) {
        free(tw);
        free(gl);
        return false;
    }
    uint8_t *pw = ztt_load_object(zcode_dir, task.proof_policy_root,
                                  VCS_ZCODE_PROOF_POLICY_WIRE_BYTES,
                                  policy_len);
    struct vcs_zcode_proof_policy_v1 policy;
    if (!pw ||
        vcs_zcode_proof_policy_parse(pw, *policy_len, &policy) !=
            VCS_ZCODE_DEV_OK ||
        vcs_zcode_proof_policy_root(&policy, derived) != VCS_ZCODE_DEV_OK ||
        memcmp(derived, task.proof_policy_root, 32) != 0) {
        free(tw);
        free(gl);
        free(pw);
        return false;
    }
    *task_wire = tw;
    *goal = gl;
    *policy_wire = pw;
    if (task_out)
        *task_out = task;
    return true;
}

/* ── zcode task offer ───────────────────────────────────────────────── */

static bool ztt_offer_workspace(const struct zcl_command_request *request,
                                struct zcl_command_reply *reply,
                                char out[4400])
{
    const struct json_value *value = json_get(request->input, "workspace");
    if (value && value->type != JSON_STR) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "BAD_WORKSPACE",
                               "normalize", false, false,
                               "workspace must be a directory path string",
                               "input.workspace");
        return false;
    }
    const char *workspace = ztl_input_str(request->input, "workspace");
    if (!workspace)
        return ztl_zcode_dir(request, reply, "zcode.task.offer", out);
    if (workspace[0] && platform_directory_canonical_real(workspace, out, 4400))
        return true;
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                           ZCL_COMMAND_EXIT_INVALID, "WORKSPACE_UNAVAILABLE",
                           "normalize", false, false,
                           "workspace must name an existing readable directory",
                           workspace);
    return false;
}

/* Additional task inputs use ordinary content.v2 members. The existing
 * three-member task context retains its identity and validation contract.
 * This carrier contains metadata, not the source/dependency closure or an
 * execution grant. Receivers must independently verify all task bindings. */
static bool ztt_offer_adoption_inputs(const char *workspace,
    const struct vcs_zcode_task_v1 *task, struct vcs_package_store *store,
    uint8_t root[32], const char **reason)
{
    static const char scope_path[] = "zcode-write-scope.v1";
    uint8_t *scope_wire = NULL, *authority_wire = NULL, *manifest_wire = NULL;
    size_t scope_len = 0, authority_len = 0, manifest_len = 0;
    struct vcs_zcode_write_scope_v1 scope;
    uint8_t scope_root[32], stored_root[32];
    struct vcs_package_manifest manifest;
    vcs_package_manifest_init(&manifest);
    *reason = "scope_unavailable_or_invalid";
    bool ok = vcs_object_load_raw_bounded(workspace, task->write_scope_root,
        VCS_ZCODE_WRITE_SCOPE_WIRE_MAX, &scope_wire, &scope_len) == 0 &&
        vcs_zcode_write_scope_parse(scope_wire, scope_len, &scope) ==
            VCS_ZCODE_WRITE_SCOPE_OK &&
        vcs_zcode_write_scope_root(&scope, scope_root) ==
            VCS_ZCODE_WRITE_SCOPE_OK &&
        memcmp(scope_root, task->write_scope_root, 32) == 0;
    if (ok) {
        *reason = "authority_unavailable_or_invalid";
        ok = vcs_zcode_task_authority_validate(workspace, task) ==
            VCS_ZCODE_TASK_AUTHORITY_OK &&
        vcs_zcode_task_authority_bundle_export(workspace, task,
            &authority_wire, &authority_len) == VCS_ZCODE_TASK_AUTHORITY_OK;
    }
    if (ok) {
        *reason = "carrier_encoding_failed";
        ok = vcs_package_content_add_file(&manifest, scope_path,
                VCS_PACKAGE_MODE_FILE, scope_wire, scope_len) &&
            vcs_package_content_add_file(&manifest,
                VCS_ZCODE_TASK_AUTHORITY_BUNDLE_PATH, VCS_PACKAGE_MODE_FILE,
                authority_wire, authority_len) &&
            vcs_package_manifest_serialize(&manifest, &manifest_wire,
                &manifest_len) && vcs_package_manifest_root(&manifest, root);
    }
    if (ok) {
        *reason = "carrier_storage_failed";
        ok = vcs_package_store_put_manifest(store, manifest_wire,
                manifest_len, stored_root) == VCS_PACKAGE_STORE_OK &&
            memcmp(root, stored_root, 32) == 0 &&
            vcs_package_content_put_file(store, root, scope_path,
                scope_wire, scope_len) == VCS_PACKAGE_STORE_OK &&
            vcs_package_content_put_file(store, root,
                VCS_ZCODE_TASK_AUTHORITY_BUNDLE_PATH, authority_wire,
                authority_len) == VCS_PACKAGE_STORE_OK;
    }
    free(scope_wire);
    free(authority_wire);
    free(manifest_wire);
    vcs_package_manifest_free(&manifest);
    if (!ok)
        LOG_FAIL("zcode.task.offer", "adoption metadata unavailable: %s",
                 *reason);
    *reason = "available";
    return ok;
}

struct ztt_adoption_wires {
    uint8_t *scope;
    size_t scope_len;
    uint8_t *authority;
    size_t authority_len;
};

static bool ztt_adopt_input_file(struct vcs_package_store *store,
    const uint8_t root[32], const struct vcs_package_manifest *manifest,
    uint32_t i, struct ztt_adoption_wires *wires)
{
    if (strcmp(manifest->files[i].path, "zcode-write-scope.v1") == 0 &&
        !wires->scope && manifest->files[i].size <= VCS_ZCODE_WRITE_SCOPE_WIRE_MAX)
        return vcs_package_content_get_file_at(store, root, manifest, i,
            &wires->scope, &wires->scope_len) == VCS_PACKAGE_STORE_OK;
    if (strcmp(manifest->files[i].path, VCS_ZCODE_TASK_AUTHORITY_BUNDLE_PATH) == 0 &&
        !wires->authority && manifest->files[i].size <= UINT64_C(1048576))
        return vcs_package_content_get_file_at(store, root, manifest, i,
            &wires->authority, &wires->authority_len) == VCS_PACKAGE_STORE_OK;
    LOG_FAIL("zcode.task.adopt", "unexpected, duplicate or oversized metadata file");
}

static bool ztt_adopt_input_bindings(const char *workspace,
    const struct vcs_zcode_task_v1 *task, const struct ztt_adoption_wires *wires)
{
    uint8_t check[32];
    struct vcs_zcode_write_scope_v1 scope;
    bool ok = wires->scope && wires->authority &&
        vcs_zcode_write_scope_parse(wires->scope, wires->scope_len, &scope) ==
            VCS_ZCODE_WRITE_SCOPE_OK &&
        vcs_zcode_write_scope_root(&scope, check) == VCS_ZCODE_WRITE_SCOPE_OK &&
        memcmp(check, task->write_scope_root, 32) == 0 &&
        vcs_zcode_task_authority_bundle_import(workspace, task,
            wires->authority, wires->authority_len) == VCS_ZCODE_TASK_AUTHORITY_OK &&
        vcs_zcode_task_authority_validate(workspace, task) ==
            VCS_ZCODE_TASK_AUTHORITY_OK &&
        vcs_object_put_addressed(workspace, task->write_scope_root,
            wires->scope, wires->scope_len);
    if (!ok) LOG_FAIL("zcode.task.adopt", "metadata authority binding failed");
    return true;
}

static bool ztt_adopt_inputs(struct vcs_package_store *store,
    const uint8_t root[32], const char *workspace,
    const struct vcs_zcode_task_v1 *task)
{
    uint8_t *manifest_wire = NULL;
    size_t manifest_len = 0;
    struct ztt_adoption_wires wires = {0};
    uint8_t check[32];
    struct vcs_package_manifest manifest;
    vcs_package_manifest_init(&manifest);
    bool ok = vcs_package_store_get_manifest_wire(store, root,
        &manifest_wire, &manifest_len) == VCS_PACKAGE_STORE_OK &&
        vcs_package_manifest_parse(manifest_wire, manifest_len, &manifest) &&
        manifest.count == 2 && vcs_package_manifest_root(&manifest, check) &&
        memcmp(check, root, 32) == 0;
    for (uint32_t i = 0; ok && i < manifest.count; ++i)
        ok = ztt_adopt_input_file(store, root, &manifest, i, &wires);
    ok = ok && ztt_adopt_input_bindings(workspace, task, &wires);
    free(manifest_wire); free(wires.scope); free(wires.authority);
    vcs_package_manifest_free(&manifest);
    if (!ok)
        LOG_FAIL("zcode.task.adopt", "task metadata is missing or mismatched");
    return true;
}

static bool ztt_adopt_context_valid(const char *workspace,
    const struct vcs_zcode_task_v1 *task, const uint8_t task_root[32],
    const char *context_hex)
{
    uint8_t root[32], *wire = NULL;
    size_t len = 0;
    struct vcs_zcode_agent_context_v1 context;
    vcs_zcode_agent_context_init(&context);
    bool ok = zcl_hex_decode_lower(context_hex, root, 32) &&
        vcs_object_load_raw_bounded(workspace, root, task->max_context_bytes,
            &wire, &len) == 0 &&
        vcs_zcode_agent_context_parse(wire, len, task->max_context_bytes,
            &context) == VCS_ZCODE_AGENT_CONTEXT_OK &&
        vcs_zcode_agent_context_validate_for_task(&context, task, task_root,
            root, true) == VCS_ZCODE_AGENT_CONTEXT_OK;
    free(wire);
    vcs_zcode_agent_context_free(&context);
    if (!ok) LOG_FAIL("zcode.task.adopt", "receiver context failed task binding");
    return true;
}

static bool ztt_adopt_reproduce(const char *workspace,
    const struct vcs_zcode_task_v1 *task, const uint8_t task_root[32],
    const char *task_hex, const char *query, char adopted_context[65])
{
    struct vcs_zcode_task_index *index = vcs_zcode_task_index_build(workspace,
        (int64_t)platform_time_wall_unix());
    struct vcs_zcode_task_conflict conflict;
    bool ambiguous = false;
    const struct vcs_zcode_task_context_entry *existing =
        vcs_zcode_task_index_context_for_task(index, task_hex, &ambiguous);
    bool ok = index && vcs_zcode_task_index_complete(index) && !ambiguous &&
        vcs_zcode_task_index_conflict(index, workspace, task, &conflict) ==
            VCS_ZCODE_TASK_CONFLICT_CLEAR;
    if (ok && existing) {
        ok = strcmp(existing->query, query) == 0;
        if (ok) (void)snprintf(adopted_context, 65, "%s",
                              existing->context_root_hex);
    }
    vcs_zcode_task_index_free(index);
    if (!ok) LOG_FAIL("zcode.task.adopt", "existing context or task conflicts");
    /* Reproduce even on retry: an indexed object's self-consistency does not
     * prove that its excerpts came from this receiver's current source. */
    struct zcode_agent_context_status captured;
    struct zcl_result result = zcode_agent_context_capture_complete(workspace,
        task, task_root, query, &captured);
    ok = result.ok && (!adopted_context[0] ||
        strcmp(adopted_context, captured.context_root_sha3) == 0);
    if (!ok) LOG_FAIL("zcode.task.adopt", "local context reproduction refused");
    (void)snprintf(adopted_context, 65, "%s", captured.context_root_sha3);
    return true;
}

static bool ztt_adopt_source_current(const char *workspace,
    const struct vcs_zcode_task_v1 *task, const uint8_t task_root[32],
    const char *adopted_context, int64_t now)
{
    uint8_t source[32];
    bool ok = vcs_zcode_task_validate_at(task, now) == VCS_ZCODE_DEV_OK &&
        vcs_tree_capture_path(workspace, source) == VCS_OK &&
        memcmp(source, task->source_root, 32) == 0 &&
        ztt_adopt_context_valid(workspace, task, task_root, adopted_context);
    if (!ok) LOG_FAIL("zcode.task.adopt", "task or source changed before storage");
    return true;
}

static bool ztt_adopt_store(const char *workspace,
    const struct vcs_zcode_task_v1 *task,
    const struct vcs_zcode_proof_policy_v1 *policy, const uint8_t task_root[32],
    const char *task_hex, const char *adopted_context,
    const uint8_t *goal, size_t goal_len)
{
    int64_t now = (int64_t)platform_time_wall_unix();
    if (!ztt_adopt_source_current(workspace, task, task_root, adopted_context, now))
        LOG_FAIL("zcode.task.adopt", "final source validation refused");
    struct vcs_zcode_task_index *index = vcs_zcode_task_index_build(workspace, now);
    bool ambiguous = false;
    struct vcs_zcode_task_conflict conflict;
    const struct vcs_zcode_task_context_entry *existing =
        vcs_zcode_task_index_context_for_task(index, task_hex, &ambiguous);
    uint8_t task_wire[VCS_ZCODE_TASK_WIRE_BYTES];
    uint8_t policy_wire[VCS_ZCODE_PROOF_POLICY_WIRE_BYTES];
    /* Keep fresh conflict checks adjacent to task-last persistence. */
    bool ok = index && vcs_zcode_task_index_complete(index) &&
        existing && !ambiguous &&
        strcmp(existing->context_root_hex, adopted_context) == 0 &&
        vcs_zcode_task_index_conflict(index, workspace, task, &conflict) ==
            VCS_ZCODE_TASK_CONFLICT_CLEAR &&
        vcs_zcode_task_serialize(task, task_wire) == VCS_ZCODE_DEV_OK &&
        vcs_zcode_proof_policy_serialize(policy, policy_wire) == VCS_ZCODE_DEV_OK &&
        vcs_object_put_addressed(workspace, task->proof_policy_root,
            policy_wire, sizeof(policy_wire)) &&
        vcs_object_put_addressed(workspace, task->goal_root, goal, goal_len) &&
        vcs_object_put_addressed(workspace, task_root, task_wire, sizeof(task_wire));
    vcs_zcode_task_index_free(index);
    if (!ok) LOG_FAIL("zcode.task.adopt", "final conflict check or storage refused");
    return true;
}

static bool ztt_adopt_workspace(const struct zcl_command_request *request,
    struct zcl_command_reply *reply, const char *query, char workspace[4400])
{
    const char *workspace_input = ztl_input_str(request->input, "workspace");
    if (!workspace_input || !query || !query[0] ||
        !platform_directory_canonical_real(workspace_input, workspace, 4400)) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
            ZCL_COMMAND_EXIT_INVALID, "BAD_ADOPTION_INPUT", "validate", false,
            false, "adoption requires an existing workspace and context symbol",
            "workspace,context_symbol");
        return false;
    }
    return true;
}

void zcl_native_handle_zcode_task_adopt(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!request || !reply) return;
    const char *query = ztl_input_str(request->input, "context_symbol");
    char workspace[4400];
    if (!ztt_adopt_workspace(request, reply, query, workspace)) return;
    uint8_t task_root[32], context_root[32], inputs_root[32];
    if (!ztl_hex32(request, reply, "zcode.task.adopt", "task_root",
            "BAD_TASK_ROOT", "original task", task_root) ||
        !ztl_hex32(request, reply, "zcode.task.adopt", "context_root",
            "BAD_CONTEXT_ROOT", "task carrier", context_root) ||
        !ztl_hex32(request, reply, "zcode.task.adopt", "inputs_root",
            "BAD_INPUTS_ROOT", "task metadata carrier", inputs_root)) return;
    bool own_store = false;
    struct vcs_package_store *store = ztl_open_store(request, &own_store,
                                                     "zcode.task.adopt");
    struct vcs_zcode_task_v1 task;
    struct vcs_zcode_proof_policy_v1 policy;
    uint8_t goal[VCS_ZCODE_TASK_CONTEXT_GOAL_MAX], derived[32], source[32];
    size_t goal_len = 0;
    int64_t now = (int64_t)platform_time_wall_unix();
    bool ok = store && vcs_zcode_task_context_admit(store, context_root,
        task_root, now, &task, &policy, goal, sizeof(goal), &goal_len,
        derived) == VCS_ZCODE_TASK_CONTEXT_OK;
    /* Snapshot capture and metadata import can retain inert objects even
     * when a later binding check refuses. This is a conservative mutation
     * indicator, not a count of newly stored objects on an idempotent retry. */
    bool writes_possible = ok;
    ok = ok && vcs_tree_capture_path(workspace, source) == VCS_OK &&
        memcmp(source, task.source_root, 32) == 0 &&
        ztt_adopt_inputs(store, inputs_root, workspace, &task);
    ztl_close_store(store, own_store);
    if (!ok) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
            ZCL_COMMAND_EXIT_INVALID, "ADOPTION_INPUTS_REFUSED", "validate",
            false, writes_possible, "task, source or metadata bindings are unavailable",
            "inert snapshot or metadata objects may remain; task storage was not reached");
        return;
    }
    char task_hex[65], adopted_context[65] = {0};
    zcl_hex_encode(task_root, 32, task_hex);
    ok = ztt_adopt_reproduce(workspace, &task, task_root, task_hex, query,
        adopted_context) && ztt_adopt_store(workspace, &task, &policy,
        task_root, task_hex, adopted_context, goal, goal_len);
    if (!ok) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
            ZCL_COMMAND_EXIT_INVALID, "ADOPTION_CONTEXT_REFUSED", "execute",
            false, true, "context, conflict check or task storage failed",
            "inert objects may remain; conflicting context roots require resolution before retry");
        return;
    }
    (void)json_push_kv_str(&reply->data, "task_root", task_hex);
    (void)json_push_kv_str(&reply->data, "context_root", adopted_context);
    (void)json_push_kv_bool(&reply->data, "executed", false);
    (void)json_push_kv_str(&reply->data, "adoption_status", "adopted");
}

void zcl_native_handle_zcode_task_offer(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;
    char zcode_dir[4400];
    if (!ztt_offer_workspace(request, reply, zcode_dir))
        return;
    uint8_t task_root[32];
    if (!ztl_hex32(request, reply, "zcode.task.offer", "task_root",
                   "BAD_TASK_ROOT",
                   "the posted task's own root", task_root))
        return;
    char task_hex[65];
    zcl_hex_encode(task_root, 32, task_hex);

    uint8_t *task_wire = NULL, *goal = NULL, *policy_wire = NULL;
    size_t task_len = 0, goal_len = 0, policy_len = 0;
    struct vcs_zcode_task_v1 task;
    if (!ztt_load_context_wires(zcode_dir, task_root, &task_wire, &task_len,
                                &goal, &goal_len, &policy_wire, &policy_len,
                                &task)) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID,
                               "TASK_WIRES_NOT_HELD", "execute", false, false,
                               "the task's three wires are not held "
                               "complete in this workspace's object store "
                               "(task root, goal preimage at task.goal_root, "
                               "proof policy at task.proof_policy_root) or "
                               "do not hash to their own addresses",
                               task_hex);
        return;
    }

    bool own_store = false;
    struct vcs_package_store *store =
        ztl_open_store(request, &own_store, "zcode.task");
    if (!store) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "NO_STORE",
                               "execute", false, false,
                               "the package store could not be opened; a "
                               "context cannot be exported or made "
                               "reachable without one",
                               zcode_dir);
        free(task_wire);
        free(goal);
        free(policy_wire);
        return;
    }
    uint8_t context_root[32];
    enum vcs_zcode_task_context_error exported = vcs_zcode_task_context_export(
        task_wire, task_len, goal, goal_len, policy_wire, policy_len, store,
        (int64_t)platform_time_wall_unix(), context_root);
    uint8_t inputs_root[32];
    const char *inputs_reason = "task_context_refused";
    bool inputs_available = exported == VCS_ZCODE_TASK_CONTEXT_OK &&
        ztt_offer_adoption_inputs(zcode_dir, &task, store, inputs_root,
                                 &inputs_reason);
    ztl_close_store(store, own_store);
    free(task_wire);
    free(goal);
    free(policy_wire);

    char context_hex[65];
    zcl_hex_encode(context_root, 32, context_hex);
    if (exported != VCS_ZCODE_TASK_CONTEXT_OK) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID,
                               "TASK_CONTEXT_REFUSED", "execute", false,
                               false,
                               "the task-context carrier refused these "
                               "bytes; every cross-binding runs at export "
                               "exactly as it will at admit",
                               vcs_zcode_task_context_error_string(exported));
        return;
    }

    (void)json_push_kv_str(&reply->data, "task_root", task_hex);
    (void)json_push_kv_str(&reply->data, "context_root", context_hex);
    (void)json_push_kv_bool(&reply->data, "adoption_inputs_available",
                           inputs_available);
    (void)json_push_kv_str(&reply->data, "adoption_inputs_status", inputs_reason);
    if (inputs_available) {
        char inputs_hex[65];
        zcl_hex_encode(inputs_root, 32, inputs_hex);
        (void)json_push_kv_str(&reply->data, "adoption_inputs_root", inputs_hex);
        struct json_value inputs_provider;
        json_init(&inputs_provider);
        ztl_publish_input(&inputs_provider, "provider",
            VCS_ZCODE_TASK_DHT_NAMESPACE, NULL, inputs_hex,
            (uint64_t)platform_time_wall_unix(), ZTT_PROVIDER_WINDOW_S);
        (void)json_push_kv(&reply->data, "adoption_inputs_provider_publish_input",
                           &inputs_provider);
        json_free(&inputs_provider);
    }
    (void)json_push_kv_str(&reply->data, "namespace",
                           VCS_ZCODE_TASK_DHT_NAMESPACE);
    (void)json_push_kv_int(&reply->data, "expires_unix",
                           (int64_t)task.expires_unix);

    /* PROVIDER first: it is the record the fetch path actually routes on. */
    uint64_t now = (uint64_t)platform_time_wall_unix();
    struct json_value publish;
    json_init(&publish);
    ztl_publish_input(&publish, "provider", VCS_ZCODE_TASK_DHT_NAMESPACE,
                      NULL, context_hex, now, ZTT_PROVIDER_WINDOW_S);
    (void)json_push_kv(&reply->data, "provider_publish_input", &publish);
    json_free(&publish);
    json_init(&publish);
    uint64_t pointer_window = (uint64_t)task.expires_unix - now;
    if (pointer_window > ZTT_POINTER_WINDOW_S)
        pointer_window = ZTT_POINTER_WINDOW_S;
    ztl_publish_input(&publish, "pointer", VCS_ZCODE_TASK_DHT_NAMESPACE,
                      task_hex, context_hex, now, pointer_window);
    (void)json_push_kv(&reply->data, "pointer_publish_input", &publish);
    json_free(&publish);

    (void)json_push_kv_str(
        &reply->data, "note",
        "offering exports what THIS node holds and announces NOTHING: no "
        "peer can find the posting yet. Telling the network is the "
        "separate second act, and it takes BOTH records in this namespace: "
        "run zcode network publish with provider_publish_input (\"ask me "
        "for these bytes\" — the record the fetch path routes on) AND with "
        "pointer_publish_input (\"this context posts this task\" — what a "
        "puller looks up when all it knows is the task root). Either one "
        "alone is a silent no-op at pull time. Both inputs are mode=plan; "
        "each returns a plan_token to commit. The context binds the goal "
        "preimage and proof policy bytes to the task's own root — a "
        "stranger re-verifies all of it from fetched bytes alone");
}

/* ── zcode task pull ────────────────────────────────────────────────── */

/* One resolved pointer's fate, kept flat so a failure never grows a
 * control path that could abort the sweep. */
struct ztt_row {
    char transport_root[65];
    char fetch_outcome[96];   /* the fetch path's own named verdict */
    bool fetched;
    char admit_rule[192];     /* the task-context layer's NAMED result */
    bool admitted;
    int64_t expires_unix;     /* filled only on a verified row */
    char goal[VCS_ZCODE_TASK_CONTEXT_GOAL_MAX + 1u];
};

void zcl_native_handle_zcode_task_pull(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;
    char zcode_dir[4400];
    if (!ztl_zcode_dir(request, reply, "zcode.task.pull", zcode_dir))
        return;
    uint8_t task_root[32];
    if (!ztl_hex32(request, reply, "zcode.task.pull", "task_root",
                   "BAD_TASK_ROOT",
                   "the task the contexts must prove they post", task_root))
        return;
    char task_hex[65];
    zcl_hex_encode(task_root, 32, task_hex);

    uint32_t cap = ZTT_ROWS_DEFAULT;
    const struct json_value *mv = json_get(request->input, "maximum_records");
    if (mv && mv->type == JSON_INT) {
        int64_t want = json_get_int(mv);
        if (want <= 0) {
            zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                                   ZCL_COMMAND_EXIT_INVALID,
                                   "BAD_MAXIMUM_RECORDS", "normalize", false,
                                   false,
                                   "maximum_records must be a positive "
                                   "integer",
                                   "zcode.task.pull");
            return;
        }
        cap = want > (int64_t)ZTT_ROWS_CEILING ? ZTT_ROWS_CEILING
                                               : (uint32_t)want;
    }

    struct json_value pointers;
    if (!ztl_query_pointers(request, reply, VCS_ZCODE_TASK_DHT_NAMESPACE,
                            task_hex, &pointers))
        return;

    /* Distinct transport roots, in discovery order, bounded. A republished
     * sequence of the same context collapses here so one publisher cannot
     * consume the row budget by republishing. */
    size_t seen = json_size(&pointers);
    struct ztt_row *rows = zcl_calloc(cap, sizeof(*rows), "ztt_pull_rows");
    if (!rows) {
        json_free(&pointers);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "ALLOC", "execute",
                               false, false, "pull row table",
                               "zcode.task.pull");
        return;
    }
    uint32_t distinct = 0;
    bool truncated = false;
    for (size_t i = 0; i < seen; i++) {
        const struct json_value *record = json_at(&pointers, i);
        const char *transport =
            record ? json_get_str(json_get(record, "transport_root")) : NULL;
        if (!transport || strlen(transport) != 64)
            continue;
        bool duplicate = false;
        for (uint32_t j = 0; j < distinct; j++)
            if (strcmp(rows[j].transport_root, transport) == 0) {
                duplicate = true;
                break;
            }
        if (duplicate)
            continue;
        if (distinct >= cap) {
            truncated = true;
            break;
        }
        (void)snprintf(rows[distinct].transport_root,
                       sizeof(rows[distinct].transport_root), "%s",
                       transport);
        (void)snprintf(rows[distinct].fetch_outcome,
                       sizeof(rows[distinct].fetch_outcome), "%s",
                       "not-attempted");
        (void)snprintf(rows[distinct].admit_rule,
                       sizeof(rows[distinct].admit_rule), "%s",
                       "not-attempted");
        distinct++;
    }
    json_free(&pointers);

    bool own_store = false;
    struct vcs_package_store *store = NULL;
    if (distinct > 0) {
        store = ztl_open_store(request, &own_store, "zcode.task");
        if (!store) {
            free(rows);
            zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                                   ZCL_COMMAND_EXIT_INTERNAL, "NO_STORE",
                                   "execute", false, false,
                                   "the package store could not be opened; "
                                   "task contexts cannot be fetched or "
                                   "verified without one",
                                   zcode_dir);
            return;
        }
    }

    uint32_t fetched = 0, admitted = 0, refused = 0;
    int64_t now = (int64_t)platform_time_wall_unix();
    for (uint32_t i = 0; i < distinct; i++) {
        struct ztt_row *row = &rows[i];
        ztl_fetch_one(request, VCS_ZCODE_TASK_DHT_NAMESPACE,
                      row->transport_root,
                      (int64_t)VCS_ZCODE_TASK_CONTEXT_MAX_PACKAGE_BYTES,
                      &row->fetched, row->fetch_outcome,
                      sizeof(row->fetch_outcome));
        fetched += row->fetched ? 1u : 0u;

        /* expect_task_root is the caller's root and is NEVER NULL. This
         * single argument is the whole reason a hostile pointer in this
         * namespace cannot deliver a different task's context: the bytes
         * must re-verify AND prove this exact task, live at this instant
         * (an expired posting drops off here). The check runs even when
         * the fetch only SCHEDULED the download — the store is the
         * authority on whether the bytes are here. A row that fails stays
         * in the report; the sweep continues. */
        uint8_t transport_root[32];
        if (!zcl_hex_decode_lower(row->transport_root, transport_root, 32)) {
            (void)snprintf(row->admit_rule, sizeof(row->admit_rule), "%s",
                           "pointer-transport-root-not-canonical-hex");
            refused++;
            continue;
        }
        struct vcs_zcode_task_v1 task;
        uint8_t derived_task_root[32];
        size_t goal_len = 0;
        enum vcs_zcode_task_context_error r = vcs_zcode_task_context_admit(
            store, transport_root, task_root, now, &task, NULL,
            (uint8_t *)row->goal, sizeof(row->goal) - 1u, &goal_len,
            derived_task_root);
        (void)snprintf(row->admit_rule, sizeof(row->admit_rule), "%s",
                       vcs_zcode_task_context_error_string(r));
        if (r != VCS_ZCODE_TASK_CONTEXT_OK) {
            refused++;
            continue;
        }
        row->admitted = true;
        row->expires_unix = task.expires_unix;
        row->goal[goal_len] = '\0';
        admitted++;
    }
    ztl_close_store(store, own_store);

    /* Two very different dead ends, never merged into one "not found":
     * nobody has posted this task, versus somebody has and nobody
     * reachable is serving the context. The next step differs
     * completely — wait for a poster, or fix reachability. */
    const char *status = "TASKS_VERIFIED";
    const char *blocker = "";
    if (distinct == 0) {
        status = "NO_TASK_POINTERS";
        blocker = "no_pointer_record_names_a_posting_for_this_task_root";
    } else if (admitted == 0) {
        /* admitted is tested BEFORE fetched, exactly as the work lane: the
         * admit above is deliberately unconditional, so a context this
         * node already holds verifies even when provider discovery served
         * nothing. */
        if (fetched == 0) {
            status = "TASK_BYTES_UNREACHABLE";
            blocker = "pointers_exist_but_no_authenticated_provider_served_"
                      "the_context_bytes";
        } else {
            status = "TASKS_REFUSED";
            blocker = "every_fetched_context_failed_a_named_admission_rule";
        }
    }

    (void)json_push_kv_str(&reply->data, "task_root", task_hex);
    (void)json_push_kv_str(&reply->data, "namespace",
                           VCS_ZCODE_TASK_DHT_NAMESPACE);
    (void)json_push_kv_str(&reply->data, "status", status);
    if (blocker[0])
        (void)json_push_kv_str(&reply->data, "blocker", blocker);
    (void)json_push_kv_int(&reply->data, "pointers_seen", (int64_t)seen);
    (void)json_push_kv_int(&reply->data, "distinct_transport_roots",
                           (int64_t)distinct);
    (void)json_push_kv_int(&reply->data, "fetched", (int64_t)fetched);
    (void)json_push_kv_int(&reply->data, "admitted", (int64_t)admitted);
    (void)json_push_kv_int(&reply->data, "refused", (int64_t)refused);
    (void)json_push_kv_int(&reply->data, "maximum_records", (int64_t)cap);
    (void)json_push_kv_bool(&reply->data, "rows_truncated", truncated);

    struct json_value list;
    json_init(&list);
    json_set_array(&list);
    for (uint32_t i = 0; i < distinct; i++) {
        const struct ztt_row *row = &rows[i];
        struct json_value entry;
        json_init(&entry);
        json_set_object(&entry);
        (void)json_push_kv_str(&entry, "context_root", row->transport_root);
        (void)json_push_kv_str(&entry, "fetch_outcome", row->fetch_outcome);
        (void)json_push_kv_str(&entry, "admit_rule", row->admit_rule);
        if (row->admitted) {
            (void)json_push_kv_bool(&entry, "verified", true);
            (void)json_push_kv_int(&entry, "expires_unix",
                                   row->expires_unix);
            (void)json_push_kv_str(&entry, "goal", row->goal);
        } else {
            (void)json_push_kv_bool(&entry, "verified", false);
        }
        (void)json_push_back(&list, &entry);
        json_free(&entry);
    }
    (void)json_push_kv(&reply->data, "rows", &list);
    json_free(&list);
    free(rows);

    (void)json_push_kv_str(
        &reply->data, "note",
        "a verified row is a posting, not an assignment and not "
        "execution: the context proves which task it posts, this node "
        "holds the bytes, and the goal text is the problem statement. "
        "Doing the work is the ordinary local journey; offering its "
        "result is zcode work offer under the work namespace");
}

/* ── zcode task board ───────────────────────────────────────────────── */

/* The board is the records lane's namespace-wide local projection (the
 * board input of `zcode network records`), enriched: every row whose
 * context this node already holds is re-verified and carries its goal, so
 * an operator reads problem statements straight off the board. Rows whose
 * bytes are not here yet say so — zcode task pull fetches them. */
void zcl_native_handle_zcode_task_board(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;
    struct json_value forwarded_input;
    json_init(&forwarded_input);
    json_set_object(&forwarded_input);
    (void)json_push_kv_str(&forwarded_input, "kind", "pointer");
    (void)json_push_kv_str(&forwarded_input, "namespace",
                           VCS_ZCODE_TASK_DHT_NAMESPACE);
    const char *datadir = ztl_input_str(request->input, "datadir");
    if (datadir && datadir[0])
        (void)json_push_kv_str(&forwarded_input, "datadir", datadir);
    (void)json_push_kv_bool(&forwarded_input, "board", true);
    struct zcl_command_request forwarded = *request;
    forwarded.input = &forwarded_input;
    struct zcl_command_reply records;
    zcl_command_reply_init(&records, "zcl.zcode_network_records.v1");
    zcl_native_handle_zcode_network_records(&forwarded, &records);
    json_free(&forwarded_input);
    if (records.exit_code != ZCL_COMMAND_EXIT_OK) {
        zcl_command_reply_fail(
            reply, records.status, records.exit_code,
            records.error.code[0] ? records.error.code : "BOARD_FAILED",
            records.error.phase[0] ? records.error.phase : "discover",
            records.error.retryable, false,
            records.error.message[0]
                ? records.error.message
                : "the task board listing did not complete",
            records.error.evidence);
        zcl_command_reply_free(&records);
        return;
    }

    /* READ means no recovery, lock creation, garbage collection, or directory
     * creation in a caller-selected datadir. Enrich only through a store the
     * hosting daemon already owns; otherwise report bytes-not-held. */
    struct vcs_package_store *store = vcs_package_store_global();
    int64_t now = (int64_t)platform_time_wall_unix();
    struct json_value rows;
    const struct json_value *in_rows = json_get(&records.data, "records");
    json_init(&rows);
    json_set_array(&rows);
    size_t count = in_rows && in_rows->type == JSON_ARR
                       ? json_size(in_rows)
                       : 0;
    for (size_t i = 0; i < count; i++) {
        const struct json_value *record = json_at(in_rows, i);
        const char *semantic =
            record ? json_get_str(json_get(record, "semantic_root")) : NULL;
        const char *transport =
            record ? json_get_str(json_get(record, "transport_root")) : NULL;
        if (!semantic || strlen(semantic) != 64 || !transport ||
            strlen(transport) != 64)
            continue;
        struct json_value entry;
        json_init(&entry);
        json_set_object(&entry);
        (void)json_push_kv_str(&entry, "task_root", semantic);
        (void)json_push_kv_str(&entry, "context_root", transport);
        uint8_t task_root[32], context_root[32];
        if (store && zcl_hex_decode_lower(semantic, task_root, 32) &&
            zcl_hex_decode_lower(transport, context_root, 32)) {
            struct vcs_zcode_task_v1 task;
            char goal[VCS_ZCODE_TASK_CONTEXT_GOAL_MAX + 1u];
            size_t goal_len = 0;
            enum vcs_zcode_task_context_error r =
                vcs_zcode_task_context_admit(
                    store, context_root, task_root, now, &task, NULL,
                    (uint8_t *)goal, sizeof(goal) - 1u, &goal_len, NULL);
            (void)json_push_kv_str(&entry, "admit_rule",
                                   vcs_zcode_task_context_error_string(r));
            if (r == VCS_ZCODE_TASK_CONTEXT_OK) {
                goal[goal_len] = '\0';
                (void)json_push_kv_bool(&entry, "verified", true);
                (void)json_push_kv_int(&entry, "expires_unix",
                                       (int64_t)task.expires_unix);
                (void)json_push_kv_str(&entry, "goal", goal);
            } else {
                (void)json_push_kv_bool(&entry, "verified", false);
            }
        } else {
            (void)json_push_kv_str(&entry, "admit_rule", "bytes-not-held");
            (void)json_push_kv_bool(&entry, "verified", false);
        }
        (void)json_push_back(&rows, &entry);
        json_free(&entry);
    }
    zcl_command_reply_free(&records);

    (void)json_push_kv_str(&reply->data, "namespace",
                           VCS_ZCODE_TASK_DHT_NAMESPACE);
    (void)json_push_kv_bool(&reply->data, "local_projection", true);
    (void)json_push_kv_int(&reply->data, "count", (int64_t)json_size(&rows));
    (void)json_push_kv(&reply->data, "rows", &rows);
    json_free(&rows);
    (void)json_push_kv_str(
        &reply->data, "note",
        "this board is what THIS node has seen — records arrive only "
        "through the ordinary paths (publish here, exact-root discovery "
        "merges, replication), so an empty board means nothing seen yet, "
        "not nothing anywhere. A verified row carries its goal text; a "
        "row whose bytes are not held yet names its rule — zcode task "
        "pull fetches and re-verifies it against the task root");
}
