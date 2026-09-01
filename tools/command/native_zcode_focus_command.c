/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Publish admitted shared-focus claims and snapshots into ZVCS CAS. */
#include "command/native_command.h"

#include "base/hex.h"
#include "command/native_story_internal.h"
#include "crypto/sha3.h"
#include "json/json.h"
#include "platform/time_compat.h"
#include "vcs/vcs_object.h"
#include "vcs/zcode_focus.h"
#include "vcs/zcode_work_swarm.h"

#include <stdlib.h>
#include <string.h>

struct zfocus_base {
    struct story_loaded_work loaded;
    struct vcs_zcode_task_v1 task;
    struct vcs_zcode_agent_context_v1 context;
    struct vcs_zcode_write_scope_v1 task_scope;
    struct vcs_zcode_focus_v1 empty_focus;
    uint8_t task_root[32];
    uint8_t empty_focus_root[32];
    uint8_t situation_root[32];
};

struct zfocus_claim_row {
    uint8_t root[32];
    struct vcs_zcode_focus_claim_v1 claim;
    struct vcs_zcode_write_scope_v1 scope;
    struct vcs_zcode_work_request_v1 request;
    struct vcs_zcode_work_admission_v1 admission;
};

static const char *zfocus_string(const struct json_value *input,
                                 const char *key)
{
    const struct json_value *value = input ? json_get(input, key) : NULL;
    return value && value->type == JSON_STR ? json_get_str(value) : NULL;
}

static bool zfocus_root_text(const char *text, uint8_t out[32])
{
    return text && strlen(text) == 64u &&
           zcl_hex_decode_lower(text, out, 32);
}

static void zfocus_fail(struct zcl_command_reply *reply, const char *code,
                        const char *phase, const char *message)
{
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                           ZCL_COMMAND_EXIT_INVALID, code, phase, false,
                           false, message, "canonical ZCODE focus objects");
}

static bool zfocus_push_root(struct json_value *data, const char *key,
                             const uint8_t root[32])
{
    char text[65];
    zcl_hex_encode(root, 32, text);
    return json_push_kv_str(data, key, text);
}

static bool zfocus_load_scope(const char *workspace, const uint8_t root[32],
                              struct vcs_zcode_write_scope_v1 *scope)
{
    uint8_t *wire = NULL; size_t wire_len = 0; uint8_t check[32];
    bool ok = vcs_object_load_raw_bounded(
                  workspace, root, VCS_ZCODE_WRITE_SCOPE_WIRE_MAX,
                  &wire, &wire_len) == 0 &&
        vcs_zcode_write_scope_parse(wire, wire_len, scope) ==
            VCS_ZCODE_WRITE_SCOPE_OK &&
        vcs_zcode_write_scope_root(scope, check) ==
            VCS_ZCODE_WRITE_SCOPE_OK &&
        memcmp(check, root, 32) == 0;
    free(wire);
    return ok;
}

static bool zfocus_load_claim(const char *workspace, const uint8_t root[32],
                              struct vcs_zcode_focus_claim_v1 *claim)
{
    uint8_t *wire = NULL; size_t wire_len = 0; uint8_t check[32];
    bool ok = vcs_object_load_raw_bounded(
                  workspace, root, VCS_ZCODE_FOCUS_CLAIM_WIRE_BYTES,
                  &wire, &wire_len) == 0 &&
        vcs_zcode_focus_claim_parse(wire, wire_len, claim) ==
            VCS_ZCODE_FOCUS_OK &&
        vcs_zcode_focus_claim_root(claim, check) == VCS_ZCODE_FOCUS_OK &&
        memcmp(check, root, 32) == 0;
    free(wire);
    return ok;
}

static bool zfocus_load_request(
    const char *workspace, const uint8_t root[32],
    struct vcs_zcode_work_request_v1 *request)
{
    uint8_t *wire = NULL; size_t wire_len = 0; uint8_t check[32];
    struct vcs_zcode_work_swarm_message message;
    bool ok = vcs_object_load_raw_bounded(
                  workspace, root, VCS_ZCODE_WORK_SWARM_MAX_WIRE_BYTES,
                  &wire, &wire_len) == 0 &&
        vcs_zcode_work_swarm_parse(wire, wire_len, &message) &&
        message.type == VCS_ZCODE_WORK_SWARM_REQUEST &&
        vcs_zcode_work_request_id(&message.body.request, check) &&
        memcmp(check, root, 32) == 0;
    if (ok) *request = message.body.request;
    free(wire);
    return ok;
}

static bool zfocus_load_admission(
    const char *workspace, const uint8_t carrier_root[32],
    struct vcs_zcode_work_admission_v1 *admission)
{
    uint8_t *wire = NULL; size_t wire_len = 0;
    uint8_t derived[32];
    struct vcs_zcode_work_swarm_message message;
    bool ok = vcs_object_load_raw_bounded(
                  workspace, carrier_root,
                  VCS_ZCODE_WORK_SWARM_MAX_WIRE_BYTES,
                  &wire, &wire_len) == 0;
    struct sha3_256_ctx hash;
    uint8_t tag = VCS_TAG_BLOB;
    sha3_256_init(&hash);
    sha3_256_write(&hash, &tag, 1);
    if (ok) sha3_256_write(&hash, wire, wire_len);
    sha3_256_finalize(&hash, derived);
    ok = ok && memcmp(derived, carrier_root, 32) == 0 &&
        vcs_zcode_work_swarm_parse(wire, wire_len, &message) &&
        message.type == VCS_ZCODE_WORK_SWARM_ADMISSION &&
        vcs_zcode_work_admission_verify(&message.body.admission);
    if (ok) *admission = message.body.admission;
    free(wire);
    return ok;
}

static bool zfocus_store_scope(
    const char *workspace, const struct vcs_zcode_write_scope_v1 *scope,
    uint8_t root[32])
{
    uint8_t *wire = NULL; size_t wire_len = 0;
    bool ok = vcs_zcode_write_scope_serialize(scope, &wire, &wire_len) ==
                  VCS_ZCODE_WRITE_SCOPE_OK &&
        vcs_zcode_write_scope_root(scope, root) ==
                  VCS_ZCODE_WRITE_SCOPE_OK &&
        vcs_object_put_addressed(workspace, root, wire, wire_len);
    struct vcs_zcode_write_scope_v1 check;
    ok = ok && zfocus_load_scope(workspace, root, &check) &&
         check.count == scope->count;
    free(wire);
    return ok;
}

static bool zfocus_store_claim(
    const char *workspace, const struct vcs_zcode_focus_claim_v1 *claim,
    uint8_t root[32])
{
    uint8_t wire[VCS_ZCODE_FOCUS_CLAIM_WIRE_BYTES];
    struct vcs_zcode_focus_claim_v1 check;
    return vcs_zcode_focus_claim_root(claim, root) == VCS_ZCODE_FOCUS_OK &&
        vcs_zcode_focus_claim_serialize(claim, wire) == VCS_ZCODE_FOCUS_OK &&
        vcs_object_put_addressed(workspace, root, wire, sizeof(wire)) &&
        zfocus_load_claim(workspace, root, &check);
}

static bool zfocus_store_focus(
    const char *workspace, const struct vcs_zcode_focus_v1 *focus,
    uint8_t root[32])
{
    uint8_t wire[VCS_ZCODE_FOCUS_WIRE_BYTES];
    uint8_t *loaded = NULL; size_t loaded_len = 0; uint8_t check_root[32];
    struct vcs_zcode_focus_v1 check;
    bool ok = vcs_zcode_focus_root(focus, root) == VCS_ZCODE_FOCUS_OK &&
        vcs_zcode_focus_serialize(focus, wire) == VCS_ZCODE_FOCUS_OK &&
        vcs_object_put_addressed(workspace, root, wire, sizeof(wire)) &&
        vcs_object_load_raw_bounded(
            workspace, root, sizeof(wire), &loaded, &loaded_len) == 0 &&
        vcs_zcode_focus_parse(loaded, loaded_len, &check) ==
            VCS_ZCODE_FOCUS_OK &&
        vcs_zcode_focus_root(&check, check_root) == VCS_ZCODE_FOCUS_OK &&
        memcmp(check_root, root, 32) == 0;
    free(loaded);
    return ok;
}

static bool zfocus_store_claim_set(
    const char *workspace, const uint8_t (*roots)[32], size_t count,
    uint8_t root[32])
{
    uint8_t *wire = NULL; size_t wire_len = 0;
    uint8_t parsed[VCS_ZCODE_FOCUS_MAX_CLAIMS][32]; size_t parsed_count = 0;
    bool ok = vcs_zcode_focus_claim_set_serialize(
                  roots, count, &wire, &wire_len) == VCS_ZCODE_FOCUS_OK &&
        vcs_zcode_focus_claim_set_root(roots, count, root) ==
                  VCS_ZCODE_FOCUS_OK &&
        vcs_object_put_addressed(workspace, root, wire, wire_len);
    uint8_t *loaded = NULL; size_t loaded_len = 0;
    ok = ok && vcs_object_load_raw_bounded(
                   workspace, root, VCS_ZCODE_FOCUS_CLAIM_SET_WIRE_MAX,
                   &loaded, &loaded_len) == 0 &&
        vcs_zcode_focus_claim_set_parse(
            loaded, loaded_len, parsed, VCS_ZCODE_FOCUS_MAX_CLAIMS,
            &parsed_count) == VCS_ZCODE_FOCUS_OK &&
        parsed_count == count &&
        (count == 0 || memcmp(parsed, roots, count * 32u) == 0);
    free(loaded); free(wire);
    return ok;
}

static bool zfocus_load_base(
    const struct zcl_command_request *request, const char *workspace,
    const char *work, struct zfocus_base *base,
    struct zcl_command_reply *reply)
{
    memset(base, 0, sizeof(*base));
    vcs_zcode_agent_context_init(&base->context);
    if (!workspace || !workspace[0] || !work || !work[0]) {
        zfocus_fail(reply, "BAD_FOCUS_PUBLICATION_INPUT", "validate",
                    "explicit workspace and work identity are required");
        return false;
    }
    if (!story_load_work(request, workspace, work, NULL,
                         &base->loaded, reply))
        return false;
    uint8_t current_source[32], context_root[32];
    bool ok = story_load_task(workspace, &base->loaded, &base->task) &&
        zfocus_root_text(base->loaded.task_root, base->task_root) &&
        story_load_agent_context(workspace, &base->loaded, &base->context) ==
            STORY_CONTEXT_PROVED &&
        vcs_zcode_agent_context_root(
            &base->context, (size_t)base->task.max_context_bytes,
            context_root) == VCS_ZCODE_AGENT_CONTEXT_OK &&
        story_workspace_source_root(workspace, current_source) &&
        memcmp(current_source, base->task.source_root, 32) == 0 &&
        zfocus_load_scope(workspace, base->task.write_scope_root,
                          &base->task_scope) &&
        vcs_zcode_focus_compose(
            &base->task, base->task_root, context_root,
            base->loaded.show.story_root, base->loaded.show.status,
            (base->context.flags & VCS_ZCODE_AGENT_CONTEXT_TRUNCATED) != 0
                ? VCS_ZCODE_FOCUS_CONTEXT_TRUNCATED : 0,
            NULL, 0, &base->empty_focus) == VCS_ZCODE_FOCUS_OK &&
        vcs_zcode_focus_root(&base->empty_focus, base->empty_focus_root) ==
            VCS_ZCODE_FOCUS_OK &&
        vcs_zcode_focus_situation_root(
            &base->empty_focus, base->situation_root) == VCS_ZCODE_FOCUS_OK;
    if (!ok)
        zfocus_fail(reply, "FOCUS_BASE_INCOMPLETE", "verify",
                    "task, context, source generation, StoryGraph or task scope could not be reverified");
    return ok;
}

static bool zfocus_scope_from_input(
    const struct json_value *input, struct vcs_zcode_write_scope_v1 *scope)
{
    const struct json_value *paths = input ? json_get(input, "write_scope") : NULL;
    if (!paths || paths->type != JSON_ARR || json_size(paths) == 0 ||
        json_size(paths) > VCS_ZCODE_WRITE_SCOPE_MAX_PATHS)
        return false;
    vcs_zcode_write_scope_init(scope);
    for (size_t i = 0; i < json_size(paths); i++) {
        const struct json_value *path = json_at(paths, i);
        if (!path || path->type != JSON_STR ||
            vcs_zcode_write_scope_add(scope, json_get_str(path)) !=
                VCS_ZCODE_WRITE_SCOPE_OK)
            return false;
    }
    return true;
}

static int zfocus_row_compare(const void *left, const void *right)
{
    return memcmp(((const struct zfocus_claim_row *)left)->root,
                  ((const struct zfocus_claim_row *)right)->root, 32);
}

static bool zfocus_load_rows(
    const struct json_value *input, const char *workspace,
    struct zfocus_claim_row rows[VCS_ZCODE_FOCUS_MAX_CLAIMS], size_t *count)
{
    const struct json_value *claims = json_get(input, "claim_roots");
    const struct json_value *admissions = json_get(
        input, "work_admission_carrier_roots");
    size_t n = claims && claims->type == JSON_ARR ? json_size(claims) : 0;
    if (n == 0 || n > VCS_ZCODE_FOCUS_MAX_CLAIMS || !admissions ||
        admissions->type != JSON_ARR || json_size(admissions) != n)
        return false;
    memset(rows, 0, sizeof(*rows) * VCS_ZCODE_FOCUS_MAX_CLAIMS);
    for (size_t i = 0; i < n; i++) {
        const struct json_value *claim = json_at(claims, i);
        const struct json_value *admission = json_at(admissions, i);
        uint8_t admission_root[32];
        if (!claim || claim->type != JSON_STR || !admission ||
            admission->type != JSON_STR ||
            !zfocus_root_text(json_get_str(claim), rows[i].root) ||
            !zfocus_root_text(json_get_str(admission), admission_root) ||
            !zfocus_load_claim(workspace, rows[i].root, &rows[i].claim) ||
            !zfocus_load_scope(workspace, rows[i].claim.write_scope_root,
                               &rows[i].scope) ||
            !zfocus_load_request(workspace, rows[i].claim.intent_root,
                                 &rows[i].request) ||
            !zfocus_load_admission(workspace, admission_root,
                                   &rows[i].admission))
            return false;
    }
    qsort(rows, n, sizeof(rows[0]), zfocus_row_compare);
    for (size_t i = 1; i < n; i++)
        if (memcmp(rows[i - 1u].root, rows[i].root, 32) == 0)
            return false;
    *count = n;
    return true;
}

static bool zfocus_store_empty(struct zfocus_base *base,
                               const char *workspace)
{
    uint8_t set_root[32], focus_root[32];
    return vcs_object_store_init(workspace) &&
        zfocus_store_claim_set(workspace, NULL, 0, set_root) &&
        memcmp(set_root, base->empty_focus.claim_set_root, 32) == 0 &&
        zfocus_store_focus(workspace, &base->empty_focus, focus_root) &&
        memcmp(focus_root, base->empty_focus_root, 32) == 0;
}

void zcl_native_handle_zcode_focus_claim_publish(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!request || !reply) return;
    const char *workspace = zfocus_string(request->input, "workspace");
    const char *work = zfocus_string(request->input, "work");
    struct zfocus_base base;
    if (!zfocus_load_base(request, workspace, work, &base, reply)) return;
    uint8_t situation[32], request_root[32], admission_root[32];
    struct vcs_zcode_write_scope_v1 scope;
    struct vcs_zcode_work_request_v1 work_request;
    struct vcs_zcode_work_admission_v1 admission;
    bool input_ok = zfocus_root_text(
            zfocus_string(request->input, "situation_root"), situation) &&
        zfocus_root_text(zfocus_string(request->input, "work_request_root"),
                         request_root) &&
        zfocus_root_text(zfocus_string(
            request->input, "work_admission_carrier_root"), admission_root) &&
        zfocus_scope_from_input(request->input, &scope) &&
        zfocus_load_request(workspace, request_root, &work_request) &&
        zfocus_load_admission(workspace, admission_root, &admission);
    if (!input_ok || memcmp(situation, base.situation_root, 32) != 0) {
        zfocus_fail(reply, "FOCUS_CLAIM_INPUT_INCOMPLETE", "verify",
                    "situation, scope, signed request or admission could not be reverified");
        goto cleanup;
    }
    int64_t now = (int64_t)platform_time_wall_unix();
    int64_t expires = base.task.expires_unix;
    if (work_request.deadline_unix < expires) expires = work_request.deadline_unix;
    if (admission.deadline_unix < expires) expires = admission.deadline_unix;
    uint8_t scope_root[32], claim_root[32], one_root[1][32];
    struct vcs_zcode_focus_claim_v1 claim = {
        .schema_version = VCS_ZCODE_FOCUS_VERSION,
        .created_unix = now,
        .expires_unix = expires,
    };
    memcpy(claim.situation_root, situation, 32);
    memcpy(claim.claimant_root, admission.worker_signer, 32);
    memcpy(claim.intent_root, request_root, 32);
    memcpy(claim.evidence_plan_root, work_request.proof_policy_root, 32);
    bool proved = now > 0 && now < expires &&
        vcs_zcode_write_scope_root(&scope, scope_root) ==
            VCS_ZCODE_WRITE_SCOPE_OK;
    memcpy(claim.write_scope_root, scope_root, 32);
    proved = proved && vcs_zcode_focus_claim_root(&claim, claim_root) ==
        VCS_ZCODE_FOCUS_OK;
    memcpy(one_root[0], claim_root, 32);
    struct vcs_zcode_focus_v1 claimed_focus;
    proved = proved && vcs_zcode_focus_compose(
        &base.task, base.task_root, base.empty_focus.context_root,
        base.loaded.show.story_root, base.loaded.show.status,
        base.empty_focus.flags, one_root, 1,
        &claimed_focus) == VCS_ZCODE_FOCUS_OK &&
        vcs_zcode_focus_claim_work_status(
            &claimed_focus, &base.task, &base.task_scope, &claim, &scope,
            one_root, 1, &work_request,
            &admission, now) == ZCL_ONTOLOGY_PROVED;
    if (!proved) {
        zfocus_fail(reply, "FOCUS_CLAIM_DISPROVED", "authorize",
                    "signed work authority does not admit this active scope claim");
        goto cleanup;
    }
    if (!zfocus_store_empty(&base, workspace) ||
        !zfocus_store_scope(workspace, &scope, scope_root) ||
        !zfocus_store_claim(workspace, &claim, claim_root)) {
        zfocus_fail(reply, "FOCUS_CLAIM_STORE_FAILED", "persist",
                    "canonical focus claim failed addressed CAS readback verification");
        goto cleanup;
    }
    bool rendered = zfocus_push_root(&reply->data, "focus_root",
                                     base.empty_focus_root) &&
        zfocus_push_root(&reply->data, "situation_root", situation) &&
        zfocus_push_root(&reply->data, "write_scope_root", scope_root) &&
        zfocus_push_root(&reply->data, "claim_root", claim_root) &&
        json_push_kv_int(&reply->data, "created_unix", now) &&
        json_push_kv_int(&reply->data, "expires_unix", expires) &&
        json_push_kv_str(&reply->data, "admitted_work_status", "PROVED") &&
        json_push_kv_bool(&reply->data, "persisted", true) &&
        json_push_kv_bool(&reply->data, "may_execute", false) &&
        json_push_kv_bool(&reply->data, "may_accept", false) &&
        json_push_kv_bool(&reply->data, "may_deploy", false);
    if (!rendered)
        zfocus_fail(reply, "FOCUS_CLAIM_OUTPUT_FAILED", "render",
                    "published focus claim could not be rendered");
cleanup:
    vcs_zcode_agent_context_free(&base.context);
}

static bool zfocus_push_claim_roots(
    struct json_value *data, const struct zfocus_claim_row *rows, size_t count)
{
    struct json_value roots;
    json_init(&roots); json_set_array(&roots);
    bool ok = true;
    for (size_t i = 0; ok && i < count; i++) {
        char text[65]; struct json_value value;
        zcl_hex_encode(rows[i].root, 32, text);
        json_init(&value); json_set_str(&value, text);
        ok = json_push_back(&roots, &value);
        json_free(&value);
    }
    if (ok) ok = json_push_kv(data, "claim_roots", &roots);
    json_free(&roots);
    return ok;
}

void zcl_native_handle_zcode_focus_snapshot_publish(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!request || !reply) return;
    const char *workspace = zfocus_string(request->input, "workspace");
    const char *work = zfocus_string(request->input, "work");
    struct zfocus_base base;
    if (!zfocus_load_base(request, workspace, work, &base, reply)) return;
    struct zfocus_claim_row rows[VCS_ZCODE_FOCUS_MAX_CLAIMS]; size_t count = 0;
    if (!zfocus_load_rows(request->input, workspace, rows, &count)) {
        zfocus_fail(reply, "FOCUS_SNAPSHOT_INPUT_INCOMPLETE", "verify",
                    "claim, scope, signed request or admission roots could not be reverified");
        goto cleanup;
    }
    uint8_t roots[VCS_ZCODE_FOCUS_MAX_CLAIMS][32];
    struct vcs_zcode_focus_claim_v1 claims[VCS_ZCODE_FOCUS_MAX_CLAIMS];
    struct vcs_zcode_write_scope_v1 scopes[VCS_ZCODE_FOCUS_MAX_CLAIMS];
    for (size_t i = 0; i < count; i++) {
        memcpy(roots[i], rows[i].root, 32); claims[i] = rows[i].claim;
        scopes[i] = rows[i].scope;
    }
    struct vcs_zcode_focus_v1 focus;
    int64_t now = (int64_t)platform_time_wall_unix();
    bool proved = now > 0 && vcs_zcode_focus_compose(
        &base.task, base.task_root, base.empty_focus.context_root,
        base.loaded.show.story_root, base.loaded.show.status,
        base.empty_focus.flags, roots, count, &focus) == VCS_ZCODE_FOCUS_OK &&
        vcs_zcode_focus_validate_for_context(
            &focus, &base.task, &base.context, roots, count, true) ==
            VCS_ZCODE_FOCUS_OK &&
        vcs_zcode_focus_claim_set_status(
            &focus, claims, scopes, count, now) == ZCL_ONTOLOGY_PROVED;
    for (size_t i = 0; proved && i < count; i++)
        proved = memcmp(claims[i].situation_root,
                        base.situation_root, 32) == 0 &&
            vcs_zcode_focus_claim_work_status(
                &focus, &base.task, &base.task_scope, &claims[i], &scopes[i],
                roots, count, &rows[i].request, &rows[i].admission,
                now) == ZCL_ONTOLOGY_PROVED;
    if (!proved) {
        zfocus_fail(reply, "FOCUS_SNAPSHOT_DISPROVED", "authorize",
                    "active claims are stale, overlapping, out of scope or not admitted by signed work facts");
        goto cleanup;
    }
    uint8_t claim_set_root[32], focus_root[32];
    if (!vcs_object_store_init(workspace) ||
        !zfocus_store_claim_set(workspace, roots, count, claim_set_root) ||
        memcmp(claim_set_root, focus.claim_set_root, 32) != 0 ||
        !zfocus_store_focus(workspace, &focus, focus_root)) {
        zfocus_fail(reply, "FOCUS_SNAPSHOT_STORE_FAILED", "persist",
                    "canonical claim set or focus failed addressed CAS readback verification");
        goto cleanup;
    }
    bool rendered = zfocus_push_root(&reply->data, "focus_root", focus_root) &&
        zfocus_push_root(&reply->data, "situation_root", base.situation_root) &&
        zfocus_push_root(&reply->data, "claim_set_root", claim_set_root) &&
        zfocus_push_claim_roots(&reply->data, rows, count) &&
        json_push_kv_int(&reply->data, "claim_count", (int64_t)count) &&
        json_push_kv_str(&reply->data, "scope_overlap", "DISPROVED") &&
        json_push_kv_str(&reply->data, "admitted_work_status", "PROVED") &&
        json_push_kv_bool(&reply->data, "persisted", true) &&
        json_push_kv_bool(&reply->data, "may_execute", false) &&
        json_push_kv_bool(&reply->data, "may_accept", false) &&
        json_push_kv_bool(&reply->data, "may_deploy", false);
    if (!rendered)
        zfocus_fail(reply, "FOCUS_SNAPSHOT_OUTPUT_FAILED", "render",
                    "published focus snapshot could not be rendered");
cleanup:
    vcs_zcode_agent_context_free(&base.context);
}
