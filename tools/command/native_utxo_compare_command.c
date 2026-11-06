/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * Purpose: compare explicitly admitted offline copies with checked cleanup. */
#include "command/native_command.h"
#include "command/native_package_artifact.h"
#include "config/command_catalog.h"
#include "config/utxo_copy_capture_validate.h"
#include "config/utxo_copy_compare.h"
#include "chain/chainparams.h"
#include "base/hex.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define UCO_PATH "core.consensus.utxo.compare.offline"
struct uco_input {
    const char *artifact, *projection;
    uint8_t projection_digest[32], accepted[32];
    enum utxo_mirror_byte_order order;
    unsigned limit;
};
struct uco_owners {
    uint8_t *manifest; size_t manifest_length;
    struct consensus_state_artifact_evidence *artifact;
    struct utxo_mirror_read_snapshot *projection;
    struct utxo_copy_capture *capture;
    struct zcl_command_cleanup_slot *slots;
};
static void uco_fail(struct zcl_command_reply *reply, const char *code)
{
    json_free(&reply->data); json_set_object(&reply->data);
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
        ZCL_COMMAND_EXIT_BLOCKED, code, "compare", false, false,
        "no completed comparison is available", UCO_PATH);
}
static const char *uco_string(const struct json_value *v, const char *key)
{
    const struct json_value *s = json_get(v, key);
    return s && s->type == JSON_STR ? json_get_str(s) : NULL;
}
static bool uco_path(const char *path)
{
    return path && path[0] && strlen(path) < 4096;
}
static bool uco_sources(const struct zcl_command_request *r, struct uco_input *out)
{
    out->artifact = uco_string(r->input, "artifact_file");
    out->projection = uco_string(r->input, "projection_file");
    const char *manifest = uco_string(r->input, "capture_manifest_file");
    const char *digest = uco_string(r->input, "projection_sha3_256");
    const char *accepted = uco_string(r->input, "accepted_manifest_sha3_256");
    const char *order = uco_string(r->input, "producer_byte_order");
    if (!uco_path(out->artifact) || !uco_path(out->projection) || !uco_path(manifest) ||
        !digest || !accepted || !order || !zcl_hex_decode_lower(digest, out->projection_digest, 32) ||
        !zcl_hex_decode_lower(accepted, out->accepted, 32)) return false;
    if (strcmp(order, "little") == 0) out->order = UTXO_MIRROR_LITTLE_ENDIAN;
    else if (strcmp(order, "big") == 0) out->order = UTXO_MIRROR_BIG_ENDIAN;
    else return false;
    return true;
}
static bool uco_input(const struct zcl_command_request *r, struct uco_input *out)
{
    const struct zcl_command_spec *spec = zcl_command_registry_find(zcl_command_catalog(), UCO_PATH, NULL);
    char why[256];
    if (!r || !spec || !zcl_command_registry_input_validate(spec, r->input, why, sizeof(why))) return false;
    if (!uco_sources(r, out)) return false;
    const struct json_value *limit = json_get(r->input, "example_limit");
    if (limit && (limit->type != JSON_INT || limit->val.i < 0 || limit->val.i > 32)) return false;
    out->limit = limit ? (unsigned)limit->val.i : 8;
    return true;
}
static bool uco_cancelled(void *context)
{
    const struct zcl_command_context *c = context;
    return c->invocation->cancelled(c->invocation->cancel_context);
}
static bool uco_open(const struct zcl_command_request *r, const struct uco_input *in,
                     struct uco_owners *owners)
{
    if (!zcl_native_package_artifact_read_file(r->input, "capture_manifest_file",
        "accepted_manifest_sha3_256", 16384, &owners->manifest, &owners->manifest_length)) return false;
    struct zcl_result admitted = consensus_state_artifact_evidence_open(in->artifact, -1, &owners->artifact);
    owners->slots[0].owner = owners->artifact;
    if (!admitted.ok || !owners->artifact) return false;
    int32_t next = -1;
    bool opened = utxo_mirror_read_snapshot_open(in->projection, in->order,
        in->projection_digest, &owners->projection, &next);
    owners->slots[1].owner = owners->projection;
    if (!opened) return false;
    struct utxo_copy_capture_request capture = {
        .manifest = (const char *)owners->manifest, .manifest_len = owners->manifest_length,
        .accepted_manifest_sha3 = in->accepted, .network = chain_params_get(),
        .authority = owners->artifact, .projection = owners->projection
    };
    return utxo_copy_capture_open(&capture, &owners->capture) == UTXO_COPY_CAPTURE_VALIDATED;
}
static bool uco_artifact_release(void **owner)
{
    struct consensus_state_artifact_evidence *typed = *owner;
    bool ok = consensus_state_artifact_evidence_close(&typed);
    *owner = typed; return ok;
}
static bool uco_projection_release(void **owner)
{
    struct utxo_mirror_read_snapshot *typed = *owner;
    bool ok = !typed || utxo_mirror_read_snapshot_abort(&typed);
    *owner = typed; return ok;
}
static bool uco_reserve(const struct zcl_command_request *request, struct uco_owners *owners)
{
    const struct zcl_command_invocation_runtime *r = request->context->invocation;
    if (!r->reserve_cleanup || !r->reserve_cleanup(r->cleanup_context, 2, &owners->slots) ||
        !owners->slots || owners->slots[0].owner || owners->slots[1].owner ||
        owners->slots[0].release_failed || owners->slots[1].release_failed) return false;
    owners->slots[0].release = uco_artifact_release;
    owners->slots[1].release = uco_projection_release;
    return true;
}
static bool uco_close(struct uco_owners *owners)
{
    utxo_copy_capture_free(owners->capture); owners->capture = NULL;
    free(owners->manifest); owners->manifest = NULL;
    bool ok = true;
    for (unsigned i = 0; i < 2; i++) {
        struct zcl_command_cleanup_slot *slot = &owners->slots[i];
        bool released = slot->release(&slot->owner);
        if (!released || slot->owner) slot->release_failed = true;
        if (slot->release_failed) ok = false;
    }
    /* Refused owners stay in caller-owned slots. No retry or transfer can
     * erase this invocation's failed checked-cleanup witness. */
    return ok;
}
static bool uco_u64(struct json_value *v, const char *key, uint64_t value)
{
    char text[32]; int n = snprintf(text, sizeof(text), "%llu", (unsigned long long)value);
    return n > 0 && (size_t)n < sizeof(text) && json_push_kv_str(v, key, text);
}
static bool uco_hash(struct json_value *v, const char *key, const uint8_t hash[32])
{
    char text[65]; zcl_hex_encode(hash, 32, text); return json_push_kv_str(v, key, text);
}
static bool uco_example(struct json_value *out, const struct utxo_copy_compare_example *e)
{
    json_set_object(out);
    return json_push_kv_int(out, "kind", e->kind) && json_push_kv_int(out, "fields", e->fields) &&
        uco_hash(out, "txid", e->txid) && json_push_kv_int(out, "vout", e->vout) &&
        json_push_kv_int(out, "authority_value", e->authority_value) &&
        json_push_kv_int(out, "projection_value", e->projection_value) &&
        uco_u64(out, "authority_script_length", e->authority_script_len) &&
        uco_u64(out, "projection_script_length", e->projection_script_len) &&
        uco_hash(out, "authority_script_sha3", e->authority_script_sha3) &&
        uco_hash(out, "projection_script_sha3", e->projection_script_sha3);
}
static bool uco_examples(struct json_value *out, const struct utxo_copy_compare_report *r)
{
    struct json_value examples = {0}; json_set_array(&examples); bool ok = true;
    for (unsigned i = 0; ok && i < r->example_count; i++) {
        struct json_value example = {0};
        ok = uco_example(&example, &r->examples[i]) && json_push_back(&examples, &example);
        json_free(&example);
    }
    if (ok) ok = json_push_kv(out, "examples", &examples);
    json_free(&examples); return ok;
}
static bool uco_report_counts(struct json_value *v, const struct utxo_copy_compare_report *r)
{
    return json_push_kv_bool(v, "complete", true) &&
        json_push_kv_str(v, "comparison", r->status == UTXO_COPY_COMPARE_EQUAL ? "equal" : "different") &&
        json_push_kv_str(v, "capture_binding", "externally_attested") &&
        uco_u64(v, "authority_count", r->authority_count) &&
        uco_u64(v, "projection_count", r->projection_count) &&
        uco_u64(v, "authority_only", r->authority_only) &&
        uco_u64(v, "projection_only", r->projection_only) &&
        uco_u64(v, "shared_equal", r->shared_equal) &&
        uco_u64(v, "shared_different", r->shared_different);
}
static bool uco_report_frontier(struct json_value *v, const struct utxo_copy_compare_report *r)
{
    return uco_u64(v, "count_delta_magnitude", r->count_delta_magnitude) &&
        json_push_kv_bool(v, "count_delta_negative", r->count_delta_negative) &&
        json_push_kv_int(v, "shared_fields", r->shared_fields) &&
        json_push_kv_int(v, "next_height", r->next_height) &&
        json_push_kv_int(v, "last_applied_height", r->last_applied_height) &&
        uco_hash(v, "authority_root", r->authority_root) &&
        uco_hash(v, "projection_root", r->projection_root) &&
        uco_hash(v, "authority_file_sha3", r->authority_file_sha3) &&
        uco_hash(v, "projection_file_sha3", r->projection_file_sha3);
}
static bool uco_report_binding(struct json_value *v, const struct utxo_copy_compare_report *r)
{
    return uco_hash(v, "artifact_digest", r->artifact_digest) &&
        uco_hash(v, "network_genesis", r->network_genesis) &&
        uco_hash(v, "block_hash", r->block_hash) &&
        uco_u64(v, "authority_generation", r->authority_generation) &&
        json_push_kv_bool(v, "examples_truncated", r->examples_truncated) &&
        uco_examples(v, r);
}
static bool uco_report(struct json_value *v, const struct utxo_copy_compare_report *r)
{
    return uco_report_counts(v, r) && uco_report_frontier(v, r) && uco_report_binding(v, r);
}
static bool uco_finished(const struct zcl_command_request *request,
    const struct utxo_copy_compare_report *result, bool opened, bool closed,
    enum utxo_copy_compare_status status)
{
    return opened && closed && !uco_cancelled((void *)request->context) &&
        (status == UTXO_COPY_COMPARE_EQUAL || status == UTXO_COPY_COMPARE_DIFFERENT) &&
        result->complete && result->counts_valid && result->roots_valid;
}
void zcl_native_handle_core_consensus_utxo_compare_offline(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!reply) return;
    struct uco_input in = {0};
    if (!uco_input(request, &in)) { uco_fail(reply, "INVALID_INPUT"); return; }
    if (!request->context || !request->context->invocation ||
        !request->context->invocation->cancelled) {
        uco_fail(reply, "CANCELLATION_UNAVAILABLE"); return;
    }
    struct uco_owners owners = {0}; struct utxo_copy_compare_report result = {0};
    if (!uco_reserve(request, &owners)) { uco_fail(reply, "CLEANUP_UNAVAILABLE"); return; }
    bool opened = !uco_cancelled((void *)request->context) && uco_open(request, &in, &owners);
    enum utxo_copy_compare_status status = UTXO_COPY_COMPARE_ERROR;
    if (opened) {
        struct utxo_copy_compare_inputs inputs = {
            .authority = owners.artifact, .projection = &owners.projection,
            .capture = owners.capture, .example_limit = in.limit,
            .cancelled = uco_cancelled, .cancel_ctx = (void *)request->context
        };
        status = utxo_copy_compare_run(&inputs, &result);
        owners.slots[1].owner = owners.projection;
    }
    bool closed = uco_close(&owners);
    if (!uco_finished(request, &result, opened, closed, status)) {
        uco_fail(reply, closed ? "COMPARISON_INCOMPLETE" : "COMPARISON_CLEANUP_FAILED"); return;
    }
    json_free(&reply->data); json_set_object(&reply->data);
    if (!uco_report(&reply->data, &result)) { uco_fail(reply, "COMPARISON_ENCODING_FAILED"); return; }
    reply->status = ZCL_COMMAND_STATUS_PASSED; reply->exit_code = ZCL_COMMAND_EXIT_OK;
}

#define UBV_PATH "core.consensus.bundle.validate"
static void ubv_fail(struct zcl_command_reply *reply, const char *code, const char *message)
{
    json_free(&reply->data); json_set_object(&reply->data);
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_BLOCKED,
        code, "validate", false, false, message, UBV_PATH);
}
static bool ubv_report(struct json_value *out, const struct consensus_state_bundle_manifest *m,
                       const uint8_t whole[32])
{
    return json_push_kv_str(out, "validation_scope", "artifact_semantics") &&
        json_push_kv_int(out, "height", m->height) &&
        uco_hash(out, "block_hash", m->block_hash) &&
        uco_hash(out, "artifact_digest", m->artifact_digest) &&
        uco_hash(out, "whole_file_sha3_256", whole) &&
        uco_hash(out, "utxo_root", m->utxo_root) &&
        uco_u64(out, "utxo_count", m->utxo_count) &&
        uco_u64(out, "anchor_count", m->anchor_count) &&
        uco_u64(out, "nullifier_count", m->nullifier_count);
}
static const char *ubv_input(const struct zcl_command_request *request)
{
    const struct zcl_command_spec *spec = zcl_command_registry_find(zcl_command_catalog(), UBV_PATH, NULL);
    char why[256];
    if (!request || !request->input || !spec ||
        !zcl_command_registry_input_validate(spec, request->input, why, sizeof why)) return NULL;
    const char *path = uco_string(request->input, "artifact_file");
    return uco_path(path) && path[0] == '/' ? path : NULL;
}
static struct zcl_command_cleanup_slot *ubv_reserve(const struct zcl_command_request *request)
{
    if (!request->context || !request->context->invocation || !request->context->invocation->reserve_cleanup)
        return NULL;
    struct zcl_command_cleanup_slot *slot = NULL;
    const struct zcl_command_invocation_runtime *runtime = request->context->invocation;
    if (!runtime->reserve_cleanup(runtime->cleanup_context, ZCL_COMMAND_CLEANUP_SLOTS_MAX, &slot) ||
        !slot || slot->owner || slot->release_failed || slot[1].owner || slot[1].release_failed) return NULL;
    slot->release = uco_artifact_release;
    return slot;
}
static bool ubv_evidence(const char *path, struct zcl_command_cleanup_slot *slot,
                         struct consensus_state_bundle_manifest *manifest,
                         uint8_t whole[32], struct zcl_result *result)
{
    struct consensus_state_artifact_evidence *artifact = NULL;
    *result = consensus_state_artifact_evidence_open(path, -1, &artifact);
    slot->owner = artifact;
    return result->ok && artifact && consensus_state_artifact_evidence_manifest_copy(artifact, manifest) &&
        consensus_state_artifact_evidence_file_digest(artifact, whole);
}
void zcl_native_handle_core_consensus_bundle_validate(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!reply) return;
    const char *path = ubv_input(request);
    if (!path) { ubv_fail(reply, "INVALID_INPUT", "an absolute artifact_file is required"); return; }
    struct zcl_command_cleanup_slot *slot = ubv_reserve(request);
    if (!slot) { ubv_fail(reply, "CLEANUP_UNAVAILABLE", "cannot reserve checked cleanup"); return; }
    struct consensus_state_bundle_manifest manifest = {0}; uint8_t whole[32] = {0};
    struct zcl_result result = {0};
    bool valid = ubv_evidence(path, slot, &manifest, whole, &result);
    bool closed = slot->release(&slot->owner);
    if (!closed || slot->owner) slot->release_failed = true;
    if (slot->release_failed) { ubv_fail(reply, "CLEANUP_FAILED", "artifact cleanup failed"); return; }
    if (!valid) { ubv_fail(reply, "ARTIFACT_INVALID", result.ok ? "artifact evidence changed" : result.message); return; }
    json_free(&reply->data); json_set_object(&reply->data);
    if (!ubv_report(&reply->data, &manifest, whole)) { ubv_fail(reply, "ENCODING_FAILED", "cannot encode validated artifact"); return; }
    reply->status = ZCL_COMMAND_STATUS_PASSED; reply->exit_code = ZCL_COMMAND_EXIT_OK;
}
