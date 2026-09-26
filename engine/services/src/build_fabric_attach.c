/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Executor-keyed attachment of a duplicate fixed compile request to
 * one already-qualified physical result, with its own signed receipt.
 *
 * The executor key is derived from the immutable bytes the trusted BUILD
 * stage actually consumes: the fixed action descriptor (kind, target,
 * resource policy, declared outputs, recomputed fixed flags/environment
 * roots, proof-policy root), the current host's compiler driver, backend,
 * and ASSEMBLER FILE BYTES (the toolchain capsule binds only the assembler
 * --version string; hashing the bytes here closes the same-version
 * tool-byte-mutation gap executor-side), and the exact .i payload bytes.
 * A physical compile publishes a self-describing CAS record at object id ==
 * key; a second eligible request attaches to the first request's qualified
 * result instead of re-running the compiler.  Reproduction (independent
 * verification) requests carry a distinct profile and are refused by name. */

#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif

#include "services/build_fabric_attach.h"

#if !defined(_WIN32)

#include "build_fabric_observation_internal.h"
#include "build_fabric_attach_identity_internal.h"
#include "build_fabric_worker_internal.h"

#include "base/hex.h"
#include "base/log_macros.h"
#include "base/safe_alloc.h"
#include "crypto/ed25519.h"
#include "crypto/sha3.h"
#include "platform/positioned_file.h"
#include "platform/time_compat.h"
#include "platform/toolchain.h"
#include "services/build_fabric_service.h"
#include "services/build_fabric_worker_evidence.h"
#include "util/spawn.h"
#include "vcs/build_action.h"
#include "vcs/build_artifact_manifest.h"
#include "vcs/build_execution_observation.h"
#include "vcs/vcs_object.h"
#include "vcs/zcode_action_input.h"
#include "vcs/zcode_dev.h"
#include "vcs/zcode_work_output.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum {
    BFAT_SCAN_CAP = 256,
    BFAT_RECEIPT_SCAN_CAP = 257,
    BFAT_RECORD_CAP = 4096,
};

/* Fixed canonical field order of the executor-key record. The serialized
 * record is exactly the hashed preimage: object id == executor key. */
struct bfat_key_fields {
    char kind[BUILD_FABRIC_KIND_MAX + 1];
    char target[BUILD_FABRIC_TARGET_MAX + 1];
    char resource_policy[BUILD_FABRIC_DESCRIPTOR_MAX + 1];
    char declared_outputs[BUILD_FABRIC_DESCRIPTOR_MAX + 1];
    uint8_t flags_root[32];
    uint8_t environment_root[32];
    uint8_t proof_policy_root[32];
    uint8_t toolchain_root[32];
    uint8_t runtime_root[32];
    uint8_t verifier_root[32];
    uint8_t input_bytes_root[32];
    uint8_t component_key[32];
    uint8_t component_preimage_root[32];
};

struct bfat_cursor {
    uint8_t *at;
    size_t left;
};

static bool bfat_put(struct bfat_cursor *c, const void *bytes, size_t len)
{
    if (len > c->left) return false;
    if (len) memcpy(c->at, bytes, len);
    c->at += len;
    c->left -= len;
    return true;
}

static bool bfat_put_u64(struct bfat_cursor *c, uint64_t value)
{
    uint8_t le[8];
    for (unsigned i = 0; i < sizeof(le); i++)
        le[i] = (uint8_t)((value >> (8U * i)) & 0xffU);
    return bfat_put(c, le, sizeof(le));
}

static bool bfat_put_labeled(struct bfat_cursor *c, const char *label,
                             const void *bytes, size_t len)
{
    return bfat_put_u64(c, (uint64_t)strlen(label)) &&
           bfat_put(c, label, strlen(label)) && bfat_put_u64(c, len) &&
           bfat_put(c, bytes, len);
}

static bool bfat_put_text(struct bfat_cursor *c, const char *label,
                          const char *value)
{
    return bfat_put_labeled(c, label, value, value ? strlen(value) : 0);
}

static bool bfat_record_serialize(const struct bfat_key_fields *f,
                                  uint8_t *out, size_t cap, size_t *out_len)
{
    struct bfat_cursor c = { out, cap };
    bool ok = bfat_put_text(&c, "kind", f->kind) &&
        bfat_put_text(&c, "target", f->target) &&
        bfat_put_text(&c, "resource_policy", f->resource_policy) &&
        bfat_put_text(&c, "declared_outputs", f->declared_outputs) &&
        bfat_put_labeled(&c, "flags_root", f->flags_root, 32) &&
        bfat_put_labeled(&c, "environment_root", f->environment_root, 32) &&
        bfat_put_labeled(&c, "proof_policy_root", f->proof_policy_root, 32) &&
        bfat_put_labeled(&c, "executor_toolchain_root", f->toolchain_root,
                         32) &&
        bfat_put_labeled(&c, "runtime_root", f->runtime_root, 32) &&
        bfat_put_labeled(&c, "verifier_root", f->verifier_root, 32) &&
        bfat_put_labeled(&c, "input_bytes_root", f->input_bytes_root, 32) &&
        bfat_put_labeled(&c, "component_proof_key", f->component_key, 32) &&
        bfat_put_labeled(&c, "component_preimage_root",
                         f->component_preimage_root, 32);
    if (!ok) return false;
    *out_len = cap - c.left;
    return true;
}

struct bfat_reader {
    const uint8_t *at;
    size_t left;
};

static bool bfat_take(struct bfat_reader *r, const uint8_t **bytes, size_t len)
{
    if (len > r->left) return false;
    *bytes = r->at;
    r->at += len;
    r->left -= len;
    return true;
}

static bool bfat_take_u64(struct bfat_reader *r, uint64_t *value)
{
    const uint8_t *le;
    if (!bfat_take(r, &le, 8)) return false;
    uint64_t v = 0;
    for (unsigned i = 0; i < 8; i++) v |= (uint64_t)le[i] << (8U * i);
    *value = v;
    return true;
}

/* Read one label/value pair; the label must match exactly. Text values are
 * NUL-terminated into `text` (cap includes the NUL); binary values must be
 * exactly 32 bytes into `digest`. */
static bool bfat_take_labeled(struct bfat_reader *r, const char *label,
                              char *text, size_t text_cap, uint8_t *digest)
{
    uint64_t label_len, value_len;
    const uint8_t *label_bytes, *value;
    if (!bfat_take_u64(r, &label_len) ||
        label_len != strlen(label) ||
        !bfat_take(r, &label_bytes, (size_t)label_len) ||
        memcmp(label_bytes, label, (size_t)label_len) != 0 ||
        !bfat_take_u64(r, &value_len))
        return false;
    if (digest) {
        return value_len == 32 &&
               bfat_take(r, &value, 32) &&
               (memcpy(digest, value, 32), true);
    }
    if (!text || value_len >= text_cap) return false;
    if (!bfat_take(r, &value, (size_t)value_len)) return false;
    if (value_len) memcpy(text, value, (size_t)value_len);
    text[value_len] = '\0';
    return true;
}

static bool bfat_record_parse(const uint8_t *wire, size_t len,
                              struct bfat_key_fields *out)
{
    struct bfat_reader r = { wire, len };
    memset(out, 0, sizeof(*out));
    return bfat_take_labeled(&r, "kind", out->kind, sizeof(out->kind), NULL) &&
        bfat_take_labeled(&r, "target", out->target, sizeof(out->target),
                          NULL) &&
        bfat_take_labeled(&r, "resource_policy", out->resource_policy,
                          sizeof(out->resource_policy), NULL) &&
        bfat_take_labeled(&r, "declared_outputs", out->declared_outputs,
                          sizeof(out->declared_outputs), NULL) &&
        bfat_take_labeled(&r, "flags_root", NULL, 0, out->flags_root) &&
        bfat_take_labeled(&r, "environment_root", NULL, 0,
                          out->environment_root) &&
        bfat_take_labeled(&r, "proof_policy_root", NULL, 0,
                          out->proof_policy_root) &&
        bfat_take_labeled(&r, "executor_toolchain_root", NULL, 0,
                          out->toolchain_root) &&
        bfat_take_labeled(&r, "runtime_root", NULL, 0,
                          out->runtime_root) &&
        bfat_take_labeled(&r, "verifier_root", NULL, 0,
                          out->verifier_root) &&
        bfat_take_labeled(&r, "input_bytes_root", NULL, 0,
                          out->input_bytes_root) &&
        bfat_take_labeled(&r, "component_proof_key", NULL, 0,
                          out->component_key) &&
        bfat_take_labeled(&r, "component_preimage_root", NULL, 0,
                          out->component_preimage_root) &&
        r.left == 0;
}

static void bfat_record_key(const uint8_t *wire, size_t len, uint8_t out[32])
{
    static const char domain[] = BUILD_FABRIC_EXECUTOR_KEY_DOMAIN;
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)domain, sizeof(domain));
    sha3_256_write(&sha, wire, len);
    sha3_256_finalize(&sha, out);
}

void build_fabric_executor_toolchain_root(
    const uint8_t driver_sha3[32], const uint8_t backend_sha3[32],
    const uint8_t assembler_sha3[32], uint8_t out[32])
{
    static const char domain[] = BUILD_FABRIC_EXECUTOR_TOOLCHAIN_DOMAIN;
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)domain, sizeof(domain));
    struct bfat_cursor c;
    uint8_t labeled[3 * (8 + 16 + 8 + 32)];
    c.at = labeled;
    c.left = sizeof(labeled);
    if (!bfat_put_labeled(&c, "driver", driver_sha3, 32) ||
        !bfat_put_labeled(&c, "backend", backend_sha3, 32) ||
        !bfat_put_labeled(&c, "assembler", assembler_sha3, 32)) {
        memset(out, 0, 32);
        return;
    }
    sha3_256_write(&sha, labeled, sizeof(labeled) - c.left);
    sha3_256_finalize(&sha, out);
}

void build_fabric_executor_key_from_parts(
    const char *kind, const char *target, const char *resource_policy,
    const char *declared_outputs, const uint8_t flags_root[32],
    const uint8_t environment_root[32], const uint8_t proof_policy_root[32],
    const uint8_t toolchain_bytes_root[32], const uint8_t input_bytes_root[32],
    uint8_t out_key[32])
{
    struct bfat_key_fields f;
    memset(&f, 0, sizeof(f));
    (void)snprintf(f.kind, sizeof(f.kind), "%s", kind ? kind : "");
    (void)snprintf(f.target, sizeof(f.target), "%s", target ? target : "");
    (void)snprintf(f.resource_policy, sizeof(f.resource_policy), "%s",
                   resource_policy ? resource_policy : "");
    (void)snprintf(f.declared_outputs, sizeof(f.declared_outputs), "%s",
                   declared_outputs ? declared_outputs : "");
    memcpy(f.flags_root, flags_root, 32);
    memcpy(f.environment_root, environment_root, 32);
    if (proof_policy_root) memcpy(f.proof_policy_root, proof_policy_root, 32);
    memcpy(f.toolchain_root, toolchain_bytes_root, 32);
    memcpy(f.input_bytes_root, input_bytes_root, 32);
    uint8_t wire[BFAT_RECORD_CAP];
    size_t wire_len = 0;
    if (!bfat_record_serialize(&f, wire, sizeof(wire), &wire_len)) {
        memset(out_key, 0, 32);
        return;
    }
    bfat_record_key(wire, wire_len, out_key);
}

/* Fill the canonical key fields for one action from checked host identities. */
static struct zcl_result bfat_fields_for_action(
    const struct db_build_action *action,
    const uint8_t toolchain_bytes_root[32],
    const struct vcs_toolchain_capsule_v1 *capsule,
    const uint8_t driver_bytes_root[32],
    const uint8_t backend_bytes_root[32],
    const uint8_t assembler_bytes_root[32],
    const uint8_t runtime_root[32],
    const uint8_t verifier_root[32],
    const uint8_t input_bytes_root[32], struct bfat_key_fields *out,
    struct vcs_component_proof_key_v1 *proof_out)
{
    uint8_t fixed_flags[32], fixed_environment[32];
    char fixed_flags_hex[65], fixed_environment_hex[65];
    if (!vcs_build_action_v1_fixed_flags_root_for_kind(action->kind,
                                                       fixed_flags) ||
        !vcs_build_action_v1_fixed_environment_root_for_kind(
            action->kind, fixed_environment))
        return ZCL_ERR(-1, "executor-fixed-descriptor-stale: unknown kind");
    zcl_hex_encode(fixed_flags, 32, fixed_flags_hex);
    zcl_hex_encode(fixed_environment, 32, fixed_environment_hex);
    if (strcmp(fixed_flags_hex, action->flags_sha3) != 0 ||
        strcmp(fixed_environment_hex, action->environment_sha3) != 0)
        return ZCL_ERR(-1, "executor-fixed-descriptor-stale");
    memset(out, 0, sizeof(*out));
    (void)snprintf(out->kind, sizeof(out->kind), "%s", action->kind);
    (void)snprintf(out->target, sizeof(out->target), "%s", action->target);
    (void)snprintf(out->resource_policy, sizeof(out->resource_policy), "%s",
                   action->resource_policy);
    (void)snprintf(out->declared_outputs, sizeof(out->declared_outputs), "%s",
                   action->declared_outputs);
    memcpy(out->flags_root, fixed_flags, 32);
    memcpy(out->environment_root, fixed_environment, 32);
    if (action->proof_policy_root_sha3[0] &&
        !zcl_hex_decode_lower(action->proof_policy_root_sha3,
                              out->proof_policy_root, 32))
        return ZCL_ERR(-1, "executor-fixed-descriptor-stale: proof policy");
    memcpy(out->toolchain_root, toolchain_bytes_root, 32);
    memcpy(out->runtime_root, runtime_root, 32);
    memcpy(out->verifier_root, verifier_root, 32);
    memcpy(out->input_bytes_root, input_bytes_root, 32);
    struct vcs_fixed_compile_proof_inputs proof_inputs = {
        .capsule = capsule,
        .driver_bytes_sha3 = driver_bytes_root,
        .backend_bytes_sha3 = backend_bytes_root,
        .assembler_bytes_sha3 = assembler_bytes_root,
        .runtime_bytes_sha3 = runtime_root,
        .verifier_bytes_sha3 = verifier_root,
        .input_bytes_sha3 = input_bytes_root,
        .proof_policy_root = out->proof_policy_root,
        .target = action->target,
        .resource_policy = action->resource_policy,
    };
    struct vcs_component_proof_key_v1 proof_key;
    if (!vcs_build_action_v1_compile_proof_key(&proof_inputs, &proof_key) ||
        !vcs_component_proof_key_derive(&proof_key, out->component_key) ||
        !vcs_component_proof_key_preimage_root(
            &proof_key, out->component_preimage_root))
        return ZCL_ERR(-1, "executor-component-key-incomplete");
    if (proof_out) *proof_out = proof_key;
    return ZCL_OK;
}

struct zcl_result build_fabric_executor_key_compose(
    const char *workspace, const struct db_build_action *action,
    const uint8_t input_bytes_root[32],
    uint8_t out_key[32])
{
    if (!workspace || !action || !input_bytes_root || !out_key)
        return ZCL_ERR(-1, "executor key requires action, input, and output");
    uint8_t driver[32], backend[32], assembler[32], toolchain_root[32];
    ZCL_CHECK(build_fabric_executor_host_tool_hashes(driver, backend,
                                                     assembler));
    build_fabric_executor_toolchain_root(driver, backend, assembler,
                                         toolchain_root);
    struct vcs_toolchain_capsule_v1 capsule;
    if (!vcs_toolchain_capsule_v1_capture(&capsule))
        return ZCL_ERR(-1, "executor-toolchain-capsule-unavailable");
    struct platform_toolchain_descriptor descriptor;
    struct vcs_toolchain_capsule_v1 checked;
    uint8_t runtime[32], verifier[32];
    if (!vcs_toolchain_capsule_v1_cached(&checked, &descriptor) ||
        memcmp(&checked, &capsule, sizeof(capsule)) != 0)
        return ZCL_ERR(-1, "executor-toolchain-cache-stale");
    ZCL_CHECK(bfat_runtime_roots(workspace, &descriptor, runtime, verifier));
    struct bfat_key_fields fields;
    ZCL_CHECK(bfat_fields_for_action(action, toolchain_root, &capsule,
                                     driver, backend, assembler,
                                     runtime, verifier,
                                     input_bytes_root, &fields,
                                     NULL));
    uint8_t wire[BFAT_RECORD_CAP];
    size_t wire_len = 0;
    if (!bfat_record_serialize(&fields, wire, sizeof(wire), &wire_len))
        return ZCL_ERR(-1, "executor key record does not fit its wire cap");
    bfat_record_key(wire, wire_len, out_key);
    return ZCL_OK;
}

static bool bfat_identity_matches(
    const struct build_fabric_executor_identity *checked,
    const uint8_t driver[32], const uint8_t backend[32],
    const uint8_t assembler[32], const uint8_t runtime[32],
    const uint8_t verifier[32])
{
    return memcmp(driver, checked->driver, 32) == 0 &&
           memcmp(backend, checked->backend, 32) == 0 &&
           memcmp(assembler, checked->assembler, 32) == 0 &&
           memcmp(runtime, checked->runtime, 32) == 0 &&
           memcmp(verifier, checked->verifier, 32) == 0;
}

static bool bfat_publish_args_valid(
    const char *workspace, const struct db_build_job *job,
    const struct db_build_action *action, const uint8_t input_bytes_root[32],
    const struct build_fabric_executor_identity *checked_identity)
{
    return workspace && job && action && input_bytes_root &&
           checked_identity;
}

struct zcl_result build_fabric_executor_key_publish(
    const char *workspace, const struct db_build_job *job,
    const struct db_build_action *action, const uint8_t input_bytes_root[32],
    const struct build_fabric_executor_identity *checked_identity)
{
    if (!bfat_publish_args_valid(workspace, job, action, input_bytes_root,
                                 checked_identity))
        return ZCL_ERR(-1, "executor key publish requires plan and input");
    struct vcs_toolchain_capsule_v1 capsule;
    uint8_t capsule_root[32];
    char capsule_hex[65];
    if (!vcs_toolchain_capsule_v1_capture(&capsule) ||
        !vcs_toolchain_capsule_v1_root(&capsule, capsule_root))
        return ZCL_ERR(-1, "executor-key-toolchain-stale: capture failed");
    zcl_hex_encode(capsule_root, 32, capsule_hex);
    if (strcmp(capsule_hex, job->toolchain_sha3) != 0)
        return ZCL_ERR(-1, "executor-key-toolchain-stale");
    uint8_t driver[32], backend[32], assembler[32], toolchain_root[32];
    ZCL_CHECK(build_fabric_executor_host_tool_hashes(driver, backend,
                                                     assembler));
    build_fabric_executor_toolchain_root(driver, backend, assembler,
                                         toolchain_root);
    struct platform_toolchain_descriptor descriptor;
    struct vcs_toolchain_capsule_v1 checked;
    uint8_t runtime[32], verifier[32];
    if (!vcs_toolchain_capsule_v1_cached(&checked, &descriptor) ||
        memcmp(&checked, &capsule, sizeof(capsule)) != 0)
        return ZCL_ERR(-1, "executor-toolchain-cache-stale");
    ZCL_CHECK(bfat_runtime_roots(workspace, &descriptor, runtime, verifier));
    if (!bfat_identity_matches(checked_identity, driver, backend, assembler,
                               runtime, verifier))
        return ZCL_ERR(-1, "executor-key-execution-identity-changed");
    struct bfat_key_fields fields;
    struct vcs_component_proof_key_v1 proof_key;
    ZCL_CHECK(bfat_fields_for_action(action, toolchain_root, &capsule,
                                     driver, backend, assembler,
                                     runtime, verifier,
                                     input_bytes_root, &fields,
                                     &proof_key));
    uint8_t proof_wire[VCS_CPK_WIRE_BYTES];
    if (!vcs_component_proof_key_encode(&proof_key, proof_wire) ||
        !vcs_object_put_addressed(workspace,
                                  fields.component_preimage_root,
                                  proof_wire, sizeof(proof_wire)))
        return ZCL_ERR(-1, "executor-component-preimage-store-failed");
    uint8_t wire[BFAT_RECORD_CAP], key[32];
    size_t wire_len = 0;
    if (!bfat_record_serialize(&fields, wire, sizeof(wire), &wire_len))
        return ZCL_ERR(-1, "executor key record does not fit its wire cap");
    bfat_record_key(wire, wire_len, key);
    if (!vcs_object_put_addressed(workspace, key, wire, wire_len))
        return ZCL_ERR(-1, "executor-key-record-cas-store-failed");
    return ZCL_OK;
}

/* Publish the executor-key record so a later eligible duplicate request can
 * attach to this physical result instead of recompiling. The record is an
 * attach index only: the observation, output, and receipt stand on their
 * own, so a publish failure is logged and degrades to a future MISS rather
 * than failing a completed physical build. */
void build_fabric_executor_key_publish_logged(
    const char *workspace, const struct db_build_job *job,
    const struct db_build_action *action, const uint8_t input_bytes_root[32],
    const struct build_fabric_executor_identity *checked_identity)
{
    struct zcl_result published = build_fabric_executor_key_publish(
        workspace, job, action, input_bytes_root, checked_identity);
    if (!published.ok)
        LOG_ERROR("build_fabric",
                  "executor key record not published for %s: %s",
                  action ? action->action_id : "?", published.message);
}

const char *build_fabric_attach_disposition_string(
    enum build_fabric_attach_disposition disposition)
{
    switch (disposition) {
    case BUILD_FABRIC_ATTACH_MISS: return "miss";
    case BUILD_FABRIC_ATTACH_HIT: return "hit";
    case BUILD_FABRIC_ATTACH_REFUSED: return "refused";
    }
    return "refused";
}

static struct zcl_result bfat_refuse(struct build_fabric_attach_report *report,
                                     const char *token)
{
    report->disposition = BUILD_FABRIC_ATTACH_REFUSED;
    (void)snprintf(report->refusal, sizeof(report->refusal), "%s", token);
    return ZCL_ERR(-1, "%s", token);
}

/* Load the action's .i payload with FULL verification before any staging or
 * execution: the zcode path re-derives every binding; the raw path caps the
 * size and re-hashes the bytes against the declared input root. */
static struct zcl_result bfat_load_input(
    const char *workspace, const struct db_build_job *job,
    const struct db_build_action *action, int64_t now,
    uint8_t **out, size_t *out_len, uint8_t input_bytes_root[32],
    char *refusal, size_t refusal_cap)
{
    *out = NULL;
    *out_len = 0;
    uint8_t input_root[32];
    if (!zcl_hex_decode_lower(action->input_root_sha3, input_root, 32))
        return ZCL_ERR(-1, "input-root-invalid");
    struct zcl_result loaded = ZCL_OK;
    if (action->task_root_sha3[0]) {
        struct vcs_zcode_task_v1 task;
        struct vcs_zcode_candidate_v1 candidate;
        struct vcs_zcode_proof_policy_v1 policy;
        bool present = false;
        struct zcl_result context = bfw_load_zcode_context(
            workspace, job, action, now, &task, &candidate, &policy,
            &present);
        if (!context.ok) {
            (void)snprintf(refusal, refusal_cap, "%s", context.message);
            return context;
        }
        if (!present)
            return ZCL_ERR(-1, "input-cas-miss: zcode context absent");
        enum vcs_zcode_action_input_result got =
            vcs_zcode_action_input_load_payload_cas(
                workspace, input_root, &task, &candidate,
                VCS_ZCODE_WORK_BUILD, out, out_len);
        if (got != VCS_ZCODE_ACTION_INPUT_OK) {
            (void)snprintf(refusal, refusal_cap, "%s",
                           vcs_zcode_action_input_result_string(got));
            return ZCL_ERR(-1, "%s", refusal);
        }
    } else {
        if (vcs_object_load_raw(workspace, input_root, out, out_len) != 0 ||
            *out_len == 0 || *out_len > VCS_BUILD_ARTIFACT_MAX_BYTES) {
            free(*out);
            *out = NULL;
            *out_len = 0;
            (void)snprintf(refusal, refusal_cap, "input-cas-miss");
            return ZCL_ERR(-1, "input-cas-miss");
        }
        uint8_t checked[32];
        sha3_256(*out, *out_len, checked);
        if (memcmp(checked, input_root, 32) != 0) {
            free(*out);
            *out = NULL;
            *out_len = 0;
            (void)snprintf(refusal, refusal_cap, "input-cas-corrupt");
            return ZCL_ERR(-1, "input-cas-corrupt");
        }
    }
    struct vcs_build_input_screen_v1 screen;
    vcs_build_input_screen_v1_init(&screen);
    if (!vcs_build_input_screen_v1_update(&screen, *out, *out_len) ||
        !vcs_build_input_screen_v1_finish(&screen)) {
        free(*out);
        *out = NULL;
        *out_len = 0;
        (void)snprintf(refusal, refusal_cap,
                       "input-dependency-closure-unknown");
        return ZCL_ERR(-1, "input-dependency-closure-unknown");
    }
    sha3_256(*out, *out_len, input_bytes_root);
    return loaded;
}

static bool bfat_receipt_signature_valid(
    struct node_db *ndb, const struct db_build_receipt *receipt)
{
    struct db_build_worker worker;
    char expected[BUILD_FABRIC_ID_HEX + 1];
    uint8_t id[32], signature[64], pubkey[32];
    return db_build_worker_find(ndb, receipt->worker_id, &worker) &&
        build_fabric_receipt_id(receipt, expected).ok &&
        strcmp(expected, receipt->receipt_id) == 0 &&
        zcl_hex_decode_lower(receipt->receipt_id, id, sizeof(id)) &&
        zcl_hex_decode_lower(receipt->signature, signature,
                             sizeof(signature)) &&
        zcl_hex_decode_lower(worker.signer_pubkey, pubkey, sizeof(pubkey)) &&
        ed25519_verify(signature, id, sizeof(id), pubkey);
}

/* One accepted row is the donor's canonical receipt only when it binds the
 * donor action, job, and output root with a success exit and an
 * observation. */
static bool bfat_row_binding_exact(
    const struct db_build_receipt *row, const struct db_build_job *donor_job,
    const struct db_build_action *donor_action)
{
    return row->exit_status == 0 &&
        strcmp(row->action_sha3, donor_action->action_id) == 0 &&
        strcmp(row->job_id, donor_job->job_id) == 0 &&
        strcmp(row->output_sha3, donor_action->output_root_sha3) == 0 &&
        row->observation_sha3[0] != '\0';
}

/* Donor receipt scan: exactly one canonical LOCAL_ACCEPTED receipt for the
 * donor action — a second match, a mismatched binding, or a truncated scan
 * disqualifies the donor. */
static bool bfat_donor_receipt_scan(
    struct node_db *ndb, const struct db_build_job *donor_job,
    const struct db_build_action *donor_action,
    struct db_build_receipt *out_receipt)
{
    struct db_build_receipt *rows = zcl_malloc(
        BFAT_RECEIPT_SCAN_CAP * sizeof(*rows), "build.attach.receipts");
    if (!rows) {
        LOG_ERROR("build_fabric", "cannot allocate donor receipt scan buffer");
        return false;
    }
    int count = db_build_job_receipts(ndb, donor_job->job_id, rows,
                                      BFAT_RECEIPT_SCAN_CAP);
    const struct db_build_receipt *accepted = NULL;
    bool complete = count >= 0 && count < BFAT_RECEIPT_SCAN_CAP;
    for (int i = 0; complete && i < count; i++) {
        if (strcmp(rows[i].action_id, donor_action->action_id) != 0 ||
            strcmp(rows[i].trust_state, "LOCAL_ACCEPTED") != 0)
            continue;
        if (accepted ||
            !bfat_row_binding_exact(&rows[i], donor_job, donor_action)) {
            complete = false;
            break;
        }
        accepted = &rows[i];
    }
    if (complete && accepted)
        *out_receipt = *accepted;
    free(rows);
    return complete && accepted != NULL;
}

static bool bfat_donor_worker_live(struct node_db *ndb, const char *worker_id,
                                   int64_t now)
{
    struct db_build_worker worker;
    return db_build_worker_find(ndb, worker_id, &worker) &&
        worker.approved && !worker.revoked &&
        (worker.expires_at == 0 || now < worker.expires_at);
}

/* Donor qualification: exactly one canonical LOCAL_ACCEPTED receipt for the
 * donor action, signature valid, donor worker approved and live, and the
 * physical observation verified against the DONOR job/action. An attached
 * receipt references the donor's observation and fails this check against
 * its own action, so an attached action can never become a donor — chains
 * of attaches are impossible. */
static bool bfat_donor_qualified(
    struct node_db *ndb, const char *workspace,
    const struct db_build_job *donor_job,
    const struct db_build_action *donor_action, int64_t now,
    struct db_build_receipt *out_receipt)
{
    struct db_build_receipt accepted;
    if (!bfat_donor_receipt_scan(ndb, donor_job, donor_action, &accepted))
        return false; /* raw-return-ok:disqualified donor; the scan logs its
                         own alloc failure and the caller reports
                         attach-refused-donor-not-qualified */
    if (!bfat_donor_worker_live(ndb, accepted.worker_id, now) ||
        !bfat_receipt_signature_valid(ndb, &accepted) ||
        !build_fabric_observation_verify(workspace, donor_job, donor_action,
                                         &accepted).ok)
        return false;
    *out_receipt = accepted;
    return true;
}

/* Re-derive one CAS-resident observation and prove the stored bytes hash to
 * the receipt's declared root. */
static struct zcl_result bfat_observation_load(
    const char *workspace, const char *root_hex,
    struct vcs_build_execution_observation_v1 *out)
{
    uint8_t root[32], checked[32], *wire = NULL;
    size_t wire_len = 0;
    if (!zcl_hex_decode_lower(root_hex, root, 32) ||
        vcs_object_load_raw(workspace, root, &wire, &wire_len) != 0)
        return ZCL_ERR(-1, "attach-output-poisoned: observation absent");
    bool ok = vcs_build_execution_observation_v1_parse(wire, wire_len, out) &&
              vcs_build_execution_observation_v1_root(out, checked) &&
              memcmp(root, checked, 32) == 0;
    free(wire);
    return ok ? ZCL_OK
              : ZCL_ERR(-1, "attach-output-poisoned: observation malformed");
}

/* Load a non-zcode chunked artifact manifest and verify its wire root, its
 * self-hash, and the action root it is bound to. */
static struct zcl_result bfat_manifest_load(
    const char *workspace, const uint8_t manifest_root[32],
    const uint8_t action_root[32],
    struct vcs_build_artifact_manifest_v1 *out)
{
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    if (vcs_object_load_raw_bounded(workspace, manifest_root,
                                    VCS_BUILD_ARTIFACT_WIRE_MAX, &wire,
                                    &wire_len) != 0)
        return ZCL_ERR(-1, "attach-output-materialize-failed: manifest");
    uint8_t checked[32];
    bool ok = vcs_build_artifact_manifest_v1_parse(wire, wire_len, out) &&
        vcs_build_artifact_manifest_v1_root(out, checked) &&
        memcmp(checked, manifest_root, 32) == 0 &&
        memcmp(out->action_sha3, action_root, 32) == 0 &&
        out->total_bytes > 0 &&
        out->total_bytes <= VCS_BUILD_ARTIFACT_MAX_BYTES;
    free(wire);
    return ok ? ZCL_OK
              : ZCL_ERR(-1, "attach-output-materialize-failed: manifest root");
}

/* Reassemble one verified manifest's bytes, checking every chunk against
 * it. */
static struct zcl_result bfat_chunks_read(
    const char *workspace,
    const struct vcs_build_artifact_manifest_v1 *manifest, uint8_t *bytes)
{
    uint64_t off = 0;
    bool ok = true;
    for (uint32_t i = 0; ok && i < manifest->chunk_count; i++) {
        uint8_t *chunk = NULL;
        size_t chunk_len = 0;
        size_t take = (size_t)(manifest->total_bytes - off);
        if (take > VCS_BUILD_ARTIFACT_CHUNK_BYTES)
            take = VCS_BUILD_ARTIFACT_CHUNK_BYTES;
        ok = vcs_object_load_raw_bounded(workspace, manifest->chunk_sha3[i],
                                         VCS_BUILD_ARTIFACT_CHUNK_BYTES,
                                         &chunk, &chunk_len) == 0 &&
            chunk_len == take &&
            vcs_build_artifact_manifest_v1_verify_chunk(manifest, i, chunk,
                                                        chunk_len);
        if (ok) memcpy(bytes + off, chunk, chunk_len);
        off += chunk_len;
        free(chunk);
    }
    if (!ok || off != manifest->total_bytes)
        return ZCL_ERR(-1, "attach-output-materialize-failed: chunks");
    return ZCL_OK;
}

/* Read a non-zcode chunked artifact manifest and reassemble its bytes,
 * verifying the manifest root, the bound action root, and every chunk. */
static struct zcl_result bfat_artifact_read(
    const char *workspace, const uint8_t manifest_root[32],
    const uint8_t action_root[32], uint8_t **out, size_t *out_len)
{
    *out = NULL;
    *out_len = 0;
    struct vcs_build_artifact_manifest_v1 manifest;
    ZCL_CHECK(bfat_manifest_load(workspace, manifest_root, action_root,
                                 &manifest));
    uint8_t *bytes = zcl_malloc((size_t)manifest.total_bytes,
                                "build.attach.output");
    if (!bytes)
        return ZCL_ERR(-1, "attach-output-materialize-failed: allocation");
    struct zcl_result chunks = bfat_chunks_read(workspace, &manifest, bytes);
    if (!chunks.ok) {
        free(bytes);
        return chunks;
    }
    *out = bytes;
    *out_len = (size_t)manifest.total_bytes;
    return ZCL_OK;
}

/* The fixed executor consumes identical bytes only when every immutable
 * action input matches. Sequence participates: two fixed steps of one job
 * are distinct actions even when their payloads coincide. task/candidate
 * roots deliberately do NOT participate — distinct provenance is exactly
 * what attaches. */
static bool bfat_donor_fields_match(const struct db_build_action *donor,
                                    const struct db_build_action *req)
{
    return strcmp(donor->kind, req->kind) == 0 &&
        donor->sequence == req->sequence &&
        strcmp(donor->input_root_sha3, req->input_root_sha3) == 0 &&
        strcmp(donor->target, req->target) == 0 &&
        strcmp(donor->flags_sha3, req->flags_sha3) == 0 &&
        strcmp(donor->environment_sha3, req->environment_sha3) == 0 &&
        strcmp(donor->virtual_workdir, req->virtual_workdir) == 0 &&
        strcmp(donor->declared_outputs, req->declared_outputs) == 0 &&
        strcmp(donor->resource_policy, req->resource_policy) == 0 &&
        strcmp(donor->proof_policy_root_sha3, req->proof_policy_root_sha3) ==
            0;
}

static void bfat_worker_id_from_pubkey(const uint8_t pubkey[32], char out[65])
{
    static const char domain[] = "zcl.build_worker.v1";
    struct sha3_256_ctx sha;
    uint8_t digest[32];
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)domain, sizeof(domain));
    sha3_256_write(&sha, pubkey, 32);
    sha3_256_finalize(&sha, digest);
    zcl_hex_encode(digest, 32, out);
}

/* Shared state for one attach pipeline run. The phases below execute in one
 * fixed verify-before-mutate order — request identity, requester worker,
 * executor key, key record, donor scan, output materialization, and only
 * then the single persist transaction — so a half-qualified donor can never
 * reach publication. Each phase returns a refusal token (NULL = proceed);
 * the scan phases also stop the pipeline cleanly on a MISS. */
struct bfat_attach_ctx {
    struct node_db *ndb;
    const char *workspace;
    struct vcs_package_store *store;
    const struct db_build_job *req_job;
    const struct db_build_action *req_action;
    const uint8_t *signer_secret;
    const uint8_t *signer_pubkey;
    struct db_build_receipt *out_receipt;
    struct build_fabric_attach_report *report;
    int64_t started_us;
    int64_t now;
    size_t input_len;
    struct db_build_job job;
    struct db_build_action action;
    char requester_worker_id[BUILD_FABRIC_ID_HEX + 1];
    char capsule_hex[65];
    struct vcs_toolchain_capsule_v1 capsule;
    uint8_t driver_bytes_root[32];
    uint8_t backend_bytes_root[32];
    uint8_t assembler_bytes_root[32];
    uint8_t runtime_root[32];
    uint8_t verifier_root[32];
    uint8_t toolchain_root[32];
    uint8_t key[32];
    struct db_build_action donor_action;
    struct db_build_receipt donor_receipt;
    struct db_build_receipt receipt;
    char refusal[BUILD_FABRIC_ERROR_MAX + 1];
};

static bool bfat_attach_args_ok(const struct bfat_attach_ctx *c)
{
    return c->ndb && c->ndb->open && c->workspace && c->req_job &&
        c->req_action && c->signer_secret && c->signer_pubkey &&
        c->out_receipt && c->report;
}

static struct zcl_result bfat_attach_stop(struct bfat_attach_ctx *c,
                                          const char *refusal)
{
    return refusal ? bfat_refuse(c->report, refusal) : ZCL_OK;
}

static bool bfat_ids_current(const struct db_build_job *req_job,
                             const struct db_build_action *req_action)
{
    char expect_action[BUILD_FABRIC_ID_HEX + 1];
    char expect_job[BUILD_FABRIC_ID_HEX + 1];
    return build_fabric_action_id(req_job, req_action, expect_action).ok &&
        strcmp(expect_action, req_action->action_id) == 0 &&
        build_fabric_job_id(req_job, expect_action, expect_job).ok &&
        strcmp(expect_job, req_job->job_id) == 0 &&
        strcmp(req_action->job_id, req_job->job_id) == 0;
}

static bool bfat_stored_plan_matches(const struct bfat_attach_ctx *c)
{
    return strcmp(c->job.job_id, c->req_job->job_id) == 0 &&
        strcmp(c->job.source_sha256, c->req_job->source_sha256) == 0 &&
        strcmp(c->job.source_cas_sha3, c->req_job->source_cas_sha3) == 0 &&
        strcmp(c->job.toolchain_sha3, c->req_job->toolchain_sha3) == 0 &&
        strcmp(c->job.profile, c->req_job->profile) == 0 &&
        strcmp(c->action.action_id, c->req_action->action_id) == 0 &&
        bfat_donor_fields_match(&c->action, c->req_action) &&
        strcmp(c->action.task_root_sha3, c->req_action->task_root_sha3) == 0 &&
        strcmp(c->action.candidate_root_sha3,
               c->req_action->candidate_root_sha3) == 0;
}

static const char *bfat_check_request_identity(struct bfat_attach_ctx *c)
{
    if (strcmp(c->req_action->kind, VCS_BUILD_ACTION_KIND_V1) != 0)
        return "attach-refused-kind-not-compile";
    if (!bfat_ids_current(c->req_job, c->req_action))
        return "attach-refused-identity-stale";
    if (!db_build_action_find(c->ndb, c->req_action->action_id, &c->action) ||
        !db_build_job_find(c->ndb, c->action.job_id, &c->job))
        return "attach-refused-action-not-planned";
    if (!bfat_stored_plan_matches(c))
        return "attach-refused-identity-stale";
    if (strcmp(c->action.state, "SNAPSHOTTED") != 0 &&
        strcmp(c->action.state, "QUEUED") != 0)
        return "attach-refused-action-state";
    return NULL;
}

static const char *bfat_check_requester_worker(struct bfat_attach_ctx *c)
{
    bfat_worker_id_from_pubkey(c->signer_pubkey, c->requester_worker_id);
    char signer_hex[65];
    zcl_hex_encode(c->signer_pubkey, 32, signer_hex);
    struct db_build_worker worker;
    if (!db_build_worker_find(c->ndb, c->requester_worker_id, &worker) ||
        !worker.approved || worker.revoked ||
        (worker.expires_at != 0 && c->now >= worker.expires_at) ||
        strcmp(worker.signer_pubkey, signer_hex) != 0)
        return "attach-refused-worker-not-approved";
    return NULL;
}

static const char *bfat_compose_requester_key(struct bfat_attach_ctx *c)
{
    uint8_t *input = NULL;
    uint8_t input_bytes_root[32];
    struct zcl_result loaded = bfat_load_input(
        c->workspace, &c->job, &c->action, c->now, &input, &c->input_len,
        input_bytes_root, c->refusal, sizeof(c->refusal));
    if (!loaded.ok) {
        if (!c->refusal[0])
            (void)snprintf(c->refusal, sizeof(c->refusal), "%s",
                           loaded.message);
        return c->refusal;
    }
    struct vcs_toolchain_capsule_v1 capsule;
    struct platform_toolchain_descriptor descriptor;
    uint8_t capsule_root[32];
    if (!vcs_toolchain_capsule_v1_cached(&capsule, &descriptor) ||
        !vcs_toolchain_capsule_v1_root(&capsule, capsule_root)) {
        free(input);
        return "executor-toolchain-cache-unavailable";
    }
    zcl_hex_encode(capsule_root, 32, c->capsule_hex);
    if (strcmp(c->capsule_hex, c->job.toolchain_sha3) != 0) {
        free(input);
        return "attach-refused-toolchain-capsule-stale";
    }
    uint8_t driver[32], backend[32], assembler[32];
    struct zcl_result tools = bfat_cached_tool_hashes(
        &descriptor, driver, backend, assembler);
    if (!tools.ok) {
        free(input);
        return "executor-toolchain-capture-failed";
    }
    struct vcs_toolchain_capsule_v1 checked_capsule;
    struct platform_toolchain_descriptor checked_descriptor;
    if (!vcs_toolchain_capsule_v1_cached(&checked_capsule,
                                          &checked_descriptor) ||
        memcmp(&checked_capsule, &capsule, sizeof(capsule)) != 0 ||
        memcmp(&checked_descriptor, &descriptor, sizeof(descriptor)) != 0) {
        free(input);
        return "executor-toolchain-cache-stale";
    }
    build_fabric_executor_toolchain_root(driver, backend, assembler,
                                         c->toolchain_root);
    struct zcl_result runtime = bfat_runtime_roots(
        c->workspace, &descriptor, c->runtime_root, c->verifier_root);
    if (!runtime.ok) {
        free(input);
        return "executor-runtime-closure-missing";
    }
    c->capsule = capsule;
    memcpy(c->driver_bytes_root, driver, 32);
    memcpy(c->backend_bytes_root, backend, 32);
    memcpy(c->assembler_bytes_root, assembler, 32);
    struct bfat_key_fields fields;
    struct zcl_result keyed = bfat_fields_for_action(
        &c->action, c->toolchain_root, &c->capsule,
        c->driver_bytes_root, c->backend_bytes_root,
        c->assembler_bytes_root, c->runtime_root, c->verifier_root,
        input_bytes_root, &fields, NULL);
    free(input);
    if (!keyed.ok) {
        (void)snprintf(c->refusal, sizeof(c->refusal), "%s", keyed.message);
        return c->refusal;
    }
    uint8_t wire[BFAT_RECORD_CAP];
    size_t wire_len = 0;
    if (!bfat_record_serialize(&fields, wire, sizeof(wire), &wire_len))
        return "executor-key-record-poisoned";
    bfat_record_key(wire, wire_len, c->key);
    zcl_hex_encode(c->key, 32, c->report->executor_key);
    return NULL;
}

/* Returns true when the pipeline must stop: *refusal NULL is a clean MISS
 * (no physical run published this key), non-NULL is the refusal token. */
static bool bfat_key_record_checked(struct bfat_attach_ctx *c,
                                    const char **refusal)
{
    uint8_t *record = NULL;
    size_t record_len = 0;
    if (vcs_object_load_raw(c->workspace, c->key, &record, &record_len) != 0) {
        c->report->attach_wall_us =
            platform_time_monotonic_us() - c->started_us;
        *refusal = NULL;
        return true;
    }
    struct bfat_key_fields record_fields;
    uint8_t record_wire[BFAT_RECORD_CAP], record_key[32];
    size_t record_wire_len = 0;
    bool ok = record_len <= sizeof(record_wire) &&
        bfat_record_parse(record, record_len, &record_fields) &&
        bfat_record_serialize(&record_fields, record_wire,
                              sizeof(record_wire), &record_wire_len) &&
        record_wire_len == record_len &&
        memcmp(record_wire, record, record_len) == 0;
    if (ok) {
        bfat_record_key(record, record_len, record_key);
        ok = memcmp(record_key, c->key, 32) == 0;
    }
    if (ok) {
        uint8_t *preimage = NULL;
        size_t preimage_len = 0;
        struct vcs_component_proof_key_v1 decoded;
        uint8_t derived[32];
        uint8_t root[32];
        ok = vcs_object_load_raw(c->workspace,
                                 record_fields.component_preimage_root,
                                 &preimage, &preimage_len) == 0 &&
            vcs_component_proof_key_decode(preimage, preimage_len, &decoded) &&
            vcs_component_proof_key_preimage_root(&decoded, root) &&
            memcmp(root, record_fields.component_preimage_root, 32) == 0 &&
            vcs_component_proof_key_derive(&decoded, derived) &&
            memcmp(derived, record_fields.component_key, 32) == 0;
        free(preimage);
    }
    free(record);
    if (!ok) {
        *refusal = "executor-key-record-poisoned";
        return true;
    }
    return false;
}

/* One scan candidate keys to the requester only when its immutable inputs
 * match, its job ran under the current capsule, its input reloads and
 * verifies, and its key re-derives from donor fields plus the CURRENT tool
 * bytes to the requester's key. */
static bool bfat_donor_key_matches(const struct bfat_attach_ctx *c,
                                   const struct db_build_job *job,
                                   const struct db_build_action *candidate)
{
    if (strcmp(candidate->kind, VCS_BUILD_ACTION_KIND_V1) != 0 ||
        strcmp(candidate->state, "ACCEPTED") != 0 ||
        !candidate->output_root_sha3[0] ||
        strcmp(candidate->action_id, c->action.action_id) == 0 ||
        !bfat_donor_fields_match(candidate, &c->action))
        return false;
    if (strcmp(job->toolchain_sha3, c->capsule_hex) != 0)
        return false;
    uint8_t *input = NULL;
    size_t input_len = 0;
    uint8_t input_root[32];
    char refusal[BUILD_FABRIC_ERROR_MAX + 1] = {0};
    struct zcl_result loaded = bfat_load_input(
        c->workspace, job, candidate, c->now, &input, &input_len, input_root,
        refusal, sizeof(refusal));
    if (!loaded.ok)
        return false;
    struct bfat_key_fields fields;
    struct zcl_result keyed = bfat_fields_for_action(
        candidate, c->toolchain_root, &c->capsule,
        c->driver_bytes_root, c->backend_bytes_root,
        c->assembler_bytes_root, c->runtime_root, c->verifier_root,
        input_root, &fields, NULL);
    free(input);
    if (!keyed.ok)
        return false;
    uint8_t wire[BFAT_RECORD_CAP], key[32];
    size_t wire_len = 0;
    if (!bfat_record_serialize(&fields, wire, sizeof(wire), &wire_len))
        return false; /* raw-return-ok:unserializable donor fields cannot key
                         a match; the candidate is skipped, not errored */
    bfat_record_key(wire, wire_len, key);
    return memcmp(key, c->key, 32) == 0;
}

/* Donor scan: durable ACCEPTED compile actions whose executor key re-derives
 * to the requester's key. Returns true when the pipeline must stop: *refusal
 * NULL is a clean MISS (no qualified donor), non-NULL is the refusal token. */
static bool bfat_donor_scan(struct bfat_attach_ctx *c, const char **refusal)
{
    struct db_build_job *jobs = zcl_malloc(BFAT_SCAN_CAP * sizeof(*jobs),
                                           "build.attach.jobs");
    struct db_build_action *actions = zcl_malloc(
        BFAT_SCAN_CAP * sizeof(*actions), "build.attach.actions");
    if (!jobs || !actions) {
        free(actions);
        free(jobs);
        *refusal = "attach-refused-scan-alloc-failed";
        return true;
    }
    bool found = false, saw_cross_profile = false, saw_unqualified = false;
    int job_count = db_build_jobs_recent(c->ndb, jobs, BFAT_SCAN_CAP);
    for (int j = 0; !found && j < job_count; j++) {
        int action_count = db_build_job_actions(c->ndb, jobs[j].job_id,
                                                actions, BFAT_SCAN_CAP);
        for (int a = 0; a < action_count; a++) {
            if (!bfat_donor_key_matches(c, &jobs[j], &actions[a]))
                continue;
            if (strcmp(jobs[j].profile, c->job.profile) != 0) {
                /* A distinct profile is a mandated independent verification
                 * run; it must execute physically, never attach. */
                saw_cross_profile = true;
                continue;
            }
            if (!bfat_donor_qualified(c->ndb, c->workspace, &jobs[j],
                                      &actions[a], c->now,
                                      &c->donor_receipt)) {
                saw_unqualified = true;
                continue;
            }
            c->donor_action = actions[a];
            found = true;
        }
    }
    free(actions);
    free(jobs);
    if (found)
        return false;
    if (saw_unqualified)
        *refusal = "attach-refused-donor-not-qualified";
    else if (saw_cross_profile)
        *refusal = "attach-refused-independent-run-required";
    else {
        c->report->attach_wall_us =
            platform_time_monotonic_us() - c->started_us;
        *refusal = NULL;
    }
    return true;
}

/* Fetch the donor output bytes WITHOUT compiling and prove them against the
 * donor's physical observation. */
static const char *bfat_output_fetch(struct bfat_attach_ctx *c,
                                     uint8_t **bytes_out, size_t *len_out)
{
    struct vcs_build_execution_observation_v1 observation;
    struct zcl_result observed = bfat_observation_load(
        c->workspace, c->donor_receipt.observation_sha3, &observation);
    if (!observed.ok) {
        (void)snprintf(c->refusal, sizeof(c->refusal), "%s", observed.message);
        return c->refusal;
    }
    uint8_t donor_output_root[32], donor_action_root[32];
    uint8_t req_action_root[32];
    if (!zcl_hex_decode_lower(c->donor_action.output_root_sha3,
                              donor_output_root, 32) ||
        !zcl_hex_decode_lower(c->donor_action.action_id, donor_action_root,
                              32) ||
        !zcl_hex_decode_lower(c->action.action_id, req_action_root, 32))
        return "attach-output-materialize-failed";
    bool zcode = c->action.task_root_sha3[0] != '\0';
    if (zcode && !c->store)
        return "attach-refused-store-unavailable";
    uint8_t *bytes = NULL;
    size_t len = 0;
    if (zcode) {
        enum vcs_zcode_work_output_result got = vcs_zcode_work_output_get(
            c->store, donor_output_root, donor_action_root, &bytes, &len);
        if (got != VCS_ZCODE_WORK_OUTPUT_OK)
            return vcs_zcode_work_output_result_string(got);
    } else {
        struct zcl_result read = bfat_artifact_read(
            c->workspace, donor_output_root, donor_action_root, &bytes, &len);
        if (!read.ok) {
            (void)snprintf(c->refusal, sizeof(c->refusal), "%s", read.message);
            return c->refusal;
        }
    }
    uint8_t bytes_root[32];
    sha3_256(bytes, len, bytes_root);
    if (memcmp(bytes_root, observation.output_bytes_root, 32) != 0) {
        free(bytes);
        return "attach-output-poisoned";
    }
    *bytes_out = bytes;
    *len_out = len;
    return NULL;
}

/* Store a copy of the verified donor output bound to the requester action
 * root, then re-read and byte-compare the copy before any durable state
 * moves. */
static const char *bfat_output_store_copy(struct bfat_attach_ctx *c,
                                          const uint8_t *bytes, size_t len,
                                          uint8_t copy_root[32])
{
    bool zcode = c->action.task_root_sha3[0] != '\0';
    uint8_t req_action_root[32];
    if (!zcl_hex_decode_lower(c->action.action_id, req_action_root, 32))
        return "attach-output-materialize-failed";
    struct zcl_result copied = ZCL_OK;
    if (zcode) {
        enum vcs_zcode_work_output_result put = vcs_zcode_work_output_put(
            c->store, req_action_root, bytes, len, copy_root);
        if (put != VCS_ZCODE_WORK_OUTPUT_OK)
            copied = ZCL_ERR(-1, "attach-output-materialize-failed: %s",
                             vcs_zcode_work_output_result_string(put));
    } else {
        copied = build_fabric_worker_store_artifact(
            c->workspace, c->action.action_id, bytes, len, copy_root);
    }
    if (copied.ok) {
        uint8_t *reread = NULL;
        size_t reread_len = 0;
        struct zcl_result verify = zcode
            ? (vcs_zcode_work_output_get(c->store, copy_root, req_action_root,
                                         &reread, &reread_len) ==
                       VCS_ZCODE_WORK_OUTPUT_OK
                   ? ZCL_OK
                   : ZCL_ERR(-1, "attach-output-materialize-failed: reread"))
            : bfat_artifact_read(c->workspace, copy_root, req_action_root,
                                 &reread, &reread_len);
        if (verify.ok &&
            (reread_len != len || memcmp(reread, bytes, len) != 0))
            verify = ZCL_ERR(-1, "attach-output-materialize-failed: bytes");
        free(reread);
        copied = verify;
    }
    if (!copied.ok) {
        (void)snprintf(c->refusal, sizeof(c->refusal), "%s", copied.message);
        return c->refusal;
    }
    zcl_hex_encode(copy_root, 32, c->report->output_copy_sha3);
    c->report->restored_bytes = len;
    return NULL;
}

/* The attached receipt names the donor's physical observation (v3 id) and
 * uses the executor key hex as its lease slot: an attach holds no process
 * lease, and the slot stays self-describing. */
static const char *bfat_receipt_prepare(struct bfat_attach_ctx *c)
{
    struct db_build_receipt *receipt = &c->receipt;
    memset(receipt, 0, sizeof(*receipt));
    (void)snprintf(receipt->action_id, sizeof(receipt->action_id), "%s",
                   c->action.action_id);
    (void)snprintf(receipt->job_id, sizeof(receipt->job_id), "%s",
                   c->job.job_id);
    (void)snprintf(receipt->worker_id, sizeof(receipt->worker_id), "%s",
                   c->requester_worker_id);
    (void)snprintf(receipt->lease_id, sizeof(receipt->lease_id), "%s",
                   c->report->executor_key);
    (void)snprintf(receipt->action_sha3, sizeof(receipt->action_sha3), "%s",
                   c->action.action_id);
    (void)snprintf(receipt->output_sha3, sizeof(receipt->output_sha3), "%s",
                   c->donor_action.output_root_sha3);
    (void)snprintf(receipt->observation_sha3,
                   sizeof(receipt->observation_sha3), "%s",
                   c->donor_receipt.observation_sha3);
    (void)snprintf(receipt->confinement, sizeof(receipt->confinement),
                   "landlock=1,seccomp=1,rlimits=1,network=0,gcc=fixed,"
                   "executor-attach=1");
    (void)snprintf(receipt->trust_state, sizeof(receipt->trust_state),
                   "LOCAL_ACCEPTED");
    receipt->exit_status = 0;
    receipt->created_at = c->now;
    if (!build_fabric_receipt_id(receipt, receipt->receipt_id).ok)
        return "attach-persist-failed: receipt id";
    uint8_t receipt_id[32], signature[64];
    if (!zcl_hex_decode_lower(receipt->receipt_id, receipt_id, 32))
        return "attach-persist-failed: receipt id";
    ed25519_sign(signature, receipt_id, sizeof(receipt_id), c->signer_secret,
                 c->signer_pubkey);
    zcl_hex_encode(signature, sizeof(signature), receipt->signature);
    return NULL;
}

/* Advance the job row when every sibling action settled; the job outcome is
 * CACHE_HIT only when every action settled by attach. A sibling scan error
 * leaves the job row untouched without failing the transaction. */
static bool bfat_job_settle_save(struct node_db *ndb,
                                 const struct db_build_job *job, int64_t now)
{
    struct db_build_action *siblings = zcl_malloc(
        BFAT_SCAN_CAP * sizeof(*siblings), "build.attach.siblings");
    if (!siblings)
        return false;
    int count = db_build_job_actions(ndb, job->job_id, siblings,
                                     BFAT_SCAN_CAP);
    bool all_done = count > 0;
    bool all_cache_hit = count > 0;
    for (int i = 0; i < count; i++) {
        bool accepted = strcmp(siblings[i].state, "ACCEPTED") == 0 ||
            strcmp(siblings[i].state, "CACHE_HIT") == 0;
        all_done = all_done && accepted;
        all_cache_hit = all_cache_hit &&
            strcmp(siblings[i].state, "CACHE_HIT") == 0;
    }
    bool ok = true;
    if (all_done) {
        struct db_build_job done_job = *job;
        const char *outcome = all_cache_hit ? "CACHE_HIT" : "ACCEPTED";
        (void)snprintf(done_job.state, sizeof(done_job.state), "%s", outcome);
        (void)snprintf(done_job.outcome, sizeof(done_job.outcome), "%s",
                       outcome);
        done_job.updated_at = now;
        ok = db_build_job_save(ndb, &done_job);
    }
    free(siblings);
    return ok;
}

static const char *bfat_receipt_reread_verify(struct bfat_attach_ctx *c)
{
    struct db_build_receipt persisted;
    char persisted_id[BUILD_FABRIC_ID_HEX + 1];
    uint8_t verify_id[32], verify_sig[64];
    if (!db_build_receipt_find(c->ndb, c->receipt.receipt_id, &persisted) ||
        !build_fabric_receipt_id(&persisted, persisted_id).ok ||
        strcmp(persisted_id, c->receipt.receipt_id) != 0 ||
        strcmp(persisted.signature, c->receipt.signature) != 0 ||
        !zcl_hex_decode_lower(persisted.receipt_id, verify_id, 32) ||
        !zcl_hex_decode_lower(persisted.signature, verify_sig, 64) ||
        !ed25519_verify(verify_sig, verify_id, 32, c->signer_pubkey))
        return "attach-persist-failed: reread";
    return NULL;
}

/* Advance the requester action and persist its OWN signed receipt in one
 * transaction; the persisted receipt is re-read and re-verified before the
 * attach is reported. */
static const char *bfat_persist_attach(struct bfat_attach_ctx *c)
{
    struct db_build_action next = c->action;
    (void)snprintf(next.state, sizeof(next.state), "CACHE_HIT");
    (void)snprintf(next.outcome, sizeof(next.outcome), "CACHE_HIT");
    (void)snprintf(next.output_root_sha3, sizeof(next.output_root_sha3), "%s",
                   c->donor_action.output_root_sha3);
    (void)snprintf(next.worker_id, sizeof(next.worker_id), "%s",
                   c->requester_worker_id);
    (void)snprintf(next.lease_id, sizeof(next.lease_id), "%s",
                   c->report->executor_key);
    next.finished_at = c->now;
    next.updated_at = c->now;
    const char *refusal = bfat_receipt_prepare(c);
    if (refusal)
        return refusal;
    if (!node_db_begin(c->ndb))
        return "attach-persist-failed: transaction";
    bool ok = db_build_action_save(c->ndb, &next) &&
        bfat_job_settle_save(c->ndb, &c->job, c->now) &&
        db_build_receipt_save(c->ndb, &c->receipt) &&
        node_db_commit(c->ndb);
    if (!ok) {
        if (!node_db_rollback(c->ndb))
            LOG_ERROR("build_fabric", "attach persist and rollback failed");
        return "attach-persist-failed";
    }
    return bfat_receipt_reread_verify(c);
}

struct zcl_result build_fabric_attach(
    struct node_db *ndb, const char *workspace, struct vcs_package_store *store,
    const struct db_build_job *req_job, const struct db_build_action *req_action,
    const uint8_t signer_secret[32], const uint8_t signer_pubkey[32],
    struct db_build_receipt *out_receipt,
    struct build_fabric_attach_report *out_report)
{
    if (out_report) memset(out_report, 0, sizeof(*out_report));
    struct bfat_attach_ctx c;
    memset(&c, 0, sizeof(c));
    c.ndb = ndb;
    c.workspace = workspace;
    c.store = store;
    c.req_job = req_job;
    c.req_action = req_action;
    c.signer_secret = signer_secret;
    c.signer_pubkey = signer_pubkey;
    c.out_receipt = out_receipt;
    c.report = out_report;
    if (!bfat_attach_args_ok(&c))
        return ZCL_ERR(-1, "attach requires db, workspace, plan, and keys");
    c.started_us = platform_time_monotonic_us();
    out_report->disposition = BUILD_FABRIC_ATTACH_MISS;
    out_report->compiler_processes = 0;
    c.now = (int64_t)platform_time_wall_unix();

    const char *refusal = bfat_check_request_identity(&c);
    if (!refusal)
        refusal = bfat_check_requester_worker(&c);
    if (!refusal)
        refusal = bfat_compose_requester_key(&c);
    if (refusal)
        return bfat_refuse(out_report, refusal);
    if (bfat_key_record_checked(&c, &refusal) ||
        bfat_donor_scan(&c, &refusal))
        return bfat_attach_stop(&c, refusal);

    (void)snprintf(out_report->donor_action_id,
                   sizeof(out_report->donor_action_id), "%s",
                   c.donor_action.action_id);
    (void)snprintf(out_report->donor_receipt_id,
                   sizeof(out_report->donor_receipt_id), "%s",
                   c.donor_receipt.receipt_id);

    /* Materialize the requester's output WITHOUT compiling: fetch the donor
     * output bytes, prove them against the donor's physical observation, and
     * store a copy bound to the requester action root. */
    uint8_t *bytes = NULL;
    size_t len = 0;
    uint8_t copy_root[32];
    refusal = bfat_output_fetch(&c, &bytes, &len);
    if (!refusal)
        refusal = bfat_output_store_copy(&c, bytes, len, copy_root);
    free(bytes);
    if (!refusal)
        refusal = bfat_persist_attach(&c);
    if (refusal)
        return bfat_refuse(out_report, refusal);

    (void)snprintf(out_report->requester_receipt_id,
                   sizeof(out_report->requester_receipt_id), "%s",
                   c.receipt.receipt_id);
    out_report->disposition = BUILD_FABRIC_ATTACH_HIT;
    out_report->attach_wall_us = platform_time_monotonic_us() - c.started_us;
    LOG_INFO("zcode.proof_perf",
             "schema=zcl.async_proof_perf.v1 action=%s stage=worker_attach "
             "at_unix_us=%lld executor_key=%s donor_action=%s "
             "donor_receipt=%s requester_receipt=%s input_bytes=%llu "
             "output_bytes=%llu attach_us=%lld processes=0 "
             "compiler_processes=0 test_processes=0 cache_hit=1 "
             "total_us=%lld",
             c.action.action_id, (long long)platform_time_realtime_us(),
             out_report->executor_key, c.donor_action.action_id,
             c.donor_receipt.receipt_id, c.receipt.receipt_id,
             (unsigned long long)c.input_len,
             (unsigned long long)out_report->restored_bytes,
             (long long)out_report->attach_wall_us,
             (long long)out_report->attach_wall_us);
    *out_receipt = c.receipt;
    return ZCL_OK;
}

#endif /* !_WIN32 */
