// one-result-type-ok:attach-key-record-helpers
/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Executor-key record wire format and key derivation for fixed
 * compile attachment. */

#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif

#include "services/build_fabric_attach.h"

#if !defined(_WIN32)

#include "build_fabric_attach_key_internal.h"
#include "build_fabric_attach_identity_internal.h"
#include "build_fabric_worker_internal.h"

#include "base/hex.h"
#include "crypto/sha3.h"
#include "platform/toolchain.h"
#include "services/build_fabric_service.h"
#include "vcs/build_action.h"
#include "vcs/proof_reuse.h"
#include "vcs/vcs_object.h"
#include "vcs/zcode_action_input.h"
#include "vcs/zcode_dev.h"

#include <stdio.h>
#include <string.h>

struct bfat_cursor { // hardening-ok: bounds-checked wire cursor, put() refuses overrun
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

bool bfat_record_serialize(const struct bfat_key_fields *f,
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

struct bfat_reader { // hardening-ok: bounds-checked wire reader, take() refuses overrun
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

bool bfat_record_parse(const uint8_t *wire, size_t len,
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

void bfat_record_key(const uint8_t *wire, size_t len, uint8_t out[32])
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
struct zcl_result bfat_fields_for_action(
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
    const char *workspace, struct vcs_package_store *store,
    const struct db_build_job *job,
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
    if (store) {
        uint8_t stored_root[32];
        if (!vcs_proof_ticket_store_put(store, proof_wire,
                                        sizeof(proof_wire), stored_root) ||
            memcmp(stored_root, fields.component_preimage_root, 32) != 0)
            return ZCL_ERR(-1, "executor-component-preimage-content-failed");
    }
    uint8_t wire[BFAT_RECORD_CAP], key[32];
    size_t wire_len = 0;
    if (!bfat_record_serialize(&fields, wire, sizeof(wire), &wire_len))
        return ZCL_ERR(-1, "executor key record does not fit its wire cap");
    bfat_record_key(wire, wire_len, key);
    if (!vcs_object_put_addressed(workspace, key, wire, wire_len))
        return ZCL_ERR(-1, "executor-key-record-cas-store-failed");
    return ZCL_OK;
}


#endif /* !_WIN32 */
