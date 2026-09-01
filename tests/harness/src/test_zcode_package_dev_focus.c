/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Prove a real C23 package task resumes through rooted focus handoff. */
#include "test/test_core.h"

#include "base/hex.h"
#include "crypto/ed25519.h"
#include "crypto/sha3.h"
#include "json/json.h"
#include "platform/environment_compat.h"
#include "platform/os_proc.h"
#include "platform/time_compat.h"
#include "vcs/package_recipe.h"
#include "vcs/vcs.h"
#include "vcs/vcs_object.h"
#include "vcs/zcode_agent_context.h"
#include "vcs/zcode_dev.h"
#include "vcs/zcode_focus.h"
#include "vcs/zcode_work_swarm.h"
#include "vcs/zcode_write_scope.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if !defined(_WIN32)
#include <errno.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

struct zpf_metrics {
    uint64_t coordination_bytes;
    uint32_t tool_calls;
    uint32_t retries;
    uint32_t conflicts;
};

#define ZPF_ENV_WORKSPACE "ZCL_TEST_FOCUS_WORKSPACE"
#define ZPF_ENV_FOCUS_ROOT "ZCL_TEST_FOCUS_ROOT"
#define ZPF_ENV_HANDOFF_ROOT "ZCL_TEST_FOCUS_HANDOFF_ROOT"
#define ZPF_ENV_ADMISSION_A_ROOT "ZCL_TEST_FOCUS_ADMISSION_A_ROOT"
#define ZPF_ENV_ADMISSION_B_ROOT "ZCL_TEST_FOCUS_ADMISSION_B_ROOT"
#define ZPF_ENV_RESUME_UNIX "ZCL_TEST_FOCUS_RESUME_UNIX"

static bool zpf_json_root(const struct json_value *object, const char *key,
                          uint8_t out[32])
{
    const struct json_value *value = object ? json_get(object, key) : NULL;
    return value && value->type == JSON_STR &&
           zcl_hex_decode_lower(json_get_str(value), out, 32);
}

static bool zpf_load(const char *workspace, const uint8_t root[32],
                     size_t maximum, uint8_t **wire, size_t *wire_len,
                     struct zpf_metrics *metrics)
{
    if (!workspace || !root || !wire || !wire_len || !metrics)
        return false;
    *wire = NULL;
    *wire_len = 0;
    metrics->tool_calls++;
    return vcs_object_load_raw_bounded(
               workspace, root, maximum, wire, wire_len) == 0;
}

static bool zpf_store_addressed(const char *workspace,
                                const uint8_t root[32],
                                const uint8_t *wire, size_t wire_len,
                                struct zpf_metrics *metrics)
{
    if (!workspace || !root || !wire || wire_len == 0 || !metrics)
        return false;
    metrics->tool_calls++;
    if (!vcs_object_put_addressed(workspace, root, wire, wire_len))
        return false;
    uint8_t *check = NULL;
    size_t check_len = 0;
    bool ok = zpf_load(workspace, root, wire_len, &check, &check_len,
                       metrics) &&
              check_len == wire_len && memcmp(check, wire, wire_len) == 0;
    free(check);
    return ok;
}

static bool zpf_store_content(const char *workspace, const uint8_t *wire,
                              size_t wire_len, uint8_t root[32],
                              struct zpf_metrics *metrics)
{
    if (!workspace || !wire || wire_len == 0 || !root || !metrics)
        return false;
    metrics->tool_calls++;
    if (!vcs_object_put(workspace, wire, wire_len, VCS_TAG_BLOB, root))
        return false;
    uint8_t *check = NULL;
    size_t check_len = 0;
    bool ok = zpf_load(workspace, root, wire_len, &check, &check_len,
                       metrics) &&
              check_len == wire_len && memcmp(check, wire, wire_len) == 0;
    free(check);
    return ok;
}

static bool zpf_transfer(const char *from, const char *to,
                         const uint8_t root[32], size_t maximum,
                         struct zpf_metrics *metrics)
{
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    if (!zpf_load(from, root, maximum, &wire, &wire_len, metrics))
        return false;
    bool ok = zpf_store_addressed(to, root, wire, wire_len, metrics);
    if (ok) metrics->coordination_bytes += wire_len;
    free(wire);
    return ok;
}

static bool zpf_load_task(const char *workspace, const uint8_t root[32],
                          struct vcs_zcode_task_v1 *task,
                          struct zpf_metrics *metrics)
{
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    uint8_t check[32];
    bool ok = zpf_load(workspace, root, VCS_ZCODE_TASK_WIRE_BYTES,
                       &wire, &wire_len, metrics) &&
        vcs_zcode_task_parse(wire, wire_len, task) == VCS_ZCODE_DEV_OK &&
        vcs_zcode_task_root(task, check) == VCS_ZCODE_DEV_OK &&
        memcmp(check, root, 32) == 0;
    free(wire);
    return ok;
}

static bool zpf_load_context(
    const char *workspace, const uint8_t root[32],
    const struct vcs_zcode_task_v1 *task, const uint8_t task_root[32],
    struct vcs_zcode_agent_context_v1 *context, size_t *wire_bytes,
    struct zpf_metrics *metrics)
{
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    vcs_zcode_agent_context_init(context);
    bool ok = zpf_load(workspace, root, (size_t)task->max_context_bytes,
                       &wire, &wire_len, metrics) &&
        vcs_zcode_agent_context_parse(
            wire, wire_len, (size_t)task->max_context_bytes, context) ==
            VCS_ZCODE_AGENT_CONTEXT_OK &&
        vcs_zcode_agent_context_validate_for_task(
            context, task, task_root, root, true) ==
            VCS_ZCODE_AGENT_CONTEXT_OK;
    free(wire);
    if (!ok) {
        vcs_zcode_agent_context_free(context);
        vcs_zcode_agent_context_init(context);
        return false;
    }
    if (wire_bytes) *wire_bytes = wire_len;
    return true;
}

static bool zpf_load_scope(const char *workspace, const uint8_t root[32],
                           struct vcs_zcode_write_scope_v1 *scope,
                           struct zpf_metrics *metrics)
{
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    uint8_t check[32];
    bool ok = zpf_load(workspace, root, VCS_ZCODE_WRITE_SCOPE_WIRE_MAX,
                       &wire, &wire_len, metrics) &&
        vcs_zcode_write_scope_parse(wire, wire_len, scope) ==
            VCS_ZCODE_WRITE_SCOPE_OK &&
        vcs_zcode_write_scope_root(scope, check) ==
            VCS_ZCODE_WRITE_SCOPE_OK &&
        memcmp(check, root, 32) == 0;
    free(wire);
    return ok;
}

static bool zpf_load_receipt(
    const char *workspace, const uint8_t root[32],
    struct vcs_zcode_work_receipt_v1 *receipt,
    struct zpf_metrics *metrics)
{
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    uint8_t check[32];
    bool ok = zpf_load(workspace, root, VCS_ZCODE_WORK_RECEIPT_WIRE_BYTES,
                       &wire, &wire_len, metrics) &&
        vcs_zcode_work_receipt_parse(wire, wire_len, receipt) ==
            VCS_ZCODE_DEV_OK &&
        vcs_zcode_work_receipt_id(receipt, check) == VCS_ZCODE_DEV_OK &&
        memcmp(check, root, 32) == 0 &&
        vcs_zcode_work_receipt_verify(
            receipt, receipt->signer_pubkey) == VCS_ZCODE_DEV_OK;
    free(wire);
    return ok;
}

static bool zpf_load_recipe(const char *workspace, const uint8_t root[32],
                            struct zpf_metrics *metrics)
{
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    uint8_t check[32];
    struct vcs_package_recipe recipe;
    vcs_package_recipe_init(&recipe);
    bool ok = zpf_load(workspace, root, VCS_PACKAGE_RECIPE_MAX_WIRE_BYTES,
                       &wire, &wire_len, metrics) &&
        vcs_package_recipe_parse(wire, wire_len, &recipe) ==
            VCS_PACKAGE_RECIPE_OK &&
        vcs_package_recipe_root(&recipe, check) == VCS_PACKAGE_RECIPE_OK &&
        memcmp(check, root, 32) == 0;
    vcs_package_recipe_free(&recipe);
    free(wire);
    return ok;
}

static bool zpf_store_scope(const char *workspace,
                            const struct vcs_zcode_write_scope_v1 *scope,
                            uint8_t root[32], size_t *wire_bytes,
                            struct zpf_metrics *metrics)
{
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    bool ok = vcs_zcode_write_scope_root(scope, root) ==
                  VCS_ZCODE_WRITE_SCOPE_OK &&
        vcs_zcode_write_scope_serialize(scope, &wire, &wire_len) ==
                  VCS_ZCODE_WRITE_SCOPE_OK &&
        zpf_store_addressed(workspace, root, wire, wire_len, metrics);
    if (ok && wire_bytes) *wire_bytes = wire_len;
    free(wire);
    return ok;
}

static bool zpf_store_work_message(
    const char *workspace, const struct vcs_zcode_work_swarm_message *message,
    const uint8_t *semantic_root, uint8_t carrier_root[32],
    size_t *wire_bytes, struct zpf_metrics *metrics)
{
    uint8_t wire[VCS_ZCODE_WORK_SWARM_MAX_WIRE_BYTES];
    size_t wire_len = 0;
    if (!vcs_zcode_work_swarm_serialize(
            message, wire, sizeof(wire), &wire_len))
        return false;
    bool ok = semantic_root
        ? zpf_store_addressed(
              workspace, semantic_root, wire, wire_len, metrics)
        : zpf_store_content(
              workspace, wire, wire_len, carrier_root, metrics);
    if (ok && semantic_root && carrier_root)
        memcpy(carrier_root, semantic_root, 32);
    if (ok && wire_bytes) *wire_bytes = wire_len;
    return ok;
}

static bool zpf_load_work_message(
    const char *workspace, const uint8_t root[32], uint8_t expected_type,
    struct vcs_zcode_work_swarm_message *message,
    struct zpf_metrics *metrics)
{
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    bool ok = zpf_load(workspace, root,
                       VCS_ZCODE_WORK_SWARM_MAX_WIRE_BYTES,
                       &wire, &wire_len, metrics) &&
        vcs_zcode_work_swarm_parse(wire, wire_len, message) &&
        message->type == expected_type;
    free(wire);
    return ok;
}

static bool zpf_store_claim(
    const char *workspace, const struct vcs_zcode_focus_claim_v1 *claim,
    uint8_t root[32], struct zpf_metrics *metrics)
{
    uint8_t wire[VCS_ZCODE_FOCUS_CLAIM_WIRE_BYTES];
    return vcs_zcode_focus_claim_root(claim, root) == VCS_ZCODE_FOCUS_OK &&
        vcs_zcode_focus_claim_serialize(claim, wire) ==
            VCS_ZCODE_FOCUS_OK &&
        zpf_store_addressed(workspace, root, wire, sizeof(wire), metrics);
}

static bool zpf_load_claim(
    const char *workspace, const uint8_t root[32],
    struct vcs_zcode_focus_claim_v1 *claim, struct zpf_metrics *metrics)
{
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    uint8_t check[32];
    bool ok = zpf_load(workspace, root, VCS_ZCODE_FOCUS_CLAIM_WIRE_BYTES,
                       &wire, &wire_len, metrics) &&
        vcs_zcode_focus_claim_parse(wire, wire_len, claim) ==
            VCS_ZCODE_FOCUS_OK &&
        vcs_zcode_focus_claim_root(claim, check) == VCS_ZCODE_FOCUS_OK &&
        memcmp(check, root, 32) == 0;
    free(wire);
    return ok;
}

static bool zpf_store_report(
    const char *workspace, const struct vcs_zcode_specialist_report_v1 *report,
    uint8_t root[32], struct zpf_metrics *metrics)
{
    uint8_t wire[VCS_ZCODE_SPECIALIST_REPORT_WIRE_BYTES];
    return vcs_zcode_specialist_report_root(report, root) ==
            VCS_ZCODE_FOCUS_OK &&
        vcs_zcode_specialist_report_serialize(report, wire) ==
            VCS_ZCODE_FOCUS_OK &&
        zpf_store_addressed(workspace, root, wire, sizeof(wire), metrics);
}

static bool zpf_load_report(
    const char *workspace, const uint8_t root[32],
    struct vcs_zcode_specialist_report_v1 *report,
    struct zpf_metrics *metrics)
{
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    uint8_t check[32];
    bool ok = zpf_load(workspace, root,
                       VCS_ZCODE_SPECIALIST_REPORT_WIRE_BYTES,
                       &wire, &wire_len, metrics) &&
        vcs_zcode_specialist_report_parse(wire, wire_len, report) ==
            VCS_ZCODE_FOCUS_OK &&
        vcs_zcode_specialist_report_root(report, check) ==
            VCS_ZCODE_FOCUS_OK &&
        memcmp(check, root, 32) == 0;
    free(wire);
    return ok;
}

static bool zpf_store_focus(
    const char *workspace, const struct vcs_zcode_focus_v1 *focus,
    uint8_t root[32], struct zpf_metrics *metrics)
{
    uint8_t wire[VCS_ZCODE_FOCUS_WIRE_BYTES];
    return vcs_zcode_focus_root(focus, root) == VCS_ZCODE_FOCUS_OK &&
        vcs_zcode_focus_serialize(focus, wire) == VCS_ZCODE_FOCUS_OK &&
        zpf_store_addressed(workspace, root, wire, sizeof(wire), metrics);
}

static bool zpf_load_focus(
    const char *workspace, const uint8_t root[32],
    struct vcs_zcode_focus_v1 *focus, struct zpf_metrics *metrics)
{
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    uint8_t check[32];
    bool ok = zpf_load(workspace, root, VCS_ZCODE_FOCUS_WIRE_BYTES,
                       &wire, &wire_len, metrics) &&
        vcs_zcode_focus_parse(wire, wire_len, focus) ==
            VCS_ZCODE_FOCUS_OK &&
        vcs_zcode_focus_root(focus, check) == VCS_ZCODE_FOCUS_OK &&
        memcmp(check, root, 32) == 0;
    free(wire);
    return ok;
}

static bool zpf_status_parse(const char *name,
                             enum zcl_ontology_status *status)
{
    if (!name || !status) return false;
    if (strcmp(name, "PROVED") == 0)
        *status = ZCL_ONTOLOGY_PROVED;
    else if (strcmp(name, "DISPROVED") == 0)
        *status = ZCL_ONTOLOGY_DISPROVED;
    else if (strcmp(name, "BOTH") == 0)
        *status = ZCL_ONTOLOGY_BOTH;
    else if (strcmp(name, "UNKNOWN") == 0)
        *status = ZCL_ONTOLOGY_UNKNOWN;
    else if (strcmp(name, "INCOMPLETE") == 0)
        *status = ZCL_ONTOLOGY_INCOMPLETE;
    else
        return false;
    return true;
}

static bool zpf_store_handoff(
    const char *workspace, const struct vcs_zcode_focus_handoff_v1 *handoff,
    uint8_t root[32], struct zpf_metrics *metrics)
{
    uint8_t wire[VCS_ZCODE_FOCUS_HANDOFF_WIRE_BYTES];
    return vcs_zcode_focus_handoff_root(handoff, root) ==
            VCS_ZCODE_FOCUS_OK &&
        vcs_zcode_focus_handoff_serialize(handoff, wire) ==
            VCS_ZCODE_FOCUS_OK &&
        zpf_store_addressed(workspace, root, wire, sizeof(wire), metrics);
}

static void zpf_request(
    struct vcs_zcode_work_request_v1 *request, uint64_t request_id,
    const struct vcs_zcode_task_v1 *task, const uint8_t task_root[32],
    const uint8_t candidate_root[32], const uint8_t action_root[32],
    const uint8_t input_root[32], const uint8_t context_root[32],
    uint8_t work_kind, int64_t deadline_unix)
{
    memset(request, 0, sizeof(*request));
    request->request_id = request_id;
    memcpy(request->task_root, task_root, 32);
    memcpy(request->candidate_root, candidate_root, 32);
    memcpy(request->action_root, action_root, 32);
    memcpy(request->input_root, input_root, 32);
    memcpy(request->context_root, context_root, 32);
    memcpy(request->proof_policy_root, task->proof_policy_root, 32);
    memcpy(request->toolchain_capsule_root,
           task->toolchain_capsule_root, 32);
    request->work_kind = work_kind;
    request->target = VCS_ZCODE_WORK_TARGET_LINUX_X86_64_V3;
    request->max_cpu_seconds = task->max_cpu_seconds;
    request->max_memory_bytes = task->max_memory_bytes;
    request->max_output_bytes = task->max_output_bytes;
    request->deadline_unix = deadline_unix;
}

static bool zpf_admission(
    struct vcs_zcode_work_admission_v1 *admission,
    const struct vcs_zcode_work_request_v1 *request, uint16_t slot,
    uint8_t disposition, const uint8_t worker_secret[32],
    const uint8_t worker_pubkey[32])
{
    memset(admission, 0, sizeof(*admission));
    admission->request_id = request->request_id;
    memcpy(admission->requester_pubkey, request->requester_pubkey, 32);
    memcpy(admission->action_root, request->action_root, 32);
    admission->lease_generation = 1;
    admission->deadline_unix = request->deadline_unix;
    admission->slot = slot;
    admission->disposition = disposition;
    return vcs_zcode_work_admission_seal(
        admission, worker_secret, worker_pubkey);
}

static void zpf_order_claims(
    const struct vcs_zcode_focus_claim_v1 *claim_a,
    const struct vcs_zcode_write_scope_v1 *scope_a,
    const uint8_t root_a[32],
    const struct vcs_zcode_focus_claim_v1 *claim_b,
    const struct vcs_zcode_write_scope_v1 *scope_b,
    const uint8_t root_b[32], struct vcs_zcode_focus_claim_v1 claims[2],
    struct vcs_zcode_write_scope_v1 scopes[2], uint8_t roots[2][32],
    size_t *from_index, size_t *next_index)
{
    bool a_first = memcmp(root_a, root_b, 32) < 0;
    claims[0] = a_first ? *claim_a : *claim_b;
    claims[1] = a_first ? *claim_b : *claim_a;
    scopes[0] = a_first ? *scope_a : *scope_b;
    scopes[1] = a_first ? *scope_b : *scope_a;
    memcpy(roots[0], a_first ? root_a : root_b, 32);
    memcpy(roots[1], a_first ? root_b : root_a, 32);
    *from_index = a_first ? 0u : 1u;
    *next_index = a_first ? 1u : 0u;
}

#if !defined(_WIN32)
static bool zpf_load_work_carrier(
    const char *workspace, const uint8_t root[32], uint8_t expected_type,
    struct vcs_zcode_work_swarm_message *message,
    struct zpf_metrics *metrics)
{
    if (!workspace || !root || !message || !metrics)
        return false;
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    uint8_t derived[32];
    struct sha3_256_ctx hash;
    bool ok = zpf_load(workspace, root,
                       VCS_ZCODE_WORK_SWARM_MAX_WIRE_BYTES,
                       &wire, &wire_len, metrics);
    sha3_256_init(&hash);
    uint8_t tag = VCS_TAG_BLOB;
    sha3_256_write(&hash, &tag, 1);
    if (ok && wire_len > 0)
        sha3_256_write(&hash, wire, wire_len);
    sha3_256_finalize(&hash, derived);
    ok = ok && memcmp(derived, root, 32) == 0 &&
        vcs_zcode_work_swarm_parse(wire, wire_len, message) &&
        message->type == expected_type;
    free(wire);
    return ok;
}

static bool zpf_load_handoff(
    const char *workspace, const uint8_t root[32],
    struct vcs_zcode_focus_handoff_v1 *handoff,
    struct zpf_metrics *metrics)
{
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    uint8_t check[32];
    bool ok = zpf_load(workspace, root,
                       VCS_ZCODE_FOCUS_HANDOFF_WIRE_BYTES,
                       &wire, &wire_len, metrics) &&
        vcs_zcode_focus_handoff_parse(wire, wire_len, handoff) ==
            VCS_ZCODE_FOCUS_OK &&
        vcs_zcode_focus_handoff_root(handoff, check) ==
            VCS_ZCODE_FOCUS_OK &&
        memcmp(check, root, 32) == 0;
    free(wire);
    return ok;
}

static bool zpf_process_reload_focus(
    const char *workspace, const uint8_t focus_root[32],
    const uint8_t *handoff_root, const uint8_t *admission_a_root,
    const uint8_t *admission_b_root, int64_t resume_unix)
{
    bool accepted = false;
    struct zpf_metrics metrics = {0};
    uint8_t *claim_set_wire = NULL;
    size_t claim_set_wire_len = 0;
    struct vcs_zcode_agent_context_v1 context;
    vcs_zcode_agent_context_init(&context);
    struct vcs_zcode_focus_v1 focus;
    struct vcs_zcode_task_v1 task;
    struct vcs_zcode_write_scope_v1 task_scope;
    uint8_t claim_roots[2][32];
    size_t claim_count = 0;
    struct vcs_zcode_focus_claim_v1 claims[2];
    struct vcs_zcode_write_scope_v1 scopes[2];

    if (!workspace || !focus_root ||
        !zpf_load_focus(workspace, focus_root, &focus, &metrics) ||
        focus.claim_count != 2 ||
        !zpf_load_task(workspace, focus.task_root, &task, &metrics) ||
        !zpf_load_scope(workspace, task.write_scope_root,
                        &task_scope, &metrics) ||
        !zpf_load_context(workspace, focus.context_root, &task,
                          focus.task_root, &context, NULL, &metrics) ||
        !zpf_load(workspace, focus.claim_set_root,
                  VCS_ZCODE_FOCUS_CLAIM_SET_WIRE_MAX,
                  &claim_set_wire, &claim_set_wire_len, &metrics) ||
        vcs_zcode_focus_claim_set_parse(
            claim_set_wire, claim_set_wire_len, claim_roots, 2,
            &claim_count) != VCS_ZCODE_FOCUS_OK || claim_count != 2)
        goto cleanup;
    free(claim_set_wire);
    claim_set_wire = NULL;
    for (size_t i = 0; i < claim_count; i++) {
        if (!zpf_load_claim(workspace, claim_roots[i],
                            &claims[i], &metrics) ||
            !zpf_load_scope(workspace, claims[i].write_scope_root,
                            &scopes[i], &metrics))
            goto cleanup;
    }
    int64_t snapshot_unix = claims[0].created_unix;
    if (claims[1].created_unix > snapshot_unix)
        snapshot_unix = claims[1].created_unix;
    if (vcs_zcode_focus_validate_for_context(
            &focus, &task, &context, claim_roots, claim_count, true) !=
            VCS_ZCODE_FOCUS_OK ||
        vcs_zcode_focus_claim_set_status(
            &focus, claims, scopes, claim_count, snapshot_unix) !=
            ZCL_ONTOLOGY_PROVED ||
        vcs_zcode_focus_claim_authority_status(
            &focus, &task, &task_scope, &claims[0], &scopes[0],
            snapshot_unix) != ZCL_ONTOLOGY_PROVED ||
        vcs_zcode_focus_claim_authority_status(
            &focus, &task, &task_scope, &claims[1], &scopes[1],
            snapshot_unix) != ZCL_ONTOLOGY_PROVED)
        goto cleanup;
    if (!handoff_root) {
        accepted = true;
        goto cleanup;
    }
    if (!admission_a_root || !admission_b_root || resume_unix <= 0)
        goto cleanup;

    struct vcs_zcode_focus_handoff_v1 handoff;
    struct vcs_zcode_specialist_report_v1 report;
    if (!zpf_load_handoff(workspace, handoff_root, &handoff, &metrics) ||
        !zpf_load_report(workspace, handoff.report_root,
                         &report, &metrics))
        goto cleanup;
    size_t from_index = claim_count, next_index = claim_count;
    for (size_t i = 0; i < claim_count; i++) {
        if (memcmp(claim_roots[i], handoff.from_claim_root, 32) == 0)
            from_index = i;
        if (memcmp(claim_roots[i], handoff.next_claim_root, 32) == 0)
            next_index = i;
    }
    if (from_index >= claim_count || next_index >= claim_count ||
        from_index == next_index)
        goto cleanup;

    struct vcs_zcode_work_swarm_message from_request, next_request;
    struct vcs_zcode_work_swarm_message from_admission, next_admission;
    if (!zpf_load_work_message(
            workspace, claims[from_index].intent_root,
            VCS_ZCODE_WORK_SWARM_REQUEST, &from_request, &metrics) ||
        !zpf_load_work_message(
            workspace, claims[next_index].intent_root,
            VCS_ZCODE_WORK_SWARM_REQUEST, &next_request, &metrics) ||
        !zpf_load_work_carrier(
            workspace, admission_a_root,
            VCS_ZCODE_WORK_SWARM_ADMISSION, &from_admission, &metrics) ||
        !zpf_load_work_carrier(
            workspace, admission_b_root,
            VCS_ZCODE_WORK_SWARM_ADMISSION, &next_admission, &metrics))
        goto cleanup;
    struct vcs_zcode_work_receipt_v1 receipt;
    if (!zpf_load_receipt(workspace, report.evidence_root,
                          &receipt, &metrics))
        goto cleanup;
    accepted = vcs_zcode_focus_handoff_validate_for_work(
        &focus, &task, &context, &task_scope, claims, scopes, claim_count,
        from_index, next_index, &from_request.body.request,
        &from_admission.body.admission, &next_request.body.request,
        &next_admission.body.admission, &receipt, &report, &handoff,
        resume_unix) == VCS_ZCODE_FOCUS_OK;

cleanup:
    free(claim_set_wire);
    vcs_zcode_agent_context_free(&context);
    return accepted;
}

static bool zpf_wait_child(pid_t pid, int *status)
{
    pid_t waited;
    do {
        waited = waitpid(pid, status, 0);
    } while (waited < 0 && errno == EINTR);
    return waited == pid;
}

static bool zpf_silence_exec_output(void)
{
    int null_fd = open("/dev/null", O_WRONLY | O_CLOEXEC);
    if (null_fd < 0)
        return false;
    bool ok =
        (null_fd == STDOUT_FILENO || dup2(null_fd, STDOUT_FILENO) >= 0) &&
        (null_fd == STDERR_FILENO || dup2(null_fd, STDERR_FILENO) >= 0);
    if (null_fd != STDOUT_FILENO && null_fd != STDERR_FILENO &&
        close(null_fd) != 0)
        ok = false;
    return ok;
}

static pid_t zpf_spawn_exec_agent(
    const char *role, const char *workspace,
    const uint8_t focus_root[32], const uint8_t *handoff_root,
    const uint8_t *admission_a_root, const uint8_t *admission_b_root,
    int64_t resume_unix)
{
    if (!role || !workspace || !focus_root)
        return -1;
    char executable[4096];
    if (!os_proc_exe_path(executable, sizeof(executable)))
        return -1;
    char focus_hex[65], handoff_hex[65] = "";
    char admission_a_hex[65] = "", admission_b_hex[65] = "";
    char resume_text[32];
    zcl_hex_encode(focus_root, 32, focus_hex);
    if (handoff_root) zcl_hex_encode(handoff_root, 32, handoff_hex);
    if (admission_a_root)
        zcl_hex_encode(admission_a_root, 32, admission_a_hex);
    if (admission_b_root)
        zcl_hex_encode(admission_b_root, 32, admission_b_hex);
    int n = snprintf(resume_text, sizeof(resume_text), "%" PRId64,
                     resume_unix);
    if (n < 0 || (size_t)n >= sizeof(resume_text))
        return -1;

    pid_t child = fork();
    if (child != 0)
        return child;
    bool env_ok =
        platform_environment_set("ZCL_TEST_FORK_GROUP",
                                 "test_zcode_package_dev", 1) == 0 &&
        platform_environment_set("ZCL_TEST_FORK_ROLE", role, 1) == 0 &&
        platform_environment_set(ZPF_ENV_WORKSPACE, workspace, 1) == 0 &&
        platform_environment_set(ZPF_ENV_FOCUS_ROOT, focus_hex, 1) == 0 &&
        platform_environment_set(ZPF_ENV_HANDOFF_ROOT, handoff_hex, 1) == 0 &&
        platform_environment_set(ZPF_ENV_ADMISSION_A_ROOT,
                                 admission_a_hex, 1) == 0 &&
        platform_environment_set(ZPF_ENV_ADMISSION_B_ROOT,
                                 admission_b_hex, 1) == 0 &&
        platform_environment_set(ZPF_ENV_RESUME_UNIX, resume_text, 1) == 0;
    if (env_ok && zpf_silence_exec_output())
        execl(executable, executable,
              "--exact=test_zcode_package_dev", (char *)NULL);
    _exit(127);
}
#endif

int zpd_focus_worker_role(const char *role)
{
#if defined(_WIN32)
    (void)role;
    return 1;
#else
    const char *workspace = getenv(ZPF_ENV_WORKSPACE);
    const char *focus_text = getenv(ZPF_ENV_FOCUS_ROOT);
    bool successor = role && strcmp(role, "shared-focus-successor") == 0;
    bool source = role && strcmp(role, "shared-focus-source") == 0;
    uint8_t focus_root[32], handoff_root[32];
    uint8_t admission_a_root[32], admission_b_root[32];
    if ((!source && !successor) || !workspace || !workspace[0] ||
        !focus_text || !zcl_hex_decode_lower(focus_text, focus_root, 32))
        return 1;
    if (source)
        return zpf_process_reload_focus(
            workspace, focus_root, NULL, NULL, NULL, 0) ? 0 : 1;

    const char *handoff_text = getenv(ZPF_ENV_HANDOFF_ROOT);
    const char *admission_a_text = getenv(ZPF_ENV_ADMISSION_A_ROOT);
    const char *admission_b_text = getenv(ZPF_ENV_ADMISSION_B_ROOT);
    const char *resume_text = getenv(ZPF_ENV_RESUME_UNIX);
    char *end = NULL;
    errno = 0;
    int64_t resume_unix = resume_text ? strtoll(resume_text, &end, 10) : 0;
    if (!handoff_text || !admission_a_text || !admission_b_text ||
        !resume_text || errno != 0 || !end || *end != '\0' ||
        resume_unix <= 0 ||
        !zcl_hex_decode_lower(handoff_text, handoff_root, 32) ||
        !zcl_hex_decode_lower(admission_a_text, admission_a_root, 32) ||
        !zcl_hex_decode_lower(admission_b_text, admission_b_root, 32))
        return 1;
    return zpf_process_reload_focus(
        workspace, focus_root, handoff_root, admission_a_root,
        admission_b_root, resume_unix) ? 0 : 1;
#endif
}

static size_t zpf_exec_clean_agent_acceptance(
    const char *worker_a, const char *worker_b,
    const uint8_t focus_root[32], const uint8_t handoff_root[32],
    const uint8_t admission_a_root[32],
    const uint8_t admission_b_root[32], int64_t resume_unix)
{
#if defined(_WIN32)
    (void)worker_a;
    (void)worker_b;
    (void)focus_root;
    (void)handoff_root;
    (void)admission_a_root;
    (void)admission_b_root;
    (void)resume_unix;
    return 0;
#else
    if (!worker_a || !worker_b || !focus_root || !handoff_root ||
        !admission_a_root || !admission_b_root || resume_unix <= 0)
        return 0;
    pid_t worker_a_pid = zpf_spawn_exec_agent(
        "shared-focus-source", worker_a, focus_root,
        NULL, NULL, NULL, 0);
    if (worker_a_pid < 0) return 0;
    pid_t worker_b_pid = zpf_spawn_exec_agent(
        "shared-focus-successor", worker_b, focus_root,
        handoff_root, admission_a_root, admission_b_root, resume_unix);
    int worker_a_status = -1, worker_b_status = -1;
    if (worker_b_pid < 0) {
        (void)zpf_wait_child(worker_a_pid, &worker_a_status);
        return 0;
    }
    bool waited_a = zpf_wait_child(worker_a_pid, &worker_a_status);
    bool waited_b = zpf_wait_child(worker_b_pid, &worker_b_status);
    size_t proved = 0;
    if (waited_a && WIFEXITED(worker_a_status) &&
        WEXITSTATUS(worker_a_status) == 0)
        proved++;
    if (waited_b && WIFEXITED(worker_b_status) &&
        WEXITSTATUS(worker_b_status) == 0)
        proved++;
    return proved;
#endif
}

#define ZPF_REQUIRE(condition)                                                \
    do {                                                                      \
        if (!(condition)) {                                                   \
            fprintf(stderr, "real focus handoff failed at %s:%d: %s\n",     \
                    __FILE__, __LINE__, #condition);                          \
            goto cleanup;                                                     \
        }                                                                     \
    } while (0)

bool zpd_real_focus_preedit_acceptance(
    const char *workspace, const char *work_id,
    const struct json_value *focus_data,
    const struct json_value *duplicate_data,
    uint8_t out_focus_root[32], int64_t *out_observed_us)
{
    bool accepted = false;
    struct zpf_metrics metrics = {0};
    struct vcs_zcode_agent_context_v1 context;
    vcs_zcode_agent_context_init(&context);
    uint8_t *claim_set_wire = NULL;
    size_t claim_set_wire_len = 0;
    uint8_t worker_a_secret[32] = {0}, worker_b_secret[32] = {0};

    ZPF_REQUIRE(workspace && workspace[0] && work_id && work_id[0] &&
                focus_data && focus_data->type == JSON_OBJ &&
                duplicate_data && duplicate_data->type == JSON_OBJ &&
                out_focus_root && out_observed_us);
    memset(out_focus_root, 0, 32);
    *out_observed_us = 0;

    uint8_t task_root[32], source_root[32], goal_root[32], context_root[32];
    uint8_t story_root[32], empty_focus_root[32], situation_root[32];
    ZPF_REQUIRE(zpf_json_root(focus_data, "task_root", task_root));
    ZPF_REQUIRE(zpf_json_root(focus_data, "source_root", source_root));
    ZPF_REQUIRE(zpf_json_root(focus_data, "goal_root", goal_root));
    ZPF_REQUIRE(zpf_json_root(focus_data, "agent_context_root",
                              context_root));
    ZPF_REQUIRE(zpf_json_root(focus_data, "story_root", story_root));
    ZPF_REQUIRE(zpf_json_root(focus_data, "focus_root", empty_focus_root));
    ZPF_REQUIRE(zpf_json_root(focus_data, "focus_situation_root",
                              situation_root));
    enum zcl_ontology_status story_status = ZCL_ONTOLOGY_INCOMPLETE;
    ZPF_REQUIRE(zpf_status_parse(
        json_get_str(json_get(focus_data, "story_status")), &story_status));
    ZPF_REQUIRE(strcmp(json_get_str(json_get(
                           focus_data, "orientation_status")),
                       "PROVED") == 0);

    const char *duplicate_kind = json_get_str(json_get(
        duplicate_data, "conflict_kind"));
    const char *duplicate_task = json_get_str(json_get(
        duplicate_data, "task_root"));
    const char *duplicate_source = json_get_str(json_get(
        duplicate_data, "source_root"));
    const char *duplicate_goal = json_get_str(json_get(
        duplicate_data, "goal_root"));
    const char *duplicate_context = json_get_str(json_get(
        duplicate_data, "agent_context_root"));
    const char *duplicate_assignment = json_get_str(json_get(
        duplicate_data, "assignment_status"));
    const char *duplicate_execution = json_get_str(json_get(
        duplicate_data, "active_execution"));
    char task_hex[65], source_hex[65], goal_hex[65], context_hex[65];
    zcl_hex_encode(task_root, 32, task_hex);
    zcl_hex_encode(source_root, 32, source_hex);
    zcl_hex_encode(goal_root, 32, goal_hex);
    zcl_hex_encode(context_root, 32, context_hex);
    ZPF_REQUIRE(duplicate_kind && duplicate_task && duplicate_source &&
                duplicate_goal && duplicate_context && duplicate_assignment &&
                duplicate_execution &&
                strcmp(duplicate_kind, "DUPLICATE_ACTIVE_WORK") == 0 &&
                strcmp(duplicate_task, task_hex) == 0 &&
                strcmp(duplicate_source, source_hex) == 0 &&
                strcmp(duplicate_goal, goal_hex) == 0 &&
                strcmp(duplicate_context, context_hex) == 0 &&
                strcmp(duplicate_assignment, "UNOBSERVED") == 0 &&
                strcmp(duplicate_execution, "UNOBSERVED") == 0);

    struct vcs_zcode_task_v1 task;
    struct vcs_zcode_write_scope_v1 task_scope;
    size_t context_wire_bytes = 0;
    ZPF_REQUIRE(zpf_load_task(workspace, task_root, &task, &metrics));
    ZPF_REQUIRE(memcmp(task.source_root, source_root, 32) == 0 &&
                memcmp(task.goal_root, goal_root, 32) == 0);
    ZPF_REQUIRE(zpf_load_context(workspace, context_root, &task, task_root,
                                 &context, &context_wire_bytes, &metrics));
    ZPF_REQUIRE(context_wire_bytes > 0);
    ZPF_REQUIRE(zpf_load_scope(workspace, task.write_scope_root,
                               &task_scope, &metrics));

    struct vcs_zcode_focus_v1 empty_focus;
    uint8_t check_root[32], check_situation[32];
    ZPF_REQUIRE(vcs_zcode_focus_compose(
                    &task, task_root, context_root, story_root, story_status,
                    0, NULL, 0, &empty_focus) == VCS_ZCODE_FOCUS_OK);
    ZPF_REQUIRE(vcs_zcode_focus_root(&empty_focus, check_root) ==
                    VCS_ZCODE_FOCUS_OK &&
                vcs_zcode_focus_situation_root(
                    &empty_focus, check_situation) == VCS_ZCODE_FOCUS_OK &&
                memcmp(check_root, empty_focus_root, 32) == 0 &&
                memcmp(check_situation, situation_root, 32) == 0);

    struct vcs_zcode_write_scope_v1 scope_a, scope_b;
    vcs_zcode_write_scope_init(&scope_a);
    vcs_zcode_write_scope_init(&scope_b);
    ZPF_REQUIRE(vcs_zcode_write_scope_add(&scope_a, "src/x.c") ==
                    VCS_ZCODE_WRITE_SCOPE_OK &&
                vcs_zcode_write_scope_add(&scope_b, "include/x.h") ==
                    VCS_ZCODE_WRITE_SCOPE_OK);
    uint8_t scope_a_root[32], scope_b_root[32];
    ZPF_REQUIRE(zpf_store_scope(workspace, &scope_a, scope_a_root,
                                NULL, &metrics));
    ZPF_REQUIRE(zpf_store_scope(workspace, &scope_b, scope_b_root,
                                NULL, &metrics));

    uint8_t worker_a_seed[32], worker_a_key[32];
    uint8_t worker_b_seed[32], worker_b_key[32];
    memset(worker_a_seed, 0xb7, sizeof(worker_a_seed));
    memset(worker_b_seed, 0xb9, sizeof(worker_b_seed));
    ed25519_keypair(worker_a_key, worker_a_secret, worker_a_seed);
    ed25519_keypair(worker_b_key, worker_b_secret, worker_b_seed);
    int64_t observed_unix = (int64_t)platform_time_wall_unix();
    ZPF_REQUIRE(observed_unix > 0 && task.expires_unix > observed_unix);
    struct vcs_zcode_focus_claim_v1 claim_a = {
        .schema_version = VCS_ZCODE_FOCUS_VERSION,
        .created_unix = observed_unix,
        .expires_unix = task.expires_unix,
    };
    struct vcs_zcode_focus_claim_v1 claim_b = claim_a;
    memcpy(claim_a.situation_root, situation_root, 32);
    memcpy(claim_a.claimant_root, worker_a_key, 32);
    memcpy(claim_a.write_scope_root, scope_a_root, 32);
    /* Pre-edit claims are proposals, not admitted work. Their intent is the
     * exact task; admitted claims below bind a signed work request instead. */
    memcpy(claim_a.intent_root, task_root, 32);
    memcpy(claim_a.evidence_plan_root, task.proof_policy_root, 32);
    memcpy(claim_b.situation_root, situation_root, 32);
    memcpy(claim_b.claimant_root, worker_b_key, 32);
    memcpy(claim_b.write_scope_root, scope_b_root, 32);
    memcpy(claim_b.intent_root, task_root, 32);
    memcpy(claim_b.evidence_plan_root, task.proof_policy_root, 32);
    uint8_t claim_a_root[32], claim_b_root[32];
    ZPF_REQUIRE(zpf_store_claim(workspace, &claim_a, claim_a_root,
                                &metrics));
    ZPF_REQUIRE(zpf_store_claim(workspace, &claim_b, claim_b_root,
                                &metrics));

    struct vcs_zcode_focus_claim_v1 claims[2];
    struct vcs_zcode_write_scope_v1 scopes[2];
    uint8_t claim_roots[2][32];
    size_t from_index = 0, next_index = 0;
    zpf_order_claims(&claim_a, &scope_a, claim_a_root,
                     &claim_b, &scope_b, claim_b_root,
                     claims, scopes, claim_roots, &from_index, &next_index);
    ZPF_REQUIRE(from_index != next_index);
    struct vcs_zcode_focus_v1 focus;
    ZPF_REQUIRE(vcs_zcode_focus_compose(
                    &task, task_root, context_root, story_root, story_status,
                    0, claim_roots, 2, &focus) == VCS_ZCODE_FOCUS_OK);
    ZPF_REQUIRE(zpf_store_focus(workspace, &focus, out_focus_root,
                                &metrics));
    ZPF_REQUIRE(vcs_zcode_focus_claim_set_serialize(
                    claim_roots, 2, &claim_set_wire,
                    &claim_set_wire_len) == VCS_ZCODE_FOCUS_OK);
    ZPF_REQUIRE(zpf_store_addressed(
                    workspace, focus.claim_set_root, claim_set_wire,
                    claim_set_wire_len, &metrics));
    ZPF_REQUIRE(vcs_zcode_focus_validate_for_context(
                    &focus, &task, &context, claim_roots, 2, false) ==
                VCS_ZCODE_FOCUS_OK);
    ZPF_REQUIRE(vcs_zcode_focus_claim_set_status(
                    &focus, claims, scopes, 2, observed_unix) ==
                ZCL_ONTOLOGY_PROVED);
    ZPF_REQUIRE(vcs_zcode_focus_claim_disjoint_status(
                    &claims[0], &scopes[0], &claims[1], &scopes[1],
                    observed_unix) == ZCL_ONTOLOGY_PROVED);
    ZPF_REQUIRE(vcs_zcode_focus_claim_authority_status(
                    &focus, &task, &task_scope, &claims[0], &scopes[0],
                    observed_unix) == ZCL_ONTOLOGY_PROVED);
    ZPF_REQUIRE(vcs_zcode_focus_claim_authority_status(
                    &focus, &task, &task_scope, &claims[1], &scopes[1],
                    observed_unix) == ZCL_ONTOLOGY_PROVED);
    *out_observed_us = platform_time_monotonic_us();
    ZPF_REQUIRE(*out_observed_us > 0);
    accepted = true;

cleanup:
    free(claim_set_wire);
    vcs_zcode_agent_context_free(&context);
    memset(worker_a_secret, 0, sizeof(worker_a_secret));
    memset(worker_b_secret, 0, sizeof(worker_b_secret));
    if (!accepted && out_focus_root) memset(out_focus_root, 0, 32);
    if (!accepted && out_observed_us) *out_observed_us = 0;
    return accepted;
}

bool zpd_real_focus_handoff_acceptance(
    const char *workspace, const char *work_id,
    const struct json_value *focus_data,
    const uint8_t source_receipt_root[32],
    const uint8_t preedit_focus_root[32], int64_t preedit_observed_us,
    int64_t edit_started_us)
{
    bool accepted = false;
    struct zpf_metrics metrics = {0};
    uint8_t *claim_set_wire = NULL;
    size_t claim_set_wire_len = 0;
    uint8_t *handoff_wire = NULL;
    size_t handoff_wire_len = 0;
    uint8_t *preedit_claim_set_wire = NULL;
    size_t preedit_claim_set_wire_len = 0;
    uint8_t worker_a_secret[32] = {0};
    uint8_t worker_b_secret[32] = {0};
    uint8_t requester_secret[32] = {0};
    struct vcs_zcode_agent_context_v1 context_a, context_b;
    vcs_zcode_agent_context_init(&context_a);
    vcs_zcode_agent_context_init(&context_b);
    char worker_a[PATH_MAX] = {0};
    char worker_b[PATH_MAX] = {0};
    int64_t measured_started_us = platform_time_monotonic_us();

    ZPF_REQUIRE(workspace && workspace[0] && work_id && work_id[0] &&
                focus_data && focus_data->type == JSON_OBJ &&
                source_receipt_root && preedit_focus_root &&
                preedit_observed_us > 0 &&
                edit_started_us >= preedit_observed_us);
    uint8_t task_root[32], context_root[32], story_root[32];
    uint8_t empty_focus_root[32], expected_situation_root[32];
    ZPF_REQUIRE(zpf_json_root(focus_data, "task_root", task_root));
    ZPF_REQUIRE(zpf_json_root(focus_data, "agent_context_root",
                              context_root));
    ZPF_REQUIRE(zpf_json_root(focus_data, "story_root", story_root));
    ZPF_REQUIRE(zpf_json_root(focus_data, "focus_root", empty_focus_root));
    ZPF_REQUIRE(zpf_json_root(focus_data, "focus_situation_root",
                              expected_situation_root));
    ZPF_REQUIRE(strcmp(json_get_str(json_get(focus_data, "story_status")),
                       "PROVED") == 0);

    struct vcs_zcode_task_v1 source_task;
    ZPF_REQUIRE(zpf_load_task(workspace, task_root, &source_task, &metrics));
    struct vcs_zcode_write_scope_v1 source_task_scope;
    ZPF_REQUIRE(zpf_load_scope(workspace, source_task.write_scope_root,
                               &source_task_scope, &metrics));
    ZPF_REQUIRE(vcs_zcode_write_scope_contains(
                    &source_task_scope, "src/x.c"));
    ZPF_REQUIRE(vcs_zcode_write_scope_contains(
                    &source_task_scope, "include/x.h"));

    struct vcs_zcode_focus_v1 preedit_focus;
    ZPF_REQUIRE(zpf_load_focus(workspace, preedit_focus_root,
                               &preedit_focus, &metrics));
    ZPF_REQUIRE(memcmp(preedit_focus.task_root, task_root, 32) == 0 &&
                memcmp(preedit_focus.goal_root, source_task.goal_root, 32) == 0 &&
                memcmp(preedit_focus.source_universe_root,
                       source_task.source_root, 32) == 0 &&
                memcmp(preedit_focus.context_root, context_root, 32) == 0 &&
                preedit_focus.claim_count == 2);
    uint8_t preedit_claim_roots[2][32];
    size_t preedit_claim_count = 0;
    ZPF_REQUIRE(zpf_load(
                    workspace, preedit_focus.claim_set_root,
                    VCS_ZCODE_FOCUS_CLAIM_SET_WIRE_MAX,
                    &preedit_claim_set_wire, &preedit_claim_set_wire_len,
                    &metrics));
    ZPF_REQUIRE(vcs_zcode_focus_claim_set_parse(
                    preedit_claim_set_wire, preedit_claim_set_wire_len,
                    preedit_claim_roots, 2, &preedit_claim_count) ==
                    VCS_ZCODE_FOCUS_OK &&
                preedit_claim_count == 2);
    free(preedit_claim_set_wire);
    preedit_claim_set_wire = NULL;
    struct vcs_zcode_focus_claim_v1 preedit_claims[2];
    struct vcs_zcode_write_scope_v1 preedit_scopes[2];
    for (size_t i = 0; i < 2; i++) {
        ZPF_REQUIRE(zpf_load_claim(workspace, preedit_claim_roots[i],
                                   &preedit_claims[i], &metrics));
        ZPF_REQUIRE(zpf_load_scope(workspace,
                                   preedit_claims[i].write_scope_root,
                                   &preedit_scopes[i], &metrics));
        ZPF_REQUIRE(memcmp(preedit_claims[i].intent_root,
                           task_root, 32) == 0 &&
                    memcmp(preedit_claims[i].evidence_plan_root,
                           source_task.proof_policy_root, 32) == 0);
    }
    int64_t preedit_claim_time = preedit_claims[0].created_unix;
    if (preedit_claims[1].created_unix > preedit_claim_time)
        preedit_claim_time = preedit_claims[1].created_unix;
    ZPF_REQUIRE(vcs_zcode_focus_claim_set_status(
                    &preedit_focus, preedit_claims, preedit_scopes, 2,
                    preedit_claim_time) == ZCL_ONTOLOGY_PROVED);
    ZPF_REQUIRE(vcs_zcode_focus_claim_disjoint_status(
                    &preedit_claims[0], &preedit_scopes[0],
                    &preedit_claims[1], &preedit_scopes[1],
                    preedit_claim_time) == ZCL_ONTOLOGY_PROVED);
    for (size_t i = 0; i < 2; i++)
        ZPF_REQUIRE(vcs_zcode_focus_claim_authority_status(
                        &preedit_focus, &source_task, &source_task_scope,
                        &preedit_claims[i], &preedit_scopes[i],
                        preedit_claim_time) == ZCL_ONTOLOGY_PROVED);
    metrics.conflicts = 1;

    uint8_t receipt_root[32];
    memcpy(receipt_root, source_receipt_root, 32);
    struct vcs_zcode_work_receipt_v1 source_receipt;
    ZPF_REQUIRE(zpf_load_receipt(workspace, receipt_root,
                                 &source_receipt, &metrics));
    ZPF_REQUIRE(source_receipt.work_kind == VCS_ZCODE_WORK_BUILD &&
                source_receipt.status == VCS_ZCODE_WORK_PASS &&
                source_receipt.exit_status == 0 &&
                memcmp(source_receipt.task_root, task_root, 32) == 0);

    uint8_t worker_a_seed[32], worker_a_key[32];
    uint8_t worker_b_seed[32], worker_b_key[32];
    uint8_t requester_seed[32], requester_key[32];
    memset(worker_a_seed, 0xb7, sizeof(worker_a_seed));
    memset(worker_b_seed, 0xb9, sizeof(worker_b_seed));
    memset(requester_seed, 0xb8, sizeof(requester_seed));
    ed25519_keypair(worker_a_key, worker_a_secret, worker_a_seed);
    ed25519_keypair(worker_b_key, worker_b_secret, worker_b_seed);
    ed25519_keypair(requester_key, requester_secret, requester_seed);
    ZPF_REQUIRE(memcmp(worker_a_key, source_receipt.signer_pubkey, 32) == 0);

    int64_t completed_unix = source_receipt.finished_unix;
    ZPF_REQUIRE(completed_unix > 0 && completed_unix <= INT64_MAX - 8 &&
                source_task.expires_unix > completed_unix + 6);
    int64_t source_expires_unix = completed_unix + 2;
    int64_t successor_expires_unix = completed_unix + 5;
    int64_t request_deadline_unix = completed_unix + 6;
    int64_t resume_unix = completed_unix + 3;

    test_make_tmpdir(worker_a, sizeof(worker_a), "real_focus", "a");
    test_make_tmpdir(worker_b, sizeof(worker_b), "real_focus", "b");
    ZPF_REQUIRE(vcs_object_store_init(worker_a));
    ZPF_REQUIRE(vcs_object_store_init(worker_b));
    const uint8_t *base_roots[] = {
        task_root, context_root, source_task.write_scope_root, receipt_root,
        source_task.acceptance_tests_root,
    };
    const size_t base_maximums[] = {
        VCS_ZCODE_TASK_WIRE_BYTES, (size_t)source_task.max_context_bytes,
        VCS_ZCODE_WRITE_SCOPE_WIRE_MAX,
        VCS_ZCODE_WORK_RECEIPT_WIRE_BYTES,
        VCS_PACKAGE_RECIPE_MAX_WIRE_BYTES,
    };
    for (size_t i = 0; i < sizeof(base_roots) / sizeof(base_roots[0]); i++) {
        ZPF_REQUIRE(zpf_transfer(workspace, worker_a, base_roots[i],
                                 base_maximums[i], &metrics));
        ZPF_REQUIRE(zpf_transfer(workspace, worker_b, base_roots[i],
                                 base_maximums[i], &metrics));
    }
    ZPF_REQUIRE(zpf_load_recipe(worker_a,
                                source_task.acceptance_tests_root, &metrics));
    ZPF_REQUIRE(zpf_load_recipe(worker_b,
                                source_task.acceptance_tests_root, &metrics));

    struct vcs_zcode_task_v1 task_a, task_b;
    struct vcs_zcode_write_scope_v1 task_scope_a, task_scope_b;
    size_t context_wire_bytes = 0, context_b_wire_bytes = 0;
    ZPF_REQUIRE(zpf_load_task(worker_a, task_root, &task_a, &metrics));
    ZPF_REQUIRE(zpf_load_task(worker_b, task_root, &task_b, &metrics));
    ZPF_REQUIRE(zpf_load_context(worker_a, context_root, &task_a, task_root,
                                 &context_a, &context_wire_bytes, &metrics));
    ZPF_REQUIRE(zpf_load_context(worker_b, context_root, &task_b, task_root,
                                 &context_b, &context_b_wire_bytes,
                                 &metrics));
    ZPF_REQUIRE(context_wire_bytes == context_b_wire_bytes);
    ZPF_REQUIRE(vcs_zcode_focus_validate_for_context(
                    &preedit_focus, &source_task, &context_a,
                    preedit_claim_roots, 2, false) == VCS_ZCODE_FOCUS_OK);
    ZPF_REQUIRE(zpf_load_scope(worker_a, task_a.write_scope_root,
                               &task_scope_a, &metrics));
    ZPF_REQUIRE(zpf_load_scope(worker_b, task_b.write_scope_root,
                               &task_scope_b, &metrics));

    struct vcs_zcode_focus_v1 empty_a, empty_b;
    uint8_t situation_a[32], situation_b[32], check_root[32];
    ZPF_REQUIRE(vcs_zcode_focus_compose(
                    &task_a, task_root, context_root, story_root,
                    ZCL_ONTOLOGY_PROVED, 0, NULL, 0, &empty_a) ==
                VCS_ZCODE_FOCUS_OK);
    ZPF_REQUIRE(vcs_zcode_focus_compose(
                    &task_b, task_root, context_root, story_root,
                    ZCL_ONTOLOGY_PROVED, 0, NULL, 0, &empty_b) ==
                VCS_ZCODE_FOCUS_OK);
    ZPF_REQUIRE(vcs_zcode_focus_situation_root(
                    &empty_a, situation_a) == VCS_ZCODE_FOCUS_OK);
    ZPF_REQUIRE(vcs_zcode_focus_situation_root(
                    &empty_b, situation_b) == VCS_ZCODE_FOCUS_OK);
    ZPF_REQUIRE(vcs_zcode_focus_root(
                    &empty_a, check_root) == VCS_ZCODE_FOCUS_OK &&
                memcmp(check_root, empty_focus_root, 32) == 0 &&
                memcmp(situation_a, situation_b, 32) == 0 &&
                memcmp(situation_a, expected_situation_root, 32) == 0);

    struct vcs_zcode_write_scope_v1 scope_a, scope_b;
    vcs_zcode_write_scope_init(&scope_a);
    vcs_zcode_write_scope_init(&scope_b);
    ZPF_REQUIRE(vcs_zcode_write_scope_add(&scope_a, "src/x.c") ==
                VCS_ZCODE_WRITE_SCOPE_OK);
    ZPF_REQUIRE(vcs_zcode_write_scope_add(&scope_b, "include/x.h") ==
                VCS_ZCODE_WRITE_SCOPE_OK);
    uint8_t scope_a_root[32], scope_b_root[32];
    size_t scope_a_bytes = 0, scope_b_bytes = 0;
    ZPF_REQUIRE(zpf_store_scope(worker_a, &scope_a, scope_a_root,
                                &scope_a_bytes, &metrics));
    ZPF_REQUIRE(zpf_store_scope(worker_b, &scope_b, scope_b_root,
                                &scope_b_bytes, &metrics));
    ZPF_REQUIRE(zpf_transfer(worker_a, worker_b, scope_a_root,
                             scope_a_bytes, &metrics));
    ZPF_REQUIRE(zpf_transfer(worker_b, worker_a, scope_b_root,
                             scope_b_bytes, &metrics));

    uint8_t continuation_root[32];
    memcpy(continuation_root, task_a.acceptance_tests_root, 32);
    ZPF_REQUIRE(memcmp(continuation_root,
                       task_b.acceptance_tests_root, 32) == 0);

    struct vcs_zcode_work_request_v1 request_a, request_b;
    zpf_request(&request_a, 1, &task_a, task_root,
                source_receipt.candidate_root, source_receipt.action_root,
                source_receipt.input_root, context_root,
                source_receipt.work_kind, request_deadline_unix);
    ZPF_REQUIRE(vcs_zcode_work_request_seal(
                    &request_a, requester_secret, requester_key));
    request_b = request_a;
    ZPF_REQUIRE(memcmp(request_a.action_root, request_b.action_root, 32) == 0);
    uint8_t request_a_root[32], request_b_root[32];
    ZPF_REQUIRE(vcs_zcode_work_request_id(&request_a, request_a_root));
    ZPF_REQUIRE(vcs_zcode_work_request_id(&request_b, request_b_root));
    ZPF_REQUIRE(memcmp(request_a_root, request_b_root, 32) == 0);
    struct vcs_zcode_work_admission_v1 admission_a, admission_b;
    ZPF_REQUIRE(zpf_admission(&admission_a, &request_a, 0,
                              VCS_ZCODE_WORK_ADMISSION_GRANTED,
                              worker_a_secret, worker_a_key));
    ZPF_REQUIRE(zpf_admission(&admission_b, &request_b, 1,
                              VCS_ZCODE_WORK_ADMISSION_ATTACHED,
                              worker_b_secret, worker_b_key));
    uint32_t duplicate_actions =
        admission_b.disposition == VCS_ZCODE_WORK_ADMISSION_ATTACHED ? 1u : 0u;
    ZPF_REQUIRE(duplicate_actions == 1u);

    struct vcs_zcode_work_swarm_message message_a = {
        .type = VCS_ZCODE_WORK_SWARM_REQUEST,
        .body.request = request_a,
    };
    struct vcs_zcode_work_swarm_message message_b;
    uint8_t request_a_carrier[32];
    size_t request_a_bytes = 0;
    ZPF_REQUIRE(zpf_store_work_message(
                    worker_a, &message_a, request_a_root,
                    request_a_carrier, &request_a_bytes, &metrics));
    message_a = (struct vcs_zcode_work_swarm_message) {
        .type = VCS_ZCODE_WORK_SWARM_ADMISSION,
        .body.admission = admission_a,
    };
    message_b = (struct vcs_zcode_work_swarm_message) {
        .type = VCS_ZCODE_WORK_SWARM_ADMISSION,
        .body.admission = admission_b,
    };
    uint8_t admission_a_carrier[32], admission_b_carrier[32];
    size_t admission_a_bytes = 0, admission_b_bytes = 0;
    ZPF_REQUIRE(zpf_store_work_message(
                    worker_a, &message_a, NULL, admission_a_carrier,
                    &admission_a_bytes, &metrics));
    ZPF_REQUIRE(zpf_store_work_message(
                    worker_b, &message_b, NULL, admission_b_carrier,
                    &admission_b_bytes, &metrics));
    ZPF_REQUIRE(zpf_transfer(worker_a, worker_b, request_a_root,
                             request_a_bytes, &metrics));
    ZPF_REQUIRE(zpf_transfer(worker_a, worker_b, admission_a_carrier,
                             admission_a_bytes, &metrics));
    ZPF_REQUIRE(zpf_transfer(worker_b, worker_a, admission_b_carrier,
                             admission_b_bytes, &metrics));

    struct vcs_zcode_focus_claim_v1 claim_a = {
        .schema_version = VCS_ZCODE_FOCUS_VERSION,
        /* This fixture observes the claim only after the real receipt exists.
         * Do not backdate it to imply pre-edit publication. */
        .created_unix = completed_unix,
        .expires_unix = source_expires_unix,
    };
    struct vcs_zcode_focus_claim_v1 claim_b = {
        .schema_version = VCS_ZCODE_FOCUS_VERSION,
        .created_unix = completed_unix,
        .expires_unix = successor_expires_unix,
    };
    ZPF_REQUIRE(claim_a.created_unix == completed_unix);
    memcpy(claim_a.situation_root, situation_a, 32);
    memcpy(claim_a.claimant_root, worker_a_key, 32);
    memcpy(claim_a.write_scope_root, scope_a_root, 32);
    memcpy(claim_a.intent_root, request_a_root, 32);
    memcpy(claim_a.evidence_plan_root, request_a.proof_policy_root, 32);
    memcpy(claim_b.situation_root, situation_b, 32);
    memcpy(claim_b.claimant_root, worker_b_key, 32);
    memcpy(claim_b.write_scope_root, scope_b_root, 32);
    memcpy(claim_b.intent_root, request_b_root, 32);
    memcpy(claim_b.evidence_plan_root, request_b.proof_policy_root, 32);
    uint8_t claim_a_root[32], claim_b_root[32];
    ZPF_REQUIRE(zpf_store_claim(worker_a, &claim_a, claim_a_root,
                                &metrics));
    ZPF_REQUIRE(zpf_store_claim(worker_b, &claim_b, claim_b_root,
                                &metrics));
    ZPF_REQUIRE(zpf_transfer(worker_a, worker_b, claim_a_root,
                             VCS_ZCODE_FOCUS_CLAIM_WIRE_BYTES, &metrics));
    ZPF_REQUIRE(zpf_transfer(worker_b, worker_a, claim_b_root,
                             VCS_ZCODE_FOCUS_CLAIM_WIRE_BYTES, &metrics));

    struct vcs_zcode_focus_claim_v1 claim_a_at_b, claim_b_at_a;
    struct vcs_zcode_write_scope_v1 scope_a_at_b, scope_b_at_a;
    ZPF_REQUIRE(zpf_load_claim(worker_b, claim_a_root,
                               &claim_a_at_b, &metrics));
    ZPF_REQUIRE(zpf_load_claim(worker_a, claim_b_root,
                               &claim_b_at_a, &metrics));
    ZPF_REQUIRE(zpf_load_scope(worker_b, scope_a_root,
                               &scope_a_at_b, &metrics));
    ZPF_REQUIRE(zpf_load_scope(worker_a, scope_b_root,
                               &scope_b_at_a, &metrics));

    struct vcs_zcode_focus_claim_v1 claims_a[2], claims_b[2];
    struct vcs_zcode_write_scope_v1 scopes_a[2], scopes_b[2];
    uint8_t claim_roots_a[2][32], claim_roots_b[2][32];
    size_t from_a = 0, next_a = 0, from_b = 0, next_b = 0;
    zpf_order_claims(&claim_a, &scope_a, claim_a_root,
                     &claim_b_at_a, &scope_b_at_a, claim_b_root,
                     claims_a, scopes_a, claim_roots_a, &from_a, &next_a);
    zpf_order_claims(&claim_a_at_b, &scope_a_at_b, claim_a_root,
                     &claim_b, &scope_b, claim_b_root,
                     claims_b, scopes_b, claim_roots_b, &from_b, &next_b);
    ZPF_REQUIRE(memcmp(claim_roots_a, claim_roots_b,
                       sizeof(claim_roots_a)) == 0 &&
                from_a == from_b && next_a == next_b);

    struct vcs_zcode_focus_v1 focus_a, focus_b;
    ZPF_REQUIRE(vcs_zcode_focus_compose(
                    &task_a, task_root, context_root, story_root,
                    ZCL_ONTOLOGY_PROVED, 0, claim_roots_a, 2, &focus_a) ==
                VCS_ZCODE_FOCUS_OK);
    ZPF_REQUIRE(vcs_zcode_focus_compose(
                    &task_b, task_root, context_root, story_root,
                    ZCL_ONTOLOGY_PROVED, 0, claim_roots_b, 2, &focus_b) ==
                VCS_ZCODE_FOCUS_OK);
    uint8_t focus_a_root[32], focus_b_root[32];
    ZPF_REQUIRE(zpf_store_focus(worker_a, &focus_a,
                                focus_a_root, &metrics));
    ZPF_REQUIRE(zpf_store_focus(worker_b, &focus_b,
                                focus_b_root, &metrics));
    ZPF_REQUIRE(memcmp(focus_a_root, focus_b_root, 32) == 0 &&
                memcmp(focus_a_root, empty_focus_root, 32) != 0);
    ZPF_REQUIRE(vcs_zcode_focus_claim_set_status(
                    &focus_b, claims_b, scopes_b, 2, completed_unix) ==
                ZCL_ONTOLOGY_PROVED);
    ZPF_REQUIRE(vcs_zcode_focus_claim_disjoint_status(
                    &claim_a_at_b, &scope_a_at_b, &claim_b, &scope_b,
                    completed_unix) == ZCL_ONTOLOGY_PROVED);

    ZPF_REQUIRE(vcs_zcode_focus_claim_set_serialize(
                    claim_roots_a, 2, &claim_set_wire,
                    &claim_set_wire_len) == VCS_ZCODE_FOCUS_OK);
    ZPF_REQUIRE(zpf_store_addressed(
                    worker_a, focus_a.claim_set_root, claim_set_wire,
                    claim_set_wire_len, &metrics));
    ZPF_REQUIRE(zpf_store_addressed(
                    worker_b, focus_b.claim_set_root, claim_set_wire,
                    claim_set_wire_len, &metrics));

    int64_t measured_elapsed =
        platform_time_monotonic_us() - measured_started_us;
    uint64_t fixture_setup_us = measured_elapsed > 0
        ? (uint64_t)measured_elapsed : 1u;
    uint32_t fixture_cas_tool_calls = metrics.tool_calls > 0
        ? metrics.tool_calls : 1u;
    struct vcs_zcode_specialist_report_v1 report_a = {
        .schema_version = VCS_ZCODE_FOCUS_VERSION,
        .role = VCS_ZCODE_SPECIALIST_CODE,
        .status = ZCL_ONTOLOGY_PROVED,
        .context_bytes = context_wire_bytes,
        /* These are shared fixture observations, not a source-agent trace. */
        .latency_us = fixture_setup_us,
        .files_opened = 0,
        .tool_calls = fixture_cas_tool_calls,
        .duplicate_actions = 0,
        .proof_reuse_count = 1,
    };
    memcpy(report_a.focus_root, focus_a_root, 32);
    memcpy(report_a.claim_root, claim_a_root, 32);
    memcpy(report_a.specialist_root, worker_a_key, 32);
    memcpy(report_a.evidence_root, receipt_root, 32);
    memcpy(report_a.result_root, source_receipt.output_root, 32);
    memcpy(report_a.next_experiment_root, continuation_root, 32);
    memcpy(report_a.evaluator_root, task_a.proof_policy_root, 32);
    struct vcs_zcode_specialist_report_v1 report_b = {
        .schema_version = VCS_ZCODE_FOCUS_VERSION,
        .role = VCS_ZCODE_SPECIALIST_PROOF,
        .status = ZCL_ONTOLOGY_INCOMPLETE,
        .context_bytes = context_b_wire_bytes,
        .latency_us = fixture_setup_us,
        .files_opened = 0,
        .tool_calls = fixture_cas_tool_calls,
        .duplicate_actions = duplicate_actions,
        .proof_reuse_count = 1,
    };
    memcpy(report_b.focus_root, focus_b_root, 32);
    memcpy(report_b.claim_root, claim_b_root, 32);
    memcpy(report_b.specialist_root, worker_b_key, 32);
    memcpy(report_b.evidence_root, request_b_root, 32);
    memcpy(report_b.result_root, continuation_root, 32);
    memcpy(report_b.next_experiment_root,
           task_b.acceptance_tests_root, 32);
    memcpy(report_b.evaluator_root, task_b.proof_policy_root, 32);
    uint8_t report_a_root[32], report_b_root[32];
    ZPF_REQUIRE(zpf_store_report(worker_a, &report_a,
                                 report_a_root, &metrics));
    ZPF_REQUIRE(zpf_store_report(worker_b, &report_b,
                                 report_b_root, &metrics));
    ZPF_REQUIRE(zpf_transfer(worker_a, worker_b, report_a_root,
                             VCS_ZCODE_SPECIALIST_REPORT_WIRE_BYTES,
                             &metrics));
    ZPF_REQUIRE(zpf_transfer(worker_b, worker_a, report_b_root,
                             VCS_ZCODE_SPECIALIST_REPORT_WIRE_BYTES,
                             &metrics));
    struct vcs_zcode_specialist_report_v1 report_a_at_b, report_b_at_a;
    ZPF_REQUIRE(zpf_load_report(worker_b, report_a_root,
                                &report_a_at_b, &metrics));
    ZPF_REQUIRE(zpf_load_report(worker_a, report_b_root,
                                &report_b_at_a, &metrics));

    struct vcs_zcode_focus_handoff_v1 handoff = {
        .schema_version = VCS_ZCODE_FOCUS_VERSION,
        .status = ZCL_ONTOLOGY_PROVED,
    };
    memcpy(handoff.focus_root, focus_a_root, 32);
    memcpy(handoff.report_root, report_a_root, 32);
    memcpy(handoff.from_claim_root, claim_a_root, 32);
    memcpy(handoff.to_specialist_root, worker_b_key, 32);
    memcpy(handoff.next_claim_root, claim_b_root, 32);
    memcpy(handoff.required_evidence_root,
           focus_a.required_evidence_root, 32);
    memcpy(handoff.continuation_root, continuation_root, 32);
    uint8_t handoff_root[32];
    ZPF_REQUIRE(zpf_store_handoff(worker_a, &handoff,
                                  handoff_root, &metrics));
    ZPF_REQUIRE(zpf_transfer(worker_a, worker_b, handoff_root,
                             VCS_ZCODE_FOCUS_HANDOFF_WIRE_BYTES, &metrics));
    size_t independent_processes = zpf_exec_clean_agent_acceptance(
        worker_a, worker_b, focus_a_root, handoff_root,
        admission_a_carrier, admission_b_carrier, resume_unix);
#if defined(_WIN32)
    ZPF_REQUIRE(independent_processes == 0);
#else
    ZPF_REQUIRE(independent_processes == 2);
#endif

    struct vcs_zcode_work_swarm_message request_a_at_b;
    struct vcs_zcode_work_swarm_message request_b_at_b;
    struct vcs_zcode_work_swarm_message admission_a_at_b;
    struct vcs_zcode_work_swarm_message admission_b_at_b;
    ZPF_REQUIRE(zpf_load_work_message(
                    worker_b, request_a_root, VCS_ZCODE_WORK_SWARM_REQUEST,
                    &request_a_at_b, &metrics));
    ZPF_REQUIRE(zpf_load_work_message(
                    worker_b, request_b_root, VCS_ZCODE_WORK_SWARM_REQUEST,
                    &request_b_at_b, &metrics));
    ZPF_REQUIRE(zpf_load_work_message(
                    worker_b, admission_a_carrier,
                    VCS_ZCODE_WORK_SWARM_ADMISSION,
                    &admission_a_at_b, &metrics));
    ZPF_REQUIRE(zpf_load_work_message(
                    worker_b, admission_b_carrier,
                    VCS_ZCODE_WORK_SWARM_ADMISSION,
                    &admission_b_at_b, &metrics));
    uint8_t request_check[32];
    ZPF_REQUIRE(vcs_zcode_work_request_id(
                    &request_a_at_b.body.request, request_check) &&
                memcmp(request_check, request_a_root, 32) == 0);
    ZPF_REQUIRE(vcs_zcode_work_request_id(
                    &request_b_at_b.body.request, request_check) &&
                memcmp(request_check, request_b_root, 32) == 0);
    struct vcs_zcode_work_receipt_v1 receipt_at_b;
    ZPF_REQUIRE(zpf_load_receipt(worker_b, receipt_root,
                                 &receipt_at_b, &metrics));
    struct vcs_zcode_focus_handoff_v1 handoff_at_b;
    ZPF_REQUIRE(zpf_load(worker_b, handoff_root,
                         VCS_ZCODE_FOCUS_HANDOFF_WIRE_BYTES,
                         &handoff_wire, &handoff_wire_len, &metrics));
    ZPF_REQUIRE(vcs_zcode_focus_handoff_parse(
                    handoff_wire, handoff_wire_len, &handoff_at_b) ==
                VCS_ZCODE_FOCUS_OK);
    free(handoff_wire);
    handoff_wire = NULL;
    ZPF_REQUIRE(vcs_zcode_focus_handoff_root(
                    &handoff_at_b, check_root) == VCS_ZCODE_FOCUS_OK &&
                memcmp(check_root, handoff_root, 32) == 0);
    ZPF_REQUIRE(vcs_zcode_focus_handoff_validate_for_work(
                    &focus_b, &task_b, &context_b, &task_scope_b,
                    claims_b, scopes_b, 2, from_b, next_b,
                    &request_a_at_b.body.request,
                    &admission_a_at_b.body.admission,
                    &request_b_at_b.body.request,
                    &admission_b_at_b.body.admission,
                    &receipt_at_b, &report_a_at_b, &handoff_at_b,
                    resume_unix) == VCS_ZCODE_FOCUS_OK);
    ZPF_REQUIRE(vcs_zcode_focus_handoff_validate_for_work(
                    &focus_b, &task_b, &context_b, &task_scope_b,
                    claims_b, scopes_b, 2, from_b, next_b,
                    &request_a_at_b.body.request,
                    &admission_a_at_b.body.admission,
                    &request_b_at_b.body.request,
                    &admission_b_at_b.body.admission,
                    &receipt_at_b, &report_a_at_b, &handoff_at_b,
                    successor_expires_unix) == VCS_ZCODE_FOCUS_BINDING);

    char focus_hex[65], handoff_hex[65], receipt_hex[65];
    zcl_hex_encode(focus_b_root, 32, focus_hex);
    zcl_hex_encode(handoff_root, 32, handoff_hex);
    zcl_hex_encode(receipt_root, 32, receipt_hex);
    int64_t source_receipt_duration_seconds =
        source_receipt.finished_unix - source_receipt.started_unix;
    int64_t observed_us = platform_time_monotonic_us();
    uint64_t edit_to_observation_us = observed_us >= edit_started_us
        ? (uint64_t)(observed_us - edit_started_us) : 0;
    ZPF_REQUIRE(edit_to_observation_us > 0);
    printf("{\"schema\":\"zcl.shared_focus_real_c23.v1\","
           "\"status\":\"passed\",\"work_id\":\"%s\","
           "\"topology\":\"%s\","
           "\"independent_processes\":\"%s\","
           "\"exec_clean_agent_programs\":\"%s\","
           "\"binding_validation\":\"PROVED\","
           "\"real_receipt_reuse\":\"PROVED\","
           "\"preedit_observation\":\"PROVED\","
           "\"preedit_claim_publication_order\":\"PROVED\","
           "\"duplicate_task_rendezvous\":\"PROVED\","
           "\"prior_source_admission_chronology\":\"INCOMPLETE\","
           "\"admitted_source_claim_publication_order\":\"INCOMPLETE\","
           "\"real_c23_task\":true,\"claims\":2,\"reports\":2,"
           "\"scope_overlap\":\"DISPROVED\",\"conflicts\":%u,"
           "\"retries\":%u,\"duplicate_actions\":%u,"
           "\"attached_admissions\":1,\"exact_action_reused\":true,"
           "\"proof_reuse\":1,\"context_bytes\":%zu,"
           "\"files_opened\":\"INCOMPLETE\","
           "\"per_specialist_tool_calls\":\"INCOMPLETE\","
           "\"fixture_cas_tool_calls\":%u,"
           "\"coordination_bytes\":%" PRIu64 ","
           "\"prose_bytes\":0,\"fixture_setup_us\":%" PRIu64 ","
           "\"report_latency\":\"INCOMPLETE\","
           "\"source_receipt_duration_seconds\":%" PRId64 ","
           "\"edit_to_observation_us\":%" PRIu64 ","
           "\"stale_successor_refused\":true,"
           "\"focus_root\":\"%s\",\"handoff_root\":\"%s\","
           "\"work_receipt_root\":\"%s\"}\n",
           work_id, independent_processes == 2
               ? "two_exec_clean_agent_programs_two_independent_cas"
               : "in_process_two_independent_cas",
           independent_processes == 2 ? "PROVED" : "INCOMPLETE",
           independent_processes == 2 ? "PROVED" : "INCOMPLETE",
           metrics.conflicts, metrics.retries, duplicate_actions,
           context_wire_bytes, fixture_cas_tool_calls,
           metrics.coordination_bytes, fixture_setup_us,
           source_receipt_duration_seconds, edit_to_observation_us,
           focus_hex, handoff_hex, receipt_hex);
    accepted = true;

cleanup:
    free(claim_set_wire);
    free(handoff_wire);
    free(preedit_claim_set_wire);
    vcs_zcode_agent_context_free(&context_a);
    vcs_zcode_agent_context_free(&context_b);
    memset(worker_a_secret, 0, sizeof(worker_a_secret));
    memset(worker_b_secret, 0, sizeof(worker_b_secret));
    memset(requester_secret, 0, sizeof(requester_secret));
    if (worker_a[0]) test_rm_rf_recursive(worker_a);
    if (worker_b[0]) test_rm_rf_recursive(worker_b);
    return accepted;
}
