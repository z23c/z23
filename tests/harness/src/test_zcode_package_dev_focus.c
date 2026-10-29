/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Prove a real C23 package task resumes through rooted focus handoff. */
#include "test/test_core.h"

#include "base/hex.h"
#include "command/native_command.h"
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

struct zpf_reload_state {
    struct vcs_zcode_agent_context_v1 *context;
    struct vcs_zcode_focus_v1 focus;
    struct vcs_zcode_task_v1 task;
    struct vcs_zcode_write_scope_v1 task_scope;
    uint8_t claim_roots[2][32];
    size_t claim_count;
    struct vcs_zcode_focus_claim_v1 claims[2];
    struct vcs_zcode_write_scope_v1 scopes[2];
};

static bool zpf_reload_load_base(
    const char *workspace, const uint8_t focus_root[32],
    struct zpf_reload_state *st, struct zpf_metrics *metrics)
{
    uint8_t *claim_set_wire = NULL;
    size_t claim_set_wire_len = 0;
    bool ok = workspace && focus_root &&
        zpf_load_focus(workspace, focus_root, &st->focus, metrics) &&
        st->focus.claim_count == 2 &&
        zpf_load_task(workspace, st->focus.task_root, &st->task, metrics) &&
        zpf_load_scope(workspace, st->task.write_scope_root,
                       &st->task_scope, metrics) &&
        zpf_load_context(workspace, st->focus.context_root, &st->task,
                         st->focus.task_root, st->context, NULL, metrics) &&
        zpf_load(workspace, st->focus.claim_set_root,
                 VCS_ZCODE_FOCUS_CLAIM_SET_WIRE_MAX,
                 &claim_set_wire, &claim_set_wire_len, metrics) &&
        vcs_zcode_focus_claim_set_parse(
            claim_set_wire, claim_set_wire_len, st->claim_roots, 2,
            &st->claim_count) == VCS_ZCODE_FOCUS_OK &&
        st->claim_count == 2;
    free(claim_set_wire);
    return ok;
}

static bool zpf_reload_load_claims(
    const char *workspace, struct zpf_reload_state *st,
    struct zpf_metrics *metrics)
{
    for (size_t i = 0; i < st->claim_count; i++) {
        if (!zpf_load_claim(workspace, st->claim_roots[i],
                            &st->claims[i], metrics) ||
            !zpf_load_scope(workspace, st->claims[i].write_scope_root,
                            &st->scopes[i], metrics))
            return false;
    }
    return true;
}

static bool zpf_reload_claims_proved(struct zpf_reload_state *st)
{
    int64_t snapshot_unix = st->claims[0].created_unix;
    if (st->claims[1].created_unix > snapshot_unix)
        snapshot_unix = st->claims[1].created_unix;
    return vcs_zcode_focus_validate_for_context(
               &st->focus, &st->task, st->context, st->claim_roots,
               st->claim_count, true) == VCS_ZCODE_FOCUS_OK &&
        vcs_zcode_focus_claim_set_status(
            &st->focus, st->claims, st->scopes, st->claim_count,
            snapshot_unix) == ZCL_ONTOLOGY_PROVED &&
        vcs_zcode_focus_claim_authority_status(
            &st->focus, &st->task, &st->task_scope, &st->claims[0],
            &st->scopes[0], snapshot_unix) == ZCL_ONTOLOGY_PROVED &&
        vcs_zcode_focus_claim_authority_status(
            &st->focus, &st->task, &st->task_scope, &st->claims[1],
            &st->scopes[1], snapshot_unix) == ZCL_ONTOLOGY_PROVED;
}

static bool zpf_reload_find_indices(
    struct zpf_reload_state *st,
    const struct vcs_zcode_focus_handoff_v1 *handoff,
    size_t *from_index, size_t *next_index)
{
    *from_index = st->claim_count;
    *next_index = st->claim_count;
    for (size_t i = 0; i < st->claim_count; i++) {
        if (memcmp(st->claim_roots[i], handoff->from_claim_root, 32) == 0)
            *from_index = i;
        if (memcmp(st->claim_roots[i], handoff->next_claim_root, 32) == 0)
            *next_index = i;
    }
    return *from_index < st->claim_count && *next_index < st->claim_count &&
        *from_index != *next_index;
}

static bool zpf_reload_load_messages(
    const char *workspace, struct zpf_reload_state *st,
    size_t from_index, size_t next_index,
    const uint8_t admission_a_root[32], const uint8_t admission_b_root[32],
    struct vcs_zcode_work_swarm_message messages[4],
    struct zpf_metrics *metrics)
{
    return zpf_load_work_message(
               workspace, st->claims[from_index].intent_root,
               VCS_ZCODE_WORK_SWARM_REQUEST, &messages[0], metrics) &&
        zpf_load_work_message(
            workspace, st->claims[next_index].intent_root,
            VCS_ZCODE_WORK_SWARM_REQUEST, &messages[1], metrics) &&
        zpf_load_work_carrier(
            workspace, admission_a_root,
            VCS_ZCODE_WORK_SWARM_ADMISSION, &messages[2], metrics) &&
        zpf_load_work_carrier(
            workspace, admission_b_root,
            VCS_ZCODE_WORK_SWARM_ADMISSION, &messages[3], metrics);
}

static bool zpf_reload_handoff_accepted(
    const char *workspace, struct zpf_reload_state *st,
    const uint8_t *handoff_root, const uint8_t *admission_a_root,
    const uint8_t *admission_b_root, int64_t resume_unix,
    struct zpf_metrics *metrics)
{
    struct vcs_zcode_focus_handoff_v1 handoff;
    struct vcs_zcode_specialist_report_v1 report;
    if (!zpf_load_handoff(workspace, handoff_root, &handoff, metrics) ||
        !zpf_load_report(workspace, handoff.report_root, &report, metrics))
        return false;
    size_t from_index = 0, next_index = 0;
    if (!zpf_reload_find_indices(st, &handoff, &from_index, &next_index))
        return false;
    struct vcs_zcode_work_swarm_message messages[4];
    if (!zpf_reload_load_messages(workspace, st, from_index, next_index,
                                  admission_a_root, admission_b_root,
                                  messages, metrics))
        return false;
    struct vcs_zcode_work_receipt_v1 receipt;
    if (!zpf_load_receipt(workspace, report.evidence_root, &receipt, metrics))
        return false;
    return vcs_zcode_focus_handoff_validate_for_work(
               &st->focus, &st->task, st->context, &st->task_scope,
               st->claims, st->scopes, st->claim_count, from_index,
               next_index, &messages[0].body.request,
               &messages[2].body.admission, &messages[1].body.request,
               &messages[3].body.admission, &receipt, &report, &handoff,
               resume_unix) == VCS_ZCODE_FOCUS_OK;
}

static bool zpf_process_reload_focus(
    const char *workspace, const uint8_t focus_root[32],
    const uint8_t *handoff_root, const uint8_t *admission_a_root,
    const uint8_t *admission_b_root, int64_t resume_unix)
{
    bool accepted = false;
    struct zpf_metrics metrics = {0};
    struct vcs_zcode_agent_context_v1 context;
    vcs_zcode_agent_context_init(&context);
    struct zpf_reload_state st = {.context = &context};

    if (!zpf_reload_load_base(workspace, focus_root, &st, &metrics) ||
        !zpf_reload_load_claims(workspace, &st, &metrics) ||
        !zpf_reload_claims_proved(&st))
        goto cleanup;
    if (!handoff_root) {
        accepted = true;
        goto cleanup;
    }
    if (!admission_a_root || !admission_b_root || resume_unix <= 0)
        goto cleanup;
    accepted = zpf_reload_handoff_accepted(
        workspace, &st, handoff_root, admission_a_root, admission_b_root,
        resume_unix, &metrics);

cleanup:
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

static bool zpf_child_exited_zero(bool waited, int status)
{
    return waited && WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

static void zpf_encode_optional_root(const uint8_t *root, char hex[65])
{
    if (root) zcl_hex_encode(root, 32, hex);
}

static bool zpf_child_environment_set(
    const char *role, const char *workspace, const char *focus_hex,
    const char *handoff_hex, const char *admission_a_hex,
    const char *admission_b_hex, const char *resume_text)
{
    return platform_environment_set("ZCL_TEST_FORK_GROUP",
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
    zpf_encode_optional_root(handoff_root, handoff_hex);
    zpf_encode_optional_root(admission_a_root, admission_a_hex);
    zpf_encode_optional_root(admission_b_root, admission_b_hex);
    int n = snprintf(resume_text, sizeof(resume_text), "%" PRId64,
                     resume_unix);
    if (n < 0 || (size_t)n >= sizeof(resume_text))
        return -1;

    pid_t child = fork();
    if (child != 0)
        return child;
    bool env_ok = zpf_child_environment_set(
        role, workspace, focus_hex, handoff_hex, admission_a_hex,
        admission_b_hex, resume_text);
    if (env_ok && zpf_silence_exec_output())
        execl(executable, executable,
              "--exact=test_zcode_package_dev", (char *)NULL);
    _exit(127);
}
#endif

#if !defined(_WIN32)
static bool zpf_resume_packet_matches(
    const char *workspace, const uint8_t task_root[32],
    const struct json_value *data)
{
    struct zpf_metrics metrics = {0};
    struct vcs_zcode_task_v1 task;
    struct vcs_zcode_write_scope_v1 scope;
    uint8_t *goal = NULL;
    size_t goal_len = 0;
    if (!zpf_load_task(workspace, task_root, &task, &metrics) ||
        !zpf_load_scope(workspace, task.write_scope_root, &scope, &metrics) ||
        !zpf_load(workspace, task.goal_root, 4096, &goal, &goal_len, &metrics))
        return false;
    const char *text = json_get_str(json_get(data, "goal"));
    const struct json_value *paths = json_get(data, "allowed_write_scopes");
    bool ok = text && strlen(text) == goal_len &&
        memcmp(text, goal, goal_len) == 0 && paths &&
        paths->type == JSON_ARR && json_size(paths) == scope.count &&
        json_get_int(json_get(data, "max_changed_files")) ==
            task.max_changed_files &&
        json_get_int(json_get(data, "max_patch_bytes")) ==
            (int64_t)task.max_patch_bytes;
    for (size_t i = 0; ok && i < scope.count; i++) {
        const char *path = json_get_str(json_at(paths, i));
        ok = path && strcmp(path, scope.paths[i]) == 0;
    }
    free(goal);
    return ok;
}

static bool zpf_resume_root_matches(const struct json_value *data,
                                    const char *key, const char *environment)
{
    const char *actual = json_get_str(json_get(data, key));
    const char *expected = getenv(environment);
    return actual && expected && strcmp(actual, expected) == 0;
}

static bool zpf_resume_complete(const struct zcl_command_request *request)
{
    struct zcl_command_reply reply;
    zcl_command_reply_init(&reply, "zcl.zcode_work_accept.v1");
    zcl_native_handle_zcode_work_accept(request, &reply);
    const char *state = json_get_str(json_get(&reply.data, "state"));
    bool ok = reply.status == ZCL_COMMAND_STATUS_PASSED && state &&
        strcmp(state, "PROVEN") == 0 &&
        !json_get_bool(json_get(&reply.data, "idempotent"));
    zcl_command_reply_free(&reply);
    return ok;
}

static bool zpf_resume_user_session(const char *workspace,
                                    const char *task_hex)
{
    uint8_t task_root[32];
    if (!workspace || !task_hex ||
        !zcl_hex_decode_lower(task_hex, task_root, 32)) return false;
    struct json_value input;
    json_init(&input); json_set_object(&input);
    bool ok = json_push_kv_str(&input, "workspace", workspace) &&
        json_push_kv_str(&input, "work", task_hex);
    struct zcl_command_request request = {.input = &input};
    struct zcl_command_reply reply;
    zcl_command_reply_init(&reply, "zcl.story_focus.v1");
    if (ok) zcl_native_handle_story_focus(&request, &reply);
    ok = ok && reply.status == ZCL_COMMAND_STATUS_PASSED &&
        zpf_resume_root_matches(&reply.data, "candidate_root", ZPF_ENV_HANDOFF_ROOT) &&
        zpf_resume_root_matches(&reply.data, "candidate_source_root", ZPF_ENV_ADMISSION_A_ROOT) &&
        zpf_resume_root_matches(&reply.data, "write_scope_root", ZPF_ENV_ADMISSION_B_ROOT) &&
        zpf_resume_packet_matches(workspace, task_root, &reply.data) &&
        zpf_resume_complete(&request);
    zcl_command_reply_free(&reply); json_free(&input);
    return ok;
}

#endif

static bool zpf_scope_refused(const char *workspace, const char *task_hex)
{
    struct json_value input;
    json_init(&input); json_set_object(&input);
    bool ok = json_push_kv_str(&input, "workspace", workspace) &&
        json_push_kv_str(&input, "work", task_hex);
    struct zcl_command_request request = {.input = &input};
    struct zcl_command_reply reply;
    zcl_command_reply_init(&reply, "zcl.story_focus.v1");
    if (ok) zcl_native_handle_story_focus(&request, &reply);
    ok = ok && reply.status == ZCL_COMMAND_STATUS_FAILED &&
        strcmp(reply.error.code, "STORY_SCOPE_UNAVAILABLE") == 0 &&
        json_get(&reply.data, "allowed_write_scopes") == NULL;
    zcl_command_reply_free(&reply); json_free(&input);
    return ok;
}

static bool zpf_scope_corruption_refused(const char *workspace,
    const char *task, const uint8_t root[32], uint8_t *wire, size_t len)
{
    if (len <= VCS_ZCODE_WRITE_SCOPE_HEADER_BYTES) return false;
    wire[len - 1] ^= 1;
    bool repaired = false;
    bool ok = vcs_object_put_addressed_repair(workspace, root, wire, len,
                                              &repaired) && repaired &&
        zpf_scope_refused(workspace, task);
    wire[len - 1] ^= 1;
    bool restored = vcs_object_put_addressed_repair(
        workspace, root, wire, len, &repaired);
    return ok && restored;
}

bool zpd_user_session_scope_refusals(const char *workspace,
                                     const struct json_value *data)
{
    uint8_t root[32], *wire = NULL;
    size_t len = 0;
    const char *task = json_get_str(json_get(data, "task_root"));
    const char *scope = json_get_str(json_get(data, "write_scope_root"));
    if (!task || !scope || !zpf_json_root(data, "write_scope_root", root) ||
        vcs_object_load_raw_bounded(workspace, root,
            VCS_ZCODE_WRITE_SCOPE_WIRE_MAX, &wire, &len) != 0)
        return false;
    char path[4600], backup[4620];
    int pn = snprintf(path, sizeof(path), "%s/.zvcs/objects/%.2s/%s",
                       workspace, scope, scope + 2);
    int bn = snprintf(backup, sizeof(backup), "%s.resume-fixture", path);
    bool moved = pn > 0 && (size_t)pn < sizeof(path) && bn > 0 &&
        (size_t)bn < sizeof(backup) && rename(path, backup) == 0;
    bool ok = moved && zpf_scope_refused(workspace, task);
    if (moved && rename(backup, path) != 0) ok = false;
    if (ok) ok = zpf_scope_corruption_refused(workspace, task, root, wire, len);
    free(wire);
    return ok;
}

bool zpd_user_session_resume(const char *workspace,
                             const struct json_value *data)
{
#if defined(_WIN32)
    (void)workspace; (void)data;
    return false;
#else
    uint8_t task[32], candidate[32], source[32], scope[32];
    if (!zpf_json_root(data, "task_root", task) ||
        !zpf_json_root(data, "candidate_root", candidate) ||
        !zpf_json_root(data, "candidate_source_root", source) ||
        !zpf_json_root(data, "write_scope_root", scope)) return false;
    pid_t child = zpf_spawn_exec_agent("user-session-resume", workspace,
                                      task, candidate, source, scope, 0);
    int status = -1;
    return child > 0 && zpf_wait_child(child, &status) &&
        WIFEXITED(status) && WEXITSTATUS(status) == 0;
#endif
}

#if !defined(_WIN32)
static bool zpf_successor_inputs(
    uint8_t handoff_root[32], uint8_t admission_a_root[32],
    uint8_t admission_b_root[32], int64_t *resume_unix)
{
    const char *handoff_text = getenv(ZPF_ENV_HANDOFF_ROOT);
    const char *admission_a_text = getenv(ZPF_ENV_ADMISSION_A_ROOT);
    const char *admission_b_text = getenv(ZPF_ENV_ADMISSION_B_ROOT);
    const char *resume_text = getenv(ZPF_ENV_RESUME_UNIX);
    char *end = NULL;
    errno = 0;
    *resume_unix = resume_text ? strtoll(resume_text, &end, 10) : 0;
    return handoff_text && admission_a_text && admission_b_text &&
        resume_text && errno == 0 && end && *end == '\0' &&
        *resume_unix > 0 &&
        zcl_hex_decode_lower(handoff_text, handoff_root, 32) &&
        zcl_hex_decode_lower(admission_a_text, admission_a_root, 32) &&
        zcl_hex_decode_lower(admission_b_text, admission_b_root, 32);
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
    if (role && strcmp(role, "user-session-resume") == 0)
        return !zpf_resume_user_session(workspace, focus_text);
    bool successor = role && strcmp(role, "shared-focus-successor") == 0;
    bool source = role && strcmp(role, "shared-focus-source") == 0;
    uint8_t focus_root[32], handoff_root[32];
    uint8_t admission_a_root[32], admission_b_root[32];
    if ((!source && !successor) || !workspace || !workspace[0] ||
        !focus_text || !zcl_hex_decode_lower(focus_text, focus_root, 32))
        return 1;
    if (source)
        return !zpf_process_reload_focus(
            workspace, focus_root, NULL, NULL, NULL, 0);

    int64_t resume_unix = 0;
    if (!zpf_successor_inputs(handoff_root, admission_a_root,
                              admission_b_root, &resume_unix))
        return 1;
    return !zpf_process_reload_focus(
        workspace, focus_root, handoff_root, admission_a_root,
        admission_b_root, resume_unix);
#endif
}

static size_t zpf_exec_clean_agent_acceptance(
    const char *worker_a, const char *worker_b,
    const uint8_t focus_root[32], const uint8_t handoff_root[32],
    const uint8_t admission_a_root[32],
    const uint8_t admission_b_root[32], int64_t resume_unix)
{
#if defined(_WIN32)
    (void)worker_a; (void)worker_b; (void)focus_root; (void)handoff_root;
    (void)admission_a_root; (void)admission_b_root; (void)resume_unix;
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
    if (zpf_child_exited_zero(waited_a, worker_a_status)) proved++;
    if (zpf_child_exited_zero(waited_b, worker_b_status)) proved++;
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

struct zpf_preedit_fx {
    const char *workspace;
    const char *work_id;
    struct zpf_metrics metrics;
    struct vcs_zcode_agent_context_v1 context;
    struct vcs_zcode_task_v1 task;
    struct vcs_zcode_write_scope_v1 task_scope;
    size_t context_wire_bytes;
    uint8_t task_root[32], source_root[32], goal_root[32];
    uint8_t context_root[32], story_root[32], empty_focus_root[32];
    uint8_t situation_root[32];
    enum zcl_ontology_status story_status;
    uint8_t worker_a_secret[32], worker_b_secret[32], requester_secret[32];
    uint8_t worker_a_key[32], worker_b_key[32], requester_key[32];
    int64_t observed_unix;
    struct vcs_zcode_work_request_v1 requests[2];
    struct vcs_zcode_work_admission_v1 admissions[2];
    uint8_t request_roots[2][32], request_carriers[2][32];
    uint8_t admission_carriers[2][32];
    char situation_hex[65], request_hex[2][65], admission_hex[2][65];
    uint8_t claim_roots_unsorted[2][32], claim_roots[2][32];
    struct vcs_zcode_focus_claim_v1 claims[2];
    struct vcs_zcode_write_scope_v1 scopes[2];
    struct vcs_zcode_focus_v1 focus;
};

static bool zpf_preedit_inputs_valid(const char *workspace, const char *work_id,
                                     const struct json_value *focus_data,
                                     const struct json_value *duplicate_data,
                                     const uint8_t *out_focus_root,
                                     const int64_t *out_observed_us)
{
    return workspace && workspace[0] && work_id && work_id[0] &&
           focus_data && focus_data->type == JSON_OBJ &&
           duplicate_data && duplicate_data->type == JSON_OBJ &&
           out_focus_root && out_observed_us;
}

static bool zpf_preedit_load_roots(struct zpf_preedit_fx *fx,
                                   const struct json_value *focus_data)
{
    return zpf_json_root(focus_data, "task_root", fx->task_root) &&
           zpf_json_root(focus_data, "source_root", fx->source_root) &&
           zpf_json_root(focus_data, "goal_root", fx->goal_root) &&
           zpf_json_root(focus_data, "agent_context_root", fx->context_root) &&
           zpf_json_root(focus_data, "story_root", fx->story_root) &&
           zpf_json_root(focus_data, "focus_root", fx->empty_focus_root) &&
           zpf_json_root(focus_data, "focus_situation_root",
                         fx->situation_root);
}

static bool zpf_preedit_load_status(struct zpf_preedit_fx *fx,
                                    const struct json_value *focus_data)
{
    fx->story_status = ZCL_ONTOLOGY_INCOMPLETE;
    return zpf_status_parse(json_get_str(json_get(focus_data, "story_status")),
                            &fx->story_status) &&
           strcmp(json_get_str(json_get(focus_data, "orientation_status")),
                  "PROVED") == 0;
}

static bool zpf_preedit_duplicate_matches(const struct json_value *duplicate_data,
                                          const struct zpf_preedit_fx *fx)
{
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
    zcl_hex_encode(fx->task_root, 32, task_hex);
    zcl_hex_encode(fx->source_root, 32, source_hex);
    zcl_hex_encode(fx->goal_root, 32, goal_hex);
    zcl_hex_encode(fx->context_root, 32, context_hex);
    return duplicate_kind && duplicate_task && duplicate_source &&
           duplicate_goal && duplicate_context && duplicate_assignment &&
           duplicate_execution &&
           strcmp(duplicate_kind, "DUPLICATE_ACTIVE_WORK") == 0 &&
           strcmp(duplicate_task, task_hex) == 0 &&
           strcmp(duplicate_source, source_hex) == 0 &&
           strcmp(duplicate_goal, goal_hex) == 0 &&
           strcmp(duplicate_context, context_hex) == 0 &&
           strcmp(duplicate_assignment, "UNOBSERVED") == 0 &&
           strcmp(duplicate_execution, "UNOBSERVED") == 0;
}

static bool zpf_preedit_load_task(struct zpf_preedit_fx *fx)
{
    return zpf_load_task(fx->workspace, fx->task_root, &fx->task,
                         &fx->metrics) &&
           memcmp(fx->task.source_root, fx->source_root, 32) == 0 &&
           memcmp(fx->task.goal_root, fx->goal_root, 32) == 0;
}

static bool zpf_preedit_load_context_scope(struct zpf_preedit_fx *fx)
{
    return zpf_load_context(fx->workspace, fx->context_root, &fx->task,
                            fx->task_root, &fx->context,
                            &fx->context_wire_bytes, &fx->metrics) &&
           fx->context_wire_bytes > 0 &&
           zpf_load_scope(fx->workspace, fx->task.write_scope_root,
                          &fx->task_scope, &fx->metrics);
}

static bool zpf_preedit_check_empty_focus(struct zpf_preedit_fx *fx)
{
    struct vcs_zcode_focus_v1 empty_focus;
    uint8_t check_root[32], check_situation[32];
    return vcs_zcode_focus_compose(&fx->task, fx->task_root, fx->context_root,
                                   fx->story_root, fx->story_status, 0, NULL,
                                   0, &empty_focus) == VCS_ZCODE_FOCUS_OK &&
           vcs_zcode_focus_root(&empty_focus, check_root) ==
               VCS_ZCODE_FOCUS_OK &&
           vcs_zcode_focus_situation_root(&empty_focus, check_situation) ==
               VCS_ZCODE_FOCUS_OK &&
           memcmp(check_root, fx->empty_focus_root, 32) == 0 &&
           memcmp(check_situation, fx->situation_root, 32) == 0;
}

static void zpf_preedit_make_keys(struct zpf_preedit_fx *fx)
{
    uint8_t worker_a_seed[32], worker_b_seed[32], requester_seed[32];
    memset(worker_a_seed, 0xb7, sizeof(worker_a_seed));
    memset(worker_b_seed, 0xb9, sizeof(worker_b_seed));
    memset(requester_seed, 0xb8, sizeof(requester_seed));
    ed25519_keypair(fx->worker_a_key, fx->worker_a_secret, worker_a_seed);
    ed25519_keypair(fx->worker_b_key, fx->worker_b_secret, worker_b_seed);
    ed25519_keypair(fx->requester_key, fx->requester_secret, requester_seed);
}

static bool zpf_preedit_observe_window(struct zpf_preedit_fx *fx)
{
    fx->observed_unix = (int64_t)platform_time_wall_unix();
    return fx->observed_unix > 0 && fx->task.expires_unix > fx->observed_unix;
}

static bool zpf_preedit_make_requests(struct zpf_preedit_fx *fx)
{
    zpf_request(&fx->requests[0], UINT64_C(7101), &fx->task, fx->task_root,
                fx->task.source_root, fx->task.acceptance_tests_root,
                fx->context_root, fx->context_root, VCS_ZCODE_WORK_BUILD,
                fx->task.expires_unix);
    zpf_request(&fx->requests[1], UINT64_C(7102), &fx->task, fx->task_root,
                fx->task.source_root, fx->task.proof_policy_root,
                fx->context_root, fx->context_root, VCS_ZCODE_WORK_BUILD,
                fx->task.expires_unix);
    return vcs_zcode_work_request_seal(&fx->requests[0], fx->requester_secret,
                                       fx->requester_key) &&
           vcs_zcode_work_request_seal(&fx->requests[1], fx->requester_secret,
                                       fx->requester_key);
}

static bool zpf_preedit_request_ids(struct zpf_preedit_fx *fx)
{
    return vcs_zcode_work_request_id(&fx->requests[0], fx->request_roots[0]) &&
           vcs_zcode_work_request_id(&fx->requests[1], fx->request_roots[1]);
}

static bool zpf_preedit_store_requests(struct zpf_preedit_fx *fx)
{
    for (size_t i = 0; i < 2; i++) {
        struct vcs_zcode_work_swarm_message message = {
            .type = VCS_ZCODE_WORK_SWARM_REQUEST,
            .body.request = fx->requests[i],
        };
        if (!zpf_store_work_message(fx->workspace, &message,
                                    fx->request_roots[i],
                                    fx->request_carriers[i], NULL,
                                    &fx->metrics))
            return false;
    }
    return true;
}

static bool zpf_preedit_admit_requests(struct zpf_preedit_fx *fx)
{
    return zpf_admission(&fx->admissions[0], &fx->requests[0], 0,
                         VCS_ZCODE_WORK_ADMISSION_GRANTED,
                         fx->worker_a_secret, fx->worker_a_key) &&
           zpf_admission(&fx->admissions[1], &fx->requests[1], 1,
                         VCS_ZCODE_WORK_ADMISSION_GRANTED,
                         fx->worker_b_secret, fx->worker_b_key);
}

static bool zpf_preedit_store_admissions(struct zpf_preedit_fx *fx)
{
    for (size_t i = 0; i < 2; i++) {
        struct vcs_zcode_work_swarm_message message = {
            .type = VCS_ZCODE_WORK_SWARM_ADMISSION,
            .body.admission = fx->admissions[i],
        };
        if (!zpf_store_work_message(fx->workspace, &message, NULL,
                                    fx->admission_carriers[i], NULL,
                                    &fx->metrics))
            return false;
    }
    return true;
}

static void zpf_preedit_encode_hex(struct zpf_preedit_fx *fx)
{
    zcl_hex_encode(fx->situation_root, 32, fx->situation_hex);
    for (size_t i = 0; i < 2; i++) {
        zcl_hex_encode(fx->request_roots[i], 32, fx->request_hex[i]);
        zcl_hex_encode(fx->admission_carriers[i], 32, fx->admission_hex[i]);
    }
}

static bool zpf_preedit_publish_claim(struct zpf_preedit_fx *fx, size_t i,
                                      const char *scope_path)
{
    struct json_value input, paths, path;
    json_init(&input); json_set_object(&input);
    json_init(&paths); json_set_array(&paths);
    json_init(&path); json_set_str(&path, scope_path);
    bool pushed = json_push_back(&paths, &path) &&
                  json_push_kv_str(&input, "workspace", fx->workspace) &&
                  json_push_kv_str(&input, "work", fx->work_id) &&
                  json_push_kv_str(&input, "situation_root",
                                   fx->situation_hex) &&
                  json_push_kv(&input, "write_scope", &paths) &&
                  json_push_kv_str(&input, "work_request_root",
                                   fx->request_hex[i]) &&
                  json_push_kv_str(&input,
                                   "work_admission_carrier_root",
                                   fx->admission_hex[i]);
    if (!pushed) return false;
    struct zcl_command_request command = {.input = &input};
    struct zcl_command_reply reply;
    zcl_command_reply_init(&reply, "zcl.focus_claim_publish_test.v1");
    zcl_native_handle_zcode_focus_claim_publish(&command, &reply);
    bool ok = reply.status == ZCL_COMMAND_STATUS_PASSED &&
              strcmp(json_get_str(json_get(
                         &reply.data, "admitted_work_status")),
                     "PROVED") == 0 &&
              zpf_json_root(&reply.data, "claim_root",
                            fx->claim_roots_unsorted[i]);
    zcl_command_reply_free(&reply);
    json_free(&path); json_free(&paths); json_free(&input);
    return ok;
}

static bool zpf_preedit_push_claim_pair(struct json_value *claims,
                                        struct json_value *admissions,
                                        const uint8_t claim_root[32],
                                        const char *admission_hex)
{
    char claim_hex[65];
    struct json_value claim_value, admission_value;
    zcl_hex_encode(claim_root, 32, claim_hex);
    json_init(&claim_value); json_set_str(&claim_value, claim_hex);
    json_init(&admission_value);
    json_set_str(&admission_value, admission_hex);
    bool pushed = json_push_back(claims, &claim_value) &&
                  json_push_back(admissions, &admission_value);
    json_free(&claim_value); json_free(&admission_value);
    return pushed;
}

static bool zpf_preedit_snapshot_input(struct json_value *input,
                                       const char *workspace,
                                       const char *work_id,
                                       struct json_value *claims,
                                       struct json_value *admissions)
{
    return json_push_kv_str(input, "workspace", workspace) &&
           json_push_kv_str(input, "work", work_id) &&
           json_push_kv(input, "claim_roots", claims) &&
           json_push_kv(input, "work_admission_carrier_roots", admissions);
}

static bool zpf_preedit_forward_snapshot(struct zpf_preedit_fx *fx,
                                         uint8_t out_focus_root[32])
{
    struct json_value snapshot_input, claim_values, admission_values;
    json_init(&snapshot_input); json_set_object(&snapshot_input);
    json_init(&claim_values); json_set_array(&claim_values);
    json_init(&admission_values); json_set_array(&admission_values);
    for (size_t i = 0; i < 2; i++) {
        if (!zpf_preedit_push_claim_pair(&claim_values, &admission_values,
                                         fx->claim_roots_unsorted[i],
                                         fx->admission_hex[i]))
            return false;
    }
    if (!zpf_preedit_snapshot_input(&snapshot_input, fx->workspace,
                                    fx->work_id, &claim_values,
                                    &admission_values))
        return false;
    struct zcl_command_request snapshot_command = {.input = &snapshot_input};
    struct zcl_command_reply snapshot_reply;
    zcl_command_reply_init(&snapshot_reply,
                           "zcl.focus_snapshot_publish_test.v1");
    zcl_native_handle_zcode_focus_snapshot_publish(
        &snapshot_command, &snapshot_reply);
    bool ok = snapshot_reply.status == ZCL_COMMAND_STATUS_PASSED &&
              strcmp(json_get_str(json_get(
                         &snapshot_reply.data, "scope_overlap")),
                     "DISPROVED") == 0 &&
              zpf_json_root(&snapshot_reply.data, "focus_root",
                            out_focus_root);
    zcl_command_reply_free(&snapshot_reply);
    json_free(&admission_values); json_free(&claim_values);
    json_free(&snapshot_input);
    return ok;
}

static bool zpf_preedit_reverse_snapshot(struct zpf_preedit_fx *fx,
                                         const uint8_t out_focus_root[32])
{
    struct json_value reverse_input, reverse_claims, reverse_admissions;
    json_init(&reverse_input); json_set_object(&reverse_input);
    json_init(&reverse_claims); json_set_array(&reverse_claims);
    json_init(&reverse_admissions); json_set_array(&reverse_admissions);
    for (size_t at = 2; at > 0; at--) {
        size_t i = at - 1u;
        if (!zpf_preedit_push_claim_pair(&reverse_claims, &reverse_admissions,
                                         fx->claim_roots_unsorted[i],
                                         fx->admission_hex[i]))
            return false;
    }
    if (!zpf_preedit_snapshot_input(&reverse_input, fx->workspace,
                                    fx->work_id, &reverse_claims,
                                    &reverse_admissions))
        return false;
    struct zcl_command_request reverse_command = {.input = &reverse_input};
    struct zcl_command_reply reverse_reply;
    uint8_t reverse_focus_root[32];
    zcl_command_reply_init(&reverse_reply,
                           "zcl.focus_snapshot_reverse_test.v1");
    zcl_native_handle_zcode_focus_snapshot_publish(
        &reverse_command, &reverse_reply);
    bool ok = reverse_reply.status == ZCL_COMMAND_STATUS_PASSED &&
              zpf_json_root(&reverse_reply.data, "focus_root",
                            reverse_focus_root) &&
              memcmp(reverse_focus_root, out_focus_root, 32) == 0;
    zcl_command_reply_free(&reverse_reply);
    json_free(&reverse_admissions); json_free(&reverse_claims);
    json_free(&reverse_input);
    return ok;
}

static void zpf_preedit_sort_claim_roots(struct zpf_preedit_fx *fx)
{
    bool first_before_second = memcmp(fx->claim_roots_unsorted[0],
                                      fx->claim_roots_unsorted[1], 32) < 0;
    memcpy(fx->claim_roots[0],
           fx->claim_roots_unsorted[first_before_second ? 0 : 1], 32);
    memcpy(fx->claim_roots[1],
           fx->claim_roots_unsorted[first_before_second ? 1 : 0], 32);
}

static bool zpf_preedit_load_claims(struct zpf_preedit_fx *fx)
{
    for (size_t i = 0; i < 2; i++) {
        if (!zpf_load_claim(fx->workspace, fx->claim_roots[i],
                            &fx->claims[i], &fx->metrics))
            return false;
        if (!zpf_load_scope(fx->workspace, fx->claims[i].write_scope_root,
                            &fx->scopes[i], &fx->metrics))
            return false;
    }
    return true;
}

static bool zpf_preedit_load_focus(struct zpf_preedit_fx *fx,
                                   const uint8_t out_focus_root[32])
{
    return zpf_load_focus(fx->workspace, out_focus_root, &fx->focus,
                          &fx->metrics) &&
           vcs_zcode_focus_validate_for_context(&fx->focus, &fx->task,
                                                &fx->context, fx->claim_roots,
                                                2, true) ==
               VCS_ZCODE_FOCUS_OK;
}

static bool zpf_preedit_claims_proved(struct zpf_preedit_fx *fx)
{
    fx->observed_unix = fx->claims[0].created_unix > fx->claims[1].created_unix
        ? fx->claims[0].created_unix : fx->claims[1].created_unix;
    return vcs_zcode_focus_claim_set_status(&fx->focus, fx->claims, fx->scopes,
                                            2, fx->observed_unix) ==
               ZCL_ONTOLOGY_PROVED &&
           vcs_zcode_focus_claim_disjoint_status(
               &fx->claims[0], &fx->scopes[0], &fx->claims[1], &fx->scopes[1],
               fx->observed_unix) == ZCL_ONTOLOGY_PROVED &&
           vcs_zcode_focus_claim_authority_status(
               &fx->focus, &fx->task, &fx->task_scope, &fx->claims[0],
               &fx->scopes[0], fx->observed_unix) == ZCL_ONTOLOGY_PROVED &&
           vcs_zcode_focus_claim_authority_status(
               &fx->focus, &fx->task, &fx->task_scope, &fx->claims[1],
               &fx->scopes[1], fx->observed_unix) == ZCL_ONTOLOGY_PROVED;
}

bool zpd_real_focus_preedit_acceptance(
    const char *workspace, const char *work_id,
    const struct json_value *focus_data,
    const struct json_value *duplicate_data,
    uint8_t out_focus_root[32], int64_t *out_observed_us)
{
    bool accepted = false;
    struct zpf_preedit_fx fx;
    memset(&fx, 0, sizeof(fx));
    vcs_zcode_agent_context_init(&fx.context);
    fx.workspace = workspace;
    fx.work_id = work_id;

    ZPF_REQUIRE(zpf_preedit_inputs_valid(workspace, work_id, focus_data,
                                         duplicate_data, out_focus_root,
                                         out_observed_us));
    memset(out_focus_root, 0, 32);
    *out_observed_us = 0;

    ZPF_REQUIRE(zpf_preedit_load_roots(&fx, focus_data));
    ZPF_REQUIRE(zpf_preedit_load_status(&fx, focus_data));
    ZPF_REQUIRE(zpf_preedit_duplicate_matches(duplicate_data, &fx));
    ZPF_REQUIRE(zpf_preedit_load_task(&fx));
    ZPF_REQUIRE(zpf_preedit_load_context_scope(&fx));
    ZPF_REQUIRE(zpf_preedit_check_empty_focus(&fx));
    zpf_preedit_make_keys(&fx);
    ZPF_REQUIRE(zpf_preedit_observe_window(&fx));
    ZPF_REQUIRE(zpf_preedit_make_requests(&fx));
    ZPF_REQUIRE(zpf_preedit_request_ids(&fx));
    ZPF_REQUIRE(zpf_preedit_store_requests(&fx));
    ZPF_REQUIRE(zpf_preedit_admit_requests(&fx));
    ZPF_REQUIRE(zpf_preedit_store_admissions(&fx));
    zpf_preedit_encode_hex(&fx);

    const char *scope_paths[2] = {"src/x.c", "include/x.h"};
    for (size_t i = 0; i < 2; i++)
        ZPF_REQUIRE(zpf_preedit_publish_claim(&fx, i, scope_paths[i]));
    ZPF_REQUIRE(zpf_preedit_forward_snapshot(&fx, out_focus_root));
    ZPF_REQUIRE(zpf_preedit_reverse_snapshot(&fx, out_focus_root));
    zpf_preedit_sort_claim_roots(&fx);
    ZPF_REQUIRE(zpf_preedit_load_claims(&fx));
    ZPF_REQUIRE(zpf_preedit_load_focus(&fx, out_focus_root));
    ZPF_REQUIRE(zpf_preedit_claims_proved(&fx));
    *out_observed_us = platform_time_monotonic_us();
    ZPF_REQUIRE(*out_observed_us > 0);
    accepted = true;

cleanup:
    vcs_zcode_agent_context_free(&fx.context);
    memset(fx.worker_a_secret, 0, sizeof(fx.worker_a_secret));
    memset(fx.worker_b_secret, 0, sizeof(fx.worker_b_secret));
    memset(fx.requester_secret, 0, sizeof(fx.requester_secret));
    if (!accepted && out_focus_root) memset(out_focus_root, 0, 32);
    if (!accepted && out_observed_us) *out_observed_us = 0;
    return accepted;
}

struct zpf_handoff_fx {
    struct zpf_metrics metrics;
    uint8_t *claim_set_wire;
    size_t claim_set_wire_len;
    uint8_t *handoff_wire;
    size_t handoff_wire_len;
    uint8_t *preedit_claim_set_wire;
    size_t preedit_claim_set_wire_len;
    uint8_t worker_a_secret[32], worker_b_secret[32], requester_secret[32];
    uint8_t worker_a_key[32], worker_b_key[32], requester_key[32];
    struct vcs_zcode_agent_context_v1 context_a, context_b;
    char worker_a[PATH_MAX], worker_b[PATH_MAX];
    int64_t measured_started_us;
    uint8_t task_root[32], context_root[32], story_root[32];
    uint8_t empty_focus_root[32], expected_situation_root[32];
    struct vcs_zcode_task_v1 source_task;
    struct vcs_zcode_write_scope_v1 source_task_scope;
    struct vcs_zcode_focus_v1 preedit_focus;
    uint8_t preedit_claim_roots[2][32];
    struct vcs_zcode_focus_claim_v1 preedit_claims[2];
    struct vcs_zcode_write_scope_v1 preedit_scopes[2];
    int64_t preedit_claim_time;
    uint8_t receipt_root[32];
    struct vcs_zcode_work_receipt_v1 source_receipt;
    int64_t completed_unix, source_expires_unix, successor_expires_unix;
    int64_t request_deadline_unix, resume_unix;
    struct vcs_zcode_task_v1 task_a, task_b;
    struct vcs_zcode_write_scope_v1 task_scope_a, task_scope_b;
    size_t context_wire_bytes, context_b_wire_bytes;
    struct vcs_zcode_focus_v1 empty_a, empty_b;
    uint8_t situation_a[32], situation_b[32], check_root[32];
    uint8_t continuation_root[32];
    struct vcs_zcode_write_scope_v1 scope_a, scope_b;
    uint8_t scope_a_root[32], scope_b_root[32];
    size_t scope_a_bytes, scope_b_bytes;
    struct vcs_zcode_work_request_v1 request_a, request_b;
    uint8_t request_a_root[32], request_b_root[32];
    struct vcs_zcode_work_admission_v1 admission_a, admission_b;
    uint32_t duplicate_actions;
    struct vcs_zcode_work_swarm_message message_a, message_b;
    uint8_t request_a_carrier[32];
    size_t request_a_bytes;
    uint8_t admission_a_carrier[32], admission_b_carrier[32];
    size_t admission_a_bytes, admission_b_bytes;
    struct vcs_zcode_focus_claim_v1 claim_a, claim_b;
    uint8_t claim_a_root[32], claim_b_root[32];
    struct vcs_zcode_focus_claim_v1 claim_a_at_b, claim_b_at_a;
    struct vcs_zcode_write_scope_v1 scope_a_at_b, scope_b_at_a;
    struct vcs_zcode_focus_claim_v1 claims_a[2], claims_b[2];
    struct vcs_zcode_write_scope_v1 scopes_a[2], scopes_b[2];
    uint8_t claim_roots_a[2][32], claim_roots_b[2][32];
    size_t from_a, next_a, from_b, next_b;
    struct vcs_zcode_focus_v1 focus_a, focus_b;
    uint8_t focus_a_root[32], focus_b_root[32];
    uint64_t fixture_setup_us;
    uint32_t fixture_cas_tool_calls;
    struct vcs_zcode_specialist_report_v1 report_a, report_b;
    uint8_t report_a_root[32], report_b_root[32];
    struct vcs_zcode_specialist_report_v1 report_a_at_b, report_b_at_a;
    struct vcs_zcode_focus_handoff_v1 handoff;
    uint8_t handoff_root[32];
    size_t independent_processes;
    struct vcs_zcode_work_swarm_message request_a_at_b, request_b_at_b;
    struct vcs_zcode_work_swarm_message admission_a_at_b, admission_b_at_b;
    struct vcs_zcode_work_receipt_v1 receipt_at_b;
    struct vcs_zcode_focus_handoff_v1 handoff_at_b;
    uint8_t request_check[32];
    uint64_t edit_to_observation_us;
};

static bool zpf_handoff_inputs_valid(const char *workspace, const char *work_id,
                                     const struct json_value *focus_data,
                                     const uint8_t *source_receipt_root,
                                     const uint8_t *preedit_focus_root,
                                     int64_t preedit_observed_us,
                                     int64_t edit_started_us)
{
    return workspace && workspace[0] && work_id && work_id[0] &&
           focus_data && focus_data->type == JSON_OBJ &&
           source_receipt_root && preedit_focus_root &&
           preedit_observed_us > 0 &&
           edit_started_us >= preedit_observed_us;
}

static bool zpf_handoff_load_inputs(struct zpf_handoff_fx *fx,
                                    const struct json_value *focus_data)
{
    return zpf_json_root(focus_data, "task_root", fx->task_root) &&
           zpf_json_root(focus_data, "agent_context_root", fx->context_root) &&
           zpf_json_root(focus_data, "story_root", fx->story_root) &&
           zpf_json_root(focus_data, "focus_root", fx->empty_focus_root) &&
           zpf_json_root(focus_data, "focus_situation_root",
                         fx->expected_situation_root) &&
           strcmp(json_get_str(json_get(focus_data, "story_status")),
                  "PROVED") == 0;
}

static bool zpf_handoff_load_source_task(struct zpf_handoff_fx *fx,
                                         const char *workspace)
{
    return zpf_load_task(workspace, fx->task_root, &fx->source_task,
                         &fx->metrics) &&
           zpf_load_scope(workspace, fx->source_task.write_scope_root,
                          &fx->source_task_scope, &fx->metrics) &&
           vcs_zcode_write_scope_contains(&fx->source_task_scope, "src/x.c") &&
           vcs_zcode_write_scope_contains(&fx->source_task_scope,
                                          "include/x.h");
}

static bool zpf_handoff_load_preedit(struct zpf_handoff_fx *fx,
                                     const char *workspace,
                                     const uint8_t preedit_focus_root[32])
{
    return zpf_load_focus(workspace, preedit_focus_root, &fx->preedit_focus,
                          &fx->metrics) &&
           memcmp(fx->preedit_focus.task_root, fx->task_root, 32) == 0 &&
           memcmp(fx->preedit_focus.goal_root, fx->source_task.goal_root,
                  32) == 0 &&
           memcmp(fx->preedit_focus.source_universe_root,
                  fx->source_task.source_root, 32) == 0 &&
           memcmp(fx->preedit_focus.context_root, fx->context_root, 32) == 0 &&
           fx->preedit_focus.claim_count == 2;
}

static bool zpf_handoff_parse_preedit_claims(struct zpf_handoff_fx *fx,
                                             const char *workspace)
{
    size_t count = 0;
    if (!zpf_load(workspace, fx->preedit_focus.claim_set_root,
                  VCS_ZCODE_FOCUS_CLAIM_SET_WIRE_MAX,
                  &fx->preedit_claim_set_wire,
                  &fx->preedit_claim_set_wire_len, &fx->metrics))
        return false;
    bool parsed = vcs_zcode_focus_claim_set_parse(
                      fx->preedit_claim_set_wire,
                      fx->preedit_claim_set_wire_len,
                      fx->preedit_claim_roots, 2, &count) ==
                      VCS_ZCODE_FOCUS_OK && count == 2;
    free(fx->preedit_claim_set_wire);
    fx->preedit_claim_set_wire = NULL;
    return parsed;
}

static bool zpf_handoff_load_preedit_claims(struct zpf_handoff_fx *fx,
                                            const char *workspace)
{
    for (size_t i = 0; i < 2; i++) {
        if (!zpf_load_claim(workspace, fx->preedit_claim_roots[i],
                            &fx->preedit_claims[i], &fx->metrics))
            return false;
        if (!zpf_load_scope(workspace,
                            fx->preedit_claims[i].write_scope_root,
                            &fx->preedit_scopes[i], &fx->metrics))
            return false;
        if (memcmp(fx->preedit_claims[i].evidence_plan_root,
                   fx->source_task.proof_policy_root, 32) != 0)
            return false;
    }
    return true;
}

static bool zpf_handoff_preedit_status(struct zpf_handoff_fx *fx)
{
    fx->preedit_claim_time = fx->preedit_claims[0].created_unix;
    if (fx->preedit_claims[1].created_unix > fx->preedit_claim_time)
        fx->preedit_claim_time = fx->preedit_claims[1].created_unix;
    return vcs_zcode_focus_claim_set_status(
               &fx->preedit_focus, fx->preedit_claims, fx->preedit_scopes, 2,
               fx->preedit_claim_time) == ZCL_ONTOLOGY_PROVED &&
           vcs_zcode_focus_claim_disjoint_status(
               &fx->preedit_claims[0], &fx->preedit_scopes[0],
               &fx->preedit_claims[1], &fx->preedit_scopes[1],
               fx->preedit_claim_time) == ZCL_ONTOLOGY_PROVED;
}

static bool zpf_handoff_preedit_authority(struct zpf_handoff_fx *fx)
{
    for (size_t i = 0; i < 2; i++) {
        if (vcs_zcode_focus_claim_authority_status(
                &fx->preedit_focus, &fx->source_task, &fx->source_task_scope,
                &fx->preedit_claims[i], &fx->preedit_scopes[i],
                fx->preedit_claim_time) != ZCL_ONTOLOGY_PROVED)
            return false;
    }
    fx->metrics.conflicts = 1;
    return true;
}

static bool zpf_handoff_load_receipt(struct zpf_handoff_fx *fx,
                                     const char *workspace,
                                     const uint8_t source_receipt_root[32])
{
    memcpy(fx->receipt_root, source_receipt_root, 32);
    return zpf_load_receipt(workspace, fx->receipt_root, &fx->source_receipt,
                            &fx->metrics) &&
           fx->source_receipt.work_kind == VCS_ZCODE_WORK_BUILD &&
           fx->source_receipt.status == VCS_ZCODE_WORK_PASS &&
           fx->source_receipt.exit_status == 0 &&
           memcmp(fx->source_receipt.task_root, fx->task_root, 32) == 0;
}

static void zpf_handoff_make_keys(struct zpf_handoff_fx *fx)
{
    uint8_t worker_a_seed[32], worker_b_seed[32], requester_seed[32];
    memset(worker_a_seed, 0xb7, sizeof(worker_a_seed));
    memset(worker_b_seed, 0xb9, sizeof(worker_b_seed));
    memset(requester_seed, 0xb8, sizeof(requester_seed));
    ed25519_keypair(fx->worker_a_key, fx->worker_a_secret, worker_a_seed);
    ed25519_keypair(fx->worker_b_key, fx->worker_b_secret, worker_b_seed);
    ed25519_keypair(fx->requester_key, fx->requester_secret, requester_seed);
}

static bool zpf_handoff_schedule_ok(struct zpf_handoff_fx *fx)
{
    fx->completed_unix = fx->source_receipt.finished_unix;
    return memcmp(fx->worker_a_key, fx->source_receipt.signer_pubkey, 32) ==
               0 &&
           fx->completed_unix > 0 &&
           fx->completed_unix <= INT64_MAX - 8 &&
           fx->source_task.expires_unix > fx->completed_unix + 6;
}

static void zpf_handoff_set_deadlines(struct zpf_handoff_fx *fx)
{
    fx->source_expires_unix = fx->completed_unix + 2;
    fx->successor_expires_unix = fx->completed_unix + 5;
    fx->request_deadline_unix = fx->completed_unix + 6;
    fx->resume_unix = fx->completed_unix + 3;
}

static bool zpf_handoff_transfer_base(struct zpf_handoff_fx *fx,
                                      const char *workspace)
{
    const uint8_t *base_roots[] = {
        fx->task_root, fx->context_root, fx->source_task.write_scope_root,
        fx->receipt_root, fx->source_task.acceptance_tests_root,
    };
    const size_t base_maximums[] = {
        VCS_ZCODE_TASK_WIRE_BYTES, (size_t)fx->source_task.max_context_bytes,
        VCS_ZCODE_WRITE_SCOPE_WIRE_MAX,
        VCS_ZCODE_WORK_RECEIPT_WIRE_BYTES,
        VCS_PACKAGE_RECIPE_MAX_WIRE_BYTES,
    };
    for (size_t i = 0; i < sizeof(base_roots) / sizeof(base_roots[0]); i++) {
        if (!zpf_transfer(workspace, fx->worker_a, base_roots[i],
                          base_maximums[i], &fx->metrics))
            return false;
        if (!zpf_transfer(workspace, fx->worker_b, base_roots[i],
                          base_maximums[i], &fx->metrics))
            return false;
    }
    return zpf_load_recipe(fx->worker_a,
                           fx->source_task.acceptance_tests_root,
                           &fx->metrics) &&
           zpf_load_recipe(fx->worker_b,
                           fx->source_task.acceptance_tests_root,
                           &fx->metrics);
}

static bool zpf_handoff_stage_workers(struct zpf_handoff_fx *fx,
                                      const char *workspace)
{
    test_make_tmpdir(fx->worker_a, sizeof(fx->worker_a), "real_focus", "a");
    test_make_tmpdir(fx->worker_b, sizeof(fx->worker_b), "real_focus", "b");
    return vcs_object_store_init(fx->worker_a) &&
           vcs_object_store_init(fx->worker_b) &&
           zpf_handoff_transfer_base(fx, workspace);
}

static bool zpf_handoff_load_workers_tasks(struct zpf_handoff_fx *fx)
{
    return zpf_load_task(fx->worker_a, fx->task_root, &fx->task_a,
                         &fx->metrics) &&
           zpf_load_task(fx->worker_b, fx->task_root, &fx->task_b,
                         &fx->metrics) &&
           zpf_load_context(fx->worker_a, fx->context_root, &fx->task_a,
                            fx->task_root, &fx->context_a,
                            &fx->context_wire_bytes, &fx->metrics) &&
           zpf_load_context(fx->worker_b, fx->context_root, &fx->task_b,
                            fx->task_root, &fx->context_b,
                            &fx->context_b_wire_bytes, &fx->metrics) &&
           fx->context_wire_bytes == fx->context_b_wire_bytes;
}

static bool zpf_handoff_validate_preedit_context(struct zpf_handoff_fx *fx)
{
    return vcs_zcode_focus_validate_for_context(
               &fx->preedit_focus, &fx->source_task, &fx->context_a,
               fx->preedit_claim_roots, 2, false) == VCS_ZCODE_FOCUS_OK &&
           zpf_load_scope(fx->worker_a, fx->task_a.write_scope_root,
                          &fx->task_scope_a, &fx->metrics) &&
           zpf_load_scope(fx->worker_b, fx->task_b.write_scope_root,
                          &fx->task_scope_b, &fx->metrics);
}

static bool zpf_handoff_compose_empty(struct zpf_handoff_fx *fx)
{
    return vcs_zcode_focus_compose(&fx->task_a, fx->task_root, fx->context_root,
                                   fx->story_root, ZCL_ONTOLOGY_PROVED, 0,
                                   NULL, 0, &fx->empty_a) ==
               VCS_ZCODE_FOCUS_OK &&
           vcs_zcode_focus_compose(&fx->task_b, fx->task_root, fx->context_root,
                                   fx->story_root, ZCL_ONTOLOGY_PROVED, 0,
                                   NULL, 0, &fx->empty_b) ==
               VCS_ZCODE_FOCUS_OK &&
           vcs_zcode_focus_situation_root(&fx->empty_a, fx->situation_a) ==
               VCS_ZCODE_FOCUS_OK &&
           vcs_zcode_focus_situation_root(&fx->empty_b, fx->situation_b) ==
               VCS_ZCODE_FOCUS_OK &&
           vcs_zcode_focus_root(&fx->empty_a, fx->check_root) ==
               VCS_ZCODE_FOCUS_OK &&
           memcmp(fx->check_root, fx->empty_focus_root, 32) == 0 &&
           memcmp(fx->situation_a, fx->situation_b, 32) == 0 &&
           memcmp(fx->situation_a, fx->expected_situation_root, 32) == 0;
}

static bool zpf_handoff_store_scopes(struct zpf_handoff_fx *fx)
{
    vcs_zcode_write_scope_init(&fx->scope_a);
    vcs_zcode_write_scope_init(&fx->scope_b);
    return vcs_zcode_write_scope_add(&fx->scope_a, "src/x.c") ==
               VCS_ZCODE_WRITE_SCOPE_OK &&
           vcs_zcode_write_scope_add(&fx->scope_b, "include/x.h") ==
               VCS_ZCODE_WRITE_SCOPE_OK &&
           zpf_store_scope(fx->worker_a, &fx->scope_a, fx->scope_a_root,
                           &fx->scope_a_bytes, &fx->metrics) &&
           zpf_store_scope(fx->worker_b, &fx->scope_b, fx->scope_b_root,
                           &fx->scope_b_bytes, &fx->metrics) &&
           zpf_transfer(fx->worker_a, fx->worker_b, fx->scope_a_root,
                        fx->scope_a_bytes, &fx->metrics) &&
           zpf_transfer(fx->worker_b, fx->worker_a, fx->scope_b_root,
                        fx->scope_b_bytes, &fx->metrics);
}

static bool zpf_handoff_continuation_root(struct zpf_handoff_fx *fx)
{
    memcpy(fx->continuation_root, fx->task_a.acceptance_tests_root, 32);
    return memcmp(fx->continuation_root, fx->task_b.acceptance_tests_root,
                  32) == 0;
}

static bool zpf_handoff_make_requests(struct zpf_handoff_fx *fx)
{
    zpf_request(&fx->request_a, 1, &fx->task_a, fx->task_root,
                fx->source_receipt.candidate_root,
                fx->source_receipt.action_root,
                fx->source_receipt.input_root, fx->context_root,
                fx->source_receipt.work_kind, fx->request_deadline_unix);
    if (!vcs_zcode_work_request_seal(&fx->request_a, fx->requester_secret,
                                     fx->requester_key))
        return false;
    fx->request_b = fx->request_a;
    return memcmp(fx->request_a.action_root, fx->request_b.action_root, 32) ==
               0 &&
           vcs_zcode_work_request_id(&fx->request_a, fx->request_a_root) &&
           vcs_zcode_work_request_id(&fx->request_b, fx->request_b_root) &&
           memcmp(fx->request_a_root, fx->request_b_root, 32) == 0;
}

static bool zpf_handoff_admit_requests(struct zpf_handoff_fx *fx)
{
    if (!zpf_admission(&fx->admission_a, &fx->request_a, 0,
                       VCS_ZCODE_WORK_ADMISSION_GRANTED,
                       fx->worker_a_secret, fx->worker_a_key))
        return false;
    if (!zpf_admission(&fx->admission_b, &fx->request_b, 1,
                       VCS_ZCODE_WORK_ADMISSION_ATTACHED,
                       fx->worker_b_secret, fx->worker_b_key))
        return false;
    fx->duplicate_actions =
        fx->admission_b.disposition == VCS_ZCODE_WORK_ADMISSION_ATTACHED
            ? 1u : 0u;
    return fx->duplicate_actions == 1u;
}

static bool zpf_handoff_store_messages(struct zpf_handoff_fx *fx)
{
    fx->message_a = (struct vcs_zcode_work_swarm_message) {
        .type = VCS_ZCODE_WORK_SWARM_REQUEST,
        .body.request = fx->request_a,
    };
    if (!zpf_store_work_message(fx->worker_a, &fx->message_a,
                                fx->request_a_root, fx->request_a_carrier,
                                &fx->request_a_bytes, &fx->metrics))
        return false;
    fx->message_a = (struct vcs_zcode_work_swarm_message) {
        .type = VCS_ZCODE_WORK_SWARM_ADMISSION,
        .body.admission = fx->admission_a,
    };
    fx->message_b = (struct vcs_zcode_work_swarm_message) {
        .type = VCS_ZCODE_WORK_SWARM_ADMISSION,
        .body.admission = fx->admission_b,
    };
    return zpf_store_work_message(fx->worker_a, &fx->message_a, NULL,
                                  fx->admission_a_carrier,
                                  &fx->admission_a_bytes, &fx->metrics) &&
           zpf_store_work_message(fx->worker_b, &fx->message_b, NULL,
                                  fx->admission_b_carrier,
                                  &fx->admission_b_bytes, &fx->metrics) &&
           zpf_transfer(fx->worker_a, fx->worker_b, fx->request_a_root,
                        fx->request_a_bytes, &fx->metrics) &&
           zpf_transfer(fx->worker_a, fx->worker_b, fx->admission_a_carrier,
                        fx->admission_a_bytes, &fx->metrics) &&
           zpf_transfer(fx->worker_b, fx->worker_a, fx->admission_b_carrier,
                        fx->admission_b_bytes, &fx->metrics);
}

static bool zpf_handoff_build_claims(struct zpf_handoff_fx *fx)
{
    fx->claim_a = (struct vcs_zcode_focus_claim_v1) {
        .schema_version = VCS_ZCODE_FOCUS_VERSION,
        /* This fixture observes the claim only after the real receipt exists.
         * Do not backdate it to imply pre-edit publication. */
        .created_unix = fx->completed_unix,
        .expires_unix = fx->source_expires_unix,
    };
    fx->claim_b = (struct vcs_zcode_focus_claim_v1) {
        .schema_version = VCS_ZCODE_FOCUS_VERSION,
        .created_unix = fx->completed_unix,
        .expires_unix = fx->successor_expires_unix,
    };
    if (fx->claim_a.created_unix != fx->completed_unix)
        return false;
    memcpy(fx->claim_a.situation_root, fx->situation_a, 32);
    memcpy(fx->claim_a.claimant_root, fx->worker_a_key, 32);
    memcpy(fx->claim_a.write_scope_root, fx->scope_a_root, 32);
    memcpy(fx->claim_a.intent_root, fx->request_a_root, 32);
    memcpy(fx->claim_a.evidence_plan_root, fx->request_a.proof_policy_root,
           32);
    memcpy(fx->claim_b.situation_root, fx->situation_b, 32);
    memcpy(fx->claim_b.claimant_root, fx->worker_b_key, 32);
    memcpy(fx->claim_b.write_scope_root, fx->scope_b_root, 32);
    memcpy(fx->claim_b.intent_root, fx->request_b_root, 32);
    memcpy(fx->claim_b.evidence_plan_root, fx->request_b.proof_policy_root,
           32);
    return true;
}

static bool zpf_handoff_store_claims(struct zpf_handoff_fx *fx)
{
    return zpf_store_claim(fx->worker_a, &fx->claim_a, fx->claim_a_root,
                           &fx->metrics) &&
           zpf_store_claim(fx->worker_b, &fx->claim_b, fx->claim_b_root,
                           &fx->metrics) &&
           zpf_transfer(fx->worker_a, fx->worker_b, fx->claim_a_root,
                        VCS_ZCODE_FOCUS_CLAIM_WIRE_BYTES, &fx->metrics) &&
           zpf_transfer(fx->worker_b, fx->worker_a, fx->claim_b_root,
                        VCS_ZCODE_FOCUS_CLAIM_WIRE_BYTES, &fx->metrics);
}

static bool zpf_handoff_load_cross_claims(struct zpf_handoff_fx *fx)
{
    return zpf_load_claim(fx->worker_b, fx->claim_a_root, &fx->claim_a_at_b,
                          &fx->metrics) &&
           zpf_load_claim(fx->worker_a, fx->claim_b_root, &fx->claim_b_at_a,
                          &fx->metrics) &&
           zpf_load_scope(fx->worker_b, fx->scope_a_root, &fx->scope_a_at_b,
                          &fx->metrics) &&
           zpf_load_scope(fx->worker_a, fx->scope_b_root, &fx->scope_b_at_a,
                          &fx->metrics);
}

static bool zpf_handoff_order_claims(struct zpf_handoff_fx *fx)
{
    zpf_order_claims(&fx->claim_a, &fx->scope_a, fx->claim_a_root,
                     &fx->claim_b_at_a, &fx->scope_b_at_a, fx->claim_b_root,
                     fx->claims_a, fx->scopes_a, fx->claim_roots_a,
                     &fx->from_a, &fx->next_a);
    zpf_order_claims(&fx->claim_a_at_b, &fx->scope_a_at_b, fx->claim_a_root,
                     &fx->claim_b, &fx->scope_b, fx->claim_b_root,
                     fx->claims_b, fx->scopes_b, fx->claim_roots_b,
                     &fx->from_b, &fx->next_b);
    return memcmp(fx->claim_roots_a, fx->claim_roots_b,
                  sizeof(fx->claim_roots_a)) == 0 &&
           fx->from_a == fx->from_b && fx->next_a == fx->next_b;
}

static bool zpf_handoff_compose_focus(struct zpf_handoff_fx *fx)
{
    return vcs_zcode_focus_compose(&fx->task_a, fx->task_root, fx->context_root,
                                   fx->story_root, ZCL_ONTOLOGY_PROVED, 0,
                                   fx->claim_roots_a, 2, &fx->focus_a) ==
               VCS_ZCODE_FOCUS_OK &&
           vcs_zcode_focus_compose(&fx->task_b, fx->task_root, fx->context_root,
                                   fx->story_root, ZCL_ONTOLOGY_PROVED, 0,
                                   fx->claim_roots_b, 2, &fx->focus_b) ==
               VCS_ZCODE_FOCUS_OK;
}

static bool zpf_handoff_store_focus(struct zpf_handoff_fx *fx)
{
    return zpf_store_focus(fx->worker_a, &fx->focus_a, fx->focus_a_root,
                           &fx->metrics) &&
           zpf_store_focus(fx->worker_b, &fx->focus_b, fx->focus_b_root,
                           &fx->metrics) &&
           memcmp(fx->focus_a_root, fx->focus_b_root, 32) == 0 &&
           memcmp(fx->focus_a_root, fx->empty_focus_root, 32) != 0 &&
           vcs_zcode_focus_claim_set_status(&fx->focus_b, fx->claims_b,
                                            fx->scopes_b, 2,
                                            fx->completed_unix) ==
               ZCL_ONTOLOGY_PROVED &&
           vcs_zcode_focus_claim_disjoint_status(
               &fx->claim_a_at_b, &fx->scope_a_at_b, &fx->claim_b, &fx->scope_b,
               fx->completed_unix) == ZCL_ONTOLOGY_PROVED;
}

static bool zpf_handoff_store_claim_set(struct zpf_handoff_fx *fx)
{
    return vcs_zcode_focus_claim_set_serialize(
               fx->claim_roots_a, 2, &fx->claim_set_wire,
               &fx->claim_set_wire_len) == VCS_ZCODE_FOCUS_OK &&
           zpf_store_addressed(fx->worker_a, fx->focus_a.claim_set_root,
                               fx->claim_set_wire, fx->claim_set_wire_len,
                               &fx->metrics) &&
           zpf_store_addressed(fx->worker_b, fx->focus_b.claim_set_root,
                               fx->claim_set_wire, fx->claim_set_wire_len,
                               &fx->metrics);
}

static void zpf_handoff_fixture_timing(struct zpf_handoff_fx *fx)
{
    int64_t measured_elapsed =
        platform_time_monotonic_us() - fx->measured_started_us;
    fx->fixture_setup_us = measured_elapsed > 0
        ? (uint64_t)measured_elapsed : 1u;
    fx->fixture_cas_tool_calls = fx->metrics.tool_calls > 0
        ? fx->metrics.tool_calls : 1u;
}

static void zpf_handoff_build_reports(struct zpf_handoff_fx *fx)
{
    fx->report_a = (struct vcs_zcode_specialist_report_v1) {
        .schema_version = VCS_ZCODE_FOCUS_VERSION,
        .role = VCS_ZCODE_SPECIALIST_CODE,
        .status = ZCL_ONTOLOGY_PROVED,
        .context_bytes = fx->context_wire_bytes,
        /* These are shared fixture observations, not a source-agent trace. */
        .latency_us = fx->fixture_setup_us,
        .files_opened = 0,
        .tool_calls = fx->fixture_cas_tool_calls,
        .duplicate_actions = 0,
        .proof_reuse_count = 1,
    };
    memcpy(fx->report_a.focus_root, fx->focus_a_root, 32);
    memcpy(fx->report_a.claim_root, fx->claim_a_root, 32);
    memcpy(fx->report_a.specialist_root, fx->worker_a_key, 32);
    memcpy(fx->report_a.evidence_root, fx->receipt_root, 32);
    memcpy(fx->report_a.result_root, fx->source_receipt.output_root, 32);
    memcpy(fx->report_a.next_experiment_root, fx->continuation_root, 32);
    memcpy(fx->report_a.evaluator_root, fx->task_a.proof_policy_root, 32);
    fx->report_b = (struct vcs_zcode_specialist_report_v1) {
        .schema_version = VCS_ZCODE_FOCUS_VERSION,
        .role = VCS_ZCODE_SPECIALIST_PROOF,
        .status = ZCL_ONTOLOGY_INCOMPLETE,
        .context_bytes = fx->context_b_wire_bytes,
        .latency_us = fx->fixture_setup_us,
        .files_opened = 0,
        .tool_calls = fx->fixture_cas_tool_calls,
        .duplicate_actions = fx->duplicate_actions,
        .proof_reuse_count = 1,
    };
    memcpy(fx->report_b.focus_root, fx->focus_b_root, 32);
    memcpy(fx->report_b.claim_root, fx->claim_b_root, 32);
    memcpy(fx->report_b.specialist_root, fx->worker_b_key, 32);
    memcpy(fx->report_b.evidence_root, fx->request_b_root, 32);
    memcpy(fx->report_b.result_root, fx->continuation_root, 32);
    memcpy(fx->report_b.next_experiment_root,
           fx->task_b.acceptance_tests_root, 32);
    memcpy(fx->report_b.evaluator_root, fx->task_b.proof_policy_root, 32);
}

static bool zpf_handoff_store_reports(struct zpf_handoff_fx *fx)
{
    return zpf_store_report(fx->worker_a, &fx->report_a, fx->report_a_root,
                            &fx->metrics) &&
           zpf_store_report(fx->worker_b, &fx->report_b, fx->report_b_root,
                            &fx->metrics) &&
           zpf_transfer(fx->worker_a, fx->worker_b, fx->report_a_root,
                        VCS_ZCODE_SPECIALIST_REPORT_WIRE_BYTES,
                        &fx->metrics) &&
           zpf_transfer(fx->worker_b, fx->worker_a, fx->report_b_root,
                        VCS_ZCODE_SPECIALIST_REPORT_WIRE_BYTES,
                        &fx->metrics);
}

static bool zpf_handoff_load_reports(struct zpf_handoff_fx *fx)
{
    return zpf_load_report(fx->worker_b, fx->report_a_root,
                           &fx->report_a_at_b, &fx->metrics) &&
           zpf_load_report(fx->worker_a, fx->report_b_root,
                           &fx->report_b_at_a, &fx->metrics);
}

static void zpf_handoff_build_handoff(struct zpf_handoff_fx *fx)
{
    fx->handoff = (struct vcs_zcode_focus_handoff_v1) {
        .schema_version = VCS_ZCODE_FOCUS_VERSION,
        .status = ZCL_ONTOLOGY_PROVED,
    };
    memcpy(fx->handoff.focus_root, fx->focus_a_root, 32);
    memcpy(fx->handoff.report_root, fx->report_a_root, 32);
    memcpy(fx->handoff.from_claim_root, fx->claim_a_root, 32);
    memcpy(fx->handoff.to_specialist_root, fx->worker_b_key, 32);
    memcpy(fx->handoff.next_claim_root, fx->claim_b_root, 32);
    memcpy(fx->handoff.required_evidence_root,
           fx->focus_a.required_evidence_root, 32);
    memcpy(fx->handoff.continuation_root, fx->continuation_root, 32);
}

static bool zpf_handoff_store_handoff(struct zpf_handoff_fx *fx)
{
    return zpf_store_handoff(fx->worker_a, &fx->handoff, fx->handoff_root,
                             &fx->metrics) &&
           zpf_transfer(fx->worker_a, fx->worker_b, fx->handoff_root,
                        VCS_ZCODE_FOCUS_HANDOFF_WIRE_BYTES, &fx->metrics);
}

static bool zpf_handoff_run_independent(struct zpf_handoff_fx *fx)
{
    fx->independent_processes = zpf_exec_clean_agent_acceptance(
        fx->worker_a, fx->worker_b, fx->focus_a_root, fx->handoff_root,
        fx->admission_a_carrier, fx->admission_b_carrier, fx->resume_unix);
#if defined(_WIN32)
    return fx->independent_processes == 0;
#else
    return fx->independent_processes == 2;
#endif
}

static bool zpf_handoff_load_messages_at_b(struct zpf_handoff_fx *fx)
{
    return zpf_load_work_message(fx->worker_b, fx->request_a_root,
                                 VCS_ZCODE_WORK_SWARM_REQUEST,
                                 &fx->request_a_at_b, &fx->metrics) &&
           zpf_load_work_message(fx->worker_b, fx->request_b_root,
                                 VCS_ZCODE_WORK_SWARM_REQUEST,
                                 &fx->request_b_at_b, &fx->metrics) &&
           zpf_load_work_message(fx->worker_b, fx->admission_a_carrier,
                                 VCS_ZCODE_WORK_SWARM_ADMISSION,
                                 &fx->admission_a_at_b, &fx->metrics) &&
           zpf_load_work_message(fx->worker_b, fx->admission_b_carrier,
                                 VCS_ZCODE_WORK_SWARM_ADMISSION,
                                 &fx->admission_b_at_b, &fx->metrics);
}

static bool zpf_handoff_request_ids_at_b(struct zpf_handoff_fx *fx)
{
    return vcs_zcode_work_request_id(&fx->request_a_at_b.body.request,
                                     fx->request_check) &&
           memcmp(fx->request_check, fx->request_a_root, 32) == 0 &&
           vcs_zcode_work_request_id(&fx->request_b_at_b.body.request,
                                     fx->request_check) &&
           memcmp(fx->request_check, fx->request_b_root, 32) == 0;
}

static bool zpf_handoff_load_handoff_at_b(struct zpf_handoff_fx *fx)
{
    if (!zpf_load_receipt(fx->worker_b, fx->receipt_root,
                          &fx->receipt_at_b, &fx->metrics))
        return false;
    if (!zpf_load(fx->worker_b, fx->handoff_root,
                  VCS_ZCODE_FOCUS_HANDOFF_WIRE_BYTES, &fx->handoff_wire,
                  &fx->handoff_wire_len, &fx->metrics))
        return false;
    bool parsed = vcs_zcode_focus_handoff_parse(
                      fx->handoff_wire, fx->handoff_wire_len,
                      &fx->handoff_at_b) == VCS_ZCODE_FOCUS_OK;
    free(fx->handoff_wire);
    fx->handoff_wire = NULL;
    return parsed;
}

static bool zpf_handoff_validate_work(struct zpf_handoff_fx *fx)
{
    return vcs_zcode_focus_handoff_root(&fx->handoff_at_b, fx->check_root) ==
               VCS_ZCODE_FOCUS_OK &&
           memcmp(fx->check_root, fx->handoff_root, 32) == 0 &&
           vcs_zcode_focus_handoff_validate_for_work(
               &fx->focus_b, &fx->task_b, &fx->context_b, &fx->task_scope_b,
               fx->claims_b, fx->scopes_b, 2, fx->from_b, fx->next_b,
               &fx->request_a_at_b.body.request,
               &fx->admission_a_at_b.body.admission,
               &fx->request_b_at_b.body.request,
               &fx->admission_b_at_b.body.admission,
               &fx->receipt_at_b, &fx->report_a_at_b, &fx->handoff_at_b,
               fx->resume_unix) == VCS_ZCODE_FOCUS_OK &&
           vcs_zcode_focus_handoff_validate_for_work(
               &fx->focus_b, &fx->task_b, &fx->context_b, &fx->task_scope_b,
               fx->claims_b, fx->scopes_b, 2, fx->from_b, fx->next_b,
               &fx->request_a_at_b.body.request,
               &fx->admission_a_at_b.body.admission,
               &fx->request_b_at_b.body.request,
               &fx->admission_b_at_b.body.admission,
               &fx->receipt_at_b, &fx->report_a_at_b, &fx->handoff_at_b,
               fx->successor_expires_unix) == VCS_ZCODE_FOCUS_BINDING;
}

static bool zpf_handoff_edit_latency(struct zpf_handoff_fx *fx,
                                     int64_t edit_started_us)
{
    int64_t observed_us = platform_time_monotonic_us();
    fx->edit_to_observation_us = observed_us >= edit_started_us
        ? (uint64_t)(observed_us - edit_started_us) : 0;
    return fx->edit_to_observation_us > 0;
}

static void zpf_handoff_print(const struct zpf_handoff_fx *fx,
                              const char *work_id)
{
    char focus_hex[65], handoff_hex[65], receipt_hex[65];
    zcl_hex_encode(fx->focus_b_root, 32, focus_hex);
    zcl_hex_encode(fx->handoff_root, 32, handoff_hex);
    zcl_hex_encode(fx->receipt_root, 32, receipt_hex);
    int64_t source_receipt_duration_seconds =
        fx->source_receipt.finished_unix - fx->source_receipt.started_unix;
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
           work_id, fx->independent_processes == 2
               ? "two_exec_clean_agent_programs_two_independent_cas"
               : "in_process_two_independent_cas",
           fx->independent_processes == 2 ? "PROVED" : "INCOMPLETE",
           fx->independent_processes == 2 ? "PROVED" : "INCOMPLETE",
           fx->metrics.conflicts, fx->metrics.retries, fx->duplicate_actions,
           fx->context_wire_bytes, fx->fixture_cas_tool_calls,
           fx->metrics.coordination_bytes, fx->fixture_setup_us,
           source_receipt_duration_seconds, fx->edit_to_observation_us,
           focus_hex, handoff_hex, receipt_hex);
}

bool zpd_real_focus_handoff_acceptance(
    const char *workspace, const char *work_id,
    const struct json_value *focus_data,
    const uint8_t source_receipt_root[32],
    const uint8_t preedit_focus_root[32], int64_t preedit_observed_us,
    int64_t edit_started_us)
{
    bool accepted = false;
    struct zpf_handoff_fx fx;
    memset(&fx, 0, sizeof(fx));
    vcs_zcode_agent_context_init(&fx.context_a);
    vcs_zcode_agent_context_init(&fx.context_b);
    fx.measured_started_us = platform_time_monotonic_us();

    ZPF_REQUIRE(zpf_handoff_inputs_valid(workspace, work_id, focus_data,
                                         source_receipt_root,
                                         preedit_focus_root,
                                         preedit_observed_us,
                                         edit_started_us));
    ZPF_REQUIRE(zpf_handoff_load_inputs(&fx, focus_data));
    ZPF_REQUIRE(zpf_handoff_load_source_task(&fx, workspace));
    ZPF_REQUIRE(zpf_handoff_load_preedit(&fx, workspace, preedit_focus_root));
    ZPF_REQUIRE(zpf_handoff_parse_preedit_claims(&fx, workspace));
    ZPF_REQUIRE(zpf_handoff_load_preedit_claims(&fx, workspace));
    ZPF_REQUIRE(zpf_handoff_preedit_status(&fx));
    ZPF_REQUIRE(zpf_handoff_preedit_authority(&fx));
    ZPF_REQUIRE(zpf_handoff_load_receipt(&fx, workspace, source_receipt_root));
    zpf_handoff_make_keys(&fx);
    ZPF_REQUIRE(zpf_handoff_schedule_ok(&fx));
    zpf_handoff_set_deadlines(&fx);
    ZPF_REQUIRE(zpf_handoff_stage_workers(&fx, workspace));
    ZPF_REQUIRE(zpf_handoff_load_workers_tasks(&fx));
    ZPF_REQUIRE(zpf_handoff_validate_preedit_context(&fx));
    ZPF_REQUIRE(zpf_handoff_compose_empty(&fx));
    ZPF_REQUIRE(zpf_handoff_store_scopes(&fx));
    ZPF_REQUIRE(zpf_handoff_continuation_root(&fx));
    ZPF_REQUIRE(zpf_handoff_make_requests(&fx));
    ZPF_REQUIRE(zpf_handoff_admit_requests(&fx));
    ZPF_REQUIRE(zpf_handoff_store_messages(&fx));
    ZPF_REQUIRE(zpf_handoff_build_claims(&fx));
    ZPF_REQUIRE(zpf_handoff_store_claims(&fx));
    ZPF_REQUIRE(zpf_handoff_load_cross_claims(&fx));
    ZPF_REQUIRE(zpf_handoff_order_claims(&fx));
    ZPF_REQUIRE(zpf_handoff_compose_focus(&fx));
    ZPF_REQUIRE(zpf_handoff_store_focus(&fx));
    ZPF_REQUIRE(zpf_handoff_store_claim_set(&fx));
    zpf_handoff_fixture_timing(&fx);
    zpf_handoff_build_reports(&fx);
    ZPF_REQUIRE(zpf_handoff_store_reports(&fx));
    ZPF_REQUIRE(zpf_handoff_load_reports(&fx));
    zpf_handoff_build_handoff(&fx);
    ZPF_REQUIRE(zpf_handoff_store_handoff(&fx));
    ZPF_REQUIRE(zpf_handoff_run_independent(&fx));
    ZPF_REQUIRE(zpf_handoff_load_messages_at_b(&fx));
    ZPF_REQUIRE(zpf_handoff_request_ids_at_b(&fx));
    ZPF_REQUIRE(zpf_handoff_load_handoff_at_b(&fx));
    ZPF_REQUIRE(zpf_handoff_validate_work(&fx));
    ZPF_REQUIRE(zpf_handoff_edit_latency(&fx, edit_started_us));
    zpf_handoff_print(&fx, work_id);
    accepted = true;

cleanup:
    free(fx.claim_set_wire);
    free(fx.handoff_wire);
    free(fx.preedit_claim_set_wire);
    vcs_zcode_agent_context_free(&fx.context_a);
    vcs_zcode_agent_context_free(&fx.context_b);
    memset(fx.worker_a_secret, 0, sizeof(fx.worker_a_secret));
    memset(fx.worker_b_secret, 0, sizeof(fx.worker_b_secret));
    memset(fx.requester_secret, 0, sizeof(fx.requester_secret));
    if (fx.worker_a[0]) test_rm_rf_recursive(fx.worker_a);
    if (fx.worker_b[0]) test_rm_rf_recursive(fx.worker_b);
    return accepted;
}
