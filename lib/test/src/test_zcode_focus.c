/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Prove rooted shared focus, disjoint claims, reports, and handoff. */
#include "test/test_core.h"

#include "crypto/ed25519.h"
#include "vcs/vcs_object.h"
#include "vcs/zcode_focus.h"

#include <stdlib.h>
#include <string.h>

static void zf_root(uint8_t out[32], uint8_t value)
{
    memset(out, value, 32);
}

static bool zf_store(const char *workspace, const uint8_t root[32],
                     const uint8_t *wire, size_t wire_len)
{
    if (!vcs_object_put_addressed(workspace, root, wire, wire_len))
        return false;
    uint8_t *check = NULL; size_t check_len = 0;
    bool ok = vcs_object_load_raw_bounded(
                  workspace, root, wire_len, &check, &check_len) == 0 &&
              check_len == wire_len && memcmp(check, wire, wire_len) == 0;
    free(check);
    return ok;
}

static bool zf_transfer(const char *from, const char *to,
                        const uint8_t root[32], size_t maximum)
{
    uint8_t *wire = NULL; size_t wire_len = 0;
    bool ok = vcs_object_load_raw_bounded(
                  from, root, maximum, &wire, &wire_len) == 0 &&
              vcs_object_put_addressed(to, root, wire, wire_len);
    free(wire);
    return ok;
}

static void zf_task(struct vcs_zcode_task_v1 *task,
                    const uint8_t scope_root[32])
{
    memset(task, 0, sizeof(*task));
    task->schema_version = VCS_ZCODE_DEV_VERSION;
    zf_root(task->source_root, 1);
    zf_root(task->dependency_lock_root, 2);
    zf_root(task->toolchain_capsule_root, 3);
    memcpy(task->write_scope_root, scope_root, 32);
    zf_root(task->acceptance_tests_root, 5);
    zf_root(task->proof_policy_root, 6);
    zf_root(task->model_policy_root, 7);
    zf_root(task->goal_root, 8);
    task->capabilities = VCS_ZCODE_TASK_CAP_SOURCE_READ |
                         VCS_ZCODE_TASK_CAP_CANDIDATE_WRITE;
    task->max_changed_files = 8;
    task->max_patch_bytes = 65536;
    task->max_context_bytes = 8192;
    task->max_cpu_seconds = 60;
    task->max_memory_bytes = UINT64_C(256) * 1024u * 1024u;
    task->max_output_bytes = UINT64_C(8) * 1024u * 1024u;
    task->expires_unix = 5000;
}

static void zf_claim(struct vcs_zcode_focus_claim_v1 *claim,
                     const uint8_t situation_root[32],
                     const uint8_t scope_root[32], uint8_t agent,
                     uint8_t intent)
{
    memset(claim, 0, sizeof(*claim));
    claim->schema_version = VCS_ZCODE_FOCUS_VERSION;
    claim->created_unix = 1000;
    claim->expires_unix = 2000;
    memcpy(claim->situation_root, situation_root, 32);
    zf_root(claim->claimant_root, agent);
    memcpy(claim->write_scope_root, scope_root, 32);
    zf_root(claim->intent_root, intent);
    zf_root(claim->evidence_plan_root, (uint8_t)(intent + 20u));
}

static void zf_report(struct vcs_zcode_specialist_report_v1 *report,
                      const uint8_t focus_root[32],
                      const uint8_t claim_root[32], uint8_t specialist,
                      uint8_t role, uint8_t base)
{
    memset(report, 0, sizeof(*report));
    report->schema_version = VCS_ZCODE_FOCUS_VERSION;
    report->role = role;
    report->status = ZCL_ONTOLOGY_PROVED;
    report->context_bytes = 1265;
    report->latency_us = 250000;
    report->files_opened = 3;
    report->tool_calls = 5;
    report->proof_reuse_count = 1;
    memcpy(report->focus_root, focus_root, 32);
    memcpy(report->claim_root, claim_root, 32);
    zf_root(report->specialist_root, specialist);
    zf_root(report->evidence_root, base);
    zf_root(report->result_root, (uint8_t)(base + 1u));
    zf_root(report->next_experiment_root, (uint8_t)(base + 2u));
    zf_root(report->evaluator_root, (uint8_t)(base + 3u));
}

static int zf_protocol_roundtrip(void)
{
    int failures = 0;
    TEST("zcode focus: two workers resume from rooted CAS without prose") {
        struct vcs_zcode_write_scope_v1 task_scope, scope_a, scope_b;
        vcs_zcode_write_scope_init(&task_scope);
        vcs_zcode_write_scope_init(&scope_a);
        vcs_zcode_write_scope_init(&scope_b);
        ASSERT_EQ(vcs_zcode_write_scope_add(&task_scope, "lib/vcs"),
                  VCS_ZCODE_WRITE_SCOPE_OK);
        ASSERT_EQ(vcs_zcode_write_scope_add(
                      &scope_a, "lib/vcs/src/zcode_focus.c"),
                  VCS_ZCODE_WRITE_SCOPE_OK);
        ASSERT_EQ(vcs_zcode_write_scope_add(
                      &scope_b, "lib/vcs/src/zcode_focus_claim.c"),
                  VCS_ZCODE_WRITE_SCOPE_OK);
        uint8_t task_scope_root[32], scope_a_root[32], scope_b_root[32];
        ASSERT_EQ(vcs_zcode_write_scope_root(&task_scope, task_scope_root),
                  VCS_ZCODE_WRITE_SCOPE_OK);
        ASSERT_EQ(vcs_zcode_write_scope_root(&scope_a, scope_a_root),
                  VCS_ZCODE_WRITE_SCOPE_OK);
        ASSERT_EQ(vcs_zcode_write_scope_root(&scope_b, scope_b_root),
                  VCS_ZCODE_WRITE_SCOPE_OK);

        struct vcs_zcode_task_v1 task;
        zf_task(&task, task_scope_root);
        uint8_t task_root[32], context_root[32], story_root[32];
        ASSERT_EQ(vcs_zcode_task_root(&task, task_root), VCS_ZCODE_DEV_OK);
        zf_root(context_root, 10); zf_root(story_root, 11);
        struct vcs_zcode_focus_v1 basis;
        ASSERT_EQ(vcs_zcode_focus_compose(
                      &task, task_root, context_root, story_root,
                      ZCL_ONTOLOGY_PROVED, 0, NULL, 0, &basis),
                  VCS_ZCODE_FOCUS_OK);
        uint8_t situation_root[32];
        ASSERT_EQ(vcs_zcode_focus_situation_root(&basis, situation_root),
                  VCS_ZCODE_FOCUS_OK);

        struct vcs_zcode_focus_claim_v1 claim_a, claim_b;
        zf_claim(&claim_a, situation_root, scope_a_root, 21, 31);
        zf_claim(&claim_b, situation_root, scope_b_root, 22, 32);
        uint8_t root_a[32], root_b[32];
        ASSERT_EQ(vcs_zcode_focus_claim_root(&claim_a, root_a),
                  VCS_ZCODE_FOCUS_OK);
        ASSERT_EQ(vcs_zcode_focus_claim_root(&claim_b, root_b),
                  VCS_ZCODE_FOCUS_OK);
        struct vcs_zcode_focus_claim_v1 claims[2] = { claim_a, claim_b };
        struct vcs_zcode_write_scope_v1 scopes[2] = { scope_a, scope_b };
        uint8_t claim_roots[2][32];
        memcpy(claim_roots[0], root_a, 32);
        memcpy(claim_roots[1], root_b, 32);
        if (memcmp(claim_roots[0], claim_roots[1], 32) > 0) {
            struct vcs_zcode_focus_claim_v1 claim_swap = claims[0];
            struct vcs_zcode_write_scope_v1 scope_swap = scopes[0];
            uint8_t root_swap[32]; memcpy(root_swap, claim_roots[0], 32);
            claims[0] = claims[1]; claims[1] = claim_swap;
            scopes[0] = scopes[1]; scopes[1] = scope_swap;
            memcpy(claim_roots[0], claim_roots[1], 32);
            memcpy(claim_roots[1], root_swap, 32);
        }
        struct vcs_zcode_focus_v1 focus;
        ASSERT_EQ(vcs_zcode_focus_compose(
                      &task, task_root, context_root, story_root,
                      ZCL_ONTOLOGY_PROVED, 0, claim_roots, 2, &focus),
                  VCS_ZCODE_FOCUS_OK);
        ASSERT_EQ(vcs_zcode_focus_claim_set_status(
                      &focus, claims, scopes, 2, 1500),
                  ZCL_ONTOLOGY_PROVED);
        ASSERT_EQ(vcs_zcode_focus_claim_disjoint_status(
                      &claim_a, &scope_a, &claim_b, &scope_b, 1500),
                  ZCL_ONTOLOGY_PROVED);
        ASSERT_EQ(vcs_zcode_focus_claim_authority_status(
                      &focus, &task, &task_scope, &claim_a, &scope_a, 1500),
                  ZCL_ONTOLOGY_PROVED);

        struct vcs_zcode_write_scope_v1 outside;
        vcs_zcode_write_scope_init(&outside);
        ASSERT_EQ(vcs_zcode_write_scope_add(&outside, "core/consensus"),
                  VCS_ZCODE_WRITE_SCOPE_OK);
        struct vcs_zcode_focus_claim_v1 outside_claim = claim_a;
        ASSERT_EQ(vcs_zcode_write_scope_root(
                      &outside, outside_claim.write_scope_root),
                  VCS_ZCODE_WRITE_SCOPE_OK);
        ASSERT_EQ(vcs_zcode_focus_claim_authority_status(
                      &focus, &task, &task_scope, &outside_claim,
                      &outside, 1500), ZCL_ONTOLOGY_DISPROVED);
        ASSERT_EQ(vcs_zcode_focus_claim_disjoint_status(
                      &claim_a, &scope_a, &claim_b, &scope_b, 2500),
                  ZCL_ONTOLOGY_INCOMPLETE);

        uint8_t focus_root[32];
        ASSERT_EQ(vcs_zcode_focus_root(&focus, focus_root),
                  VCS_ZCODE_FOCUS_OK);
        struct vcs_zcode_specialist_report_v1 report_a, report_b;
        zf_report(&report_a, focus_root, root_a, 21,
                  VCS_ZCODE_SPECIALIST_RETRIEVAL, 40);
        zf_report(&report_b, focus_root, root_b, 22,
                  VCS_ZCODE_SPECIALIST_CODE, 50);
        uint8_t report_a_root[32], report_b_root[32];
        ASSERT_EQ(vcs_zcode_specialist_report_root(
                      &report_a, report_a_root), VCS_ZCODE_FOCUS_OK);
        ASSERT_EQ(vcs_zcode_specialist_report_root(
                      &report_b, report_b_root), VCS_ZCODE_FOCUS_OK);
        struct vcs_zcode_focus_handoff_v1 handoff;
        memset(&handoff, 0, sizeof(handoff));
        handoff.schema_version = VCS_ZCODE_FOCUS_VERSION;
        handoff.status = ZCL_ONTOLOGY_PROVED;
        memcpy(handoff.focus_root, focus_root, 32);
        memcpy(handoff.report_root, report_a_root, 32);
        memcpy(handoff.from_claim_root, root_a, 32);
        memcpy(handoff.to_specialist_root, claim_b.claimant_root, 32);
        memcpy(handoff.next_claim_root, root_b, 32);
        memcpy(handoff.required_evidence_root,
               focus.required_evidence_root, 32);
        memcpy(handoff.continuation_root,
               report_a.next_experiment_root, 32);
        ASSERT_EQ(vcs_zcode_focus_handoff_validate_chain(
                      &focus, &claim_a, &report_a, &handoff, &claim_b),
                  VCS_ZCODE_FOCUS_OK);

        uint8_t focus_wire[VCS_ZCODE_FOCUS_WIRE_BYTES];
        uint8_t claim_a_wire[VCS_ZCODE_FOCUS_CLAIM_WIRE_BYTES];
        uint8_t claim_b_wire[VCS_ZCODE_FOCUS_CLAIM_WIRE_BYTES];
        uint8_t report_a_wire[VCS_ZCODE_SPECIALIST_REPORT_WIRE_BYTES];
        uint8_t report_b_wire[VCS_ZCODE_SPECIALIST_REPORT_WIRE_BYTES];
        uint8_t handoff_wire[VCS_ZCODE_FOCUS_HANDOFF_WIRE_BYTES];
        uint8_t *set_wire = NULL; size_t set_wire_len = 0;
        uint8_t handoff_root[32];
        ASSERT_EQ(vcs_zcode_focus_serialize(&focus, focus_wire),
                  VCS_ZCODE_FOCUS_OK);
        ASSERT_EQ(vcs_zcode_focus_claim_serialize(&claim_a, claim_a_wire),
                  VCS_ZCODE_FOCUS_OK);
        ASSERT_EQ(vcs_zcode_focus_claim_serialize(&claim_b, claim_b_wire),
                  VCS_ZCODE_FOCUS_OK);
        ASSERT_EQ(vcs_zcode_specialist_report_serialize(
                      &report_a, report_a_wire), VCS_ZCODE_FOCUS_OK);
        ASSERT_EQ(vcs_zcode_specialist_report_serialize(
                      &report_b, report_b_wire), VCS_ZCODE_FOCUS_OK);
        ASSERT_EQ(vcs_zcode_focus_handoff_serialize(
                      &handoff, handoff_wire), VCS_ZCODE_FOCUS_OK);
        ASSERT_EQ(vcs_zcode_focus_handoff_root(&handoff, handoff_root),
                  VCS_ZCODE_FOCUS_OK);
        ASSERT_EQ(vcs_zcode_focus_claim_set_serialize(
                      claim_roots, 2, &set_wire, &set_wire_len),
                  VCS_ZCODE_FOCUS_OK);

        char worker_a[PATH_MAX], worker_b[PATH_MAX];
        test_make_tmpdir(worker_a, sizeof(worker_a), "focus_worker", "a");
        test_make_tmpdir(worker_b, sizeof(worker_b), "focus_worker", "b");
        ASSERT(vcs_object_store_init(worker_a));
        ASSERT(vcs_object_store_init(worker_b));
        ASSERT(zf_store(worker_a, focus_root, focus_wire,
                        sizeof(focus_wire)));
        ASSERT(zf_store(worker_a, focus.claim_set_root,
                        set_wire, set_wire_len));
        ASSERT(zf_store(worker_a, root_a, claim_a_wire,
                        sizeof(claim_a_wire)));
        ASSERT(zf_store(worker_a, root_b, claim_b_wire,
                        sizeof(claim_b_wire)));
        ASSERT(zf_store(worker_a, report_a_root, report_a_wire,
                        sizeof(report_a_wire)));
        ASSERT(zf_store(worker_a, report_b_root, report_b_wire,
                        sizeof(report_b_wire)));
        ASSERT(zf_store(worker_a, handoff_root, handoff_wire,
                        sizeof(handoff_wire)));
        const uint8_t *roots[] = {
            focus_root, focus.claim_set_root, root_a, root_b,
            report_a_root, report_b_root, handoff_root,
        };
        const size_t maximums[] = {
            sizeof(focus_wire), VCS_ZCODE_FOCUS_CLAIM_SET_WIRE_MAX,
            sizeof(claim_a_wire), sizeof(claim_b_wire),
            sizeof(report_a_wire), sizeof(report_b_wire),
            sizeof(handoff_wire),
        };
        for (size_t i = 0; i < sizeof(roots) / sizeof(roots[0]); i++)
            ASSERT(zf_transfer(worker_a, worker_b, roots[i], maximums[i]));

        uint8_t *received = NULL; size_t received_len = 0;
        struct vcs_zcode_focus_v1 received_focus;
        uint8_t received_root[32];
        ASSERT(vcs_object_load_raw_bounded(
                   worker_b, focus_root, sizeof(focus_wire),
                   &received, &received_len) == 0);
        ASSERT_EQ(vcs_zcode_focus_parse(
                      received, received_len, &received_focus),
                  VCS_ZCODE_FOCUS_OK);
        free(received); received = NULL;
        ASSERT_EQ(vcs_zcode_focus_root(&received_focus, received_root),
                  VCS_ZCODE_FOCUS_OK);
        ASSERT(memcmp(received_root, focus_root, 32) == 0);

        struct vcs_zcode_specialist_report_v1 received_report;
        struct vcs_zcode_focus_handoff_v1 received_handoff;
        struct vcs_zcode_focus_claim_v1 received_claim_a, received_claim_b;
        ASSERT(vcs_object_load_raw_bounded(
                   worker_b, report_a_root, sizeof(report_a_wire),
                   &received, &received_len) == 0);
        ASSERT_EQ(vcs_zcode_specialist_report_parse(
                      received, received_len, &received_report),
                  VCS_ZCODE_FOCUS_OK);
        free(received); received = NULL;
        ASSERT(vcs_object_load_raw_bounded(
                   worker_b, handoff_root, sizeof(handoff_wire),
                   &received, &received_len) == 0);
        ASSERT_EQ(vcs_zcode_focus_handoff_parse(
                      received, received_len, &received_handoff),
                  VCS_ZCODE_FOCUS_OK);
        free(received); received = NULL;
        ASSERT(vcs_object_load_raw_bounded(
                   worker_b, root_a, sizeof(claim_a_wire),
                   &received, &received_len) == 0);
        ASSERT_EQ(vcs_zcode_focus_claim_parse(
                      received, received_len, &received_claim_a),
                  VCS_ZCODE_FOCUS_OK);
        free(received); received = NULL;
        ASSERT(vcs_object_load_raw_bounded(
                   worker_b, root_b, sizeof(claim_b_wire),
                   &received, &received_len) == 0);
        ASSERT_EQ(vcs_zcode_focus_claim_parse(
                      received, received_len, &received_claim_b),
                  VCS_ZCODE_FOCUS_OK);
        free(received); received = NULL;
        ASSERT_EQ(vcs_zcode_focus_handoff_validate_chain(
                      &received_focus, &received_claim_a, &received_report,
                      &received_handoff, &received_claim_b),
                  VCS_ZCODE_FOCUS_OK);

        uint8_t tampered[VCS_ZCODE_SPECIALIST_REPORT_WIRE_BYTES];
        memcpy(tampered, report_a_wire, sizeof(tampered));
        tampered[48] ^= 1u;
        ASSERT_EQ(vcs_zcode_specialist_report_parse(
                      tampered, sizeof(tampered), &received_report),
                  VCS_ZCODE_FOCUS_OK);
        ASSERT_EQ(vcs_zcode_specialist_report_root(
                      &received_report, received_root), VCS_ZCODE_FOCUS_OK);
        ASSERT(memcmp(received_root, report_a_root, 32) != 0);
        size_t protocol_bytes = sizeof(focus_wire) + set_wire_len +
            sizeof(claim_a_wire) + sizeof(claim_b_wire) +
            sizeof(report_a_wire) + sizeof(report_b_wire) +
            sizeof(handoff_wire);
        printf("focus_protocol: workers=2 claims=2 reports=2 "
               "overlap=DISPROVED handoff_bytes=%u total_bytes=%zu "
               "prose_bytes=0\n",
               VCS_ZCODE_FOCUS_HANDOFF_WIRE_BYTES, protocol_bytes);
        free(set_wire);
        test_rm_rf_recursive(worker_a);
        test_rm_rf_recursive(worker_b);
        PASS();
    } _test_next:;
    return failures;
}

static int zf_status_and_refusals(void)
{
    int failures = 0;
    TEST("zcode focus: ontology statuses and malformed wires fail closed") {
        struct vcs_zcode_specialist_report_v1 report;
        memset(&report, 0, sizeof(report));
        report.schema_version = VCS_ZCODE_FOCUS_VERSION;
        report.role = VCS_ZCODE_SPECIALIST_PROOF;
        report.context_bytes = 1;
        report.latency_us = 1;
        report.tool_calls = 1;
        zf_root(report.focus_root, 1); zf_root(report.claim_root, 2);
        zf_root(report.specialist_root, 3); zf_root(report.evidence_root, 4);
        zf_root(report.result_root, 5); zf_root(report.next_experiment_root, 6);
        zf_root(report.evaluator_root, 7);
        uint8_t wire[VCS_ZCODE_SPECIALIST_REPORT_WIRE_BYTES];
        for (uint8_t status = ZCL_ONTOLOGY_PROVED;
             status <= ZCL_ONTOLOGY_INCOMPLETE; status++) {
            report.status = status;
            ASSERT_EQ(vcs_zcode_specialist_report_serialize(&report, wire),
                      VCS_ZCODE_FOCUS_OK);
            struct vcs_zcode_specialist_report_v1 parsed;
            ASSERT_EQ(vcs_zcode_specialist_report_parse(
                          wire, sizeof(wire), &parsed),
                      VCS_ZCODE_FOCUS_OK);
            ASSERT_EQ(parsed.status, status);
        }
        wire[0] ^= 1u;
        struct vcs_zcode_specialist_report_v1 parsed;
        ASSERT_EQ(vcs_zcode_specialist_report_parse(
                      wire, sizeof(wire), &parsed), VCS_ZCODE_FOCUS_SHAPE);
        ASSERT_EQ(parsed.schema_version, 0);
        uint8_t duplicate[2][32];
        zf_root(duplicate[0], 9); zf_root(duplicate[1], 9);
        uint8_t *set_wire = NULL; size_t set_len = 0;
        ASSERT_EQ(vcs_zcode_focus_claim_set_serialize(
                      duplicate, 2, &set_wire, &set_len),
                  VCS_ZCODE_FOCUS_DUPLICATE);
        ASSERT(set_wire == NULL && set_len == 0);
        PASS();
    } _test_next:;
    return failures;
}

static int zf_existing_work_evidence(void)
{
    int failures = 0;
    TEST("zcode focus: claims and reports bind existing signed work evidence") {
        struct vcs_zcode_write_scope_v1 task_scope, claim_scope;
        vcs_zcode_write_scope_init(&task_scope);
        vcs_zcode_write_scope_init(&claim_scope);
        ASSERT_EQ(vcs_zcode_write_scope_add(&task_scope, "lib/vcs"),
                  VCS_ZCODE_WRITE_SCOPE_OK);
        ASSERT_EQ(vcs_zcode_write_scope_add(
                      &claim_scope, "lib/vcs/src/zcode_focus_claim.c"),
                  VCS_ZCODE_WRITE_SCOPE_OK);
        uint8_t task_scope_root[32], claim_scope_root[32];
        ASSERT_EQ(vcs_zcode_write_scope_root(
                      &task_scope, task_scope_root),
                  VCS_ZCODE_WRITE_SCOPE_OK);
        ASSERT_EQ(vcs_zcode_write_scope_root(
                      &claim_scope, claim_scope_root),
                  VCS_ZCODE_WRITE_SCOPE_OK);
        struct vcs_zcode_task_v1 task;
        zf_task(&task, task_scope_root);
        uint8_t task_root[32], context_root[32], story_root[32];
        ASSERT_EQ(vcs_zcode_task_root(&task, task_root), VCS_ZCODE_DEV_OK);
        zf_root(context_root, 90); zf_root(story_root, 91);
        struct vcs_zcode_focus_v1 basis;
        ASSERT_EQ(vcs_zcode_focus_compose(
                      &task, task_root, context_root, story_root,
                      ZCL_ONTOLOGY_UNKNOWN, 0, NULL, 0, &basis),
                  VCS_ZCODE_FOCUS_OK);
        uint8_t situation_root[32];
        ASSERT_EQ(vcs_zcode_focus_situation_root(
                      &basis, situation_root), VCS_ZCODE_FOCUS_OK);

        uint8_t requester_seed[32], requester_secret[32], requester_key[32];
        uint8_t worker_seed[32], worker_secret[32], worker_key[32];
        zf_root(requester_seed, 92); zf_root(worker_seed, 93);
        ed25519_keypair(requester_key, requester_secret, requester_seed);
        ed25519_keypair(worker_key, worker_secret, worker_seed);
        struct vcs_zcode_work_request_v1 request;
        memset(&request, 0, sizeof(request));
        request.request_id = 77;
        memcpy(request.task_root, task_root, 32);
        zf_root(request.candidate_root, 94);
        zf_root(request.action_root, 95);
        zf_root(request.input_root, 96);
        zf_root(request.context_root, 97);
        memcpy(request.proof_policy_root, task.proof_policy_root, 32);
        memcpy(request.toolchain_capsule_root,
               task.toolchain_capsule_root, 32);
        request.work_kind = VCS_ZCODE_WORK_BUILD;
        request.target = VCS_ZCODE_WORK_TARGET_LINUX_X86_64_V3;
        request.max_cpu_seconds = 30;
        request.max_memory_bytes = UINT64_C(128) * 1024u * 1024u;
        request.max_output_bytes = UINT64_C(4) * 1024u * 1024u;
        request.deadline_unix = 1800;
        ASSERT(vcs_zcode_work_request_seal(
            &request, requester_secret, requester_key));
        uint8_t request_root[32];
        ASSERT(vcs_zcode_work_request_id(&request, request_root));

        struct vcs_zcode_work_admission_v1 admission;
        memset(&admission, 0, sizeof(admission));
        admission.request_id = request.request_id;
        memcpy(admission.requester_pubkey, request.requester_pubkey, 32);
        memcpy(admission.action_root, request.action_root, 32);
        admission.lease_generation = 1;
        admission.deadline_unix = request.deadline_unix;
        admission.slot = 0;
        admission.disposition = VCS_ZCODE_WORK_ADMISSION_GRANTED;
        ASSERT(vcs_zcode_work_admission_seal(
            &admission, worker_secret, worker_key));

        struct vcs_zcode_focus_claim_v1 claim;
        memset(&claim, 0, sizeof(claim));
        claim.schema_version = VCS_ZCODE_FOCUS_VERSION;
        claim.created_unix = 1000;
        claim.expires_unix = 1700;
        memcpy(claim.situation_root, situation_root, 32);
        memcpy(claim.claimant_root, worker_key, 32);
        memcpy(claim.write_scope_root, claim_scope_root, 32);
        memcpy(claim.intent_root, request_root, 32);
        memcpy(claim.evidence_plan_root, request.proof_policy_root, 32);
        uint8_t claim_root[32];
        ASSERT_EQ(vcs_zcode_focus_claim_root(&claim, claim_root),
                  VCS_ZCODE_FOCUS_OK);
        struct vcs_zcode_focus_v1 focus;
        ASSERT_EQ(vcs_zcode_focus_compose(
                      &task, task_root, context_root, story_root,
                      ZCL_ONTOLOGY_UNKNOWN, 0,
                      (const uint8_t (*)[32])&claim_root, 1, &focus),
                  VCS_ZCODE_FOCUS_OK);
        const uint8_t (*claim_roots)[32] =
            (const uint8_t (*)[32])&claim_root;
        ASSERT_EQ(vcs_zcode_focus_claim_work_status(
                      &focus, &task, &task_scope, &claim, &claim_scope,
                      claim_roots, 1, &request, &admission, 1500),
                  ZCL_ONTOLOGY_PROVED);

        struct vcs_zcode_work_admission_v1 expired = admission;
        expired.deadline_unix = 1500;
        ASSERT(vcs_zcode_work_admission_seal(
            &expired, worker_secret, worker_key));
        ASSERT_EQ(vcs_zcode_focus_claim_work_status(
                      &focus, &task, &task_scope, &claim, &claim_scope,
                      claim_roots, 1, &request, &expired, 1500),
                  ZCL_ONTOLOGY_DISPROVED);

        struct vcs_zcode_focus_claim_v1 absent_claim = claim;
        absent_claim.expires_unix = 1600;
        ASSERT_EQ(vcs_zcode_focus_claim_work_status(
                      &focus, &task, &task_scope, &absent_claim, &claim_scope,
                      claim_roots, 1, &request, &admission, 1500),
                  ZCL_ONTOLOGY_DISPROVED);

        struct vcs_zcode_work_admission_v1 busy = admission;
        busy.lease_generation = 0;
        busy.deadline_unix = 0;
        busy.slot = UINT16_MAX;
        busy.disposition = VCS_ZCODE_WORK_ADMISSION_BUSY;
        busy.reason = VCS_ZCODE_WORK_ADMISSION_REASON_NO_SLOT;
        ASSERT(vcs_zcode_work_admission_seal(
            &busy, worker_secret, worker_key));
        ASSERT(vcs_zcode_work_admission_verify_for_request(
            &request, &busy, worker_key));
        ASSERT_EQ(vcs_zcode_focus_claim_work_status(
                      &focus, &task, &task_scope, &claim, &claim_scope,
                      claim_roots, 1, &request, &busy, 1500),
                  ZCL_ONTOLOGY_DISPROVED);

        struct vcs_zcode_work_receipt_v1 receipt;
        memset(&receipt, 0, sizeof(receipt));
        receipt.schema_version = VCS_ZCODE_DEV_VERSION;
        memcpy(receipt.task_root, request.task_root, 32);
        memcpy(receipt.candidate_root, request.candidate_root, 32);
        memcpy(receipt.action_root, request.action_root, 32);
        memcpy(receipt.input_root, request.input_root, 32);
        zf_root(receipt.output_root, 98);
        memcpy(receipt.proof_policy_root, request.proof_policy_root, 32);
        memcpy(receipt.toolchain_capsule_root,
               request.toolchain_capsule_root, 32);
        zf_root(receipt.lease_id, 99); zf_root(receipt.evidence_root, 100);
        zf_root(receipt.confinement_root, 101);
        receipt.work_kind = request.work_kind;
        receipt.status = VCS_ZCODE_WORK_PASS;
        receipt.started_unix = 1200;
        receipt.finished_unix = 1300;
        ASSERT_EQ(vcs_zcode_work_receipt_seal(
                      &receipt, worker_secret, worker_key),
                  VCS_ZCODE_DEV_OK);
        uint8_t receipt_root[32], focus_root[32];
        ASSERT_EQ(vcs_zcode_work_receipt_id(&receipt, receipt_root),
                  VCS_ZCODE_DEV_OK);
        ASSERT_EQ(vcs_zcode_focus_root(&focus, focus_root),
                  VCS_ZCODE_FOCUS_OK);
        struct vcs_zcode_specialist_report_v1 report;
        zf_report(&report, focus_root, claim_root, 93,
                  VCS_ZCODE_SPECIALIST_PROOF, 102);
        memcpy(report.specialist_root, worker_key, 32);
        memcpy(report.evidence_root, receipt_root, 32);
        memcpy(report.result_root, receipt.output_root, 32);
        ASSERT_EQ(vcs_zcode_specialist_report_validate_for_work(
                      &focus, &claim, claim_roots, 1,
                      &task, &request, &receipt, &report),
                  VCS_ZCODE_FOCUS_OK);
        uint8_t absent_root[32];
        ASSERT_EQ(vcs_zcode_focus_claim_root(&absent_claim, absent_root),
                  VCS_ZCODE_FOCUS_OK);
        struct vcs_zcode_specialist_report_v1 absent_report = report;
        memcpy(absent_report.claim_root, absent_root, 32);
        ASSERT_EQ(vcs_zcode_specialist_report_validate_for_work(
                      &focus, &absent_claim, claim_roots, 1,
                      &task, &request, &receipt, &absent_report),
                  VCS_ZCODE_FOCUS_BINDING);
        for (size_t variant = 0; variant < 3; variant++) {
            struct vcs_zcode_work_receipt_v1 mismatch = receipt;
            if (variant == 0) mismatch.candidate_root[0] ^= 1u;
            else if (variant == 1) mismatch.input_root[0] ^= 1u;
            else mismatch.work_kind = VCS_ZCODE_WORK_TEST;
            ASSERT_EQ(vcs_zcode_work_receipt_seal(
                          &mismatch, worker_secret, worker_key),
                      VCS_ZCODE_DEV_OK);
            struct vcs_zcode_specialist_report_v1 mismatch_report = report;
            ASSERT_EQ(vcs_zcode_work_receipt_id(
                          &mismatch, mismatch_report.evidence_root),
                      VCS_ZCODE_DEV_OK);
            ASSERT_EQ(vcs_zcode_specialist_report_validate_for_work(
                          &focus, &claim, claim_roots, 1, &task, &request,
                          &mismatch, &mismatch_report),
                      VCS_ZCODE_FOCUS_BINDING);
        }
        PASS();
    } _test_next:;
    return failures;
}

int test_zcode_focus(void)
{
    int failures = 0;
    failures += zf_protocol_roundtrip();
    failures += zf_status_and_refusals();
    failures += zf_existing_work_evidence();
    printf("=== zcode_focus: %d failures ===\n", failures);
    return failures;
}
