/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Prove canonical ZCODE scientific object and action identities. */

#include "test/test_core.h"

#include "base/hex.h"
#include "crypto/ed25519.h"
#include "crypto/sha256.h"
#include "crypto/sha3.h"
#include "vcs/build_action.h"
#include "vcs/zcode_science.h"

#include <stdio.h>
#include <stddef.h>
#include <string.h>

static void zs_root(uint8_t out[32], uint8_t value)
{
    memset(out, value, 32);
}

static void zs_study(struct vcs_zcode_study_spec_v1 *study)
{
    memset(study, 0, sizeof(*study));
    study->schema_version = VCS_ZCODE_SCIENCE_VERSION;
    zs_root(study->hypothesis_root, 1);
    zs_root(study->null_hypothesis_root, 2);
    zs_root(study->source_root, 3);
    zs_root(study->dependency_lock_root, 4);
    zs_root(study->toolchain_capsule_root, 5);
    zs_root(study->protocol_root, 6);
    zs_root(study->workloads_root, 7);
    zs_root(study->metrics_root, 8);
    zs_root(study->estimator_tolerance_root, 9);
    zs_root(study->environment_policy_root, 10);
    zs_root(study->citations_root, 11);
    zs_root(study->preregistration_policy_root, 12);
    study->required_reproductions = 2;
    study->required_reviews = 3;
    study->sequence = 17;
    study->created_unix = 1000;
    study->expires_unix = 5000;
}

static void zs_task_candidate(
    const struct vcs_zcode_study_spec_v1 *study,
    struct vcs_zcode_task_v1 *task,
    struct vcs_zcode_candidate_v1 *candidate,
    uint8_t task_root[32], uint8_t candidate_root[32])
{
    uint8_t study_root[32];
    (void)vcs_zcode_study_spec_root(study, study_root);
    memset(task, 0, sizeof(*task));
    task->schema_version = VCS_ZCODE_DEV_VERSION;
    memcpy(task->source_root, study->source_root, 32);
    memcpy(task->dependency_lock_root, study->dependency_lock_root, 32);
    memcpy(task->toolchain_capsule_root, study->toolchain_capsule_root, 32);
    zs_root(task->write_scope_root, 20);
    zs_root(task->acceptance_tests_root, 21);
    zs_root(task->proof_policy_root, 22);
    zs_root(task->model_policy_root, 23);
    memcpy(task->goal_root, study_root, 32);
    task->capabilities = VCS_ZCODE_TASK_CAP_V1_MASK;
    task->max_changed_files = 32;
    task->max_patch_bytes = 1024 * 1024;
    task->max_context_bytes = 2 * 1024 * 1024;
    task->max_cpu_seconds = 120;
    task->max_memory_bytes = UINT64_C(512) * 1024 * 1024;
    task->max_output_bytes = UINT64_C(64) * 1024 * 1024;
    task->expires_unix = study->expires_unix;
    (void)vcs_zcode_task_root(task, task_root);

    memset(candidate, 0, sizeof(*candidate));
    candidate->schema_version = VCS_ZCODE_DEV_VERSION;
    memcpy(candidate->task_root, task_root, 32);
    memcpy(candidate->base_source_root, task->source_root, 32);
    zs_root(candidate->patch_root, 24);
    zs_root(candidate->candidate_source_root, 25);
    zs_root(candidate->adapter_policy_root, 26);
    zs_root(candidate->author_pubkey, 27);
    candidate->sequence = 1;
    candidate->created_unix = 1100;
    (void)vcs_zcode_candidate_root(candidate, candidate_root);
}

static void zs_action(struct vcs_build_action_v1 *action, const char *kind,
                      uint64_t sequence)
{
    const char *workdir = NULL, *output = NULL, *resource = NULL;
    memset(action, 0, sizeof(*action));
    zs_root(action->source_sha256, 60);
    zs_root(action->source_cas_sha3, 61);
    zs_root(action->input_root_sha3, 62);
    zs_root(action->toolchain_capsule_sha3, 63);
    (void)vcs_build_action_v1_fixed_flags_root_for_kind(
        kind, action->flags_sha3);
    (void)vcs_build_action_v1_fixed_environment_root_for_kind(
        kind, action->environment_sha3);
    (void)snprintf(action->target, sizeof(action->target), "%s",
                   VCS_BUILD_TARGET_V1);
    (void)snprintf(action->profile, sizeof(action->profile), "science");
    (void)vcs_build_action_v1_descriptors(
        kind, &workdir, &output, &resource);
    (void)snprintf(action->virtual_workdir,
                   sizeof(action->virtual_workdir), "%s", workdir);
    (void)snprintf(action->declared_outputs,
                   sizeof(action->declared_outputs), "%s", output);
    (void)snprintf(action->resource_policy,
                   sizeof(action->resource_policy), "%s", resource);
    action->sequence = sequence;
}

static void zs_benchmark_action(struct vcs_build_action_v1 *action)
{
    zs_action(action, VCS_BUILD_ACTION_KIND_BENCHMARK_V1, 1);
}

static void zs_result(
    const struct vcs_zcode_study_spec_v1 *study,
    const uint8_t task_root[32], const uint8_t candidate_root[32],
    struct vcs_zcode_benchmark_result_v1 *result)
{
    struct vcs_build_action_v1 action;
    memset(result, 0, sizeof(*result));
    result->schema_version = VCS_ZCODE_SCIENCE_VERSION;
    (void)vcs_zcode_study_spec_root(study, result->study_root);
    memcpy(result->task_root, task_root, 32);
    memcpy(result->candidate_root, candidate_root, 32);
    zs_benchmark_action(&action);
    (void)vcs_build_action_v1_root_for_kind(
        VCS_BUILD_ACTION_KIND_BENCHMARK_V1, &action, result->action_root);
    zs_root(result->achieved_environment_root, 31);
    zs_root(result->raw_sample_root, 32);
    zs_root(result->evidence_root, 33);
    result->status = VCS_ZCODE_BENCHMARK_NULL_RESULT;
    result->challenge_block_height = 3200000;
    zs_root(result->challenge_block_hash, 34);
    result->sequence = 1;
    result->started_unix = 1200;
    result->finished_unix = 1300;
}

/* Deterministic hardware-profile fixture (fixed bytes, NOT a capture) —
 * the golden KAT below pins this exact object. */
static void zs_hardware_profile(struct vcs_zcode_hardware_profile_v1 *profile)
{
    memset(profile, 0, sizeof(*profile));
    profile->schema_version = VCS_ZCODE_HARDWARE_PROFILE_VERSION;
    memcpy(profile->cpu_vendor, "GenuineIntel", 12);
    memcpy(profile->cpu_brand, "ZClassic23 Test CPU", 19);
    profile->physical_cores = 8;
    profile->logical_cores = 16;
    profile->ram_mib = 32768;
    profile->isa_bits = VCS_ZCODE_HW_ISA_SSE4_2 | VCS_ZCODE_HW_ISA_BMI2 |
                        VCS_ZCODE_HW_ISA_FMA | VCS_ZCODE_HW_ISA_AES_NI |
                        VCS_ZCODE_HW_ISA_AVX2;
    memcpy(profile->os_sysname, "Linux", 5);
    memcpy(profile->os_machine, "x86_64", 6);
    memcpy(profile->os_release, "6.9.0-test", 10);
    profile->tsc_freq_hz = UINT64_C(3000000000);
    memcpy(profile->timer_source, "tsc", 3);
    profile->captured_unix = 1000;
}

static void zs_method(struct vcs_zcode_benchmark_method_v1 *method)
{
    memset(method, 0, sizeof(*method));
    method->schema_version = VCS_ZCODE_BENCHMARK_METHOD_VERSION;
    zs_root(method->workload_root, 0x41);
    zs_root(method->timer_root, 0x42);
    zs_root(method->estimator_root, 0x43);
    method->tolerance_ppm = 5000;
    method->warmup_samples = 10;
    method->measured_samples = 1000;
    method->sample_distribution = VCS_ZCODE_SAMPLE_DIST_TRIMMED_MEAN;
    method->trim_percent = 10;
}

/* v2 result bound to the study/task/candidate/action plus the given method
 * and hardware profile. */
static void zs_result_v2(
    const struct vcs_zcode_study_spec_v1 *study,
    const uint8_t task_root[32], const uint8_t candidate_root[32],
    const struct vcs_zcode_benchmark_method_v1 *method,
    const struct vcs_zcode_hardware_profile_v1 *profile,
    struct vcs_zcode_benchmark_result_v2 *result)
{
    struct vcs_zcode_benchmark_result_v1 v1;
    zs_result(study, task_root, candidate_root, &v1);
    memset(result, 0, sizeof(*result));
    memcpy(result, &v1,
           offsetof(struct vcs_zcode_benchmark_result_v2, method_root));
    result->schema_version = VCS_ZCODE_BENCHMARK_RESULT_V2_VERSION;
    (void)vcs_zcode_benchmark_method_root(method, result->method_root);
    (void)vcs_zcode_hardware_profile_root(
        profile, result->hardware_profile_root);
}

static int test_zs_study_codec(void)
{
    int failures = 0;
    TEST("zcode_science: preregistered study wire is exact and canonical") {
        struct vcs_zcode_study_spec_v1 study, parsed;
        zs_study(&study);
        uint8_t wire[VCS_ZCODE_STUDY_SPEC_WIRE_BYTES + 1], root[32];
        char root_hex[65];
        ASSERT_EQ(vcs_zcode_study_spec_validate_at(&study, 1500),
                  VCS_ZCODE_SCIENCE_OK);
        ASSERT_EQ(vcs_zcode_study_spec_serialize(&study, wire),
                  VCS_ZCODE_SCIENCE_OK);
        ASSERT(memcmp(wire, "ZCSTUD\r\n", 8) == 0);
        ASSERT_EQ(vcs_zcode_study_spec_parse(
                      wire, VCS_ZCODE_STUDY_SPEC_WIRE_BYTES, &parsed),
                  VCS_ZCODE_SCIENCE_OK);
        ASSERT(memcmp(&study, &parsed, sizeof(study)) == 0);
        ASSERT_EQ(vcs_zcode_study_spec_root(&study, root),
                  VCS_ZCODE_SCIENCE_OK);
        zcl_hex_encode(root, 32, root_hex);
        ASSERT_STR_EQ(root_hex,
            "36c02aa95792e0fb1698a2da0e51badb6cb7b715f8774e419681a1bfb56d2098");

        ASSERT_EQ(vcs_zcode_study_spec_parse(
                      wire, VCS_ZCODE_STUDY_SPEC_WIRE_BYTES + 1, &parsed),
                  VCS_ZCODE_SCIENCE_ERR_WIRE_SIZE);
        wire[0] ^= 1;
        ASSERT_EQ(vcs_zcode_study_spec_parse(
                      wire, VCS_ZCODE_STUDY_SPEC_WIRE_BYTES, &parsed),
                  VCS_ZCODE_SCIENCE_ERR_WIRE_MAGIC);
        ASSERT(parsed.schema_version == 0);
        study.null_hypothesis_root[0] = study.hypothesis_root[0];
        memset(study.null_hypothesis_root, 1, 32);
        ASSERT_EQ(vcs_zcode_study_spec_validate(&study),
                  VCS_ZCODE_SCIENCE_ERR_ROOT_REUSED);
        PASS();
    } _test_next:;
    return failures;
}

static int test_zs_result_and_reproduction(void)
{
    int failures = 0;
    TEST("zcode_science: results are observations and reproductions are local verdicts") {
        struct vcs_zcode_study_spec_v1 study;
        struct vcs_zcode_task_v1 task;
        struct vcs_zcode_candidate_v1 candidate;
        struct vcs_zcode_benchmark_result_v1 original, reproduced, parsed;
        struct vcs_zcode_reproduction_v1 reproduction, reproduction_parsed;
        struct vcs_build_action_v1 action;
        uint8_t task_root[32], candidate_root[32];
        zs_study(&study);
        zs_task_candidate(&study, &task, &candidate,
                          task_root, candidate_root);
        zs_result(&study, task_root, candidate_root, &original);
        zs_benchmark_action(&action);
        ASSERT_EQ(vcs_zcode_benchmark_result_validate_for_study(
                      &study, &task, &candidate, &action, &original, 2000),
                  VCS_ZCODE_SCIENCE_OK);
        struct vcs_zcode_benchmark_result_v1 tampered = original;
        tampered.action_root[0] ^= 1;
        ASSERT_EQ(vcs_zcode_benchmark_result_validate_for_study(
                      &study, &task, &candidate, &action, &tampered, 2000),
                  VCS_ZCODE_SCIENCE_ERR_ACTION_MISMATCH);
        uint8_t result_wire[VCS_ZCODE_BENCHMARK_RESULT_WIRE_BYTES + 1];
        uint8_t original_root[32], reproduced_root[32];
        char result_hex[65];
        ASSERT_EQ(vcs_zcode_benchmark_result_serialize(&original, result_wire),
                  VCS_ZCODE_SCIENCE_OK);
        ASSERT_EQ(vcs_zcode_benchmark_result_parse(
                      result_wire, VCS_ZCODE_BENCHMARK_RESULT_WIRE_BYTES,
                      &parsed), VCS_ZCODE_SCIENCE_OK);
        ASSERT_EQ(parsed.status, VCS_ZCODE_BENCHMARK_NULL_RESULT);
        ASSERT_EQ(vcs_zcode_benchmark_result_root(&original, original_root),
                  VCS_ZCODE_SCIENCE_OK);
        zcl_hex_encode(original_root, 32, result_hex);
        ASSERT_STR_EQ(result_hex,
            "342df9de90e8f61d5ef5b69ab980e940b4dde347087fd71fb5a652e47c4f6afe");
        ASSERT_EQ(vcs_zcode_benchmark_result_parse(
                      result_wire,
                      VCS_ZCODE_BENCHMARK_RESULT_WIRE_BYTES + 1, &parsed),
                  VCS_ZCODE_SCIENCE_ERR_WIRE_SIZE);

        reproduced = original;
        zs_root(reproduced.achieved_environment_root, 36);
        zs_root(reproduced.raw_sample_root, 37);
        zs_root(reproduced.evidence_root, 38);
        reproduced.status = VCS_ZCODE_BENCHMARK_NEGATIVE_RESULT;
        reproduced.sequence = 2;
        reproduced.started_unix = 1400;
        reproduced.finished_unix = 1500;
        ASSERT_EQ(vcs_zcode_benchmark_result_root(&reproduced,
                                                   reproduced_root),
                  VCS_ZCODE_SCIENCE_OK);
        memset(&reproduction, 0, sizeof(reproduction));
        reproduction.schema_version = VCS_ZCODE_SCIENCE_VERSION;
        memcpy(reproduction.study_root, original.study_root, 32);
        memcpy(reproduction.original_result_root, original_root, 32);
        memcpy(reproduction.reproduced_result_root, reproduced_root, 32);
        zs_root(reproduction.comparison_policy_root, 39);
        memcpy(reproduction.original_environment_root,
               original.achieved_environment_root, 32);
        memcpy(reproduction.reproduced_environment_root,
               reproduced.achieved_environment_root, 32);
        zs_root(reproduction.reproducer_pubkey, 40);
        reproduction.verdict = VCS_ZCODE_REPRODUCTION_CONTRADICTED;
        reproduction.sequence = 1;
        reproduction.created_unix = 1600;
        ASSERT_EQ(vcs_zcode_reproduction_validate_for_results(
                      &study, &original, &reproduced, &reproduction, 2000),
                  VCS_ZCODE_SCIENCE_OK);
        uint8_t reproduction_wire[VCS_ZCODE_REPRODUCTION_WIRE_BYTES];
        ASSERT_EQ(vcs_zcode_reproduction_serialize(
                      &reproduction, reproduction_wire),
                  VCS_ZCODE_SCIENCE_OK);
        ASSERT_EQ(vcs_zcode_reproduction_parse(
                      reproduction_wire, sizeof(reproduction_wire),
                      &reproduction_parsed), VCS_ZCODE_SCIENCE_OK);
        ASSERT_EQ(reproduction_parsed.verdict,
                  VCS_ZCODE_REPRODUCTION_CONTRADICTED);
        uint8_t reproduction_root[32];
        char reproduction_hex[65];
        ASSERT_EQ(vcs_zcode_reproduction_root(
                      &reproduction, reproduction_root),
                  VCS_ZCODE_SCIENCE_OK);
        zcl_hex_encode(reproduction_root, 32, reproduction_hex);
        ASSERT_STR_EQ(reproduction_hex,
            "d19c4242ea42a290f3982b4765b4624b7680022b3a8aa629dff4e48d41dfa10f");

        reproduction_parsed.reproduced_environment_root[0] ^= 1;
        ASSERT_EQ(vcs_zcode_reproduction_validate_for_results(
                      &study, &original, &reproduced,
                      &reproduction_parsed, 2000),
                  VCS_ZCODE_SCIENCE_ERR_ENVIRONMENT_MISMATCH);
        struct vcs_zcode_benchmark_result_v1 off_task = reproduced;
        off_task.task_root[0] ^= 1;
        ASSERT_EQ(vcs_zcode_reproduction_validate_for_results(
                      &study, &original, &off_task, &reproduction, 2000),
                  VCS_ZCODE_SCIENCE_ERR_TASK_MISMATCH);
        struct vcs_zcode_benchmark_result_v1 off_candidate = reproduced;
        off_candidate.candidate_root[0] ^= 1;
        ASSERT_EQ(vcs_zcode_reproduction_validate_for_results(
                      &study, &original, &off_candidate, &reproduction, 2000),
                  VCS_ZCODE_SCIENCE_ERR_CANDIDATE_MISMATCH);
        struct vcs_zcode_benchmark_result_v1 off_action = reproduced;
        off_action.action_root[0] ^= 1;
        ASSERT_EQ(vcs_zcode_reproduction_validate_for_results(
                      &study, &original, &off_action, &reproduction, 2000),
                  VCS_ZCODE_SCIENCE_ERR_ACTION_MISMATCH);
        original.status = 0;
        ASSERT_EQ(vcs_zcode_benchmark_result_validate(&original),
                  VCS_ZCODE_SCIENCE_ERR_STATUS);
        PASS();
    } _test_next:;
    return failures;
}

static int test_zs_findings(void)
{
    int failures = 0;
    TEST("zcode_science: structured findings bind the existing review without a hash cycle") {
        struct vcs_zcode_study_spec_v1 study;
        struct vcs_zcode_task_v1 task;
        struct vcs_zcode_candidate_v1 candidate;
        struct vcs_zcode_benchmark_result_v1 result;
        struct vcs_zcode_science_findings_v1 findings, parsed;
        struct vcs_zcode_review_v1 review;
        uint8_t task_root[32], candidate_root[32], result_root[32];
        zs_study(&study);
        zs_task_candidate(&study, &task, &candidate,
                          task_root, candidate_root);
        zs_result(&study, task_root, candidate_root, &result);
        (void)vcs_zcode_benchmark_result_root(&result, result_root);
        memset(&findings, 0, sizeof(findings));
        findings.schema_version = VCS_ZCODE_SCIENCE_VERSION;
        memcpy(findings.study_root, result.study_root, 32);
        memcpy(findings.task_root, task_root, 32);
        memcpy(findings.candidate_root, candidate_root, 32);
        memcpy(findings.result_root, result_root, 32);
        zs_root(findings.proof_set_root, 41);
        zs_root(findings.methods_root, 42);
        zs_root(findings.limitations_root, 43);
        zs_root(findings.conflicts_root, 44);
        findings.flags = VCS_ZCODE_FINDING_NULL;
        findings.severity = VCS_ZCODE_FINDING_MATERIAL;
        findings.sequence = 1;
        findings.created_unix = 1500;
        uint8_t findings_root[32];
        char findings_hex[65];
        ASSERT_EQ(vcs_zcode_science_findings_root(&findings, findings_root),
                  VCS_ZCODE_SCIENCE_OK);
        zcl_hex_encode(findings_root, 32, findings_hex);
        ASSERT_STR_EQ(findings_hex,
            "c311fd29f538c65bdd635feec84649b540d8eada42c8d7f02c1c9cc6c2118816");

        memset(&review, 0, sizeof(review));
        review.schema_version = VCS_ZCODE_DEV_VERSION;
        memcpy(review.task_root, task_root, 32);
        memcpy(review.candidate_root, candidate_root, 32);
        memcpy(review.proof_policy_root, task.proof_policy_root, 32);
        memcpy(review.proof_set_root, findings.proof_set_root, 32);
        memcpy(review.findings_root, findings_root, 32);
        zs_root(review.reviewer_pubkey, 45);
        review.verdict = VCS_ZCODE_REVIEW_APPROVE;
        review.sequence = 1;
        review.created_unix = 1600;
        ASSERT_EQ(vcs_zcode_science_findings_validate_for_review(
                      &study, &review, &result, &findings, 2000),
                  VCS_ZCODE_SCIENCE_OK);
        struct vcs_zcode_review_v1 early_review = review;
        early_review.created_unix = findings.created_unix - 1;
        ASSERT_EQ(vcs_zcode_science_findings_validate_for_review(
                      &study, &early_review, &result, &findings, 2000),
                  VCS_ZCODE_SCIENCE_ERR_EXPIRED);
        struct vcs_zcode_science_findings_v1 off_task = findings;
        off_task.task_root[0] ^= 1;
        ASSERT_EQ(vcs_zcode_science_findings_validate_for_review(
                      &study, &review, &result, &off_task, 2000),
                  VCS_ZCODE_SCIENCE_ERR_TASK_MISMATCH);
        struct vcs_zcode_science_findings_v1 off_candidate = findings;
        off_candidate.candidate_root[0] ^= 1;
        ASSERT_EQ(vcs_zcode_science_findings_validate_for_review(
                      &study, &review, &result, &off_candidate, 2000),
                  VCS_ZCODE_SCIENCE_ERR_CANDIDATE_MISMATCH);
        uint8_t wire[VCS_ZCODE_SCIENCE_FINDINGS_WIRE_BYTES];
        ASSERT_EQ(vcs_zcode_science_findings_serialize(&findings, wire),
                  VCS_ZCODE_SCIENCE_OK);
        ASSERT_EQ(vcs_zcode_science_findings_parse(
                      wire, sizeof(wire), &parsed), VCS_ZCODE_SCIENCE_OK);
        ASSERT_EQ(parsed.flags, VCS_ZCODE_FINDING_NULL);

        review.findings_root[0] ^= 1;
        ASSERT_EQ(vcs_zcode_science_findings_validate_for_review(
                      &study, &review, &result, &findings, 2000),
                  VCS_ZCODE_SCIENCE_ERR_REVIEW_MISMATCH);
        findings.flags |= VCS_ZCODE_FINDING_RETRACTION;
        ASSERT_EQ(vcs_zcode_science_findings_validate(&findings),
                  VCS_ZCODE_SCIENCE_ERR_FLAGS);
        zs_root(findings.retraction_target_root, 46);
        ASSERT_EQ(vcs_zcode_science_findings_validate(&findings),
                  VCS_ZCODE_SCIENCE_OK);
        PASS();
    } _test_next:;
    return failures;
}

static int test_zs_submission_window(void)
{
    int failures = 0;
    TEST("zcode_science: expiry gates new submissions, never historical re-verification") {
        struct vcs_zcode_study_spec_v1 study;
        struct vcs_zcode_task_v1 task;
        struct vcs_zcode_candidate_v1 candidate;
        struct vcs_zcode_benchmark_result_v1 original, reproduced;
        struct vcs_zcode_reproduction_v1 reproduction;
        struct vcs_zcode_science_findings_v1 findings;
        struct vcs_zcode_review_v1 review;
        struct vcs_build_action_v1 action;
        uint8_t task_root[32], candidate_root[32];
        uint8_t original_root[32], reproduced_root[32], findings_root[32];
        zs_study(&study);
        zs_task_candidate(&study, &task, &candidate,
                          task_root, candidate_root);
        zs_result(&study, task_root, candidate_root, &original);
        zs_benchmark_action(&action);
        (void)vcs_zcode_benchmark_result_root(&original, original_root);

        ASSERT(vcs_zcode_study_spec_accepts_submission_at(&study, 1000));
        ASSERT(vcs_zcode_study_spec_accepts_submission_at(&study, 4999));
        ASSERT(!vcs_zcode_study_spec_accepts_submission_at(&study, 999));
        ASSERT(!vcs_zcode_study_spec_accepts_submission_at(&study, 5000));

        reproduced = original;
        zs_root(reproduced.achieved_environment_root, 36);
        zs_root(reproduced.raw_sample_root, 37);
        zs_root(reproduced.evidence_root, 38);
        reproduced.status = VCS_ZCODE_BENCHMARK_NEGATIVE_RESULT;
        reproduced.sequence = 2;
        reproduced.started_unix = 1400;
        reproduced.finished_unix = 1500;
        (void)vcs_zcode_benchmark_result_root(&reproduced, reproduced_root);
        memset(&reproduction, 0, sizeof(reproduction));
        reproduction.schema_version = VCS_ZCODE_SCIENCE_VERSION;
        memcpy(reproduction.study_root, original.study_root, 32);
        memcpy(reproduction.original_result_root, original_root, 32);
        memcpy(reproduction.reproduced_result_root, reproduced_root, 32);
        zs_root(reproduction.comparison_policy_root, 39);
        memcpy(reproduction.original_environment_root,
               original.achieved_environment_root, 32);
        memcpy(reproduction.reproduced_environment_root,
               reproduced.achieved_environment_root, 32);
        zs_root(reproduction.reproducer_pubkey, 40);
        reproduction.verdict = VCS_ZCODE_REPRODUCTION_CONTRADICTED;
        reproduction.sequence = 1;
        reproduction.created_unix = 1600;

        memset(&findings, 0, sizeof(findings));
        findings.schema_version = VCS_ZCODE_SCIENCE_VERSION;
        memcpy(findings.study_root, original.study_root, 32);
        memcpy(findings.task_root, task_root, 32);
        memcpy(findings.candidate_root, candidate_root, 32);
        memcpy(findings.result_root, original_root, 32);
        zs_root(findings.proof_set_root, 41);
        zs_root(findings.methods_root, 42);
        zs_root(findings.limitations_root, 43);
        zs_root(findings.conflicts_root, 44);
        findings.flags = VCS_ZCODE_FINDING_NULL;
        findings.severity = VCS_ZCODE_FINDING_MATERIAL;
        findings.sequence = 1;
        findings.created_unix = 1700;
        (void)vcs_zcode_science_findings_root(&findings, findings_root);

        memset(&review, 0, sizeof(review));
        review.schema_version = VCS_ZCODE_DEV_VERSION;
        memcpy(review.task_root, task_root, 32);
        memcpy(review.candidate_root, candidate_root, 32);
        memcpy(review.proof_policy_root, task.proof_policy_root, 32);
        memcpy(review.proof_set_root, findings.proof_set_root, 32);
        memcpy(review.findings_root, findings_root, 32);
        zs_root(review.reviewer_pubkey, 45);
        review.verdict = VCS_ZCODE_REVIEW_APPROVE;
        review.sequence = 1;
        review.created_unix = 1800;

        /* History is preserved: every layer re-verifies after the window. */
        ASSERT_EQ(vcs_zcode_benchmark_result_validate_for_study(
                      &study, &task, &candidate, &action, &original, 6000),
                  VCS_ZCODE_SCIENCE_OK);
        ASSERT_EQ(vcs_zcode_reproduction_validate_for_results(
                      &study, &original, &reproduced, &reproduction, 6000),
                  VCS_ZCODE_SCIENCE_OK);
        ASSERT_EQ(vcs_zcode_science_findings_validate_for_review(
                      &study, &review, &original, &findings, 6000),
                  VCS_ZCODE_SCIENCE_OK);

        /* Evidence created after the window closed is still rejected. */
        struct vcs_zcode_benchmark_result_v1 late = original;
        late.started_unix = 4900;
        late.finished_unix = 5000;
        ASSERT_EQ(vcs_zcode_benchmark_result_validate_for_study(
                      &study, &task, &candidate, &action, &late, 5200),
                  VCS_ZCODE_SCIENCE_ERR_EXPIRED);
        struct vcs_zcode_reproduction_v1 late_reproduction = reproduction;
        late_reproduction.created_unix = 5000;
        ASSERT_EQ(vcs_zcode_reproduction_validate_for_results(
                      &study, &original, &reproduced,
                      &late_reproduction, 5200),
                  VCS_ZCODE_SCIENCE_ERR_EXPIRED);

        /* Evidence from the future is a distinct failure class. */
        struct vcs_zcode_benchmark_result_v1 future = original;
        future.finished_unix = 2100;
        ASSERT_EQ(vcs_zcode_benchmark_result_validate_for_study(
                      &study, &task, &candidate, &action, &future, 2000),
                  VCS_ZCODE_SCIENCE_ERR_EVIDENCE_FUTURE);
        struct vcs_zcode_reproduction_v1 future_reproduction = reproduction;
        future_reproduction.created_unix = 2100;
        ASSERT_EQ(vcs_zcode_reproduction_validate_for_results(
                      &study, &original, &reproduced,
                      &future_reproduction, 2000),
                  VCS_ZCODE_SCIENCE_ERR_EVIDENCE_FUTURE);
        struct vcs_zcode_science_findings_v1 future_findings = findings;
        future_findings.created_unix = 2100;
        struct vcs_zcode_review_v1 future_review = review;
        future_review.created_unix = 2200;
        (void)vcs_zcode_science_findings_root(&future_findings,
                                              future_review.findings_root);
        ASSERT_EQ(vcs_zcode_science_findings_validate_for_review(
                      &study, &future_review, &original,
                      &future_findings, 2000),
                  VCS_ZCODE_SCIENCE_ERR_EVIDENCE_FUTURE);
        PASS();
    } _test_next:;
    return failures;
}

static int test_zs_curation_vote(void)
{
    int failures = 0;
    TEST("zcode_science: curation is signed network-bound discovery input only") {
        struct vcs_zcode_curation_vote_v1 vote, parsed;
        memset(&vote, 0, sizeof(vote));
        vote.schema_version = VCS_ZCODE_SCIENCE_VERSION;
        zs_root(vote.network_genesis_root, 50);
        zs_root(vote.voter_zid_root, 51);
        zs_root(vote.property_root, 52);
        vote.signal = VCS_ZCODE_CURATION_INTERESTING;
        vote.sequence = 9;
        vote.expires_unix = 5000;
        uint8_t seed[32], secret[32], pubkey[32], id[32], wrong[32];
        char id_hex[65];
        zs_root(seed, 53);
        ed25519_keypair(pubkey, secret, seed);
        ASSERT_EQ(vcs_zcode_curation_vote_seal(&vote, secret, pubkey),
                  VCS_ZCODE_SCIENCE_OK);
        ASSERT_EQ(vcs_zcode_curation_vote_verify(
                      &vote, vote.network_genesis_root, vote.voter_zid_root,
                      pubkey, 2000), VCS_ZCODE_SCIENCE_OK);
        ASSERT_EQ(vcs_zcode_curation_vote_id(&vote, id),
                  VCS_ZCODE_SCIENCE_OK);
        zcl_hex_encode(id, 32, id_hex);
        ASSERT_STR_EQ(id_hex,
            "442ac3dc808c8fd6ecebb3091c08cdbaef218fabe79ab9b8df5630fb2f4306c1");
        uint8_t wire[VCS_ZCODE_CURATION_VOTE_WIRE_BYTES + 1];
        ASSERT_EQ(vcs_zcode_curation_vote_serialize(&vote, wire),
                  VCS_ZCODE_SCIENCE_OK);
        ASSERT_EQ(vcs_zcode_curation_vote_parse(
                      wire, VCS_ZCODE_CURATION_VOTE_WIRE_BYTES, &parsed),
                  VCS_ZCODE_SCIENCE_OK);
        ASSERT_EQ(vcs_zcode_curation_vote_parse(
                      wire, VCS_ZCODE_CURATION_VOTE_WIRE_BYTES + 1, &parsed),
                  VCS_ZCODE_SCIENCE_ERR_WIRE_SIZE);
        zs_root(wrong, 54);
        ASSERT_EQ(vcs_zcode_curation_vote_verify(
                      &vote, wrong, vote.voter_zid_root, pubkey, 2000),
                  VCS_ZCODE_SCIENCE_ERR_NETWORK_MISMATCH);
        ASSERT_EQ(vcs_zcode_curation_vote_verify(
                      &vote, vote.network_genesis_root, wrong, pubkey, 2000),
                  VCS_ZCODE_SCIENCE_ERR_IDENTITY_MISMATCH);
        vote.property_root[0] ^= 1;
        ASSERT_EQ(vcs_zcode_curation_vote_verify(
                      &vote, vote.network_genesis_root, vote.voter_zid_root,
                      pubkey, 2000), VCS_ZCODE_SCIENCE_ERR_SIGNATURE);
        PASS();
    } _test_next:;
    return failures;
}

static int test_zs_fixed_actions(void)
{
    int failures = 0;
    TEST("zcode_science: benchmark and reproduction actions are closed identities") {
        ASSERT_EQ(vcs_build_action_v1_work_kind(
                      VCS_BUILD_ACTION_KIND_BENCHMARK_V1),
                  VCS_ZCODE_WORK_TEST);
        ASSERT_EQ(vcs_build_action_v1_work_kind(
                      VCS_BUILD_ACTION_KIND_BENCHMARK_REPRODUCE_V1),
                  VCS_ZCODE_WORK_REPRODUCE);
        ASSERT_EQ(vcs_build_action_v1_work_kind("c23.benchmark.shell.v1"), 0);
        struct vcs_build_action_v1 benchmark, reproduction;
        uint8_t benchmark_root[32], reproduction_root[32];
        zs_action(&benchmark, VCS_BUILD_ACTION_KIND_BENCHMARK_V1, 1);
        zs_action(&reproduction,
                  VCS_BUILD_ACTION_KIND_BENCHMARK_REPRODUCE_V1, 1);
        ASSERT(vcs_build_action_v1_root_for_kind(
            VCS_BUILD_ACTION_KIND_BENCHMARK_V1,
            &benchmark, benchmark_root));
        ASSERT(vcs_build_action_v1_root_for_kind(
            VCS_BUILD_ACTION_KIND_BENCHMARK_REPRODUCE_V1,
            &reproduction, reproduction_root));
        ASSERT(memcmp(benchmark_root, reproduction_root, 32) != 0);
        ASSERT(!vcs_build_action_v1_root_for_kind(
            VCS_BUILD_ACTION_KIND_BENCHMARK_REPRODUCE_V1,
            &benchmark, reproduction_root));
        ASSERT_STR_EQ(benchmark.resource_policy,
                      VCS_BUILD_BENCHMARK_RESOURCE_POLICY_V1);
        ASSERT(strstr(benchmark.resource_policy, "network=0") != NULL);
        PASS();
    } _test_next:;
    return failures;
}

static int test_zs_source_manifest_id_is_sha3(void)
{
    int failures = 0;
    TEST("zcode source-manifest identity is SHA3-256, not SHA-256") {
        static const uint8_t wire[] = { 'c', '2', '3', 1, 2, 3 };
        uint8_t id[32], sha3[32], sha2[32];
        struct sha3_256_ctx s3;
        struct sha256_ctx s2;
        static const char domain[] = VCS_SOURCE_MANIFEST_ID_SCHEMA;

        ASSERT_STR_EQ(VCS_SOURCE_MANIFEST_ID_SCHEMA,
                      "zcl.zcode.source_manifest_sha3.v1");
        vcs_source_manifest_id(wire, sizeof(wire), id);
        sha3_256_init(&s3);
        sha3_256_write(&s3, (const uint8_t *)domain, sizeof(domain));
        sha3_256_write(&s3, wire, sizeof(wire));
        sha3_256_finalize(&s3, sha3);
        sha256_init(&s2);
        sha256_write(&s2, (const uint8_t *)domain, sizeof(domain));
        sha256_write(&s2, wire, sizeof(wire));
        sha256_finalize(&s2, sha2);
        ASSERT(memcmp(id, sha3, 32) == 0);
        ASSERT(memcmp(id, sha2, 32) != 0);
        PASS();
    } _test_next:;
    return failures;
}

static int test_zs_hardware_profile(void)
{
    int failures = 0;
    TEST("zcode_science: hardware profile is a canonical observed host description") {
        struct vcs_zcode_hardware_profile_v1 profile, parsed;
        zs_hardware_profile(&profile);
        uint8_t wire[VCS_ZCODE_HARDWARE_PROFILE_WIRE_BYTES + 1];
        uint8_t root[32], root_again[32];
        char wire_hex[2 * VCS_ZCODE_HARDWARE_PROFILE_WIRE_BYTES + 1];
        char root_hex[65];
        ASSERT_EQ(vcs_zcode_hardware_profile_validate(&profile),
                  VCS_ZCODE_SCIENCE_OK);
        ASSERT_EQ(vcs_zcode_hardware_profile_serialize(&profile, wire),
                  VCS_ZCODE_SCIENCE_OK);
        ASSERT(memcmp(wire, "ZCHWPF\r\n", 8) == 0);
        zcl_hex_encode(wire, VCS_ZCODE_HARDWARE_PROFILE_WIRE_BYTES,
                       wire_hex);
        ASSERT_STR_EQ(wire_hex,
            "5a43485750460d0a010047656e75696e65496e74656c000000005a436c617373"
            "6963323320546573742043505500000000000000000000000000000000000000"
            "000000000000000000000800100000800000000000001f000000000000004c69"
            "6e757800000000000000000000007838365f363400000000000000000000362e"
            "392e302d74657374000000000000000000000000000000000000000000000000"
            "000000000000000000000000000000000000000000000000000000000000005e"
            "d0b20000000074736300000000000000000000000000e803000000000000");
        ASSERT_EQ(vcs_zcode_hardware_profile_root(&profile, root),
                  VCS_ZCODE_SCIENCE_OK);
        ASSERT_EQ(vcs_zcode_hardware_profile_root(&profile, root_again),
                  VCS_ZCODE_SCIENCE_OK);
        ASSERT(memcmp(root, root_again, 32) == 0);
        zcl_hex_encode(root, 32, root_hex);
        ASSERT_STR_EQ(root_hex,
            "8679e5bf0c083a1b6bfa964ee8be695dc2d15fbe714b9aa31bfc199672ba275d");
        ASSERT_EQ(vcs_zcode_hardware_profile_parse(
                      wire, VCS_ZCODE_HARDWARE_PROFILE_WIRE_BYTES, &parsed),
                  VCS_ZCODE_SCIENCE_OK);
        ASSERT(memcmp(&profile, &parsed, sizeof(profile)) == 0);
        ASSERT_EQ(vcs_zcode_hardware_profile_parse(
                      wire, VCS_ZCODE_HARDWARE_PROFILE_WIRE_BYTES + 1,
                      &parsed), VCS_ZCODE_SCIENCE_ERR_WIRE_SIZE);
        wire[0] ^= 1;
        ASSERT_EQ(vcs_zcode_hardware_profile_parse(
                      wire, VCS_ZCODE_HARDWARE_PROFILE_WIRE_BYTES, &parsed),
                  VCS_ZCODE_SCIENCE_ERR_WIRE_MAGIC);
        ASSERT(parsed.schema_version == 0);

        /* NUL-padding violations: content after the first NUL, and a full
         * field with no NUL at all. */
        struct vcs_zcode_hardware_profile_v1 bad = profile;
        bad.cpu_brand[47] = '!';
        ASSERT_EQ(vcs_zcode_hardware_profile_validate(&bad),
                  VCS_ZCODE_SCIENCE_ERR_PADDING);
        bad = profile;
        memset(bad.cpu_vendor, 'A', sizeof(bad.cpu_vendor));
        ASSERT_EQ(vcs_zcode_hardware_profile_validate(&bad),
                  VCS_ZCODE_SCIENCE_ERR_PADDING);
        /* Reserved ISA bits are rejected. */
        bad = profile;
        bad.isa_bits |= UINT64_C(1) << 13;
        ASSERT_EQ(vcs_zcode_hardware_profile_validate(&bad),
                  VCS_ZCODE_SCIENCE_ERR_ISA);
        bad = profile;
        bad.physical_cores = 0;
        ASSERT_EQ(vcs_zcode_hardware_profile_validate(&bad),
                  VCS_ZCODE_SCIENCE_ERR_LIMIT);

        /* Live capture on this host always yields a valid object. */
        struct vcs_zcode_hardware_profile_v1 captured, captured_parsed;
        ASSERT(vcs_zcode_hardware_profile_capture(&captured, 2000));
        ASSERT_EQ(vcs_zcode_hardware_profile_validate(&captured),
                  VCS_ZCODE_SCIENCE_OK);
        uint8_t captured_wire[VCS_ZCODE_HARDWARE_PROFILE_WIRE_BYTES];
        ASSERT_EQ(vcs_zcode_hardware_profile_serialize(
                      &captured, captured_wire), VCS_ZCODE_SCIENCE_OK);
        ASSERT_EQ(vcs_zcode_hardware_profile_parse(
                      captured_wire, sizeof(captured_wire), &captured_parsed),
                  VCS_ZCODE_SCIENCE_OK);
        ASSERT(memcmp(&captured, &captured_parsed, sizeof(captured)) == 0);
        PASS();
    } _test_next:;
    return failures;
}

static int test_zs_benchmark_method(void)
{
    int failures = 0;
    TEST("zcode_science: benchmark method pins workload, timer, estimator, and sampling") {
        struct vcs_zcode_benchmark_method_v1 method, parsed;
        zs_method(&method);
        uint8_t wire[VCS_ZCODE_BENCHMARK_METHOD_WIRE_BYTES + 1];
        uint8_t root[32];
        char wire_hex[2 * VCS_ZCODE_BENCHMARK_METHOD_WIRE_BYTES + 1];
        char root_hex[65];
        ASSERT_EQ(vcs_zcode_benchmark_method_validate(&method),
                  VCS_ZCODE_SCIENCE_OK);
        ASSERT_EQ(vcs_zcode_benchmark_method_serialize(&method, wire),
                  VCS_ZCODE_SCIENCE_OK);
        ASSERT(memcmp(wire, "ZCBMTH\r\n", 8) == 0);
        zcl_hex_encode(wire, VCS_ZCODE_BENCHMARK_METHOD_WIRE_BYTES,
                       wire_hex);
        ASSERT_STR_EQ(wire_hex,
            "5a43424d54480d0a010041414141414141414141414141414141414141414141"
            "4141414141414141414142424242424242424242424242424242424242424242"
            "4242424242424242424243434343434343434343434343434343434343434343"
            "43434343434343434343881300000a000000e8030000040a00");
        ASSERT_EQ(vcs_zcode_benchmark_method_root(&method, root),
                  VCS_ZCODE_SCIENCE_OK);
        zcl_hex_encode(root, 32, root_hex);
        ASSERT_STR_EQ(root_hex,
            "dba5920e4b47fd67434e7cdafb51856519656ecaee8694645370905f85ead121");
        ASSERT_EQ(vcs_zcode_benchmark_method_parse(
                      wire, VCS_ZCODE_BENCHMARK_METHOD_WIRE_BYTES, &parsed),
                  VCS_ZCODE_SCIENCE_OK);
        ASSERT(memcmp(&method, &parsed, sizeof(method)) == 0);
        ASSERT_EQ(vcs_zcode_benchmark_method_parse(
                      wire, VCS_ZCODE_BENCHMARK_METHOD_WIRE_BYTES + 1,
                      &parsed), VCS_ZCODE_SCIENCE_ERR_WIRE_SIZE);
        wire[0] ^= 1;
        ASSERT_EQ(vcs_zcode_benchmark_method_parse(
                      wire, VCS_ZCODE_BENCHMARK_METHOD_WIRE_BYTES, &parsed),
                  VCS_ZCODE_SCIENCE_ERR_WIRE_MAGIC);

        /* trim_percent is meaningful only for a trimmed mean. */
        struct vcs_zcode_benchmark_method_v1 bad = method;
        bad.sample_distribution = VCS_ZCODE_SAMPLE_DIST_MINIMUM;
        ASSERT_EQ(vcs_zcode_benchmark_method_validate(&bad),
                  VCS_ZCODE_SCIENCE_ERR_DISTRIBUTION);
        bad.sample_distribution = VCS_ZCODE_SAMPLE_DIST_TRIMMED_MEAN;
        bad.trim_percent = 50;
        ASSERT_EQ(vcs_zcode_benchmark_method_validate(&bad),
                  VCS_ZCODE_SCIENCE_ERR_DISTRIBUTION);
        bad = method;
        bad.sample_distribution = 0;
        ASSERT_EQ(vcs_zcode_benchmark_method_validate(&bad),
                  VCS_ZCODE_SCIENCE_ERR_DISTRIBUTION);
        bad = method;
        bad.measured_samples = 0;
        ASSERT_EQ(vcs_zcode_benchmark_method_validate(&bad),
                  VCS_ZCODE_SCIENCE_ERR_LIMIT);
        bad.measured_samples =
            VCS_ZCODE_BENCHMARK_METHOD_MAX_MEASURED_SAMPLES + 1;
        ASSERT_EQ(vcs_zcode_benchmark_method_validate(&bad),
                  VCS_ZCODE_SCIENCE_ERR_LIMIT);
        bad = method;
        bad.reserved = 1;
        ASSERT_EQ(vcs_zcode_benchmark_method_validate(&bad),
                  VCS_ZCODE_SCIENCE_ERR_FLAGS);

        ASSERT_STR_EQ(vcs_zcode_benchmark_method_distribution_name(
                          VCS_ZCODE_SAMPLE_DIST_RAW_ALL), "raw_all");
        ASSERT_STR_EQ(vcs_zcode_benchmark_method_distribution_name(
                          VCS_ZCODE_SAMPLE_DIST_MINIMUM), "minimum");
        ASSERT_STR_EQ(vcs_zcode_benchmark_method_distribution_name(
                          VCS_ZCODE_SAMPLE_DIST_MEDIAN_QUARTILES),
                      "median_quartiles");
        ASSERT_STR_EQ(vcs_zcode_benchmark_method_distribution_name(
                          VCS_ZCODE_SAMPLE_DIST_TRIMMED_MEAN),
                      "trimmed_mean");
        ASSERT_STR_EQ(vcs_zcode_benchmark_method_distribution_name(0),
                      "unknown");
        PASS();
    } _test_next:;
    return failures;
}

static int test_zs_result_v2(void)
{
    int failures = 0;
    TEST("zcode_science: result v2 binds the method and hardware profile, still an observation") {
        struct vcs_zcode_study_spec_v1 study;
        struct vcs_zcode_task_v1 task;
        struct vcs_zcode_candidate_v1 candidate;
        struct vcs_zcode_benchmark_method_v1 method;
        struct vcs_zcode_hardware_profile_v1 profile;
        struct vcs_zcode_benchmark_result_v2 result, parsed;
        struct vcs_build_action_v1 action;
        uint8_t task_root[32], candidate_root[32];
        zs_study(&study);
        zs_task_candidate(&study, &task, &candidate,
                          task_root, candidate_root);
        zs_method(&method);
        ASSERT(vcs_zcode_hardware_profile_capture(&profile, 1250));
        zs_benchmark_action(&action);
        zs_result_v2(&study, task_root, candidate_root, &method, &profile,
                     &result);

        /* Happy path: structural + cross-validation with real method and
         * captured profile objects. */
        ASSERT_EQ(vcs_zcode_benchmark_result_v2_validate(&result),
                  VCS_ZCODE_SCIENCE_OK);
        ASSERT_EQ(vcs_zcode_benchmark_result_v2_validate_for_study(
                      &study, &task, &candidate, &action, &method, &profile,
                      &result, 2000), VCS_ZCODE_SCIENCE_OK);

        uint8_t wire[VCS_ZCODE_BENCHMARK_RESULT_V2_WIRE_BYTES + 1];
        uint8_t root[32], root_again[32];
        ASSERT_EQ(vcs_zcode_benchmark_result_v2_serialize(&result, wire),
                  VCS_ZCODE_SCIENCE_OK);
        ASSERT(memcmp(wire, "ZCBEN2\r\n", 8) == 0);
        ASSERT_EQ(vcs_zcode_benchmark_result_v2_root(&result, root),
                  VCS_ZCODE_SCIENCE_OK);
        ASSERT_EQ(vcs_zcode_benchmark_result_v2_root(&result, root_again),
                  VCS_ZCODE_SCIENCE_OK);
        ASSERT(memcmp(root, root_again, 32) == 0);
        ASSERT_EQ(vcs_zcode_benchmark_result_v2_parse(
                      wire, VCS_ZCODE_BENCHMARK_RESULT_V2_WIRE_BYTES,
                      &parsed), VCS_ZCODE_SCIENCE_OK);
        ASSERT(memcmp(&result, &parsed, sizeof(result)) == 0);
        ASSERT_EQ(vcs_zcode_benchmark_result_v2_parse(
                      wire, VCS_ZCODE_BENCHMARK_RESULT_V2_WIRE_BYTES + 1,
                      &parsed), VCS_ZCODE_SCIENCE_ERR_WIRE_SIZE);
        /* The frozen 299-byte v1 wire is not a v2 wire. */
        ASSERT_EQ(vcs_zcode_benchmark_result_v2_parse(
                      wire, VCS_ZCODE_BENCHMARK_RESULT_WIRE_BYTES, &parsed),
                  VCS_ZCODE_SCIENCE_ERR_WIRE_SIZE);

        /* Tampered bindings reject. */
        struct vcs_zcode_benchmark_result_v2 tampered = result;
        tampered.method_root[0] ^= 1;
        ASSERT_EQ(vcs_zcode_benchmark_result_v2_validate_for_study(
                      &study, &task, &candidate, &action, &method, &profile,
                      &tampered, 2000),
                  VCS_ZCODE_SCIENCE_ERR_METHOD_MISMATCH);
        tampered = result;
        tampered.hardware_profile_root[0] ^= 1;
        ASSERT_EQ(vcs_zcode_benchmark_result_v2_validate_for_study(
                      &study, &task, &candidate, &action, &method, &profile,
                      &tampered, 2000),
                  VCS_ZCODE_SCIENCE_ERR_HARDWARE_MISMATCH);
        tampered = result;
        memset(tampered.method_root, 0, 32);
        ASSERT_EQ(vcs_zcode_benchmark_result_v2_validate(&tampered),
                  VCS_ZCODE_SCIENCE_ERR_ROOT_ZERO);

        /* Inherited H2 behaviors: post-expiry revalidation passes; future
         * evidence is its own failure class. */
        ASSERT_EQ(vcs_zcode_benchmark_result_v2_validate_for_study(
                      &study, &task, &candidate, &action, &method, &profile,
                      &result, 6000), VCS_ZCODE_SCIENCE_OK);
        struct vcs_zcode_benchmark_result_v2 future = result;
        future.finished_unix = 2100;
        ASSERT_EQ(vcs_zcode_benchmark_result_v2_validate_for_study(
                      &study, &task, &candidate, &action, &method, &profile,
                      &future, 2000),
                  VCS_ZCODE_SCIENCE_ERR_EVIDENCE_FUTURE);
        struct vcs_zcode_benchmark_result_v2 late = result;
        late.started_unix = 4900;
        late.finished_unix = 5000;
        ASSERT_EQ(vcs_zcode_benchmark_result_v2_validate_for_study(
                      &study, &task, &candidate, &action, &method, &profile,
                      &late, 5200), VCS_ZCODE_SCIENCE_ERR_EXPIRED);
        PASS();
    } _test_next:;
    return failures;
}

int test_zcode_science(void)
{
    int failures = 0;
    failures += test_zs_study_codec();
    failures += test_zs_result_and_reproduction();
    failures += test_zs_findings();
    failures += test_zs_submission_window();
    failures += test_zs_curation_vote();
    failures += test_zs_fixed_actions();
    failures += test_zs_source_manifest_id_is_sha3();
    failures += test_zs_hardware_profile();
    failures += test_zs_benchmark_method();
    failures += test_zs_result_v2();
    printf("=== zcode_science: %d failures ===\n", failures);
    return failures;
}
