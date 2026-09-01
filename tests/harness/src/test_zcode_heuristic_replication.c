/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: signed independent-replication qualification adversarial tests. */
#include "test/test_core.h"

#include "crypto/ed25519.h"
#include "vcs/vcs_object.h"
#include "vcs/zcode_heuristic_replication.h"
#include "vcs/zcode_science.h"

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define HR_CHECK(name_, expression_) do {                                  \
    if (expression_) printf("  zcode_heuristic_replication: %s... OK\n",   \
                            (name_));                                      \
    else {                                                                 \
        printf("  zcode_heuristic_replication: %s... FAIL\n", (name_));   \
        failures++;                                                        \
    }                                                                      \
} while (0)

struct hr_fixture {
    struct vcs_zcode_study_spec_v1 study;
    struct vcs_zcode_task_v1 task;
    struct vcs_zcode_candidate_v1 candidate;
    struct vcs_build_action_v1 action;
    struct vcs_zcode_heuristic_v1 heuristic;
    struct vcs_zcode_benchmark_result_v1 original;
    struct vcs_zcode_benchmark_result_v1 reproduced[4];
    struct vcs_zcode_reproduction_v1 reproduction[4];
    struct vcs_zcode_science_statement_v1 anchor;
    struct vcs_zcode_science_statement_v1 statement[4];
    uint8_t evaluator_secret[32], evaluator_pubkey[32];
    uint8_t secret[4][32], pubkey[4][32];
    uint8_t study_root[32], task_root[32], heuristic_root[32];
    uint8_t candidate_root[32];
    uint8_t original_root[32], anchor_root[32];
    uint8_t reproduced_root[4][32], reproduction_root[4][32];
    uint8_t statement_root[4][32];
};

static void hr_root(uint8_t out[32], uint8_t tag)
{
    memset(out, tag, 32);
}

static bool hr_store(const char *workspace, const uint8_t root[32],
                     const uint8_t *wire, size_t wire_len)
{
    return vcs_object_put_addressed(workspace, root, wire, wire_len);
}

static bool hr_store_study(const char *workspace,
                           const struct vcs_zcode_study_spec_v1 *value,
                           uint8_t root[32])
{
    uint8_t wire[VCS_ZCODE_STUDY_SPEC_WIRE_BYTES];
    return vcs_zcode_study_spec_serialize(value, wire) ==
            VCS_ZCODE_SCIENCE_OK &&
        vcs_zcode_study_spec_root(value, root) == VCS_ZCODE_SCIENCE_OK &&
        hr_store(workspace, root, wire, sizeof(wire));
}

static bool hr_store_task(const char *workspace,
                          const struct vcs_zcode_task_v1 *value,
                          uint8_t root[32])
{
    uint8_t wire[VCS_ZCODE_TASK_WIRE_BYTES];
    return vcs_zcode_task_serialize(value, wire) == VCS_ZCODE_DEV_OK &&
        vcs_zcode_task_root(value, root) == VCS_ZCODE_DEV_OK &&
        hr_store(workspace, root, wire, sizeof(wire));
}

static bool hr_store_candidate(const char *workspace,
                               const struct vcs_zcode_candidate_v1 *value,
                               uint8_t root[32])
{
    uint8_t wire[VCS_ZCODE_CANDIDATE_WIRE_BYTES];
    return vcs_zcode_candidate_serialize(value, wire) == VCS_ZCODE_DEV_OK &&
        vcs_zcode_candidate_root(value, root) == VCS_ZCODE_DEV_OK &&
        hr_store(workspace, root, wire, sizeof(wire));
}

static bool hr_store_result(
    const char *workspace, const struct vcs_zcode_benchmark_result_v1 *value,
    uint8_t root[32])
{
    uint8_t wire[VCS_ZCODE_BENCHMARK_RESULT_WIRE_BYTES];
    return vcs_zcode_benchmark_result_serialize(value, wire) ==
            VCS_ZCODE_SCIENCE_OK &&
        vcs_zcode_benchmark_result_root(value, root) ==
            VCS_ZCODE_SCIENCE_OK &&
        hr_store(workspace, root, wire, sizeof(wire));
}

static bool hr_store_reproduction(
    const char *workspace, const struct vcs_zcode_reproduction_v1 *value,
    uint8_t root[32])
{
    uint8_t wire[VCS_ZCODE_REPRODUCTION_WIRE_BYTES];
    return vcs_zcode_reproduction_serialize(value, wire) ==
            VCS_ZCODE_SCIENCE_OK &&
        vcs_zcode_reproduction_root(value, root) == VCS_ZCODE_SCIENCE_OK &&
        hr_store(workspace, root, wire, sizeof(wire));
}

static bool hr_store_statement(
    const char *workspace, const struct vcs_zcode_science_statement_v1 *value,
    const struct vcs_zcode_science_relation_set_v1 *relations,
    uint8_t root[32])
{
    uint8_t relation_wire[VCS_ZCODE_SCIENCE_RELATION_SET_MAX_WIRE_BYTES];
    uint8_t statement_wire[VCS_ZCODE_SCIENCE_STATEMENT_WIRE_BYTES];
    uint8_t relation_root[32];
    size_t relation_len = 0;
    return vcs_zcode_science_relation_set_serialize(
               relations, relation_wire, &relation_len) ==
               VCS_ZCODE_SCIENCE_OK &&
        vcs_zcode_science_relation_set_root(relations, relation_root) ==
               VCS_ZCODE_SCIENCE_OK &&
        vcs_zcode_science_statement_serialize(value, statement_wire) ==
               VCS_ZCODE_SCIENCE_OK &&
        vcs_zcode_science_statement_root(value, root) ==
               VCS_ZCODE_SCIENCE_OK &&
        hr_store(workspace, relation_root, relation_wire, relation_len) &&
        hr_store(workspace, root, statement_wire, sizeof(statement_wire));
}

static void hr_statement_base(
    struct vcs_zcode_science_statement_v1 *statement, uint8_t profile,
    const uint8_t subject[32],
    const struct vcs_zcode_science_relation_set_v1 *relations, uint8_t tag)
{
    memset(statement, 0, sizeof(*statement));
    statement->schema_version = VCS_ZCODE_SCIENCE_STATEMENT_VERSION;
    statement->profile = profile;
    statement->access = VCS_ZCODE_SCIENCE_ACCESS_PUBLIC;
    statement->privacy = VCS_ZCODE_SCIENCE_PRIVACY_PUBLIC;
    statement->redistribution = VCS_ZCODE_SCIENCE_REDISTRIBUTION_PERMITTED;
    statement->authorship = VCS_ZCODE_SCIENCE_AUTHORSHIP_SIGNED;
    statement->relation_count = relations->row_count;
    statement->relation_types = relations->row_count == 0 ? 0 :
        VCS_ZCODE_SCIENCE_RELATION_MASK(relations->rows[0].type);
    memcpy(statement->subject_root, subject, 32);
    hr_root(statement->predicate_body_root, tag);
    hr_root(statement->profile_schema_root, (uint8_t)(tag + 1u));
    hr_root(statement->provenance_root, (uint8_t)(tag + 2u));
    hr_root(statement->activity_root, (uint8_t)(tag + 3u));
    hr_root(statement->input_root, (uint8_t)(tag + 4u));
    hr_root(statement->authorship_assertion_root, (uint8_t)(tag + 5u));
    hr_root(statement->license_root, (uint8_t)(tag + 6u));
    hr_root(statement->access_policy_root, (uint8_t)(tag + 7u));
    hr_root(statement->privacy_policy_root, (uint8_t)(tag + 8u));
    hr_root(statement->external_identifiers_root, (uint8_t)(tag + 9u));
    hr_root(statement->citations_root, (uint8_t)(tag + 10u));
    (void)vcs_zcode_science_relation_set_root(
        relations, statement->relations_root);
}

static void hr_study_task_heuristic(struct hr_fixture *f)
{
    memset(&f->study, 0, sizeof(f->study));
    f->study.schema_version = VCS_ZCODE_SCIENCE_VERSION;
    hr_root(f->study.hypothesis_root, 1);
    hr_root(f->study.null_hypothesis_root, 2);
    hr_root(f->study.source_root, 3);
    hr_root(f->study.dependency_lock_root, 4);
    hr_root(f->study.toolchain_capsule_root, 5);
    hr_root(f->study.protocol_root, 6);
    hr_root(f->study.workloads_root, 7);
    hr_root(f->study.metrics_root, 8);
    hr_root(f->study.estimator_tolerance_root, 9);
    hr_root(f->study.environment_policy_root, 10);
    hr_root(f->study.citations_root, 11);
    hr_root(f->study.preregistration_policy_root, 12);
    f->study.required_reproductions = 2;
    f->study.required_reviews = 1;
    f->study.sequence = 1;
    f->study.created_unix = 1000;
    f->study.expires_unix = 5000;
    (void)vcs_zcode_study_spec_root(&f->study, f->study_root);

    memset(&f->task, 0, sizeof(f->task));
    f->task.schema_version = VCS_ZCODE_DEV_VERSION;
    memcpy(f->task.source_root, f->study.source_root, 32);
    memcpy(f->task.dependency_lock_root, f->study.dependency_lock_root, 32);
    memcpy(f->task.toolchain_capsule_root,
           f->study.toolchain_capsule_root, 32);
    hr_root(f->task.write_scope_root, 20);
    hr_root(f->task.acceptance_tests_root, 21);
    hr_root(f->task.proof_policy_root, 22);
    hr_root(f->task.model_policy_root, 23);
    memcpy(f->task.goal_root, f->study_root, 32);
    f->task.capabilities = VCS_ZCODE_TASK_CAP_V1_MASK;
    f->task.max_changed_files = 8;
    f->task.max_patch_bytes = 65536;
    f->task.max_context_bytes = 65536;
    f->task.max_cpu_seconds = 60;
    f->task.max_memory_bytes = 16u * 1024u * 1024u;
    f->task.max_output_bytes = 1024u * 1024u;
    f->task.expires_unix = 5000;
    (void)vcs_zcode_task_root(&f->task, f->task_root);

    memset(&f->candidate, 0, sizeof(f->candidate));
    f->candidate.schema_version = VCS_ZCODE_DEV_VERSION;
    memcpy(f->candidate.task_root, f->task_root, 32);
    memcpy(f->candidate.base_source_root, f->task.source_root, 32);
    hr_root(f->candidate.patch_root, 24);
    hr_root(f->candidate.candidate_source_root, 25);
    hr_root(f->candidate.adapter_policy_root, 26);
    hr_root(f->candidate.author_pubkey, 27);
    f->candidate.sequence = 1;
    f->candidate.created_unix = 1100;
    (void)vcs_zcode_candidate_root(&f->candidate, f->candidate_root);

    const char *workdir = NULL, *output = NULL, *resource = NULL;
    memset(&f->action, 0, sizeof(f->action));
    hr_root(f->action.source_sha256, 40);
    hr_root(f->action.source_cas_sha3, 41);
    hr_root(f->action.input_root_sha3, 42);
    hr_root(f->action.toolchain_capsule_sha3, 43);
    (void)vcs_build_action_v1_fixed_flags_root_for_kind(
        VCS_BUILD_ACTION_KIND_BENCHMARK_V1, f->action.flags_sha3);
    (void)vcs_build_action_v1_fixed_environment_root_for_kind(
        VCS_BUILD_ACTION_KIND_BENCHMARK_V1, f->action.environment_sha3);
    (void)vcs_build_action_v1_descriptors(
        VCS_BUILD_ACTION_KIND_BENCHMARK_V1,
        &workdir, &output, &resource);
    (void)snprintf(f->action.target, sizeof(f->action.target), "%s",
                   VCS_BUILD_TARGET_V1);
    (void)snprintf(f->action.profile, sizeof(f->action.profile), "science");
    (void)snprintf(f->action.virtual_workdir,
                   sizeof(f->action.virtual_workdir), "%s", workdir);
    (void)snprintf(f->action.declared_outputs,
                   sizeof(f->action.declared_outputs), "%s", output);
    (void)snprintf(f->action.resource_policy,
                   sizeof(f->action.resource_policy), "%s", resource);
    f->action.sequence = 1;

    vcs_zcode_heuristic_init(&f->heuristic);
    f->heuristic.evaluator_count = 2;
    memcpy(f->heuristic.task_root, f->task_root, 32);
    memcpy(f->heuristic.source_root, f->study.source_root, 32);
    hr_root(f->heuristic.agent_context_root, 30);
    hr_root(f->heuristic.ontology_context_root, 31);
    hr_root(f->heuristic.applicability_root, 32);
    hr_root(f->heuristic.observed_features_root, 33);
    hr_root(f->heuristic.proposed_rule_root, 34);
    hr_root(f->heuristic.expected_effect_root, 35);
    hr_root(f->heuristic.proposal_input_root, 36);
    memcpy(f->heuristic.study_root, f->study_root, 32);
    memcpy(f->heuristic.preregistration_root,
           f->study.preregistration_policy_root, 32);
    hr_root(f->heuristic.provenance_root, 37);
    hr_root(f->heuristic.evaluator_roots[0], 38);
    hr_root(f->heuristic.evaluator_roots[1], 39);
    f->heuristic.requested_cpu_seconds = 30;
    f->heuristic.requested_processes = 1;
    f->heuristic.requested_memory_bytes = 1024u * 1024u;
    f->heuristic.requested_context_bytes = 4096;
    f->heuristic.requested_output_bytes = 4096;
    (void)vcs_zcode_heuristic_root(&f->heuristic, f->heuristic_root);
}

static void hr_result(struct vcs_zcode_benchmark_result_v1 *result,
                      const struct hr_fixture *f, uint8_t tag,
                      int64_t finished_unix)
{
    memset(result, 0, sizeof(*result));
    result->schema_version = VCS_ZCODE_SCIENCE_VERSION;
    memcpy(result->study_root, f->study_root, 32);
    memcpy(result->task_root, f->task_root, 32);
    memcpy(result->candidate_root, f->candidate_root, 32);
    (void)vcs_build_action_v1_root_for_kind(
        VCS_BUILD_ACTION_KIND_BENCHMARK_V1, &f->action,
        result->action_root);
    hr_root(result->achieved_environment_root, tag);
    hr_root(result->raw_sample_root, (uint8_t)(tag + 1u));
    hr_root(result->evidence_root, (uint8_t)(tag + 2u));
    result->status = VCS_ZCODE_BENCHMARK_OBSERVED;
    result->challenge_block_height = 1;
    hr_root(result->challenge_block_hash, 52);
    result->sequence = tag;
    result->started_unix = finished_unix - 10;
    result->finished_unix = finished_unix;
}

static bool hr_fixture_build(const char *workspace, struct hr_fixture *f)
{
    memset(f, 0, sizeof(*f));
    hr_study_task_heuristic(f);
    uint8_t seed[32];
    hr_root(seed, 80);
    ed25519_keypair(f->evaluator_pubkey, f->evaluator_secret, seed);
    for (size_t i = 0; i < 4; i++) {
        hr_root(seed, (uint8_t)(81u + i));
        ed25519_keypair(f->pubkey[i], f->secret[i], seed);
    }
    hr_result(&f->original, f, 60, 1300);
    if (!hr_store_study(workspace, &f->study, f->study_root) ||
        !hr_store_task(workspace, &f->task, f->task_root) ||
        !hr_store_candidate(workspace, &f->candidate, f->candidate_root) ||
        !hr_store_result(workspace, &f->original, f->original_root))
        return false;

    struct vcs_zcode_science_relation_set_v1 empty = {
        .schema_version = VCS_ZCODE_SCIENCE_RELATION_SET_VERSION,
    };
    hr_statement_base(&f->anchor, VCS_ZCODE_SCIENCE_PROFILE_RESULT,
                      f->heuristic_root, &empty, 90);
    memcpy(f->anchor.provenance_root, f->original_root, 32);
    f->anchor.observed_unix = f->original.finished_unix;
    if (vcs_zcode_science_statement_seal(
            &f->anchor, f->evaluator_secret, f->evaluator_pubkey) !=
            VCS_ZCODE_SCIENCE_OK ||
        !hr_store_statement(workspace, &f->anchor, &empty, f->anchor_root))
        return false;

    for (size_t i = 0; i < 4; i++) {
        hr_result(&f->reproduced[i], f, (uint8_t)(100u + i * 3u),
                  (int64_t)(1400u + i));
        if (!hr_store_result(workspace, &f->reproduced[i],
                             f->reproduced_root[i]))
            return false;
        struct vcs_zcode_reproduction_v1 *r = &f->reproduction[i];
        memset(r, 0, sizeof(*r));
        r->schema_version = VCS_ZCODE_SCIENCE_VERSION;
        memcpy(r->study_root, f->study_root, 32);
        memcpy(r->original_result_root, f->original_root, 32);
        memcpy(r->reproduced_result_root, f->reproduced_root[i], 32);
        hr_root(r->comparison_policy_root, (uint8_t)(120u + i));
        memcpy(r->original_environment_root,
               f->original.achieved_environment_root, 32);
        memcpy(r->reproduced_environment_root,
               f->reproduced[i].achieved_environment_root, 32);
        memcpy(r->reproducer_pubkey, f->pubkey[i], 32);
        r->verdict = i < 2 ? VCS_ZCODE_REPRODUCTION_REPLICATED :
            (i == 2 ? VCS_ZCODE_REPRODUCTION_INCONCLUSIVE :
                      VCS_ZCODE_REPRODUCTION_CONTRADICTED);
        r->sequence = i + 1u;
        r->created_unix = 1500 + (int64_t)i;
        if (!hr_store_reproduction(workspace, r, f->reproduction_root[i]))
            return false;

        struct vcs_zcode_science_relation_set_v1 support = {
            .schema_version = VCS_ZCODE_SCIENCE_RELATION_SET_VERSION,
            .row_count = 1,
            .rows = {{
                .type = VCS_ZCODE_SCIENCE_RELATION_SUPPORT,
            }},
        };
        memcpy(support.rows[0].statement_root, f->anchor_root, 32);
        hr_statement_base(&f->statement[i],
            VCS_ZCODE_SCIENCE_PROFILE_REPLICATION, f->heuristic_root,
            &support, (uint8_t)(130u + i * 11u));
        memcpy(f->statement[i].predicate_body_root,
               f->reproduction_root[i], 32);
        memcpy(f->statement[i].provenance_root, f->reproduced_root[i], 32);
        memcpy(f->statement[i].activity_root,
               r->comparison_policy_root, 32);
        memcpy(f->statement[i].input_root, f->original_root, 32);
        f->statement[i].observed_unix = r->created_unix;
        if (vcs_zcode_science_statement_seal(
                &f->statement[i], f->secret[i], f->pubkey[i]) !=
                VCS_ZCODE_SCIENCE_OK ||
            !hr_store_statement(workspace, &f->statement[i], &support,
                                f->statement_root[i]))
            return false;
    }
    return true;
}

static void hr_sort(uint8_t roots[][32], size_t count)
{
    for (size_t i = 1; i < count; i++) {
        uint8_t value[32];
        memcpy(value, roots[i], 32);
        size_t at = i;
        while (at != 0 && memcmp(roots[at - 1u], value, 32) > 0) {
            memcpy(roots[at], roots[at - 1u], 32);
            at--;
        }
        memcpy(roots[at], value, 32);
    }
}

static void hr_snapshot(
    struct vcs_zcode_heuristic_replication_snapshot_v1 *snapshot,
    const struct hr_fixture *f, const size_t rows[], size_t count)
{
    memset(snapshot, 0, sizeof(*snapshot));
    snapshot->schema_version =
        VCS_ZCODE_HEURISTIC_REPLICATION_SNAPSHOT_VERSION;
    snapshot->statement_count = (uint16_t)count;
    hr_root(snapshot->local_policy_root, 200);
    memcpy(snapshot->expected_evaluator_signer, f->evaluator_pubkey, 32);
    memcpy(snapshot->heuristic_root, f->heuristic_root, 32);
    memcpy(snapshot->anchor_statement_root, f->anchor_root, 32);
    for (size_t i = 0; i < count; i++)
        memcpy(snapshot->statement_roots[i], f->statement_root[rows[i]], 32);
    hr_sort(snapshot->statement_roots, count);
}

static bool hr_report_unchanged(
    const struct vcs_zcode_heuristic_replication_report *report,
    const struct vcs_zcode_heuristic_replication_report *sentinel)
{
    return memcmp(report, sentinel, sizeof(*report)) == 0;
}

int test_zcode_heuristic_replication(void)
{
    int failures = 0;
    char workspace[160];
    int n = snprintf(workspace, sizeof(workspace),
        "test-tmp/zcode_heuristic_replication_%d", (int)getpid());
    test_cleanup_tmpdir(workspace);
    bool setup = n > 0 && (size_t)n < sizeof(workspace) &&
        (mkdir("test-tmp", 0700) == 0 || access("test-tmp", F_OK) == 0) &&
        mkdir(workspace, 0700) == 0 && vcs_object_store_init(workspace);
    HR_CHECK("workspace-initializes", setup);
    if (!setup) return failures + 1;

    struct hr_fixture f;
    bool built = hr_fixture_build(workspace, &f);
    HR_CHECK("signed-science-fixture-builds", built);
    if (!built) {
        test_cleanup_tmpdir(workspace);
        return failures + 1;
    }

    struct vcs_zcode_heuristic_replication_snapshot_v1 snapshot;
    struct vcs_zcode_heuristic_replication_report report, sentinel;
    memset(&sentinel, 0x6d, sizeof(sentinel));
    hr_snapshot(&snapshot, &f, NULL, 0);
    HR_CHECK("empty-policy-set-is-complete-below-threshold",
        vcs_zcode_heuristic_replication_fold(
            workspace, &f.heuristic, &f.action, &snapshot, 6000, &report) ==
            VCS_ZCODE_ATTENTION_OK && report.complete && !report.qualified &&
        report.reason ==
            VCS_ZCODE_HEURISTIC_REPLICATION_REASON_BELOW_THRESHOLD &&
        report.required_reproductions == 2 && report.validated_count == 0);

    const size_t one[] = {0};
    hr_snapshot(&snapshot, &f, one, 1);
    HR_CHECK("threshold-minus-one-remains-undetermined",
        vcs_zcode_heuristic_replication_fold(
            workspace, &f.heuristic, &f.action, &snapshot, 6000, &report) ==
            VCS_ZCODE_ATTENTION_OK && !report.qualified &&
        report.replicated_count == 1 &&
        report.reason ==
            VCS_ZCODE_HEURISTIC_REPLICATION_REASON_BELOW_THRESHOLD);

    const size_t exact[] = {0, 1};
    hr_snapshot(&snapshot, &f, exact, 2);
    HR_CHECK("exact-distinct-signer-threshold-qualifies-after-expiry",
        vcs_zcode_heuristic_replication_fold(
            workspace, &f.heuristic, &f.action, &snapshot, 6000, &report) ==
            VCS_ZCODE_ATTENTION_OK && report.qualified &&
        report.replicated_count == 2 &&
        report.reason == VCS_ZCODE_HEURISTIC_REPLICATION_REASON_NONE &&
        memcmp(report.study_root, f.study_root, 32) == 0 &&
        memcmp(report.original_result_root, f.original_root, 32) == 0);

    const size_t inconclusive[] = {0, 2};
    hr_snapshot(&snapshot, &f, inconclusive, 2);
    HR_CHECK("inconclusive-is-valid-but-does-not-count",
        vcs_zcode_heuristic_replication_fold(
            workspace, &f.heuristic, &f.action, &snapshot, 6000, &report) ==
            VCS_ZCODE_ATTENTION_OK && !report.qualified &&
        report.replicated_count == 1 && report.inconclusive_count == 1 &&
        report.reason ==
            VCS_ZCODE_HEURISTIC_REPLICATION_REASON_INCONCLUSIVE);

    const size_t contradicted[] = {0, 1, 3};
    hr_snapshot(&snapshot, &f, contradicted, 3);
    HR_CHECK("contradiction-blocks-without-synthetic-retirement",
        vcs_zcode_heuristic_replication_fold(
            workspace, &f.heuristic, &f.action, &snapshot, 6000, &report) ==
            VCS_ZCODE_ATTENTION_OK && !report.qualified &&
        report.replicated_count == 2 && report.contradicted_count == 1 &&
        report.reason ==
            VCS_ZCODE_HEURISTIC_REPLICATION_REASON_CONTRADICTED);

    hr_snapshot(&snapshot, &f, exact, 2);
    memcpy(snapshot.statement_roots[1], snapshot.statement_roots[0], 32);
    report = sentinel;
    HR_CHECK("duplicate-accepted-root-refuses-atomically",
        vcs_zcode_heuristic_replication_fold(
            workspace, &f.heuristic, &f.action, &snapshot, 6000, &report) ==
            VCS_ZCODE_ATTENTION_ORDER && hr_report_unchanged(&report, &sentinel));

    hr_snapshot(&snapshot, &f, exact, 2);
    snapshot.statement_roots[2][0] = 1;
    report = sentinel;
    HR_CHECK("inactive-root-and-output-alias-refuse",
        vcs_zcode_heuristic_replication_fold(
            workspace, &f.heuristic, &f.action, &snapshot, 6000, &report) ==
            VCS_ZCODE_ATTENTION_ROOT && hr_report_unchanged(&report, &sentinel) &&
        vcs_zcode_heuristic_replication_fold(
            workspace, &f.heuristic, &f.action, &snapshot, 6000,
            (struct vcs_zcode_heuristic_replication_report *)&snapshot) ==
            VCS_ZCODE_ATTENTION_ALIAS);

    hr_snapshot(&snapshot, &f, exact, 2);
    uint8_t missing[32];
    hr_root(missing, 250);
    memcpy(snapshot.statement_roots[0], missing, 32);
    hr_sort(snapshot.statement_roots, 2);
    report = sentinel;
    HR_CHECK("missing-policy-accepted-evidence-poisons-fold",
        vcs_zcode_heuristic_replication_fold(
            workspace, &f.heuristic, &f.action, &snapshot, 6000, &report) ==
            VCS_ZCODE_ATTENTION_EVIDENCE &&
        hr_report_unchanged(&report, &sentinel));

    struct hr_fixture duplicate_signer = f;
    duplicate_signer.statement[1] = f.statement[1];
    memcpy(duplicate_signer.reproduction[1].reproducer_pubkey,
           f.pubkey[0], 32);
    bool replay_built = hr_store_reproduction(
        workspace, &duplicate_signer.reproduction[1],
        duplicate_signer.reproduction_root[1]);
    memcpy(duplicate_signer.statement[1].predicate_body_root,
           duplicate_signer.reproduction_root[1], 32);
    memcpy(duplicate_signer.statement[1].signer_pubkey, f.pubkey[0], 32);
    memset(duplicate_signer.statement[1].signature, 0, 64);
    replay_built = replay_built &&
        vcs_zcode_science_statement_seal(
            &duplicate_signer.statement[1], f.secret[0], f.pubkey[0]) ==
            VCS_ZCODE_SCIENCE_OK;
    struct vcs_zcode_science_relation_set_v1 support = {
        .schema_version = VCS_ZCODE_SCIENCE_RELATION_SET_VERSION,
        .row_count = 1,
        .rows = {{.type = VCS_ZCODE_SCIENCE_RELATION_SUPPORT}},
    };
    memcpy(support.rows[0].statement_root, f.anchor_root, 32);
    replay_built = replay_built && hr_store_statement(
        workspace, &duplicate_signer.statement[1], &support,
        duplicate_signer.statement_root[1]);
    HR_CHECK("duplicate-signer-fixture-builds", replay_built);
    hr_snapshot(&snapshot, &duplicate_signer, exact, 2);
    report = sentinel;
    HR_CHECK("same-signer-cannot-satisfy-independence",
        vcs_zcode_heuristic_replication_fold(
            workspace, &f.heuristic, &f.action, &snapshot, 6000, &report) ==
            VCS_ZCODE_ATTENTION_EVIDENCE &&
        hr_report_unchanged(&report, &sentinel));

    struct hr_fixture self_signed = f;
    self_signed.statement[0] = f.statement[0];
    memcpy(self_signed.reproduction[0].reproducer_pubkey,
           f.evaluator_pubkey, 32);
    bool self_built = hr_store_reproduction(
        workspace, &self_signed.reproduction[0],
        self_signed.reproduction_root[0]);
    memcpy(self_signed.statement[0].predicate_body_root,
           self_signed.reproduction_root[0], 32);
    memcpy(self_signed.statement[0].signer_pubkey, f.evaluator_pubkey, 32);
    memset(self_signed.statement[0].signature, 0, 64);
    self_built = self_built && vcs_zcode_science_statement_seal(
        &self_signed.statement[0], f.evaluator_secret, f.evaluator_pubkey) ==
        VCS_ZCODE_SCIENCE_OK && hr_store_statement(
            workspace, &self_signed.statement[0], &support,
            self_signed.statement_root[0]);
    HR_CHECK("evaluator-reproduction-fixture-builds", self_built);
    hr_snapshot(&snapshot, &self_signed, one, 1);
    report = sentinel;
    HR_CHECK("evaluator-cannot-reproduce-own-result",
        vcs_zcode_heuristic_replication_fold(
            workspace, &f.heuristic, &f.action, &snapshot, 6000, &report) ==
            VCS_ZCODE_ATTENTION_EVIDENCE &&
        hr_report_unchanged(&report, &sentinel));

    struct hr_fixture mismatched_key = f;
    mismatched_key.statement[0] = f.statement[0];
    memcpy(mismatched_key.reproduction[0].reproducer_pubkey,
           f.pubkey[1], 32);
    bool mismatch_built = hr_store_reproduction(
        workspace, &mismatched_key.reproduction[0],
        mismatched_key.reproduction_root[0]);
    memcpy(mismatched_key.statement[0].predicate_body_root,
           mismatched_key.reproduction_root[0], 32);
    memset(mismatched_key.statement[0].signature, 0, 64);
    mismatch_built = mismatch_built && vcs_zcode_science_statement_seal(
        &mismatched_key.statement[0], f.secret[0], f.pubkey[0]) ==
        VCS_ZCODE_SCIENCE_OK && hr_store_statement(
            workspace, &mismatched_key.statement[0], &support,
            mismatched_key.statement_root[0]);
    HR_CHECK("declared-key-mismatch-fixture-builds", mismatch_built);
    hr_snapshot(&snapshot, &mismatched_key, one, 1);
    report = sentinel;
    HR_CHECK("signed-envelope-authenticates-declared-reproducer",
        vcs_zcode_heuristic_replication_fold(
            workspace, &f.heuristic, &f.action, &snapshot, 6000, &report) ==
            VCS_ZCODE_ATTENTION_EVIDENCE &&
        hr_report_unchanged(&report, &sentinel));

    struct hr_fixture replayed_result = f;
    replayed_result.statement[1] = f.statement[1];
    memcpy(replayed_result.reproduction[1].reproduced_result_root,
           f.reproduced_root[0], 32);
    memcpy(replayed_result.reproduction[1].reproduced_environment_root,
           f.reproduced[0].achieved_environment_root, 32);
    bool result_replay_built = hr_store_reproduction(
        workspace, &replayed_result.reproduction[1],
        replayed_result.reproduction_root[1]);
    memcpy(replayed_result.statement[1].predicate_body_root,
           replayed_result.reproduction_root[1], 32);
    memcpy(replayed_result.statement[1].provenance_root,
           f.reproduced_root[0], 32);
    memset(replayed_result.statement[1].signature, 0, 64);
    result_replay_built = result_replay_built &&
        vcs_zcode_science_statement_seal(
            &replayed_result.statement[1], f.secret[1], f.pubkey[1]) ==
            VCS_ZCODE_SCIENCE_OK && hr_store_statement(
                workspace, &replayed_result.statement[1], &support,
                replayed_result.statement_root[1]);
    HR_CHECK("replayed-result-fixture-builds", result_replay_built);
    hr_snapshot(&snapshot, &replayed_result, exact, 2);
    report = sentinel;
    HR_CHECK("one-result-cannot-be-counted-by-two-signers",
        vcs_zcode_heuristic_replication_fold(
            workspace, &f.heuristic, &f.action, &snapshot, 6000, &report) ==
            VCS_ZCODE_ATTENTION_EVIDENCE &&
        hr_report_unchanged(&report, &sentinel));

    struct hr_fixture pre_study = f;
    pre_study.original.started_unix = 900;
    bool pre_study_built = hr_store_result(
        workspace, &pre_study.original, pre_study.original_root);
    struct vcs_zcode_science_relation_set_v1 empty = {
        .schema_version = VCS_ZCODE_SCIENCE_RELATION_SET_VERSION,
    };
    pre_study.anchor = f.anchor;
    memcpy(pre_study.anchor.provenance_root, pre_study.original_root, 32);
    memset(pre_study.anchor.signature, 0, 64);
    pre_study_built = pre_study_built &&
        vcs_zcode_science_statement_seal(
            &pre_study.anchor, f.evaluator_secret, f.evaluator_pubkey) ==
            VCS_ZCODE_SCIENCE_OK && hr_store_statement(
                workspace, &pre_study.anchor, &empty, pre_study.anchor_root);
    HR_CHECK("pre-study-result-fixture-builds", pre_study_built);
    hr_snapshot(&snapshot, &pre_study, NULL, 0);
    report = sentinel;
    HR_CHECK("pre-study-benchmark-cannot-qualify",
        vcs_zcode_heuristic_replication_fold(
            workspace, &f.heuristic, &f.action, &snapshot, 6000, &report) ==
            VCS_ZCODE_ATTENTION_EVIDENCE &&
        hr_report_unchanged(&report, &sentinel));

    struct vcs_build_action_v1 noncanonical_action = f.action;
    noncanonical_action.flags_sha3[0] ^= 1u;
    hr_snapshot(&snapshot, &f, NULL, 0);
    report = sentinel;
    HR_CHECK("noncanonical-action-cannot-qualify",
        vcs_zcode_heuristic_replication_fold(
            workspace, &f.heuristic, &noncanonical_action,
            &snapshot, 6000, &report) == VCS_ZCODE_ATTENTION_EVIDENCE &&
        hr_report_unchanged(&report, &sentinel));

    hr_snapshot(&snapshot, &f, one, 1);
    report = sentinel;
    HR_CHECK("future-cutoff-refuses-atomically",
        vcs_zcode_heuristic_replication_fold(
            workspace, &f.heuristic, &f.action, &snapshot, 1499, &report) ==
            VCS_ZCODE_ATTENTION_EVIDENCE &&
        hr_report_unchanged(&report, &sentinel));

    test_cleanup_tmpdir(workspace);
    return failures;
}
