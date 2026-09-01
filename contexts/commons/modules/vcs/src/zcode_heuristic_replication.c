/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: bounded signed-replication projection for heuristic evidence. */
#include "vcs/zcode_heuristic_replication.h"

#include "base/serialize_le.h"
#include "crypto/sha3.h"
#include "vcs/vcs_object.h"
#include "vcs/zcode_science.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static bool hr_root_nonzero(const uint8_t root[32])
{
    uint8_t any = 0;
    for (size_t i = 0; i < 32u; i++) any |= root[i];
    return any != 0;
}

static bool hr_overlaps(const void *a, size_t an, const void *b, size_t bn)
{
    uintptr_t x = (uintptr_t)a, y = (uintptr_t)b;
    if (x > UINTPTR_MAX - an || y > UINTPTR_MAX - bn) return true;
    return x < y + bn && y < x + an;
}

static enum vcs_zcode_attention_error hr_snapshot_validate(
    const struct vcs_zcode_heuristic_replication_snapshot_v1 *snapshot)
{
    if (!snapshot) return VCS_ZCODE_ATTENTION_NULL;
    if (snapshot->schema_version !=
        VCS_ZCODE_HEURISTIC_REPLICATION_SNAPSHOT_VERSION)
        return VCS_ZCODE_ATTENTION_VERSION;
    if (snapshot->statement_count >
        VCS_ZCODE_HEURISTIC_REPLICATION_MAX_STATEMENTS)
        return VCS_ZCODE_ATTENTION_COUNT;
    if (!hr_root_nonzero(snapshot->local_policy_root) ||
        !hr_root_nonzero(snapshot->expected_evaluator_signer) ||
        !hr_root_nonzero(snapshot->heuristic_root) ||
        !hr_root_nonzero(snapshot->anchor_statement_root))
        return VCS_ZCODE_ATTENTION_ROOT;
    for (size_t i = 0;
         i < VCS_ZCODE_HEURISTIC_REPLICATION_MAX_STATEMENTS; i++) {
        bool active = i < snapshot->statement_count;
        if (active != hr_root_nonzero(snapshot->statement_roots[i]))
            return VCS_ZCODE_ATTENTION_ROOT;
        if (active && i != 0 &&
            memcmp(snapshot->statement_roots[i - 1u],
                   snapshot->statement_roots[i], 32) >= 0)
            return VCS_ZCODE_ATTENTION_ORDER;
    }
    return VCS_ZCODE_ATTENTION_OK;
}

static void hr_snapshot_root(
    const struct vcs_zcode_heuristic_replication_snapshot_v1 *snapshot,
    uint8_t out[32])
{
    static const char domain[] =
        VCS_ZCODE_HEURISTIC_REPLICATION_SNAPSHOT_DOMAIN;
    uint8_t count[2];
    zcl_write_u16_le(count, snapshot->statement_count);
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)domain, sizeof(domain));
    sha3_256_write(&sha, snapshot->local_policy_root, 32);
    sha3_256_write(&sha, snapshot->expected_evaluator_signer, 32);
    sha3_256_write(&sha, snapshot->heuristic_root, 32);
    sha3_256_write(&sha, snapshot->anchor_statement_root, 32);
    sha3_256_write(&sha, count, sizeof(count));
    for (size_t i = 0; i < snapshot->statement_count; i++)
        sha3_256_write(&sha, snapshot->statement_roots[i], 32);
    sha3_256_finalize(&sha, out);
}

static bool hr_load(const char *workspace, const uint8_t root[32],
                    size_t maximum, uint8_t **wire, size_t *wire_len)
{
    *wire = NULL;
    *wire_len = 0;
    return vcs_object_load_raw_bounded(
        workspace, root, maximum, wire, wire_len) == 0;
}

#define HR_LOADER(name_, type_, bytes_, parse_, root_)                       \
static bool name_(const char *workspace, const uint8_t expected[32],          \
                  struct type_ *out)                                         \
{                                                                            \
    uint8_t *wire = NULL, checked[32];                                        \
    size_t wire_len = 0;                                                      \
    bool ok = hr_load(workspace, expected, bytes_, &wire, &wire_len) &&       \
        wire_len == bytes_ &&                                                 \
        parse_(wire, wire_len, out) == 0 &&                                   \
        root_(out, checked) == 0 && memcmp(checked, expected, 32) == 0;       \
    free(wire);                                                               \
    if (!ok) memset(out, 0, sizeof(*out));                                    \
    return ok;                                                                \
}

HR_LOADER(hr_study_load, vcs_zcode_study_spec_v1,
          VCS_ZCODE_STUDY_SPEC_WIRE_BYTES, vcs_zcode_study_spec_parse,
          vcs_zcode_study_spec_root)
HR_LOADER(hr_task_load, vcs_zcode_task_v1, VCS_ZCODE_TASK_WIRE_BYTES,
          vcs_zcode_task_parse, vcs_zcode_task_root)
HR_LOADER(hr_candidate_load, vcs_zcode_candidate_v1,
          VCS_ZCODE_CANDIDATE_WIRE_BYTES, vcs_zcode_candidate_parse,
          vcs_zcode_candidate_root)
HR_LOADER(hr_result_load, vcs_zcode_benchmark_result_v1,
          VCS_ZCODE_BENCHMARK_RESULT_WIRE_BYTES,
          vcs_zcode_benchmark_result_parse, vcs_zcode_benchmark_result_root)
HR_LOADER(hr_reproduction_load, vcs_zcode_reproduction_v1,
          VCS_ZCODE_REPRODUCTION_WIRE_BYTES, vcs_zcode_reproduction_parse,
          vcs_zcode_reproduction_root)

static bool hr_statement_load(
    const char *workspace, const uint8_t expected[32],
    struct vcs_zcode_science_statement_v1 *out)
{
    uint8_t *wire = NULL, checked[32];
    size_t wire_len = 0;
    bool ok = hr_load(workspace, expected,
            VCS_ZCODE_SCIENCE_STATEMENT_WIRE_BYTES, &wire, &wire_len) &&
        wire_len == VCS_ZCODE_SCIENCE_STATEMENT_WIRE_BYTES &&
        vcs_zcode_science_statement_parse(wire, wire_len, out) ==
            VCS_ZCODE_SCIENCE_OK &&
        vcs_zcode_science_statement_root(out, checked) ==
            VCS_ZCODE_SCIENCE_OK &&
        memcmp(checked, expected, 32) == 0 &&
        vcs_zcode_science_statement_verify(out, out->signer_pubkey) ==
            VCS_ZCODE_SCIENCE_OK;
    free(wire);
    if (!ok) memset(out, 0, sizeof(*out));
    return ok;
}

static bool hr_relations_load(
    const char *workspace,
    const struct vcs_zcode_science_statement_v1 *statement,
    struct vcs_zcode_science_relation_set_v1 *out)
{
    uint8_t *wire = NULL, checked[32];
    size_t wire_len = 0;
    bool ok = hr_load(workspace, statement->relations_root,
            VCS_ZCODE_SCIENCE_RELATION_SET_MAX_WIRE_BYTES,
            &wire, &wire_len) &&
        vcs_zcode_science_relation_set_parse(wire, wire_len, out) ==
            VCS_ZCODE_SCIENCE_OK &&
        vcs_zcode_science_relation_set_root(out, checked) ==
            VCS_ZCODE_SCIENCE_OK &&
        memcmp(checked, statement->relations_root, 32) == 0 &&
        vcs_zcode_science_statement_validate_relations(statement, out) ==
            VCS_ZCODE_SCIENCE_OK;
    free(wire);
    if (!ok) memset(out, 0, sizeof(*out));
    return ok;
}

static bool hr_base_bindings(
    const struct vcs_zcode_heuristic_v1 *heuristic,
    const struct vcs_zcode_study_spec_v1 *study,
    const struct vcs_zcode_task_v1 *task,
    const struct vcs_zcode_benchmark_result_v1 *original,
    const uint8_t study_root[32], const uint8_t task_root[32])
{
    return memcmp(original->study_root, study_root, 32) == 0 &&
        memcmp(original->task_root, task_root, 32) == 0 &&
        memcmp(task->goal_root, study_root, 32) == 0 &&
        memcmp(study->source_root, task->source_root, 32) == 0 &&
        memcmp(study->source_root, heuristic->source_root, 32) == 0 &&
        memcmp(study->dependency_lock_root,
               task->dependency_lock_root, 32) == 0 &&
        memcmp(study->toolchain_capsule_root,
               task->toolchain_capsule_root, 32) == 0 &&
        memcmp(study->preregistration_policy_root,
               heuristic->preregistration_root, 32) == 0;
}

static bool hr_seen(const uint8_t roots[][32], size_t count,
                    const uint8_t root[32])
{
    for (size_t i = 0; i < count; i++)
        if (memcmp(roots[i], root, 32) == 0) return true;
    return false;
}

static bool hr_replication_row(
    const char *workspace, const uint8_t statement_root[32],
    const uint8_t heuristic_root[32], const uint8_t anchor_root[32],
    const uint8_t evaluator[32], const uint8_t study_root[32],
    const uint8_t original_root[32],
    const struct vcs_zcode_study_spec_v1 *study,
    const struct vcs_zcode_task_v1 *task,
    const struct vcs_zcode_candidate_v1 *candidate,
    const struct vcs_build_action_v1 *action,
    const struct vcs_zcode_benchmark_result_v1 *original,
    int64_t now_unix, uint8_t signers[][32],
    uint8_t reproduction_roots[][32], uint8_t result_roots[][32], size_t used,
    uint8_t *verdict)
{
    struct vcs_zcode_science_statement_v1 statement;
    struct vcs_zcode_science_relation_set_v1 relations;
    struct vcs_zcode_reproduction_v1 reproduction;
    struct vcs_zcode_benchmark_result_v1 reproduced;
    if (!hr_statement_load(workspace, statement_root, &statement) ||
        !hr_relations_load(workspace, &statement, &relations) ||
        statement.profile != VCS_ZCODE_SCIENCE_PROFILE_REPLICATION ||
        statement.relation_count != 1 || relations.row_count != 1 ||
        relations.rows[0].type != VCS_ZCODE_SCIENCE_RELATION_SUPPORT ||
        memcmp(relations.rows[0].statement_root, anchor_root, 32) != 0 ||
        memcmp(statement.subject_root, heuristic_root, 32) != 0 ||
        memcmp(statement.input_root, original_root, 32) != 0 ||
        memcmp(statement.signer_pubkey, evaluator, 32) == 0 ||
        hr_seen(signers, used, statement.signer_pubkey) ||
        hr_seen(reproduction_roots, used, statement.predicate_body_root) ||
        hr_seen(result_roots, used, statement.provenance_root) ||
        !hr_reproduction_load(workspace, statement.predicate_body_root,
                              &reproduction) ||
        !hr_result_load(workspace, statement.provenance_root, &reproduced) ||
        memcmp(reproduction.reproducer_pubkey,
               statement.signer_pubkey, 32) != 0 ||
        memcmp(reproduction.study_root, study_root, 32) != 0 ||
        memcmp(reproduction.original_result_root, original_root, 32) != 0 ||
        memcmp(reproduction.reproduced_result_root,
               statement.provenance_root, 32) != 0 ||
        memcmp(reproduction.comparison_policy_root,
               statement.activity_root, 32) != 0 ||
        reproduction.created_unix != statement.observed_unix ||
        vcs_zcode_benchmark_result_validate_for_study(
            study, task, candidate, action, &reproduced, now_unix) !=
                VCS_ZCODE_SCIENCE_OK ||
        vcs_zcode_reproduction_validate_for_results(
            study, original, &reproduced, &reproduction, now_unix) !=
                VCS_ZCODE_SCIENCE_OK)
        return false;
    memcpy(signers[used], statement.signer_pubkey, 32);
    memcpy(reproduction_roots[used], statement.predicate_body_root, 32);
    memcpy(result_roots[used], statement.provenance_root, 32);
    *verdict = reproduction.verdict;
    return true;
}

enum vcs_zcode_attention_error vcs_zcode_heuristic_replication_fold(
    const char *workspace, const struct vcs_zcode_heuristic_v1 *heuristic,
    const struct vcs_build_action_v1 *action,
    const struct vcs_zcode_heuristic_replication_snapshot_v1 *snapshot,
    int64_t now_unix, struct vcs_zcode_heuristic_replication_report *report)
{
    if (!workspace || !heuristic || !action || !snapshot || !report)
        return VCS_ZCODE_ATTENTION_NULL;
    size_t workspace_bytes = strlen(workspace) + 1u;
    if (hr_overlaps(report, sizeof(*report), workspace, workspace_bytes) ||
        hr_overlaps(report, sizeof(*report), heuristic, sizeof(*heuristic)) ||
        hr_overlaps(report, sizeof(*report), action, sizeof(*action)) ||
        hr_overlaps(report, sizeof(*report), snapshot, sizeof(*snapshot)))
        return VCS_ZCODE_ATTENTION_ALIAS;
    enum vcs_zcode_attention_error error = hr_snapshot_validate(snapshot);
    if (error != VCS_ZCODE_ATTENTION_OK) return error;
    if (now_unix <= 0 ||
        vcs_zcode_heuristic_validate(heuristic) != VCS_ZCODE_ATTENTION_OK)
        return VCS_ZCODE_ATTENTION_EVIDENCE;

    uint8_t heuristic_root[32];
    if (vcs_zcode_heuristic_root(heuristic, heuristic_root) !=
            VCS_ZCODE_ATTENTION_OK ||
        memcmp(heuristic_root, snapshot->heuristic_root, 32) != 0)
        return VCS_ZCODE_ATTENTION_BINDING;

    struct vcs_zcode_science_statement_v1 anchor;
    struct vcs_zcode_science_relation_set_v1 anchor_relations;
    struct vcs_zcode_study_spec_v1 study;
    struct vcs_zcode_task_v1 task;
    struct vcs_zcode_candidate_v1 candidate;
    struct vcs_zcode_benchmark_result_v1 original;
    if (!hr_statement_load(workspace, snapshot->anchor_statement_root,
                           &anchor) ||
        memcmp(anchor.signer_pubkey,
               snapshot->expected_evaluator_signer, 32) != 0 ||
        anchor.profile != VCS_ZCODE_SCIENCE_PROFILE_RESULT ||
        memcmp(anchor.subject_root, heuristic_root, 32) != 0 ||
        !hr_relations_load(workspace, &anchor, &anchor_relations) ||
        anchor_relations.row_count != 0 ||
        !hr_study_load(workspace, heuristic->study_root, &study) ||
        !hr_task_load(workspace, heuristic->task_root, &task) ||
        !hr_result_load(workspace, anchor.provenance_root, &original) ||
        !hr_candidate_load(workspace, original.candidate_root, &candidate) ||
        !hr_base_bindings(heuristic, &study, &task, &original,
                          heuristic->study_root, heuristic->task_root) ||
        vcs_zcode_benchmark_result_validate_for_study(
            &study, &task, &candidate, action, &original, now_unix) !=
                VCS_ZCODE_SCIENCE_OK)
        return VCS_ZCODE_ATTENTION_EVIDENCE;

    struct vcs_zcode_heuristic_replication_report result = {0};
    result.complete = true;
    result.required_reproductions = study.required_reproductions;
    memcpy(result.study_root, heuristic->study_root, 32);
    memcpy(result.original_result_root, anchor.provenance_root, 32);
    hr_snapshot_root(snapshot, result.snapshot_root);

    uint8_t signers[VCS_ZCODE_HEURISTIC_REPLICATION_MAX_STATEMENTS][32] = {{0}};
    uint8_t reproduction_roots
        [VCS_ZCODE_HEURISTIC_REPLICATION_MAX_STATEMENTS][32] = {{0}};
    uint8_t result_roots
        [VCS_ZCODE_HEURISTIC_REPLICATION_MAX_STATEMENTS][32] = {{0}};
    for (size_t i = 0; i < snapshot->statement_count; i++) {
        uint8_t verdict = 0;
        if (!hr_replication_row(
                workspace, snapshot->statement_roots[i], heuristic_root,
                snapshot->anchor_statement_root,
                snapshot->expected_evaluator_signer, heuristic->study_root,
                anchor.provenance_root, &study, &task, &candidate, action,
                &original, now_unix, signers, reproduction_roots,
                result_roots, i, &verdict))
            return VCS_ZCODE_ATTENTION_EVIDENCE;
        result.validated_count++;
        if (verdict == VCS_ZCODE_REPRODUCTION_REPLICATED)
            result.replicated_count++;
        else if (verdict == VCS_ZCODE_REPRODUCTION_CONTRADICTED)
            result.contradicted_count++;
        else if (verdict == VCS_ZCODE_REPRODUCTION_INCONCLUSIVE)
            result.inconclusive_count++;
        else
            return VCS_ZCODE_ATTENTION_EVIDENCE;
    }
    if (result.contradicted_count != 0)
        result.reason = VCS_ZCODE_HEURISTIC_REPLICATION_REASON_CONTRADICTED;
    else if (result.replicated_count >= result.required_reproductions) {
        result.qualified = true;
        result.reason = VCS_ZCODE_HEURISTIC_REPLICATION_REASON_NONE;
    } else if (result.inconclusive_count != 0)
        result.reason = VCS_ZCODE_HEURISTIC_REPLICATION_REASON_INCONCLUSIVE;
    else
        result.reason =
            VCS_ZCODE_HEURISTIC_REPLICATION_REASON_BELOW_THRESHOLD;
    *report = result;
    return VCS_ZCODE_ATTENTION_OK;
}
