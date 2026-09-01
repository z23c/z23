/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_zcode_science_store — the CAS storage + rebuildable projection +
 * plan/commit service slice (S3) of the ZCODE Scientific Metaverse.
 *
 * Proofs:
 *   1. study plan → confirm:true commit; idempotent re-plan and re-commit
 *      (same roots, one CAS object); commit without confirm refused.
 *   2. projection rebuild equivalence: drop + rebuild from CAS reproduces
 *      the identical show/list output.
 *   3. expiry gates NEW submissions only: expired plans and closed study
 *      windows reject commits, while stored evidence revalidates (index,
 *      receipt) after the window closes.
 *   4. malformed / trailing / misplaced CAS objects never enter the
 *      projection.
 *   5. null and negative benchmark results commit as observations.
 *   6. contradictory reproductions are both storable.
 *   7. stale reviews (predating their findings) are rejected; fresh
 *      reviews commit.
 *   8. retractions are observations: a RETRACTION findings marks its
 *      target in the rebuilt projection, erasing nothing.
 *   9. curation votes: cross-network identity rejection, voter+sequence
 *      replay rejection, idempotent re-submit by vote id.
 *
 * Services run in-process on ./test-tmp workspaces and node.db files; the
 * canonical wires are built with the S1 codecs (test_zcode_science.c
 * fixture patterns). */

#include "test/test_core.h"

#include "base/hex.h"
#include "crypto/ed25519.h"
#include "models/database.h"
#include "services/zcode_science_service.h"
#include "vcs/blob_store.h"
#include "vcs/build_action.h"
#include "vcs/package_store.h"
#include "vcs/vcs_object.h"
#include "vcs/zcode_dev.h"
#include "vcs/zcode_dht.h"
#include "vcs/zcode_science.h"
#include "vcs/zcode_science_index.h"

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define ZSTORE_DIR_CAP 512

static int g_zstore_seq;

static void zstore_root(uint8_t out[32], uint8_t value)
{
    memset(out, value, 32);
}

static bool zstore_setup(struct node_db *ndb, char *dir, size_t cap)
{
    int n = snprintf(dir, cap, "test-tmp/zcode_science_store_%d_%d",
                     (int)getpid(), g_zstore_seq++);
    if (n <= 0 || (size_t)n >= cap)
        return false;
    char cmd[ZSTORE_DIR_CAP * 2 + 32];
    n = snprintf(cmd, sizeof(cmd), "rm -rf '%s' && mkdir -p '%s'", dir, dir);
    if (n <= 0 || (size_t)n >= sizeof(cmd) || system(cmd) != 0)
        return false;
    char db[ZSTORE_DIR_CAP + 16];
    n = snprintf(db, sizeof(db), "%s/node.db", dir);
    return n > 0 && (size_t)n < sizeof(db) && node_db_open(ndb, db) &&
           vcs_object_store_init(dir);
}

static void zstore_teardown(struct node_db *ndb, const char *dir)
{
    node_db_close(ndb);
    char cmd[ZSTORE_DIR_CAP + 16];
    int n = snprintf(cmd, sizeof(cmd), "rm -rf '%s'", dir);
    if (n > 0 && (size_t)n < sizeof(cmd))
        (void)system(cmd);
}

/* Count files under <dir>/.zvcs/objects/<shard>/. */
static int zstore_cas_object_count(const char *workspace)
{
    char objects[ZSTORE_DIR_CAP + 24];
    int n = snprintf(objects, sizeof(objects), "%s/.zvcs/objects", workspace);
    if (n <= 0 || (size_t)n >= sizeof(objects))
        return -1;
    DIR *d = opendir(objects);
    if (!d)
        return 0;
    int count = 0;
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (strlen(de->d_name) != 2)
            continue;
        char shard[ZSTORE_DIR_CAP + 32];
        n = snprintf(shard, sizeof(shard), "%s/%s", objects, de->d_name);
        if (n <= 0 || (size_t)n >= sizeof(shard))
            continue;
        DIR *sd = opendir(shard);
        if (!sd)
            continue;
        struct dirent *se;
        while ((se = readdir(sd)) != NULL)
            if (strlen(se->d_name) == 62)
                count++;
        closedir(sd);
    }
    closedir(d);
    return count;
}

/* ── fixtures (test_zcode_science.c patterns) ────────────────────── */

static void zstore_study(struct vcs_zcode_study_spec_v1 *study)
{
    memset(study, 0, sizeof(*study));
    study->schema_version = VCS_ZCODE_SCIENCE_VERSION;
    zstore_root(study->hypothesis_root, 1);
    zstore_root(study->null_hypothesis_root, 2);
    zstore_root(study->source_root, 3);
    zstore_root(study->dependency_lock_root, 4);
    zstore_root(study->toolchain_capsule_root, 5);
    zstore_root(study->protocol_root, 6);
    zstore_root(study->workloads_root, 7);
    zstore_root(study->metrics_root, 8);
    zstore_root(study->estimator_tolerance_root, 9);
    zstore_root(study->environment_policy_root, 10);
    zstore_root(study->citations_root, 11);
    zstore_root(study->preregistration_policy_root, 12);
    study->required_reproductions = 2;
    study->required_reviews = 3;
    study->sequence = 17;
    study->created_unix = 1000;
    study->expires_unix = 5000;
}

static void zstore_task_candidate(
    const struct vcs_zcode_study_spec_v1 *study,
    struct vcs_zcode_task_v1 *task, struct vcs_zcode_candidate_v1 *candidate,
    uint8_t task_root[32], uint8_t candidate_root[32])
{
    uint8_t study_root[32];
    (void)vcs_zcode_study_spec_root(study, study_root);
    memset(task, 0, sizeof(*task));
    task->schema_version = VCS_ZCODE_DEV_VERSION;
    memcpy(task->source_root, study->source_root, 32);
    memcpy(task->dependency_lock_root, study->dependency_lock_root, 32);
    memcpy(task->toolchain_capsule_root, study->toolchain_capsule_root, 32);
    zstore_root(task->write_scope_root, 20);
    zstore_root(task->acceptance_tests_root, 21);
    zstore_root(task->proof_policy_root, 22);
    zstore_root(task->model_policy_root, 23);
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
    zstore_root(candidate->patch_root, 24);
    zstore_root(candidate->candidate_source_root, 25);
    zstore_root(candidate->adapter_policy_root, 26);
    zstore_root(candidate->author_pubkey, 27);
    candidate->sequence = 1;
    candidate->created_unix = 1100;
    (void)vcs_zcode_candidate_root(candidate, candidate_root);
}

static void zstore_action(struct vcs_build_action_v1 *action)
{
    const char *workdir = NULL, *output = NULL, *resource = NULL;
    memset(action, 0, sizeof(*action));
    zstore_root(action->source_sha256, 60);
    zstore_root(action->source_cas_sha3, 61);
    zstore_root(action->input_root_sha3, 62);
    zstore_root(action->toolchain_capsule_sha3, 63);
    (void)vcs_build_action_v1_fixed_flags_root_for_kind(
        VCS_BUILD_ACTION_KIND_BENCHMARK_V1, action->flags_sha3);
    (void)vcs_build_action_v1_fixed_environment_root_for_kind(
        VCS_BUILD_ACTION_KIND_BENCHMARK_V1, action->environment_sha3);
    (void)snprintf(action->target, sizeof(action->target), "%s",
                   VCS_BUILD_TARGET_V1);
    (void)snprintf(action->profile, sizeof(action->profile), "science");
    (void)vcs_build_action_v1_descriptors(
        VCS_BUILD_ACTION_KIND_BENCHMARK_V1, &workdir, &output, &resource);
    (void)snprintf(action->virtual_workdir, sizeof(action->virtual_workdir),
                   "%s", workdir);
    (void)snprintf(action->declared_outputs, sizeof(action->declared_outputs),
                   "%s", output);
    (void)snprintf(action->resource_policy, sizeof(action->resource_policy),
                   "%s", resource);
    action->sequence = 1;
}

static void zstore_method(struct vcs_zcode_benchmark_method_v1 *method)
{
    memset(method, 0, sizeof(*method));
    method->schema_version = VCS_ZCODE_BENCHMARK_METHOD_VERSION;
    zstore_root(method->workload_root, 0x41);
    zstore_root(method->timer_root, 0x42);
    zstore_root(method->estimator_root, 0x43);
    method->tolerance_ppm = 5000;
    method->warmup_samples = 10;
    method->measured_samples = 1000;
    method->sample_distribution = VCS_ZCODE_SAMPLE_DIST_TRIMMED_MEAN;
    method->trim_percent = 10;
}

static void zstore_profile(struct vcs_zcode_hardware_profile_v1 *profile)
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

static void zstore_result_v2(
    const struct vcs_zcode_study_spec_v1 *study,
    const uint8_t task_root[32], const uint8_t candidate_root[32],
    const struct vcs_zcode_benchmark_method_v1 *method,
    const struct vcs_zcode_hardware_profile_v1 *profile,
    uint8_t status, uint64_t sequence, uint8_t evidence_byte,
    struct vcs_zcode_benchmark_result_v2 *result)
{
    struct vcs_build_action_v1 action;
    memset(result, 0, sizeof(*result));
    result->schema_version = VCS_ZCODE_BENCHMARK_RESULT_V2_VERSION;
    (void)vcs_zcode_study_spec_root(study, result->study_root);
    memcpy(result->task_root, task_root, 32);
    memcpy(result->candidate_root, candidate_root, 32);
    zstore_action(&action);
    (void)vcs_build_action_v1_root_for_kind(
        VCS_BUILD_ACTION_KIND_BENCHMARK_V1, &action, result->action_root);
    zstore_root(result->achieved_environment_root, 31);
    zstore_root(result->raw_sample_root, 32);
    zstore_root(result->evidence_root, evidence_byte);
    result->status = status;
    result->challenge_block_height = 3200000;
    zstore_root(result->challenge_block_hash, 34);
    result->sequence = sequence;
    result->started_unix = 1200;
    result->finished_unix = 1300;
    (void)vcs_zcode_benchmark_method_root(method, result->method_root);
    (void)vcs_zcode_hardware_profile_root(
        profile, result->hardware_profile_root);
}

/* Serialize + CAS-store one object addressed by its canonical root. */
static bool zstore_cas_put(const char *workspace, const uint8_t root[32],
                           const uint8_t *wire, size_t wire_len)
{
    return vcs_object_put_addressed(workspace, root, wire, wire_len);
}

static bool zstore_cas_put_study(const char *workspace,
                                 const struct vcs_zcode_study_spec_v1 *study,
                                 uint8_t root[32])
{
    uint8_t wire[VCS_ZCODE_STUDY_SPEC_WIRE_BYTES];
    return vcs_zcode_study_spec_serialize(study, wire) ==
               VCS_ZCODE_SCIENCE_OK &&
           vcs_zcode_study_spec_root(study, root) == VCS_ZCODE_SCIENCE_OK &&
           zstore_cas_put(workspace, root, wire, sizeof(wire));
}

static bool zstore_cas_put_task_candidate(
    const char *workspace, const struct vcs_zcode_task_v1 *task,
    const struct vcs_zcode_candidate_v1 *candidate,
    const uint8_t task_root[32], const uint8_t candidate_root[32])
{
    uint8_t twire[VCS_ZCODE_TASK_WIRE_BYTES];
    uint8_t cwire[VCS_ZCODE_CANDIDATE_WIRE_BYTES];
    return vcs_zcode_task_serialize(task, twire) == VCS_ZCODE_DEV_OK &&
           vcs_zcode_candidate_serialize(candidate, cwire) ==
               VCS_ZCODE_DEV_OK &&
           zstore_cas_put(workspace, task_root, twire, sizeof(twire)) &&
           zstore_cas_put(workspace, candidate_root, cwire, sizeof(cwire));
}

static bool zstore_cas_put_method_profile(
    const char *workspace, const struct vcs_zcode_benchmark_method_v1 *method,
    const struct vcs_zcode_hardware_profile_v1 *profile)
{
    uint8_t mwire[VCS_ZCODE_BENCHMARK_METHOD_WIRE_BYTES], mroot[32];
    uint8_t pwire[VCS_ZCODE_HARDWARE_PROFILE_WIRE_BYTES], proot[32];
    return vcs_zcode_benchmark_method_serialize(method, mwire) ==
               VCS_ZCODE_SCIENCE_OK &&
           vcs_zcode_benchmark_method_root(method, mroot) ==
               VCS_ZCODE_SCIENCE_OK &&
           vcs_zcode_hardware_profile_serialize(profile, pwire) ==
               VCS_ZCODE_SCIENCE_OK &&
           vcs_zcode_hardware_profile_root(profile, proot) ==
               VCS_ZCODE_SCIENCE_OK &&
           zstore_cas_put(workspace, mroot, mwire, sizeof(mwire)) &&
           zstore_cas_put(workspace, proot, pwire, sizeof(pwire));
}

static bool zstore_cas_put_result_v2(
    const char *workspace, const struct vcs_zcode_benchmark_result_v2 *result,
    uint8_t root[32])
{
    uint8_t wire[VCS_ZCODE_BENCHMARK_RESULT_V2_WIRE_BYTES];
    return vcs_zcode_benchmark_result_v2_serialize(result, wire) ==
               VCS_ZCODE_SCIENCE_OK &&
           vcs_zcode_benchmark_result_v2_root(result, root) ==
               VCS_ZCODE_SCIENCE_OK &&
           zstore_cas_put(workspace, root, wire, sizeof(wire));
}

static void zstore_findings(
    const struct vcs_zcode_study_spec_v1 *study,
    const uint8_t task_root[32], const uint8_t candidate_root[32],
    const uint8_t result_root[32], uint16_t flags,
    const uint8_t retraction_target[32], int64_t created_unix,
    struct vcs_zcode_science_findings_v1 *findings)
{
    memset(findings, 0, sizeof(*findings));
    findings->schema_version = VCS_ZCODE_SCIENCE_VERSION;
    (void)vcs_zcode_study_spec_root(study, findings->study_root);
    memcpy(findings->task_root, task_root, 32);
    memcpy(findings->candidate_root, candidate_root, 32);
    memcpy(findings->result_root, result_root, 32);
    zstore_root(findings->proof_set_root, 41);
    zstore_root(findings->methods_root, 42);
    zstore_root(findings->limitations_root, 43);
    zstore_root(findings->conflicts_root, 44);
    if (retraction_target)
        memcpy(findings->retraction_target_root, retraction_target, 32);
    findings->flags = flags;
    findings->severity = VCS_ZCODE_FINDING_MATERIAL;
    findings->sequence = 1;
    findings->created_unix = created_unix;
}

static bool zstore_cas_put_findings(
    const char *workspace, const struct vcs_zcode_science_findings_v1 *findings,
    uint8_t root[32])
{
    uint8_t wire[VCS_ZCODE_SCIENCE_FINDINGS_WIRE_BYTES];
    return vcs_zcode_science_findings_serialize(findings, wire) ==
               VCS_ZCODE_SCIENCE_OK &&
           vcs_zcode_science_findings_root(findings, root) ==
               VCS_ZCODE_SCIENCE_OK &&
           zstore_cas_put(workspace, root, wire, sizeof(wire));
}

/* Full evidence context in CAS: study, task, candidate, method, profile. */
static bool zstore_seed_context(
    const char *workspace, struct vcs_zcode_study_spec_v1 *study,
    uint8_t task_root[32], uint8_t candidate_root[32],
    struct vcs_zcode_benchmark_method_v1 *method,
    struct vcs_zcode_hardware_profile_v1 *profile)
{
    struct vcs_zcode_task_v1 task;
    struct vcs_zcode_candidate_v1 candidate;
    uint8_t study_root[32];
    zstore_study(study);
    zstore_task_candidate(study, &task, &candidate, task_root,
                          candidate_root);
    zstore_method(method);
    zstore_profile(profile);
    return zstore_cas_put_study(workspace, study, study_root) &&
           zstore_cas_put_task_candidate(workspace, &task, &candidate,
                                         task_root, candidate_root) &&
           zstore_cas_put_method_profile(workspace, method, profile);
}

/* ── 1 + 2: study plan/commit, retry, rebuild equivalence ────────── */

static int test_zstore_study_plan_commit(void)
{
    int failures = 0;
    TEST("zcode_science_store: study plan/commit is exact, idempotent, rebuildable") {
        struct node_db ndb = {0};
        char dir[ZSTORE_DIR_CAP];
        ASSERT(zstore_setup(&ndb, dir, sizeof(dir)));
        struct vcs_zcode_study_spec_v1 study;
        zstore_study(&study);
        uint8_t wire[VCS_ZCODE_STUDY_SPEC_WIRE_BYTES];
        ASSERT_EQ(vcs_zcode_study_spec_serialize(&study, wire),
                  VCS_ZCODE_SCIENCE_OK);
        struct zcode_science_plan_out plan, replan;
        ASSERT(zcode_science_study_plan(&ndb, dir, wire, sizeof(wire), 1500,
                                        &plan).ok);
        ASSERT(!plan.already_planned);
        ASSERT_EQ(plan.expires_unix, 1500 + ZCODE_SCIENCE_PLAN_TTL_SECONDS);
        /* Re-planning the same request returns the same plan. */
        ASSERT(zcode_science_study_plan(&ndb, dir, wire, sizeof(wire), 1501,
                                        &replan).ok);
        ASSERT(replan.already_planned);
        ASSERT_STR_EQ(replan.plan_root, plan.plan_root);
        /* Commit requires confirm:true. */
        struct zcode_science_commit_out commit;
        ASSERT(!zcode_science_study_commit(&ndb, dir, wire, sizeof(wire),
                                           false, 1500, &commit).ok);
        /* Commit twice: same root, one CAS object. */
        ASSERT(zcode_science_study_commit(&ndb, dir, wire, sizeof(wire),
                                          true, 1500, &commit).ok);
        ASSERT(!commit.already_committed);
        uint8_t expected_root[32];
        char expected_hex[65];
        ASSERT_EQ(vcs_zcode_study_spec_root(&study, expected_root),
                  VCS_ZCODE_SCIENCE_OK);
        zcl_hex_encode(expected_root, 32, expected_hex);
        ASSERT_STR_EQ(commit.result_root, expected_hex);
        struct zcode_science_commit_out recommit;
        ASSERT(zcode_science_study_commit(&ndb, dir, wire, sizeof(wire),
                                          true, 1502, &recommit).ok);
        ASSERT(recommit.already_committed);
        ASSERT_STR_EQ(recommit.result_root, expected_hex);
        ASSERT_EQ(zstore_cas_object_count(dir), 1);
        /* A different wire is a different request: no plan exists. */
        uint8_t other[VCS_ZCODE_STUDY_SPEC_WIRE_BYTES];
        memcpy(other, wire, sizeof(other));
        other[sizeof(other) - 1] ^= 1;
        struct zcode_science_commit_out stray;
        ASSERT(!zcode_science_study_commit(&ndb, dir, other, sizeof(other),
                                           true, 1500, &stray).ok);
        /* Projection reads before rebuild. */
        struct db_zcode_science_entry before, after;
        bool found = false;
        ASSERT(zcode_science_study_show(&ndb, expected_hex, &before,
                                        &found).ok);
        ASSERT(found);
        ASSERT_EQ(before.created_at, study.created_unix);
        ASSERT_EQ(before.expires_at, study.expires_unix);
        struct db_zcode_science_entry list_before[8], list_after[8];
        int count_before = 0, count_after = 0;
        ASSERT(zcode_science_study_list(&ndb, list_before, 8,
                                        &count_before).ok);
        ASSERT_EQ(count_before, 1);
        /* Rebuild equivalence: drop + rebuild from CAS, identical output. */
        struct zcode_science_rebuild_out rebuilt;
        ASSERT(zcode_science_rebuild(&ndb, dir, 1500, &rebuilt).ok);
        ASSERT_EQ(rebuilt.studies, 1);
        found = false;
        ASSERT(zcode_science_study_show(&ndb, expected_hex, &after,
                                        &found).ok);
        ASSERT(found);
        ASSERT(memcmp(&before, &after, sizeof(before)) == 0);
        ASSERT(zcode_science_study_list(&ndb, list_after, 8,
                                        &count_after).ok);
        ASSERT_EQ(count_after, count_before);
        ASSERT(memcmp(list_before, list_after,
                      sizeof(list_before[0]) * (size_t)count_before) == 0);
        zstore_teardown(&ndb, dir);
        PASS();
    } _test_next:;
    return failures;
}

/* ── 3: expiry gates new submissions, never history ──────────────── */

static int test_zstore_expiry(void)
{
    int failures = 0;
    TEST("zcode_science_store: expiry stops new submissions, never erases history") {
        struct node_db ndb = {0};
        char dir[ZSTORE_DIR_CAP];
        ASSERT(zstore_setup(&ndb, dir, sizeof(dir)));
        struct vcs_zcode_study_spec_v1 study;
        zstore_study(&study);
        uint8_t wire[VCS_ZCODE_STUDY_SPEC_WIRE_BYTES];
        ASSERT_EQ(vcs_zcode_study_spec_serialize(&study, wire),
                  VCS_ZCODE_SCIENCE_OK);
        struct zcode_science_plan_out plan;
        struct zcode_science_commit_out commit;
        /* Expired plan: commit after plan.expires_unix is refused. */
        ASSERT(zcode_science_study_plan(&ndb, dir, wire, sizeof(wire), 1500,
                                        &plan).ok);
        ASSERT(!zcode_science_study_commit(&ndb, dir, wire, sizeof(wire),
                                           true,
                                           plan.expires_unix + 1,
                                           &commit).ok);
        /* Commit inside the plan TTL but after the study window closes is
         * refused — the window gates NEW submissions. */
        struct vcs_zcode_study_spec_v1 short_study;
        zstore_study(&short_study);
        short_study.expires_unix = 1600;
        short_study.sequence = 18;
        uint8_t short_wire[VCS_ZCODE_STUDY_SPEC_WIRE_BYTES];
        ASSERT_EQ(vcs_zcode_study_spec_serialize(&short_study, short_wire),
                  VCS_ZCODE_SCIENCE_OK);
        struct zcode_science_plan_out short_plan;
        ASSERT(zcode_science_study_plan(&ndb, dir, short_wire,
                                        sizeof(short_wire), 1500,
                                        &short_plan).ok);
        ASSERT(!zcode_science_study_commit(&ndb, dir, short_wire,
                                           sizeof(short_wire), true, 1700,
                                           &commit).ok);
        /* Planning a study whose window already closed is refused. */
        struct zcode_science_plan_out closed_plan;
        ASSERT(!zcode_science_study_plan(&ndb, dir, short_wire,
                                         sizeof(short_wire), 1700,
                                         &closed_plan).ok);
        /* Stored evidence revalidates after expiry: commit in-window, then
         * read it through the index and projection long after. */
        ASSERT(zcode_science_study_commit(&ndb, dir, wire, sizeof(wire),
                                          true, 1500, &commit).ok);
        struct vcs_zcode_science_index *index =
            vcs_zcode_science_index_build(dir, 9999);
        ASSERT(index != NULL);
        ASSERT_EQ(vcs_zcode_science_index_study_count(index), 1);
        const struct vcs_zcode_science_index_study_entry *se =
            vcs_zcode_science_index_study_at(index, 0);
        ASSERT(se != NULL && se->expired);
        vcs_zcode_science_index_free(index);
        struct db_zcode_science_entry row;
        bool found = false;
        ASSERT(zcode_science_study_show(&ndb, commit.result_root, &row,
                                        &found).ok);
        ASSERT(found);
        /* The plan ledger itself is durable history: the committed plan
         * row survives with its result root. */
        struct db_zcode_science_plan stored_plan;
        ASSERT(db_zcode_science_plan_find(&ndb, plan.plan_root,
                                          &stored_plan));
        ASSERT_STR_EQ(stored_plan.result_root, commit.result_root);
        ASSERT_STR_EQ(stored_plan.state, ZCODE_SCIENCE_PLAN_STATE_COMMITTED);
        zstore_teardown(&ndb, dir);
        PASS();
    } _test_next:;
    return failures;
}

/* ── 4: malformed / trailing / misplaced CAS objects ─────────────── */

static int test_zstore_malformed_objects(void)
{
    int failures = 0;
    TEST("zcode_science_store: malformed, trailing, and misplaced objects never project") {
        struct node_db ndb = {0};
        char dir[ZSTORE_DIR_CAP];
        ASSERT(zstore_setup(&ndb, dir, sizeof(dir)));
        struct vcs_zcode_study_spec_v1 study;
        zstore_study(&study);
        uint8_t wire[VCS_ZCODE_STUDY_SPEC_WIRE_BYTES];
        uint8_t root[32];
        ASSERT_EQ(vcs_zcode_study_spec_serialize(&study, wire),
                  VCS_ZCODE_SCIENCE_OK);
        ASSERT_EQ(vcs_zcode_study_spec_root(&study, root),
                  VCS_ZCODE_SCIENCE_OK);
        /* One valid study committed through the service. */
        struct zcode_science_plan_out plan;
        struct zcode_science_commit_out commit;
        ASSERT(zcode_science_study_plan(&ndb, dir, wire, sizeof(wire), 1500,
                                        &plan).ok);
        ASSERT(zcode_science_study_commit(&ndb, dir, wire, sizeof(wire),
                                          true, 1500, &commit).ok);
        /* Foreign bytes addressed honestly: another CAS citizen, skipped. */
        uint8_t junk[100];
        memset(junk, 0x5a, sizeof(junk));
        uint8_t junk_root[32];
        zstore_root(junk_root, 0x77);
        ASSERT(zstore_cas_put(dir, junk_root, junk, sizeof(junk)));
        /* Study magic with a corrupted body, addressed by the corrupt
         * root: fails root agreement, skipped. */
        uint8_t corrupt[VCS_ZCODE_STUDY_SPEC_WIRE_BYTES];
        memcpy(corrupt, wire, sizeof(corrupt));
        corrupt[100] ^= 0xff;
        uint8_t corrupt_root[32];
        zstore_root(corrupt_root, 0x78);
        ASSERT(zstore_cas_put(dir, corrupt_root, corrupt, sizeof(corrupt)));
        /* Trailing bytes: right magic, wrong size, skipped. */
        uint8_t trailing[VCS_ZCODE_STUDY_SPEC_WIRE_BYTES + 1];
        memcpy(trailing, wire, sizeof(wire));
        trailing[VCS_ZCODE_STUDY_SPEC_WIRE_BYTES] = 0;
        uint8_t trailing_root[32];
        zstore_root(trailing_root, 0x79);
        ASSERT(zstore_cas_put(dir, trailing_root, trailing,
                              sizeof(trailing)));
        /* A valid wire under the WRONG address: root disagreement,
         * skipped. */
        uint8_t wrong_address[32];
        zstore_root(wrong_address, 0x7a);
        ASSERT(zstore_cas_put(dir, wrong_address, wire, sizeof(wire)));
        struct vcs_zcode_science_index *index =
            vcs_zcode_science_index_build(dir, 1500);
        ASSERT(index != NULL);
        ASSERT_EQ(vcs_zcode_science_index_study_count(index), 1);
        ASSERT(vcs_zcode_science_index_find_study(index, root) != NULL);
        vcs_zcode_science_index_free(index);
        /* Rebuild keeps exactly the one valid study. */
        struct zcode_science_rebuild_out rebuilt;
        ASSERT(zcode_science_rebuild(&ndb, dir, 1500, &rebuilt).ok);
        ASSERT_EQ(rebuilt.studies, 1);
        zstore_teardown(&ndb, dir);
        PASS();
    } _test_next:;
    return failures;
}

/* ── 5 + 6: null/negative results, contradictory reproductions ───── */

static int test_zstore_evidence(void)
{
    int failures = 0;
    TEST("zcode_science_store: null/negative results are observations; contradictions coexist") {
        struct node_db ndb = {0};
        char dir[ZSTORE_DIR_CAP];
        ASSERT(zstore_setup(&ndb, dir, sizeof(dir)));
        struct vcs_zcode_study_spec_v1 study;
        struct vcs_zcode_benchmark_method_v1 method;
        struct vcs_zcode_hardware_profile_v1 profile;
        uint8_t task_root[32], candidate_root[32];
        ASSERT(zstore_seed_context(dir, &study, task_root, candidate_root,
                                   &method, &profile));
        struct vcs_build_action_v1 action;
        zstore_action(&action);
        uint8_t mwire[VCS_ZCODE_BENCHMARK_METHOD_WIRE_BYTES];
        uint8_t pwire[VCS_ZCODE_HARDWARE_PROFILE_WIRE_BYTES];
        ASSERT_EQ(vcs_zcode_benchmark_method_serialize(&method, mwire),
                  VCS_ZCODE_SCIENCE_OK);
        ASSERT_EQ(vcs_zcode_hardware_profile_serialize(&profile, pwire),
                  VCS_ZCODE_SCIENCE_OK);
        /* A NULL result and a NEGATIVE result both commit. */
        struct vcs_zcode_benchmark_result_v2 null_result, neg_result;
        zstore_result_v2(&study, task_root, candidate_root, &method,
                         &profile, VCS_ZCODE_BENCHMARK_NULL_RESULT, 1, 33,
                         &null_result);
        zstore_result_v2(&study, task_root, candidate_root, &method,
                         &profile, VCS_ZCODE_BENCHMARK_NEGATIVE_RESULT, 2,
                         35, &neg_result);
        uint8_t null_wire[VCS_ZCODE_BENCHMARK_RESULT_V2_WIRE_BYTES];
        uint8_t neg_wire[VCS_ZCODE_BENCHMARK_RESULT_V2_WIRE_BYTES];
        ASSERT_EQ(vcs_zcode_benchmark_result_v2_serialize(&null_result,
                                                          null_wire),
                  VCS_ZCODE_SCIENCE_OK);
        ASSERT_EQ(vcs_zcode_benchmark_result_v2_serialize(&neg_result,
                                                          neg_wire),
                  VCS_ZCODE_SCIENCE_OK);
        struct zcode_science_plan_out plan;
        struct zcode_science_commit_out commit;
        ASSERT(zcode_science_work_plan(&ndb, dir, null_wire,
                                       sizeof(null_wire), mwire,
                                       sizeof(mwire), pwire, sizeof(pwire),
                                       &action, 1500, &plan).ok);
        ASSERT(zcode_science_work_commit(&ndb, dir, null_wire,
                                         sizeof(null_wire), &action, true,
                                         1500, &commit).ok);
        struct zcode_science_plan_out plan2;
        ASSERT(zcode_science_work_plan(&ndb, dir, neg_wire, sizeof(neg_wire),
                                       mwire, sizeof(mwire), pwire,
                                       sizeof(pwire), &action, 1500,
                                       &plan2).ok);
        ASSERT(zcode_science_work_commit(&ndb, dir, neg_wire,
                                         sizeof(neg_wire), &action, true,
                                         1500, &commit).ok);
        /* Status + receipt read the observation back, CAS-verified. */
        struct db_zcode_science_entry row;
        const char *kind = NULL;
        bool found = false;
        uint8_t neg_root[32];
        char neg_hex[65];
        ASSERT_EQ(vcs_zcode_benchmark_result_v2_root(&neg_result, neg_root),
                  VCS_ZCODE_SCIENCE_OK);
        zcl_hex_encode(neg_root, 32, neg_hex);
        ASSERT(zcode_science_work_status(&ndb, neg_hex, &row, &kind,
                                         &found).ok);
        ASSERT(found);
        ASSERT_STR_EQ(kind, "result");
        ASSERT_EQ(row.code, VCS_ZCODE_BENCHMARK_NEGATIVE_RESULT);
        ASSERT(zcode_science_work_receipt(&ndb, dir, neg_hex, &row,
                                          &kind).ok);
        /* Cross-validation failure: tampered action binding is refused. */
        struct vcs_zcode_benchmark_result_v2 tampered = null_result;
        tampered.action_root[0] ^= 1;
        tampered.evidence_root[0] ^= 1;
        tampered.sequence = 3;
        uint8_t tampered_wire[VCS_ZCODE_BENCHMARK_RESULT_V2_WIRE_BYTES];
        ASSERT_EQ(vcs_zcode_benchmark_result_v2_serialize(&tampered,
                                                          tampered_wire),
                  VCS_ZCODE_SCIENCE_OK);
        struct zcode_science_plan_out plan3;
        struct zcode_science_commit_out commit3;
        ASSERT(zcode_science_work_plan(&ndb, dir, tampered_wire,
                                       sizeof(tampered_wire), mwire,
                                       sizeof(mwire), pwire, sizeof(pwire),
                                       &action, 1500, &plan3).ok);
        ASSERT(!zcode_science_work_commit(&ndb, dir, tampered_wire,
                                          sizeof(tampered_wire), &action,
                                          true, 1500, &commit3).ok);
        /* Contradictory reproductions: REPLICATED and CONTRADICTED over
         * the same pair both store. The hardened cross-validator
         * re-derives V1 roots, so reproductions bind v1 result wires —
         * both are stored in CAS directly (committed evidence). */
        struct vcs_zcode_benchmark_result_v1 orig_v1, repro_v1;
        for (int i = 0; i < 2; i++) {
            struct vcs_zcode_benchmark_result_v1 *r =
                i == 0 ? &orig_v1 : &repro_v1;
            memset(r, 0, sizeof(*r));
            r->schema_version = VCS_ZCODE_SCIENCE_VERSION;
            (void)vcs_zcode_study_spec_root(&study, r->study_root);
            memcpy(r->task_root, task_root, 32);
            memcpy(r->candidate_root, candidate_root, 32);
            (void)vcs_build_action_v1_root_for_kind(
                VCS_BUILD_ACTION_KIND_BENCHMARK_V1, &action,
                r->action_root);
            zstore_root(r->achieved_environment_root, 31);
            zstore_root(r->raw_sample_root, (uint8_t)(32 + i));
            zstore_root(r->evidence_root, (uint8_t)(33 + i));
            r->status = i == 0 ? VCS_ZCODE_BENCHMARK_OBSERVED
                               : VCS_ZCODE_BENCHMARK_NEGATIVE_RESULT;
            r->challenge_block_height = 3200000;
            zstore_root(r->challenge_block_hash, 34);
            r->sequence = (uint64_t)(1 + i);
            r->started_unix = 1200;
            r->finished_unix = 1300;
        }
        uint8_t original_root[32], reproduced_root[32];
        uint8_t result_wire[VCS_ZCODE_BENCHMARK_RESULT_WIRE_BYTES];
        ASSERT_EQ(vcs_zcode_benchmark_result_serialize(&orig_v1,
                                                       result_wire),
                  VCS_ZCODE_SCIENCE_OK);
        ASSERT_EQ(vcs_zcode_benchmark_result_root(&orig_v1, original_root),
                  VCS_ZCODE_SCIENCE_OK);
        ASSERT(zstore_cas_put(dir, original_root, result_wire,
                              sizeof(result_wire)));
        ASSERT_EQ(vcs_zcode_benchmark_result_serialize(&repro_v1,
                                                       result_wire),
                  VCS_ZCODE_SCIENCE_OK);
        ASSERT_EQ(vcs_zcode_benchmark_result_root(&repro_v1,
                                                  reproduced_root),
                  VCS_ZCODE_SCIENCE_OK);
        ASSERT(zstore_cas_put(dir, reproduced_root, result_wire,
                              sizeof(result_wire)));
        struct vcs_zcode_reproduction_v1 rep_a, rep_b;
        for (int i = 0; i < 2; i++) {
            struct vcs_zcode_reproduction_v1 *r = i == 0 ? &rep_a : &rep_b;
            memset(r, 0, sizeof(*r));
            r->schema_version = VCS_ZCODE_SCIENCE_VERSION;
            memcpy(r->study_root, null_result.study_root, 32);
            memcpy(r->original_result_root, original_root, 32);
            memcpy(r->reproduced_result_root, reproduced_root, 32);
            zstore_root(r->comparison_policy_root, 39);
            memcpy(r->original_environment_root,
                   orig_v1.achieved_environment_root, 32);
            memcpy(r->reproduced_environment_root,
                   repro_v1.achieved_environment_root, 32);
            zstore_root(r->reproducer_pubkey, (uint8_t)(40 + i));
            r->verdict = i == 0 ? VCS_ZCODE_REPRODUCTION_REPLICATED
                                : VCS_ZCODE_REPRODUCTION_CONTRADICTED;
            r->sequence = (uint64_t)(1 + i);
            r->created_unix = 1400;
        }
        uint8_t rep_wire[VCS_ZCODE_REPRODUCTION_WIRE_BYTES];
        struct zcode_science_commit_out rep_commit;
        ASSERT_EQ(vcs_zcode_reproduction_serialize(&rep_a, rep_wire),
                  VCS_ZCODE_SCIENCE_OK);
        struct zcode_science_plan_out rep_plan;
        ASSERT(zcode_science_work_plan(&ndb, dir, rep_wire, sizeof(rep_wire),
                                       NULL, 0, NULL, 0, NULL, 1500,
                                       &rep_plan).ok);
        ASSERT(zcode_science_work_commit(&ndb, dir, rep_wire,
                                         sizeof(rep_wire), NULL, true, 1500,
                                         &rep_commit).ok);
        ASSERT_EQ(vcs_zcode_reproduction_serialize(&rep_b, rep_wire),
                  VCS_ZCODE_SCIENCE_OK);
        struct zcode_science_plan_out rep_plan_b;
        ASSERT(zcode_science_work_plan(&ndb, dir, rep_wire, sizeof(rep_wire),
                                       NULL, 0, NULL, 0, NULL, 1500,
                                       &rep_plan_b).ok);
        ASSERT(zcode_science_work_commit(&ndb, dir, rep_wire,
                                         sizeof(rep_wire), NULL, true, 1500,
                                         &rep_commit).ok);
        /* Both verdicts coexist in the projection. */
        struct vcs_zcode_science_index *index =
            vcs_zcode_science_index_build(dir, 1500);
        ASSERT(index != NULL);
        ASSERT_EQ(vcs_zcode_science_index_reproduction_count(index), 2);
        bool saw_replicated = false, saw_contradicted = false;
        for (size_t i = 0; i < 2; i++) {
            const struct vcs_zcode_science_index_reproduction_entry *e =
                vcs_zcode_science_index_reproduction_at(index, i);
            if (e->verdict == VCS_ZCODE_REPRODUCTION_REPLICATED)
                saw_replicated = true;
            if (e->verdict == VCS_ZCODE_REPRODUCTION_CONTRADICTED)
                saw_contradicted = true;
        }
        ASSERT(saw_replicated && saw_contradicted);
        /* The study entry counts its evidence. */
        uint8_t study_root[32];
        ASSERT_EQ(vcs_zcode_study_spec_root(&study, study_root),
                  VCS_ZCODE_SCIENCE_OK);
        const struct vcs_zcode_science_index_study_entry *se =
            vcs_zcode_science_index_find_study(index, study_root);
        ASSERT(se != NULL);
        ASSERT_EQ(se->result_count, 2);
        ASSERT_EQ(se->reproduction_count, 2);
        vcs_zcode_science_index_free(index);
        /* Rebuild equivalence over the whole evidence set. */
        struct zcode_science_rebuild_out rebuilt;
        ASSERT(zcode_science_rebuild(&ndb, dir, 1500, &rebuilt).ok);
        ASSERT_EQ(rebuilt.studies, 1);
        ASSERT_EQ(rebuilt.results, 2);
        ASSERT_EQ(rebuilt.reproductions, 2);
        zstore_teardown(&ndb, dir);
        PASS();
    } _test_next:;
    return failures;
}

/* ── 7 + 8: stale reviews, retractions ───────────────────────────── */

static int test_zstore_review_retraction(void)
{
    int failures = 0;
    TEST("zcode_science_store: stale reviews rejected; retractions mark, never erase") {
        struct node_db ndb = {0};
        char dir[ZSTORE_DIR_CAP];
        ASSERT(zstore_setup(&ndb, dir, sizeof(dir)));
        struct vcs_zcode_study_spec_v1 study;
        struct vcs_zcode_benchmark_method_v1 method;
        struct vcs_zcode_hardware_profile_v1 profile;
        uint8_t task_root[32], candidate_root[32], result_root[32];
        ASSERT(zstore_seed_context(dir, &study, task_root, candidate_root,
                                   &method, &profile));
        struct vcs_zcode_benchmark_result_v2 result;
        zstore_result_v2(&study, task_root, candidate_root, &method,
                         &profile, VCS_ZCODE_BENCHMARK_OBSERVED, 1, 33,
                         &result);
        ASSERT(zstore_cas_put_result_v2(dir, &result, result_root));
        /* Findings exist in CAS (published evidence the review binds). */
        struct vcs_zcode_science_findings_v1 findings;
        zstore_findings(&study, task_root, candidate_root, result_root, 0,
                        NULL, 1800, &findings);
        uint8_t findings_root[32];
        ASSERT(zstore_cas_put_findings(dir, &findings, findings_root));
        /* A review PREDATING its findings is stale: plan is fine, commit
         * is refused (H1). */
        struct vcs_zcode_review_v1 stale;
        memset(&stale, 0, sizeof(stale));
        stale.schema_version = VCS_ZCODE_DEV_VERSION;
        memcpy(stale.task_root, task_root, 32);
        memcpy(stale.candidate_root, candidate_root, 32);
        zstore_root(stale.proof_policy_root, 22);
        zstore_root(stale.proof_set_root, 41);
        memcpy(stale.findings_root, findings_root, 32);
        zstore_root(stale.reviewer_pubkey, 45);
        stale.verdict = VCS_ZCODE_REVIEW_APPROVE;
        stale.sequence = 1;
        stale.created_unix = 1700;
        uint8_t stale_wire[VCS_ZCODE_REVIEW_WIRE_BYTES];
        ASSERT_EQ(vcs_zcode_review_serialize(&stale, stale_wire),
                  VCS_ZCODE_DEV_OK);
        struct zcode_science_plan_out plan;
        struct zcode_science_commit_out commit;
        ASSERT(zcode_science_review_submit(&ndb, dir, stale_wire,
                                           sizeof(stale_wire), false, 1900,
                                           &plan, &commit).ok);
        ASSERT(!zcode_science_review_submit(&ndb, dir, stale_wire,
                                            sizeof(stale_wire), true, 1900,
                                            &plan, &commit).ok);
        /* A fresh review commits. */
        struct vcs_zcode_review_v1 fresh = stale;
        fresh.created_unix = 1900;
        uint8_t fresh_wire[VCS_ZCODE_REVIEW_WIRE_BYTES];
        ASSERT_EQ(vcs_zcode_review_serialize(&fresh, fresh_wire),
                  VCS_ZCODE_DEV_OK);
        ASSERT(zcode_science_review_submit(&ndb, dir, fresh_wire,
                                           sizeof(fresh_wire), false, 1900,
                                           &plan, &commit).ok);
        ASSERT(zcode_science_review_submit(&ndb, dir, fresh_wire,
                                           sizeof(fresh_wire), true, 1900,
                                           &plan, &commit).ok);
        ASSERT(!commit.already_committed);
        /* A review binding findings that are NOT in CAS is refused. */
        struct vcs_zcode_review_v1 orphan = fresh;
        zstore_root(orphan.findings_root, 0x66);
        orphan.sequence = 2;
        uint8_t orphan_wire[VCS_ZCODE_REVIEW_WIRE_BYTES];
        ASSERT_EQ(vcs_zcode_review_serialize(&orphan, orphan_wire),
                  VCS_ZCODE_DEV_OK);
        struct zcode_science_plan_out orphan_plan;
        ASSERT(zcode_science_review_submit(&ndb, dir, orphan_wire,
                                           sizeof(orphan_wire), false, 1900,
                                           &orphan_plan, &commit).ok);
        ASSERT(!zcode_science_review_submit(&ndb, dir, orphan_wire,
                                            sizeof(orphan_wire), true, 1900,
                                            &orphan_plan, &commit).ok);
        /* Retraction: a RETRACTION findings targeting the study marks it;
         * the study and its evidence stay. */
        uint8_t study_root[32];
        ASSERT_EQ(vcs_zcode_study_spec_root(&study, study_root),
                  VCS_ZCODE_SCIENCE_OK);
        struct vcs_zcode_science_findings_v1 retraction;
        zstore_findings(&study, task_root, candidate_root, result_root,
                        VCS_ZCODE_FINDING_RETRACTION, study_root, 2000,
                        &retraction);
        retraction.sequence = 2;
        uint8_t retraction_root[32];
        ASSERT(zstore_cas_put_findings(dir, &retraction, retraction_root));
        struct vcs_zcode_science_index *index =
            vcs_zcode_science_index_build(dir, 2000);
        ASSERT(index != NULL);
        const struct vcs_zcode_science_index_study_entry *se =
            vcs_zcode_science_index_find_study(index, study_root);
        ASSERT(se != NULL);
        ASSERT(se->retracted);
        ASSERT_EQ(se->result_count, 1);
        vcs_zcode_science_index_free(index);
        /* Rebuild propagates the mark into the projection. */
        struct zcode_science_rebuild_out rebuilt;
        ASSERT(zcode_science_rebuild(&ndb, dir, 2000, &rebuilt).ok);
        ASSERT_EQ(rebuilt.findings, 2);
        ASSERT_EQ(rebuilt.reviews, 1);
        char study_hex[65];
        zcl_hex_encode(study_root, 32, study_hex);
        struct db_zcode_science_entry row;
        bool found = false;
        ASSERT(zcode_science_study_show(&ndb, study_hex, &row, &found).ok);
        ASSERT(found);
        ASSERT(row.flags & 0x10000);
        zstore_teardown(&ndb, dir);
        PASS();
    } _test_next:;
    return failures;
}

/* ── 9: vote identity, replay, idempotency ───────────────────────── */

static int test_zstore_votes(void)
{
    int failures = 0;
    TEST("zcode_science_store: votes verify identity, reject replay, dedupe by id") {
        struct node_db ndb = {0};
        char dir[ZSTORE_DIR_CAP];
        ASSERT(zstore_setup(&ndb, dir, sizeof(dir)));
        uint8_t seed[32], secret[32], pubkey[32];
        zstore_root(seed, 53);
        ed25519_keypair(pubkey, secret, seed);
        struct vcs_zcode_curation_vote_v1 vote;
        memset(&vote, 0, sizeof(vote));
        vote.schema_version = VCS_ZCODE_SCIENCE_VERSION;
        zstore_root(vote.network_genesis_root, 50);
        zstore_root(vote.voter_zid_root, 51);
        zstore_root(vote.property_root, 52);
        vote.signal = VCS_ZCODE_CURATION_USEFUL;
        vote.sequence = 1;
        vote.expires_unix = 5000;
        ASSERT_EQ(vcs_zcode_curation_vote_seal(&vote, secret, pubkey),
                  VCS_ZCODE_SCIENCE_OK);
        uint8_t wire[VCS_ZCODE_CURATION_VOTE_WIRE_BYTES];
        ASSERT_EQ(vcs_zcode_curation_vote_serialize(&vote, wire),
                  VCS_ZCODE_SCIENCE_OK);
        struct zcode_science_plan_out plan;
        struct zcode_science_commit_out commit;
        /* Cross-network identity rejection: wrong expected genesis. */
        uint8_t wrong_genesis[32];
        zstore_root(wrong_genesis, 54);
        ASSERT(zcode_science_vote_submit(&ndb, dir, wire, sizeof(wire),
                                         wrong_genesis,
                                         vote.voter_zid_root, pubkey, false,
                                         1500, &plan, &commit).ok);
        ASSERT(!zcode_science_vote_submit(&ndb, dir, wire, sizeof(wire),
                                          wrong_genesis,
                                          vote.voter_zid_root, pubkey, true,
                                          1500, &plan, &commit).ok);
        /* Correct identity commits. */
        ASSERT(zcode_science_vote_submit(&ndb, dir, wire, sizeof(wire),
                                         vote.network_genesis_root,
                                         vote.voter_zid_root, pubkey, true,
                                         1500, &plan, &commit).ok);
        ASSERT(!commit.already_committed);
        char vote_id_hex[65];
        (void)snprintf(vote_id_hex, sizeof(vote_id_hex), "%s",
                       commit.result_root);
        /* Re-submitting the identical vote is an idempotent reattach. */
        ASSERT(zcode_science_vote_submit(&ndb, dir, wire, sizeof(wire),
                                         vote.network_genesis_root,
                                         vote.voter_zid_root, pubkey, true,
                                         1501, &plan, &commit).ok);
        ASSERT(commit.already_committed);
        ASSERT_STR_EQ(commit.result_root, vote_id_hex);
        ASSERT_EQ(zstore_cas_object_count(dir), 1);
        /* Replay: same voter+sequence, different property (a different
         * vote id) is rejected. */
        struct vcs_zcode_curation_vote_v1 replay = vote;
        zstore_root(replay.property_root, 55);
        replay.signature[0] = 0; /* reseal below */
        ASSERT_EQ(vcs_zcode_curation_vote_seal(&replay, secret, pubkey),
                  VCS_ZCODE_SCIENCE_OK);
        uint8_t replay_wire[VCS_ZCODE_CURATION_VOTE_WIRE_BYTES];
        ASSERT_EQ(vcs_zcode_curation_vote_serialize(&replay, replay_wire),
                  VCS_ZCODE_SCIENCE_OK);
        struct zcode_science_plan_out replay_plan;
        ASSERT(zcode_science_vote_submit(&ndb, dir, replay_wire,
                                         sizeof(replay_wire),
                                         replay.network_genesis_root,
                                         replay.voter_zid_root, pubkey,
                                         false, 1500, &replay_plan,
                                         &commit).ok);
        ASSERT(!zcode_science_vote_submit(&ndb, dir, replay_wire,
                                          sizeof(replay_wire),
                                          replay.network_genesis_root,
                                          replay.voter_zid_root, pubkey,
                                          true, 1500, &replay_plan,
                                          &commit).ok);
        /* A fresh sequence from the same voter commits. */
        struct vcs_zcode_curation_vote_v1 next = vote;
        next.sequence = 2;
        ASSERT_EQ(vcs_zcode_curation_vote_seal(&next, secret, pubkey),
                  VCS_ZCODE_SCIENCE_OK);
        uint8_t next_wire[VCS_ZCODE_CURATION_VOTE_WIRE_BYTES];
        ASSERT_EQ(vcs_zcode_curation_vote_serialize(&next, next_wire),
                  VCS_ZCODE_SCIENCE_OK);
        ASSERT(zcode_science_vote_submit(&ndb, dir, next_wire,
                                         sizeof(next_wire),
                                         next.network_genesis_root,
                                         next.voter_zid_root, pubkey, false,
                                         1500, &plan, &commit).ok);
        ASSERT(zcode_science_vote_submit(&ndb, dir, next_wire,
                                         sizeof(next_wire),
                                         next.network_genesis_root,
                                         next.voter_zid_root, pubkey, true,
                                         1500, &plan, &commit).ok);
        /* Rebuild preserves the dedupe discipline: 2 votes projected. */
        struct zcode_science_rebuild_out rebuilt;
        ASSERT(zcode_science_rebuild(&ndb, dir, 1500, &rebuilt).ok);
        ASSERT_EQ(rebuilt.votes, 2);
        struct db_zcode_science_entry row;
        bool found = false;
        const char *kind = NULL;
        (void)kind;
        ASSERT(db_zcode_science_vote_find(&ndb, vote_id_hex, &row));
        ASSERT_EQ(row.code, VCS_ZCODE_CURATION_USEFUL);
        ASSERT_EQ(row.sequence, 1);
        (void)found;
        zstore_teardown(&ndb, dir);
        PASS();
    } _test_next:;
    return failures;
}

/* ── 7: publish mirrors a committed wire into the blob carrier ─────── */

static int test_zstore_publish(void)
{
    int failures = 0;
    TEST("zcode_science_store: publish mirrors CAS wires into the blob carrier") {
        struct node_db ndb = {0};
        char dir[ZSTORE_DIR_CAP];
        ASSERT(zstore_setup(&ndb, dir, sizeof(dir)));
        char sdir[ZSTORE_DIR_CAP];
        int n = snprintf(sdir, sizeof(sdir), "test-tmp/zcode_pubstore_%d_%d",
                         (int)getpid(), g_zstore_seq++);
        ASSERT(n > 0 && (size_t)n < sizeof(sdir));
        {
            char cmd[ZSTORE_DIR_CAP * 2 + 32];
            n = snprintf(cmd, sizeof(cmd), "rm -rf '%s' && mkdir -p '%s'",
                         sdir, sdir);
            ASSERT(n > 0 && (size_t)n < sizeof(cmd) && system(cmd) == 0);
        }
        struct vcs_package_store *store =
            vcs_package_store_open(sdir, UINT64_C(4) * 1024 * 1024);
        ASSERT(store != NULL);
        /* Commit a study so its wire sits in the workspace CAS. */
        struct vcs_zcode_study_spec_v1 study;
        zstore_study(&study);
        uint8_t wire[VCS_ZCODE_STUDY_SPEC_WIRE_BYTES];
        ASSERT_EQ(vcs_zcode_study_spec_serialize(&study, wire),
                  VCS_ZCODE_SCIENCE_OK);
        struct zcode_science_plan_out plan;
        struct zcode_science_commit_out commit;
        ASSERT(zcode_science_study_plan(&ndb, dir, wire, sizeof(wire), 1500,
                                        &plan).ok);
        ASSERT(zcode_science_study_commit(&ndb, dir, wire, sizeof(wire),
                                          true, 1500, &commit).ok);
        /* Publish: the blob transport root is the pure root of the same
         * bytes; the science root stays the semantic address. */
        char blob_hex[65], kind[ZCODE_SCIENCE_KIND_CAP];
        ASSERT(zcode_science_publish(store, dir, commit.result_root,
                                     blob_hex, kind).ok);
        ASSERT_STR_EQ(kind, ZCODE_SCIENCE_KIND_STUDY);
        uint8_t pure_root[32];
        ASSERT_EQ(vcs_blob_root_of(wire, sizeof(wire), pure_root),
                  VCS_BLOB_OK);
        char pure_hex[65];
        zcl_hex_encode(pure_root, 32, pure_hex);
        ASSERT_STR_EQ(blob_hex, pure_hex);
        /* Round-trip: the carrier returns the exact science wire. */
        uint8_t got[VCS_ZCODE_STUDY_SPEC_WIRE_BYTES];
        size_t got_len = 0;
        ASSERT_EQ(vcs_blob_get_from(store, pure_root, got, sizeof(got),
                                    &got_len), VCS_BLOB_OK);
        ASSERT_EQ(got_len, sizeof(wire));
        ASSERT(memcmp(got, wire, sizeof(wire)) == 0);
        /* Idempotent: re-publish yields the same transport root. */
        char blob2[65], kind2[ZCODE_SCIENCE_KIND_CAP];
        ASSERT(zcode_science_publish(store, dir, commit.result_root,
                                     blob2, kind2).ok);
        ASSERT_STR_EQ(blob2, blob_hex);
        /* Named negatives. */
        char absent[65];
        memset(absent, 'a', 64);
        absent[64] = '\0';
        ASSERT(!zcode_science_publish(store, dir, absent, blob2,
                                      kind2).ok); /* not in CAS */
        ASSERT(!zcode_science_publish(store, dir, "zz", blob2,
                                      kind2).ok); /* bad hex */
        /* A CAS object that is not a science wire never publishes. */
        uint8_t garbage[64], garbage_addr[32];
        memset(garbage, 0xAB, sizeof(garbage));
        memset(garbage_addr, 0xCD, 32);
        ASSERT(vcs_object_put_addressed(dir, garbage_addr, garbage,
                                        sizeof(garbage)));
        char garbage_hex[65];
        zcl_hex_encode(garbage_addr, 32, garbage_hex);
        ASSERT(!zcode_science_publish(store, dir, garbage_hex, blob2,
                                      kind2).ok); /* cas-corrupt */
        ASSERT(!zcode_science_publish(NULL, dir, commit.result_root,
                                      blob2, kind2).ok); /* null store */
        vcs_package_store_close(store);
        zstore_teardown(&ndb, dir);
        {
            char cmd[ZSTORE_DIR_CAP + 16];
            n = snprintf(cmd, sizeof(cmd), "rm -rf '%s'", sdir);
            if (n > 0 && (size_t)n < sizeof(cmd))
                (void)system(cmd);
        }
        PASS();
    } _test_next:;
    return failures;
}

/* ── 8: admit receives a blob-carried wire into CAS + projection ───── */

static int test_zstore_admit(void)
{
    int failures = 0;
    TEST("zcode_science_store: admit derives the science root from blob bytes") {
        /* Node A: commit + publish. */
        struct node_db ndb_a = {0};
        char dir_a[ZSTORE_DIR_CAP];
        ASSERT(zstore_setup(&ndb_a, dir_a, sizeof(dir_a)));
        char sdir[ZSTORE_DIR_CAP];
        int n = snprintf(sdir, sizeof(sdir), "test-tmp/zcode_admstore_%d_%d",
                         (int)getpid(), g_zstore_seq++);
        ASSERT(n > 0 && (size_t)n < sizeof(sdir));
        {
            char cmd[ZSTORE_DIR_CAP * 2 + 32];
            n = snprintf(cmd, sizeof(cmd), "rm -rf '%s' && mkdir -p '%s'",
                         sdir, sdir);
            ASSERT(n > 0 && (size_t)n < sizeof(cmd) && system(cmd) == 0);
        }
        struct vcs_package_store *store =
            vcs_package_store_open(sdir, UINT64_C(4) * 1024 * 1024);
        ASSERT(store != NULL);
        struct vcs_zcode_study_spec_v1 study;
        zstore_study(&study);
        uint8_t wire[VCS_ZCODE_STUDY_SPEC_WIRE_BYTES];
        ASSERT_EQ(vcs_zcode_study_spec_serialize(&study, wire),
                  VCS_ZCODE_SCIENCE_OK);
        struct zcode_science_plan_out plan;
        struct zcode_science_commit_out commit;
        ASSERT(zcode_science_study_plan(&ndb_a, dir_a, wire, sizeof(wire),
                                        1500, &plan).ok);
        ASSERT(zcode_science_study_commit(&ndb_a, dir_a, wire, sizeof(wire),
                                          true, 1500, &commit).ok);
        char blob_hex[65], pub_kind[ZCODE_SCIENCE_KIND_CAP];
        ASSERT(zcode_science_publish(store, dir_a, commit.result_root,
                                     blob_hex, pub_kind).ok);
        /* Node B: a fresh workspace + projection, nothing in CAS. */
        struct node_db ndb_b = {0};
        char dir_b[ZSTORE_DIR_CAP];
        ASSERT(zstore_setup(&ndb_b, dir_b, sizeof(dir_b)));
        struct db_zcode_science_entry row;
        bool found = true;
        ASSERT(zcode_science_study_show(&ndb_b, commit.result_root, &row,
                                        &found).ok);
        ASSERT(!found);
        /* Admit: the science root comes from the blob BYTES, and the
         * object lands in B's CAS and projection. */
        char science_hex[65], kind[ZCODE_SCIENCE_KIND_CAP];
        bool is_new = false;
        ASSERT(zcode_science_admit(store, &ndb_b, dir_b, blob_hex, 1500,
                                   science_hex, kind, &is_new).ok);
        ASSERT(is_new);
        ASSERT_STR_EQ(kind, ZCODE_SCIENCE_KIND_STUDY);
        ASSERT_STR_EQ(science_hex, commit.result_root);
        found = false;
        ASSERT(zcode_science_study_show(&ndb_b, commit.result_root, &row,
                                        &found).ok);
        ASSERT(found);
        ASSERT_EQ(row.created_at, study.created_unix);
        ASSERT_EQ(zstore_cas_object_count(dir_b), 1);
        /* Idempotent: re-admit reports not-new, one CAS object. */
        is_new = true;
        ASSERT(zcode_science_admit(store, &ndb_b, dir_b, blob_hex, 1500,
                                   science_hex, kind, &is_new).ok);
        ASSERT(!is_new);
        ASSERT_EQ(zstore_cas_object_count(dir_b), 1);
        /* Named negatives. */
        char absent[65];
        memset(absent, 'b', 64);
        absent[64] = '\0';
        ASSERT(!zcode_science_admit(store, &ndb_b, dir_b, absent, 1500,
                                    science_hex, kind, &is_new).ok);
        /* A blob that is not a science wire is refused by name. */
        uint8_t garbage[64];
        memset(garbage, 0xAB, sizeof(garbage));
        uint8_t garbage_root[32];
        ASSERT_EQ(vcs_blob_put_to(store, garbage, sizeof(garbage),
                                  garbage_root), VCS_BLOB_OK);
        char garbage_hex[65];
        zcl_hex_encode(garbage_root, 32, garbage_hex);
        ASSERT(!zcode_science_admit(store, &ndb_b, dir_b, garbage_hex, 1500,
                                    science_hex, kind, &is_new).ok);
        ASSERT_EQ(zstore_cas_object_count(dir_b), 1);
        const char *candidates[] = {garbage_hex, absent, blob_hex};
        char selected[65];
        size_t attempts = 0;
        ASSERT(zcode_science_admit_candidates(
            store, &ndb_b, dir_b, commit.result_root, candidates, 3, 1500,
            selected, kind, &is_new, &attempts).ok);
        ASSERT_EQ(attempts, 3);
        ASSERT_STR_EQ(selected, blob_hex);
        ASSERT_STR_EQ(kind, ZCODE_SCIENCE_KIND_STUDY);
        ASSERT(!is_new);
        ASSERT_EQ(zstore_cas_object_count(dir_b), 1);
        /* The native fetch path may retain the full bounded DHT shortlist.
         * Exercise more than the former eight-entry ceiling so its caller
         * and this admission API stay bound to the same K-sized contract. */
        const char *wide_candidates[VCS_ZCODE_DHT_K];
        for (size_t i = 0; i + 1 < VCS_ZCODE_DHT_K; i++)
            wide_candidates[i] = absent;
        wide_candidates[VCS_ZCODE_DHT_K - 1] = blob_hex;
        attempts = 0;
        ASSERT(zcode_science_admit_candidates(
            store, &ndb_b, dir_b, commit.result_root, wide_candidates,
            VCS_ZCODE_DHT_K, 1500, selected, kind, &is_new, &attempts).ok);
        ASSERT_EQ(attempts, VCS_ZCODE_DHT_K);
        ASSERT_STR_EQ(selected, blob_hex);
        vcs_package_store_close(store);
        zstore_teardown(&ndb_a, dir_a);
        zstore_teardown(&ndb_b, dir_b);
        {
            char cmd[ZSTORE_DIR_CAP + 16];
            n = snprintf(cmd, sizeof(cmd), "rm -rf '%s'", sdir);
            if (n > 0 && (size_t)n < sizeof(cmd))
                (void)system(cmd);
        }
        PASS();
    } _test_next:;
    return failures;
}

/* ── 9: findings plan/commit — the command-leaf admission reviews bind ── */

static int test_zstore_findings_plan_commit(void)
{
    int failures = 0;
    TEST("zcode_science_store: findings plan/commit is exact, idempotent, reviewable") {
        struct node_db ndb = {0};
        char dir[ZSTORE_DIR_CAP];
        ASSERT(zstore_setup(&ndb, dir, sizeof(dir)));
        struct vcs_zcode_study_spec_v1 study;
        struct vcs_zcode_benchmark_method_v1 method;
        struct vcs_zcode_hardware_profile_v1 profile;
        uint8_t task_root[32], candidate_root[32], result_root[32];
        ASSERT(zstore_seed_context(dir, &study, task_root, candidate_root,
                                   &method, &profile));
        struct vcs_zcode_benchmark_result_v2 result;
        zstore_result_v2(&study, task_root, candidate_root, &method,
                         &profile, VCS_ZCODE_BENCHMARK_OBSERVED, 1, 33,
                         &result);
        ASSERT(zstore_cas_put_result_v2(dir, &result, result_root));
        struct vcs_zcode_science_findings_v1 findings;
        zstore_findings(&study, task_root, candidate_root, result_root, 0,
                        NULL, 1800, &findings);
        uint8_t wire[VCS_ZCODE_SCIENCE_FINDINGS_WIRE_BYTES];
        ASSERT_EQ(vcs_zcode_science_findings_serialize(&findings, wire),
                  VCS_ZCODE_SCIENCE_OK);
        uint8_t expected_root[32];
        char expected_hex[65];
        ASSERT_EQ(vcs_zcode_science_findings_root(&findings, expected_root),
                  VCS_ZCODE_SCIENCE_OK);
        zcl_hex_encode(expected_root, 32, expected_hex);
        int cas_before = zstore_cas_object_count(dir);
        /* Plan, then idempotent re-plan of the same request. */
        struct zcode_science_plan_out plan, replan;
        ASSERT(zcode_science_findings_plan(&ndb, dir, wire, sizeof(wire),
                                           1900, &plan).ok);
        ASSERT(!plan.already_planned);
        ASSERT_EQ(plan.expires_unix, 1900 + ZCODE_SCIENCE_PLAN_TTL_SECONDS);
        ASSERT(zcode_science_findings_plan(&ndb, dir, wire, sizeof(wire),
                                           1901, &replan).ok);
        ASSERT(replan.already_planned);
        ASSERT_STR_EQ(replan.plan_root, plan.plan_root);
        /* Commit requires confirm:true. */
        struct zcode_science_commit_out commit;
        ASSERT(!zcode_science_findings_commit(&ndb, dir, wire, sizeof(wire),
                                              false, 1900, &commit).ok);
        /* Commit twice: same root, one CAS object. */
        ASSERT(zcode_science_findings_commit(&ndb, dir, wire, sizeof(wire),
                                             true, 1900, &commit).ok);
        ASSERT(!commit.already_committed);
        ASSERT_STR_EQ(commit.result_root, expected_hex);
        struct zcode_science_commit_out recommit;
        ASSERT(zcode_science_findings_commit(&ndb, dir, wire, sizeof(wire),
                                             true, 1902, &recommit).ok);
        ASSERT(recommit.already_committed);
        ASSERT_STR_EQ(recommit.result_root, expected_hex);
        ASSERT_EQ(zstore_cas_object_count(dir), cas_before + 1);
        /* A different findings wire is a different request: no plan. */
        struct vcs_zcode_science_findings_v1 stray_f = findings;
        stray_f.created_unix = 1801;
        uint8_t stray_wire[VCS_ZCODE_SCIENCE_FINDINGS_WIRE_BYTES];
        ASSERT_EQ(vcs_zcode_science_findings_serialize(&stray_f, stray_wire),
                  VCS_ZCODE_SCIENCE_OK);
        struct zcode_science_commit_out stray;
        ASSERT(!zcode_science_findings_commit(&ndb, dir, stray_wire,
                                              sizeof(stray_wire), true, 1900,
                                              &stray).ok);
        /* Malformed wires never plan: bad magic, truncated length. */
        uint8_t badmagic[VCS_ZCODE_SCIENCE_FINDINGS_WIRE_BYTES];
        memcpy(badmagic, wire, sizeof(badmagic));
        badmagic[0] ^= 1;
        struct zcode_science_plan_out bad;
        ASSERT(!zcode_science_findings_plan(&ndb, dir, badmagic,
                                            sizeof(badmagic), 1900, &bad).ok);
        ASSERT(!zcode_science_findings_plan(&ndb, dir, wire,
                                            sizeof(wire) - 1, 1900,
                                            &bad).ok);
        /* An expired plan refuses commit. */
        struct zcode_science_plan_out late_plan;
        struct zcode_science_commit_out late_commit;
        ASSERT(zcode_science_findings_plan(&ndb, dir, stray_wire,
                                           sizeof(stray_wire), 2000,
                                           &late_plan).ok);
        ASSERT(!zcode_science_findings_commit(
            &ndb, dir, stray_wire, sizeof(stray_wire), true,
            2000 + ZCODE_SCIENCE_PLAN_TTL_SECONDS, &late_commit).ok);
        /* Projection row mapping: discussed result in link_root, empty
         * retraction target in aux_root. */
        struct db_zcode_science_entry row;
        ASSERT(db_zcode_science_findings_find(&ndb, expected_hex, &row));
        ASSERT_STR_EQ(row.root, expected_hex);
        char result_hex[65];
        zcl_hex_encode(result_root, 32, result_hex);
        ASSERT_STR_EQ(row.link_root, result_hex);
        ASSERT_EQ(row.code, findings.severity);
        ASSERT_EQ(row.flags, findings.flags);
        ASSERT_EQ(row.sequence, 1);
        ASSERT_EQ(row.created_at, findings.created_unix);
        /* Rebuild equivalence: drop + rebuild from CAS, identical row. */
        struct zcode_science_rebuild_out rebuilt;
        ASSERT(zcode_science_rebuild(&ndb, dir, 1900, &rebuilt).ok);
        ASSERT_EQ(rebuilt.findings, 1);
        struct db_zcode_science_entry after;
        ASSERT(db_zcode_science_findings_find(&ndb, expected_hex, &after));
        ASSERT(memcmp(&row, &after, sizeof(row)) == 0);
        /* The CLI-admitted findings satisfies H1: a fresh review against it
         * plans and commits. */
        struct vcs_zcode_review_v1 review;
        memset(&review, 0, sizeof(review));
        review.schema_version = VCS_ZCODE_DEV_VERSION;
        memcpy(review.task_root, task_root, 32);
        memcpy(review.candidate_root, candidate_root, 32);
        zstore_root(review.proof_policy_root, 22);
        zstore_root(review.proof_set_root, 41);
        memcpy(review.findings_root, expected_root, 32);
        zstore_root(review.reviewer_pubkey, 45);
        review.verdict = VCS_ZCODE_REVIEW_APPROVE;
        review.sequence = 1;
        review.created_unix = 1900;
        uint8_t review_wire[VCS_ZCODE_REVIEW_WIRE_BYTES];
        ASSERT_EQ(vcs_zcode_review_serialize(&review, review_wire),
                  VCS_ZCODE_DEV_OK);
        struct zcode_science_plan_out rplan;
        struct zcode_science_commit_out rcommit;
        ASSERT(zcode_science_review_submit(&ndb, dir, review_wire,
                                           sizeof(review_wire), false, 1900,
                                           &rplan, &rcommit).ok);
        ASSERT(zcode_science_review_submit(&ndb, dir, review_wire,
                                           sizeof(review_wire), true, 1900,
                                           &rplan, &rcommit).ok);
        zstore_teardown(&ndb, dir);
        PASS();
    } _test_next:;
    return failures;
}

int test_zcode_science_store(void)
{
    int failures = 0;
    failures += test_zstore_study_plan_commit();
    failures += test_zstore_expiry();
    failures += test_zstore_malformed_objects();
    failures += test_zstore_evidence();
    failures += test_zstore_review_retraction();
    failures += test_zstore_votes();
    failures += test_zstore_publish();
    failures += test_zstore_admit();
    failures += test_zstore_findings_plan_commit();
    return failures;
}
