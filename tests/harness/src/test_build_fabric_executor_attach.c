/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Prove one real avoided build: a second eligible fixed-compile
 * request attaches to the first request's qualified physical result with its
 * own signed receipt, while reproduction requests and poisoned evidence are
 * refused by name and never reach a compiler. */
#if defined(__linux__) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif

#include "test/test_core.h"

#include "base/hex.h"
#include "crypto/ed25519.h"
#include "crypto/sha3.h"
#include "models/build_fabric.h"
#include "models/database.h"
#include "platform/time_compat.h"
#include "services/build_fabric_attach.h"
#include "services/build_fabric_service.h"
#include "services/build_fabric_worker.h"
#include "vcs/build_action.h"
#include "vcs/build_artifact_manifest.h"
#include "vcs/vcs_object.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined(__linux__)
#include "../../../engine/services/src/build_fabric_attach_identity_internal.h"
#include "util/spawn.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

static const char att_id_b[] =
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
static const char att_id_c[] =
    "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
static const char att_id_d[] =
    "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
static const char att_lease_b[] =
    "1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b";

static const uint8_t att_unit[] =
    "int zbuild_fixture(void) { return 23; }\n";

#if defined(__linux__)
static int att_open_fd_count(void)
{
    DIR *dir = opendir("/proc/self/fd");
    if (!dir) return -1;
    int count = 0;
    while (readdir(dir)) count++;
    closedir(dir);
    return count;
}

static bool att_cpu_us(int who, int64_t *out)
{
    struct rusage usage;
    if (!out || getrusage(who, &usage) != 0) return false;
    *out = (int64_t)usage.ru_utime.tv_sec * INT64_C(1000000) +
           usage.ru_utime.tv_usec +
           (int64_t)usage.ru_stime.tv_sec * INT64_C(1000000) +
           usage.ru_stime.tv_usec;
    return true;
}

static bool att_copy_executable(const char *from, const char *to)
{
    FILE *source = fopen(from, "rb");
    if (!source) return false;
    FILE *target = fopen(to, "wb");
    if (!target) { fclose(source); return false; }
    unsigned char buf[65536];
    size_t n;
    bool ok = true;
    while ((n = fread(buf, 1, sizeof(buf), source)) != 0)
        if (fwrite(buf, 1, n, target) != n) { ok = false; break; }
    if (ferror(source)) ok = false;
    if (fclose(source) != 0) ok = false;
    if (fclose(target) != 0) ok = false;
    return ok && chmod(to, 0700) == 0;
}

static int test_bf_attach_sealed_verifier_aba(void)
{
    int failures = 0;
    TEST("build_fabric_attach: sealed verifier survives A-B-A and closes fd") {
        char dir[256], path[320];
        test_make_tmpdir(dir, sizeof(dir), "build_fabric_attach", "verifier-aba");
        ASSERT(snprintf(path, sizeof(path), "%s/verifier", dir) > 0);
        ASSERT(att_copy_executable("/bin/echo", path));
        int before = att_open_fd_count();
        ASSERT(before >= 0);
        struct bfat_verifier_snapshot first = { .fd = -1 };
        ASSERT_RESULT_OK(bfat_verifier_snapshot_open(path, &first));
        ASSERT((fcntl(first.fd, F_GETFD) & FD_CLOEXEC) != 0);
        const int seals = F_SEAL_WRITE | F_SEAL_GROW |
                          F_SEAL_SHRINK | F_SEAL_SEAL;
        ASSERT((fcntl(first.fd, F_GET_SEALS) & seals) == seals);
        errno = 0;
        ASSERT(pwrite(first.fd, "X", 1, 0) == -1 && errno == EPERM);
        ASSERT(att_copy_executable("/bin/false", path));
        const char *argv[] = { path, "sealed-A-ran", NULL };
        char output[128];
        ASSERT(zcl_spawn_capture_cancelable_fd(first.fd, argv, output,
                 sizeof(output), 3000, NULL, NULL, NULL) == 0);
        ASSERT(strstr(output, "sealed-A-ran") != NULL);
        ASSERT(att_copy_executable("/bin/echo", path));
        struct bfat_verifier_snapshot restored = { .fd = -1 };
        ASSERT_RESULT_OK(bfat_verifier_snapshot_open(path, &restored));
        ASSERT(memcmp(first.bytes, restored.bytes, 32) == 0);
        bfat_verifier_snapshot_close(&restored);
        bfat_verifier_snapshot_close(&first);
        ASSERT(att_open_fd_count() == before);
        PASS();
    } _test_next:;
    return failures;
}
#endif

static bool att_open(struct node_db *ndb, char *dir, size_t dir_cap,
                     char *path, size_t path_cap, const char *tag)
{
    test_make_tmpdir(dir, dir_cap, "build_fabric_attach", tag);
    (void)snprintf(path, path_cap, "%s/node.db", dir);
    memset(ndb, 0, sizeof(*ndb));
    return node_db_open(ndb, path);
}

static void att_worker_id_from_pubkey(const uint8_t pubkey[32], char out[65])
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

/* A planned, canonical, submitted compile request. source_id/source_cas_id
 * carry the request's provenance; distinct requests differ there while every
 * executor-consumed input stays identical. */
static bool att_plan_request(struct node_db *ndb, const char *workspace,
                             const char *source_id, const char *source_cas_id,
                             const char *toolchain_hex,
                             const uint8_t input_root[32],
                             const char *profile, struct db_build_job *job,
                             struct db_build_action *action)
{
    memset(job, 0, sizeof(*job));
    memset(action, 0, sizeof(*action));
    (void)snprintf(job->source_sha256, sizeof(job->source_sha256), "%s",
                   source_id);
    (void)snprintf(job->source_cas_sha3, sizeof(job->source_cas_sha3), "%s",
                   source_cas_id);
    (void)snprintf(job->toolchain_sha3, sizeof(job->toolchain_sha3), "%s",
                   toolchain_hex);
    (void)snprintf(job->profile, sizeof(job->profile), "%s", profile);
    (void)snprintf(job->state, sizeof(job->state), "PLANNED");
    job->created_at = job->updated_at = 100;
    action->sequence = 0;
    (void)snprintf(action->kind, sizeof(action->kind), "%s",
                   VCS_BUILD_ACTION_KIND_V1);
    (void)snprintf(action->state, sizeof(action->state), "SNAPSHOTTED");
    zcl_hex_encode(input_root, 32, action->input_root_sha3);
    (void)snprintf(action->target, sizeof(action->target), "%s",
                   VCS_BUILD_TARGET_V1);
    uint8_t fixed_flags[32], fixed_environment[32];
    if (!vcs_build_action_v1_fixed_flags_root_for_kind(
            action->kind, fixed_flags) ||
        !vcs_build_action_v1_fixed_environment_root_for_kind(
            action->kind, fixed_environment))
        return false;
    zcl_hex_encode(fixed_flags, 32, action->flags_sha3);
    zcl_hex_encode(fixed_environment, 32, action->environment_sha3);
    (void)snprintf(action->virtual_workdir, sizeof(action->virtual_workdir),
                   "%s", VCS_BUILD_VIRTUAL_ROOT_V1);
    (void)snprintf(action->declared_outputs, sizeof(action->declared_outputs),
                   "%s", VCS_BUILD_OUTPUT_V1);
    (void)snprintf(action->resource_policy, sizeof(action->resource_policy),
                   "%s", VCS_BUILD_RESOURCE_POLICY_V1);
    action->created_at = action->updated_at = 101;
    if (!build_fabric_action_id(job, action, action->action_id).ok ||
        !build_fabric_job_id(job, action->action_id, job->job_id).ok)
        return false;
    (void)snprintf(action->job_id, sizeof(action->job_id), "%s", job->job_id);
    int64_t now = (int64_t)platform_time_wall_unix();
    (void)workspace;
    return build_fabric_plan(ndb, job, action).ok &&
           build_fabric_submit(ndb, job->job_id, now).ok;
}

static bool att_approve_worker(struct node_db *ndb, const uint8_t pubkey[32],
                               int64_t now)
{
    struct db_build_worker worker;
    memset(&worker, 0, sizeof(worker));
    att_worker_id_from_pubkey(pubkey, worker.worker_id);
    zcl_hex_encode(pubkey, 32, worker.signer_pubkey);
    (void)snprintf(worker.capabilities, sizeof(worker.capabilities),
                   "linux,x86-64-v3,gcc,%s", VCS_BUILD_ACTION_KIND_V1);
    worker.approved = 1;
    worker.approved_at = now;
    worker.last_seen_at = now;
    return build_fabric_worker_approve(ndb, &worker, now).ok;
}

/* Drive one REAL confined compile through the production worker path and
 * admit its receipt, so the donor is a fully qualified physical result. */
static bool att_physical_run(struct node_db *ndb, const char *workspace,
                             const char *action_id, const char *lease_id,
                             const uint8_t secret[32],
                             const uint8_t pubkey[32],
                             struct db_build_receipt *out_receipt,
                             int64_t *wall_us)
{
    struct db_build_action claimed;
    bool got = false;
    int64_t now = (int64_t)platform_time_wall_unix();
    if (!build_fabric_claim(ndb, out_receipt->worker_id, lease_id, now, 300,
                            &claimed, &got).ok || !got)
        return false;
    int64_t started = platform_time_monotonic_us();
    struct zcl_result executed = build_fabric_worker_execute(
        ndb, workspace, workspace, action_id, lease_id, secret, pubkey,
        out_receipt, NULL);
    *wall_us = platform_time_monotonic_us() - started;
    if (!executed.ok) {
        printf("worker detail: %s\n", executed.message);
        return false;
    }
    return build_fabric_receipt_admit(ndb, workspace,
                                      out_receipt->receipt_id,
                                      (int64_t)platform_time_wall_unix()).ok;
}

static int att_build_work_entries(const char *workspace)
{
    char path[512];
    int n = snprintf(path, sizeof(path), "%s/.zvcs/build-work", workspace);
    if (n <= 0 || (size_t)n >= sizeof(path)) return -1;
    char cmd[600];
    n = snprintf(cmd, sizeof(cmd),
                 "ls -A \"%s\" 2>/dev/null | wc -l", path);
    if (n <= 0 || (size_t)n >= sizeof(cmd)) return -1;
    FILE *p = popen(cmd, "r");
    if (!p) return -1;
    int entries = -1;
    if (fscanf(p, "%d", &entries) != 1) entries = -1;
    if (pclose(p) == -1) return -1;
    return entries;
}

static bool att_object_path(const char *workspace, const char *hex_id,
                            char *out, size_t cap)
{
    int n = snprintf(out, cap, "%s/.zvcs/objects/%.2s/%s", workspace, hex_id,
                     hex_id + 2);
    return n > 0 && (size_t)n < cap;
}

static bool att_read_artifact_bytes(const char *workspace,
                                    const char *manifest_root_hex,
                                    uint8_t **out, size_t *out_len)
{
    uint8_t root[32], *wire = NULL;
    size_t wire_len = 0;
    if (!zcl_hex_decode_lower(manifest_root_hex, root, 32) ||
        vcs_object_load_raw(workspace, root, &wire, &wire_len) != 0)
        return false;
    struct vcs_build_artifact_manifest_v1 manifest;
    bool ok = vcs_build_artifact_manifest_v1_parse(wire, wire_len, &manifest);
    free(wire);
    if (!ok || manifest.chunk_count != 1) return false;
    return vcs_object_load_raw(workspace, manifest.chunk_sha3[0], out,
                               out_len) == 0;
}

static int test_bf_attach_avoids_second_compile(void)
{
    int failures = 0;
    TEST("build_fabric_attach: equal-inputs duplicate attaches; compiler runs once") {
        struct node_db ndb;
        char dir[256], path[320];
        ASSERT(att_open(&ndb, dir, sizeof(dir), path, sizeof(path), "hit"));
        ASSERT(vcs_object_store_init(dir));
        uint8_t input_root[32];
        sha3_256(att_unit, sizeof(att_unit) - 1u, input_root);
        ASSERT(vcs_object_put_addressed(dir, input_root, att_unit,
                                        sizeof(att_unit) - 1u));
        struct vcs_toolchain_capsule_v1 capsule;
        uint8_t capsule_root[32];
        char capsule_hex[65];
        ASSERT(vcs_toolchain_capsule_v1_capture(&capsule));
        ASSERT(vcs_toolchain_capsule_v1_root(&capsule, capsule_root));
        zcl_hex_encode(capsule_root, 32, capsule_hex);

        uint8_t seed[32], pubkey[32], secret[32];
        memset(seed, 29, sizeof(seed));
        ed25519_keypair(pubkey, secret, seed);
        int64_t now = (int64_t)platform_time_wall_unix();
        ASSERT(att_approve_worker(&ndb, pubkey, now));

        struct db_build_job job_a;
        struct db_build_action action_a;
        ASSERT(att_plan_request(&ndb, dir, att_id_b, att_id_c, capsule_hex,
                                input_root, "dev-x86-64-v3", &job_a,
                                &action_a));
        struct db_build_receipt receipt_a;
        memset(&receipt_a, 0, sizeof(receipt_a));
        att_worker_id_from_pubkey(pubkey, receipt_a.worker_id);
        int64_t physical_wall_us = 0;
        ASSERT(att_physical_run(&ndb, dir, action_a.action_id, att_id_d,
                                secret, pubkey, &receipt_a,
                                &physical_wall_us));
        struct db_build_action durable_a;
        ASSERT(db_build_action_find(&ndb, action_a.action_id, &durable_a));
        ASSERT_STR_EQ(durable_a.state, "ACCEPTED");

        /* The physical run published its executor-key record: object id ==
         * key, derived from the exact bytes the executor consumed. */
        uint8_t input_bytes_root[32], key[32];
        sha3_256(att_unit, sizeof(att_unit) - 1u, input_bytes_root);
#if defined(__linux__)
        int64_t key_self_before, key_child_before;
        int64_t key_self_after, key_child_after;
        ASSERT(att_cpu_us(RUSAGE_SELF, &key_self_before));
        ASSERT(att_cpu_us(RUSAGE_CHILDREN, &key_child_before));
#endif
        int64_t key_started_us = platform_time_monotonic_us();
        struct zcl_result composed = build_fabric_executor_key_compose(
            dir, &durable_a, input_bytes_root, key);
        int64_t key_wall_us = platform_time_monotonic_us() - key_started_us;
#if defined(__linux__)
        ASSERT(att_cpu_us(RUSAGE_SELF, &key_self_after));
        ASSERT(att_cpu_us(RUSAGE_CHILDREN, &key_child_after));
#endif
        ASSERT_RESULT_OK(composed);
        ASSERT(vcs_object_has(dir, key));

        /* The donor also stores the canonical 19-field compiler-action
         * preimage. Reconstruct it independently from input and host facts,
         * then verify its CAS bytes and single-input key changes. */
        uint8_t driver[32], backend[32], assembler[32];
        ASSERT_RESULT_OK(build_fabric_executor_host_tool_hashes(
            driver, backend, assembler));
        uint8_t runtime[32], verifier[32];
        ASSERT_RESULT_OK(build_fabric_executor_host_runtime_roots(
            dir, runtime, verifier));
        uint8_t no_proof_policy[32] = {0};
        struct vcs_fixed_compile_proof_inputs proof_inputs = {
            .capsule = &capsule,
            .driver_bytes_sha3 = driver,
            .backend_bytes_sha3 = backend,
            .assembler_bytes_sha3 = assembler,
            .runtime_bytes_sha3 = runtime,
            .verifier_bytes_sha3 = verifier,
            .input_bytes_sha3 = input_bytes_root,
            .proof_policy_root = no_proof_policy,
            .target = VCS_BUILD_TARGET_V1,
            .resource_policy = VCS_BUILD_RESOURCE_POLICY_V1,
        };
        struct vcs_component_proof_key_v1 proof_a, proof_changed;
        ASSERT(vcs_build_action_v1_compile_proof_key(&proof_inputs,
                                                     &proof_a));
        uint8_t preimage_root[32], component_key[32];
        ASSERT(vcs_component_proof_key_preimage_root(&proof_a,
                                                     preimage_root));
        ASSERT(vcs_component_proof_key_derive(&proof_a, component_key));
        uint8_t *preimage_wire = NULL;
        size_t preimage_len = 0;
        ASSERT(vcs_object_load_raw(dir, preimage_root, &preimage_wire,
                                   &preimage_len) == 0);
        struct vcs_component_proof_key_v1 decoded;
        ASSERT(vcs_component_proof_key_decode(preimage_wire, preimage_len,
                                              &decoded));
        ASSERT_EQ(vcs_component_proof_key_diff(&proof_a, &decoded), 0);
        free(preimage_wire);
        uint8_t changed_input[32];
        memcpy(changed_input, input_bytes_root, 32);
        changed_input[0] ^= 1u;
        proof_inputs.input_bytes_sha3 = changed_input;
        ASSERT(vcs_build_action_v1_compile_proof_key(&proof_inputs,
                                                     &proof_changed));
        ASSERT_EQ(vcs_component_proof_key_diff(&proof_a, &proof_changed),
                  1u << VCS_CPK_SOURCE_CLOSURE);
        proof_inputs.input_bytes_sha3 = input_bytes_root;
        uint8_t changed_assembler[32];
        memcpy(changed_assembler, assembler, 32);
        changed_assembler[0] ^= 1u;
        proof_inputs.assembler_bytes_sha3 = changed_assembler;
        ASSERT(vcs_build_action_v1_compile_proof_key(&proof_inputs,
                                                     &proof_changed));
        ASSERT_EQ(vcs_component_proof_key_diff(&proof_a, &proof_changed),
                  1u << VCS_CPK_TOOLCHAIN);
        proof_inputs.assembler_bytes_sha3 = assembler;
        uint8_t changed_backend[32];
        memcpy(changed_backend, backend, 32);
        changed_backend[0] ^= 1u;
        proof_inputs.backend_bytes_sha3 = changed_backend;
        ASSERT(vcs_build_action_v1_compile_proof_key(&proof_inputs,
                                                     &proof_changed));
        ASSERT_EQ(vcs_component_proof_key_diff(&proof_a, &proof_changed),
                  1u << VCS_CPK_TOOLCHAIN);
        proof_inputs.backend_bytes_sha3 = backend;
        uint8_t changed_policy[32] = {1};
        proof_inputs.proof_policy_root = changed_policy;
        ASSERT(vcs_build_action_v1_compile_proof_key(&proof_inputs,
                                                     &proof_changed));
        ASSERT_EQ(vcs_component_proof_key_diff(&proof_a, &proof_changed),
                  1u << VCS_CPK_POLICY);

        /* Request B: distinct task/candidate/job provenance, identical .i
         * bytes, toolchain, flags, environment, target, policy, profile. */
        struct db_build_job job_b;
        struct db_build_action action_b;
        ASSERT(att_plan_request(&ndb, dir, att_id_c, att_id_b, capsule_hex,
                                input_root, "dev-x86-64-v3", &job_b,
                                &action_b));
        ASSERT(strcmp(action_b.action_id, action_a.action_id) != 0);
        int entries_before = att_build_work_entries(dir);
        ASSERT(entries_before >= 0);

        struct db_build_receipt receipt_b;
        struct build_fabric_attach_report report;
#if defined(__linux__)
        int fds_before_attach = att_open_fd_count();
        int64_t attach_self_before, attach_child_before;
        int64_t attach_self_after, attach_child_after;
        ASSERT(fds_before_attach >= 0);
        ASSERT(att_cpu_us(RUSAGE_SELF, &attach_self_before));
        ASSERT(att_cpu_us(RUSAGE_CHILDREN, &attach_child_before));
#endif
        struct zcl_result attached = build_fabric_attach(
            &ndb, dir, NULL, &job_b, &action_b, secret, pubkey, &receipt_b,
            &report);
#if defined(__linux__)
        ASSERT(att_cpu_us(RUSAGE_SELF, &attach_self_after));
        ASSERT(att_cpu_us(RUSAGE_CHILDREN, &attach_child_after));
        ASSERT(att_open_fd_count() == fds_before_attach);
#endif
        ASSERT_RESULT_OK(attached);
        ASSERT_EQ(report.disposition, BUILD_FABRIC_ATTACH_HIT);
        ASSERT_EQ(report.compiler_processes, 0);
        char key_hex[65];
        zcl_hex_encode(key, 32, key_hex);
        ASSERT_STR_EQ(report.executor_key, key_hex);
        ASSERT_STR_EQ(report.donor_action_id, action_a.action_id);
        ASSERT_STR_EQ(report.donor_receipt_id, receipt_a.receipt_id);
        ASSERT(report.requester_receipt_id[0]);
        ASSERT(report.restored_bytes > 0);

        struct db_build_action durable_b;
        ASSERT(db_build_action_find(&ndb, action_b.action_id, &durable_b));
        ASSERT_STR_EQ(durable_b.state, "CACHE_HIT");
        ASSERT_STR_EQ(durable_b.outcome, "CACHE_HIT");
        ASSERT_STR_EQ(durable_b.output_root_sha3, durable_a.output_root_sha3);
        struct db_build_job durable_job_b;
        ASSERT(db_build_job_find(&ndb, job_b.job_id, &durable_job_b));
        ASSERT_STR_EQ(durable_job_b.state, "CACHE_HIT");

        /* Two DISTINCT signed receipts: different ids and action ids, the
         * SAME physical observation root and output root. */
        ASSERT(strcmp(receipt_b.receipt_id, receipt_a.receipt_id) != 0);
        ASSERT_STR_EQ(receipt_b.action_id, action_b.action_id);
        ASSERT_STR_EQ(receipt_b.action_sha3, action_b.action_id);
        ASSERT_STR_EQ(receipt_b.observation_sha3, receipt_a.observation_sha3);
        ASSERT_STR_EQ(receipt_b.output_sha3, receipt_a.output_sha3);
        ASSERT_STR_EQ(receipt_b.trust_state, "LOCAL_ACCEPTED");
        ASSERT_STR_EQ(receipt_b.lease_id, key_hex);
        ASSERT(strstr(receipt_b.confinement, "executor-attach=1") != NULL);
        struct db_build_receipt persisted_b;
        ASSERT(db_build_receipt_find(&ndb, receipt_b.receipt_id,
                                     &persisted_b));
        ASSERT_STR_EQ(persisted_b.signature, receipt_b.signature);

        /* The requester's restored output bytes equal the donor's. */
        uint8_t *bytes_a = NULL, *bytes_b = NULL;
        size_t len_a = 0, len_b = 0;
        ASSERT(att_read_artifact_bytes(dir, receipt_a.output_sha3, &bytes_a,
                                       &len_a));
        ASSERT(att_read_artifact_bytes(dir, report.output_copy_sha3, &bytes_b,
                                       &len_b));
        ASSERT_EQ(len_a, len_b);
        ASSERT_EQ(memcmp(bytes_a, bytes_b, len_a), 0);
        free(bytes_a);
        free(bytes_b);

        /* No staging area and no compiler process for B. */
        ASSERT_EQ(att_build_work_entries(dir), entries_before);

        /* A distinct, real submitted request with changed compiler input
         * cannot borrow A's physical result. */
        static const uint8_t changed_unit[] =
            "int zbuild_fixture(void) { return 24; }\n";
        uint8_t changed_root[32];
        sha3_256(changed_unit, sizeof(changed_unit) - 1u, changed_root);
        ASSERT(vcs_object_put_addressed(dir, changed_root, changed_unit,
                                        sizeof(changed_unit) - 1u));
        struct db_build_job job_c;
        struct db_build_action action_c;
        ASSERT(att_plan_request(&ndb, dir, att_id_d, att_id_b, capsule_hex,
                                changed_root, "dev-x86-64-v3", &job_c,
                                &action_c));
        struct db_build_receipt receipt_c;
        struct build_fabric_attach_report miss;
        struct zcl_result distinct = build_fabric_attach(
            &ndb, dir, NULL, &job_c, &action_c, secret, pubkey, &receipt_c,
            &miss);
        ASSERT_RESULT_OK(distinct);
        ASSERT_EQ(miss.disposition, BUILD_FABRIC_ATTACH_MISS);
        ASSERT(strcmp(miss.executor_key, key_hex) != 0);
        ASSERT_EQ(att_build_work_entries(dir), entries_before);
        printf("attach cost report: physical_compile_us=%lld "
               "key_compose_us=%lld attach_us=%lld restored_bytes=%llu "
               "compiler_runs=1",
               (long long)physical_wall_us,
               (long long)key_wall_us,
               (long long)report.attach_wall_us,
               (unsigned long long)report.restored_bytes);
#if defined(__linux__)
        printf(" key_self_cpu_us=%lld key_child_cpu_us=%lld "
               "attach_self_cpu_us=%lld attach_child_cpu_us=%lld",
               (long long)(key_self_after - key_self_before),
               (long long)(key_child_after - key_child_before),
               (long long)(attach_self_after - attach_self_before),
               (long long)(attach_child_after - attach_child_before));
#endif
        printf("\n");

        /* A second attach of the now-completed action refuses by name. */
        struct build_fabric_attach_report again;
        struct zcl_result repeat = build_fabric_attach(
            &ndb, dir, NULL, &job_b, &action_b, secret, pubkey, &receipt_b,
            &again);
        ASSERT(!repeat.ok);
        ASSERT_EQ(again.disposition, BUILD_FABRIC_ATTACH_REFUSED);
        ASSERT_STR_EQ(again.refusal, "attach-refused-action-state");
        node_db_close(&ndb);
        test_rm_rf(dir);
        PASS();
    } _test_next:;
    return failures;
}

static int test_bf_attach_executor_key_binds_tool_bytes(void)
{
    int failures = 0;
    TEST("build_fabric_attach: executor key binds assembler bytes, capsule binds version") {
        uint8_t driver[32], backend[32], assembler[32];
        struct zcl_result tools = build_fabric_executor_host_tool_hashes(
            driver, backend, assembler);
        ASSERT_RESULT_OK(tools);
        struct vcs_toolchain_capsule_v1 capsule;
        ASSERT(vcs_toolchain_capsule_v1_capture(&capsule));
        /* The capsule's assembler identity is the --version STRING hash; it
         * provably is not the assembler file-bytes hash. That is the gap the
         * executor key closes. (No end-to-end stub-assembler variant exists:
         * platform_toolchain_capture_descriptor resolves the fixed compiled-in
         * toolchain paths and honors no environment override.) */
        ASSERT(memcmp(capsule.assembler_sha3, assembler, 32) != 0);

        const char *old_compiler_path = getenv("COMPILER_PATH");
        char *saved_compiler_path = old_compiler_path
            ? strdup(old_compiler_path) : NULL;
        ASSERT(!old_compiler_path || saved_compiler_path);
        ASSERT(setenv("COMPILER_PATH", "/bin", 1) == 0);
        struct vcs_toolchain_capsule_v1 overridden;
        bool captured_override = vcs_toolchain_capsule_v1_capture(
            &overridden);
        uint8_t driver_override[32], backend_override[32];
        uint8_t assembler_override[32];
        struct zcl_result hashed_override =
            build_fabric_executor_host_tool_hashes(
                driver_override, backend_override, assembler_override);
        if (saved_compiler_path) {
            (void)setenv("COMPILER_PATH", saved_compiler_path, 1);
            free(saved_compiler_path);
        } else {
            (void)unsetenv("COMPILER_PATH");
        }
        ASSERT(captured_override);
        ASSERT_RESULT_OK(hashed_override);
        ASSERT_EQ(memcmp(&overridden, &capsule, sizeof(capsule)), 0);
        ASSERT_EQ(memcmp(driver_override, driver, 32), 0);
        ASSERT_EQ(memcmp(backend_override, backend, 32), 0);
        ASSERT_EQ(memcmp(assembler_override, assembler, 32), 0);

        uint8_t fixed_flags[32], fixed_environment[32], input_root[32];
        ASSERT(vcs_build_action_v1_fixed_flags_root_for_kind(
            VCS_BUILD_ACTION_KIND_V1, fixed_flags));
        ASSERT(vcs_build_action_v1_fixed_environment_root_for_kind(
            VCS_BUILD_ACTION_KIND_V1, fixed_environment));
        sha3_256(att_unit, sizeof(att_unit) - 1u, input_root);
        uint8_t toolchain_root[32], key_a[32], key_b[32];
        build_fabric_executor_toolchain_root(driver, backend, assembler,
                                             toolchain_root);
        build_fabric_executor_key_from_parts(
            VCS_BUILD_ACTION_KIND_V1, VCS_BUILD_TARGET_V1,
            VCS_BUILD_RESOURCE_POLICY_V1, VCS_BUILD_OUTPUT_V1, fixed_flags,
            fixed_environment, NULL, toolchain_root, input_root, key_a);
        uint8_t mutated_assembler[32];
        memcpy(mutated_assembler, assembler, 32);
        mutated_assembler[0] ^= 1u;
        uint8_t mutated_toolchain_root[32];
        build_fabric_executor_toolchain_root(driver, backend,
                                             mutated_assembler,
                                             mutated_toolchain_root);
        build_fabric_executor_key_from_parts(
            VCS_BUILD_ACTION_KIND_V1, VCS_BUILD_TARGET_V1,
            VCS_BUILD_RESOURCE_POLICY_V1, VCS_BUILD_OUTPUT_V1, fixed_flags,
            fixed_environment, NULL, mutated_toolchain_root, input_root,
            key_b);
        ASSERT(memcmp(toolchain_root, mutated_toolchain_root, 32) != 0);
        ASSERT(memcmp(key_a, key_b, 32) != 0);

        /* A changed fixed-flags root is a different executor key, so a
         * flag-mutated request can never see a donor record: a clean MISS. */
        uint8_t mutated_flags[32], key_c[32];
        memcpy(mutated_flags, fixed_flags, 32);
        mutated_flags[0] ^= 1u;
        build_fabric_executor_key_from_parts(
            VCS_BUILD_ACTION_KIND_V1, VCS_BUILD_TARGET_V1,
            VCS_BUILD_RESOURCE_POLICY_V1, VCS_BUILD_OUTPUT_V1, mutated_flags,
            fixed_environment, NULL, toolchain_root, input_root, key_c);
        ASSERT(memcmp(key_a, key_c, 32) != 0);
        struct vcs_build_input_screen_v1 screen;
        vcs_build_input_screen_v1_init(&screen);
        ASSERT(vcs_build_input_screen_v1_update(&screen, att_unit,
                                                sizeof(att_unit) - 1u));
        ASSERT(vcs_build_input_screen_v1_finish(&screen));
        static const uint8_t external_read[] =
            "__asm__(\".incbin \\\"/etc/hosts\\\"\");\n";
        vcs_build_input_screen_v1_init(&screen);
        ASSERT(!vcs_build_input_screen_v1_update(
            &screen, external_read, sizeof(external_read) - 1u));
        static const uint8_t spliced_keyword[] =
            "__as\\\nm__(\".incbin \\\"/etc/hosts\\\"\");\n";
        vcs_build_input_screen_v1_init(&screen);
        ASSERT(!vcs_build_input_screen_v1_update(
            &screen, spliced_keyword, sizeof(spliced_keyword) - 1u));
        static const uint8_t carriage_return_marker[] =
            "# 1 \"x\"\r__asm__(\".incbin \\\"/etc/hosts\\\"\");\r";
        vcs_build_input_screen_v1_init(&screen);
        ASSERT(!vcs_build_input_screen_v1_update(
            &screen, carriage_return_marker,
            sizeof(carriage_return_marker) - 1u));
        static const uint8_t section_directive[] =
            "int x __attribute__((section(\".foo\\n.incbin "
            "\\\"/etc/hosts\\\"\\n\")));\n";
        vcs_build_input_screen_v1_init(&screen);
        ASSERT(!vcs_build_input_screen_v1_update(
            &screen, section_directive,
            sizeof(section_directive) - 1u));
        PASS();
    } _test_next:;
    return failures;
}

static int test_bf_attach_miss_and_poisoned_record(void)
{
    int failures = 0;
    TEST("build_fabric_attach: no donor record is a clean miss; poisoned record refuses") {
        struct node_db ndb;
        char dir[256], path[320];
        ASSERT(att_open(&ndb, dir, sizeof(dir), path, sizeof(path), "miss"));
        ASSERT(vcs_object_store_init(dir));
        uint8_t input_root[32];
        sha3_256(att_unit, sizeof(att_unit) - 1u, input_root);
        ASSERT(vcs_object_put_addressed(dir, input_root, att_unit,
                                        sizeof(att_unit) - 1u));
        struct vcs_toolchain_capsule_v1 capsule;
        uint8_t capsule_root[32];
        char capsule_hex[65];
        ASSERT(vcs_toolchain_capsule_v1_capture(&capsule));
        ASSERT(vcs_toolchain_capsule_v1_root(&capsule, capsule_root));
        zcl_hex_encode(capsule_root, 32, capsule_hex);
        uint8_t seed[32], pubkey[32], secret[32];
        memset(seed, 31, sizeof(seed));
        ed25519_keypair(pubkey, secret, seed);
        ASSERT(att_approve_worker(&ndb, pubkey,
                                  (int64_t)platform_time_wall_unix()));
        struct db_build_job job;
        struct db_build_action action;
        ASSERT(att_plan_request(&ndb, dir, att_id_b, att_id_c, capsule_hex,
                                input_root, "dev-x86-64-v3", &job, &action));

        struct db_build_receipt receipt;
        struct build_fabric_attach_report report;
        struct zcl_result miss = build_fabric_attach(
            &ndb, dir, NULL, &job, &action, secret, pubkey, &receipt, &report);
        ASSERT_RESULT_OK(miss);
        ASSERT_EQ(report.disposition, BUILD_FABRIC_ATTACH_MISS);
        ASSERT_EQ(report.compiler_processes, 0);
        ASSERT_EQ(att_build_work_entries(dir), 0);

        /* A record that does not re-derive to its own address is poison. */
        uint8_t key[32];
        ASSERT(zcl_hex_decode_lower(report.executor_key, key, 32));
        static const uint8_t garbage[] = "not-an-executor-key-record";
        ASSERT(vcs_object_put_addressed(dir, key, garbage,
                                        sizeof(garbage) - 1u));
        struct zcl_result poisoned = build_fabric_attach(
            &ndb, dir, NULL, &job, &action, secret, pubkey, &receipt, &report);
        ASSERT(!poisoned.ok);
        ASSERT_EQ(report.disposition, BUILD_FABRIC_ATTACH_REFUSED);
        ASSERT_STR_EQ(report.refusal, "executor-key-record-poisoned");
        struct db_build_action durable;
        ASSERT(db_build_action_find(&ndb, action.action_id, &durable));
        ASSERT_STR_EQ(durable.state, "QUEUED");
        node_db_close(&ndb);
        test_rm_rf(dir);
        PASS();
    } _test_next:;
    return failures;
}

static int test_bf_attach_input_cas_refusals(void)
{
    int failures = 0;
    TEST("build_fabric_attach: corrupt or missing input CAS refuses before staging") {
        struct node_db ndb;
        char dir[256], path[320];
        ASSERT(att_open(&ndb, dir, sizeof(dir), path, sizeof(path), "cas"));
        ASSERT(vcs_object_store_init(dir));
        uint8_t input_root[32];
        sha3_256(att_unit, sizeof(att_unit) - 1u, input_root);
        ASSERT(vcs_object_put_addressed(dir, input_root, att_unit,
                                        sizeof(att_unit) - 1u));
        struct vcs_toolchain_capsule_v1 capsule;
        uint8_t capsule_root[32];
        char capsule_hex[65];
        ASSERT(vcs_toolchain_capsule_v1_capture(&capsule));
        ASSERT(vcs_toolchain_capsule_v1_root(&capsule, capsule_root));
        zcl_hex_encode(capsule_root, 32, capsule_hex);
        uint8_t seed[32], pubkey[32], secret[32];
        memset(seed, 37, sizeof(seed));
        ed25519_keypair(pubkey, secret, seed);
        ASSERT(att_approve_worker(&ndb, pubkey,
                                  (int64_t)platform_time_wall_unix()));
        struct db_build_job job;
        struct db_build_action action;
        ASSERT(att_plan_request(&ndb, dir, att_id_b, att_id_c, capsule_hex,
                                input_root, "dev-x86-64-v3", &job, &action));
        char object_path[600];
        char input_hex[65];
        zcl_hex_encode(input_root, 32, input_hex);
        ASSERT(att_object_path(dir, input_hex, object_path,
                               sizeof(object_path)));
        struct db_build_receipt receipt;
        struct build_fabric_attach_report report;

        ASSERT(remove(object_path) == 0);
        struct zcl_result missing = build_fabric_attach(
            &ndb, dir, NULL, &job, &action, secret, pubkey, &receipt, &report);
        ASSERT(!missing.ok);
        ASSERT_STR_EQ(report.refusal, "input-cas-miss");
        ASSERT_EQ(report.compiler_processes, 0);
        ASSERT_EQ(att_build_work_entries(dir), 0);

        ASSERT(vcs_object_put_addressed(dir, input_root, att_unit,
                                        sizeof(att_unit) - 1u));
        FILE *f = fopen(object_path, "r+b");
        ASSERT(f != NULL);
        int first = fgetc(f);
        ASSERT(first != EOF);
        ASSERT(fseek(f, 0, SEEK_SET) == 0);
        ASSERT(fputc(first ^ 1, f) != EOF);
        ASSERT(fclose(f) == 0);
        struct zcl_result corrupt = build_fabric_attach(
            &ndb, dir, NULL, &job, &action, secret, pubkey, &receipt, &report);
        ASSERT(!corrupt.ok);
        ASSERT_STR_EQ(report.refusal, "input-cas-corrupt");
        ASSERT_EQ(att_build_work_entries(dir), 0);
        struct db_build_action durable;
        ASSERT(db_build_action_find(&ndb, action.action_id, &durable));
        ASSERT_STR_EQ(durable.state, "QUEUED");
        node_db_close(&ndb);
        test_rm_rf(dir);
        PASS();
    } _test_next:;
    return failures;
}

static int test_bf_attach_unobserved_assembler_input_refused(void)
{
    int failures = 0;
    TEST("build_fabric_attach: assembler file input refuses before compiler") {
        static const uint8_t external_read[] =
            "__asm__(\".incbin \\\"/etc/hosts\\\"\");\n";
        struct node_db ndb;
        char dir[256], path[320];
        ASSERT(att_open(&ndb, dir, sizeof(dir), path, sizeof(path), "incbin"));
        ASSERT(vcs_object_store_init(dir));
        uint8_t input_root[32];
        sha3_256(external_read, sizeof(external_read) - 1u, input_root);
        ASSERT(vcs_object_put_addressed(dir, input_root, external_read,
                                        sizeof(external_read) - 1u));
        struct vcs_toolchain_capsule_v1 capsule;
        uint8_t capsule_root[32];
        char capsule_hex[65];
        ASSERT(vcs_toolchain_capsule_v1_capture(&capsule));
        ASSERT(vcs_toolchain_capsule_v1_root(&capsule, capsule_root));
        zcl_hex_encode(capsule_root, 32, capsule_hex);
        uint8_t seed[32], pubkey[32], secret[32];
        memset(seed, 41, sizeof(seed));
        ed25519_keypair(pubkey, secret, seed);
        ASSERT(att_approve_worker(&ndb, pubkey,
                                  (int64_t)platform_time_wall_unix()));
        struct db_build_job job;
        struct db_build_action action;
        ASSERT(att_plan_request(&ndb, dir, att_id_b, att_id_c, capsule_hex,
                                input_root, "dev-x86-64-v3", &job, &action));
        struct db_build_receipt receipt;
        struct build_fabric_attach_report report;
        struct zcl_result attached = build_fabric_attach(
            &ndb, dir, NULL, &job, &action, secret, pubkey, &receipt, &report);
        ASSERT(!attached.ok);
        ASSERT_STR_EQ(report.refusal, "input-dependency-closure-unknown");
        ASSERT_EQ(report.compiler_processes, 0);
        memset(&receipt, 0, sizeof(receipt));
        att_worker_id_from_pubkey(pubkey, receipt.worker_id);
        struct db_build_action claimed;
        bool got = false;
        ASSERT_RESULT_OK(build_fabric_claim(
            &ndb, receipt.worker_id, att_lease_b,
            (int64_t)platform_time_wall_unix(), 300, &claimed, &got));
        ASSERT(got);
        struct zcl_result executed = build_fabric_worker_execute(
            &ndb, dir, dir, action.action_id, att_lease_b, secret, pubkey,
            &receipt, NULL);
        ASSERT(!executed.ok);
        ASSERT_EQ(att_build_work_entries(dir), 0);
        node_db_close(&ndb);
        test_rm_rf(dir);
        PASS();
    } _test_next:;
    return failures;
}

static int test_bf_attach_reproduction_never_attaches(void)
{
    int failures = 0;
    TEST("build_fabric_attach: independent reproduction refuses attach and runs physically") {
        struct node_db ndb;
        char dir[256], path[320];
        ASSERT(att_open(&ndb, dir, sizeof(dir), path, sizeof(path), "repro"));
        ASSERT(vcs_object_store_init(dir));
        uint8_t input_root[32];
        sha3_256(att_unit, sizeof(att_unit) - 1u, input_root);
        ASSERT(vcs_object_put_addressed(dir, input_root, att_unit,
                                        sizeof(att_unit) - 1u));
        struct vcs_toolchain_capsule_v1 capsule;
        uint8_t capsule_root[32];
        char capsule_hex[65];
        ASSERT(vcs_toolchain_capsule_v1_capture(&capsule));
        ASSERT(vcs_toolchain_capsule_v1_root(&capsule, capsule_root));
        zcl_hex_encode(capsule_root, 32, capsule_hex);
        uint8_t seed[32], pubkey[32], secret[32];
        memset(seed, 29, sizeof(seed));
        ed25519_keypair(pubkey, secret, seed);
        int64_t now = (int64_t)platform_time_wall_unix();
        ASSERT(att_approve_worker(&ndb, pubkey, now));

        struct db_build_job job_a;
        struct db_build_action action_a;
        ASSERT(att_plan_request(&ndb, dir, att_id_b, att_id_c, capsule_hex,
                                input_root, "dev-x86-64-v3", &job_a,
                                &action_a));
        struct db_build_receipt receipt_a;
        memset(&receipt_a, 0, sizeof(receipt_a));
        att_worker_id_from_pubkey(pubkey, receipt_a.worker_id);
        int64_t wall_a = 0;
        ASSERT(att_physical_run(&ndb, dir, action_a.action_id, att_id_d,
                                secret, pubkey, &receipt_a, &wall_a));

        /* The mandated independent run: same everything, distinct profile. */
        char repro_action_id[65], repro_job_id[65];
        ASSERT(build_fabric_plan_reproduction(
            &ndb, action_a.action_id, VCS_BUILD_PROFILE_PHYSICAL_REPRODUCTION_V1,
            now, repro_action_id, repro_job_id).ok);
        struct db_build_action action_c;
        struct db_build_job job_c;
        ASSERT(db_build_action_find(&ndb, repro_action_id, &action_c));
        ASSERT(db_build_job_find(&ndb, repro_job_id, &job_c));
        ASSERT_STR_EQ(job_c.profile,
                      VCS_BUILD_PROFILE_PHYSICAL_REPRODUCTION_V1);

        struct db_build_receipt receipt_c;
        struct build_fabric_attach_report report;
        struct zcl_result refused = build_fabric_attach(
            &ndb, dir, NULL, &job_c, &action_c, secret, pubkey, &receipt_c,
            &report);
        ASSERT(!refused.ok);
        ASSERT_EQ(report.disposition, BUILD_FABRIC_ATTACH_REFUSED);
        ASSERT_STR_EQ(report.refusal,
                      "attach-refused-independent-run-required");
        ASSERT_EQ(att_build_work_entries(dir), 0);

        /* The reproduction then executes physically: a second real compile. */
        ASSERT(build_fabric_submit(&ndb, job_c.job_id, now).ok);
        memset(&receipt_c, 0, sizeof(receipt_c));
        att_worker_id_from_pubkey(pubkey, receipt_c.worker_id);
        int64_t wall_c = 0;
        ASSERT(att_physical_run(&ndb, dir, action_c.action_id, att_lease_b,
                                secret, pubkey, &receipt_c, &wall_c));
        struct db_build_action durable_c;
        ASSERT(db_build_action_find(&ndb, action_c.action_id, &durable_c));
        ASSERT_STR_EQ(durable_c.state, "ACCEPTED");
        ASSERT(strcmp(receipt_c.receipt_id, receipt_a.receipt_id) != 0);
        ASSERT(strcmp(receipt_c.action_id, receipt_a.action_id) != 0);
        ASSERT(strcmp(receipt_c.observation_sha3, receipt_a.observation_sha3) != 0);
        /* Manifests bind different actions; their compiled object bytes must
         * still agree across the two lease directories. */
        uint8_t *object_a = NULL, *object_c = NULL;
        size_t object_a_len = 0, object_c_len = 0;
        ASSERT(att_read_artifact_bytes(dir, receipt_a.output_sha3,
                                       &object_a, &object_a_len));
        ASSERT(att_read_artifact_bytes(dir, receipt_c.output_sha3,
                                       &object_c, &object_c_len));
        ASSERT_EQ(object_c_len, object_a_len);
        ASSERT_EQ(memcmp(object_c, object_a, object_a_len), 0);
        free(object_a);
        free(object_c);
        ASSERT(receipt_c.observation_sha3[0] &&
               receipt_a.observation_sha3[0]);
        printf("independent runs preserved: physical compiler runs=2 "
               "(primary_us=%lld reproduction_us=%lld) attaches=0\n",
               (long long)wall_a, (long long)wall_c);
        node_db_close(&ndb);
        test_rm_rf(dir);
        PASS();
    } _test_next:;
    return failures;
}

int test_build_fabric_attach(void)
{
    int failures = 0;
#if defined(__linux__)
    failures += test_bf_attach_sealed_verifier_aba();
#endif
    failures += test_bf_attach_executor_key_binds_tool_bytes();
    failures += test_bf_attach_miss_and_poisoned_record();
    failures += test_bf_attach_input_cas_refusals();
    failures += test_bf_attach_unobserved_assembler_input_refused();
    failures += test_bf_attach_avoids_second_compile();
    failures += test_bf_attach_reproduction_never_attaches();
    printf("=== build_fabric_attach: %d failures ===\n", failures);
    return failures;
}
