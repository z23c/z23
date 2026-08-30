/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_zcode_benchmark_exec — the S4 closed benchmark/reproduction
 * executor slice of the ZCODE Scientific Metaverse: receipt codecs,
 * confined fixed-action runs, and admission through the landed S3
 * plan/commit path.
 *
 * Proofs:
 *   1. Codec KATs: golden wires/roots for workload bundle, raw-sample
 *      manifest, sample payload, benchmark evidence, and environment
 *      policy; exact-length parsers reject trailing bytes and zero the
 *      output on every failure.
 *   2. Happy path: execute a benchmark end to end (confined child, CAS
 *      artifacts, S3 commit); the receipt verifier re-derives every root.
 *   3. Deterministic envelope: two runs of one recipe + action + method +
 *      now produce identical result wires except the evidence root (the
 *      sample payload carrier); method/profile/manifest roots are stable.
 *   4. Raw-sample manifest (and sample payload) tamper: a flipped byte in
 *      the CAS file breaks root agreement and the receipt is rejected.
 *   5. Environment-policy mismatch: a study policy the host cannot meet
 *      refuses execution before any run or CAS write.
 *   6. Null and negative results are valid observations: an empty
 *      workload commits as NULL_RESULT; a NEGATIVE_RESULT status admits;
 *      a CONTRADICTED reproduction commits.
 *   7. The executor refuses to run when the sandbox self-check fails
 *      (injected), and the real canary escape suite passes on this host.
 *   8. Crash discipline: a killed child stores nothing (no partial
 *      finished results in CAS, unchanged object count), a retry of the
 *      same artifacts is idempotent by plan identity, and a run that
 *      never reaches admission leaves no projection row.
 *   9. Closed-input rejection: free-form shell strings, unregistered and
 *      non-benchmark registry kinds, roots not present in CAS, and
 *      trailing bytes in a stored workload wire are all refused.
 *  10. Reproduction: a v1 original is re-run under the same fixed action
 *      (same canonical action root), the verdict compares distributions
 *      under the method tolerance, and the reproduction.v1 commits; a
 *      mismatched action sequence is refused before running.
 *
 * Services run in-process on ./test-tmp workspaces and node.db files; the
 * confined children exercise the real os_sandbox backend (Landlock +
 * seccomp + rlimits), never a mock. */

#include "test/test_core.h"

#include "base/hex.h"
#include "models/database.h"
#include "platform/os_sandbox.h"
#include "services/zcode_benchmark_executor.h"
#include "services/zcode_science_service.h"
#include "services/shop_fulfill_evidence_service.h"
#include "vcs/build_action.h"
#include "vcs/vcs_object.h"
#include "vcs/zcode_benchmark_receipt.h"
#include "vcs/zcode_dev.h"
#include "vcs/zcode_science.h"
#include "vcs/zcode_science_index.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if !defined(_WIN32)
#include <sys/socket.h>
#include <sys/wait.h>
#endif
#include <sys/stat.h>
#include <unistd.h>

#if !defined(_WIN32)
#define ZBEX_DIR_CAP 512
#define ZBEX_NOW 1400

static int g_zbex_seq;

static void zbex_root(uint8_t out[32], uint8_t value)
{
    memset(out, value, 32);
}

static bool zbex_setup(struct node_db *ndb, char *dir, size_t cap)
{
    int n = snprintf(dir, cap, "test-tmp/zcode_benchmark_exec_%d_%d",
                     (int)getpid(), g_zbex_seq++);
    if (n <= 0 || (size_t)n >= cap)
        return false;
    char cmd[ZBEX_DIR_CAP * 2 + 32];
    n = snprintf(cmd, sizeof(cmd), "rm -rf '%s' && mkdir -p '%s'", dir, dir);
    if (n <= 0 || (size_t)n >= sizeof(cmd) || system(cmd) != 0)
        return false;
    char db[ZBEX_DIR_CAP + 16];
    n = snprintf(db, sizeof(db), "%s/node.db", dir);
    return n > 0 && (size_t)n < sizeof(db) && node_db_open(ndb, db) &&
           vcs_object_store_init(dir);
}

static void zbex_teardown(struct node_db *ndb, const char *dir)
{
    node_db_close(ndb);
    char cmd[ZBEX_DIR_CAP + 16];
    int n = snprintf(cmd, sizeof(cmd), "rm -rf '%s'", dir);
    if (n > 0 && (size_t)n < sizeof(cmd))
        (void)system(cmd);
}

/* The shop surface receives a node datadir and resolves its science
 * workspace at <datadir>/zcode. These executor fixtures use the datadir
 * itself as the workspace, so this local alias preserves identical bytes. */
static bool zbex_shop_workspace_alias(const char *dir)
{
    char path[ZBEX_DIR_CAP + 16];
    int n = snprintf(path, sizeof(path), "%s/zcode", dir);
    return n > 0 && (size_t)n < sizeof(path) && symlink(".", path) == 0;
}

/* Count files under <dir>/.zvcs/objects/<shard>/. */
static int zbex_cas_object_count(const char *workspace)
{
    char objects[ZBEX_DIR_CAP + 24];
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
        char shard[ZBEX_DIR_CAP + 32];
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

/* Rewrite one byte of the CAS object addressed by root_hex. */
static bool zbex_cas_flip_byte(const char *workspace, const char *root_hex,
                               size_t offset)
{
    char path[ZBEX_DIR_CAP + 96];
    int n = snprintf(path, sizeof(path), "%s/.zvcs/objects/%.2s/%s",
                     workspace, root_hex, root_hex + 2);
    if (n <= 0 || (size_t)n >= sizeof(path))
        return false;
    FILE *f = fopen(path, "rb+");
    if (!f)
        return false;
    if (fseek(f, (long)offset, SEEK_SET) != 0) {
        fclose(f);
        return false;
    }
    int byte = fgetc(f);
    if (byte == EOF || fseek(f, (long)offset, SEEK_SET) != 0) {
        fclose(f);
        return false;
    }
    fputc(byte ^ 0xff, f);
    fclose(f);
    return true;
}

/* ── fixtures ────────────────────────────────────────────────────────── */

#define ZBEX_WORKLOAD_PAYLOAD_BYTES 2048u

static void zbex_workload_payload(uint8_t *payload)
{
    for (size_t i = 0; i < ZBEX_WORKLOAD_PAYLOAD_BYTES; i++)
        payload[i] = (uint8_t)(i * 7u + 3u);
}

/* An environment policy that constrains nothing (accepts every valid
 * captured profile). */
static void zbex_policy_open(struct vcs_zcode_environment_policy_v1 *policy)
{
    memset(policy, 0, sizeof(*policy));
    policy->schema_version = VCS_ZCODE_ENVIRONMENT_POLICY_VERSION;
}

static void zbex_study(const uint8_t policy_root[32],
                       struct vcs_zcode_study_spec_v1 *study)
{
    memset(study, 0, sizeof(*study));
    study->schema_version = VCS_ZCODE_SCIENCE_VERSION;
    zbex_root(study->hypothesis_root, 1);
    zbex_root(study->null_hypothesis_root, 2);
    zbex_root(study->source_root, 3);
    zbex_root(study->dependency_lock_root, 4);
    zbex_root(study->toolchain_capsule_root, 5);
    zbex_root(study->protocol_root, 6);
    zbex_root(study->workloads_root, 7);
    zbex_root(study->metrics_root, 8);
    zbex_root(study->estimator_tolerance_root, 9);
    memcpy(study->environment_policy_root, policy_root, 32);
    zbex_root(study->citations_root, 11);
    zbex_root(study->preregistration_policy_root, 12);
    study->required_reproductions = 2;
    study->required_reviews = 3;
    study->sequence = 17;
    study->created_unix = 1000;
    study->expires_unix = 5000;
}

static void zbex_task_candidate(
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
    zbex_root(task->write_scope_root, 20);
    zbex_root(task->acceptance_tests_root, 21);
    zbex_root(task->proof_policy_root, 22);
    zbex_root(task->model_policy_root, 23);
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
    zbex_root(candidate->patch_root, 24);
    zbex_root(candidate->candidate_source_root, 25);
    zbex_root(candidate->adapter_policy_root, 26);
    zbex_root(candidate->author_pubkey, 27);
    candidate->sequence = 1;
    candidate->created_unix = 1100;
    (void)vcs_zcode_candidate_root(candidate, candidate_root);
}

static void zbex_method(const uint8_t workload_root[32],
                        struct vcs_zcode_benchmark_method_v1 *method)
{
    memset(method, 0, sizeof(*method));
    method->schema_version = VCS_ZCODE_BENCHMARK_METHOD_VERSION;
    memcpy(method->workload_root, workload_root, 32);
    zbex_root(method->timer_root, 0x42);
    zbex_root(method->estimator_root, 0x43);
    method->tolerance_ppm = 5000;
    method->warmup_samples = 2;
    method->measured_samples = 16;
    method->sample_distribution = VCS_ZCODE_SAMPLE_DIST_TRIMMED_MEAN;
    method->trim_percent = 10;
}

struct zbex_context {
    struct vcs_zcode_environment_policy_v1 policy;
    uint8_t policy_root[32];
    struct vcs_zcode_study_spec_v1 study;
    uint8_t study_root[32];
    struct vcs_zcode_task_v1 task;
    struct vcs_zcode_candidate_v1 candidate;
    uint8_t task_root[32];
    uint8_t candidate_root[32];
    struct vcs_zcode_benchmark_method_v1 method;
    uint8_t method_root[32];
    uint8_t workload_root[32];
};

/* Build + CAS-store the whole execution context (open policy). */
static bool zbex_seed_context(const char *workspace,
                              struct zbex_context *ctx)
{
    memset(ctx, 0, sizeof(*ctx));
    zbex_policy_open(&ctx->policy);
    uint8_t policy_wire[VCS_ZCODE_ENVIRONMENT_POLICY_WIRE_BYTES];
    if (vcs_zcode_environment_policy_v1_serialize(&ctx->policy,
                                                  policy_wire) !=
            VCS_ZCODE_RECEIPT_OK ||
        vcs_zcode_environment_policy_v1_root(&ctx->policy,
                                             ctx->policy_root) !=
            VCS_ZCODE_RECEIPT_OK ||
        !vcs_object_put_addressed(workspace, ctx->policy_root, policy_wire,
                                  sizeof(policy_wire)))
        return false;
    zbex_study(ctx->policy_root, &ctx->study);
    zbex_task_candidate(&ctx->study, &ctx->task, &ctx->candidate,
                        ctx->task_root, ctx->candidate_root);
    uint8_t payload[ZBEX_WORKLOAD_PAYLOAD_BYTES];
    zbex_workload_payload(payload);
    uint8_t workload_wire[VCS_ZCODE_BENCHMARK_WORKLOAD_HEADER_BYTES +
                          ZBEX_WORKLOAD_PAYLOAD_BYTES];
    if (vcs_zcode_benchmark_workload_v1_serialize(
            payload, sizeof(payload), workload_wire,
            sizeof(workload_wire)) != VCS_ZCODE_RECEIPT_OK ||
        vcs_zcode_benchmark_workload_v1_root(workload_wire,
                                             sizeof(workload_wire),
                                             ctx->workload_root) !=
            VCS_ZCODE_RECEIPT_OK ||
        !vcs_object_put_addressed(workspace, ctx->workload_root,
                                  workload_wire, sizeof(workload_wire)))
        return false;
    zbex_method(ctx->workload_root, &ctx->method);
    uint8_t study_wire[VCS_ZCODE_STUDY_SPEC_WIRE_BYTES];
    uint8_t task_wire[VCS_ZCODE_TASK_WIRE_BYTES];
    uint8_t candidate_wire[VCS_ZCODE_CANDIDATE_WIRE_BYTES];
    uint8_t method_wire[VCS_ZCODE_BENCHMARK_METHOD_WIRE_BYTES];
    return vcs_zcode_study_spec_serialize(&ctx->study, study_wire) ==
               VCS_ZCODE_SCIENCE_OK &&
           vcs_zcode_study_spec_root(&ctx->study, ctx->study_root) ==
               VCS_ZCODE_SCIENCE_OK &&
           vcs_object_put_addressed(workspace, ctx->study_root, study_wire,
                                    sizeof(study_wire)) &&
           vcs_zcode_task_serialize(&ctx->task, task_wire) ==
               VCS_ZCODE_DEV_OK &&
           vcs_object_put_addressed(workspace, ctx->task_root, task_wire,
                                    sizeof(task_wire)) &&
           vcs_zcode_candidate_serialize(&ctx->candidate, candidate_wire) ==
               VCS_ZCODE_DEV_OK &&
           vcs_object_put_addressed(workspace, ctx->candidate_root,
                                    candidate_wire, sizeof(candidate_wire)) &&
           vcs_zcode_benchmark_method_serialize(&ctx->method, method_wire) ==
               VCS_ZCODE_SCIENCE_OK &&
           vcs_zcode_benchmark_method_root(&ctx->method, ctx->method_root) ==
               VCS_ZCODE_SCIENCE_OK &&
           vcs_object_put_addressed(workspace, ctx->method_root, method_wire,
                                    sizeof(method_wire));
}

static void zbex_request(const char *workspace,
                         const struct zbex_context *ctx,
                         struct zcode_benchmark_execute_request *req)
{
    memset(req, 0, sizeof(*req));
    static char study_hex[65], task_hex[65], candidate_hex[65],
        method_hex[65];
    zcl_hex_encode(ctx->study_root, 32, study_hex);
    zcl_hex_encode(ctx->task_root, 32, task_hex);
    zcl_hex_encode(ctx->candidate_root, 32, candidate_hex);
    zcl_hex_encode(ctx->method_root, 32, method_hex);
    req->workspace = workspace;
    req->study_root_hex = study_hex;
    req->task_root_hex = task_hex;
    req->candidate_root_hex = candidate_hex;
    req->method_root_hex = method_hex;
    req->action_kind = VCS_BUILD_ACTION_KIND_BENCHMARK_V1;
    req->action_sequence = 1;
    req->challenge_block_height = 3200000;
    zbex_root(req->challenge_block_hash, 0x34);
    req->result_sequence = 1;
    req->now = ZBEX_NOW;
    req->confirm = true;
}

static struct zcl_result zbex_selfcheck_false(const char *bench_dir)
{
    (void)bench_dir;
    return ZCL_ERR(-1, "injected self-check failure");
}

static bool zbex_hex_eq(const char *expected_hex, const uint8_t *bytes,
                        size_t len)
{
    if (strlen(expected_hex) != len * 2u)
        return false;
    uint8_t expected[256];
    if (len > sizeof(expected) ||
        !zcl_hex_decode_lower(expected_hex, expected, len))
        return false;
    return memcmp(expected, bytes, len) == 0;
}

/* ── 1: codec KATs ───────────────────────────────────────────────────── */

static int test_zbex_codec_kats(void)
{
    int failures = 0;
    TEST("zcode_benchmark_exec: receipt codec KATs, trailing rejection, zero-on-failure") {
        /* workload bundle: golden root + round trip. */
        uint8_t payload[ZBEX_WORKLOAD_PAYLOAD_BYTES];
        zbex_workload_payload(payload);
        uint8_t wwire[VCS_ZCODE_BENCHMARK_WORKLOAD_HEADER_BYTES +
                      ZBEX_WORKLOAD_PAYLOAD_BYTES];
        ASSERT_EQ(vcs_zcode_benchmark_workload_v1_serialize(
                      payload, sizeof(payload), wwire, sizeof(wwire)),
                  VCS_ZCODE_RECEIPT_OK);
        uint8_t root[32], root2[32];
        ASSERT_EQ(vcs_zcode_benchmark_workload_v1_root(
                      wwire, sizeof(wwire), root),
                  VCS_ZCODE_RECEIPT_OK);
        ASSERT(zbex_hex_eq(
            "3540ca220e2fdc13171fd72fca6e4764ba1a68499149fc6859b79a8d8eb96888",
            root, 32));
        struct vcs_zcode_benchmark_workload_v1_view wview;
        ASSERT_EQ(vcs_zcode_benchmark_workload_v1_parse(
                      wwire, sizeof(wwire), &wview),
                  VCS_ZCODE_RECEIPT_OK);
        ASSERT_EQ(wview.payload_len, ZBEX_WORKLOAD_PAYLOAD_BYTES);
        ASSERT(memcmp(wview.payload, payload, sizeof(payload)) == 0);
        /* trailing / short / magic rejections zero the view. */
        uint8_t trailing[sizeof(wwire) + 1u];
        memcpy(trailing, wwire, sizeof(wwire));
        trailing[sizeof(wwire)] = 0x00;
        ASSERT_EQ(vcs_zcode_benchmark_workload_v1_parse(
                      trailing, sizeof(trailing), &wview),
                  VCS_ZCODE_RECEIPT_ERR_WIRE_SIZE);
        ASSERT(wview.payload == NULL && wview.payload_len == 0);
        ASSERT_EQ(vcs_zcode_benchmark_workload_v1_parse(
                      wwire, sizeof(wwire) - 1u, &wview),
                  VCS_ZCODE_RECEIPT_ERR_WIRE_SIZE);
        wwire[0] ^= 0xff;
        ASSERT_EQ(vcs_zcode_benchmark_workload_v1_parse(
                      wwire, sizeof(wwire), &wview),
                  VCS_ZCODE_RECEIPT_ERR_WIRE_MAGIC);

        /* raw-sample manifest: golden wire + root. */
        struct vcs_zcode_raw_sample_manifest_v1 manifest, manifest_parsed;
        memset(&manifest, 0, sizeof(manifest));
        manifest.schema_version = VCS_ZCODE_RAW_SAMPLE_MANIFEST_VERSION;
        zbex_root(manifest.method_root, 0x41);
        zbex_root(manifest.workload_root, 0x42);
        manifest.warmup_samples = 2;
        manifest.measured_samples = 16;
        memcpy(manifest.timer_source, "tsc", 3);
        uint8_t mwire[VCS_ZCODE_RAW_SAMPLE_MANIFEST_WIRE_BYTES];
        ASSERT_EQ(vcs_zcode_raw_sample_manifest_v1_serialize(&manifest,
                                                             mwire),
                  VCS_ZCODE_RECEIPT_OK);
        ASSERT(zbex_hex_eq(
            "5a4352534d310d0a0100414141414141414141414141414141414141414141414141414141414141414142424242424242424242424242424242424242424242424242424242424242420200000000000000100000000000000074736300000000000000000000000000",
            mwire, sizeof(mwire)));
        ASSERT_EQ(vcs_zcode_raw_sample_manifest_v1_root(&manifest, root),
                  VCS_ZCODE_RECEIPT_OK);
        ASSERT(zbex_hex_eq(
            "9e655980b6250cbe14faaa4a781375cb64e63c61ef54cad05b0ab6731bd7c58a",
            root, 32));
        ASSERT_EQ(vcs_zcode_raw_sample_manifest_v1_root(&manifest, root2),
                  VCS_ZCODE_RECEIPT_OK);
        ASSERT(memcmp(root, root2, 32) == 0);
        ASSERT_EQ(vcs_zcode_raw_sample_manifest_v1_parse(
                      mwire, sizeof(mwire), &manifest_parsed),
                  VCS_ZCODE_RECEIPT_OK);
        ASSERT(memcmp(&manifest, &manifest_parsed, sizeof(manifest)) == 0);
        ASSERT_EQ(vcs_zcode_raw_sample_manifest_v1_parse(
                      mwire, sizeof(mwire) + 1u, &manifest_parsed),
                  VCS_ZCODE_RECEIPT_ERR_WIRE_SIZE);
        ASSERT(vcs_zcode_raw_sample_manifest_v1_validate(&manifest_parsed) !=
               VCS_ZCODE_RECEIPT_OK);
        {
            struct vcs_zcode_raw_sample_manifest_v1 bad = manifest;
            bad.measured_samples = 0;
            ASSERT_EQ(vcs_zcode_raw_sample_manifest_v1_validate(&bad),
                      VCS_ZCODE_RECEIPT_ERR_LIMIT);
            bad = manifest;
            memset(bad.timer_source, 0x61, sizeof(bad.timer_source));
            ASSERT_EQ(vcs_zcode_raw_sample_manifest_v1_validate(&bad),
                      VCS_ZCODE_RECEIPT_ERR_PADDING);
            bad = manifest;
            memset(bad.method_root, 0, 32);
            ASSERT_EQ(vcs_zcode_raw_sample_manifest_v1_validate(&bad),
                      VCS_ZCODE_RECEIPT_ERR_ROOT_ZERO);
        }

        /* sample payload: golden wire + root + sample_at round trip. */
        uint64_t samples[16];
        for (size_t i = 0; i < 16; i++)
            samples[i] = 1000 + i * 37;
        uint8_t pwire[VCS_ZCODE_SAMPLE_PAYLOAD_HEADER_BYTES + 8u * 16u];
        ASSERT_EQ(vcs_zcode_sample_payload_v1_serialize(
                      samples, 16, pwire, sizeof(pwire)),
                  VCS_ZCODE_RECEIPT_OK);
        ASSERT(zbex_hex_eq(
            "5a4353504c310d0a01001000000000000000e8030000000000000d04000000000000320400000000000057040000000000007c04000000000000a104000000000000c604000000000000eb04000000000000100500000000000035050000000000005a050000000000007f05000000000000a405000000000000c905000000000000ee050000000000001306000000000000",
            pwire, sizeof(pwire)));
        ASSERT_EQ(vcs_zcode_sample_payload_v1_root(pwire, sizeof(pwire),
                                                   root),
                  VCS_ZCODE_RECEIPT_OK);
        ASSERT(zbex_hex_eq(
            "18c0db534cf72fa0f838584ec01d99e74b7e01fe2ad76e8628912eb1f3779862",
            root, 32));
        struct vcs_zcode_sample_payload_v1_view pview;
        ASSERT_EQ(vcs_zcode_sample_payload_v1_parse(pwire, sizeof(pwire),
                                                    &pview),
                  VCS_ZCODE_RECEIPT_OK);
        ASSERT_EQ(pview.count, 16u);
        for (uint64_t i = 0; i < 16; i++) {
            uint64_t sample = 0;
            ASSERT(vcs_zcode_sample_payload_v1_sample_at(&pview, i,
                                                         &sample));
            ASSERT_EQ(sample, 1000 + i * 37);
        }
        {
            uint64_t sample = 0;
            ASSERT(!vcs_zcode_sample_payload_v1_sample_at(&pview, 16,
                                                          &sample));
        }
        ASSERT_EQ(vcs_zcode_sample_payload_v1_parse(pwire,
                                                    sizeof(pwire) - 1u,
                                                    &pview),
                  VCS_ZCODE_RECEIPT_ERR_WIRE_SIZE);
        ASSERT(pview.sample_bytes == NULL && pview.count == 0);
        ASSERT_EQ(vcs_zcode_sample_payload_v1_serialize(samples, 0, pwire,
                                                        sizeof(pwire)),
                  VCS_ZCODE_RECEIPT_ERR_LIMIT);

        /* benchmark evidence: golden wire + root + negative rules. */
        struct vcs_zcode_benchmark_evidence_v1 evidence, evidence_parsed;
        memset(&evidence, 0, sizeof(evidence));
        evidence.schema_version = VCS_ZCODE_BENCHMARK_EVIDENCE_VERSION;
        zbex_root(evidence.action_root, 0x51);
        zbex_root(evidence.manifest_root, 0x52);
        zbex_root(evidence.sample_payload_root, 0x53);
        evidence.min_ns = 100;
        evidence.median_ns = 200;
        evidence.max_ns = 300;
        evidence.status = VCS_ZCODE_BENCHMARK_OBSERVED;
        evidence.isolation = VCS_ZCODE_BENCHMARK_ISOLATION_FULL;
        uint8_t ewire[VCS_ZCODE_BENCHMARK_EVIDENCE_WIRE_BYTES];
        ASSERT_EQ(vcs_zcode_benchmark_evidence_v1_serialize(&evidence,
                                                            ewire),
                  VCS_ZCODE_RECEIPT_OK);
        ASSERT(zbex_hex_eq(
            "5a43424556310d0a01005151515151515151515151515151515151515151515151515151515151515151525252525252525252525252525252525252525252525252525252525252525253535353535353535353535353535353535353535353535353535353535353536400000000000000c8000000000000002c0100000000000001000000000000000000",
            ewire, sizeof(ewire)));
        ASSERT_EQ(vcs_zcode_benchmark_evidence_v1_root(&evidence, root),
                  VCS_ZCODE_RECEIPT_OK);
        ASSERT(zbex_hex_eq(
            "96ea0bcf7ae39a34571afbd31d0d585002fe6eb89124edf66445b90dd8aa2c3f",
            root, 32));
        ASSERT_EQ(vcs_zcode_benchmark_evidence_v1_parse(
                      ewire, sizeof(ewire), &evidence_parsed),
                  VCS_ZCODE_RECEIPT_OK);
        ASSERT(memcmp(&evidence, &evidence_parsed, sizeof(evidence)) == 0);
        ASSERT_EQ(vcs_zcode_benchmark_evidence_v1_parse(
                      ewire, sizeof(ewire) + 1u, &evidence_parsed),
                  VCS_ZCODE_RECEIPT_ERR_WIRE_SIZE);
        {
            struct vcs_zcode_benchmark_evidence_v1 bad = evidence;
            bad.min_ns = 400;
            ASSERT_EQ(vcs_zcode_benchmark_evidence_v1_validate(&bad),
                      VCS_ZCODE_RECEIPT_ERR_ORDER);
            bad = evidence;
            bad.status = 9;
            ASSERT_EQ(vcs_zcode_benchmark_evidence_v1_validate(&bad),
                      VCS_ZCODE_RECEIPT_ERR_STATUS);
            bad = evidence;
            bad.isolation = 2;
            ASSERT_EQ(vcs_zcode_benchmark_evidence_v1_validate(&bad),
                      VCS_ZCODE_RECEIPT_ERR_ISOLATION);
            bad = evidence;
            bad.reserved[7] = 1;
            ASSERT_EQ(vcs_zcode_benchmark_evidence_v1_validate(&bad),
                      VCS_ZCODE_RECEIPT_ERR_RESERVED);
        }

        /* environment policy: golden wire + root + accepts() matrix. */
        struct vcs_zcode_environment_policy_v1 policy, policy_parsed;
        memset(&policy, 0, sizeof(policy));
        policy.schema_version = VCS_ZCODE_ENVIRONMENT_POLICY_VERSION;
        policy.required_isa_bits =
            VCS_ZCODE_HW_ISA_SSE4_2 | VCS_ZCODE_HW_ISA_AVX2;
        policy.min_physical_cores = 2;
        policy.min_logical_cores = 4;
        policy.min_ram_mib = 1024;
        memcpy(policy.required_timer_source, "tsc", 3);
        uint8_t polwire[VCS_ZCODE_ENVIRONMENT_POLICY_WIRE_BYTES];
        ASSERT_EQ(vcs_zcode_environment_policy_v1_serialize(&policy,
                                                            polwire),
                  VCS_ZCODE_RECEIPT_OK);
        ASSERT(zbex_hex_eq(
            "5a43454e50310d0a01001100000000000000020004000004000000000000747363000000000000000000000000000000000000000000",
            polwire, sizeof(polwire)));
        ASSERT_EQ(vcs_zcode_environment_policy_v1_root(&policy, root),
                  VCS_ZCODE_RECEIPT_OK);
        ASSERT(zbex_hex_eq(
            "73ae276e00539a1dd761a3a1852e0902f1d93e546aa0d051a7231d4cf973d80b",
            root, 32));
        ASSERT_EQ(vcs_zcode_environment_policy_v1_parse(
                      polwire, sizeof(polwire), &policy_parsed),
                  VCS_ZCODE_RECEIPT_OK);
        ASSERT(memcmp(&policy, &policy_parsed, sizeof(policy)) == 0);
        ASSERT_EQ(vcs_zcode_environment_policy_v1_parse(
                      polwire, sizeof(polwire) + 1u, &policy_parsed),
                  VCS_ZCODE_RECEIPT_ERR_WIRE_SIZE);
        {
            struct vcs_zcode_environment_policy_v1 bad = policy;
            bad.required_isa_bits = UINT64_C(1) << 40;
            ASSERT_EQ(vcs_zcode_environment_policy_v1_validate(&bad),
                      VCS_ZCODE_RECEIPT_ERR_ISA);
            bad = policy;
            bad.reserved[0] = 1;
            ASSERT_EQ(vcs_zcode_environment_policy_v1_validate(&bad),
                      VCS_ZCODE_RECEIPT_ERR_RESERVED);
        }
        {
            struct vcs_zcode_hardware_profile_v1 profile;
            memset(&profile, 0, sizeof(profile));
            profile.schema_version = VCS_ZCODE_HARDWARE_PROFILE_VERSION;
            profile.physical_cores = 8;
            profile.logical_cores = 16;
            profile.ram_mib = 32768;
            profile.isa_bits = VCS_ZCODE_HW_ISA_SSE4_2 |
                               VCS_ZCODE_HW_ISA_AVX2 |
                               VCS_ZCODE_HW_ISA_FMA;
            memcpy(profile.timer_source, "tsc", 3);
            profile.captured_unix = 1000;
            ASSERT(vcs_zcode_environment_policy_v1_accepts(&policy,
                                                           &profile));
            struct vcs_zcode_hardware_profile_v1 weaker = profile;
            weaker.isa_bits = VCS_ZCODE_HW_ISA_SSE4_2; /* missing AVX2 */
            ASSERT(!vcs_zcode_environment_policy_v1_accepts(&policy,
                                                            &weaker));
            weaker = profile;
            weaker.physical_cores = 1;
            ASSERT(!vcs_zcode_environment_policy_v1_accepts(&policy,
                                                            &weaker));
            weaker = profile;
            weaker.ram_mib = 512;
            ASSERT(!vcs_zcode_environment_policy_v1_accepts(&policy,
                                                            &weaker));
            weaker = profile;
            memset(weaker.timer_source, 0, sizeof(weaker.timer_source));
            memcpy(weaker.timer_source, "hpet", 4);
            ASSERT(!vcs_zcode_environment_policy_v1_accepts(&policy,
                                                            &weaker));
            struct vcs_zcode_environment_policy_v1 open_policy;
            zbex_policy_open(&open_policy);
            ASSERT(vcs_zcode_environment_policy_v1_accepts(&open_policy,
                                                           &weaker));
        }
        PASS();
    } _test_next:;
    return failures;
}

/* ── 2 + 3: happy path, receipt verification, deterministic envelope ─── */

static int test_zbex_execute_happy(void)
{
    int failures = 0;
    TEST("zcode_benchmark_exec: confined execute commits; receipt verifies; envelope deterministic") {
        struct node_db ndb = {0};
        char dir[ZBEX_DIR_CAP];
        ASSERT(zbex_setup(&ndb, dir, sizeof(dir)));
        struct zbex_context ctx;
        ASSERT(zbex_seed_context(dir, &ctx));
        struct zcode_benchmark_execute_request req;
        zbex_request(dir, &ctx, &req);
        struct zcode_benchmark_execute_out out1;
        ASSERT(zcode_benchmark_execute(&ndb, &req, &out1).ok);
        ASSERT(out1.committed);
        ASSERT(out1.run.result.status == VCS_ZCODE_BENCHMARK_OBSERVED);
        /* The S3 admission path stored exactly one result. */
        char root_hex[65];
        zcl_hex_encode(out1.run.result_root, 32, root_hex);
        struct db_zcode_science_entry row;
        const char *kind = NULL;
        bool found = false;
        ASSERT(zcode_science_work_status(&ndb, root_hex, &row, &kind,
                                         &found).ok);
        ASSERT(found);
        ASSERT_STR_EQ(kind, "result");
        /* The aux artifacts are in CAS, addressed by their roots. */
        ASSERT(vcs_object_has(dir, out1.run.manifest_root));
        ASSERT(vcs_object_has(dir, out1.run.sample_payload_root));
        ASSERT(vcs_object_has(dir, out1.run.evidence_root));
        ASSERT(vcs_object_has(dir, out1.run.hardware_profile_root));
        /* The receipt verifier re-derives every root and binding. */
        ASSERT(zcode_benchmark_executor_verify_receipt(dir, root_hex).ok);
        ASSERT(zbex_shop_workspace_alias(dir));
        struct shop_fulfill_receipt_fact shop_fact;
        ASSERT(shop_fulfill_receipt_verify(
            &ndb, dir, out1.run.result_root, SHOP_FULFILL_RECEIPT_BENCH,
            ZBEX_NOW, &shop_fact).ok);
        ASSERT(shop_fact.passed);
        ASSERT(!shop_fact.artifact_binding_valid);
        /* Deterministic envelope: a second identical run differs ONLY in
         * the raw-sample carrier and the evidence bundle that references
         * it — the sample values are the observation, everything else in
         * the wire is bound to fixed inputs. raw_sample_root sits at
         * offset 170..202 and evidence_root at 202..234 in the v2 wire. */
        struct zcode_benchmark_execute_out out2;
        ASSERT(zcode_benchmark_execute(&ndb, &req, &out2).ok);
        ASSERT(out2.committed);
        uint8_t masked1[VCS_ZCODE_BENCHMARK_RESULT_V2_WIRE_BYTES];
        uint8_t masked2[VCS_ZCODE_BENCHMARK_RESULT_V2_WIRE_BYTES];
        memcpy(masked1, out1.run.result_wire, sizeof(masked1));
        memcpy(masked2, out2.run.result_wire, sizeof(masked2));
        memset(masked1 + 170, 0, 64);
        memset(masked2 + 170, 0, 64);
        ASSERT(memcmp(masked1, masked2, sizeof(masked1)) == 0);
        ASSERT(memcmp(out1.run.manifest_root, out2.run.manifest_root,
                      32) == 0);
        ASSERT(memcmp(out1.run.hardware_profile_root,
                      out2.run.hardware_profile_root, 32) == 0);
        /* No accepted/correct/true claim anywhere: the observation status
         * is the only signal. */
        ASSERT(out1.run.result.status == out2.run.result.status);
        zbex_teardown(&ndb, dir);
        PASS();
    } _test_next:;
    return failures;
}

/* ── 4: manifest / payload tamper → root mismatch → receipt rejected ─── */

static int test_zbex_tamper_rejected(void)
{
    int failures = 0;
    TEST("zcode_benchmark_exec: tampered manifest or sample payload breaks the receipt") {
        for (int which = 0; which < 2; which++) {
            struct node_db ndb = {0};
            char dir[ZBEX_DIR_CAP];
            ASSERT(zbex_setup(&ndb, dir, sizeof(dir)));
            struct zbex_context ctx;
            ASSERT(zbex_seed_context(dir, &ctx));
            struct zcode_benchmark_execute_request req;
            zbex_request(dir, &ctx, &req);
            struct zcode_benchmark_execute_out out;
            ASSERT(zcode_benchmark_execute(&ndb, &req, &out).ok);
            ASSERT(out.committed);
            char root_hex[65], target_hex[65];
            zcl_hex_encode(out.run.result_root, 32, root_hex);
            /* Sanity: the untampered receipt verifies. */
            ASSERT(zcode_benchmark_executor_verify_receipt(dir,
                                                           root_hex).ok);
            if (which == 0)
                zcl_hex_encode(out.run.manifest_root, 32, target_hex);
            else
                zcl_hex_encode(out.run.sample_payload_root, 32, target_hex);
            /* Flip one byte inside the stored object (past the header). */
            ASSERT(zbex_cas_flip_byte(dir, target_hex, 40));
            struct zcl_result verified =
                zcode_benchmark_executor_verify_receipt(dir, root_hex);
            ASSERT(!verified.ok);
            ASSERT(strstr(verified.message,
                          which == 0 ? "manifest" : "sample-payload") !=
                   NULL);
            zbex_teardown(&ndb, dir);
        }
        PASS();
    } _test_next:;
    return failures;
}

/* ── 5: environment-policy mismatch refuses before any run ───────────── */

static int test_zbex_environment_mismatch(void)
{
    int failures = 0;
    TEST("zcode_benchmark_exec: environment-policy violation refuses execution, stores nothing") {
        struct node_db ndb = {0};
        char dir[ZBEX_DIR_CAP];
        ASSERT(zbex_setup(&ndb, dir, sizeof(dir)));
        /* Policy no host can meet: 65535 physical cores. */
        struct vcs_zcode_environment_policy_v1 policy;
        memset(&policy, 0, sizeof(policy));
        policy.schema_version = VCS_ZCODE_ENVIRONMENT_POLICY_VERSION;
        policy.min_physical_cores = 65535;
        uint8_t policy_wire[VCS_ZCODE_ENVIRONMENT_POLICY_WIRE_BYTES];
        uint8_t policy_root[32];
        ASSERT(vcs_zcode_environment_policy_v1_serialize(
                   &policy, policy_wire) == VCS_ZCODE_RECEIPT_OK);
        ASSERT(vcs_zcode_environment_policy_v1_root(&policy, policy_root) ==
               VCS_ZCODE_RECEIPT_OK);
        ASSERT(vcs_object_put_addressed(dir, policy_root, policy_wire,
                                        sizeof(policy_wire)));
        struct zbex_context ctx;
        memset(&ctx, 0, sizeof(ctx));
        memcpy(ctx.policy_root, policy_root, 32);
        zbex_study(policy_root, &ctx.study);
        zbex_task_candidate(&ctx.study, &ctx.task, &ctx.candidate,
                            ctx.task_root, ctx.candidate_root);
        uint8_t payload[ZBEX_WORKLOAD_PAYLOAD_BYTES];
        zbex_workload_payload(payload);
        uint8_t workload_wire[VCS_ZCODE_BENCHMARK_WORKLOAD_HEADER_BYTES +
                              ZBEX_WORKLOAD_PAYLOAD_BYTES];
        ASSERT_EQ(vcs_zcode_benchmark_workload_v1_serialize(
                      payload, sizeof(payload), workload_wire,
                      sizeof(workload_wire)),
                  VCS_ZCODE_RECEIPT_OK);
        ASSERT_EQ(vcs_zcode_benchmark_workload_v1_root(
                      workload_wire, sizeof(workload_wire),
                      ctx.workload_root),
                  VCS_ZCODE_RECEIPT_OK);
        ASSERT(vcs_object_put_addressed(dir, ctx.workload_root,
                                        workload_wire,
                                        sizeof(workload_wire)));
        zbex_method(ctx.workload_root, &ctx.method);
        uint8_t study_wire[VCS_ZCODE_STUDY_SPEC_WIRE_BYTES];
        uint8_t task_wire[VCS_ZCODE_TASK_WIRE_BYTES];
        uint8_t candidate_wire[VCS_ZCODE_CANDIDATE_WIRE_BYTES];
        uint8_t method_wire[VCS_ZCODE_BENCHMARK_METHOD_WIRE_BYTES];
        ASSERT(vcs_zcode_study_spec_serialize(&ctx.study, study_wire) ==
               VCS_ZCODE_SCIENCE_OK);
        ASSERT(vcs_zcode_study_spec_root(&ctx.study, ctx.study_root) ==
               VCS_ZCODE_SCIENCE_OK);
        ASSERT(vcs_object_put_addressed(dir, ctx.study_root, study_wire,
                                        sizeof(study_wire)));
        ASSERT(vcs_zcode_task_serialize(&ctx.task, task_wire) ==
               VCS_ZCODE_DEV_OK);
        ASSERT(vcs_object_put_addressed(dir, ctx.task_root, task_wire,
                                        sizeof(task_wire)));
        ASSERT(vcs_zcode_candidate_serialize(&ctx.candidate,
                                             candidate_wire) ==
               VCS_ZCODE_DEV_OK);
        ASSERT(vcs_object_put_addressed(dir, ctx.candidate_root,
                                        candidate_wire,
                                        sizeof(candidate_wire)));
        ASSERT(vcs_zcode_benchmark_method_serialize(&ctx.method,
                                                    method_wire) ==
               VCS_ZCODE_SCIENCE_OK);
        ASSERT(vcs_zcode_benchmark_method_root(&ctx.method,
                                               ctx.method_root) ==
               VCS_ZCODE_SCIENCE_OK);
        ASSERT(vcs_object_put_addressed(dir, ctx.method_root, method_wire,
                                        sizeof(method_wire)));
        int objects_before = zbex_cas_object_count(dir);
        ASSERT(objects_before == 6);
        struct zcode_benchmark_execute_request req;
        zbex_request(dir, &ctx, &req);
        struct zcode_benchmark_execute_out out;
        struct zcl_result executed = zcode_benchmark_execute(&ndb, &req,
                                                             &out);
        ASSERT(!executed.ok);
        ASSERT(strstr(executed.message, "environment-mismatch") != NULL);
        /* Nothing ran and nothing was stored. */
        ASSERT(zbex_cas_object_count(dir) == objects_before);
        zbex_teardown(&ndb, dir);
        PASS();
    } _test_next:;
    return failures;
}

/* ── 6: null and negative results are valid observations ─────────────── */

static int test_zbex_null_negative(void)
{
    int failures = 0;
    TEST("zcode_benchmark_exec: null and negative observations commit") {
        struct node_db ndb = {0};
        char dir[ZBEX_DIR_CAP];
        ASSERT(zbex_setup(&ndb, dir, sizeof(dir)));
        struct zbex_context ctx;
        ASSERT(zbex_seed_context(dir, &ctx));
        /* An empty workload payload: the run completes and the observation
         * is NULL_RESULT — "nothing measurable" is not an execution
         * failure. */
        uint8_t empty_workload_wire[VCS_ZCODE_BENCHMARK_WORKLOAD_HEADER_BYTES];
        uint8_t empty_workload_root[32];
        ASSERT_EQ(vcs_zcode_benchmark_workload_v1_serialize(
                      NULL, 0, empty_workload_wire,
                      sizeof(empty_workload_wire)),
                  VCS_ZCODE_RECEIPT_OK);
        ASSERT_EQ(vcs_zcode_benchmark_workload_v1_root(
                      empty_workload_wire, sizeof(empty_workload_wire),
                      empty_workload_root),
                  VCS_ZCODE_RECEIPT_OK);
        ASSERT(vcs_object_put_addressed(dir, empty_workload_root,
                                        empty_workload_wire,
                                        sizeof(empty_workload_wire)));
        struct vcs_zcode_benchmark_method_v1 null_method;
        zbex_method(empty_workload_root, &null_method);
        uint8_t null_method_wire[VCS_ZCODE_BENCHMARK_METHOD_WIRE_BYTES];
        uint8_t null_method_root[32];
        ASSERT(vcs_zcode_benchmark_method_serialize(&null_method,
                                                    null_method_wire) ==
               VCS_ZCODE_SCIENCE_OK);
        ASSERT(vcs_zcode_benchmark_method_root(&null_method,
                                               null_method_root) ==
               VCS_ZCODE_SCIENCE_OK);
        ASSERT(vcs_object_put_addressed(dir, null_method_root,
                                        null_method_wire,
                                        sizeof(null_method_wire)));
        struct zcode_benchmark_execute_request req;
        zbex_request(dir, &ctx, &req);
        static char null_method_hex[65];
        zcl_hex_encode(null_method_root, 32, null_method_hex);
        req.method_root_hex = null_method_hex;
        struct zcode_benchmark_execute_out null_out;
        ASSERT(zcode_benchmark_execute(&ndb, &req, &null_out).ok);
        ASSERT(null_out.committed);
        ASSERT(null_out.run.result.status ==
               VCS_ZCODE_BENCHMARK_NULL_RESULT);
        /* A NEGATIVE_RESULT ("candidate slower") admits identically. */
        struct zcode_benchmark_run_out negative = null_out.run;
        negative.result.status = VCS_ZCODE_BENCHMARK_NEGATIVE_RESULT;
        ASSERT_EQ(vcs_zcode_benchmark_result_v2_serialize(
                      &negative.result, negative.result_wire),
                  VCS_ZCODE_SCIENCE_OK);
        struct zcode_benchmark_execute_out negative_out;
        ASSERT(zcode_benchmark_executor_admit(&ndb, dir, &negative, true,
                                              ZBEX_NOW, &negative_out).ok);
        ASSERT(negative_out.committed);
        ASSERT(negative_out.commit.result_root[0] != '\0');
        ASSERT(zbex_shop_workspace_alias(dir));
        struct shop_fulfill_receipt_fact shop_fact;
        ASSERT(!shop_fulfill_receipt_verify(
            &ndb, dir, null_out.run.result_root,
            SHOP_FULFILL_RECEIPT_BENCH, ZBEX_NOW, &shop_fact).ok);
        ASSERT_STR_EQ(shop_fact.reason, "benchmark-result-not-observed");
        uint8_t negative_root[32];
        ASSERT(zcl_hex_decode_lower(negative_out.commit.result_root,
                                    negative_root, sizeof(negative_root)));
        ASSERT(!shop_fulfill_receipt_verify(
            &ndb, dir, negative_root, SHOP_FULFILL_RECEIPT_BENCH,
            ZBEX_NOW, &shop_fact).ok);
        /* This synthetic NEGATIVE_RESULT reuses NULL_RESULT evidence, so the
         * transitive verifier rejects its binding before the status gate. */
        ASSERT_STR_EQ(shop_fact.reason, "receipt-evidence-binding-mismatch");
        zbex_teardown(&ndb, dir);
        PASS();
    } _test_next:;
    return failures;
}

/* ── 7: sandbox self-check refusal + the real escape suite ───────────── */

static char g_zbex_canary_dir[ZBEX_DIR_CAP];

/* A child under the runner's exact profile shape (read-only bench grant):
 * the granted dir denies writes, and everything outside it denies reads. */
static int zbex_canary_readonly_grant(void)
{
    char probe[ZBEX_DIR_CAP + 32];
    int n = snprintf(probe, sizeof(probe), "%s/probe.txt",
                     g_zbex_canary_dir);
    if (n <= 0 || (size_t)n >= sizeof(probe))
        return 71;
    int f = open(probe, O_CREAT | O_WRONLY, 0600);
    if (f < 0)
        return 72; /* pre-confinement staging must work */
    close(f);
    struct os_sandbox_path_rule rules[] = {
        { .path = g_zbex_canary_dir, .allow_read = true },
    };
    struct os_sandbox_profile profile =
        os_sandbox_session_child_profile(rules, 1);
    profile.rlimits.as_bytes = OS_SANDBOX_RLIMIT_KEEP;
    profile.rlimits.nproc = OS_SANDBOX_RLIMIT_KEEP;
    /* KEEP nofile as in the executor: the canary inherits this test
     * process's fds and rlimits apply before the Landlock ruleset fd. */
    profile.rlimits.nofile = OS_SANDBOX_RLIMIT_KEEP;
    if (!os_sandbox_enter(&profile).ok)
        return 70;
    if (!os_sandbox_active())
        return 71;
    int rd = open(probe, O_RDONLY);
    if (rd < 0)
        return 73; /* read on the grant survives */
    close(rd);
    int wr = open(probe, O_RDWR);
    if (wr >= 0) {
        close(wr);
        return 74; /* read-only grant must deny writes */
    }
    int out = open("/etc/passwd", O_RDONLY);
    if (out >= 0) {
        close(out);
        return 75; /* outside the grant must deny reads */
    }
    if (errno != EACCES)
        return 76;
    return 0;
}

static int test_zbex_sandbox_selfcheck(void)
{
    int failures = 0;
    TEST("zcode_benchmark_exec: self-check refusal gates execution; escape suite holds") {
        struct node_db ndb = {0};
        char dir[ZBEX_DIR_CAP];
        ASSERT(zbex_setup(&ndb, dir, sizeof(dir)));
        /* The REAL canary self-check passes on this host (Landlock ABI
         * >= 1 + seccomp). */
        char bench_dir[ZBEX_DIR_CAP + 24];
        int n = snprintf(bench_dir, sizeof(bench_dir), "%s/.zvcs/bench",
                         dir);
        ASSERT(n > 0 && (size_t)n < sizeof(bench_dir));
        ASSERT(mkdir(bench_dir, 0700) == 0 || errno == EEXIST);
        ASSERT(zcode_benchmark_executor_sandbox_selfcheck(bench_dir).ok);
        /* The injected failure is a hard refusal before any run. */
        struct zbex_context ctx;
        ASSERT(zbex_seed_context(dir, &ctx));
        int objects_before = zbex_cas_object_count(dir);
        struct zcode_benchmark_execute_request req;
        zbex_request(dir, &ctx, &req);
        struct zcode_benchmark_executor_hooks hooks = {
            .sandbox_selfcheck = zbex_selfcheck_false,
        };
        req.hooks = &hooks;
        struct zcode_benchmark_execute_out out;
        struct zcl_result executed = zcode_benchmark_execute(&ndb, &req,
                                                             &out);
        ASSERT(!executed.ok);
        ASSERT(strstr(executed.message, "sandbox-selfcheck-failed") !=
               NULL);
        ASSERT(zbex_cas_object_count(dir) == objects_before);
        /* The runner's read-only grant shape holds: write + outside-read
         * are both EACCES inside the confined child. */
        n = snprintf(g_zbex_canary_dir, sizeof(g_zbex_canary_dir), "%s",
                     bench_dir);
        ASSERT(n > 0 && (size_t)n < sizeof(g_zbex_canary_dir));
        pid_t pid = fork();
        ASSERT(pid >= 0);
        if (pid == 0)
            _exit(zbex_canary_readonly_grant());
        int status = 0;
        ASSERT(waitpid(pid, &status, 0) == pid);
        ASSERT(WIFEXITED(status));
        ASSERT_EQ(WEXITSTATUS(status), 0);
        zbex_teardown(&ndb, dir);
        PASS();
    } _test_next:;
    return failures;
}

/* ── 8: crash discipline + idempotent retry ──────────────────────────── */

static int test_zbex_crash_discipline(void)
{
    int failures = 0;
    TEST("zcode_benchmark_exec: killed child stores nothing; retry idempotent by plan identity") {
        struct node_db ndb = {0};
        char dir[ZBEX_DIR_CAP];
        ASSERT(zbex_setup(&ndb, dir, sizeof(dir)));
        struct zbex_context ctx;
        ASSERT(zbex_seed_context(dir, &ctx));
        /* A heavy method the 1-CPU-second policy kills mid-run: 4 MiB x
         * 1024 samples is multiple CPU-seconds of SHA3. */
        size_t heavy_len = 4u * 1024u * 1024u;
        uint8_t *heavy_payload = malloc(heavy_len);
        ASSERT(heavy_payload != NULL);
        memset(heavy_payload, 0x5a, heavy_len);
        size_t heavy_wire_len =
            VCS_ZCODE_BENCHMARK_WORKLOAD_HEADER_BYTES + heavy_len;
        uint8_t *heavy_wire = malloc(heavy_wire_len);
        ASSERT(heavy_wire != NULL);
        uint8_t heavy_workload_root[32];
        ASSERT_EQ(vcs_zcode_benchmark_workload_v1_serialize(
                      heavy_payload, heavy_len, heavy_wire, heavy_wire_len),
                  VCS_ZCODE_RECEIPT_OK);
        ASSERT_EQ(vcs_zcode_benchmark_workload_v1_root(
                      heavy_wire, heavy_wire_len, heavy_workload_root),
                  VCS_ZCODE_RECEIPT_OK);
        ASSERT(vcs_object_put_addressed(dir, heavy_workload_root,
                                        heavy_wire, heavy_wire_len));
        free(heavy_wire);
        free(heavy_payload);
        struct vcs_zcode_benchmark_method_v1 heavy_method;
        zbex_method(heavy_workload_root, &heavy_method);
        heavy_method.warmup_samples = 0;
        heavy_method.measured_samples = 1024;
        uint8_t heavy_method_wire[VCS_ZCODE_BENCHMARK_METHOD_WIRE_BYTES];
        uint8_t heavy_method_root[32];
        ASSERT(vcs_zcode_benchmark_method_serialize(&heavy_method,
                                                    heavy_method_wire) ==
               VCS_ZCODE_SCIENCE_OK);
        ASSERT(vcs_zcode_benchmark_method_root(&heavy_method,
                                               heavy_method_root) ==
               VCS_ZCODE_SCIENCE_OK);
        ASSERT(vcs_object_put_addressed(dir, heavy_method_root,
                                        heavy_method_wire,
                                        sizeof(heavy_method_wire)));
        int objects_before = zbex_cas_object_count(dir);
        struct zcode_benchmark_execute_request req;
        zbex_request(dir, &ctx, &req);
        static char heavy_method_hex[65];
        zcl_hex_encode(heavy_method_root, 32, heavy_method_hex);
        req.method_root_hex = heavy_method_hex;
        struct zcode_benchmark_execute_out crashed;
        struct zcl_result ran = zcode_benchmark_execute(&ndb, &req,
                                                        &crashed);
        ASSERT(!ran.ok);
        ASSERT(strstr(ran.message, "executor-run-child") != NULL);
        /* The crash left no partial finished results: CAS unchanged, no
         * projection row. */
        ASSERT(zbex_cas_object_count(dir) == objects_before);
        struct vcs_zcode_science_index *index =
            vcs_zcode_science_index_build(dir, ZBEX_NOW);
        ASSERT(index != NULL);
        ASSERT_EQ(vcs_zcode_science_index_result_count(index), 0u);
        vcs_zcode_science_index_free(index);
        /* Retry with the light method commits. */
        zbex_request(dir, &ctx, &req);
        struct zcode_benchmark_execute_out retried;
        ASSERT(zcode_benchmark_execute(&ndb, &req, &retried).ok);
        ASSERT(retried.committed);
        /* A run that never reaches admission leaves no finished result:
         * stage 1 stores only inert aux objects; the result wire is not
         * in CAS and the projection is empty. */
        struct zcode_benchmark_execute_request req2;
        zbex_request(dir, &ctx, &req2);
        req2.result_sequence = 2;
        struct zcode_benchmark_run_out orphan;
        ASSERT(zcode_benchmark_executor_run(&req2, &orphan).ok);
        ASSERT(!vcs_object_has(dir, orphan.result_root));
        index = vcs_zcode_science_index_build(dir, ZBEX_NOW);
        ASSERT(index != NULL);
        ASSERT_EQ(vcs_zcode_science_index_result_count(index), 1u);
        vcs_zcode_science_index_free(index);
        /* Idempotent retry by plan identity: plan twice, commit twice. */
        struct zcode_benchmark_execute_out plan_a, plan_b;
        ASSERT(zcode_benchmark_executor_admit(&ndb, dir, &orphan, false,
                                              ZBEX_NOW, &plan_a).ok);
        ASSERT(!plan_a.committed);
        ASSERT(zcode_benchmark_executor_admit(&ndb, dir, &orphan, false,
                                              ZBEX_NOW, &plan_b).ok);
        ASSERT(plan_b.plan.already_planned);
        ASSERT_STR_EQ(plan_a.plan.plan_root, plan_b.plan.plan_root);
        struct zcode_benchmark_execute_out commit_a, commit_b;
        ASSERT(zcode_benchmark_executor_admit(&ndb, dir, &orphan, true,
                                              ZBEX_NOW, &commit_a).ok);
        ASSERT(commit_a.committed);
        ASSERT(!commit_a.commit.already_committed);
        ASSERT(zcode_benchmark_executor_admit(&ndb, dir, &orphan, true,
                                              ZBEX_NOW, &commit_b).ok);
        ASSERT(commit_b.commit.already_committed);
        ASSERT_STR_EQ(commit_a.commit.result_root,
                      commit_b.commit.result_root);
        index = vcs_zcode_science_index_build(dir, ZBEX_NOW);
        ASSERT(index != NULL);
        ASSERT_EQ(vcs_zcode_science_index_result_count(index), 2u);
        vcs_zcode_science_index_free(index);
        zbex_teardown(&ndb, dir);
        PASS();
    } _test_next:;
    return failures;
}

/* ── 9: closed-input rejection ───────────────────────────────────────── */

static int test_zbex_closed_inputs(void)
{
    int failures = 0;
    TEST("zcode_benchmark_exec: shell strings, foreign kinds, non-CAS roots, trailing wires refused") {
        struct node_db ndb = {0};
        char dir[ZBEX_DIR_CAP];
        ASSERT(zbex_setup(&ndb, dir, sizeof(dir)));
        struct zbex_context ctx;
        ASSERT(zbex_seed_context(dir, &ctx));
        struct zcode_benchmark_execute_request req;
        struct zcode_benchmark_execute_out out;
        struct zcl_result executed;

        /* Free-form shell is not an action. */
        zbex_request(dir, &ctx, &req);
        req.action_kind = "sh -c 'echo pwned'";
        executed = zcode_benchmark_execute(&ndb, &req, &out);
        ASSERT(!executed.ok);
        ASSERT(strstr(executed.message, "action-unregistered") != NULL);
        /* An unregistered kind. */
        zbex_request(dir, &ctx, &req);
        req.action_kind = "c23.benchmark.v2";
        executed = zcode_benchmark_execute(&ndb, &req, &out);
        ASSERT(!executed.ok);
        ASSERT(strstr(executed.message, "action-unregistered") != NULL);
        /* A registered but non-benchmark kind. */
        zbex_request(dir, &ctx, &req);
        req.action_kind = VCS_BUILD_ACTION_KIND_REVIEW_V1;
        executed = zcode_benchmark_execute(&ndb, &req, &out);
        ASSERT(!executed.ok);
        ASSERT(strstr(executed.message, "action-kind-closed") != NULL);
        zbex_request(dir, &ctx, &req);
        req.action_kind = VCS_BUILD_ACTION_KIND_V1;
        executed = zcode_benchmark_execute(&ndb, &req, &out);
        ASSERT(!executed.ok);
        ASSERT(strstr(executed.message, "action-kind-closed") != NULL);
        /* Roots not present in CAS. */
        zbex_request(dir, &ctx, &req);
        req.study_root_hex =
            "9999999999999999999999999999999999999999999999999999999999999999";
        executed = zcode_benchmark_execute(&ndb, &req, &out);
        ASSERT(!executed.ok);
        ASSERT(strstr(executed.message, "study-not-in-cas") != NULL);
        zbex_request(dir, &ctx, &req);
        req.method_root_hex =
            "8888888888888888888888888888888888888888888888888888888888888888";
        executed = zcode_benchmark_execute(&ndb, &req, &out);
        ASSERT(!executed.ok);
        ASSERT(strstr(executed.message, "method-not-in-cas") != NULL);
        /* A workload wire carrying a trailing byte is an invalid object,
         * not a workload: pin a fresh root from a variant method (the
         * valid wire already occupies the seeded root, and CAS dedups by
         * address). */
        uint8_t payload[ZBEX_WORKLOAD_PAYLOAD_BYTES];
        zbex_workload_payload(payload);
        uint8_t trailing[VCS_ZCODE_BENCHMARK_WORKLOAD_HEADER_BYTES +
                         ZBEX_WORKLOAD_PAYLOAD_BYTES + 1u];
        ASSERT_EQ(vcs_zcode_benchmark_workload_v1_serialize(
                      payload, sizeof(payload), trailing,
                      sizeof(trailing) - 1u),
                  VCS_ZCODE_RECEIPT_OK);
        trailing[sizeof(trailing) - 1u] = 0x00;
        uint8_t trailing_root[32];
        zbex_root(trailing_root, 0x77);
        ASSERT(vcs_object_put_addressed(dir, trailing_root, trailing,
                                        sizeof(trailing)));
        struct vcs_zcode_benchmark_method_v1 bad_method;
        zbex_method(trailing_root, &bad_method);
        uint8_t bad_method_wire[VCS_ZCODE_BENCHMARK_METHOD_WIRE_BYTES];
        uint8_t bad_method_root[32];
        ASSERT(vcs_zcode_benchmark_method_serialize(&bad_method,
                                                    bad_method_wire) ==
               VCS_ZCODE_SCIENCE_OK);
        ASSERT(vcs_zcode_benchmark_method_root(&bad_method,
                                               bad_method_root) ==
               VCS_ZCODE_SCIENCE_OK);
        ASSERT(vcs_object_put_addressed(dir, bad_method_root,
                                        bad_method_wire,
                                        sizeof(bad_method_wire)));
        static char bad_method_hex[65];
        zcl_hex_encode(bad_method_root, 32, bad_method_hex);
        zbex_request(dir, &ctx, &req);
        req.method_root_hex = bad_method_hex;
        executed = zcode_benchmark_execute(&ndb, &req, &out);
        ASSERT(!executed.ok);
        ASSERT(strstr(executed.message, "workload-invalid") != NULL);
        zbex_teardown(&ndb, dir);
        PASS();
    } _test_next:;
    return failures;
}

/* ── 10: reproduction flow ───────────────────────────────────────────── */

static int test_zbex_reproduction(void)
{
    int failures = 0;
    TEST("zcode_benchmark_exec: reproduction re-runs the same action, contradicts, commits") {
        struct node_db ndb = {0};
        char dir[ZBEX_DIR_CAP];
        ASSERT(zbex_setup(&ndb, dir, sizeof(dir)));
        struct zbex_context ctx;
        ASSERT(zbex_seed_context(dir, &ctx));
        /* A benchmark run produces the action/profile provenance the
         * hand-built v1 original borrows. */
        struct zcode_benchmark_execute_request req;
        zbex_request(dir, &ctx, &req);
        struct zcode_benchmark_execute_out base;
        ASSERT(zcode_benchmark_execute(&ndb, &req, &base).ok);
        ASSERT(base.committed);
        /* Hand-build the v1 original with a rigged evidence median of
         * 1 ns: any real re-run is slower, so the verdict is
         * deterministically CONTRADICTED (a negative observation). */
        uint64_t rigged_samples[16];
        for (size_t i = 0; i < 16; i++)
            rigged_samples[i] = 1;
        uint8_t rigged_payload_wire[VCS_ZCODE_SAMPLE_PAYLOAD_HEADER_BYTES +
                                    8u * 16u];
        uint8_t rigged_payload_root[32];
        ASSERT_EQ(vcs_zcode_sample_payload_v1_serialize(
                      rigged_samples, 16, rigged_payload_wire,
                      sizeof(rigged_payload_wire)),
                  VCS_ZCODE_RECEIPT_OK);
        ASSERT_EQ(vcs_zcode_sample_payload_v1_root(
                      rigged_payload_wire, sizeof(rigged_payload_wire),
                      rigged_payload_root),
                  VCS_ZCODE_RECEIPT_OK);
        ASSERT(vcs_object_put_addressed(dir, rigged_payload_root,
                                        rigged_payload_wire,
                                        sizeof(rigged_payload_wire)));
        struct vcs_zcode_raw_sample_manifest_v1 original_manifest;
        memset(&original_manifest, 0, sizeof(original_manifest));
        original_manifest.schema_version =
            VCS_ZCODE_RAW_SAMPLE_MANIFEST_VERSION;
        memcpy(original_manifest.method_root, ctx.method_root, 32);
        memcpy(original_manifest.workload_root, ctx.workload_root, 32);
        original_manifest.warmup_samples = ctx.method.warmup_samples;
        original_manifest.measured_samples = ctx.method.measured_samples;
        memcpy(original_manifest.timer_source, "tsc", 3);
        uint8_t original_manifest_wire[VCS_ZCODE_RAW_SAMPLE_MANIFEST_WIRE_BYTES];
        uint8_t original_manifest_root[32];
        ASSERT_EQ(vcs_zcode_raw_sample_manifest_v1_serialize(
                      &original_manifest, original_manifest_wire),
                  VCS_ZCODE_RECEIPT_OK);
        ASSERT_EQ(vcs_zcode_raw_sample_manifest_v1_root(
                      &original_manifest, original_manifest_root),
                  VCS_ZCODE_RECEIPT_OK);
        ASSERT(vcs_object_put_addressed(dir, original_manifest_root,
                                        original_manifest_wire,
                                        sizeof(original_manifest_wire)));
        struct vcs_zcode_benchmark_evidence_v1 original_evidence;
        memset(&original_evidence, 0, sizeof(original_evidence));
        original_evidence.schema_version =
            VCS_ZCODE_BENCHMARK_EVIDENCE_VERSION;
        memcpy(original_evidence.action_root, base.run.result.action_root,
               32);
        memcpy(original_evidence.manifest_root, original_manifest_root, 32);
        memcpy(original_evidence.sample_payload_root, rigged_payload_root,
               32);
        original_evidence.min_ns = 1;
        original_evidence.median_ns = 1;
        original_evidence.max_ns = 1;
        original_evidence.status = VCS_ZCODE_BENCHMARK_OBSERVED;
        original_evidence.isolation = VCS_ZCODE_BENCHMARK_ISOLATION_FULL;
        uint8_t original_evidence_wire[VCS_ZCODE_BENCHMARK_EVIDENCE_WIRE_BYTES];
        uint8_t original_evidence_root[32];
        ASSERT_EQ(vcs_zcode_benchmark_evidence_v1_serialize(
                      &original_evidence, original_evidence_wire),
                  VCS_ZCODE_RECEIPT_OK);
        ASSERT_EQ(vcs_zcode_benchmark_evidence_v1_root(
                      &original_evidence, original_evidence_root),
                  VCS_ZCODE_RECEIPT_OK);
        ASSERT(vcs_object_put_addressed(dir, original_evidence_root,
                                        original_evidence_wire,
                                        sizeof(original_evidence_wire)));
        struct vcs_zcode_benchmark_result_v1 original;
        memset(&original, 0, sizeof(original));
        original.schema_version = VCS_ZCODE_SCIENCE_VERSION;
        memcpy(original.study_root, ctx.study_root, 32);
        memcpy(original.task_root, ctx.task_root, 32);
        memcpy(original.candidate_root, ctx.candidate_root, 32);
        memcpy(original.action_root, base.run.result.action_root, 32);
        memcpy(original.achieved_environment_root,
               base.run.hardware_profile_root, 32);
        memcpy(original.raw_sample_root, original_manifest_root, 32);
        memcpy(original.evidence_root, original_evidence_root, 32);
        original.status = VCS_ZCODE_BENCHMARK_OBSERVED;
        original.challenge_block_height = 3200000;
        zbex_root(original.challenge_block_hash, 0x34);
        original.sequence = 1;
        original.started_unix = 1300;
        original.finished_unix = ZBEX_NOW;
        uint8_t original_wire[VCS_ZCODE_BENCHMARK_RESULT_WIRE_BYTES];
        uint8_t original_root[32];
        ASSERT_EQ(vcs_zcode_benchmark_result_serialize(&original,
                                                       original_wire),
                  VCS_ZCODE_SCIENCE_OK);
        ASSERT_EQ(vcs_zcode_benchmark_result_root(&original, original_root),
                  VCS_ZCODE_SCIENCE_OK);
        ASSERT(vcs_object_put_addressed(dir, original_root, original_wire,
                                        sizeof(original_wire)));
        /* The action-mismatch refusal lands before any run. */
        static char original_hex[65], repro_method_hex[65];
        zcl_hex_encode(original_root, 32, original_hex);
        zcl_hex_encode(ctx.method_root, 32, repro_method_hex);
        struct zcode_benchmark_execute_request repro;
        memset(&repro, 0, sizeof(repro));
        repro.workspace = dir;
        repro.method_root_hex = repro_method_hex;
        repro.original_result_root_hex = original_hex;
        repro.action_kind = VCS_BUILD_ACTION_KIND_BENCHMARK_REPRODUCE_V1;
        repro.action_sequence = 2; /* the original ran with sequence 1 */
        repro.challenge_block_height = 3200000;
        zbex_root(repro.challenge_block_hash, 0x34);
        repro.result_sequence = 2;
        zbex_root(repro.reproducer_pubkey, 0x2a);
        repro.reproduction_sequence = 1;
        repro.now = ZBEX_NOW;
        repro.confirm = true;
        struct zcode_benchmark_execute_out repro_out;
        struct zcl_result mismatch =
            zcode_benchmark_execute(&ndb, &repro, &repro_out);
        ASSERT(!mismatch.ok);
        ASSERT(strstr(mismatch.message, "action-mismatch") != NULL);
        /* The matching sequence re-runs the same fixed action and the
         * slower re-observation is a committed CONTRADICTION. */
        repro.action_sequence = 1;
        ASSERT(zcode_benchmark_execute(&ndb, &repro, &repro_out).ok);
        ASSERT(repro_out.committed);
        ASSERT_EQ(repro_out.run.verdict, VCS_ZCODE_REPRODUCTION_CONTRADICTED);
        ASSERT(vcs_object_has(dir, repro_out.run.reproduced_root));
        char repro_hex[65];
        zcl_hex_encode(repro_out.run.reproduction_root, 32, repro_hex);
        struct db_zcode_science_entry row;
        const char *kind = NULL;
        bool found = false;
        ASSERT(zcode_science_work_status(&ndb, repro_hex, &row, &kind,
                                         &found).ok);
        ASSERT(found);
        ASSERT_STR_EQ(kind, "reproduction");
        ASSERT_EQ(row.code, VCS_ZCODE_REPRODUCTION_CONTRADICTED);
        /* The reproduced v1 wire's receipt chain verifies end to end. */
        char reproduced_hex[65];
        zcl_hex_encode(repro_out.run.reproduced_root, 32, reproduced_hex);
        ASSERT(zcode_benchmark_executor_verify_receipt(dir,
                                                       reproduced_hex).ok);
        zbex_teardown(&ndb, dir);
        PASS();
    } _test_next:;
    return failures;
}

int test_zcode_benchmark_exec(void)
{
    int failures = 0;
    failures += test_zbex_codec_kats();
    failures += test_zbex_execute_happy();
    failures += test_zbex_tamper_rejected();
    failures += test_zbex_environment_mismatch();
    failures += test_zbex_null_negative();
    failures += test_zbex_sandbox_selfcheck();
    failures += test_zbex_crash_discipline();
    failures += test_zbex_closed_inputs();
    failures += test_zbex_reproduction();
    return failures;
}

#else /* _WIN32 */

/* The benchmark executor is fail-closed on Windows (its refusal is the
 * acceptance in zcode_benchmark_executor_windows_refusal_acceptance.c), and
 * the fixtures here need fork + Landlock sandbox canaries. */
int test_zcode_benchmark_exec(void)
{
    printf("test_zcode_benchmark_exec: SKIP (Windows): executor refuses on "
           "Windows by design (see the refusal acceptance)\n");
    return 0;
}

#endif /* !_WIN32 */
