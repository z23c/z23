/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Confined fixed-C23 execution backed by the existing ZVCS CAS. */
#include "services/build_fabric_worker.h"
#include "base/hex.h"
#include "base/serialize_le.h"
#include "crypto/ed25519.h"
#include "crypto/sha3.h"
#include "platform/os_proc.h"
#include "platform/time_compat.h"
#include "services/build_fabric_package_executor.h"
#include "services/build_fabric_service.h"
#include "services/build_fabric_worker_evidence.h"
#include "services/build_fabric_worker_report.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"
#include "util/file_tree_ops.h"
#include "util/spawn.h"
#include "vcs/build_action.h"
#include "vcs/build_artifact_manifest.h"
#include "vcs/vcs_object.h"
#include "vcs/zcode_action_input.h"
#include "vcs/zcode_dev.h"
#include "vcs/zcode_patch.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined(_WIN32)
struct zcl_result build_fabric_worker_execute(
    struct node_db *ndb, const char *workspace, const char *datadir,
    const char *action_id, const char *lease_id,
    const uint8_t signer_secret[32], const uint8_t signer_pubkey[32],
    struct db_build_receipt *out_receipt,
    struct build_fabric_worker_feedback *out_feedback)
{
    (void)ndb; (void)workspace; (void)datadir; (void)action_id;
    (void)lease_id; (void)signer_secret; (void)signer_pubkey;
    (void)out_receipt; (void)out_feedback;
    return ZCL_ERR(-1, "build worker disabled on Windows until the "
                   "restricted-token Job Object sandbox passes admission");
}
#else
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>
#define BFW_PATH_MAX 4096
#define BFW_CAPTURE_MAX 4096
#define BFW_EXEC_TIMEOUT_MS 125000
#define BFW_PACKAGE_WALL_TIMEOUT_MS 605000
#define BFW_FUZZ_CPU_CEILING_SECONDS 580u
#define BFW_FUZZ_TIMEOUT_CEILING_MS 585000
struct bfw_paths {
    char worker[BFW_PATH_MAX];
    char work[BFW_PATH_MAX];
    char src[BFW_PATH_MAX];
    char build[BFW_PATH_MAX];
    char emit[BFW_PATH_MAX];
    char recipe[BFW_PATH_MAX];
    char input[BFW_PATH_MAX];
    char output[BFW_PATH_MAX];
};
static int64_t bfw_children_cpu_us(void)
{
    struct rusage usage;
    if (getrusage(RUSAGE_CHILDREN, &usage) != 0) return 0;
    return (int64_t)usage.ru_utime.tv_sec * INT64_C(1000000) +
           usage.ru_utime.tv_usec +
           (int64_t)usage.ru_stime.tv_sec * INT64_C(1000000) +
           usage.ru_stime.tv_usec;
}
static uint64_t bfw_capture_metric(const char *capture, const char *key,
                                   uint64_t fallback)
{
    const char *at = capture && key ? strstr(capture, key) : NULL;
    if (!at) return fallback;
    at += strlen(key);
    if (*at != '=') return fallback;
    char *end = NULL;
    unsigned long long value = strtoull(at + 1, &end, 10);
    return end != at + 1 ? (uint64_t)value : fallback;
}
static bool bfw_capability_has(const char *capabilities, const char *wanted)
{
    if (!capabilities || !wanted || !wanted[0]) return false;
    size_t wanted_len = strlen(wanted);
    const char *at = capabilities;
    while (*at) {
        const char *end = strchr(at, ',');
        size_t len = end ? (size_t)(end - at) : strlen(at);
        if (len == wanted_len && memcmp(at, wanted, len) == 0)
            return true;
        if (!end) break;
        at = end + 1;
    }
    return false;
}
static struct zcl_result bfw_worker_path(const char *workspace,
                                         char *out, size_t cap)
{
    char exe[BFW_PATH_MAX];
    if (!os_proc_exe_path(exe, sizeof(exe)))
        return ZCL_ERR(-1, "cannot resolve the running executable");
    char *deleted = strstr(exe, " (deleted)");
    if (deleted) *deleted = '\0';
    char *slash = strrchr(exe, '/');
    if (!slash) return ZCL_ERR(-1, "running executable has no directory");
    *slash = '\0';
    const char *roots[] = {exe, workspace, "."};
    const char *mids[] = {"/", "/build/bin/", "/build/bin/"};
    const char *names[] = {"zclassic23-package-verify-dev",
                           "zclassic23-package-verify"};
    for (size_t i = 0; i < sizeof(roots) / sizeof(roots[0]); i++) {
        for (size_t j = 0; j < sizeof(names) / sizeof(names[0]); j++) {
            int n = snprintf(out, cap, "%s%s%s", roots[i], mids[i], names[j]);
            if (n > 0 && (size_t)n < cap && access(out, X_OK) == 0)
                return ZCL_OK;
        }
    }
    return ZCL_ERR(-1, "fixed development or release package verifier is not built");
}
static bool bfw_path_join(char *out, size_t cap, const char *dir, const char *leaf)
{
    int n = snprintf(out, cap, "%s/%s", dir, leaf);
    return n > 0 && (size_t)n < cap;
}

static struct zcl_result bfw_paths_init(const char *workspace, const char *lease_id,
                                        const char *kind,
                                        struct bfw_paths *p)
{
    if (!workspace || !workspace[0] || !lease_id || !p)
        return ZCL_ERR(-1, "worker paths require workspace and lease");
    ZCL_CHECK(bfw_worker_path(workspace, p->worker, sizeof(p->worker)));
    char base[BFW_PATH_MAX];
    int n = snprintf(base, sizeof(base), "%s/.zvcs/build-work", workspace);
    if (n <= 0 || (size_t)n >= sizeof(base)) return ZCL_ERR(-1, "worker base path too long");
    if (mkdir(base, 0700) != 0 && errno != EEXIST)
        return ZCL_ERR(-1, "mkdir %s: %s", base, strerror(errno));
    n = snprintf(p->work, sizeof(p->work), "%s/%s", base, lease_id);
    if (n <= 0 || (size_t)n >= sizeof(p->work) || mkdir(p->work, 0700) != 0)
        return ZCL_ERR(-1, "lease work directory exists or cannot be created");
    if (!bfw_path_join(p->src, sizeof(p->src), p->work, "src") ||
        !bfw_path_join(p->build, sizeof(p->build), p->work, "build"))
        return ZCL_ERR(-1, "isolated source/output path too long");
    if (mkdir(p->src, 0700) != 0 || mkdir(p->build, 0700) != 0)
        return ZCL_ERR(-1, "cannot create isolated source/output directories");
    if (strcmp(kind, VCS_BUILD_ACTION_KIND_V1) == 0) {
        if (!bfw_path_join(p->input, sizeof(p->input), p->src, "unit.i") ||
            !bfw_path_join(p->output, sizeof(p->output), p->build, VCS_BUILD_OUTPUT_V1))
            return ZCL_ERR(-1, "compile action path too long");
    } else if (strcmp(kind, VCS_BUILD_ACTION_KIND_TEST_V1) == 0) {
        if (!bfw_path_join(p->input, sizeof(p->input), p->build, "test.bin") ||
            !bfw_path_join(p->output, sizeof(p->output), p->build, VCS_BUILD_TEST_OUTPUT_V1))
            return ZCL_ERR(-1, "test action path too long");
    } else if (strcmp(kind, VCS_BUILD_ACTION_KIND_FUZZ_V1) == 0) {
        if (!bfw_path_join(p->input, sizeof(p->input), p->build, "fuzz.bin") ||
            !bfw_path_join(p->output, sizeof(p->output), p->build, VCS_BUILD_FUZZ_OUTPUT_V1))
            return ZCL_ERR(-1, "fuzz action path too long");
    } else if (strcmp(kind, VCS_BUILD_ACTION_KIND_PACKAGE_V1) == 0) {
        if (!bfw_path_join(p->emit, sizeof(p->emit), p->work, "emit") ||
            !bfw_path_join(p->recipe, sizeof(p->recipe), p->work, "recipe.v1"))
            return ZCL_ERR(-1, "package action path too long");
        if (mkdir(p->emit, 0700) != 0)
            return ZCL_ERR(-1, "cannot create package emit directory");
        memcpy(p->input, p->recipe, strlen(p->recipe) + 1);
        if (!bfw_path_join(p->output, sizeof(p->output), p->emit,
                           VCS_BUILD_PACKAGE_OUTPUT_V1))
            return ZCL_ERR(-1, "package output path too long");
    } else {
        return ZCL_ERR(-1, "worker action kind has no fixed executor");
    }
    return ZCL_OK;
}

static void bfw_paths_cleanup(const struct bfw_paths *p)
{
    if (!p) return;
    ZCL_IGNORE_RESULT(zcl_tree_remove(p->work),
                      "ephemeral fixed-action tree cleanup");
}
static bool bfw_write_input(const char *path, const uint8_t *bytes, size_t len,
                            bool executable)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC,
                  executable ? 0500 : 0400);
    if (fd < 0) return false;
    size_t off = 0;
    while (off < len) {
        ssize_t wrote = write(fd, bytes + off, len - off);
        if (wrote < 0) {
            if (errno == EINTR) continue;
            close(fd); (void)unlink(path); return false;
        }
        if (wrote == 0) {
            close(fd); (void)unlink(path); return false;
        }
        off += (size_t)wrote;
    }
    bool synced = fsync(fd) == 0;
    bool ok = close(fd) == 0 && synced;
    if (!ok) (void)unlink(path);
    return ok;
}
static uint8_t *bfw_read_output(const char *path, size_t *len_out)
{
    *len_out = 0;
    struct stat st;
    if (stat(path, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size <= 0 ||
        (uint64_t)st.st_size > VCS_BUILD_ARTIFACT_MAX_BYTES)
        return NULL;
    size_t len = (size_t)st.st_size;
    uint8_t *bytes = zcl_malloc(len, "zbuild.output");
    if (!bytes) return NULL;
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) { free(bytes); return NULL; }
    size_t off = 0;
    while (off < len) {
        ssize_t got = read(fd, bytes + off, len - off);
        if (got < 0 && errno == EINTR) continue;
        if (got <= 0) break;
        off += (size_t)got;
    }
    close(fd);
    if (off != len) { free(bytes); return NULL; }
    *len_out = len;
    return bytes;
}

static bool bfw_elf_relocatable_x86_64(const uint8_t *bytes, size_t len)
{
    return bytes && len >= 64 && bytes[0] == 0x7f && bytes[1] == 'E' &&
           bytes[2] == 'L' && bytes[3] == 'F' && bytes[4] == 2 &&
           bytes[5] == 1 && bytes[6] == 1 && bytes[16] == 1 &&
           bytes[17] == 0 && bytes[18] == 62 && bytes[19] == 0;
}
static bool bfw_input_root_current(const char *workspace,
                                   const char *root_hex)
{
    uint8_t root[32], checked[32], *bytes = NULL;
    size_t len = 0;
    bool loaded = zcl_hex_decode_lower(root_hex, root, 32) &&
        vcs_object_load_raw(workspace, root, &bytes, &len) == 0;
    if (loaded) sha3_256(bytes, len, checked);
    free(bytes);
    return loaded && memcmp(root, checked, 32) == 0;
}

static bool bfw_toolchain_current(const struct db_build_job *job)
{
    struct vcs_toolchain_capsule_v1 capsule;
    uint8_t root[32]; char root_hex[65];
    if (!vcs_toolchain_capsule_v1_capture_gcc(&capsule) ||
        !vcs_toolchain_capsule_v1_root(&capsule, root))
        return false;
    zcl_hex_encode(root, 32, root_hex);
    return strcmp(root_hex, job->toolchain_sha3) == 0;
}

static bool bfw_binding_current(
    struct node_db *ndb, const struct db_build_job *expected_job,
    const struct db_build_action *expected_action, const char *lease_id)
{
    struct db_build_job job;
    struct db_build_action action;
    char action_id[65], job_id[65];
    return db_build_action_find(ndb, expected_action->action_id, &action) &&
        db_build_job_find(ndb, expected_job->job_id, &job) &&
        strcmp(action.state, "VERIFYING") == 0 &&
        strcmp(action.lease_id, lease_id) == 0 &&
        build_fabric_action_id(&job, &action, action_id).ok &&
        strcmp(action_id, expected_action->action_id) == 0 &&
        build_fabric_job_id(&job, action_id, job_id).ok &&
        strcmp(job_id, expected_job->job_id) == 0 &&
        strcmp(action.task_root_sha3,
               expected_action->task_root_sha3) == 0 &&
        strcmp(action.candidate_root_sha3,
               expected_action->candidate_root_sha3) == 0 &&
        strcmp(action.proof_policy_root_sha3,
               expected_action->proof_policy_root_sha3) == 0 &&
           strcmp(action.context_root_sha3,
               expected_action->context_root_sha3) == 0;
}

struct bfw_cancel_context {
    struct node_db *ndb;
    const char *action_id;
    bool named_cancel;
};

static bool bfw_cancel_requested(void *opaque)
{
    struct bfw_cancel_context *ctx = opaque;
    struct db_build_action action;
    struct db_build_job job;
    if (!ctx || !db_build_action_find(ctx->ndb, ctx->action_id, &action) ||
        !db_build_job_find(ctx->ndb, action.job_id, &job))
        return false;
    ctx->named_cancel = strcmp(action.state, "CANCELLED") == 0 ||
                        strcmp(job.state, "CANCELLED") == 0 ||
                        job.cancel_requested;
    return ctx->named_cancel;
}

static struct zcl_result bfw_load_zcode_context(
    const char *workspace, const struct db_build_job *job,
    const struct db_build_action *action, int64_t now,
    struct vcs_zcode_task_v1 *task,
    struct vcs_zcode_candidate_v1 *candidate,
    struct vcs_zcode_proof_policy_v1 *policy, bool *present)
{
    *present = false;
    if (!action->task_root_sha3[0]) return ZCL_OK;
    uint8_t task_root[32], candidate_root[32], policy_root[32];
    if (!zcl_hex_decode_lower(action->task_root_sha3, task_root, 32) ||
        !zcl_hex_decode_lower(action->candidate_root_sha3,
                              candidate_root, 32) ||
        !zcl_hex_decode_lower(action->proof_policy_root_sha3,
                              policy_root, 32))
        return ZCL_ERR(-1, "zcode-context-roots-invalid");
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    if (vcs_object_load_raw(workspace, task_root, &wire, &wire_len) != 0 ||
        vcs_zcode_task_parse(wire, wire_len, task) != VCS_ZCODE_DEV_OK) {
        free(wire);
        return ZCL_ERR(-1, "zcode-task-cas-miss-or-corrupt");
    }
    free(wire); wire = NULL; wire_len = 0;
    uint8_t checked[32];
    if (vcs_zcode_task_root(task, checked) != VCS_ZCODE_DEV_OK ||
        memcmp(checked, task_root, 32) != 0 ||
        vcs_zcode_task_validate_at(task, now) != VCS_ZCODE_DEV_OK)
        return ZCL_ERR(-1, "zcode-task-stale-or-expired");
    if (vcs_object_load_raw(workspace, candidate_root, &wire, &wire_len) != 0 ||
        vcs_zcode_candidate_parse(wire, wire_len, candidate) !=
            VCS_ZCODE_DEV_OK) {
        free(wire);
        return ZCL_ERR(-1, "zcode-candidate-cas-miss-or-corrupt");
    }
    free(wire); wire = NULL; wire_len = 0;
    if (vcs_zcode_candidate_root(candidate, checked) != VCS_ZCODE_DEV_OK ||
        memcmp(checked, candidate_root, 32) != 0 ||
        vcs_zcode_candidate_validate_for_task(task, candidate, now) !=
            VCS_ZCODE_DEV_OK)
        return ZCL_ERR(-1, "zcode-candidate-stale");
    enum vcs_zcode_patch_result patch_verified = vcs_zcode_patch_verify_cas(
        workspace, task, candidate);
    if (patch_verified != VCS_ZCODE_PATCH_OK)
        return ZCL_ERR(-1, "zcode-patch-refused: %s",
                       vcs_zcode_patch_result_string(patch_verified));
    if (vcs_object_load_raw(workspace, policy_root, &wire, &wire_len) != 0 ||
        vcs_zcode_proof_policy_parse(wire, wire_len, policy) !=
            VCS_ZCODE_DEV_OK) {
        free(wire);
        return ZCL_ERR(-1, "zcode-proof-policy-cas-miss-or-corrupt");
    }
    free(wire);
    if (vcs_zcode_proof_policy_root(policy, checked) != VCS_ZCODE_DEV_OK ||
        memcmp(checked, policy_root, 32) != 0 ||
        memcmp(task->proof_policy_root, policy_root, 32) != 0)
        return ZCL_ERR(-1, "zcode-proof-policy-stale");
    char root_hex[65];
    zcl_hex_encode(task->toolchain_capsule_root, 32, root_hex);
    if (strcmp(root_hex, job->toolchain_sha3) != 0) {
        return ZCL_ERR(-1, "zcode-toolchain-stale");
    }
    zcl_hex_encode(candidate->candidate_source_root, 32, root_hex);
    if (strcmp(root_hex, job->source_cas_sha3) != 0)
        return ZCL_ERR(-1, "zcode-candidate-source-stale");
    *present = true;
    return ZCL_OK;
}

static struct zcl_result bfw_fail(struct node_db *ndb,
                                  const char *action_id,
                                  const char *lease_id, const char *detail)
{
    int64_t now = (int64_t)platform_time_wall_unix();
    struct zcl_result finish = build_fabric_finish_leased(
        ndb, action_id, lease_id, "LOCAL_FALLBACK", detail, now);
    if (!finish.ok)
        return ZCL_ERR(-1, "%s; fallback transition failed: %s", detail,
                       finish.message);
    return ZCL_ERR(-1, "%s; named outcome LOCAL_FALLBACK", detail);
}

// long-function-ok:one-confined-action — every recheck brackets the exact
// sandbox/CAS/signature sequence; splitting it would make stale publication
// reachable between independently callable phases.
struct zcl_result build_fabric_worker_execute(
    struct node_db *ndb, const char *workspace, const char *datadir,
    const char *action_id,
    const char *lease_id, const uint8_t signer_secret[32],
    const uint8_t signer_pubkey[32], struct db_build_receipt *out_receipt,
    struct build_fabric_worker_feedback *out_feedback)
{
    if (out_feedback) memset(out_feedback, 0, sizeof(*out_feedback));
    if (!ndb || !ndb->open || !workspace || !datadir || !action_id ||
        !lease_id ||
        !signer_secret || !signer_pubkey || !out_receipt)
        return ZCL_ERR(-1, "worker execution requires lease, workspace, and key");
    int64_t worker_started_us = platform_time_monotonic_us();
    char workspace_resolved[BFW_PATH_MAX];
    if (!realpath(workspace, workspace_resolved))
        return ZCL_ERR(-1, "worker workspace cannot be resolved: %s",
                       strerror(errno));
    workspace = workspace_resolved;
    struct db_build_action action;
    struct db_build_job job;
    struct db_build_worker worker;
    if (!db_build_action_find(ndb, action_id, &action) ||
        !db_build_job_find(ndb, action.job_id, &job) ||
        !db_build_worker_find(ndb, action.worker_id, &worker) ||
        strcmp(action.lease_id, lease_id) != 0)
        return ZCL_ERR(-1, "claimed worker action is missing or stale");
    int64_t action_lookup_us =
        platform_time_monotonic_us() - worker_started_us;
    char signer_hex[65];
    zcl_hex_encode(signer_pubkey, 32, signer_hex);
    if (strcmp(signer_hex, worker.signer_pubkey) != 0)
        return bfw_fail(ndb, action_id, lease_id, "worker-signer-mismatch");
    uint8_t work_kind = vcs_build_action_v1_work_kind(action.kind);
    bool package_action =
        strcmp(action.kind, VCS_BUILD_ACTION_KIND_PACKAGE_V1) == 0;
    if ((work_kind != VCS_ZCODE_WORK_BUILD &&
         work_kind != VCS_ZCODE_WORK_TEST &&
         work_kind != VCS_ZCODE_WORK_FUZZ) ||
        !bfw_capability_has(worker.capabilities, action.kind))
        return bfw_fail(ndb, action_id, lease_id,
                        "fixed-action-executor-unavailable");
    struct vcs_toolchain_capsule_v1 capsule;
    uint8_t capsule_root[32];
    char capsule_hex[65];
    if (!vcs_toolchain_capsule_v1_capture_gcc(&capsule) ||
        !vcs_toolchain_capsule_v1_root(&capsule, capsule_root))
        return bfw_fail(ndb, action_id, lease_id, "toolchain-capture-failed");
    zcl_hex_encode(capsule_root, 32, capsule_hex);
    if (strcmp(capsule_hex, job.toolchain_sha3) != 0)
        return bfw_fail(ndb, action_id, lease_id, "toolchain-capsule-stale");
    uint8_t fixed_flags[32], fixed_environment[32];
    char fixed_flags_hex[65], fixed_environment_hex[65];
    if (!vcs_build_action_v1_fixed_flags_root_for_kind(
            action.kind, fixed_flags) ||
        !vcs_build_action_v1_fixed_environment_root_for_kind(
            action.kind, fixed_environment))
        return bfw_fail(ndb, action_id, lease_id,
                        "fixed-action-descriptor-missing");
    zcl_hex_encode(fixed_flags, 32, fixed_flags_hex);
    zcl_hex_encode(fixed_environment, 32, fixed_environment_hex);
    if (strcmp(fixed_flags_hex, action.flags_sha3) != 0 ||
        strcmp(fixed_environment_hex, action.environment_sha3) != 0)
        return bfw_fail(ndb, action_id, lease_id,
                        "fixed-flags-or-environment-stale");
    struct vcs_zcode_task_v1 zcode_task = {0};
    struct vcs_zcode_candidate_v1 zcode_candidate = {0};
    struct vcs_zcode_proof_policy_v1 zcode_policy = {0};
    bool zcode_context = false;
    struct zcl_result context = bfw_load_zcode_context(
        workspace, &job, &action, (int64_t)platform_time_wall_unix(),
        &zcode_task, &zcode_candidate, &zcode_policy, &zcode_context);
    if (!context.ok)
        return bfw_fail(ndb, action_id, lease_id, context.message);
    if (work_kind == VCS_ZCODE_WORK_FUZZ && !zcode_context)
        return bfw_fail(ndb, action_id, lease_id,
                        "fuzz-action-requires-zcode-policy");
    if (package_action && !zcode_context)
        return bfw_fail(ndb, action_id, lease_id,
                        "package-action-requires-zcode-context");
    uint8_t input_root[32], *input = NULL; size_t input_len = 0;
    struct vcs_zcode_package_action_input_v1 package_input;
    if (!zcl_hex_decode_lower(action.input_root_sha3, input_root, 32))
        return bfw_fail(ndb, action_id, lease_id, "input-root-invalid");
    if (zcode_context && package_action) {
        enum vcs_zcode_action_input_result input_result =
            vcs_zcode_package_action_input_load_cas(
                workspace, input_root, &zcode_task, &zcode_candidate,
                &package_input);
        if (input_result != VCS_ZCODE_ACTION_INPUT_OK)
            return bfw_fail(ndb, action_id, lease_id,
                vcs_zcode_action_input_result_string(input_result));
    } else if (zcode_context) {
        enum vcs_zcode_action_input_result input_result =
            vcs_zcode_action_input_load_payload_cas(
                workspace, input_root, &zcode_task, &zcode_candidate, work_kind,
                &input, &input_len);
        if (input_result != VCS_ZCODE_ACTION_INPUT_OK)
            return bfw_fail(ndb, action_id, lease_id,
                vcs_zcode_action_input_result_string(input_result));
    } else {
        if (vcs_object_load_raw(
                workspace, input_root, &input, &input_len) != 0 ||
            input_len == 0 || input_len > VCS_BUILD_ARTIFACT_MAX_BYTES) {
            free(input); return bfw_fail(
                ndb, action_id, lease_id, "input-cas-miss");
        }
        uint8_t checked_input[32];
        sha3_256(input, input_len, checked_input);
        if (memcmp(checked_input, input_root, 32) != 0) {
            free(input); return bfw_fail(
                ndb, action_id, lease_id, "input-cas-corrupt");
        }
    }
    uint64_t input_bytes = package_action
        ? VCS_ZCODE_PACKAGE_ACTION_INPUT_WIRE_BYTES : input_len;
    uint8_t observed_input_bytes_root[32] = {0};
    if (!package_action) sha3_256(input, input_len, observed_input_bytes_root);
    char observed_input_hex[65] = {0};
    if (!package_action)
        zcl_hex_encode(observed_input_bytes_root, 32, observed_input_hex);
    int64_t input_reconstruction_us =
        platform_time_monotonic_us() - worker_started_us - action_lookup_us;
    int64_t work_started = (int64_t)platform_time_wall_unix();
    struct zcl_result start = build_fabric_start(
        ndb, action_id, lease_id, work_started);
    if (!start.ok) { free(input); return start; }
    int64_t materialize_started_us = platform_time_monotonic_us();
    struct bfw_paths paths = {0};
    struct zcl_result paths_result = bfw_paths_init(
        workspace, lease_id, action.kind, &paths);
    bool test_action = work_kind == VCS_ZCODE_WORK_TEST,
         fuzz_action = work_kind == VCS_ZCODE_WORK_FUZZ;
    struct build_fabric_package_execution package_execution;
    bool materialized = paths_result.ok;
    if (materialized && package_action) {
        struct zcl_result prepared = build_fabric_package_prepare(
            workspace, datadir, paths.worker, paths.src, paths.emit,
            paths.recipe, job.profile, &zcode_task, &zcode_candidate,
            &package_execution);
        if (!prepared.ok) {
            free(input);
            bfw_paths_cleanup(&paths);
            return bfw_fail(ndb, action_id, lease_id, prepared.message);
        }
    } else if (materialized) {
        materialized = bfw_write_input(
            paths.input, input, input_len, test_action || fuzz_action);
    }
    free(input);
    if (!materialized) {
        bfw_paths_cleanup(&paths);
        return bfw_fail(ndb, action_id, lease_id, "input-materialize-failed");
    }
    int64_t sandbox_prepare_us =
        platform_time_monotonic_us() - materialize_started_us;
    char input_arg[BFW_PATH_MAX + 32], output_arg[BFW_PATH_MAX + 32];
    char seeds_arg[64], cpu_arg[64], memory_arg[96], output_limit_arg[96];
    (void)snprintf(input_arg, sizeof(input_arg),
                   fuzz_action ? "--zbuild-fuzz-input=%s"
                   : test_action ? "--zbuild-test-input=%s"
                                 : "--zbuild-input=%s",
                   paths.input);
    (void)snprintf(output_arg, sizeof(output_arg),
                   fuzz_action ? "--zbuild-fuzz-output=%s"
                   : test_action ? "--zbuild-test-output=%s"
                                 : "--zbuild-output=%s",
                   paths.output);
    (void)snprintf(seeds_arg, sizeof(seeds_arg), "--zbuild-fuzz-seeds=%u",
                   zcode_policy.deterministic_fuzz_seeds);
    uint32_t fuzz_cpu_seconds = zcode_task.max_cpu_seconds <
            BFW_FUZZ_CPU_CEILING_SECONDS
        ? zcode_task.max_cpu_seconds : BFW_FUZZ_CPU_CEILING_SECONDS;
    uint64_t fuzz_memory_bytes = zcode_task.max_memory_bytes <
            UINT64_C(2048) * 1024u * 1024u
        ? zcode_task.max_memory_bytes : UINT64_C(2048) * 1024u * 1024u;
    uint64_t fuzz_output_bytes = zcode_task.max_output_bytes <
            UINT64_C(64) * 1024u * 1024u
        ? zcode_task.max_output_bytes : UINT64_C(64) * 1024u * 1024u;
    (void)snprintf(cpu_arg, sizeof(cpu_arg), "--zbuild-fuzz-cpu-seconds=%u",
                   fuzz_cpu_seconds);
    (void)snprintf(memory_arg, sizeof(memory_arg),
                   "--zbuild-fuzz-memory-bytes=%llu",
                   (unsigned long long)fuzz_memory_bytes);
    (void)snprintf(output_limit_arg, sizeof(output_limit_arg),
                   "--zbuild-fuzz-output-bytes=%llu",
                   (unsigned long long)fuzz_output_bytes);
    const char *argv[9];
    size_t argv_count = 0;
    if (!package_action) {
        argv[argv_count++] = paths.worker;
        argv[argv_count++] = input_arg;
        argv[argv_count++] = output_arg;
        argv[argv_count++] = fuzz_action ? seeds_arg
                                         : "--require-full-isolation";
        if (fuzz_action) {
            argv[argv_count++] = cpu_arg;
            argv[argv_count++] = memory_arg;
            argv[argv_count++] = output_limit_arg;
            argv[argv_count++] = "--require-full-isolation";
        }
    }
    argv[argv_count] = NULL;
    const char *const *spawn_argv = package_action
        ? package_execution.argv : argv;
    char capture[BFW_CAPTURE_MAX];
    int execute_timeout = BFW_EXEC_TIMEOUT_MS;
    if (fuzz_action) {
        uint64_t bounded = (uint64_t)fuzz_cpu_seconds * 1000u +
                           UINT64_C(5000);
        if (bounded > BFW_FUZZ_TIMEOUT_CEILING_MS)
            bounded = BFW_FUZZ_TIMEOUT_CEILING_MS;
        execute_timeout = (int)bounded;
    } else if (package_action) {
        /* max_cpu_seconds is enforced as aggregate child CPU by the package
         * verifier. It is not a wall budget: converting it to one false-kills
         * healthy work whenever a loaded host deschedules the sandbox. */
        execute_timeout = BFW_PACKAGE_WALL_TIMEOUT_MS;
    }
    struct bfw_cancel_context cancel_context = {
        .ndb = ndb,
        .action_id = action_id,
    };
    bool spawn_cancelled = false;
    int64_t child_cpu_before_us = bfw_children_cpu_us();
    int64_t execution_started_us = platform_time_monotonic_us();
    int rc = zcl_spawn_capture_cancelable(
        spawn_argv, capture, sizeof(capture), execute_timeout,
        bfw_cancel_requested, &cancel_context, &spawn_cancelled);
    int64_t action_execution_us =
        platform_time_monotonic_us() - execution_started_us;
    if (package_action)
        build_fabric_worker_feedback_capture(out_feedback, capture, paths.src);
    int64_t child_cpu_us = bfw_children_cpu_us() - child_cpu_before_us;
    if (spawn_cancelled) {
        bfw_paths_cleanup(&paths);
        return ZCL_ERR(-1, "%s",
                       cancel_context.named_cancel
                           ? "fixed action cancelled; named outcome CANCELLED"
                           : "fixed action execution interrupted");
    }
    const char *success_marker = package_action ? "zbuild-package-ok=1"
                                 : fuzz_action ? "zbuild-fuzz-ok=1"
                                 : test_action ? "zbuild-test-ok=1"
                                               : "zbuild-ok=1";
    if (rc != 0 || strstr(capture, success_marker) == NULL) {
        /* A HOST out of process table for this uid is a wedge, not a verdict
         * about the input; the two must never reach the log looking alike.
         * See services/build_fabric_worker_report.h. */
        char detail[BUILD_FABRIC_ERROR_MAX + 1];
        (void)build_fabric_worker_classify_report(
            capture, rc, detail, sizeof(detail));
        bfw_paths_cleanup(&paths);
        return bfw_fail(ndb, action_id, lease_id, detail);
    }
    int64_t output_verify_started_us = platform_time_monotonic_us();
    struct zcl_result verify = build_fabric_begin_verify(
        ndb, action_id, lease_id, (int64_t)platform_time_wall_unix());
    if (!verify.ok) { bfw_paths_cleanup(&paths); return verify; }
    if (!bfw_binding_current(ndb, &job, &action, lease_id)) {
        bfw_paths_cleanup(&paths);
        return bfw_fail(ndb, action_id, lease_id,
                        "action-binding-changed-during-execution");
    }
    size_t output_len = 0;
    uint8_t *output = bfw_read_output(paths.output, &output_len);
    uint8_t work_status = VCS_ZCODE_WORK_PASS;
    int work_exit_status = 0;
    bool output_valid;
    if (package_action)
        output_valid = build_fabric_package_report_parse(
            output, output_len, paths.emit, &zcode_task, &zcode_candidate,
            &package_execution, &work_status, &work_exit_status).ok;
    else if (fuzz_action)
        output_valid = build_fabric_fuzz_evidence_parse(
            output, output_len, zcode_policy.deterministic_fuzz_seeds,
            &work_status, &work_exit_status).ok;
    else if (test_action)
        output_valid = build_fabric_test_evidence_parse(
            output, output_len, &work_status, &work_exit_status).ok;
    else
        output_valid = bfw_elf_relocatable_x86_64(output, output_len);
    if (!output || !output_valid) {
        free(output); bfw_paths_cleanup(&paths);
        return bfw_fail(ndb, action_id, lease_id,
                        package_action ? "package-build-report-invalid"
                        : fuzz_action ? "fuzz-evidence-invalid"
                        : test_action ? "test-evidence-invalid"
                                      : "output-elf-invalid");
    }
    int64_t output_verify_us =
        platform_time_monotonic_us() - output_verify_started_us;
    uint8_t output_root[32];
    uint8_t output_bytes_root[32];
    sha3_256(output, output_len, output_bytes_root);
    int64_t output_cas_started_us = platform_time_monotonic_us();
    struct zcl_result stored = build_fabric_worker_store_transferable_output(
        workspace, action_id, zcode_context, output, output_len, output_root);
    free(output);
    bfw_paths_cleanup(&paths);
    if (!stored.ok)
        return bfw_fail(ndb, action_id, lease_id, stored.message);
    uint8_t evidence_root[32];
    memcpy(evidence_root, output_root, sizeof(evidence_root));
    bool compile_action = strcmp(
        action.kind, VCS_BUILD_ACTION_KIND_V1) == 0;
    if (compile_action) {
        char observed_input_marker[80];
        (void)snprintf(observed_input_marker, sizeof(observed_input_marker),
                       "input_sha3=%s", observed_input_hex);
        if (!strstr(capture, observed_input_marker) ||
            !strstr(capture, "observed_reads=2") ||
            !strstr(capture, "observed_writes=1"))
            return bfw_fail(ndb, action_id, lease_id,
                            "physical-observation-incomplete");
        struct vcs_build_execution_observation_v1 observation = {
            .schema_version = VCS_BUILD_EXECUTION_OBSERVATION_VERSION,
            .flags = VCS_BUILD_OBS_REQUIRED_FLAGS,
            .exit_status = work_exit_status,
            .cpu_seconds_limit = 120,
            .memory_bytes_limit = UINT64_C(2048) * 1024u * 1024u,
            .process_limit = 16,
            .file_limit = 64,
            .file_bytes_limit = UINT64_C(256) * 1024u * 1024u,
            .output_bytes_limit = VCS_BUILD_ARTIFACT_MAX_BYTES,
            .wall_millis_limit = 120000,
        };
        if (!zcl_hex_decode_lower(action.action_id,
                                  observation.action_root, 32) ||
            !zcl_hex_decode_lower(action.input_root_sha3,
                                  observation.action_input_root, 32) ||
            !zcl_hex_decode_lower(job.toolchain_sha3,
                                  observation.toolchain_root, 32) ||
            !zcl_hex_decode_lower(action.flags_sha3,
                                  observation.flags_root, 32) ||
            !zcl_hex_decode_lower(action.environment_sha3,
                                  observation.environment_root, 32))
            return bfw_fail(ndb, action_id, lease_id,
                            "physical-observation-roots-invalid");
        memcpy(observation.artifact_root, output_root, 32);
        memcpy(observation.observed_input_bytes_root,
               observed_input_bytes_root, 32);
        memcpy(observation.output_bytes_root, output_bytes_root, 32);
        vcs_build_execution_read_set_root(
            observation.action_input_root,
            observation.observed_input_bytes_root,
            observation.toolchain_root,
            observation.declared_reads_root);
        memcpy(observation.observed_reads_root,
               observation.declared_reads_root, 32);
        vcs_build_execution_declared_write_set_root(
            action.declared_outputs, observation.declared_writes_root);
        vcs_build_execution_observed_write_set_root(
            action.declared_outputs, observation.output_bytes_root,
            observation.observed_writes_root);
        struct zcl_result observed = build_fabric_worker_store_observation(
            workspace, &observation, evidence_root);
        if (!observed.ok)
            return bfw_fail(ndb, action_id, lease_id, observed.message);
    }
    int64_t output_cas_us =
        platform_time_monotonic_us() - output_cas_started_us;
    int64_t work_finished = (int64_t)platform_time_wall_unix();
    bool input_current = package_action
        ? vcs_zcode_package_action_input_load_cas(
              workspace, input_root, &zcode_task, &zcode_candidate,
              &package_input) == VCS_ZCODE_ACTION_INPUT_OK
        : zcode_context
        ? vcs_zcode_action_input_verify_cas(
              workspace, input_root, &zcode_task, &zcode_candidate,
              work_kind) == VCS_ZCODE_ACTION_INPUT_OK
        : bfw_input_root_current(workspace, action.input_root_sha3);
    if (!input_current)
        return bfw_fail(ndb, action_id, lease_id,
                        "input-cas-changed-during-execution");
    if (!bfw_toolchain_current(&job))
        return bfw_fail(ndb, action_id, lease_id,
                        "toolchain-changed-during-execution");
    if (zcode_context) {
        struct vcs_zcode_task_v1 checked_task;
        struct vcs_zcode_candidate_v1 checked_candidate;
        struct vcs_zcode_proof_policy_v1 checked_policy;
        bool checked_present = false;
        context = bfw_load_zcode_context(
            workspace, &job, &action, work_finished, &checked_task,
            &checked_candidate, &checked_policy, &checked_present);
        if (!context.ok || !checked_present)
            return bfw_fail(ndb, action_id, lease_id,
                            context.ok ? "zcode-context-disappeared"
                                       : context.message);
        zcode_task = checked_task;
        zcode_candidate = checked_candidate;
        zcode_policy = checked_policy;
    }
    int64_t revalidation_us =
        platform_time_monotonic_us() - output_cas_started_us - output_cas_us;
    int64_t receipt_started_us = platform_time_monotonic_us();
    struct db_build_receipt receipt = {0};
    (void)snprintf(receipt.action_id, sizeof(receipt.action_id), "%s",
                   action.action_id);
    (void)snprintf(receipt.job_id, sizeof(receipt.job_id), "%s", action.job_id);
    (void)snprintf(receipt.worker_id, sizeof(receipt.worker_id), "%s",
                   action.worker_id);
    (void)snprintf(receipt.lease_id, sizeof(receipt.lease_id), "%s", lease_id);
    (void)snprintf(receipt.action_sha3, sizeof(receipt.action_sha3), "%s",
                   action.action_id);
    zcl_hex_encode(output_root, 32, receipt.output_sha3);
    char confinement_buffer[160];
    const char *confinement = package_action
        ? "landlock=1,seccomp=1,rlimits=1,network=0,package=recipe,source=cas,dependencies=receipted"
        : test_action
        ? "landlock=1,seccomp=1,rlimits=1,network=0,test=fixed"
        : "landlock=1,seccomp=1,rlimits=1,network=0,gcc=fixed";
    if (fuzz_action) {
        (void)snprintf(confinement_buffer, sizeof(confinement_buffer),
                       "landlock=1,seccomp=1,rlimits=1,network=0,"
                       "fuzz=fixed,seeds=%u,cpu_s=%u,memory=%llu,output=%llu",
                       zcode_policy.deterministic_fuzz_seeds,
                       fuzz_cpu_seconds,
                       (unsigned long long)fuzz_memory_bytes,
                       (unsigned long long)fuzz_output_bytes);
        confinement = confinement_buffer;
    }
    (void)snprintf(receipt.confinement, sizeof(receipt.confinement),
                   "%s", confinement);
    if (compile_action)
        zcl_hex_encode(evidence_root, 32, receipt.observation_sha3);
    (void)snprintf(receipt.trust_state, sizeof(receipt.trust_state),
                   "REMOTE_OBSERVED");
    receipt.exit_status = work_exit_status;
    receipt.created_at = work_finished;
    if (zcode_context) {
        struct zcl_result canonical = build_fabric_worker_canonical_receipt(
            workspace, &action, &zcode_task, &zcode_candidate, output_root,
            work_started, work_finished, evidence_root, work_kind, work_status,
            work_exit_status, confinement, signer_secret, signer_pubkey,
            receipt.work_receipt_sha3);
        if (!canonical.ok)
            return bfw_fail(ndb, action_id, lease_id, canonical.message);
    }
    if (!build_fabric_receipt_id(&receipt, receipt.receipt_id).ok)
        return bfw_fail(ndb, action_id, lease_id, "receipt-id-failed");
    uint8_t receipt_id[32], signature[64];
    if (!zcl_hex_decode_lower(receipt.receipt_id, receipt_id, 32))
        return bfw_fail(ndb, action_id, lease_id, "receipt-id-invalid");
    ed25519_sign(signature, receipt_id, sizeof(receipt_id), signer_secret,
                 signer_pubkey);
    zcl_hex_encode(signature, sizeof(signature), receipt.signature);
    int64_t receipt_sign_us =
        platform_time_monotonic_us() - receipt_started_us;
    int64_t projection_started_us = platform_time_monotonic_us();
    struct zcl_result accepted = build_fabric_receipt_quarantine(
        ndb, &receipt, receipt.created_at);
    if (!accepted.ok) return accepted;
    int64_t projection_us =
        platform_time_monotonic_us() - projection_started_us;
    uint64_t child_processes = bfw_capture_metric(
        capture, "processes", 1);
    uint64_t compiler_processes = bfw_capture_metric(
        capture, "compiler_processes", package_action ? 0 : 1);
    uint64_t test_processes = bfw_capture_metric(
        capture, "test_processes", test_action || fuzz_action ? 1 : 0);
    LOG_INFO("zcode.proof_perf",
             "schema=zcl.async_proof_perf.v1 action=%s stage=worker_execute "
             "at_unix_us=%lld "
             "lookup_us=%lld input_reconstruction_us=%lld "
             "sandbox_prepare_us=%lld execution_us=%lld child_cpu_us=%lld "
             "output_verify_us=%lld output_cas_us=%lld revalidation_us=%lld "
             "receipt_sign_us=%lld projection_us=%lld input_bytes=%llu "
             "output_bytes=%zu processes=%llu compiler_processes=%llu "
             "test_processes=%llu cache_hit=%d total_us=%lld",
             action.action_id, (long long)platform_time_realtime_us(),
             (long long)action_lookup_us,
             (long long)input_reconstruction_us,
             (long long)sandbox_prepare_us, (long long)action_execution_us,
             (long long)(child_cpu_us < 0 ? 0 : child_cpu_us),
             (long long)output_verify_us, (long long)output_cas_us,
             (long long)revalidation_us, (long long)receipt_sign_us,
             (long long)projection_us, (unsigned long long)input_bytes,
             output_len, (unsigned long long)child_processes,
             (unsigned long long)compiler_processes,
             (unsigned long long)test_processes,
             strcmp(action.state, "CACHE_HIT") == 0 ? 1 : 0,
             (long long)(platform_time_monotonic_us() - worker_started_us));
    *out_receipt = receipt;
    return ZCL_OK;
}
#endif
