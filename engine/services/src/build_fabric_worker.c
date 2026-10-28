/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Confined fixed-C23 execution backed by the existing ZVCS CAS. */
/* realpath() reaches this TU only through the glibc fortify inline that
 * -D_FORTIFY_SOURCE=2 pulls in at -O1 and above; the build's
 * -D_POSIX_C_SOURCE=200809L declares it nowhere. Without this the file
 * compiles by accident of optimisation and breaks at -O0, under
 * -U_FORTIFY_SOURCE, and on any non-glibc libc. It must precede every
 * include: after them it does nothing. See platform/modules/util/src/hw_profile.c. */
#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif

#include "services/build_fabric_worker.h"
#include "build_fabric_worker_internal.h"
#include "base/hex.h"
#include "base/serialize_le.h"
#include "crypto/ed25519.h"
#include "crypto/sha3.h"
#include "platform/os_proc.h"
#include "platform/time_compat.h"
#include "services/build_fabric_attach.h"
#include "services/build_fabric_package_executor.h"
#include "services/build_fabric_service.h"
#include "services/build_fabric_worker_evidence.h"
#include "services/build_fabric_worker_report.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"
#include "util/file_tree_ops.h"
#include "util/path_util.h"
#include "util/spawn.h"
#include "vcs/build_action.h"
#include "vcs/build_artifact_manifest.h"
#include "vcs/package_store.h"
#include "vcs/vcs_object.h"
#include "vcs/zcode_action_input.h"
#include "vcs/zcode_dev.h"
#include "vcs/zcode_patch.h"
#if !defined(_WIN32)
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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
/* The sandboxed child's own `key=value` stdout claim, matched only at a
 * token start so `processes` never reads `compiler_processes`. */
static uint64_t bfw_capture_metric(const char *capture, const char *key)
{
    size_t key_len = key ? strlen(key) : 0;
    for (const char *at = capture && key_len ? strstr(capture, key) : NULL;
         at; at = strstr(at + 1, key)) {
        bool token_start = at == capture || at[-1] == ' ' ||
                           at[-1] == '\n' || at[-1] == '\t';
        if (!token_start || at[key_len] != '=') continue;
        char *end = NULL;
        unsigned long long value = strtoull(at + key_len + 1, &end, 10);
        return end != at + key_len + 1 ? (uint64_t)value : 0;
    }
    return 0;
}
/* Host-observed accounting of the confined executor. The child's process
 * counts are copied only into the separately named unverified fields. */
static void bfw_accounting_record(
    struct build_fabric_host_accounting *out,
    const struct zcl_spawn_measure *measure, const char *capture,
    uint64_t thread_launches_before)
{
    if (!out) return;
    out->measured = measure->launched;
    out->reaped = measure->reaped;
    out->io_observed = measure->io_observed;
    out->io_error = measure->io_error;
    out->host_processes_launched =
        zcl_spawn_thread_launch_count() - thread_launches_before;
    out->host_executor_launches = measure->launched ? 1u : 0u;
    out->host_wall_us = measure->wall_us;
    out->host_cpu_user_us = measure->cpu_user_us;
    out->host_cpu_system_us = measure->cpu_system_us;
    out->host_max_rss_kib = measure->max_rss_kib;
    out->host_in_blocks = measure->in_blocks;
    out->host_out_blocks = measure->out_blocks;
    out->host_read_bytes = measure->read_bytes;
    out->host_write_bytes = measure->write_bytes;
    out->host_storage_read_bytes = measure->storage_read_bytes;
    out->host_storage_write_bytes = measure->storage_write_bytes;
    out->child_reported_processes_unverified =
        bfw_capture_metric(capture, "processes");
    out->child_reported_compiler_processes_unverified =
        bfw_capture_metric(capture, "compiler_processes");
    out->child_reported_test_processes_unverified =
        bfw_capture_metric(capture, "test_processes");
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
static bool bfw_is_release_node_image(const char *path)
{
    const char *base = path ? strrchr(path, '/') : NULL;
    base = base ? base + 1 : path;
    return base && (strcmp(base, "z23") == 0 ||
                    strcmp(base, "zclassic23") == 0);
}

static struct zcl_result bfw_worker_path_from_executable(
    const char *running_executable, const char *workspace, char *out,
    size_t cap)
{
    if (!running_executable || !running_executable[0])
        return ZCL_ERR(-1, "cannot resolve the running executable");
    char exe[BFW_PATH_MAX];
    int copied = snprintf(exe, sizeof(exe), "%s", running_executable);
    if (copied <= 0 || (size_t)copied >= sizeof(exe))
        return ZCL_ERR(-1, "running executable path is too long");
    char *deleted = strstr(exe, " (deleted)");
    if (deleted) *deleted = '\0';
    char *slash = strrchr(exe, '/');
    if (!slash) return ZCL_ERR(-1, "running executable has no directory");
    bool release_image = bfw_is_release_node_image(exe);
    *slash = '\0';
    const char *roots[] = {exe, workspace, "."};
    const char *mids[] = {"/", "/build/bin/", "/build/bin/"};
    /* New z23-* names first; the zclassic23-* names are the migration
     * symlinks, and the only names inside already-shipped release trees. */
    const char *development_names[] = {"z23-package-verify-dev",
                                       "zclassic23-package-verify-dev",
                                       "z23-package-verify",
                                       "zclassic23-package-verify"};
    const char *release_names[] = {"z23-package-verify",
                                   "zclassic23-package-verify"};
    const char *const *names = release_image ? release_names : development_names;
    const size_t name_count = release_image
        ? sizeof(release_names) / sizeof(release_names[0])
        : sizeof(development_names) / sizeof(development_names[0]);
    for (size_t i = 0; i < sizeof(roots) / sizeof(roots[0]); i++) {
        for (size_t j = 0; j < name_count; j++) {
            int n = snprintf(out, cap, "%s%s%s", roots[i], mids[i], names[j]);
            if (n > 0 && (size_t)n < cap && access(out, X_OK) == 0)
                return ZCL_OK;
        }
    }
    return ZCL_ERR(-1, "fixed development or release package verifier is not built");
}

struct zcl_result bfw_worker_path(const char *workspace,
                                  char *out, size_t cap)
{
    char exe[BFW_PATH_MAX];
    if (!os_proc_exe_path(exe, sizeof(exe)))
        return ZCL_ERR(-1, "cannot resolve the running executable");
    return bfw_worker_path_from_executable(exe, workspace, out, cap);
}

#ifdef ZCL_TESTING
struct zcl_result build_fabric_worker_verifier_path_for_test(
    const char *running_executable, const char *workspace, char *out,
    size_t cap)
{
    return bfw_worker_path_from_executable(running_executable, workspace,
                                           out, cap);
}
#endif
static struct zcl_result bfw_paths_directories(const char *workspace,
                                               const char *lease_id,
                                               struct bfw_paths *p)
{
    char base[BFW_PATH_MAX];
    int n = snprintf(base, sizeof(base), "%s/.zvcs/build-work", workspace);
    if (n <= 0 || (size_t)n >= sizeof(base)) return ZCL_ERR(-1, "worker base path too long");
    if (mkdir(base, 0700) != 0 && errno != EEXIST)
        return ZCL_ERR(-1, "mkdir %s: %s", base, strerror(errno));
    n = snprintf(p->work, sizeof(p->work), "%s/%s", base, lease_id);
    if (n <= 0 || (size_t)n >= sizeof(p->work) || mkdir(p->work, 0700) != 0)
        return ZCL_ERR(-1, "lease work directory exists or cannot be created");
    if (!zcl_path_join(p->src, sizeof(p->src), p->work, "src") ||
        !zcl_path_join(p->build, sizeof(p->build), p->work, "build"))
        return ZCL_ERR(-1, "isolated source/output path too long");
    if (mkdir(p->src, 0700) != 0 || mkdir(p->build, 0700) != 0)
        return ZCL_ERR(-1, "cannot create isolated source/output directories");
    return ZCL_OK;
}
static struct zcl_result bfw_paths_action(const char *kind, struct bfw_paths *p)
{
    if (strcmp(kind, VCS_BUILD_ACTION_KIND_V1) == 0) {
        if (!zcl_path_join(p->input, sizeof(p->input), p->src, "unit.i") ||
            !zcl_path_join(p->output, sizeof(p->output), p->build, VCS_BUILD_OUTPUT_V1))
            return ZCL_ERR(-1, "compile action path too long");
    } else if (strcmp(kind, VCS_BUILD_ACTION_KIND_TEST_V1) == 0) {
        if (!zcl_path_join(p->input, sizeof(p->input), p->build, "test.bin") ||
            !zcl_path_join(p->output, sizeof(p->output), p->build, VCS_BUILD_TEST_OUTPUT_V1))
            return ZCL_ERR(-1, "test action path too long");
    } else if (strcmp(kind, VCS_BUILD_ACTION_KIND_FUZZ_V1) == 0) {
        if (!zcl_path_join(p->input, sizeof(p->input), p->build, "fuzz.bin") ||
            !zcl_path_join(p->output, sizeof(p->output), p->build, VCS_BUILD_FUZZ_OUTPUT_V1))
            return ZCL_ERR(-1, "fuzz action path too long");
    } else if (strcmp(kind, VCS_BUILD_ACTION_KIND_PACKAGE_V1) == 0) {
        if (!zcl_path_join(p->emit, sizeof(p->emit), p->work, "emit") ||
            !zcl_path_join(p->recipe, sizeof(p->recipe), p->work, "recipe.v1"))
            return ZCL_ERR(-1, "package action path too long");
        if (mkdir(p->emit, 0700) != 0)
            return ZCL_ERR(-1, "cannot create package emit directory");
        memcpy(p->input, p->recipe, strlen(p->recipe) + 1);
        if (!zcl_path_join(p->output, sizeof(p->output), p->emit,
                           VCS_BUILD_PACKAGE_OUTPUT_V1))
            return ZCL_ERR(-1, "package output path too long");
    } else {
        return ZCL_ERR(-1, "worker action kind has no fixed executor");
    }
    return ZCL_OK;
}
static struct zcl_result bfw_paths_init(const char *workspace, const char *lease_id,
                                        const char *kind,
                                        struct bfw_paths *p)
{
    if (!workspace || !workspace[0] || !lease_id || !p)
        return ZCL_ERR(-1, "worker paths require workspace and lease");
    ZCL_CHECK(bfw_worker_path(workspace, p->worker, sizeof(p->worker)));
    struct zcl_result directories = bfw_paths_directories(workspace, lease_id, p);
    if (!directories.ok) return directories;
    return bfw_paths_action(kind, p);
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
#if !defined(__APPLE__)
static bool bfw_elf_relocatable_x86_64(const uint8_t *bytes, size_t len)
{
    return bytes && len >= 64 && bytes[0] == 0x7f && bytes[1] == 'E' &&
           bytes[2] == 'L' && bytes[3] == 'F' && bytes[4] == 2 &&
           bytes[5] == 1 && bytes[6] == 1 && bytes[16] == 1 &&
           bytes[17] == 0 && bytes[18] == 62 && bytes[19] == 0;
}
#else
static bool bfw_macho_relocatable_arm64(const uint8_t *bytes, size_t len)
{
    /* Thin, little-endian Mach-O 64: MH_MAGIC_64, CPU_TYPE_ARM64,
     * MH_OBJECT.  The fixed compiler action emits a native relocatable, not
     * the Linux ELF object checked by the other host path. */
    return bytes && len >= 32 && bytes[0] == 0xcf && bytes[1] == 0xfa &&
           bytes[2] == 0xed && bytes[3] == 0xfe && bytes[4] == 0x0c &&
           bytes[5] == 0x00 && bytes[6] == 0x00 && bytes[7] == 0x01 &&
           bytes[12] == 0x01 && bytes[13] == 0x00 && bytes[14] == 0x00 &&
           bytes[15] == 0x00;
}
#endif

static bool bfw_native_relocatable(const uint8_t *bytes, size_t len)
{
#if defined(__APPLE__)
    return bfw_macho_relocatable_arm64(bytes, len);
#else
    return bfw_elf_relocatable_x86_64(bytes, len);
#endif
}
struct bfw_cancel_context {
    struct node_db *ndb;
    const struct db_build_action *expected;
    bool named_cancel;
};

#ifdef ZCL_TESTING
static void (*bfw_test_before_owner_check)(void *);
static void *bfw_test_owner_context;
void build_fabric_worker_test_before_owner_check(void (*hook)(void *),
                                                void *context)
{
    bfw_test_before_owner_check = hook;
    bfw_test_owner_context = context;
}
#endif

static bool bfw_cancel_requested(void *opaque)
{
    struct bfw_cancel_context *ctx = opaque;
    struct db_build_action action;
    struct db_build_job job;
#ifdef ZCL_TESTING
    if (bfw_test_before_owner_check)
        bfw_test_before_owner_check(bfw_test_owner_context);
#endif
    if (!ctx || !ctx->expected ||
        !db_build_action_find(ctx->ndb, ctx->expected->action_id, &action) ||
        !db_build_job_find(ctx->ndb, action.job_id, &job))
        return true;
    ctx->named_cancel = strcmp(action.state, "CANCELLED") == 0 ||
                        strcmp(job.state, "CANCELLED") == 0 ||
                        job.cancel_requested;
    return ctx->named_cancel || strcmp(action.state, "RUNNING") != 0 ||
           strcmp(action.lease_id, ctx->expected->lease_id) != 0 ||
           strcmp(action.worker_id, ctx->expected->worker_id) != 0 ||
           strcmp(action.job_id, ctx->expected->job_id) != 0 ||
           action.attempt_count != ctx->expected->attempt_count ||
           action.lease_expires_at == 0 ||
           (int64_t)platform_time_wall_unix() >= action.lease_expires_at;
}

static const char *bfw_owner_loss_detail(bool launched)
{
    return launched ? "fixed action ownership lost; executor interrupted"
                    : "fixed action ownership lost before executor launch";
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

static struct zcl_result bfw_validate_descriptor(
    struct node_db *ndb, const char *action_id, const char *lease_id,
    const struct db_build_action *action, const struct db_build_job *job)
{
    struct vcs_toolchain_capsule_v1 capsule;
    uint8_t capsule_root[32], fixed_flags[32], fixed_environment[32];
    char capsule_hex[65], fixed_flags_hex[65], fixed_environment_hex[65];
    if (!vcs_toolchain_capsule_v1_capture(&capsule) ||
        !vcs_toolchain_capsule_v1_root(&capsule, capsule_root))
        return bfw_fail(ndb, action_id, lease_id, "toolchain-capture-failed");
    zcl_hex_encode(capsule_root, 32, capsule_hex);
    if (strcmp(capsule_hex, job->toolchain_sha3) != 0)
        return bfw_fail(ndb, action_id, lease_id, "toolchain-capsule-stale");
    if (!vcs_build_action_v1_fixed_flags_root_for_kind(action->kind, fixed_flags) ||
        !vcs_build_action_v1_fixed_environment_root_for_kind(action->kind, fixed_environment))
        return bfw_fail(ndb, action_id, lease_id, "fixed-action-descriptor-missing");
    zcl_hex_encode(fixed_flags, 32, fixed_flags_hex);
    zcl_hex_encode(fixed_environment, 32, fixed_environment_hex);
    if (strcmp(fixed_flags_hex, action->flags_sha3) != 0 ||
        strcmp(fixed_environment_hex, action->environment_sha3) != 0)
        return bfw_fail(ndb, action_id, lease_id, "fixed-flags-or-environment-stale");
    return ZCL_OK;
}

struct bfw_input_state {
    uint8_t root[32];
    uint8_t *bytes;
    size_t len;
    struct vcs_zcode_package_action_input_v1 package;
};

static struct zcl_result bfw_load_input(
    struct node_db *ndb, const char *workspace, const char *action_id,
    const char *lease_id, const struct db_build_action *action,
    const struct vcs_zcode_task_v1 *task,
    const struct vcs_zcode_candidate_v1 *candidate,
    bool zcode_context, bool package_action, uint8_t work_kind,
    struct bfw_input_state *input)
{
    if (!zcl_hex_decode_lower(action->input_root_sha3, input->root, 32))
        return bfw_fail(ndb, action_id, lease_id, "input-root-invalid");
    if (zcode_context && package_action) {
        enum vcs_zcode_action_input_result result =
            vcs_zcode_package_action_input_load_cas(workspace, input->root,
                task, candidate, &input->package);
        if (result != VCS_ZCODE_ACTION_INPUT_OK)
            return bfw_fail(ndb, action_id, lease_id,
                            vcs_zcode_action_input_result_string(result));
    } else if (zcode_context) {
        enum vcs_zcode_action_input_result result =
            vcs_zcode_action_input_load_payload_cas(workspace, input->root,
                task, candidate, work_kind, &input->bytes, &input->len);
        if (result != VCS_ZCODE_ACTION_INPUT_OK)
            return bfw_fail(ndb, action_id, lease_id,
                            vcs_zcode_action_input_result_string(result));
    } else {
        if (vcs_object_load_raw(workspace, input->root, &input->bytes,
                                &input->len) != 0 || input->len == 0 ||
            input->len > VCS_BUILD_ARTIFACT_MAX_BYTES) {
            free(input->bytes);
            return bfw_fail(ndb, action_id, lease_id, "input-cas-miss");
        }
        uint8_t checked[32];
        sha3_256(input->bytes, input->len, checked);
        if (memcmp(checked, input->root, 32) != 0) {
            free(input->bytes);
            return bfw_fail(ndb, action_id, lease_id, "input-cas-corrupt");
        }
    }
    return ZCL_OK;
}

static struct zcl_result bfw_materialize(
    struct node_db *ndb, const char *workspace, const char *datadir,
    const char *action_id, const char *lease_id,
    const struct db_build_action *action, const struct db_build_job *job,
    const struct vcs_zcode_task_v1 *task,
    const struct vcs_zcode_candidate_v1 *candidate,
    bool package_action, bool test_action, bool fuzz_action,
    uint8_t *input, size_t input_len, struct bfw_paths *paths,
    struct build_fabric_package_execution *package_execution)
{
    struct zcl_result paths_result = bfw_paths_init(
        workspace, lease_id, action->kind, paths);
    bool materialized = paths_result.ok;
    if (materialized && package_action) {
        struct zcl_result prepared = build_fabric_package_prepare(
            workspace, datadir, paths->worker, paths->src, paths->emit,
            paths->recipe, job->profile, task, candidate, package_execution);
        if (!prepared.ok) {
            free(input);
            bfw_paths_cleanup(paths);
            return bfw_fail(ndb, action_id, lease_id, prepared.message);
        }
    } else if (materialized) {
        materialized = bfw_write_input(paths->input, input, input_len,
                                       test_action || fuzz_action);
    }
    free(input);
    if (!materialized) {
        bfw_paths_cleanup(paths);
        return bfw_fail(ndb, action_id, lease_id, "input-materialize-failed");
    }
    return ZCL_OK;
}

struct bfw_argv_state {
    char input_arg[BFW_PATH_MAX + 32], output_arg[BFW_PATH_MAX + 32];
    char seeds_arg[64], cpu_arg[64], memory_arg[96], output_limit_arg[96];
    const char *argv[9];
    const char *const *selected;
    uint32_t fuzz_cpu_seconds;
    uint64_t fuzz_memory_bytes, fuzz_output_bytes;
    int timeout;
};

static void bfw_prepare_argv(struct bfw_argv_state *s,
                             const struct bfw_paths *paths,
                             const struct vcs_zcode_task_v1 *task,
                             const struct vcs_zcode_proof_policy_v1 *policy,
                             const struct build_fabric_package_execution *package,
                             bool package_action, bool test_action,
                             bool fuzz_action)
{
    (void)snprintf(s->input_arg, sizeof(s->input_arg),
                   fuzz_action ? "--zbuild-fuzz-input=%s" :
                   test_action ? "--zbuild-test-input=%s" : "--zbuild-input=%s",
                   paths->input);
    (void)snprintf(s->output_arg, sizeof(s->output_arg),
                   fuzz_action ? "--zbuild-fuzz-output=%s" :
                   test_action ? "--zbuild-test-output=%s" : "--zbuild-output=%s",
                   paths->output);
    (void)snprintf(s->seeds_arg, sizeof(s->seeds_arg), "--zbuild-fuzz-seeds=%u",
                   policy->deterministic_fuzz_seeds);
    s->fuzz_cpu_seconds = task->max_cpu_seconds < BFW_FUZZ_CPU_CEILING_SECONDS
        ? task->max_cpu_seconds : BFW_FUZZ_CPU_CEILING_SECONDS;
    s->fuzz_memory_bytes = task->max_memory_bytes < UINT64_C(2048)*1024u*1024u
        ? task->max_memory_bytes : UINT64_C(2048)*1024u*1024u;
    s->fuzz_output_bytes = task->max_output_bytes < UINT64_C(64)*1024u*1024u
        ? task->max_output_bytes : UINT64_C(64)*1024u*1024u;
    (void)snprintf(s->cpu_arg, sizeof(s->cpu_arg), "--zbuild-fuzz-cpu-seconds=%u", s->fuzz_cpu_seconds);
    (void)snprintf(s->memory_arg, sizeof(s->memory_arg), "--zbuild-fuzz-memory-bytes=%llu", (unsigned long long)s->fuzz_memory_bytes);
    (void)snprintf(s->output_limit_arg, sizeof(s->output_limit_arg), "--zbuild-fuzz-output-bytes=%llu", (unsigned long long)s->fuzz_output_bytes);
    size_t n = 0;
    if (!package_action) {
        s->argv[n++] = paths->worker;
        s->argv[n++] = s->input_arg;
        s->argv[n++] = s->output_arg;
        s->argv[n++] = fuzz_action ? s->seeds_arg : "--require-full-isolation";
        if (fuzz_action) {
            s->argv[n++] = s->cpu_arg;
            s->argv[n++] = s->memory_arg;
            s->argv[n++] = s->output_limit_arg;
            s->argv[n++] = "--require-full-isolation";
        }
    }
    s->argv[n] = NULL;
    s->selected = package_action ? package->argv : s->argv;
    s->timeout = BFW_EXEC_TIMEOUT_MS;
    if (fuzz_action) {
        uint64_t bounded = (uint64_t)s->fuzz_cpu_seconds * 1000u + UINT64_C(5000);
        if (bounded > BFW_FUZZ_TIMEOUT_CEILING_MS) bounded = BFW_FUZZ_TIMEOUT_CEILING_MS;
        s->timeout = (int)bounded;
    } else if (package_action) {
        s->timeout = BFW_PACKAGE_WALL_TIMEOUT_MS;
    }
}

static bool bfw_output_valid(
    bool package_action, bool fuzz_action, bool test_action,
    const uint8_t *output, size_t output_len, const struct bfw_paths *paths,
    const struct vcs_zcode_task_v1 *task,
    const struct vcs_zcode_candidate_v1 *candidate,
    const struct vcs_zcode_proof_policy_v1 *policy,
    const struct build_fabric_package_execution *package_execution,
    uint8_t *work_status, int *work_exit_status)
{
    if (package_action)
        return build_fabric_package_report_parse(
            output, output_len, paths->emit, task, candidate,
            package_execution, work_status, work_exit_status).ok;
    if (fuzz_action)
        return build_fabric_fuzz_evidence_parse(
            output, output_len, policy->deterministic_fuzz_seeds,
            work_status, work_exit_status).ok;
    if (test_action)
        return build_fabric_test_evidence_parse(
            output, output_len, work_status, work_exit_status).ok;
    return bfw_native_relocatable(output, output_len);
}

static struct zcl_result bfw_revalidate(
    struct node_db *ndb, const char *workspace, const char *action_id,
    const char *lease_id, const struct db_build_job *job,
    const struct db_build_action *action, uint8_t work_kind,
    bool package_action, bool zcode_context, int64_t work_finished,
    struct bfw_input_state *input, struct vcs_zcode_task_v1 *task,
    struct vcs_zcode_candidate_v1 *candidate,
    struct vcs_zcode_proof_policy_v1 *policy)
{
    bool input_current = package_action
        ? vcs_zcode_package_action_input_load_cas(
              workspace, input->root, task, candidate, &input->package)
              == VCS_ZCODE_ACTION_INPUT_OK
        : zcode_context
        ? vcs_zcode_action_input_verify_cas(workspace, input->root, task,
              candidate, work_kind) == VCS_ZCODE_ACTION_INPUT_OK
        : bfw_input_root_current(workspace, action->input_root_sha3);
    if (!input_current)
        return bfw_fail(ndb, action_id, lease_id,
                        "input-cas-changed-during-execution");
    if (!bfw_toolchain_current(job))
        return bfw_fail(ndb, action_id, lease_id,
                        "toolchain-changed-during-execution");
    if (zcode_context) {
        struct vcs_zcode_task_v1 checked_task;
        struct vcs_zcode_candidate_v1 checked_candidate;
        struct vcs_zcode_proof_policy_v1 checked_policy;
        bool checked_present = false;
        struct zcl_result context = bfw_load_zcode_context(
            workspace, job, action, work_finished, &checked_task,
            &checked_candidate, &checked_policy, &checked_present);
        if (!context.ok || !checked_present)
            return bfw_fail(ndb, action_id, lease_id,
                            context.ok ? "zcode-context-disappeared"
                                       : context.message);
        *task = checked_task;
        *candidate = checked_candidate;
        *policy = checked_policy;
    }
    return ZCL_OK;
}

struct bfw_spawn_state {
    char capture[BFW_CAPTURE_MAX];
    struct build_fabric_executor_identity checked_identity;
    struct zcl_spawn_measure measure;
    bool attach_identity_stable;
    int64_t action_execution_us;
    int64_t child_cpu_us;
};

static struct zcl_result bfw_spawn_and_classify(
    struct node_db *ndb, const char *workspace, const char *action_id,
    const char *lease_id, const struct db_build_action *action,
    const struct bfw_paths *paths, uint8_t work_kind, bool package_action,
    bool test_action, bool fuzz_action, const char *const *spawn_argv,
    int execute_timeout, uint64_t thread_launches_before,
    struct build_fabric_worker_feedback *out_feedback,
    struct build_fabric_host_accounting *out_accounting,
    struct bfw_spawn_state *out)
{
    struct bfw_cancel_context cancel_context = {.ndb = ndb, .expected = action};
    bool spawn_cancelled = false;
    out->attach_identity_stable = false;
    int64_t execution_started_us = platform_time_monotonic_us();
    int rc = bfw_attach_spawn(workspace, paths->worker, work_kind,
        package_action, spawn_argv, out->capture, sizeof(out->capture),
        execute_timeout, bfw_cancel_requested, &cancel_context,
        &spawn_cancelled, &out->checked_identity,
        &out->attach_identity_stable, &out->measure);
    out->action_execution_us = platform_time_monotonic_us() - execution_started_us;
    bfw_accounting_record(out_accounting, &out->measure, out->capture,
                          thread_launches_before);
    if (package_action)
        build_fabric_worker_feedback_capture(out_feedback, out->capture, paths->src);
    out->child_cpu_us = out->measure.cpu_user_us + out->measure.cpu_system_us;
    if (spawn_cancelled) {
        bfw_paths_cleanup(paths);
        return ZCL_ERR(-1, "%s", cancel_context.named_cancel
            ? "fixed action cancelled; named outcome CANCELLED"
            : bfw_owner_loss_detail(out->measure.launched));
    }
    const char *success_marker = package_action ? "zbuild-package-ok=1"
                                 : fuzz_action ? "zbuild-fuzz-ok=1"
                                 : test_action ? "zbuild-test-ok=1"
                                               : "zbuild-ok=1";
    if (rc != 0 || strstr(out->capture, success_marker) == NULL) {
        char detail[BUILD_FABRIC_ERROR_MAX + 1];
        (void)build_fabric_worker_classify_report(out->capture, rc,
                                                 detail, sizeof(detail));
        bfw_paths_cleanup(paths);
        return bfw_fail(ndb, action_id, lease_id, detail);
    }
    return ZCL_OK;
}

struct bfw_output_state {
    size_t len;
    uint8_t work_status;
    int work_exit_status;
    int64_t verify_us, cas_started_us;
    uint8_t root[32], bytes_root[32];
};

static struct zcl_result bfw_verify_and_store_output(
    struct node_db *ndb, const char *workspace, const char *action_id,
    const char *lease_id, const struct db_build_job *job,
    const struct db_build_action *action, const struct bfw_paths *paths,
    bool package_action, bool fuzz_action, bool test_action, bool zcode_context,
    const struct vcs_zcode_task_v1 *task,
    const struct vcs_zcode_candidate_v1 *candidate,
    const struct vcs_zcode_proof_policy_v1 *policy,
    const struct build_fabric_package_execution *package_execution,
    struct bfw_output_state *out)
{
    int64_t started_us = platform_time_monotonic_us();
    struct zcl_result verify = build_fabric_begin_verify(
        ndb, action_id, lease_id, (int64_t)platform_time_wall_unix());
    if (!verify.ok) { bfw_paths_cleanup(paths); return verify; }
    if (!bfw_binding_current(ndb, job, action, lease_id)) {
        bfw_paths_cleanup(paths);
        return bfw_fail(ndb, action_id, lease_id,
                        "action-binding-changed-during-execution");
    }
    out->len = 0;
    uint8_t *output = bfw_read_output(paths->output, &out->len);
    out->work_status = VCS_ZCODE_WORK_PASS;
    out->work_exit_status = 0;
    bool valid = bfw_output_valid(package_action, fuzz_action, test_action,
        output, out->len, paths, task, candidate, policy, package_execution,
        &out->work_status, &out->work_exit_status);
    if (!output || !valid) {
        free(output); bfw_paths_cleanup(paths);
        return bfw_fail(ndb, action_id, lease_id,
                        package_action ? "package-build-report-invalid"
                        : fuzz_action ? "fuzz-evidence-invalid"
                        : test_action ? "test-evidence-invalid"
#if defined(__APPLE__)
                                      : "output-macho-invalid");
#else
                                      : "output-elf-invalid");
#endif
    }
    out->verify_us = platform_time_monotonic_us() - started_us;
    sha3_256(output, out->len, out->bytes_root);
    out->cas_started_us = platform_time_monotonic_us();
    struct zcl_result stored = build_fabric_worker_store_transferable_output(
        workspace, action_id, zcode_context, output, out->len, out->root);
    free(output);
    bfw_paths_cleanup(paths);
    if (!stored.ok) return bfw_fail(ndb, action_id, lease_id, stored.message);
    return ZCL_OK;
}

static struct zcl_result bfw_store_observation_and_attach(
    struct node_db *ndb, const char *workspace, const char *action_id,
    const char *lease_id, const struct db_build_action *action,
    const struct db_build_job *job, const char *capture,
    const char *observed_input_hex, const uint8_t observed_input_bytes_root[32],
    const uint8_t output_root[32], const uint8_t output_bytes_root[32],
    int work_exit_status, bool attach_identity_stable,
    const struct build_fabric_executor_identity *checked_identity,
    uint8_t evidence_root[32])
{
        char observed_input_marker[80];
        (void)snprintf(observed_input_marker, sizeof(observed_input_marker),
                       "input_sha3=%s", observed_input_hex);
        if (!strstr(capture, observed_input_marker) ||
            !strstr(capture, "observed_reads=3") ||
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
        if (!zcl_hex_decode_lower(action->action_id,
                                  observation.action_root, 32) ||
            !zcl_hex_decode_lower(action->input_root_sha3,
                                  observation.action_input_root, 32) ||
            !zcl_hex_decode_lower(job->toolchain_sha3,
                                  observation.toolchain_root, 32) ||
            !zcl_hex_decode_lower(action->flags_sha3,
                                  observation.flags_root, 32) ||
            !zcl_hex_decode_lower(action->environment_sha3,
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
            action->declared_outputs, observation.declared_writes_root);
        vcs_build_execution_observed_write_set_root(
            action->declared_outputs, observation.output_bytes_root,
            observation.observed_writes_root);
        struct zcl_result observed = build_fabric_worker_store_observation(
            workspace, &observation, evidence_root);
        if (!observed.ok)
            return bfw_fail(ndb, action_id, lease_id, observed.message);
        /* Publish the executor-key record so a later eligible duplicate
         * request can attach to this physical result instead of recompiling.
         * Best-effort: the observation, output, and receipt above stand on
         * their own; a publish failure logs and degrades to a future MISS. */
        bfw_attach_publish_checked(
            attach_identity_stable, workspace, vcs_package_store_global(),
            job, action,
            observed_input_bytes_root, checked_identity);
    return ZCL_OK;
}

static struct zcl_result bfw_receipt_sign_and_quarantine(
    struct node_db *ndb, const char *workspace, const char *action_id,
    const char *lease_id, const struct db_build_action *action,
    const struct vcs_zcode_task_v1 *zcode_task,
    const struct vcs_zcode_candidate_v1 *zcode_candidate,
    const struct vcs_zcode_proof_policy_v1 *zcode_policy,
    const uint8_t output_root[32], const uint8_t evidence_root[32],
    bool package_action, bool test_action, bool fuzz_action, bool compile_action,
    bool zcode_context, uint8_t work_kind, uint8_t work_status,
    int work_exit_status, int64_t work_started, int64_t work_finished,
    uint32_t fuzz_cpu_seconds, uint64_t fuzz_memory_bytes, uint64_t fuzz_output_bytes,
    const uint8_t signer_secret[32], const uint8_t signer_pubkey[32],
    struct db_build_receipt *out, int64_t *receipt_sign_us, int64_t *projection_us)
{
    int64_t receipt_started_us = platform_time_monotonic_us();
    struct db_build_receipt receipt = {0};
    (void)snprintf(receipt.action_id, sizeof(receipt.action_id), "%s",
                   action->action_id);
    (void)snprintf(receipt.job_id, sizeof(receipt.job_id), "%s", action->job_id);
    (void)snprintf(receipt.worker_id, sizeof(receipt.worker_id), "%s",
                   action->worker_id);
    (void)snprintf(receipt.lease_id, sizeof(receipt.lease_id), "%s", lease_id);
    (void)snprintf(receipt.action_sha3, sizeof(receipt.action_sha3), "%s",
                   action->action_id);
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
                       zcode_policy->deterministic_fuzz_seeds,
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
            workspace, action, zcode_task, zcode_candidate, output_root,
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
    *receipt_sign_us =
        platform_time_monotonic_us() - receipt_started_us;
    int64_t projection_started_us = platform_time_monotonic_us();
    struct zcl_result accepted = build_fabric_receipt_quarantine(
        ndb, &receipt, receipt.created_at);
    if (!accepted.ok) return accepted;
    *projection_us =
        platform_time_monotonic_us() - projection_started_us;
    *out = receipt;
    return ZCL_OK;
}

struct bfw_initial_state {
    struct db_build_action action;
    struct db_build_job job;
    struct db_build_worker worker;
    struct vcs_zcode_task_v1 task;
    struct vcs_zcode_candidate_v1 candidate;
    struct vcs_zcode_proof_policy_v1 policy;
    bool zcode_context, package_action;
    uint8_t work_kind;
    int64_t action_lookup_us;
};

static struct zcl_result bfw_request_validate(
    struct node_db *ndb, const char *workspace, const char *datadir,
    const char *action_id, const char *lease_id, const uint8_t *secret,
    const uint8_t *pubkey, const struct db_build_receipt *receipt)
{
    if (!ndb || !ndb->open || !workspace || !datadir || !action_id ||
        !lease_id || !secret || !pubkey || !receipt)
        return ZCL_ERR(-1, "worker execution requires lease, workspace, and key");
    return ZCL_OK;
}

static struct zcl_result bfw_initial_lookup(
    struct node_db *ndb, const char *action_id, const char *lease_id,
    int64_t started, struct bfw_initial_state *s)
{
    if (!db_build_action_find(ndb, action_id, &s->action) ||
        !db_build_job_find(ndb, s->action.job_id, &s->job) ||
        !db_build_worker_find(ndb, s->action.worker_id, &s->worker) ||
        strcmp(s->action.lease_id, lease_id) != 0)
        return ZCL_ERR(-1, "claimed worker action is missing or stale");
    s->action_lookup_us = platform_time_monotonic_us() - started;
    return ZCL_OK;
}

static struct zcl_result bfw_initial_authorize(
    struct node_db *ndb, const char *workspace, const char *action_id,
    const char *lease_id, const uint8_t signer_pubkey[32],
    struct bfw_initial_state *s)
{
    char signer_hex[65];
    zcl_hex_encode(signer_pubkey, 32, signer_hex);
    if (strcmp(signer_hex, s->worker.signer_pubkey) != 0)
        return bfw_fail(ndb, action_id, lease_id, "worker-signer-mismatch");
    s->work_kind = vcs_build_action_v1_work_kind(s->action.kind);
    s->package_action = strcmp(s->action.kind, VCS_BUILD_ACTION_KIND_PACKAGE_V1) == 0;
    if ((s->work_kind != VCS_ZCODE_WORK_BUILD &&
         s->work_kind != VCS_ZCODE_WORK_TEST &&
         s->work_kind != VCS_ZCODE_WORK_FUZZ) ||
        !bfw_capability_has(s->worker.capabilities, s->action.kind))
        return bfw_fail(ndb, action_id, lease_id, "fixed-action-executor-unavailable");
    struct zcl_result descriptor = bfw_validate_descriptor(
        ndb, action_id, lease_id, &s->action, &s->job);
    if (!descriptor.ok) return descriptor;
    struct zcl_result context = bfw_load_zcode_context(
        workspace, &s->job, &s->action, (int64_t)platform_time_wall_unix(),
        &s->task, &s->candidate, &s->policy, &s->zcode_context);
    if (!context.ok) return bfw_fail(ndb, action_id, lease_id, context.message);
    if (s->work_kind == VCS_ZCODE_WORK_FUZZ && !s->zcode_context)
        return bfw_fail(ndb, action_id, lease_id, "fuzz-action-requires-zcode-policy");
    if (s->package_action && !s->zcode_context)
        return bfw_fail(ndb, action_id, lease_id, "package-action-requires-zcode-context");
    return ZCL_OK;
}

struct bfw_prepared_input {
    struct bfw_input_state input;
    uint64_t input_bytes;
    uint8_t observed_root[32];
    char observed_hex[65];
    int64_t reconstruction_us, work_started, sandbox_prepare_us;
    struct bfw_paths paths;
    struct build_fabric_package_execution package_execution;
};

static struct zcl_result bfw_prepare_execution(
    struct node_db *ndb, const char *workspace, const char *datadir,
    const char *action_id, const char *lease_id,
    const struct db_build_action *action, const struct db_build_job *job,
    const struct vcs_zcode_task_v1 *task,
    const struct vcs_zcode_candidate_v1 *candidate,
    bool zcode_context, bool package_action, uint8_t work_kind,
    int64_t worker_started_us, int64_t action_lookup_us,
    struct bfw_prepared_input *p)
{
    struct zcl_result input_result = bfw_load_input(
        ndb, workspace, action_id, lease_id, action, task, candidate,
        zcode_context, package_action, work_kind, &p->input);
    if (!input_result.ok) return input_result;
    p->input_bytes = package_action ? VCS_ZCODE_PACKAGE_ACTION_INPUT_WIRE_BYTES : p->input.len;
    if (!package_action) sha3_256(p->input.bytes, p->input.len, p->observed_root);
    if (!package_action) zcl_hex_encode(p->observed_root, 32, p->observed_hex);
    p->reconstruction_us = platform_time_monotonic_us() - worker_started_us - action_lookup_us;
    p->work_started = (int64_t)platform_time_wall_unix();
    struct zcl_result start = build_fabric_start(ndb, action_id, lease_id, p->work_started);
    if (!start.ok) { free(p->input.bytes); return start; }
    int64_t materialize_started_us = platform_time_monotonic_us();
    struct zcl_result materialized = bfw_materialize(
        ndb, workspace, datadir, action_id, lease_id, action, job, task, candidate,
        package_action, work_kind == VCS_ZCODE_WORK_TEST,
        work_kind == VCS_ZCODE_WORK_FUZZ, p->input.bytes, p->input.len,
        &p->paths, &p->package_execution);
    if (!materialized.ok) return materialized;
    p->sandbox_prepare_us = platform_time_monotonic_us() - materialize_started_us;
    return ZCL_OK;
}

static void bfw_clear_outputs(struct build_fabric_worker_feedback *feedback,
                              struct build_fabric_host_accounting *accounting)
{
    if (feedback) memset(feedback, 0, sizeof(*feedback));
    if (accounting) memset(accounting, 0, sizeof(*accounting));
}

static struct zcl_result bfw_maybe_observe(
    bool compile_action, struct node_db *ndb, const char *workspace,
    const char *action_id, const char *lease_id,
    const struct db_build_action *action, const struct db_build_job *job,
    const char *capture, const char *observed_hex, const uint8_t observed_root[32],
    const uint8_t output_root[32], const uint8_t output_bytes_root[32],
    int exit_status, bool identity_stable,
    const struct build_fabric_executor_identity *identity, uint8_t evidence_root[32])
{
    if (!compile_action) return ZCL_OK;
    return bfw_store_observation_and_attach(ndb, workspace, action_id, lease_id,
        action, job, capture, observed_hex, observed_root, output_root,
        output_bytes_root, exit_status, identity_stable, identity, evidence_root);
}

// Private phases run only here, in the original authority and cleanup order.
struct zcl_result build_fabric_worker_execute(
    struct node_db *ndb, const char *workspace, const char *datadir,
    const char *action_id,
    const char *lease_id, const uint8_t signer_secret[32],
    const uint8_t signer_pubkey[32], struct db_build_receipt *out_receipt,
    struct build_fabric_worker_feedback *out_feedback,
    struct build_fabric_host_accounting *out_accounting)
{
    bfw_clear_outputs(out_feedback, out_accounting);
    uint64_t thread_launches_before = zcl_spawn_thread_launch_count();
    struct zcl_result request = bfw_request_validate(
        ndb, workspace, datadir, action_id, lease_id, signer_secret,
        signer_pubkey, out_receipt);
    if (!request.ok) return request;
    int64_t worker_started_us = platform_time_monotonic_us();
    char workspace_resolved[BFW_PATH_MAX];
    if (!realpath(workspace, workspace_resolved))
        return ZCL_ERR(-1, "worker workspace cannot be resolved: %s",
                       strerror(errno));
    workspace = workspace_resolved;
    struct bfw_initial_state initial = {0};
    struct zcl_result lookup = bfw_initial_lookup(
        ndb, action_id, lease_id, worker_started_us, &initial);
    if (!lookup.ok) return lookup;
    struct zcl_result authorized = bfw_initial_authorize(
        ndb, workspace, action_id, lease_id, signer_pubkey, &initial);
    if (!authorized.ok) return authorized;
    struct db_build_action action = initial.action;
    struct db_build_job job = initial.job;
    struct vcs_zcode_task_v1 zcode_task = initial.task;
    struct vcs_zcode_candidate_v1 zcode_candidate = initial.candidate;
    struct vcs_zcode_proof_policy_v1 zcode_policy = initial.policy;
    bool zcode_context = initial.zcode_context;
    bool package_action = initial.package_action;
    uint8_t work_kind = initial.work_kind;
    int64_t action_lookup_us = initial.action_lookup_us;
    struct bfw_prepared_input prepared = {0};
    struct zcl_result preparation = bfw_prepare_execution(
        ndb, workspace, datadir, action_id, lease_id, &action, &job,
        &zcode_task, &zcode_candidate, zcode_context, package_action,
        work_kind, worker_started_us, action_lookup_us, &prepared);
    if (!preparation.ok) return preparation;
    struct bfw_input_state *input_state = &prepared.input;
    uint64_t input_bytes = prepared.input_bytes;
    uint8_t *observed_input_bytes_root = prepared.observed_root;
    const char *observed_input_hex = prepared.observed_hex;
    int64_t input_reconstruction_us = prepared.reconstruction_us;
    int64_t work_started = prepared.work_started;
    int64_t sandbox_prepare_us = prepared.sandbox_prepare_us;
    struct bfw_paths paths = prepared.paths;
    struct build_fabric_package_execution *package_execution = &prepared.package_execution;
    bool test_action = work_kind == VCS_ZCODE_WORK_TEST;
    bool fuzz_action = work_kind == VCS_ZCODE_WORK_FUZZ;
    struct bfw_argv_state args;
    bfw_prepare_argv(&args, &paths, &zcode_task, &zcode_policy, package_execution,
                     package_action, test_action, fuzz_action);
    const char *const *spawn_argv = args.selected;
    uint32_t fuzz_cpu_seconds = args.fuzz_cpu_seconds;
    uint64_t fuzz_memory_bytes = args.fuzz_memory_bytes;
    uint64_t fuzz_output_bytes = args.fuzz_output_bytes;
    struct bfw_spawn_state spawn;
    struct zcl_result spawned = bfw_spawn_and_classify(
        ndb, workspace, action_id, lease_id, &action, &paths, work_kind,
        package_action, test_action, fuzz_action, spawn_argv, args.timeout,
        thread_launches_before, out_feedback, out_accounting, &spawn);
    if (!spawned.ok) return spawned;
    const char *capture = spawn.capture;
    struct zcl_spawn_measure measure = spawn.measure;
    struct build_fabric_executor_identity checked_identity = spawn.checked_identity;
    bool attach_identity_stable = spawn.attach_identity_stable;
    int64_t action_execution_us = spawn.action_execution_us;
    int64_t child_cpu_us = spawn.child_cpu_us;
    struct bfw_output_state output_state;
    struct zcl_result stored = bfw_verify_and_store_output(
        ndb, workspace, action_id, lease_id, &job, &action, &paths,
        package_action, fuzz_action, test_action, zcode_context,
        &zcode_task, &zcode_candidate, &zcode_policy, package_execution,
        &output_state);
    if (!stored.ok) return stored;
    size_t output_len = output_state.len;
    uint8_t work_status = output_state.work_status;
    int work_exit_status = output_state.work_exit_status;
    int64_t output_verify_us = output_state.verify_us;
    int64_t output_cas_started_us = output_state.cas_started_us;
    uint8_t *output_root = output_state.root;
    uint8_t *output_bytes_root = output_state.bytes_root;
    uint8_t evidence_root[32];
    memcpy(evidence_root, output_root, sizeof(evidence_root));
    bool compile_action = strcmp(
        action.kind, VCS_BUILD_ACTION_KIND_V1) == 0;
    struct zcl_result observed = bfw_maybe_observe(
        compile_action, ndb, workspace, action_id, lease_id, &action, &job,
        capture, observed_input_hex, observed_input_bytes_root, output_root,
        output_bytes_root, work_exit_status, attach_identity_stable,
        &checked_identity, evidence_root);
    if (!observed.ok) return observed;
    int64_t output_cas_us =
        platform_time_monotonic_us() - output_cas_started_us;
    int64_t work_finished = (int64_t)platform_time_wall_unix();
    struct zcl_result revalidated = bfw_revalidate(
        ndb, workspace, action_id, lease_id, &job, &action, work_kind,
        package_action, zcode_context, work_finished, input_state,
        &zcode_task, &zcode_candidate, &zcode_policy);
    if (!revalidated.ok) return revalidated;
    int64_t revalidation_us =
        platform_time_monotonic_us() - output_cas_started_us - output_cas_us;
    struct db_build_receipt receipt;
    int64_t receipt_sign_us = 0, projection_us = 0;
    struct zcl_result accepted = bfw_receipt_sign_and_quarantine(
        ndb, workspace, action_id, lease_id, &action, &zcode_task,
        &zcode_candidate, &zcode_policy, output_root, evidence_root,
        package_action, test_action, fuzz_action, compile_action, zcode_context,
        work_kind, work_status, work_exit_status, work_started, work_finished,
        fuzz_cpu_seconds, fuzz_memory_bytes, fuzz_output_bytes, signer_secret,
        signer_pubkey, &receipt, &receipt_sign_us, &projection_us);
    if (!accepted.ok) return accepted;
    bfw_accounting_record(out_accounting, &measure, capture,
                          thread_launches_before);
    uint64_t host_processes =
        zcl_spawn_thread_launch_count() - thread_launches_before;
    LOG_INFO("zcode.proof_perf",
             "schema=zcl.async_proof_perf.v1 action=%s stage=worker_execute "
             "at_unix_us=%lld "
             "lookup_us=%lld input_reconstruction_us=%lld "
             "sandbox_prepare_us=%lld execution_us=%lld child_cpu_us=%lld "
             "output_verify_us=%lld output_cas_us=%lld revalidation_us=%lld "
             "receipt_sign_us=%lld projection_us=%lld input_bytes=%llu "
             "output_bytes=%zu host_processes=%llu host_executor_launches=%u "
             "host_wall_us=%lld host_io_observed=%d host_read_bytes=%llu "
             "host_write_bytes=%llu "
             "child_reported_processes_unverified=%llu "
             "child_reported_compiler_processes_unverified=%llu "
             "child_reported_test_processes_unverified=%llu "
             "cache_hit=%d total_us=%lld",
             action.action_id, (long long)platform_time_realtime_us(),
             (long long)action_lookup_us,
             (long long)input_reconstruction_us,
             (long long)sandbox_prepare_us, (long long)action_execution_us,
             (long long)(child_cpu_us < 0 ? 0 : child_cpu_us),
             (long long)output_verify_us, (long long)output_cas_us,
             (long long)revalidation_us, (long long)receipt_sign_us,
             (long long)projection_us, (unsigned long long)input_bytes,
             output_len, (unsigned long long)host_processes,
             measure.launched ? 1u : 0u, (long long)measure.wall_us,
             measure.io_observed ? 1 : 0,
             (unsigned long long)measure.read_bytes,
             (unsigned long long)measure.write_bytes,
             (unsigned long long)bfw_capture_metric(capture, "processes"),
             (unsigned long long)bfw_capture_metric(
                 capture, "compiler_processes"),
             (unsigned long long)bfw_capture_metric(
                 capture, "test_processes"),
             strcmp(action.state, "CACHE_HIT") == 0 ? 1 : 0,
             (long long)(platform_time_monotonic_us() - worker_started_us));
    *out_receipt = receipt;
    return ZCL_OK;
}

#endif
