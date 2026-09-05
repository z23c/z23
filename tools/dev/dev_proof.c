/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Admit exact commit/base pairs from the resident development proof. */

#define _POSIX_C_SOURCE 200809L

#include "dev_proof.h"
#include "dev_proof_budget.h"
#include "devloop.h"
#include "test_group_catalog.h"

#include "base/hex.h"
#include "base/safe_alloc.h"
#include "base/serialize_le.h"
#include "json/json.h"
#include "platform/directory_compat.h"
#include "platform/logical_cpu.h"
#include "platform/private_directory.h"
#include "platform/ram_scratch.h"
#include "platform/time_compat.h"
#include "base/safe_alloc.h"
#include "sha3/sha3.h"
#include "vcs/build_action.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#if !defined(_WIN32)
#include <stdarg.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define PROOF_MAX_JOBS 16u
/* v2 of these three roots: v1 was three domain tags over one file that baked
 * the absolute checkout path, so no two boxes ever agreed. A v1 root can
 * never collide with a v2 root, and a receipt carrying v1 roots is refused
 * by policy version rather than compared (dev_proof_receipt.c). */
#define PROOF_ENV_DOMAIN "zcl.dev_proof_environment.v2"
#define PROOF_FLAGS_DOMAIN "zcl.dev_proof_flags.v2"
#define PROOF_BUILD_GRAPH_DOMAIN "zcl.dev_proof_build_graph.v2"
/* The directory the build tells the compiler to record instead of this
 * checkout: Makefile ZCL_REPRO_ROOT, fed to -ffile-prefix-map. */
#define PROOF_PLAN_VIRTUAL_ROOT "/zclassic23"
#define PROOF_PLAN_MAX_BYTES 65536u

struct proof_paths {
    char root[PATH_MAX];
    char cache[PATH_MAX];
    char state[PATH_MAX];
    char receipts[PATH_MAX];
    char children[PATH_MAX];
    char logs[PATH_MAX];
    char requests[PATH_MAX];
    char attempts[PATH_MAX];
    char leases[PATH_MAX];
    char key[132];
    char receipt[PATH_MAX];
    char lock[PATH_MAX];
    char request[PATH_MAX];
    char lease[PATH_MAX];
    char queue_lock[PATH_MAX];
    char failure[PATH_MAX];
    char changed[PATH_MAX];
    char bundle_log[PATH_MAX];
    char helper_log[PATH_MAX];
    char attempt[PATH_MAX];
    char attempt_token[192];
    char phases[PATH_MAX];
    int64_t attempt_worker;
    char warmstart[PATH_MAX];
};

/* Warm-start outcome for one generation, carried from generation_prepare()
 * to the proof worker so the receipt sidecar can say what the build reused.
 * Cold is always correct; every field here is advisory. `cold_reason` is a
 * short typed string (never prose), set only on the cold path, so the one
 * status line a developer reads never has to guess why. */
struct proof_warmstart {
    char donor[33];
    char donor_local[65];
    uint64_t files_linked;
    uint64_t bytes_linked;
    bool armed;
    char cold_reason[24];
};

static void proof_why(char *why, size_t why_len, const char *message)
{
    if (why && why_len)
        (void)snprintf(why, why_len, "%s", message ? message : "unknown");
}

static bool proof_root_nonzero(const uint8_t root[32])
{
    uint8_t any = 0;
    if (!root) return false;
    for (size_t i = 0; i < 32; i++) any |= root[i];
    return any != 0;
}

static const char *proof_dimension_operation(
    enum zcl_dev_proof_dimension_id dimension)
{
    static const char *const operations[ZCL_DEV_PROOF_DIMENSIONS] = {
        "capability-inventory-generated",
        "build-only",
        "lint-fast",
        "test-exact-cache-proof-contracts",
    };
    return dimension >= ZCL_DEV_PROOF_GENERATED &&
        dimension <= ZCL_DEV_PROOF_TEST ? operations[dimension] : NULL;
}

static void proof_action_hash_text(struct sha3_256_ctx *sha,
                                   const char *text)
{
    uint8_t len_wire[4];
    size_t len = strlen(text);
    zcl_write_u32_le(len_wire, (uint32_t)len);
    sha3_256_write(sha, len_wire, sizeof(len_wire));
    sha3_256_write(sha, (const uint8_t *)text, len);
}

bool zcl_dev_proof_child_action_v1(
    const struct zcl_dev_proof_child_action_inputs_v1 *inputs,
    enum zcl_dev_proof_dimension_id dimension,
    struct vcs_build_action_v1 *action, uint8_t action_root[32])
{
    const char *operation = proof_dimension_operation(dimension);
    const char *selector = inputs ? inputs->selector : NULL;
    size_t selector_len = selector ? strlen(selector) : 0;
    if (!inputs || !action || !action_root || !operation ||
        !inputs->source_sha256_hex || !inputs->source_cas_sha3_hex ||
        !selector || inputs->selected == 0 || selector_len > UINT32_MAX ||
        (dimension == ZCL_DEV_PROOF_TEST) != (selector_len != 0) ||
        !proof_root_nonzero(inputs->toolchain_capsule_root) ||
        !proof_root_nonzero(inputs->flags_root) ||
        !proof_root_nonzero(inputs->environment_root) ||
        !proof_root_nonzero(inputs->build_graph_root))
        return false;
    memset(action, 0, sizeof(*action));
    if (!zcl_hex_decode_lower(inputs->source_sha256_hex,
                              action->source_sha256, 32) ||
        !zcl_hex_decode_lower(inputs->source_cas_sha3_hex,
                              action->source_cas_sha3, 32) ||
        !proof_root_nonzero(action->source_sha256) ||
        !proof_root_nonzero(action->source_cas_sha3))
        return false;
    struct sha3_256_ctx input;
    uint8_t number[4];
    static const uint8_t domain[] =
        "zcl.dev_proof_child_action_input.v1";
    sha3_256_init(&input);
    sha3_256_write(&input, domain, sizeof(domain));
    zcl_write_u32_le(number, (uint32_t)dimension);
    sha3_256_write(&input, number, sizeof(number));
    sha3_256_write(&input, inputs->build_graph_root, 32);
    zcl_write_u32_le(number, inputs->selected);
    sha3_256_write(&input, number, sizeof(number));
    proof_action_hash_text(&input, operation);
    proof_action_hash_text(&input, selector);
    sha3_256_finalize(&input, action->input_root_sha3);
    memcpy(action->toolchain_capsule_sha3,
           inputs->toolchain_capsule_root, 32);
    memcpy(action->flags_sha3, inputs->flags_root, 32);
    memcpy(action->environment_sha3, inputs->environment_root, 32);
    (void)snprintf(action->target, sizeof(action->target), "%s",
                   VCS_BUILD_TARGET_V1);
    (void)snprintf(action->profile, sizeof(action->profile),
                   "resident-proof-child-v1");
    const char *workdir = NULL, *output = NULL, *resource = NULL;
    if (!vcs_build_action_v1_descriptors(
            VCS_BUILD_ACTION_KIND_RESIDENT_PROOF_CHILD_V1,
            &workdir, &output, &resource))
        return false;
    (void)snprintf(action->virtual_workdir,
                   sizeof(action->virtual_workdir), "%s", workdir);
    (void)snprintf(action->declared_outputs,
                   sizeof(action->declared_outputs), "%s", output);
    (void)snprintf(action->resource_policy,
                   sizeof(action->resource_policy), "%s", resource);
    action->sequence = (uint64_t)dimension + 1u;
    return vcs_build_action_v1_root_for_kind(
        VCS_BUILD_ACTION_KIND_RESIDENT_PROOF_CHILD_V1,
        action, action_root);
}

/* Same contract as proof_why, for a refusal that can name the exact thing it
 * refused over. A bare code makes the reader open this file and hand-check a
 * twenty-entry list; the missing path plus the command that produces it is the
 * whole diagnosis. */
#if !defined(_WIN32)
static void proof_whyf(char *why, size_t why_len, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));
static void proof_whyf(char *why, size_t why_len, const char *fmt, ...)
{
    if (!why || !why_len)
        return;
    va_list ap;
    va_start(ap, fmt);
    (void)vsnprintf(why, why_len, fmt, ap);
    va_end(ap);
}
#endif

static size_t cycle_key_count(const struct json_value *cycle, const char *key,
                              const struct json_value **value)
{
    size_t count = 0;
    if (value) *value = NULL;
    if (!cycle || cycle->type != JSON_OBJ || !key) return 0;
    for (size_t i = 0; i < cycle->num_children; i++) {
        if (!cycle->keys[i] || strcmp(cycle->keys[i], key) != 0) continue;
        if (count == 0 && value) *value = &cycle->children[i];
        count++;
    }
    return count;
}

static bool cycle_field_text_once(const struct json_value *cycle,
                                  const char *key, const char *expected)
{
    const struct json_value *value = NULL;
    return expected && cycle_key_count(cycle, key, &value) == 1 &&
           value->type == JSON_STR &&
           strcmp(json_get_str(value), expected) == 0;
}

static bool cycle_field_true_once(const struct json_value *cycle,
                                  const char *key)
{
    const struct json_value *value = NULL;
    return cycle_key_count(cycle, key, &value) == 1 &&
           value->type == JSON_BOOL && json_get_bool(value);
}

static bool cycle_root_nonzero(const uint8_t root[ZCL_DEV_PROOF_ROOT_BYTES])
{
    uint8_t any = 0;
    if (!root) return false;
    for (size_t i = 0; i < ZCL_DEV_PROOF_ROOT_BYTES; i++) any |= root[i];
    return any != 0;
}

static const char *cycle_dimension_root_key(size_t id)
{
    static const char *const keys[ZCL_DEV_PROOF_DIMENSIONS] = {
        "proof_generated_root_sha3",
        "proof_compile_root_sha3",
        "proof_lint_root_sha3",
        "proof_test_root_sha3",
    };
    return id < ZCL_DEV_PROOF_DIMENSIONS ? keys[id] : NULL;
}

static bool cycle_dimension_roots_exact(
    const struct json_value *cycle,
    const struct zcl_dev_proof_dimension
        dimensions[ZCL_DEV_PROOF_DIMENSIONS])
{
    if (!dimensions) return false;
    for (size_t i = 0; i < ZCL_DEV_PROOF_DIMENSIONS; i++) {
        const char *key = cycle_dimension_root_key(i);
        size_t count = cycle_key_count(cycle, key, NULL);
        if (dimensions[i].selected == 0) {
            if (count != 0 || cycle_root_nonzero(dimensions[i].receipt_root))
                return false;
            continue;
        }
        if (count != 1 ||
            !cycle_root_nonzero(dimensions[i].receipt_root))
            return false;
        char expected[ZCL_DEV_PROOF_ROOT_BYTES * 2u + 1u];
        zcl_hex_encode(dimensions[i].receipt_root,
                       ZCL_DEV_PROOF_ROOT_BYTES, expected);
        if (!cycle_field_text_once(cycle, key, expected)) return false;
        for (size_t prior = 0; prior < i; prior++) {
            if (dimensions[prior].selected != 0 &&
                memcmp(dimensions[prior].receipt_root,
                       dimensions[i].receipt_root,
                       ZCL_DEV_PROOF_ROOT_BYTES) == 0)
                return false;
        }
    }
    return true;
}

bool zcl_dev_proof_cycle_reuse_admissible(
    const char *body, size_t body_len, const char *source_cas,
    const char *proof_inputs_sha3,
    const struct zcl_dev_proof_dimension
        dimensions[ZCL_DEV_PROOF_DIMENSIONS])
{
    uint8_t root[32];
    struct json_value cycle = {0};
    if (!body || body_len == 0 || !source_cas || !proof_inputs_sha3 ||
        !dimensions ||
        !zcl_hex_decode_lower(source_cas, root, sizeof(root)) ||
        !zcl_hex_decode_lower(proof_inputs_sha3, root, sizeof(root)) ||
        !json_read(&cycle, body, body_len) || cycle.type != JSON_OBJ) {
        json_free(&cycle);
        return false;
    }
    bool admitted =
        cycle_field_true_once(&cycle, "proof_complete") &&
        cycle_field_text_once(&cycle, "schema", "zcl.dev_cycle.v1") &&
        cycle_field_text_once(&cycle, "status", "passed") &&
        cycle_field_text_once(&cycle, "phase", "verify") &&
        cycle_field_text_once(&cycle, "proof_scope",
                              "source_wide_compile_tests_lint_fast") &&
        cycle_field_text_once(&cycle, "source_cas_sha3", source_cas) &&
        cycle_field_text_once(&cycle, "proof_inputs_sha3",
                              proof_inputs_sha3) &&
        cycle_dimension_roots_exact(&cycle, dimensions);
    json_free(&cycle);
    return admitted;
}

#if defined(_WIN32)

/* The proof worker currently depends on fork/setsid, descriptor inheritance,
 * POSIX hard-link/symlink inspection, and process-group termination.  Native
 * Windows must not approximate those authority boundaries with CRT path
 * calls or a detached shell.  Keep the typed command available, but refuse
 * before creating proof state until it is ported onto retained directories
 * and platform_process Job Objects. */
static void proof_windows_unavailable(struct zcl_dev_proof_status *out)
{
    if (out) {
        memset(out, 0, sizeof(*out));
        out->state = ZCL_DEV_PROOF_STATE_INVALID;
        (void)snprintf(out->detail, sizeof(out->detail), "%s",
                       "windows_native_proof_worker_unavailable");
    }
}

static bool proof_resolve_pair_platform(const char *repo_root,
                                        const char *requested_local,
                                        const char *requested_base,
                                        char local_commit[65],
                                        char remote_base[65],
                                        char *why, size_t why_len)
{
    (void)repo_root;
    (void)requested_local;
    (void)requested_base;
    if (local_commit) local_commit[0] = 0;
    if (remote_base) remote_base[0] = 0;
    proof_why(why, why_len, "windows_native_proof_worker_unavailable");
    return false;
}

static bool proof_status_read_platform(const char *repo_root,
                                       const char *local_commit,
                                       const char *remote_base,
                                       struct zcl_dev_proof_status *out)
{
    (void)repo_root;
    (void)local_commit;
    (void)remote_base;
    proof_windows_unavailable(out);
    return true;
}

static bool proof_ensure_platform(const char *repo_root,
                                  const char *local_commit,
                                  const char *remote_base,
                                  struct zcl_dev_proof_status *out)
{
    (void)repo_root;
    (void)local_commit;
    (void)remote_base;
    proof_windows_unavailable(out);
    return false;
}

static bool proof_queue_has_pending_platform(const char *repo_root)
{
    (void)repo_root;
    return false;
}

static int proof_queue_run_next_platform(const char *repo_root,
                                         char *why, size_t why_len)
{
    (void)repo_root;
    proof_why(why, why_len, "windows_native_proof_worker_unavailable");
    return -1;
}

static bool proof_wait_platform(const char *repo_root,
                                const char *local_commit,
                                const char *remote_base,
                                int timeout_ms,
                                struct zcl_dev_proof_status *out)
{
    (void)repo_root;
    (void)local_commit;
    (void)remote_base;
    (void)timeout_ms;
    proof_windows_unavailable(out);
    return false;
}

#else

static bool proof_oid_text(const char *value)
{
    uint8_t decoded[ZCL_DEV_PROOF_OID_MAX], len = 0;
    return zcl_dev_proof_oid_decode(value, decoded, &len);
}

static bool proof_paths_fill(const char *repo_root, const char *local,
                             const char *base, struct proof_paths *out)
{
    if (!repo_root || !local || !base || !out || !proof_oid_text(local) ||
        !proof_oid_text(base) ||
        !platform_directory_canonical_real(repo_root, out->root,
                                           sizeof(out->root)))
        return false;
    if (snprintf(out->cache, sizeof(out->cache), "%s/.cache", out->root) >=
            (int)sizeof(out->cache) ||
        snprintf(out->state, sizeof(out->state), "%s/zcl-dev-proof",
                 out->cache) >=
            (int)sizeof(out->state) ||
        snprintf(out->receipts, sizeof(out->receipts), "%s/receipts",
                 out->state) >= (int)sizeof(out->receipts) ||
        snprintf(out->children, sizeof(out->children), "%s/children",
                 out->state) >= (int)sizeof(out->children) ||
        snprintf(out->logs, sizeof(out->logs), "%s/logs", out->state) >=
            (int)sizeof(out->logs) ||
        snprintf(out->requests, sizeof(out->requests), "%s/requests",
                 out->state) >= (int)sizeof(out->requests) ||
        snprintf(out->attempts, sizeof(out->attempts), "%s/attempts",
                 out->state) >= (int)sizeof(out->attempts) ||
        snprintf(out->leases, sizeof(out->leases), "%s/leases",
                 out->state) >= (int)sizeof(out->leases) ||
        snprintf(out->key, sizeof(out->key), "%s-%s", local, base) >=
            (int)sizeof(out->key) ||
        snprintf(out->receipt, sizeof(out->receipt), "%s/%s.receipt",
                 out->receipts, out->key) >= (int)sizeof(out->receipt) ||
        snprintf(out->lock, sizeof(out->lock), "%s/%s.running", out->state,
                 out->key) >= (int)sizeof(out->lock) ||
        snprintf(out->request, sizeof(out->request), "%s/%s.request",
                 out->requests, out->key) >= (int)sizeof(out->request) ||
        snprintf(out->lease, sizeof(out->lease), "%s/%s.lease",
                 out->leases, out->key) >= (int)sizeof(out->lease) ||
        snprintf(out->queue_lock, sizeof(out->queue_lock), "%s/queue.lock",
                 out->state) >= (int)sizeof(out->queue_lock) ||
        snprintf(out->failure, sizeof(out->failure), "%s/%s.failed",
                 out->state, out->key) >= (int)sizeof(out->failure) ||
        snprintf(out->changed, sizeof(out->changed), "%s/%s.files",
                 out->state, out->key) >= (int)sizeof(out->changed) ||
        snprintf(out->bundle_log, sizeof(out->bundle_log),
                 "%s/%s.bundle.log", out->logs, out->key) >=
            (int)sizeof(out->bundle_log) ||
        snprintf(out->helper_log, sizeof(out->helper_log), "%s/%s.helper.log",
                 out->logs, out->key) >= (int)sizeof(out->helper_log) ||
        snprintf(out->phases, sizeof(out->phases), "%s/%s.phases.txt",
                 out->state, out->key) >= (int)sizeof(out->phases) ||
        snprintf(out->warmstart, sizeof(out->warmstart), "%s/%s.warmstart",
                 out->state, out->key) >= (int)sizeof(out->warmstart))
        return false;
    return true;
}

static bool proof_state_prepare(const struct proof_paths *paths)
{
    return paths && platform_private_directory_ensure(paths->cache) &&
           platform_private_directory_ensure(paths->state) &&
           platform_private_directory_ensure(paths->receipts) &&
           platform_private_directory_ensure(paths->children) &&
           platform_private_directory_ensure(paths->logs) &&
           platform_private_directory_ensure(paths->requests) &&
           platform_private_directory_ensure(paths->attempts) &&
           platform_private_directory_ensure(paths->leases);
}

static bool process_ok(const struct zcl_devloop_process_result *result)
{
    return result && !result->timed_out && !result->output_truncated &&
           result->term_signal == 0 && result->exit_code == 0;
}

/* Preserve a process result for the small number of Git reads whose failure
 * becomes proof evidence.  The ordinary wrappers below keep their compact
 * Boolean interfaces for the remaining Git queries. */
static bool git_capture_observed(const char *root, const char *const argv[],
                                 int timeout_ms, char *out, size_t out_size,
                                 struct zcl_devloop_process_result *observed)
{
    struct zcl_devloop_process_result result = {0};
    bool ran = root && argv && out && out_size > 0 &&
               zcl_devloop_process_run(root, argv, timeout_ms, &result);
    if (observed)
        *observed = result;
    if (!ran || !process_ok(&result) || result.output_len >= out_size)
        return false;
    size_t len = result.output_len;
    while (len > 0 && (result.output[len - 1] == '\n' ||
                       result.output[len - 1] == '\r'))
        len--;
    memcpy(out, result.output, len);
    out[len] = 0;
    return true;
}

static bool git_capture_within(const char *root, const char *const argv[],
                               int timeout_ms, char *out, size_t out_size)
{
    return git_capture_observed(root, argv, timeout_ms, out, out_size, NULL);
}

/* Every git query in this file answers within seconds or is not worth
 * waiting on. Only the generation reaper's recursive delete needs a budget
 * of its own, so it names one and everything else keeps the shared bound. */
static bool git_capture(const char *root, const char *const argv[],
                        char *out, size_t out_size)
{
    return git_capture_within(root, argv, 30000, out, out_size);
}

static void git_capture_why(const char *operation,
                            const struct zcl_devloop_process_result *result,
                            size_t output_capacity, char *why,
                            size_t why_len)
{
    if (!operation || !result || !why || why_len == 0)
        return;
    if (result->timed_out) {
        proof_whyf(why, why_len, "%s_timeout", operation);
    } else if (result->cancelled) {
        proof_whyf(why, why_len, "%s_cancelled", operation);
    } else if (result->term_signal != 0) {
        proof_whyf(why, why_len, "%s_signal_%d", operation,
                   result->term_signal);
    } else if (result->exit_code != 0) {
        proof_whyf(why, why_len, "%s_exit_%d", operation,
                   result->exit_code);
    } else if (result->output_truncated) {
        proof_whyf(why, why_len, "%s_truncated", operation);
    } else if (result->output_len >= output_capacity) {
        proof_whyf(why, why_len, "%s_oversize", operation);
    } else {
        proof_whyf(why, why_len, "%s_launch_failed", operation);
    }
}

static bool proof_resolve_pair_platform(const char *repo_root,
                                        const char *requested_local,
                                        const char *requested_base,
                                        char local_commit[65],
                                        char remote_base[65],
                                        char *why, size_t why_len)
{
    if (!repo_root || !local_commit || !remote_base) {
        proof_why(why, why_len, "proof_pair_input_invalid");
        return false;
    }
    if (requested_local && requested_local[0]) {
        if (!proof_oid_text(requested_local)) {
            proof_why(why, why_len, "local_commit_invalid");
            return false;
        }
        (void)snprintf(local_commit, 65, "%s", requested_local);
    } else {
        const char *argv[] = {"git", "rev-parse", "--verify", "HEAD", NULL};
        if (!git_capture(repo_root, argv, local_commit, 65) ||
            !proof_oid_text(local_commit)) {
            proof_why(why, why_len, "local_commit_unavailable");
            return false;
        }
    }
    if (requested_base && requested_base[0]) {
        if (!proof_oid_text(requested_base)) {
            proof_why(why, why_len, "remote_base_invalid");
            return false;
        }
        (void)snprintf(remote_base, 65, "%s", requested_base);
    } else {
        const char *argv[] = {"git", "rev-parse", "--verify",
                              "refs/remotes/origin/main", NULL};
        if (!git_capture(repo_root, argv, remote_base, 65) ||
            !proof_oid_text(remote_base)) {
            proof_why(why, why_len, "origin_main_unavailable");
            return false;
        }
    }
    if (why && why_len) why[0] = 0;
    return true;
}

static bool read_exact_file(const char *path, uint8_t *out, size_t size)
{
    struct stat st;
    if (!path || !out || lstat(path, &st) != 0 || !S_ISREG(st.st_mode) ||
        S_ISLNK(st.st_mode) || (st.st_mode & (S_IWGRP | S_IWOTH)) != 0 ||
        st.st_size != (off_t)size)
        return false;
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return false;
    size_t off = 0;
    while (off < size) {
        ssize_t n = read(fd, out + off, size - off);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) { close(fd); return false; }
        off += (size_t)n;
    }
    uint8_t extra;
    ssize_t tail = read(fd, &extra, 1);
    close(fd);
    return tail == 0;
}

static bool receipt_load(const struct proof_paths *paths, const char *local,
                         const char *base,
                         struct zcl_dev_acceptance_receipt_v1 *out,
                         char *why, size_t why_len)
{
    uint8_t wire[ZCL_DEV_PROOF_WIRE_BYTES];
    if (!read_exact_file(paths->receipt, wire, sizeof(wire))) {
        proof_why(why, why_len, "receipt_missing_or_unsafe");
        return false;
    }
    if (!zcl_dev_proof_receipt_parse(wire, sizeof(wire), out)) {
        proof_why(why, why_len, "receipt_parse_failed");
        return false;
    }
    return zcl_dev_proof_receipt_validate(out, local, base, why, why_len);
}

static bool proof_read_text(const char *path, char *out, size_t out_size)
{
    if (!path || !out || out_size == 0) return false;
    FILE *f = fopen(path, "r");
    if (!f) return false;
    size_t n = fread(out, 1, out_size - 1, f);
    bool ok = !ferror(f) && !(!feof(f) && n == out_size - 1);
    fclose(f);
    out[n] = 0;
    while (n > 0 && (out[n - 1] == '\n' || out[n - 1] == '\r'))
        out[--n] = 0;
    return ok;
}

/* One line for `dev proof status`/`dev proof wait` to show beside an
 * admitted receipt: what the compile step actually reused, or the typed
 * reason it did not. Reads the sidecar warm_sidecar_write() leaves beside
 * the receipt (schema "zcl.dev_proof_warmstart.v1", defined next to the
 * writer further down as PROOF_WARM_SIDECAR_SCHEMA -- duplicated here as a
 * literal because this reader sits well above that definition in the file
 * and the project avoids forward declarations). Any I/O or parse failure
 * -- older receipt, a cycle-reused receipt with no fresh sidecar, a
 * corrupt file -- leaves `out` untouched so the caller's existing fallback
 * detail stands; this is display-only and can never affect admission. */
static bool warm_status_line(const char *warmstart_path, char *out,
                             size_t out_len)
{
    char body[1024];
    if (!warmstart_path || !out || out_len == 0 ||
        !proof_read_text(warmstart_path, body, sizeof(body)))
        return false;
    char *save = NULL;
    char *line = strtok_r(body, "\n", &save);
    if (!line || strcmp(line, "zcl.dev_proof_warmstart.v1") != 0)
        return false;
    char warm_flag = 0;
    char donor[33] = {0}, reason[24] = {0};
    while ((line = strtok_r(NULL, "\n", &save))) {
        if (strncmp(line, "warm=", 5) == 0)
            warm_flag = line[5];
        else if (strncmp(line, "donor=", 6) == 0)
            (void)snprintf(donor, sizeof(donor), "%s", line + 6);
        else if (strncmp(line, "reason=", 7) == 0)
            (void)snprintf(reason, sizeof(reason), "%s", line + 7);
    }
    if (warm_flag == '1' && donor[0] && strcmp(donor, "-") != 0)
        return snprintf(out, out_len, "warm-start from donor %s", donor) > 0;
    if (warm_flag == '0')
        return snprintf(out, out_len, "cold: %s",
                        reason[0] ? reason : "unknown") > 0;
    return false;
}

static bool proof_log_contains(const char *path, const char *needle)
{
    if (!path || !needle || !needle[0])
        return false;
    FILE *f = fopen(path, "r");
    if (!f)
        return false;
    char line[1024];
    bool found = false;
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, needle)) {
            found = true;
            break;
        }
    }
    bool ok = found && !ferror(f);
    fclose(f);
    return ok;
}

static bool proof_running(const char *path, int64_t *pid_out,
                          int64_t *started_out)
{
    char text[128];
    long long pid = 0, started = 0;
    if (!proof_read_text(path, text, sizeof(text)) ||
        sscanf(text, "%lld %lld", &pid, &started) != 2 || pid <= 1 ||
        kill((pid_t)pid, 0) != 0)
        return false;
    if (pid_out) *pid_out = (int64_t)pid;
    if (started_out) *started_out = (int64_t)started;
    return true;
}

static bool proof_private_regular(const char *path)
{
    struct stat st;
    return path && lstat(path, &st) == 0 && S_ISREG(st.st_mode) &&
           !S_ISLNK(st.st_mode) && (st.st_mode & (S_IWGRP | S_IWOTH)) == 0;
}

static bool proof_lease_read(const char *path, char *token, size_t token_len,
                             int64_t *pid_out, int64_t *started_out)
{
    char text[384], parsed[192];
    long long pid = 0, started = 0;
    if (!token || token_len == 0 || !proof_private_regular(path) ||
        !proof_read_text(path, text, sizeof(text)) ||
        sscanf(text, "%191s %lld %lld", parsed, &pid, &started) != 3 ||
        strlen(parsed) >= token_len || pid <= 1 || started <= 0)
        return false;
    (void)snprintf(token, token_len, "%s", parsed);
    if (pid_out) *pid_out = (int64_t)pid;
    if (started_out) *started_out = (int64_t)started;
    return true;
}

static bool proof_lease_running(const char *path, int64_t *pid_out,
                                int64_t *started_out)
{
    char token[192];
    int64_t pid = 0;
    if (!proof_lease_read(path, token, sizeof(token), &pid, started_out) ||
        (kill((pid_t)pid, 0) != 0 && errno != EPERM))
        return false;
    if (pid_out) *pid_out = pid;
    return true;
}

static bool proof_request_read(const char *path, char local[65], char base[65],
                               int64_t *wall_out, int64_t *monotonic_out)
{
    char text[320], *lines[5], *save = NULL;
    if (!proof_private_regular(path) ||
        !proof_read_text(path, text, sizeof(text)))
        return false;
    size_t count = 0;
    for (char *line = strtok_r(text, "\n", &save); line && count < 5;
         line = strtok_r(NULL, "\n", &save))
        lines[count++] = line;
    if (count != 5 || strcmp(lines[0], "zcl.dev_proof_request.v1") != 0 ||
        !proof_oid_text(lines[1]) || !proof_oid_text(lines[2]))
        return false;
    char *wall_end = NULL, *mono_end = NULL;
    errno = 0;
    long long wall = strtoll(lines[3], &wall_end, 10);
    bool wall_ok = errno == 0 && wall_end && *wall_end == 0 && wall > 0;
    errno = 0;
    long long mono = strtoll(lines[4], &mono_end, 10);
    if (!wall_ok || errno != 0 || !mono_end || *mono_end != 0 || mono <= 0)
        return false;
    (void)snprintf(local, 65, "%s", lines[1]);
    (void)snprintf(base, 65, "%s", lines[2]);
    if (wall_out) *wall_out = (int64_t)wall;
    if (monotonic_out) *monotonic_out = (int64_t)mono;
    return true;
}

static bool proof_request_matches_pair(const char *path, const char *local,
                                       const char *base)
{
    char request_local[65], request_base[65], expected[PATH_MAX];
    int n = path && local && base
        ? snprintf(expected, sizeof(expected), "%s-%s.request", local, base)
        : -1;
    const char *leaf = path ? strrchr(path, '/') : NULL;
    return n > 0 && n < (int)sizeof(expected) && leaf &&
        strcmp(leaf + 1, expected) == 0 &&
        proof_request_read(path, request_local, request_base, NULL, NULL) &&
        strcmp(request_local, local) == 0 && strcmp(request_base, base) == 0;
}

/* Each proof attempt gets its own throwaway directory
 * (`.cache/zcl-dev-proof/attempts/<local>-<base>.XXXXXX`, see
 * proof_attempt_paths_prepare) holding that attempt's real logs
 * (lint.log/test.log/bundle.log/helpers.log under its own `logs/`
 * subdirectory) — the flat `.cache/zcl-dev-proof/logs` directory is never
 * written to. A settled `.failed` marker names only the failing reason
 * string, not where the evidence lives, so a caller diagnosing a failure
 * needs the newest attempt directory for this exact pair. mkdtemp's
 * suffix is random, not time-ordered, so "newest" means highest mtime,
 * not lexicographic order. */
static bool proof_attempt_dir_newest(const struct proof_paths *paths,
                                     char *out, size_t out_len)
{
    if (!paths || !out || out_len == 0) return false;
    char prefix[160];
    int prefix_len = snprintf(prefix, sizeof(prefix), "%s.", paths->key);
    if (prefix_len <= 0 || prefix_len >= (int)sizeof(prefix)) return false;
    DIR *dir = opendir(paths->attempts);
    if (!dir) return false;
    bool found = false;
    time_t newest_mtime = 0;
    char newest[PATH_MAX] = {0};
    for (struct dirent *entry = readdir(dir); entry; entry = readdir(dir)) {
        if (strncmp(entry->d_name, prefix, (size_t)prefix_len) != 0)
            continue;
        char candidate[PATH_MAX];
        if (snprintf(candidate, sizeof(candidate), "%s/%s", paths->attempts,
                    entry->d_name) >= (int)sizeof(candidate))
            continue;
        struct stat st;
        if (stat(candidate, &st) != 0 || !S_ISDIR(st.st_mode)) continue;
        if (!found || st.st_mtime > newest_mtime) {
            found = true;
            newest_mtime = st.st_mtime;
            (void)snprintf(newest, sizeof(newest), "%s", candidate);
        }
    }
    (void)closedir(dir);
    if (!found) return false;
    char logs[PATH_MAX];
    if (snprintf(logs, sizeof(logs), "%s/logs", newest) >= (int)sizeof(logs))
        return false;
    (void)snprintf(out, out_len, "%s", logs);
    return true;
}

static bool proof_status_read_platform(const char *repo_root,
                                       const char *local_commit,
                                       const char *remote_base,
                                       struct zcl_dev_proof_status *out)
{
    if (!out) return false;
    memset(out, 0, sizeof(*out));
    char local[65], base[65], why[160] = {0};
    if (!zcl_dev_proof_resolve_pair(repo_root, local_commit, remote_base,
                                    local, base, why, sizeof(why))) {
        out->state = ZCL_DEV_PROOF_STATE_INVALID;
        (void)snprintf(out->detail, sizeof(out->detail), "%s", why);
        return false;
    }
    (void)snprintf(out->local_commit, sizeof(out->local_commit), "%s", local);
    (void)snprintf(out->remote_base, sizeof(out->remote_base), "%s", base);
    struct proof_paths paths;
    if (!proof_paths_fill(repo_root, local, base, &paths)) {
        out->state = ZCL_DEV_PROOF_STATE_INVALID;
        (void)snprintf(out->detail, sizeof(out->detail), "%s",
                       "proof_state_path_invalid");
        return false;
    }
    (void)snprintf(out->receipt_path, sizeof(out->receipt_path), "%s",
                   paths.receipt);
    (void)snprintf(out->log_dir, sizeof(out->log_dir), "%s", paths.logs);
    struct zcl_dev_acceptance_receipt_v1 receipt;
    if (receipt_load(&paths, local, base, &receipt, why, sizeof(why))) {
        out->state = ZCL_DEV_PROOF_STATE_PASSED;
        /* The compile step's own sidecar says what it reused in one line;
         * fall back to the fixed status word only when there is none (an
         * older receipt, or one settled by cycle reuse with no fresh
         * compile of its own). */
        if (!warm_status_line(paths.warmstart, out->detail,
                              sizeof(out->detail)))
            (void)snprintf(out->detail, sizeof(out->detail), "%s",
                           "exact_receipt_admitted");
        return true;
    }
    int64_t pid = 0, started = 0;
    if (proof_lease_running(paths.lease, &pid, &started) ||
        proof_running(paths.lock, &pid, &started)) {
        int64_t now = platform_time_wall_unix();
        int64_t elapsed_ms = now > started ? (now - started) * 1000 : 0;
        out->state = ZCL_DEV_PROOF_STATE_RUNNING;
        out->worker_id = pid;
        out->started_unix = started;
        int64_t ceiling_ms = zcl_dev_proof_ceiling_ms();
        out->eta_ms = elapsed_ms < ceiling_ms ? ceiling_ms - elapsed_ms : 0;
        (void)snprintf(out->detail, sizeof(out->detail), "%s",
                       "background_verification_running");
        return true;
    }
    if (proof_request_matches_pair(paths.request, local, base)) {
        out->state = ZCL_DEV_PROOF_STATE_RUNNING;
        out->eta_ms = zcl_dev_proof_ceiling_ms();
        (void)snprintf(out->detail, sizeof(out->detail), "%s",
                       "resident_proof_request_queued");
        return true;
    }
    if (proof_private_regular(paths.request)) {
        out->state = ZCL_DEV_PROOF_STATE_FAILED;
        (void)snprintf(out->detail, sizeof(out->detail), "%s",
                       "proof_request_invalid");
        return true;
    }
    if (proof_read_text(paths.failure, out->detail, sizeof(out->detail))) {
        out->state = ZCL_DEV_PROOF_STATE_FAILED;
        (void)proof_attempt_dir_newest(&paths, out->log_dir,
                                       sizeof(out->log_dir));
        return true;
    }
    out->state = ZCL_DEV_PROOF_STATE_MISSING;
    (void)snprintf(out->detail, sizeof(out->detail), "%s",
                   "exact_receipt_missing");
    return true;
}

static void hash_begin(struct sha3_256_ctx *sha, const char *domain)
{
    sha3_256_init(sha);
    sha3_256_write(sha, (const uint8_t *)domain, strlen(domain) + 1);
}

static bool hash_file(const char *domain, const char *path, uint8_t out[32])
{
    FILE *f = fopen(path, "rb");
    if (!f) return false;
    struct sha3_256_ctx sha;
    hash_begin(&sha, domain);
    uint8_t buffer[65536];
    size_t n;
    while ((n = fread(buffer, 1, sizeof(buffer), f)) > 0)
        sha3_256_write(&sha, buffer, n);
    bool ok = !ferror(f);
    fclose(f);
    if (!ok) return false;
    sha3_256_finalize(&sha, out);
    return true;
}

static void hash_text(const char *domain, const void *text, size_t text_len,
                      uint8_t out[32])
{
    struct sha3_256_ctx sha;
    hash_begin(&sha, domain);
    sha3_256_write(&sha, text, text_len);
    sha3_256_finalize(&sha, out);
}

static bool write_all(int fd, const void *data, size_t size)
{
    const uint8_t *p = data;
    while (size > 0) {
        ssize_t n = write(fd, p, size);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return false;
        p += n;
        size -= (size_t)n;
    }
    return true;
}

static bool write_atomic(const char *path, const void *data, size_t size,
                         mode_t mode)
{
    char temp[PATH_MAX];
    if (snprintf(temp, sizeof(temp), "%s.tmp.XXXXXX", path) >=
        (int)sizeof(temp))
        return false;
    int fd = mkstemp(temp);
    if (fd < 0) return false;
    bool ok = fchmod(fd, mode) == 0 && write_all(fd, data, size) &&
              fsync(fd) == 0;
    if (close(fd) != 0) ok = false;
    if (ok && rename(temp, path) != 0) ok = false;
    if (!ok) {
        (void)unlink(temp);
    }
    return ok;
}

static bool proof_request_body(const char *local, const char *base,
                               char out[320], size_t *len_out)
{
    int n = local && base
        ? snprintf(out, 320,
                   "zcl.dev_proof_request.v1\n%s\n%s\n%lld\n%lld\n",
                   local, base,
                   (long long)platform_time_wall_unix(),
                   (long long)platform_time_monotonic_us())
        : -1;
    if (n <= 0 || n >= 320) return false;
    if (len_out) *len_out = (size_t)n;
    return true;
}

static bool proof_attempt_paths_prepare(const struct proof_paths *pair,
                                        struct proof_paths *attempt)
{
    if (!pair || !attempt) return false;
    *attempt = *pair;
    char temporary[PATH_MAX];
    if (snprintf(temporary, sizeof(temporary), "%s/%s.XXXXXX",
                 pair->attempts, pair->key) >= (int)sizeof(temporary) ||
        !mkdtemp(temporary) ||
        snprintf(attempt->attempt, sizeof(attempt->attempt), "%s",
                 temporary) >= (int)sizeof(attempt->attempt))
        return false;
    const char *leaf = strrchr(attempt->attempt, '/');
    if (!leaf || !leaf[1] || strlen(leaf + 1) >= sizeof(attempt->attempt_token))
        return false;
    (void)snprintf(attempt->attempt_token, sizeof(attempt->attempt_token),
                   "%s", leaf + 1);
    attempt->attempt_worker = (int64_t)getpid();
    if (snprintf(attempt->logs, sizeof(attempt->logs), "%s/logs",
                 attempt->attempt) >= (int)sizeof(attempt->logs) ||
        snprintf(attempt->changed, sizeof(attempt->changed),
                 "%s/changed.files", attempt->attempt) >=
            (int)sizeof(attempt->changed) ||
        snprintf(attempt->bundle_log, sizeof(attempt->bundle_log),
                 "%s/logs/bundle.log", attempt->attempt) >=
            (int)sizeof(attempt->bundle_log) ||
        snprintf(attempt->helper_log, sizeof(attempt->helper_log),
                 "%s/logs/helpers.log", attempt->attempt) >=
            (int)sizeof(attempt->helper_log) ||
        snprintf(attempt->phases, sizeof(attempt->phases), "%s/phases.txt",
                 attempt->attempt) >= (int)sizeof(attempt->phases) ||
        !platform_private_directory_ensure(attempt->logs))
        return false;
    return true;
}

static bool proof_lease_publish(const struct proof_paths *paths)
{
    char body[320];
    int n = paths
        ? snprintf(body, sizeof(body), "%s %ld %lld\n",
                   paths->attempt_token, (long)paths->attempt_worker,
                   (long long)platform_time_wall_unix())
        : -1;
    return n > 0 && n < (int)sizeof(body) &&
           write_atomic(paths->lease, body, (size_t)n, 0600);
}

static bool proof_lease_current(const struct proof_paths *paths)
{
    char token[192];
    int64_t pid = 0;
    return paths && paths->attempt_token[0] && paths->attempt_worker > 1 &&
        proof_lease_read(paths->lease, token, sizeof(token), &pid, NULL) &&
        strcmp(token, paths->attempt_token) == 0 &&
        pid == (int64_t)paths->attempt_worker;
}

static int proof_queue_lock_acquire(const struct proof_paths *paths)
{
    if (!paths) return -1;
    int fd = open(paths->queue_lock, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
    if (fd < 0 || flock(fd, LOCK_EX) != 0) {
        if (fd >= 0) close(fd);
        return -1;
    }
    return fd;
}

static void proof_queue_lock_release(int fd)
{
    if (fd < 0) return;
    (void)flock(fd, LOCK_UN);
    (void)close(fd);
}

static bool proof_write_if_current(const struct proof_paths *paths,
                                   const char *target, const void *data,
                                   size_t size, mode_t mode)
{
    int fd = proof_queue_lock_acquire(paths);
    if (fd < 0) return false;
    bool ok = proof_lease_current(paths) &&
              write_atomic(target, data, size, mode);
    proof_queue_lock_release(fd);
    return ok;
}

static void proof_unlink_if_current(const struct proof_paths *paths,
                                    const char *target)
{
    int fd = proof_queue_lock_acquire(paths);
    if (fd < 0) return;
    if (proof_lease_current(paths)) (void)unlink(target);
    proof_queue_lock_release(fd);
}

static void proof_lease_release(const struct proof_paths *paths)
{
    int fd = proof_queue_lock_acquire(paths);
    if (fd < 0) return;
    if (proof_lease_current(paths)) (void)unlink(paths->lease);
    proof_queue_lock_release(fd);
}

/* Longest repo-relative path a changed-set row may carry. Unchanged from the
 * fixed-table era; only the NUMBER of rows became heap-resident. */
#define PROOF_CHANGED_PATH_MAX 256
/* Byte ceiling on the captured list itself: the row ceiling times the row
 * length. Exceeding it is refused with the observed size, never truncated. */
#define PROOF_CHANGED_BYTES_MAX \
    ((size_t)ZCL_DEVLOOP_MAX_FILES * (size_t)PROOF_CHANGED_PATH_MAX)

void zcl_dev_proof_changed_set_release(struct zcl_dev_proof_changed_set *set)
{
    if (!set)
        return;
    free(set->bytes);
    free((void *)set->files);
    set->bytes = NULL;
    set->files = NULL;
    set->count = 0;
}

/* Read a captured list whole. Refuses with the observed byte count rather than
 * returning a shorter, still-plausible list. */
static char *changed_set_read(const char *path, size_t *len_out,
                              char *why, size_t why_len)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        proof_why(why, why_len, "changed_set_unavailable_or_truncated");
        return NULL;
    }
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        (void)close(fd);
        proof_why(why, why_len, "changed_set_unavailable_or_truncated");
        return NULL;
    }
    if ((uint64_t)st.st_size > (uint64_t)PROOF_CHANGED_BYTES_MAX) {
        (void)close(fd);
        proof_whyf(why, why_len,
                   "changed_set_unavailable_or_truncated bytes=%llu max=%zu",
                   (unsigned long long)st.st_size, PROOF_CHANGED_BYTES_MAX);
        return NULL;
    }
    size_t size = (size_t)st.st_size;
    char *bytes = zcl_calloc(size + 1, 1, "proof changed-set capture");
    if (!bytes) {
        (void)close(fd);
        proof_why(why, why_len, "changed_set_allocation_failed");
        return NULL;
    }
    size_t used = 0;
    while (used < size) {
        ssize_t n = read(fd, bytes + used, size - used);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            break;
        used += (size_t)n;
    }
    (void)close(fd);
    if (used != size) {
        free(bytes);
        proof_whyf(why, why_len,
                   "changed_set_unavailable_or_truncated read=%zu of %zu",
                   used, size);
        return NULL;
    }
    bytes[size] = 0;
    *len_out = size;
    return bytes;
}

bool zcl_dev_proof_changed_set_capture(const char *repo_root, const char *base,
                                       const char *local,
                                       const char *scratch_path,
                                       const char *persist_path,
                                       struct zcl_dev_proof_changed_set *out,
                                       char *why, size_t why_len)
{
    if (!out)
        return false;
    memset(out, 0, sizeof(*out));
    if (!repo_root || !base || !local || !scratch_path || !scratch_path[0]) {
        proof_why(why, why_len, "changed_set_request_invalid");
        return false;
    }
    const char *ancestor[] = {"git", "merge-base", "--is-ancestor", base,
                              local, NULL};
    char ignored[2];
    if (!git_capture(repo_root, ancestor, ignored, sizeof(ignored))) {
        proof_why(why, why_len, "remote_base_not_ancestor");
        return false;
    }
    /* `--output` sends the list to a file instead of the fixed-size process
     * capture buffer, so a batch of thousands of paths cannot arrive as a
     * shorter list that still parses. */
    char output_arg[PATH_MAX + 16];
    if (snprintf(output_arg, sizeof(output_arg), "--output=%s", scratch_path) >=
        (int)sizeof(output_arg)) {
        proof_why(why, why_len, "changed_set_request_invalid");
        return false;
    }
    (void)unlink(scratch_path);
    const char *argv[] = {"git", "diff", "--name-only", "--diff-filter=ACMRD",
                          output_arg, base, local, "--", NULL};
    if (!git_capture(repo_root, argv, ignored, sizeof(ignored))) {
        (void)unlink(scratch_path);
        proof_why(why, why_len, "changed_set_unavailable_or_truncated");
        return false;
    }
    size_t len = 0;
    char *bytes = changed_set_read(scratch_path, &len, why, why_len);
    (void)unlink(scratch_path);
    if (!bytes)
        return false;

    /* Count first, so an over-ceiling batch is refused with its real size. */
    size_t count = 0;
    for (size_t i = 0; i < len; i++) {
        if (bytes[i] == '\n')
            continue;
        count++;
        while (i < len && bytes[i] != '\n')
            i++;
    }
    if (count == 0) {
        free(bytes);
        proof_why(why, why_len, "changed_set_empty");
        return false;
    }
    if (count > (size_t)ZCL_DEVLOOP_MAX_FILES) {
        free(bytes);
        proof_whyf(why, why_len,
                   "changed_set_invalid_or_truncated files=%zu max=%d",
                   count, ZCL_DEVLOOP_MAX_FILES);
        return false;
    }
    const char **refs = zcl_calloc(count, sizeof(*refs),
                                   "proof changed-set rows");
    if (!refs) {
        free(bytes);
        proof_why(why, why_len, "changed_set_allocation_failed");
        return false;
    }
    size_t stored = 0, persist_len = 0;
    char *save = NULL;
    for (char *line = strtok_r(bytes, "\n", &save); line;
         line = strtok_r(NULL, "\n", &save)) {
        size_t path_len = strlen(line);
        if (path_len == 0)
            continue;
        if (stored >= count || path_len >= PROOF_CHANGED_PATH_MAX ||
            line[0] == '/' || strstr(line, "..") || strchr(line, '\\')) {
            free((void *)refs);
            free(bytes);
            proof_whyf(why, why_len,
                       "changed_set_invalid_or_truncated row=%zu", stored + 1);
            return false;
        }
        refs[stored++] = line;
        persist_len += path_len + 1;
    }
    if (stored != count) {
        free((void *)refs);
        free(bytes);
        proof_whyf(why, why_len,
                   "changed_set_invalid_or_truncated rows=%zu of %zu", stored,
                   count);
        return false;
    }
    if (persist_path && persist_path[0]) {
        char *persisted = zcl_calloc(persist_len, 1,
                                     "proof changed-set record");
        if (!persisted) {
            free((void *)refs);
            free(bytes);
            proof_why(why, why_len, "changed_set_allocation_failed");
            return false;
        }
        size_t used = 0;
        for (size_t i = 0; i < count; i++) {
            size_t path_len = strlen(refs[i]);
            memcpy(persisted + used, refs[i], path_len);
            used += path_len;
            persisted[used++] = '\n';
        }
        bool written = write_atomic(persist_path, persisted, used, 0400);
        free(persisted);
        if (!written) {
            free((void *)refs);
            free(bytes);
            proof_why(why, why_len, "changed_set_persist_failed");
            return false;
        }
    }
    out->bytes = bytes;
    out->files = refs;
    out->count = count;
    return true;
}

static bool worktree_exact(const char *root, const char *local,
                           bool include_untracked, char *why, size_t why_len)
{
    char head[65], status[ZCL_DEVLOOP_OUTPUT_MAX];
    struct zcl_devloop_process_result head_result = {0};
    struct zcl_devloop_process_result status_result = {0};
    const char *head_argv[] = {"git", "rev-parse", "--verify", "HEAD", NULL};
    const char *status_argv[] = {
        "git", "status", "--porcelain=v1",
        include_untracked ? "--untracked-files=normal" : "--untracked-files=no",
        NULL};
    if (!git_capture_observed(root, head_argv, 30000, head, sizeof(head),
                              &head_result)) {
        git_capture_why("head_capture", &head_result, sizeof(head), why,
                        why_len);
        return false;
    }
    if (!proof_oid_text(head)) {
        proof_why(why, why_len, "head_capture_output_invalid");
        return false;
    }
    if (strcmp(head, local) != 0) {
        proof_why(why, why_len, "head_changed_during_proof");
        return false;
    }
    if (!git_capture_observed(root, status_argv, 30000, status,
                              sizeof(status), &status_result)) {
        git_capture_why("worktree_status_capture", &status_result,
                        sizeof(status), why, why_len);
        return false;
    }
    if (status[0]) {
        proof_why(why, why_len, "worktree_not_clean");
        return false;
    }
    return true;
}

static bool dependency_parent_ensure(const char *path)
{
    char parent[PATH_MAX];
    if (!path || snprintf(parent, sizeof(parent), "%s", path) >=
                     (int)sizeof(parent))
        return false;
    char *leaf = strrchr(parent, '/');
    if (!leaf || leaf == parent) return false;
    *leaf = 0;
    for (char *p = parent + 1;; p++) {
        if (*p != '/' && *p != 0) continue;
        char saved = *p;
        *p = 0;
        struct stat st;
        bool ok = lstat(parent, &st) == 0
            ? S_ISDIR(st.st_mode) && !S_ISLNK(st.st_mode)
            : errno == ENOENT && mkdir(parent, 0700) == 0;
        *p = saved;
        if (!ok || saved == 0) return ok;
    }
}

/* A refusal a reader can act on names the failure, not a number. */
static const char *proof_errno_name(int value)
{
    switch (value) {
    case 0: return "no errno";
    case EACCES: return "EACCES";
    case EDQUOT: return "EDQUOT";
    case EEXIST: return "EEXIST";
    case EINVAL: return "EINVAL";
    case EIO: return "EIO";
    case EISDIR: return "EISDIR";
    case ELOOP: return "ELOOP";
    case EMLINK: return "EMLINK";
    case ENAMETOOLONG: return "ENAMETOOLONG";
    case ENOENT: return "ENOENT";
    case ENOMEM: return "ENOMEM";
    case ENOSPC: return "ENOSPC";
    case ENOTDIR: return "ENOTDIR";
    case EPERM: return "EPERM";
    case EROFS: return "EROFS";
    case EXDEV: return "EXDEV";
    default: return "unrecognised errno";
    }
}

/* Independent copies on macOS prevent generation writes reaching donors
 * through shared inodes. Elsewhere link() is the fast path but only works
 * inside one filesystem. A RAM-backed
 * generation root (/dev/shm) is a different filesystem from the checkout, so
 * link() answers EXDEV there and the dependency has to be copied byte for
 * byte. The mode carries: a hook or a .so that arrived without its executable
 * bit fails far away from here, where the cause is no longer visible.
 *
 * The MODIFICATION TIME carries for the same reason. link() preserves it for
 * free; a copy that stamps the target with the time of the copy hands the
 * generation an artifact that is newer than every source it was built from,
 * and make inside the generation then declares a stale artifact up to date
 * and never rebuilds it. That is not a hypothetical: a hot-swap fixture image
 * copied this way kept the consensus core seal of an older build and every
 * activation in the generation was rejected on shape. */
static bool dependency_copy_stat(const char *source, const char *target,
                                 const struct stat *source_st)
{
    int input = open(source, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (input < 0) return false;
    char temporary[PATH_MAX];
    int temporary_len = snprintf(temporary, sizeof(temporary),
                                 "%s.tmp.XXXXXX", target);
    bool ok = temporary_len > 0 && temporary_len < (int)sizeof(temporary);
    int output = ok ? mkstemp(temporary) : -1;
    if (output < 0) ok = false;
    unsigned char buffer[65536];
    while (ok) {
        ssize_t got = read(input, buffer, sizeof(buffer));
        if (got < 0 && errno == EINTR) continue;
        if (got < 0) ok = false;
        if (got <= 0) break;
        ok = write_all(output, buffer, (size_t)got);
    }
    int saved = errno;
    if (close(input) != 0) ok = false;
    if (output >= 0) {
        if (fchmod(output, source_st->st_mode & 07777) != 0) ok = false;
        const struct timespec times[2] = {
            source_st->st_atim, source_st->st_mtim,
        };
        if (futimens(output, times) != 0) ok = false;
        if (close(output) != 0) ok = false;
    }
    if (ok && rename(temporary, target) != 0) ok = false;
    if (!ok) {
        if (output >= 0) (void)unlink(temporary);
        if (errno == 0) errno = saved;
    }
    return ok;
}

static int dependency_seed(const char *source, const char *target,
                           const struct stat *source_st)
{
#if defined(ZCL_TESTING)
    /* Exercise the real fallback without requiring a second filesystem. */
    const char *failure = getenv("ZCL_DEV_PROOF_TEST_LINK_ERRNO");
    if (failure && (strcmp(failure, "EXDEV") == 0 ||
                    strcmp(failure, "EACCES") == 0)) {
        errno = strcmp(failure, "EXDEV") == 0 ? EXDEV : EACCES;
        return -1;
    }
#endif
#if defined(__APPLE__)
    /* Seatbelt grants paths, not independent ownership of a shared inode.
     * A writable generation must not be able to overwrite its donor. */
    return dependency_copy_stat(source, target, source_st) ? 0 : -1;
#else
    (void)source_st;
    return link(source, target);
#endif
}

static bool dependency_materialize(const char *source, const char *target)
{
    struct stat source_st, target_st;
    if (lstat(source, &source_st) != 0) return false;
    bool target_exists = lstat(target, &target_st) == 0;
    if (target_exists && S_ISLNK(target_st.st_mode)) {
        if (unlink(target) != 0) return false;
        target_exists = false;
    }
    if (S_ISREG(source_st.st_mode)) {
#if !defined(__APPLE__)
        if (target_exists && S_ISREG(target_st.st_mode) &&
            source_st.st_dev == target_st.st_dev &&
            source_st.st_ino == target_st.st_ino)
            return true;
        if (target_exists && unlink(target) != 0) return false;
#endif
        /* On macOS the temporary copy replaces an old shared inode only
         * after the source is open and the independent copy is complete. */
        if (dependency_seed(source, target, &source_st) == 0) return true;
        /* Same filesystem is the fast path; a cross-device generation root is
         * not a missing dependency, so copy rather than refuse. */
        if (errno != EXDEV && errno != EPERM && errno != EMLINK) return false;
        return dependency_copy_stat(source, target, &source_st);
    }
    if (S_ISLNK(source_st.st_mode)) {
        char link_target[PATH_MAX];
        ssize_t len = readlink(source, link_target, sizeof(link_target) - 1);
        if (len <= 0 || (size_t)len >= sizeof(link_target) - 1)
            return false;
        link_target[len] = 0;
        if (link_target[0] == '/' || strstr(link_target, ".."))
            return false;
        if (target_exists && unlink(target) != 0) return false;
        return symlink(link_target, target) == 0;
    }
    if (!S_ISDIR(source_st.st_mode) ||
        (target_exists && !S_ISDIR(target_st.st_mode)) ||
        (!target_exists && mkdir(target, 0700) != 0))
        return false;
    DIR *dir = opendir(source);
    if (!dir) return false;
    bool ok = true;
    for (struct dirent *entry = readdir(dir); ok && entry;
         entry = readdir(dir)) {
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0)
            continue;
        char child_source[PATH_MAX], child_target[PATH_MAX];
        if (snprintf(child_source, sizeof(child_source), "%s/%s", source,
                     entry->d_name) >= (int)sizeof(child_source) ||
            snprintf(child_target, sizeof(child_target), "%s/%s", target,
                     entry->d_name) >= (int)sizeof(child_target) ||
            !dependency_materialize(child_source, child_target))
            ok = false;
    }
    return closedir(dir) == 0 && ok;
}

/* Testing seam: one generation dependency materialized exactly the way the
 * proof does it. No proof, lease, or admission authority — it exists so the
 * cross-filesystem path can be pinned by a test instead of only by a live
 * RAM-backed proof run. */
bool zcl_dev_proof_dependency_materialize(const char *source,
                                          const char *target)
{
    return dependency_materialize(source, target);
}

static bool dependency_copy_fresh(const char *source, const char *target)
{
    int input = open(source, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (input < 0) return false;
    struct stat st;
    char temporary[PATH_MAX];
    int temporary_len = snprintf(temporary, sizeof(temporary),
                                 "%s.tmp.XXXXXX", target);
    bool ok = fstat(input, &st) == 0 && S_ISREG(st.st_mode) &&
        temporary_len > 0 && temporary_len < (int)sizeof(temporary);
    int output = ok ? mkstemp(temporary) : -1;
    if (output < 0) ok = false;
    unsigned char buffer[65536];
    while (ok) {
        ssize_t got = read(input, buffer, sizeof(buffer));
        if (got < 0 && errno == EINTR) continue;
        if (got < 0) ok = false;
        if (got <= 0) break;
        ok = write_all(output, buffer, (size_t)got);
    }
    if (close(input) != 0) ok = false;
    if (output >= 0) {
        if (fchmod(output, 0600) != 0) ok = false;
        if (close(output) != 0) ok = false;
    }
    if (ok && rename(temporary, target) != 0) ok = false;
    if (!ok && output >= 0) (void)unlink(temporary);
    return ok;
}

static bool depfile_tree_copy(const char *source, const char *target,
                              size_t source_root_len,
                              struct sha3_256_ctx *root, size_t *count)
{
    if (!dependency_parent_ensure(target)) return false;
    struct stat target_st;
    if (lstat(target, &target_st) != 0) {
        if (errno != ENOENT || mkdir(target, 0700) != 0) return false;
    } else if (!S_ISDIR(target_st.st_mode) || S_ISLNK(target_st.st_mode)) {
        return false;
    }
    DIR *dir = opendir(source);
    if (!dir) return false;
    bool ok = true;
    for (struct dirent *entry = readdir(dir); ok && entry;
         entry = readdir(dir)) {
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0)
            continue;
        char child_source[PATH_MAX], child_target[PATH_MAX];
        if (snprintf(child_source, sizeof(child_source), "%s/%s", source,
                     entry->d_name) >= (int)sizeof(child_source) ||
            snprintf(child_target, sizeof(child_target), "%s/%s", target,
                     entry->d_name) >= (int)sizeof(child_target)) {
            ok = false;
            break;
        }
        struct stat st;
        if (lstat(child_source, &st) != 0) ok = false;
        else if (S_ISDIR(st.st_mode))
            ok = depfile_tree_copy(child_source, child_target, source_root_len,
                                   root, count);
        else if (S_ISREG(st.st_mode) &&
                 strlen(entry->d_name) > 2 &&
                 strcmp(entry->d_name + strlen(entry->d_name) - 2, ".d") == 0) {
            uint8_t digest[32];
            ok = dependency_copy_fresh(child_source, child_target) &&
                hash_file("zcl.dev_proof_depfile.v1", child_source, digest);
            if (ok) {
                const char *relative = child_source + source_root_len;
                if (*relative == '/') relative++;
                sha3_256_write(root, (const uint8_t *)relative,
                               strlen(relative) + 1);
                sha3_256_write(root, digest, sizeof(digest));
                (*count)++;
            }
        }
    }
    return closedir(dir) == 0 && ok;
}

/* ── Warm-start proof generations ────────────────────────────────────────
 *
 * A generation is a detached worktree plus its build tree, one per
 * (checkout, local commit) pair. A fresh generation compiles every
 * translation unit because git stamps every source with the checkout time,
 * even when the commit changed one line. The shared zcc cache cannot cover
 * the gap: its key folds the working directory, which is unique per
 * generation. So a new generation hard-links the previous complete
 * generation's immutable compiler outputs and repairs make's timestamp
 * graph around the exact changed set. Make then recompiles exactly the
 * changed translation units and relinks; everything else is reused byte
 * for byte.
 *
 * Safety rests on four properties, each checked where it is used rather
 * than asserted here:
 *
 * 1. Seeded files are never rewritten in place. Objects and depfiles are
 *    published by staging plus rename (tools/dev/compile-epoch-object.sh,
 *    tools/zcc.c epoch-object publish), so a rebuild replaces the new
 *    generation's link and the donor keeps its bytes. The classifier below
 *    links only object and depfile outputs; everything else is skipped,
 *    except the small compiler-wrapper binary which is copied, never
 *    linked, because it is executed and must not share an inode across
 *    generations.
 * 2. Seeded objects are byte-valid in the new generation. Depfiles carry
 *    relative paths, -ffile-prefix-map removes the absolute build root
 *    from objects (Makefile REPRO_CFLAGS), and -frandom-seed takes the
 *    relative TU path, so identical sources compile to identical bytes.
 *    The epoch key already refuses reuse across toolchain, flag, or
 *    build-system moves: seeded objects under a stale epoch name are dead
 *    weight make never addresses.
 * 3. Freshness is content-derived, not trusted. Seeded outputs are stamped
 *    at seed time; then every path git names as changed between the donor
 *    commit and the new commit is stamped strictly later. Unchanged
 *    sources stay older than the seeds (reuse), changed sources and
 *    headers are newer (rebuild, with header dependents found through the
 *    seeded depfiles). Any failure before the repair completes unlinks the
 *    seeds, which degrades to the cold build, never to a stale reuse.
 * 4. The donor is stable. Only a generation carrying a build-complete
 *    marker for the checkout's own root, still checked out at the marked
 *    commit, with no live proof lease, may donate. Its build tree cannot
 *    change under the reader: the proof never rebuilds a completed
 *    build-only tree, and epoch publishers replace rather than mutate.
 *
 * Cold is always correct; warm start is only an optimisation. Every step
 * below refuses rather than guesses. */

#define PROOF_WARM_MARKER_REL "build/.proof-build-complete"
#define PROOF_WARM_MARKER_SCHEMA "zcl.proof_build_complete.v1"
#define PROOF_WARM_SIDECAR_SCHEMA "zcl.dev_proof_warmstart.v1"
#define PROOF_WARM_TAG_LEN 32
/* `git worktree remove` is a recursive delete of a multi-gigabyte tree.
 * The 30 s budget the short git queries share would abandon it half-done,
 * and a half-deleted generation is one the reapability check can never
 * approve again. */
#define PROOF_WARM_REMOVE_TIMEOUT_MS 600000
#define PROOF_WARM_REAP_MAX 8
/* An active proof stamps its generation when it takes it and builds for up
 * to an hour on a loaded host, so anything touched within the hour may
 * still be working. Marker-less generations get a full day: without a
 * marker there is no pair lease to consult, and age is the only signal. */
#define PROOF_WARM_IDLE_ACTIVE_SECONDS (60 * 60)
#define PROOF_WARM_IDLE_UNMARKED_SECONDS (24 * 60 * 60)

static bool warm_tag_name(const char *name)
{
    /* The pool holds exactly one shape of entry: the 32-character
     * lowercase hex tag generation_prepare() derives. Anything else under
     * .z23p was put there by something that is not this code, and is
     * therefore not this code's to seed from or delete. */
    size_t len = name ? strlen(name) : 0;
    if (len != PROOF_WARM_TAG_LEN) return false;
    for (size_t i = 0; i < len; i++) {
        char c = name[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
            return false;
    }
    return true;
}

enum warm_seed_class {
    WARM_SEED_SKIP,
    WARM_SEED_LINK,
    WARM_SEED_COPY,
};

static bool warm_path_hidden(const char *rel)
{
    /* Any hidden component (lease, session, lock, admission, staging, or
     * marker state) is live build machinery, never a reusable output. */
    if (!rel || !rel[0]) return true;
    if (rel[0] == '.') return true;
    for (const char *p = rel; *p; p++) {
        if (p[0] == '/' && p[1] == '.') return true;
    }
    return false;
}

static bool warm_has_suffix(const char *rel, const char *suffix)
{
    size_t rel_len = rel ? strlen(rel) : 0;
    size_t suffix_len = suffix ? strlen(suffix) : 0;
    return suffix_len > 0 && rel_len > suffix_len &&
           strcmp(rel + rel_len - suffix_len, suffix) == 0;
}

/* LINK: immutable compiler outputs, replaced rather than rewritten by the
 * epoch publishers, so sharing an inode with the donor is safe. COPY: the
 * small executed wrapper binary, which must not share an inode across
 * generations. SKIP: everything else, including anything rewritten in
 * place (archives, linked binaries, session stamps, locks). `rel` is
 * relative to the generation's build/ directory. */
static enum warm_seed_class warm_classify_rel(const char *rel, bool is_reg)
{
    if (!rel || !rel[0] || !is_reg || warm_path_hidden(rel))
        return WARM_SEED_SKIP;
    if (strcmp(rel, "bin/zcc") == 0)
        return WARM_SEED_COPY;
    if (warm_has_suffix(rel, ".o") || warm_has_suffix(rel, ".d"))
        return WARM_SEED_LINK;
    return WARM_SEED_SKIP;
}

static bool generation_gitlink_prepare(const struct proof_paths *paths,
                                       const char *generation,
                                       char *why, size_t why_len)
{
    char source[PATH_MAX], config[PATH_MAX + 32];
    if (snprintf(source, sizeof(source), "%s/vendor/tor", paths->root) >=
            (int)sizeof(source) ||
        snprintf(config, sizeof(config), "submodule.vendor/tor.url=%s",
                 source) >= (int)sizeof(config)) {
        proof_why(why, why_len, "proof_generation_gitlink_path_invalid");
        return false;
    }
    struct stat st;
    if (lstat(source, &st) != 0 || !S_ISDIR(st.st_mode)) {
        proof_why(why, why_len, "proof_generation_gitlink_source_unavailable");
        return false;
    }
    const char *argv[] = {
        "git", "-c", "protocol.file.allow=always", "-c", config,
        "submodule", "update", "--init", "--no-fetch", "--", "vendor/tor",
        NULL};
    char output[ZCL_DEVLOOP_OUTPUT_MAX];
    if (!git_capture(generation, argv, output, sizeof(output))) {
        proof_why(why, why_len, "proof_generation_gitlink_checkout_failed");
        return false;
    }
    return true;
}

#define PROOF_RAM_RESERVE_BYTES (6ull * 1024ull * 1024ull * 1024ull)

/* ZCL_PROOF_RAM_RESERVE_BYTES may only RAISE the reservation, never shrink
 * it. A crowded machine may refuse RAM backing outright; a spacious one may
 * promise more than the shipped default, but no host gets to pack proofs
 * tighter than the guard they were proved with. */
static uint64_t proof_ram_reserve_bytes(void)
{
    const char *text = getenv("ZCL_PROOF_RAM_RESERVE_BYTES");
    if (!text || !*text) return PROOF_RAM_RESERVE_BYTES;
    char *end = NULL;
    errno = 0;
    unsigned long long value = strtoull(text, &end, 10);
    if (errno || !end || *end || value == 0) return PROOF_RAM_RESERVE_BYTES;
    if (value < PROOF_RAM_RESERVE_BYTES) return PROOF_RAM_RESERVE_BYTES;
    return (uint64_t)value;
}


static bool warm_touch_one(const char *path, const struct timespec *stamp)
{
    /* Preserve atime; the timestamp graph only reads mtime. utimensat
     * follows the final component, but every caller stats first and only
     * ever names regular files, never symlinks. */
    const struct timespec times[2] = {
        {.tv_nsec = UTIME_OMIT},
        {.tv_sec = stamp->tv_sec, .tv_nsec = stamp->tv_nsec},
    };
    return path && stamp && utimensat(AT_FDCWD, path, times, 0) == 0;
}

static bool warm_timespec_after(const struct timespec *a,
                                const struct timespec *b)
{
    return a->tv_sec > b->tv_sec ||
           (a->tv_sec == b->tv_sec && a->tv_nsec > b->tv_nsec);
}

/* Byte copy through a temp file plus rename: the target is replaced, never
 * truncated in place, so a concurrent reader keeps coherent bytes. Mode
 * 0700, not 0600: this carries the compiler wrapper, and the bootstrap
 * declines a binary it cannot execute. Private directory already bars
 * group and other. */
static bool warm_copy_file(const char *source, const char *target)
{
    int input = open(source, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (input < 0) return false;
    struct stat st;
    char temporary[PATH_MAX];
    int temporary_len = snprintf(temporary, sizeof(temporary),
                                 "%s.tmp.XXXXXX", target);
    bool ok = fstat(input, &st) == 0 && S_ISREG(st.st_mode) &&
        temporary_len > 0 && temporary_len < (int)sizeof(temporary);
    int output = ok ? mkstemp(temporary) : -1;
    if (output < 0) ok = false;
    unsigned char buffer[65536];
    while (ok) {
        ssize_t got = read(input, buffer, sizeof(buffer));
        if (got < 0 && errno == EINTR) continue;
        if (got < 0) ok = false;
        if (got <= 0) break;
        ok = write_all(output, buffer, (size_t)got);
    }
    if (close(input) != 0) ok = false;
    if (output >= 0) {
        if (fchmod(output, 0700) != 0) ok = false;
        if (close(output) != 0) ok = false;
    }
    if (ok && rename(temporary, target) != 0) ok = false;
    if (!ok && output >= 0) (void)unlink(temporary);
    return ok;
}

struct warm_seed_accum {
    char **rels;
    size_t count;
    size_t capacity;
    uint64_t files;
    uint64_t bytes;
    bool failed;
};

static void warm_seed_accum_free(struct warm_seed_accum *accum)
{
    if (!accum) return;
    for (size_t i = 0; i < accum->count; i++) free(accum->rels[i]);
    free(accum->rels);
    memset(accum, 0, sizeof(*accum));
}

static bool warm_seed_remember(struct warm_seed_accum *accum, const char *rel)
{
    if (accum->failed || !rel) {
        accum->failed = true;
        return false;
    }
    if (accum->count == accum->capacity) {
        size_t next = accum->capacity ? accum->capacity * 2 : 256;
        char **rels =
            zcl_realloc(accum->rels, next * sizeof(*rels), "proof_warm_seed");
        if (!rels) {
            accum->failed = true;
            return false;
        }
        accum->rels = rels;
        accum->capacity = next;
    }
    size_t len = strlen(rel);
    char *copy = zcl_malloc(len + 1, "proof_warm_seed");
    if (!copy) {
        accum->failed = true;
        return false;
    }
    memcpy(copy, rel, len + 1);
    accum->rels[accum->count++] = copy;
    return true;
}

/* One regular donor file: link it (immutable output) or copy it (small
 * executed wrapper). macOS copies both classes so a writable generation
 * cannot mutate a donor through a shared inode. Before linking, unlink
 * the target so link() never follows
 * a stale symlink and never fails with EEXIST. Any single-file failure
 * skips that file and moves on: a missing seed only costs a recompile. */
static void warm_seed_file(const char *donor_file, const char *gen_file,
                           const char *rel, enum warm_seed_class class,
                           const struct stat *donor_st,
                           struct warm_seed_accum *accum)
{
    struct stat gen_st;
    bool gen_exists = lstat(gen_file, &gen_st) == 0;
    if (gen_exists && S_ISLNK(gen_st.st_mode)) {
        if (unlink(gen_file) != 0) return;
        gen_exists = false;
    }
    if (class == WARM_SEED_LINK) {
#if defined(__APPLE__)
        if (!dependency_copy_stat(donor_file, gen_file, donor_st)) return;
#else
        if (gen_exists && unlink(gen_file) != 0) return;
        if (link(donor_file, gen_file) != 0) return;
#endif
    } else if (class == WARM_SEED_COPY) {
        if (!warm_copy_file(donor_file, gen_file)) return;
    } else {
        return;
    }
    if (!warm_seed_remember(accum, rel)) {
        /* The file is seeded but untracked, so a later repair failure
         * could not roll it back; unlink it now instead of risking a
         * half-repaired tree. */
        (void)unlink(gen_file);
        return;
    }
    accum->files++;
    accum->bytes += (uint64_t)donor_st->st_size;
}

static void warm_seed_walk(const char *donor_dir, const char *gen_dir,
                           const char *rel_prefix, bool copy_wrapper,
                           struct warm_seed_accum *accum)
{
    /* The walk creates its own target directory chain: readdir order is
     * unspecified, so a file may precede its directory, and the caller
     * may hand down a root whose own parents do not exist yet (the seam
     * test seeds into a bare fixture). dependency_parent_ensure builds
     * the ancestors; the mkdir takes the directory itself. */
    struct stat gen_dir_st;
    if (!accum || accum->failed) return;
    if (lstat(gen_dir, &gen_dir_st) != 0) {
        char probe[PATH_MAX];
        if (errno != ENOENT ||
            snprintf(probe, sizeof(probe), "%s/_", gen_dir) >=
                (int)sizeof(probe) ||
            !dependency_parent_ensure(probe) ||
            (mkdir(gen_dir, 0700) != 0 && errno != EEXIST) ||
            lstat(gen_dir, &gen_dir_st) != 0) {
            accum->failed = true;
            return;
        }
    }
    if (!S_ISDIR(gen_dir_st.st_mode) || S_ISLNK(gen_dir_st.st_mode)) {
        accum->failed = true;
        return;
    }
    DIR *dir = opendir(donor_dir);
    if (!dir) return;
    for (struct dirent *entry = readdir(dir); entry;
         entry = readdir(dir)) {
        char rel[PATH_MAX], donor_child[PATH_MAX], gen_child[PATH_MAX];
        if (accum->failed) break;
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0)
            continue;
        int rel_len = rel_prefix && rel_prefix[0]
            ? snprintf(rel, sizeof(rel), "%s/%s", rel_prefix, entry->d_name)
            : snprintf(rel, sizeof(rel), "%s", entry->d_name);
        if (rel_len <= 0 || rel_len >= (int)sizeof(rel) ||
            snprintf(donor_child, sizeof(donor_child), "%s/%s", donor_dir,
                     entry->d_name) >= (int)sizeof(donor_child) ||
            snprintf(gen_child, sizeof(gen_child), "%s/%s", gen_dir,
                     entry->d_name) >= (int)sizeof(gen_child)) {
            accum->failed = true;
            break;
        }
        struct stat donor_st;
        if (lstat(donor_child, &donor_st) != 0) continue;
        if (S_ISLNK(donor_st.st_mode)) continue;
        if (S_ISDIR(donor_st.st_mode)) {
            /* Hidden directories (.leases, staging, admission) are live
             * machinery: do not recreate them, do not descend. */
            if (warm_path_hidden(rel)) continue;
            struct stat gen_st;
            if (lstat(gen_child, &gen_st) != 0) {
                if (errno != ENOENT || mkdir(gen_child, 0700) != 0)
                    continue;
            } else if (!S_ISDIR(gen_st.st_mode) ||
                       S_ISLNK(gen_st.st_mode)) {
                continue;
            }
            warm_seed_walk(donor_child, gen_child, rel, copy_wrapper,
                           accum);
            continue;
        }
        if (!S_ISREG(donor_st.st_mode)) continue;
        enum warm_seed_class class = warm_classify_rel(rel, true);
        if (class == WARM_SEED_SKIP) continue;
        /* The wrapper copy is caller-gated (bootstrap inputs must be
         * unchanged); link-class outputs need no gate beyond the epoch. */
        if (class == WARM_SEED_COPY && !copy_wrapper) continue;
        if (!dependency_parent_ensure(gen_child)) continue;
        warm_seed_file(donor_child, gen_child, rel, class, &donor_st,
                       accum);
    }
    (void)closedir(dir);
}

/* Undo a seed: unlink every tracked file. Best effort; a leftover seed
 * with untouched mtimes only costs a recompile, but a leftover seed after
 * a partial repair could mislead make, so the repair calls this before it
 * reports cold. */
static void warm_seed_rollback(const char *gen_build,
                               struct warm_seed_accum *accum)
{
    for (size_t i = 0; i < accum->count; i++) {
        char path[PATH_MAX];
        if (snprintf(path, sizeof(path), "%s/%s", gen_build,
                     accum->rels[i]) < (int)sizeof(path))
            (void)unlink(path);
    }
}

/* Is `s` the start of a 64-character lowercase hex digest? Stops at the
 * terminator, so a shorter tail is simply not one. */
static bool proof_epoch_digest(const char *s)
{
    for (size_t i = 0; i < 64; i++) {
        char c = s[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
            return false;
    }
    return true;
}

/* Hash one build-plan value with every trace of WHERE this checkout lives
 * taken out, so the same tree at two absolute paths hashes equal.
 *
 * Two rewrites, and a reason for each:
 *  - the checkout root becomes the constant the build already tells the
 *    compiler to record in its place (-ffile-prefix-map=$(CURDIR)=/zclassic23,
 *    Makefile REPRO_CFLAGS). Hashing the real path keyed the receipt on a
 *    string the compiler had itself erased.
 *  - the epoch segment of an object directory becomes a fixed token. The
 *    epoch is a cache-partition name derived from the compiler fingerprint
 *    and the flag text (Makefile zcl_compile_epoch), and that fingerprint
 *    hashes the CC command string, which spells the checkout out loud
 *    (tools/dev/build-epoch-key.sh). It is a digest, so no later rewrite can
 *    reach the path inside it -- and what it stood for is a receipt root in
 *    its own right now: the compiler by content in compiler_root, the flags
 *    in flags_root. */
static void proof_hash_plan_value(struct sha3_256_ctx *sha, const char *root,
                                  size_t root_len, const char *value)
{
    static const char epochs[] = "epochs/";
    static const char epoch_token[] = "<epoch>";
    for (const char *p = value; *p;) {
        if (strncmp(p, root, root_len) == 0) {
            sha3_256_write(sha, (const uint8_t *)PROOF_PLAN_VIRTUAL_ROOT,
                           sizeof(PROOF_PLAN_VIRTUAL_ROOT) - 1);
            p += root_len;
        } else if (strncmp(p, epochs, sizeof(epochs) - 1) == 0 &&
                   proof_epoch_digest(p + sizeof(epochs) - 1)) {
            sha3_256_write(sha, (const uint8_t *)epochs, sizeof(epochs) - 1);
            sha3_256_write(sha, (const uint8_t *)epoch_token,
                           sizeof(epoch_token) - 1);
            p += sizeof(epochs) - 1 + 64;
        } else {
            sha3_256_write(sha, (const uint8_t *)p, 1);
            p++;
        }
    }
    sha3_256_write(sha, (const uint8_t *)"", 1);
}

/* Which half of the build plan a key belongs to. A key this build has never
 * heard of goes to the build graph rather than nowhere: a line added to
 * build/dev-loop/restart.env tomorrow must change the identity, never slip
 * past it. */
static bool proof_plan_key_is_flag(const char *key)
{
    static const char *const flag_keys[] = {
        "CC", "DEV_CFLAGS", "DEV_LDFLAGS", "DEV_LIBS",
        "TEST_CFLAGS", "TEST_LDFLAGS", "TEST_LIBS",
    };
    for (size_t i = 0; i < sizeof(flag_keys) / sizeof(flag_keys[0]); i++)
        if (strcmp(key, flag_keys[i]) == 0)
            return true;
    return false;
}

/* The flag and build-graph roots, from one read of the build plan.
 *
 * COMPILER_ID is the one line dropped rather than hashed. It is a digest of
 * the CC command string, which contains this checkout's absolute path, so
 * nothing can neutralise it after the fact -- and the toolchain capsule now
 * says by content what COMPILER_ID said by name, including the header and
 * library redirections, which environment_root binds. Dropping it is the
 * whole reason two boxes can compare receipts at all. */
static bool proof_plan_roots(const char *root, uint8_t flags[32],
                             uint8_t build_graph[32])
{
    char path[PATH_MAX], body[PROOF_PLAN_MAX_BYTES];
    size_t root_len = root ? strlen(root) : 0;
    /* A root of "" or "/" would rewrite the head of every absolute path in
     * the plan, including the sysroot library paths. Refuse instead of
     * modelling it, exactly as zcc's prefix-map reader does. */
    if (!flags || !build_graph || root_len < 2u || root[0] != '/' ||
        snprintf(path, sizeof(path), "%s/build/dev-loop/restart.env", root) >=
            (int)sizeof(path))
        return false;
    FILE *f = fopen(path, "rb");
    if (!f) return false;
    size_t n = fread(body, 1, sizeof(body) - 1, f);
    bool ok = !ferror(f) && n > 0 && n < sizeof(body) - 1;
    fclose(f);
    if (!ok) return false;
    body[n] = 0;
    struct sha3_256_ctx flags_sha, graph_sha;
    hash_begin(&flags_sha, PROOF_FLAGS_DOMAIN);
    hash_begin(&graph_sha, PROOF_BUILD_GRAPH_DOMAIN);
    char *save = NULL;
    for (char *line = strtok_r(body, "\n", &save); line;
         line = strtok_r(NULL, "\n", &save)) {
        char *eq = strchr(line, '=');
        if (!eq) return false; /* a plan line that is not KEY=VALUE */
        *eq = 0;
        if (strcmp(line, "COMPILER_ID") == 0) continue;
        struct sha3_256_ctx *sha =
            proof_plan_key_is_flag(line) ? &flags_sha : &graph_sha;
        sha3_256_write(sha, (const uint8_t *)line, strlen(line) + 1);
        proof_hash_plan_value(sha, root, root_len, eq + 1);
    }
    sha3_256_finalize(&flags_sha, flags);
    sha3_256_finalize(&graph_sha, build_graph);
    return true;
}

/* The variables a receipt binds, and why each is here rather than in a flag:
 * every one changes what the resolved compiler is handed without appearing
 * in the plan's argv text -- header and library search redirection, the
 * driver's subprogram prefix, the SDK root, the build clock. CC/CXX/CFLAGS/
 * CPPFLAGS/LDFLAGS are here because they are the operator's stated intent;
 * their effect on the objects is already in flags_root, since Make bakes
 * them into the plan.
 *
 * PATH is deliberately absent, and its absence is the point. Hashing the
 * literal search path made two boxes with one toolchain disagree about a
 * variable that resolves nothing this build compiles with: the toolchain
 * capsule reads the driver at its absolute path
 * (platform/modules/platform/src/toolchain.c) and hashes the driver, the
 * backend, the assembler version, the sysroot and the ABI libraries by
 * content. A reordered PATH now moves no root; a different compiler binary
 * still moves compiler_root. Locale is absent for the same reason -- it
 * moves diagnostics, never produced bytes. */
static bool proof_environment_root(uint8_t out[32])
{
    static const char *const names[] = {
        "CC", "CXX", "CFLAGS", "CPPFLAGS", "LDFLAGS",
        "CPATH", "C_INCLUDE_PATH", "CPLUS_INCLUDE_PATH", "COMPILER_PATH",
        "LIBRARY_PATH", "GCC_EXEC_PREFIX", "SDKROOT", "SOURCE_DATE_EPOCH",
    };
    struct sha3_256_ctx sha;
    hash_begin(&sha, PROOF_ENV_DOMAIN);
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        const char *value = getenv(names[i]);
        /* Set-to-empty and unset are different facts; a bare value would
         * make them hash the same. */
        static const char set_tag[] = "set", unset_tag[] = "unset";
        const char *tag = value ? set_tag : unset_tag;
        sha3_256_write(&sha, (const uint8_t *)names[i], strlen(names[i]) + 1);
        sha3_256_write(&sha, (const uint8_t *)tag, strlen(tag) + 1);
        if (value)
            sha3_256_write(&sha, (const uint8_t *)value, strlen(value) + 1);
    }
    sha3_256_finalize(&sha, out);
    return true;
}

/* The one derivation of a proof's four toolchain roots. The receipt writes
 * them into compiler_root/flags_root/environment_root/build_graph_root, and
 * the warm-start build-complete marker seals the same four from the same
 * call -- so a donor whose build identity does not match this proof's own is
 * exactly as inadmissible as a receipt would be, and there is no second
 * derivation for the two to drift apart on. That matters because a compiler
 * upgrade, a changed CFLAGS, or a vendor archive rebuilt in place leaves no
 * source diff the wrapper-inputs check would catch.
 *
 * None of the four carries this checkout's location, so the same tree at two
 * absolute paths yields the same four values. That is what makes a receipt
 * mean anything on a second box. */
bool zcl_dev_proof_build_identity_v1_capture(
    const char *repo_root, struct zcl_dev_proof_build_identity_v1 *out)
{
    struct vcs_toolchain_capsule_v1 capsule;
    if (!repo_root || !out) return false;
    memset(out, 0, sizeof(*out));
    return vcs_toolchain_capsule_v1_capture(&capsule) &&
           vcs_toolchain_capsule_v1_root(&capsule, out->compiler) &&
           proof_plan_roots(repo_root, out->flags, out->build_graph) &&
           proof_environment_root(out->environment);
}

static bool proof_build_identity_equal(
    const struct zcl_dev_proof_build_identity_v1 *a,
    const struct zcl_dev_proof_build_identity_v1 *b)
{
    return a && b && memcmp(a->compiler, b->compiler, 32) == 0 &&
           memcmp(a->flags, b->flags, 32) == 0 &&
           memcmp(a->environment, b->environment, 32) == 0 &&
           memcmp(a->build_graph, b->build_graph, 32) == 0;
}

/* The build-complete marker is the donor gate: it says a full `make
 * build-only` finished in this generation for the marked commit under the
 * sealed `identity`. Written best effort after the compile dimension; a
 * missing marker only costs a cold build. */
static bool warm_marker_write_at(const char *generation, const char *root,
                                   const char *local, const char *base,
                                   int64_t completed,
                                   const struct zcl_dev_proof_build_identity_v1 *identity)
{
    char path[PATH_MAX], body[PATH_MAX + 512];
    char compiler_hex[65], flags_hex[65], environment_hex[65];
    char build_graph_hex[65];
    if (identity) {
        zcl_hex_encode(identity->compiler, 32, compiler_hex);
        zcl_hex_encode(identity->flags, 32, flags_hex);
        zcl_hex_encode(identity->environment, 32, environment_hex);
        zcl_hex_encode(identity->build_graph, 32, build_graph_hex);
    }
    int path_len = generation ? snprintf(path, sizeof(path), "%s/%s",
                                         generation, PROOF_WARM_MARKER_REL)
                              : -1;
    int body_len = path_len > 0 && root && local && base && completed > 0 &&
            identity
        ? snprintf(body, sizeof(body), "%s\nroot=%s\nlocal=%s\nbase=%s\n"
                   "completed=%lld\ncompiler=%s\nflags=%s\nenvironment=%s\n"
                   "build_graph=%s\n",
                   PROOF_WARM_MARKER_SCHEMA, root, local, base,
                   (long long)completed, compiler_hex, flags_hex,
                   environment_hex, build_graph_hex)
        : -1;
    return path_len > 0 && path_len < (int)sizeof(path) && body_len > 0 &&
           body_len < (int)sizeof(body) &&
           write_atomic(path, body, (size_t)body_len, 0600);
}

static bool warm_marker_write(const char *generation, const char *root,
                              const char *local, const char *base)
{
    struct zcl_dev_proof_build_identity_v1 identity;
    if (!zcl_dev_proof_build_identity_v1_capture(root, &identity))
        return false;
    return warm_marker_write_at(generation, root, local, base,
                                platform_time_wall_unix(), &identity);
}

static bool warm_marker_line(const char *line, const char *key,
                             char *out, size_t out_size)
{
    size_t key_len = strlen(key);
    if (!line || strncmp(line, key, key_len) != 0 || line[key_len] != '=')
        return false;
    const char *value = line + key_len + 1;
    size_t len = strlen(value);
    return len > 0 && len < out_size &&
           snprintf(out, out_size, "%s", value) > 0;
}

static bool warm_marker_read(const char *generation, char root[PATH_MAX],
                             char local[65], char base[65],
                             int64_t *completed_out,
                             struct zcl_dev_proof_build_identity_v1 *identity_out)
{
    char path[PATH_MAX], body[2048];
    if (!generation ||
        snprintf(path, sizeof(path), "%s/%s", generation,
                 PROOF_WARM_MARKER_REL) >= (int)sizeof(path))
        return false;
    FILE *f = fopen(path, "r");
    if (!f) return false;
    size_t n = fread(body, 1, sizeof(body) - 1, f);
    bool ok = !ferror(f);
    fclose(f);
    if (!ok || n == 0 || n == sizeof(body) - 1) return false;
    body[n] = 0;
    char *save = NULL, *line = strtok_r(body, "\n", &save);
    if (!line || strcmp(line, PROOF_WARM_MARKER_SCHEMA) != 0) return false;
    char completed_text[32] = {0};
    char got_root[PATH_MAX] = {0}, got_local[65] = {0}, got_base[65] = {0};
    char compiler_hex[65] = {0}, flags_hex[65] = {0}, build_graph_hex[65] = {0};
    char environment_hex[65] = {0};
    int fields = 0;
    while ((line = strtok_r(NULL, "\n", &save))) {
        if (warm_marker_line(line, "root", got_root, sizeof(got_root)) ||
            warm_marker_line(line, "local", got_local, sizeof(got_local)) ||
            warm_marker_line(line, "base", got_base, sizeof(got_base)) ||
            warm_marker_line(line, "completed", completed_text,
                             sizeof(completed_text)) ||
            warm_marker_line(line, "compiler", compiler_hex,
                             sizeof(compiler_hex)) ||
            warm_marker_line(line, "flags", flags_hex, sizeof(flags_hex)) ||
            warm_marker_line(line, "environment", environment_hex,
                             sizeof(environment_hex)) ||
            warm_marker_line(line, "build_graph", build_graph_hex,
                             sizeof(build_graph_hex)))
            fields++;
        else
            return false;
    }
    /* proof_oid_text rejects anything that is not a lowercase hex object
     * id; the root check below bars escapes. Any shortfall refuses -- a
     * marker from before the identity fields existed is exactly the
     * shortfall this rejects, so an old marker degrades to cold rather
     * than being adopted unverified. */
    struct zcl_dev_proof_build_identity_v1 identity;
    if (fields != 8 || !proof_oid_text(got_local) ||
        !proof_oid_text(got_base) ||
        !zcl_hex_decode_lower(compiler_hex, identity.compiler, 32) ||
        !zcl_hex_decode_lower(flags_hex, identity.flags, 32) ||
        !zcl_hex_decode_lower(environment_hex, identity.environment, 32) ||
        !zcl_hex_decode_lower(build_graph_hex, identity.build_graph, 32))
        return false;
    if (got_root[0] != '/' || strstr(got_root, "..") ||
        strchr(got_root, '\\'))
        return false;
    char *end = NULL;
    errno = 0;
    long long completed = strtoll(completed_text, &end, 10);
    if (errno != 0 || !end || *end != 0 || completed <= 0) return false;
    if (root) (void)snprintf(root, PATH_MAX, "%s", got_root);
    if (local) (void)snprintf(local, 65, "%s", got_local);
    if (base) (void)snprintf(base, 65, "%s", got_base);
    if (completed_out) *completed_out = (int64_t)completed;
    if (identity_out) *identity_out = identity;
    return true;
}

/* Same path hygiene as the proof's own changed-set capture: a diff line
 * must be a relative tracked path, never an escape. */
static bool warm_changed_path_ok(const char *line)
{
    size_t len = line ? strlen(line) : 0;
    return len > 0 && len < 256 && line[0] != '/' &&
           !strstr(line, "..") && !strchr(line, '\\');
}

/* Stamp one changed path: a regular file gets the source stamp, a
 * directory (a moved submodule pointer) stamps every regular file under
 * it, and anything else is skipped. Symlinks are never followed. */
static void warm_touch_changed(const char *generation, const char *rel,
                               const struct timespec *stamp, bool *ok)
{
    char path[PATH_MAX];
    struct stat st;
    if (!ok || !*ok || !warm_changed_path_ok(rel) ||
        snprintf(path, sizeof(path), "%s/%s", generation, rel) >=
            (int)sizeof(path) ||
        lstat(path, &st) != 0) {
        return;
    }
    if (S_ISREG(st.st_mode)) {
        if (!warm_touch_one(path, stamp)) *ok = false;
        return;
    }
    if (!S_ISDIR(st.st_mode) || S_ISLNK(st.st_mode)) return;
    /* Submodule pointer move: conservatively restamp the whole subtree so
     * no translation unit including those headers is missed. Over-broad
     * only costs recompiles, never a stale reuse. */
    char *stack[64];
    size_t depth = 0;
    char top[PATH_MAX];
    if (snprintf(top, sizeof(top), "%s", path) >= (int)sizeof(top)) {
        *ok = false;
        return;
    }
    stack[depth++] = top;
    while (depth > 0 && *ok) {
        char *dir_path = stack[--depth];
        DIR *dir = opendir(dir_path);
        if (!dir) {
            *ok = false;
            break;
        }
        for (struct dirent *entry = readdir(dir); entry && *ok;
             entry = readdir(dir)) {
            char child[PATH_MAX];
            struct stat child_st;
            if (strcmp(entry->d_name, ".") == 0 ||
                strcmp(entry->d_name, "..") == 0 ||
                snprintf(child, sizeof(child), "%s/%s", dir_path,
                         entry->d_name) >= (int)sizeof(child) ||
                lstat(child, &child_st) != 0)
                continue;
            if (S_ISLNK(child_st.st_mode)) continue;
            if (S_ISDIR(child_st.st_mode)) {
                if (depth < sizeof(stack) / sizeof(stack[0])) {
                    char *held =
                        zcl_malloc(strlen(child) + 1, "proof_warm_touch");
                    if (!held) {
                        *ok = false;
                        break;
                    }
                    (void)snprintf(held, strlen(child) + 1, "%s", child);
                    stack[depth++] = held;
                }
                continue;
            }
            if (S_ISREG(child_st.st_mode) && !warm_touch_one(child, stamp))
                *ok = false;
        }
        (void)closedir(dir);
        if (dir_path != top) free(dir_path);
    }
    while (depth > 0) free(stack[--depth]);
}

/* Donor survey record: the public seam type from dev_proof.h, so the
 * harness proves the pick policy against the exact struct production
 * surveys. The pick reads only the policy fields (completed, touched,
 * head_ok, live); path and local ride along for the caller. */

/* Newest completed, verifiable, idle generation wins; ties keep the
 * earlier candidate, which keeps repeated scans stable. */
static int warm_pick_donor(const struct zcl_dev_proof_warm_candidate
                               *candidates,
                           size_t count)
{
    int best = -1;
    for (size_t i = 0; i < count; i++) {
        if (!candidates || !candidates[i].head_ok || candidates[i].live)
            continue;
        if (best < 0 ||
            candidates[i].completed > candidates[best].completed ||
            (candidates[i].completed == candidates[best].completed &&
             candidates[i].touched > candidates[best].touched))
            best = (int)i;
    }
    return best;
}

static bool warm_generation_touched(const char *generation, int64_t *touched)
{
    struct stat st;
    if (!generation || lstat(generation, &st) != 0 ||
        !S_ISDIR(st.st_mode))
        return false;
    if (touched) *touched = (int64_t)st.st_mtime;
    return true;
}

/* A donor counts as in use while its proof lease or running lock is live.
 * The marker names the pair, so the checkout's own lease directory
 * answers exactly; anything lease-less falls back to the idle rule in the
 * caller. */
static bool warm_donor_live(const char *root, const char *local,
                            const char *base)
{
    char lease[PATH_MAX], lock[PATH_MAX];
    if (!root || !local || !base ||
        snprintf(lease, sizeof(lease),
                 "%s/.cache/zcl-dev-proof/leases/%s-%s.lease", root, local,
                 base) >= (int)sizeof(lease) ||
        snprintf(lock, sizeof(lock), "%s/.cache/zcl-dev-proof/%s-%s.running",
                 root, local, base) >= (int)sizeof(lock))
        return true;
    return proof_lease_running(lease, NULL, NULL) ||
           proof_running(lock, NULL, NULL);
}

/* Stamp every seeded output to the seed instant. Unchanged sources keep
 * their checkout mtime (older: reuse); changed sources are stamped later
 * by warm_retime_sources (newer: rebuild). */
/* Advance the wall clock past the seed stamp without inventing a
 * future time: spins a bounded number of reads until the clock moves.
 * Nanosecond clocks exit on the first read; a stuck clock refuses, which
 * the caller turns into a cold build. */
static bool warm_stamp_after(const struct timespec *seed_stamp,
                             struct timespec *source_stamp)
{
    if (!seed_stamp || !source_stamp) return false;
    for (int spins = 0; spins < 1000000; spins++) {
        if (platform_time_realtime_timespec(source_stamp) != 0)
            return false;
        if (warm_timespec_after(source_stamp, seed_stamp)) return true;
    }
    return warm_timespec_after(source_stamp, seed_stamp);
}

/* Stamp every seeded output to the seed instant. Unchanged sources keep
 * their checkout mtime (older: reuse); changed sources are stamped later
 * by warm_retime_sources (newer: rebuild). */
static bool warm_retime_outputs(const char *gen_build,
                                struct warm_seed_accum *accum,
                                struct timespec *seed_stamp)
{
    /* The platform wall clock is millisecond-granular; filesystem creation
     * timestamps can be finer. A stamp from the current tick could precede
     * a source just materialized in that tick. Wait for the next real tick
     * before stamping seeds, so unchanged sources remain strictly older. */
    struct timespec began;
    if (platform_time_realtime_timespec(&began) != 0 ||
        !warm_stamp_after(&began, seed_stamp))
        return false;
    for (size_t i = 0; i < accum->count; i++) {
        char path[PATH_MAX];
        if (snprintf(path, sizeof(path), "%s/%s", gen_build,
                     accum->rels[i]) >= (int)sizeof(path) ||
            !warm_touch_one(path, seed_stamp))
            return false;
    }
    return true;
}

/* Stamp the exact changed set strictly after the seeds. Spins the wall
 * clock forward rather than inventing a future time: both stamps stay at
 * or below the real now, so no later make ever sees a file from the
 * future. A changed path that is gone (deleted) or unstatable is skipped;
 * its absence already forces make to rebuild whatever named it. */
static bool warm_retime_sources(const char *generation,
                                const char *donor_local, const char *local,
                                const struct timespec *seed_stamp)
{
    const char *argv[] = {"git", "diff", "--name-only", "--no-renames",
                          donor_local, local, "--", NULL};
    char output[ZCL_DEVLOOP_OUTPUT_MAX];
    if (!generation || !donor_local || !local || !seed_stamp ||
        !git_capture(generation, argv, output, sizeof(output)))
        return false;
    struct timespec source_stamp = *seed_stamp;
    if (!warm_stamp_after(seed_stamp, &source_stamp)) return false;
    bool ok = true;
    char *save = NULL;
    for (char *line = strtok_r(output, "\n", &save); line && ok;
         line = strtok_r(NULL, "\n", &save)) {
        if (line[0] == 0) continue;
        warm_touch_changed(generation, line, &source_stamp, &ok);
    }
    return ok;
}

/* The seeded wrapper binary is trusted only when its build inputs are
 * byte-identical between the donor commit and the new commit. The epoch
 * key moves when the toolchain or flags move, which already strands
 * seeded objects; the wrapper has no epoch of its own, so this diff is
 * its freshness. The catalog and its reader script are inputs too: a
 * changed catalog could silently narrow the checked set. --quiet turns
 * the diff into a boolean; any failure (including "different") refuses. */
static bool warm_wrapper_inputs_unchanged(const char *root,
                                          const char *donor_local,
                                          const char *local)
{
    char catalog[PATH_MAX];
    if (!root || !donor_local || !local ||
        snprintf(catalog, sizeof(catalog), "%s/tools/dev/"
                 "zcc-bootstrap-inputs.list", root) >= (int)sizeof(catalog))
        return false;
    FILE *f = fopen(catalog, "r");
    if (!f) return false;
    const char *fixed[] = {
        "tools/dev/zcc-bootstrap-inputs.list",
        "tools/dev/zcc_bootstrap.sh",
    };
    size_t fixed_count = sizeof(fixed) / sizeof(fixed[0]);
    char inputs[12][128];
    size_t input_count = 0;
    char line[256];
    bool ok = true;
    while (fgets(line, sizeof(line), f)) {
        size_t len = strlen(line);
        while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r'))
            line[--len] = 0;
        if (len == 0 || strncmp(line, "license=", 8) == 0) continue;
        if (len >= sizeof(inputs[0])) {
            ok = false;
            break;
        }
        bool clean = true;
        for (size_t i = 0; i < len; i++) {
            char c = line[i];
            bool word = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                        (c >= '0' && c <= '9') || c == '_' || c == '.' ||
                        c == '/' || c == '-';
            if (!word) {
                clean = false;
                break;
            }
        }
        if (!clean || strstr(line, "..") || input_count >=
                sizeof(inputs) / sizeof(inputs[0])) {
            ok = false;
            break;
        }
        (void)snprintf(inputs[input_count], sizeof(inputs[0]), "%s", line);
        input_count++;
    }
    bool complete = !ferror(f);
    fclose(f);
    if (!ok || !complete || input_count == 0) return false;
    const char *argv[6 + 12 + 2 + 1];
    size_t argc = 0;
    argv[argc++] = "git";
    argv[argc++] = "diff";
    argv[argc++] = "--quiet";
    argv[argc++] = "--no-renames";
    argv[argc++] = donor_local;
    argv[argc++] = local;
    argv[argc++] = "--";
    for (size_t i = 0; i < fixed_count; i++) argv[argc++] = fixed[i];
    for (size_t i = 0; i < input_count; i++) argv[argc++] = inputs[i];
    argv[argc] = NULL;
    char ignored[8];
    return git_capture(root, argv, ignored, sizeof(ignored));
}

struct warm_donor {
    char path[PATH_MAX];
    char local[65];
    char base[65];
};

/* Newest verifiable idle generation for this root, skipping the caller's
 * own. Fills nothing and reports false when there is no donor: cold is
 * the ordinary path, not an error. */
static bool warm_donor_scan(const char *parent, const char *root,
                            const char *in_use, struct warm_donor *donor)
{
    /* No verifiable identity for THIS proof means no safe comparison for
     * any candidate: fail closed to cold rather than adopt objects this
     * scan cannot prove match. */
    struct zcl_dev_proof_build_identity_v1 current;
    if (!zcl_dev_proof_build_identity_v1_capture(root, &current))
        return false;
    DIR *dir = opendir(parent);
    if (!dir || !parent || !root || !in_use || !donor) {
        if (dir) (void)closedir(dir);
        return false;
    }
    struct zcl_dev_proof_warm_candidate *candidates = NULL;
    size_t count = 0, capacity = 0;
    for (struct dirent *entry = readdir(dir); entry;
         entry = readdir(dir)) {
        char candidate_path[PATH_MAX];
        if (!warm_tag_name(entry->d_name) ||
            snprintf(candidate_path, sizeof(candidate_path), "%s/%s",
                     parent, entry->d_name) >= (int)sizeof(candidate_path) ||
            strcmp(candidate_path, in_use) == 0)
            continue;
        char marker_root[PATH_MAX], marker_local[65], marker_base[65];
        int64_t completed = 0;
        struct zcl_dev_proof_build_identity_v1 candidate_identity;
        if (!warm_marker_read(candidate_path, marker_root, marker_local,
                              marker_base, &completed, &candidate_identity) ||
            strcmp(marker_root, root) != 0 ||
            !proof_build_identity_equal(&current, &candidate_identity))
            continue;
        char head[65];
        const char *head_argv[] = {"git", "-C", candidate_path, "rev-parse",
                                  "--verify", "HEAD", NULL};
        bool head_ok = git_capture(root, head_argv, head, sizeof(head)) &&
                       strcmp(head, marker_local) == 0;
        char obj[PATH_MAX];
        int64_t touched = 0;
        if (snprintf(obj, sizeof(obj), "%s/build/obj", candidate_path) >=
                (int)sizeof(obj) ||
            !warm_generation_touched(obj, NULL) ||
            !warm_generation_touched(candidate_path, &touched))
            continue;
        if (count == capacity) {
            size_t next = capacity ? capacity * 2 : 16;
            struct zcl_dev_proof_warm_candidate *grown = zcl_realloc(
                candidates, next * sizeof(*grown), "proof_warm_donor");
            if (!grown) {
                free(candidates);
                candidates = NULL;
                count = capacity = 0;
                break;
            }
            candidates = grown;
            capacity = next;
        }
        struct zcl_dev_proof_warm_candidate *slot = &candidates[count];
        memset(slot, 0, sizeof(*slot));
        (void)snprintf(slot->tag, sizeof(slot->tag), "%s", entry->d_name);
        (void)snprintf(slot->path, sizeof(slot->path), "%s",
                       candidate_path);
        (void)snprintf(slot->local, sizeof(slot->local), "%s",
                       marker_local);
        slot->completed = completed;
        slot->touched = touched;
        slot->head_ok = head_ok;
        /* A generation whose checkout moved since its build finished, or
         * whose proof is still leased, cannot donate: the first may hold
         * objects for another commit, the second is still writing. */
        slot->live = !head_ok ||
                     warm_donor_live(root, marker_local, marker_base);
        count++;
    }
    (void)closedir(dir);
    int best = warm_pick_donor(candidates, count);
    bool found = candidates && best >= 0;
    if (found) {
        /* Re-read the marker now the survey is done. A sibling lane can
         * finish a build in this generation while the scan runs; if the
         * marker or the identity it was sealed under moved, the surveyed
         * choice is stale and cold is safe. */
        char marker_root[PATH_MAX], marker_local[65], marker_base[65];
        int64_t completed = 0;
        struct zcl_dev_proof_build_identity_v1 recheck_identity;
        if (!warm_marker_read(candidates[best].path, marker_root,
                              marker_local, marker_base, &completed,
                              &recheck_identity) ||
            strcmp(marker_local, candidates[best].local) != 0 ||
            !proof_build_identity_equal(&current, &recheck_identity) ||
            snprintf(donor->path, sizeof(donor->path), "%s",
                     candidates[best].path) >= (int)sizeof(donor->path) ||
            snprintf(donor->local, sizeof(donor->local), "%s",
                     candidates[best].local) >= (int)sizeof(donor->local) ||
            snprintf(donor->base, sizeof(donor->base), "%s",
                     marker_base) >= (int)sizeof(donor->base))
            found = false;
    }
    free(candidates);
    return found;
}

/* Opt-out for honest cold-vs-warm measurement and for a pool under
 * suspicion. Advisory only: the variable is outside the sealed proof
 * environment allowlist, so it changes no proof input and warm and cold
 * receipts for the same pair stay comparable. */
static bool warm_start_disabled(void)
{
    const char *value = getenv("ZCL_DEV_PROOF_WARM");
    return value && (strcmp(value, "0") == 0 || strcmp(value, "off") == 0 ||
                     strcmp(value, "no") == 0);
}

/* Seed one generation's build tree from the donor and repair the
 * timestamp graph. Reports true only when the full repair completed; any
 * earlier failure rolls the seeds back and reports false (cold). */
static bool warm_start_generation(const struct proof_paths *paths,
                                  const char *parent,
                                  const char *generation, const char *local,
                                  struct proof_warmstart *warm)
{
    struct warm_donor donor;
    if (!paths || !parent || !generation || !local || !warm) return false;
    memset(&donor, 0, sizeof(donor));
    memset(warm, 0, sizeof(*warm));
    if (!warm_donor_scan(parent, paths->root, generation, &donor)) {
        (void)snprintf(warm->cold_reason, sizeof(warm->cold_reason), "%s",
                       "no_eligible_donor");
        return false;
    }
    char donor_build[PATH_MAX], gen_build[PATH_MAX];
    if (snprintf(donor_build, sizeof(donor_build), "%s/build", donor.path) >=
            (int)sizeof(donor_build) ||
        snprintf(gen_build, sizeof(gen_build), "%s/build", generation) >=
            (int)sizeof(gen_build)) {
        (void)snprintf(warm->cold_reason, sizeof(warm->cold_reason), "%s",
                       "seed_failed");
        return false;
    }
    struct warm_seed_accum accum = {0};
    /* Every build profile's epoch tree, not just build-only's: the test
     * phase's dev-proof-bundle compiles the full harness, and its
     * objects publish through the same staging-plus-rename publishers.
     * The classifier admits only object and depfile outputs plus the
     * wrapper copy; binaries, archives, stamps, leases, and locks stay
     * skipped, so the wider root adds reuse without adding risk. The
     * wrapper binary keeps make's prerequisite graph honest only when
     * its inputs are unchanged; otherwise the bootstrap rebuilds it and
     * its new mtime correctly invalidates every object. */
    bool copy_wrapper =
        warm_wrapper_inputs_unchanged(paths->root, donor.local, local);
    warm_seed_walk(donor_build, gen_build, "", copy_wrapper, &accum);
    struct timespec seed_stamp = {0};
    bool armed = !accum.failed && accum.files > 0 &&
                 warm_retime_outputs(gen_build, &accum, &seed_stamp) &&
                 warm_retime_sources(generation, donor.local, local,
                                     &seed_stamp);
    if (!armed) {
        (void)snprintf(warm->cold_reason, sizeof(warm->cold_reason), "%s",
                       "seed_failed");
        warm_seed_rollback(gen_build, &accum);
        warm_seed_accum_free(&accum);
        return false;
    }
    const char *tag = strrchr(donor.path, '/');
    tag = tag ? tag + 1 : donor.path;
    (void)snprintf(warm->donor, sizeof(warm->donor), "%s", tag);
    (void)snprintf(warm->donor_local, sizeof(warm->donor_local), "%s",
                   donor.local);
    warm->files_linked = accum.files;
    warm->bytes_linked = accum.bytes;
    warm->armed = true;
    warm_seed_accum_free(&accum);
    return true;
}

/* Only git's own answer counts a generation as disposable. Detached HEAD
 * proves nobody parked a branch here to work in, and an empty tracked
 * status proves no edit would be lost. Untracked files are excluded on
 * purpose: a generation is full of build output by construction, and that
 * output is both what makes the tree large and what nobody would miss. */
static bool warm_reapable(const char *generation)
{
    char head[256], status[4];
    const char *head_argv[] = {"git", "rev-parse", "--symbolic-full-name",
                               "HEAD", NULL};
    const char *status_argv[] = {"git", "status", "--porcelain=v1",
                                 "--untracked-files=no", NULL};
    if (!git_capture(generation, head_argv, head, sizeof(head)) ||
        strcmp(head, "HEAD") != 0)
        return false;
    /* A clean tree prints nothing. The shortest porcelain v1 line is
     * longer than this buffer, so a dirty tree overflows the capture
     * instead of fitting it: both spellings of "not clean" refuse, and a
     * git that cannot answer at all refuses too. */
    return git_capture(generation, status_argv, status, sizeof(status)) &&
           status[0] == 0;
}

struct warm_reap_entry {
    char tag[PROOF_WARM_TAG_LEN + 1];
    char path[PATH_MAX];
    char root[PATH_MAX];
    int64_t completed;
    int64_t touched;
    bool complete;
};

/* With warm start, old generations are valuable donors, so the reaper
 * keeps the newest complete generation per root and may reap the rest.
 * Hygiene, never correctness: this returns nothing and the caller ignores
 * it, because a pool that fails to shrink costs disk while a proof that
 * failed over a delete would cost every lane on this host its push.
 *
 * A donor being seeded from while it is reaped degrades gracefully: the
 * seed walk skips files that vanish, and hard links already created keep
 * their inodes after the donor names are unlinked. */
static void generation_pool_reap(const struct proof_paths *paths,
                                 const char *parent, const char *in_use)
{
    DIR *dir = opendir(parent);
    if (!dir || !paths || !parent || !in_use) {
        if (dir) (void)closedir(dir);
        return;
    }
    int64_t now = platform_time_wall_unix();
    struct warm_reap_entry *entries = NULL;
    size_t count = 0, capacity = 0;
    bool collect_ok = true;
    for (struct dirent *entry = readdir(dir); entry;
         entry = readdir(dir)) {
        char candidate[PATH_MAX];
        int64_t touched = 0;
        if (!warm_tag_name(entry->d_name) ||
            snprintf(candidate, sizeof(candidate), "%s/%s", parent,
                     entry->d_name) >= (int)sizeof(candidate) ||
            strcmp(candidate, in_use) == 0 ||
            !warm_generation_touched(candidate, &touched))
            continue;
        char marker_root[PATH_MAX] = {0}, marker_local[65] = {0};
        char marker_base[65] = {0};
        int64_t completed = 0;
        /* Cross-root generations stay in the pool under their own root's
         * newest-complete rule below; the grouping, not this read,
         * decides whose donor survives. */
        bool complete = warm_marker_read(candidate, marker_root,
                                         marker_local, marker_base,
                                         &completed, NULL);
        bool live;
        if (complete) {
            /* The lease lives under the marked root, which may be a
             * sibling checkout sharing this pool; the marker root is
             * validated absolute and escape-free on read. */
            live = warm_donor_live(marker_root, marker_local,
                                   marker_base) ||
                   now - touched <= PROOF_WARM_IDLE_ACTIVE_SECONDS;
        } else {
            live = now - touched <= PROOF_WARM_IDLE_UNMARKED_SECONDS;
        }
        if (live) continue;
        if (count == capacity) {
            size_t next = capacity ? capacity * 2 : 16;
            struct warm_reap_entry *grown = zcl_realloc(
                entries, next * sizeof(*grown), "proof_warm_reap");
            if (!grown) {
                free(entries);
                entries = NULL;
                count = capacity = 0;
                collect_ok = false;
                break;
            }
            entries = grown;
            capacity = next;
        }
        struct warm_reap_entry *slot = &entries[count++];
        memset(slot, 0, sizeof(*slot));
        (void)snprintf(slot->tag, sizeof(slot->tag), "%s", entry->d_name);
        (void)snprintf(slot->path, sizeof(slot->path), "%s", candidate);
        (void)snprintf(slot->root, sizeof(slot->root), "%s",
                       complete ? marker_root : "");
        slot->completed = completed;
        slot->touched = touched;
        slot->complete = complete;
    }
    (void)closedir(dir);
    size_t attempts = 0;
    for (size_t i = 0; collect_ok && entries && i < count &&
             attempts < PROOF_WARM_REAP_MAX;
         i++) {
        bool reap = false;
        if (!entries[i].complete) {
            reap = true;
        } else {
            /* Keep the newest complete generation per root: reap this
             * one when a same-root sibling wins the donor pick. The pick
             * is the tested policy; the reaper only groups by root. */
            struct zcl_dev_proof_warm_candidate *group = NULL;
            size_t group_count = 0, group_cap = 0;
            size_t self = 0;
            bool group_ok = true;
            for (size_t j = 0; j < count; j++) {
                if (!entries[j].complete ||
                    strcmp(entries[j].root, entries[i].root) != 0)
                    continue;
                if (group_count == group_cap) {
                    size_t next = group_cap ? group_cap * 2 : 8;
                    struct zcl_dev_proof_warm_candidate *grown =
                        zcl_realloc(group, next * sizeof(*grown),
                                    "proof_warm_reap");
                    if (!grown) {
                        group_ok = false;
                        break;
                    }
                    group = grown;
                    group_cap = next;
                }
                struct zcl_dev_proof_warm_candidate *slot =
                    &group[group_count];
                memset(slot, 0, sizeof(*slot));
                (void)snprintf(slot->tag, sizeof(slot->tag), "%s",
                               entries[j].tag);
                slot->completed = entries[j].completed;
                slot->touched = entries[j].touched;
                slot->head_ok = true;
                slot->live = false;
                if (j == i) self = group_count;
                group_count++;
            }
            if (group_ok && group_count > 0) {
                int best = warm_pick_donor(group, group_count);
                reap = best >= 0 && (size_t)best != self;
            }
            free(group);
        }
        if (!reap) continue;
        /* The cap counts candidates that reach git, not directory
         * entries: the queries plus the delete are the only expensive
         * part, and bounding them is what keeps a fast proof fast. */
        attempts++;
        if (!warm_reapable(entries[i].path)) continue;
        /* Re-read the stamp now the git queries are done. The pool is
         * shared by every checkout under this parent, so a sibling lane
         * can claim this generation while it is examined; if it did, it
         * moved the mtime out of range. */
        int64_t touched_again = 0;
        if (!warm_generation_touched(entries[i].path, &touched_again) ||
            touched_again != entries[i].touched)
            continue;
        /* --force is safe only because detached and clean were just
         * proven. What it overrides is git's refusal to delete a tree
         * that still holds untracked files, and a generation's untracked
         * files are its build scratch. */
        const char *argv[] = {"git", "worktree", "remove", "--force",
                              entries[i].path, NULL};
        char output[1024];
        (void)git_capture_within(paths->root, argv,
                                 PROOF_WARM_REMOVE_TIMEOUT_MS, output,
                                 sizeof(output));
    }
    free(entries);
}

/* Testable wrappers over the warm-start predicates. The ZCL_TESTING
 * harness proves the donor policy and the link/copy decision against
 * fixture trees — the refusals (unmarked generation, moved checkout,
 * live lease) and the publisher semantics (replace, never rewrite in
 * place) are the safety property, and neither is proven by reading it.
 * Guarded so the harness (ZCL_TESTING) and the dev binary
 * (ZCL_DEV_BUILD) compile the same seam; a release build sees none of
 * it. POSIX-only because the warm start itself lives in the POSIX arm
 * above. */
#if defined(ZCL_DEV_BUILD) || defined(ZCL_TESTING)
bool zcl_dev_proof_warm_tag(const char *name)
{
    return warm_tag_name(name);
}

bool zcl_dev_proof_warm_disabled(void)
{
    return warm_start_disabled();
}

enum zcl_dev_proof_warm_seed_class zcl_dev_proof_warm_classify(
    const char *rel, bool is_reg)
{
    switch (warm_classify_rel(rel, is_reg)) {
    case WARM_SEED_LINK: return ZCL_DEV_PROOF_WARM_LINK;
    case WARM_SEED_COPY: return ZCL_DEV_PROOF_WARM_COPY;
    default: break;
    }
    return ZCL_DEV_PROOF_WARM_SKIP;
}

int zcl_dev_proof_warm_pick(const struct zcl_dev_proof_warm_candidate *c,
                            size_t n)
{
    return warm_pick_donor(c, n);
}

bool zcl_dev_proof_warm_marker_write(
    const char *generation, const char *root, const char *local,
    const char *base, int64_t completed,
    const struct zcl_dev_proof_build_identity_v1 *identity)
{
    return warm_marker_write_at(generation, root, local, base, completed,
                                identity);
}

bool zcl_dev_proof_warm_marker_read(
    const char *generation, char root[PATH_MAX], char local[65],
    char base[65], int64_t *completed,
    struct zcl_dev_proof_build_identity_v1 *identity)
{
    return warm_marker_read(generation, root, local, base, completed,
                            identity);
}

bool zcl_dev_proof_warm_seed_and_retime(const char *donor_build,
                                        const char *gen_build,
                                        const char *gen_src,
                                        const char *const *changed,
                                        size_t nchanged,
                                        struct zcl_dev_proof_warm_stats *stats)
{
    if (!donor_build || !gen_build || !gen_src || !stats) return false;
    memset(stats, 0, sizeof(*stats));
    struct warm_seed_accum accum = {0};
    /* Unconditional wrapper copy at seam level; production gates it on
     * the bootstrap-inputs diff. */
    warm_seed_walk(donor_build, gen_build, "", true, &accum);
    struct timespec seed_stamp = {0}, source_stamp = {0};
    bool ok = !accum.failed && accum.files > 0 &&
              warm_retime_outputs(gen_build, &accum, &seed_stamp) &&
              warm_stamp_after(&seed_stamp, &source_stamp);
    for (size_t i = 0; ok && changed && i < nchanged; i++) {
        if (!changed[i]) {
            ok = false;
            break;
        }
        warm_touch_changed(gen_src, changed[i], &source_stamp, &ok);
    }
    if (ok) {
        stats->files_linked = accum.files;
        stats->bytes_linked = accum.bytes;
    } else {
        warm_seed_rollback(gen_build, &accum);
    }
    warm_seed_accum_free(&accum);
    return ok;
}
#endif /* ZCL_DEV_BUILD || ZCL_TESTING */


static bool generation_prepare(const struct proof_paths *paths,
                               const char *local,
                               struct platform_ram_scratch_lease *ram_lease,
                               struct proof_warmstart *warm,
                               char generation[PATH_MAX],
                               char *why, size_t why_len)
{
    char root_parent[PATH_MAX], parent[PATH_MAX], generation_tag[33];
    uint8_t generation_hash[ZCL_DEV_PROOF_ROOT_BYTES];
    if (snprintf(root_parent, sizeof(root_parent), "%s", paths->root) >=
        (int)sizeof(root_parent)) {
        proof_why(why, why_len, "proof_generation_path_invalid");
        return false;
    }
    char *slash = strrchr(root_parent, '/');
    if (!slash || slash == root_parent) {
        proof_why(why, why_len, "proof_generation_path_invalid");
        return false;
    }
    *slash = 0;
    struct sha3_256_ctx generation_identity;
    hash_begin(&generation_identity, "zcl.dev_proof_generation_root.v2");
    sha3_256_write(&generation_identity, (const uint8_t *)paths->root,
                   strlen(paths->root) + 1);
    sha3_256_write(&generation_identity, (const uint8_t *)local,
                   strlen(local) + 1);
    sha3_256_finalize(&generation_identity, generation_hash);
    zcl_hex_encode(generation_hash, 16, generation_tag);
    /* Build and test work here is dominated by fsync, and on a RAM-backed
     * filesystem fsync costs nothing. When the machine offers one with room to
     * spare the whole generation — checkout, build tree and test scratch —
     * lives there; otherwise it stays exactly where it was. The choice is
     * written to phases.txt so a slow proof can be read against where it ran.
     * It is deliberately NOT sealed into the receipt: two proofs of the same
     * source must admit each other whatever storage they happened to use. */
    char ram_root[PATH_MAX];
    bool ram_backed = platform_ram_scratch_root(ram_root, sizeof(ram_root), 0);
    /* Free space seen is not free space kept: N proofs asking at once each
     * saw the same headroom and together filled the tmpfs. A reservation
     * held for the life of the generation is what makes this one's yes true
     * for this one alone. Refusal is not an error — the generation falls
     * back to disk exactly as if no RAM root had been offered. */
    bool ram_reserve_refused = false;
    if (ram_backed &&
        !platform_ram_scratch_reserve(ram_root, proof_ram_reserve_bytes(),
                                      ram_lease)) {
        ram_backed = false;
        ram_reserve_refused = true;
    }
    int parent_len = ram_backed
        ? snprintf(parent, sizeof(parent), "%s/z23p", ram_root)
        : snprintf(parent, sizeof(parent), "%s/.z23p", root_parent);
    if (parent_len <= 0 || (size_t)parent_len >= sizeof(parent) ||
        snprintf(generation, PATH_MAX, "%s/%s", parent, generation_tag) >=
            PATH_MAX ||
        !platform_private_directory_ensure(parent)) {
        proof_why(why, why_len, "proof_generation_path_invalid");
        return false;
    }
    if (paths->phases[0]) {
        (void)zcl_dev_proof_phase_note(
            paths->phases, "generation_storage",
            ram_backed ? "ram"
                       : ram_reserve_refused
                             ? "disk reason=ram_reserve_refused"
                             : "disk");
        (void)zcl_dev_proof_phase_note(paths->phases, "generation_root",
                                       generation);
    }
    struct stat st;
    if (lstat(generation, &st) != 0) {
        if (errno != ENOENT) {
            proof_why(why, why_len, "proof_generation_inspection_failed");
            return false;
        }
        /* A RAM-backed generation does not survive a reboot, and git still
         * holds its registration. Drop registrations whose directory is gone
         * before adding, or the add fails on a name the tmpfs already lost. */
        const char *prune_argv[] = {"git", "worktree", "prune", NULL};
        char pruned[ZCL_DEVLOOP_OUTPUT_MAX];
        (void)git_capture(paths->root, prune_argv, pruned, sizeof(pruned));
        const char *argv[] = {"git", "worktree", "add", "--detach",
                              generation, local, NULL};
        char output[ZCL_DEVLOOP_OUTPUT_MAX];
        if (!git_capture(paths->root, argv, output, sizeof(output))) {
            proof_why(why, why_len, "proof_generation_checkout_failed");
            return false;
        }
    }
    if (!generation_gitlink_prepare(paths, generation, why, why_len))
        return false;
    /* Preserve the complete ignored compiler-input sets that source identity
     * seals. Copying a fixed archive/header subset lets a host-specific input
     * (for example libsecp256k1-darwin.a) appear during `make build-only`,
     * superseding an otherwise exact isolated proof generation. Provenance
     * stamps travel with vendor/lib so already verified inputs are not
     * needlessly rebuilt after the source checkpoint. */
    static const char *const dependencies[] = {
        "vendor/lib", "vendor/include",
        "vendor/tor/libtor.a",
        "vendor/tor/src/ext/ed25519/donna/libed25519_donna.a",
        "vendor/tor/src/ext/ed25519/ref10/libed25519_ref10.a",
        "vendor/tor/src/ext/keccak-tiny/libkeccak-tiny.a",
        "build/githooks",
#if defined(__linux__)
        /* Order-only test-binary prerequisites that no admitted executable
         * links against: the rollback group dlopens these fixture images by
         * name on Linux. Other hosts report fixture_required=false, matching
         * the Makefile's Linux-only prerequisites. */
        "build/hotswap/zcl_rollback_fixture_a.so",
        "build/hotswap/zcl_rollback_fixture_b.so",
#endif
    };
    char build_dir[PATH_MAX], bin_dir[PATH_MAX];
    if (snprintf(build_dir, sizeof(build_dir), "%s/build", generation) >=
            (int)sizeof(build_dir) ||
        snprintf(bin_dir, sizeof(bin_dir), "%s/build/bin", generation) >=
            (int)sizeof(bin_dir) ||
        !platform_private_directory_ensure(build_dir) ||
        !platform_private_directory_ensure(bin_dir)) {
        /* Distinct from the dependency loop below: nothing is missing from
         * the checkout here, the generation's own build tree could not be
         * created. Conflating the two sent a reader hunting a vendored
         * archive that was present all along. */
        proof_whyf(why, why_len, "proof_generation_build_dir_unwritable:%s",
                   build_dir);
        return false;
    }
    for (size_t i = 0; i < sizeof(dependencies) / sizeof(dependencies[0]); i++) {
        char source[PATH_MAX], target[PATH_MAX];
        if (snprintf(source, sizeof(source), "%s/%s", paths->root,
                     dependencies[i]) >= (int)sizeof(source) ||
            snprintf(target, sizeof(target), "%s/%s", generation,
                     dependencies[i]) >= (int)sizeof(target)) {
            proof_whyf(why, why_len,
                       "proof_generation_dependency_path_too_long:%s",
                       dependencies[i]);
            return false;
        }
        struct stat source_st;
        if (lstat(source, &source_st) != 0) {
            /* vendor/ entries come from the vendored-archive build; the
             * installed hooks come from arming the clone; the hotswap
             * fixture images come from any test-binary build. Naming the
             * target turns a class into one command the reader can run. */
            const char *fix = strncmp(dependencies[i], "vendor/", 7) == 0
                                  ? "make vendor"
                                  : strncmp(dependencies[i], "build/hotswap/",
                                            14) == 0
                                        ? "make test_parallel"
                                        : "make install-hooks";
            proof_whyf(why, why_len,
                       "proof_generation_dependency_unavailable:%s (%s)",
                       dependencies[i], fix);
            return false;
        }
        /* The source is right there. Telling the reader to rebuild it sent
         * ten proof attempts hunting a vendored archive that was present all
         * along; say what actually failed and why. */
        errno = 0;
        if (!dependency_parent_ensure(target) ||
            !dependency_materialize(source, target)) {
            proof_whyf(why, why_len,
                       "proof_generation_dependency_copy_failed:%s (%s)",
                       dependencies[i], proof_errno_name(errno));
            return false;
        }
    }
    if (!worktree_exact(generation, local, false, why, why_len)) {
        proof_why(why, why_len, "proof_generation_not_exact");
        return false;
    }
    /* Stamp the generation as taken before the slow preparation below.
     * The .z23p pool is shared by every checkout under this parent, so a
     * sibling lane's reaper may look at this directory at any moment;
     * this stamp, not a lock, is what tells it the generation is a
     * working set rather than abandoned scratch. Reusing a generation
     * touches only files deep inside it, so without this the directory's
     * own mtime would keep aging as if idle. Failure is ignored: a missed
     * stamp costs at worst one premature reap and one recheckout, and
     * nothing in the reaping path may fail a proof. */
    const struct timespec taken[2] = {
        {.tv_nsec = UTIME_OMIT},
        {.tv_nsec = UTIME_NOW},
    };
    (void)utimensat(AT_FDCWD, generation, taken, AT_SYMLINK_NOFOLLOW);
    /* Warm start is advisory: it fills `warm` for the receipt sidecar and
     * never fails the prepare. Any refusal inside degrades to the cold
     * build the proof has always run. ZCL_DEV_PROOF_WARM=0 forces that
     * cold path for measurement. */
    if (warm) {
        if (warm_start_disabled()) {
            (void)snprintf(warm->cold_reason, sizeof(warm->cold_reason), "%s",
                           "disabled");
        } else {
            memset(warm, 0, sizeof(*warm));
            (void)warm_start_generation(paths, parent, generation, local,
                                        warm);
        }
    }
    /* Last, so it can only ever run against a generation that is stamped
     * and therefore cannot be the thing reclaimed, and so it sits after
     * every statement that can set `why`. Placed here it has no reachable
     * way to change what this function returns or reports. */
    generation_pool_reap(paths, parent, generation);
    return true;
}

/* Every proof step runs under a budget it earned, watched by its own log.
 * `step` names the row written to phases.txt and the key its wall time is
 * remembered under, so the next proof on this checkout plans from what this
 * one actually took. */
static int run_step(const struct proof_paths *paths, const char *root,
                    const char *log_path, const char *const argv[],
                    const char *step,
                    const struct zcl_dev_proof_budget *budget,
                    struct zcl_dev_proof_step_report *report)
{
    struct zcl_dev_proof_step_report local = {0};
    if (!report) report = &local;
    int rc = zcl_dev_proof_run_watched(root, log_path, argv, budget, report);
    if (paths && paths->phases[0])
        (void)zcl_dev_proof_phase_record(paths->phases, step, report);
    char key[PROOF_TIMING_KEY_MAX];
    if (rc == 0 && paths && step &&
        snprintf(key, sizeof(key), "step.%s", step) < (int)sizeof(key))
        (void)zcl_dev_proof_timing_note(paths->state, key, report->elapsed_ms);
    return rc;
}

/* Say why a step was killed in the same sentence that says it was killed, so
 * `z23 dev proof status` can explain the verdict without a log dive. */
static void run_step_why(char *why, size_t why_len, const char *step,
                         const struct zcl_dev_proof_step_report *report)
{
    if (!why || !why_len || !report) return;
    if (report->cause == ZCL_DEV_PROOF_KILL_NONE) {
        (void)snprintf(why, why_len, "child_proof_failed_exit_%d", report->rc);
        return;
    }
    (void)snprintf(why, why_len,
                   "child_proof_%s_%s_budget_ms_%lld_elapsed_ms_%lld_idle_ms_%lld",
                   zcl_dev_proof_kill_cause_name(report->cause), step,
                   (long long)report->budget_ms,
                   (long long)report->elapsed_ms,
                   (long long)report->last_progress_age_ms);
}

/* A step's budget is what this checkout has measured it needing, and the
 * compiled-in figure only until it has. */
static struct zcl_dev_proof_budget proof_step_budget(
    const struct proof_paths *paths, const char *step, int64_t fallback_ms)
{
    char key[PROOF_TIMING_KEY_MAX];
    if (!paths || !step ||
        snprintf(key, sizeof(key), "step.%s", step) >= (int)sizeof(key))
        return zcl_dev_proof_budget_make(fallback_ms, PROOF_STEP_FLOOR_MS);
    return zcl_dev_proof_step_budget(paths->state, key, fallback_ms);
}

#define PROOF_GENERATED_DEFAULT_MS 300000
#define PROOF_COMPILE_DEFAULT_MS 900000
#define PROOF_LINT_DEFAULT_MS 600000
#define PROOF_BUNDLE_DEFAULT_MS 1800000
#define PROOF_HELPERS_DEFAULT_MS 120000

static bool inventory_output_only(const char *const *files, size_t count)
{
    return count == 1 &&
           strcmp(files[0], "docs/CAPABILITY_INVENTORY.jsonl") == 0;
}

/* Record the test-selection shape beside the dimension logs. "universal" is
 * the whole catalog, chosen because the plan's closure was capacity-bounded;
 * "exact" is the enumerated plan. */
static bool proof_note_test_selection(const struct proof_paths *paths,
                                      bool universal, uint32_t selected)
{
    char path[PATH_MAX];
    if (snprintf(path, sizeof(path), "%s/%s.test-selection.log", paths->logs,
                 paths->key) >= (int)sizeof(path))
        return false;
    FILE *f = fopen(path, "w");
    if (!f) return false;
    (void)fprintf(f, "test_selection=%s reason=%s groups_selected=%u\n",
                  universal ? "universal" : "exact",
                  universal ? "closure-universal" : "impact-plan",
                  (unsigned)selected);
    return fclose(f) == 0;
}

static bool build_test_selector(const struct zcl_devloop_plan *plan,
                                bool inventory_only, char *out,
                                size_t out_size, uint32_t *count_out)
{
    if (!plan || !out || out_size == 0 || !count_out) return false;
    if (inventory_only) {
        (void)snprintf(out, out_size, "%s", "code_inventory");
        *count_out = 1;
        return true;
    }
    size_t pos = 0;
    uint32_t count = 0;
    /* A capacity-bounded plan reaches more groups than it can enumerate. The
     * plan already turned that into the universal closure, so the proof runs
     * the whole catalog: a large run is the honest price of a change whose
     * blast radius does not fit in a list. */
    if (plan->closure_universal) {
        for (size_t i = 0; i < zcl_test_group_catalog_count(); i++) {
            const char *full = zcl_test_group_catalog_at(i);
            int n = snprintf(out + pos, out_size - pos, "%s%s",
                             pos ? "," : "", full);
            if (n <= 0 || (size_t)n >= out_size - pos) return false;
            pos += (size_t)n;
            count++;
        }
        if (count == 0) return false;
        *count_out = count;
        return true;
    }
    for (int set = 0; set < 2; set++) {
        size_t len = set == 0 ? plan->path_groups_len : plan->closure_groups_len;
        for (size_t i = 0; i < len; i++) {
            const char *group = set == 0 ? plan->path_groups[i]
                                         : plan->closure_groups[i];
            char full[128];
            if (!zcl_test_group_resolve_exact(group, full)) return false;
            bool duplicate = false;
            const char *scan = out;
            size_t full_len = strlen(full);
            while (*scan) {
                const char *end = strchr(scan, ',');
                size_t item_len = end ? (size_t)(end - scan) : strlen(scan);
                if (item_len == full_len && memcmp(scan, full, full_len) == 0)
                    duplicate = true;
                if (!end) break;
                scan = end + 1;
            }
            if (duplicate) continue;
            int n = snprintf(out + pos, out_size - pos, "%s%s",
                             pos ? "," : "", full);
            if (n <= 0 || (size_t)n >= out_size - pos) return false;
            pos += (size_t)n;
            count++;
        }
    }
    *count_out = count;
    return true;
}

#if defined(ZCL_TESTING)
bool zcl_dev_proof_test_build_test_selector(
    const struct zcl_devloop_plan *plan, bool inventory_only,
    char *out, size_t out_size, uint32_t *count_out)
{
    return build_test_selector(plan, inventory_only, out, out_size, count_out);
}
#endif

static bool parse_uint_field(const char *line, const char *key, uint32_t *out)
{
    const char *p = strstr(line, key);
    if (!p) return false;
    p += strlen(key);
    char *end = NULL;
    errno = 0;
    unsigned long value = strtoul(p, &end, 10);
    if (errno || end == p || value > UINT32_MAX) return false;
    *out = (uint32_t)value;
    return true;
}

static bool test_log_account(const char *path,
                             struct zcl_dev_proof_dimension *dim)
{
    FILE *f = fopen(path, "r");
    if (!f) return false;
    char line[4096], verdict[4096] = {0};
    uint32_t verdict_count = 0;
    bool truncated = false;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "SUITE VERDICT ", 14) == 0) {
            verdict_count++;
            if (!strchr(line, '\n'))
                truncated = true;
            (void)snprintf(verdict, sizeof(verdict), "%s", line);
        }
    }
    bool ok = !ferror(f) && !truncated && verdict_count == 1;
    fclose(f);
    uint32_t total = 0, ran = 0, reused = 0, gated = 0;
    uint32_t failed = 0, skipped = 0, unobserved = 0;
    if (!ok || !verdict[0] ||
        !parse_uint_field(verdict, "groups_total=", &total) ||
        !parse_uint_field(verdict, "groups_ran=", &ran) ||
        !parse_uint_field(verdict, "groups_cached=", &reused) ||
        !parse_uint_field(verdict, "groups_gated=", &gated) ||
        !parse_uint_field(verdict, "groups_failed=", &failed) ||
        !parse_uint_field(verdict, "self_skips=", &skipped) ||
        !parse_uint_field(verdict, "env_unobserved=", &unobserved))
        return false;
    dim->ran = ran;
    dim->reused = reused;
    dim->failed = failed;
    dim->skipped = skipped;
    return (uint64_t)total == (uint64_t)ran + reused + gated &&
           (uint64_t)ran + reused == dim->selected && failed == 0 &&
           skipped == 0 && unobserved == 0;
}

/* One dimension in flight. Dimensions that do not feed each other are started
 * together and finished together; each keeps its own log, budget, receipt root
 * and accounting exactly as when they ran one after another. */
struct proof_dimension_run {
    enum zcl_dev_proof_dimension_id id;
    const char *name;
    struct zcl_dev_proof_dimension *dim;
    bool parse_test;
    char log[PATH_MAX];
    struct zcl_dev_proof_step step;
};

static bool dimension_start(const struct proof_paths *paths,
                            const char *root,
                            struct proof_dimension_run *run,
                            enum zcl_dev_proof_dimension_id id,
                            const char *const argv[],
                            struct zcl_dev_proof_dimension *dim,
                            bool parse_test,
                            const struct zcl_dev_proof_budget *budget,
                            char *why, size_t why_len)
{
    memset(run, 0, sizeof(*run));
    run->id = id;
    run->name = zcl_dev_proof_dimension_name(id);
    run->dim = dim;
    run->parse_test = parse_test;
    if (snprintf(run->log, sizeof(run->log), "%s/%s.%s.log", paths->logs,
                 paths->key, run->name) >= (int)sizeof(run->log)) {
        proof_why(why, why_len, "child_log_path_invalid");
        return false;
    }
    if (!zcl_dev_proof_step_start(&run->step, root, run->log, argv, budget)) {
        proof_whyf(why, why_len, "child_proof_%s_could_not_start", run->name);
        return false;
    }
    return true;
}

static bool dimension_finish(const struct proof_paths *paths,
                             struct proof_dimension_run *run,
                             char *why, size_t why_len)
{
    const struct zcl_dev_proof_step_report *report = &run->step.report;
    if (paths->phases[0])
        (void)zcl_dev_proof_phase_record(paths->phases, run->name, report);
    char key[PROOF_TIMING_KEY_MAX];
    if (report->rc == 0 &&
        snprintf(key, sizeof(key), "step.%s", run->name) < (int)sizeof(key))
        (void)zcl_dev_proof_timing_note(paths->state, key, report->elapsed_ms);
    if (!hash_file(run->name, run->log, run->dim->receipt_root)) {
        proof_why(why, why_len, "child_receipt_hash_failed");
        return false;
    }
    if (report->rc != 0) {
        run->dim->failed = 1;
        run_step_why(why, why_len, run->name, report);
        return false;
    }
    if (run->parse_test) {
        /* Fold this run's per-group wall times back into the table before
         * accounting, so the next proof plans from what just happened even
         * when the accounting then refuses the run. */
        (void)zcl_dev_proof_timing_ingest_test_log(paths->state, run->log);
        if (!test_log_account(run->log, run->dim)) {
            proof_why(why, why_len, "test_accounting_incomplete");
            return false;
        }
    } else {
        run->dim->ran = run->dim->selected;
    }
    return true;
}

/* Wait for every dimension in flight. Each keeps its own watch, so a
 * concurrent set is killed by exactly the rules a lone step would have met. */
static void dimension_runs_wait(struct proof_dimension_run *runs, size_t count)
{
    for (;;) {
        bool pending = false;
        for (size_t i = 0; i < count; i++) {
            if (!runs[i].step.started || runs[i].step.finished) continue;
            if (!zcl_dev_proof_step_poll(&runs[i].step)) pending = true;
        }
        if (!pending) break;
        platform_sleep_ms(20);
    }
}

static bool run_dimension(const struct proof_paths *paths,
                          enum zcl_dev_proof_dimension_id id,
                          const char *const argv[],
                          struct zcl_dev_proof_dimension *dim,
                          bool parse_test,
                          const struct zcl_dev_proof_budget *budget,
                          char *why, size_t why_len)
{
    struct proof_dimension_run run;
    if (!dimension_start(paths, paths->root, &run, id, argv, dim, parse_test,
                         budget, why, why_len))
        return false;
    (void)zcl_dev_proof_steps_wait(&run.step, 1);
    return dimension_finish(paths, &run, why, why_len);
}

static void unused_dimension(enum zcl_dev_proof_dimension_id id,
                             struct zcl_dev_proof_dimension *dim)
{
    hash_text(zcl_dev_proof_dimension_name(id), "not_selected", 12,
              dim->receipt_root);
}

static bool cycle_proof_reuse(
    const struct proof_paths *paths, const char *source_cas,
    struct zcl_dev_proof_dimension dimensions[ZCL_DEV_PROOF_DIMENSIONS])
{
    char body[16384], why[160] = {0};
    size_t body_len = 0;
    enum zcl_devloop_state_lookup lookup = zcl_devloop_cycle_state_read(
        paths->root, body, sizeof(body), &body_len, NULL, why, sizeof(why));
    if (lookup != ZCL_DEVLOOP_STATE_FOUND) return false;
    /* Legacy cycle records bind source bytes but not the full proof action
     * inputs or dimension-specific child roots. Until the producer and
     * consumer independently derive all of them, a cycle is a safe cache miss
     * rather than authority for child receipts. */
    if (!zcl_dev_proof_cycle_reuse_admissible(
            body, body_len, source_cas, NULL, dimensions))
        return false;
    for (size_t i = 0; i < ZCL_DEV_PROOF_DIMENSIONS; i++) {
        if (dimensions[i].selected) {
            dimensions[i].reused = dimensions[i].selected;
        } else {
            unused_dimension((enum zcl_dev_proof_dimension_id)i,
                             &dimensions[i]);
        }
    }
    return true;
}

/* The test dimension's runner is exec'd with execvp(), which reuses this
 * process's own `environ` -- there is no separate envp built per child, so
 * whatever this process last set is exactly what every forked test child
 * inherits. A resident proof daemon forks many cycles from one long-lived
 * process and keeps the environment it started with; roughly sixteen
 * registered groups carry `if (!getenv("ZCL_STRESS_TESTS")) { SKIP(...) }`
 * (tests/harness/src/test_kill9_recovery.c and friends), and testcache.c
 * keys a cached verdict on that variable being present. Without this call
 * the daemon's first environment silently outlives the setting: those
 * groups self-skip and testcache happily caches the SKIP as a PASS, so a
 * push proof admits a commit having never run its stress lane. Set it here,
 * unconditionally, right before the test dimension launches -- not once at
 * daemon start, and not left to whatever exported the hook that invoked
 * this binary. */
static bool proof_stress_tests_env_prepare(char *why, size_t why_len)
{
    if (setenv("ZCL_STRESS_TESTS", "1", 1) != 0) {
        proof_why(why, why_len, "stress_tests_env_unavailable");
        return false;
    }
    return true;
}

#if defined(ZCL_TESTING)
bool zcl_dev_proof_test_stress_env_prepare(char *why, size_t why_len)
{
    return proof_stress_tests_env_prepare(why, why_len);
}

bool zcl_dev_proof_test_warm_status_line(const char *warmstart_path,
                                         char *out, size_t out_len)
{
    return warm_status_line(warmstart_path, out, out_len);
}
#endif

static bool proof_make_jobs_arg(char out[16])
{
    uint32_t jobs = platform_logical_cpu_count();
    if (jobs > PROOF_MAX_JOBS) jobs = PROOF_MAX_JOBS;
    int written = snprintf(out, 16, "-j%u", jobs);
    return written > 0 && written < 16;
}

static bool executable_reuse(const struct proof_paths *paths,
                             const char *artifact,
                             const struct dev_source_record *expected_source,
                             struct zcl_dev_proof_dimension *dimension,
                             char *why, size_t why_len)
{
    if (!paths || !artifact || !expected_source ||
        !expected_source->source_id[0] || !dimension || dimension->selected == 0) {
        proof_why(why, why_len, "proof_executable_reuse_input_invalid");
        return false;
    }
    int fd = open(artifact, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        proof_whyf(why, why_len, "proof_executable_open_failed_errno_%d",
                   errno);
        return false;
    }
    struct dev_source_record source = {0};
    char source_why[160] = {0};
    bool admitted = zcl_dev_executable_source_record_read(
        paths->root, fd, artifact, &source, source_why, sizeof(source_why));
    if (close(fd) != 0) {
        proof_whyf(why, why_len, "proof_executable_close_failed_errno_%d",
                   errno);
        return false;
    }
    if (!admitted) {
        proof_whyf(why, why_len, "proof_executable_%s",
                   source_why[0] ? source_why : "source_record_failed");
        return false;
    }
    if (strcmp(source.source_id, expected_source->source_id) != 0) {
        proof_whyf(why, why_len,
                   "proof_executable_source_identity_mismatch_actual_%.16s_expected_%.16s",
                   source.source_id, expected_source->source_id);
        return false;
    }
    if (!hash_file("zcl.dev_proof_executable_reuse.v1", artifact,
                   dimension->receipt_root)) {
        proof_why(why, why_len, "proof_executable_hash_failed");
        return false;
    }
    dimension->reused = dimension->selected;
    return true;
}

static bool admitted_executable_materialize(
    const struct proof_paths *paths, const char *generation,
    const char *source, const char *relative_target,
    const struct dev_source_record *expected_source, char target[PATH_MAX],
    char *why, size_t why_len)
{
    struct zcl_dev_proof_dimension artifact = {.selected = 1};
    int target_len = generation && relative_target && target
        ? snprintf(target, PATH_MAX, "%s/%s", generation, relative_target)
        : -1;
    if (!paths || !source || !expected_source || !target || target_len <= 0 ||
        target_len >= PATH_MAX) {
        proof_why(why, why_len, "proof_executable_target_path_invalid");
        return false;
    }
    if (!executable_reuse(paths, source, expected_source, &artifact,
                          why, why_len))
        return false;
    if (!dependency_materialize(source, target)) {
        proof_why(why, why_len, "proof_executable_materialize_failed");
        return false;
    }
    return true;
}

static bool admitted_executable_mark_fresh(const char *path)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return false;
    const struct timespec times[2] = {
        {.tv_nsec = UTIME_OMIT},
        {.tv_nsec = UTIME_NOW},
    };
    bool ok = futimens(fd, times) == 0;
    if (close(fd) != 0) ok = false;
    return ok;
}

static bool test_object_dir_relative(const struct proof_paths *paths,
                                     char object_dir[PATH_MAX])
{
    char plan[PATH_MAX];
    if (snprintf(plan, sizeof(plan), "%s/build/dev-loop/restart.env",
                 paths->root) >= (int)sizeof(plan))
        return false;
    FILE *file = fopen(plan, "r");
    if (!file) return false;
    char line[PATH_MAX];
    object_dir[0] = 0;
    while (fgets(line, sizeof(line), file)) {
        static const char prefix[] = "TEST_OBJ_DIR=";
        if (strncmp(line, prefix, sizeof(prefix) - 1) != 0) continue;
        size_t len = strcspn(line + sizeof(prefix) - 1, "\r\n");
        if (len == 0 || len >= PATH_MAX) break;
        memcpy(object_dir, line + sizeof(prefix) - 1, len);
        object_dir[len] = 0;
        break;
    }
    bool read_ok = !ferror(file) && fclose(file) == 0;
    static const char prefix[] = "build/test-obj/epochs/";
    return read_ok && strncmp(object_dir, prefix, sizeof(prefix) - 1) == 0 &&
        object_dir[sizeof(prefix) - 1] != 0 && !strstr(object_dir, "..") &&
        !strchr(object_dir, '\\');
}

static bool test_binary_path(const struct proof_paths *paths,
                             char out[PATH_MAX])
{
    char object_dir[PATH_MAX];
    if (!test_object_dir_relative(paths, object_dir)) return false;
    const char *epoch = strrchr(object_dir, '/');
    if (!epoch || !epoch[1] || strchr(epoch + 1, '/')) return false;
    int n = snprintf(out, PATH_MAX,
                     "%s/build/bin/test-fast/epochs/%s/test_parallel_fast",
                     paths->root, epoch + 1);
    return n > 0 && n < PATH_MAX && access(out, X_OK) == 0;
}

static bool test_epoch_pointer_prepare(const struct proof_paths *paths,
                                       const char *generation,
                                       const char *object_dir,
                                       uint8_t pointer_root[32])
{
    const char *epoch = strrchr(object_dir, '/');
    char source[PATH_MAX], target[PATH_MAX];
    if (!epoch || !epoch[1] || strchr(epoch + 1, '/') ||
        snprintf(source, sizeof(source), "%s/build/test-obj/.current-epoch",
                 paths->root) >= (int)sizeof(source) ||
        snprintf(target, sizeof(target), "%s/build/test-obj/.current-epoch",
                 generation) >= (int)sizeof(target) ||
        !dependency_parent_ensure(target) ||
        !dependency_copy_fresh(source, target))
        return false;
    int fd = open(target, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return false;
    char value[72];
    ssize_t got;
    do {
        got = read(fd, value, sizeof(value));
    } while (got < 0 && errno == EINTR);
    bool ok = close(fd) == 0 && got > 0 && got < (ssize_t)sizeof(value);
    size_t len = ok ? (size_t)got : 0;
    while (len > 0 && (value[len - 1] == '\n' || value[len - 1] == '\r'))
        len--;
    ok = ok && strlen(epoch + 1) == len &&
        memcmp(value, epoch + 1, len) == 0 &&
        hash_file("zcl.dev_proof_epoch_pointer.v1", target, pointer_root);
    return ok;
}

static bool test_depfiles_prepare(const struct proof_paths *paths,
                                  const char *generation,
                                  uint8_t depfile_root[32],
                                  char *why, size_t why_len)
{
    char relative[PATH_MAX], source[PATH_MAX], target[PATH_MAX];
    uint8_t pointer_root[32];
    if (!test_object_dir_relative(paths, relative)) {
        proof_why(why, why_len, "proof_test_restart_plan_invalid");
        return false;
    }
    if (snprintf(source, sizeof(source), "%s/%s", paths->root, relative) >=
            (int)sizeof(source) ||
        snprintf(target, sizeof(target), "%s/%s", generation, relative) >=
            (int)sizeof(target)) {
        proof_why(why, why_len, "proof_test_depfile_path_invalid");
        return false;
    }
    struct sha3_256_ctx root;
    hash_begin(&root, "zcl.dev_proof_depfiles.v1");
    size_t count = 0;
    if (!depfile_tree_copy(source, target, strlen(source), &root, &count)) {
        proof_why(why, why_len, "proof_test_depfile_copy_failed");
        return false;
    }
    if (count == 0) {
        proof_why(why, why_len, "proof_test_depfile_tree_empty");
        return false;
    }
    if (!test_epoch_pointer_prepare(paths, generation, relative,
                                    pointer_root)) {
        proof_why(why, why_len, "proof_test_epoch_pointer_failed");
        return false;
    }
    uint8_t count_le[8];
    zcl_write_u64_le(count_le, (uint64_t)count);
    sha3_256_write(&root, count_le, sizeof(count_le));
    sha3_256_write(&root, pointer_root, sizeof(pointer_root));
    sha3_256_finalize(&root, depfile_root);
    return true;
}

static bool test_helpers_prepare(
    const struct proof_paths *paths, const char *generation,
    const char *runner_source, const struct dev_source_record *expected_source,
    const char *make_jobs, char runner_target[PATH_MAX], uint8_t helper_root[32],
    char *why, size_t why_len)
{
    char verifier_source[PATH_MAX], verifier_target[PATH_MAX];
    char node_source[PATH_MAX], node_target[PATH_MAX];
    char nodectl_target[PATH_MAX], acme_target[PATH_MAX], fbsh_target[PATH_MAX];
    char file_size_policy_target[PATH_MAX], board_bridge_target[PATH_MAX];
    char git_hook_target[PATH_MAX];
    uint8_t depfile_root[32];
    int verifier_len = snprintf(
        verifier_source, sizeof(verifier_source),
        "%s/build/bin/zclassic23-package-verify-dev", paths->root);
    int node_len = snprintf(node_source, sizeof(node_source),
                            "%s/build/bin/z23-dev", paths->root);
    int nodectl_len = snprintf(nodectl_target, sizeof(nodectl_target),
                               "%s/build/bin/zcl-nodectl", generation);
    int acme_len = snprintf(acme_target, sizeof(acme_target),
                            "%s/build/bin/zclassic23-acme", generation);
    int fbsh_len = snprintf(fbsh_target, sizeof(fbsh_target),
                            "%s/build/bin/fbsh", generation);
    int file_size_policy_len = snprintf(
        file_size_policy_target, sizeof(file_size_policy_target),
        "%s/build/bin/file_size_policy", generation);
    int board_bridge_len = snprintf(board_bridge_target, sizeof(board_bridge_target),
                                    "%s/build/bin/fleet-board-bridge", generation);
    int git_hook_len = snprintf(git_hook_target, sizeof(git_hook_target),
                                "%s/build/bin/z23-git-hook", generation);
    if (verifier_len <= 0 ||
        (size_t)verifier_len >= sizeof(verifier_source) ||
        node_len <= 0 || (size_t)node_len >= sizeof(node_source) ||
        nodectl_len <= 0 || (size_t)nodectl_len >= sizeof(nodectl_target) ||
        acme_len <= 0 || (size_t)acme_len >= sizeof(acme_target) ||
        fbsh_len <= 0 || (size_t)fbsh_len >= sizeof(fbsh_target) ||
        file_size_policy_len <= 0 ||
        (size_t)file_size_policy_len >= sizeof(file_size_policy_target) ||
        board_bridge_len <= 0 ||
        (size_t)board_bridge_len >= sizeof(board_bridge_target) ||
        git_hook_len <= 0 ||
        (size_t)git_hook_len >= sizeof(git_hook_target)) {
        proof_why(why, why_len, "proof_test_helper_path_invalid");
        return false;
    }
    if (!admitted_executable_materialize(
            paths, generation, runner_source, "build/bin/test_parallel_fast",
            expected_source, runner_target, why, why_len)) {
        if (!why || !why[0])
            proof_why(why, why_len, "proof_test_runner_admission_failed");
        return false;
    }
    if (!admitted_executable_materialize(
            paths, generation, verifier_source,
            "build/bin/zclassic23-package-verify-dev", expected_source,
            verifier_target, why, why_len)) {
        if (!why || !why[0])
            proof_why(why, why_len, "proof_test_verifier_admission_failed");
        return false;
    }
    if (!admitted_executable_materialize(
            paths, generation, node_source, "build/bin/zclassic23",
            expected_source, node_target, why, why_len)) {
        if (!why || !why[0])
            proof_why(why, why_len, "proof_test_node_admission_failed");
        return false;
    }
    if (!admitted_executable_mark_fresh(node_target)) {
        proof_why(why, why_len, "proof_test_node_freshness_failed");
        return false;
    }
    if (!test_depfiles_prepare(paths, generation, depfile_root,
                               why, why_len)) {
        return false;
    }
    const char *prerequisite_argv[] = {
        "make", "--no-print-directory", make_jobs, "zcl-nodectl",
        "zclassic23-acme", "fbsh", "engine-unit", "tools/file_size_policy",
        "fleet-board-bridge", "git-hook",
        NULL};
    struct zcl_dev_proof_budget helper_budget =
        proof_step_budget(paths, "helpers", PROOF_HELPERS_DEFAULT_MS);
    if (run_step(paths, generation, paths->helper_log, prerequisite_argv,
                 "helpers", &helper_budget, NULL) != 0) {
        proof_why(why, why_len, "proof_test_helper_build_failed");
        return false;
    }
    uint8_t runner_root[32], verifier_root[32], node_root[32], nodectl_root[32];
    uint8_t acme_root[32], fbsh_root[32], file_size_policy_root[32];
    uint8_t board_bridge_root[32], git_hook_root[32];
    if (!hash_file("zcl.dev_proof_test_runner.v1", runner_target,
                   runner_root) ||
        !hash_file("zcl.dev_proof_package_verifier.v1", verifier_target,
                   verifier_root) ||
        !hash_file("zcl.dev_proof_test_node.v1", node_target, node_root) ||
        !hash_file("zcl.dev_proof_nodectl.v1", nodectl_target,
                   nodectl_root) ||
        !hash_file("zcl.dev_proof_acme_worker.v1", acme_target, acme_root) ||
        !hash_file("zcl.dev_proof_fbsh.v1", fbsh_target, fbsh_root) ||
        !hash_file("zcl.dev_proof_file_size_policy.v1", file_size_policy_target,
                   file_size_policy_root) ||
        !hash_file("zcl.dev_proof_board_bridge.v1", board_bridge_target,
                   board_bridge_root) ||
        !hash_file("zcl.dev_proof_git_hook.v1", git_hook_target,
                   git_hook_root)) {
        proof_why(why, why_len, "proof_test_helper_hash_failed");
        return false;
    }
    struct sha3_256_ctx helpers;
    hash_begin(&helpers, "zcl.dev_proof_test_helpers.v1");
    sha3_256_write(&helpers, runner_root, sizeof(runner_root));
    sha3_256_write(&helpers, verifier_root, sizeof(verifier_root));
    sha3_256_write(&helpers, node_root, sizeof(node_root));
    sha3_256_write(&helpers, nodectl_root, sizeof(nodectl_root));
    sha3_256_write(&helpers, acme_root, sizeof(acme_root));
    sha3_256_write(&helpers, fbsh_root, sizeof(fbsh_root));
    sha3_256_write(&helpers, file_size_policy_root,
                   sizeof(file_size_policy_root));
    sha3_256_write(&helpers, board_bridge_root, sizeof(board_bridge_root));
    sha3_256_write(&helpers, git_hook_root, sizeof(git_hook_root));
    sha3_256_write(&helpers, depfile_root, sizeof(depfile_root));
    sha3_256_finalize(&helpers, helper_root);
    return true;
}

static void test_receipt_bind_helpers(
    struct zcl_dev_proof_dimension *test, const uint8_t helper_root[32])
{
    uint8_t test_root[32];
    memcpy(test_root, test->receipt_root, sizeof(test_root));
    struct sha3_256_ctx receipt;
    hash_begin(&receipt, "zcl.dev_proof_test_child_with_helpers.v1");
    sha3_256_write(&receipt, test_root, sizeof(test_root));
    sha3_256_write(&receipt, helper_root, 32);
    sha3_256_finalize(&receipt, test->receipt_root);
}

static bool receipt_store(const struct proof_paths *paths,
                          struct zcl_dev_acceptance_receipt_v1 *receipt)
{
    uint8_t wire[ZCL_DEV_PROOF_WIRE_BYTES];
    if (!proof_lease_current(paths)) return false;
    for (size_t i = 0; i < ZCL_DEV_PROOF_DIMENSIONS; i++) {
        struct zcl_dev_proof_dimension *dimension = &receipt->dimensions[i];
        if (!dimension->selected) continue;
        uint8_t child[ZCL_DEV_PROOF_CHILD_WIRE_BYTES];
        if (!zcl_dev_proof_child_receipt_create(
                (enum zcl_dev_proof_dimension_id)i, dimension, child))
            return false;
        char root[65], path[PATH_MAX];
        zcl_hex_encode(dimension->receipt_root, ZCL_DEV_PROOF_ROOT_BYTES, root);
        if (snprintf(path, sizeof(path), "%s/%s.child", paths->children,
                     root) >= (int)sizeof(path))
            return false;
        struct stat st;
        if (lstat(path, &st) == 0) {
            uint8_t existing[ZCL_DEV_PROOF_CHILD_WIRE_BYTES];
            if (!read_exact_file(path, existing, sizeof(existing)) ||
                memcmp(existing, child, sizeof(child)) != 0)
                return false;
        } else if (errno != ENOENT ||
                   !write_atomic(path, child, sizeof(child), 0400)) {
            return false;
        }
    }
    return proof_lease_current(paths) &&
           zcl_dev_proof_receipt_child_set_root(
               receipt, receipt->child_set_root) &&
           zcl_dev_proof_receipt_seal(receipt) &&
           zcl_dev_proof_receipt_serialize(receipt, wire) &&
           proof_write_if_current(paths, paths->receipt, wire, sizeof(wire),
                                  0400);
}
/* Every phase before the first dimension ran with no clock on it, so a proof
 * that spent six minutes somewhere reported only that it took six minutes.
 * These marks cost one gettime and one appended line each, and they name the
 * phase that actually holds the wall — which is how a "the build is slow"
 * report becomes a fixable defect instead of a feeling. */
struct proof_phase_clock {
    char     path[PATH_MAX];
    int64_t  started_us;
    int64_t  last_us;
    bool     open;
};

static void proof_phase_begin(struct proof_phase_clock *clock,
                              const struct proof_paths *paths)
{
    if (!clock) return;
    memset(clock, 0, sizeof(*clock));
    clock->started_us = platform_time_monotonic_us();
    clock->last_us = clock->started_us;
    if (!paths || snprintf(clock->path, sizeof(clock->path),
                           "%s/phases.txt", paths->logs) >=
                      (int)sizeof(clock->path))
        return;
    clock->open = true;
}

/* Best effort by design: a proof must never fail because it could not write
 * its own stopwatch. A lost line costs the next reader one measurement. */
static void proof_phase_mark(struct proof_phase_clock *clock, const char *name)
{
    if (!clock || !clock->open || !name) return;
    int64_t now = platform_time_monotonic_us();
    int64_t phase_ms = (now - clock->last_us) / 1000;
    int64_t total_ms = (now - clock->started_us) / 1000;
    clock->last_us = now;
    FILE *out = fopen(clock->path, "ae");
    if (!out) return;
    (void)fprintf(out, "zcl.dev_proof_phase.v1 %-28s %8lld ms  (cumulative %8lld ms)\n",
                  name, (long long)phase_ms, (long long)total_ms);
    (void)fclose(out);
}

/* The warm-start sidecar: what the build reused, in flat grep-able
 * lines beside the fixed-width receipt. The receipt wire schema is
 * untouched — additive by a new artifact, not by repurposed fields: the
 * seal still covers exactly the dimension roots, and old readers ignore
 * the file. compile_mode is one of built, reused, skipped, failed. */
static void warm_sidecar_write(const struct proof_paths *paths,
                               const struct proof_warmstart *warm,
                               const char *compile_mode,
                               uint64_t compile_ms, uint64_t bundle_ms)
{
    char body[1024];
    int len = paths && warm && compile_mode
        ? snprintf(body, sizeof(body),
                   "%s\nwarm=%d\ndonor=%s\ndonor_local=%s\nfiles_linked=%llu\n"
                   "bytes_linked=%llu\ncompile_mode=%s\ncompile_ms=%llu\n"
                   "bundle_ms=%llu\nreason=%s\n",
                   PROOF_WARM_SIDECAR_SCHEMA, warm->armed ? 1 : 0,
                   warm->armed ? warm->donor : "-",
                   warm->armed ? warm->donor_local : "-",
                   (unsigned long long)warm->files_linked,
                   (unsigned long long)warm->bytes_linked, compile_mode,
                   (unsigned long long)compile_ms,
                   (unsigned long long)bundle_ms,
                   warm->armed ? "-"
                               : (warm->cold_reason[0] ? warm->cold_reason
                                                        : "unknown"))
        : -1;
    if (len > 0 && len < (int)sizeof(body))
        (void)write_atomic(paths->warmstart, body, (size_t)len, 0400);
}

/* The remainder of one proof worker, after the immutable generation and the
 * changed set exist. Split out so the heap-resident changed set has exactly
 * one owner and one release point across every refusal below. Takes the
 * phase clock the outer worker already opened so build/capture and the rest
 * of the proof share one cumulative timer, and the warm-start survey filled
 * by generation_prepare() so the compile dimension can publish it. */
static bool proof_worker_body(const struct proof_paths *paths,
                              const char *local, const char *base,
                              const char *generation, int64_t started_us,
                              struct proof_phase_clock *phases,
                              const struct proof_warmstart *warm,
                              const char *const *files, size_t file_count,
                              char *why, size_t why_len)
{
    struct proof_paths execution = *paths;
    (void)snprintf(execution.root, sizeof(execution.root), "%s", generation);

    bool inventory_only = inventory_output_only(files, file_count);
    struct zcl_devloop_plan plan;
    if (!zcl_devloop_plan_files(files, file_count, &plan)) {
        proof_why(why, why_len, "impact_plan_invalid");
        return false;
    }
    const char *admission_reason = "";
    if (!zcl_devloop_plan_add_closure(paths->root, files, file_count, &plan) ||
        !zcl_devloop_plan_proof_admissible(&plan, &admission_reason)) {
        proof_why(why, why_len,
                  admission_reason && admission_reason[0]
                      ? admission_reason : "impact_plan_incomplete");
        return false;
    }
    proof_phase_mark(phases, "impact_plan_closure");
    char plan_json[ZCL_DEVLOOP_PLAN_WIRE_MAX];
    /* Render the plan we just closed. The _closure spelling would open the
     * code index and re-walk the whole reverse-caller graph to rebuild the
     * plan sitting in this frame -- the most expensive phase of the proof,
     * paid twice for one answer. */
    size_t plan_len = zcl_devloop_plan_json_render(
        &plan, files, file_count, plan_json, sizeof(plan_json));
    if (!plan_len) {
        proof_why(why, why_len, "impact_plan_render_failed");
        return false;
    }
    proof_phase_mark(phases, "impact_plan_render");
    if (!worktree_exact(paths->root, local, true, why, why_len)) return false;
    proof_phase_mark(phases, "worktree_exact_recheck");

    struct dev_source_record source_before = {0}, source_after = {0};
    char sealed_source_id[65], sealed_mutation_id[65];
    if (!zcl_dev_source_identity_capture(generation, &source_before, why,
                                         why_len)) {
        if (!why || !why[0])
            proof_why(why, why_len, "source_identity_capture_failed");
        return false;
    }
    if (!source_before.cas_present) {
        proof_why(why, why_len, "source_cas_capture_failed");
        return false;
    }
    proof_phase_mark(phases, "source_identity_capture");
    memcpy(sealed_source_id, source_before.source_id,
           sizeof(sealed_source_id));
    memcpy(sealed_mutation_id, source_before.mutation_id,
           sizeof(sealed_mutation_id));
    struct zcl_dev_acceptance_receipt_v1 receipt = {0};
    if (!zcl_dev_proof_oid_decode(local, receipt.local_commit,
                                  &receipt.local_commit_len) ||
        !zcl_dev_proof_oid_decode(base, receipt.remote_base,
                                  &receipt.remote_base_len) ||
        !zcl_hex_decode_lower(source_before.cas_root_sha3,
                              receipt.source_cas_root, 32) ||
        !zcl_hex_decode_lower(source_before.mutation_id,
                              receipt.mutation_root, 32)) {
        proof_why(why, why_len, "proof_identity_decode_failed");
        return false;
    }
    hash_text("zcl.dev_proof_git_source.v1", local, strlen(local),
              receipt.source_root);
    if (!hash_file("zcl.dev_proof_changed_set.v1", paths->changed,
                   receipt.changed_set_root)) {
        proof_why(why, why_len, "changed_set_hash_failed");
        return false;
    }
    char policy_path[PATH_MAX];
    struct zcl_dev_proof_build_identity_v1 identity;
    if (snprintf(policy_path, sizeof(policy_path),
                 "%s/cognition/controllers/include/controllers/agent_impact_rules.def",
                 generation) >= (int)sizeof(policy_path) ||
        !hash_file("zcl.dev_proof_impact_policy.v1", policy_path,
                   receipt.impact_policy_root) ||
        !zcl_dev_proof_build_identity_v1_capture(paths->root, &identity)) {
        proof_why(why, why_len, "proof_toolchain_or_policy_unavailable");
        return false;
    }
    /* The same four roots the warm-start donor marker seals, from the same
     * call: the receipt and the donor gate cannot disagree about what this
     * build was. */
    memcpy(receipt.compiler_root, identity.compiler, 32);
    memcpy(receipt.flags_root, identity.flags, 32);
    memcpy(receipt.environment_root, identity.environment, 32);
    memcpy(receipt.build_graph_root, identity.build_graph, 32);
    struct sha3_256_ctx impact;
    hash_begin(&impact, "zcl.dev_proof_impact_plan.v1");
    sha3_256_write(&impact, receipt.impact_policy_root, 32);
    sha3_256_write(&impact, (const uint8_t *)plan_json, plan_len);
    sha3_256_finalize(&impact, receipt.impact_policy_root);

    struct zcl_dev_proof_dimension *generated =
        &receipt.dimensions[ZCL_DEV_PROOF_GENERATED];
    struct zcl_dev_proof_dimension *compile =
        &receipt.dimensions[ZCL_DEV_PROOF_COMPILE];
    struct zcl_dev_proof_dimension *lint =
        &receipt.dimensions[ZCL_DEV_PROOF_LINT];
    struct zcl_dev_proof_dimension *test =
        &receipt.dimensions[ZCL_DEV_PROOF_TEST];
    /* Warm-start sidecar inputs, hoisted so the bundle block can rewrite
     * the sidecar with both build phases timed. */
    const char *warm_compile_mode = "skipped";
    uint64_t warm_compile_ms = 0;

    char make_jobs[16];
    if (!proof_make_jobs_arg(make_jobs)) {
        proof_why(why, why_len, "proof_job_count_unavailable");
        return false;
    }

    generated->selected = inventory_only ? 1 : 0;
    bool compile_selected = !inventory_only && !plan.docs_only;
    compile->selected = compile_selected ? 1 : 0;
    lint->selected = inventory_only ? 0 : 1;
    char groups[ZCL_DEVLOOP_MAX_PLAN_SELECTIONS *
                (ZCL_TEST_GROUP_FULL_MAX + 1)] = {0};
    char only[sizeof(groups) + 8];
    uint32_t test_count = 0;
    if (!build_test_selector(&plan, inventory_only, groups, sizeof(groups),
                             &test_count)) {
        proof_why(why, why_len, "test_selection_invalid_or_truncated");
        return false;
    }
    test->selected = test_count;
    /* Say why the run is this large, in a file a reader finds beside the test
     * log. Without this a universal selection looks like an unexplained
     * whole-catalog run. */
    if (!proof_note_test_selection(&execution, plan.closure_universal,
                                   test_count)) {
        proof_why(why, why_len, "test_selection_note_unwritable");
        return false;
    }
    bool cycle_reused = !generated->selected && cycle_proof_reuse(
        paths, source_before.cas_root_sha3, receipt.dimensions);
    if (!cycle_reused) {
        if (generated->selected) {
            const char *argv[] = {"make", "--no-print-directory", make_jobs,
                                  "check-capability-inventory-generated", NULL};
            struct zcl_dev_proof_budget budget = proof_step_budget(
                paths, "generated", PROOF_GENERATED_DEFAULT_MS);
            if (!run_dimension(&execution, ZCL_DEV_PROOF_GENERATED, argv,
                               generated, false, &budget, why, why_len))
                return false;
        } else unused_dimension(ZCL_DEV_PROOF_GENERATED, generated);
        proof_phase_mark(phases, "dimension_generated");
        if (compile->selected) {
            char artifact[PATH_MAX];
            warm_compile_mode = "reused";
            int artifact_len = snprintf(artifact, sizeof(artifact),
                                        "%s/build/bin/z23-dev", paths->root);
            if (artifact_len <= 0 || (size_t)artifact_len >= sizeof(artifact) ||
                !executable_reuse(paths, artifact,
                                  &source_before, compile, NULL, 0)) {
                warm_compile_mode = "built";
                int64_t build_us0 = platform_time_monotonic_us();
                const char *argv[] = {"make", "--no-print-directory", make_jobs,
                                      "build-only", NULL};
                struct zcl_dev_proof_budget budget = proof_step_budget(
                    paths, "compile", PROOF_COMPILE_DEFAULT_MS);
                bool built = run_dimension(&execution, ZCL_DEV_PROOF_COMPILE,
                                           argv, compile, false, &budget, why,
                                           why_len);
                warm_compile_ms = (uint64_t)((platform_time_monotonic_us() -
                                              build_us0) / 1000);
                if (!built) {
                    warm_sidecar_write(paths, warm, "failed",
                                       warm_compile_ms, 0);
                    return false;
                }
                /* The build finished for this commit: publish the donor
                 * marker for the next generation. Best effort: a missing
                 * marker only costs the next proof a cold build. */
                (void)warm_marker_write(generation, paths->root, local,
                                        base);
            }
            warm_sidecar_write(paths, warm, warm_compile_mode,
                               warm_compile_ms, 0);
        } else {
            unused_dimension(ZCL_DEV_PROOF_COMPILE, compile);
            warm_sidecar_write(paths, warm, "skipped", 0, 0);
        }
        proof_phase_mark(phases, "dimension_compile");
        /* Lint proves the source; the test dimension proves the built
         * runner. Neither feeds the other, so both children are launched
         * before either is waited on and the proof pays for the longer of the
         * two rather than their sum. Everything above stays strictly
         * sequential on purpose: those steps are all `make` in the one
         * generation worktree, and two makes there race each other's build
         * epochs. */
        struct proof_dimension_run runs[2];
        size_t run_count = 0;
        char binary[PATH_MAX] = {0}, generation_binary[PATH_MAX] = {0};
        uint8_t helper_root[32] = {0};
        const char *lint_argv[] = {"make", "--no-print-directory", make_jobs,
                                   "lint-fast", NULL};
        struct zcl_dev_proof_budget lint_budget =
            proof_step_budget(paths, "lint", PROOF_LINT_DEFAULT_MS);
        if (!lint->selected) unused_dimension(ZCL_DEV_PROOF_LINT, lint);
        if (!test->selected) unused_dimension(ZCL_DEV_PROOF_TEST, test);
        only[0] = 0;
        if (test->selected) {
            if (strcmp(source_before.source_id, sealed_source_id) != 0 ||
                strcmp(source_before.mutation_id, sealed_mutation_id) != 0) {
                proof_whyf(
                    why, why_len,
                    "proof_saved_source_identity_changed_actual_%.16s_sealed_%.16s",
                    source_before.source_id, sealed_source_id);
                return false;
            }
            struct dev_source_record generation_checkpoint = {0};
            char checkpoint_why[160] = {0};
            if (!zcl_dev_source_identity_capture(
                    generation, &generation_checkpoint, checkpoint_why,
                    sizeof(checkpoint_why))) {
                proof_whyf(why, why_len,
                           "proof_generation_source_checkpoint_%s",
                           checkpoint_why[0] ? checkpoint_why : "failed");
                return false;
            }
            if (strcmp(generation_checkpoint.source_id, sealed_source_id) != 0 ||
                strcmp(generation_checkpoint.mutation_id,
                       sealed_mutation_id) != 0) {
                proof_whyf(
                    why, why_len,
                    "proof_generation_source_identity_changed_actual_%.16s_sealed_%.16s",
                    generation_checkpoint.source_id, sealed_source_id);
                return false;
            }
            if (!proof_stress_tests_env_prepare(why, why_len)) return false;
            if (setenv("ZCL_TESTCACHE_STORE_ROOT", paths->root, 1) != 0) {
                proof_why(why, why_len, "test_cache_store_root_unavailable");
                return false;
            }
            if (snprintf(only, sizeof(only), "--exact=%s", groups) >=
                (int)sizeof(only)) {
                proof_why(why, why_len, "test_selection_invalid_or_truncated");
                return false;
            }
            bool runner_ready = test_binary_path(paths, binary) &&
                test_helpers_prepare(
                    paths, generation, binary, &source_before,
                    make_jobs, generation_binary, helper_root, why, why_len);
            uint64_t bundle_ms = 0;
            if (!runner_ready) {
                if (why && why_len > 0) why[0] = 0;
                const char *bundle_argv[] = {
                    "make", "--no-print-directory", make_jobs,
                    "dev-proof-bundle", NULL};
                struct zcl_dev_proof_budget bundle_budget =
                    proof_step_budget(paths, "bundle",
                                      PROOF_BUNDLE_DEFAULT_MS);
                int64_t bundle_us0 = platform_time_monotonic_us();
                int bundle_rc = run_step(paths, generation, paths->bundle_log,
                                         bundle_argv, "bundle",
                                         &bundle_budget, NULL);
                /* First attempt only; a recovery rerun is rare and stays
                 * visible in the retry log. */
                bundle_ms = (uint64_t)((platform_time_monotonic_us() -
                                        bundle_us0) / 1000);
                if (bundle_rc != 0 && proof_log_contains(
                        paths->bundle_log,
                        "unverified compile epoch appeared after recovery "
                        "admission; rerun make")) {
                    char retry_log[PATH_MAX];
                    if (snprintf(retry_log, sizeof(retry_log), "%s.retry",
                                 paths->bundle_log) >= (int)sizeof(retry_log)) {
                        proof_why(why, why_len,
                                  "proof_bundle_retry_log_invalid");
                        return false;
                    }
                    bundle_rc = run_step(paths, generation, retry_log,
                                         bundle_argv, "bundle",
                                         &bundle_budget, NULL);
                }
                if (bundle_rc != 0) {
                    proof_why(why, why_len,
                              "proof_bundle_build_failed");
                    return false;
                }
                runner_ready = test_binary_path(&execution, binary) &&
                    test_helpers_prepare(
                        &execution, generation, binary, &source_before,
                        make_jobs, generation_binary, helper_root,
                        why, why_len);
                if (!runner_ready) {
                    if (!why || !why[0])
                        proof_why(why, why_len,
                                  "proof_bundle_admission_failed");
                    return false;
                }
                /* Both build phases are timed now: refresh the sidecar so
                 * the receipt directory carries the full compile story. */
                warm_sidecar_write(paths, warm, warm_compile_mode,
                                   warm_compile_ms, bundle_ms);
            }
        }
        const char *test_argv[] = {generation_binary, only, "--cache",
                                   "--activate-proof-contracts", NULL};
        struct zcl_dev_proof_budget test_budget =
            zcl_dev_proof_test_budget(paths->state, groups, test->selected);
        if (lint->selected &&
            !dimension_start(&execution, execution.root, &runs[run_count],
                             ZCL_DEV_PROOF_LINT, lint_argv, lint, false,
                             &lint_budget, why, why_len))
            return false;
        if (lint->selected) run_count++;
        if (test->selected &&
            !dimension_start(&execution, execution.root, &runs[run_count],
                             ZCL_DEV_PROOF_TEST, test_argv, test, true,
                             &test_budget, why, why_len)) {
            dimension_runs_wait(runs, run_count);
            for (size_t i = 0; i < run_count; i++)
                (void)dimension_finish(&execution, &runs[i], NULL, 0);
            return false;
        }
        if (test->selected) run_count++;
        dimension_runs_wait(runs, run_count);
        /* Fail closed on the first dimension that failed, in the order they
         * would have run sequentially, and always finish every child so each
         * one's log, receipt root and phases row survive the failure. */
        bool dimensions_ok = true;
        for (size_t i = 0; i < run_count; i++) {
            char step_why[160] = {0};
            if (dimension_finish(&execution, &runs[i], step_why,
                                 sizeof(step_why)))
                continue;
            if (dimensions_ok) proof_why(why, why_len, step_why);
            dimensions_ok = false;
        }
        if (!dimensions_ok) return false;
        if (test->selected) test_receipt_bind_helpers(test, helper_root);
        proof_phase_mark(phases, "dimension_lint_and_test");
    }

    if (!worktree_exact(generation, local, false, why, why_len))
        return false;
    if (!zcl_dev_source_cas_capture(generation, &source_after) ||
        !source_after.cas_present) {
        proof_why(why, why_len, "source_cas_recapture_failed");
        return false;
    }
    if (strcmp(source_before.cas_root_sha3, source_after.cas_root_sha3) != 0) {
        proof_why(why, why_len, "source_epoch_superseded");
        return false;
    }
    receipt.created_unix = (uint64_t)platform_time_wall_unix();
    receipt.elapsed_ms = (uint64_t)((platform_time_monotonic_us() - started_us) /
                                    1000);
    receipt.policy_version = ZCL_DEV_PROOF_POLICY_VERSION;
    receipt.complete = 1;
    if (!receipt_store(paths, &receipt)) {
        proof_why(why, why_len, "receipt_publication_failed");
        return false;
    }
    proof_unlink_if_current(paths, paths->failure);
    return true;
}

static bool proof_worker(const struct proof_paths *paths,
                         const char *local, const char *base,
                         struct platform_ram_scratch_lease *ram_lease,
                         char *why, size_t why_len)
{
    int64_t started_us = platform_time_monotonic_us();
    struct proof_phase_clock phases;
    proof_phase_begin(&phases, paths);
    if (paths->phases[0]) (void)remove(paths->phases);
    if (!worktree_exact(paths->root, local, true, why, why_len)) return false;
    proof_phase_mark(&phases, "worktree_exact_root");
    char generation[PATH_MAX];
    struct proof_warmstart warm = {0};
    if (!generation_prepare(paths, local, ram_lease, &warm, generation, why,
                            why_len))
        return false;
    proof_phase_mark(&phases, "generation_prepare");
    char scratch[PATH_MAX];
    if (snprintf(scratch, sizeof(scratch), "%s.capture", paths->changed) >=
        (int)sizeof(scratch)) {
        proof_why(why, why_len, "changed_set_request_invalid");
        return false;
    }
    struct zcl_dev_proof_changed_set changed = {0};
    if (!zcl_dev_proof_changed_set_capture(paths->root, base, local, scratch,
                                           paths->changed, &changed, why,
                                           why_len))
        return false;
    proof_phase_mark(&phases, "changed_files_capture");
    bool ok = proof_worker_body(paths, local, base, generation, started_us,
                                &phases, &warm, changed.files, changed.count,
                                why, why_len);
    zcl_dev_proof_changed_set_release(&changed);
    return ok;
}

static bool proof_worker_run(const struct proof_paths *paths,
                             const char *local, const char *base,
                             char *why, size_t why_len)
{
    struct sigaction child_action = {0};
    child_action.sa_handler = SIG_DFL;
    sigemptyset(&child_action.sa_mask);
    struct platform_ram_scratch_lease ram_lease = {0};
    bool ok = sigaction(SIGCHLD, &child_action, NULL) == 0 &&
              proof_worker(paths, local, base, &ram_lease, why, why_len);
    if (!ok && (!why || !why[0]))
        proof_why(why, why_len, "proof_child_reaping_unavailable");
    if (!ok) {
        const char *message = why && why[0]
            ? why : "background_verification_failed";
        (void)proof_write_if_current(paths, paths->failure, message,
                                     strlen(message), 0600);
    }
    proof_lease_release(paths);
    /* This attempt is the generation's life where RAM scratch is concerned:
     * its reserved room goes back to the pool the moment the worker is done,
     * every failure path included. */
    platform_ram_scratch_release(&ram_lease);
    return ok;
}

static bool proof_queue_directories(const char *repo_root,
                                    char state[PATH_MAX],
                                    char requests[PATH_MAX],
                                    char attempts[PATH_MAX])
{
    char root[PATH_MAX];
    if (!repo_root ||
        !platform_directory_canonical_real(repo_root, root, sizeof(root)))
        return false;
    int state_len = snprintf(state, PATH_MAX, "%s/.cache/zcl-dev-proof", root);
    int request_len = state_len > 0 && state_len < PATH_MAX
        ? snprintf(requests, PATH_MAX, "%s/requests", state) : -1;
    int attempt_len = request_len > 0 && request_len < PATH_MAX
        ? snprintf(attempts, PATH_MAX, "%s/attempts", state) : -1;
    return state_len > 0 && state_len < PATH_MAX && request_len > 0 &&
           request_len < PATH_MAX && attempt_len > 0 && attempt_len < PATH_MAX;
}

static bool proof_request_name(const char *name)
{
    static const char suffix[] = ".request";
    size_t len = name ? strlen(name) : 0;
    return len > sizeof(suffix) - 1 &&
        strcmp(name + len - (sizeof(suffix) - 1), suffix) == 0 &&
        !strchr(name, '/') && !strchr(name, '\\');
}

static bool proof_queue_has_pending_platform(const char *repo_root)
{
    char state[PATH_MAX], requests[PATH_MAX], attempts[PATH_MAX];
    if (!proof_queue_directories(repo_root, state, requests, attempts))
        return false;
    DIR *dir = opendir(requests);
    if (!dir) return false;
    bool found = false;
    for (struct dirent *entry = readdir(dir); entry; entry = readdir(dir)) {
        char path[PATH_MAX], local[65], base[65];
        if (!proof_request_name(entry->d_name) ||
            snprintf(path, sizeof(path), "%s/%s", requests,
                     entry->d_name) >= (int)sizeof(path))
            continue;
        if (proof_request_read(path, local, base, NULL, NULL) &&
            proof_request_matches_pair(path, local, base)) {
            found = true;
            break;
        }
    }
    (void)closedir(dir);
    return found;
}

static bool proof_queue_select(const char *requests, char selected[PATH_MAX],
                               char local[65], char base[65])
{
    DIR *dir = opendir(requests);
    if (!dir) return false;
    int64_t newest_wall = INT64_MIN, newest_monotonic = INT64_MIN;
    selected[0] = 0;
    for (struct dirent *entry = readdir(dir); entry; entry = readdir(dir)) {
        char path[PATH_MAX], candidate_local[65], candidate_base[65];
        int64_t wall = 0, monotonic = 0;
        if (!proof_request_name(entry->d_name) ||
            snprintf(path, sizeof(path), "%s/%s", requests,
                     entry->d_name) >= (int)sizeof(path) ||
            !proof_request_read(path, candidate_local, candidate_base,
                                &wall, &monotonic) ||
            !proof_request_matches_pair(path, candidate_local,
                                        candidate_base))
            continue;
        if (wall < newest_wall ||
            (wall == newest_wall && monotonic < newest_monotonic) ||
            (wall == newest_wall && monotonic == newest_monotonic &&
             selected[0] && strcmp(path, selected) <= 0))
            continue;
        newest_wall = wall;
        newest_monotonic = monotonic;
        (void)snprintf(selected, PATH_MAX, "%s", path);
        (void)snprintf(local, 65, "%s", candidate_local);
        (void)snprintf(base, 65, "%s", candidate_base);
    }
    bool ok = closedir(dir) == 0 && selected[0];
    return ok;
}

static bool proof_pair_superseded(const char *root,
                                  const char *candidate_local,
                                  const char *candidate_base,
                                  const char *selected_local,
                                  const char *selected_base)
{
    char ignored[2];
    const char *local_argv[] = {
        "git", "merge-base", "--is-ancestor", candidate_local,
        selected_local, NULL};
    const char *base_argv[] = {
        "git", "merge-base", "--is-ancestor", candidate_base,
        selected_base, NULL};
    return git_capture(root, local_argv, ignored, sizeof(ignored)) &&
           git_capture(root, base_argv, ignored, sizeof(ignored));
}

static void proof_queue_coalesce(const char *root, const char *requests,
                                 const char *selected, const char *attempts,
                                 const char *selected_local,
                                 const char *selected_base)
{
    char superseded[PATH_MAX];
    if (snprintf(superseded, sizeof(superseded), "%s/superseded", attempts) >=
            (int)sizeof(superseded) ||
        !platform_private_directory_ensure(superseded))
        return;
    char batch[PATH_MAX];
    if (snprintf(batch, sizeof(batch), "%s/batch.XXXXXX", superseded) >=
            (int)sizeof(batch) ||
        !mkdtemp(batch))
        return;
    DIR *dir = opendir(requests);
    if (!dir) return;
    for (struct dirent *entry = readdir(dir); entry; entry = readdir(dir)) {
        char source[PATH_MAX], target[PATH_MAX], local[65], base[65];
        if (!proof_request_name(entry->d_name) ||
            snprintf(source, sizeof(source), "%s/%s", requests,
                     entry->d_name) >= (int)sizeof(source) ||
            strcmp(source, selected) == 0 ||
            !proof_request_read(source, local, base, NULL, NULL) ||
            !proof_request_matches_pair(source, local, base) ||
            !proof_pair_superseded(root, local, base, selected_local,
                                   selected_base) ||
            snprintf(target, sizeof(target), "%s/%s", batch,
                     entry->d_name) >= (int)sizeof(target))
            continue;
        (void)rename(source, target);
    }
    (void)closedir(dir);
}

static int proof_queue_run_next_platform(const char *repo_root,
                                         char *why, size_t why_len)
{
    char state[PATH_MAX], requests[PATH_MAX], attempts[PATH_MAX];
    char queue_lock[PATH_MAX], selected[PATH_MAX], local[65], base[65];
    if (!proof_queue_directories(repo_root, state, requests, attempts) ||
        snprintf(queue_lock, sizeof(queue_lock), "%s/queue.lock", state) >=
            (int)sizeof(queue_lock)) {
        proof_why(why, why_len, "proof_queue_path_invalid");
        return -1;
    }
    int fd = open(queue_lock, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
    if (fd < 0 || flock(fd, LOCK_EX) != 0) {
        if (fd >= 0) close(fd);
        proof_why(why, why_len, "proof_queue_lock_failed");
        return -1;
    }
    if (!proof_queue_select(requests, selected, local, base)) {
        (void)flock(fd, LOCK_UN);
        close(fd);
        return 0;
    }
    struct proof_paths pair, attempt;
    char claimed[PATH_MAX];
    bool prepared = proof_paths_fill(repo_root, local, base, &pair) &&
        proof_state_prepare(&pair) &&
        proof_attempt_paths_prepare(&pair, &attempt) &&
        snprintf(claimed, sizeof(claimed), "%s/request", attempt.attempt) <
            (int)sizeof(claimed) && proof_lease_publish(&attempt);
    if (prepared && rename(selected, claimed) != 0) {
        if (proof_lease_current(&attempt)) (void)unlink(attempt.lease);
        prepared = false;
    }
    if (prepared)
        proof_queue_coalesce(pair.root, requests, selected, attempts, local,
                             base);
    (void)flock(fd, LOCK_UN);
    close(fd);
    if (!prepared) {
        proof_why(why, why_len, "proof_queue_claim_failed");
        return -1;
    }
    if (why && why_len) why[0] = 0;
    (void)proof_worker_run(&attempt, local, base, why, why_len);
    return 1;
}

static bool proof_ensure_platform(const char *repo_root,
                                  const char *local_commit,
                                  const char *remote_base,
                                  struct zcl_dev_proof_status *out)
{
    char local[65], base[65], why[160] = {0};
    if (!out || !zcl_dev_proof_resolve_pair(repo_root, local_commit,
                                             remote_base, local, base,
                                             why, sizeof(why))) {
        if (out) {
            memset(out, 0, sizeof(*out));
            out->state = ZCL_DEV_PROOF_STATE_INVALID;
            (void)snprintf(out->detail, sizeof(out->detail), "%s", why);
        }
        return false;
    }
    if (!zcl_dev_proof_status_read(repo_root, local, base, out)) return false;
    if (out->state == ZCL_DEV_PROOF_STATE_PASSED) {
        out->receipt_reused = true;
        return true;
    }
    if (out->state == ZCL_DEV_PROOF_STATE_RUNNING) return true;
    /* An exact commit/base pair is immutable: a `.failed` marker already
     * settles this pair's outcome. Re-enqueueing here would spend a worker
     * slot re-deriving the identical, deterministic failure and would leave
     * a caller that only checks for MISSING/RUNNING believing work is
     * still in flight. Exit with the settled status instead of lingering. */
    if (out->state == ZCL_DEV_PROOF_STATE_FAILED) return true;
    struct proof_paths paths;
    if (!proof_paths_fill(repo_root, local, base, &paths) ||
        !proof_state_prepare(&paths)) {
        out->state = ZCL_DEV_PROOF_STATE_INVALID;
        (void)snprintf(out->detail, sizeof(out->detail), "%s",
                       "proof_state_unavailable");
        return false;
    }
    char body[320];
    size_t body_len = 0;
    if (!proof_request_body(local, base, body, &body_len) ||
        !write_atomic(paths.request, body, body_len, 0600)) {
        out->state = ZCL_DEV_PROOF_STATE_INVALID;
        (void)snprintf(out->detail, sizeof(out->detail), "%s",
                       "resident_proof_enqueue_failed");
        return false;
    }
    return zcl_dev_proof_status_read(repo_root, local, base, out);
}

static bool proof_wait_platform(const char *repo_root,
                                const char *local_commit,
                                const char *remote_base,
                                int timeout_ms,
                                struct zcl_dev_proof_status *out)
{
    if (!out || timeout_ms < 1 || timeout_ms > 900000) return false;
    int64_t deadline = platform_time_monotonic_us() + (int64_t)timeout_ms * 1000;
    bool ensured = false;
    for (;;) {
        if (!zcl_dev_proof_status_read(repo_root, local_commit, remote_base, out))
            return false;
        if (!ensured && out->state == ZCL_DEV_PROOF_STATE_MISSING) {
            ensured = true;
            if (!zcl_dev_proof_ensure(repo_root, local_commit, remote_base, out))
                return false;
        }
        if (out->state != ZCL_DEV_PROOF_STATE_RUNNING &&
            out->state != ZCL_DEV_PROOF_STATE_MISSING)
            return true;
        if (platform_time_monotonic_us() >= deadline) return true;
        platform_sleep_ms(20);
    }
}

#endif /* _WIN32 */

/* One public definition per API keeps platform arms from silently drifting
 * as separate external symbols. The active arm remains a private, typed
 * implementation selected above. */
bool zcl_dev_proof_resolve_pair(const char *repo_root,
                                const char *requested_local,
                                const char *requested_base,
                                char local_commit[65],
                                char remote_base[65],
                                char *why, size_t why_len)
{
    return proof_resolve_pair_platform(repo_root, requested_local,
                                       requested_base, local_commit,
                                       remote_base, why, why_len);
}

bool zcl_dev_proof_status_read(const char *repo_root,
                               const char *local_commit,
                               const char *remote_base,
                               struct zcl_dev_proof_status *out)
{
    return proof_status_read_platform(repo_root, local_commit, remote_base,
                                      out);
}

bool zcl_dev_proof_ensure(const char *repo_root,
                          const char *local_commit,
                          const char *remote_base,
                          struct zcl_dev_proof_status *out)
{
    return proof_ensure_platform(repo_root, local_commit, remote_base, out);
}

bool zcl_dev_proof_queue_has_pending(const char *repo_root)
{
    return proof_queue_has_pending_platform(repo_root);
}

int zcl_dev_proof_queue_run_next(const char *repo_root,
                                 char *why, size_t why_len)
{
    return proof_queue_run_next_platform(repo_root, why, why_len);
}

bool zcl_dev_proof_wait(const char *repo_root,
                        const char *local_commit,
                        const char *remote_base,
                        int timeout_ms,
                        struct zcl_dev_proof_status *out)
{
    return proof_wait_platform(repo_root, local_commit, remote_base,
                               timeout_ms, out);
}
