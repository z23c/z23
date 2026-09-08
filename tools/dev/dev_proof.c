/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Admit exact commit/base pairs from the resident development proof. */

#define _POSIX_C_SOURCE 200809L
#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif

#include "dev_proof.h"
#include "dev_proof_budget.h"
#include "devloop.h"
#include "test_group_catalog.h"

#include "base/hex.h"
#include "base/safe_alloc.h"
#include "base/serialize_le.h"
#include "json/json.h"
#include "platform/directory_compat.h"
#include "platform/disk_space.h"
#include "platform/file_clone.h"
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
/* The local inode/timestamp token is verified against its own source tree;
 * it is not a portable dependency-graph input. Policy 3 preserves that
 * separate mutation binding while canonicalising its place in the graph. */
#define PROOF_BUILD_GRAPH_DOMAIN "zcl.dev_proof_build_graph.v3"
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
    char prefork_log[PATH_MAX];
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

/* Everything the child action requires of its inputs. A selector belongs to
 * the test dimension and to no other, and every one of the four identity
 * roots must be present: an all-zero root would let two different builds
 * seal the same action. */
static bool dp_child_inputs_ok(
    const struct zcl_dev_proof_child_action_inputs_v1 *inputs,
    enum zcl_dev_proof_dimension_id dimension, const char *operation,
    const char *selector, size_t selector_len)
{
    return inputs && operation && inputs->source_sha256_hex &&
           inputs->source_cas_sha3_hex && selector &&
           inputs->selected != 0 && selector_len <= UINT32_MAX &&
           (dimension == ZCL_DEV_PROOF_TEST) == (selector_len != 0) &&
           proof_root_nonzero(inputs->toolchain_capsule_root) &&
           proof_root_nonzero(inputs->flags_root) &&
           proof_root_nonzero(inputs->environment_root) &&
           proof_root_nonzero(inputs->build_graph_root);
}

static bool dp_child_action_sources(
    const struct zcl_dev_proof_child_action_inputs_v1 *inputs,
    struct vcs_build_action_v1 *action)
{
    return zcl_hex_decode_lower(inputs->source_sha256_hex,
                                action->source_sha256, 32) &&
           zcl_hex_decode_lower(inputs->source_cas_sha3_hex,
                                action->source_cas_sha3, 32) &&
           proof_root_nonzero(action->source_sha256) &&
           proof_root_nonzero(action->source_cas_sha3);
}

/* The action's input root, over the dimension, the build graph, the count
 * this child was handed, and the operation and selector it will run. */
static void dp_child_action_seal(
    const struct zcl_dev_proof_child_action_inputs_v1 *inputs,
    enum zcl_dev_proof_dimension_id dimension, const char *operation,
    const char *selector, struct vcs_build_action_v1 *action)
{
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
}

/* The workdir, declared outputs and resource policy this action kind
 * carries, taken from the one place that defines them. */
static bool dp_child_action_descriptors(struct vcs_build_action_v1 *action)
{
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
    return true;
}

bool zcl_dev_proof_child_action_v1(
    const struct zcl_dev_proof_child_action_inputs_v1 *inputs,
    enum zcl_dev_proof_dimension_id dimension,
    struct vcs_build_action_v1 *action, uint8_t action_root[32])
{
    const char *operation = proof_dimension_operation(dimension);
    const char *selector = inputs ? inputs->selector : NULL;
    size_t selector_len = selector ? strlen(selector) : 0;
    if (!action || !action_root ||
        !dp_child_inputs_ok(inputs, dimension, operation, selector,
                            selector_len))
        return false;
    memset(action, 0, sizeof(*action));
    if (!dp_child_action_sources(inputs, action)) return false;
    dp_child_action_seal(inputs, dimension, operation, selector, action);
    (void)snprintf(action->target, sizeof(action->target), "%s",
                   VCS_BUILD_TARGET_V1);
    (void)snprintf(action->profile, sizeof(action->profile),
                   "resident-proof-child-v1");
    if (!dp_child_action_descriptors(action)) return false;
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

/* Both digests must decode as lowercase hex before any of the body is
 * parsed: a digest this reader cannot decode can never be compared. */
static bool dp_cycle_inputs_ok(
    const char *body, size_t body_len, const char *source_cas,
    const char *proof_inputs_sha3,
    const struct zcl_dev_proof_dimension *dimensions)
{
    uint8_t root[32];
    return body && body_len != 0 && source_cas && proof_inputs_sha3 &&
           dimensions &&
           zcl_hex_decode_lower(source_cas, root, sizeof(root)) &&
           zcl_hex_decode_lower(proof_inputs_sha3, root, sizeof(root));
}

/* Every field the cycle must carry, each exactly once. */
static bool dp_cycle_fields_admitted(
    const struct json_value *cycle, const char *source_cas,
    const char *proof_inputs_sha3,
    const struct zcl_dev_proof_dimension
        dimensions[ZCL_DEV_PROOF_DIMENSIONS])
{
    return cycle_field_true_once(cycle, "proof_complete") &&
           cycle_field_text_once(cycle, "schema", "zcl.dev_cycle.v1") &&
           cycle_field_text_once(cycle, "status", "passed") &&
           cycle_field_text_once(cycle, "phase", "verify") &&
           cycle_field_text_once(cycle, "proof_scope",
                                 "source_wide_compile_tests_lint_fast") &&
           cycle_field_text_once(cycle, "source_cas_sha3", source_cas) &&
           cycle_field_text_once(cycle, "proof_inputs_sha3",
                                 proof_inputs_sha3) &&
           cycle_dimension_roots_exact(cycle, dimensions);
}

bool zcl_dev_proof_cycle_reuse_admissible(
    const char *body, size_t body_len, const char *source_cas,
    const char *proof_inputs_sha3,
    const struct zcl_dev_proof_dimension
        dimensions[ZCL_DEV_PROOF_DIMENSIONS])
{
    struct json_value cycle = {0};
    if (!dp_cycle_inputs_ok(body, body_len, source_cas, proof_inputs_sha3,
                            dimensions) ||
        !json_read(&cycle, body, body_len) || cycle.type != JSON_OBJ) {
        json_free(&cycle);
        return false;
    }
    bool admitted = dp_cycle_fields_admitted(&cycle, source_cas,
                                             proof_inputs_sha3, dimensions);
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

static bool proof_retry_platform(const char *repo_root,
                                 const char *local_commit,
                                 const char *remote_base,
                                 struct zcl_dev_proof_status *out)
{
    return proof_ensure_platform(repo_root, local_commit, remote_base, out);
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

/* The proof path set is filled in four named steps -- the pair identity and
 * the canonical checkout root, the state directories under it, the files
 * named after this exact commit/base pair, and that pair's log files. Every
 * step refuses on the first truncation, exactly as the single chain it
 * replaces did, and a step that refuses leaves the later ones unexecuted. */
static bool dp_paths_root(const char *repo_root, const char *local,
                          const char *base, struct proof_paths *out)
{
    return repo_root && local && base && out && proof_oid_text(local) &&
           proof_oid_text(base) &&
           platform_directory_canonical_real(repo_root, out->root,
                                             sizeof(out->root));
}

static bool dp_paths_state_dirs(struct proof_paths *out)
{
    return snprintf(out->cache, sizeof(out->cache), "%s/.cache",
                    out->root) < (int)sizeof(out->cache) &&
           snprintf(out->state, sizeof(out->state), "%s/zcl-dev-proof",
                    out->cache) < (int)sizeof(out->state) &&
           snprintf(out->receipts, sizeof(out->receipts), "%s/receipts",
                    out->state) < (int)sizeof(out->receipts) &&
           snprintf(out->children, sizeof(out->children), "%s/children",
                    out->state) < (int)sizeof(out->children) &&
           snprintf(out->logs, sizeof(out->logs), "%s/logs",
                    out->state) < (int)sizeof(out->logs) &&
           snprintf(out->requests, sizeof(out->requests), "%s/requests",
                    out->state) < (int)sizeof(out->requests) &&
           snprintf(out->attempts, sizeof(out->attempts), "%s/attempts",
                    out->state) < (int)sizeof(out->attempts) &&
           snprintf(out->leases, sizeof(out->leases), "%s/leases",
                    out->state) < (int)sizeof(out->leases);
}

static bool dp_paths_pair_files(struct proof_paths *out, const char *local,
                                const char *base)
{
    return snprintf(out->key, sizeof(out->key), "%s-%s", local,
                    base) < (int)sizeof(out->key) &&
           snprintf(out->receipt, sizeof(out->receipt), "%s/%s.receipt",
                    out->receipts, out->key) < (int)sizeof(out->receipt) &&
           snprintf(out->lock, sizeof(out->lock), "%s/%s.running",
                    out->state, out->key) < (int)sizeof(out->lock) &&
           snprintf(out->request, sizeof(out->request), "%s/%s.request",
                    out->requests, out->key) < (int)sizeof(out->request) &&
           snprintf(out->lease, sizeof(out->lease), "%s/%s.lease",
                    out->leases, out->key) < (int)sizeof(out->lease) &&
           snprintf(out->queue_lock, sizeof(out->queue_lock), "%s/queue.lock",
                    out->state) < (int)sizeof(out->queue_lock) &&
           snprintf(out->failure, sizeof(out->failure), "%s/%s.failed",
                    out->state, out->key) < (int)sizeof(out->failure) &&
           snprintf(out->changed, sizeof(out->changed), "%s/%s.files",
                    out->state, out->key) < (int)sizeof(out->changed);
}

static bool dp_paths_log_files(struct proof_paths *out)
{
    return snprintf(out->bundle_log, sizeof(out->bundle_log),
                    "%s/%s.bundle.log", out->logs,
                    out->key) < (int)sizeof(out->bundle_log) &&
           snprintf(out->prefork_log, sizeof(out->prefork_log),
                    "%s/%s.prefork.log", out->logs,
                    out->key) < (int)sizeof(out->prefork_log) &&
           snprintf(out->phases, sizeof(out->phases), "%s/%s.phases.txt",
                    out->state, out->key) < (int)sizeof(out->phases) &&
           snprintf(out->warmstart, sizeof(out->warmstart), "%s/%s.warmstart",
                    out->state, out->key) < (int)sizeof(out->warmstart);
}

static bool proof_paths_fill(const char *repo_root, const char *local,
                             const char *base, struct proof_paths *out)
{
    return dp_paths_root(repo_root, local, base, out) &&
           dp_paths_state_dirs(out) &&
           dp_paths_pair_files(out, local, base) &&
           dp_paths_log_files(out);
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

/* One side of the pair: a caller-supplied commit is only checked for shape,
 * an omitted one is read from git. The two refusal strings differ per side
 * and per cause, so both are named by the caller rather than derived. */
static bool dp_resolve_commit(const char *repo_root, const char *requested,
                              const char *const argv[],
                              const char *invalid_why,
                              const char *unavailable_why,
                              char out[65], char *why, size_t why_len)
{
    if (requested && requested[0]) {
        if (!proof_oid_text(requested)) {
            proof_why(why, why_len, invalid_why);
            return false;
        }
        (void)snprintf(out, 65, "%s", requested);
        return true;
    }
    if (!git_capture(repo_root, argv, out, 65) || !proof_oid_text(out)) {
        proof_why(why, why_len, unavailable_why);
        return false;
    }
    return true;
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
    const char *local_argv[] = {"git", "rev-parse", "--verify", "HEAD", NULL};
    const char *base_argv[] = {"git", "rev-parse", "--verify",
                               "refs/remotes/origin/main", NULL};
    if (!dp_resolve_commit(repo_root, requested_local, local_argv,
                           "local_commit_invalid", "local_commit_unavailable",
                           local_commit, why, why_len))
        return false;
    if (!dp_resolve_commit(repo_root, requested_base, base_argv,
                           "remote_base_invalid", "origin_main_unavailable",
                           remote_base, why, why_len))
        return false;
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
/* One sidecar line, assigned to whichever of the three fields it names.
 * An unrecognised key is ignored, as it always was. */
static void dp_warm_sidecar_field(const char *line, char *warm_flag,
                                  char donor[33], char reason[24])
{
    if (strncmp(line, "warm=", 5) == 0)
        *warm_flag = line[5];
    else if (strncmp(line, "donor=", 6) == 0)
        (void)snprintf(donor, 33, "%s", line + 6);
    else if (strncmp(line, "reason=", 7) == 0)
        (void)snprintf(reason, 24, "%s", line + 7);
}

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
    while ((line = strtok_r(NULL, "\n", &save)))
        dp_warm_sidecar_field(line, &warm_flag, donor, reason);
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

/* A request file is exactly five lines: the schema, the two commit ids, and
 * the two clocks. Splitting, shape-checking and clock-parsing are three
 * separate refusals, so a caller reading this code can see which of the
 * three a malformed request tripped. */
static size_t dp_request_split(char *text, char *lines[5])
{
    char *save = NULL;
    size_t count = 0;
    for (char *line = strtok_r(text, "\n", &save); line && count < 5;
         line = strtok_r(NULL, "\n", &save))
        lines[count++] = line;
    return count;
}

static bool dp_request_shape_ok(char *const lines[5], size_t count)
{
    return count == 5 &&
           strcmp(lines[0], "zcl.dev_proof_request.v1") == 0 &&
           proof_oid_text(lines[1]) && proof_oid_text(lines[2]);
}

static bool dp_request_stamps(const char *wall_text, const char *mono_text,
                              int64_t *wall_out, int64_t *monotonic_out)
{
    char *wall_end = NULL, *mono_end = NULL;
    errno = 0;
    long long wall = strtoll(wall_text, &wall_end, 10);
    bool wall_ok = errno == 0 && wall_end && *wall_end == 0 && wall > 0;
    errno = 0;
    long long mono = strtoll(mono_text, &mono_end, 10);
    if (!wall_ok || errno != 0 || !mono_end || *mono_end != 0 || mono <= 0)
        return false;
    if (wall_out) *wall_out = (int64_t)wall;
    if (monotonic_out) *monotonic_out = (int64_t)mono;
    return true;
}

static bool proof_request_read(const char *path, char local[65], char base[65],
                               int64_t *wall_out, int64_t *monotonic_out)
{
    char text[320], *lines[5];
    if (!proof_private_regular(path) ||
        !proof_read_text(path, text, sizeof(text)))
        return false;
    size_t count = dp_request_split(text, lines);
    if (!dp_request_shape_ok(lines, count)) return false;
    int64_t wall = 0, mono = 0;
    if (!dp_request_stamps(lines[3], lines[4], &wall, &mono)) return false;
    (void)snprintf(local, 65, "%s", lines[1]);
    (void)snprintf(base, 65, "%s", lines[2]);
    if (wall_out) *wall_out = wall;
    if (monotonic_out) *monotonic_out = mono;
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
static bool proof_failure_bytes(const char *path, uint8_t bytes[256],
                                 size_t *size)
{
    struct stat st;
    if (lstat(path, &st) != 0 || st.st_size <= 0 || st.st_size > 256 ||
        !read_exact_file(path, bytes, (size_t)st.st_size))
        return false;
    *size = (size_t)st.st_size;
    return true;
}

/* Any existing archive, including unreadable/unsafe evidence, disallows a
 * legacy mtime guess. A crash may leave newer attempt logs or an archive
 * without ever updating the pair marker. Only matching bytes bind them. */
static bool dp_attempt_failure_matches(const char *attempt,
                                        const uint8_t *failure, size_t size,
                                        bool *archives_seen)
{
    char logs[PATH_MAX], archive[PATH_MAX];
    struct stat st;
    if (snprintf(logs, sizeof(logs), "%s/logs", attempt) >= (int)sizeof(logs) ||
        lstat(logs, &st) != 0 || !S_ISDIR(st.st_mode) ||
        snprintf(archive, sizeof(archive), "%s/failure.txt", logs) >=
            (int)sizeof(archive)) {
        *archives_seen = true;
        return false;
    }
    if (lstat(archive, &st) != 0 && errno == ENOENT) return false;
    *archives_seen = true;
    uint8_t bytes[256];
    return read_exact_file(archive, bytes, size) &&
           memcmp(bytes, failure, size) == 0;
}

/* Highest-mtime matching attempt. With no failure filter, this is the
 * legacy selection used only when no archived failure records exist. */
static bool dp_attempt_dir_pick(DIR *dir, const char *attempts,
                                const char *prefix, size_t prefix_len,
                                const uint8_t *failure, size_t failure_size,
                                bool *archives_seen,
                                char newest[PATH_MAX])
{
    bool found = false;
    struct timespec newest_mtime = {0};
    for (struct dirent *entry = readdir(dir); entry; entry = readdir(dir)) {
        if (strncmp(entry->d_name, prefix, prefix_len) != 0)
            continue;
        char candidate[PATH_MAX];
        if (snprintf(candidate, sizeof(candidate), "%s/%s", attempts,
                    entry->d_name) >= (int)sizeof(candidate))
            continue;
        struct stat st;
        if (lstat(candidate, &st) != 0 || !S_ISDIR(st.st_mode)) continue;
        if (failure && !dp_attempt_failure_matches(candidate, failure,
                                                    failure_size, archives_seen))
            continue;
        if (!found || st.st_mtim.tv_sec > newest_mtime.tv_sec ||
            (st.st_mtim.tv_sec == newest_mtime.tv_sec &&
             st.st_mtim.tv_nsec > newest_mtime.tv_nsec)) {
            found = true;
            newest_mtime = st.st_mtim;
            (void)snprintf(newest, PATH_MAX, "%s", candidate);
        }
    }
    return found;
}

static bool proof_failure_attempt_logs(const struct proof_paths *paths,
                                       char *out, size_t out_len,
                                       bool *archive_conflict)
{
    if (archive_conflict) *archive_conflict = false;
    if (!paths || !out || out_len == 0) return false;
    uint8_t failure[256];
    size_t size = 0;
    if (!proof_failure_bytes(paths->failure, failure, &size)) return false;
    char prefix[160];
    int prefix_len = snprintf(prefix, sizeof(prefix), "%s.", paths->key);
    if (prefix_len <= 0 || prefix_len >= (int)sizeof(prefix)) return false;
    DIR *dir = opendir(paths->attempts);
    if (!dir) return false;
    char newest[PATH_MAX] = {0};
    bool archives_seen = false;
    bool found = dp_attempt_dir_pick(dir, paths->attempts, prefix,
                                     (size_t)prefix_len, failure, size,
                                     &archives_seen, newest);
    if (!found && !archives_seen) {
        rewinddir(dir);
        found = dp_attempt_dir_pick(dir, paths->attempts, prefix,
                                    (size_t)prefix_len, NULL, 0,
                                    &archives_seen, newest);
    }
    (void)closedir(dir);
    if (!found) {
        if (archive_conflict) *archive_conflict = archives_seen;
        return false;
    }
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
    (void)snprintf(out->root, sizeof(out->root), "%s", paths.root);
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
        (void)proof_failure_attempt_logs(&paths, out->log_dir,
                                         sizeof(out->log_dir), NULL);
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
        snprintf(attempt->prefork_log, sizeof(attempt->prefork_log),
                 "%s/logs/prefork.log", attempt->attempt) >=
            (int)sizeof(attempt->prefork_log) ||
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

/* Ask git for the changed list and read it back whole. Returns the buffer
 * the caller owns, or NULL with `why` already set. */
static char *dp_changed_set_fetch(const char *repo_root, const char *base,
                                  const char *local, const char *scratch_path,
                                  size_t *len_out, char *why, size_t why_len)
{
    if (!repo_root || !base || !local || !scratch_path || !scratch_path[0]) {
        proof_why(why, why_len, "changed_set_request_invalid");
        return NULL;
    }
    const char *ancestor[] = {"git", "merge-base", "--is-ancestor", base,
                              local, NULL};
    char ignored[2];
    if (!git_capture(repo_root, ancestor, ignored, sizeof(ignored))) {
        proof_why(why, why_len, "remote_base_not_ancestor");
        return NULL;
    }
    /* `--output` sends the list to a file instead of the fixed-size process
     * capture buffer, so a batch of thousands of paths cannot arrive as a
     * shorter list that still parses. */
    char output_arg[PATH_MAX + 16];
    if (snprintf(output_arg, sizeof(output_arg), "--output=%s", scratch_path) >=
        (int)sizeof(output_arg)) {
        proof_why(why, why_len, "changed_set_request_invalid");
        return NULL;
    }
    (void)unlink(scratch_path);
    const char *argv[] = {"git", "diff", "--name-only", "--diff-filter=ACMRD",
                          output_arg, base, local, "--", NULL};
    if (!git_capture(repo_root, argv, ignored, sizeof(ignored))) {
        (void)unlink(scratch_path);
        proof_why(why, why_len, "changed_set_unavailable_or_truncated");
        return NULL;
    }
    char *bytes = changed_set_read(scratch_path, len_out, why, why_len);
    (void)unlink(scratch_path);
    return bytes;
}

/* How many rows the buffer holds, counted before anything is stored so an
 * over-ceiling batch is refused with its real size. */
static size_t dp_changed_set_count(const char *bytes, size_t len)
{
    size_t count = 0;
    for (size_t i = 0; i < len; i++) {
        if (bytes[i] == '\n')
            continue;
        count++;
        while (i < len && bytes[i] != '\n')
            i++;
    }
    return count;
}

/* Point one reference per row into the buffer. An absolute path, a `..`
 * escape, a backslash, an over-long path, or more rows than the count
 * promised refuses the whole set with the row that did it. */
static bool dp_changed_set_rows(char *bytes, size_t count, const char **refs,
                                size_t *persist_len, char *why,
                                size_t why_len)
{
    size_t stored = 0;
    char *save = NULL;
    for (char *line = strtok_r(bytes, "\n", &save); line;
         line = strtok_r(NULL, "\n", &save)) {
        size_t path_len = strlen(line);
        if (path_len == 0)
            continue;
        if (stored >= count || path_len >= PROOF_CHANGED_PATH_MAX ||
            line[0] == '/' || strstr(line, "..") || strchr(line, '\\')) {
            proof_whyf(why, why_len,
                       "changed_set_invalid_or_truncated row=%zu", stored + 1);
            return false;
        }
        refs[stored++] = line;
        *persist_len += path_len + 1;
    }
    if (stored != count) {
        proof_whyf(why, why_len,
                   "changed_set_invalid_or_truncated rows=%zu of %zu", stored,
                   count);
        return false;
    }
    return true;
}

/* Write the accepted list beside the proof state, newline-terminated and
 * read-only. No persist path asked for means nothing to do. */
static bool dp_changed_set_persist(const char *persist_path,
                                   const char **refs, size_t count,
                                   size_t persist_len, char *why,
                                   size_t why_len)
{
    if (!persist_path || !persist_path[0]) return true;
    char *persisted = zcl_calloc(persist_len, 1, "proof changed-set record");
    if (!persisted) {
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
        proof_why(why, why_len, "changed_set_persist_failed");
        return false;
    }
    return true;
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
    size_t len = 0;
    char *bytes = dp_changed_set_fetch(repo_root, base, local, scratch_path,
                                       &len, why, why_len);
    if (!bytes)
        return false;
    size_t count = dp_changed_set_count(bytes, len);
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
    size_t persist_len = 0;
    if (!dp_changed_set_rows(bytes, count, refs, &persist_len, why,
                             why_len) ||
        !dp_changed_set_persist(persist_path, refs, count, persist_len, why,
                                why_len)) {
        free((void *)refs);
        free(bytes);
        return false;
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
/* The names split by what the failure is about: the first group is the
 * path -- how it is spelled, what it resolves to, what may be done with it
 * -- and the second is the store behind it. Neither group knows the
 * fallback text; only proof_errno_name below names it. */
static const char *dp_errno_name_path(int value)
{
    switch (value) {
    case EACCES: return "EACCES";
    case EEXIST: return "EEXIST";
    case EINVAL: return "EINVAL";
    case EISDIR: return "EISDIR";
    case ELOOP: return "ELOOP";
    case EMLINK: return "EMLINK";
    case ENAMETOOLONG: return "ENAMETOOLONG";
    case ENOENT: return "ENOENT";
    case ENOTDIR: return "ENOTDIR";
    case EPERM: return "EPERM";
    default: return NULL;
    }
}

static const char *dp_errno_name_store(int value)
{
    switch (value) {
    case EDQUOT: return "EDQUOT";
    case EIO: return "EIO";
    case ENOMEM: return "ENOMEM";
    case ENOSPC: return "ENOSPC";
    case EROFS: return "EROFS";
    case EXDEV: return "EXDEV";
    default: return NULL;
    }
}

static const char *proof_errno_name(int value)
{
    if (value == 0) return "no errno";
    const char *name = dp_errno_name_path(value);
    if (!name) name = dp_errno_name_store(value);
    return name ? name : "unrecognised errno";
}

/* Every generation owns independent dependency inodes. Creating another
 * hardlink changes the shared inode's ctime, invalidating an in-flight proof
 * even when its source bytes are unchanged. Clone when the platform supports
 * it, otherwise copy bytes; never link a donor into a live generation.
 * The mode carries: a hook or a .so that arrived without its executable
 * bit fails far away from here, where the cause is no longer visible.
 *
 * The MODIFICATION TIME carries for the same reason. A copy that stamps the
 * target with the time of the copy hands the
 * generation an artifact that is newer than every source it was built from,
 * and make inside the generation then declares a stale artifact up to date
 * and never rebuilds it. That is not a hypothetical: a hot-swap fixture image
 * copied this way kept the consensus core seal of an older build and every
 * activation in the generation was rejected on shape. */
/* `<target>.tmp.XXXXXX`, opened. Every copy in this file lands on a
 * temporary beside its target and is renamed over it, so a reader never
 * sees a half-written dependency. */
static bool dp_copy_temp_open(const char *target, char temporary[PATH_MAX],
                              int *output)
{
    int temporary_len = snprintf(temporary, PATH_MAX, "%s.tmp.XXXXXX",
                                 target);
    bool ok = temporary_len > 0 && temporary_len < PATH_MAX;
    *output = ok ? mkstemp(temporary) : -1;
    return *output >= 0;
}

/* Read-to-write until end of file. A short read is not an error and EINTR
 * is not a short read. */
static bool dp_copy_bytes(int input, int output)
{
    unsigned char buffer[65536];
    for (;;) {
        ssize_t got = read(input, buffer, sizeof(buffer));
        if (got < 0 && errno == EINTR) continue;
        if (got < 0) return false;
        if (got == 0) return true;
        if (!write_all(output, buffer, (size_t)got)) return false;
    }
}

/* Carry the source's mode and timestamps onto the copy, then close it. All
 * three are attempted whatever the first one does, so the descriptor is
 * never left open on a partial failure. */
static bool dp_copy_stamp_close(int output, const struct stat *source_st)
{
    bool ok = true;
    if (fchmod(output, source_st->st_mode & 07777) != 0) ok = false;
    const struct timespec times[2] = {
        source_st->st_atim, source_st->st_mtim,
    };
    if (futimens(output, times) != 0) ok = false;
    if (close(output) != 0) ok = false;
    return ok;
}

/* A fresh copy owns no source metadata: it gets the caller's owner-only
 * mode and the time of the copy. Both steps run whatever the first does. */
static bool dp_copy_mode_close(int output, mode_t mode)
{
    bool ok = true;
    if (fchmod(output, mode) != 0) ok = false;
    if (close(output) != 0) ok = false;
    return ok;
}

/* Drop the temporary and restore the errno that named the real cause: the
 * cleanup itself must not become the diagnosis. */
static void dp_copy_temp_discard(int output, const char *temporary, int saved)
{
    if (output >= 0) (void)unlink(temporary);
    if (errno == 0) errno = saved;
}

static bool dependency_copy_stat(const char *source, const char *target,
                                 const struct stat *source_st)
{
    int input = open(source, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (input < 0) return false;
    char temporary[PATH_MAX];
    int output = -1;
    bool ok = dp_copy_temp_open(target, temporary, &output);
    enum platform_file_clone_result cloned = PLATFORM_FILE_CLONE_UNAVAILABLE;
    if (ok) cloned = platform_file_clone_fd(input, output);
    if (cloned == PLATFORM_FILE_CLONE_REFUSED) {
        errno = EIO;
        ok = false;
    }
    if (ok && cloned == PLATFORM_FILE_CLONE_UNAVAILABLE)
        ok = dp_copy_bytes(input, output);
    int saved = errno;
    if (close(input) != 0) ok = false;
    if (output >= 0 && !dp_copy_stamp_close(output, source_st)) ok = false;
    if (ok && rename(temporary, target) != 0) ok = false;
    if (!ok) dp_copy_temp_discard(output, temporary, saved);
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
    return dependency_copy_stat(source, target, source_st) ? 0 : -1;
}

/* `<dir>/<name>` for both sides of a recursive walk, refusing rather than
 * truncating either. */
static bool dp_child_paths(const char *source, const char *target,
                           const char *name, char child_source[PATH_MAX],
                           char child_target[PATH_MAX])
{
    return snprintf(child_source, PATH_MAX, "%s/%s", source,
                    name) < PATH_MAX &&
           snprintf(child_target, PATH_MAX, "%s/%s", target,
                    name) < PATH_MAX;
}

/* A symlink standing where a real dependency belongs is removed first: a
 * copy through it would write outside the generation. */
static bool dp_materialize_clear_link(const char *target,
                                      const struct stat *target_st,
                                      bool *target_exists)
{
    if (!*target_exists || !S_ISLNK(target_st->st_mode)) return true;
    if (unlink(target) != 0) return false;
    *target_exists = false;
    return true;
}

static bool dp_materialize_regular(const char *source, const char *target,
                                   const struct stat *source_st)
{
    /* The temporary copy replaces an old shared inode only
     * after the source is open and the independent copy is complete. */
    if (dependency_seed(source, target, source_st) == 0) return true;
    /* Same filesystem is the fast path; a cross-device generation root is
     * not a missing dependency, so copy rather than refuse. */
    if (errno != EXDEV && errno != EPERM && errno != EMLINK) return false;
    return dependency_copy_stat(source, target, source_st);
}

static bool dp_source_parent(const char *source, char parent[PATH_MAX])
{
    size_t len = strlen(source);
    if (len >= PATH_MAX) {
        errno = ENAMETOOLONG;
        return false;
    }
    memcpy(parent, source, len + 1);
    char *slash = strrchr(parent, '/');
    if (!slash) strcpy(parent, ".");
    else if (slash == parent) slash[1] = 0;
    else *slash = 0;
    return true;
}

static bool dp_path_inside_root(const char *root, const char *path)
{
    size_t len = strlen(root);
    return strcmp(root, "/") == 0 ||
           (strncmp(root, path, len) == 0 &&
            (path[len] == 0 || path[len] == '/'));
}

/* Check every resolved prefix, not just the endpoint: a relative link can
 * leave the selected tree and reenter it, then point back into the submitting
 * checkout when its original spelling is recreated in the generation.
 * Resolving prefixes also accounts for directory aliases changing the depth
 * at which a subsequent `..` is interpreted. */
static bool dp_link_prefixes_inside(const char *source, const char *link_text,
                                    const char *source_root)
{
    char prefix[PATH_MAX], resolved[PATH_MAX];
    if (!dp_source_parent(source, prefix)) return false;
    for (const char *part = link_text; *part;) {
        size_t len = strcspn(part, "/");
        if (len == 0) { part++; continue; }
        size_t used = strlen(prefix);
        int added = snprintf(prefix + used, sizeof(prefix) - used,
                              "/%.*s", (int)len, part);
        if (added < 0 || (size_t)added >= sizeof(prefix) - used) {
            errno = ENAMETOOLONG;
            return false;
        }
        if (!realpath(prefix, resolved)) return false;
        if (!dp_path_inside_root(source_root, resolved)) {
            errno = EACCES;
            return false;
        }
        part += len;
    }
    /* The original spelling also carries a terminal slash's directory
     * requirement, which component traversal alone would discard. */
    if (!realpath(source, resolved)) return false;
    if (!dp_path_inside_root(source_root, resolved)) {
        errno = EACCES;
        return false;
    }
    return true;
}

/* Preserve relative link bytes only after their resolution has been checked
 * against the original selected dependency root, retained across recursion.
 * This remains a pathname snapshot; proof input identity checks still guard
 * source mutation before and after the generation's work. */
static bool dp_materialize_symlink(const char *source, const char *target,
                                   bool target_exists, const char *source_root)
{
    char link_target[PATH_MAX];
    ssize_t len = readlink(source, link_target, sizeof(link_target) - 1);
    if (len < 0) return false;
    if (len == 0 || (size_t)len >= sizeof(link_target) - 1) {
        errno = len == 0 ? EINVAL : ENAMETOOLONG;
        return false;
    }
    link_target[len] = 0;
    if (link_target[0] == '/') {
        errno = EACCES;
        return false;
    }
    if (!dp_link_prefixes_inside(source, link_target, source_root)) return false;
    if (target_exists && unlink(target) != 0) return false;
    return symlink(link_target, target) == 0;
}

static bool dp_materialize_dir_ensure(const struct stat *source_st,
                                      const char *target,
                                      const struct stat *target_st,
                                      bool target_exists)
{
    return S_ISDIR(source_st->st_mode) &&
           (!target_exists || S_ISDIR(target_st->st_mode)) &&
           (target_exists || mkdir(target, 0700) == 0);
}

static bool dependency_materialize_at(const char *source, const char *target,
                                      const char *source_root)
{
    struct stat source_st, target_st;
    if (lstat(source, &source_st) != 0) return false;
    bool target_exists = lstat(target, &target_st) == 0;
    if (!dp_materialize_clear_link(target, &target_st, &target_exists))
        return false;
    if (S_ISREG(source_st.st_mode))
        return dp_materialize_regular(source, target, &source_st);
    if (S_ISLNK(source_st.st_mode))
        return dp_materialize_symlink(source, target, target_exists, source_root);
    if (!dp_materialize_dir_ensure(&source_st, target, &target_st,
                                   target_exists))
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
        if (!dp_child_paths(source, target, entry->d_name, child_source,
                            child_target) ||
            !dependency_materialize_at(child_source, child_target, source_root)) {
            ok = false;
            break;
        }
    }
    int saved = errno;
    int closed = closedir(dir);
    if (!ok) errno = saved;
    return closed == 0 && ok;
}

static bool dependency_materialize(const char *source, const char *target)
{
    struct stat source_st;
    char source_root[PATH_MAX], parent[PATH_MAX];
    if (lstat(source, &source_st) != 0) return false;
    const char *root = source;
    if (!S_ISDIR(source_st.st_mode)) {
        if (!dp_source_parent(source, parent)) return false;
        root = parent;
    }
    if (!realpath(root, source_root)) return false;
    return dependency_materialize_at(source, target, source_root);
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
    int output = -1;
    bool ok = fstat(input, &st) == 0 && S_ISREG(st.st_mode) &&
        dp_copy_temp_open(target, temporary, &output);
    if (ok) ok = dp_copy_bytes(input, output);
    if (close(input) != 0) ok = false;
    if (output >= 0 && !dp_copy_mode_close(output, 0600)) ok = false;
    if (ok && rename(temporary, target) != 0) ok = false;
    if (!ok && output >= 0) (void)unlink(temporary);
    return ok;
}

/* The mirror directory this level of the walk copies into. */
static bool dp_depfile_dir_ensure(const char *target)
{
    if (!dependency_parent_ensure(target)) return false;
    struct stat target_st;
    if (lstat(target, &target_st) != 0)
        return errno == ENOENT && mkdir(target, 0700) == 0;
    return S_ISDIR(target_st.st_mode) && !S_ISLNK(target_st.st_mode);
}

static bool dp_depfile_name(const char *name)
{
    return strlen(name) > 2 && strcmp(name + strlen(name) - 2, ".d") == 0;
}

/* Copy one depfile and fold its repo-relative path and content digest into
 * the running root, in that order. Nothing is folded in unless the copy and
 * the hash both succeeded. */
static bool dp_depfile_take(const char *child_source, const char *child_target,
                            size_t source_root_len, struct sha3_256_ctx *root,
                            size_t *count)
{
    uint8_t digest[32];
    if (!dependency_copy_fresh(child_source, child_target) ||
        !hash_file("zcl.dev_proof_depfile.v1", child_source, digest))
        return false;
    const char *relative = child_source + source_root_len;
    if (*relative == '/') relative++;
    sha3_256_write(root, (const uint8_t *)relative, strlen(relative) + 1);
    sha3_256_write(root, digest, sizeof(digest));
    (*count)++;
    return true;
}

/* One directory entry: recurse, take a depfile, or ignore it. */
static bool dp_depfile_entry(const char *child_source,
                            const char *child_target, const char *name,
                            size_t source_root_len, struct sha3_256_ctx *root,
                            size_t *count, bool *recurse)
{
    *recurse = false;
    struct stat st;
    if (lstat(child_source, &st) != 0) return false;
    if (S_ISDIR(st.st_mode)) {
        *recurse = true;
        return true;
    }
    if (S_ISREG(st.st_mode) && dp_depfile_name(name))
        return dp_depfile_take(child_source, child_target, source_root_len,
                               root, count);
    return true;
}

static bool depfile_tree_copy(const char *source, const char *target,
                              size_t source_root_len,
                              struct sha3_256_ctx *root, size_t *count)
{
    if (!dp_depfile_dir_ensure(target)) return false;
    DIR *dir = opendir(source);
    if (!dir) return false;
    bool ok = true;
    for (struct dirent *entry = readdir(dir); ok && entry;
         entry = readdir(dir)) {
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0)
            continue;
        char child_source[PATH_MAX], child_target[PATH_MAX];
        if (!dp_child_paths(source, target, entry->d_name, child_source,
                            child_target)) {
            ok = false;
            break;
        }
        bool recurse = false;
        ok = dp_depfile_entry(child_source, child_target, entry->d_name,
                              source_root_len, root, count, &recurse);
        if (ok && recurse)
            ok = depfile_tree_copy(child_source, child_target, source_root_len,
                                   root, count);
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

/* How many generation directories the pool already holds. Read only when a
 * RAM reservation was refused: the log line names the count so a full pool
 * is diagnosable from the log alone instead of a manual `ls` weeks later. */
static size_t generation_dir_count(const char *parent)
{
    DIR *dir = opendir(parent);
    if (!dir) return 0;
    size_t count = 0;
    for (struct dirent *entry = readdir(dir); entry; entry = readdir(dir)) {
        if (warm_tag_name(entry->d_name)) count++;
    }
    (void)closedir(dir);
    return count;
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
    int output = -1;
    bool ok = fstat(input, &st) == 0 && S_ISREG(st.st_mode) &&
        dp_copy_temp_open(target, temporary, &output);
    if (ok) ok = dp_copy_bytes(input, output);
    if (close(input) != 0) ok = false;
    if (output >= 0 && !dp_copy_mode_close(output, 0700)) ok = false;
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

/* The walk creates its own target directory chain: readdir order is
 * unspecified, so a file may precede its directory, and the caller
 * may hand down a root whose own parents do not exist yet (the seam
 * test seeds into a bare fixture). dependency_parent_ensure builds
 * the ancestors; the mkdir takes the directory itself. */
static bool dp_seed_dir_ensure(const char *gen_dir)
{
    struct stat gen_dir_st;
    if (lstat(gen_dir, &gen_dir_st) != 0) {
        char probe[PATH_MAX];
        if (errno != ENOENT ||
            snprintf(probe, sizeof(probe), "%s/_", gen_dir) >=
                (int)sizeof(probe) ||
            !dependency_parent_ensure(probe) ||
            (mkdir(gen_dir, 0700) != 0 && errno != EEXIST) ||
            lstat(gen_dir, &gen_dir_st) != 0)
            return false;
    }
    return S_ISDIR(gen_dir_st.st_mode) && !S_ISLNK(gen_dir_st.st_mode);
}

/* The three names one entry needs: its path relative to the seed root, and
 * the donor and generation sides of it. Truncation fails the whole seed. */
static bool dp_seed_child_paths(const char *rel_prefix, const char *name,
                                const char *donor_dir, const char *gen_dir,
                                char rel[PATH_MAX], char donor_child[PATH_MAX],
                                char gen_child[PATH_MAX])
{
    int rel_len = rel_prefix && rel_prefix[0]
        ? snprintf(rel, PATH_MAX, "%s/%s", rel_prefix, name)
        : snprintf(rel, PATH_MAX, "%s", name);
    return rel_len > 0 && rel_len < PATH_MAX &&
           snprintf(donor_child, PATH_MAX, "%s/%s", donor_dir,
                    name) < PATH_MAX &&
           snprintf(gen_child, PATH_MAX, "%s/%s", gen_dir, name) < PATH_MAX;
}

/* Whether the generation side of a donor subdirectory is a real directory
 * this walk may descend into. */
static bool dp_seed_subdir_ready(const char *gen_child)
{
    struct stat gen_st;
    if (lstat(gen_child, &gen_st) != 0)
        return errno == ENOENT && mkdir(gen_child, 0700) == 0;
    return S_ISDIR(gen_st.st_mode) && !S_ISLNK(gen_st.st_mode);
}

static void dp_seed_regular(const char *donor_child, const char *gen_child,
                            const char *rel, bool copy_wrapper,
                            const struct stat *donor_st,
                            struct warm_seed_accum *accum)
{
    enum warm_seed_class class = warm_classify_rel(rel, true);
    if (class == WARM_SEED_SKIP) return;
    /* The wrapper copy is caller-gated (bootstrap inputs must be
     * unchanged); link-class outputs need no gate beyond the epoch. */
    if (class == WARM_SEED_COPY && !copy_wrapper) return;
    if (!dependency_parent_ensure(gen_child)) return;
    warm_seed_file(donor_child, gen_child, rel, class, donor_st, accum);
}

/* One donor entry. Returns false only when the whole seed must fail;
 * `*descend` says the caller should recurse into the paths it filled in. */
static bool dp_seed_entry(const char *donor_dir, const char *gen_dir,
                          const char *rel_prefix, const char *name,
                          bool copy_wrapper, struct warm_seed_accum *accum,
                          char rel[PATH_MAX], char donor_child[PATH_MAX],
                          char gen_child[PATH_MAX], bool *descend)
{
    *descend = false;
    if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0) return true;
    if (!dp_seed_child_paths(rel_prefix, name, donor_dir, gen_dir, rel,
                             donor_child, gen_child))
        return false;
    struct stat donor_st;
    if (lstat(donor_child, &donor_st) != 0) return true;
    if (S_ISLNK(donor_st.st_mode)) return true;
    if (S_ISDIR(donor_st.st_mode)) {
        /* Hidden directories (.leases, staging, admission) are live
         * machinery: do not recreate them, do not descend. */
        if (warm_path_hidden(rel)) return true;
        *descend = dp_seed_subdir_ready(gen_child);
        return true;
    }
    if (!S_ISREG(donor_st.st_mode)) return true;
    dp_seed_regular(donor_child, gen_child, rel, copy_wrapper, &donor_st,
                    accum);
    return true;
}

static void warm_seed_walk(const char *donor_dir, const char *gen_dir,
                           const char *rel_prefix, bool copy_wrapper,
                           struct warm_seed_accum *accum)
{
    if (!accum || accum->failed) return;
    if (!dp_seed_dir_ensure(gen_dir)) {
        accum->failed = true;
        return;
    }
    DIR *dir = opendir(donor_dir);
    if (!dir) return;
    for (struct dirent *entry = readdir(dir); entry;
         entry = readdir(dir)) {
        char rel[PATH_MAX], donor_child[PATH_MAX], gen_child[PATH_MAX];
        bool descend = false;
        if (accum->failed) break;
        if (!dp_seed_entry(donor_dir, gen_dir, rel_prefix, entry->d_name,
                           copy_wrapper, accum, rel, donor_child, gen_child,
                           &descend)) {
            accum->failed = true;
            break;
        }
        if (descend)
            warm_seed_walk(donor_child, gen_child, rel, copy_wrapper, accum);
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
 * whole reason two boxes can compare receipts at all. BASE_GENERATION is
 * retained canonically in the graph and returned separately for verification
 * against its own tree: inode/timestamp identity cannot survive a copy. */
/* `make dev-bin` is the sole writer of the plan file (dev-linker-select.sh
 * plus the dev build's restart-env generator); a fresh `git worktree
 * add` checkout never ran it, and ten proof attempts folding this into
 * "proof_toolchain_or_policy_unavailable" never said so. Name the path
 * and the exact command the same way the vendor dependency check
 * further down names its own missing input. */
static void dp_plan_missing_why(const char *path, int saved, char *why,
                                size_t why_len)
{
    if (saved == ENOENT)
        proof_whyf(why, why_len, "restart_env_missing:%s (make dev-bin)",
                   path);
    else
        proof_whyf(why, why_len, "restart_env_unreadable:%s (%s)", path,
                   proof_errno_name(saved));
}

/* The build plan, whole. An empty read or one that filled the buffer is
 * refused rather than hashed. */
static bool dp_plan_body_read(const char *path, char *body, size_t body_size,
                              char *why, size_t why_len)
{
    errno = 0;
    FILE *f = fopen(path, "rb");
    if (!f) {
        dp_plan_missing_why(path, errno, why, why_len);
        return false;
    }
    size_t n = fread(body, 1, body_size - 1, f);
    bool ok = !ferror(f) && n > 0 && n < body_size - 1;
    fclose(f);
    if (!ok) return false;
    body[n] = 0;
    return true;
}

/* The local mutation token, which must appear exactly once and must be a
 * 64-character lowercase hex digest. */
static bool dp_plan_mutation_take(const char *value, bool *mutation_seen,
                                  char *mutation)
{
    uint8_t decoded[32];
    if (*mutation_seen || strlen(value) != 64 ||
        !zcl_hex_decode_lower(value, decoded, sizeof(decoded))) {
        fprintf(stderr, "[devproof] build plan: invalid or duplicate local mutation token\n");
        return false;
    }
    *mutation_seen = true;
    if (mutation) memcpy(mutation, value, 65);
    return true;
}

/* One KEY=VALUE plan line, folded into whichever of the two roots owns it.
 * The mutation token is folded in by name only; its value is verified
 * against its own tree, never carried into a portable root. */
static bool dp_plan_line(char *line, const char *root, size_t root_len,
                         struct sha3_256_ctx *flags_sha,
                         struct sha3_256_ctx *graph_sha, char *mutation,
                         bool *mutation_seen)
{
    char *eq = strchr(line, '=');
    if (!eq) return false; /* a plan line that is not KEY=VALUE */
    *eq = 0;
    if (strcmp(line, "COMPILER_ID") == 0) return true;
    struct sha3_256_ctx *sha =
        proof_plan_key_is_flag(line) ? flags_sha : graph_sha;
    sha3_256_write(sha, (const uint8_t *)line, strlen(line) + 1);
    if (strcmp(line, "BASE_GENERATION") != 0) {
        proof_hash_plan_value(sha, root, root_len, eq + 1);
        return true;
    }
    if (!dp_plan_mutation_take(eq + 1, mutation_seen, mutation)) return false;
    proof_hash_plan_value(sha, root, root_len, "<local-mutation>");
    return true;
}

static bool proof_plan_roots(const char *root, uint8_t flags[32],
                             uint8_t build_graph[32], char mutation[65], char *why,
                             size_t why_len)
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
    if (!dp_plan_body_read(path, body, sizeof(body), why, why_len))
        return false;
    struct sha3_256_ctx flags_sha, graph_sha;
    hash_begin(&flags_sha, PROOF_FLAGS_DOMAIN);
    hash_begin(&graph_sha, PROOF_BUILD_GRAPH_DOMAIN);
    bool mutation_seen = false;
    char *save = NULL;
    for (char *line = strtok_r(body, "\n", &save); line;
         line = strtok_r(NULL, "\n", &save))
        if (!dp_plan_line(line, root, root_len, &flags_sha, &graph_sha,
                          mutation, &mutation_seen))
            return false;
    if (!mutation_seen) {
        fprintf(stderr, "[devproof] build plan: missing local mutation token\n");
        return false;
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
static bool proof_build_identity_capture(
    const char *repo_root, struct zcl_dev_proof_build_identity_v1 *out,
    char mutation[65], char *why, size_t why_len)
{
    struct vcs_toolchain_capsule_v1 capsule;
    if (why && why_len) why[0] = 0;
    if (!repo_root || !out) return false;
    memset(out, 0, sizeof(*out));
    return vcs_toolchain_capsule_v1_capture(&capsule) &&
           vcs_toolchain_capsule_v1_root(&capsule, out->compiler) &&
           proof_plan_roots(repo_root, out->flags, out->build_graph, mutation, why,
                            why_len) &&
           proof_environment_root(out->environment);
}

bool zcl_dev_proof_build_identity_v1_capture(
    const char *repo_root, struct zcl_dev_proof_build_identity_v1 *out,
    char *why, size_t why_len)
{
    return proof_build_identity_capture(repo_root, out, NULL, why, why_len);
}

bool zcl_dev_proof_build_plan_verify(
    const char *root, const struct zcl_dev_proof_build_identity_v1 *expected,
    const char *expected_mutation, char *why, size_t why_len)
{
    uint8_t flags[32], graph[32], decoded[32];
    char mutation[65], plan_why[PATH_MAX + 160] = {0};
    const char *reason = NULL;
    if (!expected || !expected_mutation || strlen(expected_mutation) != 64 ||
        !zcl_hex_decode_lower(expected_mutation, decoded, sizeof(decoded)) ||
        !proof_plan_roots(root, flags, graph, mutation, plan_why,
                          sizeof(plan_why)))
        reason = "proof_offline_build_plan_unavailable";
    else if (strcmp(mutation, expected_mutation) != 0)
        reason = "proof_offline_build_mutation_changed";
    else if (memcmp(flags, expected->flags, sizeof(flags)) != 0)
        reason = "proof_offline_build_flags_changed";
    else if (memcmp(graph, expected->build_graph, sizeof(graph)) != 0)
        reason = "proof_offline_build_graph_changed";
    if (reason) {
        fprintf(stderr, "[devproof] build plan verification: %s\n", reason);
        if (plan_why[0])
            proof_whyf(why, why_len, "%s:%s", reason, plan_why);
        else
            proof_why(why, why_len, reason);
        return false;
    }
    return true;
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
    if (!zcl_dev_proof_build_identity_v1_capture(root, &identity, NULL, 0))
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

/* The eight text fields a donor marker carries, before any of them has been
 * checked. Nothing here is trusted until dp_marker_identity, dp_marker_root
 * and dp_marker_completed have each had their say. */
struct dp_marker_fields {
    char root[PATH_MAX];
    char local[65];
    char base[65];
    char completed[32];
    char compiler[65];
    char flags[65];
    char environment[65];
    char build_graph[65];
};

/* The marker file, whole. A short read, an empty file, or one that filled
 * the buffer is refused rather than parsed. */
static bool dp_marker_body_read(const char *generation, char *body,
                                size_t body_size)
{
    char path[PATH_MAX];
    if (!generation ||
        snprintf(path, sizeof(path), "%s/%s", generation,
                 PROOF_WARM_MARKER_REL) >= (int)sizeof(path))
        return false;
    FILE *f = fopen(path, "r");
    if (!f) return false;
    size_t n = fread(body, 1, body_size - 1, f);
    bool ok = !ferror(f);
    fclose(f);
    if (!ok || n == 0 || n == body_size - 1) return false;
    body[n] = 0;
    return true;
}

/* Every remaining line must name exactly one known field. An unrecognised
 * line refuses the marker; it is never skipped. */
static bool dp_marker_collect(char **save, struct dp_marker_fields *got,
                              int *fields)
{
    char *line;
    while ((line = strtok_r(NULL, "\n", save))) {
        if (warm_marker_line(line, "root", got->root, sizeof(got->root)) ||
            warm_marker_line(line, "local", got->local, sizeof(got->local)) ||
            warm_marker_line(line, "base", got->base, sizeof(got->base)) ||
            warm_marker_line(line, "completed", got->completed,
                             sizeof(got->completed)) ||
            warm_marker_line(line, "compiler", got->compiler,
                             sizeof(got->compiler)) ||
            warm_marker_line(line, "flags", got->flags, sizeof(got->flags)) ||
            warm_marker_line(line, "environment", got->environment,
                             sizeof(got->environment)) ||
            warm_marker_line(line, "build_graph", got->build_graph,
                             sizeof(got->build_graph)))
            (*fields)++;
        else
            return false;
    }
    return true;
}

/* proof_oid_text rejects anything that is not a lowercase hex object
 * id; dp_marker_root_ok bars escapes. Any shortfall refuses -- a
 * marker from before the identity fields existed is exactly the
 * shortfall this rejects, so an old marker degrades to cold rather
 * than being adopted unverified. */
static bool dp_marker_identity(
    const struct dp_marker_fields *got, int fields,
    struct zcl_dev_proof_build_identity_v1 *identity)
{
    return fields == 8 && proof_oid_text(got->local) &&
           proof_oid_text(got->base) &&
           zcl_hex_decode_lower(got->compiler, identity->compiler, 32) &&
           zcl_hex_decode_lower(got->flags, identity->flags, 32) &&
           zcl_hex_decode_lower(got->environment, identity->environment, 32) &&
           zcl_hex_decode_lower(got->build_graph, identity->build_graph, 32);
}

static bool dp_marker_root_ok(const char *got_root)
{
    return got_root[0] == '/' && !strstr(got_root, "..") &&
           !strchr(got_root, '\\');
}

static bool dp_marker_completed(const char *text, int64_t *out)
{
    char *end = NULL;
    errno = 0;
    long long completed = strtoll(text, &end, 10);
    if (errno != 0 || !end || *end != 0 || completed <= 0) return false;
    *out = (int64_t)completed;
    return true;
}

static bool warm_marker_read(const char *generation, char root[PATH_MAX],
                             char local[65], char base[65],
                             int64_t *completed_out,
                             struct zcl_dev_proof_build_identity_v1 *identity_out)
{
    char body[2048];
    if (!dp_marker_body_read(generation, body, sizeof(body))) return false;
    char *save = NULL, *line = strtok_r(body, "\n", &save);
    if (!line || strcmp(line, PROOF_WARM_MARKER_SCHEMA) != 0) return false;
    struct dp_marker_fields got = {0};
    int fields = 0;
    if (!dp_marker_collect(&save, &got, &fields)) return false;
    struct zcl_dev_proof_build_identity_v1 identity;
    if (!dp_marker_identity(&got, fields, &identity)) return false;
    if (!dp_marker_root_ok(got.root)) return false;
    int64_t completed = 0;
    if (!dp_marker_completed(got.completed, &completed)) return false;
    if (root) (void)snprintf(root, PATH_MAX, "%s", got.root);
    if (local) (void)snprintf(local, 65, "%s", got.local);
    if (base) (void)snprintf(base, 65, "%s", got.base);
    if (completed_out) *completed_out = completed;
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

/* One entry of a restamped subtree: a regular file is stamped, a
 * subdirectory is pushed onto the caller's stack for the walk to reach,
 * and everything else is left alone. Symlinks are never followed. Returns
 * false only for a failure that must stop the whole restamp. */
static bool dp_touch_entry(const char *dir_path, const char *name,
                           const struct timespec *stamp, char **stack,
                           size_t stack_cap, size_t *depth)
{
    char child[PATH_MAX];
    struct stat child_st;
    if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0 ||
        snprintf(child, sizeof(child), "%s/%s", dir_path, name) >=
            (int)sizeof(child) ||
        lstat(child, &child_st) != 0)
        return true;
    if (S_ISLNK(child_st.st_mode)) return true;
    if (S_ISDIR(child_st.st_mode)) {
        if (*depth >= stack_cap) return true;
        char *held = zcl_malloc(strlen(child) + 1, "proof_warm_touch");
        if (!held) return false;
        (void)snprintf(held, strlen(child) + 1, "%s", child);
        stack[(*depth)++] = held;
        return true;
    }
    return !S_ISREG(child_st.st_mode) || warm_touch_one(child, stamp);
}

/* Restamp every regular file under one directory, iteratively: the stack
 * holds at most 64 pending directories and deeper ones are left alone,
 * because an unstamped file only costs a recompile. `top` is the caller's
 * buffer and is the one entry that must never be freed. */
static void dp_touch_subtree(const char *path, const struct timespec *stamp,
                             bool *ok)
{
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
             entry = readdir(dir))
            if (!dp_touch_entry(dir_path, entry->d_name, stamp, stack,
                                sizeof(stack) / sizeof(stack[0]), &depth))
                *ok = false;
        (void)closedir(dir);
        if (dir_path != top) free(dir_path);
    }
    while (depth > 0) free(stack[--depth]);
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
    dp_touch_subtree(path, stamp, ok);
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
/* The vocabulary a catalog path may be spelled in. Anything outside it
 * refuses the catalog rather than being quoted into a git argument. */
static bool dp_wrapper_word_char(char c)
{
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
           (c >= '0' && c <= '9') || c == '_' || c == '.' ||
           c == '/' || c == '-';
}

static bool dp_wrapper_input_clean(const char *line, size_t len)
{
    for (size_t i = 0; i < len; i++)
        if (!dp_wrapper_word_char(line[i])) return false;
    return strstr(line, "..") == NULL;
}

static size_t dp_wrapper_trim(char *line)
{
    size_t len = strlen(line);
    while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r'))
        line[--len] = 0;
    return len;
}

/* Read the bootstrap-input catalog into a fixed table. A line that is too
 * long, spelled outside the path vocabulary, or one too many for the table
 * refuses the whole catalog: a catalog this reader cannot fully account for
 * must never silently narrow the checked set. */
static bool dp_wrapper_catalog_read(FILE *f, char inputs[][128],
                                    size_t input_cap, size_t *input_count)
{
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        size_t len = dp_wrapper_trim(line);
        if (len == 0 || strncmp(line, "license=", 8) == 0) continue;
        if (len >= sizeof(inputs[0])) return false;
        if (!dp_wrapper_input_clean(line, len) || *input_count >= input_cap)
            return false;
        (void)snprintf(inputs[*input_count], sizeof(inputs[0]), "%s", line);
        (*input_count)++;
    }
    return true;
}

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
    char inputs[12][128];
    size_t input_count = 0;
    bool ok = dp_wrapper_catalog_read(f, inputs,
                                      sizeof(inputs) / sizeof(inputs[0]),
                                      &input_count);
    bool complete = !ferror(f);
    fclose(f);
    if (!ok || !complete || input_count == 0) return false;
    const char *fixed[] = {
        "tools/dev/zcc-bootstrap-inputs.list",
        "tools/dev/zcc_bootstrap.sh",
    };
    size_t fixed_count = sizeof(fixed) / sizeof(fixed[0]);
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

/* Survey one generation directory against this proof's build identity, and
 * fill the pick policy's fields for it. Returns false for a directory that
 * is not a candidate at all -- a foreign tag, the caller's own generation,
 * a missing or mismatched marker, or an object tree that cannot be
 * timestamped. */
static bool dp_donor_survey(
    const char *parent, const char *root, const char *in_use,
    const char *name,
    const struct zcl_dev_proof_build_identity_v1 *current,
    struct zcl_dev_proof_warm_candidate *slot)
{
    char candidate_path[PATH_MAX];
    if (!warm_tag_name(name) ||
        snprintf(candidate_path, sizeof(candidate_path), "%s/%s",
                 parent, name) >= (int)sizeof(candidate_path) ||
        strcmp(candidate_path, in_use) == 0)
        return false;
    char marker_root[PATH_MAX], marker_local[65], marker_base[65];
    int64_t completed = 0;
    struct zcl_dev_proof_build_identity_v1 candidate_identity;
    if (!warm_marker_read(candidate_path, marker_root, marker_local,
                          marker_base, &completed, &candidate_identity) ||
        strcmp(marker_root, root) != 0 ||
        !proof_build_identity_equal(current, &candidate_identity))
        return false;
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
        return false;
    memset(slot, 0, sizeof(*slot));
    (void)snprintf(slot->tag, sizeof(slot->tag), "%s", name);
    (void)snprintf(slot->path, sizeof(slot->path), "%s", candidate_path);
    (void)snprintf(slot->local, sizeof(slot->local), "%s", marker_local);
    slot->completed = completed;
    slot->touched = touched;
    slot->head_ok = head_ok;
    /* A generation whose checkout moved since its build finished, or
     * whose proof is still leased, cannot donate: the first may hold
     * objects for another commit, the second is still writing. */
    slot->live = !head_ok ||
                 warm_donor_live(root, marker_local, marker_base);
    return true;
}

/* Room for one more surveyed candidate. */
static bool dp_donor_reserve(struct zcl_dev_proof_warm_candidate **candidates,
                             size_t count, size_t *capacity)
{
    if (count < *capacity) return true;
    size_t next = *capacity ? *capacity * 2 : 16;
    struct zcl_dev_proof_warm_candidate *grown = zcl_realloc(
        *candidates, next * sizeof(*grown), "proof_warm_donor");
    if (!grown) return false;
    *candidates = grown;
    *capacity = next;
    return true;
}

/* Re-read the marker now the survey is done. A sibling lane can
 * finish a build in this generation while the scan runs; if the
 * marker or the identity it was sealed under moved, the surveyed
 * choice is stale and cold is safe. */
static bool dp_donor_confirm(
    const struct zcl_dev_proof_warm_candidate *best,
    const struct zcl_dev_proof_build_identity_v1 *current,
    struct warm_donor *donor)
{
    char marker_root[PATH_MAX], marker_local[65], marker_base[65];
    int64_t completed = 0;
    struct zcl_dev_proof_build_identity_v1 recheck_identity;
    return warm_marker_read(best->path, marker_root, marker_local,
                            marker_base, &completed, &recheck_identity) &&
           strcmp(marker_local, best->local) == 0 &&
           proof_build_identity_equal(current, &recheck_identity) &&
           snprintf(donor->path, sizeof(donor->path), "%s",
                    best->path) < (int)sizeof(donor->path) &&
           snprintf(donor->local, sizeof(donor->local), "%s",
                    best->local) < (int)sizeof(donor->local) &&
           snprintf(donor->base, sizeof(donor->base), "%s",
                    marker_base) < (int)sizeof(donor->base);
}

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
    if (!zcl_dev_proof_build_identity_v1_capture(root, &current, NULL, 0))
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
        struct zcl_dev_proof_warm_candidate surveyed;
        if (!dp_donor_survey(parent, root, in_use, entry->d_name, &current,
                             &surveyed))
            continue;
        if (!dp_donor_reserve(&candidates, count, &capacity)) {
            free(candidates);
            candidates = NULL;
            count = capacity = 0;
            break;
        }
        candidates[count++] = surveyed;
    }
    (void)closedir(dir);
    int best = warm_pick_donor(candidates, count);
    bool found = candidates && best >= 0;
    if (found) found = dp_donor_confirm(&candidates[best], &current, donor);
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

/* Apparent size of every regular file under `dir`, summed recursively.
 * Advisory only, for a hygiene log line: a read error or a sibling lane
 * mutating the tree mid-walk just undercounts, it never fails the sweep
 * that called this. */
static uint64_t directory_bytes_sum(const char *dir)
{
    DIR *d = opendir(dir);
    if (!d) return 0;
    uint64_t total = 0;
    for (struct dirent *entry = readdir(d); entry; entry = readdir(d)) {
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0)
            continue;
        char child[PATH_MAX];
        if (snprintf(child, sizeof(child), "%s/%s", dir, entry->d_name) >=
                (int)sizeof(child))
            continue;
        struct stat st;
        if (lstat(child, &st) != 0) continue;
        if (S_ISDIR(st.st_mode)) total += directory_bytes_sum(child);
        else if (S_ISREG(st.st_mode)) total += (uint64_t)st.st_size;
    }
    (void)closedir(d);
    return total;
}

/* With warm start, old generations are valuable donors, so the reaper
 * keeps the newest complete generation per root and may reap the rest.
 * Hygiene, never correctness: a pool that fails to shrink costs disk while
 * a proof that failed over a delete would cost every lane on this host its
 * push. `max_attempts` bounds how many candidates reach git (the prepare
 * path's own call keeps its tight PROOF_WARM_REAP_MAX budget; an explicit
 * sweep triggered off the proof's hot path can afford a larger one).
 * `removed_out`/`bytes_out`, when non-NULL, are INCREMENTED (never reset)
 * by what this call actually deleted, so a caller sweeping more than one
 * pool root can accumulate one total across calls.
 *
 * A donor being seeded from while it is reaped degrades gracefully: the
 * seed walk skips files that vanish, and hard links already created keep
 * their inodes after the donor names are unlinked. */
/* Is this pool entry an idle generation the reaper may consider, and what
 * does its marker say? Returns false for a foreign tag, the caller's own
 * generation, an untimestampable tree, or one still in use. */
static bool dp_reap_survey(const char *parent, const char *in_use,
                           const char *name, int64_t now,
                           struct warm_reap_entry *slot)
{
    char candidate[PATH_MAX];
    int64_t touched = 0;
    if (!warm_tag_name(name) ||
        snprintf(candidate, sizeof(candidate), "%s/%s", parent,
                 name) >= (int)sizeof(candidate) ||
        strcmp(candidate, in_use) == 0 ||
        !warm_generation_touched(candidate, &touched))
        return false;
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
    if (live) return false;
    memset(slot, 0, sizeof(*slot));
    (void)snprintf(slot->tag, sizeof(slot->tag), "%s", name);
    (void)snprintf(slot->path, sizeof(slot->path), "%s", candidate);
    (void)snprintf(slot->root, sizeof(slot->root), "%s",
                   complete ? marker_root : "");
    slot->completed = completed;
    slot->touched = touched;
    slot->complete = complete;
    return true;
}

/* Survey the whole pool. An allocation failure abandons the survey whole:
 * a partial list could reap a generation whose siblings were never seen. */
static bool dp_reap_collect(DIR *dir, const char *parent, const char *in_use,
                            int64_t now, struct warm_reap_entry **entries,
                            size_t *count)
{
    size_t capacity = 0;
    for (struct dirent *entry = readdir(dir); entry;
         entry = readdir(dir)) {
        struct warm_reap_entry surveyed;
        if (!dp_reap_survey(parent, in_use, entry->d_name, now, &surveyed))
            continue;
        if (*count == capacity) {
            size_t next = capacity ? capacity * 2 : 16;
            struct warm_reap_entry *grown = zcl_realloc(
                *entries, next * sizeof(*grown), "proof_warm_reap");
            if (!grown) {
                free(*entries);
                *entries = NULL;
                *count = 0;
                return false;
            }
            *entries = grown;
            capacity = next;
        }
        (*entries)[(*count)++] = surveyed;
    }
    return true;
}

/* Keep the newest complete generation per root: reap this
 * one when a same-root sibling wins the donor pick. The pick
 * is the tested policy; the reaper only groups by root. */
static bool dp_reap_superseded(const struct warm_reap_entry *entries,
                               size_t count, size_t i)
{
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
    bool reap = false;
    if (group_ok && group_count > 0) {
        int best = warm_pick_donor(group, group_count);
        reap = best >= 0 && (size_t)best != self;
    }
    free(group);
    return reap;
}

/* Delete one superseded generation, re-proving it is still idle first. */
static void dp_reap_remove(const struct proof_paths *paths,
                           const struct warm_reap_entry *entry,
                           size_t *removed_out, uint64_t *bytes_out)
{
    if (!warm_reapable(entry->path)) return;
    /* Re-read the stamp now the git queries are done. The pool is
     * shared by every checkout under this parent, so a sibling lane
     * can claim this generation while it is examined; if it did, it
     * moved the mtime out of range. */
    int64_t touched_again = 0;
    if (!warm_generation_touched(entry->path, &touched_again) ||
        touched_again != entry->touched)
        return;
    /* Measured before the delete: afterward there is nothing left to
     * walk. Advisory only, so a size that changes mid-measurement
     * just makes the log line approximate, never wrong enough to act
     * on -- nothing downstream reads these numbers back. */
    uint64_t freed = directory_bytes_sum(entry->path);
    /* --force is safe only because detached and clean were just
     * proven. What it overrides is git's refusal to delete a tree
     * that still holds untracked files, and a generation's untracked
     * files are its build scratch. */
    const char *argv[] = {"git", "worktree", "remove", "--force",
                          entry->path, NULL};
    char output[1024];
    if (git_capture_within(paths->root, argv,
                           PROOF_WARM_REMOVE_TIMEOUT_MS, output,
                           sizeof(output))) {
        if (removed_out) (*removed_out)++;
        if (bytes_out) *bytes_out += freed;
    }
}

static void generation_pool_reap_ex(const struct proof_paths *paths,
                                    const char *parent, const char *in_use,
                                    size_t max_attempts, size_t *removed_out,
                                    uint64_t *bytes_out)
{
    DIR *dir = opendir(parent);
    if (!dir || !paths || !parent || !in_use) {
        if (dir) (void)closedir(dir);
        return;
    }
    int64_t now = platform_time_wall_unix();
    struct warm_reap_entry *entries = NULL;
    size_t count = 0;
    bool collect_ok = dp_reap_collect(dir, parent, in_use, now, &entries,
                                      &count);
    (void)closedir(dir);
    size_t attempts = 0;
    for (size_t i = 0; collect_ok && entries && i < count &&
             attempts < max_attempts;
         i++) {
        if (entries[i].complete && !dp_reap_superseded(entries, count, i))
            continue;
        /* The cap counts candidates that reach git, not directory
         * entries: the queries plus the delete are the only expensive
         * part, and bounding them is what keeps a fast proof fast. */
        attempts++;
        dp_reap_remove(paths, &entries[i], removed_out, bytes_out);
    }
    free(entries);
}

static void generation_pool_reap(const struct proof_paths *paths,
                                 const char *parent, const char *in_use)
{
    generation_pool_reap_ex(paths, parent, in_use, PROOF_WARM_REAP_MAX, NULL,
                            NULL);
}

/* An explicit sweep of both this checkout's own generation pools (disk
 * beside the landing worktree, and this host's RAM root when it offers
 * one), unbounded by the tight per-prepare budget: triggered off the
 * proof's hot path (attempt end, next submit), it can afford to look at
 * more than eight candidates. Reports what it actually removed so the
 * caller can log it; `why` carries a reason only when both pool paths
 * were unusable to compute, never for "found nothing to remove" (that is
 * success, not a refusal). */
#define PROOF_POOL_SWEEP_MAX 512
bool zcl_dev_proof_generation_pool_sweep(const char *repo_root,
                                         size_t *removed_out,
                                         uint64_t *bytes_out, char *why,
                                         size_t why_len)
{
    if (why && why_len) why[0] = 0;
    if (removed_out) *removed_out = 0;
    if (bytes_out) *bytes_out = 0;
    if (!repo_root || !repo_root[0]) {
        proof_why(why, why_len, "proof_generation_pool_sweep_root_invalid");
        return false;
    }
    char root_parent[PATH_MAX];
    if (snprintf(root_parent, sizeof(root_parent), "%s", repo_root) >=
            (int)sizeof(root_parent)) {
        proof_why(why, why_len, "proof_generation_pool_sweep_root_invalid");
        return false;
    }
    char *slash = strrchr(root_parent, '/');
    if (!slash || slash == root_parent) {
        proof_why(why, why_len, "proof_generation_pool_sweep_root_invalid");
        return false;
    }
    *slash = 0;
    char disk_parent[PATH_MAX];
    if (snprintf(disk_parent, sizeof(disk_parent), "%s/.z23p", root_parent) >=
            (int)sizeof(disk_parent)) {
        proof_why(why, why_len, "proof_generation_pool_sweep_path_invalid");
        return false;
    }
    struct proof_paths paths;
    memset(&paths, 0, sizeof(paths));
    (void)snprintf(paths.root, sizeof(paths.root), "%s", repo_root);
    size_t removed = 0;
    uint64_t bytes = 0;
    generation_pool_reap_ex(&paths, disk_parent, "", PROOF_POOL_SWEEP_MAX,
                            &removed, &bytes);
    char ram_root[PATH_MAX];
    if (platform_ram_scratch_root(ram_root, sizeof(ram_root), 0)) {
        char ram_parent[PATH_MAX];
        if (snprintf(ram_parent, sizeof(ram_parent), "%s/z23p", ram_root) <
                (int)sizeof(ram_parent))
            generation_pool_reap_ex(&paths, ram_parent, "",
                                    PROOF_POOL_SWEEP_MAX, &removed, &bytes);
    }
    if (removed_out) *removed_out = removed;
    if (bytes_out) *bytes_out = bytes;
    return true;
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

/* A fresh generation checkout never carries build/bin/zcc: it is a build
 * artifact, deliberately absent from the `dependencies[]` list above so every
 * generation self-hosts its own compile cache from source. Left unbootstrapped
 * here, the FIRST `make` invocation that touches $(CC) builds it lazily at
 * Makefile parse time (tools/dev/zcc_bootstrap.sh). The lint and test
 * dimensions below are launched as two independent `make` child processes
 * before either is waited on (by design — see the comment at their call
 * site), and each reparses the Makefile and re-runs that same parse-time
 * bootstrap independently. Two such parses racing their first-ever bootstrap
 * of this generation observed BUILD_COMPILER_ID diverge between the epoch a
 * session was acquired under and the epoch verified against it later
 * (`compiler/toolchain changed during build`), even though the underlying
 * zcc bytes end up identical: the race is over which parse's view of
 * $(CC) — bare `cc` because its bootstrap had not yet completed, or the
 * fully wrapped `zcc cc` — gets recorded first.
 *
 * Bootstrap once, synchronously, right here, before any make process for
 * this generation exists. Every later parse-time freshness check then finds
 * zcc already newer than every one of its own inputs and does nothing, so
 * there is no first-mover race left to lose. Advisory only, exactly like the
 * script's own contract ("never fails a build"): a failure here is not a
 * generation-prepare failure, it just falls back to the previous lazy,
 * single-caller bootstrap the first make invocation still performs. */
static void generation_zcc_bootstrap(const char *generation)
{
    char bin_dir[PATH_MAX];
    if (!generation ||
        snprintf(bin_dir, sizeof(bin_dir), "%s/build/bin", generation) >=
            (int)sizeof(bin_dir))
        return;
    if (setenv("ZCL_BIN_DIR", bin_dir, 1) != 0) return;
    const char *argv[] = {"tools/dev/zcc_bootstrap.sh", NULL};
    struct zcl_devloop_process_result result = {0};
    (void)zcl_devloop_process_run(generation, argv, 60000, &result);
    (void)unsetenv("ZCL_BIN_DIR");
}

/* `git worktree add` copies the submitting checkout's worktree-scoped
 * core.hooksPath verbatim into a fresh generation's own config.worktree, so
 * a freshly materialized generation still names the checkout's
 * build/githooks rather than the copy generation_prepare() just
 * materialized. check-git-hooks-installed then compares
 * expected=<generation>/build/githooks against
 * actual=<submitting checkout>/build/githooks and fails closed on every
 * proof that runs the full gate set. A generation must be judged against
 * the hooks it carries, so point its own worktree config at its own copy;
 * failing that reconfiguration fails the generation closed rather than
 * judging it against someone else's checkout. */
static bool generation_hooks_configure(const char *generation, char *why,
                                       size_t why_len)
{
    char hooks_path[PATH_MAX];
    if (snprintf(hooks_path, sizeof(hooks_path), "%s/build/githooks",
                 generation) >= (int)sizeof(hooks_path)) {
        proof_why(why, why_len, "proof_generation_hooks_path_too_long");
        return false;
    }
    const char *hooks_argv[] = {"git", "config", "--worktree",
                                "core.hooksPath", hooks_path, NULL};
    char hooks_output[ZCL_DEVLOOP_OUTPUT_MAX];
    if (!git_capture(generation, hooks_argv, hooks_output,
                     sizeof(hooks_output))) {
        proof_why(why, why_len, "proof_generation_hooks_path_not_reconfigured");
        return false;
    }
    return true;
}

/* The directory the generation pool sits beside: the checkout's own
 * parent, with the checkout name trimmed off. */
static bool dp_generation_parent_dir(const char *root,
                                     char root_parent[PATH_MAX], char *why,
                                     size_t why_len)
{
    if (snprintf(root_parent, PATH_MAX, "%s", root) >= PATH_MAX) {
        proof_why(why, why_len, "proof_generation_path_invalid");
        return false;
    }
    char *slash = strrchr(root_parent, '/');
    if (!slash || slash == root_parent) {
        proof_why(why, why_len, "proof_generation_path_invalid");
        return false;
    }
    *slash = 0;
    return true;
}

/* One generation per (checkout, local commit) pair, named by a digest over
 * both so two checkouts never collide in a shared pool. */
static void dp_generation_tag(const char *root, const char *local,
                              char generation_tag[33])
{
    uint8_t generation_hash[ZCL_DEV_PROOF_ROOT_BYTES];
    struct sha3_256_ctx generation_identity;
    hash_begin(&generation_identity, "zcl.dev_proof_generation_root.v2");
    sha3_256_write(&generation_identity, (const uint8_t *)root,
                   strlen(root) + 1);
    sha3_256_write(&generation_identity, (const uint8_t *)local,
                   strlen(local) + 1);
    sha3_256_finalize(&generation_identity, generation_hash);
    zcl_hex_encode(generation_hash, 16, generation_tag);
}

/* Build and test work here is dominated by fsync, and on a RAM-backed
 * filesystem fsync costs nothing. When the machine offers one with room to
 * spare the whole generation — checkout, build tree and test scratch —
 * lives there; otherwise it stays exactly where it was. The choice is
 * written to phases.txt so a slow proof can be read against where it ran.
 * It is deliberately NOT sealed into the receipt: two proofs of the same
 * source must admit each other whatever storage they happened to use.
 *
 * Free space seen is not free space kept: N proofs asking at once each
 * saw the same headroom and together filled the tmpfs. A reservation
 * held for the life of the generation is what makes this one's yes true
 * for this one alone. Refusal is not an error — the generation falls
 * back to disk exactly as if no RAM root had been offered. */
static bool dp_generation_pool(const char *root_parent,
                               struct platform_ram_scratch_lease *ram_lease,
                               char parent[PATH_MAX], char ram_root[PATH_MAX],
                               bool *ram_backed, bool *ram_reserve_refused)
{
    *ram_backed = platform_ram_scratch_root(ram_root, PATH_MAX, 0);
    *ram_reserve_refused = false;
    if (*ram_backed &&
        !platform_ram_scratch_reserve(ram_root, proof_ram_reserve_bytes(),
                                      ram_lease)) {
        *ram_backed = false;
        *ram_reserve_refused = true;
    }
    int parent_len = *ram_backed
        ? snprintf(parent, PATH_MAX, "%s/z23p", ram_root)
        : snprintf(parent, PATH_MAX, "%s/.z23p", root_parent);
    return parent_len > 0 && (size_t)parent_len < PATH_MAX;
}

/* Where this proof ran, for a reader comparing a slow proof against its
 * storage. Display only; nothing downstream reads it back. */
static void dp_generation_storage_note(const struct proof_paths *paths,
                                       const char *ram_root, bool ram_backed,
                                       bool ram_reserve_refused,
                                       const char *generation)
{
    if (!paths->phases[0]) return;
    char storage_note[192];
    if (ram_reserve_refused) {
        uint64_t ram_free_bytes = 0;
        (void)platform_disk_space_available(ram_root, &ram_free_bytes);
        char ram_pool[PATH_MAX];
        size_t ram_pool_count = 0;
        if (snprintf(ram_pool, sizeof(ram_pool), "%s/z23p", ram_root) <
            (int)sizeof(ram_pool))
            ram_pool_count = generation_dir_count(ram_pool);
        (void)snprintf(storage_note, sizeof(storage_note),
                       "disk reason=ram_reserve_refused "
                       "requested_bytes=%llu free_bytes=%llu "
                       "generations=%zu",
                       (unsigned long long)proof_ram_reserve_bytes(),
                       (unsigned long long)ram_free_bytes,
                       ram_pool_count);
    } else {
        (void)snprintf(storage_note, sizeof(storage_note), "%s",
                       ram_backed ? "ram" : "disk");
    }
    (void)zcl_dev_proof_phase_note(paths->phases, "generation_storage",
                                   storage_note);
    (void)zcl_dev_proof_phase_note(paths->phases, "generation_root",
                                   generation);
}

/* Check the generation out when it is not already there. */
static bool dp_generation_checkout(const struct proof_paths *paths,
                                   const char *generation, const char *local,
                                   char *why, size_t why_len)
{
    struct stat st;
    if (lstat(generation, &st) == 0) return true;
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
    return true;
}

/* The generation's own build tree. Distinct from the dependency copy
 * below: nothing is missing from the checkout here, the generation's own
 * build tree could not be created. Conflating the two sent a reader
 * hunting a vendored archive that was present all along. */
static bool dp_generation_build_dirs(const char *generation, char *why,
                                     size_t why_len)
{
    char build_dir[PATH_MAX], bin_dir[PATH_MAX];
    if (snprintf(build_dir, sizeof(build_dir), "%s/build", generation) >=
            (int)sizeof(build_dir) ||
        snprintf(bin_dir, sizeof(bin_dir), "%s/build/bin", generation) >=
            (int)sizeof(bin_dir) ||
        !platform_private_directory_ensure(build_dir) ||
        !platform_private_directory_ensure(bin_dir)) {
        proof_whyf(why, why_len, "proof_generation_build_dir_unwritable:%s",
                   build_dir);
        return false;
    }
    return true;
}

/* These cross-target outputs and download caches are not native compiler
 * inputs. Carry them when present so a Windows acceptance run can reuse
 * them, but do not require a native checkout to have built a cross target. */
static bool dp_generation_dependency_optional(const char *dependency)
{
    return strcmp(dependency, "vendor/.build-x86_64-w64-mingw32") == 0 ||
           strcmp(dependency, "vendor/.cache") == 0 ||
           strcmp(dependency, "vendor/cross") == 0;
}

/* Absence must agree on both sides. A reused generation with old cross
 * inputs refuses instead of silently proving against bytes its source no
 * longer carries. Inspection errors are not evidence of absence. */
static bool dp_generation_optional_absent(const char *target,
                                          const char *dependency,
                                          char *why, size_t why_len)
{
    struct stat st;
    if (lstat(target, &st) == 0) {
        proof_whyf(why, why_len,
                   "proof_generation_optional_dependency_stale:%s",
                   dependency);
        return false;
    }
    if (errno == ENOENT) return true;
    proof_whyf(why, why_len,
               "proof_generation_dependency_inspection_failed:%s (%s)",
               dependency, proof_errno_name(errno));
    return false;
}

/* One generation dependency, copied in with its own inode. */
static bool dp_generation_dependency(const char *root, const char *generation,
                                     const char *dependency, char *why,
                                     size_t why_len)
{
    char source[PATH_MAX], target[PATH_MAX];
    if (snprintf(source, sizeof(source), "%s/%s", root,
                 dependency) >= (int)sizeof(source) ||
        snprintf(target, sizeof(target), "%s/%s", generation,
                 dependency) >= (int)sizeof(target)) {
        proof_whyf(why, why_len,
                   "proof_generation_dependency_path_too_long:%s",
                   dependency);
        return false;
    }
    struct stat source_st;
    if (lstat(source, &source_st) != 0) {
        if (errno != ENOENT) {
            proof_whyf(why, why_len,
                       "proof_generation_dependency_inspection_failed:%s (%s)",
                       dependency, proof_errno_name(errno));
            return false;
        }
        if (dp_generation_dependency_optional(dependency))
            return dp_generation_optional_absent(target, dependency, why,
                                                  why_len);
        /* vendor/ entries come from the vendored-archive build; the
         * installed hooks come from arming the clone; the hotswap
         * fixture images come from any test-binary build. Naming the
         * target turns a class into one command the reader can run. */
        const char *fix = strncmp(dependency, "vendor/", 7) == 0
                              ? "make vendor"
                              : strncmp(dependency, "build/hotswap/",
                                        14) == 0
                                    ? "make test_parallel"
                                    : "make install-hooks";
        proof_whyf(why, why_len,
                   "proof_generation_dependency_unavailable:%s (%s)",
                   dependency, fix);
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
                   dependency, proof_errno_name(errno));
        return false;
    }
    return true;
}

#if defined(ZCL_TESTING)
bool zcl_dev_proof_test_generation_dependency(const char *root,
                                              const char *generation,
                                              const char *dependency,
                                              char *why, size_t why_len)
{
    return dp_generation_dependency(root, generation, dependency, why, why_len);
}
#endif

/* Warm start is advisory: it fills `warm` for the receipt sidecar and
 * never fails the prepare. Any refusal inside degrades to the cold
 * build the proof has always run. ZCL_DEV_PROOF_WARM=0 forces that
 * cold path for measurement. */
static void dp_generation_warm(const struct proof_paths *paths,
                               const char *parent, const char *generation,
                               const char *local, struct proof_warmstart *warm)
{
    if (!warm) return;
    if (warm_start_disabled()) {
        (void)snprintf(warm->cold_reason, sizeof(warm->cold_reason), "%s",
                       "disabled");
        return;
    }
    memset(warm, 0, sizeof(*warm));
    (void)warm_start_generation(paths, parent, generation, local, warm);
}

static bool dp_generation_dependencies(const char *root,
                                        const char *generation,
                                        char *why, size_t why_len)
{
    /* Preserve the complete ignored compiler-input sets that source identity
     * seals. Copying a fixed archive/header subset lets a host-specific input
     * (for example libsecp256k1-darwin.a) appear during `make build-only`,
     * superseding an otherwise exact isolated proof generation. Provenance
     * stamps travel with vendor/lib so already verified inputs are not
     * needlessly rebuilt after the source checkpoint. */
    static const char *const dependencies[] = {
        "vendor/lib", "vendor/include",
        /* The untracked amalgamated C source beside those two. No native
         * build compiles it, so its absence looks like nothing at all --
         * until the Windows acceptance link inside a full lint dies with
         * "No rule to make target 'vendor/sqlite3.c'", naming a missing file
         * rather than a missing priming step. The Makefile's worktree-prime
         * comment names this exact trap for hand-primed worktrees; a proof
         * generation is one more of them. */
        "vendor/sqlite3.c",
        "vendor/tor/libtor.a",
        /* The manifest must travel with the archives it attests: a
         * generation without it sees archives but no provenance, rebuilds
         * Tor from source in RAM, and the next warm restart then re-copies
         * the original libtor.a under a manifest that no longer matches it. */
        "vendor/tor/.provenance",
        /* Preserve optional cross-build outputs and download caches when
         * present so a generation can reuse the submitting checkout's
         * prepared target inputs without rebuilding or downloading them. */
        "vendor/.cache",
        /* The explicit Windows release target's staged lib/include.
         * The acceptance catalog builds SQLite separately from
         * vendor/sqlite3.c. build_vendor.sh removes its transient
         * .build-<target> workspace after successful verification; that
         * scratch directory is not a compiler input or a prerequisite. */
        "vendor/cross",
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
    if (!dp_generation_build_dirs(generation, why, why_len))
        return false;
    for (size_t i = 0; i < sizeof(dependencies) / sizeof(dependencies[0]); i++)
        if (!dp_generation_dependency(root, generation,
                                      dependencies[i], why, why_len))
            return false;
    return true;
}

#if defined(ZCL_DEV_BUILD) || defined(ZCL_TESTING)
bool zcl_dev_proof_test_generation_dependencies(const char *root,
                                                const char *generation,
                                                char *why, size_t why_len)
{
    return dp_generation_dependencies(root, generation, why, why_len);
}
#endif

static bool generation_prepare(const struct proof_paths *paths,
                               const char *local,
                               struct platform_ram_scratch_lease *ram_lease,
                               struct proof_warmstart *warm,
                               char generation[PATH_MAX],
                               char *why, size_t why_len)
{
    char root_parent[PATH_MAX], parent[PATH_MAX], generation_tag[33];
    if (!dp_generation_parent_dir(paths->root, root_parent, why, why_len))
        return false;
    dp_generation_tag(paths->root, local, generation_tag);
    char ram_root[PATH_MAX];
    bool ram_backed = false, ram_reserve_refused = false;
    if (!dp_generation_pool(root_parent, ram_lease, parent, ram_root,
                            &ram_backed, &ram_reserve_refused) ||
        snprintf(generation, PATH_MAX, "%s/%s", parent, generation_tag) >=
            PATH_MAX ||
        !platform_private_directory_ensure(parent)) {
        proof_why(why, why_len, "proof_generation_path_invalid");
        return false;
    }
    dp_generation_storage_note(paths, ram_root, ram_backed,
                               ram_reserve_refused, generation);
    if (!dp_generation_checkout(paths, generation, local, why, why_len))
        return false;
    if (!generation_gitlink_prepare(paths, generation, why, why_len))
        return false;
    if (!dp_generation_dependencies(paths->root, generation, why, why_len))
        return false;
    if (!generation_hooks_configure(generation, why, why_len))
        return false;
    if (!worktree_exact(generation, local, false, why, why_len)) {
        proof_why(why, why_len, "proof_generation_not_exact");
        return false;
    }
    /* Close the lazy-bootstrap race before any dimension's `make` process
     * exists for this generation (see generation_zcc_bootstrap). */
    generation_zcc_bootstrap(generation);
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
    dp_generation_warm(paths, parent, generation, local, warm);
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
#define PROOF_BUNDLE_DEFAULT_MS 1800000
#define PROOF_LINT_ARGV_CAP 6u

static bool proof_root_is_landing(const char *root)
{
#if defined(_WIN32)
    (void)root;
    return false;
#else
    char lock[PATH_MAX];
    if (!zcl_devloop_landing_queue_lock_path(root, lock, sizeof(lock)))
        return false;
    return access(lock, F_OK) == 0;
#endif
}

/* Fill the lint-dimension make argv. A landing root (sibling queue.lock)
 * runs the full `lint` target -- every gate, not the 27-gate fast subset --
 * so a red full-lint gate fails the landing instead of reaching main
 * unseen; check-windows-acceptance rides the same invocation, where make
 * runs it once whether or not the umbrella already names it. Every other
 * proof stays on lint-fast: a lane proof pays the fast subset, a landing
 * pays the whole gate set. `jobs` is stored by pointer and must outlive
 * argv. */
static bool proof_lint_prepare(const char *root, const char *jobs,
                               const char **argv, size_t argv_cap,
                               int64_t *fallback_ms, const char **targets)
{
    bool landing;
    if (!jobs || !*jobs || !argv || argv_cap < PROOF_LINT_ARGV_CAP ||
        !fallback_ms || !targets)
        return false;
    landing = proof_root_is_landing(root);
    argv[0] = "make";
    argv[1] = "--no-print-directory";
    argv[2] = jobs;
    if (landing) {
        argv[3] = "lint";
        argv[4] = "check-windows-acceptance";
        argv[5] = NULL;
        *fallback_ms = PROOF_LINT_LANDING_MS;
        *targets = "lint check-windows-acceptance";
    } else {
        argv[3] = "lint-fast";
        argv[4] = NULL;
        argv[5] = NULL;
        *fallback_ms = PROOF_LINT_DEFAULT_MS;
        *targets = "lint-fast";
    }
    return true;
}


/* True when the lint dimension is running the whole gate set rather than
 * the fast subset. Read off the targets proof_lint_prepare() just produced
 * so there is one decision, not two that can drift: only the full set
 * reads built artifacts, so only it needs the admitted executables. */
static bool proof_lint_targets_are_full(const char *targets)
{
    return targets && strncmp(targets, "lint", 4) == 0 &&
           (targets[4] == '\0' || targets[4] == ' ');
}

/* Fill the pre-fork make argv: everything EITHER dimension can build, built
 * once, before either starts.
 *
 * The two dimensions share one generation worktree. The test dimension runs
 * no make at all -- it execs the admitted runner and reads build outputs
 * (each lint-gate shard copies build/bin/z23-lint and
 * build/bin/file_size_policy into its sandbox and execs them). The lint
 * dimension does run make: `lint`'s own built prerequisites, and one nested
 * make inside check_standalone_tools_link.sh that links every standalone
 * tool rule the Makefile carries -- a set that includes z23-lint,
 * zcl-nodectl, fbsh, file_size_policy, fleet-board-bridge and
 * zclassic23-engine-unit, i.e. the very executables the test dimension is
 * reading. A relink unlinks the output before it writes it, and on
 * 2026-09-06 a landing proof's shard exec'd build/bin/z23-lint inside that
 * window and got "No such file or directory" twice.
 *
 * So both target sets are built here, sequentially, and after the fork
 * neither dimension has anything left to link. The helper targets are named
 * literally because their hashes are folded into the
 * zcl.dev_proof_test_helpers.v1 digest one by one; the lint side is a single
 * Makefile target (proof-lint-prebuild) that names `lint`'s own prerequisite
 * list, so the two can never drift apart. `jobs` is stored by pointer and
 * must outlive argv. */
static bool proof_prefork_argv(const char *jobs, bool lint_full,
                               const char **argv, size_t argv_cap)
{
    static const char *const helpers[] = {
        "zcl-nodectl", "zclassic23-acme", "fbsh", "engine-unit",
        "tools/file_size_policy", "fleet-board-bridge", "git-hook",
        "build/bin/z23-lint",
    };
    size_t n = 0;
    if (!jobs || !*jobs || !argv || argv_cap < PROOF_PREFORK_ARGV_CAP)
        return false;
    argv[n++] = "make";
    argv[n++] = "--no-print-directory";
    argv[n++] = jobs;
    for (size_t i = 0; i < sizeof(helpers) / sizeof(helpers[0]); i++)
        argv[n++] = helpers[i];
    if (lint_full) argv[n++] = "proof-lint-prebuild";
    argv[n] = NULL;
    return true;
}

#if defined(ZCL_TESTING)
/* Seam for the pre-fork argv, so a test can prove what the step builds --
 * and that no dimension is left a target the other one also builds --
 * without driving a proof cycle. */
bool zcl_dev_proof_test_prefork_argv(const char *jobs, bool lint_full,
                                     const char **argv, size_t argv_cap)
{
    return proof_prefork_argv(jobs, lint_full, argv, argv_cap);
}
#endif
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

/* Append one resolved group name to the comma-separated selector, refusing
 * rather than truncating: a selector that lost its tail would run a
 * narrower suite than the plan asked for. */
static bool dp_selector_append(char *out, size_t out_size, size_t *pos,
                               const char *full)
{
    int n = snprintf(out + *pos, out_size - *pos, "%s%s",
                     *pos ? "," : "", full);
    if (n <= 0 || (size_t)n >= out_size - *pos) return false;
    *pos += (size_t)n;
    return true;
}

/* Is this group already in the selector? Compares whole comma-separated
 * items, so no name is a prefix match for another. */
static bool dp_selector_has(const char *out, const char *full)
{
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
    return duplicate;
}

/* A capacity-bounded plan reaches more groups than it can enumerate. The
 * plan already turned that into the universal closure, so the proof runs
 * the whole catalog: a large run is the honest price of a change whose
 * blast radius does not fit in a list. */
static bool dp_selector_universal(char *out, size_t out_size, size_t *pos,
                                  uint32_t *count)
{
    for (size_t i = 0; i < zcl_test_group_catalog_count(); i++) {
        if (!dp_selector_append(out, out_size, pos,
                                zcl_test_group_catalog_at(i)))
            return false;
        (*count)++;
    }
    return true;
}

/* One of the plan's two group lists, resolved and appended without
 * repeating anything the selector already carries. */
static bool dp_selector_groups(const char (*groups)[ZCL_DEVLOOP_GROUP_MAX],
                               size_t len, char *out, size_t out_size,
                               size_t *pos, uint32_t *count)
{
    for (size_t i = 0; i < len; i++) {
        char full[128];
        if (!zcl_test_group_resolve_exact(groups[i], full)) return false;
        if (dp_selector_has(out, full)) continue;
        if (!dp_selector_append(out, out_size, pos, full)) return false;
        (*count)++;
    }
    return true;
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
    if (plan->closure_universal) {
        if (!dp_selector_universal(out, out_size, &pos, &count) ||
            count == 0)
            return false;
        *count_out = count;
        return true;
    }
    if (!dp_selector_groups(plan->path_groups, plan->path_groups_len, out,
                            out_size, &pos, &count) ||
        !dp_selector_groups(plan->closure_groups, plan->closure_groups_len,
                            out, out_size, &pos, &count))
        return false;
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

/* Every count the suite verdict line carries. */
struct dp_test_counts {
    uint32_t total;
    uint32_t ran;
    uint32_t reused;
    uint32_t gated;
    uint32_t failed;
    uint32_t skipped;
    uint32_t unobserved;
};

/* The one SUITE VERDICT line the run must have written. Exactly one, whole:
 * a truncated line or a second one is a log this reader cannot account
 * from, so it refuses instead of reading the last one it saw. */
static bool dp_test_verdict_read(const char *path, char *verdict,
                                 size_t verdict_size)
{
    FILE *f = fopen(path, "r");
    if (!f) return false;
    char line[4096];
    uint32_t verdict_count = 0;
    bool truncated = false;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "SUITE VERDICT ", 14) == 0) {
            verdict_count++;
            if (!strchr(line, '\n'))
                truncated = true;
            (void)snprintf(verdict, verdict_size, "%s", line);
        }
    }
    bool ok = !ferror(f) && !truncated && verdict_count == 1;
    fclose(f);
    return ok && verdict[0];
}

static bool dp_test_verdict_counts(const char *verdict,
                                   struct dp_test_counts *counts)
{
    return parse_uint_field(verdict, "groups_total=", &counts->total) &&
           parse_uint_field(verdict, "groups_ran=", &counts->ran) &&
           parse_uint_field(verdict, "groups_cached=", &counts->reused) &&
           parse_uint_field(verdict, "groups_gated=", &counts->gated) &&
           parse_uint_field(verdict, "groups_failed=", &counts->failed) &&
           parse_uint_field(verdict, "self_skips=", &counts->skipped) &&
           parse_uint_field(verdict, "env_unobserved=", &counts->unobserved);
}

static bool test_log_account(const char *path,
                             struct zcl_dev_proof_dimension *dim)
{
    char verdict[4096] = {0};
    if (!dp_test_verdict_read(path, verdict, sizeof(verdict))) return false;
    struct dp_test_counts counts = {0};
    if (!dp_test_verdict_counts(verdict, &counts)) return false;
    dim->ran = counts.ran;
    dim->reused = counts.reused;
    dim->failed = counts.failed;
    dim->skipped = counts.skipped;
    return (uint64_t)counts.total ==
               (uint64_t)counts.ran + counts.reused + counts.gated &&
           (uint64_t)counts.ran + counts.reused == dim->selected &&
           counts.failed == 0 && counts.skipped == 0 &&
           counts.unobserved == 0;
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

bool zcl_dev_proof_test_lint_argv(const char *root, const char *jobs,
                                  const char **argv, size_t argv_cap,
                                  size_t *argc_out, int64_t *fallback_ms,
                                  const char **targets_out)
{
    const char *targets = NULL;
    size_t n = 0;
    if (!argc_out || !proof_lint_prepare(root, jobs, argv, argv_cap,
                                         fallback_ms, &targets))
        return false;
    while (argv[n]) n++;
    *argc_out = n;
    if (targets_out) *targets_out = targets;
    return true;
}
/* Seam for the generation-hooks regression: the exact reconfiguration
 * generation_prepare() applies after copying build/githooks into a fresh
 * generation, so a test can prove a generation whose worktree config still
 * names the submitting checkout's hooks gets pointed at its own copy. */
bool zcl_dev_proof_test_generation_hooks_configure(const char *generation,
                                                   char *why, size_t why_len)
{
    return generation_hooks_configure(generation, why, why_len);
}

/* Seam for the lint-target split: true when the recorded target list is the
 * whole gate set rather than the fast subset. The proof asks this exact
 * question to decide whether the generation needs the admitted set. */
bool zcl_dev_proof_test_lint_targets_are_full(const char *targets)
{
    return proof_lint_targets_are_full(targets);
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

/* The executables a generation is handed rather than rebuilt, and the one
 * table both the lint and the test dimension read. Handing the lint
 * dimension a different set from the test dimension is what let a landing
 * proof judge `make lint` against artifacts the submitting checkout's own
 * `make lint` never saw: the full gate set reads build/bin/z23-dev
 * (check-capability-closure's nm closure, and the `lint:` umbrella's own
 * prerequisite at Makefile:13323) and the confined package verifier
 * alongside it. Every entry is admitted through
 * admitted_executable_materialize(), so each one is content-checked --
 * the source binary must report the exact source identity this proof
 * sealed -- before it is copied in; there is no weaker path.
 *
 * build/bin/zclassic23 is the compatibility alias (Makefile:642), and the
 * dev node is what a generation can admit: the release node exposes no
 * --source-record seam (engine/entry/main.c:196 guards it on
 * ZCL_DEV_BUILD), so it cannot be content-checked and is never admitted.
 * gate_doc_no_false_deleted reads the release binary by its own name for
 * exactly that reason. */
struct proof_admitted_executable {
    const char *source;  /* relative to the submitting checkout */
    const char *target;  /* relative to the generation */
};

static const struct proof_admitted_executable proof_admitted_executables[] = {
    {"build/bin/zclassic23-package-verify-dev",
     "build/bin/zclassic23-package-verify-dev"},
    {"build/bin/z23-dev", "build/bin/z23-dev"},
    {"build/bin/z23-dev", "build/bin/zclassic23"},
};

#define PROOF_ADMITTED_EXECUTABLE_COUNT \
    (sizeof(proof_admitted_executables) / sizeof(proof_admitted_executables[0]))

/* Index each entry by name: a caller that wants one path out of the set
 * must not have to count rows. */
enum {
    PROOF_ADMITTED_PACKAGE_VERIFY = 0,
    PROOF_ADMITTED_DEV_NODE = 1,
    PROOF_ADMITTED_NODE_ALIAS = 2,
};

/* Materialize that whole set into `generation`, marking each one fresh so
 * the generation's own `make` treats it as up to date instead of relinking
 * the whole dev object graph inside a gate. Both dimensions call this, so
 * neither can drift on to its own private set.
 *
 * Idempotent by content, not by flag: an entry the generation already
 * carries is re-read through the same executable_reuse() identity check
 * and kept, so a second call costs three `--source-record` execs rather
 * than three whole-binary copies, and a generation that rebuilt its own
 * bundle keeps the bytes it just built rather than being overwritten by a
 * submitting checkout whose binaries are older than the commit under
 * proof. */
static bool proof_admitted_executables_prepare(
    const struct proof_paths *paths, const char *generation,
    const struct dev_source_record *expected_source,
    char targets[PROOF_ADMITTED_EXECUTABLE_COUNT][PATH_MAX],
    char *why, size_t why_len)
{
    struct proof_paths carried = *paths;
    if ((size_t)snprintf(carried.root, sizeof(carried.root), "%s",
                         generation) >= sizeof(carried.root)) {
        proof_why(why, why_len, "proof_admitted_generation_path_too_long");
        return false;
    }
    for (size_t i = 0; i < PROOF_ADMITTED_EXECUTABLE_COUNT; i++) {
        char source[PATH_MAX];
        struct stat carried_st;
        if (snprintf(source, sizeof(source), "%s/%s", paths->root,
                     proof_admitted_executables[i].source) >=
                (int)sizeof(source) ||
            snprintf(targets[i], PATH_MAX, "%s/%s", generation,
                     proof_admitted_executables[i].target) >= PATH_MAX) {
            proof_whyf(why, why_len, "proof_admitted_path_too_long:%s",
                       proof_admitted_executables[i].target);
            return false;
        }
        struct zcl_dev_proof_dimension carried_artifact = {.selected = 1};
        char carried_why[160] = {0};
        if (lstat(targets[i], &carried_st) == 0 &&
            S_ISREG(carried_st.st_mode) &&
            executable_reuse(&carried, targets[i], expected_source,
                             &carried_artifact, carried_why,
                             sizeof(carried_why))) {
            if (!admitted_executable_mark_fresh(targets[i])) {
                proof_whyf(why, why_len,
                           "proof_admitted_freshness_failed:%s",
                           proof_admitted_executables[i].target);
                return false;
            }
            continue;
        }
        if (!admitted_executable_materialize(
                paths, generation, source,
                proof_admitted_executables[i].target, expected_source,
                targets[i], why, why_len)) {
            if (!why || !why[0])
                proof_whyf(why, why_len, "proof_admitted_refused:%s",
                           proof_admitted_executables[i].target);
            return false;
        }
        if (!admitted_executable_mark_fresh(targets[i])) {
            proof_whyf(why, why_len, "proof_admitted_freshness_failed:%s",
                       proof_admitted_executables[i].target);
            return false;
        }
    }
    return true;
}
#if defined(ZCL_TESTING)
/* Seam for the shared admitted-executable set: the exact table both the
 * lint and the test dimension materialize into a generation, so a test can
 * prove the two dimensions are handed the same executables without driving
 * a proof cycle. Returns the number of entries written. */
size_t zcl_dev_proof_test_admitted_executables(const char **sources,
                                               const char **targets,
                                               size_t cap)
{
    size_t n = PROOF_ADMITTED_EXECUTABLE_COUNT;
    if (n > cap) return 0;
    for (size_t i = 0; i < n; i++) {
        if (sources) sources[i] = proof_admitted_executables[i].source;
        if (targets) targets[i] = proof_admitted_executables[i].target;
    }
    return n;
}
#endif

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

/* Copy the checkout's current test-object epoch pointer into the
 * generation. The epoch name must be one path segment: anything else is a
 * pointer this proof cannot reason about. */
static bool dp_epoch_pointer_copy(const struct proof_paths *paths,
                                  const char *generation, const char *epoch,
                                  char target[PATH_MAX])
{
    char source[PATH_MAX];
    return epoch && epoch[1] && !strchr(epoch + 1, '/') &&
           snprintf(source, PATH_MAX, "%s/build/test-obj/.current-epoch",
                    paths->root) < PATH_MAX &&
           snprintf(target, PATH_MAX, "%s/build/test-obj/.current-epoch",
                    generation) < PATH_MAX &&
           dependency_parent_ensure(target) &&
           dependency_copy_fresh(source, target);
}

/* The pointer's value, trimmed of its line ending. A read that filled the
 * buffer is refused: the epoch would be indistinguishable from a longer
 * one that happens to share its first bytes. */
static bool dp_epoch_value_read(const char *target, char *value,
                                size_t value_size, size_t *len_out)
{
    int fd = open(target, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return false;
    ssize_t got;
    do {
        got = read(fd, value, value_size);
    } while (got < 0 && errno == EINTR);
    bool ok = close(fd) == 0 && got > 0 && got < (ssize_t)value_size;
    size_t len = ok ? (size_t)got : 0;
    while (len > 0 && (value[len - 1] == '\n' || value[len - 1] == '\r'))
        len--;
    *len_out = len;
    return ok;
}

static bool test_epoch_pointer_prepare(const struct proof_paths *paths,
                                       const char *generation,
                                       const char *object_dir,
                                       uint8_t pointer_root[32])
{
    const char *epoch = strrchr(object_dir, '/');
    char target[PATH_MAX];
    if (!dp_epoch_pointer_copy(paths, generation, epoch, target))
        return false;
    char value[72];
    size_t len = 0;
    if (!dp_epoch_value_read(target, value, sizeof(value), &len))
        return false;
    return strlen(epoch + 1) == len &&
        memcmp(value, epoch + 1, len) == 0 &&
        hash_file("zcl.dev_proof_epoch_pointer.v1", target, pointer_root);
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

/* Everything either dimension needs COPIED into the generation, admitted
 * once, before anything builds. Split out of the old test_helpers_prepare()
 * so the admission, the single build and the hashing are three ordered
 * steps rather than one function that interleaved them: the admitted set is
 * now materialized before the pre-fork make rather than half before and
 * half after, and no dimension ever sees a generation mid-admission.
 *
 * want_test admits the test runner and the depfile tree; want_lint_artifacts
 * says the lint dimension is running the full gate set, which reads
 * build/bin/z23-dev and the confined package verifier. The shared table is
 * materialized whenever EITHER is true, so the two dimensions cannot drift
 * on to their own sets, and every entry still goes through
 * admitted_executable_materialize()'s --source-record content check. */
static bool proof_generation_inputs_prepare(
    const struct proof_paths *paths, const char *generation,
    const struct dev_source_record *expected_source,
    bool want_test, bool want_lint_artifacts, const char *runner_source,
    char runner_target[PATH_MAX],
    char admitted[PROOF_ADMITTED_EXECUTABLE_COUNT][PATH_MAX],
    uint8_t depfile_root[32], char *why, size_t why_len)
{
    if (want_test &&
        !admitted_executable_materialize(
            paths, generation, runner_source, "build/bin/test_parallel_fast",
            expected_source, runner_target, why, why_len)) {
        if (!why || !why[0])
            proof_why(why, why_len, "proof_test_runner_admission_failed");
        return false;
    }
    /* The one admitted set, shared by both dimensions: same sources, same
     * content check, same generation paths.
     *
     * Idempotent by content: an entry the generation already carries is
     * re-read through the same executable_reuse() identity check and kept,
     * so a generation that rebuilt its own bundle keeps the bytes it just
     * built rather than being overwritten by a submitting checkout whose
     * binaries are older than the commit under proof. */
    if ((want_test || want_lint_artifacts) &&
        !proof_admitted_executables_prepare(paths, generation,
                                            expected_source, admitted,
                                            why, why_len)) {
        if (!why || !why[0])
            proof_why(why, why_len, "proof_lint_admission_failed");
        return false;
    }
    if (want_test &&
        !test_depfiles_prepare(paths, generation, depfile_root, why, why_len))
        return false;
    return true;
}

/* The ONE build step both dimensions share, run alone before either starts.
 * See proof_prefork_argv() for why it has to be one step and what it covers. */
static bool proof_prefork_build(const struct proof_paths *paths,
                                const char *generation, const char *make_jobs,
                                bool lint_full, char *why, size_t why_len)
{
    const char *argv[PROOF_PREFORK_ARGV_CAP];
    if (!proof_prefork_argv(make_jobs, lint_full, argv,
                            PROOF_PREFORK_ARGV_CAP)) {
        proof_why(why, why_len, "proof_prefork_argv_invalid");
        return false;
    }
    struct zcl_dev_proof_budget budget = proof_step_budget(
        paths, "prefork",
        lint_full ? PROOF_PREFORK_LANDING_MS : PROOF_PREFORK_DEFAULT_MS);
    if (run_step(paths, generation, paths->prefork_log, argv, "prefork",
                 &budget, NULL) != 0) {
        proof_why(why, why_len, "proof_prefork_build_failed");
        return false;
    }
    return true;
}

/* Hash what the pre-fork step admitted and built into the one
 * zcl.dev_proof_test_helpers.v1 digest the test receipt is bound to. Same
 * eleven artifacts, same order, same domains as before the split: the
 * receipt says exactly what it always said. */
/* The seven helper executables the generation builds for itself, in the
 * order they fold into the digest. */
#define PROOF_HELPER_BUILT_COUNT 7
/* Eleven artifacts fold into the test helper digest: the four the pre-fork
 * step admitted, plus the seven above. */
#define PROOF_HELPER_INPUT_COUNT 11

struct dp_helper_input {
    const char *domain;
    const char *path;
};

/* A path is usable only when it was spelled whole into its buffer. */
static bool dp_path_written(int n)
{
    return n > 0 && n < PATH_MAX;
}

static bool dp_helper_built_paths(
    const char *generation, char t[PROOF_HELPER_BUILT_COUNT][PATH_MAX])
{
    return dp_path_written(snprintf(t[0], PATH_MAX,
                                    "%s/build/bin/zcl-nodectl", generation)) &&
           dp_path_written(snprintf(t[1], PATH_MAX,
                                    "%s/build/bin/zclassic23-acme",
                                    generation)) &&
           dp_path_written(snprintf(t[2], PATH_MAX,
                                    "%s/build/bin/fbsh", generation)) &&
           dp_path_written(snprintf(t[3], PATH_MAX,
                                    "%s/build/bin/file_size_policy",
                                    generation)) &&
           dp_path_written(snprintf(t[4], PATH_MAX,
                                    "%s/build/bin/fleet-board-bridge",
                                    generation)) &&
           dp_path_written(snprintf(t[5], PATH_MAX,
                                    "%s/build/bin/z23-git-hook",
                                    generation)) &&
           dp_path_written(snprintf(t[6], PATH_MAX,
                                    "%s/build/bin/z23-lint", generation));
}

/* Each artifact under its own domain, so the same bytes carried by two
 * different executables can never hash alike. */
static bool dp_helper_roots(const struct dp_helper_input *inputs,
                            size_t count, uint8_t roots[][32])
{
    for (size_t i = 0; i < count; i++)
        if (!hash_file(inputs[i].domain, inputs[i].path, roots[i]))
            return false;
    return true;
}

/* Hash what the pre-fork step admitted and built into the one
 * zcl.dev_proof_test_helpers.v1 digest the test receipt is bound to. Same
 * eleven artifacts, same order, same domains as before the split: the
 * receipt says exactly what it always said. */
static bool test_helpers_hash(
    const char *generation, const char *runner_target,
    const char admitted[PROOF_ADMITTED_EXECUTABLE_COUNT][PATH_MAX],
    const uint8_t depfile_root[32], uint8_t helper_root[32],
    char *why, size_t why_len)
{
    char built[PROOF_HELPER_BUILT_COUNT][PATH_MAX];
    if (!dp_helper_built_paths(generation, built)) {
        proof_why(why, why_len, "proof_test_helper_path_invalid");
        return false;
    }
    const struct dp_helper_input inputs[PROOF_HELPER_INPUT_COUNT] = {
        {"zcl.dev_proof_test_runner.v1", runner_target},
        {"zcl.dev_proof_package_verifier.v1",
         admitted[PROOF_ADMITTED_PACKAGE_VERIFY]},
        {"zcl.dev_proof_test_node.v1", admitted[PROOF_ADMITTED_NODE_ALIAS]},
        {"zcl.dev_proof_dev_node.v1", admitted[PROOF_ADMITTED_DEV_NODE]},
        {"zcl.dev_proof_nodectl.v1", built[0]},
        {"zcl.dev_proof_acme_worker.v1", built[1]},
        {"zcl.dev_proof_fbsh.v1", built[2]},
        {"zcl.dev_proof_file_size_policy.v1", built[3]},
        {"zcl.dev_proof_board_bridge.v1", built[4]},
        {"zcl.dev_proof_git_hook.v1", built[5]},
        {"zcl.dev_proof_lint_tool.v1", built[6]},
    };
    uint8_t roots[PROOF_HELPER_INPUT_COUNT][32];
    if (!dp_helper_roots(inputs, PROOF_HELPER_INPUT_COUNT, roots)) {
        proof_why(why, why_len, "proof_test_helper_hash_failed");
        return false;
    }
    /* Named, because the digest's membership is the contract: a reader --
     * and the lint-gate self-test that pins this block -- must be able to
     * see each artifact go in by name, not by index. */
    const uint8_t *runner_root = roots[0], *verifier_root = roots[1];
    const uint8_t *node_root = roots[2], *dev_node_root = roots[3];
    const uint8_t *nodectl_root = roots[4], *acme_root = roots[5];
    const uint8_t *fbsh_root = roots[6], *file_size_policy_root = roots[7];
    const uint8_t *board_bridge_root = roots[8], *git_hook_root = roots[9];
    const uint8_t *lint_tool_root = roots[10];
    struct sha3_256_ctx helpers;
    hash_begin(&helpers, "zcl.dev_proof_test_helpers.v1");
    sha3_256_write(&helpers, runner_root, 32);
    sha3_256_write(&helpers, verifier_root, 32);
    sha3_256_write(&helpers, node_root, 32);
    sha3_256_write(&helpers, dev_node_root, 32);
    sha3_256_write(&helpers, nodectl_root, 32);
    sha3_256_write(&helpers, acme_root, 32);
    sha3_256_write(&helpers, fbsh_root, 32);
    sha3_256_write(&helpers, file_size_policy_root, 32);
    sha3_256_write(&helpers, board_bridge_root, 32);
    sha3_256_write(&helpers, git_hook_root, 32);
    sha3_256_write(&helpers, lint_tool_root, 32);
    sha3_256_write(&helpers, depfile_root, 32);
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
#define PROOF_GROUPS_MAX \
    (ZCL_DEVLOOP_MAX_PLAN_SELECTIONS * (ZCL_TEST_GROUP_FULL_MAX + 1))

/* Everything one proof's steps hand each other. `paths` names the
 * submitting checkout and `execution` the same path set with its root
 * swapped for the generation, so each step can say which tree it means --
 * the distinction that decides whether a `make` runs in the isolated
 * generation or in the developer's own checkout. Nothing here is authority:
 * the receipt is what this file publishes, and every field below is an
 * input to it. */
struct dp_worker {
    const struct proof_paths *paths;
    struct proof_paths execution;
    const char *local;
    const char *base;
    const char *generation;
    struct proof_phase_clock *phases;
    const struct proof_warmstart *warm;
    bool inventory_only;
    struct zcl_devloop_plan plan;
    char plan_json[ZCL_DEVLOOP_PLAN_WIRE_MAX];
    size_t plan_len;
    struct dev_source_record source_before;
    char sealed_source_id[65];
    char sealed_mutation_id[65];
    struct zcl_dev_proof_build_identity_v1 identity;
    struct zcl_dev_acceptance_receipt_v1 receipt;
    char make_jobs[16];
    char groups[PROOF_GROUPS_MAX];
    char only[PROOF_GROUPS_MAX + 8];
    /* Warm-start sidecar inputs, held here so the bundle step can rewrite
     * the sidecar with both build phases timed. */
    const char *warm_compile_mode;
    uint64_t warm_compile_ms;
    char binary[PATH_MAX];
    char generation_binary[PATH_MAX];
    char admitted[PROOF_ADMITTED_EXECUTABLE_COUNT][PATH_MAX];
    uint8_t depfile_root[32];
    uint8_t helper_root[32];
    const char *lint_argv[PROOF_LINT_ARGV_CAP];
    const char *lint_targets;
    struct zcl_dev_proof_budget lint_budget;
    bool lint_reads_artifacts;
};

/* The impact plan, closed and rendered once. */
static bool dp_worker_plan(struct dp_worker *w, const char *const *files,
                           size_t file_count, char *why, size_t why_len)
{
    if (!zcl_devloop_plan_files(files, file_count, &w->plan)) {
        proof_why(why, why_len, "impact_plan_invalid");
        return false;
    }
    const char *admission_reason = "";
    if (!zcl_devloop_plan_add_closure(w->paths->root, files, file_count,
                                      &w->plan) ||
        !zcl_devloop_plan_proof_admissible(&w->plan, &admission_reason)) {
        proof_why(why, why_len,
                  admission_reason && admission_reason[0]
                      ? admission_reason : "impact_plan_incomplete");
        return false;
    }
    proof_phase_mark(w->phases, "impact_plan_closure");
    /* Render the plan we just closed. The _closure spelling would open the
     * code index and re-walk the whole reverse-caller graph to rebuild the
     * plan sitting in this frame -- the most expensive phase of the proof,
     * paid twice for one answer. */
    w->plan_len = zcl_devloop_plan_json_render(
        &w->plan, files, file_count, w->plan_json, sizeof(w->plan_json));
    if (!w->plan_len) {
        proof_why(why, why_len, "impact_plan_render_failed");
        return false;
    }
    proof_phase_mark(w->phases, "impact_plan_render");
    return true;
}

/* The source identity this proof is about, sealed so every later step can
 * be checked against the same answer. */
static bool dp_worker_seal_source(struct dp_worker *w, char *why,
                                  size_t why_len)
{
    if (!worktree_exact(w->paths->root, w->local, true, why, why_len))
        return false;
    proof_phase_mark(w->phases, "worktree_exact_recheck");
    if (!zcl_dev_source_identity_capture(w->generation, &w->source_before, why,
                                         why_len)) {
        if (!why || !why[0])
            proof_why(why, why_len, "source_identity_capture_failed");
        return false;
    }
    if (!w->source_before.cas_present) {
        proof_why(why, why_len, "source_cas_capture_failed");
        return false;
    }
    proof_phase_mark(w->phases, "source_identity_capture");
    memcpy(w->sealed_source_id, w->source_before.source_id,
           sizeof(w->sealed_source_id));
    memcpy(w->sealed_mutation_id, w->source_before.mutation_id,
           sizeof(w->sealed_mutation_id));
    return true;
}

/* The commit pair, the source roots and the changed set, into the receipt. */
static bool dp_worker_receipt_identity(struct dp_worker *w, char *why,
                                       size_t why_len)
{
    struct zcl_dev_acceptance_receipt_v1 *receipt = &w->receipt;
    if (!zcl_dev_proof_oid_decode(w->local, receipt->local_commit,
                                  &receipt->local_commit_len) ||
        !zcl_dev_proof_oid_decode(w->base, receipt->remote_base,
                                  &receipt->remote_base_len) ||
        !zcl_hex_decode_lower(w->source_before.cas_root_sha3,
                              receipt->source_cas_root, 32) ||
        !zcl_hex_decode_lower(w->source_before.mutation_id,
                              receipt->mutation_root, 32)) {
        proof_why(why, why_len, "proof_identity_decode_failed");
        return false;
    }
    hash_text("zcl.dev_proof_git_source.v1", w->local, strlen(w->local),
              receipt->source_root);
    if (!hash_file("zcl.dev_proof_changed_set.v1", w->paths->changed,
                   receipt->changed_set_root)) {
        proof_why(why, why_len, "changed_set_hash_failed");
        return false;
    }
    return true;
}

/* The impact policy, the four build-identity roots, and the impact plan
 * digest that binds the policy to the plan this proof actually ran. */
static bool dp_worker_build_identity(struct dp_worker *w, char *why,
                                     size_t why_len)
{
    char policy_path[PATH_MAX];
    struct dev_source_record original_plan_source = {0};
    if (snprintf(policy_path, sizeof(policy_path),
                 "%s/cognition/controllers/include/controllers/agent_impact_rules.def",
                 w->generation) >= (int)sizeof(policy_path) ||
        !hash_file("zcl.dev_proof_impact_policy.v1", policy_path,
                   w->receipt.impact_policy_root)) {
        proof_why(why, why_len, "proof_toolchain_or_policy_unavailable");
        return false;
    }
    if (!proof_build_identity_capture(w->paths->root, &w->identity,
                                       original_plan_source.mutation_id,
                                       why, why_len)) {
        /* Keep the exact restart-plan diagnostic when capture supplied it. */
        if (!why || !why[0])
            proof_why(why, why_len, "proof_toolchain_or_policy_unavailable");
        return false;
    }
    /* BASE_GENERATION names this plan's own source metadata, not the
     * independent generation's inode/timestamp token. Check it locally
     * before accepting the portable flags and graph as requested inputs. */
    if (!zcl_dev_source_mutation_verify(w->paths->root, &original_plan_source,
                                        why, why_len)) {
        fprintf(stderr, "[devproof] original build plan: source mutation no longer matches\n");
        proof_why(why, why_len, "proof_original_build_plan_source_changed");
        return false;
    }
    /* The same four roots the warm-start donor marker seals, from the same
     * call: the receipt and the donor gate cannot disagree about what this
     * build was. */
    memcpy(w->receipt.compiler_root, w->identity.compiler, 32);
    memcpy(w->receipt.flags_root, w->identity.flags, 32);
    memcpy(w->receipt.environment_root, w->identity.environment, 32);
    memcpy(w->receipt.build_graph_root, w->identity.build_graph, 32);
    struct sha3_256_ctx impact;
    hash_begin(&impact, "zcl.dev_proof_impact_plan.v1");
    sha3_256_write(&impact, w->receipt.impact_policy_root, 32);
    sha3_256_write(&impact, (const uint8_t *)w->plan_json, w->plan_len);
    sha3_256_finalize(&impact, w->receipt.impact_policy_root);
    return true;
}

/* Which dimensions this proof runs, and the exact test selector. */
static bool dp_worker_select(struct dp_worker *w, char *why, size_t why_len)
{
    struct zcl_dev_proof_dimension *dims = w->receipt.dimensions;
    if (!proof_make_jobs_arg(w->make_jobs)) {
        proof_why(why, why_len, "proof_job_count_unavailable");
        return false;
    }
    dims[ZCL_DEV_PROOF_GENERATED].selected = w->inventory_only ? 1 : 0;
    bool compile_selected = !w->inventory_only && !w->plan.docs_only;
    dims[ZCL_DEV_PROOF_COMPILE].selected = compile_selected ? 1 : 0;
    dims[ZCL_DEV_PROOF_LINT].selected = w->inventory_only ? 0 : 1;
    uint32_t test_count = 0;
    if (!build_test_selector(&w->plan, w->inventory_only, w->groups,
                             sizeof(w->groups), &test_count)) {
        proof_why(why, why_len, "test_selection_invalid_or_truncated");
        return false;
    }
    dims[ZCL_DEV_PROOF_TEST].selected = test_count;
    /* Say why the run is this large, in a file a reader finds beside the test
     * log. Without this a universal selection looks like an unexplained
     * whole-catalog run. */
    if (!proof_note_test_selection(&w->execution, w->plan.closure_universal,
                                   test_count)) {
        proof_why(why, why_len, "test_selection_note_unwritable");
        return false;
    }
    return true;
}

static bool dp_dim_generated(struct dp_worker *w,
                             struct zcl_dev_proof_dimension *generated,
                             char *why, size_t why_len)
{
    if (!generated->selected) {
        unused_dimension(ZCL_DEV_PROOF_GENERATED, generated);
        return true;
    }
    const char *argv[] = {"make", "--no-print-directory", w->make_jobs,
                          "check-capability-inventory-generated", NULL};
    struct zcl_dev_proof_budget budget = proof_step_budget(
        w->paths, "generated", PROOF_GENERATED_DEFAULT_MS);
    return run_dimension(&w->execution, ZCL_DEV_PROOF_GENERATED, argv,
                         generated, false, &budget, why, why_len);
}

/* Reuse the submitting checkout's executable when its content matches the
 * sealed source; otherwise build in the generation and publish the donor
 * marker. Either way the sidecar says which happened. */
static bool dp_dim_compile(struct dp_worker *w,
                           struct zcl_dev_proof_dimension *compile,
                           char *why, size_t why_len)
{
    if (!compile->selected) {
        unused_dimension(ZCL_DEV_PROOF_COMPILE, compile);
        warm_sidecar_write(w->paths, w->warm, "skipped", 0, 0);
        return true;
    }
    char artifact[PATH_MAX];
    w->warm_compile_mode = "reused";
    int artifact_len = snprintf(artifact, sizeof(artifact),
                                "%s/build/bin/z23-dev", w->paths->root);
    if (artifact_len <= 0 || (size_t)artifact_len >= sizeof(artifact) ||
        !executable_reuse(w->paths, artifact,
                          &w->source_before, compile, NULL, 0)) {
        w->warm_compile_mode = "built";
        int64_t build_us0 = platform_time_monotonic_us();
        const char *argv[] = {"make", "--no-print-directory", w->make_jobs,
                              "build-only", NULL};
        struct zcl_dev_proof_budget budget = proof_step_budget(
            w->paths, "compile", PROOF_COMPILE_DEFAULT_MS);
        bool built = run_dimension(&w->execution, ZCL_DEV_PROOF_COMPILE,
                                   argv, compile, false, &budget, why,
                                   why_len);
        w->warm_compile_ms = (uint64_t)((platform_time_monotonic_us() -
                                         build_us0) / 1000);
        if (!built) {
            warm_sidecar_write(w->paths, w->warm, "failed",
                               w->warm_compile_ms, 0);
            return false;
        }
        /* The build finished for this commit: publish the donor
         * marker for the next generation. Best effort: a missing
         * marker only costs the next proof a cold build. */
        (void)warm_marker_write(w->generation, w->paths->root, w->local,
                                w->base);
    }
    warm_sidecar_write(w->paths, w->warm, w->warm_compile_mode,
                       w->warm_compile_ms, 0);
    return true;
}

/* The lint dimension's argv, budget and targets, and the two dimensions
 * that are not selected marked unused. */
static bool dp_worker_lint_plan(struct dp_worker *w,
                                struct zcl_dev_proof_dimension *lint,
                                struct zcl_dev_proof_dimension *test,
                                char *why, size_t why_len)
{
    int64_t lint_fallback_ms = PROOF_LINT_DEFAULT_MS;
    w->lint_targets = "lint-fast";
    if (!proof_lint_prepare(w->paths->root, w->make_jobs, w->lint_argv,
                            PROOF_LINT_ARGV_CAP, &lint_fallback_ms,
                            &w->lint_targets)) {
        proof_why(why, why_len, "lint_argv_invalid");
        return false;
    }
    w->lint_budget = proof_step_budget(w->paths, "lint", lint_fallback_ms);
    if (lint->selected && w->paths->phases[0])
        (void)zcl_dev_proof_phase_note(w->paths->phases, "lint_targets",
                                       w->lint_targets);
    if (!lint->selected) unused_dimension(ZCL_DEV_PROOF_LINT, lint);
    if (!test->selected) unused_dimension(ZCL_DEV_PROOF_TEST, test);
    /* Only the full gate set reads built artifacts (check-capability-
     * closure walks the undefined symbols of build/bin/z23-dev, and the
     * `lint:` umbrella names it and the confined package verifier as its
     * own prerequisites), so only it needs the admitted executables. A
     * lane proof on lint-fast pays none of this. */
    w->lint_reads_artifacts =
        lint->selected && proof_lint_targets_are_full(w->lint_targets);
    return true;
}

/* Everything that must still be true of the source before a test runner is
 * launched, plus the environment and the --exact argument it runs under.
 * The two identity rechecks are the reason a source edit during a proof
 * cannot be admitted by it. */
static bool dp_worker_test_env(struct dp_worker *w, char *why, size_t why_len)
{
    if (strcmp(w->source_before.source_id, w->sealed_source_id) != 0 ||
        strcmp(w->source_before.mutation_id, w->sealed_mutation_id) != 0) {
        proof_whyf(
            why, why_len,
            "proof_saved_source_identity_changed_source_actual_%.16s_sealed_%.16s"
            "_mutation_actual_%.16s_sealed_%.16s",
            w->source_before.source_id, w->sealed_source_id,
            w->source_before.mutation_id, w->sealed_mutation_id);
        return false;
    }
    struct dev_source_record generation_checkpoint = {0};
    char checkpoint_why[160] = {0};
    if (!zcl_dev_source_identity_capture(
            w->generation, &generation_checkpoint, checkpoint_why,
            sizeof(checkpoint_why))) {
        proof_whyf(why, why_len,
                   "proof_generation_source_checkpoint_%s",
                   checkpoint_why[0] ? checkpoint_why : "failed");
        return false;
    }
    if (strcmp(generation_checkpoint.source_id, w->sealed_source_id) != 0 ||
        strcmp(generation_checkpoint.mutation_id,
               w->sealed_mutation_id) != 0) {
        proof_whyf(
            why, why_len,
            "proof_generation_source_identity_changed_source_actual_%.16s_sealed_%.16s"
            "_mutation_actual_%.16s_sealed_%.16s",
            generation_checkpoint.source_id, w->sealed_source_id,
            generation_checkpoint.mutation_id, w->sealed_mutation_id);
        return false;
    }
    if (!proof_stress_tests_env_prepare(why, why_len)) return false;
    if (setenv("ZCL_TESTCACHE_STORE_ROOT", w->paths->root, 1) != 0) {
        proof_why(why, why_len, "test_cache_store_root_unavailable");
        return false;
    }
    if (snprintf(w->only, sizeof(w->only), "--exact=%s", w->groups) >=
        (int)sizeof(w->only)) {
        proof_why(why, why_len, "test_selection_invalid_or_truncated");
        return false;
    }
    return true;
}

/* The submitting checkout could not supply an admissible runner
 * or helper set: build one in the generation and re-admit. */
static bool dp_worker_bundle(struct dp_worker *w, bool test_selected,
                             char *why, size_t why_len)
{
    if (why && why_len > 0) why[0] = 0;
    const char *bundle_argv[] = {
        "make", "--no-print-directory", w->make_jobs,
        "dev-proof-bundle", NULL};
    struct zcl_dev_proof_budget bundle_budget =
        proof_step_budget(w->paths, "bundle", PROOF_BUNDLE_DEFAULT_MS);
    int64_t bundle_us0 = platform_time_monotonic_us();
    int bundle_rc = run_step(w->paths, w->generation, w->paths->bundle_log,
                             bundle_argv, "bundle", &bundle_budget, NULL);
    /* First attempt only; a recovery rerun is rare and stays
     * visible in the retry log. */
    uint64_t bundle_ms = (uint64_t)((platform_time_monotonic_us() -
                                     bundle_us0) / 1000);
    if (bundle_rc != 0 && proof_log_contains(
            w->paths->bundle_log,
            "unverified compile epoch appeared after recovery "
            "admission; rerun make")) {
        char retry_log[PATH_MAX];
        if (snprintf(retry_log, sizeof(retry_log), "%s.retry",
                     w->paths->bundle_log) >= (int)sizeof(retry_log)) {
            proof_why(why, why_len, "proof_bundle_retry_log_invalid");
            return false;
        }
        bundle_rc = run_step(w->paths, w->generation, retry_log,
                             bundle_argv, "bundle", &bundle_budget, NULL);
    }
    if (bundle_rc != 0) {
        proof_why(why, why_len, "proof_bundle_build_failed");
        return false;
    }
#if defined(__APPLE__)
    /* Compare the executed bundle's plan to the requested
     * flags and graph, binding its mutation token to this
     * generation's own source metadata. */
    if (!zcl_dev_proof_build_plan_verify(
            w->generation, &w->identity, w->sealed_mutation_id,
            why, why_len)) {
        return false;
    }
#endif
    if (!test_binary_path(&w->execution, w->binary) ||
        !proof_generation_inputs_prepare(
            &w->execution, w->generation, &w->source_before,
            test_selected, w->lint_reads_artifacts, w->binary,
            w->generation_binary, w->admitted, w->depfile_root, why,
            why_len)) {
        if (!why || !why[0])
            proof_why(why, why_len, "proof_bundle_admission_failed");
        return false;
    }
    /* Both build phases are timed now: refresh the sidecar so the
     * receipt directory carries the full compile story. */
    warm_sidecar_write(w->paths, w->warm, w->warm_compile_mode,
                       w->warm_compile_ms, bundle_ms);
    return true;
}

/* EVERYTHING EITHER DIMENSION BUILDS OR IS HANDED HAPPENS HERE,
 * BEFORE THE FORK, IN ONE SEQUENCE: the shared admitted executables,
 * the test runner, the depfile tree, and then a single `make` that
 * builds the helper executables and -- for a landing, whose lint
 * dimension runs the whole gate set -- every target that gate set
 * can build. After the fork the lint dimension's make has nothing
 * left to link and the test dimension runs no make at all, so
 * neither can relink a file the other is reading. Two makes in one
 * generation worktree race each other's build epochs, and a relink
 * unlinks its output before writing it: that is how a landing
 * proof's lint-gate shard exec'd a half-written build/bin/z23-lint
 * and got rc=127 twice.
 *
 * Admit, then build. The admission is content-checked against the
 * source identity this proof sealed, and marks each entry fresh, so
 * the build below treats them as up to date instead of relinking the
 * dev object graph. Doing it first also means the build is the LAST
 * thing that touches build/ before the fork. */
static bool dp_worker_prefork(struct dp_worker *w, bool test_selected,
                              char *why, size_t why_len)
{
    bool inputs_ready = !test_selected || test_binary_path(w->paths, w->binary);
    inputs_ready = inputs_ready &&
        proof_generation_inputs_prepare(
            w->paths, w->generation, &w->source_before, test_selected,
            w->lint_reads_artifacts, w->binary, w->generation_binary,
            w->admitted, w->depfile_root, why, why_len);
    if (!inputs_ready) {
        if (!test_selected) {
            if (!why || !why[0])
                proof_why(why, why_len, "proof_lint_admission_failed");
            return false;
        }
        if (!dp_worker_bundle(w, test_selected, why, why_len)) return false;
    }
    /* The one build both dimensions share. Nothing after this links
     * anything until both children have exited. */
    if ((test_selected || w->lint_reads_artifacts) &&
        !proof_prefork_build(w->paths, w->generation, w->make_jobs,
                             w->lint_reads_artifacts, why, why_len))
        return false;
    if (test_selected &&
        !test_helpers_hash(w->generation, w->generation_binary, w->admitted,
                           w->depfile_root, w->helper_root, why, why_len))
        return false;
    proof_phase_mark(w->phases, "prefork_inputs_and_build");
    return true;
}

/* Say how long lint actually took, beside the targets it ran. The
 * full gate set's cold cost inside a fresh generation -- dominated
 * by check-standalone-tools-link, which is the one gate that runs
 * `make` and links ~47 one-shot tools no compile dimension ever
 * built -- is the number the landing budget is set against, so the
 * next reader measures it instead of guessing. */
static void dp_worker_lint_wall_note(const struct dp_worker *w,
                                     const struct proof_dimension_run *runs,
                                     size_t run_count)
{
    for (size_t i = 0; i < run_count; i++) {
        char wall[32];
        if (runs[i].id != ZCL_DEV_PROOF_LINT || !w->paths->phases[0])
            continue;
        if (snprintf(wall, sizeof(wall), "%lld",
                     (long long)runs[i].step.report.elapsed_ms) <
            (int)sizeof(wall))
            (void)zcl_dev_proof_phase_note(w->paths->phases, "lint_wall_ms",
                                           wall);
    }
}

/* Lint proves the source; the test dimension proves the built
 * runner. Neither feeds the other, so both children are launched
 * before either is waited on and the proof pays for the longer of the
 * two rather than their sum. */
static bool dp_worker_dimensions_run(struct dp_worker *w,
                                     struct zcl_dev_proof_dimension *lint,
                                     struct zcl_dev_proof_dimension *test,
                                     char *why, size_t why_len)
{
    struct proof_dimension_run runs[2];
    size_t run_count = 0;
    const char *test_argv[] = {w->generation_binary, w->only, "--cache",
                               "--activate-proof-contracts", NULL};
    struct zcl_dev_proof_budget test_budget =
        zcl_dev_proof_test_budget(w->paths->state, w->groups, test->selected);
    if (lint->selected &&
        !dimension_start(&w->execution, w->execution.root, &runs[run_count],
                         ZCL_DEV_PROOF_LINT, w->lint_argv, lint, false,
                         &w->lint_budget, why, why_len))
        return false;
    if (lint->selected) run_count++;
    if (test->selected &&
        !dimension_start(&w->execution, w->execution.root, &runs[run_count],
                         ZCL_DEV_PROOF_TEST, test_argv, test, true,
                         &test_budget, why, why_len)) {
        dimension_runs_wait(runs, run_count);
        for (size_t i = 0; i < run_count; i++)
            (void)dimension_finish(&w->execution, &runs[i], NULL, 0);
        return false;
    }
    if (test->selected) run_count++;
    dimension_runs_wait(runs, run_count);
    dp_worker_lint_wall_note(w, runs, run_count);
    /* Fail closed on the first dimension that failed, in the order they
     * would have run sequentially, and always finish every child so each
     * one's log, receipt root and phases row survive the failure. */
    bool dimensions_ok = true;
    for (size_t i = 0; i < run_count; i++) {
        char step_why[160] = {0};
        if (dimension_finish(&w->execution, &runs[i], step_why,
                             sizeof(step_why)))
            continue;
        if (dimensions_ok) proof_why(why, why_len, step_why);
        dimensions_ok = false;
    }
    if (!dimensions_ok) return false;
    if (test->selected) test_receipt_bind_helpers(test, w->helper_root);
    return true;
}

/* Every dimension this proof actually runs, in order. */
static bool dp_worker_dimensions(struct dp_worker *w, char *why,
                                 size_t why_len)
{
    struct zcl_dev_proof_dimension *dims = w->receipt.dimensions;
    struct zcl_dev_proof_dimension *lint = &dims[ZCL_DEV_PROOF_LINT];
    struct zcl_dev_proof_dimension *test = &dims[ZCL_DEV_PROOF_TEST];
    if (!dp_dim_generated(w, &dims[ZCL_DEV_PROOF_GENERATED], why, why_len))
        return false;
    proof_phase_mark(w->phases, "dimension_generated");
    if (!dp_dim_compile(w, &dims[ZCL_DEV_PROOF_COMPILE], why, why_len))
        return false;
    proof_phase_mark(w->phases, "dimension_compile");
    if (!dp_worker_lint_plan(w, lint, test, why, why_len)) return false;
    w->only[0] = 0;
    if (test->selected && !dp_worker_test_env(w, why, why_len)) return false;
    if (!dp_worker_prefork(w, test->selected != 0, why, why_len)) return false;
    if (!dp_worker_dimensions_run(w, lint, test, why, why_len)) return false;
    proof_phase_mark(w->phases, "dimension_lint_and_test");
    return true;
}

/* Prove the source never moved under the run, then publish the receipt.
 * Nothing after this point may fail: the receipt IS the admission. */
static bool dp_worker_publish(struct dp_worker *w, int64_t started_us,
                              char *why, size_t why_len)
{
    struct dev_source_record source_after = {0};
    if (!worktree_exact(w->generation, w->local, false, why, why_len))
        return false;
    if (!zcl_dev_source_cas_capture(w->generation, &source_after) ||
        !source_after.cas_present) {
        proof_why(why, why_len, "source_cas_recapture_failed");
        return false;
    }
    if (strcmp(w->source_before.cas_root_sha3,
               source_after.cas_root_sha3) != 0) {
        proof_why(why, why_len, "source_epoch_superseded");
        return false;
    }
    if (!zcl_dev_source_mutation_verify(w->generation, &w->source_before,
                                        why, why_len)) {
        fprintf(stderr, "[devproof] generation source mutation changed before receipt publication\n");
        proof_why(why, why_len, "proof_generation_mutation_changed");
        return false;
    }
    w->receipt.created_unix = (uint64_t)platform_time_wall_unix();
    w->receipt.elapsed_ms =
        (uint64_t)((platform_time_monotonic_us() - started_us) / 1000);
    w->receipt.policy_version = ZCL_DEV_PROOF_POLICY_VERSION;
    w->receipt.complete = 1;
    if (!receipt_store(w->paths, &w->receipt)) {
        proof_why(why, why_len, "receipt_publication_failed");
        return false;
    }
    proof_unlink_if_current(w->paths, w->paths->failure);
    return true;
}

static bool proof_worker_body(const struct proof_paths *paths,
                              const char *local, const char *base,
                              const char *generation, int64_t started_us,
                              struct proof_phase_clock *phases,
                              const struct proof_warmstart *warm,
                              const char *const *files, size_t file_count,
                              char *why, size_t why_len)
{
    struct dp_worker w = {0};
    w.paths = paths;
    w.execution = *paths;
    (void)snprintf(w.execution.root, sizeof(w.execution.root), "%s",
                   generation);
    w.local = local;
    w.base = base;
    w.generation = generation;
    w.phases = phases;
    w.warm = warm;
    w.inventory_only = inventory_output_only(files, file_count);
    w.warm_compile_mode = "skipped";
    if (!dp_worker_plan(&w, files, file_count, why, why_len)) return false;
    if (!dp_worker_seal_source(&w, why, why_len)) return false;
    if (!dp_worker_receipt_identity(&w, why, why_len)) return false;
    if (!dp_worker_build_identity(&w, why, why_len)) return false;
    if (!dp_worker_select(&w, why, why_len)) return false;
    bool cycle_reused =
        !w.receipt.dimensions[ZCL_DEV_PROOF_GENERATED].selected &&
        cycle_proof_reuse(paths, w.source_before.cas_root_sha3,
                          w.receipt.dimensions);
    if (!cycle_reused && !dp_worker_dimensions(&w, why, why_len))
        return false;
    return dp_worker_publish(&w, started_us, why, why_len);
}

/* A post-merge hook can queue before the submitting checkout has rebuilt its
 * restart.env. Prepare through the canonical build before copying or sealing
 * compiler inputs; preparation is not evidence and never relaxes the checks
 * that follow it. */
static bool proof_original_plan_prepare(const struct proof_paths *paths,
                                        const char *root, const char *local,
                                        const char *log_path,
                                        char *why, size_t why_len)
{
    char jobs[16];
    if (!proof_make_jobs_arg(jobs)) {
        proof_why(why, why_len, "proof_job_count_unavailable");
        return false;
    }
    const char *argv[] = {"make", "--no-print-directory", jobs, "dev-bin", NULL};
    struct zcl_dev_proof_budget budget = proof_step_budget(
        paths, "original-plan", PROOF_COMPILE_DEFAULT_MS);
    struct zcl_dev_proof_step_report report = {0};
    if (run_step(paths, root, log_path, argv, "original-plan", &budget,
                  &report) != 0) {
        if (report.cause == ZCL_DEV_PROOF_KILL_NONE)
            proof_whyf(why, why_len, "proof_original_plan_prepare_exit_%d",
                        report.rc);
        else
            run_step_why(why, why_len, "original-plan", &report);
        return false;
    }
    if (!worktree_exact(root, local, true, why, why_len)) return false;
    uint8_t flags[32], graph[32];
    struct dev_source_record plan_source = {0};
    if (!proof_plan_roots(root, flags, graph, plan_source.mutation_id,
                           why, why_len) ||
        !zcl_dev_source_mutation_verify(root, &plan_source, why, why_len)) {
        fprintf(stderr, "[devproof] prepared build plan does not match source\n");
        proof_why(why, why_len, "proof_prepared_build_plan_source_changed");
        return false;
    }
    return true;
}

#if defined(ZCL_DEV_BUILD) || defined(ZCL_TESTING)
bool zcl_dev_proof_test_original_plan_prepare(const char *root,
                                              const char *local,
                                              const char *log_path,
                                              char *why, size_t why_len)
{
    return proof_original_plan_prepare(NULL, root, local, log_path, why, why_len);
}
#endif

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
    char prepare_log[PATH_MAX];
    if (snprintf(prepare_log, sizeof(prepare_log), "%s/original-plan.log",
                  paths->logs) >= (int)sizeof(prepare_log)) {
        proof_why(why, why_len, "proof_original_plan_log_path_invalid");
        return false;
    }
    if (!proof_original_plan_prepare(paths, paths->root, local, prepare_log,
                                      why, why_len))
        return false;
    proof_phase_mark(&phases, "original_plan_prepare");
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
    /* `generation` — not `paths->root` — is what this reads: a private git
     * worktree generation_prepare() just worktree_exact()'d to exactly
     * `local`, sharing paths->root's object database so `base` still
     * resolves. paths->root is the shared landing worktree a concurrent
     * `dev land step` can rebase out from under a still-running proof; a
     * changed-set capture that read it there could TOCTOU between this
     * call and the source-identity checkpoint proof_worker_body() takes on
     * `generation` moments later, refusing with remote_base_not_ancestor
     * for a base that was real when this request was queued. `generation`
     * is sealed by worktree_exact() above and touched by nothing else. */
    struct zcl_dev_proof_changed_set changed = {0};
    if (!zcl_dev_proof_changed_set_capture(generation, base, local, scratch,
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
        char failure_log[PATH_MAX];
        if (snprintf(failure_log, sizeof(failure_log), "%s/failure.txt",
                     paths->logs) < (int)sizeof(failure_log))
            (void)proof_write_if_current(paths, failure_log, message,
                                         strlen(message), 0600);
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

/* Everything the queue lock protects, in one step: pick the oldest pending
 * request, build its paths, publish a lease, move the request into this
 * attempt, and fold away the requests it supersedes. Returns 0 when the
 * queue was empty, 1 when this attempt now owns a pair, -1 when the claim
 * failed. The caller holds and releases the lock. */
static int dp_queue_claim_locked(const char *repo_root, const char *requests,
                                 const char *attempts,
                                 char selected[PATH_MAX], char local[65],
                                 char base[65], struct proof_paths *pair,
                                 struct proof_paths *attempt)
{
    if (!proof_queue_select(requests, selected, local, base)) return 0;
    char claimed[PATH_MAX];
    bool prepared = proof_paths_fill(repo_root, local, base, pair) &&
        proof_state_prepare(pair) &&
        proof_attempt_paths_prepare(pair, attempt) &&
        snprintf(claimed, sizeof(claimed), "%s/request", attempt->attempt) <
            (int)sizeof(claimed) && proof_lease_publish(attempt);
    if (prepared && rename(selected, claimed) != 0) {
        if (proof_lease_current(attempt)) (void)unlink(attempt->lease);
        prepared = false;
    }
    if (!prepared) return -1;
    proof_queue_coalesce(pair->root, requests, selected, attempts, local,
                         base);
    return 1;
}

/* A sibling queue.lock is the existing landing-root marker. Inspect it
 * without following links so a broken marker cannot turn a landing proof
 * into an ordinary unguarded proof. The row lock itself is never held here. */
static int dp_landing_step_path(const char *root, char step[PATH_MAX])
{
    char marker[PATH_MAX];
    struct stat st;
    if (!zcl_devloop_landing_queue_lock_path(root, marker, sizeof(marker)))
        return -1;
    if (lstat(marker, &st) != 0) return errno == ENOENT ? 0 : -1;
    if (!S_ISREG(st.st_mode) || st.st_uid != geteuid()) return -1;
    int len = snprintf(step, PATH_MAX, "%s/../step.lock", root);
    return len > 0 && len < PATH_MAX ? 1 : -1;
}

/* Open the same persistent inode used by native_dev_land's exclusive step
 * writer. Only this private regular lock is trusted; a replaced path or
 * symlink must not give the worker an unrelated lock to hold. */
static int dp_landing_step_open(const char *step)
{
    int fd = open(step, O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK,
                   0600);
    if (fd < 0) return -1;
    struct stat held, named;
    bool valid = fstat(fd, &held) == 0 && lstat(step, &named) == 0 &&
        S_ISREG(held.st_mode) && S_ISREG(named.st_mode) &&
        held.st_uid == geteuid() &&
        (held.st_mode & (S_IWGRP | S_IWOTH)) == 0 &&
        held.st_dev == named.st_dev && held.st_ino == named.st_ino;
    if (valid) return fd;
    (void)close(fd);
    return -1;
}

/* Preparation owns LOCK_EX on step.lock. A proof shares that same lock
 * from before claim until all worker evidence and lease cleanup settle.
 * Contention is deferred work, never a failed proof observation. */
static int dp_landing_proof_guard(const char *root, int *guard,
                                  char *why, size_t why_len)
{
    *guard = -1;
    char step[PATH_MAX];
    int landing = dp_landing_step_path(root, step);
    if (landing == 0) return 1;
    if (landing < 0) {
        proof_why(why, why_len, "proof_landing_queue_lock_invalid");
        return -1;
    }
    int fd = dp_landing_step_open(step);
    if (fd < 0) {
        proof_why(why, why_len, "proof_landing_step_lock_failed");
        return -1;
    }
    if (flock(fd, LOCK_SH | LOCK_NB) == 0) {
        *guard = fd;
        return 1;
    }
    int saved = errno;
    (void)close(fd);
    if (saved == EWOULDBLOCK || saved == EAGAIN) {
        proof_why(why, why_len, "proof_landing_preparation_busy");
        return 0;
    }
    proof_why(why, why_len, "proof_landing_step_lock_failed");
    return -1;
}

static int dp_proof_queue_run_guarded(const char *repo_root,
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
    struct proof_paths pair, attempt;
    int claimed = dp_queue_claim_locked(repo_root, requests, attempts,
                                        selected, local, base, &pair,
                                        &attempt);
    (void)flock(fd, LOCK_UN);
    close(fd);
    if (claimed == 0) return 0;
    if (claimed < 0) {
        proof_why(why, why_len, "proof_queue_claim_failed");
        return -1;
    }
    if (why && why_len) why[0] = 0;
    (void)proof_worker_run(&attempt, local, base, why, why_len);
    return 1;
}

static int proof_queue_run_next_platform(const char *repo_root,
                                         char *why, size_t why_len)
{
    char root[PATH_MAX];
    if (!repo_root || !platform_directory_canonical_real(repo_root, root,
                                                         sizeof(root))) {
        proof_why(why, why_len, "proof_queue_path_invalid");
        return -1;
    }
    int guard = -1;
    int ready = dp_landing_proof_guard(root, &guard, why, why_len);
    if (ready <= 0) return ready;
    int result = dp_proof_queue_run_guarded(root, why, why_len);
    proof_queue_lock_release(guard);
    return result;
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
    /* A `.failed` marker settles the latest attempt for this exact pair.
     * Automatic re-enqueueing here would spend a worker slot repeating an
     * unrepaired failure and would leave
     * a caller that only checks for MISSING/RUNNING believing work is
     * still in flight. Only explicit retry after prerequisite repair may
     * queue another attempt; ordinary ensure preserves the settled status. */
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

/* Unknown marker contents are not evidence that a worker has stopped. A
 * valid stale marker is harmless only when the kernel confirms ESRCH. */
static bool dp_retry_worker_settled(const char *path, bool lease)
{
    struct stat st;
    if (lstat(path, &st) != 0) return errno == ENOENT;
    if (!proof_private_regular(path)) return false;
    int64_t pid = 0;
    if (lease) {
        char token[192];
        if (!proof_lease_read(path, token, sizeof(token), &pid, NULL))
            return false;
    } else {
        char body[128];
        long long parsed_pid = 0, started = 0;
        if (!proof_read_text(path, body, sizeof(body)) ||
            sscanf(body, "%lld %lld", &parsed_pid, &started) != 2 ||
            parsed_pid <= 1 || started <= 0)
            return false;
        pid = (int64_t)parsed_pid;
    }
    if ((int64_t)(pid_t)pid != pid) return false;
    return kill((pid_t)pid, 0) != 0 && errno == ESRCH;
}

static bool dp_retry_absent(const char *path)
{
    struct stat st;
    return lstat(path, &st) != 0 && errno == ENOENT;
}

/* Keep exact bytes, including any trailing newline, beside the failed
 * attempt's logs. Existing archived evidence is checked, never replaced.
 * Older marker-only failures have no attributable attempt and refuse. */
static bool dp_retry_archive_failure(const struct proof_paths *paths,
                                      char *why, size_t why_len)
{
    char logs[PATH_MAX], archive[PATH_MAX];
    struct stat st;
    uint8_t failure[256], prior[256];
    size_t size = 0;
    if (!proof_failure_bytes(paths->failure, failure, &size)) {
        proof_why(why, why_len, "proof_retry_failure_evidence_invalid");
        return false;
    }
    bool conflict = false;
    if (!proof_failure_attempt_logs(paths, logs, sizeof(logs), &conflict)) {
        proof_why(why, why_len, conflict ? "proof_retry_failure_archive_conflict"
                                         : "proof_retry_failure_attempt_missing");
        return false;
    }
    if (lstat(logs, &st) != 0 || !S_ISDIR(st.st_mode) ||
        snprintf(archive, sizeof(archive), "%s/failure.txt", logs) >=
            (int)sizeof(archive)) {
        proof_why(why, why_len, "proof_retry_failure_attempt_missing");
        return false;
    }
    if (!dp_retry_absent(archive)) {
        if (read_exact_file(archive, prior, size) &&
            memcmp(prior, failure, size) == 0)
            return true;
        proof_why(why, why_len, "proof_retry_failure_archive_conflict");
        return false;
    }
    if (write_atomic(archive, failure, size, 0600)) return true;
    proof_why(why, why_len, "proof_retry_failure_archive_failed");
    return false;
}

/* Called only while holding the queue's existing claim/publication lock.
 * The old pair marker remains until the normal worker replaces it; a
 * queued request already takes precedence in the status projection. */
static bool dp_retry_locked(const struct proof_paths *paths,
                             const char *local, const char *base,
                             struct zcl_dev_proof_status *out)
{
    if (!zcl_dev_proof_status_read(paths->root, local, base, out)) return false;
    const char *refusal = NULL;
    if (out->state != ZCL_DEV_PROOF_STATE_FAILED)
        refusal = "proof_retry_requires_settled_failure";
    else if (!dp_retry_absent(paths->receipt))
        refusal = "proof_retry_receipt_present";
    else if (!dp_retry_absent(paths->request))
        refusal = "proof_retry_request_present";
    else if (!dp_retry_worker_settled(paths->lease, true) ||
             !dp_retry_worker_settled(paths->lock, false))
        refusal = "proof_retry_worker_not_settled";
    if (refusal) {
        proof_why(out->detail, sizeof(out->detail), refusal);
        return false;
    }
    if (!dp_retry_archive_failure(paths, out->detail, sizeof(out->detail)))
        return false;
    char body[320];
    size_t body_len = 0;
    if (!proof_request_body(local, base, body, &body_len) ||
        !write_atomic(paths->request, body, body_len, 0600)) {
        proof_why(out->detail, sizeof(out->detail), "resident_proof_enqueue_failed");
        return false;
    }
    return zcl_dev_proof_status_read(paths->root, local, base, out);
}

static bool proof_retry_platform(const char *repo_root,
                                 const char *local_commit,
                                 const char *remote_base,
                                 struct zcl_dev_proof_status *out)
{
    if (!out || !zcl_dev_proof_status_read(repo_root, local_commit,
                                           remote_base, out))
        return false;
    if (out->state != ZCL_DEV_PROOF_STATE_FAILED) {
        proof_why(out->detail, sizeof(out->detail),
                   "proof_retry_requires_settled_failure");
        return false;
    }
    char local[65], base[65];
    (void)snprintf(local, sizeof(local), "%s", out->local_commit);
    (void)snprintf(base, sizeof(base), "%s", out->remote_base);
    struct proof_paths paths;
    if (!proof_paths_fill(repo_root, local, base, &paths) ||
        !proof_state_prepare(&paths)) {
        proof_why(out->detail, sizeof(out->detail), "proof_state_unavailable");
        return false;
    }
    int fd = proof_queue_lock_acquire(&paths);
    if (fd < 0) {
        proof_why(out->detail, sizeof(out->detail), "proof_queue_lock_failed");
        return false;
    }
    bool queued = dp_retry_locked(&paths, local, base, out);
    proof_queue_lock_release(fd);
    return queued;
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

bool zcl_dev_proof_retry(const char *repo_root,
                         const char *local_commit,
                         const char *remote_base,
                         struct zcl_dev_proof_status *out)
{
    return proof_retry_platform(repo_root, local_commit, remote_base, out);
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
