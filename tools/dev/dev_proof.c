/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Admit exact commit/base pairs from the resident development proof. */

#define _POSIX_C_SOURCE 200809L

#include "dev_proof.h"
#include "devloop.h"
#include "test_group_catalog.h"

#include "base/hex.h"
#include "base/serialize_le.h"
#include "json/json.h"
#include "platform/directory_compat.h"
#include "platform/logical_cpu.h"
#include "platform/private_directory.h"
#include "platform/time_compat.h"
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

#define PROOF_MAX_FILES ZCL_DEVLOOP_MAX_FILES
#define PROOF_MAX_JOBS 16u
#define PROOF_TIMEOUT_MS 3600000
#define PROOF_ENV_DOMAIN "zcl.dev_proof_environment.v1"

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
    int64_t attempt_worker;
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

const char *zcl_dev_proof_state_name(enum zcl_dev_proof_state state)
{
    switch (state) {
    case ZCL_DEV_PROOF_STATE_MISSING: return "missing";
    case ZCL_DEV_PROOF_STATE_RUNNING: return "running";
    case ZCL_DEV_PROOF_STATE_PASSED: return "passed";
    case ZCL_DEV_PROOF_STATE_FAILED: return "failed";
    case ZCL_DEV_PROOF_STATE_INVALID: return "invalid";
    }
    return "invalid";
}

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
                 out->logs, out->key) >= (int)sizeof(out->helper_log))
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

static bool git_capture(const char *root, const char *const argv[],
                        char *out, size_t out_size)
{
    struct zcl_devloop_process_result result = {0};
    if (!root || !argv || !out || out_size == 0 ||
        !zcl_devloop_process_run(root, argv, 30000, &result) ||
        !process_ok(&result) || result.output_len >= out_size)
        return false;
    size_t len = result.output_len;
    while (len > 0 && (result.output[len - 1] == '\n' ||
                       result.output[len - 1] == '\r'))
        len--;
    memcpy(out, result.output, len);
    out[len] = 0;
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
    struct zcl_dev_acceptance_receipt_v1 receipt;
    if (receipt_load(&paths, local, base, &receipt, why, sizeof(why))) {
        out->state = ZCL_DEV_PROOF_STATE_PASSED;
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
        out->eta_ms = elapsed_ms < PROOF_TIMEOUT_MS
            ? PROOF_TIMEOUT_MS - elapsed_ms : 0;
        (void)snprintf(out->detail, sizeof(out->detail), "%s",
                       "background_verification_running");
        return true;
    }
    if (proof_request_matches_pair(paths.request, local, base)) {
        out->state = ZCL_DEV_PROOF_STATE_RUNNING;
        out->eta_ms = PROOF_TIMEOUT_MS;
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

static bool changed_files_capture(const struct proof_paths *paths,
                                  const char *local, const char *base,
                                  char files[PROOF_MAX_FILES][256],
                                  const char *refs[PROOF_MAX_FILES],
                                  size_t *count_out, char *why, size_t why_len)
{
    const char *ancestor[] = {"git", "merge-base", "--is-ancestor", base,
                              local, NULL};
    char ignored[2];
    if (!git_capture(paths->root, ancestor, ignored, sizeof(ignored))) {
        proof_why(why, why_len, "remote_base_not_ancestor");
        return false;
    }
    const char *argv[] = {"git", "diff", "--name-only", "--diff-filter=ACMRD",
                          base, local, "--", NULL};
    char output[ZCL_DEVLOOP_OUTPUT_MAX];
    if (!git_capture(paths->root, argv, output, sizeof(output))) {
        proof_why(why, why_len, "changed_set_unavailable_or_truncated");
        return false;
    }
    size_t count = 0;
    char *save = NULL;
    for (char *line = strtok_r(output, "\n", &save); line;
         line = strtok_r(NULL, "\n", &save)) {
        size_t len = strlen(line);
        if (len == 0) continue;
        if (count >= PROOF_MAX_FILES || len >= sizeof(files[0]) ||
            line[0] == '/' || strstr(line, "..") || strchr(line, '\\')) {
            proof_why(why, why_len, "changed_set_invalid_or_truncated");
            return false;
        }
        (void)snprintf(files[count], sizeof(files[count]), "%s", line);
        refs[count] = files[count];
        count++;
    }
    if (count == 0) {
        proof_why(why, why_len, "changed_set_empty");
        return false;
    }
    char persisted[ZCL_DEVLOOP_OUTPUT_MAX];
    size_t used = 0;
    for (size_t i = 0; i < count; i++) {
        size_t len = strlen(refs[i]);
        if (len + 1 >= sizeof(persisted) - used) {
            proof_why(why, why_len, "changed_set_persist_truncated");
            return false;
        }
        memcpy(persisted + used, refs[i], len);
        used += len;
        persisted[used++] = '\n';
    }
    if (!write_atomic(paths->changed, persisted, used, 0400)) {
        proof_why(why, why_len, "changed_set_persist_failed");
        return false;
    }
    *count_out = count;
    return true;
}

static bool worktree_exact(const char *root, const char *local,
                           bool include_untracked, char *why, size_t why_len)
{
    char head[65], status[ZCL_DEVLOOP_OUTPUT_MAX];
    const char *head_argv[] = {"git", "rev-parse", "--verify", "HEAD", NULL};
    const char *status_argv[] = {
        "git", "status", "--porcelain=v1",
        include_untracked ? "--untracked-files=normal" : "--untracked-files=no",
        NULL};
    if (!git_capture(root, head_argv, head, sizeof(head)) ||
        strcmp(head, local) != 0) {
        proof_why(why, why_len, "head_changed_during_proof");
        return false;
    }
    if (!git_capture(root, status_argv, status, sizeof(status)) || status[0]) {
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
        if (target_exists && S_ISREG(target_st.st_mode) &&
            source_st.st_dev == target_st.st_dev &&
            source_st.st_ino == target_st.st_ino)
            return true;
        if (target_exists && unlink(target) != 0) return false;
        return link(source, target) == 0;
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

static bool generation_prepare(const struct proof_paths *paths,
                               const char *local, char generation[PATH_MAX],
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
    if (snprintf(parent, sizeof(parent), "%s/.z23p", root_parent) >=
            (int)sizeof(parent) ||
        snprintf(generation, PATH_MAX, "%s/%s", parent, generation_tag) >=
            PATH_MAX ||
        !platform_private_directory_ensure(parent)) {
        proof_why(why, why_len, "proof_generation_path_invalid");
        return false;
    }
    struct stat st;
    if (lstat(generation, &st) != 0) {
        if (errno != ENOENT) {
            proof_why(why, why_len, "proof_generation_inspection_failed");
            return false;
        }
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
        "build/githooks", "build/bin/z23-git-hook",
        /* Order-only test-binary prerequisites that no admitted executable
         * links against: the rollback group dlopens these fixture images by
         * name, so an exact generation without them cannot run the group. */
        "build/hotswap/zcl_rollback_fixture_a.so",
        "build/hotswap/zcl_rollback_fixture_b.so",
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
                     dependencies[i]) >= (int)sizeof(target) ||
            !dependency_parent_ensure(target) ||
            !dependency_materialize(source, target)) {
            /* vendor/ entries come from the vendored-archive build; the
             * git-hook pair comes from arming the clone; the hotswap
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
    }
    if (!worktree_exact(generation, local, false, why, why_len)) {
        proof_why(why, why_len, "proof_generation_not_exact");
        return false;
    }
    return true;
}

static int run_logged(const char *root, const char *log_path,
                      const char *const argv[], int timeout_ms)
{
    pid_t child = fork();
    if (child < 0) return -1;
    if (child == 0) {
        if (setsid() < 0 || chdir(root) != 0) _exit(127);
        struct rlimit stack = {.rlim_cur = RLIM_INFINITY,
                               .rlim_max = RLIM_INFINITY};
        (void)setrlimit(RLIMIT_STACK, &stack);
        int fd = open(log_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
        if (fd < 0 || dup2(fd, STDOUT_FILENO) < 0 ||
            dup2(fd, STDERR_FILENO) < 0)
            _exit(127);
        if (fd > STDERR_FILENO) close(fd);
        execvp(argv[0], (char *const *)argv);
        _exit(127);
    }
    int64_t deadline = platform_time_monotonic_us() + (int64_t)timeout_ms * 1000;
    int status = 0;
    for (;;) {
        pid_t got = waitpid(child, &status, WNOHANG);
        if (got == child) break;
        if (got < 0 && errno != EINTR) return -1;
        if (platform_time_monotonic_us() >= deadline) {
            (void)kill(-child, SIGTERM);
            platform_sleep_ms(100);
            (void)kill(-child, SIGKILL);
            (void)waitpid(child, &status, 0);
            return 124;
        }
        platform_sleep_ms(20);
    }
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    return WIFSIGNALED(status) ? 128 + WTERMSIG(status) : -1;
}

static bool inventory_output_only(const char *const *files, size_t count)
{
    return count == 1 &&
           strcmp(files[0], "docs/CAPABILITY_INVENTORY.jsonl") == 0;
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

static bool run_dimension(const struct proof_paths *paths,
                          enum zcl_dev_proof_dimension_id id,
                          const char *const argv[],
                          struct zcl_dev_proof_dimension *dim,
                          bool parse_test, char *why, size_t why_len)
{
    char log[PATH_MAX];
    if (snprintf(log, sizeof(log), "%s/%s.%s.log", paths->logs, paths->key,
                 zcl_dev_proof_dimension_name(id)) >= (int)sizeof(log))
        return false;
    int rc = run_logged(paths->root, log, argv, PROOF_TIMEOUT_MS);
    if (!hash_file(zcl_dev_proof_dimension_name(id), log, dim->receipt_root)) {
        proof_why(why, why_len, "child_receipt_hash_failed");
        return false;
    }
    if (rc != 0) {
        dim->failed = 1;
        if (why && why_len)
            (void)snprintf(why, why_len, "child_proof_failed_exit_%d", rc);
        return false;
    }
    if (parse_test) {
        if (!test_log_account(log, dim)) {
            proof_why(why, why_len, "test_accounting_incomplete");
            return false;
        }
    } else {
        dim->ran = dim->selected;
    }
    return true;
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

static bool environment_root(uint8_t out[32])
{
    static const char *const names[] = {
        "CC", "CFLAGS", "CPPFLAGS", "LDFLAGS", "LANG", "LC_ALL",
        "PATH", "ZCL_FAST_CC", "ZCL_FAST_JOBS",
    };
    struct sha3_256_ctx sha;
    hash_begin(&sha, PROOF_ENV_DOMAIN);
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        const char *value = getenv(names[i]);
        sha3_256_write(&sha, (const uint8_t *)names[i], strlen(names[i]) + 1);
        sha3_256_write(&sha, (const uint8_t *)(value ? value : ""),
                       value ? strlen(value) + 1 : 1);
    }
    sha3_256_finalize(&sha, out);
    return true;
}

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
    if (verifier_len <= 0 ||
        (size_t)verifier_len >= sizeof(verifier_source) ||
        node_len <= 0 || (size_t)node_len >= sizeof(node_source) ||
        nodectl_len <= 0 || (size_t)nodectl_len >= sizeof(nodectl_target) ||
        acme_len <= 0 || (size_t)acme_len >= sizeof(acme_target) ||
        fbsh_len <= 0 || (size_t)fbsh_len >= sizeof(fbsh_target)) {
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
        "zclassic23-acme", "fbsh", NULL};
    if (run_logged(generation, paths->helper_log, prerequisite_argv,
                   120000) != 0) {
        proof_why(why, why_len, "proof_test_helper_build_failed");
        return false;
    }
    uint8_t runner_root[32], verifier_root[32], node_root[32], nodectl_root[32];
    uint8_t acme_root[32], fbsh_root[32];
    if (!hash_file("zcl.dev_proof_test_runner.v1", runner_target,
                   runner_root) ||
        !hash_file("zcl.dev_proof_package_verifier.v1", verifier_target,
                   verifier_root) ||
        !hash_file("zcl.dev_proof_test_node.v1", node_target, node_root) ||
        !hash_file("zcl.dev_proof_nodectl.v1", nodectl_target,
                   nodectl_root) ||
        !hash_file("zcl.dev_proof_acme_worker.v1", acme_target, acme_root) ||
        !hash_file("zcl.dev_proof_fbsh.v1", fbsh_target, fbsh_root)) {
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

static bool proof_worker(const struct proof_paths *paths,
                         const char *local, const char *base,
                         char *why, size_t why_len)
{
    int64_t started_us = platform_time_monotonic_us();
    if (!worktree_exact(paths->root, local, true, why, why_len)) return false;
    char generation[PATH_MAX];
    if (!generation_prepare(paths, local, generation, why, why_len))
        return false;
    struct proof_paths execution = *paths;
    (void)snprintf(execution.root, sizeof(execution.root), "%s", generation);
    char files_storage[PROOF_MAX_FILES][256];
    const char *files[PROOF_MAX_FILES];
    size_t file_count = 0;
    if (!changed_files_capture(paths, local, base, files_storage, files,
                               &file_count, why, why_len))
        return false;

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
    char plan_json[ZCL_DEVLOOP_PLAN_WIRE_MAX];
    size_t plan_len = zcl_devloop_plan_json_closure(
        paths->root, files, file_count, plan_json, sizeof(plan_json));
    if (!plan_len) {
        proof_why(why, why_len, "impact_plan_render_failed");
        return false;
    }
    if (!worktree_exact(paths->root, local, true, why, why_len)) return false;

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
    char policy_path[PATH_MAX], action_path[PATH_MAX];
    if (snprintf(policy_path, sizeof(policy_path),
                 "%s/cognition/controllers/include/controllers/agent_impact_rules.def",
                 generation) >= (int)sizeof(policy_path) ||
        snprintf(action_path, sizeof(action_path),
                 "%s/build/dev-loop/restart.env", paths->root) >=
            (int)sizeof(action_path) ||
        !hash_file("zcl.dev_proof_impact_policy.v1", policy_path,
                   receipt.impact_policy_root) ||
        !hash_file("zcl.dev_proof_compiler.v1", action_path,
                   receipt.compiler_root) ||
        !hash_file("zcl.dev_proof_flags.v1", action_path,
                   receipt.flags_root) ||
        !hash_file("zcl.dev_proof_build_graph.v1", action_path,
                   receipt.build_graph_root) ||
        !environment_root(receipt.environment_root)) {
        proof_why(why, why_len, "proof_toolchain_or_policy_unavailable");
        return false;
    }
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
    bool cycle_reused = !generated->selected && cycle_proof_reuse(
        paths, source_before.cas_root_sha3, receipt.dimensions);
    if (!cycle_reused) {
        if (generated->selected) {
            const char *argv[] = {"make", "--no-print-directory", make_jobs,
                                  "check-capability-inventory-generated", NULL};
            if (!run_dimension(&execution, ZCL_DEV_PROOF_GENERATED, argv,
                               generated, false, why, why_len))
                return false;
        } else unused_dimension(ZCL_DEV_PROOF_GENERATED, generated);
        if (compile->selected) {
            char artifact[PATH_MAX];
            int artifact_len = snprintf(artifact, sizeof(artifact),
                                        "%s/build/bin/z23-dev", paths->root);
            if (artifact_len <= 0 || (size_t)artifact_len >= sizeof(artifact) ||
                !executable_reuse(paths, artifact,
                                  &source_before, compile, NULL, 0)) {
                const char *argv[] = {"make", "--no-print-directory", make_jobs,
                                      "build-only", NULL};
                if (!run_dimension(&execution, ZCL_DEV_PROOF_COMPILE, argv,
                                   compile, false, why, why_len))
                    return false;
            }
        } else unused_dimension(ZCL_DEV_PROOF_COMPILE, compile);
        if (lint->selected) {
            const char *argv[] = {"make", "--no-print-directory", make_jobs,
                                  "lint-fast", NULL};
            if (!run_dimension(&execution, ZCL_DEV_PROOF_LINT, argv, lint,
                               false, why, why_len))
                return false;
        } else unused_dimension(ZCL_DEV_PROOF_LINT, lint);
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
            if (setenv("ZCL_TESTCACHE_STORE_ROOT", paths->root, 1) != 0) {
                proof_why(why, why_len, "test_cache_store_root_unavailable");
                return false;
            }
            if (snprintf(only, sizeof(only), "--exact=%s", groups) >=
                (int)sizeof(only)) {
                proof_why(why, why_len, "test_selection_invalid_or_truncated");
                return false;
            }
            char binary[PATH_MAX], generation_binary[PATH_MAX];
            uint8_t helper_root[32];
            bool runner_ready = test_binary_path(paths, binary) &&
                test_helpers_prepare(
                    paths, generation, binary, &source_before,
                    make_jobs, generation_binary, helper_root, why, why_len);
            if (!runner_ready) {
                if (why && why_len > 0) why[0] = 0;
                const char *bundle_argv[] = {
                    "make", "--no-print-directory", make_jobs,
                    "dev-proof-bundle", NULL};
                int bundle_rc = run_logged(
                    generation, paths->bundle_log, bundle_argv,
                    PROOF_TIMEOUT_MS);
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
                    bundle_rc = run_logged(generation, retry_log, bundle_argv,
                                           PROOF_TIMEOUT_MS);
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
            }
            const char *argv[] = {generation_binary, only, "--cache",
                                  "--activate-proof-contracts", NULL};
            if (!run_dimension(&execution, ZCL_DEV_PROOF_TEST, argv,
                               test, true, why, why_len))
                return false;
            test_receipt_bind_helpers(test, helper_root);
        } else unused_dimension(ZCL_DEV_PROOF_TEST, test);
    }

    if (!worktree_exact(generation, local, false, why, why_len) ||
        !zcl_dev_source_cas_capture(generation, &source_after) ||
        !source_after.cas_present ||
        strcmp(source_before.cas_root_sha3, source_after.cas_root_sha3) != 0) {
        proof_why(why, why_len, "source_epoch_superseded");
        return false;
    }
    receipt.created_unix = (uint64_t)platform_time_wall_unix();
    receipt.elapsed_ms = (uint64_t)((platform_time_monotonic_us() - started_us) /
                                    1000);
    receipt.policy_version = 1;
    receipt.complete = 1;
    if (!receipt_store(paths, &receipt)) {
        proof_why(why, why_len, "receipt_publication_failed");
        return false;
    }
    proof_unlink_if_current(paths, paths->failure);
    return true;
}

static bool proof_worker_run(const struct proof_paths *paths,
                             const char *local, const char *base,
                             char *why, size_t why_len)
{
    struct sigaction child_action = {0};
    child_action.sa_handler = SIG_DFL;
    sigemptyset(&child_action.sa_mask);
    bool ok = sigaction(SIGCHLD, &child_action, NULL) == 0 &&
              proof_worker(paths, local, base, why, why_len);
    if (!ok && (!why || !why[0]))
        proof_why(why, why_len, "proof_child_reaping_unavailable");
    if (!ok) {
        const char *message = why && why[0]
            ? why : "background_verification_failed";
        (void)proof_write_if_current(paths, paths->failure, message,
                                     strlen(message), 0600);
    }
    proof_lease_release(paths);
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
