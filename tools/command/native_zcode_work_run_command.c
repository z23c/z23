/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: contained model-neutral handoff for one verified ZCODE task. */

#include "command/native_command.h"

#include "base/hex.h"
#include "base/cleanse.h"
#include "base/log_macros.h"
#include "config/runtime.h"
#include "json/json.h"
#include "platform/os_proc.h"
#include "platform/directory_compat.h"
#include "platform/directory_transaction.h"
#include "platform/file_metadata.h"
#include "platform/positioned_file.h"
#include "platform/time_compat.h"
#include "models/build_proof_event.h"
#include "models/database.h"
#include "services/build_fabric_service.h"
#include "services/build_fabric_worker.h"
#include "services/package_lifecycle.h"
#include "sha3/sha3.h"
#include "util/file_tree_ops.h"
#include "util/safe_alloc.h"
#include "util/spawn.h"
#include "util/clientversion.h"
#include "vcs/vcs.h"
#include "vcs/vcs_object.h"
#include "vcs/build_action.h"
#include "vcs/package_deps.h"
#include "vcs/package_recipe.h"
#include "vcs/package_reuse.h"
#include "vcs/zcode_agent_context.h"
#include "vcs/zcode_dev.h"
#include "vcs/zcode_task_index.h"
#include "vcs/zcode_write_scope.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined(_WIN32)
#include <process.h>
#endif
#include <sys/stat.h>
#include <unistd.h>

#define ZWORK_RUN_PATH_MAX 4400
#define ZWORK_ADAPTER_OUTPUT_MAX (32u * 1024u)
#define ZWORK_ADAPTER_PACKET_MAX (512u * 1024u)
#define ZWORK_DEPENDENCY_HEADER_MAX (64u * 1024u)
#define ZWORK_DEPENDENCY_CONTEXT_MAX (192u * 1024u)
#define ZWORK_DEPENDENCY_API_MAX 256u
#define ZWORK_RUN_LOG "zcode.work.run"
#define ZWORK_PREFLIGHT_OUTPUT_MAX 2048u

struct run_dependency_candidate {
    struct vcs_package_index_entry package;
    struct vcs_package_reuse_input reuse;
    char api_text[VCS_PACKAGE_REUSE_MAX_APIS][ZWORK_DEPENDENCY_API_MAX];
    struct vcs_package_build_receipt receipt;
};

#if defined(_WIN32)
static bool run_snapshot_equal(
    const struct platform_positioned_file_snapshot *a,
    const struct platform_positioned_file_snapshot *b)
{
    return a->size == b->size && a->volume == b->volume &&
        a->file_low == b->file_low && a->file_high == b->file_high &&
        a->modified_seconds == b->modified_seconds &&
        a->modified_nanoseconds == b->modified_nanoseconds &&
        a->changed_seconds == b->changed_seconds &&
        a->changed_nanoseconds == b->changed_nanoseconds;
}

static bool run_stable_read(const char *path, void *bytes, size_t cap,
                            size_t *len_out, bool current_user_only)
{
    struct platform_positioned_file file;
    struct platform_positioned_file_snapshot before, after;
    platform_positioned_file_init(&file);
    bool ok = platform_positioned_file_open(&file, path) &&
        (!current_user_only ||
         platform_positioned_file_is_current_user_only(&file)) &&
        platform_positioned_file_snapshot(&file, &before) &&
        before.size <= cap;
    int64_t got = ok ? platform_positioned_file_read(
                           &file, bytes, (size_t)before.size, 0) : -1;
    ok = ok && got >= 0 && (uint64_t)got == before.size &&
        platform_positioned_file_snapshot(&file, &after) &&
        run_snapshot_equal(&before, &after);
    platform_positioned_file_close(&file);
    if (ok && len_out) *len_out = (size_t)before.size;
    return ok;
}
#endif

static const char *run_str(const struct json_value *input, const char *key)
{
    const struct json_value *value = input ? json_get(input, key) : NULL;
    return value && value->type == JSON_STR ? json_get_str(value) : NULL;
}

static bool run_bool(const struct json_value *input, const char *key)
{
    const struct json_value *value = input ? json_get(input, key) : NULL;
    return value && value->type == JSON_BOOL && json_get_bool(value);
}

static bool run_open_existing_ledger(
    struct node_db *ndb, const char *path, const char *reason)
{
    return ndb && path && path[0] && reason && reason[0] &&
           node_db_open_existing_runtime(ndb, path, reason);
}

/* CANDIDATE_ADMITTED has exactly one meaning: the candidate is captured and
 * no signed work receipt exists for it yet.  Whether that is healthy waiting
 * or an incomplete execution is decided by one further fact — does the node
 * datadir this invocation is bound to hold an outstanding (not superseded)
 * async proof chain for the latest candidate?  The chain is keyed by task and
 * candidate roots because the task index cannot name the action before the
 * first receipt arrives.  A named or resident node datadir has a supervisor
 * that consumes that chain, so the wait is real and run must agree with zcode
 * work status instead of failing closed.  The closed scratch ledger has no
 * supervisor: a receipt gap there means the prior foreground execution never
 * finished, which stays CANDIDATE_EXECUTION_INCOMPLETE. */
static bool run_async_proof_pending(
    const char *proof_datadir, const char *task_root_hex,
    const char *candidate_root_hex,
    char state_out[BUILD_PROOF_EVENT_STATE_MAX + 1])
{
    state_out[0] = '\0';
    if (!proof_datadir || !proof_datadir[0] || !task_root_hex ||
        strlen(task_root_hex) != BUILD_PROOF_EVENT_ROOT_HEX ||
        !candidate_root_hex ||
        strlen(candidate_root_hex) != BUILD_PROOF_EVENT_ROOT_HEX)
        return false;
    char db_path[ZWORK_RUN_PATH_MAX];
    int n = snprintf(db_path, sizeof(db_path), "%s/node.db", proof_datadir);
    if (n <= 0 || (size_t)n >= sizeof(db_path) ||
        access(db_path, F_OK) != 0)
        return false;
    struct node_db local_ndb = {0};
    struct node_db *runtime = app_runtime_node_db();
    bool owned = app_runtime_node_db_handle_open(runtime) &&
                 strcmp(db_path, runtime->path) == 0;
    struct node_db *ndb = owned ? runtime : &local_ndb;
    if (!owned && !run_open_existing_ledger(
            ndb, db_path, "zcode.work.run.proof_pending"))
        return false;
    struct db_build_proof_event events[64];
    int count = db_build_proof_events_for_task(ndb, task_root_hex, events,
                                               sizeof(events) /
                                                   sizeof(events[0]));
    const struct db_build_proof_event *latest = NULL;
    bool pending = false;
    for (int i = 0; i < count; i++) {
        if (strcmp(events[i].candidate_root_sha3, candidate_root_hex) != 0 ||
            !events[i].state[0])
            continue;
        latest = &events[i];
        if (strcmp(events[i].state, "SUPERSEDED") != 0)
            pending = true;
    }
    if (pending && latest)
        (void)snprintf(state_out, BUILD_PROOF_EVENT_STATE_MAX + 1u, "%s",
                       latest->state);
    if (!owned) node_db_close(ndb);
    return pending;
}

static void run_fail(struct zcl_command_reply *reply, const char *code,
                     const char *phase, const char *detail, bool retryable,
                     bool mutated)
{
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                           ZCL_COMMAND_EXIT_INVALID, code, phase, retryable,
                           mutated, detail, "zcode.work.run");
}

static bool run_add_work_next(struct zcl_command_reply *reply,
                              const char *command, const char *workspace,
                              const char *work_id, const char *adapter,
                              const char *reason)
{
    struct json_value input;
    json_init(&input); json_set_object(&input);
    bool ok = workspace && workspace[0] && work_id && work_id[0] &&
        json_push_kv_str(&input, "workspace", workspace) &&
        json_push_kv_str(&input, "work", work_id) &&
        (!adapter || json_push_kv_str(&input, "adapter", adapter));
    char wire[sizeof(reply->next[0].input_json)];
    size_t n = ok ? json_write(&input, wire, sizeof(wire)) : 0;
    json_free(&input);
    return n > 0 && n < sizeof(wire) &&
        zcl_command_reply_add_next(reply, command, wire, reason);
}

static bool run_codex_runner_path(char out[ZWORK_RUN_PATH_MAX])
{
    char executable[ZWORK_RUN_PATH_MAX];
    const char *api_key = getenv("CODEX_API_KEY");
    const char *access_token = getenv("CODEX_ACCESS_TOKEN");
    if ((!api_key || !api_key[0]) &&
        (!access_token || !access_token[0]))
        return false;
    if ((api_key && api_key[0]) && (access_token && access_token[0]))
        return false;
    if (!os_proc_exe_path(executable, sizeof(executable)))
        return false;
    char *slash = strrchr(executable, '/');
#if defined(_WIN32)
    char *backslash = strrchr(executable, '\\');
    if (!slash || (backslash && backslash > slash)) slash = backslash;
#endif
    if (!slash)
        return false;
    *slash = '\0';
    /* The image suffix is chosen BEFORE the call: _FORTIFY_SOURCE makes
     * snprintf a macro, and a preprocessor directive between a macro's
     * parentheses is undefined behaviour. */
#if defined(_WIN32)
    const char *const runner_ext = ".exe";
#else
    const char *const runner_ext = "";
#endif
    int n = snprintf(out, ZWORK_RUN_PATH_MAX,
                     "%s/zclassic23-zcode-adapter-runner%s", executable,
                     runner_ext);
#if defined(_WIN32)
    struct platform_positioned_file runner;
    platform_positioned_file_init(&runner);
    bool ok = n > 0 && (size_t)n < ZWORK_RUN_PATH_MAX &&
        platform_positioned_file_open(&runner, out) &&
        platform_positioned_file_is_executable(&runner) &&
        platform_positioned_file_is_current_user_only(&runner);
    platform_positioned_file_close(&runner);
    return ok;
#else
    return n > 0 && (size_t)n < ZWORK_RUN_PATH_MAX && access(out, X_OK) == 0;
#endif
}

static bool run_packet_path(const char *candidate_workspace,
                            char path[ZWORK_RUN_PATH_MAX])
{
    int n = snprintf(path, ZWORK_RUN_PATH_MAX,
                     "%s/.zcode-adapter-packet.json", candidate_workspace);
    return n > 0 && (size_t)n < ZWORK_RUN_PATH_MAX;
}

static bool run_write_packet(const char *candidate_workspace,
                             const struct json_value *packet,
                             char path[ZWORK_RUN_PATH_MAX])
{
    size_t len = json_write(packet, NULL, 0);
    if (len == 0 || len > ZWORK_ADAPTER_PACKET_MAX)
        return false;
    char *wire = zcl_malloc(len + 1u, "zcode.work.adapter.packet");
    if (!wire || json_write(packet, wire, len + 1u) != len) {
        free(wire);
        return false;
    }
    if (!run_packet_path(candidate_workspace, path)) {
        free(wire);
        return false;
    }
#if defined(_WIN32)
    struct platform_directory_transaction directory;
    struct platform_directory_child staged;
    platform_directory_transaction_init(&directory);
    platform_directory_child_init(&staged);
    char staged_leaf[64];
    int staged_n = snprintf(staged_leaf, sizeof(staged_leaf),
                            ".adapter-packet.%ld.tmp", (long)_getpid());
    bool staged_created = false;
    bool ok = platform_directory_transaction_open(&directory,
                                                   candidate_workspace) &&
        staged_n > 0 && (size_t)staged_n < sizeof(staged_leaf) &&
        platform_directory_child_create(&directory, staged_leaf, &staged) &&
        (staged_created = true) &&
        platform_directory_child_write_exact(&staged, wire, len, 0) &&
        platform_directory_child_flush(&staged) &&
        platform_directory_child_replace(&directory, &staged,
                                         ".zcode-adapter-packet.json", true) &&
        platform_directory_transaction_flush(&directory);
    platform_directory_child_close(&staged);
    if (!ok && staged_created)
        (void)platform_directory_child_unlink(&directory, staged_leaf, true);
    platform_directory_transaction_close(&directory);
#else
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                  0600);
    bool ok = fd >= 0;
    size_t off = 0;
    while (ok && off < len) {
        ssize_t wrote = write(fd, wire + off, len - off);
        if (wrote < 0 && errno == EINTR)
            continue;
        if (wrote <= 0)
            ok = false;
        else
            off += (size_t)wrote;
    }
    if (ok)
        ok = fsync(fd) == 0;
    if (fd >= 0 && close(fd) != 0)
        ok = false;
    if (!ok)
        (void)unlink(path);
#endif
    free(wire);
    return ok;
}

/* The packet is an ephemeral proposal aid, never a task/candidate/receipt
 * authority.  Reading it before candidate capture lets a later adapter turn
 * retain bounded compiler feedback while the canonical source and evidence
 * are still reloaded and verified independently. */
static int run_read_packet(const char *candidate_workspace,
                           char **wire_out, size_t *len_out)
{
    *wire_out = NULL;
    *len_out = 0;
    char path[ZWORK_RUN_PATH_MAX];
    if (!run_packet_path(candidate_workspace, path)) return -1;
#if defined(_WIN32)
    char *wire = zcl_malloc(ZWORK_ADAPTER_PACKET_MAX + 1u,
                            "zcode.work.repair.packet");
    if (!wire) return -1;
    size_t len = 0;
    if (!run_stable_read(path, wire, ZWORK_ADAPTER_PACKET_MAX, &len, true)) {
        free(wire);
        struct platform_file_metadata metadata;
        return platform_file_metadata_read(path, &metadata) ==
                       PLATFORM_FILE_METADATA_MISSING
                   ? 0 : -1;
    }
    if (len == 0) { free(wire); return -1; }
    wire[len] = '\0';
    *wire_out = wire;
    *len_out = len;
    return 1;
#else
    struct stat before;
    if (lstat(path, &before) != 0)
        return errno == ENOENT ? 0 : -1;
    if (!S_ISREG(before.st_mode) || before.st_uid != geteuid() ||
        (before.st_mode & 077u) != 0 || before.st_size <= 0 ||
        (uint64_t)before.st_size > ZWORK_ADAPTER_PACKET_MAX)
        return -1;
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    struct stat opened;
    bool ok = fd >= 0 && fstat(fd, &opened) == 0 &&
        opened.st_dev == before.st_dev && opened.st_ino == before.st_ino &&
        opened.st_size == before.st_size && S_ISREG(opened.st_mode) &&
        opened.st_uid == geteuid() && (opened.st_mode & 077u) == 0;
    size_t len = ok ? (size_t)opened.st_size : 0;
    char *wire = ok ? zcl_malloc(len + 1u, "zcode.work.repair.packet") : NULL;
    if (ok && !wire) ok = false;
    size_t off = 0;
    while (ok && off < len) {
        ssize_t got = read(fd, wire + off, len - off);
        if (got < 0 && errno == EINTR) continue;
        if (got <= 0)
            ok = false;
        else
            off += (size_t)got;
    }
    if (fd >= 0 && close(fd) != 0) ok = false;
    if (!ok) {
        free(wire);
        return -1;
    }
    wire[len] = '\0';
    *wire_out = wire;
    *len_out = len;
    return 1;
#endif
}

static bool run_repair_packet_valid(const struct json_value *packet,
                                    const char *goal,
                                    uint64_t candidate_sequence)
{
    const struct json_value *diagnostic = packet && packet->type == JSON_OBJ
        ? json_get(packet, "diagnostic") : NULL;
    const struct json_value *attempt = diagnostic
        ? json_get(diagnostic, "attempt") : NULL;
    const struct json_value *exit_status = diagnostic
        ? json_get(diagnostic, "exit_status") : NULL;
    const struct json_value *feedback = diagnostic
        ? json_get(diagnostic, "compiler_feedback") : NULL;
    return goal && candidate_sequence > 1u &&
        run_str(packet, "goal") && strcmp(run_str(packet, "goal"), goal) == 0 &&
        diagnostic && diagnostic->type == JSON_OBJ &&
        run_str(diagnostic, "stage") &&
        strcmp(run_str(diagnostic, "stage"),
               "package_build_and_tests") == 0 &&
        attempt && attempt->type == JSON_INT &&
        json_get_int(attempt) == (int64_t)candidate_sequence - 1 &&
        exit_status && exit_status->type == JSON_INT &&
        json_get_int(exit_status) != 0 &&
        run_bool(diagnostic, "retry_safe") &&
        feedback && feedback->type == JSON_OBJ;
}

static void run_adapter_cleanup(const char *candidate_workspace,
                                const char *packet_path)
{
#if defined(_WIN32)
    (void)packet_path;
    struct platform_directory_transaction directory;
    platform_directory_transaction_init(&directory);
    if (platform_directory_transaction_open(&directory, candidate_workspace)) {
        (void)platform_directory_child_unlink(
            &directory, ".zcode-adapter-packet.json", true);
        platform_directory_transaction_close(&directory);
    }
#else
    if (packet_path && packet_path[0])
        (void)unlink(packet_path);
#endif
    char path[ZWORK_RUN_PATH_MAX];
    int n = snprintf(path, sizeof(path), "%s/.zcode-adapter-home",
                     candidate_workspace);
    if (n > 0 && (size_t)n < sizeof(path))
        ZCL_IGNORE_RESULT(zcl_tree_remove(path),
                          "remove private ephemeral adapter home");
    n = snprintf(path, sizeof(path), "%s/.zcode-adapter-tmp",
                 candidate_workspace);
    if (n > 0 && (size_t)n < sizeof(path))
        ZCL_IGNORE_RESULT(zcl_tree_remove(path),
                          "remove private ephemeral adapter temp");
}

static const struct vcs_zcode_task_index_entry *run_resolve(
    const struct vcs_zcode_task_index *index, const char *work, bool *ambiguous)
{
    *ambiguous = false;
    size_t count = vcs_zcode_task_index_task_count(index);
    if (count == 0) return NULL;
    if (!work || !work[0] || strcmp(work, "latest") == 0) {
        const struct vcs_zcode_task_index_entry *best =
            vcs_zcode_task_index_task_at(index, 0);
        for (size_t i = 1; i < count; i++) {
            const struct vcs_zcode_task_index_entry *at =
                vcs_zcode_task_index_task_at(index, i);
            if (at->expires_unix > best->expires_unix ||
                (at->expires_unix == best->expires_unix &&
                 strcmp(at->task_root_hex, best->task_root_hex) > 0))
                best = at;
        }
        return best;
    }
    const char *prefix = strncmp(work, "work-", 5) == 0 ? work + 5 : work;
    size_t prefix_len = strlen(prefix);
    if (prefix_len < 8 || prefix_len > 64) return NULL;
    const struct vcs_zcode_task_index_entry *match = NULL;
    for (size_t i = 0; i < count; i++) {
        const struct vcs_zcode_task_index_entry *at =
            vcs_zcode_task_index_task_at(index, i);
        if (strncmp(at->task_root_hex, prefix, prefix_len) != 0) continue;
        if (match) { *ambiguous = true; return NULL; }
        match = at;
    }
    return match;
}

static bool run_load_task(const char *workspace, const char *root_hex,
                          struct vcs_zcode_task_v1 *task)
{
    uint8_t root[32], check[32], *wire = NULL;
    size_t len = 0;
    bool ok = zcl_hex_decode_lower(root_hex, root, 32) &&
        vcs_object_load_raw_bounded(workspace, root, VCS_ZCODE_TASK_WIRE_BYTES,
                                    &wire, &len) == 0 &&
        len == VCS_ZCODE_TASK_WIRE_BYTES &&
        vcs_zcode_task_parse(wire, len, task) == VCS_ZCODE_DEV_OK &&
        vcs_zcode_task_root(task, check) == VCS_ZCODE_DEV_OK &&
        memcmp(check, root, 32) == 0;
    free(wire);
    return ok;
}

static char *run_load_goal(const char *workspace,
                           const struct vcs_zcode_task_v1 *task)
{
    uint8_t *bytes = NULL, check[32];
    size_t len = 0;
    if (vcs_object_load_raw_bounded(workspace, task->goal_root, 4096,
                                    &bytes, &len) != 0 || len == 0 ||
        memchr(bytes, '\0', len)) {
        free(bytes);
        return NULL;
    }
    sha3_256(bytes, len, check);
    if (memcmp(check, task->goal_root, 32) != 0) {
        free(bytes);
        return NULL;
    }
    char *goal = zcl_malloc(len + 1u, "zcode.work.run.goal");
    if (!goal) { free(bytes); return NULL; }
    memcpy(goal, bytes, len); goal[len] = '\0'; free(bytes);
    return goal;
}

static bool run_load_context(
    const char *workspace, const struct vcs_zcode_task_context_entry *entry,
    const struct vcs_zcode_task_v1 *task, const char *task_root_hex,
    struct vcs_zcode_agent_context_v1 *context,
    enum vcs_zcode_agent_context_result *admission)
{
    if (!admission) return false;
    *admission = VCS_ZCODE_AGENT_CONTEXT_NULL;
    uint8_t root[32], task_root[32], *wire = NULL;
    size_t len = 0;
    bool ok = zcl_hex_decode_lower(entry->context_root_hex, root, 32) &&
        zcl_hex_decode_lower(task_root_hex, task_root, 32) &&
        vcs_object_load_raw_bounded(workspace, root, task->max_context_bytes,
                                    &wire, &len) == 0 &&
        vcs_zcode_agent_context_parse(wire, len, task->max_context_bytes,
                                      context) ==
            VCS_ZCODE_AGENT_CONTEXT_OK;
    if (ok)
        *admission = vcs_zcode_agent_context_validate_for_task(
            context, task, task_root, root, true);
    free(wire);
    return ok && (*admission == VCS_ZCODE_AGENT_CONTEXT_OK ||
                  *admission == VCS_ZCODE_AGENT_CONTEXT_BINDING ||
                  *admission == VCS_ZCODE_AGENT_CONTEXT_INCOMPLETE);
}

static bool run_load_scope(const char *workspace,
                           const struct vcs_zcode_task_v1 *task,
                           struct vcs_zcode_write_scope_v1 *scope)
{
    uint8_t *wire = NULL, check[32];
    size_t len = 0;
    bool ok = vcs_object_load_raw_bounded(
            workspace, task->write_scope_root,
            VCS_ZCODE_WRITE_SCOPE_WIRE_MAX, &wire, &len) == 0 &&
        vcs_zcode_write_scope_parse(wire, len, scope) ==
            VCS_ZCODE_WRITE_SCOPE_OK &&
        vcs_zcode_write_scope_root(scope, check) ==
            VCS_ZCODE_WRITE_SCOPE_OK &&
        memcmp(check, task->write_scope_root, 32) == 0;
    free(wire);
    return ok;
}

static bool run_load_lock(const char *workspace,
                          const struct vcs_zcode_task_v1 *task,
                          struct vcs_package_lock *lock)
{
    uint8_t *wire = NULL, check[32];
    size_t len = 0;
    bool ok = vcs_object_load_raw_bounded(
            workspace, task->dependency_lock_root,
            VCS_PACKAGE_LOCK_MAX_WIRE_BYTES, &wire, &len) == 0 &&
        vcs_package_lock_parse(wire, len, lock) == VCS_PACKAGE_DEPS_OK &&
        vcs_package_lock_root(lock, check) == VCS_PACKAGE_DEPS_OK &&
        memcmp(check, task->dependency_lock_root, 32) == 0;
    free(wire);
    return ok;
}

static bool run_output_is_header(const char *path)
{
    size_t len = path ? strlen(path) : 0;
    return len > 10u && strncmp(path, "include/", 8) == 0 &&
           strcmp(path + len - 2u, ".h") == 0;
}

static bool run_dependency_api_add(struct run_dependency_candidate *candidate,
                                   const char *api, size_t len)
{
    if (!candidate || !api || len == 0 ||
        len >= ZWORK_DEPENDENCY_API_MAX ||
        candidate->reuse.api_count >= VCS_PACKAGE_REUSE_MAX_APIS)
        return false;
    for (size_t i = 0; i < candidate->reuse.api_count; i++)
        if (strlen(candidate->api_text[i]) == len &&
            memcmp(candidate->api_text[i], api, len) == 0)
            return true;
    size_t at = candidate->reuse.api_count++;
    memcpy(candidate->api_text[at], api, len);
    candidate->api_text[at][len] = '\0';
    candidate->reuse.apis[at] = candidate->api_text[at];
    return true;
}

static void run_dependency_header_symbols(
    struct run_dependency_candidate *candidate,
    const uint8_t *bytes, size_t len)
{
    static const char *const rejected[] = {
        "if", "for", "while", "switch", "sizeof", "return",
    };
    for (size_t i = 0; i < len &&
         candidate->reuse.api_count < VCS_PACKAGE_REUSE_MAX_APIS; i++) {
        if (bytes[i] != '(') continue;
        size_t end = i;
        while (end > 0 && (bytes[end - 1u] == ' ' ||
                           bytes[end - 1u] == '\t' ||
                           bytes[end - 1u] == '\n' ||
                           bytes[end - 1u] == '\r')) end--;
        size_t start = end;
        while (start > 0 &&
               ((bytes[start - 1u] >= 'A' && bytes[start - 1u] <= 'Z') ||
                (bytes[start - 1u] >= 'a' && bytes[start - 1u] <= 'z') ||
                (bytes[start - 1u] >= '0' && bytes[start - 1u] <= '9') ||
                bytes[start - 1u] == '_')) start--;
        if (start == end || (bytes[start] >= '0' && bytes[start] <= '9'))
            continue;
        bool keep = true;
        for (size_t r = 0; r < sizeof(rejected) / sizeof(rejected[0]); r++)
            if (strlen(rejected[r]) == end - start &&
                memcmp(bytes + start, rejected[r], end - start) == 0)
                keep = false;
        if (keep)
            (void)run_dependency_api_add(
                candidate, (const char *)bytes + start, end - start);
    }
}

static bool run_ascii_contains_ci(const char *haystack, const char *needle)
{
    size_t haystack_len = haystack ? strlen(haystack) : 0;
    size_t needle_len = needle ? strlen(needle) : 0;
    if (needle_len == 0 || needle_len > haystack_len) return false;
    for (size_t i = 0; i + needle_len <= haystack_len; i++) {
        bool equal = true;
        for (size_t j = 0; j < needle_len; j++) {
            unsigned char left = (unsigned char)haystack[i + j];
            unsigned char right = (unsigned char)needle[j];
            if (tolower(left) != tolower(right)) {
                equal = false;
                break;
            }
        }
        if (equal) return true;
    }
    return false;
}

static bool run_dependency_header_relevant(
    const char *goal, const char *path, const uint8_t *bytes, size_t len)
{
    const char *base = path ? strrchr(path, '/') : NULL;
    base = base ? base + 1u : path;
    size_t base_len = base ? strlen(base) : 0;
    if (base_len > 2u && strcmp(base + base_len - 2u, ".h") == 0) {
        char stem[VCS_PACKAGE_BUILD_PATH_MAX + 1u];
        size_t stem_len = base_len - 2u;
        if (stem_len < sizeof(stem)) {
            memcpy(stem, base, stem_len);
            stem[stem_len] = '\0';
            if (run_ascii_contains_ci(goal, stem)) return true;
        }
    }
    struct run_dependency_candidate symbols = {0};
    run_dependency_header_symbols(&symbols, bytes, len);
    for (size_t i = 0; i < symbols.reuse.api_count; i++)
        if (run_ascii_contains_ci(goal, symbols.reuse.apis[i])) return true;
    return false;
}

static bool run_read_dependency_header(
    const char *datadir, const char root_hex[65],
    const struct vcs_package_build_output *output,
    uint8_t **bytes_out, size_t *len_out)
{
    *bytes_out = NULL;
    *len_out = 0;
    if (!datadir || !datadir[0] || !run_output_is_header(output->path) ||
        output->bytes == 0 || output->bytes > ZWORK_DEPENDENCY_HEADER_MAX)
        return false;
    char path[ZWORK_RUN_PATH_MAX];
    int n = snprintf(path, sizeof(path), "%s/zcode/installed/%s/%s",
                     datadir, root_hex, output->path);
    if (n <= 0 || (size_t)n >= sizeof(path)) return false;
#if defined(_WIN32)
    uint8_t *bytes = zcl_malloc((size_t)output->bytes + 1u,
                                "zcode.work.locked_header");
    size_t off = 0;
    bool ok = bytes && run_stable_read(path, bytes, (size_t)output->bytes,
                                       &off, true) && off == output->bytes;
#else
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return false;
    struct stat st;
    bool ok = fstat(fd, &st) == 0 && S_ISREG(st.st_mode) &&
        (uint64_t)st.st_size == output->bytes;
    uint8_t *bytes = ok
        ? zcl_malloc((size_t)output->bytes + 1u,
                     "zcode.work.locked_header")
        : NULL;
    ok = ok && bytes;
    size_t off = 0;
    while (ok && off < (size_t)output->bytes) {
        ssize_t got = read(fd, bytes + off, (size_t)output->bytes - off);
        if (got < 0 && errno == EINTR) continue;
        if (got <= 0) ok = false;
        else off += (size_t)got;
    }
    if (close(fd) != 0) ok = false;
#endif
    uint8_t check[32];
    if (ok) {
        sha3_256(bytes, off, check);
        ok = memcmp(check, output->sha3, 32) == 0 &&
             memchr(bytes, '\0', off) == NULL;
    }
    if (!ok) {
        free(bytes);
        return false;
    }
    bytes[off] = '\0';
    *bytes_out = bytes;
    *len_out = off;
    return true;
}

static bool run_dependency_context_json(
    struct json_value *locked_out, struct json_value *selected_out,
    const char *workspace, const char *datadir,
    const struct vcs_zcode_task_v1 *task, const char *goal,
    char detail[256])
{
    json_init(locked_out); json_set_array(locked_out);
    json_init(selected_out); json_set_array(selected_out);
    size_t selected_bytes = 0;
    struct vcs_package_lock lock;
    vcs_package_lock_init(&lock);
    if (!run_load_lock(workspace, task, &lock) || lock.count == 0) {
        (void)snprintf(detail, 256, "the task dependency lock did not reverify");
        return false;
    }
    size_t count = lock.count - 1u;
    if (count == 0) return true;
    if (!datadir || !datadir[0]) {
        (void)snprintf(detail, 256,
                       "locked packages require the existing node datadir");
        return false;
    }
    struct run_dependency_candidate *candidates = zcl_calloc(
        count, sizeof(*candidates), "zcode.work.locked_dependencies");
    struct vcs_package_reuse_input *inputs = zcl_calloc(
        count, sizeof(*inputs), "zcode.work.locked_dependency_inputs");
    if (!candidates || !inputs) {
        free(inputs); free(candidates);
        (void)snprintf(detail, 256, "locked dependency context allocation failed");
        return false;
    }
    bool ok = true;
    for (size_t i = 0; ok && i < count; i++) {
        const struct vcs_package_lock_node *node = &lock.nodes[i];
        struct run_dependency_candidate *candidate = &candidates[i];
        (void)snprintf(candidate->package.name,
                       sizeof(candidate->package.name), "%s", node->name);
        (void)snprintf(candidate->package.semver,
                       sizeof(candidate->package.semver), "%s", node->semver);
        zcl_hex_encode(node->root, 32, candidate->package.package_root_hex);
        candidate->reuse.package = &candidate->package;
        candidate->reuse.locked = true;
        candidate->reuse.installed = true;
        candidate->reuse.compatible = true;
        struct package_lifecycle_step step;
        bool installed = false;
        struct zcl_result inspected = package_lifecycle_installed_inspect(
            datadir, node->root, &step, &installed);
        struct zcl_result receipt = inspected.ok && installed
            ? package_lifecycle_receipt_read(
                  datadir, step.receipt_id, &candidate->receipt)
            : ZCL_ERR(-1, "locked package is not receipt-verified and installed");
        if (!inspected.ok || !installed || !receipt.ok) {
            (void)snprintf(detail, 256,
                           "locked C23 package %s@%s is unavailable or failed receipt verification",
                           node->name, node->semver);
            ok = false;
            break;
        }
        for (size_t h = 0; h < candidate->receipt.output_count &&
             candidate->reuse.api_count < VCS_PACKAGE_REUSE_MAX_APIS; h++) {
            const struct vcs_package_build_output *output =
                &candidate->receipt.outputs[h];
            if (!run_output_is_header(output->path)) continue;
            (void)run_dependency_api_add(candidate, output->path,
                                         strlen(output->path));
            uint8_t *bytes = NULL; size_t len = 0;
            if (run_read_dependency_header(
                    datadir, candidate->package.package_root_hex,
                    output, &bytes, &len)) {
                run_dependency_header_symbols(candidate, bytes, len);
                free(bytes);
            }
        }
        inputs[i] = candidate->reuse;
        struct json_value row;
        json_init(&row); json_set_object(&row);
        ok = json_push_kv_str(&row, "name", node->name) &&
             json_push_kv_str(&row, "semver", node->semver) &&
             json_push_kv_str(&row, "package_root",
                              candidate->package.package_root_hex) &&
             json_push_back(locked_out, &row);
        json_free(&row);
    }
    struct vcs_package_reuse_plan plan;
    if (ok) ok = vcs_package_reuse_plan_build(goal, inputs, count, &plan);
    for (size_t s = 0; ok && s < plan.selected_count; s++) {
        size_t at = plan.selected[s].input_index;
        struct run_dependency_candidate *candidate = &candidates[at];
        struct json_value row, apis, headers;
        json_init(&row); json_set_object(&row);
        json_init(&apis); json_set_array(&apis);
        json_init(&headers); json_set_array(&headers);
        bool relevant[VCS_PACKAGE_BUILD_MAX_OUTPUTS] = {0};
        size_t relevant_count = 0;
        for (size_t h = 0; ok && h < candidate->receipt.output_count; h++) {
            const struct vcs_package_build_output *output =
                &candidate->receipt.outputs[h];
            if (!run_output_is_header(output->path)) continue;
            uint8_t *bytes = NULL;
            size_t len = 0;
            if (!run_read_dependency_header(
                    datadir, candidate->package.package_root_hex,
                    output, &bytes, &len)) {
                (void)snprintf(detail, 256,
                               "selected header %s changed after receipt verification",
                               output->path);
                ok = false;
                break;
            }
            relevant[h] = run_dependency_header_relevant(
                goal, output->path, bytes, len);
            if (relevant[h]) relevant_count++;
            free(bytes);
        }
        struct run_dependency_candidate selected_apis = {0};
        for (size_t h = 0; ok && h < candidate->receipt.output_count; h++) {
            const struct vcs_package_build_output *output =
                &candidate->receipt.outputs[h];
            if (!run_output_is_header(output->path) ||
                (relevant_count > 0 && !relevant[h])) continue;
            uint8_t *bytes = NULL; size_t len = 0;
            if (!run_read_dependency_header(
                    datadir, candidate->package.package_root_hex,
                    output, &bytes, &len)) {
                (void)snprintf(detail, 256,
                               "selected header %s changed after receipt verification",
                               output->path);
                ok = false;
                break;
            }
            (void)run_dependency_api_add(
                &selected_apis, output->path, strlen(output->path));
            run_dependency_header_symbols(&selected_apis, bytes, len);
            if (len > ZWORK_DEPENDENCY_CONTEXT_MAX - selected_bytes) {
                free(bytes);
                (void)snprintf(detail, 256,
                               "selected dependency headers exceed the context budget");
                ok = false;
                break;
            }
            struct json_value header;
            json_init(&header); json_set_object(&header);
            ok = json_push_kv_str(&header, "path", output->path) &&
                 json_push_kv_int(&header, "bytes", (int64_t)len) &&
                 json_push_kv_str(&header, "content", (const char *)bytes) &&
                 json_push_back(&headers, &header);
            json_free(&header);
            free(bytes);
            if (ok) selected_bytes += len;
        }
        for (size_t a = 0; ok && a < selected_apis.reuse.api_count; a++) {
            struct json_value api;
            json_init(&api);
            json_set_str(&api, selected_apis.reuse.apis[a]);
            ok = json_push_back(&apis, &api);
            json_free(&api);
        }
        ok = ok && json_push_kv_str(&row, "name", candidate->package.name) &&
             json_push_kv_str(&row, "semver", candidate->package.semver) &&
             json_push_kv_str(&row, "package_root",
                              candidate->package.package_root_hex) &&
             json_push_kv(&row, "apis", &apis) &&
             json_push_kv(&row, "headers", &headers) &&
             json_push_back(selected_out, &row);
        json_free(&headers); json_free(&apis); json_free(&row);
    }
    free(inputs); free(candidates);
    return ok;
}

static bool run_excerpts_json(
    struct json_value *out, const struct vcs_zcode_agent_context_v1 *context)
{
    json_init(out); json_set_array(out);
    for (size_t i = 0; i < context->file_count; i++) {
        const struct vcs_zcode_agent_context_entry_v1 *entry =
            &context->files[i];
        if (memchr(entry->content, '\0', entry->content_len)) return false;
        char *content = zcl_malloc(entry->content_len + 1u,
                                   "zcode.work.run.excerpt");
        if (!content) return false;
        memcpy(content, entry->content, entry->content_len);
        content[entry->content_len] = '\0';
        struct json_value row;
        json_init(&row); json_set_object(&row);
        bool ok = json_push_kv_str(&row, "path", entry->path) &&
            json_push_kv_int(&row, "start_line", entry->start_line) &&
            json_push_kv_int(&row, "full_file_bytes",
                             (int64_t)entry->full_file_bytes) &&
            json_push_kv_str(&row, "content", content) &&
            json_push_back(out, &row);
        json_free(&row); free(content);
        if (!ok) return false;
    }
    return true;
}

static bool run_candidate_metadata_read(
    const char *candidate_workspace, struct json_value *document)
{
    char path[ZWORK_RUN_PATH_MAX];
    int n = snprintf(path, sizeof(path), "%s/%s", candidate_workspace,
                     VCS_PACKAGE_DEPS_META_PATH);
    if (n <= 0 || (size_t)n >= sizeof(path)) return false;
#if defined(_WIN32)
    char *wire = zcl_malloc(VCS_PACKAGE_DEPS_META_MAX_BYTES + 1u,
                            "zcode.work.candidate_metadata");
    size_t len = 0;
    bool ok = wire && run_stable_read(path, wire,
                                      VCS_PACKAGE_DEPS_META_MAX_BYTES,
                                      &len, true) && len > 0;
#else
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return false;
    struct stat st;
    bool ok = fstat(fd, &st) == 0 && S_ISREG(st.st_mode) && st.st_size > 0 &&
        (uint64_t)st.st_size <= VCS_PACKAGE_DEPS_META_MAX_BYTES;
    size_t len = ok ? (size_t)st.st_size : 0;
    char *wire = ok ? zcl_malloc(len + 1u,
                                 "zcode.work.candidate_metadata") : NULL;
    if (ok && !wire) ok = false;
    size_t off = 0;
    while (ok && off < len) {
        ssize_t got = read(fd, wire + off, len - off);
        if (got < 0 && errno == EINTR) continue;
        if (got <= 0) ok = false;
        else off += (size_t)got;
    }
    if (close(fd) != 0) ok = false;
#endif
    if (ok) {
        wire[len] = '\0';
        json_init(document);
        ok = json_read(document, wire, len) && document->type == JSON_OBJ;
        if (!ok) json_free(document);
    }
    free(wire);
    return ok;
}

static bool run_candidate_metadata_write(
    const char *candidate_workspace, const struct json_value *document)
{
    size_t len = json_write(document, NULL, 0);
    if (len == 0 || len > VCS_PACKAGE_DEPS_META_MAX_BYTES) return false;
    char *wire = zcl_malloc(len + 1u, "zcode.work.composed_metadata");
    if (!wire || json_write(document, wire, len + 1u) != len) {
        free(wire);
        return false;
    }
    struct vcs_package_deps checked;
    bool valid = vcs_package_deps_parse_meta(
        (const uint8_t *)wire, len, &checked, NULL, 0) ==
        VCS_PACKAGE_DEPS_OK;
#if defined(_WIN32)
    struct platform_directory_transaction directory;
    struct platform_directory_child staged;
    platform_directory_transaction_init(&directory);
    platform_directory_child_init(&staged);
    char temporary[64];
    int tn = snprintf(temporary, sizeof(temporary),
                      ".zcode-package.compose.%ld.tmp", (long)_getpid());
    bool staged_created = false;
    bool ok = valid && tn > 0 && (size_t)tn < sizeof(temporary) &&
        platform_directory_transaction_open(&directory, candidate_workspace) &&
        platform_directory_child_create(&directory, temporary, &staged) &&
        (staged_created = true) &&
        platform_directory_child_write_exact(&staged, wire, len, 0) &&
        platform_directory_child_flush(&staged) &&
        platform_directory_child_replace(&directory, &staged,
                                         VCS_PACKAGE_DEPS_META_PATH, false) &&
        platform_directory_transaction_flush(&directory);
    platform_directory_child_close(&staged);
    if (!ok && staged_created)
        (void)platform_directory_child_unlink(&directory, temporary, true);
    platform_directory_transaction_close(&directory);
#else
    char path[ZWORK_RUN_PATH_MAX] = {0};
    char temporary[ZWORK_RUN_PATH_MAX] = {0};
    int pn = snprintf(path, sizeof(path), "%s/%s", candidate_workspace,
                      VCS_PACKAGE_DEPS_META_PATH);
    int tn = snprintf(temporary, sizeof(temporary),
                      "%s.zcode-package.compose.XXXXXX", candidate_workspace);
    int fd = valid && pn > 0 && (size_t)pn < sizeof(path) && tn > 0 &&
                     (size_t)tn < sizeof(temporary)
        ? mkstemp(temporary)
        : -1;
    bool ok = fd >= 0 && fcntl(fd, F_SETFD, FD_CLOEXEC) == 0;
    size_t off = 0;
    while (ok && off < len) {
        ssize_t wrote = write(fd, wire + off, len - off);
        if (wrote < 0 && errno == EINTR) continue;
        if (wrote <= 0) ok = false;
        else off += (size_t)wrote;
    }
    if (ok) ok = fsync(fd) == 0;
    if (fd >= 0 && close(fd) != 0) ok = false;
    if (ok) ok = rename(temporary, path) == 0;
    if (ok) {
        int dir_fd = open(candidate_workspace,
                          O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        ok = dir_fd >= 0 && fsync(dir_fd) == 0;
        if (dir_fd >= 0 && close(dir_fd) != 0) ok = false;
    }
    if (!ok && temporary[0]) (void)unlink(temporary);
#endif
    free(wire);
    return ok;
}

static bool run_metadata_has_root(
    const struct json_value *dependencies, const uint8_t root[32])
{
    char root_hex[65];
    zcl_hex_encode(root, 32, root_hex);
    for (size_t i = 0; dependencies && i < json_size(dependencies); i++) {
        const struct json_value *row = json_at(dependencies, i);
        const char *value = row && row->type == JSON_OBJ
            ? run_str(row, "root") : NULL;
        if (value && strcmp(value, root_hex) == 0) return true;
    }
    return false;
}

static bool run_compose_candidate_metadata(
    const char *candidate_workspace, const struct vcs_zcode_task_v1 *task,
    const char *workspace, bool *changed_out)
{
    *changed_out = false;
    struct vcs_package_lock lock;
    vcs_package_lock_init(&lock);
    if (!run_load_lock(workspace, task, &lock) || lock.count == 0)
        return false;
    struct json_value document;
    if (!run_candidate_metadata_read(candidate_workspace, &document))
        return false;
    struct json_value *dependencies = (struct json_value *)json_get(
        &document, "dependencies");
    if (!dependencies) {
        struct json_value empty;
        json_init(&empty); json_set_array(&empty);
        bool added = json_push_kv(&document, "dependencies", &empty);
        json_free(&empty);
        dependencies = added ? (struct json_value *)json_get(
            &document, "dependencies") : NULL;
    }
    bool ok = dependencies && dependencies->type == JSON_ARR;
    for (size_t i = 0; ok && i + 1u < lock.count; i++) {
        const struct vcs_package_lock_node *node = &lock.nodes[i];
        if (run_metadata_has_root(dependencies, node->root)) continue;
        char root_hex[65];
        zcl_hex_encode(node->root, 32, root_hex);
        struct json_value row;
        json_init(&row); json_set_object(&row);
        ok = json_push_kv_str(&row, "root", root_hex) &&
            json_push_kv_str(&row, "name", node->name) &&
            json_push_kv_str(&row, "semver", node->semver) &&
            json_push_back(dependencies, &row);
        json_free(&row);
        if (ok) *changed_out = true;
    }
    if (ok && *changed_out)
        ok = run_candidate_metadata_write(candidate_workspace, &document);
    json_free(&document);
    return ok;
}

struct run_behavior_diff {
    bool changed;
};

static void run_behavior_diff_cb(enum vcs_diff_kind kind,
                                 const struct vcs_entry *before,
                                 const struct vcs_entry *after, void *user)
{
    (void)kind;
    struct run_behavior_diff *diff = user;
    const char *path = after ? after->path : before ? before->path : NULL;
    if (path && strcmp(path, VCS_PACKAGE_DEPS_META_PATH) != 0)
        diff->changed = true;
}

static bool run_candidate_has_behavior_change(
    const char *workspace, const uint8_t base_root[32],
    const uint8_t candidate_root[32])
{
    struct vcs_manifest base, candidate;
    vcs_manifest_init(&base);
    vcs_manifest_init(&candidate);
    if (!vcs_tree_load(workspace, base_root, &base) ||
        !vcs_tree_load(workspace, candidate_root, &candidate)) {
        vcs_manifest_free(&candidate);
        vcs_manifest_free(&base);
        return false;
    }
    struct run_behavior_diff diff = {0};
    vcs_manifest_diff(&base, &candidate, run_behavior_diff_cb, &diff);
    vcs_manifest_free(&candidate);
    vcs_manifest_free(&base);
    return diff.changed;
}

static bool run_candidate_workspace(const char *store,
                                    const struct vcs_zcode_task_v1 *task,
                                    const char *task_hex, uint32_t attempt,
                                    const uint8_t source_root[32], char out[4400],
                                    bool *created)
{
#if defined(_WIN32)
    (void)store; (void)task; (void)task_hex; (void)attempt;
    (void)source_root; (void)out;
    if (created) *created = false;
    /* Materializing executable package workspaces is disabled until the
     * restricted-token/Job-Object sandbox is qualified. */
    return false;
#else
    char parent[ZWORK_RUN_PATH_MAX];
    int n = snprintf(parent, sizeof(parent),
                     "/tmp/zclassic23-zcode-workspaces/%lu/%.64s",
                     (unsigned long)getuid(), task_hex);
    if (n <= 0 || (size_t)n >= sizeof(parent)) return false;
    struct zcl_result made = zcl_mkdir_p(parent, 0700);
    n = snprintf(out, ZWORK_RUN_PATH_MAX, "%s/attempt-%u", parent, attempt);
    if (!made.ok || n <= 0 || (size_t)n >= ZWORK_RUN_PATH_MAX) return false;
    if (mkdir(out, 0700) == 0) {
        *created = true;
        if (vcs_tree_materialize(store, source_root, out,
                                 task->max_output_bytes, 0u) != VCS_OK) {
            ZCL_IGNORE_RESULT(
                zcl_tree_remove(out),
                "best-effort rollback of a failed candidate materialization");
            return false;
        }
        return true;
    }
    struct stat st;
    *created = false;
    return errno == EEXIST && lstat(out, &st) == 0 && S_ISDIR(st.st_mode);
#endif
}

static bool run_packet(struct json_value *packet, const char *goal,
                       const char *workspace, const char *datadir,
                       const struct vcs_zcode_task_v1 *task,
                       const struct vcs_zcode_agent_context_v1 *context,
                       const struct vcs_zcode_write_scope_v1 *scope,
                       char detail[256])
{
    struct json_value excerpts, limits, scopes, locked, dependencies;
    detail[0] = '\0';
    if (!run_excerpts_json(&excerpts, context)) {
        (void)snprintf(detail, 256,
                       "the exact workspace source excerpts could not be rendered");
        return false;
    }
    if (!run_dependency_context_json(
            &locked, &dependencies, workspace, datadir, task, goal, detail)) {
        LOG_ERROR(ZWORK_RUN_LOG, "dependency context refused: %s",
                  detail[0] ? detail : "unknown error");
        json_free(&dependencies);
        json_free(&locked);
        json_free(&excerpts);
        return false;
    }
    char lock_hex[65];
    zcl_hex_encode(task->dependency_lock_root, 32, lock_hex);
    json_init(&limits); json_set_object(&limits);
    json_init(&scopes); json_set_array(&scopes);
    bool ok = json_push_kv_int(&limits, "max_changed_files",
                               task->max_changed_files) &&
        json_push_kv_int(&limits, "max_patch_bytes",
                         (int64_t)task->max_patch_bytes);
    for (size_t i = 0; ok && i < scope->count; i++) {
        struct json_value path;
        json_init(&path); json_set_str(&path, scope->paths[i]);
        ok = json_push_back(&scopes, &path);
        json_free(&path);
    }
    json_init(packet); json_set_object(packet);
    ok = ok && json_push_kv_str(packet, "goal", goal) &&
        json_push_kv_str(packet, "context_query", context->query) &&
        json_push_kv(packet, "selected_excerpts", &excerpts) &&
        json_push_kv(packet, "locked_dependencies", &locked) &&
        json_push_kv(packet, "selected_dependency_context", &dependencies) &&
        json_push_kv(packet, "allowed_write_scopes", &scopes) &&
        json_push_kv_str(packet, "dependency_lock_root", lock_hex) &&
        json_push_kv(packet, "limits", &limits) &&
        json_push_kv_str(packet, "instruction",
                         "Write C23 only. Reuse the selected APIs before creating code. Edit only allowed paths. Do not accept, publish, or claim proof.");
    json_free(&dependencies); json_free(&locked);
    json_free(&scopes); json_free(&limits); json_free(&excerpts);
    if (!ok)
        (void)snprintf(detail, 256,
                       "the bounded model context exceeded its JSON budget");
    return ok;
}

static char *run_wire_hex(const char *workspace, const uint8_t root[32],
                          size_t maximum_bytes)
{
    uint8_t *wire = NULL;
    size_t len = 0;
    if (vcs_object_load_raw_bounded(workspace, root, maximum_bytes,
                                    &wire, &len) != 0 || len == 0 ||
        len > (SIZE_MAX - 1u) / 2u) {
        free(wire);
        return NULL;
    }
    char *hex = zcl_malloc(len * 2u + 1u, "zcode.work.run.wire_hex");
    if (hex) zcl_hex_encode(wire, len, hex);
    free(wire);
    return hex;
}

static bool run_scope_csv(const struct vcs_zcode_write_scope_v1 *scope,
                          char out[4097])
{
    size_t used = 0;
    out[0] = '\0';
    for (size_t i = 0; i < scope->count; i++) {
        size_t len = strlen(scope->paths[i]);
        size_t extra = len + (i ? 1u : 0u);
        if (extra > 4096u - used) return false;
        if (i) out[used++] = ',';
        memcpy(out + used, scope->paths[i], len);
        used += len;
        out[used] = '\0';
    }
    return used > 0;
}

static bool run_admit_input(
    struct json_value *input, const char *workspace, const char *datadir,
    const char *candidate_workspace, const char *goal,
    const struct vcs_zcode_task_index_entry *entry,
    const struct vcs_zcode_task_context_entry *context_entry,
    const struct vcs_zcode_task_v1 *task,
    const struct vcs_zcode_agent_context_v1 *context,
    const struct vcs_zcode_write_scope_v1 *scope, const char *author_hex,
    const char *adapter_hex, uint64_t candidate_sequence,
    const char *execution_profile)
{
    char *policy = run_wire_hex(workspace, task->proof_policy_root,
                                VCS_ZCODE_PROOF_POLICY_WIRE_BYTES);
    char *lock = run_wire_hex(workspace, task->dependency_lock_root,
                              VCS_PACKAGE_LOCK_MAX_WIRE_BYTES);
    char *recipe = run_wire_hex(workspace, task->acceptance_tests_root,
                                VCS_PACKAGE_RECIPE_MAX_WIRE_BYTES);
    char scopes[4097], model_hex[65];
    zcl_hex_encode(task->model_policy_root, 32, model_hex);
    json_init(input); json_set_object(input);
    bool ok = policy && lock && recipe && run_scope_csv(scope, scopes) &&
        json_push_kv_str(input, "mode", "admit") &&
        json_push_kv_str(input, "workspace", workspace) &&
        json_push_kv_str(input, "datadir", datadir) &&
        json_push_kv_str(input, "goal", goal) &&
        json_push_kv_str(input, "proof_policy_hex", policy) &&
        json_push_kv_str(input, "dependency_lock_hex", lock) &&
        json_push_kv_str(input, "acceptance_recipe_hex", recipe) &&
        json_push_kv_str(input, "write_scope_csv", scopes) &&
        json_push_kv_str(input, "model_policy_root", model_hex) &&
        json_push_kv_str(input, "context_symbol", context->query) &&
        json_push_kv_str(input, "planned_task_root", entry->task_root_hex) &&
        json_push_kv_str(input, "planned_context_root",
                         context_entry->context_root_hex) &&
        json_push_kv_str(input, "candidate_workspace", candidate_workspace) &&
        json_push_kv_str(input, "adapter_policy_root", adapter_hex) &&
        json_push_kv_str(input, "author_pubkey", author_hex) &&
        json_push_kv_int(input, "candidate_sequence",
                         (int64_t)candidate_sequence) &&
        json_push_kv_str(input, "action_kind",
                         VCS_BUILD_ACTION_KIND_PACKAGE_V1) &&
        json_push_kv_str(input, "profile", execution_profile) &&
        json_push_kv_int(input, "expires_unix", task->expires_unix) &&
        json_push_kv_int(input, "max_changed_files",
                         task->max_changed_files) &&
        json_push_kv_int(input, "max_patch_bytes",
                         (int64_t)task->max_patch_bytes) &&
        json_push_kv_int(input, "max_context_bytes",
                         (int64_t)task->max_context_bytes) &&
        json_push_kv_int(input, "max_cpu_seconds", task->max_cpu_seconds) &&
        json_push_kv_int(input, "max_memory_bytes",
                         (int64_t)task->max_memory_bytes) &&
        json_push_kv_int(input, "max_output_bytes",
                         (int64_t)task->max_output_bytes);
    free(recipe); free(lock); free(policy);
    return ok;
}

static bool run_standard_policy(
    const char *workspace, const struct vcs_zcode_task_v1 *task,
    bool *standard)
{
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    struct vcs_zcode_proof_policy_v1 policy;
    if (!standard || vcs_object_load_raw_bounded(
            workspace, task->proof_policy_root,
            VCS_ZCODE_PROOF_POLICY_WIRE_BYTES, &wire, &wire_len) != 0)
        return false;
    bool ok = vcs_zcode_proof_policy_parse(wire, wire_len, &policy) ==
              VCS_ZCODE_DEV_OK;
    free(wire);
    if (!ok) return false;
    *standard = policy.minimum_compile_receipts >= 2u ||
                policy.minimum_test_receipts >= 2u;
    return true;
}

static struct zcl_result run_plan_standard_peer(
    const char *datadir, const char *primary_action_id,
    char peer_action_id[BUILD_FABRIC_ID_HEX + 1])
{
    char db_path[ZWORK_RUN_PATH_MAX];
    int n = snprintf(db_path, sizeof(db_path), "%s/node.db", datadir);
    struct node_db ndb = {0};
    if (n <= 0 || (size_t)n >= sizeof(db_path) ||
        !run_open_existing_ledger(
            &ndb, db_path, "zcode.work.run.standard_peer"))
        return ZCL_ERR(-1, "scratch ZBuild ledger could not be reopened");
    int64_t now = platform_time_wall_unix();
    char peer_job_id[BUILD_FABRIC_ID_HEX + 1];
    struct zcl_result result = build_fabric_plan_reproduction(
        &ndb, primary_action_id, VCS_BUILD_PACKAGE_PROFILE_STANDARD_B_V1,
        now, peer_action_id, peer_job_id);
    if (result.ok) result = build_fabric_submit(&ndb, peer_job_id, now);
    node_db_close(&ndb);
    return result;
}

static struct zcl_result run_execute_action(
    const char *workspace, const char *datadir, const char *action_id,
    struct db_build_worker *worker, const uint8_t secret[32],
    const uint8_t pubkey[32], struct db_build_receipt *receipt,
    struct build_fabric_worker_feedback *feedback)
{
    char db_path[ZWORK_RUN_PATH_MAX];
    int n = snprintf(db_path, sizeof(db_path), "%s/node.db", datadir);
    struct node_db ndb = {0};
    if (n <= 0 || (size_t)n >= sizeof(db_path) ||
        !run_open_existing_ledger(
            &ndb, db_path, "zcode.work.run.execute"))
        return ZCL_ERR(-1, "scratch ZBuild ledger could not be reopened");
    int64_t now = platform_time_wall_unix();
    worker->last_seen_at = now;
    struct zcl_result result = build_fabric_worker_approve(
        &ndb, worker, now);
    uint8_t lease_root[32];
    struct sha3_256_ctx sha;
    static const char domain[] = "zcl.zcode.work.local_lease.v1";
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)domain, sizeof(domain));
    sha3_256_write(&sha, (const uint8_t *)action_id, strlen(action_id));
    sha3_256_finalize(&sha, lease_root);
    char lease_id[65];
    zcl_hex_encode(lease_root, 32, lease_id);
    struct db_build_action claimed_action;
    bool claimed = false;
    if (result.ok)
        result = build_fabric_claim(
            &ndb, worker->worker_id, lease_id, now,
            BUILD_FABRIC_LEASE_SECONDS_MAX, &claimed_action, &claimed);
    if (result.ok && (!claimed ||
        strcmp(claimed_action.action_id, action_id) != 0))
        result = ZCL_ERR(-1, "queued action was not claimable by exact id");
    if (result.ok)
        result = build_fabric_worker_execute(
            &ndb, workspace, datadir, action_id, lease_id,
            secret, pubkey, receipt, feedback);
    node_db_close(&ndb);
    return result;
}

static bool run_worker_feedback_json(
    struct json_value *out,
    const struct build_fabric_worker_feedback *feedback)
{
    json_init(out); json_set_object(out);
    bool present = feedback && feedback->present;
    return json_push_kv_bool(out, "available", present) &&
        (!present ||
         (json_push_kv_str(out, "stage", feedback->stage) &&
          json_push_kv_str(out, "compiler", feedback->compiler) &&
          json_push_kv_str(out, "path", feedback->path) &&
          json_push_kv_int(out, "line", feedback->line) &&
          json_push_kv_int(out, "column", feedback->column) &&
          json_push_kv_str(out, "message", feedback->message)));
}

static bool run_render_async_admission(
    struct zcl_command_reply *reply,
    const struct vcs_zcode_task_index_entry *entry,
    const struct zcl_command_reply *inner, const char *adapter_name,
    const char *workspace, bool details)
{
    const struct json_value *changed = json_get(&inner->data, "changed_files");
    const struct json_value *candidate = json_get(&inner->data, "candidate_root");
    const struct json_value *candidate_source =
        json_get(&inner->data, "candidate_source_root");
    const struct json_value *patch = json_get(&inner->data, "patch_root");
    const struct json_value *action = json_get(&inner->data, "action_id");
    const struct json_value *proof_state =
        json_get(&inner->data, "async_proof_state");
    const struct json_value *proof_event =
        json_get(&inner->data, "async_proof_event_root");
    const struct json_value *proof_request =
        json_get(&inner->data, "remote_request_id");
    const struct json_value *submit_us =
        json_get(&inner->data, "local_submit_us");
    if (!changed || !candidate || !candidate_source || !patch || !action ||
        !proof_state || !proof_event || !proof_request || !submit_us)
        return false;
    char work_id[32];
    (void)snprintf(work_id, sizeof(work_id), "work-%.12s",
                   entry->task_root_hex);
    struct json_value expert;
    json_init(&expert); json_set_object(&expert);
    bool ok = (!details ||
        (json_push_kv_str(&expert, "task_root", entry->task_root_hex) &&
         json_push_kv_str(&expert, "candidate_root",
                          json_get_str(candidate)) &&
         json_push_kv_str(&expert, "candidate_source_root",
                          json_get_str(candidate_source)) &&
         json_push_kv_str(&expert, "patch_root", json_get_str(patch)) &&
         json_push_kv_str(&expert, "action_id", json_get_str(action)))) &&
        json_push_kv_str(&reply->data, "work_id", work_id) &&
        json_push_kv_str(&reply->data, "state", "CANDIDATE_ADMITTED") &&
        json_push_kv_str(&reply->data, "stage",
                         "Waiting for independent reproduction") &&
        json_push_kv_int(&reply->data, "changed_files",
                         json_get_int(changed)) &&
        json_push_kv_str(&reply->data, "async_proof_state",
                         json_get_str(proof_state)) &&
        json_push_kv_int(&reply->data, "local_submit_us",
                         json_get_int(submit_us)) &&
        json_push_kv_str(&reply->data, "build_result",
                         "background_pending") &&
        json_push_kv_int(&reply->data, "compile_receipts", 0) &&
        json_push_kv_int(&reply->data, "test_receipts", 0) &&
        json_push_kv_str(&reply->data, "sanitizer_result", "pending") &&
        json_push_kv_str(&reply->data, "remote_outcome",
                         "BACKGROUND_PENDING") &&
        json_push_kv_str(&reply->data, "adapter", adapter_name) &&
        json_push_kv_str(&reply->data, "next_safe_command",
                         "zcode work status") &&
        json_push_kv_bool(&reply->data, "details_available", true) &&
        (!details ||
         (json_push_kv_str(&reply->data, "candidate_root",
                           json_get_str(candidate)) &&
          json_push_kv_str(&reply->data, "patch_root",
                           json_get_str(patch)) &&
          json_push_kv_str(&reply->data, "async_proof_event_root",
                           json_get_str(proof_event)) &&
          json_push_kv_int(&reply->data, "remote_request_id",
                           json_get_int(proof_request)) &&
          json_push_kv(&reply->data, "expert", &expert))) &&
        run_add_work_next(
            reply, "zcode.work.status", workspace, work_id, NULL,
            "show the admitted candidate while independent proof arrives");
    static const char *const metric_keys[] = {
        "foreground_request_creation_us",
        "durable_action_lookup_dedup_us",
        "live_rpc_encode_us",
        "live_rpc_admission_us",
        "live_rpc_decode_us",
        "live_rpc_request_bytes",
        "live_rpc_response_bytes",
    };
    for (size_t i = 0; ok && i < sizeof(metric_keys) / sizeof(metric_keys[0]);
         i++) {
        const struct json_value *value = json_get(
            &inner->data, metric_keys[i]);
        if (value && value->type == JSON_INT)
            ok = json_push_kv_int(&reply->data, metric_keys[i],
                                  json_get_int(value));
    }
    static const char *const reproduction_string_keys[] = {
        "reproduction_action_id",
        "reproduction_job_id",
        "reproduction_async_proof_event_root",
    };
    for (size_t i = 0; details && ok && i < sizeof(reproduction_string_keys) /
                                      sizeof(reproduction_string_keys[0]);
         i++) {
        const struct json_value *value = json_get(
            &inner->data, reproduction_string_keys[i]);
        if (value && value->type == JSON_STR)
            ok = json_push_kv_str(&reply->data, reproduction_string_keys[i],
                                  json_get_str(value));
    }
    const struct json_value *reproduction_request = json_get(
        &inner->data, "reproduction_remote_request_id");
    if (details && ok && reproduction_request &&
        reproduction_request->type == JSON_INT)
        ok = json_push_kv_int(
            &reply->data, "reproduction_remote_request_id",
            json_get_int(reproduction_request));
    json_free(&expert);
    return ok;
}

static bool run_admit(
    const char *workspace, const char *candidate_workspace,
    const char *proof_datadir, const char *goal,
    const struct vcs_zcode_task_index_entry *entry,
    const struct vcs_zcode_task_context_entry *context_entry,
    const struct vcs_zcode_task_v1 *task,
    const struct vcs_zcode_agent_context_v1 *context,
    const struct vcs_zcode_write_scope_v1 *scope,
    uint64_t candidate_sequence, const char *adapter_name, bool details,
    struct zcl_command_reply *reply)
{
    char datadir[ZWORK_RUN_PATH_MAX];
    if (proof_datadir && proof_datadir[0]) {
        int n = snprintf(datadir, sizeof(datadir), "%s", proof_datadir);
        if (n <= 0 || (size_t)n >= sizeof(datadir))
            return false;
    } else {
        (void)snprintf(datadir, sizeof(datadir), "%s", candidate_workspace);
        char *slash = strrchr(datadir, '/');
        if (!slash) return false;
        (void)snprintf(slash, (size_t)(datadir + sizeof(datadir) - slash),
                       "/zbuild");
    }
    struct zcl_result made = zcl_mkdir_p(datadir, 0700);
    struct db_build_worker worker;
    uint8_t secret[32] = {0}, pubkey[32] = {0};
    struct zcl_result identity = made.ok
        ? build_fabric_worker_identity_load(
              datadir, &worker, secret, pubkey)
        : made;
    char author_hex[65], adapter_hex[65];
    zcl_hex_encode(pubkey, 32, author_hex);
    uint8_t context_root[32], adapter_root[32];
    bool rooted = zcl_hex_decode_lower(context_entry->context_root_hex,
                                       context_root, 32);
    struct sha3_256_ctx sha;
    static const char manual_domain[] = "zcl.zcode.adapter.manual.v1";
    static const char codex_domain[] = "zcl.zcode.adapter.codex.v1";
    const char *domain = strcmp(adapter_name, "codex") == 0
        ? codex_domain : manual_domain;
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)domain, strlen(domain) + 1u);
    if (rooted) sha3_256_write(&sha, context_root, sizeof(context_root));
    if (rooted && candidate_sequence > 1u) {
        uint8_t parent_root[32];
        if (!zcl_hex_decode_lower(entry->latest_candidate_root_hex,
                                  parent_root, sizeof(parent_root)))
            rooted = false;
        else
            sha3_256_write(&sha, parent_root, sizeof(parent_root));
    }
    sha3_256_finalize(&sha, adapter_root);
    zcl_hex_encode(adapter_root, 32, adapter_hex);
    if (!identity.ok || !rooted) {
        memory_cleanse(secret, sizeof(secret));
        return false;
    }
    bool standard = false;
    if (!run_standard_policy(workspace, task, &standard)) {
        memory_cleanse(secret, sizeof(secret));
        return false;
    }
    const char *execution_profile = standard
        ? VCS_BUILD_PACKAGE_PROFILE_STANDARD_A_V1
        : VCS_BUILD_PACKAGE_PROFILE_QUICK_V1;
    struct json_value input;
    if (!run_admit_input(&input, workspace, datadir, candidate_workspace,
                         goal, entry, context_entry, task, context, scope,
                         author_hex, adapter_hex, candidate_sequence,
                         execution_profile)) {
        memory_cleanse(secret, sizeof(secret));
        return false;
    }
    struct zcl_command_request inner_request = { .input = &input };
    struct zcl_command_reply inner;
    zcl_command_reply_init(&inner, "zcl.zcode_improve.v1");
    zcl_native_handle_zcode_improve(&inner_request, &inner);
    json_free(&input);
    if (inner.status != ZCL_COMMAND_STATUS_PASSED) {
        run_fail(reply, inner.error.code[0] ? inner.error.code :
                     "CANDIDATE_ADMISSION_FAILED",
                 inner.error.phase[0] ? inner.error.phase : "admit",
                 inner.error.message[0] ? inner.error.message :
                     "existing candidate admission refused",
                 inner.error.retryable, inner.error.mutated);
        memory_cleanse(secret, sizeof(secret));
        zcl_command_reply_free(&inner);
        return true;
    }
    const struct json_value *changed = json_get(&inner.data, "changed_files");
    const struct json_value *candidate = json_get(&inner.data, "candidate_root");
    const struct json_value *candidate_source =
        json_get(&inner.data, "candidate_source_root");
    const struct json_value *patch = json_get(&inner.data, "patch_root");
    const struct json_value *action = json_get(&inner.data, "action_id");
    const struct json_value *proof_state =
        json_get(&inner.data, "async_proof_state");
    const struct json_value *proof_event =
        json_get(&inner.data, "async_proof_event_root");
    const struct json_value *proof_request =
        json_get(&inner.data, "remote_request_id");
    const struct json_value *submit_us =
        json_get(&inner.data, "local_submit_us");
    /* An explicit full-node datadir means the daemon now owns this immutable
     * action.  Foreground work ends at admission: its enabled local worker or
     * a peer may consume the action later, but the originating CLI must never
     * race either owner by generically claiming the live queue.  Closed
     * scratch ledgers (no explicit proof datadir) retain the contained local
     * execution path used by deterministic unit/development fixtures. */
    if (proof_datadir && proof_datadir[0]) {
        memory_cleanse(secret, sizeof(secret));
        bool rendered = run_render_async_admission(
            reply, entry, &inner, adapter_name, workspace, details);
        zcl_command_reply_free(&inner);
        if (!rendered)
            run_fail(reply, "ADMISSION_OUTPUT_FAILED", "render",
                     "live async admission summary could not be rendered",
                     false, true);
        return true;
    }
    struct db_build_receipt receipt;
    struct build_fabric_worker_feedback feedback;
    memset(&feedback, 0, sizeof(feedback));
    struct zcl_result executed = action && json_get_str(action)
        ? run_execute_action(workspace, datadir, json_get_str(action), &worker,
                             secret, pubkey, &receipt, &feedback)
        : ZCL_ERR(-1, "admission did not return an action id");
    char peer_action_id[BUILD_FABRIC_ID_HEX + 1] = {0};
    struct db_build_receipt peer_receipt;
    memset(&peer_receipt, 0, sizeof(peer_receipt));
    if (executed.ok && receipt.exit_status == 0 && standard) {
        executed = run_plan_standard_peer(
            datadir, json_get_str(action), peer_action_id);
        if (executed.ok)
            executed = run_execute_action(
                workspace, datadir, peer_action_id, &worker, secret, pubkey,
                &peer_receipt, NULL);
    }
    memory_cleanse(secret, sizeof(secret));
    if (!executed.ok) {
        run_fail(reply, "PACKAGE_BUILD_FAILED", "build", executed.message,
                 true, true);
        struct json_value compiler_feedback;
        if (run_worker_feedback_json(&compiler_feedback, &feedback))
            (void)json_push_kv(&reply->data, "compiler_feedback",
                               &compiler_feedback);
        json_free(&compiler_feedback);
        zcl_command_reply_free(&inner);
        return true;
    }
    struct json_value expert;
    json_init(&expert); json_set_object(&expert);
    bool expert_ok = !details ||
        (action && candidate && candidate_source && patch &&
         json_push_kv_str(&expert, "task_root", entry->task_root_hex) &&
         json_push_kv_str(&expert, "candidate_root",
                          json_get_str(candidate)) &&
         json_push_kv_str(&expert, "candidate_source_root",
                          json_get_str(candidate_source)) &&
         json_push_kv_str(&expert, "patch_root", json_get_str(patch)) &&
         json_push_kv_str(&expert, "action_id", json_get_str(action)) &&
         json_push_kv_str(&expert, "receipt_id", receipt.receipt_id) &&
         json_push_kv_str(&expert, "output_root", receipt.output_sha3) &&
         json_push_kv_str(&expert, "work_receipt_root",
                          receipt.work_receipt_sha3) &&
         (!standard ||
          (json_push_kv_str(&expert, "standard_peer_action_id",
                            peer_action_id) &&
           json_push_kv_str(&expert, "standard_peer_work_receipt_root",
                            peer_receipt.work_receipt_sha3))));
    char work_id[32];
    (void)snprintf(work_id, sizeof(work_id), "work-%.12s",
                   entry->task_root_hex);
    bool passed = receipt.exit_status == 0 &&
                  (!standard || peer_receipt.exit_status == 0);
    char next_workspace[ZWORK_RUN_PATH_MAX] = {0};
    bool next_created = false;
    uint8_t next_source_root[32];
    bool retry_ready = !passed && candidate_sequence < 3u &&
        candidate_source && json_get_str(candidate_source) &&
        zcl_hex_decode_lower(json_get_str(candidate_source), next_source_root,
                             sizeof(next_source_root)) &&
        run_candidate_workspace(workspace, task, entry->task_root_hex,
                                (uint32_t)candidate_sequence + 1u,
                                next_source_root, next_workspace,
                                &next_created);
    (void)next_created;
    struct json_value diagnostic;
    json_init(&diagnostic); json_set_object(&diagnostic);
    struct json_value compiler_feedback;
    bool feedback_ok = run_worker_feedback_json(
        &compiler_feedback, &feedback);
    bool diagnostic_ok = json_push_kv_str(&diagnostic, "stage",
                                           "package_build_and_tests") &&
        json_push_kv_int(&diagnostic, "attempt",
                         (int64_t)candidate_sequence) &&
        json_push_kv_int(&diagnostic, "exit_status", receipt.exit_status) &&
        json_push_kv_bool(&diagnostic, "retry_safe", retry_ready) &&
        feedback_ok &&
        json_push_kv(&diagnostic, "compiler_feedback", &compiler_feedback);
    struct json_value repair_packet;
    json_init(&repair_packet); json_set_object(&repair_packet);
    char repair_detail[256];
    bool repair_packet_ok = !retry_ready ||
        (run_packet(
             &repair_packet, goal, workspace, datadir, task,
             context, scope, repair_detail) &&
         json_push_kv(&repair_packet, "diagnostic", &diagnostic));
    char repair_packet_path[ZWORK_RUN_PATH_MAX] = {0};
    size_t repair_packet_bytes = retry_ready && repair_packet_ok
        ? json_write(&repair_packet, NULL, 0) : 0;
    bool repair_packet_staged = !retry_ready ||
        (repair_packet_bytes > 0 && run_write_packet(
            next_workspace, &repair_packet, repair_packet_path));
    bool ok = changed && candidate && patch && proof_state && proof_event &&
        proof_request && submit_us && diagnostic_ok && expert_ok &&
        repair_packet_ok && repair_packet_staged &&
        receipt.work_receipt_sha3[0] &&
        json_push_kv_str(&reply->data, "work_id", work_id) &&
        json_push_kv_str(&reply->data, "state", passed ? "EVIDENCE_READY" :
                         retry_ready ? "REPAIR_NEEDED" : "BLOCKED") &&
        json_push_kv_str(&reply->data, "stage",
                         passed ? "Showing result" :
                         retry_ready ? "Creating missing code" :
                                       "Needs attention") &&
        json_push_kv_int(&reply->data, "changed_files",
                         json_get_int(changed)) &&
        json_push_kv_str(&reply->data, "async_proof_state",
                         json_get_str(proof_state)) &&
        json_push_kv_int(&reply->data, "local_submit_us",
                         json_get_int(submit_us)) &&
        json_push_kv_str(&reply->data, "build_result",
                         passed ? "passed" : "failed") &&
        json_push_kv_int(&reply->data, "compile_receipts",
                         passed ? (standard ? 2 : 1) : 0) &&
        json_push_kv_int(&reply->data, "test_receipts",
                         passed ? (standard ? 2 : 1) : 0) &&
        json_push_kv_str(&reply->data, "sanitizer_result",
                         passed && standard ? "passed_asan_ubsan" :
                         standard ? "failed_or_unavailable" :
                                    "not_required") &&
        json_push_kv_int(&reply->data, "attempt",
                         (int64_t)candidate_sequence) &&
        json_push_kv(&reply->data, "diagnostic", &diagnostic) &&
        (!retry_ready ||
         json_push_kv_str(&reply->data, "candidate_workspace",
                          next_workspace)) &&
        (!retry_ready ||
         (json_push_kv_str(&reply->data, "repair_packet_path",
                           repair_packet_path) &&
          json_push_kv_int(&reply->data, "model_context_bytes",
                           (int64_t)repair_packet_bytes))) &&
        (!retry_ready || !details ||
         json_push_kv(&reply->data, "repair_packet", &repair_packet)) &&
        json_push_kv_str(&reply->data, "adapter", adapter_name) &&
        json_push_kv_str(&reply->data, "next_safe_command",
                         passed ? "zcode work status" :
                         retry_ready ? "edit candidate_workspace, then rerun zcode work run" :
                                       "zcode work status") &&
        json_push_kv_bool(&reply->data, "details_available", true) &&
        (!details ||
         (json_push_kv_str(&reply->data, "candidate_root",
                           json_get_str(candidate)) &&
          json_push_kv_str(&reply->data, "patch_root",
                           json_get_str(patch)) &&
          json_push_kv_str(&reply->data, "work_receipt_root",
                           receipt.work_receipt_sha3) &&
          json_push_kv_str(&reply->data, "async_proof_event_root",
                           json_get_str(proof_event)) &&
          json_push_kv_int(&reply->data, "remote_request_id",
                           json_get_int(proof_request)) &&
          json_push_kv(&reply->data, "expert", &expert))) &&
        run_add_work_next(
            reply, "zcode.work.status", workspace, work_id, NULL,
            retry_ready
              ? "show the repair state and its exact resumable action"
              : "show the exact build and reproduction state");
    json_free(&compiler_feedback);
    json_free(&repair_packet); json_free(&diagnostic); json_free(&expert);
    zcl_command_reply_free(&inner);
    if (!ok)
        run_fail(reply, "ADMISSION_OUTPUT_FAILED", "render",
                 "candidate admission summary could not be rendered",
                 false, true);
    return true;
}

static void run_feedback_timing(
    struct zcl_command_reply *reply, int64_t started_us)
{
    if (!reply || reply->status != ZCL_COMMAND_STATUS_PASSED) return;
    int64_t elapsed = platform_time_monotonic_us() - started_us;
    (void)json_push_kv_int(&reply->data, "local_first_feedback_us",
                           elapsed < 0 ? 0 : elapsed);
}

struct run_adapter_preflight {
    bool runner_structural;
    bool runner_identity;
    bool codex_binding;
    bool credential;
    bool sandbox;
    bool packet;
    int64_t packet_bytes;
    char codex_artifact_sha3[65];
    char packet_detail[256];
};

static bool run_preflight_runner_path(char out[ZWORK_RUN_PATH_MAX])
{
    char executable[ZWORK_RUN_PATH_MAX];
    if (!os_proc_exe_path(executable, sizeof(executable))) return false;
    char *slash = strrchr(executable, '/');
#if defined(_WIN32)
    char *backslash = strrchr(executable, '\\');
    if (!slash || (backslash && backslash > slash)) slash = backslash;
#endif
    if (!slash) return false;
    *slash = '\0';
    /* The image suffix is chosen BEFORE the call: _FORTIFY_SOURCE makes
     * snprintf a macro, and a preprocessor directive between a macro's
     * parentheses is undefined behaviour. */
#if defined(_WIN32)
    const char *const runner_ext = ".exe";
#else
    const char *const runner_ext = "";
#endif
    int n = snprintf(out, ZWORK_RUN_PATH_MAX,
                     "%s/zclassic23-zcode-adapter-runner%s", executable,
                     runner_ext);
#if defined(_WIN32)
    struct platform_positioned_file runner;
    platform_positioned_file_init(&runner);
    bool ok = n > 0 && (size_t)n < ZWORK_RUN_PATH_MAX &&
        platform_positioned_file_open(&runner, out) &&
        platform_positioned_file_is_executable(&runner) &&
        platform_positioned_file_is_current_user_only(&runner);
    platform_positioned_file_close(&runner);
    return ok;
#else
    struct stat st;
    return n > 0 && (size_t)n < ZWORK_RUN_PATH_MAX &&
        lstat(out, &st) == 0 && S_ISREG(st.st_mode) &&
        st.st_uid == getuid() && (st.st_mode & 0100u) != 0 &&
        (st.st_mode & 0022u) == 0;
#endif
}

static bool run_preflight_invoke(const char *runner, const char *verb,
                                 char output[ZWORK_PREFLIGHT_OUTPUT_MAX])
{
#if defined(_WIN32)
    (void)runner; (void)verb;
    memset(output, 0, ZWORK_PREFLIGHT_OUTPUT_MAX);
    return false;
#else
    const char *const argv[] = { runner, verb, NULL };
    memset(output, 0, ZWORK_PREFLIGHT_OUTPUT_MAX);
    return zcl_spawn_capture(argv, output, ZWORK_PREFLIGHT_OUTPUT_MAX,
                             30000) == 0;
#endif
}

static bool run_preflight_runner_identity(const char *runner)
{
    char output[ZWORK_PREFLIGHT_OUTPUT_MAX];
    if (!run_preflight_invoke(runner, "--identity", output)) return false;
    struct json_value document;
    json_init(&document);
    bool ok = json_read(&document, output, strlen(output)) &&
        document.type == JSON_OBJ;
    const char *schema = ok ? run_str(&document, "schema") : NULL;
    const char *source = ok ? run_str(&document, "source_id") : NULL;
    ok = schema && strcmp(schema,
             "zcl.zcode_adapter_runner_identity.v1") == 0 && source &&
         strcmp(source, zcl_build_source_id_sha256()) == 0;
    json_free(&document);
    return ok;
}

static bool run_preflight_codex_binding(
    const char *runner, char artifact_sha3[65])
{
    char output[ZWORK_PREFLIGHT_OUTPUT_MAX];
    artifact_sha3[0] = '\0';
    if (!run_preflight_invoke(runner, "--binding", output)) return false;
    struct json_value document;
    json_init(&document);
    bool ok = json_read(&document, output, strlen(output)) &&
        document.type == JSON_OBJ &&
        json_get_bool(json_get(&document, "ready"));
    const char *digest = ok ? run_str(&document, "artifact_sha3") : NULL;
    ok = digest && strlen(digest) == 64u;
    if (ok) (void)snprintf(artifact_sha3, 65, "%s", digest);
    json_free(&document);
    return ok;
}

static bool run_preflight_credential(void)
{
    const char *api_key = getenv("CODEX_API_KEY");
    const char *access_token = getenv("CODEX_ACCESS_TOKEN");
    bool have_api = api_key && api_key[0];
    bool have_token = access_token && access_token[0];
    const char *value = have_api ? api_key : access_token;
    return have_api != have_token && value && strlen(value) <= 16384u;
}

static bool run_preflight_sandbox(const char *runner)
{
#if defined(_WIN32)
    (void)runner;
    return false;
#else
    char root[] = "/tmp/z23-adapter-preflight.XXXXXX";
    if (!mkdtemp(root)) return false;
    struct json_value packet;
    json_init(&packet); json_set_object(&packet);
    char packet_path[ZWORK_RUN_PATH_MAX] = {0};
    bool staged = run_write_packet(root, &packet, packet_path);
    json_free(&packet);
    char output[ZWORK_PREFLIGHT_OUTPUT_MAX] = {0};
    const char *const argv[] = {
        runner, "--preflight", root, packet_path, NULL,
    };
    int rc = staged ? zcl_spawn_capture(
        argv, output, sizeof(output), 30000) : -1;
    bool started = false;
    struct json_value response;
    json_init(&response);
    if (rc == 0 && json_read(&response, output, strlen(output)) &&
        response.type == JSON_OBJ)
        started = json_get_bool(json_get(&response, "sandbox_started")) &&
            !json_get_bool(json_get(&response, "model_request_attempted"));
    json_free(&response);
    struct zcl_result removed = zcl_tree_remove(root);
    return started && removed.ok;
#endif
}

static bool run_preflight_packet(
    const struct zcl_command_request *request, int64_t *bytes_out,
    char detail[256])
{
    const char *workspace_arg = run_str(request->input, "workspace");
    const char *work = run_str(request->input, "work");
    const char *datadir_arg = run_str(request->input, "datadir");
    if (!workspace_arg || !workspace_arg[0]) workspace_arg = ".";
    char workspace[ZWORK_RUN_PATH_MAX], datadir[ZWORK_RUN_PATH_MAX] = {0};
    if (!platform_directory_canonical_real(workspace_arg, workspace,
                                           sizeof(workspace))) {
        (void)snprintf(detail, 256,
                       "workspace must resolve to an existing directory");
        return false;
    }
    if (datadir_arg && datadir_arg[0] &&
        !platform_directory_canonical_real(datadir_arg, datadir,
                                           sizeof(datadir))) {
        (void)snprintf(detail, 256,
                       "datadir must resolve to an existing node directory");
        return false;
    }
    struct vcs_zcode_task_index *index = vcs_zcode_task_index_build(
        workspace, platform_time_wall_unix());
    bool ambiguous = false, context_ambiguous = false;
    const struct vcs_zcode_task_index_entry *entry = index
        ? run_resolve(index, work, &ambiguous) : NULL;
    const struct vcs_zcode_task_context_entry *context_entry = entry
        ? vcs_zcode_task_index_context_for_task(
              index, entry->task_root_hex, &context_ambiguous) : NULL;
    struct vcs_zcode_task_v1 task;
    struct vcs_zcode_agent_context_v1 context;
    vcs_zcode_agent_context_init(&context);
    struct vcs_zcode_write_scope_v1 scope;
    vcs_zcode_write_scope_init(&scope);
    enum vcs_zcode_agent_context_result context_admission =
        VCS_ZCODE_AGENT_CONTEXT_NULL;
    char *goal = NULL;
    bool loaded = entry && context_entry && !ambiguous &&
        !context_ambiguous && !entry->expired &&
        run_load_task(workspace, entry->task_root_hex, &task) &&
        (goal = run_load_goal(workspace, &task)) != NULL &&
        run_load_context(workspace, context_entry, &task,
                         entry->task_root_hex, &context,
                         &context_admission) &&
        context_admission == VCS_ZCODE_AGENT_CONTEXT_OK &&
        run_load_scope(workspace, &task, &scope);
    struct json_value packet;
    json_init(&packet);
    bool ready = loaded && run_packet(
        &packet, goal, workspace, datadir, &task, &context, &scope, detail);
    size_t bytes = ready ? json_write(&packet, NULL, 0) : 0;
    ready = ready && bytes > 0 && bytes <= ZWORK_ADAPTER_PACKET_MAX;
    if (ready) *bytes_out = (int64_t)bytes;
    if (!loaded)
        (void)snprintf(detail, 256, "%s",
            entry && entry->expired ? "task expired; start new bounded work" :
            context_ambiguous ? "task has multiple verified contexts" :
            ambiguous ? "work selector is ambiguous" :
            "verified task, goal and unique context are required");
    json_free(&packet);
    free(goal); vcs_zcode_agent_context_free(&context);
    vcs_zcode_task_index_free(index);
    return ready;
}

static const char *run_preflight_primary(
    const struct run_adapter_preflight *state, const char **current,
    const char **next, bool *human)
{
    *human = true;
    if (!state->runner_structural || !state->runner_identity) {
        *current = state->runner_structural ? "runner_source_mismatch"
                                            : "runner_unavailable";
        *next = "make zclassic23-zcode-adapter-runner";
        return "ADAPTER_RUNNER_UNBOUND";
    }
    if (!state->codex_binding) {
        *current = "codex_executable_unbound";
        *next = "install one owner-approved Codex executable binding, then rerun z23 zcode work preflight";
        return "CODEX_EXECUTABLE_UNBOUND";
    }
    if (!state->credential) {
        *current = "single_run_credential_unavailable";
        *next = "provide exactly one supported single-run Codex credential, then rerun z23 zcode work preflight";
        return "CODEX_CREDENTIAL_UNAVAILABLE";
    }
    if (!state->sandbox) {
        *current = "filesystem_sandbox_start_failed";
        *next = "enable the required unprivileged filesystem sandbox, then rerun z23 zcode work preflight";
        return "FILESYSTEM_SANDBOX_UNAVAILABLE";
    }
    if (!state->packet) {
        *current = "bounded_packet_unavailable";
        *next = "run z23 zcode work start for one exact goal, then rerun z23 zcode work preflight with that work id";
        return "ADAPTER_PACKET_UNAVAILABLE";
    }
    *human = false;
    *current = "ready";
    *next = "z23 zcode work run --input='{\"workspace\":\".\",\"work\":\"latest\",\"adapter\":\"codex\"}'";
    return "NONE";
}

void zcl_native_handle_zcode_work_preflight(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!request || !reply) return;
    struct run_adapter_preflight state = {0};
    char runner[ZWORK_RUN_PATH_MAX] = {0};
    state.runner_structural = run_preflight_runner_path(runner);
    state.runner_identity = state.runner_structural &&
        run_preflight_runner_identity(runner);
    state.codex_binding = state.runner_structural &&
        run_preflight_codex_binding(runner, state.codex_artifact_sha3);
    state.credential = run_preflight_credential();
    state.sandbox = state.runner_structural && run_preflight_sandbox(runner);
    state.packet = run_preflight_packet(
        request, &state.packet_bytes, state.packet_detail);
    const char *current = NULL, *next = NULL;
    bool human = false;
    const char *blocker = run_preflight_primary(
        &state, &current, &next, &human);
    bool ready = strcmp(blocker, "NONE") == 0;
    struct json_value checks, executable, credential, sandbox, packet;
    json_init(&checks); json_set_object(&checks);
    json_init(&executable); json_set_object(&executable);
    json_init(&credential); json_set_object(&credential);
    json_init(&sandbox); json_set_object(&sandbox);
    json_init(&packet); json_set_object(&packet);
    bool ok = json_push_kv_bool(&executable, "ready",
                                state.runner_identity && state.codex_binding) &&
        json_push_kv_bool(&executable, "runner_bound",
                          state.runner_identity) &&
        json_push_kv_bool(&executable, "codex_bound", state.codex_binding) &&
        (!state.codex_artifact_sha3[0] ||
         json_push_kv_str(&executable, "artifact_sha3",
                          state.codex_artifact_sha3)) &&
        json_push_kv_bool(&credential, "ready", state.credential) &&
        json_push_kv_bool(&credential, "value_exposed", false) &&
        json_push_kv_bool(&sandbox, "ready", state.sandbox) &&
        json_push_kv_bool(&sandbox, "model_request_attempted", false) &&
        json_push_kv_bool(&packet, "ready", state.packet) &&
        json_push_kv_int(&packet, "bytes", state.packet_bytes) &&
        (!state.packet_detail[0] ||
         json_push_kv_str(&packet, "detail", state.packet_detail)) &&
        json_push_kv(&checks, "executable_binding", &executable) &&
        json_push_kv(&checks, "credential_capability", &credential) &&
        json_push_kv(&checks, "filesystem_sandbox", &sandbox) &&
        json_push_kv(&checks, "packet", &packet) &&
        json_push_kv_str(&reply->data, "adapter", "codex") &&
        json_push_kv_bool(&reply->data, "ready", ready) &&
        json_push_kv_bool(&reply->data, "model_request_attempted", false) &&
        json_push_kv(&reply->data, "checks", &checks) &&
        json_push_kv_str(&reply->data, "blocker", blocker) &&
        json_push_kv_str(&reply->data, "error_code", blocker) &&
        json_push_kv_str(&reply->data, "current_state", current) &&
        json_push_kv_bool(&reply->data, "retryable", !ready) &&
        json_push_kv_bool(&reply->data, "human_action_required", human) &&
        json_push_kv_str(&reply->data, "next_action", next);
    json_free(&packet); json_free(&sandbox); json_free(&credential);
    json_free(&executable); json_free(&checks);
    if (!ok) {
        run_fail(reply, "PREFLIGHT_OUTPUT_FAILED", "render",
                 "adapter readiness could not be rendered", false, false);
        return;
    }
    reply->status = ZCL_COMMAND_STATUS_PASSED;
    reply->exit_code = ZCL_COMMAND_EXIT_OK;
}

void zcl_native_handle_zcode_work_run(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!request || !reply) return;
#if defined(_WIN32)
    run_fail(reply, "PACKAGE_EXECUTION_UNSUPPORTED", "sandbox",
             "package execution is disabled on Windows until restricted "
             "tokens, Job Objects, low-integrity isolation, resource limits, "
             "and network denial pass adversarial qualification",
             false, false);
    return;
#endif
    int64_t feedback_started_us = platform_time_monotonic_us();
    const char *workspace_arg = run_str(request->input, "workspace");
    const char *work = run_str(request->input, "work");
    const char *adapter = run_str(request->input, "adapter");
    const char *proof_datadir_arg = run_str(request->input, "datadir");
    bool details = run_bool(request->input, "details");
    struct node_db *runtime_db = app_runtime_node_db();
    if ((!proof_datadir_arg || !proof_datadir_arg[0]) &&
        ((runtime_db && app_runtime_node_db_handle_open(runtime_db)) ||
         zcl_native_command_datadir_is_explicit()))
        proof_datadir_arg = zcl_native_command_datadir();
    if (!workspace_arg || !workspace_arg[0]) workspace_arg = ".";
    if (!adapter || !adapter[0]) adapter = "manual";
    bool codex_adapter = strcmp(adapter, "codex") == 0;
    if (strcmp(adapter, "manual") != 0 && !codex_adapter) {
        run_fail(reply, "ADAPTER_REFUSED", "adapter",
                 "adapter must name one fixed adapter: manual or codex",
                 false, false);
        return;
    }
    char codex_runner[ZWORK_RUN_PATH_MAX] = {0};
    if (codex_adapter && !run_codex_runner_path(codex_runner)) {
        run_fail(reply, "ADAPTER_UNAVAILABLE", "adapter",
                 "the fixed confined Codex runner or one supported single-run CODEX credential is unavailable; manual remains safe",
                 true, false);
        return;
    }
    char workspace[ZWORK_RUN_PATH_MAX];
    if (!platform_directory_canonical_real(workspace_arg, workspace,
                                           sizeof(workspace))) {
        run_fail(reply, "BAD_WORKSPACE", "resolve",
                 "workspace must resolve to an existing directory", false,
                 false);
        return;
    }
    char proof_datadir[ZWORK_RUN_PATH_MAX] = {0};
    if (proof_datadir_arg && proof_datadir_arg[0] &&
        !platform_directory_canonical_real(proof_datadir_arg, proof_datadir,
                                           sizeof(proof_datadir))) {
        run_fail(reply, "BAD_DATADIR", "resolve",
                 "datadir must resolve to an existing full-node data directory",
                 false, false);
        return;
    }
    struct vcs_zcode_task_index *index = vcs_zcode_task_index_build(
        workspace, platform_time_wall_unix());
    bool ambiguous = false;
    const struct vcs_zcode_task_index_entry *entry = index
        ? run_resolve(index, work, &ambiguous) : NULL;
    bool context_ambiguous = false;
    const struct vcs_zcode_task_context_entry *context_entry = entry
        ? vcs_zcode_task_index_context_for_task(
              index, entry->task_root_hex, &context_ambiguous) : NULL;
    struct vcs_zcode_task_v1 task;
    struct vcs_zcode_agent_context_v1 context;
    vcs_zcode_agent_context_init(&context);
    struct vcs_zcode_write_scope_v1 scope;
    vcs_zcode_write_scope_init(&scope);
    enum vcs_zcode_agent_context_result context_admission =
        VCS_ZCODE_AGENT_CONTEXT_NULL;
    char *goal = NULL;
    bool loaded = entry && context_entry && !context_ambiguous &&
        run_load_task(workspace, entry->task_root_hex, &task) &&
        (goal = run_load_goal(workspace, &task)) != NULL &&
        run_load_context(workspace, context_entry, &task,
                         entry->task_root_hex, &context,
                         &context_admission) &&
        run_load_scope(workspace, &task, &scope) && !entry->expired;
    if (!loaded) {
        run_fail(reply, context_ambiguous ? "AMBIGUOUS_CONTEXT" :
                     ambiguous ? "AMBIGUOUS_WORK" : "WORK_HANDOFF_MISSING",
                 "resolve",
                 entry && entry->expired
                    ? "task expired; start a new bounded work item"
                    : context_ambiguous
                    ? "task has multiple contexts; select an exact expert context"
                    : "verified task, goal, and unique context could not be reloaded",
                 false, false);
        free(goal); vcs_zcode_agent_context_free(&context);
        vcs_zcode_task_index_free(index); return;
    }
    /* Terminal-for-run states: the candidate's evidence is complete (or the
     * work is already accepted).  Repeating run is an idempotent observation
     * of that fact — never a fresh candidate attempt.  This is the same
     * interpretation zcode work status gives the same lifecycle fact. */
    if (strcmp(entry->state, VCS_ZCODE_TASK_STATE_EVIDENCE_READY) == 0 ||
        strcmp(entry->state, VCS_ZCODE_TASK_STATE_CANDIDATE_PROOFS_READY) == 0 ||
        strcmp(entry->state, VCS_ZCODE_TASK_STATE_PROVEN) == 0) {
        bool proven =
            strcmp(entry->state, VCS_ZCODE_TASK_STATE_PROVEN) == 0;
        bool decision =
            strcmp(entry->state,
                   VCS_ZCODE_TASK_STATE_CANDIDATE_PROOFS_READY) == 0;
        char work_id[32];
        (void)snprintf(work_id, sizeof(work_id), "work-%.12s",
                       entry->task_root_hex);
        bool ok = json_push_kv_str(&reply->data, "work_id", work_id) &&
            json_push_kv_str(&reply->data, "state", entry->state) &&
            json_push_kv_str(&reply->data, "stage",
                             proven ? "Accepted" :
                             decision ? "Ready for your decision" :
                                        "Showing result") &&
            json_push_kv_str(&reply->data, "build_result", "passed") &&
            json_push_kv_str(&reply->data, "next_safe_command",
                             "zcode work status") &&
            json_push_kv_bool(&reply->data, "details_available", true) &&
            run_add_work_next(
                reply, "zcode.work.status", workspace, work_id, NULL,
                proven ? "show the accepted work and its publication state" :
                decision ? "show the candidate awaiting your acceptance decision" :
                           "show the exact build and reproduction state");
        if (!ok)
            run_fail(reply, "HANDOFF_OUTPUT_FAILED", "render",
                     "evidence-ready summary could not be rendered",
                     false, false);
        free(goal); vcs_zcode_agent_context_free(&context);
        vcs_zcode_task_index_free(index); return;
    }
    if (strcmp(entry->state, VCS_ZCODE_TASK_STATE_CANDIDATE_ADMITTED) == 0) {
        char pending_state[BUILD_PROOF_EVENT_STATE_MAX + 1];
        if (run_async_proof_pending(proof_datadir, entry->task_root_hex,
                                    entry->latest_candidate_root_hex,
                                    pending_state)) {
            /* Same lifecycle fact, same interpretation as zcode work status:
             * the admitted candidate waits on independent proof that is
             * outstanding in the bound node's ledger.  Repeating run is an
             * idempotent observation of that wait — not a failure and never
             * a fresh attempt. */
            char work_id[32];
            (void)snprintf(work_id, sizeof(work_id), "work-%.12s",
                           entry->task_root_hex);
            bool ok =
                json_push_kv_str(&reply->data, "work_id", work_id) &&
                json_push_kv_str(&reply->data, "state", "CANDIDATE_ADMITTED") &&
                json_push_kv_str(&reply->data, "stage",
                                 "Waiting for independent reproduction") &&
                json_push_kv_str(&reply->data, "build_result",
                                 "background_pending") &&
                json_push_kv_str(&reply->data, "async_proof_state",
                                 pending_state) &&
                json_push_kv_str(&reply->data, "next_safe_command",
                                 "zcode work status") &&
                json_push_kv_bool(&reply->data, "details_available", true) &&
                run_add_work_next(
                    reply, "zcode.work.status", workspace, work_id, NULL,
                    "show the admitted candidate while independent proof arrives");
            if (!ok)
                run_fail(reply, "HANDOFF_OUTPUT_FAILED", "render",
                         "admitted-candidate waiting summary could not be rendered",
                         false, false);
            free(goal); vcs_zcode_agent_context_free(&context);
            vcs_zcode_task_index_free(index); return;
        }
        run_fail(reply, "CANDIDATE_EXECUTION_INCOMPLETE", "build",
                 "the candidate is captured but its prior package execution produced no signed work receipt and no supervised independent proof is outstanding; preserve it and diagnose the package prerequisite before starting another attempt",
                 true, true);
        free(goal); vcs_zcode_agent_context_free(&context);
        vcs_zcode_task_index_free(index); return;
    }
    bool repairing = strcmp(entry->state,
                            VCS_ZCODE_TASK_STATE_REPAIR_NEEDED) == 0;
    if (entry->candidate_count >= 3u) {
        run_fail(reply, "REPAIR_LIMIT_REACHED", "repair",
                 "three candidate attempts are preserved; start a new bounded work item",
                 false, false);
        free(goal); vcs_zcode_agent_context_free(&context);
        vcs_zcode_task_index_free(index); return;
    }
    uint64_t candidate_sequence = entry->candidate_count + 1u;
    uint8_t materialize_root[32];
    bool materialize_root_ok = true;
    if (repairing)
        materialize_root_ok = zcl_hex_decode_lower(
            entry->latest_candidate_source_root_hex, materialize_root,
            sizeof(materialize_root));
    else
        memcpy(materialize_root, task.source_root, sizeof(materialize_root));
    char candidate_workspace[ZWORK_RUN_PATH_MAX];
    bool created = false;
    if (context_admission != VCS_ZCODE_AGENT_CONTEXT_OK ||
        !materialize_root_ok || !run_candidate_workspace(
            workspace, &task, entry->task_root_hex,
            (uint32_t)candidate_sequence, materialize_root,
            candidate_workspace, &created)) {
        run_fail(reply, "HANDOFF_REFUSED", "materialize",
                 context_admission == VCS_ZCODE_AGENT_CONTEXT_INCOMPLETE
                    ? "complete context is required before model execution"
                    : context_admission == VCS_ZCODE_AGENT_CONTEXT_BINDING
                    ? "task and context bindings disagree"
                    : "isolated candidate workspace could not be created",
                 true, false);
        free(goal); vcs_zcode_agent_context_free(&context);
        vcs_zcode_task_index_free(index); return;
    }
    bool metadata_composed = false;
    if (!run_compose_candidate_metadata(
            candidate_workspace, &task, workspace, &metadata_composed)) {
        run_fail(reply, "DEPENDENCY_COMPOSITION_REFUSED", "compose",
                 "the exact task dependency lock could not be reflected in the isolated candidate metadata",
                 false, created);
        free(goal); vcs_zcode_agent_context_free(&context);
        vcs_zcode_task_index_free(index); return;
    }
    char prior_packet_path[ZWORK_RUN_PATH_MAX] = {0};
    char *prior_packet = NULL;
    size_t prior_packet_len = 0;
    int prior_packet_status = repairing && !created
        ? run_read_packet(candidate_workspace, &prior_packet,
                          &prior_packet_len)
        : 0;
    if (run_packet_path(candidate_workspace, prior_packet_path))
        run_adapter_cleanup(candidate_workspace, prior_packet_path);
    if (prior_packet_status < 0) {
        run_fail(reply, "REPAIR_CONTEXT_REFUSED", "context",
                 "the bounded repair handoff was not a private regular packet",
                 true, false);
        free(prior_packet); free(goal);
        vcs_zcode_agent_context_free(&context);
        vcs_zcode_task_index_free(index); return;
    }
    if (!created) {
        uint8_t candidate_root[32];
        if (vcs_tree_capture_into(candidate_workspace, workspace,
                                  candidate_root) != VCS_OK) {
            run_fail(reply, "CANDIDATE_CAPTURE_FAILED", "capture",
                     "candidate workspace changed or contains a refused file",
                     true, false);
            free(prior_packet); free(goal);
            vcs_zcode_agent_context_free(&context);
            vcs_zcode_task_index_free(index); return;
        }
        if (memcmp(candidate_root, materialize_root, 32) != 0 &&
            run_candidate_has_behavior_change(
                workspace, materialize_root, candidate_root)) {
            bool handled = run_admit(
                workspace, candidate_workspace, proof_datadir, goal,
                entry, context_entry,
                &task, &context, &scope, candidate_sequence, "manual",
                details, reply);
            if (handled) run_feedback_timing(reply, feedback_started_us);
            if (!handled)
                run_fail(reply, "CANDIDATE_ADMISSION_FAILED", "admit",
                         "scratch identity or existing task composition failed",
                         true, false);
            free(prior_packet); free(goal);
            vcs_zcode_agent_context_free(&context);
            vcs_zcode_task_index_free(index); return;
        }
    }
    struct json_value packet;
    json_init(&packet);
    char packet_detail[256];
    char work_id[32];
    (void)snprintf(work_id, sizeof(work_id), "work-%.12s",
                   entry->task_root_hex);
    bool packet_ok = false;
    if (prior_packet) {
        packet_ok = json_read(&packet, prior_packet, prior_packet_len) &&
            run_repair_packet_valid(&packet, goal, candidate_sequence);
        if (!packet_ok)
            (void)snprintf(packet_detail, sizeof(packet_detail),
                           "the bounded repair packet did not match the current goal and diagnostic");
    } else {
        packet_ok = run_packet(
            &packet, goal, workspace, proof_datadir, &task, &context, &scope,
            packet_detail);
    }
    free(prior_packet);
    if (!packet_ok) {
        run_fail(reply, "MODEL_CONTEXT_REFUSED", "context",
                 packet_detail[0] ? packet_detail
                                  : "the bounded model context could not be rendered",
                 true, created);
        json_free(&packet); free(goal);
        vcs_zcode_agent_context_free(&context);
        vcs_zcode_task_index_free(index); return;
    }
    size_t model_context_bytes = json_write(&packet, NULL, 0);
    if (packet_ok && codex_adapter) {
        char packet_path[ZWORK_RUN_PATH_MAX] = {0};
        char *adapter_output = zcl_malloc(ZWORK_ADAPTER_OUTPUT_MAX,
                                          "zcode.work.adapter.output");
        bool staged = adapter_output && run_write_packet(
            candidate_workspace, &packet, packet_path);
        const char *const argv[] = {
            codex_runner, candidate_workspace, packet_path, NULL,
        };
        int rc = staged ? zcl_spawn_capture(
            argv, adapter_output, ZWORK_ADAPTER_OUTPUT_MAX, 300000) : -1;
        run_adapter_cleanup(candidate_workspace, packet_path);
        if (!staged || rc != 0) {
            char detail[384];
            const char *kind = rc == 137 ? "timed out" :
                               rc == 69 || rc == 127 ? "is unavailable" :
                               "refused or failed";
            const char *output_tail = adapter_output ? adapter_output : "";
            size_t output_len = strlen(output_tail);
            if (output_len > 220u) output_tail += output_len - 220u;
            (void)snprintf(detail, sizeof(detail),
                           "confined Codex adapter %s (exit=%d)%s%.220s",
                           kind, rc,
                           adapter_output && adapter_output[0] ? ": " : "",
                           output_tail);
            run_fail(reply, rc == 137 ? "ADAPTER_TIMEOUT" :
                       rc == 69 || rc == 127 ? "ADAPTER_UNAVAILABLE" :
                                              "ADAPTER_REFUSAL",
                     "adapter", detail, rc != 70, staged);
            free(adapter_output); json_free(&packet); free(goal);
            vcs_zcode_agent_context_free(&context);
            vcs_zcode_task_index_free(index); return;
        }
        uint8_t candidate_root[32];
        bool captured = vcs_tree_capture_into(candidate_workspace, workspace,
                                              candidate_root) == VCS_OK;
        if (!captured || memcmp(candidate_root, materialize_root, 32) == 0 ||
            !run_candidate_has_behavior_change(
                workspace, materialize_root, candidate_root)) {
            run_fail(reply, captured ? "ADAPTER_REFUSAL" :
                                      "CANDIDATE_CAPTURE_FAILED",
                     captured ? "adapter" : "capture",
                     captured ? "Codex completed without an admissible behavior change beyond dependency composition"
                              : "Codex output could not be captured safely",
                     true, true);
            free(adapter_output); json_free(&packet); free(goal);
            vcs_zcode_agent_context_free(&context);
            vcs_zcode_task_index_free(index); return;
        }
        bool handled = run_admit(
            workspace, candidate_workspace, proof_datadir, goal,
            entry, context_entry,
            &task, &context, &scope, candidate_sequence, "codex", details,
            reply);
        if (handled) run_feedback_timing(reply, feedback_started_us);
        if (handled && reply->status == ZCL_COMMAND_STATUS_PASSED)
            (void)json_push_kv_int(&reply->data, "model_context_bytes",
                                   (int64_t)model_context_bytes);
        if (handled && reply->status == ZCL_COMMAND_STATUS_PASSED)
            (void)json_push_kv_bool(
                &reply->data, "candidate_dependency_metadata_changed",
                metadata_composed);
        if (details && handled && reply->status == ZCL_COMMAND_STATUS_PASSED)
            (void)json_push_kv_str(&reply->data, "adapter_output",
                                   adapter_output);
        if (!handled)
            run_fail(reply, "CANDIDATE_ADMISSION_FAILED", "admit",
                     "confined Codex result could not enter existing candidate authority",
                     true, true);
        free(adapter_output); json_free(&packet); free(goal);
        vcs_zcode_agent_context_free(&context);
        vcs_zcode_task_index_free(index); return;
    }
    char manual_packet_path[ZWORK_RUN_PATH_MAX] = {0};
    bool manual_staged = packet_ok && model_context_bytes > 0 &&
        run_write_packet(candidate_workspace, &packet, manual_packet_path);
    bool ok = manual_staged &&
        json_push_kv_str(&reply->data, "work_id", work_id) &&
        json_push_kv_str(&reply->data, "state", repairing
                         ? "REPAIR_NEEDED" : "AWAITING_CANDIDATE") &&
        json_push_kv_str(&reply->data, "stage", "Creating missing code") &&
        json_push_kv_str(&reply->data, "candidate_workspace",
                         candidate_workspace) &&
        json_push_kv_str(&reply->data, "adapter_packet_path",
                         manual_packet_path) &&
        json_push_kv_int(&reply->data, "model_context_bytes",
                         (int64_t)model_context_bytes) &&
        json_push_kv_bool(&reply->data,
                          "candidate_dependency_metadata_changed",
                          metadata_composed) &&
        json_push_kv_str(&reply->data, "authority", "NONE_MANUAL_HANDOFF") &&
        json_push_kv_bool(&reply->data, "details_available", true) &&
        run_add_work_next(
            reply, "zcode.work.status", workspace, work_id, NULL,
            "after editing the candidate workspace, show its exact next action");
    json_free(&packet); free(goal); vcs_zcode_agent_context_free(&context);
    vcs_zcode_task_index_free(index);
    if (!ok)
        run_fail(reply, "HANDOFF_OUTPUT_FAILED", "render",
                 "bounded manual adapter packet could not be rendered",
                 false, created);
}
