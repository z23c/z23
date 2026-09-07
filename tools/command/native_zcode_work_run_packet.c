/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: the ephemeral adapter packet for the native `zcode work run`
 * command — composing the bounded model context, staging it privately,
 * reading a prior repair packet back, and removing the ephemeral adapter
 * files — split out of native_zcode_work_run_command.c so each function
 * stays under the cyclomatic-complexity cap; sibling declarations live in
 * native_zcode_work_run_priv.h. */

#include "command/native_command.h"
#include "native_zcode_work_run_priv.h"

#include "base/hex.h"
#include "base/log_macros.h"
#include "json/json.h"
#include "platform/directory_transaction.h"
#include "platform/file_metadata.h"
#include "platform/positioned_file.h"
#include "util/file_tree_ops.h"
#include "util/safe_alloc.h"
#include "vcs/zcode_agent_context.h"
#include "vcs/zcode_dev.h"
#include "vcs/zcode_write_scope.h"

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

bool run_stable_read(const char *path, void *bytes, size_t cap,
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

bool run_packet_path(const char *candidate_workspace,
                     char path[ZWORK_RUN_PATH_MAX])
{
    int n = snprintf(path, ZWORK_RUN_PATH_MAX,
                     "%s/.zcode-adapter-packet.json", candidate_workspace);
    return n > 0 && (size_t)n < ZWORK_RUN_PATH_MAX;
}

/* The packet is serialized once into a private heap buffer so the staging
 * step below writes exactly the bytes the caller composed. */
static char *run_packet_wire(const struct json_value *packet, size_t *len_out)
{
    size_t len = json_write(packet, NULL, 0);
    if (len == 0 || len > ZWORK_ADAPTER_PACKET_MAX)
        return NULL;
    char *wire = zcl_malloc(len + 1u, "zcode.work.adapter.packet");
    if (!wire || json_write(packet, wire, len + 1u) != len) {
        free(wire);
        return NULL;
    }
    *len_out = len;
    return wire;
}

#if defined(_WIN32)
static bool run_packet_stage_windows(const char *candidate_workspace,
                                     const char *wire, size_t len)
{
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
    return ok;
}
#else
static bool run_packet_stage_posix(const char *path, const char *wire,
                                   size_t len)
{
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
    return ok;
}
#endif

bool run_write_packet(const char *candidate_workspace,
                      const struct json_value *packet,
                      char path[ZWORK_RUN_PATH_MAX])
{
    size_t len = 0;
    char *wire = run_packet_wire(packet, &len);
    if (!wire)
        return false;
    if (!run_packet_path(candidate_workspace, path)) {
        free(wire);
        return false;
    }
#if defined(_WIN32)
    bool ok = run_packet_stage_windows(candidate_workspace, wire, len);
#else
    bool ok = run_packet_stage_posix(path, wire, len);
#endif
    free(wire);
    return ok;
}

#if defined(_WIN32)
static int run_read_packet_windows(const char *path, char **wire_out,
                                   size_t *len_out)
{
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
}
#else
/* A readable packet must be a private regular file owned by this user and
 * inside the packet budget; anything else is refused rather than parsed. */
static bool run_packet_stat_private(const struct stat *st)
{
    return S_ISREG(st->st_mode) && st->st_uid == geteuid() &&
        (st->st_mode & 077u) == 0 && st->st_size > 0 &&
        (uint64_t)st->st_size <= ZWORK_ADAPTER_PACKET_MAX;
}

/* The opened descriptor must still name the exact file lstat admitted, so a
 * swap between the two calls cannot smuggle other bytes in. */
static bool run_packet_reopened_same(const struct stat *opened,
                                     const struct stat *before)
{
    return opened->st_dev == before->st_dev &&
        opened->st_ino == before->st_ino &&
        opened->st_size == before->st_size && S_ISREG(opened->st_mode) &&
        opened->st_uid == geteuid() && (opened->st_mode & 077u) == 0;
}

static bool run_packet_read_all(int fd, char *wire, size_t len)
{
    size_t off = 0;
    while (off < len) {
        ssize_t got = read(fd, wire + off, len - off);
        if (got < 0 && errno == EINTR) continue;
        if (got <= 0) return false;
        off += (size_t)got;
    }
    return true;
}

static int run_read_packet_posix(const char *path, char **wire_out,
                                 size_t *len_out)
{
    struct stat before;
    if (lstat(path, &before) != 0)
        return errno == ENOENT ? 0 : -1;
    if (!run_packet_stat_private(&before))
        return -1;
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    struct stat opened;
    bool ok = fd >= 0 && fstat(fd, &opened) == 0 &&
        run_packet_reopened_same(&opened, &before);
    size_t len = 0;
    char *wire = NULL;
    if (ok) {
        len = (size_t)opened.st_size;
        wire = zcl_malloc(len + 1u, "zcode.work.repair.packet");
        ok = wire != NULL && run_packet_read_all(fd, wire, len);
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
}
#endif

/* The packet is an ephemeral proposal aid, never a task/candidate/receipt
 * authority.  Reading it before candidate capture lets a later adapter turn
 * retain bounded compiler feedback while the canonical source and evidence
 * are still reloaded and verified independently. */
int run_read_packet(const char *candidate_workspace,
                    char **wire_out, size_t *len_out)
{
    *wire_out = NULL;
    *len_out = 0;
    char path[ZWORK_RUN_PATH_MAX];
    if (!run_packet_path(candidate_workspace, path)) return -1;
#if defined(_WIN32)
    return run_read_packet_windows(path, wire_out, len_out);
#else
    return run_read_packet_posix(path, wire_out, len_out);
#endif
}

static bool run_repair_diagnostic_stage(const struct json_value *diagnostic)
{
    return diagnostic && diagnostic->type == JSON_OBJ &&
        run_str(diagnostic, "stage") &&
        strcmp(run_str(diagnostic, "stage"),
               "package_build_and_tests") == 0;
}

static bool run_repair_diagnostic_attempt(const struct json_value *diagnostic,
                                          uint64_t candidate_sequence)
{
    const struct json_value *attempt = diagnostic
        ? json_get(diagnostic, "attempt") : NULL;
    const struct json_value *exit_status = diagnostic
        ? json_get(diagnostic, "exit_status") : NULL;
    return attempt && attempt->type == JSON_INT &&
        json_get_int(attempt) == (int64_t)candidate_sequence - 1 &&
        exit_status && exit_status->type == JSON_INT &&
        json_get_int(exit_status) != 0;
}

static bool run_repair_diagnostic_feedback(
    const struct json_value *diagnostic)
{
    const struct json_value *feedback = diagnostic
        ? json_get(diagnostic, "compiler_feedback") : NULL;
    return run_bool(diagnostic, "retry_safe") &&
        feedback && feedback->type == JSON_OBJ;
}

bool run_repair_packet_valid(const struct json_value *packet,
                             const char *goal,
                             uint64_t candidate_sequence)
{
    const struct json_value *diagnostic = packet && packet->type == JSON_OBJ
        ? json_get(packet, "diagnostic") : NULL;
    return goal && candidate_sequence > 1u &&
        run_str(packet, "goal") && strcmp(run_str(packet, "goal"), goal) == 0 &&
        run_repair_diagnostic_stage(diagnostic) &&
        run_repair_diagnostic_attempt(diagnostic, candidate_sequence) &&
        run_repair_diagnostic_feedback(diagnostic);
}

void run_adapter_cleanup(const char *candidate_workspace,
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

static bool run_packet_limits(struct json_value *limits,
                              const struct vcs_zcode_task_v1 *task)
{
    return json_push_kv_int(limits, "max_changed_files",
                            task->max_changed_files) &&
        json_push_kv_int(limits, "max_patch_bytes",
                         (int64_t)task->max_patch_bytes);
}

static bool run_packet_scopes(struct json_value *scopes,
                              const struct vcs_zcode_write_scope_v1 *scope)
{
    bool ok = true;
    for (size_t i = 0; ok && i < scope->count; i++) {
        struct json_value path;
        json_init(&path); json_set_str(&path, scope->paths[i]);
        ok = json_push_back(scopes, &path);
        json_free(&path);
    }
    return ok;
}

static bool run_packet_compose(
    struct json_value *packet, const char *goal,
    const struct vcs_zcode_agent_context_v1 *context,
    const struct json_value *excerpts, const struct json_value *locked,
    const struct json_value *dependencies, const struct json_value *scopes,
    const char *lock_hex, const struct json_value *limits)
{
    return json_push_kv_str(packet, "goal", goal) &&
        json_push_kv_str(packet, "context_query", context->query) &&
        json_push_kv(packet, "selected_excerpts", excerpts) &&
        json_push_kv(packet, "locked_dependencies", locked) &&
        json_push_kv(packet, "selected_dependency_context", dependencies) &&
        json_push_kv(packet, "allowed_write_scopes", scopes) &&
        json_push_kv_str(packet, "dependency_lock_root", lock_hex) &&
        json_push_kv(packet, "limits", limits) &&
        json_push_kv_str(packet, "instruction",
                         "Write C23 only. Reuse the selected APIs before creating code. Edit only allowed paths. Do not accept, publish, or claim proof.");
}

bool run_packet(struct json_value *packet, const char *goal,
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
    bool ok = run_packet_limits(&limits, task) &&
        run_packet_scopes(&scopes, scope);
    json_init(packet); json_set_object(packet);
    ok = ok && run_packet_compose(packet, goal, context, &excerpts, &locked,
                                  &dependencies, &scopes, lock_hex, &limits);
    json_free(&dependencies); json_free(&locked);
    json_free(&scopes); json_free(&limits); json_free(&excerpts);
    if (!ok)
        (void)snprintf(detail, 256,
                       "the bounded model context exceeded its JSON budget");
    return ok;
}
