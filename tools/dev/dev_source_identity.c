/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Capture and verify the canonical current source epoch for dev tools. */

#include "devloop.h"

#include "codeindex/codeindex_merkle.h"
#include "base/hex.h"
#include "crypto/sha256.h"
#include "crypto/sha3.h"
#include "platform/time_compat.h"
#include "util/safe_alloc.h"

#include <ctype.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if !defined(_WIN32)
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#endif

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

static bool process_ok(const struct zcl_devloop_process_result *result)
{
    return result && !result->timed_out && result->term_signal == 0 &&
           result->exit_code == 0;
}

bool zcl_dev_source_identity_classify_failure(
    const struct zcl_devloop_process_result *result, char *why,
    size_t why_len)
{
    if (!why || why_len == 0)
        return false;
    if (!result) {
        (void)snprintf(why, why_len, "source_identity_command_failed");
        return true;
    }
    if (result->timed_out) {
        (void)snprintf(why, why_len, "source_identity_timeout");
        return true;
    }
    if (result->term_signal != 0) {
        (void)snprintf(why, why_len, "source_identity_signal_%d",
                       result->term_signal);
        return true;
    }
    if (result->exit_code == ZCL_DEVLOOP_PROCESS_EXIT_SETUP_FAILED) {
        /* The runner itself failed before exec (setsid, ready-pipe write,
         * chdir, dup2) — not the capture command. Distinct from an ordinary
         * nonzero exit so it can be retried; see
         * zcl_dev_source_identity_failure_retryable(). */
        (void)snprintf(why, why_len, "source_identity_runner_setup_failed");
        return true;
    }
    if (result->exit_code != 0) {
        (void)snprintf(why, why_len, "source_identity_exit_%d",
                       result->exit_code);
        return true;
    }
    if (result->output_truncated) {
        (void)snprintf(why, why_len, "source_identity_output_truncated");
        return true;
    }
    (void)snprintf(why, why_len, "source_identity_command_failed");
    return true;
}

bool zcl_dev_source_identity_failure_retryable(const char *why)
{
    if (!why)
        return false;
    /* Retry only conditions load can plausibly cause: the capture ran too
     * long, was interrupted by a signal, its output was cut short, or the
     * runner itself failed to get the command started (setsid, ready-pipe
     * write, chdir, dup2 — see ZCL_DEVLOOP_PROCESS_EXIT_SETUP_FAILED). A
     * nonzero exit from the command itself, or an invalid/malformed record,
     * is a deterministic tool or content defect that a retry cannot fix. */
    return strncmp(why, "source_identity_timeout", 23) == 0 ||
           strncmp(why, "source_identity_signal_", 23) == 0 ||
           strncmp(why, "source_identity_output_truncated", 33) == 0 ||
           strncmp(why, "source_identity_runner_setup_failed", 36) == 0;
}

static bool lower_hex64(const char *input, char out[65])
{
    if (!input || strlen(input) != 64)
        return false;
    for (size_t i = 0; i < 64; i++) {
        if (!isxdigit((unsigned char)input[i]))
            return false;
        out[i] = (char)tolower((unsigned char)input[i]);
    }
    out[64] = '\0';
    return true;
}

static void source_cas_record_digest(const char *domain,
                                     const char cas_root_sha3[65],
                                     char out[65])
{
    struct sha256_ctx sha;
    unsigned char digest[SHA256_OUTPUT_SIZE];
    sha256_init(&sha);
    sha256_write(&sha, (const unsigned char *)domain, strlen(domain) + 1);
    sha256_write(&sha, (const unsigned char *)cas_root_sha3, 64);
    sha256_finalize(&sha, digest);
    zcl_hex_encode(digest, sizeof(digest), out);
}

static bool parse_source_record(const struct zcl_devloop_process_result *result,
                                struct dev_source_record *out,
                                char *why, size_t why_len)
{
    if (!out)
        return false;
    memset(out, 0, sizeof(*out));
    if (!result || !process_ok(result) || result->output_truncated) {
        (void)zcl_dev_source_identity_classify_failure(result, why, why_len);
        return false;
    }
    size_t len = result->output_len;
    while (len > 0 && (result->output[len - 1] == '\n' ||
                       result->output[len - 1] == '\r'))
        len--;
    if (len == 0 || len >= 160 || memchr(result->output, '\0', len)) {
        (void)snprintf(why, why_len, "source_identity_output_invalid");
        return false;
    }
    char body[160], source[65], complete[8], mutation[65], extra[2];
    memcpy(body, result->output, len);
    body[len] = '\0';
    int fields = sscanf(body, "%64s %7s %64s %1s", source, complete,
                        mutation, extra);
    if (fields != 3 || strcmp(complete, "1") != 0 ||
        !lower_hex64(source, out->source_id) ||
        !lower_hex64(mutation, out->mutation_id)) {
        (void)snprintf(why, why_len, "source_identity_output_invalid");
        return false;
    }
    return true;
}

bool zcl_dev_executable_source_record_read(
    const char *repo_root, int executable_fd, const char *display_path,
    struct dev_source_record *out, char *why, size_t why_len)
{
    if (!repo_root || executable_fd < 0 || !display_path || !out || !why ||
        why_len == 0) {
        if (why && why_len > 0)
            (void)snprintf(why, why_len, "source_record_input_invalid");
        return false;
    }
    struct zcl_devloop_process_result result = {0};
    const char *argv[] = {display_path, "--source-record", NULL};
    if (!zcl_devloop_process_run_fd(repo_root, executable_fd, argv, 5000,
                                    &result)) {
        (void)snprintf(why, why_len, "source_record_execution_failed");
        return false;
    }
    return parse_source_record(&result, out, why, why_len);
}

bool zcl_dev_source_cas_capture(const char *repo_root,
                                struct dev_source_record *out)
{
    if (!repo_root || !repo_root[0] || !out)
        return false;
    int64_t started_us = platform_time_monotonic_us();
    struct ci_merkle_cost cost = {0};
    struct ci_merkle *tree = ci_merkle_refresh_reconciled(repo_root, &cost);
    if (!tree) {
        out->cas_elapsed_us = platform_time_monotonic_us() - started_us;
        return false;
    }
    struct ci_merkle_node root = {0};
    bool ok = ci_merkle_root(tree, &root);
    if (ok) {
        ci_merkle_hex(&root.digest, out->cas_root_sha3);
        /* Resident candidates are not publication artifacts, but their
         * generated clientversion object still needs one exact, inspectable
         * identity for the source epoch it proves. Derive two SHA-256 values
         * from the already-captured native CAS root: no second tree walk and
         * no shell oracle in the save path. The distinct domains prevent the
         * content identity and exact-revert token from being interchangeable. */
        if (!out->source_id[0])
            source_cas_record_digest("zcl.dev_source_cas_identity.v1",
                                     out->cas_root_sha3, out->source_id);
        if (!out->mutation_id[0])
            source_cas_record_digest("zcl.dev_source_cas_mutation.v1",
                                     out->cas_root_sha3, out->mutation_id);
        out->cas_files_total = cost.files_total;
        out->cas_files_read = cost.files_read;
        out->cas_nodes_hashed = cost.nodes_hashed;
        out->cas_bytes_total = cost.bytes_total;
        out->cas_bytes_read = cost.bytes_read;
        out->cas_present = true;
    }
    ci_merkle_free(tree);
    out->cas_elapsed_us = platform_time_monotonic_us() - started_us;
    return ok;
}

/* One capture-record attempt at a given timeout. Isolated from the retry
 * loop so each attempt gets a fresh process result and a growing budget. */
static bool source_identity_capture_attempt(const char *repo_root,
                                            const char *tool, int timeout_ms,
                                            struct dev_source_record *out,
                                            char *why, size_t why_len)
{
    struct zcl_devloop_process_result result = {0};
    const char *argv[] = { tool, "capture-record", NULL };
    if (!zcl_devloop_process_run(repo_root, argv, timeout_ms, &result)) {
        (void)snprintf(why, why_len, "source_identity_capture_failed");
        return false;
    }
    if (parse_source_record(&result, out, why, why_len)) {
        char authoritative_source[sizeof(out->source_id)];
        char authoritative_mutation[sizeof(out->mutation_id)];
        memcpy(authoritative_source, out->source_id,
               sizeof(authoritative_source));
        memcpy(authoritative_mutation, out->mutation_id,
               sizeof(authoritative_mutation));
        /* Shadow rollout: the shell SHA-256 record remains the exact build and
         * publication oracle. The native persistent SHA3 tree is attached as
         * independently observable CAS identity and may be compared/audited
         * without being allowed to green-light an artifact. Restore the
         * already-validated portable record after the shadow refresh so an
         * implementation defect or future CAS-only derivation can never
         * substitute the shadow identity for publication authority. */
        (void)zcl_dev_source_cas_capture(repo_root, out);
        memcpy(out->source_id, authoritative_source,
               sizeof(out->source_id));
        memcpy(out->mutation_id, authoritative_mutation,
               sizeof(out->mutation_id));
        return true;
    }
    /* Only fold in raw tool output when the failure is a content-level
     * defect (source_identity_output_invalid): the command itself completed,
     * so its stdout is a useful diagnostic. A timeout/signal/exit/truncation
     * token already names exactly what happened and must not be overwritten
     * by whatever partial bytes a killed child managed to emit. */
    if (process_ok(&result) && result.output_len > 0 && why && why_len > 0) {
        size_t copy = result.output_len < why_len - 1 ? result.output_len
                                                       : why_len - 1;
        memcpy(why, result.output, copy);
        why[copy] = '\0';
    }
    return false;
}

bool zcl_dev_source_identity_capture(const char *repo_root,
                                     struct dev_source_record *out,
                                     char *why, size_t why_len)
{
    char tool[PATH_MAX];
    int n = snprintf(tool, sizeof(tool), "%s/tools/dev/source-identity.sh",
                     repo_root ? repo_root : "");
    if (n <= 0 || (size_t)n >= sizeof(tool)) {
        (void)snprintf(why, why_len, "source_identity_tool_path_invalid");
        return false;
    }
    /* A whole-tree hash can legitimately take longer than 30s once host load
     * climbs; a single fixed budget turned a slow box into a discarded proof
     * every time. Retry a bounded number of times with a growing timeout
     * before giving up, but only for failures a retry can plausibly fix. */
    static const int timeouts_ms[] = { 30000, 90000, 180000 };
    for (size_t attempt = 0; attempt < sizeof(timeouts_ms) /
                                            sizeof(timeouts_ms[0]);
         attempt++) {
        if (source_identity_capture_attempt(repo_root, tool,
                                            timeouts_ms[attempt], out, why,
                                            why_len))
            return true;
        if (attempt + 1 == sizeof(timeouts_ms) / sizeof(timeouts_ms[0]) ||
            !zcl_dev_source_identity_failure_retryable(why))
            return false;
    }
    return false;
}

bool zcl_dev_source_identity_verify(const char *repo_root,
                                    const struct dev_source_record *expected,
                                    char *why, size_t why_len)
{
    if (!expected) {
        (void)snprintf(why, why_len, "source_identity_expected_missing");
        return false;
    }
    char tool[PATH_MAX];
    int n = snprintf(tool, sizeof(tool), "%s/tools/dev/source-identity.sh",
                     repo_root ? repo_root : "");
    if (n <= 0 || (size_t)n >= sizeof(tool)) {
        (void)snprintf(why, why_len, "source_identity_tool_path_invalid");
        return false;
    }
    struct zcl_devloop_process_result result = {0};
    const char *argv[] = { tool, "verify-record", expected->source_id, "1",
                           expected->mutation_id, NULL };
    if (!zcl_devloop_process_run(repo_root, argv, 30000, &result) ||
        !process_ok(&result)) {
        (void)snprintf(why, why_len, "source_epoch_superseded");
        return false;
    }
    struct dev_source_record actual;
    return parse_source_record(&result, &actual, why, why_len) &&
           strcmp(actual.source_id, expected->source_id) == 0 &&
           strcmp(actual.mutation_id, expected->mutation_id) == 0;
}

bool zcl_dev_source_mutation_verify(const char *repo_root,
                                    const struct dev_source_record *expected,
                                    char *why, size_t why_len)
{
    if (!expected) {
        (void)snprintf(why, why_len, "source_identity_expected_missing");
        return false;
    }
    char tool[PATH_MAX];
    int n = snprintf(tool, sizeof(tool), "%s/tools/dev/source-identity.sh",
                     repo_root ? repo_root : "");
    if (n <= 0 || (size_t)n >= sizeof(tool)) {
        (void)snprintf(why, why_len, "source_identity_tool_path_invalid");
        return false;
    }
    struct zcl_devloop_process_result result = {0};
    const char *argv[] = {tool, "verify-mutation", expected->mutation_id,
                          NULL};
    if (!zcl_devloop_process_run(repo_root, argv, 30000, &result) ||
        !process_ok(&result) || result.output_truncated) {
        (void)snprintf(why, why_len, "source_epoch_superseded");
        return false;
    }
    size_t len = result.output_len;
    while (len > 0 && (result.output[len - 1] == '\n' ||
                       result.output[len - 1] == '\r'))
        len--;
    if (len != 64) {
        (void)snprintf(why, why_len, "source_mutation_output_invalid");
        return false;
    }
    char raw[65], actual[65];
    memcpy(raw, result.output, 64);
    raw[64] = '\0';
    if (!lower_hex64(raw, actual) ||
        strcmp(actual, expected->mutation_id) != 0) {
        (void)snprintf(why, why_len, "source_epoch_superseded");
        return false;
    }
    return true;
}

enum zcl_dev_source_admission zcl_dev_executable_source_admit(
    const char *repo_root, int executable_fd, const char *display_path,
    struct dev_source_record *out, char *why, size_t why_len)
{
    if (!repo_root || executable_fd < 0 || !display_path || !out || !why ||
        why_len == 0) {
        if (why && why_len > 0)
            (void)snprintf(why, why_len, "source_admission_input_invalid");
        return ZCL_DEV_SOURCE_ADMISSION_ERROR;
    }
    struct zcl_devloop_process_result result = {0};
    const char *argv[] = {display_path, "--source-record", NULL};
    struct dev_source_record built = {0};
    if (!zcl_devloop_process_run_fd(repo_root, executable_fd, argv, 5000,
                                    &result)) {
        (void)snprintf(why, why_len, "runner_source_record_execution_failed");
        return ZCL_DEV_SOURCE_ADMISSION_ERROR;
    }
    if (!parse_source_record(&result, &built, why, why_len)) {
        (void)snprintf(why, why_len, "runner_source_record_invalid");
        return ZCL_DEV_SOURCE_ADMISSION_STALE;
    }

    if (zcl_dev_source_mutation_verify(repo_root, &built, why, why_len)) {
        (void)zcl_dev_source_cas_capture(repo_root, &built);
        *out = built;
        return ZCL_DEV_SOURCE_ADMISSION_BUILD_MUTATION;
    }

    /* A different mutation is not itself stale: edit/revert and copying an
     * exact checkout legitimately change inode/ctime metadata. Pay the full
     * byte hash only on this uncommon path, then carry its current mutation
     * into the post-proof CAS. */
    struct dev_source_record current = {0};
    if (!zcl_dev_source_identity_capture(repo_root, &current, why, why_len))
        return ZCL_DEV_SOURCE_ADMISSION_ERROR;
    if (strcmp(current.source_id, built.source_id) != 0) {
        (void)snprintf(why, why_len, "runner_source_identity_mismatch");
        return ZCL_DEV_SOURCE_ADMISSION_STALE;
    }
    *out = current;
    return ZCL_DEV_SOURCE_ADMISSION_FULL_BYTES;
}

const char *zcl_dev_source_admission_name(
    enum zcl_dev_source_admission admission)
{
    switch (admission) {
    case ZCL_DEV_SOURCE_ADMISSION_BUILD_MUTATION:
        return "build_mutation_receipt";
    case ZCL_DEV_SOURCE_ADMISSION_FULL_BYTES:
        return "full_byte_fallback";
    case ZCL_DEV_SOURCE_ADMISSION_STALE:
        return "stale";
    case ZCL_DEV_SOURCE_ADMISSION_ERROR:
    default:
        return "error";
    }
}

#define SOURCE_NS_MAX_ROOTS 128u
#if !defined(_WIN32)
#define SOURCE_NS_MAX_DEPTH 64u
#define SOURCE_NS_MAX_ENTRIES 200000u

struct source_ns_context {
    struct sha3_256_ctx root;
    struct sha3_256_ctx guard;
    struct { dev_t dev; ino_t ino; } parents[SOURCE_NS_MAX_DEPTH];
    size_t entries;
    char *why;
    size_t why_len;
};

static bool source_ns_fail(struct source_ns_context *ctx, const char *reason)
{
    if (ctx->why && ctx->why_len && !ctx->why[0])
        (void)snprintf(ctx->why, ctx->why_len, "%s", reason);
    return false;
}

static void source_ns_u64(struct sha3_256_ctx *sha, uint64_t value)
{
    uint8_t wire[8];
    for (size_t i = 0; i < sizeof(wire); i++) {
        wire[i] = (uint8_t)value;
        value >>= 8;
    }
    sha3_256_write(sha, wire, sizeof(wire));
}

static void source_ns_text(struct sha3_256_ctx *sha, const char *text)
{
    size_t len = strlen(text);
    source_ns_u64(sha, (uint64_t)len);
    sha3_256_write(sha, (const uint8_t *)text, len);
}

static long source_ns_mtime_ns(const struct stat *st)
{
#if defined(__APPLE__)
    return st->st_mtimespec.tv_nsec;
#else
    return st->st_mtim.tv_nsec;
#endif
}

static long source_ns_ctime_ns(const struct stat *st)
{
#if defined(__APPLE__)
    return st->st_ctimespec.tv_nsec;
#else
    return st->st_ctim.tv_nsec;
#endif
}

static bool source_ns_same_stat(const struct stat *a, const struct stat *b)
{
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino &&
           a->st_size == b->st_size && a->st_mtime == b->st_mtime &&
           a->st_ctime == b->st_ctime &&
           source_ns_mtime_ns(a) == source_ns_mtime_ns(b) &&
           source_ns_ctime_ns(a) == source_ns_ctime_ns(b);
}

static void source_ns_guard_dir(struct source_ns_context *ctx,
                                const char *rel, const struct stat *st)
{
    source_ns_text(&ctx->guard, rel);
    source_ns_u64(&ctx->guard, (uint64_t)st->st_dev);
    source_ns_u64(&ctx->guard, (uint64_t)st->st_ino);
    source_ns_u64(&ctx->guard, (uint64_t)st->st_size);
    source_ns_u64(&ctx->guard, (uint64_t)st->st_mtime);
    source_ns_u64(&ctx->guard, (uint64_t)source_ns_mtime_ns(st));
    source_ns_u64(&ctx->guard, (uint64_t)st->st_ctime);
    source_ns_u64(&ctx->guard, (uint64_t)source_ns_ctime_ns(st));
}

static void source_ns_names_free(char **names, size_t count)
{
    for (size_t i = 0; i < count; i++) free(names[i]);
    free(names);
}

static int source_ns_name_cmp(const void *a, const void *b)
{
    return strcmp(*(char *const *)a, *(char *const *)b);
}

static bool source_ns_names(int fd, char ***out, size_t *out_count,
                            struct source_ns_context *ctx)
{
    int read_fd = dup(fd);
    if (read_fd < 0) return source_ns_fail(ctx, "include_directory_dup_failed");
    DIR *dir = fdopendir(read_fd);
    if (!dir) {
        (void)close(read_fd);
        return source_ns_fail(ctx, "include_directory_open_failed");
    }
    char **names = NULL;
    size_t count = 0, cap = 0;
    bool ok = true;
    for (;;) {
        errno = 0;
        struct dirent *entry = readdir(dir);
        if (!entry) { ok = errno == 0; break; }
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0) continue;
        if (count == cap) {
            size_t next = cap ? cap * 2u : 32u;
            char **grown = zcl_realloc(names, next * sizeof(*names),
                                       "include namespace names");
            if (!grown) { ok = false; break; }
            names = grown;
            cap = next;
        }
        names[count] = zcl_strdup(entry->d_name, "include namespace name");
        if (!names[count]) { ok = false; break; }
        count++;
    }
    if (closedir(dir) != 0) ok = false;
    if (!ok) {
        source_ns_names_free(names, count);
        return source_ns_fail(ctx, "include_directory_read_failed");
    }
    qsort(names, count, sizeof(*names), source_ns_name_cmp);
    *out = names;
    *out_count = count;
    return true;
}

static bool source_ns_dir(int fd, const char *rel, size_t depth,
                          struct source_ns_context *ctx);

static bool source_ns_entry(int fd, const char *name, const char *rel,
                            size_t depth, struct source_ns_context *ctx)
{
    struct stat link, target;
    if (fstatat(fd, name, &link, AT_SYMLINK_NOFOLLOW) != 0)
        return source_ns_fail(ctx, "include_entry_stat_failed");
    bool symlink = S_ISLNK(link.st_mode);
    if (symlink) {
        char text[PATH_MAX];
        ssize_t len = readlinkat(fd, name, text, sizeof(text) - 1u);
        if (len <= 0 || len >= (ssize_t)sizeof(text) - 1)
            return source_ns_fail(ctx, "include_symlink_target_invalid");
        text[len] = '\0';
        source_ns_text(&ctx->root, "link");
        source_ns_text(&ctx->root, rel);
        source_ns_text(&ctx->root, text);
        if (fstatat(fd, name, &target, 0) != 0)
            return source_ns_fail(ctx, "include_symlink_dangling");
    } else {
        target = link;
    }
    if (S_ISREG(target.st_mode)) {
        source_ns_text(&ctx->root, "file");
        source_ns_text(&ctx->root, rel);
        return true;
    }
    if (!S_ISDIR(target.st_mode))
        return source_ns_fail(ctx, "include_entry_special_type");
    source_ns_text(&ctx->root, "directory");
    source_ns_text(&ctx->root, rel);
    int child = openat(fd, name, O_RDONLY | O_CLOEXEC | O_DIRECTORY |
                      (symlink ? 0 : O_NOFOLLOW));
    if (child < 0) return source_ns_fail(ctx, "include_directory_open_failed");
    struct stat opened;
    bool ok = fstat(child, &opened) == 0 &&
              source_ns_same_stat(&target, &opened) &&
              source_ns_dir(child, rel, depth + 1u, ctx);
    if (close(child) != 0) ok = false;
    return ok ? true : source_ns_fail(ctx, "include_directory_changed");
}

static bool source_ns_scan_entries(int fd, const char *rel, size_t depth,
                                   struct source_ns_context *ctx)
{
    char **names = NULL;
    size_t count = 0;
    if (!source_ns_names(fd, &names, &count, ctx)) return false;
    bool ok = true;
    for (size_t i = 0; i < count; i++) {
        char child_rel[PATH_MAX];
        int n = snprintf(child_rel, sizeof(child_rel), "%s/%s", rel, names[i]);
        if (n <= 0 || n >= (int)sizeof(child_rel) ||
            ++ctx->entries > SOURCE_NS_MAX_ENTRIES ||
            !source_ns_entry(fd, names[i], child_rel, depth, ctx)) {
            ok = false;
            break;
        }
    }
    source_ns_names_free(names, count);
    return ok;
}

static bool source_ns_dir(int fd, const char *rel, size_t depth,
                          struct source_ns_context *ctx)
{
    struct stat before, after;
    if (depth >= SOURCE_NS_MAX_DEPTH || fstat(fd, &before) != 0 ||
        !S_ISDIR(before.st_mode))
        return source_ns_fail(ctx, "include_directory_depth_or_stat");
    for (size_t i = 0; i < depth; i++)
        if (ctx->parents[i].dev == before.st_dev &&
            ctx->parents[i].ino == before.st_ino)
            return source_ns_fail(ctx, "include_directory_cycle");
    ctx->parents[depth].dev = before.st_dev;
    ctx->parents[depth].ino = before.st_ino;
    bool ok = source_ns_scan_entries(fd, rel, depth, ctx);
    if (fstat(fd, &after) != 0 || !source_ns_same_stat(&before, &after))
        ok = false;
    if (ok) source_ns_guard_dir(ctx, rel, &after);
    return ok ? true : source_ns_fail(ctx, "include_directory_changed");
}

static bool source_ns_root(const char *cwd, const char *path, size_t index,
                           struct source_ns_context *ctx)
{
    char physical[PATH_MAX], rel[32];
    int n = path[0] == '/' ? snprintf(physical, sizeof(physical), "%s", path)
                           : snprintf(physical, sizeof(physical), "%s/%s",
                                      cwd, path);
    if (n <= 0 || n >= (int)sizeof(physical))
        return source_ns_fail(ctx, "include_root_path_too_long");
    (void)snprintf(rel, sizeof(rel), "root-%zu", index);
    source_ns_text(&ctx->root, rel);
    struct stat before, after;
    if (lstat(physical, &before) != 0) {
        if (errno != ENOENT)
            return source_ns_fail(ctx, "include_root_stat_failed");
        source_ns_text(&ctx->root, "missing");
        return true;
    }
    int fd = open(physical, O_RDONLY | O_CLOEXEC | O_DIRECTORY);
    if (fd < 0 || fstat(fd, &after) != 0 || !S_ISDIR(after.st_mode)) {
        if (fd >= 0) (void)close(fd);
        return source_ns_fail(ctx, "include_root_not_directory");
    }
    source_ns_text(&ctx->root, "present");
    bool ok = source_ns_dir(fd, rel, 0, ctx);
    struct stat final;
    if (fstat(fd, &final) != 0 || !source_ns_same_stat(&after, &final))
        ok = false;
    if (close(fd) != 0) ok = false;
    return ok ? true : source_ns_fail(ctx, "include_root_changed");
}

static bool source_ns_once(const char *cwd, const char *const roots[],
                           size_t count, uint8_t root[32], uint8_t guard[32],
                           char *why, size_t why_len)
{
    struct source_ns_context ctx = {.why = why, .why_len = why_len};
    static const char domain[] = "zcl.dev_include_namespace.v1";
    sha3_256_init(&ctx.root);
    sha3_256_init(&ctx.guard);
    sha3_256_write(&ctx.root, (const uint8_t *)domain, sizeof(domain));
    source_ns_u64(&ctx.root, count);
    for (size_t i = 0; i < count; i++) {
        if (!roots[i] || !roots[i][0])
            return source_ns_fail(&ctx, "include_search_root_incomplete");
        if (!source_ns_root(cwd, roots[i], i, &ctx)) return false;
    }
    sha3_256_finalize(&ctx.root, root);
    sha3_256_finalize(&ctx.guard, guard);
    return true;
}
#endif

static bool source_ns_args_valid(const char *cwd, const char *const roots[],
                                 size_t count, const uint8_t out[32])
{
    return cwd && cwd[0] == '/' && roots && count > 0 &&
           count <= SOURCE_NS_MAX_ROOTS && out;
}

bool zcl_dev_include_namespace_v1_root(
    const char *cwd, const char *const roots[], size_t count,
    uint8_t out[32], char *why, size_t why_len)
{
    if (why && why_len) why[0] = '\0';
    if (!source_ns_args_valid(cwd, roots, count, out)) {
        if (why && why_len)
            (void)snprintf(why, why_len, "include_search_roots_invalid");
        return false;
    }
#if defined(_WIN32)
    if (why && why_len)
        (void)snprintf(why, why_len, "include_namespace_unavailable");
    return false;
#else
    uint8_t first[32], second[32], guard_before[32], guard_after[32];
    if (!source_ns_once(cwd, roots, count, first, guard_before, why, why_len) ||
        !source_ns_once(cwd, roots, count, second, guard_after, why, why_len))
        return false;
    if (memcmp(first, second, 32) != 0 ||
        memcmp(guard_before, guard_after, 32) != 0) {
        if (why && why_len)
            (void)snprintf(why, why_len, "include_namespace_changed");
        return false;
    }
    memcpy(out, first, 32);
    return true;
#endif
}
