/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: exact bounded daily C23 growth reconstructed from Git numstat. */
#include "science/code_growth.h"

#include "base/safe_alloc.h"
#include "base/serialize_le.h"
#include "platform/clock.h"
#include "platform/directory_compat.h"
#include "platform/directory_transaction.h"
#include "platform/private_directory.h"
#if defined(_WIN32)
#include "platform/process_lifecycle.h"
#endif
#include "platform/time_compat.h"
#include "science/science_corpus.h"
#include "sha3/sha3.h"
#include "util/spawn.h"

#include <ctype.h>
#include <inttypes.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static const char *const growth_roots[] = {
#define SOURCE_ROOT(name_) name_,
#include "codeindex/source_roots.def"
#undef SOURCE_ROOT
};

enum {
    GROWTH_ARGV_FIXED = 13u,
    GROWTH_ARGV_CAP = GROWTH_ARGV_FIXED +
        sizeof(growth_roots) / sizeof(growth_roots[0]) + 1u,
};

static const char growth_cache_magic[8] = {
    'Z', '2', '3', 'G', 'R', 'O', 'W', '1',
};

enum {
    GROWTH_CACHE_VERSION = 1u,
    GROWTH_CACHE_MAGIC = 0u,
    GROWTH_CACHE_VERSION_AT = 8u,
    GROWTH_CACHE_LENGTH = 12u,
    GROWTH_CACHE_HEAD = 16u,
    GROWTH_CACHE_ROOTS = 56u,
    GROWTH_CACHE_PAYLOAD = 88u,
    GROWTH_CACHE_HEADER_SIZE = 120u,
    GROWTH_PATH_MAX = 4096u,
};

static _Atomic uint64_t growth_cache_sequence = 1u;

static bool growth_error(char *error, size_t cap, const char *message)
{
    if (error && cap) (void)snprintf(error, cap, "%s", message);
    return false;
}

static bool growth_has_segment(const char *path, const char *segment)
{
    size_t n = strlen(segment);
    for (const char *p = path; (p = strstr(p, segment)) != NULL; p++) {
        bool left = p == path || p[-1] == '/';
        bool right = p[n] == '\0' || p[n] == '/';
        if (left && right) return true;
    }
    return false;
}

static bool growth_pruned(const char *path)
{
#define SOURCE_PRUNE_DIR(name_) if (growth_has_segment(path, name_)) return true;
#define SOURCE_INVENTORY_PRUNE_DIR(name_) \
    if (growth_has_segment(path, name_)) return true;
#include "codeindex/source_prune_dirs.def"
#undef SOURCE_INVENTORY_PRUNE_DIR
#undef SOURCE_PRUNE_DIR
    return growth_has_segment(path, "test-tmp");
}

static bool growth_source_path(const char *path)
{
    if (!path || !path[0] || growth_pruned(path)) return false;
    size_t n = strlen(path);
    if (n < 3u || path[n - 2u] != '.' ||
        (path[n - 1u] != 'c' && path[n - 1u] != 'h'))
        return false;
    for (size_t i = 0; i < sizeof(growth_roots) / sizeof(growth_roots[0]); i++) {
        size_t root_len = strlen(growth_roots[i]);
        if (strncmp(path, growth_roots[i], root_len) == 0 &&
            path[root_len] == '/')
            return true;
    }
    return false;
}

static bool growth_sha(const char *text)
{
    for (size_t i = 0; i < 40u; i++)
        if (!isxdigit((unsigned char)text[i])) return false;
    return text[40] == '\t';
}

static bool growth_head_text(const char *text, char out[41])
{
    if (!text) return false;
    for (size_t i = 0; i < 40u; i++)
        if (!isxdigit((unsigned char)text[i])) return false;
    if (text[40] != '\0' && text[40] != '\n' && text[40] != '\r')
        return false;
    memcpy(out, text, 40u);
    out[40] = '\0';
    return true;
}

static void growth_digest(const void *data, size_t size, uint8_t out[32])
{
    struct sha3_256_ctx digest;
    sha3_256_init(&digest);
    sha3_256_write(&digest, data, size);
    sha3_256_finalize(&digest, out);
}

static void growth_contract_digest(uint8_t out[32])
{
    static const char contract[] =
        "z23.code-growth.v1|first-parent|reverse|no-renames|"
        "diff-merges=first-parent|root|numstat|utc-day|c-h|"
        "test-path-v1:tests/harness,lib/test,package-test-segments,test_";
    struct sha3_256_ctx digest;
    sha3_256_init(&digest);
    sha3_256_write(&digest, (const unsigned char *)contract,
                   sizeof(contract));
    for (size_t i = 0; i < sizeof(growth_roots) / sizeof(growth_roots[0]); i++)
        sha3_256_write(&digest, (const unsigned char *)growth_roots[i],
                       strlen(growth_roots[i]) + 1u);
#define SOURCE_PRUNE_DIR(name_) do { \
    static const char kind_[] = "prune"; \
    sha3_256_write(&digest, (const unsigned char *)kind_, sizeof(kind_)); \
    sha3_256_write(&digest, (const unsigned char *)name_, sizeof(name_)); \
} while (0);
#define SOURCE_INVENTORY_PRUNE_DIR(name_) do { \
    static const char kind_[] = "inventory-prune"; \
    sha3_256_write(&digest, (const unsigned char *)kind_, sizeof(kind_)); \
    sha3_256_write(&digest, (const unsigned char *)name_, sizeof(name_)); \
} while (0);
#include "codeindex/source_prune_dirs.def"
#undef SOURCE_INVENTORY_PRUNE_DIR
#undef SOURCE_PRUNE_DIR
    sha3_256_finalize(&digest, out);
}

/* Windows intentionally has no generic package/agent spawn implementation.
 * These read-only developer measurements instead use one explicit host-tool
 * capability supplied by the Windows setup courier. */
static int growth_git_capture(const char *const argv[], char *out,
                              size_t out_size, uint32_t timeout_ms)
{
#if defined(_WIN32)
    const char *configured_image = getenv("ZCL_DEV_GIT_EXE");
    /* windows-setup's canonical root is C:\msys64. Custom roots are passed
     * explicitly by windows-make; neither route searches PATH or the CWD. */
    const char *image = configured_image && configured_image[0]
        ? configured_image : "C:\\msys64\\usr\\bin\\git.exe";
    bool absolute = image &&
        ((((image[0] >= 'A' && image[0] <= 'Z') ||
           (image[0] >= 'a' && image[0] <= 'z')) && image[1] == ':' &&
          (image[2] == '/' || image[2] == '\\')) ||
         ((image[0] == '/' || image[0] == '\\') &&
          (image[1] == '/' || image[1] == '\\')));
    if (!absolute || !argv || !argv[0] || strcmp(argv[0], "git") != 0 ||
        !out || out_size == 0 || timeout_ms == 0) {
        if (out && out_size) out[0] = '\0';
        return -1;
    }
    const char *native_argv[GROWTH_ARGV_CAP];
    size_t argc = 0;
    while (argv[argc] && argc + 1u < GROWTH_ARGV_CAP) {
        native_argv[argc] = argc == 0 ? image : argv[argc];
        argc++;
    }
    if (argv[argc]) {
        out[0] = '\0';
        return -1;
    }
    native_argv[argc] = NULL;
    static const char *const environment[] = {
        "GIT_CONFIG_NOSYSTEM=1", "GIT_OPTIONAL_LOCKS=0", "GIT_PAGER=",
        "GIT_TERMINAL_PROMPT=0", "LANG=C", "LC_ALL=C", NULL,
    };
    struct platform_process_options options = {
        .image = image, .argv = native_argv, .env = environment,
    };
    struct platform_process_capture_result result;
    if (!platform_process_capture_stdout(&options, out, out_size, timeout_ms,
                                         &result) || result.timed_out ||
        result.exit_code > INT_MAX)
        return -1;
    return (int)result.exit_code;
#else
    return zcl_spawn_capture(argv, out, out_size, (int)timeout_ms);
#endif
}

static bool growth_git_identity(const char *root, char head[41], bool *clean)
{
    char head_text[48];
    const char *head_argv[] = {
        "git", "-C", root, "rev-parse", "--verify", "HEAD", NULL,
    };
    if (growth_git_capture(head_argv, head_text, sizeof(head_text), 30000) != 0 ||
        !growth_head_text(head_text, head))
        return false;
    const char *status_argv[GROWTH_ARGV_CAP] = {
        "git", "-C", root, "status", "--porcelain=v1",
        "--untracked-files=all", "--", NULL,
    };
    size_t argc = 7u;
    for (size_t i = 0; i < sizeof(growth_roots) / sizeof(growth_roots[0]); i++)
        status_argv[argc++] = growth_roots[i];
    status_argv[argc] = NULL;
    char status[2];
    int rc = growth_git_capture(status_argv, status, sizeof(status), 30000);
    if (rc != 0) return false;
    *clean = status[0] == '\0';
    return true;
}

static bool growth_cache_directory(char out[GROWTH_PATH_MAX], const char *root,
                                   bool create)
{
    char parent[GROWTH_PATH_MAX];
    int n = snprintf(parent, sizeof(parent), "%s/.cache", root);
    if (n <= 0 || (size_t)n >= sizeof(parent)) return false;
    /* Never adopt or rewrite the legacy Windows directory created with an
     * inherited DACL. A new namespace lets the private-directory constructor
     * establish owner+SYSTEM authority before any cache bytes are trusted. */
    n = snprintf(out, GROWTH_PATH_MAX,
                 "%s/z23-code-growth-private-v1", parent);
    if (n <= 0 || n >= (int)GROWTH_PATH_MAX) return false;
    return !create || (platform_directory_ensure(parent, 0700) &&
                       platform_private_directory_ensure(out));
}

static void growth_cache_store(const char *root, const char head[41],
                               const char *stream, size_t length);

static bool growth_first_parent_contains(const char *root,
                                         const char ancestor[41],
                                         const char head[41])
{
    char *commits = zcl_malloc(SCIENCE_CODE_GROWTH_GIT_BYTES_MAX,
                               "science.code_growth.first_parent");
    if (!commits) return false;
    const char *argv[] = {
        "git", "-C", root, "rev-list", "--first-parent", head, NULL,
    };
    int rc = growth_git_capture(argv, commits,
                                SCIENCE_CODE_GROWTH_GIT_BYTES_MAX, 30000);
    bool found = false;
    if (rc == 0) {
        for (const char *line = commits; line && *line;) {
            const char *end = strchr(line, '\n');
            size_t length = end ? (size_t)(end - line) : strlen(line);
            if (length == 40u && memcmp(line, ancestor, 40u) == 0) {
                found = true;
                break;
            }
            line = end ? end + 1 : NULL;
        }
    }
    free(commits);
    return found;
}

static bool growth_append_delta(const char *root, const char cached_head[41],
                                const char head[41], char **stream,
                                size_t *length)
{
    char range[84];
    int n = snprintf(range, sizeof(range), "%s..%s", cached_head, head);
    if (n <= 0 || (size_t)n >= sizeof(range)) return false;
    char *delta = zcl_malloc(SCIENCE_CODE_GROWTH_GIT_BYTES_MAX,
                             "science.code_growth.delta");
    if (!delta) return false;
    const char *argv[GROWTH_ARGV_CAP] = {
        "git", "-C", root, "log", range, "--first-parent", "--reverse",
        "--no-renames", "--diff-merges=first-parent", "--root",
        "--format=@@%H%x09%ct", "--numstat", "--", NULL,
    };
    size_t argc = 13u;
    for (size_t i = 0; i < sizeof(growth_roots) / sizeof(growth_roots[0]); i++)
        argv[argc++] = growth_roots[i];
    argv[argc] = NULL;
    int rc = growth_git_capture(argv, delta,
                                SCIENCE_CODE_GROWTH_GIT_BYTES_MAX, 30000);
    size_t delta_length = strnlen(delta, SCIENCE_CODE_GROWTH_GIT_BYTES_MAX);
    bool ok = rc == 0 &&
        delta_length + 1u < SCIENCE_CODE_GROWTH_GIT_BYTES_MAX &&
        *length < SCIENCE_CODE_GROWTH_GIT_BYTES_MAX - delta_length - 1u;
    char *combined = ok ? zcl_realloc(
        *stream, *length + delta_length + 1u,
        "science.code_growth.combined") : NULL;
    if (combined) {
        memcpy(combined + *length, delta, delta_length + 1u);
        *stream = combined;
        *length += delta_length;
    } else {
        ok = false;
    }
    free(delta);
    return ok;
}

static bool growth_cache_load(const char *root, const char head[41],
                              struct science_code_growth_history *out,
                              char *error, size_t error_cap)
{
    char directory_path[GROWTH_PATH_MAX];
    struct platform_directory_transaction directory;
    struct platform_directory_child child;
    platform_directory_transaction_init(&directory);
    platform_directory_child_init(&child);
    if (!growth_cache_directory(directory_path, root, false) ||
        !platform_directory_transaction_open(&directory, directory_path) ||
        !platform_directory_child_open(&directory, "git-numstat.v1", &child)) {
        platform_directory_child_close(&child);
        platform_directory_transaction_close(&directory);
        return false;
    }
    uint8_t header[GROWTH_CACHE_HEADER_SIZE];
    struct platform_directory_child_info info;
    uint32_t stored_length = 0;
    bool valid = platform_directory_child_info(&child, &info) &&
        info.link_count == 1u && info.current_user_only &&
        platform_directory_child_read_exact(&child, header, sizeof(header), 0);
    if (valid)
        stored_length = zcl_read_u32_le(header + GROWTH_CACHE_LENGTH);
    size_t length = stored_length;
    uint8_t contract[32];
    growth_contract_digest(contract);
    valid = valid && memcmp(header + GROWTH_CACHE_MAGIC,
                            growth_cache_magic, sizeof(growth_cache_magic)) == 0 &&
        zcl_read_u32_le(header + GROWTH_CACHE_VERSION_AT) ==
            GROWTH_CACHE_VERSION &&
        length > 0u && length < SCIENCE_CODE_GROWTH_GIT_BYTES_MAX &&
        info.size == sizeof(header) + length &&
        memcmp(header + GROWTH_CACHE_ROOTS, contract, sizeof(contract)) == 0;
    char *stream = valid ? zcl_malloc((size_t)length + 1u,
                                      "science.code_growth.cache") : NULL;
    valid = valid && stream && platform_directory_child_read_exact(
        &child, stream, length, sizeof(header));
    platform_directory_child_close(&child);
    platform_directory_transaction_close(&directory);
    if (!valid) { free(stream); return false; }
    stream[length] = '\0';
    char cached_head[41];
    memcpy(cached_head, header + GROWTH_CACHE_HEAD, 40u);
    cached_head[40] = '\0';
    valid = growth_head_text(cached_head, cached_head);
    uint8_t payload[32];
    growth_digest(stream, length, payload);
    valid = valid && memcmp(header + GROWTH_CACHE_PAYLOAD, payload,
                            sizeof(payload)) == 0;
    bool extended = valid && strcmp(cached_head, head) != 0;
    if (extended)
        valid = growth_first_parent_contains(root, cached_head, head) &&
            growth_append_delta(root, cached_head, head, &stream, &length);
    valid = valid && science_code_growth_parse(
        stream, length, out, error, error_cap);
    if (valid && extended) growth_cache_store(root, head, stream, length);
    free(stream);
    if (valid) out->cache_hit = true;
    return valid;
}

static void growth_cache_store(const char *root, const char head[41],
                               const char *stream, size_t length)
{
    if (length == 0u || length >= SCIENCE_CODE_GROWTH_GIT_BYTES_MAX ||
        length > UINT32_MAX) return;
    char directory_path[GROWTH_PATH_MAX];
    struct platform_directory_transaction directory;
    struct platform_directory_child stage;
    platform_directory_transaction_init(&directory);
    platform_directory_child_init(&stage);
    if (!growth_cache_directory(directory_path, root, true) ||
        !platform_directory_transaction_open(&directory, directory_path))
        return;
    char leaf[96];
    bool created = false;
    for (unsigned attempt = 0; attempt < 32u && !created; attempt++) {
        uint64_t sequence = atomic_fetch_add_explicit(
            &growth_cache_sequence, 1u, memory_order_relaxed);
        int n = snprintf(leaf, sizeof(leaf), "git-numstat.v1.tmp.%" PRIx64
                         ".%" PRIx64,
                         (uint64_t)clock_now_monotonic_ns(), sequence);
        created = n > 0 && (size_t)n < sizeof(leaf) &&
            platform_directory_child_create(&directory, leaf, &stage);
    }
    uint8_t header[GROWTH_CACHE_HEADER_SIZE] = {0};
    memcpy(header + GROWTH_CACHE_MAGIC, growth_cache_magic,
           sizeof(growth_cache_magic));
    zcl_write_u32_le(header + GROWTH_CACHE_VERSION_AT, GROWTH_CACHE_VERSION);
    zcl_write_u32_le(header + GROWTH_CACHE_LENGTH, (uint32_t)length);
    memcpy(header + GROWTH_CACHE_HEAD, head, 40u);
    growth_contract_digest(header + GROWTH_CACHE_ROOTS);
    growth_digest(stream, length, header + GROWTH_CACHE_PAYLOAD);
    bool staged = created;
    bool ok = created && platform_directory_child_write_exact(
        &stage, header, sizeof(header), 0) &&
        platform_directory_child_write_exact(&stage, stream, length,
                                              sizeof(header)) &&
        platform_directory_child_truncate(&stage, sizeof(header) + length) &&
        platform_directory_child_flush(&stage);
    enum platform_directory_result published = PLATFORM_DIRECTORY_IO;
    if (ok) published = platform_directory_child_move_between(
        &directory, &stage, &directory, "git-numstat.v1", false);
    if (published == PLATFORM_DIRECTORY_OK ||
        published == PLATFORM_DIRECTORY_OUTCOME_UNKNOWN)
        staged = false;
    platform_directory_child_close(&stage);
    if (staged) (void)platform_directory_child_unlink(&directory, leaf, true);
    platform_directory_transaction_close(&directory);
}

static bool growth_u64(const char *begin, const char *end, uint64_t *out)
{
    if (!begin || begin == end || !out) return false;
    uint64_t value = 0;
    for (const char *p = begin; p < end; p++) {
        if (*p < '0' || *p > '9' ||
            value > (UINT64_MAX - (uint64_t)(*p - '0')) / 10u)
            return false;
        value = value * 10u + (uint64_t)(*p - '0');
    }
    *out = value;
    return true;
}

static bool growth_day_text(uint64_t epoch_day, char out[11])
{
    if (epoch_day > (uint64_t)INT64_MAX / 86400u) return false;
    time_t stamp = (time_t)(epoch_day * 86400u);
    struct tm utc;
    return platform_time_utc_tm(stamp, &utc) &&
        strftime(out, 11u, "%Y-%m-%d", &utc) == 10u;
}

static struct science_code_growth_day *growth_day(
    struct science_code_growth_history *history, uint64_t epoch_day,
    const char sha[40])
{
    for (size_t i = 0; i < history->day_count; i++) {
        if (history->days[i].epoch_day != epoch_day) continue;
        memcpy(history->days[i].head_commit, sha, 40u);
        history->days[i].head_commit[40] = '\0';
        history->days[i].commits++;
        return &history->days[i];
    }
    if (history->day_count >= SCIENCE_CODE_GROWTH_MAX_DAYS) return NULL;
    struct science_code_growth_day *day = &history->days[history->day_count++];
    if (!growth_day_text(epoch_day, day->date)) return NULL;
    memcpy(day->head_commit, sha, 40u);
    day->head_commit[40] = '\0';
    day->epoch_day = epoch_day;
    day->commits = 1u;
    return day;
}

static int growth_day_compare(const void *left, const void *right)
{
    const struct science_code_growth_day *a = left;
    const struct science_code_growth_day *b = right;
    return a->epoch_day < b->epoch_day ? -1 : a->epoch_day > b->epoch_day;
}

static bool growth_fill_inactive_days(
    struct science_code_growth_history *history)
{
    for (size_t i = 1; i < history->day_count; i++) {
        const uint64_t previous = history->days[i - 1u].epoch_day;
        const uint64_t current = history->days[i].epoch_day;
        if (current <= previous) return false;
        const uint64_t gap = current - previous - 1u;
        if (gap == 0) continue;
        if (gap > SCIENCE_CODE_GROWTH_MAX_DAYS - history->day_count)
            return false;
        char prior_commit[41];
        memcpy(prior_commit, history->days[i - 1u].head_commit,
               sizeof(prior_commit));
        memmove(&history->days[i + (size_t)gap], &history->days[i],
                (history->day_count - i) * sizeof(history->days[0]));
        for (size_t offset = 0; offset < (size_t)gap; offset++) {
            struct science_code_growth_day *day = &history->days[i + offset];
            memset(day, 0, sizeof(*day));
            day->epoch_day = previous + 1u + offset;
            if (!growth_day_text(day->epoch_day, day->date)) return false;
            memcpy(day->head_commit, prior_commit, sizeof(day->head_commit));
        }
        history->day_count += (size_t)gap;
        i += (size_t)gap;
    }
    return true;
}

bool science_code_growth_parse(const char *stream, size_t stream_len,
                               struct science_code_growth_history *out,
                               char *error, size_t error_cap)
{
    if (!stream || !out)
        return growth_error(error, error_cap,
                            "growth stream/output is missing");
    memset(out, 0, sizeof(*out));
    struct science_code_growth_day *current = NULL;
    const char *at = stream, *end = stream + stream_len;
    while (at < end) {
        const char *line_end = memchr(at, '\n', (size_t)(end - at));
        if (!line_end) line_end = end;
        if ((size_t)(line_end - at) >= 44u &&
            at[0] == '@' && at[1] == '@') {
            uint64_t seconds = 0;
            const char *timestamp = at + 43u;
            if (!growth_sha(at + 2u) || timestamp > line_end ||
                !growth_u64(timestamp, line_end, &seconds))
                return growth_error(error, error_cap,
                                    "Git history header is malformed");
            current = growth_day(out, seconds / 86400u, at + 2u);
            if (!current)
                return growth_error(
                    error, error_cap,
                    "daily history exceeds its bounded capacity");
        } else if (line_end > at && current) {
            const char *first = memchr(at, '\t', (size_t)(line_end - at));
            const char *second = first
                ? memchr(first + 1, '\t',
                         (size_t)(line_end - first - 1))
                : NULL;
            const char *path = second ? second + 1 : NULL;
            if (!first || !second)
                return growth_error(error, error_cap,
                                    "Git numstat row is malformed");
            char bounded_path[4096];
            size_t path_len = (size_t)(line_end - path);
            if (path_len >= sizeof(bounded_path))
                return growth_error(
                    error, error_cap,
                    "Git path exceeds the bounded path size");
            memcpy(bounded_path, path, path_len);
            bounded_path[path_len] = '\0';
            if (growth_source_path(bounded_path)) {
                uint64_t added = 0, deleted = 0;
                if (!growth_u64(at, first, &added) ||
                    !growth_u64(first + 1, second, &deleted))
                    return growth_error(
                        error, error_cap,
                        "maintained C23 numstat row is not textual");
                bool test_path = science_corpus_is_test_path(bounded_path);
                uint64_t *day_added = test_path
                    ? &current->test_added : &current->non_test_added;
                uint64_t *day_deleted = test_path
                    ? &current->test_deleted : &current->non_test_deleted;
                if (UINT64_MAX - *day_added < added ||
                    UINT64_MAX - *day_deleted < deleted)
                    return growth_error(error, error_cap,
                                        "daily line count overflowed");
                *day_added += added;
                *day_deleted += deleted;
            }
        }
        at = line_end < end ? line_end + 1 : end;
    }
    if (out->day_count == 0)
        return growth_error(error, error_cap,
                            "Git history contains no maintained C23 changes");
    qsort(out->days, out->day_count, sizeof(out->days[0]), growth_day_compare);
    if (!growth_fill_inactive_days(out))
        return growth_error(error, error_cap,
                            "daily history gaps exceed bounded capacity");
    uint64_t non_test = 0, test = 0;
    for (size_t i = 0; i < out->day_count; i++) {
        struct science_code_growth_day *day = &out->days[i];
        if (day->non_test_added > UINT64_MAX - non_test ||
            day->test_added > UINT64_MAX - test)
            return growth_error(error, error_cap,
                                "cumulative line count overflowed");
        if (day->non_test_deleted > non_test + day->non_test_added ||
            day->test_deleted > test + day->test_added)
            return growth_error(
                error, error_cap,
                "history deletes lines outside reconstructed scope");
        non_test += day->non_test_added;
        non_test -= day->non_test_deleted;
        test += day->test_added;
        test -= day->test_deleted;
        day->non_test_lines = non_test;
        day->test_lines = test;
    }
    out->non_test_lines = non_test;
    out->test_lines = test;
    if (error && error_cap) error[0] = '\0';
    return true;
}

static bool growth_require_git_toplevel(const char *root, char *error,
                                        size_t error_cap)
{
    char prefix[256];
    const char *argv[] = {
        "git", "-C", root, "rev-parse", "--show-prefix", NULL,
    };
    int rc = growth_git_capture(argv, prefix, sizeof(prefix), 30000);
    if (rc < 0)
        return growth_error(
            error, error_cap,
            "growth is unavailable: trusted host Git could not be started");
    if (rc != 0)
        return growth_error(
            error, error_cap,
            "growth is unavailable: the source root is not a Git work tree");
    for (const char *p = prefix; *p; p++)
        if (*p != '\n' && *p != '\r')
            return growth_error(
                error, error_cap,
                "growth is unavailable: the source root is not the Git "
                "toplevel");
    return true;
}

bool science_code_growth_collect(const char *root,
                                 struct science_code_growth_history *out,
                                 char *error, size_t error_cap)
{
    if (!root || !root[0] || !out)
        return growth_error(error, error_cap, "source root/history output is missing");
    if (!growth_require_git_toplevel(root, error, error_cap))
        return false;
    char head[41];
    bool clean = false;
    if (!growth_git_identity(root, head, &clean))
        return growth_error(error, error_cap,
                            "growth source identity could not be measured");
    if (clean && growth_cache_load(root, head, out, error, error_cap)) {
        char verified_head[41];
        bool still_clean = false;
        if (growth_git_identity(root, verified_head, &still_clean) &&
            still_clean && strcmp(head, verified_head) == 0)
            return true;
    }
    char *stream = zcl_malloc(SCIENCE_CODE_GROWTH_GIT_BYTES_MAX,
                               "science.code_growth.git");
    if (!stream)
        return growth_error(error, error_cap,
                            "Git history buffer allocation failed");
    const char *argv[GROWTH_ARGV_CAP] = {
        "git", "-C", root, "log", "--first-parent", "--reverse",
        "--no-renames", "--diff-merges=first-parent", "--root",
        "--format=@@%H%x09%ct", "--numstat", "--", NULL,
    };
    size_t argc = 12u;
    for (size_t i = 0; i < sizeof(growth_roots) / sizeof(growth_roots[0]); i++)
        argv[argc++] = growth_roots[i];
    argv[argc] = NULL;
    int rc = growth_git_capture(argv, stream,
                                SCIENCE_CODE_GROWTH_GIT_BYTES_MAX, 120000);
    size_t length = strnlen(stream, SCIENCE_CODE_GROWTH_GIT_BYTES_MAX);
    bool ok = rc == 0 && length + 1u < SCIENCE_CODE_GROWTH_GIT_BYTES_MAX &&
        science_code_growth_parse(stream, length, out, error, error_cap);
    if (!ok) {
        free(stream);
        if (rc != 0)
            return growth_error(error, error_cap,
                                "Git history command failed");
        if (length + 1u >= SCIENCE_CODE_GROWTH_GIT_BYTES_MAX)
            return growth_error(
                error, error_cap,
                "Git history exceeded the bounded capture size");
        return false;
    }
    struct science_corpus_report current;
    if (!science_corpus_measure(root, NULL, &current)) {
        free(stream);
        return growth_error(error, error_cap,
                            "fresh maintained C23 census failed");
    }
    if (current.non_test_lines != out->non_test_lines ||
        current.test_lines != out->test_lines) {
        free(stream);
        return growth_error(
            error, error_cap,
            "Git reconstruction disagrees with the fresh maintained C23 census");
    }
    char verified_head[41];
    bool still_clean = false;
    if (clean && growth_git_identity(root, verified_head, &still_clean) &&
        still_clean && strcmp(head, verified_head) == 0)
        growth_cache_store(root, head, stream, length);
    free(stream);
    return true;
}
