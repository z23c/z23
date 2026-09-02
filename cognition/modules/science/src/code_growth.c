/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: exact bounded daily C23 growth reconstructed from Git numstat. */
#include "science/code_growth.h"

#include "base/safe_alloc.h"
#include "platform/time_compat.h"
#include "science/science_corpus.h"
#include "util/spawn.h"

#include <ctype.h>
#include <inttypes.h>
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
    GROWTH_ARGV_FIXED = 12u,
    GROWTH_ARGV_CAP = GROWTH_ARGV_FIXED +
        sizeof(growth_roots) / sizeof(growth_roots[0]) + 1u,
};

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
    int rc = zcl_spawn_capture(argv, prefix, sizeof(prefix), 30000);
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
    size_t argc = GROWTH_ARGV_FIXED;
    for (size_t i = 0; i < sizeof(growth_roots) / sizeof(growth_roots[0]); i++)
        argv[argc++] = growth_roots[i];
    argv[argc] = NULL;
    int rc = zcl_spawn_capture(argv, stream, SCIENCE_CODE_GROWTH_GIT_BYTES_MAX,
                               120000);
    size_t length = strnlen(stream, SCIENCE_CODE_GROWTH_GIT_BYTES_MAX);
    bool ok = rc == 0 && length + 1u < SCIENCE_CODE_GROWTH_GIT_BYTES_MAX &&
        science_code_growth_parse(stream, length, out, error, error_cap);
    free(stream);
    if (!ok) {
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
    if (!science_corpus_measure(root, NULL, &current))
        return growth_error(error, error_cap,
                            "fresh maintained C23 census failed");
    if (current.non_test_lines != out->non_test_lines ||
        current.test_lines != out->test_lines)
        return growth_error(
            error, error_cap,
            "Git reconstruction disagrees with the fresh maintained C23 census");
    return true;
}
