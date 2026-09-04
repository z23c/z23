/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: exact daily C23 Git-history parser and refusal tests. */
#include "science/code_growth.h"
#if defined(_WIN32)
#include "platform/process_lifecycle.h"
#endif
#include "platform/directory_compat.h"
#include "platform/temp_directory.h"
#include "util/file_tree_ops.h"
#include "util/spawn.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define GROWTH_CHECK(name_, expression_) do {                         \
    bool growth_ok_ = (expression_);                                  \
    printf("code_growth: %s... %s\n", (name_),                       \
           growth_ok_ ? "OK" : "FAIL");                             \
    if (!growth_ok_) failures++;                                      \
} while (0)

static bool growth_test_run(const char *const argv[])
{
    char output[512];
#if defined(_WIN32)
    const char *image = getenv("ZCL_DEV_GIT_EXE");
    if (!image || !image[0]) image = "C:\\msys64\\usr\\bin\\git.exe";
    const char *native_argv[16];
    size_t argc = 0;
    while (argv && argv[argc] && argc + 1u < 16u) {
        native_argv[argc] = argc == 0 ? image : argv[argc];
        argc++;
    }
    if (!argv || argv[argc]) return false;
    native_argv[argc] = NULL;
    static const char *const environment[] = {
        "GIT_CONFIG_NOSYSTEM=1", "GIT_OPTIONAL_LOCKS=0", "GIT_PAGER=",
        "GIT_TERMINAL_PROMPT=0", "LANG=C", "LC_ALL=C", NULL,
    };
    const struct platform_process_options options = {
        .image = image, .argv = native_argv, .env = environment,
    };
    struct platform_process_capture_result result = {0};
    bool launched = platform_process_capture_stdout(
        &options, output, sizeof(output), 30000u, &result);
    bool ok = launched && !result.timed_out && !result.output_truncated &&
        result.exit_code == 0;
    if (!ok)
        printf("code_growth fixture Git failed: command=%s launched=%d "
               "exit=%lu timeout=%d truncated=%d\n",
               argv[1], launched, (unsigned long)result.exit_code,
               result.timed_out, result.output_truncated);
    return ok;
#else
    return zcl_spawn_capture(argv, output, sizeof(output), 30000) == 0;
#endif
}

static bool growth_test_write(const char *path, const char *text)
{
    FILE *file = fopen(path, "wb");
    if (!file) return false;
    size_t length = strlen(text);
    bool ok = fwrite(text, 1, length, file) == length;
    return fclose(file) == 0 && ok;
}

static bool growth_test_path(char *out, size_t cap, const char *root,
                             const char *relative)
{
    int n = snprintf(out, cap, "%s/%s", root, relative);
    return n > 0 && (size_t)n < cap;
}

static bool growth_history_equal(
    const struct science_code_growth_history *left,
    const struct science_code_growth_history *right)
{
    if (left->day_count != right->day_count ||
        left->non_test_lines != right->non_test_lines ||
        left->test_lines != right->test_lines)
        return false;
    for (size_t i = 0; i < left->day_count; i++) {
        const struct science_code_growth_day *a = &left->days[i];
        const struct science_code_growth_day *b = &right->days[i];
        if (strcmp(a->date, b->date) != 0 ||
            strcmp(a->head_commit, b->head_commit) != 0 ||
            a->epoch_day != b->epoch_day || a->commits != b->commits ||
            a->non_test_added != b->non_test_added ||
            a->non_test_deleted != b->non_test_deleted ||
            a->non_test_lines != b->non_test_lines ||
            a->test_added != b->test_added ||
            a->test_deleted != b->test_deleted ||
            a->test_lines != b->test_lines)
            return false;
    }
    return true;
}

static bool growth_test_commit(const char *root, const char *message)
{
    const char *add[] = {
        "git", "-C", root, "add", "--", "lib/demo/src/a.c", NULL,
    };
    const char *commit[] = {
        "git", "-C", root, "-c", "user.name=Z23 Test",
        "-c", "user.email=z23-test@example.invalid",
        "-c", "commit.gpgsign=false", "commit", "-q", "-m", message, NULL,
    };
    return growth_test_run(add) && growth_test_run(commit);
}

static int growth_cache_tests(void)
{
    int failures = 0;
    char root[PLATFORM_TEMP_PATH_MAX];
    char source[512] = "", cache[512] = "", error[192];
    bool made = platform_temp_directory_create(
        "z23-code-growth-", root, sizeof(root));
    if (!made)
        printf("code_growth fixture temp root failed: errno=%d\n", errno);
    bool source_path_ok = made && growth_test_path(
        source, sizeof(source), root, "lib/demo/src/a.c");
    bool cache_path_ok = source_path_ok && growth_test_path(
        cache, sizeof(cache), root,
        ".cache/z23-code-growth-private-v1/git-numstat.v1");
    const char *init[] = {"git", "-C", root, "init", "-q", NULL};
    char directory[512] = "";
    bool directory_path_ok = cache_path_ok && growth_test_path(
        directory, sizeof(directory), root, "lib/demo/src");
    bool mkdir_ok = directory_path_ok;
    if (mkdir_ok) {
        for (char *at = directory + 1; *at; at++) {
            if (*at != '/') continue;
            *at = '\0';
            bool component_ok = platform_directory_ensure(directory, 0700);
            *at = '/';
            if (!component_ok) {
                mkdir_ok = false;
                break;
            }
        }
        if (mkdir_ok)
            mkdir_ok = platform_directory_ensure(directory, 0700);
    }
    bool init_ok = mkdir_ok && growth_test_run(init);
    bool write_ok = init_ok && growth_test_write(
        source, "int answer(void) { return 42; }\n");
    bool ready = write_ok && growth_test_commit(root, "initial");
    if (!ready)
        printf("code_growth fixture setup failed: made=%d source=%d cache=%d "
               "directory=%d mkdir=%d init=%d write=%d errno=%d root=%s\n",
               made, source_path_ok, cache_path_ok, directory_path_ok,
               mkdir_ok, init_ok, write_ok, errno, made ? root : "(none)");
    struct science_code_growth_history cold = {0}, warm = {0}, rebuilt = {0};
    bool cold_ok = ready && science_code_growth_collect(
        root, &cold, error, sizeof(error));
    bool warm_ok = cold_ok && science_code_growth_collect(
        root, &warm, error, sizeof(error));
    GROWTH_CHECK("clean exact HEAD reuses its verified Git stream",
                 warm_ok && !cold.cache_hit && warm.cache_hit &&
                 growth_history_equal(&cold, &warm));

    bool corrupted = warm_ok &&
        growth_test_write(cache, "not a growth cache\n");
    bool rebuilt_ok = corrupted && science_code_growth_collect(
        root, &rebuilt, error, sizeof(error));
    GROWTH_CHECK("corrupt cache falls back to exact cold reconstruction",
                 rebuilt_ok && !rebuilt.cache_hit &&
                 growth_history_equal(&cold, &rebuilt));

    bool dirtied = growth_test_write(
        source, "int answer(void) { return 42; }\nint more(void) { return 1; }\n");
    struct science_code_growth_history dirty = {0};
    GROWTH_CHECK("dirty maintained source cannot reuse stale evidence",
                 dirtied && !science_code_growth_collect(
                     root, &dirty, error, sizeof(error)) &&
                 strstr(error, "disagrees") != NULL);

    bool committed = dirtied && growth_test_commit(root, "grow");
    struct science_code_growth_history advanced = {0}, advanced_warm = {0};
    bool advanced_ok = committed && science_code_growth_collect(
        root, &advanced, error, sizeof(error));
    bool advanced_warm_ok = advanced_ok && science_code_growth_collect(
        root, &advanced_warm, error, sizeof(error));
    GROWTH_CHECK("new first-parent HEAD extends then seals the exact result",
                 advanced_warm_ok && advanced.cache_hit &&
                 advanced_warm.cache_hit &&
                 advanced.non_test_lines == cold.non_test_lines + 1u &&
                 growth_history_equal(&advanced, &advanced_warm));
    if (made) (void)zcl_tree_remove(root);
    return failures;
}

int test_code_growth(void)
{
    int failures = 0;
    static const char stream[] =
        "@@0000000000000000000000000000000000000001\t0\n"
        "5\t0\tlib/demo/src/a.c\n"
        "2\t0\tlib/test/src/test_a.c\n"
        "3\t0\ttests/harness/src/test_current.c\n"
        "-\t-\tapp/views/assets/icon.png\n"
        "10\t0\tdocs/not-maintained.c\n"
        "@@0000000000000000000000000000000000000002\t172800\n"
        "3\t1\tlib/demo/src/a.c\n"
        "4\t1\tcontexts/commons/packages/demo/tests/check.c\n";
    struct science_code_growth_history history;
    char error[160];
    bool parsed = science_code_growth_parse(
        stream, sizeof(stream) - 1u, &history, error, sizeof(error));
    GROWTH_CHECK("every UTC day is reconstructed",
                 parsed && history.day_count == 3u &&
                 strcmp(history.days[0].date, "1970-01-01") == 0 &&
                 strcmp(history.days[1].date, "1970-01-02") == 0 &&
                 strcmp(history.days[2].date, "1970-01-03") == 0);
    GROWTH_CHECK("inactive days carry totals without inventing changes",
                 parsed && history.days[1].commits == 0u &&
                 history.days[1].non_test_added == 0u &&
                 history.days[1].non_test_deleted == 0u &&
                 history.days[1].test_added == 0u &&
                 history.days[1].test_deleted == 0u &&
                 history.days[1].non_test_lines == 15u &&
                 history.days[1].test_lines == 5u);
    GROWTH_CHECK("maintained documentation source is counted; binary rows are not",
                 parsed && history.days[0].non_test_added == 15u &&
                 history.days[0].test_added == 5u);
    GROWTH_CHECK("non-test and test totals remain separate",
                 parsed && history.non_test_lines == 17u &&
                 history.test_lines == 8u &&
                 history.days[2].non_test_lines == 17u &&
                 history.days[2].test_lines == 8u);
    GROWTH_CHECK("the day's exact last commit is retained for evidence",
                 parsed && strcmp(history.days[2].head_commit,
                     "0000000000000000000000000000000000000002") == 0);

    static const char underflow[] =
        "@@0000000000000000000000000000000000000001\t0\n"
        "0\t1\tlib/demo/src/a.c\n";
    memset(&history, 0xa5, sizeof(history));
    GROWTH_CHECK("a deletion outside reconstructed history refuses",
                 !science_code_growth_parse(
                     underflow, sizeof(underflow) - 1u, &history,
                     error, sizeof(error)) &&
                 strstr(error, "deletes lines") != NULL);

    static const char malformed[] =
        "@@not-a-commit\t0\n1\t0\tlib/demo/src/a.c\n";
    GROWTH_CHECK("a malformed Git header refuses",
                 !science_code_growth_parse(
                     malformed, sizeof(malformed) - 1u, &history,
                     error, sizeof(error)));
    failures += growth_cache_tests();
    return failures;
}
