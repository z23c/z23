/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * Exercise the actual warm path decoder in a private resource tree. */
#include "../../../tools/sensors/clang_manifest_warm.c"
#include <unistd.h>

static bool wp_setup(void)
{
    if (mkdir("resource", 0700) != 0 || mkdir("resource/include", 0700) != 0 ||
        mkdir("outside", 0700) != 0)
        return false;
    return symlink("../../outside", "resource/include/escape") == 0 &&
           symlink("missing", "resource/include/dangling") == 0 &&
           symlink("..", "resource/include/root") == 0 &&
           symlink(".", "resource/include/inside") == 0;
}

static int wp_case(const struct cm_host_paths *paths, const char *path,
                    size_t n, bool expected)
{
    char out[PATH_MAX];
    bool actual = cm_host_path(paths, path, n, out, sizeof(out));
    if (actual == expected)
        return 0;
    fprintf(stderr, "warm-path fixture: %.*s expected %d got %d\n",
            (int)n, path, expected, actual);
    return 1;
}

static int wp_cases(struct cm_host_paths *paths)
{
    static const struct { const char *path; bool expected; } cases[] = {
        {"@sys/clang-resource", true},
        {"@sys/clang-resource/include", true},
        {"@sys/clang-resource/include/missing/subdir", true},
        {"@sys/clang-resource/include/inside", true},
        {"@sys/clang-resource/include/escape", false},
        {"@sys/clang-resource/include/dangling", false},
        {"@sys/clang-resource/include/root", false},
        {"@sys/clang-resource/includeX", false},
        {"@sys/clang-resource/include/..", false},
        {"@sys/clang-resource/include/.", false},
        {"@sys/clang-resource/include/", false},
        {"@sys/clang-resource/include//x", false},
    };
    int failures = 0;
    for (size_t k = 0; k < sizeof(cases) / sizeof(cases[0]); k++)
        failures += wp_case(paths, cases[k].path, strlen(cases[k].path), cases[k].expected);
    static const char nul[] = "@sys/clang-resource/include\0/escape";
    failures += wp_case(paths, nul, sizeof(nul) - 1, false);
    char tiny[2];
    if (cm_host_path(paths, cases[0].path, strlen(cases[0].path), tiny, sizeof(tiny)))
        failures++;
    paths->resource_len = 0;
    failures += wp_case(paths, cases[0].path, strlen(cases[0].path), false);
    return failures;
}

static int wp_inverse_cases(const struct cm_host_paths *paths)
{
    static const struct { const char *path; const char *suffix; bool resource; } cases[] = {
        {"@sys/clang-resource", "", true},
        {"@sys/clang-resource/include", "/include", true},
        {"@sys/clang-resource/include/missing/subdir", "/include/missing/subdir", true},
        {"@sys/clang-resource/include/inside", "/include", true},
        {"@sys", "/", false},
        {"@sys/usr/include", "/usr/include", false},
        {"@system", "./@system", false},
    };
    int failures = 0;
    for (size_t k = 0; k < sizeof(cases) / sizeof(cases[0]); k++) {
        char actual[PATH_MAX], expected[PATH_MAX];
        int n = snprintf(expected, sizeof(expected), "%s%s",
                         cases[k].resource ? paths->resource : "", cases[k].suffix);
        if (n < 0 || (size_t)n >= sizeof(expected) ||
            !cm_host_path(paths, cases[k].path, strlen(cases[k].path),
                          actual, sizeof(actual)) || strcmp(actual, expected) != 0) {
            fprintf(stderr, "warm-path fixture: wrong inverse for %s\n", cases[k].path);
            failures++;
        }
    }
    return failures;
}

int main(int argc, char **argv)
{
    struct cm_host_paths paths = {.root = "."};
    if (argc != 2 || chdir(argv[1]) != 0 || !wp_setup() ||
        !cm_host_resource_root(paths.resource, &paths.resource_len)) {
        fprintf(stderr, "warm-path fixture: setup failed\n");
        return 2;
    }
    int failures = wp_inverse_cases(&paths);
    failures += wp_cases(&paths);
    if (failures == 0)
        puts("warm-path fixture: PASS");
    return failures != 0;
}
