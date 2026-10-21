/* Copyright 2026 Rhett Creighton - Apache License 2.0 */
#include "test/test_core.h"
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include "platform/directory_compat.h"
#include "base/safe_alloc.h"

/* Remove a child directory between its parent's listing and its own scan,
 * the way a concurrent build rewrites build/. The listing of vanish_parent
 * runs for real, then the child is deleted before the scanner opens it. */
static char vanish_parent[512], vanish_child[512];
static bool vanish_armed, vanish_removed;
static bool vanish_list_children_sorted(const char *path,
                                        struct platform_directory_list *dirs,
                                        struct platform_directory_list *files)
{
    bool ok = platform_directory_list_children_sorted(path, dirs, files);
    if (ok && vanish_armed && strcmp(path, vanish_parent) == 0) {
        vanish_armed = false;
        vanish_removed = test_rm_rf_recursive(vanish_child) == 0;
    }
    return ok;
}

/* Observe the actual scanner call sites without relying on nonnull sanitizers.
 * Keep this copy private so it cannot replace the linked production scanner. */
static unsigned empty_dep_null_sorts;
static void empty_dep_sort(void *base, size_t count, size_t width,
                           int (*compare)(const void *, const void *))
{
    if (!base) {
        empty_dep_null_sorts++;
        return;
    }
    qsort(base, count, width, compare);
}

#define ci_deps_include_narrow_unsafe empty_dep_include_narrow_unsafe
#define ci_deps_include_narrow_cause empty_dep_include_narrow_cause
#define ci_deps_include_edge_root empty_dep_include_edge_root
#define ci_deps_scan empty_dep_scan
#define ci_deps_scan_roots empty_dep_scan_roots
#define codeindex_depfile_graph empty_dep_graph
#define ci_deps_stat_root_sha3 empty_dep_stat_root
#define ci_deps_stat_keys empty_dep_stat_keys
#define ci_deps_keys_free empty_dep_keys_free
#define qsort empty_dep_sort
#define platform_directory_list_children_sorted vanish_list_children_sorted
#include "../../../cognition/modules/codeindex/src/codeindex_deps.c"
#undef platform_directory_list_children_sorted
#undef qsort
#undef ci_deps_stat_root_sha3
#undef ci_deps_stat_keys
#undef ci_deps_keys_free
#undef codeindex_depfile_graph
#undef ci_deps_scan_roots
#undef ci_deps_scan
#undef ci_deps_include_edge_root
#undef ci_deps_include_narrow_cause
#undef ci_deps_include_narrow_unsafe

static int test_dep_vanished_child(void);
static int test_dep_missing_root(void);
static int test_dep_children_alloc(const char *label, bool regular);

int test_codeindex_empty_dep_paths(void)
{
    int failures = 0;
    char dir[256] = {0}, build[512];
    uint8_t exact[32], combined[32], separate[32];
    TEST("empty build scans never pass a null base to qsort") {
        test_make_tmpdir(dir, sizeof(dir), "dep_paths", "empty");
        ASSERT(dir[0]);
        int n = snprintf(build, sizeof(build), "%s/build", dir);
        ASSERT(n > 0 && (size_t)n < sizeof(build));
        ASSERT(mkdir(build, 0700) == 0);
        empty_dep_null_sorts = 0;
        ASSERT(empty_dep_scan_roots(dir, NULL, NULL, exact, combined));
        ASSERT_EQ(empty_dep_null_sorts, 0);
        ASSERT(empty_dep_stat_root(dir, separate));
        ASSERT_EQ(empty_dep_null_sorts, 0);
        ASSERT(memcmp(combined, separate, sizeof(combined)) == 0);
        PASS();
    } _test_next:;
    if (dir[0] && test_rm_rf_recursive(dir) != 0) failures++;
    failures += test_dep_vanished_child();
    failures += test_dep_missing_root();
    failures += test_dep_children_alloc("platform_directory_entries", true);
    failures += test_dep_children_alloc("platform_directory_entry_name", true);
    failures += test_dep_children_alloc("platform_directory_entries", false);
    failures += test_dep_children_alloc("platform_directory_entry_name", false);
    return failures;
}

static int test_dep_vanished_child(void)
{
    int failures = 0;
    char race[256] = {0}, race_build[512], race_sub[512], race_file[512];
    size_t race_count = 0;
    int64_t race_newest = 0;
    TEST("a child directory removed mid-scan is skipped, not fatal") {
        test_make_tmpdir(race, sizeof(race), "dep_paths", "vanish");
        ASSERT(race[0]);
        ASSERT(snprintf(race_build, sizeof(race_build), "%s/build", race) > 0);
        ASSERT(snprintf(race_sub, sizeof(race_sub), "%s/sub", race_build) > 0);
        ASSERT(snprintf(race_file, sizeof(race_file), "%s/a.d", race_build) > 0);
        ASSERT(mkdir(race_build, 0700) == 0);
        ASSERT(mkdir(race_sub, 0700) == 0);
        FILE *f = fopen(race_file, "w");
        ASSERT(f != NULL);
        ASSERT(fputs("build/a.o: core/a.c\n", f) >= 0);
        ASSERT(fclose(f) == 0);
        ASSERT(snprintf(race_file, sizeof(race_file), "%s/b.d", race_sub) > 0);
        f = fopen(race_file, "w");
        ASSERT(f != NULL);
        ASSERT(fputs("build/sub/b.o: core/b.c\n", f) >= 0);
        ASSERT(fclose(f) == 0);
        snprintf(vanish_parent, sizeof(vanish_parent), "%s", race_build);
        snprintf(vanish_child, sizeof(vanish_child), "%s", race_sub);
        vanish_armed = true;
        vanish_removed = false;
        struct dep_paths paths = {0};
        bool collected = collect_dep_paths(race, "build", &paths);
        ASSERT(vanish_removed);
        ASSERT(collected);
        ASSERT_EQ(paths.count, 1);
        ASSERT(strcmp(paths.items[0], "build/a.d") == 0);
        dep_paths_free(&paths);
        ASSERT(empty_dep_graph(race, &race_count, &race_newest));
        ASSERT_EQ(race_count, 1);
        PASS();
    } _test_next:;
    if (race[0] && test_rm_rf_recursive(race) != 0) failures++;
    return failures;
}

static int test_dep_missing_root(void)
{
    int failures = 0;
    char missing[256] = {0};
    TEST("a missing build root still fails, with ENOENT") {
        test_make_tmpdir(missing, sizeof(missing), "dep_paths", "noroot");
        ASSERT(missing[0]);
        struct dep_paths paths = {0};
        errno = 0;
        ASSERT(!collect_dep_paths(missing, "build", &paths));
        ASSERT_EQ(errno, ENOENT);
        dep_paths_free(&paths);
        PASS();
    } _test_next:;
    if (missing[0] && test_rm_rf_recursive(missing) != 0) failures++;
    return failures;
}

static bool dep_make_listing_children(const char *root, bool regular)
{
    for (int i = 0; i < 3; i++) {
        char path[512];
        int n = snprintf(path, sizeof(path), "%s/%c", root, 'c' - i);
        if (n <= 0 || (size_t)n >= sizeof(path)) return false;
        if (!regular) {
            if (mkdir(path, 0700) != 0) return false;
        } else {
            FILE *f = fopen(path, "wb");
            if (!f) return false;
            if (fclose(f) != 0) return false;
        }
    }
    return true;
}

static int test_dep_children_alloc(const char *label, bool regular)
{
    int failures = 0;
    char root[256] = {0};
    struct platform_directory_list dirs = {0}, files = {0};
    TEST("combined directory listing fails closed after a middle allocation failure") {
        printf("fault label=%s kind=%s\n", label, regular ? "files" : "directories");
        test_make_tmpdir(root, sizeof(root), "dep_paths", "listing_oom");
        ASSERT(root[0]);
        ASSERT(dep_make_listing_children(root, regular));
        zcl_alloc_fault_fail_nth(label, 2);
        bool ok = platform_directory_list_children_sorted(root, &dirs, &files);
        bool consumed = zcl_alloc_fault_armed_label() == NULL;
        zcl_alloc_fault_clear();
        ASSERT(consumed);
        ASSERT(!ok);
        ASSERT(dirs.entries == NULL && dirs.count == 0);
        ASSERT(files.entries == NULL && files.count == 0);
        ASSERT(platform_directory_list_children_sorted(root, &dirs, &files));
        struct platform_directory_list *listed = regular ? &files : &dirs;
        ASSERT_EQ(listed->count, 3);
        ASSERT(strcmp(listed->entries[0].name, "a") == 0);
        ASSERT(strcmp(listed->entries[1].name, "b") == 0);
        ASSERT(strcmp(listed->entries[2].name, "c") == 0);
        ASSERT_EQ(files.count, regular ? 3 : 0);
        ASSERT_EQ(dirs.count, regular ? 0 : 3);
        if (regular) ASSERT(files.entries[0].snapshot_valid);
        PASS();
    } _test_next:;
    zcl_alloc_fault_clear();
    platform_directory_list_free(&dirs);
    platform_directory_list_free(&files);
    if (root[0] && test_rm_rf_recursive(root) != 0) failures++;
    return failures;
}
