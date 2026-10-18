/* Copyright 2026 Rhett Creighton - Apache License 2.0 */
#include "test/test_core.h"
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

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
#include "../../../cognition/modules/codeindex/src/codeindex_deps.c"
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
    return failures;
}
