/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * Hermetic readdir failures in the exact POSIX directory implementation. */
#include "test/test_core.h"
#include "platform/directory_compat.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#if !defined(_WIN32)
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>

static int directory_reads_left = -1;
static unsigned directory_children_read;
static bool directory_stale_errno;

static struct dirent *directory_fault_readdir(DIR *dir)
{
    if (directory_reads_left == 0) {
        errno = EIO;
        return NULL;
    }
    struct dirent *entry = readdir(dir);
    if (entry && strcmp(entry->d_name, ".") && strcmp(entry->d_name, "..")) {
        directory_children_read++;
        if (directory_reads_left > 0) directory_reads_left--;
    }
    /* An unrelated successful operation is allowed to leave errno nonzero.
     * The caller must clear it immediately before EACH readdir, not once. */
    if (entry && directory_stale_errno) errno = EIO;
    return entry;
}

/* Like the existing codeindex source-local seam, this keeps fault injection
 * out of the production ABI and cannot intercept another test's enumeration. */
#define platform_directory_create fault_directory_create
#define platform_directory_ensure fault_directory_ensure
#define platform_directory_probe_real fault_directory_probe_real
#define platform_directory_canonical_real fault_directory_canonical_real
#define platform_directory_list_real_sorted fault_directory_list_real_sorted
#define platform_directory_list_real_bounded fault_directory_list_real_bounded
#define platform_directory_list_regular_sorted fault_directory_list_regular_sorted
#define platform_directory_list_children_sorted fault_directory_list_children_sorted
#define platform_directory_list_free fault_directory_list_free
#define readdir directory_fault_readdir
#include "../../../platform/modules/platform/src/directory_compat.c"
#undef readdir
#undef platform_directory_list_free
#undef platform_directory_list_children_sorted
#undef platform_directory_list_regular_sorted
#undef platform_directory_list_real_sorted
#undef platform_directory_list_real_bounded
#undef platform_directory_canonical_real
#undef platform_directory_probe_real
#undef platform_directory_ensure
#undef platform_directory_create

enum directory_kind { DIRECTORY_DIRS, DIRECTORY_FILES, DIRECTORY_BOTH };

static bool directory_fixture_child(const char *root, const char *name,
                                     bool regular)
{
    char path[512];
    int n = snprintf(path, sizeof(path), "%s/%s", root, name);
    if (n <= 0 || (size_t)n >= sizeof(path)) return false;
    if (!regular) return mkdir(path, 0700) == 0;
    FILE *f = fopen(path, "wb");
    return f && fclose(f) == 0;
}

static bool directory_fixture(const char *root, enum directory_kind kind)
{
    if (kind != DIRECTORY_FILES &&
        (!directory_fixture_child(root, "z-dir", false) ||
         !directory_fixture_child(root, "a-dir", false))) return false;
    return kind == DIRECTORY_DIRS ||
        (directory_fixture_child(root, "z-file", true) &&
         directory_fixture_child(root, "a-file", true));
}

static bool directory_fault_list(const char *root, enum directory_kind kind,
                                  struct platform_directory_list *dirs,
                                  struct platform_directory_list *files)
{
    if (kind == DIRECTORY_DIRS) return fault_directory_list_real_sorted(root, dirs);
    if (kind == DIRECTORY_FILES) return fault_directory_list_regular_sorted(root, files);
    return fault_directory_list_children_sorted(root, dirs, files);
}

static int directory_error_case(enum directory_kind kind, int after)
{
    int failures = 0;
    char root[256] = {0};
    struct platform_directory_list dirs = {0}, files = {0};
    TEST("directory enumeration errors refuse and clear every partial list") {
        printf("kind=%d error_after_children=%d\n", kind, after);
        test_make_tmpdir(root, sizeof(root), "directory_errors", "read");
        ASSERT(root[0]);
        ASSERT(directory_fixture(root, kind));
        directory_children_read = 0;
        directory_reads_left = after;
        bool ok = directory_fault_list(root, kind, &dirs, &files);
        directory_reads_left = -1;
        ASSERT_EQ(directory_children_read, (unsigned)after);
        ASSERT(!ok);
        ASSERT(dirs.entries == NULL && dirs.count == 0);
        ASSERT(files.entries == NULL && files.count == 0);
        PASS();
    } _test_next:;
    directory_reads_left = -1;
    platform_directory_list_free(&dirs);
    platform_directory_list_free(&files);
    if (root[0] && test_rm_rf_recursive(root) != 0) failures++;
    return failures;
}

static bool directory_sorted_pair(const struct platform_directory_list *list,
                                   const char *first, const char *last)
{
    return list->count == 2 && !strcmp(list->entries[0].name, first) &&
        !strcmp(list->entries[1].name, last);
}

static int directory_success_case(enum directory_kind kind)
{
    int failures = 0;
    char root[256] = {0}, link_path[512];
    struct platform_directory_list dirs = {0}, files = {0};
    TEST("successful enumeration stays sorted and omits child symlinks") {
        test_make_tmpdir(root, sizeof(root), "directory_errors", "success");
        ASSERT(root[0]);
        ASSERT(directory_fixture(root, DIRECTORY_BOTH));
        ASSERT(snprintf(link_path, sizeof(link_path), "%s/link-dir", root) > 0);
        ASSERT(symlink("a-dir", link_path) == 0);
        ASSERT(snprintf(link_path, sizeof(link_path), "%s/link-file", root) > 0);
        ASSERT(symlink("a-file", link_path) == 0);
        directory_stale_errno = true;
        bool ok = directory_fault_list(root, kind, &dirs, &files);
        directory_stale_errno = false;
        ASSERT(ok);
        if (kind != DIRECTORY_FILES)
            ASSERT(directory_sorted_pair(&dirs, "a-dir", "z-dir"));
        if (kind != DIRECTORY_DIRS) {
            ASSERT(directory_sorted_pair(&files, "a-file", "z-file"));
            ASSERT(files.entries[0].snapshot_valid && files.entries[1].snapshot_valid);
        }
        PASS();
    } _test_next:;
    directory_stale_errno = false;
    platform_directory_list_free(&dirs);
    platform_directory_list_free(&files);
    if (root[0] && test_rm_rf_recursive(root) != 0) failures++;
    return failures;
}
static int directory_bounded_case(void)
{
    int failures = 0; char root[256] = {0};
    struct platform_directory_list dirs = {0}; bool overflow = false;
    TEST("bounded enumeration refuses overflow and errors without partial output") {
        test_make_tmpdir(root, sizeof(root), "directory_errors", "bounded");
        ASSERT(root[0] && directory_fixture(root, DIRECTORY_BOTH));
        ASSERT(fault_directory_list_real_bounded(root, 4, &dirs, &overflow));
        ASSERT(!overflow && directory_sorted_pair(&dirs, "a-dir", "z-dir"));
        fault_directory_list_free(&dirs);
        ASSERT(!fault_directory_list_real_bounded(root, 3, &dirs, &overflow));
        ASSERT(overflow && !dirs.entries && dirs.count == 0);
        directory_reads_left = 1;
        ASSERT(!fault_directory_list_real_bounded(root, 4, &dirs, &overflow));
        directory_reads_left = -1;
        ASSERT(!overflow && !dirs.entries && dirs.count == 0);
        PASS();
    } _test_next:;
    directory_reads_left = -1; fault_directory_list_free(&dirs);
    if (root[0] && test_rm_rf_recursive(root) != 0) failures++;
    return failures;
}

int test_platform_directory_errors(void)
{
    int failures = 0;
    failures += directory_bounded_case();
    for (enum directory_kind kind = DIRECTORY_DIRS; kind <= DIRECTORY_BOTH; kind++) {
        failures += directory_error_case(kind, 0);
        failures += directory_error_case(kind, 1);
        failures += directory_success_case(kind);
    }
    return failures;
}
#else
int test_platform_directory_errors(void)
{
    printf("POSIX readdir fault injection not applicable on Windows\n");
    return 0;
}
#endif
