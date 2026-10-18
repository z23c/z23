/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * util/path_util.h contract: zcl_path_join writes "a/b" and refuses NULL
 * arguments and any result that does not fit; zcl_path_is_dir is true for a
 * directory and false for a regular file, a missing path and NULL;
 * zcl_is_lower_hex accepts exactly len lowercase hexadecimal characters. */

#include "test/test_core.h"

#include "util/path_util.h"

#include <limits.h>
#include <stdio.h>
#include <string.h>


static int pu_join(void)
{
    int failures = 0;
    TEST_CASE("path_util: join writes a/b and refuses NULL or a result that does not fit") {
        char out[8];
        ASSERT(zcl_path_join(out, sizeof out, "ab", "cd"));
        ASSERT(strcmp(out, "ab/cd") == 0);
        ASSERT(zcl_path_join(out, sizeof out, "abc", "def"));
        ASSERT(strcmp(out, "abc/def") == 0);
        ASSERT(!zcl_path_join(out, sizeof out, "abcd", "def"));
        ASSERT(!zcl_path_join(NULL, sizeof out, "a", "b"));
        ASSERT(!zcl_path_join(out, sizeof out, NULL, "b"));
        ASSERT(!zcl_path_join(out, sizeof out, "a", NULL));
    } TEST_END
    return failures;
}

static int pu_is_dir(void)
{
    int failures = 0;
    TEST_CASE("path_util: is_dir is true for a directory and false for a file, a missing path and NULL") {
        char dir[PATH_MAX], file[PATH_MAX], missing[PATH_MAX];
        test_make_tmpdir(dir, sizeof dir, "path_util", "dir");
        bool joined = zcl_path_join(file, sizeof file, dir, "f") &&
                      zcl_path_join(missing, sizeof missing, dir, "absent");
        FILE *f = joined ? fopen(file, "w") : NULL;
        bool made = f != NULL && fclose(f) == 0;
        bool dir_yes = zcl_path_is_dir(dir);
        bool file_no = made && !zcl_path_is_dir(file);
        bool missing_no = joined && !zcl_path_is_dir(missing);
        bool null_no = !zcl_path_is_dir(NULL);
        (void)test_rm_rf_recursive(dir);
        ASSERT(joined && made);
        ASSERT(dir_yes);
        ASSERT(file_no);
        ASSERT(missing_no);
        ASSERT(null_no);
    } TEST_END
    return failures;
}

static int pu_lower_hex(void)
{
    int failures = 0;
    TEST_CASE("path_util: lower hex accepts exactly len lowercase hex characters") {
        ASSERT(zcl_is_lower_hex("0123456789abcdef", 16));
        ASSERT(zcl_is_lower_hex("", 0));
        ASSERT(!zcl_is_lower_hex("00FF", 4));
        ASSERT(!zcl_is_lower_hex("00fg", 4));
        ASSERT(!zcl_is_lower_hex("00f", 4));
        ASSERT(!zcl_is_lower_hex("00ff0", 4));
        ASSERT(!zcl_is_lower_hex(NULL, 0));
    } TEST_END
    return failures;
}

int test_path_util(void)
{
    return pu_join() + pu_is_dir() + pu_lower_hex();
}
