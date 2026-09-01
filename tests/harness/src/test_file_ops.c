/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "test/test_core.h"
#include "config/file_ops.h"
#include <unistd.h>

static bool write_text_file(const char *path, const char *contents)
{
    FILE *f = fopen(path, "wb");
    if (!f)
        return false;
    size_t len = strlen(contents);
    bool ok = fwrite(contents, 1, len, f) == len;
    fclose(f);
    return ok;
}

static bool read_text_file(const char *path, char *out, size_t out_size)
{
    FILE *f = fopen(path, "rb");
    if (!f || out_size == 0)
        return false;
    size_t n = fread(out, 1, out_size - 1, f);
    out[n] = '\0';
    fclose(f);
    return true;
}

static int test_dir_copy_success(void)
{
    int failures = 0;

    TEST("file_ops dir_copy copies regular files and reports success") {
        char root[] = "/tmp/zcl_file_ops_success_XXXXXX";
        char *dir = mkdtemp(root);
        char src[1024], dst[1024], a[1024], b[1024], copied[1024];
        char buf[64];
        bool ok = dir != NULL;

        snprintf(src, sizeof(src), "%s/src", dir ? dir : "");
        snprintf(dst, sizeof(dst), "%s/dst", dir ? dir : "");
        snprintf(a, sizeof(a), "%s/one.txt", src);
        snprintf(b, sizeof(b), "%s/two.txt", src);
        snprintf(copied, sizeof(copied), "%s/two.txt", dst);

        ok = ok && mkdir(src, 0700) == 0;
        ok = ok && write_text_file(a, "alpha");
        ok = ok && write_text_file(b, "beta");
        ok = ok && dir_copy(src, dst);
        ok = ok && read_text_file(copied, buf, sizeof(buf));
        ok = ok && strcmp(buf, "beta") == 0;

        if (dir)
            dir_remove_tree(dir);
        ASSERT(ok);
        PASS();
    } _test_next:;

    return failures;
}

static int test_file_copy_overwrites_regular_files(void)
{
    int failures = 0;

    TEST("file_ops file_copy overwrites files and rejects directories") {
        char root[] = "/tmp/zcl_file_copy_XXXXXX";
        char *dir = mkdtemp(root);
        char src[1024], dst[1024], bad_src[1024];
        char buf[64];
        bool ok = dir != NULL;

        snprintf(src, sizeof(src), "%s/src.txt", dir ? dir : "");
        snprintf(dst, sizeof(dst), "%s/dst.txt", dir ? dir : "");
        snprintf(bad_src, sizeof(bad_src), "%s/not-a-file", dir ? dir : "");

        ok = ok && write_text_file(src, "new");
        ok = ok && write_text_file(dst, "old");
        ok = ok && file_copy(src, dst);
        ok = ok && read_text_file(dst, buf, sizeof(buf));
        ok = ok && strcmp(buf, "new") == 0;
        ok = ok && mkdir(bad_src, 0700) == 0;
        ok = ok && !file_copy(bad_src, dst);

        if (dir)
            dir_remove_tree(dir);
        ASSERT(ok);
        PASS();
    } _test_next:;

    return failures;
}

static int test_dir_copy_partial_failure(void)
{
    int failures = 0;

    TEST("file_ops dir_copy fails closed when a source entry cannot be copied") {
        char root[] = "/tmp/zcl_file_ops_partial_XXXXXX";
        char *dir = mkdtemp(root);
        char src[1024], dst[1024], ok_file[1024], bad_dir[1024];
        bool ok = dir != NULL;

        snprintf(src, sizeof(src), "%s/src", dir ? dir : "");
        snprintf(dst, sizeof(dst), "%s/dst", dir ? dir : "");
        snprintf(ok_file, sizeof(ok_file), "%s/ok.txt", src);
        snprintf(bad_dir, sizeof(bad_dir), "%s/not-a-file", src);

        ok = ok && mkdir(src, 0700) == 0;
        ok = ok && write_text_file(ok_file, "ok");
        ok = ok && mkdir(bad_dir, 0700) == 0;
        ok = ok && !dir_copy(src, dst);

        if (dir)
            dir_remove_tree(dir);
        ASSERT(ok);
        PASS();
    } _test_next:;

    return failures;
}

static int test_block_files_copy_rev_failure(void)
{
    int failures = 0;

    TEST("file_ops block_files_copy fails when rev file copy fails") {
        char root[] = "/tmp/zcl_block_files_fail_XXXXXX";
        char *dir = mkdtemp(root);
        char src[1024], dst[1024], blk[1024], rev_dir[1024];
        bool ok = dir != NULL;
        int copied = 0;

        snprintf(src, sizeof(src), "%s/src", dir ? dir : "");
        snprintf(dst, sizeof(dst), "%s/dst", dir ? dir : "");
        snprintf(blk, sizeof(blk), "%s/blk00000.dat", src);
        snprintf(rev_dir, sizeof(rev_dir), "%s/rev00000.dat", src);

        ok = ok && mkdir(src, 0700) == 0;
        ok = ok && mkdir(dst, 0700) == 0;
        ok = ok && write_text_file(blk, "block");
        ok = ok && mkdir(rev_dir, 0700) == 0;
        copied = ok ? block_files_copy(src, dst) : 0;
        ok = ok && copied == -1;

        if (dir)
            dir_remove_tree(dir);
        ASSERT(ok);
        PASS();
    } _test_next:;

    return failures;
}

int test_file_ops(void)
{
    int failures = 0;

    failures += test_file_copy_overwrites_regular_files();
    failures += test_dir_copy_success();
    failures += test_dir_copy_partial_failure();
    failures += test_block_files_copy_rev_failure();

    return failures;
}
