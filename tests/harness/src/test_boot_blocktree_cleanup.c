/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "test/test_core.h"

#include "config/boot_blocktree_cleanup.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define BBC_CHECK(name, expr) do {                                      \
    printf("boot_blocktree_cleanup: %s... ", (name));                 \
    if (expr) printf("OK\n");                                         \
    else { printf("FAIL\n"); failures++; }                            \
} while (0)

static bool bbc_mkdir(const char *path)
{
    return mkdir(path, 0700) == 0 || errno == EEXIST;
}

static bool bbc_write_file(const char *path, const char *text)
{
    FILE *f = fopen(path, "wb");
    if (!f)
        return false;
    if (text && fputs(text, f) < 0) {
        fclose(f);
        return false;
    }
    return fclose(f) == 0;
}

static bool bbc_make_blocks_index(char *lock_path, size_t lock_path_n,
                                  const char *dir)
{
    char blocks[512];
    char index[512];
    int n1 = snprintf(blocks, sizeof(blocks), "%s/blocks", dir);
    int n2 = snprintf(index, sizeof(index), "%s/blocks/index", dir);
    int n3 = snprintf(lock_path, lock_path_n, "%s/blocks/index/LOCK", dir);
    if (n1 < 0 || (size_t)n1 >= sizeof(blocks) ||
        n2 < 0 || (size_t)n2 >= sizeof(index) ||
        n3 < 0 || (size_t)n3 >= lock_path_n)
        return false;
    return bbc_mkdir(blocks) && bbc_mkdir(index);
}

static bool bbc_make_nested_dir(const char *dir, const char *name,
                                char *out_path, size_t out_path_n)
{
    char nested[512];
    char file_path[512];
    int n1 = snprintf(out_path, out_path_n, "%s/%s", dir, name);
    int n2 = snprintf(nested, sizeof(nested), "%s/%s/sub", dir, name);
    int n3 = snprintf(file_path, sizeof(file_path), "%s/file.txt", nested);
    if (n1 < 0 || (size_t)n1 >= out_path_n ||
        n2 < 0 || (size_t)n2 >= sizeof(nested) ||
        n3 < 0 || (size_t)n3 >= sizeof(file_path))
        return false;
    return bbc_mkdir(out_path) && bbc_mkdir(nested) &&
           bbc_write_file(file_path, "scratch");
}

int test_boot_blocktree_cleanup(void)
{
    int failures = 0;

    {
        char dir[256];
        char lock_path[512];
        char blocktree_path[512];
        test_make_tmpdir(dir, sizeof(dir), "boot_blocktree_cleanup", "lock");
        bool ok = bbc_make_blocks_index(lock_path, sizeof(lock_path), dir);
        ok = ok && bbc_write_file(lock_path, "stale\n");

        struct boot_blocktree_cleanup_result r =
            boot_blocktree_cleanup_prepare(dir, blocktree_path,
                                           sizeof(blocktree_path));
        char expected[512];
        snprintf(expected, sizeof(expected), "%s/blocks/index", dir);
        BBC_CHECK("removes stale block index lock",
                  ok && r.blocktree_path_ready &&
                  strcmp(blocktree_path, expected) == 0 &&
                  r.block_index_lock_removed &&
                  access(lock_path, F_OK) != 0);
        test_rm_rf_recursive(dir);
    }

    {
        char dir[256];
        char scratch[512];
        char blocktree_path[512];
        test_make_tmpdir(dir, sizeof(dir), "boot_blocktree_cleanup", "tmp");
        bool ok = bbc_make_nested_dir(dir, "chainstate_import_tmp",
                                      scratch, sizeof(scratch));

        struct boot_blocktree_cleanup_result r =
            boot_blocktree_cleanup_prepare(dir, blocktree_path,
                                           sizeof(blocktree_path));
        BBC_CHECK("removes chainstate_import_tmp tree",
                  ok && r.chainstate_import_tmp_removed &&
                  access(scratch, F_OK) != 0);
        test_rm_rf_recursive(dir);
    }

    {
        char dir[256];
        char scratch[512];
        char blocktree_path[512];
        test_make_tmpdir(dir, sizeof(dir), "boot_blocktree_cleanup", "snap");
        bool ok = bbc_make_nested_dir(dir, ".legacy_ldb_snap",
                                      scratch, sizeof(scratch));

        struct boot_blocktree_cleanup_result r =
            boot_blocktree_cleanup_prepare(dir, blocktree_path,
                                           sizeof(blocktree_path));
        BBC_CHECK("removes legacy ldb snapshot tree",
                  ok && r.legacy_ldb_snap_removed &&
                  access(scratch, F_OK) != 0);
        test_rm_rf_recursive(dir);
    }

    {
        char dir[256];
        char scratch_file[512];
        char blocktree_path[512];
        test_make_tmpdir(dir, sizeof(dir), "boot_blocktree_cleanup", "file");
        int n = snprintf(scratch_file, sizeof(scratch_file),
                         "%s/chainstate_import_tmp", dir);
        bool ok = n >= 0 && (size_t)n < sizeof(scratch_file);
        ok = ok && bbc_write_file(scratch_file, "not a directory");

        struct boot_blocktree_cleanup_result r =
            boot_blocktree_cleanup_prepare(dir, blocktree_path,
                                           sizeof(blocktree_path));
        BBC_CHECK("keeps same-named regular file",
                  ok && !r.chainstate_import_tmp_removed &&
                  access(scratch_file, F_OK) == 0);
        test_rm_rf_recursive(dir);
    }

    {
        char blocktree_path[512];
        struct boot_blocktree_cleanup_result r =
            boot_blocktree_cleanup_prepare(NULL, blocktree_path,
                                           sizeof(blocktree_path));
        BBC_CHECK("invalid datadir fails closed",
                  r.invalid_datadir && !r.blocktree_path_ready &&
                  blocktree_path[0] == '\0');
    }

    {
        char tiny[8];
        struct boot_blocktree_cleanup_result r =
            boot_blocktree_cleanup_prepare(".", tiny, sizeof(tiny));
        BBC_CHECK("truncated output path fails closed",
                  r.truncated_path && !r.blocktree_path_ready &&
                  tiny[0] == '\0');
    }

    return failures;
}
