/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "test/test_core.h"

#include "config/boot_stale_locks.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define BSL_CHECK(name, expr) do {                                      \
    printf("boot_stale_locks: %s... ", (name));                       \
    if (expr) printf("OK\n");                                         \
    else { printf("FAIL\n"); failures++; }                            \
} while (0)

static bool bsl_write_file(const char *path, const char *text)
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

static bool bsl_mkdir(const char *path)
{
    return mkdir(path, 0700) == 0 || errno == EEXIST;
}

static bool bsl_make_blocks_index(char *lock_path, size_t lock_path_n,
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
    return bsl_mkdir(blocks) && bsl_mkdir(index);
}

static bool bsl_make_chainstate(char *lock_path, size_t lock_path_n,
                                const char *dir)
{
    char chainstate[512];
    int n1 = snprintf(chainstate, sizeof(chainstate), "%s/chainstate", dir);
    int n2 = snprintf(lock_path, lock_path_n, "%s/chainstate/LOCK", dir);
    if (n1 < 0 || (size_t)n1 >= sizeof(chainstate) ||
        n2 < 0 || (size_t)n2 >= lock_path_n)
        return false;
    return bsl_mkdir(chainstate);
}

int test_boot_stale_locks(void)
{
    int failures = 0;

    {
        char dir[256];
        char lock_path[512];
        test_make_tmpdir(dir, sizeof(dir), "boot_stale_locks", "blocks_stale");
        bool ok = bsl_make_blocks_index(lock_path, sizeof(lock_path), dir);
        ok = ok && bsl_write_file(lock_path, "99999999\n");

        struct boot_stale_locks_result r =
            boot_stale_locks_preflight(dir);
        BSL_CHECK("removes stale blocks index lock",
                  ok && r.blocks_index_lock_removed &&
                  !r.blocks_index_lock_running &&
                  access(lock_path, F_OK) != 0);
        test_rm_rf_recursive(dir);
    }

    {
        char dir[256];
        char lock_path[512];
        char pid_text[64];
        test_make_tmpdir(dir, sizeof(dir), "boot_stale_locks", "blocks_live");
        bool ok = bsl_make_blocks_index(lock_path, sizeof(lock_path), dir);
        snprintf(pid_text, sizeof(pid_text), "%ld\n", (long)getpid());
        ok = ok && bsl_write_file(lock_path, pid_text);

        struct boot_stale_locks_result r =
            boot_stale_locks_preflight(dir);
        BSL_CHECK("keeps running blocks index lock",
                  ok && !r.blocks_index_lock_removed &&
                  r.blocks_index_lock_running &&
                  access(lock_path, F_OK) == 0);
        test_rm_rf_recursive(dir);
    }

    {
        char dir[256];
        char lock_path[512];
        test_make_tmpdir(dir, sizeof(dir), "boot_stale_locks", "chain_stale");
        bool ok = bsl_make_chainstate(lock_path, sizeof(lock_path), dir);
        ok = ok && bsl_write_file(lock_path, "99999999\n");

        struct boot_stale_locks_result r =
            boot_stale_locks_preflight(dir);
        BSL_CHECK("removes stale chainstate lock",
                  ok && r.chainstate_lock_removed &&
                  !r.chainstate_lock_running &&
                  access(lock_path, F_OK) != 0);
        test_rm_rf_recursive(dir);
    }

    {
        char dir[256];
        char wal_path[512];
        test_make_tmpdir(dir, sizeof(dir), "boot_stale_locks", "wal");
        int n = snprintf(wal_path, sizeof(wal_path), "%s/node.db-wal", dir);
        bool ok = n >= 0 && (size_t)n < sizeof(wal_path);
        ok = ok && bsl_write_file(wal_path, "wal data");

        struct boot_stale_locks_result r =
            boot_stale_locks_preflight(dir);
        BSL_CHECK("reports sqlite wal without deleting it",
                  ok && r.sqlite_wal_present &&
                  access(wal_path, F_OK) == 0);
        test_rm_rf_recursive(dir);
    }

    {
        struct boot_stale_locks_result r =
            boot_stale_locks_preflight(NULL);
        BSL_CHECK("invalid datadir fails closed",
                  !r.blocks_index_lock_removed &&
                  !r.blocks_index_lock_running &&
                  !r.chainstate_lock_removed &&
                  !r.chainstate_lock_running &&
                  !r.sqlite_wal_present);
    }

    return failures;
}
