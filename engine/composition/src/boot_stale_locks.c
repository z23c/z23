/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "config/boot_stale_locks.h"
#include "platform/os_proc.h"
#include "platform/private_file.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static bool boot_stale_locks_path(char *out, size_t out_n,
                                  const char *datadir,
                                  const char *suffix)
{
    if (!out || out_n == 0 || !datadir || !*datadir || !suffix || !*suffix)
        return false;

    int n = snprintf(out, out_n, "%s/%s", datadir, suffix);
    return n >= 0 && (size_t)n < out_n;
}

static bool boot_stale_locks_read_pid(struct platform_private_file *lock,
                                      long *pid_out)
{
    if (!lock || !pid_out)
        return false;
    uint64_t size = 0;
    if (!platform_private_file_size(lock, &size) || size == 0 || size >= 32)
        return false;

    char pidbuf[32] = {0};
    if (!platform_private_file_read_at(lock, pidbuf, (size_t)size, 0))
        return false;

    char *end = NULL;
    errno = 0;
    long pid = strtol(pidbuf, &end, 10);
    if (errno != 0 || !end || end == pidbuf || pid <= 0)
        return false;

    *pid_out = pid;
    return true;
}

static void boot_stale_locks_check_pid_lock(const char *path,
                                            const char *label,
                                            bool print_running,
                                            bool *removed_out,
                                            bool *running_out)
{
    if (!path || !label)
        return;

    struct platform_private_file lock;
    platform_private_file_init(&lock);
    if (!platform_private_file_open_locked(path, &lock))
        return;
    struct platform_private_file_identity identity;
    long pid = 0;
    if (!platform_private_file_identity(&lock, &identity) ||
        !boot_stale_locks_read_pid(&lock, &pid)) {
        platform_private_file_close(&lock);
        return;
    }

    enum os_proc_liveness liveness = os_proc_pid_liveness((uint64_t)pid);
    if (liveness == OS_PROC_LIVENESS_DEAD) {
        printf("Removing stale %s LOCK (pid %ld dead)\n", label, pid);
        if (platform_private_file_retire_if_identity(&lock, path, &identity) &&
            removed_out)
            *removed_out = true;
        else
            platform_private_file_close(&lock);
        return;
    }

    platform_private_file_close(&lock);
    if (running_out)
        *running_out = true;
    if (print_running) {
        fprintf(stderr,
                "ERROR: LevelDB locked by pid %ld (still running)\n"
                "Kill the other process or use a different datadir.\n",
                pid);
    }
}

struct boot_stale_locks_result
boot_stale_locks_preflight(const char *datadir)
{
    struct boot_stale_locks_result result = {0};
    if (!datadir || !*datadir) {
        fprintf(stderr, "[boot] Cannot inspect stale locks: invalid datadir\n");
        return result;
    }

    char lock_path[1024];
    if (!boot_stale_locks_path(lock_path, sizeof(lock_path), datadir,
                               "blocks/index/LOCK")) {
        fprintf(stderr, "[boot] Cannot inspect stale locks: datadir too long\n");
        return result;
    }
    boot_stale_locks_check_pid_lock(lock_path, "LevelDB", true,
                                    &result.blocks_index_lock_removed,
                                    &result.blocks_index_lock_running);

    if (!boot_stale_locks_path(lock_path, sizeof(lock_path), datadir,
                               "chainstate/LOCK")) {
        fprintf(stderr, "[boot] Cannot inspect stale locks: datadir too long\n");
        return result;
    }
    boot_stale_locks_check_pid_lock(lock_path, "chainstate", false,
                                    &result.chainstate_lock_removed,
                                    &result.chainstate_lock_running);

    if (!boot_stale_locks_path(lock_path, sizeof(lock_path), datadir,
                               "node.db-wal")) {
        fprintf(stderr, "[boot] Cannot inspect stale locks: datadir too long\n");
        return result;
    }
    if (access(lock_path, F_OK) == 0) {
        result.sqlite_wal_present = true;
        printf("SQLite WAL file exists (normal after crash recovery)\n");
    }

    return result;
}
