/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: implementation of platform/ram_scratch.h.
 *
 * POSIX arm: Linux mounts a tmpfs at /dev/shm on every mainstream
 * distribution, and it is the one RAM-backed path a program may assume by
 * name. It is still checked rather than trusted — a container can mount it
 * tiny, read-only, or not at all — and the free-space guard is what keeps a
 * caller from spending the machine's memory on scratch files.
 *
 * Windows arm: there is no equivalent the OS guarantees, so the answer is
 * always no and the caller keeps its ordinary location. */
#include "platform/ram_scratch.h"

#include "platform/disk_space.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if !defined(_WIN32)
#include <sys/stat.h>
#include <unistd.h>
#endif

#define RAM_SCRATCH_DEFAULT "/dev/shm"

bool platform_ram_scratch_root(char *out_path, size_t out_cap,
                               uint64_t min_free_bytes)
{
    if (!out_path || out_cap == 0) return false;
    out_path[0] = '\0';
    if (min_free_bytes == 0)
        min_free_bytes = PLATFORM_RAM_SCRATCH_MIN_FREE_BYTES;
#if defined(_WIN32)
    (void)min_free_bytes;
    return false;
#else
    /* An override that is empty, or not absolute, is a refusal — never a
     * silent fall back to the default, which would answer a question the
     * caller did not ask. */
    const char *candidate = getenv("ZCL_RAM_SCRATCH_ROOT");
    if (candidate && candidate[0] != '/') return false;
    if (!candidate) candidate = RAM_SCRATCH_DEFAULT;
    struct stat st;
    if (stat(candidate, &st) != 0 || !S_ISDIR(st.st_mode)) return false;
    if (access(candidate, W_OK | X_OK) != 0) return false;
    uint64_t available = 0;
    if (!platform_disk_space_available(candidate, &available) ||
        available < min_free_bytes)
        return false;
    size_t len = strlen(candidate);
    if (len == 0 || len + 1 > out_cap) return false;
    memcpy(out_path, candidate, len + 1);
    return true;
#endif
}
