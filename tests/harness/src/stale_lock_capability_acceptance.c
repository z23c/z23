/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Verify Windows stale-lock checks retain identity-bound authority. */
#if defined(_WIN32)

#include "platform/os_proc.h"
#include "platform/private_file.h"

#include <stdio.h>
#include <windows.h>

int main(void)
{
    if (os_proc_pid_liveness(GetCurrentProcessId()) !=
            OS_PROC_LIVENESS_RUNNING ||
        os_proc_pid_liveness(UINT32_MAX) != OS_PROC_LIVENESS_DEAD)
        return 1;

    char lock[MAX_PATH], replacement[MAX_PATH];
    snprintf(lock, sizeof(lock), "stale-lock-%lu.tmp",
             (unsigned long)GetCurrentProcessId());
    snprintf(replacement, sizeof(replacement), "stale-lock-%lu.new",
             (unsigned long)GetCurrentProcessId());
    struct platform_private_file held, other;
    struct platform_private_file_identity identity;
    platform_private_file_init(&held);
    platform_private_file_init(&other);
    if (!platform_private_file_create(lock, &held) ||
        !platform_private_file_identity(&held, &identity) ||
        !platform_private_file_create(replacement, &other))
        return 1;
    platform_private_file_close(&other);

    /* The verified handle denies name substitution on Windows. */
    if (MoveFileExA(replacement, lock, MOVEFILE_REPLACE_EXISTING) ||
        !platform_private_file_retire_if_identity(&held, lock, &identity))
        return 1;
    if (!platform_private_file_open_locked(replacement, &other) ||
        !platform_private_file_retire(&other, replacement))
        return 1;
    puts("stale_lock_capability_acceptance: PASS");
    return 0;
}

#else
typedef int stale_lock_capability_acceptance_not_built;
#endif
