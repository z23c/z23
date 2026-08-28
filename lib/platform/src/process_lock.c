/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Hold owner-private cross-process locks through retained files. */
#include "platform/process_lock.h"

void platform_process_lock_init(struct platform_process_lock *lock)
{
    if (!lock) return;
    platform_private_file_init(&lock->file);
    lock->held = false;
}

bool platform_process_lock_try_acquire(struct platform_process_lock *lock,
                                       const char *path, bool create)
{
    if (!lock || !path || !path[0] || lock->held) return false;
    bool ok = create
        ? platform_private_file_open_locked_create(path, &lock->file)
        : platform_private_file_open_locked(path, &lock->file);
    lock->held = ok;
    return ok;
}

void platform_process_lock_release(struct platform_process_lock *lock)
{
    if (!lock) return;
    platform_private_file_close(&lock->file);
    lock->held = false;
}
