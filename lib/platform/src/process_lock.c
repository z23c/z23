/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: implementation of platform/process_lock.h — wraps
 * platform_private_file's exclusive-create/lock/close around one retained
 * cross-process lock file, tracking `held` so acquiring twice or releasing
 * an unheld lock is a no-op rather than a double-lock/double-close. */
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
