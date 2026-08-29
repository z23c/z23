/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Retained, owner-private cross-process lock file. */
#ifndef ZCL_PLATFORM_PROCESS_LOCK_H
#define ZCL_PLATFORM_PROCESS_LOCK_H

#include "platform/private_file.h"

struct platform_process_lock {
    struct platform_private_file file;
    bool held;
};

void platform_process_lock_init(struct platform_process_lock *lock);
/* Nonblocking exclusive acquisition. The opened regular file is retained for
 * the lock lifetime and must be private/no-reparse. `create` permits securely
 * creating an absent lock file; false requires it to exist. */
bool platform_process_lock_try_acquire(struct platform_process_lock *lock,
                                       const char *path, bool create);
/* Waiting exclusive acquisition, for a lock whose holder must be waited for
 * rather than reported as a failure — a durable work queue whose mutation
 * would otherwise be silently dropped on contention. Same retained,
 * owner-private file and same release-on-crash behaviour as the nonblocking
 * call; a given lock path must use one or the other, never both. */
bool platform_process_lock_acquire(struct platform_process_lock *lock,
                                   const char *path, bool create);
void platform_process_lock_release(struct platform_process_lock *lock);

#endif
