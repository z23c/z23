/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Checkout-wide flock shared by foreground make and the dev watcher.
 *          One entry serves the Makefile host tool and in-process callers
 *          (the train gate takes the lock before it spawns make). */

#ifndef ZCL_CHECKOUT_LOCK_H
#define ZCL_CHECKOUT_LOCK_H

/* A hold taken by zcl_checkout_lock_enter. Zero it only by calling enter. */
struct zcl_checkout_lock_hold {
    int fd;
    int active;
    char *saved;
};

/* Acquire the lock at lock_file.
 * Returns 0 when the caller may run its command. hold->active is 1 when
 * this call took the flock and exported ZCL_CHECKOUT_LOCK_HELD=1; it is 0
 * when that variable was already 1 and no flock was taken.
 * Returns 99 when mode is "watcher" and the lock is already held. stderr
 * receives "deferred: foreground build holds the lock".
 * Returns 2 on an unknown mode or an I/O failure. stderr starts with
 * "checkout-lock:". err_fd < 0 writes to stderr.
 * Pair a 0 return with zcl_checkout_lock_leave. */
int zcl_checkout_lock_enter(struct zcl_checkout_lock_hold *hold,
                            const char *mode, const char *lock_file,
                            int err_fd);

/* Drop a hold from enter. Safe when enter did not take the flock. */
void zcl_checkout_lock_leave(struct zcl_checkout_lock_hold *hold);

/* Run argv under the lock. Returns the command status, 99, or 2.
 * A null or empty argv is a missing command (exit 2). */
int zcl_checkout_lock_run(const char *mode, const char *lock_file,
                          const char *const *argv, int err_fd);

#endif
