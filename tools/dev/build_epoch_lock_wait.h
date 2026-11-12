/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Bounded exclusive flock for the compile-epoch tools. The caller
 *          already holds `fd` open on `lock_file`. On success the lock stays
 *          held on that open file description after this call returns. */

#ifndef ZCL_BUILD_EPOCH_LOCK_WAIT_H
#define ZCL_BUILD_EPOCH_LOCK_WAIT_H

/* Acquire an exclusive flock on `fd`.
 * ZCL_BUILD_EPOCH_LOCK_TIMEOUT is a positive integer number of seconds
 * (default 120). Returns 0 with the lock held.
 * Returns 1 and writes one stderr line when the timeout is invalid or the
 * wait expires. err_fd < 0 writes to stderr.
 * Does not close `fd` and does not unlock it. */
int zcl_build_epoch_flock_bounded(const char *tag, int fd,
                                  const char *lock_file, const char *kind,
                                  int err_fd);

#endif
