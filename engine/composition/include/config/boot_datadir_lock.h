/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#ifndef ZCL_CONFIG_BOOT_DATADIR_LOCK_H
#define ZCL_CONFIG_BOOT_DATADIR_LOCK_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Single-process guard for the selected datadir.
 *
 * Acquisition holds a nonblocking OS file lock until release.  The PID file is
 * retained after release and is diagnostic only; leaving the inode in place
 * avoids an unlink/recreate race that could admit two writers.  Any failure to
 * establish or durably record the lock fails closed. */
bool boot_datadir_lock_acquire(const char *datadir);
void boot_datadir_lock_release(void);

#ifdef __cplusplus
}
#endif

#endif /* ZCL_CONFIG_BOOT_DATADIR_LOCK_H */
