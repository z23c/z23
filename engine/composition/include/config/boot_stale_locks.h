/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#ifndef ZCL_CONFIG_BOOT_STALE_LOCKS_H
#define ZCL_CONFIG_BOOT_STALE_LOCKS_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Startup preflight for lock artifacts left by crashed legacy storage paths.
 * The result is primarily for tests; boot ignores it and preserves the existing
 * best-effort posture before SQLite opens. */
struct boot_stale_locks_result {
    bool blocks_index_lock_removed;
    bool blocks_index_lock_running;
    bool chainstate_lock_removed;
    bool chainstate_lock_running;
    bool sqlite_wal_present;
};

struct boot_stale_locks_result
boot_stale_locks_preflight(const char *datadir);

#ifdef __cplusplus
}
#endif

#endif /* ZCL_CONFIG_BOOT_STALE_LOCKS_H */
