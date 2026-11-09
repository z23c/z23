/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * storage memory profile: the SQLite page-cache and mmap window of the
 * long-lived consensus.db and projection (progress.kv) connections.
 *
 * Folding history (IBD, refold, snapshot install) sweeps the whole file, so
 * the large open-time ceilings pay for themselves.  A node that only follows
 * the tip touches a small working set, yet the 1.6 GB consensus.db stayed
 * fully mapped and resident.  The steady profile caps each connection at
 * STORAGE_STEADY_MMAP_BYTES / STORAGE_STEADY_CACHE_KIB (never above that
 * connection's folding value); the folding profile restores the open-time
 * sizing.
 *
 * PRAGMA-only: cache_size and mmap_size change how SQLite holds and reads
 * pages, never which bytes are read or written, transaction boundaries or
 * durability. */
#ifndef ZCL_STORAGE_MEMORY_PROFILE_H
#define ZCL_STORAGE_MEMORY_PROFILE_H

#include <stdbool.h>
#include <stdint.h>

#define STORAGE_STEADY_MMAP_BYTES (64LL * 1024 * 1024)  /* 64 MiB */
#define STORAGE_STEADY_CACHE_KIB  (128LL * 1024)        /* 128 MiB */

/* Cap a folding-profile value at the steady ceiling. */
int64_t storage_memory_profile_steady_mmap(int64_t folding_mmap_bytes);
int64_t storage_memory_profile_steady_cache_kib(int64_t folding_cache_kib);

enum storage_cache_state { STORAGE_CACHE_CLOSED, STORAGE_CACHE_READY, STORAGE_CACHE_ERROR };
struct storage_cache_sample { enum storage_cache_state state; int64_t bytes; };
struct storage_cache_usage { struct storage_cache_sample progress, projection; };
struct storage_cache_snapshot {
    struct storage_cache_usage usage;
    int64_t started_unix, finished_unix; /* -1 when the clock is unavailable. */
};
enum storage_cache_snapshot_status { STORAGE_CACHE_SNAPSHOT_READY, STORAGE_CACHE_SNAPSHOT_UNAVAILABLE, STORAGE_CACHE_SNAPSHOT_BUSY };
/* Try-only copy of the last post-trim sample; never acquires a DB lock. */
enum storage_cache_snapshot_status storage_memory_profile_cached(struct storage_cache_snapshot *out);
#ifdef ZCL_TESTING
bool storage_memory_profile_test_publish(const struct storage_cache_snapshot *sample);
void storage_memory_profile_test_reset(void);
bool storage_memory_profile_test_guard(bool acquire);
#endif
/* Independent snapshots, not RSS or mmap residency. Returns false for a NULL
 * output; each sample separately names a closed store or SQLite error. */
bool storage_memory_profile_read_cache(struct storage_cache_usage *out);
void storage_memory_profile_log_cache(void);

/* Switch every open store connection to the steady (true) or folding (false)
 * profile.  Each PRAGMA is issued under the lock that owns that connection.
 * Logs one line per call.  Returns false if an open connection refused the
 * PRAGMA.  Stores that are not open are skipped. */
bool storage_memory_profile_set(bool steady);

/* Last profile requested through storage_memory_profile_set(); false
 * (folding) until the first steady request. */
bool storage_memory_profile_is_steady(void);

#endif
