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

/* Switch every open store connection to the steady (true) or folding (false)
 * profile.  Each PRAGMA is issued under the lock that owns that connection.
 * Logs one line per call.  Returns false if an open connection refused the
 * PRAGMA.  Stores that are not open are skipped. */
bool storage_memory_profile_set(bool steady);

/* Last profile requested through storage_memory_profile_set(); false
 * (folding) until the first steady request. */
bool storage_memory_profile_is_steady(void);

#endif
