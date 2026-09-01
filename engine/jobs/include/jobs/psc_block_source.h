/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * psc_block_source — the PRODUCTION block provider for the Parallel State
 * Compiler (jobs/psc_range_fold.h).
 *
 * P0 folded a fixture through an in-memory `psc_block_provider_fn`. P1 wires the
 * REAL block source: resolve height -> block_index via active_chain_at and read
 * the body via the lock-free positional reader read_block_from_disk_index_pread
 * — the SAME concurrent chain-reader + pread path bg_validation / pv_lookahead
 * already run ALONGSIDE the reducer fold. The injectable seam is the
 * psc_compile_range `provider` parameter itself: production passes
 * psc_prod_block_provider, tests pass their fixture provider — so the fold core
 * stays decoupled from block storage.
 *
 * THREAD-SAFETY: psc_compile_range calls the provider concurrently from K
 * worker threads for DISTINCT heights. active_chain_at is a lock-free window
 * read (an atomic load of chain[height], a value-snapshot of the block_index
 * pointer) and read_block_from_disk_index_pread is a stateless positional read
 * (its own contract: "Thread-safe, no shared state"), so psc_prod_block_provider
 * is safe under the worker pool with NO added locking. It reads bodies through a
 * FINALIZED range whose block_index slots do not mutate during the audit.
 */
#ifndef ZCL_JOBS_PSC_BLOCK_SOURCE_H
#define ZCL_JOBS_PSC_BLOCK_SOURCE_H

#include "jobs/psc_range_fold.h"   /* psc_block_provider_fn, struct block */

struct main_state;

/* Everything the production provider needs. `datadir` must outlive the compile.
 * Both fields are read-only for the duration of a compile and shared across the
 * K worker threads. */
struct psc_prod_source {
    struct main_state *ms;
    const char        *datadir;
};

/* psc_block_provider_fn over `struct psc_prod_source *user`. Resolves height ->
 * block_index via active_chain_at(&ms->chain_active, height); refuses a slot
 * without BLOCK_HAVE_DATA or a hash (returns false -> the compile aborts with a
 * "provider_failed" internal error, honoring the finalized-range contract that
 * every body in [lo,hi] is present); else reads the body into the caller-init'd
 * `blk` via read_block_from_disk_index_pread. */
bool psc_prod_block_provider(uint32_t height, struct block *blk, void *user);

/* Worker sizing for a PSC audit fold, mirroring pv_lookahead's cap discipline:
 * min(physical_cores, PSC_AUDIT_MAX_WORKERS), floor 1, with a ZCL_PSC_WORKERS
 * env override (clamped 1..PSC_AUDIT_MAX_WORKERS). The join shard count is left
 * to psc_compile_range's default (workers * 2). */
#define PSC_AUDIT_MAX_WORKERS 16
int psc_audit_default_workers(void);

#endif /* ZCL_JOBS_PSC_BLOCK_SOURCE_H */
