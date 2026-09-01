/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * block_prefetch — a bounded, supervised block-body read-ahead worker.
 *
 * WHY: the reducer fold is IO-bound on the LEADING body stage (body_persist /
 * body_fetch during a from-disk refold): each height is a cold open()+pread()
 * of a blk*.dat frame that the drive thread waits on before it can fold. The
 * shared block_parse_cache (storage/block_parse_cache.h) already collapses the
 * FIVE re-reads the downstream stages would each do — but the LEADING read is
 * still cold. This worker overlaps the NEXT window's cold reads with the
 * CURRENT batch's fold: given the fold's current height H it warms the OS page
 * cache for heights [H+lead, H+lead+window) AHEAD of the drive, so when the
 * drive's own pread arrives the pages are resident and it does not block on a
 * disk seek.
 *
 * The warming primitive first PROBES residency with preadv2(RWF_NOWAIT): a
 * successful probe means the pages are already cached (a "hit" — nothing to
 * do); an EAGAIN means the pages are cold (a "nowait_miss"), and only then does
 * it issue a blocking pread to warm them (and optionally retain the raw bytes
 * in a bounded LRU). On kernels without RWF_NOWAIT it degrades to always
 * warming (no probe) — correct, just no hit/miss telemetry.
 *
 * FAIL-SAFE: the fold NEVER waits on this worker. A resolve failure, read
 * failure, or a dead worker is a no-op — the drive reads the body itself
 * exactly as today (block_parse_cache falls back to read_block_from_disk_pread).
 * There is no correctness dependency: warming only changes WHEN bytes are read
 * into the page cache, never WHAT bytes the fold deserializes.
 *
 * DECOUPLED: this module owns no chain state. The current fold height and the
 * per-height on-disk position are supplied by caller callbacks (the production
 * adapter wraps active_chain_at + the block_index; a test supplies a synthetic
 * mapping), so the worker never touches main_state and stays trivially
 * unit-testable.
 *
 * DEFAULT OFF: enable-by-default awaits a live measured win on a real datadir
 * (a page-cache warm only helps on a filesystem that can actually evict — a
 * tmpfs/ramdisk keeps every page resident, so the sandbox cannot demonstrate
 * the win). See tests/harness/src/test_block_prefetch.c for the mechanism proof.
 */
#ifndef ZCL_STORAGE_BLOCK_PREFETCH_H
#define ZCL_STORAGE_BLOCK_PREFETCH_H

#include "chain/chain.h" /* struct disk_block_pos */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h> /* ssize_t */

/* Runtime configuration. Populate with block_prefetch_config_default() then
 * override fields. Copied by value at start; later edits have no effect until
 * the next start. */
struct block_prefetch_config {
    bool   enabled;   /* master switch — default OFF (see header rationale) */
    size_t max_bytes; /* raw-body LRU byte budget; 0 ⇒ page-cache warm only.
                       * Default ~64 MiB. */
    int    window;    /* heights warmed ahead per pass (default 32) */
    int    lead;      /* warm starting at cursor+lead (default = window, i.e.
                       * one full batch ahead so the CURRENT batch's fold
                       * overlaps the NEXT batch's reads) */
    bool   force_warm; /* skip the RWF_NOWAIT residency probe and ALWAYS issue
                        * the warming pread (and LRU-retain). Useful on a known-
                        * cold cold-start where every probe would miss anyway,
                        * and to exercise the warm/LRU path deterministically in
                        * tests. Default false (probe first, warm only on miss). */
};

/* Fill `cfg` with the built-in defaults (enabled=false). */
void block_prefetch_config_default(struct block_prefetch_config *cfg);

/* Leading-fold-height source. Returns true and sets *out_height to the height
 * the fold is currently processing; false when unavailable (the worker idles
 * and warms nothing). Called from the worker thread. */
typedef bool (*block_prefetch_cursor_fn)(void *user, int32_t *out_height);

/* Resolve the on-disk position of `height`. Returns true + fills *out for a
 * have-data block; false for a not-available height (a gap — skipped). MUST be
 * safe to call from the worker thread concurrently with the fold (the same
 * lock-free active_chain_at + block_index snapshot pattern bg_validation and
 * pv_lookahead already run alongside the drive). Called from the worker. */
typedef bool (*block_prefetch_pos_fn)(void *user, int32_t height,
                                      struct disk_block_pos *out);

/* Start the worker. `datadir` locates blk*.dat. On cfg->enabled==false this is
 * a no-op that returns true (started=false). Registers a supervised child on
 * the liveness tree and spawns one worker thread. Returns false only on a real
 * failure to start when enabled (thread spawn / bad args); the caller treats a
 * false as "no prefetch" and folds exactly as today. Idempotent-guarded: a
 * second start while running is a logged no-op returning false. */
bool block_prefetch_start(const char *datadir,
                          const struct block_prefetch_config *cfg,
                          block_prefetch_cursor_fn cursor_fn, void *cursor_user,
                          block_prefetch_pos_fn pos_fn, void *pos_user);

/* Stop + join the worker and clear the LRU. Safe without a prior start; safe to
 * call repeatedly. */
void block_prefetch_stop(void);

/* True between a successful enabled start and stop. */
bool block_prefetch_running(void);

/* ── Stats (lock-free atomic reads) ──────────────────────────────────── */
uint64_t block_prefetch_warm_hits(void);     /* probe found pages resident */
uint64_t block_prefetch_warmed(void);        /* blocking pread issued to warm */
uint64_t block_prefetch_nowait_misses(void); /* RWF_NOWAIT reported not-resident */
size_t   block_prefetch_lru_bytes(void);     /* raw bytes currently retained */
size_t   block_prefetch_lru_count(void);     /* entries currently retained */

/* Optional fast path: copy a retained raw body for `pos` into `buf`. Returns
 * bytes copied on an LRU hit, -1 on a miss or when buflen is too small. A
 * reader may consult this before a disk read; not wired into the hot read path
 * (documented seam) so the LRU is presently a measured-capacity structure, not
 * yet a fold fast path. Thread-safe. */
ssize_t block_prefetch_lru_get(const struct disk_block_pos *pos,
                               uint8_t *buf, size_t buflen);

/* Diagnostics registry dumper (CLAUDE.md "Adding state introspection").
 * `out` is caller-initialized; `key` is unused. Reentrant-safe. */
struct json_value;
bool block_prefetch_dump_state_json(struct json_value *out, const char *key);

#endif /* ZCL_STORAGE_BLOCK_PREFETCH_H */
