/* Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#ifndef ZCL_STORAGE_DISK_BLOCK_IO_H
#define ZCL_STORAGE_DISK_BLOCK_IO_H

#include "chain/chain.h"
#include "primitives/block.h"
#include <stdbool.h>
#include <stdio.h>

void get_block_pos_filename(char *buf, size_t buflen,
                            const char *datadir,
                            const struct disk_block_pos *pos,
                            const char *prefix);

FILE *open_disk_file(const char *datadir,
                     const struct disk_block_pos *pos,
                     const char *prefix, bool read_only);

static inline FILE *open_block_file(const char *datadir,
                                    const struct disk_block_pos *pos,
                                    bool read_only)
{
    return open_disk_file(datadir, pos, "blk", read_only);
}

static inline FILE *open_undo_file(const char *datadir,
                                   const struct disk_block_pos *pos,
                                   bool read_only)
{
    return open_disk_file(datadir, pos, "rev", read_only);
}

bool write_block_to_disk(struct block *b, struct disk_block_pos *pos,
                         const char *datadir,
                         const unsigned char message_start[4]);

/* ── Deferred block-body fdatasync (batched to a drain boundary) ──────
 * write_block_to_disk() normally fflush()es + fdatasync()s the blk*.dat fd
 * once per block. On the reducer fold / catch-up drain that per-block
 * fdatasync is an ext4 journal-commit barrier (the drive thread parks in
 * jbd2_log_wait_commit) — the dominant wait when the CPU is otherwise idle.
 *
 * In deferred mode write_block_to_disk() still fflush()es the stdio buffer to
 * the kernel (so a concurrent reader sees the bytes via the page cache) but
 * SKIPS the fdatasync, recording the (datadir, nFile) it wrote as pending.
 * disk_block_io_sync_pending() fdatasync()s every distinct pending file once
 * and clears the synced entries; a file touched across a rotation is simply
 * another pending entry, so all files a batch wrote are synced together.
 *
 * Crash-ordering invariant: the reducer drive enables deferred mode and the
 * stage drain fires disk_block_io_sync_pending() BEFORE its outer COMMIT (the
 * stage_batch_end pre-commit hook, util/stage.h). So no durable stage marker
 * (body_persist_log row, stage cursor) is committed while the block bytes it
 * references are still unsynced. Deferred mode is scoped to that drive; every
 * other write_block_to_disk() caller (import, tests) keeps the immediate
 * per-block fdatasync. Guarded by the same mutex write_block_to_disk() holds. */
void disk_block_io_set_deferred_sync(bool enabled);
bool disk_block_io_deferred_sync_enabled(void);

/* fdatasync every distinct blk*.dat file that a deferred write left pending,
 * then drop the successfully-synced entries. Returns false if any file could
 * not be synced (those entries are KEPT pending so a retry re-attempts them);
 * the caller must NOT let a durable marker commit on a false return. A no-op
 * (returns true) when nothing is pending — cheap to call on every commit. */
bool disk_block_io_sync_pending(void);

/* ── Scoped read fd cache (pread fast path) ───────────────────────────
 * read_block_from_disk_pread*() open()+close()es the blk*.dat file per block.
 * Between enter() and exit() (thread-local), the caller's thread reuses the
 * last-opened read fd when consecutive reads hit the same file, saving the
 * per-block open/close during a drain. Scope it ONLY around the reducer's
 * forward-fold read loop, where blk*.dat files are append-only and never
 * unlinked/recreated on the reading thread; exit() closes the cached fd. Every
 * reader outside the scope keeps the stateless open/close so a file replaced at
 * a reused path is never read through a stale fd. */
void disk_block_io_read_fd_cache_enter(void);
void disk_block_io_read_fd_cache_exit(void);

bool read_block_from_disk(struct block *b, const struct disk_block_pos *pos,
                          const char *datadir);

bool read_block_from_disk_index(struct block *b,
                                const struct block_index *pindex,
                                const char *datadir);

/* Close the read-only file handle cache (call on shutdown). */
void disk_block_io_close_cache(void);

/* Same as `disk_block_io_close_cache()` but assumes the caller
 * already holds the lock acquired via `disk_block_io_lock()`.
 * Use this when you need to invalidate the cache in the middle of
 * a larger critical section (e.g. the invalidate-then-unlink
 * sequence in block_pruning_service). Re-entering the public
 * close_cache from inside the lock self-deadlocks on the NORMAL
 * mutex. */
void disk_block_io_close_cache_while_locked(void);

/* ── Thread-safe pread()-based I/O for background threads ──────
 * These functions use POSIX open()/pread()/close() instead of the
 * shared FILE* cache. They are stateless and fully thread-safe
 * without any mutex — safe to call from bg_validation, bg_hash_verify,
 * or any other thread concurrently with the main P2P message loop.
 *
 * Use these for any background thread that reads block/undo files.
 * The main thread should continue using the cached FILE* path for
 * performance (sequential IBD benefits from the cache). */

/* Read raw bytes from a block/undo file at a given position.
 * Returns bytes read, or -1 on error. Thread-safe, no shared state. */
ssize_t disk_block_pread(const char *datadir, const struct disk_block_pos *pos,
                         const char *prefix, uint8_t *buf, size_t len);

/* Read and deserialize a block using pread(). Thread-safe.
 * Equivalent to read_block_from_disk() but without the FILE* cache.
 *
 * FRAMED POSITIONS ONLY. `pos` must name a record carrying the 8-byte
 * magic+size frame header, at either convention: the payload offset (frame at
 * pos-8, what a canonical block index stores) or the frame offset itself (what
 * some recovery/import paths hand over). A position with no frame at either is
 * REFUSED — it is provably not a block record, because every writer frames its
 * records (write_block_to_disk, the whole-file blk transfers in
 * net/file_service.c) and the sibling mmap reader (blocks_mmap_reader.c
 * bmr_get_payload) already refuses the same shape.
 *
 * This used to fall back to "read a fixed 2 MB window from the raw offset and
 * hand it to block_deserialize" — a guess dressed as a read, with only the
 * caller's downstream hash check between it and a wrong block. Measured live
 * (node1 2026-08-23: blk00050.dat hardlinked into a foreign live writer's
 * datadir, whose appends overwrote the indexed region) that guess produced
 * ~52% of the node's entire log volume in garbage-parse errors, plus 22.1k
 * "hash mismatch" lines where the garbage happened to parse. A dangling
 * position is now a named read failure; block_index_repair_pos_from_disk()
 * below is the repair for one that still has a copy elsewhere on disk. */
bool read_block_from_disk_pread(struct block *b,
                                const struct disk_block_pos *pos,
                                const char *datadir);

/* Profiled sibling used by the parse cache. The two optional outputs measure
 * file open/locate/pread/close and block_deserialize respectively. */
bool read_block_from_disk_pread_profiled(struct block *b,
                                         const struct disk_block_pos *pos,
                                         const char *datadir,
                                         uint64_t *read_us_out,
                                         uint64_t *parse_us_out);

/* Read and deserialize a block by index using pread(). Thread-safe.
 * Equivalent to read_block_from_disk_index() but without the FILE* cache. */
bool read_block_from_disk_index_pread(struct block *b,
                                      const struct block_index *pindex,
                                      const char *datadir);

/* Verify an existing BLOCK_HAVE_DATA claim by reading the indexed block
 * position and comparing the deserialized block hash to pindex->phashBlock.
 * Does not mutate pindex. */
bool block_index_have_data_readable(const struct block_index *pindex,
                                    const char *datadir);

/* Verify a block can be read back from `pos` and hashes to `pindex`.
 * Only then mark the index entry as BLOCK_HAVE_DATA at that position. */
bool block_index_set_have_data_verified(struct block_index *pindex,
                                        const struct disk_block_pos *pos,
                                        const char *datadir);

/* Hash-targeted self-heal for a stale/torn (nFile,nDataPos): scan the
 * entry's current blk file for a record whose block hash equals
 * *pindex->phashBlock and, on a hit, re-store the fresh position through
 * block_index_set_have_data_verified() (read-back + hash check included).
 * With scan_all_files, a same-file miss continues across the remaining blk
 * files (gap policy: stop after 3 consecutive misses); that full sweep is
 * throttled to one per 60 s per process so a mass-missing-bodies episode
 * (e.g. a blocks-less bundle) cannot turn every read failure into a full
 * blk-set walk. Returns false when no copy is found — the caller's
 * clear-and-refetch fallback then applies. Best-effort; stateless
 * (open/mmap/munmap, no FILE* cache), safe from background threads. */
bool block_index_repair_pos_from_disk(struct block_index *pindex,
                                      const char *datadir,
                                      bool scan_all_files);

/* Lock/unlock the block I/O mutex. Callers that read block or undo
 * files directly (not through read_block_from_disk) MUST wrap their
 * fopen/fread/fseek/fclose in lock/unlock to prevent SIGSEGV from
 * concurrent FILE* access across threads. */
void disk_block_io_lock(void);
void disk_block_io_unlock(void);

#endif
