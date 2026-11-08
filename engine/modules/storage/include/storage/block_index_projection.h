/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * block_index_projection — SQLite-backed projection over EV_BLOCK_HEADER
 * events from the append-only event_log.
 *
 * block_index_db.c emits an EV_BLOCK_HEADER event on every persisted
 * block-index write. The projection consumes those events and materializes
 * a SQLite table mirror that can be replayed and audited.
 *
 * Threading
 * ----------
 * `open`/`close` are called once from boot. `catch_up` is called from
 * a single consumer thread; readers (`get`, `get_by_height`, `iterate`,
 * `commitment`) are safe under concurrent readers + the single
 * consumer (SQLite WAL).
 *
 * Schema
 * -------
 *   CREATE TABLE block_index (
 *       hash       BLOB PRIMARY KEY,
 *       height     INTEGER NOT NULL,
 *       n_status   INTEGER NOT NULL,
 *       n_file     INTEGER NOT NULL,
 *       n_data_pos INTEGER NOT NULL,
 *       n_undo_pos INTEGER NOT NULL,
 *       n_time     INTEGER NOT NULL,
 *       n_bits     INTEGER NOT NULL,
 *       n_version  INTEGER NOT NULL,
 *       n_tx       INTEGER NOT NULL,
 *       blob       BLOB NOT NULL    -- ev_block_header serialized bytes
 *   ) WITHOUT ROWID;
 *   CREATE INDEX block_index_height_idx ON block_index(height);
 *
 *   CREATE TABLE projection_meta (
 *       k TEXT PRIMARY KEY,
 *       v TEXT NOT NULL
 *   );
 *   CREATE TABLE block_index_dirty (
 *       hash BLOB PRIMARY KEY
 *   ) WITHOUT ROWID;
 *
 * `projection_meta` carries `last_consumed_offset` (decimal string),
 * `events_consumed_total`, `replace_collisions_total`, `last_catch_up_ms`,
 * the bound flat payload SHA3/size/row-count/covered-offset, and a
 * schema_version sentinel. Dirty membership and row replacement commit in
 * the same transaction; binding clears dirty membership transactionally.
 */

#ifndef ZCL_STORAGE_BLOCK_INDEX_PROJECTION_H
#define ZCL_STORAGE_BLOCK_INDEX_PROJECTION_H

#include "storage/event_log.h"
#include "storage/block_index_db.h"   /* for struct disk_block_index */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct block_index_projection block_index_projection_t;

/* Open or create the projection at `path` (SQLite file). `log` is the
 * shared event log instance that catch_up will stream from. Both must
 * outlive the projection. Returns NULL on error. */
block_index_projection_t *block_index_projection_open(const char *path,
                                                      event_log_t *log);

/* Close + free. NULL-safe. */
void block_index_projection_close(block_index_projection_t *p);

/* PASSIVE WAL checkpoint on the open handle. Never blocks writers, never
 * truncates the WAL; close still runs the TRUNCATE. Returns the sqlite rc
 * (SQLITE_BUSY is benign), or SQLITE_MISUSE for a NULL or closed handle. */
int block_index_projection_checkpoint_passive(block_index_projection_t *p);

/* A stopped replay commits the last completed record and its dirty rows.
 * An observed read, SQL or commit error always returns ERROR. */
enum bip_catch_up_status { BIP_CATCH_UP_COMPLETE, BIP_CATCH_UP_STOPPED, BIP_CATCH_UP_ERROR };
enum bip_catch_up_status block_index_projection_catch_up_until(
    block_index_projection_t *p, bool (*stop)(void *), void *ctx, uint64_t *offset);
/* Complete replay; returns the committed offset or UINT64_MAX on error. */
uint64_t block_index_projection_catch_up(block_index_projection_t *p);

/* Lookup by block hash. Returns true if present; fills `out` (incl.
 * solution buffer). `out` must be initialized by the caller before
 * passing in (the projection memcpys into its fields). */
bool block_index_projection_get(block_index_projection_t *p,
                                const uint8_t hash[32],
                                struct disk_block_index *out);

enum bip_lookup_result { BIP_LOOKUP_ERROR, BIP_LOOKUP_ABSENT, BIP_LOOKUP_PRESENT };
enum bip_lookup_result block_index_projection_lookup_strict(block_index_projection_t *p,
    const uint8_t hash[32], struct disk_block_index *out);

/* Exact serialized length and embedded hash must agree with the lookup key. */
bool block_index_projection_get_strict(block_index_projection_t *p,
                                       const uint8_t hash[32],
                                       struct disk_block_index *out);

/* Read a bounded window from an existing projection under a retained directory.
 * No database, WAL or shared-memory file is created; false preserves no result. */
bool block_index_projection_read_window_existing(int dirfd,
    const uint8_t (*hashes)[32], size_t count, struct disk_block_index *out);

/* Retained read-only snapshot of an existing projection. The caller keeps the
 * directory namespace stable; SQLite may update existing WAL shared memory.
 * The stop callback and context must outlive the reader. Lookup leaves output
 * unchanged unless it returns BIP_SNAPSHOT_PRESENT. */
typedef struct bip_existing_snapshot bip_existing_snapshot_t;
enum bip_snapshot_result { BIP_SNAPSHOT_ERROR, BIP_SNAPSHOT_STOPPED, BIP_SNAPSHOT_UNSUPPORTED, BIP_SNAPSHOT_OK };
enum bip_snapshot_lookup { BIP_SNAPSHOT_LOOKUP_ERROR, BIP_SNAPSHOT_LOOKUP_STOPPED,
                           BIP_SNAPSHOT_ABSENT, BIP_SNAPSHOT_PRESENT };
enum bip_snapshot_result block_index_projection_snapshot_open(
    int dirfd, bool (*stop)(void *), void *ctx, bip_existing_snapshot_t **out);
enum bip_snapshot_lookup block_index_projection_snapshot_lookup(
    bip_existing_snapshot_t *reader, const uint8_t hash[32], struct disk_block_index *out);
/* Releases the reader even on failure. Windows is unsupported. */
bool block_index_projection_snapshot_close(bip_existing_snapshot_t *reader);

/* Lookup by height. If multiple entries share a height (siblings at
 * an unactivated branch), returns the lexicographically smallest hash.
 * Returns true on found. */
bool block_index_projection_get_by_height(block_index_projection_t *p,
                                          int height,
                                          struct disk_block_index *out);

/* Iterate every entry in canonical (height ASC, hash ASC) order. Stops
 * if `cb` returns false. Returns 0 on success, -1 on error. */
typedef bool (*block_index_projection_cb)(const uint8_t hash[32],
                                          const struct disk_block_index *idx,
                                          void *user);
int block_index_projection_iterate(block_index_projection_t *p,
                                   block_index_projection_cb cb,
                                   void *user);

/* Iterate every entry in storage order. This avoids one table lookup per row
 * on spinning disks. Callers must not derive order-sensitive evidence from
 * this traversal. Stops if `cb` returns false; returns 0 on success. */
int block_index_projection_iterate_storage_order(
    block_index_projection_t *p, block_index_projection_cb cb, void *user);

/* Bind a quiescent, SHA3-verified flat snapshot to the projection cursor and
 * clear its dirty set atomically. The row count must equal the projection's
 * current row count. */
bool block_index_projection_bind_flat(block_index_projection_t *p,
                                      const uint8_t payload_sha3[32],
                                      uint64_t payload_size,
                                      uint64_t row_count);

/* Bind a flat snapshot whose rows may be a strict superset of this event
 * projection. `covered` must prove that skipping each current projection row
 * has exactly the same in-memory result as applying it to the saved flat.
 * The proof and dirty-set clear run under the projection mutex. */
bool block_index_projection_bind_flat_if_covered(
    block_index_projection_t *p, const uint8_t payload_sha3[32],
    uint64_t payload_size, uint64_t row_count,
    block_index_projection_cb covered, void *user);

/* Move a covered binding from the flat it names to its successor, proving
 * only what changed. The stored binding must name `base` exactly (the
 * previous covered bind proved every projection row against it, and every
 * row written since is in the dirty set). `changed` lists every row hash at
 * a position where the two flats differ, old and new. The proof re-runs
 * `covered` on every dirty row and every projection row a changed hash
 * names, requires the projection row count to stay within the new flat's
 * row count, then commits exactly what block_index_projection_bind_flat_if_
 * covered commits. Returns 1 bound, 0 the stored binding does not name
 * `base` (run the full proof), -1 a row is not covered (the full proof would
 * refuse it too), -2 a storage error (run the full proof). */
int block_index_projection_rebind_flat_if_covered(
    block_index_projection_t *p, const uint8_t base_sha3[32],
    uint64_t base_size, uint64_t base_rows, const uint8_t payload_sha3[32],
    uint64_t payload_size, uint64_t row_count, const uint8_t (*changed)[32],
    size_t n_changed, block_index_projection_cb covered, void *user);

/* Threads the last covered bind used to verify rows (1 = single pass). The
 * `covered` callback of block_index_projection_bind_flat_if_covered runs on up
 * to 8 threads at once, so it must be thread-safe and side-effect free. */
unsigned block_index_projection_last_bind_threads(block_index_projection_t *p);

/* Projection rows the last full or incremental covered bind ran `covered`
 * on. */
uint64_t block_index_projection_last_bind_rows(block_index_projection_t *p);

#ifdef ZCL_TESTING
void block_index_projection_bind_workers_for_test(unsigned workers);
#endif

/* Iterate only hashes replaced after the bound flat snapshot. Returns 1 when
 * the exact identity matched, 0 when the caller must use the full scan, and
 * -1 on a storage error. */
int block_index_projection_iterate_dirty_if_bound(
    block_index_projection_t *p, const uint8_t payload_sha3[32],
    uint64_t payload_size, uint64_t row_count,
    block_index_projection_cb cb, void *user);

/* Row count. */
uint64_t block_index_projection_count(block_index_projection_t *p);

/* SHA3-256 over canonical (height ASC, hash ASC) serialization. For
 * each entry, the digest absorbs:
 *   hash[32] || height (i32 LE) || nStatus (u32 LE) || nFile (i32 LE)
 *   || nDataPos (u32 LE) || nUndoPos (u32 LE) || nTime (u32 LE)
 *   || nBits (u32 LE)
 * This is the same canonical bytes shape that the diff tool uses to
 * compare against the live LevelDB block_index. */
int block_index_projection_commitment(block_index_projection_t *p,
                                      uint8_t out[32]);

/* Diagnostics — see CLAUDE.md "Adding state introspection". */
struct json_value;
bool block_index_projection_dump_state_json(struct json_value *out,
                                            const char *key);

/* Process-wide singleton accessor (set by boot_services). NULL until boot has
 * wired it. Native diagnostics use this accessor. */
block_index_projection_t *block_index_projection_singleton(void);
void block_index_projection_set_singleton(block_index_projection_t *p);

/* After catch-up: lower the connection page cache to the steady baseline and
 * release its clean pages. Returns the page-cache bytes released (>= 0), or -1
 * if the connection is busy (try again later) or p is NULL. Takes p->mu with a
 * trylock, so it never blocks behind a reader or the catch-up writer. */
int64_t block_index_projection_release_cache(block_index_projection_t *p);

#endif /* ZCL_STORAGE_BLOCK_INDEX_PROJECTION_H */
