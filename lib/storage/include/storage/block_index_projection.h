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
#include <stdint.h>

typedef struct block_index_projection block_index_projection_t;

/* Open or create the projection at `path` (SQLite file). `log` is the
 * shared event log instance that catch_up will stream from. Both must
 * outlive the projection. Returns NULL on error. */
block_index_projection_t *block_index_projection_open(const char *path,
                                                      event_log_t *log);

/* Close + free. NULL-safe. */
void block_index_projection_close(block_index_projection_t *p);

/* Consume events from `last_consumed_offset` to the end of the log.
 * Idempotent. Returns the new last_consumed_offset on success or
 * (uint64_t)-1 on error. INSERT OR REPLACE semantics — a header whose
 * hash already exists overwrites the prior row (a reorg or a status
 * upgrade). */
uint64_t block_index_projection_catch_up(block_index_projection_t *p);

/* Lookup by block hash. Returns true if present; fills `out` (incl.
 * solution buffer). `out` must be initialized by the caller before
 * passing in (the projection memcpys into its fields). */
bool block_index_projection_get(block_index_projection_t *p,
                                const uint8_t hash[32],
                                struct disk_block_index *out);

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

#endif /* ZCL_STORAGE_BLOCK_INDEX_PROJECTION_H */
