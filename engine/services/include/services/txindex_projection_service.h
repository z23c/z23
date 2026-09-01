/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * txindex_projection_service — the supervised, bounded backfill that folds the
 * txindex projection (jobs/txindex_projection.h) forward from its cursor to the
 * finalized tip_finalize frontier (H*), plus the read + introspection surfaces.
 *
 * Shape: a chain-domain supervisor child (util/supervisor.h) driven by the
 * supervisor's own thread via on_tick. Each tick folds a STRICTLY BOUNDED batch
 * — at most TXINDEX_BATCH_BLOCKS heights AND a wall-time budget, never O(chain)
 * — under a NON-BLOCKING progress-store trylock, so it can never stall the
 * reducer drive or freeze the supervisor tree. It advances only over verified
 * persisted bodies at or below H*; a missing body names a typed coverage
 * blocker rather than a silent stop. Newly finalized blocks raise H* and are
 * folded by the same catch-up loop, so there is no separate tip-finalize hook.
 * Restartable at its cursor.
 *
 * Opt-in: registered ONLY when -txindex is set. A default boot registers no
 * child and pays zero cost (the dumper reports enabled=false without a DB
 * touch). */
#ifndef ZCL_SERVICES_TXINDEX_PROJECTION_SERVICE_H
#define ZCL_SERVICES_TXINDEX_PROJECTION_SERVICE_H

#include <stdbool.h>
#include <stdint.h>

struct json_value;

/* Register the chain-domain backfill child. No-op (and returns false) when
 * -txindex is disabled. Idempotent — a second call is a no-op. Called from the
 * boot composition root after the diagnostics main_state/datadir are wired. */
bool txindex_projection_service_register(void);

/* True once the child is registered (i.e. -txindex was on at register). */
bool txindex_projection_service_registered(void);

/* Run exactly one bounded fold batch synchronously. The on_tick wrapper calls
 * this; tests call it directly. Returns the number of blocks folded this call
 * (0 when caught up, disabled, unwired, or the store was busy). */
int txindex_projection_service_tick_once(void);

/* Read-path classification for a getrawtransaction-class lookup. The read is
 * NEVER silently wrong: a hit returns FOUND with the location; a miss below the
 * finalized tip returns BEHIND (fail soft — the tx may live above the cursor);
 * a miss at/above the tip returns ABSENT (definitively not indexed). */
enum txindex_read_status {
    TXINDEX_READ_DISABLED,   /* -txindex off / progress store not open */
    TXINDEX_READ_FOUND,      /* located: height/block_hash/tx_n filled */
    TXINDEX_READ_ABSENT,     /* caught up (cursor>=H*) and txid not present */
    TXINDEX_READ_BEHIND,     /* not present yet; cursor<H* — fail soft */
    TXINDEX_READ_BUSY,       /* store busy (trylock) or a transient DB error */
};

/* Classify a lookup outcome. Pure/testable: exposes the BEHIND-vs-ABSENT rule
 * independent of the live progress store / tip cursor. */
enum txindex_read_status txindex_projection_classify(bool found, int64_t cursor,
                                                     int64_t hstar);

/* Locate a transaction via the projection for a read. Grabs the store trylock,
 * reads the cursor, looks up `txid`, and classifies the result. Outputs
 * (nullable) are filled only on FOUND; *cursor_out always receives the folded
 * cursor. `txid` is the internal (little-endian) 32-byte hash. */
enum txindex_read_status txindex_projection_read_locate(
    const uint8_t txid[32], int64_t *height_out, uint8_t block_hash_out[32],
    int64_t *tx_n_out, int64_t *cursor_out);

/* dumpstate `txindex` (CLAUDE.md "Adding state introspection").
 * key == NULL/empty -> projection status (enabled, cursor, H*, gap, rows,
 *                       digest, counters, coverage blocker). Bare status reads
 *                       only atomics and touches NO disk.
 * key == "<64-hex txid>" -> the tx location {height, block_hash, tx_n}, or a
 *                       soft "txindex behind: cursor=H" when the index has not
 *                       yet folded far enough. */
bool txindex_dump_state_json(struct json_value *out, const char *key);

/* Bounded per-tick work (mirrors address_index's pacing exactly). */
#define TXINDEX_BATCH_BLOCKS   128
#define TXINDEX_BATCH_US       15000   /* 15 ms wall budget per tick */
#define TXINDEX_TICK_SECONDS   2

#endif /* ZCL_SERVICES_TXINDEX_PROJECTION_SERVICE_H */
