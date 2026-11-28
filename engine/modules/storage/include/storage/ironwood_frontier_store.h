/* purpose: Store ordered Ironwood frontier checkpoints in caller transactions. */
/* Copyright 2026 Rhett Creighton - Apache License 2.0 */
#ifndef ZCL_STORAGE_IRONWOOD_FRONTIER_STORE_H
#define ZCL_STORAGE_IRONWOOD_FRONTIER_STORE_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
struct sqlite3;
enum { IRONWOOD_CHECKPOINT_MAX_BYTES = 1033 };
struct ironwood_checkpoint {
    int64_t height;
    uint8_t block_hash[32];
    uint8_t root[32];
    uint64_t count;
    size_t payload_size;
    uint8_t payload[IRONWOOD_CHECKPOINT_MAX_BYTES];
};
/* Zero-initialize on every connection open or reopen. A SQLite pointer may
 * be reused after close, so a session must not survive its connection. */
struct ironwood_checkpoint_session {
    struct sqlite3 *db;
    int64_t generation;
    bool audited;
};
enum ironwood_checkpoint_result {
    IRONWOOD_CHECKPOINT_ERROR = -1,
    IRONWOOD_CHECKPOINT_MISSING = 0,
    IRONWOOD_CHECKPOINT_FOUND = 1,
    IRONWOOD_CHECKPOINT_INCOMPLETE = 2,
};
/* Schema creation, audit, lookup and writes require an existing caller-owned
 * SQLite transaction. Missing both tables creates a fresh schema; any partial
 * table/index schema refuses without mutation. Roll back after a failed write. */
bool ironwood_checkpoint_ensure_schema(struct sqlite3 *db);
enum ironwood_checkpoint_probe_result {
    IRONWOOD_CHECKPOINT_PROBE_ERROR = -1,
    IRONWOOD_CHECKPOINT_UNINITIALIZED = 0,
    IRONWOOD_CHECKPOINT_PRESENT = 1,
};
/* PRESENT only means rows exist, not that they are valid. Initialize only
 * after UNINITIALIZED; audit failure never authorizes initialization. */
enum ironwood_checkpoint_probe_result ironwood_checkpoint_probe(struct sqlite3 *db);
/* Explicit from-genesis replay only. The caller supplies the authenticated
 * genesis parent and verified protocol-empty root. */
bool ironwood_checkpoint_begin_replay(struct sqlite3 *db,
    const uint8_t parent_hash[32], const uint8_t empty_root[32]);
/* Audit the entire local sequence once at resume. No database row alone
 * proves chain identity: the caller must authenticate deterministic replay.
 * Failure leaves the output session unchanged. */
bool ironwood_checkpoint_audit(struct sqlite3 *db,
    struct ironwood_checkpoint_session *session);
/* Reuse a current audited session; otherwise perform the streaming audit. */
bool ironwood_checkpoint_refresh(struct sqlite3 *db,
    struct ironwood_checkpoint_session *session);
/* Append every canonical height in order. A NULL payload is permitted only
 * when root and count match the previous checkpoint. Parent identity must
 * match the immediately preceding block. */
bool ironwood_checkpoint_append(struct ironwood_checkpoint_session *session,
    int64_t height, const uint8_t block_hash[32], const uint8_t parent_hash[32],
    const uint8_t root[32], uint64_t count,
    const uint8_t *payload, size_t payload_size);
/* Root lookup excludes the synthetic height -1 replay baseline.
 * Returned rows are candidates. Authenticate the block and use
 * ironwood_frontier_restore with independently trusted expected root/count.
 * Output is unchanged unless FOUND. Stale/rolled-back sessions fail closed. */
enum ironwood_checkpoint_result ironwood_checkpoint_latest_before(
    struct ironwood_checkpoint_session *session, int64_t candidate_height,
    struct ironwood_checkpoint *out);
enum ironwood_checkpoint_result ironwood_checkpoint_find_root(
    struct ironwood_checkpoint_session *session, int64_t candidate_height,
    const uint8_t root[32], struct ironwood_checkpoint *out);
/* Called by anchor_kv_delete_range in its caller-owned transaction. Any
 * active sessions must be audited again after a reorg or rollback. */
bool ironwood_checkpoint_delete_range(struct sqlite3 *db,
    int64_t first_height, int64_t last_height);
#endif
