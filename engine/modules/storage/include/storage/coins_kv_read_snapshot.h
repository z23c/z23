/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Purpose: a validated, generation-consistent read snapshot of the canonical
 * coins_kv UTXO set for bounded export consumers. */
#ifndef STORAGE_COINS_KV_READ_SNAPSHOT_H
#define STORAGE_COINS_KV_READ_SNAPSHOT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct coins_kv_read_snapshot;
struct sqlite3;

/* Read from the caller-owned pinned transaction. The endpoint must be
 * the last applied block. Outputs are cleared on refusal or error. */
bool coins_kv_read_transaction_shielded_pool(struct sqlite3 *db, int32_t height,
    int64_t *sprout, int64_t *sapling, bool *found);

struct coins_kv_read_snapshot_info {
    int32_t applied_height;
    uint64_t authority_generation;
};

/* The script is owned by the snapshot and remains valid only until the next
 * call to next(), lookup(), finish(), or abort(). */
struct coins_kv_read_snapshot_row {
    uint8_t txid[32];
    uint32_t vout;
    int64_t value;
    const uint8_t *script;
    size_t script_len;
    int32_t height;
    bool is_coinbase;
};

enum coins_kv_read_snapshot_lookup_result {
    COINS_KV_LOOKUP_ERROR = -1, COINS_KV_LOOKUP_ABSENT = 0, COINS_KV_LOOKUP_FOUND = 1
};

enum coins_kv_read_snapshot_step {
    COINS_KV_READ_SNAPSHOT_ERROR = -1,
    COINS_KV_READ_SNAPSHOT_DONE = 0,
    COINS_KV_READ_SNAPSHOT_ROW = 1,
};

/* Open an independent read-only connection, begin and pin one WAL read
 * transaction with the canonical authority/frontier read, then prepare the
 * canonical (txid,vout) traversal. Returns NULL unless coins_kv is a proven,
 * non-overlay authority. The caller owns the returned snapshot. */
struct coins_kv_read_snapshot *coins_kv_read_snapshot_open(
    struct coins_kv_read_snapshot_info *out_info);

/* Return one strictly ordered, fully validated row. Malformed authority data
 * fails closed with ERROR; it is never skipped or normalized. */
enum coins_kv_read_snapshot_step coins_kv_read_snapshot_next(
    struct coins_kv_read_snapshot *snapshot,
    struct coins_kv_read_snapshot_row *out_row);

/* Query one outpoint in the pinned generation. ERROR poisons the snapshot.
 * ABSENT and ERROR zero out_row. Does not advance ordered traversal. */
enum coins_kv_read_snapshot_lookup_result coins_kv_read_snapshot_lookup(
    struct coins_kv_read_snapshot *snapshot, const uint8_t txid[32],
    uint32_t vout, struct coins_kv_read_snapshot_row *out_row);

/* Read exact shielded totals at applied_height - 1 from this pinned WAL view.
 * An absent row succeeds with found=false; errors zero outputs and poison the
 * snapshot. Known zero totals are reported with found=true. */
bool coins_kv_read_snapshot_shielded_pool(struct coins_kv_read_snapshot *snapshot,
    int32_t height, int64_t *sprout, int64_t *sapling, bool *found);

/* Finish succeeds only after next() reported DONE. Both finish and abort
 * release the SQLite transaction, connection, and row storage. */
bool coins_kv_read_snapshot_finish(struct coins_kv_read_snapshot *snapshot);
void coins_kv_read_snapshot_abort(struct coins_kv_read_snapshot *snapshot);

#endif
