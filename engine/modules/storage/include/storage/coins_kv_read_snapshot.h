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

struct coins_kv_read_snapshot_info {
    int32_t applied_height;
    uint64_t authority_generation;
};

/* The script is owned by the snapshot and remains valid only until the next
 * call to coins_kv_read_snapshot_next(), finish(), or abort(). */
struct coins_kv_read_snapshot_row {
    uint8_t txid[32];
    uint32_t vout;
    int64_t value;
    const uint8_t *script;
    size_t script_len;
    int32_t height;
    bool is_coinbase;
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

/* Finish succeeds only after next() reported DONE. Both finish and abort
 * release the SQLite transaction, connection, and row storage. */
bool coins_kv_read_snapshot_finish(struct coins_kv_read_snapshot *snapshot);
void coins_kv_read_snapshot_abort(struct coins_kv_read_snapshot *snapshot);

#endif
