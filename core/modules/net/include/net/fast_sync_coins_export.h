/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Sequential fast-sync export over one canonical coins_kv read snapshot. */
#ifndef NET_FAST_SYNC_COINS_EXPORT_H
#define NET_FAST_SYNC_COINS_EXPORT_H

#include <stdbool.h>
#include <stdint.h>

struct fast_sync_coins_export;
struct utxo_chunk;

struct fast_sync_coins_export_info {
    int32_t applied_height;
    uint64_t authority_generation;
};

enum fast_sync_coins_export_step {
    FAST_SYNC_COINS_EXPORT_ERROR = -1,
    FAST_SYNC_COINS_EXPORT_DONE = 0,
    FAST_SYNC_COINS_EXPORT_CHUNK = 1,
};

/* Open and pin one proven, durable coins_kv generation. */
struct fast_sync_coins_export *fast_sync_coins_export_open(
    struct fast_sync_coins_export_info *out_info);

/* Fill the next existing-wire utxo_chunk in canonical (txid,vout) order and
 * return its established fast_sync_chunk_hash. Scripts beyond the fixed wire
 * entry capacity are refused; no byte is truncated. */
enum fast_sync_coins_export_step fast_sync_coins_export_next_chunk(
    struct fast_sync_coins_export *exporter,
    struct utxo_chunk *out_chunk,
    uint8_t out_chunk_hash[32]);

/* Release root/count only after the complete traversal has been observed.
 * The exporter is consumed on both success and failure. */
bool fast_sync_coins_export_finish(struct fast_sync_coins_export *exporter,
                                   uint8_t out_root[32],
                                   uint64_t *out_count);
void fast_sync_coins_export_abort(struct fast_sync_coins_export *exporter);

#endif
