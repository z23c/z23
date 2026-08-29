/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Canonical coins_kv fast-sync artifact publication. */
#ifndef NET_FAST_SYNC_COINS_ARTIFACT_H
#define NET_FAST_SYNC_COINS_ARTIFACT_H

#include <stdint.h>

enum fast_sync_coins_artifact_status {
    FAST_SYNC_COINS_ARTIFACT_OK = 0,
    FAST_SYNC_COINS_ARTIFACT_INVALID_ARGUMENT,
    FAST_SYNC_COINS_ARTIFACT_SNAPSHOT_UNAVAILABLE,
    FAST_SYNC_COINS_ARTIFACT_LIMIT_EXCEEDED,
    FAST_SYNC_COINS_ARTIFACT_ALLOCATION_FAILED,
    FAST_SYNC_COINS_ARTIFACT_IO_FAILED,
    FAST_SYNC_COINS_ARTIFACT_EXPORT_FAILED,
};

struct fast_sync_coins_artifact {
    int32_t applied_height;
    uint64_t authority_generation;
    uint64_t num_utxos;
    uint64_t artifact_bytes;
    uint32_t num_chunks;
    uint32_t chunk_size;
    uint8_t utxo_root[32];
    uint8_t merkle_root[32];
    uint8_t (*chunk_hashes)[32];
};

const char *fast_sync_coins_artifact_status_name(
    enum fast_sync_coins_artifact_status status);

/* Stream one proven coins_kv generation to the existing snapshot.bin chunk
 * encoding. Publication is one descriptor-bound atomic replacement after the
 * complete traversal, root, count, and chunk manifest have been derived.
 * `out` must be uninitialized or previously released. */
enum fast_sync_coins_artifact_status fast_sync_coins_artifact_write(
    const char *destination_path,
    struct fast_sync_coins_artifact *out);

void fast_sync_coins_artifact_free(struct fast_sync_coins_artifact *artifact);

#endif
