/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Atomically publish a bounded fast-sync artifact from canonical coins_kv. */
#include "net/fast_sync_coins_artifact.h"

#include "net/fast_sync.h"
#include "net/fast_sync_coins_export.h"
#include "platform/private_file.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"

#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ARTIFACT_PATH_CAP 32768u
#define ARTIFACT_STAGE_ATTEMPTS 32u
#define ARTIFACT_CHUNK_BYTES \
    (4u + SYNC_CHUNK_SIZE * (32u + 4u + 8u + 4u + 1u + 3u + 520u))

struct artifact_writer {
    struct platform_private_file file;
    char destination[ARTIFACT_PATH_CAP];
    char parent[ARTIFACT_PATH_CAP];
    char stage[ARTIFACT_PATH_CAP];
    uint8_t (*hashes)[32];
    uint32_t hash_capacity;
    uint32_t chunks;
    uint64_t entries;
    uint64_t bytes;
    bool staged;
};

static _Atomic uint64_t g_artifact_stage_sequence;

const char *fast_sync_coins_artifact_status_name(
    enum fast_sync_coins_artifact_status status)
{
    switch (status) {
    case FAST_SYNC_COINS_ARTIFACT_OK: return "ok";
    case FAST_SYNC_COINS_ARTIFACT_INVALID_ARGUMENT: return "invalid_argument";
    case FAST_SYNC_COINS_ARTIFACT_SNAPSHOT_UNAVAILABLE: return "snapshot_unavailable";
    case FAST_SYNC_COINS_ARTIFACT_LIMIT_EXCEEDED: return "limit_exceeded";
    case FAST_SYNC_COINS_ARTIFACT_ALLOCATION_FAILED: return "allocation_failed";
    case FAST_SYNC_COINS_ARTIFACT_IO_FAILED: return "io_failed";
    case FAST_SYNC_COINS_ARTIFACT_EXPORT_FAILED: return "export_failed";
    }
    return "unknown";
}

void fast_sync_coins_artifact_free(struct fast_sync_coins_artifact *artifact)
{
    if (!artifact)
        return;
    free(artifact->chunk_hashes);
    memset(artifact, 0, sizeof(*artifact));
}

static bool artifact_open_stage(struct artifact_writer *writer,
                                const char *destination_path)
{
    platform_private_file_init(&writer->file);
    if (!platform_private_destination_resolve(
            destination_path, writer->destination,
            sizeof(writer->destination), writer->parent,
            sizeof(writer->parent))) {
        LOG_WARN("fast_sync", "artifact: destination path is not a safe file: %s",
                 destination_path ? destination_path : "(null)");
        return false;
    }

    for (uint32_t attempt = 0; attempt < ARTIFACT_STAGE_ATTEMPTS; attempt++) {
        uint64_t sequence = atomic_fetch_add_explicit(
            &g_artifact_stage_sequence, 1, memory_order_relaxed);
        int n = snprintf(writer->stage, sizeof(writer->stage),
                         "%s.z23-stage-%llu", writer->destination,
                         (unsigned long long)sequence);
        if (n <= 0 || (size_t)n >= sizeof(writer->stage)) {
            LOG_WARN("fast_sync", "artifact: staging path is too long");
            return false;
        }
        if (platform_private_file_create(writer->stage, &writer->file)) {
            writer->staged = true;
            return true;
        }
    }
    LOG_WARN("fast_sync", "artifact: cannot create exclusive stage for %s",
             writer->destination);
    return false;
}

static void artifact_discard_stage(struct artifact_writer *writer)
{
    if (!writer || !writer->staged)
        return;
    if (!platform_private_file_retire(&writer->file, writer->stage)) {
        LOG_WARN("fast_sync", "artifact: descriptor-bound stage cleanup failed: %s",
                 writer->stage);
        platform_private_file_close(&writer->file);
    }
    writer->staged = false;
}

static bool artifact_reserve_hash(struct artifact_writer *writer)
{
    if (writer->chunks >= MANIFEST_MAX_CHUNKS) {
        LOG_WARN("fast_sync", "artifact: chunk limit %u exceeded",
                 MANIFEST_MAX_CHUNKS);
        return false;
    }
    if (writer->chunks < writer->hash_capacity)
        return true;
    uint32_t next = writer->hash_capacity ? writer->hash_capacity * 2u : 16u;
    if (next > MANIFEST_MAX_CHUNKS)
        next = MANIFEST_MAX_CHUNKS;
    uint8_t (*grown)[32] = zcl_realloc(
        writer->hashes, (size_t)next * 32u, "fast_sync_artifact_hashes");
    if (!grown) {
        LOG_WARN("fast_sync", "artifact: cannot allocate %u chunk hashes", next);
        return false;
    }
    writer->hashes = grown;
    writer->hash_capacity = next;
    return true;
}

static void artifact_write_u32(uint8_t **cursor, uint32_t value)
{
    for (uint32_t i = 0; i < 4; i++)
        *(*cursor)++ = (uint8_t)(value >> (8u * i));
}

static void artifact_write_u64(uint8_t **cursor, uint64_t value)
{
    for (uint32_t i = 0; i < 8; i++)
        *(*cursor)++ = (uint8_t)(value >> (8u * i));
}

static void artifact_write_compact_size(uint8_t **cursor, uint16_t value)
{
    if (value < 253u) {
        *(*cursor)++ = (uint8_t)value;
        return;
    }
    *(*cursor)++ = 253u;
    *(*cursor)++ = (uint8_t)value;
    *(*cursor)++ = (uint8_t)(value >> 8);
}

static size_t artifact_encode_chunk(const struct utxo_chunk *chunk,
                                    uint8_t buffer[ARTIFACT_CHUNK_BYTES])
{
    if (!chunk || chunk->num_entries == 0 ||
        chunk->num_entries > SYNC_CHUNK_SIZE) {
        LOG_WARN("fast_sync", "artifact: invalid chunk entry count %u",
                 chunk ? chunk->num_entries : 0);
        return 0;
    }
    uint8_t *cursor = buffer;
    artifact_write_u32(&cursor, chunk->num_entries);
    for (uint32_t i = 0; i < chunk->num_entries; i++) {
        const typeof(chunk->entries[0]) *entry = &chunk->entries[i];
        if (entry->script_len > sizeof(entry->script)) {
            LOG_WARN("fast_sync", "artifact: chunk %u entry %u script %u exceeds %zu",
                     chunk->chunk_index, i, entry->script_len,
                     sizeof(entry->script));
            return 0;
        }
        memcpy(cursor, entry->txid, 32); cursor += 32;
        artifact_write_u32(&cursor, entry->vout);
        artifact_write_u64(&cursor, (uint64_t)entry->value);
        artifact_write_u32(&cursor, (uint32_t)entry->height);
        *cursor++ = entry->is_coinbase ? 1u : 0u;
        artifact_write_compact_size(&cursor, entry->script_len);
        memcpy(cursor, entry->script, entry->script_len);
        cursor += entry->script_len;
    }
    return (size_t)(cursor - buffer);
}

static enum fast_sync_coins_artifact_status artifact_append_chunk(
    struct artifact_writer *writer, const struct utxo_chunk *chunk,
    const uint8_t hash[32], uint8_t buffer[ARTIFACT_CHUNK_BYTES])
{
    if (chunk->chunk_index != writer->chunks) {
        LOG_WARN("fast_sync", "artifact: non-sequential chunk %u expected %u",
                 chunk->chunk_index, writer->chunks);
        return FAST_SYNC_COINS_ARTIFACT_EXPORT_FAILED;
    }
    if (!artifact_reserve_hash(writer))
        return writer->chunks >= MANIFEST_MAX_CHUNKS
            ? FAST_SYNC_COINS_ARTIFACT_LIMIT_EXCEEDED
            : FAST_SYNC_COINS_ARTIFACT_ALLOCATION_FAILED;
    size_t encoded = artifact_encode_chunk(chunk, buffer);
    if (encoded == 0)
        return FAST_SYNC_COINS_ARTIFACT_EXPORT_FAILED;
    if (writer->bytes > UINT64_MAX - encoded ||
        !platform_private_file_write_at(&writer->file, buffer, encoded,
                                        writer->bytes)) {
        LOG_WARN("fast_sync", "artifact: write failed at byte %llu",
                 (unsigned long long)writer->bytes);
        return FAST_SYNC_COINS_ARTIFACT_IO_FAILED;
    }
    memcpy(writer->hashes[writer->chunks], hash, 32);
    writer->bytes += encoded;
    writer->entries += chunk->num_entries;
    writer->chunks++;
    return FAST_SYNC_COINS_ARTIFACT_OK;
}

static bool bytes_are_zero(const uint8_t bytes[32])
{
    uint8_t combined = 0;
    for (size_t i = 0; i < 32; i++)
        combined |= bytes[i];
    return combined == 0;
}

static enum fast_sync_coins_artifact_status artifact_publish(
    struct artifact_writer *writer)
{
    if (!platform_private_file_flush(&writer->file) ||
        !platform_private_file_replace(&writer->file, writer->stage,
                                       writer->destination)) {
        LOG_WARN("fast_sync", "artifact: atomic replace failed: %s",
                 writer->destination);
        return FAST_SYNC_COINS_ARTIFACT_IO_FAILED;
    }
    writer->staged = false;
    if (!platform_private_parent_flush(writer->parent)) {
        LOG_WARN("fast_sync", "artifact: parent durability barrier failed: %s",
                 writer->parent);
        return FAST_SYNC_COINS_ARTIFACT_IO_FAILED;
    }
    return FAST_SYNC_COINS_ARTIFACT_OK;
}

enum fast_sync_coins_artifact_status fast_sync_coins_artifact_write(
    const char *destination_path, struct fast_sync_coins_artifact *out)
{
    if (!destination_path || !destination_path[0] || !out) {
        LOG_WARN("fast_sync", "artifact: invalid path/output");
        return FAST_SYNC_COINS_ARTIFACT_INVALID_ARGUMENT;
    }
    memset(out, 0, sizeof(*out));
    struct fast_sync_coins_export_info info;
    struct fast_sync_coins_export *exporter =
        fast_sync_coins_export_open(&info);
    if (!exporter)
        return FAST_SYNC_COINS_ARTIFACT_SNAPSHOT_UNAVAILABLE;

    struct artifact_writer writer = {0};
    if (!artifact_open_stage(&writer, destination_path)) {
        fast_sync_coins_export_abort(exporter);
        return FAST_SYNC_COINS_ARTIFACT_IO_FAILED;
    }
    struct utxo_chunk *chunk = zcl_calloc(1, sizeof(*chunk),
                                           "fast_sync_artifact_chunk");
    uint8_t *buffer = zcl_malloc(ARTIFACT_CHUNK_BYTES,
                                 "fast_sync_artifact_buffer");
    enum fast_sync_coins_artifact_status status =
        chunk && buffer ? FAST_SYNC_COINS_ARTIFACT_OK
                        : FAST_SYNC_COINS_ARTIFACT_ALLOCATION_FAILED;
    enum fast_sync_coins_export_step step = FAST_SYNC_COINS_EXPORT_ERROR;
    uint8_t hash[32];
    while (status == FAST_SYNC_COINS_ARTIFACT_OK &&
           (step = fast_sync_coins_export_next_chunk(exporter, chunk, hash)) ==
                    FAST_SYNC_COINS_EXPORT_CHUNK) {
        status = artifact_append_chunk(&writer, chunk, hash, buffer);
    }
    if (status == FAST_SYNC_COINS_ARTIFACT_OK &&
        step != FAST_SYNC_COINS_EXPORT_DONE)
        status = FAST_SYNC_COINS_ARTIFACT_EXPORT_FAILED;

    uint8_t root[32] = {0};
    uint64_t count = 0;
    if (status == FAST_SYNC_COINS_ARTIFACT_OK) {
        bool finished = fast_sync_coins_export_finish(exporter, root, &count);
        exporter = NULL;
        if (!finished || count == 0 || count != writer.entries ||
            writer.chunks == 0 ||
            writer.chunks != (count + SYNC_CHUNK_SIZE - 1u) /
                                  SYNC_CHUNK_SIZE) {
            LOG_WARN("fast_sync", "artifact: incomplete final facts count=%llu rows=%llu chunks=%u",
                     (unsigned long long)count,
                     (unsigned long long)writer.entries, writer.chunks);
            status = FAST_SYNC_COINS_ARTIFACT_EXPORT_FAILED;
        }
    }
    uint8_t merkle_root[32] = {0};
    if (status == FAST_SYNC_COINS_ARTIFACT_OK) {
        fast_sync_merkle_root((const uint8_t (*)[32])writer.hashes,
                              writer.chunks, merkle_root);
        if (bytes_are_zero(merkle_root)) {
            LOG_WARN("fast_sync", "artifact: merkle derivation failed");
            status = FAST_SYNC_COINS_ARTIFACT_ALLOCATION_FAILED;
        }
    }
    if (status == FAST_SYNC_COINS_ARTIFACT_OK)
        status = artifact_publish(&writer);

    if (exporter)
        fast_sync_coins_export_abort(exporter);
    if (status != FAST_SYNC_COINS_ARTIFACT_OK)
        artifact_discard_stage(&writer);
    if (status == FAST_SYNC_COINS_ARTIFACT_OK) {
        out->applied_height = info.applied_height;
        out->authority_generation = info.authority_generation;
        out->num_utxos = count;
        out->artifact_bytes = writer.bytes;
        out->num_chunks = writer.chunks;
        out->chunk_size = SYNC_CHUNK_SIZE;
        memcpy(out->utxo_root, root, 32);
        memcpy(out->merkle_root, merkle_root, 32);
        out->chunk_hashes = writer.hashes;
        writer.hashes = NULL;
    }
    free(writer.hashes);
    free(buffer);
    free(chunk);
    return status;
}
