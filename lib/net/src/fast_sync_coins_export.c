/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Canonical coins_kv rows composed into the existing bounded fast-sync
 * chunk type without exposing storage or SQLite lifetime to the wire layer. */
#include "net/fast_sync_coins_export.h"

#include "coins/utxo_commitment.h"
#include "crypto/sha3.h"
#include "net/fast_sync.h"
#include "storage/coins_kv_read_snapshot.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"

#include <stdlib.h>
#include <string.h>

struct fast_sync_coins_export {
    struct coins_kv_read_snapshot *snapshot;
    struct sha3_256_ctx sha3;
    uint64_t count;
    uint32_t next_chunk_index;
    bool exhausted;
    bool failed;
};

struct fast_sync_coins_export *fast_sync_coins_export_open(
    struct fast_sync_coins_export_info *out_info)
{
    if (out_info)
        memset(out_info, 0, sizeof(*out_info));
    if (!out_info) {
        LOG_WARN("fast_sync", "coins_export_open: out_info is NULL");
        return NULL;
    }

    struct coins_kv_read_snapshot_info snapshot_info;
    struct coins_kv_read_snapshot *snapshot =
        coins_kv_read_snapshot_open(&snapshot_info);
    if (!snapshot) {
        LOG_WARN("fast_sync", "coins_export_open: canonical snapshot unavailable");
        return NULL;
    }

    struct fast_sync_coins_export *exporter = zcl_calloc(
        1, sizeof(*exporter), "fast_sync_coins_export");
    if (!exporter) {
        coins_kv_read_snapshot_abort(snapshot);
        return NULL;
    }
    exporter->snapshot = snapshot;
    sha3_256_init(&exporter->sha3);
    out_info->applied_height = snapshot_info.applied_height;
    out_info->authority_generation = snapshot_info.authority_generation;
    return exporter;
}

static bool export_row(struct fast_sync_coins_export *exporter,
                       struct utxo_chunk *chunk,
                       const struct coins_kv_read_snapshot_row *row)
{
    uint32_t index = chunk->num_entries;
    size_t script_cap = sizeof(chunk->entries[index].script);
    if (row->script_len > script_cap) {
        LOG_WARN("fast_sync", "coins_export: chunk %u entry %u script_len %zu "
                 "exceeds wire cap %zu; refusing", chunk->chunk_index, index,
                 row->script_len, script_cap);
        return false;
    }

    memcpy(chunk->entries[index].txid, row->txid, sizeof(row->txid));
    chunk->entries[index].vout = row->vout;
    chunk->entries[index].value = row->value;
    if (row->script_len > 0)
        memcpy(chunk->entries[index].script, row->script, row->script_len);
    chunk->entries[index].script_len = (uint16_t)row->script_len;
    chunk->entries[index].height = row->height;
    chunk->entries[index].is_coinbase = row->is_coinbase;

    utxo_commitment_sha3_write_record(
        &exporter->sha3, row->txid, row->vout, row->value, row->script,
        (uint32_t)row->script_len, (uint32_t)row->height,
        (uint8_t)(row->is_coinbase ? 1 : 0));
    exporter->count++;
    chunk->num_entries++;
    return true;
}

enum fast_sync_coins_export_step fast_sync_coins_export_next_chunk(
    struct fast_sync_coins_export *exporter,
    struct utxo_chunk *out_chunk,
    uint8_t out_chunk_hash[32])
{
    if (out_chunk)
        memset(out_chunk, 0, sizeof(*out_chunk));
    if (out_chunk_hash)
        memset(out_chunk_hash, 0, 32);
    if (!exporter || !out_chunk || !out_chunk_hash || exporter->failed) {
        LOG_WARN("fast_sync", "coins_export_next: invalid state or output");
        return FAST_SYNC_COINS_EXPORT_ERROR;
    }
    if (exporter->exhausted)
        return FAST_SYNC_COINS_EXPORT_DONE;

    out_chunk->chunk_index = exporter->next_chunk_index;
    while (out_chunk->num_entries < SYNC_CHUNK_SIZE) {
        struct coins_kv_read_snapshot_row row;
        enum coins_kv_read_snapshot_step step =
            coins_kv_read_snapshot_next(exporter->snapshot, &row);
        if (step == COINS_KV_READ_SNAPSHOT_ERROR) {
            LOG_WARN("fast_sync", "coins_export_next: canonical traversal failed");
            exporter->failed = true;
            memset(out_chunk, 0, sizeof(*out_chunk));
            return FAST_SYNC_COINS_EXPORT_ERROR;
        }
        if (step == COINS_KV_READ_SNAPSHOT_DONE) {
            exporter->exhausted = true;
            break;
        }
        if (!export_row(exporter, out_chunk, &row)) {
            exporter->failed = true;
            memset(out_chunk, 0, sizeof(*out_chunk));
            return FAST_SYNC_COINS_EXPORT_ERROR;
        }
    }

    if (out_chunk->num_entries == 0)
        return FAST_SYNC_COINS_EXPORT_DONE;
    fast_sync_chunk_hash(out_chunk, out_chunk_hash);
    exporter->next_chunk_index++;
    return FAST_SYNC_COINS_EXPORT_CHUNK;
}

bool fast_sync_coins_export_finish(struct fast_sync_coins_export *exporter,
                                   uint8_t out_root[32],
                                   uint64_t *out_count)
{
    if (out_root)
        memset(out_root, 0, 32);
    if (out_count)
        *out_count = 0;
    if (!exporter) {
        LOG_WARN("fast_sync", "coins_export_finish: invalid argument");
        return false;
    }
    if (!out_root || !out_count) {
        LOG_WARN("fast_sync", "coins_export_finish: output is NULL");
        coins_kv_read_snapshot_abort(exporter->snapshot);
        free(exporter);
        return false;
    }

    bool complete = exporter->exhausted && !exporter->failed;
    uint8_t root[32] = {0};
    if (complete)
        sha3_256_finalize(&exporter->sha3, root);
    bool released = complete
        ? coins_kv_read_snapshot_finish(exporter->snapshot)
        : (coins_kv_read_snapshot_abort(exporter->snapshot), false);
    uint64_t count = exporter->count;
    free(exporter);
    if (!complete || !released) {
        LOG_WARN("fast_sync", "coins_export_finish: traversal incomplete");
        return false;
    }
    memcpy(out_root, root, sizeof(root));
    *out_count = count;
    return true;
}

void fast_sync_coins_export_abort(struct fast_sync_coins_export *exporter)
{
    if (!exporter)
        return;
    coins_kv_read_snapshot_abort(exporter->snapshot);
    free(exporter);
}
