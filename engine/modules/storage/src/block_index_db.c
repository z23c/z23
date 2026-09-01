/* Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#include "storage/block_index_db.h"
#include "core/hash.h"
#include "primitives/block.h"
#include "util/boot_phase.h"
#include "util/log_macros.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* The EV_BLOCK_HEADER projection feed is NOT emitted here (Program H0). The
 * canonical fold path (engine/jobs/src/header_admit_stage.c and the status-flip
 * paths core/modules/validation/src/process_block_{invalidate,revalidate}.c) owns the
 * single emitter via engine/jobs/include/jobs/block_header_emit.h so the LevelDB
 * block-tree can be deleted in a later Program H wave without silencing the
 * block_index_projection. */

static const char DB_BLOCK_INDEX = 'b';

bool disk_block_index_serialize(const struct disk_block_index *d,
                                struct byte_stream *s)
{
    if (!stream_write_varint(s, (uint64_t)d->nVersion))
        LOG_FAIL("block_index_db", "serialize: write nVersion failed");
    if (!stream_write_varint(s, (uint64_t)d->nHeight))
        LOG_FAIL("block_index_db", "serialize: write nHeight failed");
    if (!stream_write_varint(s, (uint64_t)d->nStatus))
        LOG_FAIL("block_index_db", "serialize: write nStatus failed");
    if (!stream_write_varint(s, (uint64_t)d->nTx))
        LOG_FAIL("block_index_db", "serialize: write nTx failed");
    if (d->nStatus & (BLOCK_HAVE_DATA | BLOCK_HAVE_UNDO))
        if (!stream_write_varint(s, (uint64_t)d->nFile))
            LOG_FAIL("block_index_db", "serialize: write nFile failed");
    if (d->nStatus & BLOCK_HAVE_DATA)
        if (!stream_write_varint(s, (uint64_t)d->nDataPos))
            LOG_FAIL("block_index_db", "serialize: write nDataPos failed");
    if (d->nStatus & BLOCK_HAVE_UNDO)
        if (!stream_write_varint(s, (uint64_t)d->nUndoPos))
            LOG_FAIL("block_index_db", "serialize: write nUndoPos failed");
    if (d->nStatus & BLOCK_ACTIVATES_UPGRADE) {
        uint32_t branchId = (uint32_t)d->nCachedBranchId;
        if (!stream_write_u32_le(s, branchId))
            LOG_FAIL("block_index_db", "serialize: write branchId failed");
    }
    if (!stream_write_bytes(s, d->hashSproutAnchor.data, 32))
        LOG_FAIL("block_index_db", "serialize: write hashSproutAnchor failed");

    if (!stream_write_i32_le(s, d->nVersion))
        LOG_FAIL("block_index_db", "serialize: write header nVersion failed");
    if (!stream_write_bytes(s, d->hashPrev.data, 32))
        LOG_FAIL("block_index_db", "serialize: write hashPrev failed");
    if (!stream_write_bytes(s, d->hashMerkleRoot.data, 32))
        LOG_FAIL("block_index_db", "serialize: write hashMerkleRoot failed");
    if (!stream_write_bytes(s, d->hashFinalSaplingRoot.data, 32))
        LOG_FAIL("block_index_db", "serialize: write hashFinalSaplingRoot failed");
    if (!stream_write_u32_le(s, d->nTime))
        LOG_FAIL("block_index_db", "serialize: write nTime failed");
    if (!stream_write_u32_le(s, d->nBits))
        LOG_FAIL("block_index_db", "serialize: write nBits failed");
    if (!stream_write_bytes(s, d->nNonce.data, 32))
        LOG_FAIL("block_index_db", "serialize: write nNonce failed");
    if (!stream_write_compact_size(s, d->nSolutionSize))
        LOG_FAIL("block_index_db", "serialize: write nSolutionSize failed");
    if (d->nSolutionSize > 0)
        if (!stream_write_bytes(s, d->nSolution, d->nSolutionSize))
            LOG_FAIL("block_index_db", "serialize: write nSolution failed");

    /* boost::optional wire format for nSproutValue */
    if (d->has_sprout_value) {
        uint8_t present = 1;
        if (!stream_write_bytes(s, &present, 1))
            LOG_FAIL("block_index_db", "serialize: write sprout present flag failed");
        if (!stream_write_i64_le(s, d->nSproutValue))
            LOG_FAIL("block_index_db", "serialize: write nSproutValue failed");
    } else {
        uint8_t absent = 0;
        if (!stream_write_bytes(s, &absent, 1))
            LOG_FAIL("block_index_db", "serialize: write sprout absent flag failed");
    }
    if (!stream_write_i64_le(s, d->nSaplingValue))
        LOG_FAIL("block_index_db", "serialize: write nSaplingValue failed");

    return true;
}

bool disk_block_index_deserialize(struct disk_block_index *d,
                                  struct byte_stream *s)
{
    uint64_t v;
    if (!stream_read_varint(s, &v))
        LOG_FAIL("block_index_db", "deserialize: read stored_version failed");
    int stored_version = (int)v;

    if (!stream_read_varint(s, &v))
        LOG_FAIL("block_index_db", "deserialize: read nHeight failed");
    d->nHeight = (int)v;
    if (!stream_read_varint(s, &v))
        LOG_FAIL("block_index_db", "deserialize: read nStatus failed");
    d->nStatus = (unsigned int)v;
    if (!stream_read_varint(s, &v))
        LOG_FAIL("block_index_db", "deserialize: read nTx failed");
    d->nTx = (unsigned int)v;
    if (d->nStatus & (BLOCK_HAVE_DATA | BLOCK_HAVE_UNDO)) {
        if (!stream_read_varint(s, &v))
            LOG_FAIL("block_index_db", "deserialize: read nFile failed");
        /* nFile is a small block-file index; a varint past INT_MAX would cast
         * to a negative file number. Reject a corrupt record loudly here rather
         * than relying on the downstream nFile<0 guards (mirrors the nHeight
         * range check in the legacy reader). */
        if (v > 0x7fffffffULL)
            LOG_FAIL("block_index_db", "deserialize: nFile out of range");
        d->nFile = (int)v;
    }
    if (d->nStatus & BLOCK_HAVE_DATA) {
        if (!stream_read_varint(s, &v))
            LOG_FAIL("block_index_db", "deserialize: read nDataPos failed");
        d->nDataPos = (unsigned int)v;
    }
    if (d->nStatus & BLOCK_HAVE_UNDO) {
        if (!stream_read_varint(s, &v))
            LOG_FAIL("block_index_db", "deserialize: read nUndoPos failed");
        d->nUndoPos = (unsigned int)v;
    }
    if (d->nStatus & BLOCK_ACTIVATES_UPGRADE) {
        uint32_t branchId;
        if (!stream_read_u32_le(s, &branchId))
            LOG_FAIL("block_index_db", "deserialize: read branchId failed");
        d->nCachedBranchId = (int64_t)branchId;
    }
    if (!stream_read_bytes(s, d->hashSproutAnchor.data, 32))
        LOG_FAIL("block_index_db", "deserialize: read hashSproutAnchor failed");

    if (!stream_read_i32_le(s, &d->nVersion))
        LOG_FAIL("block_index_db", "deserialize: read nVersion failed");
    if (!stream_read_bytes(s, d->hashPrev.data, 32))
        LOG_FAIL("block_index_db", "deserialize: read hashPrev failed");
    if (!stream_read_bytes(s, d->hashMerkleRoot.data, 32))
        LOG_FAIL("block_index_db", "deserialize: read hashMerkleRoot failed");
    if (!stream_read_bytes(s, d->hashFinalSaplingRoot.data, 32))
        LOG_FAIL("block_index_db", "deserialize: read hashFinalSaplingRoot failed");
    if (!stream_read_u32_le(s, &d->nTime))
        LOG_FAIL("block_index_db", "deserialize: read nTime failed");
    if (!stream_read_u32_le(s, &d->nBits))
        LOG_FAIL("block_index_db", "deserialize: read nBits failed");
    if (!stream_read_bytes(s, d->nNonce.data, 32))
        LOG_FAIL("block_index_db", "deserialize: read nNonce failed");
    uint64_t sol_size;
    if (!stream_read_compact_size(s, &sol_size))
        LOG_FAIL("block_index_db", "deserialize: read solution size failed");
    if (sol_size > MAX_SOLUTION_SIZE)
        LOG_FAIL("block_index_db", "deserialize: solution size %zu exceeds max", (size_t)sol_size);
    d->nSolutionSize = (size_t)sol_size;
    if (d->nSolutionSize > 0)
        if (!stream_read_bytes(s, d->nSolution, d->nSolutionSize))
            LOG_FAIL("block_index_db", "deserialize: read nSolution failed (size=%zu)", d->nSolutionSize);

    d->has_sprout_value = false;
    if (stored_version >= SPROUT_VALUE_VERSION) {
        /* boost::optional wire format: 1-byte discriminant + value.
         * 0x00 = none, 0x01 = present (followed by int64 LE). */
        uint8_t sprout_present = 0;
        if (!stream_read_bytes(s, &sprout_present, 1))
            LOG_FAIL("block_index_db", "deserialize: read sprout present flag failed");
        if (sprout_present) {
            d->has_sprout_value = true;
            if (!stream_read_i64_le(s, &d->nSproutValue))
                LOG_FAIL("block_index_db", "deserialize: read nSproutValue failed");
        }
    }
    if (stored_version >= SAPLING_VALUE_VERSION) {
        if (!stream_read_i64_le(s, &d->nSaplingValue))
            LOG_FAIL("block_index_db", "deserialize: read nSaplingValue failed");
    }

    return true;
}

void disk_block_index_get_hash(const struct disk_block_index *d,
                               struct uint256 *out)
{
    struct block_header h;
    block_header_init(&h);
    h.nVersion = d->nVersion;
    h.hashPrevBlock = d->hashPrev;
    h.hashMerkleRoot = d->hashMerkleRoot;
    h.hashFinalSaplingRoot = d->hashFinalSaplingRoot;
    h.nTime = d->nTime;
    h.nBits = d->nBits;
    h.nNonce = d->nNonce;
    memcpy(h.nSolution, d->nSolution, d->nSolutionSize);
    h.nSolutionSize = d->nSolutionSize;
    block_header_get_hash(&h, out);
}

static bool block_tree_db_write_block_index_internal(
    struct block_tree_db *btdb,
    const struct disk_block_index *d,
    bool sync)
{
    struct uint256 hash;
    disk_block_index_get_hash(d, &hash);

    char key[64];
    key[0] = DB_BLOCK_INDEX;
    memcpy(key + 1, hash.data, 32);
    size_t keylen = 33;

    struct byte_stream s;
    stream_init(&s, 512);
    if (!disk_block_index_serialize(d, &s)) {
        stream_free(&s);
        LOG_FAIL("block_index_db", "write_block_index: serialization failed for h=%d", d->nHeight);
    }

    bool ok = db_write(&btdb->db, key, keylen, (char *)s.data, s.size, sync);
    stream_free(&s);
    return ok;
}

bool block_tree_db_write_block_index(struct block_tree_db *btdb,
                                     const struct disk_block_index *d)
{
    return block_tree_db_write_block_index_internal(btdb, d, false);
}

bool block_tree_db_write_block_index_sync(struct block_tree_db *btdb,
                                          const struct disk_block_index *d)
{
    return block_tree_db_write_block_index_internal(btdb, d, true);
}

bool block_tree_db_read_block_index(struct block_tree_db *btdb,
                                    const struct uint256 *hash,
                                    struct disk_block_index *out)
{
    if (!btdb || !hash || !out)
        LOG_FAIL("block_index_db", "read_block_index: invalid argument");

    char key[64];
    key[0] = DB_BLOCK_INDEX;
    memcpy(key + 1, hash->data, 32);

    char *val = NULL;
    size_t vallen = 0;
    if (!db_read(&btdb->db, key, 33, &val, &vallen))
        return false;

    disk_block_index_init(out);
    struct byte_stream s;
    stream_init_from_data(&s, (unsigned char *)val, vallen);
    bool ok = disk_block_index_deserialize(out, &s);
    stream_free(&s);
    free(val);
    return ok;
}

bool block_tree_db_load_block_index_guts(struct block_tree_db *btdb,
                                         insert_block_index_fn insert_fn,
                                         void *ctx)
{
    char seek_key[33];
    seek_key[0] = DB_BLOCK_INDEX;
    memset(seek_key + 1, 0, 32);

    struct db_iterator it;
    db_iter_init(&it, &btdb->db);
    db_iter_seek(&it, seek_key, 33);

    uint64_t loaded = 0;
    while (db_iter_valid(&it)) {
        /* A multi-million-row LevelDB walk outlives the 2-min systemd
         * watchdog on a cold boot; pump the boot-liveness marker (same
         * convention as the flat loader's insert/link passes) so a
         * progressing load is never killed as a frozen boot. */
        if (((++loaded) & 0xFFF) == 0)
            boot_progress_note("block_index.leveldb_load", loaded, 0);
        size_t key_len;
        const char *key_data = db_iter_key(&it, &key_len);

        if (key_len < 1 || key_data[0] != DB_BLOCK_INDEX)
            break;

        size_t val_len;
        const char *val_data = db_iter_value(&it, &val_len);

        struct disk_block_index dbi;
        disk_block_index_init(&dbi);
        struct byte_stream s;
        stream_init_from_data(&s, (unsigned char *)val_data, val_len);

        if (!disk_block_index_deserialize(&dbi, &s)) {
            /* Log which key failed — helps diagnose corrupt LevelDB */
            if (key_len >= 33) {
                char hex[17];
                for (int hi = 0; hi < 8 && hi + 1 < (int)key_len; hi++)
                    snprintf(hex + hi*2, 3, "%02x",
                             (unsigned char)key_data[1 + hi]);
                fprintf(stderr,  // obs-ok:block-index-db-deserialize
                        "block_index_db: deserialize failed "
                        "key=%.16s (val_len=%zu)\n", hex, val_len);
            }
            stream_free(&s);
            db_iter_next(&it);
            continue;
        }
        stream_free(&s);

        /* Use hash from LevelDB key (bytes 1..32) to avoid recomputing
         * double-SHA256 of the full block header + equihash solution.
         * This cuts block index load from minutes to seconds. */
        struct uint256 block_hash;
        if (key_len >= 33)
            memcpy(block_hash.data, key_data + 1, 32);
        else
            disk_block_index_get_hash(&dbi, &block_hash);

        struct block_index *pindex = insert_fn(ctx, &block_hash);
        if (!pindex) {
            db_iter_next(&it);
            continue;
        }

        struct uint256 prev_hash = dbi.hashPrev;
        struct block_index *pprev = insert_fn(ctx, &prev_hash);

        pindex->pprev = pprev;
        pindex->nHeight = dbi.nHeight;
        pindex->nFile = dbi.nFile;
        pindex->nDataPos = dbi.nDataPos;
        /* CDiskBlockIndex nDataPos is already the payload offset in the
         * corresponding blkNNNNN.dat file. Preserve it byte-for-byte.
         * Translating file-0 positions here corrupts every early body read
         * when the exact zclassicd files are linked into the C23 datadir
         * (for example h=1 is 1711, not 1711 + 1703). */
        pindex->nUndoPos = dbi.nUndoPos;
        /* hashSproutAnchor not stored in block_index (Sprout deprecated) */
        pindex->nVersion = dbi.nVersion;
        pindex->hashMerkleRoot = dbi.hashMerkleRoot;
        pindex->hashFinalSaplingRoot = dbi.hashFinalSaplingRoot;
        pindex->nTime = dbi.nTime;
        pindex->nBits = dbi.nBits;
        pindex->nNonce = dbi.nNonce;
        /* Don't store solution in block_index to save RAM */
        pindex->nSolution = NULL;
        pindex->nSolutionSize = 0;
        pindex->nStatus = dbi.nStatus;
        pindex->nCachedBranchId = dbi.nCachedBranchId;
        pindex->nTx = dbi.nTx;
        if (dbi.has_sprout_value) {
            pindex->nSproutValue = dbi.nSproutValue;
            pindex->has_sprout_value = true;
        }
        pindex->nSaplingValue = dbi.nSaplingValue;

        db_iter_next(&it);
    }

    db_iter_free(&it);
    return true;
}
