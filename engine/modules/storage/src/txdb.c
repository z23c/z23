/* Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#include "storage/txdb.h"
#include "core/serialize.h"
#include "util/log_macros.h"
#include <stdlib.h>
#include <string.h>

static const char DB_TXINDEX = 't';
static const char DB_REINDEX_FLAG = 'R';
static const char DB_FLAG = 'F';

static void make_key_char(char *buf, size_t *len, char prefix)
{
    buf[0] = prefix;
    *len = 1;
}

static void make_key_char_hash(char *buf, size_t *len, char prefix,
                                const struct uint256 *hash)
{
    buf[0] = prefix;
    memcpy(buf + 1, hash->data, 32);
    *len = 33;
}

static void make_key_char_str(char *buf, size_t *len, char prefix,
                               const char *name)
{
    buf[0] = prefix;
    size_t slen = strlen(name);
    memcpy(buf + 1, name, slen);
    *len = 1 + slen;
}

bool block_tree_db_open(struct block_tree_db *btdb, const char *path,
                        size_t cache_size, bool memory, bool wipe)
{
    return db_wrapper_open(&btdb->db, path, cache_size, memory, wipe);
}

void block_tree_db_close(struct block_tree_db *btdb)
{
    db_wrapper_close(&btdb->db);
}

bool block_tree_db_write_reindexing(struct block_tree_db *btdb, bool reindexing)
{
    char key[64];
    size_t keylen;
    make_key_char(key, &keylen, DB_REINDEX_FLAG);

    if (reindexing) {
        char val = '1';
        return db_write(&btdb->db, key, keylen, &val, 1, true);
    } else {
        return db_erase(&btdb->db, key, keylen, true);
    }
}

bool block_tree_db_read_reindexing(struct block_tree_db *btdb, bool *reindexing)
{
    char key[64];
    size_t keylen;
    make_key_char(key, &keylen, DB_REINDEX_FLAG);
    *reindexing = db_exists(&btdb->db, key, keylen);
    return true;
}

/* Decode a Bitcoin-style varint from a byte buffer.
 * Returns number of bytes consumed, or 0 on error. */
static size_t decode_varint(const uint8_t *buf, size_t len, uint64_t *out)
{
    uint64_t n = 0;
    size_t i = 0;
    while (i < len) {
        uint8_t ch = buf[i];
        if (n > (UINT64_MAX >> 7)) return 0; /* overflow */
        n = (n << 7) | (ch & 0x7F);
        i++;
        if (ch & 0x80) {
            n++; /* Bitcoin varint: high bit = more bytes, add 1 */
        } else {
            *out = n;
            return i;
        }
    }
    return 0; /* truncated */
}

bool block_tree_db_read_tx_index(struct block_tree_db *btdb,
                                  const struct uint256 *txid,
                                  struct disk_tx_pos *pos)
{
    char key[64];
    size_t keylen;
    make_key_char_hash(key, &keylen, DB_TXINDEX, txid);

    char *val = NULL;
    size_t vallen = 0;
    if (!db_read(&btdb->db, key, keylen, &val, &vallen))
        return false;

    /* Try raw struct format first (written by zclassic23) */
    if (vallen == sizeof(struct disk_tx_pos)) {
        memcpy(pos, val, sizeof(struct disk_tx_pos));
        free(val);
        return true;
    }

    /* Decode varint format (written by zclassicd/Bitcoin Core):
     * CDiskTxPos inherits CDiskBlockPos: varint(nFile) + varint(nDataPos)
     * then adds varint(nTxOffset) */
    disk_tx_pos_init(pos);
    const uint8_t *p = (const uint8_t *)val;
    size_t off = 0;
    uint64_t v;

    size_t consumed = decode_varint(p + off, vallen - off, &v);
    if (!consumed) { free(val); return true; }
    pos->block_pos.nFile = (int)v;
    off += consumed;

    consumed = decode_varint(p + off, vallen - off, &v);
    if (!consumed) { free(val); return true; }
    pos->block_pos.nPos = (unsigned int)v;
    off += consumed;

    consumed = decode_varint(p + off, vallen - off, &v);
    if (!consumed) { free(val); return true; }
    pos->nTxOffset = (unsigned int)v;
    off += consumed;

    free(val);
    return true;
}

bool block_tree_db_write_tx_index(struct block_tree_db *btdb,
                                   const struct uint256 *txids,
                                   const struct disk_tx_pos *positions,
                                   size_t count)
{
    for (size_t i = 0; i < count; i++) {
        char key[64];
        size_t keylen;
        make_key_char_hash(key, &keylen, DB_TXINDEX, &txids[i]);
        if (!db_write(&btdb->db, key, keylen,
                      (const char *)&positions[i], sizeof(struct disk_tx_pos),
                      false))
            LOG_FAIL("txdb", "write_tx_index: db_write failed at index %zu", i);
    }
    return true;
}

bool block_tree_db_write_flag(struct block_tree_db *btdb,
                               const char *name, bool value)
{
    char key[256];
    size_t keylen;
    make_key_char_str(key, &keylen, DB_FLAG, name);
    char val = value ? '1' : '0';
    return db_write(&btdb->db, key, keylen, &val, 1, false);
}

bool block_tree_db_read_flag(struct block_tree_db *btdb,
                              const char *name, bool *value)
{
    char key[256];
    size_t keylen;
    make_key_char_str(key, &keylen, DB_FLAG, name);

    char *val = NULL;
    size_t vallen = 0;
    if (!db_read(&btdb->db, key, keylen, &val, &vallen))
        return false;

    *value = vallen > 0 && val[0] == '1';
    free(val);
    return true;
}
