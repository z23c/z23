/* Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2013 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#ifndef ZCL_UNDO_H
#define ZCL_UNDO_H

#include "coins/compressor.h"
#include "primitives/transaction.h"
#include "core/serialize.h"
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include "util/safe_alloc.h"

#define SCRIPT_COMPRESS_SPECIAL_SCRIPTS 6

struct tx_in_undo {
    struct tx_out txout;
    bool coinbase;
    unsigned int height;
    int version;
};

static inline void tx_in_undo_init(struct tx_in_undo *u)
{
    tx_out_set_null(&u->txout);
    u->coinbase = false;
    u->height = 0;
    u->version = 0;
}

static inline bool compressed_txout_serialize(const struct tx_out *txout,
                                               struct byte_stream *s)
{
    uint64_t compressed_val = compress_amount((uint64_t)txout->value);
    if (!stream_write_varint(s, compressed_val))
        return false;
    unsigned char comp[MAX_SCRIPT_SIZE];
    size_t comp_len = 0;
    if (script_compress(&txout->script_pub_key, comp, &comp_len)) {
        if (!stream_write_bytes(s, comp, comp_len))
            return false;
    } else {
        uint64_t nSize = txout->script_pub_key.size +
                         SCRIPT_COMPRESS_SPECIAL_SCRIPTS;
        if (!stream_write_varint(s, nSize))
            return false;
        if (!stream_write_bytes(s, txout->script_pub_key.data,
                                txout->script_pub_key.size))
            return false;
    }
    return true;
}

static inline bool compressed_txout_deserialize(struct tx_out *txout,
                                                struct byte_stream *s)
{
    uint64_t compressed_val = 0;
    if (!stream_read_varint(s, &compressed_val))
        return false;
    txout->value = (int64_t)decompress_amount(compressed_val);
    uint64_t nSize = 0;
    if (!stream_read_varint(s, &nSize))
        return false;
    if (nSize < SCRIPT_COMPRESS_SPECIAL_SCRIPTS) {
        unsigned int special_sz = script_compress_special_size((unsigned int)nSize);
        if (special_sz == 0)
            return false;
        unsigned char buf[65];
        if (!stream_read_bytes(s, buf, special_sz))
            return false;
        if (!script_decompress(&txout->script_pub_key, (unsigned int)nSize,
                               buf, special_sz))
            return false;
    } else {
        size_t script_len = (size_t)(nSize - SCRIPT_COMPRESS_SPECIAL_SCRIPTS);
        if (script_len > MAX_SCRIPT_SIZE)
            return false;
        txout->script_pub_key.size = (uint16_t)script_len;
        if (!stream_read_bytes(s, txout->script_pub_key.data, script_len))
            return false;
    }
    return true;
}

static inline bool tx_in_undo_serialize(const struct tx_in_undo *u,
                                        struct byte_stream *s)
{
    uint64_t code = (uint64_t)u->height * 2 + (u->coinbase ? 1 : 0);
    if (!stream_write_varint(s, code))
        return false;
    if (u->height > 0) {
        if (!stream_write_varint(s, (uint64_t)u->version))
            return false;
    }
    return compressed_txout_serialize(&u->txout, s);
}

static inline bool tx_in_undo_deserialize(struct tx_in_undo *u,
                                          struct byte_stream *s)
{
    uint64_t code = 0;
    if (!stream_read_varint(s, &code))
        return false;
    u->height = (unsigned int)(code / 2);
    u->coinbase = (code & 1) != 0;
    if (u->height > 0) {
        uint64_t v = 0;
        if (!stream_read_varint(s, &v))
            return false;
        u->version = (int)v;
    }
    return compressed_txout_deserialize(&u->txout, s);
}

struct tx_undo {
    struct tx_in_undo *vprevout;
    size_t num_prevout;
};

static inline void tx_undo_init(struct tx_undo *u)
{
    u->vprevout = NULL;
    u->num_prevout = 0;
}

static inline bool tx_undo_alloc(struct tx_undo *u, size_t n)
{
    u->vprevout = zcl_calloc(n, sizeof(struct tx_in_undo), "tx_undo_prevout");
    if (!u->vprevout && n > 0)
        return false;
    u->num_prevout = n;
    for (size_t i = 0; i < n; i++)
        tx_in_undo_init(&u->vprevout[i]);
    return true;
}

static inline void tx_undo_free(struct tx_undo *u)
{
    free(u->vprevout);
    u->vprevout = NULL;
    u->num_prevout = 0;
}

static inline bool tx_undo_serialize(const struct tx_undo *u,
                                     struct byte_stream *s)
{
    if (!stream_write_compact_size(s, u->num_prevout))
        return false;
    for (size_t i = 0; i < u->num_prevout; i++) {
        if (!tx_in_undo_serialize(&u->vprevout[i], s))
            return false;
    }
    return true;
}

static inline bool tx_undo_deserialize(struct tx_undo *u,
                                       struct byte_stream *s)
{
    uint64_t n = 0;
    if (!stream_read_compact_size(s, &n))
        return false;
    if (!tx_undo_alloc(u, (size_t)n))
        return false;
    for (size_t i = 0; i < u->num_prevout; i++) {
        if (!tx_in_undo_deserialize(&u->vprevout[i], s))
            return false;
    }
    return true;
}

struct block_undo {
    struct tx_undo *vtxundo;
    size_t num_txundo;
    struct uint256 old_sprout_tree_root;
};

static inline void block_undo_init(struct block_undo *u)
{
    u->vtxundo = NULL;
    u->num_txundo = 0;
    uint256_set_null(&u->old_sprout_tree_root);
}

static inline bool block_undo_alloc(struct block_undo *u, size_t n)
{
    u->vtxundo = zcl_calloc(n, sizeof(struct tx_undo), "block_undo_txs");
    if (!u->vtxundo && n > 0)
        return false;
    u->num_txundo = n;
    for (size_t i = 0; i < n; i++)
        tx_undo_init(&u->vtxundo[i]);
    return true;
}

static inline void block_undo_free(struct block_undo *u)
{
    for (size_t i = 0; i < u->num_txundo; i++)
        tx_undo_free(&u->vtxundo[i]);
    free(u->vtxundo);
    u->vtxundo = NULL;
    u->num_txundo = 0;
}

static inline bool block_undo_serialize(const struct block_undo *u,
                                        struct byte_stream *s)
{
    if (!stream_write_compact_size(s, u->num_txundo))
        return false;
    for (size_t i = 0; i < u->num_txundo; i++) {
        if (!tx_undo_serialize(&u->vtxundo[i], s))
            return false;
    }
    return stream_write_bytes(s, u->old_sprout_tree_root.data, 32);
}

static inline bool block_undo_deserialize(struct block_undo *u,
                                          struct byte_stream *s)
{
    uint64_t n = 0;
    if (!stream_read_compact_size(s, &n))
        return false;
    if (!block_undo_alloc(u, (size_t)n))
        return false;
    for (size_t i = 0; i < u->num_txundo; i++) {
        if (!tx_undo_deserialize(&u->vtxundo[i], s))
            return false;
    }
    return stream_read_bytes(s, u->old_sprout_tree_root.data, 32);
}

#endif
