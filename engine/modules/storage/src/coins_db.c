/* Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#include "storage/coins_db.h"
#include "coins_record_codec.h"
#include "core/serialize.h"
#include "util/log_macros.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char DB_COINS = 'c';
static const char DB_BEST_BLOCK = 'B';

static void make_coins_key(char *buf, size_t *len,
                            const struct uint256 *txid)
{
    buf[0] = DB_COINS;
    memcpy(buf + 1, txid->data, 32);
    *len = 33;
}

static bool cvdb_get_coins_impl(void *self, const struct uint256 *txid,
                                struct coins *out)
{
    struct coins_view_db *cvdb = (struct coins_view_db *)self;
    return coins_view_db_get_coins(cvdb, txid, out);
}

static bool cvdb_have_coins_impl(void *self, const struct uint256 *txid)
{
    struct coins_view_db *cvdb = (struct coins_view_db *)self;
    return coins_view_db_have_coins(cvdb, txid);
}

static bool cvdb_get_best_block_impl(void *self, struct uint256 *hash)
{
    struct coins_view_db *cvdb = (struct coins_view_db *)self;
    return coins_view_db_get_best_block(cvdb, hash);
}

static bool cvdb_batch_write_impl(void *self, struct coins_map *map_coins,
                                   const struct uint256 *hash_block)
{
    struct coins_view_db *cvdb = (struct coins_view_db *)self;
    return coins_view_db_batch_write(cvdb, map_coins, hash_block);
}

static struct coins_view_vtable cvdb_vtable = {
    .get_coins = cvdb_get_coins_impl,
    .have_coins = cvdb_have_coins_impl,
    .get_best_block = cvdb_get_best_block_impl,
    .batch_write = cvdb_batch_write_impl,
    .get_stats = NULL,
};

struct coins_db_decode_ctx {
    struct coins *out;
};

static bool coins_db_decode_begin(const struct coins_record_header *hdr,
                                  void *ctx)
{
    struct coins_db_decode_ctx *c = (struct coins_db_decode_ctx *)ctx;
    if (!hdr || !c || !c->out)
        return false;
    c->out->version = hdr->version;
    c->out->is_coinbase = hdr->is_coinbase;
    if (!coins_alloc(c->out, hdr->num_avail))
        return false;
    return true;
}

static bool coins_db_decode_output(const struct coins_record_output *out,
                                   void *ctx)
{
    struct coins_db_decode_ctx *c = (struct coins_db_decode_ctx *)ctx;
    if (!out || !c || !c->out || out->vout >= c->out->num_vout)
        return false;
    c->out->vout[out->vout].value = out->value;
    script_set(&c->out->vout[out->vout].script_pub_key,
               out->script, out->script_len);
    return true;
}

bool coins_view_db_open(struct coins_view_db *cvdb, const char *path,
                        size_t cache_size, bool memory, bool wipe)
{
    if (!db_wrapper_open(&cvdb->db, path, cache_size, memory, wipe))
        return false;
    cvdb->view.vtable = &cvdb_vtable;
    cvdb->view.impl = cvdb;
    return true;
}

void coins_view_db_close(struct coins_view_db *cvdb)
{
    db_wrapper_close(&cvdb->db);
}

bool coins_view_db_get_coins(struct coins_view_db *cvdb,
                             const struct uint256 *txid,
                             struct coins *out)
{
    char key[64];
    size_t keylen;
    make_coins_key(key, &keylen, txid);

    char *val = NULL;
    size_t vallen = 0;
    if (!db_read(&cvdb->db, key, keylen, &val, &vallen))
        return false;

    struct coins_db_decode_ctx ctx = { .out = out };
    struct coins_record_decode_options opts = {
        .mode = COINS_RECORD_DECODE_COINS_DB,
        .max_outputs = 0,
        .scratch = NULL,
    };
    struct coins_record_decode_ops ops = {
        .begin = coins_db_decode_begin,
        .output = coins_db_decode_output,
    };
    struct coins_record_decode_result res;
    enum coins_record_decode_status st =
        coins_record_decode((const uint8_t *)val, vallen, &opts, &ops, &ctx,
                            &res);
    if (st != COINS_RECORD_DECODE_OK) {
        free(val);
        LOG_FAIL("coins_db", "get_coins: CCoins decode failed: %s",
                 coins_record_decode_status_name(st));
    }
    out->height = res.height;

    free(val);
    coins_cleanup(out);
    return true;
}

bool coins_view_db_have_coins(struct coins_view_db *cvdb,
                              const struct uint256 *txid)
{
    char key[64];
    size_t keylen;
    make_coins_key(key, &keylen, txid);
    return db_exists(&cvdb->db, key, keylen);
}

bool coins_view_db_get_best_block(struct coins_view_db *cvdb,
                                  struct uint256 *hash)
{
    char key = DB_BEST_BLOCK;
    char *val = NULL;
    size_t vallen = 0;
    if (!db_read(&cvdb->db, &key, 1, &val, &vallen))
        return false;
    if (vallen >= 32)
        memcpy(hash->data, val, 32);
    else
        uint256_set_null(hash);
    free(val);
    return true;
}

bool coins_view_db_batch_write(struct coins_view_db *cvdb,
                               struct coins_map *map_coins,
                               const struct uint256 *hash_block)
{
    struct db_batch batch;
    db_batch_init(&batch);

    for (size_t i = 0; i < map_coins->num_buckets; i++) {
        struct coins_map_entry *e = &map_coins->buckets[i];
        if (!e->occupied || !(e->entry.flags & COINS_CACHE_DIRTY))
            continue;

        char key[64];
        size_t keylen;
        make_coins_key(key, &keylen, &e->txid);

        if (coins_is_pruned(&e->entry.coins)) {
            db_batch_delete(&batch, key, keylen);
        } else {
                struct byte_stream s;
                stream_init(&s, 256);
                const struct coins *cc = &e->entry.coins;
                (void)coins_record_encode(cc, &s);

                db_batch_put(&batch, key, keylen, (char *)s.data, s.size);
                stream_free(&s);
            }
    }

    if (!uint256_is_null(hash_block)) {
        char key = DB_BEST_BLOCK;
        db_batch_put(&batch, &key, 1, (char *)hash_block->data, 32);
    }

    bool ok = db_write_batch(&cvdb->db, &batch, true);
    db_batch_free(&batch);
    return ok;
}
