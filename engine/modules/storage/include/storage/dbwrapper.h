/* Copyright (c) 2012-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#ifndef ZCL_STORAGE_DBWRAPPER_H
#define ZCL_STORAGE_DBWRAPPER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define DBWRAPPER_PREALLOC_KEY_SIZE 64
#define DBWRAPPER_PREALLOC_VALUE_SIZE 1024

struct db_wrapper {
    void *db;
    void *env;
    void *options;
    void *read_options;
    void *iter_options;
    void *write_options;
    void *sync_options;
    void *filter_policy;
    void *cache;
    const void *snapshot;  /* leveldb_snapshot_t for atomic iteration */
    /* XOR key parsed (length-prefix stripped) from the compact-size-prefixed
     * obfuscate_key entry the DB stores.  db_read/db_iter_value undo the XOR
     * before returning, so callers always see plaintext values. */
    uint8_t obfuscate_key[32];
    size_t obfuscate_key_len;
};

struct db_batch {
    void *batch;
};

struct db_iterator {
    void *iter;
    uint8_t obfuscate_key[32];
    size_t obfuscate_key_len;
    char *deobf_buf;
    size_t deobf_cap;
};

bool db_wrapper_open(struct db_wrapper *w, const char *path,
                     size_t cache_size, bool memory, bool wipe);
void db_wrapper_close(struct db_wrapper *w);

/* Snapshot support: creates a frozen point-in-time view of the database.
 * All iterators created after snapshot_begin see a consistent state,
 * even if the database is being written to concurrently by another process
 * sharing the same LevelDB instance. Call snapshot_end when done. */
bool db_wrapper_snapshot_begin(struct db_wrapper *w);
void db_wrapper_snapshot_end(struct db_wrapper *w);

bool db_read(struct db_wrapper *w, const char *key, size_t keylen,
             char **val, size_t *vallen);
bool db_write(struct db_wrapper *w, const char *key, size_t keylen,
              const char *val, size_t vallen, bool sync);
bool db_exists(struct db_wrapper *w, const char *key, size_t keylen);
bool db_erase(struct db_wrapper *w, const char *key, size_t keylen,
              bool sync);
bool db_is_empty(struct db_wrapper *w);

void db_batch_init(struct db_batch *b);
void db_batch_free(struct db_batch *b);
void db_batch_put(struct db_batch *b, const char *key, size_t keylen,
                  const char *val, size_t vallen);
void db_batch_delete(struct db_batch *b, const char *key, size_t keylen);
bool db_write_batch(struct db_wrapper *w, struct db_batch *b, bool sync);

void db_iter_init(struct db_iterator *it, struct db_wrapper *w);
void db_iter_free(struct db_iterator *it);
bool db_iter_valid(struct db_iterator *it);
void db_iter_seek_to_first(struct db_iterator *it);
void db_iter_seek(struct db_iterator *it, const char *key, size_t keylen);
void db_iter_next(struct db_iterator *it);
const char *db_iter_key(struct db_iterator *it, size_t *keylen);
const char *db_iter_value(struct db_iterator *it, size_t *vallen);

/* Surface any LevelDB iterator status (CRC / missing SST / I/O error) after a
 * scan. Returns true if the iteration was clean, false if an error was
 * reported. A caller treating the iterated range as a COMPLETE set MUST abort
 * on false — see db_iter_check_error() in dbwrapper.c. */
bool db_iter_check_error(struct db_iterator *it);

#endif
