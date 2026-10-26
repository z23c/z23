/* Copyright (c) 2012-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#include "storage/dbwrapper.h"
#include "storage/ldb_c_api.h"
#include "platform/directory_compat.h"
#include "util/util.h"
#include "util/log_macros.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "util/safe_alloc.h"

/* Reject paths that cannot hold a database: NULL, empty, or (on Windows) a
 * UNC share. */
static bool db_wrapper_path_is_unusable(const char *path)
{
    if (!path || !path[0]) return true;
#if defined(_WIN32)
    if ((path[0] == '/' && path[1] == '/') ||
        (path[0] == '\\' && path[1] == '\\'))
        return true; /* UNC custody policy is not qualified. */
#endif
    return false;
}

/* A separator forces creation of the prefix directory above it unless it is
 * the leading root or the one following a drive-letter colon. */
static bool db_wrapper_separator_needs_mkdir(const char *p,
                                             const char *start)
{
    if (*p != '/' && *p != '\\') return false;
    if (p == start || (p == start + 2 && start[1] == ':')) return false;
    return true;
}

static bool db_wrapper_ensure_directory(const char *path)
{
    if (db_wrapper_path_is_unusable(path)) return false;
    char tmp[1024];
    int n = snprintf(tmp, sizeof(tmp), "%s", path);
    if (n < 0 || (size_t)n >= sizeof(tmp)) return false;
    for (char *p = tmp; *p; ++p) {
        if (!db_wrapper_separator_needs_mkdir(p, tmp)) continue;
        char separator = *p;
        *p = '\0';
        bool ok = platform_directory_ensure(tmp, 0755);
        *p = separator;
        if (!ok) return false;
    }
    return platform_directory_ensure(tmp, 0755);
}

/* Argument sanity only: the stricter UNC refusal lives in
 * db_wrapper_ensure_directory and must not gate in-memory opens. */
static bool db_wrapper_open_args_invalid(const struct db_wrapper *w,
                                         const char *path)
{
    return !w || !path || !path[0];
}

/* In-memory databases need no backing directory; on-disk ones must have one. */
static bool db_wrapper_directory_ready(const char *path, bool memory)
{
    if (memory) return true;
    return db_wrapper_ensure_directory(path);
}

/* Destroy any existing database at path before opening; a destroy error is
 * freed and dropped here and would resurface as an open failure. */
static void db_wrapper_wipe_if_requested(const char *path, bool wipe,
                                         bool memory)
{
    if (wipe && !memory) {
        leveldb_options_t *opts = leveldb_options_create();
        char *err = NULL;
        leveldb_destroy_db(opts, path, &err);
        leveldb_options_destroy(opts);
        if (err) { leveldb_free(err); }
    }
}

static void db_wrapper_configure_options(struct db_wrapper *w,
                                         size_t cache_size, bool memory)
{
    w->options = leveldb_options_create();
    leveldb_options_set_create_if_missing(w->options, 1);
    leveldb_options_set_compression(w->options, leveldb_no_compression);
    leveldb_options_set_max_open_files(w->options, 64);

    if (cache_size > 0) {
        w->cache = leveldb_cache_create_lru(cache_size);
        leveldb_options_set_cache(w->options, w->cache);
    }

    w->filter_policy = leveldb_filterpolicy_create_bloom(10);
    leveldb_options_set_filter_policy(w->options, w->filter_policy);

    if (memory) {
        w->env = leveldb_create_default_env();
        leveldb_options_set_env(w->options, w->env);
    }
}

/* Map ZCL_LEVELDB_NO_VERIFY_CHECKSUMS to the 1/0 value handed to LevelDB:
 * any of 1/y/Y/t/T in the flag's first byte turns verification off. */
static int db_wrapper_verify_checksums_setting(const char *flag)
{
    bool off = flag && (flag[0] == '1' || flag[0] == 'y' ||
                        flag[0] == 'Y' || flag[0] == 't' ||
                        flag[0] == 'T');
    return off ? 0 : 1;
}

/* Read the obfuscation-key value: the compact-size-prefixed key first, then
 * the bare 14-byte form.  A read error is freed and reported as absence. */
static char *db_wrapper_fetch_obfuscate_value(struct db_wrapper *w,
                                              size_t *vlen)
{
    /* The key in the DB: 0x0e (compact size = 14) followed by
     * the 14-byte string "\x00obfuscate_key" */
    char obf_db_key[16];
    obf_db_key[0] = 0x0e;  /* compact_size(14) */
    obf_db_key[1] = 0x00;  /* first byte of the key string */
    memcpy(obf_db_key + 2, "obfuscate_key", 13);
    size_t obf_keylen = 15;

    char *err2 = NULL;
    char *val = leveldb_get(w->db, w->read_options,
                            obf_db_key, obf_keylen, vlen, &err2);
    if (err2) {
        leveldb_free(err2);
        val = NULL;
    }

    if (!val) {
        /* Try alternate key format: just "\0obfuscate_key" (14 bytes) */
        obf_db_key[0] = 0x00;
        memcpy(obf_db_key + 1, "obfuscate_key", 13);
        obf_keylen = 14;
        err2 = NULL;
        val = leveldb_get(w->db, w->read_options,
                          obf_db_key, obf_keylen, vlen, &err2);
        if (err2) { leveldb_free(err2); val = NULL; }
    }
    return val;
}

/* Append min(len, limit) bytes to hex as blank-separated two-digit hex,
 * the diagnostic format used on the obfuscate-key path. */
static void db_wrapper_format_hex(char *hex, size_t cap,
                                  const unsigned char *bytes, size_t len,
                                  size_t limit)
{
    size_t off = 0;
    for (size_t i = 0; i < len && i < limit; i++)
        off += (size_t)snprintf(hex + off, cap - off, " %02x", bytes[i]);
}

/* The stored value is a length-prefixed key only when the prefix fits both
 * the 32-byte wrapper field and the value it was read from. */
static bool db_wrapper_prefixed_key_valid(uint8_t klen, size_t vlen)
{
    return klen > 0 && klen <= 32 && (size_t)(klen + 1) <= vlen;
}

static void db_wrapper_store_obfuscate_key(struct db_wrapper *w,
                                           const char *src, size_t len)
{
    memcpy(w->obfuscate_key, src, len);
    w->obfuscate_key_len = len;
}

static void db_wrapper_free_obfuscate_value(char *val)
{
    if (val) leveldb_free(val);
}

bool db_wrapper_open(struct db_wrapper *w, const char *path,
                     size_t cache_size, bool memory, bool wipe)
{
    if (db_wrapper_open_args_invalid(w, path)) return false;
    memset(w, 0, sizeof(*w));

    if (!db_wrapper_directory_ready(path, memory)) {
        LogPrintf("LevelDB directory validation failure at %s\n", path);
        return false;
    }

    db_wrapper_wipe_if_requested(path, wipe, memory);

    db_wrapper_configure_options(w, cache_size, memory);

    char *err = NULL;
    w->db = leveldb_open(w->options, path, &err);
    if (err) {
        LogPrintf("LevelDB open failure at %s: %s\n", path, err);
        leveldb_free(err);
        db_wrapper_close(w);
        return false;
    }

    w->read_options = leveldb_readoptions_create();
    w->iter_options = leveldb_readoptions_create();
    /* Default: verify checksums on both point reads and iteration.  A
     * corrupt LevelDB block now surfaces as a halt (caller-handled)
     * rather than silently truncating the iterator mid-scan — the
     * previous default caused a 219-UTXO silent drop during a
     * chainstate import.  The performance/correctness trade-off is
     * now explicit: opt out via `-leveldb-no-verify-checksums` (which
     * sets ZCL_LEVELDB_NO_VERIFY_CHECKSUMS=1) only when an operator
     * is actively troubleshooting suspected corruption.  We emit one
     * WARN per process when the off-path is selected so it shows up
     * in logs. */
    const char *skip = getenv("ZCL_LEVELDB_NO_VERIFY_CHECKSUMS");
    int verify_setting = db_wrapper_verify_checksums_setting(skip);
    bool verify_on = verify_setting != 0;
    leveldb_readoptions_set_verify_checksums(w->read_options, verify_setting);
    leveldb_readoptions_set_verify_checksums(w->iter_options, verify_setting);
    if (!verify_on) {
        static bool warned_once = false;
        if (!warned_once) {
            LogPrintf(
                "[leveldb] WARN: verify_checksums=OFF "
                "(ZCL_LEVELDB_NO_VERIFY_CHECKSUMS set) — silent block "
                "corruption will truncate iterators.  Use only for "
                "performance experiments or recovery debugging.\n");
            warned_once = true;
        }
    }
    leveldb_readoptions_set_fill_cache(w->read_options, 1);
    leveldb_readoptions_set_fill_cache(w->iter_options, 0);

    w->write_options = leveldb_writeoptions_create();
    w->sync_options = leveldb_writeoptions_create();
    leveldb_writeoptions_set_sync(w->sync_options, 1);

    /* Read obfuscation key (Bitcoin Core stores it with CDataStream serialization:
     * key = compact_size(14) + "\0obfuscate_key" = 0x0e + 0x00 + "obfuscate_key"
     * value = compact_size(8) + 8 random bytes */
    w->obfuscate_key_len = 0;
    memset(w->obfuscate_key, 0, sizeof(w->obfuscate_key));
    {
        size_t vlen = 0;
        char *val = db_wrapper_fetch_obfuscate_value(w, &vlen);

        if (val && vlen > 0) {
            /* Hex-dump diagnostics into one line each so they land in the
             * log alongside the read/write failure paths.  Buffer holds up
             * to 32 key bytes (3 hex chars apiece) plus a label. */
            char hex[128];
            db_wrapper_format_hex(hex, sizeof(hex),
                                  (const unsigned char *)val, vlen, 16);
            LogPrintf("DB obfuscate_key raw value (%zu bytes):%s\n", vlen, hex);

            /* Value format: compact_size(n) + n bytes of key */
            uint8_t klen = (uint8_t)val[0];
            if (db_wrapper_prefixed_key_valid(klen, vlen)) {
                db_wrapper_store_obfuscate_key(w, val + 1, klen);
                db_wrapper_format_hex(hex, sizeof(hex),
                                      (const unsigned char *)w->obfuscate_key,
                                      w->obfuscate_key_len,
                                      w->obfuscate_key_len);
                LogPrintf("DB obfuscation key (%zu bytes):%s\n",
                          w->obfuscate_key_len, hex);
            } else if (vlen <= 32) {
                /* Maybe value is the raw key without length prefix */
                db_wrapper_store_obfuscate_key(w, val, vlen);
                db_wrapper_format_hex(hex, sizeof(hex),
                                      (const unsigned char *)w->obfuscate_key,
                                      w->obfuscate_key_len,
                                      w->obfuscate_key_len);
                LogPrintf("DB obfuscation key (raw, %zu bytes):%s\n",
                          w->obfuscate_key_len, hex);
            }
        } else {
            LogPrintf("DB: no obfuscation key found\n");
        }
        db_wrapper_free_obfuscate_value(val);
    }

    return true;
}

bool db_wrapper_snapshot_begin(struct db_wrapper *w)
{
    if (!w || !w->db)
        LOG_FAIL("dbwrapper", "snapshot_begin: wrapper or db is NULL");
    if (w->snapshot) return true; /* already active */

    w->snapshot = leveldb_create_snapshot(w->db);
    if (!w->snapshot)
        LOG_FAIL("dbwrapper", "snapshot_begin: leveldb_create_snapshot returned NULL");

    /* Point iter_options at the snapshot so all new iterators see a
     * frozen, consistent view of the database. */
    leveldb_readoptions_set_snapshot(w->iter_options, w->snapshot);
    return true;
}

void db_wrapper_snapshot_end(struct db_wrapper *w)
{
    if (!w || !w->db || !w->snapshot) return;

    leveldb_readoptions_set_snapshot(w->iter_options, NULL);
    leveldb_release_snapshot(w->db, w->snapshot);
    w->snapshot = NULL;
}

void db_wrapper_close(struct db_wrapper *w)
{
    if (w->snapshot && w->db) {
        leveldb_readoptions_set_snapshot(w->iter_options, NULL);
        leveldb_release_snapshot(w->db, w->snapshot);
        w->snapshot = NULL;
    }
    if (w->db) leveldb_close(w->db);
    if (w->read_options) leveldb_readoptions_destroy(w->read_options);
    if (w->iter_options) leveldb_readoptions_destroy(w->iter_options);
    if (w->write_options) leveldb_writeoptions_destroy(w->write_options);
    if (w->sync_options) leveldb_writeoptions_destroy(w->sync_options);
    if (w->filter_policy) leveldb_filterpolicy_destroy(w->filter_policy);
    if (w->cache) leveldb_cache_destroy(w->cache);
    if (w->options) leveldb_options_destroy(w->options);
    if (w->env) leveldb_env_destroy(w->env);
    memset(w, 0, sizeof(*w));
}

/* Reverse the LevelDB XOR obfuscation: dst[i] = src[i] ^ key[i % key_len].
 * Bitcoin Core stores chainstate values XOR'd with a per-DB key; reads must
 * undo it before the bytes mean anything.  Safe to call in place (dst == src)
 * since each byte is consumed before it is overwritten. */
static void db_deobfuscate(char *dst, const char *src, size_t len,
                           const uint8_t *key, size_t key_len)
{
    for (size_t i = 0; i < len; i++)
        dst[i] = src[i] ^ (char)key[i % key_len];
}

bool db_read(struct db_wrapper *w, const char *key, size_t keylen,
             char **val, size_t *vallen)
{
    char *err = NULL;
    *val = leveldb_get(w->db, w->read_options, key, keylen, vallen, &err);
    if (err) {
        LogPrintf("LevelDB read failure: %s\n", err);
        leveldb_free(err);
        return false;
    }
    if (*val && w->obfuscate_key_len > 0)
        db_deobfuscate(*val, *val, *vallen,
                       w->obfuscate_key, w->obfuscate_key_len);
    return *val != NULL;
}

bool db_write(struct db_wrapper *w, const char *key, size_t keylen,
              const char *val, size_t vallen, bool sync)
{
    char *err = NULL;
    leveldb_put(w->db, sync ? w->sync_options : w->write_options,
                key, keylen, val, vallen, &err);
    if (err) {
        LogPrintf("LevelDB write failure: %s\n", err);
        leveldb_free(err);
        return false;
    }
    return true;
}

bool db_exists(struct db_wrapper *w, const char *key, size_t keylen)
{
    size_t vallen;
    char *val = NULL;
    char *err = NULL;
    val = leveldb_get(w->db, w->read_options, key, keylen, &vallen, &err);
    if (err) {
        leveldb_free(err);
        return false;
    }
    bool found = val != NULL;
    leveldb_free(val);
    return found;
}

bool db_erase(struct db_wrapper *w, const char *key, size_t keylen, bool sync)
{
    char *err = NULL;
    leveldb_delete(w->db, sync ? w->sync_options : w->write_options,
                   key, keylen, &err);
    if (err) {
        LogPrintf("LevelDB delete failure: %s\n", err);
        leveldb_free(err);
        return false;
    }
    return true;
}

bool db_is_empty(struct db_wrapper *w)
{
    leveldb_iterator_t *it = leveldb_create_iterator(w->db, w->iter_options);
    leveldb_iter_seek_to_first(it);
    bool empty = !leveldb_iter_valid(it);
    leveldb_iter_destroy(it);
    return empty;
}

/* --- Batch --- */

void db_batch_init(struct db_batch *b)
{
    b->batch = leveldb_writebatch_create();
}

void db_batch_free(struct db_batch *b)
{
    if (b->batch) leveldb_writebatch_destroy(b->batch);
    b->batch = NULL;
}

void db_batch_put(struct db_batch *b, const char *key, size_t keylen,
                  const char *val, size_t vallen)
{
    leveldb_writebatch_put(b->batch, key, keylen, val, vallen);
}

void db_batch_delete(struct db_batch *b, const char *key, size_t keylen)
{
    leveldb_writebatch_delete(b->batch, key, keylen);
}

bool db_write_batch(struct db_wrapper *w, struct db_batch *b, bool sync)
{
    char *err = NULL;
    leveldb_write(w->db, sync ? w->sync_options : w->write_options,
                  b->batch, &err);
    if (err) {
        LogPrintf("LevelDB batch write failure: %s\n", err);
        leveldb_free(err);
        return false;
    }
    return true;
}

/* --- Iterator --- */

void db_iter_init(struct db_iterator *it, struct db_wrapper *w)
{
    it->iter = leveldb_create_iterator(w->db, w->iter_options);
    memcpy(it->obfuscate_key, w->obfuscate_key, w->obfuscate_key_len);
    it->obfuscate_key_len = w->obfuscate_key_len;
    it->deobf_buf = NULL;
    it->deobf_cap = 0;
}

/* Returns true if the iterator finished cleanly (no LevelDB error), false if
 * leveldb_iter_get_error reported a status (a block-level CRC mismatch, a
 * missing/torn SST, or any I/O error surfaced mid-iteration). A caller that
 * treats the iterated range as a COMPLETE set MUST abort on false — swallowing
 * the error yields a silently TRUNCATED set (see the UTXO import reader loop in
 * node_db_import_service.c). */
bool db_iter_check_error(struct db_iterator *it)
{
    if (!it || !it->iter)
        return false;
    char *err = NULL;
    leveldb_iter_get_error(it->iter, &err);
    if (err) {
        LogPrintf("LevelDB iterator error: %s\n", err);
        leveldb_free(err);
        return false;
    }
    return true;
}

void db_iter_free(struct db_iterator *it)
{
    if (it->iter) leveldb_iter_destroy(it->iter);
    free(it->deobf_buf);
    it->iter = NULL;
    it->deobf_buf = NULL;
    it->deobf_cap = 0;
}

bool db_iter_valid(struct db_iterator *it)
{
    return leveldb_iter_valid(it->iter) != 0;
}

void db_iter_seek_to_first(struct db_iterator *it)
{
    leveldb_iter_seek_to_first(it->iter);
}

void db_iter_seek(struct db_iterator *it, const char *key, size_t keylen)
{
    leveldb_iter_seek(it->iter, key, keylen);
}

void db_iter_next(struct db_iterator *it)
{
    leveldb_iter_next(it->iter);
}

const char *db_iter_key(struct db_iterator *it, size_t *keylen)
{
    return leveldb_iter_key(it->iter, keylen);
}

#if defined(ZCL_TESTING)
/* Test seam: non-NULL replaces the leveldb_iter_value fetch so a test can
 * drive the growth-representability edge with a synthetic length, without
 * a giant allocation. The hook receives the iterator's raw leveldb handle
 * and must not dereference it. */
const char *(*db_iter_value_raw_test_hook)(void *iter, size_t *vallen);
#endif

static const char *db_iter_value_raw(struct db_iterator *it, size_t *vallen)
{
#if defined(ZCL_TESTING)
    if (db_iter_value_raw_test_hook)
        return db_iter_value_raw_test_hook(it->iter, vallen);
#endif
    return leveldb_iter_value(it->iter, vallen);
}

const char *db_iter_value(struct db_iterator *it, size_t *vallen)
{
    const char *raw = db_iter_value_raw(it, vallen);
    if (!raw || it->obfuscate_key_len == 0)
        return raw;

    /* Unrepresentable growth refused: *vallen + 256 must not wrap. No real
     * database value can reach this, so this is defence in depth. */
    if (*vallen > SIZE_MAX - 256)
        return NULL;

    /* Deobfuscate into a reusable buffer */
    if (*vallen > it->deobf_cap) {
        free(it->deobf_buf);
        it->deobf_cap = *vallen + 256;
        it->deobf_buf = zcl_malloc(it->deobf_cap, "dbwrapper_deobf_buf");
        if (!it->deobf_buf) {
            it->deobf_cap = 0;
            return NULL;
        }
    }
    db_deobfuscate(it->deobf_buf, raw, *vallen,
                   it->obfuscate_key, it->obfuscate_key_len);
    return it->deobf_buf;
}
