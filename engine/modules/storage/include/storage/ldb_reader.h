/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ldb_reader — a read-only LevelDB reader written in C23.
 *
 * WHY THIS EXISTS
 * ---------------
 * `vendor/lib/libleveldb.a` was the only reason this project needed a C++
 * compiler. Nothing in the tree uses LevelDB's C++ API — every call site
 * goes through the `leveldb_*` C API — so a C23 implementation of that
 * same C surface is a drop-in and the C++ toolchain requirement goes away.
 *
 * The on-disk format read here is LevelDB's, unchanged: CURRENT ->
 * MANIFEST-NNNNNN (a log of VersionEdits), .log write-ahead logs, and
 * .ldb/.sst tables with restart-array blocks under a 48-byte footer.
 * Reading the legacy `zclassicd` datadir is an interop requirement of the
 * documented bootstrap recipe, not a preference, so the format is fixed
 * by someone else and this code only ever reads it.
 *
 * WHAT IS AND IS NOT IMPLEMENTED
 * ------------------------------
 * Implemented: open/close, point reads, forward iteration (seek-to-first,
 * seek, next), snapshots, and the options/cache/filter/env handles the
 * tree already constructs. Write-ahead-log replay is implemented and
 * mandatory: an unflushed .log routinely holds the newest writes, and
 * ignoring it returns stale values with no error at all.
 *
 * NOT implemented, and refused by name rather than approximated:
 *   - every mutation (put/delete/write-batch/destroy) — this is a reader
 *   - compressed blocks (Snappy/zstd); the node writes uncompressed and
 *     the vendored C++ archive is built with HAVE_SNAPPY=0, so a
 *     compressed block already fails today
 *   - comparators other than leveldb.BytewiseComparator (nothing in the
 *     tree ever created one)
 *   - reverse iteration (seek-to-last / prev), which no call site uses
 *
 * FAILURE POSTURE
 * ---------------
 * Wrong chain-state bytes are the worst failure this project can have, so
 * every unhandled case is a typed error string, never a best-effort
 * answer. Where LevelDB *skips* a bad record and continues, this reader
 * stops and reports: a silently shortened UTXO scan is exactly the class
 * of bug that cost 219 UTXOs during a past chainstate import.
 *
 * THREADING
 * ---------
 * All state is immutable after open, so one open database may be read
 * from many threads at once. An individual iterator is single-threaded,
 * matching LevelDB.
 */
#ifndef ZCL_STORAGE_LDB_READER_H
#define ZCL_STORAGE_LDB_READER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ldbr_db ldbr_t;
typedef struct ldbr_iterator ldbr_iterator_t;
typedef struct ldbr_options ldbr_options_t;
typedef struct ldbr_readoptions ldbr_readoptions_t;
typedef struct ldbr_writeoptions ldbr_writeoptions_t;
typedef struct ldbr_snapshot ldbr_snapshot_t;
typedef struct ldbr_cache ldbr_cache_t;
typedef struct ldbr_filterpolicy ldbr_filterpolicy_t;
typedef struct ldbr_env ldbr_env_t;
typedef struct ldbr_writebatch ldbr_writebatch_t;

enum {
    ldbr_no_compression = 0,
    ldbr_snappy_compression = 1,
};

/* ── database ───────────────────────────────────────────────────────── */

/* Opens `name` read-only. On failure returns NULL and sets *errptr to a
 * malloc'd message the caller releases with ldbr_free().
 *
 * A directory with no CURRENT file is an EMPTY database when the options
 * carry create_if_missing (the datadir-predates-any-sync case), and an
 * error otherwise. Nothing is created, moved, or recovered on disk — the
 * C++ library's open mutates its target, which is why the callers that
 * only ever wanted to read had to copy a directory first. */
ldbr_t *ldbr_open(const ldbr_options_t *options, const char *name,
                  char **errptr);
void ldbr_close(ldbr_t *db);

/* Returns a malloc'd value of *vallen bytes, or NULL when the key is
 * absent. *errptr is set only on a real failure (corruption, I/O). */
char *ldbr_get(ldbr_t *db, const ldbr_readoptions_t *options, const char *key,
               size_t keylen, size_t *vallen, char **errptr);

void ldbr_free(void *ptr);

/* Refused: this is a reader. Each sets *errptr and changes nothing. */
void ldbr_put(ldbr_t *db, const ldbr_writeoptions_t *options, const char *key,
              size_t keylen, const char *val, size_t vallen, char **errptr);
void ldbr_delete(ldbr_t *db, const ldbr_writeoptions_t *options,
                 const char *key, size_t keylen, char **errptr);
void ldbr_write(ldbr_t *db, const ldbr_writeoptions_t *options,
                ldbr_writebatch_t *batch, char **errptr);
void ldbr_destroy_db(const ldbr_options_t *options, const char *name,
                     char **errptr);
void ldbr_compact_range(ldbr_t *db, const char *start_key, size_t start_len,
                        const char *limit_key, size_t limit_len);

/* ── iteration (forward only) ───────────────────────────────────────── */

ldbr_iterator_t *ldbr_create_iterator(ldbr_t *db,
                                      const ldbr_readoptions_t *options);
void ldbr_iter_destroy(ldbr_iterator_t *it);
unsigned char ldbr_iter_valid(const ldbr_iterator_t *it);
void ldbr_iter_seek_to_first(ldbr_iterator_t *it);
void ldbr_iter_seek(ldbr_iterator_t *it, const char *k, size_t klen);
void ldbr_iter_next(ldbr_iterator_t *it);
const char *ldbr_iter_key(const ldbr_iterator_t *it, size_t *klen);
const char *ldbr_iter_value(const ldbr_iterator_t *it, size_t *vlen);
void ldbr_iter_get_error(const ldbr_iterator_t *it, char **errptr);

/* ── snapshots (a read-only view is already frozen) ─────────────────── */

const ldbr_snapshot_t *ldbr_create_snapshot(ldbr_t *db);
void ldbr_release_snapshot(ldbr_t *db, const ldbr_snapshot_t *snapshot);

/* ── options ────────────────────────────────────────────────────────── */

ldbr_options_t *ldbr_options_create(void);
void ldbr_options_destroy(ldbr_options_t *options);
void ldbr_options_set_create_if_missing(ldbr_options_t *o, unsigned char v);
void ldbr_options_set_error_if_exists(ldbr_options_t *o, unsigned char v);
void ldbr_options_set_paranoid_checks(ldbr_options_t *o, unsigned char v);
void ldbr_options_set_compression(ldbr_options_t *o, int v);
void ldbr_options_set_max_open_files(ldbr_options_t *o, int n);
void ldbr_options_set_cache(ldbr_options_t *o, ldbr_cache_t *c);
void ldbr_options_set_filter_policy(ldbr_options_t *o, ldbr_filterpolicy_t *p);
void ldbr_options_set_env(ldbr_options_t *o, ldbr_env_t *env);

ldbr_readoptions_t *ldbr_readoptions_create(void);
void ldbr_readoptions_destroy(ldbr_readoptions_t *o);
void ldbr_readoptions_set_verify_checksums(ldbr_readoptions_t *o,
                                           unsigned char v);
void ldbr_readoptions_set_fill_cache(ldbr_readoptions_t *o, unsigned char v);
void ldbr_readoptions_set_snapshot(ldbr_readoptions_t *o,
                                   const ldbr_snapshot_t *snap);

ldbr_writeoptions_t *ldbr_writeoptions_create(void);
void ldbr_writeoptions_destroy(ldbr_writeoptions_t *o);
void ldbr_writeoptions_set_sync(ldbr_writeoptions_t *o, unsigned char v);

/* Accepted so callers still compile; the batch is inert and ldbr_write
 * refuses it. */
ldbr_writebatch_t *ldbr_writebatch_create(void);
void ldbr_writebatch_destroy(ldbr_writebatch_t *b);
void ldbr_writebatch_put(ldbr_writebatch_t *b, const char *key, size_t klen,
                         const char *val, size_t vlen);
void ldbr_writebatch_delete(ldbr_writebatch_t *b, const char *key, size_t klen);

/* Inert handles: this reader keeps whole tables mapped instead of running
 * a block cache, and it never consults a bloom filter or an env. */
ldbr_cache_t *ldbr_cache_create_lru(size_t capacity);
void ldbr_cache_destroy(ldbr_cache_t *c);
ldbr_filterpolicy_t *ldbr_filterpolicy_create_bloom(int bits_per_key);
void ldbr_filterpolicy_destroy(ldbr_filterpolicy_t *p);
ldbr_env_t *ldbr_create_default_env(void);
void ldbr_env_destroy(ldbr_env_t *env);

/* ── introspection (used by the differential harness and tests) ─────── */

/* Number of SSTables the folded MANIFEST left live, and the number of
 * write-ahead-log entries replayed into the memtable. */
size_t ldbr_stat_table_count(const ldbr_t *db);
size_t ldbr_stat_memtable_entries(const ldbr_t *db);

#ifdef __cplusplus
}
#endif

#endif /* ZCL_STORAGE_LDB_READER_H */
