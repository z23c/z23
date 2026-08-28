/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ldb_reader_internal — private shared declarations for the C23 read-only
 * LevelDB reader (public surface: storage/ldb_reader.h).
 *
 * Split across four translation units:
 *   ldb_reader_format.c   byte decoding, block decoding, block iterators
 *   ldb_reader_table.c    SSTable open (mmap + footer + index) and iterators
 *   ldb_reader_version.c  CURRENT/MANIFEST fold and write-ahead-log memtable
 *   ldb_reader_db.c       merged view, point reads, and the public API
 *
 * Everything here parses bytes that another process wrote and that may be
 * truncated, torn, or hostile. Every offset, length prefix, and varint is
 * bounds-checked against the mapped extent before use; nothing returns
 * partial data with a success status.
 */
#ifndef ZCL_STORAGE_LDB_READER_INTERNAL_H
#define ZCL_STORAGE_LDB_READER_INTERNAL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* ── on-disk constants (LevelDB format, frozen) ────────────────────── */

#define LDB_BLOCK_TRAILER_SIZE   5u        /* 1 compression byte + 4 crc */
#define LDB_FOOTER_LEN           48u       /* 2 handles (20 max) + 8 magic */
#define LDB_TABLE_MAGIC          0xdb4775248b80fb57ULL
#define LDB_LOG_BLOCK_SIZE       32768u
#define LDB_LOG_HEADER_SIZE      7u        /* crc32 + len16 + type8 */
#define LDB_MAX_LEVEL            7
#define LDB_MAX_SEQUENCE         ((uint64_t)0x00ffffffffffffffULL)

enum ldb_record_type {
    LDB_REC_ZERO = 0,
    LDB_REC_FULL = 1,
    LDB_REC_FIRST = 2,
    LDB_REC_MIDDLE = 3,
    LDB_REC_LAST = 4,
};

enum ldb_value_type {
    LDB_TYPE_DELETION = 0,
    LDB_TYPE_VALUE = 1,
};

/* ── slices ─────────────────────────────────────────────────────────── */

struct ldb_slice {
    const uint8_t *p;
    size_t n;
};

/* ── little-endian + varint decoding (all bounds-checked) ───────────── */

uint32_t ldb_fixed32(const uint8_t *p);
uint64_t ldb_fixed64(const uint8_t *p);

/* Decode a varint from [*pp, end). Advances *pp on success. Returns false
 * on truncation or on an encoding longer than the type allows. */
bool ldb_get_varint32(const uint8_t **pp, const uint8_t *end, uint32_t *out);
bool ldb_get_varint64(const uint8_t **pp, const uint8_t *end, uint64_t *out);
/* varint32 length prefix followed by that many bytes. */
bool ldb_get_length_prefixed(const uint8_t **pp, const uint8_t *end,
                             struct ldb_slice *out);

/* LevelDB's crc masking (a raw crc is never stored directly). */
uint32_t ldb_unmask_crc(uint32_t masked);

/* ── internal keys ──────────────────────────────────────────────────── */

/* An internal key is user_key || fixed64_le(sequence << 8 | type) and
 * orders by user key ascending, then by that trailer DESCENDING so the
 * newest write for a user key sorts first. Getting this backwards
 * resurrects deleted records, so it has exactly one implementation. */
int ldb_ikey_cmp(const uint8_t *a, size_t an, const uint8_t *b, size_t bn);
int ldb_ukey_cmp(const uint8_t *a, size_t an, const uint8_t *b, size_t bn);
/* User-key view of an internal key; false when it is shorter than 8. */
bool ldb_ikey_user(const uint8_t *k, size_t n, struct ldb_slice *user,
                   uint64_t *sequence, uint8_t *type);
/* Write user_key || pack(seq,type) into buf (cap must be n + 8). */
bool ldb_ikey_build(uint8_t *buf, size_t cap, const uint8_t *user, size_t n,
                    uint64_t seq, uint8_t type, size_t *out_len);

/* ── blocks ─────────────────────────────────────────────────────────── */

struct ldb_block {
    const uint8_t *data;    /* entry region + restart array */
    size_t size;
    uint32_t num_restarts;
    size_t restart_off;
    uint8_t *owned;         /* non-NULL when data must be freed */
};

/* Parse the restart trailer. Fails on any inconsistent framing. */
bool ldb_block_init(struct ldb_block *b, const uint8_t *data, size_t size,
                    uint8_t *owned);
void ldb_block_free(struct ldb_block *b);

struct ldb_block_iter {
    const struct ldb_block *b;
    size_t cur;             /* offset of current entry */
    size_t next_off;        /* offset just past current entry */
    uint8_t *key;
    size_t key_len;
    size_t key_cap;
    struct ldb_slice value;
    bool valid;
    bool corrupt;
};

bool ldb_block_iter_init(struct ldb_block_iter *it, const struct ldb_block *b);
void ldb_block_iter_free(struct ldb_block_iter *it);
void ldb_block_iter_seek_first(struct ldb_block_iter *it);
void ldb_block_iter_seek(struct ldb_block_iter *it, const uint8_t *target,
                         size_t tlen);
void ldb_block_iter_next(struct ldb_block_iter *it);

/* ── generic forward iterator (merge children speak this) ───────────── */

struct ldb_iter_vt {
    void (*destroy)(void *self);
    bool (*valid)(void *self);
    void (*seek_first)(void *self);
    void (*seek)(void *self, const uint8_t *k, size_t n);
    void (*next)(void *self);
    void (*key)(void *self, struct ldb_slice *out);
    void (*value)(void *self, struct ldb_slice *out);
    const char *(*error)(void *self);   /* NULL when clean */
};

struct ldb_iter {
    const struct ldb_iter_vt *vt;
    void *self;
};

static inline void ldb_iter_destroy(struct ldb_iter *i)
{
    if (i && i->vt && i->self) {
        i->vt->destroy(i->self);
        i->self = NULL;
    }
}

/* ── tables ─────────────────────────────────────────────────────────── */

struct ldb_table {
    const uint8_t *base;    /* mmap of the whole .ldb file */
    size_t file_size;
    struct ldb_block index;
    bool verify;
    char *err;              /* first open error, owned */
};

/* Opens path and parses footer + index block. Returns NULL and sets *err
 * (caller-owned strdup) on any framing/checksum failure. */
struct ldb_table *ldb_table_open(const char *path, bool verify, char **err);
void ldb_table_close(struct ldb_table *t);
bool ldb_table_iter_open(struct ldb_table *t, struct ldb_iter *out);

/* ── file metadata + version ────────────────────────────────────────── */

struct ldb_file_meta {
    uint64_t number;
    uint64_t size;
    uint8_t *smallest;
    size_t smallest_len;
    uint8_t *largest;
    size_t largest_len;
    struct ldb_table *table;   /* opened lazily, owned */
};

struct ldb_level {
    struct ldb_file_meta *files;
    size_t n;
    size_t cap;
};

struct ldb_version {
    struct ldb_level levels[LDB_MAX_LEVEL];
    uint64_t log_number;
    uint64_t prev_log_number;
    uint64_t next_file_number;
    uint64_t last_sequence;
    /* LevelDB's VersionSet::Recover returns Corruption when the folded
     * descriptor never carried these. Without them a truncated MANIFEST
     * folds whatever prefix survived and reports success. */
    bool have_next_file;
    bool have_last_sequence;
    bool has_comparator;
    char comparator[64];
};

/* True when dir holds a MANIFEST-NNNNNN, or any .ldb, .sst or .log file.
 * Distinguishes a fresh empty datadir from one that lost its CURRENT;
 * unreadable answers true, because unreadable is not evidence of emptiness. */
bool ldb_dir_holds_database_files(const char *dir);

/* Reads CURRENT, folds every VersionEdit in the named MANIFEST. */
bool ldb_version_load(struct ldb_version *v, const char *dir, char **err);
void ldb_version_free(struct ldb_version *v);

/* ── memtable recovered from the write-ahead log ────────────────────── */

struct ldb_mem_entry {
    const uint8_t *ikey;
    size_t ikey_len;
    const uint8_t *val;
    size_t val_len;
};

struct ldb_arena_block;

struct ldb_memtable {
    struct ldb_mem_entry *e;
    size_t n;
    size_t cap;
    struct ldb_arena_block *arena;
};

/* Replays every .log in dir whose number qualifies under v, in ascending
 * order, into a sorted in-memory table. A torn tail record is dropped the
 * way LevelDB drops it; a checksum failure inside a complete record is an
 * error. */
bool ldb_memtable_load(struct ldb_memtable *m, const char *dir,
                       const struct ldb_version *v, bool verify, char **err);
void ldb_memtable_free(struct ldb_memtable *m);
bool ldb_memtable_iter_open(struct ldb_memtable *m, struct ldb_iter *out);

/* ── log-record reader (shared by MANIFEST and the write-ahead log) ─── */

struct ldb_log_reader {
    const uint8_t *base;
    size_t size;
    size_t pos;
    uint8_t *scratch;
    size_t scratch_len;
    size_t scratch_cap;
    bool verify;
    char *err;
};

bool ldb_log_reader_init(struct ldb_log_reader *r, const uint8_t *base,
                         size_t size, bool verify);
void ldb_log_reader_free(struct ldb_log_reader *r);
/* Returns true and fills *rec while records remain. Sets r->err on a
 * checksum or framing failure; a truncated tail ends the stream cleanly. */
bool ldb_log_reader_next(struct ldb_log_reader *r, struct ldb_slice *rec);

/* ── database core (ldb_reader_db.c), consumed by the API surface ───── */

struct ldbr_db;
struct ldbr_iterator;

struct ldbr_db *ldbr_db_open_internal(const char *dir, bool verify,
                                      bool allow_missing, char **err);
void ldbr_db_close_internal(struct ldbr_db *db);
bool ldbr_db_get_internal(struct ldbr_db *db, const uint8_t *ukey, size_t klen,
                          uint8_t **val, size_t *vlen, char **err);
struct ldbr_iterator *ldbr_db_iter_internal(struct ldbr_db *db);

/* ── small helpers shared across the reader ─────────────────────────── */

char *ldb_strdup(const char *s);
char *ldb_errf(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
/* mmap a whole file read-only; returns NULL and sets *err on failure. */
const uint8_t *ldb_map_file(const char *path, size_t *out_size, char **err);
void ldb_unmap_file(const uint8_t *base, size_t size);

#endif /* ZCL_STORAGE_LDB_READER_INTERNAL_H */
