/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ldb_reader_table — SSTable (.ldb/.sst) reading for the C23 LevelDB
 * reader: mmap, 48-byte footer + magic, index block, and the two-level
 * (index block -> data block) forward iterator.
 *
 * The file is mapped once and kept mapped for the life of the table, so a
 * full-keyspace scan costs one page-cache walk instead of an open/read/
 * close per block. Every block handle is validated against the mapped
 * extent before a byte of it is touched, and the 5-byte block trailer's
 * compression byte and masked CRC-32C are both checked: an unexpected
 * compression type is refused by name rather than decoded as garbage.
 */

#include "ldb_reader_internal.h"

#include "util/crc32c.h"
#include "util/safe_alloc.h"

#include <stdlib.h>
#include <string.h>

/* ── block handles + footer ─────────────────────────────────────────── */

struct ldb_handle {
    uint64_t offset;
    uint64_t size;
};

static bool decode_handle(const uint8_t **pp, const uint8_t *end,
                          struct ldb_handle *h)
{
    return ldb_get_varint64(pp, end, &h->offset) &&
           ldb_get_varint64(pp, end, &h->size);
}

/* Materialize the block a handle names, verifying the trailer. */
static bool read_block(const struct ldb_table *t, const struct ldb_handle *h,
                       bool verify, struct ldb_block *out, char **err)
{
    uint64_t need = h->size + LDB_BLOCK_TRAILER_SIZE;
    if (h->size > t->file_size || h->offset > t->file_size ||
        need > (uint64_t)t->file_size - h->offset) {
        if (err)
            *err = ldb_errf("ldb table: block handle offset=%llu size=%llu "
                            "outside a %zu-byte file",
                            (unsigned long long)h->offset,
                            (unsigned long long)h->size, t->file_size);
        return false;
    }
    const uint8_t *p = t->base + h->offset;
    size_t n = (size_t)h->size;
    uint8_t ctype = p[n];

    if (verify) {
        uint32_t want = ldb_unmask_crc(ldb_fixed32(p + n + 1));
        uint32_t got = zcl_crc32c(p, n + 1);
        if (want != got) {
            if (err)
                *err = ldb_errf("ldb table: block crc32c mismatch at offset "
                                "%llu (want %08x got %08x)",
                                (unsigned long long)h->offset, want, got);
            return false;
        }
    }
    if (ctype != 0) {
        /* This reader refuses compressed blocks by name. The node's own
         * writer sets no_compression, and the vendored C++ archive is
         * built with HAVE_SNAPPY=0, so a compressed block already fails
         * today — it must never silently decode as raw bytes here. */
        if (err)
            *err = ldb_errf("ldb table: unsupported block compression type %u "
                            "at offset %llu (this reader handles uncompressed "
                            "blocks only)",
                            (unsigned)ctype, (unsigned long long)h->offset);
        return false;
    }
    if (!ldb_block_init(out, p, n, NULL)) {
        if (err)
            *err = ldb_errf("ldb table: malformed restart array in block at "
                            "offset %llu", (unsigned long long)h->offset);
        return false;
    }
    return true;
}

struct ldb_table *ldb_table_open(const char *path, bool verify, char **err)
{
    struct ldb_file_mapping file = {0};
    if (!ldb_map_file(path, &file, err))
        return NULL;
    size_t size = file.mapping.size;
    const uint8_t *base = file.mapping.data;
    if (size < LDB_FOOTER_LEN) {
        if (err)
            *err = ldb_errf("ldb table: %s is %zu bytes, shorter than the "
                            "%u-byte footer", path, size, LDB_FOOTER_LEN);
        ldb_unmap_file(&file);
        return NULL;
    }

    const uint8_t *foot = base + size - LDB_FOOTER_LEN;
    uint64_t magic = (uint64_t)ldb_fixed32(foot + 40) |
                     ((uint64_t)ldb_fixed32(foot + 44) << 32);
    if (magic != LDB_TABLE_MAGIC) {
        if (err)
            *err = ldb_errf("ldb table: %s has magic %016llx, expected "
                            "%016llx (not a LevelDB SSTable)", path,
                            (unsigned long long)magic,
                            (unsigned long long)LDB_TABLE_MAGIC);
        ldb_unmap_file(&file);
        return NULL;
    }

    struct ldb_handle metaindex, index;
    const uint8_t *p = foot;
    const uint8_t *end = foot + 40;
    if (!decode_handle(&p, end, &metaindex) || !decode_handle(&p, end, &index)) {
        if (err)
            *err = ldb_errf("ldb table: %s has a malformed footer handle",
                            path);
        ldb_unmap_file(&file);
        return NULL;
    }

    struct ldb_table *t = zcl_malloc(sizeof(*t), "ldb_table");
    if (!t) {
        if (err)
            *err = ldb_strdup("ldb table: out of memory");
        ldb_unmap_file(&file);
        return NULL;
    }
    memset(t, 0, sizeof(*t));
    t->file = file;
    t->base = base;
    t->file_size = size;
    t->verify = verify;

    if (!read_block(t, &index, verify, &t->index, err)) {
        ldb_unmap_file(&t->file);
        free(t);
        return NULL;
    }
    return t;
}

void ldb_table_close(struct ldb_table *t)
{
    if (!t)
        return;
    ldb_block_free(&t->index);
    ldb_unmap_file(&t->file);
    free(t->err);
    free(t);
}

/* ── two-level iterator ─────────────────────────────────────────────── */

struct table_iter {
    struct ldb_table *t;
    struct ldb_block_iter index_it;
    struct ldb_block data_blk;
    struct ldb_block_iter data_it;
    bool data_open;
    char *err;
};

static void ti_close_data(struct table_iter *ti)
{
    if (ti->data_open) {
        ldb_block_iter_free(&ti->data_it);
        ldb_block_free(&ti->data_blk);
        ti->data_open = false;
    }
}

static void ti_fail(struct table_iter *ti, char *msg)
{
    if (!ti->err)
        ti->err = msg;
    else
        free(msg);
    ti_close_data(ti);
}

/* Open the data block the current index entry points at. */
static bool ti_open_data(struct table_iter *ti)
{
    ti_close_data(ti);
    if (!ti->index_it.valid)
        return false;
    const uint8_t *p = ti->index_it.value.p;
    const uint8_t *end = p + ti->index_it.value.n;
    struct ldb_handle h;
    if (!decode_handle(&p, end, &h)) {
        ti_fail(ti, ldb_strdup("ldb table: malformed index entry handle"));
        return false;
    }
    char *err = NULL;
    if (!read_block(ti->t, &h, ti->t->verify, &ti->data_blk, &err)) {
        ti_fail(ti, err ? err : ldb_strdup("ldb table: unreadable data block"));
        return false;
    }
    if (!ldb_block_iter_init(&ti->data_it, &ti->data_blk)) {
        ldb_block_free(&ti->data_blk);
        ti_fail(ti, ldb_strdup("ldb table: data block has no restart points"));
        return false;
    }
    ti->data_open = true;
    return true;
}

/* After a Next/Seek that ran a data block dry, walk forward through index
 * entries until one yields a live entry (or the table ends). */
static void ti_skip_forward(struct table_iter *ti)
{
    while (!ti->err && (!ti->data_open || !ti->data_it.valid)) {
        if (!ti->index_it.valid)
            return;
        ldb_block_iter_next(&ti->index_it);
        if (ti->index_it.corrupt) {
            ti_fail(ti, ldb_strdup("ldb table: corrupt index block entry"));
            return;
        }
        if (!ti->index_it.valid) {
            ti_close_data(ti);
            return;
        }
        if (!ti_open_data(ti))
            return;
        ldb_block_iter_seek_first(&ti->data_it);
        if (ti->data_it.corrupt) {
            ti_fail(ti, ldb_strdup("ldb table: corrupt data block entry"));
            return;
        }
    }
}

static void ti_destroy(void *self)
{
    struct table_iter *ti = self;
    ti_close_data(ti);
    ldb_block_iter_free(&ti->index_it);
    free(ti->err);
    free(ti);
}

static bool ti_valid(void *self)
{
    struct table_iter *ti = self;
    return !ti->err && ti->data_open && ti->data_it.valid;
}

static void ti_seek_first(void *self)
{
    struct table_iter *ti = self;
    if (ti->err)
        return;
    ti_close_data(ti);
    ldb_block_iter_seek_first(&ti->index_it);
    if (ti->index_it.corrupt) {
        ti_fail(ti, ldb_strdup("ldb table: corrupt index block entry"));
        return;
    }
    if (!ti->index_it.valid)
        return;
    if (!ti_open_data(ti))
        return;
    ldb_block_iter_seek_first(&ti->data_it);
    if (ti->data_it.corrupt) {
        ti_fail(ti, ldb_strdup("ldb table: corrupt data block entry"));
        return;
    }
    ti_skip_forward(ti);
}

static void ti_seek(void *self, const uint8_t *k, size_t n)
{
    struct table_iter *ti = self;
    if (ti->err)
        return;
    ti_close_data(ti);
    ldb_block_iter_seek(&ti->index_it, k, n);
    if (ti->index_it.corrupt) {
        ti_fail(ti, ldb_strdup("ldb table: corrupt index block entry"));
        return;
    }
    if (!ti->index_it.valid)
        return;                 /* past the last block: nothing at or after */
    if (!ti_open_data(ti))
        return;
    ldb_block_iter_seek(&ti->data_it, k, n);
    if (ti->data_it.corrupt) {
        ti_fail(ti, ldb_strdup("ldb table: corrupt data block entry"));
        return;
    }
    ti_skip_forward(ti);
}

static void ti_next(void *self)
{
    struct table_iter *ti = self;
    if (ti->err || !ti->data_open)
        return;
    ldb_block_iter_next(&ti->data_it);
    if (ti->data_it.corrupt) {
        ti_fail(ti, ldb_strdup("ldb table: corrupt data block entry"));
        return;
    }
    ti_skip_forward(ti);
}

static void ti_key(void *self, struct ldb_slice *out)
{
    struct table_iter *ti = self;
    out->p = ti->data_it.key;
    out->n = ti->data_it.key_len;
}

static void ti_value(void *self, struct ldb_slice *out)
{
    struct table_iter *ti = self;
    *out = ti->data_it.value;
}

static const char *ti_error(void *self)
{
    struct table_iter *ti = self;
    return ti->err;
}

static const struct ldb_iter_vt g_table_iter_vt = {
    .destroy = ti_destroy,
    .valid = ti_valid,
    .seek_first = ti_seek_first,
    .seek = ti_seek,
    .next = ti_next,
    .key = ti_key,
    .value = ti_value,
    .error = ti_error,
};

bool ldb_table_iter_open(struct ldb_table *t, struct ldb_iter *out)
{
    struct table_iter *ti = zcl_malloc(sizeof(*ti), "ldb_table_iter");
    if (!ti)
        return false;
    memset(ti, 0, sizeof(*ti));
    ti->t = t;
    if (!ldb_block_iter_init(&ti->index_it, &t->index)) {
        /* An index block with no restart points cannot name any data
         * block; treat the table as empty rather than guessing. */
        ti->err = ldb_strdup("ldb table: index block has no restart points");
    }
    out->vt = &g_table_iter_vt;
    out->self = ti;
    return true;
}
