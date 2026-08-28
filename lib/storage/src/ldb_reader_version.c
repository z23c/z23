/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ldb_reader_version — reconstructs the current LevelDB view from disk:
 * CURRENT -> MANIFEST-NNNNNN -> the fold of every VersionEdit in it, plus
 * the memtable replayed out of the write-ahead log.
 *
 * Both halves are mandatory. A reader that folds only part of the
 * MANIFEST keeps files that were already superseded; a reader that skips
 * the .log returns stale values for the newest keys with no error at all.
 * The legacy chainstate on this host carries ~280 KB of unflushed writes
 * in its .log at any moment, so "SSTables only" is a silent-wrong-answer
 * bug, not an optimization.
 */

#include "ldb_reader_internal.h"

#include "util/safe_alloc.h"

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* VersionEdit tags (leveldb/db/version_edit.cc, frozen). */
enum {
    LDB_TAG_COMPARATOR = 1,
    LDB_TAG_LOG_NUMBER = 2,
    LDB_TAG_NEXT_FILE_NUMBER = 3,
    LDB_TAG_LAST_SEQUENCE = 4,
    LDB_TAG_COMPACT_POINTER = 5,
    LDB_TAG_DELETED_FILE = 6,
    LDB_TAG_NEW_FILE = 7,
    LDB_TAG_PREV_LOG_NUMBER = 9,
};

/* ── level file lists ───────────────────────────────────────────────── */

static bool level_push(struct ldb_level *lv, const struct ldb_file_meta *fm)
{
    if (lv->n == lv->cap) {
        size_t cap = lv->cap ? lv->cap * 2 : 8;
        struct ldb_file_meta *nf =
            zcl_realloc(lv->files, cap * sizeof(*nf), "ldb_level_files");
        if (!nf)
            return false;
        lv->files = nf;
        lv->cap = cap;
    }
    lv->files[lv->n++] = *fm;
    return true;
}

static void level_remove(struct ldb_level *lv, uint64_t number)
{
    for (size_t i = 0; i < lv->n; i++) {
        if (lv->files[i].number != number)
            continue;
        free(lv->files[i].smallest);
        free(lv->files[i].largest);
        ldb_table_close(lv->files[i].table);
        memmove(&lv->files[i], &lv->files[i + 1],
                (lv->n - i - 1) * sizeof(lv->files[0]));
        lv->n--;
        return;
    }
}

static int cmp_by_smallest(const void *a, const void *b)
{
    const struct ldb_file_meta *fa = a, *fb = b;
    int r = ldb_ikey_cmp(fa->smallest, fa->smallest_len, fb->smallest,
                         fb->smallest_len);
    if (r != 0)
        return r;
    if (fa->number < fb->number)
        return -1;
    if (fa->number > fb->number)
        return 1;
    return 0;
}

static int cmp_by_number_desc(const void *a, const void *b)
{
    const struct ldb_file_meta *fa = a, *fb = b;
    if (fa->number > fb->number)
        return -1;
    if (fa->number < fb->number)
        return 1;
    return 0;
}

/* ── VersionEdit decode ─────────────────────────────────────────────── */

static uint8_t *dup_bytes(const uint8_t *p, size_t n)
{
    uint8_t *out = zcl_malloc(n ? n : 1, "ldb_ikey_copy");
    if (!out)
        return NULL;
    if (n)
        memcpy(out, p, n);
    return out;
}

static bool apply_edit(struct ldb_version *v, const struct ldb_slice *rec,
                       char **err)
{
    const uint8_t *p = rec->p;
    const uint8_t *end = rec->p + rec->n;

    while (p < end) {
        uint32_t tag = 0;
        if (!ldb_get_varint32(&p, end, &tag)) {
            *err = ldb_strdup("ldb manifest: truncated version-edit tag");
            return false;
        }
        switch (tag) {
        case LDB_TAG_COMPARATOR: {
            struct ldb_slice s;
            if (!ldb_get_length_prefixed(&p, end, &s)) {
                *err = ldb_strdup("ldb manifest: truncated comparator name");
                return false;
            }
            size_t n = s.n < sizeof(v->comparator) - 1 ? s.n
                                                       : sizeof(v->comparator) - 1;
            memcpy(v->comparator, s.p, n);
            v->comparator[n] = '\0';
            v->has_comparator = true;
            break;
        }
        case LDB_TAG_LOG_NUMBER:
            if (!ldb_get_varint64(&p, end, &v->log_number))
                goto truncated;
            break;
        case LDB_TAG_PREV_LOG_NUMBER:
            if (!ldb_get_varint64(&p, end, &v->prev_log_number))
                goto truncated;
            break;
        case LDB_TAG_NEXT_FILE_NUMBER:
            if (!ldb_get_varint64(&p, end, &v->next_file_number))
                goto truncated;
            v->have_next_file = true;
            break;
        case LDB_TAG_LAST_SEQUENCE:
            if (!ldb_get_varint64(&p, end, &v->last_sequence))
                goto truncated;
            v->have_last_sequence = true;
            break;
        case LDB_TAG_COMPACT_POINTER: {
            uint32_t level = 0;
            struct ldb_slice key;
            if (!ldb_get_varint32(&p, end, &level) ||
                !ldb_get_length_prefixed(&p, end, &key))
                goto truncated;
            break;      /* compaction hint only; no bearing on reads */
        }
        case LDB_TAG_DELETED_FILE: {
            uint32_t level = 0;
            uint64_t number = 0;
            if (!ldb_get_varint32(&p, end, &level) ||
                !ldb_get_varint64(&p, end, &number))
                goto truncated;
            if (level >= LDB_MAX_LEVEL) {
                *err = ldb_errf("ldb manifest: deleted file at level %u", level);
                return false;
            }
            level_remove(&v->levels[level], number);
            break;
        }
        case LDB_TAG_NEW_FILE: {
            uint32_t level = 0;
            struct ldb_file_meta fm;
            struct ldb_slice smallest, largest;
            memset(&fm, 0, sizeof(fm));
            if (!ldb_get_varint32(&p, end, &level) ||
                !ldb_get_varint64(&p, end, &fm.number) ||
                !ldb_get_varint64(&p, end, &fm.size) ||
                !ldb_get_length_prefixed(&p, end, &smallest) ||
                !ldb_get_length_prefixed(&p, end, &largest))
                goto truncated;
            if (level >= LDB_MAX_LEVEL) {
                *err = ldb_errf("ldb manifest: new file at level %u", level);
                return false;
            }
            if (smallest.n < 8 || largest.n < 8) {
                *err = ldb_errf("ldb manifest: file %llu has a %zu-byte "
                                "internal key bound",
                                (unsigned long long)fm.number,
                                smallest.n < 8 ? smallest.n : largest.n);
                return false;
            }
            /* A re-add supersedes any earlier copy AND any pending delete,
             * matching leveldb's VersionSet::Builder. */
            level_remove(&v->levels[level], fm.number);
            fm.smallest = dup_bytes(smallest.p, smallest.n);
            fm.largest = dup_bytes(largest.p, largest.n);
            fm.smallest_len = smallest.n;
            fm.largest_len = largest.n;
            if (!fm.smallest || !fm.largest ||
                !level_push(&v->levels[level], &fm)) {
                free(fm.smallest);
                free(fm.largest);
                *err = ldb_strdup("ldb manifest: out of memory");
                return false;
            }
            break;
        }
        default:
            *err = ldb_errf("ldb manifest: unknown version-edit tag %u", tag);
            return false;
        }
    }
    return true;

truncated:
    *err = ldb_strdup("ldb manifest: truncated version-edit field");
    return false;
}

/* ── CURRENT -> MANIFEST ────────────────────────────────────────────── */

static bool read_current(const char *dir, char *out, size_t cap, char **err)
{
    char path[4096];
    snprintf(path, sizeof(path), "%s/CURRENT", dir);
    struct ldb_file_mapping file = {0};
    if (!ldb_map_file(path, &file, err))
        return false;
    size_t size = file.mapping.size;
    const uint8_t *base = file.mapping.data;
    if (size == 0 || size > cap - 1 || base[size - 1] != '\n') {
        *err = ldb_errf("ldb: CURRENT in %s is %zu bytes and not "
                        "newline-terminated", dir, size);
        ldb_unmap_file(&file);
        return false;
    }
    memcpy(out, base, size - 1);
    out[size - 1] = '\0';
    ldb_unmap_file(&file);
    if (strncmp(out, "MANIFEST-", 9) != 0 || strchr(out, '/') != NULL) {
        *err = ldb_errf("ldb: CURRENT in %s names '%s', not a MANIFEST file",
                        dir, out);
        return false;
    }
    return true;
}

bool ldb_version_load(struct ldb_version *v, const char *dir, char **err)
{
    memset(v, 0, sizeof(*v));

    char manifest_name[512];
    if (!read_current(dir, manifest_name, sizeof(manifest_name), err))
        return false;

    char path[4096];
    snprintf(path, sizeof(path), "%s/%s", dir, manifest_name);
    struct ldb_file_mapping file = {0};
    if (!ldb_map_file(path, &file, err))
        return false;
    size_t size = file.mapping.size;
    const uint8_t *base = file.mapping.data;

    struct ldb_log_reader r;
    ldb_log_reader_init(&r, base, size, true);

    bool ok = true;
    size_t edits = 0;
    struct ldb_slice rec;
    while (ldb_log_reader_next(&r, &rec)) {
        if (!apply_edit(v, &rec, err)) {
            ok = false;
            break;
        }
        edits++;
    }
    if (ok && r.err) {
        *err = r.err;
        r.err = NULL;
        ok = false;
    }
    if (ok && edits == 0) {
        *err = ldb_errf("ldb: %s contains no version edits", manifest_name);
        ok = false;
    }
    if (ok && !v->have_next_file) {
        *err = ldb_errf("ldb: %s has no meta-nextfile entry in descriptor "
                        "(truncated or corrupt MANIFEST)", manifest_name);
        ok = false;
    }
    if (ok && !v->have_last_sequence) {
        *err = ldb_errf("ldb: %s has no last-sequence entry in descriptor "
                        "(truncated or corrupt MANIFEST)", manifest_name);
        ok = false;
    }
    ldb_log_reader_free(&r);
    ldb_unmap_file(&file);

    if (!ok) {
        ldb_version_free(v);
        return false;
    }
    if (v->has_comparator && strcmp(v->comparator, "leveldb.BytewiseComparator") != 0) {
        *err = ldb_errf("ldb: database uses comparator '%s'; this reader "
                        "implements leveldb.BytewiseComparator only",
                        v->comparator);
        ldb_version_free(v);
        return false;
    }

    /* Level 0 files overlap, so Get must consult them newest-file-first.
     * Levels 1+ are disjoint and sorted by their smallest key. */
    if (v->levels[0].n > 1)
        qsort(v->levels[0].files, v->levels[0].n, sizeof(v->levels[0].files[0]),
              cmp_by_number_desc);
    for (int lv = 1; lv < LDB_MAX_LEVEL; lv++) {
        if (v->levels[lv].n > 1)
            qsort(v->levels[lv].files, v->levels[lv].n,
                  sizeof(v->levels[lv].files[0]), cmp_by_smallest);
    }
    return true;
}

void ldb_version_free(struct ldb_version *v)
{
    if (!v)
        return;
    for (int lv = 0; lv < LDB_MAX_LEVEL; lv++) {
        struct ldb_level *l = &v->levels[lv];
        for (size_t i = 0; i < l->n; i++) {
            free(l->files[i].smallest);
            free(l->files[i].largest);
            ldb_table_close(l->files[i].table);
        }
        free(l->files);
    }
    memset(v, 0, sizeof(*v));
}

/* ── write-ahead log replay ─────────────────────────────────────────── */

struct ldb_arena_block {
    struct ldb_arena_block *next;
    size_t used;
    size_t cap;
    uint8_t data[];
};

static uint8_t *arena_put(struct ldb_memtable *m, const uint8_t *src, size_t n)
{
    struct ldb_arena_block *b = m->arena;
    if (!b || b->cap - b->used < n) {
        size_t cap = 1u << 20;
        if (cap < n)
            cap = n;
        b = zcl_malloc(sizeof(*b) + cap, "ldb_memtable_arena");
        if (!b)
            return NULL;
        b->next = m->arena;
        b->used = 0;
        b->cap = cap;
        m->arena = b;
    }
    uint8_t *out = b->data + b->used;
    if (n)
        memcpy(out, src, n);
    b->used += n;
    return out;
}

static bool mem_push(struct ldb_memtable *m, const uint8_t *ikey, size_t klen,
                     const uint8_t *val, size_t vlen)
{
    if (m->n == m->cap) {
        size_t cap = m->cap ? m->cap * 2 : 256;
        struct ldb_mem_entry *ne =
            zcl_realloc(m->e, cap * sizeof(*ne), "ldb_memtable_entries");
        if (!ne)
            return false;
        m->e = ne;
        m->cap = cap;
    }
    uint8_t *k = arena_put(m, ikey, klen);
    if (!k)
        return false;
    uint8_t *val_copy = arena_put(m, val, vlen);
    if (!val_copy)
        return false;
    m->e[m->n].ikey = k;
    m->e[m->n].ikey_len = klen;
    m->e[m->n].val = val_copy;
    m->e[m->n].val_len = vlen;
    m->n++;
    return true;
}

/* A WriteBatch record: fixed64 sequence, fixed32 count, then `count`
 * tagged key(/value) pairs. */
static bool apply_batch(struct ldb_memtable *m, const struct ldb_slice *rec,
                        char **err)
{
    if (rec->n < 12) {
        *err = ldb_errf("ldb wal: write batch is %zu bytes, shorter than its "
                        "12-byte header", rec->n);
        return false;
    }
    uint64_t seq = ldb_fixed64(rec->p);
    uint32_t count = ldb_fixed32(rec->p + 8);
    const uint8_t *p = rec->p + 12;
    const uint8_t *end = rec->p + rec->n;

    uint8_t stack_key[512];
    for (uint32_t i = 0; i < count; i++) {
        if (p >= end) {
            *err = ldb_errf("ldb wal: batch claims %u records but ran out "
                            "after %u", count, i);
            return false;
        }
        uint8_t type = *p++;
        struct ldb_slice key, value = { .p = NULL, .n = 0 };
        if (!ldb_get_length_prefixed(&p, end, &key)) {
            *err = ldb_strdup("ldb wal: truncated key in write batch");
            return false;
        }
        if (type == LDB_TYPE_VALUE) {
            if (!ldb_get_length_prefixed(&p, end, &value)) {
                *err = ldb_strdup("ldb wal: truncated value in write batch");
                return false;
            }
        } else if (type != LDB_TYPE_DELETION) {
            *err = ldb_errf("ldb wal: unknown record type %u", (unsigned)type);
            return false;
        }
        if (seq + i > LDB_MAX_SEQUENCE) {
            *err = ldb_strdup("ldb wal: sequence number overflows 56 bits");
            return false;
        }

        uint8_t *ikey = stack_key;
        uint8_t *heap = NULL;
        if (key.n + 8 > sizeof(stack_key)) {
            heap = zcl_malloc(key.n + 8, "ldb_wal_ikey");
            if (!heap) {
                *err = ldb_strdup("ldb wal: out of memory");
                return false;
            }
            ikey = heap;
        }
        size_t klen = 0;
        bool ok = ldb_ikey_build(ikey, key.n + 8, key.p, key.n, seq + i, type,
                                 &klen) &&
                  mem_push(m, ikey, klen, value.p, value.n);
        free(heap);
        if (!ok) {
            *err = ldb_strdup("ldb wal: could not record write-batch entry");
            return false;
        }
    }
    return true;
}

static int cmp_mem_entry(const void *a, const void *b)
{
    const struct ldb_mem_entry *ea = a, *eb = b;
    return ldb_ikey_cmp(ea->ikey, ea->ikey_len, eb->ikey, eb->ikey_len);
}

static bool replay_log(struct ldb_memtable *m, const char *path, bool verify,
                       char **err)
{
    struct ldb_file_mapping file = {0};
    if (!ldb_map_file(path, &file, err))
        return false;
    size_t size = file.mapping.size;
    const uint8_t *base = file.mapping.data;
    struct ldb_log_reader r;
    ldb_log_reader_init(&r, base, size, verify);
    bool ok = true;
    struct ldb_slice rec;
    while (ldb_log_reader_next(&r, &rec)) {
        if (!apply_batch(m, &rec, err)) {
            ok = false;
            break;
        }
    }
    if (ok && r.err) {
        *err = r.err;
        r.err = NULL;
        ok = false;
    }
    ldb_log_reader_free(&r);
    ldb_unmap_file(&file);
    return ok;
}

/* Numeric prefix of "NNNNNN.log"; returns false for anything else. */
static bool parse_log_name(const char *name, uint64_t *number)
{
    const char *dot = strrchr(name, '.');
    if (!dot || strcmp(dot, ".log") != 0 || dot == name)
        return false;
    uint64_t n = 0;
    for (const char *p = name; p < dot; p++) {
        if (*p < '0' || *p > '9')
            return false;
        if (n > (UINT64_MAX - 9) / 10)
            return false;
        n = n * 10 + (uint64_t)(*p - '0');
    }
    *number = n;
    return true;
}

bool ldb_memtable_load(struct ldb_memtable *m, const char *dir,
                       const struct ldb_version *v, bool verify, char **err)
{
    memset(m, 0, sizeof(*m));

    DIR *d = opendir(dir);
    if (!d) {
        *err = ldb_errf("ldb: cannot list %s", dir);
        return false;
    }
    uint64_t *logs = NULL;
    size_t nlogs = 0, cap = 0;
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        uint64_t number = 0;
        if (!parse_log_name(de->d_name, &number))
            continue;
        /* Exactly leveldb's DBImpl::Recover admission test. */
        if (number < v->log_number && number != v->prev_log_number)
            continue;
        if (nlogs == cap) {
            size_t ncap = cap ? cap * 2 : 8;
            uint64_t *nl = zcl_realloc(logs, ncap * sizeof(*nl), "ldb_wal_list");
            if (!nl) {
                free(logs);
                closedir(d);
                *err = ldb_strdup("ldb: out of memory listing write-ahead logs");
                return false;
            }
            logs = nl;
            cap = ncap;
        }
        logs[nlogs++] = number;
    }
    closedir(d);

    /* Ascending file number = ascending sequence. */
    for (size_t i = 1; i < nlogs; i++) {
        uint64_t key = logs[i];
        size_t j = i;
        while (j > 0 && logs[j - 1] > key) {
            logs[j] = logs[j - 1];
            j--;
        }
        logs[j] = key;
    }

    bool ok = true;
    for (size_t i = 0; i < nlogs && ok; i++) {
        char path[4096];
        snprintf(path, sizeof(path), "%s/%06llu.log", dir,
                 (unsigned long long)logs[i]);
        ok = replay_log(m, path, verify, err);
    }
    free(logs);
    if (!ok) {
        ldb_memtable_free(m);
        return false;
    }
    if (m->n > 1)
        qsort(m->e, m->n, sizeof(m->e[0]), cmp_mem_entry);
    return true;
}

void ldb_memtable_free(struct ldb_memtable *m)
{
    if (!m)
        return;
    struct ldb_arena_block *b = m->arena;
    while (b) {
        struct ldb_arena_block *next = b->next;
        free(b);
        b = next;
    }
    free(m->e);
    memset(m, 0, sizeof(*m));
}

/* ── memtable iterator ──────────────────────────────────────────────── */

struct mem_iter {
    struct ldb_memtable *m;
    size_t i;
};

static void mi_destroy(void *self) { free(self); }

static bool mi_valid(void *self)
{
    struct mem_iter *mi = self;
    return mi->i < mi->m->n;
}

static void mi_seek_first(void *self)
{
    struct mem_iter *mi = self;
    mi->i = 0;
}

static void mi_seek(void *self, const uint8_t *k, size_t n)
{
    struct mem_iter *mi = self;
    size_t lo = 0, hi = mi->m->n;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (ldb_ikey_cmp(mi->m->e[mid].ikey, mi->m->e[mid].ikey_len, k, n) < 0)
            lo = mid + 1;
        else
            hi = mid;
    }
    mi->i = lo;
}

static void mi_next(void *self)
{
    struct mem_iter *mi = self;
    if (mi->i < mi->m->n)
        mi->i++;
}

static void mi_key(void *self, struct ldb_slice *out)
{
    struct mem_iter *mi = self;
    out->p = mi->m->e[mi->i].ikey;
    out->n = mi->m->e[mi->i].ikey_len;
}

static void mi_value(void *self, struct ldb_slice *out)
{
    struct mem_iter *mi = self;
    out->p = mi->m->e[mi->i].val;
    out->n = mi->m->e[mi->i].val_len;
}

static const char *mi_error(void *self) { (void)self; return NULL; }

static const struct ldb_iter_vt g_mem_iter_vt = {
    .destroy = mi_destroy,
    .valid = mi_valid,
    .seek_first = mi_seek_first,
    .seek = mi_seek,
    .next = mi_next,
    .key = mi_key,
    .value = mi_value,
    .error = mi_error,
};

bool ldb_memtable_iter_open(struct ldb_memtable *m, struct ldb_iter *out)
{
    struct mem_iter *mi = zcl_malloc(sizeof(*mi), "ldb_mem_iter");
    if (!mi)
        return false;
    mi->m = m;
    mi->i = m->n;
    out->vt = &g_mem_iter_vt;
    out->self = mi;
    return true;
}
