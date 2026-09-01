/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ldb_reader_db — the merged view: memtable over level-0 tables (newest
 * file number first) over the disjoint, binary-searchable levels 1..6,
 * plus the user-facing iterator that resolves sequence numbers and
 * tombstones down to one visible record per user key.
 *
 * This is the part that is easy to get subtly wrong and still pass a
 * smoke test. Two rules carry the correctness of the whole reader:
 *   1. internal keys order by user key ASCENDING then sequence
 *      DESCENDING, so the newest write for a key is the first one seen;
 *   2. a kTypeDeletion entry hides every older entry for that user key.
 * Invert either and spent outputs come back to life.
 */

#include "ldb_reader_internal.h"
#include "storage/ldb_reader.h"

#include "util/safe_alloc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct ldbr_db {
    char *dir;
    struct ldb_version version;
    struct ldb_memtable mem;
    bool verify;
    bool empty;             /* no CURRENT and create_if_missing was set */
    size_t table_count;
};

/* ── level (concatenating) iterator over disjoint sorted files ──────── */

struct level_iter {
    struct ldb_file_meta *files;
    size_t n;
    size_t idx;
    struct ldb_iter cur;
    bool cur_open;
    char *err;
};

static void li_close_cur(struct level_iter *li)
{
    if (li->cur_open) {
        ldb_iter_destroy(&li->cur);
        li->cur_open = false;
    }
}

static bool li_open(struct level_iter *li, size_t idx)
{
    li_close_cur(li);
    if (idx >= li->n)
        return false;
    if (!ldb_table_iter_open(li->files[idx].table, &li->cur)) {
        if (!li->err)
            li->err = ldb_strdup("ldb: out of memory opening a table iterator");
        return false;
    }
    li->idx = idx;
    li->cur_open = true;
    return true;
}

static void li_capture_err(struct level_iter *li)
{
    if (li->err || !li->cur_open)
        return;
    const char *e = li->cur.vt->error(li->cur.self);
    if (e)
        li->err = ldb_strdup(e);
}

/* Advance through following files until one yields an entry. */
static void li_skip_forward(struct level_iter *li)
{
    while (!li->err) {
        if (li->cur_open) {
            li_capture_err(li);
            if (li->err)
                return;
            if (li->cur.vt->valid(li->cur.self))
                return;
        }
        if (!li->cur_open || li->idx + 1 >= li->n) {
            li_close_cur(li);
            return;
        }
        if (!li_open(li, li->idx + 1))
            return;
        li->cur.vt->seek_first(li->cur.self);
    }
}

static void lvi_destroy(void *self)
{
    struct level_iter *li = self;
    li_close_cur(li);
    free(li->err);
    free(li);
}

static bool lvi_valid(void *self)
{
    struct level_iter *li = self;
    return !li->err && li->cur_open && li->cur.vt->valid(li->cur.self);
}

static void lvi_seek_first(void *self)
{
    struct level_iter *li = self;
    if (li->err || li->n == 0)
        return;
    if (!li_open(li, 0))
        return;
    li->cur.vt->seek_first(li->cur.self);
    li_skip_forward(li);
}

static void lvi_seek(void *self, const uint8_t *k, size_t n)
{
    struct level_iter *li = self;
    if (li->err || li->n == 0)
        return;
    /* First file whose largest key is >= the target. Levels 1+ are
     * disjoint and sorted, so there is at most one candidate. */
    size_t lo = 0, hi = li->n;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (ldb_ikey_cmp(li->files[mid].largest, li->files[mid].largest_len, k,
                         n) < 0)
            lo = mid + 1;
        else
            hi = mid;
    }
    if (lo >= li->n) {
        li_close_cur(li);
        return;
    }
    if (!li_open(li, lo))
        return;
    li->cur.vt->seek(li->cur.self, k, n);
    li_skip_forward(li);
}

static void lvi_next(void *self)
{
    struct level_iter *li = self;
    if (li->err || !li->cur_open)
        return;
    li->cur.vt->next(li->cur.self);
    li_skip_forward(li);
}

static void lvi_key(void *self, struct ldb_slice *out)
{
    struct level_iter *li = self;
    li->cur.vt->key(li->cur.self, out);
}

static void lvi_value(void *self, struct ldb_slice *out)
{
    struct level_iter *li = self;
    li->cur.vt->value(li->cur.self, out);
}

static const char *lvi_error(void *self)
{
    struct level_iter *li = self;
    if (li->err)
        return li->err;
    if (li->cur_open)
        return li->cur.vt->error(li->cur.self);
    return NULL;
}

static const struct ldb_iter_vt g_level_iter_vt = {
    .destroy = lvi_destroy,  .valid = lvi_valid,   .seek_first = lvi_seek_first,
    .seek = lvi_seek,        .next = lvi_next,     .key = lvi_key,
    .value = lvi_value,      .error = lvi_error,
};

static bool level_iter_open(struct ldb_level *lv, struct ldb_iter *out)
{
    struct level_iter *li = zcl_malloc(sizeof(*li), "ldb_level_iter");
    if (!li)
        return false;
    memset(li, 0, sizeof(*li));
    li->files = lv->files;
    li->n = lv->n;
    out->vt = &g_level_iter_vt;
    out->self = li;
    return true;
}

/* ── merging iterator ───────────────────────────────────────────────── */

struct merge_iter {
    struct ldb_iter *ch;
    size_t n;
    size_t cur;             /* == n when nothing is positioned */
    char *err;
};

static void mrg_pick_smallest(struct merge_iter *mi)
{
    mi->cur = mi->n;
    for (size_t i = 0; i < mi->n; i++) {
        const char *e = mi->ch[i].vt->error(mi->ch[i].self);
        if (e) {
            if (!mi->err)
                mi->err = ldb_strdup(e);
            mi->cur = mi->n;
            return;
        }
        if (!mi->ch[i].vt->valid(mi->ch[i].self))
            continue;
        if (mi->cur == mi->n) {
            mi->cur = i;
            continue;
        }
        struct ldb_slice a, b;
        mi->ch[i].vt->key(mi->ch[i].self, &a);
        mi->ch[mi->cur].vt->key(mi->ch[mi->cur].self, &b);
        if (ldb_ikey_cmp(a.p, a.n, b.p, b.n) < 0)
            mi->cur = i;
    }
}

static void mrg_destroy(void *self)
{
    struct merge_iter *mi = self;
    for (size_t i = 0; i < mi->n; i++)
        ldb_iter_destroy(&mi->ch[i]);
    free(mi->ch);
    free(mi->err);
    free(mi);
}

static bool mrg_valid(void *self)
{
    struct merge_iter *mi = self;
    return !mi->err && mi->cur < mi->n;
}

static void mrg_seek_first(void *self)
{
    struct merge_iter *mi = self;
    for (size_t i = 0; i < mi->n; i++)
        mi->ch[i].vt->seek_first(mi->ch[i].self);
    mrg_pick_smallest(mi);
}

static void mrg_seek(void *self, const uint8_t *k, size_t n)
{
    struct merge_iter *mi = self;
    for (size_t i = 0; i < mi->n; i++)
        mi->ch[i].vt->seek(mi->ch[i].self, k, n);
    mrg_pick_smallest(mi);
}

static void mrg_next(void *self)
{
    struct merge_iter *mi = self;
    if (mi->cur >= mi->n)
        return;
    mi->ch[mi->cur].vt->next(mi->ch[mi->cur].self);
    mrg_pick_smallest(mi);
}

static void mrg_key(void *self, struct ldb_slice *out)
{
    struct merge_iter *mi = self;
    mi->ch[mi->cur].vt->key(mi->ch[mi->cur].self, out);
}

static void mrg_value(void *self, struct ldb_slice *out)
{
    struct merge_iter *mi = self;
    mi->ch[mi->cur].vt->value(mi->ch[mi->cur].self, out);
}

static const char *mrg_error(void *self)
{
    struct merge_iter *mi = self;
    return mi->err;
}

static const struct ldb_iter_vt g_merge_iter_vt = {
    .destroy = mrg_destroy,  .valid = mrg_valid,   .seek_first = mrg_seek_first,
    .seek = mrg_seek,        .next = mrg_next,     .key = mrg_key,
    .value = mrg_value,      .error = mrg_error,
};

/* memtable + one child per level-0 file + one per level 1..6 */
static bool merged_view_open(struct ldbr_db *db, struct ldb_iter *out)
{
    size_t cap = 1 + db->version.levels[0].n + (LDB_MAX_LEVEL - 1);
    struct merge_iter *mi = zcl_malloc(sizeof(*mi), "ldb_merge_iter");
    if (!mi)
        return false;
    memset(mi, 0, sizeof(*mi));
    mi->ch = zcl_malloc(cap * sizeof(*mi->ch), "ldb_merge_children");
    if (!mi->ch) {
        free(mi);
        return false;
    }

    bool ok = ldb_memtable_iter_open(&db->mem, &mi->ch[mi->n]);
    if (ok)
        mi->n++;
    for (size_t i = 0; ok && i < db->version.levels[0].n; i++) {
        ok = ldb_table_iter_open(db->version.levels[0].files[i].table,
                                 &mi->ch[mi->n]);
        if (ok)
            mi->n++;
    }
    for (int lv = 1; ok && lv < LDB_MAX_LEVEL; lv++) {
        if (db->version.levels[lv].n == 0)
            continue;
        ok = level_iter_open(&db->version.levels[lv], &mi->ch[mi->n]);
        if (ok)
            mi->n++;
    }
    if (!ok) {
        mrg_destroy(mi);
        return false;
    }
    mi->cur = mi->n;
    out->vt = &g_merge_iter_vt;
    out->self = mi;
    return true;
}

/* ── open / close ───────────────────────────────────────────────────── */

static bool open_all_tables(struct ldbr_db *db, char **err)
{
    for (int lv = 0; lv < LDB_MAX_LEVEL; lv++) {
        struct ldb_level *l = &db->version.levels[lv];
        for (size_t i = 0; i < l->n; i++) {
            char path[4096];
            snprintf(path, sizeof(path), "%s/%06llu.ldb", db->dir,
                     (unsigned long long)l->files[i].number);
            char *terr = NULL;
            struct ldb_table *t = ldb_table_open(path, db->verify, &terr);
            if (!t && access(path, F_OK) != 0) {
                /* Pre-1.14 databases name tables .sst. Only fall back when
                 * the .ldb is genuinely ABSENT — a .ldb that exists but is
                 * truncated or has a broken footer must report its own
                 * failure, not "no such file: <number>.sst". */
                free(terr);
                terr = NULL;
                snprintf(path, sizeof(path), "%s/%06llu.sst", db->dir,
                         (unsigned long long)l->files[i].number);
                t = ldb_table_open(path, db->verify, &terr);
            }
            if (!t) {
                *err = terr ? terr
                            : ldb_errf("ldb: table %llu (level %d) is missing",
                                       (unsigned long long)l->files[i].number,
                                       lv);
                return false;
            }
            l->files[i].table = t;
            db->table_count++;
        }
    }
    return true;
}

struct ldbr_db *ldbr_db_open_internal(const char *dir, bool verify,
                                      bool allow_missing, char **err)
{
    struct ldbr_db *db = zcl_malloc(sizeof(*db), "ldbr_db");
    if (!db) {
        *err = ldb_strdup("ldb: out of memory");
        return NULL;
    }
    memset(db, 0, sizeof(*db));
    db->verify = verify;
    db->dir = ldb_strdup(dir);
    if (!db->dir) {
        free(db);
        *err = ldb_strdup("ldb: out of memory");
        return NULL;
    }

    char current[4096];
    snprintf(current, sizeof(current), "%s/CURRENT", dir);
    char *probe_err = NULL;
    struct ldb_file_mapping probe = {0};
    if (!ldb_map_file(current, &probe, &probe_err)) {
        free(probe_err);
        if (!allow_missing) {
            *err = ldb_errf("ldb: %s has no CURRENT file and "
                            "create_if_missing was not set", dir);
            ldbr_db_close_internal(db);
            return NULL;
        }
        /* create_if_missing only licenses treating a directory with NOTHING
         * in it as a fresh empty database. A directory that holds real
         * LevelDB files but has lost CURRENT is a damaged database, and
         * reporting it as empty would hand back zero records with no error —
         * a chainstate would read as zero UTXOs. Production opens with
         * create_if_missing set (dbwrapper.c), so this is the live path.
         * Refuse by name instead. */
        if (ldb_dir_holds_database_files(dir)) {
            *err = ldb_errf("ldb: %s has no CURRENT file but holds LevelDB "
                            "data files — damaged database, refusing to "
                            "report it as empty", dir);
            ldbr_db_close_internal(db);
            return NULL;
        }
        /* Datadir that predates any sync: an empty database, exactly what
         * the C++ library produced here by creating one. */
        db->empty = true;
        return db;
    }
    ldb_unmap_file(&probe);

    if (!ldb_version_load(&db->version, dir, err)) {
        ldbr_db_close_internal(db);
        return NULL;
    }
    if (!open_all_tables(db, err)) {
        ldbr_db_close_internal(db);
        return NULL;
    }
    if (!ldb_memtable_load(&db->mem, dir, &db->version, verify, err)) {
        ldbr_db_close_internal(db);
        return NULL;
    }
    return db;
}

void ldbr_db_close_internal(struct ldbr_db *db)
{
    if (!db)
        return;
    ldb_memtable_free(&db->mem);
    ldb_version_free(&db->version);
    free(db->dir);
    free(db);
}

size_t ldbr_stat_table_count(const struct ldbr_db *db)
{
    return db ? db->table_count : 0;
}

size_t ldbr_stat_memtable_entries(const struct ldbr_db *db)
{
    return db ? db->mem.n : 0;
}

/* ── point read, in level order with an early exit ──────────────────── */

static bool table_point_get(struct ldb_table *t, const uint8_t *lookup,
                            size_t lookup_len, const uint8_t *ukey,
                            size_t klen, bool *found, uint8_t **val,
                            size_t *vlen, char **err)
{
    struct ldb_iter it;
    if (!ldb_table_iter_open(t, &it)) {
        *err = ldb_strdup("ldb: out of memory opening a table iterator");
        return false;
    }
    bool ok = true;
    it.vt->seek(it.self, lookup, lookup_len);
    const char *e = it.vt->error(it.self);
    if (e) {
        *err = ldb_strdup(e);
        ok = false;
    } else if (it.vt->valid(it.self)) {
        struct ldb_slice k, v, user;
        uint8_t type = 0;
        it.vt->key(it.self, &k);
        if (!ldb_ikey_user(k.p, k.n, &user, NULL, &type)) {
            *err = ldb_strdup("ldb: malformed internal key in table");
            ok = false;
        } else if (ldb_ukey_cmp(user.p, user.n, ukey, klen) == 0) {
            *found = true;
            if (type == LDB_TYPE_VALUE) {
                it.vt->value(it.self, &v);
                *val = zcl_malloc(v.n ? v.n : 1, "ldb_get_value");
                if (!*val) {
                    *err = ldb_strdup("ldb: out of memory");
                    ok = false;
                } else {
                    if (v.n)
                        memcpy(*val, v.p, v.n);
                    *vlen = v.n;
                }
            }
        }
    }
    ldb_iter_destroy(&it);
    return ok;
}

static bool file_may_contain(const struct ldb_file_meta *f, const uint8_t *ukey,
                             size_t klen)
{
    if (f->smallest_len < 8 || f->largest_len < 8)
        return false;
    return ldb_ukey_cmp(ukey, klen, f->smallest, f->smallest_len - 8) >= 0 &&
           ldb_ukey_cmp(ukey, klen, f->largest, f->largest_len - 8) <= 0;
}

bool ldbr_db_get_internal(struct ldbr_db *db, const uint8_t *ukey, size_t klen,
                          uint8_t **val, size_t *vlen, char **err)
{
    *val = NULL;
    *vlen = 0;
    if (db->empty)
        return true;

    uint8_t stack[512];
    uint8_t *lookup = stack;
    uint8_t *heap = NULL;
    if (klen + 8 > sizeof(stack)) {
        heap = zcl_malloc(klen + 8, "ldb_lookup_key");
        if (!heap) {
            *err = ldb_strdup("ldb: out of memory");
            return false;
        }
        lookup = heap;
    }
    size_t lookup_len = 0;
    if (!ldb_ikey_build(lookup, klen + 8, ukey, klen, LDB_MAX_SEQUENCE,
                        LDB_TYPE_VALUE, &lookup_len)) {
        free(heap);
        *err = ldb_strdup("ldb: could not build a lookup key");
        return false;
    }

    bool ok = true;
    bool found = false;

    /* 1. memtable — the newest writes live only here until a flush. */
    if (db->mem.n > 0) {
        size_t lo = 0, hi = db->mem.n;
        while (lo < hi) {
            size_t mid = lo + (hi - lo) / 2;
            if (ldb_ikey_cmp(db->mem.e[mid].ikey, db->mem.e[mid].ikey_len,
                             lookup, lookup_len) < 0)
                lo = mid + 1;
            else
                hi = mid;
        }
        if (lo < db->mem.n) {
            struct ldb_slice user;
            uint8_t type = 0;
            if (!ldb_ikey_user(db->mem.e[lo].ikey, db->mem.e[lo].ikey_len,
                               &user, NULL, &type)) {
                *err = ldb_strdup("ldb: malformed internal key in memtable");
                ok = false;
            } else if (ldb_ukey_cmp(user.p, user.n, ukey, klen) == 0) {
                found = true;
                if (type == LDB_TYPE_VALUE) {
                    size_t n = db->mem.e[lo].val_len;
                    *val = zcl_malloc(n ? n : 1, "ldb_get_value");
                    if (!*val) {
                        *err = ldb_strdup("ldb: out of memory");
                        ok = false;
                    } else {
                        if (n)
                            memcpy(*val, db->mem.e[lo].val, n);
                        *vlen = n;
                    }
                }
            }
        }
    }

    /* 2. level 0, newest file number first (these files overlap). */
    for (size_t i = 0; ok && !found && i < db->version.levels[0].n; i++) {
        struct ldb_file_meta *f = &db->version.levels[0].files[i];
        if (!file_may_contain(f, ukey, klen))
            continue;
        ok = table_point_get(f->table, lookup, lookup_len, ukey, klen, &found,
                             val, vlen, err);
    }

    /* 3. levels 1..6: disjoint and sorted, so one binary search each. */
    for (int lv = 1; ok && !found && lv < LDB_MAX_LEVEL; lv++) {
        struct ldb_level *l = &db->version.levels[lv];
        if (l->n == 0)
            continue;
        size_t lo = 0, hi = l->n;
        while (lo < hi) {
            size_t mid = lo + (hi - lo) / 2;
            if (ldb_ukey_cmp(l->files[mid].largest, l->files[mid].largest_len - 8,
                             ukey, klen) < 0)
                lo = mid + 1;
            else
                hi = mid;
        }
        if (lo >= l->n || !file_may_contain(&l->files[lo], ukey, klen))
            continue;
        ok = table_point_get(l->files[lo].table, lookup, lookup_len, ukey, klen,
                             &found, val, vlen, err);
    }

    free(heap);
    if (!ok) {
        free(*val);
        *val = NULL;
        *vlen = 0;
    }
    return ok;
}

/* ── user-facing iterator (sequence + tombstone resolution) ─────────── */

struct ldbr_iterator {
    struct ldb_iter inner;
    bool inner_open;
    uint8_t *saved;
    size_t saved_len;
    size_t saved_cap;
    uint8_t *seek_buf;
    size_t seek_cap;
    struct ldb_slice user_key;
    struct ldb_slice value;
    bool valid;
    char *err;
};

static bool save_key(struct ldbr_iterator *it, const uint8_t *p, size_t n)
{
    if (n + 1 > it->saved_cap) {
        size_t cap = it->saved_cap ? it->saved_cap : 64;
        while (cap < n + 1)
            cap *= 2;
        uint8_t *ns = zcl_realloc(it->saved, cap, "ldb_iter_saved_key");
        if (!ns)
            return false;
        it->saved = ns;
        it->saved_cap = cap;
    }
    if (n)
        memcpy(it->saved, p, n);
    it->saved_len = n;
    return true;
}

/* leveldb's DBIter::FindNextUserEntry, forward direction only. */
static void find_next_user_entry(struct ldbr_iterator *it, bool skipping)
{
    it->valid = false;
    while (!it->err && it->inner.vt->valid(it->inner.self)) {
        struct ldb_slice k, user;
        uint8_t type = 0;
        it->inner.vt->key(it->inner.self, &k);
        if (!ldb_ikey_user(k.p, k.n, &user, NULL, &type)) {
            it->err = ldb_strdup("ldb: malformed internal key during iteration");
            return;
        }
        if (type == LDB_TYPE_DELETION) {
            if (!save_key(it, user.p, user.n)) {
                it->err = ldb_strdup("ldb: out of memory");
                return;
            }
            skipping = true;
        } else if (!skipping ||
                   ldb_ukey_cmp(user.p, user.n, it->saved, it->saved_len) > 0) {
            it->user_key = user;
            it->inner.vt->value(it->inner.self, &it->value);
            it->valid = true;
            return;
        }
        it->inner.vt->next(it->inner.self);
        const char *e = it->inner.vt->error(it->inner.self);
        if (e && !it->err)
            it->err = ldb_strdup(e);
    }
    const char *e = it->inner.vt->error(it->inner.self);
    if (e && !it->err)
        it->err = ldb_strdup(e);
}

struct ldbr_iterator *ldbr_db_iter_internal(struct ldbr_db *db)
{
    struct ldbr_iterator *it = zcl_malloc(sizeof(*it), "ldbr_iterator");
    if (!it)
        return NULL;
    memset(it, 0, sizeof(*it));
    if (!merged_view_open(db, &it->inner)) {
        it->err = ldb_strdup("ldb: out of memory opening the merged view");
        return it;
    }
    it->inner_open = true;
    return it;
}

void ldbr_iter_destroy(struct ldbr_iterator *it)
{
    if (!it)
        return;
    if (it->inner_open)
        ldb_iter_destroy(&it->inner);
    free(it->saved);
    free(it->seek_buf);
    free(it->err);
    free(it);
}

unsigned char ldbr_iter_valid(const struct ldbr_iterator *it)
{
    return (it && it->valid && !it->err) ? 1 : 0;
}

void ldbr_iter_seek_to_first(struct ldbr_iterator *it)
{
    if (!it || !it->inner_open || it->err)
        return;
    it->inner.vt->seek_first(it->inner.self);
    find_next_user_entry(it, false);
}

void ldbr_iter_seek(struct ldbr_iterator *it, const char *k, size_t klen)
{
    if (!it || !it->inner_open || it->err)
        return;
    if (klen + 8 > it->seek_cap) {
        size_t cap = it->seek_cap ? it->seek_cap : 64;
        while (cap < klen + 8)
            cap *= 2;
        uint8_t *nb = zcl_realloc(it->seek_buf, cap, "ldb_iter_seek_buf");
        if (!nb) {
            it->err = ldb_strdup("ldb: out of memory");
            return;
        }
        it->seek_buf = nb;
        it->seek_cap = cap;
    }
    size_t len = 0;
    if (!ldb_ikey_build(it->seek_buf, it->seek_cap, (const uint8_t *)k, klen,
                        LDB_MAX_SEQUENCE, LDB_TYPE_VALUE, &len)) {
        it->err = ldb_strdup("ldb: could not build a seek key");
        return;
    }
    it->inner.vt->seek(it->inner.self, it->seek_buf, len);
    find_next_user_entry(it, false);
}

void ldbr_iter_next(struct ldbr_iterator *it)
{
    if (!it || !it->inner_open || it->err || !it->valid)
        return;
    if (!save_key(it, it->user_key.p, it->user_key.n)) {
        it->err = ldb_strdup("ldb: out of memory");
        return;
    }
    it->inner.vt->next(it->inner.self);
    find_next_user_entry(it, true);
}

const char *ldbr_iter_key(const struct ldbr_iterator *it, size_t *klen)
{
    if (!it || !it->valid) {
        *klen = 0;
        return NULL;
    }
    *klen = it->user_key.n;
    return (const char *)it->user_key.p;
}

const char *ldbr_iter_value(const struct ldbr_iterator *it, size_t *vlen)
{
    if (!it || !it->valid) {
        *vlen = 0;
        return NULL;
    }
    *vlen = it->value.n;
    return (const char *)it->value.p;
}

void ldbr_iter_get_error(const struct ldbr_iterator *it, char **errptr)
{
    if (!errptr)
        return;
    *errptr = (it && it->err) ? ldb_strdup(it->err) : NULL;
}
