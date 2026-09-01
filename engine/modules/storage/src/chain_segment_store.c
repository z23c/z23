/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * chain_segment_store — the resident reader over a directory of sealed segments
 * (see storage/chain_segment.h for the on-disk format and the store API). This
 * is the fold's substrate below the sealed frontier: it locates the segment
 * covering a height from the seg-<first>-<count>.dat file name, keeps a small
 * LRU of mmap'd, digest-verified segment handles resident, and hands back raw
 * block bytes byte-identical to the blk*.dat body.
 *
 * Ownership + threading: one mutex guards the whole store (the segment table
 * plus the open-handle LRU). Reads are a bounded search + an mmap memcpy + one
 * per-block SHA3, so serializing them under a single lock is cheap relative to
 * the fold and keeps the handle LRU race-free without per-handle refcounts.
 */

#include "storage/chain_segment.h"

#include "platform/directory_compat.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"

#include <errno.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Small resident set of open segment handles. A sequential fold touches one
 * segment at a time and steps forward, so a handful is plenty; a larger reorg
 * or out-of-order access just re-opens (re-verifies) on eviction. */
#define CSS_HANDLE_CACHE 4

static void css_set_err(char *err, size_t errlen, const char *fmt, ...)
{
    if (!err || errlen == 0) return;
    va_list ap; va_start(ap, fmt);
    vsnprintf(err, errlen, fmt, ap);
    va_end(ap);
}

struct css_table_entry {
    uint32_t first_height;
    uint32_t count;   /* blocks in the segment (from the file name) */
};

struct css_handle {
    bool                  used;
    uint32_t              seg_index;     /* index into table[] */
    struct chain_segment *seg;           /* mmap'd, verified on open */
    uint64_t              stamp;         /* LRU recency */
};

struct chain_segment_store {
    pthread_mutex_t        lock;
    char                   dir[3072];
    struct css_table_entry *table;       /* ascending by first_height */
    uint32_t               n;
    uint32_t               sealed_max;    /* highest covered height */
    struct css_handle      cache[CSS_HANDLE_CACHE];
    uint64_t               clock;
};

/* Match "seg-<first>-<count>.dat"; fills fh, cnt on match. Kept local (the
 * writer's parse_seg_name is static in chain_segment.c). */
static bool css_parse_name(const char *name, uint32_t *fh, uint32_t *cnt)
{
    unsigned f = 0, c = 0;
    char tail = 0;
    if (sscanf(name, "seg-%u-%u.da%c", &f, &c, &tail) == 3 && tail == 't' &&
        name[strlen(name) - 1] == 't') {
        *fh = f; *cnt = c;
        return true;
    }
    return false;
}

static int css_entry_cmp(const void *a, const void *b)
{
    uint32_t x = ((const struct css_table_entry *)a)->first_height;
    uint32_t y = ((const struct css_table_entry *)b)->first_height;
    return (x > y) - (x < y);
}

/* Scan `dir` for seg-*.dat files and build the sorted coverage table. A missing
 * directory yields an empty table (not an error). */
static enum cseg_status css_scan(struct chain_segment_store *s,
                                 char *err, size_t errlen)
{
    enum platform_directory_probe_result probe =
        platform_directory_probe_real(s->dir);
    if (probe == PLATFORM_DIRECTORY_PROBE_MISSING)
        return CSEG_OK; /* no store yet */
    if (probe != PLATFORM_DIRECTORY_PROBE_OK) {
        css_set_err(err, errlen, "segment directory is not a real directory: %s",
                    s->dir);
        return CSEG_ERR_IO;
    }

    struct platform_directory_list files = {0};
    if (!platform_directory_list_regular_sorted(s->dir, &files)) {
        css_set_err(err, errlen, "cannot enumerate segment directory: %s",
                    s->dir);
        return CSEG_ERR_IO;
    }
    size_t cap = 16, n = 0;
    struct css_table_entry *tab =
        zcl_malloc(cap * sizeof(*tab), "css/table");
    if (!tab) {
        platform_directory_list_free(&files);
        css_set_err(err, errlen, "alloc");
        return CSEG_ERR_IO;
    }

    for (size_t file_i = 0; file_i < files.count; file_i++) {
        uint32_t fh, cnt;
        if (!css_parse_name(files.entries[file_i].name, &fh, &cnt)) continue;
        if (cnt == 0) continue;
        if (n == cap) {
            cap *= 2;
            struct css_table_entry *grown =
                zcl_realloc(tab, cap * sizeof(*tab), "css/table");
            if (!grown) {
                free(tab);
                platform_directory_list_free(&files);
                css_set_err(err, errlen, "grow");
                return CSEG_ERR_IO;
            }
            tab = grown;
        }
        tab[n].first_height = fh;
        tab[n].count = cnt;
        n++;
    }
    platform_directory_list_free(&files);

    qsort(tab, n, sizeof(*tab), css_entry_cmp);
    s->table = tab;
    s->n = (uint32_t)n;
    s->sealed_max = 0;
    for (uint32_t i = 0; i < s->n; i++) {
        uint32_t top = s->table[i].first_height + s->table[i].count - 1;
        if (top > s->sealed_max) s->sealed_max = top;
    }
    return CSEG_OK;
}

enum cseg_status chain_segment_store_open(const char *dir,
                                          struct chain_segment_store **out,
                                          char *err, size_t errlen)
{
    if (!dir || !out) { css_set_err(err, errlen, "null dir/out"); return CSEG_ERR_ARG; }
    *out = NULL;

    struct chain_segment_store *s = zcl_malloc(sizeof(*s), "css/open");
    if (!s) { css_set_err(err, errlen, "alloc store"); return CSEG_ERR_IO; }
    memset(s, 0, sizeof(*s));
    pthread_mutex_init(&s->lock, NULL);
    snprintf(s->dir, sizeof(s->dir), "%s", dir);

    enum cseg_status st = css_scan(s, err, errlen);
    if (st != CSEG_OK) {
        pthread_mutex_destroy(&s->lock);
        free(s);
        return st;
    }
    *out = s;
    return CSEG_OK;
}

void chain_segment_store_close(struct chain_segment_store *s)
{
    if (!s) return;
    for (int i = 0; i < CSS_HANDLE_CACHE; i++)
        if (s->cache[i].used && s->cache[i].seg)
            chain_segment_close(s->cache[i].seg);
    free(s->table);
    pthread_mutex_destroy(&s->lock);
    free(s);
}

/* Table lookup: index of the segment covering `height`, or -1. MUST hold lock. */
static int64_t css_find_locked(const struct chain_segment_store *s, uint32_t height)
{
    /* table[] is sorted and (for a well-formed store) non-overlapping. Linear
     * search is fine — the table is a few hundred entries at most and the fold
     * hits the same segment repeatedly (served by the handle LRU). */
    for (uint32_t i = 0; i < s->n; i++) {
        if (height >= s->table[i].first_height &&
            height <  s->table[i].first_height + s->table[i].count)
            return (int64_t)i;
    }
    return -1;
}

/* Ensure segment `idx` is open (mmap'd + verified) and return its handle.
 * MUST hold lock. On open failure the reason is in `err` and NULL is returned. */
static struct chain_segment *css_open_locked(struct chain_segment_store *s,
                                             uint32_t idx,
                                             char *err, size_t errlen)
{
    for (int i = 0; i < CSS_HANDLE_CACHE; i++) {
        if (s->cache[i].used && s->cache[i].seg_index == idx) {
            s->cache[i].stamp = ++s->clock;
            return s->cache[i].seg;
        }
    }
    /* Miss: pick an empty slot else the LRU. */
    int victim = 0;
    uint64_t lru = UINT64_MAX;
    for (int i = 0; i < CSS_HANDLE_CACHE; i++) {
        if (!s->cache[i].used) { victim = i; break; }
        if (s->cache[i].stamp < lru) { lru = s->cache[i].stamp; victim = i; }
    }
    char path[3200];
    snprintf(path, sizeof(path), "%s/seg-%u-%u.dat", s->dir,
             s->table[idx].first_height, s->table[idx].count);
    struct chain_segment *seg = NULL;
    enum cseg_status st = chain_segment_open(path, &seg, err, errlen);
    if (st != CSEG_OK)
        return NULL;

    if (s->cache[victim].used && s->cache[victim].seg)
        chain_segment_close(s->cache[victim].seg);
    s->cache[victim].used = true;
    s->cache[victim].seg_index = idx;
    s->cache[victim].seg = seg;
    s->cache[victim].stamp = ++s->clock;
    return seg;
}

bool chain_segment_store_covers(const struct chain_segment_store *s, uint32_t height)
{
    if (!s) return false;
    /* Cast away const only for the lock; the table is not mutated here. */
    pthread_mutex_lock((pthread_mutex_t *)&s->lock);
    bool covered = css_find_locked(s, height) >= 0;
    pthread_mutex_unlock((pthread_mutex_t *)&s->lock);
    return covered;
}

uint32_t chain_segment_store_sealed_max(const struct chain_segment_store *s)
{
    return s ? s->sealed_max : 0;
}
bool chain_segment_store_have(const struct chain_segment_store *s)
{
    return s && s->n > 0;
}
uint32_t chain_segment_store_segment_count(const struct chain_segment_store *s)
{
    return s ? s->n : 0;
}
bool chain_segment_store_segment_range(const struct chain_segment_store *s,
                                       uint32_t i, uint32_t *first,
                                       uint32_t *count)
{
    if (!s || i >= s->n) return false;
    if (first) *first = s->table[i].first_height;
    if (count) *count = s->table[i].count;
    return true;
}

enum cseg_status chain_segment_store_get_block(struct chain_segment_store *s,
                                               uint32_t height,
                                               uint8_t **bytes, size_t *len,
                                               char *err, size_t errlen)
{
    if (!s || !bytes || !len) { css_set_err(err, errlen, "null arg"); return CSEG_ERR_ARG; }
    *bytes = NULL; *len = 0;

    pthread_mutex_lock(&s->lock);
    int64_t idx = css_find_locked(s, height);
    if (idx < 0) {
        pthread_mutex_unlock(&s->lock);
        css_set_err(err, errlen, "height %u not covered by any segment", height);
        return CSEG_ERR_NOT_FOUND;
    }
    struct chain_segment *seg = css_open_locked(s, (uint32_t)idx, err, errlen);
    if (!seg) {
        pthread_mutex_unlock(&s->lock);
        return CSEG_ERR_IO;
    }
    enum cseg_status st =
        chain_segment_get_block(seg, height, bytes, len, err, errlen);
    pthread_mutex_unlock(&s->lock);
    return st;
}

enum cseg_status chain_segment_store_verify_index(struct chain_segment_store *s,
                                                  uint32_t i,
                                                  char *err, size_t errlen)
{
    if (!s) { css_set_err(err, errlen, "null store"); return CSEG_ERR_ARG; }
    pthread_mutex_lock(&s->lock);
    if (i >= s->n) {
        pthread_mutex_unlock(&s->lock);
        css_set_err(err, errlen, "segment index %u out of range (%u)", i, s->n);
        return CSEG_ERR_ARG;
    }
    /* Drop any cached handle for this index so we re-open + re-hash from disk
     * (the point of verify is to re-read, not trust a resident mmap). */
    for (int h = 0; h < CSS_HANDLE_CACHE; h++) {
        if (s->cache[h].used && s->cache[h].seg_index == i) {
            if (s->cache[h].seg) chain_segment_close(s->cache[h].seg);
            s->cache[h].used = false;
            s->cache[h].seg = NULL;
        }
    }
    char path[3200];
    snprintf(path, sizeof(path), "%s/seg-%u-%u.dat", s->dir,
             s->table[i].first_height, s->table[i].count);
    pthread_mutex_unlock(&s->lock);

    struct chain_segment *seg = NULL;
    enum cseg_status st = chain_segment_open(path, &seg, err, errlen);
    if (st == CSEG_OK && seg)
        chain_segment_close(seg);
    return st;
}
