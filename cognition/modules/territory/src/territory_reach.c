/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * territory_reach — the forward closure of the registered test entry points
 * over the code index's call graph, and the on-disk memo of that closure.
 *
 * ── The question ──
 * `code tests` answers ROUTING: change this file, run that group. It never
 * claims the group executes the file. This answers EXECUTION: starting at
 * every registered group entry symbol ("test_<group>" / "spec_<group>"), walk
 * refs.enclosing -> refs.callee_name to fixpoint. A symbol in the resulting
 * set is called, transitively, by something a registered group runs.
 *
 * ── Why it is memoized on disk ──
 * The closure is a property of the whole tree (about 30k symbols over about
 * 470k call-graph edges here), and the walk costs a few hundred milliseconds.
 * Every `code territory` call would otherwise pay it, and a command nobody
 * waits for is a command nobody runs. So the result is written beside the
 * code index it derives from, keyed on that index's SEALED source-root digest
 * — the same immutable generation key `code provenance facts` memoizes
 * against. Any edit to the tree changes that digest and the memo is rebuilt;
 * a stale memo cannot be served. The payload also carries its own SHA3-256,
 * so a torn or truncated file is rejected rather than trusted.
 *
 * The memo is a cache, never an authority: if it cannot be read OR written
 * (a read-only checkout, a full disk) the walk still runs and the answer is
 * identical, only slower.
 */

#include "territory/territory.h"

#include "base/log_macros.h"
#include "base/safe_alloc.h"
#include "base/serialize_le.h"
#include "codeindex/codeindex.h"
#include "platform/clock.h"
#include "sha3/sha3.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* The widest single-function fan-out in this tree is about 6.4k callees
 * (main). A cap below that would silently drop edges and understate reach, so
 * the buffer is sized above the observed maximum AND a full buffer is still
 * reported as truncation — the bound is not trusted to stay generous. */
enum {
    TR_FANOUT_CAP  = 8192,
    TR_MAX_SYMBOLS = 400000,
    TR_MAX_STEPS   = 400000,
};

/* ── a bounded string set with a contiguous name arena ──────────────────
 * Names live end to end in one blob so the finished set can be written to
 * disk (and searched) without a second pass over pointers. */
struct tr_strset {
    uint32_t *slot;      /* blob offset + 1; 0 means empty */
    size_t    slots;     /* power of two */
    size_t    len;
    char     *blob;
    size_t    blob_len;
    size_t    blob_cap;
};

struct territory_reach_set {
    char     *blob;      /* NUL-separated names */
    size_t    blob_len;
    uint32_t *offsets;   /* sorted by strcmp over blob */
    size_t    count;
};

static uint64_t tr_hash(const char *s)
{
    uint64_t h = 1469598103934665603ull;  /* FNV-1a */
    for (; *s; s++) {
        h ^= (unsigned char)*s;
        h *= 1099511628211ull;
    }
    return h;
}

static void tr_strset_free(struct tr_strset *s)
{
    if (!s) return;
    free(s->slot);
    free(s->blob);
    memset(s, 0, sizeof(*s));
}

static bool tr_strset_init(struct tr_strset *s, size_t slots)
{
    memset(s, 0, sizeof(*s));
    s->slots = slots;
    s->slot = zcl_calloc(slots, sizeof(*s->slot), "tr_strset_slots");
    if (!s->slot) LOG_FAIL("territory", "reach set slot table (%zu)", slots);
    s->blob_cap = 1 << 20;
    s->blob = zcl_malloc(s->blob_cap, "tr_strset_blob");
    if (!s->blob) {
        free(s->slot);
        memset(s, 0, sizeof(*s));
        LOG_FAIL("territory", "reach set name arena");
    }
    /* Offset 0 is reserved so a slot can use 0 as "empty". */
    s->blob[0] = '\0';
    s->blob_len = 1;
    return true;
}

static bool tr_strset_grow(struct tr_strset *s)
{
    size_t slots = s->slots * 2;
    uint32_t *fresh = zcl_calloc(slots, sizeof(*fresh), "tr_strset_regrow");
    if (!fresh) LOG_FAIL("territory", "reach set regrow to %zu", slots);
    for (size_t i = 0; i < s->slots; i++) {
        if (!s->slot[i]) continue;
        uint32_t off = s->slot[i] - 1;
        size_t j = (size_t)tr_hash(s->blob + off) & (slots - 1);
        while (fresh[j]) j = (j + 1) & (slots - 1);
        fresh[j] = s->slot[i];
    }
    free(s->slot);
    s->slot = fresh;
    s->slots = slots;
    return true;
}

/* Insert `name`; *added tells whether it was new. */
static bool tr_strset_add(struct tr_strset *s, const char *name, bool *added)
{
    *added = false;
    if (!name || !name[0]) return true;
    if (s->len * 10 >= s->slots * 7 && !tr_strset_grow(s))
        return false;
    size_t i = (size_t)tr_hash(name) & (s->slots - 1);
    while (s->slot[i]) {
        if (strcmp(s->blob + s->slot[i] - 1, name) == 0) return true;
        i = (i + 1) & (s->slots - 1);
    }
    size_t need = strlen(name) + 1;
    if (s->blob_len + need > s->blob_cap) {
        size_t cap = s->blob_cap;
        while (cap < s->blob_len + need) cap *= 2;
        char *fresh = zcl_realloc(s->blob, cap, "tr_strset_blobgrow");
        if (!fresh) LOG_FAIL("territory", "reach name arena to %zu", cap);
        s->blob = fresh;
        s->blob_cap = cap;
    }
    if (s->blob_len + need > UINT32_MAX)
        LOG_FAIL("territory", "reach name arena exceeds 4 GiB");
    memcpy(s->blob + s->blob_len, name, need);
    s->slot[i] = (uint32_t)s->blob_len + 1;
    s->blob_len += need;
    s->len++;
    *added = true;
    return true;
}

/* ── sorted view (what gets stored and searched) ─────────────────────── */

/* Sorting POINTERS into the finished arena (rather than offsets plus a
 * comparator global) keeps the sort context in the elements themselves; the
 * offsets are recovered afterwards by subtraction. */
static int tr_ptr_cmp(const void *a, const void *b)
{
    return strcmp(*(const char *const *)a, *(const char *const *)b);
}

bool territory_reach_contains(const struct territory_reach_set *rs,
                              const char *symbol)
{
    if (!rs || !symbol || !symbol[0] || rs->count == 0) return false;
    size_t lo = 0, hi = rs->count;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        int c = strcmp(rs->blob + rs->offsets[mid], symbol);
        if (c == 0) return true;
        if (c < 0) lo = mid + 1;
        else hi = mid;
    }
    return false;
}

size_t territory_reach_count(const struct territory_reach_set *rs)
{
    return rs ? rs->count : 0;
}

void territory_reach_free(struct territory_reach_set *rs)
{
    if (!rs) return;
    free(rs->blob);
    free(rs->offsets);
    free(rs);
}

/* ── the on-disk memo ────────────────────────────────────────────────── */

#define TR_MAGIC   "ZTREACH\0"
#define TR_VERSION 1u
enum {
    TR_HDR_MAGIC   = 0,
    TR_HDR_VERSION = 8,
    TR_HDR_SEEDS   = 12,
    TR_HDR_COUNT   = 16,
    TR_HDR_BLOBLEN = 24,
    TR_HDR_ROOT    = 32,
    TR_HDR_DIGEST  = 64,
    TR_HDR_SIZE    = 96,
};

static int tr_cache_path(char *buf, size_t cap, const char *root)
{
    return snprintf(buf, cap, "%s/.codeindex/territory_reach.v1", root);
}

/* Load and fully verify the memo, or return NULL. A rejected memo is never an
 * error the caller has to handle: it just means the walk runs. */
static struct territory_reach_set *tr_cache_load(const char *root,
                                                 const uint8_t gen[32],
                                                 uint32_t seeds)
{
    char path[TERRITORY_PATH_MAX + 64];
    int n = tr_cache_path(path, sizeof(path), root);
    if (n < 0 || (size_t)n >= sizeof(path)) return NULL;
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;

    uint8_t hdr[TR_HDR_SIZE];
    if (fread(hdr, 1, sizeof(hdr), f) != sizeof(hdr)) { fclose(f); return NULL; }
    if (memcmp(hdr + TR_HDR_MAGIC, TR_MAGIC, 8) != 0 ||
        zcl_read_u32_le(hdr + TR_HDR_VERSION) != TR_VERSION ||
        zcl_read_u32_le(hdr + TR_HDR_SEEDS) != seeds ||
        memcmp(hdr + TR_HDR_ROOT, gen, 32) != 0) {
        fclose(f);
        return NULL;
    }
    uint64_t count = zcl_read_u64_le(hdr + TR_HDR_COUNT);
    uint64_t blob_len = zcl_read_u64_le(hdr + TR_HDR_BLOBLEN);
    if (count == 0 || count > TR_MAX_SYMBOLS || blob_len < 1 ||
        blob_len > (uint64_t)UINT32_MAX) {
        fclose(f);
        return NULL;
    }

    struct territory_reach_set *rs =
        zcl_calloc(1, sizeof(*rs), "tr_cache_set");
    uint32_t *offs = zcl_malloc(sizeof(*offs) * (size_t)count, "tr_cache_offs");
    char *blob = zcl_malloc((size_t)blob_len, "tr_cache_blob");
    if (!rs || !offs || !blob) {
        free(rs); free(offs); free(blob); fclose(f);
        LOG_NULL("territory", "reach memo buffers (%llu symbols)",
                 (unsigned long long)count);
    }
    bool ok = fread(offs, sizeof(*offs), (size_t)count, f) == (size_t)count &&
              fread(blob, 1, (size_t)blob_len, f) == (size_t)blob_len;
    fclose(f);
    if (!ok) { free(rs); free(offs); free(blob); return NULL; }

    /* Verify-on-read: the payload's own digest, then structural sanity. A
     * cache that survives both is byte-identical to what the walk produced. */
    uint8_t want[32], got[32];
    memcpy(want, hdr + TR_HDR_DIGEST, 32);
    struct sha3_256_ctx c;
    sha3_256_init(&c);
    sha3_256_write(&c, (const unsigned char *)offs,
                   sizeof(*offs) * (size_t)count);
    sha3_256_write(&c, (const unsigned char *)blob, (size_t)blob_len);
    sha3_256_finalize(&c, got);
    if (memcmp(want, got, 32) != 0) {
        free(rs); free(offs); free(blob);
        return NULL;
    }
    if (blob[blob_len - 1] != '\0') {
        free(rs); free(offs); free(blob);
        return NULL;
    }
    for (uint64_t i = 0; i < count; i++) {
        if (offs[i] >= blob_len) {
            free(rs); free(offs); free(blob);
            return NULL;
        }
    }
    /* Endianness note: offsets are stored in host order inside a digest-sealed
     * payload keyed on this checkout's index. A cache file is never shared
     * between hosts; a foreign-endian file simply fails the offset check or
     * the digest and is rebuilt. */
    rs->blob = blob;
    rs->blob_len = (size_t)blob_len;
    rs->offsets = offs;
    rs->count = (size_t)count;
    return rs;
}

static void tr_cache_store(const char *root, const uint8_t gen[32],
                           uint32_t seeds, const struct territory_reach_set *rs,
                           bool *wrote)
{
    *wrote = false;
    char path[TERRITORY_PATH_MAX + 64];
    char tmp[TERRITORY_PATH_MAX + 96];
    int n = tr_cache_path(path, sizeof(path), root);
    if (n < 0 || (size_t)n >= sizeof(path)) return;
    n = snprintf(tmp, sizeof(tmp), "%s.tmp.%d", path, (int)getpid());
    if (n < 0 || (size_t)n >= sizeof(tmp)) return;

    uint8_t hdr[TR_HDR_SIZE];
    memset(hdr, 0, sizeof(hdr));
    memcpy(hdr + TR_HDR_MAGIC, TR_MAGIC, 8);
    zcl_write_u32_le(hdr + TR_HDR_VERSION, TR_VERSION);
    zcl_write_u32_le(hdr + TR_HDR_SEEDS, seeds);
    zcl_write_u64_le(hdr + TR_HDR_COUNT, (uint64_t)rs->count);
    zcl_write_u64_le(hdr + TR_HDR_BLOBLEN, (uint64_t)rs->blob_len);
    memcpy(hdr + TR_HDR_ROOT, gen, 32);

    struct sha3_256_ctx c;
    sha3_256_init(&c);
    sha3_256_write(&c, (const unsigned char *)rs->offsets,
                   sizeof(*rs->offsets) * rs->count);
    sha3_256_write(&c, (const unsigned char *)rs->blob, rs->blob_len);
    sha3_256_finalize(&c, hdr + TR_HDR_DIGEST);

    FILE *f = fopen(tmp, "wb");
    if (!f) return;  /* a read-only checkout is a normal state, not a failure */
    bool ok = fwrite(hdr, 1, sizeof(hdr), f) == sizeof(hdr) &&
              fwrite(rs->offsets, sizeof(*rs->offsets), rs->count, f) ==
                  rs->count &&
              fwrite(rs->blob, 1, rs->blob_len, f) == rs->blob_len;
    if (fclose(f) != 0) ok = false;
    if (!ok || rename(tmp, path) != 0) {
        (void)unlink(tmp);
        return;
    }
    *wrote = true;
}

/* ── the walk ────────────────────────────────────────────────────────── */

static uint64_t tr_now_us(void)
{
    int64_t ns = clock_now_monotonic_ns();
    return ns > 0 ? (uint64_t)ns / 1000ull : 0;
}

struct tr_worklist {
    uint32_t *off;
    size_t len, cap;
};

static bool tr_worklist_push(struct tr_worklist *w, uint32_t off)
{
    if (w->len == w->cap) {
        size_t cap = w->cap ? w->cap * 2 : 4096;
        uint32_t *fresh = zcl_realloc(w->off, cap * sizeof(*fresh),
                                      "tr_worklist");
        if (!fresh) LOG_FAIL("territory", "reach worklist to %zu", cap);
        w->off = fresh;
        w->cap = cap;
    }
    w->off[w->len++] = off;
    return true;
}

/* Freeze the working set into the sorted, searchable form the rest of the
 * module (and the memo) uses. Consumes `set`. */
static struct territory_reach_set *tr_freeze(struct tr_strset *set)
{
    size_t n = set->len ? set->len : 1;
    struct territory_reach_set *rs = zcl_calloc(1, sizeof(*rs), "tr_set");
    uint32_t *offs = zcl_malloc(sizeof(*offs) * n, "tr_set_offs");
    const char **ptrs = zcl_malloc(sizeof(*ptrs) * n, "tr_set_ptrs");
    if (!rs || !offs || !ptrs) {
        free(rs); free(offs); free(ptrs);
        LOG_NULL("territory", "freeze %zu reached symbols", set->len);
    }
    size_t k = 0;
    for (size_t i = 0; i < set->slots; i++)
        if (set->slot[i]) ptrs[k++] = set->blob + set->slot[i] - 1;
    qsort(ptrs, k, sizeof(*ptrs), tr_ptr_cmp);
    for (size_t i = 0; i < k; i++)
        offs[i] = (uint32_t)(ptrs[i] - set->blob);
    free(ptrs);
    rs->blob = set->blob;
    rs->blob_len = set->blob_len;
    set->blob = NULL;          /* ownership moved */
    rs->offsets = offs;
    rs->count = k;
    return rs;
}

struct territory_reach_set *territory_reach_open(
    struct codeindex *ci, const char *root,
    const struct territory_proof_source *src,
    struct territory_reach_stats *stats)
{
    struct territory_reach_stats local = {0};
    struct territory_reach_stats *st = stats ? stats : &local;
    memset(st, 0, sizeof(*st));

    if (!ci || !src || !src->at)
        LOG_NULL("territory", "reach walk needs an index and a proof source");
    st->seeds = (uint64_t)src->count;

    uint8_t gen[32];
    bool have_gen = codeindex_source_root_sha3(ci, gen);
    if (root && root[0] && have_gen) {
        struct territory_reach_set *cached =
            tr_cache_load(root, gen, (uint32_t)src->count);
        if (cached) {
            st->from_cache = true;
            st->symbols = (uint64_t)cached->count;
            return cached;
        }
    }

    uint64_t t0 = tr_now_us();
    struct tr_strset set;
    struct tr_worklist cur = {0}, next = {0};
    struct territory_reach_set *rs = NULL;
    struct ci_ref *refbuf = NULL;
    if (!tr_strset_init(&set, 1u << 16))
        LOG_NULL("territory", "reach set init");

    refbuf = zcl_malloc(sizeof(*refbuf) * TR_FANOUT_CAP, "tr_refbuf");
    if (!refbuf) {
        tr_strset_free(&set);
        LOG_NULL("territory", "reach callee buffer");
    }

    /* Seed with every registered entry point. A seed the index has never
     * heard of simply contributes nothing — the walk is over the graph, and
     * an absent root has no edges. */
    for (size_t i = 0; i < src->count; i++) {
        const char *name = src->at(i, src->user);
        if (!name || !name[0]) continue;
        bool added = false;
        if (!tr_strset_add(&set, name, &added)) goto fail;
        if (!added) continue;
        /* The offset just written is the tail of the arena. */
        size_t off = set.blob_len - (strlen(name) + 1);
        if (!tr_worklist_push(&cur, (uint32_t)off)) goto fail;
    }

    while (cur.len > 0) {
        for (size_t i = 0; i < cur.len; i++) {
            if (st->steps >= TR_MAX_STEPS || set.len >= TR_MAX_SYMBOLS) {
                st->truncated = true;
                break;
            }
            int nc = codeindex_callees(ci, set.blob + cur.off[i], refbuf,
                                       TR_FANOUT_CAP);
            st->steps++;
            if (nc < 0) goto fail;
            if (nc == TR_FANOUT_CAP) st->truncated = true;
            for (int j = 0; j < nc; j++) {
                const char *callee = refbuf[j].callee;
                if (!callee[0]) continue;
                bool added = false;
                if (!tr_strset_add(&set, callee, &added)) goto fail;
                if (!added) continue;
                size_t off = set.blob_len - (strlen(callee) + 1);
                if (!tr_worklist_push(&next, (uint32_t)off)) goto fail;
            }
        }
        if (st->truncated) break;
        free(cur.off);
        cur = next;
        memset(&next, 0, sizeof(next));
    }

    free(refbuf);
    refbuf = NULL;
    free(cur.off);
    free(next.off);
    memset(&cur, 0, sizeof(cur));
    memset(&next, 0, sizeof(next));

    rs = tr_freeze(&set);
    tr_strset_free(&set);
    if (!rs) LOG_NULL("territory", "freeze reached set");
    st->symbols = (uint64_t)rs->count;
    st->build_us = tr_now_us() - t0;

    /* Never memoize a truncated walk: a bounded answer must not be replayed
     * as though it were the closure. An EMPTY closure is not memoized either
     * — tr_cache_load rejects a zero-symbol payload as malformed, so writing
     * one would only be rewritten on every call. */
    if (root && root[0] && have_gen && !st->truncated && rs->count > 0)
        tr_cache_store(root, gen, (uint32_t)src->count, rs, &st->cache_written);
    return rs;

fail:
    free(refbuf);
    free(cur.off);
    free(next.off);
    tr_strset_free(&set);
    LOG_NULL("territory", "reach walk aborted after %llu steps",
             (unsigned long long)st->steps);
}

const char *territory_reach_verdict_label(enum territory_reach_verdict v)
{
    switch (v) {
    case TERRITORY_REACHED:   return "reached";
    case TERRITORY_UNREACHED: return "unreached";
    case TERRITORY_UNKNOWN:   return "unknown";
    }
    return "unknown";
}

const char *territory_reach_reason_label(enum territory_reach_reason r)
{
    switch (r) {
    case TERRITORY_REASON_IN_CLOSURE:     return "in-test-closure";
    case TERRITORY_REASON_NO_REFS:        return "no-reference-in-tree";
    case TERRITORY_REASON_COLD_CALLERS:   return "callers-outside-closure";
    case TERRITORY_REASON_FILE_SCOPE_REF: return "file-scope-reference-only";
    case TERRITORY_REASON_WALK_TRUNCATED: return "walk-bounded";
    }
    return "unknown";
}
