/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * block_parse_cache — implementation. See storage/block_parse_cache.h.
 *
 * DESIGN: the cache retains a fully PARSED immutable `struct block` per
 * (height,hash), deserialized once, and pins it while borrowed consumers run.
 * A direct-mapped height ring gives one bounded O(1) probe. The requested hash
 * is checked before a resident entry is borrowed, so a same-height reorg can
 * only miss. Each handle pins the entry generation until release; eviction and
 * pressure clearing mark pinned entries pending and free them only after the
 * final borrower exits. No cache mutex is held while a consumer verifies or
 * persists anything.
 *
 * On a miss, a successfully read, parsed, and hash-checked body is moved into
 * the ring without a clone. If a colliding ring slot is pinned, the new body is
 * returned through a detached, handle-owned entry instead of disturbing the
 * borrower. The compatibility get API remains for unconverted consumers: it
 * acquires the immutable body, deep-clones it, and releases the handle.
 */
#include "storage/block_parse_cache.h"

#include "chain/chain.h"
#include "core/serialize.h"
#include "primitives/block.h"
#include "storage/chain_segment.h"
#include "storage/disk_block_io.h"
#include "util/log_macros.h"
#include "util/mem_pressure.h"
#include "util/safe_alloc.h"
#include "platform/time_compat.h"

#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BPC_CAPACITY BLOCK_PARSE_CACHE_CAPACITY
_Static_assert((BPC_CAPACITY & (BPC_CAPACITY - 1u)) == 0,
               "block parse cache capacity must be a power of two");

struct bpc_entry {
    bool          used;       /* slot occupied */
    int32_t       height;     /* key part 1 */
    uint8_t       hash[32];   /* key part 2 (block hash) */
    struct block  body;       /* owned PARSED block body (deep-owned) */
    uint64_t      generation; /* identity across slot replacement */
    uint64_t      bytes;      /* body's accounted cost, mirrors g_bpc_bytes */
    uint32_t      pins;       /* immutable borrowers currently active */
    bool          pending_evict;
    bool          detached;   /* heap fallback when ring slot is pinned */
};

static pthread_mutex_t g_bpc_mutex = PTHREAD_MUTEX_INITIALIZER;
static struct bpc_entry g_bpc[BPC_CAPACITY];
static _Atomic uint64_t g_bpc_generation;
static _Atomic uint64_t g_bpc_bytes; /* resident deep-size total, ring only */

/* ── mem_pressure sink (Rung 1 follow-on, docs/adr/0003-os-substrate-
 * verdict.md) ──────────────────────────────────────────────────────
 * A REAL shrink target: every entry is a read-through cache of already-
 * persisted disk data (re-derivable by the next block_parse_cache_get()
 * miss), so dropping it under memory pressure loses nothing but a few
 * upcoming cache hits — never consensus state. Registered once, lazily,
 * on the first cache use (pthread_once — this module has no explicit
 * init entry point). */
static void bpc_shrink_for_pressure(enum mem_pressure_level level, void *ctx)
{
    (void)level;
    (void)ctx;
    block_parse_cache_clear();
}

static struct mem_pressure_sink g_bpc_pressure_sink = {
    .name = "block_parse_cache",
    .shrink = bpc_shrink_for_pressure,
    .ctx = NULL,
};

/* ── Byte ceiling (see block_parse_cache.h) ────────────────────────
 * Read ONCE from ZCL_PARSE_CACHE_MAX_BYTES on the same first-use pthread_once
 * as the pressure sink. The INFO/WARN markers below let each cache generation
 * (i.e. between block_parse_cache_clear calls) log at most one ceiling line. */
static uint64_t g_bpc_ceiling_bytes = BLOCK_PARSE_CACHE_DEFAULT_MAX_BYTES;
static bool g_bpc_ceiling_evict_logged;
static bool g_bpc_ceiling_pinned_logged;

/* Invalid or overflowing unsigned decimal uses the safe default. */
static uint64_t bpc_parse_byte_ceiling(const char *v)
{
    if (!v || !*v) return BLOCK_PARSE_CACHE_DEFAULT_MAX_BYTES;
    for (const char *p = v; *p; ++p)
        if (*p < '0' || *p > '9') return BLOCK_PARSE_CACHE_DEFAULT_MAX_BYTES;
    char *end = NULL;
    errno = 0;
    unsigned long long parsed = strtoull(v, &end, 10);
    if (errno == ERANGE || end == v || *end != 0 || parsed == 0)
        return BLOCK_PARSE_CACHE_DEFAULT_MAX_BYTES;
    uint64_t n = (uint64_t)parsed;
    if (n < BLOCK_PARSE_CACHE_MIN_MAX_BYTES)
        n = BLOCK_PARSE_CACHE_MIN_MAX_BYTES;
    if (n > BLOCK_PARSE_CACHE_MAX_MAX_BYTES)
        n = BLOCK_PARSE_CACHE_MAX_MAX_BYTES;
    return n;
}

#ifdef ZCL_TESTING
uint64_t block_parse_cache_ceiling_for_test(const char *v)
{
    return bpc_parse_byte_ceiling(v);
}
#endif

static void bpc_read_byte_ceiling_env(void)
{
    g_bpc_ceiling_bytes = bpc_parse_byte_ceiling(getenv("ZCL_PARSE_CACHE_MAX_BYTES"));
}

static pthread_once_t g_bpc_first_use_once = PTHREAD_ONCE_INIT;

static void bpc_first_use_init(void)
{
    bpc_read_byte_ceiling_env();
    (void)mem_pressure_register_sink(&g_bpc_pressure_sink);
}

/* Approximate deep resident cost of a parsed body: the struct-block frame plus
 * every heap array it owns (one struct transaction per tx, and per tx its
 * vin/vout/shielded/joinsplit arrays). A wire-serialize length would be the
 * WRONG measure here: struct script embeds its buffer inline, so a parsed
 * output costs ~10 KiB resident regardless of its ~9 wire bytes — the sizeof
 * sum IS the residency. Slight over-count is safe: it only evicts earlier. */
static uint64_t bpc_body_bytes(const struct block *b)
{
    if (!b)
        return 0;
    uint64_t n = sizeof(*b);
    for (size_t i = 0; i < b->num_vtx; i++) {
        const struct transaction *tx = &b->vtx[i];
        n += sizeof(*tx) +
             tx->num_vin * sizeof(struct tx_in) +
             tx->num_vout * sizeof(struct tx_out) +
             tx->num_shielded_spend * sizeof(struct spend_description) +
             tx->num_shielded_output * sizeof(struct output_description) +
             tx->num_joinsplit * sizeof(struct js_description);
    }
    return n;
}

/* Free one ring slot's body and subtract its accounted bytes. MUST hold
 * g_bpc_mutex. Same teardown the release/evict/clear paths already did
 * inline: the slot is reused by whoever stores into it next. */
static void bpc_free_slot_locked(struct bpc_entry *entry)
{
    block_free(&entry->body);
    atomic_fetch_sub(&g_bpc_bytes, entry->bytes);
    entry->bytes = 0;
    entry->used = false;
    entry->pending_evict = false;
    entry->generation = atomic_fetch_add(&g_bpc_generation, 1) + 1;
}

/* Oldest resident entry that may be evicted right now, or NULL when every
 * entry is pinned or already pending. MUST hold g_bpc_mutex. */
static struct bpc_entry *bpc_oldest_evictable_locked(void)
{
    struct bpc_entry *oldest = NULL;
    for (size_t i = 0; i < BPC_CAPACITY; i++) {
        struct bpc_entry *e = &g_bpc[i];
        if (!e->used || e->pins > 0 || e->pending_evict)
            continue;
        if (!oldest || e->generation < oldest->generation)
            oldest = e;
    }
    return oldest;
}

/* Enforce the resident byte ceiling straight after an insert. MUST hold
 * g_bpc_mutex. Evicts oldest-unpinned entries (generation order) until the
 * total fits; a pinned entry is never evicted — it is skipped and the scan
 * continues — and if every entry is pinned the excess survives until the
 * next insert. Logged at most once per cache generation. */
static void bpc_enforce_byte_ceiling_locked(void)
{
    uint64_t evicted = 0;
    while (atomic_load(&g_bpc_bytes) > g_bpc_ceiling_bytes) {
        struct bpc_entry *victim = bpc_oldest_evictable_locked();
        if (!victim) {
            if (!g_bpc_ceiling_pinned_logged) {
                LOG_WARN("block_parse_cache",
                         "byte ceiling reached but all entries pinned: "
                         "holding %llu bytes (ceiling %llu) until pins drop",
                         (unsigned long long)atomic_load(&g_bpc_bytes),
                         (unsigned long long)g_bpc_ceiling_bytes);
                g_bpc_ceiling_pinned_logged = true;
            }
            break;
        }
        bpc_free_slot_locked(victim);
        evicted++;
    }
    if (evicted > 0 && !g_bpc_ceiling_evict_logged) {
        LOG_INFO("block_parse_cache",
                 "byte ceiling: evicted %llu oldest entr%s, holding %llu "
                 "bytes (ceiling %llu)",
                 (unsigned long long)evicted, evicted == 1 ? "y" : "ies",
                 (unsigned long long)atomic_load(&g_bpc_bytes),
                 (unsigned long long)g_bpc_ceiling_bytes);
        g_bpc_ceiling_evict_logged = true;
    }
}

static size_t bpc_slot(int32_t height)
{
    return (size_t)(uint32_t)height & (BPC_CAPACITY - 1u);
}

/* ── Sealed-segment source (the fold substrate) ──────────────────────────
 * Below the sealed frontier a finalized body is read from an mmap'd, sealed
 * segment (sequential + hash-verified) instead of a blk*.dat pread. The store
 * is opened lazily on the first miss and keyed to a datadir; a datadir change
 * (or the absence of a segments dir) reopens/empties it. Because segments store
 * exactly the block_serialize output, deserializing the segment bytes yields a
 * struct byte-identical to a fresh disk read — and we additionally re-derive
 * the block hash and require it to equal the caller's active-chain hash before
 * serving, so a segment on a different fork can never be substituted. Any miss
 * or mismatch falls through to the unchanged blk*.dat path, so a node with no
 * segments is byte-for-byte unchanged. */
static pthread_mutex_t g_seg_mutex = PTHREAD_MUTEX_INITIALIZER;
static struct chain_segment_store *g_seg_store; /* NULL until first open */
static char g_seg_datadir[3072];
static bool g_seg_open_tried;                   /* store open attempted for g_seg_datadir */

/* Segment-vs-blk*.dat read source counters (see block_parse_cache.h). Counted
 * once per MISS-path body fetch, at the exact fork point between the two
 * sources — proves whether the fold is actually reading through the sealed
 * substrate or still falling back to blk*.dat. */
static _Atomic uint64_t g_bpc_seg_reads;
static _Atomic uint64_t g_bpc_blkdat_reads;

/* Ensure the resident store matches `datadir`. MUST hold g_seg_mutex. */
static void bpc_segment_sync_store_locked(const char *datadir)
{
    if (g_seg_open_tried && strncmp(g_seg_datadir, datadir,
                                    sizeof(g_seg_datadir)) == 0)
        return; /* already opened for this datadir */

    if (g_seg_store) {
        chain_segment_store_close(g_seg_store);
        g_seg_store = NULL;
    }
    snprintf(g_seg_datadir, sizeof(g_seg_datadir), "%s", datadir);
    g_seg_open_tried = true;

    char dir[3200];
    snprintf(dir, sizeof(dir), "%s/segments", datadir);
    char err[256] = {0};
    struct chain_segment_store *s = NULL;
    enum cseg_status st = chain_segment_store_open(dir, &s, err, sizeof(err));
    if (st != CSEG_OK) {
        LOG_WARN("block_parse_cache",
                 "segment store open failed dir=%s: %s (%s) — using blk*.dat",
                 dir, cseg_status_str(st), err);
        return;
    }
    g_seg_store = s; /* may cover nothing; that is fine */
}

/* Try to fill `out` for (height, block_hash) from a sealed segment. Returns
 * true only when a covering segment yielded a body whose re-derived hash equals
 * `block_hash`. On any negative outcome `out` is left free-safe and false is
 * returned so the caller uses the disk path. */
static bool bpc_segment_try(int32_t height, const uint8_t block_hash[32],
                            const char *datadir, struct block *out,
                            uint64_t *read_us_out, uint64_t *parse_us_out)
{
    if (!datadir || !datadir[0] || height < 0)
        return false;

    pthread_mutex_lock(&g_seg_mutex);
    bpc_segment_sync_store_locked(datadir);
    struct chain_segment_store *store = g_seg_store;
    if (!store || !chain_segment_store_covers(store, (uint32_t)height)) {
        pthread_mutex_unlock(&g_seg_mutex);
        return false;
    }
    uint8_t *raw = NULL;
    size_t rawlen = 0;
    char err[256] = {0};
    int64_t read_started = platform_time_monotonic_us();
    enum cseg_status st = chain_segment_store_get_block(
        store, (uint32_t)height, &raw, &rawlen, err, sizeof(err));
    pthread_mutex_unlock(&g_seg_mutex);
    if (read_us_out)
        *read_us_out +=
            (uint64_t)(platform_time_monotonic_us() - read_started);

    if (st != CSEG_OK || !raw || rawlen == 0) {
        if (st != CSEG_OK)
            LOG_WARN("block_parse_cache",
                     "segment read h=%d: %s (%s) — falling back to blk*.dat",
                     height, cseg_status_str(st), err);
        free(raw);
        return false;
    }

    int64_t parse_started = platform_time_monotonic_us();
    struct byte_stream s;
    stream_init_from_data(&s, raw, rawlen);
    bool parsed = block_deserialize(out, &s);
    stream_free(&s);
    free(raw);
    if (parse_us_out)
        *parse_us_out +=
            (uint64_t)(platform_time_monotonic_us() - parse_started);
    if (!parsed) {
        block_free(out);
        block_init(out);
        LOG_WARN("block_parse_cache",
                 "segment body deserialize failed h=%d — falling back", height);
        return false;
    }

    /* Bind the served body to the caller's active-chain hash: a segment on a
     * different fork (or a stale height mapping) must never be substituted. */
    struct uint256 got;
    block_get_hash(out, &got);
    if (memcmp(got.data, block_hash, 32) != 0) {
        block_free(out);
        block_init(out);
        return false;
    }
    return true;
}

static void bpc_handle_set(struct block_parse_handle *out,
                           struct bpc_entry *entry, bool hit)
{
    entry->pins++;
    out->block = &entry->body;
    out->entry = entry;
    out->generation = entry->generation;
    out->detached = entry->detached;
    out->cache_hit = hit;
}

static struct bpc_entry *bpc_detached_from(struct block *loaded,
                                           int32_t height,
                                           const uint8_t hash[32])
{
    /* Detached entries are handle-owned, not ring-resident: they die with
     * their handle, so they are not part of the tracked g_bpc_bytes total. */
    struct bpc_entry *entry = zcl_calloc(1, sizeof(*entry), "bpc detached");
    if (!entry)
        return NULL;
    entry->used = true;
    entry->height = height;
    memcpy(entry->hash, hash, 32);
    entry->body = *loaded;
    block_init(loaded);
    entry->generation = atomic_fetch_add(&g_bpc_generation, 1) + 1;
    entry->detached = true;
    return entry;
}

static bool bpc_entry_resident_hit(const struct bpc_entry *entry,
                                   int32_t height,
                                   const uint8_t block_hash[32])
{
    return entry->used && !entry->pending_evict && entry->height == height &&
           memcmp(entry->hash, block_hash, 32) == 0;
}

static bool bpc_load_miss_body(int32_t height, const uint8_t block_hash[32],
                               const struct block_index *bi,
                               const char *datadir, struct block *loaded,
                               struct block_parse_handle *out)
{
    if (!bpc_segment_try(height, block_hash, datadir, loaded,
                         &out->disk_read_us, &out->parse_us)) {
        atomic_fetch_add(&g_bpc_blkdat_reads, 1);
        struct disk_block_pos pos;
        disk_block_pos_init(&pos);
        if (!block_index_disk_pos_snapshot(bi, &pos, NULL))
            return false;
        uint64_t disk_read_us = 0;
        uint64_t parse_us = 0;
        if (!read_block_from_disk_pread_profiled(
                loaded, &pos, datadir ? datadir : "", &disk_read_us,
                &parse_us)) {
            block_free(loaded);
            return false;
        }
        out->disk_read_us += disk_read_us;
        out->parse_us += parse_us;
    } else {
        atomic_fetch_add(&g_bpc_seg_reads, 1);
    }
    return true;
}

static bool bpc_store_unpinned(struct bpc_entry *entry, struct block *loaded,
                               int32_t height, const uint8_t block_hash[32],
                               struct block_parse_handle *out)
{
    if (!entry->used || entry->pins == 0) {
        uint64_t body_bytes = bpc_body_bytes(loaded);
        if (entry->used) {
            block_free(&entry->body);
            atomic_fetch_sub(&g_bpc_bytes, entry->bytes);
        }
        memset(entry, 0, sizeof(*entry));
        entry->used = true;
        entry->height = height;
        memcpy(entry->hash, block_hash, 32);
        entry->body = *loaded;
        block_init(loaded);
        entry->bytes = body_bytes;
        atomic_fetch_add(&g_bpc_bytes, body_bytes);
        entry->generation = atomic_fetch_add(&g_bpc_generation, 1) + 1;
        bpc_handle_set(out, entry, false);
        return true;
    }
    return false;
}

static bool bpc_pin_detached_body(struct block_parse_handle *out,
                                  struct block *loaded, int32_t height,
                                  const uint8_t hash[32])
{
    struct bpc_entry *detached = bpc_detached_from(loaded, height, hash);
    block_free(loaded);
    if (!detached)
        return false;
    bpc_handle_set(out, detached, false);
    return true;
}

bool block_parse_cache_acquire(int32_t height, const uint8_t block_hash[32],
                               const struct block_index *bi,
                               const char *datadir,
                               struct block_parse_handle *out)
{
    if (!out || !block_hash || !bi)
        return false;
    memset(out, 0, sizeof(*out));
    pthread_once(&g_bpc_first_use_once, bpc_first_use_init);

    size_t slot = bpc_slot(height);
    int64_t lock_started = platform_time_monotonic_us();
    pthread_mutex_lock(&g_bpc_mutex);
    out->lock_wait_us += (uint64_t)(platform_time_monotonic_us() - lock_started);
    out->lookup_probes = 1;
    struct bpc_entry *entry = &g_bpc[slot];
    if (bpc_entry_resident_hit(entry, height, block_hash)) {
        bpc_handle_set(out, entry, true);
        pthread_mutex_unlock(&g_bpc_mutex);
        return true;
    }
    pthread_mutex_unlock(&g_bpc_mutex);

    struct block loaded;
    block_init(&loaded);
    if (!bpc_load_miss_body(height, block_hash, bi, datadir, &loaded, out))
        return false;

    struct uint256 got_hash;
    block_get_hash(&loaded, &got_hash);
    bool key_matches = memcmp(got_hash.data, block_hash, 32) == 0;
    if (!key_matches) {
        LOG_WARN("block_parse_cache",
                 "MISS body hash mismatch h=%d — not caching (bad read?)",
                 height);
        return bpc_pin_detached_body(out, &loaded, height, got_hash.data);
    }

    lock_started = platform_time_monotonic_us();
    pthread_mutex_lock(&g_bpc_mutex);
    out->lock_wait_us += (uint64_t)(platform_time_monotonic_us() - lock_started);
    entry = &g_bpc[slot];
    if (bpc_entry_resident_hit(entry, height, block_hash)) {
        bpc_handle_set(out, entry, true); /* another reader won the miss race */
        pthread_mutex_unlock(&g_bpc_mutex);
        block_free(&loaded);
        return true;
    }
    if (bpc_store_unpinned(entry, &loaded, height, block_hash, out)) {
        bpc_enforce_byte_ceiling_locked();
        pthread_mutex_unlock(&g_bpc_mutex);
        return true;
    }
    pthread_mutex_unlock(&g_bpc_mutex);

    return bpc_pin_detached_body(out, &loaded, height, block_hash);
}

const struct block *block_parse_handle_block(
    const struct block_parse_handle *handle)
{
    return handle ? handle->block : NULL;
}

void block_parse_cache_release(struct block_parse_handle *handle)
{
    if (!handle || !handle->entry)
        return;
    struct bpc_entry *entry = handle->entry;
    if (handle->detached) {
        if (entry->generation == handle->generation) {
            block_free(&entry->body);
            free(entry);
        }
        memset(handle, 0, sizeof(*handle));
        return;
    }
    pthread_mutex_lock(&g_bpc_mutex);
    if (entry->generation == handle->generation && entry->pins > 0) {
        entry->pins--;
        if (entry->pins == 0 && entry->pending_evict)
            bpc_free_slot_locked(entry);
    }
    pthread_mutex_unlock(&g_bpc_mutex);
    memset(handle, 0, sizeof(*handle));
}

bool block_parse_cache_get(int32_t height, const uint8_t block_hash[32],
                           const struct block_index *bi, const char *datadir,
                           struct block *out)
{
    struct block_parse_handle handle;
    if (!out || !block_parse_cache_acquire(height, block_hash, bi, datadir,
                                           &handle))
        return false;
    bool ok = block_clone(out, block_parse_handle_block(&handle));
    block_parse_cache_release(&handle);
    return ok;
}

void block_parse_cache_evict(int32_t height, const uint8_t hash[32])
{
    if (!hash)
        return;
    pthread_mutex_lock(&g_bpc_mutex);
    struct bpc_entry *entry = &g_bpc[bpc_slot(height)];
    if (entry->used && entry->height == height &&
        memcmp(entry->hash, hash, 32) == 0) {
        entry->pending_evict = true;
        if (entry->pins == 0)
            bpc_free_slot_locked(entry);
    }
    pthread_mutex_unlock(&g_bpc_mutex);
}

void block_parse_cache_clear(void)
{
    pthread_mutex_lock(&g_bpc_mutex);
    for (int i = 0; i < BPC_CAPACITY; i++) {
        if (!g_bpc[i].used)
            continue;
        g_bpc[i].pending_evict = true;
        if (g_bpc[i].pins == 0)
            bpc_free_slot_locked(&g_bpc[i]);
    }
    /* A clear starts a new cache generation: the once-per-generation ceiling
     * log markers apply again. Reset under the same lock the enforcer reads
     * them under, or a concurrent enforcement could double-log. */
    g_bpc_ceiling_evict_logged = false;
    g_bpc_ceiling_pinned_logged = false;
    pthread_mutex_unlock(&g_bpc_mutex);
}

void block_parse_cache_segment_read_stats(uint64_t *segment_hits,
                                          uint64_t *blkdat_reads)
{
    if (segment_hits)  *segment_hits  = atomic_load(&g_bpc_seg_reads);
    if (blkdat_reads)  *blkdat_reads  = atomic_load(&g_bpc_blkdat_reads);
}
