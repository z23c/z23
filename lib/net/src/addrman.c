/* Copyright (c) 2012 Pieter Wuille
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#include "net/addrman.h"
#include "addrman_internal.h"
#include "net/directory_influence_port.h"
#include "core/hash.h"
#include "core/random.h"
#include "core/serialize.h"
#include "util/timedata.h"
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include "util/safe_alloc.h"
#include "util/log_macros.h"
int addr_info_get_tried_bucket(const struct addr_info *info,
                               const struct uint256 *nKey)
{
    unsigned char key[NET_SERVICE_KEY_SIZE];
    net_service_get_key(&info->addr.svc, key);

    unsigned char buf[32 + NET_SERVICE_KEY_SIZE];
    memcpy(buf, nKey->data, 32);
    memcpy(buf + 32, key, NET_SERVICE_KEY_SIZE);
    struct uint256 hash1;
    hash256(buf, sizeof(buf), hash1.data);
    uint64_t h1;
    memcpy(&h1, hash1.data, sizeof(h1));

    unsigned char group[NET_ADDR_GROUP_MAX];
    size_t glen = net_addr_get_group(&info->addr.svc.addr, group, sizeof(group));

    unsigned char buf2[32 + NET_ADDR_GROUP_MAX + 8];
    memcpy(buf2, nKey->data, 32);
    memcpy(buf2 + 32, group, glen);
    uint64_t bucket_seed = h1 % ADDRMAN_TRIED_BUCKETS_PER_GROUP;
    memcpy(buf2 + 32 + glen, &bucket_seed, sizeof(bucket_seed));
    struct uint256 hash2;
    hash256(buf2, 32 + glen + sizeof(bucket_seed), hash2.data);
    uint64_t h2;
    memcpy(&h2, hash2.data, sizeof(h2));

    return (int)(h2 % ADDRMAN_TRIED_BUCKET_COUNT);
}

int addr_info_get_new_bucket(const struct addr_info *info,
                             const struct uint256 *nKey,
                             const struct net_addr *src)
{
    unsigned char src_group[NET_ADDR_GROUP_MAX];
    size_t sglen = net_addr_get_group(src, src_group, sizeof(src_group));

    unsigned char my_group[NET_ADDR_GROUP_MAX];
    size_t mglen = net_addr_get_group(&info->addr.svc.addr, my_group,
                                       sizeof(my_group));

    unsigned char buf1[32 + NET_ADDR_GROUP_MAX + NET_ADDR_GROUP_MAX];
    memcpy(buf1, nKey->data, 32);
    memcpy(buf1 + 32, my_group, mglen);
    memcpy(buf1 + 32 + mglen, src_group, sglen);
    struct uint256 hash1;
    hash256(buf1, 32 + mglen + sglen, hash1.data);
    uint64_t h1;
    memcpy(&h1, hash1.data, sizeof(h1));

    unsigned char buf2[32 + NET_ADDR_GROUP_MAX + 8];
    memcpy(buf2, nKey->data, 32);
    memcpy(buf2 + 32, src_group, sglen);
    uint64_t bucket_seed = h1 % ADDRMAN_NEW_BUCKETS_PER_SOURCE_GROUP;
    memcpy(buf2 + 32 + sglen, &bucket_seed, sizeof(bucket_seed));
    struct uint256 hash2;
    hash256(buf2, 32 + sglen + sizeof(bucket_seed), hash2.data);
    uint64_t h2;
    memcpy(&h2, hash2.data, sizeof(h2));

    return (int)(h2 % ADDRMAN_NEW_BUCKET_COUNT);
}

int addr_info_get_bucket_position(const struct addr_info *info,
                                  const struct uint256 *nKey,
                                  bool fNew, int nBucket)
{
    unsigned char key[NET_SERVICE_KEY_SIZE];
    net_service_get_key(&info->addr.svc, key);

    unsigned char buf[32 + 1 + 4 + NET_SERVICE_KEY_SIZE];
    memcpy(buf, nKey->data, 32);
    buf[32] = fNew ? 'N' : 'K';
    memcpy(buf + 33, &nBucket, 4);
    memcpy(buf + 37, key, NET_SERVICE_KEY_SIZE);
    struct uint256 h;
    hash256(buf, sizeof(buf), h.data);
    uint64_t r;
    memcpy(&r, h.data, sizeof(r));
    return (int)(r % ADDRMAN_BUCKET_SIZE);
}

bool addr_info_is_terrible(const struct addr_info *info, int64_t nNow)
{
    if (info->last_try && info->last_try >= nNow - 60)
        return false;
    if ((int64_t)info->addr.nTime > nNow + 10 * 60)
        return true;
    if (info->addr.nTime == 0 ||
        nNow - (int64_t)info->addr.nTime > ADDRMAN_HORIZON_DAYS * 24 * 60 * 60)
        return true;
    if (info->last_success == 0 && info->attempts >= ADDRMAN_RETRIES)
        return true;
    if (nNow - info->last_success > ADDRMAN_MIN_FAIL_DAYS * 24 * 60 * 60 &&
        info->attempts >= ADDRMAN_MAX_FAILURES)
        return true;
    return false;
}

/* ── the published weight table ─────────────────────────────────────────
 *
 * See "the published weight table" in net/addrman.h for why the per-entry
 * weight is gone. Here is only the mechanism: an immutable sorted array,
 * allocated whole, swapped under `am->cs`, and freed the moment it is
 * replaced — safe because every reader also holds `cs`, so a publisher that
 * owns the lock knows nobody is still inside the outgoing table. */
struct addrman_weights {
    size_t  count;
    int32_t epoch;
    struct addrman_weight_row rows[];   /* ascending by ip */
};

static int weight_row_cmp(const void *va, const void *vb)
{
    const struct addrman_weight_row *a = va, *b = vb;
    return memcmp(a->ip, b->ip, 16);
}

/* The published multiplier for `ip`, or 1.0. Caller holds `cs`. */
static double weights_lookup(const struct addrman_weights *w,
                             const unsigned char ip[16])
{
    if (!w || w->count == 0)
        return 1.0;
    size_t lo = 0, hi = w->count;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        int c = memcmp(w->rows[mid].ip, ip, 16);
        if (c < 0)
            lo = mid + 1;
        else if (c > 0)
            hi = mid;
        else
            return w->rows[mid].multiplier;
    }
    return 1.0;   /* absent == baseline, by construction */
}

double addr_info_get_chance(const struct addr_man *am,
                            const struct addr_info *info, int64_t nNow)
{
    double fChance = 1.0;
    int64_t nSinceLastTry = nNow - info->last_try;
    if (nSinceLastTry < 0) nSinceLastTry = 0;
    if (nSinceLastTry < 60 * 10)
        fChance *= 0.01;
    /* Clamp BELOW as well as above. pow(0.66, n) is a decay only for n >= 0;
     * a negative attempts count inverts it into growth, and n == -100 yields
     * 0.66^-100 — a chance so far above 1.0 that the entry wins every draw it
     * appears in. attempts is loaded from peers.dat, which records what peers
     * told us, so it must never be trusted to be non-negative here. */
    int n = info->attempts < 0 ? 0 : info->attempts;
    if (n > 8) n = 8;
    fChance *= pow(0.66, n);
    /* NET-2/T5.2: the published table raises (never lowers) the dial chance
     * for a peer this epoch ranked. Bounded and fail-open — no table, or an
     * address absent from it, leaves the classic behavior byte-identical. */
    if (am) {
        double w = weights_lookup(am->weights, info->addr.svc.addr.ip);
        if (w > 1.0) {
            if (w > ADDRMAN_REPUTATION_MAX_MULT)
                w = ADDRMAN_REPUTATION_MAX_MULT;
            fChance *= w;
        }
    }
    return fChance;
}

bool addrman_publish_reputation_weights(struct addr_man *am,
                                        const struct addrman_weight_row *rows,
                                        size_t n, int32_t epoch)
{
    if (!am)
        LOG_FAIL("addrman", "publish weights: NULL addrman");
    if (n > 0 && !rows)
        LOG_FAIL("addrman", "publish weights: %zu rows with NULL array", n);
    /* DEGRADED MODE (net/directory_influence_port.h). While the node suspects
     * it is on the minority side of a network split, directory-derived dial
     * preference gains no new influence: this is the single point where the
     * directory reaches addrman, and a bounded 1-4x multiplier learned from
     * the split's own side is exactly the input that would pin us there. The
     * table already published is LEFT ALONE — pre-split preference keeps
     * working — and selection itself is untouched, so discovery simply falls
     * back to the previous epoch's weights plus the compiled seeds and addr
     * gossip. Unregistered port = UNGOVERNED = admitted, so every binary that
     * links lib/net without the composition root behaves exactly as before. */
    if (!directory_influence_port_admits()) {
        static _Atomic uint64_t withheld;
        uint64_t w = atomic_fetch_add(&withheld, 1u) + 1u;
        if (w == 1u || w % 1024u == 0u)
            LOG_WARN("addrman",
                     "weight table withheld (%zu rows, epoch %d): directory "
                     "influence is suspended while SUSPECTED_NETSPLIT stands; "
                     "the previously published table keeps working "
                     "(withheld=%llu)",
                     n, epoch, (unsigned long long)w);
        return false;
    }

    struct addrman_weights *next = zcl_malloc(
        sizeof(*next) + n * sizeof(struct addrman_weight_row),
        "addrman_weights");
    if (!next)
        LOG_FAIL("addrman", "publish weights: alloc failed for %zu rows", n);
    next->count = 0;
    next->epoch = epoch;

    for (size_t i = 0; i < n; i++) {
        double m = rows[i].multiplier;
        if (m > ADDRMAN_REPUTATION_MAX_MULT)
            m = ADDRMAN_REPUTATION_MAX_MULT;
        if (!(m > 1.0))
            continue;   /* absence already means 1.0; NaN lands here too */
        memcpy(next->rows[next->count].ip, rows[i].ip, 16);
        next->rows[next->count].multiplier = m;
        next->count++;
    }
    if (next->count > 1) {
        qsort(next->rows, next->count, sizeof(next->rows[0]), weight_row_cmp);
        /* One address, one multiplier. A duplicate keeps the higher value —
         * the table may only ever raise a candidate's standing. */
        size_t w = 0;
        for (size_t i = 1; i < next->count; i++) {
            if (memcmp(next->rows[w].ip, next->rows[i].ip, 16) == 0) {
                if (next->rows[i].multiplier > next->rows[w].multiplier)
                    next->rows[w].multiplier = next->rows[i].multiplier;
            } else {
                next->rows[++w] = next->rows[i];
            }
        }
        next->count = w + 1;
    }

    zcl_mutex_lock(&am->cs);
    struct addrman_weights *prev = am->weights;
    am->weights = next;
    free(prev);   /* every reader holds cs; nobody is inside `prev` */
    zcl_mutex_unlock(&am->cs);
    return true;
}

double addrman_reputation_weight(struct addr_man *am,
                                 const struct net_addr *addr)
{
    if (!am || !addr)
        return 1.0;
    zcl_mutex_lock(&am->cs);
    double w = weights_lookup(am->weights, addr->ip);
    zcl_mutex_unlock(&am->cs);
    return w;
}

size_t addrman_reputation_weight_count(struct addr_man *am)
{
    if (!am)
        return 0;
    zcl_mutex_lock(&am->cs);
    size_t n = am->weights ? am->weights->count : 0;
    zcl_mutex_unlock(&am->cs);
    return n;
}

int32_t addrman_reputation_weight_epoch(struct addr_man *am)
{
    if (!am)
        return INT32_MIN;
    zcl_mutex_lock(&am->cs);
    int32_t e = am->weights ? am->weights->epoch : INT32_MIN;
    zcl_mutex_unlock(&am->cs);
    return e;
}

static bool addrman_find_occupied_slot(const int *table,
                                       int bucket_count,
                                       int start_bucket,
                                       int start_pos,
                                       int *bucket_out,
                                       int *pos_out)
{
    if (!table || bucket_count <= 0 || !bucket_out || !pos_out)
        return false;

    for (int bucket_offset = 0; bucket_offset < bucket_count; bucket_offset++) {
        int bucket = (start_bucket + bucket_offset) % bucket_count;
        for (int pos_offset = 0; pos_offset < ADDRMAN_BUCKET_SIZE; pos_offset++) {
            int pos = (start_pos + pos_offset) % ADDRMAN_BUCKET_SIZE;
            if (table[bucket * ADDRMAN_BUCKET_SIZE + pos] != -1) {
                *bucket_out = bucket;
                *pos_out = pos;
                return true;
            }
        }
    }

    return false;
}

/* ── Address index ─────────────────────────────────────────────────
 * O(1) net_addr→entry-id map so addrman_add() dedups an incoming addr
 * without the old O(id_count) linear scan over `entries` (up to 65536
 * compares per address, MAX_ADDR_TO_SEND=1000 per untrusted P2P addr
 * message). Open addressing, linear probe, tombstoned deletes — mirrors
 * the qset scheme in download.c. `entries` (with `used`) is the source
 * of truth; the index only answers "which id has this address?". All
 * helpers require the caller to hold am->cs. The index is in-memory
 * only: never serialized, rebuilt from `entries` on load. */

/* ADDRMAN_INDEX_INITIAL_SLOTS lives in addrman_internal.h — addrman_codec.c
 * sizes the index it rebuilds after a load from the same constant. */

struct addr_index_slot {
    struct net_addr key;
    int id;
    uint8_t state;   /* 0 = empty (probe end), 1 = live, 2 = tombstone */
};

/* FNV-1a over the identity-defining bytes of a net_addr. MUST hash exactly
 * the fields net_addr_eq() compares: ip[16], has_torv3, and torv3 only when
 * has_torv3 is set (torv3 bytes are ignored by eq otherwise). */
static size_t addr_index_hash(const struct net_addr *a, size_t mask)
{
    uint64_t fnv = 14695981039346656037ULL;
    for (int i = 0; i < 16; i++) {
        fnv ^= a->ip[i];
        fnv *= 1099511628211ULL;
    }
    fnv ^= (unsigned char)(a->has_torv3 ? 1u : 0u);
    fnv *= 1099511628211ULL;
    if (a->has_torv3) {
        for (int i = 0; i < TORV3_ADDR_SIZE; i++) {
            fnv ^= a->torv3[i];
            fnv *= 1099511628211ULL;
        }
    }
    return (size_t)(fnv & mask);
}

/* Return the entry id for `addr`, or -1 if not present. Const/read-only. */
static int addr_index_lookup(const struct addr_man *am,
                             const struct net_addr *addr)
{
    if (!am->idx || am->idx_slots == 0)
        return -1;
    size_t mask = am->idx_slots - 1;
    size_t idx = addr_index_hash(addr, mask);
    for (size_t i = 0; i < am->idx_slots; i++) {
        const struct addr_index_slot *e = &am->idx[(idx + i) & mask];
        if (e->state == 0)
            return -1;                          /* empty: probe chain end */
        if (e->state == 1 && net_addr_eq(&e->key, addr))
            return e->id;
    }
    return -1;
}

/* Brute-force fallback: lowest used entry id matching `addr`, else -1.
 * Used when the index is unavailable (OOM at init) and by the verifier. */
static int addr_scan_id(const struct addr_man *am, const struct net_addr *addr)
{
    for (int i = 0; i < am->id_count; i++)
        if (am->entries[i].used &&
            net_addr_eq(&am->entries[i].addr.svc.addr, addr))
            return i;
    return -1;
}

/* Insert (addr→id) without a duplicate check. Callers guarantee the address
 * is not already live (addrman_add only creates an entry after find_addr
 * returned NULL) and that capacity was reserved. Reuses tombstones. */
static void addr_index_insert_raw(struct addr_man *am,
                                  const struct net_addr *addr, int id)
{
    if (!am->idx || am->idx_slots == 0)
        return;
    size_t mask = am->idx_slots - 1;
    size_t idx = addr_index_hash(addr, mask);
    for (size_t i = 0; i < am->idx_slots; i++) {
        struct addr_index_slot *e = &am->idx[(idx + i) & mask];
        if (e->state != 1) {
            if (e->state == 2) am->idx_tombs--;
            e->key = *addr;
            e->id = id;
            e->state = 1;
            am->idx_live++;
            return;
        }
    }
}

/* Rebuild the index from `entries` (the source of truth), dropping
 * tombstones and growing to `new_slots` (power of 2). Keeps the old table
 * on alloc failure — correctness is unaffected, only probe lengths suffer.
 * Iterates ids ascending and skips duplicates so the index resolves to the
 * same (lowest) id a brute-force scan would, even for a corrupt load. */
void addrman_index_rebuild_locked(struct addr_man *am, size_t new_slots)
{
    struct addr_index_slot *ns =
        zcl_calloc(new_slots, sizeof(struct addr_index_slot), "addr_index");
    if (!ns) {
        LOG_WARN("addrman", "addrman_index_rebuild_locked: calloc failed slots=%zu, keeping old table", new_slots);
        return;
    }
    free(am->idx);
    am->idx = ns;
    am->idx_slots = new_slots;
    am->idx_live = 0;
    am->idx_tombs = 0;
    for (int i = 0; i < am->id_count; i++) {
        if (!am->entries[i].used)
            continue;
        if (addr_index_lookup(am, &am->entries[i].addr.svc.addr) != -1)
            continue;                           /* keep lowest id on dup */
        addr_index_insert_raw(am, &am->entries[i].addr.svc.addr, i);
    }
}

/* Ensure room for one more live entry at < 50% combined load. Rebuild
 * reads `entries`, so callers MUST reserve BEFORE writing the new entry
 * into `entries`/bumping id_count — otherwise the rebuild folds the new
 * entry in and the following insert_raw double-counts it. */
static void addr_index_reserve_one(struct addr_man *am)
{
    if (!am->idx || am->idx_slots == 0)
        return;
    if ((am->idx_live + am->idx_tombs + 1) * 2 < am->idx_slots)
        return;
    size_t want = am->idx_slots;
    if ((am->idx_live + 1) * 2 >= want)
        want *= 2;                              /* genuinely full: grow */
    /* else tombstone-heavy: rebuild at the same size to reclaim tombs */
    addrman_index_rebuild_locked(am, want);
}

/* Tombstone the live slot for `addr` (delete path). No-op if absent. */
static void addr_index_remove(struct addr_man *am, const struct net_addr *addr)
{
    if (!am->idx || am->idx_slots == 0)
        return;
    size_t mask = am->idx_slots - 1;
    size_t idx = addr_index_hash(addr, mask);
    for (size_t i = 0; i < am->idx_slots; i++) {
        struct addr_index_slot *e = &am->idx[(idx + i) & mask];
        if (e->state == 0)
            return;
        if (e->state == 1 && net_addr_eq(&e->key, addr)) {
            e->state = 2;
            am->idx_live--;
            am->idx_tombs++;
            return;
        }
    }
}

/* Empty the index without freeing it (addrman_clear / addrman_deserialize). */
static void addr_index_clear(struct addr_man *am)
{
    if (!am->idx || am->idx_slots == 0)
        return;
    memset(am->idx, 0, am->idx_slots * sizeof(struct addr_index_slot));
    am->idx_live = 0;
    am->idx_tombs = 0;
}

void addrman_init(struct addr_man *am)
{
    zcl_mutex_init(&am->cs);
    GetRandBytes(am->nKey.data, 32);
    am->id_count = 0;
    am->tried_count = 0;
    am->new_count = 0;
    am->weights = NULL;   /* nothing published: every address reads 1.0 */
    am->random_order = NULL;
    am->random_size = 0;
    am->random_cap = 0;
    am->entries_cap = 4096;
    am->entries = zcl_calloc(am->entries_cap, sizeof(struct addr_info), "addr_entries");
    am->idx_slots = ADDRMAN_INDEX_INITIAL_SLOTS;
    am->idx = zcl_calloc(am->idx_slots, sizeof(struct addr_index_slot), "addr_index");
    am->idx_live = 0;
    am->idx_tombs = 0;
    if (!am->idx)
        am->idx_slots = 0;   /* fall back to linear scan in find_addr */
    for (int i = 0; i < ADDRMAN_NEW_BUCKET_COUNT; i++)
        for (int j = 0; j < ADDRMAN_BUCKET_SIZE; j++)
            am->vvNew[i][j] = -1;
    for (int i = 0; i < ADDRMAN_TRIED_BUCKET_COUNT; i++)
        for (int j = 0; j < ADDRMAN_BUCKET_SIZE; j++)
            am->vvTried[i][j] = -1;
}

void addrman_free(struct addr_man *am)
{
    free(am->random_order);
    free(am->entries);
    free(am->idx);
    free(am->weights);
    am->weights = NULL;
    am->random_order = NULL;
    am->entries = NULL;
    am->idx = NULL;
    am->idx_slots = 0;
    am->idx_live = 0;
    am->idx_tombs = 0;
    zcl_mutex_destroy(&am->cs);
}

void addrman_clear(struct addr_man *am)
{
    /* The published weight table survives: it is the ranking epoch's
     * publication, not addrman's data. Dropping every address does not
     * un-rank the relays, and a re-learned address regains exactly the
     * multiplier this epoch computed for it. */
    GetRandBytes(am->nKey.data, 32);
    am->id_count = 0;
    am->tried_count = 0;
    am->new_count = 0;
    free(am->random_order);
    am->random_order = NULL;
    am->random_size = 0;
    am->random_cap = 0;
    if (am->entries)
        memset(am->entries, 0, am->entries_cap * sizeof(struct addr_info));
    addr_index_clear(am);
    for (int i = 0; i < ADDRMAN_NEW_BUCKET_COUNT; i++)
        for (int j = 0; j < ADDRMAN_BUCKET_SIZE; j++)
            am->vvNew[i][j] = -1;
    for (int i = 0; i < ADDRMAN_TRIED_BUCKET_COUNT; i++)
        for (int j = 0; j < ADDRMAN_BUCKET_SIZE; j++)
            am->vvTried[i][j] = -1;
}

size_t addrman_size(const struct addr_man *am)
{
    return am->random_size;
}

size_t addrman_proven_count(struct addr_man *am)
{
    if (!am)
        return 0;
    zcl_mutex_lock(&am->cs);
    size_t n = 0;
    for (int i = 0; i < am->id_count; i++)
        if (am->entries[i].used && am->entries[i].last_success != 0)
            n++;
    zcl_mutex_unlock(&am->cs);
    return n;
}

void addrman_random_push_locked(struct addr_man *am, int id)
{
    if (am->random_size >= am->random_cap) {
        size_t new_cap = am->random_cap ? am->random_cap * 2 : 256;
        int *p = zcl_realloc(am->random_order, new_cap * sizeof(int), "addr_random_order");
        if (!p) { LOG_WARN("addrman", "addrman_random_push_locked: realloc failed cap=%zu, dropping id=%d", new_cap, id); return; }
        am->random_order = p;
        am->random_cap = new_cap;
    }
    am->random_order[am->random_size++] = id;
}

static void swap_random(struct addr_man *am, unsigned int p1, unsigned int p2)
{
    if (p1 == p2) return;
    if (p1 >= am->random_size || p2 >= am->random_size) {
        LOG_WARN("addrman", "swap_random: index OOB p1=%u p2=%u size=%zu", p1, p2, am->random_size);
        return;
    }
    int id1 = am->random_order[p1];
    int id2 = am->random_order[p2];
    if (id1 < 0 || (size_t)id1 >= am->entries_cap) {
        LOG_WARN("addrman", "swap_random: corrupt id1=%d entries_cap=%zu", id1, am->entries_cap);
        return;
    }
    if (id2 < 0 || (size_t)id2 >= am->entries_cap) {
        LOG_WARN("addrman", "swap_random: corrupt id2=%d entries_cap=%zu", id2, am->entries_cap);
        return;
    }
    am->entries[id1].random_pos = (int)p2;
    am->entries[id2].random_pos = (int)p1;
    am->random_order[p1] = id2;
    am->random_order[p2] = id1;
}

struct addr_info *addrman_find_addr_locked(struct addr_man *am,
                                           const struct net_addr *addr, int *pnId)
{
    if (!am || !addr || !am->entries)
        LOG_NULL("addrman", "find_addr: bad args");

    if (am->idx && am->idx_slots) {
        int id = addr_index_lookup(am, addr);
        if (id < 0)
            return NULL;
        /* Defensive: a valid index always points at a matching used entry;
         * treat any mismatch as absent rather than returning a stale row. */
        if (id >= 0 && (size_t)id < am->entries_cap &&
            am->entries[id].used &&
            net_addr_eq(&am->entries[id].addr.svc.addr, addr)) {
            if (pnId) *pnId = id;
            return &am->entries[id];
        }
        return NULL;
    }

    /* Fallback: linear scan when the index is unavailable (OOM at init). */
    int id = addr_scan_id(am, addr);
    if (id < 0)
        return NULL;
    if (pnId) *pnId = id;
    return &am->entries[id];
}

static struct addr_info *create_entry(struct addr_man *am,
                                       const struct net_address *addr,
                                       const struct net_addr *source,
                                       int *pnId)
{
    int id = am->id_count;
    if ((size_t)id >= am->entries_cap) {
        size_t new_cap = am->entries_cap * 2;
        if (new_cap > ADDRMAN_MAX_ENTRIES) new_cap = ADDRMAN_MAX_ENTRIES;
        if ((size_t)id >= new_cap) LOG_NULL("addrman", "entry id=%d exceeds max capacity=%zu", id, new_cap);
        struct addr_info *p = zcl_realloc(am->entries,
                                       new_cap * sizeof(struct addr_info), "addr_entries");
        if (!p) LOG_NULL("addrman", "realloc failed for entries new_cap=%zu", new_cap);
        memset(p + am->entries_cap, 0,
               (new_cap - am->entries_cap) * sizeof(struct addr_info));
        am->entries = p;
        am->entries_cap = new_cap;
    }
    /* Reserve BEFORE bumping id_count: a rebuild scans entries[0..id_count),
     * so the not-yet-written new entry stays out and insert_raw adds it once. */
    addr_index_reserve_one(am);
    am->id_count++;

    struct addr_info *info = &am->entries[id];
    memset(info, 0, sizeof(*info));
    info->addr = *addr;
    info->source = *source;
    info->last_success = 0;
    info->last_try = 0;
    info->attempts = 0;
    info->ref_count = 0;
    info->in_tried = false;
    info->random_pos = (int)am->random_size;
    info->used = true;
    addrman_random_push_locked(am, id);
    addr_index_insert_raw(am, &info->addr.svc.addr, id);

    if (pnId) *pnId = id;
    return info;
}

static void delete_entry(struct addr_man *am, int nId)
{
    struct addr_info *info = &am->entries[nId];
    /* Drop this address from the index BEFORE clearing `used` (the key still
     * lives in info->addr). Keeps the index in lock-step with `used`. */
    addr_index_remove(am, &info->addr.svc.addr);
    swap_random(am, (unsigned int)info->random_pos,
                (unsigned int)(am->random_size - 1));
    am->random_size--;
    info->used = false;
    am->new_count--;
}

static void clear_new(struct addr_man *am, int nUBucket, int nUBucketPos)
{
    if (am->vvNew[nUBucket][nUBucketPos] != -1) {
        int nIdDelete = am->vvNew[nUBucket][nUBucketPos];
        if (nIdDelete < 0 || (size_t)nIdDelete >= am->entries_cap) {
            am->vvNew[nUBucket][nUBucketPos] = -1;
            return;
        }
        struct addr_info *info = &am->entries[nIdDelete];
        info->ref_count--;
        am->vvNew[nUBucket][nUBucketPos] = -1;
        if (info->ref_count == 0)
            delete_entry(am, nIdDelete);
    }
}

static void make_tried(struct addr_man *am, struct addr_info *info, int nId)
{
    for (int bucket = 0; bucket < ADDRMAN_NEW_BUCKET_COUNT; bucket++) {
        int pos = addr_info_get_bucket_position(info, &am->nKey, true, bucket);
        if (am->vvNew[bucket][pos] == nId) {
            am->vvNew[bucket][pos] = -1;
            info->ref_count--;
        }
    }
    am->new_count--;

    int nKBucket = addr_info_get_tried_bucket(info, &am->nKey);
    int nKBucketPos = addr_info_get_bucket_position(info, &am->nKey, false,
                                                     nKBucket);

    if (am->vvTried[nKBucket][nKBucketPos] != -1) {
        int nIdEvict = am->vvTried[nKBucket][nKBucketPos];
        if (nIdEvict < 0 || (size_t)nIdEvict >= am->entries_cap) {
            am->vvTried[nKBucket][nKBucketPos] = -1;
        } else {
            struct addr_info *old = &am->entries[nIdEvict];
            old->in_tried = false;
            am->vvTried[nKBucket][nKBucketPos] = -1;
            am->tried_count--;

            int nUBucket = addr_info_get_new_bucket(old, &am->nKey, &old->source);
            int nUBucketPos = addr_info_get_bucket_position(old, &am->nKey, true,
                                                             nUBucket);
            /* Eclipse attack mitigation: only evict the occupant of the
             * new bucket slot if it's "terrible" (stale/failed) or if
             * the evicted tried entry has fewer references. This prevents
             * an attacker from cascading evictions through tried→new to
             * purge legitimate addresses from the new table. */
            int existing_new_id = am->vvNew[nUBucket][nUBucketPos];
            if (existing_new_id != -1 &&
                existing_new_id >= 0 &&
                (size_t)existing_new_id < am->entries_cap) {
                struct addr_info *occupant = &am->entries[existing_new_id];
                if (occupant->used &&
                    !addr_info_is_terrible(occupant, GetAdjustedTime()) &&
                    occupant->ref_count <= 1) {
                    /* Occupant is still good — don't evict. Place the
                     * tried-evicted entry in a different new bucket. */
                    bool placed = false;
                    for (int attempt = 1; attempt < 8 && !placed; attempt++) {
                        unsigned char salt[4];
                        memcpy(salt, &attempt, 4);
                        /* Try alternative buckets derived from source */
                        int alt_bucket = (nUBucket + attempt * 97) %
                                         ADDRMAN_NEW_BUCKET_COUNT;
                        int alt_pos = addr_info_get_bucket_position(
                            old, &am->nKey, true, alt_bucket);
                        if (am->vvNew[alt_bucket][alt_pos] == -1) {
                            old->ref_count = 1;
                            am->vvNew[alt_bucket][alt_pos] = nIdEvict;
                            am->new_count++;
                            placed = true;
                        }
                    }
                    if (!placed) {
                        /* Last resort: evict the occupant anyway */
                        clear_new(am, nUBucket, nUBucketPos);
                        old->ref_count = 1;
                        am->vvNew[nUBucket][nUBucketPos] = nIdEvict;
                        am->new_count++;
                    }
                    goto place_tried;
                }
            }
            clear_new(am, nUBucket, nUBucketPos);
            old->ref_count = 1;
            am->vvNew[nUBucket][nUBucketPos] = nIdEvict;
            am->new_count++;
        }
    }

place_tried:
    am->vvTried[nKBucket][nKBucketPos] = nId;
    am->tried_count++;
    info->in_tried = true;
}

bool addrman_add(struct addr_man *am, const struct net_address *addr,
                 const struct net_addr *source, int64_t time_penalty)
{
    /* Fail-closed on a torn-down/invalid addrman — the SAME condition find_addr
     * guards. A detached message-cycle thread can still reach addrman_add after
     * addrman_free() has nulled am->entries and destroyed am->cs during
     * shutdown; without this guard find_addr returns NULL ("find_addr: bad
     * args") but addrman_add falls through to create_entry and dereferences the
     * freed am->entries (a use-after-free SIGSEGV). This must run BEFORE
     * zcl_mutex_lock so we never lock an already-destroyed mutex. */
    if (!am || !addr || !am->entries)
        LOG_FAIL("addrman", "addrman_add: torn-down/invalid addrman (am=%p entries=%p)",
                 (const void *)am, (const void *)(am ? am->entries : NULL));

    if (!net_addr_is_routable(&addr->svc.addr))
        return false;

    zcl_mutex_lock(&am->cs);

    bool fNew = false;
    int nId;
    struct addr_info *pinfo = addrman_find_addr_locked(am, &addr->svc.addr, &nId);

    if (pinfo) {
        int64_t nUpdateInterval = 24 * 60 * 60;
        bool fCurrentlyOnline = (GetAdjustedTime() - (int64_t)addr->nTime < 24 * 60 * 60);
        if (fCurrentlyOnline)
            nUpdateInterval = 60 * 60;

        if (addr->nTime && (!pinfo->addr.nTime ||
            (int64_t)pinfo->addr.nTime < (int64_t)addr->nTime - nUpdateInterval - time_penalty)) {
            int64_t t = (int64_t)addr->nTime - time_penalty;
            pinfo->addr.nTime = (uint32_t)(t > 0 ? t : 0);
        }

        pinfo->addr.nServices |= addr->nServices;

        if (!addr->nTime || (pinfo->addr.nTime && addr->nTime <= pinfo->addr.nTime)) {
            zcl_mutex_unlock(&am->cs);
            return false;
        }
        if (pinfo->in_tried) {
            zcl_mutex_unlock(&am->cs);
            return false;
        }
        if (pinfo->ref_count == ADDRMAN_NEW_BUCKETS_PER_ADDRESS) {
            zcl_mutex_unlock(&am->cs);
            return false;
        }

        int nFactor = 1;
        for (int n = 0; n < pinfo->ref_count; n++)
            nFactor *= 2;
        if (nFactor > 1 && (GetRandInt(nFactor) != 0)) {
            zcl_mutex_unlock(&am->cs);
            return false;
        }
    } else {
        pinfo = create_entry(am, addr, source, &nId);
        if (!pinfo) {
            zcl_mutex_unlock(&am->cs);
            LOG_FAIL("addrman", "create_entry failed for new address");
        }
        int64_t t = (int64_t)pinfo->addr.nTime - time_penalty;
        pinfo->addr.nTime = (uint32_t)(t > 0 ? t : 0);
        am->new_count++;
        fNew = true;
    }

    bool inserted = false;
    int nUBucket = addr_info_get_new_bucket(pinfo, &am->nKey, source);
    for (int attempt = 0; attempt < ADDRMAN_NEW_BUCKETS_PER_ADDRESS; attempt++) {
        int bucket = (nUBucket + attempt * 97) % ADDRMAN_NEW_BUCKET_COUNT;
        int pos = addr_info_get_bucket_position(pinfo, &am->nKey, true, bucket);
        if (am->vvNew[bucket][pos] == nId) {
            inserted = true;
            break;
        }

        bool fInsert = am->vvNew[bucket][pos] == -1;
        if (!fInsert) {
            int eId = am->vvNew[bucket][pos];
            if (eId < 0 || (size_t)eId >= am->entries_cap) {
                am->vvNew[bucket][pos] = -1;
                fInsert = true;
            } else {
                struct addr_info *existing = &am->entries[eId];
                if (!existing->used ||
                    addr_info_is_terrible(existing, GetAdjustedTime()) ||
                    (existing->ref_count > 1 && pinfo->ref_count == 0))
                    fInsert = true;
            }
        }
        if (!fInsert)
            continue;

        clear_new(am, bucket, pos);
        pinfo->ref_count++;
        am->vvNew[bucket][pos] = nId;
        inserted = true;
        break;
    }
    if (!inserted && pinfo->ref_count == 0)
        delete_entry(am, nId);

    zcl_mutex_unlock(&am->cs);
    return fNew;
}

void addrman_good(struct addr_man *am, const struct net_service *addr,
                  int64_t nTime)
{
    zcl_mutex_lock(&am->cs);

    int nId;
    struct addr_info *pinfo = addrman_find_addr_locked(am, &addr->addr, &nId);
    if (!pinfo || !net_service_eq(&pinfo->addr.svc, addr)) {
        zcl_mutex_unlock(&am->cs);
        return;
    }

    pinfo->last_success = nTime;
    pinfo->last_try = nTime;
    pinfo->attempts = 0;

    if (pinfo->in_tried) {
        zcl_mutex_unlock(&am->cs);
        return;
    }

    int nRnd = GetRandInt(ADDRMAN_NEW_BUCKET_COUNT);
    int nUBucket = -1;
    for (int n = 0; n < ADDRMAN_NEW_BUCKET_COUNT; n++) {
        int nB = (n + nRnd) % ADDRMAN_NEW_BUCKET_COUNT;
        int nBpos = addr_info_get_bucket_position(pinfo, &am->nKey, true, nB);
        if (am->vvNew[nB][nBpos] == nId) {
            nUBucket = nB;
            break;
        }
    }

    if (nUBucket == -1) {
        zcl_mutex_unlock(&am->cs);
        return;
    }

    make_tried(am, pinfo, nId);
    zcl_mutex_unlock(&am->cs);
}

void addrman_attempt(struct addr_man *am, const struct net_service *addr,
                     int64_t nTime)
{
    zcl_mutex_lock(&am->cs);
    int nId;
    struct addr_info *pinfo = addrman_find_addr_locked(am, &addr->addr, &nId);
    if (!pinfo || !net_service_eq(&pinfo->addr.svc, addr)) {
        zcl_mutex_unlock(&am->cs);
        return;
    }
    pinfo->last_try = nTime;
    pinfo->attempts++;
    zcl_mutex_unlock(&am->cs);
}

bool addrman_select(struct addr_man *am, bool new_only,
                    struct addr_info *result)
{
    zcl_mutex_lock(&am->cs);

    if (am->random_size == 0) {
        zcl_mutex_unlock(&am->cs);
        LOG_FAIL("addrman", "select failed: address table is empty");
    }
    if (new_only && am->new_count == 0) {
        zcl_mutex_unlock(&am->cs);
        LOG_FAIL("addrman", "select failed: no new addresses available");
    }

    int64_t nNow = GetAdjustedTime();

    if (!new_only && am->tried_count > 0 &&
        (am->new_count == 0 || GetRandInt(2) == 0)) {
        double fChanceFactor = 1.0;
        for (int i = 0; i < 200000; i++) {
            int nKBucket = GetRandInt(ADDRMAN_TRIED_BUCKET_COUNT);
            int nKBucketPos = GetRandInt(ADDRMAN_BUCKET_SIZE);
            if (am->vvTried[nKBucket][nKBucketPos] == -1 &&
                !addrman_find_occupied_slot(&am->vvTried[0][0],
                                            ADDRMAN_TRIED_BUCKET_COUNT,
                                            nKBucket,
                                            nKBucketPos,
                                            &nKBucket,
                                            &nKBucketPos)) {
                zcl_mutex_unlock(&am->cs);
                LOG_FAIL("addrman", "select exhausted tried bucket search after full table scan");
                return false;
            }
            int nId = am->vvTried[nKBucket][nKBucketPos];
            if (nId < 0 || (size_t)nId >= am->entries_cap) {
                am->vvTried[nKBucket][nKBucketPos] = -1; /* repair */
                fChanceFactor *= 1.2;
                continue;
            }
            struct addr_info *info = &am->entries[nId];
            double chance = fChanceFactor * addr_info_get_chance(am, info, nNow);
            if (GetRandInt(1 << 30) < chance * (double)(1 << 30)) {
                *result = *info;
                zcl_mutex_unlock(&am->cs);
                return true;
            }
            fChanceFactor *= 1.2;
        }
    } else {
        double fChanceFactor = 1.0;
        for (int i = 0; i < 200000; i++) {
            int nUBucket = GetRandInt(ADDRMAN_NEW_BUCKET_COUNT);
            int nUBucketPos = GetRandInt(ADDRMAN_BUCKET_SIZE);
            if (am->vvNew[nUBucket][nUBucketPos] == -1 &&
                !addrman_find_occupied_slot(&am->vvNew[0][0],
                                            ADDRMAN_NEW_BUCKET_COUNT,
                                            nUBucket,
                                            nUBucketPos,
                                            &nUBucket,
                                            &nUBucketPos)) {
                zcl_mutex_unlock(&am->cs);
                LOG_FAIL("addrman", "select exhausted new bucket search after full table scan");
                return false;
            }
            int nId = am->vvNew[nUBucket][nUBucketPos];
            if (nId < 0 || (size_t)nId >= am->entries_cap) {
                am->vvNew[nUBucket][nUBucketPos] = -1; /* repair */
                fChanceFactor *= 1.2;
                continue;
            }
            struct addr_info *info = &am->entries[nId];
            double chance = fChanceFactor * addr_info_get_chance(am, info, nNow);
            if (GetRandInt(1 << 30) < chance * (double)(1 << 30)) {
                *result = *info;
                zcl_mutex_unlock(&am->cs);
                return true;
            }
            fChanceFactor *= 1.2;
        }
    }

    /* Fallback for sparse bucket layouts: if randomized bucket probing
     * failed, return the first eligible address from the random-order set
     * instead of spuriously reporting an empty addrman. */
    if (am->random_size > 0) {
        size_t start = (size_t)GetRandInt((int)am->random_size);
        for (size_t n = 0; n < am->random_size; n++) {
            int nId = am->random_order[(start + n) % am->random_size];
            if (nId < 0 || (size_t)nId >= am->entries_cap)
                continue;
            struct addr_info *info = &am->entries[nId];
            if (!info->used)
                continue;
            if (new_only && info->in_tried)
                continue;
            *result = *info;
            zcl_mutex_unlock(&am->cs);
            return true;
        }
    }

    zcl_mutex_unlock(&am->cs);
    LOG_FAIL("addrman", "select failed: no eligible address found after full scan");
}

void addrman_connected(struct addr_man *am, const struct net_service *addr,
                       int64_t nTime)
{
    zcl_mutex_lock(&am->cs);
    int nId;
    struct addr_info *pinfo = addrman_find_addr_locked(am, &addr->addr, &nId);
    if (!pinfo || !net_service_eq(&pinfo->addr.svc, addr)) {
        zcl_mutex_unlock(&am->cs);
        return;
    }
    int64_t nUpdateInterval = 20 * 60;
    if (nTime - (int64_t)pinfo->addr.nTime > nUpdateInterval)
        pinfo->addr.nTime = (uint32_t)nTime;
    zcl_mutex_unlock(&am->cs);
}

size_t addrman_get_addr(struct addr_man *am, struct net_address *out,
                        size_t max_out)
{
    zcl_mutex_lock(&am->cs);
    size_t nNodes = ADDRMAN_GETADDR_MAX_PCT * am->random_size / 100;
    if (nNodes > ADDRMAN_GETADDR_MAX) nNodes = ADDRMAN_GETADDR_MAX;
    if (nNodes > max_out) nNodes = max_out;

    size_t count = 0;
    int64_t nNow = GetAdjustedTime();
    for (size_t n = 0; n < am->random_size && count < nNodes; n++) {
        int nRndPos = GetRandInt((int)(am->random_size - n)) + (int)n;
        swap_random(am, (unsigned int)n, (unsigned int)nRndPos);
        int rid = am->random_order[n];
        if (rid < 0 || (size_t)rid >= am->entries_cap) continue;
        struct addr_info *ai = &am->entries[rid];
        if (!addr_info_is_terrible(ai, nNow))
            out[count++] = ai->addr;
    }

    zcl_mutex_unlock(&am->cs);
    return count;
}

int addrman_consistency_check(const struct addr_man *am,
                              char *err_buf, size_t err_cap)
{
#define CC_ERR(fmt, ...) do { \
    if (err_buf && err_cap > 0) \
        snprintf(err_buf, err_cap, fmt __VA_OPT__(,) __VA_ARGS__); \
    return -1; \
} while (0)

    /* 1. Verify new table: every non-(-1) slot points to a valid, used,
     *    non-tried entry with ref_count > 0. */
    for (int b = 0; b < ADDRMAN_NEW_BUCKET_COUNT; b++) {
        for (int p = 0; p < ADDRMAN_BUCKET_SIZE; p++) {
            int id = am->vvNew[b][p];
            if (id == -1) continue;
            if (id < 0 || (size_t)id >= am->entries_cap)
                CC_ERR("new[%d][%d]: id=%d out of range (cap=%zu)",
                       b, p, id, am->entries_cap);
            const struct addr_info *info = &am->entries[id];
            if (!info->used)
                CC_ERR("new[%d][%d]: id=%d not used", b, p, id);
            if (info->in_tried)
                CC_ERR("new[%d][%d]: id=%d is in tried table", b, p, id);
            if (info->ref_count <= 0)
                CC_ERR("new[%d][%d]: id=%d ref_count=%d <= 0",
                       b, p, id, info->ref_count);
        }
    }

    /* 2. Verify tried table: every non-(-1) slot points to a valid, used,
     *    in_tried entry. */
    int tried_refs = 0;
    for (int b = 0; b < ADDRMAN_TRIED_BUCKET_COUNT; b++) {
        for (int p = 0; p < ADDRMAN_BUCKET_SIZE; p++) {
            int id = am->vvTried[b][p];
            if (id == -1) continue;
            if (id < 0 || (size_t)id >= am->entries_cap)
                CC_ERR("tried[%d][%d]: id=%d out of range", b, p, id);
            const struct addr_info *info = &am->entries[id];
            if (!info->used)
                CC_ERR("tried[%d][%d]: id=%d not used", b, p, id);
            if (!info->in_tried)
                CC_ERR("tried[%d][%d]: id=%d not marked in_tried",
                       b, p, id);
            tried_refs++;
        }
    }

    /* 3. Verify counts match. */
    if (tried_refs != am->tried_count)
        CC_ERR("tried_count mismatch: table has %d, tracked %d",
               tried_refs, am->tried_count);

    /* 4. Verify ref_count sums: each new-table entry's ref_count should
     *    equal the number of new bucket slots pointing to it. */
    for (int i = 0; i < am->id_count; i++) {
        const struct addr_info *info = &am->entries[i];
        if (!info->used || info->in_tried) continue;
        int actual_refs = 0;
        for (int b = 0; b < ADDRMAN_NEW_BUCKET_COUNT; b++)
            for (int p = 0; p < ADDRMAN_BUCKET_SIZE; p++)
                if (am->vvNew[b][p] == i)
                    actual_refs++;
        if (actual_refs != info->ref_count)
            CC_ERR("entry %d: ref_count=%d but %d bucket refs",
                   i, info->ref_count, actual_refs);
    }

    /* 5. Verify no duplicate entries in buckets. */
    for (int b = 0; b < ADDRMAN_TRIED_BUCKET_COUNT; b++) {
        for (int p1 = 0; p1 < ADDRMAN_BUCKET_SIZE; p1++) {
            if (am->vvTried[b][p1] == -1) continue;
            for (int p2 = p1 + 1; p2 < ADDRMAN_BUCKET_SIZE; p2++) {
                if (am->vvTried[b][p1] == am->vvTried[b][p2])
                    CC_ERR("tried[%d]: duplicate id=%d at pos %d and %d",
                           b, am->vvTried[b][p1], p1, p2);
            }
        }
    }

    /* 6. Verify the O(1) address index agrees with `entries`. */
    if (addrman_index_verify(am, err_buf, err_cap) != 0)
        return -1;

#undef CC_ERR
    return 0;
}

int addrman_index_verify(const struct addr_man *am,
                         char *err_buf, size_t err_cap)
{
#define IV_ERR(fmt, ...) do { \
    if (err_buf && err_cap > 0) \
        snprintf(err_buf, err_cap, fmt __VA_OPT__(,) __VA_ARGS__); \
    return -1; \
} while (0)

    /* NULL index == OOM fallback to linear scan: nothing to verify. */
    if (!am->idx || am->idx_slots == 0)
        return 0;

    /* Every used entry resolves through the index to the same id a
     * brute-force scan would return. */
    size_t used = 0;
    for (int i = 0; i < am->id_count; i++) {
        if (!am->entries[i].used)
            continue;
        used++;
        int li = addr_index_lookup(am, &am->entries[i].addr.svc.addr);
        int si = addr_scan_id(am, &am->entries[i].addr.svc.addr);
        if (li != si)
            IV_ERR("index/scan disagree for entry %d: index=%d scan=%d",
                   i, li, si);
    }
    if (used != am->idx_live)
        IV_ERR("idx_live=%zu but %zu used entries", am->idx_live, used);

    /* Every live slot points at a used entry whose address matches its key. */
    for (size_t s = 0; s < am->idx_slots; s++) {
        const struct addr_index_slot *e = &am->idx[s];
        if (e->state != 1)
            continue;
        if (e->id < 0 || (size_t)e->id >= am->entries_cap)
            IV_ERR("index slot %zu: id=%d out of range (cap=%zu)",
                   s, e->id, am->entries_cap);
        if (!am->entries[e->id].used)
            IV_ERR("index slot %zu: id=%d not used", s, e->id);
        if (!net_addr_eq(&e->key, &am->entries[e->id].addr.svc.addr))
            IV_ERR("index slot %zu: id=%d key mismatch", s, e->id);
    }

#undef IV_ERR
    return 0;
}

void addrman_get_bucket_stats(const struct addr_man *am,
                              struct addrman_bucket_stats *stats)
{
    memset(stats, 0, sizeof(*stats));

    for (int b = 0; b < ADDRMAN_NEW_BUCKET_COUNT; b++) {
        int fill = 0;
        for (int p = 0; p < ADDRMAN_BUCKET_SIZE; p++)
            if (am->vvNew[b][p] != -1) fill++;
        stats->new_occupied += fill;
        if (fill > 0) stats->new_buckets_nonempty++;
        if (fill > stats->max_new_bucket_fill)
            stats->max_new_bucket_fill = fill;
    }

    for (int b = 0; b < ADDRMAN_TRIED_BUCKET_COUNT; b++) {
        int fill = 0;
        for (int p = 0; p < ADDRMAN_BUCKET_SIZE; p++)
            if (am->vvTried[b][p] != -1) fill++;
        stats->tried_occupied += fill;
        if (fill > 0) stats->tried_buckets_nonempty++;
        if (fill > stats->max_tried_bucket_fill)
            stats->max_tried_bucket_fill = fill;
    }
}
