/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Block download manager — coordinates parallel block downloads.
 * Lock-free reads where possible, mutex for writes. */

#include "platform/time_compat.h"
#include "net/download.h"
#include "event/event.h"
#include "sync/sync_state.h"
#include "util/log_macros.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include "util/safe_alloc.h"

#define INITIAL_SLOTS 2048
#define INITIAL_QUEUE 4096

/* ── Dynamic IBD-aware limits ─────────────────────────────────── */

static bool dl_is_ibd(void)
{
    enum sync_state st = sync_get_state();
    return st == SYNC_HEADERS_DOWNLOAD ||
           st == SYNC_BLOCKS_DOWNLOAD ||
           st == SYNC_CONNECTING_BLOCKS;
}

size_t dl_get_max_in_flight_total(void)
{
    return dl_is_ibd() ? DL_MAX_IN_FLIGHT_TOTAL_IBD
                       : DL_MAX_IN_FLIGHT_TOTAL;
}

size_t dl_get_max_in_flight_per_peer(void)
{
    return dl_is_ibd() ? DL_MAX_IN_FLIGHT_PER_PEER_IBD
                       : DL_MAX_IN_FLIGHT_PER_PEER;
}

int dl_get_request_timeout_secs(void)
{
    return dl_is_ibd() ? DL_REQUEST_TIMEOUT_SECS_IBD
                       : DL_REQUEST_TIMEOUT_SECS;
}

static int64_t dl_peer_avoid_deadline(int64_t now)
{
    int cooldown = dl_get_request_timeout_secs();
    if (cooldown < 1)
        cooldown = 1;
    if (cooldown > DL_PEER_AVOID_COOLDOWN_SECS)
        cooldown = DL_PEER_AVOID_COOLDOWN_SECS;
    return now + cooldown;
}

static void dl_generation_advance(uint64_t *generation)
{
    (*generation)++;
    if (*generation == 0)
        *generation = 1;
}

static bool dl_assign_result_is_parkable(int result)
{
    return result == DL_ASSIGN_NO_QUEUE ||
           result == DL_ASSIGN_PEER_WINDOW_FULL ||
           result == DL_ASSIGN_GLOBAL_WINDOW_FULL ||
           result == DL_ASSIGN_HISTORY_THROTTLED ||
           result == DL_ASSIGN_PEER_AVOID_COOLDOWN;
}

static uint64_t dl_assign_dependency_generation(
    const struct download_manager *dm, int result)
{
    if (result == DL_ASSIGN_NO_QUEUE ||
        result == DL_ASSIGN_PEER_AVOID_COOLDOWN)
        return dm->queue_generation;
    return dm->capacity_generation;
}

const char *dl_assign_result_name(int result)
{
    switch (result) {
    case DL_ASSIGN_NONE:               return "none";
    case DL_ASSIGN_ASSIGNED:           return "assigned";
    case DL_ASSIGN_NO_QUEUE:           return "no_queue";
    case DL_ASSIGN_MAX_ZERO:           return "max_zero";
    case DL_ASSIGN_PEER_WINDOW_FULL:   return "peer_window_full";
    case DL_ASSIGN_GLOBAL_WINDOW_FULL: return "global_window_full";
    case DL_ASSIGN_HISTORY_THROTTLED:  return "history_throttled";
    case DL_ASSIGN_NO_SLOT:            return "no_slot";
    case DL_ASSIGN_PEER_AVOID_COOLDOWN:return "peer_avoid_cooldown";
    default:                           return "unknown";
    }
}

/* FNV-1a hash for uint256 → slot index */
static size_t hash_slot(const struct uint256 *h, size_t mask)
{
    uint64_t fnv = 14695981039346656037ULL;
    for (int i = 0; i < 32; i++) {
        fnv ^= h->data[i];
        fnv *= 1099511628211ULL;
    }
    return (size_t)(fnv & mask);
}

#define DL_QUEUE_MAX_CAP 65536
#define INITIAL_QSET_SLOTS 8192

void dl_init(struct download_manager *dm)
{
    memset(dm, 0, sizeof(*dm));
    zcl_mutex_init(&dm->cs);
    dm->queue_generation = 1;
    dm->capacity_generation = 1;
    dm->num_slots = INITIAL_SLOTS;
    dm->slots = zcl_calloc(dm->num_slots, sizeof(struct dl_in_flight), "dl_slots");
    dm->queue_cap = INITIAL_QUEUE;
    dm->queue = zcl_malloc(dm->queue_cap * sizeof(struct uint256), "dl_queue");
    dm->queue_heights = zcl_malloc(dm->queue_cap * sizeof(int32_t), "dl_queue_heights");
    dm->queue_avoid_peers =
        zcl_calloc(dm->queue_cap, sizeof(uint32_t), "dl_queue_avoid_peers");
    dm->queue_avoid_until =
        zcl_calloc(dm->queue_cap, sizeof(int64_t), "dl_queue_avoid_until");
    dm->queue_classes =
        zcl_calloc(dm->queue_cap, sizeof(*dm->queue_classes), "dl_queue_classes");
    dm->qset_slots = INITIAL_QSET_SLOTS;
    dm->qset = zcl_calloc(dm->qset_slots, sizeof(struct dl_queued_key), "dl_qset");
    if (!dm->slots || !dm->queue || !dm->queue_heights ||
        !dm->queue_avoid_peers || !dm->queue_avoid_until ||
        !dm->queue_classes || !dm->qset) {
        free(dm->slots); free(dm->queue); free(dm->queue_heights);
        free(dm->queue_avoid_peers); free(dm->queue_avoid_until);
        free(dm->queue_classes); free(dm->qset);
        dm->slots = NULL; dm->queue = NULL; dm->queue_heights = NULL;
        dm->queue_avoid_peers = NULL; dm->queue_avoid_until = NULL;
        dm->queue_classes = NULL;
        dm->qset = NULL;
        dm->num_slots = 0; dm->queue_cap = 0; dm->qset_slots = 0;
    }
}

void dl_free(struct download_manager *dm)
{
    free(dm->slots);
    free(dm->queue);
    free(dm->queue_heights);
    free(dm->queue_avoid_peers);
    free(dm->queue_avoid_until);
    free(dm->queue_classes);
    free(dm->qset);
    dm->slots = NULL;
    dm->queue = NULL;
    dm->queue_heights = NULL;
    dm->queue_avoid_peers = NULL;
    dm->queue_avoid_until = NULL;
    dm->queue_classes = NULL;
    dm->qset = NULL;
}

/* ── Queued-hash membership set ───────────────────────────────────
 * Open addressing, linear probe, tombstoned deletes. The queue array
 * is the source of truth; the set only answers "is this hash queued?"
 * in O(1) so bulk enqueues stop scanning the whole queue per item.
 * All helpers require the caller to hold dm->cs. */

static bool qset_contains(const struct download_manager *dm,
                          const struct uint256 *hash)
{
    if (!dm->qset || dm->qset_slots == 0) return false;
    size_t mask = dm->qset_slots - 1;
    size_t idx = hash_slot(hash, mask);
    for (size_t i = 0; i < dm->qset_slots; i++) {
        const struct dl_queued_key *e = &dm->qset[(idx + i) & mask];
        if (e->state == 0) return false;            /* virgin: chain end */
        if (e->state == 1 && uint256_eq(&e->hash, hash)) return true;
    }
    return false;
}

/* Insert without duplicate check (callers check qset_contains first).
 * Reuses tombstones. Never fails once capacity is ensured. */
static void qset_insert_raw(struct download_manager *dm,
                            const struct uint256 *hash)
{
    size_t mask = dm->qset_slots - 1;
    size_t idx = hash_slot(hash, mask);
    for (size_t i = 0; i < dm->qset_slots; i++) {
        struct dl_queued_key *e = &dm->qset[(idx + i) & mask];
        if (e->state != 1) {
            if (e->state == 2) dm->qset_tombs--;
            e->hash = *hash;
            e->state = 1;
            dm->qset_live++;
            return;
        }
    }
}

/* Rebuild the set from the queue array (drops tombstones), growing to
 * `new_slots` (power of 2). Keeps the old table on alloc failure —
 * correctness is unaffected, only probe lengths suffer. */
static void qset_rebuild(struct download_manager *dm, size_t new_slots)
{
    struct dl_queued_key *ns =
        zcl_calloc(new_slots, sizeof(struct dl_queued_key), "dl_qset");
    if (!ns) return;
    free(dm->qset);
    dm->qset = ns;
    dm->qset_slots = new_slots;
    dm->qset_live = 0;
    dm->qset_tombs = 0;
    for (size_t i = 0; i < dm->queue_len; i++)
        qset_insert_raw(dm, &dm->queue[i]);
}

/* Ensure room for one more live entry at < 50% combined load. */
static void qset_reserve_one(struct download_manager *dm)
{
    if (!dm->qset || dm->qset_slots == 0) return;
    if ((dm->qset_live + dm->qset_tombs + 1) * 2 < dm->qset_slots) return;
    size_t want = dm->qset_slots;
    if ((dm->qset_live + 1) * 2 >= want)
        want *= 2;                  /* genuinely full: grow */
    /* else: tombstone-heavy — rebuild at same size */
    qset_rebuild(dm, want);
}

/* Ensure room for `n_more` additional live entries at < 50% combined
 * load, in at most ONE rebuild up-front. Bulk callers MUST reserve
 * before staging inserts: qset_rebuild repopulates from dm->queue
 * only, so a rebuild fired mid-batch (by a per-insert reserve) wipes
 * every staged-but-not-yet-merged hash from the set — dedup breaks,
 * blocks download twice, and the duplicate in-flight slots leak
 * num_active. Same reason dl_queue_push reserves BEFORE its queue
 * insertion. */
static void qset_reserve_n(struct download_manager *dm, size_t n_more)
{
    if (!dm->qset || dm->qset_slots == 0) return;
    /* Live entries are bounded by queue cap + one staged batch; clamp a
     * pathological request so the doubling below cannot overflow. Past
     * the clamp the set degrades to silent dedup misses, never UB. */
    if (n_more > (size_t)DL_QUEUE_MAX_CAP * 2)
        n_more = (size_t)DL_QUEUE_MAX_CAP * 2;
    size_t want = dm->qset_slots;
    while ((dm->qset_live + n_more + 1) * 2 >= want)
        want *= 2;
    if (want == dm->qset_slots &&
        (dm->qset_live + dm->qset_tombs + n_more + 1) * 2 < dm->qset_slots)
        return;             /* enough live+tombstone headroom already */
    qset_rebuild(dm, want);
}

static void qset_remove(struct download_manager *dm,
                        const struct uint256 *hash)
{
    if (!dm->qset || dm->qset_slots == 0) return;
    size_t mask = dm->qset_slots - 1;
    size_t idx = hash_slot(hash, mask);
    for (size_t i = 0; i < dm->qset_slots; i++) {
        struct dl_queued_key *e = &dm->qset[(idx + i) & mask];
        if (e->state == 0) return;
        if (e->state == 1 && uint256_eq(&e->hash, hash)) {
            e->state = 2;
            dm->qset_live--;
            dm->qset_tombs++;
            return;
        }
    }
}

static void qset_clear(struct download_manager *dm)
{
    if (!dm->qset || dm->qset_slots == 0) return;
    memset(dm->qset, 0, dm->qset_slots * sizeof(struct dl_queued_key));
    dm->qset_live = 0;
    dm->qset_tombs = 0;
}

/* Expand queue capacity. Returns true on success. Caller holds mutex.
 * Hitting the max cap is NORMAL during deep IBD (millions of bodies
 * missing, queue bounded) — it is handled by evict/reject in
 * dl_queue_push, not logged: the old LOG_FAIL here emitted tens of
 * lines per second and drowned the journal. */
static bool dl_queue_grow(struct download_manager *dm)
{
    if (dm->queue_cap >= DL_QUEUE_MAX_CAP)
        return false; // raw-return-ok:normal-bounded-queue-backpressure
    if (dm->queue_cap == 0)
        return false; // raw-return-ok:dl_init-oom-doubling-0-spins-forever
    size_t new_cap = dm->queue_cap * 2;
    struct uint256 *nq =
        zcl_malloc(new_cap * sizeof(struct uint256), "dl_queue");
    int32_t *nh =
        zcl_malloc(new_cap * sizeof(int32_t), "dl_queue_heights");
    uint32_t *nap =
        zcl_calloc(new_cap, sizeof(uint32_t), "dl_queue_avoid_peers");
    int64_t *nau =
        zcl_calloc(new_cap, sizeof(int64_t), "dl_queue_avoid_until");
    enum dl_work_class *nc =
        zcl_calloc(new_cap, sizeof(*nc), "dl_queue_classes");
    if (!nq || !nh || !nap || !nau || !nc) {
        free(nq);
        free(nh);
        free(nap);
        free(nau);
        free(nc);
        LOG_FAIL("net", "dl_queue_grow: realloc failed for new_cap=%zu", new_cap);
    }

    if (dm->queue_len > 0) {
        memcpy(nq, dm->queue, dm->queue_len * sizeof(*nq));
        memcpy(nh, dm->queue_heights, dm->queue_len * sizeof(*nh));
        memcpy(nap, dm->queue_avoid_peers, dm->queue_len * sizeof(*nap));
        memcpy(nau, dm->queue_avoid_until, dm->queue_len * sizeof(*nau));
        memcpy(nc, dm->queue_classes, dm->queue_len * sizeof(*nc));
    }

    free(dm->queue);
    free(dm->queue_heights);
    free(dm->queue_avoid_peers);
    free(dm->queue_avoid_until);
    free(dm->queue_classes);

    dm->queue = nq;
    dm->queue_heights = nh;
    dm->queue_avoid_peers = nap;
    dm->queue_avoid_until = nau;
    dm->queue_classes = nc;
    dm->queue_cap = new_cap;
    return true;
}

/* Sort key for queue ordering: lowest height first (= closest to the
 * tip = the block that actually advances the active chain). A height of
 * -1 means "unknown" — such blocks must NOT preempt known tip-adjacent
 * blocks, so they sort to the BACK (treated as +infinity). */
static inline int64_t dl_sort_key(int32_t height)
{
    return height < 0 ? (int64_t)INT64_MAX : (int64_t)height;
}

static inline int dl_queue_order(enum dl_work_class a_class, int32_t a_height,
                                 enum dl_work_class b_class, int32_t b_height)
{
    if (a_class != b_class)
        return a_class == DL_WORK_FORWARD ? -1 : 1;
    int64_t a = dl_sort_key(a_height);
    int64_t b = dl_sort_key(b_height);
    return a < b ? -1 : a > b ? 1 : 0;
}

/* Insert a block into the download queue, keeping it sorted by height
 * ascending (lowest height = front). This is the STRUCTURAL guarantee
 * that tip-advancing blocks can never be tail-starved: dl_assign_to_peer
 * pops from the front, so the block closest to the tip is always fetched
 * first regardless of any caller's enqueue order. Caller holds mutex.
 *
 * Cost: O(log n) to find the slot + O(n) memmove to open it. Pushes are
 * one-at-a-time and the queue is bounded (<= 65536), so this is cheap
 * relative to the per-item O(n) dedup scan callers already perform. */
static bool dl_queue_push(struct download_manager *dm,
                          const struct uint256 *hash, int32_t height,
                          uint32_t avoid_peer, int64_t avoid_until,
                          enum dl_work_class work_class)
{
    if (qset_contains(dm, hash))
        return false; // raw-return-ok:duplicate-is-benign
    if (dm->queue_len >= dm->queue_cap && !dl_queue_grow(dm)) {
        /* Bounded queue at max capacity. The queue must always hold the
         * LOWEST heights (the connectable bottom of the gap) — evict the
         * highest-height tail entry when the incoming block sorts below
         * it; refuse the push otherwise. Refused blocks are re-discovered
         * by gap_fill / header sync once the bottom drains. */
        if (dm->queue_len == 0 ||
            dl_queue_order(work_class, height,
                           dm->queue_classes[dm->queue_len - 1],
                           dm->queue_heights[dm->queue_len - 1]) >= 0) {
            dm->total_queue_rejected++;
            return false; // raw-return-ok:normal-bounded-queue-backpressure
        }
        qset_remove(dm, &dm->queue[dm->queue_len - 1]);
        dm->queue_len--;
        dm->total_queue_evicted++;
    }

    /* Reserve set capacity BEFORE the queue insertion: a rebuild here
     * repopulates from dm->queue, so reserving after the queue already
     * holds `hash` would re-add it and the insert below would create a
     * SECOND live entry — a phantom that survives one qset_remove and
     * then refuses every future re-push of this hash (timeout/disconnect
     * re-queues bounce off the duplicate check forever). */
    qset_reserve_one(dm);

    /* Binary search for the first entry whose key is strictly greater
     * than ours; insert there (stable for equal heights). */
    size_t lo = 0, hi = dm->queue_len;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (dl_queue_order(dm->queue_classes[mid], dm->queue_heights[mid],
                           work_class, height) <= 0)
            lo = mid + 1;
        else
            hi = mid;
    }
    size_t pos = lo;

    if (pos < dm->queue_len) {
        memmove(&dm->queue[pos + 1], &dm->queue[pos],
                (dm->queue_len - pos) * sizeof(struct uint256));
        memmove(&dm->queue_heights[pos + 1], &dm->queue_heights[pos],
                (dm->queue_len - pos) * sizeof(int32_t));
        memmove(&dm->queue_avoid_peers[pos + 1],
                &dm->queue_avoid_peers[pos],
                (dm->queue_len - pos) * sizeof(uint32_t));
        memmove(&dm->queue_avoid_until[pos + 1],
                &dm->queue_avoid_until[pos],
                (dm->queue_len - pos) * sizeof(int64_t));
        memmove(&dm->queue_classes[pos + 1], &dm->queue_classes[pos],
                (dm->queue_len - pos) * sizeof(dm->queue_classes[0]));
    }
    dm->queue[pos] = *hash;
    dm->queue_heights[pos] = height;
    dm->queue_avoid_peers[pos] = avoid_peer;
    dm->queue_avoid_until[pos] = avoid_until;
    dm->queue_classes[pos] = work_class;
    dm->queue_len++;
    qset_insert_raw(dm, hash);
    return true;
}

static bool dl_queue_item_avoids_peer(const struct download_manager *dm,
                                      size_t idx,
                                      uint32_t peer_id,
                                      int64_t now)
{
    if (!dm->queue_avoid_peers || !dm->queue_avoid_until)
        return false;
    if (idx >= dm->queue_len)
        return false;
    if (dm->queue_avoid_until[idx] <= now)
        return false;
    return dm->queue_avoid_peers[idx] == peer_id &&
           dm->queue_avoid_until[idx] > now;
}

static void dl_queue_remove_at(struct download_manager *dm, size_t idx)
{
    if (idx >= dm->queue_len)
        return;
    size_t tail = dm->queue_len - idx - 1;
    if (tail > 0) {
        memmove(&dm->queue[idx], &dm->queue[idx + 1],
                tail * sizeof(dm->queue[0]));
        memmove(&dm->queue_heights[idx], &dm->queue_heights[idx + 1],
                tail * sizeof(dm->queue_heights[0]));
        memmove(&dm->queue_avoid_peers[idx], &dm->queue_avoid_peers[idx + 1],
                tail * sizeof(dm->queue_avoid_peers[0]));
        memmove(&dm->queue_avoid_until[idx], &dm->queue_avoid_until[idx + 1],
                tail * sizeof(dm->queue_avoid_until[0]));
        memmove(&dm->queue_classes[idx], &dm->queue_classes[idx + 1],
                tail * sizeof(dm->queue_classes[0]));
    }
    dm->queue_len--;
}

/* Remove a set of queue indices — supplied in STRICTLY ASCENDING order —
 * in a single O(queue_len) compaction pass. dl_queue_remove_at() is
 * O(queue_len) per call (a tail memmove), so removing k entries one at a
 * time is O(k * queue_len); the assign hot loop pops from the height-sorted
 * FRONT, where every per-pick removal shifts the whole tail. Batching the
 * removal keeps dl_assign_to_peer linear in the queue depth regardless of
 * batch size. Caller holds dm->cs and has already erased each index's qset
 * membership. */
static void dl_queue_remove_sorted(struct download_manager *dm,
                                   const size_t *sorted_idx, size_t n)
{
    if (n == 0)
        return;
    size_t len = dm->queue_len;
    /* Slide each contiguous run of survivors between consecutive removed
     * indices leftward with a bulk memmove. n==1 collapses to exactly the
     * single tail memmove dl_queue_remove_at() would do, so front-popping a
     * single entry costs the same as before; large batches move the tail
     * once instead of once per pick. */
    size_t w = sorted_idx[0];   /* [0, sorted_idx[0]) stays in place */
    for (size_t p = 0; p < n; p++) {
        size_t gap_start = sorted_idx[p] + 1;
        size_t gap_end = (p + 1 < n) ? sorted_idx[p + 1] : len; /* exclusive */
        size_t run = gap_end - gap_start;
        if (run > 0) {
            memmove(&dm->queue[w], &dm->queue[gap_start],
                    run * sizeof(dm->queue[0]));
            memmove(&dm->queue_heights[w], &dm->queue_heights[gap_start],
                    run * sizeof(dm->queue_heights[0]));
            memmove(&dm->queue_avoid_peers[w], &dm->queue_avoid_peers[gap_start],
                    run * sizeof(dm->queue_avoid_peers[0]));
            memmove(&dm->queue_avoid_until[w], &dm->queue_avoid_until[gap_start],
                    run * sizeof(dm->queue_avoid_until[0]));
            memmove(&dm->queue_classes[w], &dm->queue_classes[gap_start],
                    run * sizeof(dm->queue_classes[0]));
            w += run;
        }
    }
    dm->queue_len = w;
}

/* Find or update peer stats. Caller holds mutex. */
static struct dl_peer_stats *dl_find_peer(struct download_manager *dm,
                                           uint32_t peer_id, bool create)
{
    struct dl_peer_stats *reusable = NULL;
    for (size_t i = 0; i < dm->num_peers; i++) {
        if (dm->peers[i].peer_id == peer_id) {
            if (create && !dm->peers[i].active) {
                dm->peers[i].active = true;
                dm->peers[i].zero_assign_generation = 0;
                dm->peers[i].zero_assign_retry_after = 0;
                dm->peers[i].zero_assign_global_limit = 0;
                dm->peers[i].zero_assign_result = DL_ASSIGN_NONE;
            }
            return &dm->peers[i];
        }
        if (!dm->peers[i].active && !reusable)
            reusable = &dm->peers[i];
    }
    if (!create)
        return NULL;
    struct dl_peer_stats *p = reusable;
    if (!p) {
        if (dm->num_peers >= DL_MAX_TRACKED_PEERS)
            return NULL;
        p = &dm->peers[dm->num_peers++];
    }
    memset(p, 0, sizeof(*p));
    p->peer_id = peer_id;
    p->active = true;
    return p;
}

/* Find slot for hash (open addressing with linear probe).
 * Handles gaps from deletions: inactive slots are NOT probe-chain
 * terminators because dl_mark_received clears slots without
 * rehashing. We must scan through inactive slots to find matches. */
static struct dl_in_flight *find_slot(struct download_manager *dm,
                                       const struct uint256 *hash,
                                       bool find_empty)
{
    if (!dm->slots || dm->num_slots == 0) return NULL;
    size_t mask = dm->num_slots - 1;
    size_t idx = hash_slot(hash, mask);
    struct dl_in_flight *first_empty = NULL;

    for (size_t i = 0; i < dm->num_slots; i++) {
        struct dl_in_flight *s = &dm->slots[(idx + i) & mask];
        if (!s->active) {
            if (!first_empty) first_empty = s;
            /* Check if this slot was NEVER used (zero hash = virgin) */
            if (uint256_is_null(&s->hash))
                break; /* end of probe chain */
            continue; /* skip gap from deletion, keep probing */
        }
        if (uint256_eq(&s->hash, hash))
            return s;
    }
    return find_empty ? first_empty : NULL;
}

/* Rehash into a table of given size (must be power of 2). */
static void dl_rehash(struct download_manager *dm, size_t new_size)
{
    struct dl_in_flight *new_slots = zcl_calloc(new_size, sizeof(struct dl_in_flight), "dl_slots");
    if (!new_slots) return;

    size_t new_mask = new_size - 1;
    for (size_t i = 0; i < dm->num_slots; i++) {
        if (!dm->slots[i].active) continue;
        size_t idx = hash_slot(&dm->slots[i].hash, new_mask);
        for (size_t j = 0; j < new_size; j++) {
            struct dl_in_flight *s = &new_slots[(idx + j) & new_mask];
            if (!s->active) {
                *s = dm->slots[i];
                break;
            }
        }
    }
    free(dm->slots);
    dm->slots = new_slots;
    dm->num_slots = new_size;
}

/* Grow or compact hash table.
 * Grows when load factor > 50%.
 * Compacts (rehash in place) when active entries < 25% of slots
 * and total insertions have left many dead gaps. */
static void maybe_grow(struct download_manager *dm)
{
    if (dm->num_active * 2 >= dm->num_slots) {
        dl_rehash(dm, dm->num_slots * 2);
    } else if (dm->num_slots > INITIAL_SLOTS &&
               dm->num_active * 4 < dm->num_slots) {
        /* Compact: rehash at same size to eliminate dead gaps */
        dl_rehash(dm, dm->num_slots);
    }
}

bool dl_is_in_flight(struct download_manager *dm, const struct uint256 *hash)
{
    zcl_mutex_lock(&dm->cs);
    struct dl_in_flight *s = find_slot(dm, hash, false);
    bool found = (s != NULL && s->active);
    zcl_mutex_unlock(&dm->cs);
    return found;
}

bool dl_mark_requested(struct download_manager *dm,
                       const struct uint256 *hash, int32_t height,
                       uint32_t peer_id)
{
    zcl_mutex_lock(&dm->cs);

    /* Check if already in-flight */
    struct dl_in_flight *existing = find_slot(dm, hash, false);
    if (existing && existing->active) {
        dm->total_duplicate++;
        zcl_mutex_unlock(&dm->cs);
        return false;
    }

    /* Check global limit (dynamic: aggressive during IBD) */
    if (dm->num_active >= dl_get_max_in_flight_total()) {
        zcl_mutex_unlock(&dm->cs);
        return false;
    }

    maybe_grow(dm);

    /* Remove from queue if present (block is moving to in-flight).
     * O(1) membership check first — the linear scan only runs when the
     * hash is actually queued. */
    if (qset_contains(dm, hash)) {
        for (size_t j = 0; j < dm->queue_len; j++) {
            if (uint256_eq(&dm->queue[j], hash)) {
                qset_remove(dm, hash);
                dl_queue_remove_at(dm, j);
                break;
            }
        }
    }

    /* Find empty slot */
    struct dl_in_flight *slot = find_slot(dm, hash, true);
    if (!slot) {
        zcl_mutex_unlock(&dm->cs);
        LOG_FAIL("net", "dl_mark_requested: no empty slot in hash table (active=%zu, slots=%zu)",
                 dm->num_active, dm->num_slots);
    }

    slot->hash = *hash;
    slot->height = height;
    slot->peer_id = peer_id;
    slot->request_time = (int64_t)platform_time_wall_time_t();
    slot->work_class = DL_WORK_FORWARD;
    slot->active = true;
    dm->num_active++;
    dm->total_requested++;

    /* Update peer stats */
    {
        struct dl_peer_stats *ps = dl_find_peer(dm, peer_id, true);
        if (ps) ps->blocks_requested++;
    }

    zcl_mutex_unlock(&dm->cs);
    return true;
}

uint32_t dl_mark_received(struct download_manager *dm,
                          const struct uint256 *hash)
{
    zcl_mutex_lock(&dm->cs);

    struct dl_in_flight *s = find_slot(dm, hash, false);
    if (!s || !s->active) {
        zcl_mutex_unlock(&dm->cs);
        return 0;
    }

    uint32_t peer_id = s->peer_id;
    int64_t delivery = (int64_t)platform_time_wall_time_t() - s->request_time;

    s->active = false;
    /* Don't zero the hash — find_slot needs it to detect "was used" vs "never used"
     * for proper probe chain handling after deletions. */
    dm->num_active--;
    dm->total_received++;
    dl_generation_advance(&dm->capacity_generation);

    struct dl_peer_stats *ps = dl_find_peer(dm, peer_id, false);
    if (ps) {
        ps->blocks_received++;
        ps->last_body_received_time = (int64_t)platform_time_wall_time_t();
        int64_t delivery_us = delivery * 1000000;
        if (ps->avg_delivery_us == 0)
            ps->avg_delivery_us = delivery_us;
        else
            ps->avg_delivery_us = (ps->avg_delivery_us * 7 + delivery_us) / 8;

        /* Update bandwidth score: inverse of delivery time.
         * Score 128 = baseline (1s delivery). Faster = higher score.
         * Range: 1 (very slow) to 255 (very fast, <50ms). */
        if (ps->avg_delivery_us > 0) {
            /* 128M / avg_us gives ~128 at 1s, ~256 at 0.5s, ~64 at 2s */
            uint64_t score = 128000000ULL / (uint64_t)ps->avg_delivery_us;
            if (score < 1) score = 1;
            if (score > 255) score = 255;
            ps->bandwidth_score = (uint32_t)score;
        }
    }

    zcl_mutex_unlock(&dm->cs);
    return peer_id;
}

size_t dl_check_timeouts(struct download_manager *dm, int64_t now)
{
    zcl_mutex_lock(&dm->cs);

    size_t reassigned = 0;
    for (size_t i = 0; i < dm->num_slots; i++) {
        struct dl_in_flight *s = &dm->slots[i];
        if (!s->active) continue;

        int64_t age = now - s->request_time;
        if (age < dl_get_request_timeout_secs()) continue;

        /* Timed out — move back to queue for reassignment */
        event_emitf(EV_BLOCK_REQUESTED, s->peer_id,
                    "TIMEOUT h=%d age=%llds", s->height, (long long)age);

        struct dl_peer_stats *ps = dl_find_peer(dm, s->peer_id, false);
        if (ps) ps->blocks_timed_out++;

        dl_queue_push(dm, &s->hash, s->height,
                      s->peer_id, dl_peer_avoid_deadline(now),
                      s->work_class);
        s->active = false;
        dm->num_active--;
        dm->total_timed_out++;
        reassigned++;
    }

    /* Same trace as a backpressure drain (see the field comment on
     * last_forced_settle_time): the original peer's late reply — if it
     * ever arrives — will look identical to an unsolicited push. */
    if (reassigned > 0)
        dm->last_forced_settle_time = now;
    if (reassigned > 0)
        dl_generation_advance(&dm->queue_generation);
    if (reassigned > 0)
        dl_generation_advance(&dm->capacity_generation);

    /* Compact hash table if it has many dead gaps */
    maybe_grow(dm);

    zcl_mutex_unlock(&dm->cs);
    return reassigned;
}

size_t dl_peer_in_flight(struct download_manager *dm, uint32_t peer_id)
{
    zcl_mutex_lock(&dm->cs);
    size_t count = 0;
    for (size_t i = 0; i < dm->num_slots; i++) {
        if (dm->slots[i].active && dm->slots[i].peer_id == peer_id)
            count++;
    }
    zcl_mutex_unlock(&dm->cs);
    return count;
}

void dl_peer_body_progress(struct download_manager *dm, uint32_t peer_id,
                           uint64_t *requested, uint64_t *received,
                           uint64_t *timed_out)
{
    if (requested) *requested = 0;
    if (received)  *received  = 0;
    if (timed_out) *timed_out = 0;
    if (!dm)
        return;
    zcl_mutex_lock(&dm->cs);
    struct dl_peer_stats *ps = dl_find_peer(dm, peer_id, false);
    if (ps) {
        if (requested) *requested = ps->blocks_requested;
        if (received)  *received  = ps->blocks_received;
        if (timed_out) *timed_out = ps->blocks_timed_out;
    }
    zcl_mutex_unlock(&dm->cs);
}

void dl_peer_body_staleness(struct download_manager *dm, uint32_t peer_id,
                            uint64_t *received, uint64_t *timed_out,
                            int64_t *last_body_time)
{
    if (received)       *received       = 0;
    if (timed_out)      *timed_out      = 0;
    if (last_body_time) *last_body_time = 0;
    if (!dm)
        return;
    zcl_mutex_lock(&dm->cs);
    struct dl_peer_stats *ps = dl_find_peer(dm, peer_id, false);
    if (ps) {
        if (received)       *received       = ps->blocks_received;
        if (timed_out)      *timed_out      = ps->blocks_timed_out;
        if (last_body_time) *last_body_time = ps->last_body_received_time;
    }
    zcl_mutex_unlock(&dm->cs);
}

size_t dl_peer_disconnected(struct download_manager *dm, uint32_t peer_id)
{
    zcl_mutex_lock(&dm->cs);
    size_t requeued = 0;
    int64_t avoid_until =
        dl_peer_avoid_deadline((int64_t)platform_time_wall_time_t());

    for (size_t i = 0; i < dm->num_slots; i++) {
        struct dl_in_flight *s = &dm->slots[i];
        if (!s->active || s->peer_id != peer_id) continue;

        dl_queue_push(dm, &s->hash, s->height, peer_id, avoid_until,
                      s->work_class);
        s->active = false;
        dm->num_active--;
        /* Settle the request (see the invariant on the stats fields): the
         * requeued block will increment total_requested AGAIN when it is
         * re-assigned, so leaving the original request open here leaks a
         * permanent +1 into requested-vs-settled arithmetic. */
        dm->total_orphaned++;
        requeued++;
    }

    struct dl_peer_stats *ps = dl_find_peer(dm, peer_id, false);
    if (ps) ps->active = false;

    if (requeued > 0)
        event_emitf(EV_BLOCK_REQUESTED, peer_id,
                    "peer disconnect: %zu blocks requeued", requeued);
    if (requeued > 0)
        dl_generation_advance(&dm->queue_generation);
    if (requeued > 0)
        dl_generation_advance(&dm->capacity_generation);

    zcl_mutex_unlock(&dm->cs);
    return requeued;
}

/* One-block counterpart to dl_peer_disconnected — see the rationale and the
 * measured orphan numbers on the declaration in net/download.h. Settles ONLY
 * the named hash and leaves the rest of this peer's in-flight window alone;
 * the peer's dl_peer_stats stays active, because "does not have this one
 * block" is not "is gone". */
size_t dl_mark_notfound(struct download_manager *dm, uint32_t peer_id,
                        const struct uint256 *hash)
{
    if (!dm || !hash)
        return 0;

    zcl_mutex_lock(&dm->cs);

    struct dl_in_flight *s = find_slot(dm, hash, false);
    /* Only the peer we actually asked may settle the slot. A notfound from a
     * peer that does not hold this request is either stale (the slot was
     * already reassigned after a timeout) or hostile, and must not be able to
     * cancel another peer's live request. */
    if (!s || !s->active || s->peer_id != peer_id) {
        zcl_mutex_unlock(&dm->cs);
        return 0;
    }

    int64_t avoid_until =
        dl_peer_avoid_deadline((int64_t)platform_time_wall_time_t());
    dl_queue_push(dm, &s->hash, s->height, peer_id, avoid_until,
                  s->work_class);
    s->active = false;
    dm->num_active--;
    /* Settle the request exactly once (see the invariant on the stats
     * fields): the requeued block increments total_requested again when it is
     * re-assigned, so the original must not be left open. */
    dm->total_orphaned++;

    event_emitf(EV_BLOCK_REQUESTED, peer_id,
                "notfound h=%d: 1 block requeued", s->height);
    dl_generation_advance(&dm->queue_generation);
    dl_generation_advance(&dm->capacity_generation);

    zcl_mutex_unlock(&dm->cs);
    return 1;
}

uint32_t dl_peer_bandwidth_score(struct download_manager *dm, uint32_t peer_id)
{
    if (!dm) return 0;
    zcl_mutex_lock(&dm->cs);
    struct dl_peer_stats *ps = dl_find_peer(dm, peer_id, false);
    uint32_t score = ps ? ps->bandwidth_score : 0;
    zcl_mutex_unlock(&dm->cs);
    return score;
}

void dl_peer_seed_bandwidth_score(struct download_manager *dm,
                                  uint32_t peer_id, uint32_t score)
{
    if (!dm || score == 0)
        return;
    if (score > 255) score = 255;
    zcl_mutex_lock(&dm->cs);
    /* Seed the INITIAL adaptive window from banked reputation only — never
     * override a live measurement. A peer with no measured score yet starts at
     * its historical band instead of the DL_MAX_IN_FLIGHT_PER_PEER minimum;
     * once real deliveries land, dl_note_block_received recomputes the score. */
    struct dl_peer_stats *ps = dl_find_peer(dm, peer_id, true);
    if (ps && ps->bandwidth_score == 0)
        ps->bandwidth_score = score;
    zcl_mutex_unlock(&dm->cs);
}

/* qsort comparator for the bulk-enqueue staging array. */
struct dl_stage_item {
    struct uint256 hash;
    int32_t height;
    enum dl_work_class work_class;
};

static int dl_stage_cmp(const void *a, const void *b)
{
    const struct dl_stage_item *x = a, *y = b;
    return dl_queue_order(x->work_class, x->height,
                          y->work_class, y->height);
}

size_t dl_queue_blocks(struct download_manager *dm,
                       const struct uint256 *hashes,
                       const int32_t *heights,
                       size_t count)
{
    return dl_queue_blocks_class(dm, hashes, heights, count, DL_WORK_FORWARD);
}

size_t dl_queue_blocks_class(struct download_manager *dm,
                             const struct uint256 *hashes,
                             const int32_t *heights,
                             size_t count,
                             enum dl_work_class work_class)
{
    if (!dm || !hashes ||
        (work_class != DL_WORK_FORWARD && work_class != DL_WORK_HISTORY))
        return 0;
    zcl_mutex_lock(&dm->cs);

    /* Bulk enqueue is sort + single merge, NOT count repeated sorted
     * inserts: callers legitimately hand over tens of thousands of
     * blocks per call (gap_fill window, header batches), and a per-item
     * insert is an O(queue_len) memmove — O(n^2) per call while holding
     * cs, which starves the whole node. */

    /* 1. Filter into a staging array: not in-flight, not queued, not a
     *    duplicate within this batch (the qset insert handles that).
     *    Capacity is reserved ONCE up-front so no rebuild can fire
     *    mid-loop — a mid-batch rebuild repopulates from dm->queue only
     *    and would wipe the staged hashes' membership (see
     *    qset_reserve_n). */
    struct dl_stage_item *stage = NULL;
    size_t n_stage = 0;
    bool promoted = false;
    if (count > 0)
        stage = zcl_malloc(count * sizeof(*stage), "dl_stage");
    if (!stage) {
        zcl_mutex_unlock(&dm->cs);
        return 0;
    }
    qset_reserve_n(dm, count);
    for (size_t i = 0; i < count; i++) {
        struct dl_in_flight *s = find_slot(dm, &hashes[i], false);
        if (s && s->active) continue;
        if (qset_contains(dm, &hashes[i])) {
            /* A tip/forward request supersedes the same hash discovered by
             * background history without creating a duplicate. Reinsert it
             * so the class-first ordering remains valid. */
            if (work_class == DL_WORK_FORWARD) {
                for (size_t j = 0; j < dm->queue_len; j++) {
                    if (uint256_eq(&dm->queue[j], &hashes[i]) &&
                        dm->queue_classes[j] == DL_WORK_HISTORY) {
                        int32_t queued_height = heights ? heights[i]
                                                       : dm->queue_heights[j];
                        qset_remove(dm, &hashes[i]);
                        dl_queue_remove_at(dm, j);
                        promoted = dl_queue_push(
                            dm, &hashes[i], queued_height, 0, 0,
                            DL_WORK_FORWARD) || promoted;
                        break;
                    }
                }
            }
            continue;
        }
        qset_insert_raw(dm, &hashes[i]);
        stage[n_stage].hash = hashes[i];
        stage[n_stage].height = heights ? heights[i] : -1;
        stage[n_stage].work_class = work_class;
        n_stage++;
    }
    if (n_stage == 0) {
        if (promoted)
            dl_generation_advance(&dm->queue_generation);
        free(stage);
        zcl_mutex_unlock(&dm->cs);
        return 0;
    }

    /* 2. Sort the newcomers by height (lowest first). */
    qsort(stage, n_stage, sizeof(*stage), dl_stage_cmp);

    /* 3. Grow toward the merged size (bounded by DL_QUEUE_MAX_CAP). */
    while (dm->queue_len + n_stage > dm->queue_cap && dl_queue_grow(dm))
        ;

    /* 4. Single forward merge of (queue, stage) into fresh buffers,
     *    keeping only the lowest queue_cap entries; everything past the
     *    cap (the highest heights, from either source) is dropped and
     *    its membership erased. */
    size_t total = dm->queue_len + n_stage;
    struct uint256 *mh = zcl_malloc(total * sizeof(*mh), "dl_merge_h");
    int32_t *mg = zcl_malloc(total * sizeof(*mg), "dl_merge_g");
    uint32_t *map = zcl_calloc(total, sizeof(*map), "dl_merge_avoid_peers");
    int64_t *mau = zcl_calloc(total, sizeof(*mau), "dl_merge_avoid_until");
    enum dl_work_class *mc =
        zcl_calloc(total, sizeof(*mc), "dl_merge_classes");
    size_t added = 0;
    if (mh && mg && map && mau && mc) {
        size_t qi = 0, si = 0, mi = 0;
        while (qi < dm->queue_len || si < n_stage) {
            bool take_stage;
            if (qi >= dm->queue_len)      take_stage = true;
            else if (si >= n_stage)       take_stage = false;
            else take_stage = dl_queue_order(
                                  stage[si].work_class, stage[si].height,
                                  dm->queue_classes[qi],
                                  dm->queue_heights[qi]) < 0;
            if (take_stage) {
                mh[mi] = stage[si].hash;
                mg[mi] = stage[si].height;
                map[mi] = 0;
                mau[mi] = 0;
                mc[mi] = stage[si].work_class;
                si++;
            } else {
                mh[mi] = dm->queue[qi];
                mg[mi] = dm->queue_heights[qi];
                map[mi] = dm->queue_avoid_peers[qi];
                mau[mi] = dm->queue_avoid_until[qi];
                mc[mi] = dm->queue_classes[qi];
                qi++;
            }
            mi++;
        }
        size_t keep = total > dm->queue_cap ? dm->queue_cap : total;
        for (size_t i = keep; i < total; i++) {
            qset_remove(dm, &mh[i]);
            dm->total_queue_evicted++;
        }
        memcpy(dm->queue, mh, keep * sizeof(*mh));
        memcpy(dm->queue_heights, mg, keep * sizeof(*mg));
        memcpy(dm->queue_avoid_peers, map, keep * sizeof(*map));
        memcpy(dm->queue_avoid_until, mau, keep * sizeof(*mau));
        memcpy(dm->queue_classes, mc, keep * sizeof(*mc));
        dm->queue_len = keep;
        /* Count the newcomers that survived the cap: a newcomer is in
         * the queue iff its membership entry is still live. */
        added = n_stage;
        if (total > keep) {
            added = 0;
            for (size_t i = 0; i < n_stage; i++)
                if (qset_contains(dm, &stage[i].hash))
                    added++;
        }
    } else {
        /* Alloc failure: fall back to per-item sorted inserts (rare;
         * correctness over speed). qset entries for items the push
         * rejects must be erased. */
        for (size_t i = 0; i < n_stage; i++) {
            qset_remove(dm, &stage[i].hash);
            if (dl_queue_push(dm, &stage[i].hash, stage[i].height, 0, 0,
                              stage[i].work_class))
                added++;
        }
    }
    free(mh);
    free(mg);
    free(map);
    free(mau);
    free(mc);
    free(stage);

    if (added > 0 || promoted)
        dl_generation_advance(&dm->queue_generation);

    zcl_mutex_unlock(&dm->cs);
    return added;
}

void dl_queue_priority(struct download_manager *dm,
                       const struct uint256 *hash, int32_t height)
{
    zcl_mutex_lock(&dm->cs);
    bool changed = false;

    /* Skip if already in-flight */
    struct dl_in_flight *s = find_slot(dm, hash, false);
    if (s && s->active) {
        zcl_mutex_unlock(&dm->cs);
        return;
    }

    /* Remove from queue if already present (we'll re-insert sorted) */
    if (qset_contains(dm, hash)) {
        for (size_t j = 0; j < dm->queue_len; j++) {
            if (uint256_eq(&dm->queue[j], hash)) {
                int64_t now = (int64_t)platform_time_wall_time_t();
                if (dm->queue_heights[j] == height &&
                    dm->queue_classes[j] == DL_WORK_FORWARD &&
                    dm->queue_avoid_until[j] <= now) {
                    zcl_mutex_unlock(&dm->cs);
                    return;
                }
                qset_remove(dm, hash);
                dl_queue_remove_at(dm, j);
                changed = true;
                break;
            }
        }
    }

    /* Insert keeping the queue sorted by height ascending. Because the
     * queue is height-ordered and dl_assign_to_peer pops from the front,
     * a priority block (always tip-adjacent / lowest-height in practice)
     * lands at the front and is fetched first — without breaking the
     * single sorted invariant that makes tail-starvation impossible. */
    if (dl_queue_push(dm, hash, height, 0, 0, DL_WORK_FORWARD))
        changed = true;
    if (changed)
        dl_generation_advance(&dm->queue_generation);

    zcl_mutex_unlock(&dm->cs);
}

static bool dl_assignment_peer_is_parked(const struct download_manager *dm,
                                         const struct dl_peer_stats *ps,
                                         int64_t now)
{
    if (!ps || !dl_assign_result_is_parkable(ps->zero_assign_result) ||
        ps->zero_assign_generation != dl_assign_dependency_generation(
            dm, ps->zero_assign_result))
        return false;
    if (ps->zero_assign_result == DL_ASSIGN_HISTORY_THROTTLED) {
        /* Capacity may be unchanged while a newly queued forward block makes
         * this peer immediately useful. Do not let the background lane's
         * parked result hide foreground work. */
        for (size_t i = 0; i < dm->queue_len; i++)
            if (dm->queue_classes[i] == DL_WORK_FORWARD)
                return false;
    }
    if ((ps->zero_assign_result == DL_ASSIGN_PEER_WINDOW_FULL ||
         ps->zero_assign_result == DL_ASSIGN_GLOBAL_WINDOW_FULL) &&
        ps->zero_assign_global_limit != dl_get_max_in_flight_total())
        return false;
    return ps->zero_assign_retry_after <= 0 ||
           now < ps->zero_assign_retry_after;
}

bool dl_assignment_should_attempt(struct download_manager *dm,
                                  uint32_t peer_id)
{
    if (!dm)
        return false;
    zcl_mutex_lock(&dm->cs);
    struct dl_peer_stats *ps = dl_find_peer(dm, peer_id, false);
    bool should_attempt = !dl_assignment_peer_is_parked(
        dm, ps, (int64_t)platform_time_wall_time_t());
    zcl_mutex_unlock(&dm->cs);
    return should_attempt;
}

/* S2.3: best known bandwidth_score among other actively-tracked,
 * non-loopback peers. Used only to decide whether *this* requester is
 * demonstrably slower than some other known peer, gating the tip-adjacent
 * bias below. Caller holds dm->cs. Bounded by DL_MAX_TRACKED_PEERS. */
static uint32_t dl_best_bandwidth_score(const struct download_manager *dm)
{
    uint32_t best = 0;
    for (size_t i = 0; i < dm->num_peers; i++) {
        const struct dl_peer_stats *ps = &dm->peers[i];
        if (!ps->active || ps->is_loopback)
            continue;
        if (ps->bandwidth_score > best)
            best = ps->bandwidth_score;
    }
    return best;
}

/* S2.3: scan queue indices [scan_from, scan_to) for the first entry that
 * does not avoid `peer_id`. Returns the index, or `scan_to` if none found.
 * Records avoid-cooldown bookkeeping identically to the inline scan it
 * replaces (avoid_blocked / earliest retry_after). Caller holds dm->cs. */
static size_t dl_scan_queue_for_peer(struct download_manager *dm,
                                     uint32_t peer_id, int64_t now,
                                     size_t scan_from, size_t scan_to,
                                     bool *avoid_blocked,
                                     int64_t *retry_after)
{
    for (size_t i = scan_from; i < scan_to; i++) {
        if (dl_queue_item_avoids_peer(dm, i, peer_id, now)) {
            *avoid_blocked = true;
            if (*retry_after == 0 || dm->queue_avoid_until[i] < *retry_after)
                *retry_after = dm->queue_avoid_until[i];
            continue;
        }
        return i;
    }
    return scan_to;
}

size_t dl_assign_to_peer(struct download_manager *dm,
                         uint32_t peer_id,
                         struct uint256 *out_hashes,
                         size_t max_assign)
{
    zcl_mutex_lock(&dm->cs);
    int64_t now = (int64_t)platform_time_wall_time_t();
    struct dl_peer_stats *ps_assign = dl_find_peer(dm, peer_id, true);
    if (dl_assignment_peer_is_parked(dm, ps_assign, now)) {
        zcl_mutex_unlock(&dm->cs);
        return 0;
    }
    size_t queue_before = dm->queue_len;
    size_t active_before = dm->num_active;

    /* Adaptive per-peer limit: fast peers get larger windows.
     * bandwidth_score 0-63 → 16 slots, 64-127 → 32-64, 128+ → 64-128.
     * This naturally gives ~4x more work to 4x-faster peers. */
    size_t peer_count = 0;
    size_t history_peer_count = 0;
    size_t history_global_count = 0;
    for (size_t i = 0; i < dm->num_slots; i++) {
        if (!dm->slots[i].active)
            continue;
        if (dm->slots[i].work_class == DL_WORK_HISTORY) {
            history_global_count++;
            if (dm->slots[i].peer_id == peer_id)
                history_peer_count++;
        }
        if (dm->slots[i].peer_id == peer_id)
            peer_count++;
    }
    size_t forward_queued = 0;
    size_t history_queued = 0;
    for (size_t i = 0; i < dm->queue_len; i++) {
        if (dm->queue_classes[i] == DL_WORK_HISTORY)
            history_queued++;
        else
            forward_queued++;
    }
    size_t peer_limit = dl_get_max_in_flight_per_peer(); /* default for new peers */
    if (ps_assign && ps_assign->is_loopback) {
        /* K2: loopback has no WAN-fairness constraint and effectively
         * unlimited bandwidth. Use the elevated cap; the global limit
         * (DL_MAX_IN_FLIGHT_TOTAL_IBD=4096) and the consumer-side reducer
         * pipeline are the real backpressure. */
        peer_limit = DL_MAX_IN_FLIGHT_PER_LOOPBACK;
    } else if (ps_assign && ps_assign->bandwidth_score > 0) {
        /* Scale: score/128 * MAX, clamped to [16, MAX] */
        size_t max_peer = dl_get_max_in_flight_per_peer();
        peer_limit = (size_t)ps_assign->bandwidth_score
                     * max_peer / 128;
        if (peer_limit < 16) peer_limit = 16;
        if (peer_limit > max_peer)
            peer_limit = max_peer;
    }
    size_t available = 0;
    if (peer_count < peer_limit)
        available = peer_limit - peer_count;
    if (available > max_assign) available = max_assign;
    if (available > dm->queue_len) available = dm->queue_len;

    /* Also respect global limit (dynamic: aggressive during IBD).
     * num_active can legitimately EXCEED the limit (it shrinks when IBD
     * ends) — the unguarded subtraction underflowed size_t and handed
     * the pop loop a near-infinite `available`, overflowing the
     * caller's out_hashes[max_assign] buffer. */
    size_t global_limit = dl_get_max_in_flight_total();
    if (dm->num_active >= global_limit)
        available = 0;
    else if (dm->num_active + available > global_limit)
        available = global_limit - dm->num_active;

    /* History owns a subordinate lane. These limits never charge forward
     * work, so a saturated history lane cannot block a new tip request. */
    size_t history_available = 0;
    if (history_global_count < DL_MAX_HISTORY_IN_FLIGHT &&
        history_peer_count < DL_MAX_HISTORY_PER_PEER) {
        history_available = DL_MAX_HISTORY_IN_FLIGHT - history_global_count;
        size_t peer_history_available =
            DL_MAX_HISTORY_PER_PEER - history_peer_count;
        if (history_available > peer_history_available)
            history_available = peer_history_available;
        if (history_available > history_queued)
            history_available = history_queued;
    }
    size_t class_available = forward_queued + history_available;
    if (available > class_available)
        available = class_available;

    int assign_result = DL_ASSIGN_ASSIGNED;
    if (queue_before == 0)
        assign_result = DL_ASSIGN_NO_QUEUE;
    else if (max_assign == 0)
        assign_result = DL_ASSIGN_MAX_ZERO;
    else if (peer_count >= peer_limit)
        assign_result = DL_ASSIGN_PEER_WINDOW_FULL;
    else if (active_before >= global_limit)
        assign_result = DL_ASSIGN_GLOBAL_WINDOW_FULL;
    else if (forward_queued == 0 && history_queued > 0 &&
             history_available == 0)
        assign_result = DL_ASSIGN_HISTORY_THROTTLED;

    /* S2.3: bias the lowest-height (tip-adjacent, most-urgent) entries
     * toward a demonstrably faster peer. The queue is height-sorted
     * ascending, so indices [0, tip_bias_skip) are the tip-adjacent
     * reserve. Skipped for loopback (already bypasses bandwidth scaling)
     * and for peers with no established score yet (score 0 — a brand-new
     * peer gets a fair first shot rather than being penalized on no
     * evidence). `available` (this peer's quota) is computed independently,
     * so a biased peer still gets its full quota, just sourced from beyond
     * the reserve when possible. */
    size_t tip_bias_skip = 0;
    if (ps_assign && !ps_assign->is_loopback &&
        ps_assign->bandwidth_score > 0) {
        uint32_t best_score = dl_best_bandwidth_score(dm);
        if (best_score >= ps_assign->bandwidth_score * 2)
            tip_bias_skip = DL_TIP_BIAS_RESERVE;
    }
    if (tip_bias_skip > dm->queue_len)
        tip_bias_skip = dm->queue_len;
    if (history_queued > 0)
        tip_bias_skip = 0;

    /* Pick the first non-avoided entry in height order. A timed-out hash
     * should be immediately available to other peers, but the same peer
     * that just failed it should not be allowed to grab it again while
     * alternative peers are asking for work. When tip_bias_skip is set, a
     * slower peer prefers entries beyond the tip-adjacent reserve, falling
     * back INTO the reserve when nothing eligible lies beyond it (bias, not
     * a hard partition — no starvation). When tip_bias_skip == 0 (loopback,
     * unscored, or no faster peer known) this is byte-identical to the old
     * whole-queue scan. */
    size_t assigned = 0;
    size_t history_assigned = 0;
    bool avoid_blocked = false;
    bool attempted_slot = false;
    int64_t retry_after = 0;

    /* Fast path: select the whole batch in a single forward pass and remove
     * the picked entries from the queue in ONE O(queue_len) compaction,
     * rather than the per-pick dl_queue_remove_at() below whose tail memmove
     * makes the loop O(available * queue_len). During deep IBD the queue is
     * pinned near its 65536 cap and every assign call pops from the
     * height-sorted FRONT, so each per-pick removal shifted the whole tail —
     * measured at ~35-48 us PER assigned block, all while holding dm->cs,
     * serializing every other peer's assignment and every dl_mark_received.
     *
     * Semantics are identical to the loop form: avoided entries are stable
     * for the fixed `now`, and picked entries are consumed, so a forward
     * cursor over the original indices yields the exact same pick sequence
     * (all eligible primary entries in order, then all eligible fallback
     * entries in order). Gated on a queue deep enough that consuming the
     * batch cannot shift the tip-bias boundary (queue_len > available +
     * tip_bias_skip) — that is exactly the deep-queue case that matters for
     * throughput. The rare shallow-queue + active-tip-bias corner keeps the
     * loop below, where the per-pick memmove is cheap anyway. */
    bool can_batch = available > 0 &&
                     available <= DL_MAX_IN_FLIGHT_PER_LOOPBACK &&
                     (tip_bias_skip == 0 ||
                      dm->queue_len > available + tip_bias_skip);
    if (can_batch) {
        size_t orig_len = dm->queue_len;
        size_t clamp = tip_bias_skip < orig_len ? tip_bias_skip : orig_len;
        size_t picks[DL_MAX_IN_FLIGHT_PER_LOOPBACK];  /* assignment order */
        size_t npick = 0;
        size_t history_picked = 0;

        /* Primary region [clamp, orig_len): tip-adjacent reserve skipped. */
        for (size_t i = clamp; i < orig_len && npick < available; i++) {
            if (dm->queue_classes[i] == DL_WORK_HISTORY &&
                history_picked >= history_available)
                continue;
            if (dl_queue_item_avoids_peer(dm, i, peer_id, now)) {
                avoid_blocked = true;
                if (retry_after == 0 || dm->queue_avoid_until[i] < retry_after)
                    retry_after = dm->queue_avoid_until[i];
                continue;
            }
            picks[npick++] = i;
            if (dm->queue_classes[i] == DL_WORK_HISTORY)
                history_picked++;
        }
        /* Fallback region [0, clamp): entered only after the primary is
         * exhausted, matching the per-iteration fallback in the loop form. */
        if (npick < available && clamp > 0) {
            for (size_t i = 0; i < clamp && npick < available; i++) {
                if (dm->queue_classes[i] == DL_WORK_HISTORY &&
                    history_picked >= history_available)
                    continue;
                if (dl_queue_item_avoids_peer(dm, i, peer_id, now)) {
                    avoid_blocked = true;
                    if (retry_after == 0 ||
                        dm->queue_avoid_until[i] < retry_after)
                        retry_after = dm->queue_avoid_until[i];
                    continue;
                }
                picks[npick++] = i;
                if (dm->queue_classes[i] == DL_WORK_HISTORY)
                    history_picked++;
            }
        }

        if (npick > 0) {
            attempted_slot = true;
            /* Apply: move each pick into the in-flight table. The queue
             * arrays stay untouched until the single compaction below, so
             * dm->queue[picks[p]] still refers to the original index. */
            for (size_t p = 0; p < npick; p++) {
                struct uint256 hash = dm->queue[picks[p]];
                int32_t height = dm->queue_heights[picks[p]];
                enum dl_work_class work_class =
                    dm->queue_classes[picks[p]];
                qset_remove(dm, &hash);
                maybe_grow(dm);
                struct dl_in_flight *slot = find_slot(dm, &hash, true);
                if (!slot)
                    continue;
                slot->hash = hash;
                slot->height = height;
                slot->peer_id = peer_id;
                slot->request_time = now;
                slot->work_class = work_class;
                slot->active = true;
                dm->num_active++;
                dm->total_requested++;
                out_hashes[assigned++] = hash;
                if (work_class == DL_WORK_HISTORY)
                    history_assigned++;
            }
            /* Build the ascending index set for the single compaction. The
             * picks form two ascending runs (primary appended first, then
             * fallback) with every fallback index < clamp <= every primary
             * index, so fallback-run ++ primary-run is globally sorted. */
            size_t spick[DL_MAX_IN_FLIGHT_PER_LOOPBACK];
            size_t ns = 0;
            for (size_t p = 0; p < npick; p++)
                if (picks[p] < clamp)
                    spick[ns++] = picks[p];   /* fallback run (ascending) */
            for (size_t p = 0; p < npick; p++)
                if (picks[p] >= clamp)
                    spick[ns++] = picks[p];   /* primary run (ascending) */
            dl_queue_remove_sorted(dm, spick, ns);
        }
    } else {
        while (assigned < available && dm->queue_len > 0) {
            size_t bias_skip = tip_bias_skip < dm->queue_len
                                   ? tip_bias_skip : dm->queue_len;
            size_t pick = dl_scan_queue_for_peer(dm, peer_id, now, bias_skip,
                                                 dm->queue_len, &avoid_blocked,
                                                 &retry_after);
            if (pick == dm->queue_len && bias_skip > 0) {
                /* Nothing eligible past the tip-adjacent reserve — fall back
                 * into the reserve itself so a slower peer still gets work
                 * rather than stalling. */
                pick = dl_scan_queue_for_peer(dm, peer_id, now, 0, bias_skip,
                                              &avoid_blocked, &retry_after);
            }
            if (pick == dm->queue_len)
                break;

            struct uint256 hash = dm->queue[pick];
            int32_t height = dm->queue_heights[pick];
            enum dl_work_class work_class = dm->queue_classes[pick];
            if (work_class == DL_WORK_HISTORY &&
                history_assigned >= history_available)
                break;
            qset_remove(dm, &hash);
            dl_queue_remove_at(dm, pick);

            maybe_grow(dm);
            attempted_slot = true;
            struct dl_in_flight *slot = find_slot(dm, &hash, true);
            if (!slot) continue;

            slot->hash = hash;
            slot->height = height;
            slot->peer_id = peer_id;
            slot->request_time = now;
            slot->work_class = work_class;
            slot->active = true;
            dm->num_active++;
            dm->total_requested++;

            out_hashes[assigned++] = hash;
            if (work_class == DL_WORK_HISTORY)
                history_assigned++;
        }
    }

    if (assigned > 0) {
        if (ps_assign) {
            ps_assign->blocks_requested += (uint32_t)assigned;
            ps_assign->zero_assign_generation = 0;
            ps_assign->zero_assign_retry_after = 0;
            ps_assign->zero_assign_global_limit = 0;
            ps_assign->zero_assign_result = DL_ASSIGN_NONE;
        }
        assign_result = DL_ASSIGN_ASSIGNED;
    } else if (!attempted_slot && avoid_blocked &&
               assign_result == DL_ASSIGN_ASSIGNED) {
        assign_result = DL_ASSIGN_PEER_AVOID_COOLDOWN;
    } else if (assign_result == DL_ASSIGN_ASSIGNED) {
        assign_result = DL_ASSIGN_NO_SLOT;
    }

    if (assigned == 0 && ps_assign &&
        dl_assign_result_is_parkable(assign_result)) {
        ps_assign->zero_assign_generation = dl_assign_dependency_generation(
            dm, assign_result);
        ps_assign->zero_assign_retry_after =
            assign_result == DL_ASSIGN_PEER_AVOID_COOLDOWN ? retry_after : 0;
        ps_assign->zero_assign_global_limit = global_limit;
        ps_assign->zero_assign_result = assign_result;
    }

    dm->assign_attempts++;
    if (assigned > 0)
        dm->assign_successes++;
    else
        dm->assign_zero_results++;
    dm->last_assign_peer_id = peer_id;
    dm->last_assign_max_requested = (uint64_t)max_assign;
    dm->last_assign_available = (uint64_t)available;
    dm->last_assign_assigned = (uint64_t)assigned;
    dm->last_assign_queue_len = (uint64_t)queue_before;
    dm->last_assign_active = (uint64_t)active_before;
    dm->last_assign_peer_in_flight = (uint64_t)peer_count;
    dm->last_assign_peer_limit = (uint64_t)peer_limit;
    dm->last_assign_global_limit = (uint64_t)global_limit;
    dm->last_assign_result = assign_result;

    zcl_mutex_unlock(&dm->cs);
    return assigned;
}

void dl_peer_block_received(struct download_manager *dm,
                            uint32_t peer_id, int64_t delivery_us)
{
    zcl_mutex_lock(&dm->cs);
    struct dl_peer_stats *ps = dl_find_peer(dm, peer_id, false);
    if (ps) {
        ps->blocks_received++;
        ps->last_body_received_time = (int64_t)platform_time_wall_time_t();
        if (ps->avg_delivery_us == 0)
            ps->avg_delivery_us = delivery_us;
        else
            ps->avg_delivery_us = (ps->avg_delivery_us * 7 + delivery_us) / 8;

        /* Update bandwidth score */
        if (ps->avg_delivery_us > 0) {
            uint64_t score = 128000000ULL / (uint64_t)ps->avg_delivery_us;
            if (score < 1) score = 1;
            if (score > 255) score = 255;
            ps->bandwidth_score = (uint32_t)score;
        }
    }
    zcl_mutex_unlock(&dm->cs);
}

size_t dl_peer_adaptive_window(struct download_manager *dm, uint32_t peer_id)
{
    zcl_mutex_lock(&dm->cs);
    struct dl_peer_stats *ps = dl_find_peer(dm, peer_id, false);
    size_t window = dl_get_max_in_flight_per_peer();
    if (ps && ps->is_loopback) {
        window = DL_MAX_IN_FLIGHT_PER_LOOPBACK;
    } else if (ps && ps->bandwidth_score > 0) {
        size_t max_peer = dl_get_max_in_flight_per_peer();
        window = (size_t)ps->bandwidth_score * max_peer / 128;
        if (window < 16) window = 16;
        if (window > max_peer) window = max_peer;
    }
    zcl_mutex_unlock(&dm->cs);
    return window;
}

void dl_set_peer_loopback(struct download_manager *dm,
                          uint32_t peer_id, bool is_loopback)
{
    if (!dm) return;
    zcl_mutex_lock(&dm->cs);
    struct dl_peer_stats *ps = dl_find_peer(dm, peer_id, true);
    if (ps && ps->is_loopback != is_loopback) {
        ps->is_loopback = is_loopback;
        dl_generation_advance(&dm->capacity_generation);
    }
    zcl_mutex_unlock(&dm->cs);
}

void dl_add_bytes_received(struct download_manager *dm, uint64_t bytes)
{
    zcl_mutex_lock(&dm->cs);
    if (dm->sync_start_time == 0)
        dm->sync_start_time = (int64_t)platform_time_wall_time_t();
    dm->total_bytes_received += bytes;
    zcl_mutex_unlock(&dm->cs);
}

void dl_get_throughput(struct download_manager *dm,
                       uint64_t *total_bytes, double *mbps_avg)
{
    zcl_mutex_lock(&dm->cs);
    if (total_bytes) *total_bytes = dm->total_bytes_received;
    if (mbps_avg) {
        if (dm->sync_start_time > 0 && dm->total_bytes_received > 0) {
            int64_t elapsed = (int64_t)platform_time_wall_time_t() - dm->sync_start_time;
            if (elapsed < 1) elapsed = 1;
            *mbps_avg = (double)dm->total_bytes_received / (1048576.0 * elapsed);
        } else {
            *mbps_avg = 0.0;
        }
    }
    zcl_mutex_unlock(&dm->cs);
}

void dl_get_stats(struct download_manager *dm,
                  uint64_t *requested, uint64_t *received,
                  uint64_t *timed_out, uint64_t *in_flight,
                  uint64_t *queued)
{
    zcl_mutex_lock(&dm->cs);
    if (requested)  *requested  = dm->total_requested;
    if (received)   *received   = dm->total_received;
    if (timed_out)  *timed_out  = dm->total_timed_out;
    if (in_flight)  *in_flight  = dm->num_active;
    if (queued)     *queued     = dm->queue_len;
    zcl_mutex_unlock(&dm->cs);
}

void dl_get_diagnostics(struct download_manager *dm,
                        struct dl_diagnostics *out)
{
    if (!out)
        return;

    struct dl_diagnostics empty = {
        .request_timeout_seconds = dl_get_request_timeout_secs(),
        .oldest_in_flight_age_seconds = -1,
        .oldest_in_flight_height = -1,
        .oldest_in_flight_peer_id = 0,
        .last_assign_result = DL_ASSIGN_NONE,
    };
    *out = empty;
    if (!dm)
        return;

    uint32_t peer_ids[DL_MAX_TRACKED_PEERS];
    size_t peer_count = 0;
    int64_t now = (int64_t)platform_time_wall_time_t();
    int timeout = dl_get_request_timeout_secs();

    zcl_mutex_lock(&dm->cs);
    out->assign_attempts = dm->assign_attempts;
    out->assign_successes = dm->assign_successes;
    out->assign_zero_results = dm->assign_zero_results;
    out->last_assign_peer_id = dm->last_assign_peer_id;
    out->last_assign_max_requested = dm->last_assign_max_requested;
    out->last_assign_available = dm->last_assign_available;
    out->last_assign_assigned = dm->last_assign_assigned;
    out->last_assign_queue_len = dm->last_assign_queue_len;
    out->last_assign_active = dm->last_assign_active;
    out->last_assign_peer_in_flight = dm->last_assign_peer_in_flight;
    out->last_assign_peer_limit = dm->last_assign_peer_limit;
    out->last_assign_global_limit = dm->last_assign_global_limit;
    out->last_assign_result = dm->last_assign_result;
    out->queue_generation = dm->queue_generation;
    out->capacity_generation = dm->capacity_generation;
    out->total_orphaned = dm->total_orphaned;
    out->accounting_drift = (int64_t)dm->total_requested -
                            (int64_t)dm->total_received -
                            (int64_t)dm->total_timed_out -
                            (int64_t)dm->total_orphaned -
                            (int64_t)dm->num_active;
    for (size_t i = 0; i < dm->queue_len; i++) {
        if (dm->queue_classes[i] == DL_WORK_HISTORY)
            out->queued_history++;
        else
            out->queued_forward++;
        if (dm->queue_avoid_until[i] <= now)
            continue;
        int64_t remaining = dm->queue_avoid_until[i] - now;
        out->queue_peer_avoid_count++;
        if (remaining > out->queue_peer_avoid_max_seconds)
            out->queue_peer_avoid_max_seconds = remaining;
    }
    for (size_t i = 0; i < dm->num_slots; i++) {
        struct dl_in_flight *s = &dm->slots[i];
        if (!s->active)
            continue;

        if (s->work_class == DL_WORK_HISTORY)
            out->in_flight_history++;
        else
            out->in_flight_forward++;

        int64_t age = now >= s->request_time ? now - s->request_time : 0;
        if (out->oldest_in_flight_age_seconds < 0 ||
            age > out->oldest_in_flight_age_seconds) {
            out->oldest_in_flight_age_seconds = age;
            out->oldest_in_flight_height = s->height;
            out->oldest_in_flight_peer_id = s->peer_id;
        }
        if (age >= timeout)
            out->overdue_in_flight++;

        bool seen_peer = false;
        for (size_t p = 0; p < peer_count; p++) {
            if (peer_ids[p] == s->peer_id) {
                seen_peer = true;
                break;
            }
        }
        if (!seen_peer && peer_count < sizeof(peer_ids) / sizeof(peer_ids[0]))
            peer_ids[peer_count++] = s->peer_id;
    }
    out->in_flight_peer_count = (uint64_t)peer_count;
    zcl_mutex_unlock(&dm->cs);
}

int64_t dl_last_forced_settle_time(struct download_manager *dm)
{
    if (!dm) return 0;
    zcl_mutex_lock(&dm->cs);
    int64_t t = dm->last_forced_settle_time;
    zcl_mutex_unlock(&dm->cs);
    return t;
}

size_t dl_drain_for_backpressure(struct download_manager *dm)
{
    if (!dm) return 0;
    zcl_mutex_lock(&dm->cs);
    dm->last_forced_settle_time = (int64_t)platform_time_wall_time_t();
    size_t drained = dm->queue_len + dm->num_active;

    /* Drop pending hashes outright — peers won't be re-asked until
     * something else (header sync, reducer activation) re-queues. */
    dm->queue_len = 0;
    qset_clear(dm);

    /* Mark every in-flight slot inactive WITHOUT zeroing its hash:
     * find_slot relies on the hash bits to distinguish a virgin slot
     * from a deletion gap during open-addressing probes. The block
     * body that arrives later finds no active slot, dl_mark_received
     * returns 0, and net_message_free reclaims the buffer as usual.
     * Every dropped in-flight request is settled as orphaned so the
     * requested-vs-settled identity survives the drain. */
    dm->total_orphaned += dm->num_active;
    for (size_t i = 0; i < dm->num_slots; i++)
        dm->slots[i].active = false;
    dm->num_active = 0;
    if (drained > 0)
        dl_generation_advance(&dm->capacity_generation);

    zcl_mutex_unlock(&dm->cs);
    return drained;
}
