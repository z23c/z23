/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: The sender's record of a fleet push, per post and peer. The push
 * stream's close callback runs under the stream lane lock, where nothing may
 * touch the store, so it only copies the receipt into a small bounded ring;
 * the board lane tick, which already owns the store, writes the ring into
 * fleet_board_deliveries (models/fleet_board_delivery.h) and keeps that
 * table to its newest FLEET_BOARD_DELIVERY_KEEP rows. A full ring drops its
 * oldest note and counts it: the record is evidence for the sender, never
 * a condition of delivery, and the pull carries the post either way. */

#include "boot_fleet_board_frame_internal.h"
#include "boot_fleet_board_push_internal.h"
#include "config/boot_fleet_board.h"

#include "models/fleet_board_delivery.h"
#include "util/log_macros.h"
#include "util/sync.h"

#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

/* Machine names for the board results a receipt can carry. */
static const char *const k_result_names[] = {
    [FLEET_BOARD_OK] = "",
    [FLEET_BOARD_ERR_ARGS] = "args",
    [FLEET_BOARD_ERR_KIND] = "kind",
    [FLEET_BOARD_ERR_SCOPE] = "scope",
    [FLEET_BOARD_ERR_ROOM] = "room",
    [FLEET_BOARD_ERR_AGENT] = "agent",
    [FLEET_BOARD_ERR_SLUG] = "slug",
    [FLEET_BOARD_ERR_TITLE] = "title",
    [FLEET_BOARD_ERR_RECEIPT] = "receipt",
    [FLEET_BOARD_ERR_TEXT] = "text",
    [FLEET_BOARD_ERR_TTL] = "ttl",
    [FLEET_BOARD_ERR_FUTURE] = "clock_future",
    [FLEET_BOARD_ERR_EXPIRED] = "expired",
    [FLEET_BOARD_ERR_TRUNCATED] = "truncated",
    [FLEET_BOARD_ERR_TRAILING] = "trailing",
    [FLEET_BOARD_ERR_CAPACITY] = "store_full",
    [FLEET_BOARD_ERR_ID] = "id_mismatch",
    [FLEET_BOARD_ERR_SIGNATURE] = "signature",
    [FLEET_BOARD_ERR_ROLE] = "no_role",
    [FLEET_BOARD_ERR_QUOTA] = "key_quota",
    [FLEET_BOARD_ERR_BUSY] = "busy",
    [FLEET_BOARD_ERR_STORAGE] = "storage",
    [FLEET_BOARD_ERR_WIKI_QUOTA] = "wiki_quota",
    [FLEET_BOARD_ERR_WIKI_FULL] = "wiki_full",
};

/* A push the receiver answered without judging its records: the verdict
 * every record takes. Its reason is the push code's own name. */
static const uint8_t k_code_verdict[FLEET_BOARD_PUSH_CODES] = {
    [FLEET_BOARD_PUSH_CODE_COMMITTED] = FLEET_BOARD_DELIVERY_STORED,
    [FLEET_BOARD_PUSH_CODE_MALFORMED] = FLEET_BOARD_DELIVERY_REFUSED,
    [FLEET_BOARD_PUSH_CODE_AUTHOR] = FLEET_BOARD_DELIVERY_REFUSED,
    [FLEET_BOARD_PUSH_CODE_INBOX_FULL] = FLEET_BOARD_DELIVERY_DEFERRED,
    [FLEET_BOARD_PUSH_CODE_BUSY] = FLEET_BOARD_DELIVERY_DEFERRED,
    [FLEET_BOARD_PUSH_CODE_REVOKED] = FLEET_BOARD_DELIVERY_REFUSED,
    [FLEET_BOARD_PUSH_CODE_UNAVAILABLE] = FLEET_BOARD_DELIVERY_DEFERRED,
};

static zcl_mutex_t g_delivery_lock;
static zcl_once_t g_delivery_once = ZCL_ONCE_INIT;
static struct db_fleet_board_delivery g_ring[FLEET_BOARD_DELIVERY_RING];
static size_t g_ring_head;
static size_t g_ring_len;
static _Atomic size_t g_ring_count;
static _Atomic uint64_t g_ring_dropped;

static void delivery_lock_init(void)
{
    zcl_mutex_init(&g_delivery_lock);
}

static void delivery_lock(void)
{
    (void)zcl_once_call(&g_delivery_once, delivery_lock_init);
    zcl_mutex_lock(&g_delivery_lock);
}

static const char *delivery_result_name(uint8_t result)
{
    if (result >= sizeof(k_result_names) / sizeof(k_result_names[0]) ||
        !k_result_names[result])
        return "unknown";
    return k_result_names[result];
}

/* Append one note; a full ring gives up its oldest. Caller holds the lock. */
static void delivery_put_locked(const uint8_t peer[32], const uint8_t id[32],
                                uint8_t verdict, const char *reason, int64_t at)
{
    if (g_ring_len == FLEET_BOARD_DELIVERY_RING) {
        g_ring_head = (g_ring_head + 1) % FLEET_BOARD_DELIVERY_RING;
        g_ring_len--;
        atomic_fetch_add_explicit(&g_ring_dropped, 1, memory_order_relaxed);
    }
    struct db_fleet_board_delivery *d =
        &g_ring[(g_ring_head + g_ring_len) % FLEET_BOARD_DELIVERY_RING];
    memset(d, 0, sizeof(*d));
    memcpy(d->post_id, id, 32);
    memcpy(d->peer, peer, 32);
    d->verdict = verdict;
    (void)snprintf(d->reason, sizeof(d->reason), "%s", reason);
    d->at = at;
    g_ring_len++;
    atomic_store_explicit(&g_ring_count, g_ring_len, memory_order_relaxed);
}

void board_delivery_note_receipt(const uint8_t peer[32], const uint8_t ids[][32],
                                 uint8_t n, const struct board_push_receipt *rc,
                                 int64_t at)
{
    if (!peer || !ids || !rc || rc->code >= FLEET_BOARD_PUSH_CODES)
        return;
    delivery_lock();
    for (unsigned i = 0; i < n && i < FLEET_BOARD_PUSH_POSTS_MAX; i++) {
        uint8_t verdict = k_code_verdict[rc->code];
        const char *reason = board_push_code_name(rc->code);
        if (rc->code == FLEET_BOARD_PUSH_CODE_COMMITTED && i < rc->n) {
            verdict = rc->rec[i].verdict;
            reason = verdict <= FLEET_BOARD_DELIVERY_HELD
                         ? "" : delivery_result_name(rc->rec[i].result);
        }
        delivery_put_locked(peer, ids[i], verdict, reason, at);
    }
    zcl_mutex_unlock(&g_delivery_lock);
}

void board_delivery_note_unanswered(const uint8_t peer[32], const uint8_t ids[][32],
                                    uint8_t n, const char *reason, int64_t at)
{
    if (!peer || !ids || !reason)
        return;
    delivery_lock();
    for (unsigned i = 0; i < n && i < FLEET_BOARD_PUSH_POSTS_MAX; i++)
        delivery_put_locked(peer, ids[i], FLEET_BOARD_DELIVERY_DEFERRED, reason, at);
    zcl_mutex_unlock(&g_delivery_lock);
}

/* Take the oldest note, false when the ring is empty. */
static bool delivery_take(struct db_fleet_board_delivery *out)
{
    delivery_lock();
    bool any = g_ring_len > 0;
    if (any) {
        *out = g_ring[g_ring_head];
        g_ring_head = (g_ring_head + 1) % FLEET_BOARD_DELIVERY_RING;
        g_ring_len--;
        atomic_store_explicit(&g_ring_count, g_ring_len, memory_order_relaxed);
    }
    zcl_mutex_unlock(&g_delivery_lock);
    return any;
}

static bool delivery_store_free(struct node_db *store)
{
    struct node_db_status status;
    node_db_get_status(store, &status);
    return !status.tx_open;
}

size_t board_delivery_flush(struct node_db *store)
{
    if (!store || !store->open ||
        atomic_load_explicit(&g_ring_count, memory_order_relaxed) == 0)
        return 0;
    /* Somebody else's transaction is open: the notes wait for a later tick
     * rather than join it. */
    if (!delivery_store_free(store))
        return 0;
    size_t saved = 0, taken = 0;
    struct db_fleet_board_delivery d;
    while (taken < FLEET_BOARD_DELIVERY_RING && delivery_take(&d)) {
        taken++;
        if (db_fleet_board_delivery_save(store, &d)) {
            saved++;
            continue;
        }
        atomic_fetch_add_explicit(&g_ring_dropped, 1, memory_order_relaxed);
        LOG_WARN("fleet.board", "a delivery note could not be saved and was "
                 "dropped; the push itself is unaffected");
    }
    if (saved > 0 && !db_fleet_board_delivery_prune(store, FLEET_BOARD_DELIVERY_KEEP))
        LOG_WARN("fleet.board", "delivery record prune failed; the table "
                 "keeps growing until a later prune succeeds");
    return saved;
}

uint64_t board_delivery_dropped(void)
{
    return atomic_load_explicit(&g_ring_dropped, memory_order_relaxed);
}

void board_delivery_forget(void)
{
    delivery_lock();
    g_ring_head = 0;
    g_ring_len = 0;
    atomic_store_explicit(&g_ring_count, 0, memory_order_relaxed);
    atomic_store_explicit(&g_ring_dropped, 0, memory_order_relaxed);
    zcl_mutex_unlock(&g_delivery_lock);
}
