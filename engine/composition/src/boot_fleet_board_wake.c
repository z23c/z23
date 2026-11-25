/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: The "board.wake" mesh stream. A box that newly stored a fleet
 * post tells each roster peer to pull, with the roster proof and no post
 * bytes. The peer pulls on the next lane tick, including a later tick of
 * the same second. The roster pull interval stays the repair for a lost
 * wake. See config/boot_fleet_board.h.
 */

#include "boot_fleet_board_roster_internal.h"

#include "boot_fleet_board_authority_internal.h"
#include "boot_mesh_status_internal.h"
#include "config/boot_fleet_board.h"
#include "config/boot_internal.h"
#include "config/mesh_stream.h"
#include "config/runtime.h"
#include "net/net.h"
#include "net/noise_transport.h"
#include "services/p2p_node_noise.h"
#include "util/sync.h"

#include <stdatomic.h>
#include <string.h>

/* One Noise key due an early roster pull. The table is the peer cap, so a
 * wake cannot buy memory. */
static struct {
    uint8_t key[32];
    bool used;
} g_due[FLEET_BOARD_FLEET_PEERS_MAX];

static zcl_mutex_t g_due_lock;
static zcl_once_t g_due_once = ZCL_ONCE_INIT;
static _Atomic uint64_t g_news;
static uint64_t g_sent;
enum wake_counter {
    WC_NEWS, WC_NO_TARGET, WC_SENT, WC_SEND_FAILED, WC_RECEIVED, WC_REFUSED,
    WC_PULLS, WC_COUNT
};
static _Atomic uint64_t g_wc[WC_COUNT];

static void wake_count(enum wake_counter which)
{
    atomic_fetch_add_explicit(&g_wc[which], 1, memory_order_relaxed);
}

void boot_fleet_board_wake_counts(struct boot_fleet_board_wake_counts *out)
{
    if (!out)
        return;
    uint64_t *const dst[WC_COUNT] = {
        [WC_NEWS] = &out->news, [WC_NO_TARGET] = &out->no_target,
        [WC_SENT] = &out->sent, [WC_SEND_FAILED] = &out->send_failed,
        [WC_RECEIVED] = &out->received, [WC_REFUSED] = &out->refused,
        [WC_PULLS] = &out->pulls,
    };
    for (int i = 0; i < WC_COUNT; i++)
        *dst[i] = atomic_load_explicit(&g_wc[i], memory_order_relaxed);
}

#ifdef ZCL_TESTING
static _Atomic uint64_t g_test_wake_pulls;
#endif

static void wake_lock_init(void)
{
    zcl_mutex_init(&g_due_lock);
}

static void wake_lock(void)
{
    (void)zcl_once_call(&g_due_once, wake_lock_init);
    zcl_mutex_lock(&g_due_lock);
}

static void wake_unlock(void)
{
    zcl_mutex_unlock(&g_due_lock);
}

/* Remember one peer. A repeat is the same pull. A full table drops the new
 * key; the 15 s sweep still asks it. */
static void wake_due_add(const uint8_t key[32])
{
    size_t free_slot = FLEET_BOARD_FLEET_PEERS_MAX;
    wake_lock();
    for (size_t i = 0; i < FLEET_BOARD_FLEET_PEERS_MAX; i++) {
        if (g_due[i].used && memcmp(g_due[i].key, key, 32) == 0) {
            wake_unlock();
            return;
        }
        if (!g_due[i].used && free_slot == FLEET_BOARD_FLEET_PEERS_MAX)
            free_slot = i;
    }
    if (free_slot < FLEET_BOARD_FLEET_PEERS_MAX) {
        memcpy(g_due[free_slot].key, key, 32);
        g_due[free_slot].used = true;
    }
    wake_unlock();
}

static size_t wake_due_take(uint8_t (*out)[32], size_t cap)
{
    size_t n = 0;
    wake_lock();
    for (size_t i = 0; i < FLEET_BOARD_FLEET_PEERS_MAX && n < cap; i++) {
        if (!g_due[i].used)
            continue;
        memcpy(out[n++], g_due[i].key, 32);
        g_due[i].used = false;
    }
    wake_unlock();
    return n;
}

void boot_fleet_board_wake_note(void)
{
    atomic_fetch_add_explicit(&g_news, 1, memory_order_relaxed);
}

void boot_fleet_board_wake_forget(void)
{
    wake_lock();
    memset(g_due, 0, sizeof g_due);
    g_sent = 0;
    wake_unlock();
    atomic_store_explicit(&g_news, 0, memory_order_relaxed);
    boot_fleet_board_roster_push_forget();
}

/* A roster pull this box already has open toward `peer`. */
struct wake_live {
    const uint8_t *peer;
    bool found;
};

static bool wake_pull_live(struct mesh_stream *st, void *ctx)
{
    struct wake_live *live = ctx;
    if (st->local_initiator && !st->ended &&
        memcmp(st->peer_static, live->peer, 32) == 0) {
        live->found = true;
        return false;
    }
    return true;
}

static bool wake_send(struct boot_svc_ctx *svc, const uint8_t peer[32])
{
    struct noise_transport_snapshot snap;
    struct fleet_board_roster_bind bind;
    uint8_t frame[FLEET_BOARD_ROSTER_PROOF_BYTES];
    uint64_t id = 0;
    memset(&snap, 0, sizeof snap);
    memset(&bind, 0, sizeof bind);
    if (!svc || !svc->msg_processor || !svc->msg_processor->net_mgr)
        return false;
    struct p2p_node *node = boot_mesh_find_session_peer(
        svc->msg_processor->net_mgr, peer, &snap);
    if (!node)
        return false;
    p2p_node_release(node);
    memcpy(bind.transcript_hash, snap.transcript_hash, 32);
    bind.connection_generation = snap.connection_generation;
    bind.after = FLEET_BOARD_WAKE_AFTER;
    if (!board_network_genesis(bind.network_genesis) ||
        !fleet_board_roster_proof_make(FLEET_BOARD_ROSTER_SIDE_ASK, &bind,
                                       frame))
        return false;
    /* One byte of credit: the proof rides the OPEN, and the peer closes. */
    return mesh_stream_open(FLEET_BOARD_WAKE_SERVICE_NAME, peer, 1u, frame,
                            sizeof frame, NULL, &id) == MESH_STREAM_OK;
}

static void wake_send_news(struct boot_svc_ctx *svc, struct node_db *store,
                           int64_t now)
{
    uint8_t keys[FLEET_BOARD_FLEET_PEERS_MAX][32];
    uint64_t news = atomic_load_explicit(&g_news, memory_order_relaxed);
    struct node_db *pairings = app_runtime_node_db();
    size_t n;
    wake_lock();
    if (news == g_sent) {
        wake_unlock();
        return;
    }
    g_sent = news;
    wake_count(WC_NEWS);
    wake_unlock();
    if (!pairings || !app_runtime_node_db_handle_open(pairings))
        return;
    n = fleet_board_roster_targets(svc, pairings, store, now, keys,
                                   FLEET_BOARD_FLEET_PEERS_MAX);
    if (n == 0)
        wake_count(WC_NO_TARGET);
    for (size_t i = 0; i < n; i++)
        wake_count(wake_send(svc, keys[i]) ? WC_SENT : WC_SEND_FAILED);
}

static void wake_pull_due(struct boot_svc_ctx *svc)
{
    uint8_t keys[FLEET_BOARD_FLEET_PEERS_MAX][32];
    size_t n = wake_due_take(keys, FLEET_BOARD_FLEET_PEERS_MAX);
    for (size_t i = 0; i < n; i++) {
        struct wake_live live = { keys[i], false };
        mesh_stream_visit(FLEET_BOARD_ROSTER_SERVICE_NAME, wake_pull_live,
                          &live);
        if (live.found) {
            wake_due_add(keys[i]);
            continue;
        }
        if (board_open_roster_pull(svc, keys[i])) {
            wake_count(WC_PULLS);
#ifdef ZCL_TESTING
            atomic_fetch_add_explicit(&g_test_wake_pulls, 1,
                                     memory_order_relaxed);
#endif
        }
    }
}

void boot_fleet_board_wake_tick(struct boot_svc_ctx *svc, struct node_db *store,
                                int64_t now)
{
    if (now <= 0 || !svc || !store)
        return;
    wake_send_news(svc, store, now);
    wake_pull_due(svc);
}

/* The proof only. A pull frame, a short frame, or a proof bound to any
 * other cursor is not a wake. Nothing in the reply is a post. */
static enum mesh_stream_refusal wake_on_open(struct mesh_stream *st,
                                             const uint8_t *payload, size_t len,
                                             uint8_t *reply, size_t reply_cap,
                                             size_t *reply_len, void *ctx)
{
    struct fleet_board_roster_bind bind;
    struct node_db *pairings;
    struct node_db *store;
    (void)reply;
    (void)reply_cap;
    (void)ctx;
    if (reply_len)
        *reply_len = 0;
    if (!payload || len != FLEET_BOARD_ROSTER_PROOF_BYTES) {
        wake_count(WC_REFUSED);
        return MESH_STREAM_REFUSED_MALFORMED;
    }
    pairings = app_runtime_node_db();
    store = board_db();
    memset(&bind, 0, sizeof bind);
    if (!pairings || !app_runtime_node_db_handle_open(pairings) || !store ||
        !board_network_genesis(bind.network_genesis)) {
        wake_count(WC_REFUSED);
        return MESH_STREAM_REFUSED_UNAVAILABLE;
    }
    memcpy(bind.transcript_hash, st->transcript_hash, 32);
    bind.connection_generation = st->connection_generation;
    bind.after = FLEET_BOARD_WAKE_AFTER;
    if (!fleet_board_roster_admit(pairings, store, &bind, st->peer_static,
                                  payload, board_now()) ||
        !board_peer_may_read(payload)) {
        wake_count(WC_REFUSED);
        return MESH_STREAM_REFUSED_PEER_UNPAIRED;
    }
    wake_count(WC_RECEIVED);
    wake_due_add(st->peer_static);
    /* The slot must not linger open: a wake is one OPEN and a CLOSE. */
    mesh_stream_close(st, MESH_STREAM_CLOSED_BY_SERVICE, NULL, 0);
    return MESH_STREAM_OK;
}

static void wake_on_data(struct mesh_stream *st, const uint8_t *payload,
                         size_t len, void *ctx)
{
    (void)payload;
    (void)len;
    (void)ctx;
    mesh_stream_close(st, MESH_STREAM_REFUSED_MALFORMED, NULL, 0);
}

static void wake_on_tick(struct mesh_stream *st, int64_t now, void *ctx)
{
    (void)now;
    (void)ctx;
    if (st && !st->ended)
        mesh_stream_close(st, MESH_STREAM_CLOSED_BY_SERVICE, NULL, 0);
}

bool boot_fleet_board_wake_register(void)
{
    struct mesh_stream_service service;
    memset(&service, 0, sizeof service);
    mesh_stream_service_unregister(FLEET_BOARD_WAKE_SERVICE_NAME);
    service.name = FLEET_BOARD_WAKE_SERVICE_NAME;
    service.required_pairing_capability = 0;
    service.on_open = wake_on_open;
    service.on_data = wake_on_data;
    service.on_tick = wake_on_tick;
    return mesh_stream_service_register(&service) &&
           boot_fleet_board_roster_push_register();
}

#ifdef ZCL_TESTING
uint64_t boot_fleet_board_wake_test_due(void)
{
    uint64_t n = 0;
    wake_lock();
    for (size_t i = 0; i < FLEET_BOARD_FLEET_PEERS_MAX; i++)
        n += g_due[i].used ? 1u : 0u;
    wake_unlock();
    return n;
}

uint64_t boot_fleet_board_wake_test_pulls(void)
{
    return atomic_load_explicit(&g_test_wake_pulls, memory_order_relaxed);
}
#endif
