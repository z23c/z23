/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * Discover and transfer verified state through existing public peer links. */
#include "config/state_offer_peer.h"
#include "config/state_offer_link.h"
#include "config/state_offer_link_session.h"
#include "config/state_offer_store.h"
#include "config/boot_zcode_swarm.h"
#include "config/boot_zcode_swarm_membership.h"
#include "net/msgprocessor.h"
#include "net/net.h"
#include "net/state_offer.h"
#include "platform/time_compat.h"
#include "base/safe_alloc.h"
#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

#define PEER_DISCOVERY_MAX 64u
#define PEER_DISCOVERY_RETRY_MS 30000
#define PEER_LINK_QUEUE_BYTES (1024u * 1024u)
#define PEER_LINK_BURST 16u
static struct { uint64_t peer, nonce; int64_t asked_ms; } discovery[PEER_DISCOVERY_MAX];
static struct { uint64_t peer; int64_t answered_ms; } replies[PEER_DISCOVERY_MAX];
static uint8_t offer_wire[STATE_OFFER_BATCH_V1_MAX_WIRE_BYTES];
static size_t offer_wire_size;
static int64_t offer_wire_ms;
static uint64_t discovery_nonce;
static _Atomic uint64_t receiving_peer;
static pthread_mutex_t drain_lock = PTHREAD_MUTEX_INITIALIZER;

static bool eligible(const struct p2p_node *node)
{
    return node && boot_zcode_swarm_eligible(node) && (node->services & NODE_STATE_OFFER_LINK);
}

static void wake(void *ctx) { (void)ctx; boot_zcode_swarm_request_tick(); }
bool state_offer_peer_start(const char *datadir)
{
    memset(discovery, 0, sizeof(discovery));
    memset(replies, 0, sizeof(replies));
    offer_wire_size = 0;
    offer_wire_ms = -1000;
    return state_offer_link_server_start(datadir, boot_zcode_swarm_request_tick);
}
bool state_offer_peer_begin(uint64_t peer)
{
    if (!sol_client_start(peer, wake, NULL)) return false;
    atomic_store(&receiving_peer, peer);
    return true;
}
void state_offer_peer_end(uint64_t peer)
{
    sol_client_drop(peer);
    (void)atomic_compare_exchange_strong(&receiving_peer, &peer, 0);
}
bool state_offer_peer_serving_held_fetch(const struct p2p_node *node)
{
    if (!node || !msg_processor_header_sync_held()) return false;
    uint64_t peer = atomic_load(&receiving_peer);
    if (!peer || peer != boot_zcode_swarm_peer_id(node)) return false;
    int64_t last = sol_client_last_progress_ms();
    /* A future stamp (clock step) counts as recent rather than as a cut. */
    return last != INT64_MIN &&
           platform_time_monotonic_ms() - last < STATE_OFFER_FETCH_PROGRESS_WINDOW_MS;
}
void state_offer_peer_shutdown(void)
{
    sol_client_shutdown();
    atomic_store(&receiving_peer, 0);
    state_offer_link_server_shutdown();
}
static bool queue_room(struct p2p_node *node)
{
    zcl_mutex_lock(&node->cs_send);
    bool room = node->send_size <= PEER_LINK_QUEUE_BYTES - STATE_OFFER_LINK_FRAME_MAX;
    zcl_mutex_unlock(&node->cs_send);
    return room && !net_send_over_budget(node) && !atomic_load(&node->disconnect);
}
static bool send_wire(struct msg_processor *mp, struct p2p_node *node, const uint8_t *wire, size_t size)
{
    if (!p2p_node_begin_message(node, "zpkgswm", mp->params->pchMessageStart)) return false;
    p2p_node_write_message_data(node, wire, size);
    return p2p_node_end_message(node);
}
static bool send_frame(struct msg_processor *mp, struct p2p_node *node, const struct state_offer_link_frame *f)
{
    uint8_t wire[STATE_OFFER_LINK_FRAME_MAX]; size_t size = 0;
    return queue_room(node) && state_offer_link_encode(f, wire, sizeof(wire), &size) && send_wire(mp, node, wire, size);
}
static void discovery_reply(struct msg_processor *mp, struct p2p_node *node, uint64_t nonce)
{
    uint64_t peer = boot_zcode_swarm_peer_id(node);
    int64_t now = platform_time_monotonic_ms();
    size_t slot = 0;
    for (size_t i = 0; i < PEER_DISCOVERY_MAX; ++i) {
        if (replies[i].peer == peer) { slot = i; break; }
        if (!replies[i].peer || replies[i].answered_ms < replies[slot].answered_ms) slot = i;
    }
    if (replies[slot].peer == peer && now - replies[slot].answered_ms < 5000) return;
    replies[slot].peer = peer;
    replies[slot].answered_ms = now;
    if (now - offer_wire_ms >= 1000) {
        offer_wire_size = state_offer_collect_wire(offer_wire, sizeof(offer_wire));
        offer_wire_ms = now;
    }
    if (!offer_wire_size) return;
    struct state_offer_link_frame f = {.kind = STATE_OFFER_LINK_OFFER_REPLY, .nonce = nonce,
        .total = (uint32_t)offer_wire_size, .size = (uint32_t)offer_wire_size, .data = offer_wire};
    (void)send_frame(mp, node, &f);
}
static void discovery_receive(uint64_t peer, const struct state_offer_link_frame *f)
{
    size_t i = 0;
    while (i < PEER_DISCOVERY_MAX && (discovery[i].peer != peer || discovery[i].nonce != f->nonce)) ++i;
    if (i == PEER_DISCOVERY_MAX) return;
    struct state_offer_batch_v1 batch;
    if (state_offer_batch_v1_decode(&batch, f->data, f->size) != STATE_OFFER_OK) return;
    for (uint32_t j = 0; j < batch.count; ++j)
        if (state_offer_v1_verify(&batch.offers[j]) != STATE_OFFER_OK) return;
    discovery[i].nonce = 0;
    for (uint32_t j = 0; j < batch.count; ++j)
        (void)state_offer_store_record_link(&batch.offers[j], (int64_t)(peer - 1), platform_time_monotonic_ms());
}
bool state_offer_peer_frame(struct msg_processor *mp, struct p2p_node *node, const uint8_t *wire, size_t len)
{
    if (len < 4 || memcmp(wire, "ZBND", 4)) return false;
    if (!eligible(node)) return true;
    struct state_offer_link_frame f;
    if (!state_offer_link_decode(wire, len, &f)) return true;
    uint64_t peer = boot_zcode_swarm_peer_id(node);
    if (f.kind == STATE_OFFER_LINK_OFFER_REQUEST) discovery_reply(mp, node, f.nonce);
    else if (f.kind == STATE_OFFER_LINK_OFFER_REPLY) discovery_receive(peer, &f);
    else if (f.kind == STATE_OFFER_LINK_MANIFEST_REQUEST || f.kind == STATE_OFFER_LINK_CHUNK_REQUEST) {
        if (!state_offer_link_server_request(peer, node->addr.svc.addr.ip, &f)) {
            struct state_offer_link_frame refusal = {
                .kind = STATE_OFFER_LINK_REFUSAL, .nonce = f.nonce};
            memcpy(refusal.digest, f.digest, sizeof(refusal.digest));
            (void)send_frame(mp, node, &refusal);
        }
    }
    else (void)sol_client_consume(peer, &f);
    boot_zcode_swarm_request_tick();
    return true;
}
static void discover(struct msg_processor *mp, struct p2p_node *node)
{
    uint64_t peer = boot_zcode_swarm_peer_id(node);
    int64_t now = platform_time_monotonic_ms();
    size_t slot = 0;
    for (size_t i = 0; i < PEER_DISCOVERY_MAX; ++i) {
        if (discovery[i].peer == peer) { slot = i; break; }
        if (!discovery[i].peer || discovery[i].asked_ms < discovery[slot].asked_ms) slot = i;
    }
    if (discovery[slot].peer == peer && now - discovery[slot].asked_ms < PEER_DISCOVERY_RETRY_MS) return;
    if (++discovery_nonce == 0) ++discovery_nonce;
    struct state_offer_link_frame f = {.kind = STATE_OFFER_LINK_OFFER_REQUEST, .nonce = discovery_nonce};
    if (!send_frame(mp, node, &f)) return;
    discovery[slot].peer = peer; discovery[slot].nonce = f.nonce; discovery[slot].asked_ms = now;
}
static void drain(struct msg_processor *mp, struct p2p_node *node)
{
    if (pthread_mutex_trylock(&drain_lock)) return;
    uint64_t peer = boot_zcode_swarm_peer_id(node);
    uint8_t wire[STATE_OFFER_LINK_FRAME_MAX];
    unsigned sent = 0;
    for (; sent < PEER_LINK_BURST && queue_room(node); ++sent) {
        size_t size = 0; struct state_offer_link_frame f;
        bool have = sol_client_poll(peer, &f) ? state_offer_link_encode(&f, wire, sizeof(wire), &size) :
            state_offer_link_server_next(peer, wire, sizeof(wire), &size);
        if (!have) break;
        if (!send_wire(mp, node, wire, size)) {
            sol_client_drop(peer); state_offer_link_server_drop(peer); break;
        }
    }
    pthread_mutex_unlock(&drain_lock);
    if (sent == PEER_LINK_BURST && queue_room(node))
        boot_zcode_swarm_request_tick();
}
void state_offer_peer_tick(struct msg_processor *mp, struct p2p_node *node)
{
    if (!mp || !node || !eligible(node)) return;
    discover(mp, node);
    drain(mp, node);
}
static struct p2p_node **hold_peers(struct net_manager *nm, size_t *count, size_t *held)
{
    zcl_mutex_lock(&nm->cs_nodes);
    *count = nm->num_nodes;
    struct p2p_node **nodes = *count <= SIZE_MAX / sizeof(*nodes) ? zcl_malloc(*count * sizeof(*nodes), "state_offer_peer_nodes") : NULL;
    if (nodes) for (size_t i = 0; i < *count; ++i) {
        if (!eligible(nm->nodes[i])) continue;
        nodes[(*held)++] = nm->nodes[i]; p2p_node_add_ref(nm->nodes[i]);
    }
    zcl_mutex_unlock(&nm->cs_nodes);
    return nodes;
}
static bool peer_held(struct p2p_node **nodes, size_t held, uint64_t peer)
{
    for (size_t i = 0; i < held; ++i)
        if (boot_zcode_swarm_peer_id(nodes[i]) == peer) return true;
    return false;
}
/* Drain every eligible connection, then release client and server state for
 * connections that are gone. A failed snapshot proves nothing is gone. */
void state_offer_peer_pump(struct msg_processor *mp)
{
    if (!mp || !mp->net_mgr) return;
    struct net_manager *nm = mp->net_mgr;
    uint64_t receiving = atomic_load(&receiving_peer);
    uint64_t serving[STATE_OFFER_LINK_SERVER_SLOTS];
    size_t serving_count = state_offer_link_server_peers(serving, STATE_OFFER_LINK_SERVER_SLOTS);
    size_t count = 0, held = 0;
    struct p2p_node **nodes = hold_peers(nm, &count, &held);
    for (size_t i = 0; i < held; ++i) drain(mp, nodes[i]);
    bool known = nodes || !count;
    bool drop_receiving = receiving && known && !peer_held(nodes, held, receiving);
    for (size_t i = 0; i < serving_count; ++i)
        if (!known || peer_held(nodes, held, serving[i])) serving[i] = 0;
    zcl_mutex_lock(&nm->cs_nodes);
    for (size_t i = 0; i < held; ++i)
        p2p_node_release(nodes[i]);
    zcl_mutex_unlock(&nm->cs_nodes);
    if (drop_receiving) sol_client_drop(receiving);
    for (size_t i = 0; i < serving_count; ++i)
        if (serving[i]) state_offer_link_server_drop(serving[i]);
    free(nodes);
    state_offer_link_server_tick();
}
