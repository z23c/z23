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
#include "net/file_service.h"
#include "crypto/sha3.h"
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
static struct {
    uint64_t peer, nonce, endpoint_generation;
    int64_t asked_ms, advert_ms;
    uint8_t advert_digest[32];
    uint16_t advert_port;
    bool advertised;
} discovery[PEER_DISCOVERY_MAX];
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
static size_t refresh_offer_wire(int64_t now)
{
    if (offer_wire_ms == INT64_MIN || now < offer_wire_ms || now - offer_wire_ms >= 1000) {
        offer_wire_size = state_offer_collect_wire(offer_wire, sizeof(offer_wire));
        offer_wire_ms = now;
    }
    return offer_wire_size;
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
    if (!refresh_offer_wire(now)) return;
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
    if (discovery[slot].peer == peer &&
        discovery[slot].endpoint_generation == node->endpoint_generation &&
        now - discovery[slot].asked_ms < PEER_DISCOVERY_RETRY_MS) return;
    if (++discovery_nonce == 0) ++discovery_nonce;
    struct state_offer_link_frame f = {.kind = STATE_OFFER_LINK_OFFER_REQUEST, .nonce = discovery_nonce};
    if (!send_frame(mp, node, &f)) return;
    if (discovery[slot].peer != peer ||
        discovery[slot].endpoint_generation != node->endpoint_generation)
        memset(&discovery[slot], 0, sizeof(discovery[slot]));
    discovery[slot].peer = peer; discovery[slot].nonce = f.nonce; discovery[slot].asked_ms = now;
    discovery[slot].endpoint_generation = node->endpoint_generation;
}
/* Only the message owner reads and changes discovery slots. */
static int late_advert_slot(const struct p2p_node *node)
{
    uint64_t peer = boot_zcode_swarm_peer_id(node);
    for (size_t i = 0; i < PEER_DISCOVERY_MAX; ++i)
        if (discovery[i].peer == peer &&
            discovery[i].endpoint_generation == node->endpoint_generation) return (int)i;
    return -1;
}

static bool late_advert_queue_room(struct p2p_node *node, size_t payload)
{
    if (payload > PEER_LINK_QUEUE_BYTES - MSG_HEADER_SIZE) return false;
    size_t total = MSG_HEADER_SIZE + payload;
    zcl_mutex_lock(&node->cs_send);
    size_t hard = net_send_peer_bytes_hard_cap();
    bool room = node->send_size <= PEER_LINK_QUEUE_BYTES - total &&
        (!node->send_size || (total <= hard && node->send_size <= hard - total));
    zcl_mutex_unlock(&node->cs_send);
    return room && !net_send_over_budget(node) && !atomic_load(&node->disconnect);
}

#ifdef ZCL_TESTING
static int64_t g_late_test_offset;
void state_offer_peer_test_advance_advert_ms(int64_t offset) { g_late_test_offset = offset; }
void state_offer_peer_test_invalidate_wire(void) { offer_wire_ms = INT64_MIN; }
#endif
static int64_t late_advert_now(void)
{
    int64_t now = platform_time_monotonic_ms();
#ifdef ZCL_TESTING
    if (g_late_test_offset > 0 && now <= INT64_MAX - g_late_test_offset)
        now += g_late_test_offset;
#endif
    return now;
}

/* A newly available provider batch can be observed up to one second later.
 * Already-advertised sessions recheck at most every 30 seconds; a failed
 * queue attempt does not update the last successful identity or time. */
static void late_advertise(struct msg_processor *mp, struct p2p_node *node)
{
    int slot = late_advert_slot(node);
    if (slot < 0) return;
    if (!fs_server_is_running()) { discovery[slot].advertised = false; return; }
    uint16_t port = fs_server_get_port();
    if (!port) { discovery[slot].advertised = false; return; }
    size_t size = refresh_offer_wire(platform_time_monotonic_ms());
    if (!size) { discovery[slot].advertised = false; return; }
    int64_t now = late_advert_now();
    if (discovery[slot].advertised && now >= discovery[slot].advert_ms &&
        now - discovery[slot].advert_ms < PEER_DISCOVERY_RETRY_MS) return;
    const uint8_t *batch = offer_wire;
    struct sha3_256_ctx hash; uint8_t digest[32];
    sha3_256_init(&hash); sha3_256_write(&hash, (const uint8_t *)&port, sizeof(port));
    sha3_256_write(&hash, batch, size); sha3_256_finalize(&hash, digest);
    if (discovery[slot].advertised && discovery[slot].advert_port == port &&
        memcmp(discovery[slot].advert_digest, digest, sizeof(digest)) == 0) {
        discovery[slot].advert_ms = now;
        return;
    }
    if (!late_advert_queue_room(node, sizeof(port) + size) ||
        !p2p_node_begin_message(node, "zfileaddr", mp->params->pchMessageStart)) return;
    p2p_node_write_message_data(node, (const uint8_t *)&port, sizeof(port));
    p2p_node_write_message_data(node, batch, size);
    if (!p2p_node_end_message(node)) return;
    discovery[slot].advertised = true;
    discovery[slot].advert_port = port;
    discovery[slot].advert_ms = now;
    memcpy(discovery[slot].advert_digest, digest, sizeof(digest));
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
    late_advertise(mp, node);
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
/* Retained link offers are keyed by peer id - 1; drop those of peers that are
 * no longer connected. Only called when the connection snapshot succeeded. */
static void purge_gone_offers(struct p2p_node **nodes, size_t held)
{
    int64_t live[STATE_OFFER_STORE_MAX * 4u] = {0};
    size_t n = 0;
    for (size_t i = 0; i < held; ++i) {
        uint64_t peer = boot_zcode_swarm_peer_id(nodes[i]);
        if (!peer) continue;
        if (n == sizeof(live) / sizeof(live[0])) return; /* cannot prove who is gone */
        live[n++] = (int64_t)(peer - 1);
    }
    (void)state_offer_store_purge_gone_link_peers(live, n);
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
    if (known) purge_gone_offers(nodes, held);
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
