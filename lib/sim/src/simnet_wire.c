/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Deterministic in-memory P2P wire transport for a real p2p_node.
 */

#include "simnet_wire_internal.h"

#include "core/hash.h"
#include "core/serialize.h"
#include "event/event.h"
#include "net/fast_sync.h"
#include "net/net_fault.h"
#include "net/p2p_message.h"
#include "net/peer_scoring.h"
#include "net/version.h"
#include "platform/clock.h"
#include "platform/rng.h"
#include "platform/time_compat.h"
#include "primitives/block.h"
#include "util/blocker.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"

#include <stdio.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

static uint64_t simnet_wire_now_us(void)
{
    int64_t ns = clock_now_monotonic_ns();
    if (ns <= 0)
        return 0;
    return (uint64_t)ns / 1000u;
}

uint64_t simnet_wire_splitmix64_value(uint64_t x)
{
    uint64_t z = x + 0x9E3779B97F4A7C15ULL;
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

uint64_t simnet_wire_fnv_bytes(const uint8_t *bytes, size_t len)
{
    uint64_t h = SIMNET_WIRE_FNV_OFFSET;
    for (size_t i = 0; i < len; i++) {
        h ^= bytes[i];
        h *= SIMNET_WIRE_FNV_PRIME;
    }
    return h;
}

void simnet_wire_fp_mix(struct simnet_wire *wire, size_t peer_id,
                        uint8_t direction, const uint8_t *bytes,
                        size_t len)
{
    uint64_t h = wire->fingerprint ? wire->fingerprint
                                   : SIMNET_WIRE_FNV_OFFSET;
    h ^= (uint64_t)peer_id + 0x9e3779b97f4a7c15ULL;
    h *= SIMNET_WIRE_FNV_PRIME;
    h ^= direction;
    h *= SIMNET_WIRE_FNV_PRIME;
    h ^= (uint64_t)len;
    h *= SIMNET_WIRE_FNV_PRIME;
    for (size_t i = 0; i < len; i++) {
        h ^= bytes[i];
        h *= SIMNET_WIRE_FNV_PRIME;
    }
    wire->fingerprint = h;
}

static bool ring_init(struct wire_byte_ring *ring, size_t cap)
{
    if (!ring)
        LOG_FAIL("simnet.wire", "NULL ring init");
    memset(ring, 0, sizeof(*ring));
    if (cap == 0)
        cap = SIMNET_WIRE_DEFAULT_RING_CAP;
    ring->data = zcl_malloc(cap, "simnet_wire_ring");
    if (!ring->data)
        LOG_FAIL("simnet.wire", "OOM allocating ring cap=%zu", cap);
    ring->cap = cap;
    return true;
}

static void ring_free(struct wire_byte_ring *ring)
{
    if (!ring)
        return;
    free(ring->data);
    memset(ring, 0, sizeof(*ring));
}

static size_t ring_available(const struct wire_byte_ring *ring)
{
    return ring ? ring->len : 0;
}

static bool ring_copy_out(const struct wire_byte_ring *ring, size_t off,
                          uint8_t *out, size_t len)
{
    if (!ring || (!out && len > 0) || off > ring->len ||
        len > ring->len - off)
        LOG_FAIL("simnet.wire", "invalid ring copy off=%zu len=%zu", off,
                 len);
    for (size_t i = 0; i < len; i++)
        out[i] = ring->data[(ring->head + off + i) % ring->cap];
    return true;
}

static bool ring_grow(struct wire_byte_ring *ring, size_t need)
{
    if (!ring)
        LOG_FAIL("simnet.wire", "NULL ring grow");
    if (need <= ring->cap)
        return true;

    size_t new_cap = ring->cap ? ring->cap : SIMNET_WIRE_DEFAULT_RING_CAP;
    while (new_cap < need)
        new_cap *= 2u;

    uint8_t *grown = zcl_malloc(new_cap, "simnet_wire_ring_grow");
    if (!grown)
        LOG_FAIL("simnet.wire", "OOM growing ring to %zu", new_cap);
    if (ring->len > 0 && !ring_copy_out(ring, 0, grown, ring->len)) {
        free(grown);
        return false;
    }
    free(ring->data);
    ring->data = grown;
    ring->cap = new_cap;
    ring->head = 0;
    return true;
}

static bool ring_write(struct wire_byte_ring *ring, const uint8_t *bytes,
                       size_t len)
{
    if (!ring || (!bytes && len > 0))
        LOG_FAIL("simnet.wire", "invalid ring write len=%zu", len);
    if (!ring_grow(ring, ring->len + len))
        return false;
    size_t tail = (ring->head + ring->len) % ring->cap;
    for (size_t i = 0; i < len; i++)
        ring->data[(tail + i) % ring->cap] = bytes[i];
    ring->len += len;
    return true;
}

static const uint8_t *ring_linear_ptr(const struct wire_byte_ring *ring,
                                      size_t *out_len)
{
    if (!ring || !out_len)
        return NULL;
    if (ring->len == 0) {
        *out_len = 0;
        return NULL;
    }
    size_t until_end = ring->cap - ring->head;
    *out_len = ring->len < until_end ? ring->len : until_end;
    return ring->data + ring->head;
}

static bool ring_drop(struct wire_byte_ring *ring, size_t len)
{
    if (!ring || len > ring->len)
        LOG_FAIL("simnet.wire", "invalid ring drop len=%zu", len);
    ring->head = (ring->head + len) % ring->cap;
    ring->len -= len;
    if (ring->len == 0)
        ring->head = 0;
    return true;
}

static bool ring_read(struct wire_byte_ring *ring, uint8_t *out, size_t len)
{
    if (!ring_copy_out(ring, 0, out, len))
        return false;
    return ring_drop(ring, len);
}

static void simnet_wire_init_peer_addr(struct net_address *addr,
                                       size_t peer_id,
                                       const struct chain_params *params)
{
    static const unsigned char base_ip[4] = {198, 51, 100, 1};
    unsigned char ip[4];

    net_address_init(addr);
    addr->nServices = NODE_NETWORK;
    memcpy(ip, base_ip, sizeof(ip));
    ip[3] = (unsigned char)(10u + (peer_id % 200u));
    net_addr_set_ipv4(&addr->svc.addr, ip);
    addr->svc.port = params ? (uint16_t)params->nDefaultPort : 8033u;
}

static bool simnet_wire_stub_submit_block(struct block *block,
                                          struct validation_state *out,
                                          void *ctx)
{
    (void)block;
    (void)ctx;
    if (out)
        validation_state_error(out, "simnet-wire-threadless-block-submit");
    LOG_FAIL("simnet.wire", "unexpected block submit in wire harness");
}

static void simnet_wire_event_observer(enum event_type type, uint32_t peer_id,
                                       const void *payload,
                                       uint32_t payload_len, void *ctx)
{
    (void)peer_id;
    (void)payload;
    (void)payload_len;
    struct simnet_wire *wire = (struct simnet_wire *)ctx;
    if (!wire)
        return;
    if (type == EV_MSG_CHECKSUM_FAIL)
        wire->events.checksum_fail++;
    else if (type == EV_PEER_MISBEHAVE)
        wire->events.peer_misbehave++;
    else if (type == EV_BACKPRESSURE_REJECT)
        wire->events.backpressure_reject++;
    else if (type == EV_PEER_BANNED)
        wire->events.peer_banned++;
    else if (type == EV_BLOCK_REJECTED)
        wire->events.block_rejected++;
    else if (type == EV_HEADERS_REJECTED)
        wire->events.headers_rejected++;
    simnet_wire_byzantine_observe_event(wire, type, payload, payload_len);
}

static bool simnet_wire_install_event_observers(struct simnet_wire *wire)
{
    if (!wire)
        LOG_FAIL("simnet.wire", "NULL observer owner");
    event_log_init();
    bool ok =
        event_observe(EV_MSG_CHECKSUM_FAIL, simnet_wire_event_observer,
                      wire) &&
        event_observe(EV_PEER_MISBEHAVE, simnet_wire_event_observer,
                      wire) &&
        event_observe(EV_BACKPRESSURE_REJECT, simnet_wire_event_observer,
                      wire) &&
        event_observe(EV_PEER_BANNED, simnet_wire_event_observer, wire) &&
        event_observe(EV_BLOCK_REJECTED, simnet_wire_event_observer,
                      wire) &&
        event_observe(EV_HEADERS_REJECTED, simnet_wire_event_observer,
                      wire);
    if (!ok)
        LOG_FAIL("simnet.wire", "failed to install event observers");
    return true;
}

static void simnet_wire_clear_event_observers(void)
{
    event_clear_observers(EV_MSG_CHECKSUM_FAIL);
    event_clear_observers(EV_PEER_MISBEHAVE);
    event_clear_observers(EV_BACKPRESSURE_REJECT);
    event_clear_observers(EV_PEER_BANNED);
    event_clear_observers(EV_BLOCK_REJECTED);
    event_clear_observers(EV_HEADERS_REJECTED);
}

static bool simnet_wire_install_send_sentinel(struct simnet_wire *wire,
                                              size_t peer_id)
{
    if (!wire || peer_id >= wire->peer_count || !wire->peers[peer_id].node)
        LOG_FAIL("simnet.wire", "invalid sentinel install peer=%zu", peer_id);
    struct p2p_node *node = wire->peers[peer_id].node;
    struct send_segment *sentinel =
        zcl_calloc(1, sizeof(*sentinel), "simnet_wire_send_sentinel");
    if (!sentinel)
        LOG_FAIL("simnet.wire", "OOM allocating send sentinel");

    zcl_mutex_lock(&node->cs_send);
    node->send_head = sentinel;
    node->send_tail = sentinel;
    node->send_offset = 0;
    zcl_mutex_unlock(&node->cs_send);

    wire->peers[peer_id].send_sentinel = sentinel;
    return true;
}

static bool simnet_wire_init_runtime(struct simnet_wire *wire, uint64_t seed)
{
    if (!simnet_wire_install_event_observers(wire))
        return false;
    wire->tape = seed_tape_open(seed, 1700000000);
    if (!wire->tape)
        LOG_FAIL("simnet.wire", "seed_tape_open failed");
    seed_tape_install(wire->tape);

    wire->params = chain_params_get();

    main_state_init(&wire->ms);
    wire->main_ready = true;
    tx_mempool_init(&wire->mempool, 0);
    wire->mempool_ready = true;
    memset(&wire->null_view, 0, sizeof(wire->null_view));
    coins_view_cache_init(&wire->coins_tip, &wire->null_view);
    wire->coins_ready = true;
    net_manager_init(&wire->nm);
    wire->net_ready = true;
    memcpy(wire->nm.message_start, wire->params->pchMessageStart,
           MESSAGE_START_SIZE);
    wire->nm.default_port = (uint16_t)wire->params->nDefaultPort;
    wire->nm.local_services = NODE_NETWORK;
    wire->nm.local_host_nonce = rng_u64();
    if (wire->nm.local_host_nonce == 0)
        wire->nm.local_host_nonce = 1;

    memset(&wire->mp, 0, sizeof(wire->mp));
    wire->mp.main_state = &wire->ms;
    wire->mp.mempool = &wire->mempool;
    wire->mp.coins_tip = &wire->coins_tip;
    wire->mp.params = wire->params;
    wire->mp.datadir = ".";
    wire->mp.net_mgr = &wire->nm;
    wire->mp.block_submit = simnet_wire_byzantine_submit_block;
    wire->mp.block_submit_ctx = wire;
    wire->mp.compact_block_submit = simnet_wire_stub_submit_block;

    /* The per-peer p2p_node instances are created in simnet_wire_create()
     * once each peer slot's address is initialized (D2); wire->nut is then
     * aliased to peers[0].node. The msg_processor above is shared across
     * every node — one context, N connections, exactly the real model. */
    return true;
}

/* D2: create one independent p2p_node per peer slot and capture its egress.
 * Each node has its own recv/send queues, handshake state machine and ban
 * scoring, and a distinct peer address so a ban on one connection never
 * touches another (the property the eclipse test relies on). */
static bool simnet_wire_create_peer_node(struct simnet_wire *wire,
                                         size_t peer_id)
{
    if (!wire || peer_id >= wire->peer_count)
        LOG_FAIL("simnet.wire", "invalid peer node create peer=%zu", peer_id);
    struct wire_peer *peer = &wire->peers[peer_id];
    char name[32];
    snprintf(name, sizeof(name), "simnet-wire-peer%zu", peer_id);
    peer->node = p2p_node_create(&wire->nm, ZCL_INVALID_SOCKET, &peer->addr,
                                 name, true);
    if (!peer->node)
        LOG_FAIL("simnet.wire", "p2p_node_create failed peer=%zu", peer_id);
    peer->node->services = NODE_NETWORK;
    peer->node->network_node = true;
    peer->node->relay_txes = true;
    return simnet_wire_install_send_sentinel(wire, peer_id);
}

static bool simnet_wire_event_less(const struct wire_event *a,
                                   const struct wire_event *b)
{
    if (a->deliver_us != b->deliver_us)
        return a->deliver_us < b->deliver_us;
    return a->seq < b->seq;
}

static bool simnet_wire_find_next_event(const struct simnet_wire *wire,
                                        size_t *out_idx)
{
    if (!wire || !out_idx)
        LOG_FAIL("simnet.wire", "invalid event scan");
    if (wire->queue_count == 0)
        return false;

    size_t best = 0;
    for (size_t i = 1; i < wire->queue_count; i++) {
        if (simnet_wire_event_less(&wire->queue[i], &wire->queue[best]))
            best = i;
    }
    *out_idx = best;
    return true;
}

static void simnet_wire_remove_event(struct simnet_wire *wire, size_t idx)
{
    if (!wire || idx >= wire->queue_count)
        return;
    free(wire->queue[idx].bytes);
    wire->queue[idx] = wire->queue[wire->queue_count - 1];
    wire->queue_count--;
}

static bool simnet_wire_ensure_queue(struct simnet_wire *wire)
{
    if (!wire)
        LOG_FAIL("simnet.wire", "NULL queue owner");
    if (wire->queue_count < wire->queue_cap)
        return true;
    size_t new_cap = wire->queue_cap ? wire->queue_cap * 2u : 16u;
    struct wire_event *grown =
        zcl_realloc(wire->queue, new_cap * sizeof(*grown),
                    "simnet_wire_events");
    if (!grown)
        LOG_FAIL("simnet.wire", "OOM growing event queue to %zu", new_cap);
    wire->queue = grown;
    wire->queue_cap = new_cap;
    return true;
}

static bool simnet_wire_enqueue(struct simnet_wire *wire, size_t peer_id,
                                enum wire_event_kind kind,
                                const uint8_t *bytes, size_t len)
{
    if (!wire || peer_id >= wire->peer_count || (!bytes && len > 0))
        LOG_FAIL("simnet.wire", "invalid enqueue peer=%zu len=%zu",
                 peer_id, len);
    if (!simnet_wire_ensure_queue(wire))
        return false;

    uint64_t latency =
        SIMNET_WIRE_MIN_LATENCY_US +
        (rng_u64() % SIMNET_WIRE_LATENCY_SPAN_US);
    uint64_t reorder = rng_u64() % SIMNET_WIRE_REORDER_SPAN_US;
    uint64_t deliver_us = simnet_wire_now_us() + latency + reorder;

    uint8_t *copy = NULL;
    if (len > 0) {
        copy = zcl_malloc(len, "simnet_wire_event_bytes");
        if (!copy)
            LOG_FAIL("simnet.wire", "OOM copying event bytes len=%zu", len);
        memcpy(copy, bytes, len);
    }

    struct wire_event *ev = &wire->queue[wire->queue_count++];
    memset(ev, 0, sizeof(*ev));
    ev->peer_id = peer_id;
    ev->deliver_us = deliver_us;
    ev->seq = wire->next_seq++;
    ev->kind = kind;
    ev->bytes = copy;
    ev->len = len;

    struct wire_event_record rec;
    memset(&rec, 0, sizeof(rec));
    rec.peer_id = peer_id;
    rec.deliver_us = deliver_us;
    rec.seq = ev->seq;
    rec.len = len;
    rec.bytes_hash = simnet_wire_fnv_bytes(bytes, len);
    rec.kind = (uint8_t)kind;
    int rc = seed_tape_inject(wire->tape, SIMNET_WIRE_EVENT_ENQUEUED,
                              &rec, sizeof(rec));
    if (rc != 0)
        LOG_FAIL("simnet.wire", "seed_tape_inject failed rc=%d", rc);
    return true;
}

bool simnet_wire_enqueue_raw(struct simnet_wire *wire, size_t peer_id,
                             const uint8_t *bytes, size_t len)
{
    return simnet_wire_enqueue(wire, peer_id, WIRE_EVENT_DELIVER_TO_NUT,
                               bytes, len);
}

bool simnet_wire_partition_peer(struct simnet_wire *wire, size_t peer_id,
                                bool closed)
{
    if (!wire || peer_id >= wire->peer_count)
        LOG_FAIL("simnet.wire", "invalid partition peer=%zu", peer_id);
    return simnet_wire_enqueue(
        wire, peer_id, closed ? WIRE_EVENT_CLOSE : WIRE_EVENT_OPEN,
        NULL, 0);
}

bool simnet_wire_set_link_bandwidth(struct simnet_wire *wire, size_t peer_id,
                                    size_t down_cap, size_t up_cap)
{
    if (!wire || peer_id >= wire->peer_count)
        LOG_FAIL("simnet.wire", "invalid bandwidth peer=%zu", peer_id);
    struct wire_link *link = &wire->peers[peer_id].link;
    link->down_cap = down_cap;
    link->up_cap = up_cap;
    /* Seed the running budget immediately so a cap set before the first
     * tick binds that tick too (the per-tick refill in simnet_wire_tick
     * keeps it topped up thereafter). */
    link->down_tokens = down_cap;
    link->up_tokens = up_cap;
    return true;
}

bool simnet_wire_inject_message(struct simnet_wire *wire, size_t peer_id,
                                const char *command, const uint8_t *payload,
                                size_t payload_len)
{
    if (!wire || peer_id >= wire->peer_count || !command ||
        (!payload && payload_len > 0))
        LOG_FAIL("simnet.wire", "invalid inject peer=%zu len=%zu", peer_id,
                 payload_len);
    /* Open the ingress link so the frame is deliverable even for an
     * ingress-only adversary slot that never ran a handshake — mirrors the
     * direct link.open set in simnet_wire_start_honest_peer(). */
    wire->peers[peer_id].link.open = true;
    return simnet_wire_enqueue_frame(wire, peer_id, command, payload,
                                     payload_len);
}

bool simnet_wire_deliver_raw_now(struct simnet_wire *wire, size_t peer_id,
                                 const uint8_t *bytes, size_t len)
{
    if (!wire || peer_id >= wire->peer_count || (!bytes && len > 0))
        LOG_FAIL("simnet.wire", "invalid immediate delivery peer=%zu len=%zu",
                 peer_id, len);
    if (!wire->peers[peer_id].link.open)
        return true;
    return ring_write(&wire->peers[peer_id].link.to_nut, bytes, len);
}

bool simnet_wire_frame(struct simnet_wire *wire, const char *command,
                       const uint8_t *payload, size_t payload_len,
                       uint8_t **out, size_t *out_len)
{
    if (!wire || !command || !out || !out_len ||
        (!payload && payload_len > 0))
        LOG_FAIL("simnet.wire", "invalid frame request");
    if (payload_len > MAX_PROTOCOL_MESSAGE_LENGTH)
        LOG_FAIL("simnet.wire", "payload too large len=%zu", payload_len);

    size_t total = MSG_HEADER_SIZE + payload_len;
    uint8_t *frame = zcl_malloc(total, "simnet_wire_frame");
    if (!frame)
        LOG_FAIL("simnet.wire", "OOM allocating frame len=%zu", total);

    struct msg_header hdr;
    msg_header_init_full(&hdr, wire->params->pchMessageStart, command,
                         (unsigned int)payload_len);
    struct uint256 checksum;
    hash256(payload_len ? payload : (const uint8_t *)"",
            payload_len, checksum.data);
    memcpy(&hdr.nChecksum, checksum.data, sizeof(hdr.nChecksum));

    memcpy(frame, &hdr, MSG_HEADER_SIZE);
    if (payload_len > 0)
        memcpy(frame + MSG_HEADER_SIZE, payload, payload_len);

    *out = frame;
    *out_len = total;
    return true;
}

bool simnet_wire_enqueue_frame(struct simnet_wire *wire, size_t peer_id,
                               const char *command, const uint8_t *payload,
                               size_t payload_len)
{
    uint8_t *frame = NULL;
    size_t frame_len = 0;
    if (!simnet_wire_frame(wire, command, payload, payload_len,
                           &frame, &frame_len))
        return false;
    bool ok = simnet_wire_enqueue(wire, peer_id,
                                  WIRE_EVENT_DELIVER_TO_NUT,
                                  frame, frame_len);
    free(frame);
    return ok;
}

static bool simnet_wire_enqueue_verack(struct simnet_wire *wire,
                                       size_t peer_id)
{
    return simnet_wire_enqueue_frame(wire, peer_id, "verack", NULL, 0);
}

static bool simnet_wire_enqueue_pong(struct simnet_wire *wire, size_t peer_id,
                                     uint64_t nonce)
{
    struct byte_stream s;
    stream_init(&s, 8);
    bool ok = stream_write_u64_le(&s, nonce) &&
              simnet_wire_enqueue_frame(wire, peer_id, "pong", s.data,
                                        s.size);
    stream_free(&s);
    if (!ok)
        LOG_FAIL("simnet.wire", "failed to enqueue pong");
    return true;
}

bool simnet_wire_enqueue_version(struct simnet_wire *wire, size_t peer_id)
{
    if (!wire || peer_id >= wire->peer_count)
        LOG_FAIL("simnet.wire", "invalid version peer=%zu", peer_id);

    struct wire_peer *peer = &wire->peers[peer_id];
    struct version_message ver;
    version_message_init(&ver);
    ver.protocol_version = PROTOCOL_VERSION;
    ver.services = NODE_NETWORK;
    ver.timestamp = (int64_t)platform_time_wall_time_t();
    ver.addr_recv = peer->addr;
    ver.addr_from = peer->addr;
    ver.nonce = rng_u64();
    if (ver.nonce == 0 || ver.nonce == wire->nm.local_host_nonce)
        ver.nonce ^= 0xa5a5a5a55a5a5a5aULL;
    if (ver.nonce == 0 || ver.nonce == wire->nm.local_host_nonce)
        ver.nonce++;
    snprintf(ver.sub_version, sizeof(ver.sub_version), "/simnet-wire:0.1/");
    ver.start_height = 0;
    ver.relay = true;

    struct byte_stream s;
    stream_init(&s, 128);
    bool ok = version_message_serialize(&ver, &s) &&
              simnet_wire_enqueue_frame(wire, peer_id, "version", s.data,
                                        s.size);
    stream_free(&s);
    if (!ok)
        LOG_FAIL("simnet.wire", "failed to enqueue version");
    peer->version_sent = true;
    return true;
}

static bool simnet_wire_deliver_one_event(struct simnet_wire *wire,
                                          bool *progress)
{
    if (!wire || !progress)
        LOG_FAIL("simnet.wire", "invalid delivery args");
    size_t idx = 0;
    if (!simnet_wire_find_next_event(wire, &idx))
        return true;

    struct wire_event ev = wire->queue[idx];
    uint64_t now = simnet_wire_now_us();
    if (ev.deliver_us > now) {
        uint64_t delta = ev.deliver_us - now;
        if (delta > (uint64_t)INT64_MAX)
            LOG_FAIL("simnet.wire", "delivery delta too large");
        int rc = seed_tape_advance(wire->tape, (int64_t)delta);
        if (rc != 0)
            LOG_FAIL("simnet.wire", "seed_tape_advance failed rc=%d", rc);
        *progress = true;
    }

    struct wire_peer *peer = &wire->peers[ev.peer_id];
    if (ev.kind == WIRE_EVENT_DELIVER_TO_NUT && peer->link.open) {
        if (!ring_write(&peer->link.to_nut, ev.bytes, ev.len))
            return false;
        *progress = true;
    } else if (ev.kind == WIRE_EVENT_OPEN) {
        peer->link.open = true;
        *progress = true;
    } else if (ev.kind == WIRE_EVENT_CLOSE) {
        peer->link.open = false;
        *progress = true;
    }

    simnet_wire_remove_event(wire, idx);
    return true;
}

static size_t simnet_wire_recv_cap_for_queue(size_t queued, size_t base_cap)
{
    if (queued >= MAX_RECV_MESSAGES)
        return 0;

    size_t free_slots = MAX_RECV_MESSAGES - queued;
    size_t cap = free_slots * (size_t)MSG_HEADER_SIZE;
    if (cap < base_cap)
        return cap;
    return base_cap;
}

static bool simnet_wire_pump_to_nut(struct simnet_wire *wire, size_t peer_id,
                                    bool *progress)
{
    if (!wire || peer_id >= wire->peer_count || !progress)
        LOG_FAIL("simnet.wire", "invalid ingress pump peer=%zu", peer_id);
    struct wire_peer *peer = &wire->peers[peer_id];
    struct p2p_node *node = peer->node;

    while (peer->link.open && !node->disconnect &&
           ring_available(&peer->link.to_nut) > 0) {
        zcl_mutex_lock(&node->cs_recv);
        size_t queued = node->recv_msg_count;
        if (queued >= MAX_RECV_MESSAGES) {
            event_emitf(EV_BACKPRESSURE_REJECT, (uint32_t)node->id,
                        "cmd=wire reason=recv_queue_full");
            zcl_mutex_unlock(&node->cs_recv);
            break;
        }

        size_t linear_len = 0;
        const uint8_t *ptr = ring_linear_ptr(&peer->link.to_nut, &linear_len);
        if (!ptr || linear_len == 0) {
            zcl_mutex_unlock(&node->cs_recv);
            break;
        }

        size_t cap = simnet_wire_recv_cap_for_queue(
            queued, SIMNET_WIRE_IO_CHUNK_BASE);
        if (peer->link.down_tokens < cap)
            cap = peer->link.down_tokens;
        if (cap == 0) {
            zcl_mutex_unlock(&node->cs_recv);
            break;
        }
        if (cap > linear_len)
            cap = linear_len;
        size_t chunk = 1u + (rng_u64() % cap);

        bool ok = p2p_node_receive_bytes(node, (const char *)ptr,
                                         (unsigned int)chunk,
                                         wire->params->pchMessageStart);
        if (!ok) {
            (void)p2p_node_request_disconnect(
                node, P2P_DISCONNECT_MESSAGE_PARSE,
                P2P_DISCONNECT_SOURCE_SOCKET,
                node->endpoint_generation);
            for (size_t i = 0; i < node->recv_msg_count; i++)
                net_message_free(&node->recv_msgs[i]);
            node->recv_msg_count = 0;
            zcl_mutex_unlock(&node->cs_recv);
            LOG_FAIL("simnet.wire", "NUT rejected inbound bytes");
        }
        node->last_recv = platform_time_wall_time_t();
        atomic_store_explicit(&node->last_activity_monotonic_us,
                              platform_time_monotonic_us(),
                              memory_order_relaxed);
        node->recv_bytes += (uint64_t)chunk;
        if (peer->link.down_tokens != SIZE_MAX)
            peer->link.down_tokens -= chunk;
        zcl_mutex_unlock(&node->cs_recv);

        simnet_wire_fp_mix(wire, peer_id, 1, ptr, chunk);
        wire->delivered_to_nut_bytes += chunk;
        if (!ring_drop(&peer->link.to_nut, chunk))
            return false;
        *progress = true;
    }
    return true;
}

static bool simnet_wire_peer_handle_frame(struct simnet_wire *wire,
                                          size_t peer_id,
                                          const uint8_t *frame,
                                          size_t frame_len)
{
    if (!wire || peer_id >= wire->peer_count || !frame ||
        frame_len < MSG_HEADER_SIZE)
        LOG_FAIL("simnet.wire", "invalid peer frame");

    struct msg_header hdr;
    memcpy(&hdr, frame, sizeof(hdr));
    if (!msg_header_is_valid(&hdr, wire->params->pchMessageStart))
        return false;
    size_t payload_len = hdr.nMessageSize;
    if (frame_len != MSG_HEADER_SIZE + payload_len)
        LOG_FAIL("simnet.wire", "frame length mismatch");

    const uint8_t *payload = frame + MSG_HEADER_SIZE;
    struct uint256 checksum;
    hash256(payload_len ? payload : (const uint8_t *)"",
            payload_len, checksum.data);
    unsigned int expected = 0;
    memcpy(&expected, checksum.data, sizeof(expected));
    if (expected != hdr.nChecksum)
        LOG_FAIL("simnet.wire", "peer saw checksum mismatch");

    char cmd[COMMAND_SIZE + 1];
    msg_header_get_command(&hdr, cmd, sizeof(cmd));
    struct wire_peer *peer = &wire->peers[peer_id];

    if (strcmp(cmd, "version") == 0) {
        struct byte_stream s;
        struct version_message ver;
        version_message_init(&ver);
        stream_init_from_data(&s, payload, payload_len);
        bool ok = version_message_deserialize(&ver, &s);
        stream_free(&s);
        if (!ok)
            LOG_FAIL("simnet.wire", "peer failed to parse NUT version");
        peer->saw_nut_version = true;
        if (!peer->verack_sent) {
            if (!simnet_wire_enqueue_verack(wire, peer_id))
                return false;
            peer->verack_sent = true;
        }
    } else if (strcmp(cmd, "verack") == 0) {
        peer->saw_nut_verack = true;
    } else if (strcmp(cmd, "sendheaders") == 0) {
        peer->saw_nut_sendheaders = true;
    } else if (strcmp(cmd, "ping") == 0) {
        struct byte_stream s;
        uint64_t nonce = 0;
        stream_init_from_data(&s, payload, payload_len);
        bool ok = stream_read_u64_le(&s, &nonce);
        stream_free(&s);
        if (ok && !simnet_wire_enqueue_pong(wire, peer_id, nonce))
            return false;
    } else if (strcmp(cmd, "pong") == 0) {
        struct byte_stream s;
        uint64_t nonce = 0;
        stream_init_from_data(&s, payload, payload_len);
        bool ok = stream_read_u64_le(&s, &nonce);
        stream_free(&s);
        if (!ok)
            LOG_FAIL("simnet.wire", "peer failed to parse pong");
        peer->saw_nut_pong = true;
        peer->last_pong_nonce = nonce;
    }

    return true;
}

static bool simnet_wire_peer_process(struct simnet_wire *wire, size_t peer_id,
                                     bool *progress)
{
    if (!wire || peer_id >= wire->peer_count || !progress)
        LOG_FAIL("simnet.wire", "invalid peer process peer=%zu", peer_id);
    struct wire_peer *peer = &wire->peers[peer_id];

    while (ring_available(&peer->link.to_peer) >= MSG_HEADER_SIZE) {
        struct msg_header hdr;
        if (!ring_copy_out(&peer->link.to_peer, 0, (uint8_t *)&hdr,
                           sizeof(hdr)))
            return false;
        if (hdr.nMessageSize > MAX_PROTOCOL_MESSAGE_LENGTH)
            LOG_FAIL("simnet.wire", "peer frame too large: %u",
                     hdr.nMessageSize);
        size_t total = MSG_HEADER_SIZE + (size_t)hdr.nMessageSize;
        if (ring_available(&peer->link.to_peer) < total)
            break;

        uint8_t *frame = zcl_malloc(total, "simnet_wire_peer_frame");
        if (!frame)
            LOG_FAIL("simnet.wire", "OOM allocating peer frame len=%zu",
                     total);
        bool ok = ring_read(&peer->link.to_peer, frame, total) &&
                  simnet_wire_peer_handle_frame(wire, peer_id, frame, total);
        free(frame);
        if (!ok)
            return false;
        *progress = true;
    }

    return true;
}

/* D2: drain each peer's OWN p2p_node send queue back to that peer's link
 * (kills the old hardcoded peer_id=0). Routing is by node identity: the
 * msg_processor appended each reply onto the node it was invoked for, so a
 * node's egress belongs to exactly one peer. A closed link silently drops
 * the segment (a real partition, not a buffered outage). */
static bool simnet_wire_drain_peer_send(struct simnet_wire *wire,
                                        size_t peer_id, bool *progress)
{
    struct wire_peer *peer = &wire->peers[peer_id];
    struct p2p_node *node = peer->node;
    if (!node || !peer->send_sentinel)
        return true;

    zcl_mutex_lock(&node->cs_send);
    while (peer->send_sentinel->next) {
        struct send_segment *seg = peer->send_sentinel->next;
        peer->send_sentinel->next = seg->next;
        if (node->send_tail == seg)
            node->send_tail = peer->send_sentinel;
        if (node->send_size >= seg->size)
            node->send_size -= seg->size;
        else
            node->send_size = 0;
        node->send_offset = 0;

        if (peer->link.open) {
            if (!ring_write(&peer->link.to_peer, seg->data, seg->size)) {
                zcl_mutex_unlock(&node->cs_send);
                return false;
            }
            simnet_wire_fp_mix(wire, peer_id, 2, seg->data, seg->size);
            wire->delivered_to_peer_bytes += seg->size;
            if (peer->link.up_tokens != SIZE_MAX &&
                peer->link.up_tokens >= seg->size)
                peer->link.up_tokens -= seg->size;
            *progress = true;
        }
        send_segment_free(seg);
    }
    node->send_head = peer->send_sentinel;
    node->send_tail = peer->send_sentinel;
    zcl_mutex_unlock(&node->cs_send);
    return true;
}

static bool simnet_wire_drain_nut_send(struct simnet_wire *wire,
                                       bool *progress)
{
    if (!wire || !progress)
        LOG_FAIL("simnet.wire", "invalid egress drain");
    for (size_t i = 0; i < wire->peer_count; i++) {
        if (!simnet_wire_drain_peer_send(wire, i, progress))
            return false;
    }
    return true;
}

static uint64_t simnet_wire_progress_signature(const struct simnet_wire *wire)
{
    if (!wire)
        return 0;
    uint64_t h = wire->fingerprint ^ wire->queue_count;
    h ^= wire->delivered_to_nut_bytes << 7;
    h ^= wire->delivered_to_peer_bytes << 13;
    for (size_t i = 0; i < wire->peer_count; i++) {
        const struct p2p_node *node = wire->peers[i].node;
        if (node) {
            h ^= (uint64_t)node->recv_msg_count << (21u + (i % 7u));
            h ^= (uint64_t)node->send_size << (29u + (i % 3u));
            h ^= node->disconnect ? (0xfeed0001ULL + i) : 0;
        }
        h ^= ring_available(&wire->peers[i].link.to_nut) << (i % 17u);
        h ^= ring_available(&wire->peers[i].link.to_peer) << ((i + 5u) % 23u);
        h ^= wire->peers[i].saw_nut_pong ? (0xbeefULL + i) : 0;
    }
    return h;
}

bool simnet_wire_tip_hash(const struct simnet_wire *wire, struct uint256 *out)
{
    if (!wire || !out)
        LOG_FAIL("simnet.wire", "invalid tip hash request");
    struct block_index *tip = active_chain_tip(&wire->ms.chain_active);
    if (tip)
        *out = tip->hashBlock;
    else
        uint256_set_null(out);
    return true;
}

bool simnet_wire_coins_digest(const struct simnet_wire *wire,
                              struct utxo_commitment *out)
{
    if (!wire || !out)
        LOG_FAIL("simnet.wire", "invalid coins digest request");
    coins_view_cache_recompute_commitment(&wire->coins_tip, out);
    return true;
}

bool simnet_wire_save_capsule(const struct simnet_wire *wire,
                              const char *path)
{
    if (!wire || !wire->tape || !path || !*path)
        LOG_FAIL("simnet.wire", "invalid capsule save request");
    int rc = seed_tape_save(wire->tape, path);
    if (rc != 0)
        LOG_FAIL("simnet.wire", "seed_tape_save failed rc=%d path=%s",
                 rc, path);
    return true;
}

void simnet_wire_mark_monitor_failed(struct simnet_wire *wire,
                                     const char *reason)
{
    if (!wire)
        return;
    wire->monitor.failed = true;
    if (!wire->monitor.saved_capsule && wire->tape) {
        char path[96];
        snprintf(path, sizeof(path),
                 "/tmp/simnet_wire_%016llx.tape",
                 (unsigned long long)wire->master_seed);
        if (seed_tape_save(wire->tape, path) == 0)
            wire->monitor.saved_capsule = true;
    }
    if (reason && *reason)
        LOG_WARN("simnet.wire", "monitor violation: %s", reason);
}

static void simnet_wire_monitor_track_memory(struct simnet_wire *wire)
{
    if (!wire)
        return;
    struct simnet_wire_monitor *m = &wire->monitor;
    /* D2: every peer is now its own connection — the bounded-memory /
     * no-silent-halt guarantees must hold across ALL of them, so track the
     * max over each node, not just peer 0. */
    for (size_t i = 0; i < wire->peer_count; i++) {
        struct p2p_node *node = wire->peers[i].node;
        if (!node)
            continue;
        if (node->recv_msg_count > m->max_recv_msg_count)
            m->max_recv_msg_count = node->recv_msg_count;
        if (node->send_size > m->max_send_size)
            m->max_send_size = node->send_size;
        if (node->inventory_to_send_count > m->max_inventory_to_send)
            m->max_inventory_to_send = node->inventory_to_send_count;
        if (node->addr_to_send_count > m->max_addr_to_send)
            m->max_addr_to_send = node->addr_to_send_count;

        if (node->recv_msg_count > MAX_RECV_MESSAGES) {
            m->recv_queue_bounded = false;
            simnet_wire_mark_monitor_failed(wire, "recv queue exceeded cap");
        }
        if (node->send_size > net_send_peer_bytes_cap() ||
            node->inventory_to_send_count > MAX_INVENTORY_KNOWN ||
            node->addr_to_send_count > MAX_ADDR_TO_SEND) {
            m->memory_plateau_ok = false;
            if (!m->warned_memory_growth) {
                m->warned_memory_growth = true;
                LOG_WARN("simnet.wire",
                         "memory plateau warning peer=%zu send=%zu inv=%zu "
                         "addr=%zu", i, node->send_size,
                         node->inventory_to_send_count,
                         node->addr_to_send_count);
            }
        }
    }
}

static bool simnet_wire_monitor_blockers(struct simnet_wire *wire)
{
    if (!wire)
        LOG_FAIL("simnet.wire", "NULL blocker monitor");
    struct blocker_snapshot snaps[BLOCKER_CAP];
    int n = blocker_snapshot_all(snaps, BLOCKER_CAP);
    for (int i = 0; i < n; i++) {
        if (snaps[i].class != (int)BLOCKER_PERMANENT)
            continue;
        if (simnet_wire_byzantine_expected_blocker(
                wire, snaps[i].id, snaps[i].class))
            continue;
        wire->monitor.no_unexpected_permanent_blocker = false;
        simnet_wire_mark_monitor_failed(wire,
                                        "unexpected permanent blocker");
        return false;
    }
    return true;
}

static bool simnet_wire_monitor_consensus(struct simnet_wire *wire)
{
    if (!wire)
        LOG_FAIL("simnet.wire", "NULL consensus monitor");
    struct uint256 tip;
    struct utxo_commitment coins;
    if (!simnet_wire_tip_hash(wire, &tip) ||
        !simnet_wire_coins_digest(wire, &coins))
        return false;
    if (!uint256_eq(&tip, &wire->monitor.baseline_tip) ||
        !utxo_commitment_equal(&coins, &wire->monitor.baseline_coins)) {
        wire->monitor.consensus_unchanged = false;
        simnet_wire_mark_monitor_failed(wire, "consensus baseline changed");
        return false;
    }
    return true;
}

static bool simnet_wire_monitor_ban_expectations(struct simnet_wire *wire)
{
    if (!wire)
        LOG_FAIL("simnet.wire", "invalid ban monitor");
    /* D2: check each ban-expecting peer against its OWN node — a node that
     * crossed the ban threshold must be disconnected and its address banned,
     * independently of the other connections. */
    for (size_t i = 0; i < wire->peer_count; i++) {
        struct wire_peer *peer = &wire->peers[i];
        if (!peer->ban_expected || !peer->node ||
            !peer_scoring_should_ban(peer->node))
            continue;
        if (!peer->node->disconnect ||
            !is_banned(&wire->nm, &peer->node->addr.svc.addr)) {
            simnet_wire_mark_monitor_failed(
                wire, "ban threshold did not disconnect");
            return false;
        }
    }
    return true;
}

bool simnet_wire_monitor_after_tick(struct simnet_wire *wire)
{
    if (!wire)
        LOG_FAIL("simnet.wire", "NULL monitor tick");
    simnet_wire_monitor_track_memory(wire);
    simnet_wire_byzantine_after_tick(wire);
    return simnet_wire_monitor_blockers(wire) &&
           simnet_wire_monitor_consensus(wire) &&
           simnet_wire_monitor_ban_expectations(wire) &&
           !wire->monitor.failed;
}

bool simnet_wire_monitor_finish(struct simnet_wire *wire)
{
    if (!wire)
        LOG_FAIL("simnet.wire", "NULL monitor finish");
    return simnet_wire_monitor_after_tick(wire);
}

bool simnet_wire_scenario_partitions_pending(const struct simnet_wire *wire)
{
    if (!wire)
        return false;
    for (size_t i = 0; i < wire->partition_count; i++) {
        const struct wire_scenario_partition_state *p = &wire->partitions[i];
        if (!p->closed_fired)
            return true;
        if (p->duration_ticks > 0 && !p->reopened_fired)
            return true;
    }
    return false;
}

/* Fires scripted CLOSE/OPEN events (Step D1's wire_scenario.partitions[])
 * once the tick counter reaches each entry's at_tick /
 * at_tick+duration_ticks. Tick-keyed, not wall-clock, so replay stays
 * deterministic for a given seed. Routed through simnet_wire_partition_peer
 * so scripted and manually-triggered partitions share one code path. */
bool simnet_wire_apply_scenario_partitions(struct simnet_wire *wire,
                                           bool *progress)
{
    if (!wire || !progress)
        LOG_FAIL("simnet.wire", "invalid partition timeline args");
    for (size_t i = 0; i < wire->partition_count; i++) {
        struct wire_scenario_partition_state *p = &wire->partitions[i];
        if (!p->closed_fired && wire->ticks >= p->at_tick) {
            if (!simnet_wire_partition_peer(wire, p->peer_id, true))
                return false;
            p->closed_fired = true;
            *progress = true;
        }
        if (p->closed_fired && !p->reopened_fired && p->duration_ticks > 0 &&
            wire->ticks >= p->at_tick + p->duration_ticks) {
            if (!simnet_wire_partition_peer(wire, p->peer_id, false))
                return false;
            p->reopened_fired = true;
            *progress = true;
        }
    }
    return true;
}

static bool simnet_wire_idle(const struct simnet_wire *wire)
{
    if (!wire || wire->queue_count > 0)
        return false;
    /* D2: any node with a pending send or a COMPLETE queued recv message has
     * real work; check all of them, not just peer 0. An INCOMPLETE
     * head-of-queue message with no inbound bytes left to finish it (the
     * queue + every peer ring are checked below, so if we reach here none
     * are available) is a quiescent state, not activity —
     * msg_process_messages() gates on net_message_complete() and cannot
     * advance it, and no further bytes will arrive. Treating such a partial
     * as "busy" spins the run to max_ticks. The GARBAGE_AFTER_VERACK
     * bad-handshake sub-case is exactly this: the peer completes its own
     * handshake then emits a 4-byte fragment that lands as an incomplete
     * 24-byte header the node harmlessly parks in recv_msgs[0] before going
     * silent (seeds 0xf/0x69/0x8e). */
    for (size_t i = 0; i < wire->peer_count; i++) {
        const struct p2p_node *node = wire->peers[i].node;
        if (!node)
            continue;
        if (node->send_size > 0)
            return false;
        if (node->recv_msg_count > 0 &&
            net_message_complete(&node->recv_msgs[0]))
            return false;
    }
    if (simnet_wire_scenario_partitions_pending(wire))
        return false;
    for (size_t i = 0; i < wire->peer_count; i++) {
        if (wire->peers[i].kind == SIMNET_WIRE_PEER_FLOOD &&
            wire->peers[i].flood_active)
            return false;
        if (wire->peers[i].kind == SIMNET_WIRE_PEER_SLOWLORIS &&
            !wire->peers[i].adversary_done)
            return false;
        if (wire->peers[i].kind == SIMNET_WIRE_PEER_REPLAY &&
            !wire->peers[i].replay_done)
            return false;
        if (wire->peers[i].kind == SIMNET_WIRE_PEER_REORDER &&
            !wire->peers[i].reorder_done)
            return false;
        if ((wire->peers[i].kind == SIMNET_WIRE_PEER_INVALID_BLOCK ||
             wire->peers[i].kind == SIMNET_WIRE_PEER_INVALID_HEADER) &&
            !wire->peers[i].byz_injected &&
            !wire->peers[i].adversary_done &&
            wire->nut && !wire->nut->disconnect)
            return false;
        if (ring_available(&wire->peers[i].link.to_nut) > 0 ||
            ring_available(&wire->peers[i].link.to_peer) > 0)
            return false;
    }
    return true;
}

static bool simnet_wire_tick(struct simnet_wire *wire, bool *progress)
{
    if (!wire || !progress)
        LOG_FAIL("simnet.wire", "invalid tick args");
    *progress = false;

    /* Refill each link's per-tick bandwidth budget. SIZE_MAX caps stay
     * unbounded (unchanged behavior); a finite cap set via
     * simnet_wire_set_link_bandwidth() bounds this tick's throughput. */
    for (size_t i = 0; i < wire->peer_count; i++) {
        wire->peers[i].link.down_tokens = wire->peers[i].link.down_cap;
        wire->peers[i].link.up_tokens = wire->peers[i].link.up_cap;
    }

    if (!simnet_wire_apply_scenario_partitions(wire, progress))
        return false;
    if (!simnet_wire_deliver_one_event(wire, progress))
        return false;
    for (size_t i = 0; i < wire->peer_count; i++) {
        if (!simnet_wire_peer_tick(wire, i, progress))
            return false;
    }
    for (size_t i = 0; i < wire->peer_count; i++) {
        if (!simnet_wire_pump_to_nut(wire, i, progress))
            return false;
    }
    /* D2: run the shared msg_processor once per node — each connection's
     * recv queue is drained and its replies appended onto its own send
     * queue, exercising the real multi-peer dispatch path. */
    for (size_t i = 0; i < wire->peer_count; i++) {
        if (!msg_process_messages(&wire->mp, wire->peers[i].node))
            LOG_FAIL("simnet.wire", "msg_process_messages failed peer=%zu", i);
    }
    if (!simnet_wire_drain_nut_send(wire, progress))
        return false;
    for (size_t i = 0; i < wire->peer_count; i++) {
        if (!simnet_wire_peer_process(wire, i, progress))
            return false;
    }
    wire->ticks++;
    /* Track the largest single-tick delivery INTO the NUT — the bandwidth
     * monitor for capped links (a capped tick can deliver at most down_cap
     * bytes). */
    uint64_t delta = wire->delivered_to_nut_bytes - wire->last_delivered_to_nut;
    if (delta > wire->max_deliver_to_nut_per_tick)
        wire->max_deliver_to_nut_per_tick = delta;
    wire->last_delivered_to_nut = wire->delivered_to_nut_bytes;
    return simnet_wire_monitor_after_tick(wire);
}

struct simnet_wire *simnet_wire_create(size_t peer_count, uint64_t seed)
{
    if (peer_count == 0 || peer_count > SIMNET_WIRE_MAX_PEERS)
        LOG_NULL("simnet.wire", "invalid peer_count=%zu", peer_count);

    struct simnet_wire *wire =
        zcl_calloc(1, sizeof(*wire), "simnet_wire");
    if (!wire)
        LOG_NULL("simnet.wire", "OOM allocating simnet_wire");

    wire->peer_count = peer_count;
    wire->master_seed = seed;
    wire->fingerprint = SIMNET_WIRE_FNV_OFFSET;
    wire->next_seq = 1;
    wire->monitor.recv_queue_bounded = true;
    wire->monitor.no_unexpected_permanent_blocker = true;
    wire->monitor.memory_plateau_ok = true;
    wire->monitor.consensus_unchanged = true;
    wire->peers = zcl_calloc(peer_count, sizeof(*wire->peers),
                             "simnet_wire_peers");
    if (!wire->peers) {
        simnet_wire_free(wire);
        LOG_NULL("simnet.wire", "OOM allocating peers count=%zu",
                 peer_count);
    }

    if (!simnet_wire_init_runtime(wire, seed)) {
        simnet_wire_free(wire);
        LOG_NULL("simnet.wire", "runtime init failed");
    }

    for (size_t i = 0; i < peer_count; i++) {
        struct wire_peer *peer = &wire->peers[i];
        peer->kind = SIMNET_WIRE_PEER_HONEST;
        peer->child_seed = simnet_wire_splitmix64_value(seed ^ (uint64_t)i);
        peer->link.open = false;
        peer->link.down_tokens = SIZE_MAX;
        peer->link.up_tokens = SIZE_MAX;
        peer->link.down_cap = SIZE_MAX;
        peer->link.up_cap = SIZE_MAX;
        simnet_wire_init_peer_addr(&peer->addr, i, wire->params);
        if (!ring_init(&peer->link.to_nut, SIMNET_WIRE_DEFAULT_RING_CAP) ||
            !ring_init(&peer->link.to_peer, SIMNET_WIRE_DEFAULT_RING_CAP)) {
            simnet_wire_free(wire);
            LOG_NULL("simnet.wire", "peer ring init failed index=%zu", i);
        }
        if (!simnet_wire_create_peer_node(wire, i)) {
            simnet_wire_free(wire);
            LOG_NULL("simnet.wire", "peer node create failed index=%zu", i);
        }
    }

    /* wire->nut is peer 0's connection — the one the single-connection
     * call sites and simnet_wire_node() observe. */
    wire->nut = wire->peers[0].node;

    if (!simnet_wire_tip_hash(wire, &wire->monitor.baseline_tip) ||
        !simnet_wire_coins_digest(wire, &wire->monitor.baseline_coins)) {
        simnet_wire_free(wire);
        LOG_NULL("simnet.wire", "consensus monitor baseline failed");
    }

    return wire;
}

void simnet_wire_free(struct simnet_wire *wire)
{
    if (!wire)
        return;

    simnet_wire_clear_event_observers();
    /* D2: each peer owns its own p2p_node (wire->nut aliases peers[0].node,
     * so it is freed by the loop below — do NOT free it separately). The
     * send_sentinel is the node's permanent send_head and is freed by
     * p2p_node_free's send-list walk. */
    if (wire->peers) {
        for (size_t i = 0; i < wire->peer_count; i++) {
            if (wire->peers[i].node) {
                p2p_node_free(wire->peers[i].node);
                wire->peers[i].node = NULL;
            }
        }
    }
    wire->nut = NULL;
    simnet_wire_byzantine_free(wire);
    if (wire->net_ready)
        net_manager_free(&wire->nm);
    if (wire->coins_ready)
        coins_view_cache_free(&wire->coins_tip);
    if (wire->mempool_ready)
        tx_mempool_free(&wire->mempool);
    if (wire->main_ready)
        main_state_free(&wire->ms);

    if (wire->peers) {
        for (size_t i = 0; i < wire->peer_count; i++) {
            ring_free(&wire->peers[i].link.to_nut);
            ring_free(&wire->peers[i].link.to_peer);
            free(wire->peers[i].slowloris_frame);
            free(wire->peers[i].replay_frame);
        }
        free(wire->peers);
    }
    if (wire->queue) {
        for (size_t i = 0; i < wire->queue_count; i++)
            free(wire->queue[i].bytes);
        free(wire->queue);
    }
    if (wire->tape) {
        seed_tape_uninstall();
        seed_tape_close(wire->tape);
    }
    free(wire->partitions);
    free(wire);
}

struct p2p_node *simnet_wire_node(struct simnet_wire *wire)
{
    return wire ? wire->nut : NULL;
}

bool simnet_wire_start_honest_peer(struct simnet_wire *wire, size_t peer_id)
{
    if (!wire || peer_id >= wire->peer_count)
        LOG_FAIL("simnet.wire", "invalid start peer=%zu", peer_id);
    struct wire_peer *peer = &wire->peers[peer_id];
    peer->kind = SIMNET_WIRE_PEER_HONEST;
    peer->link.open = true;
    return simnet_wire_enqueue_version(wire, peer_id);
}

bool simnet_wire_peer_send_ping(struct simnet_wire *wire, size_t peer_id,
                                uint64_t nonce)
{
    if (!wire || peer_id >= wire->peer_count)
        LOG_FAIL("simnet.wire", "invalid ping peer=%zu", peer_id);
    struct byte_stream s;
    stream_init(&s, 8);
    bool ok = stream_write_u64_le(&s, nonce) &&
              simnet_wire_enqueue_frame(wire, peer_id, "ping", s.data,
                                        s.size);
    stream_free(&s);
    if (!ok)
        LOG_FAIL("simnet.wire", "failed to enqueue ping");
    wire->peers[peer_id].ping_nonce_sent = nonce;
    return true;
}

bool simnet_wire_run(struct simnet_wire *wire, uint64_t max_ticks,
                     uint64_t stuck_guard)
{
    if (!wire || max_ticks == 0)
        LOG_FAIL("simnet.wire", "invalid run max_ticks=%llu",
                 (unsigned long long)max_ticks);

    uint64_t stuck = 0;
    for (uint64_t i = 0; i < max_ticks; i++) {
        if (simnet_wire_idle(wire))
            return simnet_wire_monitor_finish(wire);
        uint64_t before = simnet_wire_progress_signature(wire);
        bool tick_progress = false;
        if (!simnet_wire_tick(wire, &tick_progress))
            return false;
        uint64_t after = simnet_wire_progress_signature(wire);
        if (tick_progress || after != before) {
            stuck = 0;
        } else {
            stuck++;
            if (stuck_guard > 0 && stuck >= stuck_guard)
                LOG_FAIL("simnet.wire", "stuck after %llu ticks",
                         (unsigned long long)stuck);
        }
    }

    (void)simnet_wire_monitor_finish(wire);
    LOG_FAIL("simnet.wire", "max_ticks exhausted ticks=%llu pending=%zu",
             (unsigned long long)max_ticks, wire->queue_count);
}

bool simnet_wire_peer_handshake_complete(const struct simnet_wire *wire,
                                         size_t peer_id)
{
    if (!wire || peer_id >= wire->peer_count)
        return false;
    const struct wire_peer *peer = &wire->peers[peer_id];
    const struct p2p_node *node = peer->node;
    if (!node)
        return false;
    return peer->version_sent &&
           peer->verack_sent &&
           peer->saw_nut_version &&
           peer->saw_nut_verack &&
           atomic_load(&node->state) >= PEER_HANDSHAKE_COMPLETE &&
           node->version == PROTOCOL_VERSION &&
           node->recv_version == PROTOCOL_VERSION &&
           !node->disconnect;
}

bool simnet_wire_peer_pong_received(const struct simnet_wire *wire,
                                    size_t peer_id, uint64_t nonce)
{
    if (!wire || peer_id >= wire->peer_count)
        return false;
    const struct wire_peer *peer = &wire->peers[peer_id];
    return peer->saw_nut_pong && peer->last_pong_nonce == nonce;
}

bool simnet_wire_get_stats(const struct simnet_wire *wire,
                           struct simnet_wire_stats *out)
{
    if (!wire || !out)
        LOG_FAIL("simnet.wire", "invalid stats request");
    memset(out, 0, sizeof(*out));
    out->ticks = wire->ticks;
    out->delivered_to_nut_bytes = wire->delivered_to_nut_bytes;
    out->delivered_to_peer_bytes = wire->delivered_to_peer_bytes;
    out->max_deliver_to_nut_per_tick = wire->max_deliver_to_nut_per_tick;
    out->fingerprint = wire->fingerprint;
    out->rng_count = seed_tape_rng_count(wire->tape);
    out->checksum_fail_events = wire->events.checksum_fail;
    out->peer_misbehave_events = wire->events.peer_misbehave;
    out->backpressure_reject_events = wire->events.backpressure_reject;
    out->peer_banned_events = wire->events.peer_banned;
    out->not_implemented_peers = wire->not_implemented_peers;
    out->max_recv_msg_count = wire->monitor.max_recv_msg_count;
    out->max_send_size = wire->monitor.max_send_size;
    out->max_inventory_to_send = wire->monitor.max_inventory_to_send;
    out->max_addr_to_send = wire->monitor.max_addr_to_send;
    out->pending_events = wire->queue_count;
    out->nut_disconnected = wire->nut ? wire->nut->disconnect : true;
    out->nut_banned = wire->nut ?
        is_banned((struct net_manager *)&wire->nm,
                  &wire->nut->addr.svc.addr) : false;
    out->recv_queue_bounded = wire->monitor.recv_queue_bounded;
    out->no_unexpected_permanent_blocker =
        wire->monitor.no_unexpected_permanent_blocker;
    out->memory_plateau_ok = wire->monitor.memory_plateau_ok;
    out->consensus_unchanged = wire->monitor.consensus_unchanged;
    out->monitor_failed = wire->monitor.failed;
    for (size_t i = 0; i < wire->peer_count; i++) {
        out->to_nut_bytes += ring_available(&wire->peers[i].link.to_nut);
        out->to_peer_bytes += ring_available(&wire->peers[i].link.to_peer);
        if (wire->peers[i].link.open)
            out->peers_open++;
    }
    if (wire->peer_count > 0) {
        out->handshake_complete =
            simnet_wire_peer_handshake_complete(wire, 0);
        out->pong_received = wire->peers[0].saw_nut_pong;
    }
    return true;
}

bool simnet_wire_get_byzantine_observation(
    const struct simnet_wire *wire,
    struct simnet_wire_byzantine_observation *out)
{
    return simnet_wire_byzantine_get_observation(wire, out);
}
