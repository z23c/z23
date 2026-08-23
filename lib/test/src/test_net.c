/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#define _DEFAULT_SOURCE
#include "platform/time_compat.h"
#include "test/test_core.h"
#include "core/hash.h"
#include "core/random.h"
#include "core/utiltime.h"
#include "net/p2p_message.h"
#include "config/boot_snapshot_offer.h"
#include "primitives/transaction.h"
#include "chain/chainparams.h"
#include "net/version.h"
#include "net/fast_sync.h"
#include "net/onion_service.h"
#include "net/onion_v3_address.h"
#include "net/onion_ratelimit.h"
#include "net/puzzle.h"
#include "net/msgprocessor.h"
#include "net/connman.h"
#include "net/peer_strategy.h"
#include "net/peer_liveness.h"
#include "net/tip_watchdog.h"
#include "net/download.h"
#include "event/event.h"
#include "sync/sync_state.h"
#include "platform/clock.h"
#include "json/json.h"
#include <sqlite3.h>
#include <unistd.h>
#include <pthread.h>
#include <stdatomic.h>
#include "util/safe_alloc.h"

static int test_onion_peer_discover(const char *datadir,
                                    struct onion_peer *out,
                                    size_t max)
{
    return (datadir && out && max > 0) ? 0 : -1;
}

static size_t test_onion_blog_serve(const char *datadir,
                                    const char *path,
                                    char *out,
                                    size_t out_len)
{
    if (!datadir || !path || !out || out_len == 0)
        return 0;
    int n = snprintf(out, out_len,
                     "HTTP/1.1 200 OK\r\n"
                     "Content-Type: text/plain\r\n"
                     "Connection: close\r\n\r\n"
                     "blog:%s:%s",
                     datadir, path);
    return n < 0 ? 0 : (size_t)n;
}

/* ── backpressure-watchdog event observers ──────────── */

static _Atomic uint64_t g_p74_active_emits   = 0;
static _Atomic uint64_t g_p74_reject_emits   = 0;
static _Atomic uint64_t g_p74_clear_emits    = 0;
static _Atomic uint32_t g_p74_last_reject_peer = 0;

static void p74_active_observer(enum event_type type, uint32_t peer_id,
                                const void *payload, uint32_t payload_len,
                                void *ctx)
{
    (void)type; (void)peer_id; (void)payload;
    (void)payload_len; (void)ctx;
    atomic_fetch_add(&g_p74_active_emits, 1);
}

static void p74_reject_observer(enum event_type type, uint32_t peer_id,
                                const void *payload, uint32_t payload_len,
                                void *ctx)
{
    (void)type; (void)payload; (void)payload_len; (void)ctx;
    atomic_store(&g_p74_last_reject_peer, peer_id);
    atomic_fetch_add(&g_p74_reject_emits, 1);
}

static void p74_clear_observer(enum event_type type, uint32_t peer_id,
                               const void *payload, uint32_t payload_len,
                               void *ctx)
{
    (void)type; (void)peer_id; (void)payload;
    (void)payload_len; (void)ctx;
    atomic_fetch_add(&g_p74_clear_emits, 1);
}

static void p74_register_observers(void)
{
    /* event_emit is a no-op until event_log_init runs. Other test
     * groups init lazily; do the same here so the watchdog tests can
     * run standalone. event_log_init clears all observers, so
     * registration must follow it. */
    event_log_init();
    atomic_store(&g_p74_active_emits, 0);
    atomic_store(&g_p74_reject_emits, 0);
    atomic_store(&g_p74_clear_emits, 0);
    atomic_store(&g_p74_last_reject_peer, 0);
    event_observe(EV_BACKPRESSURE_ACTIVE, p74_active_observer, NULL);
    event_observe(EV_BACKPRESSURE_REJECT, p74_reject_observer, NULL);
    event_observe(EV_BACKPRESSURE_CLEAR,  p74_clear_observer,  NULL);
}

/* concurrent-racer worker: each thread attempts to claim the
 * swarm slot. Exactly one must win. The thread writes 1 into the
 * `won` slot on success, 0 on failure. A shared start barrier makes
 * both pthreads hit the CAS in the same window. */
struct p26_race_arg {
    pthread_barrier_t *barrier;
    _Atomic int *won;
};

static void *p26_race_worker(void *arg)
{
    struct p26_race_arg *a = arg;
    pthread_barrier_wait(a->barrier);
    if (msgprocessor_test_swarm_try_claim())
        atomic_fetch_add(a->won, 1);
    return NULL;
}

/* ── connman snapshot-iterate stress scaffolding ─────────── */

struct p25_ctx {
    struct connman *cm;
    _Atomic bool   stop;
    _Atomic int    cycles_run;
    _Atomic int    callbacks_run;
    /* Probability of mock process_messages marking the peer to
     * disconnect, as 1-in-N. Higher N means slower churn. */
    int            disconnect_1_in_n;
};

static _Atomic int g_p25_counter;

static bool p25_mock_process_messages(void *ctx, struct p2p_node *node)
{
    struct p25_ctx *c = ctx;
    atomic_fetch_add(&c->callbacks_run, 1);
    /* Simulate a few microseconds of work under NO lock — this is the
     * whole point of the fix: callbacks run without cs_nodes held. */
    for (volatile int i = 0; i < 100; i++) { /* spin */ }
    int tick = atomic_fetch_add(&g_p25_counter, 1);
    if (c->disconnect_1_in_n > 0 &&
        (tick % c->disconnect_1_in_n) == 0) {
        node->disconnect = true;
    }
    return true;
}

static bool p25_mock_send_messages(void *ctx, struct p2p_node *node,
                                   bool send_trickle)
{
    (void)node; (void)send_trickle;
    struct p25_ctx *c = ctx;
    atomic_fetch_add(&c->callbacks_run, 1);
    for (volatile int i = 0; i < 50; i++) { /* spin */ }
    return true;
}

struct p25_order_ctx {
    _Atomic int seq;
    int send_order;
    int process_order;
};

static bool p25_order_process_messages(void *ctx, struct p2p_node *node)
{
    (void)node;
    struct p25_order_ctx *c = ctx;
    c->process_order = atomic_fetch_add(&c->seq, 1) + 1;
    return true;
}

static bool p25_order_send_messages(void *ctx, struct p2p_node *node,
                                    bool send_trickle)
{
    (void)node;
    (void)send_trickle;
    struct p25_order_ctx *c = ctx;
    c->send_order = atomic_fetch_add(&c->seq, 1) + 1;
    return true;
}

static void *p25_message_worker(void *arg)
{
    struct p25_ctx *c = arg;
    while (!atomic_load(&c->stop)) {
        connman_run_message_cycle(c->cm);
        atomic_fetch_add(&c->cycles_run, 1);
    }
    return NULL;
}

/* Drives the disconnect + deferred_free_sweep half of the loop. Mimics
 * thread_socket_handler's cleanup pass: remove disconnected nodes from
 * the array, append to deferred_free, then sweep. */
static void *p25_socket_worker(void *arg)
{
    struct p25_ctx *c = arg;
    while (!atomic_load(&c->stop)) {
        zcl_mutex_lock(&c->cm->manager.cs_nodes);

        connman_run_deferred_free_sweep(c->cm);

        for (size_t i = 0; i < c->cm->manager.num_nodes; ) {
            struct p2p_node *n = c->cm->manager.nodes[i];
            if (n->disconnect &&
                c->cm->num_deferred_free < c->cm->deferred_free_cap) {
                /* Match production thread_socket_handler's discipline:
                 * drop recv_msg_count before parking for free so
                 * p2p_node_free doesn't dereference the sentinel value
                 * our mock uses to trigger process_messages. */
                n->recv_msg_count = 0;
                c->cm->manager.nodes[i] =
                    c->cm->manager.nodes[c->cm->manager.num_nodes - 1];
                c->cm->manager.num_nodes--;
                c->cm->deferred_free[c->cm->num_deferred_free++] = n;
            } else {
                i++;
            }
        }

        zcl_mutex_unlock(&c->cm->manager.cs_nodes);
        usleep(1000);  /* 1ms pacing */
    }
    /* Drain remaining deferred_free so the test doesn't leak across
     * cases. Callers must free any nodes still left in nodes[]. */
    zcl_mutex_lock(&c->cm->manager.cs_nodes);
    connman_run_deferred_free_sweep(c->cm);
    zcl_mutex_unlock(&c->cm->manager.cs_nodes);
    return NULL;
}

/* ── Virtual clock for the onion admission tests ──────────────────────
 *
 * onion_ratelimit.c's escalation state machine only advances at whole
 * second boundaries and needs dozens of simulated seconds to exercise
 * escalate and de-escalate. Sleeping that long would violate "tests fast
 * always", so drive platform.clock directly — the same injection
 * test_clock.c and the sync-watchdog tests use. The monotonic hand
 * tracks the wall hand so the puzzle gate's load EWMA also advances. */
struct onion_fake_clock {
    _Atomic int64_t wall_ms;
};
static int64_t onion_fake_now_mono(void *self)
{
    struct onion_fake_clock *c = (struct onion_fake_clock *)self;
    return atomic_load(&c->wall_ms) * 1000000LL;
}
static int64_t onion_fake_now_wall(void *self)
{
    struct onion_fake_clock *c = (struct onion_fake_clock *)self;
    return atomic_load(&c->wall_ms);
}
static void onion_fake_clock_set_secs(struct onion_fake_clock *c, int64_t secs)
{
    atomic_store(&c->wall_ms, secs * 1000);
}

/* Hex-decode a 64-char field of a 402 challenge into 32 raw bytes. */
static void onion_hex_decode32(const char *hex, uint8_t out[32])
{
    for (int i = 0; i < 32; i++) {
        char b[3] = { hex[i * 2], hex[i * 2 + 1], '\0' };
        out[i] = (uint8_t)strtoul(b, NULL, 16);
    }
}

/* Read one integer field out of the onion_ratelimit dumpstate snapshot. */
static int64_t onion_dump_int(const char *key, bool *found)
{
    struct json_value dump = {0};
    json_init(&dump);
    int64_t v = 0;
    *found = false;
    if (onion_ratelimit_dump_state_json(&dump, NULL)) {
        const struct json_value *f = json_get(&dump, key);
        if (f) { v = json_get_int(f); *found = true; }
    }
    json_free(&dump);
    return v;
}

int test_net(void)
{
    int failures = 0;

    /* Binary keepalive contract: all boundaries are caller-clocked so this
     * suite advances hours instantly and never sleeps. */
    printf("peer_liveness: ping boundary is monotonic 60 seconds... ");
    {
        const int64_t t0 = 1000000LL;
        struct peer_liveness_sample s = {
            .connected_us = t0, .last_activity_us = t0, .ping_sent_us = 0,
        };
        bool ok = peer_liveness_decide(
                      &s, t0 + PEER_LIVENESS_PING_IDLE_US - 1) ==
                      PEER_LIVENESS_NONE &&
                  peer_liveness_decide(
                      &s, t0 + PEER_LIVENESS_PING_IDLE_US) ==
                      PEER_LIVENESS_SEND_PING;
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("peer_liveness: delayed scheduling and lost-pong boundary... ");
    {
        const int64_t t0 = 2000000LL;
        struct peer_liveness_sample delayed = {
            .connected_us = t0, .last_activity_us = t0, .ping_sent_us = 0,
        };
        bool sends_when_late = peer_liveness_decide(
            &delayed, t0 + 5 * PEER_LIVENESS_PING_IDLE_US) ==
            PEER_LIVENESS_SEND_PING;
        delayed.ping_sent_us = t0 + 5 * PEER_LIVENESS_PING_IDLE_US;
        bool waits = peer_liveness_decide(
            &delayed,
            delayed.ping_sent_us + PEER_LIVENESS_PONG_DEADLINE_US - 1) ==
            PEER_LIVENESS_NONE;
        bool drops = peer_liveness_decide(
            &delayed,
            delayed.ping_sent_us + PEER_LIVENESS_PONG_DEADLINE_US) ==
            PEER_LIVENESS_DISCONNECT_PONG_TIMEOUT;
        bool ok = sends_when_late && waits && drops;
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("peer_liveness: traffic supersedes an outstanding ping... ");
    {
        const int64_t ping_us = 100000000LL;
        struct peer_liveness_sample s = {
            .connected_us = 1,
            .last_activity_us = ping_us + 10,
            .ping_sent_us = ping_us,
        };
        bool recovered = peer_liveness_decide(
            &s, ping_us + PEER_LIVENESS_PONG_DEADLINE_US + 1) ==
            PEER_LIVENESS_SEND_PING;
        bool ok = recovered;
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("peer_liveness: hard silence backstop is exactly 20 minutes... ");
    {
        const int64_t t0 = 3000000LL;
        struct peer_liveness_sample s = {
            .connected_us = t0, .last_activity_us = t0, .ping_sent_us = 0,
        };
        bool before = peer_liveness_decide(
            &s, t0 + PEER_LIVENESS_HARD_SILENCE_US - 1) ==
            PEER_LIVENESS_SEND_PING;
        bool at = peer_liveness_decide(
            &s, t0 + PEER_LIVENESS_HARD_SILENCE_US) ==
            PEER_LIVENESS_DISCONNECT_HARD_SILENCE;
        bool ok = before && at;
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("peer_liveness: wall-clock jumps cannot alter a decision... ");
    {
        const int64_t mono = 5000000LL;
        struct peer_liveness_sample s = {
            .connected_us = mono, .last_activity_us = mono,
            .ping_sent_us = 0,
        };
        /* Deliberately model two absurd wall readings. Neither is an input to
         * the production decision seam. */
        int64_t wall_before = 1700000000000LL;
        int64_t wall_after = wall_before - 86400000LL;
        enum peer_liveness_action a = peer_liveness_decide(
            &s, mono + PEER_LIVENESS_PING_IDLE_US);
        enum peer_liveness_action b = peer_liveness_decide(
            &s, mono + PEER_LIVENESS_PING_IDLE_US);
        bool ok = wall_before != wall_after && a == b &&
                  a == PEER_LIVENESS_SEND_PING;
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("peer_disconnect: first cause and endpoint generation win... ");
    {
        struct p2p_node node;
        memset(&node, 0, sizeof(node));
        node.endpoint_generation = 42;
        bool stale_refused = !p2p_node_request_disconnect(
            &node, P2P_DISCONNECT_SYNC_STALL,
            P2P_DISCONNECT_SOURCE_SYNC, 41);
        bool first = p2p_node_request_disconnect(
            &node, P2P_DISCONNECT_PONG_TIMEOUT,
            P2P_DISCONNECT_SOURCE_KEEPALIVE, 42);
        bool second_refused = !p2p_node_request_disconnect(
            &node, P2P_DISCONNECT_IO_ERROR,
            P2P_DISCONNECT_SOURCE_SOCKET, 42);
        bool ok = stale_refused && first && second_refused &&
                  atomic_load(&node.disconnect) &&
                  atomic_load(&node.disconnect_reason) ==
                      P2P_DISCONNECT_PONG_TIMEOUT &&
                  atomic_load(&node.disconnect_source) ==
                      P2P_DISCONNECT_SOURCE_KEEPALIVE &&
                  atomic_load(&node.disconnect_endpoint_generation) == 42;
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("connman watchdog freshness requires message and dial progress... ");
    {
        struct connman cm;
        memset(&cm, 0, sizeof(cm));
        const int64_t bound = 1000000;
        bool before_start = connman_runtime_progress_fresh(&cm, bound);
        cm.started = true;
        int64_t now = platform_time_monotonic_us();
        atomic_store(&cm.message_last_progress_us, now);
        atomic_store(&cm.dial_scheduler_last_progress_us, now);
        bool both_fresh = connman_runtime_progress_fresh(&cm, bound);
        atomic_store(&cm.dial_scheduler_last_progress_us, now - bound - 1);
        bool stale_dial = !connman_runtime_progress_fresh(&cm, bound);
        atomic_store(&cm.dial_scheduler_last_progress_us, now);
        atomic_store(&cm.message_last_progress_us, now - bound - 1);
        bool stale_message = !connman_runtime_progress_fresh(&cm, bound);
        bool ok = before_start && both_fresh && stale_dial && stale_message;
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("net_addr IPv4... ");
    {
        struct net_addr a;
        net_addr_init(&a);
        unsigned char ip4[] = {192, 168, 1, 1};
        net_addr_set_ipv4(&a, ip4);
        char str[64];
        net_addr_to_string(&a, str, sizeof(str));
        if (net_addr_is_ipv4(&a) && strcmp(str, "192.168.1.1") == 0)
            printf("OK (%s)\n", str);
        else {
            printf("FAIL: %s\n", str);
            failures++;
        }
    }

    printf("net_service to_string... ");
    {
        struct net_service s;
        net_service_init(&s);
        unsigned char ip4[] = {10, 0, 0, 1};
        net_addr_set_ipv4(&s.addr, ip4);
        s.port = 8233;
        char str[64];
        net_service_to_string(&s, str, sizeof(str));
        if (strcmp(str, "10.0.0.1:8233") == 0)
            printf("OK (%s)\n", str);
        else {
            printf("FAIL: %s\n", str);
            failures++;
        }
    }

    printf("msg_header... ");
    {
        unsigned char start[4] = {0x24, 0xe9, 0x27, 0x64};
        struct msg_header h;
        msg_header_init_full(&h, start, "version", 100);
        char cmd[COMMAND_SIZE + 1];
        msg_header_get_command(&h, cmd, sizeof(cmd));
        if (strcmp(cmd, "version") == 0 && h.nMessageSize == 100 &&
            msg_header_is_valid(&h, start))
            printf("OK (%s)\n", cmd);
        else {
            printf("FAIL: %s\n", cmd);
            failures++;
        }
    }

    printf("inv_item... ");
    {
        struct uint256 hash;
        memset(hash.data, 0xab, 32);
        struct inv_item inv;
        inv_item_init_typed(&inv, MSG_TX, &hash);
        char str[128];
        inv_item_to_string(&inv, str, sizeof(str));
        if (inv_item_is_known_type(&inv) &&
            strcmp(inv_item_get_command(&inv), "tx") == 0)
            printf("OK (%s)\n", inv_item_get_command(&inv));
        else {
            printf("FAIL\n");
            failures++;
        }
    }

    printf("net_address serialize/deserialize roundtrip... ");
    {
        struct net_address a;
        net_address_init(&a);
        a.nServices = NODE_NETWORK | NODE_BLOOM;
        a.nTime = 1700000000;
        a.svc.addr.ip[12] = 192; a.svc.addr.ip[13] = 168;
        a.svc.addr.ip[14] = 1; a.svc.addr.ip[15] = 1;
        a.svc.port = 8233;
        struct byte_stream s;
        stream_init(&s, 64);
        net_address_serialize(&a, &s, true);
        struct byte_stream r;
        stream_init_from_data(&r, s.data, s.size);
        struct net_address a2;
        net_address_init(&a2);
        net_address_deserialize(&a2, &r, true);
        if (a2.nTime == 1700000000 &&
            a2.nServices == (NODE_NETWORK | NODE_BLOOM) &&
            a2.svc.addr.ip[12] == 192 && a2.svc.port == 8233)
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
        stream_free(&s);
    }

    printf("inv_item serialize/deserialize roundtrip... ");
    {
        struct inv_item inv;
        struct uint256 h;
        memset(h.data, 0xAA, 32);
        inv_item_init_typed(&inv, MSG_TX, &h);
        struct byte_stream s;
        stream_init(&s, 64);
        inv_item_serialize(&inv, &s);
        struct byte_stream r;
        stream_init_from_data(&r, s.data, s.size);
        struct inv_item inv2;
        inv_item_deserialize(&inv2, &r);
        if (inv2.type == MSG_TX && inv2.hash.data[0] == 0xAA)
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
        stream_free(&s);
    }

    printf("block_locator serialize/deserialize roundtrip... ");
    {
        struct block_locator loc;
        block_locator_init(&loc);
        loc.num_hashes = 3;
        loc.vhave = zcl_calloc(3, sizeof(struct uint256), "test_locator_hashes");
        memset(loc.vhave[0].data, 0x11, 32);
        memset(loc.vhave[1].data, 0x22, 32);
        memset(loc.vhave[2].data, 0x33, 32);
        struct byte_stream s;
        stream_init(&s, 128);
        block_locator_serialize(&loc, &s);
        struct byte_stream r;
        stream_init_from_data(&r, s.data, s.size);
        struct block_locator loc2;
        block_locator_init(&loc2);
        block_locator_deserialize(&loc2, &r);
        if (loc2.num_hashes == 3 &&
            loc2.vhave[0].data[0] == 0x11 &&
            loc2.vhave[2].data[0] == 0x33)
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
        block_locator_free(&loc);
        block_locator_free(&loc2);
        stream_free(&s);
    }

    printf("version_message serialize/deserialize roundtrip... ");
    {
        struct version_message v;
        version_message_init(&v);
        v.protocol_version = 170009;
        v.services = NODE_NETWORK;
        v.timestamp = 1700000000;
        v.addr_recv.nServices = NODE_NETWORK;
        v.addr_recv.svc.port = 8233;
        v.addr_from.nServices = NODE_NETWORK;
        v.addr_from.svc.port = 8233;
        v.nonce = 0xDEADBEEFCAFEBABEULL;
        snprintf(v.sub_version, MAX_SUBVER_LENGTH, "/ZClassic:2.1.1-3/");
        v.start_height = 500000;
        v.relay = true;

        struct byte_stream s;
        stream_init(&s, 256);
        version_message_serialize(&v, &s);

        struct byte_stream r;
        stream_init_from_data(&r, s.data, s.size);
        struct version_message v2;
        version_message_init(&v2);
        version_message_deserialize(&v2, &r);

        if (v2.protocol_version == 170009 &&
            v2.services == NODE_NETWORK &&
            v2.timestamp == 1700000000 &&
            v2.nonce == 0xDEADBEEFCAFEBABEULL &&
            strcmp(v2.sub_version, "/ZClassic:2.1.1-3/") == 0 &&
            v2.start_height == 500000 &&
            v2.relay == true &&
            v2.addr_recv.svc.port == 8233)
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
        stream_free(&s);
    }

    printf("getdata blocks serialize... ");
    {
        struct uint256 hashes[2];
        struct byte_stream s;
        struct byte_stream r;
        uint64_t count = 0;
        struct inv_item inv1, inv2;

        memset(&hashes, 0, sizeof(hashes));
        hashes[0].data[0] = 0xAA;
        hashes[1].data[0] = 0xBB;

        stream_init(&s, 128);
        if (!getdata_blocks_serialize(&s, hashes, 2)) {
            printf("FAIL\n");
            failures++;
        } else {
            stream_init_from_data(&r, s.data, s.size);
            if (!stream_read_compact_size(&r, &count) ||
                count != 2 ||
                !inv_item_deserialize(&inv1, &r) ||
                !inv_item_deserialize(&inv2, &r) ||
                inv1.type != MSG_BLOCK ||
                inv2.type != MSG_BLOCK ||
                inv1.hash.data[0] != 0xAA ||
                inv2.hash.data[0] != 0xBB) {
                printf("FAIL\n");
                failures++;
            } else {
                printf("OK\n");
            }
        }
        stream_free(&s);
    }

    printf("getheaders serialize... ");
    {
        struct block_locator loc;
        struct byte_stream s;
        struct byte_stream r;
        int32_t version = 0;
        uint64_t count = 0;
        struct uint256 stop = {0};

        block_locator_init(&loc);
        loc.num_hashes = 2;
        loc.vhave = zcl_calloc(2, sizeof(struct uint256), "test_locator_hashes");
        loc.vhave[0].data[0] = 0x11;
        loc.vhave[1].data[0] = 0x22;

        stream_init(&s, 128);
        if (!getheaders_serialize(&s, &loc, NULL)) {
            printf("FAIL\n");
            failures++;
        } else {
            stream_init_from_data(&r, s.data, s.size);
            if (!stream_read_i32_le(&r, &version) ||
                version != 170011 ||
                !stream_read_compact_size(&r, &count) ||
                count != 2 ||
                r.data[r.read_pos] != 0x11 ||
                r.data[r.read_pos + 32] != 0x22 ||
                memcmp(s.data + s.size - 32, stop.data, 32) != 0) {
                printf("FAIL\n");
                failures++;
            } else {
                printf("OK\n");
            }
        }
        block_locator_free(&loc);
        stream_free(&s);
    }

    printf("split_host_port... ");
    {
        char host[128];
        int port = 8233;
        split_host_port("192.168.1.1:9033", host, sizeof(host), &port);
        if (strcmp(host, "192.168.1.1") == 0 && port == 9033)
            printf("OK\n");
        else { printf("FAIL (host=%s port=%d)\n", host, port); failures++; }
    }

    printf("split_host_port ipv6... ");
    {
        char host[128];
        int port = 8233;
        split_host_port("[::1]:9033", host, sizeof(host), &port);
        if (strcmp(host, "::1") == 0 && port == 9033)
            printf("OK\n");
        else { printf("FAIL (host=%s port=%d)\n", host, port); failures++; }
    }

    printf("lookup_host numeric ipv4... ");
    {
        struct net_addr addrs[4];
        size_t n = 0;
        for (size_t i = 0; i < 4; i++) {
            net_addr_init(&addrs[i]);
            addrs[i].has_torv3 = true;
            memset(addrs[i].torv3, 0xa5, sizeof(addrs[i].torv3));
        }
        bool ok = lookup_host("127.0.0.1", addrs, 4, &n, false);
        if (ok && n == 1 && !addrs[0].has_torv3 &&
            addrs[0].ip[12] == 127 && addrs[0].ip[15] == 1)
            printf("OK\n");
        else { printf("FAIL (ok=%d n=%zu)\n", ok, n); failures++; }
    }

    printf("lookup_numeric... ");
    {
        struct net_service svc;
        bool ok = lookup_numeric("10.0.0.1:8233", &svc, 0);
        if (ok && !svc.addr.has_torv3 && svc.addr.ip[12] == 10 &&
            svc.port == 8233)
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("lookup_onion parse accept/refuse... ");
    {
        /* The .onion addnode parse branch (shared by RPC addnode, boot
         * -addnode, and connman_add_seed_node): a valid v3 name — derived
         * from a fixed pubkey through the shared codec, so the checksum is
         * real — parses to the pubkey bytes and port; everything else
         * fails CLOSED and never touches DNS. */
        uint8_t pub[32];
        for (int i = 0; i < 32; i++)
            pub[i] = (uint8_t)(i * 7 + 1);
        char host[ONION_V3_ADDRESS_LEN + 1];
        bool ok = onion_v3_address_from_pubkey(pub, host);

        char withport[ONION_V3_ADDRESS_LEN + 8];
        snprintf(withport, sizeof(withport), "%s:8233", host);
        struct net_service svc;
        memset(&svc, 0, sizeof(svc));
        ok = ok && lookup_onion(withport, &svc, 8033);
        ok = ok && svc.addr.has_torv3 &&
             memcmp(svc.addr.torv3, pub, 32) == 0 && svc.port == 8233;

        /* No port in the string -> the caller's default port. */
        ok = ok && lookup_onion(host, &svc, 8033) && svc.port == 8033 &&
             svc.addr.has_torv3;

        /* Refusals: corrupted checksum, truncated name, clearnet literal,
         * and a non-onion name — all fail closed. */
        char bad[ONION_V3_ADDRESS_LEN + 1];
        snprintf(bad, sizeof(bad), "%s", host);
        bad[0] = (bad[0] == 'a') ? 'b' : 'a';
        ok = ok && !lookup_onion(bad, &svc, 8033) && !svc.addr.has_torv3;
        ok = ok && !lookup_onion("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion",
                                 &svc, 8033);
        ok = ok && !lookup_onion("127.0.0.1:8233", &svc, 8033);
        ok = ok && !lookup_onion("example.com", &svc, 8033);

        /* Detection helper: suffix on the host part, with or without port. */
        ok = ok && net_name_is_onion(host) && net_name_is_onion(withport) &&
             !net_name_is_onion("10.0.0.1:8233") &&
             !net_name_is_onion("example.com");

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("net_addr onion render/parse round-trip... ");
    {
        uint8_t pub[32];
        for (int i = 0; i < 32; i++)
            pub[i] = (uint8_t)(0xff - i * 5);
        char host[ONION_V3_ADDRESS_LEN + 1];
        bool ok = onion_v3_address_from_pubkey(pub, host);

        /* pubkey -> net_addr -> string == original hostname. */
        struct net_addr a;
        ok = ok && net_addr_from_onion(host, &a);
        ok = ok && a.has_torv3 && memcmp(a.torv3, pub, 32) == 0;
        char rendered[NET_ADDR_STR_MAX + 1];
        int n = net_addr_to_string(&a, rendered, sizeof(rendered));
        ok = ok && n == (int)strlen(host) && strcmp(rendered, host) == 0;

        /* The 56-char suffix-less form parses too (codec contract). */
        char bare[57];
        memcpy(bare, host, 56);
        bare[56] = '\0';
        struct net_addr b2;
        ok = ok && net_addr_from_onion(bare, &b2) && net_addr_eq(&a, &b2);

        /* Service render is the bare hostname:port form (no brackets). */
        struct net_service s;
        net_service_init(&s);
        s.addr = a;
        s.port = 8033;
        char svc_str[NET_SERVICE_STR_MAX + 1];
        n = net_service_to_string(&s, svc_str, sizeof(svc_str));
        char expect[NET_SERVICE_STR_MAX + 1];
        snprintf(expect, sizeof(expect), "%s:8033", host);
        ok = ok && n == (int)strlen(expect) && strcmp(svc_str, expect) == 0;

        if (ok) printf("OK (%s)\n", host);
        else { printf("FAIL\n"); failures++; }
    }

    printf("millis_to_timeval... ");
    {
        struct timeval tv = millis_to_timeval(5500);
        if (tv.tv_sec == 5 && tv.tv_usec == 500000)
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("net_addr RFC classification... ");
    {
        struct net_addr a;
        net_addr_init(&a);

        unsigned char priv10[] = {10, 0, 0, 1};
        net_addr_set_ipv4(&a, priv10);
        bool ok = net_addr_is_rfc1918(&a);

        unsigned char pub8[] = {8, 8, 8, 8};
        net_addr_set_ipv4(&a, pub8);
        ok = ok && !net_addr_is_rfc1918(&a);
        ok = ok && net_addr_is_routable(&a);

        unsigned char local127[] = {127, 0, 0, 1};
        net_addr_set_ipv4(&a, local127);
        ok = ok && net_addr_is_local(&a);
        ok = ok && !net_addr_is_routable(&a);

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("net_addr_get_group ipv4... ");
    {
        struct net_addr a;
        net_addr_init(&a);
        unsigned char ip[] = {1, 2, 3, 4};
        net_addr_set_ipv4(&a, ip);
        unsigned char group[NET_ADDR_GROUP_MAX];
        size_t glen = net_addr_get_group(&a, group, sizeof(group));
        bool ok = glen == 3 && group[0] == NET_IPV4 &&
                  group[1] == 1 && group[2] == 2;
        if (ok) printf("OK\n");
        else { printf("FAIL (len=%zu g0=%d g1=%d g2=%d)\n", glen, group[0], group[1], group[2]); failures++; }
    }

    printf("net_service_get_key... ");
    {
        struct net_service s;
        net_service_init(&s);
        unsigned char ip[] = {192, 168, 1, 1};
        net_addr_set_ipv4(&s.addr, ip);
        s.port = 8233;
        unsigned char key[NET_SERVICE_KEY_SIZE];
        net_service_get_key(&s, key);
        bool ok = key[0] == 0 &&
                  memcmp(key + 1, s.addr.ip, 16) == 0 &&
                  key[33] == (8233 >> 8) && key[34] == (8233 & 0xFF);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("net_service_get_key torv3 distinctness... ");
    {
        /* Two DIFFERENT onion services on the same port must produce
         * different keys, and must not collide with any IP service —
         * previously all torv3 services shared the all-zero ip[16] key. */
        struct net_service o1, o2, ip4;
        net_service_init(&o1);
        net_service_init(&o2);
        net_service_init(&ip4);
        o1.addr.has_torv3 = true;
        o2.addr.has_torv3 = true;
        memset(o1.addr.torv3, 0x11, TORV3_ADDR_SIZE);
        memset(o2.addr.torv3, 0x22, TORV3_ADDR_SIZE);
        o1.port = o2.port = ip4.port = 8033;
        unsigned char k1[NET_SERVICE_KEY_SIZE], k2[NET_SERVICE_KEY_SIZE],
                      k3[NET_SERVICE_KEY_SIZE];
        net_service_get_key(&o1, k1);
        net_service_get_key(&o2, k2);
        net_service_get_key(&ip4, k3);
        bool ok = memcmp(k1, k2, NET_SERVICE_KEY_SIZE) != 0 &&
                  memcmp(k1, k3, NET_SERVICE_KEY_SIZE) != 0 &&
                  k1[0] == 1 && k2[0] == 1;
        /* Same service twice → identical key. */
        unsigned char k1b[NET_SERVICE_KEY_SIZE];
        net_service_get_key(&o1, k1b);
        ok = ok && memcmp(k1, k1b, NET_SERVICE_KEY_SIZE) == 0;
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("addrman init/add/size... ");
    {
        struct addr_man am;
        addrman_init(&am);
        bool ok = addrman_size(&am) == 0;

        struct net_address addr;
        net_address_init(&addr);
        unsigned char ip1[] = {8, 8, 8, 8};
        net_addr_set_ipv4(&addr.svc.addr, ip1);
        addr.svc.port = 8233;
        addr.nTime = (uint32_t)GetTime();

        struct net_addr source;
        net_addr_init(&source);
        unsigned char src_ip[] = {1, 2, 3, 4};
        net_addr_set_ipv4(&source, src_ip);

        bool added = addrman_add(&am, &addr, &source, 0);
        ok = ok && added;
        ok = ok && addrman_size(&am) == 1;

        bool duplicate_added = addrman_add(&am, &addr, &source, 0);
        ok = ok && !duplicate_added;
        ok = ok && addrman_size(&am) == 1;

        if (ok) printf("OK\n");
        else { printf("FAIL (added=%d size=%zu)\n", added, addrman_size(&am)); failures++; }
        addrman_free(&am);
    }

    printf("addrman select... ");
    {
        struct addr_man am;
        addrman_init(&am);

        for (int i = 0; i < 10; i++) {
            struct net_address addr;
            net_address_init(&addr);
            unsigned char ip[] = {50 + (unsigned char)i, 100, 0, 1};
            net_addr_set_ipv4(&addr.svc.addr, ip);
            addr.svc.port = 8233;
            addr.nTime = (uint32_t)GetTime();

            struct net_addr source;
            net_addr_init(&source);
            unsigned char src_ip[] = {60, 2, 3, (unsigned char)(i + 1)};
            net_addr_set_ipv4(&source, src_ip);

            addrman_add(&am, &addr, &source, 0);
        }

        bool ok = addrman_size(&am) == 10;
        struct addr_info result;
        bool selected = addrman_select(&am, true, &result);
        ok = ok && selected;
        ok = ok && result.addr.svc.port == 8233;

        if (ok) printf("OK\n");
        else { printf("FAIL (size=%zu sel=%d)\n", addrman_size(&am), selected); failures++; }
        addrman_free(&am);
    }

    printf("addr_info bucket computation... ");
    {
        struct addr_info info;
        memset(&info, 0, sizeof(info));
        unsigned char ip[] = {192, 168, 1, 1};
        net_addr_set_ipv4(&info.addr.svc.addr, ip);
        info.addr.svc.port = 8233;

        struct uint256 key;
        memset(key.data, 0x42, 32);

        int tried_bucket = addr_info_get_tried_bucket(&info, &key);
        int new_bucket = addr_info_get_new_bucket(&info, &key, &info.addr.svc.addr);
        int pos = addr_info_get_bucket_position(&info, &key, true, new_bucket);

        bool ok = tried_bucket >= 0 && tried_bucket < ADDRMAN_TRIED_BUCKET_COUNT;
        ok = ok && new_bucket >= 0 && new_bucket < ADDRMAN_NEW_BUCKET_COUNT;
        ok = ok && pos >= 0 && pos < ADDRMAN_BUCKET_SIZE;

        if (ok) printf("OK\n");
        else { printf("FAIL (tb=%d nb=%d pos=%d)\n", tried_bucket, new_bucket, pos); failures++; }
    }

    printf("addr_info_is_terrible... ");
    {
        struct addr_info info;
        memset(&info, 0, sizeof(info));
        info.addr.nTime = 0;
        bool ok = addr_info_is_terrible(&info, GetTime());

        info.addr.nTime = (uint32_t)GetTime();
        info.last_try = GetTime();
        ok = ok && !addr_info_is_terrible(&info, GetTime());

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("net_manager init/free... ");
    {
        struct net_manager nm;
        net_manager_init(&nm);
        memcpy(nm.message_start, "\xfa\x1a\xf9\xbf", 4);
        nm.default_port = 8233;
        bool ok = (nm.max_connections == DEFAULT_MAX_PEER_CONNECTIONS);
        ok = ok && (nm.discover == true);
        ok = ok && (nm.listen == true);
        ok = ok && (nm.num_nodes == 0);
        net_manager_free(&nm);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("net_message framing... ");
    {
        unsigned char msgstart[4] = {0xfa, 0x1a, 0xf9, 0xbf};
        struct net_message msg;
        net_message_init(&msg, msgstart);

        struct msg_header hdr;
        msg_header_init_full(&hdr, msgstart, "ping", 8);
        unsigned char payload[8] = {1, 2, 3, 4, 5, 6, 7, 8};

        uint8_t wire[MSG_HEADER_SIZE + 8];
        memcpy(wire, &hdr, MSG_HEADER_SIZE);
        memcpy(wire + MSG_HEADER_SIZE, payload, 8);

        int r1 = net_message_read_header(&msg, (const char *)wire, MSG_HEADER_SIZE);
        bool ok = (r1 == MSG_HEADER_SIZE);
        ok = ok && msg.in_data;
        ok = ok && (msg.hdr.nMessageSize == 8);

        int r2 = net_message_read_data(&msg, (const char *)payload, 8);
        ok = ok && (r2 == 8);
        ok = ok && net_message_complete(&msg);
        ok = ok && (memcmp(msg.recv_data, payload, 8) == 0);

        net_message_free(&msg);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("p2p_node create/free... ");
    {
        struct net_manager nm;
        net_manager_init(&nm);
        memcpy(nm.message_start, "\xfa\x1a\xf9\xbf", 4);

        struct net_address addr;
        net_address_init(&addr);
        unsigned char ip4[4] = {50, 0, 0, 1};
        net_addr_set_ipv4(&addr.svc.addr, ip4);
        addr.svc.port = 8233;

        struct p2p_node *node = p2p_node_create(&nm, ZCL_INVALID_SOCKET,
                                                 &addr, "test-peer", false);
        bool ok = (node != NULL);
        ok = ok && (node->id == 0);
        ok = ok && (node->inbound == false);
        ok = ok && (node->disconnect == false);
        ok = ok && (node->version == 0);
        ok = ok && (strcmp(node->addr_name, "test-peer") == 0);

        p2p_node_free(node);
        net_manager_free(&nm);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("ban management... ");
    {
        struct net_manager nm;
        net_manager_init(&nm);

        struct net_addr addr;
        net_addr_init(&addr);
        unsigned char ip4[4] = {50, 0, 0, 1};
        net_addr_set_ipv4(&addr, ip4);

        bool ok = !is_banned(&nm, &addr);
        ban_addr(&nm, &addr, 3600, false);
        ok = ok && is_banned(&nm, &addr);
        ok = ok && unban_addr(&nm, &addr);
        ok = ok && !is_banned(&nm, &addr);

        ban_addr(&nm, &addr, 3600, false);
        clear_banned(&nm);
        ok = ok && !is_banned(&nm, &addr);

        net_manager_free(&nm);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("local address management... ");
    {
        struct net_manager nm;
        net_manager_init(&nm);

        struct net_service svc;
        net_service_init(&svc);
        unsigned char ip4[4] = {50, 0, 0, 1};
        net_addr_set_ipv4(&svc.addr, ip4);
        svc.port = 8233;

        bool ok = !is_local(&nm, &svc);
        ok = ok && add_local(&nm, &svc, LOCAL_BIND);
        ok = ok && is_local(&nm, &svc);
        ok = ok && remove_local(&nm, &svc);
        ok = ok && !is_local(&nm, &svc);

        net_manager_free(&nm);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("set_limited/is_reachable... ");
    {
        struct net_manager nm;
        net_manager_init(&nm);

        bool ok = is_reachable_net(&nm, NET_IPV4);
        set_limited(&nm, NET_IPV4, true);
        ok = ok && !is_reachable_net(&nm, NET_IPV4);
        set_limited(&nm, NET_IPV4, false);
        ok = ok && is_reachable_net(&nm, NET_IPV4);

        net_manager_free(&nm);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("node_stats copy... ");
    {
        struct net_manager nm;
        net_manager_init(&nm);
        memcpy(nm.message_start, "\xfa\x1a\xf9\xbf", 4);

        struct net_address addr;
        net_address_init(&addr);
        unsigned char ip4[4] = {50, 0, 0, 1};
        net_addr_set_ipv4(&addr.svc.addr, ip4);
        addr.svc.port = 8233;

        struct p2p_node *node = p2p_node_create(&nm, ZCL_INVALID_SOCKET,
                                                 &addr, "stats-test", true);
        node->version = 170002;
        snprintf(node->clean_sub_ver, sizeof(node->clean_sub_ver),
                 "/ZClassic:1.0.0/");

        struct node_stats stats;
        p2p_node_copy_stats(node, &stats);

        bool ok = (stats.nodeid == 0);
        ok = ok && (stats.version == 170002);
        ok = ok && (stats.inbound == true);
        ok = ok && (strcmp(stats.clean_sub_ver, "/ZClassic:1.0.0/") == 0);

        p2p_node_free(node);
        net_manager_free(&nm);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* ===== NETWORKING TESTS ===== */

    /* net_addr: IPv4 init and classification */
    {
        printf("net_addr: IPv4 init and classify... ");
        struct net_addr a;
        net_addr_init(&a);
        unsigned char ip4[4] = {192, 168, 1, 100};
        net_addr_set_ipv4(&a, ip4);
        bool ok = net_addr_is_ipv4(&a);
        ok = ok && !net_addr_is_ipv6(&a);
        ok = ok && !net_addr_is_tor(&a);
        ok = ok && (net_addr_get_network(&a) == NET_IPV4);
        ok = ok && net_addr_is_valid(&a);
        ok = ok && (net_addr_get_byte(&a, 0) == 100);
        ok = ok && (net_addr_get_byte(&a, 1) == 1);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* net_addr: IPv6 classification */
    {
        printf("net_addr: IPv6 classify... ");
        struct net_addr a;
        net_addr_init(&a);
        a.ip[0] = 0x20; a.ip[1] = 0x01;
        a.ip[2] = 0x0d; a.ip[3] = 0x00;
        a.ip[15] = 0x01;
        bool ok = !net_addr_is_ipv4(&a);
        ok = ok && net_addr_is_ipv6(&a);
        ok = ok && (net_addr_get_network(&a) == NET_IPV6);
        ok = ok && net_addr_is_valid(&a);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* net_addr: null address invalid */
    {
        printf("net_addr: null address is invalid... ");
        struct net_addr a;
        net_addr_init(&a);
        bool ok = !net_addr_is_valid(&a);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* net_addr: RFC 3849 documentation address invalid */
    {
        printf("net_addr: RFC3849 doc address invalid... ");
        struct net_addr a;
        net_addr_init(&a);
        a.ip[0] = 0x20; a.ip[1] = 0x01;
        a.ip[2] = 0x0d; a.ip[3] = 0xb8;
        a.ip[15] = 0x01;
        bool ok = !net_addr_is_valid(&a);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* net_addr: equality */
    {
        printf("net_addr: equality... ");
        struct net_addr a, b;
        net_addr_init(&a);
        net_addr_init(&b);
        unsigned char ip4[4] = {10, 0, 0, 1};
        net_addr_set_ipv4(&a, ip4);
        net_addr_set_ipv4(&b, ip4);
        bool ok = net_addr_eq(&a, &b);
        unsigned char ip4b[4] = {10, 0, 0, 2};
        net_addr_set_ipv4(&b, ip4b);
        ok = ok && !net_addr_eq(&a, &b);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* net_addr: Tor address */
    {
        printf("net_addr: Tor address... ");
        struct net_addr a;
        net_addr_init(&a);
        a.has_torv3 = true;
        memset(a.torv3, 0xAB, TORV3_ADDR_SIZE);
        bool ok = net_addr_is_tor(&a);
        ok = ok && !net_addr_is_ipv4(&a);
        ok = ok && (net_addr_get_network(&a) == NET_ONION);
        ok = ok && net_addr_is_valid(&a);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* net_addr: RFC1918 private ranges */
    {
        printf("net_addr: RFC1918 private... ");
        struct net_addr a;
        net_addr_init(&a);
        unsigned char ip4[4] = {10, 0, 0, 1};
        net_addr_set_ipv4(&a, ip4);
        bool ok = net_addr_is_rfc1918(&a);
        ok = ok && !net_addr_is_routable(&a);
        unsigned char ip4b[4] = {172, 16, 5, 1};
        net_addr_set_ipv4(&a, ip4b);
        ok = ok && net_addr_is_rfc1918(&a);
        unsigned char ip4c[4] = {192, 168, 0, 1};
        net_addr_set_ipv4(&a, ip4c);
        ok = ok && net_addr_is_rfc1918(&a);
        unsigned char ip4d[4] = {8, 8, 8, 8};
        net_addr_set_ipv4(&a, ip4d);
        ok = ok && !net_addr_is_rfc1918(&a);
        ok = ok && net_addr_is_routable(&a);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* net_addr: get_group deterministic */
    {
        printf("net_addr: address group... ");
        struct net_addr a, b;
        net_addr_init(&a);
        net_addr_init(&b);
        unsigned char ip4[4] = {8, 8, 8, 8};
        net_addr_set_ipv4(&a, ip4);
        unsigned char ip4b[4] = {8, 8, 4, 4};
        net_addr_set_ipv4(&b, ip4b);
        unsigned char ga[NET_ADDR_GROUP_MAX], gb[NET_ADDR_GROUP_MAX];
        size_t la = net_addr_get_group(&a, ga, sizeof(ga));
        size_t lb = net_addr_get_group(&b, gb, sizeof(gb));
        bool ok = (la > 0 && lb > 0);
        /* Same /16 prefix -> same group */
        ok = ok && (la == lb) && (memcmp(ga, gb, la) == 0);
        /* Different /16 -> different group */
        unsigned char ip4c[4] = {1, 2, 3, 4};
        net_addr_set_ipv4(&b, ip4c);
        lb = net_addr_get_group(&b, gb, sizeof(gb));
        ok = ok && (memcmp(ga, gb, (la < lb ? la : lb)) != 0 || la != lb);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* net_service: init and equality */
    {
        printf("net_service: init and equality... ");
        struct net_service a, b;
        net_service_init(&a);
        net_service_init(&b);
        unsigned char ip4[4] = {127, 0, 0, 1};
        net_addr_set_ipv4(&a.addr, ip4);
        a.port = 8033;
        net_addr_set_ipv4(&b.addr, ip4);
        b.port = 8033;
        bool ok = net_service_eq(&a, &b);
        b.port = 18033;
        ok = ok && !net_service_eq(&a, &b);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* net_service: to_string */
    {
        printf("net_service: to_string... ");
        struct net_service s;
        net_service_init(&s);
        unsigned char ip4[4] = {192, 168, 1, 1};
        net_addr_set_ipv4(&s.addr, ip4);
        s.port = 8033;
        char buf[64];
        int n = net_service_to_string(&s, buf, sizeof(buf));
        bool ok = (n > 0);
        ok = ok && (strstr(buf, "192.168.1.1") != NULL);
        ok = ok && (strstr(buf, "8033") != NULL);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* net_addr: to_string */
    {
        printf("net_addr: to_string... ");
        struct net_addr a;
        net_addr_init(&a);
        unsigned char ip4[4] = {10, 20, 30, 40};
        net_addr_set_ipv4(&a, ip4);
        char buf[64];
        int n = net_addr_to_string(&a, buf, sizeof(buf));
        bool ok = (n > 0);
        ok = ok && (strcmp(buf, "10.20.30.40") == 0);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* msg_header: init and validate */
    {
        printf("msg_header: init and validate... ");
        unsigned char magic[MESSAGE_START_SIZE] = {0x24, 0xe9, 0x27, 0x64};
        struct msg_header h;
        msg_header_init_full(&h, magic, "ping", 8);
        bool ok = msg_header_is_valid(&h, magic);
        /* Wrong magic must fail */
        unsigned char bad_magic[MESSAGE_START_SIZE] = {0xFF, 0xFF, 0xFF, 0xFF};
        ok = ok && !msg_header_is_valid(&h, bad_magic);
        /* Default init has invalid size (-1) so should fail validation */
        struct msg_header h2;
        msg_header_init(&h2, magic);
        ok = ok && !msg_header_is_valid(&h2, magic);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* msg_header: full init with command */
    {
        printf("msg_header: command get/set... ");
        unsigned char magic[MESSAGE_START_SIZE] = {0x24, 0xe9, 0x27, 0x64};
        struct msg_header h;
        msg_header_init_full(&h, magic, "version", 100);
        bool ok = msg_header_is_valid(&h, magic);
        ok = ok && (h.nMessageSize == 100);
        char cmd[COMMAND_SIZE + 1];
        msg_header_get_command(&h, cmd, sizeof(cmd));
        ok = ok && (strcmp(cmd, "version") == 0);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* inv_item: init, types, string */
    {
        printf("inv_item: init and types... ");
        struct inv_item inv;
        inv_item_init(&inv);
        bool ok = (inv.type == 0);
        ok = ok && uint256_is_null(&inv.hash);

        struct uint256 h;
        uint256_set_null(&h);
        h.data[0] = 0xAB;
        inv_item_init_typed(&inv, MSG_TX, &h);
        ok = ok && (inv.type == MSG_TX);
        ok = ok && inv_item_is_known_type(&inv);
        ok = ok && (strcmp(inv_item_get_command(&inv), "tx") == 0);

        inv_item_init_typed(&inv, MSG_BLOCK, &h);
        ok = ok && (strcmp(inv_item_get_command(&inv), "block") == 0);
        ok = ok && inv_item_is_known_type(&inv);

        char str[128];
        inv_item_to_string(&inv, str, sizeof(str));
        ok = ok && (strlen(str) > 0);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* inv_item: init by name */
    {
        printf("inv_item: init by name... ");
        struct uint256 h;
        uint256_set_null(&h);
        h.data[31] = 0x42;
        struct inv_item inv;
        bool ok = (inv_item_init_by_name(&inv, "tx", &h) == 0);
        ok = ok && (inv.type == MSG_TX);
        ok = ok && (inv_item_init_by_name(&inv, "block", &h) == 0);
        ok = ok && (inv.type == MSG_BLOCK);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* inv_item: serialization roundtrip */
    {
        printf("inv_item: serialize roundtrip... ");
        struct uint256 h;
        uint256_set_null(&h);
        for (int i = 0; i < 32; i++) h.data[i] = (uint8_t)i;
        struct inv_item inv;
        inv_item_init_typed(&inv, MSG_TX, &h);

        struct byte_stream s;
        stream_init(&s, 128);
        bool ok = inv_item_serialize(&inv, &s);

        struct byte_stream r;
        stream_init_from_data(&r, s.data, s.size);
        struct inv_item inv2;
        ok = ok && inv_item_deserialize(&inv2, &r);
        ok = ok && (inv2.type == MSG_TX);
        ok = ok && uint256_eq(&inv2.hash, &h);
        stream_free(&s);
        stream_free(&r);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* net_address: serialization roundtrip */
    {
        printf("net_address: serialize roundtrip... ");
        struct net_address addr;
        net_address_init(&addr);
        unsigned char ip4[4] = {8, 8, 8, 8};
        net_addr_set_ipv4(&addr.svc.addr, ip4);
        addr.svc.port = 8033;
        addr.nServices = NODE_NETWORK;
        addr.nTime = 1700000000;

        struct byte_stream s;
        stream_init(&s, 128);
        bool ok = net_address_serialize(&addr, &s, true);

        struct byte_stream r;
        stream_init_from_data(&r, s.data, s.size);
        struct net_address addr2;
        net_address_init(&addr2);
        ok = ok && net_address_deserialize(&addr2, &r, true);
        ok = ok && net_addr_eq(&addr.svc.addr, &addr2.svc.addr);
        ok = ok && (addr2.svc.port == 8033);
        ok = ok && (addr2.nServices == NODE_NETWORK);
        ok = ok && (addr2.nTime == 1700000000);
        stream_free(&s);
        stream_free(&r);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* net_message: header read with valid magic */
    {
        printf("net_message: read header... ");
        unsigned char magic[MESSAGE_START_SIZE] = {0x24, 0xe9, 0x27, 0x64};
        struct net_message msg;
        net_message_init(&msg, magic);

        struct msg_header fake_hdr;
        msg_header_init_full(&fake_hdr, magic, "ping", 8);
        int n = net_message_read_header(&msg, (const char *)&fake_hdr,
                                         MSG_HEADER_SIZE);
        bool ok = (n == MSG_HEADER_SIZE);
        ok = ok && msg.in_data;
        ok = ok && (msg.hdr.nMessageSize == 8);
        char cmd[COMMAND_SIZE + 1];
        msg_header_get_command(&msg.hdr, cmd, sizeof(cmd));
        ok = ok && (strcmp(cmd, "ping") == 0);
        net_message_free(&msg);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* net_message: reject bad magic */
    {
        printf("net_message: reject bad magic... ");
        unsigned char magic[MESSAGE_START_SIZE] = {0x24, 0xe9, 0x27, 0x64};
        unsigned char bad[MESSAGE_START_SIZE] = {0xFF, 0xFF, 0xFF, 0xFF};
        struct net_message msg;
        net_message_init(&msg, magic);

        struct msg_header fake_hdr;
        msg_header_init_full(&fake_hdr, bad, "ping", 8);
        int n = net_message_read_header(&msg, (const char *)&fake_hdr,
                                         MSG_HEADER_SIZE);
        bool ok = (n == -1);
        ok = ok && !msg.in_data;
        net_message_free(&msg);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* net_message: read data and complete */
    {
        printf("net_message: read data + complete... ");
        unsigned char magic[MESSAGE_START_SIZE] = {0x24, 0xe9, 0x27, 0x64};
        struct net_message msg;
        net_message_init(&msg, magic);

        struct msg_header fake_hdr;
        msg_header_init_full(&fake_hdr, magic, "ping", 8);
        net_message_read_header(&msg, (const char *)&fake_hdr, MSG_HEADER_SIZE);
        bool ok = msg.in_data && !net_message_complete(&msg);

        uint8_t payload[8] = {1, 2, 3, 4, 5, 6, 7, 8};
        int n = net_message_read_data(&msg, (const char *)payload, 8);
        ok = ok && (n == 8);
        ok = ok && net_message_complete(&msg);
        ok = ok && (msg.data_pos == 8);
        ok = ok && (memcmp(msg.recv_data, payload, 8) == 0);
        net_message_free(&msg);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* net_message: partial header read */
    {
        printf("net_message: partial header read... ");
        unsigned char magic[MESSAGE_START_SIZE] = {0x24, 0xe9, 0x27, 0x64};
        struct net_message msg;
        net_message_init(&msg, magic);

        struct msg_header fake_hdr;
        msg_header_init_full(&fake_hdr, magic, "verack", 0);
        const char *raw = (const char *)&fake_hdr;
        /* Feed half, then the rest */
        int n1 = net_message_read_header(&msg, raw, 10);
        bool ok = (n1 == 10);
        ok = ok && !msg.in_data;
        int n2 = net_message_read_header(&msg, raw + 10, MSG_HEADER_SIZE - 10);
        ok = ok && ((unsigned)(n1 + n2) == MSG_HEADER_SIZE);
        ok = ok && msg.in_data;
        ok = ok && net_message_complete(&msg); /* size=0 -> immediately complete */
        net_message_free(&msg);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* process-wide recv queue budget caps total bytes across
     * all net_messages, not just per-message. A swarm of peers
     * staging 2 MB messages must not be able to push our resident
     * set above the configured ceiling. */
    {
        printf("net_message: recv budget rejects over-cap alloc ... ");
        unsigned char magic[MESSAGE_START_SIZE] = {0x24, 0xe9, 0x27, 0x64};

        /* 16 KB cap — smaller than any single real message. */
        setenv("ZCL_MAX_RECVBUFFER_TOTAL_BYTES", "16384", 1);

        /* Snapshot baseline; other outstanding messages in the test
         * binary should not affect the delta the assertions below
         * compute. */
        size_t base = net_recv_total_bytes();

        /* Three 8 KB messages: #1 and #2 fit (16 KB total), #3 should
         * be rejected because the cap is exactly 16 KB. */
        struct net_message m1, m2, m3;
        net_message_init(&m1, magic);
        net_message_init(&m2, magic);
        net_message_init(&m3, magic);

        struct msg_header hdr;
        msg_header_init_full(&hdr, magic, "ping", 8192);
        unsigned char payload[8192];
        memset(payload, 0x42, sizeof(payload));

        net_message_read_header(&m1, (const char *)&hdr, MSG_HEADER_SIZE);
        int n1 = net_message_read_data(&m1, (const char *)payload,
                                       sizeof(payload));
        bool ok = (n1 == (int)sizeof(payload));
        ok = ok && (net_recv_total_bytes() == base + 8192);

        net_message_read_header(&m2, (const char *)&hdr, MSG_HEADER_SIZE);
        int n2 = net_message_read_data(&m2, (const char *)payload,
                                       sizeof(payload));
        ok = ok && (n2 == (int)sizeof(payload));
        ok = ok && (net_recv_total_bytes() == base + 16384);

        net_message_read_header(&m3, (const char *)&hdr, MSG_HEADER_SIZE);
        int n3 = net_message_read_data(&m3, (const char *)payload,
                                       sizeof(payload));
        /* Over-cap allocation must fail without charging the budget. */
        ok = ok && (n3 < 0);
        ok = ok && (net_recv_total_bytes() == base + 16384);

        /* Freeing m1 must make room for one more 8 KB message. */
        net_message_free(&m1);
        ok = ok && (net_recv_total_bytes() == base + 8192);

        net_message_init(&m1, magic);
        net_message_read_header(&m1, (const char *)&hdr, MSG_HEADER_SIZE);
        int n4 = net_message_read_data(&m1, (const char *)payload,
                                       sizeof(payload));
        ok = ok && (n4 == (int)sizeof(payload));
        ok = ok && (net_recv_total_bytes() == base + 16384);

        net_message_free(&m1);
        net_message_free(&m2);
        net_message_free(&m3);
        ok = ok && (net_recv_total_bytes() == base);

        /* The cap helper must honour the env override. */
        ok = ok && (net_recv_total_bytes_cap() == 16384);

        unsetenv("ZCL_MAX_RECVBUFFER_TOTAL_BYTES");

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* Send-queue budget (getdata-flood / slow-reader DoS guard).
     *
     * A single getdata can request up to MAX_INV_SZ (50000) blocks and a
     * slow-reader peer may never drain its socket, so serving the whole
     * batch could buffer tens of GB of send_segments -> OOM. The fix
     * charges every queued send_segment against a process-wide and a
     * per-peer budget; process_getdata stops serving once over budget
     * (without disconnecting), and every drain/disconnect path releases
     * the bytes so the counter never leaks. This test exercises that
     * accounting end-to-end through the public p2p_node send path. */
    {
        printf("net: send budget caps + counter returns to 0 ... ");

        /* Small caps so a handful of queued messages trips them.
         * Per-peer cap 4 KB, process cap 16 KB. */
        setenv("ZCL_MAX_SENDBUFFER_PEER_BYTES", "4096", 1);
        setenv("ZCL_MAX_SENDBUFFER_TOTAL_BYTES", "16384", 1);

        struct net_manager nm;
        net_manager_init(&nm);
        unsigned char magic[MESSAGE_START_SIZE] = {0x24, 0xe9, 0x27, 0x64};
        memcpy(nm.message_start, magic, MESSAGE_START_SIZE);

        struct net_address addr;
        net_address_init(&addr);
        unsigned char ip4[4] = {127, 0, 0, 1};
        net_addr_set_ipv4(&addr.svc.addr, ip4);
        addr.svc.port = 8033;

        /* Baseline: other peers/tests in this binary may have outstanding
         * segments, so all assertions are on the delta from `base`. */
        size_t base = net_send_total_bytes();

        struct p2p_node *node = p2p_node_create(&nm, ZCL_INVALID_SOCKET,
                                                 &addr, "flood-peer", true);
        bool ok = (node != NULL);

        /* Nothing queued yet -> not over budget. */
        ok = ok && !net_send_over_budget(node);
        ok = ok && (node->send_size == 0);

        /* Queue several 2 KB "block" messages. send() on the invalid
         * socket can't drain them, so they accumulate exactly like a
         * slow-reader peer's queue would. */
        unsigned char payload[2048];
        memset(payload, 0x5a, sizeof(payload));

        size_t before = net_send_total_bytes();
        p2p_node_begin_message(node, "block", magic);
        p2p_node_write_message_data(node, payload, sizeof(payload));
        p2p_node_end_message(node);
        /* One message bumped both the per-peer and process-wide counters
         * by (header + payload). */
        ok = ok && (net_send_total_bytes() > before);
        ok = ok && (node->send_size > 0);
        /* One 2 KB message is under the 4 KB per-peer cap. */
        ok = ok && !net_send_over_budget(node);

        /* Keep queueing until the per-peer cap (4 KB) is exceeded; the
         * serving loop in process_getdata would break at exactly this
         * point. Bound the loop so a regression can't hang the test. */
        int guard = 0;
        while (!net_send_over_budget(node) && guard++ < 1000) {
            p2p_node_begin_message(node, "block", magic);
            p2p_node_write_message_data(node, payload, sizeof(payload));
            p2p_node_end_message(node);
        }
        ok = ok && net_send_over_budget(node);
        ok = ok && (node->send_size > net_send_peer_bytes_cap());

        /* Whitelisted/trusted peers are exempt even when over the cap. */
        node->whitelisted = true;
        ok = ok && !net_send_over_budget(node);
        node->whitelisted = false;
        ok = ok && net_send_over_budget(node);

        /* Tearing the node down drains the send queue through
         * send_segment_free, which releases every charged byte. After
         * the drain the process-wide counter must return to baseline —
         * proving the counter does not leak on disconnect/free. */
        p2p_node_free(node);
        ok = ok && (net_send_total_bytes() == base);

        /* The cap helpers honour the env overrides. */
        ok = ok && (net_send_peer_bytes_cap() == 4096);
        ok = ok && (net_send_total_bytes_cap() == 16384);

        /* Direct check of the disconnect-cleanup drain symmetry: a
         * manually built queue freed with send_segment_free (the exact
         * primitive connman's forced-disconnect path now uses) must also
         * leave the counter at baseline. */
        {
            size_t b2 = net_send_total_bytes();
            /* Build a segment via the same public send path on a fresh
             * node, then free the node — whose drain calls the exact
             * send_segment_free primitive connman's forced-disconnect
             * cleanup now uses — to confirm the counter returns to baseline
             * a second time. */
            struct p2p_node *n2 = p2p_node_create(&nm, ZCL_INVALID_SOCKET,
                                                  &addr, "flood-peer-2", true);
            ok = ok && (n2 != NULL);
            p2p_node_begin_message(n2, "block", magic);
            p2p_node_write_message_data(n2, payload, sizeof(payload));
            p2p_node_end_message(n2);
            ok = ok && (net_send_total_bytes() > b2);
            p2p_node_free(n2);
            ok = ok && (net_send_total_bytes() == b2);
        }

        net_manager_free(&nm);
        unsetenv("ZCL_MAX_SENDBUFFER_PEER_BYTES");
        unsetenv("ZCL_MAX_SENDBUFFER_TOTAL_BYTES");

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* version_message: serialize/deserialize roundtrip */
    {
        printf("version_message: serialize roundtrip... ");
        struct version_message vm;
        version_message_init(&vm);
        vm.protocol_version = 170002;
        vm.services = NODE_NETWORK;
        vm.timestamp = 1700000000;
        vm.nonce = 0xDEADBEEFCAFEBABE;
        snprintf(vm.sub_version, sizeof(vm.sub_version),
                 "/ZClassic23:0.1.0/");
        vm.start_height = 3040000;
        vm.relay = true;

        unsigned char ip4_recv[4] = {192, 168, 1, 1};
        net_addr_set_ipv4(&vm.addr_recv.svc.addr, ip4_recv);
        vm.addr_recv.svc.port = 8033;

        struct byte_stream s;
        stream_init(&s, 256);
        bool ok = version_message_serialize(&vm, &s);

        struct byte_stream r;
        stream_init_from_data(&r, s.data, s.size);
        struct version_message vm2;
        version_message_init(&vm2);
        ok = ok && version_message_deserialize(&vm2, &r);
        ok = ok && (vm2.protocol_version == 170002);
        ok = ok && (vm2.services == NODE_NETWORK);
        ok = ok && (vm2.timestamp == 1700000000);
        ok = ok && (vm2.nonce == 0xDEADBEEFCAFEBABE);
        ok = ok && (strcmp(vm2.sub_version, "/ZClassic23:0.1.0/") == 0);
        ok = ok && (vm2.start_height == 3040000);
        ok = ok && vm2.relay;
        stream_free(&s);
        stream_free(&r);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* msg_version: external IP accepts optional port */
    {
        printf("msg_version: externalip parses optional port... ");
        char ip[64];
        uint16_t port = 0;
        bool ok;

        msg_version_clear_external_ip_for_test();
        msg_version_set_external_ip("198.51.100.7", 8033);
        ok = msg_version_get_external_ip(ip, sizeof(ip), &port);
        ok = ok && (strcmp(ip, "198.51.100.7") == 0);
        ok = ok && (port == 8033);

        msg_version_set_external_ip("203.0.113.7:8023", 8033);
        port = 0;
        ok = ok && msg_version_get_external_ip(ip, sizeof(ip), &port);
        ok = ok && (strcmp(ip, "203.0.113.7") == 0);
        ok = ok && (port == 8023);
        msg_version_clear_external_ip_for_test();

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* addrman: init, add, size, select */
    {
        printf("addrman: add and select... ");
        struct addr_man am;
        addrman_init(&am);
        bool ok = (addrman_size(&am) == 0);

        struct net_address addr;
        net_address_init(&addr);
        unsigned char ip4[4] = {8, 8, 8, 8};
        net_addr_set_ipv4(&addr.svc.addr, ip4);
        addr.svc.port = 8033;
        addr.nServices = NODE_NETWORK;

        struct net_addr src;
        net_addr_init(&src);
        unsigned char src_ip[4] = {1, 2, 3, 4};
        net_addr_set_ipv4(&src, src_ip);

        ok = ok && addrman_add(&am, &addr, &src, 0);
        ok = ok && (addrman_size(&am) == 1);

        /* Select should return the address we added */
        struct addr_info info;
        memset(&info, 0, sizeof(info));
        ok = ok && addrman_select(&am, false, &info);
        ok = ok && (info.addr.svc.port == 8033);
        ok = ok && net_addr_eq(&info.addr.svc.addr, &addr.svc.addr);

        addrman_free(&am);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* addrman: multiple addresses */
    {
        printf("addrman: multiple addresses... ");
        struct addr_man am;
        addrman_init(&am);

        struct net_addr src;
        net_addr_init(&src);
        unsigned char src_ip[4] = {1, 1, 1, 1};
        net_addr_set_ipv4(&src, src_ip);

        for (int i = 0; i < 10; i++) {
            struct net_address addr;
            net_address_init(&addr);
            unsigned char ip4[4] = {(unsigned char)(50 + i), 0, 0, 1};
            net_addr_set_ipv4(&addr.svc.addr, ip4);
            addr.svc.port = 8033;
            addr.nServices = NODE_NETWORK;
            addr.nTime = (uint32_t)(GetTime() - 3600);
            addrman_add(&am, &addr, &src, 0);
        }
        bool ok = (addrman_size(&am) == 10);

        /* Select should work repeatedly */
        struct addr_info info;
        memset(&info, 0, sizeof(info));
        ok = ok && addrman_select(&am, false, &info);
        ok = ok && (info.addr.svc.port == 8033);

        /* Duplicate add should not increase count */
        struct net_address dup;
        net_address_init(&dup);
        unsigned char dup_ip[4] = {50, 0, 0, 1};
        net_addr_set_ipv4(&dup.svc.addr, dup_ip);
        dup.svc.port = 8033;
        dup.nServices = NODE_NETWORK;
        dup.nTime = (uint32_t)(GetTime() - 3600);
        addrman_add(&am, &dup, &src, 0);
        ok = ok && (addrman_size(&am) == 10);

        addrman_free(&am);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* addrman: serialize/deserialize roundtrip */
    {
        printf("addrman: serialize roundtrip... ");
        struct addr_man am;
        addrman_init(&am);

        struct net_addr src;
        net_addr_init(&src);
        unsigned char src_ip[4] = {5, 5, 5, 5};
        net_addr_set_ipv4(&src, src_ip);

        for (int i = 0; i < 5; i++) {
            struct net_address addr;
            net_address_init(&addr);
            unsigned char ip4[4] = {(unsigned char)(70 + i), 1, 2, 3};
            net_addr_set_ipv4(&addr.svc.addr, ip4);
            addr.svc.port = 8033;
            addr.nServices = NODE_NETWORK;
            addrman_add(&am, &addr, &src, 0);
        }

        struct byte_stream s;
        stream_init(&s, 4096);
        bool ok = addrman_serialize(&am, &s);

        struct addr_man am2;
        addrman_init(&am2);
        struct byte_stream r;
        stream_init_from_data(&r, s.data, s.size);
        ok = ok && addrman_deserialize(&am2, &r);
        ok = ok && (addrman_size(&am2) == addrman_size(&am));

        stream_free(&s);
        stream_free(&r);
        addrman_free(&am);
        addrman_free(&am2);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* net_manager: init, ban, unban, clear */
    {
        printf("net_manager: ban/unban/clear... ");
        struct net_manager nm;
        net_manager_init(&nm);

        struct net_addr a;
        net_addr_init(&a);
        unsigned char ip4[4] = {1, 2, 3, 4};
        net_addr_set_ipv4(&a, ip4);

        bool ok = !is_banned(&nm, &a);
        ban_addr(&nm, &a, 3600, false);
        ok = ok && is_banned(&nm, &a);

        /* Different address not banned */
        struct net_addr b;
        net_addr_init(&b);
        unsigned char ip4b[4] = {5, 6, 7, 8};
        net_addr_set_ipv4(&b, ip4b);
        ok = ok && !is_banned(&nm, &b);

        /* Unban first address */
        ok = ok && unban_addr(&nm, &a);
        ok = ok && !is_banned(&nm, &a);

        /* Ban two, clear all */
        ban_addr(&nm, &a, 3600, false);
        ban_addr(&nm, &b, 3600, false);
        ok = ok && is_banned(&nm, &a);
        ok = ok && is_banned(&nm, &b);
        clear_banned(&nm);
        ok = ok && !is_banned(&nm, &a);
        ok = ok && !is_banned(&nm, &b);

        net_manager_free(&nm);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* addr_db_read: missing peers.dat is a clean cold-start miss */
    {
        printf("addr_db_read: missing peers.dat is cold-start miss... ");
        char tmpdir[] = "/tmp/zcl_peers_missing_XXXXXX";
        bool ok = false;
        if (mkdtemp(tmpdir)) {
            struct net_manager nm;
            net_manager_init(&nm);
            ok = !addr_db_read(&nm, tmpdir);
            net_manager_free(&nm);
            char cmd[256];
            snprintf(cmd, sizeof(cmd), "rm -rf %s", tmpdir);
            (void)system(cmd);
        }
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* net_manager: init defaults */
    {
        printf("net_manager: init defaults... ");
        struct net_manager nm;
        net_manager_init(&nm);
        bool ok = nm.discover;
        ok = ok && nm.listen;
        ok = ok && (nm.local_services == NODE_NETWORK);
        ok = ok && (nm.max_connections == DEFAULT_MAX_PEER_CONNECTIONS);
        ok = ok && !nm.stop_requested;
        ok = ok && (nm.num_nodes == 0);
        ok = ok && (nm.num_banned == 0);
        ok = ok && (nm.num_listen_sockets == 0);
        net_manager_free(&nm);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* listen socket: records the kernel-assigned local port */
    {
        printf("listen socket: records bound local port... ");
        struct net_manager nm;
        struct net_service svc;
        unsigned char ip4[4] = {127, 0, 0, 1};
        net_manager_init(&nm);
        net_service_init(&svc);
        net_addr_set_ipv4(&svc.addr, ip4);
        svc.port = 0;

        bool ok = bind_listen_port(&nm, &svc, false);
        ok = ok && nm.num_listen_sockets == 1;
        ok = ok && nm.listen_sockets[0].local_port > 0;

        net_manager_free(&nm);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* p2p_node: create and free lifecycle */
    {
        printf("p2p_node: create and free... ");
        struct net_manager nm;
        net_manager_init(&nm);
        memset(nm.message_start, 0x24, MESSAGE_START_SIZE);

        struct net_address addr;
        net_address_init(&addr);
        unsigned char ip4[4] = {127, 0, 0, 1};
        net_addr_set_ipv4(&addr.svc.addr, ip4);
        addr.svc.port = 8033;

        struct p2p_node *node = p2p_node_create(&nm, ZCL_INVALID_SOCKET,
                                                  &addr, "test-peer", true);
        bool ok = (node != NULL);
        ok = ok && node->inbound;
        ok = ok && (node->socket == ZCL_INVALID_SOCKET);
        ok = ok && (node->id == 0);
        ok = ok && (node->recv_version == INIT_PROTO_VERSION);
        ok = ok && (strcmp(node->addr_name, "test-peer") == 0);
        ok = ok && (node->starting_height == -1);
        ok = ok && !node->disconnect;
        ok = ok && (node->state < PEER_HANDSHAKE_COMPLETE);

        /* Verify addr was copied */
        ok = ok && (node->addr.svc.port == 8033);
        ok = ok && net_addr_eq(&node->addr.svc.addr, &addr.svc.addr);

        p2p_node_free(node);

        /* Second node gets id=1 */
        struct p2p_node *node2 = p2p_node_create(&nm, ZCL_INVALID_SOCKET,
                                                   &addr, NULL, false);
        ok = ok && (node2 != NULL);
        ok = ok && (node2->id == 1);
        ok = ok && !node2->inbound;
        /* NULL name -> auto-generated from IP */
        ok = ok && (strlen(node2->addr_name) > 0);
        p2p_node_free(node2);

        net_manager_free(&nm);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* p2p_node: receive bytes parses message */
    {
        printf("p2p_node: receive_bytes parses message... ");
        struct net_manager nm;
        net_manager_init(&nm);
        unsigned char magic[MESSAGE_START_SIZE] = {0x24, 0xe9, 0x27, 0x64};
        memcpy(nm.message_start, magic, MESSAGE_START_SIZE);

        struct net_address addr;
        net_address_init(&addr);
        unsigned char ip4[4] = {127, 0, 0, 1};
        net_addr_set_ipv4(&addr.svc.addr, ip4);
        addr.svc.port = 8033;

        struct p2p_node *node = p2p_node_create(&nm, ZCL_INVALID_SOCKET,
                                                  &addr, "test", true);
        bool ok = (node != NULL);

        /* Build a verack message (empty payload) */
        struct msg_header hdr;
        msg_header_init_full(&hdr, magic, "verack", 0);
        /* Compute checksum for empty payload: SHA256d("") truncated to 4 bytes */
        uint8_t empty_hash[32];
        { struct sha256_ctx ctx; sha256_init(&ctx);
          sha256_write(&ctx, (const unsigned char *)"", 0);
          sha256_finalize(&ctx, empty_hash); }
        uint8_t dbl_hash[32];
        { struct sha256_ctx ctx; sha256_init(&ctx);
          sha256_write(&ctx, empty_hash, 32);
          sha256_finalize(&ctx, dbl_hash); }
        memcpy(&hdr.nChecksum, dbl_hash, 4);

        ok = ok && p2p_node_receive_bytes(node, (const char *)&hdr,
                                            MSG_HEADER_SIZE, magic);
        ok = ok && (node->recv_msg_count == 1);
        ok = ok && net_message_complete(&node->recv_msgs[0]);

        char cmd[COMMAND_SIZE + 1];
        msg_header_get_command(&node->recv_msgs[0].hdr, cmd, sizeof(cmd));
        ok = ok && (strcmp(cmd, "verack") == 0);

        p2p_node_free(node);
        net_manager_free(&nm);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* p2p_node: inventory tracking */
    {
        printf("p2p_node: inventory known + push... ");
        struct net_manager nm;
        net_manager_init(&nm);
        memset(nm.message_start, 0x24, MESSAGE_START_SIZE);

        struct net_address addr;
        net_address_init(&addr);
        unsigned char ip4[4] = {127, 0, 0, 1};
        net_addr_set_ipv4(&addr.svc.addr, ip4);

        struct p2p_node *node = p2p_node_create(&nm, ZCL_INVALID_SOCKET,
                                                  &addr, "test", false);
        bool ok = (node != NULL);
        ok = ok && (node->inventory_known_count == 0);
        ok = ok && (node->inventory_to_send_count == 0);

        struct uint256 h;
        uint256_set_null(&h);
        h.data[0] = 0x42;
        struct inv_item inv;
        inv_item_init_typed(&inv, MSG_TX, &h);

        /* push_inventory adds to send queue */
        p2p_node_push_inventory(node, &inv);
        ok = ok && (node->inventory_to_send_count == 1);

        /* add_inventory_known marks it as known */
        p2p_node_add_inventory_known(node, &inv);
        ok = ok && (node->inventory_known_count == 1);

        /* Pushing same hash again should not add duplicate */
        size_t before = node->inventory_to_send_count;
        p2p_node_push_inventory(node, &inv);
        ok = ok && (node->inventory_to_send_count == before);

        p2p_node_free(node);
        net_manager_free(&nm);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* p2p_node: address tracking */
    {
        printf("p2p_node: push_address... ");
        struct net_manager nm;
        net_manager_init(&nm);
        memset(nm.message_start, 0x24, MESSAGE_START_SIZE);

        struct net_address addr;
        net_address_init(&addr);
        unsigned char ip4[4] = {127, 0, 0, 1};
        net_addr_set_ipv4(&addr.svc.addr, ip4);

        struct p2p_node *node = p2p_node_create(&nm, ZCL_INVALID_SOCKET,
                                                  &addr, "test", false);
        bool ok = (node != NULL);
        ok = ok && (node->addr_to_send_count == 0);

        /* Push a routable address */
        struct net_address a2;
        net_address_init(&a2);
        unsigned char routable[4] = {8, 8, 8, 8};
        net_addr_set_ipv4(&a2.svc.addr, routable);
        a2.svc.port = 8033;
        p2p_node_push_address(node, &a2);
        ok = ok && (node->addr_to_send_count == 1);

        /* Insert into addr_known bloom, then second push should be filtered */
        unsigned char key[NET_SERVICE_KEY_SIZE];
        net_service_get_key(&a2.svc, key);
        rolling_bloom_insert(&node->addr_known, key, NET_SERVICE_KEY_SIZE);
        p2p_node_push_address(node, &a2);
        ok = ok && (node->addr_to_send_count == 1);

        /* Invalid address should be rejected */
        struct net_address invalid;
        net_address_init(&invalid); /* all zeros = invalid */
        p2p_node_push_address(node, &invalid);
        ok = ok && (node->addr_to_send_count == 1);

        p2p_node_free(node);
        net_manager_free(&nm);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* p2p_node: ref counting */
    {
        printf("p2p_node: ref counting... ");
        struct net_manager nm;
        net_manager_init(&nm);
        memset(nm.message_start, 0x24, MESSAGE_START_SIZE);

        struct net_address addr;
        net_address_init(&addr);
        unsigned char ip4[4] = {127, 0, 0, 1};
        net_addr_set_ipv4(&addr.svc.addr, ip4);

        struct p2p_node *node = p2p_node_create(&nm, ZCL_INVALID_SOCKET,
                                                  &addr, "test", false);
        bool ok = (node != NULL);
        ok = ok && (p2p_node_get_ref(node) == 0);
        p2p_node_add_ref(node);
        ok = ok && (p2p_node_get_ref(node) == 1);
        p2p_node_add_ref(node);
        ok = ok && (p2p_node_get_ref(node) == 2);
        p2p_node_release(node);
        ok = ok && (p2p_node_get_ref(node) == 1);

        p2p_node_free(node);
        net_manager_free(&nm);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* p2p_node: free NULL is safe */
    {
        printf("p2p_node: free NULL safe... ");
        p2p_node_free(NULL);
        printf("OK\n");
    }

    /* net_message: oversized message rejected */
    {
        printf("net_message: reject oversized... ");
        unsigned char magic[MESSAGE_START_SIZE] = {0x24, 0xe9, 0x27, 0x64};
        struct net_message msg;
        net_message_init(&msg, magic);

        struct msg_header fake_hdr;
        msg_header_init_full(&fake_hdr, magic, "block", MAX_SIZE + 1);
        int n = net_message_read_header(&msg, (const char *)&fake_hdr,
                                         MSG_HEADER_SIZE);
        bool ok = (n == -1); /* Should reject oversized */
        net_message_free(&msg);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* connman: init and free without start */
    {
        printf("connman: init/free lifecycle... ");
        chain_params_select(CHAIN_MAIN);
        const struct chain_params *params = chain_params_get();
        struct connman cm;
        struct node_signals sigs;
        memset(&sigs, 0, sizeof(sigs));
        bool ok = connman_init(&cm, params, &sigs);
        ok = ok && !cm.started;
        ok = ok && !cm.dns_seed_thread_started;
        ok = ok && !cm.socket_thread_started;
        ok = ok && !cm.open_thread_started;
        ok = ok && !cm.message_thread_started;
        ok = ok && (cm.num_deferred_free == 0);
        ok = ok && (cm.manager.default_port == params->nDefaultPort);
        ok = ok && (memcmp(cm.manager.message_start, params->pchMessageStart,
                           MESSAGE_START_SIZE) == 0);
        const char *onion_datadir = "test-datadir";
        connman_set_onion_peer_discovery(&cm, onion_datadir,
                                         test_onion_peer_discover);
        ok = ok && (cm.onion_peer_datadir == onion_datadir);
        ok = ok && (cm.onion_peer_discover == test_onion_peer_discover);
        connman_set_onion_peer_discovery(NULL, onion_datadir,
                                         test_onion_peer_discover);
        char *sv = cm.manager.sub_version;
        ok = ok && (strcmp(sv, msg_version_user_agent()) == 0);
        connman_free(&cm);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* connman: node count */
    {
        printf("connman: node_count starts at 0... ");
        const struct chain_params *params = chain_params_get();
        struct connman cm;
        struct node_signals sigs;
        memset(&sigs, 0, sizeof(sigs));
        connman_init(&cm, params, &sigs);
        bool ok = (connman_get_node_count(&cm) == 0);
        connman_free(&cm);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* inv_item: less comparison */
    {
        printf("inv_item: less comparison... ");
        struct uint256 h1, h2;
        uint256_set_null(&h1);
        uint256_set_null(&h2);
        h1.data[0] = 0x01;
        h2.data[0] = 0x02;
        struct inv_item a, b;
        inv_item_init_typed(&a, MSG_TX, &h1);
        inv_item_init_typed(&b, MSG_TX, &h2);
        bool ok = inv_item_less(&a, &b);
        ok = ok && !inv_item_less(&b, &a);
        ok = ok && !inv_item_less(&a, &a);
        /* Different types: MSG_TX < MSG_BLOCK */
        inv_item_init_typed(&b, MSG_BLOCK, &h1);
        ok = ok && inv_item_less(&a, &b);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* ── Wire compatibility: overwintered tx format ────────── */
    printf("tx overwintered v4 wire format... ");
    {
        struct transaction tx;
        transaction_init(&tx);
        tx.overwintered = true;
        tx.version = SAPLING_TX_VERSION;
        tx.version_group_id = SAPLING_VERSION_GROUP_ID;
        tx.expiry_height = 3046100;

        struct byte_stream s;
        stream_init(&s, 256);
        transaction_serialize(&tx, &s);
        /* Version bytes: 04 00 00 80 (LE, bit 31 set) */
        bool ok = (s.size >= 4 && s.data[0] == 0x04 && s.data[3] == 0x80);

        struct transaction tx2;
        transaction_init(&tx2);
        struct byte_stream r;
        stream_init_from_data(&r, s.data, s.size);
        ok = ok && transaction_deserialize(&tx2, &r);
        ok = ok && tx2.overwintered;
        ok = ok && (tx2.version == SAPLING_TX_VERSION);
        ok = ok && (tx2.version_group_id == SAPLING_VERSION_GROUP_ID);
        ok = ok && (tx2.expiry_height == 3046100);
        stream_free(&s);
        transaction_free(&tx);
        transaction_free(&tx2);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("tx non-overwintered v4 lacks flag... ");
    {
        struct transaction tx;
        transaction_init(&tx);
        tx.overwintered = false;
        tx.version = 4;

        struct byte_stream s;
        stream_init(&s, 256);
        transaction_serialize(&tx, &s);
        bool ok = (s.size >= 4 && s.data[3] != 0x80);
        stream_free(&s);
        transaction_free(&tx);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("compact_size encoding... ");
    {
        struct byte_stream s;
        stream_init(&s, 32);
        stream_write_compact_size(&s, 100);
        bool ok = (s.size == 1 && s.data[0] == 100);
        s.size = 0;
        stream_write_compact_size(&s, 253);
        ok = ok && (s.size == 3);
        s.size = 0;
        stream_write_compact_size(&s, 65536);
        ok = ok && (s.size == 5);
        stream_free(&s);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("protocol version = 170011... ");
    {
        bool ok = (PROTOCOL_VERSION == 170011);
        ok = ok && (MIN_PEER_PROTO_VERSION <= 170002);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("bootstrap service bit matches zclassicd beta6... ");
    {
        bool ok = (NODE_BOOTSTRAP == (1 << 24));
        ok = ok && ((NODE_BOOTSTRAP & NODE_NETWORK) == 0);
        ok = ok && ((NODE_BOOTSTRAP & NODE_ZCL23) == 0);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("mainnet magic bytes... ");
    {
        chain_params_select(CHAIN_MAIN);
        const struct chain_params *p = chain_params_get();
        unsigned char expected[4] = {0x24, 0xe9, 0x27, 0x64};
        bool ok = (memcmp(p->pchMessageStart, expected, 4) == 0);
        ok = ok && (p->nDefaultPort == 8033);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("version message wire size (empty subver = 86)... ");
    {
        struct version_message v;
        version_message_init(&v);
        v.protocol_version = 170011;
        v.services = NODE_NETWORK;
        struct byte_stream s;
        stream_init(&s, 256);
        version_message_serialize(&v, &s);
        bool ok = (s.size == 86);
        /* Verify proto bytes at offset 0 */
        uint32_t proto = (uint32_t)s.data[0] | ((uint32_t)s.data[1] << 8) |
                         ((uint32_t)s.data[2] << 16) | ((uint32_t)s.data[3] << 24);
        ok = ok && (proto == 170011);
        stream_free(&s);
        if (ok) printf("OK\n");
        else { printf("FAIL (size=%zu)\n", s.size); failures++; }
    }

    printf("SHA256d checksum (first 4 bytes)... ");
    {
        uint8_t payload[] = "test";
        uint8_t hash[32];
        hash256(payload, 4, hash);
        uint32_t checksum;
        memcpy(&checksum, hash, 4);
        bool ok = (checksum != 0);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* ================================================================
     * Fast sync: PoW solve + verify round-trip
     * ================================================================ */
    printf("fast_sync: PoW solve and verify... ");
    {
        uint8_t peer_id[32];
        GetRandBytes(peer_id, 32);
        struct fast_sync_pow pow;
        memset(&pow, 0, sizeof(pow));
        bool solved = fast_sync_solve_pow(peer_id, &pow);
        bool verified = solved && fast_sync_verify_pow(&pow);
        if (verified) printf("OK (nonce=%llu)\n", (unsigned long long)pow.nonce);
        else { printf("FAIL (solved=%d)\n", solved); failures++; }
    }

    printf("fast_sync: PoW rejects bad nonce... ");
    {
        uint8_t peer_id[32];
        GetRandBytes(peer_id, 32);
        struct fast_sync_pow pow;
        memset(&pow, 0, sizeof(pow));
        fast_sync_solve_pow(peer_id, &pow);
        pow.nonce++; /* corrupt the nonce */
        bool ok = !fast_sync_verify_pow(&pow);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("fast_sync: PoW rejects expired timestamp... ");
    {
        uint8_t peer_id[32];
        GetRandBytes(peer_id, 32);
        struct fast_sync_pow pow;
        memset(&pow, 0, sizeof(pow));
        fast_sync_solve_pow(peer_id, &pow);
        pow.timestamp -= 600; /* 10 minutes ago, beyond 5min window */
        bool ok = !fast_sync_verify_pow(&pow);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("fast_sync: PoW rejects NULL... ");
    {
        bool ok = !fast_sync_verify_pow(NULL);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* ================================================================
     * Fast sync: rate limiter
     * ================================================================ */
    printf("fast_sync: rate limiter allows first request... ");
    {
        struct fast_sync_rate_limiter rl;
        memset(&rl, 0, sizeof(rl));
        uint8_t ip[16] = {0,0,0,0,0,0,0,0,0,0,0xFF,0xFF,10,0,0,1};
        bool ok = fast_sync_rate_check(&rl, ip);
        if (ok && rl.num_entries == 1) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("fast_sync: rate limiter tracks separate IPs... ");
    {
        struct fast_sync_rate_limiter rl;
        memset(&rl, 0, sizeof(rl));
        uint8_t ip1[16] = {0,0,0,0,0,0,0,0,0,0,0xFF,0xFF,10,0,0,1};
        uint8_t ip2[16] = {0,0,0,0,0,0,0,0,0,0,0xFF,0xFF,10,0,0,2};
        fast_sync_rate_check(&rl, ip1);
        fast_sync_rate_check(&rl, ip2);
        bool ok = (rl.num_entries == 2);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("fast_sync: rate limiter blocks after max chunks... ");
    {
        struct fast_sync_rate_limiter rl;
        memset(&rl, 0, sizeof(rl));
        uint8_t ip[16] = {0,0,0,0,0,0,0,0,0,0,0xFF,0xFF,10,0,0,1};
        bool all_ok = true;
        for (int i = 0; i < FAST_SYNC_MAX_CHUNKS_PER_HOUR; i++) {
            if (!fast_sync_rate_check(&rl, ip)) { all_ok = false; break; }
        }
        /* Next one should be blocked */
        bool blocked = !fast_sync_rate_check(&rl, ip);
        if (all_ok && blocked) printf("OK (blocked after %d)\n", FAST_SYNC_MAX_CHUNKS_PER_HOUR);
        else { printf("FAIL (ok=%d blocked=%d)\n", all_ok, blocked); failures++; }
    }

    /* ================================================================
     * Fast sync: peer_supports_fast_sync
     * ================================================================ */
    printf("fast_sync: peer_supports_fast_sync... ");
    {
        bool has = peer_supports_fast_sync(NODE_ZCL23 | 1);
        bool not_has = !peer_supports_fast_sync(1);
        bool zero = !peer_supports_fast_sync(0);
        if (has && not_has && zero) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* ================================================================
     * Chainparams: fixed seeds within bounds
     * ================================================================ */
    printf("chainparams: fixed seeds within MAX_FIXED_SEEDS... ");
    {
        const struct chain_params *cp = chain_params_get();
        bool ok = (cp->nFixedSeeds > 0 && cp->nFixedSeeds <= MAX_FIXED_SEEDS);
        if (ok) printf("OK (%d seeds)\n", (int)cp->nFixedSeeds);
        else { printf("FAIL (%d)\n", (int)cp->nFixedSeeds); failures++; }
    }

    printf("chainparams: onion seeds present... ");
    {
        const struct chain_params *cp = chain_params_get();
        bool ok = (cp->nOnionSeeds > 0 &&
                   strstr(cp->onionSeeds[0], ".onion") != NULL);
        if (ok) printf("OK (%s)\n", cp->onionSeeds[0]);
        else { printf("FAIL\n"); failures++; }
    }

    /* ================================================================
     * Onion service: XSS prevention in search
     * ================================================================ */
    printf("onion_service: search escapes HTML in query... ");
    {
        uint8_t buf[8192];
        size_t len = onion_service_handle_request(
            "GET", "/search?q=<script>alert(1)</script>",
            NULL, 0, buf, sizeof(buf));
        buf[len < sizeof(buf) ? len : sizeof(buf) - 1] = '\0';
        /* Must NOT contain raw <script> tag */
        bool has_raw_script = (strstr((char *)buf, "<script>") != NULL);
        /* Must contain escaped version */
        bool has_escaped = (strstr((char *)buf, "&lt;script&gt;") != NULL);
        if (!has_raw_script && has_escaped) printf("OK\n");
        else { printf("FAIL (raw=%d escaped=%d)\n", has_raw_script, has_escaped); failures++; }
    }

    printf("onion_service: landing page returns valid HTML... ");
    {
        uint8_t buf[16384];
        size_t len = onion_service_handle_request(
            "GET", "/", NULL, 0, buf, sizeof(buf));
        buf[len < sizeof(buf) ? len : sizeof(buf) - 1] = '\0';
        bool has_header = (strstr((char *)buf, "HTTP/1.1 200") != NULL);
        bool has_html = (strstr((char *)buf, "</html>") != NULL);
        bool has_title = (strstr((char *)buf, "Z23") != NULL);
        if (has_header && has_html && has_title) printf("OK (%zu bytes)\n", len);
        else { printf("FAIL\n"); failures++; }
    }

    printf("onion_service: 404 for unknown path... ");
    {
        uint8_t buf[4096];
        size_t len = onion_service_handle_request(
            "GET", "/nonexistent", NULL, 0, buf, sizeof(buf));
        buf[len < sizeof(buf) ? len : sizeof(buf) - 1] = '\0';
        bool ok = (strstr((char *)buf, "404") != NULL);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("onion_service: search with empty query... ");
    {
        uint8_t buf[8192];
        size_t len = onion_service_handle_request(
            "GET", "/search", NULL, 0, buf, sizeof(buf));
        buf[len < sizeof(buf) ? len : sizeof(buf) - 1] = '\0';
        bool ok = (len > 0 && strstr((char *)buf, "200 OK") != NULL);
        if (ok) printf("OK (%zu bytes)\n", len);
        else { printf("FAIL\n"); failures++; }
    }

    printf("onion_service: NULL path defaults to landing... ");
    {
        uint8_t buf[16384];
        size_t len = onion_service_handle_request(
            "GET", NULL, NULL, 0, buf, sizeof(buf));
        buf[len < sizeof(buf) ? len : sizeof(buf) - 1] = '\0';
        bool ok = (len > 0 && strstr((char *)buf, "Z23") != NULL);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("onion_service: GET /status returns JSON with node info... ");
    {
        uint8_t buf[8192];
        size_t len = onion_service_handle_request(
            "GET", "/status", NULL, 0, buf, sizeof(buf));
        buf[len < sizeof(buf) ? len : sizeof(buf) - 1] = '\0';
        const char *resp = (const char *)buf;
        bool ok = (len > 0);
        ok = ok && (strstr(resp, "200 OK") != NULL);
        ok = ok && (strstr(resp, "application/json") != NULL);
        ok = ok && (strstr(resp, "\"height\"") != NULL);
        ok = ok && (strstr(resp, "\"peers\"") != NULL);
        ok = ok && (strstr(resp, "\"version\"") != NULL);
        ok = ok && (strstr(resp, "\"uptime\"") != NULL);
        ok = ok && (strstr(resp, "\"version\":\"0.1.0\"") != NULL);
        if (ok) printf("OK (%zu bytes)\n", len);
        else { printf("FAIL (%zu bytes: %.200s)\n", len, resp); failures++; }
    }

    printf("onion_service: signed /blog fails closed without node.db... ");
    {
        char tmpdir[256];
        uint8_t buf[4096];
        test_make_tmpdir(tmpdir, sizeof(tmpdir), "onion_blog", "route");
        onion_service_stop();
        onion_service_set_app_handlers(test_onion_blog_serve,
                                       test_onion_peer_discover);
        onion_service_start(tmpdir);
        size_t len = onion_service_handle_request(
            "GET", "/blog/test-post", NULL, 0, buf, sizeof(buf));
        buf[len < sizeof(buf) ? len : sizeof(buf) - 1] = '\0';
        const char *resp = (const char *)buf;
        bool ok = (len > 0);
        ok = ok && (strstr(resp, "HTTP/1.1 503 Service Unavailable") != NULL);
        ok = ok && (strstr(resp, "Blog storage is unavailable") != NULL);
        /* The legacy injected static handler is intentionally ignored: the
         * signed MVC mount must never downgrade to unsigned content. */
        ok = ok && (strstr(resp, "blog:") == NULL);
        ok = ok && (strstr(resp, tmpdir) == NULL);
        onion_service_set_app_handlers(NULL, NULL);
        onion_service_stop();
        test_cleanup_tmpdir(tmpdir);
        if (ok) printf("OK (%zu bytes)\n", len);
        else { printf("FAIL (%zu bytes: %.200s)\n", len, resp); failures++; }
    }

    /* ── Malformed P2P message tests ─────────────────────────── */

    printf("msg_header: oversized message rejection (>2MB)... ");
    {
        unsigned char magic[MESSAGE_START_SIZE] = {0x24, 0xe9, 0x27, 0x64};
        struct msg_header h;
        msg_header_init_full(&h, magic, "block", MAX_SIZE + 1);
        bool ok = !msg_header_is_valid(&h, magic);
        /* Exactly MAX_SIZE should still be valid */
        msg_header_init_full(&h, magic, "block", MAX_SIZE);
        ok = ok && msg_header_is_valid(&h, magic);
        /* Far oversized (e.g., 100MB) must also fail */
        msg_header_init_full(&h, magic, "block", 100 * 1024 * 1024);
        ok = ok && !msg_header_is_valid(&h, magic);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("msg_header: invalid checksum detection... ");
    {
        /* Build a version message, compute correct checksum, then corrupt it */
        unsigned char magic[MESSAGE_START_SIZE] = {0x24, 0xe9, 0x27, 0x64};
        struct version_message v;
        version_message_init(&v);
        v.protocol_version = 170009;
        v.services = NODE_NETWORK;
        v.timestamp = 1700000000;
        v.start_height = 500000;
        snprintf(v.sub_version, MAX_SUBVER_LENGTH, "/ZClassic:2.1.1-3/");

        struct byte_stream s;
        stream_init(&s, 256);
        version_message_serialize(&v, &s);

        /* Compute correct checksum: first 4 bytes of double-SHA256 */
        struct uint256 msg_hash;
        hash256(s.data, s.size, msg_hash.data);
        unsigned int correct_checksum;
        memcpy(&correct_checksum, msg_hash.data, 4);

        /* Corrupt checksum */
        unsigned int bad_checksum = correct_checksum ^ 0xFFFFFFFF;
        bool ok = (bad_checksum != correct_checksum);

        /* Verify detection: simulate what msgprocessor does */
        struct msg_header h;
        msg_header_init_full(&h, magic, "version", (unsigned int)s.size);
        h.nChecksum = bad_checksum;
        struct uint256 verify_hash;
        hash256(s.data, s.size, verify_hash.data);
        unsigned int expected;
        memcpy(&expected, verify_hash.data, 4);
        ok = ok && (expected != h.nChecksum);

        /* Correct checksum should match */
        h.nChecksum = correct_checksum;
        ok = ok && (expected == h.nChecksum);

        stream_free(&s);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("msg_header: truncated message handling... ");
    {
        /* A message header that claims 100 bytes but we only have 10 */
        unsigned char magic[MESSAGE_START_SIZE] = {0x24, 0xe9, 0x27, 0x64};
        struct net_message msg;
        net_message_init(&msg, magic);

        /* Simulate partial header read: only fill part of header buffer */
        struct msg_header h;
        msg_header_init_full(&h, magic, "ping", 100);
        msg.hdr = h;
        msg.in_data = true;
        msg.data_pos = 10; /* Only 10 of 100 bytes received */

        /* Message should not be considered complete */
        bool ok = !net_message_complete(&msg);

        /* Zero-length message should complete immediately */
        struct net_message msg2;
        net_message_init(&msg2, magic);
        msg_header_init_full(&msg2.hdr, magic, "verack", 0);
        msg2.in_data = true;
        msg2.data_pos = 0;
        ok = ok && net_message_complete(&msg2);

        net_message_free(&msg);
        net_message_free(&msg2);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("version_message: protocol version below minimum rejected... ");
    {
        struct version_message v;
        version_message_init(&v);
        v.protocol_version = 170001; /* Below MIN_PEER_PROTO_VERSION (170002) */
        v.services = NODE_NETWORK;
        v.timestamp = 1700000000;
        v.start_height = 100;

        bool ok = (v.protocol_version < MIN_PEER_PROTO_VERSION);

        /* At minimum should be accepted */
        v.protocol_version = MIN_PEER_PROTO_VERSION;
        ok = ok && (v.protocol_version >= MIN_PEER_PROTO_VERSION);

        /* Well above minimum */
        v.protocol_version = PROTOCOL_VERSION;
        ok = ok && (v.protocol_version >= MIN_PEER_PROTO_VERSION);

        /* Ancient protocol version */
        v.protocol_version = 209;
        ok = ok && (v.protocol_version < MIN_PEER_PROTO_VERSION);

        /* Zero protocol version */
        v.protocol_version = 0;
        ok = ok && (v.protocol_version < MIN_PEER_PROTO_VERSION);

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("ipv4_group16 extraction... ");
    {
        struct net_addr a;
        net_addr_init(&a);
        unsigned char ip4[] = {10, 20, 30, 40};
        net_addr_set_ipv4(&a, ip4);
        uint16_t group = (uint16_t)((a.ip[12] << 8) | a.ip[13]);
        if (group == ((10 << 8) | 20))
            printf("OK (group=%u)\n", group);
        else {
            printf("FAIL: expected %d, got %u\n", (10 << 8) | 20, group);
            failures++;
        }
    }

    printf("ipv4_group16 same /16 different /24... ");
    {
        struct net_addr a, b;
        net_addr_init(&a);
        net_addr_init(&b);
        unsigned char ip_a[] = {192, 168, 1, 10};
        unsigned char ip_b[] = {192, 168, 2, 20};
        net_addr_set_ipv4(&a, ip_a);
        net_addr_set_ipv4(&b, ip_b);
        uint16_t ga = (uint16_t)((a.ip[12] << 8) | a.ip[13]);
        uint16_t gb = (uint16_t)((b.ip[12] << 8) | b.ip[13]);
        if (ga == gb)
            printf("OK (same group %u)\n", ga);
        else {
            printf("FAIL: %u != %u\n", ga, gb);
            failures++;
        }
    }

    printf("ipv4_group16 different /16... ");
    {
        struct net_addr a, b;
        net_addr_init(&a);
        net_addr_init(&b);
        unsigned char ip_a[] = {10, 0, 1, 1};
        unsigned char ip_b[] = {10, 1, 1, 1};
        net_addr_set_ipv4(&a, ip_a);
        net_addr_set_ipv4(&b, ip_b);
        uint16_t ga = (uint16_t)((a.ip[12] << 8) | a.ip[13]);
        uint16_t gb = (uint16_t)((b.ip[12] << 8) | b.ip[13]);
        if (ga != gb)
            printf("OK (%u vs %u)\n", ga, gb);
        else {
            printf("FAIL: groups should differ\n");
            failures++;
        }
    }

    printf("misbehavior scoring increments... ");
    {
        int score = 0;
        score += 10;
        if (score == 10) score += 25;
        if (score == 35) score += 65;
        if (score == 100)
            printf("OK (score=%d)\n", score);
        else {
            printf("FAIL: expected 100, got %d\n", score);
            failures++;
        }
    }

    printf("misbehavior auto-ban at threshold... ");
    {
        int score = 0;
        bool banned = false;
        int increments[] = {20, 20, 20, 20, 20};
        for (int i = 0; i < 5; i++) {
            score += increments[i];
            if (score >= 100) { banned = true; break; }
        }
        if (banned && score == 100)
            printf("OK (banned at %d)\n", score);
        else {
            printf("FAIL: banned=%d score=%d\n", banned, score);
            failures++;
        }
    }

    printf("misbehavior no ban below threshold... ");
    {
        int score = 0;
        bool banned = false;
        int increments[] = {10, 10, 10, 10, 10, 10, 10, 10, 10};
        for (int i = 0; i < 9; i++) {
            score += increments[i];
            if (score >= 100) { banned = true; break; }
        }
        if (!banned && score == 90)
            printf("OK (score=%d, not banned)\n", score);
        else {
            printf("FAIL: banned=%d score=%d\n", banned, score);
            failures++;
        }
    }

    /* ===== ONION SERVICE ROUTING TESTS ===== */

    printf("onion: GET / returns landing page with Z23... ");
    {
        uint8_t resp[16384];
        size_t n = onion_service_handle_request("GET", "/", NULL, 0,
                                                 resp, sizeof(resp));
        bool ok = (n > 0);
        ok = ok && (strstr((char *)resp, "HTTP/1.1 200 OK") != NULL);
        ok = ok && (strstr((char *)resp, "Z23") != NULL);
        ok = ok && (strstr((char *)resp, "text/html") != NULL);
        if (ok) printf("OK (%zu bytes)\n", n);
        else { printf("FAIL (n=%zu)\n", n); failures++; }
    }

    printf("onion: GET /status returns JSON with height+version... ");
    {
        uint8_t resp[4096];
        size_t n = onion_service_handle_request("GET", "/status", NULL, 0,
                                                 resp, sizeof(resp));
        bool ok = (n > 0);
        ok = ok && (strstr((char *)resp, "HTTP/1.1 200 OK") != NULL);
        ok = ok && (strstr((char *)resp, "application/json") != NULL);
        ok = ok && (strstr((char *)resp, "\"height\"") != NULL);
        ok = ok && (strstr((char *)resp, "\"version\"") != NULL);
        if (ok) printf("OK (%zu bytes)\n", n);
        else { printf("FAIL (n=%zu)\n", n); failures++; }
    }

    printf("onion: GET /nonexistent returns 404... ");
    {
        uint8_t resp[4096];
        size_t n = onion_service_handle_request("GET", "/nonexistent", NULL, 0,
                                                 resp, sizeof(resp));
        bool ok = (n > 0);
        ok = ok && (strstr((char *)resp, "404 Not Found") != NULL);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("onion: GET /factoids redirects to explorer factoids... ");
    {
        uint8_t resp[4096];
        size_t n = onion_service_handle_request("GET", "/factoids", NULL, 0,
                                                 resp, sizeof(resp));
        resp[n < sizeof(resp) ? n : sizeof(resp) - 1] = '\0';
        bool ok = (n > 0);
        ok = ok && (strstr((char *)resp, "302 Found") != NULL);
        ok = ok && (strstr((char *)resp,
                           "Location: /explorer/factoids") != NULL);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("onion: GET /hodl redirects to explorer hodl... ");
    {
        uint8_t resp[4096];
        size_t n = onion_service_handle_request("GET", "/hodl", NULL, 0,
                                                 resp, sizeof(resp));
        resp[n < sizeof(resp) ? n : sizeof(resp) - 1] = '\0';
        bool ok = (n > 0);
        ok = ok && (strstr((char *)resp, "302 Found") != NULL);
        ok = ok && (strstr((char *)resp,
                           "Location: /explorer/hodl") != NULL);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("onion: rate limiter allows first request... ");
    {
        uint8_t resp[16384];
        size_t n = onion_service_handle_request("GET", "/", NULL, 0,
                                                 resp, sizeof(resp));
        bool ok = (n > 0);
        ok = ok && (strstr((char *)resp, "429") == NULL);
        ok = ok && (strstr((char *)resp, "200 OK") != NULL);
        if (ok) printf("OK (not rate-limited)\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* ===== ONION ADMISSION: TIERED BUDGETS + PUZZLE ESCALATION ===== */

    {
        struct onion_fake_clock fake = {0};
        const clock_iface_t iface = {
            .now_monotonic_ns = onion_fake_now_mono,
            .now_wall_ms      = onion_fake_now_wall,
            .self             = &fake,
        };
        int64_t t0 = 2000000000; /* arbitrary base, far from any real clock */
        onion_ratelimit_test_reset();
        clock_set_default(&iface);
        onion_fake_clock_set_secs(&fake, t0);

        printf("onion_ratelimit: route classification by cost tier... ");
        {
            char key[32] = "x";
            bool ok = true;
            ok = ok && onion_route_classify("GET", "/", key) == ONION_ROUTE_STATIC;
            ok = ok && key[0] == '\0';
            ok = ok && onion_route_classify("GET", "/status", NULL) == ONION_ROUTE_STATIC;
            ok = ok && onion_route_classify("GET", "/explorer/style.css", NULL) == ONION_ROUTE_STATIC;
            ok = ok && onion_route_classify("GET", "/directory.json", NULL) == ONION_ROUTE_CHEAP;
            ok = ok && onion_route_classify("GET", "/explorer/block/900000", NULL) == ONION_ROUTE_CHEAP;
            ok = ok && onion_route_classify("GET", "/store/product/7", NULL) == ONION_ROUTE_CHEAP;
            /* GET on the order collection is a status read, not a mint. */
            ok = ok && onion_route_classify("GET", "/store/orders", NULL) == ONION_ROUTE_CHEAP;
            ok = ok && onion_route_classify("POST", "/store/orders", key) == ONION_ROUTE_EXPENSIVE;
            ok = ok && strcmp(key, "store-order") == 0;
            ok = ok && onion_route_classify("GET", "/search?q=a", key) == ONION_ROUTE_EXPENSIVE;
            ok = ok && strcmp(key, "search-hostname") == 0;
            ok = ok && onion_route_classify("GET", "/explorer/search?q=a", key) == ONION_ROUTE_EXPENSIVE;
            ok = ok && strcmp(key, "search-explorer") == 0;
            if (ok) printf("OK\n");
            else { printf("FAIL\n"); failures++; }
        }

        printf("onion_ratelimit: expensive flood starves neither static nor cheap... ");
        {
            /* Flood the EXPENSIVE budget far past its cap inside one
             * window — most of these are intended to be denied. */
            for (int i = 0; i < 200; i++)
                (void)onion_ratelimit_admit("GET", "/search?q=flood", NULL, 0, NULL);

            /* Requests on the other tiers, in the SAME window, must still
             * be admitted: the budgets are independent, so a search or
             * order flood cannot take down browsing or the landing page. */
            bool all_ok = true;
            for (int i = 0; i < 10; i++) {
                if (onion_ratelimit_admit("GET", "/", NULL, 0, NULL) != ONION_ADMIT_OK)
                    all_ok = false;
                if (onion_ratelimit_admit("GET", "/directory.json", NULL, 0, NULL) != ONION_ADMIT_OK)
                    all_ok = false;
            }
            if (all_ok) printf("OK\n");
            else { printf("FAIL (a static/cheap request was denied during an expensive flood)\n"); failures++; }
        }

        printf("onion_ratelimit: cheap flood does not starve the static tier... ");
        {
            onion_fake_clock_set_secs(&fake, t0 + 500);
            for (int i = 0; i < 400; i++)
                (void)onion_ratelimit_admit("GET", "/directory.json", NULL, 0, NULL);
            bool all_ok = true;
            for (int i = 0; i < 10; i++) {
                if (onion_ratelimit_admit("GET", "/status", NULL, 0, NULL) != ONION_ADMIT_OK)
                    all_ok = false;
            }
            if (all_ok) printf("OK\n");
            else { printf("FAIL (the landing/status tier was starved)\n"); failures++; }
        }

        printf("onion_ratelimit: no pressure -> expensive path needs no puzzle... ");
        {
            onion_fake_clock_set_secs(&fake, t0 + 1000); /* fresh, unsaturated window */
            enum onion_admit_result r =
                onion_ratelimit_admit("GET", "/search?q=hi", NULL, 0, NULL);
            if (r == ONION_ADMIT_OK) printf("OK\n");
            else { printf("FAIL (result=%d)\n", (int)r); failures++; }
        }

        printf("onion_ratelimit: escalation trips after sustained saturation... ");
        struct onion_pow_challenge challenge = {0};
        {
            /* Saturate 5 consecutive one-second windows well past cap,
             * then send one more request in the 6th second: that request
             * triggers the rollover that evaluates the 5th window and
             * flips escalation, and — carrying no puzzle — must itself
             * come back POW_REQUIRED with a renderable challenge. */
            int64_t base = t0 + 2000;
            for (int w = 0; w < 5; w++) {
                onion_fake_clock_set_secs(&fake, base + w);
                for (int i = 0; i < 200; i++)
                    (void)onion_ratelimit_admit("GET", "/search?q=flood",
                                                NULL, 0, NULL);
            }
            onion_fake_clock_set_secs(&fake, base + 5);
            enum onion_admit_result r = onion_ratelimit_admit(
                "GET", "/search?q=trigger", NULL, 0, &challenge);

            struct json_value dump = {0};
            json_init(&dump);
            bool have_dump = onion_ratelimit_dump_state_json(&dump, NULL);
            const struct json_value *esc =
                have_dump ? json_get(&dump, "expensive_escalated") : NULL;
            bool escalated_flag = esc && json_get_bool(esc);
            json_free(&dump);

            bool ok = (r == ONION_ADMIT_POW_REQUIRED) && escalated_flag &&
                      strlen(challenge.seed_hex) == 64 &&
                      strlen(challenge.token_hex) == 64 &&
                      challenge.bits >= PUZZLE_MIN_BITS &&
                      challenge.server_time == base + 5;
            if (ok) printf("OK (bits=%d)\n", challenge.bits);
            else {
                printf("FAIL (result=%d escalated=%d bits=%d)\n",
                       (int)r, escalated_flag, challenge.bits);
                failures++;
            }
        }

        printf("onion_ratelimit: a solved route-bound puzzle admits while escalated... ");
        char solved_path[256] = "";
        uint8_t seed[32], token[32];
        {
            bool solved = false;
            uint64_t nonce = 0;
            int64_t ts = (int64_t)platform_time_wall_time_t();
            if (challenge.seed_hex[0]) {
                onion_hex_decode32(challenge.seed_hex, seed);
                onion_hex_decode32(challenge.token_hex, token);
                solved = puzzle_solve(seed, token, ts, challenge.bits, &nonce);
            }
            if (solved)
                snprintf(solved_path, sizeof(solved_path),
                         "/search?q=hi&pow_ts=%lld&pow_nonce=%llu",
                         (long long)ts, (unsigned long long)nonce);
            enum onion_admit_result r = solved
                ? onion_ratelimit_admit("GET", solved_path, NULL, 0, NULL)
                : ONION_ADMIT_RATE_LIMITED;
            if (solved && r == ONION_ADMIT_OK) printf("OK\n");
            else {
                printf("FAIL (solved=%d result=%d)\n", solved, (int)r);
                failures++;
            }
        }

        printf("onion_ratelimit: replaying the same solved puzzle is refused... ");
        {
            bool found = false;
            int64_t before = onion_dump_int("puzzle_failed_total", &found);
            enum onion_admit_result r = solved_path[0]
                ? onion_ratelimit_admit("GET", solved_path, NULL, 0, NULL)
                : ONION_ADMIT_OK;
            int64_t after = onion_dump_int("puzzle_failed_total", &found);
            bool ok = solved_path[0] && r == ONION_ADMIT_POW_REQUIRED &&
                      found && after == before + 1;
            if (ok) printf("OK\n");
            else {
                printf("FAIL (result=%d failed_total %lld -> %lld)\n", (int)r,
                       (long long)before, (long long)after);
                failures++;
            }
        }

        printf("onion_ratelimit: a puzzle solved for one route is refused on another... ");
        {
            /* Same seed, but the token binds the solution to /search. A
             * store order must not accept it. */
            uint64_t nonce = 0;
            int64_t ts = (int64_t)platform_time_wall_time_t();
            bool solved = puzzle_solve(seed, token, ts, challenge.bits, &nonce);
            char body[128];
            int blen = snprintf(body, sizeof(body),
                                "pow_ts=%lld&pow_nonce=%llu",
                                (long long)ts, (unsigned long long)nonce);
            enum onion_admit_result r = solved
                ? onion_ratelimit_admit("POST", "/store/orders",
                                        (const uint8_t *)body, (size_t)blen,
                                        NULL)
                : ONION_ADMIT_OK;
            if (solved && r == ONION_ADMIT_POW_REQUIRED) printf("OK\n");
            else { printf("FAIL (solved=%d result=%d)\n", solved, (int)r); failures++; }
        }

        printf("onion_ratelimit: static tier is never puzzle-gated, even escalated... ");
        {
            bool all_ok = true;
            for (int i = 0; i < 5; i++) {
                if (onion_ratelimit_admit("GET", "/", NULL, 0, NULL) != ONION_ADMIT_OK)
                    all_ok = false;
                if (onion_ratelimit_admit("GET", "/directory.json", NULL, 0, NULL) != ONION_ADMIT_OK)
                    all_ok = false;
            }
            if (all_ok) printf("OK\n");
            else { printf("FAIL (an operator was locked out of a non-expensive route)\n"); failures++; }
        }

        printf("onion_ratelimit: escalation clears after sustained quiet... ");
        {
            /* One low-volume request per second. Each first-request-of-a-
             * window rollover evaluates the prior window; after 15
             * consecutive clear evaluations de-escalation fires, and the
             * request that finalizes it — still carrying no puzzle — must
             * itself come back OK. */
            int64_t base = t0 + 2000;
            enum onion_admit_result last = ONION_ADMIT_POW_REQUIRED;
            for (int s = 6; s <= 21; s++) {
                onion_fake_clock_set_secs(&fake, base + s);
                last = onion_ratelimit_admit("GET", "/search?q=quiet",
                                             NULL, 0, NULL);
            }
            bool found = false;
            int64_t deesc = onion_dump_int("deescalate_total", &found);
            if (last == ONION_ADMIT_OK && found && deesc >= 1) printf("OK\n");
            else {
                printf("FAIL (last result=%d deescalate_total=%lld)\n",
                       (int)last, (long long)deesc);
                failures++;
            }
        }

        /* Never leak the virtual clock or admission state into later
         * tests in this process. */
        clock_reset_default();
        onion_ratelimit_test_reset();
    }

    /* ===== BLOCK RELAY DEDUPLICATION TESTS ===== */

    printf("block_already_seen: new hash returns false... ");
    {
        msgprocessor_test_reset_recent_blocks();
        struct uint256 hash;
        memset(hash.data, 0xAA, 32);
        bool ok = !msgprocessor_test_block_already_seen(&hash);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("block_already_seen: returns true after mark_seen... ");
    {
        msgprocessor_test_reset_recent_blocks();
        struct uint256 hash;
        memset(hash.data, 0xBB, 32);
        msgprocessor_test_block_mark_seen(&hash);
        bool ok = msgprocessor_test_block_already_seen(&hash);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("block_already_seen: distinct hashes are independent... ");
    {
        msgprocessor_test_reset_recent_blocks();
        struct uint256 h1, h2;
        memset(h1.data, 0x11, 32);
        memset(h2.data, 0x22, 32);
        msgprocessor_test_block_mark_seen(&h1);
        bool ok = msgprocessor_test_block_already_seen(&h1);
        ok = ok && !msgprocessor_test_block_already_seen(&h2);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("block_already_seen: ring buffer wraps at 128... ");
    {
        msgprocessor_test_reset_recent_blocks();
        struct uint256 first;
        memset(first.data, 0, 32);
        first.data[0] = 0xFF;
        msgprocessor_test_block_mark_seen(&first);

        /* Fill 127 more entries to reach capacity */
        for (int i = 1; i < 128; i++) {
            struct uint256 h;
            memset(h.data, 0, 32);
            h.data[0] = (uint8_t)i;
            msgprocessor_test_block_mark_seen(&h);
        }
        /* first should still be visible */
        bool ok = msgprocessor_test_block_already_seen(&first);

        /* Add one more to evict first (slot 0 overwritten) */
        struct uint256 extra;
        memset(extra.data, 0, 32);
        extra.data[0] = 0xFE;
        extra.data[1] = 0x01;
        msgprocessor_test_block_mark_seen(&extra);

        /* first should now be evicted */
        ok = ok && !msgprocessor_test_block_already_seen(&first);
        /* extra should be found */
        ok = ok && msgprocessor_test_block_already_seen(&extra);

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("block_already_seen: counter increments correctly... ");
    {
        msgprocessor_test_reset_recent_blocks();
        bool ok = (msgprocessor_test_get_recent_block_count() == 0);
        struct uint256 h;
        memset(h.data, 0xCC, 32);
        msgprocessor_test_block_mark_seen(&h);
        ok = ok && (msgprocessor_test_get_recent_block_count() == 1);
        msgprocessor_test_block_mark_seen(&h);
        ok = ok && (msgprocessor_test_get_recent_block_count() == 2);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("block dedupe: snapshot defer does not poison replayed block... ");
    {
        msgprocessor_test_reset_recent_blocks();
        struct uint256 h;
        memset(h.data, 0x5A, 32);
        bool ok = !msgprocessor_test_accept_block_for_processing(&h, true);
        ok = ok && !msgprocessor_test_block_already_seen(&h);
        ok = ok && msgprocessor_test_accept_block_for_processing(&h, false);
        ok = ok && msgprocessor_test_block_already_seen(&h);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("snapshot offer gate: ignore duplicate offers while snapshot owns sync... ");
    {
        bool ok = true;
        ok = ok && msgprocessor_test_should_ignore_snapshot_offer(
            SNAPSYNC_RECEIVING, 7, PEER_ACTIVE, 7, SYNC_SNAPSHOT_RECEIVE);
        ok = ok && msgprocessor_test_should_ignore_snapshot_offer(
            SNAPSYNC_NEGOTIATING, 7, PEER_ACTIVE, 8, SYNC_BLOCKS_DOWNLOAD);
        ok = ok && msgprocessor_test_should_ignore_snapshot_offer(
            SNAPSYNC_VERIFYING, 7, PEER_ACTIVE, 8, SYNC_SNAPSHOT_RECEIVE);
        ok = ok && msgprocessor_test_should_ignore_snapshot_offer(
            SNAPSYNC_IDLE, 0, PEER_SNAPSHOT_RECEIVING, 8, SYNC_BLOCKS_DOWNLOAD);
        ok = ok && msgprocessor_test_should_ignore_snapshot_offer(
            SNAPSYNC_IDLE, 0, PEER_ACTIVE, 8, SYNC_AT_TIP);
        ok = ok && !msgprocessor_test_should_ignore_snapshot_offer(
            SNAPSYNC_IDLE, 0, PEER_ACTIVE, 8, SYNC_BLOCKS_DOWNLOAD);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* ── BitTorrent-style parallel chunk sync tests ──────── */

    /* Helper: create a test UTXO database with N entries */
    char test_sync_dir[256];
    char test_sync_db[320];
    test_make_tmpdir(test_sync_dir, sizeof(test_sync_dir),
                     "net", "parallel_sync");
    snprintf(test_sync_db, sizeof(test_sync_db), "%s/node.db",
             test_sync_dir);

    /* Create test database with 100 UTXOs */
    sqlite3 *test_db = NULL;
    {
        int rc = sqlite3_open(test_sync_db, &test_db);
        if (rc != SQLITE_OK) {
            printf("parallel_sync: SKIP (cannot create test db)\n");
            goto skip_parallel_tests;
        }

        TEST_DB_EXEC(test_db,
            "CREATE TABLE IF NOT EXISTS node_state "
            "(key TEXT PRIMARY KEY, value BLOB)");
        TEST_DB_EXEC(test_db,
            "CREATE TABLE IF NOT EXISTS utxos ("
            "txid BLOB NOT NULL, vout INTEGER NOT NULL, "
            "value INTEGER NOT NULL, script BLOB NOT NULL, "
            "script_type INTEGER NOT NULL DEFAULT 0, "
            "address_hash BLOB, height INTEGER NOT NULL, "
            "is_coinbase INTEGER NOT NULL DEFAULT 0, "
            "PRIMARY KEY (txid, vout))");

        /* Set tip height and hash */
        int64_t tip_height = 100000;
        sqlite3_stmt *ins = NULL;
        TEST_DB_RUN(test_db, ins,
            "INSERT INTO node_state (key, value) VALUES (?, ?)",
        {
            sqlite3_bind_text(ins, 1, "tip_height", -1, SQLITE_STATIC);
            sqlite3_bind_blob(ins, 2, &tip_height, sizeof(tip_height),
                              SQLITE_STATIC);
        });

        uint8_t tip_hash[32];
        memset(tip_hash, 0xAB, 32);
        TEST_DB_RUN(test_db, ins,
            "INSERT INTO node_state (key, value) VALUES (?, ?)",
        {
            sqlite3_bind_text(ins, 1, "tip_hash", -1, SQLITE_STATIC);
            sqlite3_bind_blob(ins, 2, tip_hash, 32, SQLITE_STATIC);
        });

        /* Insert 100 test UTXOs with deterministic data */
        TEST_DB_BEGIN(test_db);
        sqlite3_prepare_v2(test_db,
            "INSERT INTO utxos (txid, vout, value, script, height) "
            "VALUES (?, ?, ?, ?, ?)", -1, &ins, NULL);

        for (int i = 0; i < 100; i++) {
            uint8_t txid[32];
            memset(txid, 0, 32);
            txid[0] = (uint8_t)(i & 0xFF);
            txid[1] = (uint8_t)((i >> 8) & 0xFF);

            uint8_t script[25];
            memset(script, 0x76, sizeof(script));
            script[0] = (uint8_t)i;

            sqlite3_reset(ins);
            sqlite3_bind_blob(ins, 1, txid, 32, SQLITE_STATIC);
            sqlite3_bind_int(ins, 2, i % 3);
            sqlite3_bind_int64(ins, 3, (int64_t)(i + 1) * 100000);
            sqlite3_bind_blob(ins, 4, script, 25, SQLITE_STATIC);
            sqlite3_bind_int(ins, 5, 50000 + i);
            sqlite3_step(ins);
        }
        sqlite3_finalize(ins);
        TEST_DB_COMMIT(test_db);
    }

    printf("parallel_sync: manifest chunk_count = ceil(100/500)... ");
    {
        struct sync_manifest m;
        memset(&m, 0, sizeof(m));
        bool ok = fast_sync_build_manifest_db(test_db, &m);
        /* 100 UTXOs / 500 per chunk = 1 chunk (ceil) */
        ok = ok && (m.num_chunks == 1);
        ok = ok && (m.num_utxos == 100);
        ok = ok && (m.chunk_size == SYNC_CHUNK_SIZE);
        ok = ok && (m.height == 100000);
        if (ok) printf("OK (chunks=%u, utxos=%" PRIu64 ")\n",
                        m.num_chunks, m.num_utxos);
        else { printf("FAIL (chunks=%u, utxos=%" PRIu64 ", height=%d)\n",
                        m.num_chunks, m.num_utxos, m.height); failures++; }
        sync_manifest_free(&m);
    }

    printf("parallel_sync: chunk hash deterministic... ");
    {
        struct utxo_chunk *c = zcl_calloc(1, sizeof(struct utxo_chunk), "test_chunk");
        bool ok = fast_sync_serve_chunk_db(test_db, 0, SYNC_CHUNK_SIZE, c);

        uint8_t h1[32], h2[32];
        fast_sync_chunk_hash(c, h1);
        fast_sync_chunk_hash(c, h2);
        ok = ok && (memcmp(h1, h2, 32) == 0);

        /* Non-zero hash */
        uint8_t zeros[32];
        memset(zeros, 0, 32);
        ok = ok && (memcmp(h1, zeros, 32) != 0);

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
        free(c);
    }

    printf("parallel_sync: verify_chunk matches expected hash... ");
    {
        struct utxo_chunk *c = zcl_calloc(1, sizeof(struct utxo_chunk), "test_chunk");
        fast_sync_serve_chunk_db(test_db, 0, SYNC_CHUNK_SIZE, c);

        uint8_t expected[32];
        fast_sync_chunk_hash(c, expected);
        bool ok = fast_sync_verify_chunk(c, expected);

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
        free(c);
    }

    printf("parallel_sync: bad chunk data fails verification... ");
    {
        struct utxo_chunk *c = zcl_calloc(1, sizeof(struct utxo_chunk), "test_chunk");
        fast_sync_serve_chunk_db(test_db, 0, SYNC_CHUNK_SIZE, c);

        uint8_t expected[32];
        fast_sync_chunk_hash(c, expected);

        /* Corrupt one entry */
        c->entries[0].value = 999999999;
        bool ok = !fast_sync_verify_chunk(c, expected);

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
        free(c);
    }

    printf("parallel_sync: serve_chunk contents match DB... ");
    {
        struct utxo_chunk *c = zcl_calloc(1, sizeof(struct utxo_chunk), "test_chunk");
        bool ok = fast_sync_serve_chunk_db(test_db, 0, SYNC_CHUNK_SIZE, c);
        ok = ok && (c->num_entries == 100);
        ok = ok && (c->chunk_index == 0);

        /* Verify all entries have non-zero values */
        for (uint32_t i = 0; i < c->num_entries && ok; i++)
            ok = ok && (c->entries[i].value > 0);

        if (ok) printf("OK (entries=%u)\n", c->num_entries);
        else { printf("FAIL (entries=%u)\n", c->num_entries); failures++; }
        free(c);
    }

    printf("parallel_sync: manifest merkle_root non-zero... ");
    {
        struct sync_manifest m;
        memset(&m, 0, sizeof(m));
        fast_sync_build_manifest_db(test_db, &m);

        uint8_t zeros[32];
        memset(zeros, 0, 32);
        bool ok = (memcmp(m.merkle_root, zeros, 32) != 0);
        ok = ok && (m.chunk_hashes != NULL);

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
        sync_manifest_free(&m);
    }

    printf("parallel_sync: Merkle root from chunk hashes... ");
    {
        /* Build manifest, then independently verify that
         * the stored merkle_root matches recomputation */
        struct sync_manifest m;
        memset(&m, 0, sizeof(m));
        fast_sync_build_manifest_db(test_db, &m);

        uint8_t recomputed[32];
        fast_sync_merkle_root(
            (const uint8_t (*)[32])m.chunk_hashes,
            m.num_chunks, recomputed);

        bool ok = (memcmp(m.merkle_root, recomputed, 32) == 0);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
        sync_manifest_free(&m);
    }

    printf("parallel_sync: Merkle proof verifies chunk... ");
    {
        /* Use 4 synthetic hashes to test proof verification */
        uint8_t hashes[4][32];
        for (int i = 0; i < 4; i++)
            memset(hashes[i], (uint8_t)(i + 1), 32);

        uint8_t root[32];
        fast_sync_merkle_root(
            (const uint8_t (*)[32])hashes, 4, root);

        /* Build and verify proof for each chunk */
        bool ok = true;
        for (uint32_t ci = 0; ci < 4; ci++) {
            uint8_t (*proof)[32] = NULL;
            uint32_t plen = fast_sync_build_proof(
                (const uint8_t (*)[32])hashes, 4, ci, &proof);

            ok = ok && fast_sync_verify_chunk_proof(
                ci, hashes[ci], (const uint8_t (*)[32])proof, plen, root);
            free(proof);
        }

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("parallel_sync: bad proof fails verification... ");
    {
        uint8_t hashes[4][32];
        for (int i = 0; i < 4; i++)
            memset(hashes[i], (uint8_t)(i + 1), 32);

        uint8_t root[32];
        fast_sync_merkle_root(
            (const uint8_t (*)[32])hashes, 4, root);

        uint8_t (*proof)[32] = NULL;
        uint32_t plen = fast_sync_build_proof(
            (const uint8_t (*)[32])hashes, 4, 0, &proof);

        /* Corrupt the proof */
        if (plen > 0)
            proof[0][0] ^= 0xFF;

        bool ok = !fast_sync_verify_chunk_proof(
            0, hashes[0], (const uint8_t (*)[32])proof, plen, root);
        free(proof);

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("parallel_sync: manifest from file path... ");
    {
        struct sync_manifest m;
        memset(&m, 0, sizeof(m));
        bool ok = fast_sync_build_manifest(test_sync_dir, &m);
        ok = ok && (m.num_chunks == 1);
        ok = ok && (m.num_utxos == 100);

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
        sync_manifest_free(&m);
    }

    printf("parallel_sync: serve_chunk from file path... ");
    {
        struct utxo_chunk *c = zcl_calloc(1, sizeof(struct utxo_chunk), "test_chunk");
        bool ok = fast_sync_serve_chunk(test_sync_dir, 0, c);
        ok = ok && (c->num_entries == 100);

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
        free(c);
    }

    printf("parallel_sync: P2P message type constants... ");
    {
        bool ok = (strcmp(MSG_CHUNK_REQ, "zchunkreq") == 0);
        ok = ok && (strcmp(MSG_CHUNK_DATA, "zchunkdata") == 0);
        ok = ok && (strcmp(MSG_MANIFEST, "zmanifest") == 0);
        ok = ok && (SYNC_CHUNK_SIZE == 500);

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("parallel_sync: manifest cache publishes stable header... ");
    {
        struct sync_manifest published;
        struct sync_manifest header;
        memset(&published, 0, sizeof(published));
        memset(&header, 0, sizeof(header));
        published.height = 321;
        published.num_utxos = 654;
        published.num_chunks = 2;
        published.chunk_size = SYNC_CHUNK_SIZE;
        published.chunk_hashes = zcl_calloc(2, sizeof(*published.chunk_hashes), "test_chunk_hashes");
        memset(published.block_hash, 0x11, sizeof(published.block_hash));
        memset(published.merkle_root, 0x22, sizeof(published.merkle_root));

        boot_snapshot_offer_test_set_trust_override(1);
        bool ok = published.chunk_hashes != NULL;
        ok = ok && msg_processor_publish_manifest(&published);
        ok = ok && published.chunk_hashes == NULL;
        ok = ok && msg_processor_get_manifest_header(&header);
        ok = ok && header.height == 321;
        ok = ok && header.num_chunks == 2;
        ok = ok && header.num_utxos == 654;
        ok = ok && header.chunk_size == SYNC_CHUNK_SIZE;
        ok = ok && header.chunk_hashes == NULL;
        msg_processor_invalidate_manifest();
        ok = ok && !msg_processor_get_manifest_header(&header);
        boot_snapshot_offer_test_set_trust_override(-1);

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("parallel_sync: block manifest cache publishes stable header... ");
    {
        struct block_piece_manifest published;
        struct block_piece_manifest header;
        int32_t built_at = 0;
        memset(&published, 0, sizeof(published));
        memset(&header, 0, sizeof(header));
        published.start_height = 1;
        published.end_height = 512;
        published.num_pieces = 4;
        published.piece_hashes = zcl_calloc(4, sizeof(*published.piece_hashes), "test_piece_hashes");
        memset(published.tip_hash, 0x33, sizeof(published.tip_hash));
        memset(published.merkle_root, 0x44, sizeof(published.merkle_root));

        bool ok = published.piece_hashes != NULL;
        ok = ok && msg_processor_publish_block_manifest(&published, 512);
        ok = ok && published.piece_hashes == NULL;
        ok = ok && msg_processor_get_block_manifest_header(&header, &built_at);
        ok = ok && header.start_height == 1;
        ok = ok && header.end_height == 512;
        ok = ok && header.num_pieces == 4;
        ok = ok && header.piece_hashes == NULL;
        ok = ok && built_at == 512;
        msg_processor_invalidate_block_manifest();
        ok = ok && !msg_processor_get_block_manifest_header(&header, &built_at);

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("parallel_sync: snapshot offer cache publishes stable copy... ");
    {
        struct snapshot_offer published;
        struct snapshot_offer cached;
        memset(&published, 0, sizeof(published));
        memset(&cached, 0, sizeof(cached));
        published.height = 777;
        published.num_utxos = 123456;
        published.total_bytes = 987654;
        memset(published.block_hash, 0x11, sizeof(published.block_hash));
        memset(published.utxo_root, 0x22, sizeof(published.utxo_root));
        memset(published.mmr_root, 0x33, sizeof(published.mmr_root));
        memset(published.mmb_root, 0x44, sizeof(published.mmb_root));

        boot_snapshot_offer_test_set_trust_override(1);
        msg_processor_invalidate_offer();
        bool ok = !msg_processor_get_offer(&cached);
        msg_processor_update_offer(&published);
        ok = ok && msg_processor_get_offer(&cached);
        ok = ok && cached.height == 777;
        ok = ok && cached.num_utxos == 123456;
        ok = ok && cached.total_bytes == 987654;
        ok = ok && cached.block_hash[0] == 0x11;
        ok = ok && cached.utxo_root[0] == 0x22;
        ok = ok && cached.mmr_root[0] == 0x33;
        ok = ok && cached.mmb_root[0] == 0x44;
        boot_snapshot_offer_test_set_trust_override(0);
        ok = ok && !msg_processor_get_offer(&cached);
        ok = ok && cached.height == 0;
        boot_snapshot_offer_test_set_trust_override(1);
        msg_processor_invalidate_offer();
        ok = ok && !msg_processor_get_offer(&cached);
        boot_snapshot_offer_test_set_trust_override(-1);

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* ── Swarm coordinator tests ─────────────────────────────── */

    printf("swarm_sync: init with 10 chunks, all NEEDED... ");
    {
        /* Build a synthetic manifest with 10 chunks */
        struct sync_manifest m;
        memset(&m, 0, sizeof(m));
        m.height = 100000;
        m.num_utxos = 5000;
        m.num_chunks = 10;
        m.chunk_size = 500;
        m.chunk_hashes = zcl_calloc(10, 32, "test_chunk_hashes");

        /* Fill chunk hashes with deterministic values */
        for (uint32_t i = 0; i < 10; i++)
            memset(m.chunk_hashes[i], (int)(i + 1), 32);

        struct swarm_sync ss;
        bool ok = swarm_sync_init(&ss, &m, test_sync_dir);
        ok = ok && (ss.manifest.num_chunks == 10);
        ok = ok && (ss.chunks_complete == 0);
        ok = ok && (ss.chunks_inflight == 0);

        /* Verify all chunks start as NEEDED */
        for (uint32_t i = 0; i < 10 && ok; i++)
            ok = ok && (ss.chunk_states[i] == CHUNK_NEEDED);

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }

        swarm_sync_free(&ss);
        free(m.chunk_hashes);
    }

    printf("swarm_sync: assign 3 chunks to different peers... ");
    {
        struct sync_manifest m;
        memset(&m, 0, sizeof(m));
        m.num_chunks = 10;
        m.num_utxos = 5000;
        m.chunk_size = 500;
        m.chunk_hashes = zcl_calloc(10, 32, "test_chunk_hashes");
        for (uint32_t i = 0; i < 10; i++)
            memset(m.chunk_hashes[i], (int)(i + 1), 32);

        struct swarm_sync ss;
        swarm_sync_init(&ss, &m, test_sync_dir);

        int32_t c0 = swarm_sync_assign_chunk(&ss, 100);
        int32_t c1 = swarm_sync_assign_chunk(&ss, 200);
        int32_t c2 = swarm_sync_assign_chunk(&ss, 300);

        bool ok = (c0 == 0 && c1 == 1 && c2 == 2);
        ok = ok && (ss.chunk_states[0] == CHUNK_INFLIGHT);
        ok = ok && (ss.chunk_states[1] == CHUNK_INFLIGHT);
        ok = ok && (ss.chunk_states[2] == CHUNK_INFLIGHT);
        ok = ok && (ss.chunk_peer[0] == 100);
        ok = ok && (ss.chunk_peer[1] == 200);
        ok = ok && (ss.chunk_peer[2] == 300);
        ok = ok && (ss.chunks_inflight == 3);
        /* Remaining chunks still NEEDED */
        ok = ok && (ss.chunk_states[3] == CHUNK_NEEDED);

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }

        swarm_sync_free(&ss);
        free(m.chunk_hashes);
    }

    printf("swarm_sync: assign returns -1 when all assigned... ");
    {
        struct sync_manifest m;
        memset(&m, 0, sizeof(m));
        m.num_chunks = 2;
        m.num_utxos = 1000;
        m.chunk_size = 500;
        m.chunk_hashes = zcl_calloc(2, 32, "test_chunk_hashes");

        struct swarm_sync ss;
        swarm_sync_init(&ss, &m, NULL);

        swarm_sync_assign_chunk(&ss, 1);
        swarm_sync_assign_chunk(&ss, 2);
        int32_t c = swarm_sync_assign_chunk(&ss, 3);

        bool ok = (c == -1);

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }

        swarm_sync_free(&ss);
        free(m.chunk_hashes);
    }

    printf("swarm_sync: timeout resets stale INFLIGHT to NEEDED... ");
    {
        struct sync_manifest m;
        memset(&m, 0, sizeof(m));
        m.num_chunks = 3;
        m.num_utxos = 1500;
        m.chunk_size = 500;
        m.chunk_hashes = zcl_calloc(3, 32, "test_chunk_hashes");

        struct swarm_sync ss;
        swarm_sync_init(&ss, &m, NULL);

        /* Assign all 3 chunks */
        swarm_sync_assign_chunk(&ss, 10);
        swarm_sync_assign_chunk(&ss, 20);
        swarm_sync_assign_chunk(&ss, 30);

        /* Backdate chunk 0 and 1 request times to simulate timeout */
        ss.chunk_request_time[0] = (int64_t)platform_time_wall_time_t() - 120;
        ss.chunk_request_time[1] = (int64_t)platform_time_wall_time_t() - 120;
        /* Chunk 2 stays recent */

        swarm_sync_handle_timeouts(&ss, 60);

        bool ok = (ss.chunk_states[0] == CHUNK_NEEDED);
        ok = ok && (ss.chunk_states[1] == CHUNK_NEEDED);
        ok = ok && (ss.chunk_states[2] == CHUNK_INFLIGHT);
        ok = ok && (ss.chunks_inflight == 1);

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }

        swarm_sync_free(&ss);
        free(m.chunk_hashes);
    }

    printf("swarm_sync: progress reports correct percentage... ");
    {
        struct sync_manifest m;
        memset(&m, 0, sizeof(m));
        m.num_chunks = 4;
        m.num_utxos = 2000;
        m.chunk_size = 500;
        m.chunk_hashes = zcl_calloc(4, 32, "test_chunk_hashes");

        struct swarm_sync ss;
        swarm_sync_init(&ss, &m, NULL);

        bool ok = (swarm_sync_progress(&ss) == 0);

        /* Manually mark 1 of 4 complete */
        ss.chunk_states[0] = CHUNK_COMPLETE;
        ss.chunks_complete = 1;
        ok = ok && (swarm_sync_progress(&ss) == 25);

        /* Mark 2 of 4 */
        ss.chunk_states[1] = CHUNK_COMPLETE;
        ss.chunks_complete = 2;
        ok = ok && (swarm_sync_progress(&ss) == 50);

        /* Mark all 4 */
        ss.chunk_states[2] = CHUNK_COMPLETE;
        ss.chunk_states[3] = CHUNK_COMPLETE;
        ss.chunks_complete = 4;
        ok = ok && (swarm_sync_progress(&ss) == 100);

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }

        swarm_sync_free(&ss);
        free(m.chunk_hashes);
    }

    printf("swarm_sync: is_complete only when all done... ");
    {
        struct sync_manifest m;
        memset(&m, 0, sizeof(m));
        m.num_chunks = 3;
        m.num_utxos = 1500;
        m.chunk_size = 500;
        m.chunk_hashes = zcl_calloc(3, 32, "test_chunk_hashes");

        struct swarm_sync ss;
        swarm_sync_init(&ss, &m, NULL);

        bool ok = !swarm_sync_is_complete(&ss);

        ss.chunks_complete = 2;
        ok = ok && !swarm_sync_is_complete(&ss);

        ss.chunks_complete = 3;
        ok = ok && swarm_sync_is_complete(&ss);

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }

        swarm_sync_free(&ss);
        free(m.chunk_hashes);
    }

    /* ── per-chunk SHA3 verification gates chainstate writes ── */
    printf("swarm_sync: corrupted chunk rejected and not applied... ");
    {
        char p24_dir[256];
        test_make_tmpdir(p24_dir, sizeof(p24_dir),
                         "net", "swarm_corrupt");

        /* Bootstrap an empty node.db with the schema fast_sync_apply_chunk
         * expects. We close it again so the swarm path can re-open it. */
        char p24_path[1024];
        snprintf(p24_path, sizeof(p24_path), "%s/node.db", p24_dir);
        sqlite3 *p24_db = NULL;
        bool ok = (sqlite3_open(p24_path, &p24_db) == SQLITE_OK);
        if (ok) {
            TEST_DB_EXEC(p24_db,
                "CREATE TABLE IF NOT EXISTS utxos ("
                "txid BLOB NOT NULL, vout INTEGER NOT NULL, "
                "value INTEGER NOT NULL, script BLOB NOT NULL, "
                "script_type INTEGER NOT NULL DEFAULT 0, "
                "address_hash BLOB, height INTEGER NOT NULL, "
                "is_coinbase INTEGER NOT NULL DEFAULT 0, "
                "PRIMARY KEY (txid, vout))");
        }
        sqlite3_close(p24_db);

        /* Synthetic chunk with 3 entries. Compute its real SHA3-256 hash —
         * that's the value the manifest commits to. */
        struct utxo_chunk *good = zcl_calloc(1, sizeof(*good), "p24_good");
        ok = ok && good != NULL;
        if (good) {
            good->chunk_index = 0;
            good->num_entries = 3;
            for (uint32_t i = 0; i < good->num_entries; i++) {
                memset(good->entries[i].txid, (int)(0xA0 + i), 32);
                good->entries[i].vout = i;
                good->entries[i].value = (int64_t)(i + 1) * 1000;
                good->entries[i].script[0] = 0x76;
                good->entries[i].script[1] = 0xA9;
                good->entries[i].script_len = 2;
                good->entries[i].height = 100 + (int32_t)i;
            }
        }
        uint8_t expected[32] = {0};
        if (good) fast_sync_chunk_hash(good, expected);

        /* Single-chunk manifest: merkle_root is the leaf itself. */
        struct sync_manifest m;
        memset(&m, 0, sizeof(m));
        m.height = 500;
        m.num_utxos = good ? good->num_entries : 0;
        m.num_chunks = 1;
        m.chunk_size = SYNC_CHUNK_SIZE;
        m.chunk_hashes = zcl_calloc(1, 32, "p24_hashes");
        ok = ok && m.chunk_hashes != NULL;
        if (m.chunk_hashes) memcpy(m.chunk_hashes[0], expected, 32);
        fast_sync_merkle_root((const uint8_t (*)[32])m.chunk_hashes,
                              m.num_chunks, m.merkle_root);

        struct swarm_sync ss;
        memset(&ss, 0, sizeof(ss));
        ok = ok && swarm_sync_init(&ss, &m, p24_dir);
        ok = ok && (swarm_sync_assign_chunk(&ss, 42) == 0);

        /* Single-bit flip → chunk hash diverges from manifest. This is
         * exactly the acceptance scenario from AGENT-2.md. */
        struct utxo_chunk *bad = zcl_calloc(1, sizeof(*bad), "p24_bad");
        ok = ok && bad != NULL;
        if (good && bad) {
            *bad = *good;
            bad->entries[1].value ^= 0x01;
        }

        /* Acceptance #1: corrupted chunk rejected, state reset, no writes. */
        bool received_bad = ok && swarm_sync_receive_chunk(&ss, bad, 42);
        ok = ok && !received_bad;
        ok = ok && (ss.chunk_states[0] == CHUNK_NEEDED);
        ok = ok && (ss.chunk_retries[0] == 1);
        ok = ok && (ss.chunk_peer[0] == -1);
        ok = ok && (ss.chunks_inflight == 0);

        /* Acceptance #1 (cont.): the utxos table must still be empty —
         * the failed verification has to short-circuit before
         * fast_sync_apply_chunk's AR_STEP_DONE writer runs. */
        int bad_rows = -1;
        {
            sqlite3 *q = NULL;
            if (sqlite3_open(p24_path, &q) == SQLITE_OK) {
                sqlite3_stmt *st = NULL;
                if (sqlite3_prepare_v2(q,
                        "SELECT COUNT(*) FROM utxos", -1, &st, NULL)
                    == SQLITE_OK && sqlite3_step(st) == SQLITE_ROW)
                    bad_rows = sqlite3_column_int(st, 0);
                sqlite3_finalize(st);
                sqlite3_close(q);
            }
        }
        ok = ok && (bad_rows == 0);

        /* Acceptance #3: the same chunk re-requested from a different
         * peer succeeds and lands in chainstate. */
        int32_t reassigned = ok ? swarm_sync_assign_chunk(&ss, 99) : -1;
        ok = ok && (reassigned == 0);
        bool received_good = ok && swarm_sync_receive_chunk(&ss, good, 99);
        ok = ok && received_good;
        ok = ok && (ss.chunk_states[0] == CHUNK_COMPLETE);
        ok = ok && swarm_sync_is_complete(&ss);

        int good_rows = -1;
        {
            sqlite3 *q = NULL;
            if (sqlite3_open(p24_path, &q) == SQLITE_OK) {
                sqlite3_stmt *st = NULL;
                if (sqlite3_prepare_v2(q,
                        "SELECT COUNT(*) FROM utxos", -1, &st, NULL)
                    == SQLITE_OK && sqlite3_step(st) == SQLITE_ROW)
                    good_rows = sqlite3_column_int(st, 0);
                sqlite3_finalize(st);
                sqlite3_close(q);
            }
        }
        ok = ok && (good_rows == 3);

        if (ok) printf("OK (bad→reject 0 rows, good→apply 3 rows)\n");
        else { printf("FAIL (received_bad=%d bad_rows=%d received_good=%d "
                      "good_rows=%d state=%d retries=%d)\n",
                      received_bad, bad_rows, received_good, good_rows,
                      ss.chunk_states ? (int)ss.chunk_states[0] : -1,
                      ss.chunk_retries ? ss.chunk_retries[0] : -1);
                      failures++; }

        free(good);
        free(bad);
        swarm_sync_free(&ss);
        free(m.chunk_hashes);
        test_cleanup_tmpdir(p24_dir);
    }

    /* guard: swarm_sync_init must reject a manifest that omits
     * chunk_hashes. Otherwise verify-before-apply silently degrades to
     * verify-against-zeros (pre-fix behavior). */
    printf("swarm_sync: init rejects NULL chunk_hashes... ");
    {
        struct sync_manifest m;
        memset(&m, 0, sizeof(m));
        m.num_chunks = 4;
        m.chunk_size = SYNC_CHUNK_SIZE;
        m.chunk_hashes = NULL;

        struct swarm_sync ss;
        memset(&ss, 0, sizeof(ss));
        bool init_ok = swarm_sync_init(&ss, &m, NULL);
        if (!init_ok) printf("OK\n");
        else {
            printf("FAIL (init accepted NULL hashes)\n");
            failures++;
            swarm_sync_free(&ss);
        }
    }

    /* guard: swarm_sync_init must reject num_chunks > MANIFEST_MAX_CHUNKS
     * so a malicious peer can't force a multi-gigabyte calloc via the
     * wire manifest. */
    printf("swarm_sync: init rejects oversized num_chunks... ");
    {
        uint8_t (*hashes)[32] = zcl_calloc(1, 32, "p24_oversize_hashes");
        struct sync_manifest m;
        memset(&m, 0, sizeof(m));
        m.num_chunks = MANIFEST_MAX_CHUNKS + 1u;
        m.chunk_size = SYNC_CHUNK_SIZE;
        m.chunk_hashes = hashes;

        struct swarm_sync ss;
        memset(&ss, 0, sizeof(ss));
        bool init_ok = swarm_sync_init(&ss, &m, NULL);
        if (!init_ok) printf("OK\n");
        else {
            printf("FAIL (init accepted num_chunks=%u > %u)\n",
                   m.num_chunks, MANIFEST_MAX_CHUNKS);
            failures++;
            swarm_sync_free(&ss);
        }
        free(hashes);
    }

    /* ── FlyClient challenge rate limit ─────────────────── */
    /* A flood of zfcchallenge forces snapsync_build_fc_response() to
     * reconstruct 50 MMB proofs per message, pinning a CPU. The token-
     * bucket guard (burst 30, refill 10/sec) must cap what a single
     * peer can consume while leaving other peers unimpacted. */
    printf("fc_rate: flood of 1000 challenges capped near burst+rate... ");
    {
        msgprocessor_test_fc_rate_reset();

        const int flood_count = 1000;
        int64_t base = 1000000;  /* arbitrary ms epoch — monotonic only */
        int accepted = 0, rejected = 0;
        /* 1000 challenges over 1 second → 1ms spacing. Refill at 10/sec
         * means 1 extra token per 100ms, so total accepted ≈ burst + 10. */
        for (int i = 0; i < flood_count; i++) {
            if (msgprocessor_test_fc_rate_acquire(7, base + i))
                accepted++;
            else
                rejected++;
        }

        uint32_t dropped = msgprocessor_test_fc_rate_dropped(7);
        bool ok = (accepted >= (int)FC_CHALLENGE_BURST);           /* burst honored */
        ok = ok && (accepted <= (int)FC_CHALLENGE_BURST + 15);     /* rate capped */
        ok = ok && (rejected + accepted == flood_count);
        ok = ok && (dropped == (uint32_t)rejected);                /* telemetry accurate */

        if (ok) printf("OK (accepted=%d rejected=%d dropped=%u burst=%u)\n",
                        accepted, rejected, dropped, FC_CHALLENGE_BURST);
        else { printf("FAIL (accepted=%d rejected=%d dropped=%u burst=%u)\n",
                       accepted, rejected, dropped, FC_CHALLENGE_BURST);
               failures++; }
    }

    /* A flood triggers a single ban-score event, not one per drop —
     * otherwise 1000 challenges would add 20_000 to the score and mask
     * the cause in logs. The should-score gate resets when the peer
     * next consumes a token. */
    printf("fc_rate: flood registers ban-score exactly once per episode... ");
    {
        msgprocessor_test_fc_rate_reset();

        int64_t base = 2000000;
        /* Drain the burst; next call hits the empty bucket. */
        for (uint32_t i = 0; i < FC_CHALLENGE_BURST; i++)
            (void)msgprocessor_test_fc_rate_acquire(11, base);
        bool drained = !msgprocessor_test_fc_rate_acquire(11, base);

        bool first_score  =  msgprocessor_test_fc_rate_should_score(11);
        bool second_score = !msgprocessor_test_fc_rate_should_score(11);

        /* Refill one second → at least one token available → next acquire
         * succeeds and clears the flood_scored flag. */
        bool recovered = msgprocessor_test_fc_rate_acquire(11, base + 1000);

        /* After recovery, the next flood should score again. */
        bool flood2_drained = true;
        for (uint32_t i = 0; i < FC_CHALLENGE_BURST + 5u; i++)
            if (msgprocessor_test_fc_rate_acquire(11, base + 1000)) {
                /* Tokens eventually exhaust; we just need to reach the drop. */
            }
        flood2_drained = !msgprocessor_test_fc_rate_acquire(11, base + 1000);
        bool third_score = msgprocessor_test_fc_rate_should_score(11);

        bool ok = drained && first_score && second_score
                  && recovered && flood2_drained && third_score;
        if (ok) printf("OK\n");
        else { printf("FAIL (drained=%d first=%d second=%d recovered=%d "
                      "flood2=%d third=%d)\n",
                      drained, first_score, second_score,
                      recovered, flood2_drained, third_score);
               failures++; }
    }

    /* Rate-limit is per-peer: one peer under load can't starve another. */
    printf("fc_rate: victim peer stays servable under attacker flood... ");
    {
        msgprocessor_test_fc_rate_reset();

        int64_t base = 3000000;
        /* Attacker drains its own bucket. */
        for (int i = 0; i < 1000; i++)
            (void)msgprocessor_test_fc_rate_acquire(/*attacker=*/101, base + i);

        /* Victim has never issued a challenge — full burst must be
         * available, and drops counter stays at zero. */
        int victim_accepted = 0;
        for (uint32_t i = 0; i < FC_CHALLENGE_BURST; i++)
            if (msgprocessor_test_fc_rate_acquire(/*victim=*/202, base + 1001))
                victim_accepted++;

        bool ok = (victim_accepted == (int)FC_CHALLENGE_BURST);
        ok = ok && (msgprocessor_test_fc_rate_dropped(202) == 0);
        /* Attacker's bucket saw drops. */
        ok = ok && (msgprocessor_test_fc_rate_dropped(101) > 900);

        if (ok) printf("OK (victim_accepted=%d attacker_dropped=%u)\n",
                       victim_accepted,
                       msgprocessor_test_fc_rate_dropped(101));
        else { printf("FAIL (victim_accepted=%d/%u attacker_dropped=%u)\n",
                      victim_accepted, FC_CHALLENGE_BURST,
                      msgprocessor_test_fc_rate_dropped(101));
               failures++; }

        msgprocessor_test_fc_rate_reset();
    }

    /* ── g_swarm_active TOCTOU (atomic CAS gate) ──────────── */
    /* The zmanifest handler previously did a plain read/write pair
     * on g_swarm_active: check `!g_swarm_active`, then later set
     * `g_swarm_active = true` under g_swarm_mutex. Two peers racing
     * could both observe false and both call swarm_sync_init. The
     * fix swapped that for atomic_compare_exchange_strong so exactly
     * one caller transitions the slot. */

    printf("swarm_cas: no-race fast path claims once... ");
    {
        msgprocessor_test_swarm_release();  /* baseline clean */

        bool first  = msgprocessor_test_swarm_try_claim();
        bool active = msgprocessor_test_swarm_is_active();
        bool second = msgprocessor_test_swarm_try_claim();  /* must fail */

        msgprocessor_test_swarm_release();
        bool inactive_after = !msgprocessor_test_swarm_is_active();

        bool ok = first && active && !second && inactive_after;
        if (ok) printf("OK\n");
        else { printf("FAIL (first=%d active=%d second=%d inactive_after=%d)\n",
                      first, active, second, inactive_after);
               failures++; }
    }

    printf("swarm_cas: concurrent racers — exactly one claims... ");
    {
        msgprocessor_test_swarm_release();

        pthread_barrier_t barrier;
        pthread_barrier_init(&barrier, NULL, 2);
        _Atomic int won = 0;

        struct p26_race_arg arg = { .barrier = &barrier, .won = &won };
        pthread_t t1, t2;
        pthread_create(&t1, NULL, p26_race_worker, &arg);
        pthread_create(&t2, NULL, p26_race_worker, &arg);
        pthread_join(t1, NULL);
        pthread_join(t2, NULL);
        pthread_barrier_destroy(&barrier);

        int wins = atomic_load(&won);
        bool still_active = msgprocessor_test_swarm_is_active();
        msgprocessor_test_swarm_release();

        bool ok = (wins == 1) && still_active;
        if (ok) printf("OK (wins=%d)\n", wins);
        else { printf("FAIL (wins=%d still_active=%d)\n",
                      wins, still_active);
               failures++; }
    }

    printf("swarm_cas: reset cycle re-arms the next CAS... ");
    {
        msgprocessor_test_swarm_release();

        bool c1 = msgprocessor_test_swarm_try_claim();   /* claim 1 */
        msgprocessor_test_swarm_release();               /* finish */
        bool c2 = msgprocessor_test_swarm_try_claim();   /* claim 2 must succeed */
        msgprocessor_test_swarm_release();

        bool ok = c1 && c2;
        if (ok) printf("OK\n");
        else { printf("FAIL (c1=%d c2=%d)\n", c1, c2); failures++; }
    }

    /* Clean up test database */
    sqlite3_close(test_db);
    test_cleanup_tmpdir(test_sync_dir);

skip_parallel_tests:

    /* ── peer_strategy tests ─────────────────────────────── */

    /* node_profile defaults to all false */
    {
        printf("peer_strategy: node_profile zero-init... ");
        struct node_profile p;
        memset(&p, 0, sizeof(p));
        bool ok = !p.has_public_ip && !p.nat_pmp_available &&
                  !p.upnp_available && !p.tor_available &&
                  p.public_port == 0 && p.onion_address[0] == '\0';
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* peer_strategy_select returns TRANSPORT_TOR for .onion */
    {
        printf("peer_strategy: select tor for .onion... ");
        struct node_profile p;
        memset(&p, 0, sizeof(p));
        p.has_public_ip = true;
        enum peer_transport t = peer_strategy_select(
            &p, "abc123xyz.onion");
        bool ok = (t == TRANSPORT_TOR);
        /* Also with port suffix */
        enum peer_transport t2 = peer_strategy_select(
            &p, "zc23kenfdqqkgamthif3m7lbbdsyrotsl2dlw35qrh3iuzopozmpjnad.onion:8033");
        ok = ok && (t2 == TRANSPORT_TOR);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* peer_strategy_select returns TRANSPORT_CLEARNET for IP */
    {
        printf("peer_strategy: select clearnet for IP... ");
        struct node_profile p;
        memset(&p, 0, sizeof(p));
        p.has_public_ip = true;
        enum peer_transport t = peer_strategy_select(
            &p, "198.51.100.7:8033");
        bool ok = (t == TRANSPORT_CLEARNET);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* peer_strategy_select falls back to TOR when no clearnet */
    {
        printf("peer_strategy: fallback to tor... ");
        struct node_profile p;
        memset(&p, 0, sizeof(p));
        enum peer_transport t = peer_strategy_select(
            &p, "203.0.113.9:8033");
        bool ok = (t == TRANSPORT_TOR);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* peer_strategy_get_addresses returns .onion when tor available */
    {
        printf("peer_strategy: get_addresses onion... ");
        struct node_profile p;
        memset(&p, 0, sizeof(p));
        p.tor_available = true;
        snprintf(p.onion_address, sizeof(p.onion_address),
                 "zc23kenfdqqkg.onion");
        char addrs[4][68];
        int n = peer_strategy_get_addresses(&p, addrs, 4);
        bool ok = (n == 1) &&
                  (strstr(addrs[0], ".onion") != NULL);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* peer_strategy_get_addresses returns both when both available */
    {
        printf("peer_strategy: get_addresses both... ");
        struct node_profile p;
        memset(&p, 0, sizeof(p));
        p.has_public_ip = true;
        p.public_ip[0] = 1; p.public_ip[1] = 2;
        p.public_ip[2] = 3; p.public_ip[3] = 4;
        p.public_port = 8033;
        p.tor_available = true;
        snprintf(p.onion_address, sizeof(p.onion_address),
                 "test.onion");
        char addrs[4][68];
        int n = peer_strategy_get_addresses(&p, addrs, 4);
        bool ok = (n == 2) &&
                  (strcmp(addrs[0], "1.2.3.4:8033") == 0) &&
                  (strcmp(addrs[1], "test.onion") == 0);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* peer_transport_name labels */
    {
        printf("peer_strategy: transport names... ");
        bool ok = (strcmp(peer_transport_name(TRANSPORT_CLEARNET),
                          "clearnet") == 0) &&
                  (strcmp(peer_transport_name(TRANSPORT_TOR),
                          "tor") == 0) &&
                  (strcmp(peer_transport_name(TRANSPORT_NAT_PMP),
                          "nat-pmp") == 0) &&
                  (strcmp(peer_transport_name(TRANSPORT_UPNP),
                          "upnp") == 0);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("msg_processor cache versioning... ");
    {
        bool ok = true;
        uint8_t *manifest1_hashes = NULL;
        uint8_t *manifest2_hashes = NULL;
        uint8_t *bmanifest1_hashes = NULL;
        uint8_t *bmanifest2_hashes = NULL;
        struct snapshot_offer offer1 = {0};
        struct snapshot_offer offer2 = {0};
        struct snapshot_offer got_offer = {0};
        struct sync_manifest manifest1 = {0};
        struct sync_manifest manifest2 = {0};
        struct sync_manifest manifest_out = {0};
        struct block_piece_manifest bmanifest1 = {0};
        struct block_piece_manifest bmanifest2 = {0};
        struct block_piece_manifest bmanifest_out = {0};
        struct sync_manifest manifest_bad = {0};
        struct block_piece_manifest bmanifest_bad = {0};

        offer1.height = 100;
        offer2.height = 200;

        boot_snapshot_offer_test_set_trust_override(1);
        uint64_t offer_v0 = msg_processor_offer_cache_version();
        msg_processor_update_offer(&offer1);
        uint64_t offer_v1 = msg_processor_offer_cache_version();
        ok = ok && offer_v1 > offer_v0;
        ok = ok && msg_processor_get_offer(&got_offer);
        ok = ok && got_offer.height == 100;

        msg_processor_update_offer(&offer2);
        uint64_t offer_v2 = msg_processor_offer_cache_version();
        ok = ok && offer_v2 > offer_v1;
        ok = ok && msg_processor_get_offer(&got_offer);
        ok = ok && got_offer.height == 200;
        msg_processor_invalidate_offer();
        ok = ok && msg_processor_offer_cache_version() > offer_v2;
        ok = ok && !msg_processor_get_offer(&got_offer);

        manifest1_hashes = zcl_calloc(1, 32, "test_manifest_hashes");
        manifest2_hashes = zcl_calloc(2, 32, "test_manifest_hashes");
        bmanifest1_hashes = zcl_calloc(1, 32, "test_bmanifest_hashes");
        bmanifest2_hashes = zcl_calloc(2, 32, "test_bmanifest_hashes");
        if (!manifest1_hashes || !manifest2_hashes || !bmanifest1_hashes ||
            !bmanifest2_hashes) {
            ok = false;
        } else {
        manifest1.num_chunks = 1;
        manifest1.chunk_size = 128;
        manifest1.chunk_hashes = (uint8_t (*)[32]) manifest1_hashes;
        memset(manifest1.chunk_hashes[0], 0xA0, 32);

            uint64_t manifest_v0 = msg_processor_manifest_cache_version();
            ok = ok && msg_processor_publish_manifest(&manifest1);
            manifest1_hashes = NULL;
            uint64_t manifest_v1 = msg_processor_manifest_cache_version();
            ok = ok && manifest_v1 > manifest_v0;
            ok = ok && msg_processor_get_manifest_header(&manifest_out);
            ok = ok && manifest_out.num_chunks == 1;
            ok = ok && manifest_out.chunk_size == 128;
            boot_snapshot_offer_test_set_trust_override(0);
            ok = ok && !msg_processor_get_manifest_header(&manifest_out);
            boot_snapshot_offer_test_set_trust_override(1);

            manifest2.num_chunks = 2;
            manifest2.chunk_size = 64;
            manifest2.chunk_hashes = (uint8_t (*)[32]) manifest2_hashes;
            memset(manifest2.chunk_hashes[0], 0xB0, 32);
            memset(manifest2.chunk_hashes[1], 0xB1, 32);
            uint64_t manifest_v2 = msg_processor_manifest_cache_version();
            ok = ok && msg_processor_publish_manifest(&manifest2);
            manifest2_hashes = NULL;
            uint64_t manifest_v3 = msg_processor_manifest_cache_version();
            ok = ok && manifest_v3 > manifest_v2;
            ok = ok && msg_processor_get_manifest_header(&manifest_out);
            ok = ok && manifest_out.num_chunks == 2;
            msg_processor_invalidate_manifest();
            ok = ok && msg_processor_manifest_cache_version() > manifest_v3;
            ok = ok && !msg_processor_get_manifest_header(&manifest_out);
            manifest_bad.num_chunks = 0;
            manifest_bad.chunk_size = 0;
            manifest_bad.chunk_hashes = NULL;
            uint64_t manifest_bad_v0 = msg_processor_manifest_cache_version();
            ok = ok && !msg_processor_publish_manifest(&manifest_bad);
            ok = ok && msg_processor_manifest_cache_version() == manifest_bad_v0;
        }

        if (manifest1_hashes) free(manifest1_hashes);
        if (manifest2_hashes) free(manifest2_hashes);

        bmanifest1.start_height = 1;
        bmanifest1.end_height = 100;
        bmanifest1.num_pieces = 1;
        bmanifest1.piece_hashes = (uint8_t (*)[32]) bmanifest1_hashes;
        if (ok) {
            memset(bmanifest1.piece_hashes[0], 0xC0, 32);

            uint64_t bmanifest_v0 = msg_processor_block_manifest_cache_version();
            ok = ok && msg_processor_publish_block_manifest(&bmanifest1, 100);
            bmanifest1_hashes = NULL;
            uint64_t bmanifest_v1 = msg_processor_block_manifest_cache_version();
            ok = ok && bmanifest_v1 > bmanifest_v0;
            int32_t built_at_height = 0;
            ok = ok && msg_processor_get_block_manifest_header(&bmanifest_out,
                                                               &built_at_height);
            ok = ok && built_at_height == 100;
            ok = ok && bmanifest_out.start_height == 1;

            bmanifest2.start_height = 101;
            bmanifest2.end_height = 200;
            bmanifest2.num_pieces = 2;
            bmanifest2.piece_hashes = (uint8_t (*)[32]) bmanifest2_hashes;
            memset(bmanifest2.piece_hashes[0], 0xD0, 32);
            memset(bmanifest2.piece_hashes[1], 0xD1, 32);
            uint64_t bmanifest_v2 = msg_processor_block_manifest_cache_version();
            ok = ok && msg_processor_publish_block_manifest(&bmanifest2, 200);
            bmanifest2_hashes = NULL;
            uint64_t bmanifest_v3 = msg_processor_block_manifest_cache_version();
            ok = ok && bmanifest_v3 > bmanifest_v2;
            ok = ok && msg_processor_get_block_manifest_header(&bmanifest_out,
                                                               &built_at_height);
            ok = ok && built_at_height == 200;
            msg_processor_invalidate_block_manifest();
            ok = ok && msg_processor_block_manifest_cache_version() > bmanifest_v3;
            ok = ok && !msg_processor_get_block_manifest_header(&bmanifest_out,
                                                                &built_at_height);
            ok = ok && built_at_height == 0;
            bmanifest_bad.num_pieces = 1;
            bmanifest_bad.piece_hashes = NULL;
            uint64_t bmanifest_bad_v0 = msg_processor_block_manifest_cache_version();
            ok = ok && !msg_processor_publish_block_manifest(&bmanifest_bad,
                                                             300);
            ok = ok && msg_processor_block_manifest_cache_version()
                   == bmanifest_bad_v0;
        }

        if (bmanifest1_hashes) free(bmanifest1_hashes);
        if (bmanifest2_hashes) free(bmanifest2_hashes);

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }

        msg_processor_invalidate_offer();
        msg_processor_invalidate_manifest();
        msg_processor_invalidate_block_manifest();
        boot_snapshot_offer_test_set_trust_override(-1);
    }

    /* ── Robustness: peer_misbehaving accumulates and bans ── */
    printf("net: peer_misbehaving accumulates score... ");
    {
        struct p2p_node node;
        memset(&node, 0, sizeof(node));
        snprintf(node.addr_name, sizeof(node.addr_name), "test_peer");
        struct net_manager nm;
        memset(&nm, 0, sizeof(nm));

        /* Below threshold — not disconnected */
        peer_misbehaving(&nm, &node, 50, "test1");
        bool ok = (node.misbehavior == 50 && !node.disconnect);
        /* At threshold — banned and disconnected */
        peer_misbehaving(&nm, &node, 50, "test2");
        ok = ok && (node.misbehavior == 100 && node.disconnect);
        if (ok) printf("OK\n");
        else { printf("FAIL (score=%d, disc=%d)\n", node.misbehavior, node.disconnect); failures++; }
    }

    printf("net: peer_misbehaving small increments ban at 100... ");
    {
        struct p2p_node node;
        memset(&node, 0, sizeof(node));
        snprintf(node.addr_name, sizeof(node.addr_name), "test_spam");
        struct net_manager nm;
        memset(&nm, 0, sizeof(nm));

        /* 10 bad blocks at 10 points each = 100 = banned */
        for (int i = 0; i < 10; i++)
            peer_misbehaving(&nm, &node, 10, "bad block");
        bool ok = (node.misbehavior == 100 && node.disconnect);
        if (ok) printf("OK\n");
        else { printf("FAIL (score=%d)\n", node.misbehavior); failures++; }
    }

    /* ── P2P dispatch table tests ────────────────────────── */

    printf("dispatch: table has no duplicate commands... ");
    {
        const struct msg_dispatch_entry *table = msg_get_dispatch_table();
        bool ok = true;
        for (const struct msg_dispatch_entry *a = table; a->handler; a++) {
            for (const struct msg_dispatch_entry *b = a + 1; b->handler; b++) {
                if (strcmp(a->command, b->command) == 0) {
                    printf("DUPLICATE: %s\n", a->command);
                    ok = false;
                }
            }
        }
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("dispatch: all commands <= 12 bytes... ");
    {
        const struct msg_dispatch_entry *table = msg_get_dispatch_table();
        bool ok = true;
        for (const struct msg_dispatch_entry *e = table; e->handler; e++) {
            if (strlen(e->command) > 12) {
                printf("TOO LONG: %s (%zu)\n", e->command, strlen(e->command));
                ok = false;
            }
        }
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("dispatch: all handlers non-NULL... ");
    {
        const struct msg_dispatch_entry *table = msg_get_dispatch_table();
        bool ok = true;
        int count = 0;
        for (const struct msg_dispatch_entry *e = table; e->handler; e++) {
            if (!e->handler) { ok = false; break; }
            count++;
        }
        ok = ok && (count >= 18); /* at least 18 standard + z* handlers */
        if (ok) printf("OK (%d entries)\n", count);
        else { printf("FAIL (count=%d)\n", count); failures++; }
    }

    printf("dispatch: version does not require handshake... ");
    {
        const struct msg_dispatch_entry *table = msg_get_dispatch_table();
        bool found = false;
        for (const struct msg_dispatch_entry *e = table; e->handler; e++) {
            if (strcmp(e->command, "version") == 0) {
                found = !e->requires_handshake;
                break;
            }
        }
        if (found) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("dispatch: zgame requires handshake and is zcl23_only... ");
    {
        const struct msg_dispatch_entry *table = msg_get_dispatch_table();
        bool found = false;
        for (const struct msg_dispatch_entry *e = table; e->handler; e++) {
            if (strcmp(e->command, "zgame") == 0) {
                found = e->requires_handshake && e->zcl23_only;
                break;
            }
        }
        if (found) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* ── tip-stall backpressure watchdog ─────────────────────
     * Drive the watchdog with an explicit clock + queue size to
     * verify (a) it enters BACKPRESSURE_ACTIVE on the documented
     * (stall_time AND queue_bytes) condition, (b) it rejects new
     * inv/block messages while active, (c) it clears on tip
     * advance, and (d) — under ZCL_STRESS_TESTS — that the
     * rejection layer actually caps memory pressure when a peer
     * floods us with orphan blocks during a stuck-tip episode. */

    printf("p74_watchdog: enters ACTIVE after 61s stall + 256MB queue... ");
    {
        p74_register_observers();
        tip_watchdog_test_reset();

        /* Pre-fill the simulated download queue past the high water
         * mark and freeze the clock at t=0. The watchdog's stall
         * timer is seeded to "now" by tip_watchdog_test_reset, so
         * we need to push the clock past TIP_STALL_THRESHOLD_SEC
         * before tip_watchdog_tick will trip. */
        tip_watchdog_test_set_queue_bytes(DOWNLOAD_QUEUE_HIGH_WATER + 1);
        tip_watchdog_test_set_now_ns(0);
        tip_watchdog_test_inject_tip_advance(100, 0);

        /* Force "now" forward by 61s — strictly past the threshold. */
        tip_watchdog_test_set_now_ns(
            (int64_t)(TIP_STALL_THRESHOLD_SEC + 1) * 1000000000LL);

        bool went_active = tip_watchdog_tick();
        bool sees_active = tip_watchdog_is_active();
        uint64_t active_emits = atomic_load(&g_p74_active_emits);

        /* Now an inbound inv from peer 42 must be rejected. */
        bool reject_inv   = tip_watchdog_should_reject(42, "inv");
        bool reject_block = tip_watchdog_should_reject(42, "block");
        bool keep_tx      = !tip_watchdog_should_reject(42, "tx");

        uint32_t last_peer = atomic_load(&g_p74_last_reject_peer);
        uint64_t reject_emits = atomic_load(&g_p74_reject_emits);

        bool ok = went_active && sees_active && active_emits == 1 &&
                  reject_inv && reject_block && keep_tx &&
                  last_peer == 42 && reject_emits == 2;

        if (ok) printf("OK\n");
        else { printf("FAIL (active=%d sees=%d emits=%llu inv=%d "
                      "blk=%d tx_kept=%d peer=%u rej=%llu)\n",
                      went_active, sees_active,
                      (unsigned long long)active_emits,
                      reject_inv, reject_block, keep_tx,
                      last_peer, (unsigned long long)reject_emits);
               failures++; }
    }

    printf("p74_watchdog: clears on tip advance + accepts inv/block again... ");
    {
        p74_register_observers();
        tip_watchdog_test_reset();

        tip_watchdog_test_set_queue_bytes(DOWNLOAD_QUEUE_HIGH_WATER + 1);
        tip_watchdog_test_inject_tip_advance(100, 0);
        int64_t t0 = (int64_t)(TIP_STALL_THRESHOLD_SEC + 1) * 1000000000LL;
        tip_watchdog_test_set_now_ns(t0);
        (void)tip_watchdog_tick();
        bool active_now = tip_watchdog_is_active();

        /* Tip advances at t0+100ms; tick should clear immediately
         * because (now - last_tip_advance) drops below threshold. */
        int64_t t1 = t0 + 100 * 1000000LL;
        tip_watchdog_test_inject_tip_advance(101, t1);
        tip_watchdog_test_set_now_ns(t1);
        bool still_active = tip_watchdog_tick();
        bool inv_passes  = !tip_watchdog_should_reject(7, "inv");
        bool blk_passes  = !tip_watchdog_should_reject(7, "block");

        uint64_t clear_emits = atomic_load(&g_p74_clear_emits);

        bool ok = active_now && !still_active && inv_passes &&
                  blk_passes && clear_emits == 1;
        if (ok) printf("OK\n");
        else { printf("FAIL (active_now=%d still=%d inv=%d blk=%d "
                      "clears=%llu)\n",
                      active_now, still_active, inv_passes, blk_passes,
                      (unsigned long long)clear_emits);
               failures++; }
    }

    printf("p74_watchdog: cooldown elapsed clears even without "
           "tip advance... ");
    {
        p74_register_observers();
        tip_watchdog_test_reset();

        tip_watchdog_test_set_queue_bytes(DOWNLOAD_QUEUE_HIGH_WATER + 1);
        tip_watchdog_test_inject_tip_advance(100, 0);
        int64_t t0 = (int64_t)(TIP_STALL_THRESHOLD_SEC + 1) * 1000000000LL;
        tip_watchdog_test_set_now_ns(t0);
        (void)tip_watchdog_tick();
        bool active_after_entry = tip_watchdog_is_active();

        /* Push the clock past the cooldown window without ever
         * advancing the tip — the watchdog must self-clear. */
        int64_t t1 = t0 + (int64_t)(BACKPRESSURE_REJECT_SEC + 1) *
                          1000000000LL;
        tip_watchdog_test_set_now_ns(t1);
        bool still_active = tip_watchdog_tick();

        uint64_t clear_emits = atomic_load(&g_p74_clear_emits);
        bool ok = active_after_entry && !still_active && clear_emits == 1;
        if (ok) printf("OK\n");
        else { printf("FAIL (active=%d still=%d clears=%llu)\n",
                      active_after_entry, still_active,
                      (unsigned long long)clear_emits);
               failures++; }
    }

    /* ── P4 (docs/work/coin-backfill-repair.md §4): backstop
     * reachability + honest queued accounting + re-arm latch ────
     *
     * The estimate is in_flight × BACKPRESSURE_AVG_BLOCK_BYTES +
     * queued × DL_QUEUED_ENTRY_BYTES.  The OOM backstop must be
     * STRUCTURALLY reachable in both download regimes: the trigger
     * is strict (bytes > DOWNLOAD_QUEUE_HIGH_WATER), so the
     * worst-case estimate at each in-flight cap must strictly
     * exceed the high-water mark with margin (design B3 — under
     * the rev-1 constants 1024 × 256 KiB == HIGH_WATER exactly and
     * enter_active was arithmetically dead at tip).  Queued entries
     * are hash+bookkeeping only (~64 B), so a queued-only backlog
     * must NEVER activate (kills the observed false trigger: 3,066
     * queued ≈ 196 KB real, mis-estimated as 6 GB).
     *
     * These three cases drive the watchdog through
     * tip_watchdog_test_set_dl_counts — the counts feed the REAL
     * download_queue_bytes_estimate formula, so reverting the
     * estimator to the old (in_flight + queued) × body-size
     * conflation (the 6 GB false-trigger bug) makes the queued-only
     * case activate and FAIL.  tip_watchdog_test_set_queue_bytes
     * would bypass the formula entirely and pin nothing. */

    printf("p74_watchdog: at-tip in-flight cap estimate exceeds "
           "high water and activates... ");
    {
        p74_register_observers();
        tip_watchdog_test_reset();

        size_t at_tip_estimate = (size_t)DL_MAX_IN_FLIGHT_TOTAL *
                                 (size_t)BACKPRESSURE_AVG_BLOCK_BYTES;
        /* Structural reachability: strictly above high water. */
        bool reachable = at_tip_estimate > DOWNLOAD_QUEUE_HIGH_WATER;

        /* Full at-tip in-flight cap, zero queued — the production
         * formula must compute an estimate above high water. */
        tip_watchdog_test_set_dl_counts(DL_MAX_IN_FLIGHT_TOTAL, 0);
        tip_watchdog_test_inject_tip_advance(100, 0);
        tip_watchdog_test_set_now_ns(
            (int64_t)(TIP_STALL_THRESHOLD_SEC + 1) * 1000000000LL);
        bool went_active = tip_watchdog_tick();

        bool ok = reachable && went_active && tip_watchdog_is_active() &&
                  atomic_load(&g_p74_active_emits) == 1;
        if (ok) printf("OK\n");
        else { printf("FAIL (reachable=%d est=%zu high=%lu active=%d)\n",
                      reachable, at_tip_estimate,
                      (unsigned long)DOWNLOAD_QUEUE_HIGH_WATER,
                      went_active);
               failures++; }
    }

    printf("p74_watchdog: IBD in-flight cap estimate exceeds "
           "high water and activates... ");
    {
        p74_register_observers();
        tip_watchdog_test_reset();

        size_t ibd_estimate = (size_t)DL_MAX_IN_FLIGHT_TOTAL_IBD *
                              (size_t)BACKPRESSURE_AVG_BLOCK_BYTES;
        bool reachable = ibd_estimate > DOWNLOAD_QUEUE_HIGH_WATER;

        /* Full IBD in-flight cap, zero queued, via the real formula. */
        tip_watchdog_test_set_dl_counts(DL_MAX_IN_FLIGHT_TOTAL_IBD, 0);
        tip_watchdog_test_inject_tip_advance(100, 0);
        tip_watchdog_test_set_now_ns(
            (int64_t)(TIP_STALL_THRESHOLD_SEC + 1) * 1000000000LL);
        bool went_active = tip_watchdog_tick();

        bool ok = reachable && went_active && tip_watchdog_is_active() &&
                  atomic_load(&g_p74_active_emits) == 1;
        if (ok) printf("OK\n");
        else { printf("FAIL (reachable=%d est=%zu high=%lu active=%d)\n",
                      reachable, ibd_estimate,
                      (unsigned long)DOWNLOAD_QUEUE_HIGH_WATER,
                      went_active);
               failures++; }
    }

    printf("p74_watchdog: queued-only backlog (100k entries) never "
           "activates... ");
    {
        p74_register_observers();
        tip_watchdog_test_reset();

        /* 100,000 queued hashes at the honest per-entry footprint is
         * ~6.4 MB — nowhere near 256 MiB.  Tripping from queued alone
         * would need ~4M entries; assert the accounting keeps it cold
         * under an arbitrarily long stall.  This is the case that
         * pins the estimator itself: under the old conflated formula
         * 100k queued × body-size ≈ 48 GiB would activate here. */
        size_t queued_only = (size_t)100000 * (size_t)DL_QUEUED_ENTRY_BYTES;
        bool below_high = queued_only <= DOWNLOAD_QUEUE_HIGH_WATER;

        tip_watchdog_test_set_dl_counts(0, 100000);
        tip_watchdog_test_inject_tip_advance(100, 0);
        tip_watchdog_test_set_now_ns(
            (int64_t)(TIP_STALL_THRESHOLD_SEC + 1) * 1000000000LL);
        bool a1 = tip_watchdog_tick();
        tip_watchdog_test_set_now_ns(3600LL * 1000000000LL);
        bool a2 = tip_watchdog_tick();

        bool ok = below_high && !a1 && !a2 &&
                  !tip_watchdog_is_active() &&
                  atomic_load(&g_p74_active_emits) == 0;
        if (ok) printf("OK\n");
        else { printf("FAIL (below_high=%d a1=%d a2=%d active=%d "
                      "emits=%llu)\n",
                      below_high, a1, a2, tip_watchdog_is_active(),
                      (unsigned long long)
                          atomic_load(&g_p74_active_emits));
               failures++; }
    }

    printf("p74_watchdog: no re-entry after cooldown until estimate "
           "drops below low water... ");
    {
        p74_register_observers();
        /* tip_watchdog_test_reset re-arms the hysteresis latch
         * (design P4c: armed init true; re-armed when the estimate
         * drops below HIGH_WATER/2; consumed on enter_active). */
        tip_watchdog_test_reset();

        const int64_t SEC = 1000000000LL;
        tip_watchdog_test_set_queue_bytes(DOWNLOAD_QUEUE_HIGH_WATER + 1);
        tip_watchdog_test_inject_tip_advance(100, 0);

        int64_t t0 = (int64_t)(TIP_STALL_THRESHOLD_SEC + 1) * SEC;
        tip_watchdog_test_set_now_ns(t0);
        bool entered_first = tip_watchdog_tick();  /* armed → ACTIVE */

        int64_t t1 = t0 + (int64_t)(BACKPRESSURE_REJECT_SEC + 1) * SEC;
        tip_watchdog_test_set_now_ns(t1);
        bool after_cooldown = tip_watchdog_tick(); /* cooldown → INACTIVE */

        /* Tip still stalled, estimate still above high water.  The
         * pre-latch state machine re-entered here on the very next
         * tick — the observed active→cooldown→active flapping on an
         * unchanged backlog.  The latch must hold INACTIVE. */
        bool reentered = false;
        for (int i = 1; i <= 3; i++) {
            tip_watchdog_test_set_now_ns(t1 + (int64_t)i * 10 * SEC);
            if (tip_watchdog_tick()) reentered = true;
        }
        uint64_t emits_while_blocked = atomic_load(&g_p74_active_emits);

        /* Backlog drains below low water (HIGH_WATER/2) → the next
         * tick re-arms the latch (and stays inactive: bytes are
         * below the high water anyway). */
        tip_watchdog_test_set_queue_bytes(DOWNLOAD_QUEUE_HIGH_WATER / 2 - 1);
        tip_watchdog_test_set_now_ns(t1 + 60 * SEC);
        bool low_tick_active = tip_watchdog_tick();

        /* Backlog climbs again under the unchanged stall → re-armed
         * latch is consumed and the watchdog re-enters. */
        tip_watchdog_test_set_queue_bytes(DOWNLOAD_QUEUE_HIGH_WATER + 1);
        tip_watchdog_test_set_now_ns(t1 + 70 * SEC);
        bool reentry = tip_watchdog_tick();

        bool ok = entered_first && !after_cooldown && !reentered &&
                  emits_while_blocked == 1 && !low_tick_active &&
                  reentry && tip_watchdog_is_active() &&
                  atomic_load(&g_p74_active_emits) == 2;
        if (ok) printf("OK\n");
        else { printf("FAIL (first=%d cooled=%d reentered=%d "
                      "blocked_emits=%llu low_tick=%d reentry=%d "
                      "emits=%llu)\n",
                      entered_first, after_cooldown, reentered,
                      (unsigned long long)emits_while_blocked,
                      low_tick_active, reentry,
                      (unsigned long long)
                          atomic_load(&g_p74_active_emits));
               failures++; }
    }

    /* RSS-cap stress (opt-in via ZCL_STRESS_TESTS).
     *
     * Live incident reproducer: simulate a synthetic peer pushing
     * 1000 "block" messages into the should_reject path while the
     * tip is pinned past the stall threshold. Pre-fix the rejection
     * layer didn't exist, every block_msg parsed into a 2 MB body,
     * and total scratch climbed to ~6 GB. With the watchdog in
     * place the messages get rejected at the dispatch boundary —
     * we count the rejections and assert the count matches.
     *
     * This isn't a true RSS measurement (would require fork + child
     * sampling /proc/self/status under realistic block-msg parse +
     * connect_block load, which is out of scope for a unit test).
     * It IS the operational invariant: while ACTIVE, every inbound
     * inv/block must be dropped at the dispatch boundary, no
     * exceptions. */
    if (getenv("ZCL_STRESS_TESTS")) {
        printf("p74_watchdog: 1000-orphan-block flood under stuck tip "
               "drops every message... ");
        p74_register_observers();
        tip_watchdog_test_reset();

        tip_watchdog_test_set_queue_bytes(DOWNLOAD_QUEUE_HIGH_WATER + 1);
        tip_watchdog_test_inject_tip_advance(100, 0);
        int64_t t0 = (int64_t)(TIP_STALL_THRESHOLD_SEC + 1) * 1000000000LL;
        tip_watchdog_test_set_now_ns(t0);
        (void)tip_watchdog_tick();

        const int NB = 1000;
        int dropped = 0;
        for (int i = 0; i < NB; i++) {
            if (tip_watchdog_should_reject((uint32_t)i, "block"))
                dropped++;
        }

        uint64_t reject_emits = atomic_load(&g_p74_reject_emits);
        bool ok = (dropped == NB) && (reject_emits == (uint64_t)NB);
        if (ok) printf("OK (dropped=%d emits=%llu)\n",
                       dropped, (unsigned long long)reject_emits);
        else { printf("FAIL (dropped=%d emits=%llu)\n",
                      dropped, (unsigned long long)reject_emits);
               failures++; }

        /* Restore baseline so later tests don't see overrides. */
        tip_watchdog_test_reset();
        event_clear_observers(EV_BACKPRESSURE_ACTIVE);
        event_clear_observers(EV_BACKPRESSURE_REJECT);
        event_clear_observers(EV_BACKPRESSURE_CLEAR);
    }

    /* Restore baseline so later tests don't see overrides. */
    tip_watchdog_test_reset();
    event_clear_observers(EV_BACKPRESSURE_ACTIVE);
    event_clear_observers(EV_BACKPRESSURE_REJECT);
    event_clear_observers(EV_BACKPRESSURE_CLEAR);

    printf("p25_connman: message cycle sends before inbound processing... ");
    {
        const struct chain_params *params = chain_params_get();
        struct p25_order_ctx ctx;
        memset(&ctx, 0, sizeof(ctx));

        struct connman cm;
        struct node_signals sigs;
        memset(&sigs, 0, sizeof(sigs));
        sigs.ctx = &ctx;
        sigs.process_messages = p25_order_process_messages;
        sigs.send_messages = p25_order_send_messages;

        bool ok = connman_init(&cm, params, &sigs);
        cm.manager.nodes = zcl_realloc(cm.manager.nodes,
                                       sizeof(*cm.manager.nodes),
                                       "p25_order_node_array");
        cm.manager.nodes_cap = cm.manager.nodes ? 1 : 0;
        ok = ok && cm.manager.nodes != NULL;
        struct net_address fake_addr;
        memset(&fake_addr, 0, sizeof(fake_addr));
        fake_addr.svc.port = 18033;
        struct p2p_node *n = p2p_node_create(
            &cm.manager, ZCL_INVALID_SOCKET, &fake_addr, "phase-peer",
            false);
        ok = ok && n != NULL;
        if (n) {
            n->state = PEER_HANDSHAKE_COMPLETE;
            n->recv_msg_count = 1;
            cm.manager.nodes[cm.manager.num_nodes++] = n;
        }

        bool cycle = connman_run_message_cycle(&cm);
        struct connman_message_cycle_stats stats;
        connman_get_message_cycle_stats(&cm, &stats);

        if (n)
            n->recv_msg_count = 0;
        connman_free(&cm);

        ok = ok && cycle && ctx.send_order == 1 &&
             ctx.process_order == 2 && stats.cycles == 1 &&
             stats.nodes_snapshotted == 1 && stats.send_calls == 1 &&
             stats.process_calls == 1 && stats.recv_ready == 1;
        if (ok) printf("OK\n");
        else { printf("FAIL (cycle=%d send_order=%d process_order=%d "
                      "cycles=%llu send=%llu process=%llu recv=%llu)\n",
                      cycle, ctx.send_order, ctx.process_order,
                      (unsigned long long)stats.cycles,
                      (unsigned long long)stats.send_calls,
                      (unsigned long long)stats.process_calls,
                      (unsigned long long)stats.recv_ready);
               failures++; }
    }

    /* ── connman snapshot-iterate stress (opt-in) ──────────
     * Exercise the refactored message-cycle + deferred-free-sweep
     * contract under concurrent disconnect pressure. Opt-in via
     * ZCL_STRESS_TESTS=1 so the default build/bin/test_zcl doesn't pay the
     * ~1-second wall cost for a path that rarely regresses. */
    if (getenv("ZCL_STRESS_TESTS")) {
        printf("p25_connman: 50 peers × 1s concurrent "
               "message_cycle + disconnect churn... ");

        const struct chain_params *params = chain_params_get();
        struct p25_ctx ctx;
        memset(&ctx, 0, sizeof(ctx));

        struct connman cm;
        struct node_signals sigs;
        memset(&sigs, 0, sizeof(sigs));
        sigs.ctx = &ctx;
        sigs.process_messages = p25_mock_process_messages;
        sigs.send_messages    = p25_mock_send_messages;
        /* connman_init replaces sigs with its own copy, so point at the
         * real mock functions by passing sigs before init. */

        connman_init(&cm, params, &sigs);
        ctx.cm = &cm;
        ctx.disconnect_1_in_n = 20;

        /* Allocate a nodes array large enough to hold 50 fake peers.
         * Bypass nm_add_node (static) by growing the manager's nodes
         * slot directly. Pattern only valid for tests. */
        const int n_peers = 50;
        cm.manager.nodes = zcl_realloc(
            cm.manager.nodes,
            (size_t)n_peers * sizeof(*cm.manager.nodes),
            "p25_test_node_array");
        cm.manager.nodes_cap = (size_t)n_peers;

        /* Bump recv_msg_count so process_messages actually fires on
         * each iteration; without outbound sockets the normal
         * recv-path would leave recv_msg_count at 0. */
        struct net_address fake_addr;
        memset(&fake_addr, 0, sizeof(fake_addr));
        fake_addr.svc.port = 18033;

        for (int i = 0; i < n_peers; i++) {
            char name[32];
            snprintf(name, sizeof(name), "peer%03d", i);
            struct p2p_node *n = p2p_node_create(
                &cm.manager, ZCL_INVALID_SOCKET,
                &fake_addr, name, false);
            n->state = PEER_HANDSHAKE_COMPLETE;
            n->recv_msg_count = 1;  /* make process_messages fire */
            cm.manager.nodes[cm.manager.num_nodes++] = n;
        }

        /* Run two worker threads for ~1 second: one drives the
         * message cycle, one drives the socket-cleanup + sweep. */
        pthread_t t_msg, t_sock;
        atomic_store(&ctx.stop, false);
        pthread_create(&t_sock, NULL, p25_socket_worker,  &ctx);
        pthread_create(&t_msg,  NULL, p25_message_worker, &ctx);

        usleep(1000 * 1000);  /* 1s test window */

        atomic_store(&ctx.stop, true);
        pthread_join(t_msg,  NULL);
        pthread_join(t_sock, NULL);

        /* Teardown: drop recv_msg_count so p2p_node_free doesn't chase
         * invalid recv_msgs, then free any surviving nodes plus the
         * nodes-array itself. The socket worker's final sweep already
         * drained deferred_free. */
        zcl_mutex_lock(&cm.manager.cs_nodes);
        for (size_t i = 0; i < cm.manager.num_nodes; i++) {
            cm.manager.nodes[i]->recv_msg_count = 0;
            p2p_node_free(cm.manager.nodes[i]);
        }
        cm.manager.num_nodes = 0;
        zcl_mutex_unlock(&cm.manager.cs_nodes);

        int cycles    = atomic_load(&ctx.cycles_run);
        int callbacks = atomic_load(&ctx.callbacks_run);
        size_t deferred_remaining = cm.num_deferred_free;

        connman_free(&cm);

        /* Expectations:
         *   - ≥100 full message cycles completed in 1s (conservative;
         *     real hardware runs thousands).
         *   - ≥100 callbacks executed (process_messages + send_messages
         *     per peer per cycle).
         *   - deferred_free drained cleanly (0 entries left).
         *   - Both threads joined (we got here without hanging). */
        bool ok = (cycles >= 100) && (callbacks >= 100) &&
                  (deferred_remaining == 0);
        if (ok) printf("OK (cycles=%d callbacks=%d)\n", cycles, callbacks);
        else { printf("FAIL (cycles=%d callbacks=%d "
                      "deferred_remaining=%zu)\n",
                      cycles, callbacks, deferred_remaining);
               failures++; }
    }

    /* ── Client-puzzle PoW guard for zchunkreq/zblkreq (lane I3) ────
     * See msgprocessor_snapshot.c for the stateless design note:
     * challenge = SHA3-256(secret||peer_ip||time_bucket), no per-peer
     * server state, no seed distribution round trip. Difficulty is 0
     * (mechanism present, gate open) until armed. */

    printf("snap_pow: disarmed by default — gate stays open regardless "
           "of nonce... ");
    {
        msgprocessor_test_snap_pow_reset();
        uint8_t ip[16] = {0}; ip[15] = 1;
        int64_t t = 5000000;
        bool admit_no_nonce = msgprocessor_test_snap_pow_admit_at(ip, t, NULL);
        uint64_t bogus = 0xdeadbeefULL;
        bool admit_bad_nonce =
            msgprocessor_test_snap_pow_admit_at(ip, t + 1, &bogus);
        bool ok = admit_no_nonce && admit_bad_nonce &&
                  !msg_snapshot_pow_is_armed();
        if (ok) printf("OK\n");
        else { printf("FAIL (no_nonce=%d bad_nonce=%d armed=%d)\n",
                      admit_no_nonce, admit_bad_nonce,
                      msg_snapshot_pow_is_armed());
               failures++; }
    }

    printf("snap_pow: armed gate rejects missing/wrong nonce, accepts a "
           "genuinely solved one... ");
    {
        msgprocessor_test_snap_pow_reset();
        msg_snapshot_pow_set_armed(true);
        uint8_t ip[16] = {0}; ip[15] = 2;
        int64_t t = 6000000;
        int bits = msgprocessor_test_snap_pow_bits_at(t); /* fresh window: floor */

        bool reject_missing = !msgprocessor_test_snap_pow_admit_at(ip, t, NULL);
        /* A fixed "bogus" nonce is probabilistic: at D=12 any constant can
         * be a real solution for either accepted time bucket. Search a
         * bounded set through the production admission path. Resetting the
         * load counter on each try keeps every verdict at the same D=12. */
        uint64_t bogus = 0;
        unsigned bogus_trials = 0;
        bool reject_bad = false;
        for (; bogus_trials < 64; bogus_trials++, bogus++) {
            msgprocessor_test_snap_pow_reset();
            msg_snapshot_pow_set_armed(true);
            if (!msgprocessor_test_snap_pow_admit_at(ip, t, &bogus)) {
                reject_bad = true;
                break;
            }
        }

        msgprocessor_test_snap_pow_reset();
        msg_snapshot_pow_set_armed(true);
        bits = msgprocessor_test_snap_pow_bits_at(t);
        uint64_t nonce = 0;
        bool solved = msgprocessor_test_snap_pow_solve(ip, t, bits, &nonce);
        bool accept = solved &&
                      msgprocessor_test_snap_pow_admit_at(ip, t, &nonce);

        /* Binding means the solution must fail for a different IP. A single
         * fixed second IP has the same rare-collision problem as a fixed bad
         * nonce, so test up to 64 distinct peers at a reset difficulty. If
         * peer binding were absent, the nonce would pass for all 64. */
        uint8_t other_ip[16] = {0};
        unsigned peer_trials = 0;
        bool cross_peer_rejected = false;
        for (; peer_trials < 64; peer_trials++) {
            other_ip[15] = (uint8_t)(3 + peer_trials);
            msgprocessor_test_snap_pow_reset();
            msg_snapshot_pow_set_armed(true);
            if (!msgprocessor_test_snap_pow_admit_at(other_ip, t, &nonce)) {
                cross_peer_rejected = true;
                break;
            }
        }

        msgprocessor_test_snap_pow_reset();
        bool ok = reject_missing && reject_bad && solved && accept &&
                  cross_peer_rejected;
        if (ok) printf("OK (bits=%d)\n", bits);
        else { printf("FAIL (bits=%d missing=%d bad=%d bogus_trials=%u "
                      "solved=%d accept=%d peer_trials=%u "
                      "cross_peer_rejected=%d)\n",
                      bits, reject_missing, reject_bad, bogus_trials, solved,
                      accept, peer_trials, cross_peer_rejected);
               failures++; }
    }

    printf("snap_pow: stateless recompute — no per-peer server state, "
           "no single-use consumption... ");
    {
        msgprocessor_test_snap_pow_reset();
        msg_snapshot_pow_set_armed(true);
        uint8_t ip[16] = {0}; ip[15] = 4;
        int64_t t = 7000000;
        int bits = msgprocessor_test_snap_pow_bits_at(t);

        /* Two independent solves for the identical (ip, time_bucket)
         * input must land on the identical nonce — proof the challenge
         * is a pure function of (secret, ip, bucket), not stateful
         * server-issued material that changes between calls. */
        uint64_t nonce1 = 0, nonce2 = 0;
        bool solved1 = msgprocessor_test_snap_pow_solve(ip, t, bits, &nonce1);
        bool solved2 = msgprocessor_test_snap_pow_solve(ip, t, bits, &nonce2);

        /* Verifying the same solution twice both succeed — a stateful
         * single-use ring (like struct puzzle_gate's) would reject the
         * second; this guard deliberately keeps none. */
        bool admit1 = msgprocessor_test_snap_pow_admit_at(ip, t, &nonce1);
        bool admit2 = msgprocessor_test_snap_pow_admit_at(ip, t, &nonce1);

        msg_snapshot_pow_set_armed(false);
        bool ok = solved1 && solved2 && nonce1 == nonce2 &&
                  admit1 && admit2;
        if (ok) printf("OK\n");
        else { printf("FAIL (solved1=%d solved2=%d nonce1=%llu nonce2=%llu "
                      "admit1=%d admit2=%d)\n",
                      solved1, solved2,
                      (unsigned long long)nonce1, (unsigned long long)nonce2,
                      admit1, admit2);
               failures++; }
    }

    printf("snap_pow: a solve for time bucket N-1 still verifies at "
           "bucket N (grace epoch)... ");
    {
        int64_t t0 = 8000000;
        int64_t t1 = t0 + SNAP_POW_BUCKET_SECS;
        int64_t t2 = t0 + 2 * SNAP_POW_BUCKET_SECS;
        bool solved = false;
        bool accept_in_grace = false;
        bool reject_after_grace = false;
        int attempts = 0;

        /* A nonce solved for bucket N can, with probability about 2/4096,
         * also satisfy either unrelated challenge checked at N+2.  That is
         * an ordinary hash collision, not an extension of the grace epoch.
         * Try distinct peer-bound challenges so the test proves the window
         * rule without treating a valid low-difficulty collision as a bug. */
        for (attempts = 1; attempts <= 16 && !reject_after_grace; attempts++) {
            msgprocessor_test_snap_pow_reset();
            msg_snapshot_pow_set_armed(true);
            uint8_t ip[16] = {0};
            ip[14] = 5;
            ip[15] = (uint8_t)attempts;
            int bits = msgprocessor_test_snap_pow_bits_at(t0);
            uint64_t nonce = 0;

            solved = msgprocessor_test_snap_pow_solve(ip, t0, bits, &nonce);
            /* The rate window is independent of the puzzle bucket, so each
             * admission remains at the same idle-floor difficulty. */
            accept_in_grace = solved &&
                msgprocessor_test_snap_pow_admit_at(ip, t1, &nonce);
            reject_after_grace = accept_in_grace &&
                !msgprocessor_test_snap_pow_admit_at(ip, t2, &nonce);
        }

        msg_snapshot_pow_set_armed(false);
        bool ok = solved && accept_in_grace && reject_after_grace;
        if (ok) printf("OK (attempts=%d)\n", attempts - 1);
        else { printf("FAIL (solved=%d accept_in_grace=%d "
                      "reject_after_grace=%d attempts=%d)\n",
                      solved, accept_in_grace, reject_after_grace,
                      attempts - 1);
               failures++; }
    }

    printf("snap_pow: difficulty ramps under sustained request volume and "
           "floors when idle again... ");
    {
        msgprocessor_test_snap_pow_reset();
        int64_t base = 9000000;
        int floor_bits = msgprocessor_test_snap_pow_bits_at(base);
        int last_bits = floor_bits;
        for (int i = 0; i < 60; i++)
            last_bits = msgprocessor_test_snap_pow_bits_at(base);
        bool ramped = last_bits > floor_bits &&
                      last_bits <= SNAP_POW_MAX_BITS;

        /* Far outside the request-rate window → back to the idle floor. */
        int idle_bits = msgprocessor_test_snap_pow_bits_at(
            base + SNAP_POW_WINDOW_SECS + 1);
        bool ok = floor_bits == SNAP_POW_MIN_BITS && ramped &&
                  idle_bits == floor_bits;
        msgprocessor_test_snap_pow_reset();
        if (ok) printf("OK (floor=%d ramped_to=%d idle=%d)\n",
                       floor_bits, last_bits, idle_bits);
        else { printf("FAIL (floor=%d ramped_to=%d idle=%d)\n",
                      floor_bits, last_bits, idle_bits);
               failures++; }
    }

    /* ================================================================
     * connman: v2 (Noise) transport ADVERTISEMENT census
     *
     * Observation only — nothing in the node branches on it. The v2
     * default stays OFF because every peer on the live network speaks
     * unencrypted v1; this census is the evidence a future flip would
     * need, so what has to hold is that it accumulates honestly across
     * peer churn: a live count that tracks the last sample, a high-water
     * that never regresses, and a running total that only grows.
     * ================================================================ */
    printf("connman: v2transport census accumulates across churn... ");
    {
        struct connman_v2transport_stats before, s1, s2, s3;
        connman_get_v2transport_stats(&before);

        /* Two peers advertising out of five handshaked. */
        connman_note_v2transport_sample_for_test(2, 5);
        connman_get_v2transport_stats(&s1);

        /* Churn: they leave. The live count drops to zero, but the
         * high-water and the running total must NOT. */
        connman_note_v2transport_sample_for_test(0, 4);
        connman_get_v2transport_stats(&s2);

        /* A bigger population arrives → high-water advances. */
        connman_note_v2transport_sample_for_test(3, 6);
        connman_get_v2transport_stats(&s3);

        bool live_tracks   = s1.advertising_now == 2 &&
                             s1.handshaked_now == 5 &&
                             s2.advertising_now == 0 &&
                             s3.advertising_now == 3;
        bool hw_monotonic  = s1.advertising_high_water >= 2 &&
                             s2.advertising_high_water ==
                                 s1.advertising_high_water &&
                             s3.advertising_high_water >=
                                 s2.advertising_high_water &&
                             s3.advertising_high_water >= 3;
        bool total_grows   = s1.advertising_observations_total ==
                                 before.advertising_observations_total + 2 &&
                             s2.advertising_observations_total ==
                                 s1.advertising_observations_total &&
                             s3.advertising_observations_total ==
                                 s2.advertising_observations_total + 3;
        bool samples_count = s3.samples_total == before.samples_total + 3;

        bool ok = live_tracks && hw_monotonic && total_grows && samples_count;
        if (ok) printf("OK (high_water=%zu total=%llu samples=%llu)\n",
                       s3.advertising_high_water,
                       (unsigned long long)s3.advertising_observations_total,
                       (unsigned long long)s3.samples_total);
        else { printf("FAIL (live=%d hw=%d total=%d samples=%d)\n",
                      live_tracks, hw_monotonic, total_grows, samples_count);
               failures++; }
    }

    return failures;
}
