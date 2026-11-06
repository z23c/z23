/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * Reproduce the onion FlySync shape of live run F (release 3be2ba86): a
 * fresh client with no package host and a header-sync hold meets a peer at
 * the all-zero onion address that advertises NODE_STATE_OFFER_LINK and
 * holds the rung bundle. Two connections in one process are cross-wired
 * through the production frame and tick entries, so every byte crosses the
 * same composition path a live node uses. */
#define _POSIX_C_SOURCE 200809L
#include "config/boot_internal.h"
#include "config/boot_zcode_swarm.h"
#include "config/state_offer_link.h"
#include "config/state_offer_peer.h"
#include "config/state_offer_service.h"
#include "config/state_offer_store.h"
#include "chain/chainparams.h"
#include "chain/checkpoints.h"
#include "jobs/reducer_frontier.h"
#include "net/fast_sync.h"
#include "net/msg_internal.h"
#include "net/msgprocessor.h"
#include "net/net.h"
#include "net/rom_seed.h"
#include "net/state_offer.h"
#include "platform/time_compat.h"
#include "sync/sync_planner.h"
#include "test/test_core.h"
#include "util/util.h"
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define ONION_RUNG 3200000
#define ONION_BYTES 131072u
#define ONION_PEER_TIP 3310392
#define ONION_NAME "consensus-state-bundle-3200000.sqlite"
#define ONION_CHECK(x) do { if (!(x)) { \
    fprintf(stderr, "state_offer_onion_link line %d: %s\n", __LINE__, #x); \
    return false; } } while (0)

struct onion_fixture {
    struct net_manager nm;
    struct msg_processor mp;
    struct boot_svc_ctx svc;
    struct p2p_node *to_server;   /* the client's view of the server */
    struct p2p_node *to_client;   /* the server's view of the client */
    struct p2p_node *list[2];
    struct send_segment *to_server_q, *to_client_q;
    struct rom_artifact *artifact;
    uint8_t *wire;
    unsigned stray;               /* non-ZBND frames the client sent */
    char dir[256], bundle[512], landed[512];
    bool started;
};

static const struct rom_artifact *g_onion_served;

/* The server's signed rung offer, built from the registered artifact. */
static uint32_t onion_provide(struct state_offer_batch_v1 *out, void *ctx)
{
    (void)ctx;
    const struct rom_artifact *a = g_onion_served;
    if (!out || !a) return 0;
    out->version = STATE_OFFER_VERSION;
    out->offerer_tip_height = ONION_PEER_TIP;
    struct state_offer_v1 *o = &out->offers[0];
    memset(o, 0, sizeof(*o));
    o->version = STATE_OFFER_VERSION;
    o->bundle_height = ONION_RUNG;
    o->offerer_tip_height = ONION_PEER_TIP;
    o->chunk_size = a->chunk_size;
    o->num_chunks = a->num_chunks;
    o->kind = ROM_ARTIFACT_CONSENSUS_BUNDLE;
    o->content_bytes = a->size_bytes;
    o->issued_unix = (uint64_t)platform_time_wall_time_t();
    o->filename_len = (uint16_t)strlen(ONION_NAME);
    memcpy(o->filename, ONION_NAME, o->filename_len);
    memcpy(o->chunk_tree_root, a->chunk_root, 32);
    memcpy(o->content_digest, a->whole_sha3, 32);
    memset(o->header_hash, 1, 32);
    memset(o->mmb_peaks_digest, 3, 32);
    memset(o->producer_receipt_id, 4, 32);
    uint8_t seed[32];
    memset(seed, 7, sizeof(seed));
    return state_offer_v1_sign(o, seed) == STATE_OFFER_OK ? 1u : 0u;
}

/* FlySync's filter: only a compiled rung height is wanted. */
static bool onion_rung_only(int32_t height)
{
    for (size_t i = 0; i < get_rom_state_rung_count(); i++) {
        const struct rom_state_rung *r = get_rom_state_rung_at(i);
        if (r && r->cp.height == height) return true;
    }
    return false;
}

static bool onion_hold(void) { return true; }

static struct p2p_node *onion_node(struct onion_fixture *f, struct send_segment **q, bool inbound)
{
    struct net_address zero = {0}; /* an onion peer's IP is all zeros */
    struct p2p_node *n = p2p_node_create(&f->nm, ZCL_INVALID_SOCKET, &zero, "onion", inbound);
    *q = calloc(1, sizeof(**q));
    if (!n || !*q) return n;
    n->send_head = n->send_tail = *q;
    n->version = 1;
    n->services = NODE_ZCL23 | NODE_STATE_OFFER_LINK;
    atomic_store(&n->state, PEER_SYNCING_HEADERS); /* live state "syncing_headers" */
    n->starting_height = ONION_PEER_TIP;
    return n;
}

static bool onion_bundle(struct onion_fixture *f)
{
    snprintf(f->bundle, sizeof(f->bundle), "%s/%s", f->dir, ONION_NAME);
    int fd = open(f->bundle, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) return false;
    uint8_t page[4096];
    bool ok = true;
    for (uint32_t off = 0; ok && off < ONION_BYTES; off += sizeof(page)) {
        for (size_t i = 0; i < sizeof(page); i++) page[i] = (uint8_t)(off / 4096 + i);
        if (!off) memcpy(page, "SQLite format 3", 16); /* the bundle magic */
        ok = write(fd, page, sizeof(page)) == (ssize_t)sizeof(page);
    }
    close(fd);
    return ok && rom_seed_register(f->dir, ONION_NAME, NULL, f->artifact) == ROM_REG_OK;
}

static bool onion_setup(struct onion_fixture *f)
{
    test_make_tmpdir(f->dir, sizeof(f->dir), "state_offer_onion", "link");
    snprintf(f->landed, sizeof(f->landed), "%s/bundles/%s", f->dir, ONION_NAME);
    f->artifact = calloc(1, sizeof(*f->artifact));
    f->wire = malloc(STATE_OFFER_LINK_FRAME_MAX);
    ONION_CHECK(f->artifact && f->wire);
    net_manager_init(&f->nm);
    f->mp.params = chain_params_get();
    f->mp.net_mgr = &f->nm;
    f->svc.msg_processor = &f->mp;
    f->svc.datadir = f->dir;
    boot_zcode_swarm_wire_network(&f->svc);
    ONION_CHECK(!GetBoolArg("-packagehost", false)); /* the client hosts nothing */
    f->to_server = onion_node(f, &f->to_server_q, false);
    f->to_client = onion_node(f, &f->to_client_q, true);
    ONION_CHECK(f->to_server && f->to_client && f->to_server_q && f->to_client_q);
    f->list[0] = f->to_server; f->list[1] = f->to_client;
    f->nm.nodes = f->list; f->nm.num_nodes = 2;
    state_offer_store_reset(); rom_seed_reset(); rom_seed_set_enabled(true);
    ONION_CHECK(onion_bundle(f));
    g_onion_served = f->artifact;
    state_offer_service_start(f->dir, NULL); f->started = true;
    state_offer_set_provider(onion_provide, NULL);
    reducer_frontier_provable_tip_set(0);           /* fresh datadir, height known */
    state_offer_store_set_height_filter(onion_rung_only);
    msg_processor_set_header_sync_hold(onion_hold); /* -flysync waits for its rung */
    return true;
}

/* Pop one queued message body from a captured send queue. */
static bool onion_pop(struct p2p_node *node, struct send_segment *q, uint8_t *copy, size_t *len)
{
    struct send_segment *seg = q->next;
    if (!seg || seg->size < MSG_HEADER_SIZE || seg->size - MSG_HEADER_SIZE > STATE_OFFER_LINK_FRAME_MAX)
        return false;
    *len = seg->size - MSG_HEADER_SIZE;
    memcpy(copy, seg->data + MSG_HEADER_SIZE, *len);
    q->next = seg->next;
    if (node->send_tail == seg) node->send_tail = q;
    node->send_size -= seg->size;
    send_segment_free(seg);
    return true;
}

/* Deliver every frame one side queued to the other side's frame entry. */
static void onion_relay(struct onion_fixture *f, struct p2p_node *from, struct send_segment *q,
                        struct p2p_node *to, unsigned *stray)
{
    size_t n = 0;
    while (onion_pop(from, q, f->wire, &n)) {
        if (stray && (n < 4 || memcmp(f->wire, "ZBND", 4))) ++*stray;
        (void)boot_zcode_swarm_frame(&f->mp, to, f->wire, n, &f->svc);
    }
}

/* One message-loop turn: the client's owner tick, the supervisor drain,
 * then both directions of the wire. */
static void onion_cycle(struct onion_fixture *f)
{
    boot_zcode_swarm_tick(&f->mp, f->to_server, &f->svc);
    state_offer_peer_pump(&f->mp);
    onion_relay(f, f->to_server, f->to_server_q, f->to_client, &f->stray);
    onion_relay(f, f->to_client, f->to_client_q, f->to_server, NULL);
    struct timespec t = {0, 1000000};
    (void)nanosleep(&t, NULL);
}

/* The legacy handshake offer from this peer cannot be dialled. */
static bool onion_legacy_dropped(void)
{
    struct state_offer_batch_v1 batch = {0};
    ONION_CHECK(onion_provide(&batch, NULL) == 1);
    static const uint8_t zero_ip[16];
    ONION_CHECK(state_offer_store_record(&batch.offers[0], zero_ip, 18034, 0, 1) ==
                STATE_OFFER_STORE_DROPPED_ENDPOINT);
    return true;
}

/* Discovery over the link records the rung offer and starts its fetch. */
static bool onion_discover_and_fetch(struct onion_fixture *f)
{
    struct state_offer_store_status st = {0};
    for (int i = 0; i < 5000 && st.chosen_height != ONION_RUNG; i++) {
        onion_cycle(f);
        state_offer_store_status_get(&st);
    }
    ONION_CHECK(st.peers_offering == 1 && st.offers_retained == 1);
    ONION_CHECK(st.chosen_height == ONION_RUNG);
    ONION_CHECK(st.last_decision == STATE_OFFER_DECIDE_FETCH);
    ONION_CHECK(state_offer_service_test_fetch_running());
    return true;
}

/* Run F: at 120 s core's stale-header rules dropped the peer streaming the
 * rung bundle, because the node itself withheld every getheaders. */
static bool onion_serving_peer_kept(struct onion_fixture *f)
{
    int64_t now = platform_time_wall_unix();
    f->to_server->time_connected = now - 121;
    ONION_CHECK(!syncsvc_should_disconnect_stale_header_peer(f->to_server, 0, 0, 0, now));
    ONION_CHECK(!syncsvc_is_header_sync_stalled(SYNC_HEADERS_DOWNLOAD, 0, now - 121, now));
    msg_processor_set_header_sync_hold(NULL);   /* the hold ends: discipline returns */
    ONION_CHECK(syncsvc_should_disconnect_stale_header_peer(f->to_server, 0, 0, 0, now));
    ONION_CHECK(syncsvc_is_header_sync_stalled(SYNC_HEADERS_DOWNLOAD, 0, now - 121, now));
    msg_processor_set_header_sync_hold(onion_hold);
    return true;
}

/* The fetch lands the verified rung bundle. */
static bool onion_lands(struct onion_fixture *f)
{
    struct stat st;
    for (int i = 0; i < 10000 && (state_offer_service_test_fetch_running() || stat(f->landed, &st)); i++)
        onion_cycle(f);
    onion_cycle(f); /* the owner tick publishes the last progress */
    ONION_CHECK(!stat(f->landed, &st) && (uint64_t)st.st_size == ONION_BYTES);
    struct state_offer_store_status s = {0};
    state_offer_store_status_get(&s);
    ONION_CHECK(s.fetch_bytes_done == ONION_BYTES && s.offers_rejected == 0);
    ONION_CHECK(f->stray == 0); /* the engine-off client sent only link frames */
    return true;
}

static void onion_drop_queue(struct p2p_node *n, struct send_segment *q)
{
    while (q && q->next) {
        struct send_segment *s = q->next;
        q->next = s->next;
        send_segment_free(s);
    }
    if (n) n->send_head = n->send_tail = NULL;
    free(q);
}

static void onion_cleanup(struct onion_fixture *f)
{
    msg_processor_set_header_sync_hold(NULL);
    state_offer_store_set_height_filter(NULL);
    if (f->started) boot_zcode_swarm_shutdown();
    reducer_frontier_provable_tip_reset();
    g_onion_served = NULL;
    onion_drop_queue(f->to_server, f->to_server_q);
    onion_drop_queue(f->to_client, f->to_client_q);
    f->nm.nodes = NULL; f->nm.num_nodes = 0;
    if (f->to_server) p2p_node_free(f->to_server);
    if (f->to_client) p2p_node_free(f->to_client);
    net_manager_free(&f->nm);
    rom_seed_reset(); state_offer_store_reset();
    if (f->dir[0]) test_rm_rf_recursive(f->dir);
    free(f->artifact); free(f->wire);
}

int test_state_offer_onion_link(void)
{
    struct onion_fixture f = {0};
    bool ok = onion_setup(&f) && onion_legacy_dropped() && onion_discover_and_fetch(&f) &&
              onion_serving_peer_kept(&f) && onion_lands(&f);
    onion_cleanup(&f);
    printf("state_offer_onion_link: %s\n", ok ? "OK" : "FAIL");
    return ok ? 0 : 1;
}
