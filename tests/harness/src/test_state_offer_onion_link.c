/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * Reproduce the onion FlySync shape of live run F (release 3be2ba86): a
 * fresh client with no package host and a header-sync hold meets a peer at
 * the all-zero onion address that advertises NODE_STATE_OFFER_LINK and
 * holds the rung bundle. Two connections in one process are cross-wired
 * through the production frame and tick entries, so every byte crosses the
 * same composition path a live node uses. */
#define _POSIX_C_SOURCE 200809L
#include "config/boot_internal.h"
#include "controllers/status_frontdoor.h"
#include "base/hex.h"
#include "json/json.h"
#include "config/consensus_state_install_runtime.h"
#include "config/boot_zcode_swarm.h"
#include "config/boot_zcode_swarm_membership.h"
#include "config/state_offer_link.h"
#include "config/state_offer_link_session.h"
#include "config/state_offer_peer.h"
#include "config/state_offer_service.h"
#include "config/state_offer_store.h"
#include "chain/chainparams.h"
#include "chain/checkpoints.h"
#include "jobs/reducer_frontier.h"
#include "net/connman.h"
#include "net/fast_sync.h"
#include "net/msg_internal.h"
#include "net/msgprocessor.h"
#include "net/net.h"
#include "net/rom_seed.h"
#include "net/state_offer.h"
#include "platform/time_compat.h"
#include "services/sync_monitor.h"
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
/* Two whole chunks, so a cut between them leaves a journal to resume. */
#define ONION_BYTES (2u * ROM_SEED_CHUNK_SIZE)
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
    struct p2p_node *old_server, *old_client, *idle; /* the cut pair, a peer serving nothing */
    struct send_segment *old_server_q, *old_client_q, *idle_q;
    struct rom_artifact *artifact;
    uint8_t *wire;
    unsigned stray;               /* non-ZBND frames the client sent */
    unsigned chunk_req[2];        /* chunk requests the client sent, by index */
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
        struct state_offer_link_frame fr;
        if (stray && (n < 4 || memcmp(f->wire, "ZBND", 4))) ++*stray;
        else if (stray && state_offer_link_decode(f->wire, n, &fr) &&
                 fr.kind == STATE_OFFER_LINK_CHUNK_REQUEST && fr.index < 2)
            f->chunk_req[fr.index]++;
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

static void onion_trickle(struct onion_fixture *f);

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
    /* The fetch thread opens its link session on its own schedule, and only
     * a received part counts as progress: let the server's first part in. */
    for (int i = 0; i < 10000 && !state_offer_peer_serving_held_fetch(f->to_server); i++)
        onion_trickle(f);
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
    /* The one shared exemption: the streaming connection, not its far end. */
    ONION_CHECK(state_offer_peer_serving_held_fetch(f->to_server));
    ONION_CHECK(!state_offer_peer_serving_held_fetch(f->to_client));
    msg_processor_set_header_sync_hold(NULL);   /* the hold ends: discipline returns */
    ONION_CHECK(syncsvc_should_disconnect_stale_header_peer(f->to_server, 0, 0, 0, now));
    ONION_CHECK(syncsvc_is_header_sync_stalled(SYNC_HEADERS_DOWNLOAD, 0, now - 121, now));
    ONION_CHECK(!state_offer_peer_serving_held_fetch(f->to_server));
    msg_processor_set_header_sync_hold(onion_hold);
    return true;
}

/* One message-loop turn of a slow server: the client's requests go out, but
 * at most one queued server frame comes back. */
static void onion_trickle(struct onion_fixture *f)
{
    boot_zcode_swarm_tick(&f->mp, f->to_server, &f->svc);
    state_offer_peer_pump(&f->mp);
    onion_relay(f, f->to_server, f->to_server_q, f->to_client, &f->stray);
    size_t n = 0;
    if (onion_pop(f->to_client, f->to_client_q, f->wire, &n))
        (void)boot_zcode_swarm_frame(&f->mp, f->to_server, f->wire, n, &f->svc);
    struct timespec t = {0, 1000000};
    (void)nanosleep(&t, NULL);
}

/* Trickle until one more part lands (the link progress stamp moves). */
static bool onion_one_part(struct onion_fixture *f)
{
    int64_t before = sol_client_last_progress_ms();
    for (int i = 0; i < 3000; i++) {
        onion_trickle(f);
        if (sol_client_last_progress_ms() != before) return true;
    }
    return false;
}

/* Run F2: refill attempt 2 cut the streaming peer at 303 s and again at
 * 599 s. A slow server trickles one part every 29 s (under the 30 s no-part
 * bound) for 609 s; across both refill attempts only the idle peer goes. */
static bool onion_slow_server_kept(struct onion_fixture *f)
{
    struct connman cm;
    memset(&cm, 0, sizeof(cm));
    zcl_mutex_init(&cm.manager.cs_nodes);
    f->idle = onion_node(f, &f->idle_q, false);
    ONION_CHECK(f->idle && f->idle_q);
    struct p2p_node *peers[2] = {f->to_server, f->idle};
    cm.manager.nodes = peers;
    cm.manager.num_nodes = 2;
    sync_monitor_init();
    bool ok = sync_monitor_local_header_refill(&cm, 1, "test attempt 1") == 2;
    for (int step = 0; ok && step < 21; step++) {
        sol_client_test_age_progress(29000);
        ok = state_offer_peer_serving_held_fetch(f->to_server) && onion_one_part(f) &&
             state_offer_peer_serving_held_fetch(f->to_server) &&
             !state_offer_peer_serving_held_fetch(f->idle);
    }
    ok = ok && sync_monitor_local_header_refill(&cm, 1, "test attempt 2") == 2;
    zcl_mutex_destroy(&cm.manager.cs_nodes);
    ONION_CHECK(ok);
    ONION_CHECK(!atomic_load(&f->to_server->disconnect));
    ONION_CHECK(atomic_load(&f->idle->disconnect)); /* serving nothing: still rotated */
    return true;
}

static bool onion_journal_exists(const struct onion_fixture *f)
{
    char path[600];
    struct stat st;
    snprintf(path, sizeof(path), "%s.part.journal", f->landed);
    return stat(path, &st) == 0;
}

/* Run F2 at 22:04:40: every serving peer dropped at once, long after the
 * offer wait closed. The resumable .part had just gained bytes, so the node
 * waits; once no byte has come for the progress window it falls back. */
static bool onion_cut_mid_fetch(struct onion_fixture *f)
{
    struct state_offer_store_status st = {0};
    for (int i = 0; i < 20000 && st.fetch_chunks_done < 1; i++) {
        onion_trickle(f);
        state_offer_store_status_get(&st);
    }
    ONION_CHECK(st.fetch_chunks_done == 1 && st.fetch_chunks_total == 2);
    state_offer_store_test_age_wait(STATE_OFFER_WAIT_MS);
    f->nm.num_nodes = 0; /* both ends of the connection are gone */
    atomic_store(&f->to_server->disconnect, true);
    atomic_store(&f->to_client->disconnect, true);
    for (int i = 0; i < 5000 && state_offer_service_test_fetch_running(); i++)
        onion_cycle(f);
    for (int i = 0; i < 5; i++) onion_cycle(f);
    ONION_CHECK(!state_offer_service_test_fetch_running());
    ONION_CHECK(onion_journal_exists(f));
    state_offer_store_status_get(&st);
    ONION_CHECK(st.last_decision == STATE_OFFER_DECIDE_WAIT && !st.fallback_reason[0]);
    struct state_offer_need need;
    state_offer_service_test_local_need(&need);
    ONION_CHECK(need.resume_progressing);

    sol_client_test_age_progress(STATE_OFFER_FETCH_PROGRESS_WINDOW_MS);
    /* A retried offer from the dead connection opens a session but no byte
     * comes: that is no progress, so a node with no source still falls back. */
    int64_t aged = sol_client_last_progress_ms();
    uint64_t dead = boot_zcode_swarm_peer_id(f->to_server);
    bool began = state_offer_peer_begin(dead);
    if (began) state_offer_peer_end(dead);
    bool unstamped = began && sol_client_last_progress_ms() == aged;
    state_offer_service_test_local_need(&need);
    bool stalled = unstamped && !need.resume_progressing;
    struct state_offer_record rec;
    bool fell = state_offer_store_decide_for(platform_time_monotonic_ms(), &rec, &need) ==
                STATE_OFFER_DECIDE_FALL_BACK;
    state_offer_store_status_get(&st);
    sol_client_test_age_progress(-STATE_OFFER_FETCH_PROGRESS_WINDOW_MS);
    ONION_CHECK(stalled && fell);
    ONION_CHECK(strstr(st.fallback_reason, "no acceptable offer within") != NULL);
    return true;
}

/* The peers come back on new connections: they are asked for offers at once
 * and the fetch resumes from the journal (chunk 0 is never asked again). */
static bool onion_reconnect_resumes(struct onion_fixture *f)
{
    f->old_server = f->to_server; f->old_server_q = f->to_server_q;
    f->old_client = f->to_client; f->old_client_q = f->to_client_q;
    f->to_server = onion_node(f, &f->to_server_q, false);
    f->to_client = onion_node(f, &f->to_client_q, true);
    ONION_CHECK(f->to_server && f->to_client && f->to_server_q && f->to_client_q);
    f->list[0] = f->to_server; f->list[1] = f->to_client;
    f->nm.num_nodes = 2;
    memset(f->chunk_req, 0, sizeof(f->chunk_req));
    for (int i = 0; i < 5000 && !state_offer_peer_serving_held_fetch(f->to_server); i++)
        onion_cycle(f);
    ONION_CHECK(state_offer_peer_serving_held_fetch(f->to_server));
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
    struct state_offer_restart_hint hint;
    state_offer_service_restart_hint(&hint);
    ONION_CHECK(hint.pending && hint.height == ONION_RUNG && hint.bytes == ONION_BYTES &&
                memcmp(hint.digest, f->artifact->whole_sha3, 32) == 0);
    ONION_CHECK(f->stray == 0); /* the engine-off client sent only link frames */
    ONION_CHECK(f->chunk_req[0] == 0 && f->chunk_req[1] >= 1); /* resumed from the journal */
    return true;
}

static bool onion_restart_status(const struct state_offer_restart_hint *hint)
{
    struct json_value state; json_init(&state);
    bool ok = status_frontdoor_dump_state_json(&state, NULL);
    const struct json_value *pending = json_get(&state, "restart_pending");
    const struct json_value *height = json_get(&state, "restart_bundle_height");
    const struct json_value *bytes = json_get(&state, "restart_bundle_bytes");
    const struct json_value *digest = json_get(&state, "restart_bundle_digest");
    char hex[65]; zcl_hex_encode(hint->digest, 32, hex); hex[64] = '\0';
    ok = ok && pending && pending->type == JSON_BOOL && json_get_bool(pending) &&
        height && height->type == JSON_INT && json_get_int(height) == hint->height &&
        bytes && bytes->type == JSON_INT && json_get_int(bytes) == (int64_t)hint->bytes &&
        digest && digest->type == JSON_STR && !strcmp(json_get_str(digest), hex);
    json_free(&state); return ok;
}

static bool onion_hint_negative_cases(struct onion_fixture *f)
{
    struct state_offer_restart_hint hint;
    struct state_offer_v1 offer = {0};
    offer.bundle_height = ONION_RUNG; offer.content_bytes = ONION_BYTES;
    memcpy(offer.content_digest, f->artifact->whole_sha3, 32);
    state_offer_service_test_clear_restart_hint();
    ONION_CHECK(state_offer_service_test_arm_landed(f->landed, &offer));
    state_offer_service_restart_hint(&hint); ONION_CHECK(!hint.pending);
    ONION_CHECK(state_offer_service_test_arm_landed("/different/bundle", &offer));
    state_offer_service_restart_hint(&hint); ONION_CHECK(!hint.pending);
    boot_install_bundle_clear(f->dir);
    char marker[512], request[512];
    snprintf(marker, sizeof(marker), "%s/consensus-bundle-installed.marker", f->dir);
    snprintf(request, sizeof(request), "%s/install_bundle_request", f->dir);
    FILE *fp = fopen(marker, "w"); ONION_CHECK(fp && fclose(fp) == 0);
    ONION_CHECK(state_offer_service_test_arm_landed(f->landed, &offer));
    state_offer_service_restart_hint(&hint); ONION_CHECK(!hint.pending);
    ONION_CHECK(unlink(marker) == 0);
    boot_install_bundle_clear(f->dir);
    fp = fopen(request, "w"); ONION_CHECK(fp && fputs("bad\n", fp) >= 0 && fclose(fp) == 0);
    ONION_CHECK(state_offer_service_test_arm_landed(f->landed, &offer));
    state_offer_service_restart_hint(&hint); ONION_CHECK(!hint.pending);
    boot_install_bundle_clear(f->dir);
    fp = fopen(request, "w");
    ONION_CHECK(fp && fprintf(fp, "-1\n%s\n", f->landed) > 0 && fclose(fp) == 0);
    ONION_CHECK(!state_offer_service_test_arm_landed(f->landed, &offer));
    state_offer_service_restart_hint(&hint); ONION_CHECK(!hint.pending);
    boot_install_bundle_clear(f->dir);
    ONION_CHECK(state_offer_service_test_arm_landed(f->landed, &offer));
    state_offer_service_restart_hint(&hint); ONION_CHECK(hint.pending);
    ONION_CHECK(onion_restart_status(&hint));
    state_offer_service_shutdown();
    state_offer_service_restart_hint(&hint); ONION_CHECK(!hint.pending);
    struct json_value state; json_init(&state);
    ONION_CHECK(status_frontdoor_dump_state_json(&state, NULL));
    const struct json_value *pending = json_get(&state, "restart_pending");
    bool stopped = pending && pending->type == JSON_BOOL && !json_get_bool(pending) &&
        !json_get(&state, "restart_bundle_digest");
    json_free(&state); ONION_CHECK(stopped);
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
    onion_drop_queue(f->old_server, f->old_server_q);
    onion_drop_queue(f->old_client, f->old_client_q);
    onion_drop_queue(f->idle, f->idle_q);
    f->nm.nodes = NULL; f->nm.num_nodes = 0;
    if (f->to_server) p2p_node_free(f->to_server);
    if (f->to_client) p2p_node_free(f->to_client);
    if (f->old_server) p2p_node_free(f->old_server);
    if (f->old_client) p2p_node_free(f->old_client);
    if (f->idle) p2p_node_free(f->idle);
    net_manager_free(&f->nm);
    rom_seed_reset(); state_offer_store_reset();
    if (f->dir[0]) test_rm_rf_recursive(f->dir);
    free(f->artifact); free(f->wire);
}

int test_state_offer_onion_link(void)
{
    struct onion_fixture f = {0};
    bool ok = onion_setup(&f) && onion_legacy_dropped() && onion_discover_and_fetch(&f) &&
              onion_serving_peer_kept(&f) && onion_slow_server_kept(&f) &&
              onion_cut_mid_fetch(&f) && onion_reconnect_resumes(&f) && onion_lands(&f) &&
              onion_hint_negative_cases(&f);
    onion_cleanup(&f);
    printf("state_offer_onion_link: %s\n", ok ? "OK" : "FAIL");
    return ok ? 0 : 1;
}
