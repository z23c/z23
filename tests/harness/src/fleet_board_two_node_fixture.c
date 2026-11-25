/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Two-node fleet-board fixture: see test/fleet_board_two_node_fixture.h. */

#include "test/fleet_board_two_node_fixture.h"

#include "chain/chainparams.h"
#include "config/boot_fleet_board.h"
#include "config/mesh_stream.h"
#include "crypto/ed25519.h"
#include "models/fleet_board_post.h"
#include "net/noise_transport.h"
#include "platform/clock.h"
#include "test/mesh_stream_fixture.h"
#include "test/mesh_stream_loopback.h"
#include "test/test_core.h"
#include "util/fleet_role_check.h"
#include "util/sync.h"

#include <stdio.h>
#include <string.h>

/* Two distinct, deterministic host identities. A board post is only as
 * meaningful as the key that signed it, so the tests never share one. */
void fb_test_identity(uint8_t which, uint8_t seed[32], uint8_t pk[32])
{
    uint8_t sk[32];
    memset(seed, 0, 32);
    seed[0] = which;
    seed[31] = (uint8_t)(0xa0 + which);
    ed25519_keypair(pk, sk, seed);
    memcpy(seed, sk, 32);
}

void fb_test_compose(struct fleet_board_post *post, uint8_t kind,
                            const char *agent, const char *text,
                            uint64_t created_at, uint32_t ttl)
{
    memset(post, 0, sizeof(*post));
    post->kind = kind;
    post->created_at = created_at;
    post->ttl = ttl;
    (void)snprintf(post->agent, sizeof(post->agent), "%s", agent ? agent : "");
    size_t n = strlen(text);
    memcpy(post->text, text, n);
    post->text[n] = '\0';
    post->text_len = (uint32_t)n;
}


void fb_test_scope(struct fleet_board_post *post, uint8_t scope,
                          const char *room)
{
    post->scope = scope;
    (void)snprintf(post->room, sizeof(post->room), "%s", room ? room : "");
}

bool g_fbw_deny_read;
bool g_fbw_deny_post;
uint8_t g_fbw_deny_post_key[32];

/* Role gate for this group: every key may do everything, except fleet reads
 * can be switched off and one author can be refused. */
bool fbw_role_check(const uint8_t key[32], const char *leaf,
                    const char *kind, char *why, size_t why_cap,
                    void *ctx)
{
    (void)kind;
    (void)ctx;
    bool deny = (g_fbw_deny_read &&
                 strcmp(leaf, FLEET_BOARD_FLEET_READ_LEAF) == 0) ||
                (g_fbw_deny_post &&
                 strcmp(leaf, ZCL_FLEET_LEAF_BOARD_POST) == 0 &&
                 memcmp(key, g_fbw_deny_post_key, 32) == 0);
    if (deny && why && why_cap)
        (void)snprintf(why, why_cap, "role_refused: test denies %s", leaf);
    return !deny;
}

static bool fbw_nodes_open(struct fbw *w)
{
    zcl_mutex_init(&w->nm.cs_nodes);
    zcl_mutex_init(&w->nm.cs_last_node_id);
    w->nodes_inited = true;
    struct net_address addr;
    memset(&addr, 0, sizeof(addr));
    addr.svc.port = 18035;
    w->asker = p2p_node_create(&w->nm, ZCL_INVALID_SOCKET, &addr,
                               "board-ask", true);
    w->answerer = p2p_node_create(&w->nm, ZCL_INVALID_SOCKET, &addr,
                                  "board-answer", false);
    if (!w->asker || !w->answerer)
        return false;
    w->asker->transport = w->f.term_peer.ini;
    w->answerer->transport = w->f.res_term;
    w->asker->state = PEER_HANDSHAKE_COMPLETE;
    w->answerer->state = PEER_HANDSHAKE_COMPLETE;
    w->nodes[0] = w->asker;
    w->nodes[1] = w->answerer;
    w->nm.nodes = w->nodes;
    w->nm.num_nodes = 2;
    w->ask_q = mesh_loop_sentinel(w->asker);
    w->answer_q = mesh_loop_sentinel(w->answerer);
    return w->ask_q && w->answer_q;
}

bool fbw_open(struct fbw *w)
{
    memset(w, 0, sizeof(*w));
    test_make_tmpdir(w->dir, sizeof(w->dir), "fleet_board", "carriage");
    w->fixture_open = mesh_term_fixture_open(&w->f, w->dir);
    if (!w->fixture_open || !fbw_nodes_open(w))
        return false;
    w->mp.net_mgr = &w->nm;
    w->mp.params = chain_params_get();
    w->svc.msg_processor = &w->mp;
    w->dbsvc.node_db = &w->f.ndb; /* the pairing authority */
    w->dbsvc.started = true;
    w->runtime.db_service = &w->dbsvc;
    app_runtime_set_current(&w->runtime);
    mesh_stream_test_bind(&w->svc);
    mesh_stream_test_reset();
    w->registered = boot_fleet_board_fleet_register_service();
    memset(w->box_a, 0xA1, 32);
    memset(w->box_b, 0xB2, 32);
    return w->mp.params && w->registered && node_db_open(&w->a, ":memory:") &&
           node_db_open(&w->b, ":memory:");
}

void fbw_close(struct fbw *w)
{
    boot_fleet_board_fleet_test_bind_authority(NULL, NULL, 0);
    mesh_stream_test_reset();
    boot_fleet_board_fleet_test_bind(NULL);
    mesh_stream_service_unregister(FLEET_BOARD_FLEET_SERVICE_NAME);
    mesh_stream_service_unregister(FLEET_BOARD_ROSTER_SERVICE_NAME);
    mesh_stream_service_unregister(FLEET_BOARD_WAKE_SERVICE_NAME);
    mesh_stream_test_bind(NULL);
    app_runtime_set_current(NULL);
    mesh_loop_free_queue(w->asker, w->ask_q);
    mesh_loop_free_queue(w->answerer, w->answer_q);
    p2p_node_free(w->asker);
    p2p_node_free(w->answerer);
    free(w->ask_q);
    free(w->answer_q);
    if (w->nodes_inited) {
        zcl_mutex_destroy(&w->nm.cs_nodes);
        zcl_mutex_destroy(&w->nm.cs_last_node_id);
    }
    if (w->a.open)
        node_db_close(&w->a);
    if (w->b.open)
        node_db_close(&w->b);
    if (w->fixture_open)
        mesh_term_fixture_close(&w->f);
    test_rm_rf_recursive(w->dir);
}

/* Sign and store one post in `db` as if it arrived at `received_at`. */
bool fbw_post(struct node_db *db, uint8_t who, uint8_t scope, const char *text,
              int64_t created_at, uint32_t ttl, int64_t received_at,
              struct fleet_board_post *out)
{
    uint8_t seed[32], pk[32];
    fb_test_identity(who, seed, pk);
    fb_test_compose(out, FLEET_BOARD_KIND_NOTE, "carrier", text,
                    (uint64_t)created_at, ttl);
    fb_test_scope(out, scope,
                  scope == FLEET_BOARD_SCOPE_PUBLIC ? "general" : "");
    return fleet_board_post_sign(out, seed, pk) == FLEET_BOARD_OK &&
           db_fleet_board_post_ingest(db, out, received_at, NULL) ==
               FLEET_BOARD_OK;
}

bool fbw_pull_answer(struct fbw *w, const uint8_t peer_box[32], size_t *frames)
{
    *frames = 0;
    mesh_loop_discard(w->asker, w->ask_q, w->f.res_term);
    mesh_loop_discard(w->answerer, w->answer_q, w->f.term_peer.ini);
    mesh_stream_test_reset();
    /* A partition is a session table that holds no peer: the OPEN is refused
     * as not connected before anything is sent. */
    typeof(w->nm.num_nodes) live = w->nm.num_nodes;
    if (w->partitioned)
        w->nm.num_nodes = 0;
    bool opened = boot_fleet_board_fleet_test_pull(w->f.resp_noise_pub, peer_box);
    w->nm.num_nodes = live;
    if (!opened ||
        mesh_loop_pump(w->asker, w->ask_q, w->f.res_term, &w->mp,
                       w->answerer) != 1)
        return false;
    boot_fleet_board_fleet_test_serve(); /* the answer, when there is one */
    boot_fleet_board_fleet_test_serve(); /* nothing left: close */
    *frames = mesh_loop_pump(w->answerer, w->answer_q, w->f.term_peer.ini,
                             &w->mp, w->asker);
    return true;
}

/* One whole pull toward the answering box as `peer_box`: the OPEN, the
 * answer, the close, and the commit into `into`. Returns the posts newly
 * stored; `frames` receives how many frames the answering box sent. */
size_t fbw_pull(struct fbw *w, const uint8_t peer_box[32],
                struct node_db *into, size_t *frames)
{
    if (!fbw_pull_answer(w, peer_box, frames))
        return SIZE_MAX;
    return boot_fleet_board_fleet_test_drain_into(into);
}

/* The verdict a raw OPEN from the asking node gets, read off the wire. */
uint8_t fbw_raw_open_verdict(struct fbw *w, uint64_t stream_id)
{
    uint8_t pull[FLEET_BOARD_FLEET_PULL_BYTES];
    memset(pull, 0, sizeof(pull));
    pull[0] = (uint8_t)FLEET_BOARD_FLEET_MSG_PULL;
    pull[1] = (uint8_t)FLEET_BOARD_FLEET_VERSION;
    uint8_t frame[MESH_LOOP_WIRE_MAX];
    size_t frame_len = mesh_stream_test_open_frame(
        stream_id, 4096u, FLEET_BOARD_FLEET_SERVICE_NAME, pull, sizeof(pull),
        frame, sizeof(frame));
    uint8_t answer[MESH_LOOP_WIRE_MAX];
    uint8_t kind = 0;
    bool more = false;
    if (frame_len == 0 ||
        !mesh_stream_frame(&w->mp, w->answerer, frame, frame_len, NULL))
        return 0xFFu;
    size_t answer_len = mesh_loop_take(w->answerer, w->answer_q,
                                       w->f.term_peer.ini, answer,
                                       sizeof(answer), &more);
    if (!mesh_stream_test_read_header(answer, answer_len, &kind, NULL) ||
        kind != MESH_STREAM_KIND_CLOSE)
        return 0xFEu;
    return answer[MESH_STREAM_FRAME_PREFIX_LEN + 1u + 8u];
}

/* Every fleet post in `posts` is held by `db`. */
bool fbw_holds_all(struct node_db *db,
                  const struct fleet_board_post *posts, size_t n)
{
    for (size_t i = 0; i < n; i++)
        if (!db_fleet_board_have(db, posts[i].id))
            return false;
    return true;
}

/* Deliver independently composed frames through the real encrypted P2P queue. */
bool fbw_deliver(struct fbw *w, const uint8_t *frame, size_t len)
{
    if (!len || !p2p_node_begin_message(w->asker, "zpkgswm",
                                       w->mp.params->pchMessageStart))
        return false;
    p2p_node_write_message_data(w->asker, frame, len);
    return p2p_node_end_message(w->asker) &&
           mesh_loop_pump(w->asker, w->ask_q, w->f.res_term, &w->mp,
                           w->answerer) == 1;
}

bool fbw_exact_answer(const uint8_t *frame, size_t len,
                      const struct fleet_board_post *post)
{
    uint8_t wire[MESH_LOOP_WIRE_MAX];
    size_t wire_len = 0;
    const size_t offset = MESH_STREAM_FRAME_PREFIX_LEN + 1u + 8u + 2u +
                          FLEET_BOARD_FLEET_ANSWER_HEAD +
                          FLEET_BOARD_FLEET_RECORD_HEAD;
    return fleet_board_post_encode(post, wire, sizeof(wire), &wire_len) ==
               FLEET_BOARD_OK && len == offset + wire_len &&
           memcmp(frame + offset, wire, wire_len) == 0;
}
