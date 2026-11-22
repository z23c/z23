/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Two-node fleet-board fixture: two board stores joined by one paired mesh
 * stream over the loopback wire, with the production "board" service
 * callbacks. Only the socket, the DHT delegation lookup and the clock are
 * stood in for. Shared by test_fleet_board and test_fleet_board_replication. */

#ifndef ZCL_TEST_FLEET_BOARD_TWO_NODE_FIXTURE_H
#define ZCL_TEST_FLEET_BOARD_TWO_NODE_FIXTURE_H

#include "config/boot_internal.h"
#include "config/runtime.h"
#include "config/db_service.h"
#include "models/database.h"
#include "models/fleet_board_post.h"
#include "net/msgprocessor.h"
#include "net/net.h"
#include "test/mesh_term_fixture.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Inside the fixture delegations' signed window (1000..4000). */
#define FBW_NOW INT64_C(2500)
#define FBW_PAIRED_AT INT64_C(1)
#define FBW_PAIRING_EXPIRES INT64_C(4102444800)
#define FBW_POSTS 40

struct fbw {
    char dir[256];
    struct mesh_term_fixture f;
    struct net_manager nm;
    struct msg_processor mp;
    struct p2p_node *asker;    /* accepted the link: the pulling box */
    struct p2p_node *answerer; /* dialled the link: the box behind NAT */
    struct p2p_node *nodes[2];
    struct send_segment *ask_q;
    struct send_segment *answer_q;
    struct boot_svc_ctx svc;
    struct db_service dbsvc;
    struct app_runtime_context runtime;
    struct node_db a; /* the answering box's board store */
    struct node_db b; /* the asking box's board store */
    uint8_t box_a[32];
    uint8_t box_b[32];
    bool fixture_open;
    bool nodes_inited;
    bool registered;
    bool partitioned; /* pulls cannot reach the answering box */
};

extern bool g_fbw_deny_read;
extern bool g_fbw_deny_post;
extern uint8_t g_fbw_deny_post_key[32];

/* Two distinct, deterministic host identities; a post, and its scope. */
void fb_test_identity(uint8_t which, uint8_t seed[32], uint8_t pk[32]);
void fb_test_compose(struct fleet_board_post *post, uint8_t kind,
                     const char *agent, const char *text, uint64_t created_at,
                     uint32_t ttl);
void fb_test_scope(struct fleet_board_post *post, uint8_t scope,
                   const char *room);

/* Role gate: every key may do everything, except fleet reads can be switched
 * off and one author refused. Install it with zcl_fleet_role_checker_install. */
bool fbw_role_check(const uint8_t key[32], const char *leaf, const char *kind,
                    char *why, size_t why_cap, void *ctx);
bool fbw_open(struct fbw *w);
void fbw_close(struct fbw *w);
/* Sign and store one post in db as if it arrived at received_at. */
bool fbw_post(struct node_db *db, uint8_t who, uint8_t scope, const char *text,
              int64_t created_at, uint32_t ttl, int64_t received_at,
              struct fleet_board_post *out);
/* One pull up to, but not including, the commit: the OPEN, the answer and the
 * close. False when the stream could not open (peer not connected). frames
 * receives how many frames the answering box sent. */
bool fbw_pull_answer(struct fbw *w, const uint8_t peer_box[32], size_t *frames);
/* One whole pull: fbw_pull_answer, then the commit into into. Returns the
 * posts newly stored, SIZE_MAX when the stream did not open. */
size_t fbw_pull(struct fbw *w, const uint8_t peer_box[32],
                struct node_db *into, size_t *frames);
uint8_t fbw_raw_open_verdict(struct fbw *w, uint64_t stream_id);
bool fbw_holds_all(struct node_db *db, const struct fleet_board_post *posts,
                   size_t n);
bool fbw_deliver(struct fbw *w, const uint8_t *frame, size_t len);
bool fbw_exact_answer(const uint8_t *frame, size_t len,
                      const struct fleet_board_post *post);

#endif /* ZCL_TEST_FLEET_BOARD_TWO_NODE_FIXTURE_H */
