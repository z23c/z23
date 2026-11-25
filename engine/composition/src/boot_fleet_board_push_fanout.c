/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: The push's fan-out (config/boot_fleet_board.h, PUSH). A new FLEET
 * post from the local post path is offered, in the same sending round as its
 * addressed push, to every paired peer that has a live session now and that
 * the answering half's own disclosure decision (board_push_disclosure: the
 * pairing row, a current delegation on that session, the read role, the
 * roster) would serve on a pull. A peer with no session is left to the pull;
 * a peer the decision refuses is counted by the check that failed and never
 * pushed to; a peer proving the post's author key is the author's own box.
 * A post that cannot ride now waits for that one peer exactly as an addressed
 * post does, within FLEET_BOARD_PUSH_WAIT_S, and is counted as fanned out
 * when it rides. Nothing here is retried.
 *
 * A peer on the fleet roster with no pairing row is NOT pushed to: the push
 * rides the paired "board" service, whose stream primitive refuses a peer
 * with no pairing row, and its receiving half proves a pusher only through
 * pairing rows. Such a peer still pulls over "board.roster" on the roster
 * pull interval, so the gap shows. Each fan-out post counts, in
 * push_fanout_roster_unpushed,
 * the connected roster-only peers the roster answer would serve it to now:
 * the key the peer proved with a verified asking proof on THIS session, that
 * key's standing (no pairing row, a member of the roster in force) and the
 * read role, asked exactly as board_roster_open and board_serve_authorized
 * ask them, with nothing recorded.
 */

#include "boot_fleet_board_push_round_internal.h"

#include "boot_fleet_board_authority_internal.h"
#include "boot_fleet_board_roster_internal.h"
#include "boot_mesh_status_internal.h"
#include "config/boot_internal.h"
#include "config/runtime.h"

#include "models/fleet_board_post.h"
#include "net/msgprocessor.h"
#include "net/net.h"
#include "net/noise_transport.h"

#include <stdatomic.h>
#include <string.h>

static _Atomic uint64_t g_fanout;
static _Atomic uint64_t g_fanout_refused[FLEET_BOARD_PUSH_REFUSALS];
static _Atomic uint64_t g_fanout_roster_unpushed;

/* The live session to `noise`, under its send budget: PUSH_OK, or why not.
 * `snap` receives the session. */
static int fanout_link(const struct push_round *r, const uint8_t noise[32],
                       struct noise_transport_snapshot *snap)
{
    memset(snap, 0, sizeof *snap);
    struct p2p_node *node =
        r->svc && r->svc->msg_processor && r->svc->msg_processor->net_mgr
            ? boot_mesh_find_session_peer(r->svc->msg_processor->net_mgr,
                                          noise, snap)
            : NULL;
    if (!node)
        return FLEET_BOARD_PUSH_SKIP_NOT_CONNECTED;
    bool over = net_send_over_budget(node);
    p2p_node_release(node);
    return over ? FLEET_BOARD_PUSH_SKIP_OVER_BUDGET : PUSH_OK;
}

/* One lead's fan-out judgment, once a round: connected first (a peer with
 * no session is the pull's, and is not judged or counted), then the pull's
 * own disclosure decision, which supplies the board key it would serve in
 * `fan_to`; then an older node this session, and an open push. */
static int fanout_judge(const struct push_round *r, struct push_peer *lead)
{
    const uint8_t *noise = lead->row.peer_noise_pubkey;
    struct noise_transport_snapshot snap;
    int link = fanout_link(r, noise, &snap);
    if (link == FLEET_BOARD_PUSH_SKIP_NOT_CONNECTED)
        return link;
    enum fleet_board_push_refusal refusal =
        board_push_disclosure(noise, lead->fan_to);
    if (refusal != FLEET_BOARD_PUSH_REFUSALS) {
        atomic_fetch_add_explicit(&g_fanout_refused[refusal], 1,
                                  memory_order_relaxed);
        return FLEET_BOARD_PUSH_SKIP_INELIGIBLE;
    }
    if (link != PUSH_OK)
        return link;
    if (board_push_session_unsupported(noise, &snap))
        return FLEET_BOARD_PUSH_SKIP_UNSUPPORTED;
    return board_push_out_live(noise) ? PUSH_HOLD : PUSH_OK;
}

/* Wait for `p`'s open push as an entry addressed to the key it was judged
 * for, so the next round offers the post to that peer alone. */
static void fanout_hold(struct push_round *r, const struct push_queued *q,
                        const struct push_peer *p)
{
    struct push_queued one = *q;
    one.fanout = false;
    one.fanned = true;
    one.has_to = true;
    memcpy(one.to, p->fan_to, 32);
    board_push_hold(r, &one, p);
}

/* The fan-out's step for one lead: a peer with no session, one the pull
 * would not serve and the author's own box are passed over without a skip
 * (the refusal is counted by fanout_judge). */
static void fanout_offer(struct push_round *r, const struct push_queued *q,
                         struct push_peer *p)
{
    if (p->fan_ready == PUSH_UNASKED)
        p->fan_ready = fanout_judge(r, p);
    int step = p->fan_ready;
    if (step == FLEET_BOARD_PUSH_SKIP_NOT_CONNECTED ||
        step == FLEET_BOARD_PUSH_SKIP_INELIGIBLE)
        return;
    if (memcmp(p->fan_to, q->host, 32) == 0)
        return;
    if (step == PUSH_OK)
        step = board_push_batch_add(r, p, q);
    if (step == PUSH_OK)
        atomic_fetch_add_explicit(&g_fanout, 1, memory_order_relaxed);
    else if (step == PUSH_HOLD)
        fanout_hold(r, q, p);
    else
        board_push_skip((enum fleet_board_push_skip)step, 1);
}

/* Would the roster answer serve a pull from `noise` now, on the session it
 * holds with this box? Its key must not be `host`, the post's author. */
static bool fanout_roster_serves(struct net_manager *nm,
                                 struct node_db *pairings,
                                 const uint8_t noise[32],
                                 const uint8_t host[32])
{
    struct noise_transport_snapshot snap;
    memset(&snap, 0, sizeof snap);
    struct p2p_node *node = boot_mesh_find_session_peer(nm, noise, &snap);
    if (!node)
        return false;
    p2p_node_release(node);
    uint8_t key[32];
    return fleet_board_roster_session_standing(
               pairings, board_db(), noise, snap.transcript_hash,
               snap.connection_generation, board_now(), key) &&
           memcmp(key, host, 32) != 0 && board_push_may_read(key);
}

/* The connected roster-only peers the roster answer would serve. */
static size_t fanout_roster_count(const struct push_round *r,
                                  const uint8_t host[32])
{
    struct node_db *pairings = app_runtime_node_db();
    struct net_manager *nm =
        r->svc && r->svc->msg_processor ? r->svc->msg_processor->net_mgr
                                        : NULL;
    if (!nm || !pairings || !app_runtime_node_db_handle_open(pairings))
        return 0;
    uint8_t noise[FLEET_BOARD_FLEET_PEERS_MAX][32];
    size_t n = fleet_board_roster_learned_peers(noise,
                                                FLEET_BOARD_FLEET_PEERS_MAX);
    size_t count = 0;
    for (size_t i = 0; i < n; i++)
        count += fanout_roster_serves(nm, pairings, noise[i], host);
    return count;
}

void board_push_fanout(struct push_round *r, const struct push_queued *q,
                       const struct push_peer *done)
{
    for (size_t i = 0; i < r->n_peers; i++) {
        struct push_peer *p = &r->peers[i];
        if (p->lead == p && p != done)
            fanout_offer(r, q, p);
    }
    if (!r->roster_counted || memcmp(r->roster_host, q->host, 32) != 0) {
        r->roster_unpushed = fanout_roster_count(r, q->host);
        memcpy(r->roster_host, q->host, 32);
        r->roster_counted = true;
    }
    if (r->roster_unpushed > 0)
        atomic_fetch_add_explicit(&g_fanout_roster_unpushed,
                                  r->roster_unpushed, memory_order_relaxed);
}

void board_push_fanout_sent(void)
{
    atomic_fetch_add_explicit(&g_fanout, 1, memory_order_relaxed);
}

void board_push_fanout_counts(struct boot_fleet_board_fleet_counts *out)
{
    out->push_fanout = atomic_load_explicit(&g_fanout, memory_order_relaxed);
    out->push_fanout_roster_unpushed = atomic_load_explicit(
        &g_fanout_roster_unpushed, memory_order_relaxed);
    for (size_t i = 0; i < FLEET_BOARD_PUSH_REFUSALS; i++)
        out->push_fanout_refused[i] =
            atomic_load_explicit(&g_fanout_refused[i], memory_order_relaxed);
}
