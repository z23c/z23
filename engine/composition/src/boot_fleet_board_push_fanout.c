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
 * post does, within FLEET_BOARD_PUSH_WAIT_S. Nothing here is retried.
 */

#include "boot_fleet_board_push_round_internal.h"

#include "boot_fleet_board_authority_internal.h"
#include "boot_mesh_status_internal.h"
#include "config/boot_internal.h"

#include "models/fleet_board_post.h"
#include "net/msgprocessor.h"
#include "net/net.h"
#include "net/noise_transport.h"

#include <stdatomic.h>
#include <string.h>

static _Atomic uint64_t g_fanout;
static _Atomic uint64_t g_fanout_refused[FLEET_BOARD_PUSH_REFUSALS];

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

void board_push_fanout(struct push_round *r, const struct push_queued *q,
                       const struct push_peer *done)
{
    for (size_t i = 0; i < r->n_peers; i++) {
        struct push_peer *p = &r->peers[i];
        if (p->lead == p && p != done)
            fanout_offer(r, q, p);
    }
}

void board_push_fanout_counts(struct boot_fleet_board_fleet_counts *out)
{
    out->push_fanout = atomic_load_explicit(&g_fanout, memory_order_relaxed);
    for (size_t i = 0; i < FLEET_BOARD_PUSH_REFUSALS; i++)
        out->push_fanout_refused[i] =
            atomic_load_explicit(&g_fanout_refused[i], memory_order_relaxed);
}
