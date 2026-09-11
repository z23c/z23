/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * The getheaders SERVE BUDGET and the DEFERRED-REQUEST park/replay it implies.
 * Declared in net/msg_internal.h; split out of msg_headers.c, which is pinned
 * shrink-only by tools/lint/file_size_policy_baseline.txt. process_getheaders
 * itself stays in msg_headers.c and calls straight into this file. */

#include "net/msg_internal.h"

#include "core/serialize.h"
#include "net/fast_sync.h"
#include "net/net.h"
#include "net/p2p_message.h"
#include "platform/time_compat.h"
#include "util/log_macros.h"

#include <stdatomic.h>
#include <string.h>

/* Deferred requests this node came back and answered once the peer's window
 * rolled (getheaders_park_deferred / getheaders_replay_deferred below). At
 * most one per peer per window, and always <= the defer count msg_headers.c
 * raises at the gate. */
static _Atomic uint64_t g_getheaders_replayed_deferred = 0;

/* See net/msg_internal.h. */
uint64_t getheaders_replayed_deferred(void)
{
    return atomic_load(&g_getheaders_replayed_deferred);
}

/* ── per-peer serve window ─────────────────────────────────────────
 * Each answered request serves up to getheaders_serve_page(services)
 * headers — one Equihash verification each (~0.8 s of a core) and up to
 * ~2.9 MB of wire — so an unbounded peer, not this node, chooses the
 * serve bill. Honest IBD re-asks at its own pace: a ZCL23 peer taking
 * full 2000-header pages re-asks roughly once per scheduler poll
 * (~6/min); a legacy peer (MAX_HEADERS_RESULTS=160, no NODE_ZCL23) chains
 * a new getheaders after every 160-header reply, so it legitimately re-
 * asks far more often while behind. The allowance
 * (getheaders_serve_request_allowance(), net/msg_internal.h) is a fixed
 * HEADER budget per window translated into a request count by that
 * peer's own page size, so both cases cost this node the same header-
 * serving bill; it is set generously against the honest pace — several
 * scheduler polls, or several legacy pages, land in every window, and an
 * RTT-bound pipelining burst still fits — and exceeding it costs the
 * peer nothing permanent: the request is DEFERRED — no reply, no
 * disconnect, no offence, no ban-score. A deferred peer simply sees its
 * next request go unanswered and retries; punishing here could only hurt
 * a peer we mis-measured. Same fixed window as the addr limit
 * (msgprocessor_inv.c::process_addr): roll on expiry, count admitted
 * requests, defer the rest. Counted + rising-edge logged so a deferred
 * peer's header sync never goes quiet without a name and a number. The
 * window lives on `node`, so it dies with the connection.
 *
 * getheaders_serve_page() / getheaders_serve_request_allowance() — see the
 * declarations and rationale in net/msg_internal.h. Kept next to the window
 * they bound: process_getheaders (msg_headers.c) makes the same page choice
 * for the serve-window gate and for the reply-count bound it serves under. */
int getheaders_serve_page(uint64_t services)
{
    return peer_supports_fast_sync(services) ? GETHEADERS_SERVE_PAGE_FAST_SYNC
                                              : GETHEADERS_SERVE_PAGE_LEGACY;
}

uint32_t getheaders_serve_request_allowance(uint64_t services)
{
    /* Both pages are positive compile-time constants today; the clamp keeps
     * a future page of zero (or a negative int) from becoming a divide by
     * zero or an effectively unbounded allowance. */
    int page = getheaders_serve_page(services);
    if (page <= 0)
        page = GETHEADERS_SERVE_PAGE_LEGACY;
    return GETHEADERS_SERVE_HEADERS_PER_WINDOW / (uint32_t)page;
}

/* Park the request the serve window just deferred so the send tick can answer
 * it when the window rolls (struct p2p_node::getheaders_deferred_req).
 *
 * `s` is positioned at the START of the still-unread payload: process_getheaders
 * defers before it deserializes the locator, so read_pos is exactly the byte
 * the peer's request begins at. The copy is a plain memcpy into fixed node
 * bytes — nothing is allocated on a path a hostile peer drives. A payload that
 * does not fit (or an empty one) is simply not parked, and it leaves whatever
 * is already parked alone: that earlier request is still one the peer is owed,
 * and it must not be traded for a request that cannot be answered at all. A
 * later PARKABLE defer inside the same window overwrites the slot, and a
 * request that gets SERVED disarms it (process_getheaders): the newest locator
 * is the one worth answering, and the peer only ever waits on its latest ask.
 *
 * replay_after is the window's own roll time, floored at now+1 so a backdated
 * or clock-jumped window_start can neither arm a replay for the past window
 * nor one that is already due in this same second (the replay guard is
 * `now < replay_after`, so a floor of now would refire every tick until the
 * second turned). The ARM FLAG is the length, not replay_after: the not-parked
 * path with an empty slot leaves the length at zero (disarmed) and sets
 * replay_after only so the defer log's replay_in reads 0 instead of an
 * epoch-sized negative.
 *
 * A request that is about to be SERVED supersedes anything parked from
 * the old window: the peer is waiting on THIS ask now, so an older
 * locator must not replay behind it and spend an admission on a page
 * nobody is waiting for. Only past the parse, in process_getheaders: a
 * malformed ask is admitted but never answered, and it must not take the
 * owed park with it, or the peer is back to the silence the park exists
 * to end. */
void getheaders_park_deferred(struct p2p_node *node,
                              const struct byte_stream *s,
                              int64_t now_unix)
{
    size_t len = s->size > s->read_pos ? s->size - s->read_pos : 0;
    if (len == 0 || len > GETHEADERS_DEFERRED_REQ_MAX_BYTES) {
        if (node->getheaders_deferred_len == 0)
            node->getheaders_deferred_replay_after = now_unix;
        return; // raw-return-ok:payload-does-not-fit-the-parking-slot
    }
    memcpy(node->getheaders_deferred_req, s->data + s->read_pos, len);
    node->getheaders_deferred_len = (uint16_t)len;
    int64_t rolls_at =
        node->getheaders_rate_window_start + GETHEADERS_SERVE_WINDOW_SECS;
    node->getheaders_deferred_replay_after =
        rolls_at > now_unix ? rolls_at : now_unix + 1;
}

/* See net/msg_internal.h. */
bool getheaders_replay_deferred(struct msg_processor *mp,
                                struct p2p_node *node)
{
    if (!mp || !node || node->getheaders_deferred_len == 0)
        return false; // raw-return-ok:nothing-parked-for-this-peer
    if (atomic_load(&node->disconnect))
        return false; // raw-return-ok:peer-is-going-away
    if (platform_time_wall_unix() < node->getheaders_deferred_replay_after)
        return false; // raw-return-ok:serve-window-has-not-rolled-yet

    /* DISARM FIRST, then serve. The replay runs the unmodified
     * process_getheaders, which draws an admission from the rolled window
     * like any other request and may defer (and re-park) again if the peer
     * has meanwhile refilled it — so the slot must already be free, or a
     * defer inside the replay would be lost, and a still-armed slot could
     * be served twice. Copying the bytes out first keeps the replay reading
     * a stable payload even across that re-park. */
    uint8_t payload[GETHEADERS_DEFERRED_REQ_MAX_BYTES];
    uint16_t len = node->getheaders_deferred_len;
    memcpy(payload, node->getheaders_deferred_req, len);
    node->getheaders_deferred_len = 0;
    node->getheaders_deferred_replay_after = 0;

    uint64_t n = atomic_fetch_add(&g_getheaders_replayed_deferred, 1) + 1;
    LOG_INFO("headers",
             "process_getheaders: replaying deferred getheaders from %s — "
             "serve window rolled (bytes=%u replayed_deferred=%llu)",
             node->addr_name, (unsigned)len, (unsigned long long)n);

    /* Non-owning read view over our own copy — the exact shape the live
     * dispatcher hands process_getheaders (msgprocessor.c). Its verdict is
     * the serve path's own: a replay never punishes the peer, because the
     * bytes were already accepted as a well-formed message once. */
    struct byte_stream view;
    stream_init_from_data(&view, payload, len);
    (void)process_getheaders(mp, node, &view);
    stream_free(&view);
    return true;
}
