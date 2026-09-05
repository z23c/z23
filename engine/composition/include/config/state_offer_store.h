/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: What a first-boot node does with the state offers its peers send.
 *
 * ZRC-0011 phase 1a, consumer half. A node with no fast-start state source
 * previously had exactly one thing to do: fold from genesis, loudly, through
 * bootstrap.no_state_source (engine/conditions/src/no_state_source.c). Its
 * peers may well have been holding a recent bundle the whole time; the peer
 * link simply never carried the question. Now it does — offers arrive appended
 * to "zfileaddr" (core/modules/net/include/net/state_offer.h) — and this module
 * is what the node does with them.
 *
 * The shape is a BOUNDED WAIT, not a stall. The node keeps doing the work it
 * would have done anyway (headers, from-genesis fold) from the first instant.
 * This module only decides whether a state source arrived in time to be worth
 * taking, and says so once, by name:
 *
 *   WAIT       nothing acceptable yet and the window is still open.
 *   FETCH      an acceptable offer was chosen; the caller fetches it through
 *              the UNCHANGED RMF path and installs it through the UNCHANGED
 *              install path. Nothing here relaxes either.
 *   FALL_BACK  the window closed with nothing acceptable. The caller raises
 *              bootstrap.stale_offers_only NAMING THE NEWEST HEIGHT IT SAW, so
 *              an operator learns "your peers are all stale, and this is how
 *              stale" rather than watching a silent genesis fold.
 *
 * PURE, AND DELIBERATELY CLOCKLESS. Every entry point takes monotonic
 * milliseconds from the caller. A test proves the 120-second bounded wait in
 * microseconds, and no wall clock, no timer thread and no sleep is involved in
 * a decision this node's whole first boot depends on.
 *
 * WHAT THE STORE NEVER DOES. It does not decide an offer is TRUE. Every offer
 * it holds has already been parsed under the codec's fail-closed rules and had
 * its signature verified; the only thing the store adds is preference (newest
 * first) and memory (a digest this node already fetched and rejected is not
 * chosen again). The content anchor stays where it has always been: the RMF
 * per-chunk digests, the whole-file SHA3, and the installer's checkpoint and
 * Sapling-root re-derivation. */

#ifndef ZCL_CONFIG_STATE_OFFER_STORE_H
#define ZCL_CONFIG_STATE_OFFER_STORE_H

#include "net/state_offer.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Offers retained across ALL peers. Four per peer is the wire cap; retaining
 * sixteen lets a handful of peers be heard without the newest offer being
 * evicted by a chatty one, and bounds what an unauthenticated handshake can
 * make this node remember. Static — never sized from a peer value. */
#define STATE_OFFER_STORE_MAX 16u

/* Content digests this node fetched and rejected. Same bound, same reason. */
#define STATE_OFFER_STORE_BAD_MAX 16u

/* ZRC-0011 phase 1a bounded wait, measured from the FIRST connected peer — not
 * from process start, because a node with no peers yet has nobody who could
 * have answered and starting the clock then would spend the window on the
 * dial. Two minutes: long enough for a handshake, an offer and a decision on a
 * slow link; short enough that a node with genuinely silent peers is folding
 * forward long before an operator would think to look. */
#define STATE_OFFER_WAIT_MS INT64_C(120000)

/* One retained offer plus the endpoint that would be dialled for it. The
 * endpoint comes from the LIVE CONNECTION and the message's own port field,
 * never from the offer — see net/state_offer.h. */
struct state_offer_record {
    struct state_offer_v1 offer;
    uint8_t peer_ip[16];
    uint16_t file_service_port;
    int64_t peer_id;
    int64_t heard_ms;
};

enum state_offer_decision {
    STATE_OFFER_DECIDE_WAIT = 0,
    STATE_OFFER_DECIDE_FETCH,
    STATE_OFFER_DECIDE_FALL_BACK,
};

/* Why an offer was not retained. Named so a status row can say which, and so a
 * test asserts the rule rather than "false". */
enum state_offer_store_result {
    STATE_OFFER_STORE_KEPT = 0,
    STATE_OFFER_STORE_KEPT_REPLACED, /* same digest heard again, endpoint refreshed */
    STATE_OFFER_STORE_DROPPED_INVALID,
    STATE_OFFER_STORE_DROPPED_UNSIGNED,
    STATE_OFFER_STORE_DROPPED_KIND,   /* not a consensus bundle */
    STATE_OFFER_STORE_DROPPED_BAD,    /* digest already fetched and rejected */
    STATE_OFFER_STORE_DROPPED_ENDPOINT, /* no dialable endpoint on this offer */
    STATE_OFFER_STORE_DROPPED_FULL,   /* table full and this is not newer */
};

const char *state_offer_store_result_string(enum state_offer_store_result r);
const char *state_offer_decision_string(enum state_offer_decision d);

/* Clear every offer, strike and clock. */
void state_offer_store_reset(void);

/* Arm the bounded wait. Called when the node's FIRST peer connects; later calls
 * are no-ops, so the window measures from the first peer and not the last. */
void state_offer_store_note_first_peer(int64_t now_ms);
bool state_offer_store_wait_armed(void);

/* Record one already-verified offer. Rejects by name; never allocates. */
enum state_offer_store_result state_offer_store_record(
    const struct state_offer_v1 *offer, const uint8_t peer_ip[16],
    uint16_t file_service_port, int64_t peer_id, int64_t now_ms);

/* Remember that this content digest was fetched and did NOT verify. The offer
 * is dropped, the digest is refused if re-offered, and the offering peer takes
 * a strike — a score against its own signing identity, never an address ban:
 * every inbound Tor-forwarded peer shares one loopback source address, so an
 * address ban for one bad bundle would close this node's whole inbound door
 * (core/modules/net/src/net.c:1866-1877). */
void state_offer_store_note_bad(const uint8_t content_digest[32],
                                int64_t peer_id);
bool state_offer_store_digest_is_bad(const uint8_t content_digest[32]);
uint32_t state_offer_store_peer_strikes(int64_t peer_id);

/* The decision. `out` is filled only for STATE_OFFER_DECIDE_FETCH. */
enum state_offer_decision state_offer_store_decide(
    int64_t now_ms, struct state_offer_record *out);

/* Mark the chosen offer as being acted on, so a second decide() does not hand
 * the same offer to a second fetch. Cleared by note_bad (try the next one). */
void state_offer_store_note_fetching(const uint8_t content_digest[32]);

/* The newest bundle height ANY peer offered this run, acceptable or not — the
 * number bootstrap.stale_offers_only must name. 0 when nothing was offered. */
int32_t state_offer_store_newest_height_seen(void);

/* One typed status snapshot: the row the sync/bootstrap status leaf prints. */
struct state_offer_store_status {
    bool wait_armed;
    int64_t wait_started_ms;
    uint32_t offers_seen;      /* verified offers this run, retained or not */
    uint32_t offers_retained;
    uint32_t offers_rejected;  /* fetched and failed verification */
    uint32_t peers_offering;
    int32_t newest_height_seen;
    int32_t chosen_height;     /* 0 when nothing chosen */
    uint8_t chosen_digest[32];
    uint64_t fetch_bytes_done;
    uint64_t fetch_bytes_total;
    uint32_t fetch_chunks_done;
    uint32_t fetch_chunks_total;
    enum state_offer_decision last_decision;
    /* Why the node stopped waiting, when it did. Empty while waiting. */
    char fallback_reason[128];
};
void state_offer_store_status_get(struct state_offer_store_status *out);

/* Record fetch progress for the status row. Bytes are what the RMF path has
 * durably landed, not what was requested. */
void state_offer_store_note_fetch_progress(uint32_t chunks_done,
                                           uint32_t chunks_total,
                                           uint64_t bytes_done,
                                           uint64_t bytes_total);

#endif /* ZCL_CONFIG_STATE_OFFER_STORE_H */
