/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Typed peer-offence scoring on top of peer_misbehaving().
 *
 * The legacy peer_misbehaving(mgr, node, howmuch, reason) interface in net.c
 * takes an ad-hoc integer and a free-form string. It auto-bans at a hardcoded
 * score of 100 and refuses to penalise localhost / whitelisted peers via
 * is_trusted_peer(). Every rejected-message path in msgprocessor.c has its
 * own magic number sprinkled through it.
 *
 * This header adds a thin classification layer on top:
 *
 *   - enum peer_offence assigns canonical weights to the common rejection
 *     categories, so call-sites pick a name instead of a number and the
 *     weights stay consistent across the codebase.
 *
 *   - peer_scoring_init() reads ban threshold / ban duration / decay rate
 *     from environment variables at boot. peer_misbehaving() then honours
 *     whatever is configured (default 100 / 24h / 1 point per minute) so
 *     operators can tune aggressiveness without a rebuild.
 *
 *   - peer_scoring_record() forwards a typed offence to peer_misbehaving()
 *     with the enum's value as the weight, preserving the existing
 *     is_trusted_peer() guard, auto-ban-at-threshold, and EV_PEER_MISBEHAVE
 *     / EV_PEER_BANNED events.
 *
 *   - peer_scoring_on_good_interaction() applies linear decay on good
 *     behaviour and is safe to call from hot receive paths. Decay rate is
 *     operator-configurable; default is 1 point per minute since the last
 *     good interaction.
 *
 *   - peer_scoring_reset() zeroes the score outright after an
 *     unambiguously-valid message.
 *
 *   - peer_scoring_should_ban() is a pure query (score >= threshold) for
 *     call-sites that want to check without mutating state — e.g. the
 *     connman accept-inbound path, which already goes through is_banned()
 *     for the address-level check but still wants to reject the connection
 *     if a live peer on the same node handle has already crossed the line.
 *
 * This file must NOT pull in net.h (forward-declare struct p2p_node and
 * struct net_manager) so that controllers and tools can include it without
 * dragging the whole network stack.
 */

#ifndef ZCL_NET_PEER_SCORING_H
#define ZCL_NET_PEER_SCORING_H

#include <stdbool.h>
#include <stdint.h>

struct net_manager;
struct p2p_node;

/* Canonical offence categories. Identities are sequential — the score
 * increment lives in peer_offence_weight(), NOT in the enum value, so
 * several distinctly-named offences can share a weight without the name
 * lookup lying about the category. The weights are a DoS-policy surface:
 * changing one changes ban behaviour — don't touch them casually. */
enum peer_offence {
    PEER_OFFENCE_NONE = 0,
    PEER_OFFENCE_TIMEOUT,            /*   5 — request timed out waiting for reply */
    PEER_OFFENCE_INVALID_MESSAGE,    /*  10 — malformed / undeserialisable / out-of-range request */
    PEER_OFFENCE_UNREQUESTED,        /*  10 — sent data we never asked for */
    PEER_OFFENCE_OFFER_REJECTED,     /*  10 — offer doesn't meet local requirements (not provably malicious) */
    PEER_OFFENCE_FLOOD,              /*  20 — spamming inv / headers / tx / proof requests */
    PEER_OFFENCE_INVALID_PAYLOAD,    /*  20 — envelope ok, payload truncated / out-of-spec (snapshot offers, manifests, chunk transport, compact blocks) */
    PEER_OFFENCE_INVALID_HEADER,     /*  50 — bad header (PoW / merkle / timestamp) */
    PEER_OFFENCE_INVALID_CHUNK,      /*  50 — swarm chunk/piece hash mismatch vs manifest */
    PEER_OFFENCE_INVALID_BLOCK,      /* 100 — full block failed consensus */
    PEER_OFFENCE_INVALID_PROOF,      /* 100 — cryptographic verification failed (SHA3 snapshot, FlyClient, merkle root) */
    PEER_OFFENCE_PROTOCOL_VIOLATION, /* 100 — deliberate protocol abuse (disabled feature, impossible request) */
    PEER_OFFENCE_COUNT_              /* sentinel — keep last */
};

/* Score increment for an offence. This is the SAME weight table the raw
 * peer_misbehaving() sites used before typed adoption — byte-identical
 * ban behaviour. Returns 0 for NONE/unknown. */
int peer_offence_weight(enum peer_offence offence);

/* Read configuration from environment. Safe to call multiple times (later
 * calls update the cached values). Called once from init.c at boot but
 * tests call it repeatedly to exercise env-var handling.
 *
 * Environment variables:
 *   ZCL_PEER_BAN_THRESHOLD      — integer, default 100
 *   ZCL_PEER_BAN_HOURS          — integer, default 24
 *   ZCL_PEER_SCORE_DECAY_PER_MIN — integer, default 1 (0 disables decay)
 *   ZCL_PEER_MAX_INBOUND_PER_IP — integer, default 3
 *   ZCL_NET_LOOPBACK_INBOUND_MAX — integer, default 24 (0 = no loopback
 *                                  exemption at all)
 *   ZCL_PEER_LAST_PEER_BAN_SECS — integer, default 600 */
void peer_scoring_init(void);

/* Accessors for the cached config. All thread-safe (atomic reads). */
int peer_scoring_ban_threshold(void);
int peer_scoring_ban_hours(void);
int peer_scoring_decay_rate(void);

/* Max simultaneous INBOUND connections admitted from one source IP.
 * Enforced in accept_connection() (net.c) as sybil defence: one IP must
 * not be able to consume every inbound slot.
 *
 * It is a source-IP heuristic, not an identity check — at accept() time
 * there is no peer identity yet, so several legitimate nodes behind one
 * NAT (or co-located on one host) share a single budget. Past the cap the
 * server closes the socket before any bytes are exchanged, which the
 * dialling node can only observe as "remote-close, state=connecting". The
 * knob exists so an operator serving such a source can raise it instead of
 * having to patch a literal. Default 3, clamped to [1, 4096]. */
int peer_scoring_max_inbound_per_ip(void);

/* Aggregate ceiling on inbound slots held by LOOPBACK sources at once,
 * given this node's total inbound capacity `max_inbound` (125 total minus
 * 8 reserved outbound = 117 on stock settings).
 *
 * Loopback needs a raised per-source cap so several nodes on one host can
 * peer with each other, but a per-source number alone bounds nothing:
 * 127.0.0.0/8 is 16.7M distinct 16-byte keys, so an unprivileged local
 * process can dial from a fresh source address every time. This function
 * is the real bound, and it is enforced across ALL loopback sources
 * together.
 *
 * Value = min(ZCL_NET_LOOPBACK_INBOUND_MAX, max_inbound - 3*max_inbound/4).
 * Default 24. The second term is a HARD FLOOR that no environment setting
 * can raise past: at least three quarters of inbound capacity always stays
 * available to non-loopback peers, so a local flood can never win the
 * post-restart race for every slot. On stock settings that is 24 of 117
 * for loopback and >= 93 of 117 permanently reserved for everyone else.
 *
 * Setting ZCL_NET_LOOPBACK_INBOUND_MAX=0 restores the pre-exemption
 * behaviour exactly: loopback then gets no raised cap at all and is
 * admitted under the ordinary peer_scoring_max_inbound_per_ip() budget.
 * Range [0, 4096] before clamping; a non-positive `max_inbound` yields 0. */
int peer_scoring_max_inbound_loopback(int max_inbound);

/* Ban duration, in seconds, substituted for the full peer_scoring_ban_hours()
 * when banning a peer would leave the node with no connected peer at all.
 * The peer is still scored and still disconnected — only the ban's LENGTH is
 * bounded, so a single misclassification cannot strand a node that has
 * exactly one peer for peer_scoring_ban_hours(). Default 600, clamped to
 * [60, 86400]; the ceiling means this can never be harsher than the
 * ordinary path. See peer_misbehaving() in net.c. */
int peer_scoring_last_peer_ban_secs(void);

/* Typed blocker raised by peer_misbehaving() when it takes the bounded
 * last-peer path, so a node that just banned its only route to the network
 * says so instead of looking idle. Cleared by
 * peer_lifecycle_note_handshake_complete() — the single choke point every
 * completed handshake passes through — because a completed handshake IS the
 * honest witness that the route is back. Remedy binding:
 * engine/conditions/include/conditions/blocker_remedy_bindings.def. */
#define PEER_LAST_PEER_BAN_BLOCKER_ID "net.last_peer_ban"

/* Record a typed offence. Equivalent to
 *   peer_misbehaving(nm, node, peer_offence_weight(offence), context)
 * but rejects PEER_OFFENCE_NONE (no-op) and emits a richer log line.
 *
 * The underlying peer_misbehaving() call:
 *   - Silently returns if is_trusted_peer(node) — localhost/whitelisted.
 *   - Emits EV_PEER_MISBEHAVE with the new total.
 *   - Auto-bans at peer_scoring_ban_threshold() and emits EV_PEER_BANNED.
 *   - Sets node->disconnect so the send loop drops the connection. */
void peer_scoring_record(struct net_manager *nm, struct p2p_node *node,
                         enum peer_offence offence, const char *context);

/* Pure query: has this peer's score crossed the configured ban threshold?
 * Does NOT apply decay and does NOT mutate node state. */
bool peer_scoring_should_ban(const struct p2p_node *node);

/* Apply linear decay to the node's misbehavior score. Computes
 *   decay = decay_rate * (minutes since last_good_ms)
 * and subtracts it from the current score (clamped at 0). Updates
 * last_good_ms to now_ms. Safe on trusted peers (returns score unchanged).
 *
 * Returns the post-decay score. */
int peer_scoring_decay(struct p2p_node *node, int64_t now_ms);

/* Record a successful interaction. Applies decay then updates
 * last_good_ms. This is the "breathing room" hook — call it on any
 * accepted message so a peer that mostly behaves can work off a handful
 * of earlier mistakes. */
void peer_scoring_on_good_interaction(struct p2p_node *node, int64_t now_ms);

/* Zero the score outright. Use after an unambiguously-valid message
 * (e.g. verack, a block that connected). */
void peer_scoring_reset(struct p2p_node *node);

/* Human-readable name for an offence — for logs and events. Identities
 * are unique (weights live in peer_offence_weight()), so every offence
 * gets its own honest name. */
const char *peer_offence_name(enum peer_offence offence);

/* Convenience: milliseconds since the UNIX epoch for decay math.
 * Exposed so tests can monkey-patch by calling with an explicit value. */
int64_t peer_scoring_now_ms(void);

#endif /* ZCL_NET_PEER_SCORING_H */
