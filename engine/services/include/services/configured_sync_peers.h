/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: the peers this node's operator explicitly named as connection
 * targets, the Noise identity this node itself authenticated at each of
 * those addresses, and the one rule that lets an inbound session proven to
 * carry that identity serve headers.
 *
 * WHY THIS EXISTS. Two routable nodes told to addnode each other end up with
 * one TCP connection: the sealed connection manager keeps the session dialed
 * by the lower Noise static key and evicts the other
 * (core/modules/net/src/connman_zcl23_dial.c, called from msg_version.c at
 * the inbound VERSION and the outbound VERACK). The node left holding only
 * the other's inbound connection never began header sync, because an inbound
 * peer may not become a header source (anti-eclipse), and FINDING_PEERS has
 * no edge to AT_TIP. It stayed out of sync forever.
 *
 * WHAT IS PROVEN, NOT CLAIMED. Neither the TCP source IP nor anything the
 * peer says (VERSION addr_from, gossip) authorizes anything here: several
 * machines can share one NAT address. The binding is cryptographic:
 *   1. The operator names a target address (-addnode=, -connect=,
 *      -addnode-file=, or the authenticated `addnode add|onetry` RPC).
 *   2. THIS node dials that exact address and completes a Noise XX handshake
 *      as initiator. XX message 2 carries the responder's static key under
 *      the ee and es keys, so completing it proves the host answering at the
 *      configured address holds that static private key. That is the
 *      target's authenticated identity. It is learned either from an
 *      ordinary outbound session to the target that reaches PEER_ACTIVE, or
 *      from a dedicated identity probe (configured_sync_peers.c) that
 *      completes the same handshake and closes before VERSION, so the sealed
 *      eviction never sees it.
 *   3. An inbound session qualifies only when its OWN Noise session is
 *      established and the static key it authenticated (XX message 3) equals
 *      the identity learned in step 2 for a target at the same IP. Nothing
 *      is cached per inbound session or per IP: every new session is checked
 *      against its own handshake, so a reconnect proves the binding again.
 *
 * WHY THIS IS SECURITY-EQUIVALENT TO THE OUTBOUND DIAL. An outbound sync
 * source is whoever holds the static key that answered at the configured
 * address. An admitted inbound session is authenticated as that same key.
 * A same-NAT neighbour, a spoofed addr_from or a replayed session cannot
 * produce it. Plaintext inbound sessions, Tor/loopback sources (every Tor
 * hidden-service stream arrives from 127.0.0.1) and addresses learned from
 * DHT hints, gossip, seeds, anchors or onion directory walks never qualify.
 * The rule only chooses which peer may be ASKED for headers; header and
 * block validation, download windows, per-peer limits and misbehaviour
 * scoring are the ones every peer gets, and the peer must also be
 * PEER_ACTIVE, the same handshake state an outbound peer needs. */

#ifndef ZCL_SERVICES_CONFIGURED_SYNC_PEERS_H
#define ZCL_SERVICES_CONFIGURED_SYNC_PEERS_H

#include "net/net.h"
#include "net/netaddr.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* A full table refuses the new entry (the dial still happens; only the
 * inbound header exemption is withheld). */
#define CONFIGURED_SYNC_PEERS_MAX 64

/* Minimum spacing between two identity probes of one target, so inbound
 * sessions with a wrong key cannot turn into a probe flood. */
#define CONFIGURED_SYNC_PEER_PROBE_RETRY_SECS 30

/* One identity probe of one target ends within this many milliseconds,
 * however slowly the target answers. */
#define CONFIGURED_SYNC_PEER_PROBE_DEADLINE_MS 10000

/* Record an operator-named target. Returns true when it is recorded (or was
 * already present), false for NULL, an address that can never authenticate
 * an inbound source (Tor, loopback, unspecified), or a full table. */
bool configured_sync_peer_note(const struct net_service *target);

/* Forget one operator-named target (`addnode remove`), with its identity. */
bool configured_sync_peer_forget(const struct net_service *target);

/* Record the identity this node authenticated on its OWN outbound
 * connection to the exact configured address `target`. */
void configured_sync_peer_record_identity(const struct net_service *target,
                                          const uint8_t remote_static[32]);

/* Learn the identity from an outbound session to an exact configured target
 * whose Noise handshake is established. No-op for anything else. */
void configured_sync_peer_observe_outbound(const struct p2p_node *node);

/* Copy the identity recorded for `target`. False when none is recorded. */
bool configured_sync_peer_identity(const struct net_service *target,
                                   uint8_t out_static[32]);

/* An identity prober: dial `target`, complete Noise XX as initiator and
 * return the responder's authenticated static key. The network prober runs
 * on one bounded probe thread at a time, with a copy of the local static key;
 * a test replaces it with configured_sync_peers_set_prober_for_testing. */
typedef bool (*configured_sync_peer_prober_fn)(const struct net_service *target,
                                               uint8_t out_static[32]);

/* Start the runtime probe service with the local Noise identity and network
 * magic. This is the inverse of configured_sync_peers_stop(): after an
 * in-process service restart it clears the prior stop request before new
 * probes are admitted. */
void configured_sync_peers_start(const struct net_manager *nm);

/* The local Noise identity and network magic the default prober uses. The
 * first operator-named target (-addnode/-connect/-addnode-file or the
 * addnode RPC) attaches the node's net manager; without it (or with Noise
 * off) no probe runs and no inbound session can be bound. */
void configured_sync_peers_attach_network(const struct net_manager *nm);

/* An inbound session from a target's IP that did not bind: schedule one
 * identity probe of each such target unless one is running or the last one
 * finished less than CONFIGURED_SYNC_PEER_PROBE_RETRY_SECS ago. Returns the
 * number of probes scheduled. */
size_t configured_sync_peer_request_probe(const struct p2p_node *inbound);

/* Per-tick hook from the header-sync entry point: learn the identity from
 * an outbound session to a target, or schedule a probe for an inbound
 * session from a target's IP that has not bound. */
void configured_sync_peer_observe_session(const struct p2p_node *node);

/* Stop probing: refuse new probes, end a running one within one wait slice,
 * join its thread and detach the net manager. Registered as the runtime
 * service stop (boot_runtime_sync_services.c). */
void configured_sync_peers_stop(void);

/* True once stop or process shutdown was requested. A prober checks it
 * between waits. */
bool configured_sync_peers_probe_should_stop(void);

/* Test seams. A test prober runs synchronously inside the request; a
 * threaded test prober runs on the real probe thread instead of the socket
 * prober. The test clocks replace the monotonic clock for the retry spacing
 * (seconds) and the probe deadline (milliseconds). Pass NULL to restore the
 * defaults. Reset stops and joins any probe, then clears the stop request. */
void configured_sync_peers_set_prober_for_testing(
    configured_sync_peer_prober_fn prober);
void configured_sync_peers_set_threaded_prober_for_testing(
    configured_sync_peer_prober_fn prober);
void configured_sync_peers_set_clock_for_testing(int64_t (*now_seconds)(void));
void configured_sync_peers_set_probe_clock_ms_for_testing(
    int64_t (*now_ms)(void));
/* Join the probe thread if one was spawned; true when it joined one. */
bool configured_sync_peers_join_probe_for_testing(void);
void configured_sync_peers_reset_for_testing(void);
/* The network prober's socket path against any address, loopback included,
 * so a harness listener can prove the dial, handshake and timeouts. */
bool configured_sync_peer_probe_socket_for_testing(
    const struct net_service *target, const uint8_t identity_priv[32],
    const unsigned char magic[4], uint8_t out_static[32]);

/* The inbound half of the rule above. False for outbound peers. */
bool syncsvc_peer_is_configured_inbound(const struct p2p_node *node);

/* An outbound peer, or an inbound peer that satisfies the rule above. */
bool syncsvc_peer_may_serve_headers(const struct p2p_node *node);

/* Body discipline parity. The sealed core applies Rule C (header-only peer
 * that never returns bodies) and Rule D (delivered-then-dark peer) only to
 * outbound peers (msgprocessor.c `!node->inbound`). The stale-header
 * predicate is the one stall predicate the core evaluates for inbound peers
 * too, under the same swarm/trusted-peer gates, so it applies Rules C and D
 * to a configured inbound sync peer through this function: the same
 * engine-owned predicates on the same download-manager evidence. */
bool syncsvc_configured_inbound_body_stalled(const struct p2p_node *node,
                                             int our_height,
                                             uint64_t body_received,
                                             uint64_t body_timed_out,
                                             uint64_t dark_received,
                                             uint64_t dark_timed_out,
                                             int64_t last_body_time,
                                             int64_t now_seconds);

#endif
