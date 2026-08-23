/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

/* Internal header shared between connman.c and connman_dialer.c.
 * NOT part of the public API — only included by those two files.
 *
 * The split is by responsibility:
 *   connman.c        — lifecycle (init/start/stop/join/free), addrman
 *                       persistence, seed discovery, outbound-target
 *                       selection + diversity-cap accounting, the
 *                       socket reactor thread, the message-cycle thread,
 *                       and the public stats/health accessors.
 *   connman_dialer.c  — the parallel batch dialer: anchors-first
 *                       candidate gathering, feeler probes, and the
 *                       thread_open_connections loop that drives them.
 *
 * Everything declared here used to be `static` in connman.c; it is
 * promoted to external linkage (single definition, still in whichever
 * file owns it) purely so the other file can call it — no behavior
 * changed by the split. */

#ifndef ZCL_NET_CONNMAN_INTERNAL_H
#define ZCL_NET_CONNMAN_INTERNAL_H

#include "net/connman.h"
#include "util/thread_liveness.h"
#include <stdbool.h>
#include <stdint.h>
#include <stdatomic.h>

/* Shared P2P-thread shutdown flag. Set false at connman_start(), true by
 * connman_signal_stop(); every long-running loop in both files polls it. */
extern _Atomic bool g_stop;

/* -connect mode: only connect to specified peers, no seeds. Defined
 * (non-static) in connman.c; declared here for connman_dialer.c. */
extern bool g_connect_only;

/* Supervisor liveness for the outbound-dialer thread. Registered/retired
 * from connman_start()/connman_join() in connman.c; beaten from
 * thread_open_connections() in connman_dialer.c. Defined in
 * connman_dialer.c (the thread that owns its progress marker). */
extern struct thread_liveness_child g_open_liveness;

/* ── Sybil diversity: IPv4 /16, IPv6 /32, and onion outbound caps ────
 *
 * count_outbound_in_group() only ever inspects IPv4-mapped peers — a real
 * IPv6 or .onion outbound peer was invisible to the /16 diversity cap
 * entirely, so an attacker with many distinct IPv6 addresses or (far
 * cheaper) many distinct ephemeral .onion identities could fill every
 * outbound slot with sock-puppets and eclipse the node, bypassing
 * MAX_OUTBOUND_PER_GROUP16 completely.
 *
 * IPv6: group by the /32 prefix (first 4 bytes of the real, non-mapped
 * 16-byte address — net_addr_is_ipv6() already excludes the IPv4-mapped
 * ::ffff:a.b.c.d form). /32 is a coarser allocation unit than IPv4's /16
 * convention but mirrors it: cheap for an attacker to acquire ONE real
 * /32, expensive to acquire MANY.
 *
 * Onion: a v3 onion address is a self-generated Ed25519 public key —
 * free and unlimited to mint, with no ISP/RIR allocation cost at all.
 * There is no "group" to diversify within; the only meaningful bound is
 * a flat cap on TOTAL outbound onion connections. MAX_OUTBOUND_ONION=3 is
 * enough for every remote edge in a four-node operator mesh while still
 * reserving a majority (5 of the default 8 slots) for non-onion network
 * diversity. A wall of attacker-minted .onion identities therefore still
 * cannot consume the whole outbound set.
 *
 * connman_kick_onion_seeds() / run_onion_seed_pass() is UNAFFECTED by
 * this cap: it fetches /directory.json directly over Tor via
 * tor_integration_fetch_onion_blocking() to discover CLEARNET peers —
 * it never dials an outbound P2P connection through
 * connman_pick_next_outbound_target(), so eclipse-recovery via onion
 * seeds still works even when the onion outbound bucket is full. */
#define MAX_OUTBOUND_PER_GROUP16 2
#define MAX_OUTBOUND_IPV6_GROUP32 2
#define MAX_OUTBOUND_ONION 3

/* Extract /16 subnet group from IPv4-mapped address (bytes 12-13). */
uint16_t ipv4_group16(const unsigned char ip[16]);

/* Extract IPv6 /32 group from a genuine (non-IPv4-mapped) address. */
uint32_t ipv6_group32(const unsigned char ip[16]);

/* Count outbound peers in the same IPv4 /16 / IPv6 /32 / onion bucket. */
int connman_outbound_group_count(struct connman *cm, uint16_t group);
int connman_outbound_ipv6_group_count(struct connman *cm, uint32_t group);
int connman_outbound_onion_count(struct connman *cm);

/* True if `addr` is already connected (any matching node, any state,
 * conflicting-port rules per connman_node_conflicts_with_target). */
bool connman_addr_is_connected(struct connman *cm,
                               const struct net_address *addr);

/* Shared failure-aware addrman policy. Discovered ZCL23 endpoints must pass
 * this same durable cooldown/diversity gate instead of owning a retry loop. */
int connman_addrman_retry_cooldown_for_attempts(int attempts);
bool connman_addrman_candidate_usable(struct connman *cm,
                                      const struct addr_info *info);

bool connman_gather_known_zcl23_candidate(
    struct connman *cm, const struct net_service *batch_services,
    size_t batch_count, struct connman_dial_candidate *out);

/* Release the +1 caller-owned ref that connect_node/connect_node_from_socket
 * ALWAYS return. See the definition in connman.c for the full ref-lifecycle
 * contract. */
void connman_release_connect_node_ref(struct connman *cm,
                                      struct p2p_node *node);

/* The outbound-dialer thread body (connman_dialer.c). Spawned from
 * connman_start() in connman.c. */
void *thread_open_connections(void *arg);

#endif /* ZCL_NET_CONNMAN_INTERNAL_H */
