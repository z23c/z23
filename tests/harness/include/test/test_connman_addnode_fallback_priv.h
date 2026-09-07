/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Private facet shared by the connman addnode-fallback test scenario
 * check files (test_connman_addnode_fallback.c and its
 * test_connman_addnode_*.c siblings). No sibling declares its own
 * file-scope mutable state; the fixture helpers below are pure
 * functions operating on the caller's struct connman, and the ones a
 * single scenario needs stay private to that scenario's own file. */

#ifndef TEST_CONNMAN_ADDNODE_FALLBACK_PRIV_H
#define TEST_CONNMAN_ADDNODE_FALLBACK_PRIV_H

#include <stdbool.h>
#include <stdint.h>
#include "net/connman.h"

/* Shared fixture helpers, defined in test_connman_addnode_fallback.c
 * and used by scenarios across more than one sibling file. */
void test_set_ipv4(struct net_address *addr,
                   uint8_t a, uint8_t b, uint8_t c, uint8_t d,
                   uint16_t port);
struct p2p_node *add_test_peer(struct connman *cm,
                               uint8_t a, uint8_t b,
                               uint8_t c, uint8_t d,
                               enum peer_state state,
                               bool inbound,
                               bool disconnect);
bool test_addrman_set_fail(struct connman *cm, uint8_t first_octet,
                           int attempts, int64_t last_try);

/* Scenario checks — test_connman_addnode_fallback.c's entry point calls
 * every one of these in order; each lives in the sibling file its
 * scenario names. */

/* test_connman_addnode_dial_fallback.c — DHT-hint/loopback/onion-redial
 * dial fallback, zcl23 peer-source backoff ownership, addnodes-before-
 * addrman drain, remove/compact state, outbound health diversity, and
 * the addrman peer floor across cold start, height, and subnets. */
int check_connman_addnode_dht_hint_priority_dial(void);
int check_connman_addnode_loopback_edges_distinct(void);
int check_connman_addnode_custom_port_onion_redial(void);
int check_connman_addnode_zcl23_backoff_ownership(void);
int check_connman_addnode_addnodes_drain_before_addrman(void);
int check_connman_addnode_remove_compacts_state(void);
int check_connman_addnode_outbound_health_diversity(void);
int check_connman_addnode_non_network_not_floor(void);
int check_connman_addnode_cold_start_discovery_floor(void);
int check_connman_addnode_max_height_ignores_unusable(void);
int check_connman_addnode_peer_floor_diverse_subnets(void);
int check_connman_addnode_addrman_skips_saturated(void);
int check_connman_addnode_inbound_ephemeral_not_block(void);

/* test_connman_addnode_protocol_backoff.c — pre/post-handshake protocol
 * backoff, addrman-failure cooldown, failure-aware distinct batches, the
 * onion-seed last resort, IPv6/onion diversity caps, non-blocking onion
 * queues, and the reactor's cap/exhaustion gating. */
int check_connman_addnode_prehandshake_protocol_backoff(void);
int check_connman_addnode_protocol_backoff_gt_tcp(void);
int check_connman_addnode_addrman_failures_cool_down(void);
int check_connman_addnode_failure_aware_distinct_batch(void);
int check_connman_addnode_onion_seed_last_resort(void);
int check_connman_addnode_ipv6_onion_diversity_caps(void);
int check_connman_addnode_onion_queues_no_blocking(void);
int check_connman_addnode_reactor_clamps_over_cap(void);
int check_connman_addnode_reactor_passthrough_in_cap(void);
int check_connman_addnode_reactor_refuses_exhausted(void);
int check_connman_addnode_reactor_passes_default(void);

/* test_connman_addnode_retire_and_inbound.c — retire-threshold gating
 * and revival, census harvest into addrman, fixed-seed onion no-ops,
 * relay-block handshake gating, noise capability upgrade, and inbound
 * eviction/serial-dial policy. */
int check_connman_addnode_retire_both_thresholds(void);
int check_connman_addnode_retire_needs_both_gates(void);
int check_connman_addnode_retire_suppressed_below_floor(void);
int check_connman_addnode_retire_revive_on_success(void);
int check_connman_addnode_retire_revive_on_readd(void);
int check_connman_addnode_census_harvest_to_addrman(void);
int check_connman_addnode_fixed_seeds_onion_noop(void);
int check_connman_addnode_relay_block_handshaked_only(void);
int check_connman_addnode_noise_capability_upgrade(void);
int check_connman_addnode_evict_inbound_when_outbound(void);
int check_connman_addnode_inbound_only_same_ip_stays(void);
int check_connman_addnode_operator_local_sockets_stay(void);
int check_connman_addnode_feeler_does_not_evict(void);
int check_connman_addnode_unreserved_dial_serial(void);

#endif
