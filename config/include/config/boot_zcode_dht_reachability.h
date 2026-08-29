/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Cached chain-bound ZENDP reachability for the ZCODE DHT adapter. */

#ifndef ZCL_CONFIG_BOOT_ZCODE_DHT_REACHABILITY_H
#define ZCL_CONFIG_BOOT_ZCODE_DHT_REACHABILITY_H

#include "vcs/zcode_dht_service.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct boot_svc_ctx;
struct json_value;
struct net_address;

enum boot_zcode_dht_direct_lookup {
    BOOT_ZCODE_DHT_DIRECT_FOUND = 0,
    BOOT_ZCODE_DHT_DIRECT_MISSING,
    BOOT_ZCODE_DHT_DIRECT_AMBIGUOUS,
};

/* Rebuilds only when the endpoint projection, ZID status generation, or
 * validated header tip changes. All ZENDP/ancestry work occurs in this call,
 * outside the global DHT mutex. */
bool boot_zcode_dht_reachability_refresh(
    const uint8_t network_genesis[32], struct vcs_zcode_dht_time now);

/* Service callback: fixed-memory lookup + bounded ID enqueue, followed by an
 * O(1) supervisor wake for the existing DHT-periodic owner. It never touches
 * ZENDP, the chain, addrman, connman, a database, or a socket. */
bool boot_zcode_dht_reachability_request(void *ctx,
                                         const uint8_t node_id[32],
                                         uint64_t wall_unix);

/* Resolve one chain-bound signed direct endpoint for an exact master key.
 * Address records remain untrusted route hints: callers must authenticate the
 * resulting Noise session and active delegation before sending private data. */
enum boot_zcode_dht_direct_lookup
boot_zcode_dht_reachability_direct_for_master(
    const uint8_t master_pubkey[32], struct net_address *out);

/* Clears cooldown for freshly authenticated peers, then resolves only IDs
 * requested by active lookups and submits them through the existing connman
 * dialer. Caller holds neither DHT nor reachability lock. */
void boot_zcode_dht_reachability_drive(
    struct boot_svc_ctx *svc, const struct vcs_zcode_dht_peer_view *peers,
    size_t peer_count, struct vcs_zcode_dht_time now);

void boot_zcode_dht_reachability_dump_json(struct json_value *out);
void boot_zcode_dht_reachability_reset(void);

#endif /* ZCL_CONFIG_BOOT_ZCODE_DHT_REACHABILITY_H */
