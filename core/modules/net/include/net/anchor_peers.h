/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Anchor peers — a small, integrity-checked snapshot of the node's currently
 * healthy outbound peer set, persisted to <datadir>/anchors.dat so the NEXT
 * boot can dial known-good suppliers FIRST, before falling back to the
 * addrman random walk / DNS + fixed seeds.
 *
 * Motivation (Bitcoin Core's anchor.dat, adapted): addrman is a large, mostly
 * cold table learned by gossip; picking outbound peers from it at boot is a
 * random walk that can spend many seconds landing on dead/saturated hosts
 * before it finds a live block-serving peer. But the peers we were connected
 * to moments before a clean shutdown (or the last periodic flush) are, with
 * high probability, still up and still willing. Re-dialing THEM first
 * collapses the worst-case time-to-first-peer at boot and hardens against
 * eclipse (an attacker who floods addrman still cannot displace the anchors
 * we already trust).
 *
 * On-disk format mirrors peers.dat exactly (net/addrman_integrity.c): a body
 * file (anchors.dat) plus a 48-byte SHA3-256 sidecar (anchors.dat.sha3) via
 * the shared storage/sha3_sidecar_io machinery. A corrupt or size-drifted
 * body is quarantined (renamed aside) and the node starts with an EMPTY
 * anchor set — a bad anchors file must NEVER block boot or steer outbound
 * selection toward attacker-chosen hosts.
 */

#ifndef ZCL_NET_ANCHOR_PEERS_H
#define ZCL_NET_ANCHOR_PEERS_H

#include "net/netaddr.h"
#include "util/result.h"

#include <stddef.h>
#include <stdint.h>

/* Cap on persisted anchors. Matches MAX_OUTBOUND_CONNECTIONS (net.h): we only
 * ever have that many outbound slots, so persisting more would be dead weight.
 * Kept as its own name so the file format is self-describing. */
#define ANCHOR_PEERS_MAX 8

/* One persisted anchor: enough to redial the peer and prioritise it. */
struct anchor_peer {
    struct net_addr addr;         /* IPv4-mapped / IPv6 / onion v3 */
    uint16_t        port;
    uint64_t        services;     /* advertised service bits (NODE_NETWORK …) */
    int32_t         last_height;  /* peer's starting_height when last seen */
    int64_t         last_success; /* unix seconds of last known-good contact */
};

struct anchor_peer_set {
    struct anchor_peer peers[ANCHOR_PEERS_MAX];
    size_t             count;
};

enum anchor_load_status {
    ANCHOR_LOAD_OK = 0,       /* body verified + deserialized (count may be 0) */
    ANCHOR_LOAD_EMPTY,        /* no anchors file / no sidecar — normal first run */
    ANCHOR_LOAD_QUARANTINED,  /* corrupt/tampered body — renamed aside, set empty */
};

/* Serialize `set` and write <datadir>/anchors.dat + its SHA3 sidecar
 * atomically (tmp → fsync → rename, then sidecar), same shape as
 * connman_save_addrman's peers.dat write. Writing an empty set is valid (it
 * records "no anchors" and refreshes the sidecar). Best-effort: returns a
 * non-ok zcl_result on any I/O error, which the caller logs but never treats
 * as fatal. NULL/oversized inputs return a non-ok result without touching
 * disk. */
struct zcl_result anchor_peers_save(const char *datadir,
                                    const struct anchor_peer_set *set);

/* Verify + load <datadir>/anchors.dat into *out (always initialised to
 * count=0 first). Missing body/sidecar → ANCHOR_LOAD_EMPTY. A hash mismatch,
 * size drift, bad magic, or unsupported version quarantines both files and
 * returns ANCHOR_LOAD_QUARANTINED with *out empty. Never fails hard, never
 * blocks boot. */
enum anchor_load_status anchor_peers_load(const char *datadir,
                                          struct anchor_peer_set *out);

/* Human-readable name for a load status (logging/tests). */
const char *anchor_load_status_name(enum anchor_load_status s);

#endif /* ZCL_NET_ANCHOR_PEERS_H */
