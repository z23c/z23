/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: The in-node core of `fleet bundle offer` and `fleet bundle fetch`
 *          — hand one bounded file (a git bundle, 1 B to 5 MiB) to another
 *          Z23 node over the package swarm, with a sha256 the receiver
 *          recomputes. The handlers (native_fleet_bundle_command.c) call
 *          these against the resident store and engine; the tests drive them
 *          against two in-process engines. Nothing here executes the bytes. */

#ifndef ZCL_NATIVE_FLEET_BUNDLE_H
#define ZCL_NATIVE_FLEET_BUNDLE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct vcs_package_store;
struct vcs_swarm_engine;

enum zcl_fleet_bundle_status {
    ZCL_FLEET_BUNDLE_DONE = 0, /* offered / written */
    ZCL_FLEET_BUNDLE_PENDING,  /* fetch started, chunks still arriving */
    ZCL_FLEET_BUNDLE_REFUSED,  /* code + message name the rule */
};

struct zcl_fleet_bundle_outcome {
    enum zcl_fleet_bundle_status status;
    char code[40];     /* REFUSED: the closed refusal code */
    char message[240]; /* REFUSED: the explanation */
    bool retryable;
    bool mutated;
    uint8_t root[32];
    uint8_t sha256[32];
    uint64_t size;
    size_t announced;        /* offer: ANNOUNCE frames queued */
    uint32_t present_chunks; /* fetch PENDING: progress */
    uint32_t total_chunks;
};

/* Put `path` (absolute, regular, 1 B..5 MiB) into `store` pinned and never
 * evicting, and queue its ANNOUNCE on `engine` (NULL: no announce). */
enum zcl_fleet_bundle_status zcl_fleet_bundle_offer(
    struct vcs_package_store *store, struct vcs_swarm_engine *engine,
    const char *path, struct zcl_fleet_bundle_outcome *out);

struct zcl_fleet_bundle_fetch_args {
    uint8_t root[32];
    uint8_t sha256[32];
    uint64_t size;
    const char *out_path; /* absolute; must not exist */
    int64_t day;
    uint64_t now;
};

/* One non-blocking fetch step: start (idempotent) or continue the swarm
 * download of `root`; once complete, check the shape and size, recompute
 * sha256, and only on a match create out_path (0600, exclusive). A mismatch
 * writes nothing. */
enum zcl_fleet_bundle_status zcl_fleet_bundle_fetch_step(
    struct vcs_package_store *store, struct vcs_swarm_engine *engine,
    const struct zcl_fleet_bundle_fetch_args *args,
    struct zcl_fleet_bundle_outcome *out);

/* A v3 onion endpoint only: 56 base32 characters + ".onion" with an
 * optional ":port". An IP literal or a clearnet name is false. */
bool zcl_fleet_bundle_peer_is_onion(const char *peer);

/* What the node's getpeerinfo says about the named onion after a fetch
 * timed out. UNKNOWN means the peer list could not be read: never a claim. */
enum zcl_fleet_bundle_peer_state {
    ZCL_FLEET_PEER_UNKNOWN = 0,
    ZCL_FLEET_PEER_ABSENT,    /* read; the named onion is not connected */
    ZCL_FLEET_PEER_CONNECTED, /* read; a connected addr names the onion */
};

/* True when a getpeerinfo `addr` names the onion host of `peer` (a ":port"
 * on either side is ignored). False unless `peer` is a v3 onion name. */
bool zcl_fleet_bundle_addr_is_peer(const char *peer, const char *addr);

/* The FETCH_TIMEOUT message into `out` (cap bytes). peer NULL gives the
 * no-peer text; otherwise the text names the peer by state. False when the
 * message does not fit or an argument is missing. */
bool zcl_fleet_bundle_timeout_message(char *out, size_t cap, const char *peer,
                                      enum zcl_fleet_bundle_peer_state state,
                                      const char *root);

#endif /* ZCL_NATIVE_FLEET_BUNDLE_H */
