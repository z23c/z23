/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Bounded identity-pinned direct route acquisition for paired peers. */
#ifndef ZCL_CONFIG_BOOT_MESH_ROUTE_H
#define ZCL_CONFIG_BOOT_MESH_ROUTE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct boot_svc_ctx;
struct connman;
struct db_mesh_pairing;
struct net_address;
struct noise_transport_snapshot;
struct p2p_node;

#define BOOT_MESH_ROUTE_MAX 8u
#define BOOT_MESH_ROUTE_MAX_ATTEMPTS 3u
#define BOOT_MESH_ROUTE_LIFETIME_MS UINT64_C(15000)
#define BOOT_MESH_ROUTE_TERMINAL_RETENTION_MS UINT64_C(30000)

enum boot_mesh_route_result {
    BOOT_MESH_ROUTE_ACQUIRED = 0,
    BOOT_MESH_ROUTE_PENDING,
    BOOT_MESH_ROUTE_RESOURCE_DEFERRED,
    BOOT_MESH_ROUTE_NO_ENDPOINT,
    BOOT_MESH_ROUTE_AMBIGUOUS_ENDPOINT,
    BOOT_MESH_ROUTE_BUSY,
    BOOT_MESH_ROUTE_IDENTITY_MISMATCH,
    BOOT_MESH_ROUTE_DOWNGRADE,
    BOOT_MESH_ROUTE_EXHAUSTED,
    BOOT_MESH_ROUTE_UNAVAILABLE,
};

enum boot_mesh_route_observation {
    BOOT_MESH_ROUTE_OBS_NONE = 0,
    BOOT_MESH_ROUTE_OBS_CONNECTING,
    BOOT_MESH_ROUTE_OBS_MATCHED_NOISE,
    BOOT_MESH_ROUTE_OBS_WRONG_NOISE,
    BOOT_MESH_ROUTE_OBS_PLAINTEXT,
};

const char *boot_mesh_route_result_string(enum boot_mesh_route_result result);

/* Acquire a direct route for one still-active pairing. Endpoint bytes are only
 * hints: ACQUIRED requires an established Noise session whose remote static
 * exactly matches the pairing. The caller owns the returned peer reference.
 * No private frame is sent here. */
enum boot_mesh_route_result boot_mesh_route_acquire(
    struct boot_svc_ctx *svc, const struct db_mesh_pairing *pairing,
    uint64_t wall_unix, uint64_t monotonic_ms, struct p2p_node **peer_out,
    struct noise_transport_snapshot *session_out);

void boot_mesh_route_reset(void);

#ifdef ZCL_TESTING
enum boot_mesh_route_result boot_mesh_route_test_step(
    const char pairing_id[65], const struct net_address *endpoint,
    enum boot_mesh_route_observation observation, bool resource_admitted,
    uint64_t monotonic_ms, struct connman *connman, uint8_t *attempts_out);
#endif

#endif /* ZCL_CONFIG_BOOT_MESH_ROUTE_H */
