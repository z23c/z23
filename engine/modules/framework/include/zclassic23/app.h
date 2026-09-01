/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Stable Z23 Core -> App ABI.
 *
 * This is the ONLY project header an external application generation may
 * include. Core owns consensus, keys, raw storage, sockets, boot, and process
 * lifecycle. Apps receive bounded capabilities over opaque handles. */

#ifndef ZCLASSIC23_APP_H
#define ZCLASSIC23_APP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ZCL_APP_MANIFEST_V1 1u
#define ZCL_APP_HOST_ABI_V1 1u
#define ZCL_APP_ID_MAX 63u
#define ZCL_APP_ROUTE_MAX 127u
#define ZCL_APP_TOPIC_MAX 127u
#define ZCL_APP_ERROR_MAX 191u

typedef uint64_t zcl_app_state_handle;
typedef uint64_t zcl_app_generation_lease;

struct zcl_app_bytes {
    const uint8_t *data;
    size_t len;
};

struct zcl_app_mut_bytes {
    uint8_t *data;
    size_t capacity;
    size_t len;
};

struct zcl_app_error {
    int code;
    char message[ZCL_APP_ERROR_MAX + 1];
};

/* These are the entire authority surface available to apps. There is
 * intentionally no raw SQL, filesystem, socket, private-key, peer-state,
 * chain-mutation, validation, or consensus capability. */
enum zcl_app_capability {
    ZCL_APP_CAP_CHAIN_READ       = UINT64_C(1) << 0,
    ZCL_APP_CAP_SIGNED_EVENTS    = UINT64_C(1) << 1,
    ZCL_APP_CAP_RESIDENT_STATE   = UINT64_C(1) << 2,
    ZCL_APP_CAP_WEB_ROUTES       = UINT64_C(1) << 3,
    ZCL_APP_CAP_ONION_BINDING    = UINT64_C(1) << 4,
    ZCL_APP_CAP_ZNAM_BINDING     = UINT64_C(1) << 5,
    ZCL_APP_CAP_P2P_TOPICS       = UINT64_C(1) << 6,
    ZCL_APP_CAP_WALLET_REQUESTS  = UINT64_C(1) << 7,
    ZCL_APP_CAP_SCHEDULED_JOBS   = UINT64_C(1) << 8,
    ZCL_APP_CAP_CLOCK            = UINT64_C(1) << 9,
    ZCL_APP_CAP_RANDOM           = UINT64_C(1) << 10,
};

enum zcl_app_route_flags {
    ZCL_APP_ROUTE_READ_ONLY = 1u << 0,
    ZCL_APP_ROUTE_AUTHENTICATED = 1u << 1,
    ZCL_APP_ROUTE_LOCAL_ONLY = 1u << 2,
};

struct zcl_app_request_v1 {
    uint32_t struct_size;
    const char *method;
    const char *path;
    struct zcl_app_bytes body;
    struct zcl_app_bytes operator_identity;
};

typedef int (*zcl_app_route_handler_v1)(
    const struct zcl_app_request_v1 *request,
    struct zcl_app_mut_bytes *response,
    struct zcl_app_error *error);

struct zcl_app_route_v1 {
    uint32_t struct_size;
    const char *method;
    const char *path;
    uint32_t flags;
    zcl_app_route_handler_v1 handler;
};

struct zcl_app_topic_v1 {
    uint32_t struct_size;
    const char *name;
    uint32_t wire_version;
    uint32_t max_event_bytes;
};

/* Resident host table. Every call is scoped to one opaque host context and
 * returns an explicit error. App code never owns a core pointer. */
struct zcl_app_host_v1 {
    uint32_t struct_size;
    uint32_t abi_version;
    uint64_t capabilities;
    void *host_context;

    int (*chain_query)(void *host_context, const char *query,
                       struct zcl_app_bytes args,
                       struct zcl_app_mut_bytes *response,
                       struct zcl_app_error *error);
    int (*event_append)(void *host_context, const char *app_id,
                        const char *topic, struct zcl_app_bytes event,
                        struct zcl_app_error *error);
    int (*state_open)(void *host_context, const char *app_id,
                      uint32_t schema_version,
                      zcl_app_state_handle *out,
                      struct zcl_app_error *error);
    int (*state_read)(void *host_context, zcl_app_state_handle state,
                      struct zcl_app_bytes key,
                      struct zcl_app_mut_bytes *value,
                      struct zcl_app_error *error);
    int (*state_write)(void *host_context, zcl_app_state_handle state,
                       struct zcl_app_bytes key,
                       struct zcl_app_bytes value,
                       struct zcl_app_error *error);
    int (*p2p_publish)(void *host_context, const char *topic,
                       struct zcl_app_bytes event,
                       struct zcl_app_error *error);
    int (*wallet_request)(void *host_context, const char *operation,
                          struct zcl_app_bytes request,
                          struct zcl_app_mut_bytes *response,
                          struct zcl_app_error *error);
    int (*lease_acquire)(void *host_context, uint32_t generation,
                         zcl_app_generation_lease *lease,
                         struct zcl_app_error *error);
    void (*lease_release)(void *host_context,
                          zcl_app_generation_lease lease);
};

struct zcl_app_migration_v1 {
    uint32_t struct_size;
    uint32_t from_schema;
    uint32_t to_schema;
    int (*prepare)(const struct zcl_app_host_v1 *host,
                   zcl_app_state_handle state,
                   struct zcl_app_error *error);
    int (*commit)(const struct zcl_app_host_v1 *host,
                  zcl_app_state_handle state,
                  struct zcl_app_error *error);
    void (*abort)(const struct zcl_app_host_v1 *host,
                  zcl_app_state_handle state);
};

struct zcl_app_manifest_v1 {
    uint32_t struct_size;
    uint32_t manifest_version;
    uint32_t required_host_abi;
    uint32_t state_schema_version;
    const char *app_id;
    const char *display_name;
    const char *app_version;
    const char *build_identity;
    const char *content_sha256;
    uint64_t required_capabilities;
    const struct zcl_app_route_v1 *routes;
    size_t route_count;
    const struct zcl_app_topic_v1 *topics;
    size_t topic_count;
    const struct zcl_app_migration_v1 *migration;
    int (*self_test)(const struct zcl_app_host_v1 *host,
                     struct zcl_app_error *error);
    /* Drain barrier, not an irreversible stop: after returning, the old
     * generation must remain re-enterable if migration commit or publication
     * fails. Host-owned state is unchanged until the transaction commits. */
    int (*quiesce)(const struct zcl_app_host_v1 *host,
                   uint32_t timeout_ms,
                   struct zcl_app_error *error);
};

/* Every generation exports this exact symbol. */
typedef const struct zcl_app_manifest_v1 *(*zcl_app_manifest_v1_fn)(void);

#ifdef __cplusplus
}
#endif

#endif /* ZCLASSIC23_APP_H */
