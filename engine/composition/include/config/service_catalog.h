/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Immutable shadow catalog for the target zclassic23 process roles. */

#ifndef ZCL_CONFIG_SERVICE_CATALOG_H
#define ZCL_CONFIG_SERVICE_CATALOG_H

#include "kernel/service_manifest.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

enum zcl_service_catalog_id_v1 {
    ZCL_SERVICE_ID_INIT = 1,
    ZCL_SERVICE_ID_CORE = 2,
    ZCL_SERVICE_ID_EDGE = 3,
    ZCL_SERVICE_ID_WALLET = 4,
    ZCL_SERVICE_ID_APPD = 5,
    ZCL_SERVICE_ID_BUILDD = 6,
};

/* Operation IDs are interpreted in the namespace of the peer service named
 * by zcl_service_ipc_grant_v1.peer_service_id. */
enum zcl_service_catalog_operation_v1 {
    ZCL_CORE_OPERATION_CHAIN_READ_V1 = 1,
    ZCL_EDGE_OPERATION_APP_PUBLISH_V1 = 1,
    ZCL_WALLET_OPERATION_INTENT_V1 = 1,
    ZCL_APPD_OPERATION_EDGE_RELAY_V1 = 1,
    ZCL_APPD_OPERATION_BUILD_RESULT_V1 = 2,
};

const struct zcl_service_manifest_v1 *zcl_service_catalog_v1(
    size_t *count);

enum zcl_service_manifest_result zcl_service_catalog_validate_v1(
    size_t *bad_index);

bool zcl_service_catalog_digest_v1(uint8_t out[32]);

/* Composition-root registry for the currently declared peer-local operation
 * schemas. A nonzero numeric operation alone is never sufficient authority. */
bool zcl_service_catalog_ipc_grant_known_v1(
    uint32_t caller_service_id,
    uint32_t peer_service_id,
    uint32_t operation_id);

/* True only while every entry is an observation-only declaration with no
 * active runtime-generation binding. */
bool zcl_service_catalog_shadow_only_v1(void);

#endif /* ZCL_CONFIG_SERVICE_CATALOG_H */
