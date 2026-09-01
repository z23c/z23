/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Composition-root storage for the immutable shadow service catalog. */

#include "config/service_catalog.h"

#include <string.h>

#define ZCL_SERVICE_ENTRY(...) { __VA_ARGS__ },
static const struct zcl_service_manifest_v1 g_service_catalog[] = {
#include "../services/catalog.def"
};
#undef ZCL_SERVICE_ENTRY

const struct zcl_service_manifest_v1 *zcl_service_catalog_v1(size_t *count)
{
    if (count)
        *count = sizeof(g_service_catalog) / sizeof(g_service_catalog[0]);
    return g_service_catalog;
}

enum zcl_service_manifest_result zcl_service_catalog_validate_v1(
    size_t *bad_index)
{
    enum zcl_service_manifest_result result =
        zcl_service_manifest_catalog_validate_v1(
        g_service_catalog,
        sizeof(g_service_catalog) / sizeof(g_service_catalog[0]),
        bad_index);
    if (result != ZCL_SERVICE_MANIFEST_OK)
        return result;
    for (size_t i = 0; i < sizeof(g_service_catalog) /
                                   sizeof(g_service_catalog[0]); i++) {
        for (uint32_t j = 0; j < g_service_catalog[i].ipc_grant_count; j++) {
            const struct zcl_service_ipc_grant_v1 *grant =
                &g_service_catalog[i].ipc_grants[j];
            if (!zcl_service_catalog_ipc_grant_known_v1(
                    g_service_catalog[i].service_id,
                    grant->peer_service_id, grant->operation_id)) {
                if (bad_index)
                    *bad_index = i;
                return ZCL_SERVICE_MANIFEST_IPC_GRANT;
            }
        }
    }
    return ZCL_SERVICE_MANIFEST_OK;
}

bool zcl_service_catalog_ipc_grant_known_v1(
    uint32_t caller_service_id,
    uint32_t peer_service_id,
    uint32_t operation_id)
{
    if (caller_service_id == ZCL_SERVICE_ID_EDGE)
        return (peer_service_id == ZCL_SERVICE_ID_CORE &&
                operation_id == ZCL_CORE_OPERATION_CHAIN_READ_V1) ||
               (peer_service_id == ZCL_SERVICE_ID_APPD &&
                operation_id == ZCL_APPD_OPERATION_EDGE_RELAY_V1);
    if (caller_service_id == ZCL_SERVICE_ID_WALLET)
        return peer_service_id == ZCL_SERVICE_ID_CORE &&
               operation_id == ZCL_CORE_OPERATION_CHAIN_READ_V1;
    if (caller_service_id == ZCL_SERVICE_ID_APPD)
        return (peer_service_id == ZCL_SERVICE_ID_CORE &&
                operation_id == ZCL_CORE_OPERATION_CHAIN_READ_V1) ||
               (peer_service_id == ZCL_SERVICE_ID_EDGE &&
                operation_id == ZCL_EDGE_OPERATION_APP_PUBLISH_V1) ||
               (peer_service_id == ZCL_SERVICE_ID_WALLET &&
                operation_id == ZCL_WALLET_OPERATION_INTENT_V1);
    if (caller_service_id == ZCL_SERVICE_ID_BUILDD)
        return peer_service_id == ZCL_SERVICE_ID_APPD &&
               operation_id == ZCL_APPD_OPERATION_BUILD_RESULT_V1;
    return false;
}

bool zcl_service_catalog_digest_v1(uint8_t out[32])
{
    if (!out)
        return false;
    memset(out, 0, 32);
    if (zcl_service_catalog_validate_v1(NULL) != ZCL_SERVICE_MANIFEST_OK)
        return false;
    return zcl_service_manifest_catalog_digest_v1(
        g_service_catalog,
        sizeof(g_service_catalog) / sizeof(g_service_catalog[0]), out);
}

bool zcl_service_catalog_shadow_only_v1(void)
{
    for (size_t i = 0; i < sizeof(g_service_catalog) /
                                   sizeof(g_service_catalog[0]); i++) {
        if (g_service_catalog[i].enforcement !=
                ZCL_SERVICE_ENFORCEMENT_SHADOW ||
            memcmp(g_service_catalog[i].active_generation_root,
                   (const uint8_t[32]){0}, 32) != 0)
            return false;
    }
    return true;
}
