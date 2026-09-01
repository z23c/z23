/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Composition-root storage for the declared service catalog. The table is
 * built by expanding engine/composition/services/bindings.def, exactly as the process
 * role catalog is built from engine/composition/services/catalog.def. There is no
 * editable array here — add a service by appending to the .def. */

#include "config/service_binding_catalog.h"

#include "config/service_catalog.h"

#include <string.h>

#define ZCL_SERVICE_BINDING_ENTRY(...) { __VA_ARGS__ },
static const struct zcl_service_binding_v1 g_service_bindings[] = {
#include "../services/bindings.def"
};
#undef ZCL_SERVICE_BINDING_ENTRY

#define ZCL_SERVICE_BINDING_COUNT \
    (sizeof(g_service_bindings) / sizeof(g_service_bindings[0]))

const struct zcl_service_binding_v1 *zcl_service_binding_catalog_v1(
    size_t *count)
{
    if (count)
        *count = ZCL_SERVICE_BINDING_COUNT;
    return g_service_bindings;
}

enum zcl_service_binding_result zcl_service_binding_catalog_check_v1(
    size_t *bad_index)
{
    if (bad_index)
        *bad_index = 0;
    enum zcl_service_binding_result result =
        zcl_service_binding_catalog_validate_v1(
            g_service_bindings, ZCL_SERVICE_BINDING_COUNT, bad_index);
    if (result != ZCL_SERVICE_BINDING_OK)
        return result;
    size_t manifest_count = 0;
    const struct zcl_service_manifest_v1 *manifests =
        zcl_service_catalog_v1(&manifest_count);
    for (size_t i = 0; i < ZCL_SERVICE_BINDING_COUNT; i++) {
        result = zcl_service_binding_host_check_v1(
            &g_service_bindings[i], manifests, manifest_count);
        if (result != ZCL_SERVICE_BINDING_OK) {
            if (bad_index)
                *bad_index = i;
            return result;
        }
    }
    return ZCL_SERVICE_BINDING_OK;
}

bool zcl_service_binding_catalog_root_v1(uint8_t out[32])
{
    if (!out)
        return false;
    memset(out, 0, 32);
    if (zcl_service_binding_catalog_check_v1(NULL) != ZCL_SERVICE_BINDING_OK)
        return false;
    return zcl_service_binding_catalog_digest_v1(
        g_service_bindings, ZCL_SERVICE_BINDING_COUNT, out);
}

const struct zcl_service_binding_v1 *zcl_service_binding_find_v1(
    const char *name)
{
    if (!name || !name[0])
        return NULL;
    for (size_t i = 0; i < ZCL_SERVICE_BINDING_COUNT; i++) {
        if (strncmp(g_service_bindings[i].name, name,
                    sizeof(g_service_bindings[i].name)) == 0)
            return &g_service_bindings[i];
    }
    return NULL;
}

const struct zcl_service_binding_v1 *zcl_service_binding_owner_of_command_v1(
    const char *path)
{
    if (!path || !path[0])
        return NULL;
    for (size_t i = 0; i < ZCL_SERVICE_BINDING_COUNT; i++) {
        if (zcl_service_binding_owns_command_v1(&g_service_bindings[i], path))
            return &g_service_bindings[i];
    }
    return NULL;
}
