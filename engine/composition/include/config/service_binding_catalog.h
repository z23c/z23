/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Composition root for the declared service catalog (engine/composition/services/
 * bindings.def). Reading it grants no runtime authority: a binding is a
 * declaration, and the lifecycle registry still has to admit it. */

#ifndef ZCL_CONFIG_SERVICE_BINDING_CATALOG_H
#define ZCL_CONFIG_SERVICE_BINDING_CATALOG_H

#include "kernel/service_binding.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

const struct zcl_service_binding_v1 *zcl_service_binding_catalog_v1(
    size_t *count);

/* Per-binding validity, catalog rules, AND the cross-check that every
 * host_service_id names a real APP_BROKER manifest in the process-isolation
 * catalog (engine/composition/services/catalog.def). */
enum zcl_service_binding_result zcl_service_binding_catalog_check_v1(
    size_t *bad_index);

/* Zeroed and false unless the whole catalog checks out. */
bool zcl_service_binding_catalog_root_v1(uint8_t out[32]);

/* Exact-name lookup; NULL when nothing matches. */
const struct zcl_service_binding_v1 *zcl_service_binding_find_v1(
    const char *name);

/* Which declared service owns a native command path, or NULL. Used to prove
 * no leaf under app.service.<x> exists without a binding that claims it. */
const struct zcl_service_binding_v1 *zcl_service_binding_owner_of_command_v1(
    const char *path);

#endif /* ZCL_CONFIG_SERVICE_BINDING_CATALOG_H */
