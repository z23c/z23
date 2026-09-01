/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#ifndef ZCL_CONFIG_COMMAND_CATALOG_H
#define ZCL_CONFIG_COMMAND_CATALOG_H

#include "kernel/command_registry.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Immutable composition-root view. Metadata is transport-neutral; handler
 * pointers are the explicitly injected native bindings for this build. */
const struct zcl_command_registry *zcl_command_catalog(void);

#ifdef __cplusplus
}
#endif

#endif /* ZCL_CONFIG_COMMAND_CATALOG_H */
