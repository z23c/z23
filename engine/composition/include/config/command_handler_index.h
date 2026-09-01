/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Command → handler-name index (WF4 code-capsule, dispatch join).
 *
 * The native command catalog (engine/composition/src/command_catalog.c) binds a handler
 * FUNCTION POINTER per leaf, not a symbol name, so a file→command join would
 * otherwise only guess (see native_code_command.c:818-828, the degraded
 * `commands` field). This index is a PARALLEL stringizing expansion of the
 * SAME command .def files (engine/composition/src/command_catalog.c builds
 * g_handler_index_entries[] by re-including root/core/apps/app_features/ops/
 * dev/code/accounts .def through a stringizing macro), producing a `{path,
 * handler_name}` table so `code capsule` / `code room` can resolve which
 * native command a handler backs — closing that named gap without touching
 * the handler-pointer binding. Populated at link time; a _Static_assert in
 * command_catalog.c pins the table's count at or below the full catalog's. */

#ifndef ZCL_CONFIG_COMMAND_HANDLER_INDEX_H
#define ZCL_CONFIG_COMMAND_HANDLER_INDEX_H

#include <stddef.h>

/* One command path and the (stringized) name of the C handler backing it. */
struct zcl_command_handler_entry {
    const char *path;          /* e.g. "core.status" */
    const char *handler_name;  /* e.g. "status_native_handler" */
};

/* Immutable table of every leaf that binds a native handler. */
struct zcl_command_handler_index {
    const struct zcl_command_handler_entry *entries;
    size_t count;
};

/* The process-wide handler index (static storage; never NULL). count == the
 * number of leaves that bind a native handler (see command_catalog.c). */
const struct zcl_command_handler_index *zcl_command_handler_index(void);

#endif /* ZCL_CONFIG_COMMAND_HANDLER_INDEX_H */
