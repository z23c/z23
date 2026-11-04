/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: lab.brief test seam - replace the five live sub-leaf reads
 *          with fixtures so the size cap, the unavailable path and field
 *          provenance are provable without a node, a land queue or a plan. */
#ifndef ZCL_NATIVE_DEVAGENT_BRIEF_H
#define ZCL_NATIVE_DEVAGENT_BRIEF_H

#include "command/native_command.h"
#include "json/json.h"

#include <stdbool.h>
#include <stddef.h>

/* The five sources the brief composes, in output order. */
enum zcl_devagent_brief_source {
    ZCL_BRIEF_NODE,      /* core.status.brief */
    ZCL_BRIEF_LAND,      /* dev.land.status */
    ZCL_BRIEF_PLAN,      /* docs/work/FORWARD_PLAN.md at HEAD, as {"items":[...]} */
    ZCL_BRIEF_AGENTS,    /* dev.agent.queue status */
    ZCL_BRIEF_DEADLINES, /* ops.mesh.device.pair.status */
    ZCL_BRIEF_SOURCE_COUNT
};

/* Fill `data` (an initialized json_value) with the source's data object and
 * return true, or return false with `code` (typed, upper snake) and `why`. */
typedef bool (*zcl_devagent_brief_fetch_fn)(
    const struct zcl_command_request *request,
    enum zcl_devagent_brief_source source, struct json_value *data,
    char *code, size_t code_cap, char *why, size_t why_cap);

/* Test seam: NULL restores the live reads. */
void zcl_devagent_brief_set_fetch(zcl_devagent_brief_fetch_fn fn);

#endif
