/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Capture immutable code-index context into the existing ZCODE CAS. */

#ifndef ZCL_SERVICES_ZCODE_AGENT_CONTEXT_SERVICE_H
#define ZCL_SERVICES_ZCODE_AGENT_CONTEXT_SERVICE_H

#include "base/result.h"
#include "vcs/zcode_dev.h"

#include <stddef.h>
#include <stdint.h>

struct zcode_agent_context_status {
    char context_root_sha3[65];
    char source_tree_root_sha3[65];
    char resolved_symbol[128];
    size_t file_count;
    size_t excerpt_bytes;
    size_t wire_bytes;
    bool truncated;
};

/* Resolve one exact/stable symbol through the existing code index, capture a
 * bounded deterministic source neighborhood, prove the source tree did not
 * change during capture (including selected-byte rereads), and atomically put
 * the canonical agent_context.v1 wire in the existing workspace CAS. */
struct zcl_result zcode_agent_context_capture(
    const char *workspace, const struct vcs_zcode_task_v1 *task,
    const uint8_t task_root[32], const char *query,
    struct zcode_agent_context_status *out);

#endif /* ZCL_SERVICES_ZCODE_AGENT_CONTEXT_SERVICE_H */
