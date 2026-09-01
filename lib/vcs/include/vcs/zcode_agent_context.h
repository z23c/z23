/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Canonical bounded source context handed to model-neutral agents. */

#ifndef ZCL_VCS_ZCODE_AGENT_CONTEXT_H
#define ZCL_VCS_ZCODE_AGENT_CONTEXT_H

#include "vcs/zcode_dev.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define VCS_ZCODE_AGENT_CONTEXT_VERSION 1u
#define VCS_ZCODE_AGENT_CONTEXT_DOMAIN "zcl.zcode.agent_context.v1"
#define VCS_ZCODE_AGENT_CONTEXT_FIXED_BYTES 184u
#define VCS_ZCODE_AGENT_CONTEXT_ENTRY_FIXED_BYTES 52u
#define VCS_ZCODE_AGENT_CONTEXT_MAX_FILES 16u
#define VCS_ZCODE_AGENT_CONTEXT_QUERY_MAX 256u
#define VCS_ZCODE_AGENT_CONTEXT_PATH_MAX 255u
#define VCS_ZCODE_AGENT_CONTEXT_EXCERPT_MAX (64u * 1024u)
#define VCS_ZCODE_AGENT_CONTEXT_TRUNCATED 1u

enum vcs_zcode_agent_context_result {
    VCS_ZCODE_AGENT_CONTEXT_OK = 0,
    VCS_ZCODE_AGENT_CONTEXT_NULL,
    VCS_ZCODE_AGENT_CONTEXT_SHAPE,
    VCS_ZCODE_AGENT_CONTEXT_LIMIT,
    VCS_ZCODE_AGENT_CONTEXT_ROOT,
    VCS_ZCODE_AGENT_CONTEXT_ALLOC,
    VCS_ZCODE_AGENT_CONTEXT_BINDING,
    VCS_ZCODE_AGENT_CONTEXT_INCOMPLETE,
};

struct vcs_zcode_agent_context_entry_v1 {
    char path[VCS_ZCODE_AGENT_CONTEXT_PATH_MAX + 1u];
    uint32_t start_line;
    uint64_t full_file_bytes;
    uint8_t content_root[32];
    uint8_t *content;
    size_t content_len;
};

struct vcs_zcode_agent_context_v1 {
    uint8_t task_root[32];
    uint8_t source_root[32];
    uint8_t goal_root[32];
    uint8_t source_tree_root[32];
    char query[VCS_ZCODE_AGENT_CONTEXT_QUERY_MAX + 1u];
    uint16_t flags;
    size_t file_count;
    struct vcs_zcode_agent_context_entry_v1
        files[VCS_ZCODE_AGENT_CONTEXT_MAX_FILES];
};

const char *vcs_zcode_agent_context_result_string(
    enum vcs_zcode_agent_context_result result);
void vcs_zcode_agent_context_init(struct vcs_zcode_agent_context_v1 *context);
void vcs_zcode_agent_context_free(struct vcs_zcode_agent_context_v1 *context);
enum vcs_zcode_agent_context_result vcs_zcode_agent_context_validate(
    const struct vcs_zcode_agent_context_v1 *context, size_t maximum_bytes);
enum vcs_zcode_agent_context_result vcs_zcode_agent_context_serialize(
    const struct vcs_zcode_agent_context_v1 *context, size_t maximum_bytes,
    uint8_t **wire, size_t *wire_len);
enum vcs_zcode_agent_context_result vcs_zcode_agent_context_parse(
    const uint8_t *wire, size_t wire_len, size_t maximum_bytes,
    struct vcs_zcode_agent_context_v1 *out);
enum vcs_zcode_agent_context_result vcs_zcode_agent_context_root(
    const struct vcs_zcode_agent_context_v1 *context, size_t maximum_bytes,
    uint8_t out[32]);
/* Receiver-side semantic admission. Structural validity or a matching CAS
 * address alone does not authorize use under a different task. */
enum vcs_zcode_agent_context_result vcs_zcode_agent_context_validate_for_task(
    const struct vcs_zcode_agent_context_v1 *context,
    const struct vcs_zcode_task_v1 *task,
    const uint8_t expected_task_root[32],
    const uint8_t expected_context_root[32], bool require_complete);

#endif /* ZCL_VCS_ZCODE_AGENT_CONTEXT_H */
