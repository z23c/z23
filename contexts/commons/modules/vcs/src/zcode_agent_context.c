/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Canonical bounded source context handed to model-neutral agents. */

#include "vcs/zcode_agent_context.h"

#include "base/bytes.h"
#include "vcs_priv.h"

#include "crypto/sha3.h"
#include "util/safe_alloc.h"
#include "vcs/package_manifest.h"

#include <stdlib.h>
#include <string.h>

static const uint8_t agent_context_magic[8] = {
    'Z', 'C', 'A', 'C', 'T', 'X', '\r', '\n'
};

const char *vcs_zcode_agent_context_result_string(
    enum vcs_zcode_agent_context_result result)
{
    switch (result) {
    case VCS_ZCODE_AGENT_CONTEXT_OK: return "ok";
    case VCS_ZCODE_AGENT_CONTEXT_NULL: return "null-argument";
    case VCS_ZCODE_AGENT_CONTEXT_SHAPE: return "noncanonical-context";
    case VCS_ZCODE_AGENT_CONTEXT_LIMIT: return "context-limit";
    case VCS_ZCODE_AGENT_CONTEXT_ROOT: return "context-root-mismatch";
    case VCS_ZCODE_AGENT_CONTEXT_BINDING: return "context-binding-mismatch";
    case VCS_ZCODE_AGENT_CONTEXT_INCOMPLETE: return "context-incomplete";
    case VCS_ZCODE_AGENT_CONTEXT_ALLOC: return "allocation-failed";
    }
    return "unknown";
}

void vcs_zcode_agent_context_init(struct vcs_zcode_agent_context_v1 *context)
{
    if (context) memset(context, 0, sizeof(*context));
}

void vcs_zcode_agent_context_free(struct vcs_zcode_agent_context_v1 *context)
{
    if (!context) return;
    for (size_t i = 0; i < context->file_count &&
                       i < VCS_ZCODE_AGENT_CONTEXT_MAX_FILES; i++)
        free(context->files[i].content);
    vcs_zcode_agent_context_init(context);
}

static enum vcs_zcode_agent_context_result context_measure(
    const struct vcs_zcode_agent_context_v1 *context, size_t maximum_bytes,
    size_t *total_out, uint64_t *content_out)
{
    if (!context || !total_out || !content_out)
        return VCS_ZCODE_AGENT_CONTEXT_NULL;
    size_t query_len = strnlen(context->query, sizeof(context->query));
    if (!zcl_bytes_any_set(context->task_root, 32) ||
        !zcl_bytes_any_set(context->source_root, 32) ||
        !zcl_bytes_any_set(context->goal_root, 32) ||
        !zcl_bytes_any_set(context->source_tree_root, 32) || query_len == 0 ||
        query_len > VCS_ZCODE_AGENT_CONTEXT_QUERY_MAX ||
        context->file_count == 0 ||
        context->file_count > VCS_ZCODE_AGENT_CONTEXT_MAX_FILES ||
        (context->flags & ~VCS_ZCODE_AGENT_CONTEXT_TRUNCATED) != 0)
        return VCS_ZCODE_AGENT_CONTEXT_SHAPE;
    if (maximum_bytes < VCS_ZCODE_AGENT_CONTEXT_FIXED_BYTES ||
        maximum_bytes > VCS_ZCODE_TASK_MAX_CONTEXT_BYTES)
        return VCS_ZCODE_AGENT_CONTEXT_LIMIT;
    size_t total = VCS_ZCODE_AGENT_CONTEXT_FIXED_BYTES + query_len;
    uint64_t content_total = 0;
    for (size_t i = 0; i < context->file_count; i++) {
        const struct vcs_zcode_agent_context_entry_v1 *entry =
            &context->files[i];
        size_t path_len = strnlen(entry->path, sizeof(entry->path));
        if (path_len == 0 || path_len > VCS_ZCODE_AGENT_CONTEXT_PATH_MAX ||
            !vcs_package_path_valid(entry->path) || entry->start_line == 0 ||
            entry->full_file_bytes == 0 || !entry->content ||
            entry->content_len == 0 ||
            entry->content_len > VCS_ZCODE_AGENT_CONTEXT_EXCERPT_MAX ||
            entry->content_len > entry->full_file_bytes ||
            (i > 0 && strcmp(context->files[i - 1].path,
                             entry->path) >= 0))
            return VCS_ZCODE_AGENT_CONTEXT_SHAPE;
        uint8_t root[32];
        sha3_256(entry->content, entry->content_len, root);
        if (memcmp(root, entry->content_root, 32) != 0)
            return VCS_ZCODE_AGENT_CONTEXT_ROOT;
        size_t add = VCS_ZCODE_AGENT_CONTEXT_ENTRY_FIXED_BYTES + path_len;
        if (add > SIZE_MAX - entry->content_len ||
            total > SIZE_MAX - add - entry->content_len)
            return VCS_ZCODE_AGENT_CONTEXT_LIMIT;
        total += add + entry->content_len;
        content_total += entry->content_len;
    }
    if (total > maximum_bytes)
        return VCS_ZCODE_AGENT_CONTEXT_LIMIT;
    *total_out = total;
    *content_out = content_total;
    return VCS_ZCODE_AGENT_CONTEXT_OK;
}

enum vcs_zcode_agent_context_result vcs_zcode_agent_context_validate(
    const struct vcs_zcode_agent_context_v1 *context, size_t maximum_bytes)
{
    size_t total = 0; uint64_t content = 0;
    return context_measure(context, maximum_bytes, &total, &content);
}

enum vcs_zcode_agent_context_result vcs_zcode_agent_context_serialize(
    const struct vcs_zcode_agent_context_v1 *context, size_t maximum_bytes,
    uint8_t **wire_out, size_t *wire_len)
{
    if (!wire_out || !wire_len) return VCS_ZCODE_AGENT_CONTEXT_NULL;
    *wire_out = NULL; *wire_len = 0;
    size_t total = 0; uint64_t content_total = 0;
    enum vcs_zcode_agent_context_result result = context_measure(
        context, maximum_bytes, &total, &content_total);
    if (result != VCS_ZCODE_AGENT_CONTEXT_OK) return result;
    uint8_t *wire = zcl_malloc(total, "zcode.agent_context");
    if (!wire) return VCS_ZCODE_AGENT_CONTEXT_ALLOC;
    size_t query_len = strlen(context->query), off = 0;
    memcpy(wire + off, agent_context_magic, 8); off += 8;
    vcs_wr_u16le(wire + off, VCS_ZCODE_AGENT_CONTEXT_VERSION); off += 2;
    vcs_wr_u16le(wire + off, (uint16_t)context->file_count); off += 2;
    vcs_wr_u16le(wire + off, (uint16_t)query_len); off += 2;
    vcs_wr_u16le(wire + off, context->flags); off += 2;
    vcs_wr_u64le(wire + off, content_total); off += 8;
    memcpy(wire + off, context->task_root, 32); off += 32;
    memcpy(wire + off, context->source_root, 32); off += 32;
    memcpy(wire + off, context->goal_root, 32); off += 32;
    memcpy(wire + off, context->source_tree_root, 32); off += 32;
    sha3_256((const uint8_t *)context->query, query_len, wire + off); off += 32;
    memcpy(wire + off, context->query, query_len); off += query_len;
    for (size_t i = 0; i < context->file_count; i++) {
        const struct vcs_zcode_agent_context_entry_v1 *entry =
            &context->files[i];
        size_t path_len = strlen(entry->path);
        vcs_wr_u16le(wire + off, (uint16_t)path_len); off += 2;
        vcs_wr_u16le(wire + off, 0); off += 2;
        vcs_wr_u32le(wire + off, entry->start_line); off += 4;
        vcs_wr_u32le(wire + off, (uint32_t)entry->content_len); off += 4;
        vcs_wr_u64le(wire + off, entry->full_file_bytes); off += 8;
        memcpy(wire + off, entry->content_root, 32); off += 32;
        memcpy(wire + off, entry->path, path_len); off += path_len;
        memcpy(wire + off, entry->content, entry->content_len);
        off += entry->content_len;
    }
    if (off != total) { free(wire); return VCS_ZCODE_AGENT_CONTEXT_SHAPE; }
    *wire_out = wire; *wire_len = total;
    return VCS_ZCODE_AGENT_CONTEXT_OK;
}

enum vcs_zcode_agent_context_result vcs_zcode_agent_context_parse(
    const uint8_t *wire, size_t wire_len, size_t maximum_bytes,
    struct vcs_zcode_agent_context_v1 *out)
{
    if (!wire || !out) return VCS_ZCODE_AGENT_CONTEXT_NULL;
    vcs_zcode_agent_context_init(out);
    if (wire_len < VCS_ZCODE_AGENT_CONTEXT_FIXED_BYTES ||
        wire_len > maximum_bytes ||
        memcmp(wire, agent_context_magic, 8) != 0 ||
        vcs_rd_u16le(wire + 8) != VCS_ZCODE_AGENT_CONTEXT_VERSION)
        return VCS_ZCODE_AGENT_CONTEXT_SHAPE;
    uint16_t count = vcs_rd_u16le(wire + 10);
    uint16_t query_len = vcs_rd_u16le(wire + 12);
    out->flags = vcs_rd_u16le(wire + 14);
    uint64_t expected_content = vcs_rd_u64le(wire + 16);
    if (count == 0 || count > VCS_ZCODE_AGENT_CONTEXT_MAX_FILES ||
        query_len == 0 || query_len > VCS_ZCODE_AGENT_CONTEXT_QUERY_MAX)
        return VCS_ZCODE_AGENT_CONTEXT_SHAPE;
    size_t off = 24;
    memcpy(out->task_root, wire + off, 32); off += 32;
    memcpy(out->source_root, wire + off, 32); off += 32;
    memcpy(out->goal_root, wire + off, 32); off += 32;
    memcpy(out->source_tree_root, wire + off, 32); off += 32;
    uint8_t query_root[32]; memcpy(query_root, wire + off, 32); off += 32;
    if (query_len > wire_len - off)
        return VCS_ZCODE_AGENT_CONTEXT_SHAPE;
    memcpy(out->query, wire + off, query_len); out->query[query_len] = '\0';
    uint8_t checked[32]; sha3_256(wire + off, query_len, checked);
    if (memcmp(checked, query_root, 32) != 0)
        return VCS_ZCODE_AGENT_CONTEXT_ROOT;
    off += query_len; out->file_count = count;
    uint64_t content_total = 0;
    for (size_t i = 0; i < count; i++) {
        if (wire_len - off < VCS_ZCODE_AGENT_CONTEXT_ENTRY_FIXED_BYTES)
            goto shape;
        uint16_t path_len = vcs_rd_u16le(wire + off); off += 2;
        uint16_t reserved = vcs_rd_u16le(wire + off); off += 2;
        struct vcs_zcode_agent_context_entry_v1 *entry = &out->files[i];
        entry->start_line = vcs_rd_u32le(wire + off); off += 4;
        uint32_t content_len = vcs_rd_u32le(wire + off); off += 4;
        entry->full_file_bytes = vcs_rd_u64le(wire + off); off += 8;
        memcpy(entry->content_root, wire + off, 32); off += 32;
        if (reserved != 0 || path_len == 0 ||
            path_len > VCS_ZCODE_AGENT_CONTEXT_PATH_MAX || content_len == 0 ||
            path_len > wire_len - off || content_len > wire_len - off - path_len)
            goto shape;
        memcpy(entry->path, wire + off, path_len); entry->path[path_len] = '\0';
        off += path_len;
        entry->content = zcl_malloc(content_len, "zcode.agent_context.entry");
        if (!entry->content) {
            vcs_zcode_agent_context_free(out);
            return VCS_ZCODE_AGENT_CONTEXT_ALLOC;
        }
        memcpy(entry->content, wire + off, content_len);
        entry->content_len = content_len; off += content_len;
        content_total += content_len;
    }
    if (off != wire_len || content_total != expected_content) goto shape;
    enum vcs_zcode_agent_context_result valid =
        vcs_zcode_agent_context_validate(out, maximum_bytes);
    if (valid != VCS_ZCODE_AGENT_CONTEXT_OK) {
        vcs_zcode_agent_context_free(out);
        return valid;
    }
    return VCS_ZCODE_AGENT_CONTEXT_OK;
shape:
    vcs_zcode_agent_context_free(out);
    return VCS_ZCODE_AGENT_CONTEXT_SHAPE;
}

enum vcs_zcode_agent_context_result vcs_zcode_agent_context_root(
    const struct vcs_zcode_agent_context_v1 *context, size_t maximum_bytes,
    uint8_t out[32])
{
    if (!out) return VCS_ZCODE_AGENT_CONTEXT_NULL;
    uint8_t *wire = NULL; size_t wire_len = 0;
    enum vcs_zcode_agent_context_result result =
        vcs_zcode_agent_context_serialize(context, maximum_bytes,
                                           &wire, &wire_len);
    if (result != VCS_ZCODE_AGENT_CONTEXT_OK) return result;
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    static const char domain[] = VCS_ZCODE_AGENT_CONTEXT_DOMAIN;
    sha3_256_write(&sha, (const uint8_t *)domain, sizeof(domain));
    sha3_256_write(&sha, wire, wire_len);
    sha3_256_finalize(&sha, out);
    free(wire);
    return VCS_ZCODE_AGENT_CONTEXT_OK;
}

enum vcs_zcode_agent_context_result vcs_zcode_agent_context_validate_for_task(
    const struct vcs_zcode_agent_context_v1 *context,
    const struct vcs_zcode_task_v1 *task,
    const uint8_t expected_task_root[32],
    const uint8_t expected_context_root[32], bool require_complete)
{
    if (!context || !task || !expected_task_root || !expected_context_root)
        return VCS_ZCODE_AGENT_CONTEXT_NULL;
    enum vcs_zcode_agent_context_result result =
        vcs_zcode_agent_context_validate(context, task->max_context_bytes);
    if (result != VCS_ZCODE_AGENT_CONTEXT_OK) return result;
    uint8_t task_root[32], context_root[32];
    if (vcs_zcode_task_validate(task) != VCS_ZCODE_DEV_OK ||
        vcs_zcode_task_root(task, task_root) != VCS_ZCODE_DEV_OK ||
        vcs_zcode_agent_context_root(
            context, task->max_context_bytes, context_root) !=
            VCS_ZCODE_AGENT_CONTEXT_OK)
        return VCS_ZCODE_AGENT_CONTEXT_BINDING;
    if (memcmp(task_root, expected_task_root, 32) != 0 ||
        memcmp(context_root, expected_context_root, 32) != 0 ||
        memcmp(context->task_root, task_root, 32) != 0 ||
        memcmp(context->source_root, task->source_root, 32) != 0 ||
        memcmp(context->goal_root, task->goal_root, 32) != 0)
        return VCS_ZCODE_AGENT_CONTEXT_BINDING;
    return require_complete &&
           (context->flags & VCS_ZCODE_AGENT_CONTEXT_TRUNCATED) != 0
        ? VCS_ZCODE_AGENT_CONTEXT_INCOMPLETE
        : VCS_ZCODE_AGENT_CONTEXT_OK;
}
