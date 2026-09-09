/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Validate bounded task-map hierarchy and completion dependencies. */
#include "ontology/work_map.h"

#include "base/bytes.h"
#include "base/log_macros.h"
#include "codec/cursor.h"

#include <stdbool.h>
#include <string.h>

static enum zcl_work_map_result map_refuse(
    enum zcl_work_map_result reason, size_t node)
{
    LOG_ERROR("work_map", "definition refused: reason=%d node=%zu",
              (int)reason, node);
    return reason;
}

static enum zcl_work_map_result map_node_valid(
    const struct zcl_work_map_node *nodes, size_t count, size_t index)
{
    const struct zcl_work_map_node *node = &nodes[index];
    if (!zcl_bytes_any_set(node->task_root, 32))
        return map_refuse(ZCL_WORK_MAP_IDENTITY, index);
    for (size_t i = 0; i < index; i++)
        if (memcmp(nodes[i].task_root, node->task_root, 32) == 0)
            return map_refuse(ZCL_WORK_MAP_IDENTITY, index);
    if (node->kind < ZCL_WORK_MAP_MILESTONE || node->kind > ZCL_WORK_MAP_LOOP)
        return map_refuse(ZCL_WORK_MAP_HIERARCHY, index);
    if (node->kind == ZCL_WORK_MAP_MILESTONE) {
        if (node->parent != ZCL_WORK_MAP_NO_PARENT)
            return map_refuse(ZCL_WORK_MAP_HIERARCHY, index);
    } else if (node->parent >= count ||
               nodes[node->parent].kind + 1u != node->kind) {
        return map_refuse(ZCL_WORK_MAP_HIERARCHY, index);
    }
    return ZCL_WORK_MAP_OK;
}

static enum zcl_work_map_result map_dependencies_valid(
    const struct zcl_work_map_node *node, size_t count, size_t index)
{
    if (node->dependency_count > ZCL_WORK_MAP_MAX_DEPENDENCIES)
        return map_refuse(ZCL_WORK_MAP_DEPENDENCY, index);
    for (size_t d = 0; d < node->dependency_count; d++) {
        uint16_t dependency = node->dependencies[d];
        if (dependency >= count || dependency == index)
            return map_refuse(ZCL_WORK_MAP_DEPENDENCY, index);
        for (size_t p = 0; p < d; p++)
            if (node->dependencies[p] == dependency)
                return map_refuse(ZCL_WORK_MAP_DEPENDENCY, index);
    }
    return ZCL_WORK_MAP_OK;
}

static bool map_prerequisites_ordered(
    const struct zcl_work_map_node *nodes, size_t count, size_t index,
    const bool ordered[ZCL_WORK_MAP_MAX_NODES])
{
    for (size_t d = 0; d < nodes[index].dependency_count; d++)
        if (!ordered[nodes[index].dependencies[d]]) return false;
    for (size_t child = 0; child < count; child++)
        if (nodes[child].parent == index && !ordered[child]) return false;
    return true;
}

static enum zcl_work_map_result map_order_valid(
    const struct zcl_work_map_node *nodes, size_t count)
{
    bool ordered[ZCL_WORK_MAP_MAX_NODES] = {0};
    size_t remaining = count;
    while (remaining > 0) {
        size_t before = remaining;
        for (size_t i = 0; i < count; i++) {
            if (ordered[i] || !map_prerequisites_ordered(nodes, count, i, ordered))
                continue;
            ordered[i] = true;
            remaining--;
        }
        if (remaining == before) return map_refuse(ZCL_WORK_MAP_CYCLE, count);
    }
    return ZCL_WORK_MAP_OK;
}

enum zcl_work_map_result zcl_work_map_validate(
    const struct zcl_work_map_node *nodes, size_t count)
{
    if (!nodes || count == 0 || count > ZCL_WORK_MAP_MAX_NODES)
        return map_refuse(ZCL_WORK_MAP_BOUNDS, count);
    uint16_t children[ZCL_WORK_MAP_MAX_NODES] = {0};
    for (size_t i = 0; i < count; i++) {
        enum zcl_work_map_result valid = map_node_valid(nodes, count, i);
        if (valid != ZCL_WORK_MAP_OK) return valid;
        valid = map_dependencies_valid(&nodes[i], count, i);
        if (valid != ZCL_WORK_MAP_OK) return valid;
        if (nodes[i].parent != ZCL_WORK_MAP_NO_PARENT)
            children[nodes[i].parent]++;
    }
    for (size_t i = 0; i < count; i++)
        if (nodes[i].kind != ZCL_WORK_MAP_LOOP && children[i] == 0)
            return map_refuse(ZCL_WORK_MAP_HIERARCHY, i);
    return map_order_valid(nodes, count);
}

static const uint8_t map_magic[8] = {'Z','2','3','W','M','A','P','\n'};

static bool map_write_node(struct zcl_codec_writer *writer,
                            const struct zcl_work_map_node *node)
{
    if (!zcl_codec_write_bytes(writer, node->task_root, 32) ||
        !zcl_codec_write_u16le(writer, node->kind) ||
        !zcl_codec_write_u16le(writer, node->parent) ||
        !zcl_codec_write_u16le(writer, node->dependency_count)) return false;
    for (size_t i = 0; i < node->dependency_count; i++)
        if (!zcl_codec_write_u16le(writer, node->dependencies[i])) return false;
    return true;
}

enum zcl_work_map_result zcl_work_map_serialize(
    const struct zcl_work_map_node *nodes, size_t count,
    uint8_t *wire, size_t capacity, size_t *written)
{
    if (written) *written = 0;
    if (!wire || !written) return map_refuse(ZCL_WORK_MAP_BOUNDS, count);
    enum zcl_work_map_result valid = zcl_work_map_validate(nodes, count);
    if (valid != ZCL_WORK_MAP_OK) return valid;
    size_t required = 12 + count * 38;
    for (size_t i = 0; i < count; i++) required += 2 * nodes[i].dependency_count;
    if (capacity < required) return map_refuse(ZCL_WORK_MAP_BOUNDS, count);
    struct zcl_codec_writer writer;
    zcl_codec_writer_init(&writer, wire, capacity);
    bool ok = zcl_codec_write_bytes(&writer, map_magic, sizeof(map_magic)) &&
        zcl_codec_write_u16le(&writer, 1) &&
        zcl_codec_write_u16le(&writer, (uint16_t)count);
    for (size_t i = 0; ok && i < count; i++) ok = map_write_node(&writer, &nodes[i]);
    if (!ok || !zcl_codec_writer_finish(&writer, written))
        return map_refuse(ZCL_WORK_MAP_WIRE, count);
    return ZCL_WORK_MAP_OK;
}

static bool map_read_node(struct zcl_codec_reader *reader,
                           struct zcl_work_map_node *node)
{
    if (!zcl_codec_read_bytes(reader, node->task_root, 32) ||
        !zcl_codec_read_u16le(reader, &node->kind) ||
        !zcl_codec_read_u16le(reader, &node->parent) ||
        !zcl_codec_read_u16le(reader, &node->dependency_count) ||
        node->dependency_count > ZCL_WORK_MAP_MAX_DEPENDENCIES) return false;
    for (size_t i = 0; i < node->dependency_count; i++)
        if (!zcl_codec_read_u16le(reader, &node->dependencies[i])) return false;
    return true;
}

static bool map_read_header(struct zcl_codec_reader *reader, uint16_t *count)
{
    uint8_t magic[8];
    uint16_t version = 0;
    return zcl_codec_read_bytes(reader, magic, sizeof(magic)) &&
        memcmp(magic, map_magic, sizeof(magic)) == 0 &&
        zcl_codec_read_u16le(reader, &version) && version == 1 &&
        zcl_codec_read_u16le(reader, count) && *count > 0 &&
        *count <= ZCL_WORK_MAP_MAX_NODES;
}

enum zcl_work_map_result zcl_work_map_parse(
    const uint8_t *wire, size_t length, struct zcl_work_map_node *nodes,
    size_t capacity, size_t *count)
{
    if (count) *count = 0;
    if (!wire || !nodes || !count || length > ZCL_WORK_MAP_WIRE_MAX)
        return map_refuse(ZCL_WORK_MAP_BOUNDS, 0);
    struct zcl_codec_reader reader;
    zcl_codec_reader_init(&reader, wire, length);
    uint16_t parsed = 0;
    if (!map_read_header(&reader, &parsed)) return map_refuse(ZCL_WORK_MAP_WIRE, 0);
    if (capacity < parsed) return map_refuse(ZCL_WORK_MAP_BOUNDS, parsed);
    struct zcl_work_map_node decoded[ZCL_WORK_MAP_MAX_NODES] = {0};
    for (size_t i = 0; i < parsed; i++)
        if (!map_read_node(&reader, &decoded[i])) return map_refuse(ZCL_WORK_MAP_WIRE, i);
    if (!zcl_codec_reader_finish(&reader)) return map_refuse(ZCL_WORK_MAP_WIRE, parsed);
    enum zcl_work_map_result valid = zcl_work_map_validate(decoded, parsed);
    if (valid != ZCL_WORK_MAP_OK) return valid;
    memcpy(nodes, decoded, (size_t)parsed * sizeof(*nodes));
    *count = parsed;
    return ZCL_WORK_MAP_OK;
}
