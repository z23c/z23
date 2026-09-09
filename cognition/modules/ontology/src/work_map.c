/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Validate bounded task-map hierarchy and completion dependencies. */
#include "ontology/work_map.h"

#include "base/bytes.h"
#include "base/log_macros.h"

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
