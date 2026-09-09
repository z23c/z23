/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Reverify bounded task-map bytes from existing workspace CAS. */
#include "command/native_zcode_work_map.h"

#include "base/log_macros.h"
#include "sha3/sha3.h"
#include "vcs/vcs_object.h"

#include <stdlib.h>
#include <string.h>

enum zcl_work_map_result zcl_native_work_map_load(
    const char *workspace, const uint8_t root[32],
    struct zcl_work_map_node *nodes, size_t capacity, size_t *count)
{
    if (count) *count = 0;
    if (!workspace || !workspace[0] || !root || !nodes || !count) {
        LOG_ERROR("work_map", "CAS read requires workspace, root and output");
        return ZCL_WORK_MAP_BOUNDS;
    }
    uint8_t *wire = NULL;
    size_t length = 0;
    int loaded = vcs_object_load_raw_bounded(
        workspace, root, ZCL_WORK_MAP_WIRE_MAX, &wire, &length);
    if (loaded != 0) {
        free(wire);
        LOG_ERROR("work_map", "bounded CAS map read failed: code=%d", loaded);
        return loaded == -2 ? ZCL_WORK_MAP_BOUNDS : ZCL_WORK_MAP_OBJECT;
    }
    uint8_t checked[32];
    sha3_256(wire, length, checked);
    enum zcl_work_map_result result = ZCL_WORK_MAP_IDENTITY;
    if (memcmp(root, checked, 32) == 0)
        result = zcl_work_map_parse(wire, length, nodes, capacity, count);
    else
        LOG_ERROR("work_map", "CAS map bytes do not match the requested root");
    free(wire);
    return result;
}
