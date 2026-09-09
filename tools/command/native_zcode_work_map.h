/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Verified map inputs for native Commons work projections. */
#ifndef ZCL_COMMAND_NATIVE_ZCODE_WORK_MAP_H
#define ZCL_COMMAND_NATIVE_ZCODE_WORK_MAP_H

#include "ontology/work_map.h"

/* Read existing CAS only; never creates a workspace or accepts a task.
 * Reverify SHA3(wire) against root before parsing the complete map. Failed
 * reads set count to zero and leave nodes untouched. Missing/read failures
 * are OBJECT, oversize is BOUNDS, hash mismatch is IDENTITY; malformed
 * metadata retains the validator's specific refusal. */
enum zcl_work_map_result zcl_native_work_map_load(
    const char *workspace, const uint8_t root[32],
    struct zcl_work_map_node *nodes, size_t capacity, size_t *count);

#endif /* ZCL_COMMAND_NATIVE_ZCODE_WORK_MAP_H */
