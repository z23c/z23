/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Bounded hierarchy metadata over existing canonical task roots. */
#ifndef ZCL_ONTOLOGY_WORK_MAP_H
#define ZCL_ONTOLOGY_WORK_MAP_H

#include <stddef.h>
#include <stdint.h>

enum {
    ZCL_WORK_MAP_MAX_NODES = 204,
    ZCL_WORK_MAP_MAX_DEPENDENCIES = 16,
    ZCL_WORK_MAP_NO_PARENT = UINT16_MAX,
    ZCL_WORK_MAP_WIRE_MAX = 12 + ZCL_WORK_MAP_MAX_NODES *
        (38 + 2 * ZCL_WORK_MAP_MAX_DEPENDENCIES),
};

enum zcl_work_map_kind {
    ZCL_WORK_MAP_MILESTONE = 1,
    ZCL_WORK_MAP_FEATURE,
    ZCL_WORK_MAP_LOOP,
};

/* The task root is the node identity. For a parent it names that parent's
 * integration acceptance. Indices refer only to this complete admitted map.
 * This inert definition carries no execution status or acceptance authority. */
struct zcl_work_map_node {
    uint8_t task_root[32];
    uint16_t kind;
    uint16_t parent;
    uint16_t dependency_count;
    uint16_t dependencies[ZCL_WORK_MAP_MAX_DEPENDENCIES];
};

enum zcl_work_map_result {
    ZCL_WORK_MAP_OK = 0,
    ZCL_WORK_MAP_BOUNDS,
    ZCL_WORK_MAP_IDENTITY,
    ZCL_WORK_MAP_HIERARCHY,
    ZCL_WORK_MAP_DEPENDENCY,
    ZCL_WORK_MAP_CYCLE,
    ZCL_WORK_MAP_WIRE,
};

/* Validate metadata only, without object IO, allocation or mutation. Every task must
 * still be independently resolved and its evidence qualified by the owning
 * authority. Completion dependencies include parent -> child edges as well
 * as explicit prerequisites, so a child cannot depend on its own parent. */
enum zcl_work_map_result zcl_work_map_validate(
    const struct zcl_work_map_node *nodes, size_t count);

/* Inert v1 wire: eight-byte Z23WMAP\n magic, u16le version/count, then
 * ordered nodes (root[32], u16le kind/parent/dependency_count, followed by
 * that many u16le dependency indices). Unused struct storage is not encoded.
 * Both directions validate the full graph. Failure sets the output length
 * or count to zero; parsing leaves nodes untouched. No CAS or evidence IO. */
enum zcl_work_map_result zcl_work_map_serialize(
    const struct zcl_work_map_node *nodes, size_t count,
    uint8_t *wire, size_t capacity, size_t *written);
enum zcl_work_map_result zcl_work_map_parse(
    const uint8_t *wire, size_t length, struct zcl_work_map_node *nodes,
    size_t capacity, size_t *count);

#endif /* ZCL_ONTOLOGY_WORK_MAP_H */
