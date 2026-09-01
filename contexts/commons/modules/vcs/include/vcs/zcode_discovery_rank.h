/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Deterministic discovery-only PageRank over ZCODE properties. */

#ifndef ZCL_VCS_ZCODE_DISCOVERY_RANK_H
#define ZCL_VCS_ZCODE_DISCOVERY_RANK_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define VCS_ZCODE_DISCOVERY_RANK_VERSION 1u
#define VCS_ZCODE_DISCOVERY_RANK_MASS UINT64_C(1000000000000)
#define VCS_ZCODE_DISCOVERY_RANK_DAMPING_NUMERATOR 85u
#define VCS_ZCODE_DISCOVERY_RANK_DAMPING_DENOMINATOR 100u
#define VCS_ZCODE_DISCOVERY_RANK_ITERATIONS 32u

#define VCS_ZCODE_DISCOVERY_RANK_MAX_NODES 4096u
#define VCS_ZCODE_DISCOVERY_RANK_MAX_EDGES 65536u
#define VCS_ZCODE_DISCOVERY_RANK_MAX_SEEDS 4096u
#define VCS_ZCODE_DISCOVERY_RANK_MAX_SEED_WEIGHT 1000000u

#define VCS_ZCODE_DISCOVERY_GRAPH_DOMAIN \
    "zcl.zcode.discovery_graph.v1"
#define VCS_ZCODE_DISCOVERY_SEED_SET_DOMAIN \
    "zcl.zcode.discovery_seed_set.v1"
#define VCS_ZCODE_DISCOVERY_RANK_RESULT_DOMAIN \
    "zcl.zcode.discovery_rank_result.v1"

#define VCS_ZCODE_DISCOVERY_RANK_RESULT_HEADER_BYTES 123u
#define VCS_ZCODE_DISCOVERY_RANK_ENTRY_WIRE_BYTES 40u
#define VCS_ZCODE_DISCOVERY_RANK_RESULT_MAX_WIRE_BYTES \
    (VCS_ZCODE_DISCOVERY_RANK_RESULT_HEADER_BYTES + \
     VCS_ZCODE_DISCOVERY_RANK_MAX_NODES * \
         VCS_ZCODE_DISCOVERY_RANK_ENTRY_WIRE_BYTES)

enum vcs_zcode_discovery_rank_error {
    VCS_ZCODE_DISCOVERY_RANK_OK = 0,
    VCS_ZCODE_DISCOVERY_RANK_ERR_NULL,
    VCS_ZCODE_DISCOVERY_RANK_ERR_VERSION,
    VCS_ZCODE_DISCOVERY_RANK_ERR_LIMIT,
    VCS_ZCODE_DISCOVERY_RANK_ERR_ROOT_ZERO,
    VCS_ZCODE_DISCOVERY_RANK_ERR_NODE_DUPLICATE,
    VCS_ZCODE_DISCOVERY_RANK_ERR_EDGE_NODE_MISSING,
    VCS_ZCODE_DISCOVERY_RANK_ERR_EDGE_DUPLICATE,
    VCS_ZCODE_DISCOVERY_RANK_ERR_SEED_NODE_MISSING,
    VCS_ZCODE_DISCOVERY_RANK_ERR_SEED_DUPLICATE,
    VCS_ZCODE_DISCOVERY_RANK_ERR_SEED_WEIGHT,
    VCS_ZCODE_DISCOVERY_RANK_ERR_ALLOCATION,
    VCS_ZCODE_DISCOVERY_RANK_ERR_MASS,
    VCS_ZCODE_DISCOVERY_RANK_ERR_WIRE_SIZE,
    VCS_ZCODE_DISCOVERY_RANK_ERR_WIRE_MAGIC,
    VCS_ZCODE_DISCOVERY_RANK_ERR_ORDER,
    VCS_ZCODE_DISCOVERY_RANK_ERR_COVERAGE,
};

const char *vcs_zcode_discovery_rank_error_string(
    enum vcs_zcode_discovery_rank_error error);

/* Nodes are ZCODE study/package metaverse property roots, never people. */
struct vcs_zcode_discovery_node_v1 {
    uint8_t property_root[32];
};

/* A canonical citation direction: citing_property -> cited_property. */
struct vcs_zcode_discovery_edge_v1 {
    uint8_t citing_property_root[32];
    uint8_t cited_property_root[32];
};

/* Locally trusted signed votes are verified and aggregated before this pure
 * core. A seed weight is local discovery input, never proof or reward input. */
struct vcs_zcode_discovery_seed_v1 {
    uint8_t property_root[32];
    uint32_t weight;
};

struct vcs_zcode_discovery_rank_entry_v1 {
    uint8_t property_root[32];
    uint64_t mass;
};

/* Entries are ordered by mass descending, then full property root ascending.
 * coverage_mass is the exact sum of returned entry mass. */
struct vcs_zcode_discovery_rank_result_v1 {
    uint16_t schema_version;
    uint8_t graph_root[32];
    uint8_t seed_set_root[32];
    uint8_t filter_policy_root[32];
    uint32_t node_count;
    uint32_t entry_count;
    uint64_t coverage_mass;
    bool truncated;
    struct vcs_zcode_discovery_rank_entry_v1 *entries;
};

/* Input order never affects either root. Nodes and seeds must be unique;
 * citations are a set and duplicate edges are rejected. Empty seeds select
 * uniform personalization. */
enum vcs_zcode_discovery_rank_error vcs_zcode_discovery_graph_root(
    const struct vcs_zcode_discovery_node_v1 *nodes, size_t node_count,
    const struct vcs_zcode_discovery_edge_v1 *edges, size_t edge_count,
    uint8_t out[32]);

enum vcs_zcode_discovery_rank_error vcs_zcode_discovery_seed_set_root(
    const struct vcs_zcode_discovery_node_v1 *nodes, size_t node_count,
    const struct vcs_zcode_discovery_seed_v1 *seeds, size_t seed_count,
    uint8_t out[32]);

/* Compute the fixed v1 algorithm. entry_capacity bounds rendered results,
 * not graph computation; a smaller capacity produces explicit truncation. */
enum vcs_zcode_discovery_rank_error vcs_zcode_discovery_rank_compute(
    const struct vcs_zcode_discovery_node_v1 *nodes, size_t node_count,
    const struct vcs_zcode_discovery_edge_v1 *edges, size_t edge_count,
    const struct vcs_zcode_discovery_seed_v1 *seeds, size_t seed_count,
    const uint8_t filter_policy_root[32],
    struct vcs_zcode_discovery_rank_entry_v1 *entries,
    size_t entry_capacity,
    struct vcs_zcode_discovery_rank_result_v1 *out);

enum vcs_zcode_discovery_rank_error vcs_zcode_discovery_rank_result_validate(
    const struct vcs_zcode_discovery_rank_result_v1 *result);
size_t vcs_zcode_discovery_rank_result_wire_size(
    const struct vcs_zcode_discovery_rank_result_v1 *result);
enum vcs_zcode_discovery_rank_error vcs_zcode_discovery_rank_result_serialize(
    const struct vcs_zcode_discovery_rank_result_v1 *result,
    uint8_t *wire, size_t wire_capacity, size_t *wire_len_out);
enum vcs_zcode_discovery_rank_error vcs_zcode_discovery_rank_result_parse(
    const uint8_t *wire, size_t wire_len,
    struct vcs_zcode_discovery_rank_entry_v1 *entries,
    size_t entry_capacity,
    struct vcs_zcode_discovery_rank_result_v1 *out);
enum vcs_zcode_discovery_rank_error vcs_zcode_discovery_rank_result_root(
    const struct vcs_zcode_discovery_rank_result_v1 *result,
    uint8_t out[32]);

#endif /* ZCL_VCS_ZCODE_DISCOVERY_RANK_H */
