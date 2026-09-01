/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Golden graphs for deterministic ZCODE discovery PageRank. */

#include "test/test_core.h"

#include "base/hex.h"
#include "util/safe_alloc.h"
#include "vcs/zcode_discovery_rank.h"

#include <stdio.h>
#include <string.h>

static void zdr_root(uint8_t root[32], uint8_t value)
{
    memset(root, value, 32);
}

static void zdr_node(struct vcs_zcode_discovery_node_v1 *node, uint8_t value)
{
    zdr_root(node->property_root, value);
}

static void zdr_edge(struct vcs_zcode_discovery_edge_v1 *edge,
                     uint8_t from, uint8_t to)
{
    zdr_root(edge->citing_property_root, from);
    zdr_root(edge->cited_property_root, to);
}

static void zdr_seed(struct vcs_zcode_discovery_seed_v1 *seed,
                     uint8_t node, uint32_t weight)
{
    zdr_root(seed->property_root, node);
    seed->weight = weight;
}

static uint64_t zdr_sum(
    const struct vcs_zcode_discovery_rank_entry_v1 *entries, size_t count)
{
    uint64_t sum = 0;
    for (size_t i = 0; i < count; i++) sum += entries[i].mass;
    return sum;
}

static int test_zdr_golden_and_order(void)
{
    int failures = 0;
    TEST("zcode discovery rank: golden graph is order-invariant") {
        struct vcs_zcode_discovery_node_v1 nodes[4], reversed_nodes[4];
        struct vcs_zcode_discovery_edge_v1 edges[4], reversed_edges[4];
        struct vcs_zcode_discovery_seed_v1 seeds[2], reversed_seeds[2];
        const uint8_t node_values[4] = {3, 1, 4, 2};
        for (size_t i = 0; i < 4; i++) {
            zdr_node(&nodes[i], node_values[i]);
            zdr_node(&reversed_nodes[3 - i], node_values[i]);
        }
        zdr_edge(&edges[0], 1, 2);
        zdr_edge(&edges[1], 1, 3);
        zdr_edge(&edges[2], 2, 3);
        zdr_edge(&edges[3], 3, 1); /* node 4 is dangling */
        for (size_t i = 0; i < 4; i++) reversed_edges[3 - i] = edges[i];
        zdr_seed(&seeds[0], 1, 1);
        zdr_seed(&seeds[1], 4, 3);
        reversed_seeds[0] = seeds[1];
        reversed_seeds[1] = seeds[0];
        uint8_t filter_root[32];
        zdr_root(filter_root, 9);

        struct vcs_zcode_discovery_rank_entry_v1 entries[4], entries2[4];
        struct vcs_zcode_discovery_rank_result_v1 result, result2;
        ASSERT_EQ(vcs_zcode_discovery_rank_compute(
                      nodes, 4, edges, 4, seeds, 2, filter_root,
                      entries, 4, &result), VCS_ZCODE_DISCOVERY_RANK_OK);
        ASSERT_EQ(vcs_zcode_discovery_rank_compute(
                      reversed_nodes, 4, reversed_edges, 4,
                      reversed_seeds, 2, filter_root,
                      entries2, 4, &result2), VCS_ZCODE_DISCOVERY_RANK_OK);
        ASSERT_EQ(result.coverage_mass, VCS_ZCODE_DISCOVERY_RANK_MASS);
        ASSERT_EQ(zdr_sum(entries, 4), VCS_ZCODE_DISCOVERY_RANK_MASS);
        ASSERT(!result.truncated);
        ASSERT(memcmp(result.graph_root, result2.graph_root, 32) == 0);
        ASSERT(memcmp(result.seed_set_root, result2.seed_set_root, 32) == 0);
        ASSERT(memcmp(entries, entries2, sizeof(entries)) == 0);

        uint8_t result_root[32], result_root2[32];
        char graph_hex[65], seed_hex[65], result_hex[65];
        ASSERT_EQ(vcs_zcode_discovery_rank_result_root(&result, result_root),
                  VCS_ZCODE_DISCOVERY_RANK_OK);
        ASSERT_EQ(vcs_zcode_discovery_rank_result_root(&result2, result_root2),
                  VCS_ZCODE_DISCOVERY_RANK_OK);
        ASSERT(memcmp(result_root, result_root2, 32) == 0);
        zcl_hex_encode(result.graph_root, 32, graph_hex);
        zcl_hex_encode(result.seed_set_root, 32, seed_hex);
        zcl_hex_encode(result_root, 32, result_hex);
        ASSERT_STR_EQ(graph_hex,
            "c33a5854a3b152d75a1e666b5ac4f16f57cc8a95036212ed16b00a135faaf0e3");
        ASSERT_STR_EQ(seed_hex,
            "ad36e17b2b3ae4444a81dac0e5eabcc124dc16c7605db9d3f4488794dbf51097");
        ASSERT_STR_EQ(result_hex,
            "f4d130e40dd5394295448f3473b2e82a6ee36b5eec51441fc6e3a1879848b231");
        PASS();
    } _test_next:;
    return failures;
}

static int test_zdr_cycles_dangling_and_seeds(void)
{
    int failures = 0;
    TEST("zcode discovery rank: cycles, dangling nodes, and seeds conserve mass") {
        struct vcs_zcode_discovery_node_v1 nodes[3];
        struct vcs_zcode_discovery_edge_v1 cycle[3];
        for (size_t i = 0; i < 3; i++) zdr_node(&nodes[i], (uint8_t)(i + 1));
        zdr_edge(&cycle[0], 1, 2);
        zdr_edge(&cycle[1], 2, 3);
        zdr_edge(&cycle[2], 3, 1);
        uint8_t filter_root[32];
        zdr_root(filter_root, 7);
        struct vcs_zcode_discovery_rank_entry_v1 uniform[3], dangling[3];
        struct vcs_zcode_discovery_rank_result_v1 result, dangling_result;
        ASSERT_EQ(vcs_zcode_discovery_rank_compute(
                      nodes, 3, cycle, 3, NULL, 0, filter_root,
                      uniform, 3, &result), VCS_ZCODE_DISCOVERY_RANK_OK);
        ASSERT_EQ(zdr_sum(uniform, 3), VCS_ZCODE_DISCOVERY_RANK_MASS);
        ASSERT(uniform[0].mass >= uniform[2].mass);
        ASSERT(uniform[0].mass - uniform[2].mass <= 1);

        ASSERT_EQ(vcs_zcode_discovery_rank_compute(
                      nodes, 3, NULL, 0, NULL, 0, filter_root,
                      dangling, 3, &dangling_result),
                  VCS_ZCODE_DISCOVERY_RANK_OK);
        ASSERT_EQ(zdr_sum(dangling, 3), VCS_ZCODE_DISCOVERY_RANK_MASS);
        ASSERT(dangling[0].mass >= dangling[2].mass);
        ASSERT(dangling[0].mass - dangling[2].mass <= 1);

        struct vcs_zcode_discovery_seed_v1 seed;
        zdr_seed(&seed, 3, 1);
        struct vcs_zcode_discovery_rank_entry_v1 personalized[3];
        struct vcs_zcode_discovery_rank_result_v1 personalized_result;
        ASSERT_EQ(vcs_zcode_discovery_rank_compute(
                      nodes, 3, cycle, 3, &seed, 1, filter_root,
                      personalized, 3, &personalized_result),
                  VCS_ZCODE_DISCOVERY_RANK_OK);
        ASSERT_EQ(zdr_sum(personalized, 3), VCS_ZCODE_DISCOVERY_RANK_MASS);
        ASSERT(memcmp(result.seed_set_root,
                      personalized_result.seed_set_root, 32) != 0);
        ASSERT(memcmp(uniform, personalized, sizeof(uniform)) != 0);
        PASS();
    } _test_next:;
    return failures;
}

static int test_zdr_wire_and_truncation(void)
{
    int failures = 0;
    TEST("zcode discovery rank: result wire binds coverage and truncation") {
        struct vcs_zcode_discovery_node_v1 nodes[4];
        struct vcs_zcode_discovery_edge_v1 edges[4];
        for (size_t i = 0; i < 4; i++) zdr_node(&nodes[i], (uint8_t)(i + 1));
        zdr_edge(&edges[0], 1, 2);
        zdr_edge(&edges[1], 2, 1);
        zdr_edge(&edges[2], 3, 1);
        zdr_edge(&edges[3], 4, 1);
        uint8_t filter_root[32];
        zdr_root(filter_root, 8);
        struct vcs_zcode_discovery_rank_entry_v1 entries[2], parsed_entries[2];
        struct vcs_zcode_discovery_rank_result_v1 result, parsed;
        ASSERT_EQ(vcs_zcode_discovery_rank_compute(
                      nodes, 4, edges, 4, NULL, 0, filter_root,
                      entries, 2, &result), VCS_ZCODE_DISCOVERY_RANK_OK);
        ASSERT(result.truncated);
        ASSERT_EQ(result.entry_count, 2);
        ASSERT(result.coverage_mass < VCS_ZCODE_DISCOVERY_RANK_MASS);
        ASSERT_EQ(result.coverage_mass, zdr_sum(entries, 2));

        uint8_t wire[512];
        size_t wire_len = 0;
        ASSERT_EQ(vcs_zcode_discovery_rank_result_serialize(
                      &result, wire, sizeof(wire), &wire_len),
                  VCS_ZCODE_DISCOVERY_RANK_OK);
        ASSERT_EQ(wire_len, VCS_ZCODE_DISCOVERY_RANK_RESULT_HEADER_BYTES +
                            2 * VCS_ZCODE_DISCOVERY_RANK_ENTRY_WIRE_BYTES);
        ASSERT(memcmp(wire, "ZCDRANK\n", 8) == 0);
        ASSERT_EQ(vcs_zcode_discovery_rank_result_parse(
                      wire, wire_len, parsed_entries, 2, &parsed),
                  VCS_ZCODE_DISCOVERY_RANK_OK);
        ASSERT_EQ(parsed.coverage_mass, result.coverage_mass);
        ASSERT(memcmp(parsed.entries, result.entries,
                      2 * sizeof(*entries)) == 0);
        ASSERT_EQ(vcs_zcode_discovery_rank_result_parse(
                      wire, wire_len + 1, parsed_entries, 2, &parsed),
                  VCS_ZCODE_DISCOVERY_RANK_ERR_WIRE_SIZE);
        wire[VCS_ZCODE_DISCOVERY_RANK_RESULT_HEADER_BYTES - 1] = 0;
        ASSERT_EQ(vcs_zcode_discovery_rank_result_parse(
                      wire, wire_len, parsed_entries, 2, &parsed),
                  VCS_ZCODE_DISCOVERY_RANK_ERR_COVERAGE);
        PASS();
    } _test_next:;
    return failures;
}

static int test_zdr_rejections(void)
{
    int failures = 0;
    TEST("zcode discovery rank: malformed graphs and vote spam fail closed") {
        struct vcs_zcode_discovery_node_v1 nodes[2];
        zdr_node(&nodes[0], 1);
        zdr_node(&nodes[1], 2);
        struct vcs_zcode_discovery_edge_v1 edges[2];
        zdr_edge(&edges[0], 1, 2);
        edges[1] = edges[0];
        uint8_t root[32];
        ASSERT_EQ(vcs_zcode_discovery_graph_root(nodes, 2, edges, 2, root),
                  VCS_ZCODE_DISCOVERY_RANK_ERR_EDGE_DUPLICATE);
        zdr_edge(&edges[1], 2, 3);
        ASSERT_EQ(vcs_zcode_discovery_graph_root(nodes, 2, edges, 2, root),
                  VCS_ZCODE_DISCOVERY_RANK_ERR_EDGE_NODE_MISSING);
        nodes[1] = nodes[0];
        ASSERT_EQ(vcs_zcode_discovery_graph_root(nodes, 2, NULL, 0, root),
                  VCS_ZCODE_DISCOVERY_RANK_ERR_NODE_DUPLICATE);
        zdr_node(&nodes[1], 2);

        struct vcs_zcode_discovery_seed_v1 seeds[2];
        zdr_seed(&seeds[0], 1, 1);
        seeds[1] = seeds[0];
        ASSERT_EQ(vcs_zcode_discovery_seed_set_root(nodes, 2, seeds, 2, root),
                  VCS_ZCODE_DISCOVERY_RANK_ERR_SEED_DUPLICATE);
        zdr_seed(&seeds[1], 2, 0);
        ASSERT_EQ(vcs_zcode_discovery_seed_set_root(nodes, 2, seeds, 2, root),
                  VCS_ZCODE_DISCOVERY_RANK_ERR_SEED_WEIGHT);
        zdr_seed(&seeds[1], 3, 1);
        ASSERT_EQ(vcs_zcode_discovery_seed_set_root(nodes, 2, seeds, 2, root),
                  VCS_ZCODE_DISCOVERY_RANK_ERR_SEED_NODE_MISSING);
        PASS();
    } _test_next:;
    return failures;
}

static int test_zdr_filter_and_oom(void)
{
    int failures = 0;
    TEST("zcode discovery rank: filters bind output and allocation failure is explicit") {
        struct vcs_zcode_discovery_node_v1 nodes[2];
        zdr_node(&nodes[0], 1);
        zdr_node(&nodes[1], 2);
        struct vcs_zcode_discovery_edge_v1 edge;
        zdr_edge(&edge, 1, 2);
        uint8_t filter_a[32], filter_b[32], root_a[32], root_b[32];
        zdr_root(filter_a, 6);
        zdr_root(filter_b, 7);
        struct vcs_zcode_discovery_rank_entry_v1 entries_a[2], entries_b[2];
        struct vcs_zcode_discovery_rank_result_v1 result_a, result_b;
        ASSERT_EQ(vcs_zcode_discovery_rank_compute(
                      nodes, 2, &edge, 1, NULL, 0, filter_a,
                      entries_a, 2, &result_a), VCS_ZCODE_DISCOVERY_RANK_OK);
        ASSERT_EQ(vcs_zcode_discovery_rank_compute(
                      nodes, 2, &edge, 1, NULL, 0, filter_b,
                      entries_b, 2, &result_b), VCS_ZCODE_DISCOVERY_RANK_OK);
        ASSERT(memcmp(entries_a, entries_b, sizeof(entries_a)) == 0);
        ASSERT_EQ(vcs_zcode_discovery_rank_result_root(&result_a, root_a),
                  VCS_ZCODE_DISCOVERY_RANK_OK);
        ASSERT_EQ(vcs_zcode_discovery_rank_result_root(&result_b, root_b),
                  VCS_ZCODE_DISCOVERY_RANK_OK);
        ASSERT(memcmp(root_a, root_b, 32) != 0);

        zcl_alloc_fault_fail_next("zcode_discovery_rank_nodes");
        ASSERT_EQ(vcs_zcode_discovery_rank_compute(
                      nodes, 2, &edge, 1, NULL, 0, filter_a,
                      entries_a, 2, &result_a),
                  VCS_ZCODE_DISCOVERY_RANK_ERR_ALLOCATION);
        ASSERT_EQ(result_a.schema_version, 0);
        zcl_alloc_fault_clear();
        PASS();
    } _test_next:;
    zcl_alloc_fault_clear();
    return failures;
}

int test_zcode_discovery_rank(void)
{
    int failures = 0;
    failures += test_zdr_golden_and_order();
    failures += test_zdr_cycles_dangling_and_seeds();
    failures += test_zdr_wire_and_truncation();
    failures += test_zdr_rejections();
    failures += test_zdr_filter_and_oom();
    printf("=== zcode_discovery_rank: %d failures ===\n", failures);
    return failures;
}
