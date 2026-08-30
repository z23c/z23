/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Deterministic integer PageRank for ZCODE property discovery. */

#include "vcs/zcode_discovery_rank.h"

#include "base/bytes.h"
#include "base/serialize_le.h"
#include "crypto/sha3.h"
#include "util/safe_alloc.h"

#include <stdlib.h>
#include <string.h>

static const uint8_t rank_result_magic[8] =
    {'Z','C','D','R','A','N','K','\n'};

struct rank_edge_index {
    uint32_t from;
    uint32_t to;
};

struct rank_seed_index {
    uint32_t node;
    uint32_t weight;
};

struct rank_normalized {
    uint8_t (*nodes)[32];
    size_t node_count;
    struct rank_edge_index *edges;
    size_t edge_count;
    struct rank_seed_index *seeds;
    size_t seed_count;
    uint64_t seed_weight_total;
};

struct rank_order_entry {
    uint8_t root[32];
    uint64_t mass;
};

static int rank_root_cmp(const void *a, const void *b)
{
    return memcmp(a, b, 32);
}

static int rank_edge_cmp(const void *a, const void *b)
{
    const struct rank_edge_index *ea = a;
    const struct rank_edge_index *eb = b;
    if (ea->from != eb->from) return ea->from < eb->from ? -1 : 1;
    if (ea->to != eb->to) return ea->to < eb->to ? -1 : 1;
    return 0;
}

static int rank_seed_cmp(const void *a, const void *b)
{
    const struct rank_seed_index *sa = a;
    const struct rank_seed_index *sb = b;
    if (sa->node != sb->node) return sa->node < sb->node ? -1 : 1;
    return 0;
}

static int rank_order_cmp(const void *a, const void *b)
{
    const struct rank_order_entry *ra = a;
    const struct rank_order_entry *rb = b;
    if (ra->mass != rb->mass) return ra->mass > rb->mass ? -1 : 1;
    return memcmp(ra->root, rb->root, 32);
}

static bool rank_find_node(const struct rank_normalized *normalized,
                           const uint8_t root[32], uint32_t *index_out)
{
    size_t lo = 0;
    size_t hi = normalized->node_count;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        int cmp = memcmp(root, normalized->nodes[mid], 32);
        if (cmp == 0) {
            *index_out = (uint32_t)mid;
            return true;
        }
        if (cmp < 0) hi = mid;
        else lo = mid + 1;
    }
    return false;
}

static void rank_normalized_free(struct rank_normalized *normalized)
{
    if (!normalized) return;
    free(normalized->seeds);
    free(normalized->edges);
    free(normalized->nodes);
    memset(normalized, 0, sizeof(*normalized));
}

static enum vcs_zcode_discovery_rank_error rank_normalize(
    const struct vcs_zcode_discovery_node_v1 *nodes, size_t node_count,
    const struct vcs_zcode_discovery_edge_v1 *edges, size_t edge_count,
    const struct vcs_zcode_discovery_seed_v1 *seeds, size_t seed_count,
    struct rank_normalized *out)
{
    if (!out) return VCS_ZCODE_DISCOVERY_RANK_ERR_NULL;
    memset(out, 0, sizeof(*out));
    if (!nodes || node_count == 0)
        return nodes ? VCS_ZCODE_DISCOVERY_RANK_ERR_LIMIT
                     : VCS_ZCODE_DISCOVERY_RANK_ERR_NULL;
    if ((edge_count > 0 && !edges) || (seed_count > 0 && !seeds))
        return VCS_ZCODE_DISCOVERY_RANK_ERR_NULL;
    if (node_count > VCS_ZCODE_DISCOVERY_RANK_MAX_NODES ||
        edge_count > VCS_ZCODE_DISCOVERY_RANK_MAX_EDGES ||
        seed_count > VCS_ZCODE_DISCOVERY_RANK_MAX_SEEDS ||
        seed_count > node_count)
        return VCS_ZCODE_DISCOVERY_RANK_ERR_LIMIT;

    out->nodes = zcl_malloc(node_count * sizeof(*out->nodes),
                            "zcode_discovery_rank_nodes");
    if (!out->nodes) return VCS_ZCODE_DISCOVERY_RANK_ERR_ALLOCATION;
    out->node_count = node_count;
    for (size_t i = 0; i < node_count; i++) {
        if (!zcl_bytes_any_set(nodes[i].property_root, 32)) {
            rank_normalized_free(out);
            return VCS_ZCODE_DISCOVERY_RANK_ERR_ROOT_ZERO;
        }
        memcpy(out->nodes[i], nodes[i].property_root, 32);
    }
    qsort(out->nodes, node_count, sizeof(*out->nodes), rank_root_cmp);
    for (size_t i = 1; i < node_count; i++) {
        if (memcmp(out->nodes[i - 1], out->nodes[i], 32) == 0) {
            rank_normalized_free(out);
            return VCS_ZCODE_DISCOVERY_RANK_ERR_NODE_DUPLICATE;
        }
    }

    if (edge_count > 0) {
        out->edges = zcl_malloc(edge_count * sizeof(*out->edges),
                                "zcode_discovery_rank_edges");
        if (!out->edges) {
            rank_normalized_free(out);
            return VCS_ZCODE_DISCOVERY_RANK_ERR_ALLOCATION;
        }
    }
    out->edge_count = edge_count;
    for (size_t i = 0; i < edge_count; i++) {
        if (!zcl_bytes_any_set(edges[i].citing_property_root, 32) ||
            !zcl_bytes_any_set(edges[i].cited_property_root, 32)) {
            rank_normalized_free(out);
            return VCS_ZCODE_DISCOVERY_RANK_ERR_ROOT_ZERO;
        }
        if (!rank_find_node(out, edges[i].citing_property_root,
                            &out->edges[i].from) ||
            !rank_find_node(out, edges[i].cited_property_root,
                            &out->edges[i].to)) {
            rank_normalized_free(out);
            return VCS_ZCODE_DISCOVERY_RANK_ERR_EDGE_NODE_MISSING;
        }
    }
    /* ISO C permits a zero-element qsort, but glibc annotates base nonnull
     * and UBSan correctly reports passing our intentionally-NULL empty
     * allocation.  There is no ordering work until two elements exist. */
    if (edge_count > 1)
        qsort(out->edges, edge_count, sizeof(*out->edges), rank_edge_cmp);
    for (size_t i = 1; i < edge_count; i++) {
        if (rank_edge_cmp(&out->edges[i - 1], &out->edges[i]) == 0) {
            rank_normalized_free(out);
            return VCS_ZCODE_DISCOVERY_RANK_ERR_EDGE_DUPLICATE;
        }
    }

    if (seed_count > 0) {
        out->seeds = zcl_malloc(seed_count * sizeof(*out->seeds),
                                "zcode_discovery_rank_seeds");
        if (!out->seeds) {
            rank_normalized_free(out);
            return VCS_ZCODE_DISCOVERY_RANK_ERR_ALLOCATION;
        }
    }
    out->seed_count = seed_count;
    for (size_t i = 0; i < seed_count; i++) {
        if (!zcl_bytes_any_set(seeds[i].property_root, 32)) {
            rank_normalized_free(out);
            return VCS_ZCODE_DISCOVERY_RANK_ERR_ROOT_ZERO;
        }
        if (!rank_find_node(out, seeds[i].property_root,
                            &out->seeds[i].node)) {
            rank_normalized_free(out);
            return VCS_ZCODE_DISCOVERY_RANK_ERR_SEED_NODE_MISSING;
        }
        if (seeds[i].weight == 0 ||
            seeds[i].weight > VCS_ZCODE_DISCOVERY_RANK_MAX_SEED_WEIGHT) {
            rank_normalized_free(out);
            return VCS_ZCODE_DISCOVERY_RANK_ERR_SEED_WEIGHT;
        }
        out->seeds[i].weight = seeds[i].weight;
        out->seed_weight_total += seeds[i].weight;
    }
    if (seed_count > 1)
        qsort(out->seeds, seed_count, sizeof(*out->seeds), rank_seed_cmp);
    for (size_t i = 1; i < seed_count; i++) {
        if (out->seeds[i - 1].node == out->seeds[i].node) {
            rank_normalized_free(out);
            return VCS_ZCODE_DISCOVERY_RANK_ERR_SEED_DUPLICATE;
        }
    }
    return VCS_ZCODE_DISCOVERY_RANK_OK;
}

static void rank_hash_u16(struct sha3_256_ctx *sha, uint16_t value)
{
    uint8_t le[2];
    zcl_write_u16_le(le, value);
    sha3_256_write(sha, le, sizeof(le));
}

static void rank_hash_u32(struct sha3_256_ctx *sha, uint32_t value)
{
    uint8_t le[4];
    zcl_write_u32_le(le, value);
    sha3_256_write(sha, le, sizeof(le));
}

static void rank_hash_u64(struct sha3_256_ctx *sha, uint64_t value)
{
    uint8_t le[8];
    zcl_write_u64_le(le, value);
    sha3_256_write(sha, le, sizeof(le));
}

static void rank_graph_hash(const struct rank_normalized *normalized,
                            uint8_t out[32])
{
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)VCS_ZCODE_DISCOVERY_GRAPH_DOMAIN,
                   sizeof(VCS_ZCODE_DISCOVERY_GRAPH_DOMAIN));
    rank_hash_u16(&sha, VCS_ZCODE_DISCOVERY_RANK_VERSION);
    rank_hash_u32(&sha, (uint32_t)normalized->node_count);
    rank_hash_u32(&sha, (uint32_t)normalized->edge_count);
    for (size_t i = 0; i < normalized->node_count; i++)
        sha3_256_write(&sha, normalized->nodes[i], 32);
    for (size_t i = 0; i < normalized->edge_count; i++) {
        sha3_256_write(&sha, normalized->nodes[normalized->edges[i].from], 32);
        sha3_256_write(&sha, normalized->nodes[normalized->edges[i].to], 32);
    }
    sha3_256_finalize(&sha, out);
}

static void rank_seed_hash(const struct rank_normalized *normalized,
                           uint8_t out[32])
{
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    sha3_256_write(&sha,
                   (const uint8_t *)VCS_ZCODE_DISCOVERY_SEED_SET_DOMAIN,
                   sizeof(VCS_ZCODE_DISCOVERY_SEED_SET_DOMAIN));
    rank_hash_u16(&sha, VCS_ZCODE_DISCOVERY_RANK_VERSION);
    rank_hash_u32(&sha, (uint32_t)normalized->seed_count);
    for (size_t i = 0; i < normalized->seed_count; i++) {
        sha3_256_write(&sha, normalized->nodes[normalized->seeds[i].node], 32);
        rank_hash_u32(&sha, normalized->seeds[i].weight);
    }
    sha3_256_finalize(&sha, out);
}

const char *vcs_zcode_discovery_rank_error_string(
    enum vcs_zcode_discovery_rank_error error)
{
    switch (error) {
    case VCS_ZCODE_DISCOVERY_RANK_OK: return "ok";
    case VCS_ZCODE_DISCOVERY_RANK_ERR_NULL: return "null-argument";
    case VCS_ZCODE_DISCOVERY_RANK_ERR_VERSION: return "schema-version";
    case VCS_ZCODE_DISCOVERY_RANK_ERR_LIMIT: return "limit-invalid";
    case VCS_ZCODE_DISCOVERY_RANK_ERR_ROOT_ZERO: return "root-zero";
    case VCS_ZCODE_DISCOVERY_RANK_ERR_NODE_DUPLICATE: return "node-duplicate";
    case VCS_ZCODE_DISCOVERY_RANK_ERR_EDGE_NODE_MISSING:
        return "edge-node-missing";
    case VCS_ZCODE_DISCOVERY_RANK_ERR_EDGE_DUPLICATE: return "edge-duplicate";
    case VCS_ZCODE_DISCOVERY_RANK_ERR_SEED_NODE_MISSING:
        return "seed-node-missing";
    case VCS_ZCODE_DISCOVERY_RANK_ERR_SEED_DUPLICATE: return "seed-duplicate";
    case VCS_ZCODE_DISCOVERY_RANK_ERR_SEED_WEIGHT: return "seed-weight";
    case VCS_ZCODE_DISCOVERY_RANK_ERR_ALLOCATION: return "allocation";
    case VCS_ZCODE_DISCOVERY_RANK_ERR_MASS: return "mass-conservation";
    case VCS_ZCODE_DISCOVERY_RANK_ERR_WIRE_SIZE: return "wire-size";
    case VCS_ZCODE_DISCOVERY_RANK_ERR_WIRE_MAGIC: return "wire-magic";
    case VCS_ZCODE_DISCOVERY_RANK_ERR_ORDER: return "entry-order";
    case VCS_ZCODE_DISCOVERY_RANK_ERR_COVERAGE: return "coverage-invalid";
    }
    return "unknown";
}

enum vcs_zcode_discovery_rank_error vcs_zcode_discovery_graph_root(
    const struct vcs_zcode_discovery_node_v1 *nodes, size_t node_count,
    const struct vcs_zcode_discovery_edge_v1 *edges, size_t edge_count,
    uint8_t out[32])
{
    if (!out) return VCS_ZCODE_DISCOVERY_RANK_ERR_NULL;
    memset(out, 0, 32);
    struct rank_normalized normalized;
    enum vcs_zcode_discovery_rank_error error = rank_normalize(
        nodes, node_count, edges, edge_count, NULL, 0, &normalized);
    if (error != VCS_ZCODE_DISCOVERY_RANK_OK) return error;
    rank_graph_hash(&normalized, out);
    rank_normalized_free(&normalized);
    return VCS_ZCODE_DISCOVERY_RANK_OK;
}

enum vcs_zcode_discovery_rank_error vcs_zcode_discovery_seed_set_root(
    const struct vcs_zcode_discovery_node_v1 *nodes, size_t node_count,
    const struct vcs_zcode_discovery_seed_v1 *seeds, size_t seed_count,
    uint8_t out[32])
{
    if (!out) return VCS_ZCODE_DISCOVERY_RANK_ERR_NULL;
    memset(out, 0, 32);
    struct rank_normalized normalized;
    enum vcs_zcode_discovery_rank_error error = rank_normalize(
        nodes, node_count, NULL, 0, seeds, seed_count, &normalized);
    if (error != VCS_ZCODE_DISCOVERY_RANK_OK) return error;
    rank_seed_hash(&normalized, out);
    rank_normalized_free(&normalized);
    return VCS_ZCODE_DISCOVERY_RANK_OK;
}

static void rank_add_personalization(const struct rank_normalized *normalized,
                                     uint64_t amount, uint64_t *destination)
{
    uint64_t assigned = 0;
    if (normalized->seed_count == 0) {
        uint64_t each = amount / normalized->node_count;
        uint64_t remainder = amount % normalized->node_count;
        for (size_t i = 0; i < normalized->node_count; i++) {
            uint64_t share = each + (i < remainder ? 1u : 0u);
            destination[i] += share;
        }
        return;
    }
    for (size_t i = 0; i < normalized->seed_count; i++) {
        uint64_t share =
            amount * normalized->seeds[i].weight /
            normalized->seed_weight_total;
        destination[normalized->seeds[i].node] += share;
        assigned += share;
    }
    uint64_t remainder = amount - assigned;
    for (size_t i = 0; i < (size_t)remainder; i++)
        destination[normalized->seeds[i].node]++;
}

static uint64_t rank_mass_sum(const uint64_t *mass, size_t count)
{
    uint64_t sum = 0;
    for (size_t i = 0; i < count; i++) sum += mass[i];
    return sum;
}

enum vcs_zcode_discovery_rank_error vcs_zcode_discovery_rank_compute(
    const struct vcs_zcode_discovery_node_v1 *nodes, size_t node_count,
    const struct vcs_zcode_discovery_edge_v1 *edges, size_t edge_count,
    const struct vcs_zcode_discovery_seed_v1 *seeds, size_t seed_count,
    const uint8_t filter_policy_root[32],
    struct vcs_zcode_discovery_rank_entry_v1 *entries,
    size_t entry_capacity,
    struct vcs_zcode_discovery_rank_result_v1 *out)
{
    if (!out || !entries || !filter_policy_root)
        return VCS_ZCODE_DISCOVERY_RANK_ERR_NULL;
    memset(out, 0, sizeof(*out));
    if (entry_capacity == 0 ||
        entry_capacity > VCS_ZCODE_DISCOVERY_RANK_MAX_NODES)
        return VCS_ZCODE_DISCOVERY_RANK_ERR_LIMIT;
    memset(entries, 0, entry_capacity * sizeof(*entries));
    if (!zcl_bytes_any_set(filter_policy_root, 32))
        return VCS_ZCODE_DISCOVERY_RANK_ERR_ROOT_ZERO;

    struct rank_normalized normalized;
    enum vcs_zcode_discovery_rank_error error = rank_normalize(
        nodes, node_count, edges, edge_count, seeds, seed_count, &normalized);
    if (error != VCS_ZCODE_DISCOVERY_RANK_OK) return error;

    uint64_t *current = zcl_calloc(node_count, sizeof(*current),
                                   "zcode_discovery_rank_current");
    uint64_t *next = zcl_calloc(node_count, sizeof(*next),
                                "zcode_discovery_rank_next");
    uint64_t *budgets = zcl_calloc(node_count, sizeof(*budgets),
                                   "zcode_discovery_rank_budgets");
    uint32_t *out_start = zcl_calloc(node_count, sizeof(*out_start),
                                     "zcode_discovery_rank_out_start");
    uint32_t *out_count = zcl_calloc(node_count, sizeof(*out_count),
                                     "zcode_discovery_rank_out_count");
    struct rank_order_entry *order = zcl_malloc(
        node_count * sizeof(*order), "zcode_discovery_rank_order");
    if (!current || !next || !budgets || !out_start || !out_count || !order) {
        error = VCS_ZCODE_DISCOVERY_RANK_ERR_ALLOCATION;
        goto done;
    }

    size_t edge_cursor = 0;
    for (size_t i = 0; i < node_count; i++) {
        out_start[i] = (uint32_t)edge_cursor;
        while (edge_cursor < edge_count &&
               normalized.edges[edge_cursor].from == i) {
            out_count[i]++;
            edge_cursor++;
        }
    }

    rank_add_personalization(&normalized,
                             VCS_ZCODE_DISCOVERY_RANK_MASS, current);
    const uint64_t teleport_mass =
        VCS_ZCODE_DISCOVERY_RANK_MASS *
        (VCS_ZCODE_DISCOVERY_RANK_DAMPING_DENOMINATOR -
         VCS_ZCODE_DISCOVERY_RANK_DAMPING_NUMERATOR) /
        VCS_ZCODE_DISCOVERY_RANK_DAMPING_DENOMINATOR;
    const uint64_t link_mass =
        VCS_ZCODE_DISCOVERY_RANK_MASS - teleport_mass;

    for (size_t iteration = 0;
         iteration < VCS_ZCODE_DISCOVERY_RANK_ITERATIONS; iteration++) {
        memset(next, 0, node_count * sizeof(*next));
        rank_add_personalization(&normalized, teleport_mass, next);
        uint64_t budget_sum = 0;
        for (size_t i = 0; i < node_count; i++) {
            budgets[i] =
                current[i] * VCS_ZCODE_DISCOVERY_RANK_DAMPING_NUMERATOR /
                VCS_ZCODE_DISCOVERY_RANK_DAMPING_DENOMINATOR;
            budget_sum += budgets[i];
        }
        uint64_t source_remainder = link_mass - budget_sum;
        if (source_remainder >= node_count) {
            error = VCS_ZCODE_DISCOVERY_RANK_ERR_MASS;
            goto done;
        }
        for (size_t i = 0; i < (size_t)source_remainder; i++) budgets[i]++;

        for (size_t i = 0; i < node_count; i++) {
            if (out_count[i] == 0) {
                rank_add_personalization(&normalized, budgets[i], next);
                continue;
            }
            uint64_t each = budgets[i] / out_count[i];
            uint64_t remainder = budgets[i] % out_count[i];
            for (size_t j = 0; j < out_count[i]; j++) {
                uint32_t target =
                    normalized.edges[out_start[i] + j].to;
                next[target] += each + (j < remainder ? 1u : 0u);
            }
        }
        if (rank_mass_sum(next, node_count) !=
            VCS_ZCODE_DISCOVERY_RANK_MASS) {
            error = VCS_ZCODE_DISCOVERY_RANK_ERR_MASS;
            goto done;
        }
        uint64_t *swap = current;
        current = next;
        next = swap;
    }

    for (size_t i = 0; i < node_count; i++) {
        memcpy(order[i].root, normalized.nodes[i], 32);
        order[i].mass = current[i];
    }
    qsort(order, node_count, sizeof(*order), rank_order_cmp);
    size_t rendered = node_count < entry_capacity ? node_count : entry_capacity;
    uint64_t coverage = 0;
    for (size_t i = 0; i < rendered; i++) {
        memcpy(entries[i].property_root, order[i].root, 32);
        entries[i].mass = order[i].mass;
        coverage += order[i].mass;
    }
    out->schema_version = VCS_ZCODE_DISCOVERY_RANK_VERSION;
    rank_graph_hash(&normalized, out->graph_root);
    rank_seed_hash(&normalized, out->seed_set_root);
    memcpy(out->filter_policy_root, filter_policy_root, 32);
    out->node_count = (uint32_t)node_count;
    out->entry_count = (uint32_t)rendered;
    out->coverage_mass = coverage;
    out->truncated = rendered < node_count;
    out->entries = entries;
    error = vcs_zcode_discovery_rank_result_validate(out);

done:
    free(order);
    free(out_count);
    free(out_start);
    free(budgets);
    free(next);
    free(current);
    rank_normalized_free(&normalized);
    if (error != VCS_ZCODE_DISCOVERY_RANK_OK) {
        memset(entries, 0, entry_capacity * sizeof(*entries));
        memset(out, 0, sizeof(*out));
    }
    return error;
}

enum vcs_zcode_discovery_rank_error vcs_zcode_discovery_rank_result_validate(
    const struct vcs_zcode_discovery_rank_result_v1 *result)
{
    if (!result || !result->entries)
        return VCS_ZCODE_DISCOVERY_RANK_ERR_NULL;
    if (result->schema_version != VCS_ZCODE_DISCOVERY_RANK_VERSION)
        return VCS_ZCODE_DISCOVERY_RANK_ERR_VERSION;
    if (!zcl_bytes_any_set(result->graph_root, 32) ||
        !zcl_bytes_any_set(result->seed_set_root, 32) ||
        !zcl_bytes_any_set(result->filter_policy_root, 32))
        return VCS_ZCODE_DISCOVERY_RANK_ERR_ROOT_ZERO;
    if (result->node_count == 0 ||
        result->node_count > VCS_ZCODE_DISCOVERY_RANK_MAX_NODES ||
        result->entry_count == 0 || result->entry_count > result->node_count)
        return VCS_ZCODE_DISCOVERY_RANK_ERR_LIMIT;
    if (result->truncated != (result->entry_count < result->node_count))
        return VCS_ZCODE_DISCOVERY_RANK_ERR_COVERAGE;
    uint64_t coverage = 0;
    for (size_t i = 0; i < result->entry_count; i++) {
        const struct vcs_zcode_discovery_rank_entry_v1 *entry =
            &result->entries[i];
        if (!zcl_bytes_any_set(entry->property_root, 32) ||
            entry->mass > VCS_ZCODE_DISCOVERY_RANK_MASS)
            return VCS_ZCODE_DISCOVERY_RANK_ERR_COVERAGE;
        if (i > 0) {
            const struct vcs_zcode_discovery_rank_entry_v1 *previous =
                &result->entries[i - 1];
            if (previous->mass < entry->mass ||
                (previous->mass == entry->mass &&
                 memcmp(previous->property_root, entry->property_root, 32) >= 0))
                return VCS_ZCODE_DISCOVERY_RANK_ERR_ORDER;
        }
        for (size_t j = 0; j < i; j++) {
            if (memcmp(result->entries[j].property_root,
                       entry->property_root, 32) == 0)
                return VCS_ZCODE_DISCOVERY_RANK_ERR_ORDER;
        }
        coverage += entry->mass;
    }
    if (coverage != result->coverage_mass ||
        coverage > VCS_ZCODE_DISCOVERY_RANK_MASS ||
        (!result->truncated &&
         coverage != VCS_ZCODE_DISCOVERY_RANK_MASS))
        return VCS_ZCODE_DISCOVERY_RANK_ERR_COVERAGE;
    return VCS_ZCODE_DISCOVERY_RANK_OK;
}

size_t vcs_zcode_discovery_rank_result_wire_size(
    const struct vcs_zcode_discovery_rank_result_v1 *result)
{
    if (vcs_zcode_discovery_rank_result_validate(result) !=
        VCS_ZCODE_DISCOVERY_RANK_OK)
        return 0;
    return VCS_ZCODE_DISCOVERY_RANK_RESULT_HEADER_BYTES +
           (size_t)result->entry_count *
               VCS_ZCODE_DISCOVERY_RANK_ENTRY_WIRE_BYTES;
}

enum vcs_zcode_discovery_rank_error vcs_zcode_discovery_rank_result_serialize(
    const struct vcs_zcode_discovery_rank_result_v1 *result,
    uint8_t *wire, size_t wire_capacity, size_t *wire_len_out)
{
    if (!wire_len_out) return VCS_ZCODE_DISCOVERY_RANK_ERR_NULL;
    *wire_len_out = 0;
    enum vcs_zcode_discovery_rank_error error =
        vcs_zcode_discovery_rank_result_validate(result);
    if (error != VCS_ZCODE_DISCOVERY_RANK_OK) return error;
    if (!wire) return VCS_ZCODE_DISCOVERY_RANK_ERR_NULL;
    size_t need = VCS_ZCODE_DISCOVERY_RANK_RESULT_HEADER_BYTES +
                  (size_t)result->entry_count *
                      VCS_ZCODE_DISCOVERY_RANK_ENTRY_WIRE_BYTES;
    if (wire_capacity < need) return VCS_ZCODE_DISCOVERY_RANK_ERR_WIRE_SIZE;
    size_t off = 0;
    memcpy(wire + off, rank_result_magic, sizeof(rank_result_magic));
    off += sizeof(rank_result_magic);
    zcl_write_u16_le(wire + off, result->schema_version); off += 2;
    memcpy(wire + off, result->graph_root, 32); off += 32;
    memcpy(wire + off, result->seed_set_root, 32); off += 32;
    memcpy(wire + off, result->filter_policy_root, 32); off += 32;
    zcl_write_u32_le(wire + off, result->node_count); off += 4;
    zcl_write_u32_le(wire + off, result->entry_count); off += 4;
    zcl_write_u64_le(wire + off, result->coverage_mass); off += 8;
    wire[off++] = result->truncated ? 1u : 0u;
    for (size_t i = 0; i < result->entry_count; i++) {
        memcpy(wire + off, result->entries[i].property_root, 32); off += 32;
        zcl_write_u64_le(wire + off, result->entries[i].mass); off += 8;
    }
    if (off != need) return VCS_ZCODE_DISCOVERY_RANK_ERR_WIRE_SIZE;
    *wire_len_out = need;
    return VCS_ZCODE_DISCOVERY_RANK_OK;
}

enum vcs_zcode_discovery_rank_error vcs_zcode_discovery_rank_result_parse(
    const uint8_t *wire, size_t wire_len,
    struct vcs_zcode_discovery_rank_entry_v1 *entries,
    size_t entry_capacity,
    struct vcs_zcode_discovery_rank_result_v1 *out)
{
    if (!wire || !entries || !out) return VCS_ZCODE_DISCOVERY_RANK_ERR_NULL;
    memset(entries, 0, entry_capacity * sizeof(*entries));
    memset(out, 0, sizeof(*out));
    if (wire_len < VCS_ZCODE_DISCOVERY_RANK_RESULT_HEADER_BYTES)
        return VCS_ZCODE_DISCOVERY_RANK_ERR_WIRE_SIZE;
    if (memcmp(wire, rank_result_magic, sizeof(rank_result_magic)) != 0)
        return VCS_ZCODE_DISCOVERY_RANK_ERR_WIRE_MAGIC;
    size_t off = sizeof(rank_result_magic);
    out->schema_version = zcl_read_u16_le(wire + off); off += 2;
    memcpy(out->graph_root, wire + off, 32); off += 32;
    memcpy(out->seed_set_root, wire + off, 32); off += 32;
    memcpy(out->filter_policy_root, wire + off, 32); off += 32;
    out->node_count = zcl_read_u32_le(wire + off); off += 4;
    out->entry_count = zcl_read_u32_le(wire + off); off += 4;
    out->coverage_mass = zcl_read_u64_le(wire + off); off += 8;
    uint8_t truncated = wire[off++];
    if (truncated > 1u || out->entry_count > entry_capacity ||
        out->entry_count > VCS_ZCODE_DISCOVERY_RANK_MAX_NODES) {
        memset(out, 0, sizeof(*out));
        return truncated > 1u ? VCS_ZCODE_DISCOVERY_RANK_ERR_COVERAGE
                              : VCS_ZCODE_DISCOVERY_RANK_ERR_LIMIT;
    }
    size_t expected = VCS_ZCODE_DISCOVERY_RANK_RESULT_HEADER_BYTES +
                      (size_t)out->entry_count *
                          VCS_ZCODE_DISCOVERY_RANK_ENTRY_WIRE_BYTES;
    if (wire_len != expected) {
        memset(out, 0, sizeof(*out));
        return VCS_ZCODE_DISCOVERY_RANK_ERR_WIRE_SIZE;
    }
    out->truncated = truncated != 0;
    out->entries = entries;
    for (size_t i = 0; i < out->entry_count; i++) {
        memcpy(entries[i].property_root, wire + off, 32); off += 32;
        entries[i].mass = zcl_read_u64_le(wire + off); off += 8;
    }
    enum vcs_zcode_discovery_rank_error error =
        vcs_zcode_discovery_rank_result_validate(out);
    if (error != VCS_ZCODE_DISCOVERY_RANK_OK) {
        memset(entries, 0, entry_capacity * sizeof(*entries));
        memset(out, 0, sizeof(*out));
    }
    return error;
}

enum vcs_zcode_discovery_rank_error vcs_zcode_discovery_rank_result_root(
    const struct vcs_zcode_discovery_rank_result_v1 *result,
    uint8_t out[32])
{
    if (!out) return VCS_ZCODE_DISCOVERY_RANK_ERR_NULL;
    memset(out, 0, 32);
    enum vcs_zcode_discovery_rank_error error =
        vcs_zcode_discovery_rank_result_validate(result);
    if (error != VCS_ZCODE_DISCOVERY_RANK_OK) return error;
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    sha3_256_write(&sha,
                   (const uint8_t *)VCS_ZCODE_DISCOVERY_RANK_RESULT_DOMAIN,
                   sizeof(VCS_ZCODE_DISCOVERY_RANK_RESULT_DOMAIN));
    sha3_256_write(&sha, rank_result_magic, sizeof(rank_result_magic));
    rank_hash_u16(&sha, result->schema_version);
    sha3_256_write(&sha, result->graph_root, 32);
    sha3_256_write(&sha, result->seed_set_root, 32);
    sha3_256_write(&sha, result->filter_policy_root, 32);
    rank_hash_u32(&sha, result->node_count);
    rank_hash_u32(&sha, result->entry_count);
    rank_hash_u64(&sha, result->coverage_mass);
    uint8_t truncated = result->truncated ? 1u : 0u;
    sha3_256_write(&sha, &truncated, 1);
    for (size_t i = 0; i < result->entry_count; i++) {
        sha3_256_write(&sha, result->entries[i].property_root, 32);
        rank_hash_u64(&sha, result->entries[i].mass);
    }
    sha3_256_finalize(&sha, out);
    return VCS_ZCODE_DISCOVERY_RANK_OK;
}
