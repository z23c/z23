/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * zcode_discovery_projection — the rebuildable discovery-graph projection
 * that adapts the S3 science index/workspace CAS to the S5 pure rank core
 * (vcs/zcode_discovery_rank.h). Like zcode_science_index it is a
 * REBUILDABLE PROJECTION: the canonical CAS wires stay authoritative, this
 * layer holds no truth of its own, and the same CAS content always produces
 * byte-identical graph and seed-set roots.
 *
 * LOCAL AND EXPLANATORY ONLY. Nothing in this file is consulted by evidence
 * admission (zcode_science_service), routing, rewards, elections, or any
 * protocol-control path; ranking, votes, and mass never feed proof
 * acceptance. The projection is a read-only consumer of the index and the
 * CAS: it writes nothing.
 *
 * Graph semantics (v1):
 *   - A discoverable PROPERTY is one study lineage. Lineage membership
 *     follows the zcode_dev lineage recording: a study binds its exact
 *     source_root, and candidates referenced by the study's projected
 *     results link source versions through base_source_root ->
 *     candidate_source_root. Members (study roots, source roots, candidate
 *     source roots) sharing one union-find set collapse to ONE node; the
 *     node root is the smallest member root. Two versions or two forks of
 *     one lineage therefore rank as one node.
 *   - Canonical citations are edges. A study's citations_root commits a
 *     citation-set object (below); each cited root that resolves to an
 *     admitted lineage produces one citing -> cited edge. Per citing node
 *     at most VCS_ZCODE_DISCOVERY_PROJECTION_MAX_NODE_CITATIONS edges are
 *     admitted (the citation-spam cap); the rest are omitted ascending and
 *     counted.
 *   - Seed weights come from curation votes, verified HERE (the index never
 *     verifies signatures): only votes whose seal verifies against the
 *     caller's network genesis, that are unexpired at now_unix, that carry
 *     a positive signal (USEFUL = 2, INTERESTING = 1; FLAG is never a
 *     seed), and that are not replays become seeds — one vote per voter per
 *     lineage and one per voter+sequence, with the first VALID vote in the
 *     index's vote-id order winning each slot. Weights aggregate per node
 *     and cap at VCS_ZCODE_DISCOVERY_RANK_MAX_SEED_WEIGHT.
 *
 * Determinism contract: every iteration order below is either the index's
 * root-sorted order or an explicit ascending sort, so object-admission
 * order, filesystem order, and vote arrival order never move any root. */

#ifndef ZCL_VCS_ZCODE_DISCOVERY_PROJECTION_H
#define ZCL_VCS_ZCODE_DISCOVERY_PROJECTION_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "vcs/zcode_discovery_rank.h"

struct vcs_zcode_science_index; /* opaque; see vcs/zcode_science_index.h */

#define VCS_ZCODE_DISCOVERY_PROJECTION_VERSION 1u

/* Citation-spam cap: distinct citation edges admitted per citing node.
 * Edges beyond it are omitted deterministically (cited root ascending) and
 * counted in omitted_edge_count. */
#define VCS_ZCODE_DISCOVERY_PROJECTION_MAX_NODE_CITATIONS 64u

/* A citation-set object is count*32 payload bytes holding the cited roots
 * in canonical (ascending, duplicate-free) order; the study's
 * citations_root is SHA3-256(domain || payload). Larger or non-canonical
 * payloads are not citation sets and contribute no edges. */
#define VCS_ZCODE_DISCOVERY_PROJECTION_MAX_CITATION_SET 4096u

#define VCS_ZCODE_DISCOVERY_CITATION_SET_DOMAIN \
    "zcl.zcode.discovery_citation_set.v1"
#define VCS_ZCODE_DISCOVERY_CORPUS_DOMAIN \
    "zcl.zcode.discovery_corpus.v1"
#define VCS_ZCODE_DISCOVERY_FILTER_DOMAIN \
    "zcl.zcode.discovery_filter.v1"

/* Per-vote seed weights by curation signal. */
#define VCS_ZCODE_DISCOVERY_PROJECTION_WEIGHT_USEFUL 2u
#define VCS_ZCODE_DISCOVERY_PROJECTION_WEIGHT_INTERESTING 1u

/* One collapsed study lineage (a candidate property node). members holds
 * every root that names this lineage: study roots, study source roots, and
 * the base/candidate source roots of candidates referenced by the lineage's
 * projected results. citations holds the canonical cited roots gathered
 * from the lineage's studies (unresolved here; assembly maps them onto
 * admitted nodes). */
struct vcs_zcode_discovery_lineage_v1 {
    uint8_t (*members)[32];
    size_t member_count;
    uint8_t (*citations)[32];
    size_t citation_count;
    uint32_t study_count;
    uint32_t seed_weight; /* aggregated verified votes, uncapped */
};

/* The scan output: the corpus snapshot plus every filtered lineage. */
struct vcs_zcode_discovery_scan_v1 {
    uint8_t corpus_root[32];
    struct vcs_zcode_discovery_lineage_v1 *lineages;
    size_t lineage_count;
    uint32_t votes_considered; /* index votes inspected */
    uint32_t votes_accepted;   /* votes that became seed weight */
};

/* The assembled bounded graph, ready for the pure rank core. nodes are
 * sorted ascending by root; edges are sorted by (citing, cited); seeds are
 * in node order. in_degree and node_seed_weight are parallel to nodes and
 * feed the per-entry explanation (direct citation count, seed weight). */
struct vcs_zcode_discovery_graph_v1 {
    struct vcs_zcode_discovery_node_v1 *nodes;
    size_t node_count;
    struct vcs_zcode_discovery_edge_v1 *edges;
    size_t edge_count;
    struct vcs_zcode_discovery_seed_v1 *seeds;
    size_t seed_count;
    uint32_t *in_degree;
    uint32_t *node_seed_weight;
    uint32_t omitted_node_count; /* lineages beyond the 4096-node bound */
    uint32_t omitted_edge_count; /* spam-capped + dangling-endpoint edges */
};

/* Canonical citation-set encoding: sorts a copy of roots ascending, drops
 * duplicates, writes the payload (out_payload capacity root_count*32) and
 * the commitment root SHA3-256(domain || payload). False on NULL, zero, or
 * over-bound input. */
bool vcs_zcode_discovery_citation_set_encode(
    const uint8_t *roots, size_t root_count, uint8_t *out_payload,
    size_t *out_count, uint8_t out_root[32]);

/* The corpus snapshot root: SHA3-256 over every projected section root of
 * the science index, in the index's own sorted order. Binds exactly the
 * scanned corpus — the same CAS content always yields the same root. */
bool vcs_zcode_discovery_corpus_root(
    const struct vcs_zcode_science_index *index, uint8_t out[32]);

/* The filter-policy commitment bound into every rank result. Each filter
 * field is length-prefixed (NULL is its own marker), so distinct filters
 * never collide and the root is always nonzero. */
void vcs_zcode_discovery_filter_policy_root(
    const char *search, const char *category, const char *hardware,
    const uint8_t *network_genesis, uint8_t out[32]);

/* Scan the workspace CAS through the science index into collapsed lineages.
 * study_allowlist (binary-searchable ascending, or NULL for every study)
 * implements filter-first: only allowlisted studies open lineages, and
 * results/votes resolve only against those. network_genesis NULL disables
 * vote verification (no seeds). NULL on allocation failure (logged). */
struct vcs_zcode_discovery_scan_v1 *vcs_zcode_discovery_projection_scan(
    const char *workspace,
    const struct vcs_zcode_science_index *index,
    const uint8_t (*study_allowlist)[32], size_t allowlist_count,
    const uint8_t *network_genesis, int64_t now_unix);
void vcs_zcode_discovery_scan_free(
    struct vcs_zcode_discovery_scan_v1 *scan);

/* Assemble the bounded graph: node-root representatives, the 4096-node
 * admission bound (over-limit lineages omitted by root ascending), the
 * per-node citation-spam cap, the global 65536-edge bound, and capped seed
 * weights. Deterministic for a fixed scan. */
enum vcs_zcode_discovery_rank_error vcs_zcode_discovery_projection_assemble(
    const struct vcs_zcode_discovery_scan_v1 *scan,
    struct vcs_zcode_discovery_graph_v1 *out);
void vcs_zcode_discovery_graph_free(
    struct vcs_zcode_discovery_graph_v1 *graph);

/* Compute the rank over the full graph (entries capacity must be at least
 * graph->node_count; the full vector is always rendered) plus the
 * convergence residual: the exact integer L1 distance the mass vector would
 * still move in one more fixed v1 iteration — a deterministic, locally
 * recomputed bound on how far the 32-iteration result sits from its fixed
 * point. Returns the pure core's error (ERR_LIMIT on an empty graph; the
 * caller handles the empty-corpus case before calling). */
enum vcs_zcode_discovery_rank_error vcs_zcode_discovery_projection_compute(
    const struct vcs_zcode_discovery_graph_v1 *graph,
    const uint8_t filter_policy_root[32],
    struct vcs_zcode_discovery_rank_entry_v1 *entries,
    struct vcs_zcode_discovery_rank_result_v1 *result,
    uint64_t *residual_out);

#endif /* ZCL_VCS_ZCODE_DISCOVERY_PROJECTION_H */
