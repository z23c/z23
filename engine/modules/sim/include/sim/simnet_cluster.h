/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * simnet_cluster — deterministic multi-node RAM cluster over the real
 * connect/disconnect consensus paths.
 */

#ifndef ZCL_SIM_SIMNET_CLUSTER_H
#define ZCL_SIM_SIMNET_CLUSTER_H

#include "coins/utxo_commitment.h"
#include "core/uint256.h"
#include "primitives/block.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct simnet_cluster;

/* Per-node role. Default (unset) is honest, so a cluster that never calls
 * simnet_cluster_set_role behaves byte-for-byte like the pre-role cluster. */
enum simnet_node_role {
    SIMNET_ROLE_HONEST = 0,
    SIMNET_ROLE_BYZANTINE = 1,
};

struct simnet_cluster *simnet_cluster_init(size_t node_count, uint64_t seed);
void simnet_cluster_free(struct simnet_cluster *cluster);

/* Tag node_id honest or byzantine. Lazily allocates the per-node role table on
 * the first byzantine tag, so an all-honest cluster allocates nothing and its
 * delivery fingerprint is unchanged. Returns false (and logs) on a bad node. */
bool simnet_cluster_set_role(struct simnet_cluster *cluster, size_t node_id,
                             enum simnet_node_role role);

/* A byzantine node forges an INVALID block (adversarial class chosen from
 * byz_seed via a splitmix64 draw) that links to the shared cluster base as a
 * DEPTH-1 LEAF, stores it in the cluster's byzantine outbox so the delivery
 * scheduler's "sender holds the block" invariant is satisfied, and returns its
 * hash. Broadcasting the returned hash with simnet_cluster_broadcast delivers
 * it to peers; an honest receiver rejects it through the real validator — a
 * COUNTED observation (see simnet_cluster_byzantine_rejected), never a fatal.
 * Returns false (and logs) on build/store failure. */
bool simnet_cluster_byzantine_mint_on(struct simnet_cluster *cluster,
                                      size_t node_id, uint64_t byz_seed,
                                      struct uint256 *out_block_hash);

/* Count of byzantine-origin deliveries a receiver observed-and-rejected over
 * this cluster's lifetime. > 0 proves adversarial blocks were seen and refused
 * by the real validator, not silently absent. */
uint64_t simnet_cluster_byzantine_rejected(
    const struct simnet_cluster *cluster);

bool simnet_cluster_mint_on(struct simnet_cluster *cluster, size_t node_id,
                            struct uint256 *out_block_hash);
bool simnet_cluster_broadcast(struct simnet_cluster *cluster,
                              size_t from_node,
                              const struct uint256 *block_hash);
/* Same as simnet_cluster_broadcast, but skips any destination node whose
 * index is marked true in exclude_to (an array of cluster->node_count
 * bools). Lets a caller model a network partition without a per-link
 * transport: enqueue deliveries only to currently-reachable peers. Passing
 * exclude_to == NULL broadcasts to all peers, identical to
 * simnet_cluster_broadcast. */
bool simnet_cluster_broadcast_except(struct simnet_cluster *cluster,
                                     size_t from_node,
                                     const struct uint256 *block_hash,
                                     const bool *exclude_to);

/* Relay a single known block from from_node to only the listed target nodes
 * (self entries in the list are skipped). Lets a test model a network
 * partition: enqueue deliveries within a subset now, across the whole
 * cluster later (a heal). Identical latency/reorder model as broadcast. */
bool simnet_cluster_relay_subset(struct simnet_cluster *cluster,
                                 size_t from_node,
                                 const struct uint256 *block_hash,
                                 const size_t *targets, size_t target_count);
bool simnet_cluster_deliver_pending(struct simnet_cluster *cluster);

bool simnet_cluster_tip_hash(const struct simnet_cluster *cluster,
                             size_t node_id, struct uint256 *out);
bool simnet_cluster_coins_digest(struct simnet_cluster *cluster,
                                 size_t node_id,
                                 struct utxo_commitment *out);

/* Active-tip height for node_id (>= SIM_CHAIN_BASE_HEIGHT - 1 at genesis).
 * Used to assert per-node tip monotonicity across a chaos run. */
bool simnet_cluster_tip_height(const struct simnet_cluster *cluster,
                               size_t node_id, int32_t *out_height);

uint64_t simnet_cluster_delivery_fingerprint(
    const struct simnet_cluster *cluster);

#ifdef ZCL_SIMNET_CLUSTER_INTERNAL

struct simnet_chain;

struct simnet_chain *simnet_chain_create(uint64_t node_tag);
void simnet_chain_free(struct simnet_chain *chain);

bool simnet_chain_mint(struct simnet_chain *chain, uint64_t first_seen,
                       struct uint256 *out_block_hash);
bool simnet_chain_accept_block(struct simnet_chain *chain,
                               const struct block *block,
                               uint64_t first_seen);

bool simnet_chain_has_block(const struct simnet_chain *chain,
                            const struct uint256 *hash);
bool simnet_chain_has_parent_for_block(const struct simnet_chain *chain,
                                       const struct block *block);
const struct block *simnet_chain_block_by_hash(
    const struct simnet_chain *chain, const struct uint256 *hash);
bool simnet_chain_block_first_seen(const struct simnet_chain *chain,
                                   const struct uint256 *hash,
                                   uint64_t *out_first_seen);

bool simnet_chain_tip_hash(const struct simnet_chain *chain,
                           struct uint256 *out);
bool simnet_chain_tip_height(const struct simnet_chain *chain,
                             int32_t *out_height);
bool simnet_chain_coins_digest(struct simnet_chain *chain,
                               struct utxo_commitment *out);

#endif /* ZCL_SIMNET_CLUSTER_INTERNAL */

#ifdef __cplusplus
}
#endif

#endif /* ZCL_SIM_SIMNET_CLUSTER_H */
