/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * 07_cluster_reorg — multi-node convergence via the real reorg path.
 *
 * WHAT THIS DEMONSTRATES
 * -----------------------
 * A single process can host more than one independent simulated node and
 * let them disagree, then converge — without any sockets, wall clock, or
 * mining PoW search. `simnet_cluster` (engine/modules/sim/src/simnet_cluster.c) gives
 * each node its own RAM chain (`struct simnet_chain`), built on the SAME
 * `connect_block()` / `disconnect_block()` consensus functions the live
 * node uses. Nothing about "reorg" is mocked here: when a node sees a
 * competing chain with more work, it unwinds its own blocks in reverse
 * order (`disconnect_block`, popping the UTXO changes it made) and replays
 * the winning branch forward (`connect_block`) — exactly what
 * `find_most_work_chain` + `activate_best_chain` do on a real node facing
 * a real network split.
 *
 * MENTAL MODEL
 * -------------
 *   node 0 (isolated) mints a SHORT chain  -> "loser"
 *   node 1 (isolated) mints a LONGER chain -> "winner"
 *   both branches get broadcast into the cluster's pending-message queue
 *   simnet_cluster_deliver_pending() drains that queue: each node ingests
 *     every block it doesn't yet have, and re-runs fork choice
 *   node 0 discovers node 1's chain has more cumulative work, disconnects
 *     its own losing tip back to the fork point, and connects the winning
 *     blocks forward
 *   result: BOTH nodes report the identical tip hash AND an identical
 *     UTXO-set digest (`struct utxo_commitment`, an XOR-accumulator over
 *     every live coin) — proof the reorg didn't just change the tip
 *     pointer, it actually re-derived the same coin set as the winning
 *     chain built in isolation.
 *
 * This is the same mechanism that fires live when two miners find a block
 * within seconds of each other and the network later converges on the
 * chain with more accumulated work.
 *
 * TEST-ONLY NOTE: none. Every symbol used here (`simnet_cluster_*`) is a
 * PUBLIC header (engine/modules/sim/include/sim/simnet_cluster.h), no #ifdef
 * ZCL_TESTING is needed to compile or link this file. (The integrator
 * still compiles the examples tree with -DZCL_TESTING per instructions,
 * which is harmless here.)
 */

#include "coins/utxo_commitment.h"
#include "core/uint256.h"
#include "sim/simnet_cluster.h"
#include "chain/chainparams.h"
#include "chain/chainparamsbase.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

/* Fixed seed: simnet_cluster_init() takes a uint64_t seed feeding whatever
 * internal randomness the cluster uses for delivery ordering, so a fixed
 * seed makes this program's console output byte-identical run to run. */
#define CLUSTER_SEED 0xC10A00000000A007ULL

static void print_hash(const char *label, const struct uint256 *h)
{
    char hex[65];
    uint256_get_hex(h, hex);
    printf("    %-18s %s\n", label, hex);
}

/* Mint `count` blocks on top of `node`'s current tip, storing each new
 * tip hash in `hashes`. Returns the index of the first mint that failed,
 * or `count` when every mint succeeded. */
static size_t mint_branch(struct simnet_cluster *cluster, unsigned node,
                          struct uint256 *hashes, size_t count)
{
    for (size_t i = 0; i < count; i++) {
        if (!simnet_cluster_mint_on(cluster, node, &hashes[i])) {
            return i;
        }
    }
    return count;
}

/* Broadcast every block of both partition branches into the cluster's
 * pending-delivery queue. Returns 0 when all blocks were announced;
 * otherwise the first failure, encoded as -(i+1) for node 0's i-th
 * block or +(i+1) for node 1's i-th block. */
static int broadcast_branches(struct simnet_cluster *cluster,
                              struct uint256 *losing, size_t losing_count,
                              struct uint256 *winning, size_t winning_count)
{
    for (size_t i = 0; i < losing_count; i++) {
        if (!simnet_cluster_broadcast(cluster, 0, &losing[i])) {
            return -(int)(i + 1);
        }
    }
    for (size_t i = 0; i < winning_count; i++) {
        if (!simnet_cluster_broadcast(cluster, 1, &winning[i])) {
            return (int)(i + 1);
        }
    }
    return 0;
}

/* Read both nodes' post-delivery state: tip hashes into tip0/tip1 and
 * coins digests into coins0/coins1, recording each read's success in
 * got[0..3] (tip0, tip1, coins0, coins1). Returns how many of the four
 * reads succeeded; 4 means all of them did. */
static int read_node_states(struct simnet_cluster *cluster,
                            struct uint256 *tip0, struct uint256 *tip1,
                            struct utxo_commitment *coins0,
                            struct utxo_commitment *coins1, bool got[4])
{
    got[0] = simnet_cluster_tip_hash(cluster, 0, tip0);
    got[1] = simnet_cluster_tip_hash(cluster, 1, tip1);
    got[2] = simnet_cluster_coins_digest(cluster, 0, coins0);
    got[3] = simnet_cluster_coins_digest(cluster, 1, coins1);
    return got[0] + got[1] + got[2] + got[3];
}

/* Check the three convergence invariants, recording each outcome in
 * match[0..2]: both nodes share a tip, node 0's tip is the branch's
 * original winning tip, and the UTXO digests agree. Returns true only
 * when all three hold. */
static bool convergence_verified(struct uint256 *tip0, struct uint256 *tip1,
                                 struct uint256 *winner_tip,
                                 struct utxo_commitment *coins0,
                                 struct utxo_commitment *coins1, bool match[3])
{
    match[0] = uint256_eq(tip0, tip1);
    match[1] = uint256_eq(tip0, winner_tip);
    match[2] = utxo_commitment_equal(coins0, coins1);
    return match[0] && match[1] && match[2];
}

int main(void)
{
    printf("=== 07_cluster_reorg: 2-node partition + convergence ===\n\n");

    /* Select a chain network before any chain/consensus code runs —
     * connect_block/disconnect_block and the coinbase subsidy schedule read
     * their parameters through chain_params_get(), which asserts one was
     * chosen. */
    chain_params_select(CHAIN_MAIN);

    /* [1/5] Stand up a 2-node cluster. Each node index is an independent
     * RAM chain sharing nothing but this process's memory — the closest
     * thing to two separate machines that never talk to each other until
     * we explicitly broadcast. */
    printf("[1/5] initializing 2-node simnet_cluster (seed=0x%016llX)...\n",
           (unsigned long long)CLUSTER_SEED);
    struct simnet_cluster *cluster = simnet_cluster_init(2, CLUSTER_SEED);
    if (!cluster) {
        fprintf(stderr, "FAIL: simnet_cluster_init returned NULL\n");
        return 1;
    }

    /* [2/5] Partition: mint two DIFFERENT branches with NO broadcast in
     * between. Node 0 builds a short 3-block branch; node 1 builds a
     * longer 6-block branch. Because neither side has seen the other's
     * blocks yet, both consider themselves "the tip" right now — this is
     * the simulated equivalent of a network partition where each side
     * keeps mining its own view of the chain. */
    printf("[2/5] partitioned mining: node 0 mints a 3-block losing branch, "
           "node 1 mints a 6-block winning branch...\n");
    struct uint256 losing[3];
    struct uint256 winning[6];
    size_t mint_fail = mint_branch(cluster, 0, losing, 3);
    if (mint_fail < 3) {
        fprintf(stderr, "FAIL: node 0 mint %zu failed\n", mint_fail);
        simnet_cluster_free(cluster);
        return 1;
    }
    mint_fail = mint_branch(cluster, 1, winning, 6);
    if (mint_fail < 6) {
        fprintf(stderr, "FAIL: node 1 mint %zu failed\n", mint_fail);
        simnet_cluster_free(cluster);
        return 1;
    }
    print_hash("node0 losing tip:", &losing[2]);
    print_hash("node1 winning tip:", &winning[5]);
    assert(!uint256_eq(&losing[2], &winning[5]) &&
           "the two branches must actually differ, or this demo proves nothing");

    /* [3/5] Heal the partition: broadcast every block from both branches
     * into the cluster's pending-delivery queue. Broadcasting does not
     * apply the blocks yet — it just announces "this hash exists" so the
     * next delivery pass can fetch and evaluate it. */
    printf("[3/5] broadcasting both branches into the cluster...\n");
    int bc_fail = broadcast_branches(cluster, losing, 3, winning, 6);
    if (bc_fail < 0) {
        fprintf(stderr, "FAIL: broadcast of node0 block %zu failed\n",
                (size_t)(-bc_fail - 1));
        simnet_cluster_free(cluster);
        return 1;
    }
    if (bc_fail > 0) {
        fprintf(stderr, "FAIL: broadcast of node1 block %zu failed\n",
                (size_t)(bc_fail - 1));
        simnet_cluster_free(cluster);
        return 1;
    }

    /* [4/5] Deliver: this is where the real reorg machinery runs. Node 0
     * ingests node 1's 6-block branch, finds it has more cumulative work
     * than its own 3-block tip, disconnects its 3 losing blocks
     * (disconnect_block, in reverse order, unwinding their UTXO changes)
     * and connects node 1's 6 blocks forward (connect_block). Node 1
     * symmetrically ingests node 0's shorter branch and rejects it (less
     * work) without needing to change anything. */
    printf("[4/5] delivering pending blocks (this drives disconnect_block "
           "on node 0's losing branch + connect_block for node 1's winning "
           "branch)...\n");
    if (!simnet_cluster_deliver_pending(cluster)) {
        fprintf(stderr, "FAIL: simnet_cluster_deliver_pending failed\n");
        simnet_cluster_free(cluster);
        return 1;
    }

    /* [5/5] Verify convergence: both nodes must now report the SAME tip
     * hash (node 1's original winning tip — the reorg did not invent a
     * new chain) AND the same coins digest (the UTXO-set XOR accumulator,
     * `struct utxo_commitment`) — proof the reorg actually re-derived the
     * winning chain's coin set on node 0, not merely repointed a tip
     * pointer while leaving stale coin state behind. */
    printf("[5/5] verifying both nodes converged to the same tip + coins...\n");
    struct uint256 tip0, tip1;
    struct utxo_commitment coins0, coins1;
    bool got_state[4];
    if (read_node_states(cluster, &tip0, &tip1, &coins0, &coins1,
                         got_state) != 4) {
        fprintf(stderr, "FAIL: could not read post-delivery tip/coins state "
                        "(tip0=%d tip1=%d coins0=%d coins1=%d)\n",
                got_state[0], got_state[1], got_state[2], got_state[3]);
        simnet_cluster_free(cluster);
        return 1;
    }

    print_hash("node0 final tip:", &tip0);
    print_hash("node1 final tip:", &tip1);
    printf("    node0 utxo count:  %llu\n",
           (unsigned long long)coins0.count);
    printf("    node1 utxo count:  %llu\n",
           (unsigned long long)coins1.count);

    bool match[3];
    if (!convergence_verified(&tip0, &tip1, &winning[5], &coins0, &coins1,
                              match)) {
        fprintf(stderr,
                "FAIL: convergence check failed (tips_match=%d "
                "adopted_winner=%d coins_match=%d)\n",
                match[0], match[1], match[2]);
        simnet_cluster_free(cluster);
        return 1;
    }

    printf("\n=== SUCCESS: node 0 reorged off its 3-block branch onto node "
           "1's 6-block branch via disconnect_block/connect_block; both "
           "nodes now share tip hash + identical UTXO digest ===\n");

    simnet_cluster_free(cluster);
    return 0;
}

/* Production counterpart:
 * ------------------------
 * The reorg machinery this example exercises through `simnet_cluster` (and,
 * underneath it, `simnet_chain.c`'s disconnect/connect replay loop) is the
 * SAME code path a live node runs from:
 *   - `find_most_work_chain()` / `activate_best_chain()` in
 *     core/modules/chain/src/chainstate.c — picks the best-work tip across all known
 *     block-index entries and walks disconnect/connect to get there.
 *   - `connect_block()` / `disconnect_block()` in
 *     core/modules/chain/src/connect_block.c and core/modules/chain/src/disconnect_block.c —
 *     the exact functions `simnet_chain_accept_block()` calls.
 *   - `engine/jobs/src/utxo_apply_delta_reorg.c` — the reducer-side job that
 *     applies a block-index reorg to the on-disk `coins_kv` authority table
 *     for a live node (the persistent-storage analogue of this example's
 *     in-RAM `struct utxo_commitment` digest).
 *   - `ops timeline` — inspect reorg events a live node has
 *     actually processed.
 */
