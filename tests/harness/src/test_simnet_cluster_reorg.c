/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Adversarial deep-reorg / partition / re-reorg coverage over the real
 * multi-node simnet cluster. Every scenario asserts that all nodes converge
 * on a byte-identical active tip AND coins commitment, and that the converged
 * coins set matches a direct forward build of the winning chain. These ride on
 * the real fork-choice (simnet_chain_entry_better: nChainWork, then first-seen,
 * then hash) and the real disconnect_block/connect_block reorg path in
 * engine/modules/sim/src/simnet_chain.c — a divergence here is a consensus finding, not a
 * test to relax.
 *
 * ZCL_SIMNET_CLUSTER_INTERNAL exposes the per-node simnet_chain layer so the
 * hash tie-break branch (unreachable at the cluster layer, which assigns a
 * unique first_seen per mint) can be exercised directly.
 */

#define ZCL_SIMNET_CLUSTER_INTERNAL
#include "test/test_core.h"

#include "sim/simnet_cluster.h"

#include "coins/utxo_commitment.h"
#include "core/uint256.h"

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#define SCR_CHECK(name, expr) do {                                      \
    printf("%s... ", (name));                                           \
    if ((expr)) {                                                       \
        printf("OK\n");                                                 \
    } else {                                                            \
        printf("FAIL\n  SIMNET REPRO SEED 0x%016" PRIx64 "\n",          \
               (uint64_t)(scenario_seed));                              \
        failures++;                                                     \
    }                                                                   \
} while (0)

static bool scr_mint_chain(struct simnet_cluster *cluster, size_t node_id,
                           struct uint256 *hashes, size_t count)
{
    for (size_t i = 0; i < count; i++) {
        if (!simnet_cluster_mint_on(cluster, node_id, &hashes[i]))
            return false;
    }
    return true;
}

static bool scr_broadcast(struct simnet_cluster *cluster, size_t from_node,
                          const struct uint256 *hashes, size_t count)
{
    for (size_t i = 0; i < count; i++) {
        if (!simnet_cluster_broadcast(cluster, from_node, &hashes[i]))
            return false;
    }
    return true;
}

static bool scr_relay_subset(struct simnet_cluster *cluster, size_t from_node,
                             const struct uint256 *hashes, size_t count,
                             const size_t *targets, size_t target_count)
{
    for (size_t i = 0; i < count; i++) {
        if (!simnet_cluster_relay_subset(cluster, from_node, &hashes[i],
                                         targets, target_count))
            return false;
    }
    return true;
}

static bool scr_same_tip_and_digest(struct simnet_cluster *cluster,
                                    size_t a, size_t b)
{
    struct uint256 ha, hb;
    struct utxo_commitment da, db;
    return simnet_cluster_tip_hash(cluster, a, &ha) &&
           simnet_cluster_tip_hash(cluster, b, &hb) &&
           uint256_eq(&ha, &hb) &&
           simnet_cluster_coins_digest(cluster, a, &da) &&
           simnet_cluster_coins_digest(cluster, b, &db) &&
           utxo_commitment_equal(&da, &db);
}

/* All nodes agree on tip+digest with node 0 as the anchor. */
static bool scr_all_converge(struct simnet_cluster *cluster, size_t node_count)
{
    for (size_t i = 1; i < node_count; i++) {
        if (!scr_same_tip_and_digest(cluster, 0, i))
            return false;
    }
    return true;
}

/* Direct forward build of `count` blocks on `node_id` of a fresh same-seed,
 * same-shape cluster. Node tags are seed-derived, so the winning origin node
 * reproduces byte-identical blocks — the reference the reorged nodes must
 * match. Caller must have freed any live cluster first (single installed
 * seed tape at a time). */
static bool scr_direct_build(uint64_t seed, size_t node_count, size_t node_id,
                             size_t count, struct uint256 *out_tip,
                             struct utxo_commitment *out_digest)
{
    struct simnet_cluster *direct = simnet_cluster_init(node_count, seed);
    if (!direct)
        return false;
    struct uint256 scratch[64];
    bool ok = count <= 64 &&
              scr_mint_chain(direct, node_id, scratch, count) &&
              simnet_cluster_tip_hash(direct, node_id, out_tip) &&
              simnet_cluster_coins_digest(direct, node_id, out_digest);
    simnet_cluster_free(direct);
    return ok;
}

/* (1) DEEP reorg (12 vs 14) across a 4-node cluster: the loser's whole branch
 * is undone with no leaked UTXO, and every node lands on a byte-identical view
 * that equals a direct build of the winner. */
static int scr_deep_reorg(void)
{
    int failures = 0;
    const uint64_t scenario_seed = 0xC1EE9000000000D1ULL;
    const size_t N = 4;
    const size_t LOSE = 12, WIN = 14;

    struct simnet_cluster *cluster = simnet_cluster_init(N, scenario_seed);
    SCR_CHECK("deep-reorg: 4-node init", cluster != NULL);
    if (!cluster)
        return failures;

    struct uint256 losing[12];
    struct uint256 winning[14];
    bool built = scr_mint_chain(cluster, 0, losing, LOSE) &&
                 scr_mint_chain(cluster, 1, winning, WIN);
    SCR_CHECK("deep-reorg: isolated 12- and 14-block branches build", built);

    /* Loser's view before it sees the winner (pure 12-block branch). */
    struct utxo_commitment lose_digest_pre;
    bool pre_ok = built &&
                  simnet_cluster_coins_digest(cluster, 0, &lose_digest_pre);
    SCR_CHECK("deep-reorg: loser holds its own branch pre-delivery", pre_ok);

    bool relayed = pre_ok &&
                   scr_broadcast(cluster, 0, losing, LOSE) &&
                   scr_broadcast(cluster, 1, winning, WIN) &&
                   simnet_cluster_deliver_pending(cluster);
    SCR_CHECK("deep-reorg: both branches relay to all nodes", relayed);

    struct uint256 win_tip;
    struct utxo_commitment lose_digest_post;
    bool converged =
        relayed &&
        simnet_cluster_tip_hash(cluster, 1, &win_tip) &&
        scr_all_converge(cluster, N) &&
        simnet_cluster_coins_digest(cluster, 0, &lose_digest_post);
    SCR_CHECK("deep-reorg: all 4 nodes converge on one tip+digest", converged);

    /* Winner origin (node 1) never held the loser's coins; the reorged loser
     * matching it proves the 12-block branch was fully undone. */
    struct uint256 lose_tip_post;
    SCR_CHECK("deep-reorg: reorged loser adopts the heavier winning tip",
              converged &&
              simnet_cluster_tip_hash(cluster, 0, &lose_tip_post) &&
              uint256_eq(&lose_tip_post, &win_tip));
    SCR_CHECK("deep-reorg: losing-branch coins differ from winning coins",
              converged &&
              !utxo_commitment_equal(&lose_digest_pre, &lose_digest_post));

    struct utxo_commitment win_digest;
    bool win_dig = converged &&
                   simnet_cluster_coins_digest(cluster, 1, &win_digest);
    simnet_cluster_free(cluster);

    /* Independent forward reference: a fresh same-seed cluster minting only
     * the 14-block winner must produce the identical tip + coins set. */
    struct uint256 ref_tip;
    struct utxo_commitment ref_digest;
    bool ref_ok = win_dig &&
                  scr_direct_build(scenario_seed, N, 1, WIN,
                                   &ref_tip, &ref_digest);
    SCR_CHECK("deep-reorg: reorged coins equal a direct winning build",
              ref_ok &&
              uint256_eq(&win_tip, &ref_tip) &&
              utxo_commitment_equal(&win_digest, &ref_digest) &&
              utxo_commitment_equal(&lose_digest_post, &ref_digest));
    return failures;
}

/* (2) nChainWork TIE-BREAK — two equal-work chains. The winner is the branch
 * whose tip has the lower first_seen (mint order), independent of delivery
 * order. Verified across several seeds (distinct latencies/orderings). */
static int scr_tie_break_first_seen(void)
{
    int failures = 0;
    const size_t N = 3;
    const size_t K = 5;
    const uint64_t seeds[4] = {
        0xC1EE7000000001A1ULL, 0xC1EE7000000001A2ULL,
        0xC1EE7000000001A3ULL, 0xC1EE7000000001A4ULL,
    };

    for (size_t s = 0; s < 4; s++) {
        const uint64_t scenario_seed = seeds[s];
        struct simnet_cluster *cluster = simnet_cluster_init(N, scenario_seed);
        SCR_CHECK("tie-break: init", cluster != NULL);
        if (!cluster)
            continue;

        struct uint256 a[5];
        struct uint256 b[5];
        /* Node 0 mints its whole branch first, so A's tip carries a strictly
         * lower first_seen than B's tip — A must win. */
        bool built = scr_mint_chain(cluster, 0, a, K) &&
                     scr_mint_chain(cluster, 1, b, K);
        bool relayed = built &&
                       scr_broadcast(cluster, 0, a, K) &&
                       scr_broadcast(cluster, 1, b, K) &&
                       simnet_cluster_deliver_pending(cluster);
        SCR_CHECK("tie-break: equal-length branches build and relay",
                  built && relayed);

        struct uint256 node0_tip, a_tip;
        bool winner_is_a =
            relayed &&
            simnet_cluster_tip_hash(cluster, 0, &node0_tip) &&
            uint256_eq(&node0_tip, &a[K - 1]) &&
            simnet_cluster_tip_hash(cluster, 0, &a_tip) &&
            uint256_eq(&a_tip, &a[K - 1]);
        SCR_CHECK("tie-break: first-minted (lower first_seen) branch wins",
                  winner_is_a);
        SCR_CHECK("tie-break: all nodes agree on the single winner",
                  relayed && scr_all_converge(cluster, N));
        simnet_cluster_free(cluster);
    }
    return failures;
}

/* (2b) The hash tie-break branch is only reachable when first_seen ties, which
 * never happens at the cluster layer (unique monotonic first_seen per mint).
 * Drive it directly on the per-node chain: two equal-work single-block branches
 * accepted with an identical first_seen must resolve to the lower block hash,
 * independent of accept order. */
static int scr_tie_break_hash(void)
{
    int failures = 0;
    const uint64_t scenario_seed = 0xC1EE7000000002B0ULL; /* for repro print */

    struct simnet_chain *chain_x = simnet_chain_create(0xA1);
    struct simnet_chain *chain_y = simnet_chain_create(0xB2);
    SCR_CHECK("tie-break-hash: source chains create",
              chain_x != NULL && chain_y != NULL);
    if (!chain_x || !chain_y) {
        simnet_chain_free(chain_x);
        simnet_chain_free(chain_y);
        return failures;
    }

    struct uint256 hx, hy;
    bool minted = simnet_chain_mint(chain_x, 1, &hx) &&
                  simnet_chain_mint(chain_y, 1, &hy);
    const struct block *bx = simnet_chain_block_by_hash(chain_x, &hx);
    const struct block *by = simnet_chain_block_by_hash(chain_y, &hy);
    SCR_CHECK("tie-break-hash: two distinct equal-work blocks mint",
              minted && bx && by && !uint256_eq(&hx, &hy));

    struct uint256 expected =
        (uint256_cmp(&hx, &hy) < 0) ? hx : hy; /* lower hash wins */

    /* Accept both into a fresh chain with the SAME first_seen (forces the
     * hash branch), in each order — same winner either way. */
    struct simnet_chain *ref_fwd = simnet_chain_create(0xC3);
    struct simnet_chain *ref_rev = simnet_chain_create(0xC3);
    struct uint256 tip_fwd, tip_rev;
    bool ok = minted && bx && by && ref_fwd && ref_rev &&
              simnet_chain_accept_block(ref_fwd, bx, 100) &&
              simnet_chain_accept_block(ref_fwd, by, 100) &&
              simnet_chain_accept_block(ref_rev, by, 100) &&
              simnet_chain_accept_block(ref_rev, bx, 100) &&
              simnet_chain_tip_hash(ref_fwd, &tip_fwd) &&
              simnet_chain_tip_hash(ref_rev, &tip_rev);
    SCR_CHECK("tie-break-hash: equal-first_seen tie resolves to lower hash",
              ok && uint256_eq(&tip_fwd, &expected));
    SCR_CHECK("tie-break-hash: winner is accept-order independent",
              ok && uint256_eq(&tip_rev, &expected));

    simnet_chain_free(ref_fwd);
    simnet_chain_free(ref_rev);
    simnet_chain_free(chain_x);
    simnet_chain_free(chain_y);
    return failures;
}

/* (3) PARTITION then HEAL — two isolated sides extend independently; the heal
 * converges the whole cluster on the heavier chain and the minority reorgs. */
static int scr_partition_heal(void)
{
    int failures = 0;
    const uint64_t scenario_seed = 0xC1EE5000000000E3ULL;
    const size_t N = 4;
    const size_t LEFT_LEN = 6, RIGHT_LEN = 8;
    const size_t left_side[1] = {1};   /* relay node 0's chain to node 1 */
    const size_t right_side[1] = {3};  /* relay node 2's chain to node 3 */

    struct simnet_cluster *cluster = simnet_cluster_init(N, scenario_seed);
    SCR_CHECK("partition: 4-node init", cluster != NULL);
    if (!cluster)
        return failures;

    /* Side L = {0,1}: node 0 builds, delivers only within L. */
    struct uint256 lchain[6];
    bool l_ok = scr_mint_chain(cluster, 0, lchain, LEFT_LEN) &&
                scr_relay_subset(cluster, 0, lchain, LEFT_LEN,
                                 left_side, 1) &&
                simnet_cluster_deliver_pending(cluster);
    SCR_CHECK("partition: side L extends and syncs internally",
              l_ok && scr_same_tip_and_digest(cluster, 0, 1));

    /* Side R = {2,3}: node 2 (still at base — partitioned from L) builds a
     * heavier branch and delivers only within R. */
    struct uint256 rchain[8];
    bool r_ok = l_ok &&
                scr_mint_chain(cluster, 2, rchain, RIGHT_LEN) &&
                scr_relay_subset(cluster, 2, rchain, RIGHT_LEN,
                                 right_side, 1) &&
                simnet_cluster_deliver_pending(cluster);
    SCR_CHECK("partition: side R extends and syncs internally",
              r_ok && scr_same_tip_and_digest(cluster, 2, 3));

    struct uint256 l_tip, r_tip;
    SCR_CHECK("partition: the two sides are on distinct tips while split",
              r_ok &&
              simnet_cluster_tip_hash(cluster, 0, &l_tip) &&
              simnet_cluster_tip_hash(cluster, 2, &r_tip) &&
              !uint256_eq(&l_tip, &r_tip));

    /* HEAL: cross-deliver each side's chain to the other side. */
    bool healed = r_ok &&
                  scr_broadcast(cluster, 0, lchain, LEFT_LEN) &&
                  scr_broadcast(cluster, 2, rchain, RIGHT_LEN) &&
                  simnet_cluster_deliver_pending(cluster);
    SCR_CHECK("partition: heal delivers both branches cluster-wide", healed);

    struct uint256 heal_tip;
    struct utxo_commitment heal_digest;
    bool converged = healed &&
                     scr_all_converge(cluster, N) &&
                     simnet_cluster_tip_hash(cluster, 0, &heal_tip) &&
                     simnet_cluster_coins_digest(cluster, 0, &heal_digest);
    /* Minority side L must have abandoned its 6-block branch for R's 8. */
    SCR_CHECK("partition: whole cluster converges on the heavier chain",
              converged && uint256_eq(&heal_tip, &r_tip));
    simnet_cluster_free(cluster);

    struct uint256 ref_tip;
    struct utxo_commitment ref_digest;
    bool ref_ok = converged &&
                  scr_direct_build(scenario_seed, N, 2, RIGHT_LEN,
                                   &ref_tip, &ref_digest);
    SCR_CHECK("partition: healed coins equal a direct heavier build",
              ref_ok &&
              uint256_eq(&heal_tip, &ref_tip) &&
              utxo_commitment_equal(&heal_digest, &ref_digest));
    return failures;
}

/* (4) REORG then RE-REORG — an observer chases an escalating sequence
 * base -> A(10) -> B(12) -> C(14). The net effect of the two disconnect/connect
 * churns must equal a clean forward build of C (undo/redo symmetry, no leaked
 * or double-counted coin). */
static int scr_reorg_rereorg(void)
{
    int failures = 0;
    const uint64_t scenario_seed = 0xC1EE3000000000C4ULL;
    const size_t N = 4;
    const size_t LA = 10, LB = 12, LC = 14;
    const size_t obs[1] = {3};

    struct simnet_cluster *cluster = simnet_cluster_init(N, scenario_seed);
    SCR_CHECK("re-reorg: 4-node init", cluster != NULL);
    if (!cluster)
        return failures;

    /* Three isolated forks from base, built before any delivery. */
    struct uint256 a[10];
    struct uint256 b[12];
    struct uint256 c[14];
    bool built = scr_mint_chain(cluster, 0, a, LA) &&
                 scr_mint_chain(cluster, 1, b, LB) &&
                 scr_mint_chain(cluster, 2, c, LC);
    SCR_CHECK("re-reorg: 10/12/14-block forks build in isolation", built);

    /* Stage 1: observer adopts A from base. */
    bool s1 = built &&
              scr_relay_subset(cluster, 0, a, LA, obs, 1) &&
              simnet_cluster_deliver_pending(cluster);
    SCR_CHECK("re-reorg: observer adopts A (base -> A)",
              s1 && scr_same_tip_and_digest(cluster, 3, 0));

    /* Stage 2: heavier B arrives -> first reorg A -> B. */
    bool s2 = s1 &&
              scr_relay_subset(cluster, 1, b, LB, obs, 1) &&
              simnet_cluster_deliver_pending(cluster);
    SCR_CHECK("re-reorg: observer reorgs A -> B on heavier work",
              s2 && scr_same_tip_and_digest(cluster, 3, 1));

    /* Stage 3: even-heavier C arrives -> second reorg B -> C. */
    bool s3 = s2 &&
              scr_relay_subset(cluster, 2, c, LC, obs, 1) &&
              simnet_cluster_deliver_pending(cluster);
    SCR_CHECK("re-reorg: observer re-reorgs B -> C on heaviest work",
              s3 && scr_same_tip_and_digest(cluster, 3, 2));

    /* Re-delivering the now-worse A is a no-op: the observer stays on C. */
    bool idem = s3 &&
                scr_relay_subset(cluster, 0, a, LA, obs, 1) &&
                simnet_cluster_deliver_pending(cluster);
    SCR_CHECK("re-reorg: redundant worse delivery is idempotent",
              idem && scr_same_tip_and_digest(cluster, 3, 2));

    struct uint256 obs_tip;
    struct utxo_commitment obs_digest;
    bool cap = idem &&
               simnet_cluster_tip_hash(cluster, 3, &obs_tip) &&
               simnet_cluster_coins_digest(cluster, 3, &obs_digest);
    simnet_cluster_free(cluster);

    /* Undo/redo symmetry: after base->A->B->C churn, the observer's coins must
     * equal a fresh forward-only build of C. */
    struct uint256 ref_tip;
    struct utxo_commitment ref_digest;
    bool ref_ok = cap &&
                  scr_direct_build(scenario_seed, N, 2, LC,
                                   &ref_tip, &ref_digest);
    SCR_CHECK("re-reorg: churned coins return to the direct C build",
              ref_ok &&
              uint256_eq(&obs_tip, &ref_tip) &&
              utxo_commitment_equal(&obs_digest, &ref_digest));
    return failures;
}

int test_simnet_cluster_reorg(void)
{
    printf("\n=== simnet_cluster_reorg deep-reorg/partition adversarial "
           "harness ===\n");
    int failures = 0;
    failures += scr_deep_reorg();
    failures += scr_tie_break_first_seen();
    failures += scr_tie_break_hash();
    failures += scr_partition_heal();
    failures += scr_reorg_rereorg();
    printf("=== simnet_cluster_reorg: %d failures ===\n", failures);
    return failures;
}
