/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Multi-node simnet cluster tests. These exercise retained block/undo state,
 * deterministic delivery, and real disconnect/connect reorg activation.
 */

#include "test/test_core.h"

#include "sim/simnet_cluster.h"

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#define SC_CHECK(name, expr) do {          \
    printf("%s... ", (name));              \
    if ((expr)) printf("OK\n");            \
    else { printf("FAIL\n"); failures++; } \
} while (0)

static bool sc_same_tip_and_digest(struct simnet_cluster *cluster,
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

static bool sc_broadcast_hashes(struct simnet_cluster *cluster,
                                size_t from_node,
                                const struct uint256 *hashes,
                                size_t count)
{
    for (size_t i = 0; i < count; i++) {
        if (!simnet_cluster_broadcast(cluster, from_node, &hashes[i]))
            return false;
    }
    return true;
}

static bool sc_mint_chain(struct simnet_cluster *cluster, size_t node_id,
                          struct uint256 *hashes, size_t count)
{
    for (size_t i = 0; i < count; i++) {
        if (!simnet_cluster_mint_on(cluster, node_id, &hashes[i]))
            return false;
    }
    return true;
}

static bool sc_run_determinism(uint64_t seed, struct uint256 *out_tip,
                               struct utxo_commitment *out_digest,
                               uint64_t *out_delivery_fp)
{
    struct simnet_cluster *cluster = simnet_cluster_init(3, seed);
    if (!cluster)
        return false;

    struct uint256 n0[3];
    struct uint256 n1[3];
    bool ok = sc_mint_chain(cluster, 0, n0, 3) &&
              sc_mint_chain(cluster, 1, n1, 3) &&
              sc_broadcast_hashes(cluster, 0, n0, 3) &&
              sc_broadcast_hashes(cluster, 1, n1, 3) &&
              simnet_cluster_deliver_pending(cluster) &&
              simnet_cluster_tip_hash(cluster, 2, out_tip) &&
              simnet_cluster_coins_digest(cluster, 2, out_digest);
    if (out_delivery_fp)
        *out_delivery_fp = simnet_cluster_delivery_fingerprint(cluster);
    simnet_cluster_free(cluster);
    return ok;
}

int test_simnet_cluster(void)
{
    printf("\n=== simnet_cluster retained multi-node reorg harness ===\n");
    int failures = 0;

    /* (a) Honest 2-node mint + relay convergence. */
    {
        struct simnet_cluster *cluster =
            simnet_cluster_init(2, 0xC10A000000000001ULL);
        SC_CHECK("cluster: 2-node init succeeds", cluster != NULL);
        if (cluster) {
            struct uint256 h;
            bool ok = simnet_cluster_mint_on(cluster, 0, &h) &&
                      simnet_cluster_broadcast(cluster, 0, &h) &&
                      simnet_cluster_deliver_pending(cluster);
            SC_CHECK("cluster: honest minted block relays", ok);
            SC_CHECK("cluster: honest nodes converge tip+coins",
                     ok && sc_same_tip_and_digest(cluster, 0, 1));
            simnet_cluster_free(cluster);
        }
    }

    /* (b) Competing equal-length tips converge by deterministic fork-choice. */
    {
        struct simnet_cluster *cluster =
            simnet_cluster_init(2, 0xC10A000000000002ULL);
        SC_CHECK("cluster: equal-length init succeeds", cluster != NULL);
        if (cluster) {
            struct uint256 a;
            struct uint256 b;
            bool minted = simnet_cluster_mint_on(cluster, 0, &a) &&
                          simnet_cluster_mint_on(cluster, 1, &b);
            SC_CHECK("cluster: concurrent equal-height blocks mint",
                     minted && !uint256_eq(&a, &b));
            bool relayed = minted &&
                           simnet_cluster_broadcast(cluster, 0, &a) &&
                           simnet_cluster_broadcast(cluster, 1, &b) &&
                           simnet_cluster_deliver_pending(cluster);
            SC_CHECK("cluster: competing blocks deliver", relayed);
            SC_CHECK("cluster: equal-length fork has single winner",
                     relayed && sc_same_tip_and_digest(cluster, 0, 1));
            simnet_cluster_free(cluster);
        }
    }

    /* (c) Deep reorg: node 0 unwinds a 7-block losing branch and adopts the
     * 10-block winning branch; final coin set equals direct winning build. */
    {
        struct simnet_cluster *cluster =
            simnet_cluster_init(2, 0xC10A000000000003ULL);
        SC_CHECK("cluster: deep-reorg init succeeds", cluster != NULL);
        if (cluster) {
            struct uint256 losing[7];
            struct uint256 winning[10];
            bool built = sc_mint_chain(cluster, 0, losing, 7) &&
                         sc_mint_chain(cluster, 1, winning, 10);
            SC_CHECK("cluster: isolated losing and winning branches build",
                     built);
            bool relayed = built &&
                           sc_broadcast_hashes(cluster, 0, losing, 7) &&
                           sc_broadcast_hashes(cluster, 1, winning, 10) &&
                           simnet_cluster_deliver_pending(cluster);
            SC_CHECK("cluster: deep competing branches relay", relayed);

            struct uint256 reorg_tip;
            struct uint256 win_tip;
            struct utxo_commitment reorg_digest;
            bool reorg_view =
                relayed &&
                simnet_cluster_tip_hash(cluster, 0, &reorg_tip) &&
                simnet_cluster_tip_hash(cluster, 1, &win_tip) &&
                uint256_eq(&reorg_tip, &win_tip) &&
                simnet_cluster_coins_digest(cluster, 0, &reorg_digest) &&
                sc_same_tip_and_digest(cluster, 0, 1);
            SC_CHECK("cluster: node 0 reorgs to winning branch",
                     reorg_view);

            simnet_cluster_free(cluster);

            struct simnet_cluster *direct =
                simnet_cluster_init(2, 0xC10A000000000003ULL);
            struct uint256 direct_hashes[10];
            struct uint256 direct_tip;
            struct utxo_commitment direct_digest;
            bool direct_ok =
                direct &&
                sc_mint_chain(direct, 1, direct_hashes, 10) &&
                simnet_cluster_tip_hash(direct, 1, &direct_tip) &&
                simnet_cluster_coins_digest(direct, 1, &direct_digest);
            SC_CHECK("cluster: direct winning branch builds alone",
                     direct_ok);
            SC_CHECK("cluster: reorged coins equal direct winning build",
                     reorg_view && direct_ok &&
                     uint256_eq(&reorg_tip, &direct_tip) &&
                     utxo_commitment_equal(&reorg_digest, &direct_digest));
            if (direct)
                simnet_cluster_free(direct);
        }
    }

    /* (d) Determinism: same seed yields identical final tip and digest. */
    {
        struct uint256 tip_a;
        struct uint256 tip_b;
        struct uint256 tip_c;
        struct utxo_commitment digest_a;
        struct utxo_commitment digest_b;
        struct utxo_commitment digest_c;
        uint64_t fp_a = 0;
        uint64_t fp_b = 0;
        uint64_t fp_c = 0;
        bool a = sc_run_determinism(0xC10A000000000004ULL, &tip_a,
                                    &digest_a, &fp_a);
        bool b = sc_run_determinism(0xC10A000000000004ULL, &tip_b,
                                    &digest_b, &fp_b);
        bool c = sc_run_determinism(0xC10A000000000005ULL, &tip_c,
                                    &digest_c, &fp_c);
        SC_CHECK("cluster: same seed runs complete", a && b);
        SC_CHECK("cluster: same seed final tip/digest deterministic",
                 a && b && uint256_eq(&tip_a, &tip_b) &&
                 utxo_commitment_equal(&digest_a, &digest_b) &&
                 fp_a == fp_b);
        if (c) {
            printf("[cluster determinism] different seed delivery fp: "
                   "0x%016" PRIx64 " vs 0x%016" PRIx64 "%s\n",
                   fp_a, fp_c, fp_a == fp_c ? " (same)" : " (different)");
            (void)tip_c;
            (void)digest_c;
        }
    }

    printf("=== simnet_cluster: %d failures ===\n", failures);
    return failures;
}
