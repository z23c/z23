/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_simnet_fuzz — deterministic seed-fuzzer over the REAL multi-node
 * simulator: `simnet_cluster` + `simnet_chain` drive the real
 * `connect_block()` / `disconnect_block()` paths and the real chainwork
 * fork-choice. This is the multi-node analogue of `test_reducer_stage_fuzz`
 * (which fuzzes the eight reducer stages in isolation): here we fuzz the
 * whole cluster and assert the network-level convergence invariants.
 *
 * The promise this test defends
 * -----------------------------
 * A set of honest nodes that all eventually see all blocks MUST converge:
 * one active tip hash, and a byte-identical UTXO set. Fork choice is a pure
 * function of the block set (chainwork, then a deterministic first-seen /
 * hash tie-break), so any random mint/relay/withhold schedule that ends with
 * every node holding every branch must land on the same answer everywhere.
 * If two honest nodes ever disagree on tip-or-coins after a full heal, the
 * fork-choice / disconnect-connect reorg machinery has a real bug.
 *
 * The scenario derived from each seed
 * -----------------------------------
 * Per seed we derive, deterministically:
 *   - node count (2..4);
 *   - a sequence of rounds; in each round every node mints a random-length
 *     branch (0..3 blocks) and a random subset of nodes "relays" (broadcasts
 *     its whole chain) while the rest stay silent — a send-side partition.
 *     A silent miner accumulates a private branch that competes on heal;
 *   - a FINAL HEAL round where every node broadcasts its complete chain and
 *     we deliver to quiescence, forcing every node to see every branch.
 * Then we assert the invariants:
 *   (1) every node shares node 0's tip hash;
 *   (2) `simnet_cluster_coins_digest` is identical across all nodes;
 *   (3) determinism — re-running the SAME seed yields the identical final
 *       tip, coins digest, and delivery fingerprint;
 *   (4) no crash / no leak (the whole battery runs under the harness/ASan).
 *
 * Adaptation to the public cluster API (honest, not hidden)
 * ---------------------------------------------------------
 * `simnet_cluster`'s public surface mints coinbase-only blocks and relays a
 * block to ALL peers (there is no per-link delivery filter and no
 * arbitrary-block inject). So:
 *   - "per-link partition" is modeled as SEND-side withholding: a node mines
 *     in isolation and withholds its branch until it relays — which is
 *     exactly what produces the competing-fork / reorg-on-heal dynamic the
 *     convergence invariant targets;
 *   - byzantine block rejection ("every rejected block was rejected with a
 *     NAMED reason") is exercised through the `simnet_byzantine` builders'
 *     own designed harness (`simnet_byzantine_run_connect_case` /
 *     `_run_header_case`) in the SAME seed loop, since the cluster has no
 *     surface to inject a would-be-rejected block into a node.
 *
 * Determinism / seed-replay
 * -------------------------
 * Every scheduling choice comes from a splitmix64 stream seeded from a single
 * 64-bit seed (independent of, but derived from, the same seed that drives
 * the cluster's internal seed-tape RNG). The base seed is printed once; on
 * ANY failure the failing per-seed value is printed AND a replay capsule is
 * written via the postmortem/seed-tape API so the exact case is recoverable.
 *
 * Budget / nightly depth
 * ----------------------
 * The fast pool runs a handful of seeds in well under 5 s. Set
 * `ZCL_SIMNET_FUZZ_SEEDS=<n>` for a deeper nightly sweep, and
 * `ZCL_SIMNET_FUZZ_SEED=<hex|dec>` to pin the base seed for replay.
 */

#include "test/test_core.h"

#include "coins/utxo_commitment.h"
#include "core/uint256.h"
#include "sim/postmortem.h"
#include "sim/seed_tape.h"
#include "sim/simnet_byzantine.h"
#include "sim/simnet_cluster.h"
#include "util/blocker.h"
#include "util/safe_alloc.h"

#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

/* ── harness scaffolding ───────────────────────────────────────────── */

static int g_failures;
static uint64_t g_seed;  /* the top-level seed of the scenario in flight */

#define FZ_CHECK(name, expr) do {                                        \
    if ((expr)) {                                                        \
        /* quiet on success to keep the suite log readable */            \
    } else {                                                             \
        printf("simnet_fuzz: %s... FAIL  (replay seed=0x%016llx)\n",     \
               (name), (unsigned long long)g_seed);                      \
        g_failures++;                                                    \
    }                                                                    \
} while (0)

/* splitmix64 — tiny, deterministic, well-distributed. Self-contained so the
 * seed is the single source of truth for replay (same pattern as
 * test_reducer_stage_fuzz.c). */
static uint64_t sm_next(uint64_t *s)
{
    uint64_t z = (*s += 0x9E3779B97F4A7C15ULL);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}
static uint32_t sm_u32(uint64_t *s) { return (uint32_t)(sm_next(s) >> 32); }
static int sm_range(uint64_t *s, int lo, int hi)  /* inclusive */
{
    if (hi <= lo) return lo;
    return lo + (int)(sm_u32(s) % (uint32_t)(hi - lo + 1));
}

static int mkdir_p(const char *p)
{
    if (mkdir(p, 0700) == 0) return 0;
    if (errno == EEXIST) return 0;
    return -1;
}

/* ── replay capsule on failure ─────────────────────────────────────── */

/* Persist a seed-tape replay capsule for a failing seed. Best-effort: a
 * capsule-write failure must never mask the underlying test failure, so all
 * paths here just return quietly. No cluster/tape is installed at call time
 * (we call this after every cluster has been freed), so opening a fresh tape
 * from the seed does not collide with the platform rng/clock hooks. */
static void fz_save_capsule(uint64_t seed)
{
    char dir[256];
    snprintf(dir, sizeof(dir), "./test-tmp/simnet_fuzz_cap_%d", (int)getpid());
    if (mkdir_p("./test-tmp") != 0) return;
    if (mkdir_p(dir) != 0) return;

    seed_tape_t *tape = seed_tape_open(seed, 0);
    if (!tape) return;

    struct postmortem_capture_opts opts = {
        .dir = dir,
        .tape = tape,
        .crash_signal = 0,
        .crash_unix = 0,
        .reason = "simnet_fuzz-invariant",
        .log_path = NULL,
    };
    char path[512];
    int rc = postmortem_capture_write(&opts, path, sizeof(path));
    if (rc == 0)
        printf("simnet_fuzz: replay capsule for seed=0x%016llx -> %s\n",
               (unsigned long long)seed, path);

    seed_tape_close(tape);
}

/* ── the scenario runner ───────────────────────────────────────────── */

/* FZ_MAX_NODES is the capacity of the per-node chain array in the default
 * scenario (and is available to any future large-N scenario). It is NO LONGER
 * the node-count draw ceiling: the default sweep draws from
 * FZ_DEFAULT_NODE_DRAW_MAX so raising this does not slow `make ci`. The opt-in
 * perf smoke (ZCL_SIMNET_PERF) allocates its own per-node state and can go
 * wider than FZ_MAX_NODES. */
#define FZ_MAX_NODES  32
/* Per-node hash capacity for the default scenario. The default per-node max is
 * rounds(<=5) * mints/round(<=3) = <=15 blocks — 64 leaves ~4x headroom and is
 * independent of node count (the round/mint draws do not scale with nodes). */
#define FZ_MAX_HASHES 64
/* Node-count ceiling for the DEFAULT sweep's per-seed draw. Kept small so the
 * `make ci` sweep stays fast regardless of FZ_MAX_NODES. */
#define FZ_DEFAULT_NODE_DRAW_MAX 4

struct fz_node_chain {
    struct uint256 hashes[FZ_MAX_HASHES];
    size_t count;
};

static bool fz_relay_full_chain(struct simnet_cluster *cluster, size_t node_id,
                                const struct fz_node_chain *chain)
{
    /* Broadcast the node's entire chain in mint order so a parent is always
     * enqueued before its child; re-broadcasting an already-delivered block
     * is a harmless no-op at delivery time. This is what keeps the delivery
     * queue from wedging on an orphan (child with no queued parent). */
    for (size_t i = 0; i < chain->count; i++) {
        if (!simnet_cluster_broadcast(cluster, node_id, &chain->hashes[i]))
            return false;
    }
    return true;
}

/* Run one full multi-node scenario derived deterministically from `seed`.
 * Returns true iff the harness itself ran to completion (no mint/relay/deliver
 * error). On success:
 *   - *out_tip / *out_digest / *out_fp = node 0's final tip, coins digest,
 *     and the cluster delivery fingerprint;
 *   - *out_converged = whether EVERY node shares node 0's tip hash AND coins
 *     digest (the invariant under test). */
static bool fz_run_scenario(uint64_t seed,
                            struct uint256 *out_tip,
                            struct utxo_commitment *out_digest,
                            uint64_t *out_fp,
                            bool *out_converged)
{
    uint64_t rng = seed;                       /* schedule stream */
    size_t node_count = (size_t)sm_range(&rng, 2, FZ_DEFAULT_NODE_DRAW_MAX);

    struct simnet_cluster *cluster = simnet_cluster_init(node_count, seed);
    if (!cluster)
        return false;

    struct fz_node_chain chain[FZ_MAX_NODES];
    memset(chain, 0, sizeof(chain));

    bool ok = true;
    int rounds = sm_range(&rng, 2, 5);

    for (int r = 0; r < rounds && ok; r++) {
        /* Each node extends its own branch by a random amount this round. */
        for (size_t n = 0; n < node_count && ok; n++) {
            int mints = sm_range(&rng, 0, 3);
            for (int m = 0; m < mints; m++) {
                if (chain[n].count >= FZ_MAX_HASHES)
                    break;
                struct uint256 h;
                if (!simnet_cluster_mint_on(cluster, n, &h)) {
                    ok = false;
                    break;
                }
                chain[n].hashes[chain[n].count++] = h;
            }
        }
        /* Send-side partition: a random subset of nodes relays this round;
         * the rest withhold (private branch that competes on heal). */
        for (size_t n = 0; n < node_count && ok; n++) {
            bool relays = sm_range(&rng, 0, 3) != 0;  /* ~75% relay */
            if (relays && chain[n].count > 0) {
                if (!fz_relay_full_chain(cluster, n, &chain[n]))
                    ok = false;
            }
        }
        if (ok && !simnet_cluster_deliver_pending(cluster))
            ok = false;
    }

    /* FINAL HEAL: every node relays its complete chain, then deliver to
     * quiescence — after this every node has seen every branch. */
    for (size_t n = 0; n < node_count && ok; n++) {
        if (chain[n].count > 0 && !fz_relay_full_chain(cluster, n, &chain[n]))
            ok = false;
    }
    if (ok && !simnet_cluster_deliver_pending(cluster))
        ok = false;

    bool converged = false;
    if (ok) {
        ok = simnet_cluster_tip_hash(cluster, 0, out_tip) &&
             simnet_cluster_coins_digest(cluster, 0, out_digest);
        if (ok) {
            converged = true;
            for (size_t n = 1; n < node_count; n++) {
                struct uint256 tip_n;
                struct utxo_commitment dig_n;
                if (!simnet_cluster_tip_hash(cluster, n, &tip_n) ||
                    !simnet_cluster_coins_digest(cluster, n, &dig_n) ||
                    !uint256_eq(out_tip, &tip_n) ||
                    !utxo_commitment_equal(out_digest, &dig_n)) {
                    converged = false;
                    break;
                }
            }
        }
    }

    *out_fp = simnet_cluster_delivery_fingerprint(cluster);
    *out_converged = converged;
    simnet_cluster_free(cluster);
    return ok;
}

/* ── byzantine axis: every rejected block carries a NAMED reason ─────── */

/* Reuse the simnet_byzantine builders. For a random subset of the adversarial
 * classes, run each through its designed harness and assert the rejection is
 * NAMED: `observation_ok` requires rejected==true, a non-empty reject_reason,
 * a non-empty typed blocker_id, the expected blocker class, an unchanged tip,
 * and that the next honest block is still accepted. Runs after every cluster
 * is freed, so no seed-tape is installed over the platform rng/clock. */
static void fz_byzantine_named_reason(uint64_t *rng)
{
    for (int k = 0; k < SIMNET_BYZ_CLASS_COUNT; k++) {
        if (sm_range(rng, 0, 1) == 0)
            continue;                          /* random subset */

        enum simnet_byzantine_class kind = (enum simnet_byzantine_class)k;
        blocker_reset_for_testing();
        blocker_set_clock_for_testing(1000000 + (int64_t)k * 100000);

        struct simnet_byzantine_observation obs;
        bool ran = simnet_byzantine_class_tier(kind) ==
                       SIMNET_BYZ_TIER_CONNECT_BLOCK
                       ? simnet_byzantine_run_connect_case(kind, &obs)
                       : simnet_byzantine_run_header_case(kind, &obs);

        char lbl[96];
        snprintf(lbl, sizeof(lbl), "byzantine[%s] ran",
                 simnet_byzantine_class_name(kind));
        FZ_CHECK(lbl, ran);
        if (!ran)
            continue;

        snprintf(lbl, sizeof(lbl), "byzantine[%s] rejected with NAMED reason",
                 simnet_byzantine_class_name(kind));
        FZ_CHECK(lbl, obs.rejected && obs.reject_reason[0] != '\0' &&
                      obs.blocker_id[0] != '\0');

        snprintf(lbl, sizeof(lbl), "byzantine[%s] invariant holds",
                 simnet_byzantine_class_name(kind));
        FZ_CHECK(lbl, obs.invariant_ok);
    }
}

/* ── teeth: the convergence comparator must be able to FAIL ──────────── */

/* Build a genuine divergence — mint on node 0 and never relay it — and
 * confirm node 0 and node 1 do NOT share a tip. If this ever "passes" (tips
 * equal without relay) the tip comparator used above is hollow. */
static void fz_teeth(void)
{
    struct simnet_cluster *c = simnet_cluster_init(2, 0xFEEDFACEC0FFEEULL);
    FZ_CHECK("teeth: divergence cluster inits", c != NULL);
    if (!c)
        return;

    struct uint256 h;
    struct uint256 t0;
    struct uint256 t1;
    bool got = simnet_cluster_mint_on(c, 0, &h) &&   /* no broadcast/deliver */
               simnet_cluster_tip_hash(c, 0, &t0) &&
               simnet_cluster_tip_hash(c, 1, &t1);
    FZ_CHECK("teeth: un-relayed mint diverges the tips",
             got && !uint256_eq(&t0, &t1));

    simnet_cluster_free(c);
}

/* ── opt-in perf smoke: the scheduler is O(N log N), not O(N^2) ──────── */

/* Wall-clock milliseconds from a raw monotonic read. A cluster installs its
 * seed-tape virtual clock over the platform clock_iface, so clock_now_*() is
 * virtual time during a run; this benchmark needs REAL elapsed time, so it
 * reads the syscall clock directly (the tape hook does not intercept a direct
 * clock_gettime). */
static double perf_wall_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);  // platform-ok:simnet-perf-smoke-realtime
    return (double)ts.tv_sec * 1000.0 + (double)ts.tv_nsec / 1.0e6;
}

/* One N-node scenario: every node mints one block (round 0), then re-relays
 * its whole chain across `relay_rounds` broadcast rounds and heals. The heavy
 * axis is the number of QUEUED DELIVERIES per drain (N*(N-1) each round), which
 * is exactly what the old whole-queue rescan made quadratic. Returns the
 * delivery fingerprint (via out_fp) and whether all N nodes converged. */
static bool fz_perf_scenario(size_t n_nodes, int relay_rounds, uint64_t seed,
                             uint64_t *out_fp, bool *out_converged)
{
    struct simnet_cluster *c = simnet_cluster_init(n_nodes, seed);
    if (!c)
        return false;

    /* Heap-allocated so N is not bounded by FZ_MAX_NODES / the stack. */
    struct fz_node_chain *chains =
        zcl_calloc(n_nodes, sizeof(*chains), "fz_perf_chains");
    if (!chains) {
        simnet_cluster_free(c);
        return false;
    }

    bool ok = true;
    for (size_t nnode = 0; nnode < n_nodes && ok; nnode++) {
        struct uint256 h;
        if (!simnet_cluster_mint_on(c, nnode, &h))
            ok = false;
        else
            chains[nnode].hashes[chains[nnode].count++] = h;
    }

    for (int r = 0; r < relay_rounds && ok; r++) {
        for (size_t nnode = 0; nnode < n_nodes && ok; nnode++) {
            if (chains[nnode].count > 0 &&
                !fz_relay_full_chain(c, nnode, &chains[nnode]))
                ok = false;
        }
        if (ok && !simnet_cluster_deliver_pending(c))
            ok = false;
    }
    /* final heal (redundant after the first drain, but proves quiescence). */
    for (size_t nnode = 0; nnode < n_nodes && ok; nnode++)
        if (chains[nnode].count > 0 &&
            !fz_relay_full_chain(c, nnode, &chains[nnode]))
            ok = false;
    if (ok && !simnet_cluster_deliver_pending(c))
        ok = false;

    bool converged = false;
    if (ok) {
        struct uint256 tip0;
        struct utxo_commitment dig0;
        if (simnet_cluster_tip_hash(c, 0, &tip0) &&
            simnet_cluster_coins_digest(c, 0, &dig0)) {
            converged = true;
            for (size_t nnode = 1; nnode < n_nodes; nnode++) {
                struct uint256 tn;
                struct utxo_commitment dn;
                if (!simnet_cluster_tip_hash(c, nnode, &tn) ||
                    !simnet_cluster_coins_digest(c, nnode, &dn) ||
                    !uint256_eq(&tip0, &tn) ||
                    !utxo_commitment_equal(&dig0, &dn)) {
                    converged = false;
                    break;
                }
            }
        }
    }

    *out_fp = simnet_cluster_delivery_fingerprint(c);
    *out_converged = converged;
    free(chains);
    simnet_cluster_free(c);
    return ok;
}

/* Opt-in (ZCL_SIMNET_PERF=1) N=100 smoke test. Not part of the default sweep:
 * it exists so an O(N^2)-scheduler regression is caught, and to eyeball
 * before/after wall-clock numbers. Asserts convergence, determinism (same seed
 * => identical delivery fingerprint), and a LOOSE wall-clock ceiling (generous
 * enough that ASan/CI variance never trips it, tight enough that a genuine
 * quadratic blowup at N=100 would). */
static void fz_perf_smoke(void)
{
    if (!getenv("ZCL_SIMNET_PERF")) {
        printf("simnet_fuzz: perf smoke SKIPPED "
               "(set ZCL_SIMNET_PERF=1 to run)\n");
        return;
    }

    const size_t n_nodes = 100;
    const int relay_rounds = 6;
    const uint64_t seed = 0x5152C0FFEE5EED01ULL;

    double t0 = perf_wall_ms();
    uint64_t fp_a = 0;
    bool conv_a = false;
    bool ran_a = fz_perf_scenario(n_nodes, relay_rounds, seed, &fp_a, &conv_a);
    double wall_ms = perf_wall_ms() - t0;

    /* Determinism: an identical replay must produce the identical fingerprint. */
    uint64_t fp_b = 0;
    bool conv_b = false;
    bool ran_b = fz_perf_scenario(n_nodes, relay_rounds, seed, &fp_b, &conv_b);

    /* Loose ceiling. At N=100 with 6 relay rounds the old whole-queue rescan
     * was ~1e9+ readiness checks; the heap scheduler is sub-second. A ceiling
     * of 30 s trips only on a true quadratic regression, not on normal or
     * ASan-slowed variance. */
    const double perf_ceiling_ms = 30000.0;

    printf("simnet_fuzz: perf smoke N=%zu relay_rounds=%d wall=%.1f ms "
           "(loose ceiling %.0f ms) fp=0x%016llx\n",
           n_nodes, relay_rounds, wall_ms, perf_ceiling_ms,
           (unsigned long long)fp_a);

    FZ_CHECK("perf: scenario ran to completion", ran_a && ran_b);
    FZ_CHECK("perf: all N nodes converge (tip + coins digest)",
             conv_a && conv_b);
    FZ_CHECK("perf: same seed => identical delivery fingerprint",
             fp_a == fp_b);
    FZ_CHECK("perf: drain wall-clock under loose ceiling",
             wall_ms < perf_ceiling_ms);
}

/* ── byzantine cluster axis: node roles + honest-ratio + convergence ── */

/* The FIXED sub-stream tag. ALL byzantine randomness (which nodes are
 * byzantine, which forged class each mints) is drawn from
 * splitmix64(seed ^ FZ_BYZ_SUBSTREAM_TAG), a stream DISJOINT from the schedule
 * stream `rng = seed`. That disjointness is what makes honest_permille=1000
 * reproduce the legacy all-honest delivery fingerprint bit-for-bit. */
#define FZ_BYZ_SUBSTREAM_TAG 0x42595A4E4F444531ULL  /* ASCII "BYZNODE1" */

/* Structural mirror of fz_run_scenario, made role-aware. At
 * honest_permille=1000 every node is honest and this draws the schedule stream
 * (`rng`) EXACTLY as fz_run_scenario does — same draws, same order — so it must
 * produce the identical delivery fingerprint. Byzantine nodes (permille<1000)
 * forge invalid blocks from the DISJOINT byz sub-stream and never touch `rng`.
 * Node 0 is always honest (the convergence reference). Convergence is checked
 * over honest nodes only. */
static bool fz_run_byz_parity(uint64_t seed, int honest_permille,
                              uint64_t *out_fp, bool *out_honest_converged,
                              uint64_t *out_byz_rejected)
{
    uint64_t rng = seed;                       /* schedule stream (as legacy) */
    size_t node_count = (size_t)sm_range(&rng, 2, FZ_DEFAULT_NODE_DRAW_MAX);

    uint64_t byz_rng = seed ^ FZ_BYZ_SUBSTREAM_TAG;  /* disjoint sub-stream */

    struct simnet_cluster *cluster = simnet_cluster_init(node_count, seed);
    if (!cluster)
        return false;

    bool is_byz[FZ_MAX_NODES];
    memset(is_byz, 0, sizeof(is_byz));
    for (size_t n = 0; n < node_count; n++) {
        bool byz = (n != 0) &&
                   ((int)(sm_u32(&byz_rng) % 1000u) >= honest_permille);
        is_byz[n] = byz;
        if (!simnet_cluster_set_role(cluster, n,
                byz ? SIMNET_ROLE_BYZANTINE : SIMNET_ROLE_HONEST)) {
            simnet_cluster_free(cluster);
            return false;
        }
    }

    struct fz_node_chain chain[FZ_MAX_NODES];
    struct fz_node_chain byz[FZ_MAX_NODES];
    memset(chain, 0, sizeof(chain));
    memset(byz, 0, sizeof(byz));

    bool ok = true;
    int rounds = sm_range(&rng, 2, 5);         /* SAME draw as legacy */

    for (int r = 0; r < rounds && ok; r++) {
        for (size_t n = 0; n < node_count && ok; n++) {
            if (!is_byz[n]) {
                int mints = sm_range(&rng, 0, 3);   /* SAME draw as legacy */
                for (int m = 0; m < mints; m++) {
                    if (chain[n].count >= FZ_MAX_HASHES)
                        break;
                    struct uint256 h;
                    if (!simnet_cluster_mint_on(cluster, n, &h)) {
                        ok = false;
                        break;
                    }
                    chain[n].hashes[chain[n].count++] = h;
                }
            } else if (byz[n].count < FZ_MAX_HASHES) {
                struct uint256 h;
                uint64_t bs = sm_next(&byz_rng);
                if (!simnet_cluster_byzantine_mint_on(cluster, n, bs, &h))
                    ok = false;
                else
                    byz[n].hashes[byz[n].count++] = h;
            }
        }
        for (size_t n = 0; n < node_count && ok; n++) {
            if (!is_byz[n]) {
                bool relays = sm_range(&rng, 0, 3) != 0;  /* SAME as legacy */
                if (relays && chain[n].count > 0)
                    if (!fz_relay_full_chain(cluster, n, &chain[n]))
                        ok = false;
            } else {
                for (size_t i = 0; i < byz[n].count && ok; i++)
                    if (!simnet_cluster_broadcast(cluster, n, &byz[n].hashes[i]))
                        ok = false;
            }
        }
        if (ok && !simnet_cluster_deliver_pending(cluster))
            ok = false;
    }

    for (size_t n = 0; n < node_count && ok; n++) {
        struct fz_node_chain *src = is_byz[n] ? &byz[n] : &chain[n];
        if (src->count > 0 && !fz_relay_full_chain(cluster, n, src))
            ok = false;
    }
    if (ok && !simnet_cluster_deliver_pending(cluster))
        ok = false;

    bool honest_conv = false;
    if (ok) {
        struct uint256 tip0;
        struct utxo_commitment dig0;
        if (simnet_cluster_tip_hash(cluster, 0, &tip0) &&
            simnet_cluster_coins_digest(cluster, 0, &dig0)) {
            honest_conv = true;
            for (size_t n = 1; n < node_count; n++) {
                if (is_byz[n])
                    continue;             /* only honest nodes must agree */
                struct uint256 tn;
                struct utxo_commitment dn;
                if (!simnet_cluster_tip_hash(cluster, n, &tn) ||
                    !simnet_cluster_coins_digest(cluster, n, &dn) ||
                    !uint256_eq(&tip0, &tn) ||
                    !utxo_commitment_equal(&dig0, &dn)) {
                    honest_conv = false;
                    break;
                }
            }
        }
    }

    if (out_fp)
        *out_fp = simnet_cluster_delivery_fingerprint(cluster);
    if (out_honest_converged)
        *out_honest_converged = honest_conv;
    if (out_byz_rejected)
        *out_byz_rejected = simnet_cluster_byzantine_rejected(cluster);
    simnet_cluster_free(cluster);
    return ok;
}

/* Wider fixed-N byzantine cluster for the convergence + perf axes. Node 0 is
 * honest; the rest are byzantine per the sub-stream at `honest_permille`. If
 * the draw yields NO byzantine node, one is forced so the "observed-and-
 * rejected" assertion always has something to observe. Heap-allocated so N is
 * not bounded by FZ_MAX_NODES. */
static bool fz_byz_wide(uint64_t seed, size_t n_nodes, int honest_permille,
                        bool *out_converged, uint64_t *out_byz_rejected,
                        uint64_t *out_fp)
{
    uint64_t rng = seed;
    uint64_t byz_rng = seed ^ FZ_BYZ_SUBSTREAM_TAG;

    struct simnet_cluster *c = simnet_cluster_init(n_nodes, seed);
    if (!c)
        return false;

    struct fz_node_chain *chain =
        zcl_calloc(n_nodes, sizeof(*chain), "fz_byz_chain");
    struct fz_node_chain *byz =
        zcl_calloc(n_nodes, sizeof(*byz), "fz_byz_out");
    bool *is_byz = zcl_calloc(n_nodes, sizeof(*is_byz), "fz_byz_roles");
    if (!chain || !byz || !is_byz) {
        free(chain);
        free(byz);
        free(is_byz);
        simnet_cluster_free(c);
        return false;
    }

    size_t byz_total = 0;
    for (size_t n = 0; n < n_nodes; n++) {
        bool b = (n != 0) &&
                 ((int)(sm_u32(&byz_rng) % 1000u) >= honest_permille);
        is_byz[n] = b;
        if (b)
            byz_total++;
    }
    if (byz_total == 0 && n_nodes >= 2) {
        is_byz[n_nodes - 1] = true;       /* guarantee an adversary to observe */
        byz_total = 1;
    }
    bool ok = true;
    for (size_t n = 0; n < n_nodes && ok; n++)
        if (!simnet_cluster_set_role(c, n,
                is_byz[n] ? SIMNET_ROLE_BYZANTINE : SIMNET_ROLE_HONEST))
            ok = false;

    int rounds = 4;
    for (int r = 0; r < rounds && ok; r++) {
        for (size_t n = 0; n < n_nodes && ok; n++) {
            if (!is_byz[n]) {
                int mints = sm_range(&rng, 1, 2);
                for (int m = 0; m < mints && chain[n].count < FZ_MAX_HASHES;
                     m++) {
                    struct uint256 h;
                    if (!simnet_cluster_mint_on(c, n, &h)) {
                        ok = false;
                        break;
                    }
                    chain[n].hashes[chain[n].count++] = h;
                }
            } else if (byz[n].count < FZ_MAX_HASHES) {
                struct uint256 h;
                uint64_t bs = sm_next(&byz_rng);
                if (!simnet_cluster_byzantine_mint_on(c, n, bs, &h))
                    ok = false;
                else
                    byz[n].hashes[byz[n].count++] = h;
            }
        }
        for (size_t n = 0; n < n_nodes && ok; n++) {
            struct fz_node_chain *src = is_byz[n] ? &byz[n] : &chain[n];
            for (size_t i = 0; i < src->count && ok; i++)
                if (!simnet_cluster_broadcast(c, n, &src->hashes[i]))
                    ok = false;
        }
        if (ok && !simnet_cluster_deliver_pending(c))
            ok = false;
    }
    for (size_t n = 0; n < n_nodes && ok; n++) {
        struct fz_node_chain *src = is_byz[n] ? &byz[n] : &chain[n];
        for (size_t i = 0; i < src->count && ok; i++)
            if (!simnet_cluster_broadcast(c, n, &src->hashes[i]))
                ok = false;
    }
    if (ok && !simnet_cluster_deliver_pending(c))
        ok = false;

    bool converged = false;
    if (ok) {
        struct uint256 tip0;
        struct utxo_commitment dig0;
        if (simnet_cluster_tip_hash(c, 0, &tip0) &&
            simnet_cluster_coins_digest(c, 0, &dig0)) {
            converged = true;
            for (size_t n = 1; n < n_nodes; n++) {
                if (is_byz[n])
                    continue;             /* only honest nodes must converge */
                struct uint256 tn;
                struct utxo_commitment dn;
                if (!simnet_cluster_tip_hash(c, n, &tn) ||
                    !simnet_cluster_coins_digest(c, n, &dn) ||
                    !uint256_eq(&tip0, &tn) ||
                    !utxo_commitment_equal(&dig0, &dn)) {
                    converged = false;
                    break;
                }
            }
        }
    }

    if (out_converged)
        *out_converged = converged;
    if (out_byz_rejected)
        *out_byz_rejected = simnet_cluster_byzantine_rejected(c);
    if (out_fp)
        *out_fp = simnet_cluster_delivery_fingerprint(c);
    free(chain);
    free(byz);
    free(is_byz);
    simnet_cluster_free(c);
    return ok;
}

/* Opt-in (ZCL_SIMNET_PERF=1) byzantine-mixed N=100 smoke: honest majority must
 * still converge, an adversary must be observed-and-rejected, the run must be
 * deterministic, and the scheduler must stay sub-second (loose ceiling). */
static void fz_byz_perf_smoke(void)
{
    if (!getenv("ZCL_SIMNET_PERF")) {
        printf("simnet_byzantine_cluster: perf smoke SKIPPED "
               "(set ZCL_SIMNET_PERF=1 to run)\n");
        return;
    }

    const size_t n_nodes = 100;
    const int honest_permille = 800;        /* 80% honest */
    const uint64_t seed = 0x5B0BADC0DEB47E01ULL;

    double t0 = perf_wall_ms();
    bool conv_a = false;
    uint64_t rej_a = 0;
    uint64_t fp_a = 0;
    bool ran_a = fz_byz_wide(seed, n_nodes, honest_permille,
                             &conv_a, &rej_a, &fp_a);
    double wall_ms = perf_wall_ms() - t0;

    bool conv_b = false;
    uint64_t rej_b = 0;
    uint64_t fp_b = 0;
    bool ran_b = fz_byz_wide(seed, n_nodes, honest_permille,
                             &conv_b, &rej_b, &fp_b);

    const double perf_ceiling_ms = 30000.0;
    printf("simnet_byzantine_cluster: perf N=%zu honest_permille=%d wall=%.1f ms "
           "(loose ceiling %.0f ms) byz_rejected=%llu fp=0x%016llx\n",
           n_nodes, honest_permille, wall_ms, perf_ceiling_ms,
           (unsigned long long)rej_a, (unsigned long long)fp_a);

    FZ_CHECK("byz perf: scenario ran", ran_a && ran_b);
    FZ_CHECK("byz perf: honest majority converges at N=100", conv_a && conv_b);
    FZ_CHECK("byz perf: adversary observed-and-rejected (count>0)", rej_a > 0);
    FZ_CHECK("byz perf: same seed => identical fingerprint", fp_a == fp_b);
    FZ_CHECK("byz perf: same seed => identical reject count", rej_a == rej_b);
    FZ_CHECK("byz perf: drain wall-clock under loose ceiling",
             wall_ms < perf_ceiling_ms);
}

/* ── entry point ───────────────────────────────────────────────────── */

int test_simnet_fuzz(void)
{
    printf("\n=== simnet_fuzz — deterministic multi-node cluster fuzz ===\n");
    g_failures = 0;

    if (!blocker_module_init()) {
        printf("simnet_fuzz: blocker_module_init failed\n");
        return 1;
    }

    /* Base seed: env override for replay, else a fixed default so the fast
     * run is deterministic. */
    uint64_t base_seed = 0x51C0FFEE5EED0001ULL;
    const char *seed_env = getenv("ZCL_SIMNET_FUZZ_SEED");
    if (seed_env && *seed_env)
        base_seed = strtoull(seed_env, NULL, 0);

    /* Seed count: a handful in the fast pool (<5 s); deeper for nightly. */
    int seeds = 4;
    const char *n_env = getenv("ZCL_SIMNET_FUZZ_SEEDS");
    if (n_env && *n_env) {
        long v = strtol(n_env, NULL, 0);
        if (v > 0 && v <= 100000)
            seeds = (int)v;
    }

    printf("simnet_fuzz: base_seed=0x%016llx seeds=%d "
           "(set ZCL_SIMNET_FUZZ_SEED / ZCL_SIMNET_FUZZ_SEEDS to override)\n",
           (unsigned long long)base_seed, seeds);

    fz_teeth();

    for (int i = 0; i < seeds; i++) {
        uint64_t seed = base_seed ^ ((uint64_t)i * 0x100000001B3ULL);
        seed = sm_next(&seed);       /* spread consecutive base seeds apart */
        g_seed = seed;

        int fails_before = g_failures;

        /* Determinism: the SAME seed must yield the identical final tip,
         * coins digest, and delivery fingerprint. Run twice. */
        struct uint256 tip_a;
        struct uint256 tip_b;
        struct utxo_commitment dig_a;
        struct utxo_commitment dig_b;
        uint64_t fp_a = 0;
        uint64_t fp_b = 0;
        bool conv_a = false;
        bool conv_b = false;

        bool ran_a = fz_run_scenario(seed, &tip_a, &dig_a, &fp_a, &conv_a);
        bool ran_b = fz_run_scenario(seed, &tip_b, &dig_b, &fp_b, &conv_b);

        FZ_CHECK("scenario ran to completion", ran_a && ran_b);

        if (ran_a && ran_b) {
            /* (1)+(2) all nodes converge to one tip and one coins digest. */
            FZ_CHECK("all nodes converge (tip + coins digest)",
                     conv_a && conv_b);
            /* (3) deterministic replay. */
            FZ_CHECK("same seed => identical tip",
                     uint256_eq(&tip_a, &tip_b));
            FZ_CHECK("same seed => identical coins digest",
                     utxo_commitment_equal(&dig_a, &dig_b));
            FZ_CHECK("same seed => identical delivery fingerprint",
                     fp_a == fp_b);
        }

        /* Byzantine axis: every rejected block names its reason. */
        uint64_t byz_rng = seed ^ 0xB47A511E0000ULL;
        fz_byzantine_named_reason(&byz_rng);

        /* On any failure attributable to this seed, drop a replay capsule. */
        if (g_failures > fails_before)
            fz_save_capsule(seed);
    }

    /* Opt-in N=100 perf/scale smoke (skipped fast unless ZCL_SIMNET_PERF=1). */
    fz_perf_smoke();

    printf("simnet_fuzz: %d failures (%d seeds)\n", g_failures, seeds);
    return g_failures;
}

/* ── byzantine-mix cluster group ────────────────────────────────────── */

int test_simnet_byzantine_cluster(void)
{
    printf("\n=== simnet_byzantine_cluster — N-node honest/byzantine mix ===\n");
    g_failures = 0;

    if (!blocker_module_init()) {
        printf("simnet_byzantine_cluster: blocker_module_init failed\n");
        return 1;
    }

    uint64_t base_seed = 0x5B0BADC0DEBABE01ULL;
    const char *seed_env = getenv("ZCL_SIMNET_FUZZ_SEED");
    if (seed_env && *seed_env)
        base_seed = strtoull(seed_env, NULL, 0);

    printf("simnet_byzantine_cluster: base_seed=0x%016llx tag=0x%016llx\n",
           (unsigned long long)base_seed,
           (unsigned long long)FZ_BYZ_SUBSTREAM_TAG);

    /* (b) THE HARD GATE — determinism / non-perturbation. A byzantine-capable
     * run with honest_permille=1000 must reproduce the LEGACY all-honest
     * delivery fingerprint bit-for-bit: it proves the byzantine machinery
     * draws from a disjoint sub-stream and never perturbs the schedule stream.
     * Also (a): re-running the same seed is deterministic. */
    for (int i = 0; i < 6; i++) {
        uint64_t seed = base_seed ^ ((uint64_t)i * 0x100000001B3ULL);
        seed = sm_next(&seed);
        g_seed = seed;

        struct uint256 tip;
        struct utxo_commitment dig;
        uint64_t fp_legacy = 0;
        bool conv_legacy = false;
        bool ran_legacy =
            fz_run_scenario(seed, &tip, &dig, &fp_legacy, &conv_legacy);

        uint64_t fp_h1000 = 0;
        bool honest_conv = false;
        uint64_t rej1000 = 0;
        bool ran_h1000 =
            fz_run_byz_parity(seed, 1000, &fp_h1000, &honest_conv, &rej1000);

        /* (a) same-seed determinism of the byzantine-capable runner itself. */
        uint64_t fp_h1000_b = 0;
        bool ran_h1000_b =
            fz_run_byz_parity(seed, 1000, &fp_h1000_b, NULL, NULL);

        FZ_CHECK("parity runs (legacy + permille=1000)",
                 ran_legacy && ran_h1000 && ran_h1000_b);
        FZ_CHECK("permille=1000 => byte-identical to legacy fingerprint",
                 fp_legacy == fp_h1000);
        FZ_CHECK("permille=1000 => deterministic re-run",
                 fp_h1000 == fp_h1000_b);
        FZ_CHECK("permille=1000 => zero byzantine rejections", rej1000 == 0);
    }

    /* (convergence) 80% honest over a wider cluster: the honest majority
     * converges to one honest tip + coins digest, and adversarial blocks were
     * observed-and-rejected (count > 0), not silently absent. Plus (a)
     * same-seed determinism of the delivery fingerprint and reject count. */
    for (int i = 0; i < 6; i++) {
        uint64_t seed = base_seed ^ ((uint64_t)(i + 41) * 0x100000001B3ULL);
        seed = sm_next(&seed);
        g_seed = seed;

        bool conv_a = false;
        bool conv_b = false;
        uint64_t rej_a = 0;
        uint64_t rej_b = 0;
        uint64_t fp_a = 0;
        uint64_t fp_b = 0;
        bool ran_a = fz_byz_wide(seed, 10, 800, &conv_a, &rej_a, &fp_a);
        bool ran_b = fz_byz_wide(seed, 10, 800, &conv_b, &rej_b, &fp_b);

        FZ_CHECK("byz N=10: scenario ran", ran_a && ran_b);
        FZ_CHECK("byz N=10: honest majority converges (tip + coins digest)",
                 conv_a && conv_b);
        FZ_CHECK("byz N=10: adversarial blocks observed-and-rejected (count>0)",
                 rej_a > 0 && rej_b > 0);
        FZ_CHECK("byz N=10: same seed => identical delivery fingerprint",
                 fp_a == fp_b);
        FZ_CHECK("byz N=10: same seed => identical reject count",
                 rej_a == rej_b);
    }

    /* Opt-in byzantine-mixed N=100 perf/scale smoke. */
    fz_byz_perf_smoke();

    printf("simnet_byzantine_cluster: %d failures\n", g_failures);
    return g_failures;
}
