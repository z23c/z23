/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_netsplit_detector — the SUSPECTED_NETSPLIT signal
 * (engine/services/src/network_monitor_netsplit.c). Exercises the three pure folds
 * directly, no peers and no chain:
 *
 *   1. peer tip disagreement at our height, with our own tip injected —
 *      the case the peer-vs-peer fork fold is structurally blind to;
 *   2. block-arrival rate vs the tip's nBits-implied difficulty;
 *   3. the composite verdict — peer testimony alone never decides.
 *
 * The bar the detector must clear: minority-side detection FIRES, a single
 * disagreeing peer does NOT, many peers sharing ONE address group do NOT,
 * and normal Poisson block-interval variance does NOT.
 */

#include "test/test_core.h"

#include "services/network_monitor.h"
#include "models/peer_chain_observation.h"
#include "json/json.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NS_CHECK(cond) do { \
    if (cond) { /* pass */ } \
    else { printf("  FAIL: %s (line %d)\n", #cond, __LINE__); failures++; } \
} while (0)

/* 64-hex tip hashes that differ only in their first nibble. */
static void ns_hash(char *dst, char c)
{
    memset(dst, '0', PEER_OBS_TIP_HEX);
    dst[0] = c;
    dst[PEER_OBS_TIP_HEX] = '\0';
}

static struct db_peer_chain_observation ns_obs(int64_t peer_id, int64_t height,
                                               char hashc, const char *addr)
{
    struct db_peer_chain_observation o;
    memset(&o, 0, sizeof(o));
    o.peer_id = peer_id;
    snprintf(o.addr, sizeof(o.addr), "%s", addr ? addr : "");
    o.version = 170100;
    o.best_height = height;
    if (hashc)
        ns_hash(o.tip_hash, hashc);
    return o;
}

/* ── 1. peer tip disagreement fold ───────────────────────────────────── */

static int test_tip_disagreement(void)
{
    int failures = 0;
    printf("peer tip disagreement fold (our own tip injected)...\n");

    char ours[PEER_OBS_TIP_HEX + 1];
    char theirs[PEER_OBS_TIP_HEX + 1];
    ns_hash(ours, 'a');
    ns_hash(theirs, 'b');

    struct db_peer_chain_observation obs[8];
    nm_group_key_t grp[8];
    struct network_partition_view pv;

    /* (a) MINORITY SIDE: 4 peers across 3 distinct address groups all hold
     *     `theirs` at our height; nobody holds ours. Must fire. */
    memset(grp, 0, sizeof(grp));
    obs[0] = ns_obs(1, 100, 'b', "10.1.0.1:8033");   snprintf(grp[0], sizeof(grp[0]), "g1");
    obs[1] = ns_obs(2, 100, 'b', "10.2.0.1:8033");   snprintf(grp[1], sizeof(grp[1]), "g2");
    obs[2] = ns_obs(3, 100, 'b', "10.3.0.1:8033");   snprintf(grp[2], sizeof(grp[2]), "g3");
    obs[3] = ns_obs(4, 100, 'b', "10.1.0.2:8033");   snprintf(grp[3], sizeof(grp[3]), "g1");
    memset(&pv, 0, sizeof(pv));
    network_monitor_fold_tip_disagreement(obs, 4, grp, 100, ours, &pv);
    NS_CHECK(pv.peer_tip_disagreement);
    NS_CHECK(pv.at_height == 100);
    NS_CHECK(pv.rival_peers == 4);
    NS_CHECK(pv.rival_groups == 3);
    NS_CHECK(pv.agreeing_peers == 0);
    NS_CHECK(pv.agreeing_groups == 0);
    NS_CHECK(pv.peers_considered == 4);
    NS_CHECK(strcmp(pv.rival_tip_hash, theirs) == 0);
    NS_CHECK(strcmp(pv.our_tip_hash, ours) == 0);

    /* (b) ONE PEER disagreeing must NOT fire (one group, one peer). */
    memset(grp, 0, sizeof(grp));
    obs[0] = ns_obs(1, 100, 'b', "10.1.0.1:8033");   snprintf(grp[0], sizeof(grp[0]), "g1");
    memset(&pv, 0, sizeof(pv));
    network_monitor_fold_tip_disagreement(obs, 1, grp, 100, ours, &pv);
    NS_CHECK(!pv.peer_tip_disagreement);
    NS_CHECK(pv.rival_peers == 1);
    NS_CHECK(pv.rival_groups == 1);

    /* (c) SAME ADDRESS GROUP does not count twice: five peers, all in g1.
     *     Peer count clears the bar; distinct-group count never does. */
    memset(grp, 0, sizeof(grp));
    for (int i = 0; i < 5; i++) {
        char addr[64];
        snprintf(addr, sizeof(addr), "10.1.0.%d:8033", i + 1);
        obs[i] = ns_obs(i + 1, 100, 'b', addr);
        snprintf(grp[i], sizeof(grp[i]), "g1");
    }
    memset(&pv, 0, sizeof(pv));
    network_monitor_fold_tip_disagreement(obs, 5, grp, 100, ours, &pv);
    NS_CHECK(!pv.peer_tip_disagreement);
    NS_CHECK(pv.rival_peers == 5);
    NS_CHECK(pv.rival_groups == 1);

    /* (d) NORMAL: everyone agrees with us — no rival cluster at all. */
    memset(grp, 0, sizeof(grp));
    for (int i = 0; i < 4; i++) {
        char addr[64];
        snprintf(addr, sizeof(addr), "10.%d.0.1:8033", i + 1);
        obs[i] = ns_obs(i + 1, 100, 'a', addr);
        snprintf(grp[i], sizeof(grp[i]), "g%d", i + 1);
    }
    memset(&pv, 0, sizeof(pv));
    network_monitor_fold_tip_disagreement(obs, 4, grp, 100, ours, &pv);
    NS_CHECK(!pv.peer_tip_disagreement);
    NS_CHECK(pv.agreeing_peers == 4);
    NS_CHECK(pv.agreeing_groups == 4);
    NS_CHECK(pv.rival_peers == 0);
    NS_CHECK(pv.rival_tip_hash[0] == '\0');

    /* (e) EVEN FORK: 3 groups on theirs, 3 groups on ours. That is a fork,
     *     not evidence that WE are the minority — must NOT fire. */
    memset(grp, 0, sizeof(grp));
    for (int i = 0; i < 3; i++) {
        obs[i] = ns_obs(i + 1, 100, 'b', "10.9.0.1:8033");
        snprintf(grp[i], sizeof(grp[i]), "r%d", i);
    }
    for (int i = 3; i < 6; i++) {
        obs[i] = ns_obs(i + 1, 100, 'a', "10.8.0.1:8033");
        snprintf(grp[i], sizeof(grp[i]), "m%d", i);
    }
    memset(&pv, 0, sizeof(pv));
    network_monitor_fold_tip_disagreement(obs, 6, grp, 100, ours, &pv);
    NS_CHECK(!pv.peer_tip_disagreement);
    NS_CHECK(pv.rival_groups == 3 && pv.agreeing_groups == 3);

    /* (f) A LAGGING peer's different tip proves nothing; a peer AHEAD of us
     *     cannot be adjudicated from a tip hash and only counts as context. */
    memset(grp, 0, sizeof(grp));
    obs[0] = ns_obs(1, 90,  'b', "10.1.0.1:8033");  snprintf(grp[0], sizeof(grp[0]), "g1");
    obs[1] = ns_obs(2, 90,  'b', "10.2.0.1:8033");  snprintf(grp[1], sizeof(grp[1]), "g2");
    obs[2] = ns_obs(3, 110, 'b', "10.3.0.1:8033");  snprintf(grp[2], sizeof(grp[2]), "g3");
    obs[3] = ns_obs(4, 110, 'b', "10.4.0.1:8033");  snprintf(grp[3], sizeof(grp[3]), "g4");
    memset(&pv, 0, sizeof(pv));
    network_monitor_fold_tip_disagreement(obs, 4, grp, 100, ours, &pv);
    NS_CHECK(!pv.peer_tip_disagreement);
    NS_CHECK(pv.peers_considered == 0);
    NS_CHECK(pv.peers_ahead == 2);

    /* (g) Missing group keys fall back to the addr string — three distinct
     *     addresses are still three groups, and NULL keys work at all. */
    memset(grp, 0, sizeof(grp));
    obs[0] = ns_obs(1, 100, 'b', "10.1.0.1:8033");
    obs[1] = ns_obs(2, 100, 'b', "10.2.0.1:8033");
    obs[2] = ns_obs(3, 100, 'b', "10.3.0.1:8033");
    memset(&pv, 0, sizeof(pv));
    network_monitor_fold_tip_disagreement(obs, 3, NULL, 100, ours, &pv);
    NS_CHECK(pv.peer_tip_disagreement);
    NS_CHECK(pv.rival_groups == 3);

    /* ... but two peers behind ONE address still count as one group. */
    memset(&pv, 0, sizeof(pv));
    obs[1] = ns_obs(2, 100, 'b', "10.1.0.1:8033");
    obs[2] = ns_obs(3, 100, 'b', "10.1.0.1:8033");
    network_monitor_fold_tip_disagreement(obs, 3, NULL, 100, ours, &pv);
    NS_CHECK(!pv.peer_tip_disagreement);
    NS_CHECK(pv.rival_groups == 1 && pv.rival_peers == 3);

    /* (h) Hash case is normalised, so an UPPERCASE rendering of our own tip
     *     is agreement, never a "rival chain". */
    memset(grp, 0, sizeof(grp));
    for (int i = 0; i < 3; i++) {
        char addr[64];
        snprintf(addr, sizeof(addr), "10.%d.0.1:8033", i + 1);
        obs[i] = ns_obs(i + 1, 100, 'a', addr);
        snprintf(grp[i], sizeof(grp[i]), "g%d", i + 1);
    }
    {
        char upper[PEER_OBS_TIP_HEX + 1];
        ns_hash(upper, 'A');
        for (int i = 0; i < 3; i++)
            snprintf(obs[i].tip_hash, sizeof(obs[i].tip_hash), "%s", upper);
        memset(&pv, 0, sizeof(pv));
        network_monitor_fold_tip_disagreement(obs, 3, grp, 100, upper, &pv);
        NS_CHECK(!pv.peer_tip_disagreement);
        NS_CHECK(pv.agreeing_peers == 3);
        NS_CHECK(strcmp(pv.our_tip_hash, ours) == 0); /* stored lowercased */
        /* mixed case across the two sides is still one chain */
        memset(&pv, 0, sizeof(pv));
        network_monitor_fold_tip_disagreement(obs, 3, grp, 100, ours, &pv);
        NS_CHECK(!pv.peer_tip_disagreement);
        NS_CHECK(pv.agreeing_peers == 3 && pv.rival_peers == 0);
    }

    /* (i) No usable tip of our own ⇒ report nothing, never guess. */
    memset(&pv, 0, sizeof(pv));
    network_monitor_fold_tip_disagreement(obs, 3, NULL, 100, NULL, &pv);
    NS_CHECK(!pv.peer_tip_disagreement && pv.at_height == -1);
    memset(&pv, 0, sizeof(pv));
    network_monitor_fold_tip_disagreement(obs, 3, NULL, 100, "not-a-hash", &pv);
    NS_CHECK(!pv.peer_tip_disagreement && pv.at_height == -1);
    memset(&pv, 0, sizeof(pv));
    network_monitor_fold_tip_disagreement(obs, 3, NULL, -1, ours, &pv);
    NS_CHECK(!pv.peer_tip_disagreement && pv.at_height == -1);

    /* NULL out must not crash. */
    network_monitor_fold_tip_disagreement(obs, 3, NULL, 100, ours, NULL);

    return failures;
}

/* ── 2. block-arrival rate fold ──────────────────────────────────────── */

/* Build a window of `n` blocks arriving every `interval` seconds at a fixed
 * compact difficulty. */
static int ns_window(struct nm_arrival_sample *w, int n, int64_t interval,
                     uint32_t nbits)
{
    for (int i = 0; i < n; i++) {
        w[i].height = 1000 + i;
        w[i].time_unix = 1700000000 + (int64_t)i * interval;
        w[i].nbits = nbits;
    }
    return n;
}

static int test_arrival_rate(void)
{
    int failures = 0;
    printf("block-arrival rate vs nBits-implied difficulty...\n");

    /* A plausible mainnet-shaped compact target. Its absolute value never
     * matters: the fold only ever uses difficulty RATIOS. */
    const uint32_t NBITS = 0x1c07ffff;
    struct nm_arrival_sample w[NM_ARRIVAL_MAX_WINDOW_BLOCKS];
    struct network_arrival_rate ar;

    /* (a) On target: 150 s spacing, flat difficulty ⇒ ratio ~1000, no fire. */
    int n = ns_window(w, 24, 150, NBITS);
    network_monitor_fold_arrival_rate(w, n, 150, &ar);
    NS_CHECK(ar.ready);
    NS_CHECK(!ar.rate_below_floor);
    NS_CHECK(ar.observed_interval_milli == 150000);
    NS_CHECK(ar.expected_interval_milli == 150000);
    NS_CHECK(ar.implied_hashrate_ratio_milli >= 990 &&
             ar.implied_hashrate_ratio_milli <= 1010);

    /* (b) NORMAL VARIANCE: 40% slow (210 s). Well inside Poisson noise for a
     *     24-block window — must NOT fire. */
    n = ns_window(w, 24, 210, NBITS);
    network_monitor_fold_arrival_rate(w, n, 150, &ar);
    NS_CHECK(ar.ready && !ar.rate_below_floor);
    NS_CHECK(ar.implied_hashrate_ratio_milli > NM_ARRIVAL_LOW_RATIO_MILLI);

    /* Even a 2x-slow window stays above the floor (ratio 500). */
    n = ns_window(w, 24, 300, NBITS);
    network_monitor_fold_arrival_rate(w, n, 150, &ar);
    NS_CHECK(ar.ready && !ar.rate_below_floor);

    /* (c) MINORITY SIDE: blocks arriving 4x slower than this chain's own
     *     difficulty predicts ⇒ ~25% of the calibrated hashrate. Fires. */
    n = ns_window(w, 24, 600, NBITS);
    network_monitor_fold_arrival_rate(w, n, 150, &ar);
    NS_CHECK(ar.ready && ar.rate_below_floor);
    NS_CHECK(ar.implied_hashrate_ratio_milli >= 240 &&
             ar.implied_hashrate_ratio_milli <= 260);

    /* (d) The nBits baseline is load-bearing, not decoration: the SAME 600 s
     *     spacing with difficulty that has already RETARGETED down 4x (a
     *     larger compact target == easier == lower difficulty) is the chain
     *     correctly re-calibrating, and must NOT fire. */
    ns_window(w, 24, 600, NBITS);
    for (int i = 12; i < 24; i++)
        w[i].nbits = 0x1c1ffffc; /* ~4x easier ⇒ ~1/4 the difficulty */
    network_monitor_fold_arrival_rate(w, 24, 150, &ar);
    NS_CHECK(ar.ready);
    NS_CHECK(ar.difficulty_ratio_milli < 1000); /* difficulty really fell */

    /* Conversely: on-target spacing while difficulty CLIMBED 4x means the
     *     chain is being mined far harder than its opening calibration —
     *     also not a minority signal. */
    ns_window(w, 24, 150, 0x1c01ffff); /* harder baseline */
    network_monitor_fold_arrival_rate(w, 24, 150, &ar);
    NS_CHECK(ar.ready && !ar.rate_below_floor);

    /* (e) Refusals: short window, non-monotonic timestamps, bad spacing. */
    n = ns_window(w, NM_ARRIVAL_MIN_WINDOW_BLOCKS - 1, 600, NBITS);
    network_monitor_fold_arrival_rate(w, n, 150, &ar);
    NS_CHECK(!ar.ready && !ar.rate_below_floor);

    n = ns_window(w, 24, 600, NBITS);
    for (int i = 0; i < n; i++)
        w[i].time_unix = 1700000000; /* zero span */
    network_monitor_fold_arrival_rate(w, n, 150, &ar);
    NS_CHECK(!ar.ready && !ar.rate_below_floor);

    ns_window(w, 24, 600, NBITS);
    network_monitor_fold_arrival_rate(w, 24, 0, &ar);
    NS_CHECK(!ar.ready);
    network_monitor_fold_arrival_rate(NULL, 24, 150, &ar);
    NS_CHECK(!ar.ready);
    network_monitor_fold_arrival_rate(w, 24, 150, NULL); /* must not crash */

    return failures;
}

/* ── 3. composite verdict ────────────────────────────────────────────── */

static void ns_arm_peer_signal(struct network_partition_view *pv)
{
    char ours[PEER_OBS_TIP_HEX + 1];
    ns_hash(ours, 'a');
    struct db_peer_chain_observation obs[3];
    nm_group_key_t grp[3];
    memset(grp, 0, sizeof(grp));
    obs[0] = ns_obs(1, 100, 'b', "10.1.0.1:8033"); snprintf(grp[0], sizeof(grp[0]), "g1");
    obs[1] = ns_obs(2, 100, 'b', "10.2.0.1:8033"); snprintf(grp[1], sizeof(grp[1]), "g2");
    obs[2] = ns_obs(3, 100, 'b', "10.3.0.1:8033"); snprintf(grp[2], sizeof(grp[2]), "g3");
    memset(pv, 0, sizeof(*pv));
    network_monitor_fold_tip_disagreement(obs, 3, grp, 100, ours, pv);
}

static int test_verdict(void)
{
    int failures = 0;
    printf("composite verdict — no single source decides...\n");

    struct network_partition_view pv;
    const uint32_t NBITS = 0x1c07ffff;
    struct nm_arrival_sample w[NM_ARRIVAL_MAX_WINDOW_BLOCKS];

    /* (a) Peer signal ALONE must not raise the verdict, however many groups
     *     back it. Peer testimony is never sufficient. */
    ns_arm_peer_signal(&pv);
    NS_CHECK(pv.peer_tip_disagreement);
    ns_window(w, 24, 150, NBITS);
    network_monitor_fold_arrival_rate(w, 24, 150, &pv.arrival);
    network_monitor_partition_verdict(60, 5000, &pv);
    NS_CHECK(!pv.netsplit_suspected);
    NS_CHECK(pv.signals_firing == 1);
    NS_CHECK(strstr(pv.reason, "held") != NULL);

    /* (b) Local signals ALONE (slow arrivals + stale tip, no peer
     *     disagreement) must not raise it either. */
    memset(&pv, 0, sizeof(pv));
    ns_window(w, 24, 600, NBITS);
    network_monitor_fold_arrival_rate(w, 24, 150, &pv.arrival);
    network_monitor_partition_verdict(NM_TIP_STALE_SECS + 1, 5000, &pv);
    NS_CHECK(!pv.netsplit_suspected);
    NS_CHECK(pv.signals_firing == 2);

    /* (c) Peer signal + slow block arrival ⇒ SUSPECTED. */
    ns_arm_peer_signal(&pv);
    ns_window(w, 24, 600, NBITS);
    network_monitor_fold_arrival_rate(w, 24, 150, &pv.arrival);
    network_monitor_partition_verdict(60, 5000, &pv);
    NS_CHECK(pv.netsplit_suspected);
    NS_CHECK(pv.signals_firing == 2);
    NS_CHECK(pv.computed_at == 5000);
    NS_CHECK(strstr(pv.reason, "SUSPECTED_NETSPLIT") != NULL);

    /* (d) Peer signal + stale tip ⇒ SUSPECTED (arrival window unusable). */
    ns_arm_peer_signal(&pv);
    memset(&pv.arrival, 0, sizeof(pv.arrival));
    network_monitor_partition_verdict(NM_TIP_STALE_SECS + 1, 5000, &pv);
    NS_CHECK(pv.netsplit_suspected);
    NS_CHECK(pv.tip_stale);
    NS_CHECK(pv.signals_firing == 2);

    /* Exactly at the threshold is not yet stale. */
    ns_arm_peer_signal(&pv);
    memset(&pv.arrival, 0, sizeof(pv.arrival));
    network_monitor_partition_verdict(NM_TIP_STALE_SECS, 5000, &pv);
    NS_CHECK(!pv.tip_stale && !pv.netsplit_suspected);

    /* Unknown tip age never fires signal 3. */
    ns_arm_peer_signal(&pv);
    memset(&pv.arrival, 0, sizeof(pv.arrival));
    network_monitor_partition_verdict(-1, 5000, &pv);
    NS_CHECK(!pv.tip_stale && !pv.netsplit_suspected);

    /* (e) All quiet. */
    memset(&pv, 0, sizeof(pv));
    ns_window(w, 24, 150, NBITS);
    network_monitor_fold_arrival_rate(w, 24, 150, &pv.arrival);
    network_monitor_partition_verdict(60, 5000, &pv);
    NS_CHECK(!pv.netsplit_suspected && pv.signals_firing == 0);
    NS_CHECK(pv.ready);
    NS_CHECK(strcmp(pv.reason, "no partition signal") == 0);

    network_monitor_partition_verdict(60, 5000, NULL); /* must not crash */

    return failures;
}

/* ── 4. live predicate + dumper ──────────────────────────────────────── */

static int test_live_surface(void)
{
    int failures = 0;
    printf("live predicate + netsplit dumper...\n");

    /* Nothing folded yet ⇒ the predicate is false, never "unknown". */
    struct network_partition_view got;
    memset(&got, 0, sizeof(got));
    NS_CHECK(!network_monitor_netsplit_suspected(&got));
    NS_CHECK(!network_monitor_netsplit_suspected(NULL));

    /* Inject a suspected verdict and read it back through the predicate. */
    struct network_partition_view pv;
    const uint32_t NBITS = 0x1c07ffff;
    struct nm_arrival_sample w[NM_ARRIVAL_MAX_WINDOW_BLOCKS];
    ns_arm_peer_signal(&pv);
    ns_window(w, 24, 600, NBITS);
    network_monitor_fold_arrival_rate(w, 24, 150, &pv.arrival);
    network_monitor_partition_verdict(60, 7777, &pv);
    NS_CHECK(pv.netsplit_suspected);
    network_monitor_netsplit_publish(&pv);

    memset(&got, 0, sizeof(got));
    NS_CHECK(network_monitor_netsplit_suspected(&got));
    NS_CHECK(got.ready);
    NS_CHECK(got.computed_at == 7777);
    NS_CHECK(got.rival_groups == 3);

    /* The dumper must publish the verdict and mark itself unhealthy. */
    struct json_value out;
    json_init(&out);
    NS_CHECK(network_monitor_netsplit_dump_state_json(&out, NULL));
    const struct json_value *v = json_get(&out, "netsplit_suspected");
    NS_CHECK(v != NULL && json_get_bool(v));
    v = json_get(&out, "reason");
    NS_CHECK(v != NULL && json_get_str(v) != NULL &&
             strstr(json_get_str(v), "SUSPECTED_NETSPLIT") != NULL);
    v = json_get(&out, "signals_firing");
    NS_CHECK(v != NULL && json_get_int(v) == 2);

    const struct json_value *s1 = json_get(&out, "peer_tip_disagreement");
    NS_CHECK(s1 != NULL);
    NS_CHECK(s1 && json_get(s1, "firing") &&
             json_get_bool(json_get(s1, "firing")));
    NS_CHECK(s1 && json_get(s1, "rival_groups") &&
             json_get_int(json_get(s1, "rival_groups")) == 3);

    const struct json_value *s2 = json_get(&out, "arrival_rate");
    NS_CHECK(s2 != NULL);
    NS_CHECK(s2 && json_get(s2, "implied_hashrate_ratio_milli") != NULL);
    NS_CHECK(s2 && json_get(s2, "firing") &&
             json_get_bool(json_get(s2, "firing")));

    const struct json_value *s3 = json_get(&out, "tip_staleness");
    NS_CHECK(s3 != NULL);
    NS_CHECK(s3 && json_get(s3, "stale_secs") &&
             json_get_int(json_get(s3, "stale_secs")) == NM_TIP_STALE_SECS);

    /* Health rollup contract: every dumper publishes `_health`. */
    NS_CHECK(json_get(&out, "_health") != NULL);
    json_free(&out);

    /* Clear it back to healthy so the shared process state is not left armed
     * for any other group in the same binary. */
    memset(&pv, 0, sizeof(pv));
    network_monitor_partition_verdict(60, 7778, &pv);
    network_monitor_netsplit_publish(&pv);
    NS_CHECK(!network_monitor_netsplit_suspected(NULL));

    NS_CHECK(!network_monitor_netsplit_dump_state_json(NULL, NULL));
    return failures;
}

int test_netsplit_detector(void)
{
    printf("\n=== netsplit detector tests ===\n");
    int failures = 0;
    failures += test_tip_disagreement();
    failures += test_arrival_rate();
    failures += test_verdict();
    failures += test_live_surface();
    if (failures == 0)
        printf("=== netsplit detector: all passed ===\n");
    else
        printf("=== netsplit detector: %d FAILED ===\n", failures);
    return failures;
}
