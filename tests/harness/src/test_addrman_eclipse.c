/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Adversarial eclipse-attack / poisoning coverage for addrman
 * (core/modules/net/src/addrman.c). Extends test_addrman_rebalance.c (which already
 * checks basic bucket-stat sanity + "not ALL 1024 buckets fill from one
 * source") with the SPECIFIC bounds the code actually enforces, and the
 * behaviors test_addrman_rebalance.c does not touch: selection diversity
 * under a flood, tried-table eviction bounds, and terrible/stale handling.
 *
 * The resistance properties under test, and which constant each rides on:
 *
 *   - NEW-table family bound: addr_info_get_new_bucket() computes
 *     bucket_seed = h1 % ADDRMAN_NEW_BUCKETS_PER_SOURCE_GROUP (64) where h1
 *     depends on (nKey, own_group, source_group), then the final bucket is
 *     hash256(nKey, source_group, bucket_seed) mod ADDRMAN_NEW_BUCKET_COUNT
 *     (1024). For a FIXED nKey and FIXED source_group, the final bucket is
 *     a pure function of bucket_seed alone (own_group only feeds bucket_seed,
 *     not the final hash) — so AT MOST 64 distinct bucket values are ever
 *     reachable, REGARDLESS of how many distinct destination addresses the
 *     flood uses. This is a combinatorial bound (asserted directly against
 *     the function, no insertion needed), not a statistical one. §1.
 *   - The same bound shows up in real addrman_add() floods as long as the
 *     flood stays under the ~64*ADDRMAN_BUCKET_SIZE new-table family
 *     capacity, so collision-driven probing (the "+97*attempt" retry ladder
 *     in addrman_add) rarely needs to spill outside the family. §2.
 *   - Selection diversity: addrman_select() draws a uniformly random
 *     (bucket,pos); if empty it scans forward for the nearest occupied
 *     slot, so which entry gets returned is governed by which BUCKETS are
 *     occupied, not by how many addresses are crammed into them. A
 *     source-group flood confined to <=64 buckets therefore cannot swamp
 *     honest addresses spread across many more buckets. §3.
 *   - TRIED-table family bound: addr_info_get_tried_bucket() groups by the
 *     ADDRESS'S OWN /16 (net_addr_get_group on info->addr, not source),
 *     restricted to ADDRMAN_TRIED_BUCKETS_PER_GROUP (8) of
 *     ADDRMAN_TRIED_BUCKET_COUNT (256) buckets for a fixed own-group. An
 *     attacker who owns exactly one real /16 can promote unlimited
 *     addresses to tried but can only ever touch <=8 tried buckets, so
 *     for any set of K honest tried entries (each in a bucket determined
 *     by ITS OWN distinct group) at most min(K, 8) can ever be evicted —
 *     again combinatorial, not statistical. §4, §5.
 *   - addr_info_is_terrible() / addrman_get_addr(): entries past
 *     ADDRMAN_HORIZON_DAYS / ADDRMAN_RETRIES / (ADDRMAN_MIN_FAIL_DAYS,
 *     ADDRMAN_MAX_FAILURES) are excluded from GETADDR responses and lose
 *     insertion-collision priority to fresher entries. §6.
 *
 * Determinism: every GetRandBytes/GetRandInt call in addrman.c (nKey
 * generation in addrman_init, the bucket rescan in addrman_good, the probe
 * loop in addrman_select) is routed through platform/rng.h. This file
 * installs a seeded xorshift64 `rng_iface_t` (same technique as
 * tests/harness/src/test_rng.c) for its whole run and restores the real default
 * on every exit path, so a failure reproduces exactly from
 * ADDRMAN_ECLIPSE_SEED below — no wall-clock/entropy dependency. Wall time
 * (platform_time_wall_time_t) is still read as an anchor for "N days ago"
 * timestamps, matching test_addrman_rebalance.c's convention — only
 * OFFSETS from "now" are asserted, never absolute values. */

#include "test/test_core.h"
#include "net/addrman.h"
#include "platform/rng.h"
#include "platform/time_compat.h"
#include "core/random.h"
#include "util/timedata.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define ADDRMAN_ECLIPSE_SEED 0xA1CEA11ACEULL   /* "alice ace" — arbitrary, fixed */

/* ── Seeded xorshift64 RNG (mirrors test_rng.c's xs64) ─────────────── */

struct ae_xs64 {
    uint64_t state;
};

static uint64_t ae_xs64_next(struct ae_xs64 *r)
{
    uint64_t x = r->state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    r->state = x;
    return x;
}

static bool ae_xs64_fill(void *self, uint8_t *out, size_t len)
{
    struct ae_xs64 *r = (struct ae_xs64 *)self;
    size_t i = 0;
    while (i < len) {
        uint64_t v = ae_xs64_next(r);
        size_t chunk = len - i;
        if (chunk > sizeof(v)) chunk = sizeof(v);
        memcpy(out + i, &v, chunk);
        i += chunk;
    }
    return true;
}

/* ── Address builders (public-range IPv4-mapped, matches
 *    test_addrman_rebalance.c's make_pub_addr/make_pub_source) ────── */

static struct net_address ae_addr(uint8_t a, uint8_t b, uint8_t c, uint8_t d,
                                   uint16_t port)
{
    struct net_address addr;
    memset(&addr, 0, sizeof(addr));
    memset(addr.svc.addr.ip, 0, 10);
    addr.svc.addr.ip[10] = 0xff;
    addr.svc.addr.ip[11] = 0xff;
    addr.svc.addr.ip[12] = a;
    addr.svc.addr.ip[13] = b;
    addr.svc.addr.ip[14] = c;
    addr.svc.addr.ip[15] = d ? d : 1;
    addr.svc.port = port;
    addr.nTime = (uint32_t)platform_time_wall_time_t();
    addr.nServices = 1;
    return addr;
}

static struct net_addr ae_source(uint8_t a, uint8_t b, uint8_t c, uint8_t d)
{
    struct net_addr src;
    memset(&src, 0, sizeof(src));
    memset(src.ip, 0, 10);
    src.ip[10] = 0xff;
    src.ip[11] = 0xff;
    src.ip[12] = a;
    src.ip[13] = b;
    src.ip[14] = c;
    src.ip[15] = d ? d : 1;
    return src;
}

/* Find the entry id for an address by direct linear scan of the (public)
 * `entries` array — addrman.c's find_addr() is static, but struct addr_man
 * is fully defined in the header, so tests may read `entries`/`id_count`
 * directly. Returns -1 if not found. */
static int ae_find_id(const struct addr_man *am, const struct net_address *a)
{
    for (int i = 0; i < am->id_count; i++) {
        if (am->entries[i].used &&
            memcmp(am->entries[i].addr.svc.addr.ip, a->svc.addr.ip, 16) == 0 &&
            am->entries[i].addr.svc.port == a->svc.port)
            return i;
    }
    return -1;
}

int test_addrman_eclipse(void);

int test_addrman_eclipse(void)
{
    int failures = 0;

    struct ae_xs64 rng_state = { .state = ADDRMAN_ECLIPSE_SEED };
    const rng_iface_t iface = { .fill = ae_xs64_fill, .self = &rng_state };
    rng_set_default(&iface);

    /* ── 1. NEW-table family bound is a pure function of the source
     *      group (no insertion needed) ───────────────────────────── */
    printf("addrman_eclipse: new-bucket family bounded by source group... ");
    {
        struct addr_man am;
        addrman_init(&am);
        struct net_addr attacker_src = ae_source(41, 7, 0, 1);

        bool seen[ADDRMAN_NEW_BUCKET_COUNT];
        memset(seen, 0, sizeof(seen));
        int distinct = 0;

        /* 4000 distinct destination addresses, ONE fixed source group.
         * addr_info_get_new_bucket() is called directly — no addrman_add,
         * so this is exact: it measures the reachable SET, not whatever an
         * insertion-order-dependent probe ladder happens to hit.
         *
         * bucket_seed = h1 % 64 where h1 = hash256(nKey, OWN_group,
         * source_group) — for a fixed nKey and fixed source_group, h1 (and
         * hence bucket_seed) varies ONLY with the destination's OWN /16
         * group (net_addr_get_group folds in the first two octets, see
         * core/modules/net/src/netaddr.c). The old generator held the first octet
         * fixed at 90 and swept the second octet over only 0..15 (16
         * groups) — far too few to ever approach the 64-bucket bound, so
         * the assertion below passed regardless of whether the bound was
         * enforced. Base-80 decomposition of i gives a bijection onto
         * 50*80=4000 distinct (octet1,octet2) own-group pairs, well above
         * 64, so the bound is the binding constraint, not group scarcity. */
        for (int i = 0; i < 4000; i++) {
            struct net_address dst = ae_addr(
                (uint8_t)(90 + (i / 80) % 150),
                (uint8_t)(1 + (i % 80)),
                (uint8_t)(i % 256),
                (uint8_t)((i * 3) % 254 + 1), 8033);
            struct addr_info info;
            memset(&info, 0, sizeof(info));
            info.addr = dst;
            info.source = attacker_src;
            int b = addr_info_get_new_bucket(&info, &am.nKey, &attacker_src);
            if (b >= 0 && b < ADDRMAN_NEW_BUCKET_COUNT && !seen[b]) {
                seen[b] = true;
                distinct++;
            }
        }

        bool ok = distinct <= ADDRMAN_NEW_BUCKETS_PER_SOURCE_GROUP;
        ok = ok && distinct > 0;
        if (ok)
            printf("OK (distinct=%d, bound=%d)\n", distinct,
                   ADDRMAN_NEW_BUCKETS_PER_SOURCE_GROUP);
        else {
            printf("FAIL (distinct=%d, bound=%d)\n", distinct,
                   ADDRMAN_NEW_BUCKETS_PER_SOURCE_GROUP);
            failures++;
        }
        addrman_free(&am);
    }

    /* ── 2. Real flood: a single source group cannot occupy more than a
     *      small, bounded slice of the new table ────────────────────── */
    printf("addrman_eclipse: single-source-group real flood stays bounded... ");
    {
        struct addr_man am;
        addrman_init(&am);
        struct net_addr attacker_src = ae_source(42, 9, 0, 1);

        int added = 0;
        /* Stay under the ~64-bucket family's raw slot capacity
         * (ADDRMAN_NEW_BUCKETS_PER_SOURCE_GROUP * ADDRMAN_BUCKET_SIZE =
         * 64*64 = 4096) so the vast majority of inserts land at their
         * primary (attempt=0) bucket instead of spilling via the
         * +97*attempt collision ladder — that ladder is a
         * per-ADDRESS retry, not a way to reach more source-group
         * buckets, but enough collisions can still push a few
         * insertions outside the nominal family, hence the 3x slack
         * below rather than an exact 64.
         *
         * Same own-group-diversity requirement as §1: the old generator
         * held the destination's first octet fixed at 100 and swept the
         * second octet over only 0..11 (12 groups), so this flood could
         * never occupy more than ~12 new buckets regardless of the
         * ADDRMAN_NEW_BUCKETS_PER_SOURCE_GROUP=64 restriction — removing
         * the restriction would not have made this subtest fail. Base-60
         * decomposition of i gives a bijection onto 50*60=3000 distinct
         * destination own-group pairs, well above 64, so the flood
         * actually probes the family bound. */
        for (int i = 0; i < 3000; i++) {
            struct net_address dst = ae_addr(
                (uint8_t)(100 + (i / 60) % 150),
                (uint8_t)(1 + (i % 60)),
                (uint8_t)(i % 256),
                (uint8_t)((i * 5) % 254 + 1), 8033);
            if (addrman_add(&am, &dst, &attacker_src, 0))
                added++;
        }

        struct addrman_bucket_stats stats;
        addrman_get_bucket_stats(&am, &stats);

        int bound = ADDRMAN_NEW_BUCKETS_PER_SOURCE_GROUP * 3;
        bool ok = stats.new_buckets_nonempty <= bound;
        /* And, regardless of slack, nowhere near the full 1024-bucket
         * table — the actual eclipse-resistance headline number. */
        ok = ok && stats.new_buckets_nonempty < ADDRMAN_NEW_BUCKET_COUNT / 4;
        ok = ok && (addrman_consistency_check(&am, NULL, 0) == 0);

        if (ok)
            printf("OK (added=%d, buckets=%d/%d, bound=%d)\n", added,
                   stats.new_buckets_nonempty, ADDRMAN_NEW_BUCKET_COUNT, bound);
        else {
            printf("FAIL (added=%d, buckets=%d/%d, bound=%d)\n", added,
                   stats.new_buckets_nonempty, ADDRMAN_NEW_BUCKET_COUNT, bound);
            failures++;
        }
        addrman_free(&am);
    }

    /* ── 3. Selection diversity: after the flood, honest addresses from
     *      many OTHER source groups still come back from addrman_select
     *      at a rate consistent with bucket-count share, not
     *      address-count share (attacker has ~50-100x more addresses) ── */
    printf("addrman_eclipse: selection diversity survives a flood... ");
    {
        struct addr_man am;
        addrman_init(&am);

        /* 80 honest addresses, each its OWN distinct /16 source group
         * (first octet varies 130..209, second octet fixed) — realistic
         * "many independent peers gossiped us many other peers" shape. */
        int honest_added = 0;
        for (int s = 0; s < 80; s++) {
            struct net_addr src = ae_source((uint8_t)(130 + s), 5, 0, 1);
            struct net_address dst = ae_addr((uint8_t)(130 + s), 6,
                                             (uint8_t)(s + 1), 1, 8033);
            if (addrman_add(&am, &dst, &src, 0))
                honest_added++;
        }
        struct addrman_bucket_stats before;
        addrman_get_bucket_stats(&am, &before);

        /* Attacker: single source group, 3000 addresses (37x the honest
         * count) — the whole point of the flood is to outnumber honest
         * addresses by a large margin. */
        struct net_addr attacker_src = ae_source(43, 3, 0, 1);
        int attacker_added = 0;
        for (int i = 0; i < 3000; i++) {
            struct net_address dst = ae_addr(
                (uint8_t)(220 + i / 65536),
                (uint8_t)((i / 256) % 256),
                (uint8_t)(i % 256),
                (uint8_t)((i * 7) % 254 + 1), 8033);
            if (addrman_add(&am, &dst, &attacker_src, 0))
                attacker_added++;
        }

        struct addrman_bucket_stats after;
        addrman_get_bucket_stats(&am, &after);
        int honest_buckets = before.new_buckets_nonempty;
        int attacker_buckets = after.new_buckets_nonempty - before.new_buckets_nonempty;

        int honest_hits = 0, attacker_hits = 0, other_hits = 0;
        const int trials = 4000;
        for (int t = 0; t < trials; t++) {
            struct addr_info result;
            memset(&result, 0, sizeof(result));
            if (!addrman_select(&am, true, &result)) continue;
            uint8_t a0 = result.addr.svc.addr.ip[12];
            if (a0 >= 130 && a0 <= 209) honest_hits++;
            else if (a0 >= 220) attacker_hits++;
            else other_hits++;
        }

        /* Bucket-share floor: even with generous slack for hash skew,
         * honest addresses occupying a comparable/larger BUCKET share
         * than the attacker's <=64-bucket family must not be reduced to
         * a token minority of selections. Require honest_hits to clear
         * a floor derived from the measured bucket shares (not address
         * counts), with a 2x safety margin down from the naive
         * proportional expectation. */
        double bucket_total = (double)(honest_buckets + attacker_buckets);
        double expected_honest_frac = bucket_total > 0
            ? (double)honest_buckets / bucket_total : 0.0;
        double honest_frac = (double)honest_hits / (double)trials;
        bool ok = honest_frac >= expected_honest_frac / 2.0;
        /* And the attacker must not achieve near-total eclipse despite
         * its 37x address-count advantage. */
        ok = ok && (double)attacker_hits / (double)trials < 0.90;
        ok = ok && (addrman_consistency_check(&am, NULL, 0) == 0);

        if (ok)
            printf("OK (honest=%d attacker=%d other=%d /%d trials; "
                   "buckets honest=%d attacker=%d, honest_added=%d "
                   "attacker_added=%d)\n",
                   honest_hits, attacker_hits, other_hits, trials,
                   honest_buckets, attacker_buckets, honest_added,
                   attacker_added);
        else {
            printf("FAIL (honest=%d attacker=%d other=%d /%d trials; "
                   "buckets honest=%d attacker=%d expected_frac=%.4f "
                   "honest_frac=%.4f)\n",
                   honest_hits, attacker_hits, other_hits, trials,
                   honest_buckets, attacker_buckets, expected_honest_frac,
                   honest_frac);
            failures++;
        }
        addrman_free(&am);
    }

    /* ── 4. TRIED-table family bound is a pure function of the
     *      ADDRESS'S OWN group (no insertion needed) ────────────────── */
    printf("addrman_eclipse: tried-bucket family bounded by own group... ");
    {
        struct addr_man am;
        addrman_init(&am);

        bool seen[ADDRMAN_TRIED_BUCKET_COUNT];
        memset(seen, 0, sizeof(seen));
        int distinct = 0;

        /* 4000 distinct addresses all sharing ONE own-address /16
         * (77.7.x.x) — an attacker who genuinely owns this one block. */
        for (int i = 0; i < 4000; i++) {
            struct net_address dst = ae_addr(77, 7,
                (uint8_t)((i / 256) % 256), (uint8_t)((i * 3) % 254 + 1),
                8033);
            struct addr_info info;
            memset(&info, 0, sizeof(info));
            info.addr = dst;
            int b = addr_info_get_tried_bucket(&info, &am.nKey);
            if (b >= 0 && b < ADDRMAN_TRIED_BUCKET_COUNT && !seen[b]) {
                seen[b] = true;
                distinct++;
            }
        }

        bool ok = distinct <= ADDRMAN_TRIED_BUCKETS_PER_GROUP;
        ok = ok && distinct > 0;
        if (ok)
            printf("OK (distinct=%d, bound=%d)\n", distinct,
                   ADDRMAN_TRIED_BUCKETS_PER_GROUP);
        else {
            printf("FAIL (distinct=%d, bound=%d)\n", distinct,
                   ADDRMAN_TRIED_BUCKETS_PER_GROUP);
            failures++;
        }
        addrman_free(&am);
    }

    /* ── 5. Tried eviction is bounded: a single-group attacker flood to
     *      tried can evict at most ADDRMAN_TRIED_BUCKETS_PER_GROUP of any
     *      set of honest tried entries, each in its OWN distinct group —
     *      a hard combinatorial ceiling, verified for K=24 > 8 ─────── */
    printf("addrman_eclipse: tried eviction bounded, honest mostly survive... ");
    {
        struct addr_man am;
        addrman_init(&am);

        const int K = 24;
        struct net_address honest[24];
        int honest_id[24];

        for (int i = 0; i < K; i++) {
            /* Distinct own /16 per honest address (first octet varies) —
             * each therefore lands in its own tried bucket (barring an
             * incidental hash coincidence, which the assertion below
             * tolerates via the ADDRMAN_TRIED_BUCKETS_PER_GROUP margin
             * regardless). */
            struct net_addr src = ae_source((uint8_t)(150 + i), 1, 0, 1);
            honest[i] = ae_addr((uint8_t)(150 + i), 2, 3, 4, 8033);
            addrman_add(&am, &honest[i], &src, 0);
            addrman_good(&am, &honest[i].svc,
                         (int64_t)platform_time_wall_time_t());
            honest_id[i] = ae_find_id(&am, &honest[i]);
        }

        int honest_in_tried_before = 0;
        for (int i = 0; i < K; i++)
            if (honest_id[i] >= 0 && am.entries[honest_id[i]].in_tried)
                honest_in_tried_before++;

        /* Attacker: 2000 distinct addresses, ALL sharing ONE own /16
         * (78.8.x.x), each added and immediately promoted to tried —
         * enough volume to saturate every position in every one of its
         * <=8 reachable tried buckets. */
        struct net_addr attacker_src = ae_source(78, 8, 0, 1);
        for (int i = 0; i < 2000; i++) {
            struct net_address dst = ae_addr(78, 8,
                (uint8_t)((i / 256) % 256), (uint8_t)((i * 5) % 254 + 1),
                8033);
            addrman_add(&am, &dst, &attacker_src, 0);
            addrman_good(&am, &dst.svc, (int64_t)platform_time_wall_time_t());
        }

        int honest_in_tried_after = 0;
        for (int i = 0; i < K; i++)
            if (honest_id[i] >= 0 && am.entries[honest_id[i]].in_tried)
                honest_in_tried_after++;

        int evicted = honest_in_tried_before - honest_in_tried_after;

        bool ok = (addrman_consistency_check(&am, NULL, 0) == 0);
        /* The hard ceiling: an attacker confined to
         * ADDRMAN_TRIED_BUCKETS_PER_GROUP buckets can touch at most that
         * many of the K honest buckets (each honest entry's bucket is a
         * function of ITS OWN distinct group, independent of the
         * attacker's group), so at most that many can ever be evicted —
         * regardless of how many attacker addresses are thrown at it. */
        ok = ok && evicted <= ADDRMAN_TRIED_BUCKETS_PER_GROUP;
        ok = ok && honest_in_tried_before == K;   /* sanity: all promoted */
        ok = ok && honest_in_tried_after >= K - ADDRMAN_TRIED_BUCKETS_PER_GROUP;

        if (ok)
            printf("OK (K=%d before=%d after=%d evicted=%d ceiling=%d)\n",
                   K, honest_in_tried_before, honest_in_tried_after, evicted,
                   ADDRMAN_TRIED_BUCKETS_PER_GROUP);
        else {
            printf("FAIL (K=%d before=%d after=%d evicted=%d ceiling=%d)\n",
                   K, honest_in_tried_before, honest_in_tried_after, evicted,
                   ADDRMAN_TRIED_BUCKETS_PER_GROUP);
            failures++;
        }
        addrman_free(&am);
    }

    /* ── 6. terrible/old handling: freshness + attempt-limit thresholds,
     *      and exclusion from GETADDR responses ────────────────────── */
    printf("addrman_eclipse: terrible-address thresholds + getaddr exclusion... ");
    {
        int64_t now = (int64_t)platform_time_wall_time_t();
        bool sub_ok = true;

        /* Fresh, never-tried entry: not terrible. */
        {
            struct addr_info info;
            memset(&info, 0, sizeof(info));
            info.addr.nTime = (uint32_t)now;
            sub_ok = sub_ok && !addr_info_is_terrible(&info, now);
        }
        /* Past ADDRMAN_HORIZON_DAYS with no recent nTime: terrible. */
        {
            struct addr_info info;
            memset(&info, 0, sizeof(info));
            info.addr.nTime = (uint32_t)(now - (int64_t)(ADDRMAN_HORIZON_DAYS + 1) * 86400);
            sub_ok = sub_ok && addr_info_is_terrible(&info, now);
        }
        /* nTime == 0 (never announced a time) is always terrible. */
        {
            struct addr_info info;
            memset(&info, 0, sizeof(info));
            info.addr.nTime = 0;
            sub_ok = sub_ok && addr_info_is_terrible(&info, now);
        }
        /* attempts >= ADDRMAN_RETRIES with no success ever: terrible. */
        {
            struct addr_info info;
            memset(&info, 0, sizeof(info));
            info.addr.nTime = (uint32_t)now;
            info.last_success = 0;
            info.attempts = ADDRMAN_RETRIES;
            sub_ok = sub_ok && addr_info_is_terrible(&info, now);
        }
        /* attempts just under ADDRMAN_RETRIES, no success: not (yet)
         * terrible via that clause. */
        {
            struct addr_info info;
            memset(&info, 0, sizeof(info));
            info.addr.nTime = (uint32_t)now;
            info.last_success = 0;
            info.attempts = ADDRMAN_RETRIES - 1;
            sub_ok = sub_ok && !addr_info_is_terrible(&info, now);
        }
        /* Long past last success (> ADDRMAN_MIN_FAIL_DAYS) with
         * ADDRMAN_MAX_FAILURES attempts: terrible. */
        {
            struct addr_info info;
            memset(&info, 0, sizeof(info));
            info.addr.nTime = (uint32_t)now;
            info.last_success = now - (int64_t)(ADDRMAN_MIN_FAIL_DAYS + 1) * 86400;
            info.attempts = ADDRMAN_MAX_FAILURES;
            sub_ok = sub_ok && addr_info_is_terrible(&info, now);
        }
        /* get_chance is monotonically non-increasing in attempts. */
        {
            struct addr_info info;
            memset(&info, 0, sizeof(info));
            info.last_try = now - 24 * 60 * 60;   /* stale enough to skip
                                                    * the <10min penalty */
            double prev = 1.1;   /* > max possible chance (1.0) */
            for (int n = 0; n <= 8; n++) {
                info.attempts = n;
                double c = addr_info_get_chance(NULL, &info, now);
                sub_ok = sub_ok && c <= prev + 1e-12;
                prev = c;
            }
        }

        /* GETADDR exclusion: one terrible + several fresh addresses;
         * across many calls (positions are shuffled by addrman_get_addr's
         * Fisher-Yates-style swap_random) the terrible one is never
         * returned. */
        struct addr_man am;
        addrman_init(&am);
        struct net_addr src = ae_source(160, 1, 0, 1);

        struct net_address terrible = ae_addr(161, 1, 1, 1, 8033);
        terrible.nTime = (uint32_t)(now - (int64_t)(ADDRMAN_HORIZON_DAYS + 5) * 86400);
        addrman_add(&am, &terrible, &src, 0);

        for (int i = 0; i < 40; i++) {
            struct net_address fresh = ae_addr(161, 1, 2,
                                               (uint8_t)(i + 1), 8033);
            addrman_add(&am, &fresh, &src, 0);
        }

        bool terrible_leaked = false;
        for (int call = 0; call < 20 && !terrible_leaked; call++) {
            struct net_address out[64];
            size_t got = addrman_get_addr(&am, out, 64);
            for (size_t j = 0; j < got; j++) {
                if (memcmp(out[j].svc.addr.ip, terrible.svc.addr.ip, 16) == 0 &&
                    out[j].svc.port == terrible.svc.port) {
                    terrible_leaked = true;
                    break;
                }
            }
        }
        sub_ok = sub_ok && !terrible_leaked;
        sub_ok = sub_ok && (addrman_consistency_check(&am, NULL, 0) == 0);
        addrman_free(&am);

        if (sub_ok) printf("OK\n");
        else { printf("FAIL (terrible_leaked=%d)\n", terrible_leaked); failures++; }
    }

    rng_reset_default();
    return failures;
}
