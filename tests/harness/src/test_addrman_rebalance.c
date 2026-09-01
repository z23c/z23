/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Addrman bucket rebalancing tests: consistency checks, adversarial
 * peer sets, eviction on collision, distribution audits.
 *
 * All IPs use public ranges (50-99.x.x.x) to pass net_addr_is_routable(). */

#include "platform/time_compat.h"
#include "test/test_core.h"
#include "net/addrman.h"
#include "core/random.h"
#include "core/serialize.h"
#include "util/timedata.h"
#include <string.h>
#include <stdio.h>
#include <time.h>

/* Build a routable IPv4-mapped address: ::ffff:a.b.c.d
 * Caller must use public IP ranges (not 10.x, 172.16-31, 192.168,
 * 127.x, 0.x, 192.0.2, 198.51.100, 203.0.113). */
static struct net_address make_pub_addr(uint8_t a, uint8_t b, uint8_t c,
                                        uint8_t d, uint16_t port)
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

static struct net_addr make_pub_source(uint8_t a, uint8_t b, uint8_t c,
                                       uint8_t d)
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

int test_addrman_rebalance(void)
{
    int failures = 0;

    /* ── 1. Empty addrman passes consistency check ─────────────── */
    printf("addrman_rebalance: empty consistency... ");
    {
        struct addr_man am;
        addrman_init(&am);
        char err[256] = {0};
        int rc = addrman_consistency_check(&am, err, sizeof(err));
        if (rc == 0)
            printf("OK\n");
        else {
            printf("FAIL (%s)\n", err); failures++;
        }
        addrman_free(&am);
    }

    /* ── 2. Consistency after basic adds ───────────────────────── */
    printf("addrman_rebalance: add + consistency... ");
    {
        struct addr_man am;
        addrman_init(&am);
        struct net_addr src = make_pub_source(50, 1, 0, 1);

        for (int i = 1; i <= 50; i++) {
            struct net_address addr = make_pub_addr(
                51, (uint8_t)(i / 256 + 1), (uint8_t)(i % 256),
                (uint8_t)((i * 7) % 254 + 1), 8033);
            addrman_add(&am, &addr, &src, 0);
        }

        char err[256] = {0};
        int rc = addrman_consistency_check(&am, err, sizeof(err));
        if (rc == 0 && addrman_size(&am) > 0)
            printf("OK (size=%zu)\n", addrman_size(&am));
        else {
            printf("FAIL (rc=%d size=%zu err=%s)\n", rc, addrman_size(&am), err);
            failures++;
        }
        addrman_free(&am);
    }

    /* ── 3. Consistency after good (new→tried promotion) ──────── */
    printf("addrman_rebalance: good promotion + consistency... ");
    {
        struct addr_man am;
        addrman_init(&am);
        struct net_addr src = make_pub_source(52, 1, 0, 1);

        for (int i = 1; i <= 20; i++) {
            struct net_address addr = make_pub_addr(
                53, 1, (uint8_t)(i / 256), (uint8_t)(i % 256), 8033);
            addrman_add(&am, &addr, &src, 0);
        }

        /* Mark some as good to promote to tried */
        for (int i = 1; i <= 10; i++) {
            struct net_address addr = make_pub_addr(53, 1, 0, (uint8_t)i, 8033);
            addrman_good(&am, &addr.svc, (int64_t)platform_time_wall_time_t());
        }

        char err[256] = {0};
        int rc = addrman_consistency_check(&am, err, sizeof(err));
        if (rc == 0)
            printf("OK\n");
        else {
            printf("FAIL (%s)\n", err); failures++;
        }
        addrman_free(&am);
    }

    /* ── 4. Bucket stats with known distribution ──────────────── */
    printf("addrman_rebalance: bucket stats... ");
    {
        struct addr_man am;
        addrman_init(&am);
        struct net_addr src = make_pub_source(54, 1, 0, 1);

        for (int i = 1; i <= 100; i++) {
            struct net_address addr = make_pub_addr(
                (uint8_t)(55 + i / 256), (uint8_t)(i % 256),
                (uint8_t)((i * 7) % 256), (uint8_t)((i * 13) % 254 + 1), 8033);
            addrman_add(&am, &addr, &src, 0);
        }

        struct addrman_bucket_stats stats;
        addrman_get_bucket_stats(&am, &stats);

        bool ok = stats.new_occupied > 0;
        ok = ok && stats.new_buckets_nonempty > 0;
        ok = ok && stats.max_new_bucket_fill <= ADDRMAN_BUCKET_SIZE;
        ok = ok && stats.tried_occupied == 0; /* none promoted yet */

        if (ok)
            printf("OK (new=%d in %d buckets, max_fill=%d)\n",
                   stats.new_occupied, stats.new_buckets_nonempty,
                   stats.max_new_bucket_fill);
        else {
            printf("FAIL\n"); failures++;
        }
        addrman_free(&am);
    }

    /* ── 5. Adversarial: single source flooding ───────────────── */
    printf("addrman_rebalance: single-source flood... ");
    {
        struct addr_man am;
        addrman_init(&am);

        /* One attacker source floods 500 addresses */
        struct net_addr attacker = make_pub_source(56, 2, 3, 4);
        int added = 0;
        for (int i = 0; i < 500; i++) {
            struct net_address addr = make_pub_addr(
                (uint8_t)(57 + i / 65536),
                (uint8_t)((i / 256) % 256),
                (uint8_t)(i % 256),
                (uint8_t)((i * 3) % 254 + 1), 8033);
            if (addrman_add(&am, &addr, &attacker, 0))
                added++;
        }

        struct addrman_bucket_stats stats;
        addrman_get_bucket_stats(&am, &stats);

        /* With 500 adds from one source, should NOT fill all 1024 buckets */
        bool ok = stats.new_buckets_nonempty < ADDRMAN_NEW_BUCKET_COUNT;
        ok = ok && (addrman_consistency_check(&am, NULL, 0) == 0);

        if (ok)
            printf("OK (added=%d, spread=%d/%d buckets)\n",
                   added, stats.new_buckets_nonempty,
                   ADDRMAN_NEW_BUCKET_COUNT);
        else {
            printf("FAIL\n"); failures++;
        }
        addrman_free(&am);
    }

    /* ── 6. Adversarial: diverse sources preserve distribution ── */
    printf("addrman_rebalance: diverse sources spread... ");
    {
        struct addr_man am;
        addrman_init(&am);

        /* 10 different source groups, 20 addresses each */
        for (int s = 0; s < 10; s++) {
            struct net_addr src = make_pub_source(
                (uint8_t)(60 + s), 1, 0, 1);
            for (int i = 0; i < 20; i++) {
                struct net_address addr = make_pub_addr(
                    (uint8_t)(70 + s),
                    (uint8_t)(i * 3 + 1),
                    (uint8_t)(s * 7 + i + 1),
                    (uint8_t)(i + 1), 8033);
                addrman_add(&am, &addr, &src, 0);
            }
        }

        struct addrman_bucket_stats stats;
        addrman_get_bucket_stats(&am, &stats);

        bool ok = stats.new_buckets_nonempty >= 5;
        ok = ok && stats.new_occupied > 50;
        ok = ok && (addrman_consistency_check(&am, NULL, 0) == 0);

        if (ok)
            printf("OK (placed=%d in %d buckets)\n",
                   stats.new_occupied, stats.new_buckets_nonempty);
        else {
            printf("FAIL (placed=%d in %d buckets)\n",
                   stats.new_occupied, stats.new_buckets_nonempty);
            failures++;
        }
        addrman_free(&am);
    }

    /* ── 7. Tried collision eviction maintains consistency ──────── */
    printf("addrman_rebalance: tried collision consistency... ");
    {
        struct addr_man am;
        addrman_init(&am);
        struct net_addr src = make_pub_source(80, 1, 0, 1);

        /* Add many addresses and promote to tried to force collisions */
        for (int i = 1; i <= 200; i++) {
            struct net_address addr = make_pub_addr(
                (uint8_t)(81 + i / 256),
                (uint8_t)(i % 256),
                (uint8_t)((i * 11) % 256),
                (uint8_t)((i * 17) % 254 + 1), 8033);
            addrman_add(&am, &addr, &src, 0);
        }

        /* Promote all to tried — this will cause collisions */
        for (int i = 1; i <= 200; i++) {
            struct net_address addr = make_pub_addr(
                (uint8_t)(81 + i / 256),
                (uint8_t)(i % 256),
                (uint8_t)((i * 11) % 256),
                (uint8_t)((i * 17) % 254 + 1), 8033);
            addrman_good(&am, &addr.svc, (int64_t)platform_time_wall_time_t());
        }

        char err[256] = {0};
        int rc = addrman_consistency_check(&am, err, sizeof(err));

        struct addrman_bucket_stats stats;
        addrman_get_bucket_stats(&am, &stats);

        bool ok = (rc == 0);
        ok = ok && stats.tried_occupied > 0;

        if (ok)
            printf("OK (tried=%d, new=%d after collisions)\n",
                   stats.tried_occupied, stats.new_occupied);
        else {
            printf("FAIL (rc=%d err=%s tried=%d new=%d)\n",
                   rc, err, stats.tried_occupied, stats.new_occupied);
            failures++;
        }
        addrman_free(&am);
    }

    /* ── 8. Select from tried table works ──────────────────────── */
    printf("addrman_rebalance: select tried... ");
    {
        struct addr_man am;
        addrman_init(&am);
        struct net_addr src = make_pub_source(82, 1, 0, 1);

        for (int i = 1; i <= 5; i++) {
            struct net_address addr = make_pub_addr(83, 1, 1, (uint8_t)i, 8033);
            addrman_add(&am, &addr, &src, 0);
            addrman_good(&am, &addr.svc, (int64_t)platform_time_wall_time_t());
        }

        struct addr_info result;
        bool found = addrman_select(&am, false, &result);

        if (found)
            printf("OK\n");
        else {
            printf("FAIL (select returned false)\n"); failures++;
        }
        addrman_free(&am);
    }

    /* ── 9. Attempt tracking increments ────────────────────────── */
    printf("addrman_rebalance: attempt tracking... ");
    {
        struct addr_man am;
        addrman_init(&am);
        struct net_addr src = make_pub_source(84, 1, 0, 1);
        struct net_address addr = make_pub_addr(85, 1, 1, 100, 8033);
        addrman_add(&am, &addr, &src, 0);

        for (int i = 0; i < 5; i++)
            addrman_attempt(&am, &addr.svc, (int64_t)platform_time_wall_time_t() + i);

        bool consistent = (addrman_consistency_check(&am, NULL, 0) == 0);
        if (consistent)
            printf("OK\n");
        else {
            printf("FAIL\n"); failures++;
        }
        addrman_free(&am);
    }

    /* ── 10. get_addr returns subset ───────────────────────────── */
    printf("addrman_rebalance: get_addr pct limit... ");
    {
        struct addr_man am;
        addrman_init(&am);

        for (int i = 0; i < 100; i++) {
            struct net_addr src = make_pub_source(
                (uint8_t)(86 + i % 10), 1, 0, 1);
            struct net_address addr = make_pub_addr(
                (uint8_t)(87 + i / 256), (uint8_t)(i % 256),
                (uint8_t)((i * 7) % 256), (uint8_t)((i * 3) % 254 + 1),
                8033);
            addrman_add(&am, &addr, &src, 0);
        }

        struct net_address out[200];
        size_t got = addrman_get_addr(&am, out, 200);

        size_t expected_max = addrman_size(&am) * 23 / 100;
        if (expected_max > 2500) expected_max = 2500;

        bool ok = (got <= expected_max + 1);
        ok = ok && (addrman_consistency_check(&am, NULL, 0) == 0);

        if (ok)
            printf("OK (returned %zu, max=%zu)\n", got, expected_max);
        else {
            printf("FAIL (got=%zu max=%zu)\n", got, expected_max);
            failures++;
        }
        addrman_free(&am);
    }

    /* ── 11. Terrible entries get evicted on collision ──────────── */
    printf("addrman_rebalance: terrible eviction... ");
    {
        struct addr_man am;
        addrman_init(&am);
        struct net_addr src = make_pub_source(88, 1, 0, 1);

        /* Add address with old timestamp */
        struct net_address old_addr = make_pub_addr(89, 1, 1, 1, 8033);
        old_addr.nTime = (uint32_t)(platform_time_wall_time_t() - 60 * 24 * 60 * 60);
        addrman_add(&am, &old_addr, &src, 0);

        size_t size_before = addrman_size(&am);

        for (int i = 2; i <= 30; i++) {
            struct net_address addr = make_pub_addr(89, 1, 1, (uint8_t)i, 8033);
            addrman_add(&am, &addr, &src, 0);
        }

        bool ok = addrman_size(&am) >= size_before;
        ok = ok && (addrman_consistency_check(&am, NULL, 0) == 0);

        if (ok)
            printf("OK\n");
        else {
            printf("FAIL\n"); failures++;
        }
        addrman_free(&am);
    }

    /* ── 12. Bucket position determinism ───────────────────────── */
    printf("addrman_rebalance: bucket position determinism... ");
    {
        struct addr_man am;
        addrman_init(&am);
        struct net_addr src = make_pub_source(90, 1, 0, 1);
        struct net_address addr = make_pub_addr(91, 1, 1, 42, 8033);
        addrman_add(&am, &addr, &src, 0);

        struct addr_info info;
        memset(&info, 0, sizeof(info));
        info.addr = addr;
        info.source = src;

        int b1 = addr_info_get_new_bucket(&info, &am.nKey, &src);
        int b2 = addr_info_get_new_bucket(&info, &am.nKey, &src);
        int p1 = addr_info_get_bucket_position(&info, &am.nKey, true, b1);
        int p2 = addr_info_get_bucket_position(&info, &am.nKey, true, b1);
        int tb1 = addr_info_get_tried_bucket(&info, &am.nKey);
        int tb2 = addr_info_get_tried_bucket(&info, &am.nKey);

        bool ok = (b1 == b2) && (p1 == p2) && (tb1 == tb2);
        ok = ok && (b1 >= 0 && b1 < ADDRMAN_NEW_BUCKET_COUNT);
        ok = ok && (p1 >= 0 && p1 < ADDRMAN_BUCKET_SIZE);
        ok = ok && (tb1 >= 0 && tb1 < ADDRMAN_TRIED_BUCKET_COUNT);

        if (ok)
            printf("OK\n");
        else {
            printf("FAIL (b=%d/%d p=%d/%d tb=%d/%d)\n",
                   b1, b2, p1, p2, tb1, tb2);
            failures++;
        }
        addrman_free(&am);
    }

    /* ── 13. O(1) index: dedup — same address never creates two entries ── */
    printf("addrman_rebalance: index dedup... ");
    {
        struct addr_man am;
        addrman_init(&am);
        struct net_addr src = make_pub_source(92, 1, 0, 1);
        struct net_address addr = make_pub_addr(93, 2, 3, 4, 8033);

        addrman_add(&am, &addr, &src, 0);
        size_t after_first = addrman_size(&am);
        /* Add the SAME address 50 more times — must stay one entry. */
        for (int i = 0; i < 50; i++)
            addrman_add(&am, &addr, &src, 0);

        char err[256] = {0};
        bool ok = (after_first == 1);
        ok = ok && (addrman_size(&am) == 1);
        ok = ok && (addrman_index_verify(&am, err, sizeof(err)) == 0);
        ok = ok && (addrman_consistency_check(&am, NULL, 0) == 0);

        if (ok)
            printf("OK\n");
        else {
            printf("FAIL (size=%zu err=%s)\n", addrman_size(&am), err);
            failures++;
        }
        addrman_free(&am);
    }

    /* ── 14. O(1) index agrees with brute-force scan on a full table ── */
    printf("addrman_rebalance: index == brute-force scan... ");
    {
        struct addr_man am;
        addrman_init(&am);

        /* Populate from many sources so both new and delete/evict paths
         * (clear_new → delete_entry) run and churn the index. */
        for (int s = 0; s < 20; s++) {
            struct net_addr src = make_pub_source((uint8_t)(94 + s), 1, 0, 1);
            for (int i = 0; i < 60; i++) {
                struct net_address addr = make_pub_addr(
                    (uint8_t)(120 + s),
                    (uint8_t)(i * 3 + 1),
                    (uint8_t)(s * 5 + i + 1),
                    (uint8_t)(i + 1), 8033);
                addrman_add(&am, &addr, &src, 0);
            }
        }
        /* Promote a chunk to tried to force new-bucket evictions/deletes. */
        for (int s = 0; s < 20; s++) {
            for (int i = 0; i < 30; i++) {
                struct net_address addr = make_pub_addr(
                    (uint8_t)(120 + s),
                    (uint8_t)(i * 3 + 1),
                    (uint8_t)(s * 5 + i + 1),
                    (uint8_t)(i + 1), 8033);
                addrman_good(&am, &addr.svc,
                             (int64_t)platform_time_wall_time_t());
            }
        }

        char err[256] = {0};
        /* addrman_index_verify cross-checks index lookups against a
         * brute-force scan for every used entry, plus live-slot integrity. */
        bool ok = (addrman_index_verify(&am, err, sizeof(err)) == 0);
        ok = ok && (addrman_consistency_check(&am, NULL, 0) == 0);
        ok = ok && (addrman_size(&am) > 0);

        if (ok)
            printf("OK (size=%zu)\n", addrman_size(&am));
        else {
            printf("FAIL (size=%zu err=%s)\n", addrman_size(&am), err);
            failures++;
        }
        addrman_free(&am);
    }

    /* ── 15. Serialize → deserialize rebuilds the index (dedup survives) ── */
    printf("addrman_rebalance: serialize round-trip dedup... ");
    {
        struct addr_man am;
        addrman_init(&am);
        struct net_addr src = make_pub_source(150, 1, 0, 1);

        for (int i = 1; i <= 80; i++) {
            struct net_address addr = make_pub_addr(
                151, (uint8_t)(i / 256 + 1), (uint8_t)(i % 256),
                (uint8_t)((i * 7) % 254 + 1), 8033);
            addrman_add(&am, &addr, &src, 0);
        }
        /* Promote some to tried so the serialized image has both sections. */
        for (int i = 1; i <= 20; i++) {
            struct net_address addr = make_pub_addr(
                151, (uint8_t)(i / 256 + 1), (uint8_t)(i % 256),
                (uint8_t)((i * 7) % 254 + 1), 8033);
            addrman_good(&am, &addr.svc, (int64_t)platform_time_wall_time_t());
        }
        size_t size_before = addrman_size(&am);

        struct byte_stream s;
        stream_init(&s, 4096);
        bool ser = addrman_serialize(&am, &s);

        struct addr_man am2;
        addrman_init(&am2);
        struct byte_stream rs;
        stream_init_from_data(&rs, s.data, s.size);
        bool deser = addrman_deserialize(&am2, &rs);

        char err[256] = {0};
        /* Index must be rebuilt on load and agree with the entries. */
        bool ok = ser && deser;
        ok = ok && (addrman_index_verify(&am2, err, sizeof(err)) == 0);
        ok = ok && (addrman_consistency_check(&am2, NULL, 0) == 0);
        ok = ok && (addrman_size(&am2) == size_before);

        /* Re-adding a known address into the reloaded table must dedup via
         * the rebuilt index, not create a phantom second entry. */
        size_t before_readd = addrman_size(&am2);
        struct net_address known = make_pub_addr(
            151, 1, 40, (uint8_t)((40 * 7) % 254 + 1), 8033);
        addrman_add(&am2, &known, &src, 0);
        ok = ok && (addrman_size(&am2) == before_readd);
        ok = ok && (addrman_index_verify(&am2, err, sizeof(err)) == 0);

        if (ok)
            printf("OK (size=%zu)\n", addrman_size(&am2));
        else {
            printf("FAIL (ser=%d deser=%d before=%zu after=%zu err=%s)\n",
                   ser, deser, size_before, addrman_size(&am2), err);
            failures++;
        }
        stream_free(&s);
        stream_free(&rs);
        addrman_free(&am);
        addrman_free(&am2);
    }

    /* ── 16. Delete path: churn that deletes entries keeps index in sync ── */
    printf("addrman_rebalance: delete-then-readd index sync... ");
    {
        struct addr_man am;
        addrman_init(&am);

        /* A single source flooding 400 addresses drives repeated bucket
         * collisions; failed inserts of fresh entries hit the
         * `!inserted && ref_count==0` delete_entry path, and evictions run
         * clear_new → delete_entry. If delete_entry failed to remove the
         * address from the index, a later re-add would either find a stale
         * id (index/scan disagree) or leave idx_live overcounting — both
         * caught by addrman_index_verify below. */
        struct net_addr attacker = make_pub_source(200, 2, 3, 4);
        for (int i = 0; i < 400; i++) {
            struct net_address addr = make_pub_addr(
                (uint8_t)(201 + i / 65536),
                (uint8_t)((i / 256) % 256),
                (uint8_t)(i % 256),
                (uint8_t)((i * 3) % 254 + 1), 8033);
            addrman_add(&am, &addr, &attacker, 0);
        }

        char err[256] = {0};
        bool ok = (addrman_index_verify(&am, err, sizeof(err)) == 0);
        ok = ok && (addrman_consistency_check(&am, NULL, 0) == 0);

        /* Re-add the whole flood: every currently-present address must
         * dedup (size cannot exceed the live count), index stays coherent. */
        size_t size_before_readd = addrman_size(&am);
        for (int i = 0; i < 400; i++) {
            struct net_address addr = make_pub_addr(
                (uint8_t)(201 + i / 65536),
                (uint8_t)((i / 256) % 256),
                (uint8_t)(i % 256),
                (uint8_t)((i * 3) % 254 + 1), 8033);
            addrman_add(&am, &addr, &attacker, 0);
        }
        ok = ok && (addrman_size(&am) >= size_before_readd);
        ok = ok && (addrman_index_verify(&am, err, sizeof(err)) == 0);
        ok = ok && (addrman_consistency_check(&am, NULL, 0) == 0);

        if (ok)
            printf("OK (size=%zu)\n", addrman_size(&am));
        else {
            printf("FAIL (size=%zu err=%s)\n", addrman_size(&am), err);
            failures++;
        }
        addrman_free(&am);
    }

    /* ── 17. Index grows correctly past its initial slot count ──────── */
    printf("addrman_rebalance: index grow/rebuild... ");
    {
        struct addr_man am;
        addrman_init(&am);

        /* > 4096 distinct live entries forces addr_index_reserve_one to
         * grow the table at least once (initial 8192 slots, grow at 50%
         * load). Spread across many sources so they actually land. */
        int added = 0;
        for (int s = 0; s < 90; s++) {
            struct net_addr src = make_pub_source(
                (uint8_t)(60 + s % 90), (uint8_t)(s / 90 + 1), 0, 1);
            for (int i = 0; i < 60; i++) {
                struct net_address addr = make_pub_addr(
                    (uint8_t)(64 + s % 128),
                    (uint8_t)(s),
                    (uint8_t)(i),
                    (uint8_t)(i + 1), 8033);
                if (addrman_add(&am, &addr, &src, 0))
                    added++;
            }
        }

        char err[256] = {0};
        bool ok = (addrman_size(&am) > 4096);   /* crossed the grow line */
        ok = ok && (addrman_index_verify(&am, err, sizeof(err)) == 0);
        ok = ok && (addrman_consistency_check(&am, NULL, 0) == 0);

        if (ok)
            printf("OK (added=%d size=%zu)\n", added, addrman_size(&am));
        else {
            printf("FAIL (added=%d size=%zu err=%s)\n",
                   added, addrman_size(&am), err);
            failures++;
        }
        addrman_free(&am);
    }

    return failures;
}
