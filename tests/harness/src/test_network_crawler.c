/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_network_crawler — the whole-network OBSERVATORY.
 *
 *   1. the PURE census fold (network_census_compute) over synthetic probe
 *      results: version histogram + top-N ordering, onion/clearnet split,
 *      height distribution (modal/max/min/spread), and the whole-network
 *      eclipse signal (fires when our modal is a network minority, stays quiet
 *      when we agree with the network or the sample is too small),
 *   2. the census table's bounds through the injectable probe_fn seam: addr
 *      dedup, per-round cap, and prune-when-full (never exceeds the cap),
 *   3. the network_census dumper surfaces the eclipse signal + evidence,
 *   4. THE ONION HALF: address rendering (a real v3 hostname, not the
 *      "[torv3]" placeholder that would collapse every onion into one row),
 *      the separately-bounded onion dial phase (per-round cap + wall-clock
 *      budget, clearnet never starved), and the NOT-PROBED discipline —
 *      unprobed is its own bucket, never counted as unreachable, never
 *      overwriting a real measurement, never emitted as a failed dial.
 *
 * NO real sockets and NO real circuits: the dialer is replaced by a synthetic
 * probe_fn that encodes each node's measured properties in its address octets.
 */

#include "test/test_core.h"

#include "services/network_crawler.h"
#include "conditions/net_eclipse_suspected.h"
#include "json/json.h"
#include "net/netaddr.h"
#include "net/onion_peer_merge.h"
#include "platform/time_compat.h"
#include "storage/peers_projection.h"
#include "util/blocker.h"

#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NC_CHECK(cond) do { \
    if (cond) { /* pass */ } \
    else { printf("  FAIL: %s (line %d)\n", #cond, __LINE__); failures++; } \
} while (0)

/* ── synthetic address + probe (properties encoded in IPv4 octets) ────── */

static struct net_address mk_addr(uint8_t hc, bool reachable, bool onion,
                                  uint8_t seq, uint16_t port)
{
    struct net_address na;
    net_address_init(&na);
    unsigned char flags = (uint8_t)((reachable ? 0x01 : 0) | (onion ? 0x02 : 0));
    unsigned char ip4[4] = { 10, hc, flags, seq };
    net_addr_set_ipv4(&na.svc.addr, ip4);
    na.svc.port = port;
    return na;
}

/* Decode the octets a mk_addr() encoded: height=3000000+hc, reachable/onion
 * from the flags octet. subver alternates by height parity. */
static bool synth_probe(const struct net_address *addr, int ct, int ht,
                        struct ncrawl_probe_result *out)
{
    (void)ct;
    (void)ht;
    if (!addr || !out)
        return false;
    memset(out, 0, sizeof(*out));
    net_service_to_string(&addr->svc, out->addr, sizeof(out->addr));
    if (!out->addr[0])
        return false;
    unsigned char hc = addr->svc.addr.ip[13];
    unsigned char fl = addr->svc.addr.ip[14];
    out->is_onion = (fl & 0x02) != 0;
    out->reachable = (fl & 0x01) != 0;
    out->version = 170011;
    out->services = 1;
    out->best_height = out->reachable ? (int64_t)(3000000 + hc) : -1;
    snprintf(out->subver, sizeof(out->subver), "%s",
             (hc & 1) ? "/zclassic23:1/" : "/MagicBean:2.1.2/");
    out->latency_us = 1234;
    out->last_probe_us = 1000 + (int64_t)addr->svc.addr.ip[15];
    return true;
}

/* A Tor v3 address whose 32-byte key is seeded from `seed`. */
static struct net_address mk_onion(uint8_t seed, uint16_t port)
{
    struct net_address na;
    net_address_init(&na);
    na.svc.addr.has_torv3 = true;
    for (int i = 0; i < TORV3_ADDR_SIZE; i++)
        na.svc.addr.torv3[i] = (unsigned char)(seed + i);
    /* Onions still carry a 16-byte ip[] key; make it unique per seed so the
     * durable-census key does not collide either. */
    memcpy(na.svc.addr.ip, na.svc.addr.torv3, 16);
    na.svc.port = port;
    return na;
}

/* Onion-aware synthetic probe: counts what it was asked to dial, with which
 * timeouts, and can be told to sleep on the onion branch so the wall-clock
 * budget is provable without a real circuit. */
static _Atomic int g_clear_dials;
static _Atomic int g_onion_dials;
static _Atomic int g_onion_timeout_seen;
static _Atomic int g_onion_sleep_ms;
static _Atomic int g_onion_not_probed;   /* 1 => report NOT_PROBED */

static void onion_probe_counters_reset(void)
{
    atomic_store(&g_clear_dials, 0);
    atomic_store(&g_onion_dials, 0);
    atomic_store(&g_onion_timeout_seen, 0);
    atomic_store(&g_onion_sleep_ms, 0);
    atomic_store(&g_onion_not_probed, 0);
}

static bool onion_aware_probe(const struct net_address *addr, int ct, int ht,
                              struct ncrawl_probe_result *out)
{
    if (!addr || !out)
        return false;
    memset(out, 0, sizeof(*out));
    out->is_onion = net_addr_is_tor(&addr->svc.addr);
    out->best_height = -1;
    out->last_probe_us = 4242;
    if (!network_crawler_render_addr(addr, out->addr, sizeof(out->addr)))
        return false;

    if (!out->is_onion) {
        atomic_fetch_add(&g_clear_dials, 1);
        out->reachable = true;
        out->best_height = 3000000;
        snprintf(out->subver, sizeof(out->subver), "/clear/");
        return true;
    }

    atomic_fetch_add(&g_onion_dials, 1);
    atomic_store(&g_onion_timeout_seen, ct > ht ? ct : ht);
    int nap = atomic_load(&g_onion_sleep_ms);
    if (nap > 0)
        platform_sleep_ms(nap);
    if (atomic_load(&g_onion_not_probed)) {
        out->outcome = (uint8_t)NCRAWL_OUTCOME_NOT_PROBED;
        snprintf(out->reason, sizeof(out->reason), "tor unavailable (fake)");
        return true;
    }
    out->reachable = true;
    out->best_height = 3000000;
    snprintf(out->subver, sizeof(out->subver), "/onion/");
    return true;
}

/* Build a probe result directly (for the pure-fold tests). */
static struct ncrawl_probe_result mk_res(const char *addr, bool reachable,
                                         bool onion, int64_t height,
                                         const char *subver)
{
    struct ncrawl_probe_result r;
    memset(&r, 0, sizeof(r));
    snprintf(r.addr, sizeof(r.addr), "%s", addr);
    r.reachable = reachable;
    r.is_onion = onion;
    r.version = 170011;
    r.best_height = reachable ? height : -1;
    if (subver)
        snprintf(r.subver, sizeof(r.subver), "%s", subver);
    r.latency_us = 100;
    r.last_probe_us = 42;
    return r;
}

int test_network_crawler(void)
{
    int failures = 0;
    printf("network_crawler...\n");

    /* ── 1. pure fold: histograms, splits, height distribution ─────────── */
    printf("  census fold: histogram + split + height distribution... ");
    {
        struct ncrawl_probe_result r[6] = {
            mk_res("1.0.0.1:8033", true,  false, 100, "/A/"),
            mk_res("1.0.0.2:8033", true,  false, 100, "/A/"),
            mk_res("1.0.0.3:8033", true,  false, 100, "/B/"),
            mk_res("1.0.0.4:8033", true,  false, 200, "/A/"),
            mk_res("1.0.0.5:8033", true,  true,  200, "/A/"),
            mk_res("1.0.0.6:8033", false, false, 0,   "/A/"),
        };
        struct network_census_view v;
        network_census_compute(r, 6, /*own_modal*/ 100, /*now*/ 555, &v);
        NC_CHECK(v.ready);
        NC_CHECK(v.computed_at == 555);
        NC_CHECK(v.probed == 6);
        NC_CHECK(v.reachable_count == 5);
        NC_CHECK(v.onion_count == 1);
        NC_CHECK(v.clearnet_count == 4);
        NC_CHECK(v.heights_known == 5);
        NC_CHECK(v.max_height == 200);
        NC_CHECK(v.min_height == 100);
        NC_CHECK(v.height_spread == 100);
        NC_CHECK(v.modal_height == 100);
        NC_CHECK(v.modal_height_count == 3);
        NC_CHECK(v.num_versions == 2);
        /* histogram sorted descending: /A/ (4) before /B/ (1) */
        NC_CHECK(strcmp(v.versions[0].subver, "/A/") == 0);
        NC_CHECK(v.versions[0].count == 4);
        NC_CHECK(strcmp(v.versions[1].subver, "/B/") == 0);
        NC_CHECK(v.versions[1].count == 1);
        /* we agree with the network modal → no eclipse */
        NC_CHECK(v.eclipse_suspected == false);
        printf("done\n");
    }

    /* ── 2. eclipse FIRES: our modal is a network minority ─────────────── */
    printf("  eclipse fires when our modal is a network minority... ");
    {
        struct ncrawl_probe_result r[8];
        for (int i = 0; i < 6; i++)
            r[i] = mk_res("a", true, false, 200, "/A/"); /* addr unused by fold */
        for (int i = 6; i < 8; i++)
            r[i] = mk_res("b", true, false, 100, "/A/");
        struct network_census_view v;
        network_census_compute(r, 8, /*own_modal*/ 100, 1, &v);
        NC_CHECK(v.reachable_count == 8);
        NC_CHECK(v.network_modal_height == 200);
        NC_CHECK(v.modal_height_count == 6);
        NC_CHECK(v.own_modal_height == 100);
        NC_CHECK(v.network_count_at_own_modal == 2);
        NC_CHECK(v.eclipse_suspected == true);
        printf("done\n");
    }

    /* ── 3. eclipse QUIET: sample too small + agreement + boundary ─────── */
    printf("  eclipse quiet on small sample / agreement / 1/3 boundary... ");
    {
        /* too small: 3 reachable < NCRAWL_ECLIPSE_MIN even though minority */
        struct ncrawl_probe_result small[3];
        for (int i = 0; i < 3; i++)
            small[i] = mk_res("x", true, false, 200, "/A/");
        struct network_census_view v;
        network_census_compute(small, 3, 100, 1, &v);
        NC_CHECK(v.reachable_count == 3);
        NC_CHECK(v.eclipse_suspected == false);

        /* agreement: own_modal == network modal */
        struct ncrawl_probe_result agree[6];
        for (int i = 0; i < 6; i++)
            agree[i] = mk_res("y", true, false, 200, "/A/");
        network_census_compute(agree, 6, 200, 1, &v);
        NC_CHECK(v.eclipse_suspected == false);

        /* boundary: our height is exactly 1/3 (2 of 6) → not a minority */
        struct ncrawl_probe_result edge[6];
        for (int i = 0; i < 4; i++)
            edge[i] = mk_res("z", true, false, 200, "/A/");
        for (int i = 4; i < 6; i++)
            edge[i] = mk_res("w", true, false, 100, "/A/");
        network_census_compute(edge, 6, 100, 1, &v);
        NC_CHECK(v.network_count_at_own_modal == 2);
        NC_CHECK(v.eclipse_suspected == false);
        printf("done\n");
    }

    /* ── 4. fold bounds: oversized sample clamps to the cap ────────────── */
    printf("  census fold clamps oversized sample to NCRAWL_MAX_CENSUS... ");
    {
        int big = NCRAWL_MAX_CENSUS + 10;
        struct ncrawl_probe_result *r =
            calloc((size_t)big, sizeof(*r));
        NC_CHECK(r != NULL);
        if (r) {
            for (int i = 0; i < big; i++)
                r[i] = mk_res("c", true, false, 500, "/A/");
            struct network_census_view v;
            network_census_compute(r, big, -1, 1, &v);
            NC_CHECK(v.probed == NCRAWL_MAX_CENSUS);
            NC_CHECK(v.reachable_count == NCRAWL_MAX_CENSUS);
            free(r);
        }
        printf("done\n");
    }

    /* ── 5. census ingest via probe seam: dedup + per-round cap ────────── */
    printf("  census ingest: addr dedup + per-round cap (probe seam)... ");
    {
        network_crawler_test_reset();
        network_crawler_test_set_probe_fn(synth_probe);

        /* dedup: the same address twice in one round → one census row. */
        struct net_address dup[2] = {
            mk_addr(50, true, false, 7, 8033),
            mk_addr(50, true, false, 7, 8033),
        };
        int probed = network_crawler_test_probe_round(dup, 2);
        NC_CHECK(probed == 2);
        NC_CHECK(network_crawler_test_census_count() == 1);

        /* per-round cap: feed MORE than NCRAWL_MAX_PER_ROUND distinct addrs. */
        network_crawler_test_reset();
        network_crawler_test_set_probe_fn(synth_probe);
        int over = NCRAWL_MAX_PER_ROUND + 20;
        struct net_address *addrs = calloc((size_t)over, sizeof(*addrs));
        NC_CHECK(addrs != NULL);
        if (addrs) {
            for (int i = 0; i < over; i++)
                addrs[i] = mk_addr(60, true, false, (uint8_t)i,
                                   (uint16_t)(9000 + i));
            probed = network_crawler_test_probe_round(addrs, over);
            NC_CHECK(probed == NCRAWL_MAX_PER_ROUND);
            NC_CHECK(network_crawler_test_census_count() == NCRAWL_MAX_PER_ROUND);
            free(addrs);
        }
        printf("done\n");
    }

    /* ── 6. census prune: never exceeds NCRAWL_MAX_CENSUS ──────────────── */
    printf("  census prune: bounded at NCRAWL_MAX_CENSUS under overflow... ");
    {
        network_crawler_test_reset();
        network_crawler_test_set_probe_fn(synth_probe);
        int total = NCRAWL_MAX_CENSUS + 128;   /* overflow the table */
        int counter = 0;
        bool ever_exceeded = false;
        while (counter < total) {
            struct net_address round[NCRAWL_MAX_PER_ROUND];
            int n = 0;
            for (; n < NCRAWL_MAX_PER_ROUND && counter < total; n++, counter++) {
                round[n] = mk_addr(70, true, false,
                                   (uint8_t)(counter & 0xff),
                                   (uint16_t)(10000 + counter));
            }
            network_crawler_test_probe_round(round, n);
            if (network_crawler_test_census_count() > NCRAWL_MAX_CENSUS)
                ever_exceeded = true;
        }
        NC_CHECK(!ever_exceeded);
        NC_CHECK(network_crawler_test_census_count() == NCRAWL_MAX_CENSUS);
        printf("done\n");
    }

    /* ── 7. dumper surfaces the eclipse signal + evidence ──────────────── */
    printf("  network_census dumper surfaces eclipse + evidence... ");
    {
        network_crawler_test_reset();
        network_crawler_test_set_probe_fn(synth_probe);
        network_crawler_test_set_own_modal(3000100); /* our peers on hc=100 */

        struct net_address net[8];
        for (int i = 0; i < 6; i++)   /* network majority on hc=200 */
            net[i] = mk_addr(200, true, false, (uint8_t)i, (uint16_t)(11000 + i));
        for (int i = 6; i < 8; i++)   /* our minority height hc=100 */
            net[i] = mk_addr(100, true, false, (uint8_t)i, (uint16_t)(11000 + i));
        int probed = network_crawler_test_probe_round(net, 8);
        NC_CHECK(probed == 8);

        struct json_value out;
        json_init(&out);
        bool ok = network_crawler_dump_state_json(&out, NULL);
        NC_CHECK(ok);
        const struct json_value *ecl = json_get(&out, "eclipse_suspected");
        NC_CHECK(ecl != NULL && json_get_bool(ecl) == true);
        const struct json_value *reach = json_get(&out, "reachable_count");
        NC_CHECK(reach != NULL && json_get_int(reach) == 8);
        const struct json_value *hist = json_get(&out, "version_histogram");
        NC_CHECK(hist != NULL && hist->type == JSON_ARR);
        const struct json_value *evid = json_get(&out, "eclipse_evidence");
        NC_CHECK(evid != NULL && evid->type == JSON_OBJ);
        if (evid) {
            const struct json_value *own = json_get(evid, "own_modal_height");
            const struct json_value *nm = json_get(evid, "network_modal_height");
            const struct json_value *at = json_get(evid,
                                                   "network_count_at_own_modal");
            NC_CHECK(own != NULL && json_get_int(own) == 3000100);
            NC_CHECK(nm != NULL && json_get_int(nm) == 3000200);
            NC_CHECK(at != NULL && json_get_int(at) == 2);
        }
        json_free(&out);
        network_crawler_test_reset();
        printf("done\n");
    }

    /* ── 8. eclipse CONDITION: 2-round trip + remedy names the blocker ───── */
    printf("  eclipse condition: 2 consecutive census rounds trip + remedy... ");
    {
        (void)blocker_module_init();
        net_eclipse_suspected_test_reset();

        struct network_census_view v;
        memset(&v, 0, sizeof(v));
        v.ready = true;
        v.eclipse_suspected = true;
        v.reachable_count = 9;
        v.own_modal_height = 100;
        v.network_modal_height = 200;
        v.network_count_at_own_modal = 2;

        /* Round 1: a single eclipse census must NOT fire (one noisy sample). */
        v.computed_at = 1000;
        network_crawler_test_set_view(&v);
        NC_CHECK(!net_eclipse_suspected_test_detect());

        /* Round 2 (new census fold): 2 consecutive rounds → fire. */
        v.computed_at = 1060;
        network_crawler_test_set_view(&v);
        NC_CHECK(net_eclipse_suspected_test_detect());

        /* Remedy is invoked → it names the typed blocker (cm is NULL in the
         * test harness, so the discovery kick is skipped and it returns
         * FAILED, but the blocker MUST be set first). */
        (void)net_eclipse_suspected_test_remedy();
        NC_CHECK(blocker_exists("net_eclipse_suspected"));

        /* A census that no longer suspects eclipse stops the detector. */
        v.computed_at = 1120;
        v.eclipse_suspected = false;
        network_crawler_test_set_view(&v);
        NC_CHECK(!net_eclipse_suspected_test_detect());

        net_eclipse_suspected_test_reset();
        network_crawler_test_reset();
        printf("done\n");
    }

    /* ── 9. onion address rendering: a REAL v3 hostname, never "[torv3]" ── */
    printf("  onion addresses render to distinct real v3 hostnames... ");
    {
        struct net_address clear = mk_addr(1, true, false, 9, 8033);
        char buf[NCRAWL_ADDR_MAX];
        NC_CHECK(network_crawler_render_addr(&clear, buf, sizeof(buf)));
        NC_CHECK(strcmp(buf, "10.1.1.9:8033") == 0);

        struct net_address o1 = mk_onion(0x11, 8033);
        struct net_address o2 = mk_onion(0x22, 8033);
        char h1[NCRAWL_ADDR_MAX], h2[NCRAWL_ADDR_MAX];
        NC_CHECK(network_crawler_render_addr(&o1, h1, sizeof(h1)));
        NC_CHECK(network_crawler_render_addr(&o2, h2, sizeof(h2)));
        /* "<56 base32>.onion:<port>" — 62 host chars, then ":8033". */
        NC_CHECK(strlen(h1) == 62 + 5);
        NC_CHECK(strstr(h1, ".onion:8033") != NULL);
        NC_CHECK(strstr(h1, "[torv3]") == NULL);
        /* Two different keys must NOT collapse to one census row. */
        NC_CHECK(strcmp(h1, h2) != 0);
        /* The rendered host passes core/modules/net's ONE hostname rule. */
        char host[80];
        snprintf(host, sizeof(host), "%.62s", h1);
        NC_CHECK(onion_hostname_valid(host));
        printf("done\n");
    }

    /* ── 10. NOT PROBED is its own bucket, not an unreachable ──────────── */
    printf("  fold: not-probed rows counted apart from unreachable... ");
    {
        struct ncrawl_probe_result r[5];
        r[0] = mk_res("a:8033", true,  false, 100, "/A/");
        r[1] = mk_res("b:8033", true,  false, 100, "/A/");
        r[2] = mk_res("c:8033", false, false, 0,   "/A/");   /* MEASURED down */
        r[3] = mk_res("d.onion:8033", false, true, 0, "");   /* NOT PROBED */
        r[4] = mk_res("e.onion:8033", false, true, 0, "");   /* NOT PROBED */
        for (int i = 3; i < 5; i++) {
            r[i].outcome = (uint8_t)NCRAWL_OUTCOME_NOT_PROBED;
            snprintf(r[i].reason, sizeof(r[i].reason), "tor unavailable");
        }
        struct network_census_view v;
        network_census_compute(r, 5, -1, 7, &v);
        NC_CHECK(v.probed == 5);
        NC_CHECK(v.measured_count == 3);
        NC_CHECK(v.not_probed_count == 2);
        NC_CHECK(v.onion_not_probed_count == 2);
        NC_CHECK(v.onion_measured_count == 0);
        /* The unprobed onions inflate NEITHER side of the reachability call. */
        NC_CHECK(v.reachable_count == 2);
        NC_CHECK(v.onion_count == 0);
        NC_CHECK(v.clearnet_count == 2);
        NC_CHECK(strcmp(v.not_probed_reason, "tor unavailable") == 0);
        printf("done\n");
    }

    /* ── 11. onion phase is bounded SEPARATELY; clearnet is never starved ── */
    printf("  onion phase: per-round cap + budget, clearnet runs first... ");
    {
        network_crawler_test_reset();
        network_crawler_test_set_probe_fn(onion_aware_probe);
        onion_probe_counters_reset();
        /* cap 3 onions/round, 1 in flight, 5s per dial, no wall-clock budget */
        network_crawler_test_set_onion_limits(3, 1, 5000, 0);

        struct net_address mixed[10];
        for (int i = 0; i < 4; i++)
            mixed[i] = mk_addr(40, true, false, (uint8_t)i, (uint16_t)(12000 + i));
        for (int i = 4; i < 10; i++)
            mixed[i] = mk_onion((uint8_t)(0x40 + i), (uint16_t)(12000 + i));

        int recorded = network_crawler_test_probe_round(mixed, 10);
        /* every address is RECORDED (measured or not-probed) ... */
        NC_CHECK(recorded == 10);
        /* ... but only 4 clearnet + 3 onion were actually dialed. */
        NC_CHECK(atomic_load(&g_clear_dials) == 4);
        NC_CHECK(atomic_load(&g_onion_dials) == 3);
        /* the onion branch got the ONION timeout, not the clearnet one */
        NC_CHECK(atomic_load(&g_onion_timeout_seen) == 5000);

        struct network_census_view v;
        NC_CHECK(network_crawler_get_view(&v));
        NC_CHECK(v.measured_count == 7);
        NC_CHECK(v.not_probed_count == 3);      /* the 3 over the onion cap */
        NC_CHECK(v.onion_not_probed_count == 3);
        NC_CHECK(v.clearnet_count == 4);        /* clearnet fully measured */
        NC_CHECK(v.onion_count == 3);

        /* the census row for a capped-out onion says NOT PROBED with a why */
        char capped[NCRAWL_ADDR_MAX];
        NC_CHECK(network_crawler_render_addr(&mixed[9], capped, sizeof(capped)));
        struct ncrawl_probe_result row;
        NC_CHECK(network_crawler_test_census_row(capped, &row));
        NC_CHECK(row.outcome == (uint8_t)NCRAWL_OUTCOME_NOT_PROBED);
        NC_CHECK(row.reachable == false);
        NC_CHECK(row.reason[0] != '\0');
        printf("done\n");
    }

    /* ── 12. a slow onion costs a BOUNDED amount of time, never the round ── */
    printf("  onion wall-clock budget cuts the phase off, bounded... ");
    {
        network_crawler_test_reset();
        network_crawler_test_set_probe_fn(onion_aware_probe);
        onion_probe_counters_reset();
        atomic_store(&g_onion_sleep_ms, 120);   /* each onion dial is slow */
        /* 6 onions allowed, 1 in flight, 100ms budget for the whole phase */
        network_crawler_test_set_onion_limits(6, 1, 1000, 100);

        struct net_address onions[6];
        for (int i = 0; i < 6; i++)
            onions[i] = mk_onion((uint8_t)(0x90 + i), (uint16_t)(13000 + i));

        int64_t t0 = platform_time_monotonic_us();
        int recorded = network_crawler_test_probe_round(onions, 6);
        int64_t took_ms = (platform_time_monotonic_us() - t0) / 1000;

        NC_CHECK(recorded == 6);
        /* the budget stopped the phase well short of all six dials */
        NC_CHECK(atomic_load(&g_onion_dials) < 6);
        NC_CHECK(atomic_load(&g_onion_dials) >= 1);
        /* bounded by budget + ONE in-flight dial, not 6 * 120ms */
        NC_CHECK(took_ms < 600);

        struct network_census_view v;
        NC_CHECK(network_crawler_get_view(&v));
        NC_CHECK(v.not_probed_count + v.measured_count == 6);
        NC_CHECK(v.not_probed_count >= 1);
        atomic_store(&g_onion_sleep_ms, 0);
        printf("done\n");
    }

    /* ── 13. NOT PROBED never erases a real measurement ────────────────── */
    printf("  not-probed never overwrites a measured census row... ");
    {
        network_crawler_test_reset();
        network_crawler_test_set_probe_fn(onion_aware_probe);
        onion_probe_counters_reset();
        network_crawler_test_set_onion_limits(4, 1, 1000, 0);

        struct net_address one[1] = { mk_onion(0x77, 14000) };
        char key[NCRAWL_ADDR_MAX];
        NC_CHECK(network_crawler_render_addr(&one[0], key, sizeof(key)));

        /* round 1: a real measurement */
        NC_CHECK(network_crawler_test_probe_round(one, 1) == 1);
        struct ncrawl_probe_result row;
        NC_CHECK(network_crawler_test_census_row(key, &row));
        NC_CHECK(row.outcome == (uint8_t)NCRAWL_OUTCOME_MEASURED);
        NC_CHECK(row.reachable == true);

        /* round 2: Tor goes away — the row must KEEP its measurement */
        atomic_store(&g_onion_not_probed, 1);
        NC_CHECK(network_crawler_test_probe_round(one, 1) == 1);
        NC_CHECK(network_crawler_test_census_row(key, &row));
        NC_CHECK(row.outcome == (uint8_t)NCRAWL_OUTCOME_MEASURED);
        NC_CHECK(row.reachable == true);
        NC_CHECK(network_crawler_test_census_count() == 1);
        atomic_store(&g_onion_not_probed, 0);
        printf("done\n");
    }

    /* ── 14. the dumper reports the unmeasured half honestly ───────────── */
    printf("  dumper reports not_probed + onion budget + availability... ");
    {
        network_crawler_test_reset();
        network_crawler_test_set_probe_fn(onion_aware_probe);
        onion_probe_counters_reset();
        atomic_store(&g_onion_not_probed, 1);
        network_crawler_test_set_onion_limits(2, 1, 7000, 0);

        struct net_address mix[4];
        mix[0] = mk_addr(80, true, false, 1, 15000);
        for (int i = 1; i < 4; i++)
            mix[i] = mk_onion((uint8_t)(0xB0 + i), (uint16_t)(15000 + i));
        NC_CHECK(network_crawler_test_probe_round(mix, 4) == 4);

        struct json_value out;
        json_init(&out);
        NC_CHECK(network_crawler_dump_state_json(&out, NULL));
        const struct json_value *np = json_get(&out, "not_probed_count");
        NC_CHECK(np != NULL && json_get_int(np) == 3);   /* 2 dialed + 1 capped */
        const struct json_value *onp = json_get(&out, "onion_not_probed_count");
        NC_CHECK(onp != NULL && json_get_int(onp) == 3);
        const struct json_value *mc = json_get(&out, "measured_count");
        NC_CHECK(mc != NULL && json_get_int(mc) == 1);
        const struct json_value *why = json_get(&out, "not_probed_reason");
        NC_CHECK(why != NULL && json_get_str(why) != NULL &&
                 json_get_str(why)[0] != '\0');
        const struct json_value *ot = json_get(&out, "onion_timeout_ms");
        NC_CHECK(ot != NULL && json_get_int(ot) == 7000);
        const struct json_value *avail = json_get(&out, "onion_probe_available");
        NC_CHECK(avail != NULL && avail->type == JSON_BOOL);
        const struct json_value *npl = json_get(&out, "not_probed_last_round");
        NC_CHECK(npl != NULL && json_get_int(npl) == 3);
        json_free(&out);
        atomic_store(&g_onion_not_probed, 0);
        network_crawler_test_reset();
        printf("done\n");
    }

    /* ── 14b. a FULL census: unprobed rows never evict measurements ────── */
    printf("  full census: not-probed never evicts a measured row... ");
    {
        network_crawler_test_reset();
        network_crawler_test_set_probe_fn(onion_aware_probe);
        onion_probe_counters_reset();
        /* No onion dials at all this phase: everything onion banks NOT
         * PROBED, which is the shape the defect needed (ncrawl_bank_unprobed
         * stamps last_probe_us = now, so a fresh unprobed row is never the
         * smallest-last_probe_us victim and a pure oldest-first eviction
         * always took a real measurement instead). */
        network_crawler_test_set_onion_limits(0, 1, 1000, 0);

        /* Fill the bounded census to capacity with MEASURED clearnet rows. */
        struct net_address batch[NCRAWL_MAX_PER_ROUND];
        int rounds = NCRAWL_MAX_CENSUS / NCRAWL_MAX_PER_ROUND;
        for (int r = 0; r < rounds; r++) {
            for (int i = 0; i < NCRAWL_MAX_PER_ROUND; i++)
                batch[i] = mk_addr((uint8_t)r, true, false, (uint8_t)i,
                                   (uint16_t)(20000 + r * NCRAWL_MAX_PER_ROUND
                                              + i));
            NC_CHECK(network_crawler_test_probe_round(batch, NCRAWL_MAX_PER_ROUND)
                     == NCRAWL_MAX_PER_ROUND);
        }
        NC_CHECK(network_crawler_test_census_count() == NCRAWL_MAX_CENSUS);
        struct network_census_view full;
        NC_CHECK(network_crawler_get_view(&full));
        NC_CHECK(full.measured_count == NCRAWL_MAX_CENSUS);

        /* Now push a full round of onions the crawler will NOT dial. Each
         * one banks NOT PROBED with a fresh timestamp. */
        struct net_address onions[NCRAWL_MAX_PER_ROUND];
        for (int i = 0; i < NCRAWL_MAX_PER_ROUND; i++)
            onions[i] = mk_onion((uint8_t)(0xC0 + i), (uint16_t)(21100 + i));
        NC_CHECK(network_crawler_test_probe_round(onions, NCRAWL_MAX_PER_ROUND)
                 == NCRAWL_MAX_PER_ROUND);

        /* The aggregate invariant: not one measurement was displaced. */
        struct network_census_view after;
        NC_CHECK(network_crawler_get_view(&after));
        NC_CHECK(network_crawler_test_census_count() == NCRAWL_MAX_CENSUS);
        NC_CHECK(after.measured_count == NCRAWL_MAX_CENSUS);
        NC_CHECK(after.not_probed_count == 0);

        network_crawler_test_reset();
        printf("done\n");
    }

    /* ── 15. the REAL default probe degrades an onion to NOT PROBED ─────── */
    printf("  default probe: no Tor => onion NOT PROBED (never unreachable)... ");
    {
        /* This binary links the Tor stub and never bootstraps a circuit, so
         * the onion path structurally cannot dial. It must say so. */
        NC_CHECK(network_crawler_onion_probe_available() == false);

        struct net_address o = mk_onion(0x5A, 8033);
        struct ncrawl_probe_result r;
        NC_CHECK(network_crawler_default_probe(&o, 1000, 1000, &r) == true);
        NC_CHECK(r.is_onion == true);
        NC_CHECK(r.outcome == (uint8_t)NCRAWL_OUTCOME_NOT_PROBED);
        NC_CHECK(r.reachable == false);
        NC_CHECK(strstr(r.reason, "tor") != NULL);
        NC_CHECK(strstr(r.addr, ".onion:8033") != NULL);
        printf("done\n");
    }

    /* ── 16. unprobed is banked as a NOTE, never as a failed dial ───────── */
    printf("  ledger notes unprobed addresses without a census failure... ");
    {
        uint64_t base = peers_projection_census_unprobed_total();
        uint8_t ip[16] = {0};
        ip[15] = 9;
        NC_CHECK(peers_projection_note_census_unprobed(ip, 8033,
                                                       "tor unavailable"));
        NC_CHECK(peers_projection_note_census_unprobed(NULL, 8033, NULL));
        NC_CHECK(peers_projection_census_unprobed_total() == base + 2);
        char why[PEERS_CENSUS_UNPROBED_REASON_MAX];
        peers_projection_census_unprobed_reason(why, sizeof(why));
        NC_CHECK(strcmp(why, "tor unavailable") == 0);

        /* and a real round's unprobed rows flow into the same counter */
        network_crawler_test_reset();
        network_crawler_test_set_probe_fn(onion_aware_probe);
        onion_probe_counters_reset();
        atomic_store(&g_onion_not_probed, 1);
        network_crawler_test_set_onion_limits(2, 1, 1000, 0);
        struct net_address on2[2];
        for (int i = 0; i < 2; i++)
            on2[i] = mk_onion((uint8_t)(0xE0 + i), (uint16_t)(16000 + i));
        uint64_t pre = peers_projection_census_unprobed_total();
        NC_CHECK(network_crawler_test_probe_round(on2, 2) == 2);
        NC_CHECK(peers_projection_census_unprobed_total() == pre + 2);

        /* the dumper reports the ledger-side total too */
        struct json_value d;
        json_init(&d);
        NC_CHECK(network_crawler_dump_state_json(&d, NULL));
        const struct json_value *lt =
            json_get(&d, "ledger_unprobed_notes_total");
        NC_CHECK(lt != NULL && (uint64_t)json_get_int(lt) == pre + 2);
        const struct json_value *lr =
            json_get(&d, "ledger_unprobed_last_reason");
        NC_CHECK(lr != NULL && json_get_str(lr) != NULL &&
                 json_get_str(lr)[0] != '\0');
        json_free(&d);
        atomic_store(&g_onion_not_probed, 0);
        printf("done\n");
    }

    network_crawler_test_reset();

    if (failures == 0)
        printf("network_crawler: ALL PASS\n");
    else
        printf("network_crawler: %d FAILURE(S)\n", failures);
    return failures;
}
