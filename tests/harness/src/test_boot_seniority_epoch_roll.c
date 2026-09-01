/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_boot_seniority_epoch_roll — the property nothing tested before this
 * file existed: A DIAL-PREFERENCE BOOST GOES AWAY.
 *
 * tests/harness/src/test_zid_seniority_binding.c proves a boost ARRIVES, and its
 * rotation case proves the pure epoch-comparison function decides to rebuild.
 * Neither ever ran boot_seniority_refresh_once(), and the gap between them
 * was where the bug lived: the weighting pass returned early on "no opinion"
 * without touching addrman, so a relay boosted to 2.5x in one epoch that
 * recomputed to 1.0 in the next kept the dead 2.5x for the life of the
 * process — and the rebuild never enumerated addrman, so an address that
 * fell out of both input feeds was never even revisited.
 *
 * So this file runs the REAL rebuild — the one the zcl_seniority worker
 * calls — TWICE, against ONE addrman, with the world changed underneath it,
 * and asserts what the second epoch did to the first epoch's opinions.
 *
 *   (1) A senior relay with a signed endpoint record earns a bounded boost
 *       in epoch one.
 *   (2) The SAME addrman reports that relay at exactly 1.0 in epoch two,
 *       after its anchored identity leaves the ranking. Same instance, no
 *       reconstruction — a fresh addrman would prove nothing, because the
 *       bug was precisely that the stale value was never overwritten.
 *   (3) A relay whose endpoint record was removed loses its boost too, by
 *       the same mechanism: it is simply not in the table any more.
 *   (4) An address whose boost comes from BANKED BANDWIDTH and not from the
 *       chain survives the seniority roll with its multiplier unchanged to
 *       the bit. The two signals are merged into one value on purpose (see
 *       config/boot_seniority.h); merging them must not mean a seniority
 *       roll can knock out a bandwidth boost.
 *   (5) Every multiplier in every published table is inside [1.0, 4.0], and
 *       no address is ever removed from addrman or pushed below its
 *       unweighted dial chance. Asserted on the addrman, not argued from
 *       the arithmetic.
 *
 * Plus (6): the measured cost of the per-candidate table lookup that
 * addrman_select() now pays, at a full-size table. Reported as a number, not
 * asserted to be fast — a claim about performance with no measurement behind
 * it is the thing this project does not do.
 *
 * REAL COMPONENTS, NO NODE. A real (in-memory) node.db carrying real
 * zid_identities rows, a real event log + peers projection carrying a real
 * banked session, real ed25519-signed endpoint records accepted through
 * zendp_accept(), and a real addrman. The only stand-in is the chain-anchor
 * oracle, which zendp exposes as an injection seam for exactly this reason.
 */

#include "test/test_core.h"

#include "config/boot_internal.h"
#include "config/boot_seniority.h"
#include "crypto/ed25519.h"
#include "jobs/reducer_frontier.h"
#include "models/database.h"
#include "models/zid_identity.h"
#include "net/addrman.h"
#include "platform/time_compat.h"
#include "storage/event_log.h"
#include "storage/event_log_payloads.h"
#include "storage/peers_projection.h"
#include "vcs/zendp_swarm.h"
#include "zid/zendp.h"
#include "zid/zid.h"
#include "zid/zid_seniority.h"

#include <math.h>
#include <stdio.h>
#include <string.h>

#define BSR_CHECK(name, expr) do {                                     \
    printf("boot_seniority_epoch_roll: %s... ", (name));               \
    if (expr) { printf("OK\n"); }                                      \
    else { printf("FAIL\n"); failures++; }                             \
} while (0)

/* Well past ZID_SENIORITY_MIN_AGE_BLOCKS for an identity anchored at 1. */
#define BSR_TIP        400000
#define BSR_EPOCH_ONE  (BSR_TIP - (BSR_TIP % ZID_SENIORITY_EPOCH_BLOCKS))
#define BSR_EPOCH_TWO  (BSR_EPOCH_ONE + ZID_SENIORITY_EPOCH_BLOCKS)

/* Seeds for the two anchored relay identities. */
#define BSR_SEED_A 0xA1
#define BSR_SEED_C 0xC3

/* ── the chain-anchor oracle zendp_accept resolves records against ─── */

static bool bsr_oracle(void *ctx, const uint8_t pubkey[32],
                       struct zendp_anchor *out)
{
    (void)ctx;
    if (!pubkey || !out)
        return false;
    memset(out, 0, sizeof(*out));
    out->anchor_height = 1;
    out->updated_height = 1;
    out->state = ZENDP_ANCHOR_ACTIVE;
    return true;
}

/* ── addresses ─────────────────────────────────────────────────────── */

/* A distinct /16 per fixture: addrman buckets by address group, so two
 * addresses sharing a /16 can land in one bucket and evict each other. */
static void bsr_ipv4_mapped(uint8_t out[16], uint8_t d)
{
    memset(out, 0, 10);
    out[10] = 0xff;
    out[11] = 0xff;
    out[12] = (uint8_t)(51 + d);
    out[13] = (uint8_t)(15 + d);
    out[14] = 0;
    out[15] = d;
}

static void bsr_addrman_add(struct addr_man *am, const uint8_t ip[16],
                            uint16_t port)
{
    struct net_address a;
    net_address_init(&a);
    memcpy(a.svc.addr.ip, ip, 16);
    a.svc.port = port;
    struct net_addr src;
    net_addr_init(&src);
    src.ip[10] = 0xff; src.ip[11] = 0xff; src.ip[15] = 1;
    (void)addrman_add(am, &a, &src, 0);
}

static double bsr_weight_of(struct addr_man *am, const uint8_t ip[16])
{
    struct net_addr na;
    net_addr_init(&na);
    memcpy(na.ip, ip, 16);
    return addrman_reputation_weight(am, &na);
}

static const struct addr_info *bsr_entry_of(const struct addr_man *am,
                                            const uint8_t ip[16])
{
    for (int i = 0; i < am->id_count; i++) {
        if (am->entries[i].used &&
            memcmp(am->entries[i].addr.svc.addr.ip, ip, 16) == 0)
            return &am->entries[i];
    }
    return NULL;
}

/* ── signed endpoint records ───────────────────────────────────────── */

/* Sign one IPv4 endpoint record for the identity derived from `seed_byte`
 * and hand it to the process-wide directory the way an accepted record
 * arrives. Fills pk_out with the identity the record was signed by. */
static bool bsr_install_record(uint8_t seed_byte, uint8_t last_octet,
                               uint8_t pk_out[32])
{
    uint8_t seed[32], sk[32];
    memset(seed, seed_byte, sizeof(seed));
    ed25519_keypair(pk_out, sk, seed);

    uint64_t now = (uint64_t)platform_time_wall_unix();

    struct zendp ep;
    memset(&ep, 0, sizeof(ep));
    ep.flags = ZENDP_HAS_IPV4;
    ep.ipv4[0] = (uint8_t)(51 + last_octet);
    ep.ipv4[1] = (uint8_t)(15 + last_octet);
    ep.ipv4[2] = 0;
    ep.ipv4[3] = last_octet;
    ep.ipv4_port = 8033;
    ep.services = 0x409;
    ep.height = BSR_TIP;
    ep.not_before = now - 60;

    struct zid_doc doc;
    if (!zendp_sign(&doc, &ep, 1, now + 86400, seed))
        return false;
    uint8_t wire[ZID_DOC_MAX];
    size_t n = zid_doc_encode(wire, sizeof(wire), &doc);
    if (n == 0)
        return false;
    return zendp_accept(zendp_directory_global(), wire, n, now, NULL, NULL) ==
           ZENDP_OK;
}

/* ── anchored identities ───────────────────────────────────────────── */

static bool bsr_save_identity(struct node_db *ndb, const uint8_t pk[32],
                              const char *owner)
{
    struct zid_identity row;
    memset(&row, 0, sizeof(row));
    memcpy(row.master_pubkey, pk, 32);
    memset(row.anchor_txid, pk[0] ^ 0xa5, 32);
    row.anchor_height = 1;           /* ancient: well past the age floor */
    row.updated_height = 1;
    snprintf(row.status, sizeof(row.status), "%s", "active");
    snprintf(row.source, sizeof(row.source), "%s", "zid_overlay");
    snprintf(row.owner_address, sizeof(row.owner_address), "%s", owner);
    return db_zid_identity_save(ndb, &row);
}

/* ── (1)-(5): two epochs, one addrman ──────────────────────────────── */

static int bsr_case_epoch_roll(void)
{
    int failures = 0;

    char dir[256], elog_path[300], proj_path[300];
    test_make_tmpdir(dir, sizeof(dir), "boot_seniority", "epoch_roll");
    test_projection_paths(dir, "peers", elog_path, sizeof(elog_path),
                          proj_path, sizeof(proj_path));

    /* The banked-bandwidth feed: one address with a closed session and a
     * bandwidth_score of 204, i.e. a multiplier of exactly
     * 1.0 + 3.0 * (204/255) = 3.4. Deterministic, so (4) can be asserted to
     * the bit rather than as an inequality. */
    uint8_t ip_bandwidth[16];
    bsr_ipv4_mapped(ip_bandwidth, 44);
    event_log_t *log = event_log_open(elog_path);
    peers_projection_t *proj = peers_projection_open(proj_path, log);
    if (!log || !proj) {
        printf("boot_seniority_epoch_roll: cannot open peers projection\n");
        peers_projection_close(proj);
        event_log_close(log);
        test_cleanup_tmpdir(dir);
        return 1;
    }
    {
        struct ev_peer_session_closed ev;
        uint8_t payload[EV_PEER_SESSION_CLOSED_LEN];
        memset(&ev, 0, sizeof(ev));
        memcpy(ev.ip_v4_or_v6, ip_bandwidth, 16);
        ev.port = 8033;
        ev.duration_secs = 600;
        ev.bytes_in = 1u << 20;
        ev.bytes_out = 1u << 18;
        ev.headers_delivered = 2000;
        ev.blocks_delivered = 40;
        ev.bandwidth_score = 204;
        ev.avg_latency_us = 9000;
        ev.last_useful_time = 1700000000;
        BSR_CHECK("a banked session is appended",
                  ev_peer_session_closed_serialize(&ev, payload) &&
                  event_log_append(log, EV_PEER_SESSION_CLOSED, payload,
                                   sizeof(payload)) != UINT64_MAX);
        BSR_CHECK("the peers projection folds it",
                  peers_projection_catch_up(proj) != UINT64_MAX);
    }

    /* The on-chain feed. */
    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));
    if (!node_db_open(&ndb, ":memory:") || !ndb.open) {
        printf("boot_seniority_epoch_roll: cannot open node.db\n");
        peers_projection_close(proj);
        event_log_close(log);
        test_cleanup_tmpdir(dir);
        return 1;
    }

    /* The signed-record feed, resolved against a chain that says ACTIVE. */
    zendp_set_anchor_lookup(bsr_oracle, NULL);
    zendp_directory_init(zendp_directory_global());

    uint8_t pk_a[32], pk_c[32];
    BSR_CHECK("relay A's signed endpoint record is accepted",
              bsr_install_record(BSR_SEED_A, 7, pk_a));
    BSR_CHECK("relay C's signed endpoint record is accepted",
              bsr_install_record(BSR_SEED_C, 3, pk_c));
    BSR_CHECK("both relay identities are anchored on chain",
              bsr_save_identity(&ndb, pk_a, "t1AoneOwnerAddressAAAAAAAAAAAAAAA") &&
              bsr_save_identity(&ndb, pk_c, "t1CtwoOwnerAddressCCCCCCCCCCCCCCC"));

    uint8_t ip_a[16], ip_c[16];
    bsr_ipv4_mapped(ip_a, 7);
    bsr_ipv4_mapped(ip_c, 3);

    /* One addrman for BOTH epochs. This is the whole point. */
    struct addr_man am;
    addrman_init(&am);
    bsr_addrman_add(&am, ip_a, 8033);
    bsr_addrman_add(&am, ip_c, 8033);
    bsr_addrman_add(&am, ip_bandwidth, 8033);
    size_t size_before = addrman_size(&am);

    /* Everything the rebuild reads is now in place. */
    reducer_frontier_provable_tip_set(BSR_TIP);
    boot_active_svc()->node_db = &ndb;

    BSR_CHECK("an addrman with nothing published reads exactly 1.0 everywhere",
              bsr_weight_of(&am, ip_a) == 1.0 &&
              bsr_weight_of(&am, ip_c) == 1.0 &&
              bsr_weight_of(&am, ip_bandwidth) == 1.0 &&
              addrman_reputation_weight_count(&am) == 0);

    /* ── EPOCH ONE ─────────────────────────────────────────────────── */

    BSR_CHECK("the real rebuild runs for epoch one",
              boot_seniority_refresh_once(&am, BSR_EPOCH_ONE));
    BSR_CHECK("epoch one's table is the one addrman is serving",
              addrman_reputation_weight_epoch(&am) == BSR_EPOCH_ONE);

    double a1 = bsr_weight_of(&am, ip_a);
    double c1 = bsr_weight_of(&am, ip_c);
    double b1 = bsr_weight_of(&am, ip_bandwidth);
    printf("boot_seniority_epoch_roll:   epoch %d: A=%.6fx C=%.6fx "
           "bandwidth=%.6fx (%zu rows)\n", BSR_EPOCH_ONE, a1, c1, b1,
           addrman_reputation_weight_count(&am));

    /* (1) */
    BSR_CHECK("(1) relay A earns a bounded boost in epoch one",
              a1 > 1.0 && a1 <= ADDRMAN_REPUTATION_MAX_MULT);
    BSR_CHECK("(1) relay C earns a bounded boost in epoch one",
              c1 > 1.0 && c1 <= ADDRMAN_REPUTATION_MAX_MULT);
    /* (4), first half: the bandwidth-only address, exactly 3.4. */
    BSR_CHECK("(4) the bandwidth-only address is boosted to exactly 3.4",
              fabs(b1 - 3.4) < 1e-12);

    /* ── THE WORLD CHANGES ─────────────────────────────────────────── */

    /* Relay A LEAVES THE RANKING: its anchored identity is gone from the
     * projection, so the rebuild computes nothing for it at all. This is the
     * exact shape of the original defect — the old code's response to "no
     * opinion" was to leave the previous epoch's number in place. */
    BSR_CHECK("relay A leaves the ranking",
              db_zid_identity_truncate(&ndb) &&
              bsr_save_identity(&ndb, pk_c,
                                "t1CtwoOwnerAddressCCCCCCCCCCCCCCC") &&
              db_zid_identity_count(&ndb) == 1);

    /* Relay C KEEPS its anchor but LOSES its endpoint record: nothing signs
     * for its address any more, so it has no binding to be weighed through. */
    zendp_directory_init(zendp_directory_global());
    BSR_CHECK("relay A's record is re-installed, relay C's is not",
              bsr_install_record(BSR_SEED_A, 7, pk_a));

    /* ── EPOCH TWO, SAME ADDRMAN ───────────────────────────────────── */

    BSR_CHECK("the real rebuild runs for epoch two",
              boot_seniority_refresh_once(&am, BSR_EPOCH_TWO));
    BSR_CHECK("epoch two's table replaced epoch one's",
              addrman_reputation_weight_epoch(&am) == BSR_EPOCH_TWO);

    double a2 = bsr_weight_of(&am, ip_a);
    double c2 = bsr_weight_of(&am, ip_c);
    double b2 = bsr_weight_of(&am, ip_bandwidth);
    printf("boot_seniority_epoch_roll:   epoch %d: A=%.6fx C=%.6fx "
           "bandwidth=%.6fx (%zu rows)\n", BSR_EPOCH_TWO, a2, c2, b2,
           addrman_reputation_weight_count(&am));

    /* (2) THE REGRESSION. Not "close to 1.0" and not "unset" — exactly the
     * baseline, on the same addrman that was reporting a boost a moment
     * ago, because the address is simply not in the new table. */
    BSR_CHECK("(2) relay A is back at exactly 1.0 after leaving the ranking",
              a2 == 1.0);
    /* (3) */
    BSR_CHECK("(3) relay C loses its boost when its endpoint record goes",
              c2 == 1.0);
    /* (4) */
    BSR_CHECK("(4) the bandwidth boost survives the roll to the bit",
              b2 == b1 && fabs(b2 - 3.4) < 1e-12);
    BSR_CHECK("(4) and it is the ONLY row epoch two published",
              addrman_reputation_weight_count(&am) == 1);

    /* (5) Bounds and non-exclusion, on the addrman itself. */
    bool bounded = true;
    const double seen[6] = { a1, c1, b1, a2, c2, b2 };
    for (size_t i = 0; i < 6; i++)
        if (!(seen[i] >= 1.0 && seen[i] <= ADDRMAN_REPUTATION_MAX_MULT))
            bounded = false;
    BSR_CHECK("(5) every multiplier in both epochs is inside [1.0, 4.0]",
              bounded);
    BSR_CHECK("(5) no address was removed by either rebuild",
              addrman_size(&am) == size_before && size_before == 3);

    const struct addr_info *e_a = bsr_entry_of(&am, ip_a);
    const struct addr_info *e_c = bsr_entry_of(&am, ip_c);
    const struct addr_info *e_b = bsr_entry_of(&am, ip_bandwidth);
    BSR_CHECK("(5) every address is still present after two rebuilds",
              e_a && e_c && e_b);
    /* An address the table dropped must land on the PLAIN chance — the same
     * number an addrman that never heard of this subsystem would produce. */
    double plain = e_a ? addr_info_get_chance(NULL, e_a, 1000000) : -1.0;
    BSR_CHECK("(5) a dropped address falls back to its unweighted dial chance",
              e_a && plain > 0.0 &&
              addr_info_get_chance(&am, e_a, 1000000) == plain);
    BSR_CHECK("(5) and no address is excluded — every chance is positive",
              e_a && e_c && e_b &&
              addr_info_get_chance(&am, e_a, 1000000) > 0.0 &&
              addr_info_get_chance(&am, e_c, 1000000) > 0.0 &&
              addr_info_get_chance(&am, e_b, 1000000) > 0.0);
    /* The one address still in the table is still boosted above plain. */
    BSR_CHECK("(5) the surviving boost still raises, never lowers, a chance",
              e_b &&
              addr_info_get_chance(&am, e_b, 1000000) >
                  addr_info_get_chance(NULL, e_b, 1000000));

    /* ── EPOCH THREE: everything goes ──────────────────────────────── */

    /* The last thing a "clear a weight" code path would have been needed
     * for: no inputs at all. An empty table is a legal publication and it
     * returns the whole addrman to the baseline. */
    BSR_CHECK("relay C leaves the ranking too",
              db_zid_identity_truncate(&ndb));
    zendp_directory_init(zendp_directory_global());
    BSR_CHECK("the rebuild runs with no chain input and no records",
              boot_seniority_refresh_once(
                  &am, BSR_EPOCH_TWO + ZID_SENIORITY_EPOCH_BLOCKS));
    BSR_CHECK("the bandwidth boost is STILL there — it never came from the "
              "chain", bsr_weight_of(&am, ip_bandwidth) == b1);

    boot_active_svc()->node_db = NULL;
    reducer_frontier_provable_tip_reset();
    zendp_set_anchor_lookup(NULL, NULL);
    zendp_directory_init(zendp_directory_global());
    addrman_free(&am);
    node_db_close(&ndb);
    peers_projection_close(proj);
    event_log_close(log);
    test_cleanup_tmpdir(dir);
    return failures;
}

/* ── (6) what the lookup costs addrman_select ──────────────────────── */

/* addrman_select() scores up to 200000 candidates per call and now pays one
 * binary search per score. Measure it rather than assert it is cheap. */
static int bsr_case_lookup_cost(void)
{
    int failures = 0;
    const size_t table_n = BOOT_SENIORITY_ROWS_MAX;   /* the worst case */
    const int iters = 200000;                         /* one select's ceiling */

    struct addr_man am;
    addrman_init(&am);

    struct addrman_weight_row *rows =
        malloc(table_n * sizeof(*rows));
    if (!rows) {
        printf("boot_seniority_epoch_roll: lookup cost: alloc failed\n");
        addrman_free(&am);
        return 1;
    }
    for (size_t i = 0; i < table_n; i++) {
        memset(rows[i].ip, 0, 16);
        rows[i].ip[10] = 0xff;
        rows[i].ip[11] = 0xff;
        rows[i].ip[12] = (uint8_t)(i >> 8);
        rows[i].ip[13] = (uint8_t)(i & 0xff);
        rows[i].multiplier = 2.0;
    }
    BSR_CHECK("a full-size table publishes",
              addrman_publish_reputation_weights(&am, rows, table_n, 0));
    BSR_CHECK("and holds every row",
              addrman_reputation_weight_count(&am) == table_n);

    /* One entry present in the table, one absent — absent is the miss path,
     * which walks the full depth of the search. */
    struct addr_info hit, miss;
    memset(&hit, 0, sizeof(hit));
    memset(&miss, 0, sizeof(miss));
    hit.last_try = 0;
    miss.last_try = 0;
    memcpy(hit.addr.svc.addr.ip, rows[table_n / 2].ip, 16);
    memset(miss.addr.svc.addr.ip, 0, 16);
    miss.addr.svc.addr.ip[10] = 0xff;
    miss.addr.svc.addr.ip[11] = 0xff;
    miss.addr.svc.addr.ip[12] = 0xde;
    miss.addr.svc.addr.ip[13] = 0xad;

    double sink = 0.0;
    int64_t t0 = platform_time_monotonic_us();
    for (int i = 0; i < iters; i++)
        sink += addr_info_get_chance(NULL, (i & 1) ? &hit : &miss, 1000000);
    int64_t t_plain = platform_time_monotonic_us() - t0;

    t0 = platform_time_monotonic_us();
    for (int i = 0; i < iters; i++)
        sink += addr_info_get_chance(&am, (i & 1) ? &hit : &miss, 1000000);
    int64_t t_weighted = platform_time_monotonic_us() - t0;

    double per_lookup_ns = t_weighted > t_plain
        ? (double)(t_weighted - t_plain) * 1000.0 / (double)iters : 0.0;
    printf("boot_seniority_epoch_roll:   lookup cost: %d scorings over a "
           "%zu-row table: %lld us unweighted, %lld us weighted "
           "(+%.1f ns per candidate); a full 200000-candidate select pays "
           "+%.3f ms  [sink %.3f]\n",
           iters, table_n, (long long)t_plain, (long long)t_weighted,
           per_lookup_ns, per_lookup_ns * 200000.0 / 1e6, sink);

    /* The only thing asserted is that the lookup answers correctly at full
     * size — the timing above is reported, not gated, because a shared
     * build box is not a benchmark rig. */
    BSR_CHECK("a full-size table still answers hits and misses correctly",
              addr_info_get_chance(&am, &hit, 1000000) ==
                  2.0 * addr_info_get_chance(NULL, &hit, 1000000) &&
              addr_info_get_chance(&am, &miss, 1000000) ==
                  addr_info_get_chance(NULL, &miss, 1000000));

    free(rows);
    addrman_free(&am);
    return failures;
}

int test_boot_seniority_epoch_roll(void)
{
    int failures = 0;
    printf("\n=== boot_seniority epoch roll ===\n");
    failures += bsr_case_epoch_roll();
    failures += bsr_case_lookup_cost();
    if (failures == 0)
        printf("boot_seniority_epoch_roll: all checks passed\n");
    return failures;
}
