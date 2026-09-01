/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tests for the ADDRESS BINDING that turns on-chain seniority from a table
 * the node computed and discarded into a number that changes which peer it
 * dials first — config/boot_seniority.h.
 *
 * Until this landed, boot_seniority_relay_for_addr() returned false for every
 * address: the seniority table was built, scored, owner-capped and drawn, and
 * then thrown away, so every address got multiplier 1.0 and the combined
 * weight equalled the bandwidth-only weight exactly. These cases pin the two
 * halves of the fix and the bound both halves live inside.
 *
 * The properties, each with a number attached:
 *
 *   (1) A registered address resolves to the identity that SIGNED for it, and
 *       an unregistered one resolves to nothing — false, not a penalty.
 *   (2) Seniority DEMONSTRABLY changes peer selection: two addresses with
 *       identical (zero) banked bandwidth reputation come out of one
 *       weighting pass with different dial chances, and the ratio is exactly
 *       the seniority multiplier.
 *   (3) The [1.0, 4.0] clamp holds end to end, for hostile inputs included,
 *       and NOTHING in the path can drop an address below the unweighted
 *       baseline or remove it from addrman. Non-exclusion is asserted on the
 *       addrman itself, not inferred from the arithmetic.
 *   (4) ZID_SENIORITY_EPOCH_BLOCKS is honoured at RUNTIME: the rotation
 *       decision rebuilds on an epoch boundary and idles between boundaries,
 *       which is what stops a long-running node pinning one favourite set
 *       forever.
 *   (5) The directory sweep that reaches relays with no session history
 *       issues at most ONE addrman call per address — two calls would be two
 *       influence paths in everything but name.
 *
 * NO NODE, NO CHAIN, NO NETWORK. The addrman is a local struct, the endpoint
 * records are caller-supplied views (boot_relay_bindings_build is documented
 * as taking already-verified input), and the seniority table is produced by
 * the real zid_seniority_rank so nothing here hand-forges a multiplier. */

#include "test/test_core.h"

#include "config/boot_seniority.h"
#include "net/addrman.h"
#include "zid/zid_seniority.h"

#include <math.h>
#include <stdio.h>
#include <string.h>

#define ZSB_CHECK(name, expr) do {                                    \
    printf("zid_seniority_binding: %s... ", (name));                  \
    if (expr) { printf("OK\n"); }                                     \
    else { printf("FAIL\n"); failures++; }                            \
} while (0)

/* ── fixtures ──────────────────────────────────────────────────────── */

static void zsb_ipv4_mapped(uint8_t out[16], uint8_t d)
{
    memset(out, 0, 10);
    out[10] = 0xff;
    out[11] = 0xff;
    /* A DISTINCT /16 per fixture: addrman buckets by address group, so two
     * addresses sharing a /16 can land in one bucket and evict each other,
     * which would make these cases flaky for a reason that has nothing to
     * do with seniority. */
    out[12] = (uint8_t)(51 + d); out[13] = (uint8_t)(15 + d);
    out[14] = 0; out[15] = d;
}

/* A record view as the signed-endpoint directory hands one over: already
 * signature-checked against its own master key and already resolved to an
 * ACTIVE on-chain anchor (zendp_directory_records). */
static void zsb_view_v4(struct zendp_record_view *v, uint8_t key_byte,
                        uint8_t last_octet, uint16_t port)
{
    memset(v, 0, sizeof(*v));
    memset(v->master_pubkey, key_byte, 32);
    v->anchor_height = 1000;
    v->ep.flags = ZENDP_HAS_IPV4;
    v->ep.ipv4[0] = (uint8_t)(51 + last_octet);
    v->ep.ipv4[1] = (uint8_t)(15 + last_octet);
    v->ep.ipv4[2] = 0;
    v->ep.ipv4[3] = last_octet;
    v->ep.ipv4_port = port;
}

/* Deterministic stand-in for the per-client draw. The only property the
 * weighting relies on is "uniform, pure, and different per client". */
static uint64_t zsb_mix(uint64_t x)
{
    x += 0x9E3779B97F4A7C15ull;
    x = (x ^ (x >> 30)) * 0xBF58476D1CE4E5B9ull;
    x = (x ^ (x >> 27)) * 0x94D049BB133111EBull;
    return x ^ (x >> 31);
}

struct zsb_client { uint64_t seed; };

static bool zsb_draw(void *ctx, const uint8_t relay_id[32], uint64_t *out)
{
    const struct zsb_client *c = ctx;
    uint64_t acc = c->seed;
    for (int i = 0; i < 32; i++)
        acc = zsb_mix(acc ^ relay_id[i]);
    *out = acc;
    return true;
}

/* Add `ip` to addrman as a fresh new-table entry. */
static void zsb_addrman_add(struct addr_man *am, const uint8_t ip[16],
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

/* The multiplier addrman actually PUBLISHES for `ip`. There is no third
 * state: an address absent from the published table — or an addrman with no
 * table published at all — reads exactly 1.0. */
static double zsb_weight_of(struct addr_man *am, const uint8_t ip[16])
{
    struct net_addr na;
    net_addr_init(&na);
    memcpy(na.ip, ip, 16);
    return addrman_reputation_weight(am, &na);
}

/* Publish whatever rows a pass built, the way boot_seniority_refresh_once
 * does: as ONE table, replacing the previous one whole. */
static bool zsb_publish(struct addr_man *am,
                        const struct boot_seniority_pass *pass, int32_t epoch)
{
    return addrman_publish_reputation_weights(am, pass->rows, pass->rows_n,
                                              epoch);
}

static const struct addr_info *zsb_entry_of(const struct addr_man *am,
                                            const uint8_t ip[16])
{
    for (int i = 0; i < am->id_count; i++) {
        if (am->entries[i].used &&
            memcmp(am->entries[i].addr.svc.addr.ip, ip, 16) == 0)
            return &am->entries[i];
    }
    return NULL;
}

/* ── (1) binding build + lookup honesty ────────────────────────────── */

static int zsb_case_binding(void)
{
    int failures = 0;

    struct zendp_record_view views[4];
    zsb_view_v4(&views[0], 0xA1, 7, 8033);
    zsb_view_v4(&views[1], 0xB2, 3, 8033);

    /* An onion-only record: carried, verified, and deliberately producing no
     * binding — addrman holds no torv3 entries, so a torv3 row would be a
     * lookup nothing could hit. */
    memset(&views[2], 0, sizeof(views[2]));
    memset(views[2].master_pubkey, 0xC3, 32);
    views[2].ep.flags = ZENDP_HAS_ONION;
    memset(views[2].ep.onion, 'a', 56);
    snprintf(views[2].ep.onion + 56, 7, ".onion");
    views[2].ep.onion_port = 8033;

    /* 0.0.0.0 reaches nobody and must not become a row. */
    memset(&views[3], 0, sizeof(views[3]));
    memset(views[3].master_pubkey, 0xD4, 32);
    views[3].ep.flags = ZENDP_HAS_IPV4;
    views[3].ep.ipv4_port = 8033;

    struct boot_relay_binding table[BOOT_RELAY_BINDINGS_MAX];
    size_t n = boot_relay_bindings_build(views, 4, table,
                                         BOOT_RELAY_BINDINGS_MAX);
    ZSB_CHECK("only clearnet endpoints become bindings (2 of 4 records)",
              n == 2);

    /* Sorted ascending by ip, so 54.18.0.3 precedes 58.22.0.7. */
    ZSB_CHECK("binding table is in canonical (ip, port) order",
              n == 2 && memcmp(table[0].ip, table[1].ip, 16) < 0);

    uint8_t ip7[16], ip3[16], ip9[16];
    zsb_ipv4_mapped(ip7, 7);
    zsb_ipv4_mapped(ip3, 3);
    zsb_ipv4_mapped(ip9, 9);

    uint8_t got[32];
    memset(got, 0, sizeof(got));
    bool found7 = boot_relay_binding_find(table, n, ip7, 8033, got);
    ZSB_CHECK("a registered address resolves to the key that signed for it",
              found7 && got[0] == 0xA1 && got[31] == 0xA1);

    memset(got, 0, sizeof(got));
    bool found3 = boot_relay_binding_find(table, n, ip3, 8033, got);
    ZSB_CHECK("the second registered address resolves to its own key",
              found3 && got[0] == 0xB2);

    /* The honest negative: absent is false, never a penalty and never a
     * guess at the nearest neighbour. */
    ZSB_CHECK("an unregistered address resolves to nothing",
              !boot_relay_binding_find(table, n, ip9, 8033, got));

    /* A record that named a port does not answer for a peer seen on a
     * different declared port; a peer with no declared port still matches. */
    ZSB_CHECK("a contradicting declared port withholds the binding",
              !boot_relay_binding_find(table, n, ip7, 9999, got));
    ZSB_CHECK("an undeclared peer port still matches",
              boot_relay_binding_find(table, n, ip7, 0, got));

    return failures;
}

/* ── (2) seniority demonstrably changes peer selection ─────────────── */

/* Build a real seniority table: one ancient relay, one freshly anchored,
 * both under distinct owners, ranked by the real zid_seniority_rank. */
static size_t zsb_rank(struct zid_seniority_weight *out, size_t cap,
                       int32_t tip, uint64_t client_seed)
{
    struct zid_relay_registration regs[2];
    memset(regs, 0, sizeof(regs));
    memset(regs[0].relay_id, 0xA1, 32);
    memset(regs[0].owner_id, 0x11, 32);
    regs[0].registration_height = 1;            /* ancient */
    memset(regs[1].relay_id, 0xB2, 32);
    memset(regs[1].owner_id, 0x22, 32);
    regs[1].registration_height = tip - 10;     /* under the age floor */

    struct zsb_client client = { .seed = client_seed };
    int n = zid_seniority_rank(regs, 2, tip, zsb_draw, &client, out, cap);
    return n > 0 ? (size_t)n : 0;
}

static int zsb_case_selection(void)
{
    int failures = 0;
    const int32_t tip = 400000;

    struct zid_seniority_weight weights[2];
    size_t wn = zsb_rank(weights, 2, tip, 0xC0FFEEull);
    ZSB_CHECK("both relays are ranked, none dropped", wn == 2);

    const struct zid_seniority_weight *senior =
        zid_seniority_find(weights, wn, (const uint8_t[32]){
            0xA1,0xA1,0xA1,0xA1,0xA1,0xA1,0xA1,0xA1,0xA1,0xA1,0xA1,0xA1,
            0xA1,0xA1,0xA1,0xA1,0xA1,0xA1,0xA1,0xA1,0xA1,0xA1,0xA1,0xA1,
            0xA1,0xA1,0xA1,0xA1,0xA1,0xA1,0xA1,0xA1 });
    ZSB_CHECK("the ancient relay carries a boost above the baseline",
              senior && senior->multiplier > 1.0);
    const struct zid_seniority_weight *fresh =
        zid_seniority_find(weights, wn, (const uint8_t[32]){
            0xB2,0xB2,0xB2,0xB2,0xB2,0xB2,0xB2,0xB2,0xB2,0xB2,0xB2,0xB2,
            0xB2,0xB2,0xB2,0xB2,0xB2,0xB2,0xB2,0xB2,0xB2,0xB2,0xB2,0xB2,
            0xB2,0xB2,0xB2,0xB2,0xB2,0xB2,0xB2,0xB2 });
    ZSB_CHECK("a relay under the anti-Sybil age floor carries exactly 1.0",
              fresh && fresh->multiplier == 1.0);

    struct zendp_record_view views[2];
    zsb_view_v4(&views[0], 0xA1, 7, 8033);   /* the ancient relay's address */
    zsb_view_v4(&views[1], 0xB2, 3, 8033);   /* the fresh relay's address   */

    struct boot_relay_binding bindings[BOOT_RELAY_BINDINGS_MAX];
    size_t bn = boot_relay_bindings_build(views, 2, bindings,
                                          BOOT_RELAY_BINDINGS_MAX);

    uint8_t ip_senior[16], ip_fresh[16], ip_unbound[16];
    zsb_ipv4_mapped(ip_senior, 7);
    zsb_ipv4_mapped(ip_fresh, 3);
    zsb_ipv4_mapped(ip_unbound, 99);

    struct addr_man am;
    addrman_init(&am);
    zsb_addrman_add(&am, ip_senior, 8033);
    zsb_addrman_add(&am, ip_fresh, 8033);
    zsb_addrman_add(&am, ip_unbound, 8033);
    size_t before = addrman_size(&am);

    struct addrman_weight_row rows[8];
    struct boot_seniority_pass pass;
    memset(&pass, 0, sizeof(pass));
    pass.am = &am;
    pass.table = weights;
    pass.table_n = wn;
    pass.bindings = bindings;
    pass.bindings_n = bn;
    pass.rows = rows;
    pass.rows_cap = sizeof(rows) / sizeof(rows[0]);

    /* IDENTICAL banked reputation for all three — zero. Any difference in
     * the outcome is therefore seniority and nothing else. */
    struct peer_reputation rep;
    memset(&rep, 0, sizeof(rep));
    boot_seniority_weigh_address(&pass, ip_senior, 8033, &rep);
    boot_seniority_weigh_address(&pass, ip_fresh, 8033, &rep);
    boot_seniority_weigh_address(&pass, ip_unbound, 8033, &rep);
    ZSB_CHECK("the pass publishes its table as one unit",
              zsb_publish(&am, &pass, 0));

    double w_senior = zsb_weight_of(&am, ip_senior);
    double w_fresh = zsb_weight_of(&am, ip_fresh);
    double w_unbound = zsb_weight_of(&am, ip_unbound);

    printf("zid_seniority_binding:   senior=%.4fx fresh=%.4fx "
           "unbound=%.4fx (seniority score %.4f, mass %.4f)\n",
           w_senior, w_fresh, w_unbound,
           senior ? senior->seniority : 0.0, senior ? senior->mass : 0.0);

    ZSB_CHECK("the bound senior address publishes its seniority multiplier",
              senior && fabs(w_senior - senior->multiplier) < 1e-9 &&
              w_senior > 1.0);
    /* Absent from the published table reads exactly 1.0 — the baseline is a
     * VALUE now, not a sentinel that some reader has to know to interpret. */
    ZSB_CHECK("the fresh relay's address is left on the plain baseline",
              w_fresh == 1.0);
    ZSB_CHECK("an address no record vouches for is left on the baseline",
              w_unbound == 1.0);

    /* The end of the chain: a different published weight is a different DIAL
     * CHANCE, which is what "changes peer selection" means. */
    const struct addr_info *e_senior = zsb_entry_of(&am, ip_senior);
    const struct addr_info *e_unbound = zsb_entry_of(&am, ip_unbound);
    double c_senior = e_senior ? addr_info_get_chance(&am, e_senior, 1000000)
                               : 0.0;
    double c_unbound = e_unbound ? addr_info_get_chance(&am, e_unbound, 1000000)
                                 : 0.0;
    printf("zid_seniority_binding:   dial chance senior=%.4f "
           "unbound=%.4f ratio=%.4f\n", c_senior, c_unbound,
           c_unbound > 0.0 ? c_senior / c_unbound : 0.0);
    ZSB_CHECK("the senior peer's dial chance is strictly higher",
              c_senior > c_unbound);
    ZSB_CHECK("and higher by exactly the published multiplier",
              c_unbound > 0.0 &&
              fabs((c_senior / c_unbound) - w_senior) < 1e-9);

    /* NON-EXCLUSION, asserted on addrman rather than argued from the maths:
     * every address that went in is still there and still selectable. */
    ZSB_CHECK("no address was removed by the weighting pass",
              addrman_size(&am) == before && before == 3);
    ZSB_CHECK("every address is still present after weighting",
              zsb_entry_of(&am, ip_senior) && zsb_entry_of(&am, ip_fresh) &&
              zsb_entry_of(&am, ip_unbound));
    ZSB_CHECK("no address was pushed below the unweighted baseline",
              c_unbound > 0.0 &&
              addr_info_get_chance(&am, zsb_entry_of(&am, ip_fresh),
                                   1000000) == c_unbound);

    addrman_free(&am);
    return failures;
}

/* ── (3) the [1.0, 4.0] clamp, end to end and under hostile input ──── */

static int zsb_case_clamp(void)
{
    int failures = 0;

    /* The arithmetic bound first: no pair of inputs, however absurd, leaves
     * the advisory range. */
    const double probes[] = { -1e300, -1.0, 0.0, 0.5, 1.0, 2.0, 4.0, 4.5,
                              1e9, 1e300 };
    bool in_range = true, monotone = true;
    for (size_t i = 0; i < sizeof(probes) / sizeof(probes[0]); i++) {
        for (size_t j = 0; j < sizeof(probes) / sizeof(probes[0]); j++) {
            double c = zid_seniority_combine(probes[i], probes[j]);
            if (!(c >= 1.0 && c <= ZID_SENIORITY_MAX_MULT))
                in_range = false;
            /* Neither signal can ever be used to pull a peer DOWN. */
            double lo = probes[i] < 1.0 ? 1.0
                      : (probes[i] > ZID_SENIORITY_MAX_MULT
                             ? ZID_SENIORITY_MAX_MULT : probes[i]);
            if (c < lo - 1e-9)
                monotone = false;
        }
    }
    ZSB_CHECK("every combination stays inside [1.0, 4.0]", in_range);
    ZSB_CHECK("neither signal can lower the other", monotone);

    /* Then the same bound where it is actually enforced: an out-of-range
     * weight handed straight to addrman is clamped by the CALLEE, so the
     * ceiling is a property of the API and not of this caller's discipline. */
    uint8_t ip[16];
    zsb_ipv4_mapped(ip, 21);
    struct addr_man am;
    addrman_init(&am);
    zsb_addrman_add(&am, ip, 8033);

    struct addrman_weight_row hostile;
    memcpy(hostile.ip, ip, 16);
    hostile.multiplier = 1e6;
    (void)addrman_publish_reputation_weights(&am, &hostile, 1, 0);
    double capped = zsb_weight_of(&am, ip);
    ZSB_CHECK("addrman clamps an absurd weight to exactly 4.0",
              capped == ADDRMAN_REPUTATION_MAX_MULT);

    hostile.multiplier = -5.0;
    (void)addrman_publish_reputation_weights(&am, &hostile, 1, 0);
    double floored = zsb_weight_of(&am, ip);
    ZSB_CHECK("a negative weight is dropped, leaving exactly 1.0",
              floored == 1.0);
    const struct addr_info *e = zsb_entry_of(&am, ip);
    ZSB_CHECK("a clamped-to-baseline address keeps its plain dial chance",
              e && addr_info_get_chance(&am, e, 1000000) > 0.0);
    ZSB_CHECK("and is still in addrman after the hostile weight",
              addrman_size(&am) == 1);

    /* And the whole pass with a hostile table: an over-quota, undrawable or
     * unknown relay must never produce anything but the baseline. */
    struct zid_seniority_weight weights[1];
    memset(weights, 0, sizeof(weights));
    memset(weights[0].relay_id, 0xA1, 32);
    weights[0].multiplier = 1e9;   /* a table that lies about its own bound */

    struct zendp_record_view v;
    zsb_view_v4(&v, 0xA1, 21, 8033);
    struct boot_relay_binding bindings[BOOT_RELAY_BINDINGS_MAX];
    size_t bn = boot_relay_bindings_build(&v, 1, bindings,
                                          BOOT_RELAY_BINDINGS_MAX);

    struct addrman_weight_row rows[4];
    struct boot_seniority_pass pass;
    memset(&pass, 0, sizeof(pass));
    pass.am = &am;
    pass.table = weights;
    pass.table_n = 1;
    pass.bindings = bindings;
    pass.bindings_n = bn;
    pass.rows = rows;
    pass.rows_cap = sizeof(rows) / sizeof(rows[0]);
    boot_seniority_weigh_address(&pass, ip, 8033, NULL);
    (void)zsb_publish(&am, &pass, 0);
    ZSB_CHECK("a lying seniority table still cannot exceed 4.0",
              zsb_weight_of(&am, ip) == ADDRMAN_REPUTATION_MAX_MULT);

    addrman_free(&am);
    return failures;
}

/* ── (4) the ranking epoch is honoured at runtime ──────────────────── */

static int zsb_case_rotation(void)
{
    int failures = 0;
    const int32_t E = ZID_SENIORITY_EPOCH_BLOCKS;
    int32_t epoch = -1;

    /* Nothing applied yet: the first poll always rebuilds, so a node cannot
     * come up with an empty table and sit on it. */
    ZSB_CHECK("the first poll rebuilds",
              boot_seniority_next_action(0, INT32_MIN, &epoch) ==
                  BOOT_SENIORITY_REBUILD && epoch == 0);

    ZSB_CHECK("mid-epoch polls idle rather than churning connections",
              boot_seniority_next_action(E - 1, 0, &epoch) ==
                  BOOT_SENIORITY_IDLE && epoch == 0);

    ZSB_CHECK("crossing an epoch boundary rebuilds",
              boot_seniority_next_action(E, 0, &epoch) ==
                  BOOT_SENIORITY_REBUILD && epoch == E);

    ZSB_CHECK("the next epoch idles until ITS boundary",
              boot_seniority_next_action(2 * E - 1, E, &epoch) ==
                  BOOT_SENIORITY_IDLE && epoch == E);
    ZSB_CHECK("and rebuilds on it",
              boot_seniority_next_action(2 * E, E, &epoch) ==
                  BOOT_SENIORITY_REBUILD && epoch == 2 * E);

    /* Skipping epochs (a node that was folding, or asleep) still lands on
     * the current epoch rather than replaying the ones it missed. */
    ZSB_CHECK("a jump of many epochs lands on the current one",
              boot_seniority_next_action(100 * E + 5, E, &epoch) ==
                  BOOT_SENIORITY_REBUILD && epoch == 100 * E);

    /* The consequence of rotating: the same relay set re-keyed at a
     * different epoch produces a DIFFERENT favourite, which is the whole
     * point of the rate limit. Same client, two epochs. */
    struct zid_seniority_weight a[2], b[2];
    size_t an = zsb_rank(a, 2, 400000, 0x1111ull);
    size_t bn = zsb_rank(b, 2, 400000, 0x2222ull);
    bool differs = false;
    if (an == 2 && bn == 2) {
        for (size_t i = 0; i < an; i++)
            if (a[i].multiplier != b[i].multiplier)
                differs = true;
    }
    ZSB_CHECK("re-keying the draw moves the multipliers", differs);

    /* Before any rebuild, the applied epoch is the sentinel — a node that
     * has published nothing must never look like one that is up to date. */
    ZSB_CHECK("an unstarted node reports no applied epoch",
              boot_seniority_applied_epoch() == INT32_MIN &&
              boot_seniority_rebuild_count() == 0);

    return failures;
}

/* ── (5) one call per address, never two ───────────────────────────── */

static int zsb_case_one_call(void)
{
    int failures = 0;
    const int32_t tip = 400000;

    struct zid_seniority_weight weights[2];
    size_t wn = zsb_rank(weights, 2, tip, 0xABCDull);

    struct zendp_record_view views[2];
    zsb_view_v4(&views[0], 0xA1, 7, 8033);
    zsb_view_v4(&views[1], 0xB2, 3, 8033);
    struct boot_relay_binding bindings[BOOT_RELAY_BINDINGS_MAX];
    size_t bn = boot_relay_bindings_build(views, 2, bindings,
                                          BOOT_RELAY_BINDINGS_MAX);

    uint8_t ip_senior[16];
    zsb_ipv4_mapped(ip_senior, 7);

    struct addr_man am;
    addrman_init(&am);
    zsb_addrman_add(&am, ip_senior, 8033);

    struct addrman_weight_row rows[8];
    struct boot_seniority_pass pass;
    memset(&pass, 0, sizeof(pass));
    pass.am = &am;
    pass.table = weights;
    pass.table_n = wn;
    pass.bindings = bindings;
    pass.bindings_n = bn;
    pass.rows = rows;
    pass.rows_cap = sizeof(rows) / sizeof(rows[0]);

    /* The reputation feed covers the senior address. */
    struct peer_reputation rep;
    memset(&rep, 0, sizeof(rep));
    boot_seniority_weigh_address(&pass, ip_senior, 8033, &rep);
    size_t after_feed = pass.applied;
    ZSB_CHECK("the reputation feed weighted the bound address",
              after_feed == 1 && pass.boosted == 1);

    /* The sweep that follows must not weigh it again. The second binding
     * (54.18.0.3) is under the anti-Sybil age floor, so it earns nothing and
     * emits no row. */
    size_t swept = boot_seniority_weigh_unseen_bindings(&pass);
    ZSB_CHECK("the directory sweep does not re-issue for a covered address",
              swept == 0 && pass.applied == after_feed);
    ZSB_CHECK("one covered address means exactly one published row",
              pass.rows_n == 1);

    /* A senior relay this node has NEVER dialled — no session row, so the
     * reputation feed never names it at all. Before the sweep existed, the
     * relays most worth reaching were the only ones the boost could not
     * reach. A fresh addrman, no feed pass, sweep only. */
    struct addr_man am2;
    addrman_init(&am2);
    zsb_addrman_add(&am2, ip_senior, 8033);
    ZSB_CHECK("the never-dialled relay starts on the unweighted baseline",
              zsb_weight_of(&am2, ip_senior) == 1.0);

    struct addrman_weight_row rows2[8];
    struct boot_seniority_pass pass2;
    memset(&pass2, 0, sizeof(pass2));
    pass2.am = &am2;
    pass2.table = weights;
    pass2.table_n = wn;
    pass2.bindings = bindings;
    pass2.bindings_n = bn;
    pass2.rows = rows2;
    pass2.rows_cap = sizeof(rows2) / sizeof(rows2[0]);
    size_t reached = boot_seniority_weigh_unseen_bindings(&pass2);
    (void)zsb_publish(&am2, &pass2, 0);
    printf("zid_seniority_binding:   sweep reached %zu address(es), "
           "never-dialled relay now at %.4fx\n",
           reached, zsb_weight_of(&am2, ip_senior));
    ZSB_CHECK("a never-dialled senior relay is still reached by the sweep",
              reached == 1 && zsb_weight_of(&am2, ip_senior) > 1.0);

    addrman_free(&am2);
    addrman_free(&am);
    return failures;
}

int test_zid_seniority_binding(void)
{
    int failures = 0;
    printf("\n=== ZID seniority address binding ===\n");
    failures += zsb_case_binding();
    failures += zsb_case_selection();
    failures += zsb_case_clamp();
    failures += zsb_case_rotation();
    failures += zsb_case_one_call();
    if (failures == 0)
        printf("zid_seniority_binding: all cases passed\n");
    return failures;
}
