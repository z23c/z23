/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tests for lib/net/src/peer_scoring.c — the typed offence layer that
 * wraps peer_misbehaving(). Covers config, offence-name lookup, record
 * semantics, is_trusted_peer() guard, decay, reset, should_ban, and
 * env-var overrides.
 */

#include "test/test_core.h"
#include "net/peer_scoring.h"
#include "net/net.h"
#include "core/utiltime.h"
#include "util/blocker.h"

#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

/* ── Fixture helpers ─────────────────────────────────────── */

/* Construct a minimal p2p_node on the stack. peer_misbehaving() only
 * reads node->misbehavior, ->disconnect, ->id, ->addr, ->addr_name, and
 * ->whitelisted on the score path. The ban path also calls ban_addr()
 * which uses nm->banned under nm->cs_banned — we zero the manager and
 * accept that the ban-list path grows via realloc(NULL). */
static void setup_node(struct p2p_node *node, const char *name, bool whitelisted)
{
    memset(node, 0, sizeof(*node));
    snprintf(node->addr_name, sizeof(node->addr_name), "%s", name);
    node->whitelisted = whitelisted;
    /* Make the peer look non-localhost. The IPv4-mapped prefix check in
     * is_trusted_peer() matches bytes 10..12 = {0xff, 0xff, 127}; use
     * 1.2.3.4 to stay clear of it. */
    node->addr.svc.addr.ip[10] = 0xff;
    node->addr.svc.addr.ip[11] = 0xff;
    node->addr.svc.addr.ip[12] = 1;
    node->addr.svc.addr.ip[13] = 2;
    node->addr.svc.addr.ip[14] = 3;
    node->addr.svc.addr.ip[15] = 4;
}

static void setup_localhost(struct p2p_node *node)
{
    memset(node, 0, sizeof(*node));
    snprintf(node->addr_name, sizeof(node->addr_name), "localhost");
    /* IPv4-mapped 127.0.0.1 — matches is_trusted_peer()'s prefix. */
    node->addr.svc.addr.ip[10] = 0xff;
    node->addr.svc.addr.ip[11] = 0xff;
    node->addr.svc.addr.ip[12] = 127;
    node->addr.svc.addr.ip[13] = 0;
    node->addr.svc.addr.ip[14] = 0;
    node->addr.svc.addr.ip[15] = 1;
}

static void setup_manager(struct net_manager *nm)
{
    memset(nm, 0, sizeof(*nm));
    /* cs_banned is touched only if a ban fires. Zero-initialised pthread
     * mutexes behave like PTHREAD_MUTEX_INITIALIZER on glibc. */
}

/* ── Test cases (one TEST per function to avoid label collisions) ── */

static int test_defaults(void)
{
    int failures = 0;
    unsetenv("ZCL_PEER_BAN_THRESHOLD");
    unsetenv("ZCL_PEER_BAN_HOURS");
    unsetenv("ZCL_PEER_SCORE_DECAY_PER_MIN");
    peer_scoring_init();
    TEST("peer_scoring: defaults match historical 100/24h/1") {
        ASSERT_EQ(peer_scoring_ban_threshold(), 100);
        ASSERT_EQ(peer_scoring_ban_hours(), 24);
        ASSERT_EQ(peer_scoring_decay_rate(), 1);
        PASS();
    } _test_next:;
    return failures;
}

static int test_env_overrides(void)
{
    int failures = 0;
    TEST("peer_scoring: env vars override defaults") {
        setenv("ZCL_PEER_BAN_THRESHOLD", "250", 1);
        setenv("ZCL_PEER_BAN_HOURS", "48", 1);
        setenv("ZCL_PEER_SCORE_DECAY_PER_MIN", "5", 1);
        peer_scoring_init();
        ASSERT_EQ(peer_scoring_ban_threshold(), 250);
        ASSERT_EQ(peer_scoring_ban_hours(), 48);
        ASSERT_EQ(peer_scoring_decay_rate(), 5);

        unsetenv("ZCL_PEER_BAN_THRESHOLD");
        unsetenv("ZCL_PEER_BAN_HOURS");
        unsetenv("ZCL_PEER_SCORE_DECAY_PER_MIN");
        peer_scoring_init();
        PASS();
    } _test_next:;
    return failures;
}

static int test_invalid_env(void)
{
    int failures = 0;
    TEST("peer_scoring: invalid env falls back to defaults") {
        setenv("ZCL_PEER_BAN_THRESHOLD", "0", 1);         /* below min */
        setenv("ZCL_PEER_BAN_HOURS", "garbage", 1);
        setenv("ZCL_PEER_SCORE_DECAY_PER_MIN", "-3", 1);  /* below min */
        peer_scoring_init();
        ASSERT_EQ(peer_scoring_ban_threshold(), 100);
        ASSERT_EQ(peer_scoring_ban_hours(), 24);
        ASSERT_EQ(peer_scoring_decay_rate(), 1);

        unsetenv("ZCL_PEER_BAN_THRESHOLD");
        unsetenv("ZCL_PEER_BAN_HOURS");
        unsetenv("ZCL_PEER_SCORE_DECAY_PER_MIN");
        peer_scoring_init();
        PASS();
    } _test_next:;
    return failures;
}

static int test_offence_names(void)
{
    int failures = 0;
    TEST("peer_scoring: offence names are human-readable") {
        ASSERT_STR_EQ(peer_offence_name(PEER_OFFENCE_NONE), "none");
        ASSERT_STR_EQ(peer_offence_name(PEER_OFFENCE_TIMEOUT), "timeout");
        ASSERT_STR_EQ(peer_offence_name(PEER_OFFENCE_INVALID_MESSAGE),
                      "invalid_message");
        ASSERT_STR_EQ(peer_offence_name(PEER_OFFENCE_UNREQUESTED),
                      "unrequested");
        ASSERT_STR_EQ(peer_offence_name(PEER_OFFENCE_OFFER_REJECTED),
                      "offer_rejected");
        ASSERT_STR_EQ(peer_offence_name(PEER_OFFENCE_FLOOD), "flood");
        ASSERT_STR_EQ(peer_offence_name(PEER_OFFENCE_INVALID_PAYLOAD),
                      "invalid_payload");
        ASSERT_STR_EQ(peer_offence_name(PEER_OFFENCE_INVALID_HEADER),
                      "invalid_header");
        ASSERT_STR_EQ(peer_offence_name(PEER_OFFENCE_INVALID_CHUNK),
                      "invalid_chunk");
        ASSERT_STR_EQ(peer_offence_name(PEER_OFFENCE_INVALID_BLOCK),
                      "invalid_block");
        ASSERT_STR_EQ(peer_offence_name(PEER_OFFENCE_INVALID_PROOF),
                      "invalid_proof");
        ASSERT_STR_EQ(peer_offence_name(PEER_OFFENCE_PROTOCOL_VIOLATION),
                      "protocol_violation");
        PASS();
    } _test_next:;
    return failures;
}

static int test_offence_weights(void)
{
    int failures = 0;
    TEST("peer_scoring: weight table preserves the legacy DoS weights") {
        ASSERT_EQ(peer_offence_weight(PEER_OFFENCE_NONE), 0);
        ASSERT_EQ(peer_offence_weight(PEER_OFFENCE_TIMEOUT), 5);
        ASSERT_EQ(peer_offence_weight(PEER_OFFENCE_INVALID_MESSAGE), 10);
        ASSERT_EQ(peer_offence_weight(PEER_OFFENCE_UNREQUESTED), 10);
        ASSERT_EQ(peer_offence_weight(PEER_OFFENCE_OFFER_REJECTED), 10);
        ASSERT_EQ(peer_offence_weight(PEER_OFFENCE_FLOOD), 20);
        ASSERT_EQ(peer_offence_weight(PEER_OFFENCE_INVALID_PAYLOAD), 20);
        ASSERT_EQ(peer_offence_weight(PEER_OFFENCE_INVALID_HEADER), 50);
        ASSERT_EQ(peer_offence_weight(PEER_OFFENCE_INVALID_CHUNK), 50);
        ASSERT_EQ(peer_offence_weight(PEER_OFFENCE_INVALID_BLOCK), 100);
        ASSERT_EQ(peer_offence_weight(PEER_OFFENCE_INVALID_PROOF), 100);
        ASSERT_EQ(peer_offence_weight(PEER_OFFENCE_PROTOCOL_VIOLATION), 100);
        PASS();
    } _test_next:;
    return failures;
}

static int test_record_increments(void)
{
    int failures = 0;
    TEST("peer_scoring: record increments by offence weight") {
        struct net_manager nm;
        struct p2p_node node;
        setup_manager(&nm);
        setup_node(&node, "test_peer_5", false);

        peer_scoring_record(&nm, &node, PEER_OFFENCE_INVALID_MESSAGE, "ctx");
        ASSERT_EQ(atomic_load(&node.misbehavior), 10);
        peer_scoring_record(&nm, &node, PEER_OFFENCE_TIMEOUT, "ctx");
        ASSERT_EQ(atomic_load(&node.misbehavior), 15);
        peer_scoring_record(&nm, &node, PEER_OFFENCE_INVALID_HEADER, "ctx");
        ASSERT_EQ(atomic_load(&node.misbehavior), 65);
        PASS();
    } _test_next:;
    return failures;
}

static int test_none_noop(void)
{
    int failures = 0;
    TEST("peer_scoring: NONE offence is a no-op") {
        struct net_manager nm;
        struct p2p_node node;
        setup_manager(&nm);
        setup_node(&node, "test_peer_none", false);

        peer_scoring_record(&nm, &node, PEER_OFFENCE_NONE, "no-op");
        ASSERT_EQ(atomic_load(&node.misbehavior), 0);
        ASSERT(!node.disconnect);
        PASS();
    } _test_next:;
    return failures;
}

static int test_autoban_single_hit(void)
{
    int failures = 0;
    TEST("peer_scoring: INVALID_BLOCK auto-bans at 100") {
        struct net_manager nm;
        struct p2p_node node;
        setup_manager(&nm);
        setup_node(&node, "test_peer_autoban", false);

        peer_scoring_record(&nm, &node, PEER_OFFENCE_INVALID_BLOCK, "bad");
        ASSERT_EQ(atomic_load(&node.misbehavior), 100);
        ASSERT(node.disconnect);
        ASSERT(peer_scoring_should_ban(&node));
        free(nm.banned);
        PASS();
    } _test_next:;
    return failures;
}

static int test_accumulated_hits(void)
{
    int failures = 0;
    TEST("peer_scoring: small hits accumulate to ban") {
        struct net_manager nm;
        struct p2p_node node;
        setup_manager(&nm);
        setup_node(&node, "test_peer_accum", false);

        /* 5 × FLOOD(20) = 100 → banned */
        for (int i = 0; i < 5; i++)
            peer_scoring_record(&nm, &node, PEER_OFFENCE_FLOOD, "spam");
        ASSERT_EQ(atomic_load(&node.misbehavior), 100);
        ASSERT(node.disconnect);
        free(nm.banned);
        PASS();
    } _test_next:;
    return failures;
}

static int test_localhost_exempt(void)
{
    int failures = 0;
    TEST("peer_scoring: localhost peers are exempt") {
        struct net_manager nm;
        struct p2p_node node;
        setup_manager(&nm);
        setup_localhost(&node);
        /* No hidden-service P2P route installed, so a loopback source is
         * still evidence of a same-host peer — see the onion-ingress tests
         * below for what happens once Tor is forwarding to this listener. */
        net_set_onion_ingress_port(0);

        for (int i = 0; i < 10; i++)
            peer_scoring_record(&nm, &node, PEER_OFFENCE_INVALID_BLOCK, "bad");
        /* is_trusted_peer() short-circuits before increment. */
        ASSERT_EQ(atomic_load(&node.misbehavior), 0);
        ASSERT(!node.disconnect);
        ASSERT(!peer_scoring_should_ban(&node));
        PASS();
    } _test_next:;
    return failures;
}

/* LANE C REGRESSION — an onion-reachable node sees EVERY inbound peer as
 * 127.0.0.1, because stock Tor forwards hidden-service streams to the local
 * listener as an ordinary TCP connection from loopback. While a loopback
 * source bought a blanket trusted-peer exemption, that exemption covered
 * every inbound peer such a node has, and every DoS defence that ends in
 * peer_scoring_record() was a no-op against all of them.
 *
 * The two halves of the fix are asserted together here because either one
 * alone is wrong: score the peer but keep banning by ADDRESS and the first
 * offender takes the node's whole front door with it (127.0.0.1 on the ban
 * list is checked at accept(), before any bytes, and persists in
 * banlist.dat); skip the address ban but keep the exemption and nothing is
 * ever punished at all. */
static int test_onion_ingress_scored_never_self_banned(void)
{
    int failures = 0;
    unsetenv("ZCL_PEER_BAN_THRESHOLD");
    unsetenv("ZCL_PEER_BAN_HOURS");
    peer_scoring_init();

    TEST("peer_scoring: Tor-forwarded inbound is scored but never address-banned") {
        struct net_manager nm;
        struct p2p_node node;
        setup_manager(&nm);
        setup_localhost(&node);
        node.inbound = true;
        node.accepted_local_port = 8033;

        /* No hidden-service route installed: loopback still means
         * same-host, and the peer keeps the exemption. This is the
         * pre-change behaviour, and it is the behaviour every local
         * multi-node fixture depends on. */
        net_set_onion_ingress_port(0);
        ASSERT(!net_peer_is_onion_ingress(&node));
        for (int i = 0; i < 10; i++)
            peer_scoring_record(&nm, &node, PEER_OFFENCE_INVALID_BLOCK, "bad");
        ASSERT_EQ(atomic_load(&node.misbehavior), 0);
        ASSERT(!node.disconnect);
        ASSERT_EQ((int)nm.num_banned, 0);

        /* Arm the hidden-service P2P route on the listener that accepted
         * this stream. The same sixteen address bytes are now an anonymous
         * stranger, and one invalid block must cost it the session. */
        net_set_onion_ingress_port(8033);
        ASSERT(net_peer_is_onion_ingress(&node));
        peer_scoring_record(&nm, &node, PEER_OFFENCE_INVALID_BLOCK, "bad");
        ASSERT_EQ(atomic_load(&node.misbehavior), 100);
        ASSERT(node.disconnect);
        ASSERT(peer_scoring_should_ban(&node));

        /* ...and the ban list must still be EMPTY. Banning 127.0.0.1 would
         * refuse every future inbound peer on an onion-only node. */
        ASSERT_EQ((int)nm.num_banned, 0);

        net_set_onion_ingress_port(0);
        free(nm.banned);
        PASS();
    } _test_next:;
    return failures;
}

/* The ingress arming is NARROW: it re-arms scoring only for an inbound
 * loopback peer accepted on the exact listener Tor forwards to. An outbound
 * loopback dial, a peer accepted on some other listener, and a whitelisted
 * peer all keep the exemption. */
static int test_onion_ingress_is_narrow(void)
{
    int failures = 0;
    TEST("peer_scoring: onion-ingress exemption removal is narrowly scoped") {
        struct net_manager nm;
        struct p2p_node node;
        net_set_onion_ingress_port(8033);

        /* Outbound dial to a loopback peer — we chose it, Tor did not
         * hand it to us. Still exempt. */
        setup_manager(&nm);
        setup_localhost(&node);
        node.inbound = false;
        node.accepted_local_port = 8033;
        ASSERT(!net_peer_is_onion_ingress(&node));
        peer_scoring_record(&nm, &node, PEER_OFFENCE_INVALID_BLOCK, "bad");
        ASSERT_EQ(atomic_load(&node.misbehavior), 0);

        /* Inbound on a DIFFERENT listener than the forwarded one. */
        setup_manager(&nm);
        setup_localhost(&node);
        node.inbound = true;
        node.accepted_local_port = 18033;
        ASSERT(!net_peer_is_onion_ingress(&node));
        peer_scoring_record(&nm, &node, PEER_OFFENCE_INVALID_BLOCK, "bad");
        ASSERT_EQ(atomic_load(&node.misbehavior), 0);

        /* Whitelisting the listener is the operator's explicit escape for
         * a host that genuinely runs several nodes. */
        setup_manager(&nm);
        setup_localhost(&node);
        node.inbound = true;
        node.accepted_local_port = 8033;
        node.whitelisted = true;
        peer_scoring_record(&nm, &node, PEER_OFFENCE_INVALID_BLOCK, "bad");
        ASSERT_EQ(atomic_load(&node.misbehavior), 0);
        ASSERT(!node.disconnect);

        net_set_onion_ingress_port(0);
        PASS();
    } _test_next:;
    return failures;
}

/* Counterpart to the two above: a ROUTABLE peer's address is its own, so
 * banning it punishes only the offender and the address ban still fires. */
static int test_routable_peer_still_address_banned(void)
{
    int failures = 0;
    TEST("peer_scoring: a routable offender still earns a real address ban") {
        struct net_manager nm;
        struct p2p_node node;
        setup_manager(&nm);
        setup_node(&node, "test_peer_addrban", false);

        peer_scoring_record(&nm, &node, PEER_OFFENCE_INVALID_BLOCK, "bad");
        ASSERT_EQ(atomic_load(&node.misbehavior), 100);
        ASSERT(node.disconnect);
        ASSERT_EQ((int)nm.num_banned, 1);
        free(nm.banned);
        PASS();
    } _test_next:;
    return failures;
}

static int test_whitelist_exempt(void)
{
    int failures = 0;
    TEST("peer_scoring: whitelisted peers are exempt") {
        struct net_manager nm;
        struct p2p_node node;
        setup_manager(&nm);
        setup_node(&node, "test_peer_wl", true);

        peer_scoring_record(&nm, &node, PEER_OFFENCE_INVALID_BLOCK, "bad");
        peer_scoring_record(&nm, &node, PEER_OFFENCE_INVALID_BLOCK, "bad");
        ASSERT_EQ(atomic_load(&node.misbehavior), 0);
        ASSERT(!node.disconnect);
        PASS();
    } _test_next:;
    return failures;
}

static int test_linear_decay(void)
{
    int failures = 0;
    TEST("peer_scoring: linear decay subtracts rate × minutes") {
        struct net_manager nm;
        struct p2p_node node;
        setup_manager(&nm);
        setup_node(&node, "test_peer_decay", false);

        peer_scoring_record(&nm, &node, PEER_OFFENCE_INVALID_HEADER, "ctx");
        ASSERT_EQ(atomic_load(&node.misbehavior), 50);

        /* First decay call primes the anchor without awarding decay. */
        int64_t t0 = 1000000000LL * 1000;
        peer_scoring_decay(&node, t0);
        ASSERT_EQ(atomic_load(&node.misbehavior), 50);

        /* 10 minutes later at default rate 1: should drop by 10. */
        int post = peer_scoring_decay(&node, t0 + 10 * 60 * 1000);
        ASSERT_EQ(post, 40);
        ASSERT_EQ(atomic_load(&node.misbehavior), 40);
        PASS();
    } _test_next:;
    return failures;
}

static int test_decay_floors_zero(void)
{
    int failures = 0;
    TEST("peer_scoring: decay floors at zero") {
        struct net_manager nm;
        struct p2p_node node;
        setup_manager(&nm);
        setup_node(&node, "test_peer_floor", false);

        peer_scoring_record(&nm, &node, PEER_OFFENCE_INVALID_MESSAGE, "x");
        ASSERT_EQ(atomic_load(&node.misbehavior), 10);

        int64_t t0 = 2000000000LL * 1000;
        peer_scoring_decay(&node, t0);
        int post = peer_scoring_decay(&node, t0 + 60 * 60 * 1000);
        ASSERT_EQ(post, 0);
        PASS();
    } _test_next:;
    return failures;
}

static int test_sub_minute_decay(void)
{
    int failures = 0;
    TEST("peer_scoring: sub-minute decay preserves anchor") {
        struct net_manager nm;
        struct p2p_node node;
        setup_manager(&nm);
        setup_node(&node, "test_peer_sub", false);

        peer_scoring_record(&nm, &node, PEER_OFFENCE_INVALID_HEADER, "x");
        int64_t t0 = 1700000000LL * 1000;
        peer_scoring_decay(&node, t0);

        /* 30s later → still below one minute; no decay and anchor stays. */
        peer_scoring_decay(&node, t0 + 30 * 1000);
        ASSERT_EQ(atomic_load(&node.misbehavior), 50);

        /* Another 30s → 60s from the original anchor → one point drop. */
        int post = peer_scoring_decay(&node, t0 + 60 * 1000);
        ASSERT_EQ(post, 49);
        PASS();
    } _test_next:;
    return failures;
}

static int test_reset(void)
{
    int failures = 0;
    TEST("peer_scoring: reset zeroes the score") {
        struct net_manager nm;
        struct p2p_node node;
        setup_manager(&nm);
        setup_node(&node, "test_peer_reset", false);

        peer_scoring_record(&nm, &node, PEER_OFFENCE_FLOOD, "x");
        peer_scoring_record(&nm, &node, PEER_OFFENCE_FLOOD, "x");
        ASSERT_EQ(atomic_load(&node.misbehavior), 40);

        peer_scoring_reset(&node);
        ASSERT_EQ(atomic_load(&node.misbehavior), 0);
        ASSERT(!peer_scoring_should_ban(&node));
        PASS();
    } _test_next:;
    return failures;
}

static int test_should_ban_pure(void)
{
    int failures = 0;
    TEST("peer_scoring: should_ban does not mutate") {
        struct net_manager nm;
        struct p2p_node node;
        setup_manager(&nm);
        setup_node(&node, "test_peer_pure", false);

        peer_scoring_record(&nm, &node, PEER_OFFENCE_FLOOD, "x");
        int before = atomic_load(&node.misbehavior);
        bool banned = peer_scoring_should_ban(&node);
        int after = atomic_load(&node.misbehavior);
        ASSERT_EQ(before, after);
        ASSERT(!banned); /* 20 < 100 */
        PASS();
    } _test_next:;
    return failures;
}

static int test_custom_threshold(void)
{
    int failures = 0;
    TEST("peer_scoring: custom threshold bans earlier") {
        setenv("ZCL_PEER_BAN_THRESHOLD", "30", 1);
        peer_scoring_init();

        struct net_manager nm;
        struct p2p_node node;
        setup_manager(&nm);
        setup_node(&node, "test_peer_custom", false);

        peer_scoring_record(&nm, &node, PEER_OFFENCE_FLOOD, "x");  /* 20 */
        ASSERT(!node.disconnect);
        peer_scoring_record(&nm, &node, PEER_OFFENCE_FLOOD, "x");  /* 40, past 30 */
        ASSERT(node.disconnect);
        ASSERT(peer_scoring_should_ban(&node));
        free(nm.banned);

        unsetenv("ZCL_PEER_BAN_THRESHOLD");
        peer_scoring_init();
        PASS();
    } _test_next:;
    return failures;
}

static int test_good_interaction(void)
{
    int failures = 0;
    TEST("peer_scoring: well-behaved peer stays at zero") {
        struct net_manager nm;
        struct p2p_node node;
        setup_manager(&nm);
        setup_node(&node, "test_peer_good", false);

        int64_t t0 = 1800000000LL * 1000;
        for (int i = 0; i < 50; i++)
            peer_scoring_on_good_interaction(&node, t0 + i * 60 * 1000);
        ASSERT_EQ(atomic_load(&node.misbehavior), 0);
        PASS();
    } _test_next:;
    return failures;
}

static int test_decay_disabled(void)
{
    int failures = 0;
    TEST("peer_scoring: decay=0 leaves score alone") {
        setenv("ZCL_PEER_SCORE_DECAY_PER_MIN", "0", 1);
        peer_scoring_init();

        struct net_manager nm;
        struct p2p_node node;
        setup_manager(&nm);
        setup_node(&node, "test_peer_disabled", false);

        peer_scoring_record(&nm, &node, PEER_OFFENCE_INVALID_HEADER, "x");
        int64_t t0 = 1900000000LL * 1000;
        peer_scoring_decay(&node, t0);
        peer_scoring_decay(&node, t0 + 10 * 60 * 1000);
        ASSERT_EQ(atomic_load(&node.misbehavior), 50);

        unsetenv("ZCL_PEER_SCORE_DECAY_PER_MIN");
        peer_scoring_init();
        PASS();
    } _test_next:;
    return failures;
}

/* ── Admission cap + last-peer recovery ────────────────── */

static int test_inbound_cap_config(void)
{
    int failures = 0;
    TEST("peer_scoring: per-IP inbound cap defaults to 3 and honours env") {
        unsetenv("ZCL_PEER_MAX_INBOUND_PER_IP");
        peer_scoring_init();
        ASSERT_EQ(peer_scoring_max_inbound_per_ip(), 3);

        setenv("ZCL_PEER_MAX_INBOUND_PER_IP", "16", 1);
        peer_scoring_init();
        ASSERT_EQ(peer_scoring_max_inbound_per_ip(), 16);

        /* 0 would refuse every inbound peer — clamp back to the default
         * rather than honour a value that silently disables listening. */
        setenv("ZCL_PEER_MAX_INBOUND_PER_IP", "0", 1);
        peer_scoring_init();
        ASSERT_EQ(peer_scoring_max_inbound_per_ip(), 3);

        setenv("ZCL_PEER_MAX_INBOUND_PER_IP", "garbage", 1);
        peer_scoring_init();
        ASSERT_EQ(peer_scoring_max_inbound_per_ip(), 3);

        unsetenv("ZCL_PEER_MAX_INBOUND_PER_IP");
        peer_scoring_init();
        PASS();
    } _test_next:;
    return failures;
}

/* F2 REGRESSION — the loopback relaxation is a RAISED cap, never an
 * unlimited one, and it can never take more than a quarter of inbound
 * capacity. Stock settings are 125 total connections minus 8 reserved
 * outbound = 117 inbound slots; the numbers below are asserted as exact
 * slot counts out of that 117, because "the code path exists" is not the
 * property that matters here — the numeric ceiling is. */
static int test_loopback_inbound_ceiling(void)
{
    int failures = 0;
    TEST("peer_scoring: loopback inbound ceiling is bounded at 24 of 117") {
        const int max_inbound = 117;   /* 125 - 8 reserved outbound */

        unsetenv("ZCL_NET_LOOPBACK_INBOUND_MAX");
        ASSERT_EQ(peer_scoring_max_inbound_loopback(max_inbound), 24);

        /* At least three quarters of inbound capacity is reserved for
         * non-loopback peers no matter what the operator asks for. */
        ASSERT(max_inbound -
                    peer_scoring_max_inbound_loopback(max_inbound) >= 93);

        /* An operator can raise it, but only up to the hard floor:
         * 117 - (3*117)/4 = 117 - 87 = 30. */
        setenv("ZCL_NET_LOOPBACK_INBOUND_MAX", "4096", 1);
        ASSERT_EQ(peer_scoring_max_inbound_loopback(max_inbound), 30);
        ASSERT(peer_scoring_max_inbound_loopback(max_inbound)
                    < max_inbound);

        setenv("ZCL_NET_LOOPBACK_INBOUND_MAX", "8", 1);
        ASSERT_EQ(peer_scoring_max_inbound_loopback(max_inbound), 8);

        /* 0 restores the pre-exemption behaviour: no raised cap at all. */
        setenv("ZCL_NET_LOOPBACK_INBOUND_MAX", "0", 1);
        ASSERT_EQ(peer_scoring_max_inbound_loopback(max_inbound), 0);

        setenv("ZCL_NET_LOOPBACK_INBOUND_MAX", "garbage", 1);
        ASSERT_EQ(peer_scoring_max_inbound_loopback(max_inbound), 24);

        unsetenv("ZCL_NET_LOOPBACK_INBOUND_MAX");
        ASSERT_EQ(peer_scoring_max_inbound_loopback(0), 0);
        ASSERT_EQ(peer_scoring_max_inbound_loopback(-1), 0);
        /* Tiny capacity: the floor dominates, loopback gets almost none. */
        ASSERT_EQ(peer_scoring_max_inbound_loopback(4), 1);
        PASS();
    } _test_next:;
    return failures;
}

static int test_last_peer_ban_secs_config(void)
{
    int failures = 0;
    TEST("peer_scoring: last-peer ban seconds default 600, clamped to <=24h") {
        unsetenv("ZCL_PEER_LAST_PEER_BAN_SECS");
        peer_scoring_init();
        ASSERT_EQ(peer_scoring_last_peer_ban_secs(), 600);

        setenv("ZCL_PEER_LAST_PEER_BAN_SECS", "120", 1);
        peer_scoring_init();
        ASSERT_EQ(peer_scoring_last_peer_ban_secs(), 120);

        /* Above the 24h ceiling: the recovery ban must never be able to be
         * HARSHER than the ordinary ban, so fall back to the default. */
        setenv("ZCL_PEER_LAST_PEER_BAN_SECS", "999999", 1);
        peer_scoring_init();
        ASSERT_EQ(peer_scoring_last_peer_ban_secs(), 600);

        /* Below the 60s floor — a sub-minute "ban" is not a ban. */
        setenv("ZCL_PEER_LAST_PEER_BAN_SECS", "5", 1);
        peer_scoring_init();
        ASSERT_EQ(peer_scoring_last_peer_ban_secs(), 600);

        unsetenv("ZCL_PEER_LAST_PEER_BAN_SECS");
        peer_scoring_init();
        PASS();
    } _test_next:;
    return failures;
}

/* Register `node` in `nm->nodes` so peer_misbehaving() can see how many
 * peers a ban would leave behind. Borrowed pointers — the caller owns the
 * array and the nodes. */
static void register_nodes(struct net_manager *nm, struct p2p_node **nodes,
                           size_t count)
{
    /* Production always constructs this recursive mutex in
     * net_manager_init(). A zero-filled pthread mutex happens to tolerate
     * trylock on some libc implementations, but Darwin correctly gives no
     * such portable guarantee. Exercise the production lock contract. */
    zcl_mutex_init(&nm->cs_nodes);
    nm->nodes = nodes;
    nm->num_nodes = count;
    nm->nodes_cap = count;
}

static void unregister_nodes(struct net_manager *nm)
{
    nm->nodes = NULL;
    nm->num_nodes = 0;
    nm->nodes_cap = 0;
    zcl_mutex_destroy(&nm->cs_nodes);
}

static int test_last_peer_ban_is_bounded(void)
{
    int failures = 0;
    TEST("peer_scoring: banning our ONLY peer applies a bounded recovery ban") {
        blocker_reset_for_testing();
        unsetenv("ZCL_PEER_LAST_PEER_BAN_SECS");
        unsetenv("ZCL_PEER_BAN_HOURS");
        peer_scoring_init();

        struct net_manager nm;
        struct p2p_node node;
        setup_manager(&nm);
        setup_node(&node, "only_peer", false);
        struct p2p_node *nodes[1] = { &node };
        register_nodes(&nm, nodes, 1);

        int64_t before = GetTime();
        peer_scoring_record(&nm, &node, PEER_OFFENCE_INVALID_BLOCK, "bad block");

        /* Still scored, still disconnected — the DoS defence is intact. */
        ASSERT_EQ(atomic_load(&node.misbehavior), 100);
        ASSERT(node.disconnect);
        /* Still BANNED — only the duration is bounded. */
        ASSERT_EQ((int)nm.num_banned, 1);
        int64_t until = nm.banned[0].ban_until;
        ASSERT(until > before);
        ASSERT(until <= before + 600 + 5);
        /* And it SAYS SO via the typed blocker mechanism. */
        ASSERT(blocker_exists("net.last_peer_ban"));

        free(nm.banned);
        unregister_nodes(&nm);
        blocker_reset_for_testing();
        PASS();
    } _test_next:;
    return failures;
}

static int test_second_peer_keeps_full_ban(void)
{
    int failures = 0;
    TEST("peer_scoring: with a second peer connected the ban stays full-length") {
        blocker_reset_for_testing();
        unsetenv("ZCL_PEER_LAST_PEER_BAN_SECS");
        unsetenv("ZCL_PEER_BAN_HOURS");
        peer_scoring_init();

        struct net_manager nm;
        struct p2p_node bad, good;
        setup_manager(&nm);
        setup_node(&bad, "bad_peer", false);
        setup_node(&good, "good_peer", false);
        good.addr.svc.addr.ip[15] = 9;   /* a distinct address */
        struct p2p_node *nodes[2] = { &bad, &good };
        register_nodes(&nm, nodes, 2);

        int64_t before = GetTime();
        peer_scoring_record(&nm, &bad, PEER_OFFENCE_INVALID_BLOCK, "bad block");

        ASSERT_EQ((int)nm.num_banned, 1);
        /* Full 24h, byte-identical to pre-change behaviour. */
        ASSERT(nm.banned[0].ban_until >= before + 24 * 60 * 60);
        ASSERT(!(blocker_exists("net.last_peer_ban")));

        free(nm.banned);
        unregister_nodes(&nm);
        blocker_reset_for_testing();
        PASS();
    } _test_next:;
    return failures;
}

static int test_unregistered_node_keeps_full_ban(void)
{
    int failures = 0;
    TEST("peer_scoring: an unregistered node takes the ordinary ban path") {
        blocker_reset_for_testing();
        unsetenv("ZCL_PEER_LAST_PEER_BAN_SECS");
        unsetenv("ZCL_PEER_BAN_HOURS");
        peer_scoring_init();

        /* nm->nodes is empty: the node was never published to the manager,
         * so "this is our last peer" is not something we can conclude. */
        struct net_manager nm;
        struct p2p_node node;
        setup_manager(&nm);
        setup_node(&node, "detached_peer", false);

        int64_t before = GetTime();
        peer_scoring_record(&nm, &node, PEER_OFFENCE_INVALID_BLOCK, "bad block");

        ASSERT_EQ((int)nm.num_banned, 1);
        ASSERT(nm.banned[0].ban_until >= before + 24 * 60 * 60);
        ASSERT(!(blocker_exists("net.last_peer_ban")));

        free(nm.banned);
        blocker_reset_for_testing();
        PASS();
    } _test_next:;
    return failures;
}

/* ── Entry point ───────────────────────────────────────── */

int test_peer_scoring(void);

int test_peer_scoring(void)
{
    int failures = 0;

    printf("\n=== peer_scoring ===\n");

    /* Snapshot env so test_peer_scoring doesn't leak config to suites
     * that run after it. */
    const char *orig_threshold = getenv("ZCL_PEER_BAN_THRESHOLD");
    const char *orig_hours = getenv("ZCL_PEER_BAN_HOURS");
    const char *orig_decay = getenv("ZCL_PEER_SCORE_DECAY_PER_MIN");
    char *saved_threshold = orig_threshold ? strdup(orig_threshold) : NULL;
    char *saved_hours = orig_hours ? strdup(orig_hours) : NULL;
    char *saved_decay = orig_decay ? strdup(orig_decay) : NULL;

    failures += test_defaults();
    failures += test_env_overrides();
    failures += test_invalid_env();
    failures += test_offence_names();
    failures += test_offence_weights();
    failures += test_record_increments();
    failures += test_none_noop();
    failures += test_autoban_single_hit();
    failures += test_accumulated_hits();
    failures += test_localhost_exempt();
    failures += test_onion_ingress_scored_never_self_banned();
    failures += test_onion_ingress_is_narrow();
    failures += test_routable_peer_still_address_banned();
    failures += test_whitelist_exempt();
    failures += test_linear_decay();
    failures += test_decay_floors_zero();
    failures += test_sub_minute_decay();
    failures += test_reset();
    failures += test_should_ban_pure();
    failures += test_custom_threshold();
    failures += test_good_interaction();
    failures += test_decay_disabled();
    failures += test_inbound_cap_config();
    failures += test_loopback_inbound_ceiling();
    failures += test_last_peer_ban_secs_config();
    failures += test_last_peer_ban_is_bounded();
    failures += test_second_peer_keeps_full_ban();
    failures += test_unregistered_node_keeps_full_ban();

    /* Restore env so other suites see the same state they started with. */
    if (saved_threshold) {
        setenv("ZCL_PEER_BAN_THRESHOLD", saved_threshold, 1);
        free(saved_threshold);
    } else {
        unsetenv("ZCL_PEER_BAN_THRESHOLD");
    }
    if (saved_hours) {
        setenv("ZCL_PEER_BAN_HOURS", saved_hours, 1);
        free(saved_hours);
    } else {
        unsetenv("ZCL_PEER_BAN_HOURS");
    }
    if (saved_decay) {
        setenv("ZCL_PEER_SCORE_DECAY_PER_MIN", saved_decay, 1);
        free(saved_decay);
    } else {
        unsetenv("ZCL_PEER_SCORE_DECAY_PER_MIN");
    }
    peer_scoring_init();

    return failures;
}
