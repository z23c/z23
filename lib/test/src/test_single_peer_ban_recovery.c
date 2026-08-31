/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Regression test for the single-peer strand: a node whose ONLY peer is
 * remote (not 127.0.0.0/8) and not whitelisted records one weight-100
 * offence, is correctly banned for it, and must still retain a path back
 * to the network — and must SAY SO rather than going quiet.
 *
 * Scope, and what this file deliberately does not re-test:
 *   - lib/test/src/test_header_sync_stall.c cases 9-10 already pin the
 *     loopback/whitelist exemption seam. Nothing here re-tests exemption;
 *     the peer used below is remote and unwhitelisted precisely so that
 *     the ordinary penalty DOES apply to it.
 *   - lib/test/src/test_peer_scoring.c pins the scoring config surface
 *     (thresholds, weights, decay, env knobs). This file asserts only
 *     OBSERVABLE outcomes of a ban — score, disconnect flag, the ban table
 *     entry, and the typed blocker — and references no symbol introduced
 *     by the fix, so it compiles and runs against the pre-fix tree too.
 *     That is what makes the revert-and-fail proof meaningful.
 *
 * Idiom is copied from test_peer_scoring.c: net_manager and p2p_node are
 * stack-constructed and peer_scoring_record() is called directly. No
 * sockets, no threads except the one deliberate contention case below.
 */

#include "test/test_core.h"
#include "net/peer_scoring.h"
#include "net/net.h"
#include "net/netaddr.h"
#include "core/utiltime.h"
#include "util/blocker.h"
#include "util/sync.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* The id is spelled as a literal, not via the header macro the fix added,
 * so this file still compiles when the fix is reverted. */
#define LAST_PEER_BAN_ID "net.last_peer_ban"

/* An hour. The ordinary ban is 24h; any bounded recovery ban worth the
 * name is far under this, so it separates the two outcomes with a wide
 * margin instead of pinning the fix's exact 600s default (a judgement
 * call, and not this test's business). */
#define RECOVERY_WINDOW_CEILING_SECS 3600

/* ── Fixture helpers ─────────────────────────────────────── */

/* A routable, documentation-range (RFC 5737 TEST-NET-3) address: not
 * loopback, not private, nothing the node would treat as infrastructure. */
static void setup_remote_node(struct p2p_node *node, const char *name,
                              unsigned char last_octet)
{
    memset(node, 0, sizeof(*node));
    snprintf(node->addr_name, sizeof(node->addr_name), "%s", name);
    node->whitelisted = false;
    const unsigned char ip4[4] = { 203, 0, 113, last_octet };
    net_addr_set_ipv4(&node->addr.svc.addr, ip4);
}

static void setup_manager(struct net_manager *nm)
{
    memset(nm, 0, sizeof(*nm));
}

/* Publish borrowed node pointers into the manager's node table, which is
 * what makes "how many peers would a ban leave us" answerable at all. */
static void register_nodes(struct net_manager *nm, struct p2p_node **nodes,
                           size_t count)
{
    /* Match net_manager_init(): zero-filled pthread mutexes are not a
     * portable substitute (Darwin rejects the trylock used by the strand
     * predicate), and production requires recursion. */
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

static int64_t ordinary_ban_secs(void)
{
    return (int64_t)peer_scoring_ban_hours() * 60 * 60;
}

static void reset_scoring_env(void)
{
    unsetenv("ZCL_PEER_BAN_THRESHOLD");
    unsetenv("ZCL_PEER_BAN_HOURS");
    unsetenv("ZCL_PEER_SCORE_DECAY_PER_MIN");
    unsetenv("ZCL_PEER_LAST_PEER_BAN_SECS");
    peer_scoring_init();
}

/* ── 1. The penalty is NOT softened ──────────────────────── */

/* The recovery must not be bought by exempting the peer. A remote,
 * unwhitelisted peer that feeds us an invalid block is still scored to the
 * threshold, still flagged for disconnect, and still lands in the ban
 * table. This is the assertion that distinguishes the shipped fix from the
 * tempting wrong fix (widening is_trusted_peer() to cover -addnode). */
static int test_penalty_is_not_softened(void)
{
    int failures = 0;
    TEST("single_peer_ban_recovery: the only peer is still fully penalised") {
        blocker_reset_for_testing();
        reset_scoring_env();

        struct net_manager nm;
        struct p2p_node node;
        setup_manager(&nm);
        setup_remote_node(&node, "only_peer", 7);
        struct p2p_node *nodes[1] = { &node };
        register_nodes(&nm, nodes, 1);

        /* Premise: this peer earns no exemption from anywhere. */
        ASSERT(!net_addr_is_local(&node.addr.svc.addr));
        ASSERT(!node.whitelisted);

        peer_scoring_record(&nm, &node, PEER_OFFENCE_INVALID_BLOCK,
                            "bad block");

        ASSERT_EQ(atomic_load(&node.misbehavior),
                  peer_scoring_ban_threshold());
        ASSERT(node.disconnect);
        ASSERT_EQ((int)nm.num_banned, 1);
        ASSERT(is_banned(&nm, &node.addr.svc.addr));

        free(nm.banned);
        unregister_nodes(&nm);
        blocker_reset_for_testing();
        PASS();
    } _test_next:;
    return failures;
}

/* ── 2. The path back exists: the ban is a WINDOW ────────── */

/* Teeth. Pre-fix this ban is peer_scoring_ban_hours() (24h) and persists
 * to banlist.dat across restarts, so a single misclassification takes the
 * node off the network for a day with no peer left to correct it. */
static int test_ban_window_is_bounded(void)
{
    int failures = 0;
    TEST("single_peer_ban_recovery: banning our only peer leaves a route back") {
        blocker_reset_for_testing();
        reset_scoring_env();

        struct net_manager nm;
        struct p2p_node node;
        setup_manager(&nm);
        setup_remote_node(&node, "only_peer", 7);
        struct p2p_node *nodes[1] = { &node };
        register_nodes(&nm, nodes, 1);

        int64_t before = GetTime();
        peer_scoring_record(&nm, &node, PEER_OFFENCE_INVALID_BLOCK,
                            "bad block");
        ASSERT_EQ((int)nm.num_banned, 1);

        int64_t window = nm.banned[0].ban_until - before;
        /* A real ban, not an amnesty. */
        ASSERT(window >= 60);
        /* And a bounded one: strictly shorter than the ordinary ban, and
         * short enough that an unattended node recovers on its own. */
        ASSERT(window < ordinary_ban_secs());
        ASSERT(window <= RECOVERY_WINDOW_CEILING_SECS);

        free(nm.banned);
        unregister_nodes(&nm);
        blocker_reset_for_testing();
        PASS();
    } _test_next:;
    return failures;
}

/* The window is a window: once ban_until has passed, is_banned()'s lazy
 * prune drops the entry and the address is dialable again. GetTime() has
 * no test setter, so the deadline is moved into the past rather than the
 * clock forward — this exercises the release mechanism the bounded ban
 * depends on, and would be vacuous on its own; case 2 is what pins the
 * bound itself. */
static int test_window_actually_releases(void)
{
    int failures = 0;
    TEST("single_peer_ban_recovery: the window expires and unbans the peer") {
        blocker_reset_for_testing();
        reset_scoring_env();

        struct net_manager nm;
        struct p2p_node node;
        setup_manager(&nm);
        setup_remote_node(&node, "only_peer", 7);
        struct p2p_node *nodes[1] = { &node };
        register_nodes(&nm, nodes, 1);

        peer_scoring_record(&nm, &node, PEER_OFFENCE_INVALID_BLOCK,
                            "bad block");
        ASSERT_EQ((int)nm.num_banned, 1);
        ASSERT(is_banned(&nm, &node.addr.svc.addr));

        nm.banned[0].ban_until = GetTime() - 1;
        ASSERT(!is_banned(&nm, &node.addr.svc.addr));
        ASSERT_EQ((int)nm.num_banned, 0);

        free(nm.banned);
        unregister_nodes(&nm);
        blocker_reset_for_testing();
        PASS();
    } _test_next:;
    return failures;
}

/* ── 3. It is named out loud ─────────────────────────────── */

/* Teeth. A bounded ban that nobody reports is indistinguishable from a
 * healthy idle node; the whole point is that the node says what happened.
 * Also pins that the reason text carries no volatile data — blocker.h keys
 * fault identity on the reason, so an address or score baked into it would
 * mint a new fault per peer. */
static int test_condition_is_named(void)
{
    int failures = 0;
    TEST("single_peer_ban_recovery: the node raises a typed blocker, not silence") {
        blocker_reset_for_testing();
        reset_scoring_env();

        struct net_manager nm;
        struct p2p_node node;
        setup_manager(&nm);
        setup_remote_node(&node, "only_peer", 7);
        struct p2p_node *nodes[1] = { &node };
        register_nodes(&nm, nodes, 1);

        ASSERT(!blocker_exists(LAST_PEER_BAN_ID));
        peer_scoring_record(&nm, &node, PEER_OFFENCE_INVALID_BLOCK,
                            "bad block");
        ASSERT(blocker_exists(LAST_PEER_BAN_ID));

        struct blocker_snapshot snap;
        ASSERT(blocker_find_by_id_prefix(LAST_PEER_BAN_ID, &snap));
        ASSERT_STR_EQ(snap.id, LAST_PEER_BAN_ID);
        ASSERT_STR_EQ(snap.owner_subsystem, "net");
        /* Transient: a completed handshake clears it. Not PERMANENT — this
         * is a self-healing condition, not one that needs an owner. */
        ASSERT_EQ(snap.class, BLOCKER_TRANSIENT);
        /* An operator-actionable sentence, not a label. */
        ASSERT(strlen(snap.reason) > 40);
        /* Stable identity: no peer address, no score, in the reason. */
        ASSERT(strstr(snap.reason, "203.0.113.7") == NULL);
        ASSERT(strstr(snap.reason, "only_peer") == NULL);

        /* And it is clearable — the fix clears it at the handshake-complete
         * choke point, which is the observable proof the route is back. */
        blocker_clear(LAST_PEER_BAN_ID);
        ASSERT(!blocker_exists(LAST_PEER_BAN_ID));

        free(nm.banned);
        unregister_nodes(&nm);
        blocker_reset_for_testing();
        PASS();
    } _test_next:;
    return failures;
}

/* ── 4. "Last peer" means last LIVE peer ─────────────────── */

/* Teeth, and a case the fix's own tests do not cover: a second peer that
 * is already flagged for disconnect is not a route to anywhere. Counting
 * registered nodes instead of live ones would strand the node exactly when
 * both peers fail at once — the realistic failure, since a bad block from
 * one peer usually arrives while the other is already dropping. */
static int test_dying_second_peer_still_counts_as_stranded(void)
{
    int failures = 0;
    TEST("single_peer_ban_recovery: a disconnect-flagged peer is not a route") {
        blocker_reset_for_testing();
        reset_scoring_env();

        struct net_manager nm;
        struct p2p_node bad, dying;
        setup_manager(&nm);
        setup_remote_node(&bad, "bad_peer", 7);
        setup_remote_node(&dying, "dying_peer", 9);
        dying.disconnect = true;
        struct p2p_node *nodes[2] = { &bad, &dying };
        register_nodes(&nm, nodes, 2);

        int64_t before = GetTime();
        peer_scoring_record(&nm, &bad, PEER_OFFENCE_INVALID_BLOCK,
                            "bad block");

        ASSERT_EQ((int)nm.num_banned, 1);
        ASSERT(nm.banned[0].ban_until - before <= RECOVERY_WINDOW_CEILING_SECS);
        ASSERT(blocker_exists(LAST_PEER_BAN_ID));

        free(nm.banned);
        unregister_nodes(&nm);
        blocker_reset_for_testing();
        PASS();
    } _test_next:;
    return failures;
}

/* Non-regression: with a live second peer the node is not stranded, so the
 * ordinary full-length ban applies and nothing is announced. This case
 * passes before and after the fix by design — it is the guard that the fix
 * did not quietly shorten every ban in the node. */
static int test_live_second_peer_keeps_ordinary_ban(void)
{
    int failures = 0;
    TEST("single_peer_ban_recovery: a live second peer keeps the full ban") {
        blocker_reset_for_testing();
        reset_scoring_env();

        struct net_manager nm;
        struct p2p_node bad, good;
        setup_manager(&nm);
        setup_remote_node(&bad, "bad_peer", 7);
        setup_remote_node(&good, "good_peer", 9);
        struct p2p_node *nodes[2] = { &bad, &good };
        register_nodes(&nm, nodes, 2);

        int64_t before = GetTime();
        peer_scoring_record(&nm, &bad, PEER_OFFENCE_INVALID_BLOCK,
                            "bad block");

        ASSERT_EQ((int)nm.num_banned, 1);
        ASSERT(nm.banned[0].ban_until - before >= ordinary_ban_secs());
        ASSERT(!blocker_exists(LAST_PEER_BAN_ID));

        free(nm.banned);
        unregister_nodes(&nm);
        blocker_reset_for_testing();
        PASS();
    } _test_next:;
    return failures;
}

/* ── 5. The trylock seam, characterised ──────────────────── */

struct cs_nodes_holder {
    struct net_manager *nm;
    atomic_bool held;
    atomic_bool release;
};

static void *hold_cs_nodes(void *arg)
{
    struct cs_nodes_holder *h = arg;
    zcl_mutex_lock(&h->nm->cs_nodes);
    atomic_store(&h->held, true);
    while (!atomic_load(&h->release)) {
        struct timespec ts = { 0, 1000000 }; /* 1 ms */
        nanosleep(&ts, NULL);
    }
    zcl_mutex_unlock(&h->nm->cs_nodes);
    return NULL;
}

/* The strand predicate acquires cs_nodes with trylock, so when ANOTHER
 * thread holds that lock at the instant of the ban the recovery does not
 * engage and the node takes the ordinary 24h ban with no announcement.
 * That is fail-safe (never harsher than before) but it is not
 * deterministic: the same single-peer node gets a 10-minute or a 24-hour
 * outage depending on lock timing. Pinned here so the behaviour is
 * documented rather than discovered later; passes before and after the fix
 * by construction. */
static int test_cs_nodes_contention_falls_back_to_full_ban(void)
{
    int failures = 0;
    TEST("single_peer_ban_recovery: cs_nodes contention falls back to the full ban") {
        blocker_reset_for_testing();
        reset_scoring_env();

        struct net_manager nm;
        struct p2p_node node;
        setup_manager(&nm);
        setup_remote_node(&node, "only_peer", 7);
        struct p2p_node *nodes[1] = { &node };
        register_nodes(&nm, nodes, 1);

        struct cs_nodes_holder holder = { .nm = &nm };
        atomic_init(&holder.held, false);
        atomic_init(&holder.release, false);
        pthread_t tid;
        ASSERT_EQ(pthread_create(&tid, NULL, hold_cs_nodes, &holder), 0);
        while (!atomic_load(&holder.held)) {
            struct timespec ts = { 0, 1000000 };
            nanosleep(&ts, NULL);
        }

        int64_t before = GetTime();
        peer_scoring_record(&nm, &node, PEER_OFFENCE_INVALID_BLOCK,
                            "bad block");

        atomic_store(&holder.release, true);
        pthread_join(tid, NULL);

        ASSERT_EQ((int)nm.num_banned, 1);
        ASSERT(nm.banned[0].ban_until - before >= ordinary_ban_secs());
        ASSERT(!blocker_exists(LAST_PEER_BAN_ID));

        free(nm.banned);
        unregister_nodes(&nm);
        blocker_reset_for_testing();
        PASS();
    } _test_next:;
    return failures;
}

/* The stated reason for that trylock is that a blocking acquire would
 * self-deadlock a caller which already holds cs_nodes (the header-span
 * timeout sweep in msg_headers.c scores peers under the lock). That
 * premise does not hold as written: production initialises cs_nodes with
 * zcl_mutex_init(), which sets PTHREAD_MUTEX_RECURSIVE, so a same-thread
 * re-acquire cannot deadlock — and a same-thread trylock SUCCEEDS, so the
 * msg_headers.c path is not the case the trylock protects. Pinned so that
 * turning zcl_mutex_init() non-recursive, which would make the stated
 * rationale true and the deadlock real, fails here first. */
static int test_cs_nodes_is_recursive(void)
{
    int failures = 0;
    TEST("single_peer_ban_recovery: zcl_mutex_init locks are recursive") {
        zcl_mutex_t m;
        zcl_mutex_init(&m);
        zcl_mutex_lock(&m);
        bool reentered = zcl_mutex_trylock(&m);
        ASSERT(reentered);
        if (reentered)
            zcl_mutex_unlock(&m);
        zcl_mutex_unlock(&m);
        zcl_mutex_destroy(&m);
        PASS();
    } _test_next:;
    return failures;
}

/* ── Entry point ─────────────────────────────────────────── */

int test_single_peer_ban_recovery(void);

int test_single_peer_ban_recovery(void)
{
    int failures = 0;

    printf("\n=== single_peer_ban_recovery ===\n");

    failures += test_penalty_is_not_softened();
    failures += test_ban_window_is_bounded();
    failures += test_window_actually_releases();
    failures += test_condition_is_named();
    failures += test_dying_second_peer_still_counts_as_stranded();
    failures += test_live_second_peer_keeps_ordinary_ban();
    failures += test_cs_nodes_contention_falls_back_to_full_ban();
    failures += test_cs_nodes_is_recursive();

    reset_scoring_env();
    blocker_reset_for_testing();

    return failures;
}
