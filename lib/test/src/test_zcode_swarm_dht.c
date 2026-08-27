/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The boot-level swarm-DHT discovery bridge (config/src/boot_zcode_swarm_dht.c)
 * driven against a real engine with scripted begin/poll/route outcomes.
 * Covers: inertness before hosting registers an engine; one lease per
 * stalled root completing into an applied offer; the enroll-wait window;
 * and no spin-rebegin on an unhelpful outcome. */

#include "config/boot_zcode_swarm_dht.h"
#include "test/test_core.h"
#include "vcs/package_store.h"
#include "vcs/package_swarm_node.h"
#include "vcs/zcode_dht_service.h"

#include <string.h>

/* ── scripted ops ─────────────────────────────────────────────────── */

struct fake_ops {
    struct boot_zcode_swarm_dht_ops ops;
    unsigned begins, polls, routes;
    int poll_state;
    bool complete_every_poll;
    bool begin_ok;
    uint64_t route_peer;
    uint64_t route_expiry;
    bool route_has_peer;
};

static bool fake_begin(void *ctx, const uint8_t root[32], uint64_t now_mono,
                       uint64_t *operation_id, uint64_t *generation)
{
    struct fake_ops *f = ctx;
    (void)root;
    (void)now_mono;
    f->begins++;
    if (!f->begin_ok)
        return false;
    *operation_id = f->begins;
    *generation = 1;
    return true;
}

static int fake_poll(void *ctx, uint64_t operation_id, uint64_t generation,
                     uint64_t now_mono)
{
    struct fake_ops *f = ctx;
    (void)operation_id;
    (void)generation;
    (void)now_mono;
    f->polls++;
    return f->complete_every_poll ? f->poll_state
                                  : VCS_ZCODE_DHT_RECORD_OPERATION_PENDING;
}

static bool fake_route(void *ctx, const uint8_t root[32], uint64_t now_mono,
                       uint64_t *known_peer_ids, uint64_t *expires_at, size_t max,
                       size_t *count_out)
{
    struct fake_ops *f = ctx;
    (void)root;
    (void)now_mono;
    f->routes++;
    if (!f->route_has_peer || max == 0) {
        *count_out = 0;
        return false;
    }
    known_peer_ids[0] = f->route_peer;
    expires_at[0] = f->route_expiry ? f->route_expiry : UINT64_MAX;
    *count_out = 1;
    return true;
}

/* Engine over a fresh empty package store (no book — accounting
 * skipped): enough for fetch registration plus unadvertised_roots,
 * peer_known and peer_offer. No manifest exists here because nothing
 * is served; that mirrors a requester before its first WANT lands. */
static char g_fixture_dir[512];
static struct vcs_package_store *g_fixture_store;

static struct vcs_swarm_engine *fixture_engine(const char *tag)
{
    test_make_tmpdir(g_fixture_dir, sizeof(g_fixture_dir),
                     "zcode_swarm_dht", tag);
    g_fixture_store = vcs_package_store_open(
        g_fixture_dir, VCS_PACKAGE_STORE_DEFAULT_QUOTA_BYTES);
    if (!g_fixture_store)
        return NULL;
    struct vcs_swarm_engine *engine =
        vcs_swarm_engine_create(g_fixture_store, NULL, NULL, NULL, NULL);
    if (!engine)
        vcs_package_store_close(g_fixture_store);
    return engine;
}

static void fixture_teardown(struct vcs_swarm_engine *engine)
{
    vcs_swarm_engine_free(engine);
    if (g_fixture_store) {
        vcs_package_store_close(g_fixture_store);
        g_fixture_store = NULL;
    }
    test_rm_rf(g_fixture_dir);
}

/* ── the three lifecycle pins ─────────────────────────────────────── */

static int t_discovery_inert_before_hosting(void)
{
    int failures = 0;
    static struct fake_ops f;
    memset(&f, 0, sizeof(f));
    f.ops.begin = fake_begin;
    f.ops.poll = fake_poll;
    f.ops.route = fake_route;
    f.ops.ctx = &f;
    boot_zcode_swarm_dht_test_install(&f.ops);

    TEST("discovery tick is inert before hosting registers an engine") {
        vcs_swarm_engine_set_global(NULL);
        boot_zcode_swarm_discovery_tick(100);
        ASSERT(f.begins == 0 && f.polls == 0 && f.routes == 0);
        PASS();
    } _test_next:;

    boot_zcode_swarm_dht_test_install(NULL);
    return failures;
}

static int t_lease_completes_to_offer_after_enroll(void)
{
    int failures = 0;
    static struct fake_ops f;
    memset(&f, 0, sizeof(f));
    f.ops.begin = fake_begin;
    f.ops.poll = fake_poll;
    f.ops.route = fake_route;
    f.ops.ctx = &f;
    f.begin_ok = true;
    f.complete_every_poll = true;
    f.poll_state = VCS_ZCODE_DHT_RECORD_OPERATION_COMPLETE;
    f.route_has_peer = true;
    f.route_peer = 4242;
    boot_zcode_swarm_dht_test_install(&f.ops);

    TEST("stalled root gains one lease; the completed route lands as an "
         "offer once the provider enrolls") {
        struct vcs_swarm_engine *engine = fixture_engine("enroll");
        ASSERT(engine != NULL);
        vcs_swarm_engine_set_global(engine);

        uint8_t key[33];
        memset(key, 7, sizeof(key));
        uint8_t root[32];
        memset(root, 9, sizeof(root));
        /* One download nobody advertises — the work list seeds itself. */
        ASSERT_EQ(vcs_swarm_engine_fetch(engine, root, 20500, 1),
                  VCS_SWARM_FETCH_OK);

        /* Tick 1: begins the lease and defers its own poll to the next
         * second (a fresh start continues past the dispatch switch). */
        boot_zcode_swarm_discovery_tick(200);
        ASSERT_EQ(f.begins, 1u);
        ASSERT_EQ(f.routes, 0u);
        uint8_t out[2][32];
        ASSERT(vcs_swarm_engine_unadvertised_roots(engine, out, 2) == 1u);

        /* Tick 2: discovery completes; the provider session exists in
         * the DHT route but the engine has not enrolled it yet, so the
         * evidence waits one enroll horizon instead of failing. */
        boot_zcode_swarm_discovery_tick(201);
        ASSERT_EQ(f.polls, 1u);
        ASSERT_EQ(f.routes, 1u);
        ASSERT(!vcs_swarm_engine_peer_known(engine, f.route_peer));
        ASSERT(vcs_swarm_engine_unadvertised_roots(engine, out, 2) == 1u);

        /* Enroll (membership-sync stand-in) and let the lane re-poll. */
        ASSERT(vcs_swarm_engine_peer_add(engine, f.route_peer, key));
        boot_zcode_swarm_discovery_tick(217);
        ASSERT_EQ(f.polls, 2u);
        ASSERT_EQ(f.routes, 2u);
        ASSERT(vcs_swarm_engine_peer_known(engine, f.route_peer));
        /* Applied: the root leaves the work list entirely... */
        ASSERT(vcs_swarm_engine_unadvertised_roots(engine, out, 2) == 0u);
        /* ...because this engine holds the advertisement now. */
        ASSERT(vcs_swarm_engine_peer_offer(engine, f.route_peer, root,
                                            UINT64_MAX, 1));

        vcs_swarm_engine_set_global(NULL);
        fixture_teardown(engine);
        PASS();
    } _test_next:;

    boot_zcode_swarm_dht_test_install(NULL);
    return failures;
}

static int t_unhelpful_outcome_never_spin_rebegins(void)
{
    int failures = 0;
    static struct fake_ops f;
    memset(&f, 0, sizeof(f));
    f.ops.begin = fake_begin;
    f.ops.poll = fake_poll;
    f.ops.route = fake_route;
    f.ops.ctx = &f;
    f.begin_ok = true;
    f.complete_every_poll = true;
    f.poll_state = VCS_ZCODE_DHT_RECORD_OPERATION_COMPLETE;
    f.route_has_peer = false; /* providers known, none reachable */
    boot_zcode_swarm_dht_test_install(&f.ops);

    TEST("unhelpful outcome waits its horizon; never spin-rebegins") {
        struct vcs_swarm_engine *engine = fixture_engine("backoff");
        ASSERT(engine != NULL);
        vcs_swarm_engine_set_global(engine);

        uint8_t root[32];
        memset(root, 11, sizeof(root));
        ASSERT_EQ(vcs_swarm_engine_fetch(engine, root, 20500, 1),
                  VCS_SWARM_FETCH_OK);

        boot_zcode_swarm_discovery_tick(300); /* begin */
        boot_zcode_swarm_discovery_tick(301); /* complete; enroll-wait */
        const unsigned fixed_begins = f.begins;

        /* Inside the 15 s enroll window nothing new starts... */
        boot_zcode_swarm_discovery_tick(310);
        ASSERT_EQ(f.begins, fixed_begins);
        /* ...and far past it the lane re-POLLS the held lease rather
         * than abandoning it and minting a fresh operation per tick. */
        boot_zcode_swarm_discovery_tick(400);
        boot_zcode_swarm_discovery_tick(401);
        ASSERT_EQ(f.begins, fixed_begins);
        ASSERT(f.polls > 1u);

        vcs_swarm_engine_set_global(NULL);
        fixture_teardown(engine);
        PASS();
    } _test_next:;

    boot_zcode_swarm_dht_test_install(NULL);
    return failures;
}

static int t_expired_route_never_advertises(void)
{
    int failures = 0;
    static struct fake_ops f;
    memset(&f, 0, sizeof(f));
    f.ops.begin = fake_begin;
    f.ops.poll = fake_poll;
    f.ops.route = fake_route;
    f.ops.ctx = &f;
    f.begin_ok = true;
    f.complete_every_poll = true;
    f.poll_state = VCS_ZCODE_DHT_RECORD_OPERATION_COMPLETE;
    f.route_has_peer = true;
    f.route_peer = 4343;
    f.route_expiry = 1;
    boot_zcode_swarm_dht_test_install(&f.ops);

    TEST("expired provider evidence never becomes a swarm offer") {
        struct vcs_swarm_engine *engine = fixture_engine("expired");
        ASSERT(engine != NULL);
        vcs_swarm_engine_set_global(engine);

        uint8_t key[33];
        uint8_t root[32];
        memset(key, 8, sizeof(key));
        memset(root, 12, sizeof(root));
        ASSERT(vcs_swarm_engine_peer_add(engine, f.route_peer, key));
        ASSERT_EQ(vcs_swarm_engine_fetch(engine, root, 20500, 1),
                  VCS_SWARM_FETCH_OK);
        boot_zcode_swarm_discovery_tick(500);
        boot_zcode_swarm_discovery_tick(501);
        ASSERT_EQ(f.routes, 1u);
        uint8_t out[1][32];
        ASSERT_EQ(vcs_swarm_engine_unadvertised_roots(engine, out, 1), 1u);

        vcs_swarm_engine_set_global(NULL);
        fixture_teardown(engine);
        PASS();
    } _test_next:;

    boot_zcode_swarm_dht_test_install(NULL);
    return failures;
}

static int t_adopted_root_frees_its_slot_at_once(void)
{
    int failures = 0;
    static struct fake_ops f;
    memset(&f, 0, sizeof(f));
    f.ops.begin = fake_begin;
    f.ops.poll = fake_poll;
    f.ops.route = fake_route;
    f.ops.ctx = &f;
    f.begin_ok = true; /* DISCOVERING persists: nothing ever completes */
    boot_zcode_swarm_dht_test_install(&f.ops);

    TEST("a root adopted by an advertiser frees its discovery slot in "
         "one tick") {
        struct vcs_swarm_engine *engine = fixture_engine("reap");
        ASSERT(engine != NULL);
        vcs_swarm_engine_set_global(engine);

        uint8_t key[33];
        memset(key, 7, sizeof(key));
        uint8_t roots[5][32];
        for (size_t i = 0; i < 5; i++) {
            memset(roots[i], (int)(i + 1), sizeof(roots[i]));
            ASSERT_EQ(vcs_swarm_engine_fetch(engine, roots[i], 20500, 1),
                      VCS_SWARM_FETCH_OK);
        }

        boot_zcode_swarm_discovery_tick(500);
        ASSERT_EQ(f.begins, 4u);
        const unsigned leased_begins = f.begins;
        ASSERT(vcs_swarm_engine_peer_add(engine, 77, key));
        ASSERT(vcs_swarm_engine_peer_offer(engine, 77, roots[0],
                                            UINT64_MAX, 1));
        boot_zcode_swarm_discovery_tick(501);
        ASSERT_EQ(f.begins, leased_begins + 1u);
        boot_zcode_swarm_discovery_tick(502);
        ASSERT_EQ(f.begins, leased_begins + 1u);

        vcs_swarm_engine_set_global(NULL);
        fixture_teardown(engine);
        PASS();
    } _test_next:;

    boot_zcode_swarm_dht_test_install(NULL);
    return failures;
}

int test_zcode_swarm_dht(void)
{
    return t_discovery_inert_before_hosting() +
           t_lease_completes_to_offer_after_enroll() +
           t_unhelpful_outcome_never_spin_rebegins() +
           t_expired_route_never_advertises() +
           t_adopted_root_frees_its_slot_at_once();
}
