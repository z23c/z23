/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The boot-level swarm-DHT discovery bridge (engine/composition/src/boot_zcode_swarm_dht.c)
 * driven against a real engine with scripted begin/poll/route outcomes.
 * Covers: inertness before hosting registers an engine; one lease per
 * stalled root completing into an applied offer; the enroll-wait window;
 * no spin-rebegin on an unhelpful outcome; and a routed package carrier
 * reconstructed on the node's own tick after one request. */

#include "config/boot_zcode_dht.h"
#include "config/boot_zcode_swarm_dht.h"
#include "json/json.h"
#include "test/test_core.h"
#include "test/test_zcode_swarm_priv.h"
#include "vcs/package_store.h"
#include "vcs/package_swarm_node.h"
#include "vcs/package_transport.h"
#include "vcs/zcode_dht_service.h"

#include <stdlib.h>
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

/* ── routed carrier follow-through ────────────────────────────────── */

/* Carry every frame `from` queued for `to` into `to`'s engine and any
 * synchronous answer back: the boot glue's drain/reply loop with the
 * socket elided. `to_id` names `to` inside `from`; `from_id` the other
 * way round. */
static size_t relay_frames(struct vcs_swarm_engine *from, uint64_t to_id,
                           struct vcs_swarm_engine *to, uint64_t from_id,
                           uint64_t now)
{
    uint8_t frame[VCS_SWARM_OUTBOUND_FRAME_MAX];
    uint64_t target = 0;
    size_t len = 0, moved = 0;
    while (vcs_swarm_engine_next_outbound(from, to_id, &target, frame,
                                          &len)) {
        struct vcs_swarm_frame_result res = vcs_swarm_engine_handle_frame(
            to, from_id, frame, len, SW_DAY, now);
        if (res.reply) {
            struct vcs_swarm_frame_result back =
                vcs_swarm_engine_handle_frame(from, to_id, res.reply,
                                              res.reply_len, SW_DAY, now);
            free(back.reply);
            free(res.reply);
        }
        moved++;
    }
    return moved;
}

/* Run the requester's scheduler against the seeder until the carrier
 * download leaves the moving states. No fetch call happens in here. */
static enum vcs_swarm_download_state drive_carrier(
    struct sw_node *requester, uint64_t seeder_id, struct sw_node *seeder,
    uint64_t requester_id, const uint8_t root[32], uint64_t *now)
{
    struct vcs_swarm_download_status st;
    memset(&st, 0, sizeof(st));
    for (unsigned i = 0; i < 128u; i++) {
        vcs_swarm_engine_tick(requester->engine, SW_DAY, ++*now);
        (void)relay_frames(requester->engine, seeder_id, seeder->engine,
                           requester_id, *now);
        (void)relay_frames(seeder->engine, requester_id, requester->engine,
                           seeder_id, *now);
        if (!vcs_swarm_engine_download_status(requester->engine, root, &st))
            return VCS_SWARM_DL_INACTIVE;
        if (st.state != VCS_SWARM_DL_WANT_MANIFEST &&
            st.state != VCS_SWARM_DL_CHUNKS)
            break;
    }
    return st.state;
}

static bool json_flag(const struct json_value *obj, const char *key)
{
    const struct json_value *v = json_get(obj, key);
    return v && v->type == JSON_BOOL && json_get_bool(v);
}

static bool package_complete(struct sw_node *n, const uint8_t root[32])
{
    struct vcs_package_store_status st;
    memset(&st, 0, sizeof(st));
    return vcs_package_store_package_status(n->store, root, &st) &&
           st.tracked && st.complete;
}

struct carrier_pair {
    struct sw_node seeder, requester;
    uint64_t seeder_id, requester_id;
    uint8_t transport[2][32];
    uint8_t package[2][32];
};

static bool carrier_pair_open(struct carrier_pair *cp)
{
    static const char *const dirs[2] = {"contexts/commons/packages/zhex",
                                        "contexts/commons/packages/zstr"};
    memset(cp, 0, sizeof(*cp));
    cp->seeder_id = 6101;
    cp->requester_id = 6102;
    if (!sw_node_open(&cp->seeder, "import-seed", sw_score_contributor) ||
        !sw_node_open(&cp->requester, "import-fetch", sw_score_contributor))
        return false;
    for (size_t i = 0; i < 2; i++) {
        struct vcs_package_transport_import imported;
        if (!sw_seed_in_tree_package(&cp->seeder, dirs[i],
                                     (uint8_t)(0x61u + i), i + 1u,
                                     cp->transport[i]) ||
            vcs_swarm_engine_import_transport(cp->seeder.engine,
                                              cp->transport[i], &imported) !=
                VCS_PACKAGE_TRANSPORT_OK)
            return false;
        memcpy(cp->package[i], imported.package_root, 32);
    }
    uint8_t seeder_key[33], requester_key[33];
    sw_key(0x81, seeder_key);
    sw_key(0x82, requester_key);
    return vcs_swarm_engine_peer_add(cp->seeder.engine, cp->requester_id,
                                     requester_key) &&
           vcs_swarm_engine_peer_add(cp->requester.engine, cp->seeder_id,
                                     seeder_key);
}

static void carrier_pair_close(struct carrier_pair *cp)
{
    sw_node_close(&cp->seeder);
    sw_node_close(&cp->requester);
    if (cp->seeder.datadir[0])
        test_rm_rf_recursive(cp->seeder.datadir);
    if (cp->requester.datadir[0])
        test_rm_rf_recursive(cp->requester.datadir);
}

/* The Commons journey measured one routed `zcode package fetch` finishing
 * its carrier in the background but leaving the signed package root
 * untracked until the caller re-issued the fetch 15 s later. One request
 * must be enough: the node's own tick reconstructs the package. */
static int t_routed_carrier_reconstructs_without_second_request(void)
{
    int failures = 0;
    static struct fake_ops f;
    memset(&f, 0, sizeof(f));
    f.ops.begin = fake_begin;
    f.ops.poll = fake_poll;
    f.ops.route = fake_route;
    f.ops.ctx = &f;
    boot_zcode_swarm_dht_test_install(&f.ops);
    static struct carrier_pair cp;
    struct json_value routed, other;
    json_init(&routed);
    json_init(&other);

    TEST("one routed package fetch reconstructs the signed package on the "
         "node's own tick; a non-package carrier is never reconstructed") {
        ASSERT(carrier_pair_open(&cp));
        uint64_t now = 1;
        for (size_t i = 0; i < 2; i++)
            ASSERT_EQ(vcs_swarm_engine_fetch_from(
                          cp.requester.engine, cp.transport[i], SW_DAY, now,
                          &cp.seeder_id, 1),
                      VCS_SWARM_FETCH_OK);
        /* Exactly what rpc_provider_route renders for each request: the
         * package namespace hands the engine over, any other passes NULL. */
        json_set_object(&routed);
        json_set_object(&other);
        boot_zcode_package_import_render(cp.requester.engine, cp.transport[0],
                                         VCS_SWARM_FETCH_OK, &routed);
        boot_zcode_package_import_render(NULL, cp.transport[1],
                                         VCS_SWARM_FETCH_OK, &other);
        ASSERT(!json_flag(&routed, "reconstructed"));

        for (size_t i = 0; i < 2; i++)
            ASSERT_EQ(drive_carrier(&cp.requester, cp.seeder_id, &cp.seeder,
                                    cp.requester_id, cp.transport[i], &now),
                      VCS_SWARM_DL_COMPLETE);
        /* Whole carriers alone do not make the packages: this is the
         * state the journey sat in for 15 s. */
        ASSERT(!package_complete(&cp.requester, cp.package[0]));
        ASSERT(!package_complete(&cp.requester, cp.package[1]));

        vcs_swarm_engine_set_global(cp.requester.engine);
        boot_zcode_swarm_discovery_tick(700);
        ASSERT(package_complete(&cp.requester, cp.package[0]));
        ASSERT(!package_complete(&cp.requester, cp.package[1]));
        /* Drained, not re-run every tick; the request path stays the
         * idempotent redelivery. */
        boot_zcode_swarm_discovery_tick(701);
        ASSERT(!package_complete(&cp.requester, cp.package[1]));
        ASSERT_EQ(f.begins, 0u);
        json_free(&routed);
        json_init(&routed);
        json_set_object(&routed);
        boot_zcode_package_import_render(cp.requester.engine, cp.transport[0],
                                         VCS_SWARM_FETCH_ALREADY_COMPLETE,
                                         &routed);
        ASSERT(json_flag(&routed, "reconstructed"));
        PASS();
    } _test_next:;

    vcs_swarm_engine_set_global(NULL);
    json_free(&routed);
    json_free(&other);
    carrier_pair_close(&cp);
    boot_zcode_swarm_dht_test_install(NULL);
    return failures;
}

int test_zcode_swarm_dht(void)
{
    return t_discovery_inert_before_hosting() +
           t_lease_completes_to_offer_after_enroll() +
           t_unhelpful_outcome_never_spin_rebegins() +
           t_expired_route_never_advertises() +
           t_adopted_root_frees_its_slot_at_once() +
           t_routed_carrier_reconstructs_without_second_request();
}
