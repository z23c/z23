/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tests for net/rom_seed_policy.h — defaults, bounds validation +
 * persistence round-trip, the admit/disable decision (the interface the
 * seed engine's serve path consults — exercising it here IS the
 * "disable stops serving" proof, since there is no sibling serve path in
 * this tree yet), the generosity-boost window, and live counters.
 *
 * One TEST(...) block per function (the ASSERT()/ASSERT_EQ() macros `goto
 * _test_next`, a single hardcoded label — see test/test_core.h — so two
 * TEST blocks sharing one function collide on that label). */

#include "test/test_core.h"
#include "json/json.h"

#include "net/rom_seed_policy.h"

#include <string.h>
#include <sys/stat.h>

static int t_fresh_policy_loads_defaults(void)
{
    int failures = 0;
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "rom_seed_policy", "defaults1");
    rom_seed_policy_test_reset(dir);

    TEST("fresh policy loads the compiled defaults") {
        struct rom_seed_policy p;
        rom_seed_policy_get(&p);
        ASSERT(p.enabled == ROM_SEED_POLICY_DEFAULT_ENABLED);
        ASSERT_EQ(p.global_up_bytes_per_sec,
                 (uint64_t)ROM_SEED_POLICY_DEFAULT_GLOBAL_BPS);
        ASSERT_EQ(p.per_peer_up_bytes_per_sec,
                 (uint64_t)ROM_SEED_POLICY_DEFAULT_PER_PEER_BPS);
        ASSERT_EQ(p.max_concurrent_uploads,
                 (uint32_t)ROM_SEED_POLICY_DEFAULT_MAX_CONCURRENCY);
        ASSERT_EQ(p.generosity_boost_days,
                 (uint32_t)ROM_SEED_POLICY_DEFAULT_BOOST_DAYS);
        PASS();
    } _test_next:;

    rom_seed_policy_test_reset(NULL);
    return failures;
}

/* A bare read must never have a disk side effect — rom_seed_policy_get()
 * (and therefore rom_seed_policy_dump_state_json()) is reachable from any
 * passive whole-registry sweep (e.g. the `unhealthy` health rollup,
 * engine/controllers/src/diagnostics_health_rollup.c), which runs in
 * processes that never set up a test-isolated datadir; a write here would
 * plant a file in whatever datadir that caller happens to be pointed at
 * (this is exactly how a bare rom_seed_policy_get() from the health
 * rollup used to leak a file into the operator's real datadir — see the
 * PERSISTENCE section of net/rom_seed_policy.h). An explicit owner
 * mutation still persists — proven by t_apply_takes_effect_and_survives_
 * reload below. */
static int t_bare_get_never_writes_to_disk(void)
{
    int failures = 0;
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "rom_seed_policy", "defaults2");
    rom_seed_policy_test_reset(dir);

    TEST("a bare get() of never-before-seen defaults never touches disk") {
        struct rom_seed_policy p;
        rom_seed_policy_get(&p);
        rom_seed_policy_get(&p); /* second call: still no write */
        char path[300];
        snprintf(path, sizeof(path), "%s/%s", dir, ROM_SEED_POLICY_FILENAME);
        struct stat st;
        ASSERT(stat(path, &st) != 0);
        PASS();
    } _test_next:;

    rom_seed_policy_test_reset(NULL);
    return failures;
}

static int t_apply_rejects_global_below_floor(void)
{
    int failures = 0;
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "rom_seed_policy", "apply1");
    rom_seed_policy_test_reset(dir);

    TEST("apply rejects global_up_bytes_per_sec below the floor") {
        struct rom_seed_policy p = {
            .enabled = true,
            .global_up_bytes_per_sec = ROM_SEED_POLICY_MIN_GLOBAL_BPS - 1,
            .per_peer_up_bytes_per_sec = ROM_SEED_POLICY_MIN_PER_PEER_BPS,
            .max_concurrent_uploads = 8,
            .generosity_boost_days = 3,
        };
        char err[160] = {0};
        ASSERT(!rom_seed_policy_apply(&p, err, sizeof(err)));
        ASSERT(err[0] != '\0');
        struct rom_seed_policy live;
        rom_seed_policy_get(&live);
        ASSERT_EQ(live.global_up_bytes_per_sec,
                 (uint64_t)ROM_SEED_POLICY_DEFAULT_GLOBAL_BPS);
        PASS();
    } _test_next:;

    rom_seed_policy_test_reset(NULL);
    return failures;
}

static int t_apply_rejects_per_peer_exceeds_global(void)
{
    int failures = 0;
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "rom_seed_policy", "apply2");
    rom_seed_policy_test_reset(dir);

    TEST("apply rejects per_peer exceeding global") {
        struct rom_seed_policy p = {
            .enabled = true,
            .global_up_bytes_per_sec = ROM_SEED_POLICY_MIN_GLOBAL_BPS,
            .per_peer_up_bytes_per_sec = ROM_SEED_POLICY_MIN_GLOBAL_BPS + 1,
            .max_concurrent_uploads = 8,
            .generosity_boost_days = 3,
        };
        char err[160] = {0};
        ASSERT(!rom_seed_policy_apply(&p, err, sizeof(err)));
        PASS();
    } _test_next:;

    rom_seed_policy_test_reset(NULL);
    return failures;
}

static int t_apply_rejects_concurrency_out_of_range(void)
{
    int failures = 0;
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "rom_seed_policy", "apply3");
    rom_seed_policy_test_reset(dir);

    TEST("apply rejects max_concurrent_uploads out of range") {
        struct rom_seed_policy p = {
            .enabled = true,
            .global_up_bytes_per_sec = ROM_SEED_POLICY_DEFAULT_GLOBAL_BPS,
            .per_peer_up_bytes_per_sec = ROM_SEED_POLICY_DEFAULT_PER_PEER_BPS,
            .max_concurrent_uploads = ROM_SEED_POLICY_MAX_CONCURRENCY + 1,
            .generosity_boost_days = 3,
        };
        char err[160] = {0};
        ASSERT(!rom_seed_policy_apply(&p, err, sizeof(err)));
        PASS();
    } _test_next:;

    rom_seed_policy_test_reset(NULL);
    return failures;
}

static int t_apply_takes_effect_and_survives_reload(void)
{
    int failures = 0;
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "rom_seed_policy", "apply4");
    rom_seed_policy_test_reset(dir);

    TEST("a valid apply takes effect and survives a reload") {
        struct rom_seed_policy p = {
            .enabled = false,
            .global_up_bytes_per_sec = 4ULL * 1024 * 1024,
            .per_peer_up_bytes_per_sec = 512ULL * 1024,
            .max_concurrent_uploads = 3,
            .generosity_boost_days = 2,
        };
        char err[160] = {0};
        ASSERT(rom_seed_policy_apply(&p, err, sizeof(err)));
        struct rom_seed_policy live;
        rom_seed_policy_get(&live);
        ASSERT(live.enabled == false);
        ASSERT_EQ(live.global_up_bytes_per_sec, p.global_up_bytes_per_sec);
        ASSERT_EQ(live.max_concurrent_uploads, p.max_concurrent_uploads);

        /* Force a reload from disk (simulates a process restart) and
         * confirm the applied values, not the compiled defaults, come
         * back. */
        rom_seed_policy_test_reset(dir);
        struct rom_seed_policy reloaded;
        rom_seed_policy_get(&reloaded);
        ASSERT(reloaded.enabled == false);
        ASSERT_EQ(reloaded.global_up_bytes_per_sec, p.global_up_bytes_per_sec);
        ASSERT_EQ(reloaded.per_peer_up_bytes_per_sec,
                 p.per_peer_up_bytes_per_sec);
        ASSERT_EQ(reloaded.max_concurrent_uploads, p.max_concurrent_uploads);
        ASSERT_EQ(reloaded.generosity_boost_days, p.generosity_boost_days);
        PASS();
    } _test_next:;

    rom_seed_policy_test_reset(NULL);
    return failures;
}

/* The seed engine's serve path is expected to gate every new upload
 * through rom_seed_policy_admit_upload(); since no sibling serve path is
 * in this tree yet, exercising that exact call is the "disable stops
 * serving" proof for this lane. */
static int t_admit_enabled_under_cap(void)
{
    int failures = 0;
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "rom_seed_policy", "admit1");
    rom_seed_policy_test_reset(dir);

    TEST("enabled + under cap admits; at/over cap refuses") {
        (void)rom_seed_policy_set_enabled(true);
        ASSERT(rom_seed_policy_admit_upload(0));
        struct rom_seed_policy p;
        rom_seed_policy_get(&p);
        ASSERT(!rom_seed_policy_admit_upload(p.max_concurrent_uploads));
        ASSERT(!rom_seed_policy_admit_upload(p.max_concurrent_uploads + 1));
        PASS();
    } _test_next:;

    rom_seed_policy_test_reset(NULL);
    return failures;
}

static int t_admit_disable_stops_serving(void)
{
    int failures = 0;
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "rom_seed_policy", "admit2");
    rom_seed_policy_test_reset(dir);

    TEST("disable stops serving: admit_upload refuses regardless of load") {
        (void)rom_seed_policy_set_enabled(false);
        ASSERT(!rom_seed_policy_admit_upload(0));
        struct rom_seed_policy p;
        rom_seed_policy_get(&p);
        ASSERT(p.enabled == false);
        (void)rom_seed_policy_set_enabled(true);
        ASSERT(rom_seed_policy_admit_upload(0));
        PASS();
    } _test_next:;

    rom_seed_policy_test_reset(NULL);
    return failures;
}

static int t_admit_consensus_preempt(void)
{
    int failures = 0;
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "rom_seed_policy", "admit3");
    rom_seed_policy_test_reset(dir);

    TEST("consensus_active preempts admission even when enabled") {
        ASSERT(!rom_seed_policy_consensus_active());
        rom_seed_policy_set_consensus_active(true);
        ASSERT(rom_seed_policy_consensus_active());
        ASSERT(!rom_seed_policy_admit_upload(0));
        rom_seed_policy_set_consensus_active(false);
        ASSERT(rom_seed_policy_admit_upload(0));
        PASS();
    } _test_next:;

    rom_seed_policy_test_reset(NULL);
    return failures;
}

static int t_boost_window_fresh_vs_old(void)
{
    int failures = 0;
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "rom_seed_policy", "boost1");
    rom_seed_policy_test_reset(dir);

    TEST("boost window: fresh artifact is boosted, old one is not") {
        int64_t now = 1750000000;
        int64_t fresh = now - 3600; /* 1 hour ago */
        int64_t old = now - (int64_t)(ROM_SEED_POLICY_DEFAULT_BOOST_DAYS + 1) * 86400;
        ASSERT(rom_seed_policy_is_boosted(fresh, now));
        ASSERT(!rom_seed_policy_is_boosted(old, now));
        ASSERT(!rom_seed_policy_is_boosted(0, now));
        ASSERT(!rom_seed_policy_is_boosted(-1, now));
        PASS();
    } _test_next:;

    rom_seed_policy_test_reset(NULL);
    return failures;
}

static int t_boost_window_zero_days_never_boosts(void)
{
    int failures = 0;
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "rom_seed_policy", "boost2");
    rom_seed_policy_test_reset(dir);

    TEST("zero-day boost window never boosts") {
        struct rom_seed_policy p = {
            .enabled = true,
            .global_up_bytes_per_sec = ROM_SEED_POLICY_DEFAULT_GLOBAL_BPS,
            .per_peer_up_bytes_per_sec = ROM_SEED_POLICY_DEFAULT_PER_PEER_BPS,
            .max_concurrent_uploads = 8,
            .generosity_boost_days = 0,
        };
        char err[160];
        ASSERT(rom_seed_policy_apply(&p, err, sizeof(err)));
        ASSERT(!rom_seed_policy_is_boosted(1750000000, 1750000001));
        PASS();
    } _test_next:;

    rom_seed_policy_test_reset(NULL);
    return failures;
}

static int t_boost_effective_per_peer_cap(void)
{
    int failures = 0;
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "rom_seed_policy", "boost3");
    rom_seed_policy_test_reset(dir);

    TEST("effective per-peer cap: boosted multiplies, clamped to global") {
        struct rom_seed_policy p = {
            .enabled = true,
            .global_up_bytes_per_sec = 4ULL * 1024 * 1024,
            .per_peer_up_bytes_per_sec = 1ULL * 1024 * 1024,
            .max_concurrent_uploads = 8,
            .generosity_boost_days = 7,
        };
        char err[160];
        ASSERT(rom_seed_policy_apply(&p, err, sizeof(err)));
        ASSERT_EQ(rom_seed_policy_effective_per_peer_cap(false),
                 (uint64_t)(1ULL * 1024 * 1024));
        /* 1 MB/s * 4x boost = 4 MB/s, exactly at the 4 MB/s global cap. */
        ASSERT_EQ(rom_seed_policy_effective_per_peer_cap(true),
                 (uint64_t)(4ULL * 1024 * 1024));
        PASS();
    } _test_next:;

    rom_seed_policy_test_reset(NULL);
    return failures;
}

static int t_counters(void)
{
    int failures = 0;
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "rom_seed_policy", "counters");
    rom_seed_policy_test_reset(dir);

    TEST("started/finished/refused counters and active floor at 0") {
        struct rom_seed_policy_counters c;
        rom_seed_policy_get_counters(&c);
        ASSERT_EQ(c.uploads_active, (uint32_t)0);

        rom_seed_policy_note_upload_started();
        rom_seed_policy_note_upload_started();
        rom_seed_policy_get_counters(&c);
        ASSERT_EQ(c.uploads_started_total, (uint64_t)2);
        ASSERT_EQ(c.uploads_active, (uint32_t)2);

        rom_seed_policy_note_upload_finished(1000);
        rom_seed_policy_get_counters(&c);
        ASSERT_EQ(c.uploads_finished_total, (uint64_t)1);
        ASSERT_EQ(c.bytes_served_total, (uint64_t)1000);
        ASSERT_EQ(c.uploads_active, (uint32_t)1);

        /* An extra finish beyond what was started must not underflow. */
        rom_seed_policy_note_upload_finished(500);
        rom_seed_policy_note_upload_finished(500);
        rom_seed_policy_get_counters(&c);
        ASSERT_EQ(c.uploads_active, (uint32_t)0);

        rom_seed_policy_note_upload_refused();
        rom_seed_policy_get_counters(&c);
        ASSERT_EQ(c.uploads_refused_total, (uint64_t)1);
        PASS();
    } _test_next:;

    rom_seed_policy_test_reset(NULL);
    return failures;
}

static int t_dump_state_json(void)
{
    int failures = 0;
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "rom_seed_policy", "dumpstate");
    rom_seed_policy_test_reset(dir);

    TEST("dump_state_json produces a well-formed body") {
        struct json_value out;
        json_init(&out);
        ASSERT(rom_seed_policy_dump_state_json(&out, NULL));
        ASSERT(out.type == JSON_OBJ);
        const struct json_value *policy = json_get(&out, "policy");
        ASSERT(policy && policy->type == JSON_OBJ);
        const struct json_value *counters = json_get(&out, "counters");
        ASSERT(counters && counters->type == JSON_OBJ);
        const struct json_value *health = json_get(&out, "_health");
        ASSERT(health && json_get_bool(json_get(health, "ok")));
        json_free(&out);
        PASS();
    } _test_next:;

    rom_seed_policy_test_reset(NULL);
    return failures;
}

int test_rom_seed_policy(void)
{
    int failures = 0;
    failures += t_fresh_policy_loads_defaults();
    failures += t_bare_get_never_writes_to_disk();
    failures += t_apply_rejects_global_below_floor();
    failures += t_apply_rejects_per_peer_exceeds_global();
    failures += t_apply_rejects_concurrency_out_of_range();
    failures += t_apply_takes_effect_and_survives_reload();
    failures += t_admit_enabled_under_cap();
    failures += t_admit_disable_stops_serving();
    failures += t_admit_consensus_preempt();
    failures += t_boost_window_fresh_vs_old();
    failures += t_boost_window_zero_days_never_boosts();
    failures += t_boost_effective_per_peer_cap();
    failures += t_counters();
    failures += t_dump_state_json();
    return failures;
}
