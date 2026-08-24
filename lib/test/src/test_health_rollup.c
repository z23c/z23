/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tests for the native `unhealthy` dumpstate rollup
 * (app/controllers/src/diagnostics_health_rollup.c): walks every OTHER
 * dumper in the g_dumpers[] registry, looks for the reserved `_health`
 * { ok, reason } key (see CLAUDE.md "Adding state introspection" +
 * the file header of diagnostics_health_rollup.c), and aggregates only the
 * unhealthy ones.
 *
 * Coverage, using real subsystems that seed `_health` (not a synthetic
 * stand-in). Adoption is now well past the original five exemplars — most
 * of the newly-seeded ones are reducer stages / storage projections that
 * report ok=false in THIS minimal fixture simply because this file never
 * initialises them (their real "not initialised" / "not open" condition,
 * not a bug), so a blanket "everything is healthy" baseline would be
 * fragile and dishonest. Instead:
 *   (a) the rollup runs cleanly (dump returns true) and `reporting` covers
 *       at least the original five exemplars; the SPECIFIC subsystems this
 *       fixture actually brings up healthy (legacy_mirror,
 *       chain_advance_coordinator, tip_finalize) are absent from the
 *       unhealthy array — see (c).
 *   (b) seeding one dumper (the typed blocker registry) into an unhealthy
 *       state makes it appear in the unhealthy array with its subsystem
 *       name + reason, and all_ok stays false with unhealthy_count >= 1.
 *   (c) subsystems that stayed healthy (legacy_mirror, tip_finalize,
 *       chain_advance_coordinator) are NOT included in the unhealthy array.
 *   (d) a dumper seeded in THIS round (mempool_projection — one of the
 *       storage projection dumpers whose `_health` maps the existing
 *       "open" signal, see lib/storage/src/mempool_projection.c) flips
 *       from healthy to unhealthy when its real "not open" condition is
 *       synthesized via the projection's own close() API — proving a
 *       newly-seeded dumper actually surfaces through the rollup, not just
 *       the five pre-existing exemplars above.
 *
 * tip_finalize's `_health` reports ok=false ("stage not initialised") until
 * tip_finalize_stage_init() runs, so this file pays the same minimal setup
 * cost (progress_store_open + main_state_init + tip_finalize_stage_init)
 * that lib/test/src/test_tip_finalize_stage.c already pays, purely to put
 * that one real dumper into its healthy state for test (a) — no new health
 * logic anywhere, just exercising what each dumper already computes. */

#include "test/test_core.h"
#include "controllers/diagnostics_controller.h"
#include "controllers/diagnostics_internal.h"
#include "jobs/tip_finalize_stage.h"
#include "storage/event_log.h"
#include "storage/mempool_projection.h"
#include "storage/progress_store.h"
#include "util/blocker.h"
#include "validation/main_state.h"
#include "json/json.h"

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#define HR_CHECK(name, expr) do { \
    printf("health_rollup: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

static const struct json_value *hr_find_by_subsystem(
    const struct json_value *arr, const char *name)
{
    if (!arr || arr->type != JSON_ARR || !name)
        return NULL;
    for (size_t i = 0; i < json_size(arr); i++) {
        const struct json_value *child = json_at(arr, i);
        const struct json_value *sub = json_get(child, "subsystem");
        if (sub && sub->type == JSON_STR && strcmp(sub->val.s, name) == 0)
            return child;
    }
    return NULL;
}

int test_health_rollup(void)
{
    printf("\n=== health_rollup tests ===\n");
    int failures = 0;

    blocker_reset_for_testing();

    char dir[256];
    test_fmt_tmpdir(dir, sizeof(dir), "health_rollup", "1");
    mkdir("./test-tmp", 0755);
    mkdir(dir, 0755);
    bool store_ok = progress_store_open(dir);

    /* Point the diagnostics controller at THIS fixture's datadir before any
     * rollup call. The rollup invokes every registered dumper, and the
     * datadir-reading ones (omniscience's census freshness probe, block_index,
     * nodelog, ...) resolve their paths through diag_datadir(). That is a
     * zero-initialised buffer until something sets it, and census_datadir()
     * (lib/storage/src/census_read.c) treats an EMPTY datadir as "use
     * $HOME/.zclassic-c23" — i.e. the LIVE NODE'S datadir. Unset, this test
     * opened the live node's peers_projection.db + topology.db and ran
     * census_read_graph()'s correlated ip_to_str() join across them on every
     * one of its four rollup calls: 37-80s each (measured), scaling with
     * whatever the live crawler has accumulated, for a result this test never
     * asserts on. Same pattern as lib/test/src/test_rpc.c. main_state stays
     * NULL exactly as before, so no dumper's outcome changes — only the
     * directory the datadir-reading ones look in. */
    diagnostics_controller_set_state(NULL, dir);

    struct main_state ms;
    memset(&ms, 0, sizeof(ms));
    main_state_init(&ms);
    bool tf_ok = tip_finalize_stage_init(&ms);

    /* ── (a) baseline: dump is well-formed; known-healthy exemplars
     * stay absent (see the file header for why this no longer asserts a
     * blanket all_ok==true — adoption has grown well past the five
     * subsystems this minimal fixture can bring up healthy) ──────────── */
    {
        struct json_value v = {0};
        json_set_object(&v);
        bool ok = unhealthy_dump_state_json(&v, NULL);
        HR_CHECK("baseline: dump returns true", ok);

        const struct json_value *unhealthy = json_get(&v, "unhealthy");
        HR_CHECK("baseline: unhealthy array present",
                 unhealthy && unhealthy->type == JSON_ARR);
        HR_CHECK("baseline: legacy_mirror (healthy) absent from array",
                 hr_find_by_subsystem(unhealthy, "legacy_mirror") == NULL);
        HR_CHECK("baseline: tip_finalize (healthy) absent from array",
                 hr_find_by_subsystem(unhealthy, "tip_finalize") == NULL);
        HR_CHECK("baseline: chain_advance_coordinator (healthy) absent "
                 "from array",
                 hr_find_by_subsystem(unhealthy,
                                      "chain_advance_coordinator") == NULL);

        /* Sanity: the seeded subsystems this test controls really did
         * report `_health` this cycle (guards against a silent regression
         * where a dumper stops emitting `_health` and the rollup goes
         * quiet instead of failing loud). */
        const struct json_value *checked = json_get(&v, "checked");
        const struct json_value *reporting = json_get(&v, "reporting");
        HR_CHECK("baseline: checked == dumper_count - 1 (self excluded)",
                 checked &&
                 json_get_int(checked) ==
                     (int64_t)diagnostics_dumper_count() - 1);
        HR_CHECK("baseline: reporting >= 4 seeded subsystems "
                 "(blocker, legacy_mirror, chain_advance_coordinator, "
                 "tip_finalize; many more now report too)",
                 reporting && json_get_int(reporting) >= 4);

        json_free(&v);
    }

    /* ── (b) + (c): seed exactly one dumper unhealthy ──────────────── */
    {
        struct blocker_record r;
        blocker_init(&r, "hr_test_blocker", "health_rollup_test",
                    BLOCKER_TRANSIENT, "hr_test_blocker_reason");
        blocker_set(&r);

        struct json_value v = {0};
        json_set_object(&v);
        bool ok = unhealthy_dump_state_json(&v, NULL);
        HR_CHECK("seeded: dump returns true", ok);

        const struct json_value *all_ok = json_get(&v, "all_ok");
        HR_CHECK("seeded: all_ok flips to false",
                 all_ok && !json_get_bool(all_ok));

        const struct json_value *unhealthy = json_get(&v, "unhealthy");
        const struct json_value *blocker_entry =
            hr_find_by_subsystem(unhealthy, "blocker");
        HR_CHECK("seeded: blocker subsystem appears in unhealthy array",
                 blocker_entry != NULL);
        HR_CHECK("seeded: blocker entry's reason names the test blocker",
                 blocker_entry &&
                 json_get(blocker_entry, "reason") &&
                 strstr(json_get_str(json_get(blocker_entry, "reason")),
                        "hr_test_blocker_reason") != NULL);

        const struct json_value *unhealthy_count =
            json_get(&v, "unhealthy_count");
        /* >= 1, not == 1: this fixture only initialises tip_finalize (and
         * now seeds `_health` on many more subsystems than the original 5
         * exemplars — reducer stages, projections, etc. — most of which
         * report ok=false here simply because THIS test never initialises
         * them, not because anything is actually broken). The one
         * assertion this test owns is that the blocker we just seeded is
         * IN the array (checked above) — see also (d) below for a
         * dedicated before/after flip on one specific newly-seeded
         * dumper. */
        HR_CHECK("seeded: unhealthy_count >= 1",
                 unhealthy_count && json_get_int(unhealthy_count) >= 1);
        HR_CHECK("seeded: unhealthy array length matches unhealthy_count",
                 unhealthy && unhealthy_count &&
                 (int64_t)json_size(unhealthy) ==
                     json_get_int(unhealthy_count));

        /* (c) subsystems that stayed healthy are NOT reported. */
        HR_CHECK("seeded: legacy_mirror (healthy) absent from array",
                 hr_find_by_subsystem(unhealthy, "legacy_mirror") == NULL);
        HR_CHECK("seeded: tip_finalize (healthy) absent from array",
                 hr_find_by_subsystem(unhealthy, "tip_finalize") == NULL);
        HR_CHECK("seeded: chain_advance_coordinator (healthy) absent "
                 "from array",
                 hr_find_by_subsystem(unhealthy,
                                      "chain_advance_coordinator") == NULL);
        /* The rollup never reports on itself (would recurse). */
        HR_CHECK("seeded: unhealthy never reports on itself",
                 hr_find_by_subsystem(unhealthy, "unhealthy") == NULL);

        json_free(&v);
        blocker_clear("hr_test_blocker");
    }

    /* ── (d) a newly-seeded dumper (mempool_projection) surfaces too ─── */
    {
        char proj_dir[300], elog_path[360], proj_path[360];
        test_make_tmpdir(proj_dir, sizeof(proj_dir), "health_rollup", "proj");
        test_projection_paths(proj_dir, "mempool", elog_path,
                              sizeof(elog_path), proj_path, sizeof(proj_path));
        event_log_t *log = event_log_open(elog_path);
        mempool_projection_t *p = mempool_projection_open(proj_path, log);
        HR_CHECK("(d) setup: mempool_projection opened", log && p);

        struct json_value v = {0};
        json_set_object(&v);
        unhealthy_dump_state_json(&v, NULL);
        const struct json_value *unhealthy = json_get(&v, "unhealthy");
        HR_CHECK("(d) mempool_projection healthy (open, no fails) -> "
                 "absent from array",
                 hr_find_by_subsystem(unhealthy, "mempool_projection") ==
                     NULL);
        json_free(&v);

        /* Synthesize the real "not open" condition via the projection's
         * own close() API (no new health logic — see
         * lib/storage/src/mempool_projection.c's `_health` block). */
        mempool_projection_close(p);

        json_init(&v);
        json_set_object(&v);
        unhealthy_dump_state_json(&v, NULL);
        const struct json_value *all_ok = json_get(&v, "all_ok");
        HR_CHECK("(d) all_ok is false once mempool_projection closes",
                 all_ok && !json_get_bool(all_ok));
        unhealthy = json_get(&v, "unhealthy");
        const struct json_value *mp_entry =
            hr_find_by_subsystem(unhealthy, "mempool_projection");
        HR_CHECK("(d) mempool_projection appears in unhealthy array once "
                 "closed", mp_entry != NULL);
        HR_CHECK("(d) reason names the not-open condition",
                 mp_entry && json_get(mp_entry, "reason") &&
                 strstr(json_get_str(json_get(mp_entry, "reason")),
                        "not open") != NULL);
        json_free(&v);

        event_log_close(log);
        test_rm_rf_recursive(proj_dir);
    }

    /* diagnostics_controller_set_state() above started the debug-bundle stall
     * worker; join it before the state and tmpdir it inspects go away. */
    (void)diagnostics_controller_shutdown();
    tip_finalize_stage_shutdown();
    main_state_free(&ms);
    if (store_ok) progress_store_close();
    test_cleanup_tmpdir(dir);
    blocker_reset_for_testing();
    (void)tf_ok;

    return failures;
}
