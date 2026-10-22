/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tests for the native `unhealthy` dumpstate rollup
 * (engine/controllers/src/diagnostics_health_rollup.c): walks every OTHER
 * dumper in the g_dumpers[] registry, looks for the reserved `_health`
 * { ok, reason } key (see CLAUDE.md "Adding state introspection" +
 * the file header of diagnostics_health_rollup.c), and aggregates only the
 * unhealthy ones.
 *
 * Coverage, using real subsystems that seed `_health`:
 *   (a) the rollup runs cleanly (dump returns true) and `reporting` covers at
 *       least the original five exemplars; the subsystems this fixture brings
 *       up healthy (legacy_mirror, chain_advance_coordinator, tip_finalize)
 *       are absent from the unhealthy array. Other reducer stages and
 *       projections report ok=false because this file never initialises
 *       them, so no blanket "everything is healthy" baseline is asserted.
 *   (b) seeding one dumper (the typed blocker registry) unhealthy makes it
 *       appear in the unhealthy array with its subsystem name + reason, and
 *       all_ok stays false with unhealthy_count >= 1.
 *   (c) subsystems that stayed healthy are NOT in the unhealthy array.
 *   (d) mempool_projection (its `_health` maps the "open" signal, see
 *       engine/modules/storage/src/mempool_projection.c) flips from healthy
 *       to unhealthy when closed via the projection's own close() API.
 *
 * tip_finalize's `_health` reports ok=false until tip_finalize_stage_init()
 * runs, so this file does the same minimal setup as test_tip_finalize_stage.c
 * (progress_store_open + main_state_init + tip_finalize_stage_init). */

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
     * rollup call: datadir-reading dumpers resolve paths through
     * diag_datadir(), and an empty datadir falls back to the default live
     * datadir under $HOME (not spelled out here:
     * tools/lint/lintc/gate_live_datadir_isolation.c counts the literal string
     * even inside a comment). main_state stays NULL. */
    diagnostics_controller_set_state(NULL, dir);

    struct main_state ms;
    memset(&ms, 0, sizeof(ms));
    main_state_init(&ms);
    bool tf_ok = tip_finalize_stage_init(&ms);

    /* ── (a) baseline: dump is well-formed; known-healthy exemplars stay
     * absent (no blanket all_ok==true: uninitialised stages report ok=false) ─ */
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
        /* >= 1, not == 1: many subsystems report ok=false here because this
         * fixture never initialises them. The blocker seeded above must be
         * IN the array; (d) below flips one specific dumper. */
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
         * engine/modules/storage/src/mempool_projection.c's `_health` block). */
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
