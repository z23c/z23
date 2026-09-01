/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_blocker_meta_detector -- the generic backstop for the "typed blocker
 * with an EMPTY escape_action holding H*" defect CLASS
 * (docs/work/tenacity-roadmap.md "Hold-class doctrine"; e.g. a
 * sapling-anchor P0 with no escape action). Hermetic + deterministic: the uptime clock and
 * H* are injected, the blocker registry is the real one, and the escalator is
 * driven through its real note_stall/armed seam -- no live chain, no DB.
 *
 * The stall-totality-matrix dichotomy applied to the meta layer:
 *   FIRE  -- an empty-escape blocker + frozen H* past the window -> the detector
 *            fires, arms the sticky escalator, names the offending blocker id in
 *            its detail dump, and the engine pages the operator.
 *   NO-FIRE with escape -- a blocker WITH an escape_action is not the defect.
 *   NO-FIRE advancing   -- H* climbing keeps resetting the frozen window.
 *   NO-FIRE flapping    -- ANY H* movement re-arms the window (hysteresis holds).
 *   WITNESS -- H* climbing past the detect baseline is the sole clear-edge. */

#include "test/test_core.h"

#include "conditions/blocker_stall_meta_detector.h"
#include "conditions/condition_registry.h"
#include "event/event.h"
#include "framework/condition.h"
#include "jobs/reducer_frontier.h"
#include "json/json.h"
#include "services/sticky_escalator.h"
#include "util/blocker.h"

#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define BMD_CHECK(name, expr) do {                              \
    printf("blocker_meta_detector: %s... ", (name));            \
    if ((expr)) printf("OK\n");                                 \
    else { printf("FAIL\n"); failures++; }                      \
} while (0)

#define BMD_WIN_US ((int64_t)BLOCKER_STALL_META_DEFAULT_SECS * 1000000)

static _Atomic int g_operator_events;

static void bmd_operator_observer(enum event_type type, uint32_t peer_id,
                                  const void *payload, uint32_t payload_len,
                                  void *ctx)
{
    (void)type; (void)peer_id; (void)payload; (void)payload_len; (void)ctx;
    atomic_fetch_add(&g_operator_events, 1);
}

/* Set (or refresh) a typed blocker; escape==NULL leaves escape_action empty
 * (the defect shape), non-NULL sets it (the healthy shape). */
static void bmd_set_blocker(const char *id, const char *escape)
{
    struct blocker_record r;
    blocker_init(&r, id, "bmd_test", BLOCKER_TRANSIENT, "meta-detector fixture");
    if (escape)
        snprintf(r.escape_action, sizeof(r.escape_action), "%s", escape);
    (void)blocker_set(&r);
}

/* Fresh module + registry state before each case. */
static void bmd_reset(void)
{
    blocker_reset_for_testing();
    reducer_frontier_provable_tip_reset();
    blocker_stall_meta_detector_test_reset();
    sticky_escalator_test_reset();
}

/* Read the detail-dumped first_offender_id for this condition from the real
 * engine state dump (the _health/dump surface). "" when absent. */
static const char *bmd_dumped_offender(struct json_value *dump)
{
    const struct json_value *conds = json_get(dump, "conditions");
    if (!conds)
        return "";
    for (size_t i = 0; i < json_size(conds); i++) {
        const struct json_value *c = json_at(conds, i);
        const struct json_value *n = c ? json_get(c, "name") : NULL;
        if (!n || strcmp(json_get_str(n),
                         BLOCKER_STALL_META_CONDITION_NAME) != 0)
            continue;
        const struct json_value *d = json_get(c, "detail");
        const struct json_value *o = d ? json_get(d, "first_offender_id") : NULL;
        return o ? json_get_str(o) : "";
    }
    return "";
}

int test_blocker_meta_detector(void);
int test_blocker_meta_detector(void)
{
    printf("\n=== blocker_meta_detector tests ===\n");
    int failures = 0;

    blocker_module_init();

    /* ── FIRE: empty-escape blocker + frozen H* -> detect, arm, page ──────── */
    {
        condition_engine_reset_for_testing();
        event_log_init();
        bmd_reset();
        atomic_store(&g_operator_events, 0);
        event_observe(EV_OPERATOR_NEEDED, bmd_operator_observer, NULL);
        register_blocker_stall_meta_detector();

        BMD_CHECK("condition registered in the engine",
                  condition_engine_has_registered(
                      BLOCKER_STALL_META_CONDITION_NAME));

        const int32_t H = 3056760;
        reducer_frontier_provable_tip_set(H);
        bmd_set_blocker("fixture.empty_escape", NULL);   /* the defect shape */

        /* Prime: first H* sample stamps the frozen window and returns false. */
        const int64_t t0 = 1000000;
        blocker_stall_meta_detector_test_set_clock_us(t0);
        condition_engine_tick();
        BMD_CHECK("no fire before the window elapses (first sample)",
                  condition_engine_get_active_count() == 0 &&
                  !sticky_escalator_test_armed());

        /* Jump the uptime clock past the frozen-H* window with H* held. */
        blocker_stall_meta_detector_test_set_clock_us(t0 + BMD_WIN_US + 1000000);
        for (int i = 0; i < 8; i++) {
            blocker_stall_meta_detector_test_clear_cadence();
            condition_engine_tick();
        }

        BMD_CHECK("detector fired (condition active)",
                  condition_engine_get_active_count() == 1);
        BMD_CHECK("sticky escalator ARMED (auto-terminating remedy)",
                  sticky_escalator_test_armed());
        BMD_CHECK("remedy dispatched at least once",
                  blocker_stall_meta_detector_test_remedy_calls() >= 1);
        BMD_CHECK("operator PAGED via the condition-engine path",
                  atomic_load(&g_operator_events) >= 1 &&
                  condition_engine_get_unresolved_count() == 1);

        /* The page names the offending blocker id (detail/_health surface). */
        struct json_value dump;
        json_init(&dump);
        json_set_object(&dump);
        BMD_CHECK("engine state dumps + names the offending blocker id",
                  condition_engine_dump_state_json(&dump, NULL) &&
                  strcmp(bmd_dumped_offender(&dump), "fixture.empty_escape") == 0);
        json_free(&dump);

        /* WITNESS: H* climbing past the detect baseline is the sole clear-edge. */
        reducer_frontier_provable_tip_set(H + 1);
        condition_engine_tick();
        BMD_CHECK("H* climb witnesses the clear (episode resolves)",
                  condition_engine_get_active_count() == 0 &&
                  condition_engine_get_unresolved_count() == 0);

        condition_engine_reset_for_testing();
    }

    /* ── NO-FIRE: a blocker WITH an escape_action is not the defect ───────── */
    {
        bmd_reset();
        const int32_t H = 3056760;
        reducer_frontier_provable_tip_set(H);
        bmd_set_blocker("fixture.has_escape", "refold_from_anchor");

        const int64_t t0 = 5000000;
        blocker_stall_meta_detector_test_set_clock_us(t0);
        (void)blocker_stall_meta_detector_test_detect();          /* prime */
        blocker_stall_meta_detector_test_set_clock_us(t0 + BMD_WIN_US + 1000000);
        BMD_CHECK("blocker WITH escape_action -> no fire even past the window",
                  !blocker_stall_meta_detector_test_detect() &&
                  blocker_stall_meta_detector_test_remedy_calls() == 0);
    }

    /* ── NO-FIRE: H* advancing keeps resetting the frozen window ──────────── */
    {
        bmd_reset();
        bmd_set_blocker("fixture.empty_escape", NULL);   /* defect present */
        int32_t H = 3056760;
        int64_t now = 2000000;
        bool ever_fired = false;
        for (int i = 0; i < 10; i++) {
            reducer_frontier_provable_tip_set(H + i);            /* H* climbs */
            now += BMD_WIN_US;                                   /* long gap */
            blocker_stall_meta_detector_test_set_clock_us(now);
            if (blocker_stall_meta_detector_test_detect())
                ever_fired = true;
        }
        BMD_CHECK("advancing H* never fires (window re-arms on each climb)",
                  !ever_fired);
    }

    /* ── NO-FIRE: flapping H* -> ANY movement re-arms (hysteresis holds) ──── */
    {
        bmd_reset();
        bmd_set_blocker("fixture.empty_escape", NULL);
        const int32_t A = 3056760, B = 3056761;
        int64_t now = 3000000;
        bool ever_fired = false;
        for (int i = 0; i < 12; i++) {
            reducer_frontier_provable_tip_set((i & 1) ? A : B); /* flap */
            now += BMD_WIN_US / 2;      /* < window since last change each step */
            blocker_stall_meta_detector_test_set_clock_us(now);
            if (blocker_stall_meta_detector_test_detect())
                ever_fired = true;
        }
        BMD_CHECK("flapping H* never fires (hysteresis: movement re-arms)",
                  !ever_fired);
    }

    /* ── Registration is wired into condition_registry_register_all ───────── */
    {
        condition_engine_reset_for_testing();
        condition_registry_register_all();
        BMD_CHECK("wired into the registry register-all",
                  condition_engine_has_registered(
                      BLOCKER_STALL_META_CONDITION_NAME));
        condition_engine_reset_for_testing();
    }

    return failures;
}
