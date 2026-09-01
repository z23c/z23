/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * blocker_stall_meta_detector -- generic backstop for the "typed blocker with
 * an EMPTY escape_action holding H*" defect class. See the header for doctrine.
 *
 * Detect signal (ALL must hold):
 *   1. At least one ACTIVE typed blocker has an empty escape_action.
 *   2. H* (reducer_frontier provable tip) has not advanced for > T seconds
 *      (default 900; ZCL_BLOCKER_META_STALL_SECS), uptime-clocked with a
 *      movement-reset hysteresis (ANY H* change re-arms the window).
 *   3. Best-effort: the header tip is above H* (there is pending work to fold)
 *      -- skipped when main_state is unavailable so the backstop still engages.
 *
 * Remedy: arm the sticky escalator (its deepest rung is the real
 * refold-from-anchor) and let the condition engine page the operator naming
 * this condition; the offending blocker id is named in the WARN + the detail
 * dump. Never a fake resolve. Witness (sole clear-edge): H* climbed past the
 * height captured at the rising edge of the episode.
 *
 * This condition is GENERIC: it has ZERO knowledge of any specific blocker id.
 * The instance cures (e.g. sapling_anchor_frontier_unavailable) resolve their
 * blocker before this backstop's window elapses; this catches the ones that
 * slip through -- an empty-escape blocker that nobody cures. */

#include "conditions/blocker_stall_meta_detector.h"

#include "framework/condition.h"
#include "jobs/reducer_frontier.h"
#include "platform/time_compat.h"
#include "services/sticky_escalator.h"
#include "util/blocker.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"

#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BSM_COND_NAME BLOCKER_STALL_META_CONDITION_NAME
#define BSM_SUBSYS    "condition"

/* H* movement tracking (movement-reset hysteresis). g_last_hstar = the H*
 * observed on the previous tick; g_hstar_changed_us = the uptime (monotonic us)
 * at which H* last changed. Serial condition-engine tick thread only for the
 * detect() writes; atomics so the diagnostics-thread detail() read is safe. */
static _Atomic int32_t g_last_hstar = -1;
static _Atomic int64_t g_hstar_changed_us = -1;   /* -1 = not yet observed */

/* H* captured at the rising edge of an episode; the witness clears only when H*
 * climbs strictly past it. -1 = no active episode. */
static _Atomic int32_t g_hstar_at_detect = -1;

#ifdef ZCL_TESTING
static _Atomic int64_t g_test_now_us = -1;       /* >= 0 overrides the clock */
static _Atomic int     g_test_remedy_calls;
#endif

static int64_t bsm_now_us(void)
{
#ifdef ZCL_TESTING
    int64_t t = atomic_load(&g_test_now_us);
    if (t >= 0)
        return t;
#endif
    return platform_time_monotonic_us();
}

/* Configurable frozen-H* window, in microseconds. */
static int64_t bsm_window_us(void)
{
    const char *v = getenv("ZCL_BLOCKER_META_STALL_SECS");
    if (v && v[0]) {
        long t = strtol(v, NULL, 10);
        if (t > 0)
            return (int64_t)t * 1000000;
    }
    return (int64_t)BLOCKER_STALL_META_DEFAULT_SECS * 1000000;
}

/* Count active blockers with an EMPTY escape_action; copy the FIRST such id
 * into out_id (when non-NULL). Returns the count, or -1 on an allocation
 * failure (treated by callers as "cannot determine" -> no detect). */
static int bsm_scan_empty_escape(char out_id[BLOCKER_ID_MAX])
{
    if (out_id)
        out_id[0] = '\0';
    struct blocker_snapshot *snaps =
        zcl_malloc(sizeof(*snaps) * BLOCKER_CAP, "bsm_blocker_scan");
    if (!snaps)
        LOG_RETURN(-1, BSM_SUBSYS, "blocker snapshot alloc failed");

    int n = blocker_snapshot_all(snaps, BLOCKER_CAP);
    int found = 0;
    for (int i = 0; i < n; i++) {
        if (snaps[i].escape_action[0] == '\0') {
            if (found == 0 && out_id)
                snprintf(out_id, BLOCKER_ID_MAX, "%s", snaps[i].id);
            found++;
        }
    }
    free(snaps);
    return found;
}

/* Best-effort "there is pending work below H*" gate. Returns true when we can
 * POSITIVELY confirm the node is at tip (header tip <= H*) and therefore not
 * stalled; false otherwise (including when main_state is unavailable, so the
 * backstop still engages on the blocker + frozen-H* evidence alone). */
static bool bsm_positively_at_tip(int32_t hstar)
{
    struct main_state *ms = condition_engine_main_state();
    if (!ms)
        return false;
    int header_tip = active_chain_height(&ms->chain_active);
    if (header_tip < 0)
        return false;
    return header_tip <= hstar;
}

/* The shared detect core: pure over its inputs (H* + uptime), so the ZCL_TESTING
 * seam can drive it deterministically through the real path. Updates the
 * movement-reset hysteresis, then decides. */
static bool bsm_detect_core(void)
{
    int32_t hstar = reducer_frontier_provable_tip_cached();
    int64_t now = bsm_now_us();
    if (hstar < 0)
        return false;  // raw-return-ok:H* unavailable, nothing to judge

    /* Movement-reset hysteresis: ANY H* change re-arms the frozen window. On
     * the first observation this stamps a fresh window (boot grace). */
    int32_t last = atomic_load(&g_last_hstar);
    if (hstar != last || atomic_load(&g_hstar_changed_us) < 0) {
        atomic_store(&g_last_hstar, hstar);
        atomic_store(&g_hstar_changed_us, now);
        return false;  // raw-return-ok:H* just moved (or first sample) -> not stalled
    }

    /* Positively at tip => not a stall, whatever a lingering blocker says. */
    if (bsm_positively_at_tip(hstar))
        return false;  // raw-return-ok:header tip not above H*, no pending work

    /* Any active blocker with an empty escape_action is the defect signal. */
    char blocker_id[BLOCKER_ID_MAX];
    int empty = bsm_scan_empty_escape(blocker_id);
    if (empty <= 0)
        return false;  // raw-return-ok:no empty-escape blocker (or scan failed)

    /* H* frozen long enough? */
    int64_t frozen = now - atomic_load(&g_hstar_changed_us);
    if (frozen < bsm_window_us())
        return false;  // raw-return-ok:within the frozen-H* grace window

    /* Rising edge: capture the H* baseline the witness clears against. */
    struct condition_runtime_snapshot snap;
    bool already_active =
        condition_engine_get_registered_snapshot(BSM_COND_NAME, &snap) &&
        snap.currently_active;
    if (!already_active) {
        atomic_store(&g_hstar_at_detect, hstar);
        LOG_WARN(BSM_SUBSYS,
                 "[condition:%s] DEFECT CLASS: %d blocker(s) active with an "
                 "empty escape_action while H*=%d frozen for %llds (>= %llds) "
                 "-- first offender id=%s. Arming the escalator + paging.",
                 BSM_COND_NAME, empty, (int)hstar,
                 (long long)(frozen / 1000000),
                 (long long)(bsm_window_us() / 1000000),
                 blocker_id[0] ? blocker_id : "(unnamed)");
    }
    return true;
}

static bool detect_blocker_stall_meta(void)
{
    return bsm_detect_core();
}

static enum condition_remedy_result remedy_blocker_stall_meta(void)
{
#ifdef ZCL_TESTING
    atomic_fetch_add(&g_test_remedy_calls, 1);
#endif
    /* Re-confirm the class defect still holds; if the offending blocker was
     * cured (or given an escape) in the interim, there is nothing to arm. */
    char blocker_id[BLOCKER_ID_MAX];
    int empty = bsm_scan_empty_escape(blocker_id);
    if (empty <= 0)
        return COND_REMEDY_SKIP;

    /* Arm the ALWAYS-TERMINATING remedy ladder. sticky_escalator_note_stall is
     * idempotent + reentrant-safe (re-arm, never spam); the ladder's deepest
     * rung is the real refold-from-anchor. This is the backstop's whole job --
     * a generic empty-escape stall gets the generic terminating remedy. The
     * engine pages the operator (EV_OPERATOR_NEEDED, this condition's name)
     * after max_attempts un-witnessed remedies; the blocker id is named here
     * and in the detail dump. */
    sticky_escalator_note_stall("blocker-empty-escape-stall");
    LOG_WARN(BSM_SUBSYS,
             "[condition:%s] armed the sticky escalator for %d empty-escape "
             "blocker(s); first offender id=%s (H* must climb to clear)",
             BSM_COND_NAME, empty, blocker_id[0] ? blocker_id : "(unnamed)");
    /* OK = armed. The witness (H* climb) is the sole clear-edge; if the ladder
     * does not lift H*, the engine downgrades to unwitnessed and pages. */
    return COND_REMEDY_OK;
}

static bool witness_blocker_stall_meta(int64_t target_at_detect)
{
    /* The engine passes a wall-clock timestamp; ignore it and read our own
     * captured H* baseline. */
    (void)target_at_detect;
    int32_t base = atomic_load(&g_hstar_at_detect);
    if (base < 0)
        return false;
    int32_t now = reducer_frontier_provable_tip_cached();
    if (now < 0)
        return false;              /* read failure = not-yet-cleared */
    return now > base;             /* H* climbed past the frozen height */
}

static bool detail_blocker_stall_meta(struct json_value *out)
{
    if (!out)
        return false;
    char blocker_id[BLOCKER_ID_MAX];
    int empty = bsm_scan_empty_escape(blocker_id);   /* own local; thread-safe */
    int64_t changed = atomic_load(&g_hstar_changed_us);
    int64_t frozen_secs = (changed >= 0) ? (bsm_now_us() - changed) / 1000000 : -1;
    return json_push_kv_int(out, "empty_escape_blocker_count", empty) &&
           json_push_kv_str(out, "first_offender_id",
                            (empty > 0 && blocker_id[0]) ? blocker_id : "") &&
           json_push_kv_int(out, "hstar_at_detect",
                            atomic_load(&g_hstar_at_detect)) &&
           json_push_kv_int(out, "hstar_frozen_secs", frozen_secs) &&
           json_push_kv_int(out, "window_secs", bsm_window_us() / 1000000);
}

static struct condition c_blocker_stall_meta_detector = {
    .name = BSM_COND_NAME,
    .severity = COND_CRITICAL,
    .poll_secs = 15,
    .backoff_secs = 60,
    /* Bounded: after this many un-witnessed armings the engine pages the
     * operator. The escalator keeps working (its deepest rung re-arms with a
     * cooldown); the page is a non-latching "attention welcome", never a stop. */
    .max_attempts = 5,
    .detect = detect_blocker_stall_meta,
    .remedy = remedy_blocker_stall_meta,
    .witness = witness_blocker_stall_meta,
    .detail = detail_blocker_stall_meta,
    .witness_window_secs = 120,
};

void register_blocker_stall_meta_detector(void)
{
    (void)condition_register(&c_blocker_stall_meta_detector);
}

#ifdef ZCL_TESTING
void blocker_stall_meta_detector_test_reset(void)
{
    atomic_store(&g_last_hstar, -1);
    atomic_store(&g_hstar_changed_us, -1);
    atomic_store(&g_hstar_at_detect, -1);
    atomic_store(&g_test_now_us, -1);
    atomic_store(&g_test_remedy_calls, 0);
    condition_reset_state(&c_blocker_stall_meta_detector);
}

void blocker_stall_meta_detector_test_set_clock_us(int64_t now_us)
{
    atomic_store(&g_test_now_us, now_us);
}

bool blocker_stall_meta_detector_test_detect(void)
{
    return bsm_detect_core();
}

int blocker_stall_meta_detector_test_remedy_calls(void)
{
    return atomic_load(&g_test_remedy_calls);
}

void blocker_stall_meta_detector_test_clear_cadence(void)
{
    struct condition_state *s = &c_blocker_stall_meta_detector.state;
    atomic_store(&s->last_poll_unix, (int64_t)0);
    atomic_store(&s->last_remedy_unix, (int64_t)0);
}
#endif
