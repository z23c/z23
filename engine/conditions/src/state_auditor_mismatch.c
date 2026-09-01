/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * state_auditor_mismatch — self-heal condition that fires when the
 * state_auditor background scrubber (services/state_auditor.h) has
 * CONFIRMED a stored-vs-recomputed integrity mismatch, and raises a typed
 * named blocker naming the index and height range. See
 * conditions/state_auditor_mismatch.h for the SYMPTOM/REMEDY/WITNESS
 * contract. */

#include "conditions/state_auditor_mismatch.h"

#include "framework/condition.h"
#include "services/state_auditor.h"
#include "util/blocker.h"
#include "util/log_macros.h"

#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

#ifdef ZCL_TESTING
static _Atomic int g_test_remedy_calls;
#endif

/* Build the typed blocker id for a leg. */
/* blocker-id: state_auditor.*.mismatch */
static void mismatch_blocker_id(enum state_auditor_leg leg, char *out,
                                size_t cap)
{
    snprintf(out, cap, "state_auditor.%s.mismatch",
             state_auditor_leg_name(leg));
}

static bool detect_state_auditor_mismatch(void)
{
    for (int leg = 0; leg < STATE_AUDITOR_LEG_COUNT; leg++) {
        struct state_auditor_mismatch_info info;
        if (state_auditor_get_mismatch((enum state_auditor_leg)leg, &info) &&
            info.latched)
            return true;
    }
    return false;
}

static enum condition_remedy_result remedy_state_auditor_mismatch(void)
{
    bool any = false;
    for (int leg = 0; leg < STATE_AUDITOR_LEG_COUNT; leg++) {
        struct state_auditor_mismatch_info info;
        if (!state_auditor_get_mismatch((enum state_auditor_leg)leg, &info) ||
            !info.latched)
            continue;
        any = true;

        char id[BLOCKER_ID_MAX];
        mismatch_blocker_id((enum state_auditor_leg)leg, id, sizeof(id));

        /* Non-destructive: raise/refresh a typed DEPENDENCY blocker naming the
         * exact leg + range. No store is touched, no cursor rewound, no
         * repair attempted — a corrupted stored commitment has no SAFE
         * auto-repair (see state_auditor.h); the fix is an operator/backfill
         * rebuild (op_return_index_truncate + re-derive, or a checkpoint
         * resync), which the witness below detects honestly. */
        char reason[BLOCKER_REASON_MAX];
        snprintf(reason, sizeof(reason),
                 "%s integrity mismatch confirmed at height range [%d,%d]: %s",
                 state_auditor_leg_name((enum state_auditor_leg)leg),
                 info.h_start, info.h_end, info.detail);
        struct blocker_record r;
        if (blocker_init(&r, id, "state_auditor", BLOCKER_DEPENDENCY, reason)) {
            r.escape_deadline_secs = 0; /* no auto-escape; witness clears it */
            (void)blocker_set(&r);
        }
        LOG_WARN("condition",
                 "[condition:state_auditor_mismatch] raised blocker %s: %s",
                 id, reason);
    }

#ifdef ZCL_TESTING
    if (any) atomic_fetch_add(&g_test_remedy_calls, 1);
#endif
    return any ? COND_REMEDY_OK : COND_REMEDY_SKIP;
}

static bool witness_state_auditor_mismatch(int64_t target_at_detect)
{
    (void)target_at_detect;
    // honest-witness-ok: state_auditor_get_mismatch()'s `latched` bit is not
    // an FSM/poison-absence flag — it is the live outcome of state_auditor's
    // OWN independent supervisor-driven re-verification (chain.state_auditor,
    // STATE_AUDITOR_PERIOD_SECS cadence), which keeps RE-READING the exact
    // pinned window's ground truth (the on-disk block body for op_return_
    // index, or a fresh coins_kv-vs-utxos SHA256/XOR recompute for
    // coins_commitment) every tick while a mismatch is under investigation —
    // see services/state_auditor.h "investigating" state. By the time this
    // witness runs (witness_window_secs later), several MORE independent
    // re-checks of that same window have already happened; `latched==false`
    // means the most recent one came back clean, i.e. the symptom's
    // underlying external state provably moved. The re-verification runs on
    // its own supervised cadence rather than inline in this call, but it is
    // real external-state (disk/DB) observation, not a cached decision.
    bool all_clear = true;
    for (int leg = 0; leg < STATE_AUDITOR_LEG_COUNT; leg++) {
        struct state_auditor_mismatch_info info;
        bool ok = state_auditor_get_mismatch((enum state_auditor_leg)leg,
                                             &info);
        if (ok && info.latched) {
            all_clear = false;
            continue;
        }
        /* Honest witness: state_auditor's OWN re-check of the exact pinned
         * window came back clean (real progress — see the header contract),
         * so release that leg's blocker. blocker_clear is a no-op if the id
         * was never raised. */
        char id[BLOCKER_ID_MAX];
        mismatch_blocker_id((enum state_auditor_leg)leg, id, sizeof(id));
        blocker_clear(id);
    }
    return all_clear;
}

static struct condition c_state_auditor_mismatch = {
    .name = "state_auditor_mismatch",
    .severity = COND_WARN,
    .poll_secs = 5,
    .backoff_secs = 60,
    .max_attempts = 5,
    /* Rearm-forever (peer_floor's / catalog_lag_exceeded's posture): a
     * confirmed corruption has no bounded-attempt auto-fix here — after the
     * page ladder, keep nudging every 10 min, unbounded, until an operator
     * or backfill rebuild clears it. The episode resets when detect() goes
     * false (state_auditor's own re-check cleared every leg). */
    .cooldown_secs = 600,
    .cooldown_max_rearms = 0,
    .detect = detect_state_auditor_mismatch,
    .remedy = remedy_state_auditor_mismatch,
    .witness = witness_state_auditor_mismatch,
    .witness_window_secs = 60,
};

void register_state_auditor_mismatch(void)
{
    (void)condition_register(&c_state_auditor_mismatch);
}

#ifdef ZCL_TESTING
int state_auditor_mismatch_test_remedy(void)
{
    return (int)remedy_state_auditor_mismatch();
}

bool state_auditor_mismatch_test_detect(void)
{
    return detect_state_auditor_mismatch();
}

bool state_auditor_mismatch_test_witness(void)
{
    return witness_state_auditor_mismatch(0);
}

void state_auditor_mismatch_test_reset(void)
{
    atomic_store(&g_test_remedy_calls, 0);
}
#endif
