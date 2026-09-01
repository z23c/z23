/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_refold_cadence — the PARITY-SAFETY guard for the mint/refold fold
 * cadence override (engine/jobs/src/refold_cadence.c).
 *
 * The override changes HOW MANY blocks each reducer stage folds per drain (the
 * batch) and HOW OFTEN the supervisor drives them (the tick period). The
 * load-bearing safety property is that on a NORMAL live node — no refold in
 * progress, no -mint-anchor fold ceiling set — the override is INERT:
 * refold_cadence_drain_batch returns its argument UNCHANGED and
 * refold_cadence_tick_period_us returns 0 (⇒ the caller uses its unmodified
 * 2s period_secs). This test pins that: a future edit that changes the
 * normal-mode batch or period fails here.
 *
 * It also proves the override FIRES (and honors its env knobs) when either gate
 * is active — a -mint-anchor mint (mint_fold_ceiling_set) or a -refold-*
 * fold (refold_progress cache) — and that clearing the gate RESTORES the inert
 * identity, so the accelerated cadence cannot leak into the live path. */

#include "test/test_core.h"

#include "jobs/refold_cadence.h"
#include "jobs/refold_progress.h"     /* refold_progress_test_set_cached */
#include "jobs/mint_fold_ceiling.h"   /* mint_fold_ceiling_set, MINT_FOLD_NO_CEILING */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define RC_CHECK(name, expr) do {                                  \
    printf("refold_cadence: %s... ", (name));                      \
    if (expr) { printf("OK\n"); }                                  \
    else { printf("FAIL\n"); failures++; }                         \
} while (0)

/* Force BOTH gates off — the normal live-node state. */
static void rc_clear_gates(void)
{
    mint_fold_ceiling_set(MINT_FOLD_NO_CEILING);
    refold_progress_test_set_cached(false);
    unsetenv("ZCL_REFOLD_DRAIN_BATCH");
    unsetenv("ZCL_REFOLD_TICK_MS");
}

/* (1) NORMAL live node: the override is inert — batch is the stage default,
 * tick period is 0 (⇒ the 2s period_secs is used unchanged). This is the
 * byte-for-byte-unchanged proof. */
static int case_normal_inert(void)
{
    int failures = 0;
    rc_clear_gates();

    RC_CHECK("normal: not active", !refold_cadence_active());
    /* Batch is the caller's argument, verbatim, at every stage default. */
    RC_CHECK("normal: batch 100 unchanged",  refold_cadence_drain_batch(100)  == 100);
    RC_CHECK("normal: batch 64 unchanged",   refold_cadence_drain_batch(64)   == 64);
    RC_CHECK("normal: batch 500 unchanged",  refold_cadence_drain_batch(500)  == 500);
    /* Tick override off ⇒ 0 ⇒ caller keeps its 2s period_secs. */
    RC_CHECK("normal: tick period 0", refold_cadence_tick_period_us() == 0);

    /* Even with the env knobs SET, an inactive gate keeps the override inert —
     * the env must never leak into the live path. */
    setenv("ZCL_REFOLD_DRAIN_BATCH", "9999", 1);
    setenv("ZCL_REFOLD_TICK_MS", "10", 1);
    RC_CHECK("normal: env ignored when inactive (batch)",
             refold_cadence_drain_batch(100) == 100);
    RC_CHECK("normal: env ignored when inactive (tick)",
             refold_cadence_tick_period_us() == 0);
    unsetenv("ZCL_REFOLD_DRAIN_BATCH");
    unsetenv("ZCL_REFOLD_TICK_MS");

    rc_clear_gates();
    return failures;
}

/* (2) -mint-anchor active (fold ceiling set): the accelerated defaults apply,
 * and the env knobs tune them. */
static int case_mint_active(void)
{
    int failures = 0;
    rc_clear_gates();

    mint_fold_ceiling_set(3056758);   /* the real anchor; any real height arms it */
    RC_CHECK("mint: active", refold_cadence_active());

    /* Defaults (env unset). */
    RC_CHECK("mint: default batch 2000",
             refold_cadence_drain_batch(100) == REFOLD_CADENCE_DEFAULT_DRAIN_BATCH);
    RC_CHECK("mint: default tick 250ms",
             refold_cadence_tick_period_us() ==
                 (int64_t)REFOLD_CADENCE_DEFAULT_TICK_MS * 1000);

    /* Env override. */
    setenv("ZCL_REFOLD_DRAIN_BATCH", "4000", 1);
    setenv("ZCL_REFOLD_TICK_MS", "100", 1);
    RC_CHECK("mint: env batch 4000", refold_cadence_drain_batch(100) == 4000);
    RC_CHECK("mint: env tick 100ms",
             refold_cadence_tick_period_us() == 100 * 1000);

    /* Clamps: absurd values are bounded, never returned raw. */
    setenv("ZCL_REFOLD_DRAIN_BATCH", "0", 1);        /* below floor → clamp to 1 */
    RC_CHECK("mint: batch clamp low", refold_cadence_drain_batch(100) == 1);
    setenv("ZCL_REFOLD_TICK_MS", "999999", 1);       /* above ceiling → 60000 */
    RC_CHECK("mint: tick clamp high",
             refold_cadence_tick_period_us() == (int64_t)60000 * 1000);

    rc_clear_gates();
    return failures;
}

/* (3) -refold-* active (progress cache set): same override; then clearing the
 * gate RESTORES the inert identity (no leak into the live path). */
static int case_refold_active_then_restore(void)
{
    int failures = 0;
    rc_clear_gates();

    refold_progress_test_set_cached(true);
    RC_CHECK("refold: active", refold_cadence_active());
    RC_CHECK("refold: default batch 2000",
             refold_cadence_drain_batch(100) == REFOLD_CADENCE_DEFAULT_DRAIN_BATCH);
    RC_CHECK("refold: default tick 250ms",
             refold_cadence_tick_period_us() ==
                 (int64_t)REFOLD_CADENCE_DEFAULT_TICK_MS * 1000);

    /* Clear → back to byte-identical live cadence. */
    refold_progress_test_set_cached(false);
    RC_CHECK("restore: not active", !refold_cadence_active());
    RC_CHECK("restore: batch 100 unchanged", refold_cadence_drain_batch(100) == 100);
    RC_CHECK("restore: tick period 0", refold_cadence_tick_period_us() == 0);

    rc_clear_gates();
    return failures;
}

int test_refold_cadence(void)
{
    int failures = 0;
    failures += case_normal_inert();
    failures += case_mint_active();
    failures += case_refold_active_then_restore();
    if (failures == 0)
        printf("test_refold_cadence: ALL PASSED\n");
    else
        printf("test_refold_cadence: %d FAILURE(S)\n", failures);
    return failures;
}
