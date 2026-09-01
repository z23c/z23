/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_validate_headers_tuning — the PARITY-SAFETY guard for the
 * validate_headers pool-width / forward-batch override
 * (engine/jobs/src/validate_headers_tuning.c).
 *
 * The override changes HOW MANY headers the stage Equihash-verifies at once.
 * The load-bearing safety property is that on a NORMAL live node — no refold in
 * progress, no -mint-anchor fold ceiling — it is INERT: vh_runtime_pool_size()
 * is VH_POOL_SIZE and vh_runtime_batch_size() is VH_BATCH_SIZE, and NEITHER
 * ZCL_VH_POOL nor ZCL_VH_BATCH can widen them. This test pins that: an edit
 * that lets the environment reach the live path fails here.
 *
 * It also proves the override FIRES with its accelerated defaults under either
 * fold gate, honors + clamps its env knobs there, and that clearing the gate
 * RESTORES the inert identity.
 *
 * A second override — the live catch-up pool widening — is pinned the same
 * way: ONLY while catchup_cadence_active() (peers connected + gap >=
 * threshold, driven here with the same connman/log_head fixture
 * test_catchup_cadence.c uses) does vh_runtime_pool_size() scale to
 * min(nproc, VH_CATCHUP_POOL_CAP) or ZCL_VH_CATCHUP_POOL_SIZE; the per-step
 * batch stays VH_BATCH_SIZE, the fold knobs stay fold-only, and the fold gate
 * still wins over catch-up. validate_headers_stage_catchup_step_cap() (the
 * supervisor's A12 fan-out loosening) is pinned here too: identity when
 * inactive, pool-scale x normal (max VH_CATCHUP_STEP_MULT) when active. */

#include "test/test_core.h"

#include "../../../engine/jobs/src/validate_headers_internal.h"

#include "jobs/validate_headers_stage.h"
#include "jobs/catchup_cadence.h"
#include "jobs/refold_cadence.h"
#include "jobs/refold_progress.h"     /* refold_progress_test_set_cached */
#include "jobs/mint_fold_ceiling.h"   /* mint_fold_ceiling_set, MINT_FOLD_NO_CEILING */
#include "net/connman.h"
#include "net/protocol.h"
#include "services/sync_monitor.h"
#include "util/sync.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define VHT_CHECK(name, expr) do {                                 \
    printf("validate_headers_tuning: %s... ", (name));             \
    if (expr) { printf("OK\n"); }                                  \
    else { printf("FAIL\n"); failures++; }                         \
} while (0)

/* Force BOTH fold gates off, the catch-up fixture off, and the knobs unset —
 * the live-node state. */
static void vht_clear_gates(void)
{
    mint_fold_ceiling_set(MINT_FOLD_NO_CEILING);
    refold_progress_test_set_cached(false);
    catchup_cadence_test_reset();
    sync_monitor_set_context(NULL, NULL, NULL);
    unsetenv("ZCL_VH_POOL");
    unsetenv("ZCL_VH_BATCH");
    unsetenv("ZCL_VH_CATCHUP_POOL_SIZE");
}

/* Arm the live catch-up gate: one peer at `tip`, log_head forced to 0. */
static void vht_arm_catchup(struct connman *cm, struct p2p_node *peer,
                            int tip)
{
    memset(cm, 0, sizeof(*cm));
    zcl_mutex_init(&cm->manager.cs_nodes);
    memset(peer, 0, sizeof(*peer));
    peer->id = 1;
    peer->starting_height = tip;
    peer->state = PEER_ACTIVE;
    peer->services = NODE_NETWORK;
    static struct p2p_node *peers[1];
    peers[0] = peer;
    cm->manager.nodes = peers;
    cm->manager.num_nodes = 1;
    sync_monitor_set_context(cm, NULL, NULL);
    catchup_cadence_test_set_log_head_override(0);
}

static int vht_nproc(void)
{
    long n = sysconf(_SC_NPROCESSORS_ONLN);
    if (n < 1) n = 1;
    if (n > VH_CATCHUP_POOL_CAP) n = VH_CATCHUP_POOL_CAP;
    return (int)n;
}

/* (1) NORMAL live node: compile-time widths, and the env cannot reach them. */
static int case_normal_inert(void)
{
    int failures = 0;
    vht_clear_gates();

    VHT_CHECK("normal: not active", !refold_cadence_active());
    VHT_CHECK("normal: pool = VH_POOL_SIZE",
              vh_runtime_pool_size() == VH_POOL_SIZE);
    VHT_CHECK("normal: batch = VH_BATCH_SIZE",
              vh_runtime_batch_size() == VH_BATCH_SIZE);

    setenv("ZCL_VH_POOL", "64", 1);
    setenv("ZCL_VH_BATCH", "2048", 1);
    setenv("ZCL_VH_CATCHUP_POOL_SIZE", "64", 1);
    VHT_CHECK("normal: env ignored when inactive (pool)",
              vh_runtime_pool_size() == VH_POOL_SIZE);
    VHT_CHECK("normal: env ignored when inactive (batch)",
              vh_runtime_batch_size() == VH_BATCH_SIZE);
    VHT_CHECK("normal: catch-up pool env ignored when inactive",
              vh_runtime_pool_size() == VH_POOL_SIZE);
    VHT_CHECK("normal: step cap identity when inactive",
              validate_headers_stage_catchup_step_cap(VH_BATCH_PER_TICK)
                  == VH_BATCH_PER_TICK);

    vht_clear_gates();
    return failures;
}

/* (2) -mint-anchor active: accelerated defaults, env tuning, clamps. */
static int case_mint_active(void)
{
    int failures = 0;
    vht_clear_gates();

    mint_fold_ceiling_set(3056758);   /* the real anchor; any real height arms it */
    VHT_CHECK("mint: active", refold_cadence_active());

    VHT_CHECK("mint: default pool 16",
              vh_runtime_pool_size() == VH_FOLD_POOL_DEFAULT);
    VHT_CHECK("mint: default batch 256",
              vh_runtime_batch_size() == VH_FOLD_BATCH_DEFAULT);

    setenv("ZCL_VH_POOL", "32", 1);
    setenv("ZCL_VH_BATCH", "1024", 1);
    VHT_CHECK("mint: env pool 32",  vh_runtime_pool_size()  == 32);
    VHT_CHECK("mint: env batch 1024", vh_runtime_batch_size() == 1024);

    /* Clamps: absurd values are bounded, never returned raw. */
    setenv("ZCL_VH_POOL", "0", 1);
    VHT_CHECK("mint: pool clamp low", vh_runtime_pool_size() == 1);
    setenv("ZCL_VH_POOL", "999999", 1);
    VHT_CHECK("mint: pool clamp high", vh_runtime_pool_size() == VH_MAX_POOL);
    setenv("ZCL_VH_BATCH", "-5", 1);
    VHT_CHECK("mint: batch clamp low", vh_runtime_batch_size() == 1);
    setenv("ZCL_VH_BATCH", "999999", 1);
    VHT_CHECK("mint: batch clamp high",
              vh_runtime_batch_size() == VH_MAX_BATCH);

    /* Garbage falls back to the accelerated default, never to 0. */
    setenv("ZCL_VH_POOL", "not-a-number", 1);
    setenv("ZCL_VH_BATCH", "", 1);
    VHT_CHECK("mint: garbage pool -> default",
              vh_runtime_pool_size() == VH_FOLD_POOL_DEFAULT);
    VHT_CHECK("mint: empty batch -> default",
              vh_runtime_batch_size() == VH_FOLD_BATCH_DEFAULT);

    vht_clear_gates();
    return failures;
}

/* (3) -refold-* active, then clearing the gate RESTORES the inert identity. */
static int case_refold_active_then_restore(void)
{
    int failures = 0;
    vht_clear_gates();

    refold_progress_test_set_cached(true);
    VHT_CHECK("refold: active", refold_cadence_active());
    VHT_CHECK("refold: default pool 16",
              vh_runtime_pool_size() == VH_FOLD_POOL_DEFAULT);
    VHT_CHECK("refold: default batch 256",
              vh_runtime_batch_size() == VH_FOLD_BATCH_DEFAULT);

    /* An env knob set DURING the fold must not survive the gate clearing. */
    setenv("ZCL_VH_POOL", "128", 1);
    setenv("ZCL_VH_BATCH", "4096", 1);
    refold_progress_test_set_cached(false);
    VHT_CHECK("restore: not active", !refold_cadence_active());
    VHT_CHECK("restore: pool = VH_POOL_SIZE",
              vh_runtime_pool_size() == VH_POOL_SIZE);
    VHT_CHECK("restore: batch = VH_BATCH_SIZE",
              vh_runtime_batch_size() == VH_BATCH_SIZE);

    /* The pool array is statically sized to VH_MAX_POOL — a fold width can
     * never index past it. */
    VHT_CHECK("bound: fold pool default within VH_MAX_POOL",
              VH_FOLD_POOL_DEFAULT <= VH_MAX_POOL);
    VHT_CHECK("bound: fold batch default within VH_MAX_BATCH",
              VH_FOLD_BATCH_DEFAULT <= VH_MAX_BATCH);

    vht_clear_gates();
    return failures;
}

/* (4) Live catch-up active: pool widens to min(nproc,16) / the catch-up env
 * knob (clamped), the per-step batch does NOT widen, the fold knobs do not
 * leak, the fold gate still wins, and the A12 step cap tracks the pool
 * scale. Clearing the gate RESTORES the inert identity. */
static int case_catchup_active(void)
{
    int failures = 0;
    struct connman cm;
    struct p2p_node peer;
    vht_clear_gates();
    vht_arm_catchup(&cm, &peer, 100000);
    VHT_CHECK("catchup: gate active", catchup_cadence_active());
    VHT_CHECK("catchup: not a fold", !refold_cadence_active());

    /* Defaults: pool min(nproc,16), batch UNCHANGED. */
    VHT_CHECK("catchup: default pool min(nproc,16)",
              vh_runtime_pool_size() == vht_nproc());
    VHT_CHECK("catchup: batch stays VH_BATCH_SIZE",
              vh_runtime_batch_size() == VH_BATCH_SIZE);
    VHT_CHECK("catchup: fold batch env still cannot reach the live path",
              (setenv("ZCL_VH_BATCH", "4096", 1),
               vh_runtime_batch_size() == VH_BATCH_SIZE));
    VHT_CHECK("catchup: fold pool env does not widen the catch-up pool",
              (setenv("ZCL_VH_POOL", "128", 1),
               vh_runtime_pool_size() == vht_nproc()));

    /* The catch-up knob tunes + clamps. */
    setenv("ZCL_VH_CATCHUP_POOL_SIZE", "8", 1);
    VHT_CHECK("catchup: env pool 8", vh_runtime_pool_size() == 8);
    setenv("ZCL_VH_CATCHUP_POOL_SIZE", "0", 1);
    VHT_CHECK("catchup: pool clamp low", vh_runtime_pool_size() == 1);
    setenv("ZCL_VH_CATCHUP_POOL_SIZE", "999999", 1);
    VHT_CHECK("catchup: pool clamp high",
              vh_runtime_pool_size() == VH_MAX_POOL);
    setenv("ZCL_VH_CATCHUP_POOL_SIZE", "junk", 1);
    VHT_CHECK("catchup: garbage pool -> default",
              vh_runtime_pool_size() == vht_nproc());

    /* A12 step cap: identity at/below VH_POOL_SIZE, pool-scale above,
     * capped at VH_CATCHUP_STEP_MULT. */
    setenv("ZCL_VH_CATCHUP_POOL_SIZE", "4", 1);
    VHT_CHECK("catchup: step cap identity at pool 4",
              validate_headers_stage_catchup_step_cap(VH_BATCH_PER_TICK)
                  == VH_BATCH_PER_TICK);
    setenv("ZCL_VH_CATCHUP_POOL_SIZE", "8", 1);
    VHT_CHECK("catchup: step cap 2x at pool 8",
              validate_headers_stage_catchup_step_cap(VH_BATCH_PER_TICK)
                  == VH_BATCH_PER_TICK * 2);
    setenv("ZCL_VH_CATCHUP_POOL_SIZE", "128", 1);
    VHT_CHECK("catchup: step cap saturates at VH_CATCHUP_STEP_MULT",
              validate_headers_stage_catchup_step_cap(VH_BATCH_PER_TICK)
                  == VH_BATCH_PER_TICK * VH_CATCHUP_STEP_MULT);

    /* Fold precedence: with BOTH gates open the fold widths win. Clear the
     * fold env knobs first so the fold DEFAULTS are what is asserted. */
    unsetenv("ZCL_VH_CATCHUP_POOL_SIZE");
    unsetenv("ZCL_VH_POOL");
    unsetenv("ZCL_VH_BATCH");
    mint_fold_ceiling_set(3056758);
    VHT_CHECK("catchup+fold: fold wins (pool)",
              vh_runtime_pool_size() == VH_FOLD_POOL_DEFAULT);
    VHT_CHECK("catchup+fold: fold wins (batch)",
              vh_runtime_batch_size() == VH_FOLD_BATCH_DEFAULT);
    mint_fold_ceiling_set(MINT_FOLD_NO_CEILING);

    /* Clearing the catch-up gate RESTORES the inert identity — the widening
     * cannot leak into an at-tip node. */
    setenv("ZCL_VH_CATCHUP_POOL_SIZE", "64", 1);
    catchup_cadence_test_set_log_head_override(100000); /* gap = 0 */
    VHT_CHECK("restore: catch-up gate closed", !catchup_cadence_active());
    VHT_CHECK("restore: pool = VH_POOL_SIZE",
              vh_runtime_pool_size() == VH_POOL_SIZE);
    VHT_CHECK("restore: batch = VH_BATCH_SIZE",
              vh_runtime_batch_size() == VH_BATCH_SIZE);
    VHT_CHECK("restore: step cap identity",
              validate_headers_stage_catchup_step_cap(VH_BATCH_PER_TICK)
                  == VH_BATCH_PER_TICK);

    vht_clear_gates();
    return failures;
}

int test_validate_headers_tuning(void)
{
    int failures = 0;
    failures += case_normal_inert();
    failures += case_mint_active();
    failures += case_refold_active_then_restore();
    failures += case_catchup_active();
    if (failures == 0)
        printf("test_validate_headers_tuning: ALL PASSED\n");
    else
        printf("test_validate_headers_tuning: %d FAILURE(S)\n", failures);
    return failures;
}
