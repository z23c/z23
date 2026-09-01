/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Pure sync reducer — adapter shadow harness (net/sync_reduce_adapter.h).
 * WF1 lane 1D: drives the SAME construct+compare helper the live offer-accept
 * path (msgprocessor_snapshot.c) calls in SHADOW mode, with representative
 * offer scenarios, and asserts the kernel's structural accept/reject call
 * agrees with the reference FSM's — proving the shadow comparison is sound
 * before it is ever trusted for anything beyond logging. The reference
 * `snapshot_sync_service` stays fully authoritative in production; this test
 * exercises the comparator in isolation. */

#include "test/test_core.h"
#include "net/sync_reduce_adapter.h"
#include <string.h>

static int test_sync_reduce_adapter_phase_map(void)
{
    int failures = 0;
    TEST("sync_reduce_adapter: state->phase map covers every reference state") {
        ASSERT(sync_reduce_adapter_map_phase(SNAPSYNC_IDLE) == SYNC_PHASE_IDLE);
        ASSERT(sync_reduce_adapter_map_phase(SNAPSYNC_NEGOTIATING) == SYNC_PHASE_NEGOTIATING);
        ASSERT(sync_reduce_adapter_map_phase(SNAPSYNC_RECEIVING) == SYNC_PHASE_RECEIVING);
        ASSERT(sync_reduce_adapter_map_phase(SNAPSYNC_VERIFYING) == SYNC_PHASE_VERIFYING);
        /* COMPLETE maps to STAGED, never past it — activation stays contained. */
        ASSERT(sync_reduce_adapter_map_phase(SNAPSYNC_COMPLETE) == SYNC_PHASE_STAGED);
        ASSERT(sync_reduce_adapter_map_phase(SNAPSYNC_FAILED) == SYNC_PHASE_FAILED);
        PASS();
    } _test_next:;
    return failures;
}

static int test_sync_reduce_adapter_accepted(void)
{
    int failures = 0;
    TEST("sync_reduce_adapter: fresh offer, no active session -> both accept") {
        uint8_t utxo_root[32];
        memset(utxo_root, 0xAB, sizeof(utxo_root));
        struct sync_reduce_offer_shadow_result r = sync_reduce_offer_shadow_check(
            /*state_session_id=*/0, SNAPSYNC_IDLE,
            /*event_session_id=*/42, /*offer_height=*/1000,
            utxo_root, /*reference_accepts=*/true);
        ASSERT(r.kernel_accepts);
        ASSERT(r.reference_accepts);
        ASSERT(r.agrees);
        ASSERT(r.kernel_decision.next == SYNC_PHASE_NEGOTIATING);
        PASS();
    } _test_next:;
    return failures;
}

static int test_sync_reduce_adapter_rejected_stale_session(void)
{
    int failures = 0;
    TEST("sync_reduce_adapter: offer from a different peer while busy -> both reject") {
        /* We are already negotiating with peer 7 (state_session_id=7); an
         * offer from peer 99 arrives — the reference rejects it as BUSY, the
         * kernel's stale-session guard independently no-ops it. */
        struct sync_reduce_offer_shadow_result r = sync_reduce_offer_shadow_check(
            /*state_session_id=*/7, SNAPSYNC_NEGOTIATING,
            /*event_session_id=*/99, /*offer_height=*/1000,
            NULL, /*reference_accepts=*/false);
        ASSERT(!r.kernel_accepts);
        ASSERT(!r.reference_accepts);
        ASSERT(r.agrees);
        /* Stale-session guard: unchanged phase, zero actions. */
        ASSERT(r.kernel_decision.next == SYNC_PHASE_NEGOTIATING);
        ASSERT(r.kernel_decision.action_count == 0);
        PASS();
    } _test_next:;
    return failures;
}

static int test_sync_reduce_adapter_rejected_inferior_offer(void)
{
    int failures = 0;
    TEST("sync_reduce_adapter: inferior competing offer while receiving -> both reject") {
        /* We are already receiving from peer 7 (further along than merely
         * negotiating); a weaker/inferior offer from peer 100 arrives — the
         * reference rejects it (e.g. NOT_AHEAD/WEAK_WORK), and it is also
         * out-of-session for the kernel. */
        struct sync_reduce_offer_shadow_result r = sync_reduce_offer_shadow_check(
            /*state_session_id=*/7, SNAPSYNC_RECEIVING,
            /*event_session_id=*/100, /*offer_height=*/500,
            NULL, /*reference_accepts=*/false);
        ASSERT(!r.kernel_accepts);
        ASSERT(!r.reference_accepts);
        ASSERT(r.agrees);
        ASSERT(r.kernel_decision.next == SYNC_PHASE_RECEIVING);
        ASSERT(r.kernel_decision.action_count == 0);
        PASS();
    } _test_next:;
    return failures;
}

static int test_sync_reduce_adapter_known_divergence(void)
{
    int failures = 0;
    TEST("sync_reduce_adapter: first-ever weak offer -> EXPECTED divergence (documents the gap)") {
        /* No active session yet (state_session_id==0 never gates the
         * kernel), but the offer itself is weak/out-of-range and the
         * reference rejects it on its own independent validators. The
         * kernel has no notion of offer quality — only session identity and
         * phase — so it structurally accepts. This is the known, coarser-
         * kernel gap shadow mode exists to surface (logged in production,
         * never acted on); this test pins that the comparator correctly
         * detects it as a disagreement rather than silently reporting
         * agreement. */
        struct sync_reduce_offer_shadow_result r = sync_reduce_offer_shadow_check(
            /*state_session_id=*/0, SNAPSYNC_IDLE,
            /*event_session_id=*/55, /*offer_height=*/1,
            NULL, /*reference_accepts=*/false);
        ASSERT(r.kernel_accepts);
        ASSERT(!r.reference_accepts);
        ASSERT(!r.agrees);
        PASS();
    } _test_next:;
    return failures;
}

int test_sync_reduce_adapter(void)
{
    int failures = 0;
    failures += test_sync_reduce_adapter_phase_map();
    failures += test_sync_reduce_adapter_accepted();
    failures += test_sync_reduce_adapter_rejected_stale_session();
    failures += test_sync_reduce_adapter_rejected_inferior_offer();
    failures += test_sync_reduce_adapter_known_divergence();
    return failures;
}
