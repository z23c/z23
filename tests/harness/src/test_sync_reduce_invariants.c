/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Pure sync reducer — invariants (sync/sync_reduce.h). Exhaustive enumeration
 * over phases × events × {stale,fresh} × {proof_ok} proving the structural laws
 * that make the kernel safe to trust as the single sync authority:
 *
 *   1. Every transition is well-formed (bounded next/actions/blocker).
 *   2. The next phase is always one of the LEGAL successors of `phase`.
 *   3. Repeated calls are field-identical (deterministic — sync_transition_eq).
 *   4. A stale-session event is inert (next_state==state, no action, no blocker).
 *   5. STAGED + any PROGRESS event ⇒ next==ACTIVATION_CONTAINED with blocker
 *      SYNC_BLOCKER_ACTIVATION_CONTAINED and ONLY RAISE_CONTAINMENT_BLOCKER —
 *      no other outcome (never FAIL, never STAGE_BUNDLE, never a live tip).
 *   6. Varying only the peer id never changes a transition (peer targeting
 *      lives on the event/state, not the transition logic) — and peer identity
 *      is NEVER confused with session identity.
 *   7. No path reaches STAGED except VERIFYING + PROOF_VERIFIED(proof_ok).
 *   8. VERIFYING never emits an activation action (structurally impossible —
 *      the enum has no such member; asserted at runtime as the witness).
 *   9. The Phase-3 generic-artifact stub events are inert in every phase. */

#include "test/test_core.h"
#include "sync/sync_reduce.h"
#include <string.h>

static struct sync_kernel_state mk_state(uint64_t sid, enum sync_phase p)
{
    struct sync_kernel_state s;
    memset(&s, 0, sizeof(s));
    s.session_id.value = sid;
    s.phase = p;
    return s;
}

static struct sync_event mk_event(uint64_t sid, enum sync_event_kind k,
                                  bool proof_ok, uint64_t peer)
{
    struct sync_event e;
    memset(&e, 0, sizeof(e));
    e.session_id.value = sid;
    e.kind = k;
    e.proof_ok = proof_ok;
    e.peer.value = peer;
    return e;
}

/* Legal successor table — the ONLY phases sync_reduce may return from a given
 * phase. Kept independent of the reducer's source so a wrong jump is caught. */
static bool legal_next(enum sync_phase from, enum sync_phase to)
{
    switch (from) {
    case SYNC_PHASE_IDLE:
        return to == SYNC_PHASE_IDLE || to == SYNC_PHASE_NEGOTIATING;
    case SYNC_PHASE_NEGOTIATING:
        return to == SYNC_PHASE_NEGOTIATING || to == SYNC_PHASE_RECEIVING ||
               to == SYNC_PHASE_FAILED || to == SYNC_PHASE_IDLE;
    case SYNC_PHASE_RECEIVING:
        return to == SYNC_PHASE_RECEIVING || to == SYNC_PHASE_VERIFYING ||
               to == SYNC_PHASE_FAILED || to == SYNC_PHASE_IDLE;
    case SYNC_PHASE_VERIFYING:
        return to == SYNC_PHASE_VERIFYING || to == SYNC_PHASE_STAGED ||
               to == SYNC_PHASE_FAILED || to == SYNC_PHASE_IDLE;
    case SYNC_PHASE_STAGED:
        return to == SYNC_PHASE_STAGED ||
               to == SYNC_PHASE_ACTIVATION_CONTAINED || to == SYNC_PHASE_IDLE;
    case SYNC_PHASE_ACTIVATION_CONTAINED:
        return to == SYNC_PHASE_ACTIVATION_CONTAINED || to == SYNC_PHASE_IDLE;
    case SYNC_PHASE_FAILED:
        return to == SYNC_PHASE_FAILED || to == SYNC_PHASE_IDLE;
    case SYNC_PHASE_COUNT:
        break;
    }
    return false;
}

/* Progress events (in STAGED these trip the contained activation door). The
 * typed MANIFEST_VALIDATED verdict and the Phase-3 stubs are NON-progress: in
 * STAGED they are inert, never activating. Exhaustive — no default. */
static bool is_progress_event(enum sync_event_kind k)
{
    switch (k) {
    case SYNC_EVENT_START:
    case SYNC_EVENT_OFFER_RECEIVED:
    case SYNC_EVENT_OFFER_ACCEPTED:
    case SYNC_EVENT_CHUNK_RECEIVED:
    case SYNC_EVENT_RECEIVE_COMPLETE:
    case SYNC_EVENT_PROOF_VERIFIED:
        return true;
    case SYNC_EVENT_CHUNK_REJECTED:
    case SYNC_EVENT_PROOF_FAILED:
    case SYNC_EVENT_PEER_LOST:
    case SYNC_EVENT_TIMEOUT:
    case SYNC_EVENT_STOP_REQUESTED:
    case SYNC_EVENT_MANIFEST_VALIDATED:
    case SYNC_EVENT_ARTIFACT_VERIFIED:
    case SYNC_EVENT_INSTALL_PREPARED:
    case SYNC_EVENT_INSTALL_COMMITTED:
    case SYNC_EVENT_TAIL_PIECE_VERIFIED:
    case SYNC_EVENT_REDUCER_ADVANCED:
    case SYNC_EVENT_READY_REACHED:
    case SYNC_EVENT_SOVEREIGN_REACHED:
        return false;
    case SYNC_EVENT_COUNT:
        break;
    }
    return false;
}

/* The Phase-3 generic-artifact stubs — inert in every phase this slice. */
static bool is_stub_event(enum sync_event_kind k)
{
    switch (k) {
    case SYNC_EVENT_ARTIFACT_VERIFIED:
    case SYNC_EVENT_INSTALL_PREPARED:
    case SYNC_EVENT_INSTALL_COMMITTED:
    case SYNC_EVENT_TAIL_PIECE_VERIFIED:
    case SYNC_EVENT_REDUCER_ADVANCED:
    case SYNC_EVENT_READY_REACHED:
    case SYNC_EVENT_SOVEREIGN_REACHED:
        return true;
    case SYNC_EVENT_START:
    case SYNC_EVENT_OFFER_RECEIVED:
    case SYNC_EVENT_OFFER_ACCEPTED:
    case SYNC_EVENT_CHUNK_RECEIVED:
    case SYNC_EVENT_CHUNK_REJECTED:
    case SYNC_EVENT_RECEIVE_COMPLETE:
    case SYNC_EVENT_PROOF_VERIFIED:
    case SYNC_EVENT_PROOF_FAILED:
    case SYNC_EVENT_PEER_LOST:
    case SYNC_EVENT_TIMEOUT:
    case SYNC_EVENT_STOP_REQUESTED:
    case SYNC_EVENT_MANIFEST_VALIDATED:
        return false;
    case SYNC_EVENT_COUNT:
        break;
    }
    return false;
}

static int test_wellformed_and_legal(void)
{
    int failures = 0;
    TEST("sync_reduce: every (phase,event,proof_ok) is well-formed + legal") {
        for (int p = 0; p < SYNC_PHASE_COUNT; p++) {
            for (int e = 0; e < SYNC_EVENT_COUNT; e++) {
                for (int po = 0; po <= 1; po++) {
                    struct sync_transition d = sync_reduce(
                        mk_state(5, (enum sync_phase)p),
                        mk_event(5, (enum sync_event_kind)e, po != 0, 1));
                    ASSERT(d.next_state.phase >= 0 &&
                           d.next_state.phase < SYNC_PHASE_COUNT);
                    ASSERT(legal_next((enum sync_phase)p, d.next_state.phase));
                    ASSERT(d.action_count >= 0 &&
                           d.action_count <= SYNC_TRANSITION_MAX_ACTIONS);
                    for (int i = 0; i < d.action_count; i++)
                        ASSERT(d.actions[i] > SYNC_ACTION_NONE &&
                               d.actions[i] < SYNC_ACTION_COUNT);
                    for (int i = d.action_count; i < SYNC_TRANSITION_MAX_ACTIONS; i++)
                        ASSERT(d.actions[i] == SYNC_ACTION_NONE);
                    if (d.has_blocker)
                        ASSERT(d.blocker > SYNC_BLOCKER_NONE &&
                               d.blocker < SYNC_BLOCKER_COUNT);
                    else
                        ASSERT(d.blocker == SYNC_BLOCKER_NONE);
                }
            }
        }
        PASS();
    } _test_next:;
    return failures;
}

static int test_deterministic(void)
{
    int failures = 0;
    TEST("sync_reduce: repeated calls are field-identical") {
        for (int p = 0; p < SYNC_PHASE_COUNT; p++) {
            for (int e = 0; e < SYNC_EVENT_COUNT; e++) {
                for (int po = 0; po <= 1; po++) {
                    struct sync_kernel_state s = mk_state(11, (enum sync_phase)p);
                    struct sync_event ev =
                        mk_event(11, (enum sync_event_kind)e, po != 0, 3);
                    struct sync_transition a = sync_reduce(s, ev);
                    struct sync_transition b = sync_reduce(s, ev);
                    ASSERT(sync_transition_eq(&a, &b));
                }
            }
        }
        PASS();
    } _test_next:;
    return failures;
}

static int test_stale_is_inert(void)
{
    int failures = 0;
    TEST("sync_reduce: a stale session (non-zero, mismatched) changes no field") {
        for (int p = 0; p < SYNC_PHASE_COUNT; p++) {
            for (int e = 0; e < SYNC_EVENT_COUNT; e++) {
                struct sync_kernel_state s = mk_state(100, (enum sync_phase)p);
                struct sync_event ev =
                    mk_event(999 /* wrong session */, (enum sync_event_kind)e, true, 7);
                struct sync_transition d = sync_reduce(s, ev);
                /* Full-state inertness: not a single field of state moves. */
                ASSERT(sync_kernel_state_eq(&d.next_state, &s));
                ASSERT(d.action_count == 0);
                ASSERT(!d.has_blocker);
                ASSERT(d.blocker == SYNC_BLOCKER_NONE);
                for (int i = 0; i < SYNC_TRANSITION_MAX_ACTIONS; i++)
                    ASSERT(d.actions[i] == SYNC_ACTION_NONE);
            }
        }
        PASS();
    } _test_next:;
    return failures;
}

static int test_staged_progress_is_contained(void)
{
    int failures = 0;
    TEST("sync_reduce: STAGED + any progress event ⇒ contained, no other outcome") {
        for (int e = 0; e < SYNC_EVENT_COUNT; e++) {
            if (!is_progress_event((enum sync_event_kind)e))
                continue;
            for (int po = 0; po <= 1; po++) {
                struct sync_transition d = sync_reduce(
                    mk_state(4, SYNC_PHASE_STAGED),
                    mk_event(4, (enum sync_event_kind)e, po != 0, 9));
                ASSERT(d.next_state.phase == SYNC_PHASE_ACTIVATION_CONTAINED);
                ASSERT(d.has_blocker);
                ASSERT(d.blocker == SYNC_BLOCKER_ACTIVATION_CONTAINED);
                ASSERT(d.action_count == 1);
                ASSERT(d.actions[0] == SYNC_ACTION_RAISE_CONTAINMENT_BLOCKER);
                /* No FAIL, no STAGE_BUNDLE, no other action anywhere. */
                for (int i = 1; i < SYNC_TRANSITION_MAX_ACTIONS; i++)
                    ASSERT(d.actions[i] == SYNC_ACTION_NONE);
            }
        }
        PASS();
    } _test_next:;
    return failures;
}

static int test_peer_id_never_changes_decision(void)
{
    int failures = 0;
    TEST("sync_reduce: varying only the peer id never changes a transition") {
        const uint64_t peers[] = {0, 1, 42, 0xFFFFFFFFFFFFFFFFULL};
        for (int p = 0; p < SYNC_PHASE_COUNT; p++) {
            for (int e = 0; e < SYNC_EVENT_COUNT; e++) {
                for (int po = 0; po <= 1; po++) {
                    struct sync_kernel_state s = mk_state(8, (enum sync_phase)p);
                    struct sync_transition baseline = sync_reduce(
                        s, mk_event(8, (enum sync_event_kind)e, po != 0, peers[0]));
                    for (size_t k = 1; k < sizeof(peers) / sizeof(peers[0]); k++) {
                        /* Only the phase/action/blocker logic must be peer-blind.
                         * (The adopted peer field itself may legitimately differ
                         * on an opening event, so compare the decision view.) */
                        struct sync_transition d = sync_reduce(
                            s, mk_event(8, (enum sync_event_kind)e, po != 0, peers[k]));
                        struct sync_decision bd = sync_transition_to_decision(&baseline);
                        struct sync_decision dd = sync_transition_to_decision(&d);
                        ASSERT(memcmp(&bd, &dd, sizeof(bd)) == 0);
                    }
                }
            }
        }
        PASS();
    } _test_next:;
    return failures;
}

/* Session identity and peer identity are DISTINCT: a stale session is inert
 * regardless of a matching peer, and a matching session folds regardless of a
 * differing peer. Confusing the two would break exactly one of these. */
static int test_session_and_peer_not_confused(void)
{
    int failures = 0;
    TEST("sync_reduce: session id and peer id are never confused") {
        /* Same peer, wrong session ⇒ stale/inert (peer must NOT rescue it). */
        struct sync_kernel_state s = mk_state(100, SYNC_PHASE_RECEIVING);
        s.peer.value = 77;
        struct sync_event ev = mk_event(999, SYNC_EVENT_CHUNK_RECEIVED, false, 77);
        struct sync_transition d = sync_reduce(s, ev);
        ASSERT(sync_kernel_state_eq(&d.next_state, &s));
        ASSERT(d.action_count == 0);

        /* Right session, different peer ⇒ folds normally (session gates, not peer). */
        struct sync_event ev2 = mk_event(100, SYNC_EVENT_CHUNK_RECEIVED, false, 5);
        struct sync_transition d2 = sync_reduce(s, ev2);
        ASSERT(d2.next_state.phase == SYNC_PHASE_RECEIVING);
        ASSERT(d2.action_count == 1);
        ASSERT(d2.actions[0] == SYNC_ACTION_APPLY_CHUNK);
        PASS();
    } _test_next:;
    return failures;
}

static int test_only_verifying_proof_ok_reaches_staged(void)
{
    int failures = 0;
    TEST("sync_reduce: STAGED is reachable ONLY via VERIFYING+PROOF_VERIFIED(ok)") {
        for (int p = 0; p < SYNC_PHASE_COUNT; p++) {
            for (int e = 0; e < SYNC_EVENT_COUNT; e++) {
                for (int po = 0; po <= 1; po++) {
                    struct sync_transition d = sync_reduce(
                        mk_state(6, (enum sync_phase)p),
                        mk_event(6, (enum sync_event_kind)e, po != 0, 2));
                    bool is_the_one_door =
                        (p == SYNC_PHASE_VERIFYING &&
                         e == SYNC_EVENT_PROOF_VERIFIED && po == 1);
                    if (d.next_state.phase == SYNC_PHASE_STAGED &&
                        p != SYNC_PHASE_STAGED)
                        ASSERT(is_the_one_door);
                    if (is_the_one_door) {
                        ASSERT(d.next_state.phase == SYNC_PHASE_STAGED);
                        ASSERT(d.action_count == 1);
                        ASSERT(d.actions[0] == SYNC_ACTION_STAGE_BUNDLE);
                        ASSERT(!d.has_blocker);
                    }
                }
            }
        }
        PASS();
    } _test_next:;
    return failures;
}

/* The runtime witness of the compile-time containment law: from VERIFYING, no
 * decision emits an activation/publish action (there is no such catalog member)
 * and none jumps past STAGED. */
static int test_verifying_never_activates(void)
{
    int failures = 0;
    TEST("sync_reduce: VERIFYING never emits an activation action") {
        for (int e = 0; e < SYNC_EVENT_COUNT; e++) {
            for (int po = 0; po <= 1; po++) {
                struct sync_transition d = sync_reduce(
                    mk_state(3, SYNC_PHASE_VERIFYING),
                    mk_event(3, (enum sync_event_kind)e, po != 0, 1));
                ASSERT(legal_next(SYNC_PHASE_VERIFYING, d.next_state.phase));
                for (int i = 0; i < d.action_count; i++) {
                    ASSERT(d.actions[i] > SYNC_ACTION_NONE &&
                           d.actions[i] < SYNC_ACTION_COUNT);
                    ASSERT(d.actions[i] != SYNC_ACTION_RAISE_CONTAINMENT_BLOCKER);
                }
            }
        }
        PASS();
    } _test_next:;
    return failures;
}

/* Phase-3 catalog stubs are TYPES ONLY: inert in every phase — no phase move,
 * no action, no blocker. This is the runtime proof that install/committed is
 * unreachable and the enums stay total without leaking behavior. */
static int test_stub_events_inert_everywhere(void)
{
    int failures = 0;
    TEST("sync_reduce: every generic-artifact stub event is inert in every phase") {
        for (int p = 0; p < SYNC_PHASE_COUNT; p++) {
            for (int e = 0; e < SYNC_EVENT_COUNT; e++) {
                if (!is_stub_event((enum sync_event_kind)e))
                    continue;
                struct sync_kernel_state s = mk_state(12, (enum sync_phase)p);
                struct sync_transition d = sync_reduce(
                    s, mk_event(12, (enum sync_event_kind)e, true, 4));
                ASSERT(d.next_state.phase == (enum sync_phase)p);
                ASSERT(sync_kernel_state_eq(&d.next_state, &s));
                ASSERT(d.action_count == 0);
                ASSERT(!d.has_blocker);
            }
        }
        PASS();
    } _test_next:;
    return failures;
}

int test_sync_reduce_invariants(void)
{
    int failures = 0;
    failures += test_wellformed_and_legal();
    failures += test_deterministic();
    failures += test_stale_is_inert();
    failures += test_staged_progress_is_contained();
    failures += test_peer_id_never_changes_decision();
    failures += test_session_and_peer_not_confused();
    failures += test_only_verifying_proof_ok_reaches_staged();
    failures += test_verifying_never_activates();
    failures += test_stub_events_inert_everywhere();
    return failures;
}
