/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Pure sync reducer — seed-driven fuzz (sync/sync_reduce.h). Thousands of
 * random event sequences are generated from a 64-bit seed via the seed_tape
 * RNG (engine/modules/sim/seed_tape.h). The RNG lives STRICTLY OUTSIDE the reducer — each
 * drawn event is folded through the pure sync_reduce(), and the full set of
 * structural invariants is re-checked after EVERY step. On any break the test
 * prints the seed and the minimal reproducing event trace, then fails — the
 * "every bug becomes a 64-bit seed" contract. */

#include "test/test_core.h"
#include "sync/sync_reduce.h"
#include "sim/seed_tape.h"
#include "platform/rng.h"
#include <string.h>

#define FUZZ_SEQUENCES 4000
#define FUZZ_STEPS     64

/* Legal successors of a phase — kept independent of the reducer source. */
static bool legal_next(enum sync_phase from, enum sync_phase to)
{
    /* One row per legal (from,to) edge, in the same order as the old cases;
     * anything unlisted (including COUNT) is illegal. */
    static const struct { enum sync_phase from, to; } legal_edges[] = {
        { SYNC_PHASE_IDLE, SYNC_PHASE_IDLE },
        { SYNC_PHASE_IDLE, SYNC_PHASE_NEGOTIATING },
        { SYNC_PHASE_NEGOTIATING, SYNC_PHASE_NEGOTIATING },
        { SYNC_PHASE_NEGOTIATING, SYNC_PHASE_RECEIVING },
        { SYNC_PHASE_NEGOTIATING, SYNC_PHASE_FAILED },
        { SYNC_PHASE_NEGOTIATING, SYNC_PHASE_IDLE },
        { SYNC_PHASE_RECEIVING, SYNC_PHASE_RECEIVING },
        { SYNC_PHASE_RECEIVING, SYNC_PHASE_VERIFYING },
        { SYNC_PHASE_RECEIVING, SYNC_PHASE_FAILED },
        { SYNC_PHASE_RECEIVING, SYNC_PHASE_IDLE },
        { SYNC_PHASE_VERIFYING, SYNC_PHASE_VERIFYING },
        { SYNC_PHASE_VERIFYING, SYNC_PHASE_STAGED },
        { SYNC_PHASE_VERIFYING, SYNC_PHASE_FAILED },
        { SYNC_PHASE_VERIFYING, SYNC_PHASE_IDLE },
        { SYNC_PHASE_STAGED, SYNC_PHASE_STAGED },
        { SYNC_PHASE_STAGED, SYNC_PHASE_ACTIVATION_CONTAINED },
        { SYNC_PHASE_STAGED, SYNC_PHASE_IDLE },
        { SYNC_PHASE_ACTIVATION_CONTAINED, SYNC_PHASE_ACTIVATION_CONTAINED },
        { SYNC_PHASE_ACTIVATION_CONTAINED, SYNC_PHASE_IDLE },
        { SYNC_PHASE_FAILED, SYNC_PHASE_FAILED },
        { SYNC_PHASE_FAILED, SYNC_PHASE_IDLE },
    };
    for (size_t i = 0; i < sizeof(legal_edges) / sizeof(legal_edges[0]); i++)
        if (legal_edges[i].from == from && legal_edges[i].to == to)
            return true;
    return false;
}

static bool is_progress_event(enum sync_event_kind k)
{
    /* One row per event kind, in the same order as the old cases; anything
     * unlisted (including COUNT) is not progress. */
    static const struct {
        enum sync_event_kind kind;
        bool progress;
    } progress_by_kind[] = {
        { SYNC_EVENT_START, true },
        { SYNC_EVENT_OFFER_RECEIVED, true },
        { SYNC_EVENT_OFFER_ACCEPTED, true },
        { SYNC_EVENT_CHUNK_RECEIVED, true },
        { SYNC_EVENT_RECEIVE_COMPLETE, true },
        { SYNC_EVENT_PROOF_VERIFIED, true },
        { SYNC_EVENT_CHUNK_REJECTED, false },
        { SYNC_EVENT_PROOF_FAILED, false },
        { SYNC_EVENT_PEER_LOST, false },
        { SYNC_EVENT_TIMEOUT, false },
        { SYNC_EVENT_STOP_REQUESTED, false },
        { SYNC_EVENT_MANIFEST_VALIDATED, false },
        { SYNC_EVENT_ARTIFACT_VERIFIED, false },
        { SYNC_EVENT_INSTALL_PREPARED, false },
        { SYNC_EVENT_INSTALL_COMMITTED, false },
        { SYNC_EVENT_TAIL_PIECE_VERIFIED, false },
        { SYNC_EVENT_REDUCER_ADVANCED, false },
        { SYNC_EVENT_READY_REACHED, false },
        { SYNC_EVENT_SOVEREIGN_REACHED, false },
    };
    for (size_t i = 0; i < sizeof(progress_by_kind) / sizeof(progress_by_kind[0]); i++)
        if (progress_by_kind[i].kind == k)
            return progress_by_kind[i].progress;
    return false;
}

/* Range and layout checks on a transition's next phase and action slots. */
static const char *transition_shape_reason(struct sync_transition d)
{
    if (d.next_state.phase < 0 || d.next_state.phase >= SYNC_PHASE_COUNT)
        return "next phase out of range";
    if (d.action_count < 0 || d.action_count > SYNC_TRANSITION_MAX_ACTIONS)
        return "action_count out of range";
    for (int i = 0; i < d.action_count; i++)
        if (d.actions[i] <= SYNC_ACTION_NONE || d.actions[i] >= SYNC_ACTION_COUNT)
            return "action out of range";
    for (int i = d.action_count; i < SYNC_TRANSITION_MAX_ACTIONS; i++)
        if (d.actions[i] != SYNC_ACTION_NONE)
            return "non-NONE action past action_count";
    return NULL;
}

/* has_blocker and the blocker code must agree. */
static const char *blocker_consistency_reason(struct sync_transition d)
{
    if (d.has_blocker) {
        if (d.blocker <= SYNC_BLOCKER_NONE || d.blocker >= SYNC_BLOCKER_COUNT)
            return "blocker out of range";
    } else if (d.blocker != SYNC_BLOCKER_NONE) {
        return "blocker set without has_blocker";
    }
    return NULL;
}

/* STAGED-specific invariants: containment on progress, and the only legal
 * door into STAGED. */
static const char *staged_invariant_reason(struct sync_kernel_state s,
                                           struct sync_event e,
                                           struct sync_transition d)
{
    /* 5. STAGED + progress ⇒ contained, only RAISE_CONTAINMENT_BLOCKER. */
    if (s.phase == SYNC_PHASE_STAGED && is_progress_event(e.kind)) {
        if (d.next_state.phase != SYNC_PHASE_ACTIVATION_CONTAINED ||
            !d.has_blocker || d.blocker != SYNC_BLOCKER_ACTIVATION_CONTAINED ||
            d.action_count != 1 ||
            d.actions[0] != SYNC_ACTION_RAISE_CONTAINMENT_BLOCKER)
            return "STAGED+progress did not contain cleanly";
    }

    /* 6. STAGED is ENTERED (from another phase) ONLY via
     * VERIFYING+PROOF_VERIFIED(proof_ok); a STAGED self-loop does not count. */
    if (d.next_state.phase == SYNC_PHASE_STAGED && s.phase != SYNC_PHASE_STAGED) {
        if (!(s.phase == SYNC_PHASE_VERIFYING &&
              e.kind == SYNC_EVENT_PROOF_VERIFIED && e.proof_ok))
            return "reached STAGED by an illegal door";
    }
    return NULL;
}

/* Check every invariant against one (state,event)→transition step. Returns NULL
 * on success, or a static reason string on the first violation. */
static const char *check_step(struct sync_kernel_state s,
                              struct sync_event e,
                              struct sync_transition d)
{
    /* 1. Well-formed transition. */
    const char *reason = transition_shape_reason(d);
    if (reason)
        return reason;
    reason = blocker_consistency_reason(d);
    if (reason)
        return reason;

    /* 2. Chunk counter can never exceed the offered total. */
    if (d.next_state.chunks_received.value > d.next_state.chunks_total.value)
        return "chunks_received exceeded chunks_total";

    bool stale = (s.session_id.value != 0 &&
                  e.session_id.value != s.session_id.value);

    /* 3. Stale ⇒ fully inert (no field of state moves). */
    if (stale) {
        if (!sync_kernel_state_eq(&d.next_state, &s) ||
            d.action_count != 0 || d.has_blocker)
            return "stale event was not inert";
        return NULL; /* nothing else applies to a stale step */
    }

    /* 4. Legal successor only. */
    if (!legal_next(s.phase, d.next_state.phase))
        return "illegal phase transition";

    reason = staged_invariant_reason(s, e, d);
    if (reason)
        return reason;

    /* 7. No decision ever asks for a live-tip activation — the catalog has no
     * such action, so any emitted action is a real (non-activate) member. */
    return NULL;
}

static void draw_event(struct sync_event *e, uint64_t session)
{
    memset(e, 0, sizeof(*e));
    uint64_t r = rng_u64();
    e->kind = (enum sync_event_kind)(r % SYNC_EVENT_COUNT);
    e->proof_ok = ((r >> 8) & 1u) != 0;
    /* Mostly the live session; occasionally a stale one to exercise the guard. */
    e->session_id.value = ((r >> 9) % 8 == 0) ? (session ^ 0xA5A5A5A5ULL) : session;
    e->peer.value = (r >> 16);
    /* MANIFEST_VALIDATED verdict alternates so both accept/reject fold. */
    e->verdict = ((r >> 40) & 1u) ? SYNC_OFFER_VERDICT_REJECT
                                  : SYNC_OFFER_VERDICT_ACCEPT;
}

static int test_sync_reduce_fuzz_invariants(void)
{
    int failures = 0;
    TEST("sync_reduce: seed-driven sequences preserve every invariant") {
        for (uint64_t seed = 1; seed <= FUZZ_SEQUENCES; seed++) {
            seed_tape_t *tape = seed_tape_open(seed, 0);
            ASSERT(tape != NULL);
            seed_tape_install(tape);

            struct sync_kernel_state s;
            memset(&s, 0, sizeof(s));
            s.session_id.value = 1;
            s.phase = SYNC_PHASE_IDLE;

            /* Record the trace so a failure prints a minimal reproducer. */
            enum sync_event_kind trace_kind[FUZZ_STEPS];
            bool trace_ok[FUZZ_STEPS];
            bool trace_stale[FUZZ_STEPS];

            const char *reason = NULL;
            int fail_step = -1;

            for (int step = 0; step < FUZZ_STEPS; step++) {
                struct sync_event e;
                draw_event(&e, s.session_id.value);
                trace_kind[step] = e.kind;
                trace_ok[step] = e.proof_ok;
                trace_stale[step] = (s.session_id.value != 0 &&
                                     e.session_id.value != s.session_id.value);

                struct sync_transition d = sync_reduce(s, e);

                /* Determinism: an immediate re-fold must be field-identical. */
                struct sync_transition d2 = sync_reduce(s, e);
                if (!sync_transition_eq(&d, &d2)) {
                    reason = "non-deterministic transition";
                    fail_step = step;
                    break;
                }

                reason = check_step(s, e, d);
                if (reason) { fail_step = step; break; }

                s = d.next_state;
            }

            seed_tape_uninstall();
            seed_tape_close(tape);

            if (reason) {
                printf("\n  FUZZ FAIL seed=%llu step=%d: %s\n",
                       (unsigned long long)seed, fail_step, reason);
                printf("  minimal trace (event[proof_ok][stale]):\n");
                for (int i = 0; i <= fail_step; i++)
                    printf("    %2d: %s [ok=%d]%s\n", i,
                           sync_event_name(trace_kind[i]), (int)trace_ok[i],
                           trace_stale[i] ? " [stale]" : "");
                ASSERT(reason == NULL);
                break;
            }
        }
        PASS();
    } _test_next:;
    return failures;
}

int test_sync_reduce_fuzz(void)
{
    return test_sync_reduce_fuzz_invariants();
}
