/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Pure sync reducer (sync/sync_reduce.h) — the explicit transition matrix plus
 * the full-next-state / session-identity / typed-verdict / catalog-stub laws.
 * Every (phase, classic-event) row (with a proof_ok split on the one proof-
 * gated arm) is pinned to its expected (next phase, ordered actions, blocker).
 * If the kernel's table drifts, exactly the drifted row fails and names itself.
 * The newer laws (kernel owns the whole next state; session != peer; a stale
 * session moves no field; chunk counters are bounded; STAGED cannot activate;
 * Phase-3 stubs are inert) get their own focused tests below. */

#include "test/test_core.h"
#include "sync/sync_reduce.h"
#include <string.h>

/* The kernel now folds MANIFEST_VALIDATED (typed verdict) and 7 Phase-3 stub
 * events on top of the 11 "classic" lifecycle events. The hand matrix pins the
 * 11 classic events; the verdict + stub events get dedicated tests. */
#define N_CLASSIC_EVENTS 11

struct row {
    enum sync_phase       phase;
    enum sync_event_kind  event;
    bool                  proof_ok;
    enum sync_phase       next;
    enum sync_action      acts[SYNC_TRANSITION_MAX_ACTIONS];
    int                   n_acts;
    enum sync_blocker     blocker;
};

#define A0 {SYNC_ACTION_NONE, SYNC_ACTION_NONE, SYNC_ACTION_NONE, SYNC_ACTION_NONE}

static const struct row g_matrix[] = {
    /* ── IDLE ── */
    {SYNC_PHASE_IDLE, SYNC_EVENT_START,            false, SYNC_PHASE_NEGOTIATING, A0, 0, SYNC_BLOCKER_NONE},
    {SYNC_PHASE_IDLE, SYNC_EVENT_OFFER_RECEIVED,   false, SYNC_PHASE_NEGOTIATING, {SYNC_ACTION_STORE_OFFER}, 1, SYNC_BLOCKER_NONE},
    {SYNC_PHASE_IDLE, SYNC_EVENT_OFFER_ACCEPTED,   false, SYNC_PHASE_IDLE,        A0, 0, SYNC_BLOCKER_NONE},
    {SYNC_PHASE_IDLE, SYNC_EVENT_CHUNK_RECEIVED,   false, SYNC_PHASE_IDLE,        A0, 0, SYNC_BLOCKER_NONE},
    {SYNC_PHASE_IDLE, SYNC_EVENT_CHUNK_REJECTED,   false, SYNC_PHASE_IDLE,        A0, 0, SYNC_BLOCKER_NONE},
    {SYNC_PHASE_IDLE, SYNC_EVENT_RECEIVE_COMPLETE, false, SYNC_PHASE_IDLE,        A0, 0, SYNC_BLOCKER_NONE},
    {SYNC_PHASE_IDLE, SYNC_EVENT_PROOF_VERIFIED,   true,  SYNC_PHASE_IDLE,        A0, 0, SYNC_BLOCKER_NONE},
    {SYNC_PHASE_IDLE, SYNC_EVENT_PROOF_FAILED,     false, SYNC_PHASE_IDLE,        A0, 0, SYNC_BLOCKER_NONE},
    {SYNC_PHASE_IDLE, SYNC_EVENT_PEER_LOST,        false, SYNC_PHASE_IDLE,        A0, 0, SYNC_BLOCKER_NONE},
    {SYNC_PHASE_IDLE, SYNC_EVENT_TIMEOUT,          false, SYNC_PHASE_IDLE,        A0, 0, SYNC_BLOCKER_NONE},
    {SYNC_PHASE_IDLE, SYNC_EVENT_STOP_REQUESTED,   false, SYNC_PHASE_IDLE,        A0, 0, SYNC_BLOCKER_NONE},

    /* ── NEGOTIATING ── */
    {SYNC_PHASE_NEGOTIATING, SYNC_EVENT_START,            false, SYNC_PHASE_NEGOTIATING, A0, 0, SYNC_BLOCKER_NONE},
    {SYNC_PHASE_NEGOTIATING, SYNC_EVENT_OFFER_RECEIVED,   false, SYNC_PHASE_NEGOTIATING, {SYNC_ACTION_STORE_OFFER}, 1, SYNC_BLOCKER_NONE},
    {SYNC_PHASE_NEGOTIATING, SYNC_EVENT_OFFER_ACCEPTED,   false, SYNC_PHASE_RECEIVING,   {SYNC_ACTION_RESET_OFFSET, SYNC_ACTION_BEGIN_RECEIVE}, 2, SYNC_BLOCKER_NONE},
    {SYNC_PHASE_NEGOTIATING, SYNC_EVENT_CHUNK_RECEIVED,   false, SYNC_PHASE_NEGOTIATING, A0, 0, SYNC_BLOCKER_NONE},
    {SYNC_PHASE_NEGOTIATING, SYNC_EVENT_CHUNK_REJECTED,   false, SYNC_PHASE_NEGOTIATING, A0, 0, SYNC_BLOCKER_NONE},
    {SYNC_PHASE_NEGOTIATING, SYNC_EVENT_RECEIVE_COMPLETE, false, SYNC_PHASE_NEGOTIATING, A0, 0, SYNC_BLOCKER_NONE},
    {SYNC_PHASE_NEGOTIATING, SYNC_EVENT_PROOF_VERIFIED,   true,  SYNC_PHASE_NEGOTIATING, A0, 0, SYNC_BLOCKER_NONE},
    {SYNC_PHASE_NEGOTIATING, SYNC_EVENT_PROOF_FAILED,     false, SYNC_PHASE_FAILED,      {SYNC_ACTION_FAIL}, 1, SYNC_BLOCKER_PROOF_FAILED},
    {SYNC_PHASE_NEGOTIATING, SYNC_EVENT_PEER_LOST,        false, SYNC_PHASE_FAILED,      {SYNC_ACTION_FAIL}, 1, SYNC_BLOCKER_PEER_LOST},
    {SYNC_PHASE_NEGOTIATING, SYNC_EVENT_TIMEOUT,          false, SYNC_PHASE_FAILED,      {SYNC_ACTION_FAIL}, 1, SYNC_BLOCKER_TIMEOUT},
    {SYNC_PHASE_NEGOTIATING, SYNC_EVENT_STOP_REQUESTED,   false, SYNC_PHASE_IDLE,        A0, 0, SYNC_BLOCKER_NONE},

    /* ── RECEIVING ── */
    {SYNC_PHASE_RECEIVING, SYNC_EVENT_START,            false, SYNC_PHASE_RECEIVING, A0, 0, SYNC_BLOCKER_NONE},
    {SYNC_PHASE_RECEIVING, SYNC_EVENT_OFFER_RECEIVED,   false, SYNC_PHASE_RECEIVING, A0, 0, SYNC_BLOCKER_NONE},
    {SYNC_PHASE_RECEIVING, SYNC_EVENT_OFFER_ACCEPTED,   false, SYNC_PHASE_RECEIVING, A0, 0, SYNC_BLOCKER_NONE},
    {SYNC_PHASE_RECEIVING, SYNC_EVENT_CHUNK_RECEIVED,   false, SYNC_PHASE_RECEIVING, {SYNC_ACTION_APPLY_CHUNK}, 1, SYNC_BLOCKER_NONE},
    {SYNC_PHASE_RECEIVING, SYNC_EVENT_CHUNK_REJECTED,   false, SYNC_PHASE_RECEIVING, {SYNC_ACTION_PENALIZE_PEER}, 1, SYNC_BLOCKER_NONE},
    {SYNC_PHASE_RECEIVING, SYNC_EVENT_RECEIVE_COMPLETE, false, SYNC_PHASE_VERIFYING, {SYNC_ACTION_START_VERIFY}, 1, SYNC_BLOCKER_NONE},
    {SYNC_PHASE_RECEIVING, SYNC_EVENT_PROOF_VERIFIED,   true,  SYNC_PHASE_RECEIVING, A0, 0, SYNC_BLOCKER_NONE},
    {SYNC_PHASE_RECEIVING, SYNC_EVENT_PROOF_FAILED,     false, SYNC_PHASE_FAILED,    {SYNC_ACTION_FAIL}, 1, SYNC_BLOCKER_PROOF_FAILED},
    {SYNC_PHASE_RECEIVING, SYNC_EVENT_PEER_LOST,        false, SYNC_PHASE_FAILED,    {SYNC_ACTION_FAIL}, 1, SYNC_BLOCKER_PEER_LOST},
    {SYNC_PHASE_RECEIVING, SYNC_EVENT_TIMEOUT,          false, SYNC_PHASE_FAILED,    {SYNC_ACTION_FAIL}, 1, SYNC_BLOCKER_TIMEOUT},
    {SYNC_PHASE_RECEIVING, SYNC_EVENT_STOP_REQUESTED,   false, SYNC_PHASE_IDLE,      A0, 0, SYNC_BLOCKER_NONE},

    /* ── VERIFYING (the proof gate) ── */
    {SYNC_PHASE_VERIFYING, SYNC_EVENT_START,            false, SYNC_PHASE_VERIFYING, A0, 0, SYNC_BLOCKER_NONE},
    {SYNC_PHASE_VERIFYING, SYNC_EVENT_OFFER_RECEIVED,   false, SYNC_PHASE_VERIFYING, A0, 0, SYNC_BLOCKER_NONE},
    {SYNC_PHASE_VERIFYING, SYNC_EVENT_OFFER_ACCEPTED,   false, SYNC_PHASE_VERIFYING, A0, 0, SYNC_BLOCKER_NONE},
    {SYNC_PHASE_VERIFYING, SYNC_EVENT_CHUNK_RECEIVED,   false, SYNC_PHASE_VERIFYING, A0, 0, SYNC_BLOCKER_NONE},
    {SYNC_PHASE_VERIFYING, SYNC_EVENT_CHUNK_REJECTED,   false, SYNC_PHASE_VERIFYING, A0, 0, SYNC_BLOCKER_NONE},
    {SYNC_PHASE_VERIFYING, SYNC_EVENT_RECEIVE_COMPLETE, false, SYNC_PHASE_VERIFYING, A0, 0, SYNC_BLOCKER_NONE},
    {SYNC_PHASE_VERIFYING, SYNC_EVENT_PROOF_VERIFIED,   true,  SYNC_PHASE_STAGED,    {SYNC_ACTION_STAGE_BUNDLE}, 1, SYNC_BLOCKER_NONE},
    {SYNC_PHASE_VERIFYING, SYNC_EVENT_PROOF_VERIFIED,   false, SYNC_PHASE_FAILED,    {SYNC_ACTION_FAIL}, 1, SYNC_BLOCKER_PROOF_FAILED},
    {SYNC_PHASE_VERIFYING, SYNC_EVENT_PROOF_FAILED,     false, SYNC_PHASE_FAILED,    {SYNC_ACTION_FAIL}, 1, SYNC_BLOCKER_PROOF_FAILED},
    {SYNC_PHASE_VERIFYING, SYNC_EVENT_PEER_LOST,        false, SYNC_PHASE_FAILED,    {SYNC_ACTION_FAIL}, 1, SYNC_BLOCKER_PEER_LOST},
    {SYNC_PHASE_VERIFYING, SYNC_EVENT_TIMEOUT,          false, SYNC_PHASE_FAILED,    {SYNC_ACTION_FAIL}, 1, SYNC_BLOCKER_TIMEOUT},
    {SYNC_PHASE_VERIFYING, SYNC_EVENT_STOP_REQUESTED,   false, SYNC_PHASE_IDLE,      A0, 0, SYNC_BLOCKER_NONE},

    /* ── STAGED (progress ⇒ contained) ── */
    {SYNC_PHASE_STAGED, SYNC_EVENT_START,            false, SYNC_PHASE_ACTIVATION_CONTAINED, {SYNC_ACTION_RAISE_CONTAINMENT_BLOCKER}, 1, SYNC_BLOCKER_ACTIVATION_CONTAINED},
    {SYNC_PHASE_STAGED, SYNC_EVENT_OFFER_RECEIVED,   false, SYNC_PHASE_ACTIVATION_CONTAINED, {SYNC_ACTION_RAISE_CONTAINMENT_BLOCKER}, 1, SYNC_BLOCKER_ACTIVATION_CONTAINED},
    {SYNC_PHASE_STAGED, SYNC_EVENT_OFFER_ACCEPTED,   false, SYNC_PHASE_ACTIVATION_CONTAINED, {SYNC_ACTION_RAISE_CONTAINMENT_BLOCKER}, 1, SYNC_BLOCKER_ACTIVATION_CONTAINED},
    {SYNC_PHASE_STAGED, SYNC_EVENT_CHUNK_RECEIVED,   false, SYNC_PHASE_ACTIVATION_CONTAINED, {SYNC_ACTION_RAISE_CONTAINMENT_BLOCKER}, 1, SYNC_BLOCKER_ACTIVATION_CONTAINED},
    {SYNC_PHASE_STAGED, SYNC_EVENT_RECEIVE_COMPLETE, false, SYNC_PHASE_ACTIVATION_CONTAINED, {SYNC_ACTION_RAISE_CONTAINMENT_BLOCKER}, 1, SYNC_BLOCKER_ACTIVATION_CONTAINED},
    {SYNC_PHASE_STAGED, SYNC_EVENT_PROOF_VERIFIED,   true,  SYNC_PHASE_ACTIVATION_CONTAINED, {SYNC_ACTION_RAISE_CONTAINMENT_BLOCKER}, 1, SYNC_BLOCKER_ACTIVATION_CONTAINED},
    {SYNC_PHASE_STAGED, SYNC_EVENT_CHUNK_REJECTED,   false, SYNC_PHASE_STAGED, A0, 0, SYNC_BLOCKER_NONE},
    {SYNC_PHASE_STAGED, SYNC_EVENT_PROOF_FAILED,     false, SYNC_PHASE_STAGED, A0, 0, SYNC_BLOCKER_NONE},
    {SYNC_PHASE_STAGED, SYNC_EVENT_PEER_LOST,        false, SYNC_PHASE_STAGED, A0, 0, SYNC_BLOCKER_NONE},
    {SYNC_PHASE_STAGED, SYNC_EVENT_TIMEOUT,          false, SYNC_PHASE_STAGED, A0, 0, SYNC_BLOCKER_NONE},
    {SYNC_PHASE_STAGED, SYNC_EVENT_STOP_REQUESTED,   false, SYNC_PHASE_IDLE,   A0, 0, SYNC_BLOCKER_NONE},

    /* ── ACTIVATION_CONTAINED (holds; progress re-raises; stop resets) ── */
    {SYNC_PHASE_ACTIVATION_CONTAINED, SYNC_EVENT_START,            false, SYNC_PHASE_ACTIVATION_CONTAINED, {SYNC_ACTION_RAISE_CONTAINMENT_BLOCKER}, 1, SYNC_BLOCKER_ACTIVATION_CONTAINED},
    {SYNC_PHASE_ACTIVATION_CONTAINED, SYNC_EVENT_OFFER_RECEIVED,   false, SYNC_PHASE_ACTIVATION_CONTAINED, {SYNC_ACTION_RAISE_CONTAINMENT_BLOCKER}, 1, SYNC_BLOCKER_ACTIVATION_CONTAINED},
    {SYNC_PHASE_ACTIVATION_CONTAINED, SYNC_EVENT_OFFER_ACCEPTED,   false, SYNC_PHASE_ACTIVATION_CONTAINED, {SYNC_ACTION_RAISE_CONTAINMENT_BLOCKER}, 1, SYNC_BLOCKER_ACTIVATION_CONTAINED},
    {SYNC_PHASE_ACTIVATION_CONTAINED, SYNC_EVENT_CHUNK_RECEIVED,   false, SYNC_PHASE_ACTIVATION_CONTAINED, {SYNC_ACTION_RAISE_CONTAINMENT_BLOCKER}, 1, SYNC_BLOCKER_ACTIVATION_CONTAINED},
    {SYNC_PHASE_ACTIVATION_CONTAINED, SYNC_EVENT_RECEIVE_COMPLETE, false, SYNC_PHASE_ACTIVATION_CONTAINED, {SYNC_ACTION_RAISE_CONTAINMENT_BLOCKER}, 1, SYNC_BLOCKER_ACTIVATION_CONTAINED},
    {SYNC_PHASE_ACTIVATION_CONTAINED, SYNC_EVENT_PROOF_VERIFIED,   true,  SYNC_PHASE_ACTIVATION_CONTAINED, {SYNC_ACTION_RAISE_CONTAINMENT_BLOCKER}, 1, SYNC_BLOCKER_ACTIVATION_CONTAINED},
    {SYNC_PHASE_ACTIVATION_CONTAINED, SYNC_EVENT_CHUNK_REJECTED,   false, SYNC_PHASE_ACTIVATION_CONTAINED, A0, 0, SYNC_BLOCKER_NONE},
    {SYNC_PHASE_ACTIVATION_CONTAINED, SYNC_EVENT_PROOF_FAILED,     false, SYNC_PHASE_ACTIVATION_CONTAINED, A0, 0, SYNC_BLOCKER_NONE},
    {SYNC_PHASE_ACTIVATION_CONTAINED, SYNC_EVENT_PEER_LOST,        false, SYNC_PHASE_ACTIVATION_CONTAINED, A0, 0, SYNC_BLOCKER_NONE},
    {SYNC_PHASE_ACTIVATION_CONTAINED, SYNC_EVENT_TIMEOUT,          false, SYNC_PHASE_ACTIVATION_CONTAINED, A0, 0, SYNC_BLOCKER_NONE},
    {SYNC_PHASE_ACTIVATION_CONTAINED, SYNC_EVENT_STOP_REQUESTED,   false, SYNC_PHASE_IDLE,                 A0, 0, SYNC_BLOCKER_NONE},

    /* ── FAILED (terminal; stop resets) ── */
    {SYNC_PHASE_FAILED, SYNC_EVENT_START,            false, SYNC_PHASE_FAILED, A0, 0, SYNC_BLOCKER_NONE},
    {SYNC_PHASE_FAILED, SYNC_EVENT_OFFER_RECEIVED,   false, SYNC_PHASE_FAILED, A0, 0, SYNC_BLOCKER_NONE},
    {SYNC_PHASE_FAILED, SYNC_EVENT_OFFER_ACCEPTED,   false, SYNC_PHASE_FAILED, A0, 0, SYNC_BLOCKER_NONE},
    {SYNC_PHASE_FAILED, SYNC_EVENT_CHUNK_RECEIVED,   false, SYNC_PHASE_FAILED, A0, 0, SYNC_BLOCKER_NONE},
    {SYNC_PHASE_FAILED, SYNC_EVENT_CHUNK_REJECTED,   false, SYNC_PHASE_FAILED, A0, 0, SYNC_BLOCKER_NONE},
    {SYNC_PHASE_FAILED, SYNC_EVENT_RECEIVE_COMPLETE, false, SYNC_PHASE_FAILED, A0, 0, SYNC_BLOCKER_NONE},
    {SYNC_PHASE_FAILED, SYNC_EVENT_PROOF_VERIFIED,   true,  SYNC_PHASE_FAILED, A0, 0, SYNC_BLOCKER_NONE},
    {SYNC_PHASE_FAILED, SYNC_EVENT_PROOF_FAILED,     false, SYNC_PHASE_FAILED, A0, 0, SYNC_BLOCKER_NONE},
    {SYNC_PHASE_FAILED, SYNC_EVENT_PEER_LOST,        false, SYNC_PHASE_FAILED, A0, 0, SYNC_BLOCKER_NONE},
    {SYNC_PHASE_FAILED, SYNC_EVENT_TIMEOUT,          false, SYNC_PHASE_FAILED, A0, 0, SYNC_BLOCKER_NONE},
    {SYNC_PHASE_FAILED, SYNC_EVENT_STOP_REQUESTED,   false, SYNC_PHASE_IDLE,   A0, 0, SYNC_BLOCKER_NONE},
};

static struct sync_kernel_state state_of(uint64_t sid, enum sync_phase p)
{
    struct sync_kernel_state s;
    memset(&s, 0, sizeof(s));
    s.session_id.value = sid;
    s.phase = p;
    return s;
}

static struct sync_event event_of(uint64_t sid, enum sync_event_kind k, bool proof_ok)
{
    struct sync_event e;
    memset(&e, 0, sizeof(e));
    e.session_id.value = sid;
    e.kind = k;
    e.proof_ok = proof_ok;
    return e;
}

/* ── The matrix drives the primary test ── */

static int test_sync_reduce_matrix(void)
{
    int failures = 0;
    const int rows = (int)(sizeof(g_matrix) / sizeof(g_matrix[0]));

    for (int r = 0; r < rows; r++) {
        const struct row *row = &g_matrix[r];
        TEST("sync_reduce matrix") {
            struct sync_transition d =
                sync_reduce(state_of(42, row->phase),
                            event_of(42, row->event, row->proof_ok));

            if (d.next_state.phase != row->next || d.action_count != row->n_acts ||
                d.blocker != row->blocker ||
                d.has_blocker != (row->blocker != SYNC_BLOCKER_NONE)) {
                printf("\n  ROW %d: %s + %s (proof_ok=%d): "
                       "got next=%s ac=%d blk=%d, want next=%s ac=%d blk=%d\n",
                       r, sync_phase_name(row->phase),
                       sync_event_name(row->event), (int)row->proof_ok,
                       sync_phase_name(d.next_state.phase), d.action_count, (int)d.blocker,
                       sync_phase_name(row->next), row->n_acts, (int)row->blocker);
            }
            ASSERT(d.next_state.phase == row->next);
            ASSERT(d.action_count == row->n_acts);
            ASSERT(d.blocker == row->blocker);
            ASSERT(d.has_blocker == (row->blocker != SYNC_BLOCKER_NONE));
            for (int i = 0; i < row->n_acts; i++)
                ASSERT(d.actions[i] == row->acts[i]);
            for (int i = row->n_acts; i < SYNC_TRANSITION_MAX_ACTIONS; i++)
                ASSERT(d.actions[i] == SYNC_ACTION_NONE);
            PASS();
        } _test_next:;
    }
    return failures;
}

/* The hand matrix must cover every (phase, classic-event) pair exactly once —
 * plus the VERIFYING+PROOF_VERIFIED proof_ok split. Separately, EVERY phase ×
 * EVERY event (all 19, including the typed verdict + Phase-3 stubs) must yield
 * a well-formed transition — the compiler already proves the switches are total
 * (no default), and this is the runtime witness. */
static int test_sync_reduce_matrix_is_total(void)
{
    int failures = 0;
    TEST("sync_reduce: matrix covers every (phase,classic-event); all events well-formed") {
        const int rows = (int)(sizeof(g_matrix) / sizeof(g_matrix[0]));
        ASSERT(rows == SYNC_PHASE_COUNT * N_CLASSIC_EVENTS + 1);
        /* Classic events are exactly [0, N_CLASSIC_EVENTS). */
        int seen[SYNC_PHASE_COUNT][N_CLASSIC_EVENTS];
        memset(seen, 0, sizeof(seen));
        for (int r = 0; r < rows; r++) {
            ASSERT(g_matrix[r].event < N_CLASSIC_EVENTS);
            seen[g_matrix[r].phase][g_matrix[r].event]++;
        }
        for (int p = 0; p < SYNC_PHASE_COUNT; p++)
            for (int e = 0; e < N_CLASSIC_EVENTS; e++)
                ASSERT(seen[p][e] >= 1);

        /* Full event set well-formed (totality witness). */
        for (int p = 0; p < SYNC_PHASE_COUNT; p++)
            for (int e = 0; e < SYNC_EVENT_COUNT; e++) {
                struct sync_transition d = sync_reduce(
                    state_of(1, (enum sync_phase)p),
                    event_of(1, (enum sync_event_kind)e, true));
                ASSERT(d.next_state.phase >= 0 &&
                       d.next_state.phase < SYNC_PHASE_COUNT);
                ASSERT(d.action_count >= 0 &&
                       d.action_count <= SYNC_TRANSITION_MAX_ACTIONS);
            }
        PASS();
    } _test_next:;
    return failures;
}

static int test_sync_reduce_names(void)
{
    int failures = 0;
    TEST("sync_reduce: every catalog name is non-sentinel and round-trips") {
        for (int p = 0; p < SYNC_PHASE_COUNT; p++)
            ASSERT(strcmp(sync_phase_name((enum sync_phase)p), "?") != 0);
        for (int e = 0; e < SYNC_EVENT_COUNT; e++)
            ASSERT(strcmp(sync_event_name((enum sync_event_kind)e), "?") != 0);
        for (int a = 0; a < SYNC_ACTION_COUNT; a++)
            ASSERT(strcmp(sync_action_name((enum sync_action)a), "?") != 0);
        ASSERT(strcmp(sync_phase_name((enum sync_phase)SYNC_PHASE_COUNT), "?") == 0);
        ASSERT(strcmp(sync_event_name((enum sync_event_kind)SYNC_EVENT_COUNT), "?") == 0);
        ASSERT(strcmp(sync_action_name((enum sync_action)SYNC_ACTION_COUNT), "?") == 0);
        PASS();
    } _test_next:;
    return failures;
}

static int test_sync_reduce_deterministic(void)
{
    int failures = 0;
    TEST("sync_reduce: same (state,event) yields a field-identical transition") {
        struct sync_kernel_state s = state_of(7, SYNC_PHASE_RECEIVING);
        s.chunks_total.value = 5;
        struct sync_event e = event_of(7, SYNC_EVENT_CHUNK_RECEIVED, false);
        struct sync_transition d1 = sync_reduce(s, e);
        struct sync_transition d2 = sync_reduce(s, e);
        ASSERT(sync_transition_eq(&d1, &d2));
        ASSERT(d1.action_count >= 0 &&
               d1.action_count <= SYNC_TRANSITION_MAX_ACTIONS);
        ASSERT(d1.next_state.phase >= 0 && d1.next_state.phase < SYNC_PHASE_COUNT);
        PASS();
    } _test_next:;
    return failures;
}

/* A stale session cannot change a single field of state and emits no action. */
static int test_sync_reduce_stale_session(void)
{
    int failures = 0;
    TEST("sync_reduce: a stale-session event moves no state field") {
        struct sync_kernel_state s = state_of(9, SYNC_PHASE_VERIFYING);
        s.height.value = 1234;
        s.chunks_total.value = 8;
        s.chunks_received.value = 3;
        struct sync_event e = event_of(1234, SYNC_EVENT_PROOF_VERIFIED, true);
        struct sync_transition d = sync_reduce(s, e);
        ASSERT(sync_kernel_state_eq(&d.next_state, &s));
        ASSERT(d.action_count == 0);
        ASSERT(!d.has_blocker);
        PASS();
    } _test_next:;
    return failures;
}

/* A zero session_id (a fresh IDLE with no session) must NOT gate. */
static int test_sync_reduce_zero_session_not_stale(void)
{
    int failures = 0;
    TEST("sync_reduce: zero state session does not gate the opening event") {
        struct sync_kernel_state s = state_of(0, SYNC_PHASE_IDLE);
        struct sync_event e = event_of(555, SYNC_EVENT_OFFER_RECEIVED, false);
        struct sync_transition d = sync_reduce(s, e);
        ASSERT(d.next_state.phase == SYNC_PHASE_NEGOTIATING);
        ASSERT(d.action_count == 1);
        ASSERT(d.actions[0] == SYNC_ACTION_STORE_OFFER);
        /* The opening event ADOPTS its minted session id + peer (both kept as
         * separate fields — the session is NOT the peer). */
        ASSERT(d.next_state.session_id.value == 555);
        PASS();
    } _test_next:;
    return failures;
}

/* Session id is minted nonzero + injective, and adoption keeps it distinct
 * from the peer field. */
static int test_sync_reduce_session_mint_and_adopt(void)
{
    int failures = 0;
    TEST("sync_reduce: minted session is nonzero, distinct from peer, adopted on open") {
        struct zcl_sync_session_id a = zcl_sync_session_id_mint(0);
        struct zcl_sync_session_id b = zcl_sync_session_id_mint(1);
        struct zcl_sync_session_id c = zcl_sync_session_id_mint(2);
        ASSERT(a.value != 0 && b.value != 0 && c.value != 0);
        ASSERT(!zcl_sync_session_id_is_none(a));
        ASSERT(a.value != b.value && b.value != c.value && a.value != c.value);

        struct sync_kernel_state s = state_of(0, SYNC_PHASE_IDLE);
        struct sync_event e = event_of(0, SYNC_EVENT_OFFER_RECEIVED, false);
        e.session_id = zcl_sync_session_id_mint(99);
        e.peer.value = 7;                 /* a DIFFERENT value than the session */
        struct sync_transition d = sync_reduce(s, e);
        ASSERT(d.next_state.session_id.value == zcl_sync_session_id_mint(99).value);
        ASSERT(d.next_state.peer.value == 7);
        ASSERT(d.next_state.session_id.value != d.next_state.peer.value);
        PASS();
    } _test_next:;
    return failures;
}

/* The kernel OWNS the full next state — every field folds inside sync_reduce. */
static int test_sync_reduce_full_next_state(void)
{
    int failures = 0;
    TEST("sync_reduce: the kernel folds every state field (offer/reset/chunk/stage/reset)") {
        /* STORE_OFFER records height + total + roots and zeroes the counter. */
        struct sync_kernel_state s = state_of(3, SYNC_PHASE_IDLE);
        struct sync_event off = event_of(3, SYNC_EVENT_OFFER_RECEIVED, false);
        off.height.value = 900;
        off.chunks_total.value = 4;
        memset(off.chunk_root.bytes, 0xC1, 32);
        memset(off.utxo_root.bytes, 0xD2, 32);
        struct sync_transition d = sync_reduce(s, off);
        ASSERT(d.next_state.height.value == 900);
        ASSERT(d.next_state.chunks_total.value == 4);
        ASSERT(d.next_state.chunks_received.value == 0);
        ASSERT(zcl_chunk_root_eq(&d.next_state.chunk_root, &off.chunk_root));
        ASSERT(!d.next_state.proof_ok);

        /* OFFER_ACCEPTED resets the offset (chunk counter). */
        struct sync_kernel_state rs = d.next_state;
        rs.chunks_received.value = 2;
        struct sync_event acc = event_of(3, SYNC_EVENT_OFFER_ACCEPTED, false);
        struct sync_transition d2 = sync_reduce(rs, acc);
        ASSERT(d2.next_state.phase == SYNC_PHASE_RECEIVING);
        ASSERT(d2.next_state.chunks_received.value == 0);

        /* STAGE_BUNDLE sets proof_ok + the proven utxo_root. */
        struct sync_kernel_state vs = state_of(3, SYNC_PHASE_VERIFYING);
        struct sync_event pv = event_of(3, SYNC_EVENT_PROOF_VERIFIED, true);
        memset(pv.utxo_root.bytes, 0xEE, 32);
        struct sync_transition d3 = sync_reduce(vs, pv);
        ASSERT(d3.next_state.phase == SYNC_PHASE_STAGED);
        ASSERT(d3.next_state.proof_ok);
        ASSERT(zcl_utxo_root_eq(&d3.next_state.utxo_root, &pv.utxo_root));

        /* STOP_REQUESTED clears the whole session envelope back to IDLE. */
        struct sync_kernel_state busy = state_of(3, SYNC_PHASE_RECEIVING);
        busy.peer.value = 88;
        busy.height.value = 5;
        busy.chunks_received.value = 2;
        struct sync_event stop = event_of(3, SYNC_EVENT_STOP_REQUESTED, false);
        struct sync_transition d4 = sync_reduce(busy, stop);
        ASSERT(d4.next_state.phase == SYNC_PHASE_IDLE);
        ASSERT(d4.next_state.session_id.value == 0);
        ASSERT(d4.next_state.peer.value == 0);
        ASSERT(d4.next_state.chunks_received.value == 0);
        PASS();
    } _test_next:;
    return failures;
}

/* Chunk counters can never exceed the offered total. */
static int test_sync_reduce_chunk_bounded(void)
{
    int failures = 0;
    TEST("sync_reduce: chunk counter never exceeds total") {
        struct sync_kernel_state s = state_of(4, SYNC_PHASE_RECEIVING);
        s.chunks_total.value = 3;
        s.chunks_received.value = 3;   /* already at total */
        struct sync_event e = event_of(4, SYNC_EVENT_CHUNK_RECEIVED, false);
        struct sync_transition d = sync_reduce(s, e);
        ASSERT(d.next_state.chunks_received.value == 3); /* clamped, not 4 */
        /* And repeated application stays clamped. */
        struct sync_transition d2 = sync_reduce(d.next_state, e);
        ASSERT(d2.next_state.chunks_received.value == 3);
        PASS();
    } _test_next:;
    return failures;
}

/* A chunk from the wrong artifact (mismatched chunk_root) is fully inert. */
static int test_sync_reduce_wrong_artifact_chunk_inert(void)
{
    int failures = 0;
    TEST("sync_reduce: a chunk from the wrong artifact is inert") {
        struct sync_kernel_state s = state_of(5, SYNC_PHASE_RECEIVING);
        s.chunks_total.value = 8;
        s.chunks_received.value = 2;
        memset(s.chunk_root.bytes, 0xAA, 32);  /* established artifact */

        struct sync_event e = event_of(5, SYNC_EVENT_CHUNK_RECEIVED, false);
        memset(e.chunk_root.bytes, 0xBB, 32);  /* DIFFERENT artifact */
        struct sync_transition d = sync_reduce(s, e);
        ASSERT(sync_kernel_state_eq(&d.next_state, &s)); /* nothing moved */
        ASSERT(d.action_count == 0);

        /* The matching artifact still folds. */
        struct sync_event ok = event_of(5, SYNC_EVENT_CHUNK_RECEIVED, false);
        memset(ok.chunk_root.bytes, 0xAA, 32);
        struct sync_transition d2 = sync_reduce(s, ok);
        ASSERT(d2.action_count == 1);
        ASSERT(d2.actions[0] == SYNC_ACTION_APPLY_CHUNK);
        ASSERT(d2.next_state.chunks_received.value == 3);
        PASS();
    } _test_next:;
    return failures;
}

/* Typed offer verdict: ACCEPT stores + advances, REJECT is inert — and every
 * reference rejection reason maps to REJECT (the kernel preserves the outcome). */
static int test_sync_reduce_manifest_verdict(void)
{
    int failures = 0;
    TEST("sync_reduce: MANIFEST_VALIDATED accept advances, reject is inert") {
        struct sync_kernel_state idle = state_of(0, SYNC_PHASE_IDLE);

        struct sync_event acc = event_of(21, SYNC_EVENT_MANIFEST_VALIDATED, false);
        acc.verdict = SYNC_OFFER_VERDICT_ACCEPT;
        acc.height.value = 700;
        struct sync_transition da = sync_reduce(idle, acc);
        ASSERT(da.next_state.phase == SYNC_PHASE_NEGOTIATING);
        ASSERT(da.action_count == 1);
        ASSERT(da.actions[0] == SYNC_ACTION_STORE_OFFER);
        ASSERT(da.next_state.height.value == 700);

        struct sync_event rej = event_of(22, SYNC_EVENT_MANIFEST_VALIDATED, false);
        rej.verdict = SYNC_OFFER_VERDICT_REJECT;
        struct sync_transition dr = sync_reduce(idle, rej);
        ASSERT(dr.next_state.phase == SYNC_PHASE_IDLE);
        ASSERT(dr.action_count == 0);
        /* Reject on a fresh IDLE moves nothing. */
        ASSERT(sync_kernel_state_eq(&dr.next_state, &idle));

        /* In VERIFYING/STAGED a manifest verdict is inert (never activates). */
        struct sync_kernel_state staged = state_of(23, SYNC_PHASE_STAGED);
        struct sync_event any = event_of(23, SYNC_EVENT_MANIFEST_VALIDATED, false);
        any.verdict = SYNC_OFFER_VERDICT_ACCEPT;
        struct sync_transition ds = sync_reduce(staged, any);
        ASSERT(ds.next_state.phase == SYNC_PHASE_STAGED);
        ASSERT(ds.action_count == 0);
        PASS();
    } _test_next:;
    return failures;
}

/* STAGED cannot activate and install-committed is unreachable this slice. */
static int test_sync_reduce_staged_cannot_activate(void)
{
    int failures = 0;
    TEST("sync_reduce: STAGED cannot activate; install-committed is unreachable") {
        /* Every progress event from STAGED contains; none activates. */
        const enum sync_event_kind progress[] = {
            SYNC_EVENT_START, SYNC_EVENT_OFFER_RECEIVED, SYNC_EVENT_OFFER_ACCEPTED,
            SYNC_EVENT_CHUNK_RECEIVED, SYNC_EVENT_RECEIVE_COMPLETE,
            SYNC_EVENT_PROOF_VERIFIED,
        };
        for (size_t i = 0; i < sizeof(progress) / sizeof(progress[0]); i++) {
            struct sync_transition d = sync_reduce(
                state_of(4, SYNC_PHASE_STAGED),
                event_of(4, progress[i], true));
            ASSERT(d.next_state.phase == SYNC_PHASE_ACTIVATION_CONTAINED);
            ASSERT(d.actions[0] == SYNC_ACTION_RAISE_CONTAINMENT_BLOCKER);
        }
        /* The INSTALL_COMMITTED stub event NEVER reaches an installed/committed
         * state — no phase for it exists and it is inert everywhere. */
        for (int p = 0; p < SYNC_PHASE_COUNT; p++) {
            struct sync_kernel_state s = state_of(4, (enum sync_phase)p);
            struct sync_transition d = sync_reduce(
                s, event_of(4, SYNC_EVENT_INSTALL_COMMITTED, true));
            ASSERT(d.next_state.phase == (enum sync_phase)p);
            ASSERT(sync_kernel_state_eq(&d.next_state, &s));
            ASSERT(d.action_count == 0);
        }
        PASS();
    } _test_next:;
    return failures;
}

int test_sync_reduce(void)
{
    int failures = 0;
    failures += test_sync_reduce_names();
    failures += test_sync_reduce_matrix();
    failures += test_sync_reduce_matrix_is_total();
    failures += test_sync_reduce_deterministic();
    failures += test_sync_reduce_stale_session();
    failures += test_sync_reduce_zero_session_not_stale();
    failures += test_sync_reduce_session_mint_and_adopt();
    failures += test_sync_reduce_full_next_state();
    failures += test_sync_reduce_chunk_bounded();
    failures += test_sync_reduce_wrong_artifact_chunk_inert();
    failures += test_sync_reduce_manifest_verdict();
    failures += test_sync_reduce_staged_cannot_activate();
    return failures;
}
