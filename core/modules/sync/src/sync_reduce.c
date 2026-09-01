/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Pure sync reducer — see sync/sync_reduce.h.
 *
 * The whole snapshot fast-sync FSM as one total, side-effect-free function.
 * It models the EXISTING flow (core/modules/sync/src/sync_state.c g_snapsync_transitions
 * + the offer/receive/verify path in engine/services/src/snapshot_*.c and
 * core/modules/net/src/msgprocessor_snapshot.c):
 *
 *     IDLE ──OFFER_RECEIVED/MANIFEST_VALIDATED(ACCEPT)/START──▶ NEGOTIATING
 *     NEGOTIATING ──OFFER_ACCEPTED──▶ RECEIVING
 *     RECEIVING ──RECEIVE_COMPLETE──▶ VERIFYING
 *     VERIFYING ──PROOF_VERIFIED(proof_ok)──▶ STAGED
 *     STAGED ──any progress event──▶ ACTIVATION_CONTAINED   (blocker raised)
 *     {NEGOTIATING,RECEIVING,VERIFYING} ──PROOF_FAILED/PEER_LOST/TIMEOUT──▶ FAILED
 *
 * Full next-state ownership: sync_reduce now returns a `sync_transition` whose
 * `next_state` is the COMPLETE post-fold kernel state. The kernel — not the
 * adapter — updates every field (phase, session id, peer, height, roots, chunk
 * counters, proof status). The impure adapter adopts `next_state` wholesale and
 * only executes the emitted actions; it no longer mutates state fields itself.
 *
 * Containment is UNREPRESENTABLE: the action enum has no ACTIVATE / PUBLISH
 * member (sync_kernel_catalog.def), mirroring
 * g_snapsync_transitions[VERIFYING][COMPLETE]=false. The furthest a transition
 * carries state is STAGED; the only thing it can do at the activation boundary
 * is RAISE_CONTAINMENT_BLOCKER and move to ACTIVATION_CONTAINED. The Phase-3
 * generic-artifact catalog stubs (ARTIFACT_VERIFIED … SOVEREIGN_REACHED) are
 * inert in every phase this slice — no install/committed phase is reachable.
 *
 * Purity law: no clock, RNG, socket, DB, global, or allocation. Every input is
 * in the two by-value arguments. Determinism is FIELD-WISE (sync_transition_eq)
 * — the native struct layout is deliberately NOT an ABI, so tests compare
 * fields, never raw bytes. The exhaustive phase×event switches carry NO default
 * — a new phase/event forces a compile error until every arm is handled. */

#include "sync/sync_reduce.h"

#include <string.h>

/* Catalog count guards (pattern: engine/composition/src/command_catalog.c:278). If a
 * phase/event/action is added to the .def, bump the matching number here so
 * the exhaustive switches and name tables are forced back into sync. */
_Static_assert(SYNC_PHASE_COUNT == 7,
               "sync_phase catalog changed — update sync_reduce switches + name table");
_Static_assert(SYNC_EVENT_COUNT == 19,
               "sync_event catalog changed — update sync_reduce switches + name table");
_Static_assert(SYNC_ACTION_COUNT == 10,
               "sync_action catalog changed — update the adapter action executor");

/* Structural proof of the containment law: no action names ACTIVATE/PUBLISH.
 * This is only a reminder guard — the enum simply has no such member, so a
 * decision physically cannot ask for tip activation. */
_Static_assert(SYNC_BLOCKER_COUNT >= 1, "at least SYNC_BLOCKER_NONE must exist");

/* ── Decision core builders (the phase/action/blocker part of a transition) ──
 * Each per-phase arm returns a `sync_decision` core (next phase + ordered
 * actions + optional blocker); sync_reduce() then folds the full next state on
 * top. All memset-zeroed so unused action slots read SYNC_ACTION_NONE. */

static struct sync_decision decision_base(enum sync_phase next)
{
    struct sync_decision d;
    memset(&d, 0, sizeof(d));
    d.next = next;
    for (int i = 0; i < SYNC_TRANSITION_MAX_ACTIONS; i++)
        d.actions[i] = SYNC_ACTION_NONE;
    d.action_count = 0;
    d.has_blocker = false;
    d.blocker = SYNC_BLOCKER_NONE;
    return d;
}

/* Stay in / move to `next` with no side effects. */
static struct sync_decision decision_noop(enum sync_phase next)
{
    return decision_base(next);
}

/* Move to `next` emitting a single action. */
static struct sync_decision decision_act1(enum sync_phase next,
                                          enum sync_action a0)
{
    struct sync_decision d = decision_base(next);
    d.actions[0] = a0;
    d.action_count = 1;
    return d;
}

/* Move to `next` emitting two ordered actions. */
static struct sync_decision decision_act2(enum sync_phase next,
                                          enum sync_action a0,
                                          enum sync_action a1)
{
    struct sync_decision d = decision_base(next);
    d.actions[0] = a0;
    d.actions[1] = a1;
    d.action_count = 2;
    return d;
}

/* Terminal failure with a typed blocker (proof failure / peer loss / timeout). */
static struct sync_decision decision_fail(enum sync_blocker blocker)
{
    struct sync_decision d = decision_base(SYNC_PHASE_FAILED);
    d.actions[0] = SYNC_ACTION_FAIL;
    d.action_count = 1;
    d.has_blocker = true;
    d.blocker = blocker;
    return d;
}

/* The activation door: verified state may NOT self-activate. Raise the typed
 * containment blocker and move to (or hold at) ACTIVATION_CONTAINED. The only
 * action available here is RAISE_CONTAINMENT_BLOCKER — there is deliberately
 * no ACTIVATE action to reach for. */
static struct sync_decision decision_contain(void)
{
    struct sync_decision d = decision_base(SYNC_PHASE_ACTIVATION_CONTAINED);
    d.actions[0] = SYNC_ACTION_RAISE_CONTAINMENT_BLOCKER;
    d.action_count = 1;
    d.has_blocker = true;
    d.blocker = SYNC_BLOCKER_ACTIVATION_CONTAINED;
    return d;
}

/* MANIFEST_VALIDATED orchestration: the offer's manifest was validated by the
 * SOLE authority (snapshot_manifest_validate_offer, mapped to a verdict by the
 * adapter). ACCEPT stores the offer and advances like OFFER_RECEIVED; REJECT is
 * inert. The kernel does not re-derive any range/schema/finality/work rule. */
static struct sync_decision decision_manifest(const struct sync_event *e,
                                              enum sync_phase accept_next,
                                              enum sync_phase reject_next)
{
    if (e->verdict == SYNC_OFFER_VERDICT_ACCEPT)
        return decision_act1(accept_next, SYNC_ACTION_STORE_OFFER);
    return decision_noop(reject_next);
}

/* The Phase-3 generic-artifact stub events, folded identically (inert) in every
 * phase this slice — grouped so a switch arm can dispatch them in one label
 * run. `SYNC_STUB_EVENT_CASES` expands to the `case` labels; the arm supplies
 * the trailing `return decision_noop(<phase>);`. */
#define SYNC_STUB_EVENT_CASES            \
    case SYNC_EVENT_ARTIFACT_VERIFIED:   \
    case SYNC_EVENT_INSTALL_PREPARED:    \
    case SYNC_EVENT_INSTALL_COMMITTED:   \
    case SYNC_EVENT_TAIL_PIECE_VERIFIED: \
    case SYNC_EVENT_REDUCER_ADVANCED:    \
    case SYNC_EVENT_READY_REACHED:       \
    case SYNC_EVENT_SOVEREIGN_REACHED

/* ── Per-phase transition arms (each an exhaustive event switch, no default) ── */

static struct sync_decision reduce_idle(const struct sync_event *e)
{
    switch (e->kind) {
    case SYNC_EVENT_START:            return decision_noop(SYNC_PHASE_NEGOTIATING);
    case SYNC_EVENT_OFFER_RECEIVED:   return decision_act1(SYNC_PHASE_NEGOTIATING, SYNC_ACTION_STORE_OFFER);
    case SYNC_EVENT_MANIFEST_VALIDATED: return decision_manifest(e, SYNC_PHASE_NEGOTIATING, SYNC_PHASE_IDLE);
    case SYNC_EVENT_OFFER_ACCEPTED:   return decision_noop(SYNC_PHASE_IDLE);
    case SYNC_EVENT_CHUNK_RECEIVED:   return decision_noop(SYNC_PHASE_IDLE);
    case SYNC_EVENT_CHUNK_REJECTED:   return decision_noop(SYNC_PHASE_IDLE);
    case SYNC_EVENT_RECEIVE_COMPLETE: return decision_noop(SYNC_PHASE_IDLE);
    case SYNC_EVENT_PROOF_VERIFIED:   return decision_noop(SYNC_PHASE_IDLE);
    case SYNC_EVENT_PROOF_FAILED:     return decision_noop(SYNC_PHASE_IDLE);
    case SYNC_EVENT_PEER_LOST:        return decision_noop(SYNC_PHASE_IDLE);
    case SYNC_EVENT_TIMEOUT:          return decision_noop(SYNC_PHASE_IDLE);
    case SYNC_EVENT_STOP_REQUESTED:   return decision_noop(SYNC_PHASE_IDLE);
    SYNC_STUB_EVENT_CASES:            return decision_noop(SYNC_PHASE_IDLE);
    case SYNC_EVENT_COUNT:            break; /* not a real event */
    }
    return decision_noop(SYNC_PHASE_IDLE);
}

static struct sync_decision reduce_negotiating(const struct sync_event *e)
{
    switch (e->kind) {
    case SYNC_EVENT_START:            return decision_noop(SYNC_PHASE_NEGOTIATING);
    case SYNC_EVENT_OFFER_RECEIVED:   return decision_act1(SYNC_PHASE_NEGOTIATING, SYNC_ACTION_STORE_OFFER);
    case SYNC_EVENT_MANIFEST_VALIDATED: return decision_manifest(e, SYNC_PHASE_NEGOTIATING, SYNC_PHASE_NEGOTIATING);
    case SYNC_EVENT_OFFER_ACCEPTED:   return decision_act2(SYNC_PHASE_RECEIVING, SYNC_ACTION_RESET_OFFSET, SYNC_ACTION_BEGIN_RECEIVE);
    case SYNC_EVENT_CHUNK_RECEIVED:   return decision_noop(SYNC_PHASE_NEGOTIATING);
    case SYNC_EVENT_CHUNK_REJECTED:   return decision_noop(SYNC_PHASE_NEGOTIATING);
    case SYNC_EVENT_RECEIVE_COMPLETE: return decision_noop(SYNC_PHASE_NEGOTIATING);
    case SYNC_EVENT_PROOF_VERIFIED:   return decision_noop(SYNC_PHASE_NEGOTIATING);
    case SYNC_EVENT_PROOF_FAILED:     return decision_fail(SYNC_BLOCKER_PROOF_FAILED);
    case SYNC_EVENT_PEER_LOST:        return decision_fail(SYNC_BLOCKER_PEER_LOST);
    case SYNC_EVENT_TIMEOUT:          return decision_fail(SYNC_BLOCKER_TIMEOUT);
    case SYNC_EVENT_STOP_REQUESTED:   return decision_noop(SYNC_PHASE_IDLE);
    SYNC_STUB_EVENT_CASES:            return decision_noop(SYNC_PHASE_NEGOTIATING);
    case SYNC_EVENT_COUNT:            break;
    }
    return decision_noop(SYNC_PHASE_NEGOTIATING);
}

static struct sync_decision reduce_receiving(const struct sync_event *e)
{
    switch (e->kind) {
    case SYNC_EVENT_START:            return decision_noop(SYNC_PHASE_RECEIVING);
    case SYNC_EVENT_OFFER_RECEIVED:   return decision_noop(SYNC_PHASE_RECEIVING);
    case SYNC_EVENT_MANIFEST_VALIDATED: return decision_noop(SYNC_PHASE_RECEIVING);
    case SYNC_EVENT_OFFER_ACCEPTED:   return decision_noop(SYNC_PHASE_RECEIVING);
    case SYNC_EVENT_CHUNK_RECEIVED:   return decision_act1(SYNC_PHASE_RECEIVING, SYNC_ACTION_APPLY_CHUNK);
    case SYNC_EVENT_CHUNK_REJECTED:   return decision_act1(SYNC_PHASE_RECEIVING, SYNC_ACTION_PENALIZE_PEER);
    case SYNC_EVENT_RECEIVE_COMPLETE: return decision_act1(SYNC_PHASE_VERIFYING, SYNC_ACTION_START_VERIFY);
    case SYNC_EVENT_PROOF_VERIFIED:   return decision_noop(SYNC_PHASE_RECEIVING);
    case SYNC_EVENT_PROOF_FAILED:     return decision_fail(SYNC_BLOCKER_PROOF_FAILED);
    case SYNC_EVENT_PEER_LOST:        return decision_fail(SYNC_BLOCKER_PEER_LOST);
    case SYNC_EVENT_TIMEOUT:          return decision_fail(SYNC_BLOCKER_TIMEOUT);
    case SYNC_EVENT_STOP_REQUESTED:   return decision_noop(SYNC_PHASE_IDLE);
    SYNC_STUB_EVENT_CASES:            return decision_noop(SYNC_PHASE_RECEIVING);
    case SYNC_EVENT_COUNT:            break;
    }
    return decision_noop(SYNC_PHASE_RECEIVING);
}

static struct sync_decision reduce_verifying(const struct sync_event *e)
{
    switch (e->kind) {
    case SYNC_EVENT_START:            return decision_noop(SYNC_PHASE_VERIFYING);
    case SYNC_EVENT_OFFER_RECEIVED:   return decision_noop(SYNC_PHASE_VERIFYING);
    case SYNC_EVENT_MANIFEST_VALIDATED: return decision_noop(SYNC_PHASE_VERIFYING);
    case SYNC_EVENT_OFFER_ACCEPTED:   return decision_noop(SYNC_PHASE_VERIFYING);
    case SYNC_EVENT_CHUNK_RECEIVED:   return decision_noop(SYNC_PHASE_VERIFYING);
    case SYNC_EVENT_CHUNK_REJECTED:   return decision_noop(SYNC_PHASE_VERIFYING);
    case SYNC_EVENT_RECEIVE_COMPLETE: return decision_noop(SYNC_PHASE_VERIFYING);
    /* The ONLY door to STAGED, and only when the proof actually passed. A
     * PROOF_VERIFIED carrying proof_ok==false is a failed proof, never a stage. */
    case SYNC_EVENT_PROOF_VERIFIED:
        return e->proof_ok
                   ? decision_act1(SYNC_PHASE_STAGED, SYNC_ACTION_STAGE_BUNDLE)
                   : decision_fail(SYNC_BLOCKER_PROOF_FAILED);
    case SYNC_EVENT_PROOF_FAILED:     return decision_fail(SYNC_BLOCKER_PROOF_FAILED);
    case SYNC_EVENT_PEER_LOST:        return decision_fail(SYNC_BLOCKER_PEER_LOST);
    case SYNC_EVENT_TIMEOUT:          return decision_fail(SYNC_BLOCKER_TIMEOUT);
    case SYNC_EVENT_STOP_REQUESTED:   return decision_noop(SYNC_PHASE_IDLE);
    SYNC_STUB_EVENT_CASES:            return decision_noop(SYNC_PHASE_VERIFYING);
    case SYNC_EVENT_COUNT:            break;
    }
    return decision_noop(SYNC_PHASE_VERIFYING);
}

static struct sync_decision reduce_staged(const struct sync_event *e)
{
    switch (e->kind) {
    /* Any attempt to PROGRESS past STAGED hits the contained activation door:
     * next==ACTIVATION_CONTAINED, blocker==SYNC_BLOCKER_ACTIVATION_CONTAINED,
     * and the only action is RAISE_CONTAINMENT_BLOCKER. No activate exists. */
    case SYNC_EVENT_START:            return decision_contain();
    case SYNC_EVENT_OFFER_RECEIVED:   return decision_contain();
    case SYNC_EVENT_OFFER_ACCEPTED:   return decision_contain();
    case SYNC_EVENT_CHUNK_RECEIVED:   return decision_contain();
    case SYNC_EVENT_RECEIVE_COMPLETE: return decision_contain();
    case SYNC_EVENT_PROOF_VERIFIED:   return decision_contain();
    /* Non-progress events: the bundle is already staged & verified — irrelevant
     * faults hold at STAGED; an explicit stop abandons it. MANIFEST_VALIDATED
     * and the generic-artifact stubs are non-progress here: they must NOT trip
     * the activation door (install/activation stays unrepresentable). */
    case SYNC_EVENT_MANIFEST_VALIDATED: return decision_noop(SYNC_PHASE_STAGED);
    case SYNC_EVENT_CHUNK_REJECTED:   return decision_noop(SYNC_PHASE_STAGED);
    case SYNC_EVENT_PROOF_FAILED:     return decision_noop(SYNC_PHASE_STAGED);
    case SYNC_EVENT_PEER_LOST:        return decision_noop(SYNC_PHASE_STAGED);
    case SYNC_EVENT_TIMEOUT:          return decision_noop(SYNC_PHASE_STAGED);
    case SYNC_EVENT_STOP_REQUESTED:   return decision_noop(SYNC_PHASE_IDLE);
    SYNC_STUB_EVENT_CASES:            return decision_noop(SYNC_PHASE_STAGED);
    case SYNC_EVENT_COUNT:            break;
    }
    return decision_noop(SYNC_PHASE_STAGED);
}

static struct sync_decision reduce_activation_contained(const struct sync_event *e)
{
    switch (e->kind) {
    /* Containment holds. A renewed progress attempt idempotently re-raises the
     * containment blocker; a stop resets to IDLE; everything else is inert. */
    case SYNC_EVENT_START:            return decision_contain();
    case SYNC_EVENT_OFFER_RECEIVED:   return decision_contain();
    case SYNC_EVENT_OFFER_ACCEPTED:   return decision_contain();
    case SYNC_EVENT_CHUNK_RECEIVED:   return decision_contain();
    case SYNC_EVENT_RECEIVE_COMPLETE: return decision_contain();
    case SYNC_EVENT_PROOF_VERIFIED:   return decision_contain();
    case SYNC_EVENT_MANIFEST_VALIDATED: return decision_noop(SYNC_PHASE_ACTIVATION_CONTAINED);
    case SYNC_EVENT_CHUNK_REJECTED:   return decision_noop(SYNC_PHASE_ACTIVATION_CONTAINED);
    case SYNC_EVENT_PROOF_FAILED:     return decision_noop(SYNC_PHASE_ACTIVATION_CONTAINED);
    case SYNC_EVENT_PEER_LOST:        return decision_noop(SYNC_PHASE_ACTIVATION_CONTAINED);
    case SYNC_EVENT_TIMEOUT:          return decision_noop(SYNC_PHASE_ACTIVATION_CONTAINED);
    case SYNC_EVENT_STOP_REQUESTED:   return decision_noop(SYNC_PHASE_IDLE);
    SYNC_STUB_EVENT_CASES:            return decision_noop(SYNC_PHASE_ACTIVATION_CONTAINED);
    case SYNC_EVENT_COUNT:            break;
    }
    return decision_noop(SYNC_PHASE_ACTIVATION_CONTAINED);
}

static struct sync_decision reduce_failed(const struct sync_event *e)
{
    switch (e->kind) {
    /* Terminal. Only an explicit stop clears the failure back to IDLE so a
     * fresh session can begin; every other event is inert. */
    case SYNC_EVENT_START:            return decision_noop(SYNC_PHASE_FAILED);
    case SYNC_EVENT_OFFER_RECEIVED:   return decision_noop(SYNC_PHASE_FAILED);
    case SYNC_EVENT_MANIFEST_VALIDATED: return decision_noop(SYNC_PHASE_FAILED);
    case SYNC_EVENT_OFFER_ACCEPTED:   return decision_noop(SYNC_PHASE_FAILED);
    case SYNC_EVENT_CHUNK_RECEIVED:   return decision_noop(SYNC_PHASE_FAILED);
    case SYNC_EVENT_CHUNK_REJECTED:   return decision_noop(SYNC_PHASE_FAILED);
    case SYNC_EVENT_RECEIVE_COMPLETE: return decision_noop(SYNC_PHASE_FAILED);
    case SYNC_EVENT_PROOF_VERIFIED:   return decision_noop(SYNC_PHASE_FAILED);
    case SYNC_EVENT_PROOF_FAILED:     return decision_noop(SYNC_PHASE_FAILED);
    case SYNC_EVENT_PEER_LOST:        return decision_noop(SYNC_PHASE_FAILED);
    case SYNC_EVENT_TIMEOUT:          return decision_noop(SYNC_PHASE_FAILED);
    case SYNC_EVENT_STOP_REQUESTED:   return decision_noop(SYNC_PHASE_IDLE);
    SYNC_STUB_EVENT_CASES:            return decision_noop(SYNC_PHASE_FAILED);
    case SYNC_EVENT_COUNT:            break;
    }
    return decision_noop(SYNC_PHASE_FAILED);
}

/* ── Full next-state fold ────────────────────────────────────────────── */

static bool chunk_root_is_set(const struct zcl_chunk_root *r)
{
    for (int i = 0; i < 32; i++)
        if (r->bytes[i] != 0)
            return true;
    return false;
}

/* Given the current state, the event, and the phase/action core the arm chose,
 * produce the COMPLETE next state. This is the ONLY place a state field is
 * updated — the adapter adopts the result verbatim. */
static struct sync_kernel_state apply_state(struct sync_kernel_state s,
                                            const struct sync_event *e,
                                            const struct sync_decision *core)
{
    struct sync_kernel_state ns = s;
    ns.phase = core->next;

    bool was_idle = (s.phase == SYNC_PHASE_IDLE);
    bool reset_to_idle = (core->next == SYNC_PHASE_IDLE && s.phase != SYNC_PHASE_IDLE);

    /* Session adoption: a session-less IDLE that folds an opening event OUT of
     * IDLE adopts that event's minted session id + its peer binding. session id
     * and peer stay SEPARATE fields — the session is not the peer. */
    if (zcl_sync_session_id_is_none(s.session_id) && was_idle &&
        core->next != SYNC_PHASE_IDLE) {
        ns.session_id = e->session_id;
        ns.peer = e->peer;
    }

    for (int i = 0; i < core->action_count; i++) {
        switch (core->actions[i]) {
        case SYNC_ACTION_STORE_OFFER:
            ns.height = e->height;
            ns.chunks_total = e->chunks_total;
            ns.chunks_received.value = 0;
            zcl_chunk_root_copy(&ns.chunk_root, &e->chunk_root);
            zcl_utxo_root_copy(&ns.utxo_root, &e->utxo_root); /* claimed root */
            ns.proof_ok = false;
            break;
        case SYNC_ACTION_RESET_OFFSET:
            ns.chunks_received.value = 0;
            break;
        case SYNC_ACTION_APPLY_CHUNK:
            /* Bounded: a chunk counter can NEVER exceed the offered total. */
            if (ns.chunks_received.value < ns.chunks_total.value)
                ns.chunks_received.value += 1;
            break;
        case SYNC_ACTION_STAGE_BUNDLE:
            ns.proof_ok = true;
            zcl_utxo_root_copy(&ns.utxo_root, &e->utxo_root); /* proven root */
            break;
        case SYNC_ACTION_NONE:
        case SYNC_ACTION_BEGIN_RECEIVE:
        case SYNC_ACTION_START_VERIFY:
        case SYNC_ACTION_RAISE_CONTAINMENT_BLOCKER:
        case SYNC_ACTION_PENALIZE_PEER:
        case SYNC_ACTION_FAIL:
            break;
        case SYNC_ACTION_COUNT:
            break;
        }
    }

    /* A reset back to IDLE clears the whole session envelope so a fresh session
     * starts from a clean slate (no stale peer/root/counter leaks across it). */
    if (reset_to_idle) {
        memset(&ns, 0, sizeof(ns));
        ns.phase = SYNC_PHASE_IDLE;
    }
    return ns;
}

static struct sync_transition transition_inert(struct sync_kernel_state state)
{
    struct sync_transition t;
    memset(&t, 0, sizeof(t));
    t.next_state = state;
    for (int i = 0; i < SYNC_TRANSITION_MAX_ACTIONS; i++)
        t.actions[i] = SYNC_ACTION_NONE;
    t.action_count = 0;
    t.has_blocker = false;
    t.blocker = SYNC_BLOCKER_NONE;
    return t;
}

/* ── The reducer ─────────────────────────────────────────────────────── */

struct sync_transition sync_reduce(struct sync_kernel_state state,
                                   struct sync_event event)
{
    /* Stale-session guard (load-bearing invariant): an event addressed to a
     * different, still-active session is ignored — unchanged state, zero
     * actions. A zero state session_id means "no session yet" and does not
     * gate. The compare is on the strong session type, never the peer. */
    if (!zcl_sync_session_id_is_none(state.session_id) &&
        state.session_id.value != event.session_id.value)
        return transition_inert(state);

    /* Wrong-artifact guard: a chunk whose artifact identity does not match the
     * established session artifact is inert — it can neither advance the chunk
     * counter nor emit an action. (Only gates once an artifact is actually
     * established, i.e. state.chunk_root is set; the zero/zero case folds
     * normally, preserving the quality-blind base flow.) */
    if (event.kind == SYNC_EVENT_CHUNK_RECEIVED &&
        chunk_root_is_set(&state.chunk_root) &&
        !zcl_chunk_root_eq(&state.chunk_root, &event.chunk_root))
        return transition_inert(state);

    /* Exhaustive phase switch — NO default. Each arm dispatches to a per-phase
     * event switch that is itself exhaustive. Adding a phase to the catalog
     * breaks the build here until its arm exists. */
    /* Pre-seeded with the inert core so the SYNC_PHASE_COUNT arm (not a real
     * phase) falls out to an unchanged state WITHOUT a `default:` label — a
     * default would silently absorb a newly-added phase instead of breaking
     * the build, which is the whole point of the no-default law above. */
    struct sync_decision core = decision_noop(state.phase);
    switch (state.phase) {
    case SYNC_PHASE_IDLE:                 core = reduce_idle(&event); break;
    case SYNC_PHASE_NEGOTIATING:          core = reduce_negotiating(&event); break;
    case SYNC_PHASE_RECEIVING:            core = reduce_receiving(&event); break;
    case SYNC_PHASE_VERIFYING:            core = reduce_verifying(&event); break;
    case SYNC_PHASE_STAGED:               core = reduce_staged(&event); break;
    case SYNC_PHASE_ACTIVATION_CONTAINED: core = reduce_activation_contained(&event); break;
    case SYNC_PHASE_FAILED:               core = reduce_failed(&event); break;
    case SYNC_PHASE_COUNT:                break; /* not a real phase */
    }

    struct sync_transition t;
    memset(&t, 0, sizeof(t));
    t.next_state = apply_state(state, &event, &core);
    for (int i = 0; i < SYNC_TRANSITION_MAX_ACTIONS; i++)
        t.actions[i] = core.actions[i];
    t.action_count = core.action_count;
    t.blocker = core.blocker;
    t.has_blocker = core.has_blocker;
    return t;
}

/* ── Field-wise equality + compat projection ─────────────────────────── */

bool sync_kernel_state_eq(const struct sync_kernel_state *a,
                          const struct sync_kernel_state *b)
{
    return a->session_id.value == b->session_id.value &&
           a->phase == b->phase &&
           a->peer.value == b->peer.value &&
           a->height.value == b->height.value &&
           a->chunks_total.value == b->chunks_total.value &&
           a->chunks_received.value == b->chunks_received.value &&
           zcl_chunk_root_eq(&a->chunk_root, &b->chunk_root) &&
           zcl_utxo_root_eq(&a->utxo_root, &b->utxo_root) &&
           a->proof_ok == b->proof_ok;
}

bool sync_transition_eq(const struct sync_transition *a,
                        const struct sync_transition *b)
{
    if (!sync_kernel_state_eq(&a->next_state, &b->next_state))
        return false;
    if (a->action_count != b->action_count ||
        a->blocker != b->blocker || a->has_blocker != b->has_blocker)
        return false;
    for (int i = 0; i < SYNC_TRANSITION_MAX_ACTIONS; i++)
        if (a->actions[i] != b->actions[i])
            return false;
    return true;
}

struct sync_decision sync_transition_to_decision(const struct sync_transition *t)
{
    struct sync_decision d;
    memset(&d, 0, sizeof(d));
    d.next = t->next_state.phase;
    for (int i = 0; i < SYNC_TRANSITION_MAX_ACTIONS; i++)
        d.actions[i] = t->actions[i];
    d.action_count = t->action_count;
    d.blocker = t->blocker;
    d.has_blocker = t->has_blocker;
    return d;
}

/* ── Name lookups (generated from the catalog) ──────────────────────── */

const char *sync_phase_name(enum sync_phase phase)
{
    switch (phase) {
#define SYNC_PHASE(id, name) case SYNC_PHASE_##id: return (name);
#include "sync/sync_kernel_catalog.def"
    case SYNC_PHASE_COUNT: break;
    }
    return "?";
}

const char *sync_event_name(enum sync_event_kind kind)
{
    switch (kind) {
#define SYNC_EVENT(id, name) case SYNC_EVENT_##id: return (name);
#include "sync/sync_kernel_catalog.def"
    case SYNC_EVENT_COUNT: break;
    }
    return "?";
}

const char *sync_action_name(enum sync_action action)
{
    switch (action) {
#define SYNC_ACTION(id, name) case SYNC_ACTION_##id: return (name);
#include "sync/sync_kernel_catalog.def"
    case SYNC_ACTION_COUNT: break;
    }
    return "?";
}
