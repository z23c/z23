/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

/* Pure sync reducer — the deterministic core of snapshot fast-sync.
 *
 * `sync_reduce(state, event)` is a total, side-effect-free transition
 * function: given the current POD `sync_kernel_state` and one `sync_event`
 * it returns a `sync_decision` (the next phase + a bounded list of side-effect
 * INTENTS + an optional typed blocker). It touches no clock, RNG, socket, DB,
 * or global — everything it needs is in its two by-value arguments, and its
 * output is data the impure adapter later executes. This is the same
 * OUT-struct / pure-planner discipline as sync_planner.h, taken to its limit:
 * the whole FSM is one function.
 *
 * It exists to collapse the triple-copied snapshot FSM (the atomic global in
 * sync_state.c, the singleton `.state` field, and the per-peer zsync_* shadow
 * fields) onto one authority that can be exhaustively tested and fuzzed. This
 * slice lands the kernel in SHADOW mode only — the reference service stays
 * authoritative; the adapter merely asserts agreement.
 *
 * Containment is UNREPRESENTABLE here: the action enum has no ACTIVATE /
 * PUBLISH value, mirroring g_snapsync_transitions[VERIFYING][COMPLETE]=false
 * in sync_state.c. The furthest a decision can carry state is STAGED, and the
 * only thing it can do at the activation boundary is RAISE_CONTAINMENT_BLOCKER.
 *
 * Dependency law: this header includes ONLY sync-local + core headers — no
 * net.h, no <pthread.h>, no sqlite. That keeps the kernel linkable into the
 * test harness and the (future) simulator without dragging the node in. */

#ifndef ZCL_SYNC_REDUCE_H
#define ZCL_SYNC_REDUCE_H

#include "core/zcl_ids.h"

#include <stdbool.h>
#include <stdint.h>

/* ── Phases / events / actions (generated from the .def catalog) ────── */

enum sync_phase {
#define SYNC_PHASE(id, name) SYNC_PHASE_##id,
#include "sync/sync_kernel_catalog.def"
    SYNC_PHASE_COUNT
};

enum sync_event_kind {
#define SYNC_EVENT(id, name) SYNC_EVENT_##id,
#include "sync/sync_kernel_catalog.def"
    SYNC_EVENT_COUNT
};

enum sync_action {
#define SYNC_ACTION(id, name) SYNC_ACTION_##id,
#include "sync/sync_kernel_catalog.def"
    SYNC_ACTION_COUNT
};

/* Typed containment/failure blocker a decision may raise. Kept sync-local
 * (no dependency on platform/modules/util/blocker.h) so the kernel stays pure. */
enum sync_blocker {
    SYNC_BLOCKER_NONE = 0,
    SYNC_BLOCKER_ACTIVATION_CONTAINED,   /* verified state may NOT self-activate */
    SYNC_BLOCKER_PROOF_FAILED,
    SYNC_BLOCKER_PEER_LOST,
    SYNC_BLOCKER_TIMEOUT,
    SYNC_BLOCKER_COUNT
};

/* Coarse offer/manifest verdict the reducer orchestrates on. This is NOT a
 * second copy of the manifest-validity rules — the SOLE authority for offer
 * range/schema/finality/work acceptance stays app/services'
 * snapshot_manifest_validate_offer(). The adapter maps that validator's typed
 * result onto this two-valued verdict; the kernel only decides orchestration
 * (store & advance vs decline). Kept sync-local so the kernel needs no
 * app/services header (dependency law). */
enum sync_offer_verdict {
    SYNC_OFFER_VERDICT_ACCEPT = 0,
    SYNC_OFFER_VERDICT_REJECT = 1,
};

/* ── POD state / event / transition ─────────────────────────────────── */

/* Fixed cap on the intents a single transition may emit. */
#define SYNC_TRANSITION_MAX_ACTIONS 4

/* The complete reducer state. Plain data only — no pointers, mutexes, or
 * handles — so it copies by value and a stale `session_id` is a pure compare.
 * `session_id` is a STRONG type distinct from `peer` so the two can never be
 * confused; `{0}` (zcl_sync_session_id_is_none) means "no active session". */
struct sync_kernel_state {
    struct zcl_sync_session_id session_id;  /* {0} == no active session */
    enum sync_phase        phase;
    struct zcl_peer_id     peer;            /* the peer this session is bound to */
    struct zcl_height      height;          /* target/anchor height of the artifact */
    struct zcl_chunk_index chunks_total;
    struct zcl_chunk_index chunks_received; /* completed chunk count; never > chunks_total */
    struct zcl_chunk_root  chunk_root;      /* artifact content identity */
    struct zcl_utxo_root   utxo_root;       /* claimed until VERIFYING passes, proven after */
    bool                   proof_ok;        /* set only by a passing PROOF_VERIFIED fold */
};

/* One input to the reducer. `session_id` must match the state's or the event
 * is stale (⇒ zero actions, unchanged state). */
struct sync_event {
    struct zcl_sync_session_id session_id;
    enum sync_event_kind   kind;
    struct zcl_peer_id     peer;
    struct zcl_chunk_index chunk_index;     /* CHUNK_RECEIVED / CHUNK_REJECTED */
    struct zcl_chunk_index chunks_total;    /* OFFER_RECEIVED / MANIFEST_VALIDATED */
    struct zcl_chunk_root  chunk_root;      /* OFFER_RECEIVED / MANIFEST_VALIDATED / CHUNK_RECEIVED */
    struct zcl_utxo_root   utxo_root;       /* OFFER_RECEIVED (claimed) / PROOF_VERIFIED (proven) */
    struct zcl_height      height;          /* OFFER_RECEIVED / MANIFEST_VALIDATED */
    bool                   proof_ok;        /* PROOF_VERIFIED payload */
    enum sync_offer_verdict verdict;        /* MANIFEST_VALIDATED verdict */
    uint32_t               reject_reason;   /* opaque validator reject code, carried for logging */
};

/* The reducer's FULL output: the complete next state (the kernel now owns every
 * field of sync_kernel_state — phase, session, peer, height, roots, chunk
 * counters, proof status), a bounded ordered list of side-effect intents, and
 * an optional typed blocker. Pure data; the impure adapter executes the actions
 * and adopts `next_state` wholesale (it no longer mutates state fields itself).
 *
 * NOTE: determinism is compared FIELD-WISE (sync_transition_eq / the eq
 * helpers) — NOT by memcmp over this struct, and NOT by hashing/serializing its
 * native layout. The native enum sizes and struct padding are deliberately NOT
 * a durable ABI; any replay/debug artifact must use a canonical field encoding,
 * never a raw struct copy. */
struct sync_transition {
    struct sync_kernel_state next_state;
    enum sync_action  actions[SYNC_TRANSITION_MAX_ACTIONS];
    int               action_count;
    enum sync_blocker blocker;
    bool              has_blocker;
};

/* Thin backward-compat projection: the phase-only view the earlier shadow
 * call sites used before the kernel owned the whole next state. Kept only for
 * the reference-FSM shadow path during this slice. */
struct sync_decision {
    enum sync_phase   next;
    enum sync_action  actions[SYNC_TRANSITION_MAX_ACTIONS];
    int               action_count;
    enum sync_blocker blocker;
    bool              has_blocker;
};

/* ── The reducer + helpers ──────────────────────────────────────────── */

/* Total, pure, deterministic. Same inputs ⇒ field-identical transition (see
 * sync_transition_eq). A stale event (event.session_id != state.session_id,
 * with a non-zero state session) yields next_state==state and action_count==0.
 * The kernel OWNS the full next state — no field is updated anywhere else. */
[[nodiscard]] struct sync_transition sync_reduce(struct sync_kernel_state state,
                                                 struct sync_event event);

/* Field-wise equality (for tests / determinism checks — layout-independent). */
bool sync_kernel_state_eq(const struct sync_kernel_state *a,
                          const struct sync_kernel_state *b);
bool sync_transition_eq(const struct sync_transition *a,
                        const struct sync_transition *b);

/* Project a full transition to the legacy phase-only decision (compat). */
struct sync_decision sync_transition_to_decision(const struct sync_transition *t);

/* Stable lowercase names; NULL-safe out-of-range → "?" sentinel string. */
const char *sync_phase_name(enum sync_phase phase);
const char *sync_event_name(enum sync_event_kind kind);
const char *sync_action_name(enum sync_action action);

#endif /* ZCL_SYNC_REDUCE_H */
