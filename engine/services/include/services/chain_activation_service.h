/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Chain Activation Controller — single authority for block connection.
 *
 * Problem: the old chain-connection engine was called from five places across
 * three threads with zero coordination. This controller is the SINGLE entry
 * point.
 *
 * Architecture:
 *   State machine: IDLE → BOOT_PENDING → ANCHOR_ACTIVE → READY → CONNECTING → AT_TIP
 *   Planning pattern: activation_should_connect() is pure, no side effects
 *   Execution: activation_request_connect() serializes through mutex
 *   Transition table: validates every state change, rejects illegal ones
 *
 * Key invariant: while state is ANCHOR_ACTIVE, reducer activation NEVER runs.
 * No exceptions, no bypasses, no scattered boolean overrides. */

#ifndef ZCL_CHAIN_ACTIVATION_SERVICE_H
#define ZCL_CHAIN_ACTIVATION_SERVICE_H

#include "util/sync.h"
#include <stdbool.h>
#include <stdint.h>
#include <stdatomic.h>

struct main_state;
struct coins_view_cache;
struct chain_params;
struct block;
struct validation_state;

/* ── State Machine ─────────────────────────────────────────────── */

enum activation_state {
    ACTIVATION_IDLE = 0,          /* not initialized */
    ACTIVATION_BOOT_PENDING,      /* boot in progress, connection forbidden */
    ACTIVATION_ANCHOR_ACTIVE,     /* snapshot/LDB anchor, connection forbidden */
    ACTIVATION_ANCHOR_CLEARING,   /* headers past anchor, transitioning */
    ACTIVATION_READY,             /* safe to connect blocks */
    ACTIVATION_CONNECTING,        /* reducer activation running (mutex held) */
    ACTIVATION_AT_TIP,            /* caught up, waiting for new blocks */
    ACTIVATION_FAILED,            /* unrecoverable */
    ACTIVATION_NUM_STATES
};

const char *activation_state_name(enum activation_state state);
bool activation_transition_valid(enum activation_state from, enum activation_state to);

/* ── Controller ────────────────────────────────────────────────── */

struct chain_activation_controller {
    _Atomic int state;
    zcl_mutex_t mutex;          /* serializes reducer activation execution */

    /* Context (set once at init, read-only after) */
    struct main_state *ms;
    struct coins_view_cache *coins_tip;
    const struct chain_params *params;
    const char *datadir;

    /* Diagnostics */
    int64_t last_activation_us;
    int     last_tip_height;
    int     activation_count;
    int     skip_count;

    /* deferred-activation counter. A request that hits
     * SKIP_ALREADY_RUNNING (another thread is inside reducer activation under
     * the mutex) increments this atomically instead of dropping
     * the work. The thread currently holding the mutex drains it before
     * releasing so the newly-arrived-but-skipped block gets connected
     * without waiting for the next P2P arrival. */
    _Atomic int deferred_pending;
};

void activation_controller_init(struct chain_activation_controller *ctl,
                                struct main_state *ms,
                                struct coins_view_cache *coins_tip,
                                const struct chain_params *params,
                                const char *datadir);
void activation_controller_destroy(struct chain_activation_controller *ctl);

enum activation_state activation_get_state(
    const struct chain_activation_controller *ctl);
bool activation_set_state(struct chain_activation_controller *ctl,
                          enum activation_state new_state,
                          const char *reason);

/* Convenience transitions */
void activation_set_anchor_active(struct chain_activation_controller *ctl,
                                  const char *reason);
void activation_clear_anchor(struct chain_activation_controller *ctl,
                             const char *reason);
void activation_boot_complete(struct chain_activation_controller *ctl,
                              const char *reason);

/* ── Planning (pure, no side effects) ──────────────────────────── */

enum activation_request_source {
    ACTIVATION_SRC_BOOT = 0,
    ACTIVATION_SRC_UTXO_REPLAY,
    ACTIVATION_SRC_BLOCK_FILE_SCAN,
    ACTIVATION_SRC_HEADERS_ALL_DATA,
    ACTIVATION_SRC_NEW_BLOCK,
    /* Supervisor-driven evidence-based revalidation of a previously-failed
     * block. Triggered by `chain.coord_escalation`
     * after `process_block_revalidate` clears BLOCK_FAILED_VALID on
     * oracle-verified evidence. See
     * `core/modules/validation/include/validation/process_block_revalidate.h`. */
    ACTIVATION_SRC_REVALIDATE,
};

struct activation_request {
    enum activation_request_source source;
    enum activation_state current_state;
    bool shutdown_requested;
    bool anchor_active;
    bool awaiting_utxos;
    int  chain_tip_height;
};

enum activation_decision_result {
    ACTIVATION_DO_CONNECT = 0,
    ACTIVATION_SKIP_SHUTDOWN,
    ACTIVATION_SKIP_ANCHOR_BLOCKS,
    ACTIVATION_SKIP_AWAITING_UTXOS,
    ACTIVATION_SKIP_ALREADY_RUNNING,
    ACTIVATION_SKIP_WRONG_STATE,
    ACTIVATION_SKIP_AT_TIP,
};

struct activation_decision {
    enum activation_decision_result result;
    bool should_activate;
    char reason[128];
};

/* Pure function: ALL callers use this. No globals, no side effects. */
void activation_should_connect(struct activation_decision *out,
                               const struct activation_request *req);

/* ── Execution (serialized) ────────────────────────────────────── */

enum activation_exec_result {
    ACTIVATION_EXEC_OK = 0,
    ACTIVATION_EXEC_SKIPPED,
    ACTIVATION_EXEC_FAILED,
};

struct activation_exec_outcome {
    enum activation_exec_result result;
    int  new_tip_height;
    bool reached_tip;
    char reason[128];
};

/* Single entry point replacing all direct chain-connection calls.
 * Thread-safe: mutex ensures only one execution at a time. */
void activation_request_connect(struct chain_activation_controller *ctl,
                                enum activation_request_source source,
                                struct block *pblock,
                                struct activation_exec_outcome *out);

/* atomically read-and-reset the deferred-activation counter.
 * Returns the number of SKIP_ALREADY_RUNNING requests that arrived
 * while another thread held the activation mutex, since the last
 * drain. Used by the activator (under mutex) to decide whether to
 * rerun reducer activation before transitioning out of CONNECTING.
 * Also exposed for diagnostics and tests. */
int activation_drain_deferred(struct chain_activation_controller *ctl);

/* ── Reducer-as-ingest ─────────────────────────────────────────── */

/* Where an incoming block came from. Mirrors the force/requested
 * semantics of the historical block-intake callers: P2P/compact arrive
 * unrequested (force=false, relay pre-filters apply); SUBMIT/MINED/REPAIR
 * are locally requested (force=true, relay pre-filters skipped). The source
 * is informational for now — the force flag is the live arg. */
enum reducer_source {
    REDUCER_SRC_P2P = 0,       /* msg_blocks full block */
    REDUCER_SRC_COMPACT,       /* msg_compact reassembled block */
    REDUCER_SRC_SUBMIT,        /* submitblock RPC */
    REDUCER_SRC_MINED,         /* internal miner */
    REDUCER_SRC_REPAIR,        /* rebuild_recent recovery */
};

/* reducer_is_authoritative — always true after the reducer cleanup. Live
 * block-intake call sites use the reducer pipeline, not the historical intake
 * path. */
bool reducer_is_authoritative(void);

/* reducer_ingest_block — the synchronous block-intake entry that drives the
 * staged reducer Job pipeline instead of the historical activation path.
 *
 * Contract (mirrors the historical synchronous accept/reject behavior):
 *   1. check_block (stateless PoW/merkle/structure) runs FIRST, inline,
 *      BEFORE any log/stage mutation. A garbage block is rejected with a
 *      verdict in `out` and the function returns false, giving the P2P/submit
 *      caller its DoS/ban reason without polluting the stage log.
 *   2. The header (+raw bytes) is pushed into the header_admit_inbox so
 *      the reducer's producer path (step 2) can build the block_index.
 *   3. Under ctl->mutex (the reducer activation serialization point), the
 *      eight stage step bodies are drained synchronously for the target height
 *      range — including a reorg disconnect when a better fork is selected
 *      (step 4) — ahead of the 2s supervisor tickers, so a single block
 *      reaches AT_TIP within the call.
 *   4. The freshly-written validate_headers_log / tip_finalize_log rows
 *      for the target height are read back and mapped into `out`
 *      (validation_state) so validation_state_is_valid() / the reject
 *      reason flow synchronously to the caller.
 *
 * Returns true iff the block landed on the active chain (out is MODE_VALID);
 * false on any stateless or stateful reject (out carries the reason).
 * `force` carries the requested/relay-pre-filter semantics (force=true for
 * SUBMIT/MINED/REPAIR). `out` must be a caller-owned validation_state. */
bool reducer_ingest_block(struct chain_activation_controller *ctl,
                          struct block *pblock,
                          enum reducer_source source,
                          bool force,
                          struct validation_state *out);

/* reducer_stage_p2p_block_for_catchup — fast P2P catch-up intake.
 *
 * During IBD/catch-up this runs the non-header structural body checks, stages
 * the header/solution/body for the reducer, extends the in-memory have-data
 * window, and returns a retryable "pending reducer" verdict in `out` instead
 * of synchronously draining all reducer stages. Header PoW/Equihash and body
 * merkle validation are owned by the staged reducer (validate_headers and
 * body_persist), so catch-up intake does not duplicate them. At-tip delivery
 * must still use reducer_ingest_block() so submit/relay callers get an
 * immediate final accept/reject verdict.
 *
 * Returns false by design when staging succeeds: the block is not final until
 * the reducer stages fold it and publish the tip. */
bool reducer_stage_p2p_block_for_catchup(
    struct chain_activation_controller *ctl,
    struct block *pblock,
    struct validation_state *out);

/* Exact-hash block-map hits that bypassed redundant catch-up header enqueue. */
uint64_t reducer_ingest_catchup_known_header_bypass_total(void);
uint64_t reducer_ingest_catchup_validated_solution_skip_total(void);

/* reducer_kick — wake the reducer to walk the best chain with no new block
 * (the Group-2 NULL-block "connect to best tip now" path). Drains the eight
 * stage step bodies once under ctl->mutex so cursor-driven catch-up makes
 * progress without waiting for the next 2s supervisor tick. Returns the
 * number of stage advances across all eight stages this kick produced.
 */
int reducer_kick(struct chain_activation_controller *ctl);

/* reducer_kick_unbudgeted — the dedicated -mint-anchor driver's tight kick.
 * Same locking + drive marking as reducer_kick, but the inner drain has NO 2s
 * latency budget, so one call folds the staged pipeline back-to-back until
 * convergence (a no-advance pass) instead of stopping every 2s and returning
 * to the driver loop. Only engine/composition/src/boot_mint_anchor.c (the synchronous
 * genesis..anchor mint) calls this; the normal cursor-driven catch-up keeps
 * using the budgeted reducer_kick so it yields the 2s supervisor ticks. Full
 * validation is identical. Returns the number of stage advances this kick
 * produced. */
int reducer_kick_unbudgeted(struct chain_activation_controller *ctl);

/* ── UTXO Wipe Protection ──────────────────────────────────────── */

struct utxo_wipe_decision {
    bool safe_to_wipe;
    char reason[128];
};

/* Pure function: decides if UTXO wipe is safe.
 * NEVER wipes while ANCHOR_ACTIVE or ANCHOR_CLEARING. */
void activation_should_allow_utxo_wipe(struct utxo_wipe_decision *out,
                                       enum activation_state state,
                                       bool anchor_active);

/* ── Advance-or-block decision (the silent-ready guard) ─────────── */

/* The id of the single typed blocker the activation authority owns. Visible
 * in `z23 dumpstate blocker`. */
#define ACTIVATION_BEHIND_BLOCKER_ID "chain.tip_behind_header_chain"

/* Single source of truth for the post-activate advance-or-block decision.
 * Returns true when the active tip is BEHIND the most-work valid-header chain
 * (could not advance this tick) and registers the typed behind-blocker
 * (ACTIVATION_BEHIND_BLOCKER_ID: TRANSIENT, names why/height/escape). Returns
 * false when genuinely caught up and clears the blocker. The execution path
 * uses this so READY is honest only when caught up; otherwise a named blocker
 * always exists. Exposed for tests to drive the exact production decision. */
bool activation_eval_tip_blocker(int tip_h, int best_h);

/* ── Global accessor ───────────────────────────────────────────── */

struct chain_activation_controller *boot_activation_controller(void);

#endif
