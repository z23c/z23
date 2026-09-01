/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Sticky escalator — the top-level ALWAYS-TERMINATING remedy ladder.
 *
 * This is the keystone of the sticky-node invariant S2: "Every stall reaches a
 * TERMINATING remedy; EV_OPERATOR_NEEDED is the LAST resort for genuinely-
 * unrecoverable local corruption only, never the response to a recoverable
 * class." See docs/work/sticky-node-plan.md #1 + #10.
 *
 * It is a single supervisor child (registered in g_op_sup) that consumes the
 * wedge signal raised by chain_tip_watchdog (deterministic_stall — the class
 * EVERY wedge produces) plus condition_engine_get_unresolved_count(), and drives
 * an ORDERED, PLUGGABLE rung ladder. A rung is advanced ONLY when the current
 * rung fails to make H-star/tip progress within a witness window. The deepest rung
 * re-arms with a cooldown — there is NO terminal give-up state on a recoverable
 * class. EV_OPERATOR_NEEDED, if emitted, is a NON-latching periodic "still
 * working / attention welcome" notice, never a stop.
 *
 * Verify-never-trust: no rung lowers a consensus gate. Rungs are node-local
 * recovery actions (sweep, reindex, re-derive, resnapshot, refold, peer
 * discovery, re-bootstrap). The actual chain-ADOPT step stays in the stages
 * (PoW + parity + anchor checks); the escalator only nudges re-derivation. */

#ifndef SERVICES_STICKY_ESCALATOR_H
#define SERVICES_STICKY_ESCALATOR_H

#include <stdbool.h>
#include <stdint.h>

struct main_state;
struct json_value;

/* The ordered rung ladder. Deeper = more disruptive / slower re-derivation.
 * Each must terminate; the deepest, given any honest peer set, always succeeds. */
enum sticky_rung {
    STICKY_RUNG_RETRY = 0,          /* sweep blockers + nudge conditions */
    STICKY_RUNG_TARGETED_REDERIVE,  /* blocker sweep + re-derive request */
    STICKY_RUNG_RESNAPSHOT,         /* re-pull a snapshot (lane: snapshot) */
    STICKY_RUNG_REINDEX,            /* bounded crash-only reindex-chainstate */
    STICKY_RUNG_SELF_MINT_REFOLD,   /* self-mint anchor + refold (lane: Act 3) */
    STICKY_RUNG_WIDEN_PEERS,        /* peer-discovery of last resort (lane #9) */
    STICKY_RUNG_REBOOTSTRAP,        /* re-bootstrap from genesis (floor rung) */
    STICKY_RUNG_REFOLD_FROM_ANCHOR, /* DEEPEST: runtime refold from the newest
                                     * verified anchor (arm + self-respawn) —
                                     * fail-safe-architecture.md §1 rung 3 */
    STICKY_RUNG_COUNT
};

/* A rung action returns one of these. NOT_IMPLEMENTED and FAILED both advance
 * the ladder; PROGRESSING holds the current rung for another witness window;
 * RESOLVED clears the episode. A rung MUST be non-blocking (it runs on the
 * self-heal / supervisor tick thread) — it kicks off durable work and returns. */
enum sticky_rung_result {
    STICKY_RUNG_RESOLVED = 0,       /* symptom cleared by this rung */
    STICKY_RUNG_PROGRESSING,        /* work underway; hold this rung */
    STICKY_RUNG_FAILED,             /* rung ran, no progress -> advance */
    STICKY_RUNG_NOT_IMPLEMENTED,    /* default stub -> advance */
};

typedef enum sticky_rung_result (*sticky_rung_fn)(void);

/* Register the escalator as a supervisor child in g_op_sup. Idempotent.
 * Call after main_state is initialized and after supervisor_start(). */
void sticky_escalator_register(struct main_state *ms);

/* Give the reindex rung a datadir (the bounded boot_auto_reindex primitive needs
 * it). Optional; if unset the reindex rung degrades to a stub (advance). */
void sticky_escalator_set_datadir(const char *datadir);

/* Plug a real action into a rung, replacing its default stub. Lets another lane
 * wire its rung (resnapshot/refold/widen-peers/re-bootstrap) WITHOUT editing the
 * escalator. NULL fn restores the stub. Idempotent. */
void sticky_escalator_register_rung(enum sticky_rung rung, sticky_rung_fn fn);

/* Arm (or keep armed) the ladder from a named chain-tip stall cause. The
 * chain_tip watchdog calls this on deterministic stalls or exhausted restart
 * budgets; worker-scoped stalls raise typed blockers instead. Cheap +
 * reentrant-safe; the actual rung work happens on the tick. */
void sticky_escalator_note_stall(const char *cause);

/* Run ONE ladder step: re-evaluate progress, advance/hold/reset the rung, and
 * dispatch the current rung action if it is time. Called BOTH from the self-heal
 * tick (5 s cadence) and the escalator's own supervisor tick (30 s) so the
 * ladder advances even if one driver stalls. No-op while disarmed. */
void sticky_escalator_drive(void);

/* `z23 dumpstate sticky_escalator` dumper. `out` is already initialized
 * json object; `key` is ignored. */
bool sticky_escalator_dump_state_json(struct json_value *out, const char *key);

const char *sticky_rung_name(enum sticky_rung r);

/* Tunables (seconds / blocks). */
#define STICKY_PROGRESS_MARGIN        2     /* H* climb that clears an episode */
#define STICKY_REARM_COOLDOWN_SECS    120   /* deepest-rung re-arm pause */
#define STICKY_PAGE_MIN_INTERVAL_SECS 300   /* non-latching page rate limit */
/* Consecutive targeted_rederive repairs that do NOT lift H* past the rung-entry
 * baseline before the rung FAILs (advances) instead of holding its window on a
 * repair that keeps re-clamping the same height. */
#define STICKY_REDERIVE_MAX_FLAT_REPAIRS 3
/* Livelock backstop: consecutive apply_drive passes that move NEITHER the
 * observed tip NOR the rung index before the ladder FORCE-advances the current
 * rung, so a PROGRESSING-holding rung cannot spin its whole (possibly long)
 * witness window without moving the needle. Complements the per-rung windows
 * and the absent-precondition FAILED returns; it never repeats the stuck rung. */
#define STICKY_LIVELOCK_MAX_PASSES    8
/* Blocker-aware HOLD (defect D5): while a PERMANENT-class blocker owned by the
 * sync/chain reducer domain this ladder drives is active, the escalator HOLDS
 * (no rung advance, no rung dispatch) — a permanent-class cause means the state
 * itself is incomplete (e.g. missing shielded history) or a consensus reject,
 * which NO rung (resnapshot/reindex/refold) can cure; churning them wastes hours
 * and can destroy useful state. This is the min interval between the throttled
 * "escalation held" WARNs while such a blocker persists. */
#define STICKY_HOLD_WARN_MIN_INTERVAL_SECS 300

#ifdef ZCL_TESTING
void sticky_escalator_test_reset(void);
/* Drive the ladder with an injected provable-tip and monotonic clock, running
 * the REAL advance/hold/reset logic. Returns the rung the ladder is now on. */
enum sticky_rung sticky_escalator_test_drive(int64_t injected_tip,
                                             int64_t now_unix);
bool sticky_escalator_test_armed(void);
/* Refold rung test seams: suppress the real shutdown/self-respawn syscalls (so a
 * unit test drives the rung without killing the test process) and force the
 * anchor-artifact gate (-1 = real probe, 0 = no artifact, 1 = artifact present)
 * so the arm and the no-artifact-blocker paths are both exercisable. */
void sticky_escalator_test_set_suppress_refold_restart(bool suppress);
void sticky_escalator_test_set_refold_artifact_available(int override_value);
/* widen_peers rung test seam: count of actual connman_kick_seed_discovery/
 * connman_kick_onion_seeds dispatches (excludes the no-connman / already-
 * healthy / cooldown-hold early-outs). */
uint64_t sticky_escalator_test_widen_kicks(void);

/* Livelock backstop test seam: count of times a rung was force-advanced by the
 * per-episode zero-progress assertion (STICKY_LIVELOCK_MAX_PASSES). */
uint64_t sticky_escalator_test_livelock_force_advances(void);
/* Actual action invocations (not hold polls) for one rung. */
uint64_t sticky_escalator_test_rung_dispatches(enum sticky_rung rung);
/* Override the generic auto-arm's pending-chain-work witness:
 * -1=live context, 0=caught up, 1=work pending. */
void sticky_escalator_test_set_pending_work(int override_value);

/* Blocker-aware HOLD test seams (defect D5): whether the last drive HELD on a
 * permanent sync-domain blocker, and the monotonic count of held drives. */
bool     sticky_escalator_test_held_by_permanent(void);
uint64_t sticky_escalator_test_permanent_hold_fires(void);
#endif

#endif /* SERVICES_STICKY_ESCALATOR_H */
