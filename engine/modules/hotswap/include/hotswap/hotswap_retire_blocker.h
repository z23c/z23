/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Typed blocker for a retired hot-swap generation whose superseded module
 * mapping never drained.
 *
 * The gap this closes
 * -------------------
 * `retire_handle()` (engine/modules/hotswap/src/hotswap_activate.c) dlcloses the
 * superseded module .so only after the resident quiesce callback confirms
 * every retired command-registry override snapshot has drained. If drain
 * cannot be confirmed inside the bounded ~2 s window it does the SAFE thing
 * and keeps the mapping forever — a deliberate leak that can never
 * use-after-free. Safe, but until now completely INVISIBLE: one LOG_WARN
 * line and a counter nobody polls. At a swap rate high enough to matter
 * that is one leaked mapping + fd per swap with no operator signal at all,
 * which is exactly the "silent stop" the architecture forbids: a stall must
 * be a NAMED blocker, never a quiet accumulation.
 *
 * So the retention now raises a typed blocker
 * (`hotswap.retired_generation_undrained`, BLOCKER_DEPENDENCY — the retire
 * path is waiting on command dispatch to drain, and DEPENDENCY keeps it
 * below a real resource exhaustion in `blocker_causal_priority`), with a
 * deadline-triggered escape that RETRIES the reclaim.
 *
 * Reason-string discipline
 * ------------------------
 * `blocker_set` treats the reason text as part of fault identity: a reason
 * that varies per occurrence resets the escalation clock and defeats dedup.
 * The reason here is therefore a fixed sentence with NO retained count, no
 * handle address, no generation number and no timestamp in it. The varying
 * quantity lives in `hotswap_retire_blocker_retained()` and the
 * `retained_mapped_count` field of the hotswap dump, where it belongs.
 *
 * The reclaim seam
 * ----------------
 * Dynamic loading is DEV-ONLY, so the code that actually holds the pending
 * handles and can call dlclose is compiled only under ZCL_DEV_BUILD. This
 * TU is compiled ALWAYS (naming and escape registration must not depend on
 * the build flavor) and reaches the reclaim through
 * `hotswap_retire_blocker_set_reclaimer()`. With no reclaimer installed the
 * escape does not pretend to fix anything: it logs that no reclaim path is
 * available and leaves the blocker standing, which is the honest outcome.
 */

#ifndef ZCL_HOTSWAP_RETIRE_BLOCKER_H
#define ZCL_HOTSWAP_RETIRE_BLOCKER_H

#include <stdbool.h>

/* Exact blocker id (see engine/conditions/include/conditions/
 * blocker_remedy_bindings.def for its remedy row). */
#define HOTSWAP_RETIRE_UNDRAINED_BLOCKER_ID \
    "hotswap.retired_generation_undrained"

/* Escape action name; registered by
 * hotswap_retire_blocker_register_escape(). */
#define HOTSWAP_RETIRE_ESCAPE_ACTION "hotswap_reclaim_retry"

/* Seconds from first retention to the escape (one reclaim retry). */
#define HOTSWAP_RETIRE_ESCAPE_DEADLINE_SECS 60

/* Reclaim callback installed by the activation core. Must attempt to drain
 * and dlclose every mapping still retained, and return true only when NONE
 * remain. Called from the blocker supervisor sweep's dispatch phase, i.e.
 * outside the blocker registry lock. */
typedef bool (*hotswap_reclaim_fn)(void *ctx);

/* Register HOTSWAP_RETIRE_ESCAPE_ACTION with the blocker escape registry.
 * Idempotent. `hotswap_retire_blocker_raise()` calls this itself, so boot
 * does not have to remember to: an escape_action that resolves to nothing
 * dead-ends the sweep's lookup silently, and arming it at the raise that
 * needs it removes that ordering hazard entirely. Exposed for tests and for
 * anyone who wants the action visible in the registry before first use. */
void hotswap_retire_blocker_register_escape(void);

/* Install (or clear, with fn == NULL) the reclaim seam. */
void hotswap_retire_blocker_set_reclaimer(hotswap_reclaim_fn fn, void *ctx);

/* One superseded mapping was retained because drain was unconfirmed.
 * Increments the retained count and raises/refreshes the blocker. */
void hotswap_retire_blocker_raise(void);

/* One retained mapping was reclaimed. Decrements the retained count and,
 * when it reaches zero, clears the blocker — the fault is genuinely over,
 * so the claim must not outlive it. */
void hotswap_retire_blocker_note_reclaimed(void);

/* Mappings currently retained (undrained). Volatile by design: it is
 * deliberately NOT in the blocker reason string. */
unsigned long hotswap_retire_blocker_retained(void);

/* Test hook: zero the retained count and drop any installed reclaimer.
 * Does not touch the blocker registry (use blocker_reset_for_testing). */
void hotswap_retire_blocker_reset_for_testing(void);

#endif /* ZCL_HOTSWAP_RETIRE_BLOCKER_H */
