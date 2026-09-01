/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Two typed blockers for the "declared vs observed" class of fault, plus
 * the seams the organs that detect them will plug into.
 *
 *   config.reload_diverged      — a configuration reload finished, but the
 *                                 configuration now in effect is not the
 *                                 one that was requested.
 *   service.declaration_diverged — the service declaration (the compiled
 *                                 catalog, engine/composition/services/catalog.def)
 *                                 does not match what is actually running.
 *
 * Why blockers and not just logs
 * ------------------------------
 * Both faults are the same shape as the hot-swap retained mapping: the safe
 * fallback (keep running the old configuration; keep serving whatever is
 * actually up) is CORRECT but silent, and a silent divergence is
 * indistinguishable from a healthy node. The architecture rule is that a
 * stall is a named blocker, never a quiet stop, so each gets a typed record
 * with an owner, a class, a deadline and a named escape.
 *
 * The declaration is NOT authoritative
 * ------------------------------------
 * `service.declaration_diverged` is observation only. Its escape may
 * re-observe and it may escalate; it must never reconcile reality TO the
 * declaration — nothing here is allowed to start, stop or reshape a running
 * service because a manifest said so. That is why the class is DEPENDENCY
 * (waiting on a reconciliation that a human or a future organ performs) and
 * the remedy row is OWNER.
 *
 * Reason-string discipline (why the scope is not in the reason)
 * ------------------------------------------------------------
 * `blocker_set` folds the reason text into fault identity: a reason that
 * varies per occurrence re-anchors the escape deadline and resets the
 * escalation clock, so a continuously-refiring fault would dodge escalation
 * forever. Each raise here therefore stores a FIXED reason sentence and
 * carries the varying part — which config key, which service — outside the
 * record, readable via `boot_declaration_drift_last_scope()` and written to
 * the log line at raise time.
 *
 * Handoff status (2026-07-24)
 * ---------------------------
 * Neither detecting organ exists in-tree yet: there is no configuration
 * reload path under config/, and no observer that compares the service
 * catalog against running reality. The ids, classes, escape actions,
 * escape registration and remedy rows are wired here so the organs have a
 * naming surface to call the moment they land — they call
 * `boot_config_reload_divergence_raise()` /
 * `boot_service_declaration_divergence_raise()` on detect, the matching
 * `_clear()` on convergence, and install a reconciler through
 * `boot_declaration_drift_set_reconciler()`. Until then the escapes have no
 * reconciler installed and say so instead of pretending to fix anything. No
 * fake caller was invented to make the tests pass.
 */

#ifndef ZCL_CONFIG_BOOT_DECLARATION_DRIFT_H
#define ZCL_CONFIG_BOOT_DECLARATION_DRIFT_H

#include <stdbool.h>

/* Exact blocker ids — each has a row in
 * engine/conditions/include/conditions/blocker_remedy_bindings.def. */
#define CONFIG_RELOAD_DIVERGED_BLOCKER_ID      "config.reload_diverged"
#define SERVICE_DECLARATION_DIVERGED_BLOCKER_ID "service.declaration_diverged"

/* Escape action names, registered by
 * boot_declaration_drift_register_escapes(). */
#define CONFIG_RELOAD_ESCAPE_ACTION       "config_reload_reconcile_retry"
#define SERVICE_DECLARATION_ESCAPE_ACTION "service_declaration_reobserve"

/* Seconds from first raise to the escape. */
#define DECLARATION_DRIFT_ESCAPE_DEADLINE_SECS 120

/* Which of the two faults a seam call refers to. */
enum declaration_drift_kind {
    DECLARATION_DRIFT_CONFIG_RELOAD = 0,
    DECLARATION_DRIFT_SERVICE_DECL  = 1,
};

/* Reconciler seam. Returns true only when the divergence is GONE (the
 * running configuration matches the request / the observation matches the
 * declaration). Invoked from the blocker supervisor sweep's dispatch phase,
 * outside the blocker registry lock. A service-declaration reconciler must
 * only re-observe and report — never mutate a running service. */
typedef bool (*declaration_drift_reconcile_fn)(void *ctx);

/* Register both escape actions with the blocker escape registry.
 * Idempotent. Both raise functions call this themselves, so boot does not
 * have to remember to: an escape_action that resolves to nothing dead-ends
 * the sweep's lookup silently, and arming it at the raise that needs it
 * removes that ordering hazard entirely. Exposed for tests and for anyone
 * who wants the actions visible in the registry before first use. */
void boot_declaration_drift_register_escapes(void);

/* Install (or clear, with fn == NULL) the reconciler for one kind. */
void boot_declaration_drift_set_reconciler(enum declaration_drift_kind kind,
                                           declaration_drift_reconcile_fn fn,
                                           void *ctx);

/* Raise / refresh. `scope` is the varying detail (config key, service name)
 * and is deliberately kept OUT of the blocker reason — see the header note.
 * NULL is accepted and recorded as "(unspecified)". */
void boot_config_reload_divergence_raise(const char *scope);
void boot_service_declaration_divergence_raise(const char *scope);

/* Clear on convergence. Idempotent; safe when nothing is raised. */
void boot_config_reload_divergence_clear(void);
void boot_service_declaration_divergence_clear(void);

/* Last scope recorded for `kind`, or "" if none. Returns a pointer to
 * module-static storage that is stable for the process lifetime. */
const char *boot_declaration_drift_last_scope(enum declaration_drift_kind kind);

/* Test hook: forget recorded scopes and installed reconcilers. Does not
 * touch the blocker registry (use blocker_reset_for_testing). */
void boot_declaration_drift_reset_for_testing(void);

#endif /* ZCL_CONFIG_BOOT_DECLARATION_DRIFT_H */
