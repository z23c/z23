/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * blocker_handoff_registry — carries the build-time blocker→remedy ratchet
 * (blocker_remedy_bindings.def) and the operator-decision table
 * (blocker_operator_decisions.def) to RUNTIME, so that every blocker in
 * `dumpstate blocker` says either what the node attempts or what a person
 * must decide. See "Hand-off resolution" in platform/modules/util/include/util/blocker.h
 * for the primitive side and the rationale.
 *
 * The primitive lives in platform/modules/util and must not know about app/ tables; this
 * module is the app-layer resolver it calls, installed once at boot. */

#ifndef ZCL_CONDITIONS_BLOCKER_HANDOFF_REGISTRY_H
#define ZCL_CONDITIONS_BLOCKER_HANDOFF_REGISTRY_H

#include <stdbool.h>
#include <stddef.h>

/* Install the resolver into the blocker primitive. Idempotent; call once at
 * boot alongside condition_registry_register_all(). */
void blocker_handoff_registry_install(void);

/* Row counts, for tests and for the coverage assertion below. */
size_t blocker_handoff_remedy_row_count(void);
size_t blocker_handoff_decision_row_count(void);

/* Direct lookup, bypassing the primitive — used by tests to assert a
 * specific id resolves to the row a reader would expect. `remedy_out` and
 * `decision_out` receive static-lifetime pointers (never freed); either may
 * be NULL. `needs_human_out` is true when the bound remedy is OWNER.
 * Returns false when no row owns the id. */
bool blocker_handoff_lookup(const char *id, const char **remedy_out,
                            const char **decision_out, bool *needs_human_out);

/* See CLAUDE.md "Adding state introspection". Reentrant-safe. */
struct json_value;
bool blocker_handoff_dump_state_json(struct json_value *out, const char *key);

#endif /* ZCL_CONDITIONS_BLOCKER_HANDOFF_REGISTRY_H */
