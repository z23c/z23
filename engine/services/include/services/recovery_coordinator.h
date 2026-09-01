/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * recovery_coordinator — one supervised organ whose sole job is the
 * "no applicable rung" naming fallback: when a CRITICAL inconsistency is
 * unresolved and no cheap self-healing condition owns it, name a typed
 * blocker so a silent halt is unrepresentable.
 *
 * The cheap recovery rungs it once dispatched inline (cursor warm-restart,
 * bounded range re-derive, sealed-segment refetch-by-hash) are NOT re-run
 * here: they are already owned, at equal or higher cadence, by the
 * standing conditions —
 *   - reducer_frontier_reconcile_light (CRITICAL, polls 5s): drives the
 *     tip_finalize cursor clamp (reconcile_tip_finalize_cursor) AND the
 *     bounded range re-derive (stage_reducer_frontier_reconcile_light);
 *   - segment_corruption (WARN, polls 30s): owns the exact
 *     segment_corruption_scan_one / _repair pair.
 * When either of those is the active healer the coordinator stays quiet —
 * the applicable rung is already firing on its own tick. The coordinator
 * only names the blocker for a critical stall no cheap self-heal covers.
 *
 * LOCK-ORDER LAW: the coordinator runs on a supervisor tick (chain domain),
 * never on a reducer drive path, and never takes a coins-store csr->lock. */

#ifndef ZCL_SERVICES_RECOVERY_COORDINATOR_H
#define ZCL_SERVICES_RECOVERY_COORDINATOR_H

#include <stdbool.h>

struct main_state;
struct json_value;

/* Supervised organ: registers a chain-domain liveness contract and, when a
 * critical condition is unresolved and no cheap self-healing condition owns
 * it, names a typed blocker once per tick. */
void recovery_coordinator_register(struct main_state *ms);
void recovery_coordinator_set_datadir(const char *datadir);

/* See CLAUDE.md "Adding state introspection". Reentrant-safe. */
bool recovery_coordinator_dump_state_json(struct json_value *out, const char *key);

#ifdef ZCL_TESTING
void recovery_coordinator_test_reset(void);
/* Drives one recovery pass (the internal supervisor-tick body) so a test can
 * exercise the unresolved-critical gate + owning-condition suppression
 * against the real condition engine. */
void recovery_coordinator_test_drive(void);
/* Names the typed blocker directly (the naming fallback in isolation). */
void recovery_coordinator_test_name_blocker(void);
long long recovery_coordinator_test_blocker_fires(void);
long long recovery_coordinator_test_runs(void);
#endif

#endif /* ZCL_SERVICES_RECOVERY_COORDINATOR_H */
