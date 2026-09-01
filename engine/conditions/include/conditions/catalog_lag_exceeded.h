/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * catalog_lag_exceeded — public registration + test hooks for the self-heal
 * condition that names a chain-data index lagging too far behind H* as a typed
 * blocker (see the SYMPTOM/REMEDY/WITNESS contract below). */

#ifndef ZCL_CONDITIONS_CATALOG_LAG_EXCEEDED_H
#define ZCL_CONDITIONS_CATALOG_LAG_EXCEEDED_H

#include <stdbool.h>
#include <stddef.h>

/* SYMPTOM: some ENABLED chain-data index (catalog_completeness) is more than
 *   CATALOG_LAG_EXCEEDED_BLOCKS (1000) behind the reducer's provable served
 *   height H*, sustained across two consecutive detect passes (a single blip
 *   during a normal catch-up burst never fires).
 * REMEDY (non-destructive): log which index + cursor, and raise/refresh the
 *   typed named blocker "catalog.<index>.lag_exceeded" (BLOCKER_DEPENDENCY —
 *   waiting on that index's own backfill service). Never truncates or rewrites
 *   any store.
 * WITNESSED: that index's cursor advanced past the value recorded at detect
 *   (the backfill is making real progress); the blocker is cleared on witness.
 * COND_WARN; poll_secs=5; rearm-forever cooldown (peer_floor's posture) so a
 *   persistently-behind index keeps nudging without permanently latching. */
void register_catalog_lag_exceeded(void);

/* See CLAUDE.md "Adding state introspection". Reentrant-safe.
 * `z23 dumpstate catalog_coverage` — per-index cursor, floor, target,
 * lag, coverage over the reachable range, and the decisive
 * `emptiness_is_meaningful` flag. `key` is unused (one dump returns all
 * rows). */
struct json_value;
bool catalog_coverage_dump_state_json(struct json_value *out, const char *key);

#ifdef ZCL_TESTING
struct catalog_index_status;
void catalog_lag_exceeded_test_reset(void);
/* Drive the sustain evaluator with an injected snapshot (bypasses the live
 * catalog read). Returns what detect() would return for this pass. */
bool catalog_lag_exceeded_test_feed(const struct catalog_index_status *rows,
                                    size_t n);
/* Invoke the real remedy (raises the named blocker). Returns the remedy enum
 * as an int (COND_REMEDY_*). */
int catalog_lag_exceeded_test_remedy(void);
int catalog_lag_exceeded_test_remedy_calls(void);
/* The latched offending index name after a firing feed, or NULL. */
const char *catalog_lag_exceeded_test_lagging_name(void);
#endif

#endif /* ZCL_CONDITIONS_CATALOG_LAG_EXCEEDED_H */
