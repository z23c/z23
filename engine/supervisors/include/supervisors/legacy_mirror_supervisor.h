/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#ifndef ZCL_SUPERVISORS_LEGACY_MIRROR_SUPERVISOR_H
#define ZCL_SUPERVISORS_LEGACY_MIRROR_SUPERVISOR_H

#include <stdbool.h>
#include <stdint.h>

/* Pure policy helpers used by the supervisor and its deterministic tests.
 * A missing optional zclassicd must not become a tight retry or log loop. */
int legacy_mirror_supervisor_backoff_secs(int base_cadence_secs,
                                          uint32_t consecutive_failures);
bool legacy_mirror_supervisor_should_emit_stall(uint64_t stall_count);

/* Register (or re-arm) the legacy-mirror sync as a child of the chain
 * supervisor domain, ticking every `cadence_secs` seconds;
 * `cadence_secs <= 0` defaults to 3. If already registered, only the
 * period is updated and an immediate progress/tick is recorded. Returns
 * true on success; returns false (via LOG_FAIL) if the supervisor
 * thread or domain registration fails. */
bool legacy_mirror_supervisor_start(int cadence_secs);

/* Disarm the legacy-mirror child by setting its period to 0 so it stops
 * ticking; under ZCL_TESTING it is also fully unregistered. No-op if not
 * registered. */
void legacy_mirror_supervisor_stop(void);

/* True iff the child is registered and its period is > 0 (actively
 * scheduled). */
bool legacy_mirror_supervisor_running(void);

#endif /* ZCL_SUPERVISORS_LEGACY_MIRROR_SUPERVISOR_H */
