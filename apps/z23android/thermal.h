/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZAPP_THERMAL_H
#define ZAPP_THERMAL_H
#include <stdbool.h>

enum zapp_pace { ZAPP_PACE_NORMAL, ZAPP_PACE_GENTLE, ZAPP_PACE_PAUSE };

/* The node pace for the next Android thermal status (0 none to 6 shutdown), given the pace in
 * effect. Statuses above LIGHT hold GENTLE, CRITICAL and above pause, and a paused node stays
 * paused at SEVERE so that it does not resume while the device is still hot. */
enum zapp_pace zapp_pace_next(enum zapp_pace previous, int thermal_status);

/* Whether the startup default pace must be written: only when no status has reached the pace file
 * and none is known at all. A known status whose write failed is retried, never replaced by normal. */
bool zapp_pace_default_needed(bool pace_file_written, bool status_known);

#ifdef __ANDROID__
/* Registers on_status with the platform thermal service and delivers the current status once.
 * on_status runs on a platform thread and returns whether the status reached the pace file; a status
 * it could not apply does not suppress the initial delivery. Returns false if a listener is already
 * registered or the service is unavailable. */
bool zapp_thermal_start(bool (*on_status)(int status, void *ctx), void *ctx);

/* Settles the pace after start, under the lock that serializes status deliveries: if any status has
 * been delivered (applied or not) the newest is applied again through on_status; otherwise on_none
 * runs. The decision and the write are one critical section, so no delivery can interleave and a
 * known status is never replaced by the default. */
void zapp_thermal_settle(bool (*on_status)(int status, void *ctx), void (*on_none)(void *ctx), void *ctx);

/* Unregisters the listener and releases the thermal manager. Does nothing when not started. */
void zapp_thermal_stop(void);
#endif

#endif
