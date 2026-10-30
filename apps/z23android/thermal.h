/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZAPP_THERMAL_H
#define ZAPP_THERMAL_H
#include <stdbool.h>

enum zapp_pace { ZAPP_PACE_NORMAL, ZAPP_PACE_GENTLE, ZAPP_PACE_PAUSE };

/* The node pace for the next Android thermal status (0 none to 6 shutdown), given the pace in
 * effect. Statuses above LIGHT hold GENTLE, CRITICAL and above pause, and a paused node stays
 * paused at SEVERE so that it does not resume while the device is still hot. */
enum zapp_pace zapp_pace_next(enum zapp_pace previous, int thermal_status);

#ifdef __ANDROID__
/* Registers on_status with the platform thermal service and delivers the current status once.
 * on_status runs on a platform thread. Returns false if a listener is already registered or the
 * service is unavailable. */
bool zapp_thermal_start(void (*on_status)(int status, void *ctx), void *ctx);

/* Unregisters the listener and releases the thermal manager. Does nothing when not started. */
void zapp_thermal_stop(void);
#endif

#endif
