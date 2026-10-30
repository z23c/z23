/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "thermal.h"

/* Android thermal statuses used as pace thresholds; the values are those of android/thermal.h. */
#define ZAPP_THERMAL_LIGHT 1    /* At or below: the device runs unthrottled and the node runs at full pace. */
#define ZAPP_THERMAL_MODERATE 2 /* Above LIGHT up to here: the node syncs gently. SEVERE (3) is above it. */
#define ZAPP_THERMAL_CRITICAL 4 /* At or above: the platform is out of headroom, so the node pauses. */

enum zapp_pace zapp_pace_next(enum zapp_pace previous, int thermal_status)
{
    if (thermal_status >= ZAPP_THERMAL_CRITICAL)
        return ZAPP_PACE_PAUSE;
    if (thermal_status > ZAPP_THERMAL_MODERATE)
        return previous == ZAPP_PACE_PAUSE ? ZAPP_PACE_PAUSE : ZAPP_PACE_GENTLE;
    if (thermal_status > ZAPP_THERMAL_LIGHT)
        return ZAPP_PACE_GENTLE;
    return ZAPP_PACE_NORMAL;
}

bool zapp_pace_default_needed(bool pace_file_written, bool status_known)
{
    return !pace_file_written && !status_known;
}

#ifdef __ANDROID__
#include <android/log.h>
#include <android/thermal.h>
#include <pthread.h>

struct zapp_thermal_listener {
    bool (*on_status)(int status, void *ctx);
    void *ctx;
};

static AThermalManager *g_manager;
static struct zapp_thermal_listener g_listener;

/* Held while a status is delivered, so the initial delivery and a platform callback never interleave. */
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static bool g_known; /* A status has been delivered (applied or not); g_last is the newest. */
static int g_last;

static void native_status(void *data, AThermalStatus status)
{
    const struct zapp_thermal_listener *listener = data;
    pthread_mutex_lock(&g_lock);
    g_known = true;
    g_last = (int)status;
    (void)listener->on_status((int)status, listener->ctx);
    pthread_mutex_unlock(&g_lock);
}

bool zapp_thermal_start(bool (*on_status)(int status, void *ctx), void *ctx)
{
    if (!on_status || g_manager)
        return false;
    AThermalManager *manager = AThermal_acquireManager();
    if (!manager) {
        __android_log_print(ANDROID_LOG_WARN, "z23", "thermal manager unavailable");
        return false;
    }
    g_known = false;
    g_listener = (struct zapp_thermal_listener){.on_status = on_status, .ctx = ctx};
    if (AThermal_registerThermalStatusListener(manager, native_status, &g_listener) != 0) {
        __android_log_print(ANDROID_LOG_WARN, "z23", "thermal listener registration failed");
        AThermal_releaseManager(manager);
        return false;
    }
    g_manager = manager;
    /* Read the status under the callback lock: a callback is applied before this read or after it,
     * so the status delivered last is always the newest one known. */
    pthread_mutex_lock(&g_lock);
    const AThermalStatus status = AThermal_getCurrentThermalStatus(manager);
    if (status == ATHERMAL_STATUS_ERROR)
        __android_log_print(ANDROID_LOG_WARN, "z23", "thermal status unavailable");
    else {
        g_known = true;
        g_last = (int)status;
        (void)on_status((int)status, ctx);
    }
    pthread_mutex_unlock(&g_lock);
    return true;
}

void zapp_thermal_settle(bool (*on_status)(int status, void *ctx), void (*on_none)(void *ctx), void *ctx)
{
    pthread_mutex_lock(&g_lock);
    if (g_known)
        (void)on_status(g_last, ctx);
    else
        on_none(ctx);
    pthread_mutex_unlock(&g_lock);
}

void zapp_thermal_stop(void)
{
    if (!g_manager)
        return;
    if (AThermal_unregisterThermalStatusListener(g_manager, native_status, &g_listener) != 0) {
        __android_log_print(ANDROID_LOG_WARN, "z23", "thermal listener still registered");
        return;
    }
    AThermal_releaseManager(g_manager);
    g_manager = NULL;
}
#endif
