/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "thermal.h"
#include <android/log.h>
#include <android/thermal.h>
#include <assert.h>
#include <stdio.h>

/* A fake platform thermal service: registering can fire a callback before start reads the status. */
static AThermalManager *const manager = (AThermalManager *)&manager;
static int fake_current = ATHERMAL_STATUS_NONE;
static int fake_register_result;
static int fake_callback_status = -2; /* -2: no callback during registration. */

int __android_log_print(int prio, const char *tag, const char *fmt, ...)
{
    (void)prio, (void)tag, (void)fmt;
    return 0;
}
AThermalManager *AThermal_acquireManager(void) { return manager; }
void AThermal_releaseManager(AThermalManager *m) { (void)m; }
int AThermal_registerThermalStatusListener(AThermalManager *m, AThermal_StatusCallback cb, void *data)
{
    (void)m;
    if (fake_register_result == 0 && fake_callback_status != -2)
        cb(data, (AThermalStatus)fake_callback_status);
    return fake_register_result;
}
int AThermal_unregisterThermalStatusListener(AThermalManager *m, AThermal_StatusCallback cb, void *data)
{
    (void)m, (void)cb, (void)data;
    return 0;
}
AThermalStatus AThermal_getCurrentThermalStatus(AThermalManager *m)
{
    (void)m;
    return (AThermalStatus)fake_current;
}

static int delivered[8];
static int delivered_count;
static bool apply_ok;
static bool record(int status, void *ctx)
{
    (void)ctx;
    assert(delivered_count < 8);
    delivered[delivered_count++] = status;
    return apply_ok;
}

static bool run(int current, int callback_status, bool apply_succeeds, int register_result)
{
    delivered_count = 0;
    fake_current = current;
    fake_callback_status = callback_status;
    apply_ok = apply_succeeds;
    fake_register_result = register_result;
    const bool started = zapp_thermal_start(record, NULL);
    if (started)
        zapp_thermal_stop();
    return started;
}

static int settle_status = -9; /* Status the settle applied, or -9. */
static int settle_none;        /* Times the no-status default ran. */
static bool settle_apply(int status, void *ctx)
{
    (void)ctx;
    settle_status = status;
    return true;
}
static void settle_default(void *ctx)
{
    (void)ctx;
    settle_none++;
}
/* Whether a status is known: settle either applies the newest one or runs the default, never both. */
static bool known(int *status)
{
    settle_status = -9;
    settle_none = 0;
    zapp_thermal_settle(settle_apply, settle_default, NULL);
    assert((settle_status != -9) != (settle_none == 1));
    if (status && settle_status != -9)
        *status = settle_status;
    return settle_status != -9;
}

/* The decision and the write of the startup default are one critical section under the lock that also
 * serializes callbacks, so a callback cannot run between them; the fake cannot order one there. This
 * checks the outcomes that make the section matter: a known hot status whose write failed is applied
 * again and the default never runs; with nothing known only the default runs. */
static void startup_cases(void)
{
    int last = -9;
    /* A registered listener delivers the current status once, and it is known. */
    assert(run(3, -2, true, 0));
    assert(delivered_count == 1 && delivered[0] == 3);
    assert(known(&last) && last == 3 && settle_none == 0);
    /* The current status is read after an earlier callback and applied, so the newest one wins. */
    assert(run(1, 4, true, 0));
    assert(delivered_count == 2 && delivered[0] == 4 && delivered[1] == 1);
    assert(known(&last) && last == 1);
    /* A hot status whose write failed is still known: settle applies it again, never the default. */
    assert(run(4, 4, false, 0));
    assert(delivered_count == 2 && delivered[0] == 4 && delivered[1] == 4);
    assert(known(&last) && last == 4 && settle_none == 0);
    /* An unreadable current status keeps the callback's status known. */
    assert(run(ATHERMAL_STATUS_ERROR, 4, false, 0));
    assert(delivered_count == 1 && known(&last) && last == 4);
}

static void unknown_cases(void)
{
    /* An unreadable status with no callback, and a failed registration, leave nothing known. */
    assert(run(ATHERMAL_STATUS_ERROR, -2, true, 0));
    assert(delivered_count == 0 && !known(NULL) && settle_none == 1);
    assert(!run(3, -2, true, 1));
    assert(delivered_count == 0 && !known(NULL) && settle_none == 1);
}

int main(void)
{
    startup_cases();
    unknown_cases();
    puts("thermal start tests passed");
    return 0;
}
