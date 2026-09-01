/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * reducer_drive_guard — see util/reducer_drive_guard.h. */

#include "util/reducer_drive_guard.h"
#include "core/utiltime.h"
#include <stdatomic.h>

/* Number of synchronous reducer drives currently in progress (normally 0 or 1;
 * a counter rather than a bool so a future nested drive cannot clear the flag
 * early). */
static _Atomic int g_reducer_drive_depth = 0;

/* Monotonic entry time of the OUTERMOST drive (0 when inactive) and a static
 * label naming who is driving. Both are observational only — the watchdog and
 * dumpstate read them; nothing branches on them inside the drive itself. The
 * label must point at a string literal (never freed, async-safe to read). */
static _Atomic int64_t g_reducer_drive_start_us = 0;
static const char *_Atomic g_reducer_drive_label = 0;

void reducer_drive_enter(void)
{
    reducer_drive_enter_labeled("unlabeled");
}

void reducer_drive_enter_labeled(const char *label)
{
    int prev = atomic_fetch_add_explicit(&g_reducer_drive_depth, 1,
                                         memory_order_acq_rel);
    if (prev == 0) {
        atomic_store_explicit(&g_reducer_drive_label,
                              label ? label : "unlabeled",
                              memory_order_release);
        atomic_store_explicit(&g_reducer_drive_start_us, GetTimeMicros(),
                              memory_order_release);
    }
}

void reducer_drive_exit(void)
{
    int prev = atomic_fetch_sub_explicit(&g_reducer_drive_depth, 1,
                                         memory_order_acq_rel);
    if (prev == 1) {
        atomic_store_explicit(&g_reducer_drive_start_us, 0,
                              memory_order_release);
        atomic_store_explicit(&g_reducer_drive_label, (const char *)0,
                              memory_order_release);
    }
}

bool reducer_drive_active(void)
{
    return atomic_load_explicit(&g_reducer_drive_depth, memory_order_acquire) > 0;
}

int64_t reducer_drive_age_us(void)
{
    int64_t start = atomic_load_explicit(&g_reducer_drive_start_us,
                                         memory_order_acquire);
    if (start == 0)
        return 0;
    int64_t age = GetTimeMicros() - start;
    return age > 0 ? age : 0;
}

const char *reducer_drive_label(void)
{
    const char *label = atomic_load_explicit(&g_reducer_drive_label,
                                             memory_order_acquire);
    return label ? label : "";
}
