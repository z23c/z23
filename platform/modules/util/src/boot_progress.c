/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Implementation of util/boot_progress.h — see header for rationale.
 *
 * Two atomics, no locks, no allocation. The label is stashed as an
 * atomic pointer; callers must pass string literals (or otherwise
 * process-lifetime strings) per the header contract.
 */

#include "platform/time_compat.h"
#include "util/boot_progress.h"

#include <stdatomic.h>
#include <stddef.h>
#include <time.h>

static _Atomic int64_t g_last_us = 0;
static _Atomic(const char *) g_last_label = NULL;

void boot_progress_tick(const char *label)
{
    atomic_store_explicit(&g_last_us, platform_time_monotonic_us(),
                          memory_order_relaxed);
    if (label)
        atomic_store_explicit(&g_last_label, label,
                              memory_order_relaxed);
}

int64_t boot_progress_last_us(void)
{
    return atomic_load_explicit(&g_last_us, memory_order_relaxed);
}

const char *boot_progress_last_label(void)
{
    return atomic_load_explicit(&g_last_label, memory_order_relaxed);
}
