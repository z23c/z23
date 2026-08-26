/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * RESIDENT half of the hot-swappable package-policy projection — see
 * controllers/policy_native_resident.h for why this file exists separately
 * from app/controllers/src/policy_native_handlers.c.
 *
 * The mutable file-scope statics below are exactly what a hot-swap .so must
 * never recompile. Keeping them here (a TU no manifest lists) is what lets
 * the leaf half stay swappable while the process state stays singular.
 */

#include "controllers/policy_native_resident.h"

#include <stdatomic.h>

/* The resident process state. NEVER move these into the swappable sibling:
 * a generation .so gets its own zero-initialized copy and the live counters
 * silently reset with no crash and no error. */
static atomic_bool g_policy_resident_booted;
static atomic_ullong g_policy_resident_dispatches;

void zcl_native_policy_resident_mark_boot(void)
{
    atomic_store_explicit(&g_policy_resident_booted, true,
                          memory_order_release);
}

bool zcl_native_policy_resident_booted(void)
{
    return atomic_load_explicit(&g_policy_resident_booted,
                                memory_order_acquire);
}

uint64_t zcl_native_policy_resident_note_dispatch(void)
{
    unsigned long long prev = atomic_fetch_add_explicit(
        &g_policy_resident_dispatches, 1ull, memory_order_acq_rel);
    return (uint64_t)prev + 1u;
}

uint64_t zcl_native_policy_resident_dispatches(void)
{
    return (uint64_t)atomic_load_explicit(&g_policy_resident_dispatches,
                                          memory_order_acquire);
}
