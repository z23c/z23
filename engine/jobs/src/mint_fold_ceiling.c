/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * mint_fold_ceiling — see jobs/mint_fold_ceiling.h. */

#include "jobs/mint_fold_ceiling.h"

#include <stdatomic.h>

/* Default unbounded: a normal boot never calls _set, so header_admit's
 * `next_h > ceiling` clamp is never true → the fold runs unbounded. */
static _Atomic int32_t g_mint_fold_ceiling = MINT_FOLD_NO_CEILING;

void mint_fold_ceiling_set(int32_t ceiling)
{
    atomic_store_explicit(&g_mint_fold_ceiling, ceiling, memory_order_relaxed);
}

int32_t mint_fold_ceiling_get(void)
{
    return atomic_load_explicit(&g_mint_fold_ceiling, memory_order_relaxed);
}
