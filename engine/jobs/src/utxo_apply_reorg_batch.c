/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * One inverse-delta reorg audit per locked reducer transaction. */

#include "jobs/utxo_apply_stage.h"
#include "utxo_apply_stage_internal.h"
#include "util/stage.h"

#include <stdatomic.h>
#include <stdint.h>

static uint64_t g_audited_generation;
static _Atomic uint64_t g_audit_total;

bool utxo_apply_reorg_batch_should_audit(void)
{
    bool batched = stage_batch_active();
    uint64_t generation = batched ? stage_batch_generation() : 0;
    if (batched && generation == g_audited_generation)
        return false;
    atomic_fetch_add(&g_audit_total, 1u);
    if (batched)
        g_audited_generation = generation;
    return true;
}

void utxo_apply_reorg_batch_reset(void)
{
    g_audited_generation = 0;
    atomic_store(&g_audit_total, 0u);
}

uint64_t utxo_apply_stage_reorg_audit_total(void)
{
    return atomic_load(&g_audit_total);
}
