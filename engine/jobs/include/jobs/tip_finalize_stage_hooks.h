/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Internal accessors for the tip_finalize_stage DI hooks. The public setters
 * (tip_finalize_stage_set_utxo_counter / _set_reorg_clamp) are declared in
 * jobs/tip_finalize_stage.h; these accessors are how the stage TU invokes the
 * bound hooks. See tip_finalize_stage_hooks.c. */

#ifndef ZCL_JOBS_TIP_FINALIZE_STAGE_HOOKS_H
#define ZCL_JOBS_TIP_FINALIZE_STAGE_HOOKS_H

#include <stdbool.h>
#include <stdint.h>

/* Live UTXO count after `height_after` via the bound counter, or *out_count=-1
 * and true when no counter is bound (audit is skipped, not failed). */
bool tip_finalize_hooks_count_utxos(int height_after, int64_t *out_count);

/* Clamp boot-derived cursors to `fork_height` via the bound clamp (no-op when
 * unbound). Called on a reorg rewind so a restart re-derives above the fork. */
void tip_finalize_hooks_reorg_clamp(int fork_height);

/* Clear all bound hooks (stage teardown). */
void tip_finalize_hooks_reset(void);

#endif /* ZCL_JOBS_TIP_FINALIZE_STAGE_HOOKS_H */
