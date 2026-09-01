/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * mint_fold_ceiling — the ANCHOR-SET MINT fold bound.
 *
 * The `-mint-anchor` boot mode (engine/entry/main.c) resets the staged reducer to
 * genesis and folds the on-disk block BODIES forward through the REAL
 * script_validate / proof_validate / utxo_apply / tip_finalize stages, but
 * must STOP exactly at the SHA3 UTXO checkpoint anchor (h=3,056,758) so the
 * resulting coins_kv set is the anchor set — not the contaminated tip.
 *
 * MECHANISM — a process-global atomic ceiling. header_admit_stage's step body
 * (the upstream-most stage; every downstream stage gates on its cursor) refuses
 * to admit a header above the ceiling (returns JOB_IDLE), so the whole eight-
 * stage pipeline converges AT the ceiling and goes idle there.
 *
 * NORMAL-BOOT INVARIANT: the ceiling defaults to MINT_FOLD_NO_CEILING
 * (INT32_MAX). header_admit's clamp is `next_h > ceiling` — with the default
 * ceiling that comparison is never true for any real height, so a normal boot
 * leaves the ceiling unset (no flag → never set → unbounded fold) and applies
 * no clamp. Only the `-mint-anchor` driver calls mint_fold_ceiling_set(anchor).
 *
 * This module changes NO validation rule — it only bounds HOW FAR the fold
 * walks, never what a header/block/tx must satisfy.
 */

#ifndef ZCL_JOBS_MINT_FOLD_CEILING_H
#define ZCL_JOBS_MINT_FOLD_CEILING_H

#include <stdint.h>

/* Unbounded sentinel — the default. No real height ever exceeds it, so the
 * header_admit clamp `next_h > ceiling` never fires on a normal boot. */
#define MINT_FOLD_NO_CEILING INT32_MAX

/* Set the highest height header_admit may admit (inclusive). The `-mint-anchor`
 * driver sets this to the compiled checkpoint anchor so the fold stops there.
 * Reset to MINT_FOLD_NO_CEILING to lift the bound. */
void mint_fold_ceiling_set(int32_t ceiling);

/* Read the current ceiling. Cheap atomic read — safe from any stage thread.
 * Returns MINT_FOLD_NO_CEILING when no bound is set (the default). */
int32_t mint_fold_ceiling_get(void);

#endif /* ZCL_JOBS_MINT_FOLD_CEILING_H */
