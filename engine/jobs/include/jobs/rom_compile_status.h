/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * rom_compile_status — read-only ASCII-progress telemetry for the ROM
 * compilation fold (genesis -> the compiled SHA3 UTXO checkpoint anchor,
 * REDUCER_FRONTIER_TRUSTED_ANCHOR, see jobs/reducer_frontier.h). Backs
 * `z23 dumpstate rom_compile` and the `ops.rom` native leaf.
 *
 * See CLAUDE.md "Adding state introspection". This module composes EXISTING
 * accessors only — the per-stage step-EWMA counters (the eight app/jobs
 * <stage>_stage.h headers), the refold-in-progress signal
 * (jobs/refold_progress.h), the L0 reducer frontier (jobs/reducer_frontier.h),
 * the sealed segment store (controllers/chain_segment_controller.h) and the
 * state-seal ring (services/seal_service.h) — it adds NO new counter and no
 * new source of truth, only a bounded read-only join for one operator-facing
 * view. */

#ifndef ZCL_JOBS_ROM_COMPILE_STATUS_H
#define ZCL_JOBS_ROM_COMPILE_STATUS_H

#include <stdbool.h>

struct json_value;

/* `z23 dumpstate rom_compile` / `ops.rom`: schema zcl.rom_compile.v1.
 * Reports whether a fold (from-genesis or from-anchor refold) is active, its
 * height/target/percent/rate/ETA (rate sampled across successive calls to
 * THIS process — first call in a session reports rate=0/eta unknown), the
 * eight reducer stages' live step_us_ewma (bottleneck-highlighted), and the
 * layer ladder (ROM checkpoint / sealed segment history / sealed state-seal
 * ring / delta frontier / tip ring), and a `shielded_import` section making
 * the shielded_history_import_service.c (-import-complete-shielded) import
 * -> resume transition observable: both activation cursors (anchor
 * sprout/sapling + nullifier), whether the standing
 * utxo_apply.{anchor,nullifier}_backfill_gap blockers are latched, the
 * durable anchor_kv/nullifier_kv row counts a completed import actually
 * wrote, and the reducer's own resume cursor (utxo_apply_next_height).
 * When no fold is active (a normal node at or past the anchor) this still
 * returns a complete, non-error body: fold.active=false, fold.percent
 * clamped to 100, and the layer ladder reflecting steady-state tip status.
 * Read-only; never mutates progress.kv. `key` is unused. */
bool rom_compile_status_dump_state_json(struct json_value *out,
                                        const char *key);

#ifdef ZCL_TESTING
/* Test-only: reset the cross-call rate-sample statics so a test controls the
 * first-sample / second-sample transition deterministically. */
void rom_compile_status_test_reset_rate_sample(void);
#endif

#endif /* ZCL_JOBS_ROM_COMPILE_STATUS_H */
