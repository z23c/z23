/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * utxo_apply_nullifiers — the reducer's port of zclassicd's shielded
 * double-spend gate (C-3), split out of utxo_apply_stage.c along the same
 * seam as utxo_apply_delta*.c (lint gate E1 file-size ceiling).
 *
 * Not a public API — only utxo_apply_stage.c includes this (same contract
 * as jobs/utxo_apply_delta.h). The durable set itself is the `nullifiers`
 * table in progress.kv (storage/nullifier_kv.h); this module owns the
 * per-block two-pass check-then-insert and the activation-gap blocker. */

#ifndef ZCL_JOBS_UTXO_APPLY_NULLIFIERS_H
#define ZCL_JOBS_UTXO_APPLY_NULLIFIERS_H

#include <stdbool.h>
#include <stdint.h>

struct sqlite3;
struct block;
struct delta_summary;

/* The PERMANENT blocker naming the C-3 activation gap (see the refresh
 * contract below). Shared with utxo_apply_stage_shutdown's clear. */
#define UTXO_APPLY_NF_GAP_BLOCKER_ID "utxo_apply.nullifier_backfill_gap"

/* Check every Sprout/Sapling nullifier of `blk` against the durable set +
 * the earlier-tx accumulator (zclassicd's per-tx check-then-set order,
 * main.cpp:2627 HaveShieldedRequirements), then insert all of them at
 * `height` iff the whole block is clean (two-pass — a rejected block never
 * leaves partial rows). Returns false on a STORE error (caller goes
 * JOB_FATAL — fail closed); a consensus hit flips summary->ok with status
 * "shielded_double_spend" and returns true so the regular failure path
 * (counter, log row, JOB_BLOCKED) runs. MUST run inside the stage txn so
 * pass-2 inserts commit atomically with coins + cursor + log row. */
bool utxo_apply_check_and_insert_nullifiers(struct sqlite3 *db,
                                            const struct block *blk,
                                            int height,
                                            struct delta_summary *summary);

enum utxo_apply_shielded_gate_result {
    UTXO_SHIELDED_GATE_ERROR = -1,
    UTXO_SHIELDED_GATE_CONTINUE = 0,
    UTXO_SHIELDED_GATE_HOLD = 1,
};

/* Live-reducer combined shielded-history + anchor gate. Deliberately separate
 * from the raw nullifier writer: owner-gated backfill calls that writer while
 * the activation marker is positive. Transparent-only blocks continue; an
 * incomplete prefix is parked behind its PERMANENT causal blocker with no
 * peer-invalid verdict or transient blocker; malformed/store evidence errors.
 * Anchor mutations, when any, remain in the caller's stage transaction. */
enum utxo_apply_shielded_gate_result utxo_apply_shielded_history_gate(
    struct sqlite3 *db, const struct block *blk, int height,
    struct delta_summary *summary);

/* Initialize anchor/nullifier completeness from one result-bearing reducer
 * cursor read. Missing cursor means complete genesis only when coins authority
 * is positively virgin; store/read ambiguity fails closed. */
bool utxo_apply_shielded_history_initialize(struct sqlite3 *db);

/* C-3 ACTIVATION GAP, owner-visible (see storage/nullifier_kv.h): reads
 * the `nullifier_kv.activation_cursor` marker; if > 0 the durable set is
 * MISSING every nullifier revealed at/below that height. The live reducer
 * preflight above now holds every shielded spend until backfill completes,
 * so this registers/refreshes the matching PERMANENT
 * blocker UTXO_APPLY_NF_GAP_BLOCKER_ID; only an explicit 0 marker clears it
 * (from-genesis replays and completed backfills write zero). Called from stage init
 * every boot. Best-effort: store errors are logged, never fatal. */
void utxo_apply_nullifier_gap_blocker_refresh(struct sqlite3 *db);

/* Lock-free runtime snapshot of the activation-gap marker last read by the
 * refresh above. Returns false until the boot-time refresh has completed;
 * diagnostics use that as explicit unknown evidence instead of blocking on an
 * active reducer transaction. */
bool utxo_apply_nullifier_gap_snapshot(int64_t *activation_cursor,
                                       bool *backfill_gap);

#endif /* ZCL_JOBS_UTXO_APPLY_NULLIFIERS_H */
