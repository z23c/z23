/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Lane A1 — the created_outputs retention prune, DECOUPLED from the utxo_apply
 * kernel co-commit. utxo_apply_stage_drain() calls
 * utxo_apply_created_outputs_prune_post_commit() AFTER the kernel batch has
 * committed and the kernel tx lock has been released. Wave A2 (D4): the prune
 * now runs on the projection_store handle + projection tx lock (its OWN
 * connection to the same progress.kv file), so it never re-contends the reducer
 * drive's kernel tx lock. See the .c for the crash argument. The two
 * test-observability entry points (utxo_apply_post_prune_stats,
 * utxo_apply_created_outputs_retain_set_for_test) are declared in
 * jobs/utxo_apply_stage.h. */

#ifndef ZCL_JOBS_UTXO_APPLY_CREATED_OUTPUTS_PRUNE_H
#define ZCL_JOBS_UTXO_APPLY_CREATED_OUTPUTS_PRUNE_H

/* Best-effort post-commit retention prune of the created_outputs projection.
 * No-op when the projection store is not open. Acquires
 * projection_store_tx_lock() for a strictly-sequential (never nested wrt the
 * kernel lock) transaction on the projection handle. */
void utxo_apply_created_outputs_prune_post_commit(void);

#endif /* ZCL_JOBS_UTXO_APPLY_CREATED_OUTPUTS_PRUNE_H */
