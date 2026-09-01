/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * tip_finalize_stage — reducer Job stage.
 *
 * Consumes `utxo_apply_log`; for each height where UTXO apply passed,
 * observes that the live chain has advanced to the next active tip and
 * records the finalize result while publishing the reducer-owned active tip. */

#ifndef ZCL_SERVICES_TIP_FINALIZE_STAGE_H
#define ZCL_SERVICES_TIP_FINALIZE_STAGE_H

#include "util/stage.h"

#include <stdbool.h>
#include <stdint.h>

struct json_value;
struct block_index;
struct main_state;

#define TIP_FINALIZE_BATCH_PER_TICK 100

typedef bool (*tip_finalize_utxo_count_fn)(int height_after,
                                           int64_t *out_count,
                                           void *user);

bool tip_finalize_stage_init(struct main_state *ms);
void tip_finalize_stage_shutdown(void);

/* Force the authoritative tip state (height + hash). Used during
 * trusted bypasses (bootstrap/sync). */
void tip_finalize_stage_set_authoritative_tip(int height,
                                              const uint8_t hash[32]);

/* Read the durably-recorded finalized tip hash at `height` from the
 * tip_finalize_log table on `db` (the progress.kv handle). Returns true
 * and fills `out_hash[32]` iff a finalized (ok=1) row with a 32-byte
 * tip_hash exists at that height. Used by boot_rebuild_from_log to seed
 * the active tip from the durable cursor without re-running the stage.
 * `db` must be the progress store handle (progress_store_db()). */
struct sqlite3;
bool tip_finalize_stage_finalized_tip_at(struct sqlite3 *db, int height,
                                         uint8_t out_hash[32]);

/* CONVENTION-AWARE read of the hash of the block AT `height` as witnessed by
 * tip_finalize_log. The table stores TWO conventions (see
 * finalized_row_active_match in tip_finalize_stage.c):
 *   - a FINALIZED ok=1 row at height X carries the LOOKAHEAD hash(X+1)
 *     (step_finalize binds new_tip = active_chain_at(X+1) into the row at X);
 *   - an ANCHOR seed row at height X carries the block's OWN hash(X).
 * So hash(height) is witnessed by EITHER the finalized row at height-1 OR an
 * anchor row at height. tip_finalize_stage_finalized_tip_at (above) returns
 * the RAW row blob at `height` — hash(height+1) for finalized rows — which is
 * correct only for callers that want "the tip the cursor restored to", never
 * for "the hash of block `height`". Use THIS accessor for the latter.
 * Returns true and fills out_hash iff a witness row (ok=1 + 32-byte hash, in
 * the right convention) exists. `db` is the progress store handle; acquires
 * progress_store_tx_lock() itself (recursive). SELECT-only. */
bool tip_finalize_stage_block_hash_at(struct sqlite3 *db, int height,
                                      uint8_t out_hash[32]);

/* Resolve the durable served-tip (height, own-hash) pair from the persisted
 * tip_finalize cursor, SELF-CONSISTENTLY across both log conventions. The
 * naive `tip = cursor-1` + finalized_tip_at(tip) read pairs cursor-1 with a
 * finalized row's LOOKAHEAD hash — i.e. (H-1, hash(H)), a poisoned
 * authority pair that can be manufactured in the crash window between a
 * finalize advance and the next trusted-tip anchor. This resolver tries the block's OWN hash at `cursor` first (the
 * anchor-at-cursor steady state), then `cursor-1` (the legacy +1 lattice),
 * via the convention-aware block_hash_at — the returned height ALWAYS owns
 * the returned hash. Returns false when no witness row resolves (callers
 * must treat that as "no durable tip", never guess). `db` is the progress
 * store handle. */
bool tip_finalize_stage_resolve_durable_tip(struct sqlite3 *db,
                                            int *out_height,
                                            uint8_t out_hash[32]);

/* Terminal-verb warm (the -install-consensus-bundle boot-order fix). A normal
 * boot publishes the runtime authority pair + provable-tip cache in
 * tip_finalize_stage_init, which runs AFTER the terminal install verb (the
 * engine/composition/src/boot.c verb dispatch predates staged_sync_supervisor_register).
 * The chain-binding evidence gate (chain_frontier_snapshot_collect) reads
 * both caches, so without this warm EVERY install target — copy or live —
 * refuses "selected frontier changed or is not durable" regardless of its
 * durable truth. Warm from the DURABLE store with the exact init primitives
 * and lock discipline; a genuinely torn target still refuses on real durable
 * disagreement (missing log rows / authority mismatch), just for the right
 * reason. No-op when the provable tip is already published. `existing_tip` is
 * only consulted on a datadir with no durable tip history (fresh-seed case);
 * pass active_chain_tip() or NULL. `db` must be the progress store handle. */
void tip_finalize_stage_warm_authority_caches(
    struct sqlite3 *db, const struct block_index *existing_tip,
    const char *reason);

/* Cold-start fast_sync seed: durably record the snapshot anchor at
 * `height` (hash) as an anchor tip in tip_finalize_log and advance the
 * tip_finalize stage cursor to `height` — the served-tip convention
 * (cursor C == served tip at C; task #31), NOT height+1, so the seeded
 * tip's H→H+1 transition is left pending and block H+1 publishes on first
 * arrival. (The UPSTREAM reducer cursors are still seeded to height+1,
 * their own "next height to process" convention.) The next
 * boot_rebuild_from_log restores the tip purely from the log/cursor via
 * tip_finalize_stage_resolve_durable_tip, which tries cursor then cursor-1
 * and therefore tolerates both this convention and the legacy +1 lattice.
 * Also seeds the runtime authoritative tip. Best-effort, non-fatal:
 * returns false (no mutation beyond the log row) if the progress store /
 * stage are not yet wired. `hash` is the 32-byte snapshot anchor block hash.
 *
 * `trusted_seed` is the FIX-3 cap exemption (stage_anchor.h): true ONLY
 * for an externally-verified trusted base (the SHA3-verified snapshot
 * accept). Runtime re-seeds — the per-ingest at-tip re-anchor, regtest
 * stamps — MUST pass false: a fresh datadir is still exempt via the
 * pre-insert-empty-log prong, while a stamp across a rowless span of
 * tip_finalize_log (or any upstream stage's log) is capped at the first
 * hole so the reducer re-finalizes forward instead of manufacturing the
 * log-hole wedge. */
bool tip_finalize_stage_seed_anchor(int height, const uint8_t hash[32],
                                    bool trusted_seed);

job_result_t tip_finalize_stage_step_once(void);
int tip_finalize_stage_drain(int max_steps);

uint64_t tip_finalize_stage_cursor(void);
/* Step-timing EWMA (us); see util/stage.h. 0 if never stepped. */
int64_t  tip_finalize_stage_step_us_ewma(void);
int64_t  tip_finalize_stage_last_height(void);
/* One coherent runtime publication of the reducer's served authority pair.
 * The pair is published only after the tip-finalize durable path accepts it;
 * returns false when no authority has been published in this process. */
bool tip_finalize_stage_authority_snapshot(int64_t *height,
                                           uint8_t hash[32]);
/* Test-only: reset the published served-tip height to -1 (see .c). */
void     tip_finalize_stage_test_reset(void);
uint64_t tip_finalize_stage_finalized_total(void);
uint64_t tip_finalize_stage_upstream_failed_total(void);
uint64_t tip_finalize_stage_reorg_detected_total(void);
uint64_t tip_finalize_stage_utxo_count_diverged_total(void);
uint64_t tip_finalize_stage_precondition_failed_total(void);
/* Count of LOOKAHEAD-not-ready deferrals (H held via JOB_IDLE until its
 * successor H+1 lands) — distinct from precondition_failed_total which now
 * counts only the genuine competing-fork (chainwork_not_greater) skip. */
uint64_t tip_finalize_stage_successor_pending_total(void);
/* Count of HEADER-ONLY canonical-successor finalizes: N finalized on N+1's
 * header witness because N+1's body/scripts were not yet pipelined (deadlock-
 * cure step 3). A subset of finalized_total; the complement of
 * successor_pending_total. */
uint64_t tip_finalize_stage_header_witness_total(void);
uint64_t tip_finalize_stage_total_work_added_low(void);
/* Lock-free snapshot of the last blocked-class token. Returns "" when no
 * block has been observed yet; the pointer is a process-lifetime literal
 * (safe to pass directly to LOG_WARN). For the supervisor stall log. */
const char *tip_finalize_stage_last_blocked_reason(void);

void tip_finalize_stage_set_utxo_counter(tip_finalize_utxo_count_fn fn,
                                         void *user);

/* OS-S2 reorg-clamp hook. Invoked with the fork height (the highest block the
 * pre- and post-reorg chains agree on) after a reorg rewind commits its cursor,
 * so boot-derived cursors can be clamped down. NULL clears it. */
typedef void (*tip_finalize_reorg_clamp_fn)(int fork_height, void *user);
void tip_finalize_stage_set_reorg_clamp(tip_finalize_reorg_clamp_fn fn,
                                        void *user);

bool tip_finalize_dump_state_json(struct json_value *out, const char *key);

#endif /* ZCL_SERVICES_TIP_FINALIZE_STAGE_H */
