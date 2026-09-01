/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * OP_RETURN catalog backfill — the supervised bounded background half of
 * the op_return_index projection (engine/models/src/op_return_index.c).
 *
 * The live tip-finalize hook (explorer_index_block in
 * contexts/explorer/models/src/explorer_index.c) inserts a catalog row for every
 * OP_RETURN output as new blocks land — "populate at tip-finalize for new
 * blocks". THIS service is the ONLY writer of the catalog's cursor +
 * running digest (op_return_index_get_cursor/set_cursor): it walks the
 * HISTORICAL range strictly below its cursor, up to the reducer's
 * provable tip H* (reducer_frontier_provable_tip_cached — "already-
 * persisted verified bodies"), a BOUNDED number of blocks
 * (OP_RETURN_BACKFILL_BATCH_BLOCKS) per supervisor tick. It reads bodies
 * through the ordinary disk path (active_chain_at +
 * read_block_from_disk_index_pread — the same thread-safe primitives
 * segment_sealer_service uses), never through reducer internals, so it
 * never takes csr->lock and honors the reducer-drive lock-order law.
 *
 * Row inserts (INSERT OR IGNORE, PK=(txid,vout_n)) are idempotent and
 * safe to run from ANY thread, so the live hook and this service can
 * write the SAME row without coordination. The digest CHAIN is not
 * idempotent under double-folding, so only this one supervisor-driven
 * thread ever advances cursor/digest — that keeps two independently-
 * indexing nodes convergent without a cross-thread lock.
 *
 * No dedicated pthread: registers a liveness_contract with
 * period_secs > 0, so the ROOT supervisor's own thread drives on_tick
 * (the same shape as authority_projection_audit / invariant_sentinel's
 * sweeps) — no new thread to supervise, no new failure mode.
 *
 * API
 * ---
 *   op_return_backfill_set_datadir(datadir)  — boot wiring (process-lifetime
 *                                               string, like
 *                                               recovery_coordinator_set_datadir)
 *   op_return_backfill_register()            — arm the supervisor child
 *   op_return_backfill_run_once()            — one bounded batch (tests + on_tick)
 *   op_return_index_dump_state_json — `z23 dumpstate op_return_index`
 */

#ifndef ZCL_SERVICES_OP_RETURN_BACKFILL_SERVICE_H
#define ZCL_SERVICES_OP_RETURN_BACKFILL_SERVICE_H

#include <stdbool.h>
#include <stdint.h>

#define OP_RETURN_BACKFILL_PERIOD_SECS   2
#define OP_RETURN_BACKFILL_BATCH_BLOCKS  500
/* Defensive ceiling on OP_RETURN outputs folded into one block's digest
 * step (real chain blocks carry far fewer — dozens at most). A block that
 * exceeds this is still fully row-indexed by op_return_index_apply_block_
 * rows; only the digest fold (and therefore the cursor advance) for that
 * height is skipped, loudly, so the cursor never advances past unverified
 * digest state. */
#define OP_RETURN_BACKFILL_MAX_ROWS_PER_BLOCK 65536

void op_return_backfill_set_datadir(const char *datadir);
void op_return_backfill_register(void);

/* One bounded batch, synchronous. Returns the number of blocks whose
 * digest was folded this call (0 = nothing to do / not wired yet, both
 * benign). */
int op_return_backfill_run_once(void);

void op_return_backfill_reset_for_test(void);

struct json_value;
bool op_return_index_dump_state_json(struct json_value *out, const char *key);
/* `z23 dumpstate zepoch` — epoch-anchor status snapshot (catalog
 * cursor + digest, current epoch, anchored bool). */
bool zepoch_status_dump_state_json(struct json_value *out, const char *key);

#ifdef ZCL_TESTING
struct node_db;
struct main_state;
/* Test-only context override — production wiring is app_runtime_node_db()
 * / app_runtime_main_state() + op_return_backfill_set_datadir(). */
extern struct node_db *g_op_return_backfill_test_ndb;
extern struct main_state *g_op_return_backfill_test_ms;
extern const char *g_op_return_backfill_test_datadir;
/* Inject a snapshot-seed floor without a live progress_store, so the
 * declared-partial-coverage adoption path is testable. -1 = ask the kernel
 * authority (index_fold_snapshot_seed_floor), which is the production path. */
extern _Atomic int64_t g_op_return_backfill_test_seed_floor;
#endif

#endif /* ZCL_SERVICES_OP_RETURN_BACKFILL_SERVICE_H */
