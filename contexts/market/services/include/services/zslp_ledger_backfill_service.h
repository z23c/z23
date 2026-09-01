/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ZSLP ledger backfill — the supervised bounded background half of the
 * zslp_ledger projection (contexts/market/models/src/zslp_ledger.c).
 *
 * The live tip hook (zslp_ledger_apply_slp_live, called from
 * explorer_index.c's index_op_return) creates/spends ledger rows as new
 * blocks land. THIS service is the ONLY writer of the ledger's cursor +
 * running digest (zslp_ledger_get_cursor/set_cursor): it walks the
 * HISTORICAL range strictly above its cursor, up to the reducer's provable
 * tip H* (reducer_frontier_provable_tip_cached), a BOUNDED number of heights
 * per supervisor tick, re-deriving each height purely from already-persisted
 * node.db projections (zslp_transfers / tx_outputs / tx_inputs) — no block
 * bodies, no disk, no main_state, so it never takes csr->lock and honors the
 * reducer-drive lock-order law.
 *
 * Row writes are idempotent, so the live hook and this service can touch the
 * same rows without coordination. The digest CHAIN is not idempotent under
 * double-folding, so only this one supervisor-driven thread advances
 * cursor/digest, keeping two independently-indexing nodes convergent.
 *
 * No dedicated pthread: registers a liveness_contract with period_secs > 0,
 * so the ROOT supervisor's thread drives on_tick (same shape as the
 * op_return backfill / invariant_sentinel sweeps). */

#ifndef ZCL_SERVICES_ZSLP_LEDGER_BACKFILL_SERVICE_H
#define ZCL_SERVICES_ZSLP_LEDGER_BACKFILL_SERVICE_H

#include <stdbool.h>
#include <stdint.h>

#define ZSLP_LEDGER_BACKFILL_PERIOD_SECS  2
#define ZSLP_LEDGER_BACKFILL_BATCH_BLOCKS 500

void zslp_ledger_backfill_register(void);

/* One bounded batch, synchronous. Returns the number of heights whose digest
 * was folded this call (0 = nothing to do / not wired yet, both benign). */
int zslp_ledger_backfill_run_once(void);

void zslp_ledger_backfill_reset_for_test(void);

struct json_value;
bool zslp_ledger_dump_state_json(struct json_value *out, const char *key);

#ifdef ZCL_TESTING
struct node_db;
/* Test-only context override — production wiring is app_runtime_node_db(). */
extern struct node_db *g_zslp_ledger_backfill_test_ndb;
#endif

#endif /* ZCL_SERVICES_ZSLP_LEDGER_BACKFILL_SERVICE_H */
