/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * address_index_service — the supervised, bounded backfill that folds the
 * address_index projection (jobs/address_index.h) forward from its cursor to
 * the finalized tip_finalize frontier (H*).
 *
 * Shape: a chain-domain supervisor child (util/supervisor.h) driven by the
 * supervisor's own thread via on_tick. Each tick folds a STRICTLY BOUNDED
 * batch — at most ADDRESS_INDEX_BATCH_BLOCKS heights AND a wall-time budget,
 * never O(chain) — under a NON-BLOCKING progress-store trylock, so it can never
 * stall the reducer drive or freeze the supervisor tree. It advances only over
 * verified persisted bodies at or below H*; a missing body names a typed
 * coverage blocker rather than a silent stop. Restartable at its cursor.
 *
 * Opt-in: registered ONLY when -addressindex is set. A default boot registers
 * no child and pays zero cost (the dumper reports enabled=false without DB). */
#ifndef ZCL_SERVICES_ADDRESS_INDEX_SERVICE_H
#define ZCL_SERVICES_ADDRESS_INDEX_SERVICE_H

#include <stdbool.h>

struct json_value;

/* Register the chain-domain backfill child. No-op (and returns false) when
 * -addressindex is disabled. Idempotent — a second call is a no-op. Called
 * from the boot composition root after the diagnostics main_state/datadir are
 * wired. */
bool address_index_service_register(void);

/* True once the child is registered (i.e. -addressindex was on at register). */
bool address_index_service_registered(void);

/* Run exactly one bounded fold batch synchronously. The on_tick wrapper calls
 * this; tests call it directly. Returns the number of blocks folded this call
 * (0 when caught up, disabled, unwired, or the store was busy). */
int address_index_service_tick_once(void);

/* dumpstate `address_index` (CLAUDE.md "Adding state introspection").
 * key == NULL/empty  -> projection status (enabled, cursor, H*, gap, rows,
 *                        digest, counters, coverage blocker).
 * key == "<64-hex scripthash>[:<from_height>]" -> up to a bounded page of
 *                        appearances + confirmed balance for that script. */
bool address_index_dump_state_json(struct json_value *out, const char *key);

/* Bounded per-tick work. */
#define ADDRESS_INDEX_BATCH_BLOCKS   128
#define ADDRESS_INDEX_BATCH_US       15000   /* 15 ms wall budget per tick */
#define ADDRESS_INDEX_TICK_SECONDS   2

#endif /* ZCL_SERVICES_ADDRESS_INDEX_SERVICE_H */
