/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * chain_tip — canonical owner of "set the active chain tip" semantics.
 *
 * Before this module, ~30 call sites across snapshot_sync_service,
 * chain_restore_service, process_block, msg_headers, utxo_recovery,
 * and boot.c invoked the low-level active-chain window primitive directly.
 * Each site decided independently whether to:
 *   - emit EV_TIP_UPDATED / EV_CHAIN_TIP_COMMIT events
 *   - call csr_apply_commit for SQLite persistence
 *   - update pindex_best_header
 *   - log a "[tip]" line for observability
 *
 * The result: events fire from some paths but not others, the log is
 * inconsistent, and adding a new invariant (e.g. an integrity assert)
 * means editing 30 sites — a recipe for drift.
 *
 * This module exposes a single function that all of those sites
 * SHOULD call. The bare `active_chain_move_window_tip` is a low-level
 * cache/window primitive used by this module itself; it does not publish the
 * authoritative reducer tip. New callers must use `chain_set_active_tip`. */

#ifndef ZCL_CHAIN_TIP_H
#define ZCL_CHAIN_TIP_H

#include <stdbool.h>

#include "util/result.h"

struct main_state;
struct block_index;

/* Where the tip change originated. Used in the structured `[tip]`
 * log line so operators can see at a glance which subsystem moved
 * the chain. */
enum tip_source {
    TIP_FROM_UNSPECIFIED  = 0,
    TIP_FROM_CONNECT,      /* reducer forward connect */
    TIP_FROM_DISCONNECT,   /* reducer reorg rollback */
    TIP_FROM_SNAPSHOT,     /* FlyClient+SHA3 snapshot installation */
    TIP_FROM_RESTORE,      /* boot-time chain-restore */
    TIP_FROM_BOOT_REPAIR,  /* boot.c misc fixups */
    TIP_FROM_P2P_REPAIR,   /* msg_headers post-activation repair */
    TIP_FROM_UTXO_REPAIR,  /* utxo_recovery_service */
    TIP_FROM_TEST,         /* unit/integration tests */
};

const char *tip_source_name(enum tip_source src);

/* Set the active chain tip. Wraps the low-level `active_chain_move_window_tip`
 * and adds:
 *   - reducer authority publication for trusted bootstrap/repair writes
 *   - structured `[tip] h=H hash=hex16... src=... reason=...` log line
 *   - EV_TIP_UPDATED event with hash + height payload
 *   - EV_CHAIN_TIP_COMMIT event with from/to/reason payload
 *
 * Returns ZCL_OK on success, or a zcl_result carrying code+message
 * if `active_chain_move_window_tip` returns false (typically realloc OOM at
 * very high heights) or `ms` is NULL.
 *
 * `new_tip` may be NULL to clear the tip (returns ZCL_OK; emits a
 * "[tip] CLEARED" log line). `reason` may be NULL.
 *
 * Does NOT take any locks — the caller is responsible for serializing
 * with other chain mutations (typically `ms->cs_main` or the
 * activation_controller mutex). */
struct zcl_result chain_set_active_tip(struct main_state *ms,
                                       struct block_index *new_tip,
                                       enum tip_source src,
                                       const char *reason);

#endif /* ZCL_CHAIN_TIP_H */
