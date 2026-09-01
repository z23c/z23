/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * seal_service — the host for the state-seal candidate emitter and ratifier.
 *
 * The candidate emitter runs INSIDE the utxo_apply step_apply progress.kv txn
 * when coins_applied_height crosses a 1000-block grid point in steady-state
 * tip-following (never during IBD/bulk replay): it scans coins_kv for the
 * commitment + setinfo, captures the active-chain hash at G, and inserts a
 * ratified=0 candidate seal co-committed with the coin mutation. Best-effort —
 * a seal failure must never fail the block.
 *
 * The ratifier runs every 60s from the rolling_anchor supervisor tick. It
 * promotes the newest candidate to ratified once (a) the tip has buried G by
 * the finality depth, (b) the input block-bytes prefix covers G, and (c) the
 * active chain still holds the block this seal was computed against. Failing to
 * ratify is normal (the candidate waits); it never pages.
 *
 * See CLAUDE.md "Adding state introspection" — seal_dump_state_json follows
 * that convention (delegates to seal_kv_dump_state_json). Reentrant-safe. */

#ifndef ZCL_SERVICES_SEAL_SERVICE_H
#define ZCL_SERVICES_SEAL_SERVICE_H

#include <stdbool.h>
#include <stdint.h>

struct sqlite3;
struct main_state;
struct json_value;

/* Idempotent: ensure the seal ring schema exists (progress_meta table). Call
 * once at boot after progress_store is open. Returns false if the store is
 * not open. */
bool seal_service_init(struct sqlite3 *db);

/* The utxo_apply step_apply hook: gate (next_cursor is a 1000-grid point AND
 * not IBD) + best-effort candidate emit, INSIDE the caller's already-open
 * progress.kv txn. The IBD gate is LOAD-BEARING — it keeps the ~1s O(n) coins
 * SHA3 scan off the cold-sync path (where it would turn ~25 min into hours) and
 * fires only once caught up. A no-op when next_cursor is not a grid point or
 * during IBD. The seal failure path NEVER fails the block (return is void). */
void seal_candidate_hook_in_tx(struct sqlite3 *db, struct main_state *ms,
                               int32_t next_cursor);

/* Candidate: scan coins_kv at applied frontier G, build a seal_record (block
 * hash captured from `ms`'s active chain at G), insert ratified=0. Runs INSIDE
 * the caller's already-open progress.kv txn (utxo_apply step_apply's BEGIN
 * IMMEDIATE) so the candidate co-commits with the coin mutation + cursor.
 * Best-effort: returns false (LOG_WARN) on any sub-step failure but the caller
 * MUST NOT fail the block on a false return — the seal is observe-only.
 * Exposed for direct unit testing (bypasses the grid/IBD gate). */
bool seal_candidate_emit_in_tx(struct sqlite3 *db, struct main_state *ms,
                               int32_t G);

/* Ratify pass: examine the newest un-ratified candidate; if it qualifies, mark
 * it ratified in its OWN BEGIN IMMEDIATE. Returns the number ratified (0 or 1).
 * Called from rolling_anchor on_tick. Reentrant-safe; idempotent (a ratified
 * seal stays ratified). */
int seal_ratify_tick(struct main_state *ms);

/* `z23 dumpstate seal` delegates to seal_kv_dump_state_json. */
bool seal_dump_state_json(struct json_value *out, const char *key);

#endif /* ZCL_SERVICES_SEAL_SERVICE_H */
