/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * state_auditor — continuous SAMPLED background integrity scrubber.
 *
 * Complements (does NOT replace) the existing hourly FULL-set audits
 * (invariant_sentinel's coins.commitment_audit, authority_projection_audit)
 * by re-verifying a small, bounded, RANDOM slice of already-stored integrity
 * commitments every few seconds, so a silently corrupted row is named within
 * seconds instead of waiting for the next hourly pass or an operator-run
 * `install-verify`. Two independent legs, both bounded per tick:
 *
 *   op_return_index leg — re-extracts OP_RETURN rows straight from the
 *     on-disk block body for a random contiguous height WINDOW already
 *     below the catalog's own folded cursor, folds them with the catalog's
 *     shipped chained digest primitive (op_return_index_fold_block_digest,
 *     re-seeded to a window-local zero IV — NOT the genesis-anchored
 *     production chain, so no O(chain) replay), and compares against the
 *     SAME fold over the rows actually stored in `op_return_index` for
 *     those heights. Both block bodies and already-folded catalog rows are
 *     immutable once written, so this has zero legitimate drift and zero
 *     false positives on a clean, advancing chain.
 *
 *   coins_commitment leg — the XOR-hash accumulator (coins/utxo_commitment.h)
 *     recomputed independently over a bounded (txid,vout) PRIMARY-KEY
 *     keyspace WINDOW (utxo_commitment_compute_range) from BOTH the coins_kv
 *     authority (`coins` in progress.kv) and the utxos projection (`utxos`
 *     in node.db), at the SAME instant (torn-scan guarded by re-reading both
 *     applied-height markers before/after, discarding on any move — the
 *     same discipline authority_projection_audit uses for its full-table
 *     version). Comparing two LIVE reads of the identical predicate at one
 *     instant — never a frozen historical checkpoint — means normal
 *     spending of UTXOs elsewhere in the set never produces a false
 *     mismatch. A window is chosen by (txid,vout) key, not height, because
 *     `coins` carries no height index and this module deliberately never
 *     adds one to that hot reducer-write table (see utxo_commitment.h).
 *
 * Throttling: bounded work per tick (a small fixed window on each leg),
 * idle cadence (STATE_AUDITOR_PERIOD_SECS), and never contends with the
 * reducer — coins_ram_active() (bulk-fold mode) skips the coins leg for the
 * whole tick, and every progress.kv marker read uses
 * progress_store_tx_trylock (skip the tick, never block, on contention).
 *
 * Confirmation: a mismatch is not raised on a single sample — the SAME
 * candidate window is re-checked on the immediately following tick(s);
 * only STATE_AUDITOR_CONFIRM_STREAK consecutive mismatches on that pinned
 * window latch it. Once latched, the auditor keeps RE-CHECKING that exact
 * pinned window (not a fresh random one) every tick, so the latch clears
 * only on real external repair (a truncate + backfill re-derive, or a
 * checkpoint resync) — not by coincidentally sampling elsewhere next time.
 *
 * A latched leg is surfaced to the condition engine via
 * state_auditor_get_mismatch(); see conditions/state_auditor_mismatch.h for
 * the typed-blocker remedy that rearms forever on top of it (mirrors
 * catalog_lag_exceeded / peer_floor_violated).
 */

#ifndef ZCL_SERVICES_STATE_AUDITOR_H
#define ZCL_SERVICES_STATE_AUDITOR_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

/* Idle cadence: fast enough to catch corruption "in seconds", cheap enough
 * (two small bounded windows) to never approach the reducer's hot path. */
#define STATE_AUDITOR_PERIOD_SECS        5

/* Heights re-verified per op_return_index tick. Real chain blocks carry at
 * most dozens of OP_RETURN outputs, so a 32-block window is bounded well
 * under a millisecond of extra disk-body reads. */
#define STATE_AUDITOR_OPRET_WINDOW_BLOCKS 32

/* Rows re-verified per coins_commitment tick (keyspace-window LIMIT). */
#define STATE_AUDITOR_COINS_WINDOW_ROWS   2048

/* Consecutive mismatched samples of the SAME pinned window required before
 * latching — swallows a torn-scan race exactly like the sibling full-table
 * audits' streak guards. */
#define STATE_AUDITOR_CONFIRM_STREAK      2

enum state_auditor_leg {
    STATE_AUDITOR_LEG_OP_RETURN_INDEX = 0,
    STATE_AUDITOR_LEG_COINS_COMMITMENT = 1,
    STATE_AUDITOR_LEG_COUNT,
};

/* Stable index names, used both in log/blocker text and as the dynamic
 * segment of the `state_auditor.<index>.mismatch` blocker id. */
const char *state_auditor_leg_name(enum state_auditor_leg leg);

struct state_auditor_mismatch_info {
    bool     latched;        /* CONFIRM_STREAK consecutive mismatches seen */
    int32_t  h_start;        /* inclusive height span the pinned window covers */
    int32_t  h_end;
    char     detail[192];    /* human-readable specifics (rows/digests/etc) */
};

/* Snapshot the current latch state for one leg. Pure read of atomics/a short
 * mutex hold — safe to call from the condition engine's own thread. Returns
 * false (out zeroed) for an out-of-range leg. */
bool state_auditor_get_mismatch(enum state_auditor_leg leg,
                                struct state_auditor_mismatch_info *out);

/* One bounded tick: runs both legs' window check (or investigates/re-checks
 * a pinned candidate/latched window) and updates their latch state. Never
 * blocks on the reducer (trylock-and-skip); safe to call at any boot stage
 * (returns immediately, benign, when the required handles are not wired
 * yet). Exposed for the supervisor on_tick and direct test drive. */
void state_auditor_tick_once(void);

/* Boot wiring: process-lifetime datadir string (read-only block body access,
 * same convention as op_return_backfill_set_datadir/recovery_coordinator_
 * set_datadir). Must be called before state_auditor_register(). */
void state_auditor_set_datadir(const char *datadir);

/* Register the supervisor child (chain domain, STATE_AUDITOR_PERIOD_SECS
 * cadence). Idempotent. */
void state_auditor_register(void);

/* `z23 dumpstate state_auditor`. See CLAUDE.md "Adding state
 * introspection". Reentrant-safe. */
struct json_value;
bool state_auditor_dump_state_json(struct json_value *out, const char *key);

#ifdef ZCL_TESTING
struct node_db;
struct main_state;
struct sqlite3;

/* Test-injected handles/state, mirroring authority_projection_audit's
 * g_ap_test_ndb / op_return_backfill's g_op_return_backfill_test_* globals.
 * NULL (the default) falls back to the live runtime singletons. */
extern struct node_db   *g_state_auditor_test_ndb;
extern struct main_state *g_state_auditor_test_ms;
extern struct sqlite3    *g_state_auditor_test_pdb;   /* progress.kv stand-in */
extern const char        *g_state_auditor_test_datadir;

/* Reset all counters/streaks/latches — test-only fixture reset. */
void state_auditor_reset_for_test(void);

/* Directly latch/clear a leg's mismatch state — bypasses the real window
 * check entirely, for isolated condition-wiring tests (conditions/
 * state_auditor_mismatch.c) that only need state_auditor_get_mismatch() to
 * report a specific latched/clear state, not a full fixture-driven scan. */
void state_auditor_force_latch_for_test(enum state_auditor_leg leg,
                                        int32_t h_start, int32_t h_end,
                                        const char *detail);
void state_auditor_force_clear_for_test(enum state_auditor_leg leg);

/* Deterministic seed override: when non-negative, every tick uses this value
 * (instead of an internal monotonic counter) to derive the random window —
 * lets a test drive a SPECIFIC sampled window reproducibly. -1 (default)
 * uses the internal counter. */
void state_auditor_set_test_seed(int64_t seed_or_negative_for_auto);

uint64_t state_auditor_test_op_return_ticks(void);
uint64_t state_auditor_test_coins_ticks(void);
#endif

#endif /* ZCL_SERVICES_STATE_AUDITOR_H */
