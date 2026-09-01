/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * refold_progress — the single "a from-genesis staged refold is in progress"
 * signal. A from-genesis refold (`-refold-staged`) RESETS the reducer cursors
 * to genesis and folds the chain forward reading block BODIES (never the
 * borrowed node.db `utxos`). While that fold is below the SHA3 UTXO
 * checkpoint (REDUCER_FRONTIER_TRUSTED_ANCHOR), the L0 frontier and the L1
 * self-repair must NOT treat a below-anchor cursor as a defect — the cursor is
 * legitimately re-walking the frozen region from the bottom.
 *
 * MECHANISM — a persistent progress.kv meta key (refold_in_progress, 1-byte
 * blob {0x01}) so the signal SURVIVES a restart mid-fold, plus a cached atomic
 * for a cheap hot-path read. The key is:
 *   - SET   by refold_progress_mark_started() when -refold-staged resets the
 *     reducer to genesis (engine/composition/src/boot.c);
 *   - CLEARED by refold_progress_clear_if_crossed() once the fold's
 *     utxo_apply cursor reaches/passes REDUCER_FRONTIER_TRUSTED_ANCHOR (so a
 *     refold that has re-folded the frozen prefix is back under the normal
 *     finality floor);
 *   - REFRESHED into the cached atomic by refold_progress_refresh() at boot.
 *
 * SCOPING IS THE WHOLE POINT: on a NORMAL boot the key is absent, so
 * refold_in_progress() returns false, reducer_frontier_floor() returns the
 * compiled anchor, and the reconcile condition runs fully — the same path a
 * node takes today. Only a -refold-staged datadir flips the floor to 0 and
 * suspends the self-repair.
 *
 * This module changes NO validation rule. It changes only the FLOOR used for
 * H* reporting + whether the below-anchor self-repair runs — never what a
 * block/tx must satisfy. */

#ifndef ZCL_JOBS_REFOLD_PROGRESS_H
#define ZCL_JOBS_REFOLD_PROGRESS_H

#include <stdbool.h>
#include <stdint.h>

#include <sqlite3.h>

/* The durable progress.kv key. 1-byte blob {0x01} when set; absent otherwise. */
#define REFOLD_IN_PROGRESS_KEY "refold_in_progress"

/* The FROM-ANCHOR refold sub-mode. A from-ANCHOR refold (-refold-from-anchor)
 * re-seeds the SHA3-verified anchor coin set, forces the 8 stage cursors to the
 * anchor (NOT genesis), and folds forward from the anchor reading block BODIES.
 * It ALSO sets REFOLD_IN_PROGRESS_KEY (so refold_in_progress() and the mirror-sync
 * guard at utxo_mirror_sync_service.c hold), but this distinct atomic lets the L0
 * frontier keep its floor at the COMPILED ANCHOR (the fold legitimately starts AT
 * the anchor, never below it) instead of dropping to 0 as the from-genesis refold
 * does. Cleared once the fold's utxo_apply cursor reaches the resume target. */
#define REFOLD_FROM_ANCHOR_KEY "refold_from_anchor"

/* The durable resume target (the active-chain tip the from-anchor fold climbs to).
 * Stored as a little-endian int32 blob; absent on a normal boot. Read by the CLEAR
 * edge so a mid-fold restart resumes against the same target. */
#define REFOLD_FROM_ANCHOR_TARGET_KEY "refold_from_anchor_target"

/* Cheap hot-path reader: returns the cached atomic, refreshed at boot
 * (refold_progress_refresh) and on every mark/clear. No DB read, no lock —
 * safe to call from the reducer frontier and condition detect paths. */
bool refold_in_progress(void);

/* Refresh the cached atomic from the durable key on `db`. Call once at boot
 * after the progress store is open. Returns false on a DB read error (the
 * cached value is then left conservatively false). */
bool refold_progress_refresh(sqlite3 *db);

/* SET the durable key on `db` AND update the cache. Idempotent. Call when
 * -refold-staged has reset the reducer cursors to genesis. Returns false on a
 * DB write error. */
bool refold_progress_mark_started(sqlite3 *db);

/* Boot convenience: refresh the cache from `db`, then (when `mark_started`)
 * SET the signal — the single call engine/composition/src/boot.c makes after the progress
 * store opens. Best-effort; logs on a DB error. */
void refold_progress_boot_init(sqlite3 *db, bool mark_started);

/* If the key is set AND `utxo_apply_cursor` has reached/passed
 * REDUCER_FRONTIER_TRUSTED_ANCHOR, DELETE the durable key and clear the cache.
 * A no-op (returns true) when the key is absent or the cursor is still below
 * the anchor. Returns false on a DB read/write error. */
bool refold_progress_clear_if_crossed(sqlite3 *db, int32_t utxo_apply_cursor);

/* ── FROM-ANCHOR refold (-refold-from-anchor) ───────────────────────────────
 *
 * Cheap hot-path reader: true iff the from-ANCHOR refold sub-mode is active
 * (REFOLD_FROM_ANCHOR_KEY set). Distinct from refold_in_progress(): a from-anchor
 * refold sets BOTH keys, but this one tells reducer_frontier_floor() to keep the
 * floor at the COMPILED ANCHOR (the fold starts AT the anchor) instead of dropping
 * to 0. Cached atomic, refreshed by refold_progress_refresh(). */
bool refold_from_anchor_active(void);

/* Lock-free read of the cached from-anchor resume target (the durable
 * REFOLD_FROM_ANCHOR_TARGET_KEY). Returns true and sets *out when a positive
 * target is cached; false when unset/absent. Seeded at boot by
 * refold_progress_refresh and republished on every mark/bump/clear, so the
 * rom_compile dumper reads it without taking the blocking progress lock. */
bool refold_from_anchor_target_cached(int32_t *out);

/* SET both REFOLD_IN_PROGRESS_KEY and REFOLD_FROM_ANCHOR_KEY on `db` plus the
 * durable resume target, AND update both caches. Idempotent. Call when
 * -refold-from-anchor (or the boot torn-import auto-arm) has re-seeded the anchor
 * coin set and forced the 8 stage cursors to the anchor. `resume_target` is the
 * active-chain tip the fold climbs to (the CLEAR edge keys on it). Returns false
 * on a DB write error. */
bool refold_progress_mark_started_from_anchor(sqlite3 *db, int32_t resume_target);

/* If the from-anchor key is set AND `utxo_apply_cursor` has reached/passed
 * `target`, DELETE both durable keys (+ the target) and clear both caches. A
 * no-op (returns true) when the from-anchor key is absent or the cursor is still
 * below the target. Returns false on a DB read/write error. The off-the-drive
 * reconcile tick owns this CLEAR edge. */
bool refold_progress_clear_if_reached(sqlite3 *db, int32_t utxo_apply_cursor,
                                      int32_t target);

/* CUTOVER DEFECT 1 fix — raise the durable from-anchor resume target to
 * MAX(stored, `live_tip`). The resume target is captured ONCE at boot (the
 * active-chain tip then), but the chain advances during a multi-hour fold, so
 * the stale boot target sits BELOW the true tip. The off-the-drive reconcile
 * tick calls this each tick with the LIVE active_chain_height BEFORE
 * refold_progress_clear_if_reached, so the clear edge keys on the CURRENT tip
 * and never fires while the fold is still climbing to it. NEVER lowers the
 * target (a brief reorg-rollback read must not drop the fold ceiling) and is a
 * no-op when no from-anchor refold is armed. Returns false on a DB read/write
 * error. Touches ONLY progress.kv — takes no csr->lock and runs no evidence
 * machinery, so it is safe on the reducer-drive-adjacent reconcile path. */
bool refold_progress_bump_target(sqlite3 *db, int32_t live_tip);

/* See CLAUDE.md "Adding state introspection". Reentrant-safe. */
struct json_value;
bool refold_progress_dump_state_json(struct json_value *out, const char *key);

#ifdef ZCL_TESTING
/* Test-only: force the cached atomic without touching any DB. Lets a unit
 * test exercise reducer_frontier_floor() / the reconcile gate at both
 * settings without standing up the singleton progress store. */
void refold_progress_test_set_cached(bool in_progress);
#endif

#endif /* ZCL_JOBS_REFOLD_PROGRESS_H */
