/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * index_fold_guard — shared safety rails for the body-derived secondary
 * index backfills (address_index, txindex projection). These are the two
 * always-on "omniscience" catalogs: ON by default so a plain boot knows
 * everything about its own chain, but a historical fold walks millions of
 * blocks and must never (a) fill the disk blindly, nor (b) spin forever below a
 * snapshot-seed floor where block bodies are structurally absent.
 *
 * Both rails surface a NAMED typed blocker (util/blocker.h) so a stall is an
 * operator-visible entry in `z23 dumpstate blocker`, never a silent
 * refuse. Neither ever blocks tip-follow: the caller holds only a bounded batch
 * of the progress-store trylock and yields immediately (see
 * address_index_service.c / txindex_projection_service.c). */

#ifndef ZCL_SERVICES_INDEX_FOLD_GUARD_H
#define ZCL_SERVICES_INDEX_FOLD_GUARD_H

#include <stdbool.h>
#include <stdint.h>

typedef struct sqlite3 sqlite3;

/* Conservative free-space floor a first-run/continuing index backfill requires
 * before it writes new rows. A full historical fold can add several GiB; a
 * 10 GiB headroom keeps the node well clear of the disk_monitor refuse
 * threshold (1 GiB) so consensus writes never lose their last bytes to an
 * observability index. Overridable in tests via
 * index_fold_set_min_free_for_test(). */
#define INDEX_FOLD_MIN_FREE_BYTES ((int64_t)(10LL * 1024 * 1024 * 1024))

/* Free-disk precheck. Returns true if it is safe to write index rows now.
 * Returns false — and raises a named "<index_id>.disk_low" BLOCKER_RESOURCE
 * blocker — when free space on `datadir` is below the backfill floor OR the
 * disk_monitor is already CRITICAL. Clears that blocker when space is healthy
 * again. `index_id` is the blocker id-prefix (e.g. "address_index"); `subsys`
 * is the owner subsystem. Both must be interned/static strings. A datadir whose
 * free space cannot be measured (statvfs error) fails OPEN (returns true) — the
 * disk_monitor condition owns the hard refuse; this is a conservative gate. */
bool index_fold_disk_ok(const char *index_id, const char *subsys,
                            const char *datadir);

/* Called when a fold hit an ABSENT body at `absent_height`. If that height is
 * at/below the durable snapshot-seed floor (REDUCER_TRUSTED_BASE_HEIGHT_KEY in
 * progress_meta), bodies below it are structurally absent and the projection
 * can never fold across the floor: raise a named
 * "<index_id>.below_snapshot_seed" BLOCKER_DEPENDENCY blocker (waiting on the
 * historical body/shielded backfill) instead of spinning. Above the floor — or
 * on a from-genesis datadir with no seed — it is a transient/genuine gap the
 * service's own coverage_blocked flag surfaces, so the seed blocker is cleared.
 * A DB read error leaves any existing seed blocker untouched (fail-soft). */
void index_fold_note_absent_body(const char *index_id, const char *subsys,
                                     sqlite3 *db, int64_t absent_height);

/* Clear the "<index_id>.below_snapshot_seed" blocker (the fold advanced or
 * caught up to H*). No-op if not set. */
void index_fold_clear_seed_blocker(const char *index_id);

/* The durable snapshot-seed floor (REDUCER_TRUSTED_BASE_HEIGHT_KEY, read from
 * the kernel authority progress_store_db()). Returns true and fills *floor_out
 * only when a seed floor exists; false for a from-genesis datadir OR a read
 * error, with *floor_out set to -1. Exported so a projection can ADOPT the
 * floor as its declared base instead of spinning below it.
 *
 * Reads under progress_store_tx_trylock: when the reducer drive owns the
 * progress store this YIELDS (returns false, *floor_out = -1) rather than
 * blocking. Callers run on the supervisor tick-runner thread, where a
 * blocking acquire freezes the runner heartbeat for the length of a fold
 * commit and gets the node SIGABRT'd by the systemd watchdog. A false
 * return is therefore "unknown right now, retry next tick", never "no
 * floor" — treat it as no-op, exactly as index_fold_note_absent_body does. */
bool index_fold_snapshot_seed_floor(int64_t *floor_out);

/* Ticks that yielded rather than block behind the reducer drive. Non-zero is
 * the yield WORKING, not a fault; unbounded growth with a frozen fold is not. */
uint64_t index_fold_seed_floor_yields(void);

/* DECLARED PARTIAL COVERAGE — the projection has adopted the snapshot-seed
 * floor as its base and now folds forward from `base_height`. This is the
 * successor to spinning on "<index_id>.below_snapshot_seed": the index makes
 * progress AND the coverage limit stays a NAMED, operator-visible fact rather
 * than being silently swallowed.
 *
 * Raises "<index_id>.partial_coverage" (BLOCKER_DEPENDENCY, remedy OWNER in
 * blocker_remedy_bindings.def, decision text in blocker_operator_decisions.def,
 * no escape action and no retry budget — there is nothing safe for the node to
 * attempt on its own) and clears "<index_id>.below_snapshot_seed", which the
 * declaration supersedes. Call it ONCE per adoption / once per process for an
 * already-adopted base, not per tick: the fact is standing, not recurring. */
void index_fold_declare_partial_coverage(const char *index_id,
                                         const char *subsys,
                                         int64_t base_height,
                                         int64_t seed_floor);

/* Retire the "<index_id>.partial_coverage" declaration (the index was rebuilt
 * from genesis, or the pre-seed bodies arrived). No-op if not set. */
void index_fold_clear_partial_coverage(const char *index_id);

/* UNREADABLE BODY — the sibling of note_absent_body, for the other shape.
 * Here the block index says BLOCK_HAVE_DATA and hands out an (nFile,nDataPos),
 * but the bytes there do not read back as that block: a torn import, or a
 * blk*.dat hardlinked into a live foreign writer's datadir whose own appends
 * overwrote the indexed record (see the hardlink tripwire in
 * lib/storage/src/disk_block_io.c).
 *
 * Unlike an absent body this is NOT self-limiting. Nothing in-process repairs
 * a height far below the fold frontier: the have_data_unreadable Condition
 * only inspects tip+1 and the reducer stages, so a torn body at h=1 is retried
 * by the backfill forever. Measured live 2026-08-23 on node1: 12,435 identical
 * re-reads of h=1 over 14.5 h at one every ~3 s, each emitting an identical
 * WARN, none of which could ever have succeeded.
 *
 * Raises "<index_id>.body_unreadable" (BLOCKER_DEPENDENCY, remedy OWNER, no
 * escape action and no retry budget — the node cannot re-derive bytes that are
 * not on disk). Call it once the caller's own retry budget at `height` is
 * spent, not on the first miss: a body being written right now can miss once.
 * `attempts` is the consecutive-failure count, carried into the reason text so
 * the operator sees how long it has stood. */
void index_fold_note_unreadable_body(const char *index_id, const char *subsys,
                                     int64_t height, uint64_t attempts);

/* Retire "<index_id>.body_unreadable" — the height finally read back, or the
 * fold moved past it. No-op if not set. */
void index_fold_clear_unreadable_body(const char *index_id);

/* Test-only: override the free-space floor (bytes). Pass a negative value to
 * restore the compiled INDEX_FOLD_MIN_FREE_BYTES default. */
void index_fold_set_min_free_for_test(int64_t bytes);

/* Ticks whose seed-floor read YIELDED rather than block behind the reducer
 * drive's fold commit. The read runs on the supervisor tick-runner thread,
 * where a blocking acquire freezes the runner heartbeat and gets the node
 * SIGABRT'd by the systemd watchdog; it therefore try-locks and skips. A yield
 * is a NO-OP (the blocker is left exactly as found, retried in ~2 s), so
 * non-zero here is the guard WORKING. Unbounded growth alongside a frozen fold
 * is not. */
uint64_t index_fold_seed_floor_yields(void);

#endif /* ZCL_SERVICES_INDEX_FOLD_GUARD_H */
