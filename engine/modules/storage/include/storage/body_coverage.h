/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * body_coverage — first-class tracking of WHICH block-body height ranges
 * the node holds on disk.
 *
 * The problem it removes: the node had no record of which body ranges it
 * has. A checkpoint-installed datadir at tip is still missing historical
 * bodies (e.g. 3,056,759..3,155,842) that a snapshot-seeded datadir lacks,
 * and that need surfaced only reactively as the `chain.tip_behind_header_chain`
 * blocker while the download manager chased the tip. This module records the
 * body-coverage map explicitly so a missing range is a first-class,
 * queryable fact rather than a symptom.
 *
 * Two layers, both here:
 *
 *   1. Pure range algebra over a coverage map — a sorted set of disjoint,
 *      non-adjacent inclusive height ranges [lo, hi]. insert / remove /
 *      contains / find-first-hole / total-covered are pure functions with
 *      no clock, RNG, or IO. These are the unit-tested core.
 *
 *   2. A gap-fill scheduler that composes with (never rewrites) the block
 *      download manager: given a range the consumer needs, it derives the
 *      first uncovered hole, tracks per-range progress + fill rate, and
 *      names a blocker only when a needed hole makes no progress and no
 *      source can serve it.
 *
 * Coverage is a PROJECTION of block-index BLOCK_HAVE_DATA — rebuildable,
 * never authoritative. It is maintained incrementally via
 * body_coverage_note_stored / body_coverage_note_pruned at body store/prune
 * sites, seeded by a BOUNDED scan (never an O(chain) boot pass), and
 * persisted to progress_meta so a restart does not rescan.
 */

#ifndef ZCL_STORAGE_BODY_COVERAGE_H
#define ZCL_STORAGE_BODY_COVERAGE_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

/* Named blocker surfaced when a needed body range cannot be sourced. */
#define BODY_COVERAGE_NO_SOURCE_BLOCKER "chain.body_coverage_no_source"

/* progress_meta key holding the serialized coverage map. */
#define BODY_COVERAGE_META_KEY "body_coverage_ranges"

/* Cap on ranges persisted in one blob (bounded; normal operation is 1-3
 * ranges — a contiguous chain is a single range). A pathologically
 * fragmented map persists its lowest ranges and logs the truncation; the
 * map is a projection, so a partial persist is a cheap-rederive miss, never
 * a correctness loss. */
#define BODY_COVERAGE_PERSIST_MAX_RANGES 65536u

/* Inclusive height range: [lo, hi] with 0 <= lo <= hi. */
struct bc_range {
    int64_t lo;
    int64_t hi;
};

/* A coverage map: a dynamically grown array of disjoint, NON-adjacent
 * ranges kept sorted ascending by lo. Non-adjacent means a gap of at
 * least one height separates consecutive ranges (touching ranges are
 * always merged), so the map holds the minimal representation. */
struct body_coverage_map {
    struct bc_range *ranges;
    size_t           count;
    size_t           cap;
};

/* ── Lifecycle ──────────────────────────────────────────────────── */

void body_coverage_init(struct body_coverage_map *m);
void body_coverage_free(struct body_coverage_map *m);
/* Drop all ranges, keep the allocation. */
void body_coverage_reset(struct body_coverage_map *m);

/* ── Pure range algebra ─────────────────────────────────────────── */

/* Merge the inclusive range [lo, hi] into the map, coalescing any
 * overlapping OR adjacent ranges. lo > hi or lo < 0 is a no-op that
 * returns true. Returns false only on allocation failure. */
bool body_coverage_insert(struct body_coverage_map *m, int64_t lo, int64_t hi);

/* Remove the inclusive range [lo, hi] from the map, splitting any range it
 * bisects. lo > hi or lo < 0 is a no-op that returns true. Returns false
 * only on allocation failure (a split needs one extra slot). */
bool body_coverage_remove(struct body_coverage_map *m, int64_t lo, int64_t hi);

/* True iff height h is covered. */
bool body_coverage_contains(const struct body_coverage_map *m, int64_t h);

/* Find the FIRST uncovered sub-range within the closed query window
 * [from, to]. Returns true and fills *out with the hole (clamped to the
 * window) when a hole exists; returns false when [from, to] is fully
 * covered (or the window is empty / out is NULL). */
bool body_coverage_find_first_hole(const struct body_coverage_map *m,
                                   int64_t from, int64_t to,
                                   struct bc_range *out);

/* Sum of covered heights across all ranges. */
int64_t body_coverage_total_covered(const struct body_coverage_map *m);

/* Sum of covered heights inside the closed window [lo, hi]. 0 for an empty
 * or invalid window. The windowed counterpart of total_covered. */
int64_t body_coverage_covered_in_window(const struct body_coverage_map *m,
                                        int64_t lo, int64_t hi);

/* Merge every range of `src` into `dst`. Returns false only on allocation
 * failure, in which case `dst` may hold a partial union — callers that need
 * all-or-nothing must union into a scratch map.
 *
 * Currently unused, and there is one union in particular NOT to reach for
 * it to rebuild: storage/body_history.h used to union this map (what the
 * node claims to hold, restored from progress.kv at boot) into its
 * `measured` map (what the census probed this boot) and treat the result as
 * "definitively probed". That turns a FILE into a look, and it let a node
 * whose block index had gone unreadable publish "no hole" after zero
 * successful probes. Coverage is a projection and a claim; it is never
 * evidence that anything was checked. */
bool body_coverage_union_into(struct body_coverage_map *dst,
                              const struct body_coverage_map *src);

/* Number of disjoint ranges (hole count within any window is derivable
 * via find_first_hole; this is the fragmentation measure). */
size_t body_coverage_range_count(const struct body_coverage_map *m);

/* Highest covered height, or -1 if empty. */
int64_t body_coverage_max_covered(const struct body_coverage_map *m);

/* Incremental single-height convenience wrappers for store/prune sites. */
static inline bool body_coverage_note_stored(struct body_coverage_map *m,
                                             int64_t h)
{
    return body_coverage_insert(m, h, h);
}
static inline bool body_coverage_note_pruned(struct body_coverage_map *m,
                                             int64_t h)
{
    return body_coverage_remove(m, h, h);
}

/* ── Bounded-scan builder ───────────────────────────────────────── */

/* Seed the map from a BOUNDED height window [lo, hi] by asking `have_data`
 * for each height. The caller bounds [lo, hi]; this never walks the whole
 * chain. Returns the number of heights inserted. Existing ranges are
 * preserved (this is additive). */
size_t body_coverage_scan_window(struct body_coverage_map *m,
                                  int64_t lo, int64_t hi,
                                  bool (*have_data)(int64_t h, void *ctx),
                                  void *ctx);

/* ── Persistence (progress_meta blob) ───────────────────────────── */

struct sqlite3;
/* Serialize the map to a bounded blob under BODY_COVERAGE_META_KEY. */
bool body_coverage_save(const struct body_coverage_map *m, struct sqlite3 *db);
/* Load and REPLACE the map from the persisted blob. A missing key clears
 * the map and returns true (a fresh datadir has no coverage yet). Returns
 * false on a malformed blob (the map is left cleared, fail-closed). */
bool body_coverage_load(struct body_coverage_map *m, struct sqlite3 *db);

/* Same blob format under a caller-chosen progress_meta key, so a second
 * coverage-shaped fact (e.g. body_history's "heights I have definitively
 * probed" map) persists through this one codec instead of growing a
 * parallel one. `key` must be a stable NUL-terminated literal. */
bool body_coverage_save_key(const struct body_coverage_map *m,
                            struct sqlite3 *db, const char *key);
bool body_coverage_load_key(struct body_coverage_map *m,
                            struct sqlite3 *db, const char *key);

/* ── Gap-fill scheduler ─────────────────────────────────────────── */

/* Tracks the currently needed range, the active hole being filled, its
 * progress and fill rate, and a named-blocker latch. Pure state; the
 * caller drives it each pass and enqueues the returned hole through the
 * existing download manager (this module never touches peer selection). */
struct body_coverage_scheduler {
    int64_t needed_lo;
    int64_t needed_hi;

    struct bc_range active_hole;
    bool            has_active_hole;

    /* total_covered snapshot at the last plan, for a per-second fill rate. */
    int64_t last_total_covered;
    int64_t last_plan_unix;
    double  fill_rate_per_sec;

    /* Named-blocker latch: set when a needed hole makes zero progress and
     * the caller reports no source can serve it. */
    bool    blocked_no_source;
    int64_t blocked_since_unix;

    /* Counters. */
    uint64_t plans;
    uint64_t holes_seen;
    uint64_t no_source_fires;
};

void body_coverage_scheduler_init(struct body_coverage_scheduler *s);

/* Plan one pass: set the needed range, derive the first hole in
 * [needed_lo, needed_hi] against `map`, and update progress + fill rate
 * against `now_unix`. Returns true and fills *out_hole when there is a
 * hole to enqueue; returns false when the needed range is fully covered
 * (also clears any no-source latch, since coverage is complete). */
bool body_coverage_scheduler_plan(struct body_coverage_scheduler *s,
                                   const struct body_coverage_map *map,
                                   int64_t needed_lo, int64_t needed_hi,
                                   int64_t now_unix,
                                   struct bc_range *out_hole);

/* Report that the active hole was handed to the download manager. */
void body_coverage_scheduler_mark_enqueued(struct body_coverage_scheduler *s);

/* Latch the no-source blocker: a needed hole exists but nothing can serve
 * it (no header/block-index entry, no peer). Idempotent; stamps the first
 * time only. */
void body_coverage_scheduler_mark_no_source(struct body_coverage_scheduler *s,
                                            int64_t now_unix);

/* Clear the no-source latch (progress resumed / a source appeared). */
void body_coverage_scheduler_clear_no_source(
    struct body_coverage_scheduler *s);

/* ── Global singleton + diagnostics ─────────────────────────────── */

/* Process-wide coverage map + scheduler, lock-guarded for the dump path
 * and the maintenance callers. Lock/unlock bracket every access. */
struct body_coverage_map       *body_coverage_global_map(void);
struct body_coverage_scheduler *body_coverage_global_scheduler(void);
void body_coverage_global_lock(void);
void body_coverage_global_unlock(void);

/* See CLAUDE.md "Adding state introspection". Reentrant-safe. */
struct json_value;
bool body_coverage_dump_state_json(struct json_value *out, const char *key);

#endif /* ZCL_STORAGE_BODY_COVERAGE_H */
