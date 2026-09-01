/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * catalog_completeness — the READ-ONLY catalog reader.
 *
 * Enumerates every chain-data index/projection this process knows about,
 * reads each one's live cursor, and compares it against a caller-supplied
 * target height (H* — the reducer's provable served height,
 * reducer_frontier_provable_tip_cached()). The result is a per-index lag
 * table an operator surface can render directly: "op_return_index is 0
 * blocks behind, address_index is disabled, sprout_anchor is missing
 * 1,200,000 blocks of history".
 *
 * REPORT ONLY. This module never writes to any store it reads from (not
 * anchor_kv, not nullifier_kv, not progress.kv state, not node.db) and
 * never mutates a cursor. It is pure diagnostic composition over
 * already-shipped accessors.
 *
 * Design: a small static table of {name, get_cursor(void), always_on}
 * rows (catalog_completeness.c). Sparse anchor/nullifier state journals use
 * their atomically co-committed reducer processing frontier, not the height of
 * their last state mutation. Adding a new index to the catalog is one
 * row + one wrapper function — no dynamic registration API, no dependency
 * on boot order (every wrapper degrades to "unavailable" instead of
 * assuming its subsystem is already linked).
 *
 * Layering: this file lives in engine/modules/storage/, but three of its rows are
 * backed by app/-layer accessors (op_return_index in app/models,
 * address_index in app/jobs, the explorer node.db projection in
 * app/models + app/controllers). Those symbols are reached via forward
 * declaration ONLY (see catalog_completeness.c) — never an #include of
 * controllers/models/services/views headers — so the lib/ → app/
 * direction check_lib_layering.sh enforces (HARD gate, see that script's
 * own "Fix option 2: forward declaration") stays clean.
 *
 * This lane does NOT register a diagnostics dumper or a condition; a
 * later lane wires catalog_completeness_snapshot() into
 * `z23 ops state` / a typed blocker. This module is the engine,
 * not the surface. */

#ifndef STORAGE_CATALOG_COMPLETENESS_H
#define STORAGE_CATALOG_COMPLETENESS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Sentinel a get_cursor() accessor returns when its index's subsystem is
 * not linked, not initialized, or explicitly disabled for this process
 * (e.g. -addressindex was not passed, or the shared progress.kv / node.db
 * singleton has not been wired yet — both routine, not error, states).
 * catalog_completeness_snapshot() turns this into a clean
 * {enabled=false, cursor=0, lag=0} row rather than a guess. Never a valid
 * real cursor value: every real cursor here is a block height (>= -1) or
 * an activation-derived proxy (>= 0), always far above INT64_MIN. */
#define CATALOG_CURSOR_UNAVAILABLE INT64_MIN

/* ── Is an empty index empty because nothing happened, or because it is
 *    broken? ──────────────────────────────────────────────────────────
 *
 * `lag` alone cannot answer that, and answering it wrong is expensive.
 * Measured on the canonical node 2026-07-28, at the front of the chain with
 * 22 peers: op_return_index held 0 rows, zslp_ledger 0 rows, znam_names 0
 * rows — and two subsystems gave CONTRADICTORY diagnoses of the same table.
 * catalog_lag_exceeded said "its backfill service is stalled and must
 * resume" (a defect, with an action). index_fold_guard said the bodies
 * below the snapshot-seed floor were never downloaded, so the fold can never
 * cross (structural, and "resume" cannot work). Both were reporting true
 * facts about their own concern; neither could see the fact that reconciles
 * them.
 *
 * That fact is COVERAGE: how much of the range this index can actually
 * reach has it folded? The reachable range is [floor, target] — not
 * [0, target] — because on a snapshot-seeded datadir there are no block
 * bodies below the seed height, so no index that folds bodies forward can
 * ever cover them.
 *
 * With coverage, an empty table finally means something:
 *   COMPLETE  — covered everything reachable. An empty table is EVIDENCE:
 *               nothing happened in that range.
 *   PARTIAL   — covered some of it. An empty table proves nothing.
 *   NONE      — covered none of it. An empty table proves nothing.
 *
 * Deliberately NOT a row count. COUNT(*) on op_return_index measured 3.5 s
 * on the live node — far past any poll budget — and the count is not what
 * makes emptiness meaningful anyway. Coverage is. A caller that wants the
 * number can ask the index's own dumper, which already publishes it. */
enum catalog_coverage {
    CATALOG_COVERAGE_UNKNOWN = 0, /* not enabled / no cursor to read */
    CATALOG_COVERAGE_NONE,        /* none of [floor,target] folded */
    CATALOG_COVERAGE_PARTIAL,     /* some of it folded */
    CATALOG_COVERAGE_COMPLETE,    /* all of it folded */
};

const char *catalog_coverage_name(enum catalog_coverage c);

/* One row of the completeness report. */
struct catalog_index_status {
    const char *name;   /* stable row name, e.g. "op_return_index" */
    int64_t cursor;      /* this index's live cursor (0 when !enabled) */
    int64_t target;      /* the target_height passed to snapshot() (H*) */
    int64_t lag;         /* max(0, target - cursor); 0 when !enabled */
    /* Lowest height this index could EVER cover. 0 on a from-genesis
     * datadir; the durable snapshot-seed base height
     * (reducer_trusted_base_height) on a seeded one, for the rows that fold
     * block bodies forward. A positive floor is not a fault — it is a
     * permanent, structural statement that history below it is unreachable
     * by this index and no amount of "resuming" will change that. */
    int64_t floor;
    int coverage;        /* enum catalog_coverage over [floor, target] */
    bool always_on;      /* true = expected running on every node (a
                           * disabled always_on row is worth flagging;
                           * false = legitimately opt-in, e.g. address_index) */
    bool enabled;         /* false = subsystem not linked/initialized/opted
                           * in for this process right now */
};

/* True only when this row's coverage is COMPLETE — i.e. when finding zero
 * rows in the index is EVIDENCE that nothing happened, rather than merely
 * the absence of evidence. Every caller that is about to conclude something
 * from an empty index should ask this first; a token balance read at a
 * snapshot height off an index with incomplete coverage is a guess wearing
 * a number's clothes. */
bool catalog_index_emptiness_is_meaningful(
    const struct catalog_index_status *row);

/* Upper bound on registered indexes — a compile-time static table, not a
 * dynamic registry (see the header comment above). Sized generously above
 * the current row count so a future row never needs this constant bumped
 * blindly by a caller. */
#define CATALOG_COMPLETENESS_MAX_INDEXES 16

/* Fill out[0 .. min(registered_count, max)) with one row per registered
 * index, each cursor read LIVE via its accessor and compared against
 * target_height. Returns the number of rows written (0 if out is NULL or
 * max is 0 — logged, never a crash).
 *
 * Pure read: touches no store's write path, allocates nothing (out is
 * caller-owned), and is safe to call before boot completes or with a
 * process that never linked a given subsystem — every row degrades to
 * enabled=false instead of dereferencing an unready singleton. */
size_t catalog_completeness_snapshot(struct catalog_index_status *out,
                                     size_t max, int64_t target_height);

/* The largest lag among ENABLED rows in `rows[0..n)` (disabled rows carry
 * no lag signal and are skipped — an opted-out address_index is not
 * "behind"). Returns 0 when n == 0, rows is NULL, or every enabled row is
 * caught up. Every row.lag is already clamped to >= 0 by snapshot(), so
 * this is a simple max-reduce, not a re-derivation. */
int64_t catalog_completeness_worst_lag(const struct catalog_index_status *rows,
                                       size_t n);

/* The single ENABLED row with the largest lag STRICTLY greater than
 * `threshold`, or NULL if no enabled row exceeds it (disabled rows carry no lag
 * signal and are skipped). Ties resolve to the first such row. Pure — no store
 * access — so the catalog_lag_exceeded condition and its unit test share one
 * definition of "which index is over the line". NULL rows / n==0 -> NULL. */
const struct catalog_index_status *catalog_completeness_worst_over(
    const struct catalog_index_status *rows, size_t n, int64_t threshold);

/* The omniscience verdict — a single classification over a completeness
 * snapshot PLUS the node's live network posture. */
enum catalog_verdict {
    CATALOG_VERDICT_OMNISCIENT = 0, /* every enabled index caught up, peers at
                                     * or above floor, census fresh */
    CATALOG_VERDICT_BLOCKED,        /* an enabled index is lagging */
    CATALOG_VERDICT_DEGRADED,       /* peers below floor, or census stale */
};

/* Classify `rows[0..n)` against the network posture and write a stable verdict
 * string into `out` (never overflows `out_cap`; safe with out==NULL/out_cap==0,
 * which just skips the string). Precedence: a lagging index (BLOCKED) dominates
 * a degraded P2P/census layer.
 *   - "omniscient"           — all enabled indexes lag==0, handshaked_peers >=
 *                              peer_floor, and census is fresh
 *   - "blocked:<index>@<h>"  — the worst lagging enabled index (h = its cursor)
 *   - "degraded:peers"       — handshaked_peers < peer_floor
 *   - "degraded:census"      — census_age_s < 0 (no sweep yet) or
 *                              census_age_s > census_max_age_s (stale)
 * census_age_s < 0 means "no sweep recorded yet". Returns the enum regardless
 * of whether a string buffer was supplied. Pure — testable without a node. */
enum catalog_verdict catalog_completeness_verdict(
    const struct catalog_index_status *rows, size_t n,
    int handshaked_peers, int peer_floor,
    int64_t census_age_s, int64_t census_max_age_s,
    char *out, size_t out_cap);

#endif /* STORAGE_CATALOG_COMPLETENESS_H */
