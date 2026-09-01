/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * stage_anchor — trusted reducer-anchor cursor alignment helpers.
 * utxo_apply alignment is capped by coins_applied_height when that durable
 * frontier exists, so a trusted tip cannot fake coin application, and every
 * stage is capped at its own log frontier (FIX-3) so an anchor can never
 * manufacture a rowless cursor hole. */

#ifndef ZCL_JOBS_STAGE_ANCHOR_H
#define ZCL_JOBS_STAGE_ANCHOR_H

#include <sqlite3.h>
#include <stdbool.h>
#include <stdint.h>

/* FIX-3 source guard: cap a cursor jump target at the stage's own log
 * frontier, so an anchor can never advance a cursor past a rowless height.
 * Cursor jumps over rowless heights are the manufacturing site of the
 * log-hole wedge class (the 3,135,516 span): only utxo_apply was
 * coins-capped, which is exactly why it alone stayed behind.
 *
 * Cap rule, evaluated in order:
 *   1. requested <= cursor  -> no cap (forward-only is preserved by
 *      stage_set_named_cursor_if_behind; this helper never RAISES a target
 *      and never asks for a cursor rewind).
 *   2. seed_exempt          -> no cap. The exemption is a CALLER-DECLARED
 *      verdict evaluated against PRE-INSERT state (a trusted SHA3-verified
 *      snapshot seed, or "the log was empty before the anchor row was
 *      written"). It must NEVER be inferred from the log after an anchor
 *      row was inserted: both tip_finalize self-stamp sites insert the row
 *      BEFORE the cursor write, so a post-insert "log empty" probe can
 *      never be true and a naive exemption would cap every fresh seed to 0
 *      (wedging fresh cold-syncs above the compiled checkpoint).
 *   3. log has no row below requested -> no cap (fresh-seed semantics: an
 *      empty — or not-yet-created — log is a stage that has not started,
 *      not a hole). Safe at the upstream anchor sites because
 *      stage_anchor_upstream_cursors_to inserts NO rows into upstream
 *      logs; only tip_finalize_log ever receives anchor rows, so only the
 *      self-stamp sites need prong 2.
 *   4. else *capped = the lowest rowless height in [cursor, requested)
 *      (any row counts, ok or not; cursor itself when rowless); if the
 *      span is fully covered -> no cap. The just-written anchor row at
 *      requested-1 naturally counts as coverage, keeping healthy restarts
 *      and repeated regtest stamps cap-free.
 *
 * O(log n): one point-probe at cursor plus one indexed first-gap query —
 * never a per-height loop (a [0, 3.1M) walk must not stall boot).
 *
 * Returns false ONLY on a real SQLite error (logged with context). On
 * success *capped holds the (possibly lowered) jump target; every cap also
 * emits one LOG_WARN (stage/from/requested/capped, reason=log_frontier). */
bool stage_anchor_cap_target_at_log_frontier(sqlite3 *db,
                                             const char *log_table,
                                             uint64_t cursor,
                                             uint64_t requested,
                                             bool seed_exempt,
                                             uint64_t *capped);

/* Align every upstream reducer stage cursor (header_admit .. utxo_apply)
 * forward to `target` (forward-only; never rewinds). Each stage is capped
 * at its own log frontier per the rule above; `seed_exempt` is the
 * caller-declared FIX-3 exemption (true ONLY for trusted seeds, e.g. the
 * SHA3-verified snapshot accept — fresh datadirs are already covered by
 * the empty-log prong). utxo_apply is additionally capped by
 * coins_applied_height when that durable frontier exists. */
bool stage_anchor_upstream_cursors_to(sqlite3 *db, uint64_t target,
                                      const char *owner,
                                      const char *reason,
                                      bool seed_exempt);

#endif /* ZCL_JOBS_STAGE_ANCHOR_H */
