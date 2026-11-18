/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#ifndef ZCL_DB_MODEL_CATALOG_DIGEST_HISTORY_H
#define ZCL_DB_MODEL_CATALOG_DIGEST_HISTORY_H

/* Bounded per-height digest history of the two cursor-owning catalogs.
 *
 * zslp_ledger and op_return_index each keep a cursor (the highest folded
 * height) and a running digest that chains every folded height. A chained
 * digest cannot be rewound, so a reorg that took blocks off the chain below
 * the cursor used to force a drop-and-rebuild of the whole catalog (hours on
 * mainnet). Remembering the digest AFTER each of the last
 * CATALOG_HISTORY_DEPTH folded heights makes the common reorg exact and
 * cheap: delete the catalog rows above the fork, restore cursor = fork and
 * digest = the stored digest at the fork.
 *
 * The table is a derived, rebuildable projection like the catalogs
 * themselves: never consulted by consensus, and every read treats a missing
 * entry as "not known" (the caller falls back to drop-and-rebuild). One row
 * per (catalog, height); pruned to the window on every fold step.
 *
 * `tainted` marks a height whose fold also rewrote state stamped at an
 * EARLIER height (zslp: a later transaction settled an ancestor the walk
 * bound had refused). Such a step cannot be undone by deleting rows above
 * the fork, so a rewind across a tainted height falls back to rebuild.
 *
 * Atomicity: a fold step's cursor write and its history write are one unit
 * (catalog_fold_unit_begin/end); the invariant "history(cursor) == the cursor
 * digest" therefore holds across a crash, and the rewind verifies it before
 * trusting anything. */

#include "models/database.h"

#include <stdbool.h>
#include <stdint.h>

/* Heights of history kept below the newest folded height. One more than the
 * catchup fork-scan depth (CATCHUP_FORK_SCAN_DEPTH = 4096): that scan finds a
 * stale row as deep as cursor - 4096 and rewinds to the height below it, so
 * the deepest fork it can produce is cursor - 4097, and a reorg the
 * projection rewind can detect is always inside the window. A rewind whose
 * fork is CATALOG_HISTORY_DEPTH or fewer heights below the cursor is exact;
 * one more falls back to rebuild. */
#define CATALOG_HISTORY_DEPTH 4097

enum catalog_history_kind {
    CATALOG_HISTORY_ZSLP_LEDGER = 1,
    CATALOG_HISTORY_OP_RETURN_INDEX = 2,
};

/* Outcome of a catalog unwind to a fork height. */
enum catalog_rewind {
    CATALOG_REWIND_NOOP = 0,   /* cursor at or below the fork: rows above go */
    CATALOG_REWIND_EXACT,      /* rows above go, cursor+digest restored */
    CATALOG_REWIND_REBUILD,    /* history cannot prove the fork: truncated */
    CATALOG_REWIND_ERROR,      /* a statement failed; caller rolls back */
};

/* The unit a fold step's writes share: holds the connection mutex (so no
 * statement of another thread lands between ours) and opens a SAVEPOINT.
 * end(ok=true) releases it; end(ok=false) rolls back to it. Always call end
 * after a successful begin. */
bool catalog_fold_unit_begin(struct node_db *ndb);
bool catalog_fold_unit_end(struct node_db *ndb, bool ok);

/* Record the digest after folding `height`, and (INSERT OR IGNORE) the digest
 * of `prev_height` it was folded from when that is >= 0, so a rewind to the
 * previous cursor is possible even for the first step after an upgrade.
 * An entry already held at prev_height that differs from prev_digest means the
 * catalog was refolded without this history in between: the whole history of
 * the catalog is cleared first. Prunes entries older than height -
 * CATALOG_HISTORY_DEPTH. Call inside the
 * fold unit together with the catalog's cursor write. */
bool catalog_history_record_step(struct node_db *ndb,
                                 enum catalog_history_kind kind,
                                 int32_t prev_height,
                                 const uint8_t prev_digest[32],
                                 int32_t height, const uint8_t digest[32],
                                 bool tainted);

/* True and fills digest/tainted when an entry for (kind, height) exists. */
bool catalog_history_lookup(struct node_db *ndb,
                            enum catalog_history_kind kind, int32_t height,
                            uint8_t digest_out[32], bool *tainted_out);

/* Number of entries for a catalog (diagnostics, tests). */
int64_t catalog_history_count(struct node_db *ndb,
                              enum catalog_history_kind kind);

/* Delete entries above `height`; `height` itself is kept. */
bool catalog_history_drop_above(struct node_db *ndb,
                                enum catalog_history_kind kind,
                                int32_t height);

/* Delete every entry of a catalog (truncate, base adoption). */
bool catalog_history_clear(struct node_db *ndb,
                           enum catalog_history_kind kind);

/* True when any entry in (fork_height, cursor_height] is tainted. A DB error
 * answers true (the caller then rebuilds, the safe direction). */
bool catalog_history_tainted_between(struct node_db *ndb,
                                     enum catalog_history_kind kind,
                                     int32_t fork_height,
                                     int32_t cursor_height);

/* Decide whether a catalog whose cursor sits at (cursor_height,
 * cursor_digest) can be rewound EXACTLY to `fork_height` (< cursor_height).
 * True and *fork_digest filled only when: the fork is within the window, the
 * history holds an entry for the fork and for the cursor, the cursor entry's
 * digest equals the cursor's own, and no tainted step lies between. Otherwise
 * false with a one-line reason in `why`. */
bool catalog_history_can_rewind(struct node_db *ndb,
                                enum catalog_history_kind kind,
                                int32_t fork_height, int32_t cursor_height,
                                const uint8_t cursor_digest[32],
                                uint8_t fork_digest[32], char *why,
                                size_t why_size);

#endif /* ZCL_DB_MODEL_CATALOG_DIGEST_HISTORY_H */
