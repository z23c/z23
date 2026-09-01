/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * catalog_completeness — implementation. See storage/catalog_completeness.h
 * for the design contract (REPORT ONLY, static table, forward-declared
 * app/-layer accessors).
 *
 * Cursor semantics per row:
 *   - op_return_index / address_index / view_integrity / explorer_projection
 *     report the ordinary "highest height folded contiguously from
 *     genesis" cursor their owning subsystem already exposes. lag =
 *     max(0, target - cursor) is the normal catch-up gap.
 *   - sprout_anchor / sapling_anchor / nullifier_history are activation-
 *     cursor stores (engine/modules/storage/anchor_kv.h, engine/modules/storage/nullifier_kv.h):
 *     a POSITIVE activation cursor means the prefix [0, activation_cursor)
 *     is a permanent, unbackfilled GAP, regardless of how far forward the
 *     store has since advanced. Reporting THAT forward position as
 *     "cursor" would hide the gap behind a healthy-looking lag. Instead,
 *     when the activation cursor is positive these rows report cursor=0 —
 *     "nothing from genesis is proven complete" — so lag = target (the
 *     harshest honest number), surfacing the exact
 *     utxo_apply.anchor_backfill_gap / nullifier_backfill_gap condition as
 *     a strongly positive lag rather than a small one. Only when the
 *     activation cursor is 0 (a true from-genesis store) do these rows
 *     report the atomically co-committed coins/utxo_apply frontier. Anchor and
 *     nullifier rows are sparse state-change journals: a Sprout tree whose
 *     last mutation was years ago can still have processed every later block.
 *     Treating its latest mutation height as its processing cursor creates a
 *     permanent false lag. coins_applied_height advances in the same reducer
 *     transaction that applies these stores, so it is the coverage witness.
 */

#include "storage/catalog_completeness.h"

#include "storage/anchor_kv.h"
#include "storage/coins_kv.h"
#include "storage/node_db_runtime.h"
#include "storage/nullifier_kv.h"
#include "storage/progress_store.h"
#include "storage/projection_store.h"
#include "util/log_macros.h"

#include <sqlite3.h>
#include <stdio.h>
#include <string.h>

/* ── app/-layer accessors, reached by FORWARD DECLARATION ONLY ──────────
 * Every symbol below is a pre-existing, already-shipped READ accessor
 * owned by its app/ home file (named per symbol). None is #include'd —
 * see catalog_completeness.h's layering note and
 * tools/scripts/check_lib_layering.sh's own "Fix option 2". This module
 * adds no new mutation surface: it only composes reads that already ship
 * elsewhere. */

struct node_db;

/* The process-wide explorer/node.db handle arrives through
 * storage/node_db_runtime.h — a lib/-owned port the composition root fills
 * in. It is NOT in the forward-declared list below: config/ sits ABOVE
 * lib/, so naming a config/ symbol from here would close a layering cycle
 * rather than merely skip an include. */

/* engine/models/src/op_return_index.c (models/op_return_index.h) — the
 * scalar-only variant, because struct op_return_index_cursor is an app/
 * type this layer cannot name without an include. */
extern bool op_return_index_get_cursor_heights(struct node_db *ndb,
                                               int32_t *out_height,
                                               int32_t *out_base_height);

/* contexts/explorer/models/src/explorer_index.c (models/explorer_index.h) — added
 * alongside this module for exactly this read (see that header). */
extern int64_t db_view_integrity_max_height(struct node_db *ndb);

/* engine/controllers/src/sync_controller_writers.c
 * (controllers/sync_controller.h) */
extern int node_db_sync_get_tip_height(struct node_db *ndb);

/* engine/reducer/jobs/src/reducer_frontier_trusted_base.c (jobs/reducer_frontier.h) —
 * the ONE decoder of the durable snapshot-seed base height. Forward-declared
 * rather than re-reading REDUCER_TRUSTED_BASE_HEIGHT_KEY with a locally
 * duplicated key literal and a locally duplicated 8-byte LE decode: a second
 * copy of one fact is exactly the drift this codebase keeps paying for. */
extern bool reducer_frontier_trusted_base_height_read(sqlite3 *db,
                                                      int32_t *height,
                                                      bool *found);

/* engine/jobs/src/address_index.c (jobs/address_index.h) */
extern bool address_index_enabled(void);
extern bool address_index_get_cursor(sqlite3 *db, int64_t *cursor_out);

/* engine/jobs/src/txindex_projection.c (jobs/txindex_projection.h) — the
 * txindex fold writes on the projection handle (projection_store_db) since the
 * Wave A2 split, exactly like address_index above. */
extern bool txindex_projection_enabled(void);
extern bool txindex_projection_get_cursor(sqlite3 *db, int64_t *cursor_out);

/* contexts/market/models/src/zslp_ledger.c (models/zslp_ledger.h) — the ZSLP ledger folds
 * into node.db (app_runtime_node_db), like op_return_index above. */
extern bool zslp_ledger_get_cursor(struct node_db *ndb, int32_t *out_height,
                                   uint8_t out_digest[32]);

/* ── per-index get_cursor() wrappers ─────────────────────────────────── */

static int64_t cc_get_op_return_cursor(void)
{
    struct node_db *ndb = node_db_runtime();
    if (!ndb) return CATALOG_CURSOR_UNAVAILABLE;
    int32_t h = -1, base = 0;
    if (!op_return_index_get_cursor_heights(ndb, &h, &base)) {
        LOG_WARN("catalog_completeness",
                 "op_return_index_get_cursor_heights failed (refused or "
                 "unreadable persisted state)");
        return CATALOG_CURSOR_UNAVAILABLE;
    }
    /* A positive base_height is DECLARED partial coverage, not a hidden gap:
     * the catalog states the range it covers, the limit is named by
     * op_return_index.partial_coverage, and this row keeps measuring the only
     * thing it can act on — catch-up distance to the target. Unlike the
     * activation-cursor rows above, there is nothing to un-hide here. */
    (void)base;
    return (int64_t)h;    /* -1 == "nothing folded yet", a legit low cursor */
}

static int64_t cc_get_address_index_cursor(void)
{
    if (!address_index_enabled()) return CATALOG_CURSOR_UNAVAILABLE;
    /* Wave A2 split: the address_index fold now writes on the projection
     * handle; read its committed cursor from that same handle. */
    sqlite3 *db = projection_store_db();
    if (!db) return CATALOG_CURSOR_UNAVAILABLE;
    int64_t cursor = -1;
    if (!address_index_get_cursor(db, &cursor)) {
        LOG_WARN("catalog_completeness", "address_index_get_cursor failed");
        return CATALOG_CURSOR_UNAVAILABLE;
    }
    return cursor;
}

static int64_t cc_get_txindex_cursor(void)
{
    if (!txindex_projection_enabled()) return CATALOG_CURSOR_UNAVAILABLE;
    /* Wave A2 split: the txindex fold now writes on the projection handle;
     * read its committed cursor from that same handle. */
    sqlite3 *db = projection_store_db();
    if (!db) return CATALOG_CURSOR_UNAVAILABLE;
    int64_t cursor = -1;
    if (!txindex_projection_get_cursor(db, &cursor)) {
        LOG_WARN("catalog_completeness", "txindex_projection_get_cursor failed");
        return CATALOG_CURSOR_UNAVAILABLE;
    }
    return cursor;    /* -1 == "nothing folded yet", a legit low cursor */
}

static int64_t cc_get_zslp_ledger_cursor(void)
{
    struct node_db *ndb = node_db_runtime();
    if (!ndb) return CATALOG_CURSOR_UNAVAILABLE;
    int32_t h = -1;
    uint8_t digest[32];
    if (!zslp_ledger_get_cursor(ndb, &h, digest)) {
        LOG_WARN("catalog_completeness", "zslp_ledger_get_cursor failed");
        return CATALOG_CURSOR_UNAVAILABLE;
    }
    return (int64_t)h;    /* -1 == "nothing folded yet", a legit low cursor */
}

static int64_t cc_get_view_integrity_cursor(void)
{
    struct node_db *ndb = node_db_runtime();
    if (!ndb) return CATALOG_CURSOR_UNAVAILABLE;
    return db_view_integrity_max_height(ndb);
}

static int64_t cc_get_explorer_projection_cursor(void)
{
    struct node_db *ndb = node_db_runtime();
    if (!ndb) return CATALOG_CURSOR_UNAVAILABLE;
    return (int64_t)node_db_sync_get_tip_height(ndb);
}

/* Shared by both anchor rows: activation-cursor semantics (see the file
 * header comment). `pool` is ANCHOR_POOL_SPROUT / ANCHOR_POOL_SAPLING. */
static int64_t cc_anchor_cursor(int pool)
{
    sqlite3 *db = progress_store_db();
    if (!db) return CATALOG_CURSOR_UNAVAILABLE;

    int64_t activation = 0;
    bool found = false;
    if (!anchor_kv_activation_cursor(db, pool, &activation, &found)) {
        LOG_WARN("catalog_completeness",
                 "anchor_kv_activation_cursor failed pool=%d", pool);
        return CATALOG_CURSOR_UNAVAILABLE;
    }
    if (!found) return CATALOG_CURSOR_UNAVAILABLE;    /* never adopted */
    if (activation > 0) return 0;                     /* known genesis gap */

    int32_t applied = -1;
    bool applied_found = false;
    if (!coins_kv_get_applied_height(db, &applied, &applied_found)) {
        LOG_WARN("catalog_completeness",
                 "coins applied cursor read failed for anchor pool=%d", pool);
        return CATALOG_CURSOR_UNAVAILABLE;
    }
    if (!applied_found)
        return CATALOG_CURSOR_UNAVAILABLE;
    return applied > 0 ? (int64_t)applied - 1 : 0;
}

static int64_t cc_get_sprout_anchor_cursor(void)
{
    return cc_anchor_cursor(ANCHOR_POOL_SPROUT);
}

static int64_t cc_get_sapling_anchor_cursor(void)
{
    return cc_anchor_cursor(ANCHOR_POOL_SAPLING);
}

static int64_t cc_get_nullifier_cursor(void)
{
    sqlite3 *db = progress_store_db();
    if (!db) return CATALOG_CURSOR_UNAVAILABLE;

    int64_t activation = 0;
    bool found = false;
    if (!nullifier_kv_activation_cursor(db, &activation, &found)) {
        LOG_WARN("catalog_completeness", "nullifier_kv_activation_cursor failed");
        return CATALOG_CURSOR_UNAVAILABLE;
    }
    if (!found) return CATALOG_CURSOR_UNAVAILABLE;
    if (activation > 0) return 0;

    int32_t applied = -1;
    bool applied_found = false;
    if (!coins_kv_get_applied_height(db, &applied, &applied_found)) {
        LOG_WARN("catalog_completeness",
                 "coins applied cursor read failed for nullifier history");
        return CATALOG_CURSOR_UNAVAILABLE;
    }
    if (!applied_found)
        return CATALOG_CURSOR_UNAVAILABLE;
    return applied > 0 ? (int64_t)applied - 1 : 0;
}

/* ── the static registry table — adding an index is one row + one
 * wrapper above ─────────────────────────────────────────────────────── */

struct catalog_index_entry {
    const char *name;
    int64_t (*get_cursor)(void);
    bool always_on;
    /* Does this row fold BLOCK BODIES forward from genesis? Only those are
     * floored by the snapshot seed: with no bodies below the seed height
     * there is nothing for them to read there, ever.
     *
     * The anchor/nullifier rows are false because they already encode their
     * own prefix gap through the activation-cursor convention documented at
     * the top of this file (a positive activation cursor makes them report
     * cursor=0, "nothing from genesis is proven complete"). Applying the
     * seed floor to them on top of that would credit them with coverage
     * their own convention deliberately refuses to claim. */
    bool body_folded;
};

static const struct catalog_index_entry g_catalog_indexes[] = {
    { "op_return_index",     cc_get_op_return_cursor,          true,  true  },
    { "address_index",       cc_get_address_index_cursor,      false, true  },
    { "txindex",             cc_get_txindex_cursor,            false, true  },
    { "zslp_ledger",         cc_get_zslp_ledger_cursor,        false, true  },
    { "sprout_anchor",       cc_get_sprout_anchor_cursor,       true, false },
    { "sapling_anchor",      cc_get_sapling_anchor_cursor,      true, false },
    { "nullifier_history",   cc_get_nullifier_cursor,          true, false },
    { "view_integrity",      cc_get_view_integrity_cursor,      true, true  },
    { "explorer_projection", cc_get_explorer_projection_cursor, true, true  },
};
#define CATALOG_INDEX_COUNT \
    (sizeof(g_catalog_indexes) / sizeof(g_catalog_indexes[0]))

/* ── public API ───────────────────────────────────────────────────────── */

const char *catalog_coverage_name(enum catalog_coverage c)
{
    switch (c) {
    case CATALOG_COVERAGE_UNKNOWN:  return "unknown";
    case CATALOG_COVERAGE_NONE:     return "none";
    case CATALOG_COVERAGE_PARTIAL:  return "partial";
    case CATALOG_COVERAGE_COMPLETE: return "complete";
    }
    return "(invalid)";
}

bool catalog_index_emptiness_is_meaningful(
    const struct catalog_index_status *row)
{
    return row && row->enabled &&
           row->coverage == (int)CATALOG_COVERAGE_COMPLETE;
}

/* The durable snapshot-seed base height, or 0 when this datadir has none
 * (a from-genesis node) and 0 on any read failure.
 *
 * Read ONCE per snapshot() rather than per row: it is a single durable
 * value, and re-reading it nine times would make a diagnostic nine times
 * more expensive for nine identical answers. Failure degrades to 0 — a
 * floor of 0 understates nothing and can only make coverage look WORSE
 * (the reachable range grows), so a read error can never manufacture a
 * false claim of completeness. */
static int64_t cc_seed_floor(void)
{
    sqlite3 *db = progress_store_db();
    if (!db) return 0;
    int32_t height = 0;
    bool found = false;
    if (!reducer_frontier_trusted_base_height_read(db, &height, &found)) {
        LOG_WARN("catalog_completeness",
                 "trusted-base height read failed — treating floor as 0 "
                 "(coverage can only read pessimistic, never optimistic)");
        return 0;
    }
    if (!found || height < 0) return 0;
    return (int64_t)height;
}

/* Coverage of [floor, target] given how far this index has folded.
 *
 * `cursor` is the highest height folded CONTIGUOUSLY from genesis, so a
 * cursor below the floor means the index has not yet reached the range
 * where bodies exist at all — none of the reachable range is covered. That
 * is the live case for zslp_ledger (cursor 2,881,792 against a floor of
 * 3,196,425): it looks like millions of blocks of progress and is in fact
 * zero coverage of anything readable. */
static enum catalog_coverage cc_coverage(int64_t cursor, int64_t floor,
                                         int64_t target)
{
    if (target < floor) {
        /* Nothing is reachable yet (the node has not passed its own seed).
         * Vacuously complete would be a lie dressed as a technicality:
         * report unknown rather than let a caller conclude anything. */
        return CATALOG_COVERAGE_UNKNOWN;
    }
    if (cursor >= target)  return CATALOG_COVERAGE_COMPLETE;
    if (cursor <  floor)   return CATALOG_COVERAGE_NONE;
    return CATALOG_COVERAGE_PARTIAL;
}

size_t catalog_completeness_snapshot(struct catalog_index_status *out,
                                     size_t max, int64_t target_height)
{
    if (!out || max == 0) {
        LOG_WARN("catalog_completeness",
                 "snapshot: no output buffer (out=%p max=%zu)",
                 (void *)out, max);
        return 0;
    }

    const int64_t seed_floor = cc_seed_floor();

    size_t n = CATALOG_INDEX_COUNT < max ? CATALOG_INDEX_COUNT : max;
    for (size_t i = 0; i < n; i++) {
        const struct catalog_index_entry *e = &g_catalog_indexes[i];
        struct catalog_index_status *row = &out[i];

        memset(row, 0, sizeof(*row));
        row->name = e->name;
        row->always_on = e->always_on;
        row->target = target_height;
        row->coverage = (int)CATALOG_COVERAGE_UNKNOWN;

        int64_t cursor = e->get_cursor();
        if (cursor == CATALOG_CURSOR_UNAVAILABLE) {
            row->enabled = false;
            row->cursor = 0;
            row->lag = 0;
            row->floor = 0;
            continue;
        }

        row->enabled = true;
        row->cursor = cursor;
        /* `lag` semantics are UNCHANGED on purpose. catalog_lag_exceeded
         * fires off this number, and quietly redefining it against the floor
         * would relax a live alarm's threshold under cover of a readability
         * change — the failure mode where an alarm stops firing and everyone
         * calls it an improvement. The new fields ADD truth; they move no
         * threshold. */
        int64_t lag = target_height - cursor;
        row->lag = lag > 0 ? lag : 0;
        row->floor = e->body_folded ? seed_floor : 0;
        row->coverage = (int)cc_coverage(cursor, row->floor, target_height);
    }
    return n;
}

int64_t catalog_completeness_worst_lag(const struct catalog_index_status *rows,
                                       size_t n)
{
    if (!rows) {
        LOG_WARN("catalog_completeness", "worst_lag: NULL rows (n=%zu)", n);
        return 0;
    }
    int64_t worst = 0;
    for (size_t i = 0; i < n; i++) {
        if (!rows[i].enabled) continue;
        if (rows[i].lag > worst) worst = rows[i].lag;
    }
    return worst;
}

const struct catalog_index_status *catalog_completeness_worst_over(
    const struct catalog_index_status *rows, size_t n, int64_t threshold)
{
    if (!rows) return NULL;
    const struct catalog_index_status *worst = NULL;
    for (size_t i = 0; i < n; i++) {
        if (!rows[i].enabled) continue;
        if (rows[i].lag <= threshold) continue;
        if (!worst || rows[i].lag > worst->lag) worst = &rows[i];
    }
    return worst;
}

enum catalog_verdict catalog_completeness_verdict(
    const struct catalog_index_status *rows, size_t n,
    int handshaked_peers, int peer_floor,
    int64_t census_age_s, int64_t census_max_age_s,
    char *out, size_t out_cap)
{
    /* BLOCKED dominates: an enabled index lagging at all (threshold 0) is the
     * primary omniscience deficit — a peer/census gap is secondary. */
    const struct catalog_index_status *lag =
        catalog_completeness_worst_over(rows, n, 0);
    if (lag) {
        if (out && out_cap)
            snprintf(out, out_cap, "blocked:%s@%lld",
                     lag->name ? lag->name : "?", (long long)lag->cursor);
        return CATALOG_VERDICT_BLOCKED;
    }
    if (handshaked_peers < peer_floor) {
        if (out && out_cap)
            snprintf(out, out_cap, "degraded:peers");
        return CATALOG_VERDICT_DEGRADED;
    }
    if (census_age_s < 0 || census_age_s > census_max_age_s) {
        if (out && out_cap)
            snprintf(out, out_cap, "degraded:census");
        return CATALOG_VERDICT_DEGRADED;
    }
    if (out && out_cap)
        snprintf(out, out_cap, "omniscient");
    return CATALOG_VERDICT_OMNISCIENT;
}
