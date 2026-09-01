/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Unit tests for catalog_completeness (engine/modules/storage/src/catalog_completeness.c)
 * — the read-only catalog reader that compares every chain-data index's
 * live cursor against a caller-supplied target height.
 *
 * Coverage:
 *   - lag math: cursor below/at/above target
 *   - the shielded activation-gap rows (sprout_anchor / sapling_anchor /
 *     nullifier_history) surface a KNOWN positive-activation-cursor gap as
 *     a strongly positive lag (cursor=0), and the co-committed reducer
 *     processing frontier once the store is genesis-complete, even when its
 *     last sparse state mutation is older
 *   - address_index reports enabled=false when -addressindex=0 is forced
 *     (it is ON by default now), never a crash
 *   - rows backed by app_runtime_node_db() (op_return_index,
 *     view_integrity, explorer_projection) degrade to enabled=false when
 *     no app runtime is wired in this test process
 *   - catalog_completeness_worst_lag: max-reduce over enabled rows only,
 *     synthetic arrays covering mixed/all-disabled/empty/NULL
 *   - catalog_completeness_snapshot defensive paths (NULL out, max==0,
 *     max < registered count truncates cleanly)
 */

#include "test/test_core.h"

#include "jobs/address_index.h"
#include "jobs/txindex_projection.h"
#include "sapling/incremental_merkle_tree.h"
#include "storage/anchor_kv.h"
#include "storage/catalog_completeness.h"
#include "storage/coins_kv.h"
#include "storage/nullifier_kv.h"
#include "storage/progress_store.h"
#include "util/util.h"

#include <errno.h>
#include <sqlite3.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define CC_CHECK(name, expr) do { \
    printf("  catalog_completeness: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)


static void cc_fill_hash(struct uint256 *h, uint8_t b)
{
    memset(h->data, b, 32);
}

static const struct catalog_index_status *
cc_find(const struct catalog_index_status *rows, size_t n, const char *name)
{
    for (size_t i = 0; i < n; i++)
        if (rows[i].name && strcmp(rows[i].name, name) == 0)
            return &rows[i];
    return NULL;
}

int test_catalog_completeness(void)
{
    printf("\n=== catalog_completeness tests ===\n");
    int failures = 0;

    /* address_index + txindex are both ON by default (omniscience). This test
     * exercises the DISABLED path explicitly (cursor unavailable -> excluded
     * from worst_lag), so force both off and reset the cached gates
     * deterministically. zslp_ledger degrades to disabled on its own here (no
     * app runtime / node.db wired in this bare test process, like
     * op_return_index). */
    {
        const char *offargs[] = { "test", "-addressindex=0", "-txindex=0" };
        ParseParameters(3, offargs);
        address_index_enabled_reset_for_test();
        txindex_projection_enabled_reset_for_test();
    }

    /* ── scenario A: from-genesis (activation_cursor=0) shielded stores
     * with real forward frontier rows, plus lag math above/at/below
     * target ─────────────────────────────────────────────────────────── */
    {
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "catalog_completeness", "genesis");
        CC_CHECK("scenario A: progress_store opens", progress_store_open(dir));
        sqlite3 *db = progress_store_db();
        CC_CHECK("scenario A: db handle non-NULL", db != NULL);

        CC_CHECK("scenario A: anchor schema", anchor_kv_ensure_schema(db));
        CC_CHECK("scenario A: nullifier schema",
                 nullifier_kv_ensure_schema(db));
        CC_CHECK("scenario A: anchor history from genesis",
                 anchor_kv_initialize_history(db, 0));
        CC_CHECK("scenario A: nullifier history from genesis",
                 nullifier_kv_initialize_history(db, 0));
        CC_CHECK("scenario A: coins schema", coins_kv_ensure_schema(db));
        CC_CHECK("scenario A: reducer processed through target",
                 coins_kv_set_applied_height_in_tx(db, 1001));
        CC_CHECK("scenario A: address_index schema",
                 address_index_ensure_schema(db));

        struct incremental_merkle_tree sprout;
        struct uint256 sprout_leaf;
        sprout_tree_init(&sprout);
        cc_fill_hash(&sprout_leaf, 0x31);
        incremental_tree_append(&sprout, &sprout_leaf);
        CC_CHECK("scenario A: sprout frontier @100",
                 anchor_kv_add_tree(db, ANCHOR_POOL_SPROUT, &sprout, 100));

        struct incremental_merkle_tree sapling;
        struct uint256 sapling_leaf;
        sapling_tree_init(&sapling);
        cc_fill_hash(&sapling_leaf, 0x41);
        incremental_tree_append(&sapling, &sapling_leaf);
        CC_CHECK("scenario A: sapling frontier @250",
                 anchor_kv_add_tree(db, ANCHOR_POOL_SAPLING, &sapling, 250));

        /* Sparse state rows are old, but the shared reducer processed every
         * block through 1000, so all three coverage cursors are current. */
        {
            struct catalog_index_status rows[CATALOG_COMPLETENESS_MAX_INDEXES];
            size_t n = catalog_completeness_snapshot(rows, CATALOG_COMPLETENESS_MAX_INDEXES,
                                                     1000);
            CC_CHECK("scenario A: snapshot row count == registered",
                     n > 0 && n <= CATALOG_COMPLETENESS_MAX_INDEXES);

            const struct catalog_index_status *sprout_row =
                cc_find(rows, n, "sprout_anchor");
            CC_CHECK("scenario A: sprout_anchor found + enabled",
                     sprout_row && sprout_row->enabled);
            CC_CHECK("scenario A: sparse sprout mutation processed @1000",
                     sprout_row && sprout_row->cursor == 1000);
            CC_CHECK("scenario A: sprout_anchor lag==0",
                     sprout_row && sprout_row->lag == 0);

            const struct catalog_index_status *sapling_row =
                cc_find(rows, n, "sapling_anchor");
            CC_CHECK("scenario A: sparse sapling mutation processed @1000",
                     sapling_row && sapling_row->cursor == 1000);
            CC_CHECK("scenario A: sapling_anchor lag==0",
                     sapling_row && sapling_row->lag == 0);

            /* Nullifiers share the same applied-through witness. */
            const struct catalog_index_status *nf_row =
                cc_find(rows, n, "nullifier_history");
            CC_CHECK("scenario A: nullifier_history processed @1000",
                     nf_row && nf_row->cursor == 1000);
            CC_CHECK("scenario A: nullifier_history lag==0",
                     nf_row && nf_row->lag == 0);

            /* address_index: forced -addressindex=0 -> disabled path. */
            const struct catalog_index_status *ai_row =
                cc_find(rows, n, "address_index");
            CC_CHECK("scenario A: address_index disabled (-addressindex=0)",
                     ai_row && !ai_row->enabled);
            CC_CHECK("scenario A: address_index disabled -> cursor=0 lag=0",
                     ai_row && ai_row->cursor == 0 && ai_row->lag == 0);
            CC_CHECK("scenario A: address_index always_on==false",
                     ai_row && !ai_row->always_on);

            /* txindex: forced -txindex=0 -> disabled path (excluded from lag). */
            const struct catalog_index_status *tx_row =
                cc_find(rows, n, "txindex");
            CC_CHECK("scenario A: txindex disabled (-txindex=0)",
                     tx_row && !tx_row->enabled);
            CC_CHECK("scenario A: txindex disabled -> cursor=0 lag=0",
                     tx_row && tx_row->cursor == 0 && tx_row->lag == 0);

            /* zslp_ledger: no app runtime / node.db -> disabled path. */
            const struct catalog_index_status *zslp_row =
                cc_find(rows, n, "zslp_ledger");
            CC_CHECK("scenario A: zslp_ledger disabled (no app runtime)",
                     zslp_row && !zslp_row->enabled);
            CC_CHECK("scenario A: zslp_ledger disabled -> cursor=0 lag=0",
                     zslp_row && zslp_row->cursor == 0 && zslp_row->lag == 0);

            /* no app runtime wired in this bare test process -> these
             * degrade gracefully instead of dereferencing a NULL node_db. */
            const struct catalog_index_status *or_row =
                cc_find(rows, n, "op_return_index");
            CC_CHECK("scenario A: op_return_index disabled (no app runtime)",
                     or_row && !or_row->enabled && or_row->cursor == 0 &&
                         or_row->lag == 0);
            const struct catalog_index_status *vi_row =
                cc_find(rows, n, "view_integrity");
            CC_CHECK("scenario A: view_integrity disabled (no app runtime)",
                     vi_row && !vi_row->enabled);
            const struct catalog_index_status *ep_row =
                cc_find(rows, n, "explorer_projection");
            CC_CHECK("scenario A: explorer_projection disabled (no app runtime)",
                     ep_row && !ep_row->enabled);

            CC_CHECK("scenario A: enabled shielded rows caught up",
                     catalog_completeness_worst_lag(rows, n) == 0);
        }

        /* Processing cursor above a smaller target clamps lag to zero. */
        {
            struct catalog_index_status rows[CATALOG_COMPLETENESS_MAX_INDEXES];
            size_t n = catalog_completeness_snapshot(rows, CATALOG_COMPLETENESS_MAX_INDEXES,
                                                     250);
            const struct catalog_index_status *sapling_row =
                cc_find(rows, n, "sapling_anchor");
            CC_CHECK("scenario A: at-target lag==0",
                     sapling_row && sapling_row->cursor == 1000 &&
                         sapling_row->lag == 0);
        }

        /* above target: cursor(250) > target(50) -> lag clamps to 0, never
         * negative. */
        {
            struct catalog_index_status rows[CATALOG_COMPLETENESS_MAX_INDEXES];
            size_t n = catalog_completeness_snapshot(rows, CATALOG_COMPLETENESS_MAX_INDEXES,
                                                     50);
            const struct catalog_index_status *sapling_row =
                cc_find(rows, n, "sapling_anchor");
            CC_CHECK("scenario A: above-target lag clamps to 0 (not negative)",
                     sapling_row && sapling_row->cursor == 1000 &&
                         sapling_row->lag == 0);
        }

        progress_store_close();
        test_cleanup_tmpdir(dir);
    }

    /* ── scenario B: a POSITIVE activation cursor — the permanent
     * anchor_backfill_gap / nullifier_backfill_gap wedge. The gap must
     * surface as a strongly positive lag (cursor=0), REGARDLESS of the
     * target height, matching the node's existing gap semantics. ────── */
    {
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "catalog_completeness", "gap");
        CC_CHECK("scenario B: progress_store opens", progress_store_open(dir));
        sqlite3 *db = progress_store_db();

        CC_CHECK("scenario B: anchor schema", anchor_kv_ensure_schema(db));
        CC_CHECK("scenario B: nullifier schema",
                 nullifier_kv_ensure_schema(db));
        CC_CHECK("scenario B: anchor history ABOVE genesis (known gap)",
                 anchor_kv_initialize_history(db, 500000));
        CC_CHECK("scenario B: nullifier history ABOVE genesis (known gap)",
                 nullifier_kv_initialize_history(db, 500000));

        struct catalog_index_status rows[CATALOG_COMPLETENESS_MAX_INDEXES];
        size_t n = catalog_completeness_snapshot(rows, CATALOG_COMPLETENESS_MAX_INDEXES,
                                                 1000);

        const struct catalog_index_status *sprout_row =
            cc_find(rows, n, "sprout_anchor");
        CC_CHECK("scenario B: sprout_anchor cursor==0 (gap surfaced)",
                 sprout_row && sprout_row->enabled && sprout_row->cursor == 0);
        CC_CHECK("scenario B: sprout_anchor lag==target (harshest honest lag)",
                 sprout_row && sprout_row->lag == 1000);

        const struct catalog_index_status *sapling_row =
            cc_find(rows, n, "sapling_anchor");
        CC_CHECK("scenario B: sapling_anchor cursor==0 (gap surfaced)",
                 sapling_row && sapling_row->cursor == 0);
        CC_CHECK("scenario B: sapling_anchor lag==target",
                 sapling_row && sapling_row->lag == 1000);

        const struct catalog_index_status *nf_row =
            cc_find(rows, n, "nullifier_history");
        CC_CHECK("scenario B: nullifier_history cursor==0 (gap surfaced)",
                 nf_row && nf_row->cursor == 0 && nf_row->lag == 1000);

        CC_CHECK("scenario B: worst_lag == 1000 (the wedge dominates)",
                 catalog_completeness_worst_lag(rows, n) == 1000);

        progress_store_close();
        test_cleanup_tmpdir(dir);
    }

    /* ── catalog_completeness_worst_lag: synthetic arrays, no real
     * subsystem involved ─────────────────────────────────────────────── */
    {
        struct catalog_index_status rows[4];
        memset(rows, 0, sizeof(rows));
        rows[0] = (struct catalog_index_status){
            .name = "a", .cursor = 10, .target = 100, .lag = 90,
            .always_on = true, .enabled = true};
        rows[1] = (struct catalog_index_status){
            .name = "b", .cursor = 95, .target = 100, .lag = 5,
            .always_on = true, .enabled = true};
        rows[2] = (struct catalog_index_status){
            .name = "c", .cursor = 0, .target = 100, .lag = 999999,
            .always_on = false, .enabled = false};    /* disabled: skipped */
        rows[3] = (struct catalog_index_status){
            .name = "d", .cursor = 100, .target = 100, .lag = 0,
            .always_on = true, .enabled = true};

        CC_CHECK("worst_lag: mixed enabled/disabled picks max ENABLED lag",
                 catalog_completeness_worst_lag(rows, 4) == 90);
        CC_CHECK("worst_lag: disabled row (lag=999999) never wins",
                 catalog_completeness_worst_lag(rows, 4) != 999999);

        struct catalog_index_status all_disabled[2];
        memset(all_disabled, 0, sizeof(all_disabled));
        all_disabled[0].name = "x";
        all_disabled[0].lag = 500;
        all_disabled[0].enabled = false;
        all_disabled[1].name = "y";
        all_disabled[1].lag = 700;
        all_disabled[1].enabled = false;
        CC_CHECK("worst_lag: all-disabled array -> 0",
                 catalog_completeness_worst_lag(all_disabled, 2) == 0);

        CC_CHECK("worst_lag: n==0 -> 0", catalog_completeness_worst_lag(rows, 0) == 0);
        CC_CHECK("worst_lag: NULL rows -> 0",
                 catalog_completeness_worst_lag(NULL, 4) == 0);
    }

    /* ── catalog_completeness_snapshot defensive paths ───────────────── */
    {
        struct catalog_index_status rows[CATALOG_COMPLETENESS_MAX_INDEXES];
        CC_CHECK("snapshot: NULL out -> 0",
                 catalog_completeness_snapshot(NULL, CATALOG_COMPLETENESS_MAX_INDEXES,
                                               100) == 0);
        CC_CHECK("snapshot: max==0 -> 0",
                 catalog_completeness_snapshot(rows, 0, 100) == 0);

        /* max smaller than the registered count truncates cleanly, never
         * overflows the caller's buffer. */
        struct catalog_index_status two[2];
        size_t n2 = catalog_completeness_snapshot(two, 2, 100);
        CC_CHECK("snapshot: max<registered truncates to exactly max",
                 n2 == 2);
    }

    /* ── catalog_completeness_worst_over: pure "which index is over the
     * threshold" selector ────────────────────────────────────────────── */
    {
        struct catalog_index_status rows[4];
        memset(rows, 0, sizeof(rows));
        rows[0] = (struct catalog_index_status){
            .name = "a", .cursor = 10, .target = 5000, .lag = 4990,
            .enabled = true};
        rows[1] = (struct catalog_index_status){
            .name = "b", .cursor = 4999, .target = 5000, .lag = 1,
            .enabled = true};                        /* under threshold */
        rows[2] = (struct catalog_index_status){
            .name = "c", .cursor = 0, .target = 5000, .lag = 5000,
            .enabled = false};                       /* disabled: skipped */
        rows[3] = (struct catalog_index_status){
            .name = "d", .cursor = 3000, .target = 5000, .lag = 2000,
            .enabled = true};

        const struct catalog_index_status *w =
            catalog_completeness_worst_over(rows, 4, 1000);
        CC_CHECK("worst_over: picks max ENABLED lag over threshold ('a')",
                 w && w->name && strcmp(w->name, "a") == 0);
        CC_CHECK("worst_over: disabled row never wins",
                 catalog_completeness_worst_over(rows, 4, 1000) != &rows[2]);
        CC_CHECK("worst_over: threshold above all enabled -> NULL",
                 catalog_completeness_worst_over(rows, 4, 100000) == NULL);
        CC_CHECK("worst_over: NULL rows -> NULL",
                 catalog_completeness_worst_over(NULL, 4, 0) == NULL);
    }

    /* ── catalog_completeness_verdict: the omniscience classifier ─────── */
    {
        struct catalog_index_status caught_up[2];
        memset(caught_up, 0, sizeof(caught_up));
        caught_up[0] = (struct catalog_index_status){
            .name = "x", .cursor = 100, .target = 100, .lag = 0,
            .enabled = true};
        caught_up[1] = (struct catalog_index_status){
            .name = "y", .cursor = 0, .target = 100, .lag = 999,
            .enabled = false};                        /* disabled: ignored */

        char v[96];
        /* omniscient: all enabled caught up, peers >= floor, census fresh. */
        enum catalog_verdict r =
            catalog_completeness_verdict(caught_up, 2, /*peers*/3, /*floor*/3,
                                         /*census_age*/30, /*max*/900, v,
                                         sizeof(v));
        CC_CHECK("verdict: all caught up + peers ok + census fresh -> omniscient",
                 r == CATALOG_VERDICT_OMNISCIENT && strcmp(v, "omniscient") == 0);

        /* blocked dominates even when peers/census are also bad. */
        struct catalog_index_status lag_rows[1];
        memset(lag_rows, 0, sizeof(lag_rows));
        lag_rows[0] = (struct catalog_index_status){
            .name = "txindex", .cursor = 4200, .target = 5000, .lag = 800,
            .enabled = true};
        r = catalog_completeness_verdict(lag_rows, 1, /*peers*/0, /*floor*/3,
                                         /*census_age*/-1, /*max*/900, v,
                                         sizeof(v));
        CC_CHECK("verdict: lagging index -> blocked:<name>@<cursor> (dominates)",
                 r == CATALOG_VERDICT_BLOCKED &&
                     strcmp(v, "blocked:txindex@4200") == 0);

        /* degraded:peers when caught up but below the peer floor. */
        r = catalog_completeness_verdict(caught_up, 2, /*peers*/1, /*floor*/3,
                                         /*census_age*/30, /*max*/900, v,
                                         sizeof(v));
        CC_CHECK("verdict: peers below floor -> degraded:peers",
                 r == CATALOG_VERDICT_DEGRADED &&
                     strcmp(v, "degraded:peers") == 0);

        /* degraded:census when there has been no sweep yet (age < 0). */
        r = catalog_completeness_verdict(caught_up, 2, /*peers*/3, /*floor*/3,
                                         /*census_age*/-1, /*max*/900, v,
                                         sizeof(v));
        CC_CHECK("verdict: no census sweep (age<0) -> degraded:census",
                 r == CATALOG_VERDICT_DEGRADED &&
                     strcmp(v, "degraded:census") == 0);

        /* degraded:census when the last sweep is older than the bound. */
        r = catalog_completeness_verdict(caught_up, 2, /*peers*/3, /*floor*/3,
                                         /*census_age*/2000, /*max*/900, v,
                                         sizeof(v));
        CC_CHECK("verdict: stale census (age>max) -> degraded:census",
                 r == CATALOG_VERDICT_DEGRADED &&
                     strcmp(v, "degraded:census") == 0);

        /* NULL out buffer tolerated (enum still returned). */
        r = catalog_completeness_verdict(caught_up, 2, 3, 3, 30, 900, NULL, 0);
        CC_CHECK("verdict: NULL out buffer -> still classifies omniscient",
                 r == CATALOG_VERDICT_OMNISCIENT);
    }

    printf("catalog_completeness: %d failures\n", failures);
    return failures;
}
