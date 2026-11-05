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
#include "jobs/reducer_frontier.h"
#include "models/database.h"
#include "models/op_return_index.h"
#include "models/zslp_ledger.h"
#include "storage/node_db_runtime.h"
#include "storage/progress_store.h"
#include "storage/projection_store.h"
#include "util/util.h"

#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <sqlite3.h>
#include <stdatomic.h>
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

/* Scenario A: fetch the db handle and seed the shielded, coins and
 * address_index stores only (schemas, from-genesis histories, reducer
 * height, anchor frontiers). Other catalog rows (txindex, op_return, ...)
 * are not seeded here; they degrade or stay at their default state. */
static int cc_seed_genesis_store(void)
{
    int failures = 0;
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

    return failures;
}

/* Scenario A, target 1000: the shielded anchor/nullifier rows are current
 * (processed through the target, lag==0). */
static int cc_check_genesis_shielded_rows_current(
    const struct catalog_index_status *rows, size_t n)
{
    int failures = 0;

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

    return failures;
}

/* Scenario A, target 1000: address_index and txindex, forced off with
 * flags, take the disabled path. */
static int cc_check_genesis_flag_gated_rows_disabled(
    const struct catalog_index_status *rows, size_t n)
{
    int failures = 0;

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

    return failures;
}

/* Scenario A, target 1000: rows that need an app runtime / node.db
 * degrade to the disabled path in this bare test process. */
static int cc_check_genesis_app_runtime_rows_disabled(
    const struct catalog_index_status *rows, size_t n)
{
    int failures = 0;

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

    return failures;
}

/* Scenario A: a processing cursor at or above the target clamps lag to
 * zero, never negative. */
static int cc_check_genesis_lag_clamping(void)
{
    int failures = 0;

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

    return failures;
}

/* ── scenario A: from-genesis (activation_cursor=0) shielded stores
 * with real forward frontier rows, plus lag math above/at/below
 * target ─────────────────────────────────────────────────────────── */
static int cc_scenario_genesis(void)
{
    int failures = 0;
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "catalog_completeness", "genesis");
    CC_CHECK("scenario A: progress_store opens", progress_store_open(dir));
    failures += cc_seed_genesis_store();

    /* Sparse state rows are old, but the shared reducer processed every
     * block through 1000, so all three coverage cursors are current. */
    {
        struct catalog_index_status rows[CATALOG_COMPLETENESS_MAX_INDEXES];
        size_t n = catalog_completeness_snapshot(rows, CATALOG_COMPLETENESS_MAX_INDEXES,
                                                 1000);
        CC_CHECK("scenario A: snapshot row count == registered",
                 n > 0 && n <= CATALOG_COMPLETENESS_MAX_INDEXES);

        failures += cc_check_genesis_shielded_rows_current(rows, n);
        failures += cc_check_genesis_flag_gated_rows_disabled(rows, n);
        failures += cc_check_genesis_app_runtime_rows_disabled(rows, n);

        CC_CHECK("scenario A: enabled shielded rows caught up",
                 catalog_completeness_worst_lag(rows, n) == 0);
    }

    failures += cc_check_genesis_lag_clamping();

    progress_store_close();
    test_cleanup_tmpdir(dir);
    return failures;
}

/* ── scenario B: a POSITIVE activation cursor — the permanent
 * anchor_backfill_gap / nullifier_backfill_gap wedge. The gap must
 * surface as a strongly positive lag (cursor=0), REGARDLESS of the
 * target height, matching the node's existing gap semantics. ────── */
static int cc_scenario_positive_activation_gap(void)
{
    int failures = 0;
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

    /* cursor==0 here says "nothing from genesis is proven complete", so the
     * coverage is NONE, not PARTIAL. */
    CC_CHECK("scenario B: sprout_anchor gap covers NONE",
             sprout_row && sprout_row->coverage == (int)CATALOG_COVERAGE_NONE);
    CC_CHECK("scenario B: sapling_anchor gap covers NONE",
             sapling_row &&
             sapling_row->coverage == (int)CATALOG_COVERAGE_NONE);
    CC_CHECK("scenario B: nullifier_history gap covers NONE",
             nf_row && nf_row->coverage == (int)CATALOG_COVERAGE_NONE);

    CC_CHECK("scenario B: worst_lag == 1000 (the wedge dominates)",
             catalog_completeness_worst_lag(rows, n) == 1000);

    progress_store_close();
    test_cleanup_tmpdir(dir);
    return failures;
}

/* ── catalog_completeness_worst_lag: synthetic arrays, no real
 * subsystem involved ─────────────────────────────────────────────── */
static int cc_worst_lag_synthetic_arrays(void)
{
    int failures = 0;

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
    return failures;
}

/* ── catalog_completeness_snapshot defensive paths ───────────────── */
static int cc_snapshot_defensive_paths(void)
{
    int failures = 0;

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
    return failures;
}

/* ── catalog_completeness_worst_over: pure "which index is over the
 * threshold" selector ────────────────────────────────────────────── */
static int cc_worst_over_threshold_selector(void)
{
    int failures = 0;

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
    return failures;
}

/* ── catalog_completeness_verdict: the omniscience classifier ─────── */
static int cc_verdict_classification(void)
{
    int failures = 0;

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
    return failures;
}

/* ── mutation-gap closers: cursor wrappers, seed floor, coverage, table
 * flags, snapshot_try contention, verdict boundaries ─────────────────── */

#define CC_NO_COV (-1)

static struct node_db *g_cc_port_ndb;

static struct node_db *cc_port_handle(void)
{
    return g_cc_port_ndb;
}

static const struct node_db_runtime_port g_cc_port = {
    .handle = cc_port_handle,
};

static bool cc_exec(sqlite3 *db, const char *sql)
{
    return db && sqlite3_exec(db, sql, NULL, NULL, NULL) == SQLITE_OK;
}

static bool cc_seed_trusted_floor(int32_t h)
{
    sqlite3 *db = progress_store_db();
    uint8_t b[8];
    uint64_t v = (uint64_t)h;
    for (int i = 0; i < 8; i++)
        b[i] = (uint8_t)(v >> (8 * i));
    return db && progress_meta_table_ensure(db) &&
           progress_meta_set(db, REDUCER_TRUSTED_BASE_HEIGHT_KEY, b, 8);
}

static struct catalog_index_status cc_snap_one(const char *name, int64_t target)
{
    struct catalog_index_status rows[CATALOG_COMPLETENESS_MAX_INDEXES];
    size_t n = catalog_completeness_snapshot(
        rows, CATALOG_COMPLETENESS_MAX_INDEXES, target);
    const struct catalog_index_status *r = cc_find(rows, n, name);
    struct catalog_index_status out;
    memset(&out, 0, sizeof(out));
    if (r) out = *r;
    return out;
}

static int cc_check_row(const char *label, const struct catalog_index_status *r,
                        bool enabled, int64_t cursor, int64_t lag,
                        int64_t floor, int cov)
{
    int failures = 0;
    bool ok = r && r->name && r->enabled == enabled && r->cursor == cursor &&
              r->lag == lag && r->floor == floor &&
              (cov == CC_NO_COV || r->coverage == cov);
    CC_CHECK(label, ok);
    if (!ok && r)
        printf("    got enabled=%d cursor=%lld lag=%lld floor=%lld cov=%d\n",
               r->enabled ? 1 : 0, (long long)r->cursor, (long long)r->lag,
               (long long)r->floor, r->coverage);
    return failures;
}

static int cc_expect_unavail(const char *label, const char *name)
{
    struct catalog_index_status r = cc_snap_one(name, 1000);
    return cc_check_row(label, &r, false, 0, 0, 0,
                        (int)CATALOG_COVERAGE_UNKNOWN);
}

static int cc_expect_cursor(const char *label, const char *name,
                            int64_t cursor)
{
    struct catalog_index_status r = cc_snap_one(name, 1000);
    int64_t lag = cursor < 1000 ? 1000 - cursor : 0;
    return cc_check_row(label, &r, true, cursor, lag, 0, CC_NO_COV);
}

static bool cc_open_ndb(struct node_db *ndb)
{
    memset(ndb, 0, sizeof(*ndb));
    if (!node_db_open(ndb, ":memory:") || !ndb->open) {
        node_db_close(ndb);
        return false;
    }
    return true;
}

static bool cc_seed_ndb_rows(struct node_db *ndb)
{
    struct op_return_index_cursor cur;
    memset(&cur, 0, sizeof(cur));
    cur.base_height = 0;
    cur.height = 300;
    uint8_t dg[32];
    memset(dg, 0x5A, sizeof(dg));
    return op_return_index_set_cursor(ndb, &cur) &&
           zslp_ledger_set_cursor(ndb, 420, dg) &&
           cc_exec(ndb->db, "INSERT INTO view_integrity(height,sha3_hash) "
                            "VALUES(500, zeroblob(32))") &&
           node_db_state_set_int(ndb, "sync_projection_tip_height", 640);
}

/* The registry's always_on flag per row, visible even on disabled rows. */
static int cc_check_always_on_flags(void)
{
    static const struct { const char *name; bool always_on; } want[] = {
        { "op_return_index", true },   { "address_index", false },
        { "txindex", false },          { "zslp_ledger", false },
        { "sprout_anchor", true },     { "sapling_anchor", true },
        { "nullifier_history", true }, { "view_integrity", true },
        { "explorer_projection", true },
    };
    int failures = 0;
    struct catalog_index_status rows[CATALOG_COMPLETENESS_MAX_INDEXES];
    size_t n = catalog_completeness_snapshot(
        rows, CATALOG_COMPLETENESS_MAX_INDEXES, 1000);
    CC_CHECK("registry has exactly the nine named rows", n == 9);
    for (size_t i = 0; i < sizeof(want) / sizeof(want[0]); i++) {
        const struct catalog_index_status *r = cc_find(rows, n, want[i].name);
        char label[96];
        snprintf(label, sizeof(label), "always_on(%s) == %d", want[i].name,
                 want[i].always_on ? 1 : 0);
        CC_CHECK(label, r && r->always_on == want[i].always_on);
    }
    return failures;
}

/* node.db-backed rows with a seeded floor of 600: each cursor is distinct,
 * so a wrapper returning the wrong value or the wrong row fails. */
static int cc_check_ndb_rows_seeded(void)
{
    int failures = 0;
    const int none = (int)CATALOG_COVERAGE_NONE;
    struct catalog_index_status r;
    r = cc_snap_one("op_return_index", 1000);
    failures += cc_check_row("ndb row: op_return_index @300, floor 600",
                             &r, true, 300, 700, 600, none);
    r = cc_snap_one("zslp_ledger", 1000);
    failures += cc_check_row("ndb row: zslp_ledger @420, floor 600",
                             &r, true, 420, 580, 600, none);
    r = cc_snap_one("view_integrity", 1000);
    failures += cc_check_row("ndb row: view_integrity @500, floor 600",
                             &r, true, 500, 500, 600, none);
    r = cc_snap_one("explorer_projection", 1000);
    failures += cc_check_row("ndb row: explorer_projection @640, floor 600",
                             &r, true, 640, 360, 600,
                             (int)CATALOG_COVERAGE_PARTIAL);
    r = cc_snap_one("address_index", 1000);
    failures += cc_check_row("ndb row: address_index disabled, floor 0",
                             &r, false, 0, 0, 0,
                             (int)CATALOG_COVERAGE_UNKNOWN);
    r = cc_snap_one("txindex", 1000);
    failures += cc_check_row("ndb row: txindex disabled, floor 0",
                             &r, false, 0, 0, 0,
                             (int)CATALOG_COVERAGE_UNKNOWN);
    r = cc_snap_one("sprout_anchor", 1000);
    failures += cc_check_row("ndb row: sprout_anchor unavailable, floor 0",
                             &r, false, 0, 0, 0,
                             (int)CATALOG_COVERAGE_UNKNOWN);
    return failures;
}

/* Coverage boundaries on the explorer row (floor 600): cursor == target is
 * complete, cursor == floor is partial, one below the floor is none, and a
 * target at the floor is still a real range. */
static int cc_explorer_coverage_sweep(struct node_db *ndb)
{
    static const struct { int64_t tip, target, lag; int cov; } cases[] = {
        { 1000, 1000, 0,   CATALOG_COVERAGE_COMPLETE },
        { 1200, 1000, 0,   CATALOG_COVERAGE_COMPLETE },
        { 999,  1000, 1,   CATALOG_COVERAGE_PARTIAL },
        { 600,  1000, 400, CATALOG_COVERAGE_PARTIAL },
        { 599,  1000, 401, CATALOG_COVERAGE_NONE },
        { 600,  600,  0,   CATALOG_COVERAGE_COMPLETE },
        { 550,  599,  49,  CATALOG_COVERAGE_UNKNOWN },
    };
    int failures = 0;
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        char label[96];
        snprintf(label, sizeof(label), "explorer coverage tip=%lld target=%lld",
                 (long long)cases[i].tip, (long long)cases[i].target);
        bool set = node_db_state_set_int(ndb, "sync_projection_tip_height",
                                         cases[i].tip);
        struct catalog_index_status r =
            cc_snap_one("explorer_projection", cases[i].target);
        CC_CHECK("explorer sweep: tip stored", set);
        failures += cc_check_row(label, &r, true, cases[i].tip, cases[i].lag,
                                 600, (int)cases[i].cov);
    }
    CC_CHECK("explorer sweep: tip restored to 640",
             node_db_state_set_int(ndb, "sync_projection_tip_height", 640));
    return failures;
}

static int cc_ndb_floor_variants(void)
{
    int failures = 0;
    sqlite3 *db = progress_store_db();
    /* A malformed trusted-base record fails the read: the floor degrades to
     * 0 (pessimistic), never to a made-up value. */
    CC_CHECK("floor: malformed trusted-base record stored",
             db && progress_meta_set(db, REDUCER_TRUSTED_BASE_HEIGHT_KEY,
                                     "abc", 3));
    struct catalog_index_status r = cc_snap_one("explorer_projection", 1000);
    failures += cc_check_row("floor: malformed record reads as floor 0",
                             &r, true, 640, 360, 0,
                             (int)CATALOG_COVERAGE_PARTIAL);
    /* Absent record: also floor 0. */
    CC_CHECK("floor: record deleted",
             db && progress_meta_delete(db, REDUCER_TRUSTED_BASE_HEIGHT_KEY));
    r = cc_snap_one("explorer_projection", 1000);
    failures += cc_check_row("floor: absent record reads as floor 0",
                             &r, true, 640, 360, 0,
                             (int)CATALOG_COVERAGE_PARTIAL);
    return failures;
}

static int cc_ndb_rows_body(struct node_db *ndb)
{
    int failures = 0;
    g_cc_port_ndb = ndb;
    node_db_runtime_port_set(&g_cc_port);
    CC_CHECK("ndb rows: cursors seeded", cc_seed_ndb_rows(ndb));

    failures += cc_check_always_on_flags();
    CC_CHECK("ndb rows: trusted floor 600 seeded", cc_seed_trusted_floor(600));
    failures += cc_check_ndb_rows_seeded();
    failures += cc_explorer_coverage_sweep(ndb);
    failures += cc_ndb_floor_variants();

    /* With the progress store closed the floor and every anchor row are
     * unavailable: a closed store never manufactures coverage. */
    progress_store_close();
    struct catalog_index_status r = cc_snap_one("explorer_projection", 1000);
    failures += cc_check_row("closed progress store: floor 0", &r, true, 640,
                             360, 0, (int)CATALOG_COVERAGE_PARTIAL);
    failures += cc_expect_unavail("closed progress store: sprout unavailable",
                                  "sprout_anchor");
    failures += cc_expect_unavail("closed progress store: sapling unavailable",
                                  "sapling_anchor");
    failures += cc_expect_unavail("closed progress store: nullifier unavailable",
                                  "nullifier_history");

    node_db_runtime_port_set(NULL);
    g_cc_port_ndb = NULL;
    return failures;
}

static int cc_scenario_node_db_rows(void)
{
    int failures = 0;
    char dir[256];
    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));
    test_make_tmpdir(dir, sizeof(dir), "catalog_completeness", "ndb_rows");
    bool ready = progress_store_open(dir) && cc_open_ndb(&ndb);
    CC_CHECK("ndb rows: fixture ready", ready);
    if (ready)
        failures += cc_ndb_rows_body(&ndb);
    if (ndb.open) node_db_close(&ndb);
    if (progress_store_db()) progress_store_close();
    test_cleanup_tmpdir(dir);
    return failures;
}

/* A persisted v1 op_return cursor is refused: the row is unavailable, not a
 * made-up cursor. An unopened handle makes the zslp row unavailable too. */
static int cc_scenario_refused_and_unusable_handles(void)
{
    int failures = 0;
    struct node_db ndb;
    uint8_t digest[32];
    memset(digest, 0x3C, sizeof(digest));
    bool ready = cc_open_ndb(&ndb);
    CC_CHECK("refused: ndb opens", ready);
    if (ready) {
        g_cc_port_ndb = &ndb;
        node_db_runtime_port_set(&g_cc_port);
        CC_CHECK("refused: legacy v1 op_return state written",
                 node_db_state_set_int(&ndb, "op_return_index_cursor_height",
                                       1234) &&
                 node_db_state_set(&ndb, "op_return_index_digest", digest,
                                   sizeof(digest)));
        failures += cc_expect_unavail("refused: legacy v1 op_return_index "
                                      "is unavailable", "op_return_index");
        node_db_runtime_port_set(NULL);
        g_cc_port_ndb = NULL;
    }
    if (ndb.open) node_db_close(&ndb);

    struct node_db dead;
    memset(&dead, 0, sizeof(dead));
    g_cc_port_ndb = &dead;
    node_db_runtime_port_set(&g_cc_port);
    failures += cc_expect_unavail("unusable handle: zslp_ledger unavailable",
                                  "zslp_ledger");
    failures += cc_expect_unavail("unusable handle: op_return_index "
                                  "unavailable", "op_return_index");
    node_db_runtime_port_set(NULL);
    g_cc_port_ndb = NULL;
    return failures;
}

/* ── shielded activation-cursor rows ─────────────────────────────── */

static bool cc_seed_anchor_store(sqlite3 *db)
{
    return cc_seed_trusted_floor(600) && anchor_kv_ensure_schema(db) &&
           anchor_kv_initialize_history(db, 0) &&
           coins_kv_ensure_schema(db) &&
           coins_kv_set_applied_height_in_tx(db, 1001) &&
           cc_exec(db, "UPDATE anchor_state SET activation_cursor=7 "
                       "WHERE pool=0");
}

static int cc_anchor_step_applied_sweep(sqlite3 *db)
{
    static const struct { int32_t applied; int64_t cursor; } cases[] = {
        { 0, 0 }, { 1, 0 }, { 2, 1 }, { 1001, 1000 },
    };
    int failures = 0;
    CC_CHECK("anchor: nullifier history adopted from genesis",
             nullifier_kv_ensure_schema(db) &&
             nullifier_kv_initialize_history(db, 0));
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        char label[96];
        CC_CHECK("anchor: applied height stored",
                 coins_kv_set_applied_height_in_tx(db, cases[i].applied));
        snprintf(label, sizeof(label), "anchor: sapling applied=%d -> cursor %lld",
                 (int)cases[i].applied, (long long)cases[i].cursor);
        failures += cc_expect_cursor(label, "sapling_anchor", cases[i].cursor);
        snprintf(label, sizeof(label),
                 "anchor: nullifier applied=%d -> cursor %lld",
                 (int)cases[i].applied, (long long)cases[i].cursor);
        failures += cc_expect_cursor(label, "nullifier_history",
                                     cases[i].cursor);
    }
    return failures;
}

static int cc_anchor_step_unreadable_applied(sqlite3 *db)
{
    int failures = 0;
    CC_CHECK("anchor: malformed applied height stored",
             progress_meta_set(db, COINS_APPLIED_HEIGHT_KEY, "abc", 3));
    failures += cc_expect_unavail("anchor: unreadable applied -> sapling "
                                  "unavailable", "sapling_anchor");
    failures += cc_expect_unavail("anchor: unreadable applied -> nullifier "
                                  "unavailable", "nullifier_history");
    CC_CHECK("anchor: applied height deleted",
             progress_meta_delete(db, COINS_APPLIED_HEIGHT_KEY));
    failures += cc_expect_unavail("anchor: absent applied -> sapling "
                                  "unavailable", "sapling_anchor");
    failures += cc_expect_unavail("anchor: absent applied -> nullifier "
                                  "unavailable", "nullifier_history");
    CC_CHECK("anchor: applied height restored",
             coins_kv_set_applied_height_in_tx(db, 1001));
    return failures;
}

static int cc_anchor_step_broken_activation(sqlite3 *db)
{
    int failures = 0;
    CC_CHECK("anchor: malformed nullifier activation stored",
             progress_meta_set(db, "nullifier_kv.activation_cursor", "x", 1));
    failures += cc_expect_unavail("anchor: malformed nullifier activation "
                                  "unavailable", "nullifier_history");
    CC_CHECK("anchor: nullifier activation deleted",
             progress_meta_delete(db, "nullifier_kv.activation_cursor"));
    failures += cc_expect_unavail("anchor: absent nullifier activation "
                                  "unavailable", "nullifier_history");
    CC_CHECK("anchor: anchor_state table dropped",
             cc_exec(db, "DROP TABLE anchor_state"));
    failures += cc_expect_unavail("anchor: missing anchor_state -> sprout "
                                  "unavailable", "sprout_anchor");
    failures += cc_expect_unavail("anchor: missing anchor_state -> sapling "
                                  "unavailable", "sapling_anchor");
    return failures;
}

/* Sprout carries a known gap (cursor 0), sapling is genesis-complete
 * (applied-1) and the nullifier store was never adopted (unavailable): three
 * different answers, so a swapped progress-cursor index is visible. */
static int cc_scenario_activation_rows(void)
{
    int failures = 0;
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "catalog_completeness", "activation");
    bool opened = progress_store_open(dir);
    sqlite3 *db = opened ? progress_store_db() : NULL;
    CC_CHECK("activation rows: store opens and seeds",
             db && cc_seed_anchor_store(db));
    if (db) {
        failures += cc_expect_cursor("activation: sprout gap -> cursor 0, "
                                     "floor stays 0", "sprout_anchor", 0);
        failures += cc_expect_cursor("activation: sapling genesis -> applied-1",
                                     "sapling_anchor", 1000);
        failures += cc_expect_unavail("activation: nullifier never adopted",
                                      "nullifier_history");
        failures += cc_anchor_step_applied_sweep(db);
        failures += cc_anchor_step_unreadable_applied(db);
        failures += cc_anchor_step_broken_activation(db);
    }
    if (progress_store_db()) progress_store_close();
    test_cleanup_tmpdir(dir);
    return failures;
}

/* ── address_index / txindex rows on the projection handle ────────── */

static void cc_set_index_flags(bool on)
{
    const char *on_args[] = { "test", "-addressindex=1", "-txindex=1" };
    const char *off_args[] = { "test", "-addressindex=0", "-txindex=0" };
    ParseParameters(3, on ? on_args : off_args);
    address_index_enabled_reset_for_test();
    txindex_projection_enabled_reset_for_test();
}

static int cc_projection_rows_body(void)
{
    int failures = 0;
    sqlite3 *pdb = projection_store_db();
    uint8_t dg[32];
    memset(dg, 0x6B, sizeof(dg));
    CC_CHECK("projection rows: schemas and cursors seeded",
             pdb && address_index_ensure_schema(pdb) &&
             txindex_projection_ensure_schema(pdb) &&
             address_index_set_cursor(pdb, 700, dg) &&
             txindex_projection_set_cursor(pdb, 800, dg) &&
             cc_seed_trusted_floor(600));

    struct catalog_index_status r = cc_snap_one("address_index", 1000);
    failures += cc_check_row("projection rows: address_index @700, floor 600",
                             &r, true, 700, 300, 600,
                             (int)CATALOG_COVERAGE_PARTIAL);
    CC_CHECK("projection rows: address_index opt-in, not always_on",
             !r.always_on);
    r = cc_snap_one("txindex", 1000);
    failures += cc_check_row("projection rows: txindex @800, floor 600",
                             &r, true, 800, 200, 600,
                             (int)CATALOG_COVERAGE_PARTIAL);
    CC_CHECK("projection rows: txindex opt-in, not always_on", !r.always_on);

    /* Without a projection handle both rows are unavailable, not cursor 0
     * or 1. */
    projection_store_close();
    failures += cc_expect_unavail("projection rows: no handle -> "
                                  "address_index unavailable", "address_index");
    failures += cc_expect_unavail("projection rows: no handle -> txindex "
                                  "unavailable", "txindex");
    return failures;
}

static int cc_scenario_projection_rows(void)
{
    int failures = 0;
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "catalog_completeness", "projection");
    bool ready = progress_store_open(dir) && projection_store_open(dir);
    CC_CHECK("projection rows: stores open", ready);
    if (ready) {
        cc_set_index_flags(true);
        failures += cc_projection_rows_body();
        cc_set_index_flags(false);
    }
    if (projection_store_db()) projection_store_close();
    if (progress_store_db()) progress_store_close();
    test_cleanup_tmpdir(dir);
    return failures;
}

/* ── snapshot_try: argument refusal and lock contention ───────────── */

struct cc_hold {
    atomic_int held;
    atomic_int release;
};

static void *cc_hold_thread(void *p)
{
    struct cc_hold *h = p;
    progress_store_tx_lock();
    atomic_store(&h->held, 1);
    while (!atomic_load(&h->release))
        sched_yield();
    progress_store_tx_unlock();
    return NULL;
}

static int cc_snapshot_try_busy(void)
{
    int failures = 0;
    struct catalog_index_status rows[CATALOG_COMPLETENESS_MAX_INDEXES];
    struct cc_hold hold;
    atomic_init(&hold.held, 0);
    atomic_init(&hold.release, 0);
    pthread_t th;
    bool started = pthread_create(&th, NULL, cc_hold_thread, &hold) == 0;
    CC_CHECK("snapshot_try busy: holder thread started", started);
    if (!started)
        return failures;
    while (!atomic_load(&hold.held))
        sched_yield();
    size_t count = 77;
    bool ok = catalog_completeness_snapshot_try(
        rows, CATALOG_COMPLETENESS_MAX_INDEXES, 1000, &count);
    CC_CHECK("snapshot_try busy: lock held elsewhere -> false", !ok);
    CC_CHECK("snapshot_try busy: count reset to 0, no rows claimed",
             count == 0);
    CC_CHECK("snapshot busy: wrapper returns 0 rows",
             catalog_completeness_snapshot(
                 rows, CATALOG_COMPLETENESS_MAX_INDEXES, 1000) == 0);
    atomic_store(&hold.release, 1);
    pthread_join(th, NULL);
    count = 77;
    ok = catalog_completeness_snapshot_try(
        rows, CATALOG_COMPLETENESS_MAX_INDEXES, 1000, &count);
    CC_CHECK("snapshot_try free: lock released -> true with all rows",
             ok && count == 9);
    return failures;
}

static int cc_snapshot_try_refusals(void)
{
    int failures = 0;
    struct catalog_index_status rows[CATALOG_COMPLETENESS_MAX_INDEXES];
    size_t count = 77;
    CC_CHECK("snapshot_try: NULL out -> false",
             !catalog_completeness_snapshot_try(NULL, 4, 100, &count));
    CC_CHECK("snapshot_try: NULL out zeroes count", count == 0);
    count = 77;
    CC_CHECK("snapshot_try: max==0 -> false",
             !catalog_completeness_snapshot_try(rows, 0, 100, &count));
    CC_CHECK("snapshot_try: max==0 zeroes count", count == 0);
    CC_CHECK("snapshot_try: NULL count -> false",
             !catalog_completeness_snapshot_try(rows, 4, 100, NULL));
    count = 77;
    CC_CHECK("snapshot_try: max==1 -> true",
             catalog_completeness_snapshot_try(rows, 1, 100, &count));
    CC_CHECK("snapshot_try: max==1 yields exactly one row, the first",
             count == 1 && rows[0].name &&
             strcmp(rows[0].name, "op_return_index") == 0);
    CC_CHECK("snapshot: max==1 wrapper returns 1",
             catalog_completeness_snapshot(rows, 1, 100) == 1);
    return failures;
}

/* ── pure helpers: names, emptiness, worst_over ties, verdict edges ── */

static int cc_names_and_emptiness(void)
{
    int failures = 0;
    CC_CHECK("coverage_name(UNKNOWN)",
             strcmp(catalog_coverage_name(CATALOG_COVERAGE_UNKNOWN),
                    "unknown") == 0);
    CC_CHECK("coverage_name(NONE)",
             strcmp(catalog_coverage_name(CATALOG_COVERAGE_NONE),
                    "none") == 0);
    CC_CHECK("coverage_name(PARTIAL)",
             strcmp(catalog_coverage_name(CATALOG_COVERAGE_PARTIAL),
                    "partial") == 0);
    CC_CHECK("coverage_name(COMPLETE)",
             strcmp(catalog_coverage_name(CATALOG_COVERAGE_COMPLETE),
                    "complete") == 0);
    CC_CHECK("coverage_name(out of range) is the invalid marker",
             strcmp(catalog_coverage_name((enum catalog_coverage)99),
                    "(invalid)") == 0);

    struct catalog_index_status row;
    memset(&row, 0, sizeof(row));
    row.enabled = true;
    row.coverage = (int)CATALOG_COVERAGE_COMPLETE;
    CC_CHECK("emptiness: enabled + complete -> meaningful",
             catalog_index_emptiness_is_meaningful(&row));
    row.coverage = (int)CATALOG_COVERAGE_PARTIAL;
    CC_CHECK("emptiness: enabled + partial -> not meaningful",
             !catalog_index_emptiness_is_meaningful(&row));
    row.coverage = (int)CATALOG_COVERAGE_COMPLETE;
    row.enabled = false;
    CC_CHECK("emptiness: disabled + complete -> not meaningful",
             !catalog_index_emptiness_is_meaningful(&row));
    CC_CHECK("emptiness: NULL row -> not meaningful",
             !catalog_index_emptiness_is_meaningful(NULL));
    return failures;
}

static int cc_worst_over_ties(void)
{
    int failures = 0;
    struct catalog_index_status rows[3];
    memset(rows, 0, sizeof(rows));
    rows[0] = (struct catalog_index_status){
        .name = "first", .lag = 50, .enabled = true};
    rows[1] = (struct catalog_index_status){
        .name = "tied", .lag = 50, .enabled = true};
    rows[2] = (struct catalog_index_status){
        .name = "edge", .lag = 10, .enabled = true};
    CC_CHECK("worst_over: a tie keeps the first row",
             catalog_completeness_worst_over(rows, 3, 0) == &rows[0]);
    CC_CHECK("worst_over: lag equal to the threshold is not over it",
             catalog_completeness_worst_over(rows, 3, 50) == NULL);
    CC_CHECK("worst_over: lag one above the threshold is over it",
             catalog_completeness_worst_over(rows, 3, 49) == &rows[0]);
    return failures;
}

static int cc_verdict_edges(void)
{
    int failures = 0;
    struct catalog_index_status one_lag[1];
    memset(one_lag, 0, sizeof(one_lag));
    one_lag[0] = (struct catalog_index_status){
        .name = "tx", .cursor = 99, .target = 100, .lag = 1, .enabled = true};
    struct catalog_index_status ok_rows[1];
    memset(ok_rows, 0, sizeof(ok_rows));
    ok_rows[0] = (struct catalog_index_status){
        .name = "tx", .cursor = 100, .target = 100, .lag = 0, .enabled = true};
    char v[96];

    CC_CHECK("verdict: a lag of exactly 1 is blocked",
             catalog_completeness_verdict(one_lag, 1, 3, 3, 30, 900, v,
                                          sizeof(v)) == CATALOG_VERDICT_BLOCKED &&
             strcmp(v, "blocked:tx@99") == 0);
    CC_CHECK("verdict: census age 0 is fresh -> omniscient",
             catalog_completeness_verdict(ok_rows, 1, 3, 3, 0, 900, v,
                                          sizeof(v)) ==
                 CATALOG_VERDICT_OMNISCIENT && strcmp(v, "omniscient") == 0);
    CC_CHECK("verdict: census age equal to the max is still fresh",
             catalog_completeness_verdict(ok_rows, 1, 3, 3, 900, 900, v,
                                          sizeof(v)) ==
                 CATALOG_VERDICT_OMNISCIENT);
    CC_CHECK("verdict: census age one past the max is stale",
             catalog_completeness_verdict(ok_rows, 1, 3, 3, 901, 900, v,
                                          sizeof(v)) ==
                 CATALOG_VERDICT_DEGRADED);
    CC_CHECK("verdict: peers equal to the floor are enough",
             catalog_completeness_verdict(ok_rows, 1, 3, 3, 30, 900, v,
                                          sizeof(v)) ==
                 CATALOG_VERDICT_OMNISCIENT);

    /* A NULL text buffer with a non-zero capacity must never be written,
     * whichever verdict is returned. */
    CC_CHECK("verdict: NULL out, cap>0, blocked",
             catalog_completeness_verdict(one_lag, 1, 3, 3, 30, 900, NULL,
                                          16) == CATALOG_VERDICT_BLOCKED);
    CC_CHECK("verdict: NULL out, cap>0, degraded peers",
             catalog_completeness_verdict(ok_rows, 1, 1, 3, 30, 900, NULL,
                                          16) == CATALOG_VERDICT_DEGRADED);
    CC_CHECK("verdict: NULL out, cap>0, degraded census",
             catalog_completeness_verdict(ok_rows, 1, 3, 3, -1, 900, NULL,
                                          16) == CATALOG_VERDICT_DEGRADED);
    CC_CHECK("verdict: NULL out, cap>0, omniscient",
             catalog_completeness_verdict(ok_rows, 1, 3, 3, 30, 900, NULL,
                                          16) == CATALOG_VERDICT_OMNISCIENT);
    return failures;
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

    failures += cc_scenario_genesis();
    failures += cc_scenario_positive_activation_gap();
    failures += cc_worst_lag_synthetic_arrays();
    failures += cc_snapshot_defensive_paths();
    failures += cc_worst_over_threshold_selector();
    failures += cc_verdict_classification();
    failures += cc_names_and_emptiness();
    failures += cc_worst_over_ties();
    failures += cc_verdict_edges();
    failures += cc_snapshot_try_refusals();
    failures += cc_snapshot_try_busy();
    failures += cc_scenario_node_db_rows();
    failures += cc_scenario_refused_and_unusable_handles();
    failures += cc_scenario_activation_rows();
    failures += cc_scenario_projection_rows();

    printf("catalog_completeness: %d failures\n", failures);
    return failures;
}
