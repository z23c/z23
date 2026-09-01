/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rhett Creighton
 *
 * L7 parity restoration: active-chain Sprout/Sapling anchor membership.
 *
 * This group exercises the same durable anchor store, coins-view predicate,
 * reducer writer, and shared rewind primitive used in production.  It pins
 * the important zclassicd semantics: forged roots fail, historical roots
 * pass, Sprout same-transaction intermediate roots pass, incomplete imported
 * history fails closed with a distinct verdict, and anchor writes are atomic
 * with reducer commit/rollback/reorg handling. */

#include "test/test_core.h"

#include "coins/coins_view.h"
#include "jobs/utxo_apply_anchors.h"
#include "jobs/utxo_apply_delta.h"
#include "primitives/block.h"
#include "sapling/incremental_merkle_tree.h"
#include "storage/anchor_kv.h"
#include "storage/nullifier_kv.h"
#include "util/safe_alloc.h"

#include <sqlite3.h>
#include <stdio.h>
#include <string.h>

#define L7_CHECK(name, expr) do {                              \
    printf("parity_lockin_anchor_membership: %s... ", (name)); \
    if ((expr)) printf("OK\n");                               \
    else { printf("FAIL\n"); failures++; }                    \
} while (0)

struct anchor_test_view {
    struct coins_view view;
    sqlite3 *db;
};

static enum coins_anchor_lookup_result test_get_anchor(
    void *self, enum coins_anchor_pool pool, const struct uint256 *root,
    struct incremental_merkle_tree *tree_out)
{
    struct anchor_test_view *tv = self;
    if (!tv || !tv->db)
        return COINS_ANCHOR_ERROR;
    enum anchor_kv_lookup_result r = anchor_kv_get(
        tv->db, (int)pool, root, tree_out, NULL);
    switch (r) {
    case ANCHOR_KV_FOUND: return COINS_ANCHOR_FOUND;
    case ANCHOR_KV_MISSING: return COINS_ANCHOR_MISSING;
    case ANCHOR_KV_HISTORY_INCOMPLETE:
        return COINS_ANCHOR_HISTORY_INCOMPLETE;
    case ANCHOR_KV_ERROR:
    default: return COINS_ANCHOR_ERROR;
    }
}

static struct coins_view_vtable g_test_anchor_vtable = {
    .get_anchor = test_get_anchor,
};

static void test_view_init(struct anchor_test_view *tv, sqlite3 *db)
{
    memset(tv, 0, sizeof(*tv));
    tv->db = db;
    tv->view.vtable = &g_test_anchor_vtable;
    tv->view.impl = tv;
}

static bool sql_ok(sqlite3 *db, const char *sql)
{
    char *err = NULL;
    int rc = sqlite3_exec(db, sql, NULL, NULL, &err);
    if (err)
        sqlite3_free(err);
    return rc == SQLITE_OK;
}

static void fill_hash(struct uint256 *hash, unsigned char value)
{
    memset(hash->data, value, sizeof(hash->data));
}

static void summary_init(struct delta_summary *summary)
{
    memset(summary, 0, sizeof(*summary));
    summary->ok = true;
    summary->status = "ok";
}

static bool block_with_joinsplit(struct block *blk)
{
    block_init(blk);
    blk->num_vtx = 1;
    blk->vtx = zcl_calloc(1, sizeof(*blk->vtx), "l7_anchor_block_tx");
    if (!blk->vtx)
        return false;
    transaction_init(&blk->vtx[0]);
    blk->vtx[0].num_joinsplit = 1;
    blk->vtx[0].v_joinsplit = zcl_calloc(
        1, sizeof(*blk->vtx[0].v_joinsplit), "l7_anchor_block_js");
    if (!blk->vtx[0].v_joinsplit) {
        block_free(blk);
        return false;
    }
    struct incremental_merkle_tree empty;
    sprout_tree_init(&empty);
    incremental_tree_root(&empty, &blk->vtx[0].v_joinsplit[0].anchor);
    fill_hash(&blk->vtx[0].v_joinsplit[0].commitments[0], 0x11);
    fill_hash(&blk->vtx[0].v_joinsplit[0].commitments[1], 0x22);
    return true;
}

static bool block_with_sapling_output(struct block *blk, unsigned char cm,
                                       const struct uint256 *header_root)
{
    block_init(blk);
    blk->num_vtx = 1;
    blk->vtx = zcl_calloc(1, sizeof(*blk->vtx), "l7_anchor_sapling_tx");
    if (!blk->vtx)
        return false;
    transaction_init(&blk->vtx[0]);
    blk->vtx[0].num_shielded_output = 1;
    blk->vtx[0].v_shielded_output = zcl_calloc(
        1, sizeof(*blk->vtx[0].v_shielded_output),
        "l7_anchor_sapling_output");
    if (!blk->vtx[0].v_shielded_output) {
        block_free(blk);
        return false;
    }
    fill_hash(&blk->vtx[0].v_shielded_output[0].cm, cm);
    blk->header.hashFinalSaplingRoot = *header_root;
    return true;
}

static int test_membership_predicate(void)
{
    int failures = 0;
    sqlite3 *db = NULL;
    L7_CHECK("open complete-history anchor store",
             sqlite3_open(":memory:", &db) == SQLITE_OK);
    if (!db)
        return failures + 1;
    L7_CHECK("initialize from-genesis anchor history",
             anchor_kv_initialize_history(db, 0));

    struct anchor_test_view backing;
    test_view_init(&backing, db);
    struct coins_view_cache view;
    coins_view_cache_init(&view, &backing.view);

    {
        struct transaction tx;
        transaction_init(&tx);
        tx.num_joinsplit = 1;
        tx.v_joinsplit = zcl_calloc(1, sizeof(*tx.v_joinsplit),
                                    "l7_forged_js");
        fill_hash(&tx.v_joinsplit[0].anchor, 0xDE);
        enum coins_shielded_requirements_result r =
            coins_view_cache_check_shielded_requirements(&view, &tx);
        L7_CHECK("forged Sprout root is rejected as missing",
                 r == COINS_SHIELDED_REQUIREMENTS_MISSING_ANCHOR &&
                 !coins_view_cache_have_joinsplit_requirements(&view, &tx));
        transaction_free(&tx);
    }

    {
        struct transaction tx;
        transaction_init(&tx);
        tx.num_shielded_spend = 1;
        tx.v_shielded_spend = zcl_calloc(1, sizeof(*tx.v_shielded_spend),
                                         "l7_forged_spend");
        fill_hash(&tx.v_shielded_spend[0].anchor, 0xAB);
        enum coins_shielded_requirements_result r =
            coins_view_cache_check_shielded_requirements(&view, &tx);
        L7_CHECK("forged Sapling root is rejected as missing",
                 r == COINS_SHIELDED_REQUIREMENTS_MISSING_ANCHOR &&
                 !coins_view_cache_have_joinsplit_requirements(&view, &tx));
        transaction_free(&tx);
    }

    {
        struct transaction tx;
        transaction_init(&tx);
        L7_CHECK("transparent transaction has no anchor requirement",
                 coins_view_cache_check_shielded_requirements(&view, &tx) ==
                     COINS_SHIELDED_REQUIREMENTS_OK);
        transaction_free(&tx);
    }

    struct incremental_merkle_tree sprout;
    struct uint256 sprout_root;
    sprout_tree_init(&sprout);
    struct uint256 sprout_leaf;
    fill_hash(&sprout_leaf, 0x31);
    incremental_tree_append(&sprout, &sprout_leaf);
    incremental_tree_root(&sprout, &sprout_root);
    L7_CHECK("persist historical Sprout frontier",
             anchor_kv_add_tree(db, ANCHOR_POOL_SPROUT, &sprout, 10));

    {
        struct transaction tx;
        transaction_init(&tx);
        tx.num_joinsplit = 1;
        tx.v_joinsplit = zcl_calloc(1, sizeof(*tx.v_joinsplit),
                                    "l7_known_js");
        tx.v_joinsplit[0].anchor = sprout_root;
        L7_CHECK("stored historical Sprout root is accepted",
                 coins_view_cache_have_joinsplit_requirements(&view, &tx));
        transaction_free(&tx);
    }

    struct incremental_merkle_tree sapling;
    struct uint256 sapling_root;
    sapling_tree_init(&sapling);
    struct uint256 sapling_leaf;
    fill_hash(&sapling_leaf, 0x41);
    incremental_tree_append(&sapling, &sapling_leaf);
    incremental_tree_root(&sapling, &sapling_root);
    L7_CHECK("persist historical Sapling frontier",
             anchor_kv_add_tree(db, ANCHOR_POOL_SAPLING, &sapling, 20));

    {
        struct transaction tx;
        transaction_init(&tx);
        tx.num_shielded_spend = 1;
        tx.v_shielded_spend = zcl_calloc(1, sizeof(*tx.v_shielded_spend),
                                         "l7_known_spend");
        tx.v_shielded_spend[0].anchor = sapling_root;
        L7_CHECK("stored historical Sapling root is accepted",
                 coins_view_cache_have_joinsplit_requirements(&view, &tx));
        transaction_free(&tx);
    }

    {
        struct transaction tx;
        transaction_init(&tx);
        tx.num_joinsplit = 2;
        tx.v_joinsplit = zcl_calloc(2, sizeof(*tx.v_joinsplit),
                                    "l7_intermediate_js");
        struct incremental_merkle_tree tree;
        sprout_tree_init(&tree);
        incremental_tree_root(&tree, &tx.v_joinsplit[0].anchor);
        fill_hash(&tx.v_joinsplit[0].commitments[0], 0x51);
        fill_hash(&tx.v_joinsplit[0].commitments[1], 0x52);
        incremental_tree_append(&tree, &tx.v_joinsplit[0].commitments[0]);
        incremental_tree_append(&tree, &tx.v_joinsplit[0].commitments[1]);
        incremental_tree_root(&tree, &tx.v_joinsplit[1].anchor);
        fill_hash(&tx.v_joinsplit[1].commitments[0], 0x53);
        fill_hash(&tx.v_joinsplit[1].commitments[1], 0x54);
        L7_CHECK("Sprout same-transaction intermediate root is accepted",
                 coins_view_cache_have_joinsplit_requirements(&view, &tx));
        transaction_free(&tx);
    }

    coins_view_cache_free(&view);
    sqlite3_close(db);

    sqlite3 *gap_db = NULL;
    L7_CHECK("open imported-history anchor store",
             sqlite3_open(":memory:", &gap_db) == SQLITE_OK);
    if (!gap_db)
        return failures + 1;
    L7_CHECK("mark imported anchor history incomplete",
             anchor_kv_initialize_history(gap_db, 100));
    test_view_init(&backing, gap_db);
    coins_view_cache_init(&view, &backing.view);
    {
        struct transaction tx;
        transaction_init(&tx);
        tx.num_shielded_spend = 1;
        tx.v_shielded_spend = zcl_calloc(1, sizeof(*tx.v_shielded_spend),
                                         "l7_gap_spend");
        fill_hash(&tx.v_shielded_spend[0].anchor, 0x61);
        L7_CHECK("unknown root with imported history fails closed distinctly",
                 coins_view_cache_check_shielded_requirements(&view, &tx) ==
                     COINS_SHIELDED_REQUIREMENTS_HISTORY_INCOMPLETE &&
                 !coins_view_cache_have_joinsplit_requirements(&view, &tx));
        transaction_free(&tx);
    }
    coins_view_cache_free(&view);
    sqlite3_close(gap_db);
    return failures;
}

static int test_reducer_atomicity(void)
{
    int failures = 0;
    sqlite3 *db = NULL;
    L7_CHECK("open reducer anchor store",
             sqlite3_open(":memory:", &db) == SQLITE_OK);
    if (!db)
        return failures + 1;
    L7_CHECK("initialize reducer anchor history",
             anchor_kv_initialize_history(db, 0));

    struct block sprout_block;
    L7_CHECK("construct Sprout reducer block",
             block_with_joinsplit(&sprout_block));
    struct incremental_merkle_tree expected_tree;
    struct uint256 expected_root;
    sprout_tree_init(&expected_tree);
    incremental_tree_append(
        &expected_tree, &sprout_block.vtx[0].v_joinsplit[0].commitments[0]);
    incremental_tree_append(
        &expected_tree, &sprout_block.vtx[0].v_joinsplit[0].commitments[1]);
    incremental_tree_root(&expected_tree, &expected_root);

    struct delta_summary summary;
    summary_init(&summary);
    L7_CHECK("begin reducer rollback probe", sql_ok(db, "BEGIN IMMEDIATE"));
    L7_CHECK("reducer writer inserts Sprout anchor in caller transaction",
             utxo_apply_check_and_insert_anchors(
                 db, &sprout_block, 50, &summary) && summary.ok &&
             anchor_kv_get(db, ANCHOR_POOL_SPROUT, &expected_root,
                           NULL, NULL) == ANCHOR_KV_FOUND);
    L7_CHECK("rollback reducer anchor transaction", sql_ok(db, "ROLLBACK"));
    L7_CHECK("rollback removes uncommitted Sprout anchor",
             anchor_kv_get(db, ANCHOR_POOL_SPROUT, &expected_root,
                           NULL, NULL) == ANCHOR_KV_MISSING);

    summary_init(&summary);
    L7_CHECK("begin reducer commit probe", sql_ok(db, "BEGIN IMMEDIATE"));
    L7_CHECK("reducer writer accepts Sprout block",
             utxo_apply_check_and_insert_anchors(
                 db, &sprout_block, 50, &summary) && summary.ok);
    L7_CHECK("commit reducer anchor transaction", sql_ok(db, "COMMIT"));
    L7_CHECK("committed Sprout anchor remains durable",
             anchor_kv_get(db, ANCHOR_POOL_SPROUT, &expected_root,
                           NULL, NULL) == ANCHOR_KV_FOUND);

    L7_CHECK("create reducer log/delta rewind fixtures",
             sql_ok(db,
                 "CREATE TABLE utxo_apply_log(height INTEGER PRIMARY KEY);"
                 "CREATE TABLE utxo_apply_delta(height INTEGER PRIMARY KEY);"));
    L7_CHECK("begin shared rewind rollback probe",
             sql_ok(db, "BEGIN IMMEDIATE"));
    L7_CHECK("shared reducer rewind deletes anchor in caller transaction",
             utxo_apply_delete_rows_above(db, 50, 50) &&
             anchor_kv_get(db, ANCHOR_POOL_SPROUT, &expected_root,
                           NULL, NULL) == ANCHOR_KV_MISSING);
    L7_CHECK("rollback shared rewind", sql_ok(db, "ROLLBACK"));
    L7_CHECK("rewind rollback restores anchor",
             anchor_kv_get(db, ANCHOR_POOL_SPROUT, &expected_root,
                           NULL, NULL) == ANCHOR_KV_FOUND);
    L7_CHECK("begin committed shared rewind", sql_ok(db, "BEGIN IMMEDIATE"));
    L7_CHECK("shared reducer rewind succeeds",
             utxo_apply_delete_rows_above(db, 50, 50));
    L7_CHECK("commit shared reducer rewind", sql_ok(db, "COMMIT"));
    L7_CHECK("committed rewind removes abandoned anchor",
             anchor_kv_get(db, ANCHOR_POOL_SPROUT, &expected_root,
                           NULL, NULL) == ANCHOR_KV_MISSING);
    block_free(&sprout_block);

    struct incremental_merkle_tree sapling_tree;
    struct uint256 sapling_expected;
    struct uint256 sapling_cm;
    sapling_tree_init(&sapling_tree);
    fill_hash(&sapling_cm, 0x71);
    incremental_tree_append(&sapling_tree, &sapling_cm);
    incremental_tree_root(&sapling_tree, &sapling_expected);
    struct block sapling_block;
    L7_CHECK("construct Sapling reducer block",
             block_with_sapling_output(
                 &sapling_block, 0x71, &sapling_expected));
    summary_init(&summary);
    L7_CHECK("begin Sapling reducer transaction",
             sql_ok(db, "BEGIN IMMEDIATE"));
    L7_CHECK("Sapling writer matches header and inserts anchor",
             utxo_apply_check_and_insert_anchors(
                 db, &sapling_block, 476969, &summary) && summary.ok &&
             anchor_kv_get(db, ANCHOR_POOL_SAPLING, &sapling_expected,
                           NULL, NULL) == ANCHOR_KV_FOUND);
    L7_CHECK("commit Sapling reducer transaction", sql_ok(db, "COMMIT"));
    block_free(&sapling_block);

    struct incremental_merkle_tree next_tree = sapling_tree;
    struct uint256 next_cm;
    struct uint256 next_root;
    fill_hash(&next_cm, 0x72);
    incremental_tree_append(&next_tree, &next_cm);
    incremental_tree_root(&next_tree, &next_root);
    struct uint256 wrong_root;
    fill_hash(&wrong_root, 0xFF);
    struct block wrong_block;
    L7_CHECK("construct mismatched Sapling reducer block",
             block_with_sapling_output(&wrong_block, 0x72, &wrong_root));
    summary_init(&summary);
    L7_CHECK("begin mismatched Sapling transaction",
             sql_ok(db, "BEGIN IMMEDIATE"));
    L7_CHECK("Sapling header/frontier mismatch fails closed",
             utxo_apply_check_and_insert_anchors(
                 db, &wrong_block, 476970, &summary) && !summary.ok &&
             summary.status &&
             strcmp(summary.status, "sapling_frontier_mismatch") == 0 &&
             anchor_kv_get(db, ANCHOR_POOL_SAPLING, &next_root,
                           NULL, NULL) == ANCHOR_KV_MISSING);
    L7_CHECK("rollback mismatched Sapling transaction",
             sql_ok(db, "ROLLBACK"));
    block_free(&wrong_block);

    sqlite3_close(db);
    return failures;
}

static int test_bounded_full_replay_frontier(void)
{
    int failures = 0;
    sqlite3 *db = NULL;
    L7_CHECK("open bounded full-replay store",
             sqlite3_open(":memory:", &db) == SQLITE_OK);
    if (!db)
        return failures + 1;
    L7_CHECK("bounded replay reset keeps all histories incomplete",
             shielded_history_begin_full_replay(db, 0));
    {
        int64_t sprout = -1, sapling = -1, nf = -1;
        bool sf = false, zf = false, nf_found = false;
        L7_CHECK("bounded replay publishes positive markers before genesis",
                 anchor_kv_activation_cursor(
                     db, ANCHOR_POOL_SPROUT, &sprout, &sf) &&
                 anchor_kv_activation_cursor(
                     db, ANCHOR_POOL_SAPLING, &sapling, &zf) &&
                 nullifier_kv_activation_cursor(db, &nf, &nf_found) &&
                 sf && zf && nf_found && sprout == 1 && sapling == 1 &&
                 nf == 1);
    }

    struct block blk;
    L7_CHECK("construct bounded replay Sprout block",
             block_with_joinsplit(&blk));
    struct incremental_merkle_tree expected_tree;
    struct uint256 expected_root;
    sprout_tree_init(&expected_tree);
    incremental_tree_append(
        &expected_tree, &blk.vtx[0].v_joinsplit[0].commitments[0]);
    incremental_tree_append(
        &expected_tree, &blk.vtx[0].v_joinsplit[0].commitments[1]);
    incremental_tree_root(&expected_tree, &expected_root);

    struct delta_summary summary;
    summary_init(&summary);
    L7_CHECK("normal reducer transaction begins under positive marker",
             sql_ok(db, "BEGIN IMMEDIATE"));
    L7_CHECK("normal reducer cannot borrow replay empty-frontier authority",
             utxo_apply_check_and_insert_anchors(
                 db, &blk, 0, &summary) && !summary.ok);
    L7_CHECK("normal reducer refusal rolls back", sql_ok(db, "ROLLBACK"));

    summary_init(&summary);
    L7_CHECK("bounded replay transaction begins",
             sql_ok(db, "BEGIN IMMEDIATE"));
    bool folded = utxo_apply_check_and_insert_anchors_full_replay(
        db, &blk, 0, &summary);
    L7_CHECK("bounded genesis replay uses protocol empty frontier",
             folded && summary.ok);
    L7_CHECK("bounded session advances with the anchor write",
             folded && summary.ok &&
             shielded_history_full_replay_advance_in_tx(db, 0, 0));
    L7_CHECK("bounded replay transaction commits",
             sql_ok(db, "COMMIT"));
    {
        int64_t cursor = -1;
        bool found = false;
        L7_CHECK("finished replay stays externally incomplete before epilogue",
                 anchor_kv_activation_cursor(
                     db, ANCHOR_POOL_SPROUT, &cursor, &found) &&
                 found && cursor == 1);
    }
    L7_CHECK("successful target epilogue publishes all completeness",
             shielded_history_publish_full_replay_complete(db, 0));
    L7_CHECK("replayed Sprout frontier remains after completion",
             anchor_kv_get(db, ANCHOR_POOL_SPROUT, &expected_root,
                           NULL, NULL) == ANCHOR_KV_FOUND);

    block_free(&blk);
    sqlite3_close(db);
    return failures;
}

int test_parity_lockin_anchor_membership(void)
{
    return test_membership_predicate() + test_reducer_atomicity() +
           test_bounded_full_replay_frontier();
}
