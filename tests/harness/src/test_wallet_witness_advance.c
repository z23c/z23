/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_wallet_witness_advance - stored Sapling note witnesses follow the tip.
 *
 * A wallet note received at height H must have a stored witness at height
 * H+k after k further connected blocks, whether or not those blocks carry
 * shielded outputs, and the witness root must equal the commitment-tree root
 * at that height. The send path refuses any witness whose height differs from
 * the tip, so a witness frozen at the last output-bearing block makes a
 * confirmed note unspendable until rescanwitnesses. The node.db handle is
 * closed and reopened between blocks, as a restart does.
 */

#include "test/test_core.h"

#include "core/uint256.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "sapling/incremental_merkle_tree.h"
#include "core/serialize.h"
#include "models/database.h"
#include "models/wallet_tx.h"
#include "controllers/sync_controller.h"
#include "wallet/wallet.h"
#include "util/safe_alloc.h"

#include <stdio.h>
#include <string.h>

#define WA_CHECK(name, expr) do {                          \
    printf("wallet_witness_advance: %s... ", (name));      \
    if ((expr)) printf("OK\n");                            \
    else { printf("FAIL\n"); failures++; }                 \
} while (0)

/* Defined in engine/controllers/src/sync_controller_blocks.c. */
bool advance_wallet_witnesses(struct node_db *ndb, const struct block *blk,
                              struct incremental_merkle_tree *tree,
                              int height, struct wallet *wallet);

enum { WA_RECV_HEIGHT = 100, WA_BLOCKS = 4 };

static void wa_cm(uint8_t cm[32], uint8_t tag)
{
    memset(cm, 0, 32);
    cm[0] = tag;
    cm[1] = 0x23;
}

/* Connect one block with `n_out` shielded outputs (0 or 1) whose commitment
 * is `cm`, inside the writer transaction the production caller owns. */
static bool wa_connect(struct node_db *ndb, struct incremental_merkle_tree *tree,
                       int height, size_t n_out, const uint8_t cm[32])
{
    struct transaction tx;
    transaction_init(&tx);
    if (n_out) {
        tx.v_shielded_output = zcl_calloc(
            n_out, sizeof(struct output_description), "wa_outputs");
        if (!tx.v_shielded_output) return false;
        tx.num_shielded_output = n_out;
        memcpy(tx.v_shielded_output[0].cm.data, cm, 32);
    }
    struct block blk;
    memset(&blk, 0, sizeof(blk));
    blk.vtx = &tx;
    blk.num_vtx = 1;
    bool ok = node_db_begin_immediate(ndb) &&
              advance_wallet_witnesses(ndb, &blk, tree, height, NULL) &&
              node_db_commit(ndb);
    transaction_free(&tx);
    return ok;
}

static bool wa_witness_matches(struct node_db *ndb, const uint8_t txid[32],
                               int want_height,
                               const struct incremental_merkle_tree *tree)
{
    uint8_t *blob = NULL;
    size_t len = 0;
    int wh = 0;
    if (!db_sapling_note_load_witness(ndb, txid, 0, &blob, &len, &wh))
        return false;
    struct byte_stream s;
    stream_init_from_data(&s, blob, len);
    struct incremental_witness w;
    bool ok = wh == want_height &&
              incremental_witness_deserialize(
                  &w, &s, SAPLING_INCREMENTAL_MERKLE_TREE_DEPTH,
                  tree->combine, tree->uncommitted);
    if (ok) {
        struct uint256 wr, tr;
        incremental_witness_root(&w, &wr);
        incremental_tree_root(tree, &tr);
        ok = memcmp(wr.data, tr.data, 32) == 0;
    }
    free(blob);
    return ok;
}

int test_wallet_witness_advance(void);
int test_wallet_witness_advance(void)
{
    printf("\n=== wallet witness advance (receive, reopen, connect k blocks) ===\n");
    int failures = 0;
    char datadir[256], dbpath[320];
    test_make_tmpdir(datadir, sizeof(datadir), "wallet", "witness_adv");
    snprintf(dbpath, sizeof(dbpath), "%s/node.db", datadir);

    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));
    bool opened = node_db_open(&ndb, dbpath);
    WA_CHECK("node.db opened", opened);
    if (!opened) return failures + 1;

    uint8_t txid[32], rcm[32], memo[512], ivk[32], d[11], pk_d[32], nf[32], cm[32];
    memset(txid, 0xC4, 32); memset(rcm, 0x11, 32); memset(memo, 0, 512);
    memset(ivk, 0x22, 32); memset(d, 0x33, 11); memset(pk_d, 0x44, 32);
    memset(nf, 0x55, 32);
    wa_cm(cm, 0x77);

    bool noted = node_db_sync_sapling_note(&ndb, txid, 0, 125000000, rcm, memo,
                                           512, ivk, d, pk_d, cm, nf,
                                           WA_RECV_HEIGHT);
    WA_CHECK("wallet note persisted", noted);

    struct incremental_merkle_tree tree;
    sapling_tree_init(&tree);
    uint8_t other[32];
    wa_cm(other, 0x01);
    bool ok = noted && wa_connect(&ndb, &tree, WA_RECV_HEIGHT, 1, cm);
    WA_CHECK("witness created at receive height",
             ok && wa_witness_matches(&ndb, txid, WA_RECV_HEIGHT, &tree));

    /* Block H+1 carries an unrelated output; H+2 and H+3 carry none. The
     * database is reopened before each, as after a restart. */
    for (int k = 1; k < WA_BLOCKS && ok; k++) {
        node_db_close(&ndb);
        memset(&ndb, 0, sizeof(ndb));
        ok = node_db_open(&ndb, dbpath) &&
             wa_connect(&ndb, &tree, WA_RECV_HEIGHT + k, k == 1 ? 1 : 0,
                        other);
        char name[96];
        snprintf(name, sizeof(name),
                 "witness height and root at H+%d (%s)", k,
                 k == 1 ? "block with output" : "block without outputs");
        WA_CHECK(name, ok && wa_witness_matches(
                     &ndb, txid, WA_RECV_HEIGHT + k, &tree));
    }

    node_db_close(&ndb);
    failures += test_rm_rf_recursive(datadir) != 0;
    return failures;
}
