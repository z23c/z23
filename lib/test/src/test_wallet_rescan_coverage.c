/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_wallet_rescan_coverage — regression gate for the silent rescan.
 *
 * THE DEFECT: wallet_scan_block() returned a bare 0 for BOTH "this block
 * holds nothing of yours" AND "this node has no body for that block", using
 * the same statement, with no counter. rescanblockchain then returned only
 * {start_height, stop_height} — it never reported what it found or how much
 * it had actually been able to read. On a snapshot-bootstrapped node, where
 * snapshot_controller_import.c deliberately strips BLOCK_HAVE_DATA across the
 * whole imported range, a rescan therefore walked the entire chain, read
 * nothing, and reported plain success. A user restoring a wallet concluded
 * their backup was empty.
 *
 * Every assertion below drives the REAL `rescanblockchain` RPC — the exact
 * entry point `core wallet rescan` calls — so this test compiles and runs
 * against the pre-fix tree, where it fails because the counts it demands are
 * simply absent from the reply.
 *
 * Four scenarios, all against one on-disk block reused by 200 index entries:
 *
 *   A. Full coverage, wallet owns an output  -> coverage_ok, counts add up,
 *      and the untried-shielded condition is REPORTED (the wallet holds no
 *      Sapling key, the seed-only-restore state).
 *   B. No block bodies at all (the snapshot-bootstrap case) -> must FAIL with
 *      RESCAN_NO_BLOCK_DATA, never "0 found" with a success reply.
 *   C. 75% coverage -> must FAIL with RESCAN_INCOMPLETE_COVERAGE.
 *   D. 99.5% coverage but nothing found -> must FAIL with
 *      RESCAN_INCONCLUSIVE_ZERO: we cannot prove absence of funds from a
 *      range we did not fully read.
 */

#include "test/test_core.h"

#include "controllers/wallet_controller.h"

#include "models/database.h"

#include "wallet/wallet.h"
#include "util/safe_alloc.h"
#include "wallet/wallet_sqlite.h"

#include "storage/disk_block_io.h"
#include "validation/main_state.h"
#include "validation/txmempool.h"
#include "primitives/transaction.h"
#include "primitives/block.h"
#include "script/standard.h"
#include "keys/pubkey.h"
#include "json/json.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define WRC_CHECK(name, expr) do {                        \
    printf("wallet_rescan_coverage: %s... ", (name));     \
    if ((expr)) printf("OK\n");                           \
    else { printf("FAIL\n"); failures++; }                \
} while (0)

/* Total synthetic index entries. 200 makes the 99% coverage floor
 * (WALLET_RESCAN_MIN_COVERAGE_PCT) expressible: 199/200 clears it, 150/200
 * does not. */
#define WRC_NBLOCKS 200

/* Read an int key out of an RPC reply. Returns -1 when the key is absent —
 * which is exactly what the PRE-FIX rescanblockchain reply does for every
 * count, so the assertions below fail loudly on the parent commit. */
static int64_t wrc_int(const struct json_value *o, const char *k)
{
    const struct json_value *v = json_get(o, k);
    return (v && v->type == JSON_INT) ? json_get_int(v) : -1;
}

/* Read a string key; "" when absent or not a string. */
static const char *wrc_str(const struct json_value *o, const char *k)
{
    const struct json_value *v = json_get(o, k);
    return (v && v->type == JSON_STR) ? json_get_str(v) : "";
}

/* Read a bool key. `dflt` when absent — the pre-fix reply has no
 * coverage_ok, so callers pass a value that makes the demand fail. */
static bool wrc_bool(const struct json_value *o, const char *k, bool dflt)
{
    const struct json_value *v = json_get(o, k);
    return (v && v->type == JSON_BOOL) ? json_get_bool(v) : dflt;
}

/* Build the [start, stop] params array rescanblockchain expects. */
static void wrc_params(struct json_value *p, int start, int stop)
{
    json_init(p);
    json_set_array(p);
    struct json_value v;
    json_init(&v);
    json_set_int(&v, start);
    json_push_back(p, &v);
    json_free(&v);
    json_init(&v);
    json_set_int(&v, stop);
    json_push_back(p, &v);
    json_free(&v);
}

int test_wallet_rescan_coverage(void);
int test_wallet_rescan_coverage(void)
{
    int failures = 0;

    char datadir[256];
    snprintf(datadir, sizeof(datadir),
             "test-tmp/wallet_rescan_coverage_%d", (int)getpid());
    {
        char cmd[512];
        snprintf(cmd, sizeof(cmd), "rm -rf %s && mkdir -p %s/blocks",
                 datadir, datadir);
        if (system(cmd) != 0) {
            printf("wallet_rescan_coverage: could not create %s\n", datadir);
            return 1;
        }
    }

    char dbpath[320];
    snprintf(dbpath, sizeof(dbpath), "%s/node.db", datadir);
    struct node_db ndb;
    if (!node_db_open(&ndb, dbpath)) {
        printf("wallet_rescan_coverage: node_db_open(%s) failed\n", dbpath);
        return 1;
    }

    /* ── wallet 1: owns the funding output ───────────────────────────── */
    struct wallet *w1 = zcl_calloc(1, sizeof(*w1), "test-wallet");
    /* ~40 MB wallet: heap, never stack */
    wallet_init(w1);
    struct pubkey pk;
    memset(&pk, 0, sizeof(pk));
    bool have_key = wallet_generate_new_key(w1, &pk);
    WRC_CHECK("wallet1 generates a key", have_key);
    struct key_id kid = pubkey_get_id(&pk);

    struct script pay_to_us;
    script_init(&pay_to_us);
    script_for_p2pkh(&pay_to_us, &kid);

    /* ── one real block on disk: a coinbase-shaped tx paying our key, plus
     * a Sapling tx carrying one shielded output. The second tx is what
     * makes the "wallet holds no Sapling key" condition observable — the
     * seed-only-restore state, which used to be skipped in total silence. */
    struct disk_block_pos pos;
    disk_block_pos_init(&pos);
    bool wrote = false;
    {
        struct block blk;
        block_init(&blk);
        blk.header.nVersion = 4;
        blk.header.nTime = 1700000000u;
        blk.header.nBits = 0x2000ffffu;
        blk.num_vtx = 2;
        blk.vtx = calloc(2, sizeof(*blk.vtx)); /* raw-alloc-ok:test-fixture */
        if (blk.vtx) {
            /* tx0 — pays our key */
            struct transaction *t0 = &blk.vtx[0];
            transaction_init(t0);
            t0->version = 1;
            t0->vin = calloc(1, sizeof(*t0->vin)); /* raw-alloc-ok:test-fixture */
            t0->vout = calloc(1, sizeof(*t0->vout)); /* raw-alloc-ok:test-fixture */
            if (t0->vin && t0->vout) {
                t0->num_vin = 1;
                t0->num_vout = 1;
                outpoint_set_null(&t0->vin[0].prevout);
                script_init(&t0->vin[0].script_sig);
                t0->vin[0].sequence = 0xffffffffu;
                t0->vout[0].value = 1000000;
                /* struct script is a fixed-size value type — plain copy. */
                t0->vout[0].script_pub_key = pay_to_us;
            }
            /* tx1 — Sapling v4 with one (all-zero) shielded output */
            struct transaction *t1 = &blk.vtx[1];
            transaction_init(t1);
            t1->overwintered = true;
            t1->version = 4;
            t1->version_group_id = 0x892F2085u;
            t1->v_shielded_output =
                calloc(1, sizeof(*t1->v_shielded_output)); /* raw-alloc-ok:test-fixture */
            if (t1->v_shielded_output)
                t1->num_shielded_output = 1;

            unsigned char msg_start[4] = { 0x24, 0xe9, 0x27, 0x64 };
            wrote = write_block_to_disk(&blk, &pos, datadir, msg_start);
        }
        block_free(&blk);
    }
    WRC_CHECK("write a block (1 transparent + 1 shielded tx) to disk", wrote);

    /* ── 200 index entries, every one pointing at that same on-disk block.
     * Sharing one body keeps the fixture cheap while giving a range large
     * enough to express the coverage floor. ── */
    struct block_index *idx =
        calloc(WRC_NBLOCKS, sizeof(*idx)); /* raw-alloc-ok:test-fixture */
    struct block_index **chain =
        calloc(WRC_NBLOCKS, sizeof(*chain)); /* raw-alloc-ok:test-fixture */
    WRC_CHECK("allocate synthetic chain", idx != NULL && chain != NULL);
    if (!idx || !chain) {
        free(idx); free(chain);
        node_db_close(&ndb);
        return failures + 1;
    }
    for (int i = 0; i < WRC_NBLOCKS; i++) {
        block_index_init(&idx[i]);
        idx[i].nHeight = i;
        idx[i].nFile = pos.nFile;
        idx[i].nDataPos = pos.nPos;
        idx[i].nStatus = BLOCK_HAVE_DATA;
        idx[i].phashBlock = NULL;
        chain[i] = &idx[i];
    }

    struct main_state ms;
    main_state_init(&ms);
    free(ms.chain_active.chain);
    ms.chain_active.chain = chain;
    ms.chain_active.height = WRC_NBLOCKS - 1;
    ms.chain_active.capacity = WRC_NBLOCKS;

    struct wallet_sqlite ws;
    WRC_CHECK("wallet_sqlite_open", wallet_sqlite_open(&ws, ndb.db));

    struct tx_mempool mempool;
    tx_mempool_init(&mempool, 0);

    struct rpc_table wtbl;
    rpc_table_init(&wtbl);
    register_wallet_rpc_commands(&wtbl);
    /* rpc_table_execute() refuses every method while warmup is armed
     * (code -28, "RPC server started"); this fixture never boots a node. */
    set_rpc_warmup_finished();

    rpc_wallet_set_state(w1, &ms, datadir, &ws, &mempool, NULL);
    rpc_wallet_set_node_db(&ndb);
    rpc_wallet_set_coins_tip(NULL);  /* skip the chainstate-lookup gate */

    const int last = WRC_NBLOCKS - 1;

    /* ── A. Full coverage, wallet owns an output in every block ──────── */
    {
        struct json_value params, result;
        wrc_params(&params, 0, last);
        json_init(&result);
        bool ok = rpc_table_execute(&wtbl, "rescanblockchain", &params, &result);
        WRC_CHECK("A: rescan over a fully-bodied range succeeds", ok);
        WRC_CHECK("A: reports blocks_scanned == 200",
                  wrc_int(&result, "blocks_scanned") == WRC_NBLOCKS);
        WRC_CHECK("A: reports blocks_missing_data == 0",
                  wrc_int(&result, "blocks_missing_data") == 0);
        WRC_CHECK("A: reports outputs_found == 200 (one per block)",
                  wrc_int(&result, "outputs_found") == WRC_NBLOCKS);
        WRC_CHECK("A: coverage_ok is true", wrc_bool(&result, "coverage_ok", false));
        WRC_CHECK("A: no blocker is named",
                  wrc_str(&result, "blocker")[0] == '\0');
        /* D-item: the untried-shielded condition must be VISIBLE, not silent.
         * The wallet holds no Sapling key, so every shielded output in range
         * went untried — exactly the state after a seed-only restore. */
        WRC_CHECK("A: reports sapling_key_count == 0",
                  wrc_int(&result, "sapling_key_count") == 0);
        WRC_CHECK("A: reports 200 shielded txs left untried",
                  wrc_int(&result, "shielded_txs_unscanned") == WRC_NBLOCKS);
        WRC_CHECK("A: flags shielded_scan_skipped",
                  wrc_bool(&result, "shielded_scan_skipped", false));
        json_free(&params);
        json_free(&result);
    }

    /* ── B. THE AUDIT'S CASE: a snapshot-bootstrapped node. Every block is
     * indexed but no body is on disk. The pre-fix code reported success and
     * "0 wallet outputs found" here, and the user concluded the backup was
     * empty. It must now refuse. ── */
    for (int i = 0; i < WRC_NBLOCKS; i++)
        idx[i].nStatus &= ~BLOCK_HAVE_DATA;
    {
        struct json_value params, result;
        wrc_params(&params, 0, last);
        json_init(&result);
        (void)rpc_table_execute(&wtbl, "rescanblockchain", &params, &result);
        WRC_CHECK("B: reports blocks_scanned == 0 (nothing was read)",
                  wrc_int(&result, "blocks_scanned") == 0);
        WRC_CHECK("B: reports blocks_missing_data == 200",
                  wrc_int(&result, "blocks_missing_data") == WRC_NBLOCKS);
        WRC_CHECK("B: reports outputs_found == 0",
                  wrc_int(&result, "outputs_found") == 0);
        WRC_CHECK("B: coverage_ok is FALSE — a bodyless rescan is not success",
                  wrc_bool(&result, "coverage_ok", true) == false);
        WRC_CHECK("B: names blocker RESCAN_NO_BLOCK_DATA",
                  strcmp(wrc_str(&result, "blocker"),
                         "RESCAN_NO_BLOCK_DATA") == 0);
        json_free(&params);
        json_free(&result);
    }

    /* ── C. 150/200 bodies present = 75%, under the 99% floor ────────── */
    for (int i = 0; i < WRC_NBLOCKS; i++)
        idx[i].nStatus |= BLOCK_HAVE_DATA;
    for (int i = 0; i < 50; i++)
        idx[i].nStatus &= ~BLOCK_HAVE_DATA;
    {
        struct json_value params, result;
        wrc_params(&params, 0, last);
        json_init(&result);
        (void)rpc_table_execute(&wtbl, "rescanblockchain", &params, &result);
        WRC_CHECK("C: reports blocks_scanned == 150",
                  wrc_int(&result, "blocks_scanned") == 150);
        WRC_CHECK("C: reports blocks_missing_data == 50",
                  wrc_int(&result, "blocks_missing_data") == 50);
        WRC_CHECK("C: coverage_ok is FALSE at 75% coverage",
                  wrc_bool(&result, "coverage_ok", true) == false);
        WRC_CHECK("C: names blocker RESCAN_INCOMPLETE_COVERAGE",
                  strcmp(wrc_str(&result, "blocker"),
                         "RESCAN_INCOMPLETE_COVERAGE") == 0);
        /* Found outputs are still reported — a partial scan is not a void one. */
        WRC_CHECK("C: still reports the 150 outputs it did find",
                  wrc_int(&result, "outputs_found") == 150);
        json_free(&params);
        json_free(&result);
    }

    /* ── D. 199/200 = 99.5% coverage (clears the floor) but the wallet owns
     * nothing. We still cannot say "you have no funds" — the one block we
     * could not read is exactly where they might be. ── */
    struct wallet *w2 = zcl_calloc(1, sizeof(*w2), "test-wallet");
    /* ~40 MB wallet: heap, never stack */
    wallet_init(w2);
    for (int i = 0; i < WRC_NBLOCKS; i++)
        idx[i].nStatus |= BLOCK_HAVE_DATA;
    idx[7].nStatus &= ~BLOCK_HAVE_DATA;
    rpc_wallet_set_state(w2, &ms, datadir, &ws, &mempool, NULL);
    {
        struct json_value params, result;
        wrc_params(&params, 0, last);
        json_init(&result);
        (void)rpc_table_execute(&wtbl, "rescanblockchain", &params, &result);
        WRC_CHECK("D: reports blocks_scanned == 199",
                  wrc_int(&result, "blocks_scanned") == 199);
        WRC_CHECK("D: reports blocks_missing_data == 1",
                  wrc_int(&result, "blocks_missing_data") == 1);
        WRC_CHECK("D: reports outputs_found == 0 (this wallet owns nothing)",
                  wrc_int(&result, "outputs_found") == 0);
        WRC_CHECK("D: coverage_ok is FALSE — zero-found is inconclusive here",
                  wrc_bool(&result, "coverage_ok", true) == false);
        WRC_CHECK("D: names blocker RESCAN_INCONCLUSIVE_ZERO",
                  strcmp(wrc_str(&result, "blocker"),
                         "RESCAN_INCONCLUSIVE_ZERO") == 0);
        json_free(&params);
        json_free(&result);
    }

    /* ── teardown ────────────────────────────────────────────────────── */
    rpc_wallet_set_state(NULL, NULL, NULL, NULL, NULL, NULL);
    rpc_wallet_set_node_db(NULL);
    tx_mempool_free(&mempool);
    wallet_sqlite_close(&ws);
    wallet_free(w2); free(w2);
    wallet_free(w1); free(w1);
    ms.chain_active.chain = NULL;
    ms.chain_active.capacity = 0;
    ms.chain_active.height = 0;
    free(chain);
    free(idx);
    node_db_close(&ndb);
    {
        char cmd[512];
        snprintf(cmd, sizeof(cmd), "rm -rf %s", datadir);
        (void)system(cmd);
    }

    if (failures == 0)
        printf("wallet_rescan_coverage: OK (a rescan can no longer "
               "silently find nothing)\n");
    else
        printf("=== wallet_rescan_coverage: %d failure(s) ===\n", failures);
    return failures;
}
