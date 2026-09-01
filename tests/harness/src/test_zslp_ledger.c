/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tests for the ZSLP per-(token, outpoint) ledger (zslp_ledger) — the
 * debit-correct, chain-derived token-balance projection.
 *
 *  1. GENESIS creates an unspent outpoint row (amount + address) and its
 *     holder balance.
 *  2. A SEND moves amounts to new outpoints AND marks the consumed input
 *     spent; the balance query sums UNSPENT rows only (so a spent GENESIS
 *     output no longer counts).
 *  3. The backfill cursor advances to H*, and is idempotent once caught up.
 *  4. zslp_ledger_apply_height's running digest changes when the rows at a
 *     height change (and folds every height, so an empty height still
 *     advances the chain); truncate + a fresh re-derive reproduces the exact
 *     row count and digest ("rebuildable + integrity").
 *  5. The live per-block hook (zslp_ledger_apply_slp_live) creates rows and
 *     marks spends directly from a tx + parsed SLP message.
 *
 * The projection derives purely from already-persisted node.db tables
 * (zslp_transfers / tx_outputs / tx_inputs), so these tests seed those
 * tables directly — no on-disk block bodies required. */

#include "test/test_core.h"
#include "models/database.h"
#include "models/zslp_ledger.h"
#include "models/zslp_validity.h"
#include "services/zslp_ledger_backfill_service.h"
#include "jobs/reducer_frontier.h"
#include "primitives/transaction.h"
#include "zslp/slp.h"
#include "core/amount.h"

#include <sqlite3.h>
#include <stdio.h>
#include <string.h>

/* ── Fixture seed data ────────────────────────────────────────────── */

static uint8_t g_token[32];
static uint8_t g_txid_genesis[32];
static uint8_t g_txid_send[32];
static uint8_t g_addr_a[20];
static uint8_t g_addr_b[20];

static void fill(uint8_t *p, size_t n, uint8_t v)
{
    memset(p, v, n);
}

static int count_rows(struct node_db *ndb, const char *sql)
{
    sqlite3_stmt *s = NULL;
    int n = -1;
    if (sqlite3_prepare_v2(ndb->db, sql, -1, &s, NULL) == SQLITE_OK && s) {
        if (sqlite3_step(s) == SQLITE_ROW)  // raw-sql-ok:test-readonly-count
            n = sqlite3_column_int(s, 0);
    }
    if (s) sqlite3_finalize(s);
    return n;
}

static void ins_transfer(struct node_db *ndb, const uint8_t txid[32],
                         int height, const uint8_t token_id[32], int tx_type,
                         int64_t amount, int vout, const uint8_t to_addr20[20])
{
    sqlite3_stmt *s = NULL;
    sqlite3_prepare_v2(ndb->db,
        "INSERT OR REPLACE INTO zslp_transfers"
        "(txid,block_height,token_id,tx_type,amount,vout,to_addr)"
        " VALUES(?,?,?,?,?,?,?)", -1, &s, NULL);
    sqlite3_bind_blob(s, 1, txid, 32, SQLITE_STATIC);
    sqlite3_bind_int(s, 2, height);
    sqlite3_bind_blob(s, 3, token_id, 32, SQLITE_STATIC);
    sqlite3_bind_int(s, 4, tx_type);
    sqlite3_bind_int64(s, 5, amount);
    sqlite3_bind_int(s, 6, vout);
    if (to_addr20) sqlite3_bind_blob(s, 7, to_addr20, 20, SQLITE_STATIC);
    else sqlite3_bind_null(s, 7);
    sqlite3_step(s);  // raw-sql-ok:test-fixture-insert
    sqlite3_finalize(s);
}

static void ins_output(struct node_db *ndb, const uint8_t txid[32], int vout,
                       int64_t value, const uint8_t addr20[20], int height)
{
    sqlite3_stmt *s = NULL;
    sqlite3_prepare_v2(ndb->db,
        "INSERT OR REPLACE INTO tx_outputs"
        "(txid,vout,value,script_type,address_hash,block_height)"
        " VALUES(?,?,?,1,?,?)", -1, &s, NULL);
    sqlite3_bind_blob(s, 1, txid, 32, SQLITE_STATIC);
    sqlite3_bind_int(s, 2, vout);
    sqlite3_bind_int64(s, 3, value);
    if (addr20) sqlite3_bind_blob(s, 4, addr20, 20, SQLITE_STATIC);
    else sqlite3_bind_null(s, 4);
    sqlite3_bind_int(s, 5, height);
    sqlite3_step(s);  // raw-sql-ok:test-fixture-insert
    sqlite3_finalize(s);
}

static void ins_input(struct node_db *ndb, const uint8_t txid[32],
                      int vin_index, const uint8_t prev_txid[32],
                      int prev_vout, int height)
{
    sqlite3_stmt *s = NULL;
    sqlite3_prepare_v2(ndb->db,
        "INSERT OR REPLACE INTO tx_inputs"
        "(txid,vin_index,prev_txid,prev_vout,block_height)"
        " VALUES(?,?,?,?,?)", -1, &s, NULL);
    sqlite3_bind_blob(s, 1, txid, 32, SQLITE_STATIC);
    sqlite3_bind_int(s, 2, vin_index);
    sqlite3_bind_blob(s, 3, prev_txid, 32, SQLITE_STATIC);
    sqlite3_bind_int(s, 4, prev_vout);
    sqlite3_bind_int(s, 5, height);
    sqlite3_step(s);  // raw-sql-ok:test-fixture-insert
    sqlite3_finalize(s);
}

static void ins_opreturn(struct node_db *ndb, const uint8_t txid[32],
                         int height, const uint8_t *script, size_t script_len)
{
    sqlite3_stmt *s = NULL;
    sqlite3_prepare_v2(ndb->db,
        "INSERT OR REPLACE INTO op_returns"
        "(txid,block_height,script,is_slp) VALUES(?,?,?,1)", -1, &s, NULL);
    sqlite3_bind_blob(s, 1, txid, 32, SQLITE_STATIC);
    sqlite3_bind_int(s, 2, height);
    sqlite3_bind_blob(s, 3, script, (int)script_len, SQLITE_STATIC);
    sqlite3_step(s);  // raw-sql-ok:test-fixture-insert
    sqlite3_finalize(s);
}

/* GENESIS at h=1: token T minted 1000 to addrA at (txid_genesis, vout 1).
 * SEND at h=2: spends (txid_genesis,1); 600 -> addrA (vout 1), 400 -> addrB
 * (vout 2), at txid_send. Seeds zslp_transfers + tx_outputs + tx_inputs. */
static void seed_fixture(struct node_db *ndb)
{
    fill(g_txid_genesis, 32, 0x11);
    fill(g_txid_send, 32, 0x22);
    memcpy(g_token, g_txid_genesis, 32);
    fill(g_addr_a, 20, 0xA1);
    fill(g_addr_b, 20, 0xB2);

    /* GENESIS (h=1). token_id of a GENESIS is that tx's own txid; here we use
     * a fixed token id for both sides — the ledger just collates on it. */
    ins_transfer(ndb, g_txid_genesis, 1, g_token, SLP_TX_GENESIS, 1000, 1,
                 g_addr_a);
    ins_output(ndb, g_txid_genesis, 1, 1 * COIN, g_addr_a, 1);
    uint8_t genesis_script[256];
    size_t genesis_len = slp_build_genesis(
        genesis_script, sizeof(genesis_script), "TST", "Strict Test", "",
        NULL, 0, 0, 1000);
    ins_opreturn(ndb, g_txid_genesis, 1, genesis_script, genesis_len);

    /* SEND (h=2). */
    ins_transfer(ndb, g_txid_send, 2, g_token, SLP_TX_SEND, 600, 1, g_addr_a);
    ins_transfer(ndb, g_txid_send, 2, g_token, SLP_TX_SEND, 400, 2, g_addr_b);
    ins_output(ndb, g_txid_send, 1, 1 * COIN, g_addr_a, 2);
    ins_output(ndb, g_txid_send, 2, 1 * COIN, g_addr_b, 2);
    ins_input(ndb, g_txid_send, 0, g_txid_genesis, 1, 2);
    struct uint256 wire_token;
    for (int i = 0; i < 32; i++)
        wire_token.data[i] = g_token[31 - i];
    uint64_t send_q[2] = {600, 400};
    uint8_t send_script[256];
    size_t send_len = slp_build_send(send_script, sizeof(send_script),
                                     &wire_token, send_q, 2);
    ins_opreturn(ndb, g_txid_send, 2, send_script, send_len);
}

/* ── (1)+(2)+(3) backfill: genesis, send, spend, balance, cursor ──── */

/* The run_once gate folds only up to the node_db catchup projection tip
 * (sync_projection_tip_height — the literal mirrors the private
 * SYNC_PROJECTION_TIP_HEIGHT_KEY in sync_controller_writers.c), so the
 * fixture must declare its seeded projections as committed. */
static void fixture_set_projection_tip(struct node_db *ndb, int64_t h)
{
    (void)node_db_state_set_int(ndb, "sync_projection_tip_height", h);
}

static int test_backfill_ledger(void)
{
    int failures = 0;
    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));

    printf("zslp_ledger: open in-memory node.db (schema v%d)... ",
           NODE_DB_MAX_SCHEMA);
    if (node_db_open(&ndb, ":memory:") && ndb.open) printf("OK\n");
    else { printf("FAIL\n"); return 1; }

    printf("zslp_ledger: schema_version is %d... ", NODE_DB_MAX_SCHEMA);
    { int v = node_db_schema_version(&ndb);
      if (v == NODE_DB_MAX_SCHEMA) printf("OK\n");
      else { printf("FAIL (got %d)\n", v); failures++; } }

    seed_fixture(&ndb);

    g_zslp_ledger_backfill_test_ndb = &ndb;
    zslp_ledger_backfill_reset_for_test();

    /* Fold only through h=1 first, so we can observe the GENESIS row BEFORE
     * the SEND spends it. */
    reducer_frontier_provable_tip_set(1);
    fixture_set_projection_tip(&ndb, 1);

    printf("zslp_ledger: backfill folds heights up to H*=1... ");
    { int folded = zslp_ledger_backfill_run_once();
      if (folded == 2) printf("OK\n"); /* h=0 (empty) + h=1 */
      else { printf("FAIL (folded=%d)\n", folded); failures++; } }

    printf("zslp_ledger: GENESIS created 1 unspent outpoint row... ");
    { int n = count_rows(&ndb, "SELECT COUNT(*) FROM zslp_ledger");
      int u = (int)zslp_ledger_unspent_count(&ndb);
      if (n == 1 && u == 1) printf("OK\n");
      else { printf("FAIL (rows=%d unspent=%d)\n", n, u); failures++; } }

    printf("zslp_ledger: holder balance(T,addrA) == 1000 (GENESIS)... ");
    { int64_t b = zslp_ledger_balance(&ndb, g_token, g_addr_a);
      if (b == 1000) printf("OK\n"); else { printf("FAIL (%lld)\n", (long long)b); failures++; } }

    /* Now advance to H*=2: the SEND spends GENESIS and mints two outputs. */
    reducer_frontier_provable_tip_set(2);
    fixture_set_projection_tip(&ndb, 2);

    printf("zslp_ledger: backfill folds h=2 (SEND)... ");
    { int folded = zslp_ledger_backfill_run_once();
      if (folded == 1) printf("OK\n"); else { printf("FAIL (folded=%d)\n", folded); failures++; } }

    printf("zslp_ledger: cursor advanced to H*=2... ");
    { int32_t c = -1; uint8_t d[32];
      zslp_ledger_get_cursor(&ndb, &c, d);
      if (c == 2) printf("OK\n"); else { printf("FAIL (cursor=%d)\n", c); failures++; } }

    printf("zslp_ledger: SEND created 2 rows, GENESIS marked spent "
           "(3 total, 2 unspent)... ");
    { int n = count_rows(&ndb, "SELECT COUNT(*) FROM zslp_ledger");
      int u = (int)zslp_ledger_unspent_count(&ndb);
      int sp = count_rows(&ndb,
          "SELECT COUNT(*) FROM zslp_ledger WHERE spent_by_txid IS NOT NULL");
      if (n == 3 && u == 2 && sp == 1) printf("OK\n");
      else { printf("FAIL (rows=%d unspent=%d spent=%d)\n", n, u, sp); failures++; } }

    printf("zslp_ledger: balance sums UNSPENT only — addrA==600 "
           "(1000 GENESIS spent + 600 SEND), addrB==400... ");
    { int64_t ba = zslp_ledger_balance(&ndb, g_token, g_addr_a);
      int64_t bb = zslp_ledger_balance(&ndb, g_token, g_addr_b);
      if (ba == 600 && bb == 400) printf("OK\n");
      else { printf("FAIL (addrA=%lld addrB=%lld)\n", (long long)ba, (long long)bb); failures++; } }

    printf("zslp_ledger: GENESIS outpoint spent_by == txid_send... ");
    { sqlite3_stmt *s = NULL; int ok = 0;
      sqlite3_prepare_v2(ndb.db,
        "SELECT spent_by_txid FROM zslp_ledger WHERE txid=? AND vout=1",
        -1, &s, NULL);
      sqlite3_bind_blob(s, 1, g_txid_genesis, 32, SQLITE_STATIC);
      if (sqlite3_step(s) == SQLITE_ROW &&  // raw-sql-ok:test-readonly-check
          sqlite3_column_bytes(s, 0) == 32 &&
          memcmp(sqlite3_column_blob(s, 0), g_txid_send, 32) == 0)
          ok = 1;
      sqlite3_finalize(s);
      if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; } }

    printf("zslp_ledger: idempotent once caught up (second run folds 0)... ");
    { int folded = zslp_ledger_backfill_run_once();
      if (folded == 0) printf("OK\n"); else { printf("FAIL (folded=%d)\n", folded); failures++; } }

    g_zslp_ledger_backfill_test_ndb = NULL;
    reducer_frontier_provable_tip_reset();
    node_db_close(&ndb);
    return failures;
}

/* ── (4) digest sensitivity + rebuild == original ─────────────────── */

static int test_digest_and_rebuild(void)
{
    int failures = 0;
    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));
    if (!node_db_open(&ndb, ":memory:") || !ndb.open) { printf("open FAIL\n"); return 1; }
    seed_fixture(&ndb);

    uint8_t zero[32] = {0};

    printf("zslp_ledger: an empty height still advances the digest... ");
    { uint8_t d0[32];
      zslp_ledger_apply_height(&ndb, 0, zero, d0);
      if (memcmp(d0, zero, 32) != 0) printf("OK\n");
      else { printf("FAIL\n"); failures++; } }

    printf("zslp_ledger: digest changes when a height's rows change "
           "(h=1 GENESIS vs empty h=0)... ");
    { uint8_t d_empty[32], d_genesis[32];
      zslp_ledger_apply_height(&ndb, 0, zero, d_empty);   /* no rows at h=0 */
      zslp_ledger_apply_height(&ndb, 1, zero, d_genesis); /* GENESIS at h=1 */
      if (memcmp(d_empty, d_genesis, 32) != 0) printf("OK\n");
      else { printf("FAIL\n"); failures++; } }

    /* Chain the full run to capture the reference digest, then rebuild. */
    g_zslp_ledger_backfill_test_ndb = &ndb;
    zslp_ledger_backfill_reset_for_test();
    reducer_frontier_provable_tip_set(2);
    fixture_set_projection_tip(&ndb, 2);

    printf("zslp_ledger: full fold reaches cursor=2... ");
    { (void)zslp_ledger_backfill_run_once();
      int32_t c = -1; uint8_t d[32];
      zslp_ledger_get_cursor(&ndb, &c, d);
      if (c == 2) printf("OK\n"); else { printf("FAIL (%d)\n", c); failures++; } }

    uint8_t digest_before[32]; int32_t cursor_before = -1;
    zslp_ledger_get_cursor(&ndb, &cursor_before, digest_before);
    int rows_before = count_rows(&ndb, "SELECT COUNT(*) FROM zslp_ledger");

    printf("zslp_ledger: truncate resets rows + cursor + digest... ");
    { bool ok = zslp_ledger_truncate(&ndb);
      int32_t c = -2; uint8_t d[32];
      zslp_ledger_get_cursor(&ndb, &c, d);
      int n = count_rows(&ndb, "SELECT COUNT(*) FROM zslp_ledger");
      ok = ok && c == -1 && n == 0 && memcmp(d, zero, 32) == 0;
      if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; } }

    printf("zslp_ledger: fresh re-derive reproduces exact rows + digest... ");
    { (void)zslp_ledger_backfill_run_once();
      int32_t c = -1; uint8_t d[32];
      zslp_ledger_get_cursor(&ndb, &c, d);
      int n = count_rows(&ndb, "SELECT COUNT(*) FROM zslp_ledger");
      bool ok = c == cursor_before && n == rows_before &&
                memcmp(d, digest_before, 32) == 0;
      if (ok) printf("OK\n");
      else { printf("FAIL (rows=%d/%d cursor=%d/%d)\n", n, rows_before, c, cursor_before); failures++; } }

    g_zslp_ledger_backfill_test_ndb = NULL;
    reducer_frontier_provable_tip_reset();
    node_db_close(&ndb);
    return failures;
}

/* ── (5) live per-block hook ──────────────────────────────────────── */

static int test_live_hook(void)
{
    int failures = 0;
    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));
    if (!node_db_open(&ndb, ":memory:") || !ndb.open) { printf("open FAIL\n"); return 1; }

    uint8_t addr[20]; fill(addr, 20, 0xC3);

    /* A GENESIS tx: vout[0] OP_RETURN (ignored), vout[1] P2PKH holding the
     * token. */
    struct transaction tx;
    transaction_init(&tx);
    transaction_alloc(&tx, 1, 2);
    uint256_set_null(&tx.vin[0].prevout.hash);
    tx.vin[0].prevout.n = 0xFFFFFFFFu;
    tx.vin[0].sequence = 0xFFFFFFFFu;
    tx.vout[0].script_pub_key.data[0] = 0x6a; /* OP_RETURN */
    tx.vout[0].script_pub_key.size = 1;
    tx.vout[0].value = 0;
    {
        struct script *sp = &tx.vout[1].script_pub_key;
        sp->data[0] = 0x76; sp->data[1] = 0xa9; sp->data[2] = 0x14;
        memcpy(sp->data + 3, addr, 20);
        sp->data[23] = 0x88; sp->data[24] = 0xac;
        sp->size = 25;
    }
    tx.vout[1].value = 1 * COIN;
    transaction_compute_hash(&tx);

    struct slp_message m;
    memset(&m, 0, sizeof(m));
    m.type = SLP_TX_GENESIS;
    m.initial_quantity = 777;

    printf("zslp_ledger live: GENESIS hook creates the vout[1] row... ");
    { zslp_ledger_apply_slp_live(&ndb, &tx, &m, 10);
      int n = count_rows(&ndb, "SELECT COUNT(*) FROM zslp_ledger");
      int64_t b = zslp_ledger_balance(&ndb, tx.hash.data, addr);
      if (n == 1 && b == 777) printf("OK\n");
      else { printf("FAIL (rows=%d bal=%lld)\n", n, (long long)b); failures++; } }

    printf("zslp_ledger live: idempotent re-apply (still 1 row)... ");
    { zslp_ledger_apply_slp_live(&ndb, &tx, &m, 10);
      int n = count_rows(&ndb, "SELECT COUNT(*) FROM zslp_ledger");
      if (n == 1) printf("OK\n"); else { printf("FAIL (%d)\n", n); failures++; } }

    /* A spending tx consumes (tx, vout 1); the live hook marks it spent. */
    struct transaction spend;
    transaction_init(&spend);
    transaction_alloc(&spend, 1, 1);
    memcpy(spend.vin[0].prevout.hash.data, tx.hash.data, 32);
    spend.vin[0].prevout.n = 1;
    spend.vin[0].sequence = 0xFFFFFFFFu;
    spend.vout[0].script_pub_key.data[0] = 0x6a;
    spend.vout[0].script_pub_key.size = 1;
    spend.vout[0].value = 0;
    transaction_compute_hash(&spend);

    struct slp_message ms;
    memset(&ms, 0, sizeof(ms));
    ms.type = SLP_TX_INVALID; /* a plain spend carrying no SLP output side */

    printf("zslp_ledger live: spending input marks the outpoint spent... ");
    { zslp_ledger_apply_slp_live(&ndb, &spend, &ms, 11);
      int u = (int)zslp_ledger_unspent_count(&ndb);
      int64_t b = zslp_ledger_balance(&ndb, tx.hash.data, addr);
      if (u == 0 && b == 0) printf("OK\n");
      else { printf("FAIL (unspent=%d bal=%lld)\n", u, (long long)b); failures++; } }

    transaction_free(&tx);
    transaction_free(&spend);
    node_db_close(&ndb);
    return failures;
}

/* ── (6) wallet-wide sweep ─────────────────────────────────────────────
 *
 * zslp_ledger_balance answers for ONE (token, address) pair; the wallet-wide
 * sweep answers "what does this node own" by folding the same rows over
 * every address the wallet holds. The fixture puts 600 at addrA and 400 at
 * addrB, so the three cases that matter are: a wallet holding neither
 * address (empty, not an error), a wallet holding one (600), and a wallet
 * holding both across wallet_keys AND wallet_watch_only (1000). */

static void ins_wallet_key(struct node_db *ndb, const uint8_t hash160[20])
{
    sqlite3_stmt *s = NULL;
    sqlite3_prepare_v2(ndb->db,
        "INSERT OR REPLACE INTO wallet_keys"
        "(pubkey_hash,pubkey,privkey,compressed,created_at)"
        " VALUES(?,zeroblob(33),zeroblob(32),1,0)", -1, &s, NULL);
    sqlite3_bind_blob(s, 1, hash160, 20, SQLITE_STATIC);
    sqlite3_step(s);  // raw-sql-ok:test-fixture-insert
    sqlite3_finalize(s);
}

static void ins_watch_only(struct node_db *ndb, const uint8_t hash160[20],
                           const char *address)
{
    sqlite3_stmt *s = NULL;
    sqlite3_prepare_v2(ndb->db,
        "INSERT OR REPLACE INTO wallet_watch_only"
        "(address_hash,address,created_at) VALUES(?,?,0)", -1, &s, NULL);
    sqlite3_bind_blob(s, 1, hash160, 20, SQLITE_STATIC);
    sqlite3_bind_text(s, 2, address, -1, SQLITE_STATIC);
    sqlite3_step(s);  // raw-sql-ok:test-fixture-insert
    sqlite3_finalize(s);
}

static int test_wallet_wide_sweep(void)
{
    int failures = 0;
    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));

    printf("zslp_ledger wallet: open in-memory node.db... ");
    if (node_db_open(&ndb, ":memory:") && ndb.open) printf("OK\n");
    else { printf("FAIL\n"); return 1; }

    seed_fixture(&ndb);
    g_zslp_ledger_backfill_test_ndb = &ndb;
    zslp_ledger_backfill_reset_for_test();
    reducer_frontier_provable_tip_set(2);
    fixture_set_projection_tip(&ndb, 2);
    (void)zslp_ledger_backfill_run_once();

    struct zslp_wallet_token held[8];

    /* THE empty case: unspent token rows exist, but none of them is ours. */
    printf("zslp_ledger wallet: a wallet with no keys sweeps to 0 rows "
           "(empty, not an error)... ");
    { int n = zslp_ledger_wallet_tokens(&ndb, held, 8);
      int64_t a = zslp_ledger_wallet_address_count(&ndb);
      int64_t b = zslp_ledger_wallet_balance(&ndb, g_token);
      if (n == 0 && a == 0 && b == 0) printf("OK\n");
      else { printf("FAIL (rows=%d addrs=%lld bal=%lld)\n", n,
                    (long long)a, (long long)b); failures++; } }

    /* One owned address: the wallet-wide answer equals the per-address one. */
    ins_wallet_key(&ndb, g_addr_a);

    printf("zslp_ledger wallet: one owned address folds to that address's "
           "balance (600)... ");
    { int n = zslp_ledger_wallet_tokens(&ndb, held, 8);
      int64_t per_addr = zslp_ledger_balance(&ndb, g_token, g_addr_a);
      if (n == 1 && memcmp(held[0].token_id, g_token, 32) == 0 &&
          held[0].balance == 600 && held[0].balance == per_addr &&
          held[0].utxo_count == 1) printf("OK\n");
      else { printf("FAIL (rows=%d bal=%lld per_addr=%lld utxos=%lld)\n", n,
                    (long long)held[0].balance, (long long)per_addr,
                    (long long)held[0].utxo_count); failures++; } }

    /* Second address arrives as WATCH-ONLY: the sweep must cross both
     * tables, not just wallet_keys. */
    ins_watch_only(&ndb, g_addr_b, "t1FixtureWatchOnlyAddressForAddrB");

    printf("zslp_ledger wallet: watch-only address joins the fold — "
           "600 + 400 == 1000 across 2 outpoints... ");
    { int n = zslp_ledger_wallet_tokens(&ndb, held, 8);
      int64_t a = zslp_ledger_wallet_address_count(&ndb);
      int64_t total = zslp_ledger_wallet_balance(&ndb, g_token);
      if (n == 1 && held[0].balance == 1000 && held[0].utxo_count == 2 &&
          total == 1000 && a == 2) printf("OK\n");
      else { printf("FAIL (rows=%d bal=%lld utxos=%lld total=%lld addrs=%lld)\n",
                    n, (long long)held[0].balance,
                    (long long)held[0].utxo_count, (long long)total,
                    (long long)a); failures++; } }

    /* The spent GENESIS outpoint also sat at addrA. A credit-only fold would
     * report 1600; a debit-correct one reports 1000. */
    printf("zslp_ledger wallet: sweep counts UNSPENT rows only "
           "(spent GENESIS excluded)... ");
    { int64_t total = zslp_ledger_wallet_balance(&ndb, g_token);
      int64_t rows = zslp_ledger_count(&ndb);
      if (total == 1000 && rows == 3) printf("OK\n");
      else { printf("FAIL (total=%lld rows=%lld)\n", (long long)total,
                    (long long)rows); failures++; } }

    printf("zslp_ledger wallet: a zero-capacity sweep writes nothing and "
           "returns 0... ");
    { int n = zslp_ledger_wallet_tokens(&ndb, held, 0);
      if (n == 0) printf("OK\n");
      else { printf("FAIL (rows=%d)\n", n); failures++; } }

    printf("zslp_ledger wallet: an unheld token id sweeps to balance 0... ");
    { uint8_t other[32];
      fill(other, 32, 0xEE);
      int64_t b = zslp_ledger_wallet_balance(&ndb, other);
      if (b == 0) printf("OK\n");
      else { printf("FAIL (%lld)\n", (long long)b); failures++; } }

    g_zslp_ledger_backfill_test_ndb = NULL;
    reducer_frontier_provable_tip_reset();
    node_db_close(&ndb);
    return failures;
}

static void make_wire_token(const uint8_t internal[32], struct uint256 *wire)
{
    for (int i = 0; i < 32; i++)
        wire->data[i] = internal[31 - i];
}

static void seed_send_decl(struct node_db *ndb, const uint8_t txid[32],
                           int height, const uint8_t token[32],
                           const uint64_t *quantities, int count)
{
    struct uint256 wire;
    make_wire_token(token, &wire);
    uint8_t script[256];
    size_t len = slp_build_send(script, sizeof(script), &wire,
                                quantities, count);
    ins_opreturn(ndb, txid, height, script, len);
    for (int i = 0; i < count; i++)
        if (quantities[i] > 0) {
            uint8_t addr[20];
            fill(addr, sizeof(addr), (uint8_t)(0xD0 + i));
            ins_output(ndb, txid, i + 1, 546, addr, height);
            ins_transfer(ndb, txid, height, token, SLP_TX_SEND,
                         (int64_t)quantities[i], i + 1, addr);
        }
}

static int test_strict_validity_rejections(void)
{
    int failures = 0;
    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));
    if (!node_db_open(&ndb, ":memory:") || !ndb.open) return 1;
    seed_fixture(&ndb);

    uint8_t inflation[32], forged_mint[32], second_genesis[32];
    uint8_t mixed[32], missing_parent[32], missing_child[32], burn[32];
    fill(inflation, 32, 0x33);
    fill(forged_mint, 32, 0x44);
    fill(second_genesis, 32, 0x55);
    fill(mixed, 32, 0x66);
    fill(missing_parent, 32, 0x77);
    fill(missing_child, 32, 0x88);
    fill(burn, 32, 0x99);

    uint64_t inflated_q[1] = {601};
    seed_send_decl(&ndb, inflation, 3, g_token, inflated_q, 1);
    ins_input(&ndb, inflation, 0, g_txid_send, 1, 3);

    uint64_t burn_q[1] = {250};
    seed_send_decl(&ndb, burn, 3, g_token, burn_q, 1);
    ins_input(&ndb, burn, 0, g_txid_send, 2, 3);

    struct uint256 wire;
    make_wire_token(g_token, &wire);
    uint8_t mint_script[256];
    size_t mint_len = slp_build_mint(mint_script, sizeof(mint_script),
                                     &wire, 2, 10);
    ins_opreturn(&ndb, forged_mint, 3, mint_script, mint_len);
    uint8_t mint_addr[20]; fill(mint_addr, sizeof(mint_addr), 0xE1);
    ins_output(&ndb, forged_mint, 1, 546, mint_addr, 3);
    ins_output(&ndb, forged_mint, 2, 546, mint_addr, 3);

    uint8_t second_script[256];
    size_t second_len = slp_build_genesis(
        second_script, sizeof(second_script), "TWO", "Second", "", NULL,
        0, 0, 50);
    ins_opreturn(&ndb, second_genesis, 3, second_script, second_len);
    uint8_t second_addr[20]; fill(second_addr, sizeof(second_addr), 0xE2);
    ins_output(&ndb, second_genesis, 1, 546, second_addr, 3);

    uint64_t mixed_q[1] = {400};
    seed_send_decl(&ndb, mixed, 4, g_token, mixed_q, 1);
    ins_input(&ndb, mixed, 0, g_txid_send, 2, 4);
    ins_input(&ndb, mixed, 1, second_genesis, 1, 4);

    /* Metadata names a token parent, but the raw parent declaration and
     * outpoint are missing. Descendants stay UNKNOWN, never INVALID/VALID. */
    ins_transfer(&ndb, missing_parent, 0, g_token, SLP_TX_SEND, 5, 1, NULL);
    uint64_t missing_q[1] = {5};
    seed_send_decl(&ndb, missing_child, 4, g_token, missing_q, 1);
    ins_input(&ndb, missing_child, 0, missing_parent, 1, 4);

    uint8_t digest[32] = {0}, next[32];
    for (int h = 0; h <= 4; h++) {
        if (!zslp_ledger_apply_height(&ndb, h, digest, next)) {
            failures++;
            break;
        }
        memcpy(digest, next, sizeof(digest));
    }

    char reason[96];
    printf("zslp strict: inflationary SEND is INVALID and creates no output... ");
    bool ok = zslp_validity_get(&ndb, inflation, reason, sizeof(reason)) ==
                  ZSLP_VALIDITY_INVALID &&
              strcmp(reason, "send_output_exceeds_input") == 0 &&
              count_rows(&ndb,
                "SELECT COUNT(*) FROM zslp_ledger WHERE txid=x'3333333333333333333333333333333333333333333333333333333333333333'") == 0;
    if (ok) printf("OK\n"); else { printf("FAIL (%s)\n", reason); failures++; }

    printf("zslp strict: forged MINT without current baton is INVALID... ");
    ok = zslp_validity_get(&ndb, forged_mint, reason, sizeof(reason)) ==
             ZSLP_VALIDITY_INVALID &&
         strcmp(reason, "mint_baton_lineage_invalid") == 0;
    if (ok) printf("OK\n"); else { printf("FAIL (%s)\n", reason); failures++; }

    printf("zslp strict: SEND mixing valid token ids is INVALID... ");
    ok = zslp_validity_get(&ndb, mixed, reason, sizeof(reason)) ==
             ZSLP_VALIDITY_INVALID && strcmp(reason, "mixed_token_inputs") == 0;
    if (ok) printf("OK\n"); else { printf("FAIL (%s)\n", reason); failures++; }

    printf("zslp strict: missing declared ancestry remains UNKNOWN... ");
    ok = zslp_validity_get(&ndb, missing_child, reason, sizeof(reason)) ==
             ZSLP_VALIDITY_UNKNOWN && strcmp(reason, "send_parent_unknown") == 0;
    if (ok) printf("OK\n"); else { printf("FAIL (%s)\n", reason); failures++; }

    printf("zslp strict: conservative SEND records the explicit burn... ");
    struct zslp_token_validity_summary summary;
    ok = zslp_validity_get(&ndb, burn, reason, sizeof(reason)) ==
             ZSLP_VALIDITY_VALID && strcmp(reason, "valid_send") == 0 &&
         zslp_validity_token_summary(&ndb, g_token, &summary) &&
         summary.total_minted == 1000 && summary.total_burned == 150 &&
         summary.circulating_supply == 850;
    if (ok) printf("OK\n"); else { printf("FAIL (%s)\n", reason); failures++; }

    node_db_close(&ndb);
    return failures;
}

/* ── Entry point ──────────────────────────────────────────────────── */

int test_zslp_ledger(void)
{
    int failures = 0;
    printf("\n=== ZSLP per-(token,outpoint) Ledger Tests ===\n");
    failures += test_backfill_ledger();
    failures += test_digest_and_rebuild();
    failures += test_live_hook();
    failures += test_wallet_wide_sweep();
    failures += test_strict_validity_rejections();
    return failures;
}
