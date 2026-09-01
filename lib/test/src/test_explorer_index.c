/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Full per-block explorer indexer fixture test.
 *
 * Builds one synthetic block with a transparent output, a transparent
 * input, and an OP_RETURN output, runs the single per-block indexer hook
 * (explorer_index_block) against an in-memory node.db, and asserts the
 * corresponding rows land in tx_outputs / tx_inputs / op_returns /
 * view_integrity. Proves the indexer populates the projection tables and
 * is idempotent under a re-walk (INSERT OR REPLACE). node.db only. */

#include "test/test_core.h"
#include "models/database.h"
#include "models/explorer_index.h"
#include "models/znam.h"
#include "znam/znam.h"
#include "primitives/transaction.h"
#include "primitives/block.h"
#include "chain/chain.h"

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

/* Seed a spendable tx_output owned by `addr20` at outpoint (byte×32, n), so
 * a later tx spending it resolves that address as its ZNAM owner. */
static void seed_owner_utxo(struct node_db *ndb, uint8_t prevbyte,
                            uint32_t n, const uint8_t addr20[20], int height)
{
    uint8_t txid[32];
    memset(txid, prevbyte, 32);
    db_tx_output_save(ndb, txid, n, 5 * COIN, 0, addr20, height);
}

/* Build a one-tx block whose tx spends outpoint (prevbyte×32, prevn) and
 * carries `script` (a full OP_RETURN scriptPubKey) as its sole output, then
 * run the per-block indexer at `height`. The spender's first-input address
 * (from the seeded prevout) becomes the ZNAM owner apply_znam authorizes on. */
static bool run_znam_op(struct node_db *ndb, const uint8_t *script,
                        size_t slen, uint8_t prevbyte, uint32_t prevn,
                        int height)
{
    struct transaction tx;
    transaction_init(&tx);
    transaction_alloc(&tx, 1, 1);
    memset(tx.vin[0].prevout.hash.data, prevbyte, 32);
    tx.vin[0].prevout.n = prevn;
    tx.vin[0].sequence = 0xFFFFFFFFu;
    tx.vin[0].script_sig.size = 0;
    tx.vout[0].value = 0;
    memcpy(tx.vout[0].script_pub_key.data, script, slen);
    tx.vout[0].script_pub_key.size = slen;
    tx.lock_time = 0;
    transaction_compute_hash(&tx);

    struct block blk;
    block_init(&blk);
    blk.vtx = &tx;
    blk.num_vtx = 1;
    blk.header.nTime = 1700000000u + (uint32_t)height;

    struct uint256 bhash;
    memset(bhash.data, 0x50, 32);
    bhash.data[0] = (uint8_t)height;
    bhash.data[1] = (uint8_t)(height >> 8);
    struct block_index pindex;
    memset(&pindex, 0, sizeof(pindex));
    pindex.nHeight = height;
    pindex.phashBlock = &bhash;

    uint8_t prev_receipt[32] = {0}, out_receipt[32];
    bool ok = explorer_index_block(ndb, &blk, &pindex, prev_receipt,
                                   out_receipt, NULL, NULL);
    blk.vtx = NULL;
    blk.num_vtx = 0;
    transaction_free(&tx);
    return ok;
}

/* Owner-authorization + RENEW-fold regressions for apply_znam (path A).
 * Bug 1: SET_RECORD/SET_TEXT applied with no owner check (identity spoof).
 * Bug 2: RENEW was a silent no-op. */
static int test_znam_apply_auth(struct node_db *ndb)
{
    int failures = 0;
    uint8_t ownerA[20], attackerB[20];
    memset(ownerA, 0x11, 20);
    memset(attackerB, 0x22, 20);

    /* Distinct UTXOs owned by A (0xA1..0xA4) and by attacker B (0xB1). */
    seed_owner_utxo(ndb, 0xA1, 0, ownerA, 10);
    seed_owner_utxo(ndb, 0xA2, 0, ownerA, 10);
    seed_owner_utxo(ndb, 0xA3, 0, ownerA, 10);
    seed_owner_utxo(ndb, 0xA4, 0, ownerA, 10);
    seed_owner_utxo(ndb, 0xB1, 0, attackerB, 10);

    uint8_t buf[256];
    size_t len;

    /* REGISTER znexample by owner A → sets owner + expiry_height. */
    printf("znam apply: REGISTER sets expiry_height... ");
    len = znam_build_register(buf, sizeof(buf), "znexample",
                              ZNAM_TYPE_TADDR, "t1ownertarget");
    run_znam_op(ndb, buf, len, 0xA1, 0, 100);
    struct znam_entry e0 = {0};
    bool reg_ok = db_znam_find(ndb, "znexample", &e0);
    if (reg_ok && e0.expiry_height == 100 + ZNAM_REGISTRATION_TERM_BLOCKS &&
        e0.owner_address[0] != '\0')
        printf("OK\n");
    else { printf("FAIL (find=%d expiry=%d)\n", reg_ok, e0.expiry_height);
           failures++; }

    /* Bug 1a: attacker SET_RECORD must be REJECTED (no addr row written). */
    printf("znam apply: non-owner SET_RECORD rejected... ");
    len = znam_build_set_record(buf, sizeof(buf), "znexample",
                                ZNAM_TYPE_BTC, "1AttackerBtcAddr");
    run_znam_op(ndb, buf, len, 0xB1, 0, 101);
    char addr[256] = {0};
    bool leaked = db_znam_addr_get(ndb, "znexample", ZNAM_TYPE_BTC,
                                   addr, sizeof(addr));
    if (!leaked) printf("OK\n");
    else { printf("FAIL (attacker wrote %s)\n", addr); failures++; }

    /* Owner SET_RECORD succeeds. */
    printf("znam apply: owner SET_RECORD succeeds... ");
    len = znam_build_set_record(buf, sizeof(buf), "znexample",
                                ZNAM_TYPE_BTC, "1OwnerBtcAddr");
    run_znam_op(ndb, buf, len, 0xA2, 0, 102);
    memset(addr, 0, sizeof(addr));
    bool wrote = db_znam_addr_get(ndb, "znexample", ZNAM_TYPE_BTC,
                                  addr, sizeof(addr));
    if (wrote && strcmp(addr, "1OwnerBtcAddr") == 0) printf("OK\n");
    else { printf("FAIL (wrote=%d addr=%s)\n", wrote, addr); failures++; }

    /* Bug 1b: attacker SET_TEXT must be REJECTED. */
    printf("znam apply: non-owner SET_TEXT rejected... ");
    len = znam_build_set_text(buf, sizeof(buf), "znexample",
                              "onion", "evil.onion");
    run_znam_op(ndb, buf, len, 0xB1, 0, 103);
    char txt[256] = {0};
    bool tleaked = db_znam_text_get(ndb, "znexample", "onion",
                                    txt, sizeof(txt));
    if (!tleaked) printf("OK\n");
    else { printf("FAIL (attacker wrote %s)\n", txt); failures++; }

    /* Owner SET_TEXT succeeds. */
    printf("znam apply: owner SET_TEXT succeeds... ");
    len = znam_build_set_text(buf, sizeof(buf), "znexample",
                              "onion", "good.onion");
    run_znam_op(ndb, buf, len, 0xA3, 0, 104);
    memset(txt, 0, sizeof(txt));
    bool twrote = db_znam_text_get(ndb, "znexample", "onion",
                                   txt, sizeof(txt));
    if (twrote && strcmp(txt, "good.onion") == 0) printf("OK\n");
    else { printf("FAIL (wrote=%d txt=%s)\n", twrote, txt); failures++; }

    /* Bug 2: RENEW advances expiry_height by one registration term. */
    printf("znam apply: RENEW extends expiry_height... ");
    int32_t expiry_before = e0.expiry_height;   /* 100 + TERM */
    len = znam_build_renew(buf, sizeof(buf), "znexample");
    run_znam_op(ndb, buf, len, 0xA4, 0, 105);
    struct znam_entry e1 = {0};
    bool renew_ok = db_znam_find(ndb, "znexample", &e1);
    /* base = max(expiry_before, 105) = expiry_before; +TERM again. */
    if (renew_ok &&
        e1.expiry_height == expiry_before + ZNAM_REGISTRATION_TERM_BLOCKS)
        printf("OK\n");
    else { printf("FAIL (renew=%d expiry=%d want=%d)\n", renew_ok,
                  e1.expiry_height,
                  expiry_before + ZNAM_REGISTRATION_TERM_BLOCKS);
           failures++; }

    return failures;
}

int test_explorer_index(void)
{
    int failures = 0;
    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));

    printf("explorer_index: open in-memory node.db... ");
    if (node_db_open(&ndb, ":memory:") && ndb.open) {
        printf("OK\n");
    } else {
        printf("FAIL\n");
        return 1;   /* nothing else can run */
    }

    /* Build one tx: 1 real (non-coinbase) input, 2 outputs — a transparent
     * P2PKH output and an OP_RETURN output. */
    struct transaction tx;
    transaction_init(&tx);
    transaction_alloc(&tx, 1, 2);

    /* Input spends a known prevout. */
    uint256_set_null(&tx.vin[0].prevout.hash);
    tx.vin[0].prevout.hash.data[0] = 0xAB;
    tx.vin[0].prevout.n = 7;
    tx.vin[0].sequence = 0xFFFFFFFFu;
    tx.vin[0].script_sig.size = 0;

    /* vout[0]: P2PKH scriptPubKey (OP_DUP OP_HASH160 <20> OP_EQUALVERIFY
     * OP_CHECKSIG) so utxo_classify_script extracts an address. */
    tx.vout[0].value = 5 * COIN;
    {
        struct script *sp = &tx.vout[0].script_pub_key;
        sp->data[0] = 0x76;        /* OP_DUP */
        sp->data[1] = 0xa9;        /* OP_HASH160 */
        sp->data[2] = 0x14;        /* push 20 */
        for (int i = 0; i < 20; i++)
            sp->data[3 + i] = (unsigned char)(0x10 + i);
        sp->data[23] = 0x88;       /* OP_EQUALVERIFY */
        sp->data[24] = 0xac;       /* OP_CHECKSIG */
        sp->size = 25;
    }

    /* vout[1]: OP_RETURN with arbitrary payload. */
    tx.vout[1].value = 0;
    {
        struct script *sp = &tx.vout[1].script_pub_key;
        sp->data[0] = 0x6a;        /* OP_RETURN */
        sp->data[1] = 0x04;        /* push 4 */
        sp->data[2] = 'D'; sp->data[3] = 'A'; sp->data[4] = 'T'; sp->data[5] = 'A';
        sp->size = 6;
    }
    tx.lock_time = 0;
    transaction_compute_hash(&tx);

    /* Wrap in a one-tx block at height 1. */
    struct block blk;
    block_init(&blk);
    blk.vtx = &tx;
    blk.num_vtx = 1;
    blk.header.nTime = 1700000000;

    struct uint256 bhash;
    memset(bhash.data, 0x42, 32);
    struct block_index pindex;
    memset(&pindex, 0, sizeof(pindex));
    pindex.nHeight = 1;
    pindex.phashBlock = &bhash;

    uint8_t prev_receipt[32] = {0};
    uint8_t out_receipt[32];
    int64_t sprout_v = 0, sapling_v = 0;

    printf("explorer_index: index one synthetic block... ");
    bool indexed = explorer_index_block(&ndb, &blk, &pindex, prev_receipt,
                                        out_receipt, &sprout_v, &sapling_v);
    if (indexed) printf("OK\n");
    else { printf("FAIL\n"); failures++; }

    printf("explorer_index: tx_outputs has 2 rows... ");
    { int n = count_rows(&ndb, "SELECT COUNT(*) FROM tx_outputs");
      if (n == 2) printf("OK\n"); else { printf("FAIL (got %d)\n", n); failures++; } }

    printf("explorer_index: P2PKH output recorded an address_hash... ");
    { int n = count_rows(&ndb,
        "SELECT COUNT(*) FROM tx_outputs WHERE address_hash IS NOT NULL");
      if (n == 1) printf("OK\n"); else { printf("FAIL (got %d)\n", n); failures++; } }

    printf("explorer_index: tx_inputs has 1 row (input recorded)... ");
    { int n = count_rows(&ndb, "SELECT COUNT(*) FROM tx_inputs");
      if (n == 1) printf("OK\n"); else { printf("FAIL (got %d)\n", n); failures++; } }

    printf("explorer_index: op_returns has 1 row... ");
    { int n = count_rows(&ndb, "SELECT COUNT(*) FROM op_returns");
      if (n == 1) printf("OK\n"); else { printf("FAIL (got %d)\n", n); failures++; } }

    printf("explorer_index: view_integrity has 1 row for the height... ");
    { int n = count_rows(&ndb, "SELECT COUNT(*) FROM view_integrity WHERE height=1");
      if (n == 1) printf("OK\n"); else { printf("FAIL (got %d)\n", n); failures++; } }

    printf("explorer_index: model reads the exact receipt height... ");
    { uint8_t got[32] = {0};
      if (db_view_integrity_get(&ndb, 1, got) &&
          memcmp(got, out_receipt, 32) == 0)
          printf("OK\n");
      else { printf("FAIL\n"); failures++; } }

    printf("explorer_index: missing/negative receipt leaves output untouched... ");
    { uint8_t sentinel[32], before[32];
      memset(sentinel, 0x6C, sizeof(sentinel));
      memcpy(before, sentinel, sizeof(before));
      bool missing = db_view_integrity_get(&ndb, 99, sentinel);
      bool negative = db_view_integrity_get(&ndb, -1, sentinel);
      if (!missing && !negative && memcmp(sentinel, before, 32) == 0)
          printf("OK\n");
      else { printf("FAIL\n"); failures++; } }

    /* Idempotency: re-index the same block; INSERT OR REPLACE must not
     * duplicate any row. */
    printf("explorer_index: re-index is idempotent (no duplicate rows)... ");
    bool reindexed = explorer_index_block(&ndb, &blk, &pindex, prev_receipt,
                                          out_receipt, &sprout_v, &sapling_v);
    int n_out = count_rows(&ndb, "SELECT COUNT(*) FROM tx_outputs");
    int n_in  = count_rows(&ndb, "SELECT COUNT(*) FROM tx_inputs");
    int n_or  = count_rows(&ndb, "SELECT COUNT(*) FROM op_returns");
    int n_vi  = count_rows(&ndb, "SELECT COUNT(*) FROM view_integrity");
    if (reindexed && n_out == 2 && n_in == 1 && n_or == 1 && n_vi == 1)
        printf("OK\n");
    else { printf("FAIL (out=%d in=%d or=%d vi=%d)\n", n_out, n_in, n_or, n_vi);
           failures++; }

    /* The integrity receipt must be deterministic + non-zero. */
    printf("explorer_index: integrity receipt is non-zero + deterministic... ");
    { uint8_t zero[32] = {0};
      uint8_t r2[32];
      explorer_index_block(&ndb, &blk, &pindex, prev_receipt, r2, NULL, NULL);
      if (memcmp(out_receipt, zero, 32) != 0 &&
          memcmp(out_receipt, r2, 32) == 0)
          printf("OK\n");
      else { printf("FAIL\n"); failures++; } }

    printf("explorer_index: receipt read selects adjacent heights exactly... ");
    { uint8_t second[32], got_first[32] = {0}, got_second[32] = {0};
      memset(second, 0xA5, sizeof(second));
      bool saved = db_view_integrity_save(&ndb, 2, second);
      bool first_ok = db_view_integrity_get(&ndb, 1, got_first);
      bool second_ok = db_view_integrity_get(&ndb, 2, got_second);
      if (saved && first_ok && second_ok &&
          memcmp(got_first, out_receipt, 32) == 0 &&
          memcmp(got_second, second, 32) == 0)
          printf("OK\n");
      else { printf("FAIL\n"); failures++; } }

    printf("explorer_index: malformed receipt lengths leave output untouched... ");
    { uint8_t sentinel[32], before[32];
      memset(sentinel, 0x3D, sizeof(sentinel));
      memcpy(before, sentinel, sizeof(before));
      int rc = sqlite3_exec(ndb.db,
          "INSERT INTO view_integrity(height,sha3_hash) VALUES"
          "(3,x'0102'),(4,zeroblob(33))",
          NULL, NULL, NULL); // raw-sql-ok:test-malformed-receipt-fixture
      bool short_found = db_view_integrity_get(&ndb, 3, sentinel);
      bool long_found = db_view_integrity_get(&ndb, 4, sentinel);
      if (rc == SQLITE_OK && !short_found && !long_found &&
          memcmp(sentinel, before, 32) == 0)
          printf("OK\n");
      else { printf("FAIL\n"); failures++; } }

    blk.vtx = NULL;   /* tx is stack-local; don't let block_free touch it */
    blk.num_vtx = 0;
    transaction_free(&tx);

    /* ZNAM apply-path authorization + RENEW regressions (same node.db). */
    failures += test_znam_apply_auth(&ndb);

    node_db_close(&ndb);

    printf("explorer_index: closed-db receipt read leaves output untouched... ");
    { uint8_t sentinel[32], before[32];
      memset(sentinel, 0xB7, sizeof(sentinel));
      memcpy(before, sentinel, sizeof(before));
      bool found = db_view_integrity_get(&ndb, 1, sentinel);
      if (!found && memcmp(sentinel, before, 32) == 0)
          printf("OK\n");
      else { printf("FAIL\n"); failures++; } }

    return failures;
}
