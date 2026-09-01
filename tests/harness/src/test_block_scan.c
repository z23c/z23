/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Tests for block file scanning, nChainTx propagation, and
 * BLOCK_FAILED_CHILD propagation. */

#include "test/test_core.h"
#include "storage/coins_view_sqlite.h"
#include "chain/chain.h"
#include "chain/chainparams.h"
#include "chain/pow.h"
#include "validation/chainstate.h"
#include "validation/process_block.h"
#include "primitives/block.h"
#include "core/serialize.h"
#include "controllers/wallet_scan.h"
#include "services/wallet_scan_service.h"
#include "services/legacy_import_service.h"
#include "models/database.h"
#include "models/wallet_tx.h"
#include "config/boot_cursor_state.h"
#include "wallet/wallet.h"
#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

/* ── block_index_cmp_height ────────────────────────────────────── */

static int test_cmp_height(void)
{
    printf("GIVEN block_index entries at h=5, h=2, h=9 "
           "WHEN sorted THEN ascending... ");

    struct block_index a = {0}, b = {0}, c = {0};
    a.nHeight = 5; b.nHeight = 2; c.nHeight = 9;
    struct block_index *arr[3] = {&a, &b, &c};
    qsort(arr, 3, sizeof(struct block_index *), block_index_cmp_height);

    if (arr[0]->nHeight == 2 && arr[1]->nHeight == 5 &&
        arr[2]->nHeight == 9) {
        printf("OK\n"); return 0;
    }
    printf("FAIL (got %d,%d,%d)\n",
           arr[0]->nHeight, arr[1]->nHeight, arr[2]->nHeight);
    return 1;
}

/* ── BLOCK_FAILED_CHILD propagation via height-sorted pass ──── */

static int test_failed_child_propagation(void)
{
    printf("GIVEN parent BLOCK_FAILED_VALID "
           "WHEN propagate THEN children+grandchildren marked... ");

    /* Build a small chain: genesis → A → B → C (all same height for simplicity) */
    struct block_index genesis = {0}, a = {0}, b = {0}, c = {0}, orphan = {0};
    block_index_init(&genesis);
    block_index_init(&a);
    block_index_init(&b);
    block_index_init(&c);
    block_index_init(&orphan);

    genesis.nHeight = 0;
    a.nHeight = 1; a.pprev = &genesis;
    b.nHeight = 2; b.pprev = &a;
    c.nHeight = 3; c.pprev = &b;
    orphan.nHeight = 2; orphan.pprev = &genesis; /* different branch */

    /* Mark 'a' as failed */
    a.nStatus |= BLOCK_FAILED_VALID;

    /* Collect blocks above the failed height, sort, propagate */
    struct block_index *all[] = {&b, &c, &orphan};
    qsort(all, 3, sizeof(struct block_index *), block_index_cmp_height);

    for (int i = 0; i < 3; i++) {
        if (!all[i]->pprev) continue;
        if (all[i]->nStatus & BLOCK_FAILED_MASK) continue;
        if (all[i]->pprev->nStatus & BLOCK_FAILED_MASK)
            all[i]->nStatus |= BLOCK_FAILED_CHILD;
    }

    /* b and c should be FAILED_CHILD, orphan should not */
    bool b_failed = (b.nStatus & BLOCK_FAILED_CHILD) != 0;
    bool c_failed = (c.nStatus & BLOCK_FAILED_CHILD) != 0;
    bool orphan_clean = (orphan.nStatus & BLOCK_FAILED_MASK) == 0;

    if (b_failed && c_failed && orphan_clean) {
        printf("OK\n"); return 0;
    }
    printf("FAIL (b=%d c=%d orphan=%d)\n", b_failed, c_failed, orphan_clean);
    return 1;
}

/* ── nChainTx propagation ────────────────────────────────────── */

static int test_nchaintx_propagation(void)
{
    printf("GIVEN chain genesis→1→2→3 with nTx set "
           "WHEN propagate nChainTx THEN cumulative correct... ");

    struct block_index g = {0}, b1 = {0}, b2 = {0}, b3 = {0};
    block_index_init(&g);
    block_index_init(&b1);
    block_index_init(&b2);
    block_index_init(&b3);

    g.nHeight = 0; g.nTx = 1; g.nStatus = BLOCK_HAVE_DATA;
    b1.nHeight = 1; b1.nTx = 5; b1.pprev = &g; b1.nStatus = BLOCK_HAVE_DATA;
    b2.nHeight = 2; b2.nTx = 3; b2.pprev = &b1; b2.nStatus = BLOCK_HAVE_DATA;
    b3.nHeight = 3; b3.nTx = 2; b3.pprev = &b2; b3.nStatus = BLOCK_HAVE_DATA;

    struct block_index *sorted[] = {&g, &b1, &b2, &b3};
    /* Already in order, but sort for correctness */
    qsort(sorted, 4, sizeof(struct block_index *), block_index_cmp_height);

    /* Propagate */
    for (int i = 0; i < 4; i++) {
        struct block_index *bl = sorted[i];
        if (bl->nHeight == 0) {
            bl->nChainTx = bl->nTx;
        } else if (bl->pprev && bl->pprev->nChainTx > 0) {
            bl->nChainTx = bl->pprev->nChainTx + bl->nTx;
        }
    }

    /* Check: g=1, b1=6, b2=9, b3=11 */
    if (g.nChainTx == 1 && b1.nChainTx == 6 &&
        b2.nChainTx == 9 && b3.nChainTx == 11) {
        printf("OK\n"); return 0;
    }
    printf("FAIL (g=%u b1=%u b2=%u b3=%u)\n",
           g.nChainTx, b1.nChainTx, b2.nChainTx, b3.nChainTx);
    return 1;
}

/* ── ZCL block magic validation ──────────────────────────────── */

static int test_block_magic(void)
{
    printf("GIVEN ZCL mainnet magic 0x6427e924 "
           "WHEN compared THEN matches... ");

    uint8_t raw[4] = {0x24, 0xe9, 0x27, 0x64}; /* little-endian */
    uint32_t magic = (uint32_t)raw[0] | ((uint32_t)raw[1] << 8) |
                     ((uint32_t)raw[2] << 16) | ((uint32_t)raw[3] << 24);

    if (magic == 0x6427e924) {
        printf("OK\n"); return 0;
    }
    printf("FAIL (got 0x%08x)\n", magic);
    return 1;
}

/* ── Block header parsing round-trip ─────────────────────────── */

static int test_header_parse(void)
{
    printf("GIVEN serialized block header "
           "WHEN deserialize+hash THEN produces valid hash... ");

    /* Create a minimal block header */
    struct block_header hdr;
    block_header_init(&hdr);
    hdr.nVersion = 4;
    memset(hdr.hashPrevBlock.data, 0xab, 32);
    memset(hdr.hashMerkleRoot.data, 0xcd, 32);
    memset(hdr.hashFinalSaplingRoot.data, 0, 32);
    hdr.nTime = 1478403829;
    hdr.nBits = 0x2007ffff;
    memset(hdr.nNonce.data, 0, 32);
    hdr.nSolutionSize = 1344;
    memset(hdr.nSolution, 0, 1344);

    /* Serialize */
    struct byte_stream s;
    stream_init(&s, 2048);
    if (!block_header_serialize(&hdr, &s)) {
        printf("FAIL (serialize)\n");
        stream_free(&s);
        return 1;
    }

    /* Deserialize from the serialized data */
    struct block_header hdr2;
    block_header_init(&hdr2);
    struct byte_stream s2;
    stream_init_from_data(&s2, s.data, s.size);
    if (!block_header_deserialize(&hdr2, &s2)) {
        printf("FAIL (deserialize)\n");
        stream_free(&s);
        return 1;
    }

    /* Hash should match */
    struct uint256 h1, h2;
    block_header_get_hash(&hdr, &h1);
    block_header_get_hash(&hdr2, &h2);

    stream_free(&s);

    if (uint256_eq(&h1, &h2) && hdr2.nVersion == 4 &&
        hdr2.nTime == 1478403829 && hdr2.nSolutionSize == 1344) {
        printf("OK\n"); return 0;
    }
    printf("FAIL (hash mismatch or field mismatch)\n");
    return 1;
}

/* ── coins_view_sqlite NULL safety ───────────────────────────── */

static int test_coins_sqlite_null_safety(void)
{
    printf("GIVEN NULL coins_view_sqlite "
           "WHEN get_best_block THEN returns false (no crash)... ");

    struct uint256 hash;
    bool ok = coins_view_sqlite_get_best_block(NULL, &hash);
    if (!ok) {
        printf("OK\n"); return 0;
    }
    printf("FAIL (returned true for NULL)\n");
    return 1;
}

/* ── OS-S2 #4: wallet Pass-1 file-match cache pure helpers ─────── */

#define WSCAN_CHK(cond, msg) do { \
    if (cond) { printf("  OK: %s\n", (msg)); } \
    else { printf("  FAIL: %s\n", (msg)); failures++; } \
} while (0)

static int test_wallet_scan_keyset_fp(void)
{
    int failures = 0;
    /* struct wallet embeds fixed 4096-entry arrays — heap-allocate it. */
    struct wallet *w = calloc(1, sizeof(*w));
    struct wallet *w2 = calloc(1, sizeof(*w));
    if (!w || !w2) { free(w); free(w2); printf("  keyset_fp: OOM\n"); return 1; }

    w->keystore.num_keys = 2;
    w->keystore.keys[0].used = true;
    w->keystore.keys[0].keyid.id.data[0] = 0x11;
    w->keystore.keys[1].used = true;
    w->keystore.keys[1].keyid.id.data[0] = 0x22;

    *w2 = *w;  /* identical keyset */
    uint64_t fp = wallet_scan_keyset_fp(w);
    uint64_t fp_same = wallet_scan_keyset_fp(w2);
    WSCAN_CHK(fp == fp_same, "keyset_fp is deterministic for equal keysets");
    WSCAN_CHK(fp != 0, "keyset_fp is nonzero for a populated keyset");

    /* Flip a key off → different fingerprint (import/remove invalidation). */
    w2->keystore.keys[1].used = false;
    uint64_t fp_diff = wallet_scan_keyset_fp(w2);
    WSCAN_CHK(fp_diff != fp, "keyset_fp changes when a key is removed");

    free(w);
    free(w2);
    return failures;
}

static int test_wallet_scan_cache_valid(void)
{
    int failures = 0;
    /* Same fp, tip not rewound → reusable. */
    WSCAN_CHK(wallet_scan_cache_valid(1234, 1234, 100, 100),
                "cache valid when fp matches and tip is unchanged");
    WSCAN_CHK(wallet_scan_cache_valid(1234, 1234, 100, 150),
                "cache valid when tip advanced above cached");
    /* fp mismatch (keyset changed) → invalid. */
    WSCAN_CHK(!wallet_scan_cache_valid(1234, 5678, 100, 100),
                "cache invalid when keyset fingerprint differs");
    /* tip rewound below cached (reorg) → invalid. */
    WSCAN_CHK(!wallet_scan_cache_valid(1234, 1234, 100, 90),
                "cache invalid when tip rewound below cached (reorg)");
    return failures;
}

static bool seed_wallet_projection(struct node_db *ndb)
{
    static uint8_t raw_tx[] = {0x01};
    static uint8_t script[] = {0x51};
    struct db_wallet_tx tx;
    struct db_wallet_utxo utxo;
    struct db_sapling_note note;

    memset(&tx, 0, sizeof(tx));
    memset(&utxo, 0, sizeof(utxo));
    memset(&note, 0, sizeof(note));

    memset(tx.txid, 0x91, sizeof(tx.txid));
    tx.raw_tx = raw_tx;
    tx.raw_tx_len = sizeof(raw_tx);
    tx.time_received = 1;

    memcpy(utxo.txid, tx.txid, sizeof(utxo.txid));
    memset(utxo.address_hash, 0x92, sizeof(utxo.address_hash));
    utxo.value = 1234;
    utxo.script = script;
    utxo.script_len = sizeof(script);
    utxo.height = 1;

    memset(note.txid, 0x93, sizeof(note.txid));
    memset(note.rcm, 0x94, sizeof(note.rcm));
    memset(note.ivk, 0x95, sizeof(note.ivk));
    memset(note.diversifier, 0x96, sizeof(note.diversifier));
    memset(note.pk_d, 0x97, sizeof(note.pk_d));
    memset(note.cm, 0x98, sizeof(note.cm));
    memset(note.nullifier, 0x99, sizeof(note.nullifier));
    note.value = 5678;
    note.block_height = 1;
    snprintf(note.address, sizeof(note.address), "%s", "zs1scanrollback");

    return db_wallet_tx_save(ndb, &tx) &&
           db_wallet_utxo_save(ndb, &utxo) &&
           db_sapling_note_save(ndb, &note);
}

static bool wallet_projection_seed_is_present(struct node_db *ndb)
{
    uint8_t txid[32];
    struct db_wallet_tx tx;
    memset(txid, 0x91, sizeof(txid));
    memset(&tx, 0, sizeof(tx));
    bool tx_found = db_wallet_tx_find(ndb, txid, &tx);
    if (tx_found) db_wallet_tx_free(&tx);
    return tx_found && db_wallet_utxo_balance(ndb) == 1234 &&
           db_sapling_note_balance_for_address(ndb,
                                                "zs1scanrollback") == 5678;
}

static bool node_db_has_no_open_transaction(struct node_db *ndb)
{
    struct node_db_status status;
    memset(&status, 0, sizeof(status));
    node_db_get_status(ndb, &status);
    return !status.tx_open && sqlite3_get_autocommit(ndb->db) != 0;
}

static int test_wallet_scan_empty_replacement(void)
{
    printf("GIVEN stale wallet rows WHEN empty Pass2 replaces them "
           "THEN rollback is atomic and public empty paths converge... ");
    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));
    bool ok = node_db_open(&ndb, ":memory:") &&
              seed_wallet_projection(&ndb);
    if (ok) {
        ok = sqlite3_exec(ndb.db,
            "CREATE TRIGGER fail_wallet_tx_clear BEFORE DELETE ON "
            "wallet_transactions BEGIN SELECT RAISE(ABORT,'injected'); END",
            NULL, NULL, NULL) == SQLITE_OK;
    }

    struct active_chain chain;
    active_chain_init(&chain);
    struct scan_addr_ht ht;
    scan_aht_init(&ht);
    bool file_has_match[1] = {false};
    struct timespec started = {.tv_sec = 1, .tv_nsec = 0};
    struct timespec pass1 = {.tv_sec = 1, .tv_nsec = 0};
    int failed = ok ? wallet_scan_pass2_execute(
        &ndb, &chain, "/nonexistent", 0, 1000000000,
        &ht, file_has_match, 0, &started, &pass1) : 0;
    ok = ok && failed == -1 && wallet_projection_seed_is_present(&ndb) &&
         node_db_has_no_open_transaction(&ndb);

    if (ok) {
        ok = sqlite3_exec(ndb.db, "DROP TRIGGER fail_wallet_tx_clear",
                          NULL, NULL, NULL) == SQLITE_OK;
    }
    int cleared = ok ? wallet_scan_pass2_execute(
        &ndb, &chain, "/nonexistent", 0, 1000000000,
        &ht, file_has_match, 0, &started, &pass1) : -1;
    uint8_t txid[32];
    struct db_wallet_tx tx;
    memset(txid, 0x91, sizeof(txid));
    memset(&tx, 0, sizeof(tx));
    bool tx_found = ok && db_wallet_tx_find(&ndb, txid, &tx);
    if (tx_found) db_wallet_tx_free(&tx);
    ok = ok && cleared == 0 && !tx_found &&
         db_wallet_utxo_balance(&ndb) == 0 &&
         db_sapling_note_balance_for_address(&ndb,
                                              "zs1scanrollback") == 5678 &&
         node_db_has_no_open_transaction(&ndb) &&
         node_db_begin(&ndb) && node_db_commit(&ndb);

    /* The public scanner must not bypass replacement for a zero-key wallet
     * or an empty chain range. Those were the two former early returns. */
    /* struct wallet embeds fixed 4096-entry arrays.  Keeping this fixture on
     * the stack makes the optimized aggregate test exceed macOS's worker
     * stack before its first assertion. */
    struct wallet *empty_wallet = calloc(1, sizeof(*empty_wallet));
    if (!empty_wallet) ok = false;
    if (ok) {
        ok = db_sapling_note_delete_all(&ndb) &&
             seed_wallet_projection(&ndb);
    }
    int zero_key_result = ok ? wallet_scan_blocks(
        &ndb, &chain, empty_wallet, "/nonexistent", 0, 0) : -1;
    ok = ok && zero_key_result == 0 &&
         db_wallet_tx_count(&ndb) == 0 &&
         db_wallet_utxo_balance(&ndb) == 0;

    if (ok) {
        ok = db_sapling_note_delete_all(&ndb) &&
             seed_wallet_projection(&ndb);
    }
    int empty_range_result = ok ? wallet_scan_blocks(
        &ndb, &chain, empty_wallet, "/nonexistent", 1, 0) : -1;
    ok = ok && empty_range_result == 0 &&
         db_wallet_tx_count(&ndb) == 0 &&
         db_wallet_utxo_balance(&ndb) == 0 &&
         node_db_has_no_open_transaction(&ndb);

    scan_aht_free(&ht);
    active_chain_free(&chain);
    free(empty_wallet);
    if (ndb.open) node_db_close(&ndb);
    if (ok) { printf("OK\n"); return 0; }
    printf("FAIL\n");
    return 1;
}

static int test_legacy_import_clear_rollback(void)
{
    printf("GIVEN stale transparent+Sapling rows WHEN legacy clear fails "
           "THEN all three model-owned deletes roll back... ");
    char dir[256], blocks[320], file_path[384];
    test_make_tmpdir(dir, sizeof(dir), "block_scan", "legacy_rollback");
    snprintf(blocks, sizeof(blocks), "%s/blocks", dir);
    mkdir(blocks, 0755);
    snprintf(file_path, sizeof(file_path), "%s/blk00000.dat", blocks);
    int fd = open(file_path, O_CREAT | O_WRONLY | O_TRUNC, 0600);
    uint8_t invalid_byte = 0;
    bool ok = fd >= 0 && write(fd, &invalid_byte, 1) == 1;
    if (fd >= 0) close(fd);

    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));
    ok = ok && node_db_open(&ndb, ":memory:") &&
         seed_wallet_projection(&ndb);
    if (ok) {
        ok = sqlite3_exec(ndb.db,
            "CREATE TRIGGER fail_legacy_sapling_clear BEFORE DELETE ON "
            "wallet_sapling_notes BEGIN SELECT RAISE(ABORT,'injected'); END",
            NULL, NULL, NULL) == SQLITE_OK;
    }

    struct wallet *wallet = calloc(1, sizeof(*wallet));
    if (wallet) wallet_init(wallet);
    int imported = ok && wallet
        ? legacy_import_service_run(dir, &ndb, wallet, false) : 0;
    ok = ok && wallet && imported == -1 &&
         wallet_projection_seed_is_present(&ndb) &&
         node_db_has_no_open_transaction(&ndb) &&
         node_db_begin(&ndb) && node_db_commit(&ndb);

    if (wallet) {
        wallet_free(wallet);
        free(wallet);
    }
    if (ndb.open) node_db_close(&ndb);
    (void)test_rm_rf_recursive(dir);
    if (ok) { printf("OK\n"); return 0; }
    printf("FAIL\n");
    return 1;
}

/* ── Main ────────────────────────────────────────────────────── */

/* ── boot wallet-scan cursor decision (O(delta) boot) ────────── */

static int test_wallet_scan_cursor_start(void)
{
    printf("GIVEN a persisted wallet-scan cursor + keyset fp "
           "WHEN deciding the scan start THEN O(delta) or full... ");
    int fails = 0;

    /* No cursor (an old wallet datadir) → one final full scan from 0. */
    if (boot_cursor_wallet_scan_start(false, -1, false, 0, 42, 1000) != 0)
        fails++;
    /* Cursor present, keyset unchanged → delta re-scan from cursor+1. */
    if (boot_cursor_wallet_scan_start(true, 500, true, 42, 42, 1000) != 501)
        fails++;
    /* Keyset changed (a key import) → full re-scan from 0. */
    if (boot_cursor_wallet_scan_start(true, 500, true, 42, 99, 1000) != 0)
        fails++;
    /* Cursor without a keyset stamp → full re-scan from 0. */
    if (boot_cursor_wallet_scan_start(true, 500, false, 0, 42, 1000) != 0)
        fails++;
    /* Cursor already at the tip → empty range (start > tip → skip). */
    if (boot_cursor_wallet_scan_start(true, 1000, true, 42, 42, 1000) <= 1000)
        fails++;
    /* A negative cursor is treated as no cursor → full scan. */
    if (boot_cursor_wallet_scan_start(true, -5, true, 42, 42, 1000) != 0)
        fails++;

    if (fails == 0) { printf("OK\n"); return 0; }
    printf("FAIL (%d)\n", fails);
    return 1;
}

int test_block_scan(void)
{
    int failures = 0;

    printf("\n=== Block Scan & Chain Propagation Tests ===\n");

    failures += test_cmp_height();
    failures += test_failed_child_propagation();
    failures += test_nchaintx_propagation();
    failures += test_block_magic();
    failures += test_header_parse();
    failures += test_coins_sqlite_null_safety();
    failures += test_wallet_scan_keyset_fp();
    failures += test_wallet_scan_cache_valid();
    failures += test_wallet_scan_cursor_start();
    failures += test_wallet_scan_empty_replacement();
    failures += test_legacy_import_clear_rollback();

    printf("block_scan: %d failure(s)\n\n", failures);
    return failures;
}
