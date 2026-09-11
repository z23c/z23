/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Unit test for block_index_node_db_topup_with() — the cold-import
 * restart-fragility fix (PART A).
 *
 * The bug
 * -------
 * A node that cold-imported a UTXO snapshot (seed anchor at H_seed) and
 * forward-synced PAST it has, after a flat-index reload, the contiguous
 * chain up to ~H_seed in the in-memory map PLUS the seed anchor as a
 * DETACHED non-genesis root (its pprev chain to genesis is absent — a
 * snapshot base is not P2P-downloaded). coins_best (the coins authority)
 * is the forward tip; the window (H_seed, coins_best] is body-backed /
 * connected (status>=3) in node.db `blocks` but is NOT linked into the
 * map. On restart the coins-best restore then refuses (no consensus-backed
 * ancestor — the seed anchor's null pprev) and the tip drops to genesis.
 *
 * What this test proves
 * ---------------------
 *   1. FORWARD-EXTENT FOLD: the window [H_seed+1 .. coins_best] is read
 *      from node.db `blocks`, inserted into the map, and pprev-linked all
 *      the way down to the seed anchor — so the seed anchor stops being an
 *      orphan tip and coins_best gains a pprev chain to it.
 *   2. RAISE-ONLY: an entry already in the map keeps its richer state
 *      (HAVE_DATA / nTx) — never lowered.
 *   3. STRICT NO-OP WITHOUT A SEED ANCHOR: with the durable cold-import
 *      keys absent, the top-up inserts/links nothing (the normal /
 *      P2P-origin datadir path).
 *   4. WINDOW-BOUNDED: nothing below H_seed+1 or above coins_best is
 *      touched, and no full-chain scan occurs.
 *   5. NO-OP ON EMPTY WINDOW: coins_best <= H_seed inserts nothing.
 *
 * Scratch files live under ./test-tmp/nodedbtopup_<pid>/ per the project's
 * no-/tmp convention.
 */

#include "test/test_core.h"

#include "services/block_index_loader.h"
#include "models/database.h"
#include "models/block.h"
#include "storage/coins_kv.h"
#include "storage/progress_store.h"
#include "validation/main_state.h"
#include "validation/chainstate.h"
#include "chain/chain.h"
#include "core/uint256.h"

#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define NDT_CHECK(name, expr) do { \
    printf("block_index_node_db_topup: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

/* Deterministic unique hash for height h. */
static void ndt_hash_for(int h, struct uint256 *out)
{
    memset(out->data, 0, 32);
    out->data[0] = (uint8_t)(h & 0xFF);
    out->data[1] = (uint8_t)((h >> 8) & 0xFF);
    out->data[31] = 0xA5;
}

/* Write a connected (status>=3) block row at height h into the node.db
 * `blocks` table, prev_hash = hash(h-1), with an explicit stored status,
 * undo column and file number. The STATUS bits are what the top-up reads as
 * "this row claims data" / "this row claims undo": a row that merely names a
 * file_num claims nothing, on either half. */
static bool ndt_write_block_full(struct node_db *ndb, int h, int status,
                                 int undo_pos, int file_num)
{
    static uint8_t dummy_solution[1] = {0};
    struct db_block b;
    memset(&b, 0, sizeof(b));
    struct uint256 hh, ph;
    ndt_hash_for(h, &hh);
    ndt_hash_for(h - 1, &ph);
    memcpy(b.hash, hh.data, 32);
    memcpy(b.prev_hash, ph.data, 32);
    b.height = h;
    b.version = 4;
    memset(b.merkle_root, 0x11, 32);
    b.time = 1700000000u + (uint32_t)h;
    b.bits = 0x2000ffffu;
    memset(b.nonce, 0x22, 32);
    b.solution = dummy_solution;
    b.solution_len = sizeof(dummy_solution);
    memset(b.chain_work, 0, 32);
    b.status = status;            /* connected — db_block_find_by_height filter */
    b.file_num = file_num;
    b.data_pos = 1000 + h;
    b.undo_pos = undo_pos;
    b.num_tx = 2;
    memset(b.sapling_root, 0, 32);
    memset(b.sprout_root, 0, 32);
    return db_block_save(ndb, &b);
}

/* The common shape: the row names block file 1. */
static bool ndt_write_block_row(struct node_db *ndb, int h, int status,
                                int undo_pos)
{
    return ndt_write_block_full(ndb, h, status, undo_pos, 1);
}

/* The plain window row the fold fixtures use: connected, body-backed, and
 * making NO undo claim (status has no BLOCK_HAVE_UNDO bit). */
static bool ndt_write_block(struct node_db *ndb, int h)
{
    return ndt_write_block_row(ndb, h, 3, 2000 + h);
}

/* Insert a header-only in-memory entry at height h (the stale-flat shape). */
static struct block_index *ndt_insert_entry(struct main_state *ms, int h)
{
    struct uint256 hh;
    ndt_hash_for(h, &hh);
    struct block_index *bi =
        chainstate_insert_block_index((struct chainstate *)ms, &hh);
    if (!bi)
        return NULL;
    bi->nHeight = h;
    bi->nBits = 0x2000ffffu;
    bi->nTime = 1700000000u + (uint32_t)h;
    bi->nVersion = 4;
    bi->nStatus = BLOCK_VALID_TREE;
    bi->nTx = 0;
    bi->nFile = -1;
    bi->nDataPos = 0;
    return bi;
}

/* Set the coins applied frontier so coins_best == coins_applied_height - 1. */
static bool ndt_set_coins_best(sqlite3 *db, int coins_best)
{
    if (!coins_kv_ensure_schema(db) || !progress_meta_table_ensure(db))
        return false;
    char *err = NULL;
    if (sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, &err) != SQLITE_OK) {
        if (err) sqlite3_free(err);
        return false;
    }
    bool ok = coins_kv_set_applied_height_in_tx(db, coins_best + 1);
    const char *fin = ok ? "COMMIT" : "ROLLBACK";
    if (sqlite3_exec(db, fin, NULL, NULL, &err) != SQLITE_OK) {
        if (err) sqlite3_free(err);
        ok = false;
    }
    return ok;
}

/* An entry in the header-only-snapshot-import shape: HAVE_DATA with a real
 * position, and `undo_pos` (0 meaning no HAVE_UNDO at all). */
static struct block_index *ndt_undo_entry(struct main_state *ms, int h,
                                          unsigned int undo_pos)
{
    struct block_index *bi = ndt_insert_entry(ms, h);
    if (!bi)
        return NULL;
    bi->nStatus = BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA;
    bi->nFile = 1;
    bi->nDataPos = (unsigned int)(1000 + h);
    bi->nTx = 2;
    if (undo_pos) {
        bi->nUndoPos = undo_pos;
        bi->nStatus |= BLOCK_HAVE_UNDO;
    }
    return bi;
}

/* A body-less entry carrying an undo position of its OWN
 * against a different block file — the shape the destructive clear needs:
 * adopting the row's file number invalidates this position, and
 * topup_apply_undo() then zeroes it. */
static struct block_index *ndt_no_data_undo_entry(struct main_state *ms,
                                                  int h)
{
    struct block_index *bi = ndt_insert_entry(ms, h);
    if (!bi)
        return NULL;
    bi->nStatus = BLOCK_VALID_SCRIPTS | BLOCK_HAVE_UNDO;
    bi->nFile = 2;
    bi->nUndoPos = 777;
    bi->nTx = 2;
    return bi;
}

struct ndt_undo_fixture {
    struct node_db ndb;
    sqlite3 *progress;
    struct main_state ms;
    struct block_index *u103;
    struct block_index *u104;
    struct block_index *u105;
    struct block_index *u106;
    struct block_index *u107;
    bool opened;
    bool built;
};

/* Same seed-anchor/window shape as the main fixture, but with 103, 104 and
 * 105 ALREADY in the map carrying HAVE_DATA — 103 and 105 without an undo
 * position, 104 with its own. The rows differ in what they CLAIM: 103 and
 * 104 carry BLOCK_HAVE_UNDO, 105 deliberately does not.
 *
 * 106 and 107 are the DATA half of the same rule: body-less entries whose
 * rows are the header-only snapshot-import shape written by
 * snapshot_controller_import.c — HAVE_DATA and HAVE_UNDO stripped, file_num
 * pinned to 0, positions 0. That file_num is not an address; the import
 * comment states the node gates every block-file read on the status bits. */
static void ndt_undo_fixture_build(struct ndt_undo_fixture *f,
                                   const char *dir)
{
    memset(f, 0, sizeof(*f));
    char ndb_path[320], prog_path[320];
    snprintf(ndb_path, sizeof(ndb_path), "%s/node5.db", dir);
    snprintf(prog_path, sizeof(prog_path), "%s/progress5.db", dir);
    if (!node_db_open(&f->ndb, ndb_path))
        return;
    f->opened = true;
    if (sqlite3_open(prog_path, &f->progress) != SQLITE_OK)
        return;
    for (int h = 100; h <= 102; h++)
        (void)ndt_write_block(&f->ndb, h);
    /* Rows that claim undo (status bit set) vs a row that does not. */
    (void)ndt_write_block_row(&f->ndb, 103, 3 | BLOCK_HAVE_UNDO, 2103);
    (void)ndt_write_block_row(&f->ndb, 104, 3 | BLOCK_HAVE_UNDO, 2104);
    (void)ndt_write_block_row(&f->ndb, 105, 3, 2105);
    /* Header-only import rows: no HAVE_DATA, no HAVE_UNDO, file_num 0. */
    (void)ndt_write_block_full(&f->ndb, 106, 3, 0, 0);
    (void)ndt_write_block_full(&f->ndb, 107, 3, 0, 0);
    struct uint256 seed_hash;
    ndt_hash_for(102, &seed_hash);
    (void)node_db_state_set_int(&f->ndb, "cold_import_seed_anchor_height",
                                102);
    (void)node_db_state_set(&f->ndb, "cold_import_seed_anchor_hash",
                            seed_hash.data, 32);
    (void)ndt_set_coins_best(f->progress, 107);
    main_state_init(&f->ms);
    (void)ndt_insert_entry(&f->ms, 102);
    f->u103 = ndt_undo_entry(&f->ms, 103, 0);
    f->u104 = ndt_undo_entry(&f->ms, 104, 555);
    f->u105 = ndt_undo_entry(&f->ms, 105, 0);
    /* 106: pure header-only entry (nFile -1, no position bits at all). */
    f->u106 = ndt_insert_entry(&f->ms, 106);
    f->u107 = ndt_no_data_undo_entry(&f->ms, 107);
    f->built = f->u103 && f->u104 && f->u105 && f->u106 && f->u107;
}

/* The undo top-up the node.db fold used to be unable to perform: an entry
 * that already carries HAVE_DATA but no HAVE_UNDO, whose `blocks` row still
 * names an undo position. Without it the background validator skips every
 * transparent script in the block for want of recoverable spent outputs.
 *
 * And the fail-closed half, on BOTH position bits: a row whose stored
 * status does not claim BLOCK_HAVE_UNDO (105) or BLOCK_HAVE_DATA (106, 107)
 * grants nothing, however plausible its columns look. A header-only
 * snapshot import leaves exactly that shape — status stripped of both bits,
 * file_num 0 — and nothing in this tree writes block or rev files for it.
 * An entry that gained HAVE_UNDO from such a row would send the validator
 * to a rev offset that does not exist; one that gained HAVE_DATA would
 * publish (file 0, data_pos) as a body address that does not exist. Worse,
 * adopting the row's file number counts as a file change, which sends
 * topup_apply_undo() down its TOPUP_UNDO_CLEARED path and destroys an undo
 * position the entry legitimately held (107). */
static int ndt_undo_topup_cases(const char *dir)
{
    int failures = 0;
    struct ndt_undo_fixture f;
    ndt_undo_fixture_build(&f, dir);
    NDT_CHECK("undo-topup: fixture built", f.built);
    if (f.built) {
        NDT_CHECK("undo-topup: returns ok",
                  block_index_node_db_topup_with(&f.ms, &f.ndb, f.progress,
                                                 dir));
        NDT_CHECK("undo-topup: HAVE_DATA entry gained HAVE_UNDO",
                  (f.u103->nStatus & BLOCK_HAVE_UNDO) &&
                  f.u103->nUndoPos == 2103u);
        NDT_CHECK("undo-topup: data position untouched",
                  f.u103->nFile == 1 && f.u103->nDataPos == 1103u);
        NDT_CHECK("undo-topup: existing HAVE_UNDO not overwritten",
                  (f.u104->nStatus & BLOCK_HAVE_UNDO) &&
                  f.u104->nUndoPos == 555u);
        NDT_CHECK("undo-topup: row without HAVE_UNDO grants nothing",
                  !(f.u105->nStatus & BLOCK_HAVE_UNDO) &&
                  f.u105->nUndoPos == 0u);
        NDT_CHECK("data-topup: row without HAVE_DATA grants nothing",
                  !(f.u106->nStatus & BLOCK_HAVE_DATA) &&
                  f.u106->nFile == -1 && f.u106->nDataPos == 0u);
        NDT_CHECK("data-topup: row without HAVE_DATA keeps the entry's undo",
                  (f.u107->nStatus & BLOCK_HAVE_UNDO) &&
                  f.u107->nUndoPos == 777u && f.u107->nFile == 2);
        main_state_free(&f.ms);
    }
    if (f.progress)
        sqlite3_close(f.progress);
    if (f.opened)
        node_db_close(&f.ndb);
    return failures;
}

int test_block_index_node_db_topup(void)
{
    int failures = 0;
    printf("\n=== block_index node.db forward-extent top-up tests ===\n");

    char dir[256];
    snprintf(dir, sizeof(dir), "./test-tmp/nodedbtopup_%d", (int)getpid());
    mkdir("./test-tmp", 0755);
    mkdir(dir, 0755);

    char ndb_path[320];
    snprintf(ndb_path, sizeof(ndb_path), "%s/node.db", dir);
    char prog_path[320];
    snprintf(prog_path, sizeof(prog_path), "%s/progress.db", dir);

    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));
    NDT_CHECK("setup: node.db opens", node_db_open(&ndb, ndb_path));

    sqlite3 *progress = NULL;
    NDT_CHECK("setup: progress.db opens",
              sqlite3_open(prog_path, &progress) == SQLITE_OK);

    /* Fixture: seed anchor at H_seed=102, coins_best=105.
     * node.db `blocks` carries the connected window 103..105 (plus 100..102
     * so prev-linking is exercised through the seed anchor). */
    const int H_seed = 102;
    const int coins_best = 105;
    bool wrote = true;
    for (int h = 100; h <= coins_best; h++)
        wrote &= ndt_write_block(&ndb, h);
    NDT_CHECK("setup: window blocks written", wrote);

    /* In-memory map (the post-reload shape): contiguous chain 100..101 with
     * pprev links, then the seed anchor at 102 as a DETACHED root (pprev=NULL).
     * The forward window 103..105 is NOT in the map. */
    struct main_state ms;
    main_state_init(&ms);
    struct block_index *e100 = ndt_insert_entry(&ms, 100);
    struct block_index *e101 = ndt_insert_entry(&ms, 101);
    struct block_index *seed = ndt_insert_entry(&ms, 102);
    if (e101) e101->pprev = e100;
    /* seed->pprev deliberately left NULL — the cold-import snapshot base. */
    NDT_CHECK("setup: map has 100,101,detached-seed-102",
              e100 && e101 && seed && seed->pprev == NULL);

    /* Durable cold-import seed anchor keys (height + hash). */
    struct uint256 seed_hash;
    ndt_hash_for(H_seed, &seed_hash);
    NDT_CHECK("setup: seed anchor keys written",
              node_db_state_set_int(&ndb, "cold_import_seed_anchor_height",
                                    H_seed) &&
              node_db_state_set(&ndb, "cold_import_seed_anchor_hash",
                                seed_hash.data, 32));

    /* coins_best = 105 (applied_height = 106). */
    NDT_CHECK("setup: coins frontier set", ndt_set_coins_best(progress, coins_best));

    /* ── Run the top-up. ───────────────────────────────────────────── */
    bool ran = block_index_node_db_topup_with(&ms, &ndb, progress, dir);
    NDT_CHECK("topup returns ok", ran);

    /* 1. forward window inserted + pprev-linked down to the seed anchor. */
    struct uint256 h103, h104, h105;
    ndt_hash_for(103, &h103);
    ndt_hash_for(104, &h104);
    ndt_hash_for(105, &h105);
    struct block_index *e103 = block_map_find(&ms.map_block_index, &h103);
    struct block_index *e104 = block_map_find(&ms.map_block_index, &h104);
    struct block_index *e105 = block_map_find(&ms.map_block_index, &h105);
    NDT_CHECK("window heights inserted", e103 && e104 && e105);
    NDT_CHECK("inserted heights correct",
              e103 && e103->nHeight == 103 &&
              e104 && e104->nHeight == 104 &&
              e105 && e105->nHeight == 105);
    NDT_CHECK("inserted carry HAVE_DATA + positions",
              e103 && (e103->nStatus & BLOCK_HAVE_DATA) &&
              e103->nFile == 1 && e103->nDataPos == (unsigned)(1000 + 103));
    NDT_CHECK("inserted carry nTx from blocks row",
              e103 && e103->nTx == 2 && e105 && e105->nTx == 2);
    NDT_CHECK("pprev chain 105->104->103->seed",
              e105 && e105->pprev == e104 &&
              e104 && e104->pprev == e103 &&
              e103 && e103->pprev == seed);
    NDT_CHECK("seed anchor is no longer an orphan tip (has a child)",
              e103 && e103->pprev == seed);
    NDT_CHECK("inserted chainwork strictly increasing",
              e103 && e104 && e105 &&
              arith_uint256_compare(&e104->nChainWork,
                                    &e103->nChainWork) > 0 &&
              arith_uint256_compare(&e105->nChainWork,
                                    &e104->nChainWork) > 0);

    /* 4. window-bounded: nothing above coins_best (106) inserted. */
    struct uint256 h106;
    ndt_hash_for(106, &h106);
    NDT_CHECK("nothing above coins_best inserted",
              block_map_find(&ms.map_block_index, &h106) == NULL);

    /* 2. raise-only: pre-existing entries keep their state. */
    NDT_CHECK("e101 pprev preserved", e101 && e101->pprev == e100);

    /* 5. idempotent second run changes nothing. */
    bool ran2 = block_index_node_db_topup_with(&ms, &ndb, progress, dir);
    NDT_CHECK("second topup returns ok", ran2);
    NDT_CHECK("second topup changed nothing",
              e105 && e105->pprev == e104 && e105->nTx == 2 &&
              e103 && e103->pprev == seed);

    main_state_free(&ms);

    /* ── NO-OP without a seed anchor (normal / P2P-origin datadir). ──── */
    {
        struct node_db ndb2;
        memset(&ndb2, 0, sizeof(ndb2));
        char ndb2_path[320];
        snprintf(ndb2_path, sizeof(ndb2_path), "%s/node2.db", dir);
        bool opened = node_db_open(&ndb2, ndb2_path);
        NDT_CHECK("noseed: node.db opens", opened);
        if (opened) {
            for (int h = 100; h <= coins_best; h++)
                (void)ndt_write_block(&ndb2, h);
            /* NO cold_import_seed_anchor_* keys written. */
            struct main_state ms2;
            main_state_init(&ms2);
            struct block_index *s100 = ndt_insert_entry(&ms2, 100);
            (void)s100;
            size_t before = ms2.map_block_index.size;
            bool ok = block_index_node_db_topup_with(&ms2, &ndb2, progress, dir);
            size_t after = ms2.map_block_index.size;
            NDT_CHECK("noseed: returns ok", ok);
            NDT_CHECK("noseed: STRICT no-op (map unchanged)", after == before);
            main_state_free(&ms2);
            node_db_close(&ndb2);
        }
    }

    /* ── NO-OP on an empty window (coins_best <= H_seed). ───────────── */
    {
        struct node_db ndb3;
        memset(&ndb3, 0, sizeof(ndb3));
        char ndb3_path[320];
        snprintf(ndb3_path, sizeof(ndb3_path), "%s/node3.db", dir);
        char prog3_path[320];
        snprintf(prog3_path, sizeof(prog3_path), "%s/progress3.db", dir);
        sqlite3 *progress3 = NULL;
        bool opened = node_db_open(&ndb3, ndb3_path) &&
                      sqlite3_open(prog3_path, &progress3) == SQLITE_OK;
        NDT_CHECK("empty-window: dbs open", opened);
        if (opened) {
            for (int h = 100; h <= H_seed; h++)
                (void)ndt_write_block(&ndb3, h);
            struct uint256 sh;
            ndt_hash_for(H_seed, &sh);
            node_db_state_set_int(&ndb3, "cold_import_seed_anchor_height",
                                  H_seed);
            node_db_state_set(&ndb3, "cold_import_seed_anchor_hash",
                              sh.data, 32);
            /* coins_best == H_seed → empty forward window. */
            (void)ndt_set_coins_best(progress3, H_seed);
            struct main_state ms3;
            main_state_init(&ms3);
            struct block_index *sd = ndt_insert_entry(&ms3, H_seed);
            (void)sd;
            size_t before = ms3.map_block_index.size;
            bool ok = block_index_node_db_topup_with(&ms3, &ndb3, progress3, dir);
            size_t after = ms3.map_block_index.size;
            NDT_CHECK("empty-window: returns ok", ok);
            NDT_CHECK("empty-window: no insert", after == before);
            main_state_free(&ms3);
            if (progress3) sqlite3_close(progress3);
            node_db_close(&ndb3);
        }
    }

    /* NULL node.db / NULL progress are no-op successes. */
    {
        struct main_state ms4;
        main_state_init(&ms4);
        NDT_CHECK("NULL node.db no-op",
                  block_index_node_db_topup_with(&ms4, NULL, progress, dir));
        NDT_CHECK("NULL progress no-op",
                  block_index_node_db_topup_with(&ms4, &ndb, NULL, dir));
        main_state_free(&ms4);
    }

    if (progress) sqlite3_close(progress);
    node_db_close(&ndb);
    return failures + ndt_undo_topup_cases(dir);
}
