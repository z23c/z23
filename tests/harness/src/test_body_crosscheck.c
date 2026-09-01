/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_body_crosscheck — the local-body trust root
 * (engine/services/src/shielded_history_body_crosscheck.c) that re-derives Sprout
 * frontiers + the nullifier set from PoW/merkle-bound bodies and compares them
 * against a producer's progress.kv tables.
 *
 * Fixture: a tiny linear chain (heights 0..7) written to a real COPY datadir
 * (node.db `blocks` rows + blocks/blk00000.dat bodies), plus a producer
 * progress.kv whose sprout_anchors + nullifiers EXACTLY match those bodies.
 * JoinSplit heights {2,4,6} carry 2 commitments + 2 Sprout nullifiers each;
 * Sapling-spend heights {1,5} carry one Sapling nullifier each. checkpoint = 7
 * (above the last Sprout anchor at 6, exercising the nullifier tail extension).
 *
 * Asserts: (1) happy path -> sprout_ok && nullifiers_ok; (2) a TAMPERED producer
 * Sprout anchor -> sprout_ok=false (verdict, run still true); (3) a DROPPED
 * producer nullifier -> nullifiers_ok=false; (4) an EXTRA bogus producer
 * nullifier -> nullifiers_ok=false; (5) a corrupted body byte -> run()==false
 * (infrastructure failure). */

#include "test/test_core.h"

#include "bloom/merkle.h"
#include "chain/chain.h"
#include "core/uint256.h"
#include "models/block.h"
#include "models/database.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "sapling/constants.h"
#include "sapling/incremental_merkle_tree.h"
#include "services/shielded_history_body_crosscheck.h"
#include "storage/anchor_kv.h"
#include "storage/disk_block_io.h"
#include "storage/nullifier_kv.h"
#include "util/safe_alloc.h"

#include <sqlite3.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define BX_NBLOCKS 8
#define BX_CHECKPOINT 7

#define BX_CHECK(name, expr) do {                          \
    printf("  body_crosscheck: %s... ", (name));           \
    if ((expr)) printf("OK\n");                            \
    else { printf("FAIL\n"); failures++; }                 \
} while (0)

struct bx_fixture {
    struct block blocks[BX_NBLOCKS];
    struct uint256 hashes[BX_NBLOCKS];
    struct uint256 merkles[BX_NBLOCKS];
    int file_num[BX_NBLOCKS];
    int data_pos[BX_NBLOCKS];
};

static void bx_u256(struct uint256 *o, uint8_t tag, uint32_t idx)
{
    memset(o->data, 0, 32);
    o->data[0] = tag;
    o->data[1] = (uint8_t)(idx & 0xFF);
    o->data[2] = (uint8_t)((idx >> 8) & 0xFF);
    o->data[31] = 0xC7;
}

/* ── build the in-memory chain (real round-trip-safe shielded txs) ────── */

static bool bx_make_coinbase(struct transaction *tx, int height)
{
    transaction_init(tx);
    if (!transaction_alloc(tx, 1, 1))
        return false;
    tx->vin[0].sequence = 0xffffffffu;
    tx->vout[0].value = 1000 + height; /* distinct -> distinct coinbase txid */
    transaction_compute_hash(tx);
    return true;
}

static bool bx_make_joinsplit(struct transaction *tx, uint32_t *gc, uint32_t *gn)
{
    transaction_init(tx);
    tx->version = 2; /* pre-Overwinter Sprout tx: use_groth=false round-trips */
    tx->v_joinsplit = zcl_calloc(1, sizeof(struct js_description), "bx_js");
    if (!tx->v_joinsplit)
        return false;
    tx->num_joinsplit = 1;
    tx->v_joinsplit[0].use_groth = false;
    bx_u256(&tx->v_joinsplit[0].commitments[0], 0xC0, (*gc)++);
    bx_u256(&tx->v_joinsplit[0].commitments[1], 0xC0, (*gc)++);
    bx_u256(&tx->v_joinsplit[0].nullifiers[0], 0x4E, (*gn)++);
    bx_u256(&tx->v_joinsplit[0].nullifiers[1], 0x4E, (*gn)++);
    transaction_compute_hash(tx);
    return true;
}

static bool bx_make_spend(struct transaction *tx, uint32_t *gn)
{
    transaction_init(tx);
    tx->overwintered = true;
    tx->version = SAPLING_TX_VERSION;
    tx->version_group_id = SAPLING_VERSION_GROUP_ID;
    tx->v_shielded_spend =
        zcl_calloc(1, sizeof(struct spend_description), "bx_spend");
    if (!tx->v_shielded_spend)
        return false;
    tx->num_shielded_spend = 1;
    bx_u256(&tx->v_shielded_spend[0].nullifier, 0x5E, (*gn)++);
    transaction_compute_hash(tx);
    return true;
}

static bool bx_build_blocks(struct bx_fixture *f)
{
    memset(f, 0, sizeof(*f));
    uint32_t gc = 1, gn = 1;
    for (int h = 0; h < BX_NBLOCKS; h++) {
        struct block *b = &f->blocks[h];
        block_init(b);
        b->header.nVersion = 4;
        b->header.nTime = 1700005000u + (uint32_t)h;
        b->header.nBits = 0x2000ffffu;

        bool has_js = (h == 2 || h == 4 || h == 6);
        bool has_spend = (h == 1 || h == 5);
        size_t nvtx = 1u + ((has_js || has_spend) ? 1u : 0u);
        b->vtx = zcl_calloc(nvtx, sizeof(struct transaction), "bx_vtx");
        if (!b->vtx)
            return false;
        b->num_vtx = nvtx;
        if (!bx_make_coinbase(&b->vtx[0], h))
            return false;
        if (has_js && !bx_make_joinsplit(&b->vtx[1], &gc, &gn))
            return false;
        if (has_spend && !bx_make_spend(&b->vtx[1], &gn))
            return false;

        struct uint256 txids[2];
        for (size_t i = 0; i < b->num_vtx; i++)
            txids[i] = b->vtx[i].hash;
        b->header.hashMerkleRoot = compute_merkle_root(txids, b->num_vtx);
        f->merkles[h] = b->header.hashMerkleRoot;
        if (h > 0)
            b->header.hashPrevBlock = f->hashes[h - 1];
        block_get_hash(b, &f->hashes[h]);
    }
    return true;
}

/* ── copy datadir: blk*.dat bodies + node.db header rows ──────────────── */

static bool bx_build_copy(const char *dir, struct bx_fixture *f)
{
    char ndb_path[320];
    snprintf(ndb_path, sizeof(ndb_path), "%s/node.db", dir);
    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));
    if (!node_db_open(&ndb, ndb_path))
        return false;

    static const unsigned char msg[4] = {0x24, 0xe9, 0x27, 0x64};
    static uint8_t sol[1] = {0};
    bool ok = true;
    for (int h = 0; ok && h < BX_NBLOCKS; h++) {
        struct disk_block_pos pos;
        disk_block_pos_init(&pos);
        if (!write_block_to_disk(&f->blocks[h], &pos, dir, msg)) {
            ok = false;
            break;
        }
        f->file_num[h] = pos.nFile;
        f->data_pos[h] = (int)pos.nPos;

        struct db_block db;
        memset(&db, 0, sizeof(db));
        memcpy(db.hash, f->hashes[h].data, 32);
        db.height = h;
        if (h > 0)
            memcpy(db.prev_hash, f->hashes[h - 1].data, 32);
        db.version = 4;
        memcpy(db.merkle_root, f->merkles[h].data, 32);
        db.time = f->blocks[h].header.nTime;
        db.bits = 0x2000ffffu;
        db.solution = sol;
        db.solution_len = 1;
        db.status = BLOCK_VALID_SCRIPTS; /* >= 3 connected */
        db.file_num = pos.nFile;
        db.data_pos = (int)pos.nPos;
        db.undo_pos = 0;
        db.num_tx = (int)f->blocks[h].num_vtx;
        if (!db_block_save(&ndb, &db))
            ok = false;
    }
    node_db_close(&ndb);
    return ok;
}

/* ── producer progress.kv: sprout_anchors + nullifiers folded from bodies ─ */

static bool bx_build_producer(const char *dir, struct bx_fixture *f,
                              int checkpoint)
{
    char path[320];
    snprintf(path, sizeof(path), "%s/progress.kv", dir);
    sqlite3 *db = NULL;
    if (sqlite3_open_v2(path, &db,
                        SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE,
                        NULL) != SQLITE_OK) {
        if (db)
            sqlite3_close(db);
        return false;
    }
    bool ok = anchor_kv_ensure_schema(db) && nullifier_kv_ensure_schema(db);
    struct incremental_merkle_tree tree;
    sprout_tree_init(&tree);
    for (int h = 0; ok && h <= checkpoint; h++) {
        struct block *b = &f->blocks[h];
        bool has_js = false;
        for (size_t i = 0; ok && i < b->num_vtx; i++) {
            struct transaction *tx = &b->vtx[i];
            for (size_t j = 0; j < tx->num_joinsplit; j++) {
                has_js = true;
                for (size_t k = 0; k < ZC_NUM_JS_OUTPUTS; k++)
                    incremental_tree_append(&tree,
                                            &tx->v_joinsplit[j].commitments[k]);
                for (size_t k = 0; k < 2; k++)
                    if (!nullifier_kv_add(db,
                                          tx->v_joinsplit[j].nullifiers[k].data,
                                          NULLIFIER_POOL_SPROUT, h))
                        ok = false;
            }
            for (size_t j = 0; j < tx->num_shielded_spend; j++)
                if (!nullifier_kv_add(db,
                                      tx->v_shielded_spend[j].nullifier.data,
                                      NULLIFIER_POOL_SAPLING, h))
                    ok = false;
        }
        if (ok && has_js &&
            !anchor_kv_add_tree(db, ANCHOR_POOL_SPROUT, &tree, h))
            ok = false;
    }
    sqlite3_close(db); /* default rollback journal -> no WAL, clean on close */
    return ok;
}

static bool bx_producer_open_rw(const char *dir, sqlite3 **db)
{
    char path[320];
    snprintf(path, sizeof(path), "%s/progress.kv", dir);
    return sqlite3_open_v2(path, db, SQLITE_OPEN_READWRITE, NULL) == SQLITE_OK;
}

/* Corrupt one producer Sprout anchor root (a verdict-path tamper, not a
 * resume-boundary G3b failure): the shard's end-check at that height mismatches
 * the body-derived root while every resume frontier still deserializes. */
static bool bx_tamper_anchor(const char *dir, int64_t height)
{
    sqlite3 *db = NULL;
    if (!bx_producer_open_rw(dir, &db)) {
        if (db)
            sqlite3_close(db);
        return false;
    }
    uint8_t bogus[32];
    memset(bogus, 0xEE, sizeof(bogus));
    sqlite3_stmt *st = NULL;
    bool ok = false;
    if (sqlite3_prepare_v2(db,
            "UPDATE sprout_anchors SET anchor=? WHERE height=?", -1, &st,
            NULL) == SQLITE_OK) {
        sqlite3_bind_blob(st, 1, bogus, 32, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 2, height);
        ok = sqlite3_step(st) == SQLITE_DONE && sqlite3_changes(db) == 1;
        sqlite3_finalize(st);
    }
    sqlite3_close(db);
    return ok;
}

static bool bx_drop_nf(const char *dir, int64_t height)
{
    sqlite3 *db = NULL;
    if (!bx_producer_open_rw(dir, &db)) {
        if (db)
            sqlite3_close(db);
        return false;
    }
    sqlite3_stmt *st = NULL;
    bool ok = false;
    if (sqlite3_prepare_v2(db, "DELETE FROM nullifiers WHERE height=?", -1, &st,
                           NULL) == SQLITE_OK) {
        sqlite3_bind_int64(st, 1, height);
        ok = sqlite3_step(st) == SQLITE_DONE && sqlite3_changes(db) >= 1;
        sqlite3_finalize(st);
    }
    sqlite3_close(db);
    return ok;
}

static bool bx_add_bogus_nf(const char *dir, int64_t height)
{
    sqlite3 *db = NULL;
    if (!bx_producer_open_rw(dir, &db)) {
        if (db)
            sqlite3_close(db);
        return false;
    }
    uint8_t bogus[32];
    memset(bogus, 0x9E, sizeof(bogus));
    bool ok = nullifier_kv_add(db, bogus, NULLIFIER_POOL_SAPLING, height);
    sqlite3_close(db);
    return ok;
}

/* Flip one byte deep inside block h=2's on-disk frame (a JoinSplit block, so
 * well past its header): the body still deserializes but its recomputed txid ->
 * merkle diverges from the header, so nbf_chain_body_verify rejects it. */
static bool bx_corrupt_body(const char *dir, struct bx_fixture *f)
{
    char path[400];
    snprintf(path, sizeof(path), "%s/blocks/blk%05d.dat", dir, f->file_num[2]);
    FILE *fp = fopen(path, "r+b");
    if (!fp)
        return false;
    long off = (long)f->data_pos[2] +
               (long)(f->data_pos[3] - f->data_pos[2]) / 2;
    bool ok = false;
    if (fseek(fp, off, SEEK_SET) == 0) {
        int c = fgetc(fp);
        if (c != EOF && fseek(fp, off, SEEK_SET) == 0)
            ok = (fputc(c ^ 0xFF, fp) != EOF);
    }
    return (fclose(fp) == 0) && ok;
}

static void bx_free_fixture(struct bx_fixture *f)
{
    for (int h = 0; h < BX_NBLOCKS; h++)
        block_free(&f->blocks[h]);
}

int test_body_crosscheck(void);
int test_body_crosscheck(void)
{
    printf("\n=== body_crosscheck (local-body Sprout+nullifier re-derivation) "
           "===\n");
    int failures = 0;

    struct bx_fixture *f = zcl_calloc(1, sizeof(*f), "bx_fixture");
    if (!f) {
        printf("  body_crosscheck: fixture alloc... FAIL\n");
        return 1;
    }
    BX_CHECK("build in-memory chain", bx_build_blocks(f));

    char copy_dir[256];
    test_make_tmpdir(copy_dir, sizeof(copy_dir), "body_crosscheck", "copy");
    BX_CHECK("copy datadir (bodies + node.db) built",
             bx_build_copy(copy_dir, f));

    /* (1) happy path */
    {
        char pd[256];
        test_make_tmpdir(pd, sizeof(pd), "body_crosscheck", "p1");
        BX_CHECK("happy: producer built",
                 bx_build_producer(pd, f, BX_CHECKPOINT));
        struct crosscheck_result r;
        bool ok = shielded_history_body_crosscheck_run(copy_dir, pd,
                                                       BX_CHECKPOINT, &r);
        BX_CHECK("happy: run returns true", ok);
        BX_CHECK("happy: sprout_ok && nullifiers_ok",
                 ok && r.sprout_ok && r.nullifiers_ok);
        BX_CHECK("happy: nf_count == 8", r.nf_count == 8);
        BX_CHECK("happy: sprout_frontier_count == 3",
                 r.sprout_frontier_count == 3);
        BX_CHECK("happy: max_height == checkpoint",
                 r.max_height == BX_CHECKPOINT);
        test_rm_rf_recursive(pd);
    }

    /* (2) tampered producer Sprout frontier -> sprout_ok=false (verdict) */
    {
        char pd[256];
        test_make_tmpdir(pd, sizeof(pd), "body_crosscheck", "p2");
        BX_CHECK("tamper: producer built",
                 bx_build_producer(pd, f, BX_CHECKPOINT));
        BX_CHECK("tamper: anchor@6 corrupted", bx_tamper_anchor(pd, 6));
        struct crosscheck_result r;
        bool ok = shielded_history_body_crosscheck_run(copy_dir, pd,
                                                       BX_CHECKPOINT, &r);
        BX_CHECK("tamper: run returns true (verdict, not infra)", ok);
        BX_CHECK("tamper: sprout_ok == false", ok && !r.sprout_ok);
        BX_CHECK("tamper: nullifiers_ok stays true", ok && r.nullifiers_ok);
        test_rm_rf_recursive(pd);
    }

    /* (3) dropped producer nullifier -> nullifiers_ok=false */
    {
        char pd[256];
        test_make_tmpdir(pd, sizeof(pd), "body_crosscheck", "p3");
        BX_CHECK("drop: producer built",
                 bx_build_producer(pd, f, BX_CHECKPOINT));
        BX_CHECK("drop: nullifier@1 removed", bx_drop_nf(pd, 1));
        struct crosscheck_result r;
        bool ok = shielded_history_body_crosscheck_run(copy_dir, pd,
                                                       BX_CHECKPOINT, &r);
        BX_CHECK("drop: run returns true", ok);
        BX_CHECK("drop: nullifiers_ok == false (body nf not in producer)",
                 ok && !r.nullifiers_ok);
        BX_CHECK("drop: sprout_ok stays true", ok && r.sprout_ok);
        test_rm_rf_recursive(pd);
    }

    /* (4) extra bogus producer nullifier -> nullifiers_ok=false */
    {
        char pd[256];
        test_make_tmpdir(pd, sizeof(pd), "body_crosscheck", "p4");
        BX_CHECK("extra: producer built",
                 bx_build_producer(pd, f, BX_CHECKPOINT));
        BX_CHECK("extra: bogus nullifier@3 added", bx_add_bogus_nf(pd, 3));
        struct crosscheck_result r;
        bool ok = shielded_history_body_crosscheck_run(copy_dir, pd,
                                                       BX_CHECKPOINT, &r);
        BX_CHECK("extra: run returns true", ok);
        BX_CHECK("extra: nullifiers_ok == false (producer nf not in body)",
                 ok && !r.nullifiers_ok);
        test_rm_rf_recursive(pd);
    }

    /* (5) corrupted body byte -> infrastructure failure (run==false).
     * LAST: it mutates the shared copy datadir. */
    {
        char pd[256];
        test_make_tmpdir(pd, sizeof(pd), "body_crosscheck", "p5");
        BX_CHECK("corrupt: producer built",
                 bx_build_producer(pd, f, BX_CHECKPOINT));
        BX_CHECK("corrupt: body byte flipped", bx_corrupt_body(copy_dir, f));
        struct crosscheck_result r;
        bool ok = shielded_history_body_crosscheck_run(copy_dir, pd,
                                                       BX_CHECKPOINT, &r);
        BX_CHECK("corrupt: run returns false (infrastructure failure)", !ok);
        test_rm_rf_recursive(pd);
    }

    bx_free_fixture(f);
    free(f);
    test_rm_rf_recursive(copy_dir);

    if (failures == 0)
        printf("=== body_crosscheck: ALL PASS ===\n\n");
    else
        printf("body_crosscheck: failures=%d\n", failures);
    return failures;
}
