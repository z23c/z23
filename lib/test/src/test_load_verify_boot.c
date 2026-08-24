/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_load_verify_boot — the additive load-verify normal-boot routing gate.
 *
 * The load-bearing property: a baked anchor snapshot is LOADED into coins_kv on a
 * normal boot ONLY when its recomputed body SHA3 EQUALS the compiled SHA3 UTXO
 * checkpoint; a snapshot whose SHA3 MISMATCHES is REFUSED (never seeds a bad set),
 * and the boot falls back to the proven path. This test pins the public gate
 * (boot_load_verify_snapshot_eligible) AND the exact loader binding the seed uses
 * (uss_open with expected_sha3 = the compiled checkpoint), against a scaled-down
 * synthetic snapshot whose body SHA3 IS an installed checkpoint override.
 *
 *   (a) MATCH   : snapshot SHA3 == checkpoint  → eligible=true; the verified set
 *                 iterates into coins_kv at the anchor count.
 *   (b) MISMATCH: snapshot SHA3 != checkpoint  → uss_open(.,expected=cp) returns
 *                 NULL AND eligible=false → REFUSED, coins_kv stays untouched.
 *   (c) ABSENT  : no snapshot file            → eligible=false (safe fallback).
 *   (d) HEALTHY : coins_kv already the proven authority → eligible=false even with
 *                 a matching snapshot present (a synced node is never reset).
 */

#include "test/test_core.h"

#include "config/boot.h"
#include "config/boot_shielded_seed.h"
#include "config/boot_snapshot_install.h"
#include "chain/chain.h"
#include "models/database.h"
#include "models/block.h"
#include "jobs/reducer_frontier.h"
#include "services/seed_integrity_gate.h"
#include "services/chain_restore_boot_snapshot.h"
#include "storage/progress_store.h"
#include "storage/coins_kv.h"
#include "storage/anchor_kv.h"
#include "storage/nullifier_kv.h"
#include "storage/snapshot_shielded.h"
#include "chain/checkpoints.h"
#include "chain/utxo_snapshot_loader.h"
#include "core/uint256.h"
#include "crypto/sha3.h"
#include "encoding/utilstrencodings.h"
#include "util/safe_alloc.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"

#include <dirent.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define LV_CHECK(name, expr) do {                                       \
    if (expr) { printf("  load_verify_boot: %s... OK\n", (name)); }      \
    else { printf("  load_verify_boot: %s... FAIL\n", (name)); failures++; } \
} while (0)

static void lv_wle32(uint8_t *p, uint32_t v)
{ p[0]=(uint8_t)v; p[1]=(uint8_t)(v>>8); p[2]=(uint8_t)(v>>16); p[3]=(uint8_t)(v>>24); }
static void lv_wle64(uint8_t *p, uint64_t v)
{ for (int i=0;i<8;i++) p[i]=(uint8_t)(v>>(8*i)); }

/* Build a tiny but valid USS snapshot body (N records) and return the body SHA3
 * + the assembled file bytes. `tamper` flips one body byte so the on-disk SHA3
 * differs from the header's claimed root (but we DELIBERATELY do NOT update the
 * header root, so the header still claims `body_sha3` — the loader's full-body
 * recompute catches the divergence, modeling a corrupted/forged artifact). */
struct lv_built {
    uint8_t  file[8192];
    size_t   file_len;
    uint8_t  body_sha3[32];
    uint64_t count;
    int64_t  total;
};
static void lv_build_snapshot(struct lv_built *b, bool tamper)
{
    uint8_t body[4096] = {0};
    size_t off = 0;
    uint8_t txid[32];
    for (int i = 0; i < 32; i++) txid[i] = (uint8_t)(0x40 + i);

    struct rec { uint32_t vout; int64_t value; uint8_t s[5]; uint32_t sl;
                 uint32_t height; uint8_t cb; };
    struct rec recs[3] = {
        { 0, 11111, {0x76,0xa9,0x14,0,0}, 3, 10, 1 },
        { 1, 22222, {0x6a,0,0,0,0},       1, 20, 0 },
        { 2, 33333, {0x21,0x02,0x03,0x04,0x05}, 5, 30, 0 },
    };
    int64_t total = 0;
    for (int i = 0; i < 3; i++) {
        memcpy(body + off, txid, 32); off += 32;
        lv_wle32(body + off, recs[i].vout); off += 4;
        lv_wle64(body + off, (uint64_t)recs[i].value); off += 8;
        lv_wle32(body + off, recs[i].sl); off += 4;
        memcpy(body + off, recs[i].s, recs[i].sl); off += recs[i].sl;
        lv_wle32(body + off, recs[i].height); off += 4;
        body[off++] = recs[i].cb;
        total += recs[i].value;
    }
    size_t body_len = off;
    b->count = 3;
    b->total = total;

    /* Hash the CLEAN body — that is the root the header claims AND the override
     * checkpoint will carry. */
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    sha3_256_write(&ctx, body, body_len);
    sha3_256_finalize(&ctx, b->body_sha3);

    /* Optionally tamper a body byte AFTER hashing → on-disk body no longer
     * matches the header root. */
    if (tamper) body[20] ^= 0xff;

    uint8_t header[104] = {0};
    memcpy(header, "ZCLUTXO\x00", 8);
    lv_wle32(header + 8, 1);                 /* version */
    lv_wle32(header + 16, 1234);             /* height */
    lv_wle64(header + 24, b->count);
    lv_wle64(header + 32, (uint64_t)b->total);
    /* anchor block hash header+40 left zero */
    memcpy(header + 72, b->body_sha3, 32);   /* claimed root = CLEAN body sha3 */

    memcpy(b->file, header, 104);
    memcpy(b->file + 104, body, body_len);
    b->file_len = 104 + body_len;
}

static bool lv_write(const char *path, const struct lv_built *b)
{
    FILE *f = fopen(path, "wb");
    if (!f) return false;
    size_t w = fwrite(b->file, 1, b->file_len, f);
    fclose(f);
    return w == b->file_len;
}

static bool lv_artifact_sha256(const char *path, uint8_t out[32])
{
    char err[128] = {0};
    struct uss_header hdr;
    struct uss_handle *h = uss_open(path, true, NULL, &hdr, err, sizeof(err));
    if (!h) return false;
    bool ok = uss_artifact_sha256(h, out);
    uss_close(h);
    return ok;
}

static bool lv_progress_path(char *out, size_t cap, const char *dir,
                             const char *suffix)
{
    /* A4: the kernel authority store is consensus.db after the flip; these
     * fixtures corrupt/inspect the authority, so they must target consensus.db
     * (the file the boot loader actually opens and quarantines). */
    int n = snprintf(out, cap, "%s/consensus.db%s", dir, suffix);
    return n > 0 && (size_t)n < cap;
}

static void lv_unlink_progress_store_files(const char *dir)
{
    char path[512];
    if (lv_progress_path(path, sizeof(path), dir, ""))
        unlink(path);
    if (lv_progress_path(path, sizeof(path), dir, "-wal"))
        unlink(path);
    if (lv_progress_path(path, sizeof(path), dir, "-shm"))
        unlink(path);
}

static bool lv_write_junk_progress_store(const char *dir)
{
    lv_unlink_progress_store_files(dir);
    char path[512];
    if (!lv_progress_path(path, sizeof(path), dir, ""))
        return false;
    FILE *f = fopen(path, "wb");
    if (!f)
        return false;
    const char junk[] = "not sqlite";
    bool ok = fwrite(junk, 1, sizeof(junk) - 1, f) == sizeof(junk) - 1;
    ok = fclose(f) == 0 && ok;
    return ok;
}

static bool lv_write_bad_stage_cursor_store(const char *dir)
{
    lv_unlink_progress_store_files(dir);
    char path[512];
    if (!lv_progress_path(path, sizeof(path), dir, ""))
        return false;
    sqlite3 *db = NULL;
    if (sqlite3_open(path, &db) != SQLITE_OK) {
        if (db)
            sqlite3_close(db);
        return false;
    }
    char *err = NULL;
    bool ok = sqlite3_exec(db,
        "CREATE TABLE stage_cursor (name TEXT PRIMARY KEY, bad TEXT);",
        NULL, NULL, &err) == SQLITE_OK;
    if (err)
        sqlite3_free(err);
    ok = sqlite3_close(db) == SQLITE_OK && ok;
    return ok;
}

static bool lv_has_quarantined_progress_store(const char *dir)
{
    DIR *d = opendir(dir);
    if (!d)
        return false;
    bool found = false;
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (strncmp(de->d_name, "consensus.db.quarantine.", 24) == 0) {
            found = true;
            break;
        }
    }
    closedir(d);
    return found;
}

static void lv_hash_for_height(int height, uint8_t out[32])
{
    memset(out, 0, 32);
    out[0] = 0xa5;
    out[1] = (uint8_t)(height & 0xff);
    out[2] = (uint8_t)((height >> 8) & 0xff);
    out[3] = (uint8_t)((height >> 16) & 0xff);
    out[4] = (uint8_t)((height >> 24) & 0xff);
}

static bool lv_save_block_row(struct node_db *ndb,
                              const struct block_index *bi)
{
    if (!ndb || !bi || !bi->phashBlock)
        return false;
    struct db_block row;
    memset(&row, 0, sizeof(row));
    memcpy(row.hash, bi->phashBlock->data, 32);
    row.height = bi->nHeight;
    if (bi->pprev && bi->pprev->phashBlock)
        memcpy(row.prev_hash, bi->pprev->phashBlock->data, 32);
    row.version = 4;
    row.merkle_root[0] = 0x11;
    row.time = 1700000000u + (uint32_t)bi->nHeight;
    row.bits = 0x1f0fffffu;
    row.nonce[0] = 0x22;
    uint8_t solution[1] = {0};
    row.solution = solution;
    row.solution_len = sizeof(solution);
    row.chain_work[0] = (uint8_t)(bi->nHeight & 0xff);
    row.status = BLOCK_VALID_CHAIN;
    row.file_num = 0;
    row.data_pos = bi->nHeight + 1;
    row.undo_pos = bi->nHeight + 2;
    row.num_tx = 1;
    memcpy(row.sapling_root, bi->hashFinalSaplingRoot.data,
           sizeof(row.sapling_root));
    row.sprout_root[0] = 0x44;
    return db_block_save(ndb, &row);
}

static bool lv_ensure_reducer_log_tables(sqlite3 *db)
{
    if (!db)
        return false;
    char *err = NULL;
    bool ok = sqlite3_exec(db,
        "CREATE TABLE IF NOT EXISTS validate_headers_log ("
        "height INTEGER PRIMARY KEY, hash BLOB, ok INTEGER, fail_reason TEXT);"
        "CREATE TABLE IF NOT EXISTS script_validate_log ("
        "height INTEGER PRIMARY KEY, status TEXT, ok INTEGER, "
        "fail_reason TEXT, block_hash BLOB);"
        "CREATE TABLE IF NOT EXISTS body_persist_log ("
        "height INTEGER PRIMARY KEY, ok INTEGER, fail_reason TEXT);"
        "CREATE TABLE IF NOT EXISTS proof_validate_log ("
        "height INTEGER PRIMARY KEY, status TEXT, ok INTEGER, "
        "fail_reason TEXT);"
        "CREATE TABLE IF NOT EXISTS utxo_apply_log ("
        "height INTEGER PRIMARY KEY, status TEXT, ok INTEGER,"
        "spent_count INTEGER, added_count INTEGER, total_value_delta INTEGER,"
        "applied_at INTEGER);"
        "CREATE TABLE IF NOT EXISTS tip_finalize_log ("
        "height INTEGER PRIMARY KEY, status TEXT, ok INTEGER,"
        "work_delta BLOB, utxo_size_after INTEGER, finalized_at INTEGER,"
        "tip_hash BLOB);",
        NULL, NULL, &err) == SQLITE_OK;
    if (err)
        sqlite3_free(err);
    return ok;
}

static bool lv_seed_active_chain(struct main_state *ms,
                                 struct node_db *ndb,
                                 int tip_h,
                                 int sapling_root_height,
                                 const struct uint256 *sapling_root,
                                 struct block_index **owned_blocks)
{
    if (!ms || !ndb || tip_h < 0 || !owned_blocks)
        return false;
    *owned_blocks = NULL;
    struct block_index *blocks =
        zcl_calloc((size_t)tip_h + 1u, sizeof(struct block_index),
                   "lv_active_chain_blocks");
    if (!blocks)
        return false;
    for (int h = 0; h <= tip_h; h++) {
        block_index_init(&blocks[h]);
        blocks[h].nHeight = h;
        lv_hash_for_height(h, blocks[h].hashBlock.data);
        blocks[h].phashBlock = &blocks[h].hashBlock;
        blocks[h].nTime = 1700000000u + (uint32_t)h;
        blocks[h].nBits = 0x1f0fffffu;
        blocks[h].nStatus = BLOCK_VALID_CHAIN | BLOCK_HAVE_DATA;
        if (sapling_root && h == sapling_root_height)
            blocks[h].hashFinalSaplingRoot = *sapling_root;
        if (h > 0)
            blocks[h].pprev = &blocks[h - 1];
        if (!lv_save_block_row(ndb, &blocks[h])) {
            free(blocks);
            return false;
        }
    }
    if (!active_chain_move_window_tip(&ms->chain_active, &blocks[tip_h])) {
        free(blocks);
        return false;
    }
    ms->pindex_best_header = &blocks[tip_h];
    *owned_blocks = blocks;
    return true;
}

static bool lv_seed_snapshot_coins(sqlite3 *db)
{
    uint8_t txid_a[32] = {0x31};
    uint8_t txid_b[32] = {0x52};
    return coins_kv_ensure_schema(db) &&
           coins_kv_add(db, txid_a, 0, 1100, 7, true,
                        (const uint8_t *)"\x51", 1) &&
           coins_kv_add(db, txid_b, 1, 2200, 19, false,
                        (const uint8_t *)"\x6a", 1);
}

static int32_t lv_compute_hstar(sqlite3 *db)
{
    int32_t hstar = -1;
    int32_t served = -1;
    progress_store_tx_lock();
    bool ok = reducer_frontier_compute_hstar(db, &hstar, &served);
    progress_store_tx_unlock();
    return ok ? hstar : -1;
}

static bool lv_force_stage_cursor(sqlite3 *db, const char *name, int cursor)
{
    sqlite3_stmt *st = NULL;
    if (!db || !name)
        return false;
    if (sqlite3_prepare_v2(db,
            "INSERT INTO stage_cursor(name,cursor,updated_at) "
            "VALUES(?,?,0) ON CONFLICT(name) DO UPDATE SET "
            "cursor=excluded.cursor, updated_at=excluded.updated_at",
            -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_text(st, 1, name, -1, SQLITE_STATIC);
    sqlite3_bind_int(st, 2, cursor);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE;
}

static int lv_stage_cursor(sqlite3 *db, const char *name)
{
    sqlite3_stmt *st = NULL;
    int out = -1;
    if (!db || !name)
        return out;
    if (sqlite3_prepare_v2(db,
            "SELECT cursor FROM stage_cursor WHERE name=?",
            -1, &st, NULL) != SQLITE_OK)
        return out;
    sqlite3_bind_text(st, 1, name, -1, SQLITE_STATIC);
    if (sqlite3_step(st) == SQLITE_ROW)
        out = sqlite3_column_int(st, 0);
    sqlite3_finalize(st);
    return out;
}

/* File-scope seed callback (mirrors config/src/boot_refold_staged.c
 * mint_load_record_cb): insert one snapshot record into coins_kv. */
struct lv_seed_lc { sqlite3 *db; uint64_t n; bool ok; };
static bool lv_seed_cb(const struct uss_record *r, void *vctx)
{
    struct lv_seed_lc *lc = vctx;
    if (!coins_kv_add(lc->db, r->txid, r->vout, r->value, (int32_t)r->height,
                      r->is_coinbase != 0, r->script, (size_t)r->script_len)) {
        lc->ok = false;
        return false;
    }
    lc->n++;
    return true;
}

int test_load_verify_boot(void);
int test_load_verify_boot(void)
{
    int failures = 0;
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "load_verify_boot", "main");

    /* progress.kv with a coins_kv schema (empty → NOT proven authority). */
    LV_CHECK("progress_store opens", progress_store_open(dir));
    sqlite3 *pdb = progress_store_db();
    LV_CHECK("pdb handle", pdb != NULL);
    LV_CHECK("coins_kv schema", coins_kv_ensure_schema(pdb));
    LV_CHECK("coins_kv empty", coins_kv_count(pdb) == 0);

    /* node.db (mint_snapshot_path needs a non-NULL ndb; with ZCL_MINT_ANCHOR_OUT
     * set it never derefs the path, but the eligibility guard requires non-NULL). */
    char dbpath[320];
    snprintf(dbpath, sizeof(dbpath), "%s/node.db", dir);
    struct node_db ndb;
    LV_CHECK("node_db opens", node_db_open(&ndb, dbpath));

    /* Point the mint-snapshot path helper directly at our sidecar via the env
     * override the production path-derivation honors. */
    char snap_path[400];
    snprintf(snap_path, sizeof(snap_path), "%s/utxo-anchor.snapshot", dir);
    setenv("ZCL_MINT_ANCHOR_OUT", snap_path, 1);

    /* Build a MATCHING snapshot and install its body SHA3 as the checkpoint. */
    struct lv_built ok_snap;
    lv_build_snapshot(&ok_snap, /*tamper=*/false);
    struct sha3_utxo_checkpoint cp_ovr;
    memset(&cp_ovr, 0, sizeof(cp_ovr));
    cp_ovr.height = 1234;
    memcpy(cp_ovr.sha3_hash, ok_snap.body_sha3, 32);
    cp_ovr.utxo_count = ok_snap.count;
    cp_ovr.total_supply = ok_snap.total;
    checkpoints_set_sha3_override_for_test(&cp_ovr);

    /* (c) ABSENT snapshot → eligible=false (safe fallback, no file yet). */
    unlink(snap_path);
    LV_CHECK("(c) absent snapshot → NOT eligible",
             !boot_load_verify_snapshot_eligible(&ndb, pdb));

    /* (a) MATCH: write the matching snapshot. */
    LV_CHECK("write matching snapshot", lv_write(snap_path, &ok_snap));
    LV_CHECK("(a) matching snapshot → eligible",
             boot_load_verify_snapshot_eligible(&ndb, pdb));

    /* (a) the verified set actually LOADS via the same loader binding the seed
     * uses (uss_open with expected_sha3 = the checkpoint), and iterates into
     * coins_kv at the anchor count. */
    {
        char err[128] = {0};
        struct uss_header hdr;
        const struct sha3_utxo_checkpoint *cp = get_sha3_utxo_checkpoint();
        struct uss_handle *h = uss_open(snap_path, /*verify_full_sha3=*/true,
                                        cp->sha3_hash, &hdr, err, sizeof(err));
        LV_CHECK("(a) uss_open binds checkpoint root + verifies", h != NULL);
        if (h) {
            LV_CHECK("(a) header count == checkpoint", hdr.count == cp->utxo_count);
            /* Seed coins_kv exactly like config/src/boot_refold_staged.c's
             * mint_load_record_cb does (file-scope lv_seed_cb below). */
            struct lv_seed_lc lc = { .db = pdb, .n = 0, .ok = true };
            int64_t emitted = uss_iter(h, lv_seed_cb, &lc);
            LV_CHECK("(a) seeded all records", emitted == (int64_t)hdr.count && lc.ok);
            LV_CHECK("(a) coins_kv holds the anchor count",
                     coins_kv_count(pdb) == (int64_t)cp->utxo_count);
            uss_close(h);
        }
    }

    /* (d) HEALTHY: coins_kv now holds the set; mark the migration-complete stamp
     * + applied height so it is the PROVEN authority → eligible must be FALSE even
     * though the matching snapshot is still present (never reset a synced node). */
    {
        char *terr = NULL;
        sqlite3_exec(pdb, "BEGIN IMMEDIATE", NULL, NULL, &terr);
        uint8_t one = 1;
        (void)progress_meta_set_in_tx(pdb, COINS_KV_MIGRATION_COMPLETE_KEY, &one, 1);
        (void)coins_kv_set_applied_height_in_tx(pdb, 1234);
        sqlite3_exec(pdb, "COMMIT", NULL, NULL, &terr);
        if (terr) sqlite3_free(terr);
        LV_CHECK("(d) proven authority → NOT eligible",
                 coins_kv_is_proven_authority(pdb, NULL) &&
                 !boot_load_verify_snapshot_eligible(&ndb, pdb));
    }

    /* Reset coins_kv back to empty for the mismatch case (not proven). */
    LV_CHECK("reset coins_kv for mismatch case", coins_kv_reset_for_reseed(pdb));
    LV_CHECK("coins_kv empty again", coins_kv_count(pdb) == 0);

    /* (b) MISMATCH: write a snapshot whose on-disk body SHA3 != the header's
     * claimed root == the checkpoint. uss_open(.,expected=cp) must REFUSE it
     * (NULL) and the gate must be FALSE → a bad set NEVER seeds. */
    {
        struct lv_built bad_snap;
        lv_build_snapshot(&bad_snap, /*tamper=*/true);
        /* Header still claims ok_snap.body_sha3 (== checkpoint) but the body was
         * tampered → full-body recompute diverges. */
        LV_CHECK("write tampered snapshot", lv_write(snap_path, &bad_snap));

        char err[128] = {0};
        const struct sha3_utxo_checkpoint *cp = get_sha3_utxo_checkpoint();
        struct uss_handle *h = uss_open(snap_path, /*verify_full_sha3=*/true,
                                        cp->sha3_hash, NULL, err, sizeof(err));
        LV_CHECK("(b) tampered snapshot REFUSED by loader", h == NULL);
        if (h) uss_close(h);
        LV_CHECK("(b) tampered snapshot → NOT eligible",
                 !boot_load_verify_snapshot_eligible(&ndb, pdb));
        LV_CHECK("(b) coins_kv NEVER seeded by a bad set",
                 coins_kv_count(pdb) == 0);
    }

    /* (b2) MISMATCH via wrong-checkpoint: a clean snapshot whose root != the
     * compiled checkpoint (different override). uss_open binds expected_sha3 and
     * rejects at the header memcmp BEFORE the body recompute. */
    {
        struct lv_built ok2;
        lv_build_snapshot(&ok2, /*tamper=*/false);
        LV_CHECK("rewrite clean snapshot", lv_write(snap_path, &ok2));
        /* Install a DIFFERENT checkpoint root (flip a byte) so the snapshot's
         * (valid) root no longer equals the checkpoint. */
        struct sha3_utxo_checkpoint cp_wrong = cp_ovr;
        cp_wrong.sha3_hash[0] ^= 0xff;
        checkpoints_set_sha3_override_for_test(&cp_wrong);

        char err[128] = {0};
        struct uss_handle *h = uss_open(snap_path, /*verify_full_sha3=*/true,
                                        cp_wrong.sha3_hash, NULL, err, sizeof(err));
        LV_CHECK("(b2) wrong-checkpoint snapshot REFUSED", h == NULL);
        if (h) uss_close(h);
        LV_CHECK("(b2) wrong-checkpoint → NOT eligible",
                 !boot_load_verify_snapshot_eligible(&ndb, pdb));
        LV_CHECK("(b2) coins_kv still untouched", coins_kv_count(pdb) == 0);
    }

    /* (e) P1-6: after a snapshot is SELF-SHA3 verified, the explicit
     * -load-snapshot-at-own-height loader may quarantine a broken local
     * authority store and rebuild it from that verified set. */
    {
        checkpoints_set_sha3_override_for_test(&cp_ovr);
        LV_CHECK("(e) rewrite matching snapshot for authority-store recovery",
                 lv_write(snap_path, &ok_snap));

        uint8_t old_nf[32] = {0xA5};
        uint8_t old_txid[32] = {0xC3};
        LV_CHECK("(e0) seed stale complete shielded history",
                 test_complete_genesis_shielded_replay(pdb) &&
                 nullifier_kv_add(pdb, old_nf, NULLIFIER_POOL_SAPLING, 7));
        LV_CHECK("(e0) seed pre-transition coin",
                 coins_kv_add(pdb, old_txid, 0, 99, 1, false,
                              (const uint8_t *)"\x51", 1));
        boot_shielded_interrupt_after_boundary_for_test(true);
        boot_load_snapshot_at_own_height_reset(&ndb, snap_path, dir, NULL, true);
        int64_t nf_boundary = 0, sprout_boundary = 0, sapling_boundary = 0;
        bool nf_found = false, sprout_found = false, sapling_found = false;
        bool old_nf_found = true;
        LV_CHECK("(e0) interruption leaves pre-reset coins untouched",
                 coins_kv_count(pdb) == 1);
        LV_CHECK("(e0) interruption already published positive shielded boundary",
                 nullifier_kv_activation_cursor(pdb, &nf_boundary, &nf_found) &&
                 anchor_kv_activation_cursor(pdb, ANCHOR_POOL_SPROUT,
                                              &sprout_boundary, &sprout_found) &&
                 anchor_kv_activation_cursor(pdb, ANCHOR_POOL_SAPLING,
                                              &sapling_boundary, &sapling_found) &&
                 nf_found && sprout_found && sapling_found &&
                 nf_boundary == 1234 && sprout_boundary == 1234 &&
                 sapling_boundary == 1234);
        LV_CHECK("(e0) interruption cannot retain stale nullifier rows",
                 nullifier_kv_get(pdb, old_nf, NULLIFIER_POOL_SAPLING,
                                  &old_nf_found, NULL) && !old_nf_found);

        bool marker_matches = false;
        bool marker_pending = false;
        uint8_t ok_artifact_sha256[32] = {0};
        LV_CHECK("(e0) exact snapshot identity hashes",
                 lv_artifact_sha256(snap_path, ok_artifact_sha256));
        LV_CHECK("(e0) interrupted install is a global pending boot gate",
                 boot_snapshot_install_marker_pending(pdb, &marker_pending) &&
                     marker_pending);
        LV_CHECK("(e0) interrupted install leaves matching durable marker",
                 boot_snapshot_install_marker_blocks_resume(
                     pdb, ok_artifact_sha256, &marker_matches) &&
                     marker_matches);
        bool bound_pending = false;
        LV_CHECK("(e0) pending gate accepts exact fully verified artifact",
                 boot_snapshot_install_pending_artifact_matches(
                     pdb, snap_path, &bound_pending) && bound_pending);
        marker_matches = true;
        LV_CHECK("(e0) mismatched marker identity still blocks resume",
                 boot_snapshot_install_marker_blocks_resume(
                     pdb, (uint8_t[32]){0x7F}, &marker_matches) &&
                     !marker_matches);
        struct lv_built interrupted_bad_snap;
        lv_build_snapshot(&interrupted_bad_snap, /*tamper=*/true);
        LV_CHECK("(e0) replace pending artifact with corrupt same-header file",
                 lv_write(snap_path, &interrupted_bad_snap));
        bound_pending = false;
        LV_CHECK("(e0) pending gate rejects corrupt same-header artifact",
                 !boot_snapshot_install_pending_artifact_matches(
                     pdb, snap_path, &bound_pending) && bound_pending);
        LV_CHECK("(e0) restore exact pending artifact",
                 lv_write(snap_path, &ok_snap));

        /* Restart on the same healthy authority store. The marker must defeat
         * RESUME-FAST, rerun the verified loader, and clear only after the
         * durable tip/trusted-base seed succeeds. */
        boot_load_snapshot_at_own_height_reset(&ndb, snap_path, dir, NULL,
                                               true);
        int32_t interrupted_applied = -1;
        bool interrupted_found = false;
        LV_CHECK("(e0) restart converges interrupted install",
                 coins_kv_count(pdb) == (int64_t)ok_snap.count &&
                 coins_kv_get_applied_height(pdb, &interrupted_applied,
                                             &interrupted_found) &&
                 interrupted_found && interrupted_applied == 1235);
        LV_CHECK("(e0) successful tip seed completes exact receipt",
                 (marker_matches = false,
                  !boot_snapshot_install_marker_blocks_resume(
                      pdb, ok_artifact_sha256, &marker_matches)) &&
                     marker_matches);
        struct chain_restore_boot_snapshot boot_proof;
        chain_restore_get_boot_snapshot(&boot_proof);
        char expected_artifact_sha256[65] = {0};
        HexStr(ok_artifact_sha256, 32, false, expected_artifact_sha256,
               sizeof(expected_artifact_sha256));
        LV_CHECK("(e0) dumpstate proof records committed verified reseed",
                 boot_proof.assisted_snapshot_body_sha3_verified &&
                 !boot_proof.assisted_snapshot_embedded_frontier_verified &&
                 boot_proof.assisted_snapshot_reseed_committed &&
                 boot_proof.assisted_snapshot_seed_height == 1234 &&
                 boot_proof.assisted_snapshot_record_count == ok_snap.count &&
                 strcmp(boot_proof.assisted_snapshot_payload_sha3,
                        "") != 0 &&
                 strcmp(boot_proof.assisted_snapshot_anchor_block_hash,
                        "0000000000000000000000000000000000000000000000000000000000000000") == 0 &&
                 strcmp(boot_proof.assisted_snapshot_path, snap_path) == 0);
        LV_CHECK("(e0) converged install clears global pending boot gate",
                 boot_snapshot_install_marker_pending(pdb, &marker_pending) &&
                     !marker_pending);
        bound_pending = true;
        LV_CHECK("(e0) no pending journal needs no loader artifact",
                 boot_snapshot_install_pending_artifact_matches(
                     pdb, NULL, &bound_pending) && !bound_pending);

        progress_store_close();
        LV_CHECK("(e0) completed receipt survives store reopen",
                 progress_store_open(dir));
        pdb = progress_store_db();
        marker_matches = false;
        LV_CHECK("(e0) reopened receipt retains exact artifact identity",
                 pdb && !boot_snapshot_install_marker_blocks_resume(
                            pdb, ok_artifact_sha256, &marker_matches) &&
                     marker_matches);
        LV_CHECK("(e0) resume fixture has reducer log schemas",
                 lv_ensure_reducer_log_tables(pdb));
        uint8_t resume_poison[32] = {0xD6};
        LV_CHECK("(e0) seed post-snapshot forward-state witness",
                 coins_kv_add(pdb, resume_poison, 0, 9, 1235, false,
                              (const uint8_t *)"\x51", 1));
        chain_restore_boot_snapshot_reset_for_testing();
        boot_load_snapshot_at_own_height_reset(&ndb, snap_path, dir, NULL,
                                               true);
        chain_restore_get_boot_snapshot(&boot_proof);
        LV_CHECK("(e0) RESUME-FAST republishes exact completed receipt",
                 boot_proof.assisted_snapshot_body_sha3_verified &&
                 boot_proof.assisted_snapshot_reseed_committed &&
                 !boot_proof.assisted_snapshot_embedded_frontier_verified &&
                 boot_proof.assisted_snapshot_record_count == ok_snap.count &&
                 strcmp(boot_proof.assisted_snapshot_payload_sha3, "") != 0 &&
                 strcmp(boot_proof.assisted_snapshot_artifact_sha256,
                        expected_artifact_sha256) == 0 &&
                 strcmp(boot_proof.assisted_snapshot_path, snap_path) == 0 &&
                 coins_kv_exists(pdb, resume_poison, 0));

        char *generation_err = NULL;
        bool generation_advanced =
            sqlite3_exec(pdb, "BEGIN IMMEDIATE", NULL, NULL,
                         &generation_err) == SQLITE_OK &&
            coins_kv_bump_authority_generation_in_tx(pdb) &&
            sqlite3_exec(pdb, "COMMIT", NULL, NULL,
                         &generation_err) == SQLITE_OK;
        if (!generation_advanced)
            (void)sqlite3_exec(pdb, "ROLLBACK", NULL, NULL, NULL);
        sqlite3_free(generation_err);
        int32_t stale_applied = -1;
        bool stale_pending = true, stale_matches = false;
        bool stale_frontier = true;
        LV_CHECK("(e0) authority generation invalidates completed receipt",
                 generation_advanced &&
                 !boot_snapshot_install_resume_allowed(
                     pdb, &(struct uss_header){.height = 1234},
                     ok_artifact_sha256, &stale_applied, &stale_pending,
                     &stale_matches, &stale_frontier) &&
                 !stale_pending && stale_matches && !stale_frontier);

        LV_CHECK("(e0) delete completed receipt for absent-receipt refusal",
                 progress_meta_delete(
                     pdb, BOOT_SNAPSHOT_INSTALL_MARKER_KEY));
        int32_t absent_applied = -1;
        bool absent_pending = true, absent_matches = true;
        bool absent_frontier = true;
        LV_CHECK("(e0) generic coins authority cannot replace absent receipt",
                 !boot_snapshot_install_resume_allowed(
                     pdb, &(struct uss_header){.height = 1234},
                     ok_artifact_sha256, &absent_applied, &absent_pending,
                     &absent_matches, &absent_frontier) &&
                     !absent_pending && !absent_matches && !absent_frontier);

        uint8_t legacy_marker[BOOT_SNAPSHOT_INSTALL_MARKER_BYTES] = {0};
        memcpy(legacy_marker, "ZCLSIM1", 7);
        lv_wle32(legacy_marker + 8, 1);
        lv_wle32(legacy_marker + 12,
                 BOOT_SNAPSHOT_INSTALL_MARKER_BYTES);
        lv_wle32(legacy_marker + 16, 1234);
        lv_wle64(legacy_marker + 24, ok_snap.count);
        memcpy(legacy_marker + 32, ok_snap.body_sha3, 32);
        struct uss_header legacy_header = {
            .height = 1234,
            .count = ok_snap.count,
        };
        memcpy(legacy_header.sha3_hash, ok_snap.body_sha3, 32);
        LV_CHECK("(e0) legacy v1 pending receipt is readable",
                 progress_meta_set(
                     pdb, BOOT_SNAPSHOT_INSTALL_MARKER_KEY,
                     legacy_marker, sizeof(legacy_marker)) &&
                 boot_snapshot_install_marker_pending(pdb, &marker_pending) &&
                 marker_pending &&
                 boot_snapshot_install_pending_artifact_matches(
                     pdb, snap_path, &bound_pending) && bound_pending);
        lv_wle64(legacy_marker + 24, ok_snap.count + 1);
        LV_CHECK("(e0) mismatched legacy v1 receipt fails closed",
                 progress_meta_set(
                     pdb, BOOT_SNAPSHOT_INSTALL_MARKER_KEY,
                     legacy_marker, sizeof(legacy_marker)) &&
                 !boot_snapshot_install_pending_artifact_matches(
                     pdb, snap_path, &bound_pending) && bound_pending);
        lv_wle64(legacy_marker + 24, ok_snap.count);
        LV_CHECK("(e0) verified legacy v1 receipt upgrades to exact v2",
                 progress_meta_set(
                     pdb, BOOT_SNAPSHOT_INSTALL_MARKER_KEY,
                     legacy_marker, sizeof(legacy_marker)) &&
                 boot_snapshot_install_marker_begin(
                     pdb, &legacy_header, ok_artifact_sha256) &&
                 boot_snapshot_install_marker_blocks_resume(
                     pdb, ok_artifact_sha256, &marker_matches) &&
                 marker_matches);

        /* Model a kill after the standalone applied-height COMMIT: authority
         * is true, but the in-progress marker must still force a destructive
         * verified reseed. A poison coin proves the fast-resume path did not
         * run. */
        uint8_t poison_txid[32] = {0xE7};
        LV_CHECK("(e0b) arm applied-height crash marker",
                 boot_snapshot_install_marker_begin(
                     pdb, &(struct uss_header){
                         .height = 1234, .count = ok_snap.count},
                     ok_artifact_sha256));
        LV_CHECK("(e0b) add poison coin to partial authority fixture",
                 coins_kv_add(pdb, poison_txid, 0, 7, 1234, false,
                              (const uint8_t *)"\x51", 1) &&
                 coins_kv_is_proven_authority(pdb, NULL));
        boot_load_snapshot_at_own_height_reset(&ndb, snap_path, dir, NULL,
                                               true);
        LV_CHECK("(e0b) marker suppresses RESUME-FAST and removes poison",
                 coins_kv_count(pdb) == (int64_t)ok_snap.count &&
                 !coins_kv_exists(pdb, poison_txid, 0));
        LV_CHECK("(e0b) converged retry clears marker",
                 !boot_snapshot_install_marker_blocks_resume(
                     pdb, ok_artifact_sha256, NULL));

        progress_store_close();
        LV_CHECK("(e1) corrupt progress.kv fixture written",
                 lv_write_junk_progress_store(dir));
        boot_load_snapshot_at_own_height_reset(&ndb, snap_path, dir, NULL, true);
        pdb = progress_store_db();
        int32_t applied = -1;
        bool found = false;
        LV_CHECK("(e1) corrupt progress.kv quarantined",
                 lv_has_quarantined_progress_store(dir));
        LV_CHECK("(e1) loader rebuilt coins_kv from verified snapshot",
                 pdb && coins_kv_count(pdb) == (int64_t)ok_snap.count &&
                 coins_kv_get_applied_height(pdb, &applied, &found) &&
                 found && applied == 1235);

        progress_store_close();
        LV_CHECK("(e2) bad stage_cursor fixture written",
                 lv_write_bad_stage_cursor_store(dir));
        LV_CHECK("(e2) bad schema progress_store opens",
                 progress_store_open(dir));
        boot_load_snapshot_at_own_height_reset(&ndb, snap_path, dir, NULL, true);
        pdb = progress_store_db();
        applied = -1;
        found = false;
        LV_CHECK("(e2) bad schema progress.kv quarantined",
                 lv_has_quarantined_progress_store(dir));
        LV_CHECK("(e2) loader rebuilt stage cursors and coins_kv",
                 pdb && coins_kv_count(pdb) == (int64_t)ok_snap.count &&
                 coins_kv_get_applied_height(pdb, &applied, &found) &&
                 found && applied == 1235);
    }

    /* (f) RESUME-FAST repair: if the persisted coins_kv authority has already
     * advanced beyond the snapshot seed, the explicit loader must not merely
     * skip re-seeding. It also has to seed the trusted reducer base at the
     * applied coins frontier, or H* falls back to the old checkpoint/log hole
     * and the public API reports a stale height after boot. */
    {
        struct main_state ms;
        main_state_init(&ms);
        struct block_index *owned_blocks = NULL;
        bool ok = lv_seed_active_chain(&ms, &ndb, 1239, -1, NULL,
                                       &owned_blocks);
        LV_CHECK("(f) active chain fixture reaches applied frontier", ok);
        struct lv_built bound_snap = ok_snap;
        if (ok)
            memcpy(bound_snap.file + 40,
                   owned_blocks[1234].hashBlock.data, 32);
        LV_CHECK("(f) write snapshot bound to active-chain seed",
                 ok && lv_write(snap_path, &bound_snap));
        if (ok)
            boot_load_snapshot_at_own_height_reset(
                &ndb, snap_path, dir, &ms, true);

        pdb = progress_store_db();
        char *terr = NULL;
        ok = pdb &&
            sqlite3_exec(pdb, "BEGIN IMMEDIATE", NULL, NULL, &terr) == SQLITE_OK;
        uint8_t one = 1;
        ok = ok &&
             progress_meta_set_in_tx(pdb, COINS_KV_MIGRATION_COMPLETE_KEY,
                                     &one, 1) &&
             coins_kv_set_applied_height_in_tx(pdb, 1240) &&
             sqlite3_exec(pdb, "COMMIT", NULL, NULL, &terr) == SQLITE_OK;
        if (!ok && pdb)
            sqlite3_exec(pdb, "ROLLBACK", NULL, NULL, NULL);
        if (terr)
            sqlite3_free(terr);
        LV_CHECK("(f) setup proven coins authority above snapshot seed", ok);
        LV_CHECK("(f) reducer log schemas exist",
                 pdb && lv_ensure_reducer_log_tables(pdb));
        LV_CHECK("(f) stale high header cursor fixture",
                 pdb && lv_force_stage_cursor(pdb, "validate_headers", 1250));
        LV_CHECK("(f) H* starts at checkpoint before resume repair",
                 pdb && lv_compute_hstar(pdb) == 1234);

        seed_integrity_gate_reset_for_testing();
        seed_integrity_gate_set_node_db_for_testing(&ndb);
        if (ok)
            boot_load_snapshot_at_own_height_reset(&ndb, snap_path, dir, &ms,
                                                   true);
        seed_integrity_gate_reset_for_testing();

        int32_t hstar_after = pdb ? lv_compute_hstar(pdb) : -1;
        int32_t applied = -1;
        bool found = false;
        LV_CHECK("(f) resume repair raises H* to proven coins frontier",
                 hstar_after == 1239);
        LV_CHECK("(f) resume repair rewinds high header cursor to boundary",
                 pdb && lv_stage_cursor(pdb, "validate_headers") == 1240);
        LV_CHECK("(f) resume repair stamps tip_finalize to served boundary",
                 pdb && lv_stage_cursor(pdb, "tip_finalize") == 1239);
        LV_CHECK("(f) resume repair preserves applied frontier",
                 pdb && coins_kv_get_applied_height(pdb, &applied, &found) &&
                 found && applied == 1240);

        main_state_free(&ms);
        free(owned_blocks);
    }

    /* (g) A canonical USS v2 artifact must carry its header-bound Sapling
     * frontier through the real production installer, durable receipt reopen,
     * and RESUME-FAST.  This is the proof that the typed recovery report's
     * embedded_frontier_verified=true bit describes installed authority, not
     * merely a parsable trailer. */
    {
        progress_store_close();
        char v2_dir[256];
        test_make_tmpdir(v2_dir, sizeof(v2_dir), "load_verify_boot", "v2");
        char v2_path[320], v2_dbpath[320], v2_blocks[320];
        snprintf(v2_path, sizeof(v2_path), "%s/sapling-v2.snapshot", v2_dir);
        snprintf(v2_dbpath, sizeof(v2_dbpath), "%s/node.db", v2_dir);
        snprintf(v2_blocks, sizeof(v2_blocks), "%s/blocks", v2_dir);

        struct incremental_merkle_tree v2_tree;
        sapling_tree_init(&v2_tree);
        for (uint8_t i = 1; i <= 3; i++) {
            struct uint256 leaf;
            uint256_set_null(&leaf);
            leaf.data[0] = (uint8_t)(0x90u + i);
            leaf.data[31] = i;
            incremental_tree_append(&v2_tree, &leaf);
        }
        struct uint256 v2_root;
        incremental_tree_root(&v2_tree, &v2_root);
        struct byte_stream v2_serialized;
        stream_init(&v2_serialized, 4096);
        LV_CHECK("(g) nonempty Sapling frontier serializes",
                 incremental_tree_serialize(&v2_tree, &v2_serialized) &&
                     !v2_serialized.error && v2_serialized.size > 0);

        uint8_t v2_anchor_hash[32] = {0};
        lv_hash_for_height(30, v2_anchor_hash);
        struct snapshot_shielded v2_shielded = {
            .sapling = v2_serialized.data,
            .sapling_len = (uint32_t)v2_serialized.size,
        };
        sqlite3 *v2_source = NULL;
        uint8_t v2_payload_sha3[32] = {0};
        uint64_t v2_count = 0;
        int64_t v2_supply = 0;
        bool v2_written =
            sqlite3_open(":memory:", &v2_source) == SQLITE_OK &&
            lv_seed_snapshot_coins(v2_source) &&
            coins_kv_snapshot_write(v2_source, v2_path, 30, v2_anchor_hash,
                                    &v2_shielded, v2_payload_sha3, &v2_count,
                                    &v2_supply);
        LV_CHECK("(g) canonical writer emits two-coin USS v2", v2_written &&
                 v2_count == 2 && v2_supply == 3300);
        if (v2_source)
            sqlite3_close(v2_source);

        struct uss_header v2_header;
        uint8_t v2_artifact_sha256[32] = {0};
        const uint8_t *v2_frontier = NULL;
        uint32_t v2_frontier_len = 0;
        char v2_err[160] = {0};
        struct uss_handle *v2_handle =
            uss_open(v2_path, true, NULL, &v2_header, v2_err, sizeof(v2_err));
        bool v2_parsed = v2_handle && uss_version(v2_handle) == 2 &&
            uss_frontier(v2_handle, &v2_frontier, &v2_frontier_len) &&
            v2_frontier_len == v2_serialized.size &&
            memcmp(v2_frontier, v2_serialized.data, v2_frontier_len) == 0 &&
            uss_artifact_sha256(v2_handle, v2_artifact_sha256);
        LV_CHECK("(g) production parser verifies exact v2 frontier bytes",
                 v2_parsed);
        if (v2_handle)
            uss_close(v2_handle);

        struct node_db v2_ndb;
        struct main_state v2_ms;
        main_state_init(&v2_ms);
        struct block_index *v2_blocks_owned = NULL;
        bool v2_context = node_db_open(&v2_ndb, v2_dbpath) &&
            progress_store_open(v2_dir) &&
            lv_seed_active_chain(&v2_ms, &v2_ndb, 30, 30, &v2_root,
                                 &v2_blocks_owned);
        LV_CHECK("(g) real active chain binds v2 anchor and Sapling root",
                 v2_context &&
                     memcmp(v2_header.anchor_block_hash,
                            v2_blocks_owned[30].hashBlock.data, 32) == 0 &&
                     memcmp(v2_blocks_owned[30].hashFinalSaplingRoot.data,
                            v2_root.data, 32) == 0);
        LV_CHECK("(g) v2 install fixture has no blocks directory",
                 access(v2_blocks, F_OK) != 0);

        chain_restore_boot_snapshot_reset_for_testing();
        if (v2_context)
            boot_load_snapshot_at_own_height_reset(
                &v2_ndb, v2_path, v2_dir, &v2_ms, true);
        sqlite3 *v2_pdb = progress_store_db();
        struct chain_restore_boot_snapshot v2_proof;
        chain_restore_get_boot_snapshot(&v2_proof);
        char v2_payload_hex[65] = {0};
        char v2_anchor_hex[65] = {0};
        char v2_artifact_hex[65] = {0};
        HexStr(v2_payload_sha3, 32, false, v2_payload_hex,
               sizeof(v2_payload_hex));
        HexStr(v2_anchor_hash, 32, false, v2_anchor_hex,
               sizeof(v2_anchor_hex));
        HexStr(v2_artifact_sha256, 32, false, v2_artifact_hex,
               sizeof(v2_artifact_hex));
        LV_CHECK("(g) fresh production install publishes exact verified v2 proof",
                 v2_proof.assisted_snapshot_body_sha3_verified &&
                 v2_proof.assisted_snapshot_embedded_frontier_verified &&
                 v2_proof.assisted_snapshot_reseed_committed &&
                 v2_proof.assisted_snapshot_seed_height == 30 &&
                 v2_proof.assisted_snapshot_record_count == v2_count &&
                 strcmp(v2_proof.assisted_snapshot_payload_sha3,
                        v2_payload_hex) == 0 &&
                 strcmp(v2_proof.assisted_snapshot_anchor_block_hash,
                        v2_anchor_hex) == 0 &&
                 strcmp(v2_proof.assisted_snapshot_artifact_sha256,
                        v2_artifact_hex) == 0 &&
                 strcmp(v2_proof.assisted_snapshot_path, v2_path) == 0);

        struct incremental_merkle_tree v2_anchor_tree;
        struct uint256 v2_anchor_root;
        int64_t v2_anchor_height = -1;
        sapling_tree_init(&v2_anchor_tree);
        LV_CHECK("(g) root-verified v2 frontier is durable anchor authority",
                 v2_pdb && anchor_kv_latest_tree(
                     v2_pdb, ANCHOR_POOL_SAPLING, &v2_anchor_tree,
                     &v2_anchor_root, &v2_anchor_height) == ANCHOR_KV_FOUND &&
                 v2_anchor_height == 30 &&
                 memcmp(v2_anchor_root.data, v2_root.data, 32) == 0);

        uint8_t v2_tree_blob[4096] = {0};
        size_t v2_tree_len = 0;
        int64_t v2_rebuild_height = -1;
        struct incremental_merkle_tree v2_persisted_tree;
        struct uint256 v2_persisted_root;
        sapling_tree_init(&v2_persisted_tree);
        struct byte_stream v2_tree_stream;
        bool v2_tree_pair = node_db_state_get(
                &v2_ndb, "sapling_tree", v2_tree_blob,
                sizeof(v2_tree_blob), &v2_tree_len) &&
            node_db_state_get_int(&v2_ndb, "sapling_tree_rebuild_height",
                                  &v2_rebuild_height);
        stream_init_from_data(&v2_tree_stream, v2_tree_blob, v2_tree_len);
        v2_tree_pair = v2_tree_pair &&
            incremental_tree_deserialize(&v2_persisted_tree,
                                         &v2_tree_stream);
        incremental_tree_root(&v2_persisted_tree, &v2_persisted_root);
        LV_CHECK("(g) node-state frontier pair matches header root",
                 v2_tree_pair && v2_rebuild_height == 30 &&
                 memcmp(v2_persisted_root.data, v2_root.data, 32) == 0);
        stream_free(&v2_tree_stream);

        progress_store_close();
        node_db_close(&v2_ndb);
        bool v2_reopened = node_db_open(&v2_ndb, v2_dbpath) &&
                           progress_store_open(v2_dir);
        v2_pdb = progress_store_db();
        int32_t v2_applied = -1;
        bool v2_pending = true, v2_matches = false;
        bool v2_frontier_verified = false;
        LV_CHECK("(g) reopened receipt preserves verified-frontier authority",
                 v2_reopened && boot_snapshot_install_resume_allowed(
                     v2_pdb, &v2_header, v2_artifact_sha256, &v2_applied,
                     &v2_pending, &v2_matches, &v2_frontier_verified) &&
                 v2_applied == 31 && !v2_pending && v2_matches &&
                 v2_frontier_verified);
        LV_CHECK("(g) reopened resume fixture has reducer log schemas",
                 v2_pdb && lv_ensure_reducer_log_tables(v2_pdb));
        uint8_t v2_poison[32] = {0xe4};
        LV_CHECK("(g) forward-state witness seeds after v2 install",
                 v2_pdb && coins_kv_add(
                     v2_pdb, v2_poison, 0, 77, 31, false,
                     (const uint8_t *)"\x51", 1));
        chain_restore_boot_snapshot_reset_for_testing();
        if (v2_reopened)
            boot_load_snapshot_at_own_height_reset(
                &v2_ndb, v2_path, v2_dir, &v2_ms, true);
        chain_restore_get_boot_snapshot(&v2_proof);
        LV_CHECK("(g) RESUME-FAST preserves forward state and republishes true",
                 coins_kv_exists(v2_pdb, v2_poison, 0) &&
                 v2_proof.assisted_snapshot_body_sha3_verified &&
                 v2_proof.assisted_snapshot_embedded_frontier_verified &&
                 v2_proof.assisted_snapshot_reseed_committed &&
                 strcmp(v2_proof.assisted_snapshot_artifact_sha256,
                        v2_artifact_hex) == 0 &&
                 strcmp(v2_proof.assisted_snapshot_path, v2_path) == 0);

        progress_store_close();
        node_db_close(&v2_ndb);
        main_state_free(&v2_ms);
        free(v2_blocks_owned);
        stream_free(&v2_serialized);
    }

    /* Teardown. */
    checkpoints_set_sha3_override_for_test(NULL);
    unsetenv("ZCL_MINT_ANCHOR_OUT");
    progress_store_close();
    node_db_close(&ndb);
    unlink(snap_path);
    return failures;
}
