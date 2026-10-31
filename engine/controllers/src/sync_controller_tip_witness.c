/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Wallet note witness maintenance at the chain tip, independent of the
 * catchup walk.
 *
 * The tree before the block comes from the reducer's anchor frontier and is
 * accepted only when its root equals the header root at that height. Notes
 * whose witness is behind the parent (a missed block, a rewind, a note found
 * late) are replayed from the stored witness height through the parent, at
 * most TIP_WITNESS_REPLAY_MAX blocks per call. A note further behind advances
 * by that many blocks on each call and reaches the tip after a few calls, so
 * no note stays behind for good. */

#include "controllers/sync_controller.h"
#include "sync_controller_internal.h"
#include "config/db_service.h"
#include "core/serialize.h"
#include "core/utiltime.h"
#include "models/db_txn.h"
#include "models/wallet_tx.h"
#include "primitives/block.h"
#include "sapling/incremental_merkle_tree.h"
#include "storage/anchor_kv.h"
#include "storage/disk_block_io.h"
#include "storage/progress_store.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"
#include "util/util.h"
#include <sqlite3.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

enum { TIP_WITNESS_REPLAY_MAX = 256 };

#ifdef ZCL_TESTING
static _Atomic int g_tip_witness_job_runs;

int node_db_sync_tip_witness_test_job_runs(void)
{
    return atomic_load(&g_tip_witness_job_runs);
}
#endif

/* The reducer frontier at bi's height, accepted only when its root equals the
 * header root recorded for bi. Logged on refusal. */
static bool tip_witness_tree_at(const struct block_index *bi,
                                struct incremental_merkle_tree *tree)
{
    sqlite3 *rdb = progress_store_open_reader();
    if (!rdb)
        LOG_FAIL("sync", "tip witnesses: reducer store unavailable");
    int64_t ah = -1;
    enum anchor_kv_lookup_result lr = anchor_kv_tree_at_or_below(
        rdb, ANCHOR_POOL_SAPLING, (int64_t)bi->nHeight, tree, NULL, &ah);
    sqlite3_close(rdb);
    struct uint256 root = {0};
    if (lr == ANCHOR_KV_FOUND)
        incremental_tree_root(tree, &root);
    if (lr != ANCHOR_KV_FOUND || !uint256_eq(&root, &bi->hashFinalSaplingRoot))
        LOG_FAIL("sync", "tip witnesses: no reducer frontier equal to the "
                 "header root at h=%d (found h=%lld)", bi->nHeight,
                 (long long)ah);
    return true;
}

/* Lowest block that must be replayed for some note to reach the parent of
 * height h, or h when none must. */
static int tip_witness_replay_start(struct node_db *ndb, int h)
{
    struct db_sapling_note *notes = NULL;
    int nw = db_sapling_note_list_unspent_alloc(ndb, &notes);
    int start = h;
    for (int i = 0; i < nw; i++) {
        uint8_t *blob = NULL;
        size_t len = 0;
        int wh = 0;
        bool have = db_sapling_note_load_witness(
                        ndb, notes[i].txid, notes[i].output_index, &blob, &len,
                        &wh) && blob;
        free(blob);
        int need = have ? wh + 1 : notes[i].block_height;
        if (have ? wh >= h - 1 : notes[i].block_height >= h)
            continue;
        if (need >= 0 && need < start)
            start = need;
    }
    free(notes);
    return nw < 0 ? h : start;
}

static bool tip_witness_apply_block(struct node_db *ndb, struct wallet *wallet,
                                    const struct block *blk,
                                    const struct block_index *bi,
                                    struct incremental_merkle_tree *tree)
{
    bool own_tx = sqlite3_get_autocommit(ndb->db) != 0;
    if (own_tx && !node_db_begin_immediate(ndb))
        LOG_FAIL("sync", "tip witnesses: BEGIN failed");
    bool ok = sync_advance_witnesses_core(ndb, blk, tree, bi->nHeight, wallet,
                                          false);
    struct uint256 root = {0};
    incremental_tree_root(tree, &root);
    if (ok && !uint256_eq(&root, &bi->hashFinalSaplingRoot)) {
        LOG_ERROR("sync", "tip witnesses: replayed tree differs from the "
                  "header root at h=%d", bi->nHeight);
        ok = false;
    }
    if (own_tx)
        ok = ok ? node_db_commit(ndb) : (node_db_rollback(ndb), false);
    return ok;
}

/* Replay count blocks starting at height start, one block per transaction,
 * from the reducer frontier at start - 1. On success tree is the frontier at
 * start + count - 1; pindex is the tip block, count blocks end at or before its
 * parent. The generic advance (sync_deserialize_note_witnesses) refuses any
 * witness not saved at the parent height, so a witness behind the parent is
 * brought to the parent here, block by block, before that advance accepts it. */
static bool tip_witness_replay(struct node_db *ndb, struct wallet *wallet,
                               const struct block_index *pindex, int start,
                               int count, const struct sync_block_reader *rd,
                               struct incremental_merkle_tree *tree)
{
    const struct block_index **path =
        zcl_calloc((size_t)count, sizeof(*path), "tip witness replay path");
    if (!path)
        return false;
    const struct block_index *bi = pindex;
    for (int skip = pindex->nHeight - (start + count); skip > 0 && bi; skip--)
        bi = bi->pprev;
    bi = bi ? bi->pprev : NULL;
    for (int i = count - 1; i >= 0 && bi; i--, bi = bi->pprev)
        path[i] = bi;
    bool ok = bi && bi->nHeight == start - 1 && tip_witness_tree_at(bi, tree);
    for (int i = 0; ok && i < count; i++) {
        struct block blk;
        block_init(&blk);
        if (!rd->read(rd->ctx, path[i], &blk)) {
            LOG_ERROR("sync", "tip witnesses: block body unreadable at h=%d",
                      path[i]->nHeight);
            ok = false;
        } else {
            ok = tip_witness_apply_block(ndb, wallet, &blk, path[i], tree);
        }
        block_free(&blk);
    }
    free(path);
    return ok;
}

/* A witness stored at the tip must hash to the tip's header root. One that
 * does not belongs to blocks no longer on the chain: drop it. */
static bool tip_witness_verify(struct node_db *ndb,
                               const struct block_index *pindex,
                               const struct incremental_merkle_tree *tree)
{
    struct db_sapling_note *notes = NULL;
    int nw = db_sapling_note_list_unspent_alloc(ndb, &notes);
    bool ok = nw >= 0;
    for (int i = 0; i < nw; i++) {
        uint8_t *blob = NULL;
        size_t len = 0;
        int wh = 0;
        if (!db_sapling_note_load_witness(ndb, notes[i].txid,
                notes[i].output_index, &blob, &len, &wh) || !blob ||
            wh != pindex->nHeight) {
            free(blob);
            continue;
        }
        struct byte_stream s;
        struct incremental_witness w;
        struct uint256 root = {0};
        stream_init_from_data(&s, blob, len);
        bool good = incremental_witness_deserialize(
            &w, &s, SAPLING_INCREMENTAL_MERKLE_TREE_DEPTH, tree->combine,
            tree->uncommitted);
        if (good)
            incremental_witness_root(&w, &root);
        free(blob);
        if (good && uint256_eq(&root, &pindex->hashFinalSaplingRoot))
            continue;
        LOG_WARN("sync", "tip witnesses: dropping a witness that does not "
                 "match the header root at h=%d", pindex->nHeight);
        ok = db_sapling_note_clear_witness(ndb, notes[i].txid,
                                           notes[i].output_index) && ok;
    }
    free(notes);
    return ok;
}

static bool tip_witness_apply_tip(struct node_db *ndb, struct wallet *wallet,
                                  const struct block *blk,
                                  const struct block_index *pindex,
                                  struct incremental_merkle_tree *tree)
{
    bool own_tx = sqlite3_get_autocommit(ndb->db) != 0;
    if (own_tx && !node_db_begin_immediate(ndb))
        LOG_FAIL("sync", "tip witnesses: BEGIN failed");
    bool ok = sync_advance_witnesses_core(ndb, blk, tree, pindex->nHeight,
                                          wallet, false) &&
              tip_witness_verify(ndb, pindex, tree);
    if (own_tx)
        ok = ok ? node_db_commit(ndb) : (node_db_rollback(ndb), false);
    return ok;
}

static bool tip_witness_disk_read(void *ctx, const struct block_index *bi,
                                  struct block *out)
{
    return read_block_from_disk_index_pread(out, bi, ctx);
}

enum tip_witness_prep { TIP_PREP_FAILED, TIP_PREP_PARTIAL, TIP_PREP_READY };

/* Bring the notes behind the parent forward by at most one replay window and
 * leave tree at the frontier before the tip block. PARTIAL: the window ended
 * below the parent, so the tip block waits for a later call. */
static enum tip_witness_prep tip_witness_prepare(
    struct node_db *ndb, struct wallet *wallet,
    const struct block_index *pindex, const struct sync_block_reader *rd,
    struct incremental_merkle_tree *tree)
{
    int h = pindex->nHeight;
    int start = tip_witness_replay_start(ndb, h);
    int count = h - start < TIP_WITNESS_REPLAY_MAX ? h - start
                                                   : TIP_WITNESS_REPLAY_MAX;
    bool replayed = count > 0 &&
        tip_witness_replay(ndb, wallet, pindex, start, count, rd, tree);
    if (replayed && start + count < h)
        return TIP_PREP_PARTIAL;
    if (replayed)
        return TIP_PREP_READY;
    return tip_witness_tree_at(pindex->pprev, tree) ? TIP_PREP_READY
                                                    : TIP_PREP_FAILED;
}

bool node_db_sync_advance_tip_witnesses_with(
    struct node_db *ndb, const struct block *blk,
    const struct block_index *pindex, struct wallet *wallet,
    const struct sync_block_reader *rd)
{
    if (!ndb || !ndb->open || !blk || !pindex || !pindex->pprev || !rd)
        LOG_FAIL("sync", "tip witnesses: invalid args");
    int h = pindex->nHeight;
    if (db_sapling_note_count_unspent(ndb) <= 0)
        return true; // raw-return-ok:no wallet notes, nothing to maintain
    int64_t t0 = GetTimeMicros();
    struct incremental_merkle_tree tree;
    enum tip_witness_prep prep =
        tip_witness_prepare(ndb, wallet, pindex, rd, &tree);
    if (prep == TIP_PREP_PARTIAL)
        return true; // raw-return-ok:partial replay; the next call continues
    if (prep == TIP_PREP_FAILED)
        return false; // raw-return-ok:logged by tip_witness_tree_at
    bool ok = tip_witness_apply_tip(ndb, wallet, blk, pindex, &tree);
    int64_t us = GetTimeMicros() - t0;
    if (!ok || us > 50000)
        LOG_INFO("sync", "tip witnesses h=%d ok=%d us=%lld", h, ok ? 1 : 0,
                 (long long)us);
    return ok;
}

bool node_db_sync_advance_tip_witnesses(struct node_db *ndb,
                                        const struct block *blk,
                                        const struct block_index *pindex,
                                        struct wallet *wallet)
{
    char datadir[2048];
    GetDataDir(true, datadir, sizeof(datadir));
    struct sync_block_reader rd = { tip_witness_disk_read, datadir };
    return node_db_sync_advance_tip_witnesses_with(ndb, blk, pindex, wallet,
                                                   &rd);
}

struct tip_witness_job {
    struct block blk;
    struct block_index pindex;
    struct uint256 hash;
    struct wallet *wallet;
};

static bool tip_witness_job_write(struct node_db *ndb, void *opaque)
{
    struct tip_witness_job *job = opaque;
#ifdef ZCL_TESTING
    atomic_fetch_add(&g_tip_witness_job_runs, 1);
#endif
    if (!node_db_sync_advance_tip_witnesses(ndb, &job->blk, &job->pindex,
                                            job->wallet))
        LOG_FAIL("sync", "tip witnesses: advance failed at h=%d; the "
                 "witnesses stay behind", job->pindex.nHeight);
    return true;
}

static void tip_witness_job_free(void *opaque)
{
    struct tip_witness_job *job = opaque;
    if (!job)
        return;
    block_free(&job->blk);
    free(job);
}

bool node_db_sync_advance_tip_witnesses_async(struct node_db *ndb,
                                              const struct block *blk,
                                              const struct block_index *pindex,
                                              struct wallet *wallet)
{
    if (!ndb || !ndb->open || !blk || !pindex || !pindex->pprev ||
        !pindex->phashBlock)
        LOG_FAIL("sync", "tip witnesses async: invalid args");
    struct db_service *svc = sync_db_service_for(ndb);
    if (!svc) // raw-return-ok:no db service (boot fixtures); the witnesses are rebuilt by the next call
        return true;
    struct tip_witness_job *job =
        zcl_calloc(1, sizeof(*job), "tip witness job");
    if (!job)
        return false;
    if (!node_db_sync_copy_block(&job->blk, blk)) {
        free(job);
        return false;
    }
    job->pindex = *pindex;
    job->hash = *pindex->phashBlock;
    job->pindex.phashBlock = &job->hash;
    job->wallet = wallet;
    return db_service_enqueue_write_bulk_safe(
        svc, tip_witness_job_write, job, tip_witness_job_free);
}
