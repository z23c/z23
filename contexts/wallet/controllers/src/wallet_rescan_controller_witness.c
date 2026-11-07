/* Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 *
 * rescanwitnesses RPC: rebuild Sapling Merkle witnesses for unspent notes. */

#include "controllers/wallet_rescan_controller_internal.h"
#include "services/wallet_scan_service.h"
#include "config/db_service.h"
#include "config/runtime.h"

struct wallet_rescan_block_mapping {
    int file_num;
    int fd;
    struct platform_read_mapping view;
};

static void wallet_rescan_block_mapping_init(
    struct wallet_rescan_block_mapping *mapping)
{
    mapping->file_num = -1;
    mapping->fd = -1;
    platform_read_mapping_init(&mapping->view);
}

static void wallet_rescan_block_mapping_close(
    struct wallet_rescan_block_mapping *mapping)
{
    platform_read_mapping_close(&mapping->view);
    if (mapping->fd >= 0)
        close(mapping->fd);
    wallet_rescan_block_mapping_init(mapping);
}

static bool wallet_rescan_block_mapping_open(
    struct wallet_rescan_block_mapping *mapping, const char *datadir,
    int file_num)
{
    wallet_rescan_block_mapping_close(mapping);

    char path[4096];
    int path_len = snprintf(path, sizeof(path), "%s/blocks/blk%05d.dat",
                            datadir, file_num);
    if (path_len < 0 || (size_t)path_len >= sizeof(path))
        return false;

    int fd = wallet_scan_block_file_map(path, &mapping->view);
    if (fd < 0)
        return false;

    mapping->fd = fd;
    mapping->file_num = file_num;
    platform_read_mapping_advise_sequential(&mapping->view);
    return true;
}

#include "storage/anchor_kv.h"
#include "storage/progress_store.h"

#include <limits.h>
#include "platform/time_compat.h"
#include <sqlite3.h>

static bool uint256_is_zero_local(const struct uint256 *v)
{
    static const uint8_t zero[32] = {0};
    return !v || memcmp(v->data, zero, sizeof(v->data)) == 0;
}

bool rescan_result_consensus_valid(const struct uint256 *our_root,
                                   const struct uint256 *header_root,
                                   int witness_mismatches)
{
    if (!our_root || !header_root)
        return false;
    if (witness_mismatches != 0)
        return false;
    if (uint256_is_zero_local(header_root))
        return false;
    return memcmp(our_root->data, header_root->data,
                  sizeof(our_root->data)) == 0;
}

bool rescan_endpoint_header_addressable(const struct block_index *index)
{
    return index && index->phashBlock && index->nFile >= 0 &&
           !uint256_is_zero_local(&index->hashFinalSaplingRoot);
}

const struct block_index *rescan_find_replay_endpoint(
    const struct active_chain *chain, int replay_start,
    int *endpoint_height_out)
{
    if (endpoint_height_out)
        *endpoint_height_out = -1;
    if (!chain || replay_start < 0)
        return NULL;

    /* A newly received note normally sits inside the finality window. Clamping
     * witness replay to tip-finality_depth therefore makes that note
     * impossible to recover. Start at the newest materialized active block
     * instead and walk back only over incomplete projection slots. A published
     * (nFile,nDataPos) names an already-written block body; the caller snapshots
     * this endpoint's exact hash/root and rechecks both before any save, so a
     * concurrent tip advance or reorg still fails closed. */
    for (int height = active_chain_height(chain);
         height >= replay_start; height--) {
        const struct block_index *index = active_chain_at(chain, height);
        if (!rescan_endpoint_header_addressable(index))
            continue;
        if (endpoint_height_out)
            *endpoint_height_out = height;
        return index;
    }
    return NULL;
}

size_t rescan_append_block_commitments(
    const struct block *block, struct incremental_merkle_tree *tree,
    struct incremental_witness *witnesses, bool *witness_active,
    const struct db_sapling_note *notes, int n_notes,
    int *witnesses_built)
{
    if (!block || !tree || !witnesses || !witness_active || !notes ||
        n_notes < 0 || !witnesses_built)
        return 0;

    size_t appended = 0;
    for (size_t ti = 0; ti < block->num_vtx; ti++) {
        const struct transaction *tx = &block->vtx[ti];
        for (size_t oi = 0; oi < tx->num_shielded_output; oi++) {
            const struct uint256 *cm = &tx->v_shielded_output[oi].cm;
            for (int ni = 0; ni < n_notes; ni++) {
                if (witness_active[ni])
                    incremental_witness_append(&witnesses[ni], cm);
            }
            incremental_tree_append(tree, cm);
            appended++;

            for (int ni = 0; ni < n_notes; ni++) {
                if (witness_active[ni])
                    continue;
                if (memcmp(cm->data, notes[ni].cm, sizeof(cm->data)) == 0) {
                    incremental_witness_init(&witnesses[ni], tree);
                    witness_active[ni] = true;
                    (*witnesses_built)++;
                }
            }
        }
    }
    return appended;
}

static int rescan_oldest_note_height(const struct db_sapling_note *notes,
                                     int n_notes,
                                     int sapling_activation_height)
{
    int oldest_height = INT_MAX;
    for (int i = 0; i < n_notes; i++) {
        if (notes[i].block_height >= sapling_activation_height &&
            notes[i].block_height < oldest_height)
            oldest_height = notes[i].block_height;
    }
    return oldest_height;
}

/* Seed a witness rebuild from the header-bound Sapling frontier immediately
 * before the oldest unspent note, when that frontier is present in the
 * canonical anchor ledger.  Snapshot/bundle nodes intentionally do not have
 * every pre-seed block body, so replaying from activation can never reproduce
 * their header root.  They do have the imported anchor frontiers, and a note
 * received after the seed needs only the frontier before its own block plus
 * the locally-present suffix.
 *
 * anchor_kv_get() verifies that the serialized tree hashes back to the prior
 * block's header root before returning it.  The root may have been created at
 * an earlier height (blocks without Sapling outputs repeat it), but it is still
 * exactly the frontier at oldest_height-1; start replay at oldest_height so no
 * absent, commitment-free gap needs a body. */
bool rescan_seed_before_oldest_note_from_db(
    sqlite3 *anchor_db, const struct active_chain *chain,
    const struct db_sapling_note *notes, int n_notes,
    int sapling_activation_height,
    struct incremental_merkle_tree *tree_out, int *start_height_out,
    int *seed_height_out)
{
    if (!anchor_db || !chain || !notes || n_notes <= 0 || !tree_out ||
        sapling_activation_height < 0 || !start_height_out ||
        !seed_height_out)
        return false;

    int oldest_height = rescan_oldest_note_height(notes, n_notes,
                                                  sapling_activation_height);
    if (oldest_height == INT_MAX ||
        oldest_height <= sapling_activation_height)
        return false;

    const struct block_index *prior = active_chain_at(chain,
                                                       oldest_height - 1);
    if (!prior || uint256_is_zero_local(&prior->hashFinalSaplingRoot))
        return false;

    struct incremental_merkle_tree seed;
    sapling_tree_init(&seed);
    int64_t created_height = -1;
    enum anchor_kv_lookup_result found = anchor_kv_get(
        anchor_db, ANCHOR_POOL_SAPLING, &prior->hashFinalSaplingRoot, &seed,
        &created_height);
    if (found != ANCHOR_KV_FOUND || created_height > oldest_height - 1)
        return false;

    *tree_out = seed;
    *start_height_out = oldest_height;
    *seed_height_out = oldest_height - 1;
    return true;
}

static bool rescan_seed_before_oldest_note(
    const struct active_chain *chain, const struct db_sapling_note *notes,
    int n_notes, int sapling_activation_height,
    struct incremental_merkle_tree *tree_out,
    int *start_height_out, int *seed_height_out)
{
    sqlite3 *rdb = progress_store_open_reader();
    if (!rdb)
        return false;
    bool ok = rescan_seed_before_oldest_note_from_db(
        rdb, chain, notes, n_notes, sapling_activation_height,
        tree_out, start_height_out,
        seed_height_out);
    sqlite3_close(rdb);
    return ok;
}

static bool rescan_block_body_mapped(const struct block_index *pindex,
                                     struct wallet_rescan_block_mapping *block_mapping,
                                     const char *block_datadir)
{
    /* File coordinates, not the lag-prone HAVE_DATA projection, decide
     * whether this recovery pass can attempt the immutable body. Any
     * absent/truncated body leaves the reconstructed root short and the
     * consensus comparison below refuses every save. */
    if (!pindex->phashBlock || pindex->nFile < 0)
        return false;

    if (pindex->nFile != block_mapping->file_num &&
        !wallet_rescan_block_mapping_open(block_mapping, block_datadir,
                                          pindex->nFile))
        return false;
    if (!block_mapping->view.data ||
        (uintmax_t)pindex->nDataPos >=
            (uintmax_t)block_mapping->view.size)
        return false;
    return true;
}

static void rescan_print_checkpoint(const struct incremental_merkle_tree *tree,
                                    const struct block_index *pindex,
                                    int blocks_scanned, int h,
                                    size_t total_commitments,
                                    int witnesses_built, int n_notes,
                                    int64_t t_start)
{
    int64_t elapsed = (int64_t)platform_time_wall_time_t() - t_start;
    printf("rescanwitnesses: %d blocks (height %d), "
           "%zu cms, %d/%d witnesses, %llds",
           blocks_scanned, h, total_commitments,
           witnesses_built, n_notes, (long long)elapsed);

    struct uint256 our_root;
    incremental_tree_root(tree, &our_root);
    if (memcmp(our_root.data,
               pindex->hashFinalSaplingRoot.data, 32) == 0) {
        printf(" [tree OK]\n");
    } else {
        char oh[65], bh[65];
        uint256_get_hex(&our_root, oh);
        uint256_get_hex(&pindex->hashFinalSaplingRoot, bh);
        printf(" [TREE DIVERGED!]\n"
               "  our root:   %s (size=%zu)\n"
               "  block root: %s\n",
               oh, incremental_tree_size(tree), bh);
    }
    fflush(stdout);
}

static void rescan_check_final_root(
    const struct wallet_rpc_context *ctx,
    const struct incremental_merkle_tree *tree,
    const struct uint256 *final_tree_root, int safe_tip,
    const struct uint256 *endpoint_hash, const struct uint256 *endpoint_root,
    struct uint256 *final_header_root)
{
    const struct block_index *current_save_block =
        active_chain_at(&ctx->main_state->chain_active, safe_tip);
    if (current_save_block && current_save_block->phashBlock &&
        uint256_eq(current_save_block->phashBlock, endpoint_hash) &&
        uint256_eq(&current_save_block->hashFinalSaplingRoot,
                   endpoint_root)) {
        *final_header_root = *endpoint_root;
        char oh[65], bh[65];
        uint256_get_hex(final_tree_root, oh);
        uint256_get_hex(final_header_root, bh);
        if (memcmp(final_tree_root->data, final_header_root->data, 32) == 0) {
            printf("rescanwitnesses: FINAL tree root matches block header at height %d ✓\n", safe_tip);
        } else {
            printf("rescanwitnesses: FINAL tree root DOES NOT match block header at height %d!\n"
                   "  our root:   %s (size=%zu)\n"
                   "  block root: %s\n",
                   safe_tip, oh, incremental_tree_size(tree), bh);
        }
        fflush(stdout);
    } else {
        printf("rescanwitnesses: FINAL tree root cannot be checked at height %d (missing active-chain block)\n",
               safe_tip);
        fflush(stdout);
    }
}

static int rescan_check_witness_roots(
    const struct incremental_merkle_tree *tree,
    const struct incremental_witness *witnesses, const bool *witness_active,
    int n_notes, const struct uint256 *final_tree_root)
{
    int witness_root_mismatches = 0;
    {
        char tr_hex[65]; uint256_get_hex(final_tree_root, tr_hex);
        for (int ni = 0; ni < n_notes; ni++) {
            if (!witness_active[ni]) continue;
            struct uint256 wr;
            incremental_witness_root(&witnesses[ni], &wr);
            char wr_hex[65]; uint256_get_hex(&wr, wr_hex);
            if (memcmp(wr.data, final_tree_root->data, 32) != 0) {
                witness_root_mismatches++;
                printf("rescanwitnesses: WITNESS ROOT MISMATCH for note %d!\n" // wallet-log-ok:note-index-label
                    "  tree root:    %s (size=%zu)\n"
                    "  witness root: %s (fills=%zu)\n",
                    ni, tr_hex, incremental_tree_size(tree),
                    wr_hex, witnesses[ni].num_filled);
            } else {
                printf("rescanwitnesses: note %d witness root MATCHES tree ✓\n", ni); // wallet-log-ok:note-index-label
            }
        }
        fflush(stdout);
    }
    return witness_root_mismatches;
}

static bool rescan_save_tree_state(const struct wallet_rpc_context *ctx,
                                   const struct incremental_merkle_tree *tree,
                                   int safe_tip)
{
    struct byte_stream ts;
    stream_init(&ts, 4096);
    bool ok = incremental_tree_serialize(tree, &ts) &&
        sapling_tree_persist_pair_in_open_tx(ctx->node_db, ts.data, ts.size,
                                             (int64_t)safe_tip) &&
        node_db_state_set(ctx->node_db, "sapling_tree_rescan", ts.data, ts.size);
    stream_free(&ts);
    char height_str[16];
    int n = snprintf(height_str, sizeof(height_str), "%d", safe_tip);
    return ok && n > 0 && (size_t)n < sizeof(height_str) &&
        node_db_state_set(ctx->node_db, "sapling_tree_height",
                          (const uint8_t *)height_str, (size_t)n) &&
        node_db_state_set(ctx->node_db, "sapling_tree_rescan_height",
                          (const uint8_t *)height_str, (size_t)n);
}

static bool rescan_copy_viewing_key(struct sapling_keystore *keys,
                                    const uint8_t ivk[32], uint8_t ak[32], uint8_t nk[32])
{
    bool found = false;
    if (!zcl_mutex_trylock(&keys->cs)) return false;
    for (size_t i = 0; i < keys->num_keys; i++) {
        const struct sapling_key_entry *key = &keys->keys[i];
        if (key->used && memcmp(key->ivk, ivk, 32) == 0) {
            memcpy(ak, key->xfvk.fvk.ak, 32);
            memcpy(nk, key->xfvk.fvk.nk, 32);
            found = true;
            break;
        }
    }
    zcl_mutex_unlock(&keys->cs);
    return found;
}

static int rescan_save_witnesses(const struct wallet_rpc_context *ctx,
                                 const struct incremental_witness *witnesses,
                                 const bool *witness_active,
                                 const struct db_sapling_note *notes,
                                 int n_notes, int safe_tip)
{
    int saved = 0;
    for (int ni = 0; ni < n_notes; ni++) {
        if (!witness_active[ni]) continue;

        if (incremental_tree_size(&witnesses[ni].tree) == 0)
            continue;
        uint8_t ak[32], nk[32], nf[32];
        if (!rescan_copy_viewing_key(&ctx->wallet->sapling_keys, notes[ni].ivk, ak, nk))
            continue;
        uint64_t position = incremental_tree_size(&witnesses[ni].tree) - 1;
        if (!sapling_compute_nf(notes[ni].diversifier, notes[ni].pk_d,
                                (uint64_t)notes[ni].value, notes[ni].rcm,
                                ak, nk, position, nf)) {
            memory_cleanse(ak, sizeof(ak));
            memory_cleanse(nk, sizeof(nk));
            continue;
        }
        memory_cleanse(ak, sizeof(ak));
        memory_cleanse(nk, sizeof(nk));

        struct byte_stream ws;
        stream_init(&ws, 4096);
        if (incremental_witness_serialize(&witnesses[ni], &ws)) {
            if (db_sapling_note_save_witness_and_nullifier(
                    ctx->node_db, notes[ni].txid, notes[ni].output_index,
                    ws.data, ws.size, safe_tip, nf))
                saved++;
        }
        memory_cleanse(nf, sizeof(nf));
        stream_free(&ws);
    }
    return saved;
}

struct rescan_commit {
    const struct wallet_rpc_context *ctx;
    const struct incremental_merkle_tree *tree;
    const struct incremental_witness *witnesses;
    const bool *active;
    const struct db_sapling_note *notes;
    int count, height, saved;
    struct uint256 hash, root;
    bool endpoint_changed, contended, ok;
};

static void rescan_fail_if_transaction_live(struct node_db *db)
{
    if (!sqlite3_get_autocommit(db->db)) {
        fputs("fatal: witness recovery transaction unresolved; terminating to preserve database integrity\n", stderr);
        _Exit(EXIT_FAILURE);
    }
}

static void rescan_rollback(struct node_db *db)
{
    (void)node_db_rollback(db);
    rescan_fail_if_transaction_live(db);
}

#ifdef ZCL_TESTING
void rescan_test_rollback(struct node_db *db) { rescan_rollback(db); }
#endif

static sqlite3_mutex *rescan_begin_locked(struct node_db *db, struct rescan_commit *c)
{
    if (db != c->ctx->node_db || !db->db) return NULL;
    sqlite3_mutex *mu = sqlite3_db_mutex(db->db);
    if (!mu || sqlite3_mutex_try(mu) != SQLITE_OK) {
        c->contended = true;
        return NULL;
    }
    if (!db->sync_in_batch && !sqlite3_get_autocommit(db->db)) {
        c->contended = true; sqlite3_mutex_leave(mu); return NULL;
    }
    bool ready = !db->sync_in_batch || node_db_sync_flush(db);
    if (!ready) rescan_rollback(db);
    else {
        ready = node_db_begin_immediate(db);
        if (!ready && !sqlite3_get_autocommit(db->db)) rescan_rollback(db);
    }
    if (!ready) { sqlite3_mutex_leave(mu); return NULL; }
    if (!zcl_mutex_trylock(&c->ctx->main_state->cs_main)) {
        c->contended = true;
        rescan_rollback(db);
        sqlite3_mutex_leave(mu);
        return NULL;
    }
    return mu;
}

static bool rescan_finish_locked(struct node_db *db, struct rescan_commit *c,
                                 sqlite3_mutex *mu, bool ok)
{
    if (ok) ok = node_db_commit(db);
    if (!ok) rescan_rollback(db);
    zcl_mutex_unlock(&c->ctx->main_state->cs_main);
    sqlite3_mutex_leave(mu);
    c->ok = ok;
    return ok;
}

static bool rescan_same_notes(struct node_db *db, const struct rescan_commit *c)
{
    int count = c->count;
    struct db_sapling_note *current = NULL;
    int n = db_sapling_note_list_unspent_alloc(db, &current);
    bool same = n == count;
    for (int i = 0; same && i < n; i++) {
        bool found = false;
        for (int j = 0; !found && j < n; j++) {
            const struct db_sapling_note *a = &current[i], *b = &c->notes[j];
            found = a->output_index == b->output_index && a->value == b->value &&
                a->block_height == b->block_height &&
                memcmp(a->txid, b->txid, 32) == 0 && memcmp(a->cm, b->cm, 32) == 0 &&
                memcmp(a->ivk, b->ivk, 32) == 0 && memcmp(a->rcm, b->rcm, 32) == 0 &&
                memcmp(a->diversifier, b->diversifier, 11) == 0 && memcmp(a->pk_d, b->pk_d, 32) == 0;
        }
        same = found;
    }
    free(current);
    return same;
}

static bool rescan_commit_write(struct node_db *db, void *opaque)
{
    struct rescan_commit *c = opaque;
    sqlite3_mutex *mu = rescan_begin_locked(db, c);
    if (!mu) return false;
    const struct block_index *p = active_chain_at(&c->ctx->main_state->chain_active,
                                                   c->height);
    bool current = p && p->phashBlock && uint256_eq(p->phashBlock, &c->hash) &&
                   uint256_eq(&p->hashFinalSaplingRoot, &c->root);
    c->endpoint_changed = !current;
    bool ok = current && rescan_same_notes(db, c) &&
              rescan_save_tree_state(c->ctx, c->tree, c->height);
    if (ok) {
        c->saved = rescan_save_witnesses(c->ctx, c->witnesses, c->active,
                                          c->notes, c->count, c->height);
        ok = c->saved == c->count;
    }
    return rescan_finish_locked(db, c, mu, ok);
}

static bool rescan_commit_dispatch(struct rescan_commit *c, bool replay_complete,
                                   int built, struct wallet_witness_outcome *out)
{
    if (!replay_complete || built != c->count) {
        out->status = WALLET_WITNESS_INCOMPLETE;
        return false;
    }
    struct db_service *svc = app_runtime_db_service();
    bool ok = svc && db_service_is_started(svc) &&
        db_service_node_db(svc) == c->ctx->node_db &&
        db_service_run_write(svc, rescan_commit_write, c) && c->ok;
    if (ok) {
        out->witnesses_saved = c->saved;
        out->status = WALLET_WITNESS_COMPLETE;
    } else {
        out->status = c->endpoint_changed ? WALLET_WITNESS_ENDPOINT_CHANGED :
            (c->contended ? WALLET_WITNESS_BUSY : WALLET_WITNESS_PERSIST_FAILED);
    }
    return ok;
}

#ifdef ZCL_TESTING
bool rescan_test_commit(const struct wallet_rpc_context *ctx,
                        const struct incremental_merkle_tree *tree,
                        const struct incremental_witness *witnesses,
                        const bool *active, const struct db_sapling_note *notes,
                        int count, int built, int height,
                        const struct uint256 *hash, const struct uint256 *root,
                        struct wallet_witness_outcome *out)
{
    struct rescan_commit c = {.ctx = ctx, .tree = tree, .witnesses = witnesses,
        .active = active, .notes = notes, .count = count, .height = height,
        .hash = *hash, .root = *root};
    memset(out, 0, sizeof(*out));
    return rescan_commit_dispatch(&c, true, built, out);
}
#endif

static bool rescan_empty_write(struct node_db *db, void *opaque)
{
    struct rescan_commit *c = opaque;
    sqlite3_mutex *mu = rescan_begin_locked(db, c);
    if (!mu) return false;
    const struct block_index *p = active_chain_at(&c->ctx->main_state->chain_active, c->height);
    bool current = p && p->phashBlock && uint256_eq(p->phashBlock, &c->hash) &&
                   uint256_eq(&p->hashFinalSaplingRoot, &c->root);
    c->endpoint_changed = !current;
    struct db_sapling_note *notes = NULL;
    int n = db_sapling_note_list_unspent_alloc(db, &notes);
    free(notes);
    return rescan_finish_locked(db, c, mu, current && n == 0);
}

static bool rescan_expected_endpoint(const struct wallet_rpc_context *ctx,
    const struct wallet_witness_endpoint *expected, int minimum,
    struct rescan_commit *c, bool require_body)
{
    if (!expected || expected->height < minimum) return false;
    zcl_mutex_lock(&ctx->main_state->cs_main);
    const struct block_index *p = active_chain_at(&ctx->main_state->chain_active, expected->height);
    bool ok = p && p->phashBlock && (!require_body || rescan_endpoint_header_addressable(p)) &&
        uint256_eq(p->phashBlock, &expected->hash) && uint256_eq(&p->hashFinalSaplingRoot, &expected->root);
    if (ok) { c->height = expected->height; c->hash = expected->hash; c->root = expected->root; }
    zcl_mutex_unlock(&ctx->main_state->cs_main);
    return ok;
}

static bool rescan_choose_endpoint(const struct wallet_rpc_context *ctx,
    const struct wallet_witness_endpoint *expected, int minimum,
    struct rescan_commit *c, bool require_body)
{
    if (expected) return rescan_expected_endpoint(ctx, expected, minimum, c, require_body);
    zcl_mutex_lock(&ctx->main_state->cs_main);
    int height = active_chain_height(&ctx->main_state->chain_active);
    const struct block_index *p = require_body ?
        rescan_find_replay_endpoint(&ctx->main_state->chain_active, minimum, &height) :
        active_chain_at(&ctx->main_state->chain_active, height);
    bool ok = p && p->phashBlock;
    if (ok) { c->height = height; c->hash = *p->phashBlock; c->root = p->hashFinalSaplingRoot; }
    zcl_mutex_unlock(&ctx->main_state->cs_main);
    return ok;
}

static bool rescan_empty_proof(const struct wallet_rpc_context *ctx,
                               struct wallet_witness_outcome *out,
                               const struct wallet_witness_endpoint *expected)
{
    struct rescan_commit c = {.ctx = ctx};
    bool available = rescan_choose_endpoint(ctx, expected, 0, &c, false);
    if (!available && expected) { out->status = WALLET_WITNESS_ENDPOINT_CHANGED; return false; }
    struct db_service *svc = app_runtime_db_service();
    bool ok = available && svc && db_service_is_started(svc) &&
        db_service_node_db(svc) == ctx->node_db &&
        db_service_run_write(svc, rescan_empty_write, &c) && c.ok;
    out->status = ok ? WALLET_WITNESS_COMPLETE :
        (c.endpoint_changed ? WALLET_WITNESS_ENDPOINT_CHANGED :
         (c.contended ? WALLET_WITNESS_BUSY : WALLET_WITNESS_PERSIST_FAILED));
    if (ok) { out->endpoint_height = c.height; out->endpoint_hash = c.hash; out->endpoint_root = c.root; }
    return ok;
}

/* One completion line per Sapling witness rescan that reached its scan:
 * heights, counts and milliseconds only. Refusals before the scan log nothing. */
#ifdef ZCL_TESTING
bool rescan_test_empty(const struct wallet_rpc_context *ctx, struct wallet_witness_outcome *out)
{
    return rescan_empty_proof(ctx, out, NULL);
}
#endif

static void witness_rescan_log_done(int start_height, int end_height,
                                    int blocks_scanned, int items,
                                    int64_t t0_ms, bool ok)
{
    LOG_INFO("rescanwitnesses",
             "rescanwitnesses: op=witness_rescan start_height=%d "
             "end_height=%d blocks_scanned=%d items=%d elapsed_ms=%lld "
             "result=%s",
             start_height, end_height, blocks_scanned, items,
             (long long)(platform_time_monotonic_ms() - t0_ms),
             ok ? "ok" : "failed");
}

/* First failing rescan precondition message, NULL when the context is usable. */
static const char *rescan_context_unavailable_error(
    const struct wallet_rpc_context *ctx)
{
    if (!ctx || !ctx->wallet) return "Wallet not available";
    if (!ctx->main_state)
        return "Main state not available";
    if (!wallet_ctx_db_ready(ctx))
        return "Node database not available";
    if (!ctx->datadir)
        return "Data directory not configured";
    return NULL;
}

/* Sapling activation height for the selected network, or
 * NETWORK_UPGRADE_NO_ACTIVATION when the chain params are unavailable. */
static int rescan_sapling_activation_height(void)
{
    const struct chain_params *chain = chain_params_get();
    return chain
        ? chain->consensus.vUpgrades[UPGRADE_SAPLING].nActivationHeight
        : NETWORK_UPGRADE_NO_ACTIVATION;
}

/* Block writers and stage readers use the network-specific directory
 * (<base>/regtest on regtest, ==base on mainnet). The wallet context owns
 * the base directory for backups and databases, so resolve the body root
 * explicitly instead of accidentally decoding a same-offset base file. */
static void rescan_resolve_block_datadir(const struct wallet_rpc_context *ctx,
                                         char *block_datadir,
                                         size_t block_datadir_size)
{
    GetDataDir(true, block_datadir, block_datadir_size);
    if (!block_datadir[0])
        (void)snprintf(block_datadir, block_datadir_size, "%s", ctx->datadir);
}

/* Replay blocks [sapling_start, safe_tip] into the tree and per-note
 * witnesses: skip blocks whose header root is zero or unchanged, decode each
 * tree-changing block's durable body and append its commitments, printing
 * the checkpoint root comparison on cadence. */
static bool rescan_replay_blocks(const struct wallet_rpc_context *ctx,
                                 const char *block_datadir,
                                 int sapling_start, int safe_tip,
                                 struct incremental_merkle_tree *tree,
                                 struct incremental_witness *witnesses,
                                 bool *witness_active,
                                 const struct db_sapling_note *notes,
                                 int n_notes, int64_t t_start,
                                 int *blocks_scanned_out,
                                 size_t *total_commitments_out,
                                 int *witnesses_built_out)
{
    *blocks_scanned_out = 0;
    *total_commitments_out = 0;
    *witnesses_built_out = 0;
    int blocks_scanned = 0;
    size_t total_commitments = 0;
    bool complete = true;
    int witnesses_built = 0;

    /* Keep the descriptor alive with its view.  Windows file mappings do not
     * inherit POSIX's close-after-mmap lifetime semantics. */
    struct wallet_rescan_block_mapping block_mapping;
    wallet_rescan_block_mapping_init(&block_mapping);

    for (int h = sapling_start; h <= safe_tip; h++) {
        const struct block_index *pindex =
            active_chain_at(&ctx->main_state->chain_active, h);
        if (!pindex || !pindex->phashBlock) {
            complete = false;
            continue;
        }

        /* A repeated header root proves this block did not change the Sapling
         * tree, so the body is irrelevant to witness replay. This skips the
         * overwhelming majority of blocks without trusting a heuristic wire
         * scanner. A zero root is an unavailable pre-commitment projection;
         * it cannot authorize a save and likewise supplies no changed-tree
         * evidence to replay. */
        struct uint256 before_root;
        incremental_tree_root(tree, &before_root);
        if (uint256_is_zero_local(&pindex->hashFinalSaplingRoot)) {
            complete = false;
            continue;
        }
        if (uint256_eq(&before_root, &pindex->hashFinalSaplingRoot)) {
            blocks_scanned++;
            continue;
        }
        if (!rescan_block_body_mapped(pindex, &block_mapping, block_datadir)) {
            complete = false;
            continue;
        }

        /* The header proves the tree changed. Decode this exact durable body
         * with the consensus block parser and append every output; unlike the
         * former fixed 4096-entry fast-scan buffer, this cannot silently drop
         * commitments from a valid high-output block. The final header-root
         * comparison below remains the authority before persistence. */
        size_t data_pos = (size_t)pindex->nDataPos;
        size_t block_data_len = block_mapping.view.size - data_pos;
        struct byte_stream body_stream;
        stream_init_from_data(&body_stream,
                              block_mapping.view.data + data_pos,
                              block_data_len);
        struct block block;
        block_init(&block);
        if (!block_deserialize(&block, &body_stream)) {
            block_free(&block);
            LOG_WARN_IN("rpc_rescanwitnesses", "rescanwitnesses",
                        "durable block body decode failed at height=%d", h);
            complete = false;
            blocks_scanned++;
            continue;
        }
        total_commitments += rescan_append_block_commitments(
            &block, tree, witnesses, witness_active, notes, n_notes,
            &witnesses_built);
        block_free(&block);
        blocks_scanned++;

        /* Checkpoint: compare our tree root vs block header.
         * Every 100K blocks normally, every 1000 heights in last 10K. */
        bool do_ckpt = (blocks_scanned % 100000 == 0) ||
                       (h > safe_tip - 10000 && h % 1000 == 0);
        if (do_ckpt) {
            rescan_print_checkpoint(tree, pindex, blocks_scanned, h,
                                    total_commitments, witnesses_built, n_notes,
                                    t_start);
        }
    }

    wallet_rescan_block_mapping_close(&block_mapping);

    *blocks_scanned_out = blocks_scanned;
    *total_commitments_out = total_commitments;
    *witnesses_built_out = witnesses_built;
    return complete;
}

#ifdef ZCL_TESTING
bool rescan_test_replay(const struct wallet_rpc_context *ctx, int start, int end)
{
    struct incremental_merkle_tree tree;
    sapling_tree_init(&tree);
    struct incremental_witness witness = {0};
    struct db_sapling_note note = {0};
    bool active = false;
    int blocks = 0, built = 0;
    size_t commitments = 0;
    return rescan_replay_blocks(ctx, ctx->datadir, start, end, &tree, &witness,
                                &active, &note, 0, 0, &blocks, &commitments, &built);
}
#endif

static bool rescan_witnesses_with_context(struct wallet_rpc_context *ctx,
    struct json_value *result, struct wallet_witness_outcome *out,
    const struct wallet_witness_endpoint *expected)
{
    memset(out, 0, sizeof(*out));
    out->endpoint_height = -1;
    const char *context_error = rescan_context_unavailable_error(ctx);
    if (context_error) {
        json_set_str(result, context_error);
        return false;
    }

    /* Load ALL unspent notes that need witnesses (no fixed cap — a 256-cap
     * here meant the recovery path could not rebuild witnesses for notes ranked
     * beyond #256, leaving them permanently unspendable). */
    struct db_sapling_note *notes = NULL;
    int n_notes = db_sapling_note_list_unspent_alloc(ctx->node_db, &notes);
    if (n_notes < 0) {
        json_set_str(result, "Failed to load unspent notes");
        return false;
    }
    if (n_notes == 0) {
        free(notes);
        bool empty = rescan_empty_proof(ctx, out, expected);
        json_set_object(result);
        json_push_kv_int(result, "notes_updated", 0);
        json_push_kv_str(result, "status", empty ? "no unspent notes" : "unavailable");
        return empty;
    }

    out->notes_total = n_notes;
    printf("rescanwitnesses: building witnesses for %d notes...\n", n_notes);
    fflush(stdout);

    /* Prevent sync_controller from overwriting Sapling tree during rescan */
    extern _Atomic bool g_sapling_rescan_active;
    if (atomic_exchange(&g_sapling_rescan_active, true)) {
        free(notes);
        json_set_str(result, "Witness rebuild already active");
        return false;
    }

    int sapling_start = rescan_sapling_activation_height();
    if (sapling_start < 0) {
        free(notes);
        atomic_store(&g_sapling_rescan_active, false);
        json_set_str(result,
                     "Sapling is not active on the selected network");
        return false;
    }

    /* Initialize empty tree and per-note witness state */
    struct incremental_merkle_tree tree;
    sapling_tree_init(&tree);
    int seed_height = sapling_start - 1;
    const char *seed_source = "activation";
    if (rescan_seed_before_oldest_note(&ctx->main_state->chain_active,
                                       notes, n_notes, sapling_start, &tree,
                                       &sapling_start, &seed_height)) {
        seed_source = "anchor_kv_before_oldest_note";
        LOG_INFO("rescanwitnesses",
                 "rebuilding from header-bound Sapling frontier h=%d; "
                 "oldest unspent note h=%d", seed_height, sapling_start);
    }

    struct incremental_witness *witnesses = zcl_calloc((size_t)n_notes,
        sizeof(struct incremental_witness), "rescan witnesses");
    bool *witness_active = zcl_calloc((size_t)n_notes, sizeof(bool), "rescan witness active");
    if (!witnesses || !witness_active) {
        /* zcl_calloc already logged the OOM. Match the function's existing
         * cleanup convention (see the diverged-tree refusal path): free all
         * three arrays, release the global rescan latch, and fail the RPC. */
        free(witnesses);
        free(witness_active);
        free(notes);
        atomic_store(&g_sapling_rescan_active, false);
        json_set_str(result, "Out of memory building witness arrays");
        return false;
    }
    int witnesses_built = 0;

    char block_datadir[4096];
    rescan_resolve_block_datadir(ctx, block_datadir, sizeof(block_datadir));

    int64_t t0_ms = platform_time_monotonic_ms();
    int64_t t_start = (int64_t)platform_time_wall_time_t();
    int blocks_scanned = 0;
    size_t total_commitments = 0;

    /* Pick the newest addressable, header-bound endpoint. This must include
     * the finality window: a newly confirmed note cannot acquire a witness at
     * an endpoint older than the note itself. Do not gate on BLOCK_HAVE_DATA;
     * it is a rebuildable projection. The durable coordinates select bytes,
     * and the exact hash/root snapshot below is rechecked before every save. */
    struct rescan_commit selected = {.ctx = ctx};
    if (!rescan_choose_endpoint(ctx, expected, sapling_start, &selected, true)) {
        if (expected) out->status = WALLET_WITNESS_ENDPOINT_CHANGED;
        free(witnesses);
        free(witness_active);
        free(notes);
        atomic_store(&g_sapling_rescan_active, false);
        json_set_str(result,
                     "No readable header-bound endpoint at or above the "
                     "oldest unspent note");
        return false;
    }
    int safe_tip = selected.height;
    struct uint256 endpoint_hash = selected.hash;
    struct uint256 endpoint_root = selected.root;
    out->endpoint_height = safe_tip;
    out->endpoint_hash = endpoint_hash;
    out->endpoint_root = endpoint_root;

    bool replay_complete = rescan_replay_blocks(ctx, block_datadir, sapling_start, safe_tip, &tree,
                         witnesses, witness_active, notes, n_notes, t_start,
                         &blocks_scanned, &total_commitments, &witnesses_built);

    out->witnesses_built = witnesses_built;
    /* Binary search for divergence point: check tree root at last checkpoint
     * that passed (3036968) vs block header. We know tree matches there.
     * Log our total commitment count at save height for comparison. */
    printf("rescanwitnesses: total commitments: %zu at save height %d\n",
           total_commitments, safe_tip);
    fflush(stdout);

    struct uint256 final_tree_root;
    incremental_tree_root(&tree, &final_tree_root);
    struct uint256 final_header_root;
    memset(&final_header_root, 0, sizeof(final_header_root));

    /* Verify tree root matches block header at save height */
    rescan_check_final_root(ctx, &tree, &final_tree_root, safe_tip, &endpoint_hash,
                            &endpoint_root, &final_header_root);

    /* Verify witness roots match tree root BEFORE saving */
    int witness_root_mismatches = rescan_check_witness_roots(
        &tree, witnesses, witness_active, n_notes, &final_tree_root);

    if (!rescan_result_consensus_valid(&final_tree_root, &final_header_root,
                                       witness_root_mismatches)) {
        out->status = replay_complete ? WALLET_WITNESS_FAILED : WALLET_WITNESS_INCOMPLETE;
        char our_hex[65], header_hex[65];
        uint256_get_hex(&final_tree_root, our_hex);
        uint256_get_hex(&final_header_root, header_hex);
        printf("rescanwitnesses: refusing to save diverged Sapling tree "
               "(height=%d mismatches=%d our=%s header=%s)\n",
               safe_tip, witness_root_mismatches, our_hex, header_hex);
        fflush(stdout);

        free(witnesses);
        free(witness_active);
        free(notes);
        atomic_store(&g_sapling_rescan_active, false);
        witness_rescan_log_done(sapling_start, safe_tip, blocks_scanned, 0,
                                t0_ms, false);

        json_set_object(result);
        json_push_kv_str(result, "status", "diverged");
        json_push_kv_str(result, "message",
                         "Sapling tree diverged from consensus header root; refusing to save rescan tree or witnesses");
        json_push_kv_int(result, "height", safe_tip);
        json_push_kv_str(result, "our_root", our_hex);
        json_push_kv_str(result, "header_root", header_hex);
        json_push_kv_int(result, "witness_root_mismatches",
                         witness_root_mismatches);
        return false;
    }

    struct rescan_commit commit = {
        .ctx = ctx, .tree = &tree, .witnesses = witnesses,
        .active = witness_active, .notes = notes, .count = n_notes,
        .height = safe_tip, .hash = endpoint_hash, .root = endpoint_root
    };
    bool committed = rescan_commit_dispatch(&commit, replay_complete, witnesses_built, out);
    int saved = out->witnesses_saved;

    free(witnesses);
    free(witness_active);
    free(notes);

    /* NOW release the rescan lock — tree and witnesses are all saved */
    atomic_store(&g_sapling_rescan_active, false);

    int64_t elapsed = (int64_t)platform_time_wall_time_t() - t_start;
    printf("rescanwitnesses: done in %llds — %zu cms, %d/%d witnesses, "
           "%d saved\n",
           (long long)elapsed, total_commitments, witnesses_built,
           n_notes, saved);
    fflush(stdout);

    witness_rescan_log_done(sapling_start, safe_tip, blocks_scanned, saved,
                            t0_ms, committed);
    json_set_object(result);
    json_push_kv_str(result, "seed_source", seed_source);
    json_push_kv_int(result, "seed_height", seed_height);
    json_push_kv_int(result, "replay_start_height", sapling_start);
    json_push_kv_int(result, "blocks_scanned", blocks_scanned);
    json_push_kv_int(result, "notes_total", n_notes);
    json_push_kv_int(result, "witnesses_built", witnesses_built);
    json_push_kv_int(result, "witnesses_saved", saved);
    json_push_kv_int(result, "elapsed_seconds", elapsed);
    if (!committed) {
        json_push_kv_str(result, "status", "incomplete");
        return false;
    }
    return true;
}

bool wallet_rescan_witnesses_at(struct wallet_rpc_context *ctx,
    const struct wallet_witness_endpoint *endpoint, struct wallet_witness_outcome *out)
{
    if (!out) return false;
    memset(out, 0, sizeof(*out));
    out->endpoint_height = -1;
    if (!endpoint) return false;
    struct json_value result; json_init(&result);
    bool ok = rescan_witnesses_with_context(ctx, &result, out, endpoint);
    json_free(&result);
    return ok;
}

bool wallet_rescan_witnesses_context(struct wallet_rpc_context *ctx,
                                      struct wallet_witness_outcome *out)
{
    if (!out) return false;
    struct json_value result;
    json_init(&result);
    bool ok = rescan_witnesses_with_context(ctx, &result, out, NULL);
    json_free(&result);
    return ok;
}

bool wallet_rescan_witnesses(const struct json_value *params, bool help,
                             struct json_value *result,
                             struct wallet_witness_outcome *out)
{
    if (!out) return false;
    memset(out, 0, sizeof(*out));
    out->endpoint_height = -1;
    (void)params;
    RPC_HELP(help, result,
        "rescanwitnesses\n"
        "Rebuild Sapling Merkle witnesses for all unspent shielded notes.\n"
        "Required before spending z→z or z→t. Replays the commitment tree\n"
        "from the Sapling activation height to tip.");
    return rescan_witnesses_with_context(wallet_ctx(), result, out, NULL);
}

bool rpc_rescanwitnesses(const struct json_value *params, bool help,
                         struct json_value *result)
{
    struct wallet_witness_outcome out;
    return wallet_rescan_witnesses(params, help, result, &out);
}
