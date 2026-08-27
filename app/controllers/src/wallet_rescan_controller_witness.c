/* Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 *
 * rescanwitnesses RPC: rebuild Sapling Merkle witnesses for unspent notes. */

#include "controllers/wallet_rescan_controller_internal.h"

#include "storage/anchor_kv.h"
#include "storage/progress_store.h"

#include <limits.h>
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

    int oldest_height = INT_MAX;
    for (int i = 0; i < n_notes; i++) {
        if (notes[i].block_height >= sapling_activation_height &&
            notes[i].block_height < oldest_height)
            oldest_height = notes[i].block_height;
    }
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

bool rpc_rescanwitnesses(const struct json_value *params, bool help,
	                                  struct json_value *result)
{
    struct wallet_rpc_context *ctx = wallet_ctx();
    (void)params;
    RPC_HELP(help, result,
        "rescanwitnesses\n"
        "Rebuild Sapling Merkle witnesses for all unspent shielded notes.\n"
        "Required before spending z→z or z→t. Replays the commitment tree\n"
        "from the Sapling activation height to tip.");

    ENSURE_WALLET(result);
    if (!ctx->main_state) {
        json_set_str(result, "Main state not available");
        return false;
    }
    if (!wallet_ctx_db_ready(ctx)) {
        json_set_str(result, "Node database not available");
        return false;
    }
    if (!ctx->datadir) {
        json_set_str(result, "Data directory not configured");
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
        json_set_object(result);
        json_push_kv_int(result, "notes_updated", 0);
        json_push_kv_str(result, "status", "no unspent notes");
        return true;
    }

    printf("rescanwitnesses: building witnesses for %d notes...\n", n_notes);
    fflush(stdout);

    /* Prevent sync_controller from overwriting Sapling tree during rescan */
    extern _Atomic bool g_sapling_rescan_active;
    atomic_store(&g_sapling_rescan_active, true);

    const struct chain_params *chain = chain_params_get();
    int sapling_start = chain
        ? chain->consensus.vUpgrades[UPGRADE_SAPLING].nActivationHeight
        : NETWORK_UPGRADE_NO_ACTIVATION;
    if (sapling_start < 0) {
        free(notes);
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

    /* Block writers and stage readers use the network-specific directory
     * (<base>/regtest on regtest, ==base on mainnet). The wallet context owns
     * the base directory for backups and databases, so resolve the body root
     * explicitly instead of accidentally decoding a same-offset base file. */
    char block_datadir[4096];
    GetDataDir(true, block_datadir, sizeof(block_datadir));
    if (!block_datadir[0])
        (void)snprintf(block_datadir, sizeof(block_datadir), "%s",
                       ctx->datadir);

    /* mmap cache */
    int cached_file = -1;
    uint8_t *cached_data = NULL;
    size_t cached_size = 0;

    int64_t t_start = (int64_t)platform_time_wall_time_t();
    int blocks_scanned = 0;
    size_t total_commitments = 0;

    /* Pick the newest addressable, header-bound endpoint. This must include
     * the finality window: a newly confirmed note cannot acquire a witness at
     * an endpoint older than the note itself. Do not gate on BLOCK_HAVE_DATA;
     * it is a rebuildable projection. The durable coordinates select bytes,
     * and the exact hash/root snapshot below is rechecked before every save. */
    int safe_tip = -1;
    const struct block_index *save_block = rescan_find_replay_endpoint(
        &ctx->main_state->chain_active, sapling_start, &safe_tip);
    if (!save_block) {
        free(witnesses);
        free(witness_active);
        free(notes);
        atomic_store(&g_sapling_rescan_active, false);
        json_set_str(result,
                     "No readable header-bound endpoint at or above the "
                     "oldest unspent note");
        return false;
    }
    struct uint256 endpoint_hash = *save_block->phashBlock;
    struct uint256 endpoint_root = save_block->hashFinalSaplingRoot;

    for (int h = sapling_start; h <= safe_tip; h++) {
        const struct block_index *pindex =
            active_chain_at(&ctx->main_state->chain_active, h);
        if (!pindex) continue;
        /* File coordinates, not the lag-prone HAVE_DATA projection, decide
         * whether this recovery pass can attempt the immutable body. Any
         * absent/truncated body leaves the reconstructed root short and the
         * consensus comparison below refuses every save. */
        if (!pindex->phashBlock || pindex->nFile < 0)
            continue;

        /* mmap block file */
        if (pindex->nFile != cached_file) {
            if (cached_data) munmap(cached_data, cached_size);
            char path[sizeof(block_datadir) + 32];
            snprintf(path, sizeof(path), "%s/blocks/blk%05d.dat",
                     block_datadir, pindex->nFile);
            int fd = open(path, O_RDONLY);
            if (fd < 0) { cached_data = NULL; cached_file = -1; continue; }
            struct stat fst;
            if (fstat(fd, &fst) != 0) { close(fd); continue; }
            cached_size = (size_t)fst.st_size;
            cached_data = mmap(NULL, cached_size,
                               PROT_READ, MAP_PRIVATE, fd, 0);
            close(fd);
            if (cached_data == MAP_FAILED) {
                cached_data = NULL; cached_file = -1; continue;
            }
            /* Advise kernel: sequential read, prefetch entire file */
            posix_madvise(cached_data, cached_size,
                          POSIX_MADV_SEQUENTIAL);
            posix_madvise(cached_data, cached_size,
                          POSIX_MADV_WILLNEED);
            cached_file = pindex->nFile;
        }
        if (!cached_data || pindex->nDataPos >= cached_size) continue;

        /* A repeated header root proves this block did not change the Sapling
         * tree, so the body is irrelevant to witness replay. This skips the
         * overwhelming majority of blocks without trusting a heuristic wire
         * scanner. A zero root is an unavailable pre-commitment projection;
         * it cannot authorize a save and likewise supplies no changed-tree
         * evidence to replay. */
        struct uint256 before_root;
        incremental_tree_root(&tree, &before_root);
        if (uint256_is_zero_local(&pindex->hashFinalSaplingRoot) ||
            uint256_eq(&before_root, &pindex->hashFinalSaplingRoot)) {
            blocks_scanned++;
            continue;
        }

        /* The header proves the tree changed. Decode this exact durable body
         * with the consensus block parser and append every output; unlike the
         * former fixed 4096-entry fast-scan buffer, this cannot silently drop
         * commitments from a valid high-output block. The final header-root
         * comparison below remains the authority before persistence. */
        size_t block_data_len = cached_size - pindex->nDataPos;
        struct byte_stream body_stream;
        stream_init_from_data(&body_stream,
                              cached_data + pindex->nDataPos,
                              block_data_len);
        struct block block;
        block_init(&block);
        if (!block_deserialize(&block, &body_stream)) {
            block_free(&block);
            LOG_WARN("rescanwitnesses",
                     "durable block body decode failed at height=%d", h);
            blocks_scanned++;
            continue;
        }
        total_commitments += rescan_append_block_commitments(
            &block, &tree, witnesses, witness_active, notes, n_notes,
            &witnesses_built);
        block_free(&block);
        blocks_scanned++;

        /* Checkpoint: compare our tree root vs block header.
         * Every 100K blocks normally, every 1000 heights in last 10K. */
        bool do_ckpt = (blocks_scanned % 100000 == 0) ||
                       (h > safe_tip - 10000 && h % 1000 == 0);
        if (do_ckpt) {
            int64_t elapsed = (int64_t)platform_time_wall_time_t() - t_start;
            printf("rescanwitnesses: %d blocks (height %d), "
                   "%zu cms, %d/%d witnesses, %llds",
                   blocks_scanned, h, total_commitments,
                   witnesses_built, n_notes, (long long)elapsed);

            struct uint256 our_root;
            incremental_tree_root(&tree, &our_root);
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
                       oh, incremental_tree_size(&tree), bh);
            }
            fflush(stdout);
        }
    }

    if (cached_data) munmap(cached_data, cached_size);

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
    {
        const struct block_index *current_save_block =
            active_chain_at(&ctx->main_state->chain_active, safe_tip);
        if (current_save_block && current_save_block->phashBlock &&
            uint256_eq(current_save_block->phashBlock, &endpoint_hash) &&
            uint256_eq(&current_save_block->hashFinalSaplingRoot,
                       &endpoint_root)) {
            final_header_root = endpoint_root;
            char oh[65], bh[65];
            uint256_get_hex(&final_tree_root, oh);
            uint256_get_hex(&final_header_root, bh);
            if (memcmp(final_tree_root.data, final_header_root.data, 32) == 0) {
                printf("rescanwitnesses: FINAL tree root matches block header at height %d ✓\n", safe_tip);
            } else {
                printf("rescanwitnesses: FINAL tree root DOES NOT match block header at height %d!\n"
                       "  our root:   %s (size=%zu)\n"
                       "  block root: %s\n",
                       safe_tip, oh, incremental_tree_size(&tree), bh);
            }
            fflush(stdout);
        } else {
            printf("rescanwitnesses: FINAL tree root cannot be checked at height %d (missing active-chain block)\n",
                   safe_tip);
            fflush(stdout);
        }
    }

    /* Verify witness roots match tree root BEFORE saving */
    int witness_root_mismatches = 0;
    {
        char tr_hex[65]; uint256_get_hex(&final_tree_root, tr_hex);
        for (int ni = 0; ni < n_notes; ni++) {
            if (!witness_active[ni]) continue;
            struct uint256 wr;
            incremental_witness_root(&witnesses[ni], &wr);
            char wr_hex[65]; uint256_get_hex(&wr, wr_hex);
            if (memcmp(wr.data, final_tree_root.data, 32) != 0) {
                witness_root_mismatches++;
                printf("rescanwitnesses: WITNESS ROOT MISMATCH for note %d!\n"
                    "  tree root:    %s (size=%zu)\n"
                    "  witness root: %s (fills=%zu)\n",
                    ni, tr_hex, incremental_tree_size(&tree),
                    wr_hex, witnesses[ni].num_filled);
            } else {
                printf("rescanwitnesses: note %d witness root MATCHES tree ✓\n", ni);
            }
        }
        fflush(stdout);
    }

    if (!rescan_result_consensus_valid(&final_tree_root, &final_header_root,
                                       witness_root_mismatches)) {
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

    /* Save the authoritative tree state to node_state.
     * This replaces any incomplete tree from catchup.
     * Tree is saved at safe_tip height — subsequent connect_block
     * calls will load it and extend naturally for remaining blocks. */
    {
        struct byte_stream ts;
        stream_init(&ts, 4096);
        incremental_tree_serialize(&tree, &ts);
        /* Save to the normal key + "sapling_tree_rebuild_height" as ONE
         * atomic pair (sapling_tree_persist_pair, lane/sapling-tree-persist)
         * — this is the SAME height key config/src/boot.c's loader and
         * sapling_tree_rebuild() trust to resume/fold-forward from, and the
         * consensus check just above (rescan_result_consensus_valid) already
         * proved final_tree_root == the real header root at safe_tip, so
         * safe_tip is a legitimate saved-height binding. Also save to the
         * rescan-specific key (can't be overwritten by connect_block). */
        sapling_tree_persist_pair(ctx->node_db, ts.data, ts.size,
                                  (int64_t)safe_tip);
        node_db_state_set(ctx->node_db, "sapling_tree_rescan", ts.data, ts.size);

        printf("rescanwitnesses: tree saved (%zu bytes, %zu cms)\n",
               ts.size, incremental_tree_size(&tree));
        fflush(stdout);
        stream_free(&ts);

        char height_str[16];
        snprintf(height_str, sizeof(height_str), "%d", safe_tip);
        node_db_state_set(ctx->node_db, "sapling_tree_height",
                          (uint8_t *)height_str, strlen(height_str));
        node_db_state_set(ctx->node_db, "sapling_tree_rescan_height",
                          (uint8_t *)height_str, strlen(height_str));
    }

    /* Serialize and save witnesses (BEFORE releasing the rescan lock) */
    int saved = 0;
    for (int ni = 0; ni < n_notes; ni++) {
        if (!witness_active[ni]) continue;

        const struct sapling_key_entry *key =
            sapling_keystore_find_by_ivk(&ctx->wallet->sapling_keys,
                                         notes[ni].ivk);
        if (!key || incremental_tree_size(&witnesses[ni].tree) == 0)
            continue;
        uint8_t ak[32], nk[32], nf[32];
        sapling_ask_to_ak(key->xsk.expsk.ask, ak);
        sapling_nsk_to_nk(key->xsk.expsk.nsk, nk);
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

    json_set_object(result);
    json_push_kv_str(result, "seed_source", seed_source);
    json_push_kv_int(result, "seed_height", seed_height);
    json_push_kv_int(result, "replay_start_height", sapling_start);
    json_push_kv_int(result, "blocks_scanned", blocks_scanned);
    json_push_kv_int(result, "notes_total", n_notes);
    json_push_kv_int(result, "witnesses_built", witnesses_built);
    json_push_kv_int(result, "witnesses_saved", saved);
    json_push_kv_int(result, "elapsed_seconds", elapsed);
    return true;
}
