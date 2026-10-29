/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Boot tip-publication hooks — the process_block -> chain-state seam.
 *
 * When the validation engine publishes a new active tip (or clears it on a
 * disconnect-past-genesis), it calls these hooks, which route through the
 * chain_evidence_controller when evidence is present, else the chain_state
 * repository (csr) single-writer. boot_register_process_block_hooks() wires
 * them — plus the gap-fill kick — into process_block during app_init_services.
 *
 * These are pure adapters: every input arrives by parameter, so the file owns
 * no shared boot state. boot_internal.h supplies boot_svc_ctx + the main_state
 * and coins types; the rest come from the service/validation headers below.
 */

#include "config/boot_internal.h"
#include "validation/accept_to_mempool.h"
#include "validation/process_block.h"
#include "validation/process_block_invalidate.h"
#include "storage/disk_block_io.h"
#include "services/chain_state_service.h"
#include "services/chain_evidence_authority_service.h"
#include "services/chain_tip.h"          /* chain_set_active_tip, TIP_FROM_* (ZCL_TESTING paths) */
#include "services/gap_fill_service.h"
#include "validation/mirror_consensus.h"
#include "controllers/sync_controller.h"
#include "jobs/tip_finalize_wallet_reconcile.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"
#include "util/util.h"  /* GetDataDir(true): net-specific block body root */

#include <stdlib.h>

static void boot_gap_fill_kick(void *ctx)
{
    (void)ctx;
    gap_fill_kick();
}

static void boot_restore_result_reset(
    struct process_block_mempool_restore_result *out)
{
    if (out)
        memset(out, 0, sizeof(*out));
}

/* Net-specific block body root, falling back to the configured datadir. */
static const char *boot_restore_body_datadir(
    const struct boot_svc_ctx *svc, char *net_datadir, size_t size)
{
    GetDataDir(true, net_datadir, size);
    return net_datadir[0] ? net_datadir : svc->datadir;
}

static bool boot_restore_args_valid(
    const struct boot_svc_ctx *svc,
    const struct block_index *first_disconnected,
    const struct block_index *old_active_tip,
    enum process_block_mempool_segment_action action)
{
    return svc && svc->mempool && svc->coins_tip && svc->state &&
           svc->params && svc->datadir && first_disconnected &&
           old_active_tip && first_disconnected->phashBlock &&
           old_active_tip->nHeight >= first_disconnected->nHeight &&
           (action == PROCESS_BLOCK_MEMPOOL_RESTORE_DISCONNECTED ||
            action == PROCESS_BLOCK_MEMPOOL_REMOVE_RECONNECTED);
}

/* Build the active-path array [first_disconnected .. old_active_tip] or return
 * NULL (freeing it) when the segment identity proof fails. */
static struct block_index **boot_restore_build_path(
    struct block_index *first_disconnected,
    struct block_index *old_active_tip,
    int depth)
{
    struct block_index **path = zcl_malloc(
        (size_t)depth * sizeof(*path), "invalidate_mempool_path");
    if (!path)
        return NULL;

    struct block_index *walk = old_active_tip;
    for (int i = depth - 1; i >= 0; i--) {
        if (!walk || walk->nHeight != first_disconnected->nHeight + i) {
            free(path);
            return NULL;
        }
        path[i] = walk;
        walk = walk->pprev;
    }
    if (!path[0]->phashBlock ||
        !uint256_eq(path[0]->phashBlock, first_disconnected->phashBlock)) {
        free(path);
        return NULL;
    }
    return path;
}

static bool boot_restore_read_block(
    struct boot_svc_ctx *svc,
    struct block_index *path_index,
    const char *body_datadir,
    struct block *blk,
    struct process_block_mempool_restore_result *out)
{
    /* chain[] may name a bodiless snapshot/header twin.  The block map is
     * the durable body/status owner for this exact hash; resolve through
     * it before pread, while retaining the active path only as the segment
     * identity proof above. */
    struct block_index *body_index = path_index->phashBlock
        ? block_map_find(&svc->state->map_block_index,
                         path_index->phashBlock)
        : NULL;
    if (!body_index)
        body_index = path_index;
    block_init(blk);
    if (!read_block_from_disk_index_pread(blk, body_index, body_datadir))
        return false;
    if (out)
        out->blocks_read++;
    return true;
}

static void boot_restore_invalidate_block_coins(
    struct boot_svc_ctx *svc, struct block *blk)
{
    /* The reducer inverse changed these exact coins without passing
     * through coins_view_cache::batch_write.  Drop stale cache entries
     * before the ordinary admission gate proves inputs against coins_kv. */
    for (size_t t = 0; t < blk->num_vtx; t++) {
        struct transaction *tx = &blk->vtx[t];
        (void)coins_view_cache_invalidate(svc->coins_tip, &tx->hash);
        if (!transaction_is_coinbase(tx)) {
            for (size_t v = 0; v < tx->num_vin; v++)
                (void)coins_view_cache_invalidate(
                    svc->coins_tip, &tx->vin[v].prevout.hash);
        }
    }
}

static void boot_restore_remove_reconnected(
    struct boot_svc_ctx *svc,
    struct block *blk,
    const struct block_index *path_index,
    struct process_block_mempool_restore_result *out)
{
    for (size_t t = 0; t < blk->num_vtx; t++) {
        struct transaction *tx = &blk->vtx[t];
        if (transaction_is_coinbase(tx))
            continue;
        if (out) {
            out->txs_attempted++;
            if (tx_mempool_exists(svc->mempool, &tx->hash))
                out->txs_removed++;
        }
    }
    tx_mempool_remove_for_block(svc->mempool, blk->vtx, blk->num_vtx,
                                (unsigned int)path_index->nHeight);
}

/* True when there is no wallet or the wallet reconcile succeeded. */
static bool boot_restore_wallet_reconcile(
    struct boot_svc_ctx *svc, struct block_index *path_index)
{
    return !svc->wallet || tip_finalize_run_wallet_reconcile(path_index);
}

static bool boot_restore_alloc_keep_pending(
    const struct block *blk, bool **keep_pending)
{
    *keep_pending = zcl_calloc(
        blk->num_vtx, sizeof(**keep_pending),
        "invalidate wallet pending decisions");
    return !(blk->num_vtx > 0 && !*keep_pending);
}

/* Try to re-admit one disconnected tx.  Returns true only when the mempool
 * refused it (result and detail are then filled for the caller to log). */
static bool boot_restore_accept_tx(
    struct boot_svc_ctx *svc,
    struct transaction *tx,
    bool *keep_pending,
    struct process_block_mempool_restore_result *out,
    char *detail, size_t detail_size,
    enum mempool_accept_result *ar_out)
{
    if (transaction_is_coinbase(tx))
        return false;
    if (out)
        out->txs_attempted++;
    enum mempool_accept_result ar = accept_to_mempool_detailed(
        svc->mempool, svc->coins_tip, svc->state, svc->params, tx,
        detail, detail_size);
    *ar_out = ar;
    if (ar == MEMPOOL_ACCEPT_OK || ar == MEMPOOL_ACCEPT_DUPLICATE) {
        *keep_pending = true;
        if (out)
            out->txs_accepted++;
        if (svc->connman) {
            connman_relay_transaction(svc->connman, &tx->hash);
            if (out)
                out->txs_relayed++;
        }
        return false;
    }
    if (out)
        out->txs_rejected++;
    return true;
}

/* True when there is no live wallet or the retract succeeded. */
static bool boot_restore_wallet_retract_tx(
    struct boot_svc_ctx *svc, struct transaction *tx, bool keep_pending)
{
    return !svc->wallet ||
           wallet_disconnect_transaction(svc->wallet, tx, keep_pending);
}

/* True when there is no node db or the durable retract succeeded. */
static bool boot_restore_node_db_retract(
    struct boot_svc_ctx *svc, struct block *blk, bool *keep_pending)
{
    return !svc->node_db ||
           node_db_sync_wallet_disconnect_block(svc->node_db, blk,
                                                keep_pending);
}

static void boot_restore_rewind_wallet(
    struct boot_svc_ctx *svc,
    enum process_block_mempool_segment_action action,
    const struct block_index *first_disconnected)
{
    if (action == PROCESS_BLOCK_MEMPOOL_RESTORE_DISCONNECTED && svc->wallet)
        (void)wallet_rewind_confirmations(
            svc->wallet, first_disconnected->nHeight - 1);
}

static bool boot_process_block_restore_mempool(
    void *ctx,
    struct block_index *first_disconnected,
    struct block_index *old_active_tip,
    enum process_block_mempool_segment_action action,
    struct process_block_mempool_restore_result *out)
{
    struct boot_svc_ctx *svc = ctx;
    boot_restore_result_reset(out);
    if (!boot_restore_args_valid(svc, first_disconnected, old_active_tip,
                                 action))
        return false;

    int depth = old_active_tip->nHeight - first_disconnected->nHeight + 1;
    struct block_index **path = boot_restore_build_path(
        first_disconnected, old_active_tip, depth);
    if (!path)
        return false;

    bool complete = true;
    char net_datadir[2048] = {0};
    const char *body_datadir = boot_restore_body_datadir(
        svc, net_datadir, sizeof(net_datadir));
    for (int i = 0; i < depth; i++) {
        struct block blk;
        if (!boot_restore_read_block(svc, path[i], body_datadir, &blk,
                                     out)) {
            LOG_WARN("validation",
                     "%s: cannot read block h=%d for mempool reconciliation",
                     action == PROCESS_BLOCK_MEMPOOL_RESTORE_DISCONNECTED
                         ? "invalidate" : "reconsider",
                     path[i]->nHeight);
            block_free(&blk);
            complete = false;
            break;
        }

        boot_restore_invalidate_block_coins(svc, &blk);

        if (action == PROCESS_BLOCK_MEMPOOL_REMOVE_RECONNECTED) {
            boot_restore_remove_reconnected(svc, &blk, path[i], out);
            if (!boot_restore_wallet_reconcile(svc, path[i])) {
                LOG_WARN("validation",
                         "reconsider: wallet reconciliation failed h=%d",
                         path[i]->nHeight);
                complete = false;
            }
            block_free(&blk);
            continue;
        }

        bool *keep_pending;
        if (!boot_restore_alloc_keep_pending(&blk, &keep_pending)) {
            block_free(&blk);
            complete = false;
            break;
        }

        for (size_t t = 0; t < blk.num_vtx; t++) {
            struct transaction *tx = &blk.vtx[t];
            char detail[96] = {0};
            enum mempool_accept_result ar = MEMPOOL_ACCEPT_OK;
            if (!boot_restore_accept_tx(svc, tx, &keep_pending[t], out,
                                        detail, sizeof(detail), &ar))
                continue;

            char txid[65];
            uint256_get_hex(&tx->hash, txid);
            complete = false;
            LOG_WARN("validation",
                     "invalidate: disconnected tx mempool restore refused "
                     "h=%d txid=%s result=%d detail=%s",
                     path[i]->nHeight, txid, (int)ar,
                     detail[0] ? detail : "none");
        }


        for (size_t t = 0; t < blk.num_vtx; t++) {
            if (!boot_restore_wallet_retract_tx(svc, &blk.vtx[t],
                                                keep_pending[t])) {
                LOG_WARN("validation",
                         "invalidate: live wallet retract failed h=%d tx=%zu",
                         path[i]->nHeight, t);
                complete = false;
            }
        }
        if (!boot_restore_node_db_retract(svc, &blk, keep_pending)) {
            LOG_WARN("validation",
                     "invalidate: durable wallet retract failed h=%d",
                     path[i]->nHeight);
            complete = false;
        }
        free(keep_pending);
        block_free(&blk);
    }
    boot_restore_rewind_wallet(svc, action, first_disconnected);
    free(path);
    return complete;
}

static enum process_block_tip_publish_result
boot_process_block_result_from_csr(enum csr_result rc)
{
    switch (rc) {
    case CSR_OK:
        return PROCESS_BLOCK_TIP_PUBLISH_OK;
    case CSR_REJECTED_NOT_INITIALIZED:
        return PROCESS_BLOCK_TIP_PUBLISH_REJECTED_NOT_INITIALIZED;
    case CSR_REJECTED_DB_BUSY:
        return PROCESS_BLOCK_TIP_PUBLISH_REJECTED_DB_BUSY;
    case CSR_REJECTED_PERSIST:
        return PROCESS_BLOCK_TIP_PUBLISH_REJECTED_PERSIST;
    default:
        return PROCESS_BLOCK_TIP_PUBLISH_REJECTED;
    }
}

static enum process_block_tip_publish_result
boot_process_block_result_from_cec(enum chain_evidence_controller_result rc)
{
    switch (rc) {
    case CEC_OK:
        return PROCESS_BLOCK_TIP_PUBLISH_OK;
    case CEC_REJECTED_PERSIST:
        return PROCESS_BLOCK_TIP_PUBLISH_REJECTED_PERSIST;
    default:
        return PROCESS_BLOCK_TIP_PUBLISH_REJECTED;
    }
}

static struct chain_evidence_record boot_process_block_evidence(
    const struct process_block_tip_evidence *src)
{
    struct chain_evidence_record out = {0};

    if (!src)
        return out;
    out.header_ancestry_linked = src->header_ancestry_linked;
    out.chainwork_recomputed = src->chainwork_recomputed;
    out.nakamoto_selected_best_work = src->nakamoto_selected_best_work;
    out.block_bytes_hash_checked = src->block_bytes_hash_checked;
    out.utxo_sha3_verified = src->utxo_sha3_verified;
    out.mmb_flyclient_proof_verified = src->mmb_flyclient_proof_verified;
    out.chunk_hash_coverage_verified = src->chunk_hash_coverage_verified;
    out.full_validation_complete = src->full_validation_complete;
    return out;
}

static bool boot_commit_tip_use_evidence(
    const struct boot_svc_ctx *svc,
    const struct process_block_tip_evidence *verified)
{
    return verified && svc && svc->node_db && csr_instance()->initialized;
}

static enum chain_evidence_controller_result boot_commit_tip_promote(
    struct boot_svc_ctx *svc,
    struct block_index *new_tip,
    const char *reason,
    bool update_header_tip,
    const struct process_block_tip_evidence *verified)
{
    struct chain_evidence_controller authority;
    struct chain_evidence_controller_tip_request req = {
        .new_tip = new_tip,
        .utxo_max_height = new_tip->nHeight,
        .update_header_tip = update_header_tip,
        .reason = reason ? reason : "process_block.commit_tip",
        .verified = boot_process_block_evidence(verified),
    };
    chain_evidence_controller_init(&authority, svc->node_db,
                                   csr_instance());
    return chain_evidence_controller_promote_tip(&authority, &req);
}

static struct chain_state_rollback_authorization
boot_commit_tip_rollback_auth(const struct main_state *ms,
                              const struct block_index *new_tip,
                              const char *reason)
{
    struct chain_state_rollback_authorization rollback_auth = {
        .source = CSR_ROLLBACK_SOURCE_VALIDATION,
        .decision = POLICY_ALLOW,
        .from_height = ms ? active_chain_height(&ms->chain_active) : -1,
        .to_height = new_tip->nHeight,
        .max_depth = INT64_MAX,
        .evidence_class = "validation_path_vetted",
        .reason = reason ? reason : "process_block.commit_tip",
    };
    return rollback_auth;
}

#ifdef ZCL_TESTING
static void boot_commit_tip_uninit_fallback(
    struct main_state *ms,
    struct coins_view_cache *coins_tip,
    struct block_index *new_tip,
    const char *reason,
    bool update_header_tip)
{
    (void)chain_set_active_tip(ms, new_tip, TIP_FROM_CONNECT,
                               reason ? reason : "csr_uninit_fallback");
    if (update_header_tip)
        ms->pindex_best_header = new_tip;
    if (coins_tip)
        coins_view_cache_set_best_block(coins_tip, new_tip->phashBlock);
}
#endif

static void boot_commit_tip_record_blocker(enum csr_result rc)
{
    if (rc == CSR_REJECTED_DB_BUSY)
        mirror_consensus_record_blocker("db-writer-busy");
    else if (rc == CSR_REJECTED_PERSIST)
        mirror_consensus_record_blocker("csr-persist-failed");
}

static enum process_block_tip_publish_result boot_process_block_commit_tip(
    void *ctx,
    struct main_state *ms,
    struct coins_view_cache *coins_tip,
    struct block_index *new_tip,
    const char *reason,
    bool update_header_tip,
    bool persist_coins_best,
    const struct process_block_tip_evidence *verified)
{
    struct boot_svc_ctx *svc = ctx;

#ifndef ZCL_TESTING
    (void)coins_tip;
#endif
    if (!new_tip || !new_tip->phashBlock)
        return PROCESS_BLOCK_TIP_PUBLISH_REJECTED;

    if (boot_commit_tip_use_evidence(svc, verified)) {
        enum chain_evidence_controller_result er =
            boot_commit_tip_promote(svc, new_tip, reason, update_header_tip,
                                    verified);
        if (er == CEC_OK)
            return PROCESS_BLOCK_TIP_PUBLISH_OK;
        LOG_WARN("validation",
                 "evidence controller rejected process-block tip (%s) h=%d reason=%s",
                 chain_evidence_controller_result_name(er),
                 new_tip->nHeight, reason ? reason : "");
        return boot_process_block_result_from_cec(er);
    }

    struct chain_state_rollback_authorization rollback_auth =
        boot_commit_tip_rollback_auth(ms, new_tip, reason);
    struct chain_state_commit commit = {
        .new_tip = new_tip,
        .new_coins_best = *new_tip->phashBlock,
        .expected_utxo_count = 0,
        .update_header_tip = update_header_tip,
        .persist_coins_best = persist_coins_best,
        .rollback_auth = &rollback_auth,
        .wallet_scan_height = -1,
        .reason = reason,
    };
    enum csr_result rc = csr_commit_tip(csr_instance(), &commit);

#ifdef ZCL_TESTING
    if (rc == CSR_REJECTED_NOT_INITIALIZED && ms) {
        boot_commit_tip_uninit_fallback(ms, coins_tip, new_tip, reason,
                                        update_header_tip);
        return PROCESS_BLOCK_TIP_PUBLISH_OK;
    }
#endif
    if (rc != CSR_OK) {
        LOG_WARN("validation", "csr rejected process-block tip (%s) h=%d reason=%s",
                 csr_result_name(rc), new_tip->nHeight, reason ? reason : "");
        boot_commit_tip_record_blocker(rc);
    }
    return boot_process_block_result_from_csr(rc);
}

static enum process_block_tip_publish_result boot_process_block_clear_tip(
    void *ctx,
    struct main_state *ms,
    const char *reason)
{
    (void)ctx;
    struct chain_state_rollback_authorization rollback_auth = {
        .source = CSR_ROLLBACK_SOURCE_VALIDATION,
        .decision = POLICY_ALLOW,
        .from_height = ms ? active_chain_height(&ms->chain_active) : -1,
        .to_height = -1,
        .max_depth = INT64_MAX,
        .evidence_class = "validation_disconnect_complete",
        .reason = reason ? reason : "disconnect_past_genesis",
    };
    struct chain_state_clear_commit clear = {
        .rollback_auth = &rollback_auth,
        .reason = reason ? reason : "disconnect_past_genesis",
    };
    enum csr_result rc = csr_clear_active_tip(csr_instance(), &clear);

#ifdef ZCL_TESTING
    if (rc == CSR_REJECTED_NOT_INITIALIZED && ms) {
        (void)chain_set_active_tip(ms, NULL, TIP_FROM_DISCONNECT,
                                   reason ? reason : "disconnect_past_genesis");
        return PROCESS_BLOCK_TIP_PUBLISH_OK;
    }
#endif
    if (rc != CSR_OK)
        LOG_WARN("validation", "csr rejected process-block tip clear (%s)",
                 csr_result_name(rc));
    return boot_process_block_result_from_csr(rc);
}

/* Wire the tip-publication hooks + the gap-fill kick into the validation
 * engine. Called once from app_init_services; the teardown counterpart
 * (process_block_set_tip_publication_hooks(NULL, NULL, NULL)) stays inline in
 * app_shutdown_svc since it references no moved symbol. */
void boot_register_process_block_hooks(struct boot_svc_ctx *svc)
{
    process_block_set_gap_fill_kick(boot_gap_fill_kick, svc);
    process_block_set_mempool_restore_hook(
        boot_process_block_restore_mempool, svc);
    process_block_set_tip_publication_hooks(boot_process_block_commit_tip,
                                            boot_process_block_clear_tip,
                                            svc);
}
