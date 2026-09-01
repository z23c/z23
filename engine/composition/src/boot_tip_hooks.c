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

static bool boot_process_block_restore_mempool(
    void *ctx,
    struct block_index *first_disconnected,
    struct block_index *old_active_tip,
    enum process_block_mempool_segment_action action,
    struct process_block_mempool_restore_result *out)
{
    struct boot_svc_ctx *svc = ctx;
    if (out)
        memset(out, 0, sizeof(*out));
    if (!svc || !svc->mempool || !svc->coins_tip || !svc->state ||
        !svc->params || !svc->datadir || !first_disconnected ||
        !old_active_tip || !first_disconnected->phashBlock ||
        old_active_tip->nHeight < first_disconnected->nHeight ||
        (action != PROCESS_BLOCK_MEMPOOL_RESTORE_DISCONNECTED &&
         action != PROCESS_BLOCK_MEMPOOL_REMOVE_RECONNECTED))
        return false;

    int depth = old_active_tip->nHeight - first_disconnected->nHeight + 1;
    struct block_index **path = zcl_malloc(
        (size_t)depth * sizeof(*path), "invalidate_mempool_path");
    if (!path)
        return false;

    struct block_index *walk = old_active_tip;
    for (int i = depth - 1; i >= 0; i--) {
        if (!walk || walk->nHeight != first_disconnected->nHeight + i) {
            free(path);
            return false;
        }
        path[i] = walk;
        walk = walk->pprev;
    }
    if (!path[0]->phashBlock ||
        !uint256_eq(path[0]->phashBlock, first_disconnected->phashBlock)) {
        free(path);
        return false;
    }

    bool complete = true;
    char net_datadir[2048] = {0};
    GetDataDir(true, net_datadir, sizeof(net_datadir));
    const char *body_datadir = net_datadir[0] ? net_datadir : svc->datadir;
    for (int i = 0; i < depth; i++) {
        /* chain[] may name a bodiless snapshot/header twin.  The block map is
         * the durable body/status owner for this exact hash; resolve through
         * it before pread, while retaining the active path only as the segment
         * identity proof above. */
        struct block_index *body_index = path[i]->phashBlock
            ? block_map_find(&svc->state->map_block_index,
                             path[i]->phashBlock)
            : NULL;
        if (!body_index)
            body_index = path[i];
        struct block blk;
        block_init(&blk);
        if (!read_block_from_disk_index_pread(
                &blk, body_index, body_datadir)) {
            LOG_WARN("validation",
                     "%s: cannot read block h=%d for mempool reconciliation",
                     action == PROCESS_BLOCK_MEMPOOL_RESTORE_DISCONNECTED
                         ? "invalidate" : "reconsider",
                     path[i]->nHeight);
            block_free(&blk);
            complete = false;
            break;
        }
        if (out)
            out->blocks_read++;

        /* The reducer inverse changed these exact coins without passing
         * through coins_view_cache::batch_write.  Drop stale cache entries
         * before the ordinary admission gate proves inputs against coins_kv. */
        for (size_t t = 0; t < blk.num_vtx; t++) {
            struct transaction *tx = &blk.vtx[t];
            (void)coins_view_cache_invalidate(svc->coins_tip, &tx->hash);
            if (!transaction_is_coinbase(tx)) {
                for (size_t v = 0; v < tx->num_vin; v++)
                    (void)coins_view_cache_invalidate(
                        svc->coins_tip, &tx->vin[v].prevout.hash);
            }
        }

        if (action == PROCESS_BLOCK_MEMPOOL_REMOVE_RECONNECTED) {
            for (size_t t = 0; t < blk.num_vtx; t++) {
                struct transaction *tx = &blk.vtx[t];
                if (transaction_is_coinbase(tx))
                    continue;
                if (out) {
                    out->txs_attempted++;
                    if (tx_mempool_exists(svc->mempool, &tx->hash))
                        out->txs_removed++;
                }
            }
            tx_mempool_remove_for_block(svc->mempool, blk.vtx, blk.num_vtx,
                                         (unsigned int)path[i]->nHeight);
            if (svc->wallet && !tip_finalize_run_wallet_reconcile(path[i])) {
                LOG_WARN("validation",
                         "reconsider: wallet reconciliation failed h=%d",
                         path[i]->nHeight);
                complete = false;
            }
            block_free(&blk);
            continue;
        }

        bool *keep_pending = zcl_calloc(
            blk.num_vtx, sizeof(*keep_pending),
            "invalidate wallet pending decisions");
        if (blk.num_vtx > 0 && !keep_pending) {
            block_free(&blk);
            complete = false;
            break;
        }

        for (size_t t = 0; t < blk.num_vtx; t++) {
            struct transaction *tx = &blk.vtx[t];
            if (transaction_is_coinbase(tx))
                continue;
            if (out)
                out->txs_attempted++;
            char detail[96] = {0};
            enum mempool_accept_result ar = accept_to_mempool_detailed(
                svc->mempool, svc->coins_tip, svc->state, svc->params, tx,
                detail, sizeof(detail));
            if (ar == MEMPOOL_ACCEPT_OK || ar == MEMPOOL_ACCEPT_DUPLICATE) {
                keep_pending[t] = true;
                if (out)
                    out->txs_accepted++;
                if (svc->connman) {
                    connman_relay_transaction(svc->connman, &tx->hash);
                    if (out)
                        out->txs_relayed++;
                }
                continue;
            }

            char txid[65];
            uint256_get_hex(&tx->hash, txid);
            if (out)
                out->txs_rejected++;
            complete = false;
            LOG_WARN("validation",
                     "invalidate: disconnected tx mempool restore refused "
                     "h=%d txid=%s result=%d detail=%s",
                     path[i]->nHeight, txid, (int)ar,
                     detail[0] ? detail : "none");
        }


        if (svc->wallet) {
            for (size_t t = 0; t < blk.num_vtx; t++) {
                if (!wallet_disconnect_transaction(
                        svc->wallet, &blk.vtx[t], keep_pending[t])) {
                    LOG_WARN("validation",
                             "invalidate: live wallet retract failed h=%d tx=%zu",
                             path[i]->nHeight, t);
                    complete = false;
                }
            }
        }
        if (svc->node_db &&
            !node_db_sync_wallet_disconnect_block(
                svc->node_db, &blk, keep_pending)) {
            LOG_WARN("validation",
                     "invalidate: durable wallet retract failed h=%d",
                     path[i]->nHeight);
            complete = false;
        }
        free(keep_pending);
        block_free(&blk);
    }
    if (action == PROCESS_BLOCK_MEMPOOL_RESTORE_DISCONNECTED && svc->wallet)
        (void)wallet_rewind_confirmations(
            svc->wallet, first_disconnected->nHeight - 1);
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

    if (verified && svc && svc->node_db && csr_instance()->initialized) {
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
        enum chain_evidence_controller_result er =
            chain_evidence_controller_promote_tip(&authority, &req);
        if (er == CEC_OK)
            return PROCESS_BLOCK_TIP_PUBLISH_OK;
        LOG_WARN("validation",
                 "evidence controller rejected process-block tip (%s) h=%d reason=%s",
                 chain_evidence_controller_result_name(er),
                 new_tip->nHeight, reason ? reason : "");
        return boot_process_block_result_from_cec(er);
    }

    struct chain_state_rollback_authorization rollback_auth = {
        .source = CSR_ROLLBACK_SOURCE_VALIDATION,
        .decision = POLICY_ALLOW,
        .from_height = ms ? active_chain_height(&ms->chain_active) : -1,
        .to_height = new_tip->nHeight,
        .max_depth = INT64_MAX,
        .evidence_class = "validation_path_vetted",
        .reason = reason ? reason : "process_block.commit_tip",
    };
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
        (void)chain_set_active_tip(ms, new_tip, TIP_FROM_CONNECT,
                                   reason ? reason : "csr_uninit_fallback");
        if (update_header_tip)
            ms->pindex_best_header = new_tip;
        if (coins_tip)
            coins_view_cache_set_best_block(coins_tip, new_tip->phashBlock);
        return PROCESS_BLOCK_TIP_PUBLISH_OK;
    }
#endif
    if (rc != CSR_OK) {
        LOG_WARN("validation", "csr rejected process-block tip (%s) h=%d reason=%s",
                 csr_result_name(rc), new_tip->nHeight, reason ? reason : "");
        if (rc == CSR_REJECTED_DB_BUSY)
            mirror_consensus_record_blocker("db-writer-busy");
        else if (rc == CSR_REJECTED_PERSIST)
            mirror_consensus_record_blocker("csr-persist-failed");
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
