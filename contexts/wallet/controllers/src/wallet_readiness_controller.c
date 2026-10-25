/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Safe Sapling spend-readiness projection for getwalletinfo.  This reports
 * only scalar runtime posture.  It never returns a parameter path, note,
 * witness, address, or key.
 */

#include "controllers/wallet_controller_internal.h"

#include "jobs/reducer_frontier.h"
#include "sapling/sapling_prover.h"
#include "validation/process_block.h"

#include <stdio.h>
#include <string.h>

static const char *wallet_readiness_ckpt_load_result_name(
    const struct sapling_ckpt_stats *ckpt)
{
    const char *name = "unknown";
    switch (ckpt->last_load_result) {
    case SAPLING_CKPT_LOAD_NONE:      name = "none"; break;
    case SAPLING_CKPT_LOAD_ABSENT:    name = "absent"; break;
    case SAPLING_CKPT_LOAD_VERIFIED:  name = "loaded_verified"; break;
    case SAPLING_CKPT_LOAD_DISCARDED: name = "discarded"; break;
    default: break;
    }
    return name;
}

static bool wallet_readiness_checkpoint_healthy(
    bool checkpoint_enabled, const struct sapling_ckpt_stats *ckpt)
{
    return checkpoint_enabled && ckpt->write_fails == 0 &&
        (ckpt->last_load_result == SAPLING_CKPT_LOAD_VERIFIED ||
         ckpt->last_write_height >= 0);
}

static bool wallet_readiness_witness_summary_known(
    struct wallet_rpc_context *ctx, int tip_height,
    struct db_sapling_witness_summary *ws)
{
    return ctx && ctx->node_db &&
        db_sapling_note_witness_summary(ctx->node_db, tip_height, ws);
}

static const char *wallet_readiness_witness_state(
    bool witness_known, bool witness_ready,
    const struct db_sapling_witness_summary *ws)
{
    return !witness_known ? "unavailable" :
        ws->local_unspent_notes == 0 ? "not_applicable" :
        witness_ready ? "ready" :
        ws->missing_notes > 0 ? "rescan_required_missing" :
        "rescan_required_stale";
}

void wallet_readiness_append_sapling(struct json_value *result)
{
    if (!result)
        return;

    struct json_value sapling = {0};
    json_init(&sapling);
    json_set_object(&sapling);
    (void)json_push_kv_bool(&sapling, "prover_ready",
                            zclassic_sapling_prover_is_ready());
    (void)json_push_kv_str(&sapling, "prover_backend",
                           zclassic_sapling_prover_backend());
    (void)json_push_kv_str(&sapling, "prover_status",
                           zclassic_sapling_prover_status());

    struct sapling_ckpt_stats ckpt;
    memset(&ckpt, 0, sizeof(ckpt));
    sapling_ckpt_get_stats(&ckpt);
    (void)json_push_kv_str(&sapling, "checkpoint_load_result",
                           wallet_readiness_ckpt_load_result_name(&ckpt));
    (void)json_push_kv_int(&sapling, "checkpoint_last_write_height",
                           ckpt.last_write_height);
    (void)json_push_kv_int(&sapling, "checkpoint_write_failures",
                           ckpt.write_fails);
    bool checkpoint_enabled = ckpt.path[0] != '\0';
    (void)json_push_kv_bool(&sapling, "checkpoint_enabled",
                            checkpoint_enabled);
    (void)json_push_kv_bool(
        &sapling, "checkpoint_healthy",
        wallet_readiness_checkpoint_healthy(checkpoint_enabled, &ckpt));
    struct wallet_rpc_context *ctx = wallet_ctx();
    int tip_height = reducer_frontier_external_tip_height();
    struct db_sapling_witness_summary ws;
    bool witness_known =
        wallet_readiness_witness_summary_known(ctx, tip_height, &ws);
    bool witness_ready = witness_known &&
        (ws.local_unspent_notes == 0 ||
         ws.ready_notes == ws.local_unspent_notes);
    (void)json_push_kv_bool(&sapling, "witness_ready", witness_ready);
    (void)json_push_kv_str(
        &sapling, "witness_state",
        wallet_readiness_witness_state(witness_known, witness_ready, &ws));
    (void)json_push_kv_int(&sapling, "witness_tip_height", tip_height);
    (void)json_push_kv_int(&sapling, "local_unspent_notes",
                           witness_known ? ws.local_unspent_notes : 0);
    (void)json_push_kv_int(&sapling, "witness_ready_notes",
                           witness_known ? ws.ready_notes : 0);
    (void)json_push_kv_int(&sapling, "witness_missing_notes",
                           witness_known ? ws.missing_notes : 0);
    (void)json_push_kv_int(&sapling, "witness_stale_notes",
                           witness_known ? ws.stale_notes : 0);
    (void)json_push_kv(result, "sapling", &sapling);
    json_free(&sapling);
}


/* Scan coverage for getwalletinfo. A boot catch-up that could not read its
 * range leaves the wallet incomplete: coins in the unread blocks can be
 * missing from its balance until a later boot rescans them. */
void wallet_readiness_append_scan(struct json_value *result)
{
    struct wallet_rpc_context *ctx = wallet_ctx();
    if (!result || !ctx || !ctx->wallet)
        return;
    struct wallet *w = ctx->wallet;
    zcl_mutex_lock(&w->cs);
    struct wallet_scan_retry retry = w->scan_retry;
    int through = wallet_scanned_through_height(w);
    int depth_height = w->best_block_height;
    zcl_mutex_unlock(&w->cs);

    struct json_value scan = {0};
    json_init(&scan);
    json_set_object(&scan);
    (void)json_push_kv_str(&scan, "status",
                           retry.pending ? "incomplete" : "complete");
    (void)json_push_kv_int(&scan, "scanned_through", through);
    (void)json_push_kv_int(&scan, "depth_height", depth_height);
    if (retry.pending) {
        char warning[224];
        snprintf(warning, sizeof(warning),
                 "%s: blocks from %d were not all read; coins in them can be "
                 "missing until the next boot rescans from %d",
                 retry.blocker, retry.from, retry.from);
        (void)json_push_kv_str(&scan, "blocker", retry.blocker);
        (void)json_push_kv_int(&scan, "unread_from", retry.from);
        (void)json_push_kv_int(&scan, "since", retry.since);
        (void)json_push_kv_str(&scan, "warning", warning);
    }
    (void)json_push_kv(result, "scan", &scan);
    json_free(&scan);
}
