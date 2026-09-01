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

#include <string.h>

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
    const char *load_result = "unknown";
    switch (ckpt.last_load_result) {
    case SAPLING_CKPT_LOAD_NONE:      load_result = "none"; break;
    case SAPLING_CKPT_LOAD_ABSENT:    load_result = "absent"; break;
    case SAPLING_CKPT_LOAD_VERIFIED:  load_result = "loaded_verified"; break;
    case SAPLING_CKPT_LOAD_DISCARDED: load_result = "discarded"; break;
    default: break;
    }
    (void)json_push_kv_str(&sapling, "checkpoint_load_result", load_result);
    (void)json_push_kv_int(&sapling, "checkpoint_last_write_height",
                           ckpt.last_write_height);
    (void)json_push_kv_int(&sapling, "checkpoint_write_failures",
                           ckpt.write_fails);
    bool checkpoint_enabled = ckpt.path[0] != '\0';
    (void)json_push_kv_bool(&sapling, "checkpoint_enabled",
                            checkpoint_enabled);
    (void)json_push_kv_bool(
        &sapling, "checkpoint_healthy",
        checkpoint_enabled && ckpt.write_fails == 0 &&
        (ckpt.last_load_result == SAPLING_CKPT_LOAD_VERIFIED ||
         ckpt.last_write_height >= 0));
    struct wallet_rpc_context *ctx = wallet_ctx();
    int tip_height = reducer_frontier_external_tip_height();
    struct db_sapling_witness_summary ws;
    bool witness_known = ctx && ctx->node_db &&
        db_sapling_note_witness_summary(ctx->node_db, tip_height, &ws);
    bool witness_ready = witness_known &&
        (ws.local_unspent_notes == 0 ||
         ws.ready_notes == ws.local_unspent_notes);
    const char *witness_state = !witness_known ? "unavailable" :
        ws.local_unspent_notes == 0 ? "not_applicable" :
        witness_ready ? "ready" :
        ws.missing_notes > 0 ? "rescan_required_missing" :
        "rescan_required_stale";
    (void)json_push_kv_bool(&sapling, "witness_ready", witness_ready);
    (void)json_push_kv_str(&sapling, "witness_state", witness_state);
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
