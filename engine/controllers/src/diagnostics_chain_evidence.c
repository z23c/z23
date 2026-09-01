/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Native chain-evidence diagnostics.  The bounded health_reason key omits the
 * unrelated explorer projection scan used by the full operator report. */
// one-result-type-ok:diagnostic-dumper-bool

#include "controllers/diagnostics_internal.h"
#include "config/runtime.h"
#include "core/uint256.h"
#include "json/json.h"
#include "services/chain_evidence_authority_service.h"
#include "services/chain_state_service.h"
#include "validation/contextual_check_tx.h"

#include <stdint.h>
#include <string.h>

static void push_evidence_record_json(struct json_value *out, const char *key,
                                      const struct chain_evidence_record *e)
{
    struct json_value obj = {0};
    json_set_object(&obj);
    json_push_kv_str(&obj, "source_class",
                     chain_evidence_source_class_name(
                         e ? e->source_class : CEC_SOURCE_CLASS_UNKNOWN));
    json_push_kv_str(&obj, "publish_state",
                     chain_evidence_publish_state_name(
                         e ? e->publish_state
                           : CEC_PUBLISH_NOT_PUBLISHABLE));
    json_push_kv_bool(&obj, "header_ancestry_linked",
                      e && e->header_ancestry_linked);
    json_push_kv_bool(&obj, "chainwork_recomputed",
                      e && e->chainwork_recomputed);
    json_push_kv_bool(&obj, "nakamoto_selected_best_work",
                      e && e->nakamoto_selected_best_work);
    json_push_kv_bool(&obj, "block_bytes_hash_checked",
                      e && e->block_bytes_hash_checked);
    json_push_kv_bool(&obj, "utxo_sha3_verified",
                      e && e->utxo_sha3_verified);
    json_push_kv_bool(&obj, "mmb_flyclient_proof_verified",
                      e && e->mmb_flyclient_proof_verified);
    json_push_kv_bool(&obj, "chunk_hash_coverage_verified",
                      e && e->chunk_hash_coverage_verified);
    json_push_kv_bool(&obj, "full_validation_complete",
                      e && e->full_validation_complete);
    json_push_kv(out, key, &obj);
    json_free(&obj);
}

static void push_hash_json(struct json_value *out, const char *key,
                           bool present, const struct uint256 *hash)
{
    char hex[65] = {0};
    if (present && hash)
        uint256_get_hex(hash, hex);
    json_push_kv_str(out, key, present ? hex : "");
}

bool diag_chain_evidence_dump_state_json(struct json_value *out,
                                         const char *key)
{
    if (!out)
        return false;
    struct chain_evidence_controller authority;
    struct chain_evidence_controller_view view;

    json_set_object(out);
    chain_evidence_controller_init(&authority, app_runtime_node_db(),
                                   csr_instance());
    (void)chain_evidence_drain_pending_tip(&authority);
    chain_evidence_controller_snapshot(&authority, &view);

    /* Same evidence authority as the full report; only unrelated projection
     * serialization and the explorer-history scan are omitted. */
    if (key && strcmp(key, "health_reason") == 0) {
        json_push_kv_str(out, "health_reason", view.health_reason);
        json_push_kv_str(out, "contradiction_reason",
                         view.contradiction_reason);
        json_push_kv_bool(out, "missing_active_tip_evidence",
                          view.missing_active_tip_evidence);
        json_push_kv_bool(out, "publish_state_not_local",
                          view.publish_state_not_local);
        json_push_kv_bool(out, "active_tip_hash_mismatch",
                          view.active_tip_hash_mismatch);
        json_push_kv_bool(out, "csr_cursor_mismatch",
                          view.csr_cursor_mismatch);
        return true;
    }

    json_push_kv_str(out, "sync_state",
                     chain_evidence_controller_state_name(view.state));
    json_push_kv_str(out, "publish_state",
                     chain_evidence_publish_state_name(view.publish_state));
    json_push_kv_str(out, "active_tip_source_class",
                     chain_evidence_source_class_name(
                         view.active_tip_source_class));
    json_push_kv_int(out, "active_tip", (int64_t)view.active_tip_height);
    json_push_kv_int(out, "header_tip", (int64_t)view.header_tip_height);
    json_push_kv_int(out, "persisted_active_tip",
                     (int64_t)view.persisted_active_tip_height);
    json_push_kv_int(out, "snapshot_anchor",
                     (int64_t)view.snapshot_anchor_height);
    json_push_kv_int(out, "utxo_max_height", (int64_t)view.utxo_max_height);
    json_push_kv_int(out, "coins_best_block_height",
                     (int64_t)view.coins_best_block_height);
    json_push_kv_int(out, "csr_sqlite_max_height",
                     (int64_t)view.sqlite_max_height);
    push_hash_json(out, "active_tip_hash", view.has_active_tip_hash,
                   &view.active_tip_hash);
    push_hash_json(out, "header_tip_hash", view.has_header_tip_hash,
                   &view.header_tip_hash);
    push_hash_json(out, "persisted_active_tip_hash",
                   view.has_persisted_active_tip_hash,
                   &view.persisted_active_tip_hash);
    push_hash_json(out, "coins_best_block_hash",
                   view.has_coins_best_block_hash,
                   &view.coins_best_block_hash);
    json_push_kv_bool(out, "missing_active_tip_evidence",
                      view.missing_active_tip_evidence);
    json_push_kv_bool(out, "publish_state_not_local",
                      view.publish_state_not_local);
    json_push_kv_bool(out, "active_tip_hash_mismatch",
                      view.active_tip_hash_mismatch);
    json_push_kv_bool(out, "csr_cursor_mismatch", view.csr_cursor_mismatch);
    json_push_kv_bool(out, "repaired_active_tip_evidence",
                      view.repaired_active_tip_evidence);
    json_push_kv_str(out, "health_reason", view.health_reason);
    push_evidence_record_json(out, "block_index_evidence_state",
                              &view.block_index_evidence_state);
    push_evidence_record_json(out, "active_tip_evidence",
                              &view.active_tip_evidence);
    push_evidence_record_json(out, "snapshot_evidence",
                              &view.snapshot_evidence);
    push_evidence_record_json(out, "header_chain_evidence",
                              &view.header_chain_evidence);
    json_push_kv_int(out, "deferred_proof_validation_below",
                     (int64_t)g_deferred_proof_validation_below_height);
    json_push_kv_int(out, "background_validation_height",
                     (int64_t)view.background_validation_height);
    json_push_kv_str(out, "contradiction_reason", view.contradiction_reason);
    diag_push_explorer_index_state_json(out, app_runtime_node_db());
    return true;
}
