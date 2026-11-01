/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Earned active-tip evidence: the one writer that upgrades the persisted
 * LOCAL_IMPORT active-tip record (ancestry + chainwork only, as boot
 * reconcile and the live reducer follow leave it) with the two flags a
 * genesis walk can actually establish for one exact tip hash.
 *
 * The caller (bg_validation_authority) owns the proofs: it has verified that
 * exact block through the walk (bytes) and ran the core best-work predicate
 * on it (nakamoto). This function only refuses to write them anywhere but
 * onto the persisted record that names that same tip by hash AND height, so
 * a record the live follow has not yet moved to the tip is never upgraded
 * on the strength of a different block. All three evidence keys change in
 * one transaction. */

#include "services/chain_evidence_authority_service.h"
#include "services/chain_evidence_persistence_service.h"

#include "models/database.h"
#include "models/db_txn.h"

#include <string.h>

static bool earn_persisted_names_tip(struct node_db *ndb,
                                     const struct uint256 *tip_hash,
                                     int tip_height)
{
    uint8_t persisted[32];
    size_t len = 0;
    int64_t height = -1;
    return node_db_state_get(ndb, "cec.active_tip_hash", persisted,
                             sizeof(persisted), &len) &&
           len == sizeof(persisted) &&
           memcmp(persisted, tip_hash->data, sizeof(persisted)) == 0 &&
           node_db_state_get_int(ndb, "cec.active_tip_height", &height) &&
           height == tip_height;
}

static bool earn_record_is_local_import(
    const struct chain_evidence_record *rec)
{
    return rec->source_class == CEC_SOURCE_CLASS_LOCAL_IMPORT &&
           rec->publish_state == CEC_PUBLISH_LOCAL_EVIDENCE &&
           rec->header_ancestry_linked && rec->chainwork_recomputed;
}

static bool earn_persist_all(struct chain_evidence_controller *authority,
                             const struct uint256 *tip_hash,
                             const struct chain_evidence_record *rec)
{
    struct node_db_status st = {0};
    node_db_get_status(authority->ndb, &st);
    __attribute__((cleanup(db_txn_auto_rollback)))
    struct db_txn *txn = NULL;
    if (!st.tx_open)
        txn = db_txn_begin(authority->ndb, "cec.earn_active_tip_evidence");
    if (!st.tx_open && !txn)
        return false;
    bool ok =
        chain_evidence_controller_mark_block_evidence(authority, tip_hash,
                                                      rec).ok &&
        chain_evidence_store_persist(
            authority, "cec.block_index_evidence_state", rec).ok &&
        chain_evidence_store_persist(authority, "cec.active_tip_evidence",
                                     rec).ok;
    return ok && (!txn || db_txn_commit(txn));
}

struct zcl_result chain_evidence_controller_earn_active_tip_evidence(
    struct chain_evidence_controller *authority,
    const struct uint256 *tip_hash, int tip_height,
    bool nakamoto_selected_best_work, bool block_bytes_hash_checked)
{
    struct chain_evidence_record rec;
    if (!authority || !authority->ndb || !tip_hash)
        return ZCL_ERR(-1, "earn active-tip evidence: bad args");
    if (!nakamoto_selected_best_work || !block_bytes_hash_checked)
        return ZCL_ERR(-1, "earn active-tip evidence: %s not established",
                       nakamoto_selected_best_work ? "block bytes"
                                                   : "best work");
    if (!earn_persisted_names_tip(authority->ndb, tip_hash, tip_height))
        return ZCL_ERR(-1, "persisted active-tip evidence does not name "
                           "the walk's verified tip");
    memset(&rec, 0, sizeof(rec));
    if (!chain_evidence_store_load(authority->ndb, "cec.active_tip_evidence",
                                   &rec).ok ||
        !earn_record_is_local_import(&rec))
        return ZCL_ERR(-1, "active-tip evidence is not a local import "
                           "record with ancestry and chainwork");
    rec.nakamoto_selected_best_work = true;
    rec.block_bytes_hash_checked = true;
    if (!earn_persist_all(authority, tip_hash, &rec))
        return ZCL_ERR(-1, "persisting earned active-tip evidence failed");
    return ZCL_OK;
}
