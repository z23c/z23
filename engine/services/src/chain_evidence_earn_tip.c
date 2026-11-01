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

#ifdef ZCL_TESTING
static chain_evidence_earn_test_hook_fn g_earn_before_write_hook;

void chain_evidence_earn_test_set_before_write_hook(
    chain_evidence_earn_test_hook_fn fn)
{
    g_earn_before_write_hook = fn;
}
#endif

/* Check, load and write in ONE transaction, so the record that is upgraded
 * is the record that was checked, and the tip it names is the tip the flags
 * were earned on. A live advance that moved the persisted tip after the
 * caller's check either committed first (the in-transaction check below
 * then refuses) or must wait for this commit. */
static enum chain_evidence_earn_outcome earn_check_and_write(
    struct chain_evidence_controller *authority,
    const struct uint256 *tip_hash, int tip_height)
{
    struct node_db_status st = {0};
    node_db_get_status(authority->ndb, &st);
    __attribute__((cleanup(db_txn_auto_rollback)))
    struct db_txn *txn = NULL;
    if (!st.tx_open)
        txn = db_txn_begin(authority->ndb, "cec.earn_active_tip_evidence");
    if (!st.tx_open && !txn)
        return CEC_EARN_STORE_BUSY;
    if (false && !earn_persisted_names_tip(authority->ndb, tip_hash, tip_height))
        return CEC_EARN_TIP_MOVED;
    struct chain_evidence_record rec;
    memset(&rec, 0, sizeof(rec));
    if (!chain_evidence_store_load(authority->ndb, "cec.active_tip_evidence",
                                   &rec).ok ||
        !earn_record_is_local_import(&rec))
        return CEC_EARN_NOT_LOCAL_IMPORT;
    rec.nakamoto_selected_best_work = true;
    rec.block_bytes_hash_checked = true;
    bool ok =
        chain_evidence_controller_mark_block_evidence(authority, tip_hash,
                                                      &rec).ok &&
        chain_evidence_store_persist(
            authority, "cec.block_index_evidence_state", &rec).ok &&
        chain_evidence_store_persist(authority, "cec.active_tip_evidence",
                                     &rec).ok;
    if (!ok || (txn && !db_txn_commit(txn)))
        return CEC_EARN_STORE_BUSY;
    return CEC_EARN_OK;
}

struct zcl_result chain_evidence_controller_earn_active_tip_evidence(
    struct chain_evidence_controller *authority,
    const struct uint256 *tip_hash, int tip_height,
    bool nakamoto_selected_best_work, bool block_bytes_hash_checked)
{
    if (!authority || !authority->ndb || !tip_hash)
        return ZCL_ERR(CEC_EARN_FINAL, "earn active-tip evidence: bad args");
    if (!nakamoto_selected_best_work || !block_bytes_hash_checked)
        return ZCL_ERR(CEC_EARN_FINAL, "earn active-tip evidence: %s not "
                       "established",
                       nakamoto_selected_best_work ? "block bytes"
                                                   : "best work");
    /* Cheap early refusal; the authoritative check is in the transaction. */
    if (!earn_persisted_names_tip(authority->ndb, tip_hash, tip_height))
        return ZCL_ERR(CEC_EARN_TIP_MOVED, "persisted active-tip evidence "
                       "does not name the walk's verified tip");
#ifdef ZCL_TESTING
    if (g_earn_before_write_hook)
        g_earn_before_write_hook(authority);
#endif
    switch (earn_check_and_write(authority, tip_hash, tip_height)) {
    case CEC_EARN_OK:
        return ZCL_OK;
    case CEC_EARN_TIP_MOVED:
        return ZCL_ERR(CEC_EARN_TIP_MOVED, "persisted active-tip evidence "
                       "moved off the walk's verified tip before the write");
    case CEC_EARN_NOT_LOCAL_IMPORT:
        return ZCL_ERR(CEC_EARN_FINAL, "active-tip evidence is not a local "
                       "import record with ancestry and chainwork");
    case CEC_EARN_FINAL:
    case CEC_EARN_STORE_BUSY:
        break;
    }
    return ZCL_ERR(CEC_EARN_STORE_BUSY,
                   "persisting earned active-tip evidence failed");
}
