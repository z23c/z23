// one-result-type-ok:pure-completeness-predicate — the bool export has no
// fallible state; publication itself returns the canonical struct zcl_result.
/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * bg_validation_authority — the one bridge from the read-only historical
 * validation walker to CEC_FULLY_VALIDATED. The bridge is intentionally
 * narrower than BG_VALIDATION_COMPLETE: every body must have been readable,
 * every transparent script must have had undo data, the coins frontier must
 * equal the verified tip, and assisted state must retain complete snapshot
 * evidence. */

#include "services/bg_validation_authority.h"

#include "services/bg_validation_service.h"
#include "services/chain_evidence_authority_service.h"
#include "services/chain_state_service.h"
#include "event/event.h"
#include "jobs/reducer_frontier.h"
#include "models/database.h"
#include "storage/coins_kv.h"
#include "storage/progress_store.h"
#include "util/blocker.h"
#include "util/log_macros.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"

#include <sqlite3.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

bool bg_validation_authority_claim_is_complete(
    int verified_height, int chain_height, int coins_height,
    int64_t script_skips, bool coverage_complete)
{
    return coverage_complete && chain_height > 0 &&
           verified_height == chain_height &&
           coins_height == chain_height && script_skips == 0;
}

static struct zcl_result bgv_auth_refuse(const char *reason)
{
    struct blocker_record rec;
    if (blocker_init(&rec, "bg_validation.full_history_unproven", "bg_validation",
                     BLOCKER_DEPENDENCY, reason)) {
        if (blocker_set(&rec) == 0)
            event_emitf(EV_OPERATOR_NEEDED, 0,
                        "check=%s reason=%s",
                        "bg_validation.full_history_unproven", reason);
    }
    LOG_WARN("bg_validation", "[bg-valid] authority not published: %s",
             reason);
    return ZCL_ERR(-1, "%s", reason);
}

static bool bgv_auth_evidence_ready(
    const struct chain_evidence_controller_view *view, bool external_seeded,
    char reason[192])
{
    if (external_seeded) {
        if (view->snapshot_evidence_loaded &&
            chain_evidence_record_has_snapshot_required(
                &view->snapshot_evidence))
            return true;
        snprintf(reason, 192,
                 "assisted walk lacks complete root-bound snapshot evidence");
        return false;
    }

    if (view->snapshot_evidence_loaded) {
        snprintf(reason, 192,
                 "genesis walk still carries assisted snapshot evidence");
        return false;
    }
    if (!chain_evidence_record_has_block_index_required(
            &view->active_tip_evidence) ||
        (view->active_tip_source_class != CEC_SOURCE_CLASS_NATIVE_P2P &&
         view->active_tip_source_class != CEC_SOURCE_CLASS_LOCAL_IMPORT)) {
        snprintf(reason, 192,
                 "genesis walk lacks publishable local active-tip evidence");
        return false;
    }
    return true;
}

struct zcl_result bg_validation_authority_publish(
    struct bg_validation_service *svc, bool external_seeded,
    bool coverage_complete)
{
    if (!svc || !svc->ms || !svc->ndb || !svc->ndb->open || !svc->ndb->db)
        return bgv_auth_refuse("validation authority dependencies unavailable");

    int verified = atomic_load(&svc->progress.verified_height);
    int64_t skips = atomic_load(&svc->progress.script_verif_skipped_no_undo);
    int chain_height = -1;
    int32_t coins_height = -1;
    uint8_t root_bytes[32] = {0};
    sqlite3 *pdb = progress_store_db();
    if (!pdb)
        return bgv_auth_refuse("canonical coins store unavailable");

    chain_height = active_chain_height(&svc->ms->chain_active);
    if (!coverage_complete || skips != 0 || verified != chain_height) {
        char reason[192];
        snprintf(reason, sizeof(reason),
                 "incomplete walk verified=%d tip=%d skips=%lld coverage=%s",
                 verified, chain_height, (long long)skips,
                 coverage_complete ? "complete" : "gap");
        return bgv_auth_refuse(reason);
    }

    /* The reducer uses the same recursive process lock. Holding it across the
     * height samples and SHA3 scan freezes the coins frontier for one coherent
     * claim; this runs once per completed campaign, never on the hot path. */
    progress_store_tx_lock();
    chain_height = active_chain_height(&svc->ms->chain_active);
    bool coins_ok = reducer_frontier_derive_coins_best_now(
        &coins_height, NULL, NULL);
    bool root_ok = coins_ok && coins_height == chain_height &&
                   coins_kv_commitment(pdb, root_bytes) == 0;
    int chain_height_after = active_chain_height(&svc->ms->chain_active);
    progress_store_tx_unlock();

    if (!bg_validation_authority_claim_is_complete(
            verified, chain_height, coins_height, skips, true) ||
        chain_height_after != chain_height) {
        char reason[192];
        snprintf(reason, sizeof(reason),
                 "frontier moved during authority scan verified=%d tip=%d after=%d coins=%d skips=%lld",
                 verified, chain_height, chain_height_after, coins_height,
                 (long long)skips);
        return bgv_auth_refuse(reason);
    }
    if (!root_ok)
        return bgv_auth_refuse("authoritative coins commitment failed");

    struct chain_evidence_controller authority;
    struct chain_evidence_controller_view view;
    chain_evidence_controller_init(&authority, svc->ndb, csr_instance());
    chain_evidence_controller_snapshot(&authority, &view);
    if (view.state == CEC_FULLY_VALIDATED) {
        blocker_clear("bg_validation.full_history_unproven");
        return ZCL_OK;
    }

    char reason[192] = {0};
    if (!bgv_auth_evidence_ready(&view, external_seeded, reason))
        return bgv_auth_refuse(reason);

    uint8_t authority_root_bytes[32];
    memcpy(authority_root_bytes, root_bytes, sizeof(authority_root_bytes));
    if (external_seeded) {
        size_t root_len = 0;
        if (!node_db_state_get(svc->ndb, "cec.snapshot_utxo_sha3",
                               authority_root_bytes,
                               sizeof(authority_root_bytes), &root_len) ||
            root_len != sizeof(authority_root_bytes))
            return bgv_auth_refuse(
                "assisted walk lacks its bound snapshot commitment");
    }

    struct uint256 root;
    memcpy(root.data, authority_root_bytes, sizeof(root.data));
    enum chain_evidence_controller_result result =
        chain_evidence_controller_mark_fully_validated(&authority, &root);
    if (result != CEC_OK) {
        snprintf(reason, sizeof(reason),
                 "CEC full-validation publication refused result=%s",
                 chain_evidence_controller_result_name(result));
        return bgv_auth_refuse(reason);
    }

    blocker_clear("bg_validation.full_history_unproven");
    event_emitf(EV_SYNC_STATE_CHANGE, 0,
                "bg_validation authority published height=%d origin=%s",
                chain_height, external_seeded ? "assisted_snapshot" :
                                                "genesis_history");
    LOG_INFO("bg_validation",
             "[bg-valid] durable full-validation authority published h=%d origin=%s",
             chain_height, external_seeded ? "assisted_snapshot" :
                                             "genesis_history");
    return ZCL_OK;
}
