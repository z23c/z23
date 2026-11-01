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
#include "validation/process_block.h"

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

bool bg_validation_authority_walk_is_complete(
    int verified_height, int chain_height, int64_t script_skips,
    bool coverage_complete)
{
    return bg_validation_authority_claim_is_complete(
        verified_height, chain_height, chain_height, script_skips,
        coverage_complete);
}

bool bg_validation_authority_catchup_wanted(
    int verified_height, int chain_height, int64_t script_skips,
    bool coverage_complete)
{
    return coverage_complete && script_skips == 0 && verified_height > 0 &&
           chain_height > verified_height;
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

void bg_validation_note_verified_tip(struct bg_validation_service *svc,
                                     int height,
                                     const struct block_index *pindex)
{
    uint64_t words[4];
    if (!svc || !pindex || !pindex->phashBlock)
        return;
    memcpy(words, pindex->phashBlock->data, sizeof(words));
    atomic_store(&svc->verified_tip_height, -1);
    for (int i = 0; i < 4; i++)
        atomic_store(&svc->verified_tip_words[i], words[i]);
    atomic_store(&svc->verified_tip_height, height);
}

bool bg_validation_verified_tip(const struct bg_validation_service *svc,
                                int *height, uint8_t hash[32])
{
    uint64_t words[4];
    if (!svc || !height || !hash)
        return false;
    int before = atomic_load(&svc->verified_tip_height);
    if (before < 0)
        return false;
    for (int i = 0; i < 4; i++)
        words[i] = atomic_load(&svc->verified_tip_words[i]);
    if (atomic_load(&svc->verified_tip_height) != before)
        return false;
    memcpy(hash, words, sizeof(words));
    *height = before;
    return true;
}

/* True when the walk's last booked block IS this tip, by hash. */
static bool bgv_auth_walk_verified_tip_is(
    const struct bg_validation_service *svc, const struct block_index *tip)
{
    int height = -1;
    uint8_t hash[32];
    return tip && tip->phashBlock && bg_validation_verified_tip(svc, &height,
                                                                hash) &&
           height == tip->nHeight &&
           memcmp(hash, tip->phashBlock->data, sizeof(hash)) == 0;
}

static bool bgv_auth_record_needs_earning(
    const struct chain_evidence_controller_view *view)
{
    const struct chain_evidence_record *rec = &view->active_tip_evidence;
    return rec->source_class == CEC_SOURCE_CLASS_LOCAL_IMPORT &&
           rec->publish_state == CEC_PUBLISH_LOCAL_EVIDENCE &&
           rec->header_ancestry_linked && rec->chainwork_recomputed &&
           !chain_evidence_record_has_block_index_required(rec);
}

/* Genesis path only: earn the two flags live advance and boot reconcile leave
 * false, for the exact tip the walk verified. Each is set from a check that
 * ran on that tip by hash: bytes from the walk (its body read is hash-checked
 * against the index, then fully validated), best work from the core
 * predicate. Anything short of both leaves the record alone and the caller's
 * refusal to explain it. */
static bool bgv_auth_genesis_tip_prepare(
    struct bg_validation_service *svc,
    struct chain_evidence_controller *authority,
    struct chain_evidence_controller_view *view, bool external_seeded,
    char reason[192])
{
    if (external_seeded || view->snapshot_evidence_loaded ||
        !bgv_auth_record_needs_earning(view))
        return true;
    /* Tip read, hash comparison and best-work evaluation under ONE cs_main
     * hold, so the tip judged best is the tip read. cs_main is released
     * before the controller call: the controller never runs under it. */
    zcl_mutex_lock(&svc->ms->cs_main);
    struct block_index *tip = active_chain_tip(&svc->ms->chain_active);
    bool bytes = bgv_auth_walk_verified_tip_is(svc, tip);
    bool best = bytes && process_block_tip_is_best_work(svc->ms, tip);
    struct uint256 tip_hash;
    int tip_height = -1;
    if (bytes) {
        tip_hash = *tip->phashBlock;
        tip_height = tip->nHeight;
    }
    zcl_mutex_unlock(&svc->ms->cs_main);
    if (!bytes) {
        snprintf(reason, 192,
                 "genesis walk did not verify the active tip block by hash");
        return false;
    }
    struct zcl_result earned = chain_evidence_controller_earn_active_tip_evidence(
        authority, &tip_hash, tip_height, best, bytes);
    if (!earned.ok) {
        /* Transient (tip moved / store busy) vs final-for-these-inputs: see
         * enum chain_evidence_earn_outcome. Either way the refusal is
         * returned, not latched: the re-verify loop republishes every
         * BG_PUBLISH_RETRY_CYCLES while the authority is unpublished, and
         * each pass re-derives the tip and re-earns from scratch. */
        bool transient = earned.code == CEC_EARN_TIP_MOVED ||
                         earned.code == CEC_EARN_STORE_BUSY;
        snprintf(reason, 192, "genesis walk could not earn active-tip "
                              "evidence (%s): %.120s",
                 transient ? "transient, retried next pass" : "final",
                 earned.message);
        return false;
    }
    chain_evidence_controller_snapshot(authority, view);
    return true;
}

/* A live-advance write for a newer tip can replace the earned record
 * between the earn and the snapshot that follows. Earning is tip-by-hash
 * and idempotent, so retry once from a fresh snapshot; if the record is
 * still unearned, refuse BEFORE mark_fully_validated, which would freeze
 * the controller on missing evidence.
 * The remaining window (a replacement after this snapshot) is closed in the
 * controller: the publisher marks with the verified tip hash, and a moved
 * tip answers CEC_REJECTED_TIP_MOVED, a retryable refusal, not a freeze. */
static bool bgv_auth_prepare_and_check(
    struct bg_validation_service *svc,
    struct chain_evidence_controller *authority,
    struct chain_evidence_controller_view *view, bool external_seeded,
    char reason[192])
{
    for (int attempt = 0; attempt < 2; attempt++) {
        if (attempt > 0)
            chain_evidence_controller_snapshot(authority, view);
        if (!bgv_auth_genesis_tip_prepare(svc, authority, view,
                                          external_seeded, reason))
            return false;
        if (bgv_auth_evidence_ready(view, external_seeded, reason))
            return true;
    }
    return false;
}

static bool bgv_auth_dependencies_ready(struct bg_validation_service *svc)
{
    return svc && svc->ms && svc->ndb && svc->ndb->open && svc->ndb->db;
}

static bool bgv_auth_walk_current(int verified, int chain_height,
                                  int64_t skips, bool coverage_complete,
                                  char reason[192])
{
    if (coverage_complete && skips == 0 && verified == chain_height)
        return true;
    snprintf(reason, 192,
             "incomplete walk verified=%d tip=%d skips=%lld coverage=%s",
             verified, chain_height, (long long)skips,
             coverage_complete ? "complete" : "gap");
    return false;
}

static void bgv_auth_scan_locked_frontier(
    struct bg_validation_service *svc, sqlite3 *pdb, int *chain_height,
    int32_t *coins_height, uint8_t root_bytes[32], bool *root_ok,
    int *chain_height_after)
{
    /* The reducer uses the same recursive process lock. Holding it across the
     * height samples and SHA3 scan freezes the coins frontier for one coherent
     * claim; this runs once per completed campaign, never on the hot path. */
    progress_store_tx_lock();
    *chain_height = active_chain_height(&svc->ms->chain_active);
    bool coins_ok = reducer_frontier_derive_coins_best_now(
        coins_height, NULL, NULL);
    *root_ok = coins_ok && *coins_height == *chain_height &&
               coins_kv_commitment(pdb, root_bytes) == 0;
    *chain_height_after = active_chain_height(&svc->ms->chain_active);
    progress_store_tx_unlock();
}

static bool bgv_auth_frontier_stable(int verified, int chain_height,
                                     int32_t coins_height, int64_t skips,
                                     int chain_height_after)
{
    if (!bg_validation_authority_claim_is_complete(
            verified, chain_height, coins_height, skips, true))
        return false;
    return chain_height_after == chain_height;
}

static bool bgv_auth_resolve_authority_root(
    struct bg_validation_service *svc, bool external_seeded,
    const uint8_t frontier_root[32], uint8_t authority_root[32])
{
    memcpy(authority_root, frontier_root, 32);
    if (!external_seeded)
        return true;
    size_t root_len = 0;
    return node_db_state_get(svc->ndb, "cec.snapshot_utxo_sha3",
                             authority_root, 32, &root_len) &&
           root_len == 32;
}

/* Publish through the controller. The genesis path binds the publication to
 * the persisted tip of the snapshot the evidence was judged ready on, so a
 * tip that moved since answers the retryable CEC_REJECTED_TIP_MOVED instead
 * of a freeze; the assisted path is bound by its snapshot record instead. */
static enum chain_evidence_controller_result bgv_auth_mark(
    struct chain_evidence_controller *authority,
    const struct chain_evidence_controller_view *view, bool external_seeded,
    const struct uint256 *root)
{
    if (external_seeded)
        return chain_evidence_controller_mark_fully_validated(authority, root);
    if (!view->has_persisted_active_tip_hash)
        return CEC_REJECTED_TIP_MOVED;
    return chain_evidence_controller_mark_fully_validated_at_tip(
        authority, root, &view->persisted_active_tip_hash);
}

struct zcl_result bg_validation_authority_publish(
    struct bg_validation_service *svc, bool external_seeded,
    bool coverage_complete)
{
    if (!bgv_auth_dependencies_ready(svc))
        return bgv_auth_refuse("validation authority dependencies unavailable");

    int verified = atomic_load(&svc->progress.verified_height);
    int64_t skips = atomic_load(&svc->progress.script_verif_skipped_no_undo);
    int chain_height = -1;
    int32_t coins_height = -1;
    uint8_t root_bytes[32] = {0};
    char reason[192] = {0};
    sqlite3 *pdb = progress_store_db();
    if (!pdb)
        return bgv_auth_refuse("canonical coins store unavailable");

    chain_height = active_chain_height(&svc->ms->chain_active);
    if (!bgv_auth_walk_current(verified, chain_height, skips,
                               coverage_complete, reason))
        return bgv_auth_refuse(reason);

    bool root_ok = false;
    int chain_height_after = -1;
    bgv_auth_scan_locked_frontier(svc, pdb, &chain_height, &coins_height,
                                  root_bytes, &root_ok, &chain_height_after);
    if (!bgv_auth_frontier_stable(verified, chain_height, coins_height,
                                  skips, chain_height_after)) {
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

    if (!bgv_auth_prepare_and_check(svc, &authority, &view, external_seeded,
                                    reason))
        return bgv_auth_refuse(reason);

    uint8_t authority_root_bytes[32];
    if (!bgv_auth_resolve_authority_root(svc, external_seeded, root_bytes,
                                         authority_root_bytes))
        return bgv_auth_refuse(
            "assisted walk lacks its bound snapshot commitment");

    struct uint256 root;
    memcpy(root.data, authority_root_bytes, sizeof(root.data));
    enum chain_evidence_controller_result result =
        bgv_auth_mark(&authority, &view, external_seeded, &root);
    if (result != CEC_OK) {
        snprintf(reason, sizeof(reason),
                 "CEC full-validation publication refused result=%s%s",
                 chain_evidence_controller_result_name(result),
                 result == CEC_REJECTED_TIP_MOVED ? " (retryable)" : "");
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
