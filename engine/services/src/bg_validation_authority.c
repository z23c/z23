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

bool bg_validation_checkpoint_check_get(
    const struct bg_validation_service *svc,
    struct bg_validation_checkpoint_check *out)
{
    uint64_t words[4];
    if (!svc || !out)
        return false;
    int tip = atomic_load(&svc->checkpoint_check_tip);
    int floor = atomic_load(&svc->checkpoint_check_floor);
    if (tip <= 0)
        return false;
    for (int i = 0; i < 4; i++)
        words[i] = atomic_load(&svc->checkpoint_check_words[i]);
    if (atomic_load(&svc->checkpoint_check_tip) != tip ||
        atomic_load(&svc->checkpoint_check_floor) != floor)
        return false;
    out->checkpoint_height = floor;
    out->first_height = floor + 1;
    out->tip_height = tip;
    memcpy(out->tip_hash, words, sizeof(words));
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

/* The record was earned under an earlier build (all four flags) but the
 * controller never left EMPTY / HEADERS_WORK_VALIDATED: the same earn call,
 * with its tip-by-hash checks and in-transaction state advance, finishes the
 * job. Re-earning set flags is idempotent. */
static bool bgv_auth_earned_but_not_following(
    const struct chain_evidence_controller_view *view)
{
    const struct chain_evidence_record *rec = &view->active_tip_evidence;
    return (view->state == CEC_EMPTY ||
            view->state == CEC_HEADERS_WORK_VALIDATED) &&
           rec->source_class == CEC_SOURCE_CLASS_LOCAL_IMPORT &&
           rec->publish_state == CEC_PUBLISH_LOCAL_EVIDENCE &&
           rec->header_ancestry_linked && rec->chainwork_recomputed &&
           chain_evidence_record_has_block_index_required(rec);
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
        (!bgv_auth_record_needs_earning(view) &&
         !bgv_auth_earned_but_not_following(view)))
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

/* The genesis mark latches the controller FROZEN when it is asked from a
 * state it does not accept. Not being tip-following yet is an ordinary wait,
 * not a contradiction, so refuse here and leave the freeze in the controller
 * as the last-line latch for a real one. FULLY_VALIDATED returned earlier. */
static bool bgv_auth_genesis_state_ready(
    const struct chain_evidence_controller_view *view, bool external_seeded,
    char reason[192])
{
    if (external_seeded || view->state == CEC_TIP_FOLLOWING ||
        view->state == CEC_BACKGROUND_VALIDATING)
        return true;
    snprintf(reason, 192,
             "CEC state %s not yet tip-following; genesis authority waits",
             chain_evidence_controller_state_name(view->state));
    return false;
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
            return bgv_auth_genesis_state_ready(view, external_seeded, reason);
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

/* The active tip (height and hash) at one instant, read under cs_main. */
struct bgv_scan_tip {
    int height;
    struct uint256 hash;
};

static bool bgv_auth_capture_tip(struct bg_validation_service *svc,
                                 struct bgv_scan_tip *out)
{
    zcl_mutex_lock(&svc->ms->cs_main);
    struct block_index *tip = active_chain_tip(&svc->ms->chain_active);
    bool ok = tip && tip->phashBlock;
    if (ok) {
        out->height = tip->nHeight;
        out->hash = *tip->phashBlock;
    }
    zcl_mutex_unlock(&svc->ms->cs_main);
    return ok;
}

static bool bgv_auth_same_tip(const struct bgv_scan_tip *a,
                              const struct bgv_scan_tip *b)
{
    return a->height == b->height &&
           memcmp(a->hash.data, b->hash.data, sizeof(a->hash.data)) == 0;
}

/* The tip captured before the coins-root scan must be the tip after it and,
 * when the walk noted the block it last verified, that very block. A noted
 * hash that differs means the walk's coverage is of another block at this
 * height (same-height reorg). A walk with no note (resume past the tip)
 * keeps the historical height contract; the earn still demands the note. */
static bool bgv_auth_scan_tip_stable(
    struct bg_validation_service *svc, const struct bgv_scan_tip *before,
    char reason[192])
{
    struct bgv_scan_tip after;
    if (!bgv_auth_capture_tip(svc, &after) ||
        !bgv_auth_same_tip(before, &after)) {
        snprintf(reason, 192, "active tip changed during the authority scan");
        return false;
    }
    int noted_height = -1;
    uint8_t noted[32];
    if (bg_validation_verified_tip(svc, &noted_height, noted) &&
        (noted_height != before->height ||
         memcmp(noted, before->hash.data, sizeof(noted)) != 0)) {
        snprintf(reason, 192,
                 "completed walk's verified block is not the scanned tip");
        return false;
    }
    return true;
}

#ifdef ZCL_TESTING
static bg_validation_authority_test_hook_fn g_before_mark_hook;

void bg_validation_authority_test_set_before_mark_hook(
    bg_validation_authority_test_hook_fn fn)
{
    g_before_mark_hook = fn;
}
#endif

/* Publish through the controller. The genesis path binds the publication to
 * the tip captured when the coins-root scan and the walk completed, so a tip
 * that moved since answers the retryable CEC_REJECTED_TIP_MOVED instead of a
 * freeze; the controller re-checks it inside its transaction under the
 * evidence write lock. The assisted path is bound by its snapshot record. */
static enum chain_evidence_controller_result bgv_auth_mark(
    struct bg_validation_service *svc,
    struct chain_evidence_controller *authority,
    const struct bgv_scan_tip *scanned, bool external_seeded,
    const struct uint256 *root)
{
    if (external_seeded)
        return chain_evidence_controller_mark_fully_validated(authority, root);
#ifdef ZCL_TESTING
    if (g_before_mark_hook)
        g_before_mark_hook();
#endif
    struct bgv_scan_tip now;
    if (!bgv_auth_capture_tip(svc, &now) || !bgv_auth_same_tip(scanned, &now))
        return CEC_REJECTED_TIP_MOVED;
    return chain_evidence_controller_mark_fully_validated_at_tip(
        authority, root, &scanned->hash);
}

static _Atomic(bg_validation_checkpoint_probe_fn) g_checkpoint_probe;

void bg_validation_authority_set_checkpoint_probe(
    bg_validation_checkpoint_probe_fn fn)
{
    atomic_store(&g_checkpoint_probe, fn);
}

static void bgv_auth_checkpoint_store(struct bg_validation_service *svc,
                                      int32_t floor,
                                      const struct bgv_scan_tip *tip)
{
    uint64_t words[4];
    memcpy(words, tip->hash.data, sizeof(words));
    atomic_store(&svc->checkpoint_check_tip, 0);
    atomic_store(&svc->checkpoint_check_floor, floor);
    for (int i = 0; i < 4; i++)
        atomic_store(&svc->checkpoint_check_words[i], words[i]);
    atomic_store(&svc->checkpoint_check_tip, tip->height);
}

/* A node installed from a checkpoint compiled into this binary carries no
 * snapshot evidence, so the assisted mark would refuse forever. When the
 * shared predicate holds THIS pass, the walk that just reached the scanned
 * tip checked every block above the checkpoint: answer that as a typed,
 * non-publishing result. CEC state and origin stay untouched (never
 * GENESIS_HISTORY, never FULLY_VALIDATED); no operator is paged. The
 * blocker id is raised only by bgv_auth_refuse in this file, so clearing it
 * here retires this publisher's own earlier refusal, nobody else's. */
static bool bgv_auth_checkpoint_floor(
    struct bg_validation_service *svc, bool external_seeded,
    const struct chain_evidence_controller_view *view, int32_t *floor)
{
    uint8_t snapshot_root[32];
    size_t root_len = 0;
    if (!external_seeded || view->snapshot_evidence_loaded ||
        node_db_state_get(svc->ndb, "cec.snapshot_utxo_sha3", snapshot_root,
                          sizeof(snapshot_root), &root_len))
        return false;
    bg_validation_checkpoint_probe_fn probe = atomic_load(&g_checkpoint_probe);
    sqlite3 *pdb = progress_store_db();
    if (!probe || !pdb)
        return false;
    progress_store_tx_lock();
    bool installed = probe(pdb, floor);
    progress_store_tx_unlock();
    return installed;
}

static bool bgv_auth_checkpoint_checked(
    struct bg_validation_service *svc, bool external_seeded,
    const struct chain_evidence_controller_view *view,
    const struct bgv_scan_tip *scanned, struct zcl_result *out)
{
    int32_t floor = -1;
    if (!bgv_auth_checkpoint_floor(svc, external_seeded, view, &floor) ||
        floor >= scanned->height)
        return false;
    bgv_auth_checkpoint_store(svc, floor, scanned);
    blocker_clear("bg_validation.full_history_unproven");
    LOG_INFO("bg_validation",
             "[bg-valid] background check: checked blocks %d..%d above "
             "checkpoint %d to the tip; full-history authority is not claimed",
             floor + 1, scanned->height, floor);
    *out = ZCL_ERR(BG_VALIDATION_AUTHORITY_CHECKPOINT_CHECKED,
                   "background check: checked blocks %d..%d above checkpoint "
                   "%d to the tip (not full-history authority)", floor + 1,
                   scanned->height, floor);
    return true;
}

/* The same checkpoint node whose walk PAUSED on a coverage gap with no script
 * skips: the check is still running, so answer typed instead of paging. It
 * names no checked range; the public wrapper withdraws any earlier CHECKED
 * outcome. Any other short walk (a completed walk whose catch-up could not
 * reach a moved tip, a FAILED walk) keeps the ordinary refusal and page. */
static bool bgv_auth_checkpoint_checking(
    struct bg_validation_service *svc, bool external_seeded, int64_t skips,
    int verified, int chain_height, struct zcl_result *out)
{
    struct chain_evidence_controller authority;
    struct chain_evidence_controller_view view;
    int32_t floor = -1;
    if (skips != 0 ||
        atomic_load(&svc->progress.state) != BG_VALIDATION_PAUSED)
        return false;
    chain_evidence_controller_init(&authority, svc->ndb, csr_instance());
    chain_evidence_controller_snapshot(&authority, &view);
    if (view.state == CEC_FULLY_VALIDATED ||
        !bgv_auth_checkpoint_floor(svc, external_seeded, &view, &floor))
        return false;
    blocker_clear("bg_validation.full_history_unproven");
    *out = ZCL_ERR(BG_VALIDATION_AUTHORITY_CHECKPOINT_CHECKING,
                   "background check: checking blocks above checkpoint %d, "
                   "at %d of tip %d (not full-history authority)", floor,
                   verified, chain_height);
    return true;
}

static struct zcl_result bgv_auth_publish_scanned(
    struct bg_validation_service *svc, bool external_seeded,
    const struct bgv_scan_tip *scanned, const uint8_t root_bytes[32],
    int chain_height);

static struct zcl_result bgv_auth_publish_pass(
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
                               coverage_complete, reason)) {
        struct zcl_result checking;
        if (bgv_auth_checkpoint_checking(svc, external_seeded, skips, verified,
                                         chain_height, &checking))
            return checking;
        return bgv_auth_refuse(reason);
    }

    bool root_ok = false;
    int chain_height_after = -1;
    struct bgv_scan_tip scanned;
    if (!bgv_auth_capture_tip(svc, &scanned))
        return bgv_auth_refuse("no active tip to bind the authority to");
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
    if (!bgv_auth_scan_tip_stable(svc, &scanned, reason))
        return bgv_auth_refuse(reason);
    return bgv_auth_publish_scanned(svc, external_seeded, &scanned,
                                    root_bytes, chain_height);
}

/* The scanned, stable frontier meets the controller: already published,
 * the checkpoint answer, or the full-history mark. */
static struct zcl_result bgv_auth_publish_scanned(
    struct bg_validation_service *svc, bool external_seeded,
    const struct bgv_scan_tip *scanned, const uint8_t root_bytes[32],
    int chain_height)
{
    char reason[192] = {0};
    struct chain_evidence_controller authority;
    struct chain_evidence_controller_view view;
    chain_evidence_controller_init(&authority, svc->ndb, csr_instance());
    chain_evidence_controller_snapshot(&authority, &view);
    if (view.state == CEC_FULLY_VALIDATED) {
        blocker_clear("bg_validation.full_history_unproven");
        return ZCL_OK;
    }

    struct zcl_result checked;
    if (bgv_auth_checkpoint_checked(svc, external_seeded, &view, scanned,
                                    &checked))
        return checked;

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
        bgv_auth_mark(svc, &authority, scanned, external_seeded, &root);
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

/* Every pass rewrites or withdraws the typed checkpoint outcome, so a
 * "checked to tip" never outlives the predicate or the walk behind it. */
struct zcl_result bg_validation_authority_publish(
    struct bg_validation_service *svc, bool external_seeded,
    bool coverage_complete)
{
    struct zcl_result r =
        bgv_auth_publish_pass(svc, external_seeded, coverage_complete);
    if (svc && (r.ok || r.code != BG_VALIDATION_AUTHORITY_CHECKPOINT_CHECKED))
        atomic_store(&svc->checkpoint_check_tip, 0);
    return r;
}
