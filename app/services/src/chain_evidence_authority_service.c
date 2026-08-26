/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

// one-result-type-ok:single-cec-result-enum
//
// Every fallible mutation entry on this authority returns ONE coherent domain
// result type: enum chain_evidence_controller_result. It is richer than a
// generic ok/err carrier — each CEC_REJECTED_* code IS the named failure
// reason the callers switch on:
//   - import_snapshot_evidence(), promote_tip(), mark_background_progress(),
//     mark_fully_validated() all return enum chain_evidence_controller_result.
// Non-fallible surfaces:
//   - load_state() returns the state enum (a getter); freeze() is void but
//     ALWAYS names itself (no-silent-halt) and persists the reason.
//   - the bool helpers (u256_nonzero, has_*_required, persist_state/i64/blob,
//     state_allows_tip_promotion) are PRIVATE predicates feeding the result
//     enum; parse_state is a pure decoder with defaults. The startup
//     reconcile lives in chain_evidence_reconstruct.c (the recovery half).
//     32-byte presence checks use the canonical
//     zcl_chainwork_is_zero predicate (validation/sync_evidence_policy.h).
// No public fallible operation returns a bare reason-less bool. Behavior
// bit-for-bit.

#include "services/chain_evidence_authority_service.h"
#include "util/log_macros.h"
#include "services/chain_evidence_persistence_service.h"
#include "chain_evidence_reconstruct.h"
#include "jobs/reducer_frontier.h"

#include "models/database.h"
#include "models/db_txn.h"
#include "event/event.h"
#include "validation/sync_evidence_policy.h"

#include <stdio.h>
#include <string.h>

/* ── enum name tables (pure enum -> const char* mappers) ──────── */

const char *chain_evidence_controller_state_name(enum chain_evidence_controller_state state)
{
    static const char *names[] = {
        [CEC_EMPTY]                 = "empty",
        [CEC_HEADERS_WORK_VALIDATED] = "headers_work_validated",
        [CEC_SNAPSHOT_UTXO_HASH_VERIFIED] = "snapshot_utxo_hash_verified",
        [CEC_TIP_FOLLOWING]         = "tip_following",
        [CEC_BACKGROUND_VALIDATING] = "background_validating",
        [CEC_FULLY_VALIDATED]       = "fully_validated",
        [CEC_CONTRADICTION_FROZEN]  = "contradiction_frozen",
    };
    if (state >= 0 && state < CEC_NUM_STATES)
        return names[state];
    return "unknown";
}

const char *chain_evidence_controller_result_name(enum chain_evidence_controller_result result)
{
    switch (result) {
    case CEC_OK:                              return "ok";
    case CEC_REJECTED_NULL_ARG:               return "null_arg";
    case CEC_REJECTED_FROZEN:                 return "frozen";
    case CEC_REJECTED_BAD_STATE:              return "bad_state";
    case CEC_REJECTED_BAD_PROOF:              return "bad_proof";
    case CEC_REJECTED_INCOMPLETE_INDEX_EVIDENCE:
        return "incomplete_index_evidence";
    case CEC_REJECTED_UTXO_AHEAD_OF_INDEX:    return "utxo_ahead_of_index";
    case CEC_REJECTED_CSR:                    return "csr";
    case CEC_REJECTED_PERSIST:                return "persist";
    }
    return "unknown";
}

const char *chain_evidence_source_class_name(enum chain_evidence_source_class source)
{
    switch (source) {
    case CEC_SOURCE_CLASS_UNKNOWN:         return "unknown";
    case CEC_SOURCE_CLASS_NATIVE_P2P:      return "native_p2p";
    case CEC_SOURCE_CLASS_SNAPSHOT:        return "snapshot";
    case CEC_SOURCE_CLASS_LOCAL_IMPORT:    return "local_import";
    case CEC_SOURCE_CLASS_LEGACY_ADVISORY: return "legacy_advisory";
    }
    return "unknown";
}

const char *chain_evidence_publish_state_name(enum chain_evidence_publish_state state)
{
    switch (state) {
    case CEC_PUBLISH_NOT_PUBLISHABLE:        return "not_publishable";
    case CEC_PUBLISH_LOCAL_EVIDENCE:         return "publishable_local_evidence";
    case CEC_PUBLISH_FROZEN_CONTRADICTION:   return "frozen_contradiction";
    }
    return "unknown";
}

const char *chain_evidence_full_validation_origin_name(
    enum chain_evidence_full_validation_origin origin)
{
    switch (origin) {
    case CEC_FULL_VALIDATION_UNKNOWN:           return "unknown";
    case CEC_FULL_VALIDATION_GENESIS_HISTORY:   return "genesis_full_history";
    case CEC_FULL_VALIDATION_ASSISTED_SNAPSHOT: return "assisted_snapshot";
    }
    return "unknown";
}

#ifdef ZCL_TESTING
static bool g_cec_test_fail_commit_after_csr;

void chain_evidence_controller_test_fail_commit_after_csr(bool fail)
{
    g_cec_test_fail_commit_after_csr = fail;
}
#endif

static bool u256_nonzero(const struct uint256 *u)
{
    return u && !zcl_chainwork_is_zero(u->data);
}

bool chain_evidence_record_has_block_index_required(
    const struct chain_evidence_record *evidence)
{
    return evidence &&
           evidence->publish_state == CEC_PUBLISH_LOCAL_EVIDENCE &&
           evidence->header_ancestry_linked &&
           evidence->chainwork_recomputed &&
           evidence->nakamoto_selected_best_work &&
           evidence->block_bytes_hash_checked;
}

bool chain_evidence_record_has_snapshot_required(
    const struct chain_evidence_record *evidence)
{
    return evidence &&
           evidence->source_class == CEC_SOURCE_CLASS_SNAPSHOT &&
           evidence->publish_state == CEC_PUBLISH_LOCAL_EVIDENCE &&
           evidence->header_ancestry_linked &&
           evidence->chainwork_recomputed &&
           evidence->nakamoto_selected_best_work &&
           evidence->utxo_sha3_verified &&
           evidence->mmb_flyclient_proof_verified &&
           evidence->chunk_hash_coverage_verified;
}

static bool persist_state(struct chain_evidence_controller *a,
                          enum chain_evidence_controller_state state)
{
    const char *name = chain_evidence_controller_state_name(state);
    if (!a || !a->ndb)
        return false;
    if (!node_db_state_set(a->ndb, "cec.sync_state", name, strlen(name) + 1)) {
        LOG_WARN("cec", "persist_state: node_db_state_set failed key=cec.sync_state value=%s", name);
        return false;
    }
    a->state = state;
    return true;
}

static bool persist_i64(struct chain_evidence_controller *a, const char *key, int64_t v)
{
    return a && a->ndb && node_db_state_set_int(a->ndb, key, v);
}

static bool persist_blob(struct chain_evidence_controller *a, const char *key,
                         const void *value, size_t len)
{
    return a && a->ndb && node_db_state_set(a->ndb, key, value, len);
}

static enum chain_evidence_controller_state parse_state(const char *name)
{
    if (!name || !*name)
        return CEC_EMPTY;
    for (int i = 0; i < CEC_NUM_STATES; i++) {
        if (strcmp(name, chain_evidence_controller_state_name((enum chain_evidence_controller_state)i)) == 0)
            return (enum chain_evidence_controller_state)i;
    }
    return CEC_EMPTY;
}

void chain_evidence_controller_init(struct chain_evidence_controller *authority,
                         struct node_db *ndb,
                         struct chain_state_repository *csr)
{
    if (!authority)
        return;
    memset(authority, 0, sizeof(*authority));
    authority->ndb = ndb;
    authority->csr = csr ? csr : csr_instance();
    authority->state = CEC_EMPTY;
    (void)chain_evidence_controller_load_state(authority);
    cec_reconcile_startup(authority);
}

void chain_evidence_controller_init_readonly(
    struct chain_evidence_controller *authority, struct node_db *ndb,
    struct chain_state_repository *csr)
{
    if (!authority)
        return;
    memset(authority, 0, sizeof(*authority));
    authority->ndb = ndb;
    authority->csr = csr ? csr : csr_instance();
    authority->state = CEC_EMPTY;
    (void)chain_evidence_controller_load_state_readonly(authority);
}

enum chain_evidence_controller_state
chain_evidence_controller_load_state_readonly(
    struct chain_evidence_controller *authority)
{
    char mode[64];
    size_t len = 0;

    if (!authority || !authority->ndb)
        return CEC_EMPTY;

    memset(mode, 0, sizeof(mode));
    if (node_db_state_get(authority->ndb, "cec.sync_state",
                          mode, sizeof(mode) - 1, &len)) {
        mode[sizeof(mode) - 1] = '\0';
        authority->state = parse_state(mode);
    }

    memset(authority->contradiction_reason, 0, sizeof(authority->contradiction_reason));
    (void)node_db_state_get(authority->ndb, "cec.contradiction_reason",
                            authority->contradiction_reason,
                            sizeof(authority->contradiction_reason) - 1, &len);

    return authority->state;
}

enum chain_evidence_controller_state chain_evidence_controller_load_state(
    struct chain_evidence_controller *authority)
{
    if (!authority)
        return CEC_EMPTY;
    (void)chain_evidence_controller_load_state_readonly(authority);

    /* Auto-clear stale freezes from reasons that have been demoted to
     * non-fatal warnings. Without this, a previously frozen node stays
     * frozen across upgrades even after the underlying check is gone. */
    if (authority->state == CEC_CONTRADICTION_FROZEN) {
        const char *r = authority->contradiction_reason;
        bool demoted =
            (strcmp(r, "csr_header_tip_behind_active_tip") == 0) ||
            (strcmp(r, "sqlite_height_behind_active_tip") == 0) ||
            (strcmp(r, "csr_cursor_mismatch") == 0) ||
            (strcmp(r, "active_tip_hash_mismatch") == 0) ||
            (strcmp(r, "active_tip_height_mismatch") == 0) ||
            (strcmp(r, "missing_active_tip_evidence") == 0) ||
            (strcmp(r, "legacy advisory hash disagreement") == 0) ||
            (strcmp(r, "legacy advisory post-catchup disagreement") == 0);
        if (demoted) {
            LOG_WARN("cec", "[cec] auto-clearing stale freeze (reason=%s now " "demoted to warning)", r);
            authority->state = CEC_EMPTY;
            memset(authority->contradiction_reason, 0,
                   sizeof(authority->contradiction_reason));
            (void)node_db_state_set(authority->ndb, "cec.sync_state",
                                    "empty", strlen("empty") + 1);
            (void)node_db_state_set(authority->ndb,
                                    "cec.contradiction_reason", "", 1);
            int32_t zero = 0;
            (void)node_db_state_set(authority->ndb, "cec.publish_state",
                                    &zero, sizeof(zero));
        }
    }

    /* No-silent-halt invariant for the LOAD path: a frozen controller
     * must always carry a non-empty reason. If a torn / legacy DB
     * persisted FROZEN with an empty cec.contradiction_reason (or the key
     * was lost), backfill a named reason in memory AND on disk so
     * introspection never reports a freeze that does not name itself.
     * load_state does NOT decide whether the freeze still holds — that is
     * reconcile_startup's job (called next in init), which re-derives
     * evidence for the live tip and LIFTS the freeze if it is provably
     * stale, or re-freezes with a precise reason if a contradiction
     * genuinely remains. */
    if (authority->state == CEC_CONTRADICTION_FROZEN &&
        authority->contradiction_reason[0] == '\0') {
        snprintf(authority->contradiction_reason,
                 sizeof(authority->contradiction_reason),
                 "unspecified_contradiction_persisted_without_reason");
        LOG_WARN("cec",
                 "[cec] frozen state had empty reason on load — backfilling "
                 "'%s' (reconcile will re-derive and lift if stale)",
                 authority->contradiction_reason);
        (void)node_db_state_set(authority->ndb, "cec.contradiction_reason",
                                authority->contradiction_reason,
                                strlen(authority->contradiction_reason) + 1);
    }
    return authority->state;
}

/* Residual durability failure after every retry is not silence: emit one
 * operator-visible sync event naming the key that would not hold. */
static void cec_freeze_undurable(const char *key, struct zcl_result r)
{
    event_emitf(EV_SYNC_STATE_CHANGE, 0, "cec_freeze_not_durable "
                "key=%s code=%d msg=%s", key, r.code, r.message);
}

void chain_evidence_controller_freeze(struct chain_evidence_controller *authority,
                           const char *reason)
{
    if (!authority)
        return;
    authority->state = CEC_CONTRADICTION_FROZEN;
    /* A freeze MUST always name itself: a halt with an empty reason
     * violates the no-silent-halt mandate. Coalesce NULL and "" alike. */
    snprintf(authority->contradiction_reason, sizeof(authority->contradiction_reason),
             "%s", (reason && reason[0]) ? reason : "unspecified_contradiction");
    if (authority->ndb) {
        /* Only durable form of the freeze: RAM un-freezes into the same
         * contradiction at restart. Bounded-retry lane; residue fails loud. */
        const char *name = chain_evidence_controller_state_name(
            CEC_CONTRADICTION_FROZEN);
        struct zcl_result r = chain_evidence_state_set_retry(authority->ndb,
            "cec.contradiction_reason", authority->contradiction_reason,
            strlen(authority->contradiction_reason) + 1, "cec_freeze");
        if (!r.ok)
            cec_freeze_undurable("cec.contradiction_reason", r);
        r = chain_evidence_state_set_retry(authority->ndb,
            "cec.sync_state", name, strlen(name) + 1, "cec_freeze");
        if (!r.ok)
            cec_freeze_undurable("cec.sync_state", r);
        r = chain_evidence_state_set_int_retry(authority->ndb,
            "cec.publish_state", CEC_PUBLISH_FROZEN_CONTRADICTION,
            "cec_freeze");
        if (!r.ok)
            cec_freeze_undurable("cec.publish_state", r);
    }
}

enum chain_evidence_controller_result chain_evidence_controller_import_snapshot_evidence(
    struct chain_evidence_controller *authority,
    const struct chain_evidence_controller_snapshot_meta *snapshot)
{
    if (!authority || !snapshot)
        return CEC_REJECTED_NULL_ARG;
    if (authority->state == CEC_CONTRADICTION_FROZEN)
        return CEC_REJECTED_FROZEN;
    if (snapshot->anchor_height < 0 ||
        !u256_nonzero(&snapshot->anchor_hash) ||
        !u256_nonzero(&snapshot->utxo_sha3) ||
        snapshot->utxo_count == 0 ||
        zcl_chainwork_is_zero(snapshot->chainwork) ||
        zcl_chainwork_is_zero(snapshot->mmb_root) ||
        snapshot->schema_version == 0 ||
        snapshot->finality_depth == 0 ||
        !chain_evidence_record_has_snapshot_required(&snapshot->verified)) {
        chain_evidence_controller_freeze(authority, "snapshot manifest missing verified evidence");
        return CEC_REJECTED_BAD_PROOF;
    }

    struct chain_evidence_record header = {
        .source_class = CEC_SOURCE_CLASS_SNAPSHOT,
        .publish_state = CEC_PUBLISH_LOCAL_EVIDENCE,
        .header_ancestry_linked = snapshot->verified.header_ancestry_linked,
        .chainwork_recomputed = snapshot->verified.chainwork_recomputed,
        .nakamoto_selected_best_work =
            snapshot->verified.nakamoto_selected_best_work,
    };

    if (!persist_i64(authority, "cec.snapshot_anchor_height",
                     snapshot->anchor_height) ||
        !persist_blob(authority, "cec.snapshot_anchor_hash",
                      snapshot->anchor_hash.data, 32) ||
        !persist_blob(authority, "cec.snapshot_utxo_sha3",
                      snapshot->utxo_sha3.data, 32) ||
        !persist_i64(authority, "cec.full_validation_origin",
                     CEC_FULL_VALIDATION_ASSISTED_SNAPSHOT) ||
        !persist_i64(authority, "cec.snapshot_validated", 0) ||
        !persist_i64(authority, "cec.publish_state",
                     CEC_PUBLISH_NOT_PUBLISHABLE) ||
        !persist_i64(authority, "cec.background_validation_height", 0) ||
        !persist_blob(authority, "cec.snapshot_chainwork",
                      snapshot->chainwork, 32) ||
        !persist_blob(authority, "cec.snapshot_mmb_root",
                      snapshot->mmb_root, 32) ||
        !persist_i64(authority, "cec.snapshot_utxo_count",
                     (int64_t)snapshot->utxo_count) ||
        !persist_i64(authority, "cec.snapshot_schema_version",
                     snapshot->schema_version) ||
        !persist_i64(authority, "cec.snapshot_finality_depth",
                     snapshot->finality_depth) ||
        !chain_evidence_store_persist(authority, "cec.header_chain_evidence", &header).ok) {
        chain_evidence_controller_freeze(authority, "snapshot metadata persistence failed");
        return CEC_REJECTED_PERSIST;
    }
    if (snapshot->producer) {
        if (!persist_blob(authority, "cec.snapshot_producer",
                          snapshot->producer, strlen(snapshot->producer) + 1)) {
            chain_evidence_controller_freeze(authority, "snapshot producer persistence failed");
            return CEC_REJECTED_PERSIST;
        }
    }
    if (!chain_evidence_store_persist(authority, "cec.snapshot_evidence",
                          &snapshot->verified).ok ||
        !persist_state(authority, CEC_SNAPSHOT_UTXO_HASH_VERIFIED))
        return CEC_REJECTED_PERSIST;
    return CEC_OK;
}

static bool state_allows_tip_promotion(enum chain_evidence_controller_state state)
{
    return state == CEC_EMPTY ||
           state == CEC_HEADERS_WORK_VALIDATED ||
           state == CEC_SNAPSHOT_UTXO_HASH_VERIFIED ||
           state == CEC_TIP_FOLLOWING ||
           state == CEC_BACKGROUND_VALIDATING ||
           state == CEC_FULLY_VALIDATED;
}

static void cec_restore_csr_view(struct chain_state_repository *csr,
                                 struct block_index *old_tip,
                                 struct block_index *old_header,
                                 const struct uint256 *old_coins_best)
{
    (void)csr_restore_in_memory_view(csr, old_tip, old_header,
                                     old_coins_best);
}

int chain_evidence_clamp_coins_height_to_frontier(
    struct chain_evidence_controller *authority, int requested_height)
{
    /* wave-3 delete (with the cec.coins_best_block_height int twin): the
     * clamp + the twin exist only to keep a duplicate height honest. */
    if (!authority || !authority->csr)
        return requested_height;

    /* Clamp directly to the DERIVED coins-best height when
     * coins_applied_height is present — drops the in-memory-cache ->
     * block_map roundtrip. Legacy body unchanged on !found. */
    {
        int32_t d_h = -1;
        if (reducer_frontier_derive_coins_best_now(&d_h, NULL, NULL)) {
            if (d_h < 0 || d_h >= requested_height)
                return requested_height;
            LOG_WARN("cec",
                     "[cec] Guard A: clamping cec.coins_best_block_height "
                     "%d -> %d (derived coins-best, coins_kv authority)",
                     requested_height, d_h);
            return d_h;
        }
    }

    if (!authority->csr->block_map || !authority->csr->coins_tip)
        return requested_height;
    struct uint256 coins_hash;
    memset(&coins_hash, 0, sizeof(coins_hash));
    coins_view_cache_get_best_block(authority->csr->coins_tip, &coins_hash);
    if (uint256_is_null(&coins_hash))
        return requested_height;
    struct block_index *cb =
        block_map_find(authority->csr->block_map, &coins_hash);
    if (!cb || cb->nHeight < 0 || cb->nHeight >= requested_height)
        return requested_height;
    LOG_WARN("cec",
             "[cec] Guard A: clamping cec.coins_best_block_height %d -> %d "
             "(genuine coins frontier = height of coins_best_block)",
             requested_height, cb->nHeight);
    return cb->nHeight;
}

enum chain_evidence_controller_result chain_evidence_controller_promote_tip(
    struct chain_evidence_controller *authority,
    const struct chain_evidence_controller_tip_request *request)
{
    if (!authority || !request || !request->new_tip ||
        !request->new_tip->phashBlock)
        return CEC_REJECTED_NULL_ARG;
    if (authority->state == CEC_CONTRADICTION_FROZEN)
        return CEC_REJECTED_FROZEN;
    if (!state_allows_tip_promotion(authority->state))
        return CEC_REJECTED_BAD_STATE;
    struct chain_evidence_record verified = request->verified;
    if (verified.source_class == CEC_SOURCE_CLASS_UNKNOWN)
        verified.source_class = CEC_SOURCE_CLASS_NATIVE_P2P;
    if (verified.publish_state == CEC_PUBLISH_NOT_PUBLISHABLE)
        verified.publish_state = CEC_PUBLISH_LOCAL_EVIDENCE;

    if (!chain_evidence_record_has_block_index_required(&verified)) {
        /* Don't freeze the controller on a missing-flag record: during
         * genesis-up sync the evidence flags (header_ancestry_linked,
         * chainwork_recomputed, nakamoto_selected_best_work,
         * block_bytes_hash_checked) can be temporarily missing on a
         * re-arrival of a block whose evidence record was constructed
         * before all the flags were stamped — e.g. a stale cached
         * record from a prior reorg disconnect, or a worker-thread
         * race that constructs the record before block_index_integrity
         * has finished marking it. Permanent freeze on this transient
         * shape blocks the chain
         * forever. The actual integrity of new_tip is checked further
         * down by csr_validate_locked (tip-in-index, hash-match,
         * sql-cross-check) before the commit lands. Returning
         * INCOMPLETE_INDEX_EVIDENCE without freeze lets the caller
         * retry on the next pass once the evidence record is rebuilt. */
        LOG_WARN("cec", "[cec] tip promotion missing block-index evidence " "(transient) h=%d ancestry=%d work=%d nakamoto=%d " "bytes=%d — controller stays in state=%s for retry", request->new_tip->nHeight, verified.header_ancestry_linked, verified.chainwork_recomputed, verified.nakamoto_selected_best_work, verified.block_bytes_hash_checked, chain_evidence_controller_state_name(authority->state));
        return CEC_REJECTED_INCOMPLETE_INDEX_EVIDENCE;
    }
    if (request->utxo_max_height > request->new_tip->nHeight) {
        chain_evidence_controller_freeze(authority,
            "utxo height exceeds evidenced block-index height");
        return CEC_REJECTED_UTXO_AHEAD_OF_INDEX;
    }
    if (!authority->ndb) {
        chain_evidence_controller_freeze(authority,
            "tip promotion has no evidence persistence target");
        return CEC_REJECTED_PERSIST;
    }

    struct block_index *old_tip = NULL;
    struct block_index *old_header = NULL;
    struct uint256 old_coins_best;
    memset(&old_coins_best, 0, sizeof(old_coins_best));
    if (authority->csr) {
        if (authority->csr->chain_active)
            old_tip = active_chain_tip(authority->csr->chain_active);
        if (authority->csr->pindex_best_hdr)
            old_header = *authority->csr->pindex_best_hdr;
        if (authority->csr->coins_tip)
            coins_view_cache_get_best_block(authority->csr->coins_tip,
                                            &old_coins_best);
    }

    enum chain_evidence_controller_state old_state = authority->state;
    enum chain_evidence_controller_state next_state = old_state;
    if (old_state == CEC_EMPTY ||
        old_state == CEC_SNAPSHOT_UTXO_HASH_VERIFIED ||
        old_state == CEC_HEADERS_WORK_VALIDATED)
        next_state = CEC_TIP_FOLLOWING;

    /* chain_advance opens a node.db transaction at its step 3 BEFORE
     * calling process_block_commit_tip which routes here. db_txn_begin
     * correctly refuses nesting and returns NULL. Detect the outer
     * transaction and skip our own DB_TXN_SCOPE: the persist calls
     * below will join the existing transaction, and the caller's
     * commit/rollback will atomically close both our evidence
     * persistence AND the block-index write.
     *
     * When no outer txn exists (e.g. standalone csr_commit_tip from a
     * test or boot anchor promote), open our own and commit at end.
     * The cleanup attribute auto-rollbacks our owned txn if we early-
     * return without calling db_txn_commit. db_txn_auto_rollback is a
     * no-op on NULL handles, so the outer-txn case is safe. */
    struct node_db_status _ndb_status = {0};
    if (authority->ndb)
        node_db_get_status(authority->ndb, &_ndb_status);
    bool outer_txn_present = _ndb_status.tx_open;
    __attribute__((cleanup(db_txn_auto_rollback)))
    struct db_txn *txn = NULL;
    if (!outer_txn_present) {
        txn = db_txn_begin(authority->ndb, "cec.promote_tip");
        if (!txn) {
            LOG_WARN("cec", "[cec] tip promotion txn open failed (transient) h=%d", request->new_tip->nHeight);
            return CEC_REJECTED_PERSIST;
        }
    }

    bool persisted =
        chain_evidence_controller_mark_block_evidence(
            authority, request->new_tip->phashBlock, &verified).ok &&
        persist_blob(authority, "cec.active_tip_hash",
                     request->new_tip->phashBlock->data, 32) &&
        persist_i64(authority, "cec.active_tip_height",
                    request->new_tip->nHeight) &&
        persist_i64(authority, "cec.coins_best_block_height",
                    chain_evidence_clamp_coins_height_to_frontier(
                        authority, request->new_tip->nHeight)) &&
        persist_i64(authority, "cec.utxo_max_height",
                    request->utxo_max_height) &&
        persist_i64(authority, "cec.publish_state",
                    CEC_PUBLISH_LOCAL_EVIDENCE) &&
        persist_i64(authority, "cec.active_tip_source_class",
                    verified.source_class) &&
        chain_evidence_store_persist(authority, "cec.block_index_evidence_state",
                         &verified).ok &&
        chain_evidence_store_persist(authority, "cec.active_tip_evidence",
                         &verified).ok;
    if (persisted && next_state != old_state) {
        const char *name = chain_evidence_controller_state_name(next_state);
        persisted = persist_blob(authority, "cec.sync_state",
                                 name, strlen(name) + 1);
    }
    if (!persisted) {
        /* Persistence failure is transient (SQLite contention,
         * mid-write commit clash, etc.) — NOT a chain-state
         * contradiction. Do not freeze: that sets
         * state=CEC_CONTRADICTION_FROZEN permanently, rejecting EVERY
         * subsequent commit with "(frozen)" and wedging the node on
         * the first sqlite hiccup. The wedge was reproducible on
         * fresh-datadir genesis-up sync at h=3 where the first persist
         * failed once and the chain never advanced again. Freeze is
         * reserved for true contradictions (evidence integrity
         * violations, snapshot/index disagreement). Caller retries on
         * REJECTED_PERSIST. */
        LOG_WARN("cec", "[cec] tip promotion persist failure (transient) h=%d — " "controller stays in state=%s for retry", request->new_tip->nHeight, chain_evidence_controller_state_name(old_state));
        event_emitf(EV_CHAIN_TIP_REJECTED, 0,
                    "code=cec_persist_transient h=%d",
                    request->new_tip->nHeight);
        authority->state = old_state;
        return CEC_REJECTED_PERSIST;
    }

    /* When the new tip is below the current active tip, this "promotion" is in
     * fact a reducer unwind during sibling-fork reorg recovery. The evidence
     * controller has
     * already vetted the new tip via chain_evidence_record; pass that
     * authority through to CSR as a rollback authorization so the
     * UTXO-orphan-rows guard (csr step 7) doesn't reject the legitimate
     * rollback. Without this, sibling_fork_rollback wedges at the
     * disconnect step with utxo_delta_too_big.
     *
     * Use active_chain_height() rather than old_tip pointer for the
     * comparison. After a body-pull anchor promotion that walked back
     * through unlinked pprev pointers, c->chain[c->height] can be NULL
     * while c->height is non-negative — `active_chain_tip()` returns
     * NULL in that phantom state, but CSR step 7 still computes
     * from_height from `active_chain_height()` and fires the
     * orphan-rows guard. Comparing against the height field directly
     * closes the gap. */
    int old_active_height = (authority->csr && authority->csr->chain_active)
        ? active_chain_height(authority->csr->chain_active)
        : -1;
    struct chain_state_rollback_authorization rollback_auth = {
        .source = CSR_ROLLBACK_SOURCE_VALIDATION,
        .decision = POLICY_ALLOW,
        .from_height = (int64_t)old_active_height,
        .to_height = request->new_tip->nHeight,
        .max_depth = INT64_MAX,
        .evidence_class = "evidence_controller_vouched_rollback",
        .reason = request->reason ? request->reason
                                  : "chain_evidence_controller.promote_tip",
    };
    bool is_rollback = (old_active_height >= 0 &&
                        request->new_tip->nHeight < old_active_height);

    struct chain_state_commit commit = {
        .new_tip = request->new_tip,
        .new_coins_best = *request->new_tip->phashBlock,
        .expected_utxo_count = 0,
        .update_header_tip = request->update_header_tip,
        .persist_coins_best = true,
        .rollback_auth = is_rollback ? &rollback_auth : NULL,
        .wallet_scan_height = -1,
        .reason = request->reason ? request->reason : "chain_evidence_controller.promote_tip",
    };
    enum csr_result csr = csr_commit_tip(authority->csr, &commit);
    if (csr != CSR_OK) {
        /* CSR rejections are typically transient or recoverable
         * (stale_index when block_index races ahead of active_chain,
         * utxo_delta_too_big when rollback auth missing — those
         * legitimate cases are fixed at the CSR layer). Freezing the
         * controller on any remaining CSR rejection wedges the node
         * for the rest of the process lifetime even though the
         * underlying issue might clear in the next pass. Restore
         * old_state and return CEC_REJECTED_CSR; the caller retries. */
        LOG_WARN("cec", "[cec] csr rejected tip promotion h=%d reason=%s — " "controller stays in state=%s for retry", request->new_tip->nHeight, csr_result_name(csr), chain_evidence_controller_state_name(old_state));
        authority->state = old_state;
        return CEC_REJECTED_CSR;
    }

#ifdef ZCL_TESTING
    if (g_cec_test_fail_commit_after_csr) {
        g_cec_test_fail_commit_after_csr = false;
        chain_evidence_controller_freeze(authority,
            "test-forced tip promotion evidence transaction commit failure after csr commit");
        cec_restore_csr_view(authority->csr, old_tip, old_header,
                             &old_coins_best);
        authority->state = old_state;
        return CEC_REJECTED_PERSIST;
    }
#endif

    /* Commit our txn only if we opened it ourselves. The outer caller
     * (chain_advance) is responsible for committing its own txn after
     * our writes land in it. */
    if (txn && !db_txn_commit(txn)) {
        chain_evidence_controller_freeze(authority,
            "tip promotion evidence transaction commit failed after csr commit");
        cec_restore_csr_view(authority->csr, old_tip, old_header,
                             &old_coins_best);
        authority->state = old_state;
        return CEC_REJECTED_PERSIST;
    }
    authority->state = next_state;
    return CEC_OK;
}



enum chain_evidence_controller_result chain_evidence_controller_mark_fully_validated(
    struct chain_evidence_controller *authority,
    const struct uint256 *utxo_sha3)
{
    struct uint256 expected;
    struct chain_evidence_record snapshot_evidence;
    struct chain_evidence_record active_tip_evidence;
    struct zcl_result snapshot_loaded;
    struct zcl_result active_tip_loaded;
    size_t len = 0;
    int64_t snapshot_anchor_height = -1;
    int64_t persisted_origin = CEC_FULL_VALIDATION_UNKNOWN;
    bool snapshot_metadata_present = false;

    if (!authority || !utxo_sha3)
        return CEC_REJECTED_NULL_ARG;
    if (authority->state == CEC_CONTRADICTION_FROZEN)
        return CEC_REJECTED_FROZEN;
    if (!u256_nonzero(utxo_sha3)) {
        chain_evidence_controller_freeze(
            authority, "full validation UTXO commitment is zero");
        return CEC_REJECTED_BAD_PROOF;
    }

    memset(&snapshot_evidence, 0, sizeof(snapshot_evidence));
    snapshot_loaded = chain_evidence_store_load(
        authority->ndb, "cec.snapshot_evidence", &snapshot_evidence);
    snapshot_metadata_present = authority->ndb &&
        node_db_state_get_int(authority->ndb, "cec.snapshot_anchor_height",
                              &snapshot_anchor_height);
    if (authority->ndb &&
        node_db_state_get_int(authority->ndb, "cec.full_validation_origin",
                              &persisted_origin) &&
        persisted_origin == CEC_FULL_VALIDATION_ASSISTED_SNAPSHOT)
        snapshot_metadata_present = true;

    if (snapshot_loaded.ok) {
        /* Assisted promotion remains bound to the exact imported state and
         * its durable proof record.  A state enum or caller assertion alone
         * can never launder peer/release-assisted state into sovereignty. */
        memset(&expected, 0, sizeof(expected));
        if (!authority->ndb ||
            !node_db_state_get(authority->ndb, "cec.snapshot_utxo_sha3",
                               expected.data, 32, &len) ||
            len != 32 ||
            memcmp(expected.data, utxo_sha3->data, 32) != 0 ||
            !chain_evidence_record_has_snapshot_required(
                &snapshot_evidence)) {
            chain_evidence_controller_freeze(
                authority,
                "background validation snapshot evidence mismatch");
            return CEC_REJECTED_BAD_PROOF;
        }
        snapshot_evidence.full_validation_complete = true;
        if (!persist_i64(authority, "cec.snapshot_validated", 1) ||
            !chain_evidence_store_persist(
                authority, "cec.snapshot_evidence", &snapshot_evidence).ok ||
            !persist_i64(authority, "cec.full_validation_origin",
                         CEC_FULL_VALIDATION_ASSISTED_SNAPSHOT) ||
            !persist_state(authority, CEC_FULLY_VALIDATED))
            return CEC_REJECTED_PERSIST;
        return CEC_OK;
    }

    /* Snapshot metadata without its evidence record is an interrupted or
     * corrupted assisted mode, not a genesis fold.  Fail closed instead of
     * falling through to the sovereign path. */
    if (snapshot_metadata_present) {
        chain_evidence_controller_freeze(
            authority, "full validation missing snapshot evidence record");
        return CEC_REJECTED_PERSIST;
    }

    /* A genuine genesis/full-history campaign has no snapshot record.  It
     * must, however, terminate at a locally publishable active tip whose
     * ancestry, work selection and bytes have all been checked.  The caller
     * of this authority boundary attests that the fold covered genesis..tip;
     * the exact resulting UTXO commitment is persisted below. */
    if (authority->state != CEC_TIP_FOLLOWING &&
        authority->state != CEC_BACKGROUND_VALIDATING &&
        authority->state != CEC_FULLY_VALIDATED) {
        chain_evidence_controller_freeze(
            authority, "genesis full validation requested from invalid state");
        return CEC_REJECTED_BAD_STATE;
    }
    memset(&active_tip_evidence, 0, sizeof(active_tip_evidence));
    active_tip_loaded = chain_evidence_store_load(
        authority->ndb, "cec.active_tip_evidence", &active_tip_evidence);
    if (!active_tip_loaded.ok ||
        !chain_evidence_record_has_block_index_required(
            &active_tip_evidence) ||
        (active_tip_evidence.source_class != CEC_SOURCE_CLASS_NATIVE_P2P &&
         active_tip_evidence.source_class != CEC_SOURCE_CLASS_LOCAL_IMPORT)) {
        chain_evidence_controller_freeze(
            authority,
            "genesis full validation missing local active-tip evidence");
        return CEC_REJECTED_BAD_PROOF;
    }
    active_tip_evidence.full_validation_complete = true;
    if (!persist_blob(authority, "cec.full_history_utxo_sha3",
                      utxo_sha3->data, 32) ||
        !chain_evidence_store_persist(
            authority, "cec.active_tip_evidence", &active_tip_evidence).ok ||
        !persist_i64(authority, "cec.full_validation_origin",
                     CEC_FULL_VALIDATION_GENESIS_HISTORY) ||
        !persist_state(authority, CEC_FULLY_VALIDATED))
        return CEC_REJECTED_PERSIST;
    return CEC_OK;
}
