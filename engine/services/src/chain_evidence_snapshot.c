/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

// one-result-type-ok:void-snapshot-projection — the sole public surface,
// chain_evidence_controller_snapshot(), returns void: it fills an
// out-view from persisted state with no fallible service decision. Every
// per-field load tolerates absence (defaults already set) so there is no
// failure reason to carry. Single, coherent return type by construction.

#include "services/chain_evidence_authority_service.h"
#include "services/chain_evidence_persistence_service.h"

#include "models/block.h"
#include "models/database.h"
#include "validation/sync_evidence_policy.h"

#include <stdio.h>
#include <string.h>

static bool u256_nonzero(const struct uint256 *u)
{
    return u && !zcl_chainwork_is_zero(u->data);
}

static bool u256_equal(const struct uint256 *a, const struct uint256 *b)
{
    return a && b && memcmp(a->data, b->data, 32) == 0;
}

static bool load_u256(struct node_db *ndb, const char *key,
                      struct uint256 *out)
{
    size_t len = 0;
    if (!out)
        return false;
    memset(out, 0, sizeof(*out));
    return ndb && node_db_state_get(ndb, key, out->data, 32, &len) &&
           len == 32;
}

static int state_get_i32(struct node_db *ndb, const char *key, int def)
{
    int64_t v = def;
    if (ndb)
        (void)node_db_state_get_int(ndb, key, &v);
    return (int)v;
}

static bool persisted_tip_matches_projection(struct node_db *ndb,
                                             int height,
                                             const struct uint256 *hash)
{
    struct db_block row;
    if (!ndb || height < 0 || !hash)
        return false;
    memset(&row, 0, sizeof(row));
    return db_block_find_by_height(ndb, height, &row) &&
           memcmp(row.hash, hash->data, sizeof(row.hash)) == 0;
}

/* Zero the view and reset every height marker to "absent". */
static void snapshot_view_reset(struct chain_evidence_controller_view *out)
{
    int *const absent_heights[] = {
        &out->active_tip_height,
        &out->header_tip_height,
        &out->persisted_active_tip_height,
        &out->snapshot_anchor_height,
        &out->background_validation_height,
        &out->utxo_max_height,
        &out->coins_best_block_height,
        &out->sqlite_max_height,
    };
    const size_t absent_height_count =
        sizeof(absent_heights) / sizeof(absent_heights[0]);

    memset(out, 0, sizeof(*out));
    for (size_t i = 0; i < absent_height_count; i++)
        *absent_heights[i] = -1;
}

/* Copy live CSR tip heights and hashes into the view. */
static void snapshot_copy_csr_tips(
    struct chain_evidence_controller *authority,
    struct chain_evidence_controller_view *out)
{
    struct chain_state_view csv;

    memset(&csv, 0, sizeof(csv));
    csr_snapshot(authority->csr, &csv);
    out->active_tip_height = csv.tip_height;
    out->header_tip_height = csv.header_height;
    out->sqlite_max_height = (int)csv.sql_max_height;
    out->coins_best_block_hash = csv.coins_best_block;
    out->has_coins_best_block_hash = u256_nonzero(&csv.coins_best_block);
    out->active_tip_hash = csv.tip_hash;
    out->has_active_tip_hash = u256_nonzero(&csv.tip_hash);
    if (authority->csr && authority->csr->pindex_best_hdr &&
        *authority->csr->pindex_best_hdr &&
        (*authority->csr->pindex_best_hdr)->phashBlock) {
        out->header_tip_hash =
            *(*authority->csr->pindex_best_hdr)->phashBlock;
        out->has_header_tip_hash = true;
    }
}

/* Load the persisted cec.* tip hash and height markers. */
static void snapshot_load_persisted_markers(
    struct node_db *ndb, struct chain_evidence_controller_view *out)
{
    if (load_u256(ndb, "cec.active_tip_hash", &out->persisted_active_tip_hash))
        out->has_persisted_active_tip_hash = true;
    out->persisted_active_tip_height =
        state_get_i32(ndb, "cec.active_tip_height", -1);
    out->snapshot_anchor_height =
        state_get_i32(ndb, "cec.snapshot_anchor_height", -1);
    out->background_validation_height =
        state_get_i32(ndb, "cec.background_validation_height", -1);
    out->utxo_max_height = state_get_i32(ndb, "cec.utxo_max_height", -1);
    out->coins_best_block_height =
        state_get_i32(ndb, "cec.coins_best_block_height", -1);
}

/* Load the persisted cec.* enum and flag values. */
static void snapshot_load_persisted_enums(
    struct node_db *ndb, struct chain_evidence_controller_view *out)
{
    int64_t v = -1;

    if (ndb && node_db_state_get_int(ndb, "cec.active_tip_source_class", &v))
        out->active_tip_source_class = (enum chain_evidence_source_class)v;
    v = CEC_PUBLISH_NOT_PUBLISHABLE;
    if (ndb && node_db_state_get_int(ndb, "cec.publish_state", &v))
        out->publish_state = (enum chain_evidence_publish_state)v;
    v = CEC_FULL_VALIDATION_UNKNOWN;
    if (ndb && node_db_state_get_int(ndb,
                                     "cec.full_validation_origin", &v))
        out->full_validation_origin =
            (enum chain_evidence_full_validation_origin)v;
    v = 0;
    if (ndb && node_db_state_get_int(ndb,
                                     "cec.repaired_active_tip_evidence", &v))
        out->repaired_active_tip_evidence = v != 0;
}

/* Load the durable cec evidence records, backfilling enum gaps from them. */
static void snapshot_load_evidence_records(
    struct node_db *ndb, struct chain_evidence_controller_view *out)
{
    (void)chain_evidence_store_load(ndb,
                                    "cec.block_index_evidence_state",
                                    &out->block_index_evidence_state).ok;
    (void)chain_evidence_store_load(ndb, "cec.active_tip_evidence",
                                    &out->active_tip_evidence).ok;
    out->snapshot_evidence_loaded =
        chain_evidence_store_load(ndb, "cec.snapshot_evidence",
                                  &out->snapshot_evidence).ok;
    /* Backward-readable assisted evidence: releases predating the explicit
     * origin key already bound FULLY_VALIDATED to this durable record.  Never
     * infer genesis provenance from the state enum alone. */
    if (out->full_validation_origin == CEC_FULL_VALIDATION_UNKNOWN &&
        out->state == CEC_FULLY_VALIDATED &&
        out->snapshot_evidence_loaded &&
        out->snapshot_evidence.full_validation_complete)
        out->full_validation_origin = CEC_FULL_VALIDATION_ASSISTED_SNAPSHOT;
    (void)chain_evidence_store_load(ndb, "cec.header_chain_evidence",
                                    &out->header_chain_evidence).ok;
    if (out->active_tip_source_class == CEC_SOURCE_CLASS_UNKNOWN &&
        out->active_tip_evidence.source_class != CEC_SOURCE_CLASS_UNKNOWN)
        out->active_tip_source_class = out->active_tip_evidence.source_class;
    if (out->publish_state == CEC_PUBLISH_NOT_PUBLISHABLE &&
        out->active_tip_evidence.publish_state != CEC_PUBLISH_NOT_PUBLISHABLE)
        out->publish_state = out->active_tip_evidence.publish_state;
}

/* Compute the active-tip evidence health flags. */
static void snapshot_classify_tip_evidence(
    struct chain_evidence_controller_view *out)
{
    /* "Missing" means the active tip has no publishable evidence at all.
     * A reconstructed LOCAL_IMPORT tip (ancestry-linked + chainwork-
     * recomputed, publish_state=LOCAL_EVIDENCE) is publishable low-trust
     * evidence — NOT missing. It does not satisfy the stricter
     * block-index-required predicate (which also demands bytes-hash and
     * nakamoto-selected), and that is correct: background validation
     * upgrades those flags later. Flagging a publishable local tip as
     * "missing evidence" would mark a recoverable, advancing node
     * unhealthy. */
    bool local_publishable =
        out->active_tip_evidence.publish_state == CEC_PUBLISH_LOCAL_EVIDENCE &&
        out->active_tip_evidence.header_ancestry_linked &&
        out->active_tip_evidence.chainwork_recomputed;
    out->missing_active_tip_evidence =
        out->active_tip_height >= 0 &&
        !chain_evidence_record_has_block_index_required(
            &out->active_tip_evidence) &&
        !local_publishable;
    out->publish_state_not_local =
        out->active_tip_height >= 0 &&
        out->publish_state != CEC_PUBLISH_LOCAL_EVIDENCE;
}

/* True when the persisted evidence lags the projection frontier by at
 * most one hash-bound row. */
static bool durable_frontier_lag_allows_hash_divergence(
    struct node_db *ndb, int sqlite_max_height, int active_tip_height,
    int persisted_active_tip_height, bool has_persisted_active_tip_hash,
    const struct uint256 *persisted_active_tip_hash)
{
    return sqlite_max_height >= 0 &&
           persisted_active_tip_height >= 0 &&
           has_persisted_active_tip_hash &&
           persisted_active_tip_height <= sqlite_max_height &&
           persisted_active_tip_height >= sqlite_max_height - 1 &&
           sqlite_max_height < active_tip_height &&
           persisted_tip_matches_projection(
               ndb, persisted_active_tip_height,
               persisted_active_tip_hash);
}

/* Compute the active-tip hash mismatch flags. */
static void snapshot_classify_hash_agreement(
    struct node_db *ndb, struct chain_evidence_controller_view *out)
{
    /* node.db's blocks projection and the cec evidence follower do not share
     * one transaction: the projection can commit height H while the evidence
     * record still names H-1.  Both are durable frontiers behind the live
     * reducer/window tip, and a different hash is expected in that shape.
     *
     * Keep the carve-out deliberately narrow.  The persisted evidence must be
     * at the projection frontier or exactly one row behind it, its hash must
     * bind to the canonical projection row at that persisted height, and the
     * whole durable projection must be behind the live tip. A two-row evidence
     * gap, a persisted height ahead of the projection, a missing/corrupt
     * projection binding, or a same-height hash split remains
     * active_tip_hash_mismatch. csr_cursor_mismatch independently catches a
     * live active-tip/coins-tip split. */
    bool durable_frontier_lag =
        durable_frontier_lag_allows_hash_divergence(
            ndb, out->sqlite_max_height, out->active_tip_height,
            out->persisted_active_tip_height,
            out->has_persisted_active_tip_hash,
            &out->persisted_active_tip_hash);
    out->active_tip_hash_mismatch =
        out->has_active_tip_hash &&
        out->has_persisted_active_tip_hash &&
        !durable_frontier_lag &&
        !u256_equal(&out->active_tip_hash, &out->persisted_active_tip_hash);
    out->csr_cursor_mismatch =
        out->has_active_tip_hash &&
        out->has_coins_best_block_hash &&
        !u256_equal(&out->active_tip_hash, &out->coins_best_block_hash);
}

/* Fill health_reason from the first health flag that holds. */
static void snapshot_set_health_reason(
    struct chain_evidence_controller_view *out)
{
    if (out->state == CEC_CONTRADICTION_FROZEN) {
        snprintf(out->health_reason, sizeof(out->health_reason),
                 "%.127s", out->contradiction_reason[0]
                           ? out->contradiction_reason
                           : "chain_evidence_contradiction");
    } else if (out->active_tip_hash_mismatch) {
        snprintf(out->health_reason, sizeof(out->health_reason),
                 "active_tip_hash_mismatch");
    } else if (out->csr_cursor_mismatch) {
        snprintf(out->health_reason, sizeof(out->health_reason),
                 "csr_cursor_mismatch");
    } else if (out->publish_state_not_local) {
        snprintf(out->health_reason, sizeof(out->health_reason),
                 "publish_state_not_local");
    } else if (out->missing_active_tip_evidence) {
        snprintf(out->health_reason, sizeof(out->health_reason),
                 "missing_active_tip_evidence");
    }
}

void chain_evidence_controller_snapshot(
    struct chain_evidence_controller *authority,
    struct chain_evidence_controller_view *out)
{
    if (!out)
        return;
    snapshot_view_reset(out);
    if (!authority)
        return;

    /* A snapshot is an observation, never a reconciliation boundary. The
     * mutating loader may clear/backfill stale freeze state and can submit a
     * DB-service write; doing that while a diagnostic holds sqlite3_db_mutex
     * self-deadlocks against the DB worker. Boot init owns those repairs. */
    out->state = chain_evidence_controller_load_state_readonly(authority);
    snapshot_copy_csr_tips(authority, out);
    snapshot_load_persisted_markers(authority->ndb, out);
    snapshot_load_persisted_enums(authority->ndb, out);
    snapshot_load_evidence_records(authority->ndb, out);
    snprintf(out->contradiction_reason, sizeof(out->contradiction_reason),
             "%s", authority->contradiction_reason);
    snapshot_classify_tip_evidence(out);
    snapshot_classify_hash_agreement(authority->ndb, out);
    snapshot_set_health_reason(out);
}
