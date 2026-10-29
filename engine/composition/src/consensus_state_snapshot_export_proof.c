/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Frozen-source proof gate for zcl.consensus_state_bundle.v1 export. */

#include "consensus_state_snapshot_export_internal.h"
#include "base/bytes.h"
#include "consensus_state_sqlite_text.h"

#include "chain/checkpoints.h"
#include "crypto/sha3.h"
#include "jobs/reducer_frontier.h"
#include "jobs/refold_progress.h"
#include "jobs/tip_finalize_stage.h"
#include "platform/os_proc.h"
#include "platform/positioned_file.h"
#include "sapling/incremental_merkle_tree.h"
#include "storage/anchor_kv.h"
#include "storage/coins_kv.h"
#include "storage/coins_ram.h"
#include "storage/nullifier_kv.h"
#include "services/sync_trust_policy.h"
#include "util/log_macros.h"

#include <limits.h>
#include <stdio.h>
#include <string.h>

#define EXPORT_PROOF_SUBSYS "consensus_bundle_export"

static bool running_binary_digest(uint8_t out[32])
{
    char path[PATH_MAX];
    struct platform_positioned_file file;
    struct platform_positioned_file_snapshot before;
    struct platform_positioned_file_snapshot after;
    platform_positioned_file_init(&file);
    if (!os_proc_exe_path(path, sizeof(path)) ||
        !platform_positioned_file_open(&file, path) ||
        !platform_positioned_file_snapshot(&file, &before) ||
        before.size == 0) {
        platform_positioned_file_close(&file);
        LOG_WARN(EXPORT_PROOF_SUBSYS, "running executable open failed");
        return false;
    }
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    bool ok = consensus_state_hash_positioned_file(&file, before.size, &ctx);
    ok = ok && platform_positioned_file_snapshot(&file, &after) &&
         platform_positioned_file_snapshot_equal(&before, &after);
    platform_positioned_file_close(&file);
    if (ok)
        sha3_256_finalize(&ctx, out);
    else
        LOG_WARN(EXPORT_PROOF_SUBSYS, "running executable digest failed");
    return ok;
}

static bool copy_receipt_blob(sqlite3_stmt *st, int column, uint8_t out[32])
{
    if (sqlite3_column_type(st, column) != SQLITE_BLOB)
        return false;
    const void *blob = sqlite3_column_blob(st, column);
    if (!blob || sqlite3_column_bytes(st, column) != 32)
        return false;
    memcpy(out, blob, 32);
    return true;
}

/* The source_receipt row's text columns and the schema version they name. */
struct export_receipt_head {
    int commit_type;
    const unsigned char *commit;
    int commit_len;
    uint8_t version;
    bool schema_ok;
};

/* Only the v2 receipt schema may back an export; v1 is inspection-only. */
static void export_receipt_head_read(sqlite3_stmt *st, int rc,
                                     struct export_receipt_head *h)
{
    h->commit_type = rc == SQLITE_ROW ? sqlite3_column_type(st, 10)
                                      : SQLITE_NULL;
    h->commit = h->commit_type == SQLITE_TEXT
                    ? sqlite3_column_text(st, 10) : NULL;
    h->commit_len = h->commit ? sqlite3_column_bytes(st, 10) : -1;
    const unsigned char *schema =
        rc == SQLITE_ROW && sqlite3_column_type(st, 1) == SQLITE_TEXT
            ? sqlite3_column_text(st, 1) : NULL;
    int schema_len = schema ? sqlite3_column_bytes(st, 1) : -1;
    h->version = CONSENSUS_STATE_SOURCE_RECEIPT_INVALID;
    h->schema_ok = schema && schema_len >= 0 &&
        consensus_state_source_receipt_schema_version(
            (const char *)schema, (size_t)schema_len, &h->version) &&
        h->version == CONSENSUS_STATE_SOURCE_RECEIPT_V2;
}

static bool export_receipt_blobs_copy(
    sqlite3_stmt *st, struct consensus_state_source_receipt *receipt)
{
    return copy_receipt_blob(st, 2, receipt->source_epoch_digest) &&
           copy_receipt_blob(st, 3, receipt->source_tree_root) &&
           copy_receipt_blob(st, 4, receipt->running_binary_digest) &&
           copy_receipt_blob(st, 5, receipt->toolchain_digest) &&
           copy_receipt_blob(st, 6, receipt->build_inputs_digest) &&
           copy_receipt_blob(st, 7, receipt->chain_corpus_digest);
}

static bool export_receipt_scalars_typed(sqlite3_stmt *st,
                                         const struct export_receipt_head *h,
                                         int64_t fold_cursor)
{
    return sqlite3_column_type(st, 8) == SQLITE_INTEGER &&
           (sqlite3_column_int(st, 8) == 0 ||
            sqlite3_column_int(st, 8) == 1) &&
           sqlite3_column_type(st, 9) == SQLITE_INTEGER &&
           (sqlite3_column_int(st, 9) == CONSENSUS_STATE_VALIDATION_FULL ||
            sqlite3_column_int(st, 9) ==
                CONSENSUS_STATE_VALIDATION_CHECKPOINT_FOLD) &&
           h->commit_type == SQLITE_TEXT && h->commit_len >= 0 &&
           consensus_state_source_receipt_commit_valid(
               h->version, (const char *)h->commit, (size_t)h->commit_len) &&
           sqlite3_column_type(st, 11) == SQLITE_INTEGER &&
           sqlite3_column_int64(st, 11) == fold_cursor;
}

/* Decodes the single source_receipt row into *receipt and requires that no
 * second row follows. */
static bool export_receipt_row_read(
    sqlite3_stmt *st, int rc, const struct export_receipt_head *h,
    int64_t fold_cursor, struct consensus_state_source_receipt *receipt)
{
    bool ok = rc == SQLITE_ROW && h->commit &&
              sqlite3_column_type(st, 0) == SQLITE_INTEGER &&
              sqlite3_column_int(st, 0) == 1 && h->schema_ok &&
              export_receipt_blobs_copy(st, receipt) &&
              export_receipt_scalars_typed(st, h, fold_cursor) &&
              copy_receipt_blob(st, 12, receipt->receipt_digest);
    if (!ok)
        return false;
    receipt->schema_version = h->version;
    memcpy(receipt->producer_commit, h->commit, (size_t)h->commit_len);
    receipt->producer_commit[h->commit_len] = '\0';
    receipt->source_clean = sqlite3_column_int(st, 8) == 1;
    receipt->validation_profile = (uint8_t)sqlite3_column_int(st, 9);
    receipt->fold_cursor = sqlite3_column_int64(st, 11);
    return sqlite3_step(st) == SQLITE_DONE; // raw-sql-ok:progress-kv-kernel-store
}

static bool export_receipt_provenance_ok(
    const struct consensus_state_source_receipt *receipt,
    const uint8_t chain_corpus_digest[32], bool checkpoint_content_export)
{
    uint8_t executable[32];
    return zcl_bytes_any_set(receipt->source_epoch_digest, 32) &&
           zcl_bytes_any_set(receipt->source_tree_root, 32) &&
           zcl_bytes_any_set(receipt->toolchain_digest, 32) &&
           zcl_bytes_any_set(receipt->build_inputs_digest, 32) &&
           consensus_state_source_receipt_commit_valid(
               receipt->schema_version, receipt->producer_commit,
               strnlen(receipt->producer_commit,
                       sizeof(receipt->producer_commit))) &&
           memcmp(receipt->chain_corpus_digest, chain_corpus_digest, 32) == 0 &&
           /* Fold-binary provenance vs checkpoint-content proof. The default
            * export binds the receipt to the running binary that folded the
            * state. The checkpoint-content path (caller-gated by an exact
            * compiled-checkpoint + PoW-header content match in
            * prove_checkpoint_content) instead only requires the receipt's
            * running-binary digest to be well-formed (nonzero) — the state's
            * authority comes from the SHA3 + header-root proof, not from
            * re-running the exact fold binary. No downstream gate re-checks
            * this digest, so the emitted bundle is byte-identical in shape. */
           (checkpoint_content_export
                ? zcl_bytes_any_set(receipt->running_binary_digest, 32)
                : (running_binary_digest(executable) &&
                   memcmp(receipt->running_binary_digest, executable, 32) ==
                       0));
}

/* Recomputes the source epoch and receipt digests; *recomputed receives the
 * receipt digest. */
static bool export_receipt_digests_ok(
    const struct consensus_state_source_receipt *receipt,
    uint8_t recomputed[32])
{
    uint8_t source_epoch[32];
    consensus_state_source_epoch_digest(receipt, source_epoch);
    consensus_state_source_receipt_digest(receipt, recomputed);
    return memcmp(receipt->source_epoch_digest, source_epoch, 32) == 0 &&
           memcmp(receipt->receipt_digest, recomputed, 32) == 0 &&
           zcl_bytes_any_set(recomputed, 32);
}

static bool prove_source_receipt(sqlite3 *db, int64_t fold_cursor,
                                 const uint8_t chain_corpus_digest[32],
                                 bool checkpoint_content_export,
                                 struct consensus_state_source_receipt *receipt,
                                 uint8_t source_digest[32])
{
    static const char sql[] =
        "SELECT singleton,schema,source_epoch_digest,source_tree_root,"
        "running_binary_digest,toolchain_digest,build_inputs_digest,"
        "chain_corpus_digest,source_clean,validation_profile,producer_commit,"
        "fold_cursor,receipt_digest "
        "FROM consensus_state_source_receipt ORDER BY singleton";
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) {
        LOG_WARN(EXPORT_PROOF_SUBSYS, "source provenance receipt unavailable");
        return false;
    }
    memset(receipt, 0, sizeof(*receipt));
    int rc = sqlite3_step(st); // raw-sql-ok:progress-kv-kernel-store
    struct export_receipt_head head;
    export_receipt_head_read(st, rc, &head);
    bool ok = export_receipt_row_read(st, rc, &head, fold_cursor, receipt);
    sqlite3_finalize(st);
    uint8_t recomputed[32];
    if (ok)
        ok = export_receipt_provenance_ok(receipt, chain_corpus_digest,
                                          checkpoint_content_export);
    if (ok)
        ok = export_receipt_digests_ok(receipt, recomputed);
    if (!ok) {
        LOG_WARN(EXPORT_PROOF_SUBSYS,
                 "source provenance receipt missing, malformed, stale, or "
                 "legacy inspection-only v1");
        return false;
    }
    memcpy(source_digest, recomputed, 32);
    return true;
}

static bool read_cursor(sqlite3 *db, const char *name, uint64_t *out)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT cursor FROM stage_cursor WHERE name=?", -1, &st,
            NULL) != SQLITE_OK) {
        LOG_WARN(EXPORT_PROOF_SUBSYS, "cursor prepare failed stage=%s: %s",
                 name, sqlite3_errmsg(db));
        return false;
    }
    bool ok = sqlite3_bind_text(st, 1, name, -1, SQLITE_STATIC) == SQLITE_OK;
    int rc = ok ? sqlite3_step(st) : SQLITE_ERROR; // raw-sql-ok:progress-kv-kernel-store
    if (rc == SQLITE_ROW && sqlite3_column_type(st, 0) == SQLITE_INTEGER &&
        sqlite3_column_int64(st, 0) >= 0) {
        *out = (uint64_t)sqlite3_column_int64(st, 0);
        rc = sqlite3_step(st); // raw-sql-ok:progress-kv-kernel-store
        ok = rc == SQLITE_DONE;
    } else {
        ok = false;
    }
    sqlite3_finalize(st);
    if (!ok)
        LOG_WARN(EXPORT_PROOF_SUBSYS,
                 "cursor missing/malformed stage=%s", name);
    return ok;
}

/* Cryptographic checkpoint-content proof that authorizes a checkpoint-content
 * export in place of the fold-binary-identity receipt gate. Every rung is a
 * content fact:
 *   1. expected_height == the compiled SHA3 UTXO checkpoint height (the export
 *      is only admissible AT the checkpoint — the strongest content anchor);
 *   2. the frozen transparent coins reproduce the checkpoint's SHA3 + count
 *      bit-for-bit (coins_kv_commitment canonically encodes each coin's value,
 *      so a matching SHA3 also fixes the total supply — no separate scan);
 *   3. the Sapling tip frontier Pedersen-roots to the block header's committed
 *      hashFinalSaplingRoot at that height (checkpoint_sapling_root, supplied
 *      from this node's validated header chain) — the shielded tip is bound to
 *      PoW. The install side re-derives this same binding against block_index;
 *      requiring it here fails a header-inconsistent frontier at export time.
 * Any mismatch refuses and emits nothing. Does not mutate the source. */
static bool prove_checkpoint_content(
    sqlite3 *source,
    const struct consensus_state_snapshot_export_request *request,
    struct consensus_state_export_result *result)
{
    int64_t t0 = consensus_export_clock_ms();
    consensus_export_progress_emit(
        "prove_checkpoint_content start height=%d", request->expected_height);
    const struct sha3_utxo_checkpoint *cp = get_sha3_utxo_checkpoint();
    if (!cp)
        return consensus_export_fail(
            result, CONSENSUS_EXPORT_MISSING_PROOF,
            "no compiled SHA3 UTXO checkpoint to bind the export against");
    if (request->expected_height != cp->height)
        return consensus_export_fail(
            result, CONSENSUS_EXPORT_MISSING_PROOF,
            "checkpoint-content export is admissible only at the compiled "
            "checkpoint height (want=%d got=%d)",
            cp->height, request->expected_height);

    uint8_t coins_sha3[32];
    if (coins_kv_commitment(source, coins_sha3) != 0)
        return consensus_export_fail(result, CONSENSUS_EXPORT_STORE_ERROR,
                                     "coins commitment computation failed");
    int64_t coins_count = coins_kv_count(source);
    if (coins_count < 0)
        return consensus_export_fail(result, CONSENSUS_EXPORT_STORE_ERROR,
                                     "coins count read failed");
    if (memcmp(coins_sha3, cp->sha3_hash, 32) != 0 ||
        (uint64_t)coins_count != cp->utxo_count) {
        char derived_hex[65], expected_hex[65];
        for (int i = 0; i < 32; i++) {
            snprintf(derived_hex + 2 * i, 3, "%02x", coins_sha3[i]);
            snprintf(expected_hex + 2 * i, 3, "%02x", cp->sha3_hash[i]);
        }
        return consensus_export_fail(
            result, CONSENSUS_EXPORT_MISSING_PROOF,
            "coins do not reproduce the compiled SHA3 UTXO checkpoint "
            "(sha3 derived=%s expected=%s count derived=%lld expected=%llu)",
            derived_hex, expected_hex, (long long)coins_count,
            (unsigned long long)cp->utxo_count);
    }

    struct incremental_merkle_tree sapling_tip;
    struct uint256 sapling_root;
    int64_t sapling_height = -1;
    if (anchor_kv_latest_tree(source, ANCHOR_POOL_SAPLING, &sapling_tip,
                              &sapling_root, &sapling_height) != ANCHOR_KV_FOUND)
        return consensus_export_fail(
            result, CONSENSUS_EXPORT_MISSING_PROOF,
            "Sapling tip frontier is absent; cannot bind it to the PoW header "
            "committed final Sapling root");
    if (memcmp(sapling_root.data, request->checkpoint_sapling_root, 32) != 0) {
        char derived_hex[65], expected_hex[65];
        for (int i = 0; i < 32; i++) {
            snprintf(derived_hex + 2 * i, 3, "%02x", sapling_root.data[i]);
            snprintf(expected_hex + 2 * i, 3, "%02x",
                     request->checkpoint_sapling_root[i]);
        }
        return consensus_export_fail(
            result, CONSENSUS_EXPORT_MISSING_PROOF,
            "Sapling tip frontier does not Pedersen-root to the header "
            "committed hashFinalSaplingRoot at sapling_anchor_height=%lld "
            "derived=%s expected=%s",
            (long long)sapling_height, derived_hex, expected_hex);
    }
    consensus_export_progress_emit(
        "prove_checkpoint_content done height=%d elapsed=%lldms",
        request->expected_height,
        (long long)(consensus_export_clock_ms() - t0));
    return true;
}

static bool export_check_coins_authority(
    sqlite3 *source, struct consensus_state_export_result *result)
{
    if (coins_ram_active())
        return consensus_export_fail(
            result, CONSENSUS_EXPORT_MISSING_PROOF,
            "durable export refused while coins RAM overlay is active");
    bool proven_authority = coins_kv_is_proven_authority(source, NULL);
    bool refold_marker = coins_kv_contains_refold_marker(source);
    /* Route ONLY the provenance-bit portion through the central trust table
     * (services/sync_trust_policy.h). EXPORT_BUNDLE is granted exactly in the
     * X states (proven && refold), independent of self_derived, so that input
     * is immaterial here and passed false. The derived answer is identical to
     * the old `!proven_authority || !refold_marker` gate; every other rung
     * (coins_ram, cursors, receipt, H*, served-tip hash) stays in place. */
    if (!sync_trust_cap_allowed(
            sync_trust_derive(proven_authority, refold_marker,
                              /*self_derived=*/false),
            SYNC_CAP_EXPORT_BUNDLE))
        return consensus_export_fail(
            result, CONSENSUS_EXPORT_MISSING_PROOF,
            "coins source lacks durable migration and self-folded proof "
            "(proven_authority=%d refold_marker=%d)",
            proven_authority ? 1 : 0, refold_marker ? 1 : 0);
    return true;
}

static bool export_check_applied_height(
    sqlite3 *source,
    const struct consensus_state_snapshot_export_request *request,
    struct consensus_state_export_result *result)
{
    int32_t applied = -1;
    bool applied_found = false;
    if (!coins_kv_get_applied_height(source, &applied, &applied_found))
        return consensus_export_fail(result, CONSENSUS_EXPORT_STORE_ERROR,
                                     "coins applied-height read failed");
    if (!applied_found || applied != request->expected_height + 1)
        return consensus_export_fail(
            result, CONSENSUS_EXPORT_MISSING_PROOF,
            "coins applied-height does not equal expected H+1 "
            "(applied=%d found=%d expected=%d)",
            applied, applied_found ? 1 : 0, request->expected_height + 1);
    return true;
}

static bool export_check_shielded_history(
    sqlite3 *source, struct consensus_state_export_result *result)
{
    int64_t sprout_cursor = -1;
    int64_t sapling_cursor = -1;
    int64_t nullifier_cursor = -1;
    bool sprout_found = false;
    bool sapling_found = false;
    bool nullifier_found = false;
    if (!anchor_kv_activation_cursor(source, ANCHOR_POOL_SPROUT,
                                     &sprout_cursor, &sprout_found) ||
        !anchor_kv_activation_cursor(source, ANCHOR_POOL_SAPLING,
                                     &sapling_cursor, &sapling_found) ||
        !nullifier_kv_activation_cursor(source, &nullifier_cursor,
                                        &nullifier_found))
        return consensus_export_fail(result, CONSENSUS_EXPORT_STORE_ERROR,
                                     "shielded activation cursor read failed");
    if (!sprout_found || !sapling_found || !nullifier_found ||
        sprout_cursor != 0 || sapling_cursor != 0 || nullifier_cursor != 0)
        return consensus_export_fail(
            result, CONSENSUS_EXPORT_MISSING_PROOF,
            "shielded history is not explicitly complete from genesis "
            "(sprout=%lld/found=%d sapling=%lld/found=%d "
            "nullifier=%lld/found=%d want=0/found=1)",
            (long long)sprout_cursor, sprout_found ? 1 : 0,
            (long long)sapling_cursor, sapling_found ? 1 : 0,
            (long long)nullifier_cursor, nullifier_found ? 1 : 0);
    return true;
}

static bool export_check_header_cursor(
    sqlite3 *source,
    const struct consensus_state_snapshot_export_request *request,
    uint64_t *header_cursor, struct consensus_state_export_result *result)
{
    *header_cursor = 0;
    if (!read_cursor(source, "header_admit", header_cursor) ||
        *header_cursor < (uint64_t)request->expected_height + 1)
        return consensus_export_fail(
            result, CONSENSUS_EXPORT_MISSING_PROOF,
            "header reducer cursor does not cover requested height "
            "(cursor=%llu required=%lld)",
            (unsigned long long)*header_cursor,
            (long long)request->expected_height + 1);
    return true;
}

static void export_manifest_init(
    struct consensus_state_bundle_manifest *manifest,
    const struct consensus_state_snapshot_export_request *request)
{
    memset(manifest, 0, sizeof(*manifest));
    manifest->height = request->expected_height;
    memcpy(manifest->block_hash, request->expected_block_hash, 32);
    manifest->history_complete = true;
    manifest->activation_boundary = 0;
    manifest->sprout_source_cursor = 0;
    manifest->sapling_source_cursor = 0;
    manifest->nullifier_source_cursor = 0;
    manifest->source_fold_cursor = (int64_t)request->expected_height + 1;
}

/* Proves the source receipt and binds the manifest to it. */
static bool export_prove_receipt(
    sqlite3 *source,
    const struct consensus_state_snapshot_export_request *request,
    struct consensus_state_bundle_manifest *manifest,
    struct consensus_state_source_receipt *receipt,
    const uint8_t chain_corpus_digest[32],
    struct consensus_state_export_result *result)
{
    /* Checkpoint-content export authority: a compiled-checkpoint + PoW-header
     * content proof that authorizes relaxing the receipt's fold-binary-identity
     * bind below. It TIGHTENS the admission (exact checkpoint coins SHA3 + count
     * + header Sapling-root match) — every other rung stays identical. */
    if (request->checkpoint_content_export &&
        !prove_checkpoint_content(source, request, result))
        return false;
    if (!prove_source_receipt(source, manifest->source_fold_cursor,
                              chain_corpus_digest,
                              request->checkpoint_content_export, receipt,
                              manifest->source_digest))
        return consensus_export_fail(
            result, CONSENSUS_EXPORT_MISSING_PROOF,
            "durable producer source provenance receipt unavailable");
    manifest->validation_profile = receipt->validation_profile;
    manifest->source_clean = receipt->source_clean;
    if (manifest->validation_profile != CONSENSUS_STATE_VALIDATION_FULL)
        return consensus_export_fail(
            result, CONSENSUS_EXPORT_MISSING_PROOF,
            "checkpoint-fold state is non-serving producer evidence and "
            "cannot be published by the canonical bundle exporter "
            "(validation_profile=%u required=%u)",
            (unsigned)manifest->validation_profile,
            (unsigned)CONSENSUS_STATE_VALIDATION_FULL);
    return true;
}

/* Bind the SERVED tip's own block hash. H* (== expected_height, proven by the
 * caller) IS the reducer's provable served tip, so the height is already bound
 * exactly — the remaining property is that the served tip owns
 * expected_block_hash. Read that height's hash witness CONVENTION-AWARE via
 * tip_finalize_stage_block_hash_at (the finalized ok=1 row at
 * expected_height-1 carries the LOOKAHEAD hash(expected_height); an anchor seed
 * row at expected_height carries its own hash) — the same served-tip hash
 * binding derive_coins_best uses at applied-1. Do NOT resolve via the cursor:
 * a fold-to-anchor producer's tip_finalize cursor sits at expected_height+1
 * (the H+1 steady-state convention), so tip_finalize_stage_resolve_durable_tip
 * floats one above the served tip through the finalized lookahead — a
 * different notion from the served H* that false-rejects a complete
 * producer. */
static bool export_check_served_tip(
    sqlite3 *source,
    const struct consensus_state_snapshot_export_request *request,
    struct consensus_state_export_result *result)
{
    uint8_t served_tip_hash[32] = {0};
    bool served_tip_witness_found = tip_finalize_stage_block_hash_at(
        source, request->expected_height, served_tip_hash);
    if (served_tip_witness_found &&
        memcmp(served_tip_hash, request->expected_block_hash, 32) == 0)
        return true;
    char derived_hex[65], expected_hex[65];
    for (int i = 0; i < 32; i++) {
        snprintf(derived_hex + 2 * i, 3, "%02x", served_tip_hash[i]);
        snprintf(expected_hex + 2 * i, 3, "%02x",
                 request->expected_block_hash[i]);
    }
    return consensus_export_fail(
        result, CONSENSUS_EXPORT_MISSING_PROOF,
        "durable served tip does not own expected height=%d "
        "witness_found=%d derived=%s expected=%s",
        request->expected_height, served_tip_witness_found ? 1 : 0,
        derived_hex, expected_hex);
}

/* The frozen source must be the exact durable reducer generation. */
static bool export_check_generation(
    sqlite3 *source,
    const struct consensus_state_snapshot_export_request *request,
    struct consensus_state_export_result *result)
{
    /* Refresh the durable refold mode before computing H*: its floor is a
     * cached atomic, so a stale process value can otherwise validate the
     * wrong lattice. H* and the convention-aware durable tip must both name
     * this exact generation. */
    if (!refold_progress_refresh(source))
        return consensus_export_fail(result, CONSENSUS_EXPORT_STORE_ERROR,
                                     "durable refold mode refresh failed");
    int32_t hstar = -1;
    int32_t served_floor = -1;
    if (!reducer_frontier_compute_hstar(source, &hstar, &served_floor))
        return consensus_export_fail(result, CONSENSUS_EXPORT_STORE_ERROR,
                                     "reducer H* computation failed");
    if (hstar != request->expected_height ||
        served_floor < request->expected_height)
        return consensus_export_fail(
            result, CONSENSUS_EXPORT_MISSING_PROOF,
            "frozen source is not the exact durable reducer generation "
            "(hstar=%d served_floor=%d expected=%d)",
            hstar, served_floor, request->expected_height);
    return export_check_served_tip(source, request, result);
}

static void export_header_proof_fill(
    struct consensus_state_bundle_proof_summary *proof,
    const struct consensus_state_snapshot_export_request *request,
    uint64_t header_cursor, const uint8_t chain_corpus_digest[32])
{
    snprintf(proof->component, sizeof(proof->component), "header_admit");
    proof->cursor = header_cursor;
    proof->first_height = 0;
    proof->last_height = request->expected_height;
    proof->row_count = (uint64_t)request->expected_height + 1;
    proof->hash_bound_count = proof->row_count;
    memcpy(proof->component_digest, chain_corpus_digest, 32);
}

/* Proves one reducer stage: its cursor covers the frozen generation and its
 * source rows are complete. */
static bool export_prove_stage(
    sqlite3 *source, size_t i,
    const struct consensus_state_snapshot_export_request *request,
    const struct consensus_state_bundle_manifest *manifest,
    const struct consensus_state_source_receipt *receipt,
    struct consensus_state_bundle_proof_summary *proofs,
    struct consensus_state_bundle_proof_parent *parent,
    struct consensus_state_export_result *result)
{
    uint64_t cursor = 0;
    if (!read_cursor(source, k_stages[i].name, &cursor))
        return consensus_export_fail(
            result, CONSENSUS_EXPORT_MISSING_PROOF,
            "required reducer cursor is unavailable stage=%s",
            k_stages[i].name);
    uint64_t required = k_stages[i].served_tip_cursor
                            ? (uint64_t)request->expected_height
                            : (uint64_t)request->expected_height + 1;
    bool cursor_ok = k_stages[i].served_tip_cursor
                         ? cursor >= required && cursor <= required + 1
                         : cursor >= required;
    if (!cursor_ok)
        return consensus_export_fail(
            result, CONSENSUS_EXPORT_MISSING_PROOF,
            "reducer cursor does not cover frozen generation stage=%s "
            "cursor=%llu required=%llu",
            k_stages[i].name, (unsigned long long)cursor,
            (unsigned long long)required);
    if (strcmp(k_stages[i].name, "utxo_apply") == 0 &&
        cursor != (uint64_t)request->expected_height + 1)
        return consensus_export_fail(
            result, CONSENSUS_EXPORT_MISSING_PROOF,
            "utxo cursor does not equal frozen coin generation "
            "cursor=%llu expected=%lld",
            (unsigned long long)cursor,
            (long long)request->expected_height + 1);
    if (!consensus_export_prove_stage_rows(
            source, &k_stages[i], request->expected_height, cursor,
            manifest->validation_profile, receipt->source_epoch_digest,
            &proofs[i + 1], parent, i + 1))
        return consensus_export_fail(
            result, CONSENSUS_EXPORT_MISSING_PROOF,
            "complete reducer proof rows unavailable stage=%s",
            k_stages[i].name);
    return true;
}

bool consensus_export_prove_source(
    sqlite3 *source,
    const struct consensus_state_snapshot_export_request *request,
    struct consensus_state_bundle_manifest *manifest,
    struct consensus_state_source_receipt *receipt,
    struct consensus_state_bundle_proof_summary
        proofs[CONSENSUS_STATE_BUNDLE_PROOF_COUNT],
    struct consensus_state_bundle_proof_parent *parent,
    struct consensus_state_export_result *result)
{
    int64_t prove_t0 = consensus_export_clock_ms();
    consensus_export_progress_emit(
        "consensus_export_prove_source start height=%d",
        request->expected_height);
    uint64_t header_cursor = 0;
    if (!export_check_coins_authority(source, result) ||
        !export_check_applied_height(source, request, result) ||
        !export_check_shielded_history(source, result) ||
        !export_check_header_cursor(source, request, &header_cursor, result))
        return false;

    export_manifest_init(manifest, request);
    uint8_t chain_corpus_digest[32];
    if (!consensus_export_prove_header_chain(
            source, request->expected_height, request->expected_block_hash,
            chain_corpus_digest, parent))
        return consensus_export_fail(
            result, CONSENSUS_EXPORT_MISSING_PROOF,
            "complete genesis-to-height header proof is unavailable "
            "(height=%d)",
            request->expected_height);
    if (!export_prove_receipt(source, request, manifest, receipt,
                              chain_corpus_digest, result) ||
        !export_check_generation(source, request, result))
        return false;

    memset(proofs, 0, sizeof(*proofs) * CONSENSUS_STATE_BUNDLE_PROOF_COUNT);
    export_header_proof_fill(&proofs[0], request, header_cursor,
                             chain_corpus_digest);
    for (size_t i = 0; i < sizeof(k_stages) / sizeof(k_stages[0]); i++)
        if (!export_prove_stage(source, i, request, manifest, receipt,
                                proofs, parent, result))
            return false;
    consensus_state_bundle_proof_manifest_digest(
        proofs, CONSENSUS_STATE_BUNDLE_PROOF_COUNT,
        manifest->proof_manifest_digest);
    consensus_export_progress_emit(
        "consensus_export_prove_source done height=%d elapsed=%lldms",
        request->expected_height,
        (long long)(consensus_export_clock_ms() - prove_t0));
    return true;
}
