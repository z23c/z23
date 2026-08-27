/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Frozen-source proof gate for zcl.consensus_state_bundle.v1 export. */

#include "consensus_state_snapshot_export_internal.h"
#include "consensus_state_sqlite_text.h"

#include "chain/checkpoints.h"
#include "crypto/sha3.h"
#include "jobs/reducer_frontier.h"
#include "jobs/refold_progress.h"
#include "jobs/tip_finalize_stage.h"
#include "sapling/incremental_merkle_tree.h"
#include "storage/anchor_kv.h"
#include "storage/coins_kv.h"
#include "storage/coins_ram.h"
#include "storage/nullifier_kv.h"
#include "services/sync_trust_policy.h"
#include "util/log_macros.h"

#include <errno.h>
#include <limits.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define EXPORT_PROOF_SUBSYS "consensus_bundle_export"

static bool digest_nonzero(const uint8_t digest[32])
{
    uint8_t any = 0;
    for (size_t i = 0; i < 32; i++)
        any |= digest[i];
    return any != 0;
}

static bool running_binary_digest(uint8_t out[32])
{
    int fd = open("/proc/self/exe", O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        LOG_WARN(EXPORT_PROOF_SUBSYS, "running executable open failed");
        return false;
    }
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    uint8_t buffer[32768];
    bool ok = true;
    for (;;) {
        ssize_t n = read(fd, buffer, sizeof(buffer));
        if (n > 0) {
            sha3_256_write(&ctx, buffer, (size_t)n);
            continue;
        }
        if (n == 0)
            break;
        if (errno == EINTR)
            continue;
        ok = false;
        break;
    }
    if (close(fd) != 0)
        ok = false;
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
    int commit_type = rc == SQLITE_ROW ? sqlite3_column_type(st, 10)
                                       : SQLITE_NULL;
    const unsigned char *commit = commit_type == SQLITE_TEXT
                                      ? sqlite3_column_text(st, 10) : NULL;
    int commit_len = commit ? sqlite3_column_bytes(st, 10) : -1;
    const unsigned char *schema =
        rc == SQLITE_ROW && sqlite3_column_type(st, 1) == SQLITE_TEXT
            ? sqlite3_column_text(st, 1) : NULL;
    int schema_len = schema ? sqlite3_column_bytes(st, 1) : -1;
    uint8_t receipt_version = CONSENSUS_STATE_SOURCE_RECEIPT_INVALID;
    bool schema_ok = schema && schema_len >= 0 &&
        consensus_state_source_receipt_schema_version(
            (const char *)schema, (size_t)schema_len, &receipt_version) &&
        receipt_version == CONSENSUS_STATE_SOURCE_RECEIPT_V2;
    bool ok = rc == SQLITE_ROW && commit &&
              sqlite3_column_type(st, 0) == SQLITE_INTEGER &&
              sqlite3_column_int(st, 0) == 1 &&
              schema_ok &&
              copy_receipt_blob(st, 2, receipt->source_epoch_digest) &&
              copy_receipt_blob(st, 3, receipt->source_tree_root) &&
              copy_receipt_blob(st, 4, receipt->running_binary_digest) &&
              copy_receipt_blob(st, 5, receipt->toolchain_digest) &&
              copy_receipt_blob(st, 6, receipt->build_inputs_digest) &&
              copy_receipt_blob(st, 7, receipt->chain_corpus_digest) &&
              sqlite3_column_type(st, 8) == SQLITE_INTEGER &&
              (sqlite3_column_int(st, 8) == 0 ||
               sqlite3_column_int(st, 8) == 1) &&
              sqlite3_column_type(st, 9) == SQLITE_INTEGER &&
              (sqlite3_column_int(st, 9) == CONSENSUS_STATE_VALIDATION_FULL ||
               sqlite3_column_int(st, 9) ==
                   CONSENSUS_STATE_VALIDATION_CHECKPOINT_FOLD) &&
              commit_type == SQLITE_TEXT &&
              commit_len >= 0 &&
              consensus_state_source_receipt_commit_valid(
                  receipt_version, (const char *)commit,
                  (size_t)commit_len) &&
              sqlite3_column_type(st, 11) == SQLITE_INTEGER &&
              sqlite3_column_int64(st, 11) == fold_cursor &&
              copy_receipt_blob(st, 12, receipt->receipt_digest);
    if (ok) {
        receipt->schema_version = receipt_version;
        memcpy(receipt->producer_commit, commit, (size_t)commit_len);
        receipt->producer_commit[commit_len] = '\0';
        receipt->source_clean = sqlite3_column_int(st, 8) == 1;
        receipt->validation_profile =
            (uint8_t)sqlite3_column_int(st, 9);
        receipt->fold_cursor = sqlite3_column_int64(st, 11);
        rc = sqlite3_step(st); // raw-sql-ok:progress-kv-kernel-store
        ok = rc == SQLITE_DONE;
    }
    sqlite3_finalize(st);
    uint8_t executable[32];
    uint8_t recomputed[32];
    uint8_t source_epoch[32];
    if (ok)
        ok = digest_nonzero(receipt->source_epoch_digest) &&
             digest_nonzero(receipt->source_tree_root) &&
             digest_nonzero(receipt->toolchain_digest) &&
             digest_nonzero(receipt->build_inputs_digest) &&
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
                  ? digest_nonzero(receipt->running_binary_digest)
                  : (running_binary_digest(executable) &&
                     memcmp(receipt->running_binary_digest, executable, 32) ==
                         0));
    if (ok) {
        consensus_state_source_epoch_digest(receipt, source_epoch);
        consensus_state_source_receipt_digest(receipt, recomputed);
        ok = memcmp(receipt->source_epoch_digest, source_epoch, 32) == 0 &&
             memcmp(receipt->receipt_digest, recomputed, 32) == 0 &&
             digest_nonzero(recomputed);
    }
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

bool consensus_export_prove_source(
    sqlite3 *source,
    const struct consensus_state_snapshot_export_request *request,
    struct consensus_state_bundle_manifest *manifest,
    struct consensus_state_source_receipt *receipt,
    struct consensus_state_bundle_proof_summary
        proofs[CONSENSUS_STATE_BUNDLE_PROOF_COUNT],
    struct consensus_state_export_result *result)
{
    int64_t prove_t0 = consensus_export_clock_ms();
    consensus_export_progress_emit(
        "consensus_export_prove_source start height=%d",
        request->expected_height);
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

    uint64_t header_cursor = 0;
    if (!read_cursor(source, "header_admit", &header_cursor) ||
        header_cursor < (uint64_t)request->expected_height + 1)
        return consensus_export_fail(
            result, CONSENSUS_EXPORT_MISSING_PROOF,
            "header reducer cursor does not cover requested height "
            "(cursor=%llu required=%lld)",
            (unsigned long long)header_cursor,
            (long long)request->expected_height + 1);

    memset(manifest, 0, sizeof(*manifest));
    manifest->height = request->expected_height;
    memcpy(manifest->block_hash, request->expected_block_hash, 32);
    manifest->history_complete = true;
    manifest->activation_boundary = 0;
    manifest->sprout_source_cursor = 0;
    manifest->sapling_source_cursor = 0;
    manifest->nullifier_source_cursor = 0;
    manifest->source_fold_cursor = (int64_t)request->expected_height + 1;
    uint8_t chain_corpus_digest[32];
    if (!consensus_export_prove_header_chain(source, request->expected_height,
                                             request->expected_block_hash,
                                             chain_corpus_digest))
        return consensus_export_fail(
            result, CONSENSUS_EXPORT_MISSING_PROOF,
            "complete genesis-to-height header proof is unavailable "
            "(height=%d)",
            request->expected_height);

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
    /* Bind the SERVED tip's own block hash. H* (== expected_height, proven
     * just above) IS the reducer's provable served tip, so the height is
     * already bound exactly — the remaining property is that the served tip
     * owns expected_block_hash. Read that height's hash witness CONVENTION-
     * AWARE via tip_finalize_stage_block_hash_at (the finalized ok=1 row at
     * expected_height-1 carries the LOOKAHEAD hash(expected_height); an anchor
     * seed row at expected_height carries its own hash) — the same served-tip
     * hash binding derive_coins_best uses at applied-1. Do NOT resolve via the
     * cursor: a fold-to-anchor producer's tip_finalize cursor sits at
     * expected_height+1 (the H+1 steady-state convention), so
     * tip_finalize_stage_resolve_durable_tip floats one above the served tip
     * through the finalized lookahead — a different notion from the served H*
     * that false-rejects a complete producer. */
    uint8_t served_tip_hash[32] = {0};
    bool served_tip_witness_found = tip_finalize_stage_block_hash_at(
        source, request->expected_height, served_tip_hash);
    if (!served_tip_witness_found ||
        memcmp(served_tip_hash, request->expected_block_hash, 32) != 0) {
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

    memset(proofs, 0, sizeof(*proofs) * CONSENSUS_STATE_BUNDLE_PROOF_COUNT);
    snprintf(proofs[0].component, sizeof(proofs[0].component),
             "header_admit");
    proofs[0].cursor = header_cursor;
    proofs[0].first_height = 0;
    proofs[0].last_height = request->expected_height;
    proofs[0].row_count = (uint64_t)request->expected_height + 1;
    proofs[0].hash_bound_count = proofs[0].row_count;
    memcpy(proofs[0].component_digest, chain_corpus_digest, 32);

    for (size_t i = 0; i < sizeof(k_stages) / sizeof(k_stages[0]); i++) {
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
                &proofs[i + 1]))
            return consensus_export_fail(
                result, CONSENSUS_EXPORT_MISSING_PROOF,
                "complete reducer proof rows unavailable stage=%s",
                k_stages[i].name);
    }
    consensus_state_bundle_proof_manifest_digest(
        proofs, CONSENSUS_STATE_BUNDLE_PROOF_COUNT,
        manifest->proof_manifest_digest);
    consensus_export_progress_emit(
        "consensus_export_prove_source done height=%d elapsed=%lldms",
        request->expected_height,
        (long long)(consensus_export_clock_ms() - prove_t0));
    return true;
}
