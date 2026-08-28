/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Read-only, recompute-never-trust evidence for shop fulfillments. */

#include "services/shop_fulfill_evidence_service.h"

#include "base/hex.h"
#include "base/safe_alloc.h"
#include "crypto/ed25519.h"
#include "models/build_fabric.h"
#include "platform/positioned_file.h"
#include "services/build_fabric_service.h"
#include "services/zcode_benchmark_executor.h"
#include "services/zcode_science_service.h"
#include "sha3/sha3.h"
#include "util/log_macros.h"
#include "vcs/build_action.h"
#include "vcs/package_manifest.h"
#include "vcs/vcs_object.h"
#include "vcs/zcode_science.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SFE_TAG "shop.fulfill.evidence"
#define SFE_PATH_MAX 4400u
#define SFE_HASH_BUFFER 65536u

static bool sfe_nonzero(const uint8_t value[32])
{
    uint8_t any = 0;
    if (!value) return false;
    for (size_t i = 0; i < 32; i++) any |= value[i];
    return any != 0;
}

static bool sfe_same_snapshot(
    const struct platform_positioned_file_snapshot *a,
    const struct platform_positioned_file_snapshot *b)
{
    return a->size == b->size &&
           a->modified_seconds == b->modified_seconds &&
           a->modified_nanoseconds == b->modified_nanoseconds &&
           a->changed_seconds == b->changed_seconds &&
           a->changed_nanoseconds == b->changed_nanoseconds &&
           a->volume == b->volume && a->file_low == b->file_low &&
           a->file_high == b->file_high;
}

static struct zcl_result artifact_fail(
    struct shop_fulfill_artifact_fact *out, const char *reason)
{
    if (out)
        (void)snprintf(out->reason, sizeof(out->reason), "%.95s", reason);
    LOG_ERROR(SFE_TAG, "artifact evidence refused: %s", reason);
    return ZCL_ERR(-1, "artifact evidence refused: %s", reason);
}

static struct zcl_result receipt_fail(
    struct shop_fulfill_receipt_fact *out, const char *reason)
{
    if (out)
        (void)snprintf(out->reason, sizeof(out->reason), "%.95s", reason);
    LOG_ERROR(SFE_TAG, "receipt evidence refused: %s", reason);
    return ZCL_ERR(-2, "receipt evidence refused: %s", reason);
}

static bool sfe_read_bounded(const char *path, size_t cap,
                             uint8_t **out, size_t *out_len)
{
    *out = NULL;
    *out_len = 0;
    struct platform_positioned_file file;
    platform_positioned_file_init(&file);
    if (!platform_positioned_file_open(&file, path))
        LOG_FAIL(SFE_TAG, "open bounded evidence failed: %s", path);
    struct platform_positioned_file_snapshot before, after;
    if (!platform_positioned_file_snapshot(&file, &before) ||
        before.size == 0 || before.size > cap || before.size > SIZE_MAX) {
        platform_positioned_file_close(&file);
        LOG_FAIL(SFE_TAG, "manifest is not a bounded regular file: %s", path);
    }
    size_t len = (size_t)before.size;
    uint8_t *bytes = zcl_malloc(len, "shop fulfillment manifest");
    if (!bytes) {
        platform_positioned_file_close(&file);
        LOG_FAIL(SFE_TAG, "manifest allocation failed: %zu", len);
    }
    size_t off = 0;
    while (off < len) {
        int64_t got = platform_positioned_file_read(
            &file, bytes + off, len - off, off);
        if (got <= 0) {
            free(bytes);
            platform_positioned_file_close(&file);
            LOG_FAIL(SFE_TAG, "manifest short read: %s", path);
        }
        off += (size_t)got;
    }
    bool stable = platform_positioned_file_snapshot(&file, &after) &&
                  sfe_same_snapshot(&before, &after);
    platform_positioned_file_close(&file);
    if (!stable) {
        free(bytes);
        LOG_FAIL(SFE_TAG, "manifest changed while reading: %s", path);
    }
    *out = bytes;
    *out_len = len;
    return true;
}

static bool sfe_hash_regular(const char *path, uint64_t expected_size,
                             uint8_t out[32])
{
    struct platform_positioned_file file;
    platform_positioned_file_init(&file);
    if (!platform_positioned_file_open(&file, path))
        LOG_FAIL(SFE_TAG, "open CAS bytes failed: %s", path);
    struct platform_positioned_file_snapshot before, after;
    if (!platform_positioned_file_snapshot(&file, &before) ||
        before.size == 0 || before.size != expected_size) {
        platform_positioned_file_close(&file);
        LOG_FAIL(SFE_TAG, "CAS bytes size/type mismatch: %s", path);
    }
    uint8_t buffer[SFE_HASH_BUFFER];
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    uint64_t total = 0;
    while (total < expected_size) {
        size_t wanted = expected_size - total > sizeof(buffer)
                            ? sizeof(buffer)
                            : (size_t)(expected_size - total);
        int64_t got = platform_positioned_file_read(
            &file, buffer, wanted, total);
        if (got <= 0) {
            platform_positioned_file_close(&file);
            LOG_FAIL(SFE_TAG, "read CAS bytes failed: %s", path);
        }
        total += (uint64_t)got;
        sha3_256_write(&sha, buffer, (size_t)got);
    }
    bool stable = platform_positioned_file_snapshot(&file, &after) &&
                  sfe_same_snapshot(&before, &after);
    platform_positioned_file_close(&file);
    if (!stable || total != expected_size)
        LOG_FAIL(SFE_TAG, "CAS bytes changed while hashing: %s", path);
    sha3_256_finalize(&sha, out);
    return true;
}

struct zcl_result shop_fulfill_artifact_verify(
    const char *datadir, const uint8_t content_root[32],
    const uint8_t artifact_root[32], struct shop_fulfill_artifact_fact *out)
{
    if (out) memset(out, 0, sizeof(*out));
    if (!datadir || !datadir[0] || !sfe_nonzero(content_root) ||
        !sfe_nonzero(artifact_root) || !out)
        return artifact_fail(out, "invalid-artifact-proof-input");

    char content_hex[65], artifact_hex[65], manifest_path[SFE_PATH_MAX];
    zcl_hex_encode(content_root, 32, content_hex);
    zcl_hex_encode(artifact_root, 32, artifact_hex);
    int n = snprintf(manifest_path, sizeof(manifest_path),
                     "%s/zcode/manifests/%s", datadir, content_hex);
    if (n < 0 || (size_t)n >= sizeof(manifest_path))
        return artifact_fail(out, "artifact-manifest-path-too-long");

    uint8_t *wire = NULL;
    size_t wire_len = 0;
    if (!sfe_read_bounded(manifest_path,
                          VCS_PACKAGE_MANIFEST_MAX_WIRE_BYTES,
                          &wire, &wire_len))
        return artifact_fail(out, "artifact-manifest-unreadable");
    struct vcs_package_manifest manifest;
    bool parsed = vcs_package_manifest_parse(wire, wire_len, &manifest);
    free(wire);
    if (!parsed)
        return artifact_fail(out, "artifact-manifest-invalid");
    uint8_t derived[32];
    bool root_ok = vcs_package_manifest_root(&manifest, derived) &&
        memcmp(derived, content_root, 32) == 0;
    out->manifest_root_valid = root_ok;
    if (!root_ok) {
        vcs_package_manifest_free(&manifest);
        return artifact_fail(out, "artifact-manifest-root-mismatch");
    }
    if (manifest.count != 1u || !manifest.files ||
        manifest.files[0].chunk_count != 1u ||
        manifest.files[0].size == 0 ||
        manifest.files[0].size > VCS_PACKAGE_CHUNK_BYTES ||
        !manifest.files[0].chunk_hashes ||
        memcmp(manifest.files[0].chunk_hashes, artifact_root, 32) != 0) {
        vcs_package_manifest_free(&manifest);
        return artifact_fail(out, "artifact-not-single-cas-object");
    }
    out->size_bytes = manifest.files[0].size;
    vcs_package_manifest_free(&manifest);

    char cas_path[SFE_PATH_MAX];
    n = snprintf(cas_path, sizeof(cas_path), "%s/zcode/cas/sha3/%.2s/%s",
                 datadir, artifact_hex, artifact_hex);
    if (n < 0 || (size_t)n >= sizeof(cas_path))
        return artifact_fail(out, "artifact-cas-path-too-long");
    uint8_t checked[32];
    if (!sfe_hash_regular(cas_path, out->size_bytes, checked))
        return artifact_fail(out, "artifact-cas-bytes-unreadable");
    out->cas_bytes_present = true;
    out->artifact_sha3_valid = memcmp(checked, artifact_root, 32) == 0;
    if (!out->artifact_sha3_valid)
        return artifact_fail(out, "artifact-sha3-mismatch");
    (void)snprintf(out->reason, sizeof(out->reason), "verified");
    return ZCL_OK;
}

const char *shop_fulfill_receipt_kind_name(
    enum shop_fulfill_receipt_kind kind)
{
    switch (kind) {
    case SHOP_FULFILL_RECEIPT_BUILD: return "build";
    case SHOP_FULFILL_RECEIPT_FUZZ: return "fuzz";
    case SHOP_FULFILL_RECEIPT_BENCH: return "benchmark";
    }
    return "unknown";
}

static bool sfe_kind_matches(enum shop_fulfill_receipt_kind expected,
                             const char *action_kind)
{
    if (!action_kind) return false;
    if (expected == SHOP_FULFILL_RECEIPT_BUILD)
        return strcmp(action_kind, VCS_BUILD_ACTION_KIND_V1) == 0 ||
               strcmp(action_kind, VCS_BUILD_ACTION_KIND_PACKAGE_V1) == 0;
    if (expected == SHOP_FULFILL_RECEIPT_FUZZ)
        return strcmp(action_kind, VCS_BUILD_ACTION_KIND_FUZZ_V1) == 0;
    /* Benchmark evidence has its own admitted science authority. It must
     * never be accepted merely because an ordinary build-fabric action was
     * labelled with a benchmark kind. */
    if (expected == SHOP_FULFILL_RECEIPT_BENCH) return false;
    return false;
}

/* The canonical ZCODE benchmark surface stores an admitted benchmark_result.v2
 * root in the workspace CAS, not in build_receipts. Re-run its full
 * transitive verifier. Its typed candidate root is intentionally NOT equated
 * with the fulfillment's raw byte SHA3; their domains and encodings differ. */
static struct zcl_result sfe_zcode_benchmark_verify(
    struct node_db *ndb, const char *datadir, const uint8_t receipt_id[32],
    struct shop_fulfill_receipt_fact *out)
{
    char workspace[SFE_PATH_MAX], receipt_hex[65];
    int n = snprintf(workspace, sizeof(workspace), "%s/zcode", datadir);
    if (n < 0 || (size_t)n >= sizeof(workspace))
        return receipt_fail(out, "benchmark-workspace-path-too-long");
    zcl_hex_encode(receipt_id, 32, receipt_hex);
    struct db_zcode_science_entry row;
    const char *kind = NULL;
    struct zcl_result admitted = zcode_science_work_receipt(
        ndb, workspace, receipt_hex, &row, &kind);
    if (!admitted.ok || !kind || strcmp(kind, "result") != 0)
        return receipt_fail(out, admitted.ok
            ? "benchmark-result-not-admitted" : admitted.message);
    struct zcl_result verified =
        zcode_benchmark_executor_verify_receipt(workspace, receipt_hex);
    if (!verified.ok)
        return receipt_fail(out, verified.message);
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    if (vcs_object_load_raw(workspace, receipt_id, &wire, &wire_len) != 0)
        return receipt_fail(out, "benchmark-result-not-in-cas");
    uint8_t status = 0xffu;
    struct vcs_zcode_benchmark_result_v2 result;
    bool parsed = wire_len == VCS_ZCODE_BENCHMARK_RESULT_V2_WIRE_BYTES &&
        vcs_zcode_benchmark_result_v2_parse(wire, wire_len, &result) ==
            VCS_ZCODE_SCIENCE_OK;
    if (parsed) status = result.status;
    free(wire);
    if (!parsed)
        return receipt_fail(out, "benchmark-result-kind-invalid");
    if (status != VCS_ZCODE_BENCHMARK_OBSERVED)
        return receipt_fail(out, "benchmark-result-not-observed");
    out->present = true;
    out->canonical_id_valid = true;
    out->action_binding_valid = true;
    out->artifact_binding_valid = false;
    out->passed = true;
    (void)snprintf(out->action_kind, sizeof(out->action_kind),
                   "zcode.benchmark_result.v2");
    (void)snprintf(out->reason, sizeof(out->reason),
                   "verified; artifact-link seller-bound only");
    return ZCL_OK;
}

struct zcl_result shop_fulfill_receipt_verify(
    struct node_db *ndb, const char *datadir, const uint8_t receipt_id[32],
    enum shop_fulfill_receipt_kind expected_kind,
    int64_t now_unix, struct shop_fulfill_receipt_fact *out)
{
    if (out) memset(out, 0, sizeof(*out));
    if (!ndb || !ndb->open || !datadir || !datadir[0] || !receipt_id ||
        !out || !sfe_nonzero(receipt_id) || now_unix <= 0)
        return receipt_fail(out, "invalid-receipt-proof-input");
    char receipt_hex[65];
    zcl_hex_encode(receipt_id, 32, receipt_hex);

    /* Route benchmark ids exclusively through the admitted science result
     * projection before probing build_receipts. This prevents a TEST action
     * with a benchmark-shaped label from crossing an authority boundary. */
    if (expected_kind == SHOP_FULFILL_RECEIPT_BENCH)
        return sfe_zcode_benchmark_verify(ndb, datadir, receipt_id, out);

    struct db_build_receipt receipt;
    if (!db_build_receipt_find(ndb, receipt_hex, &receipt))
        return receipt_fail(out, "receipt-not-found");
    out->present = true;
    struct db_build_action action;
    struct db_build_job job;
    struct db_build_worker worker;
    if (!db_build_action_find(ndb, receipt.action_id, &action) ||
        !db_build_job_find(ndb, receipt.job_id, &job) ||
        !db_build_worker_find(ndb, receipt.worker_id, &worker))
        return receipt_fail(out, "receipt-authorities-missing");
    (void)snprintf(out->action_kind, sizeof(out->action_kind), "%s",
                   action.kind);
    (void)snprintf(out->signer_pubkey, sizeof(out->signer_pubkey), "%s",
                   worker.signer_pubkey);
    char canonical_action[65], canonical_job[65];
    if (!build_fabric_action_id(&job, &action, canonical_action).ok ||
        strcmp(canonical_action, action.action_id) != 0 ||
        !build_fabric_job_id(&job, canonical_action, canonical_job).ok ||
        strcmp(canonical_job, job.job_id) != 0)
        return receipt_fail(out, "receipt-action-id-invalid");
    if (!sfe_kind_matches(expected_kind, action.kind))
        return receipt_fail(out, "receipt-kind-mismatch");

    char canonical[65];
    out->canonical_id_valid =
        build_fabric_receipt_id(&receipt, canonical).ok &&
        strcmp(canonical, receipt_hex) == 0;
    if (!out->canonical_id_valid)
        return receipt_fail(out, "receipt-id-invalid");

    out->action_binding_valid =
        strcmp(receipt.job_id, action.job_id) == 0 &&
        strcmp(receipt.action_sha3, action.action_id) == 0 &&
        strcmp(receipt.worker_id, action.worker_id) == 0 &&
        strcmp(receipt.lease_id, action.lease_id) == 0 &&
        strcmp(action.state, "ACCEPTED") == 0;
    if (!out->action_binding_valid)
        return receipt_fail(out, "receipt-action-binding-invalid");

    if (!worker.approved || worker.revoked ||
        (worker.expires_at != 0 && now_unix >= worker.expires_at))
        return receipt_fail(out, "receipt-signer-not-currently-approved");
    /* Promoted remote work receipts use a different canonical id/signature
     * codec. Never run the local outer-receipt proof over that type. */
    if (strcmp(receipt.trust_state, "LOCAL_ACCEPTED") != 0)
        return receipt_fail(out, "receipt-not-local-outer-authority");

    uint8_t signature[64], pubkey[32];
    out->signature_valid =
        zcl_hex_decode_lower(receipt.signature, signature, sizeof(signature)) &&
        zcl_hex_decode_lower(worker.signer_pubkey, pubkey, sizeof(pubkey)) &&
        ed25519_verify(signature, receipt_id, 32, pubkey);
    if (!out->signature_valid)
        return receipt_fail(out, "receipt-signature-invalid");

    out->passed = receipt.exit_status == 0;
    if (!out->passed)
        return receipt_fail(out, "receipt-reports-failure");
    out->artifact_binding_valid = false;
    (void)snprintf(out->reason, sizeof(out->reason),
                   "verified; artifact-link seller-bound only");
    return ZCL_OK;
}
