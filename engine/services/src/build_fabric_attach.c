/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Executor-keyed attachment of a duplicate fixed compile request to
 * one already-qualified physical result, with its own signed receipt.
 *
 * The key binds the fixed action descriptor, recomputed flags/environment,
 * proof policy, exact .i bytes, and current driver/backend/assembler file
 * bytes. The capsule binds the assembler version string; this key also binds
 * its bytes. A physical compile publishes the CAS record at its key. An
 * eligible duplicate attaches to that result. Reproduction refuses by name. */

#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif

#include "services/build_fabric_attach.h"

#if !defined(_WIN32)

#include "build_fabric_observation_internal.h"
#include "build_fabric_attach_identity_internal.h"
#include "build_fabric_attach_key_internal.h"
#include "build_fabric_worker_internal.h"

#include "base/hex.h"
#include "base/log_macros.h"
#include "base/safe_alloc.h"
#include "crypto/ed25519.h"
#include "crypto/sha3.h"
#include "platform/positioned_file.h"
#include "platform/time_compat.h"
#include "platform/toolchain.h"
#include "services/build_fabric_service.h"
#include "services/build_fabric_worker_evidence.h"
#include "util/spawn.h"
#include "vcs/build_action.h"
#include "vcs/build_artifact_manifest.h"
#include "vcs/build_execution_observation.h"
#include "vcs/proof_reuse.h"
#include "vcs/vcs_object.h"
#include "vcs/zcode_action_input.h"
#include "vcs/zcode_dev.h"
#include "vcs/zcode_work_output.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum {
    BFAT_RECEIPT_SCAN_CAP = 257,
    BFAT_SCAN_CAP = BUILD_FABRIC_ATTACH_SCAN_CAP,
};

const char *build_fabric_attach_disposition_string(
    enum build_fabric_attach_disposition disposition)
{
    switch (disposition) {
    case BUILD_FABRIC_ATTACH_MISS: return "miss";
    case BUILD_FABRIC_ATTACH_HIT: return "hit";
    case BUILD_FABRIC_ATTACH_REFUSED: return "refused";
    }
    return "refused";
}

static struct zcl_result bfat_refuse(struct build_fabric_attach_report *report,
                                     const char *token)
{
    report->disposition = BUILD_FABRIC_ATTACH_REFUSED;
    (void)snprintf(report->refusal, sizeof(report->refusal), "%s", token);
    return ZCL_ERR(-1, "%s", token);
}

/* Load the action's .i payload with FULL verification before any staging or
 * execution: the zcode path re-derives every binding; the raw path caps the
 * size and re-hashes the bytes against the declared input root. */
static struct zcl_result bfat_load_input(
    const char *workspace, const struct db_build_job *job,
    const struct db_build_action *action, int64_t now,
    uint8_t **out, size_t *out_len, uint8_t input_bytes_root[32],
    char *refusal, size_t refusal_cap)
{
    *out = NULL;
    *out_len = 0;
    uint8_t input_root[32];
    if (!zcl_hex_decode_lower(action->input_root_sha3, input_root, 32))
        return ZCL_ERR(-1, "input-root-invalid");
    struct zcl_result loaded = ZCL_OK;
    if (action->task_root_sha3[0]) {
        struct vcs_zcode_task_v1 task;
        struct vcs_zcode_candidate_v1 candidate;
        struct vcs_zcode_proof_policy_v1 policy;
        bool present = false;
        struct zcl_result context = bfw_load_zcode_context(
            workspace, job, action, now, &task, &candidate, &policy,
            &present);
        if (!context.ok) {
            (void)snprintf(refusal, refusal_cap, "%s", context.message);
            return context;
        }
        if (!present)
            return ZCL_ERR(-1, "input-cas-miss: zcode context absent");
        enum vcs_zcode_action_input_result got =
            vcs_zcode_action_input_load_payload_cas(
                workspace, input_root, &task, &candidate,
                VCS_ZCODE_WORK_BUILD, out, out_len);
        if (got != VCS_ZCODE_ACTION_INPUT_OK) {
            (void)snprintf(refusal, refusal_cap, "%s",
                           vcs_zcode_action_input_result_string(got));
            return ZCL_ERR(-1, "%s", refusal);
        }
    } else {
        if (vcs_object_load_raw(workspace, input_root, out, out_len) != 0 ||
            *out_len == 0 || *out_len > VCS_BUILD_ARTIFACT_MAX_BYTES) {
            free(*out);
            *out = NULL;
            *out_len = 0;
            (void)snprintf(refusal, refusal_cap, "input-cas-miss");
            return ZCL_ERR(-1, "input-cas-miss");
        }
        uint8_t checked[32];
        sha3_256(*out, *out_len, checked);
        if (memcmp(checked, input_root, 32) != 0) {
            free(*out);
            *out = NULL;
            *out_len = 0;
            (void)snprintf(refusal, refusal_cap, "input-cas-corrupt");
            return ZCL_ERR(-1, "input-cas-corrupt");
        }
    }
    struct vcs_build_input_screen_v1 screen;
    vcs_build_input_screen_v1_init(&screen);
    if (!vcs_build_input_screen_v1_update(&screen, *out, *out_len) ||
        !vcs_build_input_screen_v1_finish(&screen)) {
        free(*out);
        *out = NULL;
        *out_len = 0;
        (void)snprintf(refusal, refusal_cap,
                       "input-dependency-closure-unknown");
        return ZCL_ERR(-1, "input-dependency-closure-unknown");
    }
    sha3_256(*out, *out_len, input_bytes_root);
    return loaded;
}

static bool bfat_receipt_signature_valid(
    struct node_db *ndb, const struct db_build_receipt *receipt)
{
    struct db_build_worker worker;
    char expected[BUILD_FABRIC_ID_HEX + 1];
    uint8_t id[32], signature[64], pubkey[32];
    return db_build_worker_find(ndb, receipt->worker_id, &worker) &&
        build_fabric_receipt_id(receipt, expected).ok &&
        strcmp(expected, receipt->receipt_id) == 0 &&
        zcl_hex_decode_lower(receipt->receipt_id, id, sizeof(id)) &&
        zcl_hex_decode_lower(receipt->signature, signature,
                             sizeof(signature)) &&
        zcl_hex_decode_lower(worker.signer_pubkey, pubkey, sizeof(pubkey)) &&
        ed25519_verify(signature, id, sizeof(id), pubkey);
}

/* One accepted row is the donor's canonical receipt only when it binds the
 * donor action, job, and output root with a success exit and an
 * observation. */
static bool bfat_row_binding_exact(
    const struct db_build_receipt *row, const struct db_build_job *donor_job,
    const struct db_build_action *donor_action)
{
    return row->exit_status == 0 &&
        strcmp(row->action_sha3, donor_action->action_id) == 0 &&
        strcmp(row->job_id, donor_job->job_id) == 0 &&
        strcmp(row->output_sha3, donor_action->output_root_sha3) == 0 &&
        row->observation_sha3[0] != '\0';
}

/* Donor receipt scan: exactly one canonical LOCAL_ACCEPTED receipt for the
 * donor action — a second match, a mismatched binding, or a truncated scan
 * disqualifies the donor. */
static bool bfat_donor_receipt_scan(
    struct node_db *ndb, const struct db_build_job *donor_job,
    const struct db_build_action *donor_action,
    struct db_build_receipt *out_receipt, bool *history_incomplete)
{
    *history_incomplete = false;
    struct db_build_receipt *rows = zcl_malloc(
        BFAT_RECEIPT_SCAN_CAP * sizeof(*rows), "build.attach.receipts");
    if (!rows) {
        LOG_ERROR("build_fabric", "cannot allocate donor receipt scan buffer");
        *history_incomplete = true;
        return false;
    }
    int count = db_build_job_receipts_checked(
        ndb, donor_job->job_id, rows, BFAT_RECEIPT_SCAN_CAP);
    const struct db_build_receipt *accepted = NULL;
    bool complete = count >= 0 && count < BFAT_RECEIPT_SCAN_CAP;
    if (!complete) *history_incomplete = true;
    for (int i = 0; complete && i < count; i++) {
        if (strcmp(rows[i].action_id, donor_action->action_id) != 0 ||
            strcmp(rows[i].trust_state, "LOCAL_ACCEPTED") != 0)
            continue;
        if (accepted ||
            !bfat_row_binding_exact(&rows[i], donor_job, donor_action)) {
            complete = false;
            *history_incomplete = true;
            break;
        }
        accepted = &rows[i];
    }
    if (complete && accepted)
        *out_receipt = *accepted;
    free(rows);
    return complete && accepted != NULL;
}

static bool bfat_donor_worker_live(struct node_db *ndb, const char *worker_id,
                                   int64_t now)
{
    struct db_build_worker worker;
    return db_build_worker_find(ndb, worker_id, &worker) &&
        worker.approved && !worker.revoked &&
        (worker.expires_at == 0 || now < worker.expires_at);
}

/* Require one signed, live physical donor receipt and matching observation.
 * An attached receipt cannot qualify as a donor. */
static bool bfat_donor_qualified(
    struct node_db *ndb, const char *workspace,
    const struct db_build_job *donor_job,
    const struct db_build_action *donor_action, int64_t now,
    struct db_build_receipt *out_receipt, bool *history_incomplete)
{
    struct db_build_receipt accepted;
    if (!bfat_donor_receipt_scan(ndb, donor_job, donor_action, &accepted,
                                 history_incomplete))
        return false; /* raw-return-ok:disqualified donor; the caller reports
                         incomplete history or an unqualified donor */
    if (!bfat_donor_worker_live(ndb, accepted.worker_id, now) ||
        !bfat_receipt_signature_valid(ndb, &accepted))
        return false;
    if (!build_fabric_observation_verify(workspace, donor_job, donor_action,
                                         &accepted).ok) {
        *history_incomplete = true;
        return false;
    }
    *out_receipt = accepted;
    return true;
}

/* Re-derive one CAS-resident observation and prove the stored bytes hash to
 * the receipt's declared root. */
static struct zcl_result bfat_observation_load(
    const char *workspace, const char *root_hex,
    struct vcs_build_execution_observation_v1 *out)
{
    uint8_t root[32], checked[32], *wire = NULL;
    size_t wire_len = 0;
    if (!zcl_hex_decode_lower(root_hex, root, 32) ||
        vcs_object_load_raw(workspace, root, &wire, &wire_len) != 0)
        return ZCL_ERR(-1, "attach-output-poisoned: observation absent");
    bool ok = vcs_build_execution_observation_v1_parse(wire, wire_len, out) &&
              vcs_build_execution_observation_v1_root(out, checked) &&
              memcmp(root, checked, 32) == 0;
    free(wire);
    return ok ? ZCL_OK
              : ZCL_ERR(-1, "attach-output-poisoned: observation malformed");
}

/* Load a non-zcode chunked artifact manifest and verify its wire root, its
 * self-hash, and the action root it is bound to. */
static struct zcl_result bfat_manifest_load(
    const char *workspace, const uint8_t manifest_root[32],
    const uint8_t action_root[32],
    struct vcs_build_artifact_manifest_v1 *out)
{
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    if (vcs_object_load_raw_bounded(workspace, manifest_root,
                                    VCS_BUILD_ARTIFACT_WIRE_MAX, &wire,
                                    &wire_len) != 0)
        return ZCL_ERR(-1, "attach-output-materialize-failed: manifest");
    uint8_t checked[32];
    bool ok = vcs_build_artifact_manifest_v1_parse(wire, wire_len, out) &&
        vcs_build_artifact_manifest_v1_root(out, checked) &&
        memcmp(checked, manifest_root, 32) == 0 &&
        memcmp(out->action_sha3, action_root, 32) == 0 &&
        out->total_bytes > 0 &&
        out->total_bytes <= VCS_BUILD_ARTIFACT_MAX_BYTES;
    free(wire);
    return ok ? ZCL_OK
              : ZCL_ERR(-1, "attach-output-materialize-failed: manifest root");
}

/* Reassemble one verified manifest's bytes, checking every chunk against
 * it. */
static struct zcl_result bfat_chunks_read(
    const char *workspace,
    const struct vcs_build_artifact_manifest_v1 *manifest, uint8_t *bytes)
{
    uint64_t off = 0;
    bool ok = true;
    for (uint32_t i = 0; ok && i < manifest->chunk_count; i++) {
        uint8_t *chunk = NULL;
        size_t chunk_len = 0;
        size_t take = (size_t)(manifest->total_bytes - off);
        if (take > VCS_BUILD_ARTIFACT_CHUNK_BYTES)
            take = VCS_BUILD_ARTIFACT_CHUNK_BYTES;
        ok = vcs_object_load_raw_bounded(workspace, manifest->chunk_sha3[i],
                                         VCS_BUILD_ARTIFACT_CHUNK_BYTES,
                                         &chunk, &chunk_len) == 0 &&
            chunk_len == take &&
            vcs_build_artifact_manifest_v1_verify_chunk(manifest, i, chunk,
                                                        chunk_len);
        if (ok) memcpy(bytes + off, chunk, chunk_len);
        off += chunk_len;
        free(chunk);
    }
    if (!ok || off != manifest->total_bytes)
        return ZCL_ERR(-1, "attach-output-materialize-failed: chunks");
    return ZCL_OK;
}

/* Read a non-zcode chunked artifact manifest and reassemble its bytes,
 * verifying the manifest root, the bound action root, and every chunk. */
struct zcl_result bfat_artifact_read(
    const char *workspace, const uint8_t manifest_root[32],
    const uint8_t action_root[32], uint8_t **out, size_t *out_len)
{
    *out = NULL;
    *out_len = 0;
    struct vcs_build_artifact_manifest_v1 manifest;
    ZCL_CHECK(bfat_manifest_load(workspace, manifest_root, action_root,
                                 &manifest));
    uint8_t *bytes = zcl_malloc((size_t)manifest.total_bytes,
                                "build.attach.output");
    if (!bytes)
        return ZCL_ERR(-1, "attach-output-materialize-failed: allocation");
    struct zcl_result chunks = bfat_chunks_read(workspace, &manifest, bytes);
    if (!chunks.ok) {
        free(bytes);
        return chunks;
    }
    *out = bytes;
    *out_len = (size_t)manifest.total_bytes;
    return ZCL_OK;
}

/* Match executor inputs and sequence; provenance roots may differ. */
static bool bfat_donor_fields_match(const struct db_build_action *donor,
                                    const struct db_build_action *req)
{
    return strcmp(donor->kind, req->kind) == 0 &&
        donor->sequence == req->sequence &&
        strcmp(donor->input_root_sha3, req->input_root_sha3) == 0 &&
        strcmp(donor->target, req->target) == 0 &&
        strcmp(donor->flags_sha3, req->flags_sha3) == 0 &&
        strcmp(donor->environment_sha3, req->environment_sha3) == 0 &&
        strcmp(donor->virtual_workdir, req->virtual_workdir) == 0 &&
        strcmp(donor->declared_outputs, req->declared_outputs) == 0 &&
        strcmp(donor->resource_policy, req->resource_policy) == 0 &&
        strcmp(donor->proof_policy_root_sha3, req->proof_policy_root_sha3) ==
            0;
}

static void bfat_worker_id_from_pubkey(const uint8_t pubkey[32], char out[65])
{
    static const char domain[] = "zcl.build_worker.v1";
    struct sha3_256_ctx sha;
    uint8_t digest[32];
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)domain, sizeof(domain));
    sha3_256_write(&sha, pubkey, 32);
    sha3_256_finalize(&sha, digest);
    zcl_hex_encode(digest, 32, out);
}

/* Verify identity, worker, key, donor, and output before publication. */
struct bfat_attach_ctx {
    struct node_db *ndb;
    const char *workspace;
    struct vcs_package_store *store;
    const struct db_build_job *req_job;
    const struct db_build_action *req_action;
    const uint8_t *signer_secret;
    const uint8_t *signer_pubkey;
    struct db_build_receipt *out_receipt;
    struct build_fabric_attach_report *report;
    int64_t started_us;
    int64_t now;
    sqlite3_int64 db_version;
    sqlite3_int64 db_changes;
    size_t input_len;
    struct db_build_job job;
    struct db_build_action action;
    char requester_worker_id[BUILD_FABRIC_ID_HEX + 1];
    char capsule_hex[65];
    struct vcs_toolchain_capsule_v1 capsule;
    uint8_t driver_bytes_root[32];
    uint8_t backend_bytes_root[32];
    uint8_t assembler_bytes_root[32];
    uint8_t runtime_root[32];
    uint8_t verifier_root[32];
    uint8_t toolchain_root[32];
    uint8_t key[32];
    struct db_build_action donor_action;
    struct db_build_receipt donor_receipt;
    struct db_build_receipt receipt;
    char refusal[BUILD_FABRIC_ERROR_MAX + 1];
};

/* Fence other handles with data_version and this handle with total_changes. */
static bool bfat_attach_args_ok(const struct bfat_attach_ctx *c)
{
    return c->ndb && c->ndb->open && c->workspace && c->req_job &&
        c->req_action && c->signer_secret && c->signer_pubkey &&
        c->out_receipt && c->report;
}

static struct zcl_result bfat_attach_stop(struct bfat_attach_ctx *c,
                                          const char *refusal)
{
    return refusal ? bfat_refuse(c->report, refusal) : ZCL_OK;
}

static bool bfat_ids_current(const struct db_build_job *req_job,
                             const struct db_build_action *req_action)
{
    char expect_action[BUILD_FABRIC_ID_HEX + 1];
    char expect_job[BUILD_FABRIC_ID_HEX + 1];
    return build_fabric_action_id(req_job, req_action, expect_action).ok &&
        strcmp(expect_action, req_action->action_id) == 0 &&
        build_fabric_job_id(req_job, expect_action, expect_job).ok &&
        strcmp(expect_job, req_job->job_id) == 0 &&
        strcmp(req_action->job_id, req_job->job_id) == 0;
}

static bool bfat_stored_plan_matches(const struct bfat_attach_ctx *c)
{
    return strcmp(c->job.job_id, c->req_job->job_id) == 0 &&
        strcmp(c->job.source_sha256, c->req_job->source_sha256) == 0 &&
        strcmp(c->job.source_cas_sha3, c->req_job->source_cas_sha3) == 0 &&
        strcmp(c->job.toolchain_sha3, c->req_job->toolchain_sha3) == 0 &&
        strcmp(c->job.profile, c->req_job->profile) == 0 &&
        strcmp(c->action.action_id, c->req_action->action_id) == 0 &&
        bfat_donor_fields_match(&c->action, c->req_action) &&
        strcmp(c->action.task_root_sha3, c->req_action->task_root_sha3) == 0 &&
        strcmp(c->action.candidate_root_sha3,
               c->req_action->candidate_root_sha3) == 0;
}

static const char *bfat_check_request_identity(struct bfat_attach_ctx *c)
{
    if (strcmp(c->req_action->kind, VCS_BUILD_ACTION_KIND_V1) != 0)
        return "attach-refused-kind-not-compile";
    if (!bfat_ids_current(c->req_job, c->req_action))
        return "attach-refused-identity-stale";
    if (!db_build_action_find(c->ndb, c->req_action->action_id, &c->action) ||
        !db_build_job_find(c->ndb, c->action.job_id, &c->job))
        return "attach-refused-action-not-planned";
    if (!bfat_stored_plan_matches(c))
        return "attach-refused-identity-stale";
    if (strcmp(c->action.state, "SNAPSHOTTED") != 0 &&
        strcmp(c->action.state, "QUEUED") != 0)
        return "attach-refused-action-state";
    if (strcmp(c->action.state, "QUEUED") == 0 &&
        strcmp(c->job.state, "QUEUED") != 0)
        return "attach-refused-job-state";
    if (c->job.cancel_requested)
        return "attach-refused-job-cancelled";
    return NULL;
}

static const char *bfat_check_requester_worker(struct bfat_attach_ctx *c)
{
    bfat_worker_id_from_pubkey(c->signer_pubkey, c->requester_worker_id);
    char signer_hex[65];
    zcl_hex_encode(c->signer_pubkey, 32, signer_hex);
    struct db_build_worker worker;
    if (!db_build_worker_find(c->ndb, c->requester_worker_id, &worker) ||
        !worker.approved || worker.revoked ||
        (worker.expires_at != 0 && c->now >= worker.expires_at) ||
        strcmp(worker.signer_pubkey, signer_hex) != 0 ||
        !build_fabric_worker_capability_check(worker.capabilities,
                                               c->action.kind).ok)
        return "attach-refused-worker-not-approved";
    return NULL;
}

static const char *bfat_compose_requester_key(struct bfat_attach_ctx *c)
{
    uint8_t *input = NULL;
    uint8_t input_bytes_root[32];
    struct zcl_result loaded = bfat_load_input(
        c->workspace, &c->job, &c->action, c->now, &input, &c->input_len,
        input_bytes_root, c->refusal, sizeof(c->refusal));
    if (!loaded.ok) {
        if (!c->refusal[0])
            (void)snprintf(c->refusal, sizeof(c->refusal), "%s",
                           loaded.message);
        return c->refusal;
    }
    struct vcs_toolchain_capsule_v1 capsule;
    struct platform_toolchain_descriptor descriptor;
    uint8_t capsule_root[32];
    if (!vcs_toolchain_capsule_v1_cached(&capsule, &descriptor) ||
        !vcs_toolchain_capsule_v1_root(&capsule, capsule_root)) {
        free(input);
        return "executor-toolchain-cache-unavailable";
    }
    zcl_hex_encode(capsule_root, 32, c->capsule_hex);
    if (strcmp(c->capsule_hex, c->job.toolchain_sha3) != 0) {
        free(input);
        return "attach-refused-toolchain-capsule-stale";
    }
    uint8_t driver[32], backend[32], assembler[32];
    struct zcl_result tools = bfat_cached_tool_hashes(
        &descriptor, driver, backend, assembler);
    if (!tools.ok) {
        free(input);
        return "executor-toolchain-capture-failed";
    }
    struct vcs_toolchain_capsule_v1 checked_capsule;
    struct platform_toolchain_descriptor checked_descriptor;
    if (!vcs_toolchain_capsule_v1_cached(&checked_capsule,
                                          &checked_descriptor) ||
        memcmp(&checked_capsule, &capsule, sizeof(capsule)) != 0 ||
        memcmp(&checked_descriptor, &descriptor, sizeof(descriptor)) != 0) {
        free(input);
        return "executor-toolchain-cache-stale";
    }
    build_fabric_executor_toolchain_root(driver, backend, assembler,
                                         c->toolchain_root);
    struct zcl_result runtime = bfat_runtime_roots(
        c->workspace, &descriptor, c->runtime_root, c->verifier_root);
    if (!runtime.ok) {
        free(input);
        return "executor-runtime-closure-missing";
    }
    c->capsule = capsule;
    memcpy(c->driver_bytes_root, driver, 32);
    memcpy(c->backend_bytes_root, backend, 32);
    memcpy(c->assembler_bytes_root, assembler, 32);
    struct bfat_key_fields fields;
    struct zcl_result keyed = bfat_fields_for_action(
        &c->action, c->toolchain_root, &c->capsule,
        c->driver_bytes_root, c->backend_bytes_root,
        c->assembler_bytes_root, c->runtime_root, c->verifier_root,
        input_bytes_root, &fields, &c->report->proof_key);
    free(input);
    if (!keyed.ok) {
        (void)snprintf(c->refusal, sizeof(c->refusal), "%s", keyed.message);
        return c->refusal;
    }
    uint8_t wire[BFAT_RECORD_CAP];
    size_t wire_len = 0;
    if (!bfat_record_serialize(&fields, wire, sizeof(wire), &wire_len))
        return "executor-key-record-poisoned";
    bfat_record_key(wire, wire_len, c->key);
    zcl_hex_encode(c->key, 32, c->report->executor_key);
    c->report->proof_key_known = true;
    return NULL;
}

/* Returns true when the pipeline must stop: *refusal NULL is a clean MISS
 * (no physical run published this key), non-NULL is the refusal token. */
static bool bfat_key_record_checked(struct bfat_attach_ctx *c,
                                    const char **refusal)
{
    uint8_t *record = NULL;
    size_t record_len = 0;
    if (vcs_object_load_raw(c->workspace, c->key, &record, &record_len) != 0) {
        c->report->attach_wall_us =
            platform_time_monotonic_us() - c->started_us;
        *refusal = NULL;
        return true;
    }
    struct bfat_key_fields record_fields;
    uint8_t record_wire[BFAT_RECORD_CAP], record_key[32];
    size_t record_wire_len = 0;
    bool ok = record_len <= sizeof(record_wire) &&
        bfat_record_parse(record, record_len, &record_fields) &&
        bfat_record_serialize(&record_fields, record_wire,
                              sizeof(record_wire), &record_wire_len) &&
        record_wire_len == record_len &&
        memcmp(record_wire, record, record_len) == 0;
    if (ok) {
        bfat_record_key(record, record_len, record_key);
        ok = memcmp(record_key, c->key, 32) == 0;
    }
    if (ok) {
        uint8_t *preimage = NULL;
        size_t preimage_len = 0;
        struct vcs_component_proof_key_v1 decoded;
        uint8_t derived[32];
        uint8_t root[32];
        ok = vcs_object_load_raw(c->workspace,
                                 record_fields.component_preimage_root,
                                 &preimage, &preimage_len) == 0 &&
            vcs_component_proof_key_decode(preimage, preimage_len, &decoded) &&
            vcs_component_proof_key_preimage_root(&decoded, root) &&
            memcmp(root, record_fields.component_preimage_root, 32) == 0 &&
            vcs_component_proof_key_derive(&decoded, derived) &&
            memcmp(derived, record_fields.component_key, 32) == 0;
        free(preimage);
    }
    free(record);
    if (!ok) {
        *refusal = "executor-key-record-poisoned";
        return true;
    }
    return false;
}

/* Re-derive the donor key from verified input and current tool bytes. */
static bool bfat_donor_key_matches(const struct bfat_attach_ctx *c,
                                   const struct db_build_job *job,
                                   const struct db_build_action *candidate,
                                   bool *incomplete)
{
    if (strcmp(candidate->kind, VCS_BUILD_ACTION_KIND_V1) != 0 ||
        strcmp(candidate->state, "ACCEPTED") != 0 ||
        strcmp(candidate->action_id, c->action.action_id) == 0 ||
        !bfat_donor_fields_match(candidate, &c->action))
        return false;
    if (strcmp(job->toolchain_sha3, c->capsule_hex) != 0)
        return false;
    *incomplete = !candidate->output_root_sha3[0];
    if (*incomplete) return false;
    uint8_t *input = NULL;
    size_t input_len = 0;
    uint8_t input_root[32];
    char refusal[BUILD_FABRIC_ERROR_MAX + 1] = {0};
    struct zcl_result loaded = bfat_load_input(
        c->workspace, job, candidate, c->now, &input, &input_len, input_root,
        refusal, sizeof(refusal));
    *incomplete = !loaded.ok;
    if (*incomplete) return false;
    struct bfat_key_fields fields;
    struct zcl_result keyed = bfat_fields_for_action(
        candidate, c->toolchain_root, &c->capsule,
        c->driver_bytes_root, c->backend_bytes_root,
        c->assembler_bytes_root, c->runtime_root, c->verifier_root,
        input_root, &fields, NULL);
    free(input);
    *incomplete = !keyed.ok;
    if (*incomplete) return false;
    uint8_t wire[BFAT_RECORD_CAP], key[32];
    size_t wire_len = 0;
    *incomplete = !bfat_record_serialize(&fields, wire, sizeof(wire),
                                         &wire_len);
    if (*incomplete) return false;
    bfat_record_key(wire, wire_len, key);
    return memcmp(key, c->key, 32) == 0;
}

struct bfat_scan_state {
    bool found, cross_profile, unqualified, incomplete, contradictory;
    uint8_t output_bytes_root[32];
};

static void bfat_scan_one_donor(struct bfat_attach_ctx *c,
                                const struct db_build_job *job,
                                const struct db_build_action *action,
                                struct bfat_scan_state *scan)
{
    bool incomplete = false;
    if (!bfat_donor_key_matches(c, job, action, &incomplete)) {
        if (incomplete)
            LOG_ERROR("build_fabric", "attach donor input incomplete: %s",
                      action->action_id);
        scan->incomplete = scan->incomplete || incomplete;
        return;
    }
    if (strcmp(job->profile, c->job.profile) != 0) {
        scan->cross_profile = true;
        return;
    }
    struct db_build_receipt receipt;
    bool donor_incomplete = false;
    if (!bfat_donor_qualified(c->ndb, c->workspace, job, action, c->now,
                              &receipt, &donor_incomplete)) {
        scan->incomplete = scan->incomplete || donor_incomplete;
        scan->unqualified = true;
        return;
    }
    struct vcs_build_execution_observation_v1 observation;
    if (!bfat_observation_load(c->workspace, receipt.observation_sha3,
                               &observation).ok) {
        scan->incomplete = true;
        return;
    }
    if (scan->found) {
        if (memcmp(scan->output_bytes_root,
                   observation.output_bytes_root, 32) != 0)
            scan->contradictory = true;
    } else {
        memcpy(scan->output_bytes_root, observation.output_bytes_root, 32);
        c->donor_action = *action;
        c->donor_receipt = receipt;
        scan->found = true;
    }
}

static bool bfat_scan_result(struct bfat_attach_ctx *c,
                              const struct bfat_scan_state *scan,
                              const char **refusal)
{
    if (scan->incomplete)
        *refusal = "attach-refused-history-incomplete";
    else if (scan->contradictory)
        *refusal = "attach-refused-observation-conflict";
    else if (scan->found)
        return false;
    else if (scan->unqualified)
        *refusal = "attach-refused-donor-not-qualified";
    else if (scan->cross_profile)
        *refusal = "attach-refused-independent-run-required";
    else {
        c->report->attach_wall_us =
            platform_time_monotonic_us() - c->started_us;
        *refusal = NULL;
    }
    return true;
}

/* Scan accepted compile actions. Missing or ambiguous history refuses;
 * only a complete empty scan is a clean MISS. */
#ifdef ZCL_TESTING
static void (*bfat_before_donor_scan_hook)(void *);
static void *bfat_before_donor_scan_context;
#endif
static bool bfat_donor_scan(struct bfat_attach_ctx *c, const char **refusal)
{
#ifdef ZCL_TESTING
    if (bfat_before_donor_scan_hook)
        bfat_before_donor_scan_hook(bfat_before_donor_scan_context);
#endif
    struct db_build_job *jobs = zcl_malloc((BFAT_SCAN_CAP + 1u) * sizeof(*jobs),
                                           "build.attach.jobs");
    struct db_build_action *actions = zcl_malloc(
        (BFAT_SCAN_CAP + 1u) * sizeof(*actions), "build.attach.actions");
    if (!jobs || !actions) {
        free(actions);
        free(jobs);
        *refusal = "attach-refused-scan-alloc-failed";
        return true;
    }
    struct bfat_scan_state scan = {0};
    int job_count = db_build_jobs_recent_checked(
        c->ndb, jobs, BFAT_SCAN_CAP + 1u);
    if (job_count < 0 || job_count > BFAT_SCAN_CAP) scan.incomplete = true;
    for (int j = 0; !scan.incomplete && j < job_count; j++) {
        int action_count = db_build_job_actions_checked(
            c->ndb, jobs[j].job_id, actions, BFAT_SCAN_CAP + 1u);
        if (action_count < 0 || action_count > BFAT_SCAN_CAP) {
            scan.incomplete = true;
            break;
        }
        for (int a = 0; !scan.incomplete && a < action_count; a++)
            bfat_scan_one_donor(c, &jobs[j], &actions[a], &scan);
    }
    free(actions);
    free(jobs);
    return bfat_scan_result(c, &scan, refusal);
}

#ifdef ZCL_TESTING
void build_fabric_attach_test_before_donor_scan(void (*hook)(void *),
                                                void *context)
{ bfat_before_donor_scan_hook = hook; bfat_before_donor_scan_context = context; }
static void (*bfat_after_scan_hook)(void *);
static void *bfat_after_scan_context;
void build_fabric_attach_test_after_scan(void (*hook)(void *), void *context)
{ bfat_after_scan_hook = hook; bfat_after_scan_context = context; }
static int64_t bfat_test_now = -1;
void build_fabric_attach_test_now(int64_t now) { bfat_test_now = now; }
#endif

static int64_t bfat_now(void)
{
#ifdef ZCL_TESTING
    if (bfat_test_now >= 0) return bfat_test_now;
#endif
    return (int64_t)platform_time_wall_unix();
}

/* Fetch the donor output bytes WITHOUT compiling and prove them against the
 * donor's physical observation. */
static const char *bfat_output_fetch(struct bfat_attach_ctx *c,
                                     uint8_t **bytes_out, size_t *len_out)
{
    struct vcs_build_execution_observation_v1 observation;
    struct zcl_result observed = bfat_observation_load(
        c->workspace, c->donor_receipt.observation_sha3, &observation);
    if (!observed.ok) {
        (void)snprintf(c->refusal, sizeof(c->refusal), "%s", observed.message);
        return c->refusal;
    }
    uint8_t donor_output_root[32], donor_action_root[32];
    uint8_t req_action_root[32];
    if (!zcl_hex_decode_lower(c->donor_action.output_root_sha3,
                              donor_output_root, 32) ||
        !zcl_hex_decode_lower(c->donor_action.action_id, donor_action_root,
                              32) ||
        !zcl_hex_decode_lower(c->action.action_id, req_action_root, 32))
        return "attach-output-materialize-failed";
    bool zcode = c->action.task_root_sha3[0] != '\0';
    if (zcode && !c->store)
        return "attach-refused-store-unavailable";
    uint8_t *bytes = NULL;
    size_t len = 0;
    if (zcode) {
        enum vcs_zcode_work_output_result got = vcs_zcode_work_output_get(
            c->store, donor_output_root, donor_action_root, &bytes, &len);
        if (got != VCS_ZCODE_WORK_OUTPUT_OK)
            return vcs_zcode_work_output_result_string(got);
    } else {
        struct zcl_result read = bfat_artifact_read(
            c->workspace, donor_output_root, donor_action_root, &bytes, &len);
        if (!read.ok) {
            (void)snprintf(c->refusal, sizeof(c->refusal), "%s", read.message);
            return c->refusal;
        }
    }
    uint8_t bytes_root[32];
    sha3_256(bytes, len, bytes_root);
    if (memcmp(bytes_root, observation.output_bytes_root, 32) != 0) {
        free(bytes);
        return "attach-output-poisoned";
    }
    *bytes_out = bytes;
    *len_out = len;
    return NULL;
}

/* Re-read and compare the requester-bound output copy before publication. */
static const char *bfat_output_store_copy(struct bfat_attach_ctx *c,
                                          const uint8_t *bytes, size_t len,
                                          uint8_t copy_root[32])
{
    bool zcode = c->action.task_root_sha3[0] != '\0';
    uint8_t req_action_root[32];
    if (!zcl_hex_decode_lower(c->action.action_id, req_action_root, 32))
        return "attach-output-materialize-failed";
    struct zcl_result copied = ZCL_OK;
    if (zcode) {
        enum vcs_zcode_work_output_result put = vcs_zcode_work_output_put(
            c->store, req_action_root, bytes, len, copy_root);
        if (put != VCS_ZCODE_WORK_OUTPUT_OK)
            copied = ZCL_ERR(-1, "attach-output-materialize-failed: %s",
                             vcs_zcode_work_output_result_string(put));
    } else {
        copied = build_fabric_worker_store_artifact(
            c->workspace, c->action.action_id, bytes, len, copy_root);
    }
    if (copied.ok) {
        uint8_t *reread = NULL;
        size_t reread_len = 0;
        struct zcl_result verify = zcode
            ? (vcs_zcode_work_output_get(c->store, copy_root, req_action_root,
                                         &reread, &reread_len) ==
                       VCS_ZCODE_WORK_OUTPUT_OK
                   ? ZCL_OK
                   : ZCL_ERR(-1, "attach-output-materialize-failed: reread"))
            : bfat_artifact_read(c->workspace, copy_root, req_action_root,
                                 &reread, &reread_len);
        if (verify.ok &&
            (reread_len != len || memcmp(reread, bytes, len) != 0))
            verify = ZCL_ERR(-1, "attach-output-materialize-failed: bytes");
        free(reread);
        copied = verify;
    }
    if (!copied.ok) {
        (void)snprintf(c->refusal, sizeof(c->refusal), "%s", copied.message);
        return c->refusal;
    }
    zcl_hex_encode(copy_root, 32, c->report->output_copy_sha3);
    c->report->restored_bytes = len;
    return NULL;
}

/* Attach receipt binds donor observation; its lease slot holds the key. */
static const char *bfat_receipt_prepare(struct bfat_attach_ctx *c)
{
    struct db_build_receipt *receipt = &c->receipt;
    memset(receipt, 0, sizeof(*receipt));
    (void)snprintf(receipt->action_id, sizeof(receipt->action_id), "%s",
                   c->action.action_id);
    (void)snprintf(receipt->job_id, sizeof(receipt->job_id), "%s",
                   c->job.job_id);
    (void)snprintf(receipt->worker_id, sizeof(receipt->worker_id), "%s",
                   c->requester_worker_id);
    (void)snprintf(receipt->lease_id, sizeof(receipt->lease_id), "%s",
                   c->report->executor_key);
    (void)snprintf(receipt->action_sha3, sizeof(receipt->action_sha3), "%s",
                   c->action.action_id);
    (void)snprintf(receipt->output_sha3, sizeof(receipt->output_sha3), "%s",
                   c->report->output_copy_sha3);
    (void)snprintf(receipt->observation_sha3,
                   sizeof(receipt->observation_sha3), "%s",
                   c->donor_receipt.observation_sha3);
    (void)snprintf(receipt->confinement, sizeof(receipt->confinement),
                   "landlock=1,seccomp=1,rlimits=1,network=0,gcc=fixed,"
                   "executor-attach=1");
    (void)snprintf(receipt->trust_state, sizeof(receipt->trust_state),
                   "LOCAL_ACCEPTED");
    receipt->exit_status = 0;
    receipt->created_at = c->now;
    if (!build_fabric_receipt_id(receipt, receipt->receipt_id).ok)
        return "attach-persist-failed: receipt id";
    uint8_t receipt_id[32], signature[64];
    if (!zcl_hex_decode_lower(receipt->receipt_id, receipt_id, 32))
        return "attach-persist-failed: receipt id";
    ed25519_sign(signature, receipt_id, sizeof(receipt_id), c->signer_secret,
                 c->signer_pubkey);
    zcl_hex_encode(signature, sizeof(signature), receipt->signature);
    return NULL;
}

/* Re-read the stored receipt and verify its signed identity. */
static const char *bfat_receipt_reread_verify(struct bfat_attach_ctx *c)
{
    struct db_build_receipt persisted;
    char persisted_id[BUILD_FABRIC_ID_HEX + 1];
    uint8_t verify_id[32], verify_sig[64];
    if (!db_build_receipt_find(c->ndb, c->receipt.receipt_id, &persisted) ||
        !build_fabric_receipt_id(&persisted, persisted_id).ok ||
        strcmp(persisted_id, c->receipt.receipt_id) != 0 ||
        strcmp(persisted.signature, c->receipt.signature) != 0 ||
        !zcl_hex_decode_lower(persisted.receipt_id, verify_id, 32) ||
        !zcl_hex_decode_lower(persisted.signature, verify_sig, 64) ||
        !ed25519_verify(verify_sig, verify_id, 32, c->signer_pubkey))
        return "attach-persist-failed: reread";
    return NULL;
}

static const char *bfat_publication_authority(struct bfat_attach_ctx *c,
                                              struct db_build_action *next)
{
    int64_t publish_now = bfat_now();
    if (publish_now < c->now) publish_now = c->now;
    c->now = publish_now;
    const char *refusal = bfat_check_requester_worker(c);
    if (!refusal && !bfat_donor_worker_live(c->ndb,
                                            c->donor_receipt.worker_id,
                                            publish_now))
        refusal = "attach-refused-donor-not-qualified";
    next->finished_at = next->updated_at = publish_now;
    return refusal ? refusal : bfat_receipt_prepare(c);
}

/* Publish action, job and signed receipt under the connection mutex. */
static const char *bfat_persist_attach(struct bfat_attach_ctx *c)
{
    struct db_build_action next = c->action;
    (void)snprintf(next.state, sizeof(next.state), "CACHE_HIT");
    (void)snprintf(next.outcome, sizeof(next.outcome), "CACHE_HIT");
    (void)snprintf(next.output_root_sha3, sizeof(next.output_root_sha3), "%s",
                   c->report->output_copy_sha3);
    (void)snprintf(next.worker_id, sizeof(next.worker_id), "%s",
                   c->requester_worker_id);
    (void)snprintf(next.lease_id, sizeof(next.lease_id), "%s",
                   c->report->executor_key);
    sqlite3_mutex *mutex = sqlite3_db_mutex(c->ndb->db);
    if (!mutex)
        return "attach-persist-failed: connection mutex";
    sqlite3_mutex_enter(mutex);
    if (!node_db_begin_immediate(c->ndb)) {
        sqlite3_mutex_leave(mutex);
        return "attach-persist-failed: transaction";
    }
    sqlite3_int64 current_version = 0;
    if (!db_build_attach_ledger_version(c->ndb, &current_version) ||
        current_version != c->db_version ||
        sqlite3_total_changes64(c->ndb->db) != c->db_changes) {
        if (!node_db_rollback(c->ndb))
            LOG_ERROR("build_fabric", "attach stale history rollback failed");
        sqlite3_mutex_leave(mutex);
        return "attach-refused-history-stale";
    }
    const char *refusal = bfat_publication_authority(c, &next);
    if (refusal) {
        if (!node_db_rollback(c->ndb))
            LOG_ERROR("build_fabric", "attach expired authority rollback failed");
        sqlite3_mutex_leave(mutex);
        return refusal;
    }
    bool ok = db_build_action_save(c->ndb, &next) &&
        db_build_attach_settle_job(c->ndb, &c->job, c->now) &&
        db_build_receipt_save(c->ndb, &c->receipt) &&
        node_db_commit(c->ndb);
    if (!ok) {
        if (!node_db_rollback(c->ndb))
            LOG_ERROR("build_fabric", "attach persist and rollback failed");
        sqlite3_mutex_leave(mutex);
        return "attach-persist-failed";
    }
    refusal = bfat_receipt_reread_verify(c);
    sqlite3_mutex_leave(mutex);
    return refusal;
}

struct zcl_result build_fabric_attach(
    struct node_db *ndb, const char *workspace, struct vcs_package_store *store,
    const struct db_build_job *req_job, const struct db_build_action *req_action,
    const uint8_t signer_secret[32], const uint8_t signer_pubkey[32],
    struct db_build_receipt *out_receipt,
    struct build_fabric_attach_report *out_report)
{
    if (out_report) memset(out_report, 0, sizeof(*out_report));
    struct bfat_attach_ctx c;
    memset(&c, 0, sizeof(c));
    c.ndb = ndb;
    c.workspace = workspace;
    c.store = store;
    c.req_job = req_job;
    c.req_action = req_action;
    c.signer_secret = signer_secret;
    c.signer_pubkey = signer_pubkey;
    c.out_receipt = out_receipt;
    c.report = out_report;
    if (!bfat_attach_args_ok(&c))
        return ZCL_ERR(-1, "attach requires db, workspace, plan, and keys");
    c.started_us = platform_time_monotonic_us();
    out_report->disposition = BUILD_FABRIC_ATTACH_MISS;
    out_report->compiler_processes = 0;
    c.now = bfat_now();
    if (!db_build_attach_ledger_version(ndb, &c.db_version))
        return bfat_refuse(out_report, "attach-refused-history-incomplete");
    c.db_changes = sqlite3_total_changes64(ndb->db);
    const char *refusal = bfat_check_request_identity(&c);
    if (!refusal && strcmp(c.job.profile,
                           VCS_BUILD_PROFILE_PHYSICAL_REPRODUCTION_V1) == 0)
        refusal = "attach-refused-independent-run-required";
    if (!refusal)
        refusal = bfat_check_requester_worker(&c);
    if (!refusal)
        refusal = bfat_compose_requester_key(&c);
    if (refusal)
        return bfat_refuse(out_report, refusal);
    if (bfat_key_record_checked(&c, &refusal) ||
        bfat_donor_scan(&c, &refusal))
        return bfat_attach_stop(&c, refusal);

#ifdef ZCL_TESTING
    if (bfat_after_scan_hook)
        bfat_after_scan_hook(bfat_after_scan_context);
#endif
    (void)snprintf(out_report->donor_action_id,
                   sizeof(out_report->donor_action_id), "%s",
                   c.donor_action.action_id);
    (void)snprintf(out_report->donor_receipt_id,
                   sizeof(out_report->donor_receipt_id), "%s",
                   c.donor_receipt.receipt_id);
    /* Verify donor bytes, then store a requester-bound CAS copy. */
    uint8_t *bytes = NULL;
    size_t len = 0;
    uint8_t copy_root[32];
    refusal = bfat_output_fetch(&c, &bytes, &len);
    if (!refusal)
        refusal = bfat_output_store_copy(&c, bytes, len, copy_root);
    free(bytes);
    if (!refusal)
        refusal = bfat_persist_attach(&c);
    if (refusal)
        return bfat_refuse(out_report, refusal);

    (void)snprintf(out_report->requester_receipt_id,
                   sizeof(out_report->requester_receipt_id), "%s",
                   c.receipt.receipt_id);
    out_report->disposition = BUILD_FABRIC_ATTACH_HIT;
    out_report->attach_wall_us = platform_time_monotonic_us() - c.started_us;
    /* Closure capture's four ldd probes do not run the compiler. */
    LOG_INFO("zcode.proof_perf",
             "schema=zcl.async_proof_perf.v1 action=%s stage=worker_attach "
             "at_unix_us=%lld executor_key=%s donor_action=%s "
             "donor_receipt=%s requester_receipt=%s input_bytes=%llu "
             "output_bytes=%llu attach_us=%lld direct_probe_launches=4 "
             "compiler_processes=0 test_processes=0 cache_hit=1 "
             "total_us=%lld",
             c.action.action_id, (long long)platform_time_realtime_us(),
             out_report->executor_key, c.donor_action.action_id,
             c.donor_receipt.receipt_id, c.receipt.receipt_id,
             (unsigned long long)c.input_len,
             (unsigned long long)out_report->restored_bytes,
             (long long)out_report->attach_wall_us,
             (long long)out_report->attach_wall_us);
    *out_receipt = c.receipt;
    return ZCL_OK;
}

#else

#include <string.h>

const char *build_fabric_attach_disposition_string(
    enum build_fabric_attach_disposition disposition)
{
    switch (disposition) {
    case BUILD_FABRIC_ATTACH_MISS: return "miss";
    case BUILD_FABRIC_ATTACH_HIT: return "hit";
    case BUILD_FABRIC_ATTACH_REFUSED: return "refused";
    }
    return "refused";
}

/* Windows has no qualified donor replay. Report a miss so the caller
 * compiles; never report a hit. */
struct zcl_result build_fabric_attach(
    struct node_db *ndb, const char *workspace, struct vcs_package_store *store,
    const struct db_build_job *req_job, const struct db_build_action *req_action,
    const uint8_t signer_secret[32], const uint8_t signer_pubkey[32],
    struct db_build_receipt *out_receipt,
    struct build_fabric_attach_report *out_report)
{
    (void)ndb;
    (void)workspace;
    (void)store;
    (void)req_job;
    (void)req_action;
    (void)signer_secret;
    (void)signer_pubkey;
    (void)out_receipt;
    if (!out_report)
        return ZCL_ERR(-1, "attach requires a report");
    memset(out_report, 0, sizeof(*out_report));
    out_report->disposition = BUILD_FABRIC_ATTACH_MISS;
    out_report->compiler_processes = 0;
    return ZCL_OK;
}

#endif /* !_WIN32 */
