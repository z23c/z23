/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * zcode_task_index — implementation of the rebuildable dev-task projection
 * declared in vcs/zcode_task_index.h. Every build re-walks the workspace CAS
 * and re-verifies each projected wire against its address; nothing is cached
 * across builds. */

#include "vcs/zcode_task_index.h"

#include "base/hex.h"
#include "base/log_macros.h"
#include "base/safe_alloc.h"
#include "vcs/package_build.h"
#include "vcs/package_store.h"
#include "vcs/vcs_object.h"
#include "vcs/zcode_accepted_work.h"
#include "vcs/zcode_agent_context.h"
#include "vcs/zcode_app_run_observation.h"
#include "vcs/zcode_dev.h"
#include "vcs/zcode_lane.h"
#include "vcs/zcode_write_scope.h"
#include "vcs/zcode_work_output.h"

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define INDEX_LOG "vcs.task_index"

/* Wire magics from zcode_dev.c — the first 8 bytes decide whether an object
 * of the right size is even a candidate for projection. */
static const uint8_t task_magic[8] = {'Z','C','T','A','S','K','\r','\n'};
static const uint8_t candidate_magic[8] = {'Z','C','C','A','N','D','\r','\n'};
static const uint8_t context_magic[8] = {'Z','C','A','C','T','X','\r','\n'};
static const uint8_t receipt_magic[8] = {'Z','C','W','R','C','P','\r','\n'};
static const uint8_t lane_magic[8] = {'Z','C','L','A','N','E','\r','\n'};

struct vcs_zcode_task_index {
    struct vcs_zcode_task_index_entry *tasks;
    size_t task_count;
    struct vcs_zcode_task_candidate_entry *candidates;
    size_t candidate_count;
    struct vcs_zcode_task_context_entry *contexts;
    size_t context_count;
    struct vcs_zcode_task_receipt_entry *receipts;
    size_t receipt_count;
    struct vcs_zcode_task_lane_entry *lanes;
    size_t lane_count;
    bool complete;
    int64_t now_unix;
};

static bool index_hex_lower(const char *s, size_t want)
{
    for (size_t i = 0; i < want; i++) {
        char c = s[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
            return false;
    }
    return s[want] == '\0';
}

/* Project one CAS object when it is a verified task or candidate wire.
 * Wrong size or wrong magic means the object is another CAS citizen and is
 * skipped silently; right magic with a failed parse/validation/root check is
 * corruption and is logged. */
static void index_consider_object(const char *repo_root, const char *hex64,
                                  struct vcs_zcode_task_index *index,
                                  bool *cap_logged)
{
    uint8_t address[32];
    if (!zcl_hex_decode_lower(hex64, address, 32))
        return;
    uint8_t *wire = NULL;
    size_t len = 0;
    if (vcs_object_load_raw(repo_root, address, &wire, &len) != 0) {
        index->complete = false;
        LOG_ERROR(INDEX_LOG, "unreadable CAS object %.8s", hex64);
        return;
    }
    if (len == VCS_ZCODE_TASK_WIRE_BYTES &&
        memcmp(wire, task_magic, sizeof(task_magic)) == 0) {
        struct vcs_zcode_task_v1 task;
        uint8_t root[32];
        bool ok = vcs_zcode_task_parse(wire, len, &task) == VCS_ZCODE_DEV_OK &&
            vcs_zcode_task_validate(&task) == VCS_ZCODE_DEV_OK &&
            vcs_zcode_task_root(&task, root) == VCS_ZCODE_DEV_OK &&
            memcmp(root, address, 32) == 0;
        if (!ok) {
            LOG_ERROR(INDEX_LOG, "skipping task-magic object %.8s: "
                      "parse, validation, or root agreement failed", hex64);
        } else if (index->task_count >= VCS_ZCODE_TASK_INDEX_MAX_TASKS) {
            if (!*cap_logged) {
                LOG_ERROR(INDEX_LOG, "task index cap %u reached",
                          VCS_ZCODE_TASK_INDEX_MAX_TASKS);
                *cap_logged = true;
            }
        } else {
            struct vcs_zcode_task_index_entry *e =
                &index->tasks[index->task_count++];
            memset(e, 0, sizeof(*e));
            zcl_hex_encode(address, 32, e->task_root_hex);
            zcl_hex_encode(task.source_root, 32, e->source_root_hex);
            zcl_hex_encode(task.goal_root, 32, e->goal_root_hex);
            zcl_hex_encode(task.proof_policy_root, 32,
                           e->proof_policy_root_hex);
            zcl_hex_encode(task.acceptance_tests_root, 32,
                           e->acceptance_tests_root_hex);
            zcl_hex_encode(task.toolchain_capsule_root, 32,
                           e->toolchain_capsule_root_hex);
            zcl_hex_encode(task.write_scope_root, 32,
                           e->write_scope_root_hex);
            e->expires_unix = task.expires_unix;
        }
    } else if (len == VCS_ZCODE_CANDIDATE_WIRE_BYTES &&
               memcmp(wire, candidate_magic, sizeof(candidate_magic)) == 0) {
        struct vcs_zcode_candidate_v1 candidate;
        uint8_t root[32];
        bool ok = vcs_zcode_candidate_parse(wire, len, &candidate) ==
                VCS_ZCODE_DEV_OK &&
            vcs_zcode_candidate_validate(&candidate) == VCS_ZCODE_DEV_OK &&
            vcs_zcode_candidate_root(&candidate, root) == VCS_ZCODE_DEV_OK &&
            memcmp(root, address, 32) == 0;
        if (!ok) {
            LOG_ERROR(INDEX_LOG, "skipping candidate-magic object %.8s: "
                      "parse, validation, or root agreement failed", hex64);
        } else if (index->candidate_count >=
                   VCS_ZCODE_TASK_INDEX_MAX_CANDIDATES) {
            if (!*cap_logged) {
                LOG_ERROR(INDEX_LOG, "candidate index cap %u reached",
                          VCS_ZCODE_TASK_INDEX_MAX_CANDIDATES);
                *cap_logged = true;
            }
        } else {
            struct vcs_zcode_task_candidate_entry *e =
                &index->candidates[index->candidate_count++];
            memset(e, 0, sizeof(*e));
            zcl_hex_encode(candidate.task_root, 32, e->task_root_hex);
            zcl_hex_encode(address, 32, e->candidate_root_hex);
            zcl_hex_encode(candidate.candidate_source_root, 32,
                           e->candidate_source_root_hex);
            zcl_hex_encode(candidate.patch_root, 32, e->patch_root_hex);
            zcl_hex_encode(candidate.author_pubkey, 32, e->author_pubkey_hex);
            e->sequence = candidate.sequence;
            e->created_unix = candidate.created_unix;
        }
    } else if (len >= VCS_ZCODE_AGENT_CONTEXT_FIXED_BYTES &&
               memcmp(wire, context_magic, sizeof(context_magic)) == 0) {
        struct vcs_zcode_agent_context_v1 context;
        uint8_t root[32];
        bool parsed = vcs_zcode_agent_context_parse(
                wire, len, VCS_ZCODE_TASK_MAX_CONTEXT_BYTES, &context) ==
                VCS_ZCODE_AGENT_CONTEXT_OK;
        bool ok = parsed && vcs_zcode_agent_context_root(
                &context, VCS_ZCODE_TASK_MAX_CONTEXT_BYTES, root) ==
                VCS_ZCODE_AGENT_CONTEXT_OK && memcmp(root, address, 32) == 0;
        if (!ok) {
            LOG_ERROR(INDEX_LOG, "skipping context-magic object %.8s: "
                      "parse, validation, or root agreement failed", hex64);
        } else if (index->context_count >= VCS_ZCODE_TASK_INDEX_MAX_CONTEXTS) {
            if (!*cap_logged) {
                LOG_ERROR(INDEX_LOG, "context index cap %u reached",
                          VCS_ZCODE_TASK_INDEX_MAX_CONTEXTS);
                *cap_logged = true;
            }
        } else {
            struct vcs_zcode_task_context_entry *e =
                &index->contexts[index->context_count++];
            memset(e, 0, sizeof(*e));
            zcl_hex_encode(context.task_root, 32, e->task_root_hex);
            zcl_hex_encode(address, 32, e->context_root_hex);
            (void)snprintf(e->query, sizeof(e->query), "%s", context.query);
            e->wire_bytes = len;
            e->file_count = (uint32_t)context.file_count;
            for (size_t i = 0; i < context.file_count; i++)
                e->excerpt_bytes += context.files[i].content_len;
        }
        if (parsed) vcs_zcode_agent_context_free(&context);
    } else if (len == VCS_ZCODE_WORK_RECEIPT_WIRE_BYTES &&
               memcmp(wire, receipt_magic, sizeof(receipt_magic)) == 0) {
        struct vcs_zcode_work_receipt_v1 receipt;
        uint8_t root[32];
        bool ok = vcs_zcode_work_receipt_parse(wire, len, &receipt) ==
                VCS_ZCODE_DEV_OK &&
            vcs_zcode_work_receipt_id(&receipt, root) == VCS_ZCODE_DEV_OK &&
            memcmp(root, address, 32) == 0 &&
            vcs_zcode_work_receipt_verify(
                &receipt, receipt.signer_pubkey) == VCS_ZCODE_DEV_OK;
        if (!ok) {
            LOG_ERROR(INDEX_LOG, "skipping receipt-magic object %.8s: "
                      "parse, signature, or root agreement failed", hex64);
        } else if (index->receipt_count >= VCS_ZCODE_TASK_INDEX_MAX_RECEIPTS) {
            if (!*cap_logged) {
                LOG_ERROR(INDEX_LOG, "receipt index cap %u reached",
                          VCS_ZCODE_TASK_INDEX_MAX_RECEIPTS);
                *cap_logged = true;
            }
        } else {
            struct vcs_zcode_task_receipt_entry *e =
                &index->receipts[index->receipt_count++];
            memset(e, 0, sizeof(*e));
            zcl_hex_encode(receipt.task_root, 32, e->task_root_hex);
            zcl_hex_encode(receipt.candidate_root, 32,
                           e->candidate_root_hex);
            zcl_hex_encode(receipt.proof_policy_root, 32,
                           e->proof_policy_root_hex);
            zcl_hex_encode(receipt.toolchain_capsule_root, 32,
                           e->toolchain_capsule_root_hex);
            zcl_hex_encode(address, 32, e->receipt_root_hex);
            zcl_hex_encode(receipt.output_root, 32, e->output_root_hex);
            zcl_hex_encode(receipt.action_root, 32, e->action_root_hex);
            zcl_hex_encode(receipt.input_root, 32, e->input_root_hex);
            zcl_hex_encode(receipt.evidence_root, 32,
                           e->evidence_root_hex);
            zcl_hex_encode(receipt.confinement_root, 32,
                           e->confinement_root_hex);
            zcl_hex_encode(receipt.signer_pubkey, 32,
                           e->signer_pubkey_hex);
            e->work_kind = receipt.work_kind;
            e->status = receipt.status;
            e->exit_status = receipt.exit_status;
            e->started_unix = receipt.started_unix;
            e->finished_unix = receipt.finished_unix;
        }
    } else if (len == VCS_ZCODE_LANE_WIRE_BYTES &&
               memcmp(wire, lane_magic, sizeof(lane_magic)) == 0) {
        struct vcs_zcode_lane_receipt_v1 lane;
        uint8_t root[32];
        bool ok = vcs_zcode_lane_receipt_parse(wire, len, &lane) ==
                VCS_ZCODE_DEV_OK &&
            vcs_zcode_lane_receipt_id(&lane, root) == VCS_ZCODE_DEV_OK &&
            memcmp(root, address, 32) == 0 &&
            vcs_zcode_lane_receipt_verify(&lane, lane.signer_pubkey) ==
                VCS_ZCODE_DEV_OK;
        if (!ok) {
            LOG_ERROR(INDEX_LOG, "skipping lane-magic object %.8s: "
                      "parse, signature, or root agreement failed", hex64);
        } else if (index->lane_count >= VCS_ZCODE_TASK_INDEX_MAX_LANES) {
            if (!*cap_logged) {
                LOG_ERROR(INDEX_LOG, "lane index cap %u reached",
                          VCS_ZCODE_TASK_INDEX_MAX_LANES);
                *cap_logged = true;
            }
        } else {
            struct vcs_zcode_task_lane_entry *e =
                &index->lanes[index->lane_count++];
            memset(e, 0, sizeof(*e));
            zcl_hex_encode(address, 32, e->receipt_root_hex);
            zcl_hex_encode(lane.task_root, 32, e->task_root_hex);
            zcl_hex_encode(lane.candidate_root, 32, e->candidate_root_hex);
            zcl_hex_encode(lane.source_root, 32, e->source_root_hex);
            zcl_hex_encode(lane.proof_policy_root, 32,
                           e->proof_policy_root_hex);
            if (lane.lane != VCS_ZCODE_LANE_FRONTIER) {
                zcl_hex_encode(lane.proof_set_root, 32,
                               e->proof_set_root_hex);
                zcl_hex_encode(lane.prior_receipt_root, 32,
                               e->prior_receipt_root_hex);
            }
            zcl_hex_encode(lane.signer_pubkey, 32, e->signer_pubkey_hex);
            e->lane = lane.lane;
            e->created_unix = lane.created_unix;
        }
    }
    free(wire);
}

static void index_scan_shard(const char *repo_root, const char *shard_path,
                             const char *shard,
                             struct vcs_zcode_task_index *index,
                             bool *cap_logged)
{
    DIR *d = opendir(shard_path);
    if (!d) {
        index->complete = false;
        LOG_ERROR(INDEX_LOG, "cannot open CAS shard %s", shard_path);
        return;
    }
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (!index_hex_lower(de->d_name, 62))
            continue;
        char hex64[65];
        int n = snprintf(hex64, sizeof(hex64), "%s%s", shard, de->d_name);
        if (n != 64)
            continue;
        index_consider_object(repo_root, hex64, index, cap_logged);
    }
    closedir(d);
}

static int index_task_cmp(const void *a, const void *b)
{
    return strcmp(((const struct vcs_zcode_task_index_entry *)a)->task_root_hex,
                  ((const struct vcs_zcode_task_index_entry *)b)->task_root_hex);
}

static int index_candidate_cmp(const void *a, const void *b)
{
    return strcmp(
        ((const struct vcs_zcode_task_candidate_entry *)a)->candidate_root_hex,
        ((const struct vcs_zcode_task_candidate_entry *)b)->candidate_root_hex);
}

static const struct vcs_zcode_task_lane_entry *index_lane_find(
    const struct vcs_zcode_task_index *index, const char *root_hex)
{
    for (size_t i = 0; i < index->lane_count; i++)
        if (strcmp(index->lanes[i].receipt_root_hex, root_hex) == 0)
            return &index->lanes[i];
    return NULL;
}

static bool index_proof_set_valid(const char *repo_root, const char *root_hex)
{
    uint8_t root[32], checked[32], *wire = NULL;
    uint8_t receipts[VCS_ZCODE_PROOF_SET_MAX_RECEIPTS][32];
    size_t wire_len = 0, receipt_count = 0;
    bool ok = zcl_hex_decode_lower(root_hex, root, sizeof(root)) &&
        vcs_object_load_raw_bounded(repo_root, root,
                                    VCS_ZCODE_PROOF_SET_WIRE_MAX,
                                    &wire, &wire_len) == 0 &&
        vcs_zcode_proof_set_parse(
            wire, wire_len, receipts,
            VCS_ZCODE_PROOF_SET_MAX_RECEIPTS, &receipt_count) ==
                VCS_ZCODE_DEV_OK &&
        vcs_zcode_proof_set_root(
            (const uint8_t (*)[32])receipts, receipt_count, checked) ==
                VCS_ZCODE_DEV_OK &&
        memcmp(root, checked, sizeof(root)) == 0;
    free(wire); return ok;
}

static bool index_review_valid(
    const char *repo_root, const struct vcs_zcode_task_index_entry *task,
    const struct vcs_zcode_task_candidate_entry *candidate,
    const struct vcs_zcode_task_receipt_entry *receipt,
    uint8_t *verdict_out)
{
    uint8_t root[32], checked[32], signer[32], *wire = NULL;
    size_t wire_len = 0;
    struct vcs_zcode_review_v1 review;
    bool ok = receipt->work_kind == VCS_ZCODE_WORK_REVIEW &&
        receipt->status == VCS_ZCODE_WORK_PASS && receipt->exit_status == 0 &&
        zcl_hex_decode_lower(receipt->output_root_hex, root, 32) &&
        zcl_hex_decode_lower(receipt->signer_pubkey_hex, signer, 32) &&
        vcs_object_load_raw_bounded(repo_root, root,
                                    VCS_ZCODE_REVIEW_WIRE_BYTES,
                                    &wire, &wire_len) == 0 &&
        vcs_zcode_review_parse(wire, wire_len, &review) ==
            VCS_ZCODE_DEV_OK &&
        vcs_zcode_review_root(&review, checked) == VCS_ZCODE_DEV_OK &&
        memcmp(root, checked, 32) == 0 &&
        memcmp(review.reviewer_pubkey, signer, 32) == 0;
    free(wire);
    if (!ok) return false;
    char bound[65];
    zcl_hex_encode(review.task_root, 32, bound);
    ok = strcmp(bound, task->task_root_hex) == 0;
    zcl_hex_encode(review.candidate_root, 32, bound);
    ok = ok && strcmp(bound, candidate->candidate_root_hex) == 0;
    zcl_hex_encode(review.proof_policy_root, 32, bound);
    ok = ok && strcmp(bound, task->proof_policy_root_hex) == 0;
    zcl_hex_encode(review.proof_set_root, 32, bound);
    ok = ok && index_proof_set_valid(repo_root, bound);
    if (ok && verdict_out) *verdict_out = review.verdict;
    return ok;
}

static const struct vcs_zcode_task_receipt_entry *index_receipt_find(
    const struct vcs_zcode_task_index *index, const uint8_t root[32])
{
    char root_hex[65];
    zcl_hex_encode(root, 32, root_hex);
    for (size_t i = 0; i < index->receipt_count; i++)
        if (strcmp(index->receipts[i].receipt_root_hex, root_hex) == 0)
            return &index->receipts[i];
    return NULL;
}

/* A BUILD output can name the executed object directly, or it can be the
 * action-bound carrier for a canonical package-build report.  In the latter
 * case the exact emitted-file hashes live inside that report; the carrier
 * root is evidence about those bytes, not the bytes themselves. */
static bool index_app_artifact_built(
    const char *repo_root,
    const struct vcs_zcode_task_receipt_entry *build,
    const uint8_t artifact_root[32])
{
    uint8_t output_root[32], action_root[32], *wire = NULL;
    size_t wire_len = 0;
    if (!repo_root || !build || !artifact_root ||
        !zcl_hex_decode_lower(build->output_root_hex, output_root, 32) ||
        !zcl_hex_decode_lower(build->action_root_hex, action_root, 32))
        return false;
    if (memcmp(output_root, artifact_root, 32) == 0 &&
        vcs_object_load_raw(repo_root, output_root, &wire, &wire_len) == 0) {
        free(wire);
        return true;
    }
    struct vcs_package_store *store = vcs_package_store_global();
    enum vcs_zcode_work_output_result loaded = store
        ? vcs_zcode_work_output_get(
              store, output_root, action_root, &wire, &wire_len)
        : VCS_ZCODE_WORK_OUTPUT_ABSENT;
    struct vcs_package_build_receipt report;
    bool matched = loaded == VCS_ZCODE_WORK_OUTPUT_OK &&
        wire_len <= VCS_PACKAGE_BUILD_MAX_WIRE_BYTES &&
        vcs_package_build_parse(wire, wire_len, &report) ==
            VCS_PACKAGE_BUILD_OK;
    if (matched) {
        matched = false;
        for (size_t i = 0; i < report.output_count; i++)
            if (memcmp(report.outputs[i].sha3, artifact_root, 32) == 0) {
                matched = true;
                break;
            }
    }
    free(wire);
    return matched;
}

/* A signed app-run receipt is display evidence only. Re-derive its nested
 * observation and require an earlier passing build receipt under the same
 * task/candidate/policy/toolchain. This establishes the exact statement the
 * observer signed; it does not promote that statement into acceptance or
 * prove general code safety. */
static bool index_app_run_valid(
    const struct vcs_zcode_task_index *index, const char *repo_root,
    const struct vcs_zcode_task_index_entry *task,
    const struct vcs_zcode_task_candidate_entry *candidate,
    const struct vcs_zcode_task_receipt_entry *receipt,
    struct vcs_zcode_app_run_observation_v1 *out)
{
    if (!index || !repo_root || !task || !candidate || !receipt || !out ||
        receipt->work_kind != VCS_ZCODE_WORK_APP_RUN ||
        strcmp(receipt->task_root_hex, task->task_root_hex) != 0 ||
        strcmp(receipt->candidate_root_hex,
               candidate->candidate_root_hex) != 0 ||
        strcmp(receipt->proof_policy_root_hex,
               task->proof_policy_root_hex) != 0 ||
        strcmp(receipt->toolchain_capsule_root_hex,
               task->toolchain_capsule_root_hex) != 0 ||
        strcmp(receipt->output_root_hex, receipt->evidence_root_hex) != 0)
        return false;
    uint8_t root[32], checked[32], *wire = NULL;
    size_t wire_len = 0;
    bool ok = zcl_hex_decode_lower(receipt->evidence_root_hex, root, 32) &&
        vcs_object_load_raw_bounded(
            repo_root, root, VCS_ZCODE_APP_RUN_OBSERVATION_WIRE_BYTES,
            &wire, &wire_len) == 0 &&
        vcs_zcode_app_run_observation_v1_parse(wire, wire_len, out) ==
            VCS_ZCODE_APP_RUN_OK &&
        vcs_zcode_app_run_observation_v1_root(out, checked) ==
            VCS_ZCODE_APP_RUN_OK &&
        memcmp(root, checked, 32) == 0;
    free(wire);
    if (!ok) return false;
    char bound[65];
    zcl_hex_encode(out->task_root, 32, bound);
    ok = strcmp(bound, task->task_root_hex) == 0;
    zcl_hex_encode(out->candidate_root, 32, bound);
    ok = ok && strcmp(bound, candidate->candidate_root_hex) == 0;
    zcl_hex_encode(out->invocation_root, 32, bound);
    ok = ok && strcmp(bound, receipt->input_root_hex) == 0;
    zcl_hex_encode(out->confinement_root, 32, bound);
    ok = ok && strcmp(bound, receipt->confinement_root_hex) == 0 &&
        out->started_unix == receipt->started_unix &&
        out->finished_unix == receipt->finished_unix &&
        out->exit_status == receipt->exit_status;
    const struct vcs_zcode_task_receipt_entry *build =
        index_receipt_find(index, out->build_receipt_root);
    ok = ok && build && build->work_kind == VCS_ZCODE_WORK_BUILD &&
        build->status == VCS_ZCODE_WORK_PASS && build->exit_status == 0 &&
        strcmp(build->task_root_hex, task->task_root_hex) == 0 &&
        strcmp(build->candidate_root_hex,
               candidate->candidate_root_hex) == 0 &&
        strcmp(build->proof_policy_root_hex,
               task->proof_policy_root_hex) == 0 &&
        strcmp(build->toolchain_capsule_root_hex,
               task->toolchain_capsule_root_hex) == 0 &&
        build->finished_unix <= out->started_unix;
    ok = ok && build && index_app_artifact_built(
        repo_root, build, out->artifact_root);
    bool success = vcs_zcode_app_run_observation_v1_proves_success(out);
    return ok && ((success && receipt->status == VCS_ZCODE_WORK_PASS) ||
                  (!success && receipt->status != VCS_ZCODE_WORK_PASS));
}

static bool index_lane_chain_valid(
    const struct vcs_zcode_task_index *index, const char *repo_root,
    const struct vcs_zcode_task_lane_entry *lane, unsigned depth)
{
    if (!lane || depth > VCS_ZCODE_LANE_PROVEN) return false;
    if (lane->lane == VCS_ZCODE_LANE_FRONTIER)
        return lane->prior_receipt_root_hex[0] == '\0' &&
               lane->proof_set_root_hex[0] == '\0';
    if (!index_proof_set_valid(repo_root, lane->proof_set_root_hex))
        return false;
    const struct vcs_zcode_task_lane_entry *prior = index_lane_find(
        index, lane->prior_receipt_root_hex);
    return prior && prior->lane + 1u == lane->lane &&
        prior->created_unix <= lane->created_unix &&
        strcmp(prior->task_root_hex, lane->task_root_hex) == 0 &&
        strcmp(prior->candidate_root_hex, lane->candidate_root_hex) == 0 &&
        strcmp(prior->source_root_hex, lane->source_root_hex) == 0 &&
        strcmp(prior->proof_policy_root_hex,
               lane->proof_policy_root_hex) == 0 &&
        strcmp(prior->signer_pubkey_hex, lane->signer_pubkey_hex) == 0 &&
        index_lane_chain_valid(index, repo_root, prior, depth + 1u);
}

static void index_derive_states(struct vcs_zcode_task_index *index,
                                const char *repo_root,
                                int64_t now_unix)
{
    for (size_t i = 0; i < index->task_count; i++) {
        struct vcs_zcode_task_index_entry *e = &index->tasks[i];
        const struct vcs_zcode_task_candidate_entry *latest_candidate = NULL;
        for (size_t c = 0; c < index->candidate_count; c++) {
            const struct vcs_zcode_task_candidate_entry *candidate =
                &index->candidates[c];
            if (strcmp(candidate->task_root_hex, e->task_root_hex) == 0) {
                e->candidate_count++;
                if (!latest_candidate ||
                    candidate->sequence > latest_candidate->sequence ||
                    (candidate->sequence == latest_candidate->sequence &&
                     (candidate->created_unix > latest_candidate->created_unix ||
                      (candidate->created_unix == latest_candidate->created_unix &&
                       strcmp(candidate->candidate_root_hex,
                              latest_candidate->candidate_root_hex) > 0))))
                    latest_candidate = candidate;
            }
        }
        if (latest_candidate) {
            e->latest_candidate_sequence = latest_candidate->sequence;
            (void)snprintf(e->latest_candidate_root_hex,
                           sizeof(e->latest_candidate_root_hex), "%s",
                           latest_candidate->candidate_root_hex);
            (void)snprintf(e->latest_candidate_source_root_hex,
                           sizeof(e->latest_candidate_source_root_hex), "%s",
                           latest_candidate->candidate_source_root_hex);
            (void)snprintf(e->latest_patch_root_hex,
                           sizeof(e->latest_patch_root_hex), "%s",
                           latest_candidate->patch_root_hex);
        }
        int64_t latest_finished = 0, latest_review_finished = 0;
        int64_t latest_app_run_finished = 0;
        for (size_t r = 0; r < index->receipt_count; r++) {
            const struct vcs_zcode_task_receipt_entry *receipt =
                &index->receipts[r];
            if (strcmp(receipt->task_root_hex, e->task_root_hex) != 0 ||
                strcmp(receipt->proof_policy_root_hex,
                       e->proof_policy_root_hex) != 0 ||
                strcmp(receipt->toolchain_capsule_root_hex,
                       e->toolchain_capsule_root_hex) != 0)
                continue;
            bool candidate_bound = false;
            for (size_t c = 0; c < index->candidate_count; c++)
                if (strcmp(index->candidates[c].task_root_hex,
                           e->task_root_hex) == 0 &&
                    strcmp(index->candidates[c].candidate_root_hex,
                           receipt->candidate_root_hex) == 0) {
                    candidate_bound = true;
                    break;
            }
            if (!candidate_bound) continue;
            if (receipt->work_kind == VCS_ZCODE_WORK_APP_RUN) {
                if (latest_candidate &&
                    strcmp(receipt->candidate_root_hex,
                           latest_candidate->candidate_root_hex) == 0) {
                    e->app_run_receipt_count++;
                    struct vcs_zcode_app_run_observation_v1 observation;
                    if (index_app_run_valid(index, repo_root, e,
                                            latest_candidate, receipt,
                                            &observation)) {
                        e->valid_app_run_receipt_count++;
                        if (receipt->finished_unix > latest_app_run_finished ||
                            (receipt->finished_unix ==
                                 latest_app_run_finished &&
                             strcmp(receipt->receipt_root_hex,
                                    e->latest_app_run_receipt_hex) > 0)) {
                            latest_app_run_finished = receipt->finished_unix;
                            (void)snprintf(
                                e->latest_app_run_receipt_hex,
                                sizeof(e->latest_app_run_receipt_hex), "%s",
                                receipt->receipt_root_hex);
                            (void)snprintf(
                                e->latest_app_run_observation_hex,
                                sizeof(e->latest_app_run_observation_hex),
                                "%s", receipt->evidence_root_hex);
                            (void)snprintf(
                                e->latest_app_run_action_root_hex,
                                sizeof(e->latest_app_run_action_root_hex),
                                "%s", receipt->action_root_hex);
                            zcl_hex_encode(
                                observation.artifact_root, 32,
                                e->latest_app_run_artifact_root_hex);
                            zcl_hex_encode(
                                observation.invocation_root, 32,
                                e->latest_app_run_invocation_root_hex);
                            e->latest_app_run_flags = observation.flags;
                            e->latest_app_run_status = receipt->status;
                            e->latest_app_run_exit_status =
                                receipt->exit_status;
                            e->latest_app_run_finished_unix =
                                receipt->finished_unix;
                        }
                    }
                }
                continue;
            }
            e->receipt_count++;
            if (receipt->status == VCS_ZCODE_WORK_PASS &&
                receipt->exit_status == 0)
                e->passing_receipt_count++;
            uint8_t review_verdict = 0;
            if (latest_candidate &&
                strcmp(receipt->candidate_root_hex,
                       latest_candidate->candidate_root_hex) == 0 &&
                index_review_valid(repo_root, e, latest_candidate, receipt,
                                   &review_verdict)) {
                e->review_count++;
                if (receipt->finished_unix > latest_review_finished ||
                    (receipt->finished_unix == latest_review_finished &&
                     strcmp(receipt->output_root_hex,
                            e->latest_review_root_hex) > 0)) {
                    latest_review_finished = receipt->finished_unix;
                    e->latest_review_verdict = review_verdict;
                    (void)snprintf(e->latest_review_root_hex,
                                   sizeof(e->latest_review_root_hex), "%s",
                                   receipt->output_root_hex);
                }
            }
            if (latest_candidate &&
                strcmp(receipt->candidate_root_hex,
                       latest_candidate->candidate_root_hex) == 0 &&
                (receipt->finished_unix > latest_finished ||
                 (receipt->finished_unix == latest_finished &&
                  strcmp(receipt->receipt_root_hex,
                         e->latest_work_receipt_hex) > 0))) {
                latest_finished = receipt->finished_unix;
                (void)snprintf(e->latest_work_receipt_hex,
                               sizeof(e->latest_work_receipt_hex), "%s",
                               receipt->receipt_root_hex);
                (void)snprintf(e->latest_receipt_output_root_hex,
                               sizeof(e->latest_receipt_output_root_hex), "%s",
                               receipt->output_root_hex);
                (void)snprintf(e->latest_action_root_hex,
                               sizeof(e->latest_action_root_hex), "%s",
                               receipt->action_root_hex);
                e->latest_receipt_status = receipt->status;
                e->latest_receipt_exit_status = receipt->exit_status;
            }
        }
        const struct vcs_zcode_task_lane_entry *latest_lane = NULL;
        for (size_t l = 0; latest_candidate && l < index->lane_count; l++) {
            const struct vcs_zcode_task_lane_entry *lane = &index->lanes[l];
            if (strcmp(lane->task_root_hex, e->task_root_hex) != 0 ||
                strcmp(lane->candidate_root_hex,
                       latest_candidate->candidate_root_hex) != 0 ||
                strcmp(lane->source_root_hex,
                       latest_candidate->candidate_source_root_hex) != 0 ||
                strcmp(lane->proof_policy_root_hex,
                       e->proof_policy_root_hex) != 0 ||
                strcmp(lane->signer_pubkey_hex,
                       latest_candidate->author_pubkey_hex) != 0 ||
                !index_lane_chain_valid(index, repo_root, lane, 1u))
                continue;
            if (lane->lane == VCS_ZCODE_LANE_PROVEN) {
                uint8_t accepted_root[32];
                struct vcs_zcode_accepted_work_v1 accepted;
                if (!zcl_hex_decode_lower(
                        lane->receipt_root_hex, accepted_root, 32) ||
                    !vcs_zcode_accepted_work_resolve(
                        repo_root, accepted_root, now_unix, &accepted))
                    continue;
            }
            if (!latest_lane || lane->lane > latest_lane->lane ||
                (lane->lane == latest_lane->lane &&
                 (lane->created_unix > latest_lane->created_unix ||
                  (lane->created_unix == latest_lane->created_unix &&
                   strcmp(lane->receipt_root_hex,
                          latest_lane->receipt_root_hex) > 0))))
                latest_lane = lane;
        }
        if (latest_lane) {
            e->latest_lane = latest_lane->lane;
            (void)snprintf(e->latest_lane_receipt_hex,
                           sizeof(e->latest_lane_receipt_hex), "%s",
                           latest_lane->receipt_root_hex);
            e->latest_lane_created_unix = latest_lane->created_unix;
            (void)snprintf(e->latest_proof_set_root_hex,
                           sizeof(e->latest_proof_set_root_hex), "%s",
                           latest_lane->proof_set_root_hex);
        }
        e->expired = now_unix > 0 && now_unix >= e->expires_unix;
        const char *state = e->expired ? VCS_ZCODE_TASK_STATE_EXPIRED
            : e->latest_lane == VCS_ZCODE_LANE_PROVEN
                ? VCS_ZCODE_TASK_STATE_PROVEN
            : e->latest_lane == VCS_ZCODE_LANE_CANDIDATE
                ? VCS_ZCODE_TASK_STATE_CANDIDATE_PROOFS_READY
            : e->latest_work_receipt_hex[0] &&
              e->latest_receipt_status == VCS_ZCODE_WORK_PASS &&
              e->latest_receipt_exit_status == 0
                ? VCS_ZCODE_TASK_STATE_EVIDENCE_READY
            : e->latest_work_receipt_hex[0]
                ? VCS_ZCODE_TASK_STATE_REPAIR_NEEDED
            : e->candidate_count > 0 ? VCS_ZCODE_TASK_STATE_CANDIDATE_ADMITTED
            : VCS_ZCODE_TASK_STATE_AWAITING_CANDIDATE;
        (void)snprintf(e->state, sizeof(e->state), "%s", state);
    }
}

struct vcs_zcode_task_index *vcs_zcode_task_index_build(
    const char *repo_root, int64_t now_unix)
{
    if (!repo_root)
        LOG_RETURN(NULL, INDEX_LOG, "null repo_root");
    struct vcs_zcode_task_index *index =
        zcl_malloc(sizeof(*index), "vcs_zcode_task_index");
    if (!index)
        LOG_RETURN(NULL, INDEX_LOG, "index alloc");
    memset(index, 0, sizeof(*index));
    index->complete = now_unix > 0;
    index->now_unix = now_unix;
    index->tasks = zcl_malloc(sizeof(*index->tasks) *
                              VCS_ZCODE_TASK_INDEX_MAX_TASKS, "task_index_rows");
    index->candidates = zcl_malloc(sizeof(*index->candidates) *
                                   VCS_ZCODE_TASK_INDEX_MAX_CANDIDATES,
                                   "task_index_candidates");
    index->contexts = zcl_malloc(sizeof(*index->contexts) *
                                 VCS_ZCODE_TASK_INDEX_MAX_CONTEXTS,
                                 "task_index_contexts");
    index->receipts = zcl_malloc(sizeof(*index->receipts) *
                                 VCS_ZCODE_TASK_INDEX_MAX_RECEIPTS,
                                 "task_index_receipts");
    index->lanes = zcl_malloc(sizeof(*index->lanes) *
                              VCS_ZCODE_TASK_INDEX_MAX_LANES,
                              "task_index_lanes");
    if (!index->tasks || !index->candidates || !index->contexts ||
        !index->receipts || !index->lanes) {
        free(index->lanes);
        free(index->receipts);
        free(index->contexts);
        free(index->candidates);
        free(index->tasks);
        free(index);
        LOG_RETURN(NULL, INDEX_LOG, "entry arrays");
    }
    char objects[4400];
    int n = snprintf(objects, sizeof(objects), "%s/.zvcs/objects", repo_root);
    if (n <= 0 || (size_t)n >= sizeof(objects)) {
        vcs_zcode_task_index_free(index);
        LOG_RETURN(NULL, INDEX_LOG, "objects path too long");
    }
    DIR *d = opendir(objects);
    if (!d) {
        if (errno != ENOENT)
            index->complete = false;
        return index; /* absent store is an empty projection, not an error */
    }
    bool cap_logged = false;
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (!index_hex_lower(de->d_name, 2))
            continue; /* skips "tmp" and any non-shard entry */
        char shard_path[4400];
        n = snprintf(shard_path, sizeof(shard_path), "%s/%s", objects,
                     de->d_name);
        if (n <= 0 || (size_t)n >= sizeof(shard_path)) {
            index->complete = false;
            continue;
        }
        index_scan_shard(repo_root, shard_path, de->d_name, index, &cap_logged);
    }
    if (cap_logged)
        index->complete = false;
    closedir(d);
    if (index->task_count > 1)
        qsort(index->tasks, index->task_count, sizeof(*index->tasks),
              index_task_cmp);
    if (index->candidate_count > 1)
        qsort(index->candidates, index->candidate_count,
              sizeof(*index->candidates), index_candidate_cmp);
    index_derive_states(index, repo_root, now_unix);
    return index;
}

void vcs_zcode_task_index_free(struct vcs_zcode_task_index *index)
{
    if (!index)
        return;
    free(index->lanes);
    free(index->receipts);
    free(index->contexts);
    free(index->candidates);
    free(index->tasks);
    free(index);
}

size_t vcs_zcode_task_index_task_count(
    const struct vcs_zcode_task_index *index)
{
    return index ? index->task_count : 0;
}

const struct vcs_zcode_task_index_entry *vcs_zcode_task_index_task_at(
    const struct vcs_zcode_task_index *index, size_t i)
{
    if (!index || i >= index->task_count)
        return NULL;
    return &index->tasks[i];
}

size_t vcs_zcode_task_index_candidate_count(
    const struct vcs_zcode_task_index *index)
{
    return index ? index->candidate_count : 0;
}

const struct vcs_zcode_task_candidate_entry *
vcs_zcode_task_index_candidate_at(const struct vcs_zcode_task_index *index,
                                  size_t i)
{
    if (!index || i >= index->candidate_count)
        return NULL;
    return &index->candidates[i];
}

size_t vcs_zcode_task_index_lane_count(
    const struct vcs_zcode_task_index *index)
{
    return index ? index->lane_count : 0;
}

const struct vcs_zcode_task_lane_entry *vcs_zcode_task_index_lane_at(
    const struct vcs_zcode_task_index *index, size_t i)
{
    return index && i < index->lane_count ? &index->lanes[i] : NULL;
}

const struct vcs_zcode_task_context_entry *
vcs_zcode_task_index_context_for_task(
    const struct vcs_zcode_task_index *index, const char *task_root_hex,
    bool *ambiguous)
{
    if (ambiguous) *ambiguous = false;
    if (!index || !task_root_hex) return NULL;
    const struct vcs_zcode_task_context_entry *found = NULL;
    for (size_t i = 0; i < index->context_count; i++) {
        const struct vcs_zcode_task_context_entry *at = &index->contexts[i];
        if (strcmp(at->task_root_hex, task_root_hex) != 0) continue;
        if (found) {
            if (ambiguous) *ambiguous = true;
            return NULL;
        }
        found = at;
    }
    return found;
}

const struct vcs_zcode_task_index_entry *vcs_zcode_task_index_find(
    const struct vcs_zcode_task_index *index, const uint8_t task_root[32])
{
    if (!index || !task_root)
        return NULL;
    char root_hex[65];
    zcl_hex_encode(task_root, 32, root_hex);
    for (size_t i = 0; i < index->task_count; i++)
        if (strcmp(index->tasks[i].task_root_hex, root_hex) == 0)
            return &index->tasks[i];
    return NULL;
}

const char *vcs_zcode_task_conflict_kind_string(
    enum vcs_zcode_task_conflict_kind kind)
{
    switch (kind) {
    case VCS_ZCODE_TASK_CONFLICT_CLEAR: return "CLEAR";
    case VCS_ZCODE_TASK_CONFLICT_DUPLICATE_ACTIVE_WORK:
        return "DUPLICATE_ACTIVE_WORK";
    case VCS_ZCODE_TASK_CONFLICT_WRITE_SCOPE_OVERLAP:
        return "WRITE_SCOPE_OVERLAP";
    case VCS_ZCODE_TASK_CONFLICT_INCOMPLETE: return "INCOMPLETE";
    }
    return "INCOMPLETE";
}

static bool index_scope_load(const char *repo_root, const char *root_hex,
                             struct vcs_zcode_write_scope_v1 *out)
{
    uint8_t root[32], checked[32], *wire = NULL;
    size_t wire_len = 0;
    bool ok = repo_root && root_hex && out &&
        zcl_hex_decode_lower(root_hex, root, sizeof(root)) &&
        vcs_object_load_raw_bounded(repo_root, root,
                                    VCS_ZCODE_WRITE_SCOPE_WIRE_MAX,
                                    &wire, &wire_len) == 0 &&
        vcs_zcode_write_scope_parse(wire, wire_len, out) ==
            VCS_ZCODE_WRITE_SCOPE_OK &&
        vcs_zcode_write_scope_root(out, checked) ==
            VCS_ZCODE_WRITE_SCOPE_OK &&
        memcmp(root, checked, sizeof(root)) == 0;
    free(wire);
    return ok;
}

static bool index_task_open(const struct vcs_zcode_task_index_entry *entry)
{
    return entry && !entry->expired &&
        strcmp(entry->state, VCS_ZCODE_TASK_STATE_PROVEN) != 0;
}

static void index_conflict_set(
    const struct vcs_zcode_task_index *index,
    const struct vcs_zcode_task_index_entry *entry,
    enum vcs_zcode_task_conflict_kind kind,
    struct vcs_zcode_task_conflict *out)
{
    out->kind = kind;
    if (!entry) return;
    (void)snprintf(out->task_root_hex, sizeof(out->task_root_hex), "%s",
                   entry->task_root_hex);
    (void)snprintf(out->source_root_hex, sizeof(out->source_root_hex), "%s",
                   entry->source_root_hex);
    (void)snprintf(out->goal_root_hex, sizeof(out->goal_root_hex), "%s",
                   entry->goal_root_hex);
    (void)snprintf(out->write_scope_root_hex,
                   sizeof(out->write_scope_root_hex), "%s",
                   entry->write_scope_root_hex);
    bool ambiguous = false;
    const struct vcs_zcode_task_context_entry *context =
        vcs_zcode_task_index_context_for_task(index, entry->task_root_hex,
                                              &ambiguous);
    if (context && !ambiguous)
        (void)snprintf(out->context_root_hex, sizeof(out->context_root_hex),
                       "%s", context->context_root_hex);
    (void)snprintf(out->action_root_hex, sizeof(out->action_root_hex), "%s",
                   entry->latest_action_root_hex);
    (void)snprintf(out->work_receipt_root_hex,
                   sizeof(out->work_receipt_root_hex), "%s",
                   entry->latest_work_receipt_hex);
}

enum vcs_zcode_task_conflict_kind vcs_zcode_task_index_conflict(
    const struct vcs_zcode_task_index *index, const char *repo_root,
    const struct vcs_zcode_task_v1 *proposed,
    struct vcs_zcode_task_conflict *out)
{
    if (out) memset(out, 0, sizeof(*out));
    if (!index || !repo_root || !proposed || !out || !index->complete) {
        if (out) out->kind = VCS_ZCODE_TASK_CONFLICT_INCOMPLETE;
        return VCS_ZCODE_TASK_CONFLICT_INCOMPLETE;
    }
    uint8_t proposed_root[32];
    char proposed_root_hex[65], source_hex[65], goal_hex[65], scope_hex[65];
    if (vcs_zcode_task_validate_at(proposed, index->now_unix) !=
            VCS_ZCODE_DEV_OK ||
        vcs_zcode_task_root(proposed, proposed_root) != VCS_ZCODE_DEV_OK) {
        out->kind = VCS_ZCODE_TASK_CONFLICT_INCOMPLETE;
        return out->kind;
    }
    zcl_hex_encode(proposed_root, 32, proposed_root_hex);
    zcl_hex_encode(proposed->source_root, 32, source_hex);
    zcl_hex_encode(proposed->goal_root, 32, goal_hex);
    zcl_hex_encode(proposed->write_scope_root, 32, scope_hex);
    for (size_t i = 0; i < index->task_count; i++) {
        const struct vcs_zcode_task_index_entry *entry = &index->tasks[i];
        if (!index_task_open(entry) ||
            strcmp(entry->task_root_hex, proposed_root_hex) == 0 ||
            strcmp(entry->source_root_hex, source_hex) != 0)
            continue;
        if (strcmp(entry->goal_root_hex, goal_hex) == 0) {
            index_conflict_set(index, entry,
                               VCS_ZCODE_TASK_CONFLICT_DUPLICATE_ACTIVE_WORK,
                               out);
            return out->kind;
        }
    }
    struct vcs_zcode_write_scope_v1 proposed_scope;
    if (!index_scope_load(repo_root, scope_hex, &proposed_scope)) {
        out->kind = VCS_ZCODE_TASK_CONFLICT_INCOMPLETE;
        return out->kind;
    }
    for (size_t i = 0; i < index->task_count; i++) {
        const struct vcs_zcode_task_index_entry *entry = &index->tasks[i];
        if (!index_task_open(entry) ||
            strcmp(entry->task_root_hex, proposed_root_hex) == 0 ||
            strcmp(entry->source_root_hex, source_hex) != 0)
            continue;
        struct vcs_zcode_write_scope_v1 existing_scope;
        if (!index_scope_load(repo_root, entry->write_scope_root_hex,
                              &existing_scope)) {
            out->kind = VCS_ZCODE_TASK_CONFLICT_INCOMPLETE;
            return out->kind;
        }
        if (vcs_zcode_write_scope_overlaps(&proposed_scope,
                                           &existing_scope)) {
            index_conflict_set(index, entry,
                VCS_ZCODE_TASK_CONFLICT_WRITE_SCOPE_OVERLAP, out);
            return out->kind;
        }
    }
    out->kind = VCS_ZCODE_TASK_CONFLICT_CLEAR;
    return out->kind;
}

static bool index_task_has_author(const struct vcs_zcode_task_index *index,
                                  const char *task_root_hex,
                                  const char *author)
{
    for (size_t c = 0; c < index->candidate_count; c++) {
        const struct vcs_zcode_task_candidate_entry *e =
            &index->candidates[c];
        if (strcmp(e->task_root_hex, task_root_hex) == 0 &&
            strncmp(e->author_pubkey_hex, author, strlen(author)) == 0)
            return true;
    }
    return false;
}

static bool index_entry_matches(
    const struct vcs_zcode_task_index *index,
    const struct vcs_zcode_task_index_entry *e,
    const struct vcs_zcode_task_search *s)
{
    if (s->task_root && s->task_root[0] &&
        strncmp(e->task_root_hex, s->task_root, strlen(s->task_root)) != 0)
        return false;
    if (s->source_root && s->source_root[0] &&
        strncmp(e->source_root_hex, s->source_root, strlen(s->source_root)) != 0)
        return false;
    if (s->state && s->state[0] && strcmp(e->state, s->state) != 0)
        return false;
    if (s->author && s->author[0] &&
        !index_task_has_author(index, e->task_root_hex, s->author))
        return false;
    return true;
}

size_t vcs_zcode_task_index_search(
    const struct vcs_zcode_task_index *index,
    const struct vcs_zcode_task_search *search,
    const struct vcs_zcode_task_index_entry **out, size_t out_cap)
{
    if (!index || !search)
        return 0;
    size_t total = 0;
    for (size_t i = 0; i < index->task_count; i++) {
        if (!index_entry_matches(index, &index->tasks[i], search))
            continue;
        if (out && total < out_cap)
            out[total] = &index->tasks[i];
        total++;
    }
    return total;
}
