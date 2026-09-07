/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * vcs_devloop_publication — the publication advance state machine: one
 * function per phase transition (waiting-acceptance through
 * source-reproduction-ack), each idempotent and re-derivable from the
 * receipt chain alone. See vcs/vcs_devloop.h for the public contract;
 * vcs_devloop.c owns the job queue, the receipt codec, and chain
 * reconstruction that these steps call through vcs_devloop_priv.h. */

#define _GNU_SOURCE

#include "vcs/vcs_devloop.h"
#include "vcs_devloop_priv.h"
#include "base/bytes.h"
#include "vcs/vcs.h"
#include "vcs/vcs_commit.h"
#include "vcs/vcs_index.h"
#include "vcs/vcs_manifest.h"
#include "vcs/vcs_object.h"
#include "vcs/zcode_lane.h"
#include "vcs/zcode_accepted_work.h"
#include "vcs/zcode_accepted_work_bundle.h"
#include "vcs/package_mapping.h"
#include "vcs/package_release.h"
#include "vcs/zcode_commons.h"
#include "vcs/zcode_dht_record.h"
#include "vcs/build_action.h"
#include "base/hex.h"
#include "base/safe_alloc.h"
#include "base/serialize_le.h"
#include "platform/directory_compat.h"
#include "platform/private_file.h"
#include "platform/process_lock.h"
#include "platform/time_compat.h"
#include "storage/event_log.h"
#include "util/log_macros.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

/* Resolve the two well-known queue paths and take the publication queue
 * lock in one step. */
static bool publication_queue_open(const char *repo_root,
                                   char lock_path[PATH_MAX],
                                   char log_path[PATH_MAX],
                                   struct platform_process_lock *queue_lock)
{
    return publication_queue_path(repo_root, "publication.lock", lock_path,
                                  PATH_MAX) &&
           publication_queue_path(repo_root, "publication.receipts.log",
                                  log_path, PATH_MAX) &&
           publication_queue_lock_acquire(queue_lock, lock_path);
}

/* The publication phase enum is one linear progression
 * (WAITING_ACCEPTANCE=1..SOURCE_REPRODUCED=9): "at or past phase X" is a
 * numeric range test. */
static bool
publication_phase_between(enum vcs_devloop_publication_phase phase,
                          enum vcs_devloop_publication_phase lo,
                          enum vcs_devloop_publication_phase hi)
{
    return phase >= lo && phase <= hi;
}

bool
publication_receipt_phase_known(enum vcs_devloop_publication_phase phase)
{
    return publication_phase_between(
        phase, VCS_DEVLOOP_PUBLICATION_PHASE_WAITING_ACCEPTANCE,
        VCS_DEVLOOP_PUBLICATION_PHASE_SOURCE_REPRODUCED);
}

/* Serialize, store, and append-to-log a freshly built publication receipt.
 * Every advance_* step ends this same way: seal the receipt as an object,
 * then make it discoverable in the append-only receipts log. */
static bool publication_receipt_publish(
    const char *repo_root, const char *log_path,
    const struct vcs_devloop_publication_receipt *receipt,
    uint8_t receipt_root_out[32])
{
    uint8_t wire[VCS_DEV_PUBLICATION_RECEIPT_WIRE_BYTES];
    bool ok = publication_receipt_serialize(receipt, wire) &&
              vcs_object_put(repo_root, wire, sizeof(wire),
                             VCS_TAG_PUBLICATION_RECEIPT, receipt_root_out);
    event_log_t *log = ok ? event_log_open(log_path) : NULL;
    if (ok)
        ok = log && event_log_append(log, EV_VCS_PUBLICATION_RECEIPT,
                                     receipt_root_out, 32) != UINT64_MAX;
    if (log)
        event_log_close(log);
    return ok;
}

bool vcs_devloop_publication_advance_waiting_acceptance(
    const char *repo_root, const uint8_t job_root[32],
    uint8_t receipt_root_out[32], bool *reused_out)
{
    if (reused_out)
        *reused_out = false;
    if (!repo_root || !repo_root[0] || !job_root || !receipt_root_out)
        return false;
    struct vcs_devloop_publication_job job;
    if (!vcs_devloop_publication_job_load(repo_root, job_root, &job) ||
        !vcs_devloop_publication_job_is_queued(repo_root, job_root))
        return false;
    char lock_path[PATH_MAX], log_path[PATH_MAX];
    if (!publication_queue_path(repo_root, "publication.lock", lock_path,
                                sizeof(lock_path)) ||
        !publication_queue_path(repo_root, "publication.receipts.log",
                                log_path, sizeof(log_path)))
        return false;
    struct platform_process_lock queue_lock;
    if (!publication_queue_lock_acquire(&queue_lock, lock_path)) {
        return false;
    }
    struct vcs_devloop_publication_receipt current;
    uint8_t current_root[32];
    bool have_current = vcs_devloop_publication_progress_load(
        repo_root, job_root, &current, current_root);
    if (have_current && publication_receipt_phase_known(current.phase)) {
        memcpy(receipt_root_out, current_root, 32);
        if (reused_out)
            *reused_out = true;
        platform_process_lock_release(&queue_lock);
        return true;
    }
    struct vcs_devloop_publication_receipt receipt = {
        .version = VCS_DEVLOOP_PUBLICATION_RECEIPT_VERSION,
        .phase = VCS_DEVLOOP_PUBLICATION_PHASE_WAITING_ACCEPTANCE,
    };
    memcpy(receipt.job_root, job_root, 32);
    if (have_current)
        memcpy(receipt.predecessor_receipt_root, current_root, 32);
    bool ok = publication_receipt_publish(repo_root, log_path, &receipt,
                                          receipt_root_out);
    platform_process_lock_release(&queue_lock);
    return ok;
}

/* Commit the reused receipt root (when the candidate matched) and release
 * this advance_* call's queue lock -- the shared tail of a reuse branch that
 * holds no mapping set. */
static bool publication_reuse_exit(bool same, uint8_t receipt_root_out[32],
                                   const uint8_t current_root[32],
                                   bool *reused_out,
                                   struct platform_process_lock *queue_lock)
{
    if (same) {
        memcpy(receipt_root_out, current_root, 32);
        if (reused_out)
            *reused_out = true;
    }
    platform_process_lock_release(queue_lock);
    return same;
}

static bool
publication_proven_work_matches_mapping(const char *repo_root,
                                        const uint8_t mapping_set_root[32],
                                        const uint8_t accepted_work_root[32])
{
    struct vcs_package_mapping_set set;
    bool same =
        vcs_package_mapping_set_load(repo_root, mapping_set_root, &set) &&
        memcmp(set.lane_receipt_root, accepted_work_root, 32) == 0;
    vcs_package_mapping_set_free(&set);
    return same;
}

static bool publication_proven_work_matches_release(
    const char *repo_root,
    const struct vcs_devloop_publication_receipt *current,
    const uint8_t accepted_work_root[32])
{
    struct publication_artifact_chain chain;
    return publication_artifact_chain_load(repo_root, current, &chain) &&
           chain.release_published && chain.mapping_ready &&
           publication_proven_work_matches_mapping(
               repo_root, chain.mapping.artifact_root, accepted_work_root);
}

static bool publication_advance_proven_work_args_valid(
    const char *repo_root, const uint8_t job_root[32],
    const uint8_t accepted_work_root[32], const uint8_t *receipt_root_out,
    struct vcs_devloop_publication_job *job, int64_t now_unix)
{
    return repo_root && repo_root[0] && job_root && accepted_work_root &&
           receipt_root_out &&
           vcs_devloop_publication_job_load(repo_root, job_root, job) &&
           vcs_devloop_publication_job_is_queued(repo_root, job_root) &&
           publication_accepted_work_valid(repo_root, job, accepted_work_root,
                                           now_unix);
}

bool vcs_devloop_publication_advance_proven_work(
    const char *repo_root, const uint8_t job_root[32],
    const uint8_t accepted_work_root[32], int64_t now_unix,
    uint8_t receipt_root_out[32], bool *reused_out)
{
    if (reused_out)
        *reused_out = false;
    struct vcs_devloop_publication_job job;
    if (!publication_advance_proven_work_args_valid(
            repo_root, job_root, accepted_work_root, receipt_root_out, &job,
            now_unix))
        return false;
    char lock_path[PATH_MAX], log_path[PATH_MAX];
    struct platform_process_lock queue_lock;
    if (!publication_queue_open(repo_root, lock_path, log_path, &queue_lock))
        return false;
    struct vcs_devloop_publication_receipt current;
    uint8_t current_root[32];
    bool have_current = vcs_devloop_publication_progress_load(
        repo_root, job_root, &current, current_root);
    if (have_current &&
        publication_phase_between(
            current.phase, VCS_DEVLOOP_PUBLICATION_PHASE_RELEASE_PUBLISHED,
            VCS_DEVLOOP_PUBLICATION_PHASE_SOURCE_REPRODUCED)) {
        bool same = publication_proven_work_matches_release(
            repo_root, &current, accepted_work_root);
        return publication_reuse_exit(same, receipt_root_out, current_root,
                                      reused_out, &queue_lock);
    }
    if (have_current &&
        current.phase ==
            VCS_DEVLOOP_PUBLICATION_PHASE_PACKAGE_MAPPING_READY) {
        bool same = publication_proven_work_matches_mapping(
            repo_root, current.artifact_root, accepted_work_root);
        return publication_reuse_exit(same, receipt_root_out, current_root,
                                      reused_out, &queue_lock);
    }
    if (have_current &&
        current.phase == VCS_DEVLOOP_PUBLICATION_PHASE_ACCEPTED_LANE_BOUND) {
        bool same =
            memcmp(current.artifact_root, accepted_work_root, 32) == 0;
        return publication_reuse_exit(same, receipt_root_out, current_root,
                                      reused_out, &queue_lock);
    }
    if (!have_current ||
        current.phase != VCS_DEVLOOP_PUBLICATION_PHASE_WAITING_ACCEPTANCE) {
        platform_process_lock_release(&queue_lock);
        return false;
    }
    struct vcs_devloop_publication_receipt receipt = {
        .version = VCS_DEVLOOP_PUBLICATION_RECEIPT_VERSION,
        .phase = VCS_DEVLOOP_PUBLICATION_PHASE_ACCEPTED_LANE_BOUND,
    };
    memcpy(receipt.job_root, job_root, 32);
    memcpy(receipt.predecessor_receipt_root, current_root, 32);
    memcpy(receipt.artifact_root, accepted_work_root, 32);
    bool ok = publication_receipt_publish(repo_root, log_path, &receipt,
                                          receipt_root_out);
    platform_process_lock_release(&queue_lock);
    return ok;
}

/* Commit the reused receipt root (when the candidate matched) and release
 * this advance_* call's queue lock and mapping set -- the shared tail of
 * every reuse branch in advance_package_mapping. */
static bool publication_mapping_reuse_exit(
    bool same, uint8_t receipt_root_out[32], const uint8_t current_root[32],
    bool *reused_out, struct platform_process_lock *queue_lock,
    struct vcs_package_mapping_set *set)
{
    if (same) {
        memcpy(receipt_root_out, current_root, 32);
        if (reused_out)
            *reused_out = true;
    }
    platform_process_lock_release(queue_lock);
    vcs_package_mapping_set_free(set);
    return same;
}

static bool publication_advance_mapping_args_valid(
    const char *repo_root, const uint8_t job_root[32],
    const uint8_t mapping_set_root[32], const uint8_t *receipt_root_out,
    struct vcs_devloop_publication_job *job,
    struct vcs_package_mapping_set *set)
{
    return repo_root && repo_root[0] && job_root && mapping_set_root &&
           receipt_root_out &&
           vcs_devloop_publication_job_load(repo_root, job_root, job) &&
           vcs_devloop_publication_job_is_queued(repo_root, job_root) &&
           publication_mapping_valid(repo_root, job, mapping_set_root, set);
}

static bool publication_mapping_matches_current_release(
    const char *repo_root,
    const struct vcs_devloop_publication_receipt *current,
    const uint8_t mapping_set_root[32])
{
    struct publication_artifact_chain chain;
    return publication_artifact_chain_load(repo_root, current, &chain) &&
           chain.release_published && chain.mapping_ready &&
           memcmp(chain.mapping.artifact_root, mapping_set_root, 32) == 0;
}

static bool publication_mapping_accepted_lane_bound(
    const struct vcs_devloop_publication_receipt *current, bool have_current,
    const struct vcs_package_mapping_set *set)
{
    return have_current &&
           current->phase ==
               VCS_DEVLOOP_PUBLICATION_PHASE_ACCEPTED_LANE_BOUND &&
           memcmp(current->artifact_root, set->lane_receipt_root, 32) == 0;
}

bool vcs_devloop_publication_advance_package_mapping(
    const char *repo_root, const uint8_t job_root[32],
    const uint8_t mapping_set_root[32], uint64_t bytes_scanned,
    uint32_t new_chunks, uint32_t reused_chunks, uint8_t receipt_root_out[32],
    bool *reused_out)
{
    if (reused_out)
        *reused_out = false;
    struct vcs_devloop_publication_job job;
    struct vcs_package_mapping_set set;
    if (!publication_advance_mapping_args_valid(repo_root, job_root,
                                                mapping_set_root,
                                                receipt_root_out, &job, &set))
        return false;
    char lock_path[PATH_MAX], log_path[PATH_MAX];
    struct platform_process_lock queue_lock;
    if (!publication_queue_open(repo_root, lock_path, log_path,
                                &queue_lock)) {
        vcs_package_mapping_set_free(&set);
        return false;
    }
    struct vcs_devloop_publication_receipt current;
    uint8_t current_root[32];
    bool have_current = vcs_devloop_publication_progress_load(
        repo_root, job_root, &current, current_root);
    if (have_current &&
        publication_phase_between(
            current.phase, VCS_DEVLOOP_PUBLICATION_PHASE_RELEASE_PUBLISHED,
            VCS_DEVLOOP_PUBLICATION_PHASE_SOURCE_REPRODUCED)) {
        bool same = publication_mapping_matches_current_release(
            repo_root, &current, mapping_set_root);
        return publication_mapping_reuse_exit(same, receipt_root_out,
                                              current_root, reused_out,
                                              &queue_lock, &set);
    }
    if (have_current &&
        current.phase ==
            VCS_DEVLOOP_PUBLICATION_PHASE_PACKAGE_MAPPING_READY) {
        bool same = memcmp(current.artifact_root, mapping_set_root, 32) == 0;
        return publication_mapping_reuse_exit(same, receipt_root_out,
                                              current_root, reused_out,
                                              &queue_lock, &set);
    }
    if (!publication_mapping_accepted_lane_bound(&current, have_current,
                                                 &set)) {
        platform_process_lock_release(&queue_lock);
        vcs_package_mapping_set_free(&set);
        return false;
    }
    struct vcs_devloop_publication_receipt receipt = {
        .version = VCS_DEVLOOP_PUBLICATION_RECEIPT_VERSION,
        .phase = VCS_DEVLOOP_PUBLICATION_PHASE_PACKAGE_MAPPING_READY,
        .bytes_scanned = bytes_scanned,
        .new_chunks = new_chunks,
        .reused_chunks = reused_chunks,
    };
    memcpy(receipt.job_root, job_root, 32);
    memcpy(receipt.predecessor_receipt_root, current_root, 32);
    memcpy(receipt.artifact_root, mapping_set_root, 32);
    bool ok = publication_receipt_publish(repo_root, log_path, &receipt,
                                          receipt_root_out);
    platform_process_lock_release(&queue_lock);
    vcs_package_mapping_set_free(&set);
    return ok;
}

static bool publication_release_matches_current(
    const char *repo_root,
    const struct vcs_devloop_publication_receipt *current,
    const uint8_t release_root[32], const uint8_t mapping_set_root[32])
{
    struct publication_artifact_chain chain;
    return publication_artifact_chain_load(repo_root, current, &chain) &&
           chain.release_published && chain.mapping_ready &&
           memcmp(chain.release.artifact_root, release_root, 32) == 0 &&
           memcmp(chain.mapping.artifact_root, mapping_set_root, 32) == 0;
}

static bool publication_advance_release_args_valid(
    const char *repo_root, const uint8_t job_root[32],
    const uint8_t mapping_set_root[32], const uint8_t release_root[32],
    const uint8_t receipt_root_out[32],
    struct vcs_devloop_publication_job *job,
    struct vcs_package_mapping_set *set)
{
    return repo_root && repo_root[0] && job_root && mapping_set_root &&
           release_root && receipt_root_out &&
           zcl_bytes_any_set(release_root, 32) &&
           vcs_devloop_publication_job_load(repo_root, job_root, job) &&
           vcs_devloop_publication_job_is_queued(repo_root, job_root) &&
           publication_mapping_valid(repo_root, job, mapping_set_root, set);
}

bool vcs_devloop_publication_advance_release(
    const char *repo_root, const uint8_t job_root[32],
    const uint8_t mapping_set_root[32], const uint8_t release_root[32],
    uint8_t receipt_root_out[32], bool *reused_out)
{
    if (reused_out)
        *reused_out = false;
    struct vcs_devloop_publication_job job;
    struct vcs_package_mapping_set set;
    if (!publication_advance_release_args_valid(
            repo_root, job_root, mapping_set_root, release_root,
            receipt_root_out, &job, &set))
        return false;
    char lock_path[PATH_MAX], log_path[PATH_MAX];
    struct platform_process_lock queue_lock;
    if (!publication_queue_open(repo_root, lock_path, log_path,
                                &queue_lock)) {
        vcs_package_mapping_set_free(&set);
        return false;
    }
    struct vcs_devloop_publication_receipt current;
    uint8_t current_root[32];
    bool have_current = vcs_devloop_publication_progress_load(
        repo_root, job_root, &current, current_root);
    if (have_current &&
        publication_phase_between(
            current.phase, VCS_DEVLOOP_PUBLICATION_PHASE_RELEASE_PUBLISHED,
            VCS_DEVLOOP_PUBLICATION_PHASE_SOURCE_REPRODUCED)) {
        bool same = publication_release_matches_current(
            repo_root, &current, release_root, mapping_set_root);
        if (same) {
            memcpy(receipt_root_out, current_root, 32);
            if (reused_out)
                *reused_out = true;
        }
        platform_process_lock_release(&queue_lock);
        vcs_package_mapping_set_free(&set);
        return same;
    }
    bool mapped = have_current &&
                  current.phase ==
                      VCS_DEVLOOP_PUBLICATION_PHASE_PACKAGE_MAPPING_READY &&
                  memcmp(current.artifact_root, mapping_set_root, 32) == 0;
    if (!mapped) {
        platform_process_lock_release(&queue_lock);
        vcs_package_mapping_set_free(&set);
        return false;
    }
    struct vcs_devloop_publication_receipt receipt = {
        .version = VCS_DEVLOOP_PUBLICATION_RECEIPT_VERSION,
        .phase = VCS_DEVLOOP_PUBLICATION_PHASE_RELEASE_PUBLISHED,
        .bytes_scanned = current.bytes_scanned,
        .new_chunks = current.new_chunks,
        .reused_chunks = current.reused_chunks,
    };
    memcpy(receipt.job_root, job_root, 32);
    memcpy(receipt.predecessor_receipt_root, current_root, 32);
    memcpy(receipt.artifact_root, release_root, 32);
    bool ok = publication_receipt_publish(repo_root, log_path, &receipt,
                                          receipt_root_out);
    platform_process_lock_release(&queue_lock);
    vcs_package_mapping_set_free(&set);
    return ok;
}

static bool publication_advance_passport_args_valid(
    const char *repo_root, const uint8_t job_root[32],
    const uint8_t mapping_set_root[32], const uint8_t release_root[32],
    const uint8_t passport_root[32], const uint8_t *receipt_root_out,
    struct vcs_devloop_publication_job *job,
    struct vcs_package_mapping_set *set)
{
    return repo_root && repo_root[0] && job_root && mapping_set_root &&
           release_root && passport_root && receipt_root_out &&
           zcl_bytes_any_set(release_root, 32) &&
           zcl_bytes_any_set(passport_root, 32) &&
           vcs_devloop_publication_job_load(repo_root, job_root, job) &&
           vcs_devloop_publication_job_is_queued(repo_root, job_root) &&
           publication_mapping_valid(repo_root, job, mapping_set_root, set);
}

static bool publication_passport_matches_current(
    const char *repo_root,
    const struct vcs_devloop_publication_receipt *current,
    const uint8_t passport_root[32], const uint8_t release_root[32],
    const uint8_t mapping_set_root[32])
{
    struct publication_artifact_chain chain;
    return publication_artifact_chain_load(repo_root, current, &chain) &&
           chain.passport_published && chain.release_published &&
           chain.mapping_ready &&
           memcmp(chain.passport.artifact_root, passport_root, 32) == 0 &&
           memcmp(chain.release.artifact_root, release_root, 32) == 0 &&
           memcmp(chain.mapping.artifact_root, mapping_set_root, 32) == 0;
}

/* The predecessor receipt for a passport advance must be the release
 * receipt for this exact release, itself chained to this exact mapping. */
static bool publication_passport_release_ready(
    const char *repo_root,
    const struct vcs_devloop_publication_receipt *current, bool have_current,
    const uint8_t release_root[32], const uint8_t mapping_set_root[32])
{
    struct vcs_devloop_publication_receipt mapping_receipt;
    return have_current &&
           current->phase ==
               VCS_DEVLOOP_PUBLICATION_PHASE_RELEASE_PUBLISHED &&
           memcmp(current->artifact_root, release_root, 32) == 0 &&
           vcs_devloop_publication_receipt_load(
               repo_root, current->predecessor_receipt_root,
               &mapping_receipt) &&
           mapping_receipt.phase ==
               VCS_DEVLOOP_PUBLICATION_PHASE_PACKAGE_MAPPING_READY &&
           memcmp(mapping_receipt.artifact_root, mapping_set_root, 32) == 0;
}

bool vcs_devloop_publication_advance_passport(
    const char *repo_root, const uint8_t job_root[32],
    const uint8_t mapping_set_root[32], const uint8_t release_root[32],
    const uint8_t passport_root[32], uint8_t receipt_root_out[32],
    bool *reused_out)
{
    if (reused_out)
        *reused_out = false;
    struct vcs_devloop_publication_job job;
    struct vcs_package_mapping_set set;
    if (!publication_advance_passport_args_valid(
            repo_root, job_root, mapping_set_root, release_root,
            passport_root, receipt_root_out, &job, &set))
        return false;
    char lock_path[PATH_MAX], log_path[PATH_MAX];
    struct platform_process_lock queue_lock;
    if (!publication_queue_open(repo_root, lock_path, log_path,
                                &queue_lock)) {
        vcs_package_mapping_set_free(&set);
        return false;
    }
    struct vcs_devloop_publication_receipt current;
    uint8_t current_root[32];
    bool have_current = vcs_devloop_publication_progress_load(
        repo_root, job_root, &current, current_root);
    if (have_current &&
        publication_phase_between(
            current.phase, VCS_DEVLOOP_PUBLICATION_PHASE_PASSPORT_PUBLISHED,
            VCS_DEVLOOP_PUBLICATION_PHASE_SOURCE_REPRODUCED)) {
        bool same = publication_passport_matches_current(
            repo_root, &current, passport_root, release_root,
            mapping_set_root);
        return publication_mapping_reuse_exit(same, receipt_root_out,
                                              current_root, reused_out,
                                              &queue_lock, &set);
    }
    if (!publication_passport_release_ready(repo_root, &current, have_current,
                                            release_root, mapping_set_root)) {
        platform_process_lock_release(&queue_lock);
        vcs_package_mapping_set_free(&set);
        return false;
    }
    struct vcs_devloop_publication_receipt receipt = {
        .version = VCS_DEVLOOP_PUBLICATION_RECEIPT_VERSION,
        .phase = VCS_DEVLOOP_PUBLICATION_PHASE_PASSPORT_PUBLISHED,
        .bytes_scanned = current.bytes_scanned,
        .new_chunks = current.new_chunks,
        .reused_chunks = current.reused_chunks,
    };
    memcpy(receipt.job_root, job_root, 32);
    memcpy(receipt.predecessor_receipt_root, current_root, 32);
    memcpy(receipt.artifact_root, passport_root, 32);
    bool ok = publication_receipt_publish(repo_root, log_path, &receipt,
                                          receipt_root_out);
    platform_process_lock_release(&queue_lock);
    vcs_package_mapping_set_free(&set);
    return ok;
}

bool vcs_devloop_publication_advance_workspace(
    const char *repo_root, const uint8_t job_root[32],
    const uint8_t mapping_set_root[32], const uint8_t release_root[32],
    const uint8_t passport_root[32], const uint8_t workspace_root[32],
    uint8_t receipt_root_out[32], bool *reused_out)
{
    if (reused_out)
        *reused_out = false;
    struct vcs_devloop_publication_job job;
    struct vcs_package_mapping_set set;
    if (!repo_root || !repo_root[0] || !job_root || !mapping_set_root ||
        !release_root || !passport_root || !workspace_root ||
        !receipt_root_out || !zcl_bytes_any_set(release_root, 32) ||
        !zcl_bytes_any_set(passport_root, 32) ||
        !zcl_bytes_any_set(workspace_root, 32) ||
        !vcs_devloop_publication_job_load(repo_root, job_root, &job) ||
        !vcs_devloop_publication_job_is_queued(repo_root, job_root) ||
        !publication_mapping_valid(repo_root, &job, mapping_set_root, &set))
        return false;
    char lock_path[PATH_MAX], log_path[PATH_MAX];
    struct platform_process_lock queue_lock;
    if (!publication_queue_open(repo_root, lock_path, log_path,
                                &queue_lock)) {
        vcs_package_mapping_set_free(&set);
        return false;
    }
    struct vcs_devloop_publication_receipt current;
    uint8_t current_root[32];
    bool have_current = vcs_devloop_publication_progress_load(
        repo_root, job_root, &current, current_root);
    struct publication_artifact_chain chain;
    bool chained = have_current && publication_artifact_chain_load(
                                       repo_root, &current, &chain);
    if (chained &&
        publication_phase_between(
            current.phase, VCS_DEVLOOP_PUBLICATION_PHASE_WORKSPACE_PUBLISHED,
            VCS_DEVLOOP_PUBLICATION_PHASE_SOURCE_REPRODUCED)) {
        bool same =
            chain.workspace_published && chain.passport_published &&
            chain.release_published && chain.mapping_ready &&
            memcmp(chain.workspace.artifact_root, workspace_root, 32) == 0 &&
            memcmp(chain.passport.artifact_root, passport_root, 32) == 0 &&
            memcmp(chain.release.artifact_root, release_root, 32) == 0 &&
            memcmp(chain.mapping.artifact_root, mapping_set_root, 32) == 0;
        if (same) {
            memcpy(receipt_root_out, current_root, 32);
            if (reused_out)
                *reused_out = true;
        }
        platform_process_lock_release(&queue_lock);
        vcs_package_mapping_set_free(&set);
        return same;
    }
    bool passported =
        chained &&
        current.phase == VCS_DEVLOOP_PUBLICATION_PHASE_PASSPORT_PUBLISHED &&
        chain.passport_published && chain.release_published &&
        chain.mapping_ready &&
        memcmp(chain.passport.artifact_root, passport_root, 32) == 0 &&
        memcmp(chain.release.artifact_root, release_root, 32) == 0 &&
        memcmp(chain.mapping.artifact_root, mapping_set_root, 32) == 0;
    if (!passported) {
        platform_process_lock_release(&queue_lock);
        vcs_package_mapping_set_free(&set);
        return false;
    }
    struct vcs_devloop_publication_receipt receipt = {
        .version = VCS_DEVLOOP_PUBLICATION_RECEIPT_VERSION,
        .phase = VCS_DEVLOOP_PUBLICATION_PHASE_WORKSPACE_PUBLISHED,
        .bytes_scanned = current.bytes_scanned,
        .new_chunks = current.new_chunks,
        .reused_chunks = current.reused_chunks,
    };
    memcpy(receipt.job_root, job_root, 32);
    memcpy(receipt.predecessor_receipt_root, current_root, 32);
    memcpy(receipt.artifact_root, workspace_root, 32);
    bool ok = publication_receipt_publish(repo_root, log_path, &receipt,
                                          receipt_root_out);
    platform_process_lock_release(&queue_lock);
    vcs_package_mapping_set_free(&set);
    return ok;
}

#define VCS_DEV_WORKSPACE_MAX_WIRE_BYTES                                     \
    (VCS_ZCODE_WORKSPACE_MANIFEST_V1_WIRE_BASE_BYTES +                       \
     VCS_ZCODE_COMMONS_MAX_CLAIMS *                                          \
         (VCS_ZCODE_WORKSPACE_MANIFEST_V1_ENTRY_WIRE_BYTES +                 \
          VCS_ZCODE_WORKSPACE_MANIFEST_V1_EDGE_WIRE_BYTES +                  \
          VCS_ZCODE_WORKSPACE_MANIFEST_V1_ASSET_WIRE_BYTES))

static bool publication_workspace_manifest_decode_verified(
    const char *repo_root, const struct publication_artifact_chain *chain,
    struct vcs_zcode_workspace_manifest_v1_decoded *decoded)
{
    uint8_t *workspace_wire = NULL;
    size_t workspace_wire_len = 0;
    uint8_t checked_workspace_root[32];
    bool ok =
        chain && chain->workspace_published && chain->passport_published &&
        chain->release_published &&
        vcs_object_load_raw_bounded(repo_root, chain->workspace.artifact_root,
                                    VCS_DEV_WORKSPACE_MAX_WIRE_BYTES,
                                    &workspace_wire,
                                    &workspace_wire_len) == 0 &&
        vcs_zcode_workspace_manifest_v1_decode(decoded, workspace_wire,
                                               workspace_wire_len) ==
            VCS_ZCODE_COMMONS_OK &&
        vcs_zcode_workspace_manifest_v1_root(&decoded->manifest,
                                             checked_workspace_root) ==
            VCS_ZCODE_COMMONS_OK &&
        memcmp(checked_workspace_root, chain->workspace.artifact_root, 32) ==
            0;
    free(workspace_wire);
    return ok;
}

/* Exactly one workspace manifest entry must name both the accepted release
 * and its passport -- more or fewer is a corrupt or ambiguous workspace. */
static bool publication_workspace_manifest_single_match(
    const struct vcs_zcode_workspace_manifest_v1_decoded *decoded,
    const struct publication_artifact_chain *chain)
{
    size_t matching_entries = 0;
    for (size_t i = 0; i < decoded->manifest.entry_count; i++) {
        const struct vcs_zcode_workspace_entry_v1 *entry =
            &decoded->manifest.entries[i];
        if (memcmp(entry->module_release_root, chain->release.artifact_root,
                   32) == 0 &&
            memcmp(entry->module_passport_root, chain->passport.artifact_root,
                   32) == 0)
            matching_entries++;
    }
    return matching_entries == 1u;
}

static bool publication_release_load_verified(
    const char *repo_root, const struct publication_artifact_chain *chain,
    struct vcs_package_release *release)
{
    uint8_t *release_wire = NULL;
    size_t release_wire_len = 0;
    uint8_t checked_release_root[32];
    bool ok =
        vcs_object_load_raw_bounded(repo_root, chain->release.artifact_root,
                                    VCS_PACKAGE_RELEASE_MAX_WIRE_BYTES,
                                    &release_wire, &release_wire_len) == 0 &&
        vcs_package_release_parse(release_wire, release_wire_len, release) ==
            VCS_PACKAGE_RELEASE_OK &&
        vcs_package_release_verify(release) == VCS_PACKAGE_RELEASE_OK &&
        vcs_package_release_id(release, checked_release_root) ==
            VCS_PACKAGE_RELEASE_OK &&
        memcmp(checked_release_root, chain->release.artifact_root, 32) == 0;
    free(release_wire);
    return ok;
}

static bool publication_workspace_release_load(
    const char *repo_root, const struct publication_artifact_chain *chain,
    struct vcs_package_release *release_out)
{
    struct vcs_zcode_workspace_manifest_v1_decoded decoded = {0};
    bool ok = publication_workspace_manifest_decode_verified(repo_root, chain,
                                                             &decoded);
    ok = ok && publication_workspace_manifest_single_match(&decoded, chain);
    vcs_zcode_workspace_manifest_v1_decoded_free(&decoded);
    struct vcs_package_release release;
    ok = ok && publication_release_load_verified(repo_root, chain, &release);
    if (!ok)
        return false;
    *release_out = release;
    return true;
}

/* Re-load the just-stored provider record and confirm it round-trips: same
 * bytes, same parse, same derived id as the one the caller wrote. */
bool publication_provider_stored_write_verified(
    const char *repo_root, const uint8_t record_root[32],
    const uint8_t *record_wire, size_t record_wire_len,
    const struct vcs_zcode_dht_record_verify_context *verify)
{
    uint8_t *stored_wire = NULL;
    size_t stored_wire_len = 0;
    struct vcs_zcode_dht_record stored;
    uint8_t stored_root[32];
    bool ok =
        vcs_object_load_raw_bounded(repo_root, record_root,
                                    VCS_ZCODE_DHT_RECORD_WIRE_BYTES,
                                    &stored_wire, &stored_wire_len) == 0 &&
        stored_wire_len == record_wire_len &&
        memcmp(stored_wire, record_wire, record_wire_len) == 0 &&
        vcs_zcode_dht_record_parse(stored_wire, stored_wire_len, verify,
                                   &stored) == VCS_ZCODE_DHT_RECORD_OK &&
        vcs_zcode_dht_record_id(&stored, stored_root) ==
            VCS_ZCODE_DHT_RECORD_OK &&
        memcmp(stored_root, record_root, 32) == 0;
    free(stored_wire);
    return ok;
}

static bool publication_advance_provider_args_valid(
    const char *repo_root, const uint8_t job_root[32],
    const uint8_t *record_wire,
    const struct vcs_zcode_dht_record_verify_context *verify,
    const uint8_t *receipt_root_out)
{
    return repo_root && repo_root[0] && job_root && record_wire && verify &&
           receipt_root_out &&
           vcs_devloop_publication_job_is_queued(repo_root, job_root);
}

static bool publication_provider_observed_load(
    const char *repo_root, const uint8_t job_root[32],
    struct vcs_devloop_publication_job *job,
    struct vcs_devloop_publication_receipt *observed,
    uint8_t observed_root[32], struct publication_artifact_chain *chain,
    struct vcs_package_release *release)
{
    return vcs_devloop_publication_job_load(repo_root, job_root, job) &&
           vcs_devloop_publication_progress_load(repo_root, job_root,
                                                 observed, observed_root) &&
           publication_phase_between(
               observed->phase,
               VCS_DEVLOOP_PUBLICATION_PHASE_WORKSPACE_PUBLISHED,
               VCS_DEVLOOP_PUBLICATION_PHASE_SOURCE_REPRODUCED) &&
           publication_artifact_chain_load(repo_root, observed, chain) &&
           publication_workspace_release_load(repo_root, chain, release);
}

static bool publication_provider_reused_after_storage(
    const struct publication_artifact_chain *chain,
    const uint8_t current_root[32], const uint8_t observed_root[32],
    const uint8_t record_root[32])
{
    return memcmp(current_root, observed_root, 32) == 0 &&
           chain->provider_announced &&
           memcmp(chain->provider.artifact_root, record_root, 32) == 0;
}

static bool publication_provider_reused_as_announced(
    const struct vcs_devloop_publication_receipt *current,
    const uint8_t current_root[32], const uint8_t observed_root[32],
    const uint8_t record_root[32])
{
    return memcmp(current_root, observed_root, 32) == 0 &&
           memcmp(current->artifact_root, record_root, 32) == 0;
}

static bool publication_provider_workspace_ready(
    const struct vcs_devloop_publication_receipt *current, bool have_current,
    const uint8_t current_root[32], const uint8_t observed_root[32])
{
    return have_current &&
           current->phase ==
               VCS_DEVLOOP_PUBLICATION_PHASE_WORKSPACE_PUBLISHED &&
           memcmp(current_root, observed_root, 32) == 0;
}

bool vcs_devloop_publication_advance_provider(
    const char *repo_root, const uint8_t job_root[32],
    const uint8_t *record_wire, size_t record_wire_len,
    const struct vcs_zcode_dht_record_verify_context *verify,
    uint8_t receipt_root_out[32], bool *reused_out)
{
    if (reused_out)
        *reused_out = false;
    if (!publication_advance_provider_args_valid(
            repo_root, job_root, record_wire, verify, receipt_root_out))
        return false;
    struct vcs_devloop_publication_job job;
    struct vcs_devloop_publication_receipt observed;
    uint8_t observed_root[32];
    struct publication_artifact_chain chain;
    struct vcs_package_release release;
    if (!publication_provider_observed_load(repo_root, job_root, &job,
                                            &observed, observed_root, &chain,
                                            &release))
        return false;
    uint8_t record_root[32];
    if (!publication_provider_wire_store(repo_root, &release, record_wire,
                                         record_wire_len, verify,
                                         record_root))
        return false;

    char lock_path[PATH_MAX], log_path[PATH_MAX];
    struct platform_process_lock queue_lock;
    if (!publication_queue_open(repo_root, lock_path, log_path, &queue_lock))
        return false;
    struct vcs_devloop_publication_receipt current;
    uint8_t current_root[32];
    bool have_current = vcs_devloop_publication_progress_load(
        repo_root, job_root, &current, current_root);
    if (have_current &&
        publication_phase_between(
            current.phase, VCS_DEVLOOP_PUBLICATION_PHASE_STORAGE_ACKNOWLEDGED,
            VCS_DEVLOOP_PUBLICATION_PHASE_SOURCE_REPRODUCED)) {
        bool same = publication_provider_reused_after_storage(
            &chain, current_root, observed_root, record_root);
        if (same) {
            memcpy(receipt_root_out, current_root, 32);
            if (reused_out)
                *reused_out = true;
        }
        platform_process_lock_release(&queue_lock);
        return same;
    }
    if (have_current &&
        current.phase == VCS_DEVLOOP_PUBLICATION_PHASE_PROVIDER_ANNOUNCED) {
        bool same = publication_provider_reused_as_announced(
            &current, current_root, observed_root, record_root);
        if (same) {
            memcpy(receipt_root_out, current_root, 32);
            if (reused_out)
                *reused_out = true;
        }
        platform_process_lock_release(&queue_lock);
        return same;
    }
    if (!publication_provider_workspace_ready(&current, have_current,
                                              current_root, observed_root)) {
        platform_process_lock_release(&queue_lock);
        return false;
    }
    struct vcs_devloop_publication_receipt receipt = {
        .version = VCS_DEVLOOP_PUBLICATION_RECEIPT_VERSION,
        .phase = VCS_DEVLOOP_PUBLICATION_PHASE_PROVIDER_ANNOUNCED,
        .bytes_scanned = current.bytes_scanned,
        .new_chunks = current.new_chunks,
        .reused_chunks = current.reused_chunks,
        .providers = 1,
        .storage_acks = current.storage_acks,
    };
    memcpy(receipt.job_root, job_root, 32);
    memcpy(receipt.predecessor_receipt_root, current_root, 32);
    memcpy(receipt.artifact_root, record_root, 32);
    bool ok = publication_receipt_publish(repo_root, log_path, &receipt,
                                          receipt_root_out);
    platform_process_lock_release(&queue_lock);
    return ok;
}

static bool publication_storage_ack_progress_load(
    const char *repo_root, const uint8_t job_root[32],
    struct vcs_devloop_publication_receipt *progress,
    struct publication_artifact_chain *chain,
    struct vcs_package_release *release)
{
    uint8_t progress_root[32];
    if (!vcs_devloop_publication_progress_load(repo_root, job_root, progress,
                                               progress_root) ||
        !publication_phase_between(
            progress->phase, VCS_DEVLOOP_PUBLICATION_PHASE_PROVIDER_ANNOUNCED,
            VCS_DEVLOOP_PUBLICATION_PHASE_SOURCE_REPRODUCED) ||
        !publication_artifact_chain_load(repo_root, progress, chain) ||
        !chain->provider_announced ||
        !publication_workspace_release_load(repo_root, chain, release))
        return false;
    return true;
}

static bool publication_storage_ack_provider_verified(
    const char *repo_root, const struct publication_artifact_chain *chain,
    const struct vcs_package_release *release,
    const struct vcs_zcode_dht_record_verify_context *verify,
    struct vcs_zcode_dht_record *provider)
{
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    uint8_t provider_root[32];
    bool provider_expired = false;
    bool ok =
        vcs_object_load_raw_bounded(repo_root, chain->provider.artifact_root,
                                    VCS_ZCODE_DHT_RECORD_WIRE_BYTES, &wire,
                                    &wire_len) == 0 &&
        wire_len == VCS_ZCODE_DHT_RECORD_WIRE_BYTES &&
        vcs_zcode_dht_record_parse_persisted(wire, wire_len, verify,
                                             &provider_expired, provider) ==
            VCS_ZCODE_DHT_RECORD_OK &&
        provider->kind == VCS_ZCODE_DHT_RECORD_PROVIDER &&
        memcmp(provider->transport_root, release->package_root, 32) == 0 &&
        vcs_zcode_dht_record_id(provider, provider_root) ==
            VCS_ZCODE_DHT_RECORD_OK &&
        memcmp(provider_root, chain->provider.artifact_root, 32) == 0;
    free(wire);
    return ok;
}

bool vcs_devloop_publication_storage_ack_target(
    const char *repo_root, const uint8_t job_root[32],
    const struct vcs_zcode_dht_record_verify_context *verify,
    struct vcs_devloop_publication_ack_target *out)
{
    if (!repo_root || !repo_root[0] || !job_root || !verify || !out ||
        !vcs_devloop_publication_job_is_queued(repo_root, job_root))
        return false;
    memset(out, 0, sizeof(*out));
    struct vcs_devloop_publication_receipt progress;
    struct publication_artifact_chain chain;
    struct vcs_package_release release;
    if (!publication_storage_ack_progress_load(repo_root, job_root, &progress,
                                               &chain, &release))
        return false;
    struct vcs_zcode_dht_record provider;
    if (!publication_storage_ack_provider_verified(
            repo_root, &chain, &release, verify, &provider))
        return false;
    (void)snprintf(out->namespace_name, sizeof(out->namespace_name), "%s",
                   provider.namespace_name);
    memcpy(out->transport_root, release.package_root, 32);
    out->existing_acks = progress.storage_acks;
    out->already_acknowledged = chain.storage_acknowledged;
    out->already_reproduced = chain.source_reproduced;
    return true;
}

static bool publication_storage_ack_record_parse(
    const struct vcs_package_release *release,
    const struct vcs_zcode_dht_record_verify_context *verify,
    const uint8_t *record_wire, size_t record_wire_len,
    struct vcs_zcode_dht_record *record, uint8_t root_out[32])
{
    return record_wire &&
           record_wire_len == VCS_ZCODE_DHT_RECORD_WIRE_BYTES &&
           vcs_zcode_dht_record_parse(record_wire, record_wire_len, verify,
                                      record) == VCS_ZCODE_DHT_RECORD_OK &&
           record->kind == VCS_ZCODE_DHT_RECORD_STORAGE_ACK &&
           memcmp(record->transport_root, release->package_root, 32) == 0 &&
           vcs_zcode_dht_record_id(record, root_out) ==
               VCS_ZCODE_DHT_RECORD_OK;
}

static bool publication_storage_ack_provider_group_unique(
    const struct vcs_zcode_dht_record *record, const uint8_t providers[][32],
    const uint8_t groups[][32], size_t count)
{
    for (size_t j = 0; j < count; j++)
        if (memcmp(record->provider_node_id, providers[j], 32) == 0 ||
            memcmp(record->owner_group, groups[j], 32) == 0)
            return false;
    return true;
}

/* Parse, dedupe-check, and durably store the i'th storage-ack record;
 * providers[i]/groups[i]/roots[i] are filled on success. */
bool publication_storage_ack_record_ingest(
    const char *repo_root, const struct vcs_package_release *release,
    const struct vcs_zcode_dht_record_verify_context *verify,
    const uint8_t *record_wire, size_t record_wire_len,
    uint8_t providers[][32], uint8_t groups[][32], size_t i,
    uint8_t root_out[32])
{
    struct vcs_zcode_dht_record record;
    if (!publication_storage_ack_record_parse(release, verify, record_wire,
                                              record_wire_len, &record,
                                              root_out) ||
        !publication_storage_ack_provider_group_unique(&record, providers,
                                                       groups, i))
        return false;
    memcpy(providers[i], record.provider_node_id, 32);
    memcpy(groups[i], record.owner_group, 32);
    bool repaired = false;
    return vcs_object_store_init(repo_root) &&
           vcs_object_put_addressed_repair(repo_root, root_out, record_wire,
                                           record_wire_len, &repaired);
}

static bool publication_storage_acks_match_current(
    const struct vcs_devloop_publication_receipt *current,
    const struct publication_artifact_chain *chain,
    const uint8_t observed_root[32], const uint8_t current_root[32],
    const uint8_t ack_set_root[32], size_t record_count)
{
    const uint8_t *current_ack_root =
        current->phase == VCS_DEVLOOP_PUBLICATION_PHASE_SOURCE_REPRODUCED
            ? chain->storage_ack.artifact_root
            : current->artifact_root;
    return memcmp(current_root, observed_root, 32) == 0 &&
           memcmp(current_ack_root, ack_set_root, 32) == 0 &&
           current->storage_acks == record_count;
}

static bool publication_storage_acks_observed_load(
    const char *repo_root, const uint8_t job_root[32],
    struct vcs_devloop_publication_receipt *observed,
    uint8_t observed_root[32], struct publication_artifact_chain *chain,
    struct vcs_package_release *release)
{
    return vcs_devloop_publication_progress_load(repo_root, job_root,
                                                 observed, observed_root) &&
           publication_phase_between(
               observed->phase,
               VCS_DEVLOOP_PUBLICATION_PHASE_PROVIDER_ANNOUNCED,
               VCS_DEVLOOP_PUBLICATION_PHASE_SOURCE_REPRODUCED) &&
           publication_artifact_chain_load(repo_root, observed, chain) &&
           chain->provider_announced &&
           publication_workspace_release_load(repo_root, chain, release);
}

static bool
publication_storage_acks_args_valid(const char *repo_root,
                                    const uint8_t job_root[32],
                                    const uint8_t *receipt_root_out)
{
    return repo_root && repo_root[0] && job_root && receipt_root_out &&
           vcs_devloop_publication_job_is_queued(repo_root, job_root);
}

static bool publication_storage_acks_provider_ready(
    const struct vcs_devloop_publication_receipt *current, bool have_current,
    const uint8_t current_root[32], const uint8_t observed_root[32])
{
    return have_current &&
           current->phase ==
               VCS_DEVLOOP_PUBLICATION_PHASE_PROVIDER_ANNOUNCED &&
           memcmp(current_root, observed_root, 32) == 0;
}

bool vcs_devloop_publication_advance_storage_acks(
    const char *repo_root, const uint8_t job_root[32],
    const uint8_t *const record_wires[], const size_t record_wire_lengths[],
    size_t record_count,
    const struct vcs_zcode_dht_record_verify_context *verify,
    uint8_t receipt_root_out[32], bool *reused_out)
{
    if (reused_out)
        *reused_out = false;
    if (!publication_storage_acks_args_valid(repo_root, job_root,
                                             receipt_root_out))
        return false;
    struct vcs_devloop_publication_receipt observed;
    uint8_t observed_root[32];
    struct publication_artifact_chain chain;
    struct vcs_package_release release;
    if (!publication_storage_acks_observed_load(
            repo_root, job_root, &observed, observed_root, &chain, &release))
        return false;
    uint8_t ack_set_root[32];
    if (!publication_storage_ack_set_store(repo_root, &release, record_wires,
                                           record_wire_lengths, record_count,
                                           verify, ack_set_root))
        return false;

    char lock_path[PATH_MAX], log_path[PATH_MAX];
    struct platform_process_lock queue_lock;
    if (!publication_queue_open(repo_root, lock_path, log_path, &queue_lock))
        return false;
    struct vcs_devloop_publication_receipt current;
    uint8_t current_root[32];
    bool have_current = vcs_devloop_publication_progress_load(
        repo_root, job_root, &current, current_root);
    if (have_current &&
        publication_phase_between(
            current.phase, VCS_DEVLOOP_PUBLICATION_PHASE_STORAGE_ACKNOWLEDGED,
            VCS_DEVLOOP_PUBLICATION_PHASE_SOURCE_REPRODUCED)) {
        bool same = publication_storage_acks_match_current(
            &current, &chain, observed_root, current_root, ack_set_root,
            record_count);
        if (same) {
            memcpy(receipt_root_out, current_root, 32);
            if (reused_out)
                *reused_out = true;
        }
        platform_process_lock_release(&queue_lock);
        return same;
    }
    if (!publication_storage_acks_provider_ready(
            &current, have_current, current_root, observed_root)) {
        platform_process_lock_release(&queue_lock);
        return false;
    }
    uint16_t providers = current.providers > record_count
                             ? current.providers
                             : (uint16_t)record_count;
    struct vcs_devloop_publication_receipt receipt = {
        .version = VCS_DEVLOOP_PUBLICATION_RECEIPT_VERSION,
        .phase = VCS_DEVLOOP_PUBLICATION_PHASE_STORAGE_ACKNOWLEDGED,
        .bytes_scanned = current.bytes_scanned,
        .new_chunks = current.new_chunks,
        .reused_chunks = current.reused_chunks,
        .providers = providers,
        .storage_acks = (uint16_t)record_count,
    };
    memcpy(receipt.job_root, job_root, 32);
    memcpy(receipt.predecessor_receipt_root, current_root, 32);
    memcpy(receipt.artifact_root, ack_set_root, 32);
    bool ok = publication_receipt_publish(repo_root, log_path, &receipt,
                                          receipt_root_out);
    platform_process_lock_release(&queue_lock);
    return ok;
}

/* A reproducer record shares its namespace and transport with `other` but
 * must be a genuinely different provider identity, owner group, and
 * delegation key -- the same shape the provider check and every entry of
 * the storage-ack-set check require. */
static bool publication_record_same_service_distinct_identity(
    const struct vcs_zcode_dht_record *reproduction,
    const struct vcs_zcode_dht_record *other)
{
    return strcmp(reproduction->namespace_name, other->namespace_name) == 0 &&
           memcmp(reproduction->transport_root, other->transport_root, 32) ==
               0 &&
           memcmp(reproduction->provider_node_id, other->provider_node_id,
                  32) != 0 &&
           memcmp(reproduction->owner_group, other->owner_group, 32) != 0 &&
           memcmp(reproduction->delegation.doc.master_pubkey,
                  other->delegation.doc.master_pubkey, 32) != 0;
}

static bool publication_reproducer_distinct_from_provider(
    const char *repo_root, const struct publication_artifact_chain *chain,
    const struct vcs_zcode_dht_record_verify_context *verify,
    const struct vcs_zcode_dht_record *reproduction)
{
    struct vcs_zcode_dht_record provider;
    return chain && chain->provider_announced &&
           chain->storage_acknowledged &&
           publication_record_load_persisted(
               repo_root, chain->provider.artifact_root, verify, &provider) &&
           provider.kind == VCS_ZCODE_DHT_RECORD_PROVIDER &&
           publication_record_same_service_distinct_identity(reproduction,
                                                             &provider);
}

static bool publication_reproducer_ack_set_load(
    const char *repo_root, const struct publication_artifact_chain *chain,
    uint8_t **set_wire, size_t *set_len, uint16_t *count)
{
    bool ok =
        vcs_object_get(repo_root, chain->storage_ack.artifact_root,
                       VCS_TAG_PUBLICATION_ACK_SET, set_wire, set_len) == 0 &&
        *set_len >= VCS_DEV_PUBLICATION_ACK_SET_HEADER_BYTES &&
        memcmp(*set_wire, publication_ack_set_magic, 8) == 0 &&
        zcl_read_u32_le(*set_wire + 8) == 1u;
    *count = ok ? zcl_read_u16_le(*set_wire + 12) : 0;
    return ok && *count >= VCS_DEVLOOP_PUBLICATION_ACK_MIN &&
           *count <= VCS_DEVLOOP_PUBLICATION_ACK_MAX &&
           *set_len == VCS_DEV_PUBLICATION_ACK_SET_HEADER_BYTES +
                           (size_t)*count * 32u;
}

static bool publication_reproducer_distinct_from_all_acks(
    const char *repo_root,
    const struct vcs_zcode_dht_record_verify_context *verify,
    const struct vcs_zcode_dht_record *reproduction, const uint8_t *set_wire,
    uint16_t count)
{
    for (uint16_t i = 0; i < count; i++) {
        const uint8_t *root = set_wire +
                              VCS_DEV_PUBLICATION_ACK_SET_HEADER_BYTES +
                              (size_t)i * 32u;
        struct vcs_zcode_dht_record storage;
        if (!publication_record_load_persisted(repo_root, root, verify,
                                               &storage) ||
            storage.kind != VCS_ZCODE_DHT_RECORD_STORAGE_ACK ||
            !publication_record_same_service_distinct_identity(reproduction,
                                                               &storage))
            return false;
    }
    return true;
}

static bool publication_reproducer_distinct(
    const char *repo_root, const struct publication_artifact_chain *chain,
    const struct vcs_zcode_dht_record_verify_context *verify,
    const struct vcs_zcode_dht_record *reproduction)
{
    if (!publication_reproducer_distinct_from_provider(repo_root, chain,
                                                       verify, reproduction))
        return false;
    uint8_t *set_wire = NULL;
    size_t set_len = 0;
    uint16_t count = 0;
    bool ok = publication_reproducer_ack_set_load(repo_root, chain, &set_wire,
                                                  &set_len, &count) &&
              publication_reproducer_distinct_from_all_acks(
                  repo_root, verify, reproduction, set_wire, count);
    free(set_wire);
    return ok;
}

/* Load the job/progress/chain/release quadruple for a source-reproduction
 * ack target and confirm the publication has reached (or passed) the
 * storage-acknowledged phase with both storage and provider steps done. */
static bool publication_source_reproduction_progress_load(
    const char *repo_root, const uint8_t job_root[32],
    struct vcs_devloop_publication_job *job,
    struct publication_artifact_chain *chain,
    struct vcs_package_release *release, uint16_t *existing_acks)
{
    struct vcs_devloop_publication_receipt progress;
    uint8_t progress_root[32];
    if (!vcs_devloop_publication_job_load(repo_root, job_root, job) ||
        !vcs_devloop_publication_progress_load(repo_root, job_root, &progress,
                                               progress_root) ||
        !publication_phase_between(
            progress.phase,
            VCS_DEVLOOP_PUBLICATION_PHASE_STORAGE_ACKNOWLEDGED,
            VCS_DEVLOOP_PUBLICATION_PHASE_SOURCE_REPRODUCED) ||
        !publication_artifact_chain_load(repo_root, &progress, chain) ||
        !chain->storage_acknowledged || !chain->provider_announced ||
        !publication_workspace_release_load(repo_root, chain, release))
        return false;
    *existing_acks = progress.storage_acks;
    return true;
}

bool vcs_devloop_publication_source_reproduction_target(
    const char *repo_root, const uint8_t job_root[32],
    const struct vcs_zcode_dht_record_verify_context *verify,
    struct vcs_devloop_publication_ack_target *out)
{
    if (!repo_root || !repo_root[0] || !job_root || !verify || !out ||
        !vcs_devloop_publication_job_is_queued(repo_root, job_root))
        return false;
    memset(out, 0, sizeof(*out));
    struct vcs_devloop_publication_job job;
    struct publication_artifact_chain chain;
    struct vcs_package_release release;
    uint16_t existing_acks = 0;
    if (!publication_source_reproduction_progress_load(
            repo_root, job_root, &job, &chain, &release, &existing_acks))
        return false;
    struct vcs_zcode_dht_record provider;
    if (!publication_record_load_persisted(
            repo_root, chain.provider.artifact_root, verify, &provider) ||
        provider.kind != VCS_ZCODE_DHT_RECORD_PROVIDER ||
        memcmp(provider.transport_root, release.package_root, 32) != 0)
        return false;
    (void)snprintf(out->namespace_name, sizeof(out->namespace_name), "%s",
                   provider.namespace_name);
    memcpy(out->transport_root, release.package_root, 32);
    memcpy(out->source_root, job.source_tree_root, 32);
    out->existing_acks = existing_acks;
    out->already_acknowledged = true;
    out->already_reproduced = chain.source_reproduced;
    return true;
}

bool vcs_devloop_publication_advance_source_reproduction_ack(
    const char *repo_root, const uint8_t job_root[32],
    const uint8_t *record_wire, size_t record_wire_len,
    const struct vcs_zcode_dht_record_verify_context *verify,
    uint8_t receipt_root_out[32], bool *reused_out)
{
    if (reused_out)
        *reused_out = false;
    if (!repo_root || !repo_root[0] || !job_root || !record_wire || !verify ||
        !receipt_root_out ||
        !vcs_devloop_publication_job_is_queued(repo_root, job_root))
        return false;
    struct vcs_devloop_publication_job job;
    struct vcs_devloop_publication_receipt observed;
    uint8_t observed_root[32];
    struct publication_artifact_chain chain;
    struct vcs_package_release release;
    struct vcs_zcode_dht_record reproduction;
    uint8_t record_root[32];
    if (!vcs_devloop_publication_job_load(repo_root, job_root, &job) ||
        !vcs_devloop_publication_progress_load(repo_root, job_root, &observed,
                                               observed_root) ||
        (observed.phase !=
             VCS_DEVLOOP_PUBLICATION_PHASE_STORAGE_ACKNOWLEDGED &&
         observed.phase != VCS_DEVLOOP_PUBLICATION_PHASE_SOURCE_REPRODUCED) ||
        !publication_artifact_chain_load(repo_root, &observed, &chain) ||
        !chain.storage_acknowledged ||
        !publication_workspace_release_load(repo_root, &chain, &release) ||
        record_wire_len != VCS_ZCODE_DHT_RECORD_WIRE_BYTES ||
        vcs_zcode_dht_record_parse(record_wire, record_wire_len, verify,
                                   &reproduction) !=
            VCS_ZCODE_DHT_RECORD_OK ||
        reproduction.kind != VCS_ZCODE_DHT_RECORD_SOURCE_REPRODUCTION_ACK ||
        memcmp(reproduction.semantic_root, job.source_tree_root, 32) != 0 ||
        memcmp(reproduction.transport_root, release.package_root, 32) != 0 ||
        !publication_reproducer_distinct(repo_root, &chain, verify,
                                         &reproduction) ||
        vcs_zcode_dht_record_id(&reproduction, record_root) !=
            VCS_ZCODE_DHT_RECORD_OK)
        return false;
    bool repaired = false;
    if (!vcs_object_store_init(repo_root) ||
        !vcs_object_put_addressed_repair(repo_root, record_root, record_wire,
                                         record_wire_len, &repaired))
        return false;

    char lock_path[PATH_MAX], log_path[PATH_MAX];
    struct platform_process_lock queue_lock;
    if (!publication_queue_open(repo_root, lock_path, log_path, &queue_lock))
        return false;
    struct vcs_devloop_publication_receipt current;
    uint8_t current_root[32];
    bool have_current = vcs_devloop_publication_progress_load(
        repo_root, job_root, &current, current_root);
    if (have_current &&
        current.phase == VCS_DEVLOOP_PUBLICATION_PHASE_SOURCE_REPRODUCED) {
        bool same = memcmp(current_root, observed_root, 32) == 0 &&
                    memcmp(current.artifact_root, record_root, 32) == 0;
        if (same) {
            memcpy(receipt_root_out, current_root, 32);
            if (reused_out)
                *reused_out = true;
        }
        platform_process_lock_release(&queue_lock);
        return same;
    }
    if (!have_current ||
        current.phase != VCS_DEVLOOP_PUBLICATION_PHASE_STORAGE_ACKNOWLEDGED ||
        memcmp(current_root, observed_root, 32) != 0) {
        platform_process_lock_release(&queue_lock);
        return false;
    }
    struct vcs_devloop_publication_receipt receipt = {
        .version = VCS_DEVLOOP_PUBLICATION_RECEIPT_VERSION,
        .phase = VCS_DEVLOOP_PUBLICATION_PHASE_SOURCE_REPRODUCED,
        .bytes_scanned = current.bytes_scanned,
        .new_chunks = current.new_chunks,
        .reused_chunks = current.reused_chunks,
        .providers = current.providers,
        .storage_acks = current.storage_acks,
    };
    memcpy(receipt.job_root, job_root, 32);
    memcpy(receipt.predecessor_receipt_root, current_root, 32);
    memcpy(receipt.artifact_root, record_root, 32);
    bool ok = publication_receipt_publish(repo_root, log_path, &receipt,
                                          receipt_root_out);
    platform_process_lock_release(&queue_lock);
    return ok;
}

/* A publication-eligible verdict must be a complete "verify" proof with a
 * boundable phase/scope and decodable source identity and CAS roots. */
bool publication_enqueue_proof_basis_valid(
    const struct vcs_devloop_verdict *verdict, uint8_t source_identity[32],
    uint8_t source_cas[32])
{
    size_t phase_len = verdict->phase ? strlen(verdict->phase) : 0;
    size_t scope_len =
        verdict->proof_scope ? strlen(verdict->proof_scope) : 0;
    return verdict->proof_complete && phase_len != 0 &&
           strcmp(verdict->phase, "verify") == 0 && phase_len < 24 &&
           scope_len != 0 && scope_len < 64 &&
           vcs_devloop_hex32_decode(verdict->source_identity_hex,
                                    source_identity) &&
           vcs_devloop_hex32_decode(verdict->source_cas_hex, source_cas);
}
