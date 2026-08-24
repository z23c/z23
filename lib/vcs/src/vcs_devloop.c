/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * vcs_devloop — implementation. See vcs/vcs_devloop.h. */

#include "vcs/vcs_devloop.h"

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
#include "vcs/zcode_commons_v2.h"
#include "vcs/zcode_dht_record.h"
#include "vcs/build_action.h"

#include "base/hex.h"
#include "base/safe_alloc.h"
#include "base/serialize_le.h"
#include "platform/time_compat.h"
#include "storage/event_log.h"
#include "util/log_macros.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

bool vcs_devloop_hex32_decode(const char *hex, uint8_t out[32])
{
    return zcl_hex_decode(hex, out, 32);
}

#define VCS_DEV_PROOF_WIRE_BYTES 268u
#define VCS_DEV_PUBLICATION_JOB_WIRE_BYTES 236u
#define VCS_DEV_PUBLICATION_RECEIPT_WIRE_BYTES 132u
#define VCS_DEV_PUBLICATION_PROGRESS_MAX 4096u
#define VCS_DEV_PUBLICATION_ACK_SET_HEADER_BYTES 16u

static const uint8_t dev_proof_magic[8] = {'Z','D','P','F','1',0,0,0};
static const uint8_t publication_job_magic[8] =
    {'Z','P','J','B','1',0,0,0};
static const uint8_t publication_receipt_magic[8] =
    {'Z','P','R','C','1',0,0,0};
static const uint8_t publication_ack_set_magic[8] =
    {'Z','P','A','K','1',0,0,0};

static bool publication_root_nonzero(const uint8_t root[32])
{
    uint8_t any = 0;
    if (!root) return false;
    for (size_t i = 0; i < 32; i++) any |= root[i];
    return any != 0;
}

static void publication_fixed(char *out, size_t cap, const char *value)
{
    memset(out, 0, cap);
    if (value)
        (void)snprintf(out, cap, "%s", value);
}

static bool publication_job_serialize(
    const struct vcs_devloop_publication_job *job,
    uint8_t wire[VCS_DEV_PUBLICATION_JOB_WIRE_BYTES])
{
    if (!job || !wire ||
        job->version != VCS_DEVLOOP_PUBLICATION_JOB_VERSION ||
        !publication_root_nonzero(job->vcs_commit_root) ||
        !publication_root_nonzero(job->source_tree_root) ||
        !publication_root_nonzero(job->proof_receipt_root) ||
        !publication_root_nonzero(job->source_identity_sha256) ||
        !publication_root_nonzero(job->source_cas_sha3)) {
        LOG_WARN("vcs.devloop", "publication job serialize: invalid roots");
        return false;
    }
    size_t off = 0;
    memcpy(wire + off, publication_job_magic, 8); off += 8;
    zcl_write_u32_le(wire + off, job->version); off += 4;
    memcpy(wire + off, job->vcs_commit_root, 32); off += 32;
    memcpy(wire + off, job->source_tree_root, 32); off += 32;
    memcpy(wire + off, job->proof_receipt_root, 32); off += 32;
    memcpy(wire + off, job->source_identity_sha256, 32); off += 32;
    memcpy(wire + off, job->source_cas_sha3, 32); off += 32;
    memcpy(wire + off, job->generation_sha256, 32); off += 32;
    memcpy(wire + off, job->parent_workspace_root, 32); off += 32;
    return off == VCS_DEV_PUBLICATION_JOB_WIRE_BYTES;
}

static bool publication_job_parse(
    const uint8_t *wire, size_t wire_len,
    struct vcs_devloop_publication_job *out)
{
    if (!wire || !out || wire_len != VCS_DEV_PUBLICATION_JOB_WIRE_BYTES ||
        memcmp(wire, publication_job_magic, 8) != 0) {
        LOG_WARN("vcs.devloop", "publication job parse: invalid wire");
        return false;
    }
    struct vcs_devloop_publication_job parsed = {0};
    size_t off = 8;
    parsed.version = zcl_read_u32_le(wire + off); off += 4;
    memcpy(parsed.vcs_commit_root, wire + off, 32); off += 32;
    memcpy(parsed.source_tree_root, wire + off, 32); off += 32;
    memcpy(parsed.proof_receipt_root, wire + off, 32); off += 32;
    memcpy(parsed.source_identity_sha256, wire + off, 32); off += 32;
    memcpy(parsed.source_cas_sha3, wire + off, 32); off += 32;
    memcpy(parsed.generation_sha256, wire + off, 32); off += 32;
    memcpy(parsed.parent_workspace_root, wire + off, 32); off += 32;
    uint8_t checked[VCS_DEV_PUBLICATION_JOB_WIRE_BYTES];
    if (off != wire_len || !publication_job_serialize(&parsed, checked) ||
        memcmp(checked, wire, wire_len) != 0) {
        LOG_WARN("vcs.devloop", "publication job parse: noncanonical wire");
        return false;
    }
    *out = parsed;
    return true;
}

bool vcs_devloop_publication_job_load(
    const char *repo_root, const uint8_t job_root[32],
    struct vcs_devloop_publication_job *out)
{
    if (!repo_root || !repo_root[0] || !job_root || !out) {
        LOG_WARN("vcs.devloop", "publication job load: invalid arguments");
        return false;
    }
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    if (vcs_object_get(repo_root, job_root, VCS_TAG_PUBLICATION_JOB,
                       &wire, &wire_len) != 0) {
        LOG_WARN("vcs.devloop", "publication job load: object unavailable");
        return false;
    }
    bool ok = publication_job_parse(wire, wire_len, out);
    free(wire);
    return ok;
}

struct publication_queue_scan {
    const uint8_t *job_root;
    bool found;
};

static bool publication_queue_scan_cb(uint64_t offset,
                                      enum event_log_type type,
                                      const void *payload, size_t len,
                                      void *user)
{
    (void)offset;
    struct publication_queue_scan *scan = user;
    if (type == EV_VCS_PUBLICATION_JOB && len == 32 && payload &&
        memcmp(payload, scan->job_root, 32) == 0) {
        scan->found = true;
        return false;
    }
    return true;
}

static bool publication_queue_path(const char *repo_root, const char *name,
                                   char *out, size_t out_size)
{
    int n = repo_root && name
        ? snprintf(out, out_size, "%s/.zvcs/%s", repo_root, name) : -1;
    if (n <= 0 || (size_t)n >= out_size) {
        LOG_WARN("vcs.devloop", "publication queue path exceeds bound");
        return false;
    }
    return true;
}

bool vcs_devloop_publication_job_is_queued(
    const char *repo_root, const uint8_t job_root[32])
{
    if (!repo_root || !repo_root[0] || !job_root) {
        LOG_WARN("vcs.devloop", "publication queue status: invalid arguments");
        return false;
    }
    char path[PATH_MAX];
    if (!publication_queue_path(repo_root, "publication.log", path,
                                sizeof(path)))
        return false;
    struct stat st;
    if (stat(path, &st) != 0)
        return false;
    event_log_t *log = event_log_open(path);
    if (!log) {
        LOG_WARN("vcs.devloop", "publication queue status: open failed");
        return false;
    }
    struct publication_queue_scan scan = {.job_root = job_root};
    bool ok = event_log_stream(log, 0, publication_queue_scan_cb, &scan) == 0;
    event_log_close(log);
    if (!ok)
        LOG_WARN("vcs.devloop", "publication queue status: stream failed");
    return ok && scan.found;
}

bool vcs_devloop_publication_job_requeue(
    const char *repo_root, const uint8_t job_root[32], bool *reused_out)
{
    if (reused_out) *reused_out = false;
    struct vcs_devloop_publication_job checked;
    if (!repo_root || !repo_root[0] || !job_root ||
        !vcs_devloop_publication_job_load(repo_root, job_root, &checked)) {
        LOG_WARN("vcs.devloop", "publication requeue: invalid job");
        return false;
    }
    char lock_path[PATH_MAX], log_path[PATH_MAX];
    if (!publication_queue_path(repo_root, "publication.lock", lock_path,
                                sizeof(lock_path)) ||
        !publication_queue_path(repo_root, "publication.log", log_path,
                                sizeof(log_path)))
        return false;
    int lock_fd = open(lock_path, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
    if (lock_fd < 0 || flock(lock_fd, LOCK_EX) != 0) {
        if (lock_fd >= 0) close(lock_fd);
        LOG_WARN("vcs.devloop", "publication requeue: lock failed");
        return false;
    }
    event_log_t *log = event_log_open(log_path);
    struct publication_queue_scan scan = {.job_root = job_root};
    bool ok = log &&
        event_log_stream(log, 0, publication_queue_scan_cb, &scan) == 0;
    if (ok && !scan.found)
        ok = event_log_append(log, EV_VCS_PUBLICATION_JOB, job_root, 32) !=
             UINT64_MAX;
    if (log) event_log_close(log);
    (void)flock(lock_fd, LOCK_UN);
    close(lock_fd);
    if (!ok) {
        LOG_WARN("vcs.devloop", "publication requeue: durable append failed");
        return false;
    }
    if (reused_out) *reused_out = scan.found;
    return true;
}

static bool publication_receipt_serialize(
    const struct vcs_devloop_publication_receipt *receipt,
    uint8_t wire[VCS_DEV_PUBLICATION_RECEIPT_WIRE_BYTES])
{
    if (!receipt || !wire ||
        receipt->version != VCS_DEVLOOP_PUBLICATION_RECEIPT_VERSION ||
        (receipt->phase !=
             VCS_DEVLOOP_PUBLICATION_PHASE_WAITING_ACCEPTANCE &&
         receipt->phase !=
             VCS_DEVLOOP_PUBLICATION_PHASE_ACCEPTED_LANE_BOUND &&
         receipt->phase !=
             VCS_DEVLOOP_PUBLICATION_PHASE_PACKAGE_MAPPING_READY &&
         receipt->phase !=
             VCS_DEVLOOP_PUBLICATION_PHASE_RELEASE_PUBLISHED &&
         receipt->phase !=
             VCS_DEVLOOP_PUBLICATION_PHASE_PASSPORT_PUBLISHED &&
         receipt->phase !=
             VCS_DEVLOOP_PUBLICATION_PHASE_WORKSPACE_PUBLISHED &&
         receipt->phase !=
             VCS_DEVLOOP_PUBLICATION_PHASE_PROVIDER_ANNOUNCED &&
         receipt->phase !=
             VCS_DEVLOOP_PUBLICATION_PHASE_STORAGE_ACKNOWLEDGED &&
         receipt->phase !=
             VCS_DEVLOOP_PUBLICATION_PHASE_SOURCE_REPRODUCED) ||
        !publication_root_nonzero(receipt->job_root) ||
        (receipt->phase !=
             VCS_DEVLOOP_PUBLICATION_PHASE_WAITING_ACCEPTANCE &&
         !publication_root_nonzero(receipt->artifact_root))) {
        LOG_WARN("vcs.devloop", "publication receipt serialize: invalid");
        return false;
    }
    size_t off = 0;
    memcpy(wire + off, publication_receipt_magic, 8); off += 8;
    zcl_write_u32_le(wire + off, receipt->version); off += 4;
    zcl_write_u32_le(wire + off, (uint32_t)receipt->phase); off += 4;
    memcpy(wire + off, receipt->job_root, 32); off += 32;
    memcpy(wire + off, receipt->predecessor_receipt_root, 32); off += 32;
    memcpy(wire + off, receipt->artifact_root, 32); off += 32;
    zcl_write_u64_le(wire + off, receipt->bytes_scanned); off += 8;
    zcl_write_u32_le(wire + off, receipt->new_chunks); off += 4;
    zcl_write_u32_le(wire + off, receipt->reused_chunks); off += 4;
    zcl_write_u16_le(wire + off, receipt->providers); off += 2;
    zcl_write_u16_le(wire + off, receipt->storage_acks); off += 2;
    return off == VCS_DEV_PUBLICATION_RECEIPT_WIRE_BYTES;
}

static bool publication_receipt_parse(
    const uint8_t *wire, size_t wire_len,
    struct vcs_devloop_publication_receipt *out)
{
    if (!wire || !out ||
        wire_len != VCS_DEV_PUBLICATION_RECEIPT_WIRE_BYTES ||
        memcmp(wire, publication_receipt_magic, 8) != 0)
        return false;
    struct vcs_devloop_publication_receipt receipt = {0};
    size_t off = 8;
    receipt.version = zcl_read_u32_le(wire + off); off += 4;
    receipt.phase = (enum vcs_devloop_publication_phase)
        zcl_read_u32_le(wire + off); off += 4;
    memcpy(receipt.job_root, wire + off, 32); off += 32;
    memcpy(receipt.predecessor_receipt_root, wire + off, 32); off += 32;
    memcpy(receipt.artifact_root, wire + off, 32); off += 32;
    receipt.bytes_scanned = zcl_read_u64_le(wire + off); off += 8;
    receipt.new_chunks = zcl_read_u32_le(wire + off); off += 4;
    receipt.reused_chunks = zcl_read_u32_le(wire + off); off += 4;
    receipt.providers = zcl_read_u16_le(wire + off); off += 2;
    receipt.storage_acks = zcl_read_u16_le(wire + off); off += 2;
    uint8_t checked[VCS_DEV_PUBLICATION_RECEIPT_WIRE_BYTES];
    if (off != wire_len ||
        !publication_receipt_serialize(&receipt, checked) ||
        memcmp(checked, wire, wire_len) != 0)
        return false;
    *out = receipt;
    return true;
}

bool vcs_devloop_publication_receipt_load(
    const char *repo_root, const uint8_t receipt_root[32],
    struct vcs_devloop_publication_receipt *out)
{
    if (!repo_root || !repo_root[0] || !receipt_root || !out)
        return false;
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    if (vcs_object_get(repo_root, receipt_root,
                       VCS_TAG_PUBLICATION_RECEIPT,
                       &wire, &wire_len) != 0)
        return false;
    bool ok = publication_receipt_parse(wire, wire_len, out);
    free(wire);
    return ok;
}

struct publication_progress_scan {
    const char *repo_root;
    const uint8_t *job_root;
    struct vcs_devloop_publication_receipt latest;
    uint8_t latest_root[32];
    size_t count;
    bool found;
    bool failed;
};

static bool publication_progress_scan_cb(
    uint64_t offset, enum event_log_type type,
    const void *payload, size_t len, void *user)
{
    (void)offset;
    struct publication_progress_scan *scan = user;
    if (type != EV_VCS_PUBLICATION_RECEIPT)
        return true;
    if (++scan->count > VCS_DEV_PUBLICATION_PROGRESS_MAX ||
        len != 32 || !payload) {
        scan->failed = true;
        return false;
    }
    struct vcs_devloop_publication_receipt receipt;
    if (!vcs_devloop_publication_receipt_load(
            scan->repo_root, payload, &receipt)) {
        scan->failed = true;
        return false;
    }
    if (memcmp(receipt.job_root, scan->job_root, 32) == 0) {
        scan->latest = receipt;
        memcpy(scan->latest_root, payload, 32);
        scan->found = true;
    }
    return true;
}

bool vcs_devloop_publication_progress_load(
    const char *repo_root, const uint8_t job_root[32],
    struct vcs_devloop_publication_receipt *out,
    uint8_t receipt_root_out[32])
{
    if (!repo_root || !repo_root[0] || !job_root || !out ||
        !receipt_root_out)
        return false;
    char path[PATH_MAX];
    if (!publication_queue_path(repo_root, "publication.receipts.log",
                                path, sizeof(path)))
        return false;
    struct stat st;
    if (stat(path, &st) != 0)
        return false;
    event_log_t *log = event_log_open(path);
    if (!log)
        return false;
    struct publication_progress_scan scan = {
        .repo_root = repo_root,
        .job_root = job_root,
    };
    bool streamed = event_log_stream(
        log, 0, publication_progress_scan_cb, &scan) == 0;
    event_log_close(log);
    if (!streamed || scan.failed || !scan.found)
        return false;
    *out = scan.latest;
    memcpy(receipt_root_out, scan.latest_root, 32);
    return true;
}

struct publication_artifact_chain {
    bool mapping_ready;
    bool release_published;
    bool passport_published;
    bool workspace_published;
    bool provider_announced;
    bool storage_acknowledged;
    bool source_reproduced;
    struct vcs_devloop_publication_receipt mapping;
    struct vcs_devloop_publication_receipt release;
    struct vcs_devloop_publication_receipt passport;
    struct vcs_devloop_publication_receipt workspace;
    struct vcs_devloop_publication_receipt provider;
    struct vcs_devloop_publication_receipt storage_ack;
    struct vcs_devloop_publication_receipt source_reproduction;
};

/* Resolve an additive artifact suffix back to its mapping receipt.  Every
 * link is address-verified by the object loader and must stay on the exact
 * immutable job; callers can therefore reuse one checked chain instead of
 * reimplementing predecessor traversal for every idempotent retry. */
static bool publication_artifact_chain_load(
    const char *repo_root,
    const struct vcs_devloop_publication_receipt *latest,
    struct publication_artifact_chain *out)
{
    if (!repo_root || !latest || !out) return false;
    memset(out, 0, sizeof(*out));
    const struct vcs_devloop_publication_receipt *cursor = latest;
    if (cursor->phase == VCS_DEVLOOP_PUBLICATION_PHASE_SOURCE_REPRODUCED) {
        out->source_reproduction = *cursor;
        out->source_reproduced = true;
        if (!vcs_devloop_publication_receipt_load(
                repo_root, cursor->predecessor_receipt_root,
                &out->storage_ack) ||
            out->storage_ack.phase !=
                VCS_DEVLOOP_PUBLICATION_PHASE_STORAGE_ACKNOWLEDGED ||
            memcmp(out->storage_ack.job_root, latest->job_root, 32) != 0)
            return false;
        cursor = &out->storage_ack;
    }
    if (cursor->phase ==
            VCS_DEVLOOP_PUBLICATION_PHASE_STORAGE_ACKNOWLEDGED) {
        if (!out->source_reproduced) out->storage_ack = *cursor;
        out->storage_acknowledged = true;
        if (!vcs_devloop_publication_receipt_load(
                repo_root, cursor->predecessor_receipt_root,
                &out->provider) ||
            out->provider.phase !=
                VCS_DEVLOOP_PUBLICATION_PHASE_PROVIDER_ANNOUNCED ||
            memcmp(out->provider.job_root, latest->job_root, 32) != 0)
            return false;
        cursor = &out->provider;
    }
    if (cursor->phase ==
            VCS_DEVLOOP_PUBLICATION_PHASE_PROVIDER_ANNOUNCED) {
        if (!out->storage_acknowledged) out->provider = *cursor;
        out->provider_announced = true;
        if (!vcs_devloop_publication_receipt_load(
                repo_root, cursor->predecessor_receipt_root,
                &out->workspace) ||
            out->workspace.phase !=
                VCS_DEVLOOP_PUBLICATION_PHASE_WORKSPACE_PUBLISHED ||
            memcmp(out->workspace.job_root, latest->job_root, 32) != 0)
            return false;
        cursor = &out->workspace;
    }
    if (cursor->phase ==
            VCS_DEVLOOP_PUBLICATION_PHASE_WORKSPACE_PUBLISHED) {
        if (!out->provider_announced) out->workspace = *cursor;
        out->workspace_published = true;
        if (!vcs_devloop_publication_receipt_load(
                repo_root, cursor->predecessor_receipt_root,
                &out->passport) ||
            out->passport.phase !=
                VCS_DEVLOOP_PUBLICATION_PHASE_PASSPORT_PUBLISHED ||
            memcmp(out->passport.job_root, latest->job_root, 32) != 0)
            return false;
        cursor = &out->passport;
    }
    if (cursor->phase ==
            VCS_DEVLOOP_PUBLICATION_PHASE_PASSPORT_PUBLISHED) {
        if (!out->workspace_published) out->passport = *cursor;
        out->passport_published = true;
        if (!vcs_devloop_publication_receipt_load(
                repo_root, cursor->predecessor_receipt_root,
                &out->release) ||
            out->release.phase !=
                VCS_DEVLOOP_PUBLICATION_PHASE_RELEASE_PUBLISHED ||
            memcmp(out->release.job_root, latest->job_root, 32) != 0)
            return false;
        cursor = &out->release;
    }
    if (cursor->phase ==
            VCS_DEVLOOP_PUBLICATION_PHASE_RELEASE_PUBLISHED) {
        if (!out->passport_published) out->release = *cursor;
        out->release_published = true;
        if (!vcs_devloop_publication_receipt_load(
                repo_root, cursor->predecessor_receipt_root,
                &out->mapping) ||
            out->mapping.phase !=
                VCS_DEVLOOP_PUBLICATION_PHASE_PACKAGE_MAPPING_READY ||
            memcmp(out->mapping.job_root, latest->job_root, 32) != 0)
            return false;
        cursor = &out->mapping;
    }
    if (cursor->phase ==
            VCS_DEVLOOP_PUBLICATION_PHASE_PACKAGE_MAPPING_READY) {
        if (!out->release_published) out->mapping = *cursor;
        out->mapping_ready = true;
    }
    return true;
}

bool vcs_devloop_publication_advance_waiting_acceptance(
    const char *repo_root, const uint8_t job_root[32],
    uint8_t receipt_root_out[32], bool *reused_out)
{
    if (reused_out) *reused_out = false;
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
    int lock_fd = open(lock_path, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
    if (lock_fd < 0 || flock(lock_fd, LOCK_EX) != 0) {
        if (lock_fd >= 0) close(lock_fd);
        return false;
    }
    struct vcs_devloop_publication_receipt current;
    uint8_t current_root[32];
    bool have_current = vcs_devloop_publication_progress_load(
        repo_root, job_root, &current, current_root);
    if (have_current &&
        (current.phase ==
             VCS_DEVLOOP_PUBLICATION_PHASE_WAITING_ACCEPTANCE ||
         current.phase ==
             VCS_DEVLOOP_PUBLICATION_PHASE_ACCEPTED_LANE_BOUND ||
         current.phase ==
             VCS_DEVLOOP_PUBLICATION_PHASE_PACKAGE_MAPPING_READY ||
         current.phase ==
             VCS_DEVLOOP_PUBLICATION_PHASE_RELEASE_PUBLISHED ||
         current.phase ==
             VCS_DEVLOOP_PUBLICATION_PHASE_PASSPORT_PUBLISHED ||
         current.phase ==
             VCS_DEVLOOP_PUBLICATION_PHASE_WORKSPACE_PUBLISHED ||
         current.phase ==
             VCS_DEVLOOP_PUBLICATION_PHASE_PROVIDER_ANNOUNCED ||
         current.phase ==
             VCS_DEVLOOP_PUBLICATION_PHASE_STORAGE_ACKNOWLEDGED ||
         current.phase ==
             VCS_DEVLOOP_PUBLICATION_PHASE_SOURCE_REPRODUCED)) {
        memcpy(receipt_root_out, current_root, 32);
        if (reused_out) *reused_out = true;
        (void)flock(lock_fd, LOCK_UN);
        close(lock_fd);
        return true;
    }
    struct vcs_devloop_publication_receipt receipt = {
        .version = VCS_DEVLOOP_PUBLICATION_RECEIPT_VERSION,
        .phase = VCS_DEVLOOP_PUBLICATION_PHASE_WAITING_ACCEPTANCE,
    };
    memcpy(receipt.job_root, job_root, 32);
    if (have_current)
        memcpy(receipt.predecessor_receipt_root, current_root, 32);
    uint8_t wire[VCS_DEV_PUBLICATION_RECEIPT_WIRE_BYTES];
    bool ok = publication_receipt_serialize(&receipt, wire) &&
        vcs_object_put(repo_root, wire, sizeof(wire),
                       VCS_TAG_PUBLICATION_RECEIPT, receipt_root_out);
    event_log_t *log = ok ? event_log_open(log_path) : NULL;
    if (ok)
        ok = log && event_log_append(
            log, EV_VCS_PUBLICATION_RECEIPT, receipt_root_out, 32) !=
            UINT64_MAX;
    if (log) event_log_close(log);
    (void)flock(lock_fd, LOCK_UN);
    close(lock_fd);
    return ok;
}

static bool publication_accepted_work_valid(
    const char *repo_root,
    const struct vcs_devloop_publication_job *job,
    const uint8_t accepted_work_root[32], int64_t now_unix)
{
    struct vcs_zcode_accepted_work_v1 accepted;
    return now_unix > 0 && vcs_zcode_accepted_work_resolve(
            repo_root, accepted_work_root, now_unix, &accepted) &&
        memcmp(accepted.proven.source_root,
               job->source_tree_root, 32) == 0;
}

bool vcs_devloop_publication_advance_proven_work(
    const char *repo_root, const uint8_t job_root[32],
    const uint8_t accepted_work_root[32], int64_t now_unix,
    uint8_t receipt_root_out[32], bool *reused_out)
{
    if (reused_out) *reused_out = false;
    if (!repo_root || !repo_root[0] || !job_root || !accepted_work_root ||
        !receipt_root_out)
        return false;
    struct vcs_devloop_publication_job job;
    if (!vcs_devloop_publication_job_load(repo_root, job_root, &job) ||
        !vcs_devloop_publication_job_is_queued(repo_root, job_root) ||
        !publication_accepted_work_valid(
            repo_root, &job, accepted_work_root, now_unix))
        return false;
    char lock_path[PATH_MAX], log_path[PATH_MAX];
    if (!publication_queue_path(repo_root, "publication.lock", lock_path,
                                sizeof(lock_path)) ||
        !publication_queue_path(repo_root, "publication.receipts.log",
                                log_path, sizeof(log_path)))
        return false;
    int lock_fd = open(lock_path, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
    if (lock_fd < 0 || flock(lock_fd, LOCK_EX) != 0) {
        if (lock_fd >= 0) close(lock_fd);
        return false;
    }
    struct vcs_devloop_publication_receipt current;
    uint8_t current_root[32];
    bool have_current = vcs_devloop_publication_progress_load(
        repo_root, job_root, &current, current_root);
    if (have_current &&
        (current.phase == VCS_DEVLOOP_PUBLICATION_PHASE_RELEASE_PUBLISHED ||
         current.phase == VCS_DEVLOOP_PUBLICATION_PHASE_PASSPORT_PUBLISHED ||
         current.phase ==
             VCS_DEVLOOP_PUBLICATION_PHASE_WORKSPACE_PUBLISHED ||
         current.phase ==
             VCS_DEVLOOP_PUBLICATION_PHASE_PROVIDER_ANNOUNCED ||
         current.phase ==
             VCS_DEVLOOP_PUBLICATION_PHASE_STORAGE_ACKNOWLEDGED ||
         current.phase ==
             VCS_DEVLOOP_PUBLICATION_PHASE_SOURCE_REPRODUCED)) {
        struct publication_artifact_chain chain;
        struct vcs_package_mapping_set set;
        vcs_package_mapping_set_init(&set);
        bool same = publication_artifact_chain_load(
                repo_root, &current, &chain) &&
            chain.release_published && chain.mapping_ready &&
            vcs_package_mapping_set_load(
                repo_root, chain.mapping.artifact_root, &set) &&
            memcmp(set.lane_receipt_root, accepted_work_root, 32) == 0;
        if (same) {
            memcpy(receipt_root_out, current_root, 32);
            if (reused_out) *reused_out = true;
        }
        vcs_package_mapping_set_free(&set);
        (void)flock(lock_fd, LOCK_UN);
        close(lock_fd);
        return same;
    }
    if (have_current && current.phase ==
            VCS_DEVLOOP_PUBLICATION_PHASE_PACKAGE_MAPPING_READY) {
        struct vcs_package_mapping_set set;
        bool same = vcs_package_mapping_set_load(
                repo_root, current.artifact_root, &set) &&
            memcmp(set.lane_receipt_root, accepted_work_root, 32) == 0;
        if (same) {
            memcpy(receipt_root_out, current_root, 32);
            if (reused_out) *reused_out = true;
        }
        vcs_package_mapping_set_free(&set);
        (void)flock(lock_fd, LOCK_UN);
        close(lock_fd);
        return same;
    }
    if (have_current && current.phase ==
            VCS_DEVLOOP_PUBLICATION_PHASE_ACCEPTED_LANE_BOUND) {
        bool same = memcmp(current.artifact_root,
                           accepted_work_root, 32) == 0;
        if (same) {
            memcpy(receipt_root_out, current_root, 32);
            if (reused_out) *reused_out = true;
        }
        (void)flock(lock_fd, LOCK_UN);
        close(lock_fd);
        return same;
    }
    if (!have_current || current.phase !=
            VCS_DEVLOOP_PUBLICATION_PHASE_WAITING_ACCEPTANCE) {
        (void)flock(lock_fd, LOCK_UN);
        close(lock_fd);
        return false;
    }
    struct vcs_devloop_publication_receipt receipt = {
        .version = VCS_DEVLOOP_PUBLICATION_RECEIPT_VERSION,
        .phase = VCS_DEVLOOP_PUBLICATION_PHASE_ACCEPTED_LANE_BOUND,
    };
    memcpy(receipt.job_root, job_root, 32);
    memcpy(receipt.predecessor_receipt_root, current_root, 32);
    memcpy(receipt.artifact_root, accepted_work_root, 32);
    uint8_t wire[VCS_DEV_PUBLICATION_RECEIPT_WIRE_BYTES];
    bool ok = publication_receipt_serialize(&receipt, wire) &&
        vcs_object_put(repo_root, wire, sizeof(wire),
                       VCS_TAG_PUBLICATION_RECEIPT, receipt_root_out);
    event_log_t *log = ok ? event_log_open(log_path) : NULL;
    if (ok)
        ok = log && event_log_append(
            log, EV_VCS_PUBLICATION_RECEIPT, receipt_root_out, 32) !=
            UINT64_MAX;
    if (log) event_log_close(log);
    (void)flock(lock_fd, LOCK_UN);
    close(lock_fd);
    return ok;
}

static bool publication_mapping_valid(
    const char *repo_root, const struct vcs_devloop_publication_job *job,
    const uint8_t mapping_set_root[32],
    struct vcs_package_mapping_set *set_out)
{
    struct vcs_package_mapping_set set;
    if (!vcs_package_mapping_set_load(repo_root, mapping_set_root, &set) ||
        memcmp(set.source_tree_root, job->source_tree_root, 32) != 0 ||
        !publication_root_nonzero(set.lane_receipt_root)) {
        vcs_package_mapping_set_free(&set);
        return false;
    }
    struct vcs_manifest tree;
    if (!vcs_tree_load(repo_root, job->source_tree_root, &tree)) {
        vcs_package_mapping_set_free(&set);
        return false;
    }
    bool ok = tree.count > 0;
    for (size_t i = 0; ok && i < tree.count; i++) {
        uint8_t *hashes = NULL;
        uint32_t chunks = 0;
        ok = vcs_object_has(repo_root, tree.entries[i].blob) &&
            vcs_package_mapping_set_find(
                repo_root, &set, tree.entries[i].blob,
                tree.entries[i].size, &hashes, &chunks);
        free(hashes);
    }
    vcs_manifest_free(&tree);
    if (!ok) {
        vcs_package_mapping_set_free(&set);
        return false;
    }
    *set_out = set;
    return true;
}

bool vcs_devloop_publication_advance_package_mapping(
    const char *repo_root, const uint8_t job_root[32],
    const uint8_t mapping_set_root[32], uint64_t bytes_scanned,
    uint32_t new_chunks, uint32_t reused_chunks,
    uint8_t receipt_root_out[32], bool *reused_out)
{
    if (reused_out) *reused_out = false;
    struct vcs_devloop_publication_job job;
    struct vcs_package_mapping_set set;
    if (!repo_root || !repo_root[0] || !job_root || !mapping_set_root ||
        !receipt_root_out ||
        !vcs_devloop_publication_job_load(repo_root, job_root, &job) ||
        !vcs_devloop_publication_job_is_queued(repo_root, job_root) ||
        !publication_mapping_valid(repo_root, &job, mapping_set_root, &set))
        return false;
    char lock_path[PATH_MAX], log_path[PATH_MAX];
    bool paths = publication_queue_path(
            repo_root, "publication.lock", lock_path, sizeof(lock_path)) &&
        publication_queue_path(repo_root, "publication.receipts.log",
                               log_path, sizeof(log_path));
    int lock_fd = paths
        ? open(lock_path, O_RDWR | O_CREAT | O_CLOEXEC, 0600) : -1;
    if (lock_fd < 0 || flock(lock_fd, LOCK_EX) != 0) {
        if (lock_fd >= 0) close(lock_fd);
        vcs_package_mapping_set_free(&set);
        return false;
    }
    struct vcs_devloop_publication_receipt current;
    uint8_t current_root[32];
    bool have_current = vcs_devloop_publication_progress_load(
        repo_root, job_root, &current, current_root);
    if (have_current &&
        (current.phase == VCS_DEVLOOP_PUBLICATION_PHASE_RELEASE_PUBLISHED ||
         current.phase == VCS_DEVLOOP_PUBLICATION_PHASE_PASSPORT_PUBLISHED ||
         current.phase ==
             VCS_DEVLOOP_PUBLICATION_PHASE_WORKSPACE_PUBLISHED ||
         current.phase ==
             VCS_DEVLOOP_PUBLICATION_PHASE_PROVIDER_ANNOUNCED ||
         current.phase ==
             VCS_DEVLOOP_PUBLICATION_PHASE_STORAGE_ACKNOWLEDGED ||
         current.phase ==
             VCS_DEVLOOP_PUBLICATION_PHASE_SOURCE_REPRODUCED)) {
        struct publication_artifact_chain chain;
        bool same = publication_artifact_chain_load(
                repo_root, &current, &chain) &&
            chain.release_published && chain.mapping_ready &&
            memcmp(chain.mapping.artifact_root, mapping_set_root, 32) == 0;
        if (same) {
            memcpy(receipt_root_out, current_root, 32);
            if (reused_out) *reused_out = true;
        }
        (void)flock(lock_fd, LOCK_UN);
        close(lock_fd);
        vcs_package_mapping_set_free(&set);
        return same;
    }
    if (have_current && current.phase ==
            VCS_DEVLOOP_PUBLICATION_PHASE_PACKAGE_MAPPING_READY) {
        bool same = memcmp(current.artifact_root, mapping_set_root, 32) == 0;
        if (same) {
            memcpy(receipt_root_out, current_root, 32);
            if (reused_out) *reused_out = true;
        }
        (void)flock(lock_fd, LOCK_UN);
        close(lock_fd);
        vcs_package_mapping_set_free(&set);
        return same;
    }
    bool accepted = have_current && current.phase ==
            VCS_DEVLOOP_PUBLICATION_PHASE_ACCEPTED_LANE_BOUND &&
        memcmp(current.artifact_root, set.lane_receipt_root, 32) == 0;
    if (!accepted) {
        (void)flock(lock_fd, LOCK_UN);
        close(lock_fd);
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
    uint8_t wire[VCS_DEV_PUBLICATION_RECEIPT_WIRE_BYTES];
    bool ok = publication_receipt_serialize(&receipt, wire) &&
        vcs_object_put(repo_root, wire, sizeof(wire),
                       VCS_TAG_PUBLICATION_RECEIPT, receipt_root_out);
    event_log_t *log = ok ? event_log_open(log_path) : NULL;
    if (ok)
        ok = log && event_log_append(
            log, EV_VCS_PUBLICATION_RECEIPT, receipt_root_out, 32) !=
            UINT64_MAX;
    if (log) event_log_close(log);
    (void)flock(lock_fd, LOCK_UN);
    close(lock_fd);
    vcs_package_mapping_set_free(&set);
    return ok;
}

bool vcs_devloop_publication_advance_release(
    const char *repo_root, const uint8_t job_root[32],
    const uint8_t mapping_set_root[32], const uint8_t release_root[32],
    uint8_t receipt_root_out[32], bool *reused_out)
{
    if (reused_out) *reused_out = false;
    struct vcs_devloop_publication_job job;
    struct vcs_package_mapping_set set;
    if (!repo_root || !repo_root[0] || !job_root || !mapping_set_root ||
        !release_root || !receipt_root_out ||
        !publication_root_nonzero(release_root) ||
        !vcs_devloop_publication_job_load(repo_root, job_root, &job) ||
        !vcs_devloop_publication_job_is_queued(repo_root, job_root) ||
        !publication_mapping_valid(repo_root, &job, mapping_set_root, &set))
        return false;
    char lock_path[PATH_MAX], log_path[PATH_MAX];
    bool paths = publication_queue_path(
            repo_root, "publication.lock", lock_path, sizeof(lock_path)) &&
        publication_queue_path(repo_root, "publication.receipts.log",
                               log_path, sizeof(log_path));
    int lock_fd = paths
        ? open(lock_path, O_RDWR | O_CREAT | O_CLOEXEC, 0600) : -1;
    if (lock_fd < 0 || flock(lock_fd, LOCK_EX) != 0) {
        if (lock_fd >= 0) close(lock_fd);
        vcs_package_mapping_set_free(&set);
        return false;
    }
    struct vcs_devloop_publication_receipt current;
    uint8_t current_root[32];
    bool have_current = vcs_devloop_publication_progress_load(
        repo_root, job_root, &current, current_root);
    if (have_current &&
        (current.phase == VCS_DEVLOOP_PUBLICATION_PHASE_RELEASE_PUBLISHED ||
         current.phase == VCS_DEVLOOP_PUBLICATION_PHASE_PASSPORT_PUBLISHED ||
         current.phase ==
             VCS_DEVLOOP_PUBLICATION_PHASE_WORKSPACE_PUBLISHED ||
         current.phase ==
             VCS_DEVLOOP_PUBLICATION_PHASE_PROVIDER_ANNOUNCED ||
         current.phase ==
             VCS_DEVLOOP_PUBLICATION_PHASE_STORAGE_ACKNOWLEDGED ||
         current.phase ==
             VCS_DEVLOOP_PUBLICATION_PHASE_SOURCE_REPRODUCED)) {
        struct publication_artifact_chain chain;
        bool same = publication_artifact_chain_load(
                repo_root, &current, &chain) &&
            chain.release_published && chain.mapping_ready &&
            memcmp(chain.release.artifact_root, release_root, 32) == 0 &&
            memcmp(chain.mapping.artifact_root, mapping_set_root, 32) == 0;
        if (same) {
            memcpy(receipt_root_out, current_root, 32);
            if (reused_out) *reused_out = true;
        }
        (void)flock(lock_fd, LOCK_UN);
        close(lock_fd);
        vcs_package_mapping_set_free(&set);
        return same;
    }
    bool mapped = have_current && current.phase ==
            VCS_DEVLOOP_PUBLICATION_PHASE_PACKAGE_MAPPING_READY &&
        memcmp(current.artifact_root, mapping_set_root, 32) == 0;
    if (!mapped) {
        (void)flock(lock_fd, LOCK_UN);
        close(lock_fd);
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
    uint8_t wire[VCS_DEV_PUBLICATION_RECEIPT_WIRE_BYTES];
    bool ok = publication_receipt_serialize(&receipt, wire) &&
        vcs_object_put(repo_root, wire, sizeof(wire),
                       VCS_TAG_PUBLICATION_RECEIPT, receipt_root_out);
    event_log_t *log = ok ? event_log_open(log_path) : NULL;
    if (ok)
        ok = log && event_log_append(
            log, EV_VCS_PUBLICATION_RECEIPT, receipt_root_out, 32) !=
            UINT64_MAX;
    if (log) event_log_close(log);
    (void)flock(lock_fd, LOCK_UN);
    close(lock_fd);
    vcs_package_mapping_set_free(&set);
    return ok;
}

bool vcs_devloop_publication_advance_passport(
    const char *repo_root, const uint8_t job_root[32],
    const uint8_t mapping_set_root[32], const uint8_t release_root[32],
    const uint8_t passport_root[32], uint8_t receipt_root_out[32],
    bool *reused_out)
{
    if (reused_out) *reused_out = false;
    struct vcs_devloop_publication_job job;
    struct vcs_package_mapping_set set;
    if (!repo_root || !repo_root[0] || !job_root || !mapping_set_root ||
        !release_root || !passport_root || !receipt_root_out ||
        !publication_root_nonzero(release_root) ||
        !publication_root_nonzero(passport_root) ||
        !vcs_devloop_publication_job_load(repo_root, job_root, &job) ||
        !vcs_devloop_publication_job_is_queued(repo_root, job_root) ||
        !publication_mapping_valid(repo_root, &job, mapping_set_root, &set))
        return false;
    char lock_path[PATH_MAX], log_path[PATH_MAX];
    bool paths = publication_queue_path(
            repo_root, "publication.lock", lock_path, sizeof(lock_path)) &&
        publication_queue_path(repo_root, "publication.receipts.log",
                               log_path, sizeof(log_path));
    int lock_fd = paths
        ? open(lock_path, O_RDWR | O_CREAT | O_CLOEXEC, 0600) : -1;
    if (lock_fd < 0 || flock(lock_fd, LOCK_EX) != 0) {
        if (lock_fd >= 0) close(lock_fd);
        vcs_package_mapping_set_free(&set);
        return false;
    }
    struct vcs_devloop_publication_receipt current;
    uint8_t current_root[32];
    bool have_current = vcs_devloop_publication_progress_load(
        repo_root, job_root, &current, current_root);
    if (have_current &&
        (current.phase == VCS_DEVLOOP_PUBLICATION_PHASE_PASSPORT_PUBLISHED ||
         current.phase ==
             VCS_DEVLOOP_PUBLICATION_PHASE_WORKSPACE_PUBLISHED ||
         current.phase ==
             VCS_DEVLOOP_PUBLICATION_PHASE_PROVIDER_ANNOUNCED ||
         current.phase ==
             VCS_DEVLOOP_PUBLICATION_PHASE_STORAGE_ACKNOWLEDGED ||
         current.phase ==
             VCS_DEVLOOP_PUBLICATION_PHASE_SOURCE_REPRODUCED)) {
        struct publication_artifact_chain chain;
        bool same = publication_artifact_chain_load(
                repo_root, &current, &chain) &&
            chain.passport_published && chain.release_published &&
            chain.mapping_ready &&
            memcmp(chain.passport.artifact_root, passport_root, 32) == 0 &&
            memcmp(chain.release.artifact_root, release_root, 32) == 0 &&
            memcmp(chain.mapping.artifact_root, mapping_set_root, 32) == 0;
        if (same) {
            memcpy(receipt_root_out, current_root, 32);
            if (reused_out) *reused_out = true;
        }
        (void)flock(lock_fd, LOCK_UN);
        close(lock_fd);
        vcs_package_mapping_set_free(&set);
        return same;
    }
    bool released = have_current && current.phase ==
            VCS_DEVLOOP_PUBLICATION_PHASE_RELEASE_PUBLISHED &&
        memcmp(current.artifact_root, release_root, 32) == 0;
    struct vcs_devloop_publication_receipt mapping_receipt;
    released = released && vcs_devloop_publication_receipt_load(
            repo_root, current.predecessor_receipt_root,
            &mapping_receipt) &&
        mapping_receipt.phase ==
            VCS_DEVLOOP_PUBLICATION_PHASE_PACKAGE_MAPPING_READY &&
        memcmp(mapping_receipt.artifact_root, mapping_set_root, 32) == 0;
    if (!released) {
        (void)flock(lock_fd, LOCK_UN);
        close(lock_fd);
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
    uint8_t wire[VCS_DEV_PUBLICATION_RECEIPT_WIRE_BYTES];
    bool ok = publication_receipt_serialize(&receipt, wire) &&
        vcs_object_put(repo_root, wire, sizeof(wire),
                       VCS_TAG_PUBLICATION_RECEIPT, receipt_root_out);
    event_log_t *log = ok ? event_log_open(log_path) : NULL;
    if (ok)
        ok = log && event_log_append(
            log, EV_VCS_PUBLICATION_RECEIPT, receipt_root_out, 32) !=
            UINT64_MAX;
    if (log) event_log_close(log);
    (void)flock(lock_fd, LOCK_UN);
    close(lock_fd);
    vcs_package_mapping_set_free(&set);
    return ok;
}

bool vcs_devloop_publication_advance_workspace(
    const char *repo_root, const uint8_t job_root[32],
    const uint8_t mapping_set_root[32], const uint8_t release_root[32],
    const uint8_t passport_root[32], const uint8_t workspace_root[32],
    uint8_t receipt_root_out[32], bool *reused_out)
{
    if (reused_out) *reused_out = false;
    struct vcs_devloop_publication_job job;
    struct vcs_package_mapping_set set;
    if (!repo_root || !repo_root[0] || !job_root || !mapping_set_root ||
        !release_root || !passport_root || !workspace_root ||
        !receipt_root_out || !publication_root_nonzero(release_root) ||
        !publication_root_nonzero(passport_root) ||
        !publication_root_nonzero(workspace_root) ||
        !vcs_devloop_publication_job_load(repo_root, job_root, &job) ||
        !vcs_devloop_publication_job_is_queued(repo_root, job_root) ||
        !publication_mapping_valid(repo_root, &job, mapping_set_root, &set))
        return false;
    char lock_path[PATH_MAX], log_path[PATH_MAX];
    bool paths = publication_queue_path(
            repo_root, "publication.lock", lock_path, sizeof(lock_path)) &&
        publication_queue_path(repo_root, "publication.receipts.log",
                               log_path, sizeof(log_path));
    int lock_fd = paths
        ? open(lock_path, O_RDWR | O_CREAT | O_CLOEXEC, 0600) : -1;
    if (lock_fd < 0 || flock(lock_fd, LOCK_EX) != 0) {
        if (lock_fd >= 0) close(lock_fd);
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
        (current.phase ==
             VCS_DEVLOOP_PUBLICATION_PHASE_WORKSPACE_PUBLISHED ||
         current.phase ==
             VCS_DEVLOOP_PUBLICATION_PHASE_PROVIDER_ANNOUNCED ||
         current.phase ==
             VCS_DEVLOOP_PUBLICATION_PHASE_STORAGE_ACKNOWLEDGED ||
         current.phase ==
             VCS_DEVLOOP_PUBLICATION_PHASE_SOURCE_REPRODUCED)) {
        bool same = chain.workspace_published &&
            chain.passport_published && chain.release_published &&
            chain.mapping_ready &&
            memcmp(chain.workspace.artifact_root, workspace_root, 32) == 0 &&
            memcmp(chain.passport.artifact_root, passport_root, 32) == 0 &&
            memcmp(chain.release.artifact_root, release_root, 32) == 0 &&
            memcmp(chain.mapping.artifact_root, mapping_set_root, 32) == 0;
        if (same) {
            memcpy(receipt_root_out, current_root, 32);
            if (reused_out) *reused_out = true;
        }
        (void)flock(lock_fd, LOCK_UN);
        close(lock_fd);
        vcs_package_mapping_set_free(&set);
        return same;
    }
    bool passported = chained && current.phase ==
            VCS_DEVLOOP_PUBLICATION_PHASE_PASSPORT_PUBLISHED &&
        chain.passport_published && chain.release_published &&
        chain.mapping_ready &&
        memcmp(chain.passport.artifact_root, passport_root, 32) == 0 &&
        memcmp(chain.release.artifact_root, release_root, 32) == 0 &&
        memcmp(chain.mapping.artifact_root, mapping_set_root, 32) == 0;
    if (!passported) {
        (void)flock(lock_fd, LOCK_UN);
        close(lock_fd);
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
    uint8_t wire[VCS_DEV_PUBLICATION_RECEIPT_WIRE_BYTES];
    bool ok = publication_receipt_serialize(&receipt, wire) &&
        vcs_object_put(repo_root, wire, sizeof(wire),
                       VCS_TAG_PUBLICATION_RECEIPT, receipt_root_out);
    event_log_t *log = ok ? event_log_open(log_path) : NULL;
    if (ok)
        ok = log && event_log_append(
            log, EV_VCS_PUBLICATION_RECEIPT, receipt_root_out, 32) !=
            UINT64_MAX;
    if (log) event_log_close(log);
    (void)flock(lock_fd, LOCK_UN);
    close(lock_fd);
    vcs_package_mapping_set_free(&set);
    return ok;
}

#define VCS_DEV_WORKSPACE_MAX_WIRE_BYTES                              \
    (VCS_ZCODE_WORKSPACE_MANIFEST_V1_WIRE_BASE_BYTES +                \
     VCS_ZCODE_COMMONS_MAX_CLAIMS *                                   \
         (VCS_ZCODE_WORKSPACE_MANIFEST_V1_ENTRY_WIRE_BYTES +          \
          VCS_ZCODE_WORKSPACE_MANIFEST_V1_EDGE_WIRE_BYTES +           \
          VCS_ZCODE_WORKSPACE_MANIFEST_V1_ASSET_WIRE_BYTES))

static bool publication_workspace_release_load(
    const char *repo_root, const struct publication_artifact_chain *chain,
    struct vcs_package_release *release_out)
{
    uint8_t *workspace_wire = NULL;
    size_t workspace_wire_len = 0;
    struct vcs_zcode_workspace_manifest_v1_decoded decoded = {0};
    uint8_t checked_workspace_root[32];
    bool ok = chain && chain->workspace_published &&
        chain->passport_published && chain->release_published &&
        vcs_object_load_raw_bounded(
            repo_root, chain->workspace.artifact_root,
            VCS_DEV_WORKSPACE_MAX_WIRE_BYTES,
            &workspace_wire, &workspace_wire_len) == 0 &&
        vcs_zcode_workspace_manifest_v1_decode(
            &decoded, workspace_wire, workspace_wire_len) ==
            VCS_ZCODE_COMMONS_V2_OK &&
        vcs_zcode_workspace_manifest_v1_root(
            &decoded.manifest, checked_workspace_root) ==
            VCS_ZCODE_COMMONS_V2_OK &&
        memcmp(checked_workspace_root,
               chain->workspace.artifact_root, 32) == 0;
    size_t matching_entries = 0;
    for (size_t i = 0; ok && i < decoded.manifest.entry_count; i++) {
        const struct vcs_zcode_workspace_entry_v1 *entry =
            &decoded.manifest.entries[i];
        if (memcmp(entry->module_release_root,
                   chain->release.artifact_root, 32) == 0 &&
            memcmp(entry->module_passport_root,
                   chain->passport.artifact_root, 32) == 0)
            matching_entries++;
    }
    ok = ok && matching_entries == 1u;
    vcs_zcode_workspace_manifest_v1_decoded_free(&decoded);
    free(workspace_wire);
    uint8_t *release_wire = NULL;
    size_t release_wire_len = 0;
    uint8_t checked_release_root[32];
    struct vcs_package_release release;
    ok = ok && vcs_object_load_raw_bounded(
            repo_root, chain->release.artifact_root,
            VCS_PACKAGE_RELEASE_MAX_WIRE_BYTES,
            &release_wire, &release_wire_len) == 0 &&
        vcs_package_release_parse(
            release_wire, release_wire_len, &release) ==
            VCS_PACKAGE_RELEASE_OK &&
        vcs_package_release_verify(&release) == VCS_PACKAGE_RELEASE_OK &&
        vcs_package_release_id(
            &release, checked_release_root) == VCS_PACKAGE_RELEASE_OK &&
        memcmp(checked_release_root,
               chain->release.artifact_root, 32) == 0;
    free(release_wire);
    if (!ok) return false;
    *release_out = release;
    return true;
}

static bool publication_provider_wire_store(
    const char *repo_root, const struct vcs_package_release *release,
    const uint8_t *record_wire, size_t record_wire_len,
    const struct vcs_zcode_dht_record_verify_context *verify,
    uint8_t record_root_out[32])
{
    struct vcs_zcode_dht_record record;
    if (!release || !record_wire || !verify || !record_root_out ||
        record_wire_len != VCS_ZCODE_DHT_RECORD_WIRE_BYTES ||
        vcs_zcode_dht_record_parse(
            record_wire, record_wire_len, verify, &record) !=
            VCS_ZCODE_DHT_RECORD_OK ||
        record.kind != VCS_ZCODE_DHT_RECORD_PROVIDER ||
        memcmp(record.transport_root, release->package_root, 32) != 0 ||
        vcs_zcode_dht_record_id(&record, record_root_out) !=
            VCS_ZCODE_DHT_RECORD_OK)
        return false;
    bool repaired = false;
    if (!vcs_object_store_init(repo_root) ||
        !vcs_object_put_addressed_repair(
            repo_root, record_root_out, record_wire, record_wire_len,
            &repaired))
        return false;
    uint8_t *stored_wire = NULL;
    size_t stored_wire_len = 0;
    struct vcs_zcode_dht_record stored;
    uint8_t stored_root[32];
    bool ok = vcs_object_load_raw_bounded(
            repo_root, record_root_out,
            VCS_ZCODE_DHT_RECORD_WIRE_BYTES,
            &stored_wire, &stored_wire_len) == 0 &&
        stored_wire_len == record_wire_len &&
        memcmp(stored_wire, record_wire, record_wire_len) == 0 &&
        vcs_zcode_dht_record_parse(
            stored_wire, stored_wire_len, verify, &stored) ==
            VCS_ZCODE_DHT_RECORD_OK &&
        vcs_zcode_dht_record_id(&stored, stored_root) ==
            VCS_ZCODE_DHT_RECORD_OK &&
        memcmp(stored_root, record_root_out, 32) == 0;
    free(stored_wire);
    return ok;
}

bool vcs_devloop_publication_advance_provider(
    const char *repo_root, const uint8_t job_root[32],
    const uint8_t *record_wire, size_t record_wire_len,
    const struct vcs_zcode_dht_record_verify_context *verify,
    uint8_t receipt_root_out[32], bool *reused_out)
{
    if (reused_out) *reused_out = false;
    if (!repo_root || !repo_root[0] || !job_root || !record_wire || !verify ||
        !receipt_root_out ||
        !vcs_devloop_publication_job_is_queued(repo_root, job_root))
        return false;
    struct vcs_devloop_publication_job job;
    struct vcs_devloop_publication_receipt observed;
    uint8_t observed_root[32];
    struct publication_artifact_chain chain;
    struct vcs_package_release release;
    if (!vcs_devloop_publication_job_load(repo_root, job_root, &job) ||
        !vcs_devloop_publication_progress_load(
            repo_root, job_root, &observed, observed_root) ||
        (observed.phase !=
             VCS_DEVLOOP_PUBLICATION_PHASE_WORKSPACE_PUBLISHED &&
         observed.phase !=
             VCS_DEVLOOP_PUBLICATION_PHASE_PROVIDER_ANNOUNCED &&
         observed.phase !=
             VCS_DEVLOOP_PUBLICATION_PHASE_STORAGE_ACKNOWLEDGED &&
         observed.phase !=
             VCS_DEVLOOP_PUBLICATION_PHASE_SOURCE_REPRODUCED) ||
        !publication_artifact_chain_load(repo_root, &observed, &chain) ||
        !publication_workspace_release_load(repo_root, &chain, &release))
        return false;
    uint8_t record_root[32];
    if (!publication_provider_wire_store(
            repo_root, &release, record_wire, record_wire_len, verify,
            record_root))
        return false;

    char lock_path[PATH_MAX], log_path[PATH_MAX];
    bool paths = publication_queue_path(
            repo_root, "publication.lock", lock_path, sizeof(lock_path)) &&
        publication_queue_path(repo_root, "publication.receipts.log",
                               log_path, sizeof(log_path));
    int lock_fd = paths
        ? open(lock_path, O_RDWR | O_CREAT | O_CLOEXEC, 0600) : -1;
    if (lock_fd < 0 || flock(lock_fd, LOCK_EX) != 0) {
        if (lock_fd >= 0) close(lock_fd);
        return false;
    }
    struct vcs_devloop_publication_receipt current;
    uint8_t current_root[32];
    bool have_current = vcs_devloop_publication_progress_load(
        repo_root, job_root, &current, current_root);
    if (have_current &&
        (current.phase ==
             VCS_DEVLOOP_PUBLICATION_PHASE_STORAGE_ACKNOWLEDGED ||
         current.phase == VCS_DEVLOOP_PUBLICATION_PHASE_SOURCE_REPRODUCED)) {
        bool same = memcmp(current_root, observed_root, 32) == 0 &&
            chain.provider_announced &&
            memcmp(chain.provider.artifact_root, record_root, 32) == 0;
        if (same) {
            memcpy(receipt_root_out, current_root, 32);
            if (reused_out) *reused_out = true;
        }
        (void)flock(lock_fd, LOCK_UN);
        close(lock_fd);
        return same;
    }
    if (have_current && current.phase ==
            VCS_DEVLOOP_PUBLICATION_PHASE_PROVIDER_ANNOUNCED) {
        bool same = memcmp(current_root, observed_root, 32) == 0 &&
            memcmp(current.artifact_root, record_root, 32) == 0;
        if (same) {
            memcpy(receipt_root_out, current_root, 32);
            if (reused_out) *reused_out = true;
        }
        (void)flock(lock_fd, LOCK_UN);
        close(lock_fd);
        return same;
    }
    if (!have_current || current.phase !=
            VCS_DEVLOOP_PUBLICATION_PHASE_WORKSPACE_PUBLISHED ||
        memcmp(current_root, observed_root, 32) != 0) {
        (void)flock(lock_fd, LOCK_UN);
        close(lock_fd);
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
    uint8_t wire[VCS_DEV_PUBLICATION_RECEIPT_WIRE_BYTES];
    bool ok = publication_receipt_serialize(&receipt, wire) &&
        vcs_object_put(repo_root, wire, sizeof(wire),
                       VCS_TAG_PUBLICATION_RECEIPT, receipt_root_out);
    event_log_t *log = ok ? event_log_open(log_path) : NULL;
    if (ok)
        ok = log && event_log_append(
            log, EV_VCS_PUBLICATION_RECEIPT, receipt_root_out, 32) !=
            UINT64_MAX;
    if (log) event_log_close(log);
    (void)flock(lock_fd, LOCK_UN);
    close(lock_fd);
    return ok;
}

static int publication_root_compare(const void *left, const void *right)
{
    return memcmp(left, right, 32);
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
    uint8_t progress_root[32];
    struct publication_artifact_chain chain;
    struct vcs_package_release release;
    if (!vcs_devloop_publication_progress_load(
            repo_root, job_root, &progress, progress_root) ||
        (progress.phase !=
             VCS_DEVLOOP_PUBLICATION_PHASE_PROVIDER_ANNOUNCED &&
         progress.phase !=
             VCS_DEVLOOP_PUBLICATION_PHASE_STORAGE_ACKNOWLEDGED &&
         progress.phase !=
             VCS_DEVLOOP_PUBLICATION_PHASE_SOURCE_REPRODUCED) ||
        !publication_artifact_chain_load(repo_root, &progress, &chain) ||
        !chain.provider_announced ||
        !publication_workspace_release_load(repo_root, &chain, &release))
        return false;

    uint8_t *wire = NULL;
    size_t wire_len = 0;
    struct vcs_zcode_dht_record provider;
    uint8_t provider_root[32];
    bool provider_expired = false;
    bool ok = vcs_object_load_raw_bounded(
            repo_root, chain.provider.artifact_root,
            VCS_ZCODE_DHT_RECORD_WIRE_BYTES, &wire, &wire_len) == 0 &&
        wire_len == VCS_ZCODE_DHT_RECORD_WIRE_BYTES &&
        vcs_zcode_dht_record_parse_persisted(
            wire, wire_len, verify, &provider_expired, &provider) ==
                VCS_ZCODE_DHT_RECORD_OK &&
        provider.kind == VCS_ZCODE_DHT_RECORD_PROVIDER &&
        memcmp(provider.transport_root, release.package_root, 32) == 0 &&
        vcs_zcode_dht_record_id(&provider, provider_root) ==
            VCS_ZCODE_DHT_RECORD_OK &&
        memcmp(provider_root, chain.provider.artifact_root, 32) == 0;
    free(wire);
    if (!ok)
        return false;
    (void)snprintf(out->namespace_name, sizeof(out->namespace_name), "%s",
                   provider.namespace_name);
    memcpy(out->transport_root, release.package_root, 32);
    out->existing_acks = progress.storage_acks;
    out->already_acknowledged = chain.storage_acknowledged;
    out->already_reproduced = chain.source_reproduced;
    return true;
}

static bool publication_storage_ack_set_store(
    const char *repo_root, const struct vcs_package_release *release,
    const uint8_t *const record_wires[], const size_t record_wire_lengths[],
    size_t record_count,
    const struct vcs_zcode_dht_record_verify_context *verify,
    uint8_t ack_set_root_out[32])
{
    if (!repo_root || !release || !record_wires || !record_wire_lengths ||
        record_count < VCS_DEVLOOP_PUBLICATION_ACK_MIN ||
        record_count > VCS_DEVLOOP_PUBLICATION_ACK_MAX ||
        !verify || !ack_set_root_out)
        return false;
    uint8_t roots[VCS_DEVLOOP_PUBLICATION_ACK_MAX][32];
    uint8_t providers[VCS_DEVLOOP_PUBLICATION_ACK_MAX][32];
    uint8_t groups[VCS_DEVLOOP_PUBLICATION_ACK_MAX][32];
    for (size_t i = 0; i < record_count; i++) {
        struct vcs_zcode_dht_record record;
        if (!record_wires[i] ||
            record_wire_lengths[i] != VCS_ZCODE_DHT_RECORD_WIRE_BYTES ||
            vcs_zcode_dht_record_parse(
                record_wires[i], record_wire_lengths[i], verify, &record) !=
                VCS_ZCODE_DHT_RECORD_OK ||
            record.kind != VCS_ZCODE_DHT_RECORD_STORAGE_ACK ||
            memcmp(record.transport_root, release->package_root, 32) != 0 ||
            vcs_zcode_dht_record_id(&record, roots[i]) !=
                VCS_ZCODE_DHT_RECORD_OK)
            return false;
        for (size_t j = 0; j < i; j++)
            if (memcmp(record.provider_node_id, providers[j], 32) == 0 ||
                memcmp(record.owner_group, groups[j], 32) == 0)
                return false;
        memcpy(providers[i], record.provider_node_id, 32);
        memcpy(groups[i], record.owner_group, 32);
        bool repaired = false;
        if (!vcs_object_store_init(repo_root) ||
            !vcs_object_put_addressed_repair(
                repo_root, roots[i], record_wires[i],
                record_wire_lengths[i], &repaired))
            return false;
    }
    qsort(roots, record_count, 32, publication_root_compare);
    uint8_t wire[VCS_DEV_PUBLICATION_ACK_SET_HEADER_BYTES +
                 VCS_DEVLOOP_PUBLICATION_ACK_MAX * 32];
    size_t wire_len = VCS_DEV_PUBLICATION_ACK_SET_HEADER_BYTES +
                      record_count * 32;
    memset(wire, 0, wire_len);
    memcpy(wire, publication_ack_set_magic, 8);
    zcl_write_u32_le(wire + 8, 1u);
    zcl_write_u16_le(wire + 12, (uint16_t)record_count);
    memcpy(wire + VCS_DEV_PUBLICATION_ACK_SET_HEADER_BYTES,
           roots, record_count * 32);
    if (!vcs_object_put(repo_root, wire, wire_len,
                        VCS_TAG_PUBLICATION_ACK_SET, ack_set_root_out))
        return false;
    uint8_t *stored = NULL;
    size_t stored_len = 0;
    bool ok = vcs_object_get(
            repo_root, ack_set_root_out, VCS_TAG_PUBLICATION_ACK_SET,
            &stored, &stored_len) == 0 &&
        stored_len == wire_len && memcmp(stored, wire, wire_len) == 0;
    free(stored);
    return ok;
}

bool vcs_devloop_publication_advance_storage_acks(
    const char *repo_root, const uint8_t job_root[32],
    const uint8_t *const record_wires[], const size_t record_wire_lengths[],
    size_t record_count,
    const struct vcs_zcode_dht_record_verify_context *verify,
    uint8_t receipt_root_out[32], bool *reused_out)
{
    if (reused_out) *reused_out = false;
    if (!repo_root || !repo_root[0] || !job_root || !receipt_root_out ||
        !vcs_devloop_publication_job_is_queued(repo_root, job_root))
        return false;
    struct vcs_devloop_publication_receipt observed;
    uint8_t observed_root[32];
    struct publication_artifact_chain chain;
    struct vcs_package_release release;
    if (!vcs_devloop_publication_progress_load(
            repo_root, job_root, &observed, observed_root) ||
        (observed.phase !=
             VCS_DEVLOOP_PUBLICATION_PHASE_PROVIDER_ANNOUNCED &&
         observed.phase !=
             VCS_DEVLOOP_PUBLICATION_PHASE_STORAGE_ACKNOWLEDGED &&
         observed.phase !=
             VCS_DEVLOOP_PUBLICATION_PHASE_SOURCE_REPRODUCED) ||
        !publication_artifact_chain_load(repo_root, &observed, &chain) ||
        !chain.provider_announced ||
        !publication_workspace_release_load(repo_root, &chain, &release))
        return false;
    uint8_t ack_set_root[32];
    if (!publication_storage_ack_set_store(
            repo_root, &release, record_wires, record_wire_lengths,
            record_count, verify, ack_set_root))
        return false;

    char lock_path[PATH_MAX], log_path[PATH_MAX];
    bool paths = publication_queue_path(
            repo_root, "publication.lock", lock_path, sizeof(lock_path)) &&
        publication_queue_path(repo_root, "publication.receipts.log",
                               log_path, sizeof(log_path));
    int lock_fd = paths
        ? open(lock_path, O_RDWR | O_CREAT | O_CLOEXEC, 0600) : -1;
    if (lock_fd < 0 || flock(lock_fd, LOCK_EX) != 0) {
        if (lock_fd >= 0) close(lock_fd);
        return false;
    }
    struct vcs_devloop_publication_receipt current;
    uint8_t current_root[32];
    bool have_current = vcs_devloop_publication_progress_load(
        repo_root, job_root, &current, current_root);
    if (have_current &&
        (current.phase ==
             VCS_DEVLOOP_PUBLICATION_PHASE_STORAGE_ACKNOWLEDGED ||
         current.phase == VCS_DEVLOOP_PUBLICATION_PHASE_SOURCE_REPRODUCED)) {
        const uint8_t *current_ack_root = current.phase ==
                VCS_DEVLOOP_PUBLICATION_PHASE_SOURCE_REPRODUCED
            ? chain.storage_ack.artifact_root : current.artifact_root;
        bool same = memcmp(current_root, observed_root, 32) == 0 &&
            memcmp(current_ack_root, ack_set_root, 32) == 0 &&
            current.storage_acks == record_count;
        if (same) {
            memcpy(receipt_root_out, current_root, 32);
            if (reused_out) *reused_out = true;
        }
        (void)flock(lock_fd, LOCK_UN);
        close(lock_fd);
        return same;
    }
    if (!have_current || current.phase !=
            VCS_DEVLOOP_PUBLICATION_PHASE_PROVIDER_ANNOUNCED ||
        memcmp(current_root, observed_root, 32) != 0) {
        (void)flock(lock_fd, LOCK_UN);
        close(lock_fd);
        return false;
    }
    struct vcs_devloop_publication_receipt receipt = {
        .version = VCS_DEVLOOP_PUBLICATION_RECEIPT_VERSION,
        .phase = VCS_DEVLOOP_PUBLICATION_PHASE_STORAGE_ACKNOWLEDGED,
        .bytes_scanned = current.bytes_scanned,
        .new_chunks = current.new_chunks,
        .reused_chunks = current.reused_chunks,
        .providers = current.providers > record_count
            ? current.providers : (uint16_t)record_count,
        .storage_acks = (uint16_t)record_count,
    };
    memcpy(receipt.job_root, job_root, 32);
    memcpy(receipt.predecessor_receipt_root, current_root, 32);
    memcpy(receipt.artifact_root, ack_set_root, 32);
    uint8_t wire[VCS_DEV_PUBLICATION_RECEIPT_WIRE_BYTES];
    bool ok = publication_receipt_serialize(&receipt, wire) &&
        vcs_object_put(repo_root, wire, sizeof(wire),
                       VCS_TAG_PUBLICATION_RECEIPT, receipt_root_out);
    event_log_t *log = ok ? event_log_open(log_path) : NULL;
    if (ok)
        ok = log && event_log_append(
            log, EV_VCS_PUBLICATION_RECEIPT, receipt_root_out, 32) !=
            UINT64_MAX;
    if (log) event_log_close(log);
    (void)flock(lock_fd, LOCK_UN);
    close(lock_fd);
    return ok;
}

static bool publication_record_load_persisted(
    const char *repo_root, const uint8_t root[32],
    const struct vcs_zcode_dht_record_verify_context *verify,
    struct vcs_zcode_dht_record *record)
{
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    bool expired = false;
    uint8_t checked[32];
    bool ok = vcs_object_load_raw_bounded(
            repo_root, root, VCS_ZCODE_DHT_RECORD_WIRE_BYTES,
            &wire, &wire_len) == 0 &&
        wire_len == VCS_ZCODE_DHT_RECORD_WIRE_BYTES &&
        vcs_zcode_dht_record_parse_persisted(
            wire, wire_len, verify, &expired, record) ==
            VCS_ZCODE_DHT_RECORD_OK &&
        vcs_zcode_dht_record_id(record, checked) ==
            VCS_ZCODE_DHT_RECORD_OK &&
        memcmp(checked, root, 32) == 0;
    free(wire);
    return ok;
}

static bool publication_reproducer_distinct(
    const char *repo_root, const struct publication_artifact_chain *chain,
    const struct vcs_zcode_dht_record_verify_context *verify,
    const struct vcs_zcode_dht_record *reproduction)
{
    struct vcs_zcode_dht_record provider;
    if (!chain || !chain->provider_announced ||
        !chain->storage_acknowledged || !publication_record_load_persisted(
            repo_root, chain->provider.artifact_root, verify, &provider) ||
        provider.kind != VCS_ZCODE_DHT_RECORD_PROVIDER ||
        strcmp(reproduction->namespace_name, provider.namespace_name) != 0 ||
        memcmp(reproduction->transport_root,
               provider.transport_root, 32) != 0 ||
        memcmp(reproduction->provider_node_id,
               provider.provider_node_id, 32) == 0 ||
        memcmp(reproduction->owner_group,
               provider.owner_group, 32) == 0 ||
        memcmp(reproduction->delegation.doc.master_pubkey,
               provider.delegation.doc.master_pubkey, 32) == 0)
        return false;

    uint8_t *set_wire = NULL;
    size_t set_len = 0;
    bool ok = vcs_object_get(
            repo_root, chain->storage_ack.artifact_root,
            VCS_TAG_PUBLICATION_ACK_SET, &set_wire, &set_len) == 0 &&
        set_len >= VCS_DEV_PUBLICATION_ACK_SET_HEADER_BYTES &&
        memcmp(set_wire, publication_ack_set_magic, 8) == 0 &&
        zcl_read_u32_le(set_wire + 8) == 1u;
    uint16_t count = ok ? zcl_read_u16_le(set_wire + 12) : 0;
    ok = ok && count >= VCS_DEVLOOP_PUBLICATION_ACK_MIN &&
        count <= VCS_DEVLOOP_PUBLICATION_ACK_MAX &&
        set_len == VCS_DEV_PUBLICATION_ACK_SET_HEADER_BYTES +
                       (size_t)count * 32u;
    for (uint16_t i = 0; ok && i < count; i++) {
        const uint8_t *root = set_wire +
            VCS_DEV_PUBLICATION_ACK_SET_HEADER_BYTES + (size_t)i * 32u;
        struct vcs_zcode_dht_record storage;
        ok = publication_record_load_persisted(
                repo_root, root, verify, &storage) &&
            storage.kind == VCS_ZCODE_DHT_RECORD_STORAGE_ACK &&
            strcmp(storage.namespace_name,
                   reproduction->namespace_name) == 0 &&
            memcmp(storage.transport_root,
                   reproduction->transport_root, 32) == 0 &&
            memcmp(reproduction->provider_node_id,
                   storage.provider_node_id, 32) != 0 &&
            memcmp(reproduction->owner_group,
                   storage.owner_group, 32) != 0 &&
            memcmp(reproduction->delegation.doc.master_pubkey,
                   storage.delegation.doc.master_pubkey, 32) != 0;
    }
    free(set_wire);
    return ok;
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
    struct vcs_devloop_publication_receipt progress;
    uint8_t progress_root[32];
    struct publication_artifact_chain chain;
    struct vcs_package_release release;
    if (!vcs_devloop_publication_job_load(repo_root, job_root, &job) ||
        !vcs_devloop_publication_progress_load(
            repo_root, job_root, &progress, progress_root) ||
        (progress.phase !=
             VCS_DEVLOOP_PUBLICATION_PHASE_STORAGE_ACKNOWLEDGED &&
         progress.phase != VCS_DEVLOOP_PUBLICATION_PHASE_SOURCE_REPRODUCED) ||
        !publication_artifact_chain_load(repo_root, &progress, &chain) ||
        !chain.storage_acknowledged || !chain.provider_announced ||
        !publication_workspace_release_load(repo_root, &chain, &release))
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
    out->existing_acks = progress.storage_acks;
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
    if (reused_out) *reused_out = false;
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
        !vcs_devloop_publication_progress_load(
            repo_root, job_root, &observed, observed_root) ||
        (observed.phase !=
             VCS_DEVLOOP_PUBLICATION_PHASE_STORAGE_ACKNOWLEDGED &&
         observed.phase != VCS_DEVLOOP_PUBLICATION_PHASE_SOURCE_REPRODUCED) ||
        !publication_artifact_chain_load(repo_root, &observed, &chain) ||
        !chain.storage_acknowledged ||
        !publication_workspace_release_load(repo_root, &chain, &release) ||
        record_wire_len != VCS_ZCODE_DHT_RECORD_WIRE_BYTES ||
        vcs_zcode_dht_record_parse(
            record_wire, record_wire_len, verify, &reproduction) !=
            VCS_ZCODE_DHT_RECORD_OK ||
        reproduction.kind !=
            VCS_ZCODE_DHT_RECORD_SOURCE_REPRODUCTION_ACK ||
        memcmp(reproduction.semantic_root, job.source_tree_root, 32) != 0 ||
        memcmp(reproduction.transport_root, release.package_root, 32) != 0 ||
        !publication_reproducer_distinct(
            repo_root, &chain, verify, &reproduction) ||
        vcs_zcode_dht_record_id(&reproduction, record_root) !=
            VCS_ZCODE_DHT_RECORD_OK)
        return false;
    bool repaired = false;
    if (!vcs_object_store_init(repo_root) ||
        !vcs_object_put_addressed_repair(
            repo_root, record_root, record_wire, record_wire_len, &repaired))
        return false;

    char lock_path[PATH_MAX], log_path[PATH_MAX];
    bool paths = publication_queue_path(
            repo_root, "publication.lock", lock_path, sizeof(lock_path)) &&
        publication_queue_path(repo_root, "publication.receipts.log",
                               log_path, sizeof(log_path));
    int lock_fd = paths
        ? open(lock_path, O_RDWR | O_CREAT | O_CLOEXEC, 0600) : -1;
    if (lock_fd < 0 || flock(lock_fd, LOCK_EX) != 0) {
        if (lock_fd >= 0) close(lock_fd);
        return false;
    }
    struct vcs_devloop_publication_receipt current;
    uint8_t current_root[32];
    bool have_current = vcs_devloop_publication_progress_load(
        repo_root, job_root, &current, current_root);
    if (have_current && current.phase ==
            VCS_DEVLOOP_PUBLICATION_PHASE_SOURCE_REPRODUCED) {
        bool same = memcmp(current_root, observed_root, 32) == 0 &&
            memcmp(current.artifact_root, record_root, 32) == 0;
        if (same) {
            memcpy(receipt_root_out, current_root, 32);
            if (reused_out) *reused_out = true;
        }
        (void)flock(lock_fd, LOCK_UN);
        close(lock_fd);
        return same;
    }
    if (!have_current || current.phase !=
            VCS_DEVLOOP_PUBLICATION_PHASE_STORAGE_ACKNOWLEDGED ||
        memcmp(current_root, observed_root, 32) != 0) {
        (void)flock(lock_fd, LOCK_UN);
        close(lock_fd);
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
    uint8_t wire[VCS_DEV_PUBLICATION_RECEIPT_WIRE_BYTES];
    bool ok = publication_receipt_serialize(&receipt, wire) &&
        vcs_object_put(repo_root, wire, sizeof(wire),
                       VCS_TAG_PUBLICATION_RECEIPT, receipt_root_out);
    event_log_t *log = ok ? event_log_open(log_path) : NULL;
    if (ok)
        ok = log && event_log_append(
            log, EV_VCS_PUBLICATION_RECEIPT, receipt_root_out, 32) !=
            UINT64_MAX;
    if (log) event_log_close(log);
    (void)flock(lock_fd, LOCK_UN);
    close(lock_fd);
    return ok;
}

static bool publication_enqueue_from_commit(
    const char *repo_root, const struct vcs_devloop_verdict *verdict,
    const uint8_t commit_root[32], const uint8_t parent_workspace_root[32],
    struct vcs_devloop_anchor_result *out)
{
    uint8_t source_identity[32], source_cas[32];
    size_t phase_len = verdict->phase ? strlen(verdict->phase) : 0;
    size_t scope_len = verdict->proof_scope ? strlen(verdict->proof_scope) : 0;
    if (!verdict->proof_complete || phase_len == 0 ||
        strcmp(verdict->phase, "verify") != 0 || phase_len >= 24 ||
        scope_len == 0 || scope_len >= 64 ||
        !vcs_devloop_hex32_decode(verdict->source_identity_hex,
                                  source_identity) ||
        !vcs_devloop_hex32_decode(verdict->source_cas_hex, source_cas)) {
        (void)snprintf(out->publication_error,
                       sizeof(out->publication_error), "%s",
                       "complete verify proof lacks exact bounded source identity, source CAS, or proof scope");
        LOG_WARN("vcs.devloop", "publication enqueue: incomplete proof basis");
        return false;
    }
    uint8_t *commit_preimage = NULL;
    size_t commit_len = 0;
    struct vcs_commit commit;
    if (vcs_object_get(repo_root, commit_root, VCS_TAG_COMMIT,
                       &commit_preimage, &commit_len) != 0 ||
        !vcs_commit_parse_preimage(commit_preimage, commit_len, &commit)) {
        free(commit_preimage);
        (void)snprintf(out->publication_error,
                       sizeof(out->publication_error), "%s",
                       "the committed ZVCS source object could not be reloaded");
        LOG_WARN("vcs.devloop", "publication enqueue: commit reload failed");
        return false;
    }
    free(commit_preimage);

    uint8_t proof_wire[VCS_DEV_PROOF_WIRE_BYTES] = {0};
    size_t off = 0;
    memcpy(proof_wire + off, dev_proof_magic, 8); off += 8;
    zcl_write_u32_le(proof_wire + off, 1); off += 4;
    memcpy(proof_wire + off, commit_root, 32); off += 32;
    memcpy(proof_wire + off, commit.tree_hash, 32); off += 32;
    memcpy(proof_wire + off, source_identity, 32); off += 32;
    memcpy(proof_wire + off, source_cas, 32); off += 32;
    memcpy(proof_wire + off, commit.generation_sha256, 32); off += 32;
    zcl_write_u64_le(proof_wire + off,
                     verdict->elapsed_ms < 0 ? 0 :
                     (uint64_t)verdict->elapsed_ms); off += 8;
    publication_fixed((char *)proof_wire + off, 24, verdict->phase); off += 24;
    publication_fixed((char *)proof_wire + off, 64,
                      verdict->proof_scope); off += 64;
    if (off != sizeof(proof_wire) ||
        !vcs_object_put(repo_root, proof_wire, sizeof(proof_wire),
                        VCS_TAG_DEV_PROOF, out->proof_receipt_root)) {
        (void)snprintf(out->publication_error,
                       sizeof(out->publication_error), "%s",
                       "the immutable proof receipt could not be stored");
        LOG_WARN("vcs.devloop", "publication enqueue: proof store failed");
        return false;
    }

    struct vcs_devloop_publication_job job = {
        .version = VCS_DEVLOOP_PUBLICATION_JOB_VERSION,
    };
    memcpy(job.vcs_commit_root, commit_root, 32);
    memcpy(job.source_tree_root, commit.tree_hash, 32);
    memcpy(job.proof_receipt_root, out->proof_receipt_root, 32);
    memcpy(job.source_identity_sha256, source_identity, 32);
    memcpy(job.source_cas_sha3, source_cas, 32);
    memcpy(job.generation_sha256, commit.generation_sha256, 32);
    if (parent_workspace_root)
        memcpy(job.parent_workspace_root, parent_workspace_root, 32);
    uint8_t job_wire[VCS_DEV_PUBLICATION_JOB_WIRE_BYTES];
    if (!publication_job_serialize(&job, job_wire) ||
        !vcs_object_put(repo_root, job_wire, sizeof(job_wire),
                        VCS_TAG_PUBLICATION_JOB,
                        out->publication_job_root) ||
        !vcs_devloop_publication_job_requeue(
            repo_root, out->publication_job_root,
            &out->publication_reused)) {
        (void)snprintf(out->publication_error,
                       sizeof(out->publication_error), "%s",
                       "the immutable publication job could not be durably queued");
        LOG_WARN("vcs.devloop", "publication enqueue: job queue failed");
        return false;
    }
    return true;
}

static void anchor_cycle_sync(const char *repo_root,
                              const struct vcs_devloop_verdict *v,
                              struct vcs_devloop_anchor_result *out)
{
    struct vcs_repo *r = vcs_open(repo_root);
    if (!r) {
        snprintf(out->error, sizeof(out->error),
                 "vcs_open failed for repo_root=%s", repo_root);
        LOG_WARN("vcs.devloop", "anchor_cycle: vcs_open failed root=%s",
                 repo_root);
        return;
    }

    /* First-run ergonomics: a repo with no HEAD ref yet is about to take its
     * first snapshot of the whole worktree, which is the one call in the
     * hot dev-loop path that is not O(changed files). Log the one-time
     * cost rather than staying silent about it. */
    struct vcs_index *idx = vcs_repo_index(r);
    uint8_t head_probe[32];
    bool head_found = false;
    bool first_snapshot =
        idx && vcs_index_ref_get(idx, "HEAD", head_probe, &head_found) &&
        !head_found;

    uint8_t generation[32];
    memset(generation, 0, sizeof(generation));
    bool have_generation = v->generation_hex && v->generation_hex[0] &&
                          vcs_devloop_hex32_decode(v->generation_hex, generation);
    if (v->generation_hex && v->generation_hex[0] && !have_generation)
        LOG_WARN("vcs.devloop",
                 "anchor_cycle: unparsable generation hex (binding zero): %s",
                 v->generation_hex);

    struct vcs_snapshot_meta meta = {0};
    meta.verdict_status = v->verdict_status;
    meta.phase = v->phase;
    meta.elapsed_ms = v->elapsed_ms < 0 ? 0 : (uint64_t)v->elapsed_ms;
    meta.generation_sha256 = have_generation ? generation : NULL;
    meta.agent_id = v->agent_id;
    meta.session_id = v->session_id;
    meta.task_ref = v->task_ref;

    int64_t t0 = platform_time_monotonic_us();
    uint8_t commit_id[32];
    int rc = vcs_snapshot(r, &meta, commit_id);
    int64_t t1 = platform_time_monotonic_us();

    if (first_snapshot)
        LOG_INFO("vcs.devloop",
                 "anchor_cycle: first snapshot of the working tree took %lld ms",
                 (long long)((t1 - t0) / 1000));

    vcs_close(r);

    if (rc == VCS_OK) {
        out->status = VCS_DEVLOOP_ANCHOR_OK;
        memcpy(out->commit_id, commit_id, 32);
        if (v->proof_complete) {
            int64_t enqueue_started = platform_time_monotonic_us();
            bool queued = publication_enqueue_from_commit(
                repo_root, v, commit_id, NULL, out);
            out->publication_enqueue_us =
                platform_time_monotonic_us() - enqueue_started;
            out->publication_status = queued
                ? VCS_DEVLOOP_PUBLICATION_QUEUED
                : VCS_DEVLOOP_PUBLICATION_ERROR;
        }
        return;
    }
    if (rc == VCS_REFUSED) {
        out->status = VCS_DEVLOOP_ANCHOR_REFUSED;
        snprintf(out->error, sizeof(out->error),
                 "sealed-path change refused (advisory here; the dev-loop "
                 "publish already happened) — run the owner-gated unseal "
                 "ritual before the next anchor");
        LOG_WARN("vcs.devloop",
                 "anchor_cycle: sealed-path refusal (advisory; publish already happened)");
        return;
    }
    snprintf(out->error, sizeof(out->error), "vcs_snapshot failed (rc=%d)", rc);
    LOG_WARN("vcs.devloop", "anchor_cycle: vcs_snapshot failed rc=%d", rc);
}

/* Open (creating if absent) .zvcs/bootstrap.lock for the baseline
 * singleton. Returns -1 on any setup failure. Never spawns a process —
 * open()/mkdir() only (the ZVCS-sovereignty lint gate requires lib/vcs,
 * being release-linkable, to stay process-spawn free). */
static int open_bootstrap_lock(const char *repo_root, char *lock_path,
                               size_t lock_path_sz)
{
    char dir[PATH_MAX];
    int n = snprintf(dir, sizeof(dir), "%s/.zvcs", repo_root);
    if (n <= 0 || (size_t)n >= sizeof(dir) ||
        (mkdir(dir, 0700) != 0 && errno != EEXIST))
        return -1;
    n = snprintf(lock_path, lock_path_sz, "%s/bootstrap.lock", dir);
    if (n <= 0 || (size_t)n >= lock_path_sz)
        return -1;
    return open(lock_path, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
}

/* The first snapshot is generation-neutral bootstrap work: it may need to
 * durably store thousands of blobs. lib/vcs runs it synchronously in the
 * caller's own thread of control — it never forks a worker to detach it
 * (that mechanics lives in the dev-only tools/dev/devloop_baseline.c, which
 * calls THIS function from a double-forked grandchild). A singleton flock
 * still keeps two concurrent callers (in-process or across processes) from
 * racing the same baseline. */
void vcs_devloop_run_initial_baseline(const char *repo_root,
                                      struct vcs_devloop_anchor_result *out)
{
    if (!out)
        return;
    memset(out, 0, sizeof(*out));
    out->status = VCS_DEVLOOP_ANCHOR_ERROR;

    if (!repo_root || !repo_root[0]) {
        snprintf(out->error, sizeof(out->error),
                 "vcs_devloop: invalid repo_root");
        LOG_WARN("vcs.devloop", "run_initial_baseline: invalid repo_root");
        return;
    }

    char lock_path[PATH_MAX];
    int lock_fd = open_bootstrap_lock(repo_root, lock_path, sizeof(lock_path));
    if (lock_fd < 0) {
        snprintf(out->error, sizeof(out->error),
                 "could not open .zvcs/bootstrap.lock under %s", repo_root);
        LOG_WARN("vcs.devloop", "run_initial_baseline: lock open failed root=%s",
                 repo_root);
        return;
    }
    if (flock(lock_fd, LOCK_EX | LOCK_NB) != 0) {
        close(lock_fd);
        out->status = VCS_DEVLOOP_ANCHOR_DEFERRED;
        snprintf(out->error, sizeof(out->error),
                 "another caller already holds the initial ZVCS baseline lock");
        return;
    }

    struct vcs_devloop_verdict baseline = {
        .verdict_status = 0,
        .phase = "bootstrap_baseline",
        .elapsed_ms = 0,
    };
    anchor_cycle_sync(repo_root, &baseline, out);
    if (out->status == VCS_DEVLOOP_ANCHOR_OK)
        LOG_INFO("vcs.devloop", "run_initial_baseline: complete root=%s",
                 repo_root);
    else
        LOG_WARN("vcs.devloop", "run_initial_baseline: failed root=%s: %s",
                 repo_root, out->error[0] ? out->error : "unknown error");

    (void)flock(lock_fd, LOCK_UN);
    close(lock_fd);
}

static bool durable_history_present(const char *repo_root)
{
    char path[PATH_MAX];
    int n = snprintf(path, sizeof(path), "%s/.zvcs/commits.log", repo_root);
    if (n <= 0 || (size_t)n >= sizeof(path))
        return false;
    struct stat st;
    return stat(path, &st) == 0 && st.st_size > 0;
}

static bool initial_baseline_running(const char *repo_root)
{
    char path[PATH_MAX];
    int n = snprintf(path, sizeof(path), "%s/.zvcs/bootstrap.lock",
                     repo_root);
    if (n <= 0 || (size_t)n >= sizeof(path))
        return false;
    int fd = open(path, O_RDWR | O_CLOEXEC);
    if (fd < 0)
        return false;
    if (flock(fd, LOCK_EX | LOCK_NB) != 0) {
        bool running = errno == EWOULDBLOCK || errno == EAGAIN;
        close(fd);
        return running;
    }
    (void)flock(fd, LOCK_UN);
    close(fd);
    return false;
}

void vcs_devloop_anchor_cycle(const char *repo_root,
                              const struct vcs_devloop_verdict *v,
                              struct vcs_devloop_anchor_result *out)
{
    if (!out)
        return;
    memset(out, 0, sizeof(*out));
    out->status = VCS_DEVLOOP_ANCHOR_ERROR;

    if (!repo_root || !repo_root[0] || !v) {
        snprintf(out->error, sizeof(out->error),
                 "vcs_devloop: invalid arguments (repo_root or verdict is NULL)");
        LOG_WARN("vcs.devloop", "anchor_cycle: invalid arguments");
        return;
    }

    if (v->defer_initial_snapshot && initial_baseline_running(repo_root)) {
        out->status = VCS_DEVLOOP_ANCHOR_DEFERRED;
        out->baseline_needed = false;
        snprintf(out->error, sizeof(out->error),
                 "generation-neutral initial ZVCS baseline is still building; this cycle is unanchored");
        return;
    }

    if (v->defer_initial_snapshot && !durable_history_present(repo_root)) {
        /* lib/vcs never launches the baseline itself (the ZVCS-sovereignty
         * lint gate forbids fork/exec here). Report that one is REQUIRED
         * and leave this cycle unanchored; the caller runs it —
         * synchronously via vcs_devloop_run_initial_baseline(), or detached
         * via the dev-only launcher in tools/dev/devloop_baseline.c. */
        out->status = VCS_DEVLOOP_ANCHOR_DEFERRED;
        out->baseline_needed = true;
        snprintf(out->error, sizeof(out->error),
                 "generation-neutral initial ZVCS baseline required; this cycle is unanchored");
        return;
    }

    anchor_cycle_sync(repo_root, v, out);
}

struct accepted_candidate_queue_scan {
    uint8_t (*roots)[32];
    size_t count;
    size_t cap;
    bool overflow;
};

static bool accepted_candidate_queue_scan_cb(
    uint64_t offset, enum event_log_type type, const void *payload, size_t len,
    void *user)
{
    (void)offset;
    struct accepted_candidate_queue_scan *scan = user;
    if (type != EV_VCS_PUBLICATION_JOB || len != 32 || !payload)
        return true;
    if (scan->count >= scan->cap) {
        scan->overflow = true;
        return false;
    }
    memcpy(scan->roots[scan->count++], payload, 32);
    return true;
}

static void accepted_candidate_fail(
    struct vcs_devloop_accepted_candidate_result *out, const char *detail)
{
    (void)snprintf(out->error, sizeof(out->error), "%s", detail);
    LOG_WARN("vcs.devloop", "accepted candidate publication: %s", detail);
}

static bool accepted_candidate_existing_job(
    const char *workspace, const uint8_t source_root[32],
    const uint8_t accepted_work_root[32], int64_t now_unix,
    struct vcs_devloop_accepted_candidate_result *out)
{
    char path[PATH_MAX];
    if (!publication_queue_path(workspace, "publication.log", path,
                                sizeof(path)))
        return false;
    struct stat st;
    if (stat(path, &st) != 0)
        return errno == ENOENT;
    uint8_t (*roots)[32] = zcl_calloc(
        VCS_DEV_PUBLICATION_PROGRESS_MAX, sizeof(*roots),
        "accepted_candidate_queue_roots");
    if (!roots) {
        accepted_candidate_fail(out, "publication queue scan allocation failed");
        return false;
    }
    event_log_t *log = event_log_open(path);
    struct accepted_candidate_queue_scan scan = {
        .roots = roots, .cap = VCS_DEV_PUBLICATION_PROGRESS_MAX,
    };
    bool scanned = log && event_log_stream(
        log, 0, accepted_candidate_queue_scan_cb, &scan) == 0 &&
        !scan.overflow;
    if (log) event_log_close(log);
    if (!scanned) {
        free(roots);
        accepted_candidate_fail(out, "publication queue is corrupt or over budget");
        return false;
    }
    for (size_t i = 0; i < scan.count; i++) {
        struct vcs_devloop_publication_job job;
        if (!vcs_devloop_publication_job_load(workspace, roots[i], &job) ||
            memcmp(job.source_tree_root, source_root, 32) != 0)
            continue;
        uint8_t waiting_root[32], progress_root[32];
        bool waiting_reused = false, proven_reused = false;
        if (!vcs_devloop_publication_advance_waiting_acceptance(
                workspace, roots[i], waiting_root, &waiting_reused) ||
            !vcs_devloop_publication_advance_proven_work(
                workspace, roots[i], accepted_work_root, now_unix,
                progress_root, &proven_reused))
            continue;
        (void)waiting_reused;
        memcpy(out->source_tree_root, job.source_tree_root, 32);
        memcpy(out->vcs_commit_root, job.vcs_commit_root, 32);
        memcpy(out->proof_receipt_root, job.proof_receipt_root, 32);
        memcpy(out->publication_job_root, roots[i], 32);
        memcpy(out->publication_progress_root, progress_root, 32);
        out->reused = true;
        free(roots);
        return true;
    }
    free(roots);
    return true;
}

void vcs_devloop_publication_bind_accepted_candidate(
    const char *authority_workspace, const char *candidate_workspace,
    const uint8_t accepted_work_root[32],
    const uint8_t expected_source_root[32], int64_t now_unix,
    struct vcs_devloop_accepted_candidate_result *out)
{
    if (!out) return;
    memset(out, 0, sizeof(*out));
    if (!authority_workspace || !authority_workspace[0] ||
        !candidate_workspace || !candidate_workspace[0] ||
        !accepted_work_root || !expected_source_root || now_unix <= 0) {
        accepted_candidate_fail(out, "invalid accepted candidate binding input");
        return;
    }

    uint8_t actual_source_root[32];
    if (vcs_tree_capture_path(candidate_workspace, actual_source_root) !=
            VCS_OK ||
        memcmp(actual_source_root, expected_source_root, 32) != 0) {
        accepted_candidate_fail(out,
            "retained candidate source no longer matches the accepted source root");
        return;
    }
    uint8_t *bundle = NULL;
    size_t bundle_len = 0;
    struct vcs_zcode_accepted_work_v1 exported, imported;
    enum vcs_zcode_accepted_work_bundle_result bundle_result =
        vcs_zcode_accepted_work_bundle_export(
            authority_workspace, accepted_work_root, now_unix,
            &bundle, &bundle_len, &exported);
    if (bundle_result != VCS_ZCODE_ACCEPTED_WORK_BUNDLE_OK ||
        memcmp(exported.candidate.candidate_source_root,
               expected_source_root, 32) != 0) {
        free(bundle);
        accepted_candidate_fail(out,
            "accepted-work authority does not bind the retained candidate source");
        return;
    }
    bundle_result = vcs_zcode_accepted_work_bundle_import(
        candidate_workspace, accepted_work_root, expected_source_root,
        bundle, bundle_len, &imported, &out->imported_objects,
        &out->imported_work_receipts);
    free(bundle);
    if (bundle_result != VCS_ZCODE_ACCEPTED_WORK_BUNDLE_OK ||
        memcmp(imported.accepted_work_root, accepted_work_root, 32) != 0) {
        accepted_candidate_fail(out,
            "accepted-work authority bundle failed independent import verification");
        return;
    }

    if (!accepted_candidate_existing_job(
            authority_workspace, expected_source_root, accepted_work_root,
            now_unix, out))
        return;
    if (out->reused) {
        out->ok = true;
        return;
    }

    struct vcs_manifest manifest;
    uint8_t *manifest_wire = NULL;
    size_t manifest_len = 0;
    if (!vcs_tree_load(candidate_workspace, expected_source_root, &manifest)) {
        accepted_candidate_fail(out, "accepted candidate manifest could not be reloaded");
        return;
    }
    bool serialized = vcs_manifest_serialize(
        &manifest, &manifest_wire, &manifest_len);
    vcs_manifest_free(&manifest);
    if (!serialized) {
        accepted_candidate_fail(out, "accepted candidate manifest could not be serialized");
        return;
    }
    uint8_t source_identity[32];
    vcs_source_manifest_id(manifest_wire, manifest_len, source_identity);
    free(manifest_wire);
    char source_identity_hex[65], source_cas_hex[65];
    zcl_hex_encode(source_identity, 32, source_identity_hex);
    zcl_hex_encode(expected_source_root, 32, source_cas_hex);
    uint8_t parent_workspace_root[32];
    if (vcs_tree_capture_into(candidate_workspace, authority_workspace,
                              actual_source_root) != VCS_OK ||
        memcmp(actual_source_root, expected_source_root, 32) != 0 ||
        vcs_tree_capture_path(authority_workspace, parent_workspace_root) !=
            VCS_OK) {
        accepted_candidate_fail(out,
            "candidate and unchanged parent source could not enter the publication CAS");
        return;
    }
    char accepted_hex[65];
    zcl_hex_encode(accepted_work_root, 32, accepted_hex);
    struct vcs_commit detached = {
        .version = VCS_COMMIT_VERSION,
        .verdict_status = 0,
        .elapsed_ms = 0,
        .committed_at = now_unix,
    };
    memcpy(detached.tree_hash, expected_source_root, 32);
    (void)snprintf(detached.phase, sizeof(detached.phase), "%s", "verify");
    (void)snprintf(detached.task_ref, sizeof(detached.task_ref), "%s",
                   accepted_hex);
    uint8_t commit_preimage[VCS_COMMIT_PREIMAGE_BYTES];
    uint8_t commit_root[32];
    if (!vcs_commit_preimage(&detached, commit_preimage) ||
        !vcs_object_put(authority_workspace, commit_preimage,
                        sizeof(commit_preimage), VCS_TAG_COMMIT, commit_root)) {
        accepted_candidate_fail(out,
            "detached accepted candidate commit could not enter the publication CAS");
        return;
    }
    struct vcs_devloop_verdict verdict = {
        .verdict_status = 0,
        .phase = "verify",
        .elapsed_ms = 0,
        .proof_complete = true,
        .proof_scope = "accepted_work_proof_policy",
        .source_identity_hex = source_identity_hex,
        .source_cas_hex = source_cas_hex,
    };
    struct vcs_devloop_anchor_result anchor = {0};
    struct vcs_devloop_publication_job job;
    bool queued = publication_enqueue_from_commit(
        authority_workspace, &verdict, commit_root, parent_workspace_root,
        &anchor);
    anchor.publication_status = queued
        ? VCS_DEVLOOP_PUBLICATION_QUEUED
        : VCS_DEVLOOP_PUBLICATION_ERROR;
    if (!queued ||
        !vcs_devloop_publication_job_load(
            authority_workspace, anchor.publication_job_root, &job) ||
        memcmp(job.source_tree_root, expected_source_root, 32) != 0 ||
        memcmp(job.parent_workspace_root, parent_workspace_root, 32) != 0) {
        accepted_candidate_fail(out, anchor.publication_error[0]
            ? anchor.publication_error
            : anchor.error[0] ? anchor.error
            : "accepted candidate publication job could not be queued");
        return;
    }
    uint8_t waiting_root[32], progress_root[32];
    bool waiting_reused = false, proven_reused = false;
    if (!vcs_devloop_publication_advance_waiting_acceptance(
            authority_workspace, anchor.publication_job_root,
            waiting_root, &waiting_reused) ||
        !vcs_devloop_publication_advance_proven_work(
            authority_workspace, anchor.publication_job_root,
            accepted_work_root, now_unix, progress_root, &proven_reused)) {
        accepted_candidate_fail(out,
            "publication job refused the independently verified accepted-work root");
        return;
    }
    (void)waiting_root;
    (void)waiting_reused;
    (void)proven_reused;
    memcpy(out->source_tree_root, job.source_tree_root, 32);
    memcpy(out->vcs_commit_root, job.vcs_commit_root, 32);
    memcpy(out->proof_receipt_root, job.proof_receipt_root, 32);
    memcpy(out->publication_job_root, anchor.publication_job_root, 32);
    memcpy(out->publication_progress_root, progress_root, 32);
    out->ok = true;
}
