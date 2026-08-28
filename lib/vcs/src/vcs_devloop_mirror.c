/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Persist optional mirror receipts derived from P2P publication. */

#include "vcs/vcs_devloop_mirror.h"

#include "vcs/vcs_devloop.h"
#include "vcs/vcs_object.h"
#include "vcs_priv.h"

#include "base/serialize_le.h"
#include "storage/event_log.h"
#include "util/log_macros.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef _WIN32
#include <sys/file.h>
#endif
#include <sys/stat.h>
#include <unistd.h>

#define VCS_DEVLOOP_MIRROR_WIRE_BYTES 269u
#define VCS_DEVLOOP_MIRROR_LOG_MAX 4096u
#define VCS_DEVLOOP_MIRROR_LOG_RECORD_BYTES 64u
#define VCS_DEVLOOP_MIRROR_LOG_MAX_BYTES \
    (VCS_DEVLOOP_MIRROR_LOG_MAX * VCS_DEVLOOP_MIRROR_LOG_RECORD_BYTES)

static const uint8_t mirror_magic[8] = {'Z','M','R','R','1',0,0,0};

static bool mirror_root_nonzero(const uint8_t root[32])
{
    uint8_t any = 0;
    if (!root) return false;
    for (size_t i = 0; i < 32; i++) any |= root[i];
    return any != 0;
}

static bool mirror_receipt_serialize(
    const struct vcs_devloop_mirror_receipt *receipt,
    uint8_t wire[VCS_DEVLOOP_MIRROR_WIRE_BYTES])
{
    if (!receipt || !wire ||
        receipt->version != VCS_DEVLOOP_MIRROR_RECEIPT_VERSION ||
        !mirror_root_nonzero(receipt->job_root) ||
        !mirror_root_nonzero(receipt->vcs_commit_root) ||
        !mirror_root_nonzero(receipt->source_identity_sha256) ||
        !mirror_root_nonzero(receipt->proof_receipt_root) ||
        !mirror_root_nonzero(receipt->release_root) ||
        !mirror_root_nonzero(receipt->workspace_root) ||
        !mirror_root_nonzero(receipt->provider_record_root) ||
        (receipt->git_oid_len != 0 && receipt->git_oid_len != 20 &&
         receipt->git_oid_len != 32))
        return false;
    for (size_t i = receipt->git_oid_len;
         i < VCS_DEVLOOP_MIRROR_OID_MAX_BYTES; i++) {
        if (receipt->git_oid[i] != 0)
            return false;
    }
    size_t off = 0;
    memcpy(wire + off, mirror_magic, sizeof(mirror_magic)); off += 8;
    zcl_write_u32_le(wire + off, receipt->version); off += 4;
    memcpy(wire + off, receipt->job_root, 32); off += 32;
    memcpy(wire + off, receipt->vcs_commit_root, 32); off += 32;
    memcpy(wire + off, receipt->source_identity_sha256, 32); off += 32;
    memcpy(wire + off, receipt->proof_receipt_root, 32); off += 32;
    memcpy(wire + off, receipt->release_root, 32); off += 32;
    memcpy(wire + off, receipt->workspace_root, 32); off += 32;
    memcpy(wire + off, receipt->provider_record_root, 32); off += 32;
    wire[off++] = receipt->git_oid_len;
    memcpy(wire + off, receipt->git_oid,
           VCS_DEVLOOP_MIRROR_OID_MAX_BYTES);
    off += VCS_DEVLOOP_MIRROR_OID_MAX_BYTES;
    return off == VCS_DEVLOOP_MIRROR_WIRE_BYTES;
}

static bool mirror_receipt_parse(
    const uint8_t *wire, size_t wire_len,
    struct vcs_devloop_mirror_receipt *out)
{
    if (!wire || !out || wire_len != VCS_DEVLOOP_MIRROR_WIRE_BYTES ||
        memcmp(wire, mirror_magic, sizeof(mirror_magic)) != 0)
        return false;
    struct vcs_devloop_mirror_receipt parsed = {0};
    size_t off = 8;
    parsed.version = zcl_read_u32_le(wire + off); off += 4;
    memcpy(parsed.job_root, wire + off, 32); off += 32;
    memcpy(parsed.vcs_commit_root, wire + off, 32); off += 32;
    memcpy(parsed.source_identity_sha256, wire + off, 32); off += 32;
    memcpy(parsed.proof_receipt_root, wire + off, 32); off += 32;
    memcpy(parsed.release_root, wire + off, 32); off += 32;
    memcpy(parsed.workspace_root, wire + off, 32); off += 32;
    memcpy(parsed.provider_record_root, wire + off, 32); off += 32;
    parsed.git_oid_len = wire[off++];
    memcpy(parsed.git_oid, wire + off, VCS_DEVLOOP_MIRROR_OID_MAX_BYTES);
    off += VCS_DEVLOOP_MIRROR_OID_MAX_BYTES;
    uint8_t checked[VCS_DEVLOOP_MIRROR_WIRE_BYTES];
    if (off != wire_len || !mirror_receipt_serialize(&parsed, checked) ||
        memcmp(checked, wire, wire_len) != 0)
        return false;
    *out = parsed;
    return true;
}

bool vcs_devloop_mirror_receipt_load(
    const char *repo_root, const uint8_t receipt_root[32],
    struct vcs_devloop_mirror_receipt *out)
{
    if (!repo_root || !repo_root[0] || !receipt_root || !out)
        return false;
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    if (vcs_object_load_raw_bounded(
            repo_root, receipt_root, VCS_DEVLOOP_MIRROR_WIRE_BYTES,
            &wire, &wire_len) != 0)
        return false;
    uint8_t derived[32];
    vcs_sha3_tag(VCS_TAG_DEV_MIRROR_RECEIPT, wire, wire_len, derived);
    bool ok = memcmp(derived, receipt_root, 32) == 0 &&
        mirror_receipt_parse(wire, wire_len, out);
    free(wire);
    return ok;
}

#ifndef _WIN32
static bool mirror_path(const char *repo_root, const char *leaf,
                        char out[PATH_MAX])
{
    int n = repo_root && leaf
        ? snprintf(out, PATH_MAX, "%s/.zvcs/%s", repo_root, leaf) : -1;
    return n > 0 && n < PATH_MAX;
}

struct mirror_scan {
    const char *repo_root;
    const uint8_t *job_root;
    uint32_t count;
    bool found;
    bool invalid;
    uint8_t receipt_root[32];
    struct vcs_devloop_mirror_receipt receipt;
};

static bool mirror_scan_cb(uint64_t offset, enum event_log_type type,
                           const void *payload, size_t len, void *user)
{
    (void)offset;
    struct mirror_scan *scan = user;
    if (++scan->count > VCS_DEVLOOP_MIRROR_LOG_MAX ||
        type != EV_VCS_DEV_MIRROR_RECEIPT || !payload || len != 32) {
        scan->invalid = true;
        return false;
    }
    struct vcs_devloop_mirror_receipt receipt;
    if (!vcs_devloop_mirror_receipt_load(
            scan->repo_root, payload, &receipt)) {
        scan->invalid = true;
        return false;
    }
    if (memcmp(receipt.job_root, scan->job_root, 32) != 0)
        return true;
    if (scan->found && memcmp(scan->receipt_root, payload, 32) != 0) {
        scan->invalid = true;
        return false;
    }
    scan->found = true;
    memcpy(scan->receipt_root, payload, 32);
    scan->receipt = receipt;
    return true;
}

static bool mirror_scan_log(const char *repo_root, const uint8_t job_root[32],
                            struct mirror_scan *scan)
{
    char path[PATH_MAX];
    struct stat st;
    if (!mirror_path(repo_root, "publication.mirrors.log", path) ||
        stat(path, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size < 0 ||
        (uint64_t)st.st_size > VCS_DEVLOOP_MIRROR_LOG_MAX_BYTES)
        return false;
    *scan = (struct mirror_scan) {
        .repo_root = repo_root,
        .job_root = job_root,
    };
    event_log_t *log = event_log_open(path);
    bool ok = log && event_log_stream(log, 0, mirror_scan_cb, scan) == 0;
    if (log) event_log_close(log);
    return ok && !scan->invalid;
}

enum vcs_devloop_mirror_lookup vcs_devloop_mirror_load_for_job(
    const char *repo_root, const uint8_t job_root[32],
    struct vcs_devloop_mirror_receipt *out,
    uint8_t receipt_root_out[32])
{
    if (!repo_root || !repo_root[0] || !job_root || !out ||
        !receipt_root_out)
        return VCS_DEVLOOP_MIRROR_INVALID;
#ifdef _WIN32
    /* The event-log snapshot and its lock must be bound to retained handles;
     * a pathname-only emulation could mix generations during publication. */
    return VCS_DEVLOOP_MIRROR_INVALID;
#else
    char path[PATH_MAX], lock_path[PATH_MAX];
    struct stat st;
    if (!mirror_path(repo_root, "publication.mirrors.log", path) ||
        !mirror_path(repo_root, "publication.mirrors.lock", lock_path))
        return VCS_DEVLOOP_MIRROR_INVALID;
    if (stat(path, &st) != 0)
        return errno == ENOENT ? VCS_DEVLOOP_MIRROR_ABSENT
                               : VCS_DEVLOOP_MIRROR_INVALID;
    int lock_fd = open(lock_path, O_RDONLY | O_CLOEXEC);
    if (lock_fd < 0 || flock(lock_fd, LOCK_SH) != 0) {
        if (lock_fd >= 0) close(lock_fd);
        return VCS_DEVLOOP_MIRROR_INVALID;
    }
    struct mirror_scan scan;
    bool valid = mirror_scan_log(repo_root, job_root, &scan);
    (void)flock(lock_fd, LOCK_UN);
    close(lock_fd);
    if (!valid)
        return VCS_DEVLOOP_MIRROR_INVALID;
    if (!scan.found)
        return VCS_DEVLOOP_MIRROR_ABSENT;
    *out = scan.receipt;
    memcpy(receipt_root_out, scan.receipt_root, 32);
    return VCS_DEVLOOP_MIRROR_FOUND;
#endif
}

static bool mirror_build_from_provider(
    const char *repo_root, const uint8_t job_root[32],
    const uint8_t *git_oid, size_t git_oid_len,
    struct vcs_devloop_mirror_receipt *out)
{
    if (git_oid_len != 0 && git_oid_len != 20 && git_oid_len != 32)
        return false;
    if (git_oid_len > 0 && !git_oid)
        return false;
    struct vcs_devloop_publication_job job;
    struct vcs_devloop_publication_receipt provider, workspace, passport;
    struct vcs_devloop_publication_receipt release;
    uint8_t provider_progress_root[32];
    if (!vcs_devloop_publication_job_is_queued(repo_root, job_root) ||
        !vcs_devloop_publication_job_load(repo_root, job_root, &job) ||
        !vcs_devloop_publication_progress_load(
            repo_root, job_root, &provider, provider_progress_root) ||
        provider.phase != VCS_DEVLOOP_PUBLICATION_PHASE_PROVIDER_ANNOUNCED ||
        memcmp(provider.job_root, job_root, 32) != 0 ||
        !vcs_devloop_publication_receipt_load(
            repo_root, provider.predecessor_receipt_root, &workspace) ||
        workspace.phase != VCS_DEVLOOP_PUBLICATION_PHASE_WORKSPACE_PUBLISHED ||
        memcmp(workspace.job_root, job_root, 32) != 0 ||
        !vcs_devloop_publication_receipt_load(
            repo_root, workspace.predecessor_receipt_root, &passport) ||
        passport.phase != VCS_DEVLOOP_PUBLICATION_PHASE_PASSPORT_PUBLISHED ||
        memcmp(passport.job_root, job_root, 32) != 0 ||
        !vcs_devloop_publication_receipt_load(
            repo_root, passport.predecessor_receipt_root, &release) ||
        release.phase != VCS_DEVLOOP_PUBLICATION_PHASE_RELEASE_PUBLISHED ||
        memcmp(release.job_root, job_root, 32) != 0)
        return false;
    *out = (struct vcs_devloop_mirror_receipt) {
        .version = VCS_DEVLOOP_MIRROR_RECEIPT_VERSION,
        .git_oid_len = (uint8_t)git_oid_len,
    };
    memcpy(out->job_root, job_root, 32);
    memcpy(out->vcs_commit_root, job.vcs_commit_root, 32);
    memcpy(out->source_identity_sha256, job.source_identity_sha256, 32);
    memcpy(out->proof_receipt_root, job.proof_receipt_root, 32);
    memcpy(out->release_root, release.artifact_root, 32);
    memcpy(out->workspace_root, workspace.artifact_root, 32);
    memcpy(out->provider_record_root, provider.artifact_root, 32);
    if (git_oid_len > 0)
        memcpy(out->git_oid, git_oid, git_oid_len);
    return true;
}
#endif

bool vcs_devloop_mirror_record(
    const char *repo_root, const uint8_t job_root[32],
    const uint8_t *git_oid, size_t git_oid_len,
    uint8_t receipt_root_out[32], bool *reused_out)
{
    if (reused_out) *reused_out = false;
    if (!repo_root || !repo_root[0] || !job_root || !receipt_root_out)
        return false;
#ifdef _WIN32
    (void)git_oid;
    (void)git_oid_len;
    /* Refuse before object publication or log mutation until a retained-root
     * cross-process lock and atomic event-log transaction are qualified. */
    return false;
#else
    struct vcs_devloop_mirror_receipt receipt;
    uint8_t wire[VCS_DEVLOOP_MIRROR_WIRE_BYTES];
    if (!mirror_build_from_provider(
            repo_root, job_root, git_oid, git_oid_len, &receipt) ||
        !mirror_receipt_serialize(&receipt, wire) ||
        !vcs_object_put(repo_root, wire, sizeof(wire),
                        VCS_TAG_DEV_MIRROR_RECEIPT, receipt_root_out))
        return false;
    char lock_path[PATH_MAX], log_path[PATH_MAX];
    if (!mirror_path(repo_root, "publication.mirrors.lock", lock_path) ||
        !mirror_path(repo_root, "publication.mirrors.log", log_path))
        return false;
    int lock_fd = open(lock_path, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
    if (lock_fd < 0 || flock(lock_fd, LOCK_EX) != 0) {
        if (lock_fd >= 0) close(lock_fd);
        return false;
    }
    struct stat st;
    struct mirror_scan scan = {0};
    bool log_exists = stat(log_path, &st) == 0;
    bool ok = !log_exists || mirror_scan_log(repo_root, job_root, &scan);
    if (ok && scan.found) {
        ok = memcmp(scan.receipt_root, receipt_root_out, 32) == 0;
        if (ok && reused_out) *reused_out = true;
    } else if (ok) {
        event_log_t *log = event_log_open(log_path);
        ok = log && event_log_append(
            log, EV_VCS_DEV_MIRROR_RECEIPT, receipt_root_out, 32) !=
            UINT64_MAX;
        if (log) event_log_close(log);
    }
    (void)flock(lock_fd, LOCK_UN);
    close(lock_fd);
    if (!ok)
        LOG_WARN("vcs.devloop.mirror",
                 "mirror receipt append or exact retry validation failed");
    return ok;
#endif
}
