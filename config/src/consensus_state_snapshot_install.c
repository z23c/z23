/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Contained admission preview for zcl.consensus_state_bundle.v1. */

#include "config/consensus_state_snapshot_install.h"

#include "config/consensus_state_bundle_validate.h"
#include "config/consensus_state_install_verify_receipt.h"
#include "config/consensus_state_producer_receipt.h"
#include "consensus_state_snapshot_install_internal.h"
#include "core/utiltime.h"
#include "crypto/sha3.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"
#include "util/sync.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <sqlite3.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define INSTALL_SUBSYS "consensus_bundle_install"

struct consensus_state_artifact_evidence {
    zcl_mutex_t mutex;
    int artifact_fd;
    sqlite3 *bundle_db;
    struct stat identity;
    struct consensus_state_bundle_manifest manifest;
    uint8_t file_digest[32];
    uint8_t receipt_digest[32];
};

static bool descriptor_identity_unchanged(int fd,
                                          const struct stat *before);

static void digest_u64(struct sha3_256_ctx *ctx, uint64_t value)
{
    uint8_t encoded[8];
    for (size_t i = 0; i < sizeof(encoded); i++)
        encoded[i] = (uint8_t)(value >> (8u * i));
    sha3_256_write(ctx, encoded, sizeof(encoded));
}

static bool descriptor_file_digest(int fd, const struct stat *identity,
                                   uint8_t out[32])
{
    if (fd < 0 || !identity || !out || identity->st_size < 0)
        return false;
    uint8_t buffer[64u * 1024u];
    off_t offset = 0;
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    while (offset < identity->st_size) {
        size_t want = sizeof(buffer);
        off_t remaining = identity->st_size - offset;
        if (remaining < (off_t)want)
            want = (size_t)remaining;
        ssize_t got = pread(fd, buffer, want, offset);
        if (got < 0 && errno == EINTR)
            continue;
        if (got <= 0)
            return false;
        sha3_256_write(&ctx, buffer, (size_t)got);
        offset += got;
    }
    sha3_256_finalize(&ctx, out);
    return descriptor_identity_unchanged(fd, identity);
}

static void artifact_receipt_digest_build(
    const struct consensus_state_artifact_evidence *evidence,
    uint8_t out[32])
{
    static const char domain[] =
        CONSENSUS_STATE_BUNDLE_SCHEMA "/validation-receipt";
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    sha3_256_write(&ctx, (const uint8_t *)domain, sizeof(domain));
    sha3_256_write(&ctx, evidence->manifest.artifact_digest, 32);
    sha3_256_write(&ctx, evidence->file_digest, 32);
    digest_u64(&ctx, (uint64_t)evidence->identity.st_dev);
    digest_u64(&ctx, (uint64_t)evidence->identity.st_ino);
    digest_u64(&ctx, (uint64_t)evidence->identity.st_size);
    digest_u64(&ctx, (uint64_t)evidence->identity.st_mode);
    digest_u64(&ctx, (uint64_t)evidence->identity.st_mtim.tv_sec);
    digest_u64(&ctx, (uint64_t)evidence->identity.st_mtim.tv_nsec);
    digest_u64(&ctx, (uint64_t)evidence->identity.st_ctim.tv_sec);
    digest_u64(&ctx, (uint64_t)evidence->identity.st_ctim.tv_nsec);
    sha3_256_finalize(&ctx, out);
}

static bool install_fail(struct consensus_state_install_result *result,
                         enum consensus_state_install_status status,
                         const char *fmt, ...)
{
    char reason[192];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(reason, sizeof(reason), fmt, ap);
    va_end(ap);
    if (result) {
        result->status = status;
        snprintf(result->reason, sizeof(result->reason), "%s", reason);
    }
    LOG_WARN(INSTALL_SUBSYS, "%s", reason);
    return false;
}

static bool immutable_regular_file_open(const char *path, int *out_fd,
                                        struct stat *identity)
{
    if (out_fd)
        *out_fd = -1;
    if (!path || !path[0] || !out_fd || !identity) {
        LOG_WARN(INSTALL_SUBSYS, "bundle path/output is missing");
        return false;
    }
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        LOG_WARN(INSTALL_SUBSYS, "bundle descriptor open failed: %s",
                 strerror(errno));
        return false;
    }
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        LOG_WARN(INSTALL_SUBSYS, "bundle descriptor is not a regular file");
        close(fd);
        return false;
    }
    if ((st.st_mode & (S_IWUSR | S_IWGRP | S_IWOTH)) != 0) {
        LOG_WARN(INSTALL_SUBSYS,
                 "bundle is writable; immutable admission refused path=%s", path);
        close(fd);
        return false;
    }
    *identity = st;
    *out_fd = fd;
    return true;
}

static bool descriptor_identity_unchanged(int fd, const struct stat *before)
{
    struct stat after;
    return fd >= 0 && before && fstat(fd, &after) == 0 &&
           S_ISREG(after.st_mode) &&
           before->st_dev == after.st_dev && before->st_ino == after.st_ino &&
           before->st_size == after.st_size &&
           before->st_mode == after.st_mode &&
           before->st_mtim.tv_sec == after.st_mtim.tv_sec &&
           before->st_mtim.tv_nsec == after.st_mtim.tv_nsec &&
           before->st_ctim.tv_sec == after.st_ctim.tv_sec &&
           before->st_ctim.tv_nsec == after.st_ctim.tv_nsec;
}

static bool sidecars_absent(const char *path)
{
    static const char *const suffixes[] = {"-wal", "-shm", "-journal"};
    char candidate[PATH_MAX + 16];
    for (size_t i = 0; i < sizeof(suffixes) / sizeof(suffixes[0]); i++) {
        int n = snprintf(candidate, sizeof(candidate), "%s%s", path,
                         suffixes[i]);
        if (n <= 0 || (size_t)n >= sizeof(candidate))
            LOG_FAIL(INSTALL_SUBSYS, "bundle sidecar path too long");
        struct stat st;
        errno = 0;
        if (lstat(candidate, &st) == 0 || errno != ENOENT) {
            LOG_WARN(INSTALL_SUBSYS,
                     "bundle sidecar present or unreadable path=%s", candidate);
            return false;
        }
    }
    return true;
}

static bool open_bundle_descriptor(int artifact_fd, sqlite3 **bundle_db)
{
    char uri[96];
    int n = snprintf(uri, sizeof(uri),
                     "file:/proc/self/fd/%d?mode=ro&immutable=1", artifact_fd);
    if (n <= 0 || (size_t)n >= sizeof(uri))
        LOG_FAIL(INSTALL_SUBSYS, "bundle URI too long");
    int rc = sqlite3_open_v2(uri, bundle_db,
                             SQLITE_OPEN_READONLY | SQLITE_OPEN_URI |
                                 SQLITE_OPEN_NOMUTEX,
                             NULL);
    if (rc != SQLITE_OK)
        LOG_WARN(INSTALL_SUBSYS, "bundle open failed: %s",
                 *bundle_db ? sqlite3_errmsg(*bundle_db) : "no handle");
    if (rc != SQLITE_OK)
        return false;
    int defensive = 0;
    int trusted = 1;
    if (sqlite3_db_config(*bundle_db, SQLITE_DBCONFIG_DEFENSIVE, 1,
                          &defensive) != SQLITE_OK ||
        sqlite3_db_config(*bundle_db, SQLITE_DBCONFIG_TRUSTED_SCHEMA, 0,
                          &trusted) != SQLITE_OK ||
        defensive != 1 || trusted != 0 ||
        sqlite3_exec(*bundle_db, "PRAGMA query_only=ON", NULL, NULL, NULL) !=
            SQLITE_OK) {
        LOG_WARN(INSTALL_SUBSYS, "bundle SQLite hardening failed");
        return false;
    }
    (void)sqlite3_limit(*bundle_db, SQLITE_LIMIT_LENGTH, 2000000);
    (void)sqlite3_limit(*bundle_db, SQLITE_LIMIT_SQL_LENGTH, 65536);
    (void)sqlite3_limit(*bundle_db, SQLITE_LIMIT_COLUMN, 64);
    if (sqlite3_exec(*bundle_db, "BEGIN", NULL, NULL, NULL) != SQLITE_OK) {
        LOG_WARN(INSTALL_SUBSYS, "bundle read transaction begin failed: %s",
                 sqlite3_errmsg(*bundle_db));
        return false;
    }
    return true;
}

static void artifact_evidence_discard(
    struct consensus_state_artifact_evidence *evidence)
{
    if (!evidence)
        return;
    zcl_mutex_lock(&evidence->mutex);
    if (evidence->bundle_db) {
        (void)sqlite3_exec(evidence->bundle_db, "ROLLBACK", NULL, NULL, NULL);
        if (sqlite3_close(evidence->bundle_db) != SQLITE_OK)
            LOG_WARN(INSTALL_SUBSYS, "bundle evidence close failed");
    }
    if (evidence->artifact_fd >= 0 && close(evidence->artifact_fd) != 0)
        LOG_WARN(INSTALL_SUBSYS, "bundle evidence descriptor close failed: %s",
                 strerror(errno));
    zcl_mutex_unlock(&evidence->mutex);
    zcl_mutex_destroy(&evidence->mutex);
    free(evidence);
}

static struct zcl_result artifact_evidence_open_impl(
    const char *bundle_path, int datadir_fd,
    enum consensus_state_install_failpoint requested_failpoint,
    struct consensus_state_install_result *legacy_result,
    struct consensus_state_artifact_evidence **out)
{
    if (out)
        *out = NULL;
    if (!bundle_path || !out)
        return ZCL_ERR(-1, "artifact evidence: null path/output");
    if (requested_failpoint < CONSENSUS_INSTALL_FAIL_NONE ||
        requested_failpoint > CONSENSUS_INSTALL_FAIL_AFTER_BUNDLE_VALIDATE)
        return ZCL_ERR(-2, "artifact evidence: invalid failpoint=%d",
                       (int)requested_failpoint);

    struct consensus_state_artifact_evidence *evidence = zcl_malloc(
        sizeof(*evidence), "consensus state artifact evidence");
    if (!evidence)
        return ZCL_ERR(-3, "artifact evidence: allocation failed");
    memset(evidence, 0, sizeof(*evidence));
    zcl_mutex_init(&evidence->mutex);
    evidence->artifact_fd = -1;

    if (!immutable_regular_file_open(bundle_path, &evidence->artifact_fd,
                                     &evidence->identity) ||
        !sidecars_absent(bundle_path)) {
        artifact_evidence_discard(evidence);
        return ZCL_ERR(-4, "artifact evidence: bundle is not immutable/finalized");
    }
    if (!descriptor_file_digest(evidence->artifact_fd, &evidence->identity,
                                evidence->file_digest)) {
        artifact_evidence_discard(evidence);
        return ZCL_ERR(-5, "artifact evidence: initial complete-file hash failed");
    }

    /* Install-verify receipt: a prior full content verify of this exact
     * bundle SHA3-256 under this exact verifying binary's build epoch lets
     * the O(bundle-size) deep scan below be skipped. Admission (chain
     * binding, CAS, guards) is untouched — this only decides how much of
     * consensus_state_bundle_validate_ex() runs; the cheap structural checks
     * always run. Any failure to compute the epoch (unstamped build) or find
     * a matching receipt fails soft to a full verify. */
    bool skip_deep_scan = false;
    uint8_t verifier_epoch[32];
    bool have_epoch =
        consensus_state_producer_receipt_current_binary_epoch(verifier_epoch);
    if (have_epoch && datadir_fd >= 0) {
        int64_t age_us = 0;
        if (consensus_state_install_verify_receipt_lookup(
                datadir_fd, evidence->file_digest, verifier_epoch,
                &age_us)) {
            skip_deep_scan = true;
            LOG_INFO(INSTALL_SUBSYS,
                     "install-verify receipt honored: deep content scan "
                     "skipped (receipt age=%.0fs)",
                     (double)age_us / 1000000.0);
        }
    }

    if (!open_bundle_descriptor(evidence->artifact_fd,
                                &evidence->bundle_db)) {
        artifact_evidence_discard(evidence);
        return ZCL_ERR(-6, "artifact evidence: immutable SQLite open failed");
    }
    if (!descriptor_identity_unchanged(evidence->artifact_fd,
                                       &evidence->identity)) {
        artifact_evidence_discard(evidence);
        return ZCL_ERR(-7, "artifact evidence: identity changed during open");
    }
    if (requested_failpoint == CONSENSUS_INSTALL_FAIL_AFTER_BUNDLE_OPEN) {
        artifact_evidence_discard(evidence);
        return ZCL_ERR(-8, "artifact evidence: injected failure after open");
    }

    struct consensus_state_install_result validation_result;
    memset(&validation_result, 0, sizeof(validation_result));
    struct consensus_state_install_result *validation_out =
        legacy_result ? legacy_result : &validation_result;
    if (!consensus_state_bundle_validate_ex(evidence->bundle_db,
                                            &evidence->manifest,
                                            validation_out, skip_deep_scan)) {
        artifact_evidence_discard(evidence);
        return ZCL_ERR(-9, "artifact evidence: semantic validation failed: %s",
                       validation_out->reason);
    }
    if (!descriptor_identity_unchanged(evidence->artifact_fd,
                                       &evidence->identity)) {
        artifact_evidence_discard(evidence);
        return ZCL_ERR(-10,
                       "artifact evidence: identity changed during validation");
    }
    uint8_t final_file_digest[32];
    if (!descriptor_file_digest(evidence->artifact_fd, &evidence->identity,
                                final_file_digest) ||
        memcmp(final_file_digest, evidence->file_digest, 32) != 0) {
        artifact_evidence_discard(evidence);
        return ZCL_ERR(-11,
                       "artifact evidence: complete file changed during validation");
    }
    if (requested_failpoint == CONSENSUS_INSTALL_FAIL_AFTER_BUNDLE_VALIDATE) {
        artifact_evidence_discard(evidence);
        return ZCL_ERR(-12,
                       "artifact evidence: injected failure after validation");
    }
    artifact_receipt_digest_build(evidence, evidence->receipt_digest);
    if (!skip_deep_scan && have_epoch && datadir_fd >= 0)
        consensus_state_install_verify_receipt_store(
            datadir_fd, evidence->file_digest, verifier_epoch);
    *out = evidence;
    return ZCL_OK;
}

struct zcl_result consensus_state_artifact_evidence_open(
    const char *bundle_path, int receipt_datadir_fd,
    struct consensus_state_artifact_evidence **out)
{
    return artifact_evidence_open_impl(bundle_path, receipt_datadir_fd,
                                       CONSENSUS_INSTALL_FAIL_NONE, NULL, out);
}

void consensus_state_artifact_evidence_free(
    struct consensus_state_artifact_evidence *evidence)
{
    artifact_evidence_discard(evidence);
}

bool consensus_state_artifact_evidence_manifest_copy(
    const struct consensus_state_artifact_evidence *evidence,
    struct consensus_state_bundle_manifest *out)
{
    if (!evidence || !out)
        return false;
    zcl_mutex_lock((zcl_mutex_t *)&evidence->mutex);
    bool ok = evidence->artifact_fd >= 0 && evidence->bundle_db &&
        consensus_state_artifact_evidence_revalidate(evidence);
    if (ok)
        *out = evidence->manifest;
    zcl_mutex_unlock((zcl_mutex_t *)&evidence->mutex);
    return ok;
}

bool consensus_state_artifact_evidence_digest(
    const struct consensus_state_artifact_evidence *evidence,
    uint8_t out[32])
{
    if (!evidence || !out)
        return false;
    zcl_mutex_lock((zcl_mutex_t *)&evidence->mutex);
    bool ok = consensus_state_artifact_evidence_revalidate(evidence);
    if (ok)
        memcpy(out, evidence->manifest.artifact_digest, 32);
    zcl_mutex_unlock((zcl_mutex_t *)&evidence->mutex);
    return ok;
}

bool consensus_state_artifact_evidence_revalidate(
    const struct consensus_state_artifact_evidence *evidence)
{
    if (!evidence)
        return false;
    zcl_mutex_lock((zcl_mutex_t *)&evidence->mutex);
    uint8_t current[32];
    bool ok = evidence->artifact_fd >= 0 && evidence->bundle_db &&
        descriptor_file_digest(evidence->artifact_fd, &evidence->identity,
                               current) &&
        memcmp(current, evidence->file_digest, 32) == 0;
    zcl_mutex_unlock((zcl_mutex_t *)&evidence->mutex);
    return ok;
}

bool consensus_state_artifact_evidence_receipt_digest(
    const struct consensus_state_artifact_evidence *evidence,
    uint8_t out[32])
{
    if (!evidence || !out)
        return false;
    zcl_mutex_lock((zcl_mutex_t *)&evidence->mutex);
    bool ok = consensus_state_artifact_evidence_revalidate(evidence);
    if (ok)
        memcpy(out, evidence->receipt_digest, 32);
    zcl_mutex_unlock((zcl_mutex_t *)&evidence->mutex);
    return ok;
}

bool consensus_state_artifact_evidence_file_digest(
    const struct consensus_state_artifact_evidence *evidence,
    uint8_t out[32])
{
    if (!evidence || !out)
        return false;
    zcl_mutex_lock((zcl_mutex_t *)&evidence->mutex);
    bool ok = consensus_state_artifact_evidence_revalidate(evidence);
    if (ok)
        memcpy(out, evidence->file_digest, 32);
    zcl_mutex_unlock((zcl_mutex_t *)&evidence->mutex);
    return ok;
}

bool consensus_state_artifact_evidence_candidate_lease_begin(
    const struct consensus_state_artifact_evidence *evidence,
    struct consensus_state_bundle_manifest *manifest,
    uint8_t receipt_digest[32], sqlite3 **db)
{
    if (!evidence || !manifest || !receipt_digest || !db)
        return false;
    *db = NULL;
    zcl_mutex_lock((zcl_mutex_t *)&evidence->mutex);
    if (!evidence->bundle_db ||
        !consensus_state_artifact_evidence_revalidate(evidence)) {
        LOG_WARN(INSTALL_SUBSYS,
                 "artifact evidence lease refused: stale evidence");
        zcl_mutex_unlock((zcl_mutex_t *)&evidence->mutex);
        return false;
    }
    *manifest = evidence->manifest;
    memcpy(receipt_digest, evidence->receipt_digest, 32);
    *db = evidence->bundle_db;
    return true;
}

void consensus_state_artifact_evidence_candidate_lease_end(
    const struct consensus_state_artifact_evidence *evidence)
{
    if (evidence)
        zcl_mutex_unlock((zcl_mutex_t *)&evidence->mutex);
}

bool consensus_state_snapshot_install(
    sqlite3 *progress_db,
    const struct consensus_state_snapshot_install_request *request,
    struct consensus_state_install_result *result)
{
    if (result)
        memset(result, 0, sizeof(*result));
    if (!progress_db || !request || !request->bundle_path)
        return install_fail(result, CONSENSUS_INSTALL_REFUSED,
                            "NULL progress_db/request/bundle_path");
    struct consensus_state_artifact_evidence *evidence = NULL;
    /* This preview/contained verb (see the "Always false" note below) has no
     * datadir capability of its own to key an install-verify receipt on;
     * every call runs the full content verify. */
    struct zcl_result admitted = artifact_evidence_open_impl(
        request->bundle_path, -1, request->failpoint, result, &evidence);
    bool ok = admitted.ok;
    if (!ok) {
        enum consensus_state_install_status status = CONSENSUS_INSTALL_REFUSED;
        if (request->failpoint != CONSENSUS_INSTALL_FAIL_NONE &&
            (admitted.code == -8 || admitted.code == -12))
            status = CONSENSUS_INSTALL_INJECTED_FAILURE;
        else if (admitted.code == -3 || admitted.code == -5 ||
                 admitted.code == -6)
            status = CONSENSUS_INSTALL_STORE_ERROR;
        return install_fail(result, status, "%s", admitted.message);
    }
    struct consensus_state_bundle_manifest manifest;
    if (!consensus_state_artifact_evidence_manifest_copy(evidence, &manifest)) {
        consensus_state_artifact_evidence_free(evidence);
        return install_fail(result, CONSENSUS_INSTALL_REFUSED,
                            "artifact evidence became stale after admission");
    }
    if (ok && (request->expected_height != manifest.height ||
               memcmp(request->expected_block_hash, manifest.block_hash, 32)
                   != 0)) {
        (void)install_fail(result, CONSENSUS_INSTALL_REFUSED,
                           "bundle height/hash does not match caller assertion");
        ok = false;
    }
    if (ok && result) {
        result->height = manifest.height;
        result->history_complete = manifest.history_complete;
        result->source_clean = manifest.source_clean;
        result->validation_profile = manifest.validation_profile;
    }
    if (ok) {
        /* Containment is load-bearing. Presence of roots/cursors/digests and a
         * caller boolean cannot prove complete historical anchors/nullifiers,
         * signature authority, or a rollback generation. Promotion remains
         * unavailable until those receipts are cryptographically bound and a
         * kill/reopen campaign proves the one-transaction publisher. */
        (void)install_fail(
            result, CONSENSUS_INSTALL_VERIFIED_CONTAINED,
            "verified %s height=%d history=%s source=%s profile=%s; "
            "activation contained pending "
            "bound proof authority, rollback generation, and crash proof",
            CONSENSUS_STATE_BUNDLE_SCHEMA, manifest.height,
            manifest.history_complete ? "complete_claim" : "incomplete",
            manifest.source_clean ? "clean" : "dirty",
            manifest.validation_profile == CONSENSUS_STATE_VALIDATION_FULL
                ? "full" : "checkpoint_fold");
        ok = false;
    }

    consensus_state_artifact_evidence_free(evidence);
    return ok; /* Always false while activation containment is in force. */
}
