/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Contained admission preview for zcl.consensus_state_bundle.v1. */

#include "config/consensus_state_snapshot_install.h"

#include "config/consensus_state_bundle_validate.h"
#include "config/consensus_state_install_verify_receipt.h"
#include "config/consensus_state_producer_receipt.h"
#include "consensus_state_snapshot_install_internal.h"
#include "core/utiltime.h"
#include "core/amount.h"
#include "coins/utxo_commitment.h"
#include "script/script.h"
#include "platform/positioned_file.h"
#include "storage/sqlite_pinned_reader.h"
#include "crypto/sha3.h"
#include "services/sync_benchmark_service.h"
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
#ifndef _WIN32
#include <sys/stat.h>
#include <unistd.h>
#endif

#define INSTALL_SUBSYS "consensus_bundle_install"

#ifdef _WIN32

struct consensus_state_artifact_evidence { unsigned char unavailable; };

static bool artifact_coins_begin_platform_arm(
    const struct consensus_state_artifact_evidence *evidence,
    struct consensus_state_artifact_coins **out)
{
    (void)evidence;
    if (out) *out = NULL;
    return false;
}

static enum coins_kv_read_snapshot_step artifact_coins_next_platform_arm(
    struct consensus_state_artifact_coins *it,
    struct coins_kv_read_snapshot_row *out)
{
    (void)it;
    if (out) memset(out, 0, sizeof(*out));
    return COINS_KV_READ_SNAPSHOT_ERROR;
}

static bool artifact_coins_finish_platform_arm(
    struct consensus_state_artifact_coins *it)
{
    (void)it;
    return false;
}

static void artifact_coins_abort_platform_arm(
    struct consensus_state_artifact_coins *it)
{
    (void)it;
}



struct zcl_result consensus_state_artifact_evidence_open(
    const char *bundle_path, int receipt_datadir_fd,
    struct consensus_state_artifact_evidence **out)
{
    (void)bundle_path;
    (void)receipt_datadir_fd;
    if (out)
        *out = NULL;
    return ZCL_ERR(-1,
                   "artifact evidence refused: native Windows consensus "
                   "install is disabled pending qualified handle-bound "
                   "SQLite admission and atomic generation activation");
}

void consensus_state_artifact_evidence_free(
    struct consensus_state_artifact_evidence *evidence)
{
    (void)consensus_state_artifact_evidence_close(&evidence);
}

bool consensus_state_artifact_evidence_manifest_copy(
    const struct consensus_state_artifact_evidence *evidence,
    struct consensus_state_bundle_manifest *manifest)
{
    (void)evidence;
    if (manifest)
        memset(manifest, 0, sizeof(*manifest));
    return false;
}

bool consensus_state_artifact_evidence_digest(
    const struct consensus_state_artifact_evidence *evidence, uint8_t out[32])
{
    (void)evidence;
    if (out)
        memset(out, 0, 32);
    return false;
}

bool consensus_state_artifact_evidence_revalidate(
    const struct consensus_state_artifact_evidence *evidence)
{
    (void)evidence;
    return false;
}

bool consensus_state_artifact_evidence_receipt_digest(
    const struct consensus_state_artifact_evidence *evidence, uint8_t out[32])
{
    return consensus_state_artifact_evidence_digest(evidence, out);
}

bool consensus_state_artifact_evidence_file_digest(
    const struct consensus_state_artifact_evidence *evidence, uint8_t out[32])
{
    return consensus_state_artifact_evidence_digest(evidence, out);
}

bool consensus_state_artifact_evidence_candidate_lease_begin(
    const struct consensus_state_artifact_evidence *evidence,
    struct consensus_state_bundle_manifest *manifest,
    uint8_t receipt_digest[32], sqlite3 **db)
{
    (void)evidence;
    if (manifest)
        memset(manifest, 0, sizeof(*manifest));
    if (receipt_digest)
        memset(receipt_digest, 0, 32);
    if (db)
        *db = NULL;
    return false;
}

void consensus_state_artifact_evidence_candidate_lease_end(
    const struct consensus_state_artifact_evidence *evidence)
{
    (void)evidence;
}

bool consensus_state_snapshot_install(
    sqlite3 *progress_db,
    const struct consensus_state_snapshot_install_request *request,
    struct consensus_state_install_result *result)
{
    (void)progress_db;
    (void)request;
    if (result) {
        memset(result, 0, sizeof(*result));
        result->status = CONSENSUS_INSTALL_REFUSED;
        snprintf(result->reason, sizeof(result->reason),
                 "native Windows consensus install refused before file, "
                 "datadir, or state mutation");
    }
    LOG_WARN(INSTALL_SUBSYS,
             "native Windows consensus install refused before mutation");
    return false;
}

#else

struct consensus_state_artifact_evidence {
    zcl_mutex_t mutex;
    struct platform_positioned_file artifact_file;
    struct platform_positioned_file_snapshot artifact_snapshot;
    struct sqlite_pinned_reader *reader;
    int artifact_fd; /* Borrowed alias; artifact_file owns this descriptor. */
    sqlite3 *bundle_db;
    bool coins_iterator_active;
    unsigned candidate_leases;
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

static bool immutable_regular_file_open(
    const char *path, struct platform_positioned_file *file,
    int *out_fd, struct stat *identity,
    struct platform_positioned_file_snapshot *snapshot)
{
    *out_fd = -1;
    if (!path || !path[0] || !platform_positioned_file_open(file, path)) {
        LOG_WARN(INSTALL_SUBSYS, "bundle retained-file open failed");
        return false;
    }
    intptr_t native = platform_positioned_file_native_fd(file);
    if (native < 0 || native > INT_MAX) {
        LOG_WARN(INSTALL_SUBSYS, "bundle retained descriptor is invalid");
        return false;
    }
    int fd = (int)native;
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        LOG_WARN(INSTALL_SUBSYS, "bundle descriptor is not a regular file");
        return false;
    }
    if ((st.st_mode & (S_IWUSR | S_IWGRP | S_IWOTH)) != 0) {
        LOG_WARN(INSTALL_SUBSYS,
                 "bundle is writable; immutable admission refused path=%s", path);
        return false;
    }
    if (!platform_positioned_file_snapshot(file, snapshot)) {
        LOG_WARN(INSTALL_SUBSYS, "bundle retained snapshot failed");
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

static bool open_bundle_descriptor(
    struct consensus_state_artifact_evidence *evidence)
{
    if (!sqlite_pinned_reader_open(&evidence->artifact_file,
                                   &evidence->artifact_snapshot,
                                   &evidence->reader)) {
        LOG_WARN(INSTALL_SUBSYS, "bundle retained-object SQLite open failed");
        return false;
    }
    sqlite3 **bundle_db = &evidence->bundle_db;
    *bundle_db = sqlite_pinned_reader_db(evidence->reader);
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

static bool artifact_evidence_close_checked(
    struct consensus_state_artifact_evidence **owner)
{
    if (!owner) return false;
    struct consensus_state_artifact_evidence *evidence = *owner;
    if (!evidence) return true;
    zcl_mutex_lock(&evidence->mutex);
    if (evidence->coins_iterator_active || evidence->candidate_leases) {
        LOG_WARN(INSTALL_SUBSYS, "bundle evidence retained: consumer lease active");
        zcl_mutex_unlock(&evidence->mutex);
        return false;
    }
    /* sqlite3_close rolls back only after confirming it can close; BUSY
     * retains the transaction, readiness and borrowed positioned-file owner. */
    if (evidence->reader && !sqlite_pinned_reader_close(&evidence->reader)) {
        LOG_WARN(INSTALL_SUBSYS, "bundle evidence retained: SQLite close busy or failed");
        zcl_mutex_unlock(&evidence->mutex);
        return false;
    }
    evidence->bundle_db = NULL;
    /* Positioned-file close is void. Use the exact retained native descriptor
     * for a checked POSIX close; never retry an ambiguous EINTR by fd/name. */
    intptr_t native = platform_positioned_file_native_fd(&evidence->artifact_file);
    bool closed = native < 0 || (native <= INT_MAX && close((int)native) == 0);
    platform_positioned_file_init(&evidence->artifact_file);
    evidence->artifact_fd = -1;
    zcl_mutex_unlock(&evidence->mutex);
    zcl_mutex_destroy(&evidence->mutex);
    free(evidence); *owner = NULL;
    if (!closed) LOG_WARN(INSTALL_SUBSYS, "bundle evidence native close failed");
    return closed;
}

/* Preserve the legacy constructor cleanup contract. Exceptional retained
 * failed-open ownership remains a known limitation; it is not exposed as
 * usable evidence and is not solved by the successful-admission close API. */
static void artifact_evidence_discard(
    struct consensus_state_artifact_evidence *evidence)
{
    (void)artifact_evidence_close_checked(&evidence);
}

/* Stage 1 of artifact evidence open: pin the immutable file and hash it.
 * Discards the evidence on failure, exactly as the inline checks did. */
static struct zcl_result artifact_evidence_open_pinned_file(
    const char *bundle_path,
    struct consensus_state_artifact_evidence *evidence)
{
    if (!immutable_regular_file_open(bundle_path, &evidence->artifact_file,
                                     &evidence->artifact_fd, &evidence->identity,
                                     &evidence->artifact_snapshot) ||
        !sidecars_absent(bundle_path)) {
        artifact_evidence_discard(evidence);
        return ZCL_ERR(-4, "artifact evidence: bundle is not immutable/finalized");
    }
    if (!descriptor_file_digest(evidence->artifact_fd, &evidence->identity,
                                evidence->file_digest)) {
        artifact_evidence_discard(evidence);
        return ZCL_ERR(-5, "artifact evidence: initial complete-file hash failed");
    }
    return ZCL_OK;
}

/* True when a prior full verify receipt for this bundle digest and the
 * current binary epoch exists; *age_us then holds the receipt age. */
static bool artifact_evidence_receipt_honored(
    bool have_epoch, int datadir_fd,
    const struct consensus_state_artifact_evidence *evidence,
    const uint8_t verifier_epoch[32], int64_t *age_us)
{
    return have_epoch && datadir_fd >= 0 &&
           consensus_state_install_verify_receipt_lookup(
               datadir_fd, evidence->file_digest, verifier_epoch, age_us);
}

/* Stage 2: open the SQLite descriptor and apply the after-open failpoint. */
static struct zcl_result artifact_evidence_open_bundle_stage(
    struct consensus_state_artifact_evidence *evidence,
    enum consensus_state_install_failpoint requested_failpoint)
{
    if (!open_bundle_descriptor(evidence)) {
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
    return ZCL_OK;
}

/* Stage 3: semantic validation, then re-check that the descriptor identity
 * and the complete-file digest did not move, then the after-validate failpoint. */
static struct zcl_result artifact_evidence_validate_stage(
    struct consensus_state_artifact_evidence *evidence,
    enum consensus_state_install_failpoint requested_failpoint,
    struct consensus_state_install_result *legacy_result, bool skip_deep_scan)
{
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
    return ZCL_OK;
}

/* Record a receipt after a full (non-skipped) verify when an epoch exists. */
static void artifact_evidence_receipt_store_after_full_verify(
    bool skip_deep_scan, bool have_epoch, int datadir_fd,
    const struct consensus_state_artifact_evidence *evidence,
    const uint8_t verifier_epoch[32])
{
    if (!skip_deep_scan && have_epoch && datadir_fd >= 0)
        consensus_state_install_verify_receipt_store(
            datadir_fd, evidence->file_digest, verifier_epoch);
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
    platform_positioned_file_init(&evidence->artifact_file);

    struct zcl_result stage = artifact_evidence_open_pinned_file(
        bundle_path, evidence);
    if (!stage.ok)
        return stage;

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
    int64_t age_us = 0;
    if (artifact_evidence_receipt_honored(have_epoch, datadir_fd, evidence,
                                          verifier_epoch, &age_us)) {
        skip_deep_scan = true;
        LOG_INFO(INSTALL_SUBSYS,
                 "install-verify receipt honored: deep content scan "
                 "skipped (receipt age=%.0fs)",
                 (double)age_us / 1000000.0);
    }

    stage = artifact_evidence_open_bundle_stage(evidence, requested_failpoint);
    if (!stage.ok)
        return stage;
    stage = artifact_evidence_validate_stage(evidence, requested_failpoint,
                                             legacy_result, skip_deep_scan);
    if (!stage.ok)
        return stage;
    artifact_receipt_digest_build(evidence, evidence->receipt_digest);
    artifact_evidence_receipt_store_after_full_verify(
        skip_deep_scan, have_epoch, datadir_fd, evidence, verifier_epoch);
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
    (void)consensus_state_artifact_evidence_close(&evidence);
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
    if (evidence->candidate_leases == UINT_MAX || !evidence->bundle_db ||
        !consensus_state_artifact_evidence_revalidate(evidence)) {
        LOG_WARN(INSTALL_SUBSYS,
                 "artifact evidence lease refused: stale evidence");
        zcl_mutex_unlock((zcl_mutex_t *)&evidence->mutex);
        return false;
    }
    ((struct consensus_state_artifact_evidence *)evidence)->candidate_leases++;
    *manifest = evidence->manifest;
    memcpy(receipt_digest, evidence->receipt_digest, 32);
    *db = evidence->bundle_db;
    return true;
}

void consensus_state_artifact_evidence_candidate_lease_end(
    const struct consensus_state_artifact_evidence *evidence)
{
    if (evidence) {
        /* Successful begin holds this recursive mutex until its paired end. */
        struct consensus_state_artifact_evidence *owner =
            (struct consensus_state_artifact_evidence *)evidence;
        if (owner->candidate_leases) owner->candidate_leases--;
        zcl_mutex_unlock(&owner->mutex);
    }
}

/* One iterator borrows the evidence's already-pinned read transaction. Its
 * lease serializes SQLite use; callers complete it on the thread that began it. */
struct consensus_state_artifact_coins {
    struct consensus_state_artifact_evidence *evidence;
    sqlite3_stmt *rows;
    struct consensus_state_bundle_manifest manifest;
    struct sha3_256_ctx digest;
    uint8_t last_txid[32];
    uint32_t last_vout;
    uint64_t count;
    bool have_last, exhausted, failed;
};

static bool artifact_coins_begin_platform_arm(
    const struct consensus_state_artifact_evidence *evidence,
    struct consensus_state_artifact_coins **out)
{
    if (out) *out = NULL;
    if (!evidence || !out) return false;
    struct consensus_state_bundle_manifest manifest;
    uint8_t receipt[32];
    sqlite3 *db = NULL;
    if (!consensus_state_artifact_evidence_candidate_lease_begin(
            evidence, &manifest, receipt, &db))
        return false;
    struct consensus_state_artifact_evidence *owner =
        (struct consensus_state_artifact_evidence *)evidence;
    if (owner->coins_iterator_active) {
        LOG_WARN(INSTALL_SUBSYS, "coin iterator already active");
        consensus_state_artifact_evidence_candidate_lease_end(evidence);
        return false;
    }
    struct consensus_state_artifact_coins *it =
        zcl_calloc(1, sizeof(*it), "artifact coin iterator");
    if (!it) {
        consensus_state_artifact_evidence_candidate_lease_end(evidence);
        return false;
    }
    static const char sql[] =
        "SELECT txid,vout,value,script,height,is_coinbase "
        "FROM coins ORDER BY txid,vout";
    int rc = sqlite3_prepare_v2(db, sql, -1, &it->rows, NULL);
    if (rc != SQLITE_OK) {
        LOG_WARN(INSTALL_SUBSYS, "coin iterator prepare failed rc=%d", rc);
        if (it->rows && sqlite3_finalize(it->rows) != SQLITE_OK)
            LOG_WARN(INSTALL_SUBSYS, "coin iterator failed prepare cleanup");
        free(it);
        consensus_state_artifact_evidence_candidate_lease_end(evidence);
        return false;
    }
    it->evidence = owner;
    it->manifest = manifest;
    sha3_256_init(&it->digest);
    owner->coins_iterator_active = true;
    *out = it;
    return true;
}

static bool artifact_coin_scalars_valid(int64_t vout, int64_t value,
                                        int64_t height, int64_t coinbase,
                                        int32_t last_applied_height)
{
    return vout >= 0 && vout <= UINT32_MAX && MoneyRange(value) &&
        height >= 0 && height <= last_applied_height &&
        coinbase >= 0 && coinbase <= 1;
}

static bool artifact_coin_row_valid(sqlite3_stmt *rows, const int types[6],
                                    int32_t last_applied_height)
{
    for (int i = 0; i < 6; i++) {
        int expected = i == 0 || i == 3 ? SQLITE_BLOB : SQLITE_INTEGER;
        if (types[i] != expected) return false;
    }
    int64_t vout = sqlite3_column_int64(rows, 1);
    int64_t value = sqlite3_column_int64(rows, 2);
    int64_t height = sqlite3_column_int64(rows, 4);
    int64_t coinbase = sqlite3_column_int64(rows, 5);
    int script_len = sqlite3_column_bytes(rows, 3);
    return sqlite3_column_blob(rows, 0) && sqlite3_column_bytes(rows, 0) == 32 &&
        artifact_coin_scalars_valid(vout, value, height, coinbase,
                                    last_applied_height) &&
        script_len >= 0 && script_len <= MAX_SCRIPT_SIZE &&
        (script_len == 0 || sqlite3_column_blob(rows, 3) != NULL);
}

static bool artifact_coins_next_ready(
    struct consensus_state_artifact_coins *it,
    struct coins_kv_read_snapshot_row *out)
{
    if (out) memset(out, 0, sizeof(*out));
    if (!it || !out || it->failed || it->exhausted) {
        if (it) it->failed = true;
        LOG_WARN(INSTALL_SUBSYS, "coin iterator next: invalid state");
        return false;
    }
    if (!descriptor_identity_unchanged(it->evidence->artifact_fd,
                                        &it->evidence->identity)) {
        it->failed = true;
        LOG_WARN(INSTALL_SUBSYS, "coin iterator input identity changed");
        return false;
    }
    return true;
}

static enum coins_kv_read_snapshot_step artifact_coins_next_platform_arm(
    struct consensus_state_artifact_coins *it,
    struct coins_kv_read_snapshot_row *out)
{
    if (!artifact_coins_next_ready(it, out))
        return COINS_KV_READ_SNAPSHOT_ERROR;
    int rc = sqlite3_step(it->rows); // raw-sql-ok:read-only-introspection
    if (rc == SQLITE_DONE) {
        it->exhausted = true;
        return COINS_KV_READ_SNAPSHOT_DONE;
    }
    if (rc != SQLITE_ROW) {
        it->failed = true;
        LOG_WARN(INSTALL_SUBSYS, "coin iterator step failed rc=%d", rc);
        return COINS_KV_READ_SNAPSHOT_ERROR;
    }
    /* Same strict row domain as coins_kv_read_snapshot_next; no coercion,
     * skipped rows or alternate commitment encoding is permitted here. */
    int types[6];
    for (int i = 0; i < 6; i++) types[i] = sqlite3_column_type(it->rows, i);
    int64_t vout = sqlite3_column_int64(it->rows, 1);
    int64_t value = sqlite3_column_int64(it->rows, 2);
    int64_t height = sqlite3_column_int64(it->rows, 4);
    int64_t coinbase = sqlite3_column_int64(it->rows, 5);
    int script_len = sqlite3_column_bytes(it->rows, 3);
    const uint8_t *txid = sqlite3_column_blob(it->rows, 0);
    const uint8_t *script = sqlite3_column_blob(it->rows, 3);
    bool valid = artifact_coin_row_valid(it->rows, types, it->manifest.height);
    int order = valid && it->have_last ? memcmp(txid, it->last_txid, 32) : 1;
    if (!valid || (it->have_last &&
        (order < 0 || (order == 0 && (uint32_t)vout <= it->last_vout))) ||
        it->count == UINT64_MAX) {
        it->failed = true;
        LOG_WARN(INSTALL_SUBSYS, "coin iterator malformed or unordered row");
        return COINS_KV_READ_SNAPSHOT_ERROR;
    }
    memcpy(out->txid, txid, 32);
    out->vout = (uint32_t)vout;
    out->value = value;
    out->script = script_len > 0 ? script : NULL;
    out->script_len = (size_t)script_len;
    out->height = (int32_t)height;
    out->is_coinbase = coinbase != 0;
    utxo_commitment_sha3_write_record(&it->digest, out->txid, out->vout,
        out->value, out->script, (uint32_t)out->script_len,
        (uint32_t)out->height, (uint8_t)out->is_coinbase);
    memcpy(it->last_txid, txid, 32);
    it->last_vout = out->vout;
    it->have_last = true;
    it->count++;
    return COINS_KV_READ_SNAPSHOT_ROW;
}

static bool artifact_coins_release(struct consensus_state_artifact_coins *it)
{
    int rc = sqlite3_finalize(it->rows);
    it->rows = NULL;
    if (rc != SQLITE_OK)
        LOG_WARN(INSTALL_SUBSYS, "coin iterator finalize failed rc=%d", rc);
    it->evidence->coins_iterator_active = false;
    consensus_state_artifact_evidence_candidate_lease_end(it->evidence);
    free(it);
    return rc == SQLITE_OK;
}

static bool artifact_coins_finish_platform_arm(
    struct consensus_state_artifact_coins *it)
{
    if (!it) return false;
    bool ok = it->exhausted && !it->failed;
    if (ok) {
        uint8_t digest[32];
        sha3_256_finalize(&it->digest, digest);
        ok = it->count == it->manifest.utxo_count &&
             memcmp(digest, it->manifest.utxo_root, 32) == 0 &&
             consensus_state_artifact_evidence_revalidate(it->evidence);
    }
    bool released = artifact_coins_release(it);
    if (!ok || !released)
        LOG_WARN(INSTALL_SUBSYS, "coin iterator completion refused");
    return ok && released;
}

static void artifact_coins_abort_platform_arm(
    struct consensus_state_artifact_coins *it)
{
    if (it) (void)artifact_coins_release(it);
}

/* Map an admission failure code to the install status; same precedence as
 * the original inline chain (injected failpoint first, then store errors). */
static enum consensus_state_install_status
install_status_for_admission_failure(
    enum consensus_state_install_failpoint failpoint, int code)
{
    if (failpoint != CONSENSUS_INSTALL_FAIL_NONE &&
        (code == -8 || code == -12))
        return CONSENSUS_INSTALL_INJECTED_FAILURE;
    if (code == -3 || code == -5 || code == -6)
        return CONSENSUS_INSTALL_STORE_ERROR;
    return CONSENSUS_INSTALL_REFUSED;
}

static bool snapshot_install_caller_assertion_mismatch(
    const struct consensus_state_snapshot_install_request *request,
    const struct consensus_state_bundle_manifest *manifest)
{
    return request->expected_height != manifest->height ||
           memcmp(request->expected_block_hash, manifest->block_hash, 32) != 0;
}

static void snapshot_install_publish_manifest_fields(
    struct consensus_state_install_result *result,
    const struct consensus_state_bundle_manifest *manifest)
{
    if (!result)
        return;
    result->height = manifest->height;
    result->history_complete = manifest->history_complete;
    result->source_clean = manifest->source_clean;
    result->validation_profile = manifest->validation_profile;
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
     * every call runs the full content verify.
     *
     * zcl.sync_benchmark.v1: SYNC_BENCH_ARTIFACT_VERIFY brackets exactly the
     * open+content-verify call below (the expensive, real work); it is never
     * begun for a request that fails NULL validation above. */
    sync_benchmark_phase_begin(SYNC_BENCH_ARTIFACT_VERIFY);
    struct zcl_result admitted = artifact_evidence_open_impl(
        request->bundle_path, -1, request->failpoint, result, &evidence);
    sync_benchmark_phase_end(SYNC_BENCH_ARTIFACT_VERIFY);
    bool ok = admitted.ok;
    if (!ok)
        return install_fail(
            result,
            install_status_for_admission_failure(request->failpoint,
                                                 admitted.code),
            "%s", admitted.message);
    /* SYNC_BENCH_INSTALL brackets the admission-to-contained-result stretch:
     * manifest copy, the caller-assertion match, and the verified-contained
     * status build. sync_benchmark_mark_ready() fires exactly once, the
     * instant this reaches CONSENSUS_INSTALL_VERIFIED_CONTAINED — the "usable,
     * not yet sovereign" milestone the header documents: the bundle is
     * verified and its data is available, even though full activation
     * authority (bound proof authority, rollback generation, crash proof)
     * remains future work and this call still returns false. */
    sync_benchmark_phase_begin(SYNC_BENCH_INSTALL);
    struct consensus_state_bundle_manifest manifest;
    if (!consensus_state_artifact_evidence_manifest_copy(evidence, &manifest)) {
        sync_benchmark_phase_end(SYNC_BENCH_INSTALL);
        consensus_state_artifact_evidence_free(evidence);
        return install_fail(result, CONSENSUS_INSTALL_REFUSED,
                            "artifact evidence became stale after admission");
    }
    if (ok && snapshot_install_caller_assertion_mismatch(request, &manifest)) {
        (void)install_fail(result, CONSENSUS_INSTALL_REFUSED,
                           "bundle height/hash does not match caller assertion");
        ok = false;
    }
    if (ok)
        snapshot_install_publish_manifest_fields(result, &manifest);
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
        sync_benchmark_mark_ready();
        ok = false;
    }
    sync_benchmark_phase_end(SYNC_BENCH_INSTALL);

    consensus_state_artifact_evidence_free(evidence);
    return ok; /* Always false while activation containment is in force. */
}

#endif

/* One explicit public definition; platform policy stays inside the body.
 * Windows never admits evidence. POSIX retains the checked owner on BUSY or
 * active consumers and preserves terminal native-close failure semantics. */
bool consensus_state_artifact_evidence_close(
    struct consensus_state_artifact_evidence **owner)
{
#ifdef _WIN32
    return owner && !*owner;
#else
    return artifact_evidence_close_checked(owner);
#endif
}

bool consensus_state_artifact_coins_begin(
    const struct consensus_state_artifact_evidence *evidence,
    struct consensus_state_artifact_coins **out)
{
    return artifact_coins_begin_platform_arm(evidence, out);
}

enum coins_kv_read_snapshot_step consensus_state_artifact_coins_next(
    struct consensus_state_artifact_coins *iterator,
    struct coins_kv_read_snapshot_row *out)
{
    return artifact_coins_next_platform_arm(iterator, out);
}

bool consensus_state_artifact_coins_finish(
    struct consensus_state_artifact_coins *iterator)
{
    return artifact_coins_finish_platform_arm(iterator);
}

void consensus_state_artifact_coins_abort(
    struct consensus_state_artifact_coins *iterator)
{
    artifact_coins_abort_platform_arm(iterator);
}
