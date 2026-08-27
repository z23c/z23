/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Contained, immutable full-history consensus-state exporter. */
#define _GNU_SOURCE
#include "config/consensus_state_snapshot_export.h"
#include "config/consensus_state_bundle_validate.h"
#include "platform/fd_path.h"
#include "platform/rename_compat.h"
#include "consensus_state_snapshot_export_internal.h"
#include "storage/consensus_db.h"    /* CONSENSUS_DB_FILENAME + legacy name */
#include "storage/progress_store.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <sqlite3.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define EXPORT_SUBSYS "consensus_bundle_export"

bool consensus_export_fail(struct consensus_state_export_result *result,
                           enum consensus_state_export_status status,
                           const char *fmt, ...)
{
    char reason[384];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(reason, sizeof(reason), fmt, ap);
    va_end(ap);
    if (result) {
        result->status = status;
        snprintf(result->reason, sizeof(result->reason), "%s", reason);
    }
    LOG_WARN(EXPORT_SUBSYS, "%s", reason);
    return false;
}

/* Case-insensitive prefix test used to reject an export output name that would
 * collide with a live store family. */
static bool export_name_has_prefix_ci(const char *name, const char *prefix)
{
    for (size_t i = 0; prefix[i] != '\0'; i++) {
        unsigned char c = (unsigned char)name[i];
        if (c == '\0')
            return false;
        if (c >= 'A' && c <= 'Z')
            c = (unsigned char)(c - 'A' + 'a');
        if (c != (unsigned char)prefix[i])
            return false;
    }
    return true;
}

static bool output_name_valid(const char *name)
{
    if (!name || !name[0] || strchr(name, '/') || strchr(name, '?') ||
        strchr(name, '#') || strchr(name, '%') || strcmp(name, ".") == 0 ||
        strcmp(name, "..") == 0)
        return false;
    /* A4: refuse a name that would clobber EITHER live store — the consensus.db
     * kernel authority (post-flip) or the progress.kv projection store. */
    if (export_name_has_prefix_ci(name, CONSENSUS_DB_FILENAME) ||
        export_name_has_prefix_ci(name, CONSENSUS_DB_LEGACY_KERNEL_FILENAME))
        return false;
    return strlen(name) < CONSENSUS_EXPORT_NAME_MAX - 48;
}

void consensus_export_output_init(struct consensus_export_output_binding *output)
{
    memset(output, 0, sizeof(*output));
    output->dirfd = -1;
    output->temp_fd = -1;
}

static bool output_name_absent(const struct consensus_export_output_binding *output,
                               const char *name)
{
    struct stat st;
    errno = 0;
    return fstatat(output->dirfd, name, &st, AT_SYMLINK_NOFOLLOW) != 0 &&
           errno == ENOENT;
}

static bool output_final_identity_matches(
    const struct consensus_export_output_binding *output, struct stat *st_out)
{
    struct stat st;
    if (!output || output->dirfd < 0 || !output->final_name[0] ||
        fstatat(output->dirfd, output->final_name, &st,
                AT_SYMLINK_NOFOLLOW) != 0 ||
        !S_ISREG(st.st_mode) || st.st_nlink != 1 ||
        st.st_dev != output->temp_dev ||
        st.st_ino != output->temp_ino ||
        (st.st_mode & (S_IWUSR | S_IWGRP | S_IWOTH)) != 0)
        return false;
    if (st_out)
        *st_out = st;
    return true;
}

static bool output_sidecars_absent(
    const struct consensus_export_output_binding *output)
{
    static const char *const suffixes[] = {"-journal", "-wal", "-shm"};
    char sidecar[CONSENSUS_EXPORT_NAME_MAX + 16];
    for (size_t i = 0; i < sizeof(suffixes) / sizeof(suffixes[0]); i++) {
        int n = snprintf(sidecar, sizeof(sidecar), "%s%s", output->final_name,
                         suffixes[i]);
        if (n <= 0 || (size_t)n >= sizeof(sidecar))
            return false;
        struct stat st;
        errno = 0;
        if (fstatat(output->dirfd, sidecar, &st, AT_SYMLINK_NOFOLLOW) == 0 ||
            errno != ENOENT)
            return false;
    }
    return true;
}

void consensus_export_staging_discard(
    struct consensus_export_output_binding *output)
{
    if (!output || !output->stage_created || output->dirfd < 0 ||
        !output->stage_name[0])
        return;
    struct stat named;
    if (fstatat(output->dirfd, output->stage_name, &named,
                AT_SYMLINK_NOFOLLOW) == 0 &&
        S_ISREG(named.st_mode) && named.st_dev == output->temp_dev &&
        named.st_ino == output->temp_ino) {
        /* The staged bytes are abandoned, not published: deleting the staging
         * name under its verified identity is what closing the anonymous
         * Linux inode does. A name that no longer resolves to the staged
         * inode is somebody else's file and is left for inspection. */
        if (unlinkat(output->dirfd, output->stage_name, 0) != 0)
            LOG_WARN(EXPORT_SUBSYS, "output staging discard failed errno=%d",
                     errno);
    }
    output->stage_created = false;
    output->stage_name[0] = '\0';
}

void consensus_export_output_close(struct consensus_export_output_binding *output)
{
    if (!output || output->abandon_on_close)
        return;
    consensus_export_staging_discard(output);
    if (output->vfs_registered) {
        (void)sqlite3_vfs_unregister(&output->vfs);
        output->vfs_registered = false;
    }
    if (output->temp_fd >= 0) {
        (void)close(output->temp_fd);
        output->temp_fd = -1;
    }
    if (output->dirfd >= 0) {
        (void)close(output->dirfd);
        output->dirfd = -1;
    }
}

bool consensus_export_output_open(
    const struct consensus_state_snapshot_export_request *request,
    struct consensus_export_output_binding *output,
    struct consensus_state_export_result *result)
{
    if (request->output_dir_fd < 0 || !output_name_valid(request->output_name))
        return consensus_export_fail(result, CONSENSUS_EXPORT_REFUSED,
                                     "output directory/name is invalid");
    int fd = fcntl(request->output_dir_fd, F_DUPFD_CLOEXEC, 3);
    if (fd < 0)
        return consensus_export_fail(result, CONSENSUS_EXPORT_REFUSED,
                                     "output directory descriptor duplicate failed");
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISDIR(st.st_mode)) {
        (void)close(fd);
        return consensus_export_fail(result, CONSENSUS_EXPORT_REFUSED,
                                     "output descriptor is not a directory");
    }
    output->dirfd = fd;
    snprintf(output->final_name, sizeof(output->final_name), "%s",
             request->output_name);
    if (!output_name_absent(output, output->final_name)) {
        consensus_export_output_close(output);
        return consensus_export_fail(result, CONSENSUS_EXPORT_REFUSED,
                                     "output name already exists or is uninspectable");
    }
    return true;
}

#ifdef ZCL_TESTING
static void (*g_after_output_bind_hook)(void *) = NULL;
static void *g_after_output_bind_ctx = NULL;
static void (*g_after_staging_create_hook)(void *, int) = NULL;
static void *g_after_staging_create_ctx = NULL;
static void (*g_before_link_hook)(void *) = NULL;
static void *g_before_link_ctx = NULL;

void consensus_state_snapshot_export_test_set_after_output_bind_hook(
    void (*hook)(void *), void *ctx)
{
    g_after_output_bind_hook = hook;
    g_after_output_bind_ctx = ctx;
}

void consensus_state_snapshot_export_test_set_after_staging_create_hook(
    void (*hook)(void *, int), void *ctx)
{
    g_after_staging_create_hook = hook;
    g_after_staging_create_ctx = ctx;
}

void consensus_export_run_after_bind_hook(void)
{
    void (*hook)(void *) = g_after_output_bind_hook;
    void *ctx = g_after_output_bind_ctx;
    g_after_output_bind_hook = NULL;
    g_after_output_bind_ctx = NULL;
    if (hook)
        hook(ctx);
}

[[maybe_unused]] static void output_run_after_staging_create_hook(int staging_fd)
{
    void (*hook)(void *, int) = g_after_staging_create_hook;
    void *ctx = g_after_staging_create_ctx;
    g_after_staging_create_hook = NULL;
    g_after_staging_create_ctx = NULL;
    if (hook)
        hook(ctx, staging_fd);
}

static void output_run_before_link_hook(void)
{
    void (*hook)(void *) = g_before_link_hook;
    void *ctx = g_before_link_ctx;
    g_before_link_hook = NULL;
    g_before_link_ctx = NULL;
    if (hook)
        hook(ctx);
}
#else
void consensus_export_run_after_bind_hook(void) { }
[[maybe_unused]] static void output_run_after_staging_create_hook(int staging_fd)
{
    (void)staging_fd;
}
static void output_run_before_link_hook(void) { }
#endif

/* INVARIANT MAPPING (seal→publish containment). On Linux the staging inode is
 * anonymous (O_TMPFILE): no pathname can reach the sealed bytes between seal
 * and publication, publication links the pinned descriptor by
 * /proc/self/fd/N + AT_SYMLINK_FOLLOW, and nlink==0 is checked at every
 * re-verify point. Darwin has neither O_TMPFILE nor linkat(AT_EMPTY_PATH), so
 * the same lifecycle is staged as a hidden O_CREAT|O_EXCL sibling of the final
 * output (CONSENSUS_STATE_STAGE_PREFIX + final + pid + seq) inside the pinned
 * 0700 datadir directory and published by an atomic no-replace rename of that
 * name. The no-name property is preserved there only as "no attacker-visible
 * name without write access to the datadir" — 0700 dir + EXCL creation + a
 * staging window that ends in one rename — which is WEAKER than Linux's
 * anonymous inode and is recorded as such: the descriptor identity
 * (dev/ino/size/mtimes) is re-verified at every point where Linux checked
 * nlink==0, the staging link count must stay exactly 1 until the rename, and
 * the installer independently reopens and re-hashes the published bytes. */
static bool output_stage_create(struct consensus_export_output_binding *output,
                                struct consensus_state_export_result *result)
{
    for (unsigned seq = 0; seq < 64; seq++) {
        int n = snprintf(output->stage_name, sizeof(output->stage_name),
                         CONSENSUS_STATE_STAGE_PREFIX "%.*s.stage.%ld.%u",
                         CONSENSUS_EXPORT_NAME_MAX - 48, output->final_name,
                         (long)getpid(), seq);
        if (n <= 0 || (size_t)n >= sizeof(output->stage_name) ||
            (size_t)n >= (size_t)NAME_MAX) {
            output->stage_name[0] = '\0';
            return consensus_export_fail(result, CONSENSUS_EXPORT_REFUSED,
                                         "output staging name is invalid");
        }
        output->temp_fd = openat(output->dirfd, output->stage_name,
            O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, S_IRUSR | S_IWUSR);
        if (output->temp_fd >= 0) {
            output->stage_created = true;
            return true;
        }
        if (errno != EEXIST)
            break;
    }
    output->stage_name[0] = '\0';
    return consensus_export_fail(result, CONSENSUS_EXPORT_OUTPUT_ERROR,
                                 "output staging create failed");
}

bool consensus_export_open_temp(struct consensus_export_output_binding *output,
                                sqlite3 **destination,
                                struct consensus_state_export_result *result)
{
    *destination = NULL;
    if (!output_name_absent(output, output->final_name))
        return consensus_export_fail(result, CONSENSUS_EXPORT_REFUSED,
                                     "output name appeared after descriptor bind");

#if defined(__APPLE__)
    if (!output_stage_create(output, result))
        return false;
#else
    output->temp_fd = openat(output->dirfd, ".",
        O_TMPFILE | O_RDWR | O_CLOEXEC, S_IRUSR | S_IWUSR);
    if (output->temp_fd < 0)
        return consensus_export_fail(result, CONSENSUS_EXPORT_OUTPUT_ERROR,
                                     "anonymous output staging create failed");
#endif
    struct stat created;
    if (fstat(output->temp_fd, &created) != 0 || !S_ISREG(created.st_mode) ||
        !consensus_export_staging_nlink_valid(output, created.st_nlink)) {
        return consensus_export_fail(result, CONSENSUS_EXPORT_OUTPUT_ERROR,
                                     "output staging descriptor identity invalid");
    }
    output->temp_dev = created.st_dev;
    output->temp_ino = created.st_ino;
    output_run_after_staging_create_hook(output->temp_fd);

    if (!consensus_export_output_vfs_register(output))
        return consensus_export_fail(result, CONSENSUS_EXPORT_OUTPUT_ERROR,
                                     "descriptor SQLite VFS register failed");
    int rc = sqlite3_open_v2("zcl-export-main", destination,
        SQLITE_OPEN_READWRITE | SQLITE_OPEN_NOMUTEX, output->vfs_name);
    struct stat opened;
    if (rc != SQLITE_OK || fstat(output->temp_fd, &opened) != 0 ||
        opened.st_dev != output->temp_dev || opened.st_ino != output->temp_ino ||
        !consensus_export_staging_nlink_valid(output, opened.st_nlink)) {
        (void)consensus_export_output_sqlite_close_strict(output, destination);
        return consensus_export_fail(result, CONSENSUS_EXPORT_OUTPUT_ERROR,
                                     "output SQLite descriptor open failed");
    }
    int defensive = 0;
    char *error = NULL;
    bool ok = sqlite3_db_config(*destination, SQLITE_DBCONFIG_DEFENSIVE, 1,
                                &defensive) == SQLITE_OK &&
              defensive == 1 &&
              sqlite3_exec(*destination,
                  "PRAGMA journal_mode=MEMORY;"
                  "PRAGMA synchronous=FULL;"
                  "PRAGMA temp_store=MEMORY;"
                  "PRAGMA foreign_keys=ON;"
                  "PRAGMA locking_mode=EXCLUSIVE;",
                  NULL, NULL, &error) == SQLITE_OK;
    if (error) {
        LOG_WARN(EXPORT_SUBSYS, "output durability configuration failed: %s",
                 error);
        sqlite3_free(error);
    }
    if (!ok) {
        (void)consensus_export_output_sqlite_close_strict(output, destination);
        return consensus_export_fail(result, CONSENSUS_EXPORT_OUTPUT_ERROR,
                                     "FULL-durable output setup failed");
    }
    return true;
}

static bool manifests_equal(
    const struct consensus_state_bundle_manifest *a,
    const struct consensus_state_bundle_manifest *b)
{
    return a->height == b->height &&
           a->history_complete == b->history_complete &&
           a->source_clean == b->source_clean &&
           a->validation_profile == b->validation_profile &&
           a->activation_boundary == b->activation_boundary &&
           a->utxo_count == b->utxo_count &&
           a->total_supply == b->total_supply &&
           a->anchor_count == b->anchor_count &&
           a->sprout_frontier_height == b->sprout_frontier_height &&
           a->sapling_frontier_height == b->sapling_frontier_height &&
           a->nullifier_count == b->nullifier_count &&
           a->sprout_source_cursor == b->sprout_source_cursor &&
           a->sapling_source_cursor == b->sapling_source_cursor &&
           a->nullifier_source_cursor == b->nullifier_source_cursor &&
           a->source_fold_cursor == b->source_fold_cursor &&
           memcmp(a->block_hash, b->block_hash, 32) == 0 &&
           memcmp(a->utxo_root, b->utxo_root, 32) == 0 &&
           memcmp(a->anchor_digest, b->anchor_digest, 32) == 0 &&
           memcmp(a->sprout_frontier_root, b->sprout_frontier_root, 32) == 0 &&
           memcmp(a->sapling_frontier_root, b->sapling_frontier_root, 32) == 0 &&
           memcmp(a->nullifier_digest, b->nullifier_digest, 32) == 0 &&
           memcmp(a->proof_manifest_digest, b->proof_manifest_digest, 32) == 0 &&
           memcmp(a->source_digest, b->source_digest, 32) == 0 &&
           memcmp(a->artifact_digest, b->artifact_digest, 32) == 0;
}

bool consensus_export_finalize_temp(
    struct consensus_export_output_binding *output,
    const struct consensus_state_bundle_manifest *manifest,
    struct consensus_state_export_result *result)
{
    if (!output || output->temp_fd < 0 || !output_sidecars_absent(output))
        return consensus_export_fail(result, CONSENSUS_EXPORT_OUTPUT_ERROR,
                                     "bundle staging identity/sidecar invalid");
    if (fsync(output->temp_fd) != 0 ||
        fchmod(output->temp_fd, S_IRUSR) != 0 ||
        fsync(output->temp_fd) != 0)
        return consensus_export_fail(result, CONSENSUS_EXPORT_OUTPUT_ERROR,
                                     "bundle fsync/immutable mode failed");

    struct stat before;
    if (!consensus_export_seal_readonly(output, &before))
        return consensus_export_fail(result, CONSENSUS_EXPORT_OUTPUT_ERROR,
                                     "bundle writable staging descriptor retained");
    if (!S_ISREG(before.st_mode) ||
        before.st_dev != output->temp_dev || before.st_ino != output->temp_ino ||
        !consensus_export_staging_nlink_valid(output, before.st_nlink) ||
        (before.st_mode & (S_IWUSR | S_IWGRP | S_IWOTH)) != 0)
        return consensus_export_fail(result, CONSENSUS_EXPORT_OUTPUT_ERROR,
                                     "staged bundle identity/mode invalid");
    sqlite3 *check = NULL;
    if (sqlite3_open_v2("zcl-export-main", &check,
            SQLITE_OPEN_READONLY | SQLITE_OPEN_NOMUTEX,
            output->vfs_name) != SQLITE_OK) {
        (void)consensus_export_output_sqlite_close_strict(output, &check);
        return consensus_export_fail(result, CONSENSUS_EXPORT_OUTPUT_ERROR,
                                     "immutable bundle reopen failed");
    }
    int defensive = 0;
    int trusted = 1;
    bool ok = sqlite3_db_config(check, SQLITE_DBCONFIG_DEFENSIVE, 1,
                                &defensive) == SQLITE_OK &&
              sqlite3_db_config(check, SQLITE_DBCONFIG_TRUSTED_SCHEMA, 0,
                                &trusted) == SQLITE_OK &&
              defensive == 1 && trusted == 0 &&
              sqlite3_exec(check, "PRAGMA query_only=ON", NULL, NULL, NULL) ==
                  SQLITE_OK;
    struct consensus_state_bundle_manifest reopened;
    struct consensus_state_install_result validation;
    memset(&reopened, 0, sizeof(reopened));
    memset(&validation, 0, sizeof(validation));
    if (ok)
        ok = consensus_state_bundle_validate(check, &reopened, &validation);
    if (ok)
        ok = manifests_equal(manifest, &reopened);
    if (!consensus_export_output_sqlite_close_strict(output, &check))
        ok = false;
    struct stat after;
    if (!ok || fstat(output->temp_fd, &after) != 0 ||
        before.st_dev != after.st_dev || before.st_ino != after.st_ino ||
        !consensus_export_staging_nlink_valid(output, after.st_nlink) ||
        before.st_mode != after.st_mode ||
        before.st_size != after.st_size ||
        before.st_mtim.tv_sec != after.st_mtim.tv_sec ||
        before.st_mtim.tv_nsec != after.st_mtim.tv_nsec ||
        before.st_ctim.tv_sec != after.st_ctim.tv_sec ||
        before.st_ctim.tv_nsec != after.st_ctim.tv_nsec)
        return consensus_export_fail(
            result, CONSENSUS_EXPORT_OUTPUT_ERROR,
            "independent immutable bundle validation failed");

    uint8_t sealed_digest[32];
    uint8_t after_hook_digest[32];
    if (!consensus_export_descriptor_digest(output->temp_fd, sealed_digest))
        return consensus_export_fail(result, CONSENSUS_EXPORT_OUTPUT_ERROR,
                                     "sealed bundle complete-file digest failed");
    output_run_before_link_hook();
    struct stat after_hook;
    if (!consensus_export_descriptor_digest(output->temp_fd, after_hook_digest) ||
        memcmp(sealed_digest, after_hook_digest, 32) != 0 ||
        fstat(output->temp_fd, &after_hook) != 0 ||
        after_hook.st_dev != after.st_dev || after_hook.st_ino != after.st_ino ||
        !consensus_export_staging_nlink_valid(output, after_hook.st_nlink) ||
        after_hook.st_size != after.st_size ||
        after_hook.st_mode != after.st_mode ||
        after_hook.st_mtim.tv_sec != after.st_mtim.tv_sec ||
        after_hook.st_mtim.tv_nsec != after.st_mtim.tv_nsec ||
        after_hook.st_ctim.tv_sec != after.st_ctim.tv_sec ||
        after_hook.st_ctim.tv_nsec != after.st_ctim.tv_nsec)
        return consensus_export_fail(result, CONSENSUS_EXPORT_OUTPUT_ERROR,
                                     "bundle changed after immutable validation");
    if (!output_name_absent(output, output->final_name) ||
        !output_sidecars_absent(output) ||
        !consensus_export_staging_publish(output))
        return consensus_export_fail(result, CONSENSUS_EXPORT_OUTPUT_ERROR,
                                     "atomic no-replace bundle publish failed");
    output->published = true;
    struct stat published;
    uint8_t published_digest[32];
    if (!output_final_identity_matches(output, &published) ||
        published.st_size != after.st_size ||
        published.st_mtim.tv_sec != after.st_mtim.tv_sec ||
        published.st_mtim.tv_nsec != after.st_mtim.tv_nsec ||
        published.st_ctim.tv_sec < after.st_ctim.tv_sec ||
        (published.st_ctim.tv_sec == after.st_ctim.tv_sec &&
         published.st_ctim.tv_nsec < after.st_ctim.tv_nsec) ||
        !consensus_export_descriptor_digest(output->temp_fd, published_digest) ||
        memcmp(sealed_digest, published_digest, 32) != 0 ||
        fsync(output->dirfd) != 0) {
        /* Never unlink after a separate identity check: a concurrent name
         * replacement could turn cleanup into deletion of an unrelated file.
         * The result remains refused and no activation caller exists; an
         * ambiguous fully-validated link is left for explicit inspection. */
        return consensus_export_fail(result, CONSENSUS_EXPORT_OUTPUT_ERROR,
                                     "bundle published identity/durability ambiguous");
    }
    return true;
}

bool consensus_export_digest_nonzero(const uint8_t digest[32])
{
    uint8_t any = 0;
    for (size_t i = 0; i < 32; i++)
        any |= digest[i];
    return any != 0;
}

/* Shared derive+write core used by BOTH exporter entries. Runs the proof, opens
 * the anonymous staging inode, writes the bundle, and strictly closes the dest.
 * The CALLER owns the SOURCE read transaction (a held lock+BEGIN on the owned
 * handle for the offline mint, or a private WAL-snapshot BEGIN for the live
 * exporter). *manifest is filled for finalize_temp/result on success. */
bool consensus_export_prove_write(
    sqlite3 *source,
    const struct consensus_state_snapshot_export_request *request,
    struct consensus_export_output_binding *output,
    struct consensus_state_bundle_manifest *manifest,
    struct consensus_state_export_result *result)
{
    struct consensus_state_source_receipt receipt;
    memset(&receipt, 0, sizeof(receipt));
    struct consensus_state_bundle_proof_summary
        proofs[CONSENSUS_STATE_BUNDLE_PROOF_COUNT];
    memset(proofs, 0, sizeof(proofs));
    sqlite3 *destination = NULL;

    bool ok = consensus_export_prove_source(source, request, manifest, &receipt,
                                            proofs, result);
    if (ok)
        ok = consensus_export_open_temp(output, &destination, result);
    if (ok)
        ok = consensus_export_write_bundle(source, destination, manifest,
                                           &receipt, proofs, result);
    if (destination) {
        if (!consensus_export_output_sqlite_close_strict(output, &destination) && ok) {
            (void)consensus_export_fail(result, CONSENSUS_EXPORT_OUTPUT_ERROR,
                                        "bundle close failed");
            ok = false;
        }
        destination = NULL;
    }
    return ok;
}

/* Fill the EXPORTED result on success — identical for both entries. */
void consensus_export_fill_success(
    const struct consensus_state_bundle_manifest *manifest,
    struct consensus_state_export_result *result)
{
    if (!result)
        return;
    result->status = CONSENSUS_EXPORT_EXPORTED;
    result->history_complete = true;
    result->source_clean = manifest->source_clean;
    result->validation_profile = manifest->validation_profile;
    result->height = manifest->height;
    result->utxo_count = manifest->utxo_count;
    result->anchor_count = manifest->anchor_count;
    result->nullifier_count = manifest->nullifier_count;
    memcpy(result->artifact_digest, manifest->artifact_digest, 32);
    snprintf(result->reason, sizeof(result->reason),
             "exported immutable %s height=%d source=%s profile=%s",
             CONSENSUS_STATE_BUNDLE_SCHEMA, manifest->height,
             manifest->source_clean ? "clean" : "dirty",
             manifest->validation_profile == CONSENSUS_STATE_VALIDATION_FULL
                 ? "full" : "checkpoint_fold");
}

bool consensus_state_snapshot_export(
    sqlite3 *progress_db,
    const struct consensus_state_snapshot_export_request *request,
    struct consensus_state_export_result *result)
{
    if (result)
        memset(result, 0, sizeof(*result));
    if (!progress_db || !request)
        return consensus_export_fail(result, CONSENSUS_EXPORT_REFUSED,
                                     "NULL progress_db/request");
    if (progress_store_db() != progress_db)
        return consensus_export_fail(result, CONSENSUS_EXPORT_REFUSED,
                                     "source is not the owned progress.kv handle");
    if (request->expected_height < 0 ||
        request->expected_height >= INT32_MAX ||
        !consensus_export_digest_nonzero(request->expected_block_hash))
        return consensus_export_fail(
            result, CONSENSUS_EXPORT_REFUSED,
            "invalid expected source height/hash (height=%d hash_nonzero=%d)",
            request->expected_height,
            consensus_export_digest_nonzero(request->expected_block_hash)
                ? 1 : 0);

    struct consensus_export_output_binding *output = zcl_calloc(
        1, sizeof(*output), "consensus_export_output_binding");
    if (!output)
        return consensus_export_fail(result, CONSENSUS_EXPORT_OUTPUT_ERROR,
                                     "output binding allocation failed");
    consensus_export_output_init(output);
    if (!consensus_export_output_open(request, output, result)) {
        free(output);
        return false;
    }
    consensus_export_run_after_bind_hook();

    struct consensus_state_bundle_manifest manifest;
    memset(&manifest, 0, sizeof(manifest));
    bool source_tx = false;
    bool ok = true;

    progress_store_tx_lock();
    if (sqlite3_get_autocommit(progress_db) == 0) {
        (void)consensus_export_fail(result, CONSENSUS_EXPORT_REFUSED,
                                    "source already has an open transaction");
        ok = false;
    }
    if (ok && sqlite3_exec(progress_db, "BEGIN", NULL, NULL, NULL) !=
                  SQLITE_OK) {
        (void)consensus_export_fail(result, CONSENSUS_EXPORT_STORE_ERROR,
                                    "frozen source transaction begin failed");
        ok = false;
    } else if (ok) {
        source_tx = true;
    }
    if (ok)
        ok = consensus_export_prove_write(progress_db, request, output, &manifest,
                                result);
    if (source_tx) {
        const char *finish = ok ? "COMMIT" : "ROLLBACK";
        if (sqlite3_exec(progress_db, finish, NULL, NULL, NULL) != SQLITE_OK) {
            if (ok)
                (void)consensus_export_fail(
                    result, CONSENSUS_EXPORT_STORE_ERROR,
                    "frozen source transaction close failed");
            ok = false;
            sqlite3_exec(progress_db, "ROLLBACK", NULL, NULL, NULL);
        }
    }
    progress_store_tx_unlock();

    if (ok)
        ok = consensus_export_finalize_temp(output, &manifest, result);
    if (!ok) {
        consensus_export_output_close(output);
        if (!output->abandon_on_close)
            free(output);
        return false;
    }
    consensus_export_fill_success(&manifest, result);
    consensus_export_output_close(output);
    if (!output->abandon_on_close)
        free(output);
    return true;
}
