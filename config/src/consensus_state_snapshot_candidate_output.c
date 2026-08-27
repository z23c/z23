/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * PURPOSE: Staging (anonymous inode on Linux, hidden exclusive name on
 * Darwin), sealing, reopen validation, and no-replace publication for
 * contained consensus-state candidates. */

#define _GNU_SOURCE

#include "consensus_state_snapshot_install_internal.h"

#include "storage/consensus_db.h"    /* CONSENSUS_DB_FILENAME + legacy name */
#include "util/log_macros.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <sqlite3.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define CANDIDATE_SUBSYS "consensus_state_candidate"

static bool candidate_name_has_prefix_ci(const char *name, const char *prefix)
{
    if (!name)
        return false;
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

/* A4: refuse an export output name that would collide with EITHER live store —
 * the consensus.db kernel authority (post-flip) or the progress.kv projection
 * store (which also stays live for address_index/txindex). */
static bool candidate_name_is_active_family(const char *name)
{
    return candidate_name_has_prefix_ci(name, CONSENSUS_DB_FILENAME) ||
           candidate_name_has_prefix_ci(name,
                                        CONSENSUS_DB_LEGACY_KERNEL_FILENAME);
}

static bool candidate_name_valid(const char *name)
{
    if (!name || !name[0] || strcmp(name, ".") == 0 ||
        strcmp(name, "..") == 0 || candidate_name_is_active_family(name))
        return false;
    size_t length = strlen(name);
    if (length >= CONSENSUS_EXPORT_NAME_MAX - 48)
        return false;
    for (size_t i = 0; i < length; i++) {
        unsigned char c = (unsigned char)name[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-'))
            return false;
    }
    return true;
}

static bool output_name_absent(
    const struct consensus_state_candidate_output *output, const char *name)
{
    struct stat st;
    errno = 0;
    return output && output->binding.dirfd >= 0 && name &&
           fstatat(output->binding.dirfd, name, &st,
                   AT_SYMLINK_NOFOLLOW) != 0 &&
           errno == ENOENT;
}

static bool output_sidecars_absent(
    const struct consensus_state_candidate_output *output, const char *name)
{
    static const char *const suffixes[] = {"-journal", "-wal", "-shm"};
    char sidecar[CONSENSUS_EXPORT_NAME_MAX + 16];
    for (size_t i = 0; i < sizeof(suffixes) / sizeof(suffixes[0]); i++) {
        int n = snprintf(sidecar, sizeof(sidecar), "%s%s", name, suffixes[i]);
        struct stat st;
        errno = 0;
        if (n <= 0 || (size_t)n >= sizeof(sidecar) ||
            fstatat(output->binding.dirfd, sidecar, &st,
                    AT_SYMLINK_NOFOLLOW) == 0 ||
            errno != ENOENT)
            return false;
    }
    return true;
}

void consensus_state_candidate_output_cleanup(
    struct consensus_state_candidate_output *output)
{
    if (!output || output->binding.abandon_on_close)
        return;
    /* Darwin: abandon the staged bytes by removing the staging name under its
     * verified identity (Linux: the anonymous inode dies with the descriptor). */
    consensus_export_staging_discard(&output->binding);
    if (output->binding.vfs_registered) {
        if (sqlite3_vfs_unregister(&output->binding.vfs) != SQLITE_OK)
            LOG_WARN(CANDIDATE_SUBSYS,
                     "candidate descriptor VFS unregister failed");
        output->binding.vfs_registered = false;
    }
    if (output->binding.temp_fd >= 0)
        (void)close(output->binding.temp_fd);
    if (output->binding.dirfd >= 0)
        (void)close(output->binding.dirfd);
    output->binding.temp_fd = -1;
    output->binding.dirfd = -1;
}

bool consensus_state_candidate_output_open(
    const struct consensus_state_candidate_request *request,
    struct consensus_state_candidate_output *output,
    struct consensus_state_candidate_result *result)
{
    memset(output, 0, sizeof(*output));
    output->binding.dirfd = -1;
    output->binding.temp_fd = -1;
    if (!request || request->output_dir_fd < 0 ||
        !candidate_name_valid(request->output_name))
        return consensus_state_candidate_fail(
            result, CONSENSUS_CANDIDATE_REFUSED,
            "candidate output directory/name is invalid");
    output->binding.dirfd =
        fcntl(request->output_dir_fd, F_DUPFD_CLOEXEC, 3);
    struct stat directory;
    if (output->binding.dirfd < 0 ||
        fstat(output->binding.dirfd, &directory) != 0 ||
        !S_ISDIR(directory.st_mode)) {
        consensus_state_candidate_output_cleanup(output);
        return consensus_state_candidate_fail(
            result, CONSENSUS_CANDIDATE_REFUSED,
            "candidate output descriptor is not a directory");
    }
    snprintf(output->binding.final_name,
             sizeof(output->binding.final_name), "%s", request->output_name);
    if (!output_name_absent(output, output->binding.final_name)) {
        consensus_state_candidate_output_cleanup(output);
        return consensus_state_candidate_fail(
            result, CONSENSUS_CANDIDATE_REFUSED,
            "candidate output already exists or is uninspectable");
    }
    return true;
}

bool consensus_state_candidate_sqlite_close_strict(
    struct consensus_state_candidate_output *output, sqlite3 **db)
{
    return consensus_export_output_sqlite_close_strict(
        output ? &output->binding : NULL, db);
}

bool consensus_state_candidate_output_sqlite_open(
    struct consensus_state_candidate_output *output, sqlite3 **db)
{
    struct consensus_state_export_result bridge;
    memset(&bridge, 0, sizeof(bridge));
    if (!consensus_export_open_temp(&output->binding, db, &bridge))
        return false;
    int trusted = 1;
    if (sqlite3_db_config(*db, SQLITE_DBCONFIG_TRUSTED_SCHEMA, 0,
                          &trusted) != SQLITE_OK || trusted != 0) {
        (void)consensus_state_candidate_sqlite_close_strict(output, db);
        return false;
    }
    return true;
}

#ifdef ZCL_TESTING
static void (*g_candidate_before_link_hook)(void *) = NULL;
static void *g_candidate_before_link_ctx = NULL;

void consensus_state_snapshot_candidate_test_set_before_link_hook(
    void (*hook)(void *), void *ctx)
{
    g_candidate_before_link_hook = hook;
    g_candidate_before_link_ctx = ctx;
}

static void candidate_run_before_link_hook(void)
{
    void (*hook)(void *) = g_candidate_before_link_hook;
    void *ctx = g_candidate_before_link_ctx;
    g_candidate_before_link_hook = NULL;
    g_candidate_before_link_ctx = NULL;
    if (hook)
        hook(ctx);
}
#else
static void candidate_run_before_link_hook(void) { }
#endif

bool consensus_state_candidate_output_finalize(
    struct consensus_state_candidate_output *output,
    const struct consensus_state_bundle_manifest *manifest,
    const uint8_t admission_receipt[32],
    enum consensus_state_candidate_failpoint failpoint,
    struct consensus_state_candidate_result *result)
{
    int fd = output->binding.temp_fd;
    if (!output_sidecars_absent(output, output->binding.final_name) ||
        fsync(fd) != 0 || fchmod(fd, S_IRUSR) != 0 || fsync(fd) != 0)
        return consensus_state_candidate_fail(
            result, CONSENSUS_CANDIDATE_OUTPUT_ERROR,
            "candidate staging durability/seal failed");
    struct stat sealed;
    if (!consensus_export_seal_readonly(&output->binding, &sealed))
        return consensus_state_candidate_fail(
            result, CONSENSUS_CANDIDATE_OUTPUT_ERROR,
            "candidate writable staging descriptor could not be retired");
    fd = output->binding.temp_fd;
    if (!S_ISREG(sealed.st_mode) ||
        !consensus_export_staging_nlink_valid(&output->binding,
                                              sealed.st_nlink) ||
        sealed.st_dev != output->binding.temp_dev ||
        sealed.st_ino != output->binding.temp_ino ||
        (sealed.st_mode & (S_IWUSR | S_IWGRP | S_IWOTH)) != 0)
        return consensus_state_candidate_fail(
            result, CONSENSUS_CANDIDATE_OUTPUT_ERROR,
            "candidate anonymous staging identity invalid");

    sqlite3 *check = NULL;
    bool ok = sqlite3_open_v2("zcl-export-main", &check,
        SQLITE_OPEN_READONLY | SQLITE_OPEN_NOMUTEX,
        output->binding.vfs_name) == SQLITE_OK;
    int defensive = 0;
    int trusted = 1;
    if (ok)
        ok = sqlite3_db_config(check, SQLITE_DBCONFIG_DEFENSIVE, 1,
                               &defensive) == SQLITE_OK && defensive == 1 &&
             sqlite3_db_config(check, SQLITE_DBCONFIG_TRUSTED_SCHEMA, 0,
                               &trusted) == SQLITE_OK && trusted == 0 &&
             sqlite3_exec(check, "PRAGMA query_only=ON", NULL, NULL, NULL) ==
                 SQLITE_OK &&
             consensus_state_candidate_validate_reopened(
                 check, manifest, admission_receipt, result);
    if (!consensus_state_candidate_sqlite_close_strict(output, &check))
        ok = false;
    struct stat after;
    if (!ok || fstat(fd, &after) != 0 || sealed.st_dev != after.st_dev ||
        sealed.st_ino != after.st_ino ||
        !consensus_export_staging_nlink_valid(&output->binding,
                                              after.st_nlink) ||
        sealed.st_size != after.st_size ||
        sealed.st_mode != after.st_mode ||
        sealed.st_mtim.tv_sec != after.st_mtim.tv_sec ||
        sealed.st_mtim.tv_nsec != after.st_mtim.tv_nsec ||
        sealed.st_ctim.tv_sec != after.st_ctim.tv_sec ||
        sealed.st_ctim.tv_nsec != after.st_ctim.tv_nsec)
        return consensus_state_candidate_fail(
            result, CONSENSUS_CANDIDATE_OUTPUT_ERROR,
            "independent immutable candidate validation failed");
    if (failpoint == CONSENSUS_CANDIDATE_FAIL_AFTER_REOPEN)
        return consensus_state_candidate_fail(
            result, CONSENSUS_CANDIDATE_INJECTED_FAILURE,
            "injected failure after candidate reopen");
    if (!consensus_export_descriptor_digest(fd, result->candidate_file_digest))
        return consensus_state_candidate_fail(
            result, CONSENSUS_CANDIDATE_OUTPUT_ERROR,
            "candidate complete-file digest failed");
    candidate_run_before_link_hook();
    uint8_t after_hook_digest[32];
    struct stat after_hook;
    if (!consensus_export_descriptor_digest(fd, after_hook_digest) ||
        memcmp(after_hook_digest, result->candidate_file_digest, 32) != 0 ||
        fstat(fd, &after_hook) != 0 || after_hook.st_dev != sealed.st_dev ||
        after_hook.st_ino != sealed.st_ino ||
        !consensus_export_staging_nlink_valid(&output->binding,
                                              after_hook.st_nlink) ||
        after_hook.st_size != sealed.st_size ||
        after_hook.st_mode != sealed.st_mode ||
        after_hook.st_mtim.tv_sec != sealed.st_mtim.tv_sec ||
        after_hook.st_mtim.tv_nsec != sealed.st_mtim.tv_nsec ||
        after_hook.st_ctim.tv_sec != sealed.st_ctim.tv_sec ||
        after_hook.st_ctim.tv_nsec != sealed.st_ctim.tv_nsec)
        return consensus_state_candidate_fail(
            result, CONSENSUS_CANDIDATE_OUTPUT_ERROR,
            "candidate changed after immutable digest");
    if (!output_name_absent(output, output->binding.final_name) ||
        !output_sidecars_absent(output, output->binding.final_name) ||
        !consensus_export_staging_publish(&output->binding))
        return consensus_state_candidate_fail(
            result, CONSENSUS_CANDIDATE_OUTPUT_ERROR,
            "candidate atomic no-replace link failed");
    output->binding.published = true;
    struct stat final;
    uint8_t published_digest[32];
    if (fstatat(output->binding.dirfd, output->binding.final_name, &final,
                AT_SYMLINK_NOFOLLOW) != 0 || !S_ISREG(final.st_mode) ||
        !output_sidecars_absent(output, output->binding.final_name) ||
        final.st_dev != sealed.st_dev || final.st_ino != sealed.st_ino ||
        final.st_nlink != 1 || final.st_size != sealed.st_size ||
        (final.st_mode & (S_IWUSR | S_IWGRP | S_IWOTH)) != 0 ||
        !consensus_export_descriptor_digest(fd, published_digest) ||
        memcmp(published_digest, result->candidate_file_digest, 32) != 0 ||
        fsync(output->binding.dirfd) != 0)
        return consensus_state_candidate_fail(
            result, CONSENSUS_CANDIDATE_OUTPUT_ERROR,
            "candidate final inode/directory durability ambiguous");
    return true;
}
