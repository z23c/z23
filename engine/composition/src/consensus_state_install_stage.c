/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: retain exact admitted bundle bytes before the wallet fence. */
#include "consensus_state_install_stage.h"
#include "consensus_state_snapshot_install_internal.h"
#include "config/consensus_state_snapshot_install.h"
#include "config/boot_datadir_lock.h"
#include "wallet/wallet_sqlite.h"
#include "util/safe_alloc.h"
#include "base/hex.h"
#include <errno.h>
#include <fcntl.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#if !defined(_WIN32)
#include "platform/fd_path.h"
#include "platform/rename_compat.h"
#include <dirent.h>
#include <limits.h>
#include <sys/stat.h>
#include <unistd.h>

static _Atomic unsigned g_stage_nonce;

static bool cis_private_dir(int fd)
{
    struct stat st;
    return !fstat(fd, &st) && S_ISDIR(st.st_mode) && st.st_uid == geteuid() && !(st.st_mode & 0077);
}
static bool cis_named_identity(int dir, const char *name, int fd)
{
    struct stat a, b;
    return !fstat(fd, &a) && !fstatat(dir, name, &b, AT_SYMLINK_NOFOLLOW) &&
        S_ISREG(a.st_mode) && S_ISREG(b.st_mode) && a.st_dev == b.st_dev && a.st_ino == b.st_ino &&
        a.st_uid == geteuid() && a.st_nlink == 1;
}
static bool cis_named_matches(int dir, const char *name, int fd)
{
    struct stat a;
    return cis_named_identity(dir, name, fd) && !fstat(fd, &a) && !(a.st_mode & 0277);
}
static bool cis_admit(int dir, const char *name, const uint8_t whole[32],
                      const uint8_t logical[32], struct consensus_state_artifact_evidence **admitted)
{
    char path[4096];
    int fd = openat(dir, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return false;
    struct consensus_state_artifact_evidence *copy = NULL;
    uint8_t got_whole[32], got_logical[32];
    bool ok = cis_named_matches(dir, name, fd) && platform_dirfd_child_path(path, sizeof(path), dir, name) &&
        consensus_state_artifact_evidence_open(path, -1, &copy).ok &&
        consensus_state_artifact_evidence_file_digest(copy, got_whole) &&
        consensus_state_artifact_evidence_digest(copy, got_logical) &&
        !memcmp(whole, got_whole, 32) && !memcmp(logical, got_logical, 32) &&
        cis_named_matches(dir, name, fd) && !fsync(fd);
    if (close(fd)) ok = false;
    if (ok && admitted) { *admitted = copy; copy = NULL; }
    if (!consensus_state_artifact_evidence_close(&copy)) ok = false;
    return ok;
}
static bool cis_verify(int dir, const char *name, const uint8_t whole[32], const uint8_t logical[32])
{ return cis_admit(dir, name, whole, logical, NULL); }
static bool cis_names(const struct consensus_state_bundle_manifest *m, const uint8_t digest[32],
                      char *final, size_t final_cap, char *temp, size_t temp_cap)
{
    char hash[65];
    zcl_hex_encode(digest, 32, hash);
    unsigned nonce = atomic_fetch_add(&g_stage_nonce, 1);
    int a = snprintf(final, final_cap, "retained-%d-%s.sqlite", (int)m->height, hash);
    int b = snprintf(temp, temp_cap, ".retained-%ld-%u.part", (long)getpid(), nonce);
    return a > 0 && (size_t)a < final_cap && b > 0 && (size_t)b < temp_cap;
}
static bool cis_prepare_copy(int dir, const char *temp, int fd,
    const struct consensus_state_artifact_evidence *source, const uint8_t whole[32], const uint8_t logical[32])
{
    return consensus_state_artifact_evidence_copy_to_fd(source, fd) && !fsync(fd) &&
        !fchmod(fd, 0400) && !fsync(fd) && cis_named_matches(dir, temp, fd) &&
        cis_verify(dir, temp, whole, logical);
}
static bool cis_directories_unchanged(int root, int dir, const char *datadir)
{
    struct stat opened, named;
    if (fstat(dir, &opened) || fstatat(root, "bundles", &named, AT_SYMLINK_NOFOLLOW) ||
        !S_ISDIR(named.st_mode) || opened.st_dev != named.st_dev || opened.st_ino != named.st_ino ||
        !boot_datadir_lock_matches_fd(root)) return false;
    struct stat root_opened, root_named;
    return !fstat(root, &root_opened) && !lstat(datadir, &root_named) &&
        S_ISDIR(root_named.st_mode) && root_opened.st_dev == root_named.st_dev &&
        root_opened.st_ino == root_named.st_ino;
}
static bool cis_copy_publish(int dir, const char *temp, const char *final,
    const struct consensus_state_artifact_evidence *source, const uint8_t whole[32], const uint8_t logical[32])
{
    int fd = openat(dir, temp, O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) return false;
    bool published = false;
    bool ok = cis_prepare_copy(dir, temp, fd, source, whole, logical);
    if (ok && !platform_renameat_noreplace(dir, temp, dir, final)) {
        published = true;
        ok = cis_named_matches(dir, final, fd) && !fsync(dir);
    } else if (ok && errno == EEXIST) {
        ok = cis_verify(dir, final, whole, logical) && !fsync(dir);
    } else ok = false;
    if (!published && cis_named_identity(dir, temp, fd)) (void)unlinkat(dir, temp, 0);
    if (close(fd)) ok = false;
    return ok;
}
static bool cis_prepare_names(const char *datadir, const struct consensus_state_artifact_evidence *source,
    char *out, size_t cap, char final[160], char temp[96], uint8_t whole[32], uint8_t logical[32])
{
    struct consensus_state_bundle_manifest m;
    if (!consensus_state_artifact_evidence_manifest_copy(source, &m) ||
        !consensus_state_artifact_evidence_file_digest(source, whole) ||
        !consensus_state_artifact_evidence_digest(source, logical)) return false;
    if (!cis_names(&m, whole, final, 160, temp, 96)) return false;
    int n = snprintf(out, cap, "%s/bundles/%s", datadir, final);
    if (n < 0 || (size_t)n >= cap) { out[0] = 0; return false; }
    return true;
}
static bool cis_open_dirs(const char *datadir, int *root_out, int *dir_out)
{
    int root = open(datadir, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (root < 0 || !cis_private_dir(root) || !boot_datadir_lock_matches_fd(root)) {
        if (root >= 0) close(root);
        return false;
    }
    bool made = mkdirat(root, "bundles", 0700) == 0;
    if (!made && errno != EEXIST) { close(root); return false; }
    *root_out = root;
    *dir_out = openat(root, "bundles", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    return true;
}
static bool cis_finish_opened(int root, int dir, const char *datadir,
    const struct consensus_state_artifact_evidence *source, const char *final, const char *temp,
    const uint8_t whole[32], const uint8_t logical[32], struct consensus_state_artifact_evidence **staged)
{
    bool ok = dir >= 0 && cis_private_dir(dir) && !fsync(root) &&
        (cis_verify(dir, final, whole, logical) || cis_copy_publish(dir, temp, final, source, whole, logical)) &&
        cis_admit(dir, final, whole, logical, staged) && !fsync(dir);
    if (ok) ok = cis_directories_unchanged(root, dir, datadir);
    if (dir >= 0 && close(dir)) ok = false;
    if (close(root)) ok = false;
    return ok;
}
static bool cis_stage_platform_arm(const char *datadir,
    const struct consensus_state_artifact_evidence *source, char *out, size_t cap,
    struct consensus_state_artifact_evidence **staged)
{
    if (out && cap) out[0] = 0;
    if (staged) *staged = NULL;
    if (!datadir || !source || !out || !cap || !staged) return false;
    uint8_t whole[32], logical[32]; char final[160], temp[96];
    if (!cis_prepare_names(datadir, source, out, cap, final, temp, whole, logical)) return false;
    int root, dir;
    if (!cis_open_dirs(datadir, &root, &dir)) { out[0] = 0; return false; }
    bool ok = cis_finish_opened(root, dir, datadir, source, final, temp, whole, logical, staged);
    if (!ok) { out[0] = 0; if (*staged) (void)consensus_state_artifact_evidence_close(staged); }
    return ok;
}
static bool cis_old_matches_platform_arm(const char *path, const struct wallet_cutover_binding *expected)
{
    struct consensus_state_artifact_evidence *evidence = NULL;
    if (!path || !expected || !consensus_state_artifact_evidence_open(path, -1, &evidence).ok) return false;
    struct consensus_state_bundle_manifest manifest;
    bool ok = consensus_state_artifact_evidence_manifest_copy(evidence, &manifest) &&
        manifest.height == expected->target_height &&
        memcmp(manifest.block_hash, expected->target_hash, 32) == 0 &&
        memcmp(manifest.artifact_digest, expected->artifact_digest, 32) == 0;
    return consensus_state_artifact_evidence_close(&evidence) && ok;
}

static char *cis_old_find_platform_arm(const char *datadir,
    const struct wallet_cutover_binding *expected)
{
    if (!datadir || !expected) return NULL;
    char directory[PATH_MAX];
    int n = snprintf(directory, sizeof(directory), "%s/bundles", datadir);
    if (n < 0 || (size_t)n >= sizeof(directory)) return NULL;
    DIR *dir = opendir(directory);
    if (!dir) return NULL;
    char *found = NULL;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        size_t len = strlen(entry->d_name);
        if (len < 8 || strcmp(entry->d_name + len - 7, ".sqlite") != 0) continue;
        char path[PATH_MAX];
        int written = snprintf(path, sizeof(path), "%s/%s", directory, entry->d_name);
        if (written < 0 || (size_t)written >= sizeof(path)) continue;
        if (!cis_old_matches_platform_arm(path, expected)) continue;
        found = zcl_malloc((size_t)written + 1, "old cutover bundle path");
        if (found) memcpy(found, path, (size_t)written + 1);
        break;
    }
    closedir(dir);
    return found;
}

#else
static bool cis_old_matches_platform_arm(const char *path, const struct wallet_cutover_binding *expected)
{ (void)path; (void)expected; return false; }
static char *cis_old_find_platform_arm(const char *datadir, const struct wallet_cutover_binding *expected)
{ (void)datadir; (void)expected; return NULL; }
static bool cis_stage_platform_arm(const char *datadir,
    const struct consensus_state_artifact_evidence *source, char *out, size_t cap,
    struct consensus_state_artifact_evidence **staged)
{ (void)datadir; (void)source; if (out && cap) out[0] = 0; if (staged) *staged = NULL; return false; }
#endif

bool consensus_state_install_stage(const char *datadir,
    const struct consensus_state_artifact_evidence *source, char *out, size_t cap,
    struct consensus_state_artifact_evidence **staged)
{ return cis_stage_platform_arm(datadir, source, out, cap, staged); }
bool consensus_state_old_artifact_matches(const char *path,
    const struct wallet_cutover_binding *expected)
{ return cis_old_matches_platform_arm(path, expected); }
char *consensus_state_find_old_retry_bundle(const char *datadir,
    const struct wallet_cutover_binding *expected)
{ return cis_old_find_platform_arm(datadir, expected); }

bool consensus_state_stage_evidence_matches(const struct consensus_state_artifact_evidence *artifact,
    const uint8_t whole[32], const uint8_t logical[32])
{
    uint8_t actual_whole[32], actual_logical[32];
    return artifact && whole && logical &&
        consensus_state_artifact_evidence_file_digest(artifact, actual_whole) &&
        consensus_state_artifact_evidence_digest(artifact, actual_logical) &&
        memcmp(whole, actual_whole, 32) == 0 && memcmp(logical, actual_logical, 32) == 0;
}
