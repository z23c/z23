/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: own installed app snapshot lifetime around the existing resident seam. */
#include "services/package_resident.h"
#include "platform/os_proc.h"
#include "platform/temp_directory.h"
#include "base/hex.h"
#include "sha3/sha3.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if !defined(_WIN32)
#include <sys/stat.h>
#include <unistd.h>
#endif
#if defined(__APPLE__)
#include <sys/clonefile.h>
#endif

void package_resident_init(struct package_resident *app)
{
    memset(app, 0, sizeof(*app));
    resident_launch_init(&app->launch);
}

struct zcl_result package_resident_close(struct package_resident *app)
{
    char error[RESIDENT_LAUNCH_ERROR_MAX] = {0};
    if (!app) return ZCL_ERR(-1, "resident-close: missing app owner");
    if (app->launch.spawned &&
        !resident_launch_cancel(&app->launch, 300, error, sizeof(error)))
        return ZCL_ERR(-1, "resident-cancel: %s", error);
    resident_launch_close(&app->launch);
#if !defined(_WIN32)
    if (app->snapshot_image[0] && unlink(app->snapshot_image) != 0 && errno != ENOENT)
        return ZCL_ERR(-1, "resident-snapshot-unlink: %s", strerror(errno));
    app->snapshot_image[0] = 0;
    if (app->snapshot_directory[0] && rmdir(app->snapshot_directory) != 0 && errno != ENOENT)
        return ZCL_ERR(-1, "resident-snapshot-directory-cleanup: %s", strerror(errno));
    app->snapshot_directory[0] = 0;
    platform_ram_scratch_release(&app->snapshot_lease);
#endif
    return ZCL_OK;
}

#if !defined(_WIN32)
static bool pr_copy(int source, int target, uint64_t length)
{
    for (uint64_t offset = 0; offset < length;) {
        unsigned char bytes[4096];
        size_t want = length - offset < sizeof(bytes) ? (size_t)(length - offset) : sizeof(bytes);
        ssize_t n = pread(source, bytes, want, (off_t)offset);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return false;
        for (ssize_t written = 0; written < n;) {
            ssize_t count = write(target, bytes + written, (size_t)(n - written));
            if (count < 0 && errno == EINTR) continue;
            if (count <= 0) return false;
            written += count;
        }
        offset += (uint64_t)n;
    }
    return true;
}

static int pr_snapshot_target(int in, int dir, bool *cloned)
{
#if defined(__APPLE__)
    if (fclonefileat(in, dir, "image", CLONE_NOFOLLOW) == 0) *cloned = true;
    else if (errno != ENOTSUP && errno != EXDEV) return -1;
#else
    (void)in;
#endif
    return openat(dir, "image", O_RDWR | O_NOFOLLOW | O_CLOEXEC |
                    (*cloned ? 0 : O_CREAT | O_EXCL), 0600);
}

static bool pr_snapshot_hash(int target, uint64_t size, char out[65])
{
    struct sha3_256_ctx hash;
    sha3_256_init(&hash);
    for (uint64_t offset = 0; offset < size;) {
        unsigned char bytes[4096];
        size_t want = size - offset < sizeof(bytes) ? (size_t)(size - offset) : sizeof(bytes);
        ssize_t n = pread(target, bytes, want, (off_t)offset);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return false;
        sha3_256_write(&hash, bytes, (size_t)n);
        offset += (uint64_t)n;
    }
    unsigned char digest[32];
    sha3_256_finalize(&hash, digest);
    zcl_hex_encode(digest, sizeof(digest), out);
    return true;
}

static bool pr_snapshot_accept(int target,
    const struct platform_positioned_file_snapshot *before,
    const struct package_resident *app, struct resident_launch_accepted *accepted)
{
    struct stat st;
    if (fstat(target, &st) != 0 || (uint64_t)st.st_size != before->size ||
        ((uint64_t)st.st_ino == before->file_low && (uint64_t)st.st_dev == before->volume))
        return false;
    if (!pr_snapshot_hash(target, before->size, accepted->image_sha3_hex)) return false;
    if (strcmp(accepted->image_sha3_hex, app->artifact.accepted.image_sha3_hex) != 0)
        return false;
    accepted->image_volume = (uint64_t)st.st_dev;
    accepted->image_low = (uint64_t)st.st_ino;
    accepted->image_high = 0;
    accepted->image_size = before->size;
    return true;
}

static bool pr_snapshot_fill(int in, int target, int dir, uint64_t size, bool cloned)
{
    return target >= 0 && (cloned || pr_copy(in, target, size)) &&
        fchmod(target, 0500) == 0 && fsync(target) == 0 && fsync(dir) == 0;
}

static bool pr_snapshot_directory(struct package_resident *app, uint64_t size)
{
    char root[128];
    if (platform_ram_scratch_private_root(root, sizeof(root)) &&
        platform_ram_scratch_reserve_private(root, size, &app->snapshot_lease)) {
        if (platform_temp_directory_create_under(root, "z23-resident-",
                app->snapshot_directory, sizeof(app->snapshot_directory))) return true;
        platform_ram_scratch_release(&app->snapshot_lease);
    }
    (void)snprintf(app->snapshot_directory, sizeof(app->snapshot_directory),
                   "/tmp/z23-resident-XXXXXX");
    if (mkdtemp(app->snapshot_directory)) return true;
    app->snapshot_directory[0] = 0;
    return false;
}

static bool pr_snapshot(struct package_resident *app,
                        struct resident_launch_accepted *accepted)
{
    struct platform_positioned_file source;
    struct platform_positioned_file_snapshot before;
    platform_positioned_file_init(&source);
    int dir = -1, target = -1;
    bool ok = false, cloned = false;
    if (!platform_positioned_file_open(&source, app->artifact.locator) ||
        !platform_positioned_file_snapshot(&source, &before) ||
        before.size != app->artifact.accepted.image_size || before.size > 64u * 1024u * 1024u)
        goto done;
    if (!pr_snapshot_directory(app, before.size)) goto done;
    dir = open(app->snapshot_directory, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (dir < 0) goto done;
    (void)snprintf(app->snapshot_image, sizeof(app->snapshot_image), "%s/image", app->snapshot_directory);
    int in = (int)platform_positioned_file_native_fd(&source);
    target = pr_snapshot_target(in, dir, &cloned);
    if (!pr_snapshot_fill(in, target, dir, before.size, cloned)) goto done;
    ok = pr_snapshot_accept(target, &before, app, accepted);
done:
    platform_positioned_file_close(&source);
    if (target >= 0 && close(target) != 0) ok = false;
    if (dir >= 0 && close(dir) != 0) ok = false;
    return ok;
}
#endif

struct zcl_result package_resident_prepare(struct package_resident *app,
    const struct package_resident_artifact *artifact)
{
    if (!app || !artifact || app->launch.spawned || app->snapshot_directory[0])
        return ZCL_ERR(-1, "resident-prepare: an unused owner and accepted artifact are required");
#if defined(_WIN32)
    return ZCL_ERR(-1, "resident-unavailable: exact process launch is not qualified on Windows");
#else
    app->artifact = *artifact;
    struct resident_launch_accepted snapshot = {0};
    char error[RESIDENT_LAUNCH_ERROR_MAX] = {0};
    if (!app->startup.platform_ms) {
        if (!resident_startup_begin(&app->startup, RESIDENT_STARTUP_PLATFORM_MS,
                RESIDENT_STARTUP_PROTOCOL_MS, error, sizeof(error)))
            return ZCL_ERR(-1, "resident-startup-budget: %s", error);
    }
    if (!resident_startup_check(&app->startup, error, sizeof(error)))
        return ZCL_ERR(-1, "resident-startup-budget: %s", error);
    if (!pr_snapshot(app, &snapshot) ||
        !resident_launch_prepare(&app->launch, app->snapshot_image, &snapshot, error, sizeof(error))) {
        struct zcl_result cleanup = package_resident_close(app);
        if (!cleanup.ok) return cleanup;
        return ZCL_ERR(-1, "resident-snapshot-refused: accepted independent bytes unavailable: %s", error);
    }
    return ZCL_OK;
#endif
}

struct zcl_result package_resident_prepare_reuse(struct package_resident *app,
    const struct package_resident_artifact *artifact)
{
    if (!app || !artifact || app->launch.spawned || !app->snapshot_image[0] ||
        strcmp(app->launch.accepted.image_sha3_hex, artifact->accepted.image_sha3_hex) != 0 ||
        app->launch.accepted.image_size != artifact->accepted.image_size)
        return ZCL_ERR(-1, "resident-reuse: idle independent snapshot of the exact artifact required");
    struct resident_launch_accepted accepted = app->launch.accepted;
    resident_launch_close(&app->launch);
    char error[RESIDENT_LAUNCH_ERROR_MAX] = {0};
    if (!resident_startup_begin(&app->startup, RESIDENT_STARTUP_PLATFORM_MS,
            RESIDENT_STARTUP_PROTOCOL_MS, error, sizeof(error)) ||
        !resident_launch_prepare(&app->launch, app->snapshot_image, &accepted, error, sizeof(error))) {
        struct zcl_result cleanup = package_resident_close(app);
        if (!cleanup.ok) return cleanup;
        return ZCL_ERR(-1, "resident-reuse: independent snapshot verification failed: %s", error);
    }
    app->artifact = *artifact;
    memset(&app->receipt, 0, sizeof(app->receipt));
    return ZCL_OK;
}

static bool pr_receipt_process_valid(const struct package_resident *app)
{
    const struct resident_receipt *r = &app->receipt;
    uint64_t token = 0;
    bool proof = false;
#if defined(__APPLE__)
    proof = strcmp(r->mapped_proof, "cdhash_suspended") == 0;
#elif defined(__linux__)
    proof = strcmp(r->mapped_proof, "proc_exe_triple") == 0 ||
            strcmp(r->mapped_proof, "fexecve_inode") == 0;
#endif
    return proof && r->pid && r->pid == app->launch.pid && r->start_token &&
        r->start_token == app->launch.start_token &&
        os_proc_pid_start_token(r->pid, &token) && token == r->start_token &&
        memcmp(r->nonce, app->launch.nonce, sizeof(r->nonce)) == 0;
}

static bool pr_receipt_image_valid(const struct package_resident *app)
{
    const struct resident_receipt *r = &app->receipt;
    const struct resident_launch_accepted *a = &app->launch.accepted;
    return memcmp(r->image_sha3_hex, app->artifact.accepted.image_sha3_hex, sizeof(r->image_sha3_hex)) == 0 &&
        r->image_volume == a->image_volume && r->image_low == a->image_low &&
        r->image_high == a->image_high && r->image_size == a->image_size;
}

struct zcl_result package_resident_start(struct package_resident *app)
{
    if (!app || app->launch.spawned || !app->snapshot_image[0])
        return ZCL_ERR(-1, "resident-start: prepared unused app required");
    char error[RESIDENT_LAUNCH_ERROR_MAX] = {0};
    char *argv[] = {app->snapshot_image, "--resident", app->launch.nonce, NULL};
    char *env[] = {"Z23_RESIDENT_STARTUP_V2=1", NULL};
    if (!resident_startup_check(&app->startup, error, sizeof(error)))
        return ZCL_ERR(-1, "resident-startup-budget: %s", error);
    if (!resident_launch_spawn(&app->launch, argv, env, &app->receipt, error, sizeof(error)))
        return ZCL_ERR(-1, "resident-spawn-refused: %s", error);
    if (!pr_receipt_process_valid(app) || !pr_receipt_image_valid(app)) {
        struct zcl_result cleanup = package_resident_close(app);
        if (!cleanup.ok) return cleanup;
        return ZCL_ERR(-1, "resident-receipt-refused: accepted image, mapped proof or process identity differs");
    }
    return ZCL_OK;
}
