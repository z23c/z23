/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * Purpose: Immutable compiler files and a fail-closed private Linux root. */
#define _GNU_SOURCE
#include "platform/os_sandbox.h"
#if defined(__linux__)
#include "sha3/sha3.h"
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>
#define KIT_SEALS (F_SEAL_WRITE|F_SEAL_GROW|F_SEAL_SHRINK|F_SEAL_SEAL)
#define KIT_PATH 4096
static struct zcl_result kit_error(const char *stage)
{
    int error = errno;
    return ZCL_ERR(-1, "kit root %s: errno=%d (%s)", stage, error, strerror(error));
}
static bool kit_write_all(int fd, const uint8_t *bytes, size_t length)
{
    size_t offset = 0;
    while (offset < length) {
        ssize_t n = write(fd, (const unsigned char *)bytes + offset, length - offset);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return false;
        offset += (size_t)n;
    }
    return true;
}
static bool kit_hash_fd(int fd, size_t length, const uint8_t blob[32])
{
    struct stat st;
    if (fstat(fd, &st) || st.st_size < 0 || (uint64_t)st.st_size != length) return false;
    struct sha3_256_ctx hash; uint8_t digest[32], tag = 0x20, buffer[16384];
    sha3_256_init(&hash); sha3_256_write(&hash, &tag, 1); size_t offset = 0;
    while (offset < length) {
        size_t want = length - offset < sizeof(buffer) ? length - offset : sizeof(buffer);
        ssize_t n = pread(fd, buffer, want, (off_t)offset);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return false;
        sha3_256_write(&hash, buffer, (size_t)n); offset += (size_t)n;
    }
    sha3_256_finalize(&hash, digest);
    if (memcmp(digest, blob, 32)) { errno = EBADMSG; return false; }
    return true;
}
struct zcl_result os_sandbox_kit_capture(const void *bytes, size_t length,
    uint32_t mode, const uint8_t blob[32], int *out)
{
    if (!out || *out != -1 || !blob || (!bytes && length) ||
        length > (256u << 20) || !S_ISREG(mode) || (mode & 07000))
        return ZCL_ERR(-1, "kit file: invalid bounded regular-file input");
    int fd = memfd_create("z23-kit", MFD_CLOEXEC|MFD_ALLOW_SEALING);
    if (fd < 0) return kit_error("memfd");
    if (!kit_write_all(fd, bytes, length) || fchmod(fd, 0444 | (mode & 0111)) ||
        fcntl(fd, F_ADD_SEALS, KIT_SEALS) || !kit_hash_fd(fd, length, blob)) {
        struct zcl_result error = kit_error("capture/seal/rehash"); close(fd); return error;
    }
    *out = fd; return ZCL_OK;
}
struct zcl_result os_sandbox_kit_backing_create(int *out)
{
    if (!out || *out != -1) return ZCL_ERR(-1, "kit backing: invalid output");
    int fd = memfd_create("z23-kit", MFD_CLOEXEC|MFD_ALLOW_SEALING);
    if (fd < 0) return kit_error("backing memfd");
    *out = fd; return ZCL_OK;
}
struct zcl_result os_sandbox_kit_backing_append(int fd, const void *bytes, size_t length)
{
    if ((!bytes && length) || !kit_write_all(fd, bytes, length)) return kit_error("backing write");
    return ZCL_OK;
}
struct zcl_result os_sandbox_kit_backing_seal(int fd)
{
    if (fcntl(fd, F_ADD_SEALS, KIT_SEALS)) return kit_error("backing seal");
    return ZCL_OK;
}
static bool kit_component(const char *part, size_t n)
{
    if (!n || (n == 1 && part[0] == '.') || (n == 2 && part[0] == '.' && part[1] == '.')) return false;
    for (size_t i = 0; i < n; ++i) if ((unsigned char)part[i] < 32) return false;
    return true;
}
static bool kit_relative(const char *path)
{
    if (!path || !*path || *path == '/' || strlen(path) >= KIT_PATH) return false;
    const char *part = path;
    for (const char *p = path; ; ++p) {
        if (*p != '/' && *p) continue;
        size_t n = (size_t)(p - part);
        if (!kit_component(part, n)) return false;
        if (!*p) return true;
        part = p + 1;
    }
}
static bool kit_directory(const char *path)
{
    struct stat st;
    return (mkdir(path, 0700) == 0 || errno == EEXIST) &&
        lstat(path, &st) == 0 && S_ISDIR(st.st_mode);
}
static bool kit_parents(char *path)
{
    for (char *p = path + 1; *p; ++p) {
        if (*p != '/') continue;
        *p = 0; bool ok = kit_directory(path); *p = '/';
        if (!ok) return false;
    }
    return true;
}
static bool kit_bind(const char *source, const char *target, bool readonly)
{
    return mount(source, target, NULL, MS_BIND, NULL) == 0 &&
        mount(NULL, target, NULL, MS_BIND|MS_REMOUNT|MS_NOSUID|MS_NODEV|
            (readonly ? MS_RDONLY : 0), NULL) == 0;
}
static bool kit_copy_fd(int source, int destination, size_t start, size_t length)
{
    uint8_t buffer[16384]; size_t offset = 0;
    while (offset < length) {
        size_t want = length - offset < sizeof(buffer) ? length - offset : sizeof(buffer);
        ssize_t got;
        do { got = pread(source, buffer, want, (off_t)(start + offset)); } while (got < 0 && errno == EINTR);
        if (got <= 0 || !kit_write_all(destination, buffer, (size_t)got)) return false;
        offset += (size_t)got;
    }
    return true;
}
static bool kit_sealed_stat(const struct os_sandbox_kit_file *file, struct stat *st)
{
    int seals = fcntl(file->fd, F_GET_SEALS);
    return seals >= 0 && (seals & KIT_SEALS) == KIT_SEALS &&
        fstat(file->fd, st) == 0 && S_ISREG(st->st_mode) &&
        st->st_size >= 0 && (uint64_t)st->st_size <= (256u << 20);
}
struct kit_slice { size_t start, length; uint32_t mode; };
static bool kit_slice_metadata(const struct os_sandbox_kit_file *file, struct kit_slice *slice)
{
    struct stat st;
    if (!kit_relative(file->path) || !kit_sealed_stat(file, &st)) return false;
    slice->start = file->slice ? file->offset : 0;
    slice->length = file->slice ? file->length : (size_t)st.st_size;
    slice->mode = file->slice ? file->mode : (uint32_t)st.st_mode;
    size_t start = slice->start, length = slice->length;
    return S_ISREG(slice->mode) && !(slice->mode & 07000) && start <= (size_t)st.st_size &&
        length <= (size_t)st.st_size - start && (off_t)start >= 0 &&
        (size_t)(off_t)start == start && (off_t)(start + length) >= 0 &&
        (size_t)(off_t)(start + length) == start + length;
}
static bool kit_file(const struct os_sandbox_kit_file *file, const char *root)
{
    char target[KIT_PATH]; struct kit_slice slice;
    if (!kit_slice_metadata(file, &slice)) return false;
    int n = snprintf(target, sizeof(target), "%s/%s", root, file->path);
    if (n < 0 || (size_t)n >= sizeof(target) || !kit_parents(target)) return false;
    int fd = open(target, O_RDWR|O_CREAT|O_EXCL|O_CLOEXEC|O_NOFOLLOW, 0600);
    if (fd < 0) return false;
    /* Copy sealed bytes into private tmpfs and rehash before the read-only pivot. */
    bool ok = kit_copy_fd(file->fd, fd, slice.start, slice.length) &&
        kit_hash_fd(fd, slice.length, file->blob) && fchmod(fd, 0444 | (slice.mode & 0111)) == 0;
    if (close(fd)) ok = false;
    return ok;
}
#if defined(ZCL_TESTING)
bool os_sandbox_test_kit_file(const struct os_sandbox_kit_file *file, const char *root)
{
    return kit_file(file, root);
}
#endif
static bool kit_mount_at(const char *root, const char *name, const char *source,
    bool readonly, const char *type, const char *options)
{
    char path[KIT_PATH];
    int n = snprintf(path, sizeof(path), "%s/%s", root, name);
    if (n <= 0 || (size_t)n >= sizeof(path) || !kit_directory(path)) return false;
    if (type) return mount(source, path, type, MS_NOSUID|MS_NODEV|MS_NOEXEC|
        (readonly ? MS_RDONLY : 0), options) == 0;
    return !source || kit_bind(source, path, readonly);
}
static bool kit_special(const struct os_sandbox_kit_root *root)
{
    if (!kit_mount_at(root->mount_dir, "source", root->source_dir, true, NULL, NULL) ||
        !kit_mount_at(root->mount_dir, "work", root->work_dir, false, NULL, NULL) ||
        !kit_mount_at(root->mount_dir, "tmp", "tmpfs", false, "tmpfs", "size=64m,mode=1777") ||
        /* No procfs: the namespace reaper retains its pre-pivot view. An empty
         * /proc prevents exposing that view through /proc/1/{root,cwd,fd}. */
        !kit_mount_at(root->mount_dir, "proc", NULL, true, NULL, NULL) ||
        !kit_mount_at(root->mount_dir, "dev", NULL, true, NULL, NULL)) return false;
    char path[KIT_PATH]; int n = snprintf(path, sizeof(path), "%s/dev/null", root->mount_dir);
    if (n <= 0 || (size_t)n >= sizeof(path)) return false;
    int fd = open(path, O_CREAT|O_EXCL|O_WRONLY|O_CLOEXEC, 0600);
    if (fd < 0 || close(fd)) return false;
    /* The sole host device exception, installed before dropping the old root. */
    return mount("/dev/null", path, NULL, MS_BIND, NULL) == 0;
}
static struct zcl_result kit_namespaces(int report_fd)
{
    if (prctl(PR_SET_DUMPABLE, 1, 0, 0, 0) || os_sandbox_pidns_enter_clean(report_fd))
        return kit_error("user/PID namespace");
    if (unshare(CLONE_NEWNS|CLONE_NEWNET|CLONE_NEWIPC|CLONE_NEWUTS))
        return kit_error("mount/network namespace");
    if (mount(NULL, "/", NULL, MS_REC|MS_PRIVATE, NULL)) return kit_error("private propagation");
    return ZCL_OK;
}
static struct zcl_result kit_pivot(const struct os_sandbox_kit_root *root)
{
    char old[KIT_PATH]; int n = snprintf(old, sizeof(old), "%s/.old-root", root->mount_dir);
    if (n <= 0 || (size_t)n >= sizeof(old) || mkdir(old, 0700) || chdir(root->mount_dir))
        return kit_error("root pivot preparation");
    if (syscall(SYS_pivot_root, ".", ".old-root") || chdir("/") ||
        umount2("/.old-root", MNT_DETACH) || rmdir("/.old-root")) return kit_error("root pivot");
    if (mount(NULL, "/", NULL, MS_REMOUNT|MS_RDONLY|MS_NOSUID|MS_NODEV, NULL))
        return kit_error("read-only root");
    return ZCL_OK;
}
struct zcl_result os_sandbox_kit_enter(const struct os_sandbox_kit_root *root,
    int report_fd)
{
    if (!root || !root->files || !root->count || root->count > 4096 ||
        !root->mount_dir || !root->source_dir)
        return ZCL_ERR(-1, "kit root: missing bounded fixed mappings");
    struct zcl_result entered = kit_namespaces(report_fd);
    if (!entered.ok) return entered;
    if (mount("tmpfs", root->mount_dir, "tmpfs", MS_NOSUID|MS_NODEV, "size=272m,mode=0700"))
        return kit_error("private root mount");
    for (size_t i = 0; i < root->count; ++i)
        if (!kit_file(&root->files[i], root->mount_dir)) return kit_error("sealed regular-file materialization");
    if (!kit_special(root)) return kit_error("fixed namespace mappings");
    return kit_pivot(root);
}
#else
struct zcl_result os_sandbox_kit_backing_create(int *fd)
{ (void)fd; return ZCL_ERR(-1, "sealed compiler kits require Linux"); }
struct zcl_result os_sandbox_kit_backing_append(int fd, const void *bytes, size_t length)
{ (void)fd; (void)bytes; (void)length; return ZCL_ERR(-1, "sealed compiler kits require Linux"); }
struct zcl_result os_sandbox_kit_backing_seal(int fd)
{ (void)fd; return ZCL_ERR(-1, "sealed compiler kits require Linux"); }
struct zcl_result os_sandbox_kit_capture(const void *bytes, size_t length,
    uint32_t mode, const uint8_t blob[32], int *fd)
{
    (void)bytes; (void)length; (void)mode; (void)blob; (void)fd;
    return ZCL_ERR(-1, "sealed compiler kits require Linux");
}
struct zcl_result os_sandbox_kit_enter(const struct os_sandbox_kit_root *root, int report_fd)
{
    (void)root; (void)report_fd; return ZCL_ERR(-1, "private compiler roots require Linux");
}
#endif
