/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: proves file_copy() produces a private, byte-identical, bounded
 * copy and refuses a directory destination.
 *
 * The `_WIN32` arm (dir_copy() refuses without creating the tree;
 * block_files_clean() spares blk*.dat) lives on as the `file_ops_copy` entry
 * in platform/modules/platform/tests/windows_acceptance.mk, which
 * cross-links it for Windows with a no-op zcl_tree_remove() stub. */
#include "test/test_core.h"

#include "config/file_ops.h"
#include "platform/positioned_file.h"
#include "platform/private_directory.h"
#include "platform/private_file.h"

#include <stdio.h>
#include <string.h>
#if defined(__APPLE__)
#include "platform/file_clone.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#endif

static int file_ops_copy_probe(const char *datadir)
{
    if (!platform_private_directory_ensure(datadir))
        return 2;
    char source[1024], target[1024], directory_target[1024];
    if (snprintf(source, sizeof(source), "%s/source.bin", datadir) <= 0 ||
        snprintf(target, sizeof(target), "%s/target.bin", datadir) <= 0 ||
        snprintf(directory_target, sizeof(directory_target), "%s/directory",
                 datadir) <= 0)
        return 3;
    struct platform_private_file file;
    platform_private_file_init(&file);
    static const char payload[] = "stable-copy-payload";
    if (!platform_private_file_create(source, &file) ||
        !platform_private_file_write_at(&file, payload, sizeof(payload), 0) ||
        !platform_private_file_flush(&file))
        return 4;
    platform_private_file_close(&file);
    if (!platform_private_directory_ensure(directory_target) ||
        file_copy(source, directory_target) || !file_copy(source, target))
        return 5;
    struct platform_positioned_file copied;
    char actual[sizeof(payload)];
    platform_positioned_file_init(&copied);
    bool ok = platform_positioned_file_open(&copied, target) &&
              platform_positioned_file_is_private(&copied) &&
              platform_positioned_file_read(&copied, actual, sizeof(actual),
                                             0) == (int64_t)sizeof(actual) &&
              memcmp(actual, payload, sizeof(payload)) == 0;
    platform_positioned_file_close(&copied);
    return ok ? 0 : 8;
}

#if defined(__APPLE__)
/* Device offset of byte 0. F_LOG2PHYS follows the current file offset, so
 * measure a saved position and put the descriptor back. */
static int clone_phys(int fd, off_t *out)
{
    struct log2phys phys;
    off_t saved;
    memset(&phys, 0, sizeof phys);
    saved = lseek(fd, 0, SEEK_CUR);
    if (saved < 0 || lseek(fd, 0, SEEK_SET) != 0) return -1;
    if (fcntl(fd, F_LOG2PHYS, &phys) != 0) {
        (void)lseek(fd, saved, SEEK_SET);
        return -1;
    }
    if (lseek(fd, saved, SEEK_SET) < 0) return -1;
    *out = phys.l2p_devoffset;
    return 0;
}

static int clone_fill(int fd, size_t n, unsigned char mark)
{
    unsigned char buf[65536];
    size_t left = n;
    memset(buf, 0xa5, sizeof buf);
    buf[0] = mark;
    while (left) {
        size_t chunk = left < sizeof buf ? left : sizeof buf;
        if (write(fd, buf, chunk) != (ssize_t)chunk) return -1;
        if (left == n) buf[0] = 0xa5;
        left -= chunk;
    }
    return fsync(fd) == 0 ? 0 : -1;
}

static long long clone_us(struct timespec start)
{
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (long long)(now.tv_sec - start.tv_sec) * 1000000LL +
           (long long)(now.tv_nsec - start.tv_nsec) / 1000LL;
}

static int clone_open_pair(const char *dir, int *src, int *dst, char *dst_path,
                           size_t cap)
{
    char src_path[1024];
    int s, d;
    if (snprintf(src_path, sizeof src_path, "%s/clone-src", dir) >=
        (int)sizeof src_path)
        return -1;
    if (snprintf(dst_path, cap, "%s/clone-dst", dir) >= (int)cap) return -1;
    s = open(src_path, O_CREAT | O_TRUNC | O_RDWR | O_CLOEXEC, 0600);
    if (s < 0 || clone_fill(s, 32u * 1024u * 1024u, 0x11) != 0) {
        if (s >= 0) close(s);
        return -1;
    }
    close(s);
    s = open(src_path, O_RDONLY | O_CLOEXEC);
    d = open(dst_path, O_CREAT | O_TRUNC | O_RDWR | O_CLOEXEC, 0600);
    /* Source is world-readable; the empty destination stays private. */
    if (s < 0 || d < 0 || fchmod(s, 0644) != 0 || lseek(s, 2, SEEK_SET) != 2) {
        if (s >= 0) close(s);
        if (d >= 0) close(d);
        return -1;
    }
    *src = s;
    *dst = d;
    return 0;
}

/* 1 when dest shares source's device blocks, the path, and a distinct inode. */
static int clone_shares_blocks(int src, int dst, const char *path,
                               off_t *src_phys, off_t *dst_phys)
{
    struct stat a, b, c;
    if (fstat(src, &a) != 0 || fstat(dst, &b) != 0 || lstat(path, &c) != 0)
        return 0;
    if (a.st_size != b.st_size || c.st_ino != b.st_ino || c.st_ino == a.st_ino)
        return 0;
    if (a.st_size <= 0) return 0;
    if (clone_phys(src, src_phys) != 0 || clone_phys(dst, dst_phys) != 0)
        return 0;
    return *src_phys == *dst_phys && *src_phys != 0;
}

static int clone_bytes_ok(int src, int dst)
{
    struct stat st;
    unsigned char first = 0, last = 0;
    if (fstat(src, &st) != 0 || st.st_size <= 0) return 0;
    if (pread(dst, &first, 1, 0) != 1) return 0;
    if (pread(dst, &last, 1, st.st_size - 1) != 1) return 0;
    return first == 0x11 && last == 0xa5;
}

static int clone_refuses_same(const char *dir)
{
    char path[1024];
    struct stat before, after;
    int fd;
    enum platform_file_clone_result result;
    if (snprintf(path, sizeof path, "%s/clone-src", dir) >= (int)sizeof path)
        return 0;
    fd = open(path, O_RDWR | O_CLOEXEC);
    if (fd < 0 || fstat(fd, &before) != 0) {
        if (fd >= 0) close(fd);
        return 0;
    }
    result = platform_file_clone_fd(fd, fd);
    if (fstat(fd, &after) != 0) {
        close(fd);
        return 0;
    }
    close(fd);
    return result == PLATFORM_FILE_CLONE_REFUSED &&
           before.st_ino == after.st_ino && before.st_size == after.st_size;
}

/* Full read/write of clone-src, for the latency baseline beside the clone. */
static long long clone_copy_baseline(const char *dir, off_t src_phys, int *private)
{
    char src_path[1024], copy_path[1024];
    unsigned char buf[65536];
    struct timespec start;
    int in, out;
    off_t copy_phys = 0;
    long long elapsed;
    *private = 0;
    if (snprintf(src_path, sizeof src_path, "%s/clone-src", dir) >=
            (int)sizeof src_path ||
        snprintf(copy_path, sizeof copy_path, "%s/clone-byte", dir) >=
            (int)sizeof copy_path)
        return -1;
    in = open(src_path, O_RDONLY | O_CLOEXEC);
    out = open(copy_path, O_CREAT | O_TRUNC | O_RDWR | O_CLOEXEC, 0600);
    if (in < 0 || out < 0) {
        if (in >= 0) close(in);
        if (out >= 0) close(out);
        return -1;
    }
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (;;) {
        ssize_t got = read(in, buf, sizeof buf);
        if (got < 0) {
            close(in);
            close(out);
            return -1;
        }
        if (got == 0) break;
        if (write(out, buf, (size_t)got) != got) {
            close(in);
            close(out);
            return -1;
        }
    }
    elapsed = clone_us(start);
    if (fsync(out) != 0) {
        close(in);
        close(out);
        return -1;
    }
    if (clone_phys(out, &copy_phys) == 0)
        *private = copy_phys != 0 && copy_phys != src_phys;
    close(in);
    close(out);
    return elapsed;
}

static int clone_mode_private(int dst, const char *path)
{
    struct stat published;
    if (fstat(dst, &published) != 0 || (published.st_mode & 0777) != 0600)
        return 0;
    if (lstat(path, &published) != 0 || (published.st_mode & 0777) != 0600)
        return 0;
    return 1;
}

static int clone_case_failed(int shared, int bytes_ok, int offsets_ok,
                             int refused, int copy_private, int mode_ok)
{
    return !shared || !bytes_ok || !offsets_ok || !refused || !copy_private ||
           !mode_ok;
}

static int apple_file_clone_case(const char *dir)
{
    char dst_path[1024];
    int src = -1, dst = -1, shared, bytes_ok, offsets_ok, copy_private, refused;
    int mode_ok;
    struct timespec start;
    long long clone_elapsed, copy_elapsed;
    enum platform_file_clone_result result;
    off_t src_phys = 0, dst_phys = 0;
    if (clone_open_pair(dir, &src, &dst, dst_path, sizeof dst_path) != 0)
        return 30;
    clock_gettime(CLOCK_MONOTONIC, &start);
    result = platform_file_clone_fd(src, dst);
    clone_elapsed = clone_us(start);
    shared = result == PLATFORM_FILE_CLONE_CLONED &&
             clone_shares_blocks(src, dst, dst_path, &src_phys, &dst_phys);
    bytes_ok = clone_bytes_ok(src, dst);
    offsets_ok = lseek(src, 0, SEEK_CUR) == 2 && lseek(dst, 0, SEEK_CUR) == 0;
    mode_ok = clone_mode_private(dst, dst_path);
    close(src);
    close(dst);
    copy_elapsed = clone_copy_baseline(dir, src_phys, &copy_private);
    refused = clone_refuses_same(dir);
    printf("file_clone: result=%d shared=%d copy_private=%d bytes_ok=%d "
           "offsets=%d refused=%d mode=%d clone_us=%lld copy_us=%lld "
           "src_phys=%lld dst_phys=%lld\n",
           (int)result, shared, copy_private, bytes_ok, offsets_ok, refused,
           mode_ok, clone_elapsed, copy_elapsed, (long long)src_phys,
           (long long)dst_phys);
    if (clone_case_failed(shared, bytes_ok, offsets_ok, refused, copy_private,
                          mode_ok))
        return 32;
    if (copy_elapsed < 0 || clone_elapsed < 0 || clone_elapsed >= copy_elapsed)
        return 33;
    return 0;
}
#endif

int test_file_ops_copy(void)
{
    int failures = 0;
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "file_ops_copy", "private");
    printf("file_ops_copy: private byte-identical copy, directory "
           "destination refused... ");
    int rc = file_ops_copy_probe(dir);
    if (rc == 0) {
        printf("OK\n");
    } else {
        printf("FAIL (step %d)\n", rc);
        failures++;
    }
    test_rm_rf_recursive(dir);
#if defined(__APPLE__)
    {
        char clone_dir[256];
        int crc;
        test_make_tmpdir(clone_dir, sizeof(clone_dir), "file_ops_copy", "clone");
        printf("file_clone: macOS descriptor clone shares the source blocks... ");
        crc = apple_file_clone_case(clone_dir);
        if (crc == 0) printf("OK\n");
        else {
            printf("FAIL (step %d)\n", crc);
            failures++;
        }
        test_rm_rf_recursive(clone_dir);
    }
#endif
    return failures;
}
