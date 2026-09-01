/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Implementation of platform/dlopen_pin.h. */
#if !defined(_WIN32)
#define _DEFAULT_SOURCE
#endif
#include "platform/dlopen_pin.h"
#include "platform/fd_path.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#if defined(__APPLE__) && !defined(_WIN32)
#include <stdatomic.h>
#include <sys/stat.h>
#endif

#if defined(__APPLE__) && !defined(_WIN32)

static _Atomic uint32_t g_pin_counter;

static bool copy_fd_to_fd(int src_fd, int dst_fd)
{
    unsigned char buffer[64 * 1024];

    if (lseek(src_fd, 0, SEEK_SET) < 0)
        return false;

    for (;;) {
        ssize_t n = read(src_fd, buffer, sizeof(buffer));
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return false;
        }
        if (n == 0)
            break;

        size_t written = 0;
        while (written < (size_t)n) {
            ssize_t w = write(dst_fd, buffer + written,
                              (size_t)n - written);
            if (w < 0) {
                if (errno == EINTR)
                    continue;
                return false;
            }
            written += (size_t)w;
        }
    }
    return true;
}

static bool macos_temp_base(char *out, size_t out_size)
{
    const char *base = getenv("TMPDIR");
    /* A relative or empty TMPDIR is not a temporary directory; refusing to
     * honour one keeps a hostile environment from steering scratch files into
     * the process working directory. */
    if (!base || base[0] != '/')
        base = "/tmp";
    int written = snprintf(out, out_size, "%s", base);
    return written > 0 && (size_t)written < out_size;
}

static bool platform_dlopen_pin_path_apple(int fd,
                                           const char *artifact_sha256,
                                           char *path, size_t path_size)
{
    if (!artifact_sha256 || !artifact_sha256[0])
        return false;

    char base[256];
    if (!macos_temp_base(base, sizeof(base)))
        return false;

    size_t base_len = strlen(base);
    while (base_len > 1 && base[base_len - 1] == '/')
        base[--base_len] = '\0';

    uint32_t start = atomic_fetch_add_explicit(&g_pin_counter, 1,
                                               memory_order_relaxed);

    for (unsigned attempt = 0; attempt < 64; attempt++) {
        uint32_t counter = start + (uint32_t)attempt;
        int n = snprintf(path, path_size,
                         "%s/zcl_hotswap_%s_%d_%u.so",
                         base, artifact_sha256, (int)getpid(), counter);
        if (n < 0 || (size_t)n >= path_size) {
            path[0] = '\0';
            return false;
        }

        int out_fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC,
                          0600);
        if (out_fd < 0) {
            if (errno == EEXIST)
                continue;
            path[0] = '\0';
            return false;
        }

        bool ok = copy_fd_to_fd(fd, out_fd);
        if (fsync(out_fd) != 0)
            ok = false;
        close(out_fd);

        if (!ok) {
            unlink(path);
            path[0] = '\0';
            return false;
        }
        return true;
    }

    path[0] = '\0';
    return false;
}

#endif /* __APPLE__ && !_WIN32 */

bool platform_dlopen_pin_path(int fd, const char *artifact_sha256,
                              char *path, size_t path_size)
{
    if (fd < 0 || !path || path_size == 0)
        return false;
    path[0] = '\0';

#if defined(__linux__) && !defined(_WIN32)
    (void)artifact_sha256;
    return platform_fd_path(path, path_size, fd, NULL);
#elif defined(__APPLE__) && !defined(_WIN32)
    return platform_dlopen_pin_path_apple(fd, artifact_sha256, path,
                                          path_size);
#else
    (void)artifact_sha256;
    return false;
#endif
}

void platform_dlopen_pin_path_cleanup(const char *path)
{
    if (!path || !path[0])
        return;

#if defined(__APPLE__) && !defined(_WIN32)
    (void)unlink(path);
#else
    (void)path;
#endif
}
