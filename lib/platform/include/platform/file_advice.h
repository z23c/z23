/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: posix_fadvise() has no equivalent name on Darwin, so block-file
 * scan/prefetch callers (boot_block_file_scan, test_block_prefetch) get one
 * intent-preserving seam: sequential readahead maps to F_RDAHEAD there
 * (POSIX_FADV_SEQUENTIAL on Linux), and "drop this range from cache" maps to
 * F_NOCACHE (POSIX_FADV_DONTNEED on Linux). */

#ifndef ZCL_PLATFORM_FILE_ADVICE_H
#define ZCL_PLATFORM_FILE_ADVICE_H

#include <stdint.h>
#if !defined(_WIN32)
#include <fcntl.h>
#include <sys/types.h>
#endif

static inline void platform_file_advise_sequential(int fd, int64_t length)
{
#if defined(_WIN32)
    (void)fd;
    (void)length;
#elif defined(__APPLE__)
    (void)length;
    (void)fcntl(fd, F_RDAHEAD, 1);
#else
    (void)posix_fadvise(fd, 0, length, POSIX_FADV_SEQUENTIAL);
#endif
}

static inline int platform_file_advise_dontneed(int fd, int64_t length)
{
#if defined(_WIN32)
    (void)fd;
    (void)length;
    return 0;
#elif defined(__APPLE__)
    (void)length;
    return fcntl(fd, F_NOCACHE, 1);
#else
    return posix_fadvise(fd, 0, length, POSIX_FADV_DONTNEED);
#endif
}

#endif
