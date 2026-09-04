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

/* "I am about to read exactly this range, start fetching it now."
 *
 * On a seek-bound device this is the difference between a walk that issues
 * one small read per record and waits for the head each time, and one where
 * the kernel has already streamed the range into the page cache. The boot
 * repair walks read 36 bytes per block from positions it has already sorted
 * into disk order, so it knows its next few megabytes exactly — which is
 * precisely the information POSIX_FADV_WILLNEED wants and the generic
 * readahead heuristic cannot infer from 36-byte reads.
 *
 * Advisory everywhere and a no-op where the platform has no equivalent:
 * Darwin's F_RDAHEAD is a whole-descriptor mode rather than a range hint, so
 * the range collapses to enabling readahead on the descriptor. */
static inline void platform_file_advise_willneed(int fd, int64_t offset,
                                                 int64_t length)
{
#if defined(_WIN32)
    (void)fd;
    (void)offset;
    (void)length;
#elif defined(__APPLE__)
    (void)offset;
    (void)length;
    (void)fcntl(fd, F_RDAHEAD, 1);
#else
    (void)posix_fadvise(fd, (off_t)offset, (off_t)length, POSIX_FADV_WILLNEED);
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
