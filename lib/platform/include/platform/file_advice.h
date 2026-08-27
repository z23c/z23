/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#ifndef ZCL_PLATFORM_FILE_ADVICE_H
#define ZCL_PLATFORM_FILE_ADVICE_H

#include <fcntl.h>
#include <sys/types.h>

static inline void platform_file_advise_sequential(int fd, off_t length)
{
#if defined(__APPLE__)
    (void)length;
    (void)fcntl(fd, F_RDAHEAD, 1);
#else
    (void)posix_fadvise(fd, 0, length, POSIX_FADV_SEQUENTIAL);
#endif
}

static inline int platform_file_advise_dontneed(int fd, off_t length)
{
#if defined(__APPLE__)
    (void)length;
    return fcntl(fd, F_NOCACHE, 1);
#else
    return posix_fadvise(fd, 0, length, POSIX_FADV_DONTNEED);
#endif
}

#endif
