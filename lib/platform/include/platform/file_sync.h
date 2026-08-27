/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Expose the platform data-only durability primitive through one API. */

#ifndef ZCL_PLATFORM_FILE_SYNC_H
#define ZCL_PLATFORM_FILE_SYNC_H

#include <unistd.h>

static inline int platform_data_sync(int fd)
{
#if defined(__APPLE__)
    return fsync(fd);
#else
    return fdatasync(fd);
#endif
}

#endif
