/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: data-only durability sync for hot WAL/journal/CAS writers
 * (rom_journal, event_log, disk_block_io, consensus_state_publication_cas).
 * fdatasync() skips the metadata-sync cost fsync() pays when only file
 * contents changed, but Darwin has no fdatasync(2), so this seam falls back
 * to full fsync() there rather than leaving callers to guess per host. */

#ifndef ZCL_PLATFORM_FILE_SYNC_H
#define ZCL_PLATFORM_FILE_SYNC_H

#include <unistd.h>
#if defined(_WIN32)
#include <errno.h>
#include <io.h>
#include <windows.h>
#endif

static inline int platform_data_sync(int fd)
{
#if defined(_WIN32)
    intptr_t handle = _get_osfhandle(fd);
    if (handle == -1) {
        errno = EBADF;
        return -1;
    }
    if (FlushFileBuffers((HANDLE)handle))
        return 0;
    errno = EIO;
    return -1;
#elif defined(__APPLE__)
    return fsync(fd);
#else
    return fdatasync(fd);
#endif
}

#endif
