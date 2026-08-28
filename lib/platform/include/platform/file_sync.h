/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: data-only durability sync for hot WAL/journal/CAS writers
 * (rom_journal, event_log, disk_block_io, consensus_state_publication_cas).
 * fdatasync() skips the metadata-sync cost fsync() pays when only file
 * contents changed, but Darwin has no fdatasync(2), so this seam falls back
 * to full fsync() there rather than leaving callers to guess per host. */

#ifndef ZCL_PLATFORM_FILE_SYNC_H
#define ZCL_PLATFORM_FILE_SYNC_H

#if defined(_WIN32)
#include <io.h>
#else
#include <unistd.h>
#endif

static inline int platform_data_sync(int fd)
{
#if defined(_WIN32)
    return _commit(fd);
#elif defined(__APPLE__)
    return fsync(fd);
#else
    return fdatasync(fd);
#endif
}

/* Flush an existing descriptor including metadata needed for durable file or
 * directory updates. Directory descriptors are supported where the host
 * permits opening them; callers may retain best-effort behavior. */
static inline int platform_file_sync(int fd)
{
#if defined(_WIN32)
    return _commit(fd);
#else
    return fsync(fd);
#endif
}

#endif
