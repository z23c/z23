/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: data-only durability sync for hot WAL/journal/CAS writers
 * (rom_journal, event_log, disk_block_io, consensus_state_publication_cas).
 * fdatasync() skips the metadata-sync cost fsync() pays when only file
 * contents changed, but Darwin has no fdatasync(2), so this seam falls back
 * to fsync() there rather than leaving callers to guess per host.
 *
 * Authority-bearing writes have a deliberately separate barrier.  On macOS,
 * fsync() may return after the drive accepted data into a volatile cache;
 * F_FULLFSYNC asks the storage stack to push it through that cache.  Wallet
 * keys/backups and canonical generation pointers need that stronger contract,
 * while rebuildable block bodies, projections, and CAS objects retain the
 * cheaper data/file barriers above. */

#ifndef ZCL_PLATFORM_FILE_SYNC_H
#define ZCL_PLATFORM_FILE_SYNC_H

#if defined(_WIN32)
#include <io.h>
#else
#include <fcntl.h>
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

/* Flush authority-bearing bytes through the strongest native persistent-file
 * barrier this platform exposes.  There is intentionally no Darwin fallback
 * from F_FULLFSYNC to fsync(): silently weakening a custody boundary because a
 * filesystem rejected the command would make a successful backup claim false.
 * Callers that hold only rebuildable state must use platform_data_sync() or
 * platform_file_sync() instead. */
static inline int platform_authority_sync(int fd)
{
#if defined(_WIN32)
    return _commit(fd);
#elif defined(__APPLE__)
    return fcntl(fd, F_FULLFSYNC);
#else
    return fsync(fd);
#endif
}

static inline const char *platform_authority_sync_backend(void)
{
#if defined(_WIN32)
    return "FlushFileBuffers";
#elif defined(__APPLE__)
    return "fcntl(F_FULLFSYNC)";
#else
    return "fsync";
#endif
}

#endif
