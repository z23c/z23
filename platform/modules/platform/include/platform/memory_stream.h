/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * One read-only FILE stream over a caller-owned buffer, on both platform arms.
 *
 * fmemopen(3) is POSIX-only: the Windows C runtime neither declares nor
 * exports it, so a caller that reaches for it is an implicit declaration
 * under GCC 14 and later and an int-to-pointer result that slips past the
 * usual `if (!fp)` guard. Line-oriented readers (fgets) over an in-memory
 * blob use this instead. */
#ifndef ZCL_PLATFORM_MEMORY_STREAM_H
#define ZCL_PLATFORM_MEMORY_STREAM_H

#include <errno.h>
#include <stdint.h>
#include <stdio.h>

/* Open `len` bytes of `data` for reading. An empty buffer is EINVAL on both
 * arms (fmemopen refuses it too). POSIX streams read the buffer in place, so
 * `data` must outlive the stream; the Windows arm copies the bytes into an
 * anonymous temporary file that the runtime deletes on fclose. Returns NULL
 * with errno set on failure. Close with fclose(). */
static inline FILE *platform_memory_stream_open_read(const void *data, size_t len)
{
    if (!data || len == 0) {
        errno = EINVAL;
        return NULL;
    }
#if defined(_WIN32)
    FILE *fp = tmpfile();
    if (!fp) return NULL;
    if (fwrite(data, 1, len, fp) != len || fflush(fp) != 0 ||
        fseek(fp, 0, SEEK_SET) != 0) {
        int saved = errno ? errno : EIO;
        (void)fclose(fp);
        errno = saved;
        return NULL;
    }
    return fp;
#else
    /* fmemopen takes a non-const buffer but a "r" stream never writes it. */
    return fmemopen((void *)(uintptr_t)data, len, "r");
#endif
}

#endif
