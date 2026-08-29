/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Windows-only internal helper shared by disk_space.c,
 * file_metadata.c and positioned_file.c — converts a UTF-8 pathname into the
 * wide \\?\-extended form CreateFileW/GetDiskFreeSpaceExW want, covering
 * drive-absolute, UNC, and already-extended inputs. Compiles to nothing on
 * POSIX, where the same paths are handed to open()/statvfs() unchanged.
 *
 * The separator rewrite is load-bearing, not cosmetic. The \\?\ prefix turns
 * OFF every Win32 path parse — including the forward-slash-to-backslash
 * rewrite — so a '/' left in the string reaches the object manager as an
 * ordinary filename character and the open fails with ERROR_INVALID_NAME.
 * That is neither ERROR_FILE_NOT_FOUND nor ERROR_PATH_NOT_FOUND, so the
 * callers' missing-vs-refused split reports a file that plainly exists as
 * refused/unreadable. In-tree callers do join with '/' (util/boot_status.c,
 * platform/state_root.c, the native zcode workspace paths), so the rewrite
 * has to happen HERE, before the prefix goes on.
 *
 * One definition, three callers. private_file.c's pf_wide is this same
 * function and is the last remaining copy; it is correct today because it
 * already normalises, and adopting this header is its one-line follow-up. */
#ifndef ZCL_PLATFORM_WINDOWS_PATH_INTERNAL_H
#define ZCL_PLATFORM_WINDOWS_PATH_INTERNAL_H

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <stdbool.h>
#include <wchar.h>

static inline bool platform_windows_wide_path(const char *utf8,
                                              wchar_t out[32768])
{
    if (!utf8 || !utf8[0]) return false;
    wchar_t plain[32768];
    /* cbMultiByte = -1 declares the source NUL-terminated, and the count
     * returned for that form INCLUDES the terminating L'\0'. So the characters
     * are plain[0 .. n - 2] and plain[n - 1] is the terminator: the rewrite
     * below stops at n - 1 to touch every character and never the terminator,
     * while the wmemcpy lengths use the full n precisely because n carries
     * that terminator with it. */
    int n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, utf8, -1,
                                plain, 32768);
    if (n <= 0) return false;
    for (int i = 0; i < n - 1; i++)
        if (plain[i] == L'/')
            plain[i] = L'\\';
    if (wcsncmp(plain, L"\\\\?\\", 4) == 0) {
        wmemcpy(out, plain, (size_t)n);
        return true;
    }
    if (plain[0] == L'\\' && plain[1] == L'\\') {
        if ((size_t)n + 6 >= 32768) return false;
        wmemcpy(out, L"\\\\?\\UNC\\", 8);
        wmemcpy(out + 8, plain + 2, (size_t)n - 2);
        return true;
    }
    if (plain[0] && plain[1] == L':' &&
        (plain[2] == L'\\' || plain[2] == L'/')) {
        if ((size_t)n + 4 >= 32768) return false;
        wmemcpy(out, L"\\\\?\\", 4);
        wmemcpy(out + 4, plain, (size_t)n);
        return true;
    }
    wmemcpy(out, plain, (size_t)n);
    return true;
}
#endif

#endif
