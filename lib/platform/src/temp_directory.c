/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: implementation of platform/temp_directory.h. Both arms differ in
 * exactly one thing — where the OS keeps its temporary directory — and share
 * the create itself, which is platform_private_directory_create(): mkdir(2)
 * with 0700 plus an owner/mode re-validation on POSIX, CreateDirectoryW()
 * with an owner+SYSTEM-only descriptor plus a live-handle ACL re-validation
 * on Windows. Both of those fail with EEXIST rather than adopting an
 * existing directory, which is what makes this create atomic: the create
 * call IS the existence test, so there is no window between the two for
 * another process to plant the name. */
#include "base/hex.h"
#include "platform/temp_directory.h"

#include "platform/private_directory.h"
#include "platform/rng.h"

#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* Leave the prefix, the separator, the 18-digit leaf and the terminator room
 * inside PLATFORM_TEMP_PATH_MAX, so a base that would not fit is rejected
 * here rather than silently truncated into a shorter, colliding path. */
#define TEMP_DIRECTORY_BASE_MAX \
    (PLATFORM_TEMP_PATH_MAX - PLATFORM_TEMP_PREFIX_MAX - 24u)

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#define TEMP_DIRECTORY_SEPARATOR '\\'

static bool temp_directory_base(char *out, size_t cap)
{
    wchar_t wide[MAX_PATH + 1];
    DWORD count = (DWORD)(sizeof(wide) / sizeof(wide[0]));
    DWORD len = GetTempPathW(count, wide);
    if (len == 0 || len >= count || cap > (size_t)INT_MAX) return false;
    return WideCharToMultiByte(CP_UTF8, 0, wide, -1, out, (int)cap, NULL,
                               NULL) > 0;
}

#else
#include <stdlib.h>

#define TEMP_DIRECTORY_SEPARATOR '/'

static bool temp_directory_base(char *out, size_t cap)
{
    const char *base = getenv("TMPDIR");
    /* A relative or empty TMPDIR is not a temporary directory; refusing to
     * honour one keeps a hostile environment from steering the scratch tree
     * into the process working directory. */
    if (!base || base[0] != '/') base = "/tmp";
    int written = snprintf(out, cap, "%s", base);
    return written > 0 && (size_t)written < cap;
}
#endif

bool platform_temp_directory_create(const char *name_prefix, char *out_path,
                                    size_t out_cap)
{
    if (out_path && out_cap) out_path[0] = '\0';
    if (!name_prefix || !name_prefix[0] || !out_path || out_cap == 0) {
        errno = EINVAL;
        return false;
    }
    if (strlen(name_prefix) > PLATFORM_TEMP_PREFIX_MAX ||
        strchr(name_prefix, '/') || strchr(name_prefix, '\\')) {
        errno = EINVAL;
        return false;
    }
    char base[TEMP_DIRECTORY_BASE_MAX];
    if (!temp_directory_base(base, sizeof(base))) {
        errno = ENOENT;
        return false;
    }
    size_t base_len = strlen(base);
    while (base_len > 1 &&
           (base[base_len - 1] == '/' || base[base_len - 1] == '\\'))
        base[--base_len] = '\0';
    if (base_len == 0) {
        errno = ENOENT;
        return false;
    }

    for (unsigned attempt = 0; attempt < 64u; attempt++) {
        /* Eight bytes of CSPRNG plus the attempt counter, hex-encoded as one
         * slice. The counter is not decoration: a deterministic simulator may
         * have installed a fixed rng_fill(), and without it every retry inside
         * one call would re-propose the one name that just collided. */
        uint8_t nonce[9];
        char leaf[sizeof(nonce) * 2u + 1u];
        if (!rng_fill(nonce, sizeof(nonce) - 1u)) {
            errno = EIO;
            return false;
        }
        nonce[sizeof(nonce) - 1u] = (uint8_t)attempt;
        zcl_hex_encode(nonce, sizeof(nonce), leaf);

        char candidate[PLATFORM_TEMP_PATH_MAX];
        int written = snprintf(candidate, sizeof(candidate), "%s%c%s%s",
                               base, TEMP_DIRECTORY_SEPARATOR, name_prefix,
                               leaf);
        if (written <= 0 || (size_t)written >= sizeof(candidate)) {
            errno = ENAMETOOLONG;
            return false;
        }
        errno = 0;
        if (platform_private_directory_create(candidate)) {
            int copied = snprintf(out_path, out_cap, "%s", candidate);
            if (copied > 0 && (size_t)copied < out_cap) return true;
            /* The caller's buffer cannot hold the path we just created, so
             * it could never remove it. Remove it here and fail. */
            (void)platform_private_directory_remove_empty(candidate);
            out_path[0] = '\0';
            errno = ENAMETOOLONG;
            return false;
        }
        /* Only a name collision is retryable. A permission or IO failure is
         * reported as-is rather than burned through 64 identical attempts. */
        if (errno != EEXIST) return false;
    }
    errno = EEXIST;
    return false;
}
