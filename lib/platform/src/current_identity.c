/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Resolve the current host account identity without granting authority. */
#include "platform/current_identity.h"

#include <stdint.h>
#include <stdio.h>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

bool platform_current_identity(char *out, size_t out_size)
{
    if (!out || out_size == 0)
        return false;
    out[0] = '\0';
    HANDLE token = NULL;
    DWORD needed = 0;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
        return false;
    (void)GetTokenInformation(token, TokenUser, NULL, 0, &needed);
    TOKEN_USER *user = needed ? (TOKEN_USER *)LocalAlloc(LPTR, needed) : NULL;
    bool ok = user && GetTokenInformation(token, TokenUser, user, needed,
                                           &needed) && IsValidSid(user->User.Sid);
    if (!ok) {
        if (user) LocalFree(user);
        CloseHandle(token);
        return false;
    }
    SID_IDENTIFIER_AUTHORITY *authority =
        GetSidIdentifierAuthority(user->User.Sid);
    UCHAR count = *GetSidSubAuthorityCount(user->User.Sid);
    uint64_t authority_value = 0;
    for (size_t i = 0; i < sizeof(authority->Value); i++)
        authority_value = (authority_value << 8) | authority->Value[i];
    int written = snprintf(out, out_size, "sid:S-%u-%llu",
                           (unsigned)SID_REVISION,
                           (unsigned long long)authority_value);
    ok = written > 0 && (size_t)written < out_size;
    size_t used = ok ? (size_t)written : 0;
    for (UCHAR i = 0; ok && i < count; i++) {
        written = snprintf(out + used, out_size - used, "-%lu",
                           (unsigned long)*GetSidSubAuthority(user->User.Sid,
                                                              i));
        ok = written > 0 && (size_t)written < out_size - used;
        if (ok)
            used += (size_t)written;
    }
    LocalFree(user);
    CloseHandle(token);
    if (!ok)
        out[0] = '\0';
    return ok;
}
#else
#include <unistd.h>

bool platform_current_identity(char *out, size_t out_size)
{
    if (!out || out_size == 0)
        return false;
    int written = snprintf(out, out_size, "uid:%llu",
                           (unsigned long long)geteuid());
    return written > 0 && (size_t)written < out_size;
}
#endif
