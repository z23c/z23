/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Resolve and create the owner-private development state root. */
#include "platform/state_root.h"
#include "platform/private_directory.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <aclapi.h>
#include <shlobj.h>
#include <knownfolders.h>
#include "private_acl_internal.h"

/* If a pre-existing %LOCALAPPDATA%\z23 tree carries inherited ACEs from an
 * older install or sandbox, re-stamp it with the current owner+SYSTEM,
 * protected DACL.  This is a one-time migration: it keeps the state root
 * private without changing the canonical path. */
static bool state_root_repair_acl(const char *path)
{
    wchar_t wide[32768];
    struct platform_private_acl acl;
    platform_private_acl_init_empty(&acl);
    if (!path || !path[0] ||
        MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path, -1,
                            wide, 32768) <= 0 ||
        !platform_private_acl_create(&acl)) {
        platform_private_acl_destroy(&acl);
        return false;
    }
    HANDLE directory = CreateFileW(
        wide, WRITE_DAC | READ_CONTROL,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    PACL dacl = NULL;
    BOOL dacl_present = false, defaulted = false;
    bool ok = directory != INVALID_HANDLE_VALUE &&
              GetSecurityDescriptorDacl(platform_private_acl_descriptor(&acl),
                                        &dacl_present, &dacl, &defaulted) &&
              dacl_present &&
              SetSecurityInfo(directory, SE_FILE_OBJECT,
                              DACL_SECURITY_INFORMATION |
                                  PROTECTED_DACL_SECURITY_INFORMATION,
                              NULL, NULL, dacl, NULL) == ERROR_SUCCESS;
    if (directory != INVALID_HANDLE_VALUE) CloseHandle(directory);
    platform_private_acl_destroy(&acl);
    return ok;
}

static bool state_root_ensure_private(const char *path)
{
    if (platform_private_directory_ensure(path)) return true;
    return state_root_repair_acl(path) && platform_private_directory_ensure(path);
}

static bool state_root_base_from_known_folder(char base[32768])
{
    PWSTR wide = NULL;
    if (FAILED(SHGetKnownFolderPath(&FOLDERID_LocalAppData, KF_FLAG_DEFAULT,
                                    NULL, &wide)))
        return false;
    int n = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, wide, -1,
                                base, 32768, NULL, NULL);
    CoTaskMemFree(wide);
    return n > 1;
}

bool platform_state_root(char *out, size_t cap)
{
    char base[32768], z23[32768];
    char env_base[32768];
    DWORD env_len = GetEnvironmentVariableA("ZCL_STATE_ROOT", env_base,
                                            sizeof(env_base));
    if (env_len > 0 && env_len < sizeof(env_base)) {
        int n = snprintf(base, sizeof(base), "%s", env_base);
        if (n <= 0 || (size_t)n >= sizeof(base)) return false;
    } else if (!state_root_base_from_known_folder(base)) {
        return false;
    }
    if (snprintf(z23, sizeof(z23), "%s/z23", base) <= 0 ||
        !state_root_ensure_private(z23))
        return false;
    int n = snprintf(out, cap, "%s/dev", z23);
    return n > 0 && (size_t)n < cap && state_root_ensure_private(out);
}
#else
#include <errno.h>
#include <sys/stat.h>
static bool ensure_parent(const char *path)
{
    char copy[4096];
    size_t length = path ? strlen(path) : 0;
    if (!length || length >= sizeof(copy)) return false;
    memcpy(copy, path, length + 1u);
    for (char *p = copy + (copy[0] == '/' ? 1 : 0); ; ++p) {
        if (*p != '/' && *p != '\0') continue;
        char saved = *p; *p = '\0';
        if (copy[0] && mkdir(copy, 0700) != 0 && errno != EEXIST)
            return false;
        struct stat info;
        if (copy[0] && (lstat(copy, &info) != 0 ||
                        !S_ISDIR(info.st_mode) || S_ISLNK(info.st_mode)))
            return false;
        *p = saved;
        if (!saved) break;
    }
    return true;
}
bool platform_state_root(char *out, size_t cap)
{
    const char *xdg=getenv("XDG_STATE_HOME"), *home=getenv("HOME");
    char base[4096], z23[4096]; int n;
    if (xdg&&xdg[0]) n=snprintf(base,sizeof(base),"%s",xdg);
    else if (home&&home[0]) { n=snprintf(base,sizeof(base),"%s/.local/state",home); }
    else return false;
    if(n<=0||(size_t)n>=sizeof(base)||!ensure_parent(base)||
       snprintf(z23,sizeof(z23),"%s/z23",base)<=0||
       !platform_private_directory_ensure(z23)) return false;
    n=snprintf(out,cap,"%s/dev",z23);
    return n>0&&(size_t)n<cap&&platform_private_directory_ensure(out);
}
#endif
