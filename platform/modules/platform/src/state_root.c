/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Resolve and create owner-private development and application roots. */
#include "platform/state_root.h"
#include "platform/private_directory.h"
#include "platform/path_compat.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static bool state_root_join(char *out, size_t cap, const char *base,
                            const char *leaf)
{
    if (!out || !cap || !base || !leaf)
        return false;
    int n = snprintf(out, cap, "%s/%s", base, leaf);
    return n > 0 && (size_t)n < cap;
}

static bool state_root_directory_existing(const char *path)
{
    uintptr_t retained = 0;
    if (!platform_private_directory_open_validated_traverse(path, &retained))
        return false;
    platform_private_directory_close(retained);
    return true;
}

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <aclapi.h>
#include <shlobj.h>
#include <knownfolders.h>
#include "private_acl_internal.h"

static bool state_root_acl_prepare(const char *path, wchar_t wide[32768],
                                   struct platform_private_acl *acl)
{
    if (!path || !path[0] ||
        MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path, -1,
                            wide, 32768) <= 0 ||
        !platform_private_acl_create(acl)) {
        platform_private_acl_destroy(acl);
        return false;
    }
    return true;
}

static bool state_root_acl_target_valid(HANDLE directory,
                                        BY_HANDLE_FILE_INFORMATION *info)
{
    return directory != INVALID_HANDLE_VALUE &&
           GetFileInformationByHandle(directory, info) &&
           (info->dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0 &&
           (info->dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0;
}

static bool state_root_acl_restamp(HANDLE directory,
                                   struct platform_private_acl *acl,
                                   PSECURITY_DESCRIPTOR *current)
{
    PSID owner = NULL;
    PACL dacl = NULL;
    BOOL dacl_present = false, defaulted = false;
    return GetSecurityInfo(directory, SE_FILE_OBJECT,
                           OWNER_SECURITY_INFORMATION, &owner, NULL, NULL,
                           NULL, current) == ERROR_SUCCESS &&
           owner && EqualSid(owner, acl->user->User.Sid) &&
           GetSecurityDescriptorDacl(platform_private_acl_descriptor(acl),
                                     &dacl_present, &dacl, &defaulted) &&
           dacl_present &&
           SetSecurityInfo(directory, SE_FILE_OBJECT,
                           DACL_SECURITY_INFORMATION |
                               PROTECTED_DACL_SECURITY_INFORMATION,
                           NULL, NULL, dacl, NULL) == ERROR_SUCCESS;
}

/* If a pre-existing %LOCALAPPDATA%\z23 tree carries inherited ACEs from an
 * older install or sandbox, re-stamp it with the current owner+SYSTEM,
 * protected DACL.  This is a one-time migration: it keeps the state root
 * private without changing the canonical path. */
static bool state_root_repair_acl(const char *path)
{
    wchar_t wide[32768];
    struct platform_private_acl acl;
    platform_private_acl_init_empty(&acl);
    if (!state_root_acl_prepare(path, wide, &acl))
        return false;
    HANDLE directory = CreateFileW(
        wide, WRITE_DAC | READ_CONTROL,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    BY_HANDLE_FILE_INFORMATION info = {0};
    PSECURITY_DESCRIPTOR current = NULL;
    bool ok = state_root_acl_target_valid(directory, &info) &&
              state_root_acl_restamp(directory, &acl, &current);
    if (current) LocalFree(current);
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
    typedef HRESULT (WINAPI *folder_fn)(REFKNOWNFOLDERID, DWORD, HANDLE, PWSTR *);
    typedef void (WINAPI *free_fn)(LPVOID);
    /* Shell32 must stay unloaded until folder discovery is actually needed:
     * UI-restricted selfexec children otherwise fail before reaching main. */
    HMODULE shell = LoadLibraryExW(L"shell32.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
    HMODULE ole = LoadLibraryExW(L"ole32.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
    folder_fn folder = NULL;
    free_fn release = NULL;
    FARPROC get_symbol = shell ? GetProcAddress(shell, "SHGetKnownFolderPath") : NULL;
    FARPROC free_symbol = ole ? GetProcAddress(ole, "CoTaskMemFree") : NULL;
    static_assert(sizeof(folder) == sizeof(get_symbol), "Windows folder symbol width");
    static_assert(sizeof(release) == sizeof(free_symbol), "Windows allocator symbol width");
    memcpy(&folder, &get_symbol, sizeof(folder));
    memcpy(&release, &free_symbol, sizeof(release));
    if (!folder || !release)
        fprintf(stderr, "state_root: Windows folder API unavailable\n");
    PWSTR wide = NULL;
    int n = 0;
    if (folder && release &&
        SUCCEEDED(folder(&FOLDERID_LocalAppData, KF_FLAG_DEFAULT, NULL, &wide)))
        n = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, wide, -1,
                                base, 32768, NULL, NULL);
    if (wide && release) release(wide);
    if (ole) FreeLibrary(ole);
    if (shell) FreeLibrary(shell);
    return n > 1;
}

static bool state_root_resolve(char *out, size_t cap, bool create, bool application)
{
    char base[32768], z23[32768];
    wchar_t env_base[32768];
    DWORD env_len = GetEnvironmentVariableW(L"ZCL_STATE_ROOT", env_base,
                                            32768);
    if (env_len > 0 && env_len < 32768) {
        int n = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, env_base,
                                    -1, base, sizeof(base), NULL, NULL);
        if (n <= 1) return false;
    } else if (env_len >= 32768) {
        return false;
    } else if (!state_root_base_from_known_folder(base)) {
        return false;
    }
    if (application && !platform_path_is_absolute(base)) return false;
    if (!state_root_join(z23, sizeof(z23), base, "z23") ||
        !(create ? state_root_ensure_private(z23)
                  : state_root_directory_existing(z23)))
        return false;
    return state_root_join(out, cap, z23, application ? "apps" : "dev") &&
           (create ? state_root_ensure_private(out)
                   : state_root_directory_existing(out));
}

#else
#include <errno.h>
#include <sys/stat.h>

static bool ensure_parent_component(const char *path, bool create)
{
    if (create && mkdir(path, 0700) != 0 && errno != EEXIST)
        return false;
    struct stat info;
    return lstat(path, &info) == 0 && S_ISDIR(info.st_mode) &&
           !S_ISLNK(info.st_mode);
}

static bool ensure_parent(const char *path, bool create)
{
    char copy[4096];
    size_t length = path ? strlen(path) : 0;
    if (!length || length >= sizeof(copy)) return false;
    memcpy(copy, path, length + 1u);
    for (char *p = copy + (copy[0] == '/' ? 1 : 0); ; ++p) {
        if (*p != '/' && *p != '\0') continue;
        char saved = *p; *p = '\0';
        if (copy[0] && !ensure_parent_component(copy, create))
            return false;
        *p = saved;
        if (!saved) break;
    }
    return true;
}
static bool state_root_posix_base(char base[4096])
{
    const char *xdg = getenv("XDG_STATE_HOME"), *home = getenv("HOME");
    int n;
    if (xdg && xdg[0]) n = snprintf(base, 4096, "%s", xdg);
    else if (home && home[0]) n = snprintf(base, 4096, "%s/.local/state", home);
    else return false;
    return n > 0 && n < 4096;
}

static bool state_root_resolve(char *out, size_t cap, bool create, bool application)
{
    char base[4096], z23[4096];
    if (!state_root_posix_base(base)) return false;
    if (application && !platform_path_is_absolute(base)) return false;
    if(!ensure_parent(base, create)||
       !state_root_join(z23,sizeof(z23),base,"z23")||
       !(create ? platform_private_directory_ensure(z23)
                : state_root_directory_existing(z23))) return false;
    return state_root_join(out,cap,z23,application ? "apps" : "dev")&&
           (create ? platform_private_directory_ensure(out)
                   : state_root_directory_existing(out));
}

#endif

bool platform_state_root(char *out, size_t cap)
{
    return state_root_resolve(out, cap, true, false);
}

bool platform_state_root_existing(char *out, size_t cap)
{
    return state_root_resolve(out, cap, false, false);
}

bool platform_application_state_root(char *out, size_t cap)
{
    return state_root_resolve(out, cap, true, true);
}
