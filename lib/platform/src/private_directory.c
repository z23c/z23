/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: create and verify a directory only its owner can read -- Win32
 * (an explicit DACL naming the token user alone, no inherited ACEs) and
 * POSIX (0700 plus an ownership and mode recheck). Refuses rather than
 * loosening when the directory already exists with wider access. */
#include "platform/private_directory.h"
#include "base/safe_alloc.h"

#include <errno.h>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#include <stdio.h>
#include <stdlib.h>

static bool private_directory_wide(const char *path, wchar_t out[32768])
{
    return path && path[0] && MultiByteToWideChar(
        CP_UTF8, MB_ERR_INVALID_CHARS, path, -1, out, 32768) > 0;
}

static bool current_user_sid(HANDLE *token_out, TOKEN_USER **user_out)
{
    HANDLE token = NULL;
    DWORD size = 0;
    TOKEN_USER *user = NULL;
    bool ok = OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token) &&
              !GetTokenInformation(token, TokenUser, NULL, 0, &size) &&
              GetLastError() == ERROR_INSUFFICIENT_BUFFER;
    if (ok) user = zcl_malloc(size, "private_directory.token_user");
    ok = ok && user && GetTokenInformation(token, TokenUser, user, size,
                                            &size);
    if (!ok) {
        free(user);
        if (token) CloseHandle(token);
        return false;
    }
    *token_out = token;
    *user_out = user;
    return true;
}

static bool private_directory_validate(HANDLE directory, PSID user_sid)
{
    BYTE system_buffer[SECURITY_MAX_SID_SIZE];
    DWORD system_size = sizeof(system_buffer);
    PSID owner = NULL;
    PACL dacl = NULL;
    PSECURITY_DESCRIPTOR descriptor = NULL;
    BY_HANDLE_FILE_INFORMATION info = {0};
    bool ok = GetFileInformationByHandle(directory, &info) &&
              (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0 &&
              (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0 &&
              CreateWellKnownSid(WinLocalSystemSid, NULL, system_buffer,
                                 &system_size) &&
              GetSecurityInfo(directory, SE_FILE_OBJECT,
                              OWNER_SECURITY_INFORMATION |
                                  DACL_SECURITY_INFORMATION,
                              &owner, NULL, &dacl, NULL,
                              &descriptor) == ERROR_SUCCESS &&
              owner && EqualSid(owner, user_sid) && dacl;
    SECURITY_DESCRIPTOR_CONTROL control = 0;
    DWORD revision = 0;
    ok = ok && GetSecurityDescriptorControl(descriptor, &control, &revision) &&
         (control & SE_DACL_PROTECTED) != 0;
    ACL_SIZE_INFORMATION acl_info = {0};
    ok = ok && GetAclInformation(dacl, &acl_info, sizeof(acl_info),
                                 AclSizeInformation);
    bool user_allowed = false, system_allowed = false;
    for (DWORD i = 0; ok && i < acl_info.AceCount; ++i) {
        void *raw = NULL;
        if (!GetAce(dacl, i, &raw)) { ok = false; break; }
        ACE_HEADER *header = raw;
        if (header->AceType != ACCESS_ALLOWED_ACE_TYPE) {
            ok = false;
            break;
        }
        ACCESS_ALLOWED_ACE *ace = raw;
        PSID sid = &ace->SidStart;
        bool is_user = EqualSid(sid, user_sid) != 0;
        bool is_system = EqualSid(sid, system_buffer) != 0;
        if ((!is_user && !is_system) ||
            (ace->Mask & FILE_ALL_ACCESS) != FILE_ALL_ACCESS) {
            ok = false;
            break;
        }
        user_allowed |= is_user;
        system_allowed |= is_system;
    }
    if (descriptor) LocalFree(descriptor);
    return ok && user_allowed && system_allowed;
}

bool platform_private_directory_ensure(const char *path)
{
    wchar_t wide[32768];
    HANDLE token = NULL;
    TOKEN_USER *user = NULL;
    if (!private_directory_wide(path, wide) ||
        !current_user_sid(&token, &user)) {
        errno = EINVAL;
        return false;
    }
    LPWSTR sid = NULL;
    bool ok = ConvertSidToStringSidW(user->User.Sid, &sid) != 0;
    wchar_t sddl[512];
    int written = ok ? swprintf(sddl, 512,
        L"O:%lsD:P(A;;FA;;;%ls)(A;;FA;;;SY)", sid, sid) : -1;
    PSECURITY_DESCRIPTOR security_descriptor = NULL;
    ok = written > 0 && written < 512 &&
         ConvertStringSecurityDescriptorToSecurityDescriptorW(
             sddl, SDDL_REVISION_1, &security_descriptor, NULL);
    SECURITY_ATTRIBUTES attributes = {
        .nLength = sizeof(attributes),
        .lpSecurityDescriptor = security_descriptor,
        .bInheritHandle = FALSE};
    if (ok && !CreateDirectoryW(wide, &attributes)) {
        DWORD error = GetLastError();
        ok = error == ERROR_ALREADY_EXISTS;
        if (!ok) errno = error == ERROR_ACCESS_DENIED ? EACCES : EIO;
    }
    HANDLE directory = INVALID_HANDLE_VALUE;
    if (ok)
        directory = CreateFileW(
            wide, READ_CONTROL | FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    ok = ok && directory != INVALID_HANDLE_VALUE &&
         private_directory_validate(directory, user->User.Sid);
    if (!ok && errno == 0) errno = EACCES;
    if (directory != INVALID_HANDLE_VALUE) CloseHandle(directory);
    if (security_descriptor) LocalFree(security_descriptor);
    if (sid) LocalFree(sid);
    free(user);
    CloseHandle(token);
    return ok;
}

#else
#include <sys/stat.h>
#include <unistd.h>

bool platform_private_directory_ensure(const char *path)
{
    if (!path || !path[0]) { errno = EINVAL; return false; }
    if (mkdir(path, 0700) != 0 && errno != EEXIST) return false;
    struct stat st;
    if (lstat(path, &st) != 0) return false;
    if (!S_ISDIR(st.st_mode) || S_ISLNK(st.st_mode) ||
        st.st_uid != geteuid() || (st.st_mode & 0777) != 0700) {
        errno = EACCES;
        return false;
    }
    return true;
}
#endif
