/* Headless acceptance for current-user private directory boundaries. */
#include "platform/private_directory.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <aclapi.h>
#include <stdio.h>
#include <windows.h>

static int fail(const char *message)
{
    fprintf(stderr, "private_directory_acceptance: %s\n", message);
    return 1;
}

static bool acl_is_explicitly_private(HANDLE directory)
{
    HANDLE token = NULL;
    DWORD user_size = 0;
    TOKEN_USER *user = NULL;
    PSID owner = NULL;
    PACL dacl = NULL;
    PSECURITY_DESCRIPTOR descriptor = NULL;
    BYTE system_buffer[SECURITY_MAX_SID_SIZE];
    DWORD system_size = sizeof(system_buffer);
    bool ok = OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token) &&
              !GetTokenInformation(token, TokenUser, NULL, 0, &user_size) &&
              GetLastError() == ERROR_INSUFFICIENT_BUFFER;
    if (ok) user = HeapAlloc(GetProcessHeap(), 0, user_size);
    ok = ok && user &&
         GetTokenInformation(token, TokenUser, user, user_size, &user_size) &&
         CreateWellKnownSid(WinLocalSystemSid, NULL, system_buffer,
                            &system_size) &&
         GetSecurityInfo(directory, SE_FILE_OBJECT,
                         OWNER_SECURITY_INFORMATION |
                             DACL_SECURITY_INFORMATION,
                         &owner, NULL, &dacl, NULL,
                         &descriptor) == ERROR_SUCCESS &&
         owner && EqualSid(owner, user->User.Sid) && dacl;
    SECURITY_DESCRIPTOR_CONTROL control = 0;
    DWORD revision = 0;
    ok = ok && GetSecurityDescriptorControl(descriptor, &control, &revision) &&
         (control & SE_DACL_PROTECTED) != 0;
    ACL_SIZE_INFORMATION info = {0};
    ok = ok && GetAclInformation(dacl, &info, sizeof(info),
                                 AclSizeInformation) &&
         info.AceCount == 2;
    bool saw_user = false, saw_system = false;
    for (DWORD i = 0; ok && i < info.AceCount; ++i) {
        void *raw = NULL;
        ok = GetAce(dacl, i, &raw) != 0;
        if (!ok) break;
        ACE_HEADER *header = raw;
        ACCESS_ALLOWED_ACE *ace = raw;
        PSID sid = &ace->SidStart;
        bool is_user = EqualSid(sid, user->User.Sid) != 0;
        bool is_system = EqualSid(sid, system_buffer) != 0;
        ok = header->AceType == ACCESS_ALLOWED_ACE_TYPE &&
             (header->AceFlags & INHERITED_ACE) == 0 &&
             (is_user || is_system) &&
             (ace->Mask & FILE_ALL_ACCESS) == FILE_ALL_ACCESS;
        saw_user |= is_user;
        saw_system |= is_system;
    }
    if (descriptor) LocalFree(descriptor);
    if (user) HeapFree(GetProcessHeap(), 0, user);
    if (token) CloseHandle(token);
    return ok && saw_user && saw_system;
}

static bool add_everyone_ace(const wchar_t *path)
{
    HANDLE directory = CreateFileW(
        path, READ_CONTROL | WRITE_DAC,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    PACL old_dacl = NULL, new_dacl = NULL;
    PSECURITY_DESCRIPTOR descriptor = NULL;
    BYTE everyone_buffer[SECURITY_MAX_SID_SIZE];
    DWORD everyone_size = sizeof(everyone_buffer);
    bool ok = directory != INVALID_HANDLE_VALUE &&
              CreateWellKnownSid(WinWorldSid, NULL, everyone_buffer,
                                 &everyone_size) &&
              GetSecurityInfo(directory, SE_FILE_OBJECT,
                              DACL_SECURITY_INFORMATION, NULL, NULL,
                              &old_dacl, NULL,
                              &descriptor) == ERROR_SUCCESS;
    EXPLICIT_ACCESSW entry = {0};
    entry.grfAccessPermissions = FILE_GENERIC_READ;
    entry.grfAccessMode = GRANT_ACCESS;
    entry.grfInheritance = NO_INHERITANCE;
    entry.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    entry.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
    entry.Trustee.ptstrName = (LPWSTR)(void *)everyone_buffer;
    ok = ok && SetEntriesInAclW(1, &entry, old_dacl, &new_dacl) ==
                   ERROR_SUCCESS &&
         SetSecurityInfo(directory, SE_FILE_OBJECT,
                         DACL_SECURITY_INFORMATION |
                             PROTECTED_DACL_SECURITY_INFORMATION,
                         NULL, NULL, new_dacl, NULL) == ERROR_SUCCESS;
    if (new_dacl) LocalFree(new_dacl);
    if (descriptor) LocalFree(descriptor);
    if (directory != INVALID_HANDLE_VALUE) CloseHandle(directory);
    return ok;
}

int main(void)
{
    wchar_t temp[MAX_PATH], root[MAX_PATH], private_path[MAX_PATH];
    wchar_t permissive[MAX_PATH], target[MAX_PATH], link_path[MAX_PATH];
    wchar_t moved_path[MAX_PATH], staged_path[MAX_PATH], collision_path[MAX_PATH];
    wchar_t compromised_path[MAX_PATH];
    if (!GetTempPathW(MAX_PATH, temp) ||
        swprintf(root, MAX_PATH, L"%lsz23-private-dir-%lu", temp,
                 (unsigned long)GetCurrentProcessId()) <= 0 ||
        !CreateDirectoryW(root, NULL))
        return fail("fixture root create failed");
    (void)swprintf(private_path, MAX_PATH, L"%ls\\private", root);
    (void)swprintf(permissive, MAX_PATH, L"%ls\\permissive", root);
    (void)swprintf(target, MAX_PATH, L"%ls\\target", root);
    (void)swprintf(link_path, MAX_PATH, L"%ls\\link", root);
    (void)swprintf(moved_path, MAX_PATH, L"%ls\\private-moved", root);
    (void)swprintf(staged_path, MAX_PATH, L"%ls\\staged", root);
    (void)swprintf(collision_path, MAX_PATH, L"%ls\\collision", root);
    (void)swprintf(compromised_path, MAX_PATH, L"%ls\\compromised", root);

    char utf8[MAX_PATH * 3];
    if (!WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, private_path, -1,
                             utf8, sizeof(utf8), NULL, NULL) ||
        !platform_private_directory_ensure(utf8) ||
        !platform_private_directory_ensure(utf8))
        return fail("create/existing validation failed");

    HANDLE private_handle = CreateFileW(
        private_path, READ_CONTROL | FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    if (private_handle == INVALID_HANDLE_VALUE ||
        !acl_is_explicitly_private(private_handle))
        return fail("private ACL is not explicit user+SYSTEM/protected");
    CloseHandle(private_handle);

    uintptr_t native = (uintptr_t)INVALID_HANDLE_VALUE;
    BY_HANDLE_FILE_INFORMATION before = {0}, after = {0};
    if (!platform_private_directory_open_validated(utf8, &native) ||
        !GetFileInformationByHandle((HANDLE)native, &before) ||
        !MoveFileExW(private_path, moved_path, 0) ||
        !GetFileInformationByHandle((HANDLE)native, &after) ||
        before.dwVolumeSerialNumber != after.dwVolumeSerialNumber ||
        before.nFileIndexHigh != after.nFileIndexHigh ||
        before.nFileIndexLow != after.nFileIndexLow)
        return fail("validated handle did not remain bound across rename");
    platform_private_directory_close(native);
    if (!MoveFileExW(moved_path, private_path, 0))
        return fail("fixture rename restore failed");

    char staged_utf8[MAX_PATH * 3], moved_utf8[MAX_PATH * 3];
    char collision_utf8[MAX_PATH * 3];
    if (!WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, staged_path, -1,
                             staged_utf8, sizeof(staged_utf8), NULL, NULL) ||
        !WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, moved_path, -1,
                             moved_utf8, sizeof(moved_utf8), NULL, NULL) ||
        !WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, collision_path, -1,
                             collision_utf8, sizeof(collision_utf8), NULL,
                             NULL) ||
        !platform_private_directory_create(staged_utf8) ||
        platform_private_directory_create(staged_utf8) ||
        !platform_private_directory_publish_no_clobber(staged_utf8,
                                                        moved_utf8) ||
        !platform_private_directory_create(collision_utf8) ||
        platform_private_directory_publish_no_clobber(collision_utf8,
                                                       moved_utf8) ||
        !platform_private_directory_remove_empty(collision_utf8) ||
        !platform_private_directory_remove_empty(moved_utf8))
        return fail("create-only/no-clobber publication failed");

    if (!CreateDirectoryW(permissive, NULL) ||
        !WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, permissive, -1,
                             utf8, sizeof(utf8), NULL, NULL) ||
        platform_private_directory_ensure(utf8))
        return fail("permissive inherited ACL accepted");

    if (!WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, compromised_path,
                             -1, utf8, sizeof(utf8), NULL, NULL) ||
        !platform_private_directory_create(utf8) ||
        !add_everyone_ace(compromised_path) ||
        platform_private_directory_ensure(utf8))
        return fail("extra Everyone ACE accepted");

    if (!CreateDirectoryW(target, NULL))
        return fail("reparse target create failed");
    DWORD flags = SYMBOLIC_LINK_FLAG_DIRECTORY;
#ifdef SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE
    flags |= SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE;
#endif
    if (CreateSymbolicLinkW(link_path, target, flags)) {
        if (!WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, link_path, -1,
                                 utf8, sizeof(utf8), NULL, NULL) ||
            platform_private_directory_ensure(utf8))
            return fail("directory reparse point accepted");
        RemoveDirectoryW(link_path);
    }

    RemoveDirectoryW(private_path);
    RemoveDirectoryW(permissive);
    RemoveDirectoryW(compromised_path);
    RemoveDirectoryW(target);
    RemoveDirectoryW(root);
    puts("private_directory_acceptance: PASS");
    return 0;
}
