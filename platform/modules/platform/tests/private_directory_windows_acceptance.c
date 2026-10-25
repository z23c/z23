/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Headless acceptance for current-user private directory boundaries. */
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

static bool acl_has_private_entries(PSECURITY_DESCRIPTOR descriptor,
                                    PACL dacl, PSID user_sid, PSID system_sid)
{
    SECURITY_DESCRIPTOR_CONTROL control = 0;
    DWORD revision = 0;
    bool ok = GetSecurityDescriptorControl(descriptor, &control, &revision) &&
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
        bool is_user = EqualSid(sid, user_sid) != 0;
        bool is_system = EqualSid(sid, system_sid) != 0;
        ok = header->AceType == ACCESS_ALLOWED_ACE_TYPE &&
             (header->AceFlags & INHERITED_ACE) == 0 &&
             (is_user || is_system) &&
             (ace->Mask & FILE_ALL_ACCESS) == FILE_ALL_ACCESS;
        saw_user |= is_user;
        saw_system |= is_system;
    }
    return ok && saw_user && saw_system;
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
    ok = ok && acl_has_private_entries(descriptor, dacl, user->User.Sid,
                                       system_buffer);
    if (descriptor) LocalFree(descriptor);
    if (user) HeapFree(GetProcessHeap(), 0, user);
    if (token) CloseHandle(token);
    return ok;
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

struct private_directory_fixture {
    wchar_t root[MAX_PATH], private_path[MAX_PATH], permissive[MAX_PATH];
    wchar_t target[MAX_PATH], link_path[MAX_PATH], moved_path[MAX_PATH];
    wchar_t staged_path[MAX_PATH], collision_path[MAX_PATH];
    wchar_t compromised_path[MAX_PATH];
    char utf8[MAX_PATH * 3];
};

static int create_fixture_paths(struct private_directory_fixture *fixture)
{
    wchar_t temp[MAX_PATH];
    if (!GetTempPathW(MAX_PATH, temp) ||
        swprintf(fixture->root, MAX_PATH, L"%lsz23-private-dir-%lu-%llu", temp,
                 (unsigned long)GetCurrentProcessId(),
                 (unsigned long long)GetTickCount64()) <= 0 ||
        !CreateDirectoryW(fixture->root, NULL))
        return fail("fixture root create failed");
    (void)swprintf(fixture->private_path, MAX_PATH, L"%ls\\private", fixture->root);
    (void)swprintf(fixture->permissive, MAX_PATH, L"%ls\\permissive", fixture->root);
    (void)swprintf(fixture->target, MAX_PATH, L"%ls\\target", fixture->root);
    (void)swprintf(fixture->link_path, MAX_PATH, L"%ls\\link", fixture->root);
    (void)swprintf(fixture->moved_path, MAX_PATH, L"%ls\\private-moved", fixture->root);
    (void)swprintf(fixture->staged_path, MAX_PATH, L"%ls\\staged", fixture->root);
    (void)swprintf(fixture->collision_path, MAX_PATH, L"%ls\\collision", fixture->root);
    (void)swprintf(fixture->compromised_path, MAX_PATH, L"%ls\\compromised", fixture->root);

    return 0;
}

static int check_explicit_private_acl(struct private_directory_fixture *fixture)
{
    if (!WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, fixture->private_path, -1,
                             fixture->utf8, sizeof(fixture->utf8), NULL, NULL))
        return fail("private path UTF-8 conversion failed");
    if (!platform_private_directory_ensure(fixture->utf8)) {
        RemoveDirectoryW(fixture->private_path);
        RemoveDirectoryW(fixture->root);
        fputs("private_directory_acceptance: REFUSE: runtime cannot prove "
              "native SID/DACL semantics\n", stderr);
        return 77;
    }
    if (!platform_private_directory_ensure(fixture->utf8))
        return fail("create/existing validation failed");

    HANDLE private_handle = CreateFileW(
        fixture->private_path, READ_CONTROL | FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    if (private_handle == INVALID_HANDLE_VALUE ||
        !acl_is_explicitly_private(private_handle))
        return fail("private ACL is not explicit user+SYSTEM/protected");
    CloseHandle(private_handle);

    return 0;
}

static int check_retained_handle_rename(struct private_directory_fixture *fixture)
{
    uintptr_t native = (uintptr_t)INVALID_HANDLE_VALUE;
    BY_HANDLE_FILE_INFORMATION before = {0}, after = {0};
    if (!platform_private_directory_open_validated(fixture->utf8, &native) ||
        !FlushFileBuffers((HANDLE)native) ||
        !GetFileInformationByHandle((HANDLE)native, &before) ||
        !MoveFileExW(fixture->private_path, fixture->moved_path, 0) ||
        !GetFileInformationByHandle((HANDLE)native, &after) ||
        before.dwVolumeSerialNumber != after.dwVolumeSerialNumber ||
        before.nFileIndexHigh != after.nFileIndexHigh ||
        before.nFileIndexLow != after.nFileIndexLow)
        return fail("validated handle did not remain bound across rename");
    platform_private_directory_close(native);
    if (!MoveFileExW(fixture->moved_path, fixture->private_path, 0))
        return fail("fixture rename restore failed");

    return 0;
}

static int check_no_clobber_publication(struct private_directory_fixture *fixture)
{
    char staged_utf8[MAX_PATH * 3], moved_utf8[MAX_PATH * 3];
    char collision_utf8[MAX_PATH * 3];
    if (!WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, fixture->staged_path, -1,
                             staged_utf8, sizeof(staged_utf8), NULL, NULL) ||
        !WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, fixture->moved_path, -1,
                             moved_utf8, sizeof(moved_utf8), NULL, NULL) ||
        !WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, fixture->collision_path, -1,
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

    return 0;
}

static int check_unsafe_directory_refusals(struct private_directory_fixture *fixture)
{
    if (!CreateDirectoryW(fixture->permissive, NULL) ||
        !WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, fixture->permissive, -1,
                             fixture->utf8, sizeof(fixture->utf8), NULL, NULL) ||
        platform_private_directory_ensure(fixture->utf8))
        return fail("permissive inherited ACL accepted");

    if (!WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, fixture->compromised_path,
                             -1, fixture->utf8, sizeof(fixture->utf8), NULL, NULL) ||
        !platform_private_directory_create(fixture->utf8) ||
        !add_everyone_ace(fixture->compromised_path) ||
        platform_private_directory_ensure(fixture->utf8))
        return fail("extra Everyone ACE accepted");

    if (!CreateDirectoryW(fixture->target, NULL))
        return fail("reparse target create failed");
    DWORD flags = SYMBOLIC_LINK_FLAG_DIRECTORY;
#ifdef SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE
    flags |= SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE;
#endif
    if (CreateSymbolicLinkW(fixture->link_path, fixture->target, flags)) {
        if (!WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, fixture->link_path, -1,
                                 fixture->utf8, sizeof(fixture->utf8), NULL, NULL) ||
            platform_private_directory_ensure(fixture->utf8))
            return fail("directory reparse point accepted");
        RemoveDirectoryW(fixture->link_path);
    }

    return 0;
}

static int remove_fixture_paths(struct private_directory_fixture *fixture)
{
    RemoveDirectoryW(fixture->private_path);
    RemoveDirectoryW(fixture->permissive);
    RemoveDirectoryW(fixture->compromised_path);
    RemoveDirectoryW(fixture->target);
    RemoveDirectoryW(fixture->root);
    return 0;
}

int main(void)
{
    struct private_directory_fixture fixture = {0};
    int result = create_fixture_paths(&fixture);
    if (result) return result;
    result = check_explicit_private_acl(&fixture);
    if (result) return result;
    result = check_retained_handle_rename(&fixture);
    if (result) return result;
    result = check_no_clobber_publication(&fixture);
    if (result) return result;
    result = check_unsafe_directory_refusals(&fixture);
    if (result) return result;
    result = remove_fixture_paths(&fixture);
    if (result) return result;
    puts("private_directory_acceptance: PASS");
    return 0;
}
