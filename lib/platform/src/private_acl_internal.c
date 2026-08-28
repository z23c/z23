/* Copyright 2026 Rhett Creighton - Apache License 2.0 */
#include "private_acl_internal.h"

#if defined(_WIN32)
#include <aclapi.h>
#include <sddl.h>
#include <stdio.h>
#include <stdlib.h>

void platform_private_acl_init_empty(struct platform_private_acl *acl)
{
    if (acl) *acl = (struct platform_private_acl){0};
}

static bool current_user(struct platform_private_acl *acl)
{
    DWORD size = 0;
    bool ok = OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &acl->token) &&
              !GetTokenInformation(acl->token, TokenUser, NULL, 0, &size) &&
              GetLastError() == ERROR_INSUFFICIENT_BUFFER;
    if (ok) acl->user = malloc(size);
    return ok && acl->user &&
           GetTokenInformation(acl->token, TokenUser, acl->user, size, &size);
}

bool platform_private_acl_create(struct platform_private_acl *acl)
{
    if (!acl) return false;
    platform_private_acl_init_empty(acl);
    if (!current_user(acl)) {
        platform_private_acl_destroy(acl);
        return false;
    }
    LPWSTR sid = NULL;
    bool ok = ConvertSidToStringSidW(acl->user->User.Sid, &sid) != 0;
    wchar_t sddl[512];
    int written = ok ? swprintf(sddl, 512,
        L"O:%lsD:P(A;;FA;;;%ls)(A;;FA;;;SY)", sid, sid) : -1;
    ok = written > 0 && written < 512 &&
         ConvertStringSecurityDescriptorToSecurityDescriptorW(
             sddl, SDDL_REVISION_1, &acl->descriptor, NULL);
    if (sid) LocalFree(sid);
    if (!ok) platform_private_acl_destroy(acl);
    return ok;
}

void platform_private_acl_destroy(struct platform_private_acl *acl)
{
    if (!acl) return;
    if (acl->descriptor) LocalFree(acl->descriptor);
    free(acl->user);
    if (acl->token) CloseHandle(acl->token);
    platform_private_acl_init_empty(acl);
}

PSECURITY_DESCRIPTOR platform_private_acl_descriptor(
    const struct platform_private_acl *acl)
{
    return acl ? acl->descriptor : NULL;
}

static bool validate_for_user(HANDLE handle, PSID user_sid,
                              bool expect_directory)
{
    BYTE system_buffer[SECURITY_MAX_SID_SIZE];
    DWORD system_size = sizeof(system_buffer);
    PSID owner = NULL;
    PACL dacl = NULL;
    PSECURITY_DESCRIPTOR descriptor = NULL;
    BY_HANDLE_FILE_INFORMATION file_info = {0};
    bool ok = handle != INVALID_HANDLE_VALUE && user_sid &&
              GetFileInformationByHandle(handle, &file_info) &&
              ((file_info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) ==
                  expect_directory &&
              (file_info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0 &&
              CreateWellKnownSid(WinLocalSystemSid, NULL, system_buffer,
                                 &system_size) &&
              GetSecurityInfo(handle, SE_FILE_OBJECT,
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
                                 AclSizeInformation) &&
         acl_info.AceCount == 2;
    bool user_allowed = false, system_allowed = false;
    for (DWORD i = 0; ok && i < acl_info.AceCount; ++i) {
        void *raw = NULL;
        if (!GetAce(dacl, i, &raw)) { ok = false; break; }
        ACE_HEADER *header = raw;
        if (header->AceType != ACCESS_ALLOWED_ACE_TYPE ||
            (header->AceFlags & INHERITED_ACE) != 0) {
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

bool platform_private_acl_validate_handle(HANDLE handle,
                                          bool expect_directory)
{
    struct platform_private_acl acl;
    platform_private_acl_init_empty(&acl);
    bool ok = current_user(&acl) &&
              validate_for_user(handle, acl.user->User.Sid,
                                expect_directory);
    platform_private_acl_destroy(&acl);
    return ok;
}
#else
typedef int platform_private_acl_internal_nonempty_translation_unit;
#endif
