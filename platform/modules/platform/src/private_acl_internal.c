/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Windows-only implementation of private_acl_internal.h —
 * synthesizes an SDDL descriptor granting full access solely to the current
 * user's SID and SYSTEM, and validates that an open handle's owner and DACL
 * (exactly two non-inherited allow ACEs, one per grantee) still match it.
 * An empty translation unit on POSIX. */
#include "private_acl_internal.h"
#include "base/safe_alloc.h"

#if defined(_WIN32) || defined(__MSYS__)
#include "base/safe_alloc.h"

#include <aclapi.h>
#include <sddl.h>
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>

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
    if (ok) acl->user = zcl_malloc(size, "private_acl_token_user");
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

/* True when the handle is open, user_sid is present, and the file the
 * handle refers to is of the expected kind and not a reparse point. */
static bool handle_and_file_kind_valid(HANDLE handle, PSID user_sid,
                                       bool expect_directory)
{
    BY_HANDLE_FILE_INFORMATION file_info = {0};
    return handle != INVALID_HANDLE_VALUE && user_sid &&
           GetFileInformationByHandle(handle, &file_info) &&
           ((file_info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) ==
               expect_directory &&
           (file_info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0;
}

/* Queries the handle's owner and DACL; true only when the query succeeds,
 * the owner SID is exactly user_sid, and a DACL is present. */
static bool owner_and_dacl_match_user(HANDLE handle, PSID user_sid,
                                      PSID *owner, PACL *dacl,
                                      PSECURITY_DESCRIPTOR *descriptor)
{
    return GetSecurityInfo(handle, SE_FILE_OBJECT,
                           OWNER_SECURITY_INFORMATION |
                               DACL_SECURITY_INFORMATION,
                           owner, NULL, dacl, NULL,
                           descriptor) == ERROR_SUCCESS &&
           *owner && EqualSid(*owner, user_sid) && *dacl;
}

/* True when the descriptor reports a protected DACL holding exactly two
 * ACEs; outputs the ACL size information for the caller's scan. */
static bool dacl_protected_with_two_aces(PSECURITY_DESCRIPTOR descriptor,
                                         PACL dacl,
                                         ACL_SIZE_INFORMATION *acl_info)
{
    SECURITY_DESCRIPTOR_CONTROL control = 0;
    DWORD revision = 0;
    return GetSecurityDescriptorControl(descriptor, &control, &revision) &&
           (control & SE_DACL_PROTECTED) != 0 &&
           GetAclInformation(dacl, acl_info, sizeof(*acl_info),
                             AclSizeInformation) &&
           acl_info->AceCount == 2;
}

/* True when one DACL ACE is a non-inherited allow entry granting
 * FILE_ALL_ACCESS to user_sid or the SYSTEM SID; reports the grantee or
 * grantees it matched. */
static bool ace_grants_full_access(void *raw, PSID user_sid, PSID system_sid,
                                   bool *is_user, bool *is_system)
{
    ACE_HEADER *header = raw;
    if (header->AceType != ACCESS_ALLOWED_ACE_TYPE ||
        (header->AceFlags & INHERITED_ACE) != 0) return false;
    ACCESS_ALLOWED_ACE *ace = raw;
    PSID sid = &ace->SidStart;
    *is_user = EqualSid(sid, user_sid) != 0;
    *is_system = EqualSid(sid, system_sid) != 0;
    return (*is_user || *is_system) &&
           (ace->Mask & FILE_ALL_ACCESS) == FILE_ALL_ACCESS;
}

static bool validate_for_user(HANDLE handle, PSID user_sid,
                              bool expect_directory)
{
    BYTE system_buffer[SECURITY_MAX_SID_SIZE];
    DWORD system_size = sizeof(system_buffer);
    PSID owner = NULL;
    PACL dacl = NULL;
    PSECURITY_DESCRIPTOR descriptor = NULL;
    ACL_SIZE_INFORMATION acl_info = {0};
    bool ok = handle_and_file_kind_valid(handle, user_sid,
                                         expect_directory) &&
              CreateWellKnownSid(WinLocalSystemSid, NULL, system_buffer,
                                 &system_size) &&
              owner_and_dacl_match_user(handle, user_sid, &owner, &dacl,
                                        &descriptor) &&
              dacl_protected_with_two_aces(descriptor, dacl, &acl_info);
    bool user_allowed = false, system_allowed = false;
    for (DWORD i = 0; ok && i < acl_info.AceCount; ++i) {
        void *raw = NULL;
        bool is_user = false, is_system = false;
        if (!GetAce(dacl, i, &raw) ||
            !ace_grants_full_access(raw, user_sid, system_buffer,
                                    &is_user, &is_system)) {
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
