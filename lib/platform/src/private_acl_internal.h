/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Windows-only internal helper shared by private_directory.c and
 * directory_transaction.c — builds the owner+SYSTEM-exclusive security
 * descriptor stamped on a new private directory/file, and validates that an
 * already-open handle's real owner and DACL still match it (no inherited or
 * extra ACEs). Compiles to an empty translation unit on POSIX, where
 * private-ness is enforced by mode bits instead. */
#ifndef ZCL_PLATFORM_PRIVATE_ACL_INTERNAL_H
#define ZCL_PLATFORM_PRIVATE_ACL_INTERNAL_H

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

struct platform_private_acl {
    HANDLE token;
    TOKEN_USER *user;
    PSECURITY_DESCRIPTOR descriptor;
};

void platform_private_acl_init_empty(struct platform_private_acl *acl);
bool platform_private_acl_create(struct platform_private_acl *acl);
void platform_private_acl_destroy(struct platform_private_acl *acl);
PSECURITY_DESCRIPTOR platform_private_acl_descriptor(
    const struct platform_private_acl *acl);
bool platform_private_acl_validate_handle(HANDLE handle,
                                          bool expect_directory);
#endif

#endif
