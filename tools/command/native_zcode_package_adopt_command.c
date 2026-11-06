/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: zcode.package.adopt and zcode.package.copies (red stubs). */

#include "command/native_command.h"
#include "command/native_zcode_package_copy.h"

#include <string.h>

bool zcl_package_copy_open_as(const char *dir,
                              enum zcl_package_copy_access access,
                              struct zcl_package_copy *copy,
                              struct zcl_command_reply *reply,
                              const char *command)
{
    (void)access;
    return zcl_package_copy_open(dir, copy, reply, command);
}

enum zcl_package_copy_adoption zcl_package_copy_adopted(
    const char *datadir, const struct zcl_package_copy *copy,
    struct zcl_package_adopt_record *record)
{
    (void)datadir; (void)copy; (void)record;
    return ZCL_PACKAGE_COPY_ADOPTION_UNREADABLE;
}

void zcl_native_handle_zcode_package_adopt(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    (void)request;
    zcl_package_copy_fail(reply, "NOT_IMPLEMENTED", false, "red stub", "");
}

void zcl_native_handle_zcode_package_copies(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    (void)request;
    zcl_package_copy_fail(reply, "NOT_IMPLEMENTED", false, "red stub", "");
}
