/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: personal package copies — fork, version save/list/restore. */

#include "command/native_command.h"

static void zpc_stub(struct zcl_command_reply *reply, const char *command)
{
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                           ZCL_COMMAND_EXIT_INVALID, "NOT_IMPLEMENTED",
                           "execute", false, false, "not implemented",
                           command);
}

void zcl_native_handle_zcode_package_fork(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    (void)request;
    zpc_stub(reply, "zcode.package.fork");
}

void zcl_native_handle_zcode_package_version_save(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    (void)request;
    zpc_stub(reply, "zcode.package.version.save");
}

void zcl_native_handle_zcode_package_version_list(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    (void)request;
    zpc_stub(reply, "zcode.package.version.list");
}

void zcl_native_handle_zcode_package_version_restore(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    (void)request;
    zpc_stub(reply, "zcode.package.version.restore");
}

void zcl_native_handle_zcode_package_share(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    (void)request;
    zpc_stub(reply, "zcode.package.share");
}
