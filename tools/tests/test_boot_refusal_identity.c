/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: proves a boot refusal report names the acting OS identity --
 * platform_current_identity() yields a Windows `sid:S-` or POSIX `uid:`
 * string, and the rendered BOOT_DATADIR_CREATE_FAILED report must carry the
 * datadir and that exact identity, so a refusal says WHO was refused. */
#include "config/boot_error.h"
#include "config/boot_refusal_reports.h"
#include "platform/current_identity.h"

#include <errno.h>
#include <string.h>

int main(void)
{
    char identity[192];
    if (!platform_current_identity(identity, sizeof(identity)) ||
        (!strstr(identity, "sid:S-") && !strstr(identity, "uid:")))
        return 1;
    boot_report_datadir_create_failed("synthetic-private-datadir", EACCES);
    char report[4096];
    if (!boot_error_last_render(report, sizeof(report)) ||
        !strstr(report, "BOOT_DATADIR_CREATE_FAILED") ||
        !strstr(report, "datadir=synthetic-private-datadir") ||
        !strstr(report, "identity=") || !strstr(report, identity))
        return 2;
    return 0;
}
