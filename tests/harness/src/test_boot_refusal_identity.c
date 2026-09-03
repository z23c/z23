/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: proves a boot refusal report names the acting OS identity --
 * platform_current_identity() yields a Windows `sid:S-` or POSIX `uid:`
 * string, and the rendered BOOT_DATADIR_CREATE_FAILED report must carry the
 * datadir and that exact identity, so a refusal says WHO was refused.
 *
 * Rehomed from tools/tests/test_boot_refusal_identity.c, which only ran when
 * a human invoked tools/scripts/winacceptance.sh. The probe body is the
 * original program verbatim. */
#include "test/test_core.h"

#include "config/boot_error.h"
#include "config/boot_refusal_reports.h"
#include "platform/current_identity.h"

#include <errno.h>
#include <string.h>

static int current_identity_boundary_probe(void)
{
    char untouched = 'x';
    if (platform_current_identity(NULL, 16))
        return 1;
    if (platform_current_identity(&untouched, 0) || untouched != 'x')
        return 2;

    char identity[192];
    if (!platform_current_identity(identity, sizeof(identity)))
        return 3;
    size_t required = strlen(identity) + 1;
    if (required <= 1 || required > sizeof(identity))
        return 4;

    char exact[192];
    memset(exact, 'x', sizeof(exact));
    if (!platform_current_identity(exact, required) ||
        strcmp(exact, identity) != 0)
        return 5;

    char short_out[192];
    memset(short_out, 'x', sizeof(short_out));
    if (platform_current_identity(short_out, required - 1) ||
        short_out[0] != '\0')
        return 6;
    return 0;
}

static int boot_refusal_identity_probe(void)
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

int test_boot_refusal_identity(void)
{
    int failures = 0;
    int rc = current_identity_boundary_probe();
    printf("current_identity: size boundaries fail closed with empty output... ");
    if (rc == 0) {
        printf("OK\n");
    } else {
        printf("FAIL (step %d)\n", rc);
        failures++;
    }

    rc = boot_refusal_identity_probe();
    printf("boot_refusal_identity: refusal report names the acting OS "
           "identity... ");
    if (rc == 0) {
        printf("OK\n");
    } else {
        printf("FAIL (step %d)\n", rc);
        failures++;
    }
    return failures;
}
