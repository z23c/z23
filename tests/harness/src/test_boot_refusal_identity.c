/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: proves a boot refusal report names the acting OS identity --
 * platform_current_identity() yields a Windows `sid:S-` or POSIX `uid:`
 * string, and the rendered BOOT_DATADIR_CREATE_FAILED report must carry the
 * datadir and that exact identity, so a refusal says WHO was refused.
 *
 * Rehomed from tools/tests/test_boot_refusal_identity.c; the probe body is
 * the original program verbatim. */
#include "test/test_core.h"

#include "config/boot_error.h"
#include "config/boot_mempool_limits.h"
#include "config/boot_refusal_reports.h"
#include "platform/current_identity.h"

#include <errno.h>
#include <stdlib.h>
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

static bool mempool_limits_probe_start_ok(void *ctx)
{
    (void)ctx;
    return true;
}

static bool mempool_limits_probe_start_fail(void *ctx)
{
    (void)ctx;
    return false;
}

static void mempool_limits_probe_stop(void *ctx)
{
    (void)ctx;
}

static struct boot_svc_ctx *mempool_limits_probe_ctx(void)
{
    struct boot_svc_ctx *svc = calloc(1, sizeof(*svc));
    if (!svc)
        return NULL;
    zcl_service_kernel_init(&svc->service_kernel);
    static char db_standin;
    svc->db_service = (struct db_service *)&db_standin;
    return svc;
}

static int mempool_limits_refusal_codes(bool started, const char *code)
{
    char report[4096];
    if (started)
        return 3;
    if (!boot_error_reported())
        return 4;
    if (strcmp(boot_error_first_code(), code) != 0)
        return 5;
    if (!boot_error_last_render(report, sizeof(report)) ||
        !strstr(report, code) ||
        !strstr(report, "services.mempool_limits"))
        return 6;
    return 0;
}

static int boot_mempool_limits_register_refusal_probe(void)
{
    struct boot_svc_ctx *svc = mempool_limits_probe_ctx();
    if (!svc)
        return 1;
    const struct zcl_service_spec dup = {
        .name = "mempool_limits",
        .start = mempool_limits_probe_start_ok,
        .stop = mempool_limits_probe_stop,
        .flags = ZCL_SERVICE_OPTIONAL,
    };
    int rc = 2;
    if (zcl_service_kernel_register(&svc->service_kernel, &dup)) {
        boot_error_reset_for_testing();
        rc = mempool_limits_refusal_codes(
            boot_start_mempool_limits_service(svc),
            "BOOT_MEMPOOL_LIMITS_REGISTER_FAILED");
    }
    free(svc);
    return rc;
}

static int boot_mempool_limits_start_refusal_probe(void)
{
    struct boot_svc_ctx *svc = mempool_limits_probe_ctx();
    if (!svc)
        return 1;
    const struct zcl_service_spec blocker = {
        .name = "required_blocker",
        .start = mempool_limits_probe_start_fail,
        .stop = mempool_limits_probe_stop,
        .flags = 0,
    };
    int rc = 2;
    if (zcl_service_kernel_register(&svc->service_kernel, &blocker)) {
        boot_error_reset_for_testing();
        rc = mempool_limits_refusal_codes(
            boot_start_mempool_limits_service(svc),
            "BOOT_MEMPOOL_LIMITS_START_FAILED");
    }
    free(svc);
    return rc;
}

static int boot_signal_handler_install_refusal_probe(void)
{
    char report[4096];
    boot_error_reset_for_testing();
    boot_report_signal_handler_install_failed();
    if (!boot_error_reported())
        return 1;
    if (strcmp(boot_error_first_code(),
               "BOOT_SIGNAL_HANDLER_INSTALL_FAILED") != 0)
        return 2;
    if (!boot_error_last_render(report, sizeof(report)) ||
        !strstr(report, "BOOT_SIGNAL_HANDLER_INSTALL_FAILED") ||
        !strstr(report, "prologue.observability"))
        return 3;
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

    rc = boot_signal_handler_install_refusal_probe();
    printf("boot_refusal_identity: signal_handler_install failure is "
           "BOOT_SIGNAL_HANDLER_INSTALL_FAILED... ");
    if (rc == 0) {
        printf("OK\n");
    } else {
        printf("FAIL (step %d)\n", rc);
        failures++;
    }

    rc = boot_mempool_limits_register_refusal_probe();
    printf("boot_refusal_identity: mempool_limits register failure is "
           "BOOT_MEMPOOL_LIMITS_REGISTER_FAILED... ");
    if (rc == 0) {
        printf("OK\n");
    } else {
        printf("FAIL (step %d)\n", rc);
        failures++;
    }

    rc = boot_mempool_limits_start_refusal_probe();
    printf("boot_refusal_identity: mempool_limits start failure is "
           "BOOT_MEMPOOL_LIMITS_START_FAILED... ");
    if (rc == 0) {
        printf("OK\n");
    } else {
        printf("FAIL (step %d)\n", rc);
        failures++;
    }
    return failures;
}
