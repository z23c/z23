/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_sandbox_steady_refusal — boot_sandbox_enter
 * (engine/composition/src/boot_sandbox_startup.c).
 *
 * -sandbox off and a NULL app context stay quiet: the call returns ok and
 * does not latch a boot error. -sandbox=steady with no datadir returns not
 * ok and reports BOOT_SANDBOX_STEADY_REFUSED with phase sandbox.steady and
 * evidence stage=sandbox_no_datadir.
 */

#include "test/test_core.h"

#include "config/boot_error.h"
#include "config/boot.h"

#include "../../../engine/composition/src/boot_cutover_startup_internal.h"

#include <stdio.h>
#include <string.h>

#define SSR_CHECK(name, expr) do {                              \
    printf("  sandbox_steady_refusal: %s... ", (name));         \
    if (expr) printf("OK\n");                                   \
    else { printf("FAIL\n"); failures++; }                      \
} while (0)

static bool ssr_render_has_stage(void)
{
    char rendered[BOOT_ERROR_RENDER_MAX];
    size_t n = boot_error_last_render(rendered, sizeof(rendered));
    return n > 0 &&
           strstr(rendered, "phase:    sandbox.steady") != NULL &&
           strstr(rendered, "stage=sandbox_no_datadir") != NULL;
}

int test_sandbox_steady_refusal(void);
int test_sandbox_steady_refusal(void)
{
    test_reset_shared_globals();
    printf("\n=== sandbox_steady_refusal tests ===\n");
    int failures = 0;
    struct app_context actx;

    boot_error_reset_for_testing();
    memset(&actx, 0, sizeof(actx));
    struct zcl_result quiet = boot_sandbox_enter(&actx, NULL);
    SSR_CHECK("steady off returns ok", quiet.ok == true);
    SSR_CHECK("steady off does not latch", boot_error_reported() == false);

    boot_error_reset_for_testing();
    struct zcl_result null_actx = boot_sandbox_enter(NULL, NULL);
    SSR_CHECK("NULL actx returns ok", null_actx.ok == true);
    SSR_CHECK("NULL actx does not latch", boot_error_reported() == false);

    boot_error_reset_for_testing();
    memset(&actx, 0, sizeof(actx));
    actx.sandbox_steady = true;
    struct zcl_result refused = boot_sandbox_enter(&actx, NULL);
    SSR_CHECK("no datadir returns not ok", refused.ok == false);
    SSR_CHECK("no datadir latches", boot_error_reported() == true);
    SSR_CHECK("no datadir code",
              strcmp(boot_error_first_code(),
                     "BOOT_SANDBOX_STEADY_REFUSED") == 0);
    SSR_CHECK("no datadir names stage", ssr_render_has_stage());

    return failures;
}
