/* Copyright 2026 Rhett Creighton, Apache-2.0
 *
 * test_canary_watch_register_refusal — shipped boot_canary_watch_register
 * (engine/composition/src/boot_canary_watch.c). A NULL boot service context
 * returns false and latches BOOT_CANARY_WATCH_REGISTER_REFUSED with phase
 * canary.watch and evidence stage=canary_watch_no_context. No live
 * boot_svc_ctx and no canary sentinel poll: that path starts the watch.
 */

#include "test/test_core.h"

#include "config/boot_error.h"
#include "config/boot_internal.h"

#include <stdio.h>
#include <string.h>

#define CHECK(name, expr) do {                                          \
    printf("  canary_watch_register_refusal: %s... ", (name));          \
    if (expr) printf("OK\n");                                           \
    else { printf("FAIL\n"); failures++; }                              \
} while (0)

static bool cwr_render_names_refusal(void)
{
    char rendered[BOOT_ERROR_RENDER_MAX];
    size_t n = boot_error_last_render(rendered, sizeof(rendered));
    return n > 0 &&
           strstr(rendered, "phase:    canary.watch") != NULL &&
           strstr(rendered, "stage=canary_watch_no_context") != NULL;
}

int test_canary_watch_register_refusal(void);
int test_canary_watch_register_refusal(void)
{
    test_reset_shared_globals();
    boot_error_reset_for_testing();
    printf("\n=== canary_watch_register_refusal tests ===\n");
    int failures = 0;

    CHECK("quiet before register", boot_error_reported() == false);
    bool refused = boot_canary_watch_register(NULL);
    CHECK("NULL context returns false", refused == false);
    CHECK("NULL context latches", boot_error_reported() == true);
    CHECK("NULL context code",
          strcmp(boot_error_first_code(),
                 "BOOT_CANARY_WATCH_REGISTER_REFUSED") == 0);
    CHECK("NULL context names phase and stage", cwr_render_names_refusal());
    return failures;
}
