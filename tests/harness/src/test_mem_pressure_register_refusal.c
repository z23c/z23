/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_mem_pressure_register_refusal — shipped boot_mem_pressure_register
 * (engine/composition/src/boot_mem_pressure.c). A NULL boot service context
 * returns false and latches BOOT_MEM_PRESSURE_REGISTER_REFUSED with phase
 * mem.pressure and evidence stage=mem_pressure_no_context. No live
 * boot_svc_ctx: that path starts the memory-pressure poll.
 */

#include "test/test_core.h"

#include "config/boot_error.h"
#include "config/boot_internal.h"

#include <stdio.h>
#include <string.h>

#define CHECK(name, expr) do {                                          \
    printf("  mem_pressure_register_refusal: %s... ", (name));          \
    if (expr) printf("OK\n");                                           \
    else { printf("FAIL\n"); failures++; }                              \
} while (0)

static bool mpr_render_names_refusal(void)
{
    char rendered[BOOT_ERROR_RENDER_MAX];
    size_t n = boot_error_last_render(rendered, sizeof(rendered));
    return n > 0 &&
           strstr(rendered, "phase:    mem.pressure") != NULL &&
           strstr(rendered, "stage=mem_pressure_no_context") != NULL;
}

int test_mem_pressure_register_refusal(void);
int test_mem_pressure_register_refusal(void)
{
    test_reset_shared_globals();
    boot_error_reset_for_testing();
    printf("\n=== mem_pressure_register_refusal tests ===\n");
    int failures = 0;

    CHECK("quiet before register", boot_error_reported() == false);
    bool refused = boot_mem_pressure_register(NULL);
    CHECK("NULL context returns false", refused == false);
    CHECK("NULL context latches", boot_error_reported() == true);
    CHECK("NULL context code",
          strcmp(boot_error_first_code(),
                 "BOOT_MEM_PRESSURE_REGISTER_REFUSED") == 0);
    CHECK("NULL context names phase and stage", mpr_render_names_refusal());
    return failures;
}
