/* Copyright 2026 Rhett Creighton, Apache-2.0
 *
 * test_soak_attestation_register_refusal — shipped
 * boot_soak_attestation_register
 * (engine/composition/src/boot_soak_attestation.c). A NULL boot service
 * context returns false and latches BOOT_SOAK_ATTESTATION_REGISTER_REFUSED
 * with phase soak.attestation and evidence
 * stage=soak_attestation_no_context. No live boot_svc_ctx: that path
 * registers the service.
 */

#include "test/test_core.h"

#include "config/boot_error.h"
#include "config/boot_internal.h"

#include <stdio.h>
#include <string.h>

#define CHECK(name, expr) do {                                          \
    printf("  soak_attestation_register_refusal: %s... ", (name));      \
    if (expr) printf("OK\n");                                           \
    else { printf("FAIL\n"); failures++; }                              \
} while (0)

static bool sar_render_names_refusal(void)
{
    char rendered[BOOT_ERROR_RENDER_MAX];
    size_t n = boot_error_last_render(rendered, sizeof(rendered));
    return n > 0 &&
           strstr(rendered, "phase:    soak.attestation") != NULL &&
           strstr(rendered, "stage=soak_attestation_no_context") != NULL;
}

int test_soak_attestation_register_refusal(void);
int test_soak_attestation_register_refusal(void)
{
    test_reset_shared_globals();
    boot_error_reset_for_testing();
    printf("\n=== soak_attestation_register_refusal tests ===\n");
    int failures = 0;

    CHECK("quiet before register", boot_error_reported() == false);
    bool refused = boot_soak_attestation_register(NULL);
    CHECK("NULL context returns false", refused == false);
    CHECK("NULL context latches", boot_error_reported() == true);
    CHECK("NULL context code",
          strcmp(boot_error_first_code(),
                 "BOOT_SOAK_ATTESTATION_REGISTER_REFUSED") == 0);
    CHECK("NULL context names phase and stage", sar_render_names_refusal());
    return failures;
}
