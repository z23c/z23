/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Unit tests for the boot de-fatal keystone:
 *   - the service_state primitive (platform/modules/util/src/service_state.c), the
 *     node's canonical runtime operational mode, and
 *   - chain_integrity_classify (engine/services/.../chain_restore_integrity.c),
 *     the predicate the boot finalize gate switches on to decide
 *     RECONCILABLE (DEGRADED_SERVING, never fatal) vs UNRECOVERABLE
 *     (fatal-LOUD) vs CLEAN.
 *
 * The classifier cases mirror a boot-loop shape:
 * zero_nbits=0, mismatches=0, tip_window_holes=2155 -> RECONCILABLE. */

#include "test/test_core.h"
#include "util/service_state.h"
#include "services/chain_restore_integrity.h"

#include <string.h>

#define SSC(desc, expr) do { \
    printf("service_state: %s... ", (desc)); \
    if (expr) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

int test_service_state(void)
{
    printf("\n=== service_state + integrity classifier tests ===\n");
    int failures = 0;

    /* ── names ── */
    SSC("name boot",
        strcmp(service_state_name(SERVICE_STATE_BOOT), "boot") == 0);
    SSC("name degraded_serving",
        strcmp(service_state_name(SERVICE_STATE_DEGRADED_SERVING),
               "degraded_serving") == 0);
    SSC("name healthy",
        strcmp(service_state_name(SERVICE_STATE_HEALTHY), "healthy") == 0);
    SSC("name out-of-range -> unknown",
        strcmp(service_state_name((enum service_state)999), "unknown") == 0);

    /* ── transitions ── */
    service_state_advance(SERVICE_STATE_RESTORE, "loading");
    SSC("advance to restore", service_state_current() == SERVICE_STATE_RESTORE);
    SSC("reason recorded", strcmp(service_state_reason(), "loading") == 0);

    service_state_advance(SERVICE_STATE_DEGRADED_SERVING,
                          "reconcilable divergence");
    SSC("advance to degraded_serving",
        service_state_current() == SERVICE_STATE_DEGRADED_SERVING);
    SSC("reason refreshed",
        strcmp(service_state_reason(), "reconcilable divergence") == 0);

    /* out-of-range targets are ignored; state unchanged */
    service_state_advance((enum service_state)-1, "bogus-low");
    SSC("invalid low ignored",
        service_state_current() == SERVICE_STATE_DEGRADED_SERVING);
    service_state_advance((enum service_state)SERVICE_STATE__COUNT, "bogus-high");
    SSC("invalid high ignored",
        service_state_current() == SERVICE_STATE_DEGRADED_SERVING);

    /* idempotent re-advance keeps state, refreshes reason */
    service_state_advance(SERVICE_STATE_DEGRADED_SERVING, "still degraded");
    SSC("idempotent re-advance",
        service_state_current() == SERVICE_STATE_DEGRADED_SERVING &&
        strcmp(service_state_reason(), "still degraded") == 0);

    service_state_advance(SERVICE_STATE_HEALTHY, "caught up");
    SSC("advance to healthy",
        service_state_current() == SERVICE_STATE_HEALTHY);

    /* ── boot-exit de-fatal targets (boot_services.c frontend/runtime) ──
     * Pins the exact (state, reason) the de-fatal uses, so a future rename or
     * a regression that points the boot path at a dropped state is caught. */
    SSC("DEGRADED_SERVING in range",
        (int)SERVICE_STATE_DEGRADED_SERVING >= 0 &&
        (int)SERVICE_STATE_DEGRADED_SERVING < (int)SERVICE_STATE__COUNT);

    service_state_advance(SERVICE_STATE_SYNCING, "syncing");
    service_state_advance(SERVICE_STATE_DEGRADED_SERVING,
                          "frontend_services_unavailable");
    SSC("frontend de-fatal -> DEGRADED_SERVING + reason",
        service_state_current() == SERVICE_STATE_DEGRADED_SERVING &&
        strcmp(service_state_reason(), "frontend_services_unavailable") == 0);
    SSC("frontend reason fits g_reason buffer",
        strlen("frontend_services_unavailable") < 127);

    /* runtime de-fatal after an already-DEGRADED frontend: refresh, no drop */
    service_state_advance(SERVICE_STATE_DEGRADED_SERVING,
                          "runtime_services_unavailable");
    SSC("runtime de-fatal stays DEGRADED_SERVING (idempotent refresh)",
        service_state_current() == SERVICE_STATE_DEGRADED_SERVING &&
        strcmp(service_state_reason(), "runtime_services_unavailable") == 0);
    SSC("runtime reason fits g_reason buffer",
        strlen("runtime_services_unavailable") < 127);

    /* ── integrity classifier: the boot de-fatal predicate ── */
    struct chain_integrity_result r;

    /* CLEAN: nothing wrong */
    memset(&r, 0, sizeof(r));
    r.ok = true;
    SSC("classify clean",
        chain_integrity_classify(&r) == CHAIN_INTEGRITY_CLEAN);

    /* RECONCILABLE: the LIVE case — window holes only, no nbits/mismatch */
    memset(&r, 0, sizeof(r));
    r.tip_window_holes = 2155;
    r.first_tip_window_hole = 3130702;
    r.tip_height = 3132856;
    r.ok = false;
    SSC("classify reconcilable (live boot-loop shape)",
        chain_integrity_classify(&r) == CHAIN_INTEGRITY_RECONCILABLE);

    /* UNRECOVERABLE: active_chain mismatch dominates even with holes */
    memset(&r, 0, sizeof(r));
    r.active_chain_mismatches = 1;
    r.tip_window_holes = 2155;
    r.ok = false;
    SSC("classify unrecoverable (mismatch)",
        chain_integrity_classify(&r) == CHAIN_INTEGRITY_UNRECOVERABLE);

    /* UNRECOVERABLE: zero nbits in the tip window */
    memset(&r, 0, sizeof(r));
    r.zero_nbits_count = 3;
    r.ok = false;
    SSC("classify unrecoverable (zero nbits)",
        chain_integrity_classify(&r) == CHAIN_INTEGRITY_UNRECOVERABLE);

    /* NULL fails closed */
    SSC("classify NULL -> unrecoverable",
        chain_integrity_classify(NULL) == CHAIN_INTEGRITY_UNRECOVERABLE);

    printf("service_state: %d failures\n", failures);
    return failures;
}
