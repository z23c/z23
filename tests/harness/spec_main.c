/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Spec-only test runner — runs all user story tests.
 * Build: make spec
 *
 * Kathy Sierra "Badass" specs: every test verifies
 * the USER becomes more capable, not the APP works. */

#include "test/test_core.h"
#include "keys/key.h"
#include "chain/chainparams.h"
#include <signal.h>

volatile sig_atomic_t g_shutdown_requested = 0;

int main(void)
{
    setbuf(stdout, NULL);
    int failures = 0;

    chain_params_select(CHAIN_MAIN);
    ecc_start();
    ecc_verify_init();

    printf("=== Z23 User Story Specs ===\n");
    printf("Kathy Sierra principle: test the USER, not the APP.\n\n");

    failures += spec_wallet_dashboard();
    failures += spec_wallet_send();
    failures += spec_wallet_receive();
    failures += spec_wallet_shield();
    failures += spec_wallet_node();
    failures += spec_wallet_history();
    failures += spec_wallet_coins();
    failures += spec_wallet_pulse();
    failures += spec_wallet_tx_detail();
    failures += spec_wallet_navigation();
    failures += spec_wallet_errors();
    failures += spec_wallet_privacy();
    failures += spec_wallet_sovereignty();
    failures += spec_wallet_celebration();
    failures += spec_wallet_empowerment();
    failures += spec_wallet_flow();
    failures += spec_wallet_accessibility();

    printf("\n=== MVC Data Layer & Event System ===\n");
    failures += spec_data_hooks();
    failures += spec_event_observers();
    failures += spec_state_machine();
    failures += spec_ux_sierra();
    failures += spec_html_quality();
    failures += spec_user_journeys();
    failures += spec_e2e_wallet();
    failures += spec_render_audit();
    failures += spec_smoke();
    failures += spec_100_stories();

    ecc_verify_destroy();
    ecc_stop();

    printf("\n========================================\n");
    printf("%s (%d spec failures)\n",
           failures ? "SOME SPECS FAILED" : "ALL SPECS PASSED", failures);
    printf("========================================\n");
    return failures ? 1 : 0;
}
