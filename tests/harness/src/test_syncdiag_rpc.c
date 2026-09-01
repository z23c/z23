/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Regression test: `getsyncdiag` RPC crashes via `json_free` on uninitialized
 * stack memory.
 *
 * The bug: `rpc_getsyncdiag` in `engine/controllers/src/health_controller.c`
 * declares `struct json_value wd;` (and `hdr`) without `json_init()` or
 * `= {0}`. `json_set_object(&wd)` internally calls `json_free(&wd)`,
 * which reads uninitialized `type`, `num_children`, and `children` —
 * typically crashing with SIGSEGV/SIGABRT once the stack region holds
 * non-zero residue from earlier RPCs (which is always the case on a
 * live node).
 *
 * This test dirties the lower stack with 0xCC before calling the RPC
 * to force the uninitialized read to observe garbage in a fresh test
 * process, making the repro deterministic. Post-fix (wd/hdr explicitly
 * zero-initialized), the RPC must return a well-formed JSON object
 * containing non-empty `watchdog` and `headers` sub-objects. */


#include "test/syncdiag_rpc_fixture.h"

int test_syncdiag_rpc(void)
{
    int failures = 0;
    agent_security_posture_test_override_review_required(0);

    syncdiag_reset_rpc_globals_for_test();

    failures += syncdiag_cases_anchorstatus();
    failures += syncdiag_cases_network();
    failures += syncdiag_cases_health();
    failures += syncdiag_cases_api_catalog();
    failures += syncdiag_cases_agent_status();
    failures += syncdiag_cases_agent_projection();
    failures += syncdiag_cases_agent_codemap();
    failures += syncdiag_cases_agent_contracts();
    failures += syncdiag_cases_agent_ops();
    failures += syncdiag_cases_agent_interface();
    failures += syncdiag_cases_operator();

    syncdiag_reset_rpc_globals_for_test();
    agent_security_posture_test_override_review_required(-1);
    return failures;
}
