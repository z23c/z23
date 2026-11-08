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
#include "services/chain_evidence_authority_service.h"
#include "net/peer_lifecycle.h"

static int syncdiag_peer_summary(void)
{
    struct json_value params = {0}, arg = {0}, result = {0};
    json_set_array(&params);
    json_set_str(&arg, "peer_lifecycle");
    json_push_back(&params, &arg);
    json_set_str(&arg, "summary");
    json_push_back(&params, &arg);
    peer_lifecycle_note_attempt(NULL, PEER_LIFECYCLE_SOURCE_UNKNOWN);
    bool ok = diag_rpc_dumpstate_builtin(&params, false, &result);
    const struct json_value *state = json_get(&result, "state");
    const struct json_value *attempted = json_get(state, "attempted");
    bool valid = ok && attempted && attempted->type == JSON_INT &&
                 json_get_int(attempted) > 0 && !json_get(state, "peers") &&
                 json_write(&result, NULL, 0) < 4096;
    json_free(&result);
    json_free(&params);
    json_set_array(&params);
    json_set_str(&arg, "peer_lifecycle");
    json_push_back(&params, &arg);
    ok = diag_rpc_dumpstate_builtin(&params, false, &result);
    state = json_get(&result, "state");
    valid = valid && ok && json_get(state, "peers") != NULL;
    json_free(&result);
    json_set_str(&arg, "incidents");
    json_push_back(&params, &arg);
    ok = diag_rpc_dumpstate_builtin(&params, false, &result);
    state = json_get(&result, "state");
    valid = valid && ok && json_get(state, "incident_count") != NULL;
    if (!valid)
        printf("FAIL: peer lifecycle summary must contain totals without peer rows\n");
    json_free(&result);
    json_free(&arg);
    json_free(&params);
    return valid ? 0 : 1;
}

int test_syncdiag_rpc(void)
{
    int failures = 0;
    agent_security_posture_test_override_review_required(0);

    syncdiag_reset_rpc_globals_for_test();

    failures += syncdiag_peer_summary();

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
    /* Reap the one-shot evidence-maintenance thread healthcheck reads spawn. */
    chain_evidence_maintain_quiesce();

    syncdiag_reset_rpc_globals_for_test();
    agent_security_posture_test_override_review_required(-1);
    return failures;
}
