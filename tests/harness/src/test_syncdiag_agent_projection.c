/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * agent projection cases: bounded optional detail, stale mirror
 * suppression, stalled catch-up and idle download flags, fast-cache-miss
 * detail retention, and one-block-lookahead chain-ok classification.
 *
 * This file owns the group entry point; the six scenarios themselves
 * live in its test_syncdiag_agent_projection_*.c siblings, grouped by
 * what they cover (declared in test_syncdiag_agent_projection_priv.h).
 * Each scenario builds its fixture, calls the RPC, asserts on the
 * result, and frees what it owns; syncdiag_cases_agent_projection()
 * runs all six through a shared sd_report() helper.
 */

#include "test/syncdiag_rpc_fixture.h"
#include "test/test_syncdiag_agent_projection_priv.h"

static void sd_report(const char *desc, bool ok, int *failures)
{
    printf("%s", desc);
    if (ok)
        printf("OK\n");
    else {
        printf("FAIL\n");
        (*failures)++;
    }
}

int syncdiag_cases_agent_projection(void)
{
    int failures = 0;

    sd_report("api: native RPC agent bounds optional detail when budget "
              "is spent... ",
              sd_agent_budget_bound_scenario(), &failures);
    sd_report("api: native RPC agent suppresses stale mirror latch... ",
              sd_agent_stale_mirror_latch_scenario(), &failures);
    sd_report("api: native RPC agent flags stalled catch-up "
              "telemetry... ",
              sd_agent_stalled_catchup_scenario(), &failures);
    sd_report("api: native RPC agent flags idle download dispatch... ",
              sd_agent_dispatch_idle_scenario(), &failures);
    sd_report("api: native RPC agent keeps projection detail on fast "
              "cache miss... ",
              sd_agent_cache_miss_scenario(), &failures);
    sd_report("api: agentdiagnose treats one-block lookahead as "
              "chain-ok... ",
              sd_diag_lookahead_scenario(), &failures);

    return failures;
}
