/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * getnetworkinfo / peerincidents / bootstrapstatus cases: reachability
 * schema, external endpoint, duplicate-host telemetry, and the versioned
 * P2P + snapshot-authority posture.
 *
 * This file owns the group entry point; the ten scenarios themselves
 * live in its test_syncdiag_network_*.c siblings, grouped by what they
 * cover (declared in test_syncdiag_network_priv.h). Each scenario is
 * its own function that builds its fixture, calls the RPC, asserts on
 * the result, and frees what it owns; syncdiag_cases_network() runs
 * all ten and prints one OK/FAIL line per scenario.
 */

#include "test/syncdiag_rpc_fixture.h"
#include "test/test_syncdiag_network_priv.h"

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

int syncdiag_cases_network(void)
{
    int failures = 0;

    sd_report("machine_identity: reports independent live facts without "
              "secrets... ",
              sd_machine_identity_scenario(), &failures);
    sd_report("onionstatus: exposes one coherent bootstrap-state "
              "contract... ",
              sd_onionstatus_ready_scenario(), &failures);
    sd_report("onionstatus: -tor requested but not running is unavailable "
              "not disabled (RED)... ",
              sd_onionstatus_unavailable_scenario(), &failures);
    sd_report("getnetworkinfo: reports stable startup reachability schema "
              "(RED)... ",
              sd_getnetworkinfo_startup_scenario(), &failures);
    sd_report("peerincidents: exposes compact duplicate host telemetry "
              "(RED)... ",
              sd_peerincidents_duplicate_host_scenario(), &failures);
    sd_report("peerincidents: normalizes dumpstate compatibility fallback "
              "(RED)... ",
              sd_peerincidents_dumpstate_fallback_scenario(), &failures);
    sd_report("getnetworkinfo: exposes configured external endpoint "
              "(RED)... ",
              sd_getnetworkinfo_external_endpoint_scenario(), &failures);
    sd_report("bootstrapstatus: exposes versioned P2P and beta6 "
              "snapshot contract (RED)... ",
              sd_bootstrapstatus_ready_scenario(), &failures);
    sd_report("bootstrapstatus: exposes snapshot authority posture "
              "(RED)... ",
              sd_bootstrapstatus_snapshot_authority_scenario(), &failures);
    sd_report("getnetworkinfo: separates inbound reachability from "
              "outbound handshakes (RED)... ",
              sd_getnetworkinfo_reachability_scenario(), &failures);

    return failures;
}
