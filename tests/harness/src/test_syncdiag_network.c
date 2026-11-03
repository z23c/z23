/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * getnetworkinfo / peerincidents / bootstrapstatus cases: reachability
 * schema, external endpoint, duplicate-host telemetry, and the versioned
 * P2P + snapshot-authority posture.
 *
 * This file owns the group entry point; the scenarios themselves
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
    sd_report("bootstrapstatus: params_served and its blocker track "
              "-paramsdir, not just arming (RED)... ",
              sd_bootstrapstatus_beta6_params_scenario(), &failures);
    sd_report("getnetworkinfo: separates inbound reachability from "
              "outbound handshakes (RED)... ",
              sd_getnetworkinfo_reachability_scenario(), &failures);
    sd_report("getpeerinfo: reports plaintext, handshaking and hybrid "
              "Noise transport per peer (RED)... ",
              sd_getpeerinfo_transport_scenario(), &failures);
    sd_report("listbanned: lists a core ban with its reason; setban remove "
              "lifts it from the table and banlist.dat... ",
              sd_bans_listbanned_remove_scenario(), &failures);
    sd_report("setban add: bans a numeric address through core and persists; "
              "bad address, command, bantime and arity are RPC errors... ",
              sd_bans_setban_add_scenario(), &failures);
    sd_report("clearbanned: empties the table and banlist.dat; listbanned "
              "skips expired bans... ",
              sd_bans_clearbanned_scenario(), &failures);
    sd_report("setban add: refuses a bantime past the cap or one that would "
              "overflow... ",
              sd_bans_overflow_bantime_scenario(), &failures);
    sd_report("setban add: refuses a bantime that is not a whole number... ",
              sd_bans_nonnumeric_bantime_scenario(), &failures);
    sd_report("setban add: refuses a loopback address instead of a silent "
              "no-op... ",
              sd_bans_loopback_add_scenario(), &failures);

    return failures;
}
