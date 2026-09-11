/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Private facet shared by the sync-diagnostics network test scenario
 * check files (test_syncdiag_network.c and its
 * test_syncdiag_network_*.c siblings). No sibling declares its own
 * file-scope mutable state; each scenario's own fixture context
 * (struct sd_bootstrap_ctx, struct sd_snapshot_authority_ctx,
 * struct sd_reach_ctx) stays private to the sibling file that declares
 * and uses it — only the group entry point in test_syncdiag_network.c
 * needs to call every scenario across the split files.
 */

#ifndef TEST_SYNCDIAG_NETWORK_PRIV_H
#define TEST_SYNCDIAG_NETWORK_PRIV_H

#include <stdbool.h>

/* test_syncdiag_network_identity_and_onion.c — machine_identity,
 * onionstatus (ready and unavailable), getnetworkinfo's startup
 * reachability schema, peerincidents' duplicate-host telemetry and
 * dumpstate compatibility fallback, and getnetworkinfo's configured
 * external endpoint. */
bool sd_machine_identity_scenario(void);
bool sd_onionstatus_ready_scenario(void);
bool sd_onionstatus_unavailable_scenario(void);
bool sd_getnetworkinfo_startup_scenario(void);
bool sd_peerincidents_duplicate_host_scenario(void);
bool sd_peerincidents_dumpstate_fallback_scenario(void);
bool sd_getnetworkinfo_external_endpoint_scenario(void);

/* test_syncdiag_network_bootstrap_and_reachability.c —
 * bootstrapstatus's versioned P2P and beta6 snapshot contract, its
 * snapshot authority posture, and getnetworkinfo's inbound/outbound
 * reachability separation. */
bool sd_bootstrapstatus_ready_scenario(void);
bool sd_bootstrapstatus_snapshot_authority_scenario(void);
bool sd_bootstrapstatus_beta6_params_scenario(void);
bool sd_getnetworkinfo_reachability_scenario(void);

#endif
