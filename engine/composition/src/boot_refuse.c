/* Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 *
 * purpose: refuse a boot at a permanent gate instead of parking alive-degraded,
 * split out of boot.c (E1 file-size ceiling) so boot.c stays under its
 * recorded line ceiling. See config/boot_internal.h for the declaration. */

#include "config/boot_internal.h"
#include "config/boot_error.h"
#include "util/boot_status.h"
#include "util/log_macros.h"

#include <stdio.h>
#include <unistd.h>
#include "util/thread_registry.h"

/* A one-shot -export-consensus-bundle must never wait at a boot gate: one
 * REFUSED line, latch FATAL, return false so main exits 1. Returns true when
 * it handled the gate, so both terminal gate behaviours below share it. */
bool boot_gate_export_refusal(const char *name)
{
    if (!boot_export_mode_active())
        return false;
    fprintf(stdout, "REFUSED: -export-consensus-bundle: reason=%s\n", name);
    fflush(stdout);
    boot_error_report(BOOT_ERROR_FATAL, "BOOT_EXPORT_BLOCKED",
                      "export_consensus_bundle",
                      "one-shot export hit a permanent boot blocker",
                      NULL, 0, "reason=%s", name);
    LOG_ERROR("boot.park", "export mode refuses to park at gate %s", name);
    return true;
}

/* Refuse the boot at a permanent gate: name the blocker in the beacon, render
 * the typed FATAL block with the operator's own next command, and return false
 * so app_init stops and main exits 1. Never true.
 *
 * Parking is only honest while the process is still worth something to an
 * operator. This gate fires at stage crypto_ready — no RPC bound,
 * serving=false — and the unit is Type=notify with READY= never sent from a
 * park, so systemd would show `activating (start)` until TimeoutStartSec
 * without ever saying failed. A refusal that exits reaches the operator in
 * seconds, and Restart= then owns the retry. */
bool boot_refuse_at_permanent_gate(const char *gate_name, const char *message,
                                   const struct boot_error_next *next,
                                   size_t next_count, const char *evidence)
{
    const char *name = gate_name ? gate_name : "boot_storage_gate";
    boot_status_set_blocker(name, name);
    if (boot_gate_export_refusal(name))
        return false;
    fprintf(stderr,
        "REFUSED: boot gate '%s' — the node is NOT running and NOT serving; "
        "nothing was started.\n", name);
    fflush(stderr);
    boot_error_report(BOOT_ERROR_FATAL, "BOOT_GATE_REFUSED", name,
                      message && message[0] ? message
                                            : "a permanent boot gate refused",
                      next, next_count, "reason=%s%s%s", name,
                      evidence && evidence[0] ? " " : "",
                      evidence ? evidence : "");
    return false;
}

/* Park alive-degraded until shutdown, then return false. Never true.
 * -export-consensus-bundle: one REFUSED line, latch FATAL, return (exit 1).
 * ONLY for a gate whose process still has something to offer while it waits;
 * a gate firing before the node serves anything must use
 * boot_refuse_at_permanent_gate() instead. */
bool boot_park_until_shutdown(const char *gate_name)
{
    const char *name = gate_name ? gate_name : "boot_storage_gate";
    boot_status_set_blocker(name, name);
    if (boot_gate_export_refusal(name))
        return false;
    fprintf(stderr,
        "[boot] PARKED alive-degraded at gate '%s' — bounded re-derive budget "
        "exhausted; the operator was paged. NOT crash-looping; waiting for a "
        "shutdown signal.\n", name);
    while (!thread_registry_shutdown_requested())
        sleep(2);
    return false;
}
