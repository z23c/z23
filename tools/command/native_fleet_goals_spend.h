/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: Grades G11 (zero ZCL spend) from the declared capabilities of the
 *          fleet leaves in a command registry. Reads no wallet, datadir,
 *          node or ledger; a declared capability is not a measured spend.
 */

#ifndef ZCL_NATIVE_FLEET_GOALS_SPEND_H
#define ZCL_NATIVE_FLEET_GOALS_SPEND_H

#include "command/native_fleet_goals.h"
#include "kernel/command_registry.h"

/* Grades G11 over `reg`: UNMEASURED with no fleet leaves, FAIL naming the
 * first wallet-declaring leaves, else PARTIAL with the scanned count. Never
 * PASS. A NULL registry is UNMEASURED. */
struct zcl_goal_result zcl_goals_spend_measure(
    const struct zcl_command_registry *reg);

#endif
