/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Grades the seamless-update row G6 of `fleet.goals` from the
 *          release conveyor's own ledger on the conveyor host: its tick.log
 *          (START, RELEASED, FAILED, HELD lines) and the per-attempt
 *          release-<sha8>.log. Read-only; it starts nothing and probes no
 *          remote host. */

#ifndef ZCL_NATIVE_FLEET_GOALS_RELEASE_H
#define ZCL_NATIVE_FLEET_GOALS_RELEASE_H

#include "command/native_fleet_goals.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Landings the newest attempt may run ahead of the last release before the
 * row fails even without a FAILED line (a held or stopped conveyor). */
#define ZCL_GOALS_RELEASE_BEHIND_MAX 12

struct zcl_goals_release_in {
    const char *state_dir; /* conveyor state dir holding tick.log and
                            * release-<sha8>.log; NULL = unmeasured */
    size_t admitted_hosts; /* admitted roster size, supplied by the wiring */
    int64_t now_unix;      /* for the age of the last release */
    int64_t behind_max;    /* 0 = ZCL_GOALS_RELEASE_BEHIND_MAX */
};

/* FAIL when the newest conveyor attempt after the last RELEASED failed
 * (naming its rc and the last step its log recorded), when a release ran
 * more than behind_max landings behind the newest attempt, or when the
 * last release logged a host whose CLI, z23-dev or docs were NOT updated.
 * PARTIAL when the conveyor is current: the processes each host runs are
 * not probed. UNMEASURED without a ledger. Never PASS. */
struct zcl_goal_result zcl_goals_release_measure(
    const struct zcl_goals_release_in *in);

#endif /* ZCL_NATIVE_FLEET_GOALS_RELEASE_H */
