/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * netsplit_degraded_mode — the poll loop that turns the netsplit DETECTOR
 * (services/network_monitor.h, network_monitor_netsplit_suspected) into a
 * standing POSTURE (services/directory_influence_policy.h) and a named,
 * operator-visible blocker.
 *
 * DETECT: the corroborated minority-side verdict stands. The detect pass also
 * folds the verdict — in both directions — into the directory-influence
 * policy, so engaging AND disengaging degraded mode happen on the poll
 * cadence and never depend on a witness window being open.
 * REMEDY: names it (blocker SUSPECTED_NETSPLIT, raised by the policy) and
 * returns COND_REMEDY_FAILED. There is no local cure for a network split;
 * claiming one would be a lie. What the node does have is a correct posture:
 * new directory entries gain no influence, pre-split final entries keep
 * working, discovery leans on the always-present roots, and tip-following,
 * relay, the explorer and wallet viewing are untouched.
 * WITNESSED: the detector stops firing; the detect pass has already restored
 * influence and cleared the blocker.
 */

#ifndef ZCL_CONDITIONS_NETSPLIT_DEGRADED_MODE_H
#define ZCL_CONDITIONS_NETSPLIT_DEGRADED_MODE_H

#include <stdbool.h>

void register_netsplit_degraded_mode(void);

#ifdef ZCL_TESTING
bool netsplit_degraded_mode_test_detect(void);
#endif

#endif /* ZCL_CONDITIONS_NETSPLIT_DEGRADED_MODE_H */
