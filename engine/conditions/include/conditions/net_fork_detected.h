/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * net_fork_detected — OBSERVATIONAL fork-evidence detector. SYMPTOM: the
 * network monitor's consensus view reports two peer clusters at the SAME
 * advertised height with DIFFERENT tip hashes, each backed by at least
 * NM_FORK_MIN_CLUSTER peers (real branch evidence, not one lagging/lying peer).
 * REMEDY: names it with a typed BLOCKER_TRANSIENT ("net_fork_detected")
 * carrying the fork height and both hashes + cluster sizes; no self-heal
 * (COND_REMEDY_FAILED) — the node never picks a side here, find_most_work_chain
 * does. WITNESSED: clears once the view shows no fork, or our tip has advanced
 * past the contested height. */

#ifndef ZCL_CONDITIONS_NET_FORK_DETECTED_H
#define ZCL_CONDITIONS_NET_FORK_DETECTED_H

#include <stdbool.h>

void register_net_fork_detected(void);

#ifdef ZCL_TESTING
void net_fork_detected_test_reset(void);
bool net_fork_detected_test_detect(void);
#endif

#endif /* ZCL_CONDITIONS_NET_FORK_DETECTED_H */
