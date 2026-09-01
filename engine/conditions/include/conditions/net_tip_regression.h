/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * net_tip_regression — OBSERVATIONAL "we are falling behind the network"
 * detector. SYMPTOM: the reachable network's modal advertised height keeps
 * advancing while OUR served (active-chain) height does not move for
 * NET_TIP_REGRESSION_SECS, and we are strictly behind the best advertised
 * chain. REMEDY: names it with a typed BLOCKER_TRANSIENT ("net_tip_regression")
 * carrying our height, the network modal/max height, and our delta; no self-heal
 * (COND_REMEDY_FAILED) — chain selection stays find_most_work_chain's job.
 * WITNESSED: clears once our height advances past the height at detect, or we
 * reach the network's best. One of several redundant fall-behind signals. */

#ifndef ZCL_CONDITIONS_NET_TIP_REGRESSION_H
#define ZCL_CONDITIONS_NET_TIP_REGRESSION_H

#include <stdbool.h>
#include <stdint.h>

void register_net_tip_regression(void);

#ifdef ZCL_TESTING
void net_tip_regression_test_reset(void);
/* Override the wall clock (unix secs) this detector samples. -1 = real clock. */
void net_tip_regression_test_set_now(int64_t now_unix);
bool net_tip_regression_test_detect(void);
#endif

#endif /* ZCL_CONDITIONS_NET_TIP_REGRESSION_H */
