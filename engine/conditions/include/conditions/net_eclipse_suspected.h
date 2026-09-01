/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * net_eclipse_suspected — the eclipse BLOCKER, promoted from the network_crawler
 * census `eclipse_suspected` field to a typed (detect, remedy, witness)
 * condition. SYMPTOM: the crawler's wider-network census flags eclipse (our
 * connected peers cluster on a height that is a small minority of the reachable
 * network) for 2 consecutive census rounds — durable enough to not be one noisy
 * sample. REMEDY: names it with a typed BLOCKER_TRANSIENT and actively widens
 * peering (connman_kick_seed_discovery + connman_kick_onion_seeds). WITNESSED:
 * clears once the census no longer suspects eclipse and we hold healthy
 * outbound peers again. Observational overlay on chain selection — never
 * touches find_most_work_chain. */

#ifndef ZCL_CONDITIONS_NET_ECLIPSE_SUSPECTED_H
#define ZCL_CONDITIONS_NET_ECLIPSE_SUSPECTED_H

#include <stdbool.h>
#include <stdint.h>

void register_net_eclipse_suspected(void);

#ifdef ZCL_TESTING
void net_eclipse_suspected_test_reset(void);
bool net_eclipse_suspected_test_detect(void);
/* Run the remedy directly (returns COND_REMEDY_OK/FAILED as an int to avoid
 * pulling framework/condition.h into the test's include set). */
int  net_eclipse_suspected_test_remedy(void);
#endif

#endif /* ZCL_CONDITIONS_NET_ECLIPSE_SUSPECTED_H */
