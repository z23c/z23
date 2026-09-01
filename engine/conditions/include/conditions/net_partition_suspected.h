/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * net_partition_suspected — OBSERVATIONAL "WE may be cut off" detector (not
 * "the network halted"). SYMPTOM, either: (A) our sampled handshaked-peer count
 * collapses below NET_PARTITION_MIN_PEERS for NET_PARTITION_SECS (eclipse), or
 * (B) we still have peers and are strictly behind the best advertised chain, yet
 * neither our height NOR the network's max advertised height has moved for
 * NET_PARTITION_SECS (nothing is being delivered to us). REMEDY: names it with a
 * typed BLOCKER_TRANSIENT ("net_partition_suspected"); no self-heal
 * (COND_REMEDY_FAILED) — peer re-discovery is peer_floor_violated's remedy; this
 * is a redundant, independent naming of the same "falling behind" class from the
 * partition angle. WITNESSED: clears once peers recover above the floor, or our
 * height / the network max advances again. */

#ifndef ZCL_CONDITIONS_NET_PARTITION_SUSPECTED_H
#define ZCL_CONDITIONS_NET_PARTITION_SUSPECTED_H

#include <stdbool.h>
#include <stdint.h>

void register_net_partition_suspected(void);

#ifdef ZCL_TESTING
void net_partition_suspected_test_reset(void);
/* Override the wall clock (unix secs) this detector samples. -1 = real clock. */
void net_partition_suspected_test_set_now(int64_t now_unix);
bool net_partition_suspected_test_detect(void);
#endif

#endif /* ZCL_CONDITIONS_NET_PARTITION_SUSPECTED_H */
