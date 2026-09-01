/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * chain_reorg_uncorroborated — the eclipse-resistance BLOCKER for a best-header
 * SWITCH that only one address group has served. SYMPTOM: the header
 * corroboration policy (net/header_corroboration.h) is currently HOLDING a
 * strictly-better, deeper-than-K, above-checkpoint reorg candidate because no
 * second distinct address group has corroborated the new branch. REMEDY: names
 * it with a typed BLOCKER_TRANSIENT (fork height + work delta + peer) and
 * actively widens peering (connman_kick_seed_discovery + connman_kick_onion_
 * seeds) to solicit an independent corroborator. WITNESSED: clears the instant
 * the hold clears — a second group corroborates the branch, or the branch is
 * abandoned/absorbed as the honest chain advances. Local policy overlay: the
 * held candidate never leaves the header tree and the peer is never banned;
 * plain extension of the current chain is never affected. */

#ifndef ZCL_CONDITIONS_CHAIN_REORG_UNCORROBORATED_H
#define ZCL_CONDITIONS_CHAIN_REORG_UNCORROBORATED_H

#include <stdbool.h>

void register_chain_reorg_uncorroborated(void);

#endif /* ZCL_CONDITIONS_CHAIN_REORG_UNCORROBORATED_H */
