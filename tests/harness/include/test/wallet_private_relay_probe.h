/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Hook from the Sapling shielded-send test into the private-relay group. */

#ifndef ZCL_TEST_WALLET_PRIVATE_RELAY_PROBE_H
#define ZCL_TEST_WALLET_PRIVATE_RELAY_PROBE_H

struct simnet;
struct transaction;

/* Take one fully proved and verified shielded transaction through the
 * private pool, a delayed push to one onion peer, and acceptance by a second
 * node's message processor. Returns the number of failed checks. */
int wallet_private_relay_shielded_probe(struct simnet *s,
                                        struct transaction *tx);

#endif
