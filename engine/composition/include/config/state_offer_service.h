/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Produce this node's state offers, and act on the ones it accepts.
 *
 * ZRC-0011 phase 1a, the half that touches the world. config/state_offer_store.h
 * decides; this module supplies the facts the decision needs and carries out
 * what it decides.
 *
 * PRODUCING. A node offers only what it actually holds and can actually serve:
 * an artifact the ROM seed registry has registered under <datadir>/bundles/,
 * whose bundle manifest opens and names a height and a block hash, that is
 * within 576 blocks of this node's own tip. The offer is signed with the same
 * durable Ed25519 online identity the mesh status lane already signs with
 * (vcs_zcode_dht_online_key_load) — no new key, no new key file. A node with no
 * identity material, no eligible bundle, or no running file service simply
 * offers nothing, which is the pre-offer behaviour unchanged.
 *
 * ACTING. When the store chooses an offer, the bytes are fetched through the
 * UNCHANGED ROM-manifest path: the per-chunk SHA3 manifest is fetched and bound
 * to the offer's own chunk root, every chunk is content-verified BEFORE its
 * journal bit is set, the whole file is SHA3-checked before the atomic rename,
 * and the landed file is read-only exactly as an operator-seeded one is. Then
 * the UNCHANGED install path is armed through boot_install_bundle_request(), so
 * checkpoint re-derivation and Sapling-root re-derivation happen exactly as
 * they do for a bundle an operator dropped in by hand. This module adds no
 * verification of its own and removes none.
 *
 * A fetch that fails at any of those checks discards the file, strikes the
 * offering peer in the store, and lets the next offer be chosen. The peer is
 * never address-banned — see config/state_offer_store.h.
 *
 * THREADING. The decision runs on the caller's tick (the peer-link swarm tick);
 * the download runs on ONE worker thread, started at most once, joined at
 * shutdown. A multi-hundred-megabyte transfer must never run on the thread that
 * processes peer messages. */

#ifndef ZCL_CONFIG_STATE_OFFER_SERVICE_H
#define ZCL_CONFIG_STATE_OFFER_SERVICE_H

#include <stdbool.h>
#include <stdint.h>

struct msg_processor;
struct node_db;

/* Register the receive-side sink on the message processor. Separate from
 * start() because the message processor is built after the datadir is known. */
void state_offer_service_wire(struct msg_processor *mp);

/* Register the offer provider (send side) and the offer sink (receive side),
 * and record the datadir the fetch will stage into. Safe to call when this node
 * has no identity or no bundle: it then consumes offers without making any. */
void state_offer_service_start(const char *datadir, struct node_db *ndb);
void state_offer_service_shutdown(void);

/* Advance the consumer. Called from the peer-link tick, so it must stay cheap:
 * it notes the first peer, asks the store for a decision, and starts at most
 * one download thread. It never blocks on IO. */
void state_offer_service_tick(void);

#ifdef ZCL_TESTING
/* Rebuild the cached artifact snapshot on the next provider call. */
void state_offer_service_test_invalidate(void);
#endif

#endif /* ZCL_CONFIG_STATE_OFFER_SERVICE_H */
