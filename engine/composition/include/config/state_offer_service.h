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
 * within 576 blocks of this node's own tip (the compiled checkpoint height is
 * exempt from that window — see net/state_offer.h). The offer is signed with the
 * same durable Ed25519 online identity the mesh status lane and the fleet board
 * already sign with — no new key, no new key file, no second identity.
 *
 * That identity is minted ON DEMAND, and only for a node that has something to
 * advertise: the first peer-link tick at which this node holds a bundle it
 * would offer calls vcs_zcode_dht_online_key_load_or_create(), the same call the
 * fleet board makes. Before this, the key existed only if an operator had
 * happened to use the board, so a hosted node that registered and served a
 * half-gigabyte consensus bundle appended NO offer to its handshakes and a
 * stranger could never find it. A node holding no eligible bundle, or with no
 * running file service, still mints nothing and offers nothing.
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
#include <stddef.h>
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

/* True iff a peer handshaking with this node right now would hear a state
 * offer: this node can sign one AND its cached artifact snapshot holds a bundle
 * that passes the freshness rule at our own tip. The single honest answer to
 * "can a stranger find a state source through me", and the fact
 * `bootstrapstatus` reports. Reads cached state only — never drives the disk
 * scan that opens bundle manifests. */
bool state_offer_service_advertising(void);

/* Advance the consumer. Called from the peer-link tick, so it must stay cheap:
 * it notes the first peer, asks the store for a decision, and starts at most
 * one download thread. It never blocks on IO. */
void state_offer_service_tick(void);

#ifdef ZCL_TESTING
/* Rebuild the cached artifact snapshot on the next provider call. */
void state_offer_service_test_invalidate(void);
/* Pretend this node holds one registered bundle at `bundle_height`, so the
 * "do we hold something worth advertising" rule can be driven without a
 * datadir full of half-gigabyte artifacts. */
void state_offer_service_test_hold_artifact(int32_t bundle_height);
/* Run the mint-if-we-hold-something decision against an injected tip. */
void state_offer_service_test_ensure_identity(int32_t tip);
/* True iff this node can sign an offer right now. */
bool state_offer_service_test_have_identity(void);
/* Force the disk-backed artifact snapshot rebuild (the real
 * rom_seed_list()->open()->manifest-read path this file uses to decide what
 * to offer, not the injected `test_hold_artifact` shortcut) and return how
 * many artifacts it found offerable. `state_offer_service_start` must have
 * been called first so g_datadir is set. */
uint32_t state_offer_service_test_refresh_and_count(void);
/* Compose the absolute path this file resolves for a registered artifact's
 * catalog filename (rom_seed's stored `a->filename`), WITHOUT touching disk
 * or the snapshot — the exact function `sosvc_refresh_snapshot_locked` calls
 * to open the bundle manifest. Returns false only on truncation. Lets a test
 * pin the composed path against both the bare-basename and
 * "bundles/<name>" catalog shapes without needing a semantically valid
 * bundle on disk. `state_offer_service_start` must have been called first so
 * g_datadir is set. */
bool state_offer_service_test_compose_path(const char *filename, char *out,
                                           size_t out_sz);
#endif

#endif /* ZCL_CONFIG_STATE_OFFER_SERVICE_H */
