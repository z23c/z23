/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: The "ledger" mesh stream service — the owner's private fleet
 * ledger replicating between PAIRED peers, and nowhere else.
 *
 * Pull only. A box asks each paired peer for the rows of that peer's own
 * chain it does not already hold, and answers the same question when asked.
 * Nothing is pushed, nothing is gossiped, and no row is ever volunteered to
 * anyone: a peer that never asks never learns.
 *
 * The privacy boundary is three checks that do not depend on each other.
 * The stream primitive refuses a link that is not an established Noise
 * session and a peer whose pairing row does not grant the capability. This
 * lane checks the pairing itself before it opens anything, so an outbound
 * stream is never opened toward an unpaired peer even if the primitive
 * would have allowed it. And the ledger module refuses any row that does
 * not carry exactly the box and signer this peer's verified delegation
 * authorises. One of those failing is caught by the other two.
 *
 * DISK WRITES NEVER HAPPEN ON THE STREAM LANE. A received batch is copied
 * into a bounded per-stream buffer under the lane lock and handed to this
 * lane's own tick, which verifies and commits it with no lock held. A
 * chainlog append is two fsyncs, and on the slow-disk boxes this fleet
 * treats as first class that is long enough to stall the one stream pump
 * every service shares.
 */

#ifndef ZCL_CONFIG_BOOT_FLEET_LEDGER_H
#define ZCL_CONFIG_BOOT_FLEET_LEDGER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct boot_svc_ctx;

#define FLEET_LEDGER_SERVICE_NAME "ledger"

/* One pull per paired peer at this cadence — the same interval the mesh
 * status refresher already polls paired machines on, because a ledger pull
 * answers the same kind of question about the same peers. */
#define FLEET_LEDGER_PULL_INTERVAL_S 15

/* The PULL a stream opens with, and the answer's bound. One answer fits in
 * one stream frame, so a batch is never split across frames and a receiver
 * never has to hold half a row. */
#define FLEET_LEDGER_MSG_PULL 1u
#define FLEET_LEDGER_PULL_BYTES 10u
#define FLEET_LEDGER_ANSWER_MAX (size_t)(48u * 1024u)

/* Batches waiting to be committed by the tick. Small: a peer that answers
 * faster than this box can commit is asked less often, not queued deeper. */
#define FLEET_LEDGER_INBOX_MAX 8u

void boot_fleet_ledger_wire(struct boot_svc_ctx *svc);
void boot_fleet_ledger_shutdown(void);

/* Registered once; serves both halves of every ledger stream. Exposed so a
 * test can register the service without a live composition context. */
bool boot_fleet_ledger_register_service(void);

/* Refusals this lane counts, reported by `fleet ledger status`.
 *
 * delegation_refused: peers neither asked nor answered because their ZID
 * delegation was no longer current, on either half of the protocol. A
 * pairing row states its own window and its own revocation and nothing
 * about the master identity behind it, so this number is the only place a
 * revoked-but-unexpired pairing becomes visible.
 *
 * inbox_full: batches that arrived with no free commit slot. No row is
 * lost — the next pull asks for the same range — but a box that keeps
 * printing this one is not keeping up with what it asks for. */
uint64_t boot_fleet_ledger_delegation_refused_count(void);
uint64_t boot_fleet_ledger_inbox_full_count(void);

#ifdef ZCL_TESTING
struct zcl_fleet_ledger;
struct vcs_zcode_dht_delegation;
/* Test seams that drive the EXACT production callbacks, the same way
 * mesh_stream's own seams do — no reimplementation of the protocol lives
 * in the test.
 *
 * A loopback runs both halves in one process, and the served identity is
 * process-wide, so the seams name the store each half acts on rather than
 * sharing one: bind supplies the ANSWERING box's store and identity, the
 * pair wire() would have read from the datadir; pull opens the asking
 * half's stream toward a peer the caller has already resolved, which is
 * the one frame-level entry point; pull_paired runs the REAL pull lane,
 * pairing rows and delegation check included, against the caller's store;
 * serve runs the answering tick once; drain_into runs the inbox commit the
 * supervisor tick would have run, against the ASKING box's store,
 * synchronously, so a test never waits on a clock.
 *
 * Pass NULL to bind to unbind and empty the inbox. */
void boot_fleet_ledger_test_bind(struct zcl_fleet_ledger *ledger,
                                 const uint8_t box_id[32],
                                 const uint8_t signer[32]);
bool boot_fleet_ledger_test_pull(const uint8_t peer_noise[32],
                                 const uint8_t peer_box_id[32],
                                 const uint8_t peer_signer[32],
                                 uint64_t since_seq);
void boot_fleet_ledger_test_pull_paired(struct zcl_fleet_ledger *ledger,
                                        int64_t now);
void boot_fleet_ledger_test_serve(void);
void boot_fleet_ledger_test_drain_into(struct zcl_fleet_ledger *ledger);

/* Stand in for the ONE composition root this test group cannot host: the
 * DHT service that holds a paired peer's current delegation, the network
 * genesis that service is bound to, and — because an accept callback is
 * handed no clock — the fixture's fixed time. The AUTHORITY ITSELF is never
 * stubbed: the real mesh_pairing_service_authorize_status still runs
 * against the real node.db, so what a test grades is this lane's decision
 * and not a stand-in for it. Bound delegations match on the Noise static,
 * exactly as the DHT lookup does. Pass NULL to unbind. */
void boot_fleet_ledger_test_bind_authority(
    const struct vcs_zcode_dht_delegation *peer_delegation,
    const uint8_t network_genesis[32], int64_t now);
#endif

#endif /* ZCL_CONFIG_BOOT_FLEET_LEDGER_H */
