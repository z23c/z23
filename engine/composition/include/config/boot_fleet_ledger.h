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

#endif /* ZCL_CONFIG_BOOT_FLEET_LEDGER_H */
