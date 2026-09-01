/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Boot-time wiring of SIGNED ENDPOINT RECORDS (zid/zendp.h "ZIDE",
 * carried as blobs by vcs/zendp_swarm.h).
 *
 * Two jobs, both of which can only be done at the composition root:
 *
 *  1. Close the chain binding. vcs/zendp_swarm.h names a port for
 *     "is this master key anchored on-chain, at what height, and is it
 *     still live?"; the answer lives in db_zid_identity_find
 *     (app/models), far above contexts/commons/modules/vcs. This file registers the
 *     implementation. Until it is registered, zendp fails CLOSED:
 *     every record is refused ZENDP_ERR_NO_ANCHOR_LOOKUP.
 *
 *  2. Project the verified records into peer discovery as an
 *     ADDITIONAL source — never a replacement for, and never a filter
 *     on, any source already wired. */

#ifndef ZCL_CONFIG_BOOT_ENDPOINT_RECORDS_H
#define ZCL_CONFIG_BOOT_ENDPOINT_RECORDS_H

#include "net/onion_discovery.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Register the on-chain identity lookup with vcs/zendp_swarm. Safe to
 * call before node.db is open: the lookup itself reports "could not
 * ask" separately from "the chain said no". */
void boot_endpoint_records_register(void);

/* THE ONE mapping from a zid_identities projection row to an anchor
 * verdict, over whichever node.db the caller has: the running node
 * passes its runtime handle, the CLI (tools/command/native_zendp_command.c)
 * passes an ad-hoc READONLY one. Exported rather than copied — a second
 * copy of "which status literal means ACTIVE" is a second answer to the
 * only question this whole subsystem asks.
 *
 * Returns false when the question could not be ASKED (no node.db, or a
 * status literal this build does not know), which is never the same as
 * "no such identity" — that is a true return carrying
 * ZENDP_ANCHOR_ABSENT. */
struct node_db;
struct zendp_anchor;
bool boot_endpoint_anchor_from_db(struct node_db *ndb,
                                  const uint8_t pubkey[32],
                                  struct zendp_anchor *out);

/* Load every record filed under <datadir>/zcode/endpoints/ into the
 * process-wide directory, re-running the WHOLE pipeline on each — the
 * files are witnesses, never the authority for what a record says, and
 * a key that was ACTIVE when the file was written may have been revoked
 * since. A record that does not resolve to an ACTIVE on-chain anchor is
 * DISCARDED here, exactly as it would be on the wire.
 *
 * CALL THIS ON THE BOOT THREAD ONLY. It reads files and does one
 * node.db lookup per record. The discovery projection
 * (boot_endpoint_record_peers) runs on the shared supervisor tick
 * runner via onion_directory_tick, and a blocking DB read there is how
 * this node has been killed by its own watchdog before — so the load is
 * a one-shot at start and never lazy off the discovery path.
 *
 * Returns the number of records installed. Bounded by ZENDP_DIR_MAX;
 * a NULL or missing directory is 0, not an error (the state of a node
 * that has never accepted a record). */
int boot_endpoint_records_load(const char *datadir);

/* An onion_signed_peer_source_fn over the verified endpoint-record
 * directory: only records inside their own signed validity window and
 * backed by an ACTIVE on-chain anchor, projected through the same v3
 * hostname rule every other source passes. Returns 0 when nothing has
 * been accepted, which is the state of a node that has never seen a
 * record. */
int boot_endpoint_record_peers(void *ctx, struct onion_peer *out, size_t max);

/* ── revalidation: a key revoked mid-run stops being advertised ─────
 *
 * The load above is a one-shot, so until now the chain's verdict on a
 * record was decided once, at acceptance, and cached for the life of the
 * process. A key REVOKED or ROTATED while the node stayed up kept being
 * offered to peer discovery until the record's own signed expiry (the
 * `zcode endpoint publish` default is 3 days, and no maximum window is
 * enforced anywhere) or until a restart.
 *
 * WHAT DRIVES IT. The fold publishes a monotonic counter on every
 * applied ANCHOR / ROTATE / REVOKE (zid_identity_status_generation,
 * models/zid_identity.h). This worker polls that counter; when it moves,
 * it re-asks the chain about every held record and drops the ones that
 * are no longer ACTIVE. Poll, not push, deliberately: a callback would
 * run this node.db sweep on the block-fold thread.
 *
 * WHY A DEDICATED THREAD, and not a supervisor tick child. The sweep
 * performs one node.db read per held identity. The two in-tree shapes
 * for a supervised periodic job are a tick child driven by the shared
 * root runner (engine/services/src/op_return_backfill_service.c) and an OS
 * thread that heartbeats itself (engine/composition/src/boot_seniority.c). This
 * takes the second, for the same reason boot_seniority.h gives and the
 * same reason this file's load is boot-only: a blocking database read on
 * the shared tick runner parks every other child behind it, and that is
 * how this node has been SIGABRT'd by its own watchdog. The tick runner
 * also drives onion_directory_tick, which reads the very directory this
 * sweep writes — putting the sweep there would mean the discovery
 * projection waited on the database by construction.
 *
 * It is still SUPERVISED: registered as "net.endpoint_revalidate" with
 * period 0 (self-heartbeat) and an armed no-progress policy. The marker
 * counts applied sweeps, so a worker that runs forever without ever
 * resolving a generation bump raises a stall instead of looking healthy.
 */

/* What one pass decided. IDLE is the only outcome that reports the
 * worker healthy-with-nothing-to-do, and it is returned ONLY when the
 * generation has positively not moved since the last applied sweep. */
enum boot_endpoint_reval_outcome {
    BOOT_ENDPOINT_REVAL_IDLE = 0,    /* no status change since last sweep */
    BOOT_ENDPOINT_REVAL_APPLIED,     /* swept; the chain's answers applied */
    BOOT_ENDPOINT_REVAL_UNAVAILABLE, /* the chain could not be asked */
};

/* Run one pass on the CALLING thread. Blocks on node.db. This is exactly
 * what the worker loop calls, so a test that drives it drives the real
 * path. Safe to call with no records held (IDLE / a no-op sweep). */
enum boot_endpoint_reval_outcome boot_endpoint_records_revalidate_once(void);

/* Start the supervised worker. Idempotent; a failed spawn is logged and
 * leaves revalidation off rather than failing the boot. */
void boot_endpoint_records_start_revalidation(void);

/* See CLAUDE.md "Adding state introspection". Reentrant-safe. key: NULL. */
struct json_value;
bool boot_endpoint_records_dump_state_json(struct json_value *out,
                                           const char *key);

#endif
