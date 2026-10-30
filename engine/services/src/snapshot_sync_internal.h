/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * snapshot_sync_internal.h — shared declarations across the purpose-named
 * files that make up snapshot sync:
 *
 *   snapshot_sync_service.c   — public API + init/free + dispatch
 *   snapshot_offer.c          — offer evaluation/accept
 *   snapshot_fetch.c          — chunk receive
 *   snapshot_verify.c         — SHA3 + FlyClient verify
 *   snapshot_apply.c          — promote staged UTXOs + activate tip
 *
 * NOT a public header. Only included by the five files above. The
 * trailing "_internal" suffix marks these symbols as file-local to
 * the snapshot_sync translation units; they should not be referenced
 * from app/controllers or core/modules/net code. */

#ifndef ZCL_SNAPSHOT_SYNC_INTERNAL_H
#define ZCL_SNAPSHOT_SYNC_INTERNAL_H

#include "net/snapshot_sync_contract.h"
#include "config/db_service.h"       /* db_service_write_fn */
#include "services/snapshot_manifest.h"
#include "models/database.h"
#include "util/result.h"
#include "ports/snapshot_store_port.h"
#include "adapters/outbound/persistence/snapshot_store_sqlite.h"

#include <stdbool.h>
#include <stdint.h>

struct chain_evidence_record;
struct main_state;
struct block_index;

/* Batch commit interval.  Smaller batches (25K) produce shorter WAL
 * checkpoints (~3-5s), reducing TCP backpressure pauses that trigger
 * false stall detections.  The tradeoff is slightly more total I/O,
 * but snapshot sync is I/O-bound anyway. */
#define SNAPSYNC_BATCH_COMMIT_ROWS 25000

#define SNAPSYNC_STAGING_TABLE "snapshot_staging_utxos"
#define SNAPSYNC_STAGING_PHASE_KEY "snapshot_staging_phase"
#define SNAPSYNC_STAGING_LAST_DISCARD_KEY "snapshot_staging_last_discard"
#define SNAPSYNC_PHASE_CHUNK_RECEIVE "chunk_receive"
#define SNAPSYNC_PHASE_SNAPSHOT_VERIFY "snapshot_verify"
#define SNAPSYNC_PHASE_ATOMIC_ACTIVATE "atomic_activate"

/* Cross-phase context structs */
struct snapsync_apply_chunk_ctx {
    struct snapshot_sync_service *svc;
    uint8_t *chunk_data;
    size_t chunk_len;
    int applied;
};

struct snapsync_finalize_ctx {
    struct snapshot_sync_service *svc;
    bool ok;
    bool activation_attempted;
    struct zcl_result activation_result;
};

/* ── Lock helpers (defined in snapshot_sync_service.c) ─────────── */
void snapsync_service_lock_internal(void);
void snapsync_service_unlock_internal(void);

/* ── Misc shared helpers (defined in snapshot_sync_service.c) ──── */
int64_t snapsync_now_us_internal(void);
bool snapsync_run_write_internal(struct snapshot_sync_service *svc,
                                 db_service_write_fn fn,
                                 void *ctx);

/* Bind the default snapshot storage port (sqlite adapter) onto `ndb`.
 * The caller owns `ctx` (stack storage); it must outlive every call made
 * through `*out_port`. This is the single place the subsystem chooses its
 * storage adapter — the service files name only the port. Returns ZCL_OK on
 * success; a non-ok result (carrying the reason) on a NULL out_port (a NULL
 * ndb is permitted, the port's methods then fail safely). The SHA3
 * commitment math is NOT routed through this port — it stays inline in the
 * service with the live sqlite handle. */
struct zcl_result snapsync_bind_store_internal(
    struct snapshot_store_sqlite_ctx *ctx,
    struct node_db *ndb,
    struct snapshot_store_port *out_port);

/* ── Manifest <-> params helpers (snapshot_offer.c) ────────────── */
enum snapsync_offer_result snapsync_offer_result_from_manifest_internal(
    enum snapshot_manifest_result result);
void snapsync_manifest_from_params_internal(struct snapshot_manifest *m,
                                            const struct snapshot_offer_params *p);
void snapsync_params_from_manifest_internal(struct snapshot_offer_params *p,
                                            const struct snapshot_manifest *m);

/* ── Staging helpers (snapshot_fetch.c) ────────────────────────── */
struct zcl_result snapsync_discard_staging_internal(struct node_db *ndb,
                                                    const char *reason);
struct zcl_result snapsync_discard_staging_txn_internal(struct node_db *ndb,
                                           const char *label,
                                           const char *reason);
struct zcl_result snapsync_set_staging_phase_internal(struct node_db *ndb,
                                                      const char *phase);
/* db_service_write_fn callback — fixed bool(struct node_db*, void*) signature. */
bool snapsync_discard_staging_write_internal(struct node_db *ndb, void *ctx);
int64_t snapsync_staging_count_internal(struct node_db *ndb);
void snapsync_hash_staging_internal(struct node_db *ndb, uint8_t out[32],
                                    uint64_t *utxo_count);

/* ── Receive-mode helpers (snapshot_fetch.c) ───────────────────── */
/* db_service_write_fn callback — fixed bool(struct node_db*, void*) signature. */
bool snapsync_rollback_receive_write_internal(struct node_db *ndb, void *ctx);
struct zcl_result snapsync_exit_turbo_mode_internal(struct snapshot_sync_service *svc);

/* ── Failure helpers (snapshot_verify.c) ───────────────────────── */
void snapsync_mark_failed_internal(struct snapshot_sync_service *svc,
                                   const char *state_reason);
/* Records the failure (event + state) and returns a non-ok result whose
 * .code/.message carry `reason`. Always non-ok by construction. */
struct zcl_result snapsync_finalize_fail_internal(struct snapsync_finalize_ctx *finalize,
                                     struct node_db *ndb,
                                     struct snapshot_sync_service *svc,
                                     uint32_t peer_id,
                                     const char *reason,
                                     const char *state_reason);

/* ── Stage promotion (snapshot_apply.c) ────────────────────────── */
struct zcl_result snapsync_stage_promote_active_internal(struct node_db *ndb,
                                            const struct snapshot_sync_service *svc,
                                            const uint8_t local_root[32],
                                            uint64_t local_count,
                                            const struct chain_evidence_record *verified);

#endif /* ZCL_SNAPSHOT_SYNC_INTERNAL_H */
