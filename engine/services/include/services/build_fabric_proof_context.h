/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: One build worker's durable proof state on the production path:
 *          start-time recovery, the signed issuer log, the receiver rebuilt
 *          from CAS under the worker table's trust policy, per-execution
 *          ticket publication, and the feedback-only reuse shadow.
 *
 * The context is an explicit object the runtime owns and passes to each
 * step; no library function reads it from hidden global state. It holds the
 * issuer seed for its lifetime and wipes it on close.
 *
 * Tickets are FEEDBACK ONLY here. Attach's donor scan remains the reuse
 * authority; the shadow computes the ticket decision next to every attach
 * decision and counts whether the two agree. */

#ifndef ZCL_SERVICES_BUILD_FABRIC_PROOF_CONTEXT_H
#define ZCL_SERVICES_BUILD_FABRIC_PROOF_CONTEXT_H

#include "base/result.h"
#include "vcs/proof_ticket.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct node_db;
struct vcs_package_store;
struct vcs_proof_receiver;
struct db_build_action;
struct db_build_receipt;
struct build_fabric_attach_report;
struct build_fabric_host_accounting;

struct build_fabric_proof_context;

/* Receiver and issuer state tokens. Every refusal is one of these names and
 * is also logged; none is silent. */
#define BUILD_FABRIC_PROOF_STATE_NOT_STARTED "not_started"
#define BUILD_FABRIC_PROOF_STATE_READY "ready"
#define BUILD_FABRIC_PROOF_STATE_STORE_UNAVAILABLE "refused_store_unavailable"
#define BUILD_FABRIC_PROOF_STATE_CATALOG_UNREADABLE "refused_catalog_unreadable"
#define BUILD_FABRIC_PROOF_STATE_CATALOG_MOVED "refused_catalog_moved"
#define BUILD_FABRIC_PROOF_STATE_WORKER_UNREADABLE "refused_worker_row_unreadable"
#define BUILD_FABRIC_PROOF_STATE_HISTORY_MISSING "refused_history_missing"
#define BUILD_FABRIC_PROOF_STATE_RESTORE_REFUSED "refused_issuer_restore"
#define BUILD_FABRIC_PROOF_STATE_HEADS_REFUSED "refused_heads_snapshot"
#define BUILD_FABRIC_PROOF_STATE_POLICY_REFUSED "refused_trust_policy"
#define BUILD_FABRIC_PROOF_STATE_REBUILD_REFUSED "refused_receiver_rebuild"
#define BUILD_FABRIC_PROOF_STATE_ALLOCATION "refused_allocation"
#define BUILD_FABRIC_PROOF_STATE_SYNC_REFUSED "refused_receiver_sync"
/* A staged publication worker start could not complete. The row stays
 * staged for the next worker start; this worker issues nothing until then. */
#define BUILD_FABRIC_PROOF_STATE_PENDING_REFUSED "refused_pending_recovery"
/* The in-memory issuer no longer provably extends the durable head (an
 * append whose staging was refused, or a staged row this issuer did not
 * write). Issuance stops until the next worker start recovers it. */
#define BUILD_FABRIC_PROOF_STATE_ISSUE_PAUSED "refused_issue_paused"

/* Rebuild and restore retry this many times when the catalog moves. */
#define BUILD_FABRIC_PROOF_OPEN_ATTEMPTS 4u

struct build_fabric_proof_stats {
    const char *issuer_state;
    const char *receiver_state;
    uint64_t issuer_leaves;          /* issuer high-water mark */
    uint64_t receiver_tickets;       /* retained by the last rebuild/sync */
    uint64_t receiver_checkpoints;
    uint64_t receiver_skipped;
    uint64_t receiver_catalog_rows;  /* rebuild budget: catalog size */
    uint64_t issued;
    uint64_t issue_refused;
    const char *last_issue_refusal;
    uint64_t shadow_decisions;       /* pairs with a computed ticket outcome */
    uint64_t shadow_unavailable;     /* attach decisions with no ticket view */
    uint64_t ticket_hit;
    uint64_t ticket_hit_fail;
    uint64_t ticket_miss;
    uint64_t ticket_refuse;
    uint64_t attach_hit;
    uint64_t attach_miss;
    uint64_t attach_refused;
    uint64_t agree;
    uint64_t disagree;
    uint64_t disagree_attach_only;   /* attach HIT, ticket not HIT */
    uint64_t disagree_ticket_only;   /* ticket HIT, attach not HIT */
    const char *last_attach;
    const char *last_ticket_outcome;
    const char *last_ticket_reason;
};

/* Worker start, the only place proof history is replayed. Selects the one
 * proof store handle for <datadir>/zcode (the node-global handle when it
 * owns that directory, else a private one), completes any staged
 * publication through build_fabric_proof_pending_recover, restores the
 * writable issuer log at the worker's durable head, and rebuilds the
 * receiver with vcs_proof_receiver_rebuild_with_policy bounded by
 * vcs_package_store_catalog_rows. Each step is O(catalog) and runs once.
 * Only invalid arguments or a failed context allocation return an error.
 * Every other refusal, a staged row recovery could not complete included,
 * returns a context whose state tokens name it, and leaves the row staged;
 * issuance or the shadow is then unavailable. Tickets are feedback, so the
 * caller starts the worker whatever this returns. */
struct zcl_result build_fabric_proof_context_open(
    struct node_db *ndb, const char *datadir, const char *worker_id,
    const uint8_t seed[32], struct build_fabric_proof_context **out);
void build_fabric_proof_context_close(struct build_fabric_proof_context *ctx);

/* Readable from any thread. */
void build_fabric_proof_context_stats(
    const struct build_fabric_proof_context *ctx,
    struct build_fabric_proof_stats *out);
/* Distinct independent EXECUTED PASS signers the shadow requires (>= 1). */
struct zcl_result build_fabric_proof_context_set_quorum(
    struct build_fabric_proof_context *ctx, uint32_t quorum);
const struct vcs_proof_receiver *build_fabric_proof_context_receiver(
    const struct build_fabric_proof_context *ctx);

/* The component proof key of one plain fixed compile, derived from this
 * host's current tool bytes exactly as the executor key publishes it. */
struct zcl_result build_fabric_proof_compile_key(
    const char *workspace, const struct db_build_action *action,
    const uint8_t input_bytes_root[32],
    struct vcs_component_proof_key_v1 *out);

/* After an executed plain compile's receipt is admitted: sign one
 * BUILD/PASS/EXECUTED ticket over its physical observation and append it
 * at the durable head. The cost is independent of history: it reads only
 * the head checkpoint, stages the exact ticket and checkpoint wires in the
 * worker row, writes both to CAS without eviction, advances the head with
 * the row's conditional finalize, and syncs the live receiver with that one
 * delta. A staged row this issuer left behind is completed the same way
 * first. Nothing here replays history; a state only worker start can
 * recover pauses issuance. The executed result stands whatever this
 * returns. */
struct zcl_result build_fabric_proof_issue_executed(
    struct build_fabric_proof_context *ctx, struct node_db *ndb,
    const char *workspace, const struct db_build_action *action,
    const struct db_build_receipt *receipt,
    const struct build_fabric_host_accounting *accounting);

/* Shadow one attach decision: compute vcs_proof_reuse_decide for the key
 * attach composed, under the worker table's current trust policy and the
 * requester's own trust domain, and count the pair. Changes nothing.
 * Returns an error naming why no ticket decision was computed (also counted
 * as shadow_unavailable); the caller ignores it, tickets being feedback. */
struct zcl_result build_fabric_proof_shadow_attach(
    struct build_fabric_proof_context *ctx, struct node_db *ndb,
    const char *workspace, const uint8_t requester_pubkey[32],
    const struct build_fabric_attach_report *report);

/* The stats as the dumpstate "proof" object (schema zcl.build_fabric_proof.v1). */
struct json_value;
void build_fabric_proof_stats_json(const struct build_fabric_proof_stats *s,
                                   struct json_value *out);

#ifdef ZCL_TESTING
enum build_fabric_proof_issue_point {
    BUILD_FABRIC_PROOF_ISSUE_AFTER_STAGE = 1,
    BUILD_FABRIC_PROOF_ISSUE_AFTER_TICKET_PUT,
    BUILD_FABRIC_PROOF_ISSUE_AFTER_CHECKPOINT_PUT,
    BUILD_FABRIC_PROOF_ISSUE_BEFORE_FINALIZE,
};
/* Fires at each durable boundary of the live publication path. */
void build_fabric_proof_test_issue_hook(
    void (*hook)(enum build_fabric_proof_issue_point point, void *context),
    void *context);

/* One armed failure at a time; it stays armed until reset to NONE. */
enum build_fabric_proof_fault {
    BUILD_FABRIC_PROOF_FAULT_NONE = 0,
    BUILD_FABRIC_PROOF_FAULT_OPEN_ALLOCATION,
    BUILD_FABRIC_PROOF_FAULT_OPEN_RECOVERY,
    BUILD_FABRIC_PROOF_FAULT_ISSUE_STAGE,
    BUILD_FABRIC_PROOF_FAULT_ISSUE_TICKET_PUT,
    BUILD_FABRIC_PROOF_FAULT_ISSUE_FINALIZE,
    BUILD_FABRIC_PROOF_FAULT_SHADOW_DECIDE,
};
void build_fabric_proof_test_fault(enum build_fabric_proof_fault fault);
#endif

#endif /* ZCL_SERVICES_BUILD_FABRIC_PROOF_CONTEXT_H */
