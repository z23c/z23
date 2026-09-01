/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: Contained publication compare-and-swap decision for a consensus-
 * state bundle. Combines the three already-landed contained evidence receipts
 *   (a) artifact validation admission (consensus_state_artifact_evidence),
 *   (b) process-singleton selected-chain binding (consensus_state_chain_evidence),
 *   (c) producer-owned source receipt (consensus_state_source_receipt)
 * into ONE durable decision record: ADMIT (all three present and mutually
 * binding — same artifact file identity, same selected H/hash, same source
 * epoch) or a typed refusal naming the exact missing/mismatched binding.
 *
 * CONTAINED like its inputs: it never publishes, loads, or mutates node state.
 * Its only output is a durable decision record written to a caller-provided
 * directory capability with FULL durability, plus an in-process latest-decision
 * snapshot for dumpstate. The decision binds the expected current node frontier
 * (H*, durable tip hash) at decision time, so a later apply step can detect
 * staleness; a re-run over a changed frontier yields a fresh decision digest and
 * the stale one must never be reused. Fails closed on every ambiguity.
 */

#ifndef ZCL_SERVICES_CONSENSUS_STATE_PUBLICATION_CAS_H
#define ZCL_SERVICES_CONSENSUS_STATE_PUBLICATION_CAS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sqlite3.h>

#include "services/consensus_state_chain_binding_service.h"
#include "storage/consensus_state_bundle_codec.h"
#include "util/result.h"

struct main_state;
struct consensus_state_artifact_evidence;
struct consensus_state_chain_evidence;
struct json_value;

#define CONSENSUS_STATE_PUBLICATION_DECISION_SCHEMA \
    "zcl.consensus_state_publication_decision.v1"

enum consensus_state_publication_decision {
    CONSENSUS_PUBLICATION_REFUSED = 0,
    CONSENSUS_PUBLICATION_ADMIT = 1,
};

/* Typed refusal, naming the exact failed binding. NONE only on ADMIT. */
enum consensus_state_publication_refusal {
    CONSENSUS_PUBLICATION_REFUSAL_NONE = 0,
    CONSENSUS_PUBLICATION_REFUSAL_NULL_INPUT = 1,
    CONSENSUS_PUBLICATION_REFUSAL_LANE_UNKNOWN = 2,
    CONSENSUS_PUBLICATION_REFUSAL_ARTIFACT_MANIFEST = 3,
    CONSENSUS_PUBLICATION_REFUSAL_ARTIFACT_DIGEST_MISMATCH = 4,
    CONSENSUS_PUBLICATION_REFUSAL_CHAIN_ARTIFACT_MISMATCH = 5,
    CONSENSUS_PUBLICATION_REFUSAL_SOURCE_RECEIPT_MISSING = 6,
    CONSENSUS_PUBLICATION_REFUSAL_SOURCE_RECEIPT_MALFORMED = 7,
    CONSENSUS_PUBLICATION_REFUSAL_SOURCE_ARTIFACT_MISMATCH = 8,
    CONSENSUS_PUBLICATION_REFUSAL_PROFILE_NOT_SERVING = 9,
    CONSENSUS_PUBLICATION_REFUSAL_FRONTIER_UNKNOWN = 10,
    CONSENSUS_PUBLICATION_REFUSAL_FRONTIER_BEHIND = 11,
};

/* Extracted, primitive-only inputs to the PURE decision. The run wrapper fills
 * these from the opaque handles + the captured frontier; a test can construct
 * them directly for a deterministic pinned-digest vector. */
struct consensus_state_publication_cas_inputs {
    struct consensus_state_bundle_manifest manifest;   /* from artifact */
    uint8_t artifact_logical_digest[32];               /* artifact logical id */
    uint8_t artifact_receipt_digest[32];               /* file/inode identity */
    bool chain_evidence_present;
    bool chain_bound_to_artifact;   /* matches same receipt digest + lane */
    bool checkpoint_authority_used; /* cryptographically bound in evidence */
    bool assisted_authority_used;   /* borrowed above-checkpoint tier; also
                                     * cryptographically bound in the evidence
                                     * digest. Permits the same below-bundle
                                     * frontier as the checkpoint path. */
    uint8_t chain_evidence_digest[32];
    bool source_receipt_present;
    struct consensus_state_source_receipt source_receipt;
    enum consensus_state_target_lane target_lane;
    bool frontier_known;
    int32_t frontier_height;         /* durable H* at decision time */
    uint8_t frontier_hash[32];       /* durable tip hash at decision time */
};

/* Durable publication decision record. Canonical, self-describing, digest-
 * bound. `decision_digest` binds every identity + the expected node frontier;
 * two runs over a changed frontier produce different digests (staleness). */
struct consensus_state_publication_decision_record {
    enum consensus_state_publication_decision decision;
    enum consensus_state_publication_refusal refusal;
    uint8_t artifact_receipt_digest[32];
    uint8_t chain_evidence_digest[32];
    uint8_t source_receipt_digest[32];
    uint8_t source_epoch_digest[32];
    int32_t bundle_height;
    uint8_t bundle_hash[32];
    uint8_t validation_profile;
    enum consensus_state_target_lane target_lane;
    int32_t expected_frontier_height;
    uint8_t expected_frontier_hash[32];
    uint8_t decision_digest[32];
    char reason[192];
};

/* PURE, total. Produces a fully-populated decision record (ADMIT or a typed
 * refusal). Never fails, allocates, or does I/O; deterministic in its inputs. */
void consensus_state_publication_cas_decide(
    const struct consensus_state_publication_cas_inputs *in,
    struct consensus_state_publication_decision_record *out);

/* Recompute the canonical decision digest over `record`'s bound fields.
 * Total; returns false only on a NULL argument. */
bool consensus_state_publication_decision_digest(
    const struct consensus_state_publication_decision_record *record,
    uint8_t out[32]);

/* True iff `record` was decided at exactly the given current frontier — the
 * CAS staleness predicate a later apply step uses. Total. */
bool consensus_state_publication_cas_decision_is_current(
    const struct consensus_state_publication_decision_record *record,
    int32_t current_frontier_height, const uint8_t current_frontier_hash[32]);

struct consensus_state_publication_cas_request {
    /* Process-singleton assertion (same contract as chain-evidence build):
     * the frontier is captured from the open reducer/progress authority. */
    struct main_state *main;
    const struct consensus_state_artifact_evidence *artifact;
    const struct consensus_state_chain_evidence *chain_evidence;
    const struct consensus_state_source_receipt *source_receipt;
    enum consensus_state_target_lane target_lane;
    /* Borrowed directory capability for the durable record. output_name must
     * be one normalized path component. The record is written no-follow, fsynced,
     * and atomically renamed into place (FULL durability). */
    int output_dir_fd;
    const char *output_name;
};

/* Capture the current durable frontier from the process singleton, decide, then
 * durably persist the decision record and refresh the dumpstate snapshot. The
 * record is produced and persisted for BOTH ADMIT and refusal. Returns non-ok
 * only on a null/non-singleton request or a durable-write failure; a refusal
 * decision is a successful run that produced a refusal record. Never publishes,
 * loads, or mutates node state. */
struct zcl_result consensus_state_publication_cas_run(
    const struct consensus_state_publication_cas_request *request,
    struct consensus_state_publication_decision_record *out_record);

/* Reload and verify a persisted decision record from a directory capability.
 * Recomputes the canonical digest and rejects any tamper. */
struct zcl_result consensus_state_publication_cas_load(
    int dir_fd, const char *name,
    struct consensus_state_publication_decision_record *out_record);

#ifdef ZCL_TESTING
/* Hermetic durable-I/O race seam. Production callers use cas_run(); tests may
 * persist an already-decided record and pause one writer immediately after its
 * unique temp inode is opened. */
typedef void (*consensus_state_publication_cas_after_temp_open_hook)(
    const struct consensus_state_publication_decision_record *record,
    void *ctx);
void consensus_state_publication_cas_test_set_after_temp_open_hook(
    consensus_state_publication_cas_after_temp_open_hook hook, void *ctx);
struct zcl_result consensus_state_publication_cas_persist_for_test(
    int dir_fd, const char *name,
    const struct consensus_state_publication_decision_record *record);
#endif

/* Capture the node's provable frontier (H*) and H*'s own block hash — the
 * (height, hash) pair cas_run() binds into the decision for staleness. Reads
 * the open progress-store singleton (process authority); returns false on a
 * genuinely uncomputable frontier (compute_hstar fails, H*<0, or H*'s hash is
 * unresolvable). Split out of the CAS TU as its own seam; also the direct
 * capture surface for tests over a progress-store fixture. */
bool consensus_state_publication_cas_capture_frontier(
    int32_t *out_height, uint8_t out_hash[32]);
/* Same capture while the caller already owns the progress-store lock and an
 * SQLite cutover transaction. Never acquires the process lock itself. */
bool consensus_state_publication_cas_capture_frontier_locked(
    sqlite3 *progress_db, int32_t *out_height, uint8_t out_hash[32]);

const char *consensus_state_publication_decision_name(
    enum consensus_state_publication_decision decision);
const char *consensus_state_publication_refusal_name(
    enum consensus_state_publication_refusal refusal);

/* Native dump-state surface: latest in-process decision record status. */
bool consensus_state_publication_cas_dump_state_json(struct json_value *out,
                                                     const char *key);

#endif /* ZCL_SERVICES_CONSENSUS_STATE_PUBLICATION_CAS_H */
