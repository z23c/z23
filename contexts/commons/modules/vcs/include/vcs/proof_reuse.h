/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Issuer ticket logs, the receiver's checkpoint-verified ticket
 *          set, and the exact-key reuse decision over it.
 *
 * Trust flows one way. A producer (issuer) appends signed tickets to its own
 * log and signs checkpoints over the log's MMR root. A receiver syncs a
 * checkpoint plus only the tickets it has not seen, and accepts them when
 * its verified prefix plus that delta reproduces the signed root. Only a
 * ticket covered by such a checkpoint can support reuse.
 *
 * Nothing about AUTHORITY is cached at ingest: verifier membership,
 * revocation, the candidate trust domain and the policy root are all read
 * from the request at decision time. What ingest retains is bytes, roots,
 * coverage and equivocation evidence, all facts about signed data.
 *
 * Contradictions are kept. PASS and FAIL for one key are both retained and
 * refuse reuse with `proof_observation_conflict`; two signed checkpoints
 * that cannot both be true mark their issuer equivocating, keep both, and
 * make every ticket of that issuer ineligible (`issuer_equivocation`).
 */

#ifndef ZCL_VCS_PROOF_REUSE_H
#define ZCL_VCS_PROOF_REUSE_H

#include "vcs/proof_ticket.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* ── Issuer log (producer side) ─────────────────────────────────────── */

struct vcs_proof_issuer_log;

/* The seed stays in memory for this log's lifetime and is wiped on free. */
struct vcs_proof_issuer_log *vcs_proof_issuer_log_new(const uint8_t seed[32]);
void vcs_proof_issuer_log_free(struct vcs_proof_issuer_log *log);
void vcs_proof_issuer_log_pubkey(const struct vcs_proof_issuer_log *log,
                                 uint8_t out[VCS_PROOF_PUBKEY_BYTES]);
/* Stamp issuer_seq, sign, encode and append one ticket. */
bool vcs_proof_issuer_log_append(struct vcs_proof_issuer_log *log,
                                 struct vcs_proof_ticket_v1 *ticket,
                                 uint8_t wire[VCS_PROOF_TICKET_WIRE_BYTES]);
/* Sign a checkpoint over the whole log, chained to the previous one. */
bool vcs_proof_issuer_log_checkpoint(
    struct vcs_proof_issuer_log *log, uint64_t created_unix,
    uint8_t wire[VCS_PROOF_CHECKPOINT_WIRE_BYTES]);
uint64_t vcs_proof_issuer_log_count(const struct vcs_proof_issuer_log *log);
/* The retained wire at `seq`, NULL out of range. */
const uint8_t *vcs_proof_issuer_log_ticket(
    const struct vcs_proof_issuer_log *log, uint64_t seq);

/* ── Receiver ───────────────────────────────────────────────────────── */

struct vcs_proof_receiver;

struct vcs_proof_receiver *vcs_proof_receiver_new(void);
void vcs_proof_receiver_free(struct vcs_proof_receiver *r);

/* Retain a ticket that arrived outside a log sync. It stays ineligible
 * (`not_checkpointed`) until a verified checkpoint covers it. Duplicate
 * observation roots are not appended twice (*added=false). */
bool vcs_proof_receiver_add_ticket(struct vcs_proof_receiver *r,
                                   const uint8_t *wire, size_t len,
                                   bool *added);
/* Retained observations for `input_key` (covered or not), insertion
 * order. Fills at most `cap` wire pointers; returns the total. */
size_t vcs_proof_receiver_lookup(const struct vcs_proof_receiver *r,
                                 const uint8_t input_key[VCS_PROOF_ROOT_BYTES],
                                 const uint8_t **wires, size_t cap);
size_t vcs_proof_receiver_ticket_count(const struct vcs_proof_receiver *r);

enum vcs_proof_sync_outcome {
    VCS_PROOF_SYNC_ADVANCED = 0,  /* delta verified, coverage extended */
    VCS_PROOF_SYNC_CURRENT,       /* already verified this checkpoint */
    VCS_PROOF_SYNC_EQUIVOCATION,  /* issuer signed a contradiction */
    VCS_PROOF_SYNC_REFUSED,       /* could not verify; nothing changed */
};

#define VCS_PROOF_SYNC_WHY_OK "ok"
#define VCS_PROOF_SYNC_WHY_MALFORMED "checkpoint_malformed"
#define VCS_PROOF_SYNC_WHY_SIGNATURE "checkpoint_signature_invalid"
#define VCS_PROOF_SYNC_WHY_GAP "checkpoint_gap"
#define VCS_PROOF_SYNC_WHY_UNVERIFIABLE "checkpoint_unverifiable"
#define VCS_PROOF_SYNC_WHY_COUNT "delta_count_mismatch"
#define VCS_PROOF_SYNC_WHY_DELTA "delta_invalid"
#define VCS_PROOF_SYNC_WHY_EQUIVOCATION "issuer_equivocation"
#define VCS_PROOF_SYNC_WHY_RESOURCES "sync_resources"

struct vcs_proof_sync_report {
    enum vcs_proof_sync_outcome outcome;
    const char *reason;
    uint64_t leaves_before;
    uint64_t leaves_after;
    uint64_t bytes;          /* checkpoint + delta wire bytes consumed */
};

/* Verify `checkpoint` against this receiver's verified prefix for its
 * issuer plus `delta` (the issuer's tickets at seq leaves_before..count-1,
 * in order). Returns false only for caller errors; every verdict about the
 * data, including REFUSED, is a true return with a named reason. */
bool vcs_proof_receiver_sync(struct vcs_proof_receiver *r,
                             const uint8_t *checkpoint, size_t checkpoint_len,
                             const uint8_t *const *delta,
                             const size_t *delta_lens, size_t delta_count,
                             struct vcs_proof_sync_report *out);
/* Verified leaf count for an issuer: where its next delta starts. */
uint64_t vcs_proof_receiver_issuer_leaves(
    const struct vcs_proof_receiver *r,
    const uint8_t issuer[VCS_PROOF_PUBKEY_BYTES]);
bool vcs_proof_receiver_issuer_equivocating(
    const struct vcs_proof_receiver *r,
    const uint8_t issuer[VCS_PROOF_PUBKEY_BYTES]);
/* Signed checkpoints retained for an issuer, including every side of an
 * equivocation. */
size_t vcs_proof_receiver_issuer_checkpoints(
    const struct vcs_proof_receiver *r,
    const uint8_t issuer[VCS_PROOF_PUBKEY_BYTES]);

/* ── Reuse decision ─────────────────────────────────────────────────── */

/* The candidate's own trust domain. Nothing signed by a key in here may
 * authorize reuse for that candidate, whatever else trusts it. */
struct vcs_proof_candidate_domain {
    uint8_t author_pubkey[VCS_PROOF_PUBKEY_BYTES];      /* required */
    bool has_local_signer;
    uint8_t local_signer_pubkey[VCS_PROOF_PUBKEY_BYTES]; /* same-uid key */
    const uint8_t (*extra)[VCS_PROOF_PUBKEY_BYTES];
    size_t extra_count;
};

/* The receiver's CURRENT policy, read at every decision. */
struct vcs_proof_reuse_policy {
    uint8_t policy_root[VCS_PROOF_ROOT_BYTES];
    const uint8_t (*verifiers)[VCS_PROOF_PUBKEY_BYTES];
    size_t verifier_count;
    const uint8_t (*revoked)[VCS_PROOF_PUBKEY_BYTES];
    size_t revoked_count;
    uint32_t quorum;               /* distinct EXECUTED PASS signers, >= 1 */
    uint64_t now_unix;             /* 0 disables freshness checks */
    uint64_t max_age_seconds;      /* 0 = no age bound */
    uint64_t max_future_seconds;   /* allowed clock skew */
};

/* Artifact bytes by artifact_root (SHA3-256 of the bytes). The bytes are
 * borrowed until the next call; the decision re-hashes them. */
struct vcs_proof_artifact_source {
    bool (*fetch)(void *ctx, const uint8_t artifact_root[VCS_PROOF_ROOT_BYTES],
                  const uint8_t **bytes, size_t *len);
    void *ctx;
};

struct vcs_proof_reuse_request {
    const struct vcs_component_proof_key_v1 *local;
    enum vcs_proof_action_class action_class;
    const struct vcs_proof_candidate_domain *domain;
    const struct vcs_proof_reuse_policy *policy;
    const struct vcs_proof_artifact_source *artifacts; /* BUILD reuse */
};

enum vcs_proof_reuse_outcome {
    VCS_PROOF_REUSE_MISS = 0,     /* run fresh */
    VCS_PROOF_REUSE_HIT_PASS,     /* reuse the PASS (artifact verified) */
    VCS_PROOF_REUSE_HIT_FAIL,     /* known failing; still rerunnable */
    VCS_PROOF_REUSE_REFUSE,       /* ambiguous or invalid: named refusal */
};

/* Per-ticket reasons. */
#define VCS_PROOF_TICKET_ELIGIBLE "eligible"
#define VCS_PROOF_TICKET_MALFORMED "ticket_malformed"
#define VCS_PROOF_TICKET_KEY_MISMATCH "key_mismatch"
#define VCS_PROOF_TICKET_PREIMAGE_MISMATCH "key_preimage_mismatch"
#define VCS_PROOF_TICKET_SOURCE_MISMATCH "source_mismatch"
#define VCS_PROOF_TICKET_CLASS_MISMATCH "action_class_mismatch"
#define VCS_PROOF_TICKET_SIGNATURE_INVALID "signature_invalid"
#define VCS_PROOF_TICKET_SIGNER_IN_DOMAIN "signer_in_candidate_domain"
#define VCS_PROOF_TICKET_SIGNER_REVOKED "signer_revoked"
#define VCS_PROOF_TICKET_SIGNER_UNTRUSTED "signer_not_trusted_for_reuse"
#define VCS_PROOF_TICKET_REUSED "reused_not_independent"
#define VCS_PROOF_TICKET_STALE "ticket_stale"
#define VCS_PROOF_TICKET_FUTURE "ticket_from_future"
#define VCS_PROOF_TICKET_EQUIVOCATION "issuer_equivocation"
#define VCS_PROOF_TICKET_NOT_CHECKPOINTED "not_checkpointed"
/* Decision reasons. */
#define VCS_PROOF_REUSE_WHY_HIT "eligible_quorum"
#define VCS_PROOF_REUSE_WHY_KNOWN_FAIL "eligible_failure"
#define VCS_PROOF_REUSE_WHY_NONE "no_observation"
#define VCS_PROOF_REUSE_WHY_INELIGIBLE "no_eligible_observation"
#define VCS_PROOF_REUSE_WHY_QUORUM "quorum_not_met"
#define VCS_PROOF_REUSE_WHY_ARTIFACT_MISMATCH "artifact_bytes_mismatch"
#define VCS_PROOF_REUSE_WHY_ARTIFACT_MISSING "artifact_unavailable"
#define VCS_PROOF_REUSE_WHY_ARGUMENTS "reuse_arguments_invalid"
#define VCS_PROOF_REUSE_WHY_PREIMAGE "key_preimage_invalid"
#define VCS_PROOF_REUSE_WHY_POLICY "reuse_policy_invalid"
#define VCS_PROOF_REUSE_WHY_POLICY_ROOT "policy_root_inconsistent"
#define VCS_PROOF_REUSE_WHY_DOMAIN "candidate_domain_invalid"
#define VCS_PROOF_REUSE_WHY_CAPACITY "classification_capacity"

struct vcs_proof_ticket_class {
    uint8_t observation_root[VCS_PROOF_ROOT_BYTES];
    uint8_t producer_pubkey[VCS_PROOF_PUBKEY_BYTES];
    uint8_t artifact_root[VCS_PROOF_ROOT_BYTES];
    enum vcs_proof_verdict verdict;  /* 0 when malformed */
    bool eligible;
    const char *reason;              /* one of VCS_PROOF_TICKET_* */
};

#define VCS_PROOF_REUSE_MAX_USED 16u

struct vcs_proof_reuse_decision {
    enum vcs_proof_reuse_outcome outcome;
    const char *reason;
    uint8_t input_key[VCS_PROOF_ROOT_BYTES];
    uint8_t artifact_root[VCS_PROOF_ROOT_BYTES]; /* verified, BUILD HIT */
    uint32_t tickets_seen;
    uint32_t eligible_pass;
    uint32_t eligible_fail;
    uint32_t distinct_pass_signers;
    /* True when a quorum existed but the artifact bytes did not hash to
     * their root: a false hit caught and refused. */
    bool false_hit_refused;
    /* Observation roots that authorize a HIT or HIT_FAIL, or the
     * conflicting ones on REFUSE. */
    uint8_t used[VCS_PROOF_REUSE_MAX_USED][VCS_PROOF_ROOT_BYTES];
    uint32_t used_count;
};

/* Decide reuse for one obligation over every observation `r` retains for
 * the key derived from req->local. `classes` must hold `class_cap`
 * entries; more observations than that is a REFUSE
 * (classification_capacity), never a silent truncation. Returns false only
 * for caller errors (out->outcome = REFUSE with a named reason). */
bool vcs_proof_reuse_decide(const struct vcs_proof_receiver *r,
                            const struct vcs_proof_reuse_request *req,
                            struct vcs_proof_ticket_class *classes,
                            size_t class_cap,
                            struct vcs_proof_reuse_decision *out);

const char *vcs_proof_reuse_outcome_name(enum vcs_proof_reuse_outcome o);

/* ── CAS placement ──────────────────────────────────────────────────── */

struct vcs_package_store;
/* Store a ticket, checkpoint or key preimage wire as a content.v2 blob. */
bool vcs_proof_ticket_store_put(struct vcs_package_store *store,
                                const uint8_t *wire, size_t len,
                                uint8_t blob_root[VCS_PROOF_ROOT_BYTES]);
/* Load one preimage by its CAS root and verify it re-encodes to that root. */
bool vcs_component_proof_key_load(struct vcs_package_store *store,
                                  const uint8_t preimage_root[32],
                                  struct vcs_component_proof_key_v1 *out);
/* Rebuild a receiver from the ticket and checkpoint blobs in `store`: every
 * ticket is retained, then each issuer's checkpoints are replayed in
 * leaf_count order through vcs_proof_receiver_sync(). Other blobs are
 * counted in *skipped. */
bool vcs_proof_receiver_rebuild(struct vcs_proof_receiver *r,
                                struct vcs_package_store *store,
                                size_t *tickets, size_t *checkpoints,
                                size_t *skipped);

#endif /* ZCL_VCS_PROOF_REUSE_H */
