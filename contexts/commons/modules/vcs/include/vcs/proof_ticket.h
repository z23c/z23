/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Component proof input keys, signed proof tickets, an append-only
 *          key-to-observation index, and the receiver reuse decision.
 *
 * This is the TICKET object of docs/work/CANONICAL_LIFECYCLE.md (PROOF_SET
 * section). Two identities, never confused:
 *
 *   input_key         what was proven: SHA3-256 of the component's complete
 *                     input closure (zcl.component_proof_key.v1). It excludes
 *                     verdict, time, producer, signature and commit ids.
 *   observation_root  who observed what: SHA3-256 of the complete signed
 *                     ticket wire. Changing any byte makes another root.
 *
 * A signature authenticates WHO asserted WHAT. It never makes a result
 * correct, and a signer inside the candidate's own trust domain (the
 * candidate author, the same-uid local proof signer, or any key the caller
 * places in that domain) never authorizes reuse. PASS and FAIL for one key
 * coexist as separate immutable observations; an eligible contradiction
 * refuses with `proof_observation_conflict`, the same name the build fabric
 * evaluator uses (engine/services/src/build_fabric_evidence.c).
 *
 * The receiver never trusts a ticket's claimed key: it derives the key from
 * its OWN local preimage and a ticket whose key or preimage root differs is
 * ineligible. The preimage wire is a CAS blob (vcs/blob_store.h) so any
 * party can fetch it by root, inspect every field and re-derive the key.
 */

#ifndef ZCL_VCS_PROOF_TICKET_H
#define ZCL_VCS_PROOF_TICKET_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define VCS_PROOF_ROOT_BYTES 32u
#define VCS_PROOF_PUBKEY_BYTES 32u
#define VCS_PROOF_SIGNATURE_BYTES 64u

/* The shared contradiction name. build_fabric_evidence.c refuses with the
 * same token; both read it from here. */
#define VCS_PROOF_OBSERVATION_CONFLICT "proof_observation_conflict"

/* ── zcl.component_proof_key.v1 ───────────────────────────────────────────
 *
 * Fifteen 32-byte roots in this fixed order. Every field is a root so the
 * preimage has one shape; text inputs become roots through
 * vcs_component_proof_field_root(), and the environment through
 * vcs_component_proof_environment_root(). toolchain_root is the v1
 * toolchain capsule root, the same root vcs_fastobj_key() binds.
 *
 * Preimage wire (CAS blob, 496 bytes, little-endian):
 *   0   magic[8] = "Z23CPK1\0"
 *   8   version u32 = 1
 *   12  field_count u32 = 15
 *   16  roots[15][32] in enum vcs_component_proof_field order
 *   496 end
 *
 * input_key = SHA3-256("zcl.component_proof_key.v1" ||
 *                      for each field: u16le field_id || u32le 32 || root)
 * Every root must be nonzero: an absent input is a named empty root from
 * vcs_component_proof_field_root(field, "", 0), never zero bytes. */
enum vcs_component_proof_field {
    VCS_CPK_KIND = 0,
    VCS_CPK_UNIT_ID,
    VCS_CPK_SOURCE_CLOSURE,
    VCS_CPK_DEPENDENCY_CLOSURE,
    VCS_CPK_TOOLCHAIN,
    VCS_CPK_TARGET,
    VCS_CPK_FLAGS,
    VCS_CPK_ENVIRONMENT,
    VCS_CPK_ABI_GENERATION,
    VCS_CPK_BUILD_GRAPH,
    VCS_CPK_HARNESS,
    VCS_CPK_FIXTURES,
    VCS_CPK_INVARIANTS,
    VCS_CPK_INTEGRATION_EDGES,
    VCS_CPK_POLICY,
    VCS_CPK_FIELD_COUNT,
};

#define VCS_CPK_WIRE_BYTES (16u + 15u * VCS_PROOF_ROOT_BYTES)

struct vcs_component_proof_key_v1 {
    uint8_t roots[VCS_CPK_FIELD_COUNT][VCS_PROOF_ROOT_BYTES];
};

/* Stable lowercase field name ("source_closure", ...), NULL out of range. */
const char *vcs_component_proof_field_name(enum vcs_component_proof_field f);

/* Root of one text/byte input: SHA3-256("zcl.component_proof_key.field.v1"
 * || u16le field || u64le len || bytes). Binding the field id means the
 * same text in two fields never yields one root. */
bool vcs_component_proof_field_root(enum vcs_component_proof_field field,
                                    const void *bytes, size_t len,
                                    uint8_t out[VCS_PROOF_ROOT_BYTES]);

/* One allowlisted environment variable. value NULL means "unset", which is
 * bound distinctly from the empty string. */
struct vcs_component_proof_env {
    const char *name;
    const char *value;
};

/* Canonical environment root over the ALLOWLISTED variables only. Names
 * must be [A-Z0-9_]+, strictly ascending (byte order) and unique; anything
 * else is refused, never silently sorted. A variable outside the allowlist
 * is simply not an input. */
bool vcs_component_proof_environment_root(
    const struct vcs_component_proof_env *env, size_t count,
    uint8_t out[VCS_PROOF_ROOT_BYTES]);

bool vcs_component_proof_key_valid(const struct vcs_component_proof_key_v1 *k);
bool vcs_component_proof_key_encode(const struct vcs_component_proof_key_v1 *k,
                                    uint8_t out[VCS_CPK_WIRE_BYTES]);
/* Exact length, magic, version, field count and nonzero roots; anything
 * else (including trailing bytes) is refused. */
bool vcs_component_proof_key_decode(const uint8_t *wire, size_t len,
                                    struct vcs_component_proof_key_v1 *out);
bool vcs_component_proof_key_derive(const struct vcs_component_proof_key_v1 *k,
                                    uint8_t input_key[VCS_PROOF_ROOT_BYTES]);
/* CAS address of the preimage wire: vcs_blob_root() of its bytes. */
bool vcs_component_proof_key_preimage_root(
    const struct vcs_component_proof_key_v1 *k,
    uint8_t out[VCS_PROOF_ROOT_BYTES]);
/* Bit i set when field i differs. Diagnostics only: names what a miss
 * changed once the ticket's preimage has been fetched from CAS. */
uint32_t vcs_component_proof_key_diff(const struct vcs_component_proof_key_v1 *a,
                                      const struct vcs_component_proof_key_v1 *b);

/* ── zcl.proof_ticket.v1 ──────────────────────────────────────────────────
 *
 * Fixed wire (256 bytes, little-endian):
 *   0   magic[8] = "Z23PTK1\0"
 *   8   version u32 = 1
 *   12  verdict u8 (PASS=1, FAIL=2)
 *   13  reproduced u8 (0 or 1): the signer claims it executed the checks
 *       itself rather than copying another observation
 *   14  reserved[2] = zero
 *   16  input_key[32]
 *   48  key_preimage_root[32]   CAS root of the zcl.component_proof_key.v1 wire
 *   80  evidence_root[32]       CAS root of the log/output evidence
 *   112 checks_run u32          >= 1
 *   116 checks_passed u32       PASS: == checks_run; FAIL: < checks_run
 *   120 cpu_us u64
 *   128 wall_us u64
 *   136 bytes_in u64
 *   144 bytes_out u64
 *   152 created_unix u64        nonzero
 *   160 producer_pubkey[32]
 *   192 signature[64]
 *   256 end
 *
 * signature = Ed25519 over "zcl.proof_ticket.v1" || bytes [0,192), so the
 * producer key is inside the signed bytes.
 * observation_root = SHA3-256("zcl.proof_ticket_root.v1" || all 256 bytes). */
#define VCS_PROOF_TICKET_WIRE_BYTES 256u
#define VCS_PROOF_TICKET_SIGNED_BYTES 192u

enum vcs_proof_verdict {
    VCS_PROOF_VERDICT_PASS = 1,
    VCS_PROOF_VERDICT_FAIL = 2,
};

struct vcs_proof_ticket_v1 {
    enum vcs_proof_verdict verdict;
    bool reproduced;
    uint8_t input_key[VCS_PROOF_ROOT_BYTES];
    uint8_t key_preimage_root[VCS_PROOF_ROOT_BYTES];
    uint8_t evidence_root[VCS_PROOF_ROOT_BYTES];
    uint32_t checks_run;
    uint32_t checks_passed;
    uint64_t cpu_us;
    uint64_t wall_us;
    uint64_t bytes_in;
    uint64_t bytes_out;
    uint64_t created_unix;
    uint8_t producer_pubkey[VCS_PROOF_PUBKEY_BYTES];
    uint8_t signature[VCS_PROOF_SIGNATURE_BYTES];
};

/* Body fields (everything before producer_pubkey) are canonical. */
bool vcs_proof_ticket_body_valid(const struct vcs_proof_ticket_v1 *t);
/* Sign with a caller-held Ed25519 seed; fills producer_pubkey/signature.
 * The library never reads a key file: which identity signs is the
 * caller's trust decision, and the receiver re-checks it. */
bool vcs_proof_ticket_sign(struct vcs_proof_ticket_v1 *t,
                           const uint8_t seed[32]);
bool vcs_proof_ticket_signature_valid(const struct vcs_proof_ticket_v1 *t);
bool vcs_proof_ticket_encode(const struct vcs_proof_ticket_v1 *t,
                             uint8_t out[VCS_PROOF_TICKET_WIRE_BYTES]);
/* Refuses wrong length (truncated or trailing bytes), bad magic/version,
 * nonzero reserved bytes and non-canonical values. Does NOT verify the
 * signature: an undecodable ticket is not a ticket, a badly signed one is
 * a ticket with a reason. */
bool vcs_proof_ticket_decode(const uint8_t *wire, size_t len,
                             struct vcs_proof_ticket_v1 *out);
bool vcs_proof_ticket_observation_root(const uint8_t *wire, size_t len,
                                       uint8_t out[VCS_PROOF_ROOT_BYTES]);

/* ── Index: input_key -> SET of observation roots ─────────────────────────
 *
 * Append-only and set-valued. Adding never overwrites, collapses or picks
 * the newest: a PASS and a FAIL for one key are both retained. It is a
 * projection: vcs_proof_ticket_index_rebuild() reconstructs it from the
 * ticket blobs in a package store, so losing it loses nothing. */
struct vcs_proof_ticket_index_entry {
    uint8_t input_key[VCS_PROOF_ROOT_BYTES];
    uint8_t observation_root[VCS_PROOF_ROOT_BYTES];
    uint8_t wire[VCS_PROOF_TICKET_WIRE_BYTES];
};

struct vcs_proof_ticket_index {
    struct vcs_proof_ticket_index_entry *entries;
    size_t count;
    size_t cap;
};

void vcs_proof_ticket_index_init(struct vcs_proof_ticket_index *index);
void vcs_proof_ticket_index_free(struct vcs_proof_ticket_index *index);
/* Decodes, derives the observation root and appends unless that exact root
 * is already present (*added=false then). Undecodable bytes are refused. */
bool vcs_proof_ticket_index_add(struct vcs_proof_ticket_index *index,
                                const uint8_t *wire, size_t len,
                                bool *added);
/* Every retained observation for `input_key`, in insertion order. Fills at
 * most `cap` pointers and returns the total count (which may exceed cap). */
size_t vcs_proof_ticket_index_lookup(
    const struct vcs_proof_ticket_index *index,
    const uint8_t input_key[VCS_PROOF_ROOT_BYTES],
    const struct vcs_proof_ticket_index_entry **out, size_t cap);

struct vcs_package_store;
/* Store a ticket wire or a preimage wire as a content.v2 blob. */
bool vcs_proof_ticket_store_put(struct vcs_package_store *store,
                                const uint8_t *wire, size_t len,
                                uint8_t blob_root[VCS_PROOF_ROOT_BYTES]);
/* Load one preimage by its CAS root and verify it re-encodes to that root. */
bool vcs_component_proof_key_load(struct vcs_package_store *store,
                                   const uint8_t preimage_root[32],
                                   struct vcs_component_proof_key_v1 *out);
/* Rebuild the projection from every complete blob in `store` that decodes
 * as a ticket. Other blobs are counted in *skipped, not errors. */
bool vcs_proof_ticket_index_rebuild(struct vcs_proof_ticket_index *index,
                                    struct vcs_package_store *store,
                                    size_t *added, size_t *skipped);

/* ── Receiver reuse decision ───────────────────────────────────────────── */

/* The candidate's own trust domain. Nothing signed by a key in here may
 * authorize reuse for that candidate, whatever else trusts it. */
struct vcs_proof_candidate_domain {
    uint8_t author_pubkey[VCS_PROOF_PUBKEY_BYTES];      /* required */
    bool has_local_signer;
    uint8_t local_signer_pubkey[VCS_PROOF_PUBKEY_BYTES]; /* same-uid key */
    const uint8_t (*extra)[VCS_PROOF_PUBKEY_BYTES];
    size_t extra_count;
};

struct vcs_proof_reuse_policy {
    uint8_t policy_root[VCS_PROOF_ROOT_BYTES];
    /* Verifiers whose independent reproductions this receiver accepts. */
    const uint8_t (*verifiers)[VCS_PROOF_PUBKEY_BYTES];
    size_t verifier_count;
    uint32_t quorum;               /* distinct PASS signers, >= 1 */
    uint64_t now_unix;             /* 0 disables freshness checks */
    uint64_t max_age_seconds;      /* 0 = no age bound */
    uint64_t max_future_seconds;   /* allowed clock skew */
};

enum vcs_proof_reuse_outcome {
    VCS_PROOF_REUSE_MISS = 0,     /* rerun */
    VCS_PROOF_REUSE_HIT_PASS,     /* reuse the PASS; skip the work */
    VCS_PROOF_REUSE_HIT_FAIL,     /* known failing; still rerunnable */
    VCS_PROOF_REUSE_REFUSE,       /* ambiguous or invalid: named refusal */
};

/* Per-ticket reasons. */
#define VCS_PROOF_TICKET_ELIGIBLE "eligible"
#define VCS_PROOF_TICKET_MALFORMED "ticket_malformed"
#define VCS_PROOF_TICKET_DUPLICATE "duplicate_observation"
#define VCS_PROOF_TICKET_KEY_MISMATCH "key_mismatch"
#define VCS_PROOF_TICKET_PREIMAGE_MISMATCH "key_preimage_mismatch"
#define VCS_PROOF_TICKET_SIGNATURE_INVALID "signature_invalid"
#define VCS_PROOF_TICKET_SIGNER_IN_DOMAIN "signer_in_candidate_domain"
#define VCS_PROOF_TICKET_SIGNER_UNTRUSTED "signer_not_trusted_for_reuse"
#define VCS_PROOF_TICKET_NOT_REPRODUCED "not_reproduced"
#define VCS_PROOF_TICKET_STALE "ticket_stale"
#define VCS_PROOF_TICKET_FUTURE "ticket_from_future"
/* Decision reasons. */
#define VCS_PROOF_REUSE_WHY_HIT "eligible_quorum"
#define VCS_PROOF_REUSE_WHY_KNOWN_FAIL "eligible_failure"
#define VCS_PROOF_REUSE_WHY_NONE "no_observation"
#define VCS_PROOF_REUSE_WHY_INELIGIBLE "no_eligible_observation"
#define VCS_PROOF_REUSE_WHY_QUORUM "quorum_not_met"
#define VCS_PROOF_REUSE_WHY_ARGUMENTS "reuse_arguments_invalid"
#define VCS_PROOF_REUSE_WHY_PREIMAGE "key_preimage_invalid"
#define VCS_PROOF_REUSE_WHY_POLICY "reuse_policy_invalid"
#define VCS_PROOF_REUSE_WHY_POLICY_ROOT "policy_root_inconsistent"
#define VCS_PROOF_REUSE_WHY_DOMAIN "candidate_domain_invalid"
#define VCS_PROOF_REUSE_WHY_CAPACITY "classification_capacity"

struct vcs_proof_ticket_class {
    uint8_t observation_root[VCS_PROOF_ROOT_BYTES];
    uint8_t producer_pubkey[VCS_PROOF_PUBKEY_BYTES];
    enum vcs_proof_verdict verdict;  /* 0 when malformed */
    bool eligible;
    const char *reason;              /* one of VCS_PROOF_TICKET_* */
};

#define VCS_PROOF_REUSE_MAX_USED 16u

struct vcs_proof_reuse_decision {
    enum vcs_proof_reuse_outcome outcome;
    const char *reason;
    uint8_t input_key[VCS_PROOF_ROOT_BYTES];
    uint32_t tickets_seen;
    uint32_t eligible_pass;
    uint32_t eligible_fail;
    uint32_t distinct_pass_signers;
    /* Observation roots that authorize a HIT (PASS) or HIT_FAIL, or the
     * conflicting ones on REFUSE. */
    uint8_t used[VCS_PROOF_REUSE_MAX_USED][VCS_PROOF_ROOT_BYTES];
    uint32_t used_count;
};

/* Decide reuse for one component. `wires`/`lens` are candidate tickets
 * (any source: an index lookup, a peer). `classes` receives one entry per
 * ticket and must hold `count`. Returns false only for caller errors, with
 * out->outcome = REFUSE and a named reason; true for every decision,
 * including MISS and REFUSE. */
bool vcs_proof_reuse_decide(const struct vcs_component_proof_key_v1 *local,
                            const struct vcs_proof_candidate_domain *domain,
                            const struct vcs_proof_reuse_policy *policy,
                            const uint8_t *const *wires, const size_t *lens,
                            size_t count,
                            struct vcs_proof_ticket_class *classes,
                            struct vcs_proof_reuse_decision *out);

/* Same decision over every observation `index` holds for the local key.
 * `classes` must hold `class_cap` entries; more observations than that is
 * a REFUSE (classification_capacity), never a silent truncation. */
bool vcs_proof_reuse_decide_index(
    const struct vcs_component_proof_key_v1 *local,
    const struct vcs_proof_candidate_domain *domain,
    const struct vcs_proof_reuse_policy *policy,
    const struct vcs_proof_ticket_index *index,
    struct vcs_proof_ticket_class *classes, size_t class_cap,
    struct vcs_proof_reuse_decision *out);

const char *vcs_proof_reuse_outcome_name(enum vcs_proof_reuse_outcome o);

#endif /* ZCL_VCS_PROOF_TICKET_H */
