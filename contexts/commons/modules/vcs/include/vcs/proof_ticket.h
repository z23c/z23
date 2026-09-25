/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Component proof input keys, interface contract roots, signed
 *          proof tickets and signed per-issuer log checkpoints (codecs).
 *
 * This is the TICKET object of docs/work/CANONICAL_LIFECYCLE.md (PROOF_SET
 * section). Four identities, never substituted for one another:
 *
 *   source identity   source_closure root: which source bytes were compiled
 *   action key        input_key: SHA3-256 of the complete input closure of
 *                     one build action or proof obligation
 *                     (zcl.component_proof_key.v1). It excludes verdict,
 *                     time, producer, signature and commit ids.
 *   artifact identity artifact_root: SHA3-256 of the produced output bytes
 *   observation root  SHA3-256 of the complete signed ticket wire
 *
 * A signature authenticates WHO asserted WHAT. It never makes a result
 * correct. Reuse decisions live in vcs/proof_reuse.h; this header only
 * defines canonical bytes and their roots.
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
 * Nineteen nonzero 32-byte roots in this fixed order. An absent input is a
 * named empty root (vcs_component_proof_field_root(field, "", 0)), never
 * zero bytes.
 *
 *   source_closure      every source byte the action reads
 *   dependency_closure  resolved dependency bytes; an obligation that
 *                       EXECUTES callee bytes (a linked test group) binds the
 *                       callee implementation roots here
 *   negative_lookups    every include/namespace probe that did NOT exist,
 *                       in search order: adding a file that shadows a miss
 *                       changes the key
 *   generated_inputs    generated headers/sources with their producer
 *                       action keys
 *   toolchain           v1 toolchain capsule root (vcs_fastobj_key binds it)
 *   linker, sysroot     link tool and system root identity
 *   flags               the ORDERED argv (vcs_component_proof_ordered_root)
 *   environment         allowlisted names and values only
 *   integration_edges   sorted (callee component, callee contract_root) set:
 *                       interface identity, never callee implementation bytes
 *
 * Preimage wire (CAS blob, 624 bytes, little-endian):
 *   0   magic[8] = "Z23CPK1\0"
 *   8   version u32 = 1
 *   12  field_count u32 = 19
 *   16  roots[19][32] in enum vcs_component_proof_field order
 *   624 end
 *
 * input_key = SHA3-256("zcl.component_proof_key.v1" ||
 *                      for each field: u16le field_id || u32le 32 || root) */
enum vcs_component_proof_field {
    VCS_CPK_KIND = 0,
    VCS_CPK_UNIT_ID,
    VCS_CPK_SOURCE_CLOSURE,
    VCS_CPK_DEPENDENCY_CLOSURE,
    VCS_CPK_NEGATIVE_LOOKUPS,
    VCS_CPK_GENERATED_INPUTS,
    VCS_CPK_TOOLCHAIN,
    VCS_CPK_LINKER,
    VCS_CPK_SYSROOT,
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

#define VCS_CPK_WIRE_BYTES (16u + 19u * VCS_PROOF_ROOT_BYTES)

struct vcs_component_proof_key_v1 {
    uint8_t roots[VCS_CPK_FIELD_COUNT][VCS_PROOF_ROOT_BYTES];
};

/* Stable lowercase field name ("source_closure", ...), NULL out of range. */
const char *vcs_component_proof_field_name(enum vcs_component_proof_field f);

/* Root of one byte input: SHA3-256("zcl.component_proof_key.field.v1" ||
 * u16le field || u64le len || bytes). */
bool vcs_component_proof_field_root(enum vcs_component_proof_field field,
                                    const void *bytes, size_t len,
                                    uint8_t out[VCS_PROOF_ROOT_BYTES]);

/* Root of an ORDERED string list (argv, include-search misses). Order is
 * identity: swapping two flags yields another root. */
bool vcs_component_proof_ordered_root(enum vcs_component_proof_field field,
                                      const char *const *items, size_t count,
                                      uint8_t out[VCS_PROOF_ROOT_BYTES]);

/* One allowlisted environment variable; value NULL means "unset". */
struct vcs_component_proof_env {
    const char *name;
    const char *value;
};

/* Names must be [A-Z0-9_]+, strictly ascending and unique; anything else
 * is refused, never silently sorted. */
bool vcs_component_proof_environment_root(
    const struct vcs_component_proof_env *env, size_t count,
    uint8_t out[VCS_PROOF_ROOT_BYTES]);

/* One generated input: its path, content root and the action key of the
 * action that produced it. */
struct vcs_component_proof_generated {
    const char *path;
    uint8_t content_root[VCS_PROOF_ROOT_BYTES];
    uint8_t producer_key[VCS_PROOF_ROOT_BYTES];
};

/* Paths strictly ascending and unique, else refused. */
bool vcs_component_proof_generated_root(
    const struct vcs_component_proof_generated *inputs, size_t count,
    uint8_t out[VCS_PROOF_ROOT_BYTES]);

/* ── Interface contracts ──────────────────────────────────────────────────
 *
 * contract_root = SHA3-256 over a component's EXPORTED interface: its id,
 * the normalized public-header token stream (ordered), the exported
 * symbol/ABI signature set and the declared semantic premise/invariant id
 * set. A private implementation edit leaves it unchanged; a header, ABI or
 * premise change moves it. Sets are sorted here; duplicates are refused. */
struct vcs_component_contract {
    const char *component_id;
    const char *const *header_tokens;
    size_t header_token_count;
    const char *const *symbols;
    size_t symbol_count;
    const char *const *premises;
    size_t premise_count;
};

bool vcs_component_contract_root(const struct vcs_component_contract *c,
                                 uint8_t out[VCS_PROOF_ROOT_BYTES]);

/* One caller->callee interface edge. */
struct vcs_component_edge {
    const char *callee_id;
    uint8_t contract_root[VCS_PROOF_ROOT_BYTES];
};

/* integration_edges field root over the edge set sorted by callee id; a
 * callee listed twice is refused. */
bool vcs_component_integration_edges_root(
    const struct vcs_component_edge *edges, size_t count,
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
/* Bit i set when field i differs (diagnostics: names what a miss moved). */
uint32_t vcs_component_proof_key_diff(const struct vcs_component_proof_key_v1 *a,
                                      const struct vcs_component_proof_key_v1 *b);

/* ── zcl.proof_ticket.v1 ──────────────────────────────────────────────────
 *
 * Fixed wire (360 bytes, little-endian):
 *   0   magic[8] = "Z23PTK1\0"
 *   8   version u32 = 1
 *   12  verdict u8        PASS=1, FAIL=2
 *   13  basis u8          EXECUTED=1 (the signer ran the checks itself) or
 *                         REUSED=2 (provenance only; never counts to quorum)
 *   14  action_class u8   BUILD=1 (produces an artifact), CHECK=2
 *   15  reserved u8 = 0
 *   16  input_key[32]
 *   48  key_preimage_root[32]  CAS root of the key preimage wire
 *   80  source_root[32]        the preimage's source_closure root
 *   112 artifact_root[32]      BUILD+PASS: SHA3-256 of output bytes; else 0
 *   144 evidence_root[32]      CAS root of the log/output evidence
 *   176 basis_ref[32]          REUSED: the observation root reused; else 0
 *   208 checks_run u32         >= 1
 *   212 checks_passed u32      PASS: == checks_run; FAIL: < checks_run
 *   216 cpu_us u64
 *   224 wall_us u64
 *   232 bytes_in u64
 *   240 bytes_out u64
 *   248 created_unix u64       nonzero
 *   256 issuer_seq u64         this ticket's position in the producer's log
 *   264 producer_pubkey[32]
 *   296 signature[64]
 *   360 end
 *
 * signature = Ed25519 over "zcl.proof_ticket.v1" || bytes [0,296).
 * observation_root = SHA3-256("zcl.proof_ticket_root.v1" || all 360 bytes).
 * The observation root is also the ticket's leaf in its issuer's log. */
#define VCS_PROOF_TICKET_WIRE_BYTES 360u
#define VCS_PROOF_TICKET_SIGNED_BYTES 296u

enum vcs_proof_verdict {
    VCS_PROOF_VERDICT_PASS = 1,
    VCS_PROOF_VERDICT_FAIL = 2,
};

enum vcs_proof_basis {
    VCS_PROOF_BASIS_EXECUTED = 1,
    VCS_PROOF_BASIS_REUSED = 2,
};

enum vcs_proof_action_class {
    VCS_PROOF_ACTION_BUILD = 1,
    VCS_PROOF_ACTION_CHECK = 2,
};

struct vcs_proof_ticket_v1 {
    enum vcs_proof_verdict verdict;
    enum vcs_proof_basis basis;
    enum vcs_proof_action_class action_class;
    uint8_t input_key[VCS_PROOF_ROOT_BYTES];
    uint8_t key_preimage_root[VCS_PROOF_ROOT_BYTES];
    uint8_t source_root[VCS_PROOF_ROOT_BYTES];
    uint8_t artifact_root[VCS_PROOF_ROOT_BYTES];
    uint8_t evidence_root[VCS_PROOF_ROOT_BYTES];
    uint8_t basis_ref[VCS_PROOF_ROOT_BYTES];
    uint32_t checks_run;
    uint32_t checks_passed;
    uint64_t cpu_us;
    uint64_t wall_us;
    uint64_t bytes_in;
    uint64_t bytes_out;
    uint64_t created_unix;
    uint64_t issuer_seq;
    uint8_t producer_pubkey[VCS_PROOF_PUBKEY_BYTES];
    uint8_t signature[VCS_PROOF_SIGNATURE_BYTES];
};

/* SHA3-256 of raw artifact bytes: the artifact identity. */
bool vcs_proof_artifact_root(const uint8_t *bytes, size_t len,
                             uint8_t out[VCS_PROOF_ROOT_BYTES]);

/* Body fields (everything before producer_pubkey) are canonical. */
bool vcs_proof_ticket_body_valid(const struct vcs_proof_ticket_v1 *t);
/* Sign with a caller-held Ed25519 seed; fills producer_pubkey/signature.
 * The library never reads a key file: which identity signs is the
 * caller's decision, and the receiver re-checks it. */
bool vcs_proof_ticket_sign(struct vcs_proof_ticket_v1 *t,
                           const uint8_t seed[32]);
bool vcs_proof_ticket_signature_valid(const struct vcs_proof_ticket_v1 *t);
bool vcs_proof_ticket_encode(const struct vcs_proof_ticket_v1 *t,
                             uint8_t out[VCS_PROOF_TICKET_WIRE_BYTES]);
/* Refuses wrong length (truncated or trailing bytes), bad magic/version,
 * nonzero reserved bytes and non-canonical values. Does NOT verify the
 * signature. */
bool vcs_proof_ticket_decode(const uint8_t *wire, size_t len,
                             struct vcs_proof_ticket_v1 *out);
bool vcs_proof_ticket_observation_root(const uint8_t *wire, size_t len,
                                       uint8_t out[VCS_PROOF_ROOT_BYTES]);

/* ── zcl.proof_checkpoint.v1 ──────────────────────────────────────────────
 *
 * One issuer's append-only ticket log is a Merkle Mountain Range
 * (chain/mmr.h) whose leaves are observation roots in issuer_seq order. A
 * checkpoint signs its current size and root.
 *
 * Fixed wire (224 bytes, little-endian):
 *   0   magic[8] = "Z23PCK1\0"
 *   8   version u32 = 1
 *   12  reserved u32 = 0
 *   16  issuer_pubkey[32]
 *   48  leaf_count u64          >= 1
 *   56  mmr_root[32]            mmr_root() of the log
 *   88  peaks_root[32]          SHA3-256("zcl.proof_checkpoint.peaks.v1" ||
 *                               mmr_serialize() bytes): resumable state
 *   120 prev_checkpoint_root[32] zero only for the issuer's first
 *   152 created_unix u64        nonzero
 *   160 signature[64]
 *   224 end
 *
 * signature = Ed25519 over "zcl.proof_checkpoint.v1" || bytes [0,160).
 * checkpoint_root = SHA3-256("zcl.proof_checkpoint_root.v1" || 224 bytes). */
#define VCS_PROOF_CHECKPOINT_WIRE_BYTES 224u
#define VCS_PROOF_CHECKPOINT_SIGNED_BYTES 160u

struct vcs_proof_checkpoint_v1 {
    uint8_t issuer_pubkey[VCS_PROOF_PUBKEY_BYTES];
    uint64_t leaf_count;
    uint8_t mmr_root[VCS_PROOF_ROOT_BYTES];
    uint8_t peaks_root[VCS_PROOF_ROOT_BYTES];
    uint8_t prev_checkpoint_root[VCS_PROOF_ROOT_BYTES];
    uint64_t created_unix;
    uint8_t signature[VCS_PROOF_SIGNATURE_BYTES];
};

struct mmr;
/* peaks_root of an MMR state. */
bool vcs_proof_checkpoint_peaks_root(const struct mmr *m,
                                     uint8_t out[VCS_PROOF_ROOT_BYTES]);
bool vcs_proof_checkpoint_sign(struct vcs_proof_checkpoint_v1 *c,
                               const uint8_t seed[32]);
bool vcs_proof_checkpoint_signature_valid(
    const struct vcs_proof_checkpoint_v1 *c);
bool vcs_proof_checkpoint_encode(const struct vcs_proof_checkpoint_v1 *c,
                                 uint8_t out[VCS_PROOF_CHECKPOINT_WIRE_BYTES]);
bool vcs_proof_checkpoint_decode(const uint8_t *wire, size_t len,
                                 struct vcs_proof_checkpoint_v1 *out);
bool vcs_proof_checkpoint_root(const uint8_t *wire, size_t len,
                               uint8_t out[VCS_PROOF_ROOT_BYTES]);

#endif /* ZCL_VCS_PROOF_TICKET_H */
