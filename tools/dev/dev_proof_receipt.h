/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Fixed-width signed local acceptance and child-receipt contract. */

#ifndef ZCL_TOOLS_DEV_PROOF_RECEIPT_H
#define ZCL_TOOLS_DEV_PROOF_RECEIPT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define ZCL_DEV_PROOF_OID_MAX 32u
#define ZCL_DEV_PROOF_ROOT_BYTES 32u
#define ZCL_DEV_PROOF_DIMENSIONS 4u
/* The v1 record: fixed fields, canonical little-endian encoding, sealed by
 * a SHA3-256 digest under a domain string. Its bytes are unchanged in v2 and
 * a v1 file on disk still parses — it is refused by name, not misread. */
#define ZCL_DEV_PROOF_UNSIGNED_WIRE_BYTES 664u
/* The v2 record: the same 664-byte body plus a fixed signer trailer of
 * signer_pubkey[32] || signature[64]. Callers keep sizing their buffers with
 * ZCL_DEV_PROOF_WIRE_BYTES; only the number behind the name moved. */
#define ZCL_DEV_PROOF_SIGNER_TRAILER_BYTES 96u
#define ZCL_DEV_PROOF_WIRE_BYTES \
    (ZCL_DEV_PROOF_UNSIGNED_WIRE_BYTES + ZCL_DEV_PROOF_SIGNER_TRAILER_BYTES)
/* Byte offset of the u32 format version inside the record: 8 magic bytes. */
#define ZCL_DEV_PROOF_WIRE_VERSION_OFFSET 8u
#define ZCL_DEV_PROOF_PUBKEY_BYTES 32u
#define ZCL_DEV_PROOF_SIGNATURE_BYTES 64u
#define ZCL_DEV_PROOF_CHILD_WIRE_BYTES 100u

/* A signed per-group observation. This is deliberately a different wire
 * object from the pair receipt above: old receipt parsers reject its size and
 * magic, and no verdict leaf alone admits a publication.
 *
 * Canonical wire layout (little-endian integers):
 *   0   magic[8] = "Z23VLF1\0"
 *   8   version u32 = 1
 *   12  verdict u8 (PASS=1, FAIL=2)
 *   13  group_len u8 (1..127)
 *   14  reserved[2] = zero
 *   16  exact test-cache key[32]
 *   48  group[128] (group_len bytes then a canonical zero tail)
 *   176 observed_unix u64
 *   184 elapsed_ms u64
 *   192 log_seq u64
 *   200 prev_log_head[32]
 *   232 producer_pubkey[32]
 *   264 signature[64]
 *
 * The Ed25519 message is domain "zcl.dev_verdict_leaf.v1" followed by bytes
 * [0,232). The future CAS root is SHA3-256 over domain
 * "zcl.dev_verdict_leaf_root.v1" followed by all 328 signed wire bytes. */
#define ZCL_DEV_VERDICT_LEAF_KEY_BYTES 32u
#define ZCL_DEV_VERDICT_LEAF_GROUP_BYTES 128u
#define ZCL_DEV_VERDICT_LEAF_GROUP_MAX 127u
#define ZCL_DEV_VERDICT_LEAF_UNSIGNED_WIRE_BYTES 232u
#define ZCL_DEV_VERDICT_LEAF_WIRE_BYTES 328u

enum zcl_dev_verdict_leaf_verdict {
    ZCL_DEV_VERDICT_LEAF_PASS = 1,
    ZCL_DEV_VERDICT_LEAF_FAIL = 2,
};

struct zcl_dev_verdict_leaf_v1 {
    uint8_t key[ZCL_DEV_VERDICT_LEAF_KEY_BYTES];
    char group[ZCL_DEV_VERDICT_LEAF_GROUP_BYTES];
    uint8_t group_len;
    enum zcl_dev_verdict_leaf_verdict verdict;
    uint64_t observed_unix;
    uint64_t elapsed_ms;
    uint64_t log_seq;
    uint8_t prev_log_head[ZCL_DEV_PROOF_ROOT_BYTES];
    bool has_signature;
    uint8_t producer_pubkey[ZCL_DEV_PROOF_PUBKEY_BYTES];
    uint8_t signature[ZCL_DEV_PROOF_SIGNATURE_BYTES];
};

#define ZCL_DEV_VERDICT_WHY_ARGUMENTS "verdict_leaf_arguments_invalid"
#define ZCL_DEV_VERDICT_WHY_FRAMING "verdict_leaf_framing_invalid"
#define ZCL_DEV_VERDICT_WHY_SCHEMA "verdict_leaf_schema_unknown"
#define ZCL_DEV_VERDICT_WHY_ENCODING "verdict_leaf_encoding_invalid"
#define ZCL_DEV_VERDICT_WHY_UNSIGNED "verdict_leaf_unsigned"
#define ZCL_DEV_VERDICT_WHY_KEY "verdict_leaf_key_mismatch"
#define ZCL_DEV_VERDICT_WHY_GROUP "verdict_leaf_group_mismatch"
/* What the roots in a receipt mean, versioned apart from the record layout.
 * Every producer stamps this and every reader refuses anything else, so a
 * receipt whose roots were derived under an older policy is named
 * (`receipt_schema_old`) instead of being compared against roots that mean
 * something different. Policy 1 keyed compiler/flags/build_graph to three
 * domain tags over one file that spelled the producer's checkout path, and
 * environment to the literal PATH; policy 2 keys them to the toolchain
 * capsule and to path-neutralised build-plan text, so two boxes with one
 * toolchain agree. */
#define ZCL_DEV_PROOF_POLICY_VERSION 2u

enum zcl_dev_proof_dimension_id {
    ZCL_DEV_PROOF_GENERATED = 0,
    ZCL_DEV_PROOF_COMPILE,
    ZCL_DEV_PROOF_LINT,
    ZCL_DEV_PROOF_TEST,
};

struct zcl_dev_proof_dimension {
    uint8_t receipt_root[ZCL_DEV_PROOF_ROOT_BYTES];
    uint32_t selected;
    uint32_t ran;
    uint32_t reused;
    uint32_t failed;
    uint32_t skipped;
};

struct zcl_dev_acceptance_receipt_v1 {
    uint8_t local_commit[ZCL_DEV_PROOF_OID_MAX];
    uint8_t remote_base[ZCL_DEV_PROOF_OID_MAX];
    uint8_t local_commit_len;
    uint8_t remote_base_len;

    uint8_t source_root[ZCL_DEV_PROOF_ROOT_BYTES];
    uint8_t source_cas_root[ZCL_DEV_PROOF_ROOT_BYTES];
    uint8_t mutation_root[ZCL_DEV_PROOF_ROOT_BYTES];
    uint8_t changed_set_root[ZCL_DEV_PROOF_ROOT_BYTES];
    uint8_t impact_policy_root[ZCL_DEV_PROOF_ROOT_BYTES];
    uint8_t compiler_root[ZCL_DEV_PROOF_ROOT_BYTES];
    uint8_t flags_root[ZCL_DEV_PROOF_ROOT_BYTES];
    uint8_t environment_root[ZCL_DEV_PROOF_ROOT_BYTES];
    uint8_t build_graph_root[ZCL_DEV_PROOF_ROOT_BYTES];
    uint8_t child_set_root[ZCL_DEV_PROOF_ROOT_BYTES];

    struct zcl_dev_proof_dimension dimensions[ZCL_DEV_PROOF_DIMENSIONS];
    uint64_t created_unix;
    uint64_t elapsed_ms;
    uint32_t policy_version;
    uint32_t complete;
    uint8_t seal[ZCL_DEV_PROOF_ROOT_BYTES];

    /* Signer trailer. `has_signature` is false for a v1 record read off
     * disk; such a record validates to "receipt_unsigned" and is never
     * admitted. It is not serialized — the wire length says which it is. */
    bool has_signature;
    uint8_t signer_pubkey[ZCL_DEV_PROOF_PUBKEY_BYTES];
    uint8_t signature[ZCL_DEV_PROOF_SIGNATURE_BYTES];
};

const char *zcl_dev_proof_dimension_name(enum zcl_dev_proof_dimension_id id);
bool zcl_dev_proof_oid_decode(const char *hex,
                              uint8_t out[ZCL_DEV_PROOF_OID_MAX],
                              uint8_t *out_len);
bool zcl_dev_proof_oid_encode(const uint8_t oid[ZCL_DEV_PROOF_OID_MAX],
                              uint8_t oid_len, char *out, size_t out_size);
/* Seal AND sign one receipt with this box's Ed25519 development identity,
 * creating that key on first use. Fills `seal`, `signer_pubkey`, `signature`
 * and sets `has_signature`. Returns false — leaving the receipt unsigned and
 * therefore inadmissible — when the key cannot be created or read; the typed
 * reason is logged by zcl_dev_proof_signer_sign(). There is no unsigned
 * fallback. */
bool zcl_dev_proof_receipt_seal(struct zcl_dev_acceptance_receipt_v1 *receipt);
bool zcl_dev_proof_receipt_child_set_root(
    const struct zcl_dev_acceptance_receipt_v1 *receipt,
    uint8_t out[ZCL_DEV_PROOF_ROOT_BYTES]);
/* Admission decision for one receipt against one commit/base pair. `why`
 * receives exactly one refusal token; the signer-related ones are
 * receipt_unsigned, signature_invalid, signer_unknown and
 * signer_key_unreadable. Never aborts: every bad input is a named refusal. */
bool zcl_dev_proof_receipt_validate(
    const struct zcl_dev_acceptance_receipt_v1 *receipt,
    const char *local_commit, const char *remote_base,
    char *why, size_t why_len);
/* Always writes the v2 record (ZCL_DEV_PROOF_WIRE_BYTES). A receipt that was
 * never signed cannot be serialized — refusing here is what keeps an unsigned
 * record from reaching the cache in the first place. */
bool zcl_dev_proof_receipt_serialize(
    const struct zcl_dev_acceptance_receipt_v1 *receipt,
    uint8_t out[ZCL_DEV_PROOF_WIRE_BYTES]);
/* Accepts either wire length: ZCL_DEV_PROOF_WIRE_BYTES (v2, signed) or
 * ZCL_DEV_PROOF_UNSIGNED_WIRE_BYTES (v1, has_signature false). Parsing a v1
 * record succeeds so that validate() can name it; admitting it does not. */
bool zcl_dev_proof_receipt_parse(
    const uint8_t *wire, size_t wire_len,
    struct zcl_dev_acceptance_receipt_v1 *out);
bool zcl_dev_proof_child_receipt_create(
    enum zcl_dev_proof_dimension_id id,
    struct zcl_dev_proof_dimension *dimension,
    uint8_t out[ZCL_DEV_PROOF_CHILD_WIRE_BYTES]);
bool zcl_dev_proof_child_receipt_validate(
    const uint8_t *wire, size_t wire_len,
    enum zcl_dev_proof_dimension_id id,
    const struct zcl_dev_proof_dimension *dimension);

/* Sign one structurally valid PASS or FAIL observation with this box's
 * existing proof identity. This authenticates an observation; it grants no
 * coverage, union, publication, or admission authority. */
bool zcl_dev_verdict_leaf_sign(struct zcl_dev_verdict_leaf_v1 *leaf,
                               char *why, size_t why_len);
bool zcl_dev_verdict_leaf_serialize(
    const struct zcl_dev_verdict_leaf_v1 *leaf,
    uint8_t out[ZCL_DEV_VERDICT_LEAF_WIRE_BYTES],
    char *why, size_t why_len);
bool zcl_dev_verdict_leaf_parse(
    const uint8_t *wire, size_t wire_len,
    struct zcl_dev_verdict_leaf_v1 *out,
    char *why, size_t why_len);
/* expected_key and expected_group are mandatory. A true result means the
 * exact-key/group observation has a trusted valid signature, including when
 * verdict==FAIL. The caller must inspect verdict; true never means PASS. */
bool zcl_dev_verdict_leaf_verify(
    const struct zcl_dev_verdict_leaf_v1 *leaf,
    const uint8_t expected_key[ZCL_DEV_VERDICT_LEAF_KEY_BYTES],
    const char *expected_group, char *why, size_t why_len);
bool zcl_dev_verdict_leaf_root(
    const struct zcl_dev_verdict_leaf_v1 *leaf,
    uint8_t out[ZCL_DEV_PROOF_ROOT_BYTES], char *why, size_t why_len);

#endif
