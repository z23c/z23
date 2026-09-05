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

#endif
