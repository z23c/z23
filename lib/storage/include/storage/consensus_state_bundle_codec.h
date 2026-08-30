/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Canonical logical encoding for zcl.consensus_state_bundle.v1. */

#ifndef ZCL_STORAGE_CONSENSUS_STATE_BUNDLE_CODEC_H
#define ZCL_STORAGE_CONSENSUS_STATE_BUNDLE_CODEC_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define CONSENSUS_STATE_BUNDLE_SCHEMA "zcl.consensus_state_bundle.v1"
#define CONSENSUS_STATE_SOURCE_RECEIPT_SCHEMA_V1 \
    "zcl.consensus_state_source_receipt.v1"
#define CONSENSUS_STATE_SOURCE_RECEIPT_SCHEMA_V2 \
    "zcl.consensus_state_source_receipt.v2"
#define CONSENSUS_STATE_SOURCE_RECEIPT_SCHEMA \
    CONSENSUS_STATE_SOURCE_RECEIPT_SCHEMA_V2
#define CONSENSUS_STATE_SOURCE_EPOCH_META_KEY \
    "consensus_state.source_epoch_digest"
#define CONSENSUS_STATE_BUNDLE_PROOF_COUNT 8u
#define CONSENSUS_STATE_BUNDLE_PROOF_NAME_MAX 31u

/* Proof work actually performed by the producer.  These values are part of
 * the canonical bundle digest; a checkpoint-matched state fold must never be
 * mistaken for a full local replay of scripts and shielded proofs. */
enum consensus_state_validation_profile {
    CONSENSUS_STATE_VALIDATION_INVALID = 0,
    CONSENSUS_STATE_VALIDATION_FULL = 1,
    CONSENSUS_STATE_VALIDATION_CHECKPOINT_FOLD = 2,
};

enum consensus_state_source_receipt_version {
    CONSENSUS_STATE_SOURCE_RECEIPT_INVALID = 0,
    CONSENSUS_STATE_SOURCE_RECEIPT_V1 = 1,
    CONSENSUS_STATE_SOURCE_RECEIPT_V2 = 2,
};

struct sha3_256_ctx;

/* Producer claims bound to an exact running executable and chain corpus. The
 * bundle preserves these fields so offline verification can recompute the
 * receipt digest. source_tree_root and toolchain_digest are claims, not an
 * independent rebuild proof; their authority comes from the known executable
 * that emitted and durably recorded this receipt. */
struct consensus_state_source_receipt {
    uint8_t schema_version;
    uint8_t source_epoch_digest[32];
    /* v1: legacy SHA3 claim derived from a Git SHA-1 + clean bit.
     * v2: exact zcl.dev_source_identity.v2 SHA-256 over canonical current
     * source-tree paths, modes, file bytes, and symlink targets. */
    uint8_t source_tree_root[32];
    uint8_t running_binary_digest[32];
    uint8_t toolchain_digest[32];
    uint8_t build_inputs_digest[32];
    uint8_t chain_corpus_digest[32];
    bool source_clean;
    uint8_t validation_profile;
    /* v1 authority input. V2 reserves this field as empty; GitHub trace
     * metadata belongs outside the authoritative receipt. */
    char producer_commit[41];
    int64_t fold_cursor;
    uint8_t receipt_digest[32];
};

/* Exact schema parsing and legacy-field shape. V1 requires a lowercase 40-hex
 * Git commit because it is part of that legacy digest. V2 requires empty. */
bool consensus_state_source_receipt_schema_version(
    const char *schema, size_t schema_len, uint8_t *out_version);
const char *consensus_state_source_receipt_schema(uint8_t version);
bool consensus_state_source_receipt_commit_valid(uint8_t version,
                                                 const char *commit,
                                                 size_t commit_len);

/* Canonical summaries of producer evidence: header chain plus seven reducer
 * stages. component_digest commits the complete source rows inspected by the
 * exporter. These are evidence emitted by the receipt-bound executable, not
 * ZClassic header commitments and never peer-state PoW authentication. */
struct consensus_state_bundle_proof_summary {
    char component[CONSENSUS_STATE_BUNDLE_PROOF_NAME_MAX + 1u];
    uint64_t cursor;
    int64_t first_height;
    int64_t last_height;
    uint64_t row_count;
    uint64_t hash_bound_count;
    uint8_t component_digest[32];
};

/* Optional, explicit lineage for a proof summary that extends an installed
 * bundle rather than rescanning genesis rows which the atomic install no
 * longer stores.  The parent summary was admitted with the parent artifact;
 * suffix_digest commits only rows this producer inspected above base_height.
 * The final component_digest is re-derived from this structure, so lineage is
 * inspectable evidence rather than an opaque narrative field. */
struct consensus_state_bundle_proof_parent {
    bool present;
    int32_t base_height;
    uint8_t base_block_hash[32];
    uint8_t validation_profile;
    uint8_t proof_manifest_digest[32];
    uint8_t source_digest[32];
    uint8_t artifact_digest[32];
    struct consensus_state_bundle_proof_summary
        components[CONSENSUS_STATE_BUNDLE_PROOF_COUNT];
    uint8_t suffix_digest[CONSENSUS_STATE_BUNDLE_PROOF_COUNT][32];
};

struct consensus_state_bundle_manifest {
    int32_t height;
    uint8_t block_hash[32];
    bool history_complete;
    bool source_clean;
    uint8_t validation_profile;
    int64_t activation_boundary;
    uint8_t utxo_root[32];
    uint64_t utxo_count;
    int64_t total_supply;
    uint8_t anchor_digest[32];
    uint64_t anchor_count;
    uint8_t sprout_frontier_root[32];
    int64_t sprout_frontier_height;
    uint8_t sapling_frontier_root[32];
    int64_t sapling_frontier_height;
    uint8_t nullifier_digest[32];
    uint64_t nullifier_count;
    int64_t sprout_source_cursor;
    int64_t sapling_source_cursor;
    int64_t nullifier_source_cursor;
    int64_t source_fold_cursor;
    uint8_t proof_manifest_digest[32];
    uint8_t source_digest[32];
    uint8_t artifact_digest[32];
};

void consensus_state_bundle_anchor_digest_begin(struct sha3_256_ctx *ctx);
void consensus_state_bundle_anchor_digest_row(
    struct sha3_256_ctx *ctx, uint8_t pool, const uint8_t root[32],
    uint64_t height, const uint8_t *tree, uint32_t tree_len);
void consensus_state_bundle_nullifier_digest_begin(struct sha3_256_ctx *ctx);
void consensus_state_bundle_nullifier_digest_row(
    struct sha3_256_ctx *ctx, uint8_t pool, const uint8_t nf[32],
    uint64_t height);
void consensus_state_bundle_artifact_digest(
    const struct consensus_state_bundle_manifest *manifest, uint8_t out[32]);
void consensus_state_source_receipt_digest(
    const struct consensus_state_source_receipt *receipt, uint8_t out[32]);
void consensus_state_source_epoch_digest(
    const struct consensus_state_source_receipt *receipt, uint8_t out[32]);
void consensus_state_bundle_proof_manifest_digest(
    const struct consensus_state_bundle_proof_summary *summaries,
    size_t count, uint8_t out[32]);
bool consensus_state_bundle_proof_extension_digest(
    const struct consensus_state_bundle_proof_parent *parent,
    size_t ordinal, uint8_t out[32]);

#endif /* ZCL_STORAGE_CONSENSUS_STATE_BUNDLE_CODEC_H */
