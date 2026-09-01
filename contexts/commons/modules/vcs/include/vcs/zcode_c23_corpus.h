/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: canonical simulation-only C23 corpus census objects. */
#ifndef ZCL_VCS_ZCODE_C23_CORPUS_H
#define ZCL_VCS_ZCODE_C23_CORPUS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define VCS_ZCODE_SOURCE_ASSIGNMENT_V1_DOMAIN \
    "zcl.zcode.source_assignment.v1"
#define VCS_ZCODE_C23_CORPUS_RULES_V1_DOMAIN \
    "zcl.zcode.c23_corpus_rules.v1"
#define VCS_ZCODE_C23_CORPUS_SHARD_V1_DOMAIN \
    "zcl.zcode.c23_corpus_shard.v1"
#define VCS_ZCODE_C23_CORPUS_CHECKPOINT_V1_DOMAIN \
    "zcl.zcode.c23_corpus_checkpoint.v1"
#define VCS_ZCODE_PRODUCTIVITY_RECEIPT_V1_DOMAIN \
    "zcl.zcode.productivity_receipt.v1"

#define VCS_ZCODE_C23_CORPUS_SIMULATION_ONLY (1u << 0)
#define VCS_ZCODE_C23_CORPUS_NOT_OWNER_APPROVED (1u << 1)
#define VCS_ZCODE_C23_CORPUS_REQUIRED_FLAGS \
    (VCS_ZCODE_C23_CORPUS_SIMULATION_ONLY | \
     VCS_ZCODE_C23_CORPUS_NOT_OWNER_APPROVED)

#define VCS_ZCODE_SOURCE_ASSIGNMENT_WIRE_BYTES 328u
#define VCS_ZCODE_C23_CORPUS_RULES_WIRE_BYTES 156u
#define VCS_ZCODE_C23_MAX_FILE_BYTES (UINT64_C(64) * 1024u * 1024u)
#define VCS_ZCODE_C23_OVERLAP_THRESHOLD_BPS 8000u
#define VCS_ZCODE_C23_SHARD_ENTRY_MAX 4096u
#define VCS_ZCODE_C23_CHECKPOINT_SHARD_MAX 4096u
#define VCS_ZCODE_C23_PAGE_MAX 256u
#define VCS_ZCODE_C23_PUBLICATION_BATCH_MAX 256u
#define VCS_ZCODE_C23_DURABLE_ACKS 5u
#define VCS_ZCODE_C23_DURABLE_OPERATOR_GROUPS 3u
#define VCS_ZCODE_C23_FIRST_MILESTONE_LOC UINT64_C(50000000)
#define VCS_ZCODE_C23_SECOND_MILESTONE_LOC UINT64_C(100000000)
#define VCS_ZCODE_C23_SHARD_HEADER_WIRE_BYTES 112u
#define VCS_ZCODE_C23_SHARD_ENTRY_WIRE_BYTES 280u
#define VCS_ZCODE_C23_CHECKPOINT_HEADER_WIRE_BYTES 388u
#define VCS_ZCODE_C23_CHECKPOINT_BINDING_WIRE_BYTES 144u
#define VCS_ZCODE_PRODUCTIVITY_RECEIPT_WIRE_BYTES 324u

enum vcs_zcode_source_kind_v1 {
    VCS_ZCODE_SOURCE_HUMAN_AUTHORED = 1,
    VCS_ZCODE_SOURCE_AI_AUTHORED = 2,
    VCS_ZCODE_SOURCE_CANONICAL_IMPORT = 3,
    VCS_ZCODE_SOURCE_MECHANICAL_GENERATION = 4,
    VCS_ZCODE_SOURCE_VENDOR_MATERIAL = 5,
};

enum vcs_zcode_c23_extension_v1 {
    VCS_ZCODE_C23_EXTENSION_C = 1u << 0,
    VCS_ZCODE_C23_EXTENSION_H = 1u << 1,
    VCS_ZCODE_C23_EXTENSION_DEF = 1u << 2,
};

#define VCS_ZCODE_C23_EXTENSION_MASK \
    (VCS_ZCODE_C23_EXTENSION_C | VCS_ZCODE_C23_EXTENSION_H | \
     VCS_ZCODE_C23_EXTENSION_DEF)

enum vcs_zcode_c23_evidence_v1 {
    VCS_ZCODE_C23_EVIDENCE_API = UINT64_C(1) << 0,
    VCS_ZCODE_C23_EVIDENCE_RECIPE = UINT64_C(1) << 1,
    VCS_ZCODE_C23_EVIDENCE_TESTS = UINT64_C(1) << 2,
    VCS_ZCODE_C23_EVIDENCE_PERMISSIVE_LICENSE = UINT64_C(1) << 3,
    VCS_ZCODE_C23_EVIDENCE_QUALITY_PROFILE = UINT64_C(1) << 4,
    VCS_ZCODE_C23_EVIDENCE_SOURCE_ASSIGNMENT = UINT64_C(1) << 5,
    VCS_ZCODE_C23_EVIDENCE_REPRODUCIBLE = UINT64_C(1) << 6,
    VCS_ZCODE_C23_EVIDENCE_FAMILY_QUORUM = UINT64_C(1) << 7,
    VCS_ZCODE_C23_EVIDENCE_COMPLETE_POSSESSION = UINT64_C(1) << 8,
};

#define VCS_ZCODE_C23_EVIDENCE_REQUIRED_MASK UINT64_C(0x1ff)

enum vcs_zcode_c23_error {
    VCS_ZCODE_C23_OK = 0,
    VCS_ZCODE_C23_NULL,
    VCS_ZCODE_C23_SIZE,
    VCS_ZCODE_C23_MAGIC,
    VCS_ZCODE_C23_VERSION,
    VCS_ZCODE_C23_FLAGS,
    VCS_ZCODE_C23_ENUM,
    VCS_ZCODE_C23_ROOT,
    VCS_ZCODE_C23_ORDER,
    VCS_ZCODE_C23_POLICY,
    VCS_ZCODE_C23_TIME,
    VCS_ZCODE_C23_SIGNATURE,
    VCS_ZCODE_C23_OVERFLOW,
    VCS_ZCODE_C23_CURSOR,
    VCS_ZCODE_C23_ANCESTRY,
    VCS_ZCODE_C23_PROOF,
};

enum vcs_zcode_c23_entry_flag_v1 {
    VCS_ZCODE_C23_ENTRY_COUNTED = 1u << 0,
    VCS_ZCODE_C23_ENTRY_DURABLE = 1u << 1,
};

enum vcs_zcode_c23_exclusion_v1 {
    VCS_ZCODE_C23_EXCLUDE_VENDOR = 1u << 0,
    VCS_ZCODE_C23_EXCLUDE_MECHANICAL = 1u << 1,
    VCS_ZCODE_C23_EXCLUDE_UNASSIGNED = 1u << 2,
    VCS_ZCODE_C23_EXCLUDE_LICENSE = 1u << 3,
    VCS_ZCODE_C23_EXCLUDE_UNSUPPORTED = 1u << 4,
    VCS_ZCODE_C23_EXCLUDE_OVERSIZE = 1u << 5,
    VCS_ZCODE_C23_EXCLUDE_INCOMPLETE = 1u << 6,
    VCS_ZCODE_C23_EXCLUDE_DUPLICATE = 1u << 7,
    VCS_ZCODE_C23_EXCLUDE_CONFLICT = 1u << 8,
    VCS_ZCODE_C23_EXCLUDE_REVIEW_REQUIRED = 1u << 9,
    VCS_ZCODE_C23_EXCLUDE_STALE_ADMISSION = 1u << 10,
    VCS_ZCODE_C23_EXCLUDE_INCOMPLETE_POSSESSION = 1u << 11,
};

#define VCS_ZCODE_C23_EXCLUSION_MASK UINT32_C(0x00000fff)

enum vcs_zcode_c23_milestone_v1 {
    VCS_ZCODE_C23_MILESTONE_NONE = 0,
    VCS_ZCODE_C23_MILESTONE_50M = 1,
    VCS_ZCODE_C23_MILESTONE_100M = 2,
};

struct vcs_zcode_source_assignment_v1 {
    uint16_t schema_version;
    uint16_t flags;
    uint16_t source_kind;
    uint16_t reserved;
    uint64_t sequence;
    uint64_t assigned_height;
    int64_t assigned_mtp;
    uint8_t source_root[32];
    uint8_t author_binding_root[32];
    uint8_t upstream_source_root[32];
    uint8_t upstream_author_root[32];
    uint8_t license_root[32];
    uint8_t assignment_evidence_root[32];
    uint8_t signer_pubkey[32];
    uint8_t signature[64];
};

struct vcs_zcode_c23_corpus_rules_v1 {
    uint16_t schema_version;
    uint16_t flags;
    uint16_t extension_mask;
    uint16_t overlap_threshold_bps;
    uint16_t shard_entry_max;
    uint16_t checkpoint_shard_max;
    uint16_t page_max;
    uint16_t publication_batch_max;
    uint8_t durable_ack_count;
    uint8_t durable_operator_group_count;
    uint16_t reserved;
    uint64_t max_file_bytes;
    uint64_t first_milestone_loc;
    uint64_t second_milestone_loc;
    uint64_t required_evidence_mask;
    uint8_t syntax_profile_root[32];
    uint8_t semantic_unitizer_root[32];
    uint8_t permissive_license_policy_root[32];
};

struct vcs_zcode_c23_corpus_entry_v1 {
    uint8_t semantic_lineage_root[32];
    uint8_t release_root[32];
    uint8_t passport_root[32];
    uint8_t proof_root[32];
    uint8_t source_assignment_root[32];
    uint8_t admission_root[32];
    uint8_t possession_root[32];
    uint64_t release_sequence;
    uint64_t production_loc;
    uint64_t test_loc;
    uint64_t physical_lines;
    uint64_t unique_semantic_units;
    uint64_t evidence_mask;
    uint32_t exclusion_mask;
    uint32_t flags;
};

struct vcs_zcode_c23_corpus_shard_v1 {
    uint16_t schema_version;
    uint16_t flags;
    uint8_t rules_root[32];
    uint8_t family_policy_root[32];
    uint8_t moderation_set_root[32];
    const struct vcs_zcode_c23_corpus_entry_v1 *entries;
    size_t entry_count;
};

struct vcs_zcode_c23_checkpoint_shard_v1 {
    uint8_t shard_root[32];
    uint8_t first_lineage_root[32];
    uint8_t last_lineage_root[32];
    uint64_t entry_count;
    uint64_t production_loc;
    uint64_t test_loc;
    uint64_t durable_loc;
    uint64_t physical_lines;
    uint64_t unique_semantic_units;
};

struct vcs_zcode_c23_corpus_checkpoint_v1 {
    uint16_t schema_version;
    uint16_t flags;
    uint16_t milestone;
    uint16_t reserved;
    uint64_t sequence;
    uint8_t predecessor_checkpoint_root[32];
    uint8_t verified_50m_ancestor_root[32];
    uint8_t rules_root[32];
    uint8_t family_policy_root[32];
    uint8_t moderation_set_root[32];
    uint8_t replication_evidence_root[32];
    uint64_t cutoff_height;
    int64_t cutoff_mtp;
    uint64_t total_entries;
    uint64_t production_loc;
    uint64_t test_loc;
    uint64_t durable_loc;
    uint64_t physical_lines;
    uint64_t unique_semantic_units;
    uint64_t excluded_entries;
    const struct vcs_zcode_c23_checkpoint_shard_v1 *shards;
    size_t shard_count;
    uint8_t signer_pubkey[32];
    uint8_t signature[64];
};

struct vcs_zcode_c23_page_cursor_v1 {
    uint8_t shard_root[32];
    uint16_t next_index;
};

enum vcs_zcode_productivity_evidence_v1 {
    VCS_ZCODE_PRODUCTIVITY_PROVEN_WORK = 1u << 0,
    VCS_ZCODE_PRODUCTIVITY_HUMAN_ACCEPTED = 1u << 1,
    VCS_ZCODE_PRODUCTIVITY_SIGNED_RELEASE = 1u << 2,
    VCS_ZCODE_PRODUCTIVITY_FAMILY_ADMITTED = 1u << 3,
    VCS_ZCODE_PRODUCTIVITY_PACKAGE_RETRIEVABLE = 1u << 4,
};

#define VCS_ZCODE_PRODUCTIVITY_REQUIRED_MASK UINT32_C(0x0000001f)

struct vcs_zcode_productivity_receipt_v1 {
    uint16_t schema_version;
    uint16_t flags;
    uint32_t evidence_mask;
    uint32_t reserved;
    uint64_t completed_height;
    int64_t completed_mtp;
    uint8_t work_root[32];
    uint8_t acceptance_root[32];
    uint8_t release_root[32];
    uint8_t admission_root[32];
    uint8_t package_root[32];
    uint8_t checkpoint_root[32];
    uint8_t signer_pubkey[32];
    uint8_t signature[64];
};

typedef bool (*vcs_zcode_productivity_proof_fn)(
    void *ctx, const struct vcs_zcode_productivity_receipt_v1 *receipt);

struct vcs_zcode_productivity_verify_context_v1 {
    uint64_t current_height;
    int64_t current_mtp;
    vcs_zcode_productivity_proof_fn prove_chain;
    void *prove_chain_ctx;
};

const char *vcs_zcode_c23_error_string(enum vcs_zcode_c23_error error);

bool vcs_zcode_source_kind_counts_v1(uint16_t source_kind);
enum vcs_zcode_c23_error vcs_zcode_source_assignment_v1_validate(
    const struct vcs_zcode_source_assignment_v1 *assignment);
enum vcs_zcode_c23_error vcs_zcode_source_assignment_v1_sign(
    struct vcs_zcode_source_assignment_v1 *assignment,
    const uint8_t signer_seed[32]);
enum vcs_zcode_c23_error vcs_zcode_source_assignment_v1_encode(
    const struct vcs_zcode_source_assignment_v1 *assignment,
    uint8_t *wire, size_t wire_capacity, size_t *wire_len);
enum vcs_zcode_c23_error vcs_zcode_source_assignment_v1_decode(
    struct vcs_zcode_source_assignment_v1 *out,
    const uint8_t *wire, size_t wire_len);
enum vcs_zcode_c23_error vcs_zcode_source_assignment_v1_root(
    const struct vcs_zcode_source_assignment_v1 *assignment,
    uint8_t out[32]);

void vcs_zcode_c23_corpus_rules_v1_default(
    struct vcs_zcode_c23_corpus_rules_v1 *rules);
enum vcs_zcode_c23_error vcs_zcode_c23_corpus_rules_v1_validate(
    const struct vcs_zcode_c23_corpus_rules_v1 *rules);
enum vcs_zcode_c23_error vcs_zcode_c23_corpus_rules_v1_encode(
    const struct vcs_zcode_c23_corpus_rules_v1 *rules,
    uint8_t *wire, size_t wire_capacity, size_t *wire_len);
enum vcs_zcode_c23_error vcs_zcode_c23_corpus_rules_v1_decode(
    struct vcs_zcode_c23_corpus_rules_v1 *out,
    const uint8_t *wire, size_t wire_len);
enum vcs_zcode_c23_error vcs_zcode_c23_corpus_rules_v1_root(
    const struct vcs_zcode_c23_corpus_rules_v1 *rules, uint8_t out[32]);

size_t vcs_zcode_c23_corpus_shard_v1_wire_size(size_t entry_count);
enum vcs_zcode_c23_error vcs_zcode_c23_corpus_shard_v1_validate(
    const struct vcs_zcode_c23_corpus_shard_v1 *shard);
enum vcs_zcode_c23_error vcs_zcode_c23_corpus_shard_v1_encode(
    const struct vcs_zcode_c23_corpus_shard_v1 *shard,
    uint8_t *wire, size_t wire_capacity, size_t *wire_len);
enum vcs_zcode_c23_error vcs_zcode_c23_corpus_shard_v1_decode(
    struct vcs_zcode_c23_corpus_shard_v1 *out,
    struct vcs_zcode_c23_corpus_entry_v1 *entries, size_t entry_capacity,
    const uint8_t *wire, size_t wire_len);
enum vcs_zcode_c23_error vcs_zcode_c23_corpus_shard_v1_root(
    const struct vcs_zcode_c23_corpus_shard_v1 *shard, uint8_t out[32]);
enum vcs_zcode_c23_error vcs_zcode_c23_corpus_shard_v1_page(
    const struct vcs_zcode_c23_corpus_shard_v1 *shard,
    const struct vcs_zcode_c23_page_cursor_v1 *cursor, size_t page_size,
    size_t *first_index, size_t *item_count,
    struct vcs_zcode_c23_page_cursor_v1 *next_cursor, bool *has_more);

size_t vcs_zcode_c23_corpus_checkpoint_v1_wire_size(size_t shard_count);
enum vcs_zcode_c23_error vcs_zcode_c23_corpus_checkpoint_v1_validate(
    const struct vcs_zcode_c23_corpus_checkpoint_v1 *checkpoint);
enum vcs_zcode_c23_error vcs_zcode_c23_corpus_checkpoint_v1_sign(
    struct vcs_zcode_c23_corpus_checkpoint_v1 *checkpoint,
    const uint8_t signer_seed[32]);
enum vcs_zcode_c23_error vcs_zcode_c23_corpus_checkpoint_v1_encode(
    const struct vcs_zcode_c23_corpus_checkpoint_v1 *checkpoint,
    uint8_t *wire, size_t wire_capacity, size_t *wire_len);
enum vcs_zcode_c23_error vcs_zcode_c23_corpus_checkpoint_v1_decode(
    struct vcs_zcode_c23_corpus_checkpoint_v1 *out,
    struct vcs_zcode_c23_checkpoint_shard_v1 *shards,
    size_t shard_capacity, const uint8_t *wire, size_t wire_len);
enum vcs_zcode_c23_error vcs_zcode_c23_corpus_checkpoint_v1_root(
    const struct vcs_zcode_c23_corpus_checkpoint_v1 *checkpoint,
    uint8_t out[32]);
enum vcs_zcode_c23_error vcs_zcode_c23_corpus_checkpoint_v1_verify_successor(
    const struct vcs_zcode_c23_corpus_checkpoint_v1 *prior,
    const struct vcs_zcode_c23_corpus_checkpoint_v1 *next);

enum vcs_zcode_c23_error vcs_zcode_productivity_receipt_v1_validate(
    const struct vcs_zcode_productivity_receipt_v1 *receipt);
enum vcs_zcode_c23_error vcs_zcode_productivity_receipt_v1_sign(
    struct vcs_zcode_productivity_receipt_v1 *receipt,
    const uint8_t signer_seed[32]);
enum vcs_zcode_c23_error vcs_zcode_productivity_receipt_v1_encode(
    const struct vcs_zcode_productivity_receipt_v1 *receipt,
    uint8_t *wire, size_t wire_capacity, size_t *wire_len);
enum vcs_zcode_c23_error vcs_zcode_productivity_receipt_v1_decode(
    struct vcs_zcode_productivity_receipt_v1 *out,
    const uint8_t *wire, size_t wire_len);
enum vcs_zcode_c23_error vcs_zcode_productivity_receipt_v1_root(
    const struct vcs_zcode_productivity_receipt_v1 *receipt,
    uint8_t out[32]);
bool vcs_zcode_productivity_receipt_v1_shareable(
    const struct vcs_zcode_productivity_receipt_v1 *receipt,
    const struct vcs_zcode_productivity_verify_context_v1 *verify);

#endif /* ZCL_VCS_ZCODE_C23_CORPUS_H */
