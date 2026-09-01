/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: canonical simulation-only C23 corpus census objects. */

#include "vcs/zcode_c23_corpus.h"

#include "base/bytes.h"
#include "base/cleanse.h"
#include "base/serialize_le.h"
#include "crypto/ed25519.h"
#include "crypto/sha3.h"
#include "vcs/signed_evidence.h"

#include <string.h>

static const uint8_t assignment_magic[8] = {'Z','C','S','A','1',0,0,0};
static const uint8_t rules_magic[8] = {'Z','C','C','R','1',0,0,0};
static const char assignment_signature_domain[] =
    "zcl.zcode.source_assignment.signature.v1";

const char *vcs_zcode_c23_error_string(enum vcs_zcode_c23_error error)
{
    switch (error) {
    case VCS_ZCODE_C23_OK: return "ok";
    case VCS_ZCODE_C23_NULL: return "null-argument";
    case VCS_ZCODE_C23_SIZE: return "wire-size";
    case VCS_ZCODE_C23_MAGIC: return "wire-magic";
    case VCS_ZCODE_C23_VERSION: return "schema-version";
    case VCS_ZCODE_C23_FLAGS: return "flags";
    case VCS_ZCODE_C23_ENUM: return "closed-enum";
    case VCS_ZCODE_C23_ROOT: return "root";
    case VCS_ZCODE_C23_ORDER: return "canonical-order";
    case VCS_ZCODE_C23_POLICY: return "census-policy";
    case VCS_ZCODE_C23_TIME: return "chain-time";
    case VCS_ZCODE_C23_SIGNATURE: return "signature";
    case VCS_ZCODE_C23_OVERFLOW: return "arithmetic-overflow";
    case VCS_ZCODE_C23_CURSOR: return "root-cursor";
    case VCS_ZCODE_C23_ANCESTRY: return "checkpoint-ancestry";
    case VCS_ZCODE_C23_PROOF: return "external-proof";
    }
    return "unknown-c23-corpus-error";
}

bool vcs_zcode_source_kind_counts_v1(uint16_t source_kind)
{
    return source_kind == VCS_ZCODE_SOURCE_HUMAN_AUTHORED ||
           source_kind == VCS_ZCODE_SOURCE_AI_AUTHORED ||
           source_kind == VCS_ZCODE_SOURCE_CANONICAL_IMPORT;
}

static enum vcs_zcode_c23_error assignment_shape(
    const struct vcs_zcode_source_assignment_v1 *assignment,
    bool require_signature)
{
    if (!assignment) return VCS_ZCODE_C23_NULL;
    if (assignment->schema_version != 1) return VCS_ZCODE_C23_VERSION;
    if (assignment->flags != VCS_ZCODE_C23_CORPUS_REQUIRED_FLAGS)
        return VCS_ZCODE_C23_FLAGS;
    if (assignment->source_kind < VCS_ZCODE_SOURCE_HUMAN_AUTHORED ||
        assignment->source_kind > VCS_ZCODE_SOURCE_VENDOR_MATERIAL ||
        assignment->reserved != 0)
        return VCS_ZCODE_C23_ENUM;
    if (!assignment->sequence || !assignment->assigned_height ||
        assignment->assigned_mtp <= 0)
        return VCS_ZCODE_C23_TIME;
    if (!zcl_bytes_any_set(assignment->source_root, 32) ||
        !zcl_bytes_any_set(assignment->author_binding_root, 32) ||
        !zcl_bytes_any_set(assignment->license_root, 32) ||
        !zcl_bytes_any_set(assignment->assignment_evidence_root, 32) ||
        !zcl_bytes_any_set(assignment->signer_pubkey, 32))
        return VCS_ZCODE_C23_ROOT;
    bool has_upstream_source =
        zcl_bytes_any_set(assignment->upstream_source_root, 32);
    bool has_upstream_author =
        zcl_bytes_any_set(assignment->upstream_author_root, 32);
    if (assignment->source_kind == VCS_ZCODE_SOURCE_CANONICAL_IMPORT ||
        assignment->source_kind == VCS_ZCODE_SOURCE_VENDOR_MATERIAL) {
        if (!has_upstream_source || !has_upstream_author)
            return VCS_ZCODE_C23_POLICY;
    } else if (assignment->source_kind ==
               VCS_ZCODE_SOURCE_MECHANICAL_GENERATION) {
        if (!has_upstream_source || has_upstream_author)
            return VCS_ZCODE_C23_POLICY;
    } else if (has_upstream_source || has_upstream_author) {
        return VCS_ZCODE_C23_POLICY;
    }
    if (require_signature && !zcl_bytes_any_set(assignment->signature, 64))
        return VCS_ZCODE_C23_SIGNATURE;
    return VCS_ZCODE_C23_OK;
}

static size_t assignment_write_unsigned(
    const struct vcs_zcode_source_assignment_v1 *assignment, uint8_t *wire)
{
    size_t off = 0;
    memcpy(wire + off, assignment_magic, sizeof(assignment_magic));
    off += sizeof(assignment_magic);
    zcl_write_u16_le(wire + off, assignment->schema_version); off += 2;
    zcl_write_u16_le(wire + off, assignment->flags); off += 2;
    zcl_write_u16_le(wire + off, assignment->source_kind); off += 2;
    zcl_write_u16_le(wire + off, assignment->reserved); off += 2;
    zcl_write_u64_le(wire + off, assignment->sequence); off += 8;
    zcl_write_u64_le(wire + off, assignment->assigned_height); off += 8;
    zcl_write_u64_le(wire + off, (uint64_t)assignment->assigned_mtp); off += 8;
    memcpy(wire + off, assignment->source_root, 32u * 7u);
    off += 32u * 7u;
    return off;
}

static bool assignment_signature_valid(
    const struct vcs_zcode_source_assignment_v1 *assignment)
{
    uint8_t wire[VCS_ZCODE_SOURCE_ASSIGNMENT_WIRE_BYTES];
    uint8_t preimage[sizeof(assignment_signature_domain) - 1u +
                     VCS_ZCODE_SOURCE_ASSIGNMENT_WIRE_BYTES];
    size_t unsigned_len = assignment_write_unsigned(assignment, wire);
    size_t domain_len = sizeof(assignment_signature_domain) - 1u;
    memcpy(preimage, assignment_signature_domain, domain_len);
    memcpy(preimage + domain_len, wire, unsigned_len);
    bool ok = ed25519_verify(assignment->signature, preimage,
                             domain_len + unsigned_len,
                             assignment->signer_pubkey);
    memory_cleanse(preimage, sizeof(preimage));
    memory_cleanse(wire, sizeof(wire));
    return ok;
}

enum vcs_zcode_c23_error vcs_zcode_source_assignment_v1_validate(
    const struct vcs_zcode_source_assignment_v1 *assignment)
{
    enum vcs_zcode_c23_error error = assignment_shape(assignment, true);
    if (error != VCS_ZCODE_C23_OK) return error;
    return assignment_signature_valid(assignment)
        ? VCS_ZCODE_C23_OK : VCS_ZCODE_C23_SIGNATURE;
}

enum vcs_zcode_c23_error vcs_zcode_source_assignment_v1_sign(
    struct vcs_zcode_source_assignment_v1 *assignment,
    const uint8_t signer_seed[32])
{
    if (!assignment || !signer_seed) return VCS_ZCODE_C23_NULL;
    uint8_t secret[32];
    ed25519_keypair(assignment->signer_pubkey, secret, signer_seed);
    memset(assignment->signature, 0, sizeof(assignment->signature));
    enum vcs_zcode_c23_error error = assignment_shape(assignment, false);
    if (error != VCS_ZCODE_C23_OK) {
        memory_cleanse(secret, sizeof(secret));
        return error;
    }
    uint8_t wire[VCS_ZCODE_SOURCE_ASSIGNMENT_WIRE_BYTES];
    uint8_t preimage[sizeof(assignment_signature_domain) - 1u +
                     VCS_ZCODE_SOURCE_ASSIGNMENT_WIRE_BYTES];
    size_t unsigned_len = assignment_write_unsigned(assignment, wire);
    size_t domain_len = sizeof(assignment_signature_domain) - 1u;
    memcpy(preimage, assignment_signature_domain, domain_len);
    memcpy(preimage + domain_len, wire, unsigned_len);
    ed25519_sign(assignment->signature, preimage, domain_len + unsigned_len,
                 secret, assignment->signer_pubkey);
    memory_cleanse(secret, sizeof(secret));
    memory_cleanse(preimage, sizeof(preimage));
    memory_cleanse(wire, sizeof(wire));
    return vcs_zcode_source_assignment_v1_validate(assignment);
}

enum vcs_zcode_c23_error vcs_zcode_source_assignment_v1_encode(
    const struct vcs_zcode_source_assignment_v1 *assignment,
    uint8_t *wire, size_t wire_capacity, size_t *wire_len)
{
    if (wire_len) *wire_len = 0;
    if (!wire || !wire_len) return VCS_ZCODE_C23_NULL;
    enum vcs_zcode_c23_error error =
        vcs_zcode_source_assignment_v1_validate(assignment);
    if (error != VCS_ZCODE_C23_OK) return error;
    if (wire_capacity < VCS_ZCODE_SOURCE_ASSIGNMENT_WIRE_BYTES)
        return VCS_ZCODE_C23_SIZE;
    size_t off = assignment_write_unsigned(assignment, wire);
    memcpy(wire + off, assignment->signature, 64); off += 64;
    *wire_len = off;
    return off == VCS_ZCODE_SOURCE_ASSIGNMENT_WIRE_BYTES
        ? VCS_ZCODE_C23_OK : VCS_ZCODE_C23_SIZE;
}

enum vcs_zcode_c23_error vcs_zcode_source_assignment_v1_decode(
    struct vcs_zcode_source_assignment_v1 *out,
    const uint8_t *wire, size_t wire_len)
{
    if (!out || !wire) return VCS_ZCODE_C23_NULL;
    memset(out, 0, sizeof(*out));
    if (wire_len != VCS_ZCODE_SOURCE_ASSIGNMENT_WIRE_BYTES)
        return VCS_ZCODE_C23_SIZE;
    if (memcmp(wire, assignment_magic, sizeof(assignment_magic)) != 0)
        return VCS_ZCODE_C23_MAGIC;
    size_t off = sizeof(assignment_magic);
    out->schema_version = zcl_read_u16_le(wire + off); off += 2;
    out->flags = zcl_read_u16_le(wire + off); off += 2;
    out->source_kind = zcl_read_u16_le(wire + off); off += 2;
    out->reserved = zcl_read_u16_le(wire + off); off += 2;
    out->sequence = zcl_read_u64_le(wire + off); off += 8;
    out->assigned_height = zcl_read_u64_le(wire + off); off += 8;
    out->assigned_mtp = (int64_t)zcl_read_u64_le(wire + off); off += 8;
    memcpy(out->source_root, wire + off, 32u * 7u); off += 32u * 7u;
    memcpy(out->signature, wire + off, 64); off += 64;
    enum vcs_zcode_c23_error error = off == wire_len
        ? vcs_zcode_source_assignment_v1_validate(out)
        : VCS_ZCODE_C23_SIZE;
    if (error != VCS_ZCODE_C23_OK) memset(out, 0, sizeof(*out));
    return error;
}

enum vcs_zcode_c23_error vcs_zcode_source_assignment_v1_root(
    const struct vcs_zcode_source_assignment_v1 *assignment,
    uint8_t out[32])
{
    if (out) memset(out, 0, 32);
    if (!assignment || !out) return VCS_ZCODE_C23_NULL;
    uint8_t wire[VCS_ZCODE_SOURCE_ASSIGNMENT_WIRE_BYTES];
    size_t wire_len = 0;
    enum vcs_zcode_c23_error error = vcs_zcode_source_assignment_v1_encode(
        assignment, wire, sizeof(wire), &wire_len);
    if (error != VCS_ZCODE_C23_OK) return error;
    return vcs_signed_evidence_root(VCS_ZCODE_SOURCE_ASSIGNMENT_V1_DOMAIN,
                                    strlen(VCS_ZCODE_SOURCE_ASSIGNMENT_V1_DOMAIN) + 1u,
                                    wire, wire_len, out)
               ? VCS_ZCODE_C23_OK : VCS_ZCODE_C23_NULL;
}

static void literal_root(const char *literal, uint8_t out[32])
{
    sha3_256((const uint8_t *)literal, strlen(literal), out);
}

void vcs_zcode_c23_corpus_rules_v1_default(
    struct vcs_zcode_c23_corpus_rules_v1 *rules)
{
    if (!rules) return;
    memset(rules, 0, sizeof(*rules));
    rules->schema_version = 1;
    rules->flags = VCS_ZCODE_C23_CORPUS_REQUIRED_FLAGS;
    rules->extension_mask = VCS_ZCODE_C23_EXTENSION_MASK;
    rules->overlap_threshold_bps = VCS_ZCODE_C23_OVERLAP_THRESHOLD_BPS;
    rules->shard_entry_max = VCS_ZCODE_C23_SHARD_ENTRY_MAX;
    rules->checkpoint_shard_max = VCS_ZCODE_C23_CHECKPOINT_SHARD_MAX;
    rules->page_max = VCS_ZCODE_C23_PAGE_MAX;
    rules->publication_batch_max = VCS_ZCODE_C23_PUBLICATION_BATCH_MAX;
    rules->durable_ack_count = VCS_ZCODE_C23_DURABLE_ACKS;
    rules->durable_operator_group_count =
        VCS_ZCODE_C23_DURABLE_OPERATOR_GROUPS;
    rules->max_file_bytes = VCS_ZCODE_C23_MAX_FILE_BYTES;
    rules->first_milestone_loc = VCS_ZCODE_C23_FIRST_MILESTONE_LOC;
    rules->second_milestone_loc = VCS_ZCODE_C23_SECOND_MILESTONE_LOC;
    rules->required_evidence_mask = VCS_ZCODE_C23_EVIDENCE_REQUIRED_MASK;
    literal_root("c23:production-and-test:.c,.h,.def:recipe-declared:v1",
                 rules->syntax_profile_root);
    literal_root("c23:strip-comments-blanks-brace-only:semantic-units:v1",
                 rules->semantic_unitizer_root);
    literal_root("c23:permissive-license-required:vendor-excluded:v1",
                 rules->permissive_license_policy_root);
}

enum vcs_zcode_c23_error vcs_zcode_c23_corpus_rules_v1_validate(
    const struct vcs_zcode_c23_corpus_rules_v1 *rules)
{
    if (!rules) return VCS_ZCODE_C23_NULL;
    if (rules->schema_version != 1) return VCS_ZCODE_C23_VERSION;
    if (rules->flags != VCS_ZCODE_C23_CORPUS_REQUIRED_FLAGS)
        return VCS_ZCODE_C23_FLAGS;
    if (rules->extension_mask != VCS_ZCODE_C23_EXTENSION_MASK ||
        rules->overlap_threshold_bps !=
            VCS_ZCODE_C23_OVERLAP_THRESHOLD_BPS ||
        rules->shard_entry_max != VCS_ZCODE_C23_SHARD_ENTRY_MAX ||
        rules->checkpoint_shard_max !=
            VCS_ZCODE_C23_CHECKPOINT_SHARD_MAX ||
        rules->page_max != VCS_ZCODE_C23_PAGE_MAX ||
        rules->publication_batch_max !=
            VCS_ZCODE_C23_PUBLICATION_BATCH_MAX ||
        rules->durable_ack_count != VCS_ZCODE_C23_DURABLE_ACKS ||
        rules->durable_operator_group_count !=
            VCS_ZCODE_C23_DURABLE_OPERATOR_GROUPS ||
        rules->reserved != 0 ||
        rules->max_file_bytes != VCS_ZCODE_C23_MAX_FILE_BYTES ||
        rules->first_milestone_loc !=
            VCS_ZCODE_C23_FIRST_MILESTONE_LOC ||
        rules->second_milestone_loc !=
            VCS_ZCODE_C23_SECOND_MILESTONE_LOC ||
        rules->required_evidence_mask !=
            VCS_ZCODE_C23_EVIDENCE_REQUIRED_MASK)
        return VCS_ZCODE_C23_POLICY;
    if (!zcl_bytes_any_set(rules->syntax_profile_root, 32) ||
        !zcl_bytes_any_set(rules->semantic_unitizer_root, 32) ||
        !zcl_bytes_any_set(rules->permissive_license_policy_root, 32))
        return VCS_ZCODE_C23_ROOT;
    struct vcs_zcode_c23_corpus_rules_v1 expected;
    vcs_zcode_c23_corpus_rules_v1_default(&expected);
    return memcmp(rules, &expected, sizeof(expected)) == 0
        ? VCS_ZCODE_C23_OK : VCS_ZCODE_C23_POLICY;
}

static size_t rules_write(const struct vcs_zcode_c23_corpus_rules_v1 *rules,
                          uint8_t wire[VCS_ZCODE_C23_CORPUS_RULES_WIRE_BYTES])
{
    size_t off = 0;
    memcpy(wire + off, rules_magic, sizeof(rules_magic)); off += 8;
    zcl_write_u16_le(wire + off, rules->schema_version); off += 2;
    zcl_write_u16_le(wire + off, rules->flags); off += 2;
    zcl_write_u16_le(wire + off, rules->extension_mask); off += 2;
    zcl_write_u16_le(wire + off, rules->overlap_threshold_bps); off += 2;
    zcl_write_u16_le(wire + off, rules->shard_entry_max); off += 2;
    zcl_write_u16_le(wire + off, rules->checkpoint_shard_max); off += 2;
    zcl_write_u16_le(wire + off, rules->page_max); off += 2;
    zcl_write_u16_le(wire + off, rules->publication_batch_max); off += 2;
    wire[off++] = rules->durable_ack_count;
    wire[off++] = rules->durable_operator_group_count;
    zcl_write_u16_le(wire + off, rules->reserved); off += 2;
    zcl_write_u64_le(wire + off, rules->max_file_bytes); off += 8;
    zcl_write_u64_le(wire + off, rules->first_milestone_loc); off += 8;
    zcl_write_u64_le(wire + off, rules->second_milestone_loc); off += 8;
    zcl_write_u64_le(wire + off, rules->required_evidence_mask); off += 8;
    memcpy(wire + off, rules->syntax_profile_root, 32u * 3u);
    off += 32u * 3u;
    return off;
}

enum vcs_zcode_c23_error vcs_zcode_c23_corpus_rules_v1_encode(
    const struct vcs_zcode_c23_corpus_rules_v1 *rules,
    uint8_t *wire, size_t wire_capacity, size_t *wire_len)
{
    if (wire_len) *wire_len = 0;
    if (!wire || !wire_len) return VCS_ZCODE_C23_NULL;
    enum vcs_zcode_c23_error error =
        vcs_zcode_c23_corpus_rules_v1_validate(rules);
    if (error != VCS_ZCODE_C23_OK) return error;
    if (wire_capacity < VCS_ZCODE_C23_CORPUS_RULES_WIRE_BYTES)
        return VCS_ZCODE_C23_SIZE;
    *wire_len = rules_write(rules, wire);
    return *wire_len == VCS_ZCODE_C23_CORPUS_RULES_WIRE_BYTES
        ? VCS_ZCODE_C23_OK : VCS_ZCODE_C23_SIZE;
}

enum vcs_zcode_c23_error vcs_zcode_c23_corpus_rules_v1_decode(
    struct vcs_zcode_c23_corpus_rules_v1 *out,
    const uint8_t *wire, size_t wire_len)
{
    if (!out || !wire) return VCS_ZCODE_C23_NULL;
    memset(out, 0, sizeof(*out));
    if (wire_len != VCS_ZCODE_C23_CORPUS_RULES_WIRE_BYTES)
        return VCS_ZCODE_C23_SIZE;
    if (memcmp(wire, rules_magic, sizeof(rules_magic)) != 0)
        return VCS_ZCODE_C23_MAGIC;
    size_t off = sizeof(rules_magic);
    out->schema_version = zcl_read_u16_le(wire + off); off += 2;
    out->flags = zcl_read_u16_le(wire + off); off += 2;
    out->extension_mask = zcl_read_u16_le(wire + off); off += 2;
    out->overlap_threshold_bps = zcl_read_u16_le(wire + off); off += 2;
    out->shard_entry_max = zcl_read_u16_le(wire + off); off += 2;
    out->checkpoint_shard_max = zcl_read_u16_le(wire + off); off += 2;
    out->page_max = zcl_read_u16_le(wire + off); off += 2;
    out->publication_batch_max = zcl_read_u16_le(wire + off); off += 2;
    out->durable_ack_count = wire[off++];
    out->durable_operator_group_count = wire[off++];
    out->reserved = zcl_read_u16_le(wire + off); off += 2;
    out->max_file_bytes = zcl_read_u64_le(wire + off); off += 8;
    out->first_milestone_loc = zcl_read_u64_le(wire + off); off += 8;
    out->second_milestone_loc = zcl_read_u64_le(wire + off); off += 8;
    out->required_evidence_mask = zcl_read_u64_le(wire + off); off += 8;
    memcpy(out->syntax_profile_root, wire + off, 32u * 3u);
    off += 32u * 3u;
    enum vcs_zcode_c23_error error = off == wire_len
        ? vcs_zcode_c23_corpus_rules_v1_validate(out)
        : VCS_ZCODE_C23_SIZE;
    if (error != VCS_ZCODE_C23_OK) memset(out, 0, sizeof(*out));
    return error;
}

enum vcs_zcode_c23_error vcs_zcode_c23_corpus_rules_v1_root(
    const struct vcs_zcode_c23_corpus_rules_v1 *rules, uint8_t out[32])
{
    if (out) memset(out, 0, 32);
    if (!rules || !out) return VCS_ZCODE_C23_NULL;
    uint8_t wire[VCS_ZCODE_C23_CORPUS_RULES_WIRE_BYTES];
    size_t wire_len = 0;
    enum vcs_zcode_c23_error error = vcs_zcode_c23_corpus_rules_v1_encode(
        rules, wire, sizeof(wire), &wire_len);
    if (error != VCS_ZCODE_C23_OK) return error;
    return vcs_signed_evidence_root(VCS_ZCODE_C23_CORPUS_RULES_V1_DOMAIN,
                                    strlen(VCS_ZCODE_C23_CORPUS_RULES_V1_DOMAIN) + 1u,
                                    wire, wire_len, out)
               ? VCS_ZCODE_C23_OK : VCS_ZCODE_C23_NULL;
}
