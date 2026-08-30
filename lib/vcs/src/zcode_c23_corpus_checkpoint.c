/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: signed, paged lower-bound checkpoints over verified C23 shards. */

#include "vcs/zcode_c23_corpus.h"

#include "base/bytes.h"
#include "base/checked.h"
#include "base/cleanse.h"
#include "base/serialize_le.h"
#include "crypto/ed25519.h"
#include "crypto/sha3.h"

#include <string.h>

static const uint8_t checkpoint_magic[8] = {'Z','C','C','P','1',0,0,0};
static const char checkpoint_signature_domain[] =
    "zcl.zcode.c23_corpus_checkpoint.signature.v1";

static bool zero_root(const uint8_t root[32])
{
    return !zcl_bytes_any_set(root, 32);
}

size_t vcs_zcode_c23_corpus_checkpoint_v1_wire_size(size_t shard_count)
{
    if (shard_count > VCS_ZCODE_C23_CHECKPOINT_SHARD_MAX) return 0;
    return VCS_ZCODE_C23_CHECKPOINT_HEADER_WIRE_BYTES +
           shard_count * VCS_ZCODE_C23_CHECKPOINT_BINDING_WIRE_BYTES;
}

static bool add_to(uint64_t *sum, uint64_t value)
{
    return zcl_u64_add(*sum, value, sum);
}

static enum vcs_zcode_c23_error checkpoint_shape(
    const struct vcs_zcode_c23_corpus_checkpoint_v1 *checkpoint,
    bool require_signature)
{
    if (!checkpoint) return VCS_ZCODE_C23_NULL;
    if (checkpoint->schema_version != 1) return VCS_ZCODE_C23_VERSION;
    if (checkpoint->flags != VCS_ZCODE_C23_CORPUS_REQUIRED_FLAGS)
        return VCS_ZCODE_C23_FLAGS;
    if (checkpoint->milestone > VCS_ZCODE_C23_MILESTONE_100M ||
        checkpoint->reserved != 0)
        return VCS_ZCODE_C23_ENUM;
    if (!checkpoint->sequence || !checkpoint->cutoff_height ||
        checkpoint->cutoff_mtp <= 0)
        return VCS_ZCODE_C23_TIME;
    if ((checkpoint->sequence == 1 &&
         !zero_root(checkpoint->predecessor_checkpoint_root)) ||
        (checkpoint->sequence > 1 &&
         zero_root(checkpoint->predecessor_checkpoint_root)))
        return VCS_ZCODE_C23_ANCESTRY;
    const uint8_t *roots[] = {
        checkpoint->rules_root, checkpoint->family_policy_root,
        checkpoint->moderation_set_root,
        checkpoint->replication_evidence_root, checkpoint->signer_pubkey,
    };
    for (size_t i = 0; i < sizeof(roots) / sizeof(roots[0]); i++)
        if (!zcl_bytes_any_set(roots[i], 32)) return VCS_ZCODE_C23_ROOT;
    if (!checkpoint->shards || checkpoint->shard_count == 0 ||
        checkpoint->shard_count > VCS_ZCODE_C23_CHECKPOINT_SHARD_MAX)
        return VCS_ZCODE_C23_SIZE;
    uint64_t entries = 0, production = 0, tests = 0, durable = 0;
    uint64_t physical = 0, unique = 0;
    for (size_t i = 0; i < checkpoint->shard_count; i++) {
        const struct vcs_zcode_c23_checkpoint_shard_v1 *binding =
            &checkpoint->shards[i];
        if (!zcl_bytes_any_set(binding->shard_root, 32) ||
            !zcl_bytes_any_set(binding->first_lineage_root, 32) ||
            !zcl_bytes_any_set(binding->last_lineage_root, 32) ||
            memcmp(binding->first_lineage_root,
                   binding->last_lineage_root, 32) > 0 ||
            binding->entry_count == 0)
            return VCS_ZCODE_C23_ROOT;
        if (i > 0 && memcmp(checkpoint->shards[i - 1u].last_lineage_root,
                            binding->first_lineage_root, 32) >= 0)
            return VCS_ZCODE_C23_ORDER;
        uint64_t total = 0;
        if (!zcl_u64_add(binding->production_loc, binding->test_loc,
                         &total) || binding->durable_loc > total ||
            !add_to(&entries, binding->entry_count) ||
            !add_to(&production, binding->production_loc) ||
            !add_to(&tests, binding->test_loc) ||
            !add_to(&durable, binding->durable_loc) ||
            !add_to(&physical, binding->physical_lines) ||
            !add_to(&unique, binding->unique_semantic_units))
            return VCS_ZCODE_C23_OVERFLOW;
    }
    if (entries != checkpoint->total_entries ||
        production != checkpoint->production_loc ||
        tests != checkpoint->test_loc || durable != checkpoint->durable_loc ||
        physical != checkpoint->physical_lines ||
        unique != checkpoint->unique_semantic_units ||
        checkpoint->excluded_entries > checkpoint->total_entries)
        return VCS_ZCODE_C23_POLICY;
    uint64_t total_loc = 0;
    if (!zcl_u64_add(production, tests, &total_loc))
        return VCS_ZCODE_C23_OVERFLOW;
    if (checkpoint->milestone == VCS_ZCODE_C23_MILESTONE_50M) {
        if (total_loc < VCS_ZCODE_C23_FIRST_MILESTONE_LOC ||
            durable < VCS_ZCODE_C23_FIRST_MILESTONE_LOC ||
            !zero_root(checkpoint->verified_50m_ancestor_root))
            return VCS_ZCODE_C23_POLICY;
    } else if (checkpoint->milestone == VCS_ZCODE_C23_MILESTONE_100M) {
        if (total_loc < VCS_ZCODE_C23_SECOND_MILESTONE_LOC ||
            durable < VCS_ZCODE_C23_SECOND_MILESTONE_LOC ||
            zero_root(checkpoint->verified_50m_ancestor_root))
            return VCS_ZCODE_C23_POLICY;
    } else if (!zero_root(checkpoint->verified_50m_ancestor_root) &&
               total_loc < VCS_ZCODE_C23_FIRST_MILESTONE_LOC) {
        return VCS_ZCODE_C23_POLICY;
    }
    if (require_signature && !zcl_bytes_any_set(checkpoint->signature, 64))
        return VCS_ZCODE_C23_SIGNATURE;
    return VCS_ZCODE_C23_OK;
}

static size_t checkpoint_header_write(
    const struct vcs_zcode_c23_corpus_checkpoint_v1 *checkpoint,
    uint8_t wire[324])
{
    size_t off = 0;
    memcpy(wire + off, checkpoint_magic, 8); off += 8;
    zcl_write_u16_le(wire + off, checkpoint->schema_version); off += 2;
    zcl_write_u16_le(wire + off, checkpoint->flags); off += 2;
    zcl_write_u16_le(wire + off, checkpoint->milestone); off += 2;
    zcl_write_u16_le(wire + off, checkpoint->reserved); off += 2;
    zcl_write_u64_le(wire + off, checkpoint->sequence); off += 8;
    memcpy(wire + off, checkpoint->predecessor_checkpoint_root, 32); off += 32;
    memcpy(wire + off, checkpoint->verified_50m_ancestor_root, 32); off += 32;
    memcpy(wire + off, checkpoint->rules_root, 32); off += 32;
    memcpy(wire + off, checkpoint->family_policy_root, 32); off += 32;
    memcpy(wire + off, checkpoint->moderation_set_root, 32); off += 32;
    memcpy(wire + off, checkpoint->replication_evidence_root, 32); off += 32;
    zcl_write_u64_le(wire + off, checkpoint->cutoff_height); off += 8;
    zcl_write_u64_le(wire + off, (uint64_t)checkpoint->cutoff_mtp); off += 8;
    zcl_write_u64_le(wire + off, checkpoint->total_entries); off += 8;
    zcl_write_u64_le(wire + off, checkpoint->production_loc); off += 8;
    zcl_write_u64_le(wire + off, checkpoint->test_loc); off += 8;
    zcl_write_u64_le(wire + off, checkpoint->durable_loc); off += 8;
    zcl_write_u64_le(wire + off, checkpoint->physical_lines); off += 8;
    zcl_write_u64_le(wire + off, checkpoint->unique_semantic_units); off += 8;
    zcl_write_u64_le(wire + off, checkpoint->excluded_entries); off += 8;
    zcl_write_u16_le(wire + off, (uint16_t)checkpoint->shard_count); off += 2;
    zcl_write_u16_le(wire + off, 0); off += 2;
    memcpy(wire + off, checkpoint->signer_pubkey, 32); off += 32;
    return off;
}

static size_t binding_write(
    const struct vcs_zcode_c23_checkpoint_shard_v1 *binding, uint8_t *wire)
{
    size_t off = 0;
    memcpy(wire + off, binding->shard_root, 32); off += 32;
    memcpy(wire + off, binding->first_lineage_root, 32); off += 32;
    memcpy(wire + off, binding->last_lineage_root, 32); off += 32;
    zcl_write_u64_le(wire + off, binding->entry_count); off += 8;
    zcl_write_u64_le(wire + off, binding->production_loc); off += 8;
    zcl_write_u64_le(wire + off, binding->test_loc); off += 8;
    zcl_write_u64_le(wire + off, binding->durable_loc); off += 8;
    zcl_write_u64_le(wire + off, binding->physical_lines); off += 8;
    zcl_write_u64_le(wire + off, binding->unique_semantic_units); off += 8;
    return off;
}

static enum vcs_zcode_c23_error checkpoint_signing_root(
    const struct vcs_zcode_c23_corpus_checkpoint_v1 *checkpoint,
    uint8_t out[32])
{
    enum vcs_zcode_c23_error error = checkpoint_shape(checkpoint, false);
    if (error != VCS_ZCODE_C23_OK) return error;
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)checkpoint_signature_domain,
                   sizeof(checkpoint_signature_domain) - 1u);
    uint8_t header[324];
    size_t header_len = checkpoint_header_write(checkpoint, header);
    sha3_256_write(&sha, header, header_len);
    uint8_t binding_wire[VCS_ZCODE_C23_CHECKPOINT_BINDING_WIRE_BYTES];
    for (size_t i = 0; i < checkpoint->shard_count; i++) {
        size_t n = binding_write(&checkpoint->shards[i], binding_wire);
        sha3_256_write(&sha, binding_wire, n);
    }
    sha3_256_finalize(&sha, out);
    return VCS_ZCODE_C23_OK;
}

enum vcs_zcode_c23_error vcs_zcode_c23_corpus_checkpoint_v1_validate(
    const struct vcs_zcode_c23_corpus_checkpoint_v1 *checkpoint)
{
    enum vcs_zcode_c23_error error = checkpoint_shape(checkpoint, true);
    if (error != VCS_ZCODE_C23_OK) return error;
    uint8_t signing_root[32];
    error = checkpoint_signing_root(checkpoint, signing_root);
    if (error != VCS_ZCODE_C23_OK) return error;
    bool valid = ed25519_verify(checkpoint->signature, signing_root,
                                sizeof(signing_root),
                                checkpoint->signer_pubkey);
    memory_cleanse(signing_root, sizeof(signing_root));
    return valid ? VCS_ZCODE_C23_OK : VCS_ZCODE_C23_SIGNATURE;
}

enum vcs_zcode_c23_error vcs_zcode_c23_corpus_checkpoint_v1_sign(
    struct vcs_zcode_c23_corpus_checkpoint_v1 *checkpoint,
    const uint8_t signer_seed[32])
{
    if (!checkpoint || !signer_seed) return VCS_ZCODE_C23_NULL;
    uint8_t secret[32], signing_root[32];
    ed25519_keypair(checkpoint->signer_pubkey, secret, signer_seed);
    memset(checkpoint->signature, 0, sizeof(checkpoint->signature));
    enum vcs_zcode_c23_error error =
        checkpoint_signing_root(checkpoint, signing_root);
    if (error == VCS_ZCODE_C23_OK)
        ed25519_sign(checkpoint->signature, signing_root,
                     sizeof(signing_root), secret,
                     checkpoint->signer_pubkey);
    memory_cleanse(secret, sizeof(secret));
    memory_cleanse(signing_root, sizeof(signing_root));
    return error == VCS_ZCODE_C23_OK
        ? vcs_zcode_c23_corpus_checkpoint_v1_validate(checkpoint) : error;
}

enum vcs_zcode_c23_error vcs_zcode_c23_corpus_checkpoint_v1_encode(
    const struct vcs_zcode_c23_corpus_checkpoint_v1 *checkpoint,
    uint8_t *wire, size_t wire_capacity, size_t *wire_len)
{
    if (wire_len) *wire_len = 0;
    if (!wire || !wire_len) return VCS_ZCODE_C23_NULL;
    enum vcs_zcode_c23_error error =
        vcs_zcode_c23_corpus_checkpoint_v1_validate(checkpoint);
    if (error != VCS_ZCODE_C23_OK) return error;
    size_t needed = vcs_zcode_c23_corpus_checkpoint_v1_wire_size(
        checkpoint->shard_count);
    if (!needed || wire_capacity < needed) return VCS_ZCODE_C23_SIZE;
    size_t off = checkpoint_header_write(checkpoint, wire);
    for (size_t i = 0; i < checkpoint->shard_count; i++)
        off += binding_write(&checkpoint->shards[i], wire + off);
    memcpy(wire + off, checkpoint->signature, 64); off += 64;
    *wire_len = off;
    return off == needed ? VCS_ZCODE_C23_OK : VCS_ZCODE_C23_SIZE;
}

static size_t binding_read(struct vcs_zcode_c23_checkpoint_shard_v1 *binding,
                           const uint8_t *wire)
{
    size_t off = 0;
    memcpy(binding->shard_root, wire + off, 32); off += 32;
    memcpy(binding->first_lineage_root, wire + off, 32); off += 32;
    memcpy(binding->last_lineage_root, wire + off, 32); off += 32;
    binding->entry_count = zcl_read_u64_le(wire + off); off += 8;
    binding->production_loc = zcl_read_u64_le(wire + off); off += 8;
    binding->test_loc = zcl_read_u64_le(wire + off); off += 8;
    binding->durable_loc = zcl_read_u64_le(wire + off); off += 8;
    binding->physical_lines = zcl_read_u64_le(wire + off); off += 8;
    binding->unique_semantic_units = zcl_read_u64_le(wire + off); off += 8;
    return off;
}

enum vcs_zcode_c23_error vcs_zcode_c23_corpus_checkpoint_v1_decode(
    struct vcs_zcode_c23_corpus_checkpoint_v1 *out,
    struct vcs_zcode_c23_checkpoint_shard_v1 *shards,
    size_t shard_capacity, const uint8_t *wire, size_t wire_len)
{
    if (!out || !shards || !wire) return VCS_ZCODE_C23_NULL;
    memset(out, 0, sizeof(*out));
    if (wire_len < VCS_ZCODE_C23_CHECKPOINT_HEADER_WIRE_BYTES ||
        memcmp(wire, checkpoint_magic, 8) != 0)
        return wire_len < VCS_ZCODE_C23_CHECKPOINT_HEADER_WIRE_BYTES
            ? VCS_ZCODE_C23_SIZE : VCS_ZCODE_C23_MAGIC;
    size_t off = 8;
    out->schema_version = zcl_read_u16_le(wire + off); off += 2;
    out->flags = zcl_read_u16_le(wire + off); off += 2;
    out->milestone = zcl_read_u16_le(wire + off); off += 2;
    out->reserved = zcl_read_u16_le(wire + off); off += 2;
    out->sequence = zcl_read_u64_le(wire + off); off += 8;
    memcpy(out->predecessor_checkpoint_root, wire + off, 32); off += 32;
    memcpy(out->verified_50m_ancestor_root, wire + off, 32); off += 32;
    memcpy(out->rules_root, wire + off, 32); off += 32;
    memcpy(out->family_policy_root, wire + off, 32); off += 32;
    memcpy(out->moderation_set_root, wire + off, 32); off += 32;
    memcpy(out->replication_evidence_root, wire + off, 32); off += 32;
    out->cutoff_height = zcl_read_u64_le(wire + off); off += 8;
    out->cutoff_mtp = (int64_t)zcl_read_u64_le(wire + off); off += 8;
    out->total_entries = zcl_read_u64_le(wire + off); off += 8;
    out->production_loc = zcl_read_u64_le(wire + off); off += 8;
    out->test_loc = zcl_read_u64_le(wire + off); off += 8;
    out->durable_loc = zcl_read_u64_le(wire + off); off += 8;
    out->physical_lines = zcl_read_u64_le(wire + off); off += 8;
    out->unique_semantic_units = zcl_read_u64_le(wire + off); off += 8;
    out->excluded_entries = zcl_read_u64_le(wire + off); off += 8;
    size_t count = zcl_read_u16_le(wire + off); off += 2;
    uint16_t reserved = zcl_read_u16_le(wire + off); off += 2;
    memcpy(out->signer_pubkey, wire + off, 32); off += 32;
    size_t needed = vcs_zcode_c23_corpus_checkpoint_v1_wire_size(count);
    if (reserved || !count || count > shard_capacity ||
        !needed || needed != wire_len) {
        memset(out, 0, sizeof(*out));
        return reserved ? VCS_ZCODE_C23_ENUM : VCS_ZCODE_C23_SIZE;
    }
    memset(shards, 0, count * sizeof(*shards));
    for (size_t i = 0; i < count; i++)
        off += binding_read(&shards[i], wire + off);
    memcpy(out->signature, wire + off, 64); off += 64;
    out->shards = shards;
    out->shard_count = count;
    enum vcs_zcode_c23_error error = off == wire_len
        ? vcs_zcode_c23_corpus_checkpoint_v1_validate(out)
        : VCS_ZCODE_C23_SIZE;
    if (error != VCS_ZCODE_C23_OK) memset(out, 0, sizeof(*out));
    return error;
}

enum vcs_zcode_c23_error vcs_zcode_c23_corpus_checkpoint_v1_root(
    const struct vcs_zcode_c23_corpus_checkpoint_v1 *checkpoint,
    uint8_t out[32])
{
    if (out) memset(out, 0, 32);
    if (!checkpoint || !out) return VCS_ZCODE_C23_NULL;
    enum vcs_zcode_c23_error error =
        vcs_zcode_c23_corpus_checkpoint_v1_validate(checkpoint);
    if (error != VCS_ZCODE_C23_OK) return error;
    struct sha3_256_ctx sha;
    static const char domain[] = VCS_ZCODE_C23_CORPUS_CHECKPOINT_V1_DOMAIN;
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)domain, sizeof(domain));
    uint8_t header[324];
    size_t header_len = checkpoint_header_write(checkpoint, header);
    sha3_256_write(&sha, header, header_len);
    uint8_t binding_wire[VCS_ZCODE_C23_CHECKPOINT_BINDING_WIRE_BYTES];
    for (size_t i = 0; i < checkpoint->shard_count; i++) {
        size_t n = binding_write(&checkpoint->shards[i], binding_wire);
        sha3_256_write(&sha, binding_wire, n);
    }
    sha3_256_write(&sha, checkpoint->signature, 64);
    sha3_256_finalize(&sha, out);
    return VCS_ZCODE_C23_OK;
}

enum vcs_zcode_c23_error vcs_zcode_c23_corpus_checkpoint_v1_verify_successor(
    const struct vcs_zcode_c23_corpus_checkpoint_v1 *prior,
    const struct vcs_zcode_c23_corpus_checkpoint_v1 *next)
{
    enum vcs_zcode_c23_error error =
        vcs_zcode_c23_corpus_checkpoint_v1_validate(prior);
    if (error != VCS_ZCODE_C23_OK) return error;
    error = vcs_zcode_c23_corpus_checkpoint_v1_validate(next);
    if (error != VCS_ZCODE_C23_OK) return error;
    if (prior->sequence == UINT64_MAX) return VCS_ZCODE_C23_OVERFLOW;
    uint8_t prior_root[32];
    error = vcs_zcode_c23_corpus_checkpoint_v1_root(prior, prior_root);
    if (error != VCS_ZCODE_C23_OK) return error;
    if (next->sequence != prior->sequence + 1u ||
        memcmp(next->predecessor_checkpoint_root, prior_root, 32) != 0 ||
        next->cutoff_height < prior->cutoff_height ||
        next->cutoff_mtp < prior->cutoff_mtp ||
        memcmp(next->rules_root, prior->rules_root, 32) != 0 ||
        memcmp(next->family_policy_root, prior->family_policy_root, 32) != 0)
        return VCS_ZCODE_C23_ANCESTRY;
    uint8_t expected_50m[32] = {0};
    if (prior->milestone == VCS_ZCODE_C23_MILESTONE_50M)
        memcpy(expected_50m, prior_root, 32);
    else if (zcl_bytes_any_set(prior->verified_50m_ancestor_root, 32))
        memcpy(expected_50m, prior->verified_50m_ancestor_root, 32);
    if (memcmp(next->verified_50m_ancestor_root, expected_50m, 32) != 0)
        return VCS_ZCODE_C23_ANCESTRY;
    if (next->milestone == VCS_ZCODE_C23_MILESTONE_100M &&
        !zcl_bytes_any_set(expected_50m, 32))
        return VCS_ZCODE_C23_ANCESTRY;
    return VCS_ZCODE_C23_OK;
}
