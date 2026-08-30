/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: encode and evaluate simulation-only ZC23 shadow policy. */

#include "vcs/zcode_shadow_policy.h"

#include "base/bytes.h"
#include "base/checked.h"
#include "codec/cursor.h"
#include "crypto/sha3.h"
#include "vcs/zcode_score_receipt.h"

#include <string.h>

static const uint8_t reproducer_magic[8] = {
    'Z', 'C', 'R', 'S', 'E', 'T', '\r', '\n'
};
static const uint8_t policy_magic[8] = {
    'Z', 'C', 'P', 'O', 'L', 'C', '\r', '\n'
};

static bool shadow_zero(const uint8_t bytes[32])
{
    return !zcl_bytes_any_set(bytes, 32);
}

const char *vcs_zcode_shadow_error_string(enum vcs_zcode_shadow_error error)
{
    switch (error) {
    case VCS_ZCODE_SHADOW_OK: return "ok";
    case VCS_ZCODE_SHADOW_NULL: return "null-argument";
    case VCS_ZCODE_SHADOW_WIRE_SIZE: return "wire-size";
    case VCS_ZCODE_SHADOW_MAGIC: return "wire-magic";
    case VCS_ZCODE_SHADOW_VERSION: return "schema-version";
    case VCS_ZCODE_SHADOW_FLAGS: return "simulation-flags";
    case VCS_ZCODE_SHADOW_RESERVED: return "reserved-bytes";
    case VCS_ZCODE_SHADOW_ROOT: return "root";
    case VCS_ZCODE_SHADOW_ORDER: return "entry-order";
    case VCS_ZCODE_SHADOW_DUPLICATE: return "duplicate-entry";
    case VCS_ZCODE_SHADOW_LIMIT: return "entry-limit";
    case VCS_ZCODE_SHADOW_TIME: return "time-window";
    case VCS_ZCODE_SHADOW_EPOCH: return "epoch-window";
    case VCS_ZCODE_SHADOW_ACTION: return "reproduction-action";
    case VCS_ZCODE_SHADOW_NOT_FOUND: return "signer-not-approved";
    case VCS_ZCODE_SHADOW_NETWORK: return "network-mismatch";
    case VCS_ZCODE_SHADOW_POLICY: return "policy-mismatch";
    case VCS_ZCODE_SHADOW_CATEGORY: return "creation-category";
    case VCS_ZCODE_SHADOW_AMOUNT: return "shadow-award";
    case VCS_ZCODE_SHADOW_OVERFLOW: return "arithmetic-overflow";
    }
    return "unknown-shadow-policy-error";
}

static enum vcs_zcode_shadow_error reproducer_entry_validate(
    const struct vcs_zcode_approved_reproducer_entry_v1 *entry)
{
    if (!entry) return VCS_ZCODE_SHADOW_NULL;
    if (!zcl_bytes_any_set(entry->signer_pubkey, 32) ||
        !zcl_bytes_any_set(entry->contributor_binding_root, 32) ||
        !zcl_bytes_any_set(entry->operator_group_root, 32))
        return VCS_ZCODE_SHADOW_ROOT;
    uint8_t expected[32];
    vcs_zcode_score_action_root(VCS_ZCODE_SCORE_INDEPENDENT_REPRODUCTION,
                                expected);
    if (memcmp(entry->action_root, expected, 32) != 0)
        return VCS_ZCODE_SHADOW_ACTION;
    if (entry->valid_through_epoch == 0 ||
        entry->valid_from_epoch > entry->valid_through_epoch)
        return VCS_ZCODE_SHADOW_TIME;
    if (entry->valid_from_unix <= 0 ||
        entry->valid_from_unix > entry->valid_through_unix)
        return VCS_ZCODE_SHADOW_TIME;
    return VCS_ZCODE_SHADOW_OK;
}

void vcs_zcode_approved_reproducer_set_init(
    struct vcs_zcode_approved_reproducer_set_v1 *set)
{
    if (!set) return;
    memset(set, 0, sizeof(*set));
    set->schema_version = VCS_ZCODE_SHADOW_POLICY_VERSION;
    set->flags = VCS_ZCODE_APPROVED_REPRODUCER_REQUIRED_FLAGS;
}

enum vcs_zcode_shadow_error vcs_zcode_approved_reproducer_set_add(
    struct vcs_zcode_approved_reproducer_set_v1 *set,
    const struct vcs_zcode_approved_reproducer_entry_v1 *entry)
{
    if (!set || !entry) return VCS_ZCODE_SHADOW_NULL;
    enum vcs_zcode_shadow_error err = reproducer_entry_validate(entry);
    if (err != VCS_ZCODE_SHADOW_OK) return err;
    if (set->entry_count >= VCS_ZCODE_APPROVED_REPRODUCER_MAX_ENTRIES)
        return VCS_ZCODE_SHADOW_LIMIT;
    size_t pos = 0;
    while (pos < set->entry_count) {
        int cmp = memcmp(entry->signer_pubkey,
                         set->entries[pos].signer_pubkey, 32);
        if (cmp == 0) return VCS_ZCODE_SHADOW_DUPLICATE;
        if (cmp < 0) break;
        pos++;
    }
    for (size_t i = set->entry_count; i > pos; i--)
        set->entries[i] = set->entries[i - 1u];
    set->entries[pos] = *entry;
    set->entry_count++;
    return VCS_ZCODE_SHADOW_OK;
}

enum vcs_zcode_shadow_error vcs_zcode_approved_reproducer_set_validate(
    const struct vcs_zcode_approved_reproducer_set_v1 *set)
{
    if (!set) return VCS_ZCODE_SHADOW_NULL;
    if (set->schema_version != VCS_ZCODE_SHADOW_POLICY_VERSION)
        return VCS_ZCODE_SHADOW_VERSION;
    if (set->flags != VCS_ZCODE_APPROVED_REPRODUCER_REQUIRED_FLAGS)
        return VCS_ZCODE_SHADOW_FLAGS;
    if (set->sequence == 0 || !zcl_bytes_any_set(set->network_genesis_root, 32))
        return VCS_ZCODE_SHADOW_ROOT;
    if ((set->sequence == 1 && !shadow_zero(set->predecessor_set_root)) ||
        (set->sequence > 1 && !zcl_bytes_any_set(set->predecessor_set_root, 32)))
        return VCS_ZCODE_SHADOW_ROOT;
    if (set->entry_count == 0 ||
        set->entry_count > VCS_ZCODE_APPROVED_REPRODUCER_MAX_ENTRIES)
        return VCS_ZCODE_SHADOW_LIMIT;
    for (size_t i = 0; i < set->entry_count; i++) {
        enum vcs_zcode_shadow_error err =
            reproducer_entry_validate(&set->entries[i]);
        if (err != VCS_ZCODE_SHADOW_OK) return err;
        if (i > 0 && memcmp(set->entries[i - 1u].signer_pubkey,
                            set->entries[i].signer_pubkey, 32) >= 0)
            return VCS_ZCODE_SHADOW_ORDER;
    }
    return VCS_ZCODE_SHADOW_OK;
}

static bool reproducer_wire_size(size_t count, size_t *out)
{
    size_t entries = 0;
    return zcl_size_mul(count, VCS_ZCODE_APPROVED_REPRODUCER_ENTRY_BYTES,
                        &entries) &&
           zcl_size_add(VCS_ZCODE_APPROVED_REPRODUCER_SET_HEADER_BYTES,
                        entries, out);
}

enum vcs_zcode_shadow_error vcs_zcode_approved_reproducer_set_serialize(
    const struct vcs_zcode_approved_reproducer_set_v1 *set,
    uint8_t *out, size_t out_capacity, size_t *out_len)
{
    if (out_len) *out_len = 0;
    if (!set || !out || !out_len) return VCS_ZCODE_SHADOW_NULL;
    enum vcs_zcode_shadow_error err =
        vcs_zcode_approved_reproducer_set_validate(set);
    if (err != VCS_ZCODE_SHADOW_OK) return err;
    size_t need = 0;
    if (!reproducer_wire_size(set->entry_count, &need))
        return VCS_ZCODE_SHADOW_OVERFLOW;
    if (out_capacity < need) return VCS_ZCODE_SHADOW_WIRE_SIZE;
    struct zcl_codec_writer writer;
    zcl_codec_writer_init(&writer, out, need);
    bool ok = zcl_codec_write_bytes(&writer, reproducer_magic, 8) &&
        zcl_codec_write_u16le(&writer, set->schema_version) &&
        zcl_codec_write_u16le(&writer, set->flags) &&
        zcl_codec_write_u32le(&writer, 0) &&
        zcl_codec_write_u64le(&writer, set->sequence) &&
        zcl_codec_write_bytes(&writer, set->network_genesis_root, 32) &&
        zcl_codec_write_bytes(&writer, set->predecessor_set_root, 32) &&
        zcl_codec_write_u16le(&writer, (uint16_t)set->entry_count) &&
        zcl_codec_write_bytes(&writer, (const uint8_t[6]){0}, 6);
    for (size_t i = 0; ok && i < set->entry_count; i++) {
        const struct vcs_zcode_approved_reproducer_entry_v1 *entry =
            &set->entries[i];
        ok = zcl_codec_write_bytes(&writer, entry->signer_pubkey, 32) &&
            zcl_codec_write_bytes(&writer,
                                  entry->contributor_binding_root, 32) &&
            zcl_codec_write_bytes(&writer, entry->operator_group_root, 32) &&
            zcl_codec_write_bytes(&writer, entry->action_root, 32) &&
            zcl_codec_write_u64le(&writer, entry->valid_from_epoch) &&
            zcl_codec_write_u64le(&writer, entry->valid_through_epoch) &&
            zcl_codec_write_i64le(&writer, entry->valid_from_unix) &&
            zcl_codec_write_i64le(&writer, entry->valid_through_unix);
    }
    size_t written = 0;
    if (!ok || !zcl_codec_writer_finish(&writer, &written) || written != need)
        return VCS_ZCODE_SHADOW_WIRE_SIZE;
    *out_len = written;
    return VCS_ZCODE_SHADOW_OK;
}

enum vcs_zcode_shadow_error vcs_zcode_approved_reproducer_set_parse(
    const uint8_t *wire, size_t wire_len,
    struct vcs_zcode_approved_reproducer_set_v1 *out)
{
    if (!wire || !out) return VCS_ZCODE_SHADOW_NULL;
    memset(out, 0, sizeof(*out));
    if (wire_len < VCS_ZCODE_APPROVED_REPRODUCER_SET_HEADER_BYTES ||
        wire_len > VCS_ZCODE_APPROVED_REPRODUCER_SET_MAX_WIRE_BYTES)
        return VCS_ZCODE_SHADOW_WIRE_SIZE;
    struct zcl_codec_reader reader;
    uint8_t magic[8], reserved[6];
    uint32_t reserved32 = 0;
    uint16_t count = 0;
    zcl_codec_reader_init(&reader, wire, wire_len);
    bool ok = zcl_codec_read_bytes(&reader, magic, 8) &&
        zcl_codec_read_u16le(&reader, &out->schema_version) &&
        zcl_codec_read_u16le(&reader, &out->flags) &&
        zcl_codec_read_u32le(&reader, &reserved32) &&
        zcl_codec_read_u64le(&reader, &out->sequence) &&
        zcl_codec_read_bytes(&reader, out->network_genesis_root, 32) &&
        zcl_codec_read_bytes(&reader, out->predecessor_set_root, 32) &&
        zcl_codec_read_u16le(&reader, &count) &&
        zcl_codec_read_bytes(&reader, reserved, sizeof(reserved));
    size_t expected = 0;
    if (!ok || memcmp(magic, reproducer_magic, 8) != 0) {
        memset(out, 0, sizeof(*out));
        return ok ? VCS_ZCODE_SHADOW_MAGIC : VCS_ZCODE_SHADOW_WIRE_SIZE;
    }
    if (reserved32 != 0 || memcmp(reserved, (const uint8_t[6]){0}, 6) != 0) {
        memset(out, 0, sizeof(*out));
        return VCS_ZCODE_SHADOW_RESERVED;
    }
    if (count == 0 || count > VCS_ZCODE_APPROVED_REPRODUCER_MAX_ENTRIES ||
        !reproducer_wire_size(count, &expected) || expected != wire_len) {
        memset(out, 0, sizeof(*out));
        return VCS_ZCODE_SHADOW_WIRE_SIZE;
    }
    out->entry_count = count;
    for (size_t i = 0; ok && i < out->entry_count; i++) {
        struct vcs_zcode_approved_reproducer_entry_v1 *entry =
            &out->entries[i];
        ok = zcl_codec_read_bytes(&reader, entry->signer_pubkey, 32) &&
            zcl_codec_read_bytes(&reader,
                                 entry->contributor_binding_root, 32) &&
            zcl_codec_read_bytes(&reader, entry->operator_group_root, 32) &&
            zcl_codec_read_bytes(&reader, entry->action_root, 32) &&
            zcl_codec_read_u64le(&reader, &entry->valid_from_epoch) &&
            zcl_codec_read_u64le(&reader, &entry->valid_through_epoch) &&
            zcl_codec_read_i64le(&reader, &entry->valid_from_unix) &&
            zcl_codec_read_i64le(&reader, &entry->valid_through_unix);
    }
    if (!ok || !zcl_codec_reader_finish(&reader)) {
        memset(out, 0, sizeof(*out));
        return VCS_ZCODE_SHADOW_WIRE_SIZE;
    }
    enum vcs_zcode_shadow_error err =
        vcs_zcode_approved_reproducer_set_validate(out);
    if (err != VCS_ZCODE_SHADOW_OK) memset(out, 0, sizeof(*out));
    return err;
}

enum vcs_zcode_shadow_error vcs_zcode_approved_reproducer_set_root(
    const struct vcs_zcode_approved_reproducer_set_v1 *set, uint8_t out[32])
{
    if (out) memset(out, 0, 32);
    if (!set || !out) return VCS_ZCODE_SHADOW_NULL;
    uint8_t wire[VCS_ZCODE_APPROVED_REPRODUCER_SET_MAX_WIRE_BYTES];
    size_t wire_len = 0;
    enum vcs_zcode_shadow_error err =
        vcs_zcode_approved_reproducer_set_serialize(
            set, wire, sizeof(wire), &wire_len);
    if (err != VCS_ZCODE_SHADOW_OK) return err;
    struct sha3_256_ctx sha;
    static const char domain[] = VCS_ZCODE_APPROVED_REPRODUCER_SET_DOMAIN;
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)domain, sizeof(domain));
    sha3_256_write(&sha, wire, wire_len);
    sha3_256_finalize(&sha, out);
    return VCS_ZCODE_SHADOW_OK;
}

enum vcs_zcode_shadow_error vcs_zcode_approved_reproducer_set_find(
    const struct vcs_zcode_approved_reproducer_set_v1 *set,
    const uint8_t signer_pubkey[32], const uint8_t action_root[32],
    uint64_t epoch, int64_t receipt_unix,
    struct vcs_zcode_approved_reproducer_entry_v1 *out)
{
    if (out) memset(out, 0, sizeof(*out));
    if (!set || !signer_pubkey || !action_root || !out)
        return VCS_ZCODE_SHADOW_NULL;
    enum vcs_zcode_shadow_error err =
        vcs_zcode_approved_reproducer_set_validate(set);
    if (err != VCS_ZCODE_SHADOW_OK) return err;
    for (size_t i = 0; i < set->entry_count; i++) {
        const struct vcs_zcode_approved_reproducer_entry_v1 *entry =
            &set->entries[i];
        int cmp = memcmp(signer_pubkey, entry->signer_pubkey, 32);
        if (cmp < 0) break;
        if (cmp > 0) continue;
        if (memcmp(action_root, entry->action_root, 32) != 0)
            return VCS_ZCODE_SHADOW_ACTION;
        if (epoch < entry->valid_from_epoch ||
            epoch > entry->valid_through_epoch)
            return VCS_ZCODE_SHADOW_EPOCH;
        if (receipt_unix < entry->valid_from_unix ||
            receipt_unix > entry->valid_through_unix)
            return VCS_ZCODE_SHADOW_TIME;
        *out = *entry;
        return VCS_ZCODE_SHADOW_OK;
    }
    return VCS_ZCODE_SHADOW_NOT_FOUND;
}

void vcs_zcode_policy_candidate_init(
    struct vcs_zcode_policy_candidate_v1 *policy,
    const uint8_t network_genesis_root[32],
    const uint8_t approved_reproducer_set_root[32],
    const uint8_t covenant_document_root[32])
{
    if (!policy) return;
    memset(policy, 0, sizeof(*policy));
    policy->schema_version = VCS_ZCODE_SHADOW_POLICY_VERSION;
    policy->flags = VCS_ZCODE_POLICY_CANDIDATE_REQUIRED_FLAGS;
    policy->policy_version = VCS_ZC23_POLICY_CANDIDATE_VERSION;
    memcpy(policy->ticker, "ZC23", 4);
    policy->decimals = VCS_ZC23_DECIMALS;
    policy->cap_algorithm = VCS_ZC23_CAP_ALGORITHM_WHOLE_TOKEN_HALVING_V1;
    policy->admitted_category_mask = VCS_ZC23_SHADOW_CATEGORY_MASK;
    policy->challenge_blocks = VCS_ZC23_CHALLENGE_BLOCKS;
    policy->challenge_seconds = VCS_ZC23_CHALLENGE_SECONDS;
    policy->initial_supply_atoms = VCS_ZC23_INITIAL_SUPPLY_ATOMS;
    policy->atoms_per_token = VCS_ZC23_ATOMS_PER_TOKEN;
    policy->epochs_per_era = VCS_ZC23_EPOCHS_PER_ERA;
    policy->base_epoch_tokens = VCS_ZC23_BASE_EPOCH_TOKENS;
    policy->maximum_supply_atoms = VCS_ZC23_MAX_SUPPLY_ATOMS;
    if (network_genesis_root)
        memcpy(policy->network_genesis_root, network_genesis_root, 32);
    if (approved_reproducer_set_root)
        memcpy(policy->approved_reproducer_set_root,
               approved_reproducer_set_root, 32);
    if (covenant_document_root)
        memcpy(policy->covenant_document_root, covenant_document_root, 32);
    policy->award_atoms[VCS_ZCODE_CREATION_PUBLIC_SOURCE - 1u] =
        VCS_ZC23_SHADOW_PUBLIC_SOURCE_ATOMS;
    policy->award_atoms[VCS_ZCODE_CREATION_BORN_RED_FIX - 1u] =
        VCS_ZC23_SHADOW_BORN_RED_ATOMS;
    policy->award_atoms[VCS_ZCODE_CREATION_SECURITY_FIX - 1u] =
        VCS_ZC23_SHADOW_BORN_RED_ATOMS;
    policy->award_atoms[VCS_ZCODE_CREATION_INDEPENDENT_REPRODUCTION - 1u] =
        VCS_ZC23_SHADOW_INDEPENDENT_REPRODUCTION_ATOMS;
    policy->award_atoms[VCS_ZCODE_CREATION_COMPATIBILITY - 1u] =
        VCS_ZC23_SHADOW_COMPATIBILITY_ATOMS;
    policy->award_atoms[VCS_ZCODE_CREATION_PRESERVATION - 1u] =
        VCS_ZC23_SHADOW_PRESERVATION_ATOMS;
}

enum vcs_zcode_shadow_error vcs_zcode_policy_candidate_validate(
    const struct vcs_zcode_policy_candidate_v1 *policy)
{
    if (!policy) return VCS_ZCODE_SHADOW_NULL;
    if (policy->schema_version != VCS_ZCODE_SHADOW_POLICY_VERSION ||
        policy->policy_version != VCS_ZC23_POLICY_CANDIDATE_VERSION)
        return VCS_ZCODE_SHADOW_VERSION;
    if (policy->flags != VCS_ZCODE_POLICY_CANDIDATE_REQUIRED_FLAGS)
        return VCS_ZCODE_SHADOW_FLAGS;
    if (memcmp(policy->ticker, "ZC23", 4) != 0 ||
        policy->decimals != VCS_ZC23_DECIMALS ||
        policy->cap_algorithm !=
            VCS_ZC23_CAP_ALGORITHM_WHOLE_TOKEN_HALVING_V1 ||
        policy->admitted_category_mask != VCS_ZC23_SHADOW_CATEGORY_MASK)
        return VCS_ZCODE_SHADOW_POLICY;
    if (policy->challenge_blocks != VCS_ZC23_CHALLENGE_BLOCKS ||
        policy->challenge_seconds != VCS_ZC23_CHALLENGE_SECONDS ||
        policy->initial_supply_atoms != VCS_ZC23_INITIAL_SUPPLY_ATOMS ||
        policy->atoms_per_token != VCS_ZC23_ATOMS_PER_TOKEN ||
        policy->epochs_per_era != VCS_ZC23_EPOCHS_PER_ERA ||
        policy->base_epoch_tokens != VCS_ZC23_BASE_EPOCH_TOKENS ||
        policy->maximum_supply_atoms != VCS_ZC23_MAX_SUPPLY_ATOMS)
        return VCS_ZCODE_SHADOW_POLICY;
    if (!zcl_bytes_any_set(policy->network_genesis_root, 32) ||
        !zcl_bytes_any_set(policy->approved_reproducer_set_root, 32) ||
        !zcl_bytes_any_set(policy->covenant_document_root, 32))
        return VCS_ZCODE_SHADOW_ROOT;
    static const uint64_t expected[6] = {
        VCS_ZC23_SHADOW_PUBLIC_SOURCE_ATOMS,
        VCS_ZC23_SHADOW_BORN_RED_ATOMS,
        VCS_ZC23_SHADOW_BORN_RED_ATOMS,
        VCS_ZC23_SHADOW_INDEPENDENT_REPRODUCTION_ATOMS,
        VCS_ZC23_SHADOW_COMPATIBILITY_ATOMS,
        VCS_ZC23_SHADOW_PRESERVATION_ATOMS,
    };
    if (memcmp(policy->award_atoms, expected, sizeof(expected)) != 0)
        return VCS_ZCODE_SHADOW_AMOUNT;
    uint64_t maximum = 0;
    if (vcs_zc23_max_supply_atoms(&maximum) != VCS_ZCODE_CREATION_OK)
        return VCS_ZCODE_SHADOW_OVERFLOW;
    return maximum == policy->maximum_supply_atoms
        ? VCS_ZCODE_SHADOW_OK : VCS_ZCODE_SHADOW_POLICY;
}

enum vcs_zcode_shadow_error vcs_zcode_policy_candidate_validate_set(
    const struct vcs_zcode_policy_candidate_v1 *policy,
    const struct vcs_zcode_approved_reproducer_set_v1 *set)
{
    enum vcs_zcode_shadow_error err =
        vcs_zcode_policy_candidate_validate(policy);
    if (err != VCS_ZCODE_SHADOW_OK) return err;
    err = vcs_zcode_approved_reproducer_set_validate(set);
    if (err != VCS_ZCODE_SHADOW_OK) return err;
    if (memcmp(policy->network_genesis_root,
               set->network_genesis_root, 32) != 0)
        return VCS_ZCODE_SHADOW_NETWORK;
    uint8_t root[32];
    err = vcs_zcode_approved_reproducer_set_root(set, root);
    if (err != VCS_ZCODE_SHADOW_OK) return err;
    return memcmp(root, policy->approved_reproducer_set_root, 32) == 0
        ? VCS_ZCODE_SHADOW_OK : VCS_ZCODE_SHADOW_POLICY;
}

enum vcs_zcode_shadow_error vcs_zcode_policy_candidate_serialize(
    const struct vcs_zcode_policy_candidate_v1 *policy,
    uint8_t out[VCS_ZCODE_POLICY_CANDIDATE_WIRE_BYTES])
{
    if (!policy || !out) return VCS_ZCODE_SHADOW_NULL;
    enum vcs_zcode_shadow_error err =
        vcs_zcode_policy_candidate_validate(policy);
    if (err != VCS_ZCODE_SHADOW_OK) return err;
    struct zcl_codec_writer writer;
    zcl_codec_writer_init(&writer, out, VCS_ZCODE_POLICY_CANDIDATE_WIRE_BYTES);
    bool ok = zcl_codec_write_bytes(&writer, policy_magic, 8) &&
        zcl_codec_write_u16le(&writer, policy->schema_version) &&
        zcl_codec_write_u16le(&writer, policy->flags) &&
        zcl_codec_write_u32le(&writer, policy->policy_version) &&
        zcl_codec_write_bytes(&writer, policy->ticker, 4) &&
        zcl_codec_write_u8(&writer, policy->decimals) &&
        zcl_codec_write_u8(&writer, policy->cap_algorithm) &&
        zcl_codec_write_u16le(&writer, policy->admitted_category_mask) &&
        zcl_codec_write_u64le(&writer, policy->challenge_blocks) &&
        zcl_codec_write_i64le(&writer, policy->challenge_seconds) &&
        zcl_codec_write_u64le(&writer, policy->initial_supply_atoms) &&
        zcl_codec_write_u64le(&writer, policy->atoms_per_token) &&
        zcl_codec_write_u64le(&writer, policy->epochs_per_era) &&
        zcl_codec_write_u64le(&writer, policy->base_epoch_tokens) &&
        zcl_codec_write_u64le(&writer, policy->maximum_supply_atoms) &&
        zcl_codec_write_bytes(&writer, policy->network_genesis_root, 32) &&
        zcl_codec_write_bytes(&writer,
                              policy->approved_reproducer_set_root, 32) &&
        zcl_codec_write_bytes(&writer, policy->covenant_document_root, 32);
    for (size_t i = 0; ok && i < 6; i++)
        ok = zcl_codec_write_u64le(&writer, policy->award_atoms[i]);
    ok = ok && zcl_codec_write_bytes(&writer, (const uint8_t[32]){0}, 32);
    size_t written = 0;
    return ok && zcl_codec_writer_finish(&writer, &written) &&
                   written == VCS_ZCODE_POLICY_CANDIDATE_WIRE_BYTES
        ? VCS_ZCODE_SHADOW_OK : VCS_ZCODE_SHADOW_WIRE_SIZE;
}

enum vcs_zcode_shadow_error vcs_zcode_policy_candidate_parse(
    const uint8_t *wire, size_t wire_len,
    struct vcs_zcode_policy_candidate_v1 *out)
{
    if (!wire || !out) return VCS_ZCODE_SHADOW_NULL;
    memset(out, 0, sizeof(*out));
    if (wire_len != VCS_ZCODE_POLICY_CANDIDATE_WIRE_BYTES)
        return VCS_ZCODE_SHADOW_WIRE_SIZE;
    struct zcl_codec_reader reader;
    uint8_t magic[8], reserved[32];
    zcl_codec_reader_init(&reader, wire, wire_len);
    bool ok = zcl_codec_read_bytes(&reader, magic, 8) &&
        zcl_codec_read_u16le(&reader, &out->schema_version) &&
        zcl_codec_read_u16le(&reader, &out->flags) &&
        zcl_codec_read_u32le(&reader, &out->policy_version) &&
        zcl_codec_read_bytes(&reader, out->ticker, 4) &&
        zcl_codec_read_u8(&reader, &out->decimals) &&
        zcl_codec_read_u8(&reader, &out->cap_algorithm) &&
        zcl_codec_read_u16le(&reader, &out->admitted_category_mask) &&
        zcl_codec_read_u64le(&reader, &out->challenge_blocks) &&
        zcl_codec_read_i64le(&reader, &out->challenge_seconds) &&
        zcl_codec_read_u64le(&reader, &out->initial_supply_atoms) &&
        zcl_codec_read_u64le(&reader, &out->atoms_per_token) &&
        zcl_codec_read_u64le(&reader, &out->epochs_per_era) &&
        zcl_codec_read_u64le(&reader, &out->base_epoch_tokens) &&
        zcl_codec_read_u64le(&reader, &out->maximum_supply_atoms) &&
        zcl_codec_read_bytes(&reader, out->network_genesis_root, 32) &&
        zcl_codec_read_bytes(&reader,
                             out->approved_reproducer_set_root, 32) &&
        zcl_codec_read_bytes(&reader, out->covenant_document_root, 32);
    for (size_t i = 0; ok && i < 6; i++)
        ok = zcl_codec_read_u64le(&reader, &out->award_atoms[i]);
    ok = ok && zcl_codec_read_bytes(&reader, reserved, 32) &&
        zcl_codec_reader_finish(&reader);
    if (!ok) {
        memset(out, 0, sizeof(*out));
        return VCS_ZCODE_SHADOW_WIRE_SIZE;
    }
    if (memcmp(magic, policy_magic, 8) != 0) {
        memset(out, 0, sizeof(*out));
        return VCS_ZCODE_SHADOW_MAGIC;
    }
    if (memcmp(reserved, (const uint8_t[32]){0}, 32) != 0) {
        memset(out, 0, sizeof(*out));
        return VCS_ZCODE_SHADOW_RESERVED;
    }
    enum vcs_zcode_shadow_error err =
        vcs_zcode_policy_candidate_validate(out);
    if (err != VCS_ZCODE_SHADOW_OK) memset(out, 0, sizeof(*out));
    return err;
}

enum vcs_zcode_shadow_error vcs_zcode_policy_candidate_root(
    const struct vcs_zcode_policy_candidate_v1 *policy, uint8_t out[32])
{
    if (out) memset(out, 0, 32);
    if (!policy || !out) return VCS_ZCODE_SHADOW_NULL;
    uint8_t wire[VCS_ZCODE_POLICY_CANDIDATE_WIRE_BYTES];
    enum vcs_zcode_shadow_error err =
        vcs_zcode_policy_candidate_serialize(policy, wire);
    if (err != VCS_ZCODE_SHADOW_OK) return err;
    struct sha3_256_ctx sha;
    static const char domain[] = VCS_ZCODE_POLICY_CANDIDATE_DOMAIN;
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)domain, sizeof(domain));
    sha3_256_write(&sha, wire, sizeof(wire));
    sha3_256_finalize(&sha, out);
    return VCS_ZCODE_SHADOW_OK;
}

enum vcs_zcode_shadow_error vcs_zcode_policy_candidate_award_atoms(
    const struct vcs_zcode_policy_candidate_v1 *policy, uint16_t category,
    uint64_t *out_atoms)
{
    if (out_atoms) *out_atoms = 0;
    if (!policy || !out_atoms) return VCS_ZCODE_SHADOW_NULL;
    enum vcs_zcode_shadow_error err =
        vcs_zcode_policy_candidate_validate(policy);
    if (err != VCS_ZCODE_SHADOW_OK) return err;
    if (category < VCS_ZCODE_CREATION_PUBLIC_SOURCE ||
        category > VCS_ZCODE_CREATION_PRESERVATION ||
        (policy->admitted_category_mask & (UINT16_C(1) << category)) == 0)
        return VCS_ZCODE_SHADOW_CATEGORY;
    *out_atoms = policy->award_atoms[category - 1u];
    return *out_atoms != 0 ? VCS_ZCODE_SHADOW_OK : VCS_ZCODE_SHADOW_AMOUNT;
}
