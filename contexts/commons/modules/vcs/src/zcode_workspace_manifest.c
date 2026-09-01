/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: canonical package-side objects for the Living Commons protocol. */

#include "vcs/zcode_commons.h"

#include "base/bytes.h"
#include "base/cleanse.h"
#include "base/checked.h"
#include "base/safe_alloc.h"
#include "base/serialize_le.h"
#include "crypto/ed25519.h"
#include "crypto/sha3.h"

#include <stdlib.h>
#include <string.h>

static const uint8_t passport_magic[8] = {'Z','C','M','P','1',0,0,0};
static const uint8_t workspace_manifest_magic[8] = {
    'Z','C','W','M','1',0,0,0,
};
static const char passport_signature_domain[] =
    VCS_ZCODE_MODULE_PASSPORT_V1_SIGNING_DOMAIN;
static const char workspace_manifest_signature_domain[] =
    VCS_ZCODE_WORKSPACE_MANIFEST_V1_SIGNING_DOMAIN;

static bool workspace_zero(const uint8_t root[32])
{
    return !zcl_bytes_any_set(root, 32);
}

static void workspace_hash_u16(struct sha3_256_ctx *sha, uint16_t value)
{
    uint8_t le[2];
    zcl_write_u16_le(le, value);
    sha3_256_write(sha, le, sizeof(le));
}

static void workspace_hash_u32(struct sha3_256_ctx *sha, uint32_t value)
{
    uint8_t le[4];
    zcl_write_u32_le(le, value);
    sha3_256_write(sha, le, sizeof(le));
}

static void workspace_hash_u64(struct sha3_256_ctx *sha, uint64_t value)
{
    uint8_t le[8];
    zcl_write_u64_le(le, value);
    sha3_256_write(sha, le, sizeof(le));
}

static void workspace_hash_start(struct sha3_256_ctx *sha,
                                 const char *domain)
{
    sha3_256_init(sha);
    sha3_256_write(sha, (const uint8_t *)domain, strlen(domain) + 1u);
}

static bool workspace_flags(uint16_t version, uint16_t flags)
{
    return version == 1 && flags == VCS_ZCODE_COMMONS_REQUIRED_FLAGS;
}

enum vcs_zcode_commons_error vcs_zcode_typed_asset_manifest_v1_validate(
    const struct vcs_zcode_typed_asset_manifest_v1 *asset)
{
    if (!asset) return VCS_ZCODE_COMMONS_NULL;
    if (asset->schema_version != 1)
        return VCS_ZCODE_COMMONS_VERSION_ERROR;
    if (!workspace_flags(asset->schema_version, asset->flags))
        return VCS_ZCODE_COMMONS_FLAGS;
    if (asset->kind < VCS_ZCODE_ASSET_SOURCE ||
        asset->kind > VCS_ZCODE_ASSET_DATASET ||
        (asset->license != VCS_ZCODE_ASSET_LICENSE_CC0_1_0 &&
         asset->license != VCS_ZCODE_ASSET_LICENSE_CC_BY_4_0))
        return VCS_ZCODE_COMMONS_ENUM;
    if (!zcl_bytes_any_set(asset->format_root, 32) ||
        !zcl_bytes_any_set(asset->content_root, 32) ||
        !zcl_bytes_any_set(asset->signer_root, 32) ||
        !zcl_bytes_any_set(asset->signature, 64) || asset->byte_count == 0)
        return VCS_ZCODE_COMMONS_ROOT;
    if (asset->license == VCS_ZCODE_ASSET_LICENSE_CC_BY_4_0 &&
        !zcl_bytes_any_set(asset->attribution_root, 32))
        return VCS_ZCODE_COMMONS_POLICY;
    return VCS_ZCODE_COMMONS_OK;
}

enum vcs_zcode_commons_error vcs_zcode_typed_asset_manifest_v1_root(
    const struct vcs_zcode_typed_asset_manifest_v1 *asset, uint8_t out[32])
{
    if (out) memset(out, 0, 32);
    if (!asset || !out) return VCS_ZCODE_COMMONS_NULL;
    enum vcs_zcode_commons_error error =
        vcs_zcode_typed_asset_manifest_v1_validate(asset);
    if (error != VCS_ZCODE_COMMONS_OK) return error;
    struct sha3_256_ctx sha;
    workspace_hash_start(&sha, VCS_ZCODE_TYPED_ASSET_MANIFEST_V1_DOMAIN);
    workspace_hash_u16(&sha, asset->schema_version);
    workspace_hash_u16(&sha, asset->flags);
    workspace_hash_u16(&sha, asset->kind);
    workspace_hash_u16(&sha, asset->license);
    sha3_256_write(&sha, asset->format_root, 32);
    sha3_256_write(&sha, asset->content_root, 32);
    sha3_256_write(&sha, asset->attribution_root, 32);
    sha3_256_write(&sha, asset->collection_root, 32);
    workspace_hash_u64(&sha, asset->byte_count);
    sha3_256_write(&sha, asset->signer_root, 32);
    sha3_256_write(&sha, asset->signature, 64);
    sha3_256_finalize(&sha, out);
    return VCS_ZCODE_COMMONS_OK;
}

enum vcs_zcode_commons_error vcs_zcode_quality_profile_v1_validate(
    const struct vcs_zcode_quality_profile_v1 *profile)
{
    if (!profile) return VCS_ZCODE_COMMONS_NULL;
    if (profile->schema_version != 1)
        return VCS_ZCODE_COMMONS_VERSION_ERROR;
    if (!workspace_flags(profile->schema_version, profile->flags))
        return VCS_ZCODE_COMMONS_FLAGS;
    if (profile->reserved != 0 || profile->field > VCS_ZCODE_QUALITY_GAMES)
        return VCS_ZCODE_COMMONS_ENUM;
    if ((profile->required_check_mask & VCS_ZCODE_QUALITY_UNIVERSAL_MASK) !=
        VCS_ZCODE_QUALITY_UNIVERSAL_MASK)
        return VCS_ZCODE_COMMONS_POLICY;
    if (!zcl_bytes_any_set(profile->universal_profile_root, 32))
        return VCS_ZCODE_COMMONS_ROOT;
    if (profile->field == VCS_ZCODE_QUALITY_UNIVERSAL) {
        if (profile->required_check_mask != VCS_ZCODE_QUALITY_UNIVERSAL_MASK ||
            !workspace_zero(profile->additive_rules_root))
            return VCS_ZCODE_COMMONS_POLICY;
    } else if (!zcl_bytes_any_set(profile->additive_rules_root, 32)) {
        return VCS_ZCODE_COMMONS_ROOT;
    }
    return VCS_ZCODE_COMMONS_OK;
}

enum vcs_zcode_commons_error vcs_zcode_quality_profile_v1_root(
    const struct vcs_zcode_quality_profile_v1 *profile, uint8_t out[32])
{
    if (out) memset(out, 0, 32);
    if (!profile || !out) return VCS_ZCODE_COMMONS_NULL;
    enum vcs_zcode_commons_error error =
        vcs_zcode_quality_profile_v1_validate(profile);
    if (error != VCS_ZCODE_COMMONS_OK) return error;
    struct sha3_256_ctx sha;
    workspace_hash_start(&sha, VCS_ZCODE_QUALITY_PROFILE_V1_DOMAIN);
    workspace_hash_u16(&sha, profile->schema_version);
    workspace_hash_u16(&sha, profile->flags);
    workspace_hash_u16(&sha, profile->field);
    workspace_hash_u16(&sha, profile->reserved);
    workspace_hash_u64(&sha, profile->required_check_mask);
    sha3_256_write(&sha, profile->universal_profile_root, 32);
    sha3_256_write(&sha, profile->additive_rules_root, 32);
    sha3_256_finalize(&sha, out);
    return VCS_ZCODE_COMMONS_OK;
}

static enum vcs_zcode_commons_error passport_shape(
    const struct vcs_zcode_module_passport_v1 *passport,
    bool require_signature)
{
    if (!passport) return VCS_ZCODE_COMMONS_NULL;
    if (passport->schema_version != 1)
        return VCS_ZCODE_COMMONS_VERSION_ERROR;
    if (!workspace_flags(passport->schema_version, passport->flags))
        return VCS_ZCODE_COMMONS_FLAGS;
    const uint8_t *roots[] = {
        passport->stable_api_root, passport->recipe_root,
        passport->toolchain_root, passport->tests_root,
        passport->license_root, passport->semantic_fingerprint_root,
        passport->workspace_lineage_root, passport->source_assignment_root,
        passport->quality_profiles_root, passport->signer_root,
    };
    for (size_t i = 0; i < sizeof(roots) / sizeof(roots[0]); i++)
        if (!zcl_bytes_any_set(roots[i], 32))
            return VCS_ZCODE_COMMONS_ROOT;
    if (require_signature && !zcl_bytes_any_set(passport->signature, 64))
        return VCS_ZCODE_COMMONS_ROOT;
    return VCS_ZCODE_COMMONS_OK;
}

enum vcs_zcode_commons_error vcs_zcode_module_passport_v1_validate(
    const struct vcs_zcode_module_passport_v1 *passport)
{
    return passport_shape(passport, true);
}

static size_t passport_write_unsigned(
    const struct vcs_zcode_module_passport_v1 *passport, uint8_t *wire)
{
    size_t off = 0;
    memcpy(wire + off, passport_magic, sizeof(passport_magic));
    off += sizeof(passport_magic);
    zcl_write_u16_le(wire + off, passport->schema_version); off += 2;
    zcl_write_u16_le(wire + off, passport->flags); off += 2;
    memcpy(wire + off, passport->stable_api_root, 32u * 10u);
    off += 32u * 10u;
    return off;
}

enum vcs_zcode_commons_error vcs_zcode_module_passport_v1_signing_payload(
    const struct vcs_zcode_module_passport_v1 *passport,
    uint8_t *payload, size_t payload_capacity, size_t *payload_len)
{
    if (payload_len) *payload_len = 0;
    if (!passport || !payload || !payload_len)
        return VCS_ZCODE_COMMONS_NULL;
    enum vcs_zcode_commons_error error = passport_shape(passport, false);
    if (error != VCS_ZCODE_COMMONS_OK) return error;
    if (payload_capacity < VCS_ZCODE_MODULE_PASSPORT_V1_SIGNING_PAYLOAD_BYTES)
        return VCS_ZCODE_COMMONS_SIZE;
    const size_t domain_len = sizeof(passport_signature_domain) - 1u;
    memcpy(payload, passport_signature_domain, domain_len);
    size_t unsigned_len = passport_write_unsigned(passport,
                                                   payload + domain_len);
    *payload_len = domain_len + unsigned_len;
    return *payload_len == VCS_ZCODE_MODULE_PASSPORT_V1_SIGNING_PAYLOAD_BYTES
        ? VCS_ZCODE_COMMONS_OK : VCS_ZCODE_COMMONS_SIZE;
}

static bool passport_signature_valid(
    const struct vcs_zcode_module_passport_v1 *passport)
{
    uint8_t payload[VCS_ZCODE_MODULE_PASSPORT_V1_SIGNING_PAYLOAD_BYTES];
    size_t payload_len = 0;
    if (vcs_zcode_module_passport_v1_signing_payload(
            passport, payload, sizeof(payload), &payload_len) !=
        VCS_ZCODE_COMMONS_OK)
        return false;
    bool valid = ed25519_verify(passport->signature, payload, payload_len,
                                passport->signer_root);
    memory_cleanse(payload, sizeof(payload));
    return valid;
}

enum vcs_zcode_commons_error vcs_zcode_module_passport_v1_verify(
    const struct vcs_zcode_module_passport_v1 *passport)
{
    enum vcs_zcode_commons_error error = passport_shape(passport, true);
    if (error != VCS_ZCODE_COMMONS_OK) return error;
    return passport_signature_valid(passport)
        ? VCS_ZCODE_COMMONS_OK : VCS_ZCODE_COMMONS_SIGNATURE;
}

enum vcs_zcode_commons_error vcs_zcode_module_passport_v1_sign(
    struct vcs_zcode_module_passport_v1 *passport,
    const uint8_t signer_seed[32])
{
    if (!passport || !signer_seed) return VCS_ZCODE_COMMONS_NULL;
    uint8_t secret[32];
    ed25519_keypair(passport->signer_root, secret, signer_seed);
    memset(passport->signature, 0, sizeof(passport->signature));
    enum vcs_zcode_commons_error error = passport_shape(passport, false);
    if (error != VCS_ZCODE_COMMONS_OK) {
        memory_cleanse(secret, sizeof(secret));
        return error;
    }
    uint8_t payload[VCS_ZCODE_MODULE_PASSPORT_V1_SIGNING_PAYLOAD_BYTES];
    size_t payload_len = 0;
    error = vcs_zcode_module_passport_v1_signing_payload(
        passport, payload, sizeof(payload), &payload_len);
    if (error == VCS_ZCODE_COMMONS_OK)
        ed25519_sign(passport->signature, payload, payload_len,
                     secret, passport->signer_root);
    memory_cleanse(secret, sizeof(secret));
    memory_cleanse(payload, sizeof(payload));
    if (error != VCS_ZCODE_COMMONS_OK) return error;
    return vcs_zcode_module_passport_v1_verify(passport);
}

enum vcs_zcode_commons_error vcs_zcode_module_passport_v1_encode(
    const struct vcs_zcode_module_passport_v1 *passport,
    uint8_t *wire, size_t wire_capacity, size_t *wire_len)
{
    if (wire_len) *wire_len = 0;
    if (!passport || !wire || !wire_len) return VCS_ZCODE_COMMONS_NULL;
    enum vcs_zcode_commons_error error =
        vcs_zcode_module_passport_v1_verify(passport);
    if (error != VCS_ZCODE_COMMONS_OK) return error;
    if (wire_capacity < VCS_ZCODE_MODULE_PASSPORT_V1_WIRE_BYTES)
        return VCS_ZCODE_COMMONS_SIZE;
    size_t off = passport_write_unsigned(passport, wire);
    memcpy(wire + off, passport->signature, 64); off += 64;
    *wire_len = off;
    return off == VCS_ZCODE_MODULE_PASSPORT_V1_WIRE_BYTES
        ? VCS_ZCODE_COMMONS_OK : VCS_ZCODE_COMMONS_SIZE;
}

enum vcs_zcode_commons_error vcs_zcode_module_passport_v1_decode(
    struct vcs_zcode_module_passport_v1 *out,
    const uint8_t *wire, size_t wire_len)
{
    if (!out || !wire) return VCS_ZCODE_COMMONS_NULL;
    memset(out, 0, sizeof(*out));
    if (wire_len != VCS_ZCODE_MODULE_PASSPORT_V1_WIRE_BYTES)
        return VCS_ZCODE_COMMONS_SIZE;
    if (memcmp(wire, passport_magic, sizeof(passport_magic)) != 0)
        return VCS_ZCODE_COMMONS_MAGIC;
    size_t off = sizeof(passport_magic);
    out->schema_version = zcl_read_u16_le(wire + off); off += 2;
    out->flags = zcl_read_u16_le(wire + off); off += 2;
    memcpy(out->stable_api_root, wire + off, 32u * 10u); off += 32u * 10u;
    memcpy(out->signature, wire + off, 64); off += 64;
    enum vcs_zcode_commons_error error =
        off == wire_len ? vcs_zcode_module_passport_v1_verify(out)
                        : VCS_ZCODE_COMMONS_SIZE;
    if (error != VCS_ZCODE_COMMONS_OK) memset(out, 0, sizeof(*out));
    return error;
}

enum vcs_zcode_commons_error vcs_zcode_module_passport_v1_root(
    const struct vcs_zcode_module_passport_v1 *passport, uint8_t out[32])
{
    if (out) memset(out, 0, 32);
    if (!passport || !out) return VCS_ZCODE_COMMONS_NULL;
    enum vcs_zcode_commons_error error =
        vcs_zcode_module_passport_v1_validate(passport);
    if (error != VCS_ZCODE_COMMONS_OK) return error;
    struct sha3_256_ctx sha;
    workspace_hash_start(&sha, VCS_ZCODE_MODULE_PASSPORT_V1_DOMAIN);
    workspace_hash_u16(&sha, passport->schema_version);
    workspace_hash_u16(&sha, passport->flags);
    sha3_256_write(&sha, passport->stable_api_root, 32u * 10u);
    sha3_256_write(&sha, passport->signature, 64);
    sha3_256_finalize(&sha, out);
    return VCS_ZCODE_COMMONS_OK;
}

static enum vcs_zcode_commons_error workspace_entries_validate(
    const struct vcs_zcode_workspace_manifest_v1 *workspace)
{
    for (size_t i = 0; i < workspace->entry_count; i++) {
        const struct vcs_zcode_workspace_entry_v1 *entry =
            &workspace->entries[i];
        enum vcs_zcode_commons_error error =
            vcs_zcode_workspace_entry_v1_validate(entry);
        if (error != VCS_ZCODE_COMMONS_OK) return error;
        if (i > 0 && memcmp(workspace->entries[i - 1u].module_release_root,
                            entry->module_release_root, 32) >= 0)
            return VCS_ZCODE_COMMONS_ORDER;
        for (size_t j = 0; j < i; j++)
            if (memcmp(workspace->entries[j].semantic_fingerprint_root,
                       entry->semantic_fingerprint_root, 32) == 0)
                return VCS_ZCODE_COMMONS_DUPLICATE;
    }
    return VCS_ZCODE_COMMONS_OK;
}

enum vcs_zcode_commons_error vcs_zcode_workspace_entry_v1_validate(
    const struct vcs_zcode_workspace_entry_v1 *entry)
{
    if (!entry) return VCS_ZCODE_COMMONS_NULL;
    if (!zcl_bytes_any_set(entry->module_release_root, 32) ||
        !zcl_bytes_any_set(entry->module_passport_root, 32) ||
        !zcl_bytes_any_set(entry->semantic_fingerprint_root, 32) ||
        !zcl_bytes_any_set(entry->source_assignment_root, 32) ||
        entry->sequence == 0)
        return VCS_ZCODE_COMMONS_ROOT;
    return VCS_ZCODE_COMMONS_OK;
}

enum vcs_zcode_commons_error vcs_zcode_workspace_entry_v1_root(
    const struct vcs_zcode_workspace_entry_v1 *entry, uint8_t out[32])
{
    if (out) memset(out, 0, 32);
    if (!entry || !out) return VCS_ZCODE_COMMONS_NULL;
    enum vcs_zcode_commons_error error =
        vcs_zcode_workspace_entry_v1_validate(entry);
    if (error != VCS_ZCODE_COMMONS_OK) return error;
    struct sha3_256_ctx sha;
    workspace_hash_start(&sha, VCS_ZCODE_WORKSPACE_ENTRY_V1_DOMAIN);
    sha3_256_write(&sha, entry->module_release_root, 32u * 5u);
    workspace_hash_u64(&sha, entry->sequence);
    sha3_256_finalize(&sha, out);
    return VCS_ZCODE_COMMONS_OK;
}

static enum vcs_zcode_commons_error workspace_edges_validate(
    const struct vcs_zcode_workspace_manifest_v1 *workspace)
{
    uint32_t *indegree = zcl_calloc(
        workspace->entry_count, sizeof(*indegree), "workspace_v1_indegree");
    bool *removed = zcl_calloc(
        workspace->entry_count, sizeof(*removed), "workspace_v1_removed");
    if (!indegree || !removed) {
        free(indegree); free(removed);
        return VCS_ZCODE_COMMONS_LIMIT;
    }
    enum vcs_zcode_commons_error error = VCS_ZCODE_COMMONS_OK;
    for (size_t i = 0; i < workspace->edge_count; i++) {
        const struct vcs_zcode_workspace_edge_v1 *edge = &workspace->edges[i];
        if (edge->reserved != 0 || edge->from_entry >= workspace->entry_count ||
            edge->to_entry >= workspace->entry_count ||
            edge->from_entry == edge->to_entry) {
            error = VCS_ZCODE_COMMONS_ENUM; goto done;
        }
        if (i > 0) {
            const struct vcs_zcode_workspace_edge_v1 *prior =
                &workspace->edges[i - 1u];
            if (prior->from_entry > edge->from_entry ||
                (prior->from_entry == edge->from_entry &&
                 prior->to_entry >= edge->to_entry)) {
                error = VCS_ZCODE_COMMONS_ORDER; goto done;
            }
        }
        indegree[edge->to_entry]++;
    }
    size_t removed_count = 0;
    while (removed_count < workspace->entry_count) {
        size_t node = workspace->entry_count;
        for (size_t i = 0; i < workspace->entry_count; i++)
            if (!removed[i] && indegree[i] == 0) { node = i; break; }
        if (node == workspace->entry_count) {
            error = VCS_ZCODE_COMMONS_POLICY; goto done;
        }
        removed[node] = true; removed_count++;
        for (size_t i = 0; i < workspace->edge_count; i++)
            if (workspace->edges[i].from_entry == node)
                indegree[workspace->edges[i].to_entry]--;
    }
done:
    free(indegree); free(removed);
    return error;
}

static enum vcs_zcode_commons_error workspace_manifest_shape(
    const struct vcs_zcode_workspace_manifest_v1 *workspace,
    bool require_signature)
{
    if (!workspace) return VCS_ZCODE_COMMONS_NULL;
    if (workspace->schema_version != 1)
        return VCS_ZCODE_COMMONS_VERSION_ERROR;
    if (!workspace_flags(workspace->schema_version, workspace->flags))
        return VCS_ZCODE_COMMONS_FLAGS;
    if (workspace->sequence == 0 || workspace->entry_count == 0 ||
        workspace->entry_count > VCS_ZCODE_COMMONS_MAX_CLAIMS ||
        workspace->edge_count > VCS_ZCODE_COMMONS_MAX_CLAIMS ||
        workspace->typed_asset_count > VCS_ZCODE_COMMONS_MAX_CLAIMS ||
        !workspace->entries ||
        (workspace->edge_count > 0 && !workspace->edges) ||
        (workspace->typed_asset_count > 0 && !workspace->typed_asset_roots))
        return VCS_ZCODE_COMMONS_LIMIT;
    if ((workspace->sequence == 1 &&
         !workspace_zero(workspace->predecessor_workspace_root)) ||
        (workspace->sequence > 1 &&
         workspace_zero(workspace->predecessor_workspace_root)) ||
        !zcl_bytes_any_set(workspace->signer_root, 32) ||
        (require_signature &&
         !zcl_bytes_any_set(workspace->signature, 64)))
        return VCS_ZCODE_COMMONS_ROOT;
    enum vcs_zcode_commons_error error =
        workspace_entries_validate(workspace);
    if (error != VCS_ZCODE_COMMONS_OK) return error;
    for (size_t i = 0; i < workspace->typed_asset_count; i++) {
        if (!zcl_bytes_any_set(workspace->typed_asset_roots[i], 32))
            return VCS_ZCODE_COMMONS_ROOT;
        if (i > 0 && memcmp(workspace->typed_asset_roots[i - 1u],
                            workspace->typed_asset_roots[i], 32) >= 0)
            return VCS_ZCODE_COMMONS_ORDER;
    }
    return workspace_edges_validate(workspace);
}

enum vcs_zcode_commons_error vcs_zcode_workspace_manifest_v1_validate(
    const struct vcs_zcode_workspace_manifest_v1 *workspace)
{
    return workspace_manifest_shape(workspace, true);
}

static void workspace_manifest_hash_fields(
    struct sha3_256_ctx *sha,
    const struct vcs_zcode_workspace_manifest_v1 *workspace)
{
    workspace_hash_u16(sha, workspace->schema_version);
    workspace_hash_u16(sha, workspace->flags);
    workspace_hash_u64(sha, workspace->sequence);
    sha3_256_write(sha, workspace->predecessor_workspace_root, 32);
    workspace_hash_u64(sha, workspace->entry_count);
    workspace_hash_u64(sha, workspace->edge_count);
    workspace_hash_u64(sha, workspace->typed_asset_count);
    for (size_t i = 0; i < workspace->entry_count; i++) {
        const struct vcs_zcode_workspace_entry_v1 *entry =
            &workspace->entries[i];
        sha3_256_write(sha, entry->module_release_root, 32u * 5u);
        workspace_hash_u64(sha, entry->sequence);
    }
    for (size_t i = 0; i < workspace->edge_count; i++) {
        workspace_hash_u16(sha, workspace->edges[i].from_entry);
        workspace_hash_u16(sha, workspace->edges[i].to_entry);
        workspace_hash_u32(sha, workspace->edges[i].reserved);
    }
    for (size_t i = 0; i < workspace->typed_asset_count; i++)
        sha3_256_write(sha, workspace->typed_asset_roots[i], 32);
    sha3_256_write(sha, workspace->signer_root, 32);
}

enum vcs_zcode_commons_error vcs_zcode_workspace_manifest_v1_unsigned_root(
    const struct vcs_zcode_workspace_manifest_v1 *workspace,
    uint8_t out[32])
{
    if (out) memset(out, 0, 32);
    if (!workspace || !out) return VCS_ZCODE_COMMONS_NULL;
    enum vcs_zcode_commons_error error =
        workspace_manifest_shape(workspace, false);
    if (error != VCS_ZCODE_COMMONS_OK) return error;
    struct sha3_256_ctx sha;
    workspace_hash_start(
        &sha, VCS_ZCODE_WORKSPACE_MANIFEST_V1_UNSIGNED_DOMAIN);
    workspace_manifest_hash_fields(&sha, workspace);
    sha3_256_finalize(&sha, out);
    return VCS_ZCODE_COMMONS_OK;
}

enum vcs_zcode_commons_error vcs_zcode_workspace_manifest_v1_signing_payload(
    const struct vcs_zcode_workspace_manifest_v1 *workspace,
    uint8_t *payload, size_t payload_capacity, size_t *payload_len)
{
    if (payload_len) *payload_len = 0;
    if (!workspace || !payload || !payload_len)
        return VCS_ZCODE_COMMONS_NULL;
    if (payload_capacity <
        VCS_ZCODE_WORKSPACE_MANIFEST_V1_SIGNING_PAYLOAD_BYTES)
        return VCS_ZCODE_COMMONS_SIZE;
    const size_t domain_len =
        sizeof(workspace_manifest_signature_domain) - 1u;
    memcpy(payload, workspace_manifest_signature_domain, domain_len);
    enum vcs_zcode_commons_error error =
        vcs_zcode_workspace_manifest_v1_unsigned_root(
            workspace, payload + domain_len);
    if (error != VCS_ZCODE_COMMONS_OK) return error;
    *payload_len = domain_len + 32u;
    return *payload_len ==
            VCS_ZCODE_WORKSPACE_MANIFEST_V1_SIGNING_PAYLOAD_BYTES
        ? VCS_ZCODE_COMMONS_OK : VCS_ZCODE_COMMONS_SIZE;
}

enum vcs_zcode_commons_error vcs_zcode_workspace_manifest_v1_verify(
    const struct vcs_zcode_workspace_manifest_v1 *workspace)
{
    enum vcs_zcode_commons_error error =
        workspace_manifest_shape(workspace, true);
    if (error != VCS_ZCODE_COMMONS_OK) return error;
    uint8_t payload[
        VCS_ZCODE_WORKSPACE_MANIFEST_V1_SIGNING_PAYLOAD_BYTES];
    size_t payload_len = 0;
    error = vcs_zcode_workspace_manifest_v1_signing_payload(
        workspace, payload, sizeof(payload), &payload_len);
    bool valid = error == VCS_ZCODE_COMMONS_OK &&
        ed25519_verify(workspace->signature, payload, payload_len,
                       workspace->signer_root);
    memory_cleanse(payload, sizeof(payload));
    if (error != VCS_ZCODE_COMMONS_OK) return error;
    return valid ? VCS_ZCODE_COMMONS_OK
                 : VCS_ZCODE_COMMONS_SIGNATURE;
}

static bool workspace_manifest_wire_add(size_t *total, size_t count,
                                        size_t item_size)
{
    size_t bytes = 0;
    return total && zcl_size_mul(count, item_size, &bytes) &&
        zcl_size_add(*total, bytes, total);
}

enum vcs_zcode_commons_error vcs_zcode_workspace_manifest_v1_wire_size(
    const struct vcs_zcode_workspace_manifest_v1 *workspace,
    size_t *wire_size)
{
    if (wire_size) *wire_size = 0;
    if (!workspace || !wire_size) return VCS_ZCODE_COMMONS_NULL;
    enum vcs_zcode_commons_error error =
        vcs_zcode_workspace_manifest_v1_verify(workspace);
    if (error != VCS_ZCODE_COMMONS_OK) return error;
    size_t total = VCS_ZCODE_WORKSPACE_MANIFEST_V1_WIRE_BASE_BYTES;
    if (!workspace_manifest_wire_add(
            &total, workspace->entry_count,
            VCS_ZCODE_WORKSPACE_MANIFEST_V1_ENTRY_WIRE_BYTES) ||
        !workspace_manifest_wire_add(
            &total, workspace->edge_count,
            VCS_ZCODE_WORKSPACE_MANIFEST_V1_EDGE_WIRE_BYTES) ||
        !workspace_manifest_wire_add(
            &total, workspace->typed_asset_count,
            VCS_ZCODE_WORKSPACE_MANIFEST_V1_ASSET_WIRE_BYTES))
        return VCS_ZCODE_COMMONS_OVERFLOW;
    *wire_size = total;
    return VCS_ZCODE_COMMONS_OK;
}

enum vcs_zcode_commons_error vcs_zcode_workspace_manifest_v1_encode(
    const struct vcs_zcode_workspace_manifest_v1 *workspace,
    uint8_t *wire, size_t wire_capacity, size_t *wire_len)
{
    if (wire_len) *wire_len = 0;
    if (!workspace || !wire || !wire_len)
        return VCS_ZCODE_COMMONS_NULL;
    size_t expected = 0;
    enum vcs_zcode_commons_error error =
        vcs_zcode_workspace_manifest_v1_wire_size(workspace, &expected);
    if (error != VCS_ZCODE_COMMONS_OK) return error;
    if (wire_capacity < expected) return VCS_ZCODE_COMMONS_SIZE;
    size_t off = 0;
    memcpy(wire + off, workspace_manifest_magic,
           sizeof(workspace_manifest_magic));
    off += sizeof(workspace_manifest_magic);
    zcl_write_u16_le(wire + off, workspace->schema_version); off += 2;
    zcl_write_u16_le(wire + off, workspace->flags); off += 2;
    zcl_write_u64_le(wire + off, workspace->sequence); off += 8;
    memcpy(wire + off, workspace->predecessor_workspace_root, 32); off += 32;
    zcl_write_u32_le(wire + off, (uint32_t)workspace->entry_count); off += 4;
    zcl_write_u32_le(wire + off, (uint32_t)workspace->edge_count); off += 4;
    zcl_write_u32_le(wire + off,
                     (uint32_t)workspace->typed_asset_count); off += 4;
    memcpy(wire + off, workspace->signer_root, 32); off += 32;
    for (size_t i = 0; i < workspace->entry_count; i++) {
        const struct vcs_zcode_workspace_entry_v1 *entry =
            &workspace->entries[i];
        memcpy(wire + off, entry->module_release_root, 32u * 5u);
        off += 32u * 5u;
        zcl_write_u64_le(wire + off, entry->sequence); off += 8;
    }
    for (size_t i = 0; i < workspace->edge_count; i++) {
        zcl_write_u16_le(wire + off, workspace->edges[i].from_entry); off += 2;
        zcl_write_u16_le(wire + off, workspace->edges[i].to_entry); off += 2;
        zcl_write_u32_le(wire + off, workspace->edges[i].reserved); off += 4;
    }
    for (size_t i = 0; i < workspace->typed_asset_count; i++) {
        memcpy(wire + off, workspace->typed_asset_roots[i], 32); off += 32;
    }
    memcpy(wire + off, workspace->signature, 64); off += 64;
    if (off != expected) return VCS_ZCODE_COMMONS_SIZE;
    *wire_len = off;
    return VCS_ZCODE_COMMONS_OK;
}

void vcs_zcode_workspace_manifest_v1_decoded_free(
    struct vcs_zcode_workspace_manifest_v1_decoded *decoded)
{
    if (!decoded) return;
    free(decoded->entries);
    free(decoded->edges);
    free(decoded->typed_asset_roots);
    memset(decoded, 0, sizeof(*decoded));
}

enum vcs_zcode_commons_error vcs_zcode_workspace_manifest_v1_decode(
    struct vcs_zcode_workspace_manifest_v1_decoded *out,
    const uint8_t *wire, size_t wire_len)
{
    if (!out || !wire) return VCS_ZCODE_COMMONS_NULL;
    memset(out, 0, sizeof(*out));
    if (wire_len < VCS_ZCODE_WORKSPACE_MANIFEST_V1_WIRE_BASE_BYTES)
        return VCS_ZCODE_COMMONS_SIZE;
    if (memcmp(wire, workspace_manifest_magic,
               sizeof(workspace_manifest_magic)) != 0)
        return VCS_ZCODE_COMMONS_MAGIC;
    size_t off = sizeof(workspace_manifest_magic);
    struct vcs_zcode_workspace_manifest_v1 *workspace = &out->manifest;
    workspace->schema_version = zcl_read_u16_le(wire + off); off += 2;
    workspace->flags = zcl_read_u16_le(wire + off); off += 2;
    workspace->sequence = zcl_read_u64_le(wire + off); off += 8;
    memcpy(workspace->predecessor_workspace_root, wire + off, 32); off += 32;
    workspace->entry_count = zcl_read_u32_le(wire + off); off += 4;
    workspace->edge_count = zcl_read_u32_le(wire + off); off += 4;
    workspace->typed_asset_count = zcl_read_u32_le(wire + off); off += 4;
    memcpy(workspace->signer_root, wire + off, 32); off += 32;
    if (workspace->entry_count == 0 ||
        workspace->entry_count > VCS_ZCODE_COMMONS_MAX_CLAIMS ||
        workspace->edge_count > VCS_ZCODE_COMMONS_MAX_CLAIMS ||
        workspace->typed_asset_count > VCS_ZCODE_COMMONS_MAX_CLAIMS) {
        memset(out, 0, sizeof(*out));
        return VCS_ZCODE_COMMONS_LIMIT;
    }
    size_t expected = VCS_ZCODE_WORKSPACE_MANIFEST_V1_WIRE_BASE_BYTES;
    if (!workspace_manifest_wire_add(
            &expected, workspace->entry_count,
            VCS_ZCODE_WORKSPACE_MANIFEST_V1_ENTRY_WIRE_BYTES) ||
        !workspace_manifest_wire_add(
            &expected, workspace->edge_count,
            VCS_ZCODE_WORKSPACE_MANIFEST_V1_EDGE_WIRE_BYTES) ||
        !workspace_manifest_wire_add(
            &expected, workspace->typed_asset_count,
            VCS_ZCODE_WORKSPACE_MANIFEST_V1_ASSET_WIRE_BYTES)) {
        memset(out, 0, sizeof(*out));
        return VCS_ZCODE_COMMONS_OVERFLOW;
    }
    if (wire_len != expected) {
        memset(out, 0, sizeof(*out));
        return VCS_ZCODE_COMMONS_SIZE;
    }
    out->entries = zcl_calloc(
        workspace->entry_count, sizeof(*out->entries),
        "workspace_manifest_v1_entries");
    if (workspace->edge_count > 0)
        out->edges = zcl_calloc(
            workspace->edge_count, sizeof(*out->edges),
            "workspace_manifest_v1_edges");
    if (workspace->typed_asset_count > 0)
        out->typed_asset_roots = zcl_calloc(
            workspace->typed_asset_count, sizeof(*out->typed_asset_roots),
            "workspace_manifest_v1_assets");
    if (!out->entries || (workspace->edge_count > 0 && !out->edges) ||
        (workspace->typed_asset_count > 0 && !out->typed_asset_roots)) {
        vcs_zcode_workspace_manifest_v1_decoded_free(out);
        return VCS_ZCODE_COMMONS_LIMIT;
    }
    workspace->entries = out->entries;
    workspace->edges = out->edges;
    workspace->typed_asset_roots = out->typed_asset_roots;
    for (size_t i = 0; i < workspace->entry_count; i++) {
        memcpy(out->entries[i].module_release_root, wire + off, 32u * 5u);
        off += 32u * 5u;
        out->entries[i].sequence = zcl_read_u64_le(wire + off); off += 8;
    }
    for (size_t i = 0; i < workspace->edge_count; i++) {
        out->edges[i].from_entry = zcl_read_u16_le(wire + off); off += 2;
        out->edges[i].to_entry = zcl_read_u16_le(wire + off); off += 2;
        out->edges[i].reserved = zcl_read_u32_le(wire + off); off += 4;
    }
    for (size_t i = 0; i < workspace->typed_asset_count; i++) {
        memcpy(out->typed_asset_roots[i], wire + off, 32); off += 32;
    }
    memcpy(workspace->signature, wire + off, 64); off += 64;
    enum vcs_zcode_commons_error error = off == wire_len
        ? vcs_zcode_workspace_manifest_v1_verify(workspace)
        : VCS_ZCODE_COMMONS_SIZE;
    if (error != VCS_ZCODE_COMMONS_OK)
        vcs_zcode_workspace_manifest_v1_decoded_free(out);
    return error;
}

enum vcs_zcode_commons_error vcs_zcode_workspace_manifest_v1_root(
    const struct vcs_zcode_workspace_manifest_v1 *workspace,
    uint8_t out[32])
{
    if (out) memset(out, 0, 32);
    if (!workspace || !out) return VCS_ZCODE_COMMONS_NULL;
    enum vcs_zcode_commons_error error =
        vcs_zcode_workspace_manifest_v1_validate(workspace);
    if (error != VCS_ZCODE_COMMONS_OK) return error;
    struct sha3_256_ctx sha;
    workspace_hash_start(&sha, VCS_ZCODE_WORKSPACE_MANIFEST_V1_DOMAIN);
    workspace_manifest_hash_fields(&sha, workspace);
    sha3_256_write(&sha, workspace->signature, 64);
    sha3_256_finalize(&sha, out);
    return VCS_ZCODE_COMMONS_OK;
}

enum vcs_zcode_commons_error vcs_zcode_mission_v1_validate(
    const struct vcs_zcode_mission_v1 *mission)
{
    if (!mission) return VCS_ZCODE_COMMONS_NULL;
    if (mission->schema_version != 1)
        return VCS_ZCODE_COMMONS_VERSION_ERROR;
    if (!workspace_flags(mission->schema_version, mission->flags))
        return VCS_ZCODE_COMMONS_FLAGS;
    if (!zcl_bytes_any_set(mission->publisher_binding_root, 32) ||
        !zcl_bytes_any_set(mission->subject_tags_root, 32) ||
        !zcl_bytes_any_set(mission->goal_text_root, 32) ||
        !zcl_bytes_any_set(mission->signature, 64) ||
        mission->created_height == 0 || mission->created_mtp <= 0)
        return VCS_ZCODE_COMMONS_ROOT;
    return VCS_ZCODE_COMMONS_OK;
}

enum vcs_zcode_commons_error vcs_zcode_mission_v1_root(
    const struct vcs_zcode_mission_v1 *mission, uint8_t out[32])
{
    if (out) memset(out, 0, 32);
    if (!mission || !out) return VCS_ZCODE_COMMONS_NULL;
    enum vcs_zcode_commons_error error =
        vcs_zcode_mission_v1_validate(mission);
    if (error != VCS_ZCODE_COMMONS_OK) return error;
    struct sha3_256_ctx sha;
    workspace_hash_start(&sha, VCS_ZCODE_MISSION_V1_DOMAIN);
    workspace_hash_u16(&sha, mission->schema_version);
    workspace_hash_u16(&sha, mission->flags);
    sha3_256_write(&sha, mission->publisher_binding_root, 32u * 4u);
    workspace_hash_u64(&sha, mission->created_height);
    workspace_hash_u64(&sha, (uint64_t)mission->created_mtp);
    sha3_256_write(&sha, mission->signature, 64);
    sha3_256_finalize(&sha, out);
    return VCS_ZCODE_COMMONS_OK;
}

enum vcs_zcode_commons_error vcs_zcode_contribution_split_v1_validate(
    const struct vcs_zcode_contribution_split_v1 *split)
{
    if (!split) return VCS_ZCODE_COMMONS_NULL;
    if (split->schema_version != 1)
        return VCS_ZCODE_COMMONS_VERSION_ERROR;
    if (!workspace_flags(split->schema_version, split->flags))
        return VCS_ZCODE_COMMONS_FLAGS;
    if (!zcl_bytes_any_set(split->claim_root, 32) ||
        split->total_award_atoms == 0 || split->entry_count == 0 ||
        split->entry_count > VCS_ZCODE_CONTRIBUTION_SPLIT_MAX)
        return VCS_ZCODE_COMMONS_LIMIT;
    uint64_t sum = 0;
    for (size_t i = 0; i < split->entry_count; i++) {
        const struct vcs_zcode_contribution_split_entry_v1 *entry =
            &split->entries[i];
        if (!zcl_bytes_any_set(entry->recipient_binding_root, 32) ||
            !zcl_bytes_any_set(entry->signature, 64) ||
            entry->award_atoms == 0)
            return VCS_ZCODE_COMMONS_ROOT;
        if (i > 0 && memcmp(
                split->entries[i - 1u].recipient_binding_root,
                entry->recipient_binding_root, 32) >= 0)
            return VCS_ZCODE_COMMONS_ORDER;
        if (!zcl_u64_add(sum, entry->award_atoms, &sum))
            return VCS_ZCODE_COMMONS_OVERFLOW;
    }
    return sum == split->total_award_atoms
        ? VCS_ZCODE_COMMONS_OK : VCS_ZCODE_COMMONS_AMOUNT;
}

enum vcs_zcode_commons_error vcs_zcode_contribution_split_v1_root(
    const struct vcs_zcode_contribution_split_v1 *split, uint8_t out[32])
{
    if (out) memset(out, 0, 32);
    if (!split || !out) return VCS_ZCODE_COMMONS_NULL;
    enum vcs_zcode_commons_error error =
        vcs_zcode_contribution_split_v1_validate(split);
    if (error != VCS_ZCODE_COMMONS_OK) return error;
    struct sha3_256_ctx sha;
    workspace_hash_start(&sha, VCS_ZCODE_CONTRIBUTION_SPLIT_V1_DOMAIN);
    workspace_hash_u16(&sha, split->schema_version);
    workspace_hash_u16(&sha, split->flags);
    sha3_256_write(&sha, split->claim_root, 32);
    workspace_hash_u64(&sha, split->total_award_atoms);
    workspace_hash_u64(&sha, split->entry_count);
    for (size_t i = 0; i < split->entry_count; i++) {
        sha3_256_write(&sha, split->entries[i].recipient_binding_root, 32);
        workspace_hash_u64(&sha, split->entries[i].award_atoms);
        sha3_256_write(&sha, split->entries[i].signature, 64);
    }
    sha3_256_finalize(&sha, out);
    return VCS_ZCODE_COMMONS_OK;
}
