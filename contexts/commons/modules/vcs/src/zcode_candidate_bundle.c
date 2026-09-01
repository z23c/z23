/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Bounded candidate authority transfer over existing content.v2. */

#include "vcs/zcode_candidate_bundle.h"

#include "vcs_priv.h"

#include "util/safe_alloc.h"
#include "vcs/package_store.h"
#include "vcs/vcs.h"
#include "vcs/vcs_object.h"
#include "vcs/zcode_patch.h"
#include "vcs/zcode_write_scope.h"

#include <stdlib.h>
#include <string.h>

static const uint8_t bundle_magic[8] = {
    'Z', 'C', 'B', 'N', 'D', 'L', '\r', '\n'
};

struct bundle_blob {
    uint8_t hash[32];
    uint8_t *bytes;
    size_t len;
};

struct bundle_parts {
    const uint8_t *scope;
    size_t scope_len;
    const uint8_t *patch;
    size_t patch_len;
    const uint8_t *base;
    size_t base_len;
    const uint8_t *candidate;
    size_t candidate_len;
    const uint8_t *blob_records;
    uint32_t blob_count;
};

const char *vcs_zcode_candidate_bundle_result_string(
    enum vcs_zcode_candidate_bundle_result result)
{
    switch (result) {
    case VCS_ZCODE_CANDIDATE_BUNDLE_OK: return "ok";
    case VCS_ZCODE_CANDIDATE_BUNDLE_NULL: return "null-argument";
    case VCS_ZCODE_CANDIDATE_BUNDLE_SHAPE: return "noncanonical-bundle";
    case VCS_ZCODE_CANDIDATE_BUNDLE_LIMIT: return "bundle-limit";
    case VCS_ZCODE_CANDIDATE_BUNDLE_CAS: return "cas-miss-or-corrupt";
    case VCS_ZCODE_CANDIDATE_BUNDLE_AUTHORITY:
        return "candidate-authority-mismatch";
    case VCS_ZCODE_CANDIDATE_BUNDLE_ALLOC: return "allocation-failed";
    }
    return "unknown";
}

static void bundle_blobs_free(struct bundle_blob *blobs, size_t count)
{
    if (!blobs) return;
    for (size_t i = 0; i < count; i++) free(blobs[i].bytes);
    free(blobs);
}

static int bundle_blob_compare(const void *a, const void *b)
{
    const struct bundle_blob *left = a, *right = b;
    return memcmp(left->hash, right->hash, 32);
}

static bool bundle_load_raw(const char *repo_root, const uint8_t root[32],
                            uint8_t **wire, size_t *wire_len)
{
    *wire = NULL; *wire_len = 0;
    return vcs_object_load_raw(repo_root, root, wire, wire_len) == 0;
}

static enum vcs_zcode_candidate_bundle_result bundle_collect_blobs(
    const char *repo_root, const struct vcs_zcode_patch_v1 *patch,
    struct bundle_blob **out, size_t *out_count, uint64_t max_bytes)
{
    *out = NULL; *out_count = 0;
    struct bundle_blob *blobs = zcl_calloc(
        patch->count, sizeof(*blobs), "zcode.candidate_bundle.blobs");
    if (!blobs) return VCS_ZCODE_CANDIDATE_BUNDLE_ALLOC;
    uint64_t total = 0; size_t count = 0;
    for (size_t i = 0; i < patch->count; i++) {
        const struct vcs_zcode_patch_change_v1 *change = &patch->changes[i];
        if (change->kind == VCS_DIFF_REMOVED) continue;
        bool duplicate = false;
        for (size_t j = 0; j < count; j++)
            if (memcmp(blobs[j].hash, change->new_blob, 32) == 0) {
                duplicate = true; break;
            }
        if (duplicate) continue;
        if (UINT64_MAX - total < change->new_size ||
            total + change->new_size > max_bytes) {
            bundle_blobs_free(blobs, count);
            return VCS_ZCODE_CANDIDATE_BUNDLE_LIMIT;
        }
        uint8_t *bytes = NULL; size_t len = 0;
        if (vcs_object_get(repo_root, change->new_blob, VCS_TAG_BLOB,
                           &bytes, &len) != 0 || len != change->new_size) {
            free(bytes); bundle_blobs_free(blobs, count);
            return VCS_ZCODE_CANDIDATE_BUNDLE_CAS;
        }
        memcpy(blobs[count].hash, change->new_blob, 32);
        blobs[count].bytes = bytes; blobs[count].len = len;
        total += len; count++;
    }
    qsort(blobs, count, sizeof(*blobs), bundle_blob_compare);
    *out = blobs; *out_count = count;
    return VCS_ZCODE_CANDIDATE_BUNDLE_OK;
}

static bool bundle_add_size(size_t *total, size_t add)
{
    if (SIZE_MAX - *total < add) return false;
    *total += add;
    return true;
}

enum vcs_zcode_candidate_bundle_result vcs_zcode_candidate_bundle_export(
    const char *repo_root, const struct vcs_zcode_task_v1 *task,
    const struct vcs_zcode_candidate_v1 *candidate,
    uint8_t **wire_out, size_t *wire_len)
{
    if (!repo_root || !task || !candidate || !wire_out || !wire_len)
        return VCS_ZCODE_CANDIDATE_BUNDLE_NULL;
    *wire_out = NULL; *wire_len = 0;
    if (vcs_zcode_patch_verify_cas(repo_root, task, candidate) !=
        VCS_ZCODE_PATCH_OK)
        return VCS_ZCODE_CANDIDATE_BUNDLE_AUTHORITY;
    uint8_t *scope = NULL, *patch_wire = NULL, *base = NULL, *candidate_wire = NULL;
    size_t scope_len = 0, patch_len = 0, base_len = 0, candidate_len = 0;
    bool loaded = bundle_load_raw(repo_root, task->write_scope_root,
                                  &scope, &scope_len) &&
        bundle_load_raw(repo_root, candidate->patch_root,
                        &patch_wire, &patch_len) &&
        bundle_load_raw(repo_root, task->source_root, &base, &base_len) &&
        bundle_load_raw(repo_root, candidate->candidate_source_root,
                        &candidate_wire, &candidate_len);
    if (!loaded) {
        free(candidate_wire); free(base); free(patch_wire); free(scope);
        return VCS_ZCODE_CANDIDATE_BUNDLE_CAS;
    }
    struct vcs_zcode_patch_v1 parsed_patch;
    if (vcs_zcode_patch_parse(patch_wire, patch_len, &parsed_patch) !=
        VCS_ZCODE_PATCH_OK) {
        free(candidate_wire); free(base); free(patch_wire); free(scope);
        return VCS_ZCODE_CANDIDATE_BUNDLE_CAS;
    }
    struct bundle_blob *blobs = NULL; size_t blob_count = 0;
    enum vcs_zcode_candidate_bundle_result result = bundle_collect_blobs(
        repo_root, &parsed_patch, &blobs, &blob_count,
        task->max_patch_bytes);
    vcs_zcode_patch_free(&parsed_patch);
    size_t total = VCS_ZCODE_CANDIDATE_BUNDLE_HEADER_BYTES;
    bool sized = result == VCS_ZCODE_CANDIDATE_BUNDLE_OK &&
        bundle_add_size(&total, scope_len) &&
        bundle_add_size(&total, patch_len) && bundle_add_size(&total, base_len) &&
        bundle_add_size(&total, candidate_len);
    for (size_t i = 0; sized && i < blob_count; i++)
        sized = bundle_add_size(
            &total, VCS_ZCODE_CANDIDATE_BUNDLE_BLOB_HEADER_BYTES) &&
            bundle_add_size(&total, blobs[i].len);
    if (!sized || total > task->max_context_bytes ||
        total > VCS_PACKAGE_STORE_MAX_PACKAGE_BYTES || blob_count > UINT32_MAX) {
        if (result == VCS_ZCODE_CANDIDATE_BUNDLE_OK)
            result = VCS_ZCODE_CANDIDATE_BUNDLE_LIMIT;
        bundle_blobs_free(blobs, blob_count);
        free(candidate_wire); free(base); free(patch_wire); free(scope);
        return result;
    }
    uint8_t *wire = zcl_malloc(total, "zcode.candidate_bundle.wire");
    if (!wire) result = VCS_ZCODE_CANDIDATE_BUNDLE_ALLOC;
    if (result == VCS_ZCODE_CANDIDATE_BUNDLE_OK) {
        memcpy(wire, bundle_magic, 8);
        vcs_wr_u16le(wire + 8, VCS_ZCODE_CANDIDATE_BUNDLE_VERSION);
        vcs_wr_u16le(wire + 10, 0);
        vcs_wr_u32le(wire + 12, (uint32_t)blob_count);
        vcs_wr_u64le(wire + 16, scope_len);
        vcs_wr_u64le(wire + 24, patch_len);
        vcs_wr_u64le(wire + 32, base_len);
        vcs_wr_u64le(wire + 40, candidate_len);
        size_t off = VCS_ZCODE_CANDIDATE_BUNDLE_HEADER_BYTES;
        memcpy(wire + off, scope, scope_len); off += scope_len;
        memcpy(wire + off, patch_wire, patch_len); off += patch_len;
        memcpy(wire + off, base, base_len); off += base_len;
        memcpy(wire + off, candidate_wire, candidate_len); off += candidate_len;
        for (size_t i = 0; i < blob_count; i++) {
            memcpy(wire + off, blobs[i].hash, 32); off += 32;
            vcs_wr_u64le(wire + off, blobs[i].len); off += 8;
            memcpy(wire + off, blobs[i].bytes, blobs[i].len);
            off += blobs[i].len;
        }
        if (off != total) result = VCS_ZCODE_CANDIDATE_BUNDLE_SHAPE;
    }
    bundle_blobs_free(blobs, blob_count);
    free(candidate_wire); free(base); free(patch_wire); free(scope);
    if (result != VCS_ZCODE_CANDIDATE_BUNDLE_OK) {
        free(wire); return result;
    }
    *wire_out = wire; *wire_len = total;
    return VCS_ZCODE_CANDIDATE_BUNDLE_OK;
}

static bool bundle_take(const uint8_t *wire, size_t wire_len, size_t *off,
                        uint64_t wanted, const uint8_t **part,
                        size_t *part_len)
{
    if (wanted > SIZE_MAX || (size_t)wanted > wire_len - *off) return false;
    *part = wire + *off; *part_len = (size_t)wanted; *off += (size_t)wanted;
    return true;
}

static enum vcs_zcode_candidate_bundle_result bundle_parse_parts(
    const uint8_t *wire, size_t wire_len,
    const struct vcs_zcode_task_v1 *task, struct bundle_parts *parts)
{
    memset(parts, 0, sizeof(*parts));
    if (wire_len < VCS_ZCODE_CANDIDATE_BUNDLE_HEADER_BYTES ||
        wire_len > task->max_context_bytes ||
        wire_len > VCS_PACKAGE_STORE_MAX_PACKAGE_BYTES ||
        memcmp(wire, bundle_magic, 8) != 0 ||
        vcs_rd_u16le(wire + 8) != VCS_ZCODE_CANDIDATE_BUNDLE_VERSION ||
        vcs_rd_u16le(wire + 10) != 0)
        return VCS_ZCODE_CANDIDATE_BUNDLE_SHAPE;
    parts->blob_count = vcs_rd_u32le(wire + 12);
    if (parts->blob_count > 4096u) return VCS_ZCODE_CANDIDATE_BUNDLE_LIMIT;
    size_t off = VCS_ZCODE_CANDIDATE_BUNDLE_HEADER_BYTES;
    if (!bundle_take(wire, wire_len, &off, vcs_rd_u64le(wire + 16),
                     &parts->scope, &parts->scope_len) ||
        !bundle_take(wire, wire_len, &off, vcs_rd_u64le(wire + 24),
                     &parts->patch, &parts->patch_len) ||
        !bundle_take(wire, wire_len, &off, vcs_rd_u64le(wire + 32),
                     &parts->base, &parts->base_len) ||
        !bundle_take(wire, wire_len, &off, vcs_rd_u64le(wire + 40),
                     &parts->candidate, &parts->candidate_len))
        return VCS_ZCODE_CANDIDATE_BUNDLE_SHAPE;
    parts->blob_records = wire + off;
    for (uint32_t i = 0; i < parts->blob_count; i++) {
        if (wire_len - off < VCS_ZCODE_CANDIDATE_BUNDLE_BLOB_HEADER_BYTES)
            return VCS_ZCODE_CANDIDATE_BUNDLE_SHAPE;
        uint64_t len = vcs_rd_u64le(wire + off + 32);
        off += VCS_ZCODE_CANDIDATE_BUNDLE_BLOB_HEADER_BYTES;
        if (len > SIZE_MAX || (size_t)len > wire_len - off)
            return VCS_ZCODE_CANDIDATE_BUNDLE_SHAPE;
        off += (size_t)len;
    }
    return off == wire_len ? VCS_ZCODE_CANDIDATE_BUNDLE_OK
                           : VCS_ZCODE_CANDIDATE_BUNDLE_SHAPE;
}

static enum vcs_zcode_candidate_bundle_result bundle_validate_authority(
    const struct bundle_parts *parts,
    const struct vcs_zcode_task_v1 *task,
    const struct vcs_zcode_candidate_v1 *candidate,
    struct vcs_zcode_patch_v1 *patch_out)
{
    struct vcs_zcode_write_scope_v1 scope;
    struct vcs_manifest base, candidate_manifest;
    uint8_t checked[32];
    if (vcs_zcode_write_scope_parse(parts->scope, parts->scope_len, &scope) !=
            VCS_ZCODE_WRITE_SCOPE_OK ||
        vcs_zcode_write_scope_root(&scope, checked) !=
            VCS_ZCODE_WRITE_SCOPE_OK ||
        memcmp(checked, task->write_scope_root, 32) != 0 ||
        !vcs_manifest_parse(parts->base, parts->base_len, &base))
        return VCS_ZCODE_CANDIDATE_BUNDLE_AUTHORITY;
    bool valid = vcs_manifest_tree_hash(&base, checked) &&
        memcmp(checked, task->source_root, 32) == 0 &&
        vcs_manifest_parse(parts->candidate, parts->candidate_len,
                           &candidate_manifest);
    if (!valid) {
        vcs_manifest_free(&base);
        return VCS_ZCODE_CANDIDATE_BUNDLE_AUTHORITY;
    }
    valid = vcs_manifest_tree_hash(&candidate_manifest, checked) &&
        memcmp(checked, candidate->candidate_source_root, 32) == 0 &&
        vcs_zcode_patch_parse(parts->patch, parts->patch_len, patch_out) ==
            VCS_ZCODE_PATCH_OK &&
        vcs_zcode_patch_root(patch_out, checked) == VCS_ZCODE_PATCH_OK &&
        memcmp(checked, candidate->patch_root, 32) == 0;
    if (valid) {
        struct vcs_zcode_patch_v1 derived;
        bool derived_ready = vcs_zcode_patch_derive(
            &base, task->source_root, &candidate_manifest,
            candidate->candidate_source_root, &scope,
            task->max_changed_files, task->max_patch_bytes, &derived) ==
                VCS_ZCODE_PATCH_OK;
        valid = derived_ready &&
            vcs_zcode_patch_root(&derived, checked) == VCS_ZCODE_PATCH_OK &&
            memcmp(checked, candidate->patch_root, 32) == 0;
        if (derived_ready) vcs_zcode_patch_free(&derived);
    }
    vcs_manifest_free(&candidate_manifest); vcs_manifest_free(&base);
    if (!valid) vcs_zcode_patch_free(patch_out);
    return valid ? VCS_ZCODE_CANDIDATE_BUNDLE_OK
                 : VCS_ZCODE_CANDIDATE_BUNDLE_AUTHORITY;
}

static bool bundle_blob_expected(const struct vcs_zcode_patch_v1 *patch,
                                 const uint8_t hash[32], uint64_t len)
{
    for (size_t i = 0; i < patch->count; i++)
        if (patch->changes[i].kind != VCS_DIFF_REMOVED &&
            memcmp(patch->changes[i].new_blob, hash, 32) == 0)
            return patch->changes[i].new_size == len;
    return false;
}

static enum vcs_zcode_candidate_bundle_result bundle_validate_blobs(
    const struct bundle_parts *parts,
    const struct vcs_zcode_patch_v1 *patch)
{
    const uint8_t *at = parts->blob_records;
    uint64_t total = 0; uint8_t prior[32] = {0};
    for (uint32_t i = 0; i < parts->blob_count; i++) {
        const uint8_t *hash = at; uint64_t len = vcs_rd_u64le(at + 32);
        at += VCS_ZCODE_CANDIDATE_BUNDLE_BLOB_HEADER_BYTES;
        if ((i > 0 && memcmp(prior, hash, 32) >= 0) ||
            !bundle_blob_expected(patch, hash, len) ||
            UINT64_MAX - total < len)
            return VCS_ZCODE_CANDIDATE_BUNDLE_AUTHORITY;
        uint8_t got[32];
        vcs_sha3_tag(VCS_TAG_BLOB, at, (size_t)len, got);
        if (memcmp(got, hash, 32) != 0)
            return VCS_ZCODE_CANDIDATE_BUNDLE_AUTHORITY;
        memcpy(prior, hash, 32); total += len; at += (size_t)len;
    }
    size_t unique_expected = 0;
    for (size_t i = 0; i < patch->count; i++) {
        if (patch->changes[i].kind == VCS_DIFF_REMOVED) continue;
        bool seen = false;
        for (size_t j = 0; j < i; j++)
            if (patch->changes[j].kind != VCS_DIFF_REMOVED &&
                memcmp(patch->changes[j].new_blob,
                       patch->changes[i].new_blob, 32) == 0) {
                seen = true; break;
            }
        if (!seen) unique_expected++;
    }
    return unique_expected == parts->blob_count &&
           total <= patch->content_bytes
        ? VCS_ZCODE_CANDIDATE_BUNDLE_OK
        : VCS_ZCODE_CANDIDATE_BUNDLE_AUTHORITY;
}

static enum vcs_zcode_candidate_bundle_result bundle_store_blobs(
    const char *repo_root, const struct bundle_parts *parts)
{
    const uint8_t *at = parts->blob_records;
    for (uint32_t i = 0; i < parts->blob_count; i++) {
        const uint8_t *hash = at; uint64_t len = vcs_rd_u64le(at + 32);
        at += VCS_ZCODE_CANDIDATE_BUNDLE_BLOB_HEADER_BYTES;
        uint8_t got[32];
        if (!vcs_object_put(repo_root, at, (size_t)len, VCS_TAG_BLOB, got) ||
            memcmp(got, hash, 32) != 0)
            return VCS_ZCODE_CANDIDATE_BUNDLE_CAS;
        at += (size_t)len;
    }
    return VCS_ZCODE_CANDIDATE_BUNDLE_OK;
}

enum vcs_zcode_candidate_bundle_result vcs_zcode_candidate_bundle_import(
    const char *repo_root, const struct vcs_zcode_task_v1 *task,
    const struct vcs_zcode_candidate_v1 *candidate,
    const uint8_t *wire, size_t wire_len)
{
    if (!repo_root || !task || !candidate || !wire)
        return VCS_ZCODE_CANDIDATE_BUNDLE_NULL;
    struct bundle_parts parts;
    enum vcs_zcode_candidate_bundle_result result = bundle_parse_parts(
        wire, wire_len, task, &parts);
    if (result != VCS_ZCODE_CANDIDATE_BUNDLE_OK) return result;
    struct vcs_zcode_patch_v1 patch;
    result = bundle_validate_authority(&parts, task, candidate, &patch);
    if (result != VCS_ZCODE_CANDIDATE_BUNDLE_OK) return result;
    result = bundle_validate_blobs(&parts, &patch);
    if (result != VCS_ZCODE_CANDIDATE_BUNDLE_OK) {
        vcs_zcode_patch_free(&patch);
        return result;
    }
    if (!vcs_object_store_init(repo_root) ||
        !vcs_object_put_addressed(repo_root, task->write_scope_root,
                                  parts.scope, parts.scope_len) ||
        !vcs_object_put_addressed(repo_root, candidate->patch_root,
                                  parts.patch, parts.patch_len) ||
        !vcs_object_put_addressed(repo_root, task->source_root,
                                  parts.base, parts.base_len) ||
        !vcs_object_put_addressed(repo_root, candidate->candidate_source_root,
                                  parts.candidate, parts.candidate_len))
        result = VCS_ZCODE_CANDIDATE_BUNDLE_CAS;
    if (result == VCS_ZCODE_CANDIDATE_BUNDLE_OK)
        result = bundle_store_blobs(repo_root, &parts);
    vcs_zcode_patch_free(&patch);
    if (result != VCS_ZCODE_CANDIDATE_BUNDLE_OK) return result;
    return vcs_zcode_patch_verify_cas(repo_root, task, candidate) ==
            VCS_ZCODE_PATCH_OK
        ? VCS_ZCODE_CANDIDATE_BUNDLE_OK
        : VCS_ZCODE_CANDIDATE_BUNDLE_AUTHORITY;
}
