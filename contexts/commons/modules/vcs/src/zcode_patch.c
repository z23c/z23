/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Canonical manifest-derived ZCODE candidate patch evidence. */

#include "vcs/zcode_patch.h"

#include "base/bytes.h"
#include "vcs_priv.h"

#include "crypto/sha3.h"
#include "util/safe_alloc.h"
#include "vcs/package_manifest.h"
#include "vcs/vcs.h"
#include "vcs/vcs_object.h"

#include <stdlib.h>
#include <string.h>

static const uint8_t patch_magic[8] = {
    'Z', 'C', 'P', 'A', 'T', 'C', 'H', '\n'
};

const char *vcs_zcode_patch_result_string(enum vcs_zcode_patch_result result)
{
    switch (result) {
    case VCS_ZCODE_PATCH_OK: return "ok";
    case VCS_ZCODE_PATCH_NULL: return "null-argument";
    case VCS_ZCODE_PATCH_SHAPE: return "noncanonical-patch";
    case VCS_ZCODE_PATCH_SCOPE: return "outside-write-scope";
    case VCS_ZCODE_PATCH_LIMIT: return "task-limit-exceeded";
    case VCS_ZCODE_PATCH_ALLOC: return "allocation-failed";
    case VCS_ZCODE_PATCH_MANIFEST_MISMATCH: return "manifest-root-mismatch";
    case VCS_ZCODE_PATCH_CAS: return "cas-miss-or-corrupt";
    }
    return "unknown";
}

void vcs_zcode_patch_init(struct vcs_zcode_patch_v1 *patch)
{
    if (patch) memset(patch, 0, sizeof(*patch));
}

void vcs_zcode_patch_free(struct vcs_zcode_patch_v1 *patch)
{
    if (!patch) return;
    for (size_t i = 0; i < patch->count; i++) free(patch->changes[i].path);
    free(patch->changes);
    vcs_zcode_patch_init(patch);
}

static bool descriptor_absent(uint32_t mode, uint64_t size,
                              const uint8_t blob[32])
{
    return mode == 0 && size == 0 && zcl_bytes_all_zero(blob, 32);
}

static bool descriptor_present(uint32_t mode, const uint8_t blob[32])
{
    return mode != 0 && !zcl_bytes_all_zero(blob, 32);
}

enum vcs_zcode_patch_result vcs_zcode_patch_validate(
    const struct vcs_zcode_patch_v1 *patch)
{
    if (!patch) return VCS_ZCODE_PATCH_NULL;
    if (zcl_bytes_all_zero(patch->base_source_root, 32) ||
        zcl_bytes_all_zero(patch->candidate_source_root, 32) ||
        memcmp(patch->base_source_root, patch->candidate_source_root, 32) == 0 ||
        patch->count == 0 || patch->count > VCS_ZCODE_PATCH_MAX_CHANGES ||
        !patch->changes)
        return VCS_ZCODE_PATCH_SHAPE;
    uint64_t content_bytes = 0;
    for (size_t i = 0; i < patch->count; i++) {
        const struct vcs_zcode_patch_change_v1 *change = &patch->changes[i];
        if (!change->path || !vcs_package_path_valid(change->path) ||
            (i > 0 && strcmp(patch->changes[i - 1u].path, change->path) >= 0))
            return VCS_ZCODE_PATCH_SHAPE;
        bool old_present = descriptor_present(change->old_mode,
                                                change->old_blob);
        bool new_present = descriptor_present(change->new_mode,
                                                change->new_blob);
        if ((change->kind == VCS_DIFF_ADDED &&
             (!descriptor_absent(change->old_mode, change->old_size,
                                 change->old_blob) || !new_present)) ||
            (change->kind == VCS_DIFF_REMOVED &&
             (!old_present ||
              !descriptor_absent(change->new_mode, change->new_size,
                                 change->new_blob))) ||
            (change->kind == VCS_DIFF_MODIFIED &&
             (!old_present || !new_present ||
              (change->old_mode == change->new_mode &&
               memcmp(change->old_blob, change->new_blob, 32) == 0))) ||
            (change->kind != VCS_DIFF_ADDED &&
             change->kind != VCS_DIFF_REMOVED &&
             change->kind != VCS_DIFF_MODIFIED))
            return VCS_ZCODE_PATCH_SHAPE;
        if (new_present) {
            if (UINT64_MAX - content_bytes < change->new_size)
                return VCS_ZCODE_PATCH_LIMIT;
            content_bytes += change->new_size;
        }
    }
    if (content_bytes != patch->content_bytes)
        return VCS_ZCODE_PATCH_SHAPE;
    return VCS_ZCODE_PATCH_OK;
}

struct derive_context {
    struct vcs_zcode_patch_v1 *patch;
    const struct vcs_zcode_write_scope_v1 *scope;
    uint32_t max_changed_files;
    uint64_t max_patch_bytes;
    enum vcs_zcode_patch_result result;
};

static void derive_change(enum vcs_diff_kind kind, const struct vcs_entry *old,
                          const struct vcs_entry *new_entry, void *user)
{
    struct derive_context *ctx = user;
    if (ctx->result != VCS_ZCODE_PATCH_OK) return;
    const char *path = new_entry ? new_entry->path : old->path;
    if (!vcs_zcode_write_scope_contains(ctx->scope, path)) {
        ctx->result = VCS_ZCODE_PATCH_SCOPE;
        return;
    }
    if (ctx->patch->count >= ctx->max_changed_files ||
        ctx->patch->count >= VCS_ZCODE_PATCH_MAX_CHANGES) {
        ctx->result = VCS_ZCODE_PATCH_LIMIT;
        return;
    }
    uint64_t added_bytes = new_entry ? new_entry->size : 0;
    if (UINT64_MAX - ctx->patch->content_bytes < added_bytes ||
        ctx->patch->content_bytes + added_bytes > ctx->max_patch_bytes) {
        ctx->result = VCS_ZCODE_PATCH_LIMIT;
        return;
    }
    if (ctx->patch->count == ctx->patch->cap) {
        size_t next_cap = ctx->patch->cap ? ctx->patch->cap * 2u : 8u;
        if (next_cap > ctx->max_changed_files)
            next_cap = ctx->max_changed_files;
        struct vcs_zcode_patch_change_v1 *next = zcl_realloc(
            ctx->patch->changes, next_cap * sizeof(*next),
            "zcode.patch.changes");
        if (!next) {
            ctx->result = VCS_ZCODE_PATCH_ALLOC;
            return;
        }
        ctx->patch->changes = next;
        ctx->patch->cap = next_cap;
    }
    struct vcs_zcode_patch_change_v1 *change =
        &ctx->patch->changes[ctx->patch->count];
    memset(change, 0, sizeof(*change));
    size_t path_len = strlen(path);
    change->path = zcl_malloc(path_len + 1u, "zcode.patch.path");
    if (!change->path) {
        ctx->result = VCS_ZCODE_PATCH_ALLOC;
        return;
    }
    memcpy(change->path, path, path_len + 1u);
    change->kind = kind;
    if (old) {
        change->old_mode = old->mode;
        change->old_size = old->size;
        memcpy(change->old_blob, old->blob, 32);
    }
    if (new_entry) {
        change->new_mode = new_entry->mode;
        change->new_size = new_entry->size;
        memcpy(change->new_blob, new_entry->blob, 32);
    }
    ctx->patch->content_bytes += added_bytes;
    ctx->patch->count++;
}

enum vcs_zcode_patch_result vcs_zcode_patch_derive(
    struct vcs_manifest *base, const uint8_t base_root[32],
    struct vcs_manifest *candidate, const uint8_t candidate_root[32],
    const struct vcs_zcode_write_scope_v1 *scope,
    uint32_t max_changed_files, uint64_t max_patch_bytes,
    struct vcs_zcode_patch_v1 *out)
{
    if (!base || !base_root || !candidate || !candidate_root || !scope || !out)
        return VCS_ZCODE_PATCH_NULL;
    vcs_zcode_patch_init(out);
    uint8_t actual_base[32], actual_candidate[32];
    if (!vcs_manifest_tree_hash(base, actual_base) ||
        !vcs_manifest_tree_hash(candidate, actual_candidate) ||
        memcmp(actual_base, base_root, 32) != 0 ||
        memcmp(actual_candidate, candidate_root, 32) != 0)
        return VCS_ZCODE_PATCH_MANIFEST_MISMATCH;
    if (max_changed_files == 0 ||
        max_changed_files > VCS_ZCODE_PATCH_MAX_CHANGES || max_patch_bytes == 0)
        return VCS_ZCODE_PATCH_LIMIT;
    memcpy(out->base_source_root, base_root, 32);
    memcpy(out->candidate_source_root, candidate_root, 32);
    struct derive_context ctx = {
        .patch = out,
        .scope = scope,
        .max_changed_files = max_changed_files,
        .max_patch_bytes = max_patch_bytes,
        .result = VCS_ZCODE_PATCH_OK,
    };
    vcs_manifest_diff(base, candidate, derive_change, &ctx);
    if (ctx.result != VCS_ZCODE_PATCH_OK) {
        vcs_zcode_patch_free(out);
        return ctx.result;
    }
    enum vcs_zcode_patch_result result = vcs_zcode_patch_validate(out);
    if (result != VCS_ZCODE_PATCH_OK) vcs_zcode_patch_free(out);
    return result;
}

enum vcs_zcode_patch_result vcs_zcode_patch_serialize(
    const struct vcs_zcode_patch_v1 *patch, uint8_t **wire_out,
    size_t *wire_len)
{
    if (!wire_out || !wire_len) return VCS_ZCODE_PATCH_NULL;
    *wire_out = NULL; *wire_len = 0;
    enum vcs_zcode_patch_result valid = vcs_zcode_patch_validate(patch);
    if (valid != VCS_ZCODE_PATCH_OK) return valid;
    size_t total = VCS_ZCODE_PATCH_HEADER_BYTES;
    for (size_t i = 0; i < patch->count; i++) {
        size_t path_len = strlen(patch->changes[i].path);
        if (SIZE_MAX - total < VCS_ZCODE_PATCH_CHANGE_FIXED_BYTES + path_len)
            return VCS_ZCODE_PATCH_LIMIT;
        total += VCS_ZCODE_PATCH_CHANGE_FIXED_BYTES + path_len;
    }
    uint8_t *wire = zcl_malloc(total, "zcode.patch.wire");
    if (!wire) return VCS_ZCODE_PATCH_ALLOC;
    memcpy(wire, patch_magic, 8);
    vcs_wr_u16le(wire + 8, VCS_ZCODE_PATCH_VERSION);
    vcs_wr_u16le(wire + 10, 0);
    vcs_wr_u32le(wire + 12, (uint32_t)patch->count);
    vcs_wr_u64le(wire + 16, patch->content_bytes);
    memcpy(wire + 24, patch->base_source_root, 32);
    memcpy(wire + 56, patch->candidate_source_root, 32);
    size_t off = VCS_ZCODE_PATCH_HEADER_BYTES;
    for (size_t i = 0; i < patch->count; i++) {
        const struct vcs_zcode_patch_change_v1 *change = &patch->changes[i];
        size_t path_len = strlen(change->path);
        wire[off++] = (uint8_t)change->kind; wire[off++] = 0;
        vcs_wr_u16le(wire + off, (uint16_t)path_len); off += 2;
        vcs_wr_u32le(wire + off, change->old_mode); off += 4;
        vcs_wr_u64le(wire + off, change->old_size); off += 8;
        memcpy(wire + off, change->old_blob, 32); off += 32;
        vcs_wr_u32le(wire + off, change->new_mode); off += 4;
        vcs_wr_u64le(wire + off, change->new_size); off += 8;
        memcpy(wire + off, change->new_blob, 32); off += 32;
        memcpy(wire + off, change->path, path_len); off += path_len;
    }
    *wire_out = wire; *wire_len = total;
    return VCS_ZCODE_PATCH_OK;
}

enum vcs_zcode_patch_result vcs_zcode_patch_parse(
    const uint8_t *wire, size_t wire_len, struct vcs_zcode_patch_v1 *out)
{
    if (!wire || !out) return VCS_ZCODE_PATCH_NULL;
    vcs_zcode_patch_init(out);
    if (wire_len < VCS_ZCODE_PATCH_HEADER_BYTES ||
        memcmp(wire, patch_magic, 8) != 0 ||
        vcs_rd_u16le(wire + 8) != VCS_ZCODE_PATCH_VERSION ||
        vcs_rd_u16le(wire + 10) != 0)
        return VCS_ZCODE_PATCH_SHAPE;
    uint32_t count = vcs_rd_u32le(wire + 12);
    if (count == 0 || count > VCS_ZCODE_PATCH_MAX_CHANGES)
        return VCS_ZCODE_PATCH_SHAPE;
    out->content_bytes = vcs_rd_u64le(wire + 16);
    memcpy(out->base_source_root, wire + 24, 32);
    memcpy(out->candidate_source_root, wire + 56, 32);
    out->changes = zcl_calloc(count, sizeof(*out->changes),
                              "zcode.patch.parse.changes");
    if (!out->changes) return VCS_ZCODE_PATCH_ALLOC;
    out->cap = count;
    size_t off = VCS_ZCODE_PATCH_HEADER_BYTES;
    for (size_t i = 0; i < count; i++) {
        if (wire_len - off < VCS_ZCODE_PATCH_CHANGE_FIXED_BYTES) goto shape;
        struct vcs_zcode_patch_change_v1 *change = &out->changes[i];
        change->kind = (enum vcs_diff_kind)wire[off++];
        if (wire[off++] != 0) goto shape;
        uint16_t path_len = vcs_rd_u16le(wire + off); off += 2;
        change->old_mode = vcs_rd_u32le(wire + off); off += 4;
        change->old_size = vcs_rd_u64le(wire + off); off += 8;
        memcpy(change->old_blob, wire + off, 32); off += 32;
        change->new_mode = vcs_rd_u32le(wire + off); off += 4;
        change->new_size = vcs_rd_u64le(wire + off); off += 8;
        memcpy(change->new_blob, wire + off, 32); off += 32;
        if (path_len == 0 || path_len > VCS_PACKAGE_PATH_MAX ||
            path_len > wire_len - off)
            goto shape;
        change->path = zcl_malloc((size_t)path_len + 1u,
                                  "zcode.patch.parse.path");
        if (!change->path) {
            vcs_zcode_patch_free(out);
            return VCS_ZCODE_PATCH_ALLOC;
        }
        memcpy(change->path, wire + off, path_len);
        change->path[path_len] = '\0'; off += path_len;
        out->count++;
    }
    if (off != wire_len ||
        vcs_zcode_patch_validate(out) != VCS_ZCODE_PATCH_OK)
        goto shape;
    return VCS_ZCODE_PATCH_OK;
shape:
    vcs_zcode_patch_free(out);
    return VCS_ZCODE_PATCH_SHAPE;
}

enum vcs_zcode_patch_result vcs_zcode_patch_root(
    const struct vcs_zcode_patch_v1 *patch, uint8_t out[32])
{
    if (!out) return VCS_ZCODE_PATCH_NULL;
    uint8_t *wire = NULL; size_t wire_len = 0;
    enum vcs_zcode_patch_result result =
        vcs_zcode_patch_serialize(patch, &wire, &wire_len);
    if (result != VCS_ZCODE_PATCH_OK) return result;
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    static const char domain[] = VCS_ZCODE_PATCH_DOMAIN;
    sha3_256_write(&sha, (const uint8_t *)domain, sizeof(domain));
    sha3_256_write(&sha, wire, wire_len);
    sha3_256_finalize(&sha, out);
    free(wire);
    return VCS_ZCODE_PATCH_OK;
}

static bool patch_changed_blobs_verify(
    const char *repo_root, const struct vcs_zcode_patch_v1 *patch)
{
    for (size_t i = 0; i < patch->count; i++) {
        const struct vcs_zcode_patch_change_v1 *change = &patch->changes[i];
        if (change->kind == VCS_DIFF_REMOVED) continue;
        uint8_t *content = NULL; size_t content_len = 0;
        if (vcs_object_get(repo_root, change->new_blob, VCS_TAG_BLOB,
                           &content, &content_len) != 0 ||
            content_len != change->new_size) {
            free(content);
            return false;
        }
        free(content);
    }
    return true;
}

enum vcs_zcode_patch_result vcs_zcode_patch_verify_cas(
    const char *repo_root, const struct vcs_zcode_task_v1 *task,
    const struct vcs_zcode_candidate_v1 *candidate)
{
    if (!repo_root || !task || !candidate) return VCS_ZCODE_PATCH_NULL;
    uint8_t *wire = NULL; size_t wire_len = 0; uint8_t checked_root[32];
    struct vcs_zcode_patch_v1 stored;
    if (vcs_object_load_raw(repo_root, candidate->patch_root,
                            &wire, &wire_len) != 0 ||
        vcs_zcode_patch_parse(wire, wire_len, &stored) !=
            VCS_ZCODE_PATCH_OK) {
        free(wire);
        return VCS_ZCODE_PATCH_CAS;
    }
    free(wire); wire = NULL; wire_len = 0;
    bool stored_valid = vcs_zcode_patch_root(&stored, checked_root) ==
            VCS_ZCODE_PATCH_OK &&
        memcmp(checked_root, candidate->patch_root, 32) == 0 &&
        memcmp(stored.base_source_root, task->source_root, 32) == 0 &&
        memcmp(stored.candidate_source_root,
               candidate->candidate_source_root, 32) == 0 &&
        stored.count <= task->max_changed_files &&
        stored.content_bytes <= task->max_patch_bytes;
    vcs_zcode_patch_free(&stored);
    if (!stored_valid) return VCS_ZCODE_PATCH_MANIFEST_MISMATCH;

    struct vcs_zcode_write_scope_v1 scope;
    if (vcs_object_load_raw(repo_root, task->write_scope_root,
                            &wire, &wire_len) != 0 ||
        vcs_zcode_write_scope_parse(wire, wire_len, &scope) !=
            VCS_ZCODE_WRITE_SCOPE_OK) {
        free(wire);
        return VCS_ZCODE_PATCH_CAS;
    }
    free(wire);
    if (vcs_zcode_write_scope_root(&scope, checked_root) !=
            VCS_ZCODE_WRITE_SCOPE_OK ||
        memcmp(checked_root, task->write_scope_root, 32) != 0)
        return VCS_ZCODE_PATCH_CAS;
    struct vcs_manifest base, candidate_manifest;
    if (!vcs_tree_load(repo_root, task->source_root, &base))
        return VCS_ZCODE_PATCH_CAS;
    if (!vcs_tree_load(repo_root, candidate->candidate_source_root,
                       &candidate_manifest)) {
        vcs_manifest_free(&base);
        return VCS_ZCODE_PATCH_CAS;
    }
    struct vcs_zcode_patch_v1 derived;
    enum vcs_zcode_patch_result result = vcs_zcode_patch_derive(
        &base, task->source_root, &candidate_manifest,
        candidate->candidate_source_root, &scope, task->max_changed_files,
        task->max_patch_bytes, &derived);
    vcs_manifest_free(&candidate_manifest); vcs_manifest_free(&base);
    if (result != VCS_ZCODE_PATCH_OK) return result;
    bool matches = patch_changed_blobs_verify(repo_root, &derived) &&
        vcs_zcode_patch_root(&derived, checked_root) ==
            VCS_ZCODE_PATCH_OK &&
        memcmp(checked_root, candidate->patch_root, 32) == 0;
    vcs_zcode_patch_free(&derived);
    return matches ? VCS_ZCODE_PATCH_OK
                   : VCS_ZCODE_PATCH_MANIFEST_MISMATCH;
}
