/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Carry canonical task lock/recipe wires inside content.v2. */

#include "vcs/zcode_task_authority_bundle.h"

#include "vcs_priv.h"

#include "util/safe_alloc.h"
#include "vcs/package_deps.h"
#include "vcs/package_recipe.h"
#include "vcs/vcs.h"
#include "vcs/vcs_object.h"

#include <stdlib.h>
#include <string.h>

static const uint8_t task_authority_magic[8] = {
    'Z', 'C', 'T', 'A', 'U', 'T', '\r', '\n'
};

enum vcs_zcode_task_authority_result vcs_zcode_task_authority_bundle_export(
    const char *repo_root, const struct vcs_zcode_task_v1 *task,
    uint8_t **wire, size_t *wire_len)
{
    if (!repo_root || !task || !wire || !wire_len)
        return VCS_ZCODE_TASK_AUTHORITY_NULL;
    *wire = NULL; *wire_len = 0;
    uint8_t *lock = NULL, *recipe = NULL; size_t lock_len = 0, recipe_len = 0;
    if (vcs_object_load_raw(repo_root, task->dependency_lock_root,
                            &lock, &lock_len) != 0 ||
        vcs_object_load_raw(repo_root, task->acceptance_tests_root,
                            &recipe, &recipe_len) != 0) {
        free(recipe); free(lock); return VCS_ZCODE_TASK_AUTHORITY_CAS;
    }
    if (lock_len > VCS_PACKAGE_LOCK_MAX_WIRE_BYTES ||
        recipe_len > VCS_PACKAGE_RECIPE_MAX_WIRE_BYTES ||
        SIZE_MAX - VCS_ZCODE_TASK_AUTHORITY_BUNDLE_HEADER_BYTES < lock_len ||
        SIZE_MAX - VCS_ZCODE_TASK_AUTHORITY_BUNDLE_HEADER_BYTES - lock_len <
            recipe_len) {
        free(recipe); free(lock); return VCS_ZCODE_TASK_AUTHORITY_CAS;
    }
    size_t total = VCS_ZCODE_TASK_AUTHORITY_BUNDLE_HEADER_BYTES + lock_len +
                   recipe_len;
    uint8_t *out = zcl_malloc(total, "zcode.task_authority.bundle");
    if (!out) {
        free(recipe); free(lock); return VCS_ZCODE_TASK_AUTHORITY_CAS;
    }
    memcpy(out, task_authority_magic, 8);
    vcs_wr_u16le(out + 8, VCS_ZCODE_TASK_AUTHORITY_BUNDLE_VERSION);
    vcs_wr_u16le(out + 10, 0);
    vcs_wr_u64le(out + 12, lock_len);
    vcs_wr_u64le(out + 20, recipe_len);
    memcpy(out + 28, lock, lock_len);
    memcpy(out + 28 + lock_len, recipe, recipe_len);
    free(recipe); free(lock);
    *wire = out; *wire_len = total;
    return VCS_ZCODE_TASK_AUTHORITY_OK;
}

enum vcs_zcode_task_authority_result vcs_zcode_task_authority_bundle_import(
    const char *repo_root, const struct vcs_zcode_task_v1 *task,
    const uint8_t *wire, size_t wire_len)
{
    if (!repo_root || !task || !wire)
        return VCS_ZCODE_TASK_AUTHORITY_NULL;
    if (wire_len < VCS_ZCODE_TASK_AUTHORITY_BUNDLE_HEADER_BYTES ||
        memcmp(wire, task_authority_magic, 8) != 0 ||
        vcs_rd_u16le(wire + 8) != VCS_ZCODE_TASK_AUTHORITY_BUNDLE_VERSION ||
        vcs_rd_u16le(wire + 10) != 0)
        return VCS_ZCODE_TASK_AUTHORITY_CAS;
    uint64_t lock_len64 = vcs_rd_u64le(wire + 12);
    uint64_t recipe_len64 = vcs_rd_u64le(wire + 20);
    if (lock_len64 > VCS_PACKAGE_LOCK_MAX_WIRE_BYTES ||
        recipe_len64 > VCS_PACKAGE_RECIPE_MAX_WIRE_BYTES ||
        lock_len64 + recipe_len64 +
                VCS_ZCODE_TASK_AUTHORITY_BUNDLE_HEADER_BYTES != wire_len)
        return VCS_ZCODE_TASK_AUTHORITY_CAS;
    uint8_t lock_root[32], recipe_root[32]; size_t lock_len = (size_t)lock_len64;
    enum vcs_zcode_task_authority_result result =
        vcs_zcode_task_authority_roots(
            wire + 28, lock_len, wire + 28 + lock_len,
            (size_t)recipe_len64, lock_root, recipe_root);
    if (result != VCS_ZCODE_TASK_AUTHORITY_OK) return result;
    if (memcmp(lock_root, task->dependency_lock_root, 32) != 0 ||
        memcmp(recipe_root, task->acceptance_tests_root, 32) != 0)
        return VCS_ZCODE_TASK_AUTHORITY_CAS;
    uint8_t stored_lock[32], stored_recipe[32];
    result = vcs_zcode_task_authority_store(
            repo_root, wire + 28, lock_len, wire + 28 + lock_len,
            (size_t)recipe_len64, stored_lock, stored_recipe);
    if (result != VCS_ZCODE_TASK_AUTHORITY_OK) return result;
    return memcmp(stored_lock, lock_root, 32) == 0 &&
           memcmp(stored_recipe, recipe_root, 32) == 0
        ? VCS_ZCODE_TASK_AUTHORITY_OK : VCS_ZCODE_TASK_AUTHORITY_CAS;
}

enum vcs_zcode_task_authority_result
vcs_zcode_task_authority_bundle_validate_for_candidate(
    const char *repo_root, const struct vcs_zcode_task_v1 *task,
    const struct vcs_zcode_candidate_v1 *candidate,
    const uint8_t *wire, size_t wire_len)
{
    if (!repo_root || !task || !candidate || !wire)
        return VCS_ZCODE_TASK_AUTHORITY_NULL;
    if (wire_len < VCS_ZCODE_TASK_AUTHORITY_BUNDLE_HEADER_BYTES ||
        memcmp(wire, task_authority_magic, 8) != 0 ||
        vcs_rd_u16le(wire + 8) != VCS_ZCODE_TASK_AUTHORITY_BUNDLE_VERSION ||
        vcs_rd_u16le(wire + 10) != 0)
        return VCS_ZCODE_TASK_AUTHORITY_CAS;
    uint64_t lock_len64 = vcs_rd_u64le(wire + 12);
    uint64_t recipe_len64 = vcs_rd_u64le(wire + 20);
    if (lock_len64 > VCS_PACKAGE_LOCK_MAX_WIRE_BYTES ||
        recipe_len64 > VCS_PACKAGE_RECIPE_MAX_WIRE_BYTES ||
        lock_len64 + recipe_len64 +
                VCS_ZCODE_TASK_AUTHORITY_BUNDLE_HEADER_BYTES != wire_len)
        return VCS_ZCODE_TASK_AUTHORITY_CAS;
    size_t lock_len = (size_t)lock_len64;
    const uint8_t *lock = wire + VCS_ZCODE_TASK_AUTHORITY_BUNDLE_HEADER_BYTES;
    const uint8_t *recipe_wire = lock + lock_len;
    uint8_t lock_root[32], recipe_root[32];
    enum vcs_zcode_task_authority_result result =
        vcs_zcode_task_authority_roots(
            lock, lock_len, recipe_wire, (size_t)recipe_len64,
            lock_root, recipe_root);
    if (result != VCS_ZCODE_TASK_AUTHORITY_OK ||
        memcmp(lock_root, task->dependency_lock_root, 32) != 0 ||
        memcmp(recipe_root, task->acceptance_tests_root, 32) != 0)
        return VCS_ZCODE_TASK_AUTHORITY_CAS;
    struct vcs_package_recipe recipe;
    if (vcs_package_recipe_parse(
            recipe_wire, (size_t)recipe_len64, &recipe) !=
            VCS_PACKAGE_RECIPE_OK)
        return VCS_ZCODE_TASK_AUTHORITY_RECIPE;
    const uint8_t *roots[] = { candidate->candidate_source_root };
    char detail[160];
    for (size_t i = 0; i < sizeof(roots) / sizeof(roots[0]); i++) {
        struct vcs_manifest manifest;
        if (!vcs_tree_load(repo_root, roots[i], &manifest)) {
            vcs_package_recipe_free(&recipe);
            return VCS_ZCODE_TASK_AUTHORITY_CAS;
        }
        bool present = vcs_package_recipe_files_in_vcs_manifest(
            &recipe, &manifest, detail, sizeof(detail));
        vcs_manifest_free(&manifest);
        if (!present) {
            vcs_package_recipe_free(&recipe);
            return VCS_ZCODE_TASK_AUTHORITY_MEMBERSHIP;
        }
    }
    vcs_package_recipe_free(&recipe);
    return VCS_ZCODE_TASK_AUTHORITY_OK;
}
