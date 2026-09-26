/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Canonical lock and recipe authority for ZCODE tasks. */

#include "vcs/zcode_task_authority.h"

#include "vcs_priv.h"

#include "crypto/sha3.h"
#include "vcs/package_deps.h"
#include "vcs/package_recipe.h"
#include "vcs/vcs.h"
#include "vcs/vcs_object.h"

#include <stdlib.h>
#include <string.h>

const char *vcs_zcode_task_authority_result_string(
    enum vcs_zcode_task_authority_result result)
{
    switch (result) {
    case VCS_ZCODE_TASK_AUTHORITY_OK: return "ok";
    case VCS_ZCODE_TASK_AUTHORITY_NULL: return "null-argument";
    case VCS_ZCODE_TASK_AUTHORITY_LOCK: return "dependency-lock-invalid";
    case VCS_ZCODE_TASK_AUTHORITY_RECIPE: return "acceptance-recipe-invalid";
    case VCS_ZCODE_TASK_AUTHORITY_MEMBERSHIP:
        return "acceptance-recipe-path-missing";
    case VCS_ZCODE_TASK_AUTHORITY_CAS: return "task-authority-cas-miss";
    case VCS_ZCODE_TASK_AUTHORITY_ACCEPTANCE_TESTS_MODIFIED:
        return "candidate-modified-acceptance-tests";
    }
    return "unknown";
}

enum vcs_zcode_task_authority_result vcs_zcode_task_authority_roots(
    const uint8_t *lock_wire, size_t lock_len,
    const uint8_t *recipe_wire, size_t recipe_len,
    uint8_t lock_root[32], uint8_t recipe_root[32])
{
    if (!lock_wire || !recipe_wire || !lock_root || !recipe_root)
        return VCS_ZCODE_TASK_AUTHORITY_NULL;
    struct vcs_package_lock lock;
    if (vcs_package_lock_parse(lock_wire, lock_len, &lock) !=
            VCS_PACKAGE_DEPS_OK || lock.count == 0 ||
        vcs_package_lock_root(&lock, lock_root) != VCS_PACKAGE_DEPS_OK)
        return VCS_ZCODE_TASK_AUTHORITY_LOCK;
    struct vcs_package_recipe recipe;
    if (vcs_package_recipe_parse(recipe_wire, recipe_len, &recipe) !=
            VCS_PACKAGE_RECIPE_OK)
        return VCS_ZCODE_TASK_AUTHORITY_RECIPE;
    enum vcs_package_recipe_error rooted = vcs_package_recipe_root(
        &recipe, recipe_root);
    vcs_package_recipe_free(&recipe);
    return rooted == VCS_PACKAGE_RECIPE_OK
        ? VCS_ZCODE_TASK_AUTHORITY_OK : VCS_ZCODE_TASK_AUTHORITY_RECIPE;
}

enum vcs_zcode_task_authority_result vcs_zcode_task_authority_store(
    const char *repo_root, const uint8_t *lock_wire, size_t lock_wire_len,
    const uint8_t *recipe_wire, size_t recipe_wire_len,
    uint8_t lock_root[32], uint8_t recipe_root[32])
{
    if (!repo_root || !lock_wire || !recipe_wire || !lock_root ||
        !recipe_root)
        return VCS_ZCODE_TASK_AUTHORITY_NULL;
    enum vcs_zcode_task_authority_result result = vcs_zcode_task_authority_roots(
        lock_wire, lock_wire_len, recipe_wire, recipe_wire_len,
        lock_root, recipe_root);
    if (result != VCS_ZCODE_TASK_AUTHORITY_OK) return result;
    if (!vcs_object_store_init(repo_root) ||
        !vcs_object_put_addressed_repair(
            repo_root, lock_root, lock_wire, lock_wire_len, NULL) ||
        !vcs_object_put_addressed_repair(
            repo_root, recipe_root, recipe_wire, recipe_wire_len, NULL))
        return VCS_ZCODE_TASK_AUTHORITY_CAS;
    uint8_t *lock_check = NULL, *recipe_check = NULL;
    size_t lock_check_len = 0, recipe_check_len = 0;
    bool loaded = vcs_object_load_raw(
            repo_root, lock_root, &lock_check, &lock_check_len) == 0 &&
        vcs_object_load_raw(
            repo_root, recipe_root, &recipe_check, &recipe_check_len) == 0 &&
        lock_check_len == lock_wire_len && recipe_check_len == recipe_wire_len &&
        memcmp(lock_check, lock_wire, lock_wire_len) == 0 &&
        memcmp(recipe_check, recipe_wire, recipe_wire_len) == 0;
    uint8_t checked_lock[32], checked_recipe[32];
    result = loaded ? vcs_zcode_task_authority_roots(
        lock_check, lock_check_len, recipe_check, recipe_check_len,
        checked_lock, checked_recipe) : VCS_ZCODE_TASK_AUTHORITY_CAS;
    free(recipe_check); free(lock_check);
    return result == VCS_ZCODE_TASK_AUTHORITY_OK &&
           memcmp(checked_lock, lock_root, 32) == 0 &&
           memcmp(checked_recipe, recipe_root, 32) == 0
        ? VCS_ZCODE_TASK_AUTHORITY_OK : VCS_ZCODE_TASK_AUTHORITY_CAS;
}

static const struct vcs_entry *task_authority_entry(
    const struct vcs_manifest *manifest, const char *path)
{
    size_t lo = 0, hi = manifest->count;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2u;
        int cmp = strcmp(manifest->entries[mid].path, path);
        if (cmp == 0) return &manifest->entries[mid];
        if (cmp < 0) lo = mid + 1u; else hi = mid;
    }
    return NULL;
}

/* VCS_ZCODE_ACCEPTANCE_TESTS_BYTES_DOMAIN over the recipe root and the exact
 * manifest entry of every recipe test source. Membership was already
 * checked; a missing entry still fails closed. */
static bool task_authority_tests_bytes_root(
    const struct vcs_package_recipe *recipe, const uint8_t recipe_root[32],
    const struct vcs_manifest *manifest, uint8_t out[32])
{
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    static const char domain[] = VCS_ZCODE_ACCEPTANCE_TESTS_BYTES_DOMAIN;
    sha3_256_write(&sha, (const uint8_t *)domain, sizeof(domain));
    sha3_256_write(&sha, recipe_root, 32);
    uint8_t scalar[8];
    vcs_wr_u16le(scalar, (uint16_t)recipe->test_sources.count);
    sha3_256_write(&sha, scalar, 2);
    for (size_t i = 0; i < recipe->test_sources.count; i++) {
        const char *path = recipe->test_sources.items[i];
        const struct vcs_entry *entry = task_authority_entry(manifest, path);
        if (!entry) return false;
        size_t path_len = strlen(path);
        vcs_wr_u16le(scalar, (uint16_t)path_len);
        sha3_256_write(&sha, scalar, 2);
        sha3_256_write(&sha, (const uint8_t *)path, path_len);
        vcs_wr_u32le(scalar, entry->mode);
        sha3_256_write(&sha, scalar, 4);
        vcs_wr_u64le(scalar, entry->size);
        sha3_256_write(&sha, scalar, 8);
        sha3_256_write(&sha, entry->blob, 32);
    }
    sha3_256_finalize(&sha, out);
    return true;
}

/* Recipe membership in one exact source tree, then that tree's
 * acceptance-tests bytes root. */
static enum vcs_zcode_task_authority_result task_authority_tree_tests(
    const char *repo_root, const struct vcs_package_recipe *recipe,
    const uint8_t recipe_root[32], const uint8_t source_root[32],
    uint8_t tests_root[32])
{
    struct vcs_manifest manifest;
    if (!vcs_tree_load(repo_root, source_root, &manifest))
        return VCS_ZCODE_TASK_AUTHORITY_CAS;
    char detail[160];
    bool ok = vcs_package_recipe_files_in_vcs_manifest(
            recipe, &manifest, detail, sizeof(detail)) &&
        task_authority_tests_bytes_root(
            recipe, recipe_root, &manifest, tests_root);
    vcs_manifest_free(&manifest);
    return ok ? VCS_ZCODE_TASK_AUTHORITY_OK
              : VCS_ZCODE_TASK_AUTHORITY_MEMBERSHIP;
}

static enum vcs_zcode_task_authority_result task_authority_validate_tree(
    const char *repo_root, const struct vcs_zcode_task_v1 *task,
    const uint8_t source_root[32], uint8_t tests_root[32])
{
    uint8_t *lock_wire = NULL, *recipe_wire = NULL;
    size_t lock_len = 0, recipe_len = 0;
    if (vcs_object_load_raw(repo_root, task->dependency_lock_root,
                            &lock_wire, &lock_len) != 0 ||
        vcs_object_load_raw(repo_root, task->acceptance_tests_root,
                            &recipe_wire, &recipe_len) != 0) {
        free(recipe_wire); free(lock_wire);
        return VCS_ZCODE_TASK_AUTHORITY_CAS;
    }
    uint8_t lock_root[32], recipe_root[32];
    enum vcs_zcode_task_authority_result result = vcs_zcode_task_authority_roots(
        lock_wire, lock_len, recipe_wire, recipe_len, lock_root, recipe_root);
    if (result == VCS_ZCODE_TASK_AUTHORITY_OK &&
        (memcmp(lock_root, task->dependency_lock_root, 32) != 0 ||
         memcmp(recipe_root, task->acceptance_tests_root, 32) != 0))
        result = VCS_ZCODE_TASK_AUTHORITY_CAS;
    struct vcs_package_recipe recipe;
    bool parsed = result == VCS_ZCODE_TASK_AUTHORITY_OK &&
        vcs_package_recipe_parse(recipe_wire, recipe_len, &recipe) ==
            VCS_PACKAGE_RECIPE_OK;
    if (parsed) {
        result = task_authority_tree_tests(
            repo_root, &recipe, recipe_root, source_root, tests_root);
        vcs_package_recipe_free(&recipe);
    } else if (result == VCS_ZCODE_TASK_AUTHORITY_OK) {
        result = VCS_ZCODE_TASK_AUTHORITY_CAS;
    }
    free(recipe_wire); free(lock_wire);
    return result;
}

enum vcs_zcode_task_authority_result vcs_zcode_task_acceptance_tests_bytes_root(
    const char *repo_root, const struct vcs_zcode_task_v1 *task,
    uint8_t out[32])
{
    if (!repo_root || !task || !out) return VCS_ZCODE_TASK_AUTHORITY_NULL;
    return task_authority_validate_tree(
        repo_root, task, task->source_root, out);
}

enum vcs_zcode_task_authority_result vcs_zcode_task_authority_validate(
    const char *repo_root, const struct vcs_zcode_task_v1 *task)
{
    uint8_t tests_root[32];
    return vcs_zcode_task_acceptance_tests_bytes_root(
        repo_root, task, tests_root);
}

/* The candidate is judged by the task's tests: its tree must carry the
 * exact recipe test-source entries of the task's base tree. */
enum vcs_zcode_task_authority_result
vcs_zcode_task_authority_validate_for_candidate(
    const char *repo_root, const struct vcs_zcode_task_v1 *task,
    const struct vcs_zcode_candidate_v1 *candidate)
{
    if (!repo_root || !task || !candidate)
        return VCS_ZCODE_TASK_AUTHORITY_NULL;
    uint8_t base_tests[32], candidate_tests[32];
    enum vcs_zcode_task_authority_result result =
        vcs_zcode_task_acceptance_tests_bytes_root(
            repo_root, task, base_tests);
    if (result == VCS_ZCODE_TASK_AUTHORITY_OK)
        result = task_authority_validate_tree(
            repo_root, task, candidate->candidate_source_root,
            candidate_tests);
    if (result == VCS_ZCODE_TASK_AUTHORITY_OK &&
        memcmp(base_tests, candidate_tests, 32) != 0)
        result = VCS_ZCODE_TASK_AUTHORITY_ACCEPTANCE_TESTS_MODIFIED;
    return result;
}
