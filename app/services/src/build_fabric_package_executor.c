/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Materialize and verify whole C23 packages from immutable ZCODE inputs. */

#include "services/build_fabric_package_executor.h"

#include "base/hex.h"
#include "crypto/sha3.h"
#include "util/file_tree_ops.h"
#include "util/safe_alloc.h"
#include "vcs/build_artifact_manifest.h"
#include "vcs/build_action.h"
#include "vcs/package_manifest.h"
#include "vcs/package_recipe.h"
#include "vcs/source_bundle.h"
#include "vcs/vcs.h"
#include "vcs/vcs_object.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define BFP_PATH_MAX BUILD_FABRIC_PACKAGE_PATH_MAX

static bool bfp_write(const char *path, const uint8_t *bytes, size_t len)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0400);
    if (fd < 0) return false;
    size_t off = 0;
    while (off < len) {
        ssize_t wrote = write(fd, bytes + off, len - off);
        if (wrote < 0 && errno == EINTR) continue;
        if (wrote <= 0) break;
        off += (size_t)wrote;
    }
    bool synced = off == len && fsync(fd) == 0;
    bool closed = close(fd) == 0;
    bool ok = synced && closed;
    if (!ok) (void)unlink(path);
    return ok;
}

static uint8_t *bfp_read(const char *path, size_t *len_out)
{
    *len_out = 0;
    struct stat st;
    if (stat(path, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size <= 0 ||
        (uint64_t)st.st_size > VCS_BUILD_ARTIFACT_MAX_BYTES)
        return NULL;
    size_t len = (size_t)st.st_size;
    uint8_t *bytes = zcl_malloc(len, "zbuild.package-read");
    if (!bytes)
        return NULL;
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        free(bytes);
        return NULL;
    }
    size_t off = 0;
    while (off < len) {
        ssize_t got = read(fd, bytes + off, len - off);
        if (got < 0 && errno == EINTR)
            continue;
        if (got <= 0)
            break;
        off += (size_t)got;
    }
    close(fd);
    if (off != len) {
        free(bytes);
        return NULL;
    }
    *len_out = len;
    return bytes;
}

static bool bfp_sha3_file(const char *path, uint8_t out[32],
                          uint64_t *bytes_out)
{
    struct stat st;
    if (lstat(path, &st) != 0 || !S_ISREG(st.st_mode))
        return false;
    FILE *f = fopen(path, "rb");
    if (!f)
        return false;
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    uint8_t buf[65536];
    uint64_t total = 0;
    size_t got;
    while ((got = fread(buf, 1, sizeof(buf), f)) > 0) {
        sha3_256_write(&sha, buf, got);
        total += got;
    }
    bool ok = ferror(f) == 0 && fclose(f) == 0;
    if (!ok)
        return false;
    sha3_256_finalize(&sha, out);
    *bytes_out = total;
    return true;
}

static struct zcl_result bfp_materialize_tree(
    const char *workspace, const struct vcs_zcode_candidate_v1 *candidate,
    const char *destination)
{
    int result = vcs_tree_materialize(
        workspace, candidate->candidate_source_root, destination,
        VCS_SOURCE_BUNDLE_MAX_SOURCE_BYTES, 0400u);
    return result == VCS_OK
        ? ZCL_OK : ZCL_ERR(-1, "candidate-tree-materialize-failed: %d", result);
}

static struct zcl_result bfp_verify_dependency(
    const char *dir, const uint8_t expected_root[32])
{
    char report_path[BFP_PATH_MAX];
    int n = snprintf(report_path, sizeof(report_path), "%s/build-report", dir);
    if (n <= 0 || (size_t)n >= sizeof(report_path))
        return ZCL_ERR(-1, "dependency-build-report-path-too-long");
    size_t wire_len = 0;
    uint8_t *wire = bfp_read(report_path, &wire_len);
    struct vcs_package_build_receipt receipt;
    enum vcs_package_build_error parsed = wire &&
            wire_len <= VCS_PACKAGE_BUILD_MAX_WIRE_BYTES
        ? vcs_package_build_parse(wire, wire_len, &receipt)
        : VCS_PACKAGE_BUILD_ERR_WIRE_OVERSIZE;
    free(wire);
    if (parsed != VCS_PACKAGE_BUILD_OK ||
        memcmp(receipt.package_root, expected_root, 32) != 0 ||
        !vcs_package_build_installable(&receipt))
        return ZCL_ERR(-1, "dependency-build-report-refused");
    for (size_t i = 0; i < receipt.output_count; i++) {
        char path[BFP_PATH_MAX];
        uint8_t sha[32];
        uint64_t bytes = 0;
        n = snprintf(path, sizeof(path), "%s/%s", dir,
                     receipt.outputs[i].path);
        if (n <= 0 || (size_t)n >= sizeof(path) ||
            !bfp_sha3_file(path, sha, &bytes) ||
            bytes != receipt.outputs[i].bytes ||
            memcmp(sha, receipt.outputs[i].sha3, 32) != 0)
            return ZCL_ERR(-1, "dependency-output-mismatch: %s",
                           receipt.outputs[i].path);
    }
    return ZCL_OK;
}

static void bfp_free_recipe(uint8_t **wire, size_t *wire_len)
{
    free(*wire);
    *wire = NULL;
    *wire_len = 0;
}

static struct zcl_result bfp_load_inputs(
    const char *workspace, const char *datadir,
    const struct vcs_zcode_task_v1 *task,
    struct build_fabric_package_execution *out, uint8_t **recipe_wire,
    size_t *recipe_wire_len, char package_name[VCS_PACKAGE_RELEASE_NAME_MAX + 1u])
{
    uint8_t *lock_wire = NULL;
    size_t lock_wire_len = 0;
    if (vcs_object_load_raw(workspace, task->dependency_lock_root,
                            &lock_wire, &lock_wire_len) != 0 ||
        vcs_package_lock_parse(lock_wire, lock_wire_len, &out->lock) !=
            VCS_PACKAGE_DEPS_OK) {
        free(lock_wire);
        return ZCL_ERR(-1, "package-dependency-lock-cas-miss-or-corrupt");
    }
    free(lock_wire);
    uint8_t checked_lock[32];
    if (out->lock.count == 0 ||
        vcs_package_lock_root(&out->lock, checked_lock) !=
            VCS_PACKAGE_DEPS_OK ||
        memcmp(checked_lock, task->dependency_lock_root, 32) != 0 ||
        out->lock.nodes[out->lock.count - 1u].depth != 0 ||
        out->lock.nodes[out->lock.count - 1u].name[0] == '\0')
        return ZCL_ERR(-1, "package-dependency-lock-target-mismatch");
    (void)snprintf(package_name, VCS_PACKAGE_RELEASE_NAME_MAX + 1u, "%s",
                   out->lock.nodes[out->lock.count - 1u].name);
    if (!package_name[0])
        return ZCL_ERR(-1, "package-lock-target-name-missing");
    if (vcs_object_load_raw(workspace, task->acceptance_tests_root,
                            recipe_wire, recipe_wire_len) != 0)
        return ZCL_ERR(-1, "package-recipe-cas-miss");
    struct vcs_package_recipe recipe;
    uint8_t checked_recipe[32];
    enum vcs_package_recipe_error parsed = vcs_package_recipe_parse(
        *recipe_wire, *recipe_wire_len, &recipe);
    if (parsed != VCS_PACKAGE_RECIPE_OK ||
        vcs_package_recipe_root(&recipe, checked_recipe) !=
            VCS_PACKAGE_RECIPE_OK ||
        memcmp(checked_recipe, task->acceptance_tests_root, 32) != 0) {
        if (parsed == VCS_PACKAGE_RECIPE_OK)
            vcs_package_recipe_free(&recipe);
        bfp_free_recipe(recipe_wire, recipe_wire_len);
        return ZCL_ERR(-1, "package-recipe-root-mismatch");
    }
    vcs_package_recipe_free(&recipe);
    char datadir_resolved[BFP_PATH_MAX];
    if (!realpath(datadir, datadir_resolved)) {
        bfp_free_recipe(recipe_wire, recipe_wire_len);
        return ZCL_ERR(-1, "package-datadir-cannot-resolve");
    }
    out->dep_count = out->lock.count - 1u;
    for (size_t i = 0; i < out->dep_count; i++) {
        char root_hex[65];
        char expected[BFP_PATH_MAX];
        char resolved[BFP_PATH_MAX];
        zcl_hex_encode(out->lock.nodes[i].root, 32, root_hex);
        int n = snprintf(expected, sizeof(expected),
                         "%s/zcode/installed/%s", datadir_resolved, root_hex);
        if (n <= 0 || (size_t)n >= sizeof(expected) ||
            !realpath(expected, resolved) || strcmp(expected, resolved) != 0) {
            bfp_free_recipe(recipe_wire, recipe_wire_len);
            return ZCL_ERR(-1, "locked-dependency-not-installed: %s",
                           root_hex);
        }
        struct zcl_result verified = bfp_verify_dependency(
            resolved, out->lock.nodes[i].root);
        if (!verified.ok) {
            bfp_free_recipe(recipe_wire, recipe_wire_len);
            return verified;
        }
        (void)snprintf(out->dep_dirs[i], sizeof(out->dep_dirs[i]), "%s",
                       resolved);
    }
    return ZCL_OK;
}

struct zcl_result build_fabric_package_prepare(
    const char *workspace, const char *datadir, const char *worker,
    const char *source_dir, const char *emit_dir, const char *recipe_path,
    const char *profile,
    const struct vcs_zcode_task_v1 *task,
    const struct vcs_zcode_candidate_v1 *candidate,
    struct build_fabric_package_execution *out)
{
    if (!workspace || !datadir || !worker || !source_dir || !emit_dir ||
        !recipe_path || !profile || !task || !candidate || !out)
        return ZCL_ERR(-1, "package execution requires closed inputs");
    bool standard =
        strcmp(profile, VCS_BUILD_PACKAGE_PROFILE_STANDARD_A_V1) == 0 ||
        strcmp(profile, VCS_BUILD_PACKAGE_PROFILE_STANDARD_B_V1) == 0;
    memset(out, 0, sizeof(*out));
    uint8_t *recipe_wire = NULL;
    size_t recipe_wire_len = 0;
    char package_name[VCS_PACKAGE_RELEASE_NAME_MAX + 1u];
    struct zcl_result loaded = bfp_load_inputs(
        workspace, datadir, task, out, &recipe_wire, &recipe_wire_len,
        package_name);
    if (!loaded.ok)
        return loaded;
    struct zcl_result tree = bfp_materialize_tree(
        workspace, candidate, source_dir);
    if (!tree.ok || !bfp_write(recipe_path, recipe_wire, recipe_wire_len)) {
        bfp_free_recipe(&recipe_wire, &recipe_wire_len);
        return tree.ok ? ZCL_ERR(-1, "package-recipe-materialize-failed")
                       : tree;
    }
    bfp_free_recipe(&recipe_wire, &recipe_wire_len);
    char lock_hex[65];
    zcl_hex_encode(candidate->candidate_source_root, 32, out->source_root_hex);
    zcl_hex_encode(task->dependency_lock_root, 32, lock_hex);
    (void)snprintf(out->source_arg, sizeof(out->source_arg),
                   "--zbuild-package-source=%s", source_dir);
    (void)snprintf(out->recipe_arg, sizeof(out->recipe_arg),
                   "--zbuild-package-recipe=%s", recipe_path);
    (void)snprintf(out->name_arg, sizeof(out->name_arg),
                   "--zbuild-package-name=%s", package_name);
    (void)snprintf(out->profile_arg, sizeof(out->profile_arg),
                   "--zbuild-package-profile=%s",
                   standard ? "standard" : "quick");
    (void)snprintf(out->cpu_arg, sizeof(out->cpu_arg),
                   "--zbuild-package-max-cpu-seconds=%u",
                   task->max_cpu_seconds);
    (void)snprintf(out->emit_arg, sizeof(out->emit_arg), "--emit=%s", emit_dir);
    (void)snprintf(out->lock_arg, sizeof(out->lock_arg),
                   "--lock-root=%s", lock_hex);
    size_t n = 0;
    out->argv[n++] = worker;
    out->argv[n++] = out->source_root_hex;
    out->argv[n++] = out->source_arg;
    out->argv[n++] = out->recipe_arg;
    out->argv[n++] = out->name_arg;
    out->argv[n++] = out->profile_arg;
    out->argv[n++] = out->cpu_arg;
    out->argv[n++] = out->emit_arg;
    out->argv[n++] = out->lock_arg;
    for (size_t i = 0; i < out->dep_count; i++) {
        char root_hex[65];
        zcl_hex_encode(out->lock.nodes[i].root, 32, root_hex);
        (void)snprintf(out->dep_args[i], sizeof(out->dep_args[i]),
                       "--dep=%s,%s", root_hex, out->dep_dirs[i]);
        out->argv[n++] = out->dep_args[i];
    }
    out->argv[n++] = "--require-full-isolation";
    out->argv[n] = NULL;
    return ZCL_OK;
}

struct zcl_result build_fabric_package_report_parse(
    const uint8_t *wire, size_t wire_len, const char *emit_dir,
    const struct vcs_zcode_task_v1 *task,
    const struct vcs_zcode_candidate_v1 *candidate,
    const struct build_fabric_package_execution *execution,
    uint8_t *work_status, int *exit_status)
{
    struct vcs_package_build_receipt receipt;
    if (!wire || wire_len > VCS_PACKAGE_BUILD_MAX_WIRE_BYTES ||
        vcs_package_build_parse(wire, wire_len, &receipt) !=
            VCS_PACKAGE_BUILD_OK ||
        memcmp(receipt.package_root, candidate->candidate_source_root, 32) !=
            0 ||
        memcmp(receipt.recipe_root, task->acceptance_tests_root, 32) != 0 ||
        memcmp(receipt.lock_root, task->dependency_lock_root, 32) != 0 ||
        receipt.dep_count != execution->dep_count ||
        receipt.isolation != VCS_PACKAGE_BUILD_ISOLATION_FULL)
        return ZCL_ERR(-1, "package-build-report-binding-invalid");
    for (size_t i = 0; i < execution->dep_count; i++) {
        bool found = false;
        for (size_t j = 0; j < receipt.dep_count; j++)
            if (memcmp(execution->lock.nodes[i].root,
                       receipt.dep_roots[j], 32) == 0)
                found = true;
        if (!found)
            return ZCL_ERR(-1, "package-build-report-dependency-missing");
    }
    for (size_t i = 0; i < receipt.output_count; i++) {
        char path[BFP_PATH_MAX];
        uint8_t sha[32];
        uint64_t bytes = 0;
        int n = snprintf(path, sizeof(path), "%s/%s", emit_dir,
                         receipt.outputs[i].path);
        if (n <= 0 || (size_t)n >= sizeof(path) ||
            !bfp_sha3_file(path, sha, &bytes) ||
            bytes != receipt.outputs[i].bytes ||
            memcmp(sha, receipt.outputs[i].sha3, 32) != 0)
            return ZCL_ERR(-1, "package-build-report-output-mismatch");
    }
    bool passed = vcs_package_build_installable(&receipt);
    *work_status = passed ? VCS_ZCODE_WORK_PASS : VCS_ZCODE_WORK_FAIL;
    *exit_status = passed ? 0
        : receipt.test_exit_code != 0 ? (int)receipt.test_exit_code : 1;
    return ZCL_OK;
}
