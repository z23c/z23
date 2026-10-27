/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: rederive the self-hosted package DAG and its root projection. */

#include "test/test_core.h"

#include "base/hex.h"
#include "config/c23_commons_build_profile.h"
#include "core/uint256.h"
#include "keys/key.h"
#include "keys/pubkey.h"
#include "platform/os_sandbox.h"
#include "platform/directory_compat.h"
#include "services/package_lifecycle.h"
#include "util/spawn.h"
#include "vcs/package_build.h"
#include "vcs/package_checkout.h"
#include "vcs/package_publish.h"
#include "vcs/package_prepare.h"
#include "vcs/package_reproduce.h"
#include "vcs/package_store.h"

#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define REGISTRY_PACKAGE_VERIFIER "build/bin/z23-package-verify-dev"
#define REGISTRY_DOGFOOD_MAX_DEPS 8u

struct registry_expected {
    const char *name;
    const char *dir;
    uint64_t sequence;
    const char *content_root;
    const char *release_root;
    const char *recipe_root;
    const char *lock_root;
    const char *capsule_root;
    const char *publisher_pubkey;
    const char *signature;
};

#define ZCODE_PACKAGE(name, dir, sequence, content, release, recipe, lock, capsule, publisher, signature) \
    {name, dir, sequence, content, release, recipe, lock, capsule, publisher, signature},
static const struct registry_expected registry_packages[] = {
#include "../../../engine/composition/zcode_package_registry.def"
#include "../../../engine/composition/zcode_c23_commons_app.def"
};
#undef ZCODE_PACKAGE

static bool registry_prepare(const struct registry_expected *expected,
                             struct vcs_package_prepared *prepared)
{
    uint8_t pubkey[33];
    if (!zcl_hex_decode_lower(expected->publisher_pubkey, pubkey,
                              sizeof(pubkey)))
        return false;
    struct vcs_package_prepare_options options = {
        .dir = expected->dir,
        .publisher_sequence = expected->sequence,
        .reward_address = "",
        .chain_id = "zclassic-main",
    };
    memcpy(options.publisher_pubkey, pubkey, sizeof(pubkey));
    char detail[256];
    if (vcs_package_prepare(&options, prepared, detail, sizeof(detail)) !=
        VCS_PACKAGE_PREPARE_OK)
        return false;
    if (!zcl_hex_decode_lower(expected->signature,
                              prepared->release.signature,
                              sizeof(prepared->release.signature))) {
        vcs_package_prepared_free(prepared);
        return false;
    }
    return true;
}

static bool registry_publish_store(
    struct vcs_package_store *store,
    const struct vcs_package_prepared *prepared, const char *source_dir)
{
    uint8_t admitted[32];
    bool ok = vcs_package_store_put_manifest(
        store, prepared->manifest_wire, prepared->manifest_wire_len,
        admitted) == VCS_PACKAGE_STORE_OK &&
        memcmp(admitted, prepared->package_root, 32) == 0;
    uint8_t chunk[VCS_PACKAGE_CHUNK_BYTES];
    for (size_t i = 0; ok && i < prepared->manifest.count; i++) {
        const struct vcs_package_file *file = &prepared->manifest.files[i];
        for (uint32_t j = 0; ok && j < file->chunk_count; j++) {
            size_t len = 0; enum vcs_package_publish_rule rule;
            ok = vcs_package_publish_read_chunk(
                source_dir, file, j, chunk, &len, &rule) &&
                vcs_package_store_put_chunk(store, prepared->package_root,
                    file->path, j, chunk, len) == VCS_PACKAGE_STORE_OK;
        }
    }
    uint8_t recipe_root[32]; enum vcs_package_accept_result accepted;
    ok = ok && vcs_package_store_put_recipe(
        store, prepared->recipe_wire, prepared->recipe_wire_len,
        recipe_root) == VCS_PACKAGE_STORE_OK &&
        memcmp(recipe_root, prepared->recipe_root, 32) == 0 &&
        vcs_package_store_put_release(store, &prepared->release, &accepted) ==
            VCS_PACKAGE_STORE_OK && accepted == VCS_PACKAGE_ACCEPT_OK &&
        vcs_package_store_verify_possession(store, prepared->package_root,
                                            false);
    return ok;
}

static bool registry_publish_scratch(
    const struct vcs_package_prepared *prepared, const char *source_dir)
{
    char scratch[256];
    test_make_tmpdir(scratch, sizeof(scratch), "zcode_registry", "package");
    struct vcs_package_store *store = vcs_package_store_open(
        scratch, UINT64_C(256) * 1024u * 1024u);
    if (!store)
        return false;
    bool ok = registry_publish_store(store, prepared, source_dir);
    vcs_package_store_close(store);
    test_rm_rf(scratch);
    return ok;
}

static bool registry_read_receipt_path(
    const char *path,
    struct vcs_package_build_receipt *receipt)
{
    uint8_t wire[VCS_PACKAGE_BUILD_MAX_WIRE_BYTES];
    FILE *file = fopen(path, "rb");
    if (!file)
        return false;
    size_t wire_len = fread(wire, 1, sizeof(wire), file);
    bool ok = wire_len > 0 && feof(file) && !ferror(file);
    fclose(file);
    return ok && vcs_package_build_parse(wire, wire_len, receipt) ==
                     VCS_PACKAGE_BUILD_OK;
}

static bool registry_read_receipt(
    const char *datadir, const char *root_hex,
    struct vcs_package_build_receipt *receipt)
{
    char path[1024];
    int n = snprintf(path, sizeof(path), "%s/zcode/installed/%s/build-report",
                     datadir, root_hex);
    return n > 0 && (size_t)n < sizeof(path) &&
        registry_read_receipt_path(path, receipt);
}

static bool registry_write_bytes(const char *path, const uint8_t *bytes,
                                 size_t len)
{
    FILE *file = fopen(path, "wb");
    if (!file)
        return false;
    bool ok = fwrite(bytes, 1, len, file) == len && fflush(file) == 0;
    if (fclose(file) != 0)
        ok = false;
    return ok;
}

static bool registry_build_one(const char *datadir, const char *root_hex,
                               int64_t now_unix)
{
    struct package_lifecycle_plan_report plan;
    struct zcl_result planned =
        package_lifecycle_plan(datadir, root_hex, now_unix, &plan);
    if (!planned.ok || !plan.ready) {
        printf("  zcode_package_registry: plan %s failed rule=%s detail=%s "
               "message=%s\n", root_hex, plan.rule, plan.detail,
               planned.message);
        return false;
    }
    struct package_lifecycle_commit_report commit;
    struct zcl_result committed = package_lifecycle_commit(
        datadir, plan.plan_id, now_unix + 1, &commit);
    if (!committed.ok || !commit.installed) {
        printf("  zcode_package_registry: commit %s failed rule=%s detail=%s "
               "message=%s\n", root_hex, commit.rule, commit.detail,
               committed.message);
        return false;
    }
    return true;
}

static const struct registry_expected *registry_named(const char *name)
{
    for (size_t i = 0;
         i < sizeof(registry_packages) / sizeof(registry_packages[0]); i++)
        if (strcmp(registry_packages[i].name, name) == 0)
            return &registry_packages[i];
    return NULL;
}

struct registry_stranger_paths {
    char checkout[1024], source[1024], binary[1024];
    char app_include[1024], base_include[1024], codec_include[1024];
    char json_include[1024], app_archive[1024], base_archive[1024];
    char codec_archive[1024], json_archive[1024];
    char app_i[1100], base_i[1100], codec_i[1100], json_i[1100];
};

static bool registry_stranger_checkout(
    const char *datadir, const struct registry_expected *app,
    struct registry_stranger_paths *paths)
{
    struct vcs_package_store *store = vcs_package_store_open(
        datadir, UINT64_C(256) * 1024u * 1024u);
    uint8_t app_root[32];
    if (!store || !zcl_hex_decode_lower(app->content_root, app_root,
                                         sizeof(app_root))) {
        vcs_package_store_close(store);
        return false;
    }
    int n = snprintf(paths->checkout, sizeof(paths->checkout),
                     "%s/stranger-source", datadir);
    struct vcs_package_checkout_metrics metrics;
    enum vcs_package_checkout_result checked = n > 0 &&
            (size_t)n < sizeof(paths->checkout)
        ? vcs_package_checkout(store, app_root, paths->checkout, &metrics)
        : VCS_PACKAGE_CHECKOUT_DESTINATION;
    bool refused_existing = checked == VCS_PACKAGE_CHECKOUT_OK &&
        vcs_package_checkout(store, app_root, paths->checkout, NULL) ==
            VCS_PACKAGE_CHECKOUT_DESTINATION;
    vcs_package_store_close(store);
    if (checked != VCS_PACKAGE_CHECKOUT_OK || !refused_existing ||
        metrics.files != 6u || metrics.chunks != 6u || metrics.bytes == 0)
        return false;
    return true;
}

static bool registry_stranger_resolve_paths(
    const char *datadir, const struct registry_expected *app,
    const struct registry_expected *base,
    const struct registry_expected *codec,
    const struct registry_expected *json,
    struct registry_stranger_paths *paths)
{
    if (snprintf(paths->source, sizeof(paths->source), "%s/app/main.c",
                 paths->checkout) <= 0 ||
        snprintf(paths->binary, sizeof(paths->binary), "%s/commons-demo",
                 datadir) <= 0 ||
        snprintf(paths->app_include, sizeof(paths->app_include),
                 "%s/zcode/installed/%s/include", datadir,
                 app->content_root) <= 0 ||
        snprintf(paths->base_include, sizeof(paths->base_include),
                 "%s/zcode/installed/%s/include", datadir,
                 base->content_root) <= 0 ||
        snprintf(paths->codec_include, sizeof(paths->codec_include),
                 "%s/zcode/installed/%s/include", datadir,
                 codec->content_root) <= 0 ||
        snprintf(paths->json_include, sizeof(paths->json_include),
                 "%s/zcode/installed/%s/include", datadir,
                 json->content_root) <= 0 ||
        snprintf(paths->app_archive, sizeof(paths->app_archive),
                 "%s/zcode/installed/%s/lib/libcommons-demo.a", datadir,
                 app->content_root) <= 0 ||
        snprintf(paths->base_archive, sizeof(paths->base_archive),
                 "%s/zcode/installed/%s/lib/libbase.a", datadir,
                 base->content_root) <= 0 ||
        snprintf(paths->codec_archive, sizeof(paths->codec_archive),
                 "%s/zcode/installed/%s/lib/libcodec.a", datadir,
                 codec->content_root) <= 0 ||
        snprintf(paths->json_archive, sizeof(paths->json_archive),
                 "%s/zcode/installed/%s/lib/libjson.a", datadir,
                 json->content_root) <= 0)
        return false;
    if (access(paths->binary, F_OK) == 0)
        return false;
    return true;
}

static bool registry_stranger_include_flags(
    struct registry_stranger_paths *paths)
{
    if (snprintf(paths->app_i, sizeof(paths->app_i), "-I%s",
                 paths->app_include) <= 0 ||
        snprintf(paths->base_i, sizeof(paths->base_i), "-I%s",
                 paths->base_include) <= 0 ||
        snprintf(paths->codec_i, sizeof(paths->codec_i), "-I%s",
                 paths->codec_include) <= 0 ||
        snprintf(paths->json_i, sizeof(paths->json_i), "-I%s",
                 paths->json_include) <= 0)
        return false;
    return true;
}

static bool registry_stranger_build(const char *datadir)
{
    const struct registry_expected *app =
        registry_named("zclassic23/commons-demo");
    const struct registry_expected *base = registry_named("zclassic23/base");
    const struct registry_expected *codec =
        registry_named("zclassic23/codec");
    const struct registry_expected *json = registry_named("zclassic23/json");
    if (!app || !base || !codec || !json)
        return false;

    struct registry_stranger_paths paths;
    bool ok = registry_stranger_checkout(datadir, app, &paths);
    if (ok)
        ok = registry_stranger_resolve_paths(datadir, app, base, codec, json,
                                             &paths);
    if (ok)
        ok = registry_stranger_include_flags(&paths);
    char output[1024];
    if (ok) {
        const char *compile_argv[] = {
            "cc", "-std=c23", "-O1", "-D_POSIX_C_SOURCE=200809L",
            paths.app_i, paths.base_i, paths.codec_i, paths.json_i,
            paths.source, paths.app_archive, paths.json_archive,
            paths.codec_archive, paths.base_archive, "-o", paths.binary, NULL,
        };
        int compile_rc = zcl_spawn_capture(compile_argv, output,
                                           sizeof(output), 30000);
        if (compile_rc != 0) {
            printf("  zcode_package_registry: stranger compile failed rc=%d %s\n",
                   compile_rc, output);
            ok = false;
        }
    }
    if (ok) {
        const char *run_argv[] = {paths.binary, NULL};
        int run_rc = zcl_spawn_capture(run_argv, output, sizeof(output), 3000);
        if (run_rc != 0 ||
            strcmp(output, "commons|3|030000000700636f6d6d6f6e73\n") != 0) {
            printf("  zcode_package_registry: stranger run failed rc=%d %s\n",
                   run_rc, output);
            ok = false;
        }
    }
    return ok;
}

static bool registry_archive_root(
    const struct vcs_package_build_receipt *receipt, char out[65])
{
    const uint8_t *root = NULL;
    for (size_t i = 0; i < receipt->output_count; i++) {
        const char *path = receipt->outputs[i].path;
        size_t len = strlen(path);
        if (strncmp(path, "lib/", 4) == 0 && len > 2u &&
            strcmp(path + len - 2u, ".a") == 0) {
            if (root)
                return false;
            root = receipt->outputs[i].sha3;
        }
    }
    if (!root)
        return false;
    zcl_hex_encode(root, 32, out);
    return true;
}

struct registry_dogfood_run {
    char source_abs[PATH_MAX], recipe_path[PATH_MAX], emit_dir[PATH_MAX];
    char source_arg[PATH_MAX + 64u], recipe_arg[PATH_MAX + 64u];
    char name_arg[VCS_PACKAGE_RELEASE_NAME_MAX + 64u];
    char profile_arg[80], cpu_arg[64], emit_arg[PATH_MAX + 32u];
    char lock_arg[96];
    char dep_args[REGISTRY_DOGFOOD_MAX_DEPS][PATH_MAX + 96u];
    const char *argv[REGISTRY_DOGFOOD_MAX_DEPS + 13u];
    size_t argc;
};

static bool registry_dogfood_receipt_matches(
    const char *datadir, const struct registry_expected *expected,
    const struct vcs_package_prepared *prepared,
    struct vcs_package_build_receipt *decentralized)
{
    bool ok = prepared->lock.count > 0 &&
        prepared->lock.count - 1u <= REGISTRY_DOGFOOD_MAX_DEPS &&
        memcmp(prepared->lock.nodes[prepared->lock.count - 1u].root,
               prepared->package_root, 32) == 0;
    if (ok)
        ok = registry_read_receipt(datadir, expected->content_root,
                                   decentralized) &&
             decentralized->dep_count == prepared->lock.count - 1u;
    for (size_t i = 0; ok && i < decentralized->dep_count; i++)
        ok = memcmp(decentralized->dep_roots[i],
                    prepared->lock.nodes[i].root, 32) == 0;
    return ok;
}

static bool registry_dogfood_prepare_paths(
    bool ok, const char *scratch, const struct registry_expected *expected,
    const struct vcs_package_prepared *prepared,
    struct registry_dogfood_run *run)
{
    char scratch_abs[PATH_MAX];
    if (ok)
        ok = platform_directory_canonical_real(
                 scratch, scratch_abs, sizeof(scratch_abs)) &&
             platform_directory_canonical_real(
                 expected->dir, run->source_abs, sizeof(run->source_abs));
    if (ok) {
        int rn = snprintf(run->recipe_path, sizeof(run->recipe_path),
                          "%s/recipe.wire", scratch_abs);
        int en = snprintf(run->emit_dir, sizeof(run->emit_dir), "%s/emit",
                          scratch_abs);
        ok = rn > 0 && (size_t)rn < sizeof(run->recipe_path) &&
             en > 0 && (size_t)en < sizeof(run->emit_dir) &&
             registry_write_bytes(run->recipe_path, prepared->recipe_wire,
                                  prepared->recipe_wire_len);
    }
    return ok;
}

static bool registry_dogfood_arg_strings(
    const struct vcs_package_build_receipt *decentralized,
    const struct registry_expected *expected,
    struct registry_dogfood_run *run)
{
    char lock_hex[65];
    /* The installed receipt carries the lifecycle's fully resolved DAG
     * lock. prepare() deliberately has only the package-local direct
     * declarations available, so its projection lock is not the build
     * closure when a dependency itself has dependencies. */
    zcl_hex_encode(decentralized->lock_root, 32, lock_hex);
    int sn = snprintf(run->source_arg, sizeof(run->source_arg),
                      "--zbuild-package-source=%s", run->source_abs);
    int rn = snprintf(run->recipe_arg, sizeof(run->recipe_arg),
                      "--zbuild-package-recipe=%s", run->recipe_path);
    int nn = snprintf(run->name_arg, sizeof(run->name_arg),
                      "--zbuild-package-name=%s", expected->name);
    int pn = snprintf(run->profile_arg, sizeof(run->profile_arg),
                      "--zbuild-package-profile=quick");
    int cn = snprintf(run->cpu_arg, sizeof(run->cpu_arg),
                      "--zbuild-package-max-cpu-seconds=600");
    int en = snprintf(run->emit_arg, sizeof(run->emit_arg), "--emit=%s",
                      run->emit_dir);
    int ln = snprintf(run->lock_arg, sizeof(run->lock_arg),
                      "--lock-root=%s", lock_hex);
    return sn > 0 && (size_t)sn < sizeof(run->source_arg) &&
           rn > 0 && (size_t)rn < sizeof(run->recipe_arg) &&
           nn > 0 && (size_t)nn < sizeof(run->name_arg) &&
           pn > 0 && (size_t)pn < sizeof(run->profile_arg) &&
           cn > 0 && (size_t)cn < sizeof(run->cpu_arg) &&
           en > 0 && (size_t)en < sizeof(run->emit_arg) &&
           ln > 0 && (size_t)ln < sizeof(run->lock_arg);
}

static bool registry_dogfood_build_argv(
    struct registry_dogfood_run *run, const char *datadir,
    const struct registry_expected *expected,
    const struct vcs_package_prepared *prepared)
{
    bool ok = true;
    run->argv[run->argc++] = REGISTRY_PACKAGE_VERIFIER;
    run->argv[run->argc++] = expected->content_root;
    run->argv[run->argc++] = run->source_arg;
    run->argv[run->argc++] = run->recipe_arg;
    run->argv[run->argc++] = run->name_arg;
    run->argv[run->argc++] = run->profile_arg;
    run->argv[run->argc++] = run->cpu_arg;
    run->argv[run->argc++] = run->emit_arg;
    run->argv[run->argc++] = run->lock_arg;
    for (size_t i = 0; ok && i + 1u < prepared->lock.count; i++) {
        char dep_hex[65], installed[PATH_MAX];
        zcl_hex_encode(prepared->lock.nodes[i].root, 32, dep_hex);
        int in = snprintf(installed, sizeof(installed),
                          "%s/zcode/installed/%s", datadir, dep_hex);
        int dn = in > 0 && (size_t)in < sizeof(installed)
            ? snprintf(run->dep_args[i], sizeof(run->dep_args[i]),
                       "--dep=%s,%s", dep_hex, installed) : -1;
        ok = dn > 0 && (size_t)dn < sizeof(run->dep_args[i]);
        if (ok)
            run->argv[run->argc++] = run->dep_args[i];
    }
    /* Landlock is Linux-only; on macOS the decentralized build already
     * runs degraded, so requiring full isolation here would make the
     * dogfood comparison impossible.  Degraded-to-degraded is still an
     * apples-to-apples check of the same recipe, lock and compiler. */
    if (os_sandbox_landlock_abi() >= 1)
        run->argv[run->argc++] = "--require-full-isolation";
    run->argv[run->argc] = NULL;
    return ok;
}

static int registry_dogfood_report_path(
    const struct registry_dogfood_run *run, char *out, size_t cap)
{
    return snprintf(out, cap, "%s/build-report", run->emit_dir);
}

static bool registry_dogfood_compare_reproduction(
    struct vcs_package_build_receipt *repository,
    struct vcs_package_build_receipt *decentralized, char artifact_root[65],
    struct vcs_reproduce_verdict *verdict)
{
    vcs_package_reproduce_compare(repository, decentralized, verdict);
    return verdict->reproduced &&
           strcmp(repository->compiler_id, decentralized->compiler_id) == 0 &&
           strcmp(repository->compiler_version,
                  decentralized->compiler_version) == 0 &&
           strcmp(repository->flags, decentralized->flags) == 0 &&
           strcmp(repository->flags,
                  ZCL_C23_COMMONS_BUILD_FLAGS_QUICK_V2) == 0 &&
           repository->isolation == decentralized->isolation &&
           repository->test_ran && decentralized->test_ran &&
           registry_archive_root(repository, artifact_root);
}

/* Build one real monolith-owned module straight from its ordinary repository
 * source root, then compare that result with the independently materialized
 * decentralized package build. Both consume the same canonical recipe,
 * dependency lock, installed dependency roots, compiler and quick profile. */
static bool registry_dogfood_consumer(
    const char *datadir, const struct registry_expected *expected,
    char artifact_root[65])
{
    struct vcs_package_prepared prepared;
    if (!registry_prepare(expected, &prepared))
        return false;
    struct vcs_package_build_receipt decentralized;
    bool ok = registry_dogfood_receipt_matches(datadir, expected, &prepared,
                                               &decentralized);

    char scratch[256];
    struct registry_dogfood_run run = {0};
    test_make_tmpdir(scratch, sizeof(scratch), "zcode_registry", "dogfood");
    ok = registry_dogfood_prepare_paths(ok, scratch, expected, &prepared,
                                        &run);
    if (ok)
        ok = registry_dogfood_arg_strings(&decentralized, expected, &run);
    if (ok)
        ok = registry_dogfood_build_argv(&run, datadir, expected, &prepared);

    char output[4096];
    int run_rc = ok ? zcl_spawn_capture(
        run.argv, output, sizeof(output), 300000) : -1;
    if (run_rc != 0) {
        printf("  zcode_package_registry: repo-source build %s failed "
               "rc=%d %s\n", expected->name, run_rc, ok ? output : "shape");
        ok = false;
    }
    struct vcs_package_build_receipt repository;
    char candidate_report[PATH_MAX];
    int cn = registry_dogfood_report_path(&run, candidate_report,
                                          sizeof(candidate_report));
    if (ok)
        ok = cn > 0 && (size_t)cn < sizeof(candidate_report) &&
             registry_read_receipt_path(candidate_report, &repository);
    struct vcs_reproduce_verdict verdict;
    if (ok) {
        ok = registry_dogfood_compare_reproduction(&repository, &decentralized,
                                                   artifact_root, &verdict);
        if (!ok) {
            char repo_lock[65], decentralized_lock[65], prepared_lock[65];
            zcl_hex_encode(repository.lock_root, 32, repo_lock);
            zcl_hex_encode(decentralized.lock_root, 32, decentralized_lock);
            zcl_hex_encode(prepared.lock_root, 32, prepared_lock);
            printf("  zcode_package_registry: dogfood %s diverged "
                   "rule=%s detail=%s repository_lock=%s "
                   "decentralized_lock=%s prepared_lock=%s\n",
                   expected->name,
                   vcs_reproduce_rule_string(
                       (enum vcs_reproduce_rule)verdict.rule),
                   verdict.detail, repo_lock, decentralized_lock,
                   prepared_lock);
        }
    }
    test_rm_rf(scratch);
    vcs_package_prepared_free(&prepared);
    return ok;
}

static bool registry_dogfood(const char *datadir)
{
    const struct registry_expected *package =
        registry_named("zclassic23/package");
    const struct registry_expected *json =
        registry_named("zclassic23/json");
    char package_artifact[65], json_artifact[65];
    bool ok = package && json &&
        registry_dogfood_consumer(datadir, package, package_artifact) &&
        registry_dogfood_consumer(datadir, json, json_artifact);
    if (ok)
        printf("{\"schema\":\"zcl.c23_commons_dogfood.v1\","
               "\"consumer_count\":2,\"profile\":\"quick-v1\","
               "\"repository_source_roots\":true,"
               "\"decentralized_source_roots\":true,"
               "\"compiler_identity_equal\":true,"
               "\"artifact_roots_equal\":true,"
               "\"consumers\":[{\"name\":\"%s\","
               "\"archive_root\":\"%s\"},{\"name\":\"%s\","
               "\"archive_root\":\"%s\"}]}\n",
               package->name, package_artifact, json->name, json_artifact);
    return ok;
}

static bool registry_graph_shape(const char *datadir,
                                 size_t *levels_out,
                                 size_t *closure_out)
{
    const struct registry_expected *app =
        registry_named("zclassic23/commons-demo");
    if (!app || !levels_out || !closure_out) {
        printf("  zcode_package_registry: graph inputs missing app=%s "
               "levels=%s closure=%s\n", app ? "present" : "missing",
               levels_out ? "present" : "missing",
               closure_out ? "present" : "missing");
        return false;
    }
    struct package_lifecycle_plan_report plan;
    struct zcl_result planned = package_lifecycle_plan(
        datadir, app->content_root, INT64_C(1700000900), &plan);
    if (!planned.ok || !plan.ready || plan.plan.step_count < 4u) {
        printf("  zcode_package_registry: graph plan failed ready=%s "
               "steps=%zu rule=%s detail=%s message=%s\n",
               plan.ready ? "true" : "false", plan.plan.step_count,
               plan.rule, plan.detail, planned.message);
        return false;
    }
    uint16_t maximum_depth = 0;
    for (size_t i = 0; i < plan.plan.step_count; i++)
        if (plan.plan.steps[i].depth > maximum_depth)
            maximum_depth = plan.plan.steps[i].depth;
    *levels_out = (size_t)maximum_depth + 1u;
    *closure_out = plan.plan.step_count;
    if (*levels_out < 3u) {
        printf("  zcode_package_registry: graph too shallow levels=%zu "
               "closure=%zu\n", *levels_out, *closure_out);
        for (size_t i = 0; i < plan.plan.step_count; i++)
            printf("    step=%zu depth=%u name=%s\n", i,
                   (unsigned)plan.plan.steps[i].depth,
                   plan.plan.steps[i].name);
    }
    return *levels_out >= 3u;
}

static bool registry_open_builder_stores(
    const char *builder_a, const char *builder_b,
    struct vcs_package_store **store_a, struct vcs_package_store **store_b)
{
    *store_a = vcs_package_store_open(
        builder_a, UINT64_C(256) * 1024u * 1024u);
    *store_b = vcs_package_store_open(
        builder_b, UINT64_C(256) * 1024u * 1024u);
    return *store_a && *store_b;
}

static bool registry_publish_pair(
    struct vcs_package_store *store_a, struct vcs_package_store *store_b,
    const struct vcs_package_prepared *prepared, const char *source_dir,
    bool *published_a, bool *published_b)
{
    *published_a = registry_publish_store(store_a, prepared, source_dir);
    *published_b = registry_publish_store(store_b, prepared, source_dir);
    return *published_a && *published_b;
}

static void registry_close_builder_stores(struct vcs_package_store *store_a,
                                          struct vcs_package_store *store_b)
{
    if (store_a)
        vcs_package_store_close(store_a);
    if (store_b)
        vcs_package_store_close(store_b);
}

static bool registry_graph_shape_checked(bool ok, const char *builder,
                                         size_t *levels_out,
                                         size_t *closure_out)
{
    return ok && registry_graph_shape(builder, levels_out, closure_out);
}

static bool registry_build_and_read_receipts(
    const char *builder_a, const char *builder_b, const char *content_root,
    int64_t now, struct vcs_package_build_receipt *a,
    struct vcs_package_build_receipt *b)
{
    return registry_build_one(builder_a, content_root, now) &&
           registry_build_one(builder_b, content_root, now) &&
           registry_read_receipt(builder_a, content_root, a) &&
           registry_read_receipt(builder_b, content_root, b);
}

static bool registry_verify_builder_pair(
    struct vcs_package_build_receipt *a, struct vcs_package_build_receipt *b,
    struct vcs_reproduce_verdict *verdict, size_t *reproduced_out)
{
    vcs_package_reproduce_compare(a, b, verdict);
    bool ok = verdict->reproduced && a->output_count > 0 &&
        b->output_count == a->output_count &&
        strcmp(a->flags, ZCL_C23_COMMONS_BUILD_FLAGS_QUICK_V2) == 0 &&
        strcmp(b->flags, ZCL_C23_COMMONS_BUILD_FLAGS_QUICK_V2) == 0 &&
        a->test_ran && b->test_ran &&
        a->result_class == VCS_PACKAGE_BUILD_RESULT_TEST_PASS &&
        b->result_class == VCS_PACKAGE_BUILD_RESULT_TEST_PASS;
    if (ok)
        (*reproduced_out)++;
    return ok;
}

static bool registry_consumer_checks(bool ok, const char *builder)
{
    return ok && registry_dogfood(builder) &&
           registry_stranger_build(builder);
}

static bool registry_independent_reproduction(size_t *reproduced_out)
{
    *reproduced_out = 0;
    char builder_a[256], builder_b[256];
    test_make_tmpdir(builder_a, sizeof(builder_a), "zcode_registry",
                     "builder_a");
    test_make_tmpdir(builder_b, sizeof(builder_b), "zcode_registry",
                     "builder_b");
    struct vcs_package_store *store_a = NULL, *store_b = NULL;
    bool ok = registry_open_builder_stores(builder_a, builder_b, &store_a,
                                           &store_b);
    if (!ok)
        printf("  zcode_package_registry: builder store open failed a=%s "
               "b=%s\n", store_a ? "open" : "failed",
               store_b ? "open" : "failed");
    for (size_t i = 0;
         ok && i < sizeof(registry_packages) / sizeof(registry_packages[0]);
         i++) {
        struct vcs_package_prepared prepared;
        ok = registry_prepare(&registry_packages[i], &prepared);
        if (ok) {
            bool published_a, published_b;
            ok = registry_publish_pair(store_a, store_b, &prepared,
                                       registry_packages[i].dir,
                                       &published_a, &published_b);
            if (!ok)
                printf("  zcode_package_registry: publish %s failed "
                       "builder_a=%s builder_b=%s\n",
                       registry_packages[i].name,
                       published_a ? "ok" : "failed",
                       published_b ? "ok" : "failed");
            vcs_package_prepared_free(&prepared);
        } else {
            printf("  zcode_package_registry: prepare %s failed\n",
                   registry_packages[i].name);
        }
    }
    registry_close_builder_stores(store_a, store_b);

    size_t dependency_levels = 0, app_closure = 0;
    ok = registry_graph_shape_checked(ok, builder_a, &dependency_levels,
                                      &app_closure);
    if (ok)
        printf("{\"schema\":\"zcl.c23_commons_graph.v1\","
               "\"package_count\":%zu,\"dependency_levels\":%zu,"
               "\"application_closure_packages\":%zu,"
               "\"exact_roots\":true,\"author_signatures_verified\":true,"
               "\"declarative_recipes\":true}\n",
               sizeof(registry_packages) / sizeof(registry_packages[0]),
               dependency_levels, app_closure);

    for (size_t i = 0;
         ok && i < sizeof(registry_packages) / sizeof(registry_packages[0]);
         i++) {
        const struct registry_expected *expected = &registry_packages[i];
        int64_t now = INT64_C(1700001000) + (int64_t)i * 4;
        struct vcs_package_build_receipt a, b;
        ok = registry_build_and_read_receipts(builder_a, builder_b,
                                              expected->content_root, now,
                                              &a, &b);
        struct vcs_reproduce_verdict verdict;
        if (ok) {
            ok = registry_verify_builder_pair(&a, &b, &verdict,
                                              reproduced_out);
            if (!ok)
                printf("  zcode_package_registry: reproduction %s failed "
                       "rule=%s detail=%s\n", expected->name,
                       vcs_reproduce_rule_string(
                           (enum vcs_reproduce_rule)verdict.rule),
                       verdict.detail);
        }
    }
    ok = registry_consumer_checks(ok, builder_b);
    test_rm_rf(builder_a);
    test_rm_rf(builder_b);
    return ok;
}

static int registry_test_independent_reproduction(void)
{
    int failures = 0;
    TEST("zcode package registry: two isolated builders reproduce all artifacts") {
        size_t reproduced = 0;
        ASSERT(registry_independent_reproduction(&reproduced));
        ASSERT_EQ(reproduced,
                  sizeof(registry_packages) / sizeof(registry_packages[0]));
        PASS();
    } _test_next:;
    return failures;
}

int test_zcode_package_registry(void)
{
    int failures = 0;
    /* Every store here is a fixture discarded whole (scratch publishes and
     * two builder datadirs removed at the end); no case crashes mid-write
     * and reads back, so the per-write fsync buys nothing. Prior setting
     * restored below. */
    bool registry_prior_sync = vcs_package_store_deferred_sync_enabled();
    vcs_package_store_set_deferred_sync(true);
    TEST("zcode package registry: C23 Commons Alpha roots and DAG rederive") {
        ASSERT_EQ(sizeof(registry_packages) / sizeof(registry_packages[0]),
                  17);
        for (size_t i = 0;
             i < sizeof(registry_packages) / sizeof(registry_packages[0]);
             i++) {
            const struct registry_expected *expected = &registry_packages[i];
            struct vcs_package_prepared prepared;
            ASSERT(registry_prepare(expected, &prepared));
            ASSERT_STR_EQ(prepared.release.name, expected->name);
            char content[65], release[65], recipe[65], lock[65], capsule[65];
            zcl_hex_encode(prepared.package_root, 32, content);
            zcl_hex_encode(prepared.signing_digest, 32, release);
            zcl_hex_encode(prepared.recipe_root, 32, recipe);
            zcl_hex_encode(prepared.lock_root, 32, lock);
            zcl_hex_encode(prepared.capsule_root, 32, capsule);
            /* The def is a projection of lib/ content; when a lane moves
             * that content the derived row below is the ready-to-paste
             * replacement (ZCODE_PACKAGE keeps name, dir and sequence; the
             * signature is re-signed live by the alpha fixture identity,
             * the same 0x47-key convention every swarm fixture signs
             * with). */
            char signature[VCS_PACKAGE_RELEASE_SIGNATURE_BYTES * 2u + 1u];
            /* The capsule root pins the exact toolchain used to build the
             * package; it is platform-specific (Linux GCC vs Apple Clang) and
             * therefore not compared against the Linux-generated def.  The
             * content/release/recipe/lock roots are the portable package
             * identity and are still enforced. */
            bool drifted = strcmp(content, expected->content_root) != 0 ||
                           strcmp(release, expected->release_root) != 0 ||
                           strcmp(recipe, expected->recipe_root) != 0 ||
                           strcmp(lock, expected->lock_root) != 0 ||
                           vcs_package_release_verify(&prepared.release) !=
                               VCS_PACKAGE_RELEASE_OK;
            if (drifted) {
                struct privkey key;
                memset(&key, 0, sizeof(key));
                memset(key.vch, 0x47, sizeof(key.vch));
                key.fValid = true;
                key.fCompressed = true;
                struct uint256 digest;
                memcpy(digest.data, prepared.signing_digest, 32);
                uint8_t compact[COMPACT_SIGNATURE_SIZE];
                if (privkey_sign_compact(&key, &digest, compact)) {
                    memcpy(prepared.release.signature, compact + 1,
                           VCS_PACKAGE_RELEASE_SIGNATURE_BYTES);
                    zcl_hex_encode(prepared.release.signature,
                                   VCS_PACKAGE_RELEASE_SIGNATURE_BYTES,
                                   signature);
                } else {
                    signature[0] = '\0';
                }
                printf("  registry drift %s: re-derive as\n"
                       "    \"%s\", \"%s\", \"%s\",\n"
                       "    \"%s\",\n    \"%s\",\n    \"%s\",\n"
                       "    \"%s\",\n    \"%s\",\n    \"%s\")\n",
                       expected->name, expected->name, expected->dir,
                       content, release, recipe, lock, capsule,
                       expected->publisher_pubkey, signature);
                printf("    fix: tools/scripts/zcode_registry_rederive.sh\n"
                       "    (this root is also pinned in each dependent's\n"
                       "     zcode-package.json; the script settles both)\n");
            }
            ASSERT_STR_EQ(content, expected->content_root);
            ASSERT_STR_EQ(release, expected->release_root);
            ASSERT_STR_EQ(recipe, expected->recipe_root);
            ASSERT_STR_EQ(lock, expected->lock_root);
            ASSERT_EQ(vcs_package_release_verify(&prepared.release),
                      VCS_PACKAGE_RELEASE_OK);
            ASSERT(capsule[0] != '\0');
            ASSERT(registry_publish_scratch(&prepared, expected->dir));
            ASSERT(prepared.lock.count >= 1);
            ASSERT_EQ(prepared.lock.nodes[prepared.lock.count - 1u].depth, 0);
            ASSERT_EQ(prepared.lock.nodes[prepared.lock.count - 1u].direct_deps,
                      prepared.lock.count - 1u);
            for (size_t d = 0; d + 1u < prepared.lock.count; d++) {
                bool found = false;
                for (size_t p = 0; p < i; p++) {
                    uint8_t prior[32];
                    ASSERT(zcl_hex_decode_lower(
                        registry_packages[p].content_root, prior,
                        sizeof(prior)));
                    found = found || memcmp(prepared.lock.nodes[d].root,
                                             prior, sizeof(prior)) == 0;
                }
                ASSERT(found);
                ASSERT_EQ(prepared.lock.nodes[d].depth, 1);
            }
            vcs_package_prepared_free(&prepared);
        }
        PASS();
    } _test_next:;
    failures += registry_test_independent_reproduction();
    vcs_package_store_set_deferred_sync(registry_prior_sync);
    printf("=== zcode_package_registry: %d failures ===\n", failures);
    return failures;
}
