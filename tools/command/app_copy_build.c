/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: the copy derivations app.build and app.run.copy share
 * (command/app_copy_build.h). */

#include "command/app_copy_build.h"
#include "command/app_image.h"
#include "command/native_app_compose.h"

#include "base/hex.h"
#include "base/safe_alloc.h"
#include "json/json.h"
#include "platform/directory_compat.h"
#include "util/path_util.h"
#include "vcs/package_deps.h"
#include "vcs/package_prepare.h"
#include "vcs/package_release.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ACB_STORE "app_build"

bool app_copy_build_dir(const char *datadir, const char *copy, char *out,
                        size_t cap, struct zcl_command_reply *reply)
{
    char raw[APP_COPY_BUILD_PATH];
    bool named = copy && !strchr(copy, '/');
    if (!copy || (!named && copy[0] != '/') ||
        (named && (copy[0] == '.' ||
                   strlen(copy) > ZCL_PACKAGE_ADOPT_NAME_MAX))) {
        zcl_package_copy_fail(reply, "BAD_COPY", false, "copy must be an "
                              "absolute directory or a copy name under "
                              "<datadir>/copies", copy ? copy : "");
        return false;
    }
    int n = named ? snprintf(raw, sizeof(raw), "%s/copies/%s", datadir, copy)
                  : snprintf(raw, sizeof(raw), "%s", copy);
    if (n <= 0 || (size_t)n >= sizeof(raw) ||
        !platform_directory_canonical_real(raw, out, cap)) {
        zcl_package_copy_fail(reply, "COPY_MISSING", false,
                              "no such copy directory", raw);
        return false;
    }
    return true;
}

bool app_copy_build_roots(const char *datadir, const char *copy_dir,
                          const struct zcl_package_copy *copy,
                          uint8_t package_root[32],
                          uint8_t dependency_root[32],
                          struct zcl_command_reply *reply)
{
    struct vcs_package_release release;
    uint8_t release_id[32];
    struct vcs_package_prepared prepared;
    char detail[256] = "";
    if (zcl_package_copy_find_release(datadir, copy->parent_release, &release,
                                      release_id) != ZCL_PACKAGE_COPY_FOUND) {
        zcl_package_copy_fail(reply, "RELEASE_UNKNOWN", false, "the release "
                              "this copy came from is not persisted in this "
                              "datadir", datadir);
        return false;
    }
    struct vcs_package_prepare_options o = {
        .dir = copy_dir, .publisher_sequence = 1, .reward_address = "",
        .chain_id = release.chain_id,
    };
    memcpy(o.publisher_pubkey, release.publisher_pubkey,
           sizeof(o.publisher_pubkey));
    vcs_package_prepared_init(&prepared);
    bool ok = vcs_package_prepare(&o, &prepared, detail, sizeof(detail)) ==
              VCS_PACKAGE_PREPARE_OK;
    if (ok) {
        memcpy(package_root, prepared.package_root, 32);
        app_image_dependency_root(&prepared.lock, dependency_root);
    } else {
        zcl_package_copy_fail(reply, "PACKAGE_INVALID", false, "the saved "
                              "copy does not prepare as a package", detail);
    }
    vcs_package_prepared_free(&prepared);
    return ok;
}

bool app_copy_build_store(const char *datadir, const uint8_t fork[32],
                          struct app_copy_build_store *out,
                          struct zcl_command_reply *reply)
{
    char store[APP_COPY_BUILD_PATH], hex[65], work[APP_COPY_BUILD_PATH];
    zcl_hex_encode(fork, 32, hex);
    bool ok = zcl_path_join(store, sizeof(store), datadir, ACB_STORE) &&
              zcl_path_join(work, sizeof(work), store, "work") &&
              zcl_path_join(out->work, sizeof(out->work), work, hex) &&
              zcl_path_join(out->images, sizeof(out->images), store,
                            "images") &&
              zcl_path_join(out->records, sizeof(out->records), store,
                            "records");
    if (!ok)
        zcl_package_copy_fail(reply, "PATH_TOO_LONG", false,
                              "the datadir path is too long", datadir);
    return ok;
}

bool app_copy_build_keys(const char *datadir, const char *copy_dir,
                         struct app_copy_build_keys *out,
                         struct zcl_command_reply *reply)
{
    static const char *const names[] = {"package_root", "closure_root",
                                        "env_root", "dependency_root"};
    uint8_t *roots[] = {out->package_root, out->closure_root, out->env_root,
                        out->dependency_root};
    const char *kv[] = {"copy", copy_dir, "datadir", datadir};
    struct json_value in;
    struct zcl_command_reply plan;
    memset(out, 0, sizeof(*out));
    bool ok = zcl_app_inner_call_built("app.build", &in,
                                       zcl_app_input(&in, kv, 4), &plan);
    for (size_t i = 0; ok && i < 4; i++) {
        const char *hex = zcl_app_inner_str(&plan, names[i]);
        ok = hex && strlen(hex) == 64 && zcl_hex_decode(hex, roots[i], 32);
    }
    const struct json_value *hit = ok ? json_get(&plan.data, "cache_hit")
                                      : NULL;
    out->hit = hit && hit->type == JSON_BOOL && json_get_bool(hit);
    if (!ok && plan.status == ZCL_COMMAND_STATUS_PASSED)
        zcl_package_copy_fail(reply, "PLAN_INCOMPLETE", false, "app.build's "
                              "plan named no roots", copy_dir);
    else if (!ok)
        zcl_app_inner_fail(reply, &plan, false);
    zcl_command_reply_free(&plan);
    return ok;
}

bool app_copy_build_carry(const char *datadir, const uint8_t fork[32],
                          const struct app_copy_build_keys *from,
                          const struct app_copy_build_keys *to,
                          struct zcl_command_reply *reply)
{
    struct app_copy_build_store *store;
    struct app_image_build rec;
    bool hit = false;
    if (!from->hit || memcmp(from->closure_root, to->closure_root, 32) != 0 ||
        memcmp(from->env_root, to->env_root, 32) != 0 ||
        memcmp(from->dependency_root, to->dependency_root, 32) != 0) {
        zcl_package_copy_fail(reply, "NOT_CARRIED", false, "the copy had no "
                              "current build, or a build input changed",
                              datadir);
        return false;
    }
    store = zcl_calloc(1, sizeof(*store), "app_copy_build.carry");
    if (!store) {
        zcl_package_copy_fail(reply, "ALLOC", false, "build store paths",
                              datadir);
        return false;
    }
    if (!app_copy_build_store(datadir, fork, store, reply)) {
        free(store);
        return false;
    }
    struct zcl_result r = app_image_build_load(
        store->records, from->package_root, from->env_root,
        from->dependency_root, &rec, &hit);
    bool ok = r.ok && hit &&
              memcmp(rec.closure_root, to->closure_root, 32) == 0;
    if (!ok)
        zcl_package_copy_fail(reply, "RECORD_INVALID", false, "the build "
                              "record to carry is missing or names another "
                              "closure", r.ok ? store->records : r.message);
    if (ok) {
        memcpy(rec.package_root, to->package_root, 32);
        memcpy(rec.dependency_root, to->dependency_root, 32);
        r = app_image_build_save(store->records, &rec, NULL, 0);
        if (!r.ok)
            zcl_package_copy_fail(reply, "RECORD_SAVE_FAILED", false, "the "
                                  "carried build record could not be saved",
                                  r.message);
        ok = r.ok;
    }
    free(store);
    return ok;
}
