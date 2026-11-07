/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: the copy derivations app.build and app.run.copy share
 * (command/app_copy_build.h). */

#include "command/app_copy_build.h"

#include "base/hex.h"
#include "platform/directory_compat.h"
#include "sha3/sha3.h"
#include "util/path_util.h"
#include "vcs/package_deps.h"
#include "vcs/package_prepare.h"
#include "vcs/package_release.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ACB_STORE "app_build"
#define ACB_DEPS_DOMAIN "zcl.app_build.dependency_set.v1"

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

static int acb_root_cmp(const void *a, const void *b)
{
    return memcmp(a, b, 32);
}

/* SHA3 over the sorted directly declared dependency roots (the lock's
 * nodes other than the target, which is last). */
static void acb_dependency_root(const struct vcs_package_lock *lock,
                                uint8_t out[32])
{
    uint8_t roots[VCS_PACKAGE_LOCK_MAX_NODES][32];
    size_t n = 0;
    for (size_t i = 0; i + 1u < lock->count && n < VCS_PACKAGE_LOCK_MAX_NODES;
         i++)
        memcpy(roots[n++], lock->nodes[i].root, 32);
    qsort(roots, n, 32, acb_root_cmp);
    uint8_t count_le[4] = {(uint8_t)n, (uint8_t)(n >> 8), 0, 0};
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)ACB_DEPS_DOMAIN,
                   sizeof(ACB_DEPS_DOMAIN));
    sha3_256_write(&sha, count_le, sizeof(count_le));
    for (size_t i = 0; i < n; i++)
        sha3_256_write(&sha, roots[i], 32);
    sha3_256_finalize(&sha, out);
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
        acb_dependency_root(&prepared.lock, dependency_root);
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
