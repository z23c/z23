/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: app.build — build the user's own copy of an app into an image
 * plus a zcl.app_build.v1 build record (command/app_image.h) that open and
 * playtest later run that exact image from.
 *
 * Who may build. The copy must be ADOPTED (zcode.package.adopt) or a
 * friend's RECEIVED_TRUSTED copy (zcode.package.bundle.receive's one-time
 * owner confirmation), with only local saves and restores after its root:
 * one check, zcl_package_copy_adopted(). Anything else is NOT_ADOPTED.
 * Building only produces bytes; running needs accept_execution for the exact
 * image_sha3, so an agent may plan and confirm this leaf.
 *
 * Plan (writes nothing): refuses a dirty tree (UNSAVED_CHANGES), derives
 *   package_root     the release package root of the saved tree
 *                    (vcs_package_prepare over the clean copy),
 *   dependency_root  SHA3 over the sorted roots the copy's zcode-package.json
 *                    declares (a fixed non-zero root when it declares none);
 *                    a caller's dependency_root that differs is
 *                    DEPENDENCY_MISMATCH,
 *   env_root         the captured toolchain capsule root,
 *   closure_root     the declared input closure of the make fragment
 *                    (command/app_build_make.h),
 * reports cache_hit when a record for (package, env, dependency) holds this
 * closure and its image is stored, and returns a plan_id binding them all.
 *
 * Confirm re-derives the plan, then on a cache hit returns the record and
 * runs no make. Otherwise it runs `make app` out of tree in a fresh
 * APP_OUT under <datadir>/app_build/work/<copy root>, confined where the
 * host can (the reply says "unconfined" where not), refuses BUILD_FAILED
 * with a bounded log tail, refuses CLOSURE_DRIFT when a depfile names an
 * input the plan's closure did not declare, stores the image at
 * <datadir>/app_build/images/<image_sha3> and saves the record under
 * <datadir>/app_build/records. Nothing is executed but the build. */

#include "command/native_command.h"

#include "command/app_build_make.h"
#include "command/app_image.h"
#include "command/native_zcode_package_copy.h"

#include "base/hex.h"
#include "json/json.h"
#include "platform/directory_compat.h"
#include "sha3/sha3.h"
#include "util/authority_receipt.h"
#include "util/file_io.h"
#include "util/file_tree_ops.h"
#include "vcs/package_deps.h"
#include "vcs/package_prepare.h"
#include "vcs/package_release.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define ZAB_PATH 4400
#define ZAB_STORE "app_build"
#define ZAB_PLAN_DOMAIN "zcl.app_build.plan.v1"
#define ZAB_DEPS_DOMAIN "zcl.app_build.dependency_set.v1"
#define ZAB_IMAGE_MAX (512u << 20)
#define ZAB_COMMAND "app.build"

struct zab {
    const struct json_value *input;
    struct zcl_command_reply *reply;
    const char *datadir;
    char copy_dir[ZAB_PATH];
    struct zcl_package_copy copy;
    bool copy_open;
    enum zcl_package_copy_adoption auth;
    uint8_t package_root[32];
    uint8_t env_root[32];
    uint8_t dependency_root[32];
    uint8_t plan_id[32];
    struct app_build_closure closure;
    char work[ZAB_PATH];
    char images[ZAB_PATH];
    char records[ZAB_PATH];
    struct app_image_build cached;
    bool cache_hit;
    bool confine;
};

static void zab_fail(struct zab *z, const char *code, bool mutated,
                     const char *message, const char *evidence)
{
    zcl_package_copy_fail(z->reply, code, mutated, message, evidence);
}

static bool zab_pathf(char *out, size_t cap, const char *a, const char *b)
{
    int n = snprintf(out, cap, "%s/%s", a, b);
    return n > 0 && (size_t)n < cap;
}

/* ── which copy, and may it be built ─────────────────────────────────── */

/* `copy` is an absolute directory, or a name under <datadir>/copies. */
static bool zab_resolve(struct zab *z)
{
    const char *copy = zcl_package_copy_str(z->input, "copy");
    char raw[ZAB_PATH];
    bool named = copy && !strchr(copy, '/');
    if (!copy || (!named && copy[0] != '/') ||
        (named && (copy[0] == '.' ||
                   strlen(copy) > ZCL_PACKAGE_ADOPT_NAME_MAX))) {
        zab_fail(z, "BAD_COPY", false, "copy must be an absolute directory "
                 "or a copy name under <datadir>/copies", copy ? copy : "");
        return false;
    }
    int n = named ? snprintf(raw, sizeof(raw), "%s/copies/%s", z->datadir, copy)
                  : snprintf(raw, sizeof(raw), "%s", copy);
    if (n <= 0 || (size_t)n >= sizeof(raw) ||
        !platform_directory_canonical_real(raw, z->copy_dir,
                                           sizeof(z->copy_dir))) {
        zab_fail(z, "COPY_MISSING", false, "no such copy directory", raw);
        return false;
    }
    return true;
}

static bool zab_authorize(struct zab *z)
{
    z->auth = zcl_package_copy_adopted(z->datadir, &z->copy, NULL);
    if (z->auth == ZCL_PACKAGE_COPY_ADOPTED ||
        z->auth == ZCL_PACKAGE_COPY_RECEIVED_TRUSTED)
        return true;
    zab_fail(z, "NOT_ADOPTED", false,
             z->auth == ZCL_PACKAGE_COPY_FOREIGN_COMMITS
                 ? "this copy has a commit that is not a local save or "
                   "restore; adopt it again before building"
                 : "only an adopted copy, or a received copy whose publisher "
                   "and root the owner confirmed, may be built",
             zcl_package_copy_adoption_name(z->auth));
    return false;
}

static bool zab_clean(struct zab *z)
{
    size_t changes = 0;
    if (!zcl_package_copy_unsaved(&z->copy, &changes)) {
        zab_fail(z, "STATUS_FAILED", false, "the copy's status scan failed",
                 z->copy_dir);
        return false;
    }
    if (changes > 0) {
        zab_fail(z, "UNSAVED_CHANGES", false, "save or restore the copy "
                 "first: only a saved version is built", z->copy_dir);
        return false;
    }
    return true;
}

/* ── the roots ───────────────────────────────────────────────────────── */

static int zab_root_cmp(const void *a, const void *b)
{
    return memcmp(a, b, 32);
}

/* SHA3 over the sorted directly declared dependency roots (the lock's
 * nodes other than the target, which is last). */
static void zab_dependency_root(const struct vcs_package_lock *lock,
                                uint8_t out[32])
{
    uint8_t roots[VCS_PACKAGE_LOCK_MAX_NODES][32];
    size_t n = 0;
    for (size_t i = 0; i + 1u < lock->count && n < VCS_PACKAGE_LOCK_MAX_NODES;
         i++)
        memcpy(roots[n++], lock->nodes[i].root, 32);
    qsort(roots, n, 32, zab_root_cmp);
    uint8_t count_le[4] = {(uint8_t)n, (uint8_t)(n >> 8), 0, 0};
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)ZAB_DEPS_DOMAIN,
                   sizeof(ZAB_DEPS_DOMAIN));
    sha3_256_write(&sha, count_le, sizeof(count_le));
    for (size_t i = 0; i < n; i++)
        sha3_256_write(&sha, roots[i], 32);
    sha3_256_finalize(&sha, out);
}

/* The package root and declared dependencies of the clean copy, prepared
 * exactly as a publish would (under the release's publisher key). */
static bool zab_package(struct zab *z)
{
    struct vcs_package_release release;
    uint8_t release_id[32];
    struct vcs_package_prepared prepared;
    char detail[256] = "";
    if (zcl_package_copy_find_release(z->datadir, z->copy.parent_release,
                                      &release, release_id) !=
        ZCL_PACKAGE_COPY_FOUND) {
        zab_fail(z, "RELEASE_UNKNOWN", false, "the release this copy came "
                 "from is not persisted in this datadir", z->datadir);
        return false;
    }
    struct vcs_package_prepare_options o = {
        .dir = z->copy_dir, .publisher_sequence = 1, .reward_address = "",
        .chain_id = release.chain_id,
    };
    memcpy(o.publisher_pubkey, release.publisher_pubkey,
           sizeof(o.publisher_pubkey));
    vcs_package_prepared_init(&prepared);
    if (vcs_package_prepare(&o, &prepared, detail, sizeof(detail)) !=
        VCS_PACKAGE_PREPARE_OK) {
        zab_fail(z, "PACKAGE_INVALID", false, "the saved copy does not "
                 "prepare as a package", detail);
        vcs_package_prepared_free(&prepared);
        return false;
    }
    memcpy(z->package_root, prepared.package_root, 32);
    zab_dependency_root(&prepared.lock, z->dependency_root);
    vcs_package_prepared_free(&prepared);
    return true;
}

static bool zab_dependencies_match(struct zab *z)
{
    const char *hex = zcl_package_copy_str(z->input, "dependency_root");
    uint8_t want[32];
    if (!hex)
        return true;
    if (!zcl_hex_decode(hex, want, 32) || strlen(hex) != 64) {
        zab_fail(z, "BAD_DEPENDENCY_ROOT", false,
                 "dependency_root must be 64 hex characters", hex);
        return false;
    }
    if (memcmp(want, z->dependency_root, 32) != 0) {
        char have[65];
        zcl_hex_encode(z->dependency_root, 32, have);
        zab_fail(z, "DEPENDENCY_MISMATCH", false, "the copy declares a "
                 "different dependency set than the one asked for", have);
        return false;
    }
    return true;
}

static bool zab_make_fragment(struct zab *z)
{
    char path[ZAB_PATH];
    struct stat st;
    if (zab_pathf(path, sizeof(path), z->copy_dir, "Makefile") &&
        lstat(path, &st) == 0 && S_ISREG(st.st_mode))
        return true;
    zab_fail(z, "NO_MAKE_FRAGMENT", false, "the copy has no Makefile with "
             "print-app-closure and app targets", z->copy_dir);
    return false;
}

static bool zab_store_paths(struct zab *z)
{
    char store[ZAB_PATH], fork[65], work[ZAB_PATH];
    zcl_hex_encode(z->copy.fork_version, 32, fork);
    bool ok = zab_pathf(store, sizeof(store), z->datadir, ZAB_STORE) &&
              zab_pathf(work, sizeof(work), store, "work") &&
              zab_pathf(z->work, sizeof(z->work), work, fork) &&
              zab_pathf(z->images, sizeof(z->images), store, "images") &&
              zab_pathf(z->records, sizeof(z->records), store, "records");
    if (!ok)
        zab_fail(z, "PATH_TOO_LONG", false, "the datadir path is too long",
                 z->datadir);
    return ok;
}

static bool zab_closure(struct zab *z)
{
    char why[320] = "";
    const struct app_build_make m = {.copy_dir = z->copy_dir,
                                     .work_dir = z->work,
                                     .confine = z->confine};
    if (app_build_closure_query(&m, &z->closure, why, sizeof(why)))
        return true;
    zab_fail(z, "CLOSURE_INVALID", false, "the make fragment's declared "
             "closure could not be read", why);
    return false;
}

static bool zab_image_path(const struct zab *z, const uint8_t sha[32],
                           char *out, size_t cap)
{
    char hex[65];
    zcl_hex_encode(sha, 32, hex);
    return zab_pathf(out, cap, z->images, hex);
}

/* A record for (package, env, dependency) that holds this closure and whose
 * image is still stored. A malformed record is a refusal, never a miss. */
static bool zab_cache(struct zab *z)
{
    char image[ZAB_PATH];
    struct stat st;
    bool hit = false;
    struct zcl_result r = app_image_build_load(
        z->records, z->package_root, z->env_root, z->dependency_root,
        &z->cached, &hit);
    if (!r.ok) {
        zab_fail(z, "RECORD_INVALID", false, "a stored build record for this "
                 "copy is unreadable", r.message);
        return false;
    }
    z->cache_hit = hit &&
                   memcmp(z->cached.closure_root, z->closure.root, 32) == 0 &&
                   zab_image_path(z, z->cached.image_sha3, image,
                                  sizeof(image)) &&
                   lstat(image, &st) == 0 && S_ISREG(st.st_mode);
    return true;
}

static void zab_plan_id(struct zab *z)
{
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)ZAB_PLAN_DOMAIN,
                   sizeof(ZAB_PLAN_DOMAIN));
    sha3_256_write(&sha, z->copy.fork_version, 32);
    sha3_256_write(&sha, z->copy.head_version, 32);
    sha3_256_write(&sha, z->package_root, 32);
    sha3_256_write(&sha, z->closure.root, 32);
    sha3_256_write(&sha, z->env_root, 32);
    sha3_256_write(&sha, z->dependency_root, 32);
    sha3_256_finalize(&sha, z->plan_id);
}

/* Every check and root a plan and its confirm both derive. */
static bool zab_derive(struct zab *z)
{
    if (!zab_resolve(z) ||
        !zcl_package_copy_open(z->copy_dir, &z->copy, z->reply, ZAB_COMMAND))
        return false;
    z->copy_open = true;
    if (!zab_authorize(z) || !zab_clean(z) || !zab_make_fragment(z) ||
        !zab_package(z) || !zab_dependencies_match(z) || !zab_store_paths(z))
        return false;
    struct zcl_result env = app_image_env_root(z->env_root);
    if (!env.ok) {
        zab_fail(z, "ENV_UNAVAILABLE", false, "the toolchain capsule could "
                 "not be captured", env.message);
        return false;
    }
    z->confine = app_build_make_confinable();
    if (!zab_closure(z) || !zab_cache(z))
        return false;
    zab_plan_id(z);
    return true;
}

/* ── replies ─────────────────────────────────────────────────────────── */

static void zab_describe(struct zab *z, const char *stage, bool unconfined)
{
    struct json_value *d = &z->reply->data;
    (void)json_push_kv_str(d, "stage", stage);
    (void)json_push_kv_str(d, "copy", z->copy_dir);
    (void)json_push_kv_str(d, "authorization",
                           zcl_package_copy_adoption_name(z->auth));
    zcl_package_copy_push_root(d, "version", z->copy.head_version);
    zcl_package_copy_push_root(d, "package_root", z->package_root);
    zcl_package_copy_push_root(d, "closure_root", z->closure.root);
    zcl_package_copy_push_root(d, "env_root", z->env_root);
    zcl_package_copy_push_root(d, "dependency_root", z->dependency_root);
    (void)json_push_kv_int(d, "closure_inputs", (int64_t)z->closure.count);
    (void)json_push_kv_bool(d, "cache_hit", z->cache_hit);
    (void)json_push_kv_str(d, "confinement",
                           unconfined ? "unconfined" : "landlock");
    zcl_package_copy_push_root(d, "plan_id", z->plan_id);
}

static void zab_commit_reply(struct zab *z, const struct app_image_build *rec,
                             const char *image, const char *record,
                             bool make_ran, bool unconfined)
{
    struct json_value *d = &z->reply->data;
    uint8_t id[32];
    zab_describe(z, "commit", unconfined);
    zcl_package_copy_push_root(d, "image_sha3", rec->image_sha3);
    (void)json_push_kv_str(d, "image_path", image);
    if (app_image_build_id(rec, id).ok)
        zcl_package_copy_push_root(d, "record_id", id);
    (void)json_push_kv_str(d, "record_path", record);
    (void)json_push_kv_str(d, "record_store", z->records);
    (void)json_push_kv_str(d, "build_dir", z->work);
    (void)json_push_kv_bool(d, "make_ran", make_ran);
    (void)json_push_kv_bool(d, "executed", false);
    (void)json_push_kv_str(d, "next", "app open or app playtest this "
                           "image_sha3 with accept_execution:true");
    z->reply->error.mutated = make_ran;
}

/* ── the build ───────────────────────────────────────────────────────── */

/* Copy the built image into the content-addressed store (0700, so it can be
 * executed later); an image already stored under its hash is kept. */
static bool zab_store_image(struct zab *z, const char *built, char *final,
                            size_t cap, uint8_t sha[32])
{
    uint8_t *bytes = NULL;
    size_t len = 0;
    struct stat st;
    if (!zcl_read_whole_file(built, ZAB_IMAGE_MAX, &bytes, &len, ZAB_COMMAND) ||
        len == 0) {
        free(bytes);
        return false;
    }
    zcl_sha3_256(bytes, len, sha);
    char hex[65];
    zcl_hex_encode(sha, 32, hex);
    bool ok = zab_pathf(final, cap, z->images, hex);
    if (ok && lstat(final, &st) != 0)
        ok = authority_receipt_write_atomic(z->images, hex, bytes, len, final,
                                            cap) &&
             chmod(final, 0700) == 0;
    free(bytes);
    return ok;
}

/* Capture the stored image's identity and save the record. */
static bool zab_record(struct zab *z, const char *image,
                       const uint8_t sha[32], struct app_image_build *rec,
                       char *record, size_t cap)
{
    memset(rec, 0, sizeof(*rec));
    memcpy(rec->package_root, z->package_root, 32);
    memcpy(rec->closure_root, z->closure.root, 32);
    memcpy(rec->env_root, z->env_root, 32);
    memcpy(rec->dependency_root, z->dependency_root, 32);
    struct zcl_result r = app_image_capture(image, rec);
    if (r.ok && memcmp(rec->image_sha3, sha, 32) != 0)
        r = ZCL_ERR(-1, "the stored image at %s is not the bytes built",
                    image);
    if (r.ok)
        r = app_image_build_save(z->records, rec, record, cap);
    if (!r.ok)
        zab_fail(z, "RECORD_SAVE_FAILED", true, "the build record could not "
                 "be saved", r.message);
    return r.ok;
}

static bool zab_dirs(struct zab *z, char *run, size_t cap)
{
    bool ok = zcl_mkdir_p(z->work, 0700).ok &&
              zcl_mkdir_p(z->images, 0700).ok &&
              zcl_mkdir_p(z->records, 0700).ok &&
              zab_pathf(run, cap, z->work, "run-XXXXXX") && mkdtemp(run);
    if (!ok)
        zab_fail(z, "BUILD_DIR_FAILED", false, "the build directories could "
                 "not be created", z->work);
    return ok;
}

/* make ran: refuse a failed build or an undeclared input, else store. */
static void zab_after_make(struct zab *z, const struct app_build_make *m,
                           const char *run,
                           const struct app_build_make_result *res)
{
    char why[320] = "", built[ZAB_PATH], image[ZAB_PATH], record[ZAB_PATH];
    uint8_t sha[32];
    struct app_image_build rec;
    if (!res->ok) {
        (void)json_push_kv_str(&z->reply->data, "confinement",
                               res->unconfined ? "unconfined" : "landlock");
        (void)json_push_kv_str(&z->reply->data, "log_tail", res->tail);
        zab_fail(z, "BUILD_FAILED", true, res->why, z->copy_dir);
        return;
    }
    if (!app_build_depfiles_declared(m, run, &z->closure, why, sizeof(why))) {
        zab_fail(z, "CLOSURE_DRIFT", true, "the build's inputs differ from "
                 "the closure the plan declared", why);
        return;
    }
    if (!zab_pathf(built, sizeof(built), run, APP_BUILD_IMAGE_NAME) ||
        !zab_store_image(z, built, image, sizeof(image), sha)) {
        zab_fail(z, "IMAGE_STORE_FAILED", true, "make app left no image at "
                 "$(APP_OUT)/app, or it could not be stored", run);
        return;
    }
    if (zab_record(z, image, sha, &rec, record, sizeof(record)))
        zab_commit_reply(z, &rec, image, record, true, res->unconfined);
}

static void zab_build(struct zab *z)
{
    char run[ZAB_PATH];
    struct app_build_make_result *res = calloc(1, sizeof(*res));
    if (!res) {
        zab_fail(z, "ALLOCATION_FAILED", false, "build result allocation "
                 "failed", z->copy_dir);
        return;
    }
    if (zab_dirs(z, run, sizeof(run))) {
        const struct app_build_make m = {.copy_dir = z->copy_dir,
                                         .work_dir = z->work,
                                         .confine = z->confine};
        app_build_make_run(&m, run, res);
        zab_after_make(z, &m, run, res);
        struct zcl_result rm = zcl_tree_remove(run);
        if (!rm.ok)
            fprintf(stderr, "[app.build] could not remove %s: %s\n", run,
                    rm.message);
    }
    free(res);
}

static void zab_confirm(struct zab *z)
{
    char image[ZAB_PATH], record[ZAB_PATH], key[65];
    if (!zcl_package_copy_plan_matches(z->input, z->plan_id, z->reply,
                                       ZAB_COMMAND))
        return;
    if (!z->cache_hit) {
        zab_build(z);
        return;
    }
    uint8_t k[32];
    app_image_build_key(z->package_root, z->env_root, z->dependency_root, k);
    zcl_hex_encode(k, 32, key);
    (void)snprintf(record, sizeof(record), "%s/%s%s", z->records, key,
                   APP_IMAGE_BUILD_FILE_SUFFIX);
    (void)zab_image_path(z, z->cached.image_sha3, image, sizeof(image));
    zab_commit_reply(z, &z->cached, image, record, false, !z->confine);
}

void zcl_native_handle_app_build(const struct zcl_command_request *request,
                                 struct zcl_command_reply *reply)
{
    struct zab *z = request && reply ? calloc(1, sizeof(*z)) : NULL;
    if (!z) {
        if (reply)
            zcl_package_copy_fail(reply, "ALLOCATION_FAILED", false,
                                  "app.build state allocation failed",
                                  ZAB_COMMAND);
        return;
    }
    z->input = request->input;
    z->reply = reply;
    z->datadir = zcl_package_copy_datadir(request->input, reply, ZAB_COMMAND);
    if (z->datadir && zab_derive(z)) {
        if (zcl_package_copy_confirmed(request->input)) {
            zab_confirm(z);
        } else {
            zab_describe(z, "plan", !z->confine);
            (void)json_push_kv_str(&reply->data, "next", "repeat with this "
                                   "plan_id and confirm:true to build");
        }
    }
    if (z->copy_open)
        zcl_package_copy_close(&z->copy);
    app_build_closure_free(&z->closure);
    free(z);
}
