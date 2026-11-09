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
 * Plan (no persistent build writes): without version refuses a dirty tree
 * (UNSAVED_CHANGES); an explicit saved version derives from temporary verified
 * materialization, never the live copy. Derives
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
 * APP_OUT under <datadir>/app_build/work/<copy root>, using a private temporary
 * alias when that path cannot be passed literally to make recipes. The
 * temporary source and writable work remain separate; configured TMPDIR is
 * respected and unsafe temporary paths refuse before the build. It is confined where the
 * host can (the reply says "unconfined" where not), refuses BUILD_FAILED
 * with a bounded log tail, refuses CLOSURE_DRIFT when a depfile names an
 * input the plan's closure did not declare, stores the image at
 * <datadir>/app_build/images/<image_sha3> and saves the record under
 * <datadir>/app_build/records. Nothing is executed but the build. */

#include "command/native_command.h"

#include "command/app_build_make.h"
#include "command/app_copy_build.h"
#include "command/native_app_compose.h"
#include "command/native_app_launch.h"
#include "command/app_image.h"
#include "command/app_toolchain.h"
#include "command/native_zcode_package_copy.h"

#include "base/hex.h"
#include "base/safe_alloc.h"
#include "json/json.h"
#include "platform/directory_compat.h"
#include "platform/temp_directory.h"
#include "sha3/sha3.h"
#include "util/authority_receipt.h"
#include "util/file_io.h"
#include "util/file_tree_ops.h"
#include "util/path_util.h"
#include "vcs/package_deps.h"
#include "vcs/package_prepare.h"
#include "vcs/package_release.h"
#include "vcs/package_store.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define ZAB_PATH APP_COPY_BUILD_PATH
#define ZAB_STORE "app_build"
#define ZAB_PLAN_DOMAIN "zcl.app_build.plan.v1"
#define ZAB_IMAGE_MAX (512u << 20)
#define ZAB_COMMAND "app.build"

struct zab {
    const struct json_value *input;
    struct zcl_command_reply *reply;
    const char *datadir;
    const char *version;
    char copy_dir[ZAB_PATH];
    char selected_source[PLATFORM_TEMP_PATH_MAX];
    char temporary_work[PLATFORM_TEMP_PATH_MAX];
    struct zcl_package_copy copy;
    bool copy_open;
    enum zcl_package_copy_adoption auth;
    uint8_t package_root[32];
    uint8_t env_root[32];
    uint8_t dependency_root[32];
    uint8_t plan_id[32];
    struct app_build_closure closure;
    struct app_toolchain kit;
    struct app_copy_build_store store;
    struct app_image_build cached;
    bool cache_hit;
    bool confine;
};

static void zab_fail(struct zab *z, const char *code, bool mutated,
                     const char *message, const char *evidence)
{
    zcl_package_copy_fail(z->reply, code, mutated, message, evidence);
}

/* Recipes receive paths as make variables as well as argv. Keep their
 * execution workspace independent of shell/make syntax in a user's HOME.
 * Canonicalize existing paths so a harmless-looking alias cannot hide it. */
static bool zab_make_path(const char *path)
{
    char real[ZAB_PATH];
    static const char safe[] =
        "/ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-";
    return path[0] && strspn(path, safe) == strlen(path) &&
        platform_directory_canonical_real(path, real, sizeof(real)) &&
        strspn(real, safe) == strlen(real);
}

static bool zab_private_workspace(struct zab *z, const char *prefix,
                                   char *path, size_t cap, bool mutated)
{
    if (!platform_temp_directory_create(prefix, path, cap)) {
        zab_fail(z, "BUILD_WORKSPACE_FAILED", mutated,
                 "could not create a private build workspace in the configured temporary directory",
                 ZAB_COMMAND);
        return false;
    }
    if (zab_make_path(path)) return true;
    zab_fail(z, "BUILD_WORKSPACE_PATH_UNSUPPORTED", mutated,
             "set TMPDIR to a private temporary directory whose path and canonical path contain only letters, digits, slash, dot, underscore or hyphen; the app copy can remain where it is",
             ZAB_COMMAND);
    return false;
}

static bool zab_outside_work(struct zab *z, const char *path)
{
    char source[ZAB_PATH], work[ZAB_PATH];
    if (platform_directory_canonical_real(path, source, sizeof(source)) &&
        platform_directory_canonical_real(z->store.work, work, sizeof(work))) {
        size_t len = strlen(work);
        if (strncmp(source, work, len) || (source[len] != '/' && source[len] != '\0'))
            return true;
    }
    zab_fail(z, "SNAPSHOT_NOT_ISOLATED", true,
             "source and private workspace aliases must be outside the writable build directory",
             ZAB_COMMAND);
    return false;
}

/* ── which copy, and may it be built ─────────────────────────────────── */

/* `copy` is an absolute directory, or a name under <datadir>/copies. */
static bool zab_resolve(struct zab *z)
{
    return app_copy_build_dir(z->datadir, zcl_package_copy_str(z->input, "copy"),
                              z->copy_dir, sizeof(z->copy_dir), z->reply);
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

static const char *zab_source(const struct zab *z)
{
    return z->version ? z->selected_source : z->copy_dir;
}

static bool zab_open_copy(struct zab *z)
{
    const struct json_value *v = json_get(z->input, "version");
    uint8_t id[32];
    if (v) {
        z->version = json_get_str(v);
        if (!z->version || strlen(z->version) != 64 ||
            !zcl_hex_decode_lower(z->version, id, 32)) {
            zab_fail(z, "BAD_VERSION", false,
                     "version must be an exact lowercase saved-version root", ZAB_COMMAND);
            return false;
        }
    }
    z->copy_open = zcl_package_copy_open_selected(z->copy_dir, &z->copy,
        z->reply, ZAB_COMMAND, z->version);
    return z->copy_open;
}

static bool zab_selected_source(struct zab *z)
{
    if (!z->version) return zab_clean(z);
    if (!zab_private_workspace(z, "z23-build-selected-", z->selected_source,
                               sizeof(z->selected_source), false)) {
        return false;
    }
    if (vcs_tree_materialize_disposable(z->copy_dir, z->copy.selected_tree, z->selected_source,
                             VCS_PACKAGE_STORE_MAX_PACKAGE_BYTES, 0) != VCS_OK) {
        zab_fail(z, "SNAPSHOT_MATERIALIZE_FAILED", false,
                 "selected saved source could not be verified and materialized", ZAB_COMMAND);
        return false;
    }
    return true;
}

/* ── the roots ───────────────────────────────────────────────────────── */

/* The package root and declared dependencies of the clean copy, prepared
 * exactly as a publish would (under the release's publisher key). */
static bool zab_package_at(struct zab *z, const char *dir,
                           uint8_t package_root[32], uint8_t dependency_root[32])
{
    return app_copy_build_roots(z->datadir, dir, &z->copy, package_root,
                                dependency_root, z->reply);
}

static bool zab_package(struct zab *z)
{
    return zab_package_at(z, zab_source(z), z->package_root, z->dependency_root);
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
    if (zcl_path_join(path, sizeof(path), zab_source(z), "Makefile") &&
        lstat(path, &st) == 0 && S_ISREG(st.st_mode))
        return true;
    zab_fail(z, "NO_MAKE_FRAGMENT", false, "the copy has no Makefile with "
             "print-app-closure and app targets", z->copy_dir);
    return false;
}

static bool zab_store_paths(struct zab *z)
{
    return app_copy_build_store(z->datadir, z->copy.fork_version, &z->store, z->reply);
}

static bool zab_closure(struct zab *z)
{
    char why[320] = "";
    const struct app_build_make m = {.copy_dir = zab_source(z),
                                     .work_dir = z->store.work,
                                     .confine = z->confine, .kit = &z->kit};
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
    return zcl_path_join(out, cap, z->store.images, hex);
}

/* A record for (package, env, dependency) that holds this closure and whose
 * image is still stored. A malformed record is a refusal, never a miss. */
static bool zab_cache(struct zab *z)
{
    char image[ZAB_PATH];
    struct stat st;
    bool hit = false;
    struct zcl_result r = app_image_build_load(
        z->store.records, z->package_root, z->env_root, z->dependency_root,
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
    sha3_256_write(&sha, z->copy.selected_version, 32);
    sha3_256_write(&sha, z->package_root, 32);
    sha3_256_write(&sha, z->closure.root, 32);
    sha3_256_write(&sha, z->env_root, 32);
    sha3_256_write(&sha, z->dependency_root, 32);
    sha3_256_finalize(&sha, z->plan_id);
}

static bool zab_environment(struct zab *z)
{
    char kit_why[256] = "";
    if (!app_toolchain_resolve(&z->kit, kit_why, sizeof(kit_why)) ||
        (z->kit.selected && !app_toolchain_seal(&z->kit, kit_why, sizeof(kit_why)))) {
        zab_fail(z, "ENV_UNAVAILABLE", false, "the selected compiler kit is unavailable", kit_why);
        return false;
    }
    struct zcl_result env = ZCL_OK;
    if (z->kit.selected) memcpy(z->env_root, z->kit.env, 32);
    else env = app_image_env_root(z->env_root);
    if (!env.ok) {
        zab_fail(z, "ENV_UNAVAILABLE", false, env.message, env.message);
        return false;
    }
    return true;
}

/* Every check and root a plan and its confirm both derive. */
static bool zab_derive(struct zab *z)
{
    if (!zab_resolve(z) || !zab_open_copy(z))
        return false;
    if (!zab_authorize(z) || !zab_selected_source(z) || !zab_make_fragment(z) ||
        !zab_package(z) || !zab_dependencies_match(z) || !zab_store_paths(z) ||
        !zab_environment(z)) return false;
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
    zcl_package_copy_push_root(d, "version", z->copy.selected_version);
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

/* One POSIX-shell word: plain bytes stay, anything else is backslashed. */
static bool zab_sh_word(char **at, size_t *left, const char *s)
{
    for (; *s; s++) {
        bool plain = (*s >= 'a' && *s <= 'z') || (*s >= 'A' && *s <= 'Z') ||
                     (*s >= '0' && *s <= '9') || strchr("_./:@+-=", *s);
        size_t need = plain ? 1u : 2u;
        if (*s < 32 || *s == 127 || *left <= need)
            return false;
        if (!plain)
            *(*at)++ = '\\';
        *(*at)++ = *s;
        *left -= need;
        **at = '\0';
    }
    return true;
}

/* The preview capture lives in the build store, never in the copy: a file
 * inside the copy's tracked tree is an unsaved change that blocks build and
 * share. <datadir>/app_build/previews/<image sha3>.png, created 0700 here
 * (the confirm half only). False with PREVIEW_DIR_FAILED when it cannot be. */
static bool zab_preview_target(struct zab *z, const char *image, char *dir,
                               size_t dcap, char *file, size_t fcap)
{
    const char *hex = strrchr(image, '/');
    hex = hex ? hex + 1 : image;
    bool ok = hex[0] && zcl_path_join(dir, dcap, z->datadir,
                                      "app_build/previews") &&
              snprintf(file, fcap, "%s.png", hex) < (int)fcap &&
              zcl_mkdir_p(dir, 0700).ok;
    if (!ok)
        zab_fail(z, "PREVIEW_DIR_FAILED", true, "the build succeeded but the "
                 "preview directory could not be created", dir);
    return ok;
}

/* The pasteable PREVIEW command: the built image, then its origin app's
 * compiled-in preview arguments (a capture path in the build store). */
static bool zab_preview_cmd(const struct app_launch_preview *p,
                            const char *image, char *cmd, size_t cap)
{
    char *at = cmd;
    size_t left = cap;
    cmd[0] = '\0';
    if (!zab_sh_word(&at, &left, image))
        return false;
    for (unsigned i = 0; i < p->arg_count; i++) {
        if (left < 2)
            return false;
        *at++ = ' ';
        *at = '\0';
        left--;
        if (!zab_sh_word(&at, &left, p->args[i]))
            return false;
    }
    return true;
}

/* An app whose launch row carries a preview argv gets ONE pasteable preview
 * command after a successful build; any other app gets none. app open still
 * takes no argv: this only prints the run for the owner to paste. */
static void zab_preview_hint(struct zab *z, const char *image)
{
    struct vcs_package_release release;
    uint8_t release_id[32];
    char base[ZCL_PACKAGE_COPY_BASE_MAX + 1u];
    char cmd[ZAB_PATH * 2 + 256], line[ZAB_PATH * 3 + 320];
    struct app_launch_preview p;
    if (zcl_package_copy_find_release(z->datadir, z->copy.parent_release,
                                      &release, release_id) !=
        ZCL_PACKAGE_COPY_FOUND)
        return;
    zcl_package_copy_name_base(release.name, base);
    char pdir[ZAB_PATH], pfile[96];
    struct app_launch_preview probe;
    if (!app_launch_preview(base, "/", &probe))
        return; /* no preview row: nothing to offer, nothing to create */
    if (!zab_preview_target(z, image, pdir, sizeof(pdir), pfile,
                            sizeof(pfile)) ||
        !app_launch_preview_as(base, pdir, pfile, &p) ||
        !zab_preview_cmd(&p, image, cmd, sizeof(cmd)))
        return;
    struct json_value argv;
    json_init(&argv);
    json_set_array(&argv);
    struct json_value item;
    json_init(&item);
    json_set_str(&item, image);
    bool ok = json_push_back(&argv, &item);
    json_free(&item);
    for (unsigned i = 0; ok && i < p.arg_count; i++) {
        json_init(&item);
        json_set_str(&item, p.args[i]);
        ok = json_push_back(&argv, &item);
        json_free(&item);
    }
    if (ok && snprintf(line, sizeof(line), "Preview: run %s to save %s", cmd,
                       p.capture_path) < (int)sizeof(line)) {
        (void)json_push_kv(&z->reply->data, "preview_argv", &argv);
        (void)json_push_kv_str(&z->reply->data, "preview", line);
    }
    json_free(&argv);
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
    (void)json_push_kv_str(d, "record_store", z->store.records);
    (void)json_push_kv_str(d, "build_dir", z->store.work);
    (void)json_push_kv_bool(d, "make_ran", make_ran);
    (void)json_push_kv_bool(d, "executed", false);
    if (z->version) {
        (void)json_push_kv_str(d, "next", "app open or app playtest this "
                               "image_sha3 with accept_execution:true");
    } else {
        char next[ZAB_PATH + 96];
        if (zcl_app_hint(next, sizeof(next), zcl_package_copy_str(z->input, "datadir"),
                         "open %s", zcl_package_copy_str(z->input, "copy")
                                       ? zcl_package_copy_str(z->input, "copy") : "COPY"))
            (void)json_push_kv_str(d, "next", next);
    }
    zab_preview_hint(z, image);
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
    bool ok = zcl_path_join(final, cap, z->store.images, hex);
    if (ok && lstat(final, &st) != 0)
        ok = authority_receipt_write_atomic(z->store.images, hex, bytes, len, final,
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
        r = app_image_build_save(z->store.records, rec, record, cap);
    if (!r.ok)
        zab_fail(z, "RECORD_SAVE_FAILED", true, "the build record could not "
                 "be saved", r.message);
    return r.ok;
}

/* The alias names existing persistent work, not a second build store. Its
 * private parent is not writable by confined make; the sandbox and disk watcher
 * still receive the real work directory. Removing the parent unlinks the
 * alias and cannot descend into persistent work. */
static bool zab_work_alias(struct zab *z, char *alias, size_t cap)
{
#if defined(_WIN32)
    (void)alias; (void)cap;
    zab_fail(z, "BUILD_WORKSPACE_UNSUPPORTED", true,
             "this host cannot create a private make workspace alias", ZAB_COMMAND);
    return false;
#else
    char target[ZAB_PATH], resolved[ZAB_PATH];
    if (!zab_private_workspace(z, "z23-build-work-", z->temporary_work,
                               sizeof(z->temporary_work), true)) return false;
    if (!zab_outside_work(z, z->temporary_work)) return false;
    bool ok = platform_directory_canonical_real(z->store.work, target, sizeof(target)) &&
        zcl_path_join(alias, cap, z->temporary_work, "output") &&
        symlink(target, alias) == 0 &&
        platform_directory_canonical_real(alias, resolved, sizeof(resolved)) &&
        strcmp(target, resolved) == 0;
    if (!ok)
        zab_fail(z, "BUILD_WORKSPACE_FAILED", true,
                 "could not bind private workspace to the existing build directory", ZAB_COMMAND);
    return ok;
#endif
}

static bool zab_dirs(struct zab *z, char *run, size_t cap)
{
    char alias[ZAB_PATH];
    bool ok = zcl_mkdir_p(z->store.work, 0700).ok &&
              zcl_mkdir_p(z->store.images, 0700).ok &&
              zcl_mkdir_p(z->store.records, 0700).ok;
    if (ok && !zab_make_path(z->store.work) && !zab_work_alias(z, alias, sizeof(alias)))
        return false;
    const char *work = z->temporary_work[0] ? alias : z->store.work;
    ok = ok && zcl_path_join(run, cap, work, "run-XXXXXX") && mkdtemp(run);
    if (!ok)
        zab_fail(z, "BUILD_DIR_FAILED", true, "the build directories could "
                 "not be created", z->store.work);
    return ok;
}

/* Leave room for the failure envelope even when every retained byte needs
 * JSON escaping. Build output is untrusted text, never terminal controls or
 * raw non-UTF-8 bytes. The input already names the copy; do not spend the
 * error budget on an arbitrarily escaped copy pathname. */
static void zab_build_failure(struct zab *z,
                               const struct app_build_make_result *res)
{
    enum { TAIL_BYTES = 768 };
    char tail[TAIL_BYTES + 1];
    size_t len = strnlen(res->tail, APP_BUILD_TAIL_MAX);
    size_t from = len > TAIL_BYTES ? len - TAIL_BYTES : 0;
    for (size_t i = from; i < len; i++) {
        unsigned char c = (unsigned char)res->tail[i];
        tail[i - from] = (c == '\n' || c == '\t' || (c >= 32 && c < 127))
                            ? (char)c : '?';
    }
    tail[len - from] = '\0';
    zab_fail(z, "BUILD_FAILED", true, res->why, ZAB_COMMAND);
    struct json_value facts;
    json_init(&facts);
    json_set_object(&facts);
    bool ok = json_push_kv_str(&facts, "confinement",
                               res->unconfined ? "unconfined" : "landlock") &&
              json_push_kv_str(&facts, "log_tail", tail) &&
              json_push_kv_bool(&facts, "log_tail_truncated", from != 0) &&
              json_push_kv(&z->reply->data, "failure_facts", &facts);
    json_free(&facts);
    if (!ok)
        fprintf(stderr, "app.build: could not attach bounded compiler failure facts\n");
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
        zab_build_failure(z, res);
        return;
    }
    if (!app_build_depfiles_declared(m, run, &z->closure, why, sizeof(why))) {
        zab_fail(z, "CLOSURE_DRIFT", true, "the build's inputs differ from "
                 "the closure the plan declared", why);
        return;
    }
    if (!zcl_path_join(built, sizeof(built), run, APP_BUILD_IMAGE_NAME) ||
        !zab_store_image(z, built, image, sizeof(image), sha)) {
        zab_fail(z, "IMAGE_STORE_FAILED", true, "make app left no image at "
                 "$(APP_OUT)/app, or it could not be stored", run);
        return;
    }
    if (zab_record(z, image, sha, &rec, record, sizeof(record)))
        zab_commit_reply(z, &rec, image, record, true, res->unconfined);
}

/* Source is a sibling of work/, never below make's writable ancestor.
 * Preserve captured modes: they participate in package identity. */
static bool zab_snapshot_create(struct zab *z, char snapshot[ZAB_PATH])
{
    char parent[ZAB_PATH], pattern[ZAB_PATH];
    if (z->temporary_work[0]) {
        if (!zab_private_workspace(z, "z23-build-source-", snapshot, ZAB_PATH, true)) return false;
    } else {
        if (!zcl_path_join(parent, sizeof(parent), z->datadir, ZAB_STORE "/sources") ||
            !zcl_mkdir_p(parent, 0700).ok ||
            !zcl_path_join(pattern, sizeof(pattern), parent, "saved-XXXXXX") ||
            !mkdtemp(pattern)) {
            zab_fail(z, "SNAPSHOT_CREATE_FAILED", true,
                     "could not create private saved-source directory", z->datadir);
            return false;
        }
        (void)snprintf(snapshot, ZAB_PATH, "%s", pattern);
    }
    if (vcs_tree_materialize_disposable(z->copy_dir, z->copy.head_tree, snapshot,
                             VCS_PACKAGE_STORE_MAX_PACKAGE_BYTES, 0) != VCS_OK) {
        zab_fail(z, "SNAPSHOT_MATERIALIZE_FAILED", true,
                 "could not materialize the saved head from verified objects", snapshot);
        return false;
    }
    return true;
}

static bool zab_snapshot_matches(struct zab *z, const struct app_build_make *m)
{
    uint8_t package[32], dependencies[32];
    struct app_build_closure closure = {0};
    char why[320] = "";
    if (!zab_package_at(z, m->copy_dir, package, dependencies))
        return false;
    bool ok = app_build_closure_query(m, &closure, why, sizeof(why));
    if (!ok) {
        zab_fail(z, "SNAPSHOT_CLOSURE_FAILED", true,
                 "saved-source closure could not be derived before compilation", why);
    } else if (memcmp(package, z->package_root, 32) != 0 ||
               memcmp(dependencies, z->dependency_root, 32) != 0 ||
               memcmp(closure.root, z->closure.root, 32) != 0) {
        zab_fail(z, "SNAPSHOT_ROOT_MISMATCH", true,
                 "saved-source package, dependencies or closure differ from the plan",
                 m->copy_dir);
        ok = false;
    }
    app_build_closure_free(&closure);
    return ok;
}

static void zab_scratch_remove(const char *path)
{
    if (!path[0]) return;
    struct zcl_result rm = zcl_tree_remove(path);
    if (!rm.ok)
        fprintf(stderr, "[app.build] could not remove private build scratch %s: %s\n",
                path, rm.message);
}

static void zab_build(struct zab *z)
{
    char run[ZAB_PATH], snapshot[ZAB_PATH] = "";
    struct app_build_make_result *res =
        zcl_calloc(1, sizeof(*res), "app.build.make_result");
    if (!res) {
        zab_fail(z, "ALLOCATION_FAILED", false, "build result allocation "
                 "failed", z->copy_dir);
        return;
    }
    if (zab_dirs(z, run, sizeof(run))) {
        const struct app_build_make m = {.copy_dir = z->version ? z->selected_source : snapshot,
                                         .work_dir = z->store.work,
                                         .confine = z->confine, .kit = &z->kit};
        if ((z->version || zab_snapshot_create(z, snapshot)) &&
            zab_outside_work(z, m.copy_dir) &&
            zab_snapshot_matches(z, &m)) {
            app_build_make_run(&m, run, res);
            zab_after_make(z, &m, run, res);
        }
        zab_scratch_remove(snapshot);
        zab_scratch_remove(run);
    }
    zab_scratch_remove(z->temporary_work);
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
    (void)snprintf(record, sizeof(record), "%s/%s%s", z->store.records, key,
                   APP_IMAGE_BUILD_FILE_SUFFIX);
    (void)zab_image_path(z, z->cached.image_sha3, image, sizeof(image));
    zab_commit_reply(z, &z->cached, image, record, false, !z->confine);
}

void zcl_native_handle_app_build(const struct zcl_command_request *request,
                                 struct zcl_command_reply *reply)
{
    struct zab *z = request && reply
                        ? zcl_calloc(1, sizeof(*z), "app.build.state")
                        : NULL;
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
    if (z->selected_source[0]) {
        struct zcl_result rm = zcl_tree_remove(z->selected_source);
        if (!rm.ok)
            zab_fail(z, "SNAPSHOT_CLEANUP_FAILED", true,
                     "private selected-source scratch cleanup failed", rm.message);
    }
    app_build_closure_free(&z->closure);
    app_toolchain_free(&z->kit);
    free(z);
}
